//! Enterprise & managed policy engine powering `browser://policy` and `singularity://policy`.
//!
//! Loads mandatory and recommended policies from Linux managed JSON directories
//! (`/etc/singularity/policies/managed/*.json`), custom test directories, Windows Registry
//! representations (HKLM/HKCU), or command-line overrides, and enforces `Mandatory` locks
//! inside [`SettingsRegistry`].

use crate::schema::SettingValue;
use crate::SettingsRegistry;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

/// Maximum policy file size accepted from disk (2 MiB) to guard against accidental DoS.
const MAX_POLICY_FILE_BYTES: u64 = 2 * 1024 * 1024;

/// Origin source from which a managed policy entry was loaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PolicySource {
    WindowsRegistryHklm,
    WindowsRegistryHkcu,
    LinuxManagedJson,
    CommandLine,
    Default,
}

impl PolicySource {
    /// Human-readable source label displayed in `browser://policy`.
    pub fn label(&self) -> &'static str {
        match self {
            Self::WindowsRegistryHklm => "Windows Registry (HKLM)",
            Self::WindowsRegistryHkcu => "Windows Registry (HKCU)",
            Self::LinuxManagedJson => "Linux Managed JSON",
            Self::CommandLine => "Command Line",
            Self::Default => "Default",
        }
    }

    /// Precedence rank used when merging conflicting entries with the same enforcement level.
    pub fn priority(&self) -> u8 {
        match self {
            Self::CommandLine => 5,
            Self::WindowsRegistryHklm => 4,
            Self::LinuxManagedJson => 4,
            Self::WindowsRegistryHkcu => 3,
            Self::Default => 1,
        }
    }
}

/// Enforcement level of an enterprise policy entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PolicyEnforcement {
    /// Overrides user preference and locks the setting against runtime modification or reset.
    Mandatory,
    /// Provides an administrator-recommended default that users may still override.
    Recommended,
}

/// Single enterprise policy rule bound to a hierarchical `SettingsRegistry` key.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ManagedPolicyEntry {
    pub key: String,
    pub value: SettingValue,
    pub source: PolicySource,
    pub enforcement: PolicyEnforcement,
    pub scope: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PolicyExportSnapshot {
    version: String,
    total_policies: usize,
    mandatory_count: usize,
    recommended_count: usize,
    policies: Vec<ManagedPolicyEntry>,
}

/// Coerces plain JSON-derived `SettingValue` variants to match a target setting's expected type
/// (e.g., `Text("#000000")` -> `ColorHex("#000000")`, `Int(200)` -> `Float(200.0)`).
pub(crate) fn coerce_value_for_target(
    target_default: &SettingValue,
    candidate: &SettingValue,
) -> SettingValue {
    match (target_default, candidate) {
        (SettingValue::ColorHex(_), SettingValue::Text(s)) => SettingValue::ColorHex(s.clone()),
        (SettingValue::Float(_), SettingValue::Int(i)) => SettingValue::Float(*i as f64),
        _ => candidate.clone(),
    }
}

/// Converts a `serde_json::Value` (either tagged `SettingValue` or raw JSON scalar)
/// into a strongly-typed [`SettingValue`].
pub(crate) fn json_value_to_setting_value(v: &JsonValue) -> Result<SettingValue, String> {
    if v.is_object() {
        if let Ok(tagged) = serde_json::from_value::<SettingValue>(v.clone()) {
            return Ok(tagged);
        }
        return Err(format!(
            "Unsupported JSON object for SettingValue (expected tagged SettingValue): {}",
            v
        ));
    }

    match v {
        JsonValue::Bool(b) => Ok(SettingValue::Bool(*b)),
        JsonValue::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(SettingValue::Int(i))
            } else if let Some(f) = n.as_f64() {
                if f.is_finite() {
                    Ok(SettingValue::Float(f))
                } else {
                    Err("Non-finite float value in policy JSON".to_string())
                }
            } else {
                Err(format!("Unsupported numeric value in policy JSON: {}", n))
            }
        }
        JsonValue::String(s) => Ok(SettingValue::Text(s.clone())),
        _ => Err(format!("Unsupported JSON value type in policy: {}", v)),
    }
}

fn parse_enforcement(raw: &str) -> Result<PolicyEnforcement, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "mandatory" | "locked" | "enforced" => Ok(PolicyEnforcement::Mandatory),
        "recommended" | "default" | "optional" => Ok(PolicyEnforcement::Recommended),
        other => Err(format!("Unknown policy enforcement '{}'", other)),
    }
}

fn parse_source(raw: &str) -> Result<PolicySource, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "windowsregistryhklm" | "hklm" | "windows_registry_hklm" => {
            Ok(PolicySource::WindowsRegistryHklm)
        }
        "windowsregistryhkcu" | "hkcu" | "windows_registry_hkcu" => {
            Ok(PolicySource::WindowsRegistryHkcu)
        }
        "linuxmanagedjson" | "linux_managed_json" | "managed_json" => {
            Ok(PolicySource::LinuxManagedJson)
        }
        "commandline" | "command_line" | "cli" => Ok(PolicySource::CommandLine),
        "default" => Ok(PolicySource::Default),
        other => Err(format!("Unknown policy source '{}'", other)),
    }
}

/// Clamps a JSON-derived [`ManagedPolicyEntry`] so untrusted or lower-privilege JSON inputs
/// cannot self-elevate `enforcement` (e.g. `Recommended` -> `Mandatory`) or `source` priority
/// above the caller-supplied `(max_source, max_enforcement)` ceiling.
fn clamp_policy_entry_privileges(
    mut entry: ManagedPolicyEntry,
    max_source: PolicySource,
    max_enforcement: PolicyEnforcement,
) -> ManagedPolicyEntry {
    if max_enforcement == PolicyEnforcement::Recommended {
        entry.enforcement = PolicyEnforcement::Recommended;
    }
    if entry.source.priority() > max_source.priority() {
        entry.source = max_source;
    }
    entry
}

/// Central enterprise policy loader, inspector, and enforcer for `browser://policy`.
#[derive(Debug, Clone, Default)]
pub struct PolicyEngine {
    entries: BTreeMap<String, ManagedPolicyEntry>,
    loaded_sources: Vec<String>,
}

impl PolicyEngine {
    /// Standard system directory for mandatory Linux policy JSON files.
    pub const DEFAULT_LINUX_MANAGED_DIR: &'static str = "/etc/singularity/policies/managed";
    /// Standard system directory for recommended Linux policy JSON files.
    pub const DEFAULT_LINUX_RECOMMENDED_DIR: &'static str = "/etc/singularity/policies/recommended";

    /// Creates an empty `PolicyEngine`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Loads system policies from `/etc/singularity/policies/managed/*.json` (Mandatory)
    /// and `/etc/singularity/policies/recommended/*.json` (Recommended), ignoring missing dirs.
    pub fn load_default_linux_policies() -> Self {
        let mut engine = Self::new();
        let managed = Path::new(Self::DEFAULT_LINUX_MANAGED_DIR);
        if managed.is_dir() {
            let _ = engine.load_from_dir(
                managed,
                PolicySource::LinuxManagedJson,
                PolicyEnforcement::Mandatory,
                "machine",
            );
        }
        let recommended = Path::new(Self::DEFAULT_LINUX_RECOMMENDED_DIR);
        if recommended.is_dir() {
            let _ = engine.load_from_dir(
                recommended,
                PolicySource::LinuxManagedJson,
                PolicyEnforcement::Recommended,
                "machine",
            );
        }
        engine
    }

    /// Loads all `*.json` files from `dir` in deterministic alphabetical filename order.
    pub fn load_from_dir(
        &mut self,
        dir: impl AsRef<Path>,
        source: PolicySource,
        default_enforcement: PolicyEnforcement,
        default_scope: &str,
    ) -> Result<usize, String> {
        let dir_path = dir.as_ref();
        let read_dir = fs::read_dir(dir_path).map_err(|e| {
            format!(
                "Failed to read policy directory '{}': {}",
                dir_path.display(),
                e
            )
        })?;

        let mut json_files = Vec::new();
        for entry_res in read_dir {
            let entry = entry_res.map_err(|e| format!("Directory entry error: {}", e))?;
            let path = entry.path();
            if path.is_file()
                && path
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
            {
                json_files.push(path);
            }
        }
        json_files.sort();

        let mut total_loaded = 0usize;
        for file_path in json_files {
            total_loaded +=
                self.load_from_file(&file_path, source, default_enforcement, default_scope)?;
        }
        Ok(total_loaded)
    }

    /// Loads a single managed JSON policy file from disk.
    pub fn load_from_file(
        &mut self,
        path: impl AsRef<Path>,
        source: PolicySource,
        default_enforcement: PolicyEnforcement,
        default_scope: &str,
    ) -> Result<usize, String> {
        let path_ref = path.as_ref();
        let meta = fs::metadata(path_ref)
            .map_err(|e| format!("Failed to stat policy file '{}': {}", path_ref.display(), e))?;
        if meta.len() > MAX_POLICY_FILE_BYTES {
            return Err(format!(
                "Policy file '{}' exceeds maximum allowed size ({} bytes)",
                path_ref.display(),
                MAX_POLICY_FILE_BYTES
            ));
        }

        let raw = fs::read_to_string(path_ref)
            .map_err(|e| format!("Failed to read policy file '{}': {}", path_ref.display(), e))?;
        let count = self.load_json_str(&raw, source, default_enforcement, default_scope)?;
        self.loaded_sources.push(path_ref.display().to_string());
        Ok(count)
    }

    /// Parses and merges policies from a JSON string.
    ///
    /// Supports:
    /// 1. Flat key -> scalar/tagged `SettingValue` map (e.g. `{"security.sandbox.level": 4}`).
    /// 2. Key -> rich policy object (`{"security.sandbox.level": {"value": 4, "enforcement": "Mandatory", "scope": "machine"}}`).
    /// 3. Structured export snapshot (`{"policies": [ManagedPolicyEntry, ...]}`).
    /// 4. Top-level JSON array of [`ManagedPolicyEntry`].
    pub fn load_json_str(
        &mut self,
        json: &str,
        source: PolicySource,
        default_enforcement: PolicyEnforcement,
        default_scope: &str,
    ) -> Result<usize, String> {
        let parsed: JsonValue =
            serde_json::from_str(json).map_err(|e| format!("Invalid policy JSON: {}", e))?;

        let mut loaded = 0usize;

        if let Some(arr) = parsed.as_array() {
            for item in arr {
                let entry: ManagedPolicyEntry = serde_json::from_value(item.clone())
                    .map_err(|e| format!("Invalid ManagedPolicyEntry in array: {}", e))?;
                let clamped = clamp_policy_entry_privileges(entry, source, default_enforcement);
                if self.insert_policy(clamped) {
                    loaded += 1;
                }
            }
            return Ok(loaded);
        }

        let Some(obj) = parsed.as_object() else {
            return Err("Policy JSON root must be a JSON object or array".to_string());
        };

        // Structured snapshot format produced by `export_json()`.
        if let Some(policies_val) = obj.get("policies").filter(|v| v.is_array()) {
            let entries: Vec<ManagedPolicyEntry> = serde_json::from_value(policies_val.clone())
                .map_err(|e| format!("Invalid 'policies' array in snapshot: {}", e))?;
            for entry in entries {
                let clamped = clamp_policy_entry_privileges(entry, source, default_enforcement);
                if self.insert_policy(clamped) {
                    loaded += 1;
                }
            }
            return Ok(loaded);
        }

        for (key, val) in obj {
            if key.is_empty() || key.starts_with('_') || key == "$schema" {
                continue;
            }

            let entry = if let Some(sub) = val.as_object() {
                if sub.contains_key("type") && sub.contains_key("value") && !sub.contains_key("enforcement") {
                    let typed_val = json_value_to_setting_value(val)?;
                    ManagedPolicyEntry {
                        key: key.clone(),
                        value: typed_val,
                        source,
                        enforcement: default_enforcement,
                        scope: default_scope.to_string(),
                    }
                } else if let Some(inner_val) = sub.get("value") {
                    let typed_val = json_value_to_setting_value(inner_val)?;
                    let enforcement = match sub.get("enforcement").and_then(JsonValue::as_str) {
                        Some(raw_enf) => parse_enforcement(raw_enf)?,
                        None => default_enforcement,
                    };
                    let entry_source = match sub.get("source").and_then(JsonValue::as_str) {
                        Some(raw_src) => parse_source(raw_src)?,
                        None => source,
                    };
                    let scope = sub
                        .get("scope")
                        .and_then(JsonValue::as_str)
                        .unwrap_or(default_scope)
                        .to_string();
                    clamp_policy_entry_privileges(
                        ManagedPolicyEntry {
                            key: key.clone(),
                            value: typed_val,
                            source: entry_source,
                            enforcement,
                            scope,
                        },
                        source,
                        default_enforcement,
                    )
                } else {
                    return Err(format!(
                        "Policy object for key '{}' must contain 'value'",
                        key
                    ));
                }
            } else {
                let typed_val = json_value_to_setting_value(val)?;
                ManagedPolicyEntry {
                    key: key.clone(),
                    value: typed_val,
                    source,
                    enforcement: default_enforcement,
                    scope: default_scope.to_string(),
                }
            };

            if self.insert_policy(entry) {
                loaded += 1;
            }
        }

        Ok(loaded)
    }

    /// Inserts or merges a [`ManagedPolicyEntry`] while honoring enforcement and source precedence:
    /// - A `Recommended` policy never overwrites an existing `Mandatory` policy.
    /// - A `Mandatory` policy always overrides a `Recommended` policy.
    /// - At equal enforcement, equal or higher source priority overwrites the previous entry.
    pub fn insert_policy(&mut self, entry: ManagedPolicyEntry) -> bool {
        if let Some(existing) = self.entries.get(&entry.key) {
            match (existing.enforcement, entry.enforcement) {
                (PolicyEnforcement::Mandatory, PolicyEnforcement::Recommended) => return false,
                (PolicyEnforcement::Mandatory, PolicyEnforcement::Mandatory)
                | (PolicyEnforcement::Recommended, PolicyEnforcement::Recommended) => {
                    if entry.source.priority() < existing.source.priority() {
                        return false;
                    }
                }
                (PolicyEnforcement::Recommended, PolicyEnforcement::Mandatory) => {}
            }
        }
        self.entries.insert(entry.key.clone(), entry);
        true
    }

    /// Removes a policy entry by setting key.
    pub fn remove_policy(&mut self, key: &str) -> Option<ManagedPolicyEntry> {
        self.entries.remove(key)
    }

    /// Clears all loaded policy entries and source metadata.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.loaded_sources.clear();
    }

    /// Returns the total number of loaded policy entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if no policies are loaded.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Looks up a single managed policy entry by setting key.
    pub fn get(&self, key: &str) -> Option<&ManagedPolicyEntry> {
        self.entries.get(key)
    }

    /// Returns `true` if `key` is governed by a `Mandatory` enterprise policy.
    pub fn is_mandatory_locked(&self, key: &str) -> bool {
        self.entries
            .get(key)
            .is_some_and(|e| e.enforcement == PolicyEnforcement::Mandatory)
    }

    /// Lists all active policies in deterministic alphabetical key order.
    pub fn list_policies(&self) -> Vec<&ManagedPolicyEntry> {
        self.entries.values().collect()
    }

    /// Lists all keys locked under `Mandatory` enforcement.
    pub fn mandatory_keys(&self) -> Vec<String> {
        self.entries
            .values()
            .filter(|e| e.enforcement == PolicyEnforcement::Mandatory)
            .map(|e| e.key.clone())
            .collect()
    }

    /// Returns the list of disk files loaded into this engine.
    pub fn loaded_sources(&self) -> &[String] {
        &self.loaded_sources
    }

    /// Applies all policies in this engine onto the target [`SettingsRegistry`], locking all
    /// valid `Mandatory` keys and returning the number of policy entries successfully applied.
    pub fn apply_to_registry(&self, registry: &mut SettingsRegistry) -> usize {
        registry.apply_policy_engine(self)
    }

    /// Exports all active policies as a pretty-printed JSON snapshot suitable for `browser://policy`.
    pub fn export_json(&self) -> Result<String, String> {
        let policies: Vec<ManagedPolicyEntry> = self.entries.values().cloned().collect();
        let mandatory_count = policies
            .iter()
            .filter(|p| p.enforcement == PolicyEnforcement::Mandatory)
            .count();
        let recommended_count = policies.len().saturating_sub(mandatory_count);

        let snapshot = PolicyExportSnapshot {
            version: "1.0.0".to_string(),
            total_policies: policies.len(),
            mandatory_count,
            recommended_count,
            policies,
        };

        serde_json::to_string_pretty(&snapshot)
            .map_err(|e| format!("Failed to serialize policies JSON: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_policy_dir(label: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "singularity_policy_test_{}_{}_{}",
            label,
            std::process::id(),
            nanos
        ));
        fs::create_dir_all(&dir).expect("create temp policy dir");
        dir
    }

    #[test]
    fn test_policy_engine_dir_loading_precedence_and_export_roundtrip() {
        let dir = unique_temp_policy_dir("dir_load");
        let file_a = dir.join("01_base.json");
        let file_b = dir.join("02_override.json");

        fs::write(
            &file_a,
            r##"{
                "security.sandbox.level": 4,
                "ui.theme.primary_background_hex": "#000000",
                "media.audio.volume_boost_percent": {
                    "value": 200,
                    "enforcement": "Recommended",
                    "scope": "user"
                }
            }"##,
        )
        .unwrap();
        fs::write(
            &file_b,
            r#"{
                "security.v8.jitless_strict_mode": true
            }"#,
        )
        .unwrap();

        let mut engine = PolicyEngine::new();
        let loaded = engine
            .load_from_dir(
                &dir,
                PolicySource::LinuxManagedJson,
                PolicyEnforcement::Mandatory,
                "machine",
            )
            .expect("load policy dir");
        assert_eq!(loaded, 4);
        assert!(engine.is_mandatory_locked("security.sandbox.level"));
        assert!(engine.is_mandatory_locked("security.v8.jitless_strict_mode"));
        assert!(!engine.is_mandatory_locked("media.audio.volume_boost_percent"));
        assert_eq!(engine.list_policies().len(), 4);

        // Recommended policy must NOT overwrite Mandatory policy
        let inserted = engine.insert_policy(ManagedPolicyEntry {
            key: "security.sandbox.level".into(),
            value: SettingValue::Int(1),
            source: PolicySource::CommandLine,
            enforcement: PolicyEnforcement::Recommended,
            scope: "user".into(),
        });
        assert!(!inserted);
        assert_eq!(
            engine.get("security.sandbox.level").unwrap().value,
            SettingValue::Int(4)
        );

        // Export JSON and reload into a fresh engine
        let exported = engine.export_json().expect("export policy json");
        assert!(exported.contains("\"mandatory_count\": 3"));
        assert!(exported.contains("\"recommended_count\": 1"));

        let mut engine2 = PolicyEngine::new();
        let reloaded = engine2
            .load_json_str(
                &exported,
                PolicySource::LinuxManagedJson,
                PolicyEnforcement::Mandatory,
                "machine",
            )
            .expect("reload exported snapshot");
        assert_eq!(reloaded, 4);
        assert!(engine2.is_mandatory_locked("security.sandbox.level"));
        assert!(!engine2.is_mandatory_locked("media.audio.volume_boost_percent"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_policy_json_cannot_self_elevate_enforcement_or_source() {
        let mut engine = PolicyEngine::new();
        // Seed a Mandatory CommandLine policy
        assert!(engine.insert_policy(ManagedPolicyEntry {
            key: "security.sandbox.level".into(),
            value: SettingValue::Int(4),
            source: PolicySource::CommandLine,
            enforcement: PolicyEnforcement::Mandatory,
            scope: "machine".into(),
        }));

        // 1. Recommended JSON (rich object) attempting to self-elevate to Mandatory + CommandLine
        let loaded_rec = engine
            .load_json_str(
                r#"{
                    "security.sandbox.level": {
                        "value": 1,
                        "enforcement": "Mandatory",
                        "source": "CommandLine",
                        "scope": "machine"
                    },
                    "ui.sidebar.position": {
                        "value": "right",
                        "enforcement": "Mandatory",
                        "source": "CommandLine",
                        "scope": "user"
                    }
                }"#,
                PolicySource::LinuxManagedJson,
                PolicyEnforcement::Recommended,
                "user",
            )
            .expect("load recommended json");
        // security.sandbox.level must NOT be overwritten; ui.sidebar.position is clamped to Recommended/LinuxManagedJson
        assert_eq!(loaded_rec, 1);
        assert_eq!(
            engine.get("security.sandbox.level").unwrap().value,
            SettingValue::Int(4)
        );
        let sidebar = engine.get("ui.sidebar.position").unwrap();
        assert_eq!(sidebar.enforcement, PolicyEnforcement::Recommended);
        assert_eq!(sidebar.source, PolicySource::LinuxManagedJson);
        assert!(!engine.is_mandatory_locked("ui.sidebar.position"));

        // 2. LinuxManagedJson (Mandatory) attempting to spoof source="CommandLine" to override CLI policy
        let loaded_spoof = engine
            .load_json_str(
                r#"[
                    {
                        "key": "security.sandbox.level",
                        "value": {"type": "Int", "value": 0},
                        "source": "CommandLine",
                        "enforcement": "Mandatory",
                        "scope": "machine"
                    },
                    {
                        "key": "security.v8.jitless_strict_mode",
                        "value": {"type": "Bool", "value": true},
                        "source": "CommandLine",
                        "enforcement": "Mandatory",
                        "scope": "machine"
                    }
                ]"#,
                PolicySource::LinuxManagedJson,
                PolicyEnforcement::Mandatory,
                "machine",
            )
            .expect("load array json");
        assert_eq!(loaded_spoof, 1);
        assert_eq!(
            engine.get("security.sandbox.level").unwrap().value,
            SettingValue::Int(4)
        );
        assert_eq!(
            engine.get("security.v8.jitless_strict_mode").unwrap().source,
            PolicySource::LinuxManagedJson
        );

        // 3. Snapshot format loaded with Recommended + Default must clamp every entry
        let exported = engine.export_json().expect("export snapshot");
        let mut engine_low = PolicyEngine::new();
        let loaded_low = engine_low
            .load_json_str(
                &exported,
                PolicySource::Default,
                PolicyEnforcement::Recommended,
                "user",
            )
            .expect("load snapshot under low trust");
        assert!(loaded_low >= 3);
        for pol in engine_low.list_policies() {
            assert_eq!(pol.enforcement, PolicyEnforcement::Recommended);
            assert_eq!(pol.source, PolicySource::Default);
        }
    }
}
