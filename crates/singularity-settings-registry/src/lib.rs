//! `singularity-settings-registry` — The 2,500+ Power-User Configuration Engine
//! powering `singularity://settings`, `browser://flags`, and `browser://policy`.

pub mod catalog;
pub mod flags;
pub mod macros;
pub mod policy;
pub mod schema;
pub mod search;
pub mod storage;

pub use flags::{ExperimentFlag, FlagOrigin, FlagsStore};
pub use policy::{ManagedPolicyEntry, PolicyEngine, PolicyEnforcement, PolicySource};
pub use schema::{
    HotReloadEvent, SettingCategory, SettingDescriptor, SettingDiffRow, SettingEntry, SettingValue,
    TargetSubsystem, ValueConstraint,
};
pub use search::{FuzzyMatch, VirtualizedViewport};

use crate::catalog::build_full_settings_catalog;
use crate::policy::{coerce_value_for_target, json_value_to_setting_value};
use crate::search::{compute_virtualized_viewport, compute_virtualized_viewport_filtered};
use crate::storage::{export_sqlite_transaction_sql, TomlSettingsSnapshot};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("Setting key not found: {0}")]
    KeyNotFound(String),
    #[error("Setting '{key}' is locked by a mandatory enterprise policy")]
    PolicyLocked { key: String },
    #[error("Type mismatch for setting '{key}': expected matching variant for {expected:?}, got {actual:?}")]
    TypeMismatch {
        key: String,
        expected: SettingValue,
        actual: SettingValue,
    },
    #[error("Constraint validation failed for setting '{key}' with value {value:?}")]
    ConstraintViolation { key: String, value: SettingValue },
    #[error("TOML serialization error: {0}")]
    TomlSerError(#[from] toml::ser::Error),
    #[error("TOML deserialization error: {0}")]
    TomlDeError(#[from] toml::de::Error),
}

pub type HotReloadCallback = Arc<dyn Fn(&HotReloadEvent) + Send + Sync>;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JsonSettingsSnapshot {
    version: String,
    modified_only: bool,
    count: usize,
    overrides: BTreeMap<String, SettingValue>,
}

/// High-performance, indexed configuration registry holding 2,500+ granular browser settings.
pub struct SettingsRegistry {
    entries: Vec<SettingEntry>,
    key_to_index: HashMap<String, usize>,
    hot_reload_hooks: Vec<HotReloadCallback>,
    pending_restart_keys: BTreeSet<String>,
    mandatory_locked_keys: BTreeSet<String>,
    recommended_applied_values: HashMap<String, SettingValue>,
}

impl Default for SettingsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SettingsRegistry {
    /// Initializes the full 2,500+ settings registry with O(1) key lookup tables.
    pub fn new() -> Self {
        let entries = build_full_settings_catalog();
        let mut key_to_index = HashMap::with_capacity(entries.len());
        for (idx, entry) in entries.iter().enumerate() {
            key_to_index.insert(entry.key.clone(), idx);
        }
        Self {
            entries,
            key_to_index,
            hot_reload_hooks: Vec::new(),
            pending_restart_keys: BTreeSet::new(),
            mandatory_locked_keys: BTreeSet::new(),
            recommended_applied_values: HashMap::new(),
        }
    }

    /// Total number of registered settings (guaranteed >= 2,400).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns a slice of all registered settings.
    pub fn all_entries(&self) -> &[SettingEntry] {
        &self.entries
    }

    /// Looks up a setting by its hierarchical dot-separated key in O(1) time.
    pub fn get(&self, key: &str) -> Option<&SettingEntry> {
        let &idx = self.key_to_index.get(key)?;
        self.entries.get(idx)
    }

    /// Returns the number of settings registered in a specific category.
    pub fn count_by_category(&self, category: SettingCategory) -> usize {
        self.entries.iter().filter(|e| e.category == category).count()
    }

    /// Returns a summary map of setting counts across all 9 mandatory categories.
    pub fn category_counts(&self) -> Vec<(SettingCategory, usize)> {
        SettingCategory::ALL
            .iter()
            .map(|&cat| (cat, self.count_by_category(cat)))
            .collect()
    }

    /// Registers a live hot-reload listener notified whenever a hot-reloadable setting is updated.
    pub fn register_hot_reload_hook(&mut self, hook: HotReloadCallback) {
        self.hot_reload_hooks.push(hook);
    }

    /// Returns `true` if one or more non-hot-reloadable settings were modified and require a restart.
    pub fn requires_restart(&self) -> bool {
        !self.pending_restart_keys.is_empty()
    }

    /// Returns the sorted list of modified setting keys waiting for a browser restart to take effect.
    pub fn pending_restart_keys(&self) -> Vec<String> {
        self.pending_restart_keys.iter().cloned().collect()
    }

    /// Clears recorded restart-required setting keys (e.g. after applying them at process restart).
    pub fn clear_pending_restart(&mut self) {
        self.pending_restart_keys.clear();
    }

    /// Returns `true` if the setting key is locked by an active `Mandatory` enterprise policy.
    pub fn is_policy_locked(&self, key: &str) -> bool {
        self.mandatory_locked_keys.contains(key)
    }

    /// Returns the sorted list of keys currently locked by `Mandatory` enterprise policies.
    pub fn policy_locked_keys(&self) -> Vec<String> {
        self.mandatory_locked_keys.iter().cloned().collect()
    }

    fn set_internal(
        &mut self,
        key: &str,
        new_value: SettingValue,
        bypass_policy_lock: bool,
    ) -> Result<HotReloadEvent, RegistryError> {
        let &idx = self
            .key_to_index
            .get(key)
            .ok_or_else(|| RegistryError::KeyNotFound(key.to_string()))?;

        if !bypass_policy_lock && self.mandatory_locked_keys.contains(key) {
            return Err(RegistryError::PolicyLocked {
                key: key.to_string(),
            });
        }

        let entry = &mut self.entries[idx];
        if !entry.default_value.matches_type(&new_value) {
            return Err(RegistryError::TypeMismatch {
                key: key.to_string(),
                expected: entry.default_value.clone(),
                actual: new_value,
            });
        }

        if !entry.validate_value(&new_value) {
            return Err(RegistryError::ConstraintViolation {
                key: key.to_string(),
                value: new_value,
            });
        }

        let hot_reloadable = entry.hot_reloadable;
        let old_value = std::mem::replace(&mut entry.current_value, new_value.clone());
        let changed = old_value != new_value;
        let event = HotReloadEvent {
            key: entry.key.clone(),
            category: entry.category,
            subsystem: entry.subsystem,
            old_value,
            new_value,
            chromium_cli_arg: entry.to_chromium_cli_arg(),
            requires_restart: !hot_reloadable,
        };

        if hot_reloadable {
            for hook in &self.hot_reload_hooks {
                hook(&event);
            }
        } else if changed {
            self.pending_restart_keys.insert(event.key.clone());
        }

        Ok(event)
    }

    /// Mutates a setting value after verifying policy locks, type safety, range/enum constraints,
    /// and security rules. Fires live hot-reload hooks only when `entry.hot_reloadable == true`;
    /// otherwise records the setting as requiring a restart without invoking hot-reload hooks.
    pub fn set(&mut self, key: &str, new_value: SettingValue) -> Result<HotReloadEvent, RegistryError> {
        let evt = self.set_internal(key, new_value, false)?;
        // User explicitly set this setting; clear any prior recommended-policy baseline marker.
        self.recommended_applied_values.remove(key);
        Ok(evt)
    }

    /// Alias for [`Self::set`] that validates and applies a setting value.
    pub fn set_value(&mut self, key: &str, new_value: SettingValue) -> Result<HotReloadEvent, RegistryError> {
        self.set(key, new_value)
    }

    /// Applies all valid policies from a [`PolicyEngine`] onto this registry.
    ///
    /// - `Mandatory` policies override the current value and lock the key against user mutation/reset.
    /// - `Recommended` policies apply only when the setting is still at its default (or a prior
    ///   recommended policy value), leaving the user free to override it afterward.
    /// - Invalid or security-violating policy values are rejected without weakening validation.
    pub fn apply_policy_engine(&mut self, policy: &PolicyEngine) -> usize {
        self.mandatory_locked_keys.clear();
        let mut applied = 0usize;

        for policy_entry in policy.list_policies() {
            let Some(&idx) = self.key_to_index.get(&policy_entry.key) else {
                continue;
            };

            let coerced = {
                let setting = &self.entries[idx];
                coerce_value_for_target(&setting.default_value, &policy_entry.value)
            };

            match policy_entry.enforcement {
                PolicyEnforcement::Mandatory => {
                    if self.set_internal(&policy_entry.key, coerced, true).is_ok() {
                        self.mandatory_locked_keys.insert(policy_entry.key.clone());
                        self.recommended_applied_values.remove(&policy_entry.key);
                        applied += 1;
                    }
                }
                PolicyEnforcement::Recommended => {
                    let can_apply_recommended = {
                        let setting = &self.entries[idx];
                        !setting.is_modified()
                            || self
                                .recommended_applied_values
                                .get(&policy_entry.key)
                                .is_some_and(|prev| *prev == setting.current_value)
                    };
                    if can_apply_recommended
                        && self
                            .set_internal(&policy_entry.key, coerced.clone(), true)
                            .is_ok()
                    {
                        self.recommended_applied_values
                            .insert(policy_entry.key.clone(), coerced);
                        applied += 1;
                    }
                }
            }
        }

        applied
    }

    /// Returns serializable diff rows for all settings whose current value differs from default.
    pub fn diff_modified_settings(&self) -> Vec<SettingDiffRow> {
        self.entries
            .iter()
            .filter(|e| e.is_modified())
            .map(|e| SettingDiffRow {
                id: e.id,
                key: e.key.clone(),
                category: e.category,
                subsystem: e.subsystem,
                title: e.title.clone(),
                default_value: e.default_value.clone(),
                current_value: e.current_value.clone(),
                hot_reloadable: e.hot_reloadable,
                locked_by_policy: self.mandatory_locked_keys.contains(&e.key),
            })
            .collect()
    }

    /// Returns borrowed tuples `(descriptor, default_value, current_value)` for all modified settings.
    pub fn diff_modified_entries(&self) -> Vec<(&SettingDescriptor, &SettingValue, &SettingValue)> {
        self.entries
            .iter()
            .filter(|e| e.is_modified())
            .map(|e| (e, &e.default_value, &e.current_value))
            .collect()
    }

    /// Resets a single setting back to its schema default value (refused if locked by mandatory policy).
    pub fn reset_to_default(&mut self, key: &str) -> Result<HotReloadEvent, RegistryError> {
        let default_val = self
            .get(key)
            .ok_or_else(|| RegistryError::KeyNotFound(key.to_string()))?
            .default_value
            .clone();
        self.set(key, default_val)
    }

    /// Resets all modified, non-policy-locked settings inside a single [`SettingCategory`]
    /// back to their factory defaults and returns the count reset.
    pub fn reset_category(&mut self, category: SettingCategory) -> usize {
        let mut reset_count = 0usize;
        let mut hot_reload_events = Vec::new();
        for entry in &mut self.entries {
            if entry.category != category
                || !entry.is_modified()
                || self.mandatory_locked_keys.contains(&entry.key)
            {
                continue;
            }
            reset_count += 1;
            self.recommended_applied_values.remove(&entry.key);
            let new_value = entry.default_value.clone();
            let old_value = std::mem::replace(&mut entry.current_value, new_value.clone());
            if entry.hot_reloadable {
                hot_reload_events.push(HotReloadEvent {
                    key: entry.key.clone(),
                    category: entry.category,
                    subsystem: entry.subsystem,
                    old_value,
                    new_value,
                    chromium_cli_arg: entry.to_chromium_cli_arg(),
                    requires_restart: false,
                });
            } else {
                self.pending_restart_keys.insert(entry.key.clone());
            }
        }
        for evt in &hot_reload_events {
            for hook in &self.hot_reload_hooks {
                hook(evt);
            }
        }
        reset_count
    }

    /// Resets all modified, non-policy-locked settings back to their factory defaults, firing
    /// hot-reload hooks only for hot-reloadable settings (and recording restart requirements for
    /// the rest), and returns the total count reset.
    pub fn reset_all_to_defaults(&mut self) -> usize {
        let mut reset_count = 0usize;
        let mut hot_reload_events = Vec::new();
        for entry in &mut self.entries {
            if entry.is_modified() && !self.mandatory_locked_keys.contains(&entry.key) {
                reset_count += 1;
                self.recommended_applied_values.remove(&entry.key);
                let new_value = entry.default_value.clone();
                let old_value = std::mem::replace(&mut entry.current_value, new_value.clone());
                if entry.hot_reloadable {
                    hot_reload_events.push(HotReloadEvent {
                        key: entry.key.clone(),
                        category: entry.category,
                        subsystem: entry.subsystem,
                        old_value,
                        new_value,
                        chromium_cli_arg: entry.to_chromium_cli_arg(),
                        requires_restart: false,
                    });
                } else {
                    self.pending_restart_keys.insert(entry.key.clone());
                }
            }
        }
        for evt in &hot_reload_events {
            for hook in &self.hot_reload_hooks {
                hook(evt);
            }
        }
        reset_count
    }

    /// Collects all active Chromium command-line switches generated by the registry.
    pub fn compile_chromium_command_line_switches(&self) -> Vec<String> {
        self.entries
            .iter()
            .filter_map(|e| e.to_chromium_cli_arg())
            .collect()
    }

    /// Performs a virtualized fuzzy search across all 2,500+ settings for 200Hz+ UI rendering.
    pub fn query_virtualized<'a>(
        &'a self,
        category_filter: Option<SettingCategory>,
        search_query: &str,
        scroll_offset_px: usize,
        viewport_height_px: usize,
        row_height_px: usize,
    ) -> VirtualizedViewport<'a> {
        compute_virtualized_viewport(
            &self.entries,
            category_filter,
            search_query,
            scroll_offset_px,
            viewport_height_px,
            row_height_px,
            4,
        )
    }

    /// Performs a virtualized fuzzy search with an optional `modified_only` filter.
    pub fn query_virtualized_filtered<'a>(
        &'a self,
        category: Option<SettingCategory>,
        query: &str,
        modified_only: bool,
        scroll_offset_px: usize,
        viewport_height_px: usize,
        row_height_px: usize,
    ) -> VirtualizedViewport<'a> {
        compute_virtualized_viewport_filtered(
            &self.entries,
            category,
            query,
            modified_only,
            scroll_offset_px,
            viewport_height_px,
            row_height_px,
            4,
        )
    }

    /// Exports modified or all settings to a TOML configuration document.
    pub fn export_toml(&self, only_modified: bool) -> Result<String, RegistryError> {
        let snap = TomlSettingsSnapshot::from_entries(&self.entries, only_modified);
        Ok(snap.to_toml_string()?)
    }

    /// Imports and applies all valid setting overrides from a TOML document, skipping obsolete,
    /// policy-locked, or invalid keys without aborting the remaining user settings.
    pub fn import_toml(&mut self, toml_str: &str) -> Result<usize, RegistryError> {
        let snap = TomlSettingsSnapshot::from_toml_str(toml_str)?;
        let mut applied = 0;
        for (k, v) in snap.overrides {
            if self.set(&k, v).is_ok() {
                applied += 1;
            }
        }
        Ok(applied)
    }

    /// Exports modified or all settings to a pretty-printed JSON snapshot document.
    pub fn export_json(&self, modified_only: bool) -> Result<String, String> {
        let mut overrides = BTreeMap::new();
        for entry in &self.entries {
            if !modified_only || entry.is_modified() {
                overrides.insert(entry.key.clone(), entry.current_value.clone());
            }
        }
        let snapshot = JsonSettingsSnapshot {
            version: "1.0.0".to_string(),
            modified_only,
            count: overrides.len(),
            overrides,
        };
        serde_json::to_string_pretty(&snapshot)
            .map_err(|e| format!("Failed to serialize settings JSON: {}", e))
    }

    /// Imports and applies all valid setting overrides from a JSON snapshot (either the
    /// structured envelope produced by [`Self::export_json`] or a flat `{"key": value}` map),
    /// skipping unknown, invalid, or policy-locked keys without aborting valid overrides.
    pub fn import_json(&mut self, json: &str) -> Result<usize, String> {
        let root: JsonValue =
            serde_json::from_str(json).map_err(|e| format!("Failed to parse settings JSON: {}", e))?;

        let Some(obj) = root.as_object() else {
            return Err("Settings JSON root must be an object".to_string());
        };

        let map_obj = match obj.get("overrides").and_then(JsonValue::as_object) {
            Some(overrides_map) => overrides_map,
            None => obj,
        };

        let mut applied = 0usize;
        for (key, raw_val) in map_obj {
            let Some(&idx) = self.key_to_index.get(key) else {
                continue;
            };
            let Ok(parsed_val) = json_value_to_setting_value(raw_val) else {
                continue;
            };
            let coerced = coerce_value_for_target(&self.entries[idx].default_value, &parsed_val);
            if self.set(key, coerced).is_ok() {
                applied += 1;
            }
        }

        Ok(applied)
    }

    /// Exports settings to a transactional SQLite SQL script.
    pub fn export_sqlite_sql(&self, only_modified: bool) -> String {
        export_sqlite_transaction_sql(&self.entries, only_modified)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn test_registry_exceeds_2000_settings_and_category_minimums() {
        let registry = SettingsRegistry::new();
        assert!(
            registry.len() >= 2000,
            "Expected >= 2000 settings, got {}",
            registry.len()
        );

        let sec = registry.count_by_category(SettingCategory::SecurityHardening);
        let priv_af = registry.count_by_category(SettingCategory::PrivacyAntiFingerprinting);
        let net = registry.count_by_category(SettingCategory::NetworkDnsHttp3);
        let mullvad = registry.count_by_category(SettingCategory::MullvadWireGuard);
        let gpu = registry.count_by_category(SettingCategory::RenderingGpuPerformance);
        let vault = registry.count_by_category(SettingCategory::PasswordManagerCrypto);
        let media = registry.count_by_category(SettingCategory::MediaAudioVideo);
        let ui = registry.count_by_category(SettingCategory::ThemesCursorsUiUx);

        assert!(sec >= 400, "SecurityHardening required 400+, got {}", sec);
        assert!(priv_af >= 350, "PrivacyAntiFingerprinting required 350+, got {}", priv_af);
        assert!(net >= 300, "NetworkDnsHttp3 required 300+, got {}", net);
        assert!(mullvad >= 150, "MullvadWireGuard required 150+, got {}", mullvad);
        assert!(gpu >= 300, "RenderingGpuPerformance required 300+, got {}", gpu);
        assert!(vault >= 150, "PasswordManagerCrypto required 150+, got {}", vault);
        assert!(media >= 150, "MediaAudioVideo required 150+, got {}", media);
        assert!(ui >= 250, "ThemesCursorsUiUx required 250+, got {}", ui);

        // Ensure all setting keys are 100% unique
        assert_eq!(registry.key_to_index.len(), registry.len());
    }

    #[test]
    fn test_hot_reload_and_toml_roundtrip() {
        let mut registry = SettingsRegistry::new();
        let events_fired = Arc::new(AtomicUsize::new(0));
        let events_clone = Arc::clone(&events_fired);

        registry.register_hot_reload_hook(Arc::new(move |_evt| {
            events_clone.fetch_add(1, Ordering::SeqCst);
        }));

        registry
            .set("media.audio.volume_boost_percent", SettingValue::Float(350.0))
            .expect("Valid 350% volume boost");
        assert_eq!(events_fired.load(Ordering::SeqCst), 1);

        // Out-of-bounds constraint violation (> 400%)
        assert!(registry
            .set("media.audio.volume_boost_percent", SettingValue::Float(450.0))
            .is_err());

        let toml_out = registry.export_toml(true).expect("Export TOML");
        assert!(toml_out.contains("media.audio.volume_boost_percent"));

        let mut second_registry = SettingsRegistry::new();
        let count = second_registry.import_toml(&toml_out).expect("Import TOML");
        assert_eq!(count, 1);
        assert_eq!(
            second_registry
                .get("media.audio.volume_boost_percent")
                .unwrap()
                .current_value,
            SettingValue::Float(350.0)
        );
    }

    #[test]
    fn test_virtualized_fuzzy_search() {
        let registry = SettingsRegistry::new();
        let vp = registry.query_virtualized(None, "mullvad daita", 0, 600, 54);
        assert!(vp.total_matching_items >= 5);
        assert!(!vp.visible_slice.is_empty());
        assert!(vp.visible_slice[0].key.contains("daita"));
    }

    #[test]
    fn test_hot_reload_gated_by_hot_reloadable_flag() {
        let mut registry = SettingsRegistry::new();
        let fired_keys = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let fired_clone = Arc::clone(&fired_keys);

        registry.register_hot_reload_hook(Arc::new(move |evt| {
            fired_clone.lock().unwrap().push(evt.key.clone());
        }));

        // Non-hot-reloadable setting must NOT trigger hook and must record pending restart.
        let evt_restart = registry
            .set("security.sandbox.level", SettingValue::Int(2))
            .expect("Valid sandbox level");
        assert!(evt_restart.requires_restart);
        assert!(fired_keys.lock().unwrap().is_empty());
        assert!(registry.requires_restart());
        assert_eq!(
            registry.pending_restart_keys(),
            vec!["security.sandbox.level".to_string()]
        );

        // Hot-reloadable setting MUST trigger hook and must NOT add to pending restart keys.
        let evt_live = registry
            .set_value("media.audio.volume_boost_percent", SettingValue::Float(250.0))
            .expect("Valid volume boost");
        assert!(!evt_live.requires_restart);
        assert_eq!(
            *fired_keys.lock().unwrap(),
            vec!["media.audio.volume_boost_percent".to_string()]
        );
        assert_eq!(
            registry.pending_restart_keys(),
            vec!["security.sandbox.level".to_string()]
        );

        // Resetting all restores both settings, only firing hook for the hot-reloadable one.
        registry.clear_pending_restart();
        fired_keys.lock().unwrap().clear();
        let reset_count = registry.reset_all_to_defaults();
        assert_eq!(reset_count, 2);
        assert_eq!(
            *fired_keys.lock().unwrap(),
            vec!["media.audio.volume_boost_percent".to_string()]
        );
        assert_eq!(
            registry.pending_restart_keys(),
            vec!["security.sandbox.level".to_string()]
        );
    }

    #[test]
    fn test_set_value_and_import_toml_reject_malicious_values() {
        let mut registry = SettingsRegistry::new();

        // Direct set / set_value rejections
        assert!(registry
            .set_value(
                "network.proxy.global_socks5_endpoint",
                SettingValue::Text("socks5h://10.64.0.1:1080 --no-sandbox".into()),
            )
            .is_err());
        assert!(registry
            .set_value(
                "vault.storage.file_path",
                SettingValue::Text("../../../etc/passwd".into()),
            )
            .is_err());
        assert!(registry
            .set_value(
                "mullvad.api.endpoint_url",
                SettingValue::Text("javascript:alert(1)".into()),
            )
            .is_err());
        assert!(registry
            .set_value(
                "privacy.user_agent.uniform_frozen_string",
                SettingValue::Text("Mozilla/5.0\r\n--no-sandbox".into()),
            )
            .is_err());

        // TOML import skips malicious overrides while still applying safe ones
        let malicious_toml = r#"
version = "1.0.0"

[overrides."network.proxy.global_socks5_endpoint"]
type = "Text"
value = "socks5h://10.64.0.1:1080 --disable-web-security"

[overrides."vault.storage.file_path"]
type = "Text"
value = "../../etc/shadow"

[overrides."mullvad.api.endpoint_url"]
type = "Text"
value = "file:///etc/passwd"

[overrides."network.dns.primary_doq_endpoint"]
type = "Text"
value = "quic://dns.quad9.net:853"
"#;
        let applied = registry.import_toml(malicious_toml).expect("Parse TOML");
        assert_eq!(applied, 1);
        assert_eq!(
            registry.get("network.dns.primary_doq_endpoint").unwrap().current_value,
            SettingValue::Text("quic://dns.quad9.net:853".into())
        );
        assert_eq!(
            registry.get("network.proxy.global_socks5_endpoint").unwrap().current_value,
            SettingValue::Text(String::new())
        );
    }

    #[test]
    fn test_compiled_chromium_switches_are_safe_and_accurate() {
        let registry = SettingsRegistry::new();
        let switches = registry.compile_chromium_command_line_switches();

        assert!(
            !switches.iter().any(|s| s.ends_with("=false")),
            "Must never emit `=false` for boolean switches"
        );
        assert!(!switches.iter().any(|s| s == "--jitless" || s.starts_with("--jitless=")));
        assert!(
            !switches.iter().any(|s| s == "--proxy-server="),
            "Must never emit empty `--proxy-server=`"
        );
        assert!(
            switches.iter().any(|s| s == "--disk-cache-size=1073741824"),
            "Expected 1024 MiB disk-cache-size to be converted to 1073741824 bytes"
        );
        for sw in &switches {
            assert!(!sw.contains('\0') && !sw.contains('\r') && !sw.contains('\n'));
        }
    }

    #[test]
    fn test_roadmap_nine_categories_exceed_2400_keys_and_all_namespaces_present() {
        let registry = SettingsRegistry::new();
        assert_eq!(SettingCategory::ALL.len(), 9);
        assert_eq!(SettingCategory::all().len(), 9);
        assert!(SettingCategory::all().contains(&SettingCategory::ExtensionsPwaEcosystem));
        assert_eq!(registry.category_counts().len(), 9);

        assert!(
            registry.len() > 2400,
            "Expected > 2,400 settings after Master Roadmap expansion, got {}",
            registry.len()
        );

        let ext_count = registry.count_by_category(SettingCategory::ExtensionsPwaEcosystem);
        assert!(
            ext_count >= 45,
            "ExtensionsPwaEcosystem required >= 45 settings, got {}",
            ext_count
        );

        // Verify every single Master Roadmap namespace is populated and reachable
        for expected_prefix in [
            "extensions.",
            "userscripts.",
            "pwa.",
            "bookmarks.",
            "collections.",
            "notes.",
            "reading_list.",
            "reader.",
            "pdf.",
            "capture.",
            "print.",
            "page_tools.",
            "downloads.",
            "omnibox.",
            "search.",
            "history.",
            "session.",
            "shields.",
            "privacy.gpc.",
            "privacy.forgetful.",
            "permissions.",
            "devtools.",
            "performance.",
            "profiles.",
            "translate.",
            "accessibility.",
            "sync.",
            "ui.sidebar.",
            "ui.split_view.",
            "ui.command_palette.",
            "ui.command_chains.",
            "ui.gestures.",
            "ui.boosts.",
            "ui.custom_css.",
            "ui.ntp.",
            "ui.statusbar.",
            "ui.address_bar.",
            "ui.layout.",
            "ui.window.",
            "ui.theme.color_scheme_mode",
            "ui.theme.schedule.",
            "ui.theme.adaptive_site_accent.",
            "vault.trash.",
            "vault.biometric.",
            "vault.pin.",
            "vault.payment.",
            "vault.alias.",
        ] {
            assert!(
                registry
                    .all_entries()
                    .iter()
                    .any(|e| e.key.starts_with(expected_prefix)),
                "Missing expected Master Roadmap namespace prefix: {}",
                expected_prefix
            );
        }

        // Verify all new TargetSubsystem variants are represented in the live catalog
        for subsystem in [
            TargetSubsystem::ExtensionRuntime,
            TargetSubsystem::UserscriptEngine,
            TargetSubsystem::PwaHost,
            TargetSubsystem::SyncEngine,
            TargetSubsystem::TranslateEngine,
            TargetSubsystem::AccessibilityEngine,
            TargetSubsystem::DevToolsEngine,
        ] {
            assert!(
                registry.all_entries().iter().any(|e| e.subsystem == subsystem),
                "Subsystem {:?} has no registered settings",
                subsystem
            );
            assert!(!subsystem.slug().is_empty());
        }
    }

    #[test]
    fn test_diff_modified_settings_reset_category_and_virtualized_filtered() {
        let mut registry = SettingsRegistry::new();
        assert!(registry.diff_modified_settings().is_empty());

        registry
            .set("extensions.developer_mode.enabled", SettingValue::Bool(true))
            .unwrap();
        registry
            .set("pwa.window.tabbed_application_mode", SettingValue::Bool(true))
            .unwrap();
        registry
            .set("downloads.parallel.max_segments_per_file", SettingValue::Int(16))
            .unwrap();

        let diffs = registry.diff_modified_settings();
        assert_eq!(diffs.len(), 3);
        let serialized_diffs = serde_json::to_string(&diffs).expect("SettingDiffRow serializes to JSON");
        assert!(serialized_diffs.contains("extensions.developer_mode.enabled"));
        assert_eq!(registry.diff_modified_entries().len(), 3);

        // query_virtualized_filtered with modified_only = true returns strictly modified settings
        let vp_all_mod = registry.query_virtualized_filtered(None, "", true, 0, 800, 54);
        assert_eq!(vp_all_mod.total_matching_items, 3);

        let vp_ext_mod = registry.query_virtualized_filtered(
            Some(SettingCategory::ExtensionsPwaEcosystem),
            "",
            true,
            0,
            800,
            54,
        );
        assert_eq!(vp_ext_mod.total_matching_items, 2);

        // reset_category resets only ExtensionsPwaEcosystem, leaving NetworkDnsHttp3 intact
        let reset_ext = registry.reset_category(SettingCategory::ExtensionsPwaEcosystem);
        assert_eq!(reset_ext, 2);
        assert_eq!(registry.diff_modified_settings().len(), 1);
        assert_eq!(
            registry.diff_modified_settings()[0].key,
            "downloads.parallel.max_segments_per_file"
        );
    }

    #[test]
    fn test_export_json_and_import_json_roundtrip_and_security() {
        let mut registry = SettingsRegistry::new();
        registry
            .set("ui.theme.color_scheme_mode", SettingValue::Text("scheduled".into()))
            .unwrap();
        registry
            .set("accessibility.focus_ring.color_hex", SettingValue::ColorHex("#FF00AA".into()))
            .unwrap();
        registry
            .set("performance.limiter.ram_hard_cap_mb", SettingValue::Int(16384))
            .unwrap();

        let json_out = registry.export_json(true).expect("Export JSON");
        assert!(json_out.contains("\"count\": 3"));
        assert!(json_out.contains("ui.theme.color_scheme_mode"));

        let mut second = SettingsRegistry::new();
        let imported = second.import_json(&json_out).expect("Import JSON snapshot");
        assert_eq!(imported, 3);
        assert_eq!(
            second.get("ui.theme.color_scheme_mode").unwrap().current_value,
            SettingValue::Text("scheduled".into())
        );
        assert_eq!(
            second.get("accessibility.focus_ring.color_hex").unwrap().current_value,
            SettingValue::ColorHex("#FF00AA".into())
        );

        // Flat JSON import with scalar coercion + malicious value rejection
        let flat_json = r##"{
            "ui.gestures.trail_color_hex": "#00FFCC",
            "accessibility.tts.speech_rate": 2,
            "vault.storage.file_path": "../../etc/passwd",
            "unknown.obsolete.key": true
        }"##;
        let flat_applied = second.import_json(flat_json).expect("Import flat JSON");
        assert_eq!(flat_applied, 2);
        assert_eq!(
            second.get("ui.gestures.trail_color_hex").unwrap().current_value,
            SettingValue::ColorHex("#00FFCC".into())
        );
        assert_eq!(
            second.get("accessibility.tts.speech_rate").unwrap().current_value,
            SettingValue::Float(2.0)
        );
        assert_ne!(
            second.get("vault.storage.file_path").unwrap().current_value,
            SettingValue::Text("../../etc/passwd".into())
        );

        // Malformed JSON must return Err
        assert!(second.import_json("{ invalid json").is_err());
    }

    #[test]
    fn test_policy_engine_application_and_mandatory_locking() {
        let mut registry = SettingsRegistry::new();
        let mut policy = PolicyEngine::new();

        policy
            .load_json_str(
                r#"{
                    "devtools.cdp.remote_debugging_enabled": {
                        "value": false,
                        "enforcement": "Mandatory",
                        "scope": "machine"
                    },
                    "security.sandbox.level": {
                        "value": 3,
                        "enforcement": "Mandatory",
                        "scope": "machine"
                    },
                    "ui.sidebar.position": {
                        "value": "right",
                        "enforcement": "Recommended",
                        "scope": "user"
                    },
                    "vault.storage.file_path": {
                        "value": "../../../etc/shadow",
                        "enforcement": "Mandatory",
                        "scope": "machine"
                    }
                }"#,
                PolicySource::LinuxManagedJson,
                PolicyEnforcement::Mandatory,
                "machine",
            )
            .expect("Parse policy JSON");

        let applied = policy.apply_to_registry(&mut registry);
        // 3 valid policies applied; malicious path traversal policy must be rejected
        assert_eq!(applied, 3);
        assert!(registry.is_policy_locked("devtools.cdp.remote_debugging_enabled"));
        assert!(registry.is_policy_locked("security.sandbox.level"));
        assert!(!registry.is_policy_locked("ui.sidebar.position"));
        assert!(!registry.is_policy_locked("vault.storage.file_path"));

        // Mandatory keys reject set, reset_to_default, reset_category, reset_all, import_json
        assert!(matches!(
            registry.set("security.sandbox.level", SettingValue::Int(1)),
            Err(RegistryError::PolicyLocked { .. })
        ));
        assert!(matches!(
            registry.reset_to_default("security.sandbox.level"),
            Err(RegistryError::PolicyLocked { .. })
        ));
        assert_eq!(registry.reset_category(SettingCategory::SecurityHardening), 0);
        assert_eq!(
            registry.get("security.sandbox.level").unwrap().current_value,
            SettingValue::Int(3)
        );

        // Diff reports locked_by_policy = true for modified mandatory setting
        let diffs = registry.diff_modified_settings();
        let sandbox_diff = diffs
            .iter()
            .find(|r| r.key == "security.sandbox.level")
            .expect("sandbox diff row");
        assert!(sandbox_diff.locked_by_policy);

        // Recommended policy WAS applied initially, and user CAN freely override it
        assert_eq!(
            registry.get("ui.sidebar.position").unwrap().current_value,
            SettingValue::Text("right".into())
        );
        registry
            .set("ui.sidebar.position", SettingValue::Text("left".into()))
            .expect("User may override Recommended policy");
        assert_eq!(
            registry.get("ui.sidebar.position").unwrap().current_value,
            SettingValue::Text("left".into())
        );

        // reset_all_to_defaults never resets Mandatory-locked settings
        registry
            .set("downloads.parallel.max_segments_per_file", SettingValue::Int(12))
            .unwrap();
        let reset_n = registry.reset_all_to_defaults();
        assert_eq!(reset_n, 1);
        assert_eq!(
            registry.get("security.sandbox.level").unwrap().current_value,
            SettingValue::Int(3)
        );
    }

    #[test]
    fn test_flags_store_reexported_api_end_to_end() {
        let mut store = FlagsStore::new();
        assert!(store.len() >= 35);
        assert!(store.get("enable-unsafe-webgpu").is_some());
        assert!(store.get("singularity-wgpu-shaders-200hz").is_some());
        assert!(store.get("singularity-zero-knowledge-sync").is_some());
        assert!(store.get("pwa-window-controls-overlay").is_some());
        assert!(store.get("singularity-remote-debugging-pipe-mux").is_some());

        store.set_flag("enable-unsafe-webgpu", 1).unwrap();
        store.set_flag("singularity-hover-preconnect-0rtt", 1).unwrap();
        assert!(store.has_pending_restart());

        let (en, _dis, sw) = store.compile_chromium_args();
        assert!(en.contains(&"WebGPU".to_string()));
        assert!(sw.contains(&"--enable-unsafe-webgpu".to_string()));
        assert!(sw.contains(&"--singularity-hover-preconnect-0rtt".to_string()));

        store.clear_pending_restart();
        assert!(!store.has_pending_restart());

        // Resetting after boot differs from boot state -> pending restart is true again
        store.reset_all();
        assert!(store.has_pending_restart());
    }
}
