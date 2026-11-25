//! `singularity-settings-registry` — The 2,000+ Power-User Configuration Engine
//! powering `singularity://settings` and `singularity://flags`.

pub mod catalog;
pub mod macros;
pub mod schema;
pub mod search;
pub mod storage;

use crate::catalog::build_full_settings_catalog;
use crate::schema::{HotReloadEvent, SettingCategory, SettingEntry, SettingValue};
use crate::search::{compute_virtualized_viewport, VirtualizedViewport};
use crate::storage::{export_sqlite_transaction_sql, TomlSettingsSnapshot};
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("Setting key not found: {0}")]
    KeyNotFound(String),
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

/// High-performance, indexed configuration registry holding 2,165+ granular browser settings.
pub struct SettingsRegistry {
    entries: Vec<SettingEntry>,
    key_to_index: HashMap<String, usize>,
    hot_reload_hooks: Vec<HotReloadCallback>,
    pending_restart_keys: BTreeSet<String>,
}

impl Default for SettingsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SettingsRegistry {
    /// Initializes the full 2,165+ settings registry with O(1) key lookup tables.
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
        }
    }

    /// Total number of registered settings (guaranteed >= 2,000).
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

    /// Returns a summary map of setting counts across all 8 mandatory categories.
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

    /// Mutates a setting value after verifying type safety, range/enum constraints, and security rules.
    /// Fires live hot-reload hooks only when `entry.hot_reloadable == true`; otherwise records the
    /// setting as requiring a restart without invoking hot-reload hooks.
    pub fn set(&mut self, key: &str, new_value: SettingValue) -> Result<HotReloadEvent, RegistryError> {
        let &idx = self
            .key_to_index
            .get(key)
            .ok_or_else(|| RegistryError::KeyNotFound(key.to_string()))?;

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

    /// Alias for [`Self::set`] that validates and applies a setting value.
    pub fn set_value(&mut self, key: &str, new_value: SettingValue) -> Result<HotReloadEvent, RegistryError> {
        self.set(key, new_value)
    }

    /// Resets a single setting back to its schema default value.
    pub fn reset_to_default(&mut self, key: &str) -> Result<HotReloadEvent, RegistryError> {
        let default_val = self
            .get(key)
            .ok_or_else(|| RegistryError::KeyNotFound(key.to_string()))?
            .default_value
            .clone();
        self.set(key, default_val)
    }

    /// Resets all modified settings back to their factory defaults, firing hot-reload hooks
    /// only for hot-reloadable settings (and recording restart requirements for the rest),
    /// and returns the total count reset.
    pub fn reset_all_to_defaults(&mut self) -> usize {
        let mut reset_count = 0usize;
        let mut hot_reload_events = Vec::new();
        for entry in &mut self.entries {
            if entry.is_modified() {
                reset_count += 1;
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

    /// Performs a virtualized fuzzy search across all 2,165+ settings for 200Hz+ UI rendering.
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

    /// Exports modified or all settings to a TOML configuration document.
    pub fn export_toml(&self, only_modified: bool) -> Result<String, RegistryError> {
        let snap = TomlSettingsSnapshot::from_entries(&self.entries, only_modified);
        Ok(snap.to_toml_string()?)
    }

    /// Imports and applies all valid setting overrides from a TOML document, skipping obsolete
    /// or invalid keys without aborting the remaining user settings.
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
}
