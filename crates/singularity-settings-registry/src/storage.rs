//! Serialization & Persistence Engine (TOML & SQLite SQL Snapshot Export/Import)
//! for the Singularity 2,165+ Settings Registry.

use crate::schema::{SettingEntry, SettingValue};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Compact TOML representation storing either user-modified overrides or the full registry.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TomlSettingsSnapshot {
    pub version: String,
    pub overrides: BTreeMap<String, SettingValue>,
}

impl TomlSettingsSnapshot {
    pub fn from_entries(entries: &[SettingEntry], only_modified: bool) -> Self {
        let mut overrides = BTreeMap::new();
        for entry in entries {
            if !only_modified || entry.is_modified() {
                overrides.insert(entry.key.clone(), entry.current_value.clone());
            }
        }
        Self {
            version: "1.0.0".to_string(),
            overrides,
        }
    }

    pub fn to_toml_string(&self) -> Result<String, toml::ser::Error> {
        toml::to_string_pretty(self)
    }

    pub fn from_toml_str(raw: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(raw)
    }
}

fn escape_sql_literal(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '\0' => {}
            '\'' => out.push_str("''"),
            '\r' | '\n' => out.push(' '),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

/// Generates a deterministic SQLite relational transaction script for persisting all settings.
/// Indexes rows by their stable text `key` (`TEXT PRIMARY KEY`) instead of an unstable
/// catalog-order numeric ID so catalog updates never corrupt unrelated settings on upsert.
pub fn export_sqlite_transaction_sql(entries: &[SettingEntry], only_modified: bool) -> String {
    let mut selected: Vec<&SettingEntry> = entries
        .iter()
        .filter(|e| !only_modified || e.is_modified())
        .collect();
    selected.sort_by(|a, b| a.key.cmp(&b.key));

    let mut sql = String::with_capacity(selected.len() * 160 + 256);
    sql.push_str("BEGIN TRANSACTION;\n");
    sql.push_str(
        "CREATE TABLE IF NOT EXISTS singularity_settings (\n\
         key TEXT PRIMARY KEY NOT NULL,\n\
         category TEXT NOT NULL,\n\
         subsystem TEXT NOT NULL,\n\
         value_json TEXT NOT NULL,\n\
         is_modified INTEGER NOT NULL\n\
         );\n",
    );
    sql.push_str("CREATE INDEX IF NOT EXISTS idx_singularity_settings_cat ON singularity_settings(category);\n");

    for entry in selected {
        let raw_json =
            serde_json::to_string(&entry.current_value).unwrap_or_else(|_| "\"\"".to_string());
        let val_json = escape_sql_literal(&raw_json);
        let key_escaped = escape_sql_literal(&entry.key);
        let modified_flag = if entry.is_modified() { 1 } else { 0 };
        sql.push_str(&format!(
            "INSERT INTO singularity_settings (key, category, subsystem, value_json, is_modified) VALUES ('{}', '{}', '{}', '{}', {}) ON CONFLICT(key) DO UPDATE SET category = excluded.category, subsystem = excluded.subsystem, value_json = excluded.value_json, is_modified = excluded.is_modified;\n",
            key_escaped,
            entry.category.slug(),
            entry.subsystem.slug(),
            val_json,
            modified_flag
        ));
    }

    sql.push_str("COMMIT;\n");
    sql
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{SettingCategory, TargetSubsystem, ValueConstraint};

    fn make_entry(id: usize, key: &str, default: SettingValue, current: SettingValue) -> SettingEntry {
        SettingEntry {
            id,
            key: key.to_string(),
            category: SettingCategory::NetworkDnsHttp3,
            subsystem: TargetSubsystem::RustNetworkPool,
            title: key.to_string(),
            description: "desc".to_string(),
            default_value: default,
            current_value: current,
            constraint: ValueConstraint::Unconstrained,
            chromium_switch: None,
            hot_reloadable: true,
        }
    }

    #[test]
    fn test_sqlite_export_uses_stable_text_primary_key_and_is_id_independent() {
        let v1_entries = vec![
            make_entry(
                1,
                "network.dns.primary_doq_endpoint",
                SettingValue::Text("quic://a.example:853".into()),
                SettingValue::Text("quic://custom.example:853".into()),
            ),
            make_entry(
                2,
                "network.http3.quic_enabled",
                SettingValue::Bool(true),
                SettingValue::Bool(false),
            ),
        ];

        // Simulate a future catalog release where IDs shifted and order changed.
        let v2_entries = vec![
            make_entry(
                502,
                "network.http3.quic_enabled",
                SettingValue::Bool(true),
                SettingValue::Bool(false),
            ),
            make_entry(
                199,
                "network.dns.primary_doq_endpoint",
                SettingValue::Text("quic://a.example:853".into()),
                SettingValue::Text("quic://custom.example:853".into()),
            ),
        ];

        let sql_v1 = export_sqlite_transaction_sql(&v1_entries, true);
        let sql_v2 = export_sqlite_transaction_sql(&v2_entries, true);

        assert!(sql_v1.contains("key TEXT PRIMARY KEY NOT NULL"));
        assert!(!sql_v1.contains("id INTEGER PRIMARY KEY"));
        assert!(!sql_v1.contains("INSERT OR REPLACE"));
        assert!(sql_v1.contains("ON CONFLICT(key) DO UPDATE"));
        assert_eq!(sql_v1, sql_v2, "SQLite export must be invariant to numeric catalog ID shifts");
    }
}
