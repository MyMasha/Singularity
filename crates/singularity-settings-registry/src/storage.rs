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
pub fn export_sqlite_transaction_sql(entries: &[SettingEntry], only_modified: bool) -> String {
    let mut sql = String::with_capacity(entries.len() * 128);
    sql.push_str("BEGIN TRANSACTION;\n");
    sql.push_str(
        "CREATE TABLE IF NOT EXISTS singularity_settings (\n\
         id INTEGER PRIMARY KEY,\n\
         setting_key TEXT UNIQUE NOT NULL,\n\
         category TEXT NOT NULL,\n\
         subsystem TEXT NOT NULL,\n\
         value_json TEXT NOT NULL,\n\
         is_modified INTEGER NOT NULL\n\
         );\n",
    );
    sql.push_str("CREATE INDEX IF NOT EXISTS idx_singularity_settings_cat ON singularity_settings(category);\n");

    for entry in entries {
        if only_modified && !entry.is_modified() {
            continue;
        }
        let raw_json =
            serde_json::to_string(&entry.current_value).unwrap_or_else(|_| "\"\"".to_string());
        let val_json = escape_sql_literal(&raw_json);
        let key_escaped = escape_sql_literal(&entry.key);
        let modified_flag = if entry.is_modified() { 1 } else { 0 };
        sql.push_str(&format!(
            "INSERT OR REPLACE INTO singularity_settings (id, setting_key, category, subsystem, value_json, is_modified) VALUES ({}, '{}', '{}', '{}', '{}', {});\n",
            entry.id,
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
