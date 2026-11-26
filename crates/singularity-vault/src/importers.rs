//! Multi-Manager Vault Importers (12 Formats with Auto-Detection), Pure-Rust RFC 4180 CSV Parser,
//! Conflict Preview, Configurable Atomic Merge (`Skip` / `Overwrite` / `KeepBoth`),
//! and Exporters (CSV, Plain JSON, and Password-Protected Encrypted JSON).

use crate::crypto::{
    generate_salt_and_xnonce, Argon2idConfig, DerivedVaultKey, VaultCryptoError,
};
use crate::cxf::{deserialize_cxf_json, import_cxf_to_vault_parts};
use crate::format::{
    CardPayload, CustomField, CustomFieldKind, IdentityPayload, LoginPayload, SecureNotePayload,
    VaultFolder, VaultItem, VaultItemKind, VaultPlaintextPayloadV2,
};
use crate::matcher::{extract_etld_plus_one, UriMatchRule, VaultUriEntry};
use crate::passkey::StoredPasskeyCredential;
use crate::payment::{detect_card_brand, CardBrand};
use crate::totp::{decode_base32_secret, format_otpauth_uri, parse_otpauth_uri, OtpAuthConfig};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use thiserror::Error;
use zeroize::Zeroize;

pub const SINGULARITY_ENCRYPTED_EXPORT_MAGIC: &str =
    "SINGULARITY-EXPORT-ENCRYPTED-V1-XCHACHA20-POLY1305";

#[derive(Debug, Error)]
pub enum ImportError {
    #[error("Unable to auto-detect import format: {0}")]
    UnknownFormat(String),
    #[error("Malformed CSV input: {0}")]
    InvalidCsv(String),
    #[error("Malformed JSON input: {0}")]
    InvalidJson(String),
    #[error("Encrypted export cryptographic error: {0}")]
    Crypto(#[from] VaultCryptoError),
}

/// Supported password manager import formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportFormat {
    ChromeCsv,
    FirefoxCsv,
    BitwardenJson,
    BitwardenCsv,
    OnePasswordCsv,
    KeePassCsv,
    ProtonPassCsv,
    ProtonPassJson,
    DashlaneCsv,
    LastPassCsv,
    SingularityJson,
    FidoCxf,
}

/// Strategy applied to conflicting items during atomic vault import.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictResolution {
    #[default]
    Skip,
    Overwrite,
    KeepBoth,
}

/// Conflict detected between an existing vault item and an incoming imported item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportConflict {
    pub existing_item_id: String,
    pub existing_name: String,
    pub incoming_item: VaultItem,
    pub reason: String,
}

/// Pre-commit analysis previewing additions, exact duplicates, and conflicts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportPreview {
    pub format: ImportFormat,
    pub new_items: Vec<VaultItem>,
    pub duplicates: Vec<VaultItem>,
    pub conflicts: Vec<ImportConflict>,
    pub folders: Vec<VaultFolder>,
    pub passkeys: Vec<StoredPasskeyCredential>,
    pub warnings: Vec<String>,
}

/// Summary of mutations committed atomically by [`apply_import_atomic`].
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ImportApplyResult {
    pub added: usize,
    pub overwritten: usize,
    pub skipped: usize,
    pub kept_both: usize,
    pub folders_added: usize,
    pub passkeys_added: usize,
}

// ============================================================================
// PURE-RUST RFC 4180 CSV PARSER & WRITER
// ============================================================================

/// Parses an RFC 4180 CSV document (supporting UTF-8 BOM, CRLF/LF, quoted fields with
/// embedded commas/newlines, and escaped `""` double quotes).
pub fn parse_csv_rfc4180(input: &str) -> Result<Vec<Vec<String>>, ImportError> {
    let cleaned = input.strip_prefix('\u{FEFF}').unwrap_or(input);
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut current_row: Vec<String> = Vec::new();
    let mut current_field = String::new();
    let mut in_quotes = false;
    let mut field_started = false;

    let chars: Vec<char> = cleaned.chars().collect();
    let mut i = 0usize;

    while i < chars.len() {
        let ch = chars[i];
        if in_quotes {
            if ch == '"' {
                if i + 1 < chars.len() && chars[i + 1] == '"' {
                    current_field.push('"');
                    i += 2;
                    continue;
                } else {
                    in_quotes = false;
                    i += 1;
                    continue;
                }
            } else {
                current_field.push(ch);
                i += 1;
                continue;
            }
        } else {
            match ch {
                '"' if !field_started => {
                    in_quotes = true;
                    field_started = true;
                    i += 1;
                }
                ',' => {
                    current_row.push(std::mem::take(&mut current_field));
                    field_started = false;
                    i += 1;
                }
                '\r' => {
                    if i + 1 < chars.len() && chars[i + 1] == '\n' {
                        i += 2;
                    } else {
                        i += 1;
                    }
                    current_row.push(std::mem::take(&mut current_field));
                    if !(current_row.len() == 1 && current_row[0].is_empty()) {
                        rows.push(std::mem::take(&mut current_row));
                    } else {
                        current_row.clear();
                    }
                    field_started = false;
                }
                '\n' => {
                    i += 1;
                    current_row.push(std::mem::take(&mut current_field));
                    if !(current_row.len() == 1 && current_row[0].is_empty()) {
                        rows.push(std::mem::take(&mut current_row));
                    } else {
                        current_row.clear();
                    }
                    field_started = false;
                }
                other => {
                    current_field.push(other);
                    field_started = true;
                    i += 1;
                }
            }
        }
    }

    if in_quotes {
        return Err(ImportError::InvalidCsv("Unterminated quoted CSV field".into()));
    }
    if field_started || !current_row.is_empty() {
        current_row.push(current_field);
        if !(current_row.len() == 1 && current_row[0].is_empty()) {
            rows.push(current_row);
        }
    }

    Ok(rows)
}

fn encode_csv_field_rfc4180(field: &str) -> String {
    if field.contains(',') || field.contains('"') || field.contains('\n') || field.contains('\r') {
        let escaped = field.replace('"', "\"\"");
        format!("\"{}\"", escaped)
    } else {
        field.to_string()
    }
}

fn encode_csv_row_rfc4180(fields: &[String]) -> String {
    fields
        .iter()
        .map(|f| encode_csv_field_rfc4180(f))
        .collect::<Vec<_>>()
        .join(",")
}

// ============================================================================
// FORMAT AUTO-DETECTION
// ============================================================================

/// Auto-detects the source password manager format from raw CSV or JSON content.
pub fn detect_import_format(input: &str) -> Result<ImportFormat, ImportError> {
    let trimmed = input.strip_prefix('\u{FEFF}').unwrap_or(input).trim();
    if trimmed.is_empty() {
        return Err(ImportError::UnknownFormat("Input is empty".into()));
    }

    if trimmed.starts_with('{') {
        let val: Value = serde_json::from_str(trimmed)
            .map_err(|e| ImportError::InvalidJson(e.to_string()))?;
        if val.get("accounts").and_then(|v| v.as_array()).is_some()
            && val.get("version").is_some()
        {
            return Ok(ImportFormat::FidoCxf);
        }
        if val.get("vaults").and_then(|v| v.as_object()).is_some() {
            return Ok(ImportFormat::ProtonPassJson);
        }
        if val.get("schema_version").is_some()
            || val.get("singularity_export_version").is_some()
            || val
                .get("magic")
                .and_then(|v| v.as_str())
                .map(|m| m.starts_with("SINGULARITY-"))
                .unwrap_or(false)
        {
            return Ok(ImportFormat::SingularityJson);
        }
        if val.get("items").and_then(|v| v.as_array()).is_some() {
            return Ok(ImportFormat::BitwardenJson);
        }
        return Err(ImportError::UnknownFormat(
            "Unrecognized JSON vault schema".into(),
        ));
    }

    let rows = parse_csv_rfc4180(trimmed)?;
    let header_row = rows
        .first()
        .ok_or_else(|| ImportError::UnknownFormat("Empty CSV input".into()))?;
    let headers: Vec<String> = header_row
        .iter()
        .map(|h| h.trim().to_ascii_lowercase())
        .collect();
    let has = |col: &str| headers.iter().any(|h| h == col);

    if has("login_username") && has("login_password") {
        return Ok(ImportFormat::BitwardenCsv);
    }
    if has("httprealm") || has("formactionorigin") || has("timepasswordchanged") {
        return Ok(ImportFormat::FirefoxCsv);
    }
    if has("grouping") && has("extra") && has("fav") {
        return Ok(ImportFormat::LastPassCsv);
    }
    if has("username2") || has("otpsecret") {
        return Ok(ImportFormat::DashlaneCsv);
    }
    if has("vault") && (has("totp") || has("email")) && has("password") {
        return Ok(ImportFormat::ProtonPassCsv);
    }
    if has("otpauth")
        || (has("title") && has("website") && has("password"))
        || (has("title") && has("archived") && has("url"))
    {
        return Ok(ImportFormat::OnePasswordCsv);
    }
    if (has("account") && has("login name") && has("web site"))
        || (has("group") && has("title") && has("username") && has("url"))
    {
        return Ok(ImportFormat::KeePassCsv);
    }
    if has("url") && has("username") && has("password") {
        return Ok(ImportFormat::ChromeCsv);
    }

    Err(ImportError::UnknownFormat(format!(
        "Unrecognized CSV header columns: {:?}",
        headers
    )))
}

// ============================================================================
// PER-FORMAT PARSERS
// ============================================================================

struct ParsedBundle {
    items: Vec<VaultItem>,
    folders: Vec<VaultFolder>,
    passkeys: Vec<StoredPasskeyCredential>,
    warnings: Vec<String>,
}

fn col_map(header: &[String]) -> HashMap<String, usize> {
    header
        .iter()
        .enumerate()
        .map(|(i, h)| (h.trim().to_ascii_lowercase(), i))
        .collect()
}

fn get_col<'a>(row: &'a [String], cols: &HashMap<String, usize>, names: &[&str]) -> &'a str {
    for &n in names {
        if let Some(&idx) = cols.get(n) {
            if let Some(val) = row.get(idx) {
                return val.trim();
            }
        }
    }
    ""
}

fn apply_totp_str(login: &mut LoginPayload, raw_totp: &str, warnings: &mut Vec<String>) {
    let trimmed = raw_totp.trim();
    if trimmed.is_empty() {
        return;
    }
    if trimmed.to_ascii_lowercase().starts_with("otpauth://") {
        match parse_otpauth_uri(trimmed) {
            Ok(cfg) => {
                login.totp_secret_base32 = Some(cfg.secret_base32.clone());
                login.totp_algorithm = cfg.algorithm;
                login.totp_digits = cfg.digits;
                login.totp_period_sec = cfg.period_sec;
                login.otp_kind = cfg.kind;
            }
            Err(e) => warnings.push(format!("Skipped malformed otpauth URI: {}", e)),
        }
    } else if decode_base32_secret(trimmed).is_ok() {
        login.totp_secret_base32 = Some(trimmed.to_ascii_uppercase());
    } else {
        warnings.push("Skipped invalid non-Base32 TOTP secret".into());
    }
}

fn get_or_create_folder(
    folders: &mut Vec<VaultFolder>,
    folder_name: &str,
    now_unix: u64,
) -> Option<String> {
    let trimmed = folder_name.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(existing) = folders
        .iter()
        .find(|f| f.name.eq_ignore_ascii_case(trimmed))
    {
        return Some(existing.id.clone());
    }
    let id = format!("folder-imp-{}", folders.len() + 1);
    folders.push(VaultFolder {
        id: id.clone(),
        name: trimmed.to_string(),
        parent_id: None,
        icon: None,
        color: None,
        revision: 1,
        updated_at_unix: now_unix,
    });
    Some(id)
}

fn make_login_item(
    idx: usize,
    prefix: &str,
    name: &str,
    url: &str,
    username: &str,
    password: &str,
    totp: &str,
    notes: &str,
    favorite: bool,
    folder_id: Option<String>,
    now_unix: u64,
    warnings: &mut Vec<String>,
) -> VaultItem {
    let resolved_name = if !name.trim().is_empty() {
        name.trim().to_string()
    } else if let Some(dom) = extract_etld_plus_one(url) {
        dom
    } else if !url.trim().is_empty() {
        url.trim().to_string()
    } else {
        format!("Imported Login {}", idx + 1)
    };

    let uris = if url.trim().is_empty() {
        Vec::new()
    } else {
        vec![VaultUriEntry::new(url.trim(), UriMatchRule::BaseDomain)]
    };

    let mut login = LoginPayload::default();
    login.username = username.to_string();
    login.password = password.to_string();
    login.uris = uris;
    login.notes = notes.to_string();
    apply_totp_str(&mut login, totp, warnings);

    let mut item = VaultItem::new(
        format!("{}-{}", prefix, idx + 1),
        resolved_name,
        VaultItemKind::Login(login),
        now_unix,
    );
    item.favorite = favorite;
    item.folder_id = folder_id;
    item
}

fn parse_csv_bundle(
    format: ImportFormat,
    input: &str,
    now_unix: u64,
) -> Result<ParsedBundle, ImportError> {
    let rows = parse_csv_rfc4180(input)?;
    if rows.is_empty() {
        return Err(ImportError::InvalidCsv("Empty CSV document".into()));
    }
    let cols = col_map(&rows[0]);
    let mut items = Vec::new();
    let mut folders = Vec::new();
    let mut warnings = Vec::new();

    for (idx, row) in rows.iter().skip(1).enumerate() {
        if row.iter().all(|c| c.trim().is_empty()) {
            continue;
        }
        match format {
            ImportFormat::ChromeCsv => {
                let name = get_col(row, &cols, &["name", "title"]);
                let url = get_col(row, &cols, &["url", "origin"]);
                let user = get_col(row, &cols, &["username"]);
                let pass = get_col(row, &cols, &["password"]);
                let note = get_col(row, &cols, &["note", "notes"]);
                let totp = get_col(row, &cols, &["totp"]);
                let folder = get_col(row, &cols, &["folder"]);
                let fav = matches!(
                    get_col(row, &cols, &["favorite"]).to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes"
                );
                let fid = get_or_create_folder(&mut folders, folder, now_unix);
                items.push(make_login_item(
                    idx,
                    "chrome",
                    name,
                    url,
                    user,
                    pass,
                    totp,
                    note,
                    fav,
                    fid,
                    now_unix,
                    &mut warnings,
                ));
            }
            ImportFormat::FirefoxCsv => {
                let url = get_col(row, &cols, &["url"]);
                let user = get_col(row, &cols, &["username"]);
                let pass = get_col(row, &cols, &["password"]);
                items.push(make_login_item(
                    idx,
                    "firefox",
                    "",
                    url,
                    user,
                    pass,
                    "",
                    "",
                    false,
                    None,
                    now_unix,
                    &mut warnings,
                ));
            }
            ImportFormat::BitwardenCsv => {
                let item_type = get_col(row, &cols, &["type"]).to_ascii_lowercase();
                let folder = get_col(row, &cols, &["folder"]);
                let fid = get_or_create_folder(&mut folders, folder, now_unix);
                let fav = matches!(
                    get_col(row, &cols, &["favorite"]).to_ascii_lowercase().as_str(),
                    "1" | "true"
                );
                let name = get_col(row, &cols, &["name"]);
                let notes = get_col(row, &cols, &["notes"]);

                if item_type == "note" {
                    let mut it = VaultItem::new(
                        format!("bw-csv-{}", idx + 1),
                        if name.is_empty() { "Note" } else { name },
                        VaultItemKind::SecureNote(SecureNotePayload {
                            body: notes.to_string(),
                            markdown: false,
                        }),
                        now_unix,
                    );
                    it.favorite = fav;
                    it.folder_id = fid;
                    items.push(it);
                } else {
                    let uri = get_col(row, &cols, &["login_uri"]);
                    let user = get_col(row, &cols, &["login_username"]);
                    let pass = get_col(row, &cols, &["login_password"]);
                    let totp = get_col(row, &cols, &["login_totp"]);
                    let mut it = make_login_item(
                        idx,
                        "bw-csv",
                        name,
                        uri,
                        user,
                        pass,
                        totp,
                        notes,
                        fav,
                        fid,
                        now_unix,
                        &mut warnings,
                    );
                    let fields_raw = get_col(row, &cols, &["fields"]);
                    for line in fields_raw.lines() {
                        if let Some((k, v)) = line.split_once(':') {
                            it.custom_fields.push(CustomField {
                                name: k.trim().to_string(),
                                value: v.trim().to_string(),
                                kind: CustomFieldKind::Text,
                            });
                        }
                    }
                    items.push(it);
                }
            }
            ImportFormat::OnePasswordCsv => {
                let title = get_col(row, &cols, &["title"]);
                let url = get_col(row, &cols, &["url", "website"]);
                let user = get_col(row, &cols, &["username"]);
                let pass = get_col(row, &cols, &["password"]);
                let totp = get_col(row, &cols, &["otpauth", "one-time password"]);
                let notes = get_col(row, &cols, &["notes"]);
                let fav = matches!(
                    get_col(row, &cols, &["favorite"]).to_ascii_lowercase().as_str(),
                    "1" | "true"
                );
                let tags_raw = get_col(row, &cols, &["tags"]);
                let mut it = make_login_item(
                    idx,
                    "1p",
                    title,
                    url,
                    user,
                    pass,
                    totp,
                    notes,
                    fav,
                    None,
                    now_unix,
                    &mut warnings,
                );
                if !tags_raw.is_empty() {
                    it.tags = tags_raw
                        .split([',', ';'])
                        .map(|t| t.trim().to_string())
                        .filter(|t| !t.is_empty())
                        .collect();
                }
                items.push(it);
            }
            ImportFormat::KeePassCsv => {
                let group = get_col(row, &cols, &["group"]);
                let fid = get_or_create_folder(&mut folders, group, now_unix);
                let title = get_col(row, &cols, &["title", "account"]);
                let url = get_col(row, &cols, &["url", "web site"]);
                let user = get_col(row, &cols, &["username", "login name"]);
                let pass = get_col(row, &cols, &["password"]);
                let totp = get_col(row, &cols, &["totp"]);
                let notes = get_col(row, &cols, &["notes", "comments"]);
                items.push(make_login_item(
                    idx,
                    "keepass",
                    title,
                    url,
                    user,
                    pass,
                    totp,
                    notes,
                    false,
                    fid,
                    now_unix,
                    &mut warnings,
                ));
            }
            ImportFormat::ProtonPassCsv => {
                let name = get_col(row, &cols, &["name"]);
                let url = get_col(row, &cols, &["url"]);
                let user = {
                    let u = get_col(row, &cols, &["username"]);
                    if u.is_empty() {
                        get_col(row, &cols, &["email"])
                    } else {
                        u
                    }
                };
                let pass = get_col(row, &cols, &["password"]);
                let totp = get_col(row, &cols, &["totp"]);
                let note = get_col(row, &cols, &["note"]);
                let vault = get_col(row, &cols, &["vault"]);
                let fid = get_or_create_folder(&mut folders, vault, now_unix);
                items.push(make_login_item(
                    idx,
                    "proton-csv",
                    name,
                    url,
                    user,
                    pass,
                    totp,
                    note,
                    false,
                    fid,
                    now_unix,
                    &mut warnings,
                ));
            }
            ImportFormat::DashlaneCsv => {
                let title = get_col(row, &cols, &["title"]);
                let url = get_col(row, &cols, &["url"]);
                let user = {
                    let u1 = get_col(row, &cols, &["username"]);
                    if !u1.is_empty() {
                        u1
                    } else {
                        get_col(row, &cols, &["username2", "username3"])
                    }
                };
                let pass = get_col(row, &cols, &["password"]);
                let totp = get_col(row, &cols, &["otpsecret"]);
                let note = get_col(row, &cols, &["note"]);
                let cat = get_col(row, &cols, &["category"]);
                let fid = get_or_create_folder(&mut folders, cat, now_unix);
                items.push(make_login_item(
                    idx,
                    "dashlane",
                    title,
                    url,
                    user,
                    pass,
                    totp,
                    note,
                    false,
                    fid,
                    now_unix,
                    &mut warnings,
                ));
            }
            ImportFormat::LastPassCsv => {
                let url = get_col(row, &cols, &["url"]);
                let name = get_col(row, &cols, &["name"]);
                let user = get_col(row, &cols, &["username"]);
                let pass = get_col(row, &cols, &["password"]);
                let totp = get_col(row, &cols, &["totp"]);
                let extra = get_col(row, &cols, &["extra"]);
                let group = get_col(row, &cols, &["grouping"]);
                let fav = matches!(
                    get_col(row, &cols, &["fav"]).to_ascii_lowercase().as_str(),
                    "1" | "true"
                );
                let fid = get_or_create_folder(&mut folders, group, now_unix);
                if url.eq_ignore_ascii_case("http://sn") {
                    let mut it = VaultItem::new(
                        format!("lp-{}", idx + 1),
                        if name.is_empty() { "Secure Note" } else { name },
                        VaultItemKind::SecureNote(SecureNotePayload {
                            body: extra.to_string(),
                            markdown: false,
                        }),
                        now_unix,
                    );
                    it.favorite = fav;
                    it.folder_id = fid;
                    items.push(it);
                } else {
                    items.push(make_login_item(
                        idx,
                        "lp",
                        name,
                        url,
                        user,
                        pass,
                        totp,
                        extra,
                        fav,
                        fid,
                        now_unix,
                        &mut warnings,
                    ));
                }
            }
            _ => unreachable!(),
        }
    }

    Ok(ParsedBundle {
        items,
        folders,
        passkeys: Vec::new(),
        warnings,
    })
}

fn parse_bitwarden_json(input: &str, now_unix: u64) -> Result<ParsedBundle, ImportError> {
    let root: Value =
        serde_json::from_str(input).map_err(|e| ImportError::InvalidJson(e.to_string()))?;
    let mut folders = Vec::new();
    let mut items = Vec::new();
    let mut warnings = Vec::new();

    if let Some(f_arr) = root.get("folders").and_then(|v| v.as_array()) {
        for f in f_arr {
            let id = f.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let name = f.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            if !id.is_empty() && !name.is_empty() {
                folders.push(VaultFolder {
                    id,
                    name,
                    parent_id: None,
                    icon: None,
                    color: None,
                    revision: 1,
                    updated_at_unix: now_unix,
                });
            }
        }
    }

    let arr = root
        .get("items")
        .and_then(|v| v.as_array())
        .ok_or_else(|| ImportError::InvalidJson("Bitwarden JSON missing 'items' array".into()))?;

    for (idx, raw) in arr.iter().enumerate() {
        let id = raw
            .get("id")
            .and_then(|v| v.as_str())
            .map(String::from)
            .unwrap_or_else(|| format!("bw-json-{}", idx + 1));
        let name = raw
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("Untitled")
            .to_string();
        let notes = raw
            .get("notes")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let favorite = raw.get("favorite").and_then(|v| v.as_bool()).unwrap_or(false);
        let folder_id = raw
            .get("folderId")
            .and_then(|v| v.as_str())
            .map(String::from);
        let bw_type = raw.get("type").and_then(|v| v.as_u64()).unwrap_or(1);

        let kind = match bw_type {
            1 => {
                let l = raw.get("login");
                let username = l
                    .and_then(|v| v.get("username"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let password = l
                    .and_then(|v| v.get("password"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let mut uris = Vec::new();
                if let Some(u_arr) = l.and_then(|v| v.get("uris")).and_then(|v| v.as_array()) {
                    for u in u_arr {
                        if let Some(u_str) = u.get("uri").and_then(|v| v.as_str()) {
                            let rule = match u.get("match").and_then(|v| v.as_u64()) {
                                Some(1) => UriMatchRule::Host,
                                Some(2) => UriMatchRule::StartsWith,
                                Some(3) => UriMatchRule::Exact,
                                Some(4) => UriMatchRule::GlobRegex,
                                Some(5) => UriMatchRule::Never,
                                _ => UriMatchRule::BaseDomain,
                            };
                            uris.push(VaultUriEntry::new(u_str, rule));
                        }
                    }
                }
                let mut login = LoginPayload::default();
                login.username = username;
                login.password = password;
                login.uris = uris;
                login.notes = notes;
                if let Some(totp) = l.and_then(|v| v.get("totp")).and_then(|v| v.as_str()) {
                    apply_totp_str(&mut login, totp, &mut warnings);
                }
                VaultItemKind::Login(login)
            }
            2 => VaultItemKind::SecureNote(SecureNotePayload {
                body: notes,
                markdown: false,
            }),
            3 => {
                let c = raw.get("card");
                let number = c
                    .and_then(|v| v.get("number"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let brand_str = c.and_then(|v| v.get("brand")).and_then(|v| v.as_str()).unwrap_or("");
                let brand = match CardBrand::from_name(brand_str) {
                    CardBrand::Unknown => detect_card_brand(&number),
                    b => b,
                };
                let exp_month = c
                    .and_then(|v| v.get("expMonth"))
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<u8>().ok())
                    .unwrap_or(0);
                let exp_year = c
                    .and_then(|v| v.get("expYear"))
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<u16>().ok())
                    .unwrap_or(0);
                VaultItemKind::Card(CardPayload {
                    cardholder_name: c
                        .and_then(|v| v.get("cardholderName"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    number,
                    brand,
                    exp_month,
                    exp_year,
                    cvv: c
                        .and_then(|v| v.get("code"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    pin: None,
                    billing_address: None,
                    notes,
                })
            }
            4 => {
                let id_obj = raw.get("identity");
                let s = |k: &str| {
                    id_obj
                        .and_then(|v| v.get(k))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string()
                };
                VaultItemKind::Identity(IdentityPayload {
                    title: s("title"),
                    first_name: s("firstName"),
                    middle_name: s("middleName"),
                    last_name: s("lastName"),
                    email: s("email"),
                    phone: s("phone"),
                    company: s("company"),
                    address1: s("address1"),
                    address2: s("address2"),
                    city: s("city"),
                    state: s("state"),
                    postal_code: s("postalCode"),
                    country: s("country"),
                    national_id: {
                        let v = s("ssn");
                        if v.is_empty() { None } else { Some(v) }
                    },
                    passport_number: {
                        let v = s("passportNumber");
                        if v.is_empty() { None } else { Some(v) }
                    },
                    driver_license: {
                        let v = s("licenseNumber");
                        if v.is_empty() { None } else { Some(v) }
                    },
                    birth_date: None,
                    notes,
                })
            }
            other => {
                warnings.push(format!("Skipped unsupported Bitwarden item type {}", other));
                continue;
            }
        };

        let mut item = VaultItem::new(id, name, kind, now_unix);
        item.favorite = favorite;
        item.folder_id = folder_id;
        if let Some(fields) = raw.get("fields").and_then(|v| v.as_array()) {
            for f in fields {
                let fname = f.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let fval = f.get("value").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let fkind = match f.get("type").and_then(|v| v.as_u64()) {
                    Some(1) => CustomFieldKind::Hidden,
                    Some(2) => CustomFieldKind::Boolean,
                    Some(3) => CustomFieldKind::Linked,
                    _ => CustomFieldKind::Text,
                };
                if !fname.is_empty() {
                    item.custom_fields.push(CustomField {
                        name: fname,
                        value: fval,
                        kind: fkind,
                    });
                }
            }
        }
        items.push(item);
    }

    Ok(ParsedBundle {
        items,
        folders,
        passkeys: Vec::new(),
        warnings,
    })
}

fn parse_protonpass_json(input: &str, now_unix: u64) -> Result<ParsedBundle, ImportError> {
    let root: Value =
        serde_json::from_str(input).map_err(|e| ImportError::InvalidJson(e.to_string()))?;
    let vaults = root
        .get("vaults")
        .and_then(|v| v.as_object())
        .ok_or_else(|| ImportError::InvalidJson("ProtonPass JSON missing 'vaults' object".into()))?;

    let mut items = Vec::new();
    let mut folders = Vec::new();
    let mut warnings = Vec::new();

    for (vault_id, vault_val) in vaults {
        let vault_name = vault_val
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or(vault_id);
        let fid = get_or_create_folder(&mut folders, vault_name, now_unix);
        let Some(v_items) = vault_val.get("items").and_then(|v| v.as_array()) else {
            continue;
        };

        for (idx, raw) in v_items.iter().enumerate() {
            let item_id = raw
                .get("itemId")
                .and_then(|v| v.as_str())
                .map(String::from)
                .unwrap_or_else(|| format!("proton-{}-{}", vault_id, idx + 1));
            let data = raw.get("data").unwrap_or(raw);
            let meta = data.get("metadata").unwrap_or(data);
            let name = meta
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("Untitled")
                .to_string();
            let note = meta
                .get("note")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let content = data.get("content").unwrap_or(data);
            let item_type = data.get("type").and_then(|v| v.as_str()).unwrap_or("login");

            let kind = match item_type {
                "note" => VaultItemKind::SecureNote(SecureNotePayload {
                    body: note,
                    markdown: false,
                }),
                "creditCard" => {
                    let number = content
                        .get("number")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let brand = detect_card_brand(&number);
                    let exp = content.get("expirationDate").and_then(|v| v.as_str()).unwrap_or("");
                    let (exp_year, exp_month) = if let Some((y, m)) = exp.split_once('-') {
                        (y.parse().unwrap_or(0), m.parse().unwrap_or(0))
                    } else {
                        (0, 0)
                    };
                    VaultItemKind::Card(CardPayload {
                        cardholder_name: content
                            .get("cardholderName")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        number,
                        brand,
                        exp_month,
                        exp_year,
                        cvv: content
                            .get("verificationNumber")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        pin: content.get("pin").and_then(|v| v.as_str()).map(String::from),
                        billing_address: None,
                        notes: note,
                    })
                }
                _ => {
                    let username = content
                        .get("itemEmail")
                        .or_else(|| content.get("username"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let password = content
                        .get("password")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let uris: Vec<VaultUriEntry> = content
                        .get("urls")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|u| u.as_str())
                                .map(|s| VaultUriEntry::base_domain(s.to_string()))
                                .collect()
                        })
                        .unwrap_or_default();
                    let mut login = LoginPayload::default();
                    login.username = username;
                    login.password = password;
                    login.uris = uris;
                    login.notes = note;
                    if let Some(totp) = content.get("totpUri").and_then(|v| v.as_str()) {
                        apply_totp_str(&mut login, totp, &mut warnings);
                    }
                    VaultItemKind::Login(login)
                }
            };

            let mut item = VaultItem::new(item_id, name, kind, now_unix);
            item.folder_id = fid.clone();
            items.push(item);
        }
    }

    Ok(ParsedBundle {
        items,
        folders,
        passkeys: Vec::new(),
        warnings,
    })
}

fn parse_singularity_json(input: &str) -> Result<ParsedBundle, ImportError> {
    let payload: VaultPlaintextPayloadV2 =
        serde_json::from_str(input).map_err(|e| ImportError::InvalidJson(e.to_string()))?;
    Ok(ParsedBundle {
        items: payload.items,
        folders: payload.folders,
        passkeys: payload.passkeys,
        warnings: Vec::new(),
    })
}

fn parse_bundle(
    format: ImportFormat,
    input: &str,
    now_unix: u64,
) -> Result<ParsedBundle, ImportError> {
    match format {
        ImportFormat::ChromeCsv
        | ImportFormat::FirefoxCsv
        | ImportFormat::BitwardenCsv
        | ImportFormat::OnePasswordCsv
        | ImportFormat::KeePassCsv
        | ImportFormat::ProtonPassCsv
        | ImportFormat::DashlaneCsv
        | ImportFormat::LastPassCsv => parse_csv_bundle(format, input, now_unix),
        ImportFormat::BitwardenJson => parse_bitwarden_json(input, now_unix),
        ImportFormat::ProtonPassJson => parse_protonpass_json(input, now_unix),
        ImportFormat::SingularityJson => parse_singularity_json(input),
        ImportFormat::FidoCxf => {
            let doc = deserialize_cxf_json(input)
                .map_err(|e| ImportError::InvalidJson(e.to_string()))?;
            let (items, folders, passkeys) = import_cxf_to_vault_parts(&doc, now_unix);
            Ok(ParsedBundle {
                items,
                folders,
                passkeys,
                warnings: Vec::new(),
            })
        }
    }
}

// ============================================================================
// CONFLICT PREVIEW & CONFIGURABLE ATOMIC MERGE
// ============================================================================

fn item_identity_key(item: &VaultItem) -> String {
    match &item.kind {
        VaultItemKind::Login(l) => {
            let domain = l
                .primary_uri()
                .and_then(extract_etld_plus_one)
                .unwrap_or_else(|| item.name.trim().to_ascii_lowercase());
            format!("login|{}|{}", domain, l.username.trim().to_ascii_lowercase())
        }
        other => format!("{}|{}", other.type_name(), item.name.trim().to_ascii_lowercase()),
    }
}

fn items_content_equal(a: &VaultItem, b: &VaultItem) -> bool {
    match (&a.kind, &b.kind) {
        (VaultItemKind::Login(la), VaultItemKind::Login(lb)) => {
            la.username == lb.username
                && la.password == lb.password
                && la.totp_secret_base32 == lb.totp_secret_base32
                && la.notes == lb.notes
        }
        (VaultItemKind::Card(ca), VaultItemKind::Card(cb)) => {
            ca.number == cb.number && ca.exp_month == cb.exp_month && ca.exp_year == cb.exp_year
        }
        (VaultItemKind::SecureNote(na), VaultItemKind::SecureNote(nb)) => na.body == nb.body,
        (VaultItemKind::Wifi(wa), VaultItemKind::Wifi(wb)) => {
            wa.ssid == wb.ssid && wa.password == wb.password
        }
        (VaultItemKind::ApiSecret(aa), VaultItemKind::ApiSecret(ab)) => {
            aa.service_name == ab.service_name && aa.api_key == ab.api_key
        }
        (VaultItemKind::License(la), VaultItemKind::License(lb)) => {
            la.product_name == lb.product_name && la.license_key == lb.license_key
        }
        (VaultItemKind::SshKey(sa), VaultItemKind::SshKey(sb)) => {
            sa.private_key_pem == sb.private_key_pem
        }
        (VaultItemKind::Identity(ia), VaultItemKind::Identity(ib)) => {
            ia.email == ib.email && ia.first_name == ib.first_name && ia.last_name == ib.last_name
        }
        _ => false,
    }
}

/// Parses an import payload (auto-detecting format if `format_override` is `None`) and classifies
/// every incoming entry into `new_items`, exact `duplicates`, or `conflicts` against `existing_items`.
pub fn preview_import(
    existing_items: &[VaultItem],
    input: &str,
    format_override: Option<ImportFormat>,
    now_unix: u64,
) -> Result<ImportPreview, ImportError> {
    let format = match format_override {
        Some(f) => f,
        None => detect_import_format(input)?,
    };
    let bundle = parse_bundle(format, input, now_unix)?;

    let mut existing_by_key: HashMap<String, &VaultItem> = HashMap::new();
    for ex in existing_items {
        if !ex.is_trashed() {
            existing_by_key.insert(item_identity_key(ex), ex);
        }
    }

    let mut new_items = Vec::new();
    let mut duplicates = Vec::new();
    let mut conflicts = Vec::new();

    for incoming in bundle.items {
        let key = item_identity_key(&incoming);
        if let Some(&existing) = existing_by_key.get(&key) {
            if items_content_equal(existing, &incoming) {
                duplicates.push(incoming);
            } else {
                conflicts.push(ImportConflict {
                    existing_item_id: existing.id.clone(),
                    existing_name: existing.name.clone(),
                    incoming_item: incoming,
                    reason: format!("Differing credentials/content for key '{}'", key),
                });
            }
        } else {
            new_items.push(incoming);
        }
    }

    Ok(ImportPreview {
        format,
        new_items,
        duplicates,
        conflicts,
        folders: bundle.folders,
        passkeys: bundle.passkeys,
        warnings: bundle.warnings,
    })
}

/// Atomically applies an [`ImportPreview`] onto `payload` using `resolution` (`Skip`, `Overwrite`,
/// or `KeepBoth`). Stages all mutations on a clone before committing so partial failures never
/// corrupt the vault state.
pub fn apply_import_atomic(
    payload: &mut VaultPlaintextPayloadV2,
    preview: ImportPreview,
    resolution: ConflictResolution,
    now_unix: u64,
) -> ImportApplyResult {
    let mut staged = payload.clone();
    let mut result = ImportApplyResult::default();

    // 1. Merge folders (remapping folder IDs by case-insensitive name if already present)
    let mut folder_id_remap: HashMap<String, String> = HashMap::new();
    for folder in preview.folders {
        if let Some(existing) = staged
            .folders
            .iter()
            .find(|f| f.name.eq_ignore_ascii_case(&folder.name))
        {
            folder_id_remap.insert(folder.id.clone(), existing.id.clone());
        } else {
            folder_id_remap.insert(folder.id.clone(), folder.id.clone());
            staged.folders.push(folder);
            result.folders_added += 1;
        }
    }

    let remap_folder = |item: &mut VaultItem| {
        if let Some(ref fid) = item.folder_id {
            if let Some(mapped) = folder_id_remap.get(fid) {
                item.folder_id = Some(mapped.clone());
            }
        }
    };

    // Helper to ensure unique item IDs
    let ensure_unique_id = |items: &[VaultItem], base_id: &str| -> String {
        if !items.iter().any(|i| i.id == base_id) {
            return base_id.to_string();
        }
        let mut n = 1usize;
        loop {
            let cand = format!("{}-copy-{}", base_id, n);
            if !items.iter().any(|i| i.id == cand) {
                return cand;
            }
            n += 1;
        }
    };

    // 2. Add new items
    for mut item in preview.new_items {
        remap_folder(&mut item);
        item.id = ensure_unique_id(&staged.items, &item.id);
        staged.items.push(item);
        result.added += 1;
    }

    // 3. Skip exact duplicates
    result.skipped += preview.duplicates.len();

    // 4. Resolve conflicts according to policy
    for conflict in preview.conflicts {
        let mut incoming = conflict.incoming_item;
        remap_folder(&mut incoming);
        match resolution {
            ConflictResolution::Skip => {
                result.skipped += 1;
            }
            ConflictResolution::Overwrite => {
                if let Some(existing) = staged
                    .items
                    .iter_mut()
                    .find(|i| i.id == conflict.existing_item_id)
                {
                    // Preserve password history when overwriting a Login item
                    if let (
                        VaultItemKind::Login(ref mut ex_login),
                        VaultItemKind::Login(ref inc_login),
                    ) = (&mut existing.kind, &incoming.kind)
                    {
                        let mut updated_login = inc_login.clone();
                        updated_login.password_history = ex_login.password_history.clone();
                        let old_pw = ex_login.password.clone();
                        let new_pw = inc_login.password.clone();
                        updated_login.password = old_pw;
                        updated_login.update_password(new_pw, now_unix);
                        existing.kind = VaultItemKind::Login(updated_login);
                        existing.password_updated_at_unix = Some(now_unix);
                    } else {
                        existing.kind = incoming.kind;
                    }
                    existing.name = incoming.name;
                    existing.updated_at_unix = now_unix;
                    existing.revision = existing.revision.saturating_add(1);
                    result.overwritten += 1;
                } else {
                    incoming.id = ensure_unique_id(&staged.items, &incoming.id);
                    staged.items.push(incoming);
                    result.added += 1;
                }
            }
            ConflictResolution::KeepBoth => {
                incoming.id = ensure_unique_id(&staged.items, &incoming.id);
                incoming.name = format!("{} (Imported)", incoming.name);
                staged.items.push(incoming);
                result.kept_both += 1;
            }
        }
    }

    // 5. Merge passkeys (deduplicated by credential_id_hex)
    for pk in preview.passkeys {
        if !staged
            .passkeys
            .iter()
            .any(|p| p.credential_id_hex.eq_ignore_ascii_case(&pk.credential_id_hex))
        {
            staged.passkeys.push(pk);
            result.passkeys_added += 1;
        }
    }

    staged.bump_revision(now_unix);
    *payload = staged;
    result
}

// ============================================================================
// EXPORTERS: CSV, PLAIN JSON, PASSWORD-PROTECTED ENCRYPTED JSON
// ============================================================================

/// Exports active (non-trashed) Login items into RFC 4180 CSV (`name,url,username,password,totp,folder,favorite,notes`).
pub fn export_to_csv(items: &[VaultItem], folders: &[VaultFolder]) -> String {
    let folder_names: HashMap<&str, &str> = folders
        .iter()
        .map(|f| (f.id.as_str(), f.name.as_str()))
        .collect();

    let mut lines = Vec::new();
    lines.push("name,url,username,password,totp,folder,favorite,notes".to_string());

    for item in items {
        if item.is_trashed() {
            continue;
        }
        let VaultItemKind::Login(ref l) = item.kind else {
            continue;
        };
        let url = l.primary_uri().unwrap_or("").to_string();
        let totp_uri = l
            .totp_secret_base32
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .and_then(|sec| {
                format_otpauth_uri(&OtpAuthConfig {
                    kind: l.otp_kind,
                    issuer: Some(item.name.clone()),
                    account_name: l.username.clone(),
                    secret_base32: sec.to_string(),
                    algorithm: l.totp_algorithm,
                    digits: l.totp_digits,
                    period_sec: l.totp_period_sec,
                })
                .ok()
            })
            .unwrap_or_default();
        let folder = item
            .folder_id
            .as_deref()
            .and_then(|fid| folder_names.get(fid).copied())
            .unwrap_or("")
            .to_string();
        let fav = if item.favorite { "1" } else { "0" }.to_string();
        let row = vec![
            item.name.clone(),
            url,
            l.username.clone(),
            l.password.clone(),
            totp_uri,
            folder,
            fav,
            l.notes.clone(),
        ];
        lines.push(encode_csv_row_rfc4180(&row));
    }

    lines.join("\n")
}

/// Exports the unlocked V2 vault payload as pretty-printed plaintext Singularity JSON.
pub fn export_to_plain_json(payload: &VaultPlaintextPayloadV2) -> Result<String, ImportError> {
    serde_json::to_string_pretty(payload).map_err(|e| ImportError::InvalidJson(e.to_string()))
}

/// Password-protected encrypted Singularity JSON export envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedJsonExportEnvelope {
    pub magic: String,
    pub exported_at_unix: u64,
    pub kdf_config: Argon2idConfig,
    pub salt_base64: String,
    pub xnonce_base64: String,
    pub ciphertext_base64: String,
}

fn build_export_aad(
    magic: &str,
    exported_at_unix: u64,
    kdf_config: Argon2idConfig,
    salt: &[u8; 32],
    xnonce: &[u8; 24],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(magic.len() + 76);
    aad.extend_from_slice(magic.as_bytes());
    aad.extend_from_slice(&exported_at_unix.to_le_bytes());
    aad.extend_from_slice(&kdf_config.memory_kib.to_le_bytes());
    aad.extend_from_slice(&kdf_config.iterations.to_le_bytes());
    aad.extend_from_slice(&kdf_config.parallelism.to_le_bytes());
    aad.extend_from_slice(salt);
    aad.extend_from_slice(xnonce);
    aad
}

/// Exports the unlocked V2 vault payload as a password-protected Argon2id + XChaCha20-Poly1305 JSON file.
pub fn export_to_encrypted_json(
    payload: &VaultPlaintextPayloadV2,
    export_password: &[u8],
    kdf_config: Argon2idConfig,
    now_unix: u64,
) -> Result<String, ImportError> {
    kdf_config.validate_bounds()?;
    let (salt, xnonce) = generate_salt_and_xnonce();
    let key = DerivedVaultKey::derive_argon2id(export_password, &salt, kdf_config)?;

    let mut pt =
        serde_json::to_vec(payload).map_err(|e| ImportError::InvalidJson(e.to_string()))?;
    let aad = build_export_aad(
        SINGULARITY_ENCRYPTED_EXPORT_MAGIC,
        now_unix,
        kdf_config,
        &salt,
        &xnonce,
    );
    let enc = key.encrypt_xchacha20_poly1305(&pt, &xnonce, &aad);
    pt.zeroize();
    let ct = enc?;

    let env = EncryptedJsonExportEnvelope {
        magic: SINGULARITY_ENCRYPTED_EXPORT_MAGIC.to_string(),
        exported_at_unix: now_unix,
        kdf_config,
        salt_base64: BASE64.encode(salt),
        xnonce_base64: BASE64.encode(xnonce),
        ciphertext_base64: BASE64.encode(ct),
    };
    serde_json::to_string_pretty(&env).map_err(|e| ImportError::InvalidJson(e.to_string()))
}

/// Decrypts a password-protected Singularity encrypted JSON export back into `VaultPlaintextPayloadV2`.
pub fn import_from_encrypted_json(
    encrypted_json: &str,
    export_password: &[u8],
) -> Result<VaultPlaintextPayloadV2, ImportError> {
    let env: EncryptedJsonExportEnvelope = serde_json::from_str(encrypted_json)
        .map_err(|e| ImportError::InvalidJson(e.to_string()))?;
    if env.magic != SINGULARITY_ENCRYPTED_EXPORT_MAGIC {
        return Err(VaultCryptoError::UnsupportedVersion(env.magic).into());
    }
    env.kdf_config.validate_bounds()?;

    let salt: [u8; 32] = BASE64
        .decode(&env.salt_base64)
        .map_err(|_| VaultCryptoError::DecryptionFailed)?
        .try_into()
        .map_err(|_| VaultCryptoError::DecryptionFailed)?;
    let xnonce: [u8; 24] = BASE64
        .decode(&env.xnonce_base64)
        .map_err(|_| VaultCryptoError::DecryptionFailed)?
        .try_into()
        .map_err(|_| VaultCryptoError::DecryptionFailed)?;
    let ct = BASE64
        .decode(&env.ciphertext_base64)
        .map_err(|_| VaultCryptoError::DecryptionFailed)?;

    let key = DerivedVaultKey::derive_argon2id(export_password, &salt, env.kdf_config)?;
    let aad = build_export_aad(
        &env.magic,
        env.exported_at_unix,
        env.kdf_config,
        &salt,
        &xnonce,
    );
    let mut pt = key.decrypt_xchacha20_poly1305(&ct, &xnonce, &aad)?;
    let parsed = serde_json::from_slice::<VaultPlaintextPayloadV2>(&pt)
        .map_err(|e| ImportError::InvalidJson(e.to_string()));
    pt.zeroize();
    parsed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc4180_csv_parser_quoted_newlines_and_escapes() {
        let csv = "\u{FEFF}name,url,username,password,note\r\n\"Git,Hub\",https://github.com,alice,\"p\"\"ass,1\",\"line1\nline2\"\r\n";
        let rows = parse_csv_rfc4180(csv).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1][0], "Git,Hub");
        assert_eq!(rows[1][3], "p\"ass,1");
        assert_eq!(rows[1][4], "line1\nline2");
    }

    #[test]
    fn test_format_auto_detection_all_12_formats() {
        assert_eq!(
            detect_import_format("name,url,username,password,note\nGH,https://github.com,a,b,").unwrap(),
            ImportFormat::ChromeCsv
        );
        assert_eq!(
            detect_import_format("url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged\nhttps://a.com,u,p,,,,0,0,0").unwrap(),
            ImportFormat::FirefoxCsv
        );
        assert_eq!(
            detect_import_format("folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n,,login,GH,,,,https://github.com,u,p,").unwrap(),
            ImportFormat::BitwardenCsv
        );
        assert_eq!(
            detect_import_format(r#"{"folders":[],"items":[{"id":"1","type":1,"name":"GH","login":{"username":"a","password":"b"}}]}"#).unwrap(),
            ImportFormat::BitwardenJson
        );
        assert_eq!(
            detect_import_format("Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\nGH,https://github.com,a,b,,0,0,,").unwrap(),
            ImportFormat::OnePasswordCsv
        );
        assert_eq!(
            detect_import_format("Group,Title,Username,Password,URL,Notes,TOTP\nRoot,GH,a,b,https://github.com,,").unwrap(),
            ImportFormat::KeePassCsv
        );
        assert_eq!(
            detect_import_format("name,url,email,username,password,note,totp,vault\nGH,https://github.com,a@b.c,a,b,,,Personal").unwrap(),
            ImportFormat::ProtonPassCsv
        );
        assert_eq!(
            detect_import_format(r#"{"vaults":{"v1":{"name":"Personal","items":[]}}}"#).unwrap(),
            ImportFormat::ProtonPassJson
        );
        assert_eq!(
            detect_import_format("username,username2,username3,title,password,note,url,category,otpSecret\na,,,GH,b,,https://github.com,Work,").unwrap(),
            ImportFormat::DashlaneCsv
        );
        assert_eq!(
            detect_import_format("url,username,password,totp,extra,name,grouping,fav\nhttps://github.com,a,b,,,GH,Work,1").unwrap(),
            ImportFormat::LastPassCsv
        );
        assert_eq!(
            detect_import_format(r#"{"schema_version":"V2","items":[],"folders":[],"passkeys":[]}"#).unwrap(),
            ImportFormat::SingularityJson
        );
        assert_eq!(
            detect_import_format(r#"{"version":{"major":1,"minor":0},"exporter":"Test","timestamp":1,"accounts":[]}"#).unwrap(),
            ImportFormat::FidoCxf
        );
    }

    #[test]
    fn test_conflict_preview_atomic_merge_and_exporters() {
        let mut vault = VaultPlaintextPayloadV2::default();
        let mut l1 = LoginPayload::default();
        l1.username = "alice".into();
        l1.password = "old-password".into();
        l1.uris = vec![VaultUriEntry::base_domain("https://github.com")];
        vault
            .items
            .push(VaultItem::new("ex-1", "GitHub", VaultItemKind::Login(l1), 1_000));

        let mut l2 = LoginPayload::default();
        l2.username = "123456".into();
        l2.password = "same-password".into();
        l2.uris = vec![VaultUriEntry::base_domain("https://mullvad.net")];
        vault
            .items
            .push(VaultItem::new("ex-2", "Mullvad", VaultItemKind::Login(l2), 1_000));

        let csv_in = "\
name,url,username,password,note
GitHub,https://github.com,alice,new-rotated-password,updated
Mullvad,https://mullvad.net,123456,same-password,
Proton,https://proton.me,alice@proton.me,proton-secret,mail";

        let preview = preview_import(&vault.items, csv_in, None, 2_000).unwrap();
        assert_eq!(preview.format, ImportFormat::ChromeCsv);
        assert_eq!(preview.new_items.len(), 1);
        assert_eq!(preview.duplicates.len(), 1);
        assert_eq!(preview.conflicts.len(), 1);

        // Overwrite policy updates GitHub and keeps old password in password_history
        let res = apply_import_atomic(&mut vault, preview, ConflictResolution::Overwrite, 2_000);
        assert_eq!(res.added, 1);
        assert_eq!(res.overwritten, 1);
        assert_eq!(res.skipped, 1);
        assert_eq!(vault.items.len(), 3);
        if let VaultItemKind::Login(ref l) = vault.items[0].kind {
            assert_eq!(l.password, "new-rotated-password");
            assert_eq!(l.password_history.len(), 1);
            assert_eq!(l.password_history[0].password, "old-password");
        } else {
            panic!("Expected login item");
        }

        // Export CSV, Plain JSON, and Password-Protected Encrypted JSON roundtrip
        let exported_csv = export_to_csv(&vault.items, &vault.folders);
        assert!(exported_csv.contains("new-rotated-password"));
        assert!(exported_csv.contains("proton-secret"));

        let exported_plain = export_to_plain_json(&vault).unwrap();
        let re_preview = preview_import(&[], &exported_plain, None, 3_000).unwrap();
        assert_eq!(re_preview.format, ImportFormat::SingularityJson);
        assert_eq!(re_preview.new_items.len(), 3);

        let fast_kdf = Argon2idConfig {
            memory_kib: 4096,
            iterations: 1,
            parallelism: 1,
        };
        let exported_enc =
            export_to_encrypted_json(&vault, b"export-secret-pw", fast_kdf, 3_000).unwrap();
        assert!(!exported_enc.contains("new-rotated-password"));
        assert!(import_from_encrypted_json(&exported_enc, b"wrong").is_err());
        let decrypted = import_from_encrypted_json(&exported_enc, b"export-secret-pw").unwrap();
        assert_eq!(decrypted.items.len(), 3);
    }

    #[test]
    fn test_all_manager_parsers_and_skip_keepboth_policies() {
        // Bitwarden JSON (Login + Card + Identity + Note + Folder + CustomFields)
        let bw_json = r#"{
            "folders": [{"id": "f1", "name": "Finance"}],
            "items": [
                {
                    "id": "i1", "type": 1, "name": "Bank", "folderId": "f1", "favorite": true,
                    "notes": "main bank",
                    "login": {
                        "username": "alice", "password": "BankSecret#1",
                        "totp": "otpauth://totp/Bank:alice?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&digits=8&period=30",
                        "uris": [{"uri": "https://bank.example.com/login", "match": 1}]
                    },
                    "fields": [{"name": "Account", "value": "FR761234", "type": 1}]
                },
                {
                    "id": "i2", "type": 3, "name": "Visa Card",
                    "card": {"cardholderName": "Alice", "number": "4242424242424242", "brand": "Visa", "expMonth": "12", "expYear": "2029", "code": "999"}
                },
                {
                    "id": "i3", "type": 4, "name": "My ID",
                    "identity": {"firstName": "Alice", "lastName": "Liddell", "email": "alice@example.com"}
                },
                {
                    "id": "i4", "type": 2, "name": "Recovery", "notes": "secret-seed-words"
                }
            ]
        }"#;
        let bw_prev = preview_import(&[], bw_json, None, 1_000).unwrap();
        assert_eq!(bw_prev.format, ImportFormat::BitwardenJson);
        assert_eq!(bw_prev.new_items.len(), 4);
        assert_eq!(bw_prev.folders.len(), 1);
        assert_eq!(bw_prev.new_items[0].custom_fields.len(), 1);
        assert_eq!(bw_prev.new_items[0].custom_fields[0].kind, CustomFieldKind::Hidden);

        // ProtonPass JSON
        let pp_json = r#"{
            "vaults": {
                "v1": {
                    "name": "Personal",
                    "items": [
                        {
                            "itemId": "p1",
                            "data": {
                                "type": "login",
                                "metadata": {"name": "Proton", "note": "mail"},
                                "content": {"itemEmail": "alice@proton.me", "password": "PpSecret!9", "urls": ["https://proton.me"], "totpUri": "JBSWY3DPEHPK3PXP"}
                            }
                        }
                    ]
                }
            }
        }"#;
        let pp_prev = preview_import(&[], pp_json, None, 1_000).unwrap();
        assert_eq!(pp_prev.format, ImportFormat::ProtonPassJson);
        assert_eq!(pp_prev.new_items.len(), 1);

        // 1Password, KeePass, Dashlane, LastPass (including Secure Note http://sn), Firefox, Bitwarden CSV
        let lp_csv = "url,username,password,totp,extra,name,grouping,fav\nhttps://gh.com,u,p,JBSWY3DPEHPK3PXP,note,GH,Dev,1\nhttp://sn,,, ,secret-note-body,MyNote,Notes,0";
        let lp_prev = preview_import(&[], lp_csv, None, 1_000).unwrap();
        assert_eq!(lp_prev.format, ImportFormat::LastPassCsv);
        assert_eq!(lp_prev.new_items.len(), 2);
        assert!(matches!(lp_prev.new_items[1].kind, VaultItemKind::SecureNote(_)));

        let op_csv = "Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\nGitLab,https://gitlab.com,alice,glpass,JBSWY3DPEHPK3PXP,1,0,\"dev,ci\",note";
        let op_prev = preview_import(&[], op_csv, None, 1_000).unwrap();
        assert_eq!(op_prev.format, ImportFormat::OnePasswordCsv);
        assert_eq!(op_prev.new_items[0].tags, vec!["dev", "ci"]);

        let kp_csv = "Group,Title,Username,Password,URL,Notes,TOTP\nRoot,Server,root,s3cr3t,https://srv.local,ssh,\n";
        let kp_prev = preview_import(&[], kp_csv, None, 1_000).unwrap();
        assert_eq!(kp_prev.format, ImportFormat::KeePassCsv);
        assert_eq!(kp_prev.new_items.len(), 1);

        let dl_csv = "username,username2,username3,title,password,note,url,category,otpSecret\n,alice@ex.com,,Portal,dlpass,n,https://portal.example,Work,JBSWY3DPEHPK3PXP";
        let dl_prev = preview_import(&[], dl_csv, None, 1_000).unwrap();
        assert_eq!(dl_prev.format, ImportFormat::DashlaneCsv);
        assert_eq!(dl_prev.new_items.len(), 1);

        // Test ConflictResolution::Skip and ConflictResolution::KeepBoth
        let mut target = VaultPlaintextPayloadV2::default();
        apply_import_atomic(&mut target, bw_prev, ConflictResolution::Skip, 1_000);
        let conflict_csv = "name,url,username,password,note\nBank,https://bank.example.com,alice,DifferentPass#2,";
        let c_prev_skip = preview_import(&target.items, conflict_csv, None, 2_000).unwrap();
        assert_eq!(c_prev_skip.conflicts.len(), 1);
        let skip_res = apply_import_atomic(&mut target, c_prev_skip, ConflictResolution::Skip, 2_000);
        assert_eq!(skip_res.skipped, 1);
        assert_eq!(target.items.len(), 4);

        let c_prev_both = preview_import(&target.items, conflict_csv, None, 2_100).unwrap();
        let both_res =
            apply_import_atomic(&mut target, c_prev_both, ConflictResolution::KeepBoth, 2_100);
        assert_eq!(both_res.kept_both, 1);
        assert_eq!(target.items.len(), 5);
    }
}
