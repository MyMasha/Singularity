//! Native Chrome Extensions Manager for Singularity (Manifest V2 / V3).
//!
//! Manages unpacked Chrome extensions under `%APPDATA%\.singularity\extensions`
//! (loaded natively by WebView2 via `ICoreWebView2Profile7::AddBrowserExtension`
//! through `wry`'s `with_browser_extensions_enabled(true)` + `with_extensions_path(...)`),
//! with disabled extensions safely parked in `%APPDATA%\.singularity\extensions-disabled`.
//!
//! Supports:
//! - 1-click install from the official Chrome Web Store (URL or 32-char extension ID via CRX2/CRX3).
//! - 1-click import from locally installed Chrome / Brave / Edge profiles.
//! - Local unpacked folder or `.crx` / `.zip` installation with strict zip-slip & size caps.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Cursor, Read};
use std::path::{Component, Path, PathBuf};
#[cfg(not(target_os = "windows"))]
use std::process::{Command, Stdio};
use subtle::ConstantTimeEq;

const MAX_CRX_BYTES: usize = 32 * 1024 * 1024; // 32 MiB compressed package cap
const MAX_EXTRACTED_BYTES: u64 = 64 * 1024 * 1024; // 64 MiB total uncompressed cap
const MAX_ARCHIVE_ENTRIES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SiteAccessMode {
    OnClick,
    OnSpecificSites,
    #[default]
    OnAllSites,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExtensionCommand {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub suggested_key: Option<String>,
    #[serde(default)]
    pub custom_key: Option<String>,
    #[serde(default)]
    pub global: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionActionState {
    #[serde(default)]
    pub badge_text: String,
    #[serde(default = "default_badge_bg")]
    pub badge_bg_color: String,
    #[serde(default = "default_badge_fg")]
    pub badge_text_color: String,
    #[serde(default)]
    pub title: String,
    #[serde(default = "default_true_ext")]
    pub enabled: bool,
    #[serde(default)]
    pub dynamic_icon_data_url: Option<String>,
}

fn default_badge_bg() -> String {
    "#7C3AED".to_string()
}

fn default_badge_fg() -> String {
    "#FFFFFF".to_string()
}

fn default_true_ext() -> bool {
    true
}

impl Default for ExtensionActionState {
    fn default() -> Self {
        Self {
            badge_text: String::new(),
            badge_bg_color: default_badge_bg(),
            badge_text_color: default_badge_fg(),
            title: String::new(),
            enabled: true,
            dynamic_icon_data_url: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WebAccessibleResourceRule {
    #[serde(default)]
    pub resources: Vec<String>,
    #[serde(default)]
    pub matches: Vec<String>,
    #[serde(default)]
    pub use_dynamic_url: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExtensionSecurityPolicy {
    #[serde(default)]
    pub extension_pages_csp: Option<String>,
    #[serde(default)]
    pub sandbox_csp: Option<String>,
    #[serde(default)]
    pub web_accessible_resources: Vec<WebAccessibleResourceRule>,
}

impl ExtensionSecurityPolicy {
    /// Checks whether a relative resource path may be loaded by a web origin.
    pub fn is_web_accessible(&self, rel_path: &str, origin: &str) -> bool {
        let norm_path = rel_path.trim_start_matches('/');
        for rule in &self.web_accessible_resources {
            let res_match = rule.resources.iter().any(|pat| wildcard_match_ext(pat, norm_path));
            if !res_match {
                continue;
            }
            if rule.matches.is_empty()
                || rule.matches.iter().any(|m| {
                    m == "<all_urls>"
                        || m == "*://*/*"
                        || m == "https://*/*"
                        || wildcard_match_ext(m, origin)
                })
            {
                return true;
            }
        }
        false
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionErrorEntry {
    pub timestamp_ms: u64,
    pub level: String,
    pub message: String,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub stack: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionWarning {
    pub permission: String,
    pub severity: String,
    pub label_en: String,
    pub label_fr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StagedExtensionReview {
    pub id: String,
    pub name: String,
    pub version: String,
    pub manifest_version: u64,
    pub permissions: Vec<String>,
    pub host_permissions: Vec<String>,
    pub warnings: Vec<PermissionWarning>,
    pub staged_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionUpdateAvailable {
    pub id: String,
    pub version: String,
    pub codebase_url: String,
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeMessagingHost {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub path: String,
    #[serde(rename = "type", default = "default_stdio_type")]
    pub transport_type: String,
    #[serde(default)]
    pub allowed_origins: Vec<String>,
}

fn default_stdio_type() -> String {
    "stdio".to_string()
}

impl NativeMessagingHost {
    pub fn allows_extension(&self, extension_id: &str) -> bool {
        let target = format!("chrome-extension://{}/", extension_id.to_ascii_lowercase());
        self.allowed_origins
            .iter()
            .any(|o| o.eq_ignore_ascii_case(&target))
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ChromeExtensionInfo {
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub enabled: bool,
    pub pinned: bool,
    pub has_icon: bool,
    pub manifest_version: u64,
    pub popup_path: Option<String>,
    pub options_path: Option<String>,
    pub side_panel_path: Option<String>,
    pub permissions: Vec<String>,
    pub host_permissions: Vec<String>,
    pub install_path: String,
    pub source_path: Option<String>,
    pub runtime_id: Option<String>,
    pub site_access_mode: SiteAccessMode,
    pub allowed_sites: Vec<String>,
    pub allow_in_incognito: bool,
    pub allow_file_urls: bool,
    pub allow_user_scripts: bool,
    pub commands: Vec<ExtensionCommand>,
    pub url_overrides: std::collections::BTreeMap<String, String>,
    pub update_url: Option<String>,
    pub error_count: usize,
    pub security_policy: ExtensionSecurityPolicy,
    pub action_state: ExtensionActionState,
}

/// Out-of-band Singularity metadata stored in `%APPDATA%\.singularity\extensions_meta\<dir_id>.json`
/// (outside the extension directory so Chromium never sees extra files inside the unpacked root).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExtensionMeta {
    pub source_path: Option<String>,
    pub runtime_id: Option<String>,
    #[serde(default)]
    pub site_access_mode: SiteAccessMode,
    #[serde(default)]
    pub allowed_sites: Vec<String>,
    #[serde(default)]
    pub allow_in_incognito: bool,
    #[serde(default)]
    pub allow_file_urls: bool,
    #[serde(default)]
    pub allow_user_scripts: bool,
    #[serde(default)]
    pub custom_shortcuts: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    pub pin_order: Option<u32>,
    #[serde(default)]
    pub update_url: Option<String>,
    #[serde(default)]
    pub last_updated_ms: Option<u64>,
    #[serde(default)]
    pub errors: Vec<ExtensionErrorEntry>,
    #[serde(default)]
    pub action_state: ExtensionActionState,
}

#[derive(Debug, Clone, Serialize)]
pub struct CatalogExtension {
    pub id: &'static str,
    pub name: &'static str,
    pub category: &'static str,
    pub description: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct DetectedExternalExtension {
    pub browser: String,
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub source_dir: String,
}

pub fn curated_catalog() -> Vec<CatalogExtension> {
    vec![
        CatalogExtension {
            id: "ddkjiahejlhfcafbddmgiahcphecmpfh",
            name: "uBlock Origin Lite",
            category: "Privacy",
            description: "Ultra-lightweight Manifest V3 content and tracker blocker.",
        },
        CatalogExtension {
            id: "mnjggcdmjocbbbhaepdhchncahnbgone",
            name: "SponsorBlock for YouTube",
            category: "YouTube",
            description: "Automatically skips sponsored segments, intros, and reminders on YouTube.",
        },
        CatalogExtension {
            id: "gebbhagfogifgggkldgodflihgfeippi",
            name: "Return YouTube Dislike",
            category: "YouTube",
            description: "Restores the community dislike counter on YouTube videos.",
        },
        CatalogExtension {
            id: "eimadpbcbfnmbkopoojfekhnkhdbieeh",
            name: "Dark Reader",
            category: "Appearance",
            description: "Adaptive OLED dark mode for every website.",
        },
        CatalogExtension {
            id: "nngceckbapebfimnlniiiahkandclblb",
            name: "Bitwarden Password Manager",
            category: "Security",
            description: "Open-source end-to-end encrypted password manager.",
        },
        CatalogExtension {
            id: "ghmbeldphafepmbegfdlkpapadhbakde",
            name: "Proton Pass",
            category: "Security",
            description: "Encrypted password and email alias manager by Proton.",
        },
        CatalogExtension {
            id: "pkehgijcmpdhfbdbbnkijodmdjhbjlgp",
            name: "Privacy Badger",
            category: "Privacy",
            description: "Automatically learns to block invisible trackers (EFF).",
        },
    ]
}

pub fn enabled_extensions_dir(roaming_root: &Path) -> PathBuf {
    roaming_root.join("extensions")
}

pub fn disabled_extensions_dir(roaming_root: &Path) -> PathBuf {
    roaming_root.join("extensions-disabled")
}

pub fn extensions_meta_dir(roaming_root: &Path) -> PathBuf {
    roaming_root.join("extensions_meta")
}

pub fn read_extension_meta(roaming_root: &Path, dir_id: &str) -> ExtensionMeta {
    if !is_valid_extension_dir_id(dir_id) {
        return ExtensionMeta::default();
    }
    let path = extensions_meta_dir(roaming_root).join(format!("{}.json", dir_id));
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|raw| serde_json::from_str::<ExtensionMeta>(&raw).ok())
        .unwrap_or_default()
}

fn write_extension_meta(roaming_root: &Path, dir_id: &str, meta: &ExtensionMeta) {
    if !is_valid_extension_dir_id(dir_id) {
        return;
    }
    let dir = extensions_meta_dir(roaming_root);
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join(format!("{}.json", dir_id));
    if let Ok(json) = serde_json::to_string_pretty(meta) {
        let _ = std::fs::write(&path, json);
    }
}

pub fn save_extension_source_path(roaming_root: &Path, dir_id: &str, source_path: &str) {
    let trimmed = source_path.trim();
    if trimmed.is_empty() || !is_valid_extension_dir_id(dir_id) {
        return;
    }
    let mut meta = read_extension_meta(roaming_root, dir_id);
    meta.source_path = Some(trimmed.to_string());
    write_extension_meta(roaming_root, dir_id, &meta);
}

pub fn save_extension_runtime_id(roaming_root: &Path, dir_id: &str, runtime_id: &str) {
    let clean = runtime_id.trim().to_ascii_lowercase();
    if !is_chrome_store_id(&clean) || !is_valid_extension_dir_id(dir_id) {
        return;
    }
    let mut meta = read_extension_meta(roaming_root, dir_id);
    if meta.runtime_id.as_deref() == Some(clean.as_str()) {
        return;
    }
    meta.runtime_id = Some(clean);
    write_extension_meta(roaming_root, dir_id, &meta);
    invalidate_extensions_cache();
}

pub fn remove_extension_meta(roaming_root: &Path, dir_id: &str) {
    if !is_valid_extension_dir_id(dir_id) {
        return;
    }
    let _ = std::fs::remove_file(extensions_meta_dir(roaming_root).join(format!("{}.json", dir_id)));
}

/// Returns `(install_dir, is_enabled)` for an installed extension directory ID.
pub fn locate_extension_dir(roaming_root: &Path, id: &str) -> Option<(PathBuf, bool)> {
    if !is_valid_extension_dir_id(id) {
        return None;
    }
    let enabled = enabled_extensions_dir(roaming_root).join(id);
    if enabled.is_dir() {
        return Some((enabled, true));
    }
    let disabled = disabled_extensions_dir(roaming_root).join(id);
    if disabled.is_dir() {
        return Some((disabled, false));
    }
    None
}

/// Validates a safe extension directory ID (no slashes, no `..`, ASCII alnum / `_` / `-`).
pub fn is_valid_extension_dir_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id != "."
        && id != ".."
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Validates a relative path inside an extension directory or archive, rejecting Windows drive
/// prefixes (`Component::Prefix`, `:`), root dirs (`Component::RootDir`), parent traversal
/// (`Component::ParentDir`), backslashes, and NUL bytes.
fn is_safe_relative_extension_path(rel: &Path) -> bool {
    let raw = rel.to_string_lossy();
    if raw.is_empty() || raw.contains(':') || raw.contains('\0') || raw.contains('\\') {
        return false;
    }
    let mut has_normal = false;
    for comp in rel.components() {
        match comp {
            Component::Normal(seg) => {
                let s = seg.to_string_lossy();
                if s.is_empty() || s.contains(':') {
                    return false;
                }
                has_normal = true;
            }
            Component::CurDir => {}
            Component::Prefix(_) | Component::RootDir | Component::ParentDir => return false,
        }
    }
    has_normal
}

/// Extracts and validates a 32-character Chrome Web Store extension ID (`a`..=`p`)
/// from either a raw ID or a Chrome Web Store URL.
pub fn parse_chrome_web_store_id(input: &str) -> Option<String> {
    let trimmed = input.trim();
    if is_chrome_store_id(trimmed) {
        return Some(trimmed.to_ascii_lowercase());
    }
    // Strip query string and fragment before scanning path segments
    let without_frag = trimmed.split('#').next().unwrap_or(trimmed);
    let without_query = without_frag.split('?').next().unwrap_or(without_frag);
    for seg in without_query.split('/').rev() {
        let s = seg.trim();
        if is_chrome_store_id(s) {
            return Some(s.to_ascii_lowercase());
        }
    }
    None
}

pub fn is_chrome_store_id(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| (b'a'..=b'p').contains(&b.to_ascii_lowercase()))
}

/// Strips a CRX2 or CRX3 header if present and returns the embedded ZIP slice.
pub fn extract_zip_slice_from_crx(raw: &[u8]) -> Result<&[u8], String> {
    if raw.len() < 16 {
        return Err("Extension package is too short or corrupted.".into());
    }
    if raw.starts_with(b"PK\x03\x04") {
        return Ok(raw);
    }
    if !raw.starts_with(b"Cr24") {
        return Err("Unrecognized format: expected a .crx (Cr24) or .zip package.".into());
    }
    let version = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]);
    let zip_offset = match version {
        3 => {
            let header_len = u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]) as usize;
            12usize
                .checked_add(header_len)
                .ok_or_else(|| "Invalid CRX3 header.".to_string())?
        }
        2 => {
            let pubkey_len = u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]) as usize;
            let sig_len = u32::from_le_bytes([raw[12], raw[13], raw[14], raw[15]]) as usize;
            16usize
                .checked_add(pubkey_len)
                .and_then(|v| v.checked_add(sig_len))
                .ok_or_else(|| "Invalid CRX2 header.".to_string())?
        }
        other => {
            return Err(format!("Unsupported CRX version ({}).", other));
        }
    };
    if zip_offset >= raw.len() || !raw[zip_offset..].starts_with(b"PK\x03\x04") {
        return Err("Embedded ZIP archive not found inside CRX package.".into());
    }
    Ok(&raw[zip_offset..])
}

/// Safely extracts a `.crx` or `.zip` Chrome extension archive into `dest_dir` with strict
/// zip-slip protection, symlink rejection, entry-count caps, and total uncompressed size caps.
pub fn extract_crx_or_zip_to_dir(raw: &[u8], dest_dir: &Path) -> Result<(), String> {
    if raw.len() > MAX_CRX_BYTES {
        return Err("Extension package is too large (> 32 MiB).".into());
    }
    let zip_bytes = extract_zip_slice_from_crx(raw)?;
    let reader = Cursor::new(zip_bytes);
    let mut archive =
        zip::ZipArchive::new(reader).map_err(|e| format!("Invalid ZIP archive: {}", e))?;

    if archive.len() > MAX_ARCHIVE_ENTRIES {
        return Err("Too many files inside extension archive.".into());
    }

    std::fs::create_dir_all(dest_dir)
        .map_err(|e| format!("Failed to create extension directory: {}", e))?;

    let mut total_written: u64 = 0;
    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| format!("Failed reading archive entry: {}", e))?;
        if entry
            .unix_mode()
            .is_some_and(|mode| (mode & 0o170000) == 0o120000)
        {
            return Err("Disallowed symbolic link detected inside archive.".into());
        }
        let Some(rel_path) = entry.enclosed_name().map(|p| p.to_path_buf()) else {
            return Err("Disallowed path detected inside archive (zip-slip blocked).".into());
        };
        if !is_safe_relative_extension_path(&rel_path) {
            return Err("Disallowed path component detected inside archive (zip-slip blocked).".into());
        }
        let out_path = dest_dir.join(&rel_path);
        if entry.is_dir() {
            std::fs::create_dir_all(&out_path)
                .map_err(|e| format!("Failed creating directory {}: {}", rel_path.display(), e))?;
        } else {
            if let Some(parent) = out_path.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("Failed creating parent directory: {}", e))?;
            }
            let mut out_file = std::fs::File::create(&out_path)
                .map_err(|e| format!("Failed writing {}: {}", rel_path.display(), e))?;
            let mut buf = [0u8; 8192];
            loop {
                let n = entry
                    .read(&mut buf)
                    .map_err(|e| format!("Decompression error: {}", e))?;
                if n == 0 {
                    break;
                }
                total_written = total_written.saturating_add(n as u64);
                if total_written > MAX_EXTRACTED_BYTES {
                    return Err("Extracted extension exceeds 64 MiB limit — aborted.".into());
                }
                std::io::Write::write_all(&mut out_file, &buf[..n])
                    .map_err(|e| format!("Disk write error: {}", e))?;
            }
        }
    }

    // If the archive had a single top-level wrapper folder containing manifest.json, unwrap it.
    if !dest_dir.join("manifest.json").is_file() {
        let subdirs: Vec<PathBuf> = std::fs::read_dir(dest_dir)
            .ok()
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                std::fs::symlink_metadata(p)
                    .map(|m| !m.file_type().is_symlink() && m.is_dir())
                    .unwrap_or(false)
                    && p.file_name()
                        .and_then(|n| n.to_str())
                        .map(|n| !n.eq_ignore_ascii_case("__MACOSX"))
                        .unwrap_or(true)
            })
            .collect();
        if subdirs.len() == 1 && subdirs[0].join("manifest.json").is_file() {
            let inner = &subdirs[0];
            let entries: Vec<PathBuf> = std::fs::read_dir(inner)
                .ok()
                .into_iter()
                .flatten()
                .flatten()
                .map(|e| e.path())
                .collect();
            for item in entries {
                if let Some(fname) = item.file_name() {
                    let _ = std::fs::rename(&item, dest_dir.join(fname));
                }
            }
            let _ = std::fs::remove_dir_all(inner);
        }
    }

    if !dest_dir.join("manifest.json").is_file() {
        return Err("manifest.json not found inside this Chrome extension.".into());
    }
    Ok(())
}

fn is_safe_locale_tag(locale: &str) -> bool {
    !locale.is_empty()
        && locale.len() <= 32
        && locale
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn read_configured_ui_language(roaming_root: &Path) -> Option<String> {
    let raw = std::fs::read_to_string(roaming_root.join("profile.json")).ok()?;
    let val = serde_json::from_str::<serde_json::Value>(&raw).ok()?;
    let lang = val.get("language").and_then(|v| v.as_str())?;
    if crate::roaming_store::is_valid_language(lang) {
        Some(lang.to_string())
    } else {
        None
    }
}

fn resolve_i18n_string(
    ext_dir: &Path,
    raw: &str,
    preferred_lang: Option<&str>,
    default_locale: Option<&str>,
) -> String {
    let trimmed = raw.trim();
    if !(trimmed.starts_with("__MSG_") && trimmed.ends_with("__") && trimmed.len() > 8) {
        return trimmed.to_string();
    }
    let key = &trimmed[6..trimmed.len() - 2];

    // Respect configured UI language first, then manifest `default_locale`, then English fallback.
    let mut locales: Vec<String> = Vec::new();
    let mut push_locale = |loc: &str| {
        let clean = loc.trim();
        if is_safe_locale_tag(clean) && !locales.iter().any(|x| x.eq_ignore_ascii_case(clean)) {
            locales.push(clean.to_string());
        }
    };

    if let Some(lang) = preferred_lang {
        match lang.trim().to_ascii_lowercase().as_str() {
            "fr" => {
                push_locale("fr");
                push_locale("fr_FR");
            }
            "en" => {
                push_locale("en");
                push_locale("en_US");
                push_locale("en_GB");
            }
            other if !other.is_empty() => {
                push_locale(other);
            }
            _ => {}
        }
    }
    if let Some(def_loc) = default_locale {
        push_locale(def_loc);
        if let Some((base, _)) = def_loc.split_once(['_', '-']) {
            push_locale(base);
        }
    }
    push_locale("en");
    push_locale("en_US");
    push_locale("en_GB");

    let locales_root = ext_dir.join("_locales");
    let Ok(loc_meta) = std::fs::symlink_metadata(&locales_root) else {
        return trimmed.to_string();
    };
    if loc_meta.file_type().is_symlink() || !loc_meta.is_dir() {
        return trimmed.to_string();
    }

    for locale in locales {
        let p = locales_root.join(&locale).join("messages.json");
        let Ok(m) = std::fs::symlink_metadata(&p) else {
            continue;
        };
        if m.file_type().is_symlink() || !m.is_file() {
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(&p) {
            let clean = text.trim_start_matches('\u{feff}');
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(clean) {
                if let Some(obj) = val.as_object() {
                    for (k, v) in obj {
                        if k.eq_ignore_ascii_case(key) {
                            if let Some(msg) = v.get("message").and_then(|m| m.as_str()) {
                                if !msg.trim().is_empty() {
                                    return msg.trim().to_string();
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    trimmed.to_string()
}

fn pick_manifest_icon_rel_path(manifest: &serde_json::Value) -> Option<String> {
    let pick_from_map = |val: &serde_json::Value| -> Option<String> {
        if let Some(s) = val.as_str() {
            return Some(s.to_string());
        }
        let obj = val.as_object()?;
        for size in ["128", "96", "64", "48", "32", "24", "16"] {
            if let Some(p) = obj.get(size).and_then(|v| v.as_str()) {
                return Some(p.to_string());
            }
        }
        obj.values().find_map(|v| v.as_str().map(|s| s.to_string()))
    };

    if let Some(icons) = manifest.get("icons") {
        if let Some(p) = pick_from_map(icons) {
            return Some(p);
        }
    }
    for action_key in ["action", "browser_action", "page_action"] {
        if let Some(di) = manifest.get(action_key).and_then(|a| a.get("default_icon")) {
            if let Some(p) = pick_from_map(di) {
                return Some(p);
            }
        }
    }
    None
}

fn parse_extension_dir(
    roaming_root: &Path,
    ext_dir: &Path,
    id: &str,
    enabled: bool,
    pinned_ids: &[String],
) -> Option<ChromeExtensionInfo> {
    let meta = read_extension_meta(roaming_root, id);
    let preferred_lang = read_configured_ui_language(roaming_root);
    parse_extension_dir_with_meta_and_lang(
        ext_dir,
        id,
        enabled,
        pinned_ids,
        meta,
        preferred_lang.as_deref(),
    )
}

fn parse_extension_dir_with_meta(
    ext_dir: &Path,
    id: &str,
    enabled: bool,
    pinned_ids: &[String],
    meta: ExtensionMeta,
) -> Option<ChromeExtensionInfo> {
    parse_extension_dir_with_meta_and_lang(ext_dir, id, enabled, pinned_ids, meta, None)
}

fn parse_extension_dir_with_meta_and_lang(
    ext_dir: &Path,
    id: &str,
    enabled: bool,
    pinned_ids: &[String],
    meta: ExtensionMeta,
    preferred_lang: Option<&str>,
) -> Option<ChromeExtensionInfo> {
    let manifest_path = ext_dir.join("manifest.json");
    let raw = std::fs::read_to_string(&manifest_path).ok()?;
    let clean = raw.trim_start_matches('\u{feff}');
    let manifest: serde_json::Value = serde_json::from_str(clean).ok()?;

    let default_locale = manifest.get("default_locale").and_then(|v| v.as_str());
    let raw_name = manifest
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or(id);
    let raw_desc = manifest
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let name = resolve_i18n_string(ext_dir, raw_name, preferred_lang, default_locale);
    let description = resolve_i18n_string(ext_dir, raw_desc, preferred_lang, default_locale);
    let version = manifest
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("1.0")
        .to_string();
    let manifest_version = manifest
        .get("manifest_version")
        .and_then(|v| v.as_u64())
        .unwrap_or(3);

    let popup_path = manifest
        .get("action")
        .or_else(|| manifest.get("browser_action"))
        .or_else(|| manifest.get("page_action"))
        .and_then(|a| a.get("default_popup"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let options_path = manifest
        .get("options_page")
        .and_then(|v| v.as_str())
        .or_else(|| {
            manifest
                .get("options_ui")
                .and_then(|o| o.get("page"))
                .and_then(|v| v.as_str())
        })
        .map(|s| s.to_string());

    let host_permissions: Vec<String> = manifest
        .get("host_permissions")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .take(16)
                .collect()
        })
        .unwrap_or_default();

    let mut permissions: Vec<String> = manifest
        .get("permissions")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .take(16)
                .collect()
        })
        .unwrap_or_default();
    for hp in &host_permissions {
        if permissions.len() >= 24 {
            break;
        }
        if !permissions.iter().any(|p| p == hp) {
            permissions.push(hp.clone());
        }
    }

    let side_panel_path = manifest
        .get("side_panel")
        .and_then(|s| s.get("default_path"))
        .and_then(|v| v.as_str())
        .or_else(|| {
            manifest
                .get("sidebar_action")
                .and_then(|s| s.get("default_panel"))
                .and_then(|v| v.as_str())
        })
        .map(|s| s.to_string());

    let mut commands = Vec::new();
    if let Some(cmd_obj) = manifest.get("commands").and_then(|v| v.as_object()) {
        for (cmd_name, cmd_val) in cmd_obj {
            let desc = cmd_val
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let suggested = cmd_val.get("suggested_key").and_then(|sk| {
                sk.get("default")
                    .or_else(|| sk.get("windows"))
                    .or_else(|| sk.get("linux"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            });
            let custom_key = meta.custom_shortcuts.get(cmd_name).cloned();
            let global = cmd_val
                .get("global")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            commands.push(ExtensionCommand {
                name: cmd_name.clone(),
                description: desc,
                suggested_key: suggested,
                custom_key,
                global,
            });
        }
    }

    let mut url_overrides = std::collections::BTreeMap::new();
    if let Some(ov) = manifest
        .get("chrome_url_overrides")
        .and_then(|v| v.as_object())
    {
        for (k, v) in ov {
            if let Some(s) = v.as_str() {
                url_overrides.insert(k.clone(), s.to_string());
            }
        }
    }

    let update_url = manifest
        .get("update_url")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| meta.update_url.clone());

    let mut security_policy = ExtensionSecurityPolicy::default();
    if let Some(csp) = manifest.get("content_security_policy") {
        if let Some(s) = csp.as_str() {
            security_policy.extension_pages_csp = Some(s.to_string());
        } else if let Some(obj) = csp.as_object() {
            security_policy.extension_pages_csp = obj
                .get("extension_pages")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            security_policy.sandbox_csp = obj
                .get("sandbox")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
        }
    }
    if let Some(war) = manifest
        .get("web_accessible_resources")
        .and_then(|v| v.as_array())
    {
        let mut mv2_resources = Vec::new();
        for item in war {
            if let Some(s) = item.as_str() {
                mv2_resources.push(s.to_string());
            } else if let Some(obj) = item.as_object() {
                let resources = obj
                    .get("resources")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default();
                let matches = obj
                    .get("matches")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default();
                let use_dynamic_url = obj
                    .get("use_dynamic_url")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                security_policy
                    .web_accessible_resources
                    .push(WebAccessibleResourceRule {
                        resources,
                        matches,
                        use_dynamic_url,
                    });
            }
        }
        if !mv2_resources.is_empty() {
            security_policy
                .web_accessible_resources
                .push(WebAccessibleResourceRule {
                    resources: mv2_resources,
                    matches: vec!["<all_urls>".to_string()],
                    use_dynamic_url: false,
                });
        }
    }

    let has_icon = pick_manifest_icon_rel_path(&manifest)
        .and_then(|rel| resolve_safe_child_path(ext_dir, &rel))
        .is_some_and(|p| p.is_file());

    let error_count = meta.errors.len();
    let mut action_state = meta.action_state;
    if action_state.title.is_empty() {
        action_state.title = manifest
            .get("action")
            .or_else(|| manifest.get("browser_action"))
            .or_else(|| manifest.get("page_action"))
            .and_then(|a| a.get("default_title"))
            .and_then(|v| v.as_str())
            .map(|s| resolve_i18n_string(ext_dir, s, preferred_lang, default_locale))
            .unwrap_or_else(|| name.clone());
    }

    Some(ChromeExtensionInfo {
        id: id.to_string(),
        name,
        version,
        description,
        enabled,
        pinned: pinned_ids.iter().any(|p| p == id),
        has_icon,
        manifest_version,
        popup_path,
        options_path,
        side_panel_path,
        permissions,
        host_permissions,
        install_path: ext_dir.to_string_lossy().to_string(),
        source_path: meta.source_path,
        runtime_id: meta.runtime_id,
        site_access_mode: meta.site_access_mode,
        allowed_sites: meta.allowed_sites,
        allow_in_incognito: meta.allow_in_incognito,
        allow_file_urls: meta.allow_file_urls,
        allow_user_scripts: meta.allow_user_scripts,
        commands,
        url_overrides,
        update_url,
        error_count,
        security_policy,
        action_state,
    })
}

fn resolve_safe_child_path(base_dir: &Path, rel: &str) -> Option<PathBuf> {
    let trimmed = rel.trim().trim_start_matches('/');
    let rel_path = Path::new(trimmed);
    if !is_safe_relative_extension_path(rel_path) {
        return None;
    }
    let joined = base_dir.join(rel_path);
    let canon_base = std::fs::canonicalize(base_dir).ok()?;
    let canon_target = std::fs::canonicalize(&joined).ok()?;
    if canon_target.starts_with(&canon_base) {
        Some(canon_target)
    } else {
        None
    }
}

/// Lists all installed Chrome extensions (both enabled in `extensions/` and disabled in `extensions-disabled/`).
pub fn list_extensions(roaming_root: &Path, pinned_ids: &[String]) -> Vec<ChromeExtensionInfo> {
    let preferred_lang = read_configured_ui_language(roaming_root);
    let mut out = Vec::new();
    for (dir, enabled) in [
        (enabled_extensions_dir(roaming_root), true),
        (disabled_extensions_dir(roaming_root), false),
    ] {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let p = entry.path();
            if !p.is_dir() {
                continue;
            }
            let Some(id) = p.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if !is_valid_extension_dir_id(id) {
                continue;
            }
            let meta = read_extension_meta(roaming_root, id);
            if let Some(info) = parse_extension_dir_with_meta_and_lang(
                &p,
                id,
                enabled,
                pinned_ids,
                meta,
                preferred_lang.as_deref(),
            ) {
                out.push(info);
            }
        }
    }
    out.sort_by(|a, b| {
        b.enabled
            .cmp(&a.enabled)
            .then_with(|| b.pinned.cmp(&a.pinned))
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    out
}

static EXTENSIONS_CACHE: std::sync::OnceLock<
    std::sync::Mutex<Option<(PathBuf, Option<String>, Vec<String>, Vec<ChromeExtensionInfo>)>>,
> = std::sync::OnceLock::new();

static EXTENSION_HOST_DOMAINS_CACHE: std::sync::OnceLock<
    std::sync::Mutex<Option<(PathBuf, Vec<String>)>>,
> = std::sync::OnceLock::new();

/// Returns installed extensions from RAM when unchanged (zero directory scans on `/api/state`).
pub fn list_extensions_cached(
    roaming_root: &Path,
    pinned_ids: &[String],
) -> Vec<ChromeExtensionInfo> {
    let lang = read_configured_ui_language(roaming_root);
    let lock = EXTENSIONS_CACHE.get_or_init(|| std::sync::Mutex::new(None));
    if let Ok(guard) = lock.lock() {
        if let Some((ref cached_root, ref cached_lang, ref cached_pinned, ref items)) = *guard {
            if cached_root == roaming_root
                && *cached_lang == lang
                && cached_pinned.as_slice() == pinned_ids
            {
                return items.clone();
            }
        }
    }
    let fresh = list_extensions(roaming_root, pinned_ids);
    if let Ok(mut guard) = lock.lock() {
        *guard = Some((roaming_root.to_path_buf(), lang, pinned_ids.to_vec(), fresh.clone()));
    }
    fresh
}

/// Returns `true` if `host` is a TLD, multi-label public suffix (eTLD like `co.uk`, `com.au`,
/// `gouv.fr`), or shared hosting public suffix (`github.io`, `pages.dev`, `netlify.app`, etc.)
/// that an extension must NEVER be allowed to blanket-whitelist.
fn is_public_suffix(host: &str) -> bool {
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 || labels.iter().any(|l| l.is_empty()) {
        return true;
    }

    const MULTI_LABEL_PUBLIC_SUFFIXES: &[&str] = &[
        // Country second-level registries
        "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk",
        "nhs.uk", "police.uk", "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au",
        "id.au", "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz", "co.jp", "ne.jp", "or.jp",
        "go.jp", "ac.jp", "ed.jp", "gr.jp", "lg.jp", "com.br", "net.br", "org.br", "gov.br",
        "edu.br", "co.kr", "or.kr", "go.kr", "ne.kr", "ac.kr", "com.cn", "net.cn", "org.cn",
        "gov.cn", "edu.cn", "com.tw", "org.tw", "gov.tw", "edu.tw", "com.hk", "org.hk",
        "gov.hk", "edu.hk", "com.sg", "org.sg", "gov.sg", "edu.sg", "co.in", "net.in",
        "org.in", "gov.in", "ac.in", "nic.in", "co.za", "org.za", "gov.za", "ac.za", "co.il",
        "org.il", "gov.il", "ac.il", "com.mx", "org.mx", "gob.mx", "edu.mx", "com.ar",
        "org.ar", "gov.ar", "com.tr", "org.tr", "gov.tr", "edu.tr", "com.pl", "net.pl",
        "org.pl", "gov.pl", "edu.pl", "com.es", "nom.es", "org.es", "gob.es", "edu.es",
        "asso.fr", "nom.fr", "prd.fr", "gouv.fr", "tm.fr", "com.fr", "gv.at", "or.at",
        "ac.at", "co.at", "com.ua", "org.ua", "gov.ua", "net.ua", "com.ru", "org.ru",
        "net.ru", "pp.ru", "co.id", "or.id", "go.id", "ac.id", "com.my", "org.my", "gov.my",
        "edu.my", "com.ph", "org.ph", "gov.ph", "com.vn", "org.vn", "gov.vn", "co.th",
        "or.th", "go.th", "ac.th", "com.co", "org.co", "gov.co", "com.pe", "org.pe", "gob.pe",
        "com.ve", "com.eg", "com.sa", "com.ng", "com.pk", "com.bd", "co.ke", "co.tz",
        "com.gr", "com.pt", "com.ro", "com.hr", "com.cy", "com.mt", "eu.org", "uk.com",
        "us.com", "de.com", "eu.com", "gb.com", "no.com", "qc.com", "ru.com", "sa.com",
        "se.com", "za.com", "br.com", "cn.com", "jpn.com", "kr.com", "mex.com", "in.net",
        "uk.net", "se.net", "gb.net", "hu.net",
        // Shared multi-tenant hosting / PSL private suffixes
        "github.io", "gitlab.io", "bitbucket.io", "pages.dev", "workers.dev", "netlify.app",
        "vercel.app", "herokuapp.com", "appspot.com", "firebaseapp.com", "web.app",
        "cloudfront.net", "amazonaws.com", "s3.amazonaws.com", "azurewebsites.net",
        "blob.core.windows.net", "cloudapp.net", "googleapis.com", "googleusercontent.com",
        "blogspot.com", "wordpress.com", "tumblr.com", "glitch.me", "fly.dev", "onrender.com",
        "railway.app", "deno.dev", "surge.sh", "replit.dev", "repl.co", "ngrok.io",
        "ngrok-free.app", "trycloudflare.com", "duckdns.org", "ddns.net", "no-ip.org",
        "dyndns.org",
    ];
    if MULTI_LABEL_PUBLIC_SUFFIXES.contains(&host) {
        return true;
    }

    // Generic ccTLD 2nd-level registry guard (e.g., `<registry>.<cc>` with 2-letter ccTLD)
    if labels.len() == 2 && labels[1].len() == 2 && labels[1].bytes().all(|b| b.is_ascii_alphabetic()) {
        if matches!(
            labels[0],
            "co" | "com" | "org" | "net" | "gov" | "gob" | "gouv" | "govt" | "edu" | "ac"
                | "mil" | "nic" | "sch" | "nom" | "asso" | "or" | "ne" | "go" | "ed" | "gr"
                | "lg" | "gv" | "id" | "me" | "ltd" | "plc"
        ) {
            return true;
        }
    }

    false
}

/// Extracts a concrete domain from a Chrome extension match pattern or URL
/// (e.g. `https://*.bitwarden.com/*` -> `bitwarden.com`), ignoring broad wildcards
/// like `<all_urls>`, `*://*/*`, and multi-label public suffixes (`co.uk`, `github.io`, etc.)
/// so the adblocker stays effective on normal sites.
fn extract_concrete_host_from_pattern(raw: &str) -> Option<String> {
    let s = raw.trim().to_ascii_lowercase();
    if s.is_empty() || s == "<all_urls>" {
        return None;
    }
    let after_scheme = if let Some((_, rest)) = s.split_once("://") {
        rest
    } else {
        return None;
    };
    let host_port = after_scheme.split('/').next().unwrap_or("");
    let host = host_port.split(':').next().unwrap_or("").trim();
    let host = host.trim_start_matches("*.").trim_start_matches('.').trim_end_matches('.');
    if host.is_empty()
        || host.contains('*')
        || !host.contains('.')
        || host == "localhost"
        || host == "127.0.0.1"
        || host.parse::<std::net::IpAddr>().is_ok()
        || !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        || is_public_suffix(host)
    {
        return None;
    }
    Some(host.to_string())
}

/// Collects concrete host domains declared in enabled Chrome extensions' `manifest.json`
/// (`host_permissions`, `permissions`, `content_scripts[].matches`, `externally_connectable.matches`)
/// — strictly excluding `optional_host_permissions`, `homepage_url`, and public suffixes —
/// so Singularity preserves extension auth cookies and API token-refresh calls safely.
pub fn collect_installed_extension_host_domains(roaming_root: &Path) -> Vec<String> {
    let lock = EXTENSION_HOST_DOMAINS_CACHE.get_or_init(|| std::sync::Mutex::new(None));
    if let Ok(guard) = lock.lock() {
        if let Some((ref cached_root, ref domains)) = *guard {
            if cached_root == roaming_root {
                return domains.clone();
            }
        }
    }

    let mut set = std::collections::BTreeSet::new();
    let dir = enabled_extensions_dir(roaming_root);
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if !p.is_dir() {
                continue;
            }
            let Ok(raw) = std::fs::read_to_string(p.join("manifest.json")) else {
                continue;
            };
            let Ok(manifest) =
                serde_json::from_str::<serde_json::Value>(raw.trim_start_matches('\u{feff}'))
            else {
                continue;
            };

            let mut patterns: Vec<&str> = Vec::new();
            // Strictly exclude `optional_host_permissions` and `homepage_url`!
            for key in ["host_permissions", "permissions"] {
                if let Some(arr) = manifest.get(key).and_then(|v| v.as_array()) {
                    for item in arr {
                        if let Some(s) = item.as_str() {
                            if s.contains("://") {
                                patterns.push(s);
                            }
                        }
                    }
                }
            }
            if let Some(cs_arr) = manifest.get("content_scripts").and_then(|v| v.as_array()) {
                for cs in cs_arr {
                    if let Some(m_arr) = cs.get("matches").and_then(|v| v.as_array()) {
                        for item in m_arr {
                            if let Some(s) = item.as_str() {
                                patterns.push(s);
                            }
                        }
                    }
                }
            }
            if let Some(ec_arr) = manifest
                .get("externally_connectable")
                .and_then(|e| e.get("matches"))
                .and_then(|v| v.as_array())
            {
                for item in ec_arr {
                    if let Some(s) = item.as_str() {
                        patterns.push(s);
                    }
                }
            }

            for pat in patterns {
                if let Some(host) = extract_concrete_host_from_pattern(pat) {
                    set.insert(host);
                }
            }
        }
    }

    let domains: Vec<String> = set.into_iter().collect();
    if let Ok(mut guard) = lock.lock() {
        *guard = Some((roaming_root.to_path_buf(), domains.clone()));
    }
    domains
}

/// Returns `true` when `host` equals or is a subdomain of any domain in `ext_domains`.
pub fn host_matches_extension_domains(host: &str, ext_domains: &[String]) -> bool {
    let clean = host.trim().trim_start_matches('.').to_ascii_lowercase();
    if clean.is_empty() {
        return false;
    }
    ext_domains.iter().any(|d| {
        clean == *d
            || (clean.len() > d.len()
                && clean.ends_with(d.as_str())
                && clean.as_bytes()[clean.len() - d.len() - 1] == b'.')
    })
}

/// Invalidates the cached extensions snapshot after any install, uninstall, toggle, or pin mutation.
pub fn invalidate_extensions_cache() {
    if let Some(lock) = EXTENSIONS_CACHE.get() {
        if let Ok(mut guard) = lock.lock() {
            *guard = None;
        }
    }
    if let Some(lock) = EXTENSION_HOST_DOMAINS_CACHE.get() {
        if let Ok(mut guard) = lock.lock() {
            *guard = None;
        }
    }
}

fn decode_xml_char_entities(input: &str) -> String {
    if !input.contains('&') {
        return input.to_string();
    }
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'&' {
            if let Some(semi) = input[i..].find(';') {
                if semi <= 12 {
                    let ent = &input[i + 1..i + semi];
                    let decoded = match ent {
                        "amp" => Some('&'),
                        "lt" => Some('<'),
                        "gt" => Some('>'),
                        "quot" => Some('"'),
                        "apos" => Some('\''),
                        "colon" => Some(':'),
                        "tab" => Some('\t'),
                        "newline" => Some('\n'),
                        _ if ent.starts_with("#x") || ent.starts_with("#X") => {
                            u32::from_str_radix(&ent[2..], 16)
                                .ok()
                                .and_then(char::from_u32)
                        }
                        _ if ent.starts_with('#') => {
                            ent[1..].parse::<u32>().ok().and_then(char::from_u32)
                        }
                        _ => None,
                    };
                    if let Some(ch) = decoded {
                        out.push(ch);
                        i += semi + 1;
                        continue;
                    }
                }
            }
        }
        if let Some(ch) = input[i..].chars().next() {
            out.push(ch);
            i += ch.len_utf8();
        } else {
            break;
        }
    }
    out
}

fn contains_dangerous_css_or_uri(raw: &str) -> bool {
    let decoded = decode_xml_char_entities(raw);
    let compact: String = decoded
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && !c.is_control())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    compact.contains("javascript:")
        || compact.contains("vbscript:")
        || compact.contains("data:")
        || compact.contains("@import")
        || compact.contains("expression(")
        || compact.contains("behavior:")
        || compact.contains("-moz-binding")
        || compact.contains("url(http:")
        || compact.contains("url(https:")
        || compact.contains("url(//")
}

/// Strict allowlist SVG icon sanitizer/validator:
/// - Rejects `<!DOCTYPE`, `<!ENTITY`, `<![CDATA[`, `<?xml-stylesheet`, and malformed tags.
/// - Allows ONLY safe static vector SVG elements (blocking `<script>`, `<*:script>`,
///   `<foreignObject>`, SMIL `<set>`/`<animate*>`, `<iframe>`, `<object>`, `<embed>`, `<a>`, etc.).
/// - Rejects ALL `on*` event attributes (with or without spaces around `=`, with or without namespace).
/// - Rejects `javascript:`, `vbscript:`, `data:`, and external URLs in `href`/`xlink:href`/`src`/CSS.
pub fn is_safe_svg_icon(bytes: &[u8]) -> bool {
    let Ok(txt) = std::str::from_utf8(bytes) else {
        return false;
    };
    if txt.contains('\0') {
        return false;
    }
    let lower_full = txt.to_ascii_lowercase();
    if lower_full.contains("<!doctype")
        || lower_full.contains("<!entity")
        || lower_full.contains("<![cdata[")
        || lower_full.contains("<?xml-stylesheet")
    {
        return false;
    }

    const ALLOWED_SVG_ELEMENTS: &[&str] = &[
        "svg", "g", "defs", "title", "desc", "metadata", "symbol", "use", "path", "circle",
        "ellipse", "rect", "line", "polyline", "polygon", "lineargradient", "radialgradient",
        "stop", "clippath", "mask", "pattern", "filter", "fegaussianblur", "feoffset", "feblend",
        "fecolormatrix", "fecomponenttransfer", "fefunca", "fefuncr", "fefuncg", "fefuncb",
        "fecomposite", "feflood", "femerge", "femergenode", "fedropshadow", "text", "tspan",
        "style",
    ];

    let b = txt.as_bytes();
    let len = b.len();
    let mut i = 0usize;
    let mut saw_svg_root = false;
    let mut in_style = false;
    let mut style_start = 0usize;

    while i < len {
        if b[i] != b'<' {
            i += 1;
            continue;
        }
        // Comment `<!-- ... -->`
        if txt[i..].starts_with("<!--") {
            let Some(end_rel) = txt[i + 4..].find("-->") else {
                return false;
            };
            i += 4 + end_rel + 3;
            continue;
        }
        // Processing instruction: allow ONLY `<?xml ... ?>`
        if txt[i..].starts_with("<?") {
            let Some(end_rel) = txt[i + 2..].find("?>") else {
                return false;
            };
            let pi = txt[i + 2..i + 2 + end_rel].trim_start();
            let pi_name = pi.split_whitespace().next().unwrap_or("");
            if !pi_name.eq_ignore_ascii_case("xml") {
                return false;
            }
            i += 2 + end_rel + 2;
            continue;
        }
        // Reject any other `<!...` declaration
        if i + 1 < len && b[i + 1] == b'!' {
            return false;
        }

        // Parse tag until matching `>` respecting quoted attribute values
        let tag_start = i + 1;
        let mut j = tag_start;
        let mut quote: u8 = 0;
        while j < len {
            let ch = b[j];
            if quote != 0 {
                if ch == quote {
                    quote = 0;
                }
            } else if ch == b'"' || ch == b'\'' {
                quote = ch;
            } else if ch == b'>' {
                break;
            }
            j += 1;
        }
        if j >= len || quote != 0 {
            return false;
        }
        let inner = txt[tag_start..j].trim();
        let is_closing = inner.starts_with('/');
        let inner_body = inner.trim_start_matches('/').trim_end_matches('/').trim();
        if inner_body.is_empty() {
            return false;
        }

        let name_end = inner_body
            .find(|c: char| c.is_ascii_whitespace())
            .unwrap_or(inner_body.len());
        let raw_tag_name = &inner_body[..name_end];
        let local_tag = raw_tag_name
            .rsplit(':')
            .next()
            .unwrap_or(raw_tag_name)
            .to_ascii_lowercase();

        if !ALLOWED_SVG_ELEMENTS.contains(&local_tag.as_str()) {
            return false;
        }

        if is_closing {
            if local_tag == "style" && in_style {
                let style_body = &txt[style_start..i];
                if contains_dangerous_css_or_uri(style_body) {
                    return false;
                }
                in_style = false;
            }
            i = j + 1;
            continue;
        }

        if local_tag == "svg" {
            saw_svg_root = true;
        }
        if local_tag == "style" && !inner.ends_with('/') {
            in_style = true;
            style_start = j + 1;
        }

        // Parse and validate every attribute in the opening tag
        let attrs = &inner_body[name_end..];
        let ab = attrs.as_bytes();
        let alen = ab.len();
        let mut p = 0usize;
        while p < alen {
            while p < alen && (ab[p].is_ascii_whitespace() || ab[p] == b'/') {
                p += 1;
            }
            if p >= alen {
                break;
            }
            let a_start = p;
            while p < alen && !ab[p].is_ascii_whitespace() && ab[p] != b'=' {
                p += 1;
            }
            let raw_attr_name = &attrs[a_start..p];
            if raw_attr_name.is_empty() {
                return false;
            }
            let local_attr = raw_attr_name
                .rsplit(':')
                .next()
                .unwrap_or(raw_attr_name)
                .to_ascii_lowercase();

            // Block ALL `on*` event handler attributes (regardless of whitespace around `=`)
            if local_attr.starts_with("on") {
                return false;
            }

            while p < alen && ab[p].is_ascii_whitespace() {
                p += 1;
            }
            let attr_val = if p < alen && ab[p] == b'=' {
                p += 1;
                while p < alen && ab[p].is_ascii_whitespace() {
                    p += 1;
                }
                if p >= alen {
                    return false;
                }
                if ab[p] == b'"' || ab[p] == b'\'' {
                    let q = ab[p];
                    let vs = p + 1;
                    let mut ve = vs;
                    while ve < alen && ab[ve] != q {
                        ve += 1;
                    }
                    if ve >= alen {
                        return false;
                    }
                    p = ve + 1;
                    &attrs[vs..ve]
                } else {
                    let vs = p;
                    while p < alen && !ab[p].is_ascii_whitespace() {
                        p += 1;
                    }
                    &attrs[vs..p]
                }
            } else {
                ""
            };

            let decoded_val = decode_xml_char_entities(attr_val);
            let compact_val: String = decoded_val
                .chars()
                .filter(|c| !c.is_ascii_whitespace() && !c.is_control())
                .map(|c| c.to_ascii_lowercase())
                .collect();

            if compact_val.contains("javascript:")
                || compact_val.contains("vbscript:")
                || compact_val.contains("data:")
            {
                return false;
            }
            if matches!(local_attr.as_str(), "href" | "src" | "action" | "formaction") {
                // Only allow local fragment references (`#id`) on SVG elements like `<use>` / gradients
                let trimmed_val = decoded_val.trim();
                if !trimmed_val.is_empty() && !trimmed_val.starts_with('#') {
                    return false;
                }
            }
            if local_attr == "style" && contains_dangerous_css_or_uri(attr_val) {
                return false;
            }
        }

        i = j + 1;
    }

    saw_svg_root && !in_style
}

/// Reads the real icon image bytes and MIME type for an installed Chrome extension.
pub fn read_extension_icon(roaming_root: &Path, id: &str) -> Option<(Vec<u8>, &'static str)> {
    if !is_valid_extension_dir_id(id) {
        return None;
    }
    let candidates = [
        enabled_extensions_dir(roaming_root).join(id),
        disabled_extensions_dir(roaming_root).join(id),
    ];
    for ext_dir in candidates {
        let manifest_path = ext_dir.join("manifest.json");
        let Ok(raw) = std::fs::read_to_string(&manifest_path) else {
            continue;
        };
        let Ok(manifest) = serde_json::from_str::<serde_json::Value>(raw.trim_start_matches('\u{feff}')) else {
            continue;
        };
        let Some(rel) = pick_manifest_icon_rel_path(&manifest) else {
            continue;
        };
        let Some(icon_path) = resolve_safe_child_path(&ext_dir, &rel) else {
            continue;
        };
        let Ok(bytes) = std::fs::read(&icon_path) else {
            continue;
        };
        if bytes.is_empty() || bytes.len() > 2 * 1024 * 1024 {
            continue;
        }
        let mime = match icon_path
            .extension()
            .and_then(|e| e.to_str())
            .map(|s| s.to_ascii_lowercase())
            .as_deref()
        {
            Some("svg") => {
                // Strict allowlist SVG validation (blocks scripts, SMIL, foreignObject, on*, javascript:/data:)
                if !is_safe_svg_icon(&bytes) {
                    continue;
                }
                "image/svg+xml"
            }
            Some("webp") => "image/webp",
            Some("jpg") | Some("jpeg") => "image/jpeg",
            Some("ico") => "image/x-icon",
            _ => "image/png",
        };
        return Some((bytes, mime));
    }
    None
}

fn read_pb_varint(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let mut out = 0u64;
    let mut shift = 0u32;
    while *pos < buf.len() && shift < 64 {
        let b = buf[*pos];
        *pos += 1;
        out |= ((b & 0x7F) as u64) << shift;
        if (b & 0x80) == 0 {
            return Some(out);
        }
        shift += 7;
    }
    None
}

fn extract_pb_bytes_field(buf: &[u8], target_field: u64) -> Option<&[u8]> {
    let mut pos = 0usize;
    while pos < buf.len() {
        let tag = read_pb_varint(buf, &mut pos)?;
        let field_num = tag >> 3;
        let wire_type = tag & 0x07;
        match wire_type {
            0 => {
                let _ = read_pb_varint(buf, &mut pos)?;
            }
            1 => {
                pos = pos.checked_add(8)?;
                if pos > buf.len() {
                    return None;
                }
            }
            2 => {
                let len = read_pb_varint(buf, &mut pos)? as usize;
                let end = pos.checked_add(len)?;
                if end > buf.len() {
                    return None;
                }
                let slice = &buf[pos..end];
                pos = end;
                if field_num == target_field {
                    return Some(slice);
                }
            }
            5 => {
                pos = pos.checked_add(4)?;
                if pos > buf.len() {
                    return None;
                }
            }
            _ => return None,
        }
    }
    None
}

fn extract_all_pb_bytes_fields<'a>(buf: &'a [u8], target_field: u64) -> Option<Vec<&'a [u8]>> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < buf.len() {
        let tag = read_pb_varint(buf, &mut pos)?;
        let field_num = tag >> 3;
        let wire_type = tag & 0x07;
        match wire_type {
            0 => {
                let _ = read_pb_varint(buf, &mut pos)?;
            }
            1 => {
                pos = pos.checked_add(8)?;
                if pos > buf.len() {
                    return None;
                }
            }
            2 => {
                let len = read_pb_varint(buf, &mut pos)? as usize;
                let end = pos.checked_add(len)?;
                if end > buf.len() {
                    return None;
                }
                let slice = &buf[pos..end];
                pos = end;
                if field_num == target_field {
                    out.push(slice);
                }
            }
            5 => {
                pos = pos.checked_add(4)?;
                if pos > buf.len() {
                    return None;
                }
            }
            _ => return None,
        }
    }
    Some(out)
}

/// Pure-Rust FIPS 180-4 SHA-1 (used exclusively for legacy CRX2 RSA-SHA1 signature verification).
fn sha1_digest(data: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x6745_2301;
    let mut h1: u32 = 0xEFCD_AB89;
    let mut h2: u32 = 0x98BA_DCFE;
    let mut h3: u32 = 0x1032_5476;
    let mut h4: u32 = 0xC3D2_E1F0;

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut padded = Vec::with_capacity(data.len() + 72);
    padded.extend_from_slice(data);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0x00);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.chunks_exact(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6u32),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut out = [0u8; 20];
    out[0..4].copy_from_slice(&h0.to_be_bytes());
    out[4..8].copy_from_slice(&h1.to_be_bytes());
    out[8..12].copy_from_slice(&h2.to_be_bytes());
    out[12..16].copy_from_slice(&h3.to_be_bytes());
    out[16..20].copy_from_slice(&h4.to_be_bytes());
    out
}

fn read_der_tlv(buf: &[u8], expected_tag: u8) -> Option<(&[u8], &[u8])> {
    if buf.len() < 2 || buf[0] != expected_tag {
        return None;
    }
    let first = buf[1];
    let (len, hdr_len) = if first < 0x80 {
        (first as usize, 2usize)
    } else {
        let count = (first & 0x7F) as usize;
        if count == 0 || count > 4 || buf.len() < 2 + count || buf[2] == 0 {
            return None;
        }
        let mut val = 0usize;
        for &b in &buf[2..2 + count] {
            val = (val << 8) | (b as usize);
        }
        if val < 0x80 {
            return None;
        }
        (val, 2 + count)
    };
    let end = hdr_len.checked_add(len)?;
    if end > buf.len() {
        return None;
    }
    Some((&buf[hdr_len..end], &buf[end..]))
}

fn parse_der_positive_uint(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    let (raw, rest) = read_der_tlv(buf, 0x02)?;
    if raw.is_empty() || (raw[0] & 0x80) != 0 {
        return None;
    }
    let stripped = if raw[0] == 0x00 {
        if raw.len() == 1 || (raw[1] & 0x80) == 0 {
            return None;
        }
        &raw[1..]
    } else {
        raw
    };
    Some((stripped, rest))
}

fn parse_rsa_spki_der(spki: &[u8], min_modulus_bytes: usize) -> Result<(Vec<u8>, Vec<u8>), String> {
    const RSA_ENCRYPTION_OID: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
    let (seq, rem) = read_der_tlv(spki, 0x30).ok_or("Invalid RSA SPKI SEQUENCE")?;
    if !rem.is_empty() {
        return Err("Trailing bytes after RSA SPKI".into());
    }
    let (alg_id, after_alg) = read_der_tlv(seq, 0x30).ok_or("Invalid AlgorithmIdentifier")?;
    let (oid, alg_params) = read_der_tlv(alg_id, 0x06).ok_or("Invalid algorithm OID")?;
    if oid != RSA_ENCRYPTION_OID {
        return Err("Unsupported public key algorithm (expected rsaEncryption)".into());
    }
    if !alg_params.is_empty() && alg_params != [0x05, 0x00] {
        return Err("Invalid RSA AlgorithmIdentifier parameters".into());
    }
    let (bit_str, after_bs) =
        read_der_tlv(after_alg, 0x03).ok_or("Invalid subjectPublicKey BIT STRING")?;
    if !after_bs.is_empty() || bit_str.len() < 2 || bit_str[0] != 0x00 {
        return Err("Malformed subjectPublicKey BIT STRING".into());
    }
    let (rsa_seq, rsa_rem) =
        read_der_tlv(&bit_str[1..], 0x30).ok_or("Invalid RSAPublicKey SEQUENCE")?;
    if !rsa_rem.is_empty() {
        return Err("Trailing bytes in RSAPublicKey".into());
    }
    let (n, after_n) = parse_der_positive_uint(rsa_seq).ok_or("Invalid RSA modulus")?;
    let (e, after_e) = parse_der_positive_uint(after_n).ok_or("Invalid RSA exponent")?;
    if !after_e.is_empty() {
        return Err("Trailing bytes after RSA exponent".into());
    }
    if n.len() < min_modulus_bytes || n.len() > 512 || (n[n.len() - 1] & 1) == 0 {
        return Err("Unsupported or weak RSA modulus".into());
    }
    if e.is_empty() || e.len() > 8 || (e[e.len() - 1] & 1) == 0 || (e.len() == 1 && e[0] < 3) {
        return Err("Unsupported or invalid RSA exponent".into());
    }
    Ok((n.to_vec(), e.to_vec()))
}

fn be_bytes_to_limbs(be: &[u8], limb_count: usize) -> Vec<u32> {
    let mut limbs = vec![0u32; limb_count];
    for (idx, &byte) in be.iter().rev().enumerate() {
        let limb_idx = idx / 4;
        if limb_idx < limb_count {
            limbs[limb_idx] |= (byte as u32) << ((idx % 4) * 8);
        }
    }
    limbs
}

fn limbs_to_be_bytes(limbs: &[u32], out_len: usize) -> Vec<u8> {
    let mut out = vec![0u8; out_len];
    for idx in 0..out_len {
        let limb_idx = idx / 4;
        let shift = (idx % 4) * 8;
        let b = if limb_idx < limbs.len() {
            ((limbs[limb_idx] >> shift) & 0xFF) as u8
        } else {
            0
        };
        out[out_len - 1 - idx] = b;
    }
    out
}

fn cmp_limbs(a: &[u32], b: &[u32]) -> std::cmp::Ordering {
    for i in (0..a.len().max(b.len())).rev() {
        let av = a.get(i).copied().unwrap_or(0);
        let bv = b.get(i).copied().unwrap_or(0);
        if av != bv {
            return av.cmp(&bv);
        }
    }
    std::cmp::Ordering::Equal
}

fn inv_mod_2_32(a: u32) -> u32 {
    let mut x = a;
    for _ in 0..5 {
        x = x.wrapping_mul(2u32.wrapping_sub(a.wrapping_mul(x)));
    }
    x
}

fn mont_mul(a: &[u32], b: &[u32], n: &[u32], n0_inv: u32) -> Vec<u32> {
    let m = n.len();
    let mut t = vec![0u32; m + 2];
    for &ai_u32 in a.iter().take(m) {
        let ai = ai_u32 as u64;
        let mut carry: u64 = 0;
        for j in 0..m {
            let prod = (t[j] as u64) + ai * (b[j] as u64) + carry;
            t[j] = prod as u32;
            carry = prod >> 32;
        }
        let sum = (t[m] as u64) + carry;
        t[m] = sum as u32;
        t[m + 1] = (sum >> 32) as u32;

        let u = t[0].wrapping_mul(n0_inv) as u64;
        let prod0 = (t[0] as u64) + u * (n[0] as u64);
        let mut carry2: u64 = prod0 >> 32;
        for j in 1..m {
            let prod = (t[j] as u64) + u * (n[j] as u64) + carry2;
            t[j - 1] = prod as u32;
            carry2 = prod >> 32;
        }
        let sum2 = (t[m] as u64) + carry2;
        t[m - 1] = sum2 as u32;
        t[m] = t[m + 1] + (sum2 >> 32) as u32;
        t[m + 1] = 0;
    }
    if t[m] != 0 || cmp_limbs(&t[..m], n) != std::cmp::Ordering::Less {
        let mut borrow: u64 = 0;
        for j in 0..m {
            let nj = (n[j] as u64) + borrow;
            let tj = t[j] as u64;
            if tj >= nj {
                t[j] = (tj - nj) as u32;
                borrow = 0;
            } else {
                t[j] = ((1u64 << 32) + tj - nj) as u32;
                borrow = 1;
            }
        }
    }
    t.truncate(m);
    t
}

fn compute_r2_mod_n(n: &[u32]) -> Vec<u32> {
    let m = n.len();
    let mut r = vec![0u32; m];
    r[0] = 1;
    for _ in 0..(2 * 32 * m) {
        let mut carry = 0u32;
        for limb in &mut r {
            let next_carry = *limb >> 31;
            *limb = (*limb << 1) | carry;
            carry = next_carry;
        }
        if carry != 0 || cmp_limbs(&r, n) != std::cmp::Ordering::Less {
            let mut borrow: u64 = 0;
            for j in 0..m {
                let nj = (n[j] as u64) + borrow;
                let rj = r[j] as u64;
                if rj >= nj {
                    r[j] = (rj - nj) as u32;
                    borrow = 0;
                } else {
                    r[j] = ((1u64 << 32) + rj - nj) as u32;
                    borrow = 1;
                }
            }
        }
    }
    r
}

fn rsa_mod_pow(base_be: &[u8], exp_be: &[u8], mod_be: &[u8]) -> Result<Vec<u8>, String> {
    let k = mod_be.len();
    let m = k.div_ceil(4);
    let n = be_bytes_to_limbs(mod_be, m);
    let b = be_bytes_to_limbs(base_be, m);
    if base_be.len() > k || cmp_limbs(&b, &n) != std::cmp::Ordering::Less {
        return Err("RSA signature representative out of range".into());
    }
    let n0_inv = inv_mod_2_32(n[0]).wrapping_neg();
    let r2 = compute_r2_mod_n(&n);
    let base_mont = mont_mul(&b, &r2, &n, n0_inv);
    let mut one = vec![0u32; m];
    one[0] = 1;
    let mut acc_mont = mont_mul(&one, &r2, &n, n0_inv);

    for &eb in exp_be {
        for bit in (0..8).rev() {
            acc_mont = mont_mul(&acc_mont, &acc_mont, &n, n0_inv);
            if ((eb >> bit) & 1) == 1 {
                acc_mont = mont_mul(&acc_mont, &base_mont, &n, n0_inv);
            }
        }
    }
    let res = mont_mul(&acc_mont, &one, &n, n0_inv);
    Ok(limbs_to_be_bytes(&res, k))
}

fn verify_rsa_pkcs1v15_digest(
    spki_der: &[u8],
    digest: &[u8],
    digest_info_prefix: &[u8],
    signature: &[u8],
    min_modulus_bytes: usize,
) -> Result<(), String> {
    let (n, e) = parse_rsa_spki_der(spki_der, min_modulus_bytes)?;
    let k = n.len();
    if signature.len() != k {
        return Err("Invalid RSA signature length".into());
    }
    let t_len = digest_info_prefix.len() + digest.len();
    if k < t_len + 11 {
        return Err("RSA modulus too small for PKCS#1 v1.5 padding".into());
    }
    let em = rsa_mod_pow(signature, &e, &n)?;
    let ps_len = k - t_len - 3;
    let mut expected = Vec::with_capacity(k);
    expected.push(0x00);
    expected.push(0x01);
    expected.resize(2 + ps_len, 0xFF);
    expected.push(0x00);
    expected.extend_from_slice(digest_info_prefix);
    expected.extend_from_slice(digest);

    if bool::from(em.as_slice().ct_eq(expected.as_slice())) {
        Ok(())
    } else {
        Err("RSA PKCS#1 v1.5 signature verification failed".into())
    }
}

fn verify_rsa_pkcs1v15_sha256(spki_der: &[u8], digest: &[u8; 32], sig: &[u8]) -> Result<(), String> {
    const SHA256_DIGEST_INFO_PREFIX: &[u8] = &[
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];
    verify_rsa_pkcs1v15_digest(spki_der, digest, SHA256_DIGEST_INFO_PREFIX, sig, 256)
}

fn verify_rsa_pkcs1v15_sha1(spki_der: &[u8], digest: &[u8; 20], sig: &[u8]) -> Result<(), String> {
    const SHA1_DIGEST_INFO_PREFIX: &[u8] = &[
        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
    ];
    verify_rsa_pkcs1v15_digest(spki_der, digest, SHA1_DIGEST_INFO_PREFIX, sig, 128)
}

fn encode_crx_id_bytes(id_16: &[u8; 16]) -> String {
    let mut id = String::with_capacity(32);
    for &b in id_16 {
        id.push((b'a' + (b >> 4)) as char);
        id.push((b'a' + (b & 0x0F)) as char);
    }
    id
}

fn chromium_id_bytes_from_spki(spki: &[u8]) -> [u8; 16] {
    let digest = Sha256::digest(spki);
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

/// Cryptographically verified CRX2/CRX3 metadata bound to its 32-char extension ID.
#[derive(Debug, Clone)]
pub struct VerifiedCrxPackage {
    pub derived_id: String,
    pub public_key_b64: String,
    pub zip_offset: usize,
}

/// Performs full cryptographic verification of a CRX2 (RSA PKCS#1 v1.5 SHA-1) or CRX3
/// (protobuf `CrxFileHeader` + `SignedData.crx_id` + `"CRX3 SignedData\0"` RSA PKCS#1 v1.5 SHA-256)
/// package, strictly binding the derived SHA-256 public-key ID to `expected_ext_id` (if given).
pub fn verify_crx_package(
    raw: &[u8],
    expected_ext_id: Option<&str>,
) -> Result<VerifiedCrxPackage, String> {
    if raw.len() < 16 || !raw.starts_with(b"Cr24") {
        return Err("Invalid CRX package header (expected Cr24 magic).".into());
    }
    if raw.len() > MAX_CRX_BYTES {
        return Err("Extension package is too large (> 32 MiB).".into());
    }
    let version = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]);
    match version {
        2 => {
            let pk_len = u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]) as usize;
            let sig_len = u32::from_le_bytes([raw[12], raw[13], raw[14], raw[15]]) as usize;
            if !(32..=4096).contains(&pk_len) || !(128..=512).contains(&sig_len) {
                return Err("CRX2 header has invalid key or signature length.".into());
            }
            let sig_start = 16usize
                .checked_add(pk_len)
                .ok_or_else(|| "CRX2 header length overflow.".to_string())?;
            let zip_offset = sig_start
                .checked_add(sig_len)
                .ok_or_else(|| "CRX2 header length overflow.".to_string())?;
            if zip_offset >= raw.len() || !raw[zip_offset..].starts_with(b"PK\x03\x04") {
                return Err("CRX2 package missing embedded ZIP archive.".into());
            }
            let pubkey_der = &raw[16..sig_start];
            let sig = &raw[sig_start..zip_offset];
            let zip_bytes = &raw[zip_offset..];

            let derived_id = encode_crx_id_bytes(&chromium_id_bytes_from_spki(pubkey_der));
            if let Some(exp) = expected_ext_id {
                if !derived_id.eq_ignore_ascii_case(exp.trim()) {
                    return Err(format!(
                        "CRX2 extension ID mismatch: key derives '{}' but '{}' was requested.",
                        derived_id, exp
                    ));
                }
            }

            let digest = sha1_digest(zip_bytes);
            verify_rsa_pkcs1v15_sha1(pubkey_der, &digest, sig)
                .map_err(|e| format!("CRX2 cryptographic signature check failed: {}", e))?;

            Ok(VerifiedCrxPackage {
                derived_id,
                public_key_b64: BASE64.encode(pubkey_der),
                zip_offset,
            })
        }
        3 => {
            let hdr_len = u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]) as usize;
            let zip_offset = 12usize
                .checked_add(hdr_len)
                .ok_or_else(|| "CRX3 header length overflow.".to_string())?;
            if hdr_len == 0 || zip_offset >= raw.len() || !raw[zip_offset..].starts_with(b"PK\x03\x04") {
                return Err("CRX3 package missing valid header or embedded ZIP archive.".into());
            }
            let header = &raw[12..zip_offset];
            let zip_bytes = &raw[zip_offset..];

            // CrxFileHeader.signed_header_data (field 10000) is mandatory in CRX3
            let signed_header_data = extract_pb_bytes_field(header, 10000)
                .ok_or_else(|| "CRX3 header missing signed_header_data.".to_string())?;
            let crx_id_slice = extract_pb_bytes_field(signed_header_data, 1)
                .ok_or_else(|| "CRX3 signed_header_data missing crx_id.".to_string())?;
            let crx_id_arr: [u8; 16] = crx_id_slice
                .try_into()
                .map_err(|_| "CRX3 crx_id must be exactly 16 bytes.".to_string())?;
            let header_ext_id = encode_crx_id_bytes(&crx_id_arr);

            if let Some(exp) = expected_ext_id {
                if !header_ext_id.eq_ignore_ascii_case(exp.trim()) {
                    return Err(format!(
                        "CRX3 extension ID mismatch: signed_header_data binds '{}' but '{}' was requested.",
                        header_ext_id, exp
                    ));
                }
            }

            // Build exact CRX3 signed payload digest:
            // SHA-256("CRX3 SignedData\0" || le32(signed_header_data.len()) || signed_header_data || zip)
            let mut hasher = Sha256::new();
            hasher.update(b"CRX3 SignedData\x00");
            hasher.update((signed_header_data.len() as u32).to_le_bytes());
            hasher.update(signed_header_data);
            hasher.update(zip_bytes);
            let digest: [u8; 32] = hasher.finalize().into();

            let rsa_proofs = extract_all_pb_bytes_fields(header, 2)
                .ok_or_else(|| "Malformed CRX3 protobuf header.".to_string())?;
            let mut matched_pk_b64: Option<String> = None;
            for proof in rsa_proofs {
                let Some(pk) = extract_pb_bytes_field(proof, 1) else {
                    continue;
                };
                let Some(sig) = extract_pb_bytes_field(proof, 2) else {
                    continue;
                };
                if pk.len() < 32 || pk.len() > 4096 {
                    continue;
                }
                let pk_id = chromium_id_bytes_from_spki(pk);
                if bool::from(pk_id.ct_eq(&crx_id_arr)) {
                    verify_rsa_pkcs1v15_sha256(pk, &digest, sig)
                        .map_err(|e| format!("CRX3 cryptographic signature check failed: {}", e))?;
                    matched_pk_b64 = Some(BASE64.encode(pk));
                }
            }

            let Some(public_key_b64) = matched_pk_b64 else {
                return Err(
                    "CRX3 header contains no valid RSA-SHA256 proof matching the declared crx_id."
                        .into(),
                );
            };

            Ok(VerifiedCrxPackage {
                derived_id: header_ext_id,
                public_key_b64,
                zip_offset,
            })
        }
        other => Err(format!("Unsupported CRX version ({}).", other)),
    }
}

/// Extracts the base64-encoded SubjectPublicKeyInfo (`"key"`) from a CRX2 or CRX3 package header
/// so unpacked installation preserves the exact deterministic 32-character Chrome Web Store ID.
pub fn extract_crx_public_key_b64(raw: &[u8]) -> Option<String> {
    if raw.len() < 16 || !raw.starts_with(b"Cr24") {
        return None;
    }
    let version = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]);
    match version {
        3 => {
            let hdr_len = u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]) as usize;
            let end = 12usize.checked_add(hdr_len)?;
            if end > raw.len() {
                return None;
            }
            let header = &raw[12..end];
            let target_crx_id: Option<[u8; 16]> = extract_pb_bytes_field(header, 10000)
                .and_then(|shd| extract_pb_bytes_field(shd, 1))
                .and_then(|s| s.try_into().ok());

            // Prefer the proof whose SHA-256 prefix matches `signed_header_data.crx_id`
            let mut first_pk: Option<String> = None;
            for proof_field in [2u64, 3u64] {
                let Some(proofs) = extract_all_pb_bytes_fields(header, proof_field) else {
                    continue;
                };
                for proof in proofs {
                    if let Some(pk) = extract_pb_bytes_field(proof, 1) {
                        if pk.len() >= 32 && pk.len() <= 4096 {
                            if let Some(ref wanted) = target_crx_id {
                                if chromium_id_bytes_from_spki(pk) == *wanted {
                                    return Some(BASE64.encode(pk));
                                }
                            }
                            if first_pk.is_none() {
                                first_pk = Some(BASE64.encode(pk));
                            }
                        }
                    }
                }
            }
            first_pk
        }
        2 => {
            let pk_len = u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]) as usize;
            let end = 16usize.checked_add(pk_len)?;
            if pk_len >= 32 && pk_len <= 4096 && end <= raw.len() {
                return Some(BASE64.encode(&raw[16..end]));
            }
            None
        }
        _ => None,
    }
}

/// Computes Chromium's exact 32-char extension ID (`a`..=`p`) from a base64 `"key"` string.
pub fn chromium_id_from_public_key_b64(key_b64: &str) -> Option<String> {
    let clean: String = key_b64.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = BASE64.decode(clean.as_bytes()).ok()?;
    Some(encode_crx_id_bytes(&chromium_id_bytes_from_spki(&bytes)))
}

pub fn find_runtime_extension_id(
    roaming_root: &Path,
    ext_dir: &Path,
    dir_id: &str,
    ext_name: &str,
) -> Option<String> {
    let profile_dirs = [
        roaming_root.join("cef-profile").join("Default"),
        roaming_root.join("cef-profile"),
        roaming_root
            .join("browser-engine")
            .join("EBWebView")
            .join("Default"),
    ];
    let norm_target = ext_dir
        .to_string_lossy()
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_ascii_lowercase();
    let suffix_match = format!("\\extensions\\{}", dir_id.to_ascii_lowercase());
    let mut name_fallback: Option<String> = None;

    for profile_dir in &profile_dirs {
        for fname in ["Preferences", "Secure Preferences"] {
            let p = profile_dir.join(fname);
            let Ok(raw) = std::fs::read_to_string(&p) else {
                continue;
            };
            let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw) else {
                continue;
            };
            let Some(settings) = val
                .get("extensions")
                .and_then(|e| e.get("settings"))
                .and_then(|s| s.as_object())
            else {
                continue;
            };
            for (rt_id, entry) in settings {
                if !is_chrome_store_id(rt_id) {
                    continue;
                }
                if let Some(epath) = entry.get("path").and_then(|v| v.as_str()) {
                    let norm = epath
                        .replace('/', "\\")
                        .trim_end_matches('\\')
                        .to_ascii_lowercase();
                    if norm == norm_target || norm.ends_with(&suffix_match) {
                        return Some(rt_id.to_ascii_lowercase());
                    }
                }
                if name_fallback.is_none() && !ext_name.is_empty() {
                    if let Some(mname) = entry
                        .get("manifest")
                        .and_then(|m| m.get("name"))
                        .and_then(|v| v.as_str())
                    {
                        if mname.eq_ignore_ascii_case(ext_name) {
                            name_fallback = Some(rt_id.to_ascii_lowercase());
                        }
                    }
                }
            }
        }
    }
    name_fallback
}

/// Resolves the live `chrome-extension://<runtime_id>/<popup_or_options_html>` URL and display name
/// for an enabled Chrome extension so Singularity can render its native popup/options window.
pub fn resolve_extension_runtime_url(
    roaming_root: &Path,
    dir_id: &str,
    open_options: bool,
) -> Option<(String, String)> {
    if !is_valid_extension_dir_id(dir_id) {
        return None;
    }
    let ext_dir = enabled_extensions_dir(roaming_root).join(dir_id);
    if !ext_dir.is_dir() {
        return None;
    }
    let manifest_raw = std::fs::read_to_string(ext_dir.join("manifest.json")).ok()?;
    let manifest: serde_json::Value =
        serde_json::from_str(manifest_raw.trim_start_matches('\u{feff}')).ok()?;

    let info = parse_extension_dir(roaming_root, &ext_dir, dir_id, true, &[])?;
    let rel_raw = if open_options {
        info.options_path.as_deref().or(info.popup_path.as_deref())
    } else {
        info.popup_path.as_deref().or(info.options_path.as_deref())
    }?;
    let rel_clean = rel_raw.trim().trim_start_matches('/');
    if rel_clean.is_empty()
        || rel_clean.contains("..")
        || rel_clean.contains('\\')
        || rel_clean.bytes().any(|b| b <= 0x20 || b == 0x7F)
    {
        return None;
    }
    // Strip optional query/fragment when verifying the file exists on disk
    let rel_file = rel_clean
        .split(&['?', '#'][..])
        .next()
        .unwrap_or(rel_clean);
    resolve_safe_child_path(&ext_dir, rel_file)?;

    let runtime_id = read_extension_meta(roaming_root, dir_id)
        .runtime_id
        .filter(|id| is_chrome_store_id(id))
        .or_else(|| find_runtime_extension_id(roaming_root, &ext_dir, dir_id, &info.name))
        .or_else(|| {
            manifest
                .get("key")
                .and_then(|v| v.as_str())
                .and_then(chromium_id_from_public_key_b64)
        })
        .or_else(|| {
            if is_chrome_store_id(dir_id) {
                Some(dir_id.to_ascii_lowercase())
            } else {
                None
            }
        })?;

    Some((
        format!("chrome-extension://{}/{}", runtime_id, rel_clean),
        info.name,
    ))
}

fn random_hex_nonce() -> String {
    let mut b = [0u8; 8];
    OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

/// Downloads, cryptographically verifies (CRX2/CRX3 signature + strict ID <-> public key binding),
/// and installs a Chrome extension directly from the Chrome Web Store by ID or URL.
pub fn install_from_chrome_web_store(
    roaming_root: &Path,
    input: &str,
    pinned_ids: &[String],
) -> Result<ChromeExtensionInfo, String> {
    let ext_id = parse_chrome_web_store_id(input).ok_or_else(|| {
        "Invalid Chrome Web Store ID or URL (32 characters a-p expected).".to_string()
    })?;

    let crx_url = format!(
        "https://clients2.google.com/service/update2/crx?response=redirect&prodversion=131.0.0.0&acceptformat=crx2,crx3&x=id%3D{}%26uc",
        ext_id
    );

    let staging_root = roaming_root.join(".ext-staging");
    let _ = std::fs::create_dir_all(&staging_root);
    let tmp_crx = staging_root.join(format!("dl-{}-{}.crx", ext_id, random_hex_nonce()));
    let _ = std::fs::remove_file(&tmp_crx);

    #[cfg(target_os = "windows")]
    {
        let dl = crate::winhttp_client::winhttp_download_https_to_file(
            &crx_url,
            &tmp_crx,
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            &[],
            10_000,
            25_000,
            MAX_CRX_BYTES,
        );
        if dl.is_err() || !tmp_crx.is_file() {
            let _ = std::fs::remove_file(&tmp_crx);
            return Err("Failed downloading package from the Chrome Web Store.".into());
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        let status = Command::new("curl")
            .args([
                "-fsSL",
                "--proto",
                "=https",
                "--proto-redir",
                "=https",
                "--max-time",
                "25",
                "-A",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                &crx_url,
                "-o",
                &tmp_crx.to_string_lossy(),
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|e| format!("Failed downloading extension: {}", e))?;
        if !status.success() || !tmp_crx.is_file() {
            let _ = std::fs::remove_file(&tmp_crx);
            return Err("Failed downloading package from the Chrome Web Store.".into());
        }
    }

    let raw_bytes = std::fs::read(&tmp_crx)
        .map_err(|e| format!("Failed reading downloaded CRX package: {}", e))?;
    let _ = std::fs::remove_file(&tmp_crx);

    if !raw_bytes.starts_with(b"Cr24") {
        return Err("Chrome Web Store download is not a signed CRX2/CRX3 package.".into());
    }
    // Verify signature + ID binding BEFORE any extraction or disk writes.
    verify_crx_package(&raw_bytes, Some(&ext_id))?;

    install_bytes_under_id(roaming_root, &ext_id, &raw_bytes, pinned_ids)
}

fn install_bytes_under_id(
    roaming_root: &Path,
    ext_id: &str,
    raw_bytes: &[u8],
    pinned_ids: &[String],
) -> Result<ChromeExtensionInfo, String> {
    if !is_valid_extension_dir_id(ext_id) {
        return Err("Invalid extension identifier.".into());
    }

    // Cryptographically verify ALL CRX2/CRX3 packages and strictly bind ID <-> public key
    // BEFORE extraction or writing `"key"` into manifest.json.
    let verified_key_b64 = if raw_bytes.starts_with(b"Cr24") {
        let expected = if is_chrome_store_id(ext_id) {
            Some(ext_id)
        } else {
            None
        };
        let verified = verify_crx_package(raw_bytes, expected)?;
        Some(verified.public_key_b64)
    } else {
        None
    };

    let enabled_root = enabled_extensions_dir(roaming_root);
    let disabled_root = disabled_extensions_dir(roaming_root);
    std::fs::create_dir_all(&enabled_root)
        .map_err(|e| format!("Failed creating extensions directory: {}", e))?;

    let staging_root = roaming_root.join(".ext-staging");
    let _ = std::fs::create_dir_all(&staging_root);
    let stage_dir = staging_root.join(format!("stage-{}-{}", ext_id, random_hex_nonce()));
    let _ = std::fs::remove_dir_all(&stage_dir);

    if let Err(err) = extract_crx_or_zip_to_dir(raw_bytes, &stage_dir) {
        let _ = std::fs::remove_dir_all(&stage_dir);
        return Err(err);
    }

    // Preserve cryptographically verified CRX public key inside manifest.json so Chromium assigns
    // the exact bound 32-character Chrome Store ID.
    if let Some(key_b64) = verified_key_b64 {
        let mpath = stage_dir.join("manifest.json");
        if let Ok(raw_m) = std::fs::read_to_string(&mpath) {
            if let Ok(mut mval) =
                serde_json::from_str::<serde_json::Value>(raw_m.trim_start_matches('\u{feff}'))
            {
                if let Some(obj) = mval.as_object_mut() {
                    if !obj.contains_key("key") {
                        obj.insert("key".to_string(), serde_json::Value::String(key_b64));
                        if let Ok(updated) = serde_json::to_string_pretty(&mval) {
                            let _ = std::fs::write(&mpath, updated);
                        }
                    }
                }
            }
        }
    }

    let final_dir = enabled_root.join(ext_id);
    let _ = std::fs::remove_dir_all(&final_dir);
    let _ = std::fs::remove_dir_all(disabled_root.join(ext_id));

    if std::fs::rename(&stage_dir, &final_dir).is_err() {
        copy_dir_recursive(&stage_dir, &final_dir, &mut 0)?;
        let _ = std::fs::remove_dir_all(&stage_dir);
    }

    parse_extension_dir(roaming_root, &final_dir, ext_id, true, pinned_ids)
        .ok_or_else(|| "Extension installed, but manifest.json could not be parsed.".to_string())
}

fn copy_dir_recursive(src: &Path, dst: &Path, total_bytes: &mut u64) -> Result<(), String> {
    std::fs::create_dir_all(dst)
        .map_err(|e| format!("Failed creating directory {}: {}", dst.display(), e))?;
    let entries = std::fs::read_dir(src)
        .map_err(|e| format!("Failed reading directory {}: {}", src.display(), e))?;
    for entry in entries.flatten() {
        let fname = entry.file_name();
        if let Some(name_str) = fname.to_str() {
            if name_str.eq_ignore_ascii_case(".git")
                || name_str.eq_ignore_ascii_case("__MACOSX")
            {
                continue;
            }
        }
        let path = entry.path();
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        let target = dst.join(&fname);
        if meta.is_dir() {
            copy_dir_recursive(&path, &target, total_bytes)?;
        } else if meta.is_file() {
            *total_bytes = total_bytes.saturating_add(meta.len());
            if *total_bytes > MAX_EXTRACTED_BYTES {
                return Err("Local extension exceeds 64 MiB limit.".into());
            }
            std::fs::copy(&path, &target)
                .map_err(|e| format!("Failed copying {}: {}", path.display(), e))?;
        }
    }
    Ok(())
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn normalize_local_extension_input(raw: &str) -> String {
    let mut s = raw
        .trim()
        .trim_matches(|c| c == '"' || c == '\'')
        .trim()
        .to_string();
    if let Some(rest) = s
        .strip_prefix("file:///")
        .or_else(|| s.strip_prefix("FILE:///"))
    {
        // Decode %XX escapes strictly on raw bytes (never slice &str mid-UTF-8 char!)
        let mut decoded = Vec::with_capacity(rest.len());
        let bytes = rest.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' && i + 2 < bytes.len() {
                if let (Some(hi), Some(lo)) = (hex_nibble(bytes[i + 1]), hex_nibble(bytes[i + 2])) {
                    decoded.push((hi << 4) | lo);
                    i += 3;
                    continue;
                }
            }
            decoded.push(bytes[i]);
            i += 1;
        }
        let mut out = String::from_utf8_lossy(&decoded).into_owned();
        if cfg!(target_os = "windows") {
            out = out.replace('/', "\\");
        } else if !out.starts_with('/') {
            out.insert(0, '/');
        }
        s = out;
    }
    s
}

fn is_shared_user_or_root_dir(dir: &Path) -> bool {
    if dir.parent().is_none() {
        return true;
    }
    for env_key in ["USERPROFILE", "HOME", "TEMP", "TMP"] {
        if let Some(val) = std::env::var_os(env_key) {
            if PathBuf::from(val) == dir {
                return true;
            }
        }
    }
    if let Some(name) = dir.file_name().and_then(|n| n.to_str()) {
        let lower = name.to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "downloads"
                | "téléchargements"
                | "telechargements"
                | "desktop"
                | "bureau"
                | "documents"
                | "temp"
                | "tmp"
        ) {
            return true;
        }
    }
    false
}

fn collect_manifest_referenced_rel_paths(manifest: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();
    let mut push_clean = |raw: &str| {
        let mut clean = raw
            .trim()
            .split(&['?', '#'][..])
            .next()
            .unwrap_or("")
            .trim()
            .replace('\\', "/");
        while let Some(stripped) = clean.strip_prefix("./").or_else(|| clean.strip_prefix('/')) {
            clean = stripped.to_string();
        }
        if !clean.is_empty()
            && !clean.contains("://")
            && !clean.contains('*')
            && is_safe_relative_extension_path(Path::new(&clean))
        {
            out.push(clean);
        }
    };

    if let Some(icons) = manifest.get("icons").and_then(|v| v.as_object()) {
        for v in icons.values() {
            if let Some(s) = v.as_str() {
                push_clean(s);
            }
        }
    }
    for key in ["action", "browser_action", "page_action"] {
        if let Some(act) = manifest.get(key) {
            if let Some(p) = act.get("default_popup").and_then(|v| v.as_str()) {
                push_clean(p);
            }
            if let Some(ic) = act.get("default_icon") {
                if let Some(s) = ic.as_str() {
                    push_clean(s);
                } else if let Some(obj) = ic.as_object() {
                    for v in obj.values() {
                        if let Some(s) = v.as_str() {
                            push_clean(s);
                        }
                    }
                }
            }
        }
    }
    if let Some(p) = manifest.get("options_page").and_then(|v| v.as_str()) {
        push_clean(p);
    }
    if let Some(p) = manifest
        .get("options_ui")
        .and_then(|o| o.get("page"))
        .and_then(|v| v.as_str())
    {
        push_clean(p);
    }
    if let Some(p) = manifest
        .get("side_panel")
        .and_then(|sp| sp.get("default_path"))
        .and_then(|v| v.as_str())
    {
        push_clean(p);
    }
    if let Some(p) = manifest.get("devtools_page").and_then(|v| v.as_str()) {
        push_clean(p);
    }
    if let Some(overrides) = manifest
        .get("chrome_url_overrides")
        .and_then(|v| v.as_object())
    {
        for v in overrides.values() {
            if let Some(s) = v.as_str() {
                push_clean(s);
            }
        }
    }
    if let Some(bg) = manifest.get("background") {
        if let Some(sw) = bg.get("service_worker").and_then(|v| v.as_str()) {
            push_clean(sw);
        }
        if let Some(page) = bg.get("page").and_then(|v| v.as_str()) {
            push_clean(page);
        }
        if let Some(scripts) = bg.get("scripts").and_then(|v| v.as_array()) {
            for item in scripts {
                if let Some(s) = item.as_str() {
                    push_clean(s);
                }
            }
        }
    }
    if let Some(cs_arr) = manifest.get("content_scripts").and_then(|v| v.as_array()) {
        for cs in cs_arr {
            for field in ["js", "css"] {
                if let Some(arr) = cs.get(field).and_then(|v| v.as_array()) {
                    for item in arr {
                        if let Some(s) = item.as_str() {
                            push_clean(s);
                        }
                    }
                }
            }
        }
    }
    if let Some(dnr_rules) = manifest
        .get("declarative_net_request")
        .and_then(|v| v.get("rule_resources"))
        .and_then(|v| v.as_array())
    {
        for r in dnr_rules {
            if let Some(p) = r.get("path").and_then(|v| v.as_str()) {
                push_clean(p);
            }
        }
    }
    if let Some(war_arr) = manifest
        .get("web_accessible_resources")
        .and_then(|v| v.as_array())
    {
        for item in war_arr {
            if let Some(s) = item.as_str() {
                push_clean(s);
            } else if let Some(res) = item.get("resources").and_then(|v| v.as_array()) {
                for r in res {
                    if let Some(s) = r.as_str() {
                        push_clean(s);
                    }
                }
            }
        }
    }
    out
}

fn copy_manifest_and_referenced_files(
    src_dir: &Path,
    src_manifest_file: &Path,
    manifest: &serde_json::Value,
    dst_dir: &Path,
) -> Result<(), String> {
    std::fs::create_dir_all(dst_dir)
        .map_err(|e| format!("Failed creating directory {}: {}", dst_dir.display(), e))?;
    std::fs::copy(src_manifest_file, dst_dir.join("manifest.json"))
        .map_err(|e| format!("Failed copying manifest.json: {}", e))?;

    let mut total_bytes = std::fs::metadata(src_manifest_file)
        .map(|m| m.len())
        .unwrap_or(0);
    // Use `symlink_metadata()` instead of `.is_dir()` so symlinked `_locales` cannot exfiltrate files
    let locales_src = src_dir.join("_locales");
    if let Ok(meta) = std::fs::symlink_metadata(&locales_src) {
        if !meta.file_type().is_symlink() && meta.is_dir() {
            copy_dir_recursive(&locales_src, &dst_dir.join("_locales"), &mut total_bytes)?;
        }
    }
    for rel in collect_manifest_referenced_rel_paths(manifest) {
        let rel_path = Path::new(&rel);
        // Reject Windows drive prefixes (`Component::Prefix`, `:`), RootDir, and ParentDir before join
        if !is_safe_relative_extension_path(rel_path) {
            continue;
        }
        let raw_src_candidate = src_dir.join(rel_path);
        let Ok(raw_meta) = std::fs::symlink_metadata(&raw_src_candidate) else {
            continue;
        };
        if raw_meta.file_type().is_symlink() || !raw_meta.is_file() {
            continue;
        }
        if let Some(src_file) = resolve_safe_child_path(src_dir, &rel) {
            if src_file.is_file() {
                let Ok(meta) = std::fs::symlink_metadata(&src_file) else {
                    continue;
                };
                if meta.file_type().is_symlink() {
                    continue;
                }
                total_bytes = total_bytes.saturating_add(meta.len());
                if total_bytes > MAX_EXTRACTED_BYTES {
                    return Err("Local extension exceeds 64 MiB limit.".into());
                }
                let target = dst_dir.join(rel_path);
                if let Some(parent) = target.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let _ = std::fs::copy(&src_file, &target);
            }
        }
    }
    Ok(())
}

/// Installs an extension from a direct `manifest.json` (or `.json` manifest) file, a local
/// unpacked folder (containing `manifest.json`), or a `.crx`/`.zip` archive.
pub fn install_from_local_path(
    roaming_root: &Path,
    source_path: &str,
    explicit_id: Option<&str>,
    pinned_ids: &[String],
) -> Result<ChromeExtensionInfo, String> {
    let trimmed = normalize_local_extension_input(source_path);
    if trimmed.is_empty() {
        return Err("Local extension path is empty.".into());
    }
    let src = PathBuf::from(&trimmed);
    if !src.exists() {
        return Err(format!("Path not found: {}", src.display()));
    }

    let mut from_manifest_file = false;
    let mut explicit_manifest_file: Option<PathBuf> = None;
    let folder_src = if src.is_file() {
        let is_json_file = src
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("json"))
            .unwrap_or(false);
        if is_json_file {
            from_manifest_file = true;
            explicit_manifest_file = Some(src.clone());
            src.parent()
                .map(Path::to_path_buf)
                .ok_or_else(|| "Invalid manifest.json path (no parent folder).".to_string())?
        } else {
            let raw = std::fs::read(&src).map_err(|e| format!("Failed reading file: {}", e))?;
            let id = if raw.starts_with(b"Cr24") {
                let expected = explicit_id.filter(|s| is_chrome_store_id(s));
                let verified = verify_crx_package(&raw, expected)?;
                match explicit_id {
                    Some(eid) => derive_safe_id(eid),
                    None => verified.derived_id,
                }
            } else {
                let stem = src
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("local_ext");
                derive_safe_id(explicit_id.unwrap_or(stem))
            };
            save_extension_source_path(roaming_root, &id, &trimmed);
            return install_bytes_under_id(roaming_root, &id, &raw, pinned_ids);
        }
    } else {
        src.clone()
    };

    // Folder install: accept direct manifest.json file, folder containing manifest.json, or Chrome's <ext_id>/<version>/ layout
    let (manifest_dir, manifest_file) = if let Some(ref mf) = explicit_manifest_file {
        (folder_src.clone(), mf.clone())
    } else if folder_src.join("manifest.json").is_file() {
        (folder_src.clone(), folder_src.join("manifest.json"))
    } else {
        let sub = pick_latest_version_subdir(&folder_src).ok_or_else(|| {
            "manifest.json not found inside this Chrome extension directory.".to_string()
        })?;
        let mf = sub.join("manifest.json");
        (sub, mf)
    };

    let manifest_raw = std::fs::read_to_string(&manifest_file)
        .map_err(|e| format!("Failed reading manifest.json: {}", e))?;
    let manifest: serde_json::Value =
        serde_json::from_str(manifest_raw.trim_start_matches('\u{feff}'))
            .map_err(|e| format!("Invalid manifest.json JSON syntax: {}", e))?;
    if !manifest.is_object() {
        return Err("Invalid manifest.json: root value must be a JSON object.".into());
    }
    let is_standard_manifest_name = manifest_file
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.eq_ignore_ascii_case("manifest.json"))
        .unwrap_or(false);
    if !is_standard_manifest_name && manifest.get("manifest_version").is_none() {
        return Err(
            "Selected JSON file is not a Chrome extension manifest (missing \"manifest_version\")."
                .into(),
        );
    }

    let preferred_lang = read_configured_ui_language(roaming_root);
    let default_locale = manifest.get("default_locale").and_then(|v| v.as_str());
    let manifest_key_id = manifest
        .get("key")
        .and_then(|v| v.as_str())
        .and_then(chromium_id_from_public_key_b64);
    let manifest_name = manifest
        .get("name")
        .and_then(|v| v.as_str())
        .map(|raw| {
            resolve_i18n_string(
                &manifest_dir,
                raw,
                preferred_lang.as_deref(),
                default_locale,
            )
        })
        .filter(|s| !s.trim().is_empty() && !s.starts_with("__MSG_"));

    let shared_parent = from_manifest_file && is_shared_user_or_root_dir(&manifest_dir);
    let inferred_id = explicit_id
        .map(|s| s.to_string())
        .or(manifest_key_id)
        .or_else(|| {
            // If path looks like .../Extensions/<32-char-id>/<version>, grab the parent ID
            if let Some(parent_name) = manifest_dir
                .parent()
                .and_then(|p| p.file_name())
                .and_then(|n| n.to_str())
            {
                if is_chrome_store_id(parent_name) {
                    return Some(parent_name.to_ascii_lowercase());
                }
            }
            if !shared_parent {
                if let Some(dir_name) = manifest_dir.file_name().and_then(|n| n.to_str()) {
                    let lower = dir_name.to_ascii_lowercase();
                    if !matches!(lower.as_str(), "dist" | "build" | "out" | "src" | "extension") {
                        return Some(dir_name.to_string());
                    }
                }
            }
            manifest_name.clone()
        })
        .or(manifest_name)
        .unwrap_or_else(|| "local_ext".to_string());

    let id = derive_safe_id(&inferred_id);
    let enabled_root = enabled_extensions_dir(roaming_root);
    let disabled_root = disabled_extensions_dir(roaming_root);
    std::fs::create_dir_all(&enabled_root)
        .map_err(|e| format!("Failed creating extensions directory: {}", e))?;

    let final_dir = enabled_root.join(&id);
    let same_target = final_dir.exists()
        && std::fs::canonicalize(&manifest_dir).ok() == std::fs::canonicalize(&final_dir).ok();
    if !same_target {
        let _ = std::fs::remove_dir_all(&final_dir);
        let _ = std::fs::remove_dir_all(disabled_root.join(&id));

        if shared_parent {
            if let Err(err) = copy_manifest_and_referenced_files(
                &manifest_dir,
                &manifest_file,
                &manifest,
                &final_dir,
            ) {
                let _ = std::fs::remove_dir_all(&final_dir);
                return Err(err);
            }
        } else {
            let mut copied = 0u64;
            if let Err(err) = copy_dir_recursive(&manifest_dir, &final_dir, &mut copied) {
                let _ = std::fs::remove_dir_all(&final_dir);
                if from_manifest_file {
                    // Fallback if user selected manifest.json inside a huge folder > 64 MiB
                    if let Err(err2) = copy_manifest_and_referenced_files(
                        &manifest_dir,
                        &manifest_file,
                        &manifest,
                        &final_dir,
                    ) {
                        let _ = std::fs::remove_dir_all(&final_dir);
                        return Err(err2);
                    }
                } else {
                    return Err(err);
                }
            } else if !final_dir.join("manifest.json").is_file() {
                std::fs::copy(&manifest_file, final_dir.join("manifest.json"))
                    .map_err(|e| format!("Failed writing manifest.json: {}", e))?;
            }
        }
        save_extension_source_path(roaming_root, &id, &trimmed);
    }

    parse_extension_dir(roaming_root, &final_dir, &id, true, pinned_ids)
        .ok_or_else(|| "Extension copied, but manifest.json is invalid.".to_string())
}

/// Refreshes an installed extension from its recorded local source (`manifest.json`, folder, or
/// `.crx`/`.zip`) when available, or re-validates its installed directory on disk otherwise.
pub fn refresh_installed_extension(
    roaming_root: &Path,
    id: &str,
    pinned_ids: &[String],
) -> Result<ChromeExtensionInfo, String> {
    if !is_valid_extension_dir_id(id) {
        return Err("Invalid extension identifier.".into());
    }
    let (ext_dir, was_enabled) = locate_extension_dir(roaming_root, id)
        .ok_or_else(|| "Extension not found.".to_string())?;
    let meta = read_extension_meta(roaming_root, id);

    let updated = if let Some(ref src) = meta.source_path {
        if Path::new(src).exists() {
            let mut info = install_from_local_path(roaming_root, src, Some(id), pinned_ids)?;
            if !was_enabled {
                set_extension_enabled(roaming_root, id, false)?;
                let disabled_path = disabled_extensions_dir(roaming_root).join(id);
                info = parse_extension_dir(roaming_root, &disabled_path, id, false, pinned_ids)
                    .ok_or_else(|| "Extension refreshed, but manifest.json is invalid.".to_string())?;
            }
            info
        } else {
            parse_extension_dir(roaming_root, &ext_dir, id, was_enabled, pinned_ids)
                .ok_or_else(|| "Extension manifest.json could not be parsed.".to_string())?
        }
    } else {
        parse_extension_dir(roaming_root, &ext_dir, id, was_enabled, pinned_ids)
            .ok_or_else(|| "Extension manifest.json could not be parsed.".to_string())?
    };

    invalidate_extensions_cache();
    Ok(updated)
}

fn derive_safe_id(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .take(48)
        .collect();
    let trimmed = cleaned.trim_matches('_');
    if trimmed.is_empty() {
        format!("ext_{}", std::process::id())
    } else {
        trimmed.to_string()
    }
}

/// Compares Chrome extension version directory names numerically (e.g. `1.10.0_0 > 1.9.0_0`).
fn compare_extension_version_names(a: &str, b: &str) -> std::cmp::Ordering {
    fn parse_parts(s: &str) -> Vec<Result<u64, &str>> {
        s.split(['.', '_', '-'])
            .filter(|seg| !seg.is_empty())
            .map(|seg| seg.parse::<u64>().map_err(|_| seg))
            .collect()
    }
    let pa = parse_parts(a);
    let pb = parse_parts(b);
    let max_len = pa.len().max(pb.len());
    for i in 0..max_len {
        let ord = match (pa.get(i), pb.get(i)) {
            (Some(Ok(va)), Some(Ok(vb))) => va.cmp(vb),
            (Some(Ok(va)), None) => va.cmp(&0),
            (None, Some(Ok(vb))) => 0u64.cmp(vb),
            (Some(Err(sa)), Some(Err(sb))) => sa.cmp(sb),
            (Some(Ok(_)), Some(Err(_))) => std::cmp::Ordering::Greater,
            (Some(Err(_)), Some(Ok(_))) => std::cmp::Ordering::Less,
            (Some(Err(_)), None) => std::cmp::Ordering::Greater,
            (None, Some(Err(_))) => std::cmp::Ordering::Less,
            (None, None) => std::cmp::Ordering::Equal,
        };
        if ord != std::cmp::Ordering::Equal {
            return ord;
        }
    }
    a.cmp(b)
}

fn pick_latest_version_subdir(ext_root: &Path) -> Option<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(ext_root)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            std::fs::symlink_metadata(p)
                .map(|m| !m.file_type().is_symlink() && m.is_dir())
                .unwrap_or(false)
                && p.join("manifest.json").is_file()
        })
        .collect();
    dirs.sort_by(|a, b| {
        let an = a.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let bn = b.file_name().and_then(|n| n.to_str()).unwrap_or("");
        compare_extension_version_names(an, bn)
    });
    dirs.pop()
}

pub fn set_extension_enabled(roaming_root: &Path, id: &str, enabled: bool) -> Result<(), String> {
    if !is_valid_extension_dir_id(id) {
        return Err("Invalid extension identifier.".into());
    }
    let enabled_dir = enabled_extensions_dir(roaming_root);
    let disabled_dir = disabled_extensions_dir(roaming_root);
    std::fs::create_dir_all(&enabled_dir).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&disabled_dir).map_err(|e| e.to_string())?;

    let (src, dst) = if enabled {
        (disabled_dir.join(id), enabled_dir.join(id))
    } else {
        (enabled_dir.join(id), disabled_dir.join(id))
    };

    if dst.is_dir() && !src.is_dir() {
        return Ok(());
    }
    if !src.is_dir() {
        return Err("Extension not found.".into());
    }
    let _ = std::fs::remove_dir_all(&dst);
    std::fs::rename(&src, &dst)
        .map_err(|e| format!("Failed updating extension state: {}", e))?;
    Ok(())
}

pub fn remove_extension(roaming_root: &Path, id: &str) -> Result<(), String> {
    if !is_valid_extension_dir_id(id) {
        return Err("Invalid extension identifier.".into());
    }
    let _ = std::fs::remove_dir_all(enabled_extensions_dir(roaming_root).join(id));
    let _ = std::fs::remove_dir_all(disabled_extensions_dir(roaming_root).join(id));
    remove_extension_meta(roaming_root, id);
    Ok(())
}

/// Scans locally installed Chrome, Brave, and Edge profiles so users can import their
/// existing Chrome extensions into Singularity in 1 click.
pub fn scan_installed_browsers_extensions() -> Vec<DetectedExternalExtension> {
    let mut roots: Vec<(&'static str, PathBuf)> = Vec::new();

    #[cfg(target_os = "windows")]
    if let Ok(local_app) = std::env::var("LOCALAPPDATA") {
        let base = PathBuf::from(local_app);
        roots.push((
            "Chrome",
            base.join("Google")
                .join("Chrome")
                .join("User Data")
                .join("Default")
                .join("Extensions"),
        ));
        roots.push((
            "Brave",
            base.join("BraveSoftware")
                .join("Brave-Browser")
                .join("User Data")
                .join("Default")
                .join("Extensions"),
        ));
        roots.push((
            "Edge",
            base.join("Microsoft")
                .join("Edge")
                .join("User Data")
                .join("Default")
                .join("Extensions"),
        ));
    }

    #[cfg(not(target_os = "windows"))]
    if let Ok(home) = std::env::var("HOME") {
        let cfg = PathBuf::from(home).join(".config");
        roots.push((
            "Chrome",
            cfg.join("google-chrome").join("Default").join("Extensions"),
        ));
        roots.push((
            "Brave",
            cfg.join("BraveSoftware")
                .join("Brave-Browser")
                .join("Default")
                .join("Extensions"),
        ));
        roots.push((
            "Chromium",
            cfg.join("chromium").join("Default").join("Extensions"),
        ));
    }

    let mut found = Vec::new();
    let mut seen_ids = std::collections::HashSet::new();

    for (browser, ext_root) in roots {
        let Ok(entries) = std::fs::read_dir(&ext_root) else {
            continue;
        };
        for entry in entries.flatten() {
            let p = entry.path();
            if !p.is_dir() {
                continue;
            }
            let Some(id) = p.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if !is_chrome_store_id(id) || seen_ids.contains(id) {
                continue;
            }
            let Some(ver_dir) = pick_latest_version_subdir(&p) else {
                continue;
            };
            if let Some(info) =
                parse_extension_dir_with_meta(&ver_dir, id, true, &[], ExtensionMeta::default())
            {
                // Skip Chromium internal component helpers without human-readable names
                if info.name.starts_with("__MSG_") {
                    continue;
                }
                seen_ids.insert(id.to_string());
                found.push(DetectedExternalExtension {
                    browser: browser.to_string(),
                    id: id.to_string(),
                    name: info.name,
                    version: info.version,
                    description: info.description,
                    source_dir: ver_dir.to_string_lossy().to_string(),
                });
            }
        }
    }
    found.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    found
}

fn wildcard_match_ext(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star_p, mut star_t) = (None, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi].eq_ignore_ascii_case(&t[ti])) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star_p = Some(pi);
            star_t = ti;
            pi += 1;
        } else if let Some(sp) = star_p {
            pi = sp + 1;
            star_t += 1;
            ti = star_t;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// Extracts a 32-char Edge Add-ons store ID (`a`..=`p`) from either a raw ID or a
/// `microsoftedge.microsoft.com/addons/detail/.../<id>` URL.
pub fn parse_edge_addons_id(input: &str) -> Option<String> {
    let trimmed = input.trim();
    if is_chrome_store_id(trimmed) {
        return Some(trimmed.to_ascii_lowercase());
    }
    if !trimmed.to_ascii_lowercase().contains("microsoftedge.microsoft.com") {
        return None;
    }
    parse_chrome_web_store_id(trimmed)
}

/// Generates localized EN/FR permission audit warnings before confirming extension installation.
pub fn describe_extension_permissions(
    permissions: &[String],
    host_permissions: &[String],
) -> Vec<PermissionWarning> {
    let mut warnings = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let all: Vec<&String> = permissions.iter().chain(host_permissions.iter()).collect();
    for perm in all {
        let p = perm.trim();
        if !seen.insert(p.to_string()) {
            continue;
        }
        let (severity, en, fr) = match p {
            "<all_urls>" | "*://*/*" | "http://*/*" | "https://*/*" => (
                "high",
                "Read and change all your data on all websites",
                "Lire et modifier toutes vos donnees sur tous les sites web",
            ),
            "tabs" => (
                "medium",
                "Read your browsing history and open tabs",
                "Lire votre historique de navigation et vos onglets ouverts",
            ),
            "history" => (
                "medium",
                "Read and change your browsing history",
                "Lire et modifier votre historique de navigation",
            ),
            "cookies" => (
                "high",
                "Read and modify cookies (including active sessions)",
                "Lire et modifier les cookies (y compris vos sessions actives)",
            ),
            "webRequest" | "webRequestBlocking" | "declarativeNetRequest" => (
                "medium",
                "Intercept, inspect, or block network requests",
                "Intercepter, inspecter ou bloquer les requetes reseau",
            ),
            "clipboardRead" => (
                "high",
                "Read data you copy and paste",
                "Lire les donnees copiees dans le presse-papiers",
            ),
            "clipboardWrite" => (
                "low",
                "Modify data you copy and paste",
                "Modifier les donnees dans le presse-papiers",
            ),
            "nativeMessaging" => (
                "high",
                "Communicate with cooperating native applications on this device",
                "Communiquer avec des applications natives sur cet appareil",
            ),
            "debugger" => (
                "high",
                "Access the page debugger backend (full tab inspection)",
                "Acceder au debogueur de page (inspection complete des onglets)",
            ),
            "downloads" => (
                "medium",
                "Manage your downloads",
                "Gerer vos telechargements",
            ),
            "bookmarks" => (
                "medium",
                "Read and change your bookmarks",
                "Lire et modifier vos favoris",
            ),
            "management" => (
                "high",
                "Manage your apps, extensions, and themes",
                "Gerer vos applications, extensions et themes",
            ),
            "proxy" => (
                "high",
                "Control proxy and network routing settings",
                "Controler les parametres proxy et le routage reseau",
            ),
            "storage" | "unlimitedStorage" => (
                "low",
                "Store extension preferences and local data",
                "Stocker les preferences et donnees locales de l'extension",
            ),
            "scripting" | "activeTab" => (
                "medium",
                "Run scripts inside web pages you interact with",
                "Executer des scripts dans les pages web visitees",
            ),
            other if other.starts_with("http://") || other.starts_with("https://") || other.starts_with("*://") => {
                warnings.push(PermissionWarning {
                    permission: other.to_string(),
                    severity: "medium".to_string(),
                    label_en: format!("Read and change your data on {}", other),
                    label_fr: format!("Lire et modifier vos donnees sur {}", other),
                });
                continue;
            }
            _ => continue,
        };
        warnings.push(PermissionWarning {
            permission: p.to_string(),
            severity: severity.to_string(),
            label_en: en.to_string(),
            label_fr: fr.to_string(),
        });
    }
    warnings
}

/// Inspects an unpacked directory or `.crx`/`.zip`/`.xpi` archive and returns a permission review
/// summary without permanently enabling the extension.
pub fn stage_extension_for_review(source: &Path) -> Result<StagedExtensionReview, String> {
    let manifest_raw = if source.is_dir() {
        std::fs::read_to_string(source.join("manifest.json"))
            .map_err(|e| format!("Cannot read manifest.json: {}", e))?
    } else if source.is_file() {
        let bytes = std::fs::read(source).map_err(|e| format!("Cannot read archive: {}", e))?;
        if bytes.len() > MAX_CRX_BYTES {
            return Err("Archive exceeds 32 MiB limit".to_string());
        }
        let zip_slice = extract_zip_slice_from_crx(&bytes).unwrap_or(&bytes);
        let mut archive = zip::ZipArchive::new(Cursor::new(zip_slice))
            .map_err(|e| format!("Invalid extension archive (.crx/.zip/.xpi): {}", e))?;
        let mut mf = archive
            .by_name("manifest.json")
            .map_err(|_| "Archive does not contain a root manifest.json".to_string())?;
        let mut s = String::new();
        mf.read_to_string(&mut s)
            .map_err(|e| format!("Failed to read manifest.json from archive: {}", e))?;
        s
    } else {
        return Err("Extension source path does not exist".to_string());
    };

    let manifest: serde_json::Value = serde_json::from_str(manifest_raw.trim_start_matches('\u{feff}'))
        .map_err(|e| format!("Invalid manifest.json: {}", e))?;
    let name = manifest
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("Unknown Extension")
        .to_string();
    let version = manifest
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("1.0")
        .to_string();
    let manifest_version = manifest
        .get("manifest_version")
        .and_then(|v| v.as_u64())
        .unwrap_or(3);
    let permissions: Vec<String> = manifest
        .get("permissions")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let host_permissions: Vec<String> = manifest
        .get("host_permissions")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let warnings = describe_extension_permissions(&permissions, &host_permissions);
    let id = source
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("staged_ext")
        .to_string();

    Ok(StagedExtensionReview {
        id,
        name,
        version,
        manifest_version,
        permissions,
        host_permissions,
        warnings,
        staged_path: source.to_string_lossy().to_string(),
    })
}

pub fn set_extension_site_access(
    roaming_root: &Path,
    dir_id: &str,
    mode: SiteAccessMode,
    allowed_sites: Vec<String>,
) -> Result<(), String> {
    if !is_valid_extension_dir_id(dir_id) {
        return Err("Invalid extension ID".to_string());
    }
    let mut meta = read_extension_meta(roaming_root, dir_id);
    meta.site_access_mode = mode;
    meta.allowed_sites = allowed_sites
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .take(128)
        .collect();
    write_extension_meta(roaming_root, dir_id, &meta);
    invalidate_extensions_cache();
    Ok(())
}

pub fn set_extension_privacy_flags(
    roaming_root: &Path,
    dir_id: &str,
    allow_in_incognito: Option<bool>,
    allow_file_urls: Option<bool>,
    allow_user_scripts: Option<bool>,
) -> Result<(), String> {
    if !is_valid_extension_dir_id(dir_id) {
        return Err("Invalid extension ID".to_string());
    }
    let mut meta = read_extension_meta(roaming_root, dir_id);
    if let Some(v) = allow_in_incognito {
        meta.allow_in_incognito = v;
    }
    if let Some(v) = allow_file_urls {
        meta.allow_file_urls = v;
    }
    if let Some(v) = allow_user_scripts {
        meta.allow_user_scripts = v;
    }
    write_extension_meta(roaming_root, dir_id, &meta);
    invalidate_extensions_cache();
    Ok(())
}

pub fn set_extension_command_shortcut(
    roaming_root: &Path,
    dir_id: &str,
    command_name: &str,
    shortcut: Option<String>,
) -> Result<(), String> {
    if !is_valid_extension_dir_id(dir_id) || command_name.trim().is_empty() {
        return Err("Invalid extension ID or command name".to_string());
    }
    let mut meta = read_extension_meta(roaming_root, dir_id);
    match shortcut.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) {
        Some(key) => {
            meta.custom_shortcuts.insert(command_name.trim().to_string(), key);
        }
        None => {
            meta.custom_shortcuts.remove(command_name.trim());
        }
    }
    write_extension_meta(roaming_root, dir_id, &meta);
    invalidate_extensions_cache();
    Ok(())
}

pub fn record_extension_error(
    roaming_root: &Path,
    dir_id: &str,
    entry: ExtensionErrorEntry,
) -> Result<(), String> {
    if !is_valid_extension_dir_id(dir_id) {
        return Err("Invalid extension ID".to_string());
    }
    let mut meta = read_extension_meta(roaming_root, dir_id);
    meta.errors.push(entry);
    if meta.errors.len() > 200 {
        let excess = meta.errors.len() - 200;
        meta.errors.drain(0..excess);
    }
    write_extension_meta(roaming_root, dir_id, &meta);
    invalidate_extensions_cache();
    Ok(())
}

pub fn get_extension_errors(roaming_root: &Path, dir_id: &str) -> Vec<ExtensionErrorEntry> {
    read_extension_meta(roaming_root, dir_id).errors
}

pub fn clear_extension_errors(roaming_root: &Path, dir_id: &str) -> Result<(), String> {
    if !is_valid_extension_dir_id(dir_id) {
        return Err("Invalid extension ID".to_string());
    }
    let mut meta = read_extension_meta(roaming_root, dir_id);
    meta.errors.clear();
    write_extension_meta(roaming_root, dir_id, &meta);
    invalidate_extensions_cache();
    Ok(())
}

pub fn set_extension_action_badge(
    roaming_root: &Path,
    dir_id: &str,
    badge_text: String,
    badge_bg_color: Option<String>,
) -> Result<(), String> {
    if !is_valid_extension_dir_id(dir_id) {
        return Err("Invalid extension ID".to_string());
    }
    let mut meta = read_extension_meta(roaming_root, dir_id);
    meta.action_state.badge_text = badge_text.chars().take(8).collect();
    if let Some(bg) = badge_bg_color {
        if !bg.trim().is_empty() {
            meta.action_state.badge_bg_color = bg.trim().to_string();
        }
    }
    write_extension_meta(roaming_root, dir_id, &meta);
    invalidate_extensions_cache();
    Ok(())
}

/// Parses an Omaha v3 XML update manifest (`<app appid="..."><updatecheck codebase="..." version="..." hash_sha256="..."/>`)
/// in pure Rust with zero external XML dependencies.
pub fn parse_omaha_update_xml(xml: &str) -> Vec<ExtensionUpdateAvailable> {
    fn extract_attr(tag: &str, attr: &str) -> Option<String> {
        let pat_dq = format!("{}=\"", attr);
        if let Some(pos) = tag.find(&pat_dq) {
            let rest = &tag[pos + pat_dq.len()..];
            if let Some(end) = rest.find('"') {
                return Some(rest[..end].to_string());
            }
        }
        let pat_sq = format!("{}='", attr);
        if let Some(pos) = tag.find(&pat_sq) {
            let rest = &tag[pos + pat_sq.len()..];
            if let Some(end) = rest.find('\'') {
                return Some(rest[..end].to_string());
            }
        }
        None
    }

    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(app_pos) = rest.find("<app ") {
        rest = &rest[app_pos..];
        let app_tag_end = match rest.find('>') {
            Some(i) => i,
            None => break,
        };
        let app_tag = &rest[..app_tag_end];
        let app_id = extract_attr(app_tag, "appid").unwrap_or_default();
        let next_section_end = rest.find("</app>").unwrap_or(rest.len());
        let app_body = &rest[app_tag_end..next_section_end];
        if let Some(uc_pos) = app_body.find("<updatecheck") {
            let uc_rest = &app_body[uc_pos..];
            if let Some(uc_end) = uc_rest.find('>') {
                let uc_tag = &uc_rest[..uc_end];
                let status = extract_attr(uc_tag, "status").unwrap_or_else(|| "ok".to_string());
                if status == "ok" {
                    if let (Some(version), Some(codebase)) =
                        (extract_attr(uc_tag, "version"), extract_attr(uc_tag, "codebase"))
                    {
                        let sha256 = extract_attr(uc_tag, "hash_sha256")
                            .or_else(|| extract_attr(uc_tag, "fp"));
                        if !app_id.is_empty() && !codebase.is_empty() {
                            out.push(ExtensionUpdateAvailable {
                                id: app_id,
                                version,
                                codebase_url: codebase,
                                sha256,
                            });
                        }
                    }
                }
            }
        }
        rest = &rest[next_section_end.min(rest.len())..];
    }
    out
}

/// Discovers Chrome-compatible Native Messaging host JSON manifests from configured directories.
pub fn discover_native_messaging_hosts(dirs: &[PathBuf]) -> Vec<NativeMessagingHost> {
    let mut hosts = Vec::new();
    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let p = entry.path();
            if p.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            if let Ok(raw) = std::fs::read_to_string(&p) {
                if let Ok(host) = serde_json::from_str::<NativeMessagingHost>(&raw) {
                    if !host.name.trim().is_empty() && !host.path.trim().is_empty() {
                        hosts.push(host);
                    }
                }
            }
        }
    }
    hosts
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    // TEST-ONLY deterministic 2048-bit RSA keypair generated strictly for unit tests.
    const TEST_RSA_SPKI_HEX: &str = "30820122300d06092a864886f70d01010105000382010f003082010a0282010100aa5f50dd32852e58e9f7d75cc18fe1113ef1e6faf502a6e0a0b99221ea018d9d9d2bf697773fca29f109a7baf49e623bff246c1e538c6784ab9ee373b208b0eed95692c8aae41a0c383066dc742ed01c403c7f25588adb5023bdaef9dbf6a8782a7d2a79142e9eef144aab5cd780a6131dc39523c13b75ed193441f9bcd08e8e2dd6aecab83f269b1cf1302083395d5a8bca6d6fa13ef6ae36f955f28adf051ade7d19a39ff13aa8d9fe34efae738278643271b4c2d4b41d3de830eab5f31356115229c4ce0dc57bbd1865db876e33eb80ef8806eb2cf977ef0ad78f5e80ba3fc3d33642c85616869ac59123d374ef2a2c180f3f3262be809ce228e385aef6cd0203010001";
    const TEST_RSA_N_HEX: &str = "aa5f50dd32852e58e9f7d75cc18fe1113ef1e6faf502a6e0a0b99221ea018d9d9d2bf697773fca29f109a7baf49e623bff246c1e538c6784ab9ee373b208b0eed95692c8aae41a0c383066dc742ed01c403c7f25588adb5023bdaef9dbf6a8782a7d2a79142e9eef144aab5cd780a6131dc39523c13b75ed193441f9bcd08e8e2dd6aecab83f269b1cf1302083395d5a8bca6d6fa13ef6ae36f955f28adf051ade7d19a39ff13aa8d9fe34efae738278643271b4c2d4b41d3de830eab5f31356115229c4ce0dc57bbd1865db876e33eb80ef8806eb2cf977ef0ad78f5e80ba3fc3d33642c85616869ac59123d374ef2a2c180f3f3262be809ce228e385aef6cd";
    const TEST_RSA_D_HEX: &str = "400270a0b27eec1356d019774d77cf9109ab9be2f4938afc0116c76afb7e9ae4b92ccfc84772cd73258ec19851988202d590ab1857be7c1411e0afc70380156d9f7551cf97b8fc7a53d0078d530f557c0fbc4aeece8dd8e90a8c950565d98da11c218b8813079309f2ff3cd3b459aecba6d6991d66577f2e55d656e54bc5b590e2735e17a647e78c89ce7559e581d8ebd4f3018e265dfe1a4747cefd7042d45f95aa2505757360f3ab144d59f383aaf9ffff35e88d0070d987fd766e369582f139561ce162c1ed262886a03eaba534c3c93aa226aadb7af65320a42d62a9fa400f86a285d39568601081701e02fc7eeca7a3048833ec41410c1f5460f05a38d7";
    const TEST_RSA_EXT_ID: &str = "ofhmgkpplmjecihkgbocjddacdknlbhf";

    fn encode_pb_varint(mut v: u64, out: &mut Vec<u8>) {
        loop {
            let mut b = (v & 0x7F) as u8;
            v >>= 7;
            if v != 0 {
                b |= 0x80;
            }
            out.push(b);
            if v == 0 {
                break;
            }
        }
    }

    fn push_pb_bytes_field(field_num: u64, data: &[u8], out: &mut Vec<u8>) {
        encode_pb_varint((field_num << 3) | 2, out);
        encode_pb_varint(data.len() as u64, out);
        out.extend_from_slice(data);
    }

    fn sign_pkcs1v15_test(prefix: &[u8], digest: &[u8]) -> Vec<u8> {
        let n = hex::decode(TEST_RSA_N_HEX).unwrap();
        let d = hex::decode(TEST_RSA_D_HEX).unwrap();
        let k = n.len();
        let ps_len = k - 3 - prefix.len() - digest.len();
        let mut em = Vec::with_capacity(k);
        em.push(0x00);
        em.push(0x01);
        em.resize(2 + ps_len, 0xFF);
        em.push(0x00);
        em.extend_from_slice(prefix);
        em.extend_from_slice(digest);
        rsa_mod_pow(&em, &d, &n).unwrap()
    }

    fn build_signed_crx3(zip_buf: &[u8]) -> Vec<u8> {
        const SHA256_PREFIX: &[u8] = &[
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0x04, 0x20,
        ];
        let spki = hex::decode(TEST_RSA_SPKI_HEX).unwrap();
        let crx_id = chromium_id_bytes_from_spki(&spki);

        let mut signed_header_data = Vec::new();
        push_pb_bytes_field(1, &crx_id, &mut signed_header_data);

        let mut hasher = Sha256::new();
        hasher.update(b"CRX3 SignedData\x00");
        hasher.update((signed_header_data.len() as u32).to_le_bytes());
        hasher.update(&signed_header_data);
        hasher.update(zip_buf);
        let digest: [u8; 32] = hasher.finalize().into();

        let sig = sign_pkcs1v15_test(SHA256_PREFIX, &digest);

        let mut proof = Vec::new();
        push_pb_bytes_field(1, &spki, &mut proof);
        push_pb_bytes_field(2, &sig, &mut proof);

        let mut header = Vec::new();
        push_pb_bytes_field(2, &proof, &mut header);
        push_pb_bytes_field(10000, &signed_header_data, &mut header);

        let mut crx3 = Vec::new();
        crx3.extend_from_slice(b"Cr24");
        crx3.extend_from_slice(&3u32.to_le_bytes());
        crx3.extend_from_slice(&(header.len() as u32).to_le_bytes());
        crx3.extend_from_slice(&header);
        crx3.extend_from_slice(zip_buf);
        crx3
    }

    fn build_signed_crx2(zip_buf: &[u8]) -> Vec<u8> {
        const SHA1_PREFIX: &[u8] = &[
            0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04,
            0x14,
        ];
        let spki = hex::decode(TEST_RSA_SPKI_HEX).unwrap();
        let digest = sha1_digest(zip_buf);
        let sig = sign_pkcs1v15_test(SHA1_PREFIX, &digest);

        let mut crx2 = Vec::new();
        crx2.extend_from_slice(b"Cr24");
        crx2.extend_from_slice(&2u32.to_le_bytes());
        crx2.extend_from_slice(&(spki.len() as u32).to_le_bytes());
        crx2.extend_from_slice(&(sig.len() as u32).to_le_bytes());
        crx2.extend_from_slice(&spki);
        crx2.extend_from_slice(&sig);
        crx2.extend_from_slice(zip_buf);
        crx2
    }

    #[test]
    fn test_parse_chrome_web_store_id() {
        assert_eq!(
            parse_chrome_web_store_id("ddkjiahejlhfcafbddmgiahcphecmpfh").as_deref(),
            Some("ddkjiahejlhfcafbddmgiahcphecmpfh")
        );
        assert_eq!(
            parse_chrome_web_store_id(
                "https://chromewebstore.google.com/detail/ublock-origin-lite/ddkjiahejlhfcafbddmgiahcphecmpfh?hl=fr"
            )
            .as_deref(),
            Some("ddkjiahejlhfcafbddmgiahcphecmpfh")
        );
        assert!(parse_chrome_web_store_id("../../../etc/passwd").is_none());
        assert!(parse_chrome_web_store_id("not-a-valid-id").is_none());
    }

    #[test]
    fn test_crx2_and_crx3_cryptographic_verification_and_tamper_rejection() {
        // Verify FIPS 180-4 SHA-1 vectors
        assert_eq!(
            hex::encode(sha1_digest(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );

        // Verify OpenSSL-generated RSA-2048 SHA-256 & SHA-1 signatures independently
        let spki = hex::decode(TEST_RSA_SPKI_HEX).unwrap();
        let openssl_sig256 = hex::decode("978762c47e11af78c5bd9278a717a23c4f029dece726bd7cd693f9adb117b31593a1e009a6140bf69efa5cc4388d8b42a92951f891ee7fde56b250aac0d769671393738d8f844d74abfbaaf979a43e4f11dc055a1207411cc69818f319c9b7b8ca04db0696b316c88df2b08b2447192cbedbc37ee867dae8bbe8bdf651fc067c216db70b349e190cba9e550665be88c16a77a18d68564fda3686ca1095502dc84e177f48e80eee372e09004d9fc4e5da1d01ea0a4a3ce428edda6e8d3ec4fb531416d49730617afb05c777bda062813426a6f42222e08265004fe25b0b56036074fd919dcb0d0cb941faabd3a79a9430f9ca0d643a44d8b9bfd1f5309355134c").unwrap();
        let openssl_sig1 = hex::decode("65ea71e043bdaf8b1619f2bb919956c583e2252f0bd868f49ff8f3bf56eebd5521363ceb493be394d62237145dc5affc4487931cedd7da975d36812c0e1f92dcda5fd79f8ca22e31ac4430d3fd74329b052abf99933eb87c3ab7ae2786767187162cfd9673b28c4223d670be022d0b55e122f3331573a9bcde0165844147dfd645f0f98c4a65f363b316756601563d30f0992399de082ef04d88b8c4687dcd3761dad8744dc75c4c52de37ad4b72d4e0fdd6a578082ce70a9438b526edd1b93d6ba2181c14adeac915544abe0456a58f232109011442ebed9e406ac017c9f7e2177c3d117882a04b417951ec78b47deb76e436140675273f0a581262680481ef").unwrap();
        let d256: [u8; 32] = Sha256::digest(b"test-crx-payload").into();
        let d1 = sha1_digest(b"test-crx-payload");
        verify_rsa_pkcs1v15_sha256(&spki, &d256, &openssl_sig256).expect("OpenSSL RSA-SHA256");
        verify_rsa_pkcs1v15_sha1(&spki, &d1, &openssl_sig1).expect("OpenSSL RSA-SHA1");

        // Build minimal valid ZIP containing manifest.json
        let mut zip_buf = Vec::new();
        {
            let mut zw = zip::ZipWriter::new(Cursor::new(&mut zip_buf));
            let opts = zip::write::SimpleFileOptions::default();
            zw.start_file("manifest.json", opts).unwrap();
            zw.write_all(
                br#"{"manifest_version":3,"name":"Test Ext","version":"1.2.3","description":"Demo","permissions":["storage"],"host_permissions":["https://api.example.com/*"]}"#,
            )
            .unwrap();
            zw.finish().unwrap();
        }

        // 1. Valid RSA-2048 signed CRX3 passes verification and installs under bound ID
        let crx3 = build_signed_crx3(&zip_buf);
        let verified3 = verify_crx_package(&crx3, Some(TEST_RSA_EXT_ID)).expect("verify CRX3");
        assert_eq!(verified3.derived_id, TEST_RSA_EXT_ID);

        // Wrong expected ID is rejected!
        assert!(verify_crx_package(&crx3, Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")).is_err());

        // Tampered ZIP byte inside CRX3 is rejected!
        let mut tampered_crx3 = crx3.clone();
        let last_idx = tampered_crx3.len() - 1;
        tampered_crx3[last_idx] ^= 0x01;
        assert!(verify_crx_package(&tampered_crx3, Some(TEST_RSA_EXT_ID)).is_err());

        // Unsigned/synthetic CRX3 header is rejected by install_bytes_under_id!
        let mut unsigned_crx3 = Vec::new();
        unsigned_crx3.extend_from_slice(b"Cr24");
        unsigned_crx3.extend_from_slice(&3u32.to_le_bytes());
        unsigned_crx3.extend_from_slice(&4u32.to_le_bytes());
        unsigned_crx3.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        unsigned_crx3.extend_from_slice(&zip_buf);

        let tmp = std::env::temp_dir().join(format!(
            "singularity-ext-test-{}-{}",
            std::process::id(),
            random_hex_nonce()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        assert!(install_bytes_under_id(&tmp, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", &unsigned_crx3, &[]).is_err());
        assert!(install_bytes_under_id(&tmp, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", &crx3, &[]).is_err());

        let info = install_bytes_under_id(&tmp, TEST_RSA_EXT_ID, &crx3, &[]).expect("install verified CRX3");
        assert_eq!(info.name, "Test Ext");
        assert_eq!(info.version, "1.2.3");
        assert!(info.enabled);
        assert_eq!(info.host_permissions, vec!["https://api.example.com/*"]);
        assert!(info.permissions.contains(&"https://api.example.com/*".to_string()));

        set_extension_enabled(&tmp, TEST_RSA_EXT_ID, false).unwrap();
        let listed = list_extensions(&tmp, &[]);
        assert_eq!(listed.len(), 1);
        assert!(!listed[0].enabled);

        remove_extension(&tmp, TEST_RSA_EXT_ID).unwrap();
        assert!(list_extensions(&tmp, &[]).is_empty());

        // 2. Valid RSA-2048 signed CRX2 passes verification & tampered CRX2 is rejected
        let crx2 = build_signed_crx2(&zip_buf);
        let verified2 = verify_crx_package(&crx2, Some(TEST_RSA_EXT_ID)).expect("verify CRX2");
        assert_eq!(verified2.derived_id, TEST_RSA_EXT_ID);
        let mut tampered_crx2 = crx2.clone();
        let li2 = tampered_crx2.len() - 1;
        tampered_crx2[li2] ^= 0x80;
        assert!(verify_crx_package(&tampered_crx2, Some(TEST_RSA_EXT_ID)).is_err());

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_svg_sanitizer_public_suffixes_utf8_paths_i18n_and_numeric_versions() {
        // 1. Strict allowlist SVG sanitizer
        assert!(is_safe_svg_icon(
            br##"<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><defs><linearGradient id="g"><stop offset="0%"/></linearGradient></defs><path d="M0 0h24v24H0z" fill="url(#g)"/><use href="#g"/></svg>"##
        ));
        for bad_svg in [
            br#"<svg><script>alert(1)</script></svg>"#.as_slice(),
            br#"<svg xmlns:x="http://www.w3.org/2000/svg"><x:script>alert(1)</x:script></svg>"#,
            br#"<svg><foreignObject><body xmlns="http://www.w3.org/1999/xhtml"><img src=x onerror=alert(1)></body></foreignObject></svg>"#,
            br#"<svg onload = "alert(1)"><rect width="10" height="10"/></svg>"#,
            br#"<svg><rect onclick="alert(1)"/></svg>"#,
            br#"<svg><set attributeName="href" to="javascript:alert(1)"/></svg>"#,
            br#"<svg><animate onbegin="alert(1)"/></svg>"#,
            br#"<svg><use href="javascript:alert(1)"/></svg>"#,
            br#"<svg><use href="&#106;avascript:alert(1)"/></svg>"#,
            br#"<svg><use xlink:href="data:image/svg+xml,<svg/>"/></svg>"#,
            br#"<svg><style>@import url(https://evil.test/x.css);</style></svg>"#,
        ] {
            assert!(
                !is_safe_svg_icon(bad_svg),
                "must reject malicious SVG: {}",
                String::from_utf8_lossy(bad_svg)
            );
        }

        // 2. Public suffix rejection & exclusion of optional_host_permissions / homepage_url
        assert_eq!(extract_concrete_host_from_pattern("https://*.co.uk/*"), None);
        assert_eq!(extract_concrete_host_from_pattern("https://*.com.au/*"), None);
        assert_eq!(extract_concrete_host_from_pattern("https://*.github.io/*"), None);
        assert_eq!(
            extract_concrete_host_from_pattern("https://*.bbc.co.uk/*").as_deref(),
            Some("bbc.co.uk")
        );
        assert_eq!(
            extract_concrete_host_from_pattern("https://myorg.github.io/*").as_deref(),
            Some("myorg.github.io")
        );

        let tmp = std::env::temp_dir().join(format!(
            "singularity-ext-hardening-{}-{}",
            std::process::id(),
            random_hex_nonce()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        let ext_dir = tmp.join("extensions").join("test_ext");
        std::fs::create_dir_all(ext_dir.join("_locales/en")).unwrap();
        std::fs::create_dir_all(ext_dir.join("_locales/fr")).unwrap();
        std::fs::create_dir_all(ext_dir.join("_locales/de")).unwrap();
        std::fs::write(
            ext_dir.join("_locales/en/messages.json"),
            r#"{"appName":{"message":"English Name"}}"#,
        )
        .unwrap();
        std::fs::write(
            ext_dir.join("_locales/fr/messages.json"),
            r#"{"appName":{"message":"Nom Francais"}}"#,
        )
        .unwrap();
        std::fs::write(
            ext_dir.join("_locales/de/messages.json"),
            r#"{"appName":{"message":"Deutscher Name"}}"#,
        )
        .unwrap();
        std::fs::write(
            ext_dir.join("manifest.json"),
            r#"{
                "manifest_version": 3,
                "name": "__MSG_appName__",
                "default_locale": "de",
                "version": "1.0.0",
                "host_permissions": ["https://*.bitwarden.com/*", "https://*.co.uk/*"],
                "optional_host_permissions": ["https://optional-only.example.com/*"],
                "homepage_url": "https://homepage-only.example.org/"
            }"#,
        )
        .unwrap();

        // Respects default_locale ("de") when no UI language configured; never forces "fr"!
        let info_default = parse_extension_dir(&tmp, &ext_dir, "test_ext", true, &[]).unwrap();
        assert_eq!(info_default.name, "Deutscher Name");

        // Respects configured UI language ("en") in profile.json
        std::fs::write(tmp.join("profile.json"), r#"{"language":"en"}"#).unwrap();
        let info_en = parse_extension_dir(&tmp, &ext_dir, "test_ext", true, &[]).unwrap();
        assert_eq!(info_en.name, "English Name");

        // Respects configured UI language ("fr") when user explicitly chose French
        std::fs::write(tmp.join("profile.json"), r#"{"language":"fr"}"#).unwrap();
        let info_fr = parse_extension_dir(&tmp, &ext_dir, "test_ext", true, &[]).unwrap();
        assert_eq!(info_fr.name, "Nom Francais");

        // Host domains exclude optional_host_permissions, homepage_url, and public suffixes
        invalidate_extensions_cache();
        let domains = collect_installed_extension_host_domains(&tmp);
        assert!(domains.contains(&"bitwarden.com".to_string()));
        assert!(!domains.contains(&"co.uk".to_string()));
        assert!(!domains.contains(&"optional-only.example.com".to_string()));
        assert!(!domains.contains(&"homepage-only.example.org".to_string()));

        // 3. UTF-8 byte-safe percent decoding never panics on multi-byte sequences after '%'
        let _ = normalize_local_extension_input("file:///tmp/%é/ext");
        let _ = normalize_local_extension_input("file:///tmp/%aé/ext");
        assert!(normalize_local_extension_input("file:///tmp/my%20ext").contains("my ext"));

        // 4. Relative path guard rejects Windows drive prefixes, root, parent traversal
        assert!(!is_safe_relative_extension_path(Path::new("C:evil.js")));
        assert!(!is_safe_relative_extension_path(Path::new("C:/Windows/a.js")));
        assert!(!is_safe_relative_extension_path(Path::new("/etc/passwd")));
        assert!(!is_safe_relative_extension_path(Path::new("../escape.js")));
        assert!(is_safe_relative_extension_path(Path::new("scripts/content.js")));

        // 5. Numeric extension version sorting (1.10.0_0 > 1.9.0_0)
        assert_eq!(
            compare_extension_version_names("1.10.0_0", "1.9.0_0"),
            std::cmp::Ordering::Greater
        );
        assert_eq!(
            compare_extension_version_names("2.0.0_12", "2.0.0_2"),
            std::cmp::Ordering::Greater
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
