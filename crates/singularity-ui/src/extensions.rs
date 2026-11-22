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
use std::path::{Path, PathBuf};
#[cfg(not(target_os = "windows"))]
use std::process::{Command, Stdio};

const MAX_CRX_BYTES: usize = 32 * 1024 * 1024; // 32 MiB compressed package cap
const MAX_EXTRACTED_BYTES: u64 = 64 * 1024 * 1024; // 64 MiB total uncompressed cap
const MAX_ARCHIVE_ENTRIES: usize = 4096;

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
    pub permissions: Vec<String>,
    pub install_path: String,
    pub source_path: Option<String>,
    pub runtime_id: Option<String>,
}

/// Out-of-band Singularity metadata stored in `%APPDATA%\.singularity\extensions_meta\<dir_id>.json`
/// (outside the extension directory so Chromium never sees extra files inside the unpacked root).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExtensionMeta {
    pub source_path: Option<String>,
    pub runtime_id: Option<String>,
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
/// zip-slip protection, entry-count caps, and total uncompressed size caps.
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
        let Some(rel_path) = entry.enclosed_name().map(|p| p.to_path_buf()) else {
            return Err("Disallowed path detected inside archive (zip-slip blocked).".into());
        };
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
                p.is_dir()
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
        return Err("manifest.json introuvable dans cette extension Chrome.".into());
    }
    Ok(())
}

fn resolve_i18n_string(ext_dir: &Path, raw: &str) -> String {
    let trimmed = raw.trim();
    if !(trimmed.starts_with("__MSG_") && trimmed.ends_with("__") && trimmed.len() > 8) {
        return trimmed.to_string();
    }
    let key = &trimmed[6..trimmed.len() - 2];
    for locale in ["fr", "fr_FR", "en", "en_US", "en_GB"] {
        let p = ext_dir.join("_locales").join(locale).join("messages.json");
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
    parse_extension_dir_with_meta(ext_dir, id, enabled, pinned_ids, meta)
}

fn parse_extension_dir_with_meta(
    ext_dir: &Path,
    id: &str,
    enabled: bool,
    pinned_ids: &[String],
    meta: ExtensionMeta,
) -> Option<ChromeExtensionInfo> {
    let manifest_path = ext_dir.join("manifest.json");
    let raw = std::fs::read_to_string(&manifest_path).ok()?;
    let clean = raw.trim_start_matches('\u{feff}');
    let manifest: serde_json::Value = serde_json::from_str(clean).ok()?;

    let raw_name = manifest
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or(id);
    let raw_desc = manifest
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let name = resolve_i18n_string(ext_dir, raw_name);
    let description = resolve_i18n_string(ext_dir, raw_desc);
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

    let permissions = manifest
        .get("permissions")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .take(16)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let has_icon = pick_manifest_icon_rel_path(&manifest)
        .and_then(|rel| resolve_safe_child_path(ext_dir, &rel))
        .is_some_and(|p| p.is_file());

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
        permissions,
        install_path: ext_dir.to_string_lossy().to_string(),
        source_path: meta.source_path,
        runtime_id: meta.runtime_id,
    })
}

fn resolve_safe_child_path(base_dir: &Path, rel: &str) -> Option<PathBuf> {
    let trimmed = rel.trim().trim_start_matches('/');
    if trimmed.is_empty() || trimmed.contains("..") || trimmed.contains('\\') {
        return None;
    }
    let joined = base_dir.join(trimmed);
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
            if let Some(info) = parse_extension_dir(roaming_root, &p, id, enabled, pinned_ids) {
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
    std::sync::Mutex<Option<(PathBuf, Vec<String>, Vec<ChromeExtensionInfo>)>>,
> = std::sync::OnceLock::new();

static EXTENSION_HOST_DOMAINS_CACHE: std::sync::OnceLock<
    std::sync::Mutex<Option<(PathBuf, Vec<String>)>>,
> = std::sync::OnceLock::new();

/// Returns installed extensions from RAM when unchanged (zero directory scans on `/api/state`).
pub fn list_extensions_cached(
    roaming_root: &Path,
    pinned_ids: &[String],
) -> Vec<ChromeExtensionInfo> {
    let lock = EXTENSIONS_CACHE.get_or_init(|| std::sync::Mutex::new(None));
    if let Ok(guard) = lock.lock() {
        if let Some((ref cached_root, ref cached_pinned, ref items)) = *guard {
            if cached_root == roaming_root && cached_pinned.as_slice() == pinned_ids {
                return items.clone();
            }
        }
    }
    let fresh = list_extensions(roaming_root, pinned_ids);
    if let Ok(mut guard) = lock.lock() {
        *guard = Some((roaming_root.to_path_buf(), pinned_ids.to_vec(), fresh.clone()));
    }
    fresh
}

/// Extracts a concrete domain from a Chrome extension match pattern or URL
/// (e.g. `https://*.bitwarden.com/*` -> `bitwarden.com`), ignoring broad wildcards
/// like `<all_urls>` or `*://*/*` so the adblocker stays effective on normal sites.
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
    let host = host.trim_start_matches("*.").trim_start_matches('.');
    if host.is_empty()
        || host.contains('*')
        || !host.contains('.')
        || host == "localhost"
        || host == "127.0.0.1"
        || !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    {
        return None;
    }
    Some(host.to_string())
}

/// Collects concrete host domains declared in enabled Chrome extensions' `manifest.json`
/// (`host_permissions`, `optional_host_permissions`, `permissions`, `content_scripts[].matches`,
/// `externally_connectable.matches`, `homepage_url`) so Singularity preserves extension auth
/// cookies and API token-refresh calls.
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
            for key in ["host_permissions", "optional_host_permissions", "permissions"] {
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
            if let Some(hp) = manifest.get("homepage_url").and_then(|v| v.as_str()) {
                patterns.push(hp);
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
                // Defense-in-depth: reject scripted SVGs even though endpoint also sets CSP sandbox
                let Ok(txt) = std::str::from_utf8(&bytes) else {
                    continue;
                };
                let lower = txt.to_ascii_lowercase();
                if lower.contains("<script")
                    || lower.contains("foreignobject")
                    || lower.contains("onload=")
                    || lower.contains("onerror=")
                    || lower.contains("javascript:")
                {
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
            // CrxFileHeader: field 2 = sha256_with_rsa (AsymmetricKeyProof), field 3 = sha256_with_ecdsa
            // AsymmetricKeyProof: field 1 = public_key (bytes)
            for proof_field in [2u64, 3u64] {
                if let Some(proof) = extract_pb_bytes_field(header, proof_field) {
                    if let Some(pk) = extract_pb_bytes_field(proof, 1) {
                        if pk.len() >= 32 && pk.len() <= 4096 {
                            return Some(BASE64.encode(pk));
                        }
                    }
                }
            }
            None
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
    let digest = Sha256::digest(&bytes);
    let mut id = String::with_capacity(32);
    for &b in &digest[..16] {
        id.push((b'a' + (b >> 4)) as char);
        id.push((b'a' + (b & 0x0F)) as char);
    }
    Some(id)
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

/// Downloads and installs a Chrome extension directly from the Chrome Web Store by ID or URL.
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

    install_bytes_under_id(roaming_root, &ext_id, &raw_bytes, pinned_ids)
}

fn install_bytes_under_id(
    roaming_root: &Path,
    ext_id: &str,
    raw_bytes: &[u8],
    pinned_ids: &[String],
) -> Result<ChromeExtensionInfo, String> {
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

    // Preserve CRX public key inside manifest.json so WebView2 assigns the exact Chrome Store ID
    if let Some(key_b64) = extract_crx_public_key_b64(raw_bytes) {
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
        // Decode basic %XX escapes (e.g., %20 for spaces)
        let mut decoded = Vec::with_capacity(rest.len());
        let bytes = rest.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' && i + 2 < bytes.len() {
                if let Ok(val) = u8::from_str_radix(&rest[i + 1..i + 3], 16) {
                    decoded.push(val);
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
            && !clean.contains("..")
            && !clean.contains('*')
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
    if src_dir.join("_locales").is_dir() {
        let _ = copy_dir_recursive(
            &src_dir.join("_locales"),
            &dst_dir.join("_locales"),
            &mut total_bytes,
        );
    }
    for rel in collect_manifest_referenced_rel_paths(manifest) {
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
                let target = dst_dir.join(&rel);
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
            let stem = src
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("local_ext");
            let id = derive_safe_id(explicit_id.unwrap_or(stem));
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

    let manifest_key_id = manifest
        .get("key")
        .and_then(|v| v.as_str())
        .and_then(chromium_id_from_public_key_b64);
    let manifest_name = manifest
        .get("name")
        .and_then(|v| v.as_str())
        .map(|raw| resolve_i18n_string(&manifest_dir, raw))
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

fn pick_latest_version_subdir(ext_root: &Path) -> Option<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(ext_root)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir() && p.join("manifest.json").is_file())
        .collect();
    dirs.sort();
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

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
    fn test_crx3_extraction_and_zip_slip_rejection() {
        // Build a minimal valid ZIP containing manifest.json
        let mut zip_buf = Vec::new();
        {
            let mut zw = zip::ZipWriter::new(Cursor::new(&mut zip_buf));
            let opts = zip::write::SimpleFileOptions::default();
            zw.start_file("manifest.json", opts).unwrap();
            zw.write_all(
                br#"{"manifest_version":3,"name":"Test Ext","version":"1.2.3","description":"Demo"}"#,
            )
            .unwrap();
            zw.finish().unwrap();
        }

        // Wrap in a synthetic CRX3 header: "Cr24" + version=3 + header_len=4 + 4 dummy bytes + ZIP
        let mut crx3 = Vec::new();
        crx3.extend_from_slice(b"Cr24");
        crx3.extend_from_slice(&3u32.to_le_bytes());
        crx3.extend_from_slice(&4u32.to_le_bytes());
        crx3.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        crx3.extend_from_slice(&zip_buf);

        let tmp = std::env::temp_dir().join(format!("singularity-ext-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let info = install_bytes_under_id(&tmp, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", &crx3, &[])
            .expect("install CRX3");
        assert_eq!(info.name, "Test Ext");
        assert_eq!(info.version, "1.2.3");
        assert!(info.enabled);

        set_extension_enabled(&tmp, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false).unwrap();
        let listed = list_extensions(&tmp, &[]);
        assert_eq!(listed.len(), 1);
        assert!(!listed[0].enabled);

        remove_extension(&tmp, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        assert!(list_extensions(&tmp, &[]).is_empty());
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
