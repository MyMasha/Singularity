//! Hybrid DRM Playback Engine for Singularity Browser:
//! 1. **VMP/PlayReady Domain Classification** (cross-platform): identifies streaming services
//!    that require Verified Media Path (VMP) or Hardware PlayReady (Netflix, Disney+, Prime Video,
//!    Canal+, Apple TV+, Max, etc.) so those tabs automatically use the signed Windows DRM engine.
//! 2. **Chromium CEF Widevine CDM Bootstrap** (cross-platform prefs + Windows CDM seed): enables
//!    `protected_media_identifier = 1` in `<cef_profile_dir>/Default/Preferences` without
//!    overwriting unrelated settings, and on Windows seeds `<cef_profile_dir>/WidevineCdm`
//!    atomically from an existing local Chrome/Edge/Brave installation when not yet downloaded.
//! 3. **Signed Windows WebView2 DRM Tab Host** (`#[cfg(target_os = "windows")]`): embeds a
//!    hardened child WebView2 inside `tao` with **zero `window.ipc` exposure**, fail-closed
//!    local-IPC/file/policy navigation filtering, and native fullscreen + history COM callbacks.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Domains whose EME DRM streams require Google VMP signing or Windows Hardware PlayReady.
const VMP_DRM_DOMAINS: &[(&str, &str)] = &[
    ("netflix.com", "Netflix"),
    ("disneyplus.com", "Disney+"),
    ("primevideo.com", "Prime Video"),
    ("canalplus.com", "Canal+"),
    ("mycanal.fr", "Canal+"),
    ("tv.apple.com", "Apple TV+"),
    ("max.com", "Max"),
    ("hbomax.com", "Max"),
    ("paramountplus.com", "Paramount+"),
    ("hulu.com", "Hulu"),
    ("peacocktv.com", "Peacock"),
    ("dazn.com", "DAZN"),
    ("molotov.tv", "Molotov"),
    ("france.tv", "France.tv"),
    ("tf1.fr", "TF1+"),
    ("m6plus.m6.fr", "M6+"),
    ("discoveryplus.com", "Discovery+"),
    ("hotstar.com", "Hotstar"),
    ("starplus.com", "Star+"),
    ("rakuten.tv", "Rakuten TV"),
    ("fubo.tv", "Fubo"),
    ("sling.com", "Sling TV"),
    ("crunchyroll.com", "Crunchyroll"),
];

const MAX_PREFERENCES_BYTES: u64 = 32 * 1024 * 1024;
static TMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(1);

fn strip_prefix_ignore_ascii_case<'a>(haystack: &'a str, prefix: &str) -> Option<&'a str> {
    if haystack.len() >= prefix.len() && haystack[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(&haystack[prefix.len()..])
    } else {
        None
    }
}

/// Strictly parses an `http://` or `https://` URL (case-insensitive) and returns the normalized
/// lowercase host with userinfo, port, and trailing `.` removed. Returns `None` for non-HTTP(S)
/// schemes, control characters, empty/ambiguous authorities, or invalid ports.
fn extract_http_host(url: &str) -> Option<String> {
    if url.bytes().any(|b| b < 0x20 || b == 0x7F) {
        return None;
    }
    let trimmed = url.trim();
    let rest = strip_prefix_ignore_ascii_case(trimmed, "https://")
        .or_else(|| strip_prefix_ignore_ascii_case(trimmed, "http://"))?;

    let authority = rest.split(['/', '\\', '?', '#']).next().unwrap_or("");
    if authority.is_empty() || authority.bytes().any(|b| b.is_ascii_whitespace()) {
        return None;
    }

    let hostport = match authority.rsplit_once('@') {
        Some((_, hp)) => hp,
        None => authority,
    };
    if hostport.is_empty() {
        return None;
    }

    if let Some(after_open) = hostport.strip_prefix('[') {
        let (host, tail) = after_open.split_once(']')?;
        if host.is_empty()
            || host.contains('[')
            || host.contains(']')
            || host.contains('%')
            || host.parse::<std::net::Ipv6Addr>().is_err()
        {
            return None;
        }
        if !tail.is_empty() && tail != ":" {
            let port_str = tail.strip_prefix(':')?;
            if port_str.is_empty() || !port_str.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            if port_str.parse::<u16>().ok()? == 0 {
                return None;
            }
        }
        return Some(host.to_ascii_lowercase());
    }

    if hostport.contains('[') || hostport.contains(']') {
        return None;
    }

    let raw_host = match hostport.split_once(':') {
        Some((h, p)) => {
            if p.contains(':') {
                return None;
            }
            if !p.is_empty() {
                if !p.bytes().all(|b| b.is_ascii_digit()) {
                    return None;
                }
                if p.parse::<u16>().ok()? == 0 {
                    return None;
                }
            }
            h
        }
        None => hostport,
    };

    let host = raw_host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() || host.contains('%') || host.bytes().any(|b| b.is_ascii_whitespace()) {
        return None;
    }
    Some(host)
}

fn host_matches_domain(host: &str, domain: &str) -> bool {
    host == domain
        || (host.len() > domain.len()
            && host.ends_with(domain)
            && host.as_bytes()[host.len() - domain.len() - 1] == b'.')
}

/// Returns a human-readable streaming service label when `url` requires the signed VMP/PlayReady
/// DRM engine (`Netflix`, `Disney+`, `Prime Video`, `Canal+`, `Apple TV+`, `Max`, etc.).
pub fn drm_service_label(url: &str) -> Option<&'static str> {
    let host = extract_http_host(url)?;
    for &(domain, label) in VMP_DRM_DOMAINS {
        if host_matches_domain(&host, domain) {
            return Some(label);
        }
    }
    None
}

/// Returns `true` if `url` is an `http://`/`https://` URL on a VMP/PlayReady-restricted streaming
/// domain (or any of its subdomains).
pub fn requires_vmp_drm_engine(url: &str) -> bool {
    drm_service_label(url).is_some()
}

/// Returns `true` if a tab navigating to `url` should run on the signed DRM engine:
/// strictly limited to `http://` and `https://` URLs when either `manually_pinned` is active
/// or `requires_vmp_drm_engine(url)` matches.
pub fn should_use_drm_engine(url: &str, manually_pinned: bool) -> bool {
    if extract_http_host(url).is_none() {
        return false;
    }
    manually_pinned || requires_vmp_drm_engine(url)
}

fn is_symlink_or_reparse(meta: &std::fs::Metadata) -> bool {
    if meta.file_type().is_symlink() {
        return true;
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        if (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            return true;
        }
    }
    false
}

fn ensure_safe_dir(path: &Path) -> bool {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => !is_symlink_or_reparse(&meta) && meta.is_dir(),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            if std::fs::create_dir_all(path).is_err() {
                return false;
            }
            std::fs::symlink_metadata(path)
                .map(|m| !is_symlink_or_reparse(&m) && m.is_dir())
                .unwrap_or(false)
        }
        Err(_) => false,
    }
}

fn atomic_write_regular_file(path: &Path, data: &[u8]) -> bool {
    let Some(parent) = path.parent() else {
        return false;
    };
    let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if is_symlink_or_reparse(&meta) || !meta.file_type().is_file() {
            return false;
        }
    }

    let seq = TMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp_path = parent.join(format!("{}.tmp.{}.{}", file_name, std::process::id(), seq));
    let mut file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp_path)
    {
        Ok(f) => f,
        Err(_) => return false,
    };

    if file.write_all(data).is_err() || file.sync_all().is_err() {
        drop(file);
        let _ = std::fs::remove_file(&tmp_path);
        return false;
    }
    drop(file);

    // Re-check target immediately before rename to avoid following a raced symlink.
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if is_symlink_or_reparse(&meta) || !meta.file_type().is_file() {
            let _ = std::fs::remove_file(&tmp_path);
            return false;
        }
    }

    if std::fs::rename(&tmp_path, path).is_err() {
        let _ = std::fs::remove_file(&tmp_path);
        return false;
    }
    true
}

/// Ensures `<cef_profile_dir>/Default/Preferences` enables
/// `profile.default_content_setting_values.protected_media_identifier = 1` (Allow)
/// without overwriting unrelated keys and without following any symlinks.
fn ensure_cef_preferences_protected_media(cef_profile_dir: &Path) -> bool {
    if !ensure_safe_dir(cef_profile_dir) {
        return false;
    }
    let default_dir = cef_profile_dir.join("Default");
    if !ensure_safe_dir(&default_dir) {
        return false;
    }
    let prefs_path = default_dir.join("Preferences");

    let mut root = match std::fs::symlink_metadata(&prefs_path) {
        Ok(meta) => {
            if is_symlink_or_reparse(&meta)
                || !meta.file_type().is_file()
                || meta.len() > MAX_PREFERENCES_BYTES
            {
                return false;
            }
            let Ok(raw) = std::fs::read_to_string(&prefs_path) else {
                return false;
            };
            let trimmed = raw.trim_start_matches('\u{feff}').trim();
            if trimmed.is_empty() {
                serde_json::Value::Object(serde_json::Map::new())
            } else {
                match serde_json::from_str::<serde_json::Value>(trimmed) {
                    Ok(v) if v.is_object() => v,
                    _ => return false,
                }
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            serde_json::Value::Object(serde_json::Map::new())
        }
        Err(_) => return false,
    };

    let Some(root_obj) = root.as_object_mut() else {
        return false;
    };
    let profile_val = root_obj
        .entry("profile".to_string())
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    let Some(profile_obj) = profile_val.as_object_mut() else {
        return false;
    };
    let dcsv_val = profile_obj
        .entry("default_content_setting_values".to_string())
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    let Some(dcsv_obj) = dcsv_val.as_object_mut() else {
        return false;
    };

    if dcsv_obj
        .get("protected_media_identifier")
        .and_then(|v| v.as_i64())
        == Some(1)
    {
        return true;
    }

    dcsv_obj.insert(
        "protected_media_identifier".to_string(),
        serde_json::Value::Number(1.into()),
    );

    let Ok(serialized) = serde_json::to_vec(&root) else {
        return false;
    };
    atomic_write_regular_file(&prefs_path, &serialized)
}

fn parse_numeric_version(raw: &str) -> Option<Vec<u64>> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 64 {
        return None;
    }
    let mut parts = Vec::new();
    for seg in trimmed.split('.') {
        if seg.is_empty() || !seg.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        parts.push(seg.parse::<u64>().ok()?);
    }
    if parts.len() < 2 {
        return None;
    }
    Some(parts)
}

fn is_valid_widevine_cdm_dir(dir: &Path) -> bool {
    let Ok(dir_meta) = std::fs::symlink_metadata(dir) else {
        return false;
    };
    if is_symlink_or_reparse(&dir_meta) || !dir_meta.is_dir() {
        return false;
    }

    let manifest = dir.join("manifest.json");
    let Ok(manifest_meta) = std::fs::symlink_metadata(&manifest) else {
        return false;
    };
    if is_symlink_or_reparse(&manifest_meta)
        || !manifest_meta.file_type().is_file()
        || manifest_meta.len() == 0
        || manifest_meta.len() > 1_048_576
    {
        return false;
    }

    let plat_dir = dir.join("_platform_specific");
    let Ok(plat_meta) = std::fs::symlink_metadata(&plat_dir) else {
        return false;
    };
    if is_symlink_or_reparse(&plat_meta) || !plat_meta.is_dir() {
        return false;
    }

    let arch_dir = plat_dir.join("win_x64");
    let Ok(arch_meta) = std::fs::symlink_metadata(&arch_dir) else {
        return false;
    };
    if is_symlink_or_reparse(&arch_meta) || !arch_meta.is_dir() {
        return false;
    }

    let dll_path = arch_dir.join("widevinecdm.dll");
    let Ok(dll_meta) = std::fs::symlink_metadata(&dll_path) else {
        return false;
    };
    !is_symlink_or_reparse(&dll_meta) && dll_meta.file_type().is_file() && dll_meta.len() > 0
}

fn read_manifest_version(dir: &Path) -> Option<(String, Vec<u64>)> {
    let manifest = dir.join("manifest.json");
    let meta = std::fs::symlink_metadata(&manifest).ok()?;
    if is_symlink_or_reparse(&meta) || !meta.file_type().is_file() || meta.len() > 1_048_576 {
        return None;
    }
    let raw = std::fs::read_to_string(&manifest).ok()?;
    let val: serde_json::Value = serde_json::from_str(raw.trim_start_matches('\u{feff}')).ok()?;
    let ver_str = val.get("version")?.as_str()?.trim().to_string();
    let parsed = parse_numeric_version(&ver_str)?;
    Some((ver_str, parsed))
}

fn find_newest_widevine_candidate(roots: &[PathBuf]) -> Option<(String, PathBuf)> {
    let mut best: Option<(Vec<u64>, String, PathBuf)> = None;

    let mut consider = |ver_str: String, parsed: Vec<u64>, dir: PathBuf| {
        if !is_valid_widevine_cdm_dir(&dir) {
            return;
        }
        let replace = match best.as_ref() {
            Some((best_ver, _, _)) => parsed > *best_ver,
            None => true,
        };
        if replace {
            best = Some((parsed, ver_str, dir));
        }
    };

    for root in roots {
        let Ok(root_meta) = std::fs::symlink_metadata(root) else {
            continue;
        };
        if is_symlink_or_reparse(&root_meta) || !root_meta.is_dir() {
            continue;
        }

        // Bundled layout (e.g. Chrome Application/<ver>/WidevineCdm/manifest.json)
        if is_valid_widevine_cdm_dir(root) {
            if let Some((ver_str, parsed)) = read_manifest_version(root) {
                consider(ver_str, parsed, root.clone());
            }
        }

        // Component-updated layout (e.g. User Data/WidevineCdm/<cdm_ver>/manifest.json)
        let Ok(entries) = std::fs::read_dir(root) else {
            continue;
        };
        for entry in entries.flatten() {
            let p = entry.path();
            let Ok(meta) = std::fs::symlink_metadata(&p) else {
                continue;
            };
            if is_symlink_or_reparse(&meta) || !meta.is_dir() {
                continue;
            }
            let Some(name) = p.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if let Some(parsed) = parse_numeric_version(name) {
                consider(name.to_string(), parsed, p);
            }
        }
    }

    best.map(|(_, ver_str, dir)| (ver_str, dir))
}

#[cfg(target_os = "windows")]
fn strip_win_verbatim_prefix(path: &Path) -> String {
    let raw = path.to_string_lossy();
    if let Some(unc) = raw.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{}", unc)
    } else if let Some(stripped) = raw.strip_prefix(r"\\?\") {
        stripped.to_string()
    } else {
        raw.into_owned()
    }
}

#[cfg(target_os = "windows")]
fn copy_widevine_tree_no_symlinks(
    src: &Path,
    dst: &Path,
    depth: usize,
    files_copied: &mut usize,
) -> bool {
    const MAX_DEPTH: usize = 4;
    const MAX_FILES: usize = 64;
    const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;

    if depth > MAX_DEPTH || !ensure_safe_dir(dst) {
        return false;
    }
    let Ok(src_meta) = std::fs::symlink_metadata(src) else {
        return false;
    };
    if is_symlink_or_reparse(&src_meta) || !src_meta.is_dir() {
        return false;
    }

    let Ok(entries) = std::fs::read_dir(src) else {
        return false;
    };
    for entry in entries.flatten() {
        let src_path = entry.path();
        let Ok(meta) = std::fs::symlink_metadata(&src_path) else {
            return false;
        };
        if is_symlink_or_reparse(&meta) {
            return false;
        }
        let Some(name) = src_path.file_name() else {
            return false;
        };
        let dst_path = dst.join(name);

        if meta.is_dir() {
            if !copy_widevine_tree_no_symlinks(&src_path, &dst_path, depth + 1, files_copied) {
                return false;
            }
        } else if meta.file_type().is_file() {
            use std::io::Read;
            if *files_copied >= MAX_FILES || meta.len() > MAX_FILE_BYTES {
                return false;
            }
            let copy_ok = {
                let Ok(reader) = std::fs::File::open(&src_path) else {
                    return false;
                };
                let Ok(mut writer) = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&dst_path)
                else {
                    return false;
                };
                let mut limited = reader.take(MAX_FILE_BYTES + 1);
                match std::io::copy(&mut limited, &mut writer) {
                    Ok(copied) if copied <= MAX_FILE_BYTES => writer.sync_all().is_ok(),
                    _ => false,
                }
            };
            if !copy_ok {
                let _ = std::fs::remove_file(&dst_path);
                return false;
            }
            *files_copied += 1;
        } else {
            return false;
        }
    }
    true
}

#[cfg(target_os = "windows")]
fn collect_windows_widevine_search_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
        let base = PathBuf::from(local_app_data);
        roots.push(base.join("Google").join("Chrome").join("User Data").join("WidevineCdm"));
        roots.push(base.join("Microsoft").join("Edge").join("User Data").join("WidevineCdm"));
        roots.push(
            base.join("BraveSoftware")
                .join("Brave-Browser")
                .join("User Data")
                .join("WidevineCdm"),
        );
    }

    if let Ok(program_files) = std::env::var("ProgramFiles") {
        let chrome_app = PathBuf::from(program_files)
            .join("Google")
            .join("Chrome")
            .join("Application");
        if let Ok(app_meta) = std::fs::symlink_metadata(&chrome_app) {
            if !is_symlink_or_reparse(&app_meta) && app_meta.is_dir() {
                if let Ok(entries) = std::fs::read_dir(&chrome_app) {
                    for entry in entries.flatten() {
                        let p = entry.path();
                        let Ok(meta) = std::fs::symlink_metadata(&p) else {
                            continue;
                        };
                        if is_symlink_or_reparse(&meta) || !meta.is_dir() {
                            continue;
                        }
                        let cand = p.join("WidevineCdm");
                        if let Ok(cm) = std::fs::symlink_metadata(&cand) {
                            if !is_symlink_or_reparse(&cm) && cm.is_dir() {
                                roots.push(cand);
                            }
                        }
                    }
                }
            }
        }
    }

    roots
}

fn resolve_valid_cef_widevine_hint_dir(widevine_root: &Path) -> Option<PathBuf> {
    let root_meta = std::fs::symlink_metadata(widevine_root).ok()?;
    if is_symlink_or_reparse(&root_meta) || !root_meta.is_dir() {
        return None;
    }
    let canon_root = std::fs::canonicalize(widevine_root).ok()?;

    let hint_path = widevine_root.join("latest-component-updated-widevine-cdm");
    let meta = std::fs::symlink_metadata(&hint_path).ok()?;
    if is_symlink_or_reparse(&meta) || !meta.file_type().is_file() || meta.len() > 65_536 {
        return None;
    }
    let raw = std::fs::read_to_string(&hint_path).ok()?;
    let val = serde_json::from_str::<serde_json::Value>(raw.trim_start_matches('\u{feff}')).ok()?;
    let path_str = val.get("Path").and_then(|v| v.as_str())?;
    if path_str.trim().is_empty() {
        return None;
    }

    let candidate = Path::new(path_str);
    let cand_meta = std::fs::symlink_metadata(candidate).ok()?;
    if is_symlink_or_reparse(&cand_meta) || !cand_meta.is_dir() {
        return None;
    }
    let canon_candidate = std::fs::canonicalize(candidate).ok()?;
    // Strictly confine the hint `Path` beneath the canonical `widevine_root` directory.
    if !canon_candidate.starts_with(&canon_root) {
        return None;
    }
    if !is_valid_widevine_cdm_dir(&canon_candidate) {
        return None;
    }
    Some(canon_candidate)
}

fn existing_cef_widevine_is_valid(widevine_root: &Path) -> bool {
    resolve_valid_cef_widevine_hint_dir(widevine_root).is_some()
}

#[cfg(target_os = "windows")]
fn bootstrap_windows_cef_widevine_cdm(cef_profile_dir: &Path) -> bool {
    if !ensure_safe_dir(cef_profile_dir) {
        return false;
    }
    let widevine_root = cef_profile_dir.join("WidevineCdm");
    if existing_cef_widevine_is_valid(&widevine_root) {
        return true;
    }

    let search_roots = collect_windows_widevine_search_roots();
    let Some((ver_str, src_dir)) = find_newest_widevine_candidate(&search_roots) else {
        return false;
    };

    if !ensure_safe_dir(&widevine_root) {
        return false;
    }

    let target_ver_dir = widevine_root.join(&ver_str);
    if !is_valid_widevine_cdm_dir(&target_ver_dir) {
        if let Ok(meta) = std::fs::symlink_metadata(&target_ver_dir) {
            if is_symlink_or_reparse(&meta) {
                return false;
            }
        }
        let seq = TMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let staging_dir = widevine_root.join(format!(
            ".staging-{}-{}-{}",
            ver_str,
            std::process::id(),
            seq
        ));
        if let Ok(meta) = std::fs::symlink_metadata(&staging_dir) {
            if is_symlink_or_reparse(&meta) {
                return false;
            }
            let _ = std::fs::remove_dir_all(&staging_dir);
        }

        let mut files_copied = 0usize;
        let copied = copy_widevine_tree_no_symlinks(&src_dir, &staging_dir, 0, &mut files_copied)
            && is_valid_widevine_cdm_dir(&staging_dir);
        if !copied {
            let _ = std::fs::remove_dir_all(&staging_dir);
            return false;
        }

        if let Ok(meta) = std::fs::symlink_metadata(&target_ver_dir) {
            if is_symlink_or_reparse(&meta) {
                let _ = std::fs::remove_dir_all(&staging_dir);
                return false;
            }
            if meta.is_dir() {
                if std::fs::remove_dir_all(&target_ver_dir).is_err() {
                    let _ = std::fs::remove_dir_all(&staging_dir);
                    return false;
                }
            } else if std::fs::remove_file(&target_ver_dir).is_err() {
                let _ = std::fs::remove_dir_all(&staging_dir);
                return false;
            }
        }

        if std::fs::rename(&staging_dir, &target_ver_dir).is_err() {
            let _ = std::fs::remove_dir_all(&staging_dir);
            return false;
        }
    }

    let abs_ver_dir = std::fs::canonicalize(&target_ver_dir).unwrap_or(target_ver_dir);
    let clean_abs = strip_win_verbatim_prefix(&abs_ver_dir);
    let hint_json = serde_json::json!({ "Path": clean_abs });
    let Ok(bytes) = serde_json::to_vec(&hint_json) else {
        return false;
    };
    let hint_path = widevine_root.join("latest-component-updated-widevine-cdm");
    atomic_write_regular_file(&hint_path, &bytes)
}

/// Prepares the Chromium CEF profile for Widevine CDM playback:
/// 1. Sets `profile.default_content_setting_values.protected_media_identifier = 1` in
///    `<cef_profile_dir>/Default/Preferences` without clobbering existing JSON keys.
/// 2. On Windows, verifies or atomically seeds `<cef_profile_dir>/WidevineCdm` from an existing
///    Chrome, Edge, or Brave Widevine CDM directory (refusing symlinks throughout).
///
/// Returns `true` if Widevine CDM is ready/present or if the protected media preference was
/// successfully configured.
pub fn ensure_cef_widevine_ready(cef_profile_dir: &Path) -> bool {
    let prefs_ok = ensure_cef_preferences_protected_media(cef_profile_dir);
    #[cfg(target_os = "windows")]
    {
        let cdm_ok = bootstrap_windows_cef_widevine_cdm(cef_profile_dir);
        cdm_ok || prefs_ok
    }
    #[cfg(not(target_os = "windows"))]
    {
        prefs_ok
    }
}

/// Removes `<roaming_root>/drm-webview2/` cleanly if present, refusing to follow symlinks.
pub fn clear_drm_webview_storage(roaming_root: &Path) {
    if let Ok(root_meta) = std::fs::symlink_metadata(roaming_root) {
        if is_symlink_or_reparse(&root_meta) || !root_meta.is_dir() {
            return;
        }
    } else {
        return;
    }

    let storage_dir = roaming_root.join("drm-webview2");
    if let Ok(meta) = std::fs::symlink_metadata(&storage_dir) {
        if is_symlink_or_reparse(&meta) {
            return;
        }
        if meta.is_dir() {
            let _ = std::fs::remove_dir_all(&storage_dir);
        }
    }
}

#[cfg(target_os = "windows")]
mod windows_drm {
    use super::*;
    use crate::cef_runtime::{
        is_blocked_local_ipc_url, is_dangerous_download_name, is_dangerous_download_url,
        CefCallbackEvent, CefEventSink,
    };
    use std::sync::atomic::AtomicBool;
    use std::sync::{Arc, Mutex};
    use wry::{WebViewBuilderExtWindows, WebViewExtWindows};

    /// Fail-closed navigation policy callback evaluated on every navigation and new-window request
    /// (enforces Kill-Switch, Lockdown, and ad/tracker filtering before WebView2 connects).
    pub type DrmNavigationPolicyFn = Arc<dyn Fn(&str) -> bool + Send + Sync>;

    /// Normalizes HTTP(S)/WS(S) scheme prefixes to lowercase `http://`/`https://` so
    /// `check_navigation_policy` (which requires lowercase `http://`/`https://`) enforces
    /// Mullvad Kill-Switch, Emergency Lockdown, and Adblocker uniformly across subresources & WS.
    fn normalize_drm_policy_url(trimmed: &str) -> Option<String> {
        if let Some(rest) = strip_prefix_ignore_ascii_case(trimmed, "https://") {
            Some(format!("https://{rest}"))
        } else if let Some(rest) = strip_prefix_ignore_ascii_case(trimmed, "http://") {
            Some(format!("http://{rest}"))
        } else if let Some(rest) = strip_prefix_ignore_ascii_case(trimmed, "wss://") {
            Some(format!("https://{rest}"))
        } else if let Some(rest) = strip_prefix_ignore_ascii_case(trimmed, "ws://") {
            Some(format!("http://{rest}"))
        } else {
            None
        }
    }

    /// Fail-closed gate for WebView2 `<iframe>` navigations (`add_FrameNavigationStarting`) and
    /// subresource requests (`add_WebResourceRequested`).
    /// Blocks `file://`, local loopback IPC, unknown schemes, and any HTTP(S)/WS(S) target denied
    /// by `nav_policy` (Mullvad Kill-Switch, Emergency Lockdown, Adblocker), while preserving
    /// non-network in-memory schemes (`about:blank`, `about:srcdoc`, `data:`, `blob:`, `javascript:`)
    /// needed by signed MSE/EME streaming players after `is_blocked_local_ipc_url` screening.
    pub(super) fn is_allowed_drm_frame_or_resource_url(
        url: &str,
        bind_port: u16,
        nav_policy: &DrmNavigationPolicyFn,
    ) -> bool {
        let trimmed = url.trim();
        if trimmed.is_empty()
            || trimmed.bytes().any(|b| b < 0x20 || b == 0x7F)
            || strip_prefix_ignore_ascii_case(trimmed, "file:").is_some()
            || is_blocked_local_ipc_url(trimmed, bind_port)
        {
            return false;
        }
        if trimmed.eq_ignore_ascii_case("about:blank")
            || trimmed.eq_ignore_ascii_case("about:srcdoc")
            || strip_prefix_ignore_ascii_case(trimmed, "data:").is_some()
            || strip_prefix_ignore_ascii_case(trimmed, "blob:").is_some()
            || strip_prefix_ignore_ascii_case(trimmed, "javascript:").is_some()
        {
            return true;
        }
        match normalize_drm_policy_url(trimmed) {
            Some(policy_url) => (nav_policy)(&policy_url),
            None => false,
        }
    }

    /// Fail-closed gate for downloads initiated inside a WebView2 DRM tab
    /// (invoked via `ICoreWebView2_4::add_DownloadStarting` through `with_download_started_handler`).
    /// Blocks loopback/local-IPC/file downloads, non-HTTP(S) smuggling (`blob:`/`data:`),
    /// `nav_policy` denials (Kill-Switch/Lockdown/Adblocker), and dangerous executable extensions.
    pub(super) fn is_allowed_drm_download(
        dl_url: &str,
        dest_path: &Path,
        bind_port: u16,
        nav_policy: &DrmNavigationPolicyFn,
    ) -> bool {
        let trimmed = dl_url.trim();
        if trimmed.is_empty()
            || trimmed.bytes().any(|b| b < 0x20 || b == 0x7F)
            || strip_prefix_ignore_ascii_case(trimmed, "file:").is_some()
            || is_blocked_local_ipc_url(trimmed, bind_port)
        {
            return false;
        }
        if extract_http_host(trimmed).is_none() {
            return false;
        }
        let Some(policy_url) = normalize_drm_policy_url(trimmed) else {
            return false;
        };
        if !(nav_policy)(&policy_url) {
            return false;
        }
        if is_dangerous_download_url(trimmed) {
            return false;
        }
        if let Some(file_name) = dest_path.file_name().and_then(|n| n.to_str()) {
            if is_dangerous_download_name(file_name) {
                return false;
            }
        }
        true
    }

    /// Shared WebView2 browser context backed by `<roaming_root>/drm-webview2`.
    pub type DrmWebContext = wry::WebContext;

    /// Creates a shared `DrmWebContext` backed by `<roaming_root>/drm-webview2`.
    pub fn create_drm_web_context(roaming_root: &Path) -> DrmWebContext {
        let data_dir = roaming_root.join("drm-webview2");
        if ensure_safe_dir(roaming_root) {
            let _ = ensure_safe_dir(&data_dir);
        }
        wry::WebContext::new(Some(data_dir))
    }

    /// Embedded Windows WebView2 child browser used exclusively for signed VMP/PlayReady DRM tabs.
    /// Never exposes `window.ipc` to web content.
    pub struct DrmWebViewHandle {
        webview: wry::WebView,
        zoom_factor: std::sync::atomic::AtomicU64,
        last_url: Arc<Mutex<String>>,
        can_back: Arc<AtomicBool>,
        can_fwd: Arc<AtomicBool>,
        muted: AtomicBool,
    }

    impl DrmWebViewHandle {
        #[allow(clippy::too_many_arguments)]
        pub fn spawn(
            window: &tao::window::Window,
            web_context: &mut wry::WebContext,
            x: i32,
            y: i32,
            w: u32,
            h: u32,
            url: &str,
            tab_id: u64,
            bind_port: u16,
            is_private: bool,
            sink: CefEventSink,
            nav_policy: DrmNavigationPolicyFn,
        ) -> Result<Self, String> {
            // Fail-closed validation of the initial URL before creating any child WebView2.
            if is_blocked_local_ipc_url(url, bind_port) || !(nav_policy)(url) {
                return Err("Navigation blocked by Singularity DRM security policy".into());
            }

            let last_url = Arc::new(Mutex::new(url.to_string()));
            let can_back = Arc::new(AtomicBool::new(false));
            let can_fwd = Arc::new(AtomicBool::new(false));

            let nav_sink = Arc::clone(&sink);
            let nav_last_url = Arc::clone(&last_url);
            let nav_policy_cb = Arc::clone(&nav_policy);

            let nw_sink = Arc::clone(&sink);
            let nw_policy_cb = Arc::clone(&nav_policy);
            let dl_policy_cb = Arc::clone(&nav_policy);

            let pl_sink = Arc::clone(&sink);
            let pl_last_url = Arc::clone(&last_url);
            let pl_can_back = Arc::clone(&can_back);
            let pl_can_fwd = Arc::clone(&can_fwd);

            let title_sink = Arc::clone(&sink);

            // SECURITY (N4 #4): Do NOT register any JS IPC bridge — never expose `window.ipc` to web pages!
            let webview = wry::WebViewBuilder::new_with_web_context(web_context)
                .with_bounds(wry::Rect {
                    position: wry::dpi::PhysicalPosition::new(x, y).into(),
                    size: wry::dpi::PhysicalSize::new(w.max(1), h.max(1)).into(),
                })
                .with_visible(false)
                .with_focused(false)
                .with_background_color((0, 0, 0, 255))
                .with_theme(wry::Theme::Dark)
                .with_autoplay(true)
                .with_incognito(is_private)
                .with_devtools(cfg!(debug_assertions))
                .with_url(url)
                .with_navigation_handler(move |nav_url| {
                    let trimmed = nav_url.trim();
                    if strip_prefix_ignore_ascii_case(trimmed, "file:").is_some()
                        || is_blocked_local_ipc_url(&nav_url, bind_port)
                        || !(nav_policy_cb)(&nav_url)
                    {
                        return false;
                    }
                    if extract_http_host(&nav_url).is_some() {
                        if let Ok(mut guard) = nav_last_url.lock() {
                            *guard = nav_url.clone();
                        }
                        (nav_sink)(CefCallbackEvent::AddressChanged {
                            tab_id,
                            url: nav_url,
                        });
                    }
                    true
                })
                .with_new_window_req_handler(move |req_url, _features| {
                    if extract_http_host(&req_url).is_some()
                        && !is_blocked_local_ipc_url(&req_url, bind_port)
                        && (nw_policy_cb)(&req_url)
                    {
                        (nw_sink)(CefCallbackEvent::OpenNewTab {
                            url: req_url,
                            background: false,
                            from_ui: false,
                        });
                    }
                    wry::NewWindowResponse::Deny
                })
                .with_on_page_load_handler(move |event, load_url| {
                    if extract_http_host(&load_url).is_some() {
                        if let Ok(mut guard) = pl_last_url.lock() {
                            *guard = load_url.clone();
                        }
                        match event {
                            wry::PageLoadEvent::Started => {
                                (pl_sink)(CefCallbackEvent::PageStarted {
                                    tab_id,
                                    url: load_url,
                                });
                            }
                            wry::PageLoadEvent::Finished => {
                                (pl_sink)(CefCallbackEvent::PageFinished {
                                    tab_id,
                                    url: load_url,
                                    http_status: 200,
                                });
                                (pl_sink)(CefCallbackEvent::NavigationStateChanged {
                                    tab_id,
                                    can_go_back: pl_can_back.load(Ordering::Acquire),
                                    can_go_forward: pl_can_fwd.load(Ordering::Acquire),
                                });
                            }
                        }
                    }
                })
                .with_document_title_changed_handler(move |title| {
                    if !title.is_empty() {
                        (title_sink)(CefCallbackEvent::TitleChanged { tab_id, title });
                    }
                })
                // Registers `ICoreWebView2_4::add_DownloadStarting` natively via `wry`:
                // cancels loopback/IPC, Kill-Switch/Lockdown/Adblocker, non-HTTP(S), and dangerous downloads.
                .with_download_started_handler(move |dl_url, dest_path| {
                    is_allowed_drm_download(&dl_url, dest_path.as_path(), bind_port, &dl_policy_cb)
                })
                .build_as_child(window)
                .map_err(|e| format!("Failed to spawn DRM WebView2 tab: {}", e))?;

            // Attach native WebView2 COM handlers directly on `ICoreWebView2` (zero JS injection!).
            let core_wv = webview.webview();
            let core_env = webview.environment();
            unsafe {
                if let Ok(settings) = core_wv.Settings() {
                    let _ = settings.SetIsStatusBarEnabled(false);
                }

                // 1. Subframe (`<iframe>`) navigation filter enforcing local-IPC guard + `nav_policy`
                //    (Mullvad Kill-Switch, Emergency Lockdown, Singularity Shield adblocker).
                let frame_policy_cb = Arc::clone(&nav_policy);
                let mut frame_nav_token: i64 = 0;
                let frame_nav_handler =
                    webview2_com::NavigationStartingEventHandler::create(Box::new(
                        move |_sender, args| {
                            if let Some(args) = args {
                                let mut uri_pwstr = Default::default();
                                let allowed = if args.Uri(&mut uri_pwstr).is_ok() {
                                    let frame_url = webview2_com::take_pwstr(uri_pwstr);
                                    is_allowed_drm_frame_or_resource_url(
                                        &frame_url,
                                        bind_port,
                                        &frame_policy_cb,
                                    )
                                } else {
                                    false
                                };
                                if !allowed {
                                    let _ = args.SetCancel(true);
                                }
                            }
                            Ok(())
                        },
                    ));
                let _ = core_wv.add_FrameNavigationStarting(&frame_nav_handler, &mut frame_nav_token);

                // 2. Network-layer subresource filter across ALL resource contexts (fetch, XHR,
                //    scripts, media, images, iframes, WebSockets) — short-circuits disallowed
                //    requests with a synthetic 403 before WebView2 opens any socket.
                let wildcard_filter = webview2_com::CoTaskMemPWSTR::from("*");
                let _ = core_wv.AddWebResourceRequestedFilter(
                    *wildcard_filter.as_ref().as_pcwstr(),
                    webview2_com::Microsoft::Web::WebView2::Win32::COREWEBVIEW2_WEB_RESOURCE_CONTEXT_ALL,
                );
                let res_policy_cb = Arc::clone(&nav_policy);
                let mut res_token: i64 = 0;
                let res_handler = webview2_com::WebResourceRequestedEventHandler::create(Box::new(
                    move |_sender, args| {
                        if let Some(args) = args {
                            let allowed = match args.Request() {
                                Ok(req) => {
                                    let mut uri_pwstr = Default::default();
                                    if req.Uri(&mut uri_pwstr).is_ok() {
                                        let req_url = webview2_com::take_pwstr(uri_pwstr);
                                        is_allowed_drm_frame_or_resource_url(
                                            &req_url,
                                            bind_port,
                                            &res_policy_cb,
                                        )
                                    } else {
                                        false
                                    }
                                }
                                Err(_) => false,
                            };
                            if !allowed {
                                let reason = webview2_com::CoTaskMemPWSTR::from(
                                    "Blocked by Singularity Policy",
                                );
                                let headers = webview2_com::CoTaskMemPWSTR::from(
                                    "Content-Type: text/plain; charset=utf-8\r\nCache-Control: no-store",
                                );
                                if let Ok(resp) = core_env.CreateWebResourceResponse(
                                    None,
                                    403,
                                    *reason.as_ref().as_pcwstr(),
                                    *headers.as_ref().as_pcwstr(),
                                ) {
                                    let _ = args.SetResponse(&resp);
                                }
                            }
                        }
                        Ok(())
                    },
                ));
                let _ = core_wv.add_WebResourceRequested(&res_handler, &mut res_token);

                let fs_sink = Arc::clone(&sink);
                let mut fs_token: i64 = 0;
                let fs_handler = webview2_com::ContainsFullScreenElementChangedEventHandler::create(
                    Box::new(move |sender, _| {
                        if let Some(wv) = sender {
                            let mut is_fs = Default::default();
                            if wv.ContainsFullScreenElement(&mut is_fs).is_ok() {
                                (fs_sink)(CefCallbackEvent::FullscreenChanged {
                                    tab_id,
                                    enabled: is_fs.as_bool(),
                                });
                            }
                        }
                        Ok(())
                    }),
                );
                let _ = core_wv.add_ContainsFullScreenElementChanged(&fs_handler, &mut fs_token);

                let hist_sink = Arc::clone(&sink);
                let hist_back = Arc::clone(&can_back);
                let hist_fwd = Arc::clone(&can_fwd);
                let hist_last_url = Arc::clone(&last_url);
                let mut hist_token: i64 = 0;
                let hist_handler =
                    webview2_com::HistoryChangedEventHandler::create(Box::new(move |sender, _| {
                        if let Some(wv) = sender {
                            let mut b = Default::default();
                            let mut f = Default::default();
                            let back_ok = wv.CanGoBack(&mut b).is_ok() && b.as_bool();
                            let fwd_ok = wv.CanGoForward(&mut f).is_ok() && f.as_bool();
                            hist_back.store(back_ok, Ordering::Release);
                            hist_fwd.store(fwd_ok, Ordering::Release);
                            (hist_sink)(CefCallbackEvent::NavigationStateChanged {
                                tab_id,
                                can_go_back: back_ok,
                                can_go_forward: fwd_ok,
                            });

                            // Keep address bar in sync across SPA `history.pushState` transitions
                            // (Netflix, Disney+, Prime Video, Canal+, Max).
                            let mut src_pwstr = Default::default();
                            if wv.Source(&mut src_pwstr).is_ok() {
                                let src = webview2_com::take_pwstr(src_pwstr);
                                if extract_http_host(&src).is_some() {
                                    let changed = hist_last_url
                                        .lock()
                                        .map(|mut g| {
                                            if *g != src {
                                                *g = src.clone();
                                                true
                                            } else {
                                                false
                                            }
                                        })
                                        .unwrap_or(false);
                                    if changed {
                                        (hist_sink)(CefCallbackEvent::AddressChanged {
                                            tab_id,
                                            url: src,
                                        });
                                    }
                                }
                            }
                        }
                        Ok(())
                    }));
                let _ = core_wv.add_HistoryChanged(&hist_handler, &mut hist_token);
            }

            Ok(Self {
                webview,
                zoom_factor: std::sync::atomic::AtomicU64::new(1.0_f64.to_bits()),
                last_url,
                can_back,
                can_fwd,
                muted: AtomicBool::new(false),
            })
        }

        pub fn set_bounds(&self, x: i32, y: i32, w: u32, h: u32) -> bool {
            let rect = wry::Rect {
                position: wry::dpi::PhysicalPosition::new(x, y).into(),
                size: wry::dpi::PhysicalSize::new(w.max(1), h.max(1)).into(),
            };
            self.webview.set_bounds(rect).is_ok()
        }

        pub fn set_visible(&self, visible: bool) -> bool {
            self.webview.set_visible(visible).is_ok()
        }

        pub fn focus(&self) {
            let _ = self.webview.focus();
        }

        pub fn load_url(&self, url: &str) {
            let _ = self.webview.load_url(url);
        }

        pub fn url(&self) -> Option<String> {
            if let Ok(current) = self.webview.url() {
                if !current.is_empty() {
                    if let Ok(mut guard) = self.last_url.lock() {
                        *guard = current.clone();
                    }
                    return Some(current);
                }
            }
            self.last_url
                .lock()
                .ok()
                .filter(|u| !u.is_empty())
                .map(|u| u.clone())
        }

        pub fn evaluate_script(&self, js: &str) {
            let _ = self.webview.evaluate_script(js);
        }

        pub fn reload(&self) {
            let _ = self.webview.reload();
        }

        pub fn can_go_back(&self) -> bool {
            if let Ok(val) = self.webview.can_go_back() {
                self.can_back.store(val, Ordering::Release);
                return val;
            }
            self.can_back.load(Ordering::Acquire)
        }

        pub fn can_go_forward(&self) -> bool {
            if let Ok(val) = self.webview.can_go_forward() {
                self.can_fwd.store(val, Ordering::Release);
                return val;
            }
            self.can_fwd.load(Ordering::Acquire)
        }

        pub fn go_back(&self) -> bool {
            if self.can_go_back() {
                self.webview.go_back().is_ok()
            } else {
                false
            }
        }

        pub fn go_forward(&self) -> bool {
            if self.can_go_forward() {
                self.webview.go_forward().is_ok()
            } else {
                false
            }
        }

        pub fn zoom_step(&self, delta: f64) -> i32 {
            let cur = f64::from_bits(self.zoom_factor.load(Ordering::Acquire));
            let safe_cur = if cur.is_finite() && cur > 0.0 { cur } else { 1.0 };
            if !delta.is_finite() {
                return (safe_cur * 100.0).round() as i32;
            }
            // Match CEF's logarithmic 1.2^level zoom curve so +/-0.5 steps yield identical %.
            let cur_level = safe_cur.max(0.25).log(1.2);
            let mut next_level = (cur_level + delta).clamp(-4.0, 5.0);
            if next_level.abs() < 0.05 {
                next_level = 0.0;
            }
            let next_factor = 1.2_f64.powf(next_level);
            self.zoom_factor
                .store(next_factor.to_bits(), Ordering::Release);
            let _ = self.webview.zoom(next_factor);
            (next_factor * 100.0).round() as i32
        }

        pub fn zoom_reset(&self) -> i32 {
            self.zoom_factor
                .store(1.0_f64.to_bits(), Ordering::Release);
            let _ = self.webview.zoom(1.0);
            100
        }

        pub fn close_force(&self) {
            let _ = self.webview.set_visible(false);
            let _ = unsafe { self.webview.controller().Close() };
        }

        pub fn open_devtools(&self) {
            unsafe {
                let _ = self.webview.webview().OpenDevToolsWindow();
            }
        }

        pub fn set_audio_muted(&self, muted: bool) -> bool {
            self.muted.store(muted, Ordering::Release);
            let flag = if muted { "true" } else { "false" };
            let js = format!(
                "(function(){{try{{document.querySelectorAll('video,audio').forEach(function(m){{m.muted={};}});}}catch(_e){{}}}})();",
                flag
            );
            self.webview.evaluate_script(&js).is_ok()
        }

        pub fn is_audio_muted(&self) -> bool {
            self.muted.load(Ordering::Acquire)
        }
    }

    impl Drop for DrmWebViewHandle {
        fn drop(&mut self) {
            let _ = self.webview.set_visible(false);
        }
    }
}

#[cfg(target_os = "windows")]
pub use windows_drm::{
    create_drm_web_context, DrmNavigationPolicyFn, DrmWebContext, DrmWebViewHandle,
};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DrmSitePolicy {
    pub domain: String,
    pub allow_protected_content: bool,
    pub force_signed_drm_engine: bool,
    pub allow_hardware_playready: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WidevineStatusReport {
    pub cef_widevine_ready: bool,
    pub detected_version: Option<String>,
    pub cdm_path: Option<String>,
    pub supported_vmp_domains_count: usize,
    pub playready_hybrid_available: bool,
}

/// Inspects either the Singularity roaming root (`<dir>/cef-profile`) or a direct CEF profile
/// directory (`<dir>`) and reports Widevine CDM readiness for `browser://components` and
/// `browser://media-internals`.
pub fn inspect_widevine_status(cef_profile_dir: &Path) -> WidevineStatusReport {
    let direct_root = cef_profile_dir.join("WidevineCdm");
    let nested_root = cef_profile_dir.join("cef-profile").join("WidevineCdm");

    let mut ready_dir: Option<PathBuf> = None;
    let mut detected_version: Option<String> = None;

    for cdm_root in [&direct_root, &nested_root] {
        if existing_cef_widevine_is_valid(cdm_root) {
            if let Some(valid_dir) = resolve_valid_cef_widevine_hint_dir(cdm_root) {
                if let Some((ver, _)) = read_manifest_version(&valid_dir) {
                    detected_version = Some(ver);
                    ready_dir = Some(valid_dir);
                    break;
                }
            }
        } else if std::fs::symlink_metadata(
            cdm_root.join("latest-component-updated-widevine-cdm"),
        )
        .is_err()
        {
            if let Some((ver, valid_dir)) = find_newest_widevine_candidate(&[cdm_root.clone()]) {
                if read_manifest_version(&valid_dir).is_some() {
                    detected_version = Some(ver);
                    ready_dir = Some(valid_dir);
                    break;
                }
            }
        }
    }

    let cdm_path = ready_dir
        .as_ref()
        .map(|p| {
            #[cfg(target_os = "windows")]
            {
                strip_win_verbatim_prefix(p)
            }
            #[cfg(not(target_os = "windows"))]
            {
                p.to_string_lossy().to_string()
            }
        })
        .or_else(|| {
            if nested_root.is_dir() {
                Some(nested_root.to_string_lossy().to_string())
            } else if direct_root.is_dir() {
                Some(direct_root.to_string_lossy().to_string())
            } else {
                None
            }
        });

    WidevineStatusReport {
        cef_widevine_ready: ready_dir.is_some() && detected_version.is_some(),
        detected_version,
        cdm_path,
        supported_vmp_domains_count: VMP_DRM_DOMAINS.len(),
        playready_hybrid_available: cfg!(target_os = "windows"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_test_dir(tag: &str) -> PathBuf {
        let seq = TMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "singularity_drm_test_{}_{}_{}",
            tag,
            std::process::id(),
            seq
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp test dir");
        dir
    }

    #[test]
    fn test_requires_vmp_drm_engine_classification_and_edge_cases() {
        // Exact apex domains, subdomains, ports, uppercase, userinfo, trailing dot
        let positives = [
            "https://netflix.com/browse",
            "https://www.netflix.com/watch/80100172",
            "HTTPS://APP.DISNEYPLUS.COM:443/en-us/home",
            "http://www.primevideo.com./detail/abc",
            "https://user:pass@canalplus.com/live",
            "https://www.mycanal.fr/chaines",
            "https://tv.apple.com/us/show/severance",
            "https://play.max.com/video",
            "https://play.hbomax.com/page",
            "https://www.paramountplus.com/shows/",
            "https://www.hulu.com/hub/home",
            "https://www.peacocktv.com/watch",
            "https://www.dazn.com/en-FR/home",
            "https://app.molotov.tv/home",
            "https://www.france.tv/france-2/direct.html",
            "https://www.tf1.fr/tf1/direct",
            "https://www.m6plus.m6.fr/direct",
            "https://play.discoveryplus.com/",
            "https://www.hotstar.com/in",
            "https://www.starplus.com/",
            "https://www.rakuten.tv/fr",
            "https://www.fubo.tv/welcome",
            "https://watch.sling.com/",
            "https://www.crunchyroll.com/watch/GR751KNZY",
        ];
        for url in positives {
            assert!(
                requires_vmp_drm_engine(url),
                "expected VMP DRM engine for {}",
                url
            );
        }

        // Non-DRM, spoofed domains, non-HTTP schemes, local addresses, malformed URLs
        let negatives = [
            "https://youtube.com/watch?v=dQw4w9WgXcQ",
            "https://github.com/MyMasha/Singularity",
            "https://apple.com/iphone",
            "https://evilnetflix.com/watch",
            "https://netflix.com.evil.org/watch",
            "https://m6.fr/",
            "file:///netflix.com/index.html",
            "javascript://netflix.com/%0aalert(1)",
            "about:blank",
            "singularity://settings",
            "chrome-extension://abcdefghijklmnop/popup.html",
            "http://127.0.0.1:8080/netflix.com",
            "http://localhost:3000/netflix.com",
            "https://netflix.com:0/watch",
            "https://netflix.com:99999/watch",
            "ht\ttps://netflix.com/",
            "",
        ];
        for url in negatives {
            assert!(
                !requires_vmp_drm_engine(url),
                "did NOT expect VMP DRM engine for {}",
                url
            );
        }
    }

    #[test]
    fn test_drm_service_labels() {
        assert_eq!(
            drm_service_label("https://www.netflix.com/watch/123"),
            Some("Netflix")
        );
        assert_eq!(
            drm_service_label("https://www.disneyplus.com/home"),
            Some("Disney+")
        );
        assert_eq!(
            drm_service_label("https://www.primevideo.com/"),
            Some("Prime Video")
        );
        assert_eq!(
            drm_service_label("https://www.canalplus.com/"),
            Some("Canal+")
        );
        assert_eq!(
            drm_service_label("https://www.mycanal.fr/"),
            Some("Canal+")
        );
        assert_eq!(
            drm_service_label("https://tv.apple.com/"),
            Some("Apple TV+")
        );
        assert_eq!(drm_service_label("https://play.max.com/"), Some("Max"));
        assert_eq!(drm_service_label("https://play.hbomax.com/"), Some("Max"));
        assert_eq!(
            drm_service_label("https://www.paramountplus.com/"),
            Some("Paramount+")
        );
        assert_eq!(drm_service_label("https://www.hulu.com/"), Some("Hulu"));
        assert_eq!(
            drm_service_label("https://www.peacocktv.com/"),
            Some("Peacock")
        );
        assert_eq!(drm_service_label("https://www.dazn.com/"), Some("DAZN"));
        assert_eq!(
            drm_service_label("https://app.molotov.tv/"),
            Some("Molotov")
        );
        assert_eq!(
            drm_service_label("https://www.france.tv/"),
            Some("France.tv")
        );
        assert_eq!(drm_service_label("https://www.tf1.fr/"), Some("TF1+"));
        assert_eq!(
            drm_service_label("https://m6plus.m6.fr/"),
            Some("M6+")
        );
        assert_eq!(
            drm_service_label("https://www.crunchyroll.com/"),
            Some("Crunchyroll")
        );
        assert_eq!(drm_service_label("https://example.org/"), None);
        assert_eq!(drm_service_label("file:///netflix.com"), None);
    }

    #[test]
    fn test_should_use_drm_engine() {
        assert!(should_use_drm_engine("https://www.netflix.com/browse", false));
        assert!(!should_use_drm_engine("https://example.com/", false));
        assert!(should_use_drm_engine("https://example.com/", true));
        assert!(should_use_drm_engine("HTTP://EXAMPLE.COM:8080/video", true));
        // Non-HTTP(S) schemes must NEVER route to the DRM engine even when manually pinned
        assert!(!should_use_drm_engine("singularity://settings", true));
        assert!(!should_use_drm_engine("file:///C:/secret.txt", true));
        assert!(!should_use_drm_engine("about:blank", true));
        assert!(!should_use_drm_engine("javascript:alert(1)", true));
    }

    #[test]
    fn test_ensure_cef_widevine_ready_preserves_existing_preferences_json() {
        let profile = unique_test_dir("prefs_preserve");
        let default_dir = profile.join("Default");
        std::fs::create_dir_all(&default_dir).expect("mkdir Default");
        let prefs_path = default_dir.join("Preferences");

        let initial = serde_json::json!({
            "browser": { "has_seen_welcome_page": true },
            "extensions": { "theme": { "id": "dark" } },
            "profile": {
                "name": "Singularity",
                "default_content_setting_values": {
                    "notifications": 2,
                    "geolocation": 2
                }
            }
        });
        std::fs::write(&prefs_path, serde_json::to_vec(&initial).unwrap())
            .expect("write initial Preferences");

        assert!(ensure_cef_widevine_ready(&profile));

        let updated_raw = std::fs::read_to_string(&prefs_path).expect("read updated Preferences");
        let updated: serde_json::Value =
            serde_json::from_str(&updated_raw).expect("parse updated Preferences");

        assert_eq!(updated["browser"]["has_seen_welcome_page"], true);
        assert_eq!(updated["extensions"]["theme"]["id"], "dark");
        assert_eq!(updated["profile"]["name"], "Singularity");
        assert_eq!(
            updated["profile"]["default_content_setting_values"]["notifications"],
            2
        );
        assert_eq!(
            updated["profile"]["default_content_setting_values"]["geolocation"],
            2
        );
        assert_eq!(
            updated["profile"]["default_content_setting_values"]["protected_media_identifier"],
            1
        );

        // Fresh profile without Default/Preferences creates it cleanly
        let fresh_profile = unique_test_dir("prefs_fresh");
        assert!(ensure_cef_widevine_ready(&fresh_profile));
        let fresh_raw =
            std::fs::read_to_string(fresh_profile.join("Default").join("Preferences"))
                .expect("read fresh Preferences");
        let fresh: serde_json::Value = serde_json::from_str(&fresh_raw).expect("parse fresh");
        assert_eq!(
            fresh["profile"]["default_content_setting_values"]["protected_media_identifier"],
            1
        );

        let _ = std::fs::remove_dir_all(&profile);
        let _ = std::fs::remove_dir_all(&fresh_profile);
    }

    #[test]
    fn test_widevine_candidate_version_selection_and_storage_cleanup() {
        let root = unique_test_dir("widevine_candidates");

        let make_cdm = |dir: &Path, ver: &str| {
            let dll_dir = dir.join("_platform_specific").join("win_x64");
            std::fs::create_dir_all(&dll_dir).expect("mkdir win_x64");
            std::fs::write(
                dir.join("manifest.json"),
                serde_json::json!({ "version": ver }).to_string(),
            )
            .expect("write manifest");
            std::fs::write(dll_dir.join("widevinecdm.dll"), b"MZ-dummy-cdm")
                .expect("write dummy dll");
        };

        let chrome_ud = root.join("chrome_ud");
        make_cdm(&chrome_ud.join("4.10.999.0"), "4.10.999.0");
        make_cdm(&chrome_ud.join("4.10.2891.0"), "4.10.2891.0");
        // Missing DLL must be ignored even if higher version
        std::fs::create_dir_all(chrome_ud.join("9.9.9.9")).expect("mkdir incomplete");
        std::fs::write(
            chrome_ud.join("9.9.9.9").join("manifest.json"),
            r#"{"version":"9.9.9.9"}"#,
        )
        .expect("write incomplete manifest");

        let bundled = root.join("chrome_bundled");
        make_cdm(&bundled, "4.10.2934.0");

        let (best_ver, best_dir) =
            find_newest_widevine_candidate(&[chrome_ud.clone(), bundled.clone()])
                .expect("find newest candidate");
        assert_eq!(best_ver, "4.10.2934.0");
        assert_eq!(best_dir, bundled);

        // Storage cleanup removes `<roaming>/drm-webview2/`
        let roaming = unique_test_dir("roaming_cleanup");
        let drm_dir = roaming.join("drm-webview2");
        std::fs::create_dir_all(&drm_dir).expect("mkdir drm-webview2");
        std::fs::write(drm_dir.join("Cookies"), b"test").expect("write cookie");
        clear_drm_webview_storage(&roaming);
        assert!(!drm_dir.exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            // Symlinked Preferences must be refused (never follow)
            let sym_prof = unique_test_dir("symlink_prefs");
            std::fs::create_dir_all(sym_prof.join("Default")).expect("mkdir Default");
            let outside = sym_prof.join("outside.json");
            std::fs::write(&outside, br#"{"keep":true}"#).expect("write outside");
            symlink(&outside, sym_prof.join("Default").join("Preferences"))
                .expect("create prefs symlink");
            assert!(!ensure_cef_preferences_protected_media(&sym_prof));
            assert_eq!(
                std::fs::read_to_string(&outside).expect("read outside"),
                r#"{"keep":true}"#
            );

            // Symlinked drm-webview2 must NOT delete its target
            let sym_roaming = unique_test_dir("symlink_storage");
            let target_dir = sym_roaming.join("protected_target");
            std::fs::create_dir_all(&target_dir).expect("mkdir target");
            std::fs::write(target_dir.join("keep.txt"), b"ok").expect("write keep");
            symlink(&target_dir, sym_roaming.join("drm-webview2"))
                .expect("create storage symlink");
            clear_drm_webview_storage(&sym_roaming);
            assert!(target_dir.join("keep.txt").is_file());

            let _ = std::fs::remove_dir_all(&sym_prof);
            let _ = std::fs::remove_dir_all(&sym_roaming);
        }

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&roaming);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_drm_frame_subresource_and_download_security_gates() {
        use std::sync::Arc;

        let allow_public_no_ads: DrmNavigationPolicyFn = Arc::new(|u: &str| {
            !u.contains("doubleclick.net") && !u.contains("blocked-by-killswitch.test")
        });
        let deny_all_lockdown: DrmNavigationPolicyFn = Arc::new(|_u: &str| false);
        let bind_port: u16 = 54321;

        // 1. Subframe & subresource gate
        assert!(windows_drm::is_allowed_drm_frame_or_resource_url(
            "https://www.netflix.com/watch/123",
            bind_port,
            &allow_public_no_ads
        ));
        assert!(windows_drm::is_allowed_drm_frame_or_resource_url(
            "wss://push.netflix.com/socket",
            bind_port,
            &allow_public_no_ads
        ));
        assert!(windows_drm::is_allowed_drm_frame_or_resource_url(
            "blob:https://www.netflix.com/550e8400-e29b-41d4-a716-446655440000",
            bind_port,
            &allow_public_no_ads
        ));
        assert!(windows_drm::is_allowed_drm_frame_or_resource_url(
            "about:blank",
            bind_port,
            &allow_public_no_ads
        ));
        assert!(windows_drm::is_allowed_drm_frame_or_resource_url(
            "about:srcdoc",
            bind_port,
            &allow_public_no_ads
        ));
        assert!(windows_drm::is_allowed_drm_frame_or_resource_url(
            "data:image/svg+xml,<svg/>",
            bind_port,
            &allow_public_no_ads
        ));

        // Local IPC, file://, blob targeting local IPC, ad domains, and Lockdown/Kill-Switch MUST be blocked
        assert!(!windows_drm::is_allowed_drm_frame_or_resource_url(
            "http://127.0.0.1:54321/api/state",
            bind_port,
            &allow_public_no_ads
        ));
        assert!(!windows_drm::is_allowed_drm_frame_or_resource_url(
            "ws://127.0.0.1:54321/ws",
            bind_port,
            &allow_public_no_ads
        ));
        assert!(!windows_drm::is_allowed_drm_frame_or_resource_url(
            "blob:http://127.0.0.1:54321/550e8400",
            bind_port,
            &allow_public_no_ads
        ));
        assert!(!windows_drm::is_allowed_drm_frame_or_resource_url(
            "file:///C:/Windows/win.ini",
            bind_port,
            &allow_public_no_ads
        ));
        assert!(!windows_drm::is_allowed_drm_frame_or_resource_url(
            "https://ads.doubleclick.net/pixel.js",
            bind_port,
            &allow_public_no_ads
        ));
        assert!(!windows_drm::is_allowed_drm_frame_or_resource_url(
            "https://www.netflix.com/watch/123",
            bind_port,
            &deny_all_lockdown
        ));
        assert!(!windows_drm::is_allowed_drm_frame_or_resource_url(
            "wss://push.netflix.com/socket",
            bind_port,
            &deny_all_lockdown
        ));

        // 2. Download gate
        assert!(windows_drm::is_allowed_drm_download(
            "https://cdn.example.com/subtitles.vtt",
            Path::new("C:\\Users\\test\\Downloads\\subtitles.vtt"),
            bind_port,
            &allow_public_no_ads
        ));
        assert!(!windows_drm::is_allowed_drm_download(
            "http://127.0.0.1:54321/api/export",
            Path::new("C:\\Users\\test\\Downloads\\export.json"),
            bind_port,
            &allow_public_no_ads
        ));
        assert!(!windows_drm::is_allowed_drm_download(
            "file:///C:/Windows/System32/cmd.exe",
            Path::new("C:\\Users\\test\\Downloads\\cmd.exe"),
            bind_port,
            &allow_public_no_ads
        ));
        assert!(!windows_drm::is_allowed_drm_download(
            "https://cdn.example.com/update.exe",
            Path::new("C:\\Users\\test\\Downloads\\update.bin"),
            bind_port,
            &allow_public_no_ads
        ));
        assert!(!windows_drm::is_allowed_drm_download(
            "https://cdn.example.com/download?id=1",
            Path::new("C:\\Users\\test\\Downloads\\dropper.ps1"),
            bind_port,
            &allow_public_no_ads
        ));
        assert!(!windows_drm::is_allowed_drm_download(
            "blob:https://www.netflix.com/550e8400",
            Path::new("C:\\Users\\test\\Downloads\\smuggled.html"),
            bind_port,
            &allow_public_no_ads
        ));
        assert!(!windows_drm::is_allowed_drm_download(
            "https://cdn.example.com/subtitles.vtt",
            Path::new("C:\\Users\\test\\Downloads\\subtitles.vtt"),
            bind_port,
            &deny_all_lockdown
        ));
    }

    #[test]
    fn test_inspect_widevine_status_and_hint_path_confinement() {
        let make_cdm = |dir: &Path, ver: &str| {
            let dll_dir = dir.join("_platform_specific").join("win_x64");
            std::fs::create_dir_all(&dll_dir).expect("mkdir win_x64");
            std::fs::write(
                dir.join("manifest.json"),
                serde_json::json!({ "version": ver }).to_string(),
            )
            .expect("write manifest");
            std::fs::write(dll_dir.join("widevinecdm.dll"), b"MZ-dummy-cdm")
                .expect("write dummy dll");
        };

        // 1. Empty WidevineCdm directory MUST NOT report ready
        let empty_profile = unique_test_dir("wv_empty_dir");
        std::fs::create_dir_all(empty_profile.join("WidevineCdm")).expect("mkdir WidevineCdm");
        let rep = inspect_widevine_status(&empty_profile);
        assert!(!rep.cef_widevine_ready);
        assert!(rep.detected_version.is_none());

        // 2. Manifest without DLL MUST NOT report ready
        let no_dll_profile = unique_test_dir("wv_no_dll");
        let no_dll_ver = no_dll_profile.join("WidevineCdm").join("4.10.2891.0");
        std::fs::create_dir_all(&no_dll_ver).expect("mkdir ver");
        std::fs::write(no_dll_ver.join("manifest.json"), r#"{"version":"4.10.2891.0"}"#)
            .expect("write manifest");
        let rep = inspect_widevine_status(&no_dll_profile);
        assert!(!rep.cef_widevine_ready);

        // 3. Roaming root (`<roaming>/cef-profile/WidevineCdm/<ver>`) with valid hint reports ready
        let roaming = unique_test_dir("wv_roaming_valid");
        let wv_root = roaming.join("cef-profile").join("WidevineCdm");
        let ver_dir = wv_root.join("4.10.2934.0");
        make_cdm(&ver_dir, "4.10.2934.0");
        let hint_path = wv_root.join("latest-component-updated-widevine-cdm");
        std::fs::write(
            &hint_path,
            serde_json::json!({ "Path": ver_dir.to_string_lossy() }).to_string(),
        )
        .expect("write valid hint");

        assert!(existing_cef_widevine_is_valid(&wv_root));
        let rep_roaming = inspect_widevine_status(&roaming);
        assert!(rep_roaming.cef_widevine_ready);
        assert_eq!(rep_roaming.detected_version.as_deref(), Some("4.10.2934.0"));

        // Direct cef_profile_dir also works
        let rep_direct = inspect_widevine_status(&roaming.join("cef-profile"));
        assert!(rep_direct.cef_widevine_ready);
        assert_eq!(rep_direct.detected_version.as_deref(), Some("4.10.2934.0"));

        // 4. Hint pointing OUTSIDE widevine_root (even to a valid CDM dir) MUST be rejected
        let outside = unique_test_dir("wv_outside_escape");
        make_cdm(&outside, "4.10.9999.0");
        std::fs::write(
            &hint_path,
            serde_json::json!({ "Path": outside.to_string_lossy() }).to_string(),
        )
        .expect("write escaped hint");
        assert!(!existing_cef_widevine_is_valid(&wv_root));
        let rep_escaped = inspect_widevine_status(&roaming);
        assert!(!rep_escaped.cef_widevine_ready);

        let _ = std::fs::remove_dir_all(&empty_profile);
        let _ = std::fs::remove_dir_all(&no_dll_profile);
        let _ = std::fs::remove_dir_all(&roaming);
        let _ = std::fs::remove_dir_all(&outside);
    }
}
