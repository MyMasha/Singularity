//! Verified Auto-Updater & Native Windows Uninstaller for Singularity Browser.
//!
//! - Connects directly to the public repository `https://github.com/MyMasha/Singularity`
//!   with zero embedded credentials or tokens and enforces a strict GitHub HTTPS host allowlist.
//! - Verifies mandatory SHA-256 checksums (`SHA256SUMS.txt`) from the same GitHub Release
//!   before replacing or executing any binary (no fallback to mutable branches).
//! - Enforces Ed25519 signature verification over `SHA256SUMS.txt` (`SHA256SUMS.txt.sig`)
//!   fed via `option_env!("SINGULARITY_RELEASE_SIGNING_PUBKEY_HEX")` (with fallback to
//!   `RELEASE_SIGNING_PUBKEY_HEX`), failing CLOSED in release builds if unconfigured.
//! - Stages downloaded installers inside the user-private `.singularity/updates` directory
//!   using exclusive random filenames (`create_new(true)`), eliminating `%TEMP%` TOCTOU races.
//! - Uses an explicit exact-filename allowlist for uninstallation (zero destructive wildcards).

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rand_core::{OsRng, RngCore};
use serde::Serialize;
use sha2::{Digest, Sha256};
#[cfg(not(target_os = "windows"))]
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use subtle::ConstantTimeEq;

pub const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const REPO_URL: &str = "https://github.com/MyMasha/Singularity";
pub const RELEASES_API_URL: &str = "https://api.github.com/repos/MyMasha/Singularity/releases/latest";
pub const PUBLIC_ASSET_URL_WINDOWS: &str =
    "https://github.com/MyMasha/Singularity/releases/latest/download/Singularity-setup.exe";
pub const PUBLIC_ASSET_URL_LINUX: &str =
    "https://github.com/MyMasha/Singularity/releases/latest/download/singularity-linux-x86_64";
pub const PUBLIC_SHA256SUMS_URL: &str =
    "https://github.com/MyMasha/Singularity/releases/latest/download/SHA256SUMS.txt";

/// Strict HTTPS host allowlist for all update metadata and release asset URLs.
pub const ALLOWED_UPDATE_HOSTS: &[&str] = &[
    "github.com",
    "api.github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
    "github-releases.githubusercontent.com",
];

/// Explicit exact-filename allowlist for Windows uninstallation (zero wildcards).
pub const UNINSTALL_ALLOWED_EXACT_FILES: &[&str] = &[
    "singularity.exe",
    "singularity.ico",
    "libcef.dll",
    "chrome_elf.dll",
    "libEGL.dll",
    "libGLESv2.dll",
    "d3dcompiler_47.dll",
    "vk_swiftshader.dll",
    "vulkan-1.dll",
    "vk_swiftshader_icd.json",
    "icudtl.dat",
    "v8_context_snapshot.bin",
    "snapshot_blob.bin",
    "resources.pak",
    "chrome_100_percent.pak",
    "chrome_200_percent.pak",
    "cef.pak",
    "cef_100_percent.pak",
    "cef_200_percent.pak",
    "cef_extensions.pak",
    "devtools_resources.pak",
    "Launch-Singularity.bat",
    "Update-Singularity.bat",
    "Update-Singularity.ps1",
];

/// Fallback 64-hex-character Ed25519 release signing public key when
/// `SINGULARITY_RELEASE_SIGNING_PUBKEY_HEX` is not injected at compile time via `option_env!`.
/// Release builds (`#[cfg(not(debug_assertions))]`) FAIL CLOSED if neither source provides a
/// valid 64-hex Ed25519 verifying key.
pub const RELEASE_SIGNING_PUBKEY_HEX: &str =
    "3af87c325effee5f8f23e1ba7d9b8c5e7cebda70388718e87cf308237e70c155";

/// Validates that `pubkey_hex` is a well-formed 64-hex-character Ed25519 verifying key.
pub fn is_valid_ed25519_pubkey_hex(pubkey_hex: &str) -> bool {
    let trimmed = pubkey_hex.trim();
    if trimmed.len() != 64 {
        return false;
    }
    let Ok(bytes) = hex::decode(trimmed) else {
        return false;
    };
    let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) else {
        return false;
    };
    VerifyingKey::from_bytes(&arr).is_ok()
}

/// Resolves the compiled-in Ed25519 release signing public key from
/// `option_env!("SINGULARITY_RELEASE_SIGNING_PUBKEY_HEX")` with fallback to `RELEASE_SIGNING_PUBKEY_HEX`.
pub fn resolve_release_signing_pubkey_hex() -> Option<&'static str> {
    let candidate = option_env!("SINGULARITY_RELEASE_SIGNING_PUBKEY_HEX")
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| RELEASE_SIGNING_PUBKEY_HEX.trim());
    if is_valid_ed25519_pubkey_hex(candidate) {
        Some(candidate)
    } else {
        None
    }
}

/// Enforces mandatory Ed25519 release signing verification policy:
/// - If a valid 64-hex Ed25519 key is configured, returns `Ok(Some(key_hex))`.
/// - In release builds (`#[cfg(not(debug_assertions))]`), ALWAYS fails closed if unconfigured.
/// - In debug/test builds, requires a valid key unless `allow_unsigned_debug_opt_out` is `true`
///   (e.g. via `SINGULARITY_ALLOW_UNSIGNED_DEV_UPDATE=1` for local dev/unit tests only).
pub fn resolve_mandatory_signing_pubkey(
    configured_pubkey: Option<&str>,
    allow_unsigned_debug_opt_out: bool,
) -> Result<Option<String>, String> {
    if let Some(pk) = configured_pubkey {
        let trimmed = pk.trim();
        if !trimmed.is_empty() {
            if is_valid_ed25519_pubkey_hex(trimmed) {
                return Ok(Some(trimmed.to_string()));
            }
            return Err(
                "Invalid Ed25519 release signing public key configuration (expected 64 valid hex chars)."
                    .into(),
            );
        }
    }

    #[cfg(not(debug_assertions))]
    {
        let _ = allow_unsigned_debug_opt_out;
        Err(
            "Unsigned updates are forbidden in release builds: no valid Ed25519 release signing public key (SINGULARITY_RELEASE_SIGNING_PUBKEY_HEX) is configured."
                .into(),
        )
    }

    #[cfg(debug_assertions)]
    {
        if allow_unsigned_debug_opt_out {
            Ok(None)
        } else {
            Err(
                "Update refused: no valid Ed25519 release signing public key is configured (set SINGULARITY_RELEASE_SIGNING_PUBKEY_HEX at build time, or opt out in debug builds with SINGULARITY_ALLOW_UNSIGNED_DEV_UPDATE=1)."
                    .into(),
            )
        }
    }
}

/// Validates that `url` uses HTTPS on port 443 and targets one of `ALLOWED_UPDATE_HOSTS`.
pub fn is_allowed_update_https_url(url: &str) -> bool {
    let Ok(parsed) = crate::winhttp_client::parse_http_url_parts(url) else {
        return false;
    };
    if !parsed.is_https || parsed.port != 443 {
        return false;
    }
    let host = parsed.host.to_ascii_lowercase();
    ALLOWED_UPDATE_HOSTS.iter().any(|allowed| host == *allowed)
}

/// Resolves an optional user-provided GitHub token solely from the `SINGULARITY_GITHUB_TOKEN`
/// environment variable (never hardcoded; public releases work anonymously by default).
pub fn resolve_github_token() -> Option<String> {
    std::env::var("SINGULARITY_GITHUB_TOKEN")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[derive(Debug, Clone, Serialize)]
pub struct UpdateCheckInfo {
    pub current_version: String,
    pub latest_version: String,
    pub update_available: bool,
    pub release_url: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct UpdateProgressSnapshot {
    pub phase: String,
    pub active: bool,
    pub downloaded_bytes: u64,
    pub total_bytes: u64,
    pub percent: u8,
    pub speed_bps: u64,
    pub latest_version: String,
    pub message: String,
    pub error: Option<String>,
}

impl Default for UpdateProgressSnapshot {
    fn default() -> Self {
        Self {
            phase: "idle".into(),
            active: false,
            downloaded_bytes: 0,
            total_bytes: 0,
            percent: 0,
            speed_bps: 0,
            latest_version: String::new(),
            message: String::new(),
            error: None,
        }
    }
}

static UPDATE_PROGRESS: std::sync::OnceLock<std::sync::Mutex<UpdateProgressSnapshot>> =
    std::sync::OnceLock::new();

fn update_progress_lock() -> &'static std::sync::Mutex<UpdateProgressSnapshot> {
    UPDATE_PROGRESS.get_or_init(|| std::sync::Mutex::new(UpdateProgressSnapshot::default()))
}

fn update_progress_state<F>(f: F) -> UpdateProgressSnapshot
where
    F: FnOnce(&mut UpdateProgressSnapshot),
{
    let mut guard = update_progress_lock()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    f(&mut guard);
    guard.clone()
}

pub fn get_update_progress() -> UpdateProgressSnapshot {
    update_progress_lock()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

/// Returns the user-private updates staging directory (`<roaming>/.singularity/updates`),
/// creating it with `0o700` permissions on Unix, rejecting symlinks, and pruning stale installers.
pub fn prepare_private_updates_dir() -> Result<PathBuf, String> {
    let base = crate::roaming_store::resolve_roaming_singularity_dir();
    prepare_private_updates_dir_at(&base)
}

fn prepare_private_updates_dir_at(roaming_root: &Path) -> Result<PathBuf, String> {
    std::fs::create_dir_all(roaming_root)
        .map_err(|e| format!("Failed creating roaming directory: {}", e))?;
    let updates_dir = roaming_root.join("updates");
    std::fs::create_dir_all(&updates_dir)
        .map_err(|e| format!("Failed creating private updates directory: {}", e))?;

    let meta = std::fs::symlink_metadata(&updates_dir)
        .map_err(|e| format!("Failed inspecting updates directory: {}", e))?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err("Refused unsafe updates directory (symlink or non-directory).".into());
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = meta.permissions();
        perms.set_mode(0o700);
        std::fs::set_permissions(&updates_dir, perms)
            .map_err(|e| format!("Failed setting 0700 permissions on updates directory: {}", e))?;
    }

    cleanup_stale_update_artifacts(&updates_dir);
    Ok(updates_dir)
}

fn cleanup_stale_update_artifacts(updates_dir: &Path) {
    let Ok(entries) = std::fs::read_dir(updates_dir) else {
        return;
    };
    for ent in entries.flatten() {
        let p = ent.path();
        let Ok(meta) = std::fs::symlink_metadata(&p) else {
            continue;
        };
        if meta.file_type().is_symlink() || !meta.is_file() {
            continue;
        }
        if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
            if name.starts_with("Singularity-setup-")
                || name.starts_with("singularity-update-")
                || name.starts_with("SHA256SUMS-")
                || name.ends_with(".dl.tmp")
            {
                let _ = std::fs::remove_file(&p);
            }
        }
    }
}

/// Allocates a collision-free random file inside `updates_dir` using exclusive creation
/// (`create_new(true)` and `0o600` on Unix) so no pre-existing or attacker-planted path is reused.
fn allocate_exclusive_update_file(
    updates_dir: &Path,
    prefix: &str,
    suffix: &str,
) -> Result<PathBuf, String> {
    let mut rnd = [0u8; 16];
    OsRng.fill_bytes(&mut rnd);
    let path = updates_dir.join(format!(
        "{}-{}-{}{}",
        prefix,
        std::process::id(),
        hex::encode(rnd),
        suffix
    ));
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| format!("Failed exclusively creating {}: {}", path.display(), e))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|e| format!("Failed exclusively creating {}: {}", path.display(), e))?;
    }
    Ok(path)
}

/// Cleans up leftover `.old` executable backups and stale staged installers in the user-private
/// `updates/` directory (plus legacy `%TEMP%` installer) without stripping SmartScreen protections.
pub fn perform_startup_maintenance() {
    let _ = crate::roaming_store::ensure_roaming_dir_initialized();

    if let Ok(current_exe) = std::env::current_exe() {
        let old_exe = if cfg!(target_os = "windows") {
            current_exe.with_extension("exe.old")
        } else {
            let mut p = current_exe.as_os_str().to_os_string();
            p.push(".old");
            PathBuf::from(p)
        };
        if old_exe.exists() {
            let _ = std::fs::remove_file(old_exe);
        }
    }
    let updates_dir = crate::roaming_store::resolve_roaming_singularity_dir().join("updates");
    if updates_dir.is_dir() {
        cleanup_stale_update_artifacts(&updates_dir);
    }
    #[cfg(target_os = "windows")]
    {
        let tmp_setup = std::env::temp_dir().join("Singularity-setup-update.exe");
        if tmp_setup.exists() {
            let _ = std::fs::remove_file(tmp_setup);
        }
    }
}

#[cfg(target_os = "windows")]
fn system_powershell_path() -> PathBuf {
    if let Ok(sysroot) = std::env::var("SystemRoot") {
        let p = PathBuf::from(sysroot)
            .join("System32")
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe");
        if p.is_file() {
            return p;
        }
    }
    PathBuf::from(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
}

/// Verifies a detached base64-encoded Ed25519 signature (`SHA256SUMS.txt.sig`) over `sums_bytes`
/// using the 32-byte hex-encoded Ed25519 verifying key (`pubkey_hex`).
pub fn verify_sha256sums_ed25519(
    sums_bytes: &[u8],
    sig_b64: &str,
    pubkey_hex: &str,
) -> Result<(), String> {
    let pk_bytes = hex::decode(pubkey_hex.trim())
        .map_err(|_| "Invalid Ed25519 release signing public key hex.".to_string())?;
    let pk_arr: [u8; 32] = pk_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "Ed25519 release signing public key must be 32 bytes.".to_string())?;
    let verifying_key = VerifyingKey::from_bytes(&pk_arr)
        .map_err(|_| "Malformed Ed25519 release signing public key.".to_string())?;

    let sig_bytes = BASE64
        .decode(sig_b64.trim())
        .map_err(|_| "Invalid base64 encoding in SHA256SUMS.txt.sig.".to_string())?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "Ed25519 signature must be exactly 64 bytes.".to_string())?;
    let signature = Signature::from_bytes(&sig_arr);

    verifying_key
        .verify(sums_bytes, &signature)
        .map_err(|_| "Ed25519 signature verification failed for SHA256SUMS.txt.".to_string())
}

/// Checks public GitHub Releases (`https://github.com/MyMasha/Singularity`) for a newer version.
pub fn check_for_updates() -> Result<UpdateCheckInfo, String> {
    if !is_allowed_update_https_url(RELEASES_API_URL) {
        return Err("Update metadata URL failed strict GitHub host allowlist.".into());
    }
    let opt_token = resolve_github_token();

    #[cfg(target_os = "windows")]
    let raw_json = {
        let ua = format!("Singularity-Browser/{}", CURRENT_VERSION);
        let fetch_rel = |tok: Option<&str>| -> Result<String, String> {
            let mut headers = vec![("Accept", "application/vnd.github+json")];
            let auth_val;
            if let Some(t) = tok {
                auth_val = format!("Bearer {}", t);
                headers.push(("Authorization", auth_val.as_str()));
            }
            let bytes = crate::winhttp_client::winhttp_get_https_bytes(
                RELEASES_API_URL,
                &ua,
                &headers,
                6_000,
                10_000,
                512 * 1024,
            )?;
            Ok(String::from_utf8_lossy(&bytes).trim().to_string())
        };
        match opt_token.as_deref() {
            Some(tok) => fetch_rel(Some(tok)).or_else(|_| fetch_rel(None)),
            None => fetch_rel(None),
        }
        .map_err(|err| {
            eprintln!("[singularity-updater] Update check failed: {}", err);
            "Unable to check for updates (offline or GitHub API unreachable).".to_string()
        })?
    };

    #[cfg(not(target_os = "windows"))]
    let raw_json = {
        let fetch_release_json = |tok: Option<&str>| -> Option<String> {
            let mut child = Command::new("curl")
                .args([
                    "-fsS",
                    "--proto",
                    "=https",
                    "--max-time",
                    "8",
                    "-K",
                    "-",
                    RELEASES_API_URL,
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .ok()?;

            if let Some(mut stdin) = child.stdin.take() {
                let _ = writeln!(stdin, "header = \"User-Agent: Singularity-Browser/{}\"", CURRENT_VERSION);
                let _ = writeln!(stdin, "header = \"Accept: application/vnd.github+json\"");
                if let Some(t) = tok {
                    let clean: String = t
                        .chars()
                        .filter(|c| !matches!(c, '\r' | '\n' | '"' | '\\' | '\0'))
                        .collect();
                    let _ = writeln!(stdin, "header = \"Authorization: Bearer {}\"", clean);
                }
            }
            let out = child.wait_with_output().ok()?;
            if !out.status.success() {
                return None;
            }
            Some(String::from_utf8_lossy(&out.stdout).into_owned())
        };

        let res = match opt_token.as_deref() {
            Some(tok) => fetch_release_json(Some(tok)).or_else(|| fetch_release_json(None)),
            None => fetch_release_json(None),
        };
        res.ok_or_else(|| "Unable to reach GitHub Releases.".to_string())?
    };

    let val: serde_json::Value = serde_json::from_str(&raw_json)
        .map_err(|_| "Invalid GitHub Releases API response.".to_string())?;
    let tag = val
        .get("tag_name")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().trim_start_matches('v').to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "Missing tag_name in GitHub Releases API response.".to_string())?;
    let release_url = val
        .get("html_url")
        .and_then(|v| v.as_str())
        .filter(|u| is_allowed_update_https_url(u))
        .unwrap_or("https://github.com/MyMasha/Singularity/releases")
        .to_string();

    let update_available = is_newer_semver(&tag, CURRENT_VERSION);
    Ok(UpdateCheckInfo {
        current_version: CURRENT_VERSION.to_string(),
        latest_version: tag,
        update_available,
        release_url,
    })
}

fn cmp_semver_prerelease(a: &str, b: &str) -> std::cmp::Ordering {
    let mut ia = a.split('.');
    let mut ib = b.split('.');
    loop {
        match (ia.next(), ib.next()) {
            (None, None) => return std::cmp::Ordering::Equal,
            (None, Some(_)) => return std::cmp::Ordering::Less,
            (Some(_), None) => return std::cmp::Ordering::Greater,
            (Some(sa), Some(sb)) => {
                let a_num = !sa.is_empty() && sa.bytes().all(|c| c.is_ascii_digit());
                let b_num = !sb.is_empty() && sb.bytes().all(|c| c.is_ascii_digit());
                let ord = match (a_num, b_num) {
                    (true, true) => {
                        let na = sa.trim_start_matches('0');
                        let nb = sb.trim_start_matches('0');
                        na.len().cmp(&nb.len()).then_with(|| na.cmp(nb))
                    }
                    (true, false) => std::cmp::Ordering::Less,
                    (false, true) => std::cmp::Ordering::Greater,
                    (false, false) => sa.cmp(sb),
                };
                if ord != std::cmp::Ordering::Equal {
                    return ord;
                }
            }
        }
    }
}

/// SemVer 2.0 comparator: separates `major.minor.patch` from `-prerelease` tags and `+build` metadata,
/// comparing numeric prerelease identifiers numerically (`alpha.10 > alpha.2`).
pub fn is_newer_semver(candidate: &str, current: &str) -> bool {
    fn parse_semver(s: &str) -> Option<((u64, u64, u64), Option<String>)> {
        let stripped = s.trim().trim_start_matches('v');
        let no_build = stripped.split('+').next().unwrap_or(stripped);
        let (core, pre) = match no_build.split_once('-') {
            Some((c, p)) if !p.is_empty() => (c, Some(p.to_string())),
            Some(_) => return None,
            None => (no_build, None),
        };
        let mut nums = core.split('.');
        let major = nums.next()?.parse::<u64>().ok()?;
        let minor = nums.next().unwrap_or("0").parse::<u64>().ok()?;
        let patch = nums.next().unwrap_or("0").parse::<u64>().ok()?;
        if nums.next().is_some() {
            return None;
        }
        Some(((major, minor, patch), pre))
    }

    let (Some((c_ver, c_pre)), Some((cur_ver, cur_pre))) =
        (parse_semver(candidate), parse_semver(current))
    else {
        return false;
    };

    if c_ver != cur_ver {
        return c_ver > cur_ver;
    }
    match (c_pre, cur_pre) {
        (None, Some(_)) => true,
        (Some(_), None) | (None, None) => false,
        (Some(a), Some(b)) => cmp_semver_prerelease(&a, &b) == std::cmp::Ordering::Greater,
    }
}

/// Parses a `SHA256SUMS.txt` manifest and extracts the 32-byte digest for `asset_name`,
/// skipping malformed or single-token lines safely.
pub fn parse_sha256sums_for_asset(manifest: &str, asset_name: &str) -> Option<[u8; 32]> {
    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut parts = trimmed.split_whitespace();
        let Some(hash_hex) = parts.next() else {
            continue;
        };
        let Some(file_tok) = parts.next() else {
            continue;
        };
        let file = file_tok.trim_start_matches('*');
        if file == asset_name && hash_hex.len() == 64 {
            if let Ok(decoded) = hex::decode(hash_hex) {
                if let Ok(arr) = <[u8; 32]>::try_from(decoded.as_slice()) {
                    return Some(arr);
                }
            }
        }
    }
    None
}

/// Computes and verifies the SHA-256 digest of `file_path` in constant time against `SHA256SUMS.txt`.
pub fn verify_downloaded_binary_sha256(
    file_path: &Path,
    sums_manifest: &str,
    asset_name: &str,
) -> Result<(), String> {
    let expected = parse_sha256sums_for_asset(sums_manifest, asset_name).ok_or_else(|| {
        format!(
            "SHA-256 checksum for '{}' not found in SHA256SUMS.txt.",
            asset_name
        )
    })?;
    let meta = std::fs::symlink_metadata(file_path)
        .map_err(|e| format!("Failed inspecting downloaded binary: {}", e))?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err("Refused unsafe update artifact (symlink or non-regular file).".into());
    }
    let bytes = std::fs::read(file_path)
        .map_err(|e| format!("Failed reading downloaded binary: {}", e))?;
    let actual: [u8; 32] = Sha256::digest(&bytes).into();
    if !bool::from(actual.ct_eq(&expected)) {
        return Err(format!(
            "SHA-256 integrity verification failed for '{}'. Update aborted.",
            asset_name
        ));
    }
    Ok(())
}

/// Checks whether the Pure Chromium (CEF) runtime (`libcef.dll`, `icudtl.dat`, `resources.pak`)
/// is installed alongside the currently running `singularity.exe`.
#[cfg(target_os = "windows")]
pub fn has_local_cef_runtime() -> bool {
    let Ok(exe) = std::env::current_exe() else {
        return false;
    };
    let Some(dir) = exe.parent() else {
        return false;
    };
    dir.join("libcef.dll").is_file()
        && dir.join("icudtl.dat").is_file()
        && dir.join("resources.pak").is_file()
}

/// Ensures Windows searches the `singularity.exe` directory first when delay-loading `libcef.dll`
/// and its Chromium dependencies, even if launched with an arbitrary working directory.
#[cfg(target_os = "windows")]
pub fn configure_local_cef_dll_directory() {
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "kernel32")]
    extern "system" {
        fn SetDllDirectoryW(lpPathName: *const u16) -> i32;
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let wide: Vec<u16> = dir.as_os_str().encode_wide().chain(Some(0)).collect();
            unsafe {
                let _ = SetDllDirectoryW(wide.as_ptr());
            }
        }
    }
}

/// Displays a clear native Win32 dialog if Pure Chromium runtime files are missing and offline
/// self-healing could not reach GitHub Releases (never an opaque system DLL error).
#[cfg(target_os = "windows")]
pub fn show_missing_cef_error_dialog(err: &str) {
    use std::os::windows::ffi::OsStrExt;
    const MB_OK: u32 = 0x0000_0000;
    const MB_ICONERROR: u32 = 0x0000_0010;
    #[link(name = "user32")]
    extern "system" {
        fn MessageBoxW(
            hWnd: *mut core::ffi::c_void,
            lpText: *const u16,
            lpCaption: *const u16,
            uType: u32,
        ) -> i32;
    }
    let body = format!(
        "Singularity Browser v{} requires its Pure Chromium (CEF) runtime (libcef.dll), which was not found next to singularity.exe.\n\n\
         Automatic download failed: {}\n\n\
         Please download and run Singularity-setup.exe from:\n\
         https://github.com/MyMasha/Singularity/releases/latest\n\n\
         Your existing encrypted profile (%APPDATA%\\.singularity) will be preserved.",
        CURRENT_VERSION, err
    );
    let text_w: Vec<u16> = std::ffi::OsStr::new(&body).encode_wide().chain(Some(0)).collect();
    let title_w: Vec<u16> = std::ffi::OsStr::new("Singularity Browser — Chromium Runtime Required")
        .encode_wide()
        .chain(Some(0))
        .collect();
    unsafe {
        let _ = MessageBoxW(
            core::ptr::null_mut(),
            text_w.as_ptr(),
            title_w.as_ptr(),
            MB_OK | MB_ICONERROR,
        );
    }
}

#[cfg(target_os = "windows")]
fn download_and_run_verified_setup_installer(
    target_dir: &Path,
    allow_same_version: bool,
) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    let allow_dev_unsigned =
        std::env::var("SINGULARITY_ALLOW_UNSIGNED_DEV_UPDATE").as_deref() == Ok("1");
    let signing_pubkey = resolve_mandatory_signing_pubkey(
        resolve_release_signing_pubkey_hex(),
        allow_dev_unsigned,
    )?;

    if !is_allowed_update_https_url(RELEASES_API_URL) {
        return Err("Update metadata URL failed strict GitHub host allowlist.".into());
    }

    let updates_dir = prepare_private_updates_dir()?;
    let setup_tmp = allocate_exclusive_update_file(&updates_dir, "Singularity-setup", ".exe")?;
    let sums_file = allocate_exclusive_update_file(&updates_dir, "SHA256SUMS", ".txt")?;
    let sig_file = allocate_exclusive_update_file(&updates_dir, "SHA256SUMS", ".txt.sig")?;

    let opt_token = resolve_github_token();
    let ua = format!("Singularity-Updater/{}", CURRENT_VERSION);

    let fetch_api = |tok: Option<&str>| -> Result<serde_json::Value, String> {
        let mut headers = vec![("Accept", "application/vnd.github+json")];
        let auth_val;
        if let Some(t) = tok {
            auth_val = format!("Bearer {}", t);
            headers.push(("Authorization", auth_val.as_str()));
        }
        let bytes = crate::winhttp_client::winhttp_get_https_bytes(
            RELEASES_API_URL,
            &ua,
            &headers,
            8_000,
            15_000,
            512 * 1024,
        )?;
        serde_json::from_slice(&bytes)
            .map_err(|_| "Invalid GitHub Releases API response.".to_string())
    };

    let rel = match opt_token.as_deref() {
        Some(tok) => fetch_api(Some(tok)).or_else(|_| fetch_api(None)),
        None => fetch_api(None),
    };
    let rel = match rel {
        Ok(v) => v,
        Err(e) => {
            let _ = std::fs::remove_file(&setup_tmp);
            let _ = std::fs::remove_file(&sums_file);
            let _ = std::fs::remove_file(&sig_file);
            return Err(e);
        }
    };

    let latest_ver = rel
        .get("tag_name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .trim_start_matches('v')
        .to_string();

    // Anti-downgrade guard: re-verify semantic version right before downloading & executing.
    let version_ok = if allow_same_version {
        !latest_ver.is_empty() && !is_newer_semver(CURRENT_VERSION, &latest_ver)
    } else {
        is_newer_semver(&latest_ver, CURRENT_VERSION)
    };
    if !version_ok {
        let _ = std::fs::remove_file(&setup_tmp);
        let _ = std::fs::remove_file(&sums_file);
        let _ = std::fs::remove_file(&sig_file);
        return Err(format!(
            "Refused non-newer or downgrade release version '{}' (current v{}).",
            latest_ver, CURRENT_VERSION
        ));
    }

    let assets = rel
        .get("assets")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let find_asset_info = |name: &str| -> Option<(String, u64)> {
        assets.iter().find_map(|a| {
            if a.get("name").and_then(|n| n.as_str()) == Some(name) {
                let url = a
                    .get("browser_download_url")
                    .and_then(|u| u.as_str())
                    .filter(|u| is_allowed_update_https_url(u))?
                    .to_string();
                let sz = a.get("size").and_then(|s| s.as_u64()).unwrap_or(0);
                Some((url, sz))
            } else {
                None
            }
        })
    };

    let Some((setup_url, setup_api_size)) = find_asset_info("Singularity-setup.exe") else {
        let _ = std::fs::remove_file(&setup_tmp);
        let _ = std::fs::remove_file(&sums_file);
        let _ = std::fs::remove_file(&sig_file);
        return Err(
            "Release asset 'Singularity-setup.exe' is unavailable or failed host allowlist.".into(),
        );
    };
    let Some((sums_url, _)) = find_asset_info("SHA256SUMS.txt") else {
        let _ = std::fs::remove_file(&setup_tmp);
        let _ = std::fs::remove_file(&sums_file);
        let _ = std::fs::remove_file(&sig_file);
        return Err(
            "Release asset 'SHA256SUMS.txt' is unavailable or failed host allowlist.".into(),
        );
    };
    let sig_url = find_asset_info("SHA256SUMS.txt.sig").map(|(u, _)| u);

    if signing_pubkey.is_some() && sig_url.is_none() {
        let _ = std::fs::remove_file(&setup_tmp);
        let _ = std::fs::remove_file(&sums_file);
        let _ = std::fs::remove_file(&sig_file);
        return Err("Missing SHA256SUMS.txt.sig Ed25519 signature asset. Update aborted.".into());
    }

    update_progress_state(|st| {
        st.phase = "downloading".into();
        st.active = true;
        st.latest_version = latest_ver.clone();
        st.downloaded_bytes = 0;
        st.total_bytes = setup_api_size;
        st.percent = 0;
        st.speed_bps = 0;
        st.error = None;
        st.message = if latest_ver.is_empty() {
            "Downloading Singularity update...".into()
        } else {
            format!("Downloading Singularity v{}...", latest_ver)
        };
    });

    let dl_started = std::time::Instant::now();
    let mut last_report = std::time::Instant::now()
        .checked_sub(std::time::Duration::from_millis(200))
        .unwrap_or(dl_started);
    let dl_setup = crate::winhttp_client::winhttp_download_https_to_file_with_progress(
        &setup_url,
        &setup_tmp,
        &ua,
        &[],
        10_000,
        240_000,
        350 * 1024 * 1024,
        |downloaded, http_total| {
            let total = if http_total > 0 {
                http_total
            } else {
                setup_api_size
            };
            let now = std::time::Instant::now();
            if now.duration_since(last_report) >= std::time::Duration::from_millis(80)
                || (total > 0 && downloaded >= total)
            {
                last_report = now;
                let elapsed = now.duration_since(dl_started).as_secs_f64().max(0.05);
                let speed = (downloaded as f64 / elapsed) as u64;
                let pct = if total > 0 {
                    ((downloaded.saturating_mul(99)) / total).min(99) as u8
                } else {
                    0
                };
                update_progress_state(|st| {
                    st.phase = "downloading".into();
                    st.downloaded_bytes = downloaded;
                    st.total_bytes = total;
                    st.percent = pct;
                    st.speed_bps = speed;
                });
            }
        },
    );
    let dl_sums = if dl_setup.is_ok() {
        update_progress_state(|st| {
            st.phase = "verifying".into();
            st.percent = 99;
            st.speed_bps = 0;
            st.message = "Verifying Ed25519 signature and SHA-256 checksum...".into();
        });
        crate::winhttp_client::winhttp_download_https_to_file(
            &sums_url,
            &sums_file,
            &ua,
            &[],
            10_000,
            25_000,
            512 * 1024,
        )
    } else {
        Err("Skipped sums".into())
    };
    if dl_setup.is_err() || dl_sums.is_err() || !setup_tmp.exists() || !sums_file.exists() {
        let _ = std::fs::remove_file(&setup_tmp);
        let _ = std::fs::remove_file(&sums_file);
        let _ = std::fs::remove_file(&sig_file);
        return Err(
            "Failed downloading Singularity-setup.exe or SHA256SUMS.txt from GitHub Releases."
                .into(),
        );
    }

    let sums_bytes = std::fs::read(&sums_file).map_err(|e| {
        let _ = std::fs::remove_file(&setup_tmp);
        let _ = std::fs::remove_file(&sums_file);
        let _ = std::fs::remove_file(&sig_file);
        format!("Failed reading SHA256SUMS.txt: {}", e)
    })?;
    let sums_content = String::from_utf8_lossy(&sums_bytes).into_owned();
    let _ = std::fs::remove_file(&sums_file);

    if let Some(ref pk_hex) = signing_pubkey {
        let Some(s_url) = sig_url else {
            let _ = std::fs::remove_file(&setup_tmp);
            let _ = std::fs::remove_file(&sig_file);
            return Err("Missing SHA256SUMS.txt.sig Ed25519 signature. Update aborted.".into());
        };
        if crate::winhttp_client::winhttp_download_https_to_file(
            &s_url,
            &sig_file,
            &ua,
            &[],
            8_000,
            15_000,
            64 * 1024,
        )
        .is_err()
        {
            let _ = std::fs::remove_file(&setup_tmp);
            let _ = std::fs::remove_file(&sig_file);
            return Err("Failed downloading SHA256SUMS.txt.sig. Update aborted.".into());
        }
        let sig_str = std::fs::read_to_string(&sig_file).map_err(|_| {
            let _ = std::fs::remove_file(&setup_tmp);
            let _ = std::fs::remove_file(&sig_file);
            "Missing SHA256SUMS.txt.sig Ed25519 signature. Update aborted.".to_string()
        })?;
        let _ = std::fs::remove_file(&sig_file);
        if let Err(err) = verify_sha256sums_ed25519(&sums_bytes, &sig_str, pk_hex) {
            let _ = std::fs::remove_file(&setup_tmp);
            return Err(err);
        }
    } else {
        let _ = std::fs::remove_file(&sig_file);
    }

    if let Err(err) =
        verify_downloaded_binary_sha256(&setup_tmp, &sums_content, "Singularity-setup.exe")
    {
        let _ = std::fs::remove_file(&setup_tmp);
        return Err(err);
    }

    update_progress_state(|st| {
        st.phase = "installing".into();
        st.percent = 100;
        if st.total_bytes > 0 {
            st.downloaded_bytes = st.total_bytes;
        }
        st.speed_bps = 0;
        st.message = "Installing update and relaunching Singularity...".into();
    });

    // Clear `running.lock` and arm `planned_restart.flag` so the upgraded browser restores all
    // open windows silently without triggering a false-positive `unclean_shutdown` crash popup.
    crate::crash_guard::mark_planned_restart(
        &crate::roaming_store::resolve_roaming_singularity_dir(),
    );

    // Final immediate SHA-256 re-verification right before spawn inside our user-private
    // `updates/` directory (zero sleep window!).
    if let Err(err) =
        verify_downloaded_binary_sha256(&setup_tmp, &sums_content, "Singularity-setup.exe")
    {
        let _ = std::fs::remove_file(&setup_tmp);
        return Err(err);
    }

    // Launch the verified native Win32 installer silently so it atomically installs/updates
    // `singularity.exe`, `libcef.dll`, and all Pure Chromium CEF runtime files, then relaunches.
    Command::new(&setup_tmp)
        .arg("--silent")
        .arg("--dir")
        .arg(target_dir)
        .arg("--launch")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .map_err(|e| format!("Failed launching verified installer: {}", e))?;
    std::process::exit(0);
}

/// Self-healing Windows runtime bootstrap: if `singularity.exe` was updated in-place from v1.0.x
/// (Edge WebView2) or run standalone without `libcef.dll`, downloads the verified
/// `Singularity-setup.exe` bundle and silently installs Pure Chromium CEF into the current folder.
#[cfg(target_os = "windows")]
pub fn bootstrap_missing_cef_runtime() -> Result<(), String> {
    let current_exe = std::env::current_exe()
        .map_err(|e| format!("Unable to locate current executable: {}", e))?;
    let target_dir = current_exe.parent().unwrap_or(Path::new("."));
    download_and_run_verified_setup_installer(target_dir, true)
}

/// Starts a background non-blocking self-update job so the UI can stream a live download
/// progress bar via `GET /api/updater/progress`.
pub fn start_self_update_async() -> UpdateProgressSnapshot {
    let mut should_spawn = false;
    let snap = update_progress_state(|st| {
        if !st.active {
            *st = UpdateProgressSnapshot {
                phase: "checking".into(),
                active: true,
                downloaded_bytes: 0,
                total_bytes: 0,
                percent: 0,
                speed_bps: 0,
                latest_version: String::new(),
                message: "Checking GitHub Releases...".into(),
                error: None,
            };
            should_spawn = true;
        }
    });
    if should_spawn {
        let _ = std::thread::Builder::new()
            .name("singularity-self-updater".into())
            .spawn(|| match execute_self_update() {
                Ok(msg) => {
                    update_progress_state(|st| {
                        st.active = false;
                        if st.phase != "installing" {
                            st.phase = "up_to_date".into();
                            st.percent = 100;
                            st.message = msg;
                        }
                    });
                }
                Err(err) => {
                    update_progress_state(|st| {
                        st.active = false;
                        st.phase = "error".into();
                        st.speed_bps = 0;
                        st.message = err.clone();
                        st.error = Some(err);
                    });
                }
            });
    }
    snap
}

/// Downloads, verifies Ed25519 signature + SHA-256 integrity, and atomically updates the
/// installation directly from public GitHub Release Assets at `https://github.com/MyMasha/Singularity`.
pub fn execute_self_update() -> Result<String, String> {
    update_progress_state(|st| {
        st.phase = "checking".into();
        st.active = true;
        st.error = None;
    });

    let force = std::env::var("SINGULARITY_FORCE_UPDATE").as_deref() == Ok("1");
    if !force {
        // Propagate check_for_updates() errors instead of masking them!
        let info = check_for_updates()?;
        update_progress_state(|st| {
            st.latest_version = info.latest_version.clone();
        });
        if !info.update_available {
            let msg = format!(
                "Singularity is already up to date (v{}).",
                info.current_version
            );
            update_progress_state(|st| {
                st.phase = "up_to_date".into();
                st.active = false;
                st.percent = 100;
                st.message = msg.clone();
            });
            return Ok(msg);
        }
    }

    let current_exe = std::env::current_exe()
        .map_err(|e| format!("Unable to locate current executable: {}", e))?;
    let target_dir = current_exe.parent().unwrap_or(Path::new("."));

    #[cfg(target_os = "windows")]
    {
        download_and_run_verified_setup_installer(target_dir, force)?;
        Ok("Singularity updater launched.".into())
    }

    #[cfg(not(target_os = "windows"))]
    {
        let allow_dev_unsigned =
            std::env::var("SINGULARITY_ALLOW_UNSIGNED_DEV_UPDATE").as_deref() == Ok("1");
        let signing_pubkey = resolve_mandatory_signing_pubkey(
            resolve_release_signing_pubkey_hex(),
            allow_dev_unsigned,
        )?;

        if !is_allowed_update_https_url(RELEASES_API_URL) {
            return Err("Update metadata URL failed strict GitHub host allowlist.".into());
        }

        let updates_dir = prepare_private_updates_dir()?;
        let new_exe = allocate_exclusive_update_file(&updates_dir, "singularity-update", ".bin")?;
        let sums_file = allocate_exclusive_update_file(&updates_dir, "SHA256SUMS", ".txt")?;
        let sig_file = allocate_exclusive_update_file(&updates_dir, "SHA256SUMS", ".txt.sig")?;

        let opt_token = resolve_github_token();
        let fetch_api = |tok: Option<&str>| -> Option<serde_json::Value> {
            let mut api_child = Command::new("curl")
                .args([
                    "-fsS",
                    "--proto",
                    "=https",
                    "--max-time",
                    "10",
                    "-K",
                    "-",
                    RELEASES_API_URL,
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .ok()?;
            if let Some(mut stdin) = api_child.stdin.take() {
                let _ = writeln!(
                    stdin,
                    "header = \"User-Agent: Singularity-Updater/{}\"",
                    CURRENT_VERSION
                );
                let _ = writeln!(stdin, "header = \"Accept: application/vnd.github+json\"");
                if let Some(t) = tok {
                    let clean_tok: String = t
                        .chars()
                        .filter(|c| !matches!(c, '\r' | '\n' | '"' | '\\' | '\0'))
                        .collect();
                    let _ = writeln!(stdin, "header = \"Authorization: Bearer {}\"", clean_tok);
                }
            }
            let api_out = api_child.wait_with_output().ok()?;
            if !api_out.status.success() {
                return None;
            }
            serde_json::from_slice(&api_out.stdout).ok()
        };

        let rel: serde_json::Value = match opt_token.as_deref() {
            Some(tok) => fetch_api(Some(tok)).or_else(|| fetch_api(None)),
            None => fetch_api(None),
        }
        .ok_or_else(|| {
            let _ = std::fs::remove_file(&new_exe);
            let _ = std::fs::remove_file(&sums_file);
            let _ = std::fs::remove_file(&sig_file);
            "Unable to fetch GitHub Release metadata.".to_string()
        })?;

        let latest_ver = rel
            .get("tag_name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .trim_start_matches('v')
            .to_string();
        let version_ok = if force {
            !latest_ver.is_empty() && !is_newer_semver(CURRENT_VERSION, &latest_ver)
        } else {
            is_newer_semver(&latest_ver, CURRENT_VERSION)
        };
        if !version_ok {
            let _ = std::fs::remove_file(&new_exe);
            let _ = std::fs::remove_file(&sums_file);
            let _ = std::fs::remove_file(&sig_file);
            return Err(format!(
                "Refused non-newer or downgrade release version '{}' (current v{}).",
                latest_ver, CURRENT_VERSION
            ));
        }

        let assets = rel
            .get("assets")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let find_asset_url = |name: &str| -> Option<String> {
            assets.iter().find_map(|a| {
                if a.get("name").and_then(|n| n.as_str()) == Some(name) {
                    a.get("browser_download_url")
                        .and_then(|u| u.as_str())
                        .filter(|u| is_allowed_update_https_url(u))
                        .map(|s| s.to_string())
                } else {
                    None
                }
            })
        };

        let Some(bin_url) = find_asset_url("singularity-linux-x86_64") else {
            let _ = std::fs::remove_file(&new_exe);
            let _ = std::fs::remove_file(&sums_file);
            let _ = std::fs::remove_file(&sig_file);
            return Err(
                "Release asset 'singularity-linux-x86_64' is unavailable or failed host allowlist."
                    .into(),
            );
        };
        let Some(sums_url) = find_asset_url("SHA256SUMS.txt") else {
            let _ = std::fs::remove_file(&new_exe);
            let _ = std::fs::remove_file(&sums_file);
            let _ = std::fs::remove_file(&sig_file);
            return Err(
                "Release asset 'SHA256SUMS.txt' is unavailable or failed host allowlist.".into(),
            );
        };
        let sig_url = find_asset_url("SHA256SUMS.txt.sig");
        if signing_pubkey.is_some() && sig_url.is_none() {
            let _ = std::fs::remove_file(&new_exe);
            let _ = std::fs::remove_file(&sums_file);
            let _ = std::fs::remove_file(&sig_file);
            return Err("Missing SHA256SUMS.txt.sig Ed25519 signature. Update aborted.".into());
        }

        let curl_download = |url: &str, out_path: &Path| -> bool {
            if !is_allowed_update_https_url(url) {
                return false;
            }
            let Ok(mut child) = Command::new("curl")
                .args([
                    "-fsSL",
                    "--max-redirs",
                    "5",
                    "--proto",
                    "=https",
                    "--proto-redir",
                    "=https",
                    "-K",
                    "-",
                    url,
                    "-o",
                    &out_path.to_string_lossy(),
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
            else {
                return false;
            };
            if let Some(mut stdin) = child.stdin.take() {
                let _ = writeln!(
                    stdin,
                    "header = \"User-Agent: Singularity-Updater/{}\"",
                    CURRENT_VERSION
                );
            }
            child.wait().is_ok_and(|s| s.success())
        };

        if !curl_download(&bin_url, &new_exe) || !curl_download(&sums_url, &sums_file) {
            let _ = std::fs::remove_file(&new_exe);
            let _ = std::fs::remove_file(&sums_file);
            let _ = std::fs::remove_file(&sig_file);
            return Err(
                "Failed downloading update binary or SHA256SUMS.txt from GitHub Releases.".into(),
            );
        }

        let sums_bytes = std::fs::read(&sums_file).map_err(|e| {
            let _ = std::fs::remove_file(&new_exe);
            let _ = std::fs::remove_file(&sums_file);
            let _ = std::fs::remove_file(&sig_file);
            format!("Failed reading SHA256SUMS.txt: {}", e)
        })?;
        let sums_content = String::from_utf8_lossy(&sums_bytes).into_owned();
        let _ = std::fs::remove_file(&sums_file);

        if let Some(ref pk_hex) = signing_pubkey {
            let Some(s_url) = sig_url else {
                let _ = std::fs::remove_file(&new_exe);
                let _ = std::fs::remove_file(&sig_file);
                return Err("Missing SHA256SUMS.txt.sig Ed25519 signature. Update aborted.".into());
            };
            if !curl_download(&s_url, &sig_file) {
                let _ = std::fs::remove_file(&new_exe);
                let _ = std::fs::remove_file(&sig_file);
                return Err("Failed downloading SHA256SUMS.txt.sig. Update aborted.".into());
            }
            let sig_str = std::fs::read_to_string(&sig_file).unwrap_or_default();
            let _ = std::fs::remove_file(&sig_file);
            if let Err(err) = verify_sha256sums_ed25519(&sums_bytes, &sig_str, pk_hex) {
                let _ = std::fs::remove_file(&new_exe);
                return Err(err);
            }
        } else {
            let _ = std::fs::remove_file(&sig_file);
        }

        if let Err(err) =
            verify_downloaded_binary_sha256(&new_exe, &sums_content, "singularity-linux-x86_64")
        {
            let _ = std::fs::remove_file(&new_exe);
            return Err(err);
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&new_exe)
                .map_err(|e| e.to_string())?
                .permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&new_exe, perms)
                .map_err(|e| format!("Failed setting executable permissions: {}", e))?;
        }

        // Atomic replace (fall back to same-filesystem staged copy + re-verify + rename on EXDEV).
        if std::fs::rename(&new_exe, &current_exe).is_err() {
            let staged_target = allocate_exclusive_update_file(target_dir, ".singularity-new", ".tmp")?;
            if let Err(e) = std::fs::copy(&new_exe, &staged_target) {
                let _ = std::fs::remove_file(&staged_target);
                let _ = std::fs::remove_file(&new_exe);
                return Err(format!("Failed staging verified binary: {}", e));
            }
            let _ = std::fs::remove_file(&new_exe);
            if let Err(err) = verify_downloaded_binary_sha256(
                &staged_target,
                &sums_content,
                "singularity-linux-x86_64",
            ) {
                let _ = std::fs::remove_file(&staged_target);
                return Err(err);
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = std::fs::metadata(&staged_target) {
                    let mut perms = meta.permissions();
                    perms.set_mode(0o755);
                    let _ = std::fs::set_permissions(&staged_target, perms);
                }
            }
            std::fs::rename(&staged_target, &current_exe).map_err(|e| {
                let _ = std::fs::remove_file(&staged_target);
                format!("Failed replacing binary: {}", e)
            })?;
        }

        crate::crash_guard::mark_planned_restart(
            &crate::roaming_store::resolve_roaming_singularity_dir(),
        );
        let _ = Command::new(&current_exe).stdin(Stdio::null()).spawn();
        std::process::exit(0);
    }
}

/// Computes the exact allowlisted uninstall targets inside `install_dir`.
/// Refuses directories that do not contain `singularity.exe`, never uses wildcards, and only
/// includes `locales/` if `libcef.dll` or `resources.pak` is present and `locales` is not a symlink.
pub fn collect_uninstall_targets(
    install_dir: &Path,
) -> Result<(Vec<PathBuf>, Option<PathBuf>), String> {
    let exe_path = install_dir.join("singularity.exe");
    let exe_meta = std::fs::symlink_metadata(&exe_path)
        .map_err(|_| "Uninstall aborted: install directory does not contain singularity.exe.".to_string())?;
    if exe_meta.file_type().is_symlink() || !exe_meta.is_file() {
        return Err("Uninstall aborted: singularity.exe is not a regular file.".into());
    }

    let has_cef_runtime = install_dir.join("libcef.dll").is_file()
        || install_dir.join("resources.pak").is_file();

    let mut files = Vec::new();
    for &exact_name in UNINSTALL_ALLOWED_EXACT_FILES {
        let candidate = install_dir.join(exact_name);
        if let Ok(meta) = std::fs::symlink_metadata(&candidate) {
            if !meta.file_type().is_symlink() && meta.is_file() {
                files.push(candidate);
            }
        }
    }

    let locales_target = if has_cef_runtime {
        let loc = install_dir.join("locales");
        match std::fs::symlink_metadata(&loc) {
            Ok(meta) if !meta.file_type().is_symlink() && meta.is_dir() => Some(loc),
            _ => None,
        }
    } else {
        None
    };

    Ok((files, locales_target))
}

/// Native Win32 Uninstaller invoked via `singularity.exe --uninstall` (supports `--silent`/`--quiet`).
pub fn execute_uninstall() -> Result<(), String> {
    let silent = std::env::args()
        .any(|a| a == "--silent" || a == "--quiet" || a.eq_ignore_ascii_case("/s"));
    execute_uninstall_with_mode(silent)
}

pub fn execute_uninstall_with_mode(silent: bool) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::ffi::OsStrExt;
        use std::os::windows::process::CommandExt;

        const MB_YESNO: u32 = 0x0000_0004;
        const MB_ICONQUESTION: u32 = 0x0000_0020;
        const MB_ICONWARNING: u32 = 0x0000_0030;
        const MB_ICONINFORMATION: u32 = 0x0000_0040;
        const IDYES: i32 = 6;
        const HKEY_CURRENT_USER: isize = -2147483647i32 as isize;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        const MOVEFILE_DELAY_UNTIL_REBOOT: u32 = 0x0000_0004;

        #[link(name = "user32")]
        extern "system" {
            fn MessageBoxW(
                hWnd: *mut core::ffi::c_void,
                lpText: *const u16,
                lpCaption: *const u16,
                uType: u32,
            ) -> i32;
        }
        #[link(name = "advapi32")]
        extern "system" {
            fn RegDeleteKeyW(hKey: isize, lpSubKey: *const u16) -> i32;
        }
        #[link(name = "kernel32")]
        extern "system" {
            fn MoveFileExW(
                lpExistingFileName: *const u16,
                lpNewFileName: *const u16,
                dwFlags: u32,
            ) -> i32;
        }

        fn wide(s: &str) -> Vec<u16> {
            std::ffi::OsStr::new(s).encode_wide().chain(Some(0)).collect()
        }

        let purge = if silent {
            false
        } else {
            let ans = unsafe {
                MessageBoxW(
                    core::ptr::null_mut(),
                    wide("Do you want to uninstall Singularity Browser from this computer?").as_ptr(),
                    wide("Uninstall Singularity").as_ptr(),
                    MB_YESNO | MB_ICONQUESTION,
                )
            };
            if ans != IDYES {
                return Ok(());
            }

            let p = unsafe {
                MessageBoxW(
                    core::ptr::null_mut(),
                    wide("Also delete your encrypted Roaming\\.singularity profile (sessions, vault, bookmarks, and extensions)?").as_ptr(),
                    wide("User Data (.singularity)").as_ptr(),
                    MB_YESNO | MB_ICONWARNING,
                )
            };
            p == IDYES
        };

        if let Ok(profile) = std::env::var("USERPROFILE") {
            let _ = std::fs::remove_file(Path::new(&profile).join("Desktop").join("Singularity.lnk"));
        }
        if let Ok(appdata) = std::env::var("APPDATA") {
            let _ = std::fs::remove_file(
                Path::new(&appdata)
                    .join("Microsoft")
                    .join("Windows")
                    .join("Start Menu")
                    .join("Programs")
                    .join("Singularity.lnk"),
            );
            if purge {
                let _ = std::fs::remove_dir_all(Path::new(&appdata).join(".singularity"));
            }
        }

        unsafe {
            let subkey = wide("Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Singularity");
            let _ = RegDeleteKeyW(HKEY_CURRENT_USER, subkey.as_ptr());
        }

        if let Ok(current_exe) = std::env::current_exe() {
            if let Some(install_dir) = current_exe.parent() {
                // Only proceed if the install directory demonstrably contains `singularity.exe`.
                if collect_uninstall_targets(install_dir).is_ok() {
                    let _ = std::fs::remove_file(install_dir.join("singularity.ico"));

                    let exe_w: Vec<u16> =
                        current_exe.as_os_str().encode_wide().chain(Some(0)).collect();
                    unsafe {
                        let _ = MoveFileExW(
                            exe_w.as_ptr(),
                            core::ptr::null(),
                            MOVEFILE_DELAY_UNTIL_REBOOT,
                        );
                    }

                    // Strict exact-name allowlist cleanup — zero wildcards, verifies `singularity.exe`
                    // presence first, and removes `locales` only if `libcef.dll` or `resources.pak` existed.
                    const PS_CLEANUP_SCRIPT: &str = r#"
Start-Sleep -Seconds 2
$dir = $env:SINGULARITY_DEL_DIR
if (-not $dir -or -not (Test-Path -LiteralPath $dir -PathType Container)) { exit 0 }
$exePath = Join-Path $dir 'singularity.exe'
if (-not (Test-Path -LiteralPath $exePath -PathType Leaf)) { exit 0 }
$hasCef = (Test-Path -LiteralPath (Join-Path $dir 'libcef.dll') -PathType Leaf) -or (Test-Path -LiteralPath (Join-Path $dir 'resources.pak') -PathType Leaf)
$allowedFiles = @(
    'singularity.exe',
    'singularity.ico',
    'libcef.dll',
    'chrome_elf.dll',
    'libEGL.dll',
    'libGLESv2.dll',
    'd3dcompiler_47.dll',
    'vk_swiftshader.dll',
    'vulkan-1.dll',
    'vk_swiftshader_icd.json',
    'icudtl.dat',
    'v8_context_snapshot.bin',
    'snapshot_blob.bin',
    'resources.pak',
    'chrome_100_percent.pak',
    'chrome_200_percent.pak',
    'cef.pak',
    'cef_100_percent.pak',
    'cef_200_percent.pak',
    'cef_extensions.pak',
    'devtools_resources.pak',
    'Launch-Singularity.bat',
    'Update-Singularity.bat',
    'Update-Singularity.ps1'
)
foreach ($name in $allowedFiles) {
    $p = Join-Path $dir $name
    if (Test-Path -LiteralPath $p -PathType Leaf) {
        $item = Get-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue
        if ($item -and -not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue
        }
    }
}
if ($hasCef) {
    $locDir = Join-Path $dir 'locales'
    if (Test-Path -LiteralPath $locDir -PathType Container) {
        $locItem = Get-Item -LiteralPath $locDir -Force -ErrorAction SilentlyContinue
        if ($locItem -and -not ($locItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            Remove-Item -LiteralPath $locDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
if ((Get-ChildItem -LiteralPath $dir -Force -ErrorAction SilentlyContinue | Measure-Object).Count -eq 0) {
    Remove-Item -LiteralPath $dir -Force -ErrorAction SilentlyContinue
}
"#;
                    let _ = Command::new(system_powershell_path())
                        .args([
                            "-NoProfile",
                            "-NonInteractive",
                            "-WindowStyle",
                            "Hidden",
                            "-Command",
                            PS_CLEANUP_SCRIPT,
                        ])
                        .env("SINGULARITY_DEL_DIR", install_dir)
                        .stdin(Stdio::null())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .creation_flags(CREATE_NO_WINDOW)
                        .spawn();
                }
            }
        }

        if !silent {
            unsafe {
                MessageBoxW(
                    core::ptr::null_mut(),
                    wide("Singularity has been uninstalled successfully.").as_ptr(),
                    wide("Singularity").as_ptr(),
                    MB_ICONINFORMATION,
                );
            }
        }
        return Ok(());
    }

    #[cfg(not(target_os = "windows"))]
    {
        if !silent {
            println!("To uninstall on Linux/macOS, remove the `singularity` binary and optionally ~/.singularity");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn test_ed25519_pubkey_fail_closed_policy() {
        let sk = SigningKey::from_bytes(&[0x11u8; 32]);
        let valid_hex = hex::encode(sk.verifying_key().to_bytes());
        assert!(is_valid_ed25519_pubkey_hex(&valid_hex));
        assert!(!is_valid_ed25519_pubkey_hex(""));
        assert!(!is_valid_ed25519_pubkey_hex("deadbeef"));

        // Valid configured key succeeds everywhere
        assert_eq!(
            resolve_mandatory_signing_pubkey(Some(&valid_hex), false).unwrap(),
            Some(valid_hex)
        );
        // Invalid non-empty key always errors
        assert!(resolve_mandatory_signing_pubkey(Some("not-hex"), true).is_err());
        // Missing key without opt-out always fails closed
        assert!(resolve_mandatory_signing_pubkey(None, false).is_err());
        assert!(resolve_mandatory_signing_pubkey(Some(""), false).is_err());

        #[cfg(debug_assertions)]
        assert_eq!(resolve_mandatory_signing_pubkey(None, true).unwrap(), None);
        #[cfg(not(debug_assertions))]
        assert!(resolve_mandatory_signing_pubkey(None, true).is_err());
    }

    #[test]
    fn test_allowed_update_https_host_allowlist() {
        for ok in [
            "https://github.com/MyMasha/Singularity/releases/latest",
            "https://api.github.com/repos/MyMasha/Singularity/releases/latest",
            "https://objects.githubusercontent.com/github-production-release-asset/foo",
            "https://release-assets.githubusercontent.com/bar",
            "https://github-releases.githubusercontent.com/baz",
            "HTTPS://GITHUB.COM/MyMasha/Singularity/releases/download/v2.0.10/SHA256SUMS.txt",
        ] {
            assert!(is_allowed_update_https_url(ok), "should allow {}", ok);
        }
        for bad in [
            "http://github.com/MyMasha/Singularity",
            "https://github.com:8443/MyMasha/Singularity",
            "https://evil.github.com.attacker.test/setup.exe",
            "https://raw.githubusercontent.com/MyMasha/Singularity/main/dist/SHA256SUMS.txt",
            "https://attacker.example/Singularity-setup.exe",
            "file:///tmp/Singularity-setup.exe",
        ] {
            assert!(!is_allowed_update_https_url(bad), "must reject {}", bad);
        }
    }

    #[test]
    fn test_semver_prerelease_numeric_and_sha256sums_malformed_lines() {
        // Numeric prerelease identifiers compared numerically (SemVer 2.0.0 §11.4)
        assert!(is_newer_semver("2.1.0-alpha.10", "2.1.0-alpha.2"));
        assert!(!is_newer_semver("2.1.0-alpha.2", "2.1.0-alpha.10"));
        assert!(is_newer_semver("2.1.0-rc.10", "2.1.0-rc.2"));
        assert!(is_newer_semver("2.1.0-alpha.beta", "2.1.0-alpha.1"));
        assert!(is_newer_semver("2.1.0-alpha.1", "2.1.0-alpha"));
        assert!(is_newer_semver("2.1.0", "2.1.0-rc.99"));
        assert!(!is_newer_semver("2.0.7", "2.0.8"));

        // Malformed single-token lines in SHA256SUMS.txt MUST be skipped, not abort parsing
        let manifest = "\
MALFORMED_SINGLE_TOKEN_LINE
not_a_hash_at_all
# comment line
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  *Singularity-setup.exe
";
        let digest = parse_sha256sums_for_asset(manifest, "Singularity-setup.exe")
            .expect("must skip malformed single-token lines and find valid checksum");
        assert_eq!(
            hex::encode(digest),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_private_updates_dir_and_uninstall_strict_allowlist() {
        let mut rnd = [0u8; 6];
        OsRng.fill_bytes(&mut rnd);
        let root = std::env::temp_dir().join(format!("singularity-upd-test-{}", hex::encode(rnd)));
        let _ = std::fs::remove_dir_all(&root);

        // Private updates dir + exclusive random file creation
        let updates_dir = prepare_private_updates_dir_at(&root).expect("create updates dir");
        let f1 = allocate_exclusive_update_file(&updates_dir, "Singularity-setup", ".exe")
            .expect("exclusive create");
        assert!(f1.is_file());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir_mode = std::fs::metadata(&updates_dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(dir_mode, 0o700);
            let file_mode = std::fs::metadata(&f1).unwrap().permissions().mode() & 0o777;
            assert_eq!(file_mode, 0o600);
        }

        // Uninstall allowlist refuses directory without singularity.exe
        let install_dir = root.join("install");
        std::fs::create_dir_all(install_dir.join("locales")).unwrap();
        std::fs::write(install_dir.join("user_important.dll"), b"keep").unwrap();
        std::fs::write(install_dir.join("user_game.pak"), b"keep").unwrap();
        std::fs::write(install_dir.join("user_data.dat"), b"keep").unwrap();
        std::fs::write(install_dir.join("user_save.bin"), b"keep").unwrap();
        assert!(collect_uninstall_targets(&install_dir).is_err());

        // With singularity.exe only (no libcef.dll / resources.pak), locales/ is NOT selected and user files are untouched
        std::fs::write(install_dir.join("singularity.exe"), b"exe").unwrap();
        let (files1, loc1) = collect_uninstall_targets(&install_dir).unwrap();
        assert_eq!(files1, vec![install_dir.join("singularity.exe")]);
        assert!(loc1.is_none());

        // With libcef.dll present, ONLY allowlisted files + locales/ are selected (never user *.dll/*.pak/*.dat/*.bin)
        std::fs::write(install_dir.join("libcef.dll"), b"cef").unwrap();
        std::fs::write(install_dir.join("icudtl.dat"), b"icu").unwrap();
        let (files2, loc2) = collect_uninstall_targets(&install_dir).unwrap();
        assert!(files2.contains(&install_dir.join("singularity.exe")));
        assert!(files2.contains(&install_dir.join("libcef.dll")));
        assert!(files2.contains(&install_dir.join("icudtl.dat")));
        assert!(!files2.contains(&install_dir.join("user_important.dll")));
        assert!(!files2.contains(&install_dir.join("user_game.pak")));
        assert!(!files2.contains(&install_dir.join("user_data.dat")));
        assert!(!files2.contains(&install_dir.join("user_save.bin")));
        assert_eq!(loc2, Some(install_dir.join("locales")));

        let _ = std::fs::remove_dir_all(&root);
    }
}
