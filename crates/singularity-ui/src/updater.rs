//! Verified Auto-Updater & Native Windows Uninstaller for Singularity Browser.
//!
//! - Connects directly to the public repository `https://github.com/MyMasha/Singularity`
//!   with zero embedded credentials or tokens.
//! - Verifies mandatory SHA-256 checksums (`SHA256SUMS.txt`) from the same GitHub Release
//!   before replacing or executing any binary (no fallback to mutable `main` branch).
//! - Supports optional out-of-band Ed25519 signature verification over `SHA256SUMS.txt`
//!   (`SHA256SUMS.txt.sig`) when `RELEASE_SIGNING_PUBKEY_HEX` is configured.
//! - Uses absolute `%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe` with
//!   `CREATE_NO_WINDOW` and environment-variable argument passing (zero shell interpolation,
//!   zero flashing consoles, and no SmartScreen ADS stripping).

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Serialize;
use sha2::{Digest, Sha256};
#[cfg(not(target_os = "windows"))]
use std::io::Write;
use std::path::Path;
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

/// Optional 64-hex-character Ed25519 public key used to verify `SHA256SUMS.txt.sig`
/// out-of-band. When non-empty, `execute_self_update()` refuses any release whose
/// `SHA256SUMS.txt` is missing or fails Ed25519 signature verification.
pub const RELEASE_SIGNING_PUBKEY_HEX: &str = "";

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

/// Cleans up leftover `.old` executable backups and temporary installer updates, and ensures
/// `%APPDATA%\.singularity` exists without stripping Windows SmartScreen protections.
pub fn perform_startup_maintenance() {
    let _ = crate::roaming_store::ensure_roaming_dir_initialized();

    if let Ok(current_exe) = std::env::current_exe() {
        let old_exe = if cfg!(target_os = "windows") {
            current_exe.with_extension("exe.old")
        } else {
            let mut p = current_exe.as_os_str().to_os_string();
            p.push(".old");
            std::path::PathBuf::from(p)
        };
        if old_exe.exists() {
            let _ = std::fs::remove_file(old_exe);
        }
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
fn system_powershell_path() -> std::path::PathBuf {
    if let Ok(sysroot) = std::env::var("SystemRoot") {
        let p = std::path::PathBuf::from(sysroot)
            .join("System32")
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe");
        if p.is_file() {
            return p;
        }
    }
    std::path::PathBuf::from(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
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
        .map_err(|_| "Unable to check for updates (offline or GitHub API unreachable).".to_string())?
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
        .unwrap_or(CURRENT_VERSION)
        .trim_start_matches('v')
        .to_string();
    let release_url = val
        .get("html_url")
        .and_then(|v| v.as_str())
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

/// SemVer 2.0 comparator: separates `major.minor.patch` from `-prerelease` tags and `+build` metadata.
pub fn is_newer_semver(candidate: &str, current: &str) -> bool {
    fn parse_semver(s: &str) -> Option<((u64, u64, u64), Option<String>)> {
        let stripped = s.trim().trim_start_matches('v');
        let no_build = stripped.split('+').next().unwrap_or(stripped);
        let (core, pre) = match no_build.split_once('-') {
            Some((c, p)) => (c, Some(p.to_string())),
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
        (Some(a), Some(b)) => a > b,
    }
}

/// Parses a `SHA256SUMS.txt` manifest and extracts the 32-byte digest for `asset_name`.
pub fn parse_sha256sums_for_asset(manifest: &str, asset_name: &str) -> Option<[u8; 32]> {
    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut parts = trimmed.split_whitespace();
        let hash_hex = parts.next()?;
        let file = parts.next()?.trim_start_matches('*');
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
fn download_and_run_verified_setup_installer(target_dir: &Path) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    let setup_tmp = std::env::temp_dir().join("Singularity-setup-update.exe");
    let sums_file = std::env::temp_dir().join("Singularity-SHA256SUMS.new.txt");
    let sig_file = std::env::temp_dir().join("Singularity-SHA256SUMS.new.txt.sig");
    let require_ed25519 = !RELEASE_SIGNING_PUBKEY_HEX.trim().is_empty();
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
    }?;

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
                    .filter(|u| u.starts_with("https://"))
                    .map(|s| s.to_string())
            } else {
                None
            }
        })
    };

    let Some(setup_url) = find_asset_url("Singularity-setup.exe") else {
        return Err("Release asset 'Singularity-setup.exe' is unavailable for the latest release.".into());
    };
    let Some(sums_url) = find_asset_url("SHA256SUMS.txt") else {
        return Err("Release asset 'SHA256SUMS.txt' is unavailable for the latest release.".into());
    };
    let sig_url = find_asset_url("SHA256SUMS.txt.sig");

    let dl_setup = crate::winhttp_client::winhttp_download_https_to_file(
        &setup_url,
        &setup_tmp,
        &ua,
        &[],
        10_000,
        240_000,
        350 * 1024 * 1024,
    );
    let dl_sums = if dl_setup.is_ok() {
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
        return Err("Failed downloading Singularity-setup.exe or SHA256SUMS.txt from GitHub Releases.".into());
    }
    if let Some(s_url) = sig_url {
        let _ = crate::winhttp_client::winhttp_download_https_to_file(
            &s_url,
            &sig_file,
            &ua,
            &[],
            8_000,
            15_000,
            64 * 1024,
        );
    }

    let sums_bytes = std::fs::read(&sums_file)
        .map_err(|e| format!("Failed reading SHA256SUMS.txt: {}", e))?;
    let sums_content = String::from_utf8_lossy(&sums_bytes).into_owned();
    let _ = std::fs::remove_file(&sums_file);

    if require_ed25519 {
        let sig_str = std::fs::read_to_string(&sig_file).map_err(|_| {
            let _ = std::fs::remove_file(&setup_tmp);
            "Missing SHA256SUMS.txt.sig Ed25519 signature. Update aborted.".to_string()
        })?;
        let _ = std::fs::remove_file(&sig_file);
        if let Err(err) =
            verify_sha256sums_ed25519(&sums_bytes, &sig_str, RELEASE_SIGNING_PUBKEY_HEX)
        {
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

    // Clear `running.lock` and arm `planned_restart.flag` so the upgraded browser restores all
    // open windows silently without triggering a false-positive `unclean_shutdown` crash popup.
    crate::crash_guard::mark_planned_restart(
        &crate::roaming_store::resolve_roaming_singularity_dir(),
    );

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
    download_and_run_verified_setup_installer(target_dir)
}

/// Downloads, verifies SHA-256 integrity (and Ed25519 signature when configured), and atomically
/// updates the installation directly from public GitHub Release Assets at
/// `https://github.com/MyMasha/Singularity`.
pub fn execute_self_update() -> Result<String, String> {
    let force = std::env::var("SINGULARITY_FORCE_UPDATE").as_deref() == Ok("1");
    if !force {
        if let Ok(info) = check_for_updates() {
            if !info.update_available {
                return Ok(format!(
                    "Singularity is already up to date (v{}).",
                    info.current_version
                ));
            }
        }
    }

    let current_exe = std::env::current_exe()
        .map_err(|e| format!("Unable to locate current executable: {}", e))?;
    let target_dir = current_exe.parent().unwrap_or(Path::new("."));

    #[cfg(target_os = "windows")]
    {
        download_and_run_verified_setup_installer(target_dir)?;
        Ok("Singularity updater launched.".into())
    }

    #[cfg(not(target_os = "windows"))]
    {
        let new_exe = target_dir.join("singularity.new");
        let sums_file = target_dir.join("SHA256SUMS.new.txt");
        let sig_file = target_dir.join("SHA256SUMS.new.txt.sig");
        let require_ed25519 = !RELEASE_SIGNING_PUBKEY_HEX.trim().is_empty();
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
                let _ = writeln!(stdin, "header = \"User-Agent: Singularity-Updater/{}\"", CURRENT_VERSION);
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
        .ok_or_else(|| "Unable to fetch GitHub Release metadata.".to_string())?;

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
                        .filter(|u| u.starts_with("https://"))
                        .map(|s| s.to_string())
                } else {
                    None
                }
            })
        };

        let sig_url = find_asset_url("SHA256SUMS.txt.sig");
        let (bin_url, sums_url) = if let (Some(b_url), Some(s_url)) = (
            find_asset_url("singularity-linux-x86_64"),
            find_asset_url("SHA256SUMS.txt"),
        ) {
            (b_url, s_url)
        } else {
            let tag = rel
                .get("tag_name")
                .and_then(|v| v.as_str())
                .filter(|t| {
                    !t.is_empty()
                        && t.bytes().all(|b| {
                            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')
                        })
                })
                .ok_or_else(|| "Release assets not found and tag name is invalid.".to_string())?;
            (
                format!(
                    "https://raw.githubusercontent.com/MyMasha/Singularity/{}/dist/singularity-linux-x86_64",
                    tag
                ),
                format!(
                    "https://raw.githubusercontent.com/MyMasha/Singularity/{}/dist/SHA256SUMS.txt",
                    tag
                ),
            )
        };

        let curl_download = |url: &str, out_path: &Path| -> bool {
            let Ok(mut child) = Command::new("curl")
                .args([
                    "-fsSL",
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
                let _ = writeln!(stdin, "header = \"User-Agent: Singularity-Updater/{}\"", CURRENT_VERSION);
            }
            child.wait().is_ok_and(|s| s.success())
        };

        if !curl_download(&bin_url, &new_exe) || !curl_download(&sums_url, &sums_file) {
            let _ = std::fs::remove_file(&new_exe);
            let _ = std::fs::remove_file(&sums_file);
            return Err("Failed downloading update binary or SHA256SUMS.txt from GitHub Releases.".into());
        }

        let sums_bytes = std::fs::read(&sums_file)
            .map_err(|e| format!("Failed reading SHA256SUMS.txt: {}", e))?;
        let sums_content = String::from_utf8_lossy(&sums_bytes).into_owned();
        let _ = std::fs::remove_file(&sums_file);

        if require_ed25519 {
            let Some(s_url) = sig_url else {
                let _ = std::fs::remove_file(&new_exe);
                return Err("Missing SHA256SUMS.txt.sig Ed25519 signature. Update aborted.".into());
            };
            if !curl_download(&s_url, &sig_file) {
                let _ = std::fs::remove_file(&new_exe);
                let _ = std::fs::remove_file(&sig_file);
                return Err("Failed downloading SHA256SUMS.txt.sig. Update aborted.".into());
            }
            let sig_str = std::fs::read_to_string(&sig_file).unwrap_or_default();
            let _ = std::fs::remove_file(&sig_file);
            if let Err(err) =
                verify_sha256sums_ed25519(&sums_bytes, &sig_str, RELEASE_SIGNING_PUBKEY_HEX)
            {
                let _ = std::fs::remove_file(&new_exe);
                return Err(err);
            }
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

        std::fs::rename(&new_exe, &current_exe)
            .map_err(|e| format!("Failed replacing binary: {}", e))?;
        crate::crash_guard::mark_planned_restart(
            &crate::roaming_store::resolve_roaming_singularity_dir(),
        );
        let _ = Command::new(&current_exe).stdin(Stdio::null()).spawn();
        std::process::exit(0);
    }
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
                let _ = std::fs::remove_file(install_dir.join("singularity.ico"));

                let exe_w: Vec<u16> = current_exe.as_os_str().encode_wide().chain(Some(0)).collect();
                unsafe {
                    let _ = MoveFileExW(exe_w.as_ptr(), core::ptr::null(), MOVEFILE_DELAY_UNTIL_REBOOT);
                }

                const PS_CLEANUP_SCRIPT: &str = r#"
Start-Sleep -Seconds 2
if ($env:SINGULARITY_DEL_EXE -and (Test-Path -LiteralPath $env:SINGULARITY_DEL_EXE)) {
    Remove-Item -LiteralPath $env:SINGULARITY_DEL_EXE -Force -ErrorAction SilentlyContinue
}
if ($env:SINGULARITY_DEL_DIR -and (Test-Path -LiteralPath $env:SINGULARITY_DEL_DIR)) {
    foreach ($pat in @('*.dll','*.pak','*.dat','*.bin','vk_swiftshader_icd.json','singularity.ico')) {
        Get-ChildItem -LiteralPath $env:SINGULARITY_DEL_DIR -Filter $pat -File -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
    }
    $locDir = Join-Path $env:SINGULARITY_DEL_DIR 'locales'
    if (Test-Path -LiteralPath $locDir) {
        Remove-Item -LiteralPath $locDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    if ((Get-ChildItem -LiteralPath $env:SINGULARITY_DEL_DIR -Force -ErrorAction SilentlyContinue | Measure-Object).Count -eq 0) {
        Remove-Item -LiteralPath $env:SINGULARITY_DEL_DIR -Force -ErrorAction SilentlyContinue
    }
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
                    .env("SINGULARITY_DEL_EXE", &current_exe)
                    .env("SINGULARITY_DEL_DIR", install_dir)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .creation_flags(CREATE_NO_WINDOW)
                    .spawn();
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
