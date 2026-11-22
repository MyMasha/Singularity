//! `%APPDATA%\.singularity` (`Roaming\.singularity`) Encrypted User Profile & Session Token Vault.
//!
//! Creates and manages the `.singularity` directory in Windows `AppData\Roaming\.singularity`
//! (or `~/.singularity` on Unix):
//! - `master.dpapi` / `master.key` : 256-bit master key protected by Windows DPAPI (`CryptProtectData`)
//! - `tokens.enc`                  : XChaCha20-Poly1305 AEAD encrypted OAuth & session tokens
//!                                   (Google, Microsoft, GitHub, Discord, Twitch, Apple, etc.)
//! - `vault.singularity-vault`     : Argon2id + XChaCha20-Poly1305 zero-knowledge password/2FA vault
//! - `settings.toml`               : Persisted user overrides across all 2,165 engine settings
//! - `profile.json`                : Bookmarks, search engine, onboarding state, history, preferences
//! - `browser-engine/`             : Persistent isolated WebView2 runtime profile directory

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key, XChaCha20Poly1305, XNonce,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
#[cfg(not(target_os = "windows"))]
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const TOKENS_ENVELOPE_MAGIC: &str = "SINGULARITY-ROAMING-TOKENS-V3-XCHACHA20-POLY1305";
#[cfg(not(target_os = "windows"))]
const UNIX_SEALED_KEY_MAGIC: &str = "SINGULARITY-UNIX-MASTER-V2";

/// Resolves `%APPDATA%\.singularity` on Windows (`C:\Users\<User>\AppData\Roaming\.singularity`)
/// or `~/.singularity` on Linux/macOS.
pub fn resolve_roaming_singularity_dir() -> PathBuf {
    if let Ok(override_dir) = std::env::var("SINGULARITY_ROAMING_DIR") {
        if !override_dir.trim().is_empty() {
            return PathBuf::from(override_dir);
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(appdata) = std::env::var("APPDATA") {
            if !appdata.trim().is_empty() {
                return PathBuf::from(appdata).join(".singularity");
            }
        }
        if let Ok(userprofile) = std::env::var("USERPROFILE") {
            if !userprofile.trim().is_empty() {
                return PathBuf::from(userprofile)
                    .join("AppData")
                    .join("Roaming")
                    .join(".singularity");
            }
        }
    }

    if let Ok(home) = std::env::var("HOME") {
        if !home.trim().is_empty() {
            return PathBuf::from(home).join(".singularity");
        }
    }

    // Isolated per-PID fallback instead of shared predictable `/tmp/.singularity`
    std::env::temp_dir().join(format!(".singularity-{}", std::process::id()))
}

/// Ensures `%APPDATA%\.singularity` and its `browser-engine` subdirectory exist and initializes
/// the sealed master key if not yet created.
pub fn ensure_roaming_dir_initialized() -> Result<PathBuf, String> {
    let dir = resolve_roaming_singularity_dir();
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("Failed to create {}: {}", dir.display(), e))?;
    let engine_dir = dir.join("browser-engine");
    let _ = std::fs::create_dir_all(&engine_dir);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for d in [&dir, &engine_dir] {
            if let Ok(meta) = std::fs::metadata(d) {
                let mut perms = meta.permissions();
                perms.set_mode(0o700);
                let _ = std::fs::set_permissions(d, perms);
            }
        }
    }

    let mut key = load_or_create_master_key(&dir)?;
    key.zeroize();
    Ok(dir)
}

#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct EncryptedAuthTokenRecord {
    pub id: String,
    pub provider: String,
    pub domain: String,
    pub path: String,
    pub token_name: String,
    pub secret_value: String,
    pub http_only: bool,
    pub secure: bool,
    #[zeroize(skip)]
    pub expires_unix: Option<i64>,
    #[zeroize(skip)]
    pub updated_unix: u64,
    pub kind: String,
}

impl EncryptedAuthTokenRecord {
    /// Returns a strictly redacted preview without exposing prefix characters or exact byte length.
    pub fn masked_preview(&self) -> String {
        let len = self.secret_value.chars().count();
        if len >= 20 {
            let suffix: String = self
                .secret_value
                .chars()
                .rev()
                .take(2)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            format!("••••••••••{}", suffix)
        } else {
            "••••••••••".to_string()
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RoamingTokensPlaintext {
    pub sessions: Vec<EncryptedAuthTokenRecord>,
    pub saved_mullvad_account: Option<String>,
}

impl Drop for RoamingTokensPlaintext {
    fn drop(&mut self) {
        if let Some(ref mut acc) = self.saved_mullvad_account {
            acc.zeroize();
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EncryptedTokensEnvelope {
    magic: String,
    xnonce_base64: String,
    ciphertext_base64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BookmarkEntry {
    pub id: String,
    pub title: String,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryItem {
    pub title: String,
    pub url: String,
    pub visited_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedTabEntry {
    pub title: String,
    pub url: String,
    #[serde(default)]
    pub media_time_sec: Option<u64>,
    #[serde(default)]
    pub scroll_y: Option<u32>,
    #[serde(default)]
    pub group_id: Option<String>,
    #[serde(default)]
    pub favicon_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SavedTabGroup {
    pub id: String,
    pub title: String,
    pub color: String,
    #[serde(default)]
    pub collapsed: bool,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct WindowGeometry {
    #[serde(default)]
    pub pos_x: Option<i32>,
    #[serde(default)]
    pub pos_y: Option<i32>,
    #[serde(default)]
    pub width: Option<u32>,
    #[serde(default)]
    pub height: Option<u32>,
    #[serde(default)]
    pub maximized: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowSessionFile {
    pub window_id: String,
    pub pid: u32,
    pub updated_unix: u64,
    #[serde(default)]
    pub active_tab_index: usize,
    #[serde(default)]
    pub tabs: Vec<SavedTabEntry>,
    #[serde(default)]
    pub tab_groups: Vec<SavedTabGroup>,
    #[serde(default)]
    pub geometry: WindowGeometry,
    /// Set to `true` only when this window closed cleanly while another Singularity window
    /// remained alive, so a window manually closed minutes/hours earlier is pruned on next
    /// boot while windows closed together during Windows Restart (<= 20s) or power loss all reopen.
    #[serde(default)]
    pub closed_while_other_live: bool,
}

/// Single-use sibling window restoration payload written under `%APPDATA%\.singularity\handoff\restore-<id>.json`
/// so restarting after running 2+ Singularity windows reopens EVERY window separately with its own
/// tabs, tab groups, active tab, and saved screen position/size instead of merging them into one!
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowRestorePayload {
    #[serde(default)]
    pub active_tab_index: usize,
    #[serde(default)]
    pub tabs: Vec<SavedTabEntry>,
    #[serde(default)]
    pub tab_groups: Vec<SavedTabGroup>,
    #[serde(default)]
    pub geometry: WindowGeometry,
}

/// Authenticated peer descriptor published by each live Singularity window in
/// `%APPDATA%\.singularity\windows\<window_id>.json` for instant cross-window tab transfers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveWindowDescriptor {
    pub window_id: String,
    pub pid: u32,
    pub port: u16,
    pub hwnd: isize,
    pub transfer_token: String,
    pub updated_unix: u64,
}

/// Single-use tab detach handoff payload written under `%APPDATA%\.singularity\handoff\<id>.json`
/// so tearing a tab out into a brand-new window never exposes URLs on OS command lines.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TabHandoffPayload {
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub favicon_url: Option<String>,
    #[serde(default)]
    pub media_time_sec: Option<u64>,
    #[serde(default)]
    pub scroll_y: Option<u32>,
    #[serde(default)]
    pub pos_x: Option<i32>,
    #[serde(default)]
    pub pos_y: Option<i32>,
}

pub fn is_valid_handoff_id(id: &str) -> bool {
    (16..=64).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_hexdigit())
}

fn default_restore_session() -> bool {
    true
}

fn default_tab_unload_mode() -> String {
    "medium".to_string()
}

fn default_tab_unload_custom_minutes() -> u64 {
    120
}

/// Strips volatile timestamp query parameters (`t=`, `time_continue=`, `start=`) so we can match
/// the same video across reloads or update its resume second cleanly.
pub fn normalize_url_without_media_time(url: &str) -> String {
    let (without_hash, _hash) = match url.split_once('#') {
        Some((b, h)) => (b, Some(h)),
        None => (url, None),
    };
    let Some((base, query)) = without_hash.split_once('?') else {
        return without_hash.to_string();
    };
    let kept: Vec<&str> = query
        .split('&')
        .filter(|pair| {
            let key = pair.split('=').next().unwrap_or("").to_ascii_lowercase();
            !matches!(key.as_str(), "" | "t" | "time_continue" | "start")
        })
        .collect();
    if kept.is_empty() {
        base.to_string()
    } else {
        format!("{}?{}", base, kept.join("&"))
    }
}

/// Injects an exact video playback timestamp into supported video URLs (YouTube watch/youtu.be,
/// Twitch VODs) when restoring a tab after shutdown/crash or RAM unload. For all other sites,
/// returns the original URL unchanged (handled by the universal HTML5 `<video>` resume seeker).
pub fn apply_media_timestamp_to_url(url: &str, time_sec: u64) -> String {
    if time_sec < 3 {
        return url.to_string();
    }
    let lower = url.to_ascii_lowercase();
    let is_youtube_watch = (lower.contains("://www.youtube.com/watch")
        || lower.contains("://youtube.com/watch")
        || lower.contains("://m.youtube.com/watch")
        || lower.contains("://music.youtube.com/watch")
        || lower.contains("://youtu.be/"))
        && !lower.contains("/live");
    let is_twitch_vod = lower.contains("://www.twitch.tv/videos/")
        || lower.contains("://twitch.tv/videos/")
        || lower.contains("://m.twitch.tv/videos/");

    if !is_youtube_watch && !is_twitch_vod {
        return url.to_string();
    }

    let (without_hash, hash) = match url.split_once('#') {
        Some((b, h)) => (b, Some(h)),
        None => (url, None),
    };
    let (base, existing_query) = match without_hash.split_once('?') {
        Some((b, q)) => (b, Some(q)),
        None => (without_hash, None),
    };

    let mut params: Vec<String> = existing_query
        .unwrap_or("")
        .split('&')
        .filter(|pair| {
            let key = pair.split('=').next().unwrap_or("").to_ascii_lowercase();
            !matches!(key.as_str(), "" | "t" | "time_continue" | "start")
        })
        .map(|s| s.to_string())
        .collect();

    if is_youtube_watch {
        params.push(format!("t={}s", time_sec));
    } else {
        let h = time_sec / 3600;
        let m = (time_sec % 3600) / 60;
        let s = time_sec % 60;
        params.push(format!("t={}h{}m{}s", h, m, s));
    }

    let mut rebuilt = format!("{}?{}", base, params.join("&"));
    if let Some(h) = hash {
        rebuilt.push('#');
        rebuilt.push_str(h);
    }
    rebuilt
}

/// Computes the tab RAM unload timeout in seconds for the 4 supported memory-saver modes:
/// - `"low"`    : relaxed memory saving (2 hours / 120 min)
/// - `"medium"` : balanced memory saving — unloads silent background tabs after 15 min (default)
/// - `"hard"`   : ultra-low RAM — unloads silent background tabs after 3 min
/// - `"custom"` : user-selected delay (`custom_minutes`, clamped 1 min..=30 days)
pub fn tab_unload_timeout_seconds(mode: &str, custom_minutes: u64) -> u64 {
    match mode {
        "low" => 2 * 3600,
        "medium" => 15 * 60,
        "hard" => 3 * 60,
        "custom" => custom_minutes.clamp(1, 43_200) * 60,
        _ => 15 * 60,
    }
}

pub fn default_theme_id() -> String {
    "singularity".to_string()
}

pub fn default_language() -> String {
    "en".to_string()
}

/// Validates a persisted UI language identifier (`"en"` English or `"fr"` French).
pub fn is_valid_language(lang: &str) -> bool {
    matches!(lang, "en" | "fr")
}

/// Validates a persisted cosmic UI / WebGL2 theme identifier.
pub fn is_valid_theme_id(id: &str) -> bool {
    matches!(
        id,
        "singularity" | "soleil" | "pulsar" | "nebuleuse" | "eclipse" | "aurore"
    )
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfile {
    pub onboarding_completed: bool,
    #[serde(default)]
    pub tutorial_v1_completed: bool,
    #[serde(default = "default_language")]
    pub language: String,
    #[serde(default = "default_theme_id")]
    pub theme_id: String,
    pub default_search_engine: String,
    #[serde(default = "default_restore_session")]
    pub restore_session: bool,
    #[serde(default)]
    pub session_restore_v2_migrated: bool,
    #[serde(default)]
    pub active_tab_index: usize,
    #[serde(default = "default_tab_unload_mode")]
    pub tab_unload_mode: String,
    #[serde(default = "default_tab_unload_custom_minutes")]
    pub tab_unload_custom_minutes: u64,
    #[serde(default)]
    pub pinned_extensions: Vec<String>,
    pub strict_mullvad_killswitch: bool,
    pub mullvad_auto_connect: bool,
    pub mullvad_entry_relay: String,
    pub mullvad_exit_relay: String,
    pub mullvad_multihop: bool,
    pub bookmarks: Vec<BookmarkEntry>,
    pub history: Vec<HistoryItem>,
    pub saved_tabs: Vec<SavedTabEntry>,
    #[serde(default)]
    pub saved_tab_groups: Vec<SavedTabGroup>,
}

impl Default for UserProfile {
    fn default() -> Self {
        Self {
            onboarding_completed: false,
            tutorial_v1_completed: false,
            language: default_language(),
            theme_id: default_theme_id(),
            default_search_engine: "ddg".to_string(),
            restore_session: true,
            session_restore_v2_migrated: true,
            active_tab_index: 0,
            tab_unload_mode: default_tab_unload_mode(),
            tab_unload_custom_minutes: default_tab_unload_custom_minutes(),
            pinned_extensions: Vec::new(),
            strict_mullvad_killswitch: false,
            mullvad_auto_connect: false,
            mullvad_entry_relay: "se-got-wg-001".to_string(),
            mullvad_exit_relay: "ch-zrh-wg-001".to_string(),
            mullvad_multihop: true,
            bookmarks: default_bookmarks(),
            history: Vec::new(),
            saved_tabs: Vec::new(),
            saved_tab_groups: Vec::new(),
        }
    }
}

pub fn default_bookmarks() -> Vec<BookmarkEntry> {
    vec![
        BookmarkEntry {
            id: "bm-google".into(),
            title: "Google".into(),
            url: "https://www.google.com".into(),
        },
        BookmarkEntry {
            id: "bm-youtube".into(),
            title: "YouTube".into(),
            url: "https://www.youtube.com".into(),
        },
        BookmarkEntry {
            id: "bm-github".into(),
            title: "GitHub".into(),
            url: "https://github.com".into(),
        },
        BookmarkEntry {
            id: "bm-discord".into(),
            title: "Discord".into(),
            url: "https://discord.com/app".into(),
        },
        BookmarkEntry {
            id: "bm-twitch".into(),
            title: "Twitch".into(),
            url: "https://www.twitch.tv".into(),
        },
        BookmarkEntry {
            id: "bm-wikipedia".into(),
            title: "Wikipedia".into(),
            url: "https://en.wikipedia.org".into(),
        },
        BookmarkEntry {
            id: "bm-ddg".into(),
            title: "DuckDuckGo".into(),
            url: "https://duckduckgo.com".into(),
        },
    ]
}

#[cfg(target_os = "windows")]
fn is_process_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    const STILL_ACTIVE: u32 = 259;
    #[link(name = "kernel32")]
    extern "system" {
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut core::ffi::c_void;
        fn GetExitCodeProcess(handle: *mut core::ffi::c_void, exit_code: *mut u32) -> i32;
        fn CloseHandle(handle: *mut core::ffi::c_void) -> i32;
    }
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return false;
        }
        let mut code: u32 = 0;
        let ok = GetExitCodeProcess(h, &mut code);
        CloseHandle(h);
        ok != 0 && code == STILL_ACTIVE
    }
}

#[cfg(not(target_os = "windows"))]
fn is_process_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    Path::new(&format!("/proc/{}", pid)).exists()
}

fn generate_window_id() -> String {
    let mut rnd = [0u8; 6];
    OsRng.fill_bytes(&mut rnd);
    format!("win-{}-{}", std::process::id(), hex::encode(rnd))
}

fn load_window_session_file(path: &Path) -> Option<WindowSessionFile> {
    if let Ok(raw) = std::fs::read_to_string(path) {
        if let Ok(parsed) = serde_json::from_str::<WindowSessionFile>(&raw) {
            return Some(parsed);
        }
    }
    let bak = path.with_extension("json.bak");
    if let Ok(raw) = std::fs::read_to_string(&bak) {
        if let Ok(parsed) = serde_json::from_str::<WindowSessionFile>(&raw) {
            return Some(parsed);
        }
    }
    None
}

/// High-level manager for `%APPDATA%\.singularity` encrypted tokens, user profile, settings, and vault.
pub struct RoamingSingularityStore {
    root_dir: PathBuf,
    window_id: String,
    ui_slot_lock_path: Option<PathBuf>,
    pub window_geometry: WindowGeometry,
    pub pending_restore_window_ids: Vec<String>,
    pub restored_windows_count: usize,
    pub merged_windows_count: usize,
    pub is_secondary_live_window: bool,
    pub startup_handoff: Option<TabHandoffPayload>,
    master_key: [u8; 32],
    pub profile: UserProfile,
    pub tokens: RoamingTokensPlaintext,
}

impl Drop for RoamingSingularityStore {
    fn drop(&mut self) {
        self.release_ui_webview_slot();
        self.master_key.zeroize();
    }
}

impl RoamingSingularityStore {
    pub fn open_default() -> Result<Self, String> {
        Self::open_default_with_launch_args(None, None, false)
    }

    pub fn open_default_with_options(
        detach_handoff_id: Option<&str>,
        force_new_window: bool,
    ) -> Result<Self, String> {
        Self::open_default_with_launch_args(detach_handoff_id, None, force_new_window)
    }

    pub fn open_default_with_launch_args(
        detach_handoff_id: Option<&str>,
        restore_session_id: Option<&str>,
        force_new_window: bool,
    ) -> Result<Self, String> {
        let dir = ensure_roaming_dir_initialized()?;
        Self::open_at_with_launch_args(dir, detach_handoff_id, restore_session_id, force_new_window)
    }

    pub fn open_at(root_dir: PathBuf) -> Result<Self, String> {
        Self::open_at_with_launch_args(root_dir, None, None, false)
    }

    pub fn open_at_with_options(
        root_dir: PathBuf,
        detach_handoff_id: Option<&str>,
        force_new_window: bool,
    ) -> Result<Self, String> {
        Self::open_at_with_launch_args(root_dir, detach_handoff_id, None, force_new_window)
    }

    pub fn open_at_with_launch_args(
        root_dir: PathBuf,
        detach_handoff_id: Option<&str>,
        restore_session_id: Option<&str>,
        force_new_window: bool,
    ) -> Result<Self, String> {
        std::fs::create_dir_all(&root_dir)
            .map_err(|e| format!("Cannot create {}: {}", root_dir.display(), e))?;
        let engine_dir = root_dir.join("browser-engine");
        let sessions_dir = root_dir.join("sessions");
        let favicons_dir = root_dir.join("favicons");
        let windows_dir = root_dir.join("windows");
        let handoff_dir = root_dir.join("handoff");
        let _ = std::fs::create_dir_all(&engine_dir);
        let _ = std::fs::create_dir_all(&sessions_dir);
        let _ = std::fs::create_dir_all(&favicons_dir);
        let _ = std::fs::create_dir_all(&windows_dir);
        let _ = std::fs::create_dir_all(&handoff_dir);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for d in [
                &root_dir,
                &engine_dir,
                &sessions_dir,
                &favicons_dir,
                &windows_dir,
                &handoff_dir,
            ] {
                if let Ok(meta) = std::fs::metadata(d) {
                    let mut perms = meta.permissions();
                    perms.set_mode(0o700);
                    let _ = std::fs::set_permissions(d, perms);
                }
            }
        }

        let master_key = load_or_create_master_key(&root_dir)?;
        let mut profile = load_profile(&root_dir);
        let mut migrated_profile = false;
        if !profile.session_restore_v2_migrated {
            profile.restore_session = true;
            profile.session_restore_v2_migrated = true;
            migrated_profile = true;
        }
        let tokens = load_encrypted_tokens(&root_dir, &master_key)?;
        let window_id = generate_window_id();
        let current_pid = std::process::id();

        let startup_handoff = detach_handoff_id
            .and_then(|id| Self::consume_detach_handoff(&root_dir, id));
        let restore_payload = if startup_handoff.is_none() {
            restore_session_id.and_then(|id| Self::consume_window_restore_handoff(&root_dir, id))
        } else {
            None
        };

        let mut window_geometry = WindowGeometry::default();
        let mut pending_restore_window_ids: Vec<String> = Vec::new();
        let mut restored_windows_count = 0usize;
        let merged_windows_count = 0usize;
        let mut is_secondary_live_window = false;
        let mut claimed_dead_paths: Vec<PathBuf> = Vec::new();

        if let Some(ref h) = startup_handoff {
            // Torn-off tab window: boot cleanly with ONLY this detached tab (never steal or
            // duplicate another window's open tabs!).
            is_secondary_live_window = true;
            profile.saved_tabs.clear();
            profile.saved_tab_groups.clear();
            profile.active_tab_index = 0;
            let trimmed_url = h.url.trim();
            let is_valid_settings = trimmed_url == "singularity://settings"
                || (trimmed_url.starts_with("singularity://settings/")
                    && trimmed_url.len() <= 64
                    && trimmed_url["singularity://settings/".len()..]
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
            if trimmed_url.starts_with("https://")
                || trimmed_url.starts_with("http://")
                || is_valid_settings
            {
                profile.saved_tabs.push(SavedTabEntry {
                    title: if h.title.trim().is_empty() {
                        trimmed_url.to_string()
                    } else {
                        h.title.trim().chars().take(180).collect()
                    },
                    url: trimmed_url.to_string(),
                    media_time_sec: h.media_time_sec,
                    scroll_y: h.scroll_y,
                    group_id: None,
                    favicon_url: h.favicon_url.clone(),
                });
            }
        } else if let Some(rp) = restore_payload {
            // Sibling window spawned on multi-window restart: restore ONLY this window's own
            // tabs, tab groups, active tab, and saved screen geometry!
            is_secondary_live_window = true;
            profile.saved_tabs = rp.tabs;
            profile.saved_tab_groups = rp.tab_groups;
            profile.active_tab_index = rp
                .active_tab_index
                .min(profile.saved_tabs.len().saturating_sub(1));
            window_geometry = rp.geometry;
            restored_windows_count = 1;
        } else if force_new_window {
            is_secondary_live_window = true;
            profile.saved_tabs.clear();
            profile.saved_tab_groups.clear();
            profile.active_tab_index = 0;
        } else {
            // Multi-window crash-proof separate session restoration:
            // - Simultaneous Singularity windows each persist their own `sessions/<win_id>.json`
            //   (tabs, tab groups, active tab, and screen geometry).
            // - On restart, Window #1 claims the first dead session and queues each remaining
            //   non-empty dead window session as a single-use `--restore-session <id>` handoff
            //   so EVERY previously open window reopens separately with its own tabs (never merged!).
            let crashed_prev = crate::crash_guard::has_unclean_crash_sentinel(&root_dir);
            let planned_restart = crate::crash_guard::consume_planned_restart_flag(&root_dir);
            let restore_all_checkpoint = crashed_prev || planned_restart;
            let mut live_other_windows = 0usize;
            let mut dead_sessions: Vec<(PathBuf, WindowSessionFile)> = Vec::new();
            if let Ok(entries) = std::fs::read_dir(&sessions_dir) {
                for ent in entries.flatten() {
                    let p = ent.path();
                    if p.extension().and_then(|e| e.to_str()) != Some("json") {
                        continue;
                    }
                    if p.file_name().and_then(|n| n.to_str()) == Some("crash_checkpoint.json") {
                        continue;
                    }
                    if let Some(sess) = load_window_session_file(&p) {
                        if sess.pid != current_pid && is_process_alive(sess.pid) {
                            live_other_windows += 1;
                        } else {
                            dead_sessions.push((p, sess));
                        }
                    }
                }
            }

            if live_other_windows > 0 {
                // Another Singularity window is already live: start this new window cleanly
                // with its own independent tab list without touching dead session files!
                is_secondary_live_window = true;
                profile.saved_tabs.clear();
                profile.saved_tab_groups.clear();
                profile.active_tab_index = 0;
            } else {
                let mut all_non_empty: Vec<WindowSessionFile> = Vec::new();
                dead_sessions.sort_by_key(|(_, s)| s.updated_unix);
                for (path, sess) in dead_sessions {
                    claimed_dead_paths.push(path);
                    if !sess.tabs.is_empty() {
                        all_non_empty.push(sess);
                    }
                }
                if restore_all_checkpoint || all_non_empty.is_empty() {
                    for cp_sess in Self::load_crash_checkpoint_at(&root_dir) {
                        if cp_sess.tabs.is_empty() {
                            continue;
                        }
                        if let Some(existing) =
                            all_non_empty.iter_mut().find(|s| s.window_id == cp_sess.window_id)
                        {
                            if cp_sess.updated_unix >= existing.updated_unix {
                                *existing = cp_sess;
                            }
                        } else {
                            all_non_empty.push(cp_sess);
                        }
                    }
                }
                if !all_non_empty.is_empty() {
                    let latest_active_unix = all_non_empty
                        .iter()
                        .filter(|s| !s.closed_while_other_live)
                        .map(|s| s.updated_unix)
                        .max()
                        .or_else(|| all_non_empty.iter().map(|s| s.updated_unix).max())
                        .unwrap_or(0);
                    // On crash recovery or planned OS/updater restart, restore EVERY non-empty
                    // window from the last checkpoint. On normal restart, restore every window
                    // still open at exit (`!closed_while_other_live`) OR closed within 20s of the
                    // last window (multi-window exit).
                    let non_empty_dead: Vec<WindowSessionFile> = all_non_empty
                        .into_iter()
                        .filter(|s| {
                            restore_all_checkpoint
                                || !s.closed_while_other_live
                                || latest_active_unix.saturating_sub(s.updated_unix) <= 20
                        })
                        .collect();

                    if let Some(first) = non_empty_dead.first() {
                        profile.saved_tabs = first.tabs.clone();
                        profile.saved_tab_groups = first.tab_groups.clone();
                        profile.active_tab_index = first
                            .active_tab_index
                            .min(profile.saved_tabs.len().saturating_sub(1));
                        window_geometry = first.geometry;
                        restored_windows_count = 1;

                        if profile.restore_session {
                            // Spawn each additional dead window as its own independent Singularity window
                            // (capped at 7 extra windows = 8 total for safety).
                            for sibling in non_empty_dead.into_iter().skip(1).take(7) {
                                let rp = WindowRestorePayload {
                                    active_tab_index: sibling.active_tab_index,
                                    tabs: sibling.tabs,
                                    tab_groups: sibling.tab_groups,
                                    geometry: sibling.geometry,
                                };
                                if let Ok(rid) = Self::write_window_restore_handoff_at(&root_dir, &rp) {
                                    pending_restore_window_ids.push(rid);
                                }
                            }
                            restored_windows_count += pending_restore_window_ids.len();
                        }
                    }
                }
            }
        }

        let store = Self {
            root_dir,
            window_id,
            ui_slot_lock_path: None,
            window_geometry,
            pending_restore_window_ids,
            restored_windows_count,
            merged_windows_count,
            is_secondary_live_window,
            startup_handoff,
            master_key,
            profile,
            tokens,
        };

        if !store.tokens_file_path().exists() {
            let _ = store.save_tokens();
        }
        if !claimed_dead_paths.is_empty() {
            let _ = store.save_window_session();
            if !store.is_secondary_live_window {
                let _ = store.save_profile();
            }
            for old_p in claimed_dead_paths {
                if old_p != store.window_session_file_path() {
                    let _ = std::fs::remove_file(&old_p);
                    let _ = std::fs::remove_file(old_p.with_extension("json.bak"));
                }
            }
        } else if migrated_profile || !store.profile_file_path().exists() {
            let _ = store.save_profile();
        } else if !store.profile.saved_tabs.is_empty() {
            let _ = store.save_window_session();
        }

        Ok(store)
    }

    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    pub fn window_id(&self) -> &str {
        &self.window_id
    }

    pub fn sessions_dir(&self) -> PathBuf {
        self.root_dir.join("sessions")
    }

    pub fn favicons_dir(&self) -> PathBuf {
        self.root_dir.join("favicons")
    }

    pub fn windows_dir(&self) -> PathBuf {
        self.root_dir.join("windows")
    }

    pub fn handoff_dir(&self) -> PathBuf {
        self.root_dir.join("handoff")
    }

    pub fn window_session_file_path(&self) -> PathBuf {
        self.sessions_dir().join(format!("{}.json", self.window_id))
    }

    /// Deletes this window's persisted session files (called when exiting empty or after moving
    /// this window's only tab into another window so it never reopens as a duplicate ghost window).
    pub fn delete_window_session(&self) {
        let p = self.window_session_file_path();
        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_file(p.with_extension("json.bak"));
    }

    pub fn live_window_file_path(&self) -> PathBuf {
        self.windows_dir().join(format!("{}.json", self.window_id))
    }

    /// Publishes this window's authenticated loopback transfer descriptor so other Singularity
    /// windows can drop dragged tabs directly into this window.
    pub fn register_live_window(&self, port: u16, hwnd: isize, transfer_token: &str) {
        let _ = std::fs::create_dir_all(self.windows_dir());
        let desc = LiveWindowDescriptor {
            window_id: self.window_id.clone(),
            pid: std::process::id(),
            port,
            hwnd,
            transfer_token: transfer_token.to_string(),
            updated_unix: unix_now(),
        };
        if let Ok(bytes) = serde_json::to_vec(&desc) {
            let _ = atomic_write(&self.live_window_file_path(), &bytes);
        }
    }

    /// Removes this window's live peer descriptor on clean shutdown.
    pub fn unregister_live_window(&self) {
        let _ = std::fs::remove_file(self.live_window_file_path());
    }

    /// Lists all other currently alive Singularity windows (pruning stale descriptors from dead PIDs).
    pub fn list_other_live_windows(&self) -> Vec<LiveWindowDescriptor> {
        let current_pid = std::process::id();
        let Ok(entries) = std::fs::read_dir(self.windows_dir()) else {
            return Vec::new();
        };
        let mut live = Vec::new();
        for ent in entries.flatten() {
            let p = ent.path();
            if p.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let Ok(raw) = std::fs::read_to_string(&p) else {
                continue;
            };
            let Ok(desc) = serde_json::from_str::<LiveWindowDescriptor>(&raw) else {
                let _ = std::fs::remove_file(&p);
                continue;
            };
            if desc.window_id == self.window_id || desc.pid == current_pid {
                continue;
            }
            if is_process_alive(desc.pid) {
                live.push(desc);
            } else {
                let _ = std::fs::remove_file(&p);
            }
        }
        live.sort_by_key(|d| d.updated_unix);
        live
    }

    /// Writes a single-use tab detach handoff file and returns its random 32-hex-char ID.
    pub fn write_detach_handoff(&self, payload: &TabHandoffPayload) -> Result<String, String> {
        let dir = self.handoff_dir();
        let _ = std::fs::create_dir_all(&dir);
        let mut rnd = [0u8; 16];
        OsRng.fill_bytes(&mut rnd);
        let id = hex::encode(rnd);
        let bytes = serde_json::to_vec(payload)
            .map_err(|e| format!("Failed serializing tab handoff: {}", e))?;
        atomic_write(&dir.join(format!("{}.json", id)), &bytes)?;
        Ok(id)
    }

    /// Reads and immediately deletes a single-use tab detach handoff file.
    pub fn consume_detach_handoff(root_dir: &Path, handoff_id: &str) -> Option<TabHandoffPayload> {
        if !is_valid_handoff_id(handoff_id) {
            return None;
        }
        let path = root_dir
            .join("handoff")
            .join(format!("{}.json", handoff_id));
        let raw = std::fs::read_to_string(&path).ok()?;
        let _ = std::fs::remove_file(&path);
        serde_json::from_str::<TabHandoffPayload>(&raw).ok()
    }

    /// Writes a single-use sibling window restore handoff (`handoff/restore-<id>.json`).
    pub fn write_window_restore_handoff_at(
        root_dir: &Path,
        payload: &WindowRestorePayload,
    ) -> Result<String, String> {
        let dir = root_dir.join("handoff");
        let _ = std::fs::create_dir_all(&dir);
        let mut rnd = [0u8; 16];
        OsRng.fill_bytes(&mut rnd);
        let id = hex::encode(rnd);
        let bytes = serde_json::to_vec(payload)
            .map_err(|e| format!("Failed serializing window restore handoff: {}", e))?;
        atomic_write(&dir.join(format!("restore-{}.json", id)), &bytes)?;
        Ok(id)
    }

    /// Reads and immediately deletes a single-use sibling window restore handoff.
    pub fn consume_window_restore_handoff(
        root_dir: &Path,
        restore_id: &str,
    ) -> Option<WindowRestorePayload> {
        if !is_valid_handoff_id(restore_id) {
            return None;
        }
        let path = root_dir
            .join("handoff")
            .join(format!("restore-{}.json", restore_id));
        let raw = std::fs::read_to_string(&path).ok()?;
        let _ = std::fs::remove_file(&path);
        serde_json::from_str::<WindowRestorePayload>(&raw).ok()
    }

    /// Pure Chromium (CEF) persistent profile & cache directory (`%APPDATA%\.singularity\cef-profile`).
    /// Shared across ALL windows & tabs inside Singularity's single Chromium browser process (0% Edge!).
    pub fn chromium_profile_dir(&self) -> PathBuf {
        self.root_dir.join("cef-profile")
    }

    pub fn webview_engine_dir(&self) -> PathBuf {
        self.root_dir.join("browser-engine")
    }

    pub fn ui_webview_dir(&self) -> PathBuf {
        self.root_dir.join("browser-ui")
    }

    /// Generates a unique collision-free window session identifier for a new in-process CEF window.
    pub fn new_window_session_id() -> String {
        let mut rnd = [0u8; 6];
        OsRng.fill_bytes(&mut rnd);
        format!("win-{}-{}", std::process::id(), hex::encode(rnd))
    }

    /// Persists a specific in-process window's tabs, groups, active tab, and geometry to
    /// `sessions/<window_id>.json` (+ `.bak`), enabling clean multi-window restart inside a single
    /// low-RAM Chromium process.
    #[allow(clippy::too_many_arguments)]
    pub fn save_window_session_for(
        &self,
        window_id: &str,
        tabs: &[SavedTabEntry],
        tab_groups: &[SavedTabGroup],
        active_tab_index: usize,
        geometry: WindowGeometry,
        closed_while_other_live: bool,
        write_backup: bool,
    ) -> Result<(), String> {
        let sessions_dir = self.sessions_dir();
        let _ = std::fs::create_dir_all(&sessions_dir);
        let sess = WindowSessionFile {
            window_id: window_id.to_string(),
            pid: std::process::id(),
            updated_unix: unix_now(),
            active_tab_index: active_tab_index.min(tabs.len().saturating_sub(1)),
            tabs: tabs.to_vec(),
            tab_groups: tab_groups.to_vec(),
            geometry,
            closed_while_other_live,
        };
        let bytes = serde_json::to_vec(&sess)
            .map_err(|e| format!("Window session serialization error: {}", e))?;
        let path = sessions_dir.join(format!("{}.json", window_id));
        atomic_write(&path, &bytes)?;
        if write_backup && !sess.tabs.is_empty() {
            let _ = atomic_write(&path.with_extension("json.bak"), &bytes);
        }
        Ok(())
    }

    /// Deletes a specific in-process window's persisted session files when closed empty or
    /// after its only tab was transferred to another window.
    pub fn delete_window_session_for(&self, window_id: &str) {
        if window_id.is_empty()
            || !window_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return;
        }
        let p = self.sessions_dir().join(format!("{}.json", window_id));
        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_file(p.with_extension("json.bak"));
    }

    /// Atomically persists a rolling multi-window crash-recovery checkpoint containing ALL open
    /// windows, tabs, groups, active indices, geometries, and latest video timestamps.
    pub fn save_crash_checkpoint(&self, sessions: &[WindowSessionFile]) {
        if sessions.is_empty() {
            return;
        }
        let sessions_dir = self.sessions_dir();
        let _ = std::fs::create_dir_all(&sessions_dir);
        if let Ok(bytes) = serde_json::to_vec(sessions) {
            let _ = atomic_write(&sessions_dir.join("crash_checkpoint.json"), &bytes);
        }
    }

    /// Loads the rolling multi-window crash-recovery checkpoint if present.
    pub fn load_crash_checkpoint_at(root_dir: &Path) -> Vec<WindowSessionFile> {
        let p = root_dir.join("sessions").join("crash_checkpoint.json");
        let Ok(bytes) = std::fs::read(&p) else {
            return Vec::new();
        };
        serde_json::from_slice::<Vec<WindowSessionFile>>(&bytes).unwrap_or_default()
    }

    /// Allocates an isolated, reusable per-live-window WebView2 user-data directory
    /// (`browser-ui-slots/slot-<N>`) so concurrent Singularity windows never collide on a shared
    /// `browser-ui` WebView2 host process (`0x8007139F` environment mismatch, startup stall, or
    /// cross-window black screen).
    pub fn allocate_ui_webview_slot(&mut self) -> PathBuf {
        use std::io::Write as _;
        if let Some(ref existing_lock) = self.ui_slot_lock_path {
            if let Some(parent) = existing_lock.parent() {
                return parent.to_path_buf();
            }
        }
        let slots_root = self.root_dir.join("browser-ui-slots");
        let _ = std::fs::create_dir_all(&slots_root);
        let current_pid = std::process::id();
        let owner_payload = format!("{}\n{}\n", current_pid, self.window_id);

        for idx in 0..32usize {
            let slot_dir = slots_root.join(format!("slot-{}", idx));
            let _ = std::fs::create_dir_all(&slot_dir);
            let lock_path = slot_dir.join(".owner.pid");

            if let Ok(raw) = std::fs::read_to_string(&lock_path) {
                let mut lines = raw.lines();
                let owner_pid = lines
                    .next()
                    .and_then(|l| l.trim().parse::<u32>().ok())
                    .unwrap_or(0);
                let owner_win = lines.next().unwrap_or("").trim();
                if owner_pid != 0
                    && is_process_alive(owner_pid)
                    && (owner_pid != current_pid || owner_win != self.window_id)
                {
                    continue;
                }
                let _ = std::fs::remove_file(&lock_path);
            }

            if let Ok(mut f) = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&lock_path)
            {
                let _ = f.write_all(owner_payload.as_bytes());
                self.ui_slot_lock_path = Some(lock_path);
                return slot_dir;
            }
        }

        let fallback = slots_root.join(format!("ephemeral-{}", self.window_id));
        let _ = std::fs::create_dir_all(&fallback);
        fallback
    }

    pub fn release_ui_webview_slot(&mut self) {
        if let Some(lock_path) = self.ui_slot_lock_path.take() {
            let _ = std::fs::remove_file(lock_path);
        }
    }

    pub fn extensions_dir(&self) -> PathBuf {
        crate::extensions::enabled_extensions_dir(&self.root_dir)
    }

    pub fn effective_tab_unload_seconds(&self) -> u64 {
        tab_unload_timeout_seconds(
            &self.profile.tab_unload_mode,
            self.profile.tab_unload_custom_minutes,
        )
    }

    pub fn tokens_file_path(&self) -> PathBuf {
        self.root_dir.join("tokens.enc")
    }

    pub fn vault_file_path(&self) -> PathBuf {
        self.root_dir.join("vault.singularity-vault")
    }

    pub fn settings_file_path(&self) -> PathBuf {
        self.root_dir.join("settings.toml")
    }

    pub fn profile_file_path(&self) -> PathBuf {
        self.root_dir.join("profile.json")
    }

    pub fn profile_backup_file_path(&self) -> PathBuf {
        self.root_dir.join("profile.json.bak")
    }

    pub fn has_encrypted_vault_on_disk(&self) -> bool {
        self.vault_file_path().is_file()
    }

    pub fn read_vault_envelope_from_disk(&self) -> Result<String, String> {
        std::fs::read_to_string(self.vault_file_path())
            .map_err(|e| format!("Impossible de lire le coffre-fort: {}", e))
    }

    pub fn write_vault_envelope_to_disk(&self, encrypted_envelope: &str) -> Result<(), String> {
        atomic_write(&self.vault_file_path(), encrypted_envelope.as_bytes())
    }

    fn has_other_live_windows_at(root_dir: &Path, own_window_id: &str) -> bool {
        let current_pid = std::process::id();
        let Ok(entries) = std::fs::read_dir(root_dir.join("sessions")) else {
            return false;
        };
        for ent in entries.flatten() {
            let p = ent.path();
            if p.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            if let Some(sess) = load_window_session_file(&p) {
                if sess.window_id != own_window_id
                    && sess.pid != current_pid
                    && is_process_alive(sess.pid)
                {
                    return true;
                }
            }
        }
        false
    }

    fn write_window_session_snapshot(
        root_dir: &Path,
        window_id: &str,
        profile: &UserProfile,
        geometry: WindowGeometry,
        closed_while_other_live: bool,
        write_backup: bool,
    ) -> Result<(), String> {
        let sessions_dir = root_dir.join("sessions");
        let _ = std::fs::create_dir_all(&sessions_dir);
        let sess = WindowSessionFile {
            window_id: window_id.to_string(),
            pid: std::process::id(),
            updated_unix: unix_now(),
            active_tab_index: profile.active_tab_index,
            tabs: profile.saved_tabs.clone(),
            tab_groups: profile.saved_tab_groups.clone(),
            geometry,
            closed_while_other_live,
        };
        let bytes = serde_json::to_vec(&sess)
            .map_err(|e| format!("Window session serialization error: {}", e))?;
        let path = sessions_dir.join(format!("{}.json", window_id));
        atomic_write(&path, &bytes)?;
        if write_backup && !sess.tabs.is_empty() {
            let _ = atomic_write(&path.with_extension("json.bak"), &bytes);
        }
        Ok(())
    }

    fn write_profile_snapshot(
        root_dir: &Path,
        window_id: &str,
        profile: &UserProfile,
        geometry: WindowGeometry,
        write_backup: bool,
    ) -> Result<(), String> {
        let _ = Self::write_window_session_snapshot(
            root_dir,
            window_id,
            profile,
            geometry,
            false,
            write_backup,
        );
        let mut to_write = profile.clone();
        if Self::has_other_live_windows_at(root_dir, window_id) {
            let existing_disk = load_profile(root_dir);
            if !existing_disk.saved_tabs.is_empty() {
                to_write.saved_tabs = existing_disk.saved_tabs;
                to_write.saved_tab_groups = existing_disk.saved_tab_groups;
                to_write.active_tab_index = existing_disk.active_tab_index;
            }
        }
        let json = serde_json::to_vec(&to_write)
            .map_err(|e| format!("Profile serialization error: {}", e))?;
        atomic_write(&root_dir.join("profile.json"), &json)?;
        if write_backup && !to_write.saved_tabs.is_empty() {
            let _ = atomic_write(&root_dir.join("profile.json.bak"), &json);
        }
        Ok(())
    }

    /// Atomically persists THIS window's own tabs, active tab, tab groups, and window geometry to
    /// `sessions/<window_id>.json` + `.bak` so multiple simultaneous windows never clash.
    pub fn save_window_session(&self) -> Result<(), String> {
        Self::write_window_session_snapshot(
            &self.root_dir,
            &self.window_id,
            &self.profile,
            self.window_geometry,
            false,
            true,
        )
    }

    /// Persists or cleans up THIS window's session on clean exit:
    /// - If this window has zero saved web tabs, removes its session file (no blank ghost windows).
    /// - Otherwise saves its final tabs & screen geometry and records whether another Singularity
    ///   window was still alive at close time (so Windows Restart / multi-window exit reopens all
    ///   windows separately while a window manually closed long before shutdown stays closed).
    pub fn save_window_session_on_close(&self) {
        if self.profile.saved_tabs.is_empty() {
            self.delete_window_session();
            return;
        }
        let other_live = Self::has_other_live_windows_at(&self.root_dir, &self.window_id);
        let _ = Self::write_window_session_snapshot(
            &self.root_dir,
            &self.window_id,
            &self.profile,
            self.window_geometry,
            other_live,
            true,
        );
    }

    pub fn save_profile(&self) -> Result<(), String> {
        Self::write_profile_snapshot(
            &self.root_dir,
            &self.window_id,
            &self.profile,
            self.window_geometry,
            true,
        )
    }

    /// Zero-stall non-blocking persistence for hot UI / HTTP paths: clones the in-memory profile
    /// in microseconds and coalesces disk flushes on a dedicated background Rust I/O thread
    /// (writing `.bak` mirrors at most every 30s so NTFS `FlushFileBuffers` never stalls the UI).
    pub fn schedule_save_profile(&self) {
        profile_persist_worker().enqueue(
            self.root_dir.clone(),
            self.window_id.clone(),
            self.profile.clone(),
            self.window_geometry,
        );
    }

    /// Synchronously drains any pending background profile writes (called on clean shutdown).
    pub fn flush_async_persistence(&self) {
        profile_persist_worker().flush_now();
    }

    /// Updates the saved video playback timestamp & scroll offset of the matching saved tab
    /// in memory (returns `true` if modified).
    pub fn update_saved_tab_media_progress(
        &mut self,
        url: &str,
        time_sec: u64,
        scroll_y: u32,
    ) -> bool {
        let norm_target = normalize_url_without_media_time(url);
        let mut changed = false;
        for entry in &mut self.profile.saved_tabs {
            if normalize_url_without_media_time(&entry.url) == norm_target {
                let next_time = if time_sec >= 2 { Some(time_sec) } else { entry.media_time_sec };
                let next_scroll = if scroll_y > 0 { Some(scroll_y) } else { entry.scroll_y };
                if entry.media_time_sec != next_time || entry.scroll_y != next_scroll {
                    entry.media_time_sec = next_time;
                    entry.scroll_y = next_scroll;
                    changed = true;
                }
                break;
            }
        }
        changed
    }

    pub fn save_settings_toml(&self, toml_content: &str) -> Result<(), String> {
        atomic_write(&self.settings_file_path(), toml_content.as_bytes())
    }

    pub fn load_settings_toml(&self) -> Option<String> {
        std::fs::read_to_string(self.settings_file_path()).ok()
    }

    /// Encrypts `self.tokens` with XChaCha20-Poly1305 AEAD and writes atomically to `tokens.enc`.
    pub fn save_tokens(&self) -> Result<(), String> {
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&self.master_key));
        let mut nonce_bytes = [0u8; 24];
        OsRng.fill_bytes(&mut nonce_bytes);
        let xnonce = XNonce::from_slice(&nonce_bytes);

        let mut plaintext = serde_json::to_vec(&self.tokens)
            .map_err(|e| format!("Token store serialization error: {}", e))?;

        let payload = Payload {
            msg: &plaintext,
            aad: TOKENS_ENVELOPE_MAGIC.as_bytes(),
        };
        let enc_res = cipher.encrypt(xnonce, payload);
        plaintext.zeroize();
        let ciphertext =
            enc_res.map_err(|_| "XChaCha20-Poly1305 token encryption failed".to_string())?;

        let env = EncryptedTokensEnvelope {
            magic: TOKENS_ENVELOPE_MAGIC.to_string(),
            xnonce_base64: BASE64.encode(nonce_bytes),
            ciphertext_base64: BASE64.encode(ciphertext),
        };
        let encoded = serde_json::to_vec_pretty(&env)
            .map_err(|e| format!("Envelope serialization error: {}", e))?;
        atomic_write(&self.tokens_file_path(), &encoded)
    }

    /// Inserts or updates a session/OAuth token and persists `tokens.enc` encrypted on disk.
    pub fn upsert_token(&mut self, record: EncryptedAuthTokenRecord) -> Result<(), String> {
        if let Some(existing) = self.tokens.sessions.iter_mut().find(|r| r.id == record.id) {
            *existing = record;
        } else {
            self.tokens.sessions.push(record);
        }
        self.save_tokens()
    }

    /// Batch-upserts multiple captured browser cookies/tokens and writes `tokens.enc` once if changed.
    pub fn upsert_tokens_batch(
        &mut self,
        incoming: Vec<EncryptedAuthTokenRecord>,
    ) -> Result<usize, String> {
        if incoming.is_empty() {
            return Ok(0);
        }
        let mut changed = 0usize;
        for rec in incoming {
            if let Some(existing) = self.tokens.sessions.iter_mut().find(|r| r.id == rec.id) {
                if existing.secret_value != rec.secret_value
                    || existing.expires_unix != rec.expires_unix
                {
                    *existing = rec;
                    changed += 1;
                }
            } else {
                self.tokens.sessions.push(rec);
                changed += 1;
            }
        }
        if changed > 0 {
            self.save_tokens()?;
        }
        Ok(changed)
    }

    /// Removes all encrypted tokens matching a specific provider (e.g. `"Google"`, `"Microsoft"`),
    /// token ID, or `"ALL"` wildcard.
    pub fn remove_tokens_by_provider_or_id(&mut self, target: &str) -> Result<usize, String> {
        let before = self.tokens.sessions.len();
        if target.eq_ignore_ascii_case("ALL") {
            self.tokens.sessions.clear();
        } else {
            self.tokens.sessions.retain(|t| {
                !t.provider.eq_ignore_ascii_case(target) && t.id != target
            });
        }
        let removed = before.saturating_sub(self.tokens.sessions.len());
        if removed > 0 {
            self.save_tokens()?;
        }
        Ok(removed)
    }

    pub fn clear_all_tokens(&mut self) -> Result<(), String> {
        self.tokens.sessions.clear();
        self.save_tokens()
    }

    /// Records a history item in RAM without forcing an immediate disk `fsync`.
    /// Call `save_profile()` periodically or on shutdown to persist coalesced updates.
    pub fn record_history_in_memory(&mut self, title: &str, url: &str) {
        if !url.starts_with("https://") && !url.starts_with("http://") {
            return;
        }
        let now = unix_now();
        self.profile.history.retain(|h| h.url != url);
        self.profile.history.insert(
            0,
            HistoryItem {
                title: if title.trim().is_empty() {
                    url.to_string()
                } else {
                    title.trim().to_string()
                },
                url: url.to_string(),
                visited_unix: now,
            },
        );
        if self.profile.history.len() > 400 {
            self.profile.history.truncate(400);
        }
    }

    pub fn record_history(&mut self, title: &str, url: &str) {
        self.record_history_in_memory(title, url);
        let _ = self.save_profile();
    }

    pub fn toggle_bookmark(&mut self, title: &str, url: &str) -> bool {
        if !url.starts_with("https://") && !url.starts_with("http://") {
            return false;
        }
        if let Some(pos) = self.profile.bookmarks.iter().position(|b| b.url == url) {
            self.profile.bookmarks.remove(pos);
            let _ = self.save_profile();
            false
        } else {
            let mut rnd = [0u8; 6];
            OsRng.fill_bytes(&mut rnd);
            let id = format!("bm-{}-{}", unix_now(), hex::encode(rnd));
            self.profile.bookmarks.push(BookmarkEntry {
                id,
                title: if title.trim().is_empty() {
                    url.to_string()
                } else {
                    title.trim().to_string()
                },
                url: url.to_string(),
            });
            let _ = self.save_profile();
            true
        }
    }
}

fn matches_domain_or_sub(domain_no_leading_dot: &str, suffix: &str) -> bool {
    domain_no_leading_dot == suffix
        || (domain_no_leading_dot.len() > suffix.len()
            && domain_no_leading_dot.ends_with(suffix)
            && domain_no_leading_dot.as_bytes()[domain_no_leading_dot.len() - suffix.len() - 1]
                == b'.')
}

fn is_google_or_youtube_domain(d: &str) -> bool {
    const GOOGLE_DOMAINS: &[&str] = &[
        "google.com",
        "google.fr",
        "google.be",
        "google.ch",
        "google.ca",
        "google.co.uk",
        "google.de",
        "google.es",
        "google.it",
        "google.nl",
        "google.jp",
        "youtube.com",
        "youtu.be",
    ];
    GOOGLE_DOMAINS
        .iter()
        .any(|g| matches_domain_or_sub(d, g))
}

/// Classifies whether a browser cookie is an authentication/login session token (Google, Microsoft,
/// GitHub, Discord, Twitch, Apple, X, or OAuth/SSO session cookies) that should be encrypted in
/// `%APPDATA%\.singularity\tokens.enc`.
pub fn classify_auth_cookie(domain: &str, cookie_name: &str) -> Option<&'static str> {
    let d = domain.trim_start_matches('.').to_ascii_lowercase();
    let n = cookie_name.to_ascii_lowercase();

    if is_google_or_youtube_domain(&d) {
        const GOOGLE_AUTH: &[&str] = &[
            "sid",
            "hsid",
            "ssid",
            "apisid",
            "sapisid",
            "lsid",
            "__secure-1psid",
            "__secure-3psid",
            "__secure-1papisid",
            "__secure-3papisid",
            "__secure-1psidts",
            "__secure-3psidts",
            "__secure-1psidcc",
            "__secure-3psidcc",
            "__host-gaps",
            "__host-1plsid",
            "__host-3plsid",
            "account_chooser",
            "login_info",
            "smsv",
        ];
        if GOOGLE_AUTH.contains(&n.as_str()) || n.contains("psid") || n.contains("oauth") {
            return Some("Google");
        }
    }

    let is_microsoft = matches_domain_or_sub(&d, "live.com")
        || matches_domain_or_sub(&d, "microsoft.com")
        || matches_domain_or_sub(&d, "microsoftonline.com")
        || matches_domain_or_sub(&d, "office.com")
        || matches_domain_or_sub(&d, "outlook.com");
    if is_microsoft {
        const MS_AUTH: &[&str] = &[
            "estsauth",
            "estsauthpersistent",
            "estsauthlight",
            "wlssc",
            "mspauth",
            "mspprof",
            "mspok",
            "pplstate",
            "signinstatecookie",
            "oparams",
            "rpssecauth",
            "anon",
            "nap",
        ];
        if MS_AUTH.contains(&n.as_str()) || n.contains("auth") || n.contains("token") {
            return Some("Microsoft");
        }
    }

    if matches_domain_or_sub(&d, "github.com") {
        if matches!(
            n.as_str(),
            "user_session" | "__host-user_session_same_site" | "logged_in" | "dotcom_user" | "_gh_sess"
        ) {
            return Some("GitHub");
        }
    }

    if matches_domain_or_sub(&d, "discord.com") {
        if n.contains("token") || n == "__dcfduid" || n == "__sdcfduid" {
            return Some("Discord");
        }
    }

    if matches_domain_or_sub(&d, "twitch.tv") {
        if matches!(n.as_str(), "auth-token" | "persistent" | "login" | "twilight-user") {
            return Some("Twitch");
        }
    }

    if matches_domain_or_sub(&d, "apple.com") || matches_domain_or_sub(&d, "icloud.com") {
        if n.contains("myacinfo") || n.contains("webauth") || n == "dsid" {
            return Some("Apple");
        }
    }

    if matches_domain_or_sub(&d, "x.com") || matches_domain_or_sub(&d, "twitter.com") {
        if matches!(n.as_str(), "auth_token" | "ct0" | "twid") {
            return Some("X / Twitter");
        }
    }

    if is_tiktok_domain(&d) {
        const TIKTOK_AUTH: &[&str] = &[
            "sessionid",
            "sessionid_ss",
            "sid_tt",
            "uid_tt",
            "uid_tt_ss",
            "sid_guard",
            "sid_ucp_v1",
            "ssid_ucp_v1",
            "odin_tt",
            "cmpl_token",
            "tt_chain_token",
            "passport_auth_status",
            "passport_auth_status_ss",
        ];
        if TIKTOK_AUTH.contains(&n.as_str()) {
            return Some("TikTok");
        }
    }

    // Generic OAuth / SSO / Session cookies on other sites
    if n.contains("access_token")
        || n.contains("refresh_token")
        || n.contains("id_token")
        || n.contains("auth_token")
        || n.contains("session_token")
        || n == "sessionid"
        || n == "connect.sid"
    {
        return Some("Session Web");
    }

    None
}

fn is_tiktok_domain(d: &str) -> bool {
    const TIKTOK_DOMAINS: &[&str] = &[
        "tiktok.com",
        "tiktokv.com",
        "tiktokv.eu",
        "tiktokv.us",
        "tiktokw.us",
        "tiktokw.eu",
        "byteoversea.com",
        "bytedance.com",
        "byteimg.com",
        "bytescm.com",
        "tiktokcdn.com",
        "tiktokcdn-us.com",
        "tiktokcdn-eu.com",
        "tiktokcdn-in.com",
        "ttwstatic.com",
        "ttlivecdn.com",
        "tiktokstaticb.com",
        "ibytedtos.com",
        "ibyteimg.com",
        "muscdn.com",
        "musical.ly",
        "tiktokglobalshop.com",
    ];
    TIKTOK_DOMAINS.iter().any(|t| matches_domain_or_sub(d, t))
}

/// Classification for selective cookie scrubbing: ONLY trackers, ad-network cookies, and
/// malicious/injected cookies are ever removed; 100% of login tokens, sessions, consent,
/// CSRF, anti-bot, and functional cookies are strictly preserved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CookieThreatKind {
    Tracker,
    Advertising,
    Malicious,
}

/// Returns `true` for cookies that are strictly protected (auth tokens, `__Host-`/`__Secure-`
/// security cookies, Google/YouTube consent & anti-abuse cookies, TikTok first-party session &
/// anti-bot cookies, Cloudflare/CSRF/session cookies) and must NEVER be deleted by selective cleanup.
pub fn is_protected_session_or_functional_cookie(domain: &str, cookie_name: &str) -> bool {
    if classify_auth_cookie(domain, cookie_name).is_some() {
        return true;
    }
    let d = domain.trim_start_matches('.').to_ascii_lowercase();
    let n = cookie_name.trim().to_ascii_lowercase();
    if n.starts_with("__host-") || n.starts_with("__secure-") {
        return true;
    }
    // Preserve ALL first-party TikTok anti-bot, feed, device & pixel-compat cookies on TikTok's own
    // domains (while still blocking 3rd-party `_ttp` ad pixel cookies on external websites).
    if is_tiktok_domain(&d) {
        return true;
    }
    const ESSENTIAL_COOKIES: &[&str] = &[
        // Google / YouTube consent, security & playback state
        "socs",
        "consent",
        "aec",
        "nid",
        "otz",
        "pref",
        "gps",
        "ysc",
        "visitor_info1_live",
        "visitor_privacy_metadata",
        "login_info",
        "ogp",
        "ogpc",
        "dv",
        "cgic",
        "stx_gp",
        // TikTok / anti-bot / Cloudflare / Akamai / DataDome / WAF / CSRF / standard web sessions
        "ttwid",
        "mstoken",
        "s_v_web_id",
        "tt_csrf_token",
        "passport_csrf_token",
        "passport_csrf_token_default",
        "passport_fe_beating_status",
        "tt_webid",
        "tt_webid_v2",
        "store-idc",
        "store-country-code",
        "tt-target-idc",
        "webapp_launch_mode",
        "ak_bmsc",
        "bm_sz",
        "_abck",
        "datadome",
        "px3",
        "_px3",
        "_pxvid",
        "cf_clearance",
        "__cf_bm",
        "_cfuvid",
        "cf_chl_2",
        "cf_chl_prog",
        "csrftoken",
        "csrf_token",
        "xsrf-token",
        "__requestverificationtoken",
        "phpsessid",
        "jsessionid",
        "aspsessionid",
        "asp.net_sessionid",
        "laravel_session",
        "_session_id",
        "session_id",
        "session",
        "sid",
        "remember_me",
        "c_user",
        "xs",
        "datr",
        "sb",
        "wd",
    ];
    if ESSENTIAL_COOKIES.contains(&n.as_str()) {
        return true;
    }
    n.contains("csrf") || n.contains("xsrf") || n.contains("session") || n.contains("auth")
}

/// Classifies whether a cookie is strictly a tracker, advertising cookie, or malicious cookie
/// eligible for surgical deletion. Returns `None` for all legitimate session, login, consent,
/// and functional cookies.
pub fn classify_tracker_or_malicious_cookie(
    domain: &str,
    cookie_name: &str,
    cookie_value: &str,
) -> Option<CookieThreatKind> {
    let d = domain.trim_start_matches('.').to_ascii_lowercase();
    let n = cookie_name.trim().to_ascii_lowercase();

    // 1. Malicious / XSS-injected / cookie-bombing payloads (checked even before name allowlist
    //    except for pure auth tokens — an oversized >8 KiB or `<script>` payload is never valid).
    let val_lower = cookie_value.to_ascii_lowercase();
    let has_injection_payload = cookie_value.len() > 8192
        || val_lower.contains("<script")
        || val_lower.contains("</script")
        || val_lower.contains("javascript:")
        || val_lower.contains("vbscript:")
        || val_lower.contains("onerror=")
        || val_lower.contains("onload=")
        || val_lower.contains("document.cookie");
    if has_injection_payload {
        return Some(CookieThreatKind::Malicious);
    }

    const MALICIOUS_DOMAINS: &[&str] = &[
        "coinhive.com",
        "coin-hive.com",
        "cryptoloot.pro",
        "jsecoin.com",
        "minero.cc",
        "webminepool.com",
        "propellerads.com",
        "popads.net",
        "popcash.net",
        "exoclick.com",
        "juicyads.com",
        "trafficjunky.net",
        "clickadu.com",
        "hilltopads.net",
        "adsterra.com",
        "acscdn.com",
        "pushame.com",
        "monetag.com",
        "onclickalgo.com",
        "onclkds.com",
        "pushwelcome.com",
        "notifpush.com",
    ];
    if MALICIOUS_DOMAINS
        .iter()
        .any(|m| matches_domain_or_sub(&d, m))
    {
        return Some(CookieThreatKind::Malicious);
    }

    // 2. Hard protection for all auth tokens, sessions, consent, security & functional cookies.
    if is_protected_session_or_functional_cookie(&d, &n) {
        return None;
    }

    // 3. Dedicated advertising network domains (never host user login accounts).
    const AD_DOMAINS: &[&str] = &[
        "doubleclick.net",
        "googlesyndication.com",
        "googleadservices.com",
        "adservice.google.com",
        "adservice.google.fr",
        "ads.google.com",
        "adnxs.com",
        "criteo.com",
        "criteo.net",
        "taboola.com",
        "outbrain.com",
        "pubmatic.com",
        "rubiconproject.com",
        "openx.net",
        "casalemedia.com",
        "advertising.com",
        "adsrvr.org",
        "amazon-adsystem.com",
        "sharethrough.com",
        "smartadserver.com",
        "bidswitch.net",
        "moatads.com",
        "doubleverify.com",
        "adsafeprotected.com",
        "indexww.com",
        "lijit.com",
        "yieldmo.com",
        "teads.tv",
        "33across.com",
        "mathtag.com",
        "turn.com",
        "adform.net",
        "adroll.com",
        "rtbhouse.com",
        "zemanta.com",
        "revcontent.com",
        "mgid.com",
        "ads-twitter.com",
        "ads.linkedin.com",
        "px.ads.linkedin.com",
        "bat.bing.com",
        "media.net",
        "sovrn.com",
        "gumgum.com",
        "triplelift.com",
        "spotxchange.com",
        "springserve.com",
        "lkqd.net",
        "adcolony.com",
        "applovin.com",
        "unityads.unity3d.com",
        "vungle.com",
        "ironsrc.com",
        "flurry.com",
    ];
    if AD_DOMAINS.iter().any(|a| matches_domain_or_sub(&d, a)) {
        return Some(CookieThreatKind::Advertising);
    }

    // 4. Dedicated analytics, behavioral tracking & data-broker domains.
    const TRACKER_DOMAINS: &[&str] = &[
        "google-analytics.com",
        "googletagmanager.com",
        "analytics.google.com",
        "facebook.net",
        "connect.facebook.net",
        "scorecardresearch.com",
        "quantserve.com",
        "hotjar.com",
        "mouseflow.com",
        "fullstory.com",
        "mixpanel.com",
        "segment.io",
        "segment.com",
        "amplitude.com",
        "clarity.ms",
        "demdex.net",
        "krxd.net",
        "bluekai.com",
        "rlcdn.com",
        "tapad.com",
        "exelator.com",
        "eyeota.net",
        "agkn.com",
        "crwdcntrl.net",
        "lotame.com",
        "omtrdc.net",
        "2o7.net",
        "everesttech.net",
        "newrelic.com",
        "nr-data.net",
        "bugsnag.com",
        "sentry-cdn.com",
        "branch.io",
        "adjust.com",
        "appsflyer.com",
        "kochava.com",
        "singular.net",
        "chartbeat.net",
        "parsely.com",
        "kissmetrics.com",
        "crazyegg.com",
        "luckyorange.com",
        "inspectlet.com",
        "heap.io",
        "heapanalytics.com",
        "pendo.io",
    ];
    if TRACKER_DOMAINS
        .iter()
        .any(|t| matches_domain_or_sub(&d, t))
    {
        return Some(CookieThreatKind::Tracker);
    }

    // 5. Unambiguous first-party-injected advertising cookies (Meta Pixel, Google Ads, Criteo, Prebid, etc.).
    const AD_COOKIE_NAMES: &[&str] = &[
        "_gcl_au",
        "_gcl_aw",
        "_gcl_dc",
        "_gcl_gb",
        "_gcl_gf",
        "_gcl_ha",
        "_fbp",
        "_fbc",
        "_uetvid",
        "_uetsid",
        "_ttp",
        "_tt_enable_cookie",
        "_pin_unauth",
        "_scid",
        "_sctr",
        "_rdt_uuid",
        "li_fat_id",
        "li_sugr",
        "_li_dcdm_c",
        "cto_bundle",
        "cto_bidid",
        "cto_tld_test",
        "_sharedid",
        "sharedid",
        "_pubcid",
        "anj",
        "uuid2",
        "tuuid",
        "tuuid_lu",
        "everest_g_v2",
        "ad-id",
        "ad-privacy",
        "ads_prefs",
        "taboola_select",
        "trc_cookie_storage",
        "outbrain_cid_fetch",
    ];
    if AD_COOKIE_NAMES.contains(&n.as_str())
        || n.starts_with("_gcl_")
        || n.starts_with("_gac_")
        || n.starts_with("pbjs_")
        || n.starts_with("_pbjs_")
        || n.starts_with("panoramaid")
        || n.starts_with("cto_")
    {
        return Some(CookieThreatKind::Advertising);
    }

    // 6. Unambiguous analytics / session-replay / behavioral tracker cookies.
    const TRACKER_COOKIE_NAMES: &[&str] = &[
        "_ga",
        "_gid",
        "_gat",
        "__utma",
        "__utmb",
        "__utmc",
        "__utmt",
        "__utmz",
        "__utmv",
        "_clck",
        "_clsk",
        "_hjid",
        "_hjfirstseen",
        "_hjabsolutesessioninprogress",
        "_hjincludedinpageviewsample",
        "_hjtldtest",
        "ajs_anonymous_id",
        "ajs_group_id",
        "hubspotutk",
        "__hstc",
        "__hssc",
        "__hssrc",
        "_mkto_trk",
        "optimizelyenduserid",
        "demdex",
        "dpm",
        "s_vi",
        "s_fid",
        "s_cc",
        "s_sq",
        "_ym_uid",
        "_ym_d",
        "_ym_isad",
        "_ym_visorc",
        "_cc_id",
        "_cc_aud",
        "_cc_cc",
        "_cc_dc",
        "lotame_domain_check",
        "personalization_id",
    ];
    if TRACKER_COOKIE_NAMES.contains(&n.as_str())
        || n.starts_with("_ga_")
        || n.starts_with("_gat_")
        || n.starts_with("_hjsession")
        || n.starts_with("_vwo_uuid")
        || n.starts_with("_vis_opt_")
        || (n.starts_with("mp_") && n.ends_with("_mixpanel"))
        || n.starts_with("amplitude_id_")
        || n.starts_with("_sp_id.")
        || n.starts_with("_sp_ses.")
        || n.starts_with("amcv_")
        || n.starts_with("amcvs_")
    {
        return Some(CookieThreatKind::Tracker);
    }

    None
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(1_763_500_000)
}

fn load_profile(root_dir: &Path) -> UserProfile {
    for candidate in ["profile.json", "profile.json.bak"] {
        let path = root_dir.join(candidate);
        if let Ok(raw) = std::fs::read_to_string(&path) {
            if let Ok(parsed) = serde_json::from_str::<UserProfile>(&raw) {
                return parsed;
            }
        }
    }
    UserProfile::default()
}

fn load_encrypted_tokens(
    root_dir: &Path,
    master_key: &[u8; 32],
) -> Result<RoamingTokensPlaintext, String> {
    let path = root_dir.join("tokens.enc");
    if !path.is_file() {
        return Ok(RoamingTokensPlaintext::default());
    }
    let raw = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let env: EncryptedTokensEnvelope =
        serde_json::from_str(&raw).map_err(|_| "Invalid tokens.enc envelope".to_string())?;
    if env.magic != TOKENS_ENVELOPE_MAGIC {
        return Err("Unsupported tokens.enc magic header".into());
    }

    let nonce_vec = BASE64
        .decode(&env.xnonce_base64)
        .map_err(|_| "Invalid nonce base64".to_string())?;
    let nonce_arr: [u8; 24] = nonce_vec
        .try_into()
        .map_err(|_| "Invalid XNonce length".to_string())?;
    let ciphertext = BASE64
        .decode(&env.ciphertext_base64)
        .map_err(|_| "Invalid ciphertext base64".to_string())?;

    let cipher = XChaCha20Poly1305::new(Key::from_slice(master_key));
    let mut plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce_arr),
            Payload {
                msg: &ciphertext,
                aad: env.magic.as_bytes(),
            },
        )
        .map_err(|_| "AEAD authentication failed for tokens.enc".to_string())?;

    let decoded = serde_json::from_slice::<RoamingTokensPlaintext>(&plaintext)
        .map_err(|_| "Malformed decrypted token payload".to_string());
    plaintext.zeroize();
    decoded
}

/// Atomically writes `bytes` to `target` using an exclusive random temporary file created with
/// `0o600` permissions on Unix (preventing TOCTOU permission windows and concurrent temp collisions).
fn atomic_write(target: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = target.parent().unwrap_or_else(|| Path::new("."));
    let file_name = target
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("singularity");
    let mut rnd = [0u8; 8];
    OsRng.fill_bytes(&mut rnd);
    let tmp = parent.join(format!(
        ".{}.{}.{}.tmp",
        file_name,
        std::process::id(),
        hex::encode(rnd)
    ));

    let write_res = (|| -> std::io::Result<()> {
        #[cfg(unix)]
        let mut f = {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)?
        };
        #[cfg(not(unix))]
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;

        f.write_all(bytes)?;
        f.sync_all()?;
        Ok(())
    })();

    if let Err(e) = write_res {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("Failed writing {}: {}", tmp.display(), e));
    }

    if let Err(e) = std::fs::rename(&tmp, target) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("Failed committing {}: {}", target.display(), e));
    }
    Ok(())
}

/// Atomically creates `target` ONLY if it does not already exist.
/// Returns `Ok(true)` if created by this caller, or `Ok(false)` if another thread/process won the race.
fn atomic_write_create_new(target: &Path, bytes: &[u8]) -> Result<bool, String> {
    let parent = target.parent().unwrap_or_else(|| Path::new("."));
    let file_name = target
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("singularity");
    let mut rnd = [0u8; 8];
    OsRng.fill_bytes(&mut rnd);
    let tmp = parent.join(format!(
        ".{}.{}.{}.init.tmp",
        file_name,
        std::process::id(),
        hex::encode(rnd)
    ));

    let write_res = (|| -> std::io::Result<()> {
        #[cfg(unix)]
        let mut f = {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)?
        };
        #[cfg(not(unix))]
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;

        f.write_all(bytes)?;
        f.sync_all()?;
        Ok(())
    })();

    if let Err(e) = write_res {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("Failed writing {}: {}", tmp.display(), e));
    }

    match std::fs::hard_link(&tmp, target) {
        Ok(()) => {
            let _ = std::fs::remove_file(&tmp);
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = std::fs::remove_file(&tmp);
            Ok(false)
        }
        Err(_) => {
            // Fallback for filesystems without hard-link support (e.g., FAT32/exFAT)
            let _ = std::fs::remove_file(&tmp);
            let direct = (|| -> std::io::Result<()> {
                #[cfg(unix)]
                let mut f = {
                    use std::os::unix::fs::OpenOptionsExt;
                    std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(target)?
                };
                #[cfg(not(unix))]
                let mut f = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(target)?;
                f.write_all(bytes)?;
                f.sync_all()?;
                Ok(())
            })();
            match direct {
                Ok(()) => Ok(true),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
                Err(e) => Err(format!("Failed creating {}: {}", target.display(), e)),
            }
        }
    }
}

#[cfg(not(target_os = "windows"))]
#[derive(Debug, Serialize, Deserialize)]
struct UnixSealedMasterKey {
    magic: String,
    salt_b64: String,
    xnonce_b64: String,
    ciphertext_b64: String,
}

#[cfg(not(target_os = "windows"))]
fn derive_unix_machine_kek(salt: &[u8; 32], root_dir: &Path) -> Zeroizing<[u8; 32]> {
    let machine_id = std::fs::read_to_string("/etc/machine-id")
        .or_else(|_| std::fs::read_to_string("/var/lib/dbus/machine-id"))
        .unwrap_or_default();
    let user = std::env::var("USER").unwrap_or_default();
    let home = std::env::var("HOME").unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(b"Singularity-Unix-MasterKey-KEK-v2:");
    hasher.update(salt);
    hasher.update(b":");
    hasher.update(machine_id.trim().as_bytes());
    hasher.update(b":");
    hasher.update(user.as_bytes());
    hasher.update(b":");
    hasher.update(home.as_bytes());
    hasher.update(b":");
    hasher.update(root_dir.to_string_lossy().as_bytes());
    Zeroizing::new(hasher.finalize().into())
}

#[cfg(not(target_os = "windows"))]
fn unix_keyring_account_id(root_dir: &Path) -> String {
    let mut h = Sha256::new();
    h.update(root_dir.to_string_lossy().as_bytes());
    let digest = hex::encode(h.finalize());
    format!("roaming-master-{}", &digest[..16])
}

#[cfg(not(target_os = "windows"))]
fn try_load_unix_keyring_key(root_dir: &Path) -> Option<[u8; 32]> {
    let account = unix_keyring_account_id(root_dir);
    #[cfg(target_os = "macos")]
    let out = std::process::Command::new("security")
        .args([
            "find-generic-password",
            "-s",
            "singularity-browser",
            "-a",
            &account,
            "-w",
        ])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    #[cfg(not(target_os = "macos"))]
    let out = std::process::Command::new("secret-tool")
        .args([
            "lookup",
            "service",
            "singularity-browser",
            "account",
            &account,
        ])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;

    if !out.status.success() {
        return None;
    }
    let raw = Zeroizing::new(String::from_utf8(out.stdout).ok()?);
    let decoded = Zeroizing::new(BASE64.decode(raw.trim()).ok()?);
    decoded.as_slice().try_into().ok()
}

#[cfg(not(target_os = "windows"))]
fn try_store_unix_keyring_key(root_dir: &Path, master_key: &[u8; 32]) -> bool {
    let account = unix_keyring_account_id(root_dir);
    let encoded = Zeroizing::new(BASE64.encode(master_key));
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("security")
            .args([
                "add-generic-password",
                "-U",
                "-s",
                "singularity-browser",
                "-a",
                &account,
                "-w",
                encoded.as_str(),
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let Ok(mut child) = std::process::Command::new("secret-tool")
            .args([
                "store",
                "--label=Singularity Browser Roaming Master Key",
                "service",
                "singularity-browser",
                "account",
                &account,
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
        else {
            return false;
        };
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(encoded.as_bytes());
        }
        child.wait().is_ok_and(|s| s.success())
    }
}

static MASTER_KEY_INIT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(target_os = "windows")]
fn read_dpapi_master_key(dpapi_path: &Path) -> Result<[u8; 32], String> {
    // Fail closed if existing master.dpapi cannot be read or unprotected — NEVER silently overwrite!
    let sealed = std::fs::read(dpapi_path)
        .map_err(|e| format!("Failed reading {}: {}", dpapi_path.display(), e))?;
    let unsealed = Zeroizing::new(dpapi_unprotect(&sealed)?);
    let arr: [u8; 32] = unsealed
        .as_slice()
        .try_into()
        .map_err(|_| "Corrupted master.dpapi key length".to_string())?;
    Ok(arr)
}

#[cfg(not(target_os = "windows"))]
fn read_unix_master_key(key_path: &Path, root_dir: &Path) -> Result<[u8; 32], String> {
    // Fail closed on existing key file — NEVER silently regenerate and destroy tokens.enc
    let raw = Zeroizing::new(
        std::fs::read_to_string(key_path)
            .map_err(|e| format!("Failed reading {}: {}", key_path.display(), e))?,
    );
    if let Ok(sealed) = serde_json::from_str::<UnixSealedMasterKey>(raw.trim()) {
        if sealed.magic != UNIX_SEALED_KEY_MAGIC {
            return Err("Unsupported Unix master.key magic header".into());
        }
        let salt_vec = BASE64
            .decode(&sealed.salt_b64)
            .map_err(|_| "Invalid master.key salt".to_string())?;
        let nonce_vec = BASE64
            .decode(&sealed.xnonce_b64)
            .map_err(|_| "Invalid master.key nonce".to_string())?;
        let ct = BASE64
            .decode(&sealed.ciphertext_b64)
            .map_err(|_| "Invalid master.key ciphertext".to_string())?;
        let salt: [u8; 32] = salt_vec
            .try_into()
            .map_err(|_| "Invalid master.key salt length".to_string())?;
        let xnonce: [u8; 24] = nonce_vec
            .try_into()
            .map_err(|_| "Invalid master.key nonce length".to_string())?;
        let kek = derive_unix_machine_kek(&salt, root_dir);
        let cipher = XChaCha20Poly1305::new(Key::from_slice(kek.as_ref()));
        let pt = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(&xnonce),
                    Payload {
                        msg: &ct,
                        aad: UNIX_SEALED_KEY_MAGIC.as_bytes(),
                    },
                )
                .map_err(|_| "Failed to unseal Unix master.key".to_string())?,
        );
        let arr: [u8; 32] = pt
            .as_slice()
            .try_into()
            .map_err(|_| "Invalid unsealed master.key length".to_string())?;
        return Ok(arr);
    }

    // Legacy Base64 plaintext migration path (auto-re-seals to authenticated v2 envelope)
    let decoded = Zeroizing::new(
        BASE64
            .decode(raw.trim())
            .map_err(|_| "Corrupted master.key file".to_string())?,
    );
    let arr: [u8; 32] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| "Invalid legacy master.key length".to_string())?;
    let _ = save_unix_sealed_master_key(key_path, root_dir, &arr);
    Ok(arr)
}

fn load_or_create_master_key(root_dir: &Path) -> Result<[u8; 32], String> {
    let _guard = MASTER_KEY_INIT_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    #[cfg(target_os = "windows")]
    {
        let dpapi_path = root_dir.join("master.dpapi");
        if dpapi_path.exists() {
            return read_dpapi_master_key(&dpapi_path);
        }

        let mut fresh_key = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(fresh_key.as_mut());
        let sealed = dpapi_protect(fresh_key.as_ref())?;
        if !atomic_write_create_new(&dpapi_path, &sealed)? {
            return read_dpapi_master_key(&dpapi_path);
        }
        return Ok(*fresh_key);
    }

    #[cfg(not(target_os = "windows"))]
    {
        let key_path = root_dir.join("master.key");
        if !key_path.exists() {
            if let Some(keyring_key) = try_load_unix_keyring_key(root_dir) {
                return Ok(keyring_key);
            }
        }
        if key_path.exists() {
            return read_unix_master_key(&key_path, root_dir);
        }

        let mut fresh_key = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(fresh_key.as_mut());
        // Prefer OS keyring (GNOME Keyring / KWallet via secret-tool or macOS Keychain);
        // fall back to 0600 sealed master.key only when running headless without a keyring daemon.
        if try_store_unix_keyring_key(root_dir, &fresh_key) {
            return Ok(*fresh_key);
        }
        let encoded = encode_unix_sealed_master_key(root_dir, &fresh_key)?;
        if !atomic_write_create_new(&key_path, &encoded)? {
            return read_unix_master_key(&key_path, root_dir);
        }
        Ok(*fresh_key)
    }
}

#[cfg(not(target_os = "windows"))]
fn encode_unix_sealed_master_key(
    root_dir: &Path,
    master_key: &[u8; 32],
) -> Result<Vec<u8>, String> {
    let mut salt = [0u8; 32];
    let mut xnonce = [0u8; 24];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut xnonce);
    let kek = derive_unix_machine_kek(&salt, root_dir);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(kek.as_ref()));
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&xnonce),
            Payload {
                msg: master_key.as_ref(),
                aad: UNIX_SEALED_KEY_MAGIC.as_bytes(),
            },
        )
        .map_err(|_| "Failed to seal Unix master.key".to_string())?;
    let env = UnixSealedMasterKey {
        magic: UNIX_SEALED_KEY_MAGIC.to_string(),
        salt_b64: BASE64.encode(salt),
        xnonce_b64: BASE64.encode(xnonce),
        ciphertext_b64: BASE64.encode(ct),
    };
    serde_json::to_vec_pretty(&env).map_err(|e| format!("Failed serializing master.key: {}", e))
}

#[cfg(not(target_os = "windows"))]
fn save_unix_sealed_master_key(
    key_path: &Path,
    root_dir: &Path,
    master_key: &[u8; 32],
) -> Result<(), String> {
    let encoded = encode_unix_sealed_master_key(root_dir, master_key)?;
    atomic_write(key_path, &encoded)
}

#[cfg(target_os = "windows")]
const DPAPI_ENTROPY: &[u8] = b"Singularity-Roaming-DPAPI-Entropy-v3";

#[cfg(target_os = "windows")]
#[repr(C)]
struct CryptoApiBlob {
    cb_data: u32,
    pb_data: *mut u8,
}

#[cfg(target_os = "windows")]
#[link(name = "crypt32")]
extern "system" {
    fn CryptProtectData(
        p_data_in: *const CryptoApiBlob,
        sz_data_descr: *const u16,
        p_optional_entropy: *const CryptoApiBlob,
        pv_reserved: *mut core::ffi::c_void,
        p_prompt_struct: *mut core::ffi::c_void,
        dw_flags: u32,
        p_data_out: *mut CryptoApiBlob,
    ) -> i32;

    fn CryptUnprotectData(
        p_data_in: *const CryptoApiBlob,
        ppsz_data_descr: *mut *mut u16,
        p_optional_entropy: *const CryptoApiBlob,
        pv_reserved: *mut core::ffi::c_void,
        p_prompt_struct: *mut core::ffi::c_void,
        dw_flags: u32,
        p_data_out: *mut CryptoApiBlob,
    ) -> i32;
}

#[cfg(target_os = "windows")]
#[link(name = "kernel32")]
extern "system" {
    fn LocalFree(h_mem: *mut core::ffi::c_void) -> *mut core::ffi::c_void;
}

#[cfg(target_os = "windows")]
fn dpapi_protect(secret: &[u8]) -> Result<Vec<u8>, String> {
    const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;
    let mut in_buf = secret.to_vec();
    let mut entropy_buf = DPAPI_ENTROPY.to_vec();

    let data_in = CryptoApiBlob {
        cb_data: in_buf.len() as u32,
        pb_data: in_buf.as_mut_ptr(),
    };
    let entropy = CryptoApiBlob {
        cb_data: entropy_buf.len() as u32,
        pb_data: entropy_buf.as_mut_ptr(),
    };
    let mut data_out = CryptoApiBlob {
        cb_data: 0,
        pb_data: core::ptr::null_mut(),
    };

    let ok = unsafe {
        CryptProtectData(
            &data_in,
            core::ptr::null(),
            &entropy,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut data_out,
        )
    };
    in_buf.zeroize();

    if ok == 0 || data_out.pb_data.is_null() {
        return Err("Windows DPAPI CryptProtectData failed".into());
    }

    let out_slice =
        unsafe { core::slice::from_raw_parts(data_out.pb_data, data_out.cb_data as usize) };
    let result = out_slice.to_vec();
    unsafe {
        LocalFree(data_out.pb_data as *mut core::ffi::c_void);
    }
    Ok(result)
}

#[cfg(target_os = "windows")]
fn dpapi_unprotect(sealed: &[u8]) -> Result<Vec<u8>, String> {
    const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;
    let mut in_buf = sealed.to_vec();
    let mut entropy_buf = DPAPI_ENTROPY.to_vec();

    let data_in = CryptoApiBlob {
        cb_data: in_buf.len() as u32,
        pb_data: in_buf.as_mut_ptr(),
    };
    let entropy = CryptoApiBlob {
        cb_data: entropy_buf.len() as u32,
        pb_data: entropy_buf.as_mut_ptr(),
    };
    let mut data_out = CryptoApiBlob {
        cb_data: 0,
        pb_data: core::ptr::null_mut(),
    };

    let ok = unsafe {
        CryptUnprotectData(
            &data_in,
            core::ptr::null_mut(),
            &entropy,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut data_out,
        )
    };

    if ok == 0 || data_out.pb_data.is_null() {
        return Err("Windows DPAPI CryptUnprotectData failed".into());
    }

    let out_slice =
        unsafe { core::slice::from_raw_parts_mut(data_out.pb_data, data_out.cb_data as usize) };
    let result = out_slice.to_vec();
    // Volatile zeroize prevents compiler dead-store elimination before LocalFree
    out_slice.zeroize();
    unsafe {
        LocalFree(data_out.pb_data as *mut core::ffi::c_void);
    }
    Ok(result)
}

struct PersistQueueState {
    pending: Option<(PathBuf, String, UserProfile, WindowGeometry)>,
    flush_requested: bool,
    generation: u64,
    flushed_generation: u64,
}

struct ProfilePersistWorker {
    state: Mutex<PersistQueueState>,
    wake_cond: Condvar,
    done_cond: Condvar,
}

impl ProfilePersistWorker {
    fn spawn() -> &'static Self {
        static INSTANCE: OnceLock<ProfilePersistWorker> = OnceLock::new();
        INSTANCE.get_or_init(|| {
            let worker = ProfilePersistWorker {
                state: Mutex::new(PersistQueueState {
                    pending: None,
                    flush_requested: false,
                    generation: 0,
                    flushed_generation: 0,
                }),
                wake_cond: Condvar::new(),
                done_cond: Condvar::new(),
            };
            let _ = std::thread::Builder::new()
                .name("singularity-io-persist".into())
                .spawn(|| {
                    // Wait until OnceLock initialization completes, then loop forever coalescing writes.
                    let w = profile_persist_worker();
                    let mut last_backup_at = Instant::now()
                        .checked_sub(Duration::from_secs(60))
                        .unwrap_or_else(Instant::now);
                    loop {
                        let (job, gen_id, force_bak) = {
                            let mut st = w.state.lock().unwrap_or_else(|e| e.into_inner());
                            while st.pending.is_none() {
                                if st.flush_requested {
                                    st.flush_requested = false;
                                    st.flushed_generation = st.generation;
                                    w.done_cond.notify_all();
                                }
                                st = w.wake_cond.wait(st).unwrap_or_else(|e| e.into_inner());
                            }
                            // Brief 220ms coalescing window so rapid tab switches / title ticks
                            // collapse into ONE single atomic disk write instead of hammering NTFS!
                            if !st.flush_requested {
                                let (guard, _) = w
                                    .wake_cond
                                    .wait_timeout(st, Duration::from_millis(220))
                                    .unwrap_or_else(|e| e.into_inner());
                                st = guard;
                            }
                            let job = st.pending.take();
                            let gen_id = st.generation;
                            let force_bak = st.flush_requested;
                            (job, gen_id, force_bak)
                        };
                        if let Some((root_dir, window_id, profile, geometry)) = job {
                            let write_backup =
                                force_bak || last_backup_at.elapsed() >= Duration::from_secs(30);
                            let _ = RoamingSingularityStore::write_profile_snapshot(
                                &root_dir,
                                &window_id,
                                &profile,
                                geometry,
                                write_backup,
                            );
                            if write_backup {
                                last_backup_at = Instant::now();
                            }
                        }
                        let mut st = w.state.lock().unwrap_or_else(|e| e.into_inner());
                        st.flushed_generation = gen_id;
                        if st.pending.is_none() {
                            st.flush_requested = false;
                        }
                        w.done_cond.notify_all();
                    }
                });
            worker
        })
    }

    fn enqueue(
        &self,
        root_dir: PathBuf,
        window_id: String,
        profile: UserProfile,
        geometry: WindowGeometry,
    ) {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        st.pending = Some((root_dir, window_id, profile, geometry));
        st.generation = st.generation.wrapping_add(1);
        self.wake_cond.notify_one();
    }

    fn flush_now(&self) {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let target = st.generation;
        if st.pending.is_none() && st.flushed_generation == target {
            return;
        }
        st.flush_requested = true;
        self.wake_cond.notify_one();
        let deadline = Instant::now() + Duration::from_secs(3);
        while st.flushed_generation != target || st.pending.is_some() {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            let (guard, _) = self
                .done_cond
                .wait_timeout(st, deadline - now)
                .unwrap_or_else(|e| e.into_inner());
            st = guard;
        }
    }
}

fn profile_persist_worker() -> &'static ProfilePersistWorker {
    ProfilePersistWorker::spawn()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roaming_singularity_encrypted_google_microsoft_tokens_roundtrip() {
        let test_dir = std::env::temp_dir().join(format!("singularity_roaming_test_{}", unix_now()));
        let _ = std::fs::remove_dir_all(&test_dir);

        {
            let mut store = RoamingSingularityStore::open_at(test_dir.clone())
                .expect("Initialize .singularity directory");

            assert_eq!(
                classify_auth_cookie(".google.com", "__Secure-1PSID"),
                Some("Google")
            );
            assert_eq!(
                classify_auth_cookie("login.microsoftonline.com", "ESTSAUTHPERSISTENT"),
                Some("Microsoft")
            );

            store
                .upsert_token(EncryptedAuthTokenRecord {
                    id: "Google::.google.com::__Secure-1PSID".into(),
                    provider: "Google".into(),
                    domain: ".google.com".into(),
                    path: "/".into(),
                    token_name: "__Secure-1PSID".into(),
                    secret_value: "g.a000secretGoogleSessionToken998877".into(),
                    http_only: true,
                    secure: true,
                    expires_unix: Some(1_900_000_000),
                    updated_unix: unix_now(),
                    kind: "cookie_session".into(),
                })
                .expect("Encrypt Google token");

            store
                .upsert_token(EncryptedAuthTokenRecord {
                    id: "Microsoft::login.live.com::WLSSC".into(),
                    provider: "Microsoft".into(),
                    domain: "login.live.com".into(),
                    path: "/".into(),
                    token_name: "WLSSC".into(),
                    secret_value: "msft_live_encrypted_oauth_session_token_445566".into(),
                    http_only: true,
                    secure: true,
                    expires_unix: Some(1_900_000_000),
                    updated_unix: unix_now(),
                    kind: "cookie_session".into(),
                })
                .expect("Encrypt Microsoft token");

            // Verify raw file on disk does NOT contain plaintext secrets
            let raw_disk = std::fs::read_to_string(store.tokens_file_path()).unwrap();
            assert!(!raw_disk.contains("g.a000secretGoogleSessionToken998877"));
            assert!(!raw_disk.contains("msft_live_encrypted_oauth_session_token_445566"));
        }

        // Re-open store from disk and verify AEAD decryption restores both Google & Microsoft tokens
        let reopened =
            RoamingSingularityStore::open_at(test_dir.clone()).expect("Re-open .singularity");
        assert_eq!(reopened.tokens.sessions.len(), 2);
        assert!(reopened
            .tokens
            .sessions
            .iter()
            .any(|t| t.provider == "Google"
                && t.secret_value == "g.a000secretGoogleSessionToken998877"));
        assert!(reopened
            .tokens
            .sessions
            .iter()
            .any(|t| t.provider == "Microsoft"
                && t.secret_value == "msft_live_encrypted_oauth_session_token_445566"));

        let _ = std::fs::remove_dir_all(&test_dir);
    }

    #[test]
    fn test_concurrent_first_launch_never_corrupts_master_key_or_tokens() {
        let mut rnd = [0u8; 6];
        OsRng.fill_bytes(&mut rnd);
        let test_dir = std::env::temp_dir().join(format!(
            "singularity_concurrent_init_{}",
            hex::encode(rnd)
        ));
        let _ = std::fs::remove_dir_all(&test_dir);

        let handles: Vec<_> = (0..16)
            .map(|_| {
                let dir = test_dir.clone();
                std::thread::spawn(move || {
                    let store = RoamingSingularityStore::open_at(dir)
                        .expect("Concurrent first-launch open_at must never fail");
                    store.master_key
                })
            })
            .collect();

        let keys: Vec<[u8; 32]> = handles
            .into_iter()
            .map(|h| h.join().expect("Worker thread panicked"))
            .collect();
        for k in &keys[1..] {
            assert_eq!(k, &keys[0], "All concurrent instances must converge on the exact same master key");
        }

        let _ = std::fs::remove_dir_all(&test_dir);
    }
}
