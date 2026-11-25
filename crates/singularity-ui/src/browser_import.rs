//! Local Read-Only Installed Browser Scanner & Open-Tab / Bookmark Importer.
//!
//! Detects installed Chromium-family browsers (Google Chrome, Microsoft Edge, Opera GX, Opera,
//! Brave, Vivaldi, Arc, Chromium, Thorium) and Gecko-family browsers (Mozilla Firefox, Zen,
//! LibreWolf, Floorp, Waterfox) on Windows and Linux, and extracts their currently open tabs
//! and bookmarks purely locally in safe Rust (zero external dependencies, strictly read-only).

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

const MAX_SESSION_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_LZ4_DECOMPRESSED_BYTES: usize = 64 * 1024 * 1024;
const MAX_TABS_PER_BROWSER: usize = 250;
const MAX_BOOKMARKS_PER_BROWSER: usize = 2000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportedTab {
    pub title: String,
    pub url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportedBookmark {
    pub title: String,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedBrowserInfo {
    pub id: String,
    pub name: String,
    pub engine: String,
    pub accent: String,
    pub open_tabs_count: usize,
    pub bookmarks_count: usize,
    pub sample_titles: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ExtractedBrowserData {
    pub tabs: Vec<ImportedTab>,
    pub bookmarks: Vec<ImportedBookmark>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BrowserEngineKind {
    Chromium,
    ChromiumRootProfile, // Opera / Opera GX put Sessions/ & Bookmarks right in the data root
    Firefox,
}

struct BrowserSpec {
    id: &'static str,
    name: &'static str,
    engine: BrowserEngineKind,
    accent: &'static str,
    data_dirs: Vec<PathBuf>,
    exe_paths: Vec<PathBuf>,
}

fn is_importable_http_url(url: &str) -> bool {
    let trimmed = url.trim();
    if trimmed.len() < 10 || trimmed.len() > 2048 {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();
    if !(lower.starts_with("https://") || lower.starts_with("http://")) {
        return false;
    }
    // Skip local loopback / blank / browser internal redirect pages
    if lower.starts_with("http://127.0.0.1")
        || lower.starts_with("http://localhost")
        || lower.starts_with("https://localhost")
    {
        return false;
    }
    !trimmed.bytes().any(|b| b < 0x20 || b == 0x7f)
}

fn clean_title(raw: &str, url: &str) -> String {
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_control())
        .take(140)
        .collect::<String>()
        .trim()
        .to_string();
    if !cleaned.is_empty() {
        return cleaned;
    }
    url.trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or(url)
        .trim_start_matches("www.")
        .to_string()
}

fn read_bounded_file(path: &Path) -> Option<Vec<u8>> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() == 0 || meta.len() > MAX_SESSION_FILE_BYTES {
        return None;
    }
    std::fs::read(path).ok()
}

fn build_browser_catalog() -> Vec<BrowserSpec> {
    let mut specs = Vec::new();

    #[cfg(target_os = "windows")]
    {
        let local = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
        let roaming = std::env::var_os("APPDATA").map(PathBuf::from);
        let pf = std::env::var_os("ProgramFiles").map(PathBuf::from);
        let pf86 = std::env::var_os("ProgramFiles(x86)").map(PathBuf::from);

        let join_opt = |base: &Option<PathBuf>, rel: &str| -> Option<PathBuf> {
            base.as_ref().map(|b| b.join(rel))
        };

        let mut push_spec = |id: &'static str,
                             name: &'static str,
                             engine: BrowserEngineKind,
                             accent: &'static str,
                             data: Vec<Option<PathBuf>>,
                             exes: Vec<Option<PathBuf>>| {
            specs.push(BrowserSpec {
                id,
                name,
                engine,
                accent,
                data_dirs: data.into_iter().flatten().collect(),
                exe_paths: exes.into_iter().flatten().collect(),
            });
        };

        push_spec(
            "chrome",
            "Google Chrome",
            BrowserEngineKind::Chromium,
            "#4285F4",
            vec![join_opt(&local, r"Google\Chrome\User Data")],
            vec![
                join_opt(&pf, r"Google\Chrome\Application\chrome.exe"),
                join_opt(&pf86, r"Google\Chrome\Application\chrome.exe"),
                join_opt(&local, r"Google\Chrome\Application\chrome.exe"),
            ],
        );
        push_spec(
            "edge",
            "Microsoft Edge",
            BrowserEngineKind::Chromium,
            "#00A4EF",
            vec![join_opt(&local, r"Microsoft\Edge\User Data")],
            vec![
                join_opt(&pf86, r"Microsoft\Edge\Application\msedge.exe"),
                join_opt(&pf, r"Microsoft\Edge\Application\msedge.exe"),
            ],
        );
        push_spec(
            "opera_gx",
            "Opera GX",
            BrowserEngineKind::ChromiumRootProfile,
            "#FA1E4E",
            vec![join_opt(&roaming, r"Opera Software\Opera GX Stable")],
            vec![
                join_opt(&local, r"Programs\Opera GX\opera.exe"),
                join_opt(&local, r"Programs\Opera GX\launcher.exe"),
            ],
        );
        push_spec(
            "opera",
            "Opera",
            BrowserEngineKind::ChromiumRootProfile,
            "#FF1B2D",
            vec![join_opt(&roaming, r"Opera Software\Opera Stable")],
            vec![
                join_opt(&local, r"Programs\Opera\opera.exe"),
                join_opt(&local, r"Programs\Opera\launcher.exe"),
                join_opt(&pf, r"Opera\launcher.exe"),
            ],
        );
        push_spec(
            "brave",
            "Brave",
            BrowserEngineKind::Chromium,
            "#FB542B",
            vec![join_opt(&local, r"BraveSoftware\Brave-Browser\User Data")],
            vec![
                join_opt(&pf, r"BraveSoftware\Brave-Browser\Application\brave.exe"),
                join_opt(&pf86, r"BraveSoftware\Brave-Browser\Application\brave.exe"),
                join_opt(&local, r"BraveSoftware\Brave-Browser\Application\brave.exe"),
            ],
        );
        push_spec(
            "firefox",
            "Mozilla Firefox",
            BrowserEngineKind::Firefox,
            "#FF7139",
            vec![join_opt(&roaming, r"Mozilla\Firefox\Profiles")],
            vec![
                join_opt(&pf, r"Mozilla Firefox\firefox.exe"),
                join_opt(&pf86, r"Mozilla Firefox\firefox.exe"),
            ],
        );
        push_spec(
            "vivaldi",
            "Vivaldi",
            BrowserEngineKind::Chromium,
            "#EF3939",
            vec![join_opt(&local, r"Vivaldi\User Data")],
            vec![
                join_opt(&local, r"Vivaldi\Application\vivaldi.exe"),
                join_opt(&pf, r"Vivaldi\Application\vivaldi.exe"),
            ],
        );

        // Arc on Windows (MSIX Package path + standard fallback)
        let mut arc_dirs: Vec<Option<PathBuf>> = vec![join_opt(&local, r"Arc\User Data")];
        if let Some(ref loc) = local {
            if let Ok(entries) = std::fs::read_dir(loc.join("Packages")) {
                for ent in entries.flatten() {
                    let fname = ent.file_name().to_string_lossy().to_string();
                    if fname.starts_with("TheBrowserCompany.Arc_") {
                        arc_dirs.push(Some(
                            ent.path()
                                .join("LocalCache")
                                .join("Local")
                                .join("Arc")
                                .join("User Data"),
                        ));
                    }
                }
            }
        }
        push_spec(
            "arc",
            "Arc",
            BrowserEngineKind::Chromium,
            "#6C7BFF",
            arc_dirs,
            vec![join_opt(&local, r"Microsoft\WindowsApps\Arc.exe")],
        );

        push_spec(
            "zen",
            "Zen Browser",
            BrowserEngineKind::Firefox,
            "#F0B254",
            vec![join_opt(&roaming, r"zen\Profiles")],
            vec![
                join_opt(&pf, r"Zen Browser\zen.exe"),
                join_opt(&local, r"Zen Browser\zen.exe"),
            ],
        );
        push_spec(
            "librewolf",
            "LibreWolf",
            BrowserEngineKind::Firefox,
            "#00ACFF",
            vec![join_opt(&roaming, r"librewolf\Profiles")],
            vec![join_opt(&pf, r"LibreWolf\librewolf.exe")],
        );
        push_spec(
            "floorp",
            "Floorp",
            BrowserEngineKind::Firefox,
            "#5B8DEF",
            vec![join_opt(&roaming, r"Floorp\Profiles")],
            vec![join_opt(&pf, r"Ablaze Floorp\floorp.exe")],
        );
        push_spec(
            "waterfox",
            "Waterfox",
            BrowserEngineKind::Firefox,
            "#00AEF0",
            vec![join_opt(&roaming, r"Waterfox\Profiles")],
            vec![join_opt(&pf, r"Waterfox\waterfox.exe")],
        );
        push_spec(
            "chromium",
            "Chromium",
            BrowserEngineKind::Chromium,
            "#5E97F6",
            vec![join_opt(&local, r"Chromium\User Data")],
            vec![join_opt(&local, r"Chromium\Application\chrome.exe")],
        );
        push_spec(
            "thorium",
            "Thorium",
            BrowserEngineKind::Chromium,
            "#8AB4F8",
            vec![join_opt(&local, r"Thorium\User Data")],
            vec![join_opt(&local, r"Thorium\Application\thorium.exe")],
        );
    }

    #[cfg(not(target_os = "windows"))]
    {
        if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
            let cfg = home.join(".config");
            let mut push_spec = |id: &'static str,
                                 name: &'static str,
                                 engine: BrowserEngineKind,
                                 accent: &'static str,
                                 data: Vec<PathBuf>,
                                 exes: Vec<PathBuf>| {
                specs.push(BrowserSpec {
                    id,
                    name,
                    engine,
                    accent,
                    data_dirs: data,
                    exe_paths: exes,
                });
            };
            push_spec(
                "chrome",
                "Google Chrome",
                BrowserEngineKind::Chromium,
                "#4285F4",
                vec![cfg.join("google-chrome")],
                vec![PathBuf::from("/usr/bin/google-chrome")],
            );
            push_spec(
                "edge",
                "Microsoft Edge",
                BrowserEngineKind::Chromium,
                "#00A4EF",
                vec![cfg.join("microsoft-edge")],
                vec![PathBuf::from("/usr/bin/microsoft-edge")],
            );
            push_spec(
                "brave",
                "Brave",
                BrowserEngineKind::Chromium,
                "#FB542B",
                vec![cfg.join("BraveSoftware/Brave-Browser")],
                vec![PathBuf::from("/usr/bin/brave-browser")],
            );
            push_spec(
                "opera",
                "Opera",
                BrowserEngineKind::ChromiumRootProfile,
                "#FF1B2D",
                vec![cfg.join("opera")],
                vec![PathBuf::from("/usr/bin/opera")],
            );
            push_spec(
                "vivaldi",
                "Vivaldi",
                BrowserEngineKind::Chromium,
                "#EF3939",
                vec![cfg.join("vivaldi")],
                vec![PathBuf::from("/usr/bin/vivaldi")],
            );
            push_spec(
                "chromium",
                "Chromium",
                BrowserEngineKind::Chromium,
                "#5E97F6",
                vec![cfg.join("chromium")],
                vec![PathBuf::from("/usr/bin/chromium")],
            );
            push_spec(
                "firefox",
                "Mozilla Firefox",
                BrowserEngineKind::Firefox,
                "#FF7139",
                vec![home.join(".mozilla/firefox")],
                vec![PathBuf::from("/usr/bin/firefox")],
            );
            push_spec(
                "librewolf",
                "LibreWolf",
                BrowserEngineKind::Firefox,
                "#00ACFF",
                vec![home.join(".librewolf")],
                vec![PathBuf::from("/usr/bin/librewolf")],
            );
            push_spec(
                "zen",
                "Zen Browser",
                BrowserEngineKind::Firefox,
                "#F0B254",
                vec![home.join(".zen")],
                vec![PathBuf::from("/usr/bin/zen-browser")],
            );
        }
    }

    specs
}

fn spec_is_installed(spec: &BrowserSpec) -> bool {
    spec.data_dirs.iter().any(|d| d.is_dir()) || spec.exe_paths.iter().any(|p| p.is_file())
}

fn collect_chromium_profile_dirs(data_dir: &Path, include_root: bool) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if include_root
        && (data_dir.join("Sessions").is_dir()
            || data_dir.join("Bookmarks").is_file()
            || data_dir.join("Current Session").is_file()
            || data_dir.join("Last Session").is_file())
    {
        dirs.push(data_dir.to_path_buf());
    }
    let default_dir = data_dir.join("Default");
    if default_dir.is_dir() {
        dirs.push(default_dir);
    }
    if let Ok(entries) = std::fs::read_dir(data_dir) {
        let mut profiles: Vec<PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.is_dir()
                    && p.file_name()
                        .and_then(|n| n.to_str())
                        .map(|n| n.starts_with("Profile "))
                        .unwrap_or(false)
            })
            .collect();
        profiles.sort();
        dirs.extend(profiles);
    }
    dirs
}

/// Pure-Rust, zero-unsafe Chromium SNSS (`Session_*` / `Current Session` / `Last Session`)
/// binary session parser. Extracts currently open tabs in exact window & tab order,
/// respecting `kCommandSetSelectedNavigationIndex`, `kCommandTabClosed`, and `kCommandWindowClosed`.
pub fn parse_chromium_snss_session(bytes: &[u8]) -> Vec<ImportedTab> {
    if bytes.len() < 8 || &bytes[0..4] != b"SNSS" {
        return Vec::new();
    }

    let read_u16 = |buf: &[u8], off: usize| -> Option<u16> {
        let sl = buf.get(off..off + 2)?;
        Some(u16::from_le_bytes([sl[0], sl[1]]))
    };
    let read_u32 = |buf: &[u8], off: usize| -> Option<u32> {
        let sl = buf.get(off..off + 4)?;
        Some(u32::from_le_bytes([sl[0], sl[1], sl[2], sl[3]]))
    };
    let read_i32 = |buf: &[u8], off: usize| -> Option<i32> {
        let sl = buf.get(off..off + 4)?;
        Some(i32::from_le_bytes([sl[0], sl[1], sl[2], sl[3]]))
    };

    let mut tab_window: HashMap<i32, i32> = HashMap::new();
    let mut tab_index_in_win: HashMap<i32, i32> = HashMap::new();
    let mut tab_selected_nav: HashMap<i32, i32> = HashMap::new();
    let mut tab_navs: HashMap<i32, HashMap<i32, (String, String)>> = HashMap::new();
    let mut closed_tabs: HashSet<i32> = HashSet::new();
    let mut closed_windows: HashSet<i32> = HashSet::new();

    let mut pos = 8usize;
    while pos + 2 <= bytes.len() {
        let Some(cmd_size_u16) = read_u16(bytes, pos) else {
            break;
        };
        let cmd_size = cmd_size_u16 as usize;
        pos += 2;
        if cmd_size == 0 || pos + cmd_size > bytes.len() {
            break;
        }
        let cmd_id = bytes[pos];
        let payload = &bytes[pos + 1..pos + cmd_size];
        pos += cmd_size;

        match cmd_id {
            // kCommandSetTabWindow = 0 (window_id: i32, tab_id: i32)
            0 => {
                if let (Some(win_id), Some(tab_id)) = (read_i32(payload, 0), read_i32(payload, 4)) {
                    tab_window.insert(tab_id, win_id);
                    closed_tabs.remove(&tab_id);
                    closed_windows.remove(&win_id);
                }
            }
            // kCommandSetTabIndexInWindow = 2 (tab_id: i32, index: i32)
            2 => {
                if let (Some(tab_id), Some(idx)) = (read_i32(payload, 0), read_i32(payload, 4)) {
                    tab_index_in_win.insert(tab_id, idx);
                }
            }
            // kCommandUpdateTabNavigation = 6 (Pickle: payload_size, tab_id, nav_idx, url, title...)
            6 => {
                if payload.len() < 16 {
                    continue;
                }
                let Some(tab_id) = read_i32(payload, 4) else {
                    continue;
                };
                let Some(nav_idx) = read_i32(payload, 8) else {
                    continue;
                };
                let Some(url_len_u32) = read_u32(payload, 12) else {
                    continue;
                };
                let url_len = url_len_u32 as usize;
                let url_start = 16usize;
                let Some(url_end) = url_start.checked_add(url_len) else {
                    continue;
                };
                if url_end > payload.len() {
                    continue;
                }
                let url = String::from_utf8_lossy(&payload[url_start..url_end]).into_owned();
                let url_padded = (url_len + 3) & !3;
                let title_len_off = url_start.saturating_add(url_padded);

                let mut title = String::new();
                if let Some(title_chars_u32) = read_u32(payload, title_len_off) {
                    let title_bytes_len = (title_chars_u32 as usize).saturating_mul(2);
                    let title_start = title_len_off + 4;
                    if let Some(title_end) = title_start.checked_add(title_bytes_len) {
                        if title_end <= payload.len() {
                            let utf16: Vec<u16> = payload[title_start..title_end]
                                .chunks_exact(2)
                                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                                .collect();
                            title = String::from_utf16_lossy(&utf16);
                        }
                    }
                }

                closed_tabs.remove(&tab_id);
                tab_navs
                    .entry(tab_id)
                    .or_default()
                    .insert(nav_idx, (url, title));
            }
            // kCommandSetSelectedNavigationIndex = 7 (tab_id: i32, selected_nav_idx: i32)
            7 => {
                if let (Some(tab_id), Some(nav_idx)) = (read_i32(payload, 0), read_i32(payload, 4))
                {
                    tab_selected_nav.insert(tab_id, nav_idx);
                }
            }
            // kCommandTabClosed = 16 (tab_id: i32, close_time: i64)
            16 => {
                if let Some(tab_id) = read_i32(payload, 0) {
                    closed_tabs.insert(tab_id);
                }
            }
            // kCommandWindowClosed = 17 (window_id: i32, close_time: i64)
            17 => {
                if let Some(win_id) = read_i32(payload, 0) {
                    closed_windows.insert(win_id);
                }
            }
            _ => {}
        }
    }

    let mut ordered_open: Vec<(i32, i32, i32, ImportedTab)> = Vec::new();
    for (&tab_id, nav_map) in &tab_navs {
        if closed_tabs.contains(&tab_id) {
            continue;
        }
        let win_id = tab_window.get(&tab_id).copied().unwrap_or(0);
        if win_id != 0 && closed_windows.contains(&win_id) {
            continue;
        }
        let chosen = tab_selected_nav
            .get(&tab_id)
            .and_then(|sel| nav_map.get(sel))
            .or_else(|| nav_map.iter().max_by_key(|(&k, _)| k).map(|(_, v)| v));
        let Some((url, title)) = chosen else {
            continue;
        };
        if !is_importable_http_url(url) {
            continue;
        }
        let idx = tab_index_in_win.get(&tab_id).copied().unwrap_or(i32::MAX);
        ordered_open.push((
            win_id,
            idx,
            tab_id,
            ImportedTab {
                title: clean_title(title, url),
                url: url.trim().to_string(),
            },
        ));
    }

    ordered_open.sort_by_key(|(win, idx, tid, _)| (*win, *idx, *tid));
    ordered_open.into_iter().map(|(_, _, _, t)| t).collect()
}

/// Parses Chromium's `Bookmarks` JSON file (`roots.bookmark_bar`, `roots.other`, `roots.synced`).
pub fn parse_chromium_bookmarks(bytes: &[u8]) -> Vec<ImportedBookmark> {
    let Ok(root) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    fn walk(node: &serde_json::Value, out: &mut Vec<ImportedBookmark>) {
        if out.len() >= MAX_BOOKMARKS_PER_BROWSER {
            return;
        }
        if node.get("type").and_then(|v| v.as_str()) == Some("url") {
            if let Some(url) = node.get("url").and_then(|v| v.as_str()) {
                if is_importable_http_url(url) {
                    let name = node.get("name").and_then(|v| v.as_str()).unwrap_or("");
                    out.push(ImportedBookmark {
                        title: clean_title(name, url),
                        url: url.trim().to_string(),
                    });
                }
            }
            return;
        }
        if let Some(children) = node.get("children").and_then(|v| v.as_array()) {
            for child in children {
                walk(child, out);
                if out.len() >= MAX_BOOKMARKS_PER_BROWSER {
                    break;
                }
            }
        }
    }
    if let Some(roots) = root.get("roots").and_then(|v| v.as_object()) {
        for key in ["bookmark_bar", "other", "synced"] {
            if let Some(branch) = roots.get(key) {
                walk(branch, &mut out);
            }
        }
    }
    out
}

/// Pure-Rust, zero-unsafe, bounds-checked raw LZ4 block decompressor (for Mozilla `mozLz40`).
pub fn decompress_lz4_block(src: &[u8], expected_len: usize) -> Result<Vec<u8>, String> {
    if expected_len > MAX_LZ4_DECOMPRESSED_BYTES {
        return Err("LZ4 payload exceeds safety limit".into());
    }
    let mut out = Vec::with_capacity(expected_len.min(1024 * 1024));
    let mut ip = 0usize;

    while ip < src.len() {
        let token = src[ip];
        ip += 1;

        // 1. Literals
        let mut lit_len = (token >> 4) as usize;
        if lit_len == 15 {
            loop {
                let b = *src.get(ip).ok_or("Truncated LZ4 literal length")?;
                ip += 1;
                lit_len = lit_len
                    .checked_add(b as usize)
                    .ok_or("LZ4 literal length overflow")?;
                if b != 255 {
                    break;
                }
            }
        }
        let lit_end = ip.checked_add(lit_len).ok_or("LZ4 literal end overflow")?;
        if lit_end > src.len() {
            return Err("Truncated LZ4 literals".into());
        }
        if out.len().saturating_add(lit_len) > MAX_LZ4_DECOMPRESSED_BYTES {
            return Err("LZ4 output exceeds limit".into());
        }
        out.extend_from_slice(&src[ip..lit_end]);
        ip = lit_end;

        // End of block (last sequence has no match part)
        if ip >= src.len() {
            break;
        }

        // 2. Match offset (u16 LE)
        if ip + 2 > src.len() {
            return Err("Truncated LZ4 match offset".into());
        }
        let offset = u16::from_le_bytes([src[ip], src[ip + 1]]) as usize;
        ip += 2;
        if offset == 0 || offset > out.len() {
            return Err("Invalid LZ4 match offset".into());
        }

        // 3. Match length
        let mut match_len = ((token & 0x0F) as usize) + 4;
        if (token & 0x0F) == 15 {
            loop {
                let b = *src.get(ip).ok_or("Truncated LZ4 match length")?;
                ip += 1;
                match_len = match_len
                    .checked_add(b as usize)
                    .ok_or("LZ4 match length overflow")?;
                if b != 255 {
                    break;
                }
            }
        }
        if out.len().saturating_add(match_len) > MAX_LZ4_DECOMPRESSED_BYTES {
            return Err("LZ4 match output exceeds limit".into());
        }
        // Byte-by-byte copy preserves overlapping RLE patterns cleanly
        for _ in 0..match_len {
            let b = out[out.len() - offset];
            out.push(b);
        }
    }

    Ok(out)
}

/// Decompresses a Mozilla `mozLz40\0` payload (or returns plain JSON bytes as-is).
pub fn decode_mozlz4_or_json(bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.len() >= 12 && &bytes[0..8] == b"mozLz40\0" {
        let expected = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as usize;
        decompress_lz4_block(&bytes[12..], expected).ok()
    } else if bytes.first() == Some(&b'{') {
        Some(bytes.to_vec())
    } else {
        None
    }
}

/// Parses a Firefox / Gecko `recovery.jsonlz4` or `sessionstore.jsonlz4` file and extracts
/// every open tab's active history entry across all open `windows` (ignoring `_closedWindows`).
pub fn parse_firefox_session(bytes: &[u8]) -> Vec<ImportedTab> {
    let Some(json_bytes) = decode_mozlz4_or_json(bytes) else {
        return Vec::new();
    };
    let Ok(root) = serde_json::from_slice::<serde_json::Value>(&json_bytes) else {
        return Vec::new();
    };
    let Some(windows) = root.get("windows").and_then(|v| v.as_array()) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for win in windows {
        let Some(tabs) = win.get("tabs").and_then(|v| v.as_array()) else {
            continue;
        };
        for tab in tabs {
            let Some(entries) = tab.get("entries").and_then(|v| v.as_array()) else {
                continue;
            };
            if entries.is_empty() {
                continue;
            }
            // Firefox `tab.index` is 1-based; clamp safely to 1..=entries.len()
            let idx_1based = tab
                .get("index")
                .and_then(|v| v.as_u64())
                .map(|i| i as usize)
                .unwrap_or(entries.len())
                .clamp(1, entries.len());
            let entry = &entries[idx_1based - 1];
            let Some(url) = entry.get("url").and_then(|v| v.as_str()) else {
                continue;
            };
            if !is_importable_http_url(url) {
                continue;
            }
            let title = entry.get("title").and_then(|v| v.as_str()).unwrap_or("");
            out.push(ImportedTab {
                title: clean_title(title, url),
                url: url.trim().to_string(),
            });
            if out.len() >= MAX_TABS_PER_BROWSER {
                return out;
            }
        }
    }
    out
}

/// Parses a Firefox `bookmarkbackups/*.jsonlz4` snapshot to extract bookmarks without SQLite.
pub fn parse_firefox_bookmarks_lz4(bytes: &[u8]) -> Vec<ImportedBookmark> {
    let Some(json_bytes) = decode_mozlz4_or_json(bytes) else {
        return Vec::new();
    };
    let Ok(root) = serde_json::from_slice::<serde_json::Value>(&json_bytes) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    fn walk(node: &serde_json::Value, out: &mut Vec<ImportedBookmark>) {
        if out.len() >= MAX_BOOKMARKS_PER_BROWSER {
            return;
        }
        if let Some(uri) = node.get("uri").and_then(|v| v.as_str()) {
            if is_importable_http_url(uri) {
                let title = node.get("title").and_then(|v| v.as_str()).unwrap_or("");
                out.push(ImportedBookmark {
                    title: clean_title(title, uri),
                    url: uri.trim().to_string(),
                });
            }
        }
        if let Some(children) = node.get("children").and_then(|v| v.as_array()) {
            for child in children {
                walk(child, out);
                if out.len() >= MAX_BOOKMARKS_PER_BROWSER {
                    break;
                }
            }
        }
    }
    walk(&root, &mut out);
    out
}

fn extract_chromium_profile(profile_dir: &Path) -> ExtractedBrowserData {
    let mut data = ExtractedBrowserData::default();

    // 1. Modern Chromium `Sessions/Session_<timestamp>` (newest first; fallback to previous if empty)
    let sessions_dir = profile_dir.join("Sessions");
    if sessions_dir.is_dir() {
        let mut session_files: Vec<(std::time::SystemTime, String, PathBuf)> =
            std::fs::read_dir(&sessions_dir)
                .ok()
                .into_iter()
                .flatten()
                .flatten()
                .filter_map(|e| {
                    let name = e.file_name().to_string_lossy().to_string();
                    if !name.starts_with("Session_") {
                        return None;
                    }
                    let path = e.path();
                    let mtime = e
                        .metadata()
                        .ok()
                        .and_then(|m| m.modified().ok())
                        .unwrap_or(std::time::UNIX_EPOCH);
                    Some((mtime, name, path))
                })
                .collect();
        session_files.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)));
        for (_, _, path) in session_files.into_iter().take(2) {
            if let Some(bytes) = read_bounded_file(&path) {
                let parsed = parse_chromium_snss_session(&bytes);
                if !parsed.is_empty() {
                    data.tabs = parsed;
                    break;
                }
            }
        }
    }

    // 2. Legacy Chromium / Opera fallback: `Current Session` / `Last Session`
    if data.tabs.is_empty() {
        for candidate in ["Current Session", "Last Session"] {
            let p = profile_dir.join(candidate);
            if let Some(bytes) = read_bounded_file(&p) {
                let parsed = parse_chromium_snss_session(&bytes);
                if !parsed.is_empty() {
                    data.tabs = parsed;
                    break;
                }
            }
        }
    }

    // 3. Chromium `Bookmarks` JSON
    let bm_path = profile_dir.join("Bookmarks");
    if let Some(bytes) = read_bounded_file(&bm_path) {
        data.bookmarks = parse_chromium_bookmarks(&bytes);
    }

    data
}

fn extract_firefox_profile(profile_dir: &Path) -> ExtractedBrowserData {
    let mut data = ExtractedBrowserData::default();

    // Priority: live `recovery.jsonlz4` -> `sessionstore.jsonlz4` -> `recovery.baklz4` -> `previous.jsonlz4` -> legacy `sessionstore.js`
    let candidates = [
        profile_dir.join("sessionstore-backups").join("recovery.jsonlz4"),
        profile_dir.join("sessionstore.jsonlz4"),
        profile_dir.join("sessionstore-backups").join("recovery.baklz4"),
        profile_dir.join("sessionstore-backups").join("previous.jsonlz4"),
        profile_dir.join("sessionstore.js"),
    ];
    for path in candidates {
        if let Some(bytes) = read_bounded_file(&path) {
            let parsed = parse_firefox_session(&bytes);
            if !parsed.is_empty() {
                data.tabs = parsed;
                break;
            }
        }
    }

    // Latest `bookmarkbackups/*.jsonlz4`
    let bm_dir = profile_dir.join("bookmarkbackups");
    if bm_dir.is_dir() {
        let mut backups: Vec<(std::time::SystemTime, PathBuf)> = std::fs::read_dir(&bm_dir)
            .ok()
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| {
                let path = e.path();
                let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
                if ext != "jsonlz4" && ext != "json" {
                    return None;
                }
                let mtime = e
                    .metadata()
                    .ok()
                    .and_then(|m| m.modified().ok())
                    .unwrap_or(std::time::UNIX_EPOCH);
                Some((mtime, path))
            })
            .collect();
        backups.sort_by(|a, b| b.0.cmp(&a.0));
        if let Some((_, newest)) = backups.first() {
            if let Some(bytes) = read_bounded_file(newest) {
                data.bookmarks = parse_firefox_bookmarks_lz4(&bytes);
            }
        }
    }

    data
}

fn extract_spec_data(spec: &BrowserSpec) -> ExtractedBrowserData {
    let mut combined = ExtractedBrowserData::default();
    let mut seen_tab_urls: HashSet<String> = HashSet::new();
    let mut seen_bm_urls: HashSet<String> = HashSet::new();

    for data_dir in &spec.data_dirs {
        if !data_dir.is_dir() {
            continue;
        }
        let profile_dirs: Vec<PathBuf> = match spec.engine {
            BrowserEngineKind::Chromium => collect_chromium_profile_dirs(data_dir, false),
            BrowserEngineKind::ChromiumRootProfile => collect_chromium_profile_dirs(data_dir, true),
            BrowserEngineKind::Firefox => std::fs::read_dir(data_dir)
                .ok()
                .into_iter()
                .flatten()
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.is_dir())
                .collect(),
        };

        for pdir in profile_dirs {
            let prof_data = match spec.engine {
                BrowserEngineKind::Chromium | BrowserEngineKind::ChromiumRootProfile => {
                    extract_chromium_profile(&pdir)
                }
                BrowserEngineKind::Firefox => extract_firefox_profile(&pdir),
            };
            for tab in prof_data.tabs {
                if combined.tabs.len() >= MAX_TABS_PER_BROWSER {
                    break;
                }
                if seen_tab_urls.insert(tab.url.clone()) {
                    combined.tabs.push(tab);
                }
            }
            for bm in prof_data.bookmarks {
                if combined.bookmarks.len() >= MAX_BOOKMARKS_PER_BROWSER {
                    break;
                }
                if seen_bm_urls.insert(bm.url.clone()) {
                    combined.bookmarks.push(bm);
                }
            }
        }
    }

    combined
}

/// Scans this PC for all installed desktop browsers and returns live counts of their open tabs
/// and bookmarks (strictly read-only, 100% local).
pub fn scan_installed_browsers() -> Vec<DetectedBrowserInfo> {
    let catalog = build_browser_catalog();
    let mut results = Vec::new();

    for spec in &catalog {
        if !spec_is_installed(spec) {
            continue;
        }
        let data = extract_spec_data(spec);
        let sample_titles: Vec<String> = data
            .tabs
            .iter()
            .take(3)
            .map(|t| t.title.clone())
            .collect();
        results.push(DetectedBrowserInfo {
            id: spec.id.to_string(),
            name: spec.name.to_string(),
            engine: match spec.engine {
                BrowserEngineKind::Firefox => "firefox".to_string(),
                _ => "chromium".to_string(),
            },
            accent: spec.accent.to_string(),
            open_tabs_count: data.tabs.len(),
            bookmarks_count: data.bookmarks.len(),
            sample_titles,
        });
    }

    // Prioritize browsers with the most open tabs, then bookmarks, then alphabetical
    results.sort_by(|a, b| {
        b.open_tabs_count
            .cmp(&a.open_tabs_count)
            .then_with(|| b.bookmarks_count.cmp(&a.bookmarks_count))
            .then_with(|| a.name.cmp(&b.name))
    });
    results
}

/// Extracts open tabs & bookmarks from the specified installed browser IDs (deduplicated).
pub fn extract_from_browser_ids(browser_ids: &[String]) -> ExtractedBrowserData {
    let catalog = build_browser_catalog();
    let wanted: HashSet<&str> = browser_ids.iter().map(String::as_str).collect();
    let mut combined = ExtractedBrowserData::default();
    let mut seen_tab_urls: HashSet<String> = HashSet::new();
    let mut seen_bm_urls: HashSet<String> = HashSet::new();

    for spec in &catalog {
        if !wanted.contains(spec.id) || !spec_is_installed(spec) {
            continue;
        }
        let data = extract_spec_data(spec);
        for tab in data.tabs {
            if combined.tabs.len() >= MAX_TABS_PER_BROWSER {
                break;
            }
            if seen_tab_urls.insert(tab.url.clone()) {
                combined.tabs.push(tab);
            }
        }
        for bm in data.bookmarks {
            if combined.bookmarks.len() >= MAX_BOOKMARKS_PER_BROWSER {
                break;
            }
            if seen_bm_urls.insert(bm.url.clone()) {
                combined.bookmarks.push(bm);
            }
        }
    }

    combined
}

fn decode_html_entities(input: &str) -> String {
    if !input.contains('&') {
        return input.to_string();
    }
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'&' {
            if let Some(semi_rel) = input[i..].find(';') {
                if semi_rel <= 12 {
                    let ent = &input[i + 1..i + semi_rel];
                    let decoded = match ent {
                        "amp" => Some('&'),
                        "lt" => Some('<'),
                        "gt" => Some('>'),
                        "quot" => Some('"'),
                        "apos" => Some('\''),
                        "nbsp" => Some(' '),
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
                        i += semi_rel + 1;
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

fn extract_href_from_anchor_attrs(attrs: &str) -> Option<String> {
    let bytes = attrs.as_bytes();
    let len = bytes.len();
    let mut i = 0;
    while i < len {
        let iter_start = i;
        while i < len && (bytes[i].is_ascii_whitespace() || bytes[i] == b'/') {
            i += 1;
        }
        if i >= len {
            break;
        }
        if bytes[i] == b'>' {
            i += 1;
            continue;
        }
        let name_start = i;
        while i < len && !bytes[i].is_ascii_whitespace() && bytes[i] != b'=' && bytes[i] != b'>' {
            i += 1;
        }
        let attr_name = &attrs[name_start..i];
        while i < len && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= len {
            break;
        }
        if bytes[i] == b'>' {
            i += 1;
            continue;
        }
        if bytes[i] != b'=' {
            if i == iter_start {
                i += 1;
            }
            continue;
        }
        i += 1; // skip '='
        while i < len && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= len {
            break;
        }
        let (val_start, val_end, next_i) = if bytes[i] == b'"' || bytes[i] == b'\'' {
            let quote = bytes[i];
            let vs = i + 1;
            let mut j = vs;
            while j < len && bytes[j] != quote {
                j += 1;
            }
            (vs, j, (j + 1).min(len))
        } else {
            let vs = i;
            let mut j = vs;
            while j < len && !bytes[j].is_ascii_whitespace() && bytes[j] != b'>' {
                j += 1;
            }
            let adv = if j < len && bytes[j] == b'>' { j + 1 } else { j };
            (vs, j, adv)
        };
        if attr_name.eq_ignore_ascii_case("href") {
            return Some(decode_html_entities(attrs[val_start..val_end].trim()));
        }
        i = next_i.max(iter_start + 1);
    }
    None
}

fn strip_html_tags(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut in_tag = false;
    for ch in raw.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(ch),
            _ => {}
        }
    }
    out
}

/// Parses standard Netscape Bookmarks HTML files (`bookmarks.html`) exported by Chrome, Edge,
/// Brave, Opera, Vivaldi, Firefox, Safari, Arc, etc., safely in pure Rust in strictly linear `O(N)` time.
pub fn parse_netscape_bookmarks_html(html: &str) -> Vec<ImportedBookmark> {
    const MAX_ANCHOR_INNER_BYTES: usize = 4096;
    let mut out = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let bytes = html.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    while i + 2 < len && out.len() < MAX_BOOKMARKS_PER_BROWSER {
        if bytes[i] == b'<'
            && (bytes[i + 1] == b'a' || bytes[i + 1] == b'A')
            && (bytes[i + 2].is_ascii_whitespace() || bytes[i + 2] == b'>')
        {
            // Find matching '>' respecting quoted attributes (including large ICON="data:...")
            let attrs_start = i + 2;
            let mut j = attrs_start;
            let mut quote: u8 = 0;
            while j < len {
                let b = bytes[j];
                if quote != 0 {
                    if b == quote {
                        quote = 0;
                    }
                } else if b == b'"' || b == b'\'' {
                    quote = b;
                } else if b == b'>' {
                    break;
                }
                j += 1;
            }
            if j >= len {
                break;
            }
            let attrs = &html[attrs_start..j];
            let content_start = j + 1;

            // Linear single-pass scan until closing `</a>`, next opening `<a`, or EOF.
            // Because `i` always advances to at least `k`, each byte is visited at most once (O(N)).
            let mut k = content_start;
            let mut content_end = len;
            let mut next_i = len;
            while k + 2 < len {
                if bytes[k] == b'<' {
                    if k + 3 < len
                        && bytes[k + 1] == b'/'
                        && (bytes[k + 2] == b'a' || bytes[k + 2] == b'A')
                        && (bytes[k + 3] == b'>' || bytes[k + 3].is_ascii_whitespace())
                    {
                        content_end = k;
                        let mut end_tag = k + 3;
                        while end_tag < len && bytes[end_tag] != b'>' {
                            end_tag += 1;
                        }
                        next_i = if end_tag < len { end_tag + 1 } else { len };
                        break;
                    }
                    if (bytes[k + 1] == b'a' || bytes[k + 1] == b'A')
                        && (bytes[k + 2].is_ascii_whitespace() || bytes[k + 2] == b'>')
                    {
                        // Implicitly close unclosed `<a>` before the next `<a ...>` without rescanning
                        content_end = k;
                        next_i = k;
                        break;
                    }
                }
                k += 1;
            }
            if let Some(href) = extract_href_from_anchor_attrs(attrs) {
                let url = href.trim().to_string();
                if is_importable_http_url(&url) && seen.insert(url.clone()) {
                    let mut bounded_end = content_end.min(content_start.saturating_add(MAX_ANCHOR_INNER_BYTES));
                    while bounded_end > content_start && !html.is_char_boundary(bounded_end) {
                        bounded_end -= 1;
                    }
                    let raw_inner = &html[content_start..bounded_end];
                    let stripped = strip_html_tags(raw_inner);
                    let decoded_title = decode_html_entities(&stripped);
                    let title = clean_title(&decoded_title, &url);
                    out.push(ImportedBookmark { title, url });
                }
            }
            i = next_i;
        } else {
            i += 1;
        }
    }
    out
}

fn collect_generic_json_bookmarks(
    val: &serde_json::Value,
    out: &mut Vec<ImportedBookmark>,
    seen: &mut HashSet<String>,
) {
    if out.len() >= MAX_BOOKMARKS_PER_BROWSER {
        return;
    }
    match val {
        serde_json::Value::Array(arr) => {
            for item in arr {
                collect_generic_json_bookmarks(item, out, seen);
                if out.len() >= MAX_BOOKMARKS_PER_BROWSER {
                    break;
                }
            }
        }
        serde_json::Value::Object(map) => {
            let url_opt = map
                .get("url")
                .and_then(|v| v.as_str())
                .or_else(|| map.get("uri").and_then(|v| v.as_str()))
                .or_else(|| map.get("href").and_then(|v| v.as_str()));
            if let Some(u) = url_opt {
                let url = u.trim().to_string();
                if is_importable_http_url(&url) && seen.insert(url.clone()) {
                    let raw_title = map
                        .get("title")
                        .and_then(|v| v.as_str())
                        .or_else(|| map.get("name").and_then(|v| v.as_str()))
                        .unwrap_or("");
                    out.push(ImportedBookmark {
                        title: clean_title(raw_title, &url),
                        url,
                    });
                }
            }
            for child_key in ["bookmarks", "children", "items", "roots"] {
                if let Some(sub) = map.get(child_key) {
                    collect_generic_json_bookmarks(sub, out, seen);
                }
            }
        }
        _ => {}
    }
}

/// Parses an exported bookmarks file in any common browser export format:
/// - Standard Netscape Bookmarks HTML (`.html` / `.htm` from Chrome, Edge, Firefox, Brave, Opera, Safari)
/// - Chromium `Bookmarks` JSON (`roots.bookmark_bar` / `roots.other` / `roots.synced`)
/// - Firefox JSON backup (`children` + `uri` / `title`)
/// - Singularity / generic JSON array or `{ "bookmarks": [...] }`
pub fn parse_exported_bookmarks_file(filename: &str, content: &str) -> Vec<ImportedBookmark> {
    let trimmed = content.trim_start_matches('\u{feff}').trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let lower_name = filename.to_ascii_lowercase();
    let looks_json = trimmed.starts_with('{')
        || trimmed.starts_with('[')
        || lower_name.ends_with(".json");

    if looks_json {
        // 1. Chromium native `Bookmarks` JSON structure first
        let mut from_chromium = parse_chromium_bookmarks(trimmed.as_bytes());
        if !from_chromium.is_empty() {
            let mut seen = HashSet::new();
            from_chromium.retain(|b| seen.insert(b.url.clone()));
            from_chromium.truncate(MAX_BOOKMARKS_PER_BROWSER);
            return from_chromium;
        }
        // 2. Firefox JSON backup / Singularity JSON / generic array
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) {
            let mut out = Vec::new();
            let mut seen = HashSet::new();
            collect_generic_json_bookmarks(&val, &mut out, &mut seen);
            if !out.is_empty() {
                return out;
            }
        }
    }

    parse_netscape_bookmarks_html(trimmed)
}

fn escape_html_text(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Formats Singularity bookmarks as a standards-compliant Netscape Bookmarks HTML file
/// directly importable by Chrome, Edge, Firefox, Brave, Opera, Safari, and Singularity.
pub fn format_netscape_bookmarks_html(bookmarks: &[(String, String)]) -> String {
    let mut out = String::from(
        "<!DOCTYPE NETSCAPE-Bookmark-file-1>\n\
         <!-- This is an automatically generated file exported by Singularity Browser. -->\n\
         <META HTTP-EQUIV=\"Content-Type\" CONTENT=\"text/html; charset=UTF-8\">\n\
         <TITLE>Singularity Bookmarks</TITLE>\n\
         <H1>Singularity Bookmarks</H1>\n\
         <DL><p>\n\
         \x20\x20<DT><H3 PERSONAL_TOOLBAR_FOLDER=\"true\">Bookmarks Bar</H3>\n\
         \x20\x20<DL><p>\n",
    );
    for (title, url) in bookmarks {
        if !is_importable_http_url(url) {
            continue;
        }
        out.push_str("    <DT><A HREF=\"");
        out.push_str(&escape_html_text(url.trim()));
        out.push_str("\">");
        out.push_str(&escape_html_text(title.trim()));
        out.push_str("</A>\n");
    }
    out.push_str("  </DL><p>\n</DL><p>\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_snss_cmd(buf: &mut Vec<u8>, cmd_id: u8, payload: &[u8]) {
        let size = (payload.len() + 1) as u16;
        buf.extend_from_slice(&size.to_le_bytes());
        buf.push(cmd_id);
        buf.extend_from_slice(payload);
    }

    fn build_nav_pickle(tab_id: i32, nav_idx: i32, url: &str, title: &str) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&tab_id.to_le_bytes());
        body.extend_from_slice(&nav_idx.to_le_bytes());
        // Pickle ReadString (UTF-8, 4-byte padded)
        body.extend_from_slice(&(url.len() as u32).to_le_bytes());
        body.extend_from_slice(url.as_bytes());
        while body.len() % 4 != 0 {
            body.push(0);
        }
        // Pickle ReadString16 (UTF-16LE, 4-byte padded)
        let utf16: Vec<u16> = title.encode_utf16().collect();
        body.extend_from_slice(&(utf16.len() as u32).to_le_bytes());
        for ch in utf16 {
            body.extend_from_slice(&ch.to_le_bytes());
        }
        while body.len() % 4 != 0 {
            body.push(0);
        }
        let mut out = Vec::new();
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(&body);
        out
    }

    #[test]
    fn test_chromium_snss_parser_extracts_open_tabs_and_ignores_closed() {
        let mut snss = Vec::new();
        snss.extend_from_slice(b"SNSS");
        snss.extend_from_slice(&3u32.to_le_bytes());

        // Window 10: Tab 1 (index 1, navigated 0->1), Tab 2 (index 0), Tab 3 (closed!)
        for (win, tab, idx) in [(10i32, 1i32, 1i32), (10, 2, 0), (10, 3, 2), (20, 4, 0)] {
            let mut p = Vec::new();
            p.extend_from_slice(&win.to_le_bytes());
            p.extend_from_slice(&tab.to_le_bytes());
            push_snss_cmd(&mut snss, 0, &p);

            let mut pi = Vec::new();
            pi.extend_from_slice(&tab.to_le_bytes());
            pi.extend_from_slice(&idx.to_le_bytes());
            push_snss_cmd(&mut snss, 2, &pi);
        }

        // Tab 1 has two history entries; select index 1
        push_snss_cmd(
            &mut snss,
            6,
            &build_nav_pickle(1, 0, "https://www.youtube.com/", "YouTube"),
        );
        push_snss_cmd(
            &mut snss,
            6,
            &build_nav_pickle(
                1,
                1,
                "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
                "My Video",
            ),
        );
        let mut sel = Vec::new();
        sel.extend_from_slice(&1i32.to_le_bytes());
        sel.extend_from_slice(&1i32.to_le_bytes());
        push_snss_cmd(&mut snss, 7, &sel);

        // Tab 2 (index 0 -> should appear first!)
        push_snss_cmd(
            &mut snss,
            6,
            &build_nav_pickle(2, 0, "https://github.com/MyMasha/Singularity", "Singularity"),
        );
        // Tab 3 -> closed via kCommandTabClosed (16)
        push_snss_cmd(
            &mut snss,
            6,
            &build_nav_pickle(3, 0, "https://closed-tab.example.com/", "Closed"),
        );
        push_snss_cmd(&mut snss, 16, &3i32.to_le_bytes());

        // Tab 4 in Window 20 -> window closed via kCommandWindowClosed (17)
        push_snss_cmd(
            &mut snss,
            6,
            &build_nav_pickle(4, 0, "https://closed-win.example.com/", "Closed Win"),
        );
        push_snss_cmd(&mut snss, 17, &20i32.to_le_bytes());

        let tabs = parse_chromium_snss_session(&snss);
        assert_eq!(tabs.len(), 2);
        assert_eq!(tabs[0].url, "https://github.com/MyMasha/Singularity");
        assert_eq!(tabs[0].title, "Singularity");
        assert_eq!(tabs[1].url, "https://www.youtube.com/watch?v=dQw4w9WgXcQ");
        assert_eq!(tabs[1].title, "My Video");
    }

    #[test]
    fn test_firefox_mozlz4_session_and_bookmarks_parsing() {
        let json = br#"{"windows":[{"tabs":[{"index":2,"entries":[{"url":"https://old.example.com","title":"Old"},{"url":"https://www.twitch.tv/shroud","title":"Shroud Live"}]},{"index":1,"entries":[{"url":"about:preferences","title":"Prefs"}]}]}],"_closedWindows":[{"tabs":[{"index":1,"entries":[{"url":"https://closed.example.com","title":"Closed"}]}]}]}"#;
        // Encode a valid uncompressed raw LZ4 block: literal length header + raw literals
        let mut lz4 = Vec::new();
        let mut rem = json.len();
        if rem < 15 {
            lz4.push((rem as u8) << 4);
        } else {
            lz4.push(0xF0);
            rem -= 15;
            while rem >= 255 {
                lz4.push(255);
                rem -= 255;
            }
            lz4.push(rem as u8);
        }
        lz4.extend_from_slice(json);

        let mut mozlz4 = Vec::new();
        mozlz4.extend_from_slice(b"mozLz40\0");
        mozlz4.extend_from_slice(&(json.len() as u32).to_le_bytes());
        mozlz4.extend_from_slice(&lz4);

        let tabs = parse_firefox_session(&mozlz4);
        assert_eq!(tabs.len(), 1);
        assert_eq!(tabs[0].url, "https://www.twitch.tv/shroud");
        assert_eq!(tabs[0].title, "Shroud Live");

        // Also test LZ4 match back-reference decompression (overlapping RLE copy)
        // 1 literal 'A' + match offset=1, len=4+6=10 -> "AAAAAAAAAAA" (11 'A's)
        let rle_lz4 = [0x16u8, b'A', 0x01, 0x00];
        let dec = decompress_lz4_block(&rle_lz4, 11).expect("decompress RLE match");
        assert_eq!(dec, b"AAAAAAAAAAA");

        // Also test Chromium Bookmarks JSON parsing
        let bm_json = br#"{"roots":{"bookmark_bar":{"type":"folder","children":[{"type":"url","name":"Rust","url":"https://www.rust-lang.org/"},{"type":"url","name":"Internal","url":"chrome://settings"}]}}}"#;
        let bms = parse_chromium_bookmarks(bm_json);
        assert_eq!(bms.len(), 1);
        assert_eq!(bms[0].title, "Rust");
        assert_eq!(bms[0].url, "https://www.rust-lang.org/");
    }

    #[test]
    fn test_netscape_html_and_json_bookmark_import_export_roundtrip() {
        let chrome_html = r#"<!DOCTYPE NETSCAPE-Bookmark-file-1>
<META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=UTF-8">
<TITLE>Bookmarks</TITLE>
<DL><p>
  <DT><H3 PERSONAL_TOOLBAR_FOLDER="true">Bookmarks bar</H3>
  <DL><p>
    <DT><A HREF="https://www.youtube.com/watch?v=abc&amp;t=42" ADD_DATE="1700000000" ICON="data:image/png;base64,AAAA">YouTube &amp; Chill</A>
    <DT><A href='https://github.com/MyMasha/Singularity'>Singularity &lt;Browser&gt;</A>
    <DT><A HREF="javascript:alert(1)">XSS Bookmark</A>
    <DT><A HREF="chrome://extensions">Internal Chrome</A>
    <DT><A HREF="https://www.youtube.com/watch?v=abc&amp;t=42">Duplicate Entry</A>
  </DL><p>
</DL><p>"#;

        let parsed = parse_exported_bookmarks_file("bookmarks_2026.html", chrome_html);
        assert_eq!(parsed.len(), 2, "must skip javascript:, chrome:, and duplicates");
        assert_eq!(parsed[0].url, "https://www.youtube.com/watch?v=abc&t=42");
        assert_eq!(parsed[0].title, "YouTube & Chill");
        assert_eq!(parsed[1].url, "https://github.com/MyMasha/Singularity");
        assert_eq!(parsed[1].title, "Singularity <Browser>");

        // Export to Netscape HTML and roundtrip parse cleanly
        let pairs: Vec<(String, String)> = parsed
            .iter()
            .map(|b| (b.title.clone(), b.url.clone()))
            .collect();
        let exported = format_netscape_bookmarks_html(&pairs);
        assert!(exported.contains("<!DOCTYPE NETSCAPE-Bookmark-file-1>"));
        assert!(exported.contains("YouTube &amp; Chill"));
        assert!(exported.contains("Singularity &lt;Browser&gt;"));
        let roundtrip = parse_netscape_bookmarks_html(&exported);
        assert_eq!(roundtrip, parsed);

        // Firefox JSON backup format (`uri` + `children`)
        let ff_json = r#"{"type":"text/x-moz-place-container","children":[{"title":"Proton Mail","uri":"https://mail.proton.me/"},{"title":"Bad","uri":"place:sort=8"}]}"#;
        let ff_bms = parse_exported_bookmarks_file("bookmarks-2026.json", ff_json);
        assert_eq!(ff_bms.len(), 1);
        assert_eq!(ff_bms[0].title, "Proton Mail");
        assert_eq!(ff_bms[0].url, "https://mail.proton.me/");

        // Simple JSON array export
        let simple_json = r#"[{"title":"Docs","url":"https://docs.rs/"},{"title":"Loopback","url":"http://127.0.0.1:8080/"}]"#;
        let simple_bms = parse_exported_bookmarks_file("my-bookmarks.json", simple_json);
        assert_eq!(simple_bms.len(), 1);
        assert_eq!(simple_bms[0].url, "https://docs.rs/");
    }

    #[test]
    fn test_anchor_attr_parser_no_infinite_loop_on_gt_without_equals() {
        assert_eq!(extract_href_from_anchor_attrs(">"), None);
        assert_eq!(extract_href_from_anchor_attrs("foo> bar>"), None);
        assert_eq!(
            extract_href_from_anchor_attrs("data-x> href=\"https://example.org/a\""),
            Some("https://example.org/a".to_string())
        );
        assert_eq!(
            extract_href_from_anchor_attrs("a=> b> href=https://example.org/b"),
            Some("https://example.org/b".to_string())
        );
        assert_eq!(extract_href_from_anchor_attrs("é> >>>"), None);
    }

    #[test]
    fn test_netscape_bookmarks_linear_time_on_many_unclosed_anchors() {
        let mut payload = String::with_capacity(200_000);
        for idx in 0..5_000 {
            payload.push_str(&format!("<a href=\"https://example.org/item/{}\">Item {}", idx, idx));
        }
        let parsed = parse_netscape_bookmarks_html(&payload);
        assert_eq!(parsed.len(), MAX_BOOKMARKS_PER_BROWSER);
        assert_eq!(parsed[0].url, "https://example.org/item/0");
        assert_eq!(parsed[0].title, "Item 0");

        // Also test many unclosed non-matching anchors followed by one valid anchor
        let mut non_matching = String::with_capacity(500_000);
        for _ in 0..20_000 {
            non_matching.push_str("<a data-x=\"1\">unclosed ");
        }
        non_matching.push_str("<a href=\"https://rust-lang.org/\">Rust</a>");
        let parsed2 = parse_netscape_bookmarks_html(&non_matching);
        assert_eq!(parsed2.len(), 1);
        assert_eq!(parsed2[0].url, "https://rust-lang.org/");
        assert_eq!(parsed2[0].title, "Rust");
    }
}
