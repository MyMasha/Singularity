//! Pure Chromium Embedded Framework (CEF) Runtime Engine for Singularity Browser on Windows.
//!
//! Replaces Microsoft Edge WebView2 (`wry` / `msedgewebview2.exe`) completely with pure
//! Chromium (`libcef.dll` via `cef` 150.2.1 / branch 7871 with proprietary H.264/AAC/HEVC codecs):
//! - **Single Chromium Browser Process** shared across ALL Singularity windows & tabs
//!   (one GPU process, one Network Service, one Storage Service — eliminates multi-window
//!   WebView2 process-tree duplication!).
//! - **Zero Microsoft Edge bloat**: disables `BackForwardCache`, `OptimizationHints`, `MediaRouter`,
//!   `Translate`, `AutofillServerCommunication`, component updates, background networking, and
//!   enforces `--process-per-site` + bounded 64 MiB disk / 32 MiB media caches.
//! - **Real Chromium Network-Layer uBlock Blocker**: cancels ads & trackers in
//!   `ResourceRequestHandler::on_before_resource_load` BEFORE Chromium connects or allocates RAM.
//! - **Native V8 `window.ipc.postMessage` + Document-Start Injection**: binds `window.ipc` and runs
//!   content/start-paused scripts inside `RenderProcessHandler::on_context_created` BEFORE page JS.
//! - **External Message Pump**: runs CEF's UI work on the exact same Win32 thread as `tao` via
//!   `on_schedule_message_pump_work` (zero busy polling, zero cross-thread HWND focus bugs).

#![cfg(target_os = "windows")]

use crate::roaming_store::{
    classify_auth_cookie, classify_tracker_or_malicious_cookie,
    is_protected_session_or_functional_cookie, unix_now, CookieThreatKind,
    EncryptedAuthTokenRecord,
};
use crate::shell::SingularityBrowserShell;
use cef::*;
use singularity_core::{FilterDecision, NetworkResourceType};
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

const WINDOWS_TO_UNIX_EPOCH_US: i64 = 11_644_473_600_000_000;
const IPC_MESSAGE_NAME: &str = "sg_ipc";
const LEGACY_IPC_MESSAGE_NAME: &str = "singularity_ipc";

fn monotonic_millis() -> u64 {
    static START: OnceLock<std::time::Instant> = OnceLock::new();
    let epoch = START.get_or_init(std::time::Instant::now);
    (epoch.elapsed().as_millis() as u64).saturating_add(1)
}

#[link(name = "user32")]
extern "system" {
    fn SetWindowPos(
        hwnd: *mut core::ffi::c_void,
        hwnd_insert_after: *mut core::ffi::c_void,
        x: i32,
        y: i32,
        cx: i32,
        cy: i32,
        uflags: u32,
    ) -> i32;
    fn ShowWindow(hwnd: *mut core::ffi::c_void, n_cmd_show: i32) -> i32;
    fn InvalidateRect(
        hwnd: *mut core::ffi::c_void,
        lp_rect: *const core::ffi::c_void,
        b_erase: i32,
    ) -> i32;
    fn UpdateWindow(hwnd: *mut core::ffi::c_void) -> i32;
    fn SetFocus(hwnd: *mut core::ffi::c_void) -> *mut core::ffi::c_void;
    fn GetAsyncKeyState(vkey: i32) -> i16;
}

#[link(name = "kernel32")]
extern "system" {
    fn GetCurrentProcess() -> *mut core::ffi::c_void;
    fn K32EmptyWorkingSet(hprocess: *mut core::ffi::c_void) -> i32;
    fn CreatePipe(
        h_read_pipe: *mut *mut core::ffi::c_void,
        h_write_pipe: *mut *mut core::ffi::c_void,
        lp_pipe_attributes: *const core::ffi::c_void,
        n_size: u32,
    ) -> i32;
    fn ReadFile(
        h_file: *mut core::ffi::c_void,
        lp_buffer: *mut u8,
        n_number_of_bytes_to_read: u32,
        lp_number_of_bytes_read: *mut u32,
        lp_overlapped: *mut core::ffi::c_void,
    ) -> i32;
    fn WriteFile(
        h_file: *mut core::ffi::c_void,
        lp_buffer: *const u8,
        n_number_of_bytes_to_write: u32,
        lp_number_of_bytes_written: *mut u32,
        lp_overlapped: *mut core::ffi::c_void,
    ) -> i32;
    fn CloseHandle(h_object: *mut core::ffi::c_void) -> i32;
}

/// Releases idle working-set pages back to Windows when a window is minimized or idle.
pub fn trim_process_working_set() {
    unsafe {
        let _ = K32EmptyWorkingSet(GetCurrentProcess());
    }
}

fn is_ctrl_or_mbutton_down_cef() -> bool {
    const VK_MBUTTON: i32 = 0x04;
    const VK_CONTROL: i32 = 0x11;
    unsafe {
        ((GetAsyncKeyState(VK_MBUTTON) as u16) & 0x8000) != 0
            || ((GetAsyncKeyState(VK_CONTROL) as u16) & 0x8000) != 0
    }
}

/// Callback events emitted from CEF browser/client handlers into `server.rs`'s `tao` event loop.
#[derive(Debug, Clone)]
pub enum CefCallbackEvent {
    BrowserCreated {
        tab_id: u64,
        is_ui: bool,
        hwnd: isize,
    },
    DestroyChildHwnd {
        hwnd: isize,
    },
    UiIpc(String),
    ContentIpc {
        tab_id: u64,
        body: String,
    },
    PageStarted {
        tab_id: u64,
        url: String,
    },
    PageFinished {
        tab_id: u64,
        url: String,
        http_status: i32,
    },
    LoadError {
        tab_id: u64,
        is_ui: bool,
        error_code: i32,
        error_text: String,
        failed_url: String,
    },
    RenderProcessTerminated {
        tab_id: u64,
        is_ui: bool,
        status: i32,
        error_code: i32,
        error_string: String,
    },
    AddressChanged {
        tab_id: u64,
        url: String,
    },
    TitleChanged {
        tab_id: u64,
        title: String,
    },
    FaviconChanged {
        tab_id: u64,
        favicon_url: String,
    },
    FullscreenChanged {
        tab_id: u64,
        enabled: bool,
    },
    OpenNewTab {
        url: String,
        background: bool,
    },
    DownloadStarted {
        download_id: u32,
        filename: String,
        path: String,
    },
    DownloadCompleted {
        download_id: u32,
        filename: String,
        path: String,
        success: bool,
    },
    NavigationStateChanged {
        tab_id: u64,
        can_go_back: bool,
        can_go_forward: bool,
    },
    NativeShortcut {
        tab_id: u64,
        action: &'static str,
    },
    CloseExtensionPopup,
}

pub type CefEventSink = Arc<dyn Fn(CefCallbackEvent) + Send + Sync>;
pub type CefPumpCallback = Arc<dyn Fn(i64) + Send + Sync>;
pub type CefRelaunchCallback = Arc<dyn Fn() + Send + Sync>;
pub type CefDownloadResolver = Arc<dyn Fn(&str, &str) -> (PathBuf, String) + Send + Sync>;

#[derive(Clone, Default)]
struct RendererBrowserConfig {
    is_ui: bool,
    ui_port: u16,
    init_script: String,
    resume_script: String,
}

thread_local! {
    static RENDERER_CONFIGS: RefCell<HashMap<i32, RendererBrowserConfig>> =
        RefCell::new(HashMap::new());
}

fn cef_str_userfree(s: CefStringUserfree) -> String {
    CefString::from(&s).to_string()
}

fn starts_with_ignore_ascii_case(haystack: &str, prefix: &str) -> bool {
    haystack.len() >= prefix.len() && haystack[..prefix.len()].eq_ignore_ascii_case(prefix)
}

fn strip_prefix_ignore_ascii_case<'a>(haystack: &'a str, prefix: &str) -> Option<&'a str> {
    if starts_with_ignore_ascii_case(haystack, prefix) {
        Some(&haystack[prefix.len()..])
    } else {
        None
    }
}

/// Strictly validates that `url` is on the exact local UI shell origin `http://127.0.0.1:<ui_port>`.
fn is_exact_local_ui_origin(url: &str, ui_port: u16) -> bool {
    if ui_port == 0 {
        return false;
    }
    let trimmed = url.trim();
    if trimmed.is_empty() || trimmed.bytes().any(|b| b < 0x20 || b == 0x7F || b == b'\\') {
        return false;
    }
    let Some(rest) = strip_prefix_ignore_ascii_case(trimmed, "http://") else {
        return false;
    };
    let expected_authority = format!("127.0.0.1:{ui_port}");
    let Some(after_auth) = rest.strip_prefix(&expected_authority) else {
        return false;
    };
    after_auth.is_empty()
        || after_auth.starts_with('/')
        || after_auth.starts_with('?')
        || after_auth.starts_with('#')
}

fn parse_http_or_ws_host_port(url: &str, allow_ws: bool) -> Option<(String, u16)> {
    // Reject C0/DEL control bytes anywhere in the URL (prevents browser stripping bypasses like `ht\ttp://`).
    if url.bytes().any(|b| b < 0x20 || b == 0x7F) {
        return None;
    }
    let trimmed = url.trim();
    let (default_port, rest) = if let Some(r) = strip_prefix_ignore_ascii_case(trimmed, "https://")
    {
        (443u16, r)
    } else if let Some(r) = strip_prefix_ignore_ascii_case(trimmed, "http://") {
        (80u16, r)
    } else if allow_ws {
        if let Some(r) = strip_prefix_ignore_ascii_case(trimmed, "wss://") {
            (443u16, r)
        } else if let Some(r) = strip_prefix_ignore_ascii_case(trimmed, "ws://") {
            (80u16, r)
        } else {
            return None;
        }
    } else {
        return None;
    };

    // Chromium/WHATWG treats `\` identically to `/` as an authority terminator for special schemes.
    let authority = rest.split(['/', '\\', '?', '#']).next().unwrap_or("");
    if authority.is_empty() || authority.bytes().any(|b| b.is_ascii_whitespace()) {
        return None;
    }

    // Per WHATWG URL spec, if userinfo is present, the effective host:port follows the LAST `@`.
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
            || host.parse::<Ipv6Addr>().is_err()
        {
            return None;
        }
        let port = if tail.is_empty() || tail == ":" {
            default_port
        } else if let Some(p) = tail.strip_prefix(':') {
            if !p.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            let parsed = p.parse::<u16>().ok()?;
            if parsed == 0 {
                return None;
            }
            parsed
        } else {
            return None;
        };
        return Some((host.to_ascii_lowercase(), port));
    }

    if hostport.contains('[') || hostport.contains(']') {
        return None;
    }

    let (host, port) = match hostport.split_once(':') {
        Some((h, p)) => {
            if p.contains(':') {
                // Reject unbracketed IPv6 or double-port ambiguity.
                return None;
            }
            let port = if p.is_empty() {
                default_port
            } else {
                if !p.bytes().all(|b| b.is_ascii_digit()) {
                    return None;
                }
                let parsed = p.parse::<u16>().ok()?;
                if parsed == 0 {
                    return None;
                }
                parsed
            };
            (h, port)
        }
        None => (hostport, default_port),
    };

    // Reject empty or percent-encoded/ambiguous hostnames (Chromium percent-decodes host labels).
    if host.is_empty() || host.contains('%') || host.bytes().any(|b| b.is_ascii_whitespace()) {
        return None;
    }
    Some((host.to_ascii_lowercase(), port))
}

fn parse_http_host_port(url: &str) -> Option<(String, u16)> {
    parse_http_or_ws_host_port(url, false)
}

fn parse_whatwg_ipv4_part(part: &str) -> Option<u64> {
    if part.is_empty() {
        return None;
    }
    if let Some(hex) = part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
        if hex.is_empty() {
            return Some(0);
        }
        if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        return u64::from_str_radix(hex, 16).ok();
    }
    if part.len() > 1 && part.starts_with('0') {
        if !part.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
            return None;
        }
        return u64::from_str_radix(part, 8).ok();
    }
    if !part.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    part.parse::<u64>().ok()
}

/// Parses WHATWG / POSIX `inet_aton` IPv4 representations including 1..4 dot-separated parts
/// and decimal, octal (`0177.0.0.1`), and hexadecimal (`0x7f000001`, `0x7f.1`) encodings.
fn parse_whatwg_ipv4(host: &str) -> Option<Ipv4Addr> {
    let trimmed = host.trim_end_matches('.');
    if trimmed.is_empty() {
        return None;
    }
    let parts: Vec<&str> = trimmed.split('.').collect();
    if parts.is_empty() || parts.len() > 4 {
        return None;
    }
    let mut nums = Vec::with_capacity(parts.len());
    for part in &parts {
        nums.push(parse_whatwg_ipv4_part(part)?);
    }
    let last_idx = nums.len() - 1;
    for &n in &nums[..last_idx] {
        if n > 255 {
            return None;
        }
    }
    let last_limit: u64 = 1u64 << (8 * (5 - nums.len()));
    if nums[last_idx] >= last_limit {
        return None;
    }
    let val: u32 = match nums.len() {
        1 => nums[0] as u32,
        2 => ((nums[0] as u32) << 24) | (nums[1] as u32),
        3 => ((nums[0] as u32) << 24) | ((nums[1] as u32) << 16) | (nums[2] as u32),
        4 => {
            ((nums[0] as u32) << 24)
                | ((nums[1] as u32) << 16)
                | ((nums[2] as u32) << 8)
                | (nums[3] as u32)
        }
        _ => return None,
    };
    Some(Ipv4Addr::from(val))
}

fn is_local_ipv4(ip: Ipv4Addr) -> bool {
    ip.is_loopback() || ip.is_unspecified() || ip.octets()[0] == 0
}

fn is_local_or_ambiguous_host(host: &str) -> bool {
    // Normalize IDNA fullwidth dot separators to ASCII `.` so `localhost。` cannot slip past.
    let normalized = host
        .replace(['\u{3002}', '\u{FF0E}', '\u{FF61}'], ".")
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if normalized.is_empty() {
        return true;
    }
    if normalized == "localhost" || normalized.ends_with(".localhost") {
        return true;
    }
    if let Ok(v6) = normalized.parse::<Ipv6Addr>() {
        let segs = v6.segments();
        // Block loopback `::1`, unspecified `::`, entire IPv4-mapped `::ffff:0.0.0.0/96`,
        // and deprecated IPv4-compatible `::0.0.0.0/96`.
        let is_ipv4_mapped_prefix = segs[0] == 0
            && segs[1] == 0
            && segs[2] == 0
            && segs[3] == 0
            && segs[4] == 0
            && segs[5] == 0xffff;
        let is_ipv4_compat_prefix =
            segs[0] == 0 && segs[1] == 0 && segs[2] == 0 && segs[3] == 0 && segs[4] == 0 && segs[5] == 0;
        return v6.is_loopback()
            || v6.is_unspecified()
            || is_ipv4_mapped_prefix
            || is_ipv4_compat_prefix
            || v6.to_ipv4_mapped().is_some_and(is_local_ipv4)
            || v6.to_ipv4().is_some_and(is_local_ipv4);
    }
    if normalized.contains(':') {
        // Malformed IPv6 literal: fail closed.
        return true;
    }
    if let Some(v4) = parse_whatwg_ipv4(&normalized) {
        return is_local_ipv4(v4);
    }
    // Fail closed if all labels look numeric/octal/hex (ambiguous IPv4-like literal).
    let looks_numeric = normalized.split('.').all(|part| {
        !part.is_empty()
            && (part.bytes().all(|b| b.is_ascii_digit())
                || part
                    .strip_prefix("0x")
                    .or_else(|| part.strip_prefix("0X"))
                    .is_some_and(|hex| hex.bytes().all(|b| b.is_ascii_hexdigit())))
    });
    if looks_numeric {
        return true;
    }
    false
}

/// Fail-closed guard preventing untrusted web content from reaching `file://` or the local
/// Singularity UI/IPC HTTP server on `bind_port` via scheme/encoding/IP obfuscation.
fn is_blocked_local_ipc_url(nav_url: &str, bind_port: u16) -> bool {
    if nav_url.bytes().any(|b| b < 0x20 || b == 0x7F) {
        return true;
    }
    let mut current = nav_url.trim();
    if current.is_empty() {
        return true;
    }

    // Unwrap nested wrapper schemes (`view-source:`, `blob:`, `filesystem:`) with a strict depth bound.
    for _ in 0..8 {
        if let Some(rest) = strip_prefix_ignore_ascii_case(current, "view-source:") {
            current = rest.trim();
            if current.is_empty() {
                return true;
            }
            continue;
        }
        if let Some(rest) = strip_prefix_ignore_ascii_case(current, "blob:") {
            let trimmed_rest = rest.trim();
            if trimmed_rest.is_empty() {
                return true;
            }
            // Standard opaque-origin Blob URL (`blob:null/<uuid>`) cannot target local IPC or files.
            if starts_with_ignore_ascii_case(trimmed_rest, "null/") {
                return false;
            }
            current = trimmed_rest;
            continue;
        }
        if let Some(rest) = strip_prefix_ignore_ascii_case(current, "filesystem:") {
            current = rest.trim();
            if current.is_empty() {
                return true;
            }
            continue;
        }
        break;
    }

    // Excessively nested wrapper schemes -> fail closed.
    if starts_with_ignore_ascii_case(current, "view-source:")
        || starts_with_ignore_ascii_case(current, "blob:")
        || starts_with_ignore_ascii_case(current, "filesystem:")
    {
        return true;
    }

    // Always block `file:` (including `FILE:///`, `file:/`, `view-source:file://...`).
    if starts_with_ignore_ascii_case(current, "file:") {
        return true;
    }

    // Scheme-relative URLs (`//127.0.0.1:PORT/...`) -> inspect as HTTP, fail closed if malformed.
    if current.starts_with("//") {
        let synthetic = format!("http:{current}");
        return match parse_http_or_ws_host_port(&synthetic, false) {
            Some((host, port)) => port == bind_port && is_local_or_ambiguous_host(&host),
            None => true,
        };
    }

    // Validate scheme syntax before first `:`. Missing or invalid scheme -> fail closed.
    let Some((scheme, after_colon)) = current.split_once(':') else {
        return true;
    };
    let valid_scheme = !scheme.is_empty()
        && scheme.as_bytes()[0].is_ascii_alphabetic()
        && scheme
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'));
    if !valid_scheme {
        return true;
    }

    let scheme_lower = scheme.to_ascii_lowercase();
    match scheme_lower.as_str() {
        "http" | "https" | "ws" | "wss" => {
            // Require strict `://` (reject ambiguous `http:127.0.0.1`, `http:/host`, `http:\\host`).
            if !after_colon.starts_with("//") {
                return true;
            }
            match parse_http_or_ws_host_port(current, true) {
                Some((host, port)) => port == bind_port && is_local_or_ambiguous_host(&host),
                None => true, // Fail closed on any malformed/ambiguous HTTP(S)/WS(S) URL.
            }
        }
        "about" => !(current.eq_ignore_ascii_case("about:blank")
            || current.eq_ignore_ascii_case("about:srcdoc")),
        "data" | "javascript" | "chrome-extension" | "mailto" | "tel" => false,
        _ => {
            // For other authority-bearing schemes (e.g. `ftp://`), block if targeting local bind_port.
            if let Some(after_slashes) = after_colon.strip_prefix("//") {
                let synthetic = format!("http://{after_slashes}");
                return match parse_http_or_ws_host_port(&synthetic, false) {
                    Some((host, port)) => port == bind_port && is_local_or_ambiguous_host(&host),
                    None => true,
                };
            }
            false
        }
    }
}

fn collect_enabled_extension_dirs(extensions_dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(extensions_dir) else {
        return Vec::new();
    };
    let mut dirs = Vec::new();
    for ent in entries.flatten() {
        let p = ent.path();
        if p.is_dir() && p.join("manifest.json").is_file() {
            dirs.push(p);
        }
    }
    dirs.sort();
    dirs
}

wrap_v8_handler! {
    struct SingularityIpcV8Handler;

    impl V8Handler {
        fn execute(
            &self,
            name: Option<&CefString>,
            _object: Option<&mut V8Value>,
            arguments: Option<&[Option<V8Value>]>,
            retval: Option<&mut Option<V8Value>>,
            _exception: Option<&mut CefString>,
        ) -> ::std::os::raw::c_int {
            let fn_name = name.map(CefString::to_string).unwrap_or_default();
            if fn_name != "postMessage" {
                return 0;
            }
            let payload = arguments
                .and_then(|args| args.first())
                .and_then(|v| v.as_ref())
                .filter(|v| v.is_string() != 0)
                .map(|v| cef_str_userfree(v.string_value()))
                .unwrap_or_default();
            if !payload.is_empty() && payload.len() <= 262_144 {
                if let Some(ctx) = v8_context_get_current_context() {
                    if let Some(frame) = ctx.frame() {
                        let is_main = frame.is_main() != 0;
                        let frame_url = cef_str_userfree(frame.url());
                        let authorized = is_main
                            && frame
                                .browser()
                                .map(|b| {
                                    RENDERER_CONFIGS.with(|map| {
                                        map.borrow()
                                            .get(&b.identifier())
                                            .is_some_and(|cfg| {
                                                cfg.is_ui
                                                    && is_exact_local_ui_origin(
                                                        &frame_url,
                                                        cfg.ui_port,
                                                    )
                                            })
                                    })
                                })
                                .unwrap_or(false);
                        if authorized {
                            if let Some(mut msg) =
                                process_message_create(Some(&CefString::from(IPC_MESSAGE_NAME)))
                            {
                                if let Some(args) = msg.argument_list() {
                                    let _ = args.set_string(0, Some(&CefString::from(payload.as_str())));
                                }
                                frame.send_process_message(ProcessId::BROWSER, Some(&mut msg));
                            }
                        }
                    }
                }
            }
            if let Some(ret) = retval {
                *ret = v8_value_create_undefined();
            }
            1
        }
    }
}

wrap_render_process_handler! {
    struct SingularityRenderProcessHandler;

    impl RenderProcessHandler {
        fn on_browser_created(
            &self,
            browser: Option<&mut Browser>,
            extra_info: Option<&mut DictionaryValue>,
        ) {
            let Some(browser) = browser else {
                return;
            };
            let bid = browser.identifier();
            let mut cfg = RendererBrowserConfig::default();
            if let Some(info) = extra_info {
                let k_ui = CefString::from("is_ui");
                if info.has_key(Some(&k_ui)) != 0 {
                    cfg.is_ui = info.bool(Some(&k_ui)) != 0;
                }
                let k_ui_port = CefString::from("ui_port");
                if info.has_key(Some(&k_ui_port)) != 0 {
                    let raw_port = info.int(Some(&k_ui_port));
                    if (1..=u16::MAX as i32).contains(&raw_port) {
                        cfg.ui_port = raw_port as u16;
                    }
                }
                let k_init = CefString::from("init_script");
                if info.has_key(Some(&k_init)) != 0 {
                    cfg.init_script = cef_str_userfree(info.string(Some(&k_init)));
                }
                let k_resume = CefString::from("resume_script");
                if info.has_key(Some(&k_resume)) != 0 {
                    cfg.resume_script = cef_str_userfree(info.string(Some(&k_resume)));
                }
            }
            RENDERER_CONFIGS.with(|map| {
                map.borrow_mut().insert(bid, cfg);
            });
        }

        fn on_browser_destroyed(&self, browser: Option<&mut Browser>) {
            if let Some(browser) = browser {
                let bid = browser.identifier();
                RENDERER_CONFIGS.with(|map| {
                    map.borrow_mut().remove(&bid);
                });
            }
        }

        fn on_context_created(
            &self,
            browser: Option<&mut Browser>,
            frame: Option<&mut Frame>,
            context: Option<&mut V8Context>,
        ) {
            let (Some(browser), Some(frame), Some(context)) = (browser, frame, context) else {
                return;
            };
            let is_main = frame.is_main() != 0;
            let frame_url = cef_str_userfree(frame.url());
            let cfg = RENDERER_CONFIGS.with(|map| {
                map.borrow()
                    .get(&browser.identifier())
                    .cloned()
                    .unwrap_or_default()
            });

            // SECURITY (N4 #4): Expose `window.ipc.postMessage(payload)` EXCLUSIVELY to the main
            // frame of the local Singularity UI shell on exact origin `http://127.0.0.1:<ui_port>`.
            // NEVER expose `window.ipc` to web pages (`!cfg.is_ui`) or any iframe!
            if cfg.is_ui && is_main && is_exact_local_ui_origin(&frame_url, cfg.ui_port) {
                if let Some(global) = context.global() {
                    if let Some(mut ipc_obj) = v8_value_create_object(None, None) {
                        let mut handler = SingularityIpcV8Handler::new();
                        let fn_name = CefString::from("postMessage");
                        if let Some(mut post_fn) =
                            v8_value_create_function(Some(&fn_name), Some(&mut handler))
                        {
                            let _ = ipc_obj.set_value_bykey(
                                Some(&fn_name),
                                Some(&mut post_fn),
                                V8Propertyattribute::default(),
                            );
                        }
                        let ipc_key = CefString::from("ipc");
                        let _ = global.set_value_bykey(
                            Some(&ipc_key),
                            Some(&mut ipc_obj),
                            V8Propertyattribute::default(),
                        );
                    }
                }
            }

            // Document-start injection BEFORE page scripts execute (zero autoplay blip!).
            if !cfg.is_ui {
                if !cfg.init_script.is_empty() {
                    let code = CefString::from(cfg.init_script.as_str());
                    let src_url = CefString::from("singularity://init/content.js");
                    frame.execute_java_script(Some(&code), Some(&src_url), 0);
                }
                if is_main && !cfg.resume_script.is_empty() {
                    let code = CefString::from(cfg.resume_script.as_str());
                    let src_url = CefString::from("singularity://init/resume.js");
                    frame.execute_java_script(Some(&code), Some(&src_url), 0);
                }
            }
        }
    }
}

wrap_browser_process_handler! {
    struct SingularityBrowserProcessHandler {
        context_initialized: Arc<AtomicBool>,
        on_pump: Option<CefPumpCallback>,
        on_relaunch: Option<CefRelaunchCallback>,
    }

    impl BrowserProcessHandler {
        fn on_context_initialized(&self) {
            self.context_initialized.store(true, Ordering::Release);
        }

        fn on_schedule_message_pump_work(&self, delay_ms: i64) {
            if let Some(ref cb) = self.on_pump {
                cb(delay_ms);
            }
        }

        fn on_already_running_app_relaunch(
            &self,
            _command_line: Option<&mut CommandLine>,
            _current_directory: Option<&CefString>,
        ) -> ::std::os::raw::c_int {
            if let Some(ref cb) = self.on_relaunch {
                cb();
                1
            } else {
                0
            }
        }
    }
}

wrap_app! {
    struct SingularityCefApp {
        extensions_dir: Option<PathBuf>,
        context_initialized: Arc<AtomicBool>,
        on_pump: Option<CefPumpCallback>,
        on_relaunch: Option<CefRelaunchCallback>,
    }

    impl App {
        fn on_before_command_line_processing(
            &self,
            process_type: Option<&CefString>,
            command_line: Option<&mut CommandLine>,
        ) {
            let ptype = process_type.map(CefString::to_string).unwrap_or_default();
            if !ptype.is_empty() {
                return;
            }
            let Some(cmd) = command_line else {
                return;
            };

            // Pure Chromium aggressive RAM-optimization & zero-bloat flags (0% Edge):
            // - `--process-per-site`: consolidates same-site tabs into 1 renderer process
            // - Disables `BackForwardCache` (saves 30-50% per-tab RAM!) and unused background services
            // - Caps disk cache (64 MiB) & media cache (32 MiB)
            let switches = [
                "process-per-site",
                "disable-component-update",
                "disable-sync",
                "disable-domain-reliability",
                "disable-breakpad",
                "disable-default-apps",
                "no-first-run",
                "no-default-browser-check",
                "force-dark-mode",
            ];
            for sw in switches {
                cmd.append_switch(Some(&CefString::from(sw)));
            }

            let kv_switches = [
                (
                    "disable-features",
                    "BackForwardCache,OptimizationHints,OptimizationGuideModelDownloading,MediaRouter,DialMediaRouteProvider,Translate,InterestFeedContentSuggestions,AutofillServerCommunication,HeavyAdIntervention,GlobalMediaControls",
                ),
                ("enable-features", "PlatformHEVCDecoderSupport"),
                ("disable-blink-features", "AutomationControlled"),
                ("autoplay-policy", "no-user-gesture-required"),
                ("disk-cache-size", "67108864"),
                ("media-cache-size", "67108864"),
            ];
            for (k, v) in kv_switches {
                cmd.append_switch_with_value(Some(&CefString::from(k)), Some(&CefString::from(v)));
            }

            if let Some(io_pipes) = cdp_pipe_io_arg() {
                // Zero-restart dynamic Chrome Extensions bridge over private in-process Win32
                // anonymous kernel pipes (zero TCP port, zero external process access).
                // Extensions are synced live via `Extensions.loadUnpacked` / `Extensions.uninstall`
                // so Chromium registers them as `kUnpacked` instead of read-only `kCommandLine`.
                cmd.append_switch(Some(&CefString::from("remote-debugging-pipe")));
                cmd.append_switch_with_value(
                    Some(&CefString::from("remote-debugging-io-pipes")),
                    Some(&CefString::from(io_pipes.as_str())),
                );
                cmd.append_switch(Some(&CefString::from("enable-unsafe-extension-debugging")));
            } else if let Some(ref ext_dir) = self.extensions_dir {
                let enabled = collect_enabled_extension_dirs(ext_dir);
                if !enabled.is_empty() {
                    let joined = enabled
                        .iter()
                        .map(|p| p.to_string_lossy().into_owned())
                        .collect::<Vec<_>>()
                        .join(",");
                    cmd.append_switch_with_value(
                        Some(&CefString::from("load-extension")),
                        Some(&CefString::from(joined.as_str())),
                    );
                }
            }
        }

        fn browser_process_handler(&self) -> Option<BrowserProcessHandler> {
            Some(SingularityBrowserProcessHandler::new(
                Arc::clone(&self.context_initialized),
                self.on_pump.clone(),
                self.on_relaunch.clone(),
            ))
        }

        fn render_process_handler(&self) -> Option<RenderProcessHandler> {
            Some(SingularityRenderProcessHandler::new())
        }
    }
}

#[cfg(singularity_cef_sandbox)]
extern "C" {
    fn cef_sandbox_info_create() -> *mut core::ffi::c_void;
    fn cef_sandbox_info_destroy(sandbox_info: *mut core::ffi::c_void);
}

fn is_unsafe_no_sandbox_opt_out() -> bool {
    let env_requested = std::env::var("SINGULARITY_ALLOW_UNSAFE_NO_SANDBOX")
        .map(|v| v.trim() == "1")
        .unwrap_or(false);
    #[cfg(debug_assertions)]
    {
        env_requested
    }
    #[cfg(not(debug_assertions))]
    {
        if env_requested {
            eprintln!(
                "[singularity-cef] SECURITY WARNING: SINGULARITY_ALLOW_UNSAFE_NO_SANDBOX=1 is ignored in release builds."
            );
        }
        false
    }
}

/// RAII wrapper for CEF's Windows `SandboxInfo` (`cef_sandbox_info_create`/`cef_sandbox_info_destroy`).
struct ScopedCefSandboxInfo {
    ptr: *mut core::ffi::c_void,
}

impl ScopedCefSandboxInfo {
    fn new(disable_sandbox: bool) -> Self {
        if disable_sandbox {
            return Self {
                ptr: std::ptr::null_mut(),
            };
        }
        #[cfg(singularity_cef_sandbox)]
        {
            let ptr = unsafe { cef_sandbox_info_create() };
            Self { ptr }
        }
        #[cfg(not(singularity_cef_sandbox))]
        {
            Self {
                ptr: std::ptr::null_mut(),
            }
        }
    }

    fn as_cef_ptr(&self) -> *mut u8 {
        self.ptr.cast::<u8>()
    }

    fn is_active(&self) -> bool {
        !self.ptr.is_null()
    }
}

impl Drop for ScopedCefSandboxInfo {
    fn drop(&mut self) {
        #[cfg(singularity_cef_sandbox)]
        if !self.ptr.is_null() {
            unsafe {
                cef_sandbox_info_destroy(self.ptr);
            }
            self.ptr = std::ptr::null_mut();
        }
    }
}

/// MUST be called at the very entry of `main()` on Windows when `--type=...` is present.
/// Executes the Chromium subprocess (`renderer`, `gpu-process`, `utility`, etc.) cleanly via
/// CEF's native Win32 command-line parser (avoiding `Args::as_cmd_line()`, which loses quoting
/// on Windows paths containing spaces!).
pub fn maybe_run_cef_subprocess() -> Option<i32> {
    // Required in CEF 133+ before calling `execute_process` or `initialize`.
    let _ = api_hash(sys::CEF_API_VERSION_LAST, 0);

    let args = args::Args::new();
    let mut app = SingularityCefApp::new(
        None,
        Arc::new(AtomicBool::new(false)),
        None,
        None,
    );
    let disable_sandbox = is_unsafe_no_sandbox_opt_out();
    let sandbox_info = ScopedCefSandboxInfo::new(disable_sandbox);
    let ret = execute_process(
        Some(args.as_main_args()),
        Some(&mut app),
        sandbox_info.as_cef_ptr(),
    );
    if ret >= 0 {
        Some(ret)
    } else {
        None
    }
}

/// RAII guard for the single process-wide Chromium Embedded Framework runtime.
pub struct CefRuntimeGuard {
    _initialized: bool,
    context_initialized: Arc<AtomicBool>,
    log_path: PathBuf,
}

impl CefRuntimeGuard {
    pub fn initialize(
        profile_dir: &Path,
        extensions_dir: &Path,
        cef_log_path: Option<&Path>,
        verbose_logging: bool,
        on_pump: CefPumpCallback,
        on_relaunch: CefRelaunchCallback,
    ) -> Result<Self, String> {
        let _ = api_hash(sys::CEF_API_VERSION_LAST, 0);
        let _ = std::fs::create_dir_all(profile_dir);

        // Create private in-process Win32 anonymous pipes BEFORE `cef::initialize` so
        // `on_before_command_line_processing` attaches `--remote-debugging-io-pipes`.
        let _ = init_cdp_pipe_bridge();

        let context_initialized = Arc::new(AtomicBool::new(false));
        let args = args::Args::new();
        let mut app = SingularityCefApp::new(
            Some(extensions_dir.to_path_buf()),
            Arc::clone(&context_initialized),
            Some(on_pump),
            Some(on_relaunch),
        );

        let profile_str = profile_dir.to_string_lossy().into_owned();
        let exe_path = std::env::current_exe().ok();
        let exe_dir = exe_path.as_ref().and_then(|p| p.parent().map(Path::to_path_buf));
        let resolved_log = cef_log_path
            .map(Path::to_path_buf)
            .unwrap_or_else(|| profile_dir.parent().unwrap_or(profile_dir).join("cef.log"));
        if let Some(parent) = resolved_log.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let disable_sandbox = is_unsafe_no_sandbox_opt_out();
        let sandbox_info = ScopedCefSandboxInfo::new(disable_sandbox);
        let no_sandbox_flag: ::std::os::raw::c_int = if disable_sandbox {
            eprintln!(
                "[singularity-cef] SECURITY WARNING: Chromium sandbox disabled via SINGULARITY_ALLOW_UNSAFE_NO_SANDBOX=1 (debug build)."
            );
            1
        } else {
            if !sandbox_info.is_active() {
                eprintln!(
                    "[singularity-cef] SECURITY WARNING: cef_sandbox.lib was not linked into this build; CEF 150 falls back to unsandboxed mode without cef_sandbox.lib or bootstrap.exe."
                );
            }
            0
        };

        let mut settings = Settings {
            no_sandbox: no_sandbox_flag,
            multi_threaded_message_loop: 0,
            external_message_pump: 1,
            windowless_rendering_enabled: 0,
            root_cache_path: CefString::from(profile_str.as_str()),
            cache_path: CefString::from(profile_str.as_str()),
            persist_session_cookies: 1,
            cookieable_schemes_list: CefString::from("chrome-extension"),
            cookieable_schemes_exclude_defaults: 0,
            background_color: 0xFF00_0000, // OLED Pure Black (#000000) — zero white flash
            log_file: CefString::from(resolved_log.to_string_lossy().as_ref()),
            log_severity: if verbose_logging {
                LogSeverity::INFO
            } else {
                LogSeverity::WARNING
            },
            ..Default::default()
        };
        if let Some(ref exe) = exe_path {
            settings.browser_subprocess_path = CefString::from(exe.to_string_lossy().as_ref());
        }
        if let Some(ref dir) = exe_dir {
            settings.resources_dir_path = CefString::from(dir.to_string_lossy().as_ref());
            let loc_dir = dir.join("locales");
            if loc_dir.is_dir() {
                settings.locales_dir_path = CefString::from(loc_dir.to_string_lossy().as_ref());
            }
        }

        let ok = initialize(
            Some(args.as_main_args()),
            Some(&settings),
            Some(&mut app),
            sandbox_info.as_cef_ptr(),
        );
        if ok == 0 {
            let code = get_exit_code();
            return Err(format!(
                "CEF Chromium runtime initialization failed (exit_code={}, another instance may own this profile).",
                code
            ));
        }
        Ok(Self {
            _initialized: true,
            context_initialized,
            log_path: resolved_log,
        })
    }

    /// Pumps CEF until `BrowserProcessHandler::on_context_initialized()` fires so browsers are
    /// NEVER created before Chromium's BrowserContext & Mojo channels are ready.
    pub fn wait_for_context_initialized(&self, timeout: std::time::Duration) -> bool {
        let start = std::time::Instant::now();
        while !self.context_initialized.load(Ordering::Acquire) {
            pump_cef_message_loop();
            if self.context_initialized.load(Ordering::Acquire) {
                return true;
            }
            if start.elapsed() >= timeout {
                return false;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        true
    }

    pub fn is_context_initialized(&self) -> bool {
        self.context_initialized.load(Ordering::Acquire)
    }

    pub fn log_path(&self) -> &Path {
        &self.log_path
    }
}

impl Drop for CefRuntimeGuard {
    fn drop(&mut self) {
        if self._initialized {
            shutdown();
        }
    }
}

thread_local! {
    static IN_CEF_PUMP: Cell<bool> = const { Cell::new(false) };
    static PUMP_AGAIN: Cell<bool> = const { Cell::new(false) };
}

struct PumpReentrantReset;
impl Drop for PumpReentrantReset {
    fn drop(&mut self) {
        IN_CEF_PUMP.with(|f| f.set(false));
    }
}

/// Runs a single re-entrancy-safe iteration of CEF's external message pump on the main UI thread.
pub fn pump_cef_message_loop() {
    if IN_CEF_PUMP.with(|f| f.get()) {
        PUMP_AGAIN.with(|f| f.set(true));
        return;
    }
    for _ in 0..2 {
        PUMP_AGAIN.with(|f| f.set(false));
        IN_CEF_PUMP.with(|f| f.set(true));
        let _reset = PumpReentrantReset;
        do_message_loop_work();
        drop(_reset);
        if !PUMP_AGAIN.with(|f| f.get()) {
            break;
        }
    }
}

/// Allows/disables nested Chromium task processing during native Win32 modal loops (drag/menus).
pub fn set_cef_nestable_tasks_allowed(allowed: bool) {
    set_nestable_tasks_allowed(if allowed { 1 } else { 0 });
}

/// Creates a pure in-memory incognito Chromium `RequestContext` (zero disk cookies or history).
pub fn create_incognito_request_context() -> Option<RequestContext> {
    let settings = RequestContextSettings {
        cache_path: CefString::default(),
        persist_session_cookies: 0,
        ..Default::default()
    };
    request_context_create_context(Some(&settings), None)
}

#[derive(Clone)]
struct ClientConfig {
    is_ui: bool,
    is_ext_popup: bool,
    is_standalone_popup: bool,
    tab_id: u64,
    bind_port: u16,
    sink: CefEventSink,
    shared_shell: Arc<Mutex<SingularityBrowserShell>>,
    download_resolver: CefDownloadResolver,
    downloads: Arc<Mutex<HashMap<u32, (String, String)>>>,
    last_user_gesture_ms: Arc<AtomicU64>,
    no_gesture_urls: Arc<Mutex<HashMap<String, u64>>>,
}

impl ClientConfig {
    fn record_user_gesture(&self) {
        self.last_user_gesture_ms
            .store(monotonic_millis(), Ordering::Release);
    }

    fn record_non_gesture_nav(&self, url: &str) {
        if url.is_empty() {
            return;
        }
        let now = monotonic_millis();
        if let Ok(mut map) = self.no_gesture_urls.lock() {
            if map.len() >= 64 {
                map.retain(|_, ts| now.saturating_sub(*ts) < 15_000);
            }
            if map.len() >= 64 {
                map.clear();
            }
            map.insert(url.to_string(), now);
        }
    }

    fn has_verified_user_gesture(&self, url: &str, original_url: &str) -> bool {
        const USER_GESTURE_WINDOW_MS: u64 = 5_000;
        let now = monotonic_millis();
        let last = self.last_user_gesture_ms.load(Ordering::Acquire);
        if last == 0 || now.saturating_sub(last) > USER_GESTURE_WINDOW_MS {
            return false;
        }
        if let Ok(mut map) = self.no_gesture_urls.lock() {
            map.retain(|_, ts| now.saturating_sub(*ts) < 15_000);
            let url_no_gesture = !url.is_empty()
                && map.get(url).is_some_and(|&ts| ts >= last);
            let orig_no_gesture = !original_url.is_empty()
                && map.get(original_url).is_some_and(|&ts| ts >= last);
            if url_no_gesture || orig_no_gesture {
                return false;
            }
        }
        true
    }
}

wrap_context_menu_handler! {
    struct SingularityContextMenuHandler {
        cfg: ClientConfig,
    }

    impl ContextMenuHandler {
        fn on_before_context_menu(
            &self,
            _browser: Option<&mut Browser>,
            _frame: Option<&mut Frame>,
            _params: Option<&mut ContextMenuParams>,
            model: Option<&mut MenuModel>,
        ) {
            if !self.cfg.is_ui {
                self.cfg.record_user_gesture();
            }
            if self.cfg.is_ui {
                if let Some(m) = model {
                    let _ = m.clear();
                }
            }
        }
    }
}

static OPEN_CEF_BROWSERS: AtomicUsize = AtomicUsize::new(0);

/// Returns the number of live Chromium CEF browser instances awaiting `on_before_close`.
pub fn open_cef_browser_count() -> usize {
    OPEN_CEF_BROWSERS.load(Ordering::Acquire)
}

/// Pumps CEF's external message loop until all closing child browsers complete `on_before_close`
/// (up to `timeout`) so `cef::shutdown()` never hits Chromium's open-browser teardown assertion.
pub fn drain_browsers_before_shutdown(timeout: std::time::Duration) -> usize {
    if let Some(mgr) = cookie_manager_get_global_manager(None) {
        let _ = mgr.flush_store(None);
    }
    let start = std::time::Instant::now();
    while open_cef_browser_count() > 0 && start.elapsed() < timeout {
        pump_cef_message_loop();
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    for _ in 0..3 {
        pump_cef_message_loop();
        std::thread::sleep(std::time::Duration::from_millis(4));
    }
    open_cef_browser_count()
}

wrap_life_span_handler! {
    struct SingularityLifeSpanHandler {
        cfg: ClientConfig,
    }

    impl LifeSpanHandler {
        fn on_after_created(&self, browser: Option<&mut Browser>) {
            OPEN_CEF_BROWSERS.fetch_add(1, Ordering::AcqRel);
            if self.cfg.is_standalone_popup {
                return;
            }
            let hwnd = browser
                .and_then(|b| b.host())
                .map(|h| h.window_handle().0 as isize)
                .unwrap_or(0);
            (self.cfg.sink)(CefCallbackEvent::BrowserCreated {
                tab_id: self.cfg.tab_id,
                is_ui: self.cfg.is_ui,
                hwnd,
            });
        }

        fn on_before_close(&self, _browser: Option<&mut Browser>) {
            let mut cur = OPEN_CEF_BROWSERS.load(Ordering::Acquire);
            while cur > 0 {
                match OPEN_CEF_BROWSERS.compare_exchange_weak(
                    cur,
                    cur - 1,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => break,
                    Err(actual) => cur = actual,
                }
            }
        }

        fn on_before_popup(
            &self,
            _browser: Option<&mut Browser>,
            _frame: Option<&mut Frame>,
            _popup_id: ::std::os::raw::c_int,
            target_url: Option<&CefString>,
            _target_frame_name: Option<&CefString>,
            target_disposition: WindowOpenDisposition,
            user_gesture: ::std::os::raw::c_int,
            popup_features: Option<&PopupFeatures>,
            _window_info: Option<&mut WindowInfo>,
            client: Option<&mut Option<Client>>,
            _settings: Option<&mut BrowserSettings>,
            _extra_info: Option<&mut Option<DictionaryValue>>,
            _no_javascript_access: Option<&mut ::std::os::raw::c_int>,
        ) -> ::std::os::raw::c_int {
            if user_gesture != 0 {
                self.cfg.record_user_gesture();
            }
            let url = target_url.map(CefString::to_string).unwrap_or_default();
            let is_explicit_popup = popup_features
                .map(|f| f.is_popup != 0 || f.width_set != 0 || f.height_set != 0)
                .unwrap_or(false);
            if self.cfg.is_ext_popup {
                if starts_with_ignore_ascii_case(&url, "chrome-extension://") {
                    return 0;
                }
                if is_explicit_popup
                    && parse_http_host_port(&url).is_some()
                    && !is_blocked_local_ipc_url(&url, self.cfg.bind_port)
                {
                    // SECURITY (N3 #27): Allow OAuth/SSO popup dialogs opened from Chrome extension
                    // popups so `window.opener` handoffs complete cleanly, BUT attach a fresh client
                    // with `is_ext_popup: false` so `ResourceRequestHandler` (adblocker + local IPC
                    // guard) stays fully enforced on the external web popup!
                    if let Some(client_slot) = client {
                        let popup_cfg = ClientConfig {
                            is_ui: false,
                            is_ext_popup: false,
                            is_standalone_popup: true,
                            tab_id: 0,
                            bind_port: self.cfg.bind_port,
                            sink: Arc::clone(&self.cfg.sink),
                            shared_shell: Arc::clone(&self.cfg.shared_shell),
                            download_resolver: Arc::clone(&self.cfg.download_resolver),
                            downloads: Arc::new(Mutex::new(HashMap::new())),
                            last_user_gesture_ms: Arc::new(AtomicU64::new(if user_gesture != 0 {
                                monotonic_millis()
                            } else {
                                0
                            })),
                            no_gesture_urls: Arc::new(Mutex::new(HashMap::new())),
                        };
                        *client_slot = Some(SingularityCefClient::new(popup_cfg));
                    }
                    return 0;
                }
            }
            if !self.cfg.is_ui && parse_http_host_port(&url).is_some()
                && !is_blocked_local_ipc_url(&url, self.cfg.bind_port)
            {
                let background = !is_explicit_popup
                    && (target_disposition == WindowOpenDisposition::NEW_BACKGROUND_TAB
                        || is_ctrl_or_mbutton_down_cef());
                (self.cfg.sink)(CefCallbackEvent::OpenNewTab { url, background });
            }
            1 // Always suppress unmanaged external popup windows
        }

        fn do_close(&self, browser: Option<&mut Browser>) -> ::std::os::raw::c_int {
            if self.cfg.is_ext_popup || self.cfg.is_standalone_popup {
                return 0; // Closing an extension/OAuth popup SHOULD close its own popup window.
            }
            // CRITICAL: On Windows, returning 0 from `do_close()` for an embedded WS_CHILD browser
            // causes CEF to post `WM_CLOSE` to the top-level parent `tao` window, closing the ENTIRE
            // browser window when the user closes a single tab! Instead, schedule destruction of ONLY
            // this child browser's HWND on the UI thread and return 1 (`true`).
            let hwnd = browser
                .and_then(|b| b.host())
                .map(|h| h.window_handle().0 as isize)
                .unwrap_or(0);
            if hwnd != 0 {
                (self.cfg.sink)(CefCallbackEvent::DestroyChildHwnd { hwnd });
            }
            1
        }
    }
}

wrap_display_handler! {
    struct SingularityDisplayHandler {
        cfg: ClientConfig,
    }

    impl DisplayHandler {
        fn on_address_change(
            &self,
            _browser: Option<&mut Browser>,
            frame: Option<&mut Frame>,
            url: Option<&CefString>,
        ) {
            if self.cfg.is_ui || self.cfg.is_ext_popup || self.cfg.tab_id == 0 {
                return;
            }
            if !frame.map(|f| f.is_main() != 0).unwrap_or(false) {
                return;
            }
            let u = url.map(CefString::to_string).unwrap_or_default();
            if starts_with_ignore_ascii_case(&u, "https://")
                || starts_with_ignore_ascii_case(&u, "http://")
            {
                (self.cfg.sink)(CefCallbackEvent::AddressChanged {
                    tab_id: self.cfg.tab_id,
                    url: u,
                });
            }
        }

        fn on_title_change(&self, _browser: Option<&mut Browser>, title: Option<&CefString>) {
            if self.cfg.is_ui || self.cfg.is_ext_popup || self.cfg.tab_id == 0 {
                return;
            }
            let t = title.map(CefString::to_string).unwrap_or_default();
            if !t.is_empty() {
                (self.cfg.sink)(CefCallbackEvent::TitleChanged {
                    tab_id: self.cfg.tab_id,
                    title: t,
                });
            }
        }

        fn on_favicon_urlchange(
            &self,
            _browser: Option<&mut Browser>,
            icon_urls: Option<&mut CefStringList>,
        ) {
            if self.cfg.is_ui || self.cfg.is_ext_popup || self.cfg.tab_id == 0 {
                return;
            }
            let Some(list) = icon_urls else {
                return;
            };
            // Non-owning read from CEF's borrowed CefStringList
            let raw_ptr: *mut sys::_cef_string_list_t = list.into();
            if raw_ptr.is_null() {
                return;
            }
            let count = unsafe { sys::cef_string_list_size(raw_ptr) };
            for i in 0..count.min(8) {
                let mut val: sys::cef_string_t = unsafe { std::mem::zeroed() };
                if unsafe { sys::cef_string_list_value(raw_ptr, i, &mut val) } > 0 {
                    let href = CefString::from(std::ptr::from_ref(&val)).to_string();
                    // SECURITY/MEM (N3 #36): `cef_string_list_value` allocates a UTF-16 copy
                    // with a destructor; always clear it immediately after extracting to `String`.
                    unsafe {
                        sys::cef_string_utf16_clear(&mut val);
                    }
                    if href.len() <= 512
                        && parse_http_host_port(&href).is_some()
                        && !is_blocked_local_ipc_url(&href, self.cfg.bind_port)
                    {
                        (self.cfg.sink)(CefCallbackEvent::FaviconChanged {
                            tab_id: self.cfg.tab_id,
                            favicon_url: href,
                        });
                        break;
                    }
                } else {
                    unsafe {
                        sys::cef_string_utf16_clear(&mut val);
                    }
                }
            }
        }

        fn on_fullscreen_mode_change(
            &self,
            _browser: Option<&mut Browser>,
            fullscreen: ::std::os::raw::c_int,
        ) {
            if self.cfg.is_ui || self.cfg.is_ext_popup || self.cfg.tab_id == 0 {
                return;
            }
            (self.cfg.sink)(CefCallbackEvent::FullscreenChanged {
                tab_id: self.cfg.tab_id,
                enabled: fullscreen != 0,
            });
        }
    }
}

wrap_load_handler! {
    struct SingularityLoadHandler {
        cfg: ClientConfig,
    }

    impl LoadHandler {
        fn on_loading_state_change(
            &self,
            _browser: Option<&mut Browser>,
            _is_loading: ::std::os::raw::c_int,
            can_go_back: ::std::os::raw::c_int,
            can_go_forward: ::std::os::raw::c_int,
        ) {
            if self.cfg.is_ui || self.cfg.is_ext_popup || self.cfg.tab_id == 0 {
                return;
            }
            (self.cfg.sink)(CefCallbackEvent::NavigationStateChanged {
                tab_id: self.cfg.tab_id,
                can_go_back: can_go_back != 0,
                can_go_forward: can_go_forward != 0,
            });
        }

        fn on_load_start(
            &self,
            _browser: Option<&mut Browser>,
            frame: Option<&mut Frame>,
            _transition_type: TransitionType,
        ) {
            if self.cfg.is_ext_popup || (!self.cfg.is_ui && self.cfg.tab_id == 0) {
                return;
            }
            let Some(frame) = frame else {
                return;
            };
            if frame.is_main() == 0 {
                return;
            }
            let u = cef_str_userfree(frame.url());
            if u.starts_with("https://") || u.starts_with("http://") {
                (self.cfg.sink)(CefCallbackEvent::PageStarted {
                    tab_id: self.cfg.tab_id,
                    url: u,
                });
            }
        }

        fn on_load_end(
            &self,
            _browser: Option<&mut Browser>,
            frame: Option<&mut Frame>,
            http_status_code: ::std::os::raw::c_int,
        ) {
            if self.cfg.is_ext_popup || (!self.cfg.is_ui && self.cfg.tab_id == 0) {
                return;
            }
            let Some(frame) = frame else {
                return;
            };
            if frame.is_main() == 0 {
                return;
            }
            let u = cef_str_userfree(frame.url());
            if u.starts_with("https://") || u.starts_with("http://") {
                (self.cfg.sink)(CefCallbackEvent::PageFinished {
                    tab_id: self.cfg.tab_id,
                    url: u,
                    http_status: http_status_code,
                });
            }
        }

        fn on_load_error(
            &self,
            _browser: Option<&mut Browser>,
            frame: Option<&mut Frame>,
            error_code: Errorcode,
            error_text: Option<&CefString>,
            failed_url: Option<&CefString>,
        ) {
            if error_code == Errorcode::ABORTED {
                return;
            }
            let is_main = frame.map(|f| f.is_main() != 0).unwrap_or(true);
            if !is_main {
                return;
            }
            (self.cfg.sink)(CefCallbackEvent::LoadError {
                tab_id: self.cfg.tab_id,
                is_ui: self.cfg.is_ui,
                error_code: *error_code.as_ref() as i32,
                error_text: error_text.map(CefString::to_string).unwrap_or_default(),
                failed_url: failed_url.map(CefString::to_string).unwrap_or_default(),
            });
        }
    }
}

fn map_cef_resource_type(rt: ResourceType) -> NetworkResourceType {
    if rt == ResourceType::MAIN_FRAME {
        NetworkResourceType::MainFrameDocument
    } else if rt == ResourceType::SUB_FRAME {
        NetworkResourceType::SubFrame
    } else if rt == ResourceType::SCRIPT {
        NetworkResourceType::Script
    } else if rt == ResourceType::IMAGE {
        NetworkResourceType::Image
    } else if rt == ResourceType::STYLESHEET {
        NetworkResourceType::Stylesheet
    } else if rt == ResourceType::PING {
        NetworkResourceType::PingBeacon
    } else {
        NetworkResourceType::XmlHttpRequestFetch
    }
}

fn registrable_site(host: &str) -> String {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let parts: Vec<&str> = h.split('.').filter(|s| !s.is_empty()).collect();
    if parts.len() <= 2 {
        return h;
    }
    let last2 = format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]);
    if matches!(
        last2.as_str(),
        "co.uk" | "com.au" | "co.jp" | "com.br" | "co.kr" | "co.nz" | "com.mx" | "co.za"
    ) && parts.len() >= 3
    {
        format!("{}.{}", parts[parts.len() - 3], last2)
    } else {
        last2
    }
}

fn host_in_list(host: &str, domains: &[&str]) -> bool {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    domains
        .iter()
        .any(|d| h == *d || h.ends_with(&format!(".{}", d)))
}

fn is_same_platform_ecosystem(doc_host: &str, req_host: &str) -> bool {
    if doc_host.is_empty() || req_host.is_empty() {
        return false;
    }
    if registrable_site(doc_host) == registrable_site(req_host) {
        return true;
    }
    const ECOSYSTEMS: &[&[&str]] = &[
        &[
            "tiktok.com",
            "tiktokv.com",
            "tiktokv.eu",
            "tiktokv.us",
            "tiktokw.us",
            "tiktokw.eu",
            "tiktokcdn.com",
            "tiktokcdn-us.com",
            "tiktokcdn-eu.com",
            "tiktokcdn-in.com",
            "byteoversea.com",
            "bytedance.com",
            "byteimg.com",
            "bytescm.com",
            "ttwstatic.com",
            "ttlivecdn.com",
            "tiktokstaticb.com",
            "ibytedtos.com",
            "ibyteimg.com",
            "muscdn.com",
            "musical.ly",
            "sgsnssdk.com",
            "isnssdk.com",
            "tiktokglobalshop.com",
        ],
        &[
            "youtube.com",
            "youtu.be",
            "googlevideo.com",
            "ytimg.com",
            "ggpht.com",
            "google.com",
            "google.fr",
            "gstatic.com",
            "googleusercontent.com",
            "googleapis.com",
        ],
        &["twitch.tv", "ttvnw.net", "jtvnw.net", "twitchcdn.net"],
        &[
            "facebook.com",
            "fbcdn.net",
            "instagram.com",
            "cdninstagram.com",
            "threads.net",
            "messenger.com",
        ],
        &["x.com", "twitter.com", "twimg.com", "t.co"],
        &["discord.com", "discordapp.com", "discordapp.net", "discord.gg"],
    ];
    ECOSYSTEMS
        .iter()
        .any(|group| host_in_list(doc_host, group) && host_in_list(req_host, group))
}

wrap_resource_request_handler! {
    struct SingularityResourceRequestHandler {
        cfg: ClientConfig,
    }

    impl ResourceRequestHandler {
        fn on_before_resource_load(
            &self,
            browser: Option<&mut Browser>,
            _frame: Option<&mut Frame>,
            request: Option<&mut Request>,
            _callback: Option<&mut Callback>,
        ) -> ReturnValue {
            if self.cfg.is_ui || self.cfg.is_ext_popup {
                return ReturnValue::CONTINUE;
            }
            let Some(req) = request else {
                return ReturnValue::CONTINUE;
            };
            let url = cef_str_userfree(req.url());
            if starts_with_ignore_ascii_case(&url, "chrome-extension://") {
                return ReturnValue::CONTINUE;
            }
            if is_blocked_local_ipc_url(&url, self.cfg.bind_port) {
                return ReturnValue::CANCEL;
            }
            let rtype = req.resource_type();
            if rtype == ResourceType::MAIN_FRAME {
                return ReturnValue::CONTINUE;
            }
            let Some((req_host, _)) = parse_http_host_port(&url) else {
                return ReturnValue::CONTINUE;
            };
            let first_party_url = cef_str_userfree(req.first_party_for_cookies());
            if starts_with_ignore_ascii_case(&first_party_url, "chrome-extension://") {
                return ReturnValue::CONTINUE;
            }
            let mut doc_host = parse_http_host_port(&first_party_url)
                .map(|(h, _)| h)
                .unwrap_or_default();
            if doc_host.is_empty() {
                if let Some(main_url) = browser
                    .and_then(|b| b.main_frame())
                    .map(|f| cef_str_userfree(f.url()))
                {
                    if starts_with_ignore_ascii_case(&main_url, "chrome-extension://") {
                        return ReturnValue::CONTINUE;
                    }
                    if let Some((mh, _)) = parse_http_host_port(&main_url) {
                        doc_host = mh;
                    }
                }
            }
            // Never block same-site or same-platform CDN/API resources (TikTok, YouTube, Twitch,
            // Google, Meta, Discord, X) so web SPAs and anti-bot telemetry stay 100% functional!
            if !doc_host.is_empty() && is_same_platform_ecosystem(&doc_host, &req_host) {
                return ReturnValue::CONTINUE;
            }
            let res_type = map_cef_resource_type(rtype);
            if let Ok(shell) = self.cfg.shared_shell.lock() {
                let ext_domains =
                    crate::extensions::collect_installed_extension_host_domains(shell.roaming.root_dir());
                if crate::extensions::host_matches_extension_domains(&req_host, &ext_domains) {
                    return ReturnValue::CONTINUE;
                }
                if !matches!(
                    shell.core.adblocker.evaluate_request(&url, &req_host, &doc_host, res_type),
                    FilterDecision::Allow | FilterDecision::AllowByExceptionRule(_)
                ) {
                    return ReturnValue::CANCEL;
                }
            }
            ReturnValue::CONTINUE
        }
    }
}

wrap_request_handler! {
    struct SingularityRequestHandler {
        cfg: ClientConfig,
    }

    impl RequestHandler {
        fn on_before_browse(
            &self,
            _browser: Option<&mut Browser>,
            _frame: Option<&mut Frame>,
            request: Option<&mut Request>,
            user_gesture: ::std::os::raw::c_int,
            is_redirect: ::std::os::raw::c_int,
        ) -> ::std::os::raw::c_int {
            if self.cfg.is_ui {
                return 0;
            }
            if let Some(req) = request {
                let url = cef_str_userfree(req.url());
                if is_blocked_local_ipc_url(&url, self.cfg.bind_port) {
                    return 1; // Cancel navigation to local IPC port or file://
                }
                if user_gesture != 0 {
                    self.cfg.record_user_gesture();
                } else if is_redirect == 0 {
                    self.cfg.record_non_gesture_nav(&url);
                }
            }
            0
        }

        fn on_open_urlfrom_tab(
            &self,
            _browser: Option<&mut Browser>,
            _frame: Option<&mut Frame>,
            target_url: Option<&CefString>,
            target_disposition: WindowOpenDisposition,
            user_gesture: ::std::os::raw::c_int,
        ) -> ::std::os::raw::c_int {
            if user_gesture != 0 && !self.cfg.is_ui {
                self.cfg.record_user_gesture();
            }
            if self.cfg.is_ui || target_disposition == WindowOpenDisposition::CURRENT_TAB {
                return 0;
            }
            let url = target_url.map(CefString::to_string).unwrap_or_default();
            if parse_http_host_port(&url).is_some()
                && !is_blocked_local_ipc_url(&url, self.cfg.bind_port)
            {
                let background = target_disposition == WindowOpenDisposition::NEW_BACKGROUND_TAB
                    || is_ctrl_or_mbutton_down_cef();
                (self.cfg.sink)(CefCallbackEvent::OpenNewTab { url, background });
                return 1;
            }
            0
        }

        fn resource_request_handler(
            &self,
            _browser: Option<&mut Browser>,
            _frame: Option<&mut Frame>,
            _request: Option<&mut Request>,
            _is_navigation: ::std::os::raw::c_int,
            _is_download: ::std::os::raw::c_int,
            _request_initiator: Option<&CefString>,
            _disable_default_handling: Option<&mut ::std::os::raw::c_int>,
        ) -> Option<ResourceRequestHandler> {
            if self.cfg.is_ui || self.cfg.is_ext_popup {
                None
            } else {
                Some(SingularityResourceRequestHandler::new(self.cfg.clone()))
            }
        }

        fn on_render_process_terminated(
            &self,
            _browser: Option<&mut Browser>,
            status: TerminationStatus,
            error_code: ::std::os::raw::c_int,
            error_string: Option<&CefString>,
        ) {
            (self.cfg.sink)(CefCallbackEvent::RenderProcessTerminated {
                tab_id: self.cfg.tab_id,
                is_ui: self.cfg.is_ui,
                status: *status.as_ref() as i32,
                error_code,
                error_string: error_string.map(CefString::to_string).unwrap_or_default(),
            });
        }
    }
}

fn percent_decode_ascii_lossy(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let h1 = (bytes[i + 1] as char).to_digit(16);
            let h2 = (bytes[i + 2] as char).to_digit(16);
            if let (Some(a), Some(b)) = (h1, h2) {
                out.push(((a << 4) | b) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn is_dangerous_download_name(name: &str) -> bool {
    const DANGEROUS_EXTS: &[&str] = &[
        ".exe", ".msi", ".msp", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf",
        ".hta", ".scr", ".com", ".pif", ".lnk", ".dll", ".cpl", ".reg", ".jar", ".sh", ".appimage",
    ];
    let cleaned = name
        .trim()
        .trim_end_matches(|c: char| c == '.' || c.is_ascii_whitespace())
        .to_ascii_lowercase();
    if cleaned.is_empty() {
        return false;
    }
    DANGEROUS_EXTS.iter().any(|ext| cleaned.ends_with(ext))
}

fn is_dangerous_download_url(url: &str) -> bool {
    let without_frag = url.split(['?', '#']).next().unwrap_or("");
    let segment = without_frag
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or("");
    if segment.is_empty() {
        return false;
    }
    is_dangerous_download_name(segment)
        || is_dangerous_download_name(&percent_decode_ascii_lossy(segment))
}

fn is_dangerous_download_mime(mime: &str) -> bool {
    let m = mime
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    matches!(
        m.as_str(),
        "application/x-msdownload"
            | "application/x-msdos-program"
            | "application/x-dosexec"
            | "application/x-msi"
            | "application/x-sh"
            | "application/x-shellscript"
            | "application/x-bat"
            | "application/x-csh"
            | "application/java-archive"
            | "application/hta"
            | "application/x-powershell"
            | "application/javascript"
            | "application/x-javascript"
            | "text/javascript"
            | "application/x-vbscript"
            | "text/vbscript"
            | "application/x-ms-shortcut"
    )
}

wrap_download_handler! {
    struct SingularityDownloadHandler {
        cfg: ClientConfig,
    }

    impl DownloadHandler {
        fn can_download(
            &self,
            _browser: Option<&mut Browser>,
            url: Option<&CefString>,
            _request_method: Option<&CefString>,
        ) -> ::std::os::raw::c_int {
            if let Some(u) = url.map(CefString::to_string) {
                if !u.is_empty() && is_blocked_local_ipc_url(&u, self.cfg.bind_port) {
                    return 0;
                }
            }
            1
        }

        fn on_before_download(
            &self,
            _browser: Option<&mut Browser>,
            download_item: Option<&mut DownloadItem>,
            suggested_name: Option<&CefString>,
            callback: Option<&mut BeforeDownloadCallback>,
        ) -> ::std::os::raw::c_int {
            let (Some(item), Some(cb)) = (download_item, callback) else {
                return 0;
            };
            let dl_id = item.id();
            let uri = cef_str_userfree(item.url());
            let orig_uri = cef_str_userfree(item.original_url());
            let mime = cef_str_userfree(item.mime_type());
            let suggested = suggested_name
                .map(CefString::to_string)
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| cef_str_userfree(item.suggested_file_name()));
            let (dest_path, filename) = (self.cfg.download_resolver)(&suggested, &uri);
            let dest_str = dest_path.to_string_lossy().into_owned();
            let dest_basename = dest_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");

            // SECURITY (N4 #6): Never silently drop potentially executable/dangerous payloads or
            // drive-by downloads lacking a verified user gesture — force an explicit OS Save dialog.
            let is_dangerous = is_dangerous_download_name(&suggested)
                || is_dangerous_download_name(&filename)
                || is_dangerous_download_name(dest_basename)
                || is_dangerous_download_url(&uri)
                || is_dangerous_download_url(&orig_uri)
                || is_dangerous_download_mime(&mime);
            let has_user_gesture = self.cfg.has_verified_user_gesture(&uri, &orig_uri);
            let show_dialog: ::std::os::raw::c_int =
                if is_dangerous || !has_user_gesture { 1 } else { 0 };

            if let Ok(mut map) = self.cfg.downloads.lock() {
                map.insert(dl_id, (filename.clone(), dest_str.clone()));
            }
            cb.cont(Some(&CefString::from(dest_str.as_str())), show_dialog);
            (self.cfg.sink)(CefCallbackEvent::DownloadStarted {
                download_id: dl_id,
                filename,
                path: dest_str,
            });
            1
        }

        fn on_download_updated(
            &self,
            _browser: Option<&mut Browser>,
            download_item: Option<&mut DownloadItem>,
            _callback: Option<&mut DownloadItemCallback>,
        ) {
            let Some(item) = download_item else {
                return;
            };
            if item.is_valid() == 0 {
                return;
            }
            let complete = item.is_complete() != 0;
            let canceled = item.is_canceled() != 0;
            if !complete && !canceled {
                return;
            }
            let dl_id = item.id();
            let tracked = self
                .cfg
                .downloads
                .lock()
                .ok()
                .and_then(|mut m| m.remove(&dl_id));
            let Some((filename, path)) = tracked else {
                return;
            };
            let final_path = {
                let fp = cef_str_userfree(item.full_path());
                if fp.is_empty() { path } else { fp }
            };
            (self.cfg.sink)(CefCallbackEvent::DownloadCompleted {
                download_id: dl_id,
                filename,
                path: final_path,
                success: complete && !canceled,
            });
        }
    }
}

wrap_keyboard_handler! {
    struct SingularityKeyboardHandler {
        cfg: ClientConfig,
    }

    impl KeyboardHandler {
        fn on_pre_key_event(
            &self,
            _browser: Option<&mut Browser>,
            event: Option<&KeyEvent>,
            _os_event: Option<&mut sys::MSG>,
            _is_keyboard_shortcut: Option<&mut ::std::os::raw::c_int>,
        ) -> ::std::os::raw::c_int {
            let Some(ev) = event else {
                return 0;
            };
            if ev.type_ != KeyEventType::RAWKEYDOWN {
                return 0;
            }
            if !self.cfg.is_ui {
                self.cfg.record_user_gesture();
            }

            const EVENTFLAG_SHIFT_DOWN: u32 = 1 << 1;
            const EVENTFLAG_CONTROL_DOWN: u32 = 1 << 2;
            const EVENTFLAG_ALT_DOWN: u32 = 1 << 3;
            const EVENTFLAG_COMMAND_DOWN: u32 = 1 << 7;
            const EVENTFLAG_ALTGR_DOWN: u32 = 1 << 12;

            // Logical layout-mapped Windows Virtual Key codes (AZERTY-safe: `VK_W` is strictly the
            // logical `W` key and NEVER matches `Ctrl+Z` / `VK_Z` on French AZERTY keyboards!).
            const VK_TAB: i32 = 0x09;
            const VK_ESCAPE: i32 = 0x1B;
            const VK_PRIOR: i32 = 0x21; // PageUp
            const VK_NEXT: i32 = 0x22; // PageDown
            const VK_LEFT: i32 = 0x25;
            const VK_RIGHT: i32 = 0x27;
            const VK_0: i32 = 0x30;
            const VK_1: i32 = 0x31;
            const VK_9: i32 = 0x39;
            const VK_D: i32 = 0x44;
            const VK_H: i32 = 0x48;
            const VK_L: i32 = 0x4C;
            const VK_N: i32 = 0x4E;
            const VK_R: i32 = 0x52;
            const VK_T: i32 = 0x54;
            const VK_W: i32 = 0x57;
            const VK_NUMPAD0: i32 = 0x60;
            const VK_NUMPAD1: i32 = 0x61;
            const VK_NUMPAD9: i32 = 0x69;
            const VK_ADD: i32 = 0x6B;
            const VK_SUBTRACT: i32 = 0x6D;
            const VK_F4: i32 = 0x73;
            const VK_F5: i32 = 0x74;
            const VK_F6: i32 = 0x75;
            const VK_F11: i32 = 0x7A;
            const VK_BROWSER_BACK: i32 = 0xA6;
            const VK_BROWSER_FORWARD: i32 = 0xA7;
            const VK_OEM_PLUS: i32 = 0xBB;
            const VK_OEM_COMMA: i32 = 0xBC;
            const VK_OEM_MINUS: i32 = 0xBD;

            let shift = (ev.modifiers & EVENTFLAG_SHIFT_DOWN) != 0;
            let ctrl = (ev.modifiers & EVENTFLAG_CONTROL_DOWN) != 0;
            let alt = (ev.modifiers & EVENTFLAG_ALT_DOWN) != 0;
            let meta = (ev.modifiers & EVENTFLAG_COMMAND_DOWN) != 0;
            let altgr = (ev.modifiers & EVENTFLAG_ALTGR_DOWN) != 0;
            // Exclude AltGr (Ctrl+Alt on Windows AZERTY/ISO layouts) from Ctrl shortcuts!
            let ctrl_only = ctrl && !alt && !altgr && !meta;
            let alt_only = alt && !ctrl && !altgr && !meta;
            let no_mods = !ctrl && !alt && !altgr && !meta && !shift;
            let vk = ev.windows_key_code;

            // Extension popups close natively on Escape without needing any `window.ipc` exposure.
            if self.cfg.is_ext_popup {
                if no_mods && vk == VK_ESCAPE {
                    (self.cfg.sink)(CefCallbackEvent::CloseExtensionPopup);
                    return 1;
                }
                return 0;
            }
            if self.cfg.is_standalone_popup {
                return 0;
            }

            // Native navigation & zoom shortcuts (dispatched via `NativeShortcut`).
            let native_action: Option<&'static str> = if vk == VK_BROWSER_BACK
                || (alt_only && !shift && vk == VK_LEFT)
            {
                Some("web_back")
            } else if vk == VK_BROWSER_FORWARD || (alt_only && !shift && vk == VK_RIGHT) {
                Some("web_forward")
            } else if !self.cfg.is_ui && ctrl_only && !shift && (vk == VK_OEM_PLUS || vk == VK_ADD)
            {
                Some("zoom_in")
            } else if !self.cfg.is_ui
                && ctrl_only
                && !shift
                && (vk == VK_OEM_MINUS || vk == VK_SUBTRACT)
            {
                Some("zoom_out")
            } else if !self.cfg.is_ui && ctrl_only && !shift && (vk == VK_0 || vk == VK_NUMPAD0) {
                Some("zoom_reset")
            } else {
                None
            };

            if let Some(act) = native_action {
                (self.cfg.sink)(CefCallbackEvent::NativeShortcut {
                    tab_id: self.cfg.tab_id,
                    action: act,
                });
                return 1;
            }

            // SECURITY (N4 #4): Handle browser shortcuts for web pages natively in the trusted
            // browser process (works inside cross-origin iframes and cannot be forged by page JS).
            if !self.cfg.is_ui && self.cfg.tab_id != 0 {
                let web_shortcut: Option<(&'static str, Option<u8>)> = if no_mods && vk == VK_F11 {
                    Some(("toggle_fullscreen", None))
                } else if ctrl_only && shift && vk == VK_T {
                    Some(("reopen_closed_tab", None))
                } else if ctrl_only && !shift && vk == VK_T {
                    Some(("new_tab", None))
                } else if ctrl_only && !shift && vk == VK_N {
                    Some(("new_window", None))
                } else if ctrl_only && !shift && (vk == VK_W || vk == VK_F4) {
                    Some(("close_active_tab", None))
                } else if ctrl_only && shift && vk == VK_TAB {
                    Some(("prev_tab", None))
                } else if ctrl_only && !shift && (vk == VK_TAB || vk == VK_NEXT) {
                    Some(("next_tab", None))
                } else if ctrl_only && !shift && vk == VK_PRIOR {
                    Some(("prev_tab", None))
                } else if (ctrl_only && !shift && vk == VK_L)
                    || (alt_only && !shift && vk == VK_D)
                    || (no_mods && vk == VK_F6)
                {
                    Some(("focus_omnibar", None))
                } else if (ctrl_only && vk == VK_R)
                    || ((no_mods || (ctrl_only && !shift)) && vk == VK_F5)
                {
                    Some(("reload_tab", None))
                } else if ctrl_only && !shift && vk == VK_D {
                    Some(("toggle_bookmark", None))
                } else if ctrl_only && !shift && vk == VK_H {
                    Some(("open_history", None))
                } else if ctrl_only && !shift && vk == VK_OEM_COMMA {
                    Some(("open_settings", None))
                } else if ctrl_only && !shift && (VK_1..=VK_9).contains(&vk) {
                    Some(("jump_tab", Some((vk - VK_0) as u8)))
                } else if ctrl_only && !shift && (VK_NUMPAD1..=VK_NUMPAD9).contains(&vk) {
                    Some(("jump_tab", Some((vk - VK_NUMPAD0) as u8)))
                } else {
                    None
                };

                if let Some((act, idx)) = web_shortcut {
                    let body = match idx {
                        Some(n) => format!(r#"{{"k":"shortcut","a":"{}","n":{}}}"#, act, n),
                        None => format!(r#"{{"k":"shortcut","a":"{}"}}"#, act),
                    };
                    (self.cfg.sink)(CefCallbackEvent::ContentIpc {
                        tab_id: self.cfg.tab_id,
                        body,
                    });
                    return 1;
                }
            }
            0
        }
    }
}

wrap_client! {
    struct SingularityCefClient {
        cfg: ClientConfig,
    }

    impl Client {
        fn context_menu_handler(&self) -> Option<ContextMenuHandler> {
            Some(SingularityContextMenuHandler::new(self.cfg.clone()))
        }

        fn display_handler(&self) -> Option<DisplayHandler> {
            Some(SingularityDisplayHandler::new(self.cfg.clone()))
        }

        fn download_handler(&self) -> Option<DownloadHandler> {
            if self.cfg.is_ui {
                None
            } else {
                Some(SingularityDownloadHandler::new(self.cfg.clone()))
            }
        }

        fn keyboard_handler(&self) -> Option<KeyboardHandler> {
            Some(SingularityKeyboardHandler::new(self.cfg.clone()))
        }

        fn life_span_handler(&self) -> Option<LifeSpanHandler> {
            Some(SingularityLifeSpanHandler::new(self.cfg.clone()))
        }

        fn load_handler(&self) -> Option<LoadHandler> {
            Some(SingularityLoadHandler::new(self.cfg.clone()))
        }

        fn request_handler(&self) -> Option<RequestHandler> {
            Some(SingularityRequestHandler::new(self.cfg.clone()))
        }

        fn on_process_message_received(
            &self,
            _browser: Option<&mut Browser>,
            frame: Option<&mut Frame>,
            source_process: ProcessId,
            message: Option<&mut ProcessMessage>,
        ) -> ::std::os::raw::c_int {
            let Some(msg) = message else {
                return 0;
            };
            let msg_name = cef_str_userfree(msg.name());
            if msg_name != IPC_MESSAGE_NAME && msg_name != LEGACY_IPC_MESSAGE_NAME {
                return 0;
            }
            // SECURITY (N4 #4): Only the local Singularity UI shell main frame on exact origin
            // `http://127.0.0.1:<bind_port>` may send renderer IPC (`UiIpc`). Reject ALL IPC
            // from web browsers, extension popups, subframes, or non-local origins.
            if msg_name != IPC_MESSAGE_NAME
                || !self.cfg.is_ui
                || self.cfg.is_ext_popup
                || self.cfg.is_standalone_popup
                || source_process != ProcessId::RENDERER
            {
                return 1;
            }
            let Some(frame) = frame else {
                return 1;
            };
            if frame.is_main() == 0 {
                return 1;
            }
            let frame_url = cef_str_userfree(frame.url());
            if !is_exact_local_ui_origin(&frame_url, self.cfg.bind_port) {
                return 1;
            }

            let body = msg
                .argument_list()
                .filter(|a| a.size() > 0)
                .map(|a| cef_str_userfree(a.string(0)))
                .unwrap_or_default();
            if body.is_empty() || body.len() > 262_144 {
                return 1;
            }
            (self.cfg.sink)(CefCallbackEvent::UiIpc(body));
            1
        }
    }
}

/// Owned handle to a child CEF Chromium browser embedded inside a frameless `tao` HWND.
pub struct CefBrowserHandle {
    browser: Browser,
    cached_hwnd: Cell<isize>,
}

impl CefBrowserHandle {
    pub fn cache_hwnd(&self, hwnd: isize) {
        if hwnd != 0 {
            self.cached_hwnd.set(hwnd);
        }
    }

    pub fn hwnd(&self) -> *mut core::ffi::c_void {
        let cached = self.cached_hwnd.get();
        if cached != 0 {
            return cached as *mut core::ffi::c_void;
        }
        if let Some(host) = self.browser.host() {
            let ptr = host.window_handle().0 as *mut core::ffi::c_void;
            if !ptr.is_null() {
                self.cached_hwnd.set(ptr as isize);
                return ptr;
            }
        }
        core::ptr::null_mut()
    }

    /// Resizes and positions the child CEF HWND in physical pixels. Returns `true` only if the
    /// underlying Win32 HWND already existed (so callers do not poison layout caches on NULL HWND).
    pub fn set_bounds(&self, x: i32, y: i32, w: u32, h: u32) -> bool {
        const SWP_NOZORDER: u32 = 0x0004;
        const SWP_NOACTIVATE: u32 = 0x0010;
        let hwnd = self.hwnd();
        if hwnd.is_null() {
            return false;
        }
        unsafe {
            let _ = SetWindowPos(
                hwnd,
                core::ptr::null_mut(),
                x,
                y,
                w.max(1) as i32,
                h.max(1) as i32,
                SWP_NOZORDER | SWP_NOACTIVATE,
            );
        }
        true
    }

    /// Shows or hides the windowed child CEF HWND natively via Win32 `ShowWindow` (which signals
    /// Chromium's `HWNDMessageHandler` cleanly without calling OSR-only `CefBrowserHost::WasHidden`).
    pub fn set_visible(&self, visible: bool) -> bool {
        const SW_HIDE: i32 = 0;
        const SW_SHOWNOACTIVATE: i32 = 4;
        let hwnd = self.hwnd();
        if hwnd.is_null() {
            return false;
        }
        unsafe {
            let _ = ShowWindow(hwnd, if visible { SW_SHOWNOACTIVATE } else { SW_HIDE });
            if visible {
                let _ = InvalidateRect(hwnd, core::ptr::null(), 0);
                let _ = UpdateWindow(hwnd);
            }
        }
        true
    }

    pub fn focus(&self) {
        if let Some(host) = self.browser.host() {
            host.set_focus(1);
        }
        let hwnd = self.hwnd();
        if !hwnd.is_null() {
            unsafe {
                let _ = SetFocus(hwnd);
            }
        }
    }

    pub fn load_url(&self, url: &str) {
        if let Some(frame) = self.browser.main_frame() {
            frame.load_url(Some(&CefString::from(url)));
        }
    }

    pub fn url(&self) -> Option<String> {
        let frame = self.browser.main_frame()?;
        let u = cef_str_userfree(frame.url());
        if u.is_empty() { None } else { Some(u) }
    }

    pub fn evaluate_script(&self, js: &str) {
        if let Some(frame) = self.browser.main_frame() {
            let code = CefString::from(js);
            let src = CefString::from("singularity://eval");
            frame.execute_java_script(Some(&code), Some(&src), 0);
        }
    }

    pub fn reload(&self) {
        self.browser.reload();
    }

    pub fn can_go_back(&self) -> bool {
        self.browser.can_go_back() != 0
    }

    pub fn can_go_forward(&self) -> bool {
        self.browser.can_go_forward() != 0
    }

    pub fn go_back(&self) -> bool {
        if self.browser.can_go_back() != 0 {
            self.browser.go_back();
            true
        } else {
            false
        }
    }

    pub fn go_forward(&self) -> bool {
        if self.browser.can_go_forward() != 0 {
            self.browser.go_forward();
            true
        } else {
            false
        }
    }

    pub fn zoom_step(&self, delta: f64) -> i32 {
        if let Some(host) = self.browser.host() {
            let cur = host.zoom_level();
            let mut next = (cur + delta).clamp(-4.0, 5.0);
            if next.abs() < 0.05 {
                next = 0.0;
            }
            host.set_zoom_level(next);
            return (1.2_f64.powf(next) * 100.0).round() as i32;
        }
        100
    }

    pub fn zoom_reset(&self) -> i32 {
        if let Some(host) = self.browser.host() {
            host.set_zoom_level(0.0);
        }
        100
    }

    pub fn request_context(&self) -> Option<RequestContext> {
        self.browser.host()?.request_context()
    }

    pub fn close_force(&self) {
        const SW_HIDE: i32 = 0;
        let hwnd = self.hwnd();
        if !hwnd.is_null() {
            unsafe {
                let _ = ShowWindow(hwnd, SW_HIDE);
            }
        }
        if let Some(host) = self.browser.host() {
            host.close_browser(1);
        }
    }
}

impl Drop for CefBrowserHandle {
    fn drop(&mut self) {
        self.close_force();
    }
}

/// Spawns a pure Chromium (`RuntimeStyle::ALLOY`) child browser embedded inside `parent_hwnd`.
#[allow(clippy::too_many_arguments)]
pub fn spawn_cef_child_browser(
    parent_hwnd_isize: isize,
    x: i32,
    y: i32,
    width: u32,
    height: u32,
    url: &str,
    is_ui: bool,
    is_ext_popup: bool,
    tab_id: u64,
    bind_port: u16,
    init_script: Option<&str>,
    resume_script: Option<&str>,
    mut request_context: Option<RequestContext>,
    sink: CefEventSink,
    shared_shell: Arc<Mutex<SingularityBrowserShell>>,
    download_resolver: CefDownloadResolver,
) -> Result<CefBrowserHandle, String> {
    let parent_handle = sys::HWND(parent_hwnd_isize as *mut sys::HWND__);
    let rect = Rect {
        x,
        y,
        width: width.max(1) as i32,
        height: height.max(1) as i32,
    };
    let mut window_info = WindowInfo {
        runtime_style: RuntimeStyle::ALLOY,
        ..Default::default()
    }
    .set_as_child(parent_handle, &rect);
    if !is_ui && !is_ext_popup {
        // Start hidden so layout cache reveals it smoothly once bounds match (zero flicker!)
        window_info.style &= !0x1000_0000u32; // Clear WS_VISIBLE
    }

    let settings = BrowserSettings {
        background_color: 0xFF00_0000,
        ..Default::default()
    };

    let cfg = ClientConfig {
        is_ui,
        is_ext_popup,
        is_standalone_popup: false,
        tab_id,
        bind_port,
        sink,
        shared_shell,
        download_resolver,
        downloads: Arc::new(Mutex::new(HashMap::new())),
        last_user_gesture_ms: Arc::new(AtomicU64::new(0)),
        no_gesture_urls: Arc::new(Mutex::new(HashMap::new())),
    };
    let mut client = SingularityCefClient::new(cfg);

    let mut extra = dictionary_value_create();
    if let Some(ref mut dict) = extra {
        let _ = dict.set_bool(Some(&CefString::from("is_ui")), if is_ui { 1 } else { 0 });
        let _ = dict.set_int(Some(&CefString::from("ui_port")), bind_port as i32);
        if let Some(script) = init_script {
            let _ = dict.set_string(
                Some(&CefString::from("init_script")),
                Some(&CefString::from(script)),
            );
        }
        if let Some(script) = resume_script {
            let _ = dict.set_string(
                Some(&CefString::from("resume_script")),
                Some(&CefString::from(script)),
            );
        }
    }

    let browser = browser_host_create_browser_sync(
        Some(&window_info),
        Some(&mut client),
        Some(&CefString::from(url)),
        Some(&settings),
        extra.as_mut(),
        request_context.as_mut(),
    )
    .ok_or_else(|| "CEF browser_host_create_browser_sync returned None".to_string())?;

    let handle = CefBrowserHandle {
        browser,
        cached_hwnd: Cell::new(0),
    };
    if !is_ui && !is_ext_popup {
        handle.set_visible(false);
    }
    Ok(handle)
}

struct CookieHygieneFinalize {
    shared_shell: Arc<Mutex<SingularityBrowserShell>>,
    save_tokens: bool,
    captured: Mutex<Vec<EncryptedAuthTokenRecord>>,
    stats: Mutex<(usize, usize, usize)>,
    on_done: Option<Arc<dyn Fn(usize, usize, usize, usize) + Send + Sync>>,
}

impl Drop for CookieHygieneFinalize {
    fn drop(&mut self) {
        let synced = if self.save_tokens {
            let batch = self
                .captured
                .lock()
                .ok()
                .map(|mut g| std::mem::take(&mut *g))
                .unwrap_or_default();
            if batch.is_empty() {
                0
            } else if let Ok(mut shell) = self.shared_shell.lock() {
                if shell.private_browsing_active {
                    0
                } else {
                    shell.roaming.upsert_tokens_batch(batch).unwrap_or(0)
                }
            } else {
                0
            }
        } else {
            0
        };
        if let Some(mgr) = cookie_manager_get_global_manager(None) {
            let _ = mgr.flush_store(None);
        }
        if let Some(ref cb) = self.on_done {
            let (tr, ad, mal) = self.stats.lock().map(|g| *g).unwrap_or((0, 0, 0));
            cb(tr, ad, mal, synced);
        }
    }
}

wrap_cookie_visitor! {
    struct SingularityCookieHygieneVisitor {
        purge_trackers: bool,
        fin: Arc<CookieHygieneFinalize>,
    }

    impl CookieVisitor {
        fn visit(
            &self,
            cookie: Option<&Cookie>,
            _count: ::std::os::raw::c_int,
            _total: ::std::os::raw::c_int,
            delete_cookie: Option<&mut ::std::os::raw::c_int>,
        ) -> ::std::os::raw::c_int {
            if let Some(c) = cookie {
                let domain = c.domain.to_string();
                let name = c.name.to_string();
                let value = c.value.to_string();
                let path = c.path.to_string();

                let mut deleted = false;
                let dom_lower = domain.trim().to_ascii_lowercase();
                let is_ext_scheme = dom_lower.starts_with("chrome-extension");
                if self.purge_trackers && !is_ext_scheme {
                    let mut threat = classify_tracker_or_malicious_cookie(&domain, &name, &value);
                    let is_ext_host = if !domain.is_empty() {
                        self.fin
                            .shared_shell
                            .lock()
                            .ok()
                            .map(|shell| {
                                let ext_domains =
                                    crate::extensions::collect_installed_extension_host_domains(
                                        shell.roaming.root_dir(),
                                    );
                                crate::extensions::host_matches_extension_domains(
                                    &domain,
                                    &ext_domains,
                                )
                            })
                            .unwrap_or(false)
                    } else {
                        false
                    };
                    if is_ext_host && threat != Some(CookieThreatKind::Malicious) {
                        threat = None;
                    }
                    if threat.is_none()
                        && !is_ext_host
                        && !domain.is_empty()
                        && !is_protected_session_or_functional_cookie(&domain, &name)
                    {
                        if let Ok(shell) = self.fin.shared_shell.lock() {
                            let clean_dom = domain.trim_start_matches('.');
                            let probe_url = format!("https://{}/", clean_dom);
                            if matches!(
                                shell.core.adblocker.evaluate_request(
                                    &probe_url,
                                    clean_dom,
                                    clean_dom,
                                    NetworkResourceType::Image,
                                ),
                                FilterDecision::BlockedByDomainRule(_)
                            ) {
                                threat = Some(CookieThreatKind::Tracker);
                            }
                        }
                    }
                    if let Some(kind) = threat {
                        if let Some(del) = delete_cookie {
                            *del = 1;
                            deleted = true;
                            if let Ok(mut st) = self.fin.stats.lock() {
                                match kind {
                                    CookieThreatKind::Tracker => st.0 += 1,
                                    CookieThreatKind::Advertising => st.1 += 1,
                                    CookieThreatKind::Malicious => st.2 += 1,
                                }
                            }
                        }
                    }
                }

                if !deleted && self.fin.save_tokens && !value.is_empty() && !domain.is_empty() {
                    if let Some(provider) = classify_auth_cookie(&domain, &name) {
                        let now_unix_u64 = unix_now();
                        let now_unix = now_unix_u64 as i64;
                        let (is_expired, exp_unix) = if c.has_expires != 0 {
                            if c.expires.val > WINDOWS_TO_UNIX_EPOCH_US {
                                let unix_sec =
                                    (c.expires.val - WINDOWS_TO_UNIX_EPOCH_US) / 1_000_000;
                                (unix_sec <= now_unix, Some(unix_sec))
                            } else {
                                (true, None)
                            }
                        } else {
                            (false, None)
                        };
                        if !is_expired {
                            let is_host_prefix = name.to_ascii_lowercase().starts_with("__host-");
                            let host_only = is_host_prefix || !domain.starts_with('.');
                            let same_site = if c.same_site == CookieSameSite::STRICT_MODE {
                                Some("strict".to_string())
                            } else if c.same_site == CookieSameSite::LAX_MODE {
                                Some("lax".to_string())
                            } else if c.same_site == CookieSameSite::NO_RESTRICTION {
                                Some("none".to_string())
                            } else {
                                None
                            };
                            if let Ok(mut cap) = self.fin.captured.lock() {
                                cap.push(EncryptedAuthTokenRecord {
                                    id: format!("{}::{}::{}", provider, domain, name),
                                    provider: provider.to_string(),
                                    domain,
                                    path: if is_host_prefix || path.is_empty() {
                                        "/".to_string()
                                    } else {
                                        path
                                    },
                                    token_name: name,
                                    secret_value: value,
                                    http_only: c.httponly != 0,
                                    secure: c.secure != 0 || is_host_prefix,
                                    same_site,
                                    host_only,
                                    expires_unix: exp_unix,
                                    updated_unix: now_unix_u64,
                                    kind: "cookie_session".to_string(),
                                });
                            }
                        }
                    }
                }
            }
            1
        }
    }
}

wrap_set_cookie_callback! {
    struct SingularitySetCookieCounter {
        remaining: Arc<AtomicUsize>,
        succeeded: Arc<AtomicUsize>,
    }

    impl SetCookieCallback {
        fn on_complete(&self, success: ::std::os::raw::c_int) {
            if success != 0 {
                self.succeeded.fetch_add(1, Ordering::AcqRel);
            }
            self.remaining.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

wrap_completion_callback! {
    struct SingularityCompletionFlag {
        done: Arc<AtomicBool>,
    }

    impl CompletionCallback {
        fn on_complete(&self) {
            self.done.store(true, Ordering::Release);
        }
    }
}

struct HydrateFinalize {
    shared_shell: Arc<Mutex<SingularityBrowserShell>>,
    existing: Mutex<HashSet<(String, String)>>,
    manager: CookieManager,
    visit_done: Arc<AtomicBool>,
    pending_sets: Arc<AtomicUsize>,
    hydrated_count: Arc<AtomicUsize>,
}

impl Drop for HydrateFinalize {
    fn drop(&mut self) {
        let sessions = self
            .shared_shell
            .lock()
            .ok()
            .filter(|s| !s.private_browsing_active)
            .map(|s| s.roaming.tokens.sessions.clone())
            .unwrap_or_default();
        let seen = self.existing.lock().ok().map(|g| g.clone()).unwrap_or_default();
        let now_unix = unix_now() as i64;
        for rec in sessions {
            if rec.kind != "cookie_session"
                || rec.domain.is_empty()
                || rec.token_name.is_empty()
            {
                continue;
            }
            // SECURITY (N3 #26): Skip already-expired auth cookies.
            if let Some(exp) = rec.expires_unix {
                if exp <= now_unix {
                    continue;
                }
            }
            let lower_name = rec.token_name.to_ascii_lowercase();
            let is_host_prefix = lower_name.starts_with("__host-");
            let clean_dom = rec.domain.trim_start_matches('.').to_ascii_lowercase();
            if clean_dom.is_empty() {
                continue;
            }
            if seen.contains(&(clean_dom.clone(), lower_name.clone())) {
                continue;
            }
            let cookie_url = format!("https://{}/", clean_dom);
            let is_host_only = is_host_prefix || rec.host_only || !rec.domain.starts_with('.');
            let is_3p_cookie = lower_name.starts_with("__secure-3p");
            let secure_flag = if is_host_prefix
                || rec.secure
                || lower_name.starts_with("__secure-")
                || is_3p_cookie
            {
                1
            } else {
                0
            };
            // SECURITY (N3 #26): Preserve exact SameSite mode (never downgrade `Strict` to `Lax`).
            let same_site = match rec
                .same_site
                .as_deref()
                .map(|s| s.trim().to_ascii_lowercase())
                .as_deref()
            {
                Some("strict") => CookieSameSite::STRICT_MODE,
                Some("lax") => CookieSameSite::LAX_MODE,
                Some("none") | Some("no_restriction") => {
                    if secure_flag != 0 {
                        CookieSameSite::NO_RESTRICTION
                    } else {
                        CookieSameSite::LAX_MODE
                    }
                }
                _ => {
                    if is_3p_cookie && secure_flag != 0 {
                        CookieSameSite::NO_RESTRICTION
                    } else {
                        CookieSameSite::LAX_MODE
                    }
                }
            };
            let mut cef_cookie = Cookie {
                name: CefString::from(rec.token_name.as_str()),
                value: CefString::from(rec.secret_value.as_str()),
                domain: if is_host_only {
                    // Empty domain creates a host-only cookie (required by RFC 6265bis for `__Host-*`).
                    CefString::default()
                } else {
                    CefString::from(rec.domain.as_str())
                },
                path: CefString::from(if is_host_prefix || rec.path.is_empty() {
                    "/"
                } else {
                    rec.path.as_str()
                }),
                secure: secure_flag,
                httponly: if rec.http_only { 1 } else { 0 },
                same_site,
                ..Default::default()
            };
            if let Some(exp) = rec.expires_unix {
                if let Some(us) = exp
                    .checked_mul(1_000_000)
                    .and_then(|v| v.checked_add(WINDOWS_TO_UNIX_EPOCH_US))
                {
                    cef_cookie.has_expires = 1;
                    cef_cookie.expires = Basetime { val: us };
                }
            }
            self.pending_sets.fetch_add(1, Ordering::AcqRel);
            let mut cb = SingularitySetCookieCounter::new(
                Arc::clone(&self.pending_sets),
                Arc::clone(&self.hydrated_count),
            );
            let queued = self.manager.set_cookie(
                Some(&CefString::from(cookie_url.as_str())),
                Some(&cef_cookie),
                Some(&mut cb),
            );
            if queued == 0 {
                self.pending_sets.fetch_sub(1, Ordering::AcqRel);
            }
        }
        let _ = self.manager.flush_store(None);
        self.visit_done.store(true, Ordering::Release);
    }
}

wrap_cookie_visitor! {
    struct SingularityHydrateCollector {
        fin: Arc<HydrateFinalize>,
    }

    impl CookieVisitor {
        fn visit(
            &self,
            cookie: Option<&Cookie>,
            _count: ::std::os::raw::c_int,
            _total: ::std::os::raw::c_int,
            _delete_cookie: Option<&mut ::std::os::raw::c_int>,
        ) -> ::std::os::raw::c_int {
            if let Some(c) = cookie {
                let dom = c
                    .domain
                    .to_string()
                    .trim_start_matches('.')
                    .to_ascii_lowercase();
                let name = c.name.to_string().to_ascii_lowercase();
                if let Ok(mut set) = self.fin.existing.lock() {
                    set.insert((dom, name));
                }
            }
            1
        }
    }
}

wrap_cookie_visitor! {
    struct SingularityProviderPurgeVisitor {
        target: String,
    }

    impl CookieVisitor {
        fn visit(
            &self,
            cookie: Option<&Cookie>,
            _count: ::std::os::raw::c_int,
            _total: ::std::os::raw::c_int,
            delete_cookie: Option<&mut ::std::os::raw::c_int>,
        ) -> ::std::os::raw::c_int {
            if let Some(c) = cookie {
                let dom = c.domain.to_string();
                let name = c.name.to_string();
                if let Some(prov) = classify_auth_cookie(&dom, &name) {
                    let cid = format!("{}::{}::{}", prov, dom, name);
                    if self.target.eq_ignore_ascii_case("ALL")
                        || prov.eq_ignore_ascii_case(&self.target)
                        || cid == self.target
                    {
                        if let Some(del) = delete_cookie {
                            *del = 1;
                        }
                    }
                }
            }
            1
        }
    }
}

/// Synchronously warms Chromium's persistent SQLite cookie store AND hydrates any missing
/// encrypted Roaming auth cookies BEFORE initial restored tabs navigate — preventing the
/// "appeared logged out until manual F5 refresh" startup race!
pub fn hydrate_cookies_from_roaming_cef_sync(
    shared_shell: &Arc<Mutex<SingularityBrowserShell>>,
    timeout: std::time::Duration,
) -> usize {
    let is_private = shared_shell
        .lock()
        .map(|s| s.private_browsing_active)
        .unwrap_or(true);
    if is_private {
        return 0;
    }
    let Some(mgr) = cookie_manager_get_global_manager(None) else {
        return 0;
    };

    let visit_done = Arc::new(AtomicBool::new(false));
    let pending_sets = Arc::new(AtomicUsize::new(0));
    let hydrated_count = Arc::new(AtomicUsize::new(0));

    {
        let fin = Arc::new(HydrateFinalize {
            shared_shell: Arc::clone(shared_shell),
            existing: Mutex::new(HashSet::new()),
            manager: mgr.clone(),
            visit_done: Arc::clone(&visit_done),
            pending_sets: Arc::clone(&pending_sets),
            hydrated_count: Arc::clone(&hydrated_count),
        });
        let mut visitor = SingularityHydrateCollector::new(fin);
        let ok = mgr.visit_all_cookies(Some(&mut visitor));
        if ok == 0 {
            return 0;
        }
    }

    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        pump_cef_message_loop();
        if visit_done.load(Ordering::Acquire) && pending_sets.load(Ordering::Acquire) == 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }

    let restored = hydrated_count.load(Ordering::Acquire);
    if restored > 0 && start.elapsed() < timeout {
        let flushed = Arc::new(AtomicBool::new(false));
        let mut flush_cb = SingularityCompletionFlag::new(Arc::clone(&flushed));
        if mgr.flush_store(Some(&mut flush_cb)) != 0 {
            while !flushed.load(Ordering::Acquire) && start.elapsed() < timeout {
                pump_cef_message_loop();
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
        }
    }
    restored
}

/// Flushes Chromium's persistent cookie store to disk synchronously before clean browser shutdown
/// so freshly refreshed Google / TikTok / YouTube session cookies are never dropped on exit.
pub fn flush_cookie_store_cef_sync(timeout: std::time::Duration) {
    let Some(mgr) = cookie_manager_get_global_manager(None) else {
        return;
    };
    let done = Arc::new(AtomicBool::new(false));
    let mut cb = SingularityCompletionFlag::new(Arc::clone(&done));
    if mgr.flush_store(Some(&mut cb)) == 0 {
        return;
    }
    let start = std::time::Instant::now();
    while !done.load(Ordering::Acquire) && start.elapsed() < timeout {
        pump_cef_message_loop();
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
}

/// Backwards-compatible entry point delegating to synchronous cookie hydration.
pub fn hydrate_cookies_from_roaming_cef(shared_shell: &Arc<Mutex<SingularityBrowserShell>>) {
    let _ = hydrate_cookies_from_roaming_cef_sync(
        shared_shell,
        std::time::Duration::from_millis(1500),
    );
}

/// Single-pass asynchronous CEF cookie hygiene & encrypted auth token snapshot.
pub fn run_cookie_hygiene_cef(
    shared_shell: &Arc<Mutex<SingularityBrowserShell>>,
    purge_trackers: bool,
    save_tokens: bool,
    on_done: Option<Arc<dyn Fn(usize, usize, usize, usize) + Send + Sync>>,
) {
    let Some(mgr) = cookie_manager_get_global_manager(None) else {
        if let Some(cb) = on_done {
            cb(0, 0, 0, 0);
        }
        return;
    };
    let fin = Arc::new(CookieHygieneFinalize {
        shared_shell: Arc::clone(shared_shell),
        save_tokens,
        captured: Mutex::new(Vec::new()),
        stats: Mutex::new((0, 0, 0)),
        on_done,
    });
    let mut visitor = SingularityCookieHygieneVisitor::new(purge_trackers, fin);
    let _ = mgr.visit_all_cookies(Some(&mut visitor));
}

/// Deletes Chromium cookies matching a specific provider (`"Google"`, `"Microsoft"`, etc.) or `"ALL"`.
pub fn purge_provider_cookies_cef(target: &str) {
    let Some(mgr) = cookie_manager_get_global_manager(None) else {
        return;
    };
    let mut visitor = SingularityProviderPurgeVisitor::new(target.to_string());
    let _ = mgr.visit_all_cookies(Some(&mut visitor));
}

/// Clears all cookies from Chromium's global store (called ONLY on explicit full logout/reset).
pub fn clear_all_cookies_cef() {
    if let Some(mgr) = cookie_manager_get_global_manager(None) {
        let _ = mgr.delete_cookies(None, None, None);
        let _ = mgr.flush_store(None);
    }
}

// =================================================================================================
// Zero-Restart Dynamic Chrome Extensions Bridge (Private In-Process Anonymous Win32 CDP Pipes)
// =================================================================================================

type CdpPendingMap =
    HashMap<u64, std::sync::mpsc::Sender<Result<serde_json::Value, String>>>;

const MAX_CDP_FRAME_BYTES: usize = 4 * 1024 * 1024;
const CDP_WRITE_QUEUE_CAPACITY: usize = 64;

/// RAII wrapper for a Win32 `HANDLE` that always invokes `CloseHandle` on `Drop`.
struct OwnedHandle {
    raw: usize,
}

impl OwnedHandle {
    fn from_raw(ptr: *mut core::ffi::c_void) -> Option<Self> {
        let raw = ptr as usize;
        // Reject NULL and Win32 INVALID_HANDLE_VALUE ((HANDLE)-1 == usize::MAX).
        if raw == 0 || raw == usize::MAX {
            None
        } else {
            Some(Self { raw })
        }
    }

    fn as_ptr(&self) -> *mut core::ffi::c_void {
        self.raw as *mut core::ffi::c_void
    }

    fn raw_usize(&self) -> usize {
        self.raw
    }

    /// Transfers ownership of the raw handle to Chromium (`--remote-debugging-io-pipes`) without closing.
    fn into_raw(self) -> usize {
        let raw = self.raw;
        std::mem::forget(self);
        raw
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if self.raw != 0 && self.raw != usize::MAX {
            unsafe {
                let _ = CloseHandle(self.raw as *mut core::ffi::c_void);
            }
            self.raw = 0;
        }
    }
}

fn dispatch_cdp_frame(body: &[u8], pending: &Arc<Mutex<CdpPendingMap>>) {
    if body.is_empty() {
        return;
    }
    if let Ok(val) = serde_json::from_slice::<serde_json::Value>(body) {
        if let Some(id) = val.get("id").and_then(|v| v.as_u64()) {
            let reply = if let Some(err) = val.get("error") {
                let msg = err
                    .get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or("CDP command error")
                    .to_string();
                Err(msg)
            } else {
                Ok(val
                    .get("result")
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!({})))
            };
            if let Ok(mut map) = pending.lock() {
                if let Some(tx) = map.remove(&id) {
                    let _ = tx.send(reply);
                }
            }
        }
    }
}

struct CdpPipeBridge {
    write_tx: std::sync::mpsc::SyncSender<(u64, Vec<u8>)>,
    chrome_io_arg: String,
    pending: Arc<Mutex<CdpPendingMap>>,
    next_id: AtomicU64,
    alive: Arc<AtomicBool>,
}

static CDP_PIPE_BRIDGE: OnceLock<Option<CdpPipeBridge>> = OnceLock::new();
static DYNAMIC_EXTENSIONS_ACTIVE: AtomicBool = AtomicBool::new(false);

fn init_cdp_pipe_bridge() -> Option<&'static CdpPipeBridge> {
    CDP_PIPE_BRIDGE
        .get_or_init(|| {
            let mut raw_chrome_read: *mut core::ffi::c_void = std::ptr::null_mut();
            let mut raw_rust_write: *mut core::ffi::c_void = std::ptr::null_mut();
            if unsafe {
                CreatePipe(
                    &mut raw_chrome_read,
                    &mut raw_rust_write,
                    std::ptr::null(),
                    65536,
                )
            } == 0
            {
                return None;
            }
            let chrome_read = OwnedHandle::from_raw(raw_chrome_read)?;
            let rust_write = OwnedHandle::from_raw(raw_rust_write)?;

            let mut raw_rust_read: *mut core::ffi::c_void = std::ptr::null_mut();
            let mut raw_chrome_write: *mut core::ffi::c_void = std::ptr::null_mut();
            if unsafe {
                CreatePipe(
                    &mut raw_rust_read,
                    &mut raw_chrome_write,
                    std::ptr::null(),
                    65536,
                )
            } == 0
            {
                return None;
            }
            let rust_read = OwnedHandle::from_raw(raw_rust_read)?;
            let chrome_write = OwnedHandle::from_raw(raw_chrome_write)?;

            let cr_val = chrome_read.raw_usize();
            let cw_val = chrome_write.raw_usize();
            if cr_val > u32::MAX as usize || cw_val > u32::MAX as usize {
                // All 4 OwnedHandles close automatically on Drop.
                return None;
            }

            let pending: Arc<Mutex<CdpPendingMap>> = Arc::new(Mutex::new(HashMap::new()));
            let alive = Arc::new(AtomicBool::new(true));
            let (write_tx, write_rx) =
                std::sync::mpsc::sync_channel::<(u64, Vec<u8>)>(CDP_WRITE_QUEUE_CAPACITY);

            // Dedicated bounded writer thread so blocking Win32 `WriteFile` NEVER stalls the UI thread.
            let writer_pending = Arc::clone(&pending);
            let writer_alive = Arc::clone(&alive);
            if std::thread::Builder::new()
                .name("singularity-cdp-writer".into())
                .spawn(move || {
                    let write_handle = rust_write;
                    let h = write_handle.as_ptr();
                    while let Ok((req_id, bytes)) = write_rx.recv() {
                        let mut offset = 0usize;
                        let mut failed = false;
                        while offset < bytes.len() {
                            let mut written: u32 = 0;
                            let remaining = (bytes.len() - offset).min(u32::MAX as usize) as u32;
                            let ok = unsafe {
                                WriteFile(
                                    h,
                                    bytes.as_ptr().add(offset),
                                    remaining,
                                    &mut written,
                                    std::ptr::null_mut(),
                                )
                            };
                            if ok == 0 || written == 0 {
                                failed = true;
                                break;
                            }
                            offset += written as usize;
                        }
                        if failed {
                            writer_alive.store(false, Ordering::Release);
                            if let Ok(mut map) = writer_pending.lock() {
                                if let Some(tx) = map.remove(&req_id) {
                                    let _ = tx
                                        .send(Err("Failed writing CDP frame to Chromium pipe".into()));
                                }
                                for (_, tx) in map.drain() {
                                    let _ = tx.send(Err("CDP pipe write failed".into()));
                                }
                            }
                            break;
                        }
                    }
                    // `write_handle` drops here and calls `CloseHandle`.
                })
                .is_err()
            {
                return None;
            }

            let reader_pending = Arc::clone(&pending);
            let reader_alive = Arc::clone(&alive);
            if std::thread::Builder::new()
                .name("singularity-cdp-reader".into())
                .spawn(move || {
                    let read_handle = rust_read;
                    let h = read_handle.as_ptr();
                    let mut chunk = [0u8; 4096];
                    let mut acc: Vec<u8> = Vec::with_capacity(8192);
                    let mut discarding_oversized = false;
                    loop {
                        let mut nread: u32 = 0;
                        let ok = unsafe {
                            ReadFile(
                                h,
                                chunk.as_mut_ptr(),
                                chunk.len() as u32,
                                &mut nread,
                                std::ptr::null_mut(),
                            )
                        };
                        if ok == 0 || nread == 0 {
                            break;
                        }
                        let mut slice = &chunk[..nread as usize];
                        while !slice.is_empty() {
                            if discarding_oversized {
                                // Drain oversized frame bytes up to the terminating `\0` so all
                                // subsequent CDP frames stay strictly synchronized.
                                if let Some(nul_pos) = slice.iter().position(|&b| b == 0) {
                                    discarding_oversized = false;
                                    slice = &slice[nul_pos + 1..];
                                } else {
                                    slice = &[];
                                }
                                continue;
                            }
                            if let Some(nul_pos) = slice.iter().position(|&b| b == 0) {
                                let part = &slice[..nul_pos];
                                if acc.len().saturating_add(part.len()) <= MAX_CDP_FRAME_BYTES {
                                    acc.extend_from_slice(part);
                                    dispatch_cdp_frame(&acc, &reader_pending);
                                }
                                acc.clear();
                                slice = &slice[nul_pos + 1..];
                            } else {
                                if acc.len().saturating_add(slice.len()) > MAX_CDP_FRAME_BYTES {
                                    acc.clear();
                                    acc.shrink_to(8192);
                                    discarding_oversized = true;
                                } else {
                                    acc.extend_from_slice(slice);
                                }
                                slice = &[];
                            }
                        }
                    }
                    reader_alive.store(false, Ordering::Release);
                    if let Ok(mut map) = reader_pending.lock() {
                        for (_, tx) in map.drain() {
                            let _ = tx.send(Err("CDP pipe closed".into()));
                        }
                    }
                    // `read_handle` drops here and calls `CloseHandle`.
                })
                .is_err()
            {
                // Dropping `write_tx` signals the writer thread to exit and close `rust_write`;
                // `chrome_read` and `chrome_write` drop and close automatically.
                return None;
            }

            // Ownership of Chromium's pipe ends transfers to Chromium's in-process DevTools pipe
            // handler via `--remote-debugging-io-pipes`.
            let cr_owned = chrome_read.into_raw();
            let cw_owned = chrome_write.into_raw();

            Some(CdpPipeBridge {
                write_tx,
                chrome_io_arg: format!("{},{}", cr_owned as u32, cw_owned as u32),
                pending,
                next_id: AtomicU64::new(1),
                alive,
            })
        })
        .as_ref()
}

fn cdp_pipe_io_arg() -> Option<String> {
    CDP_PIPE_BRIDGE
        .get()
        .and_then(|opt| opt.as_ref())
        .map(|b| b.chrome_io_arg.clone())
}

fn cdp_call(
    method: &str,
    params: serde_json::Value,
    timeout: std::time::Duration,
    pump_ui: bool,
) -> Result<serde_json::Value, String> {
    let bridge = CDP_PIPE_BRIDGE
        .get()
        .and_then(|opt| opt.as_ref())
        .ok_or_else(|| "CDP pipe bridge not initialized".to_string())?;
    if !bridge.alive.load(Ordering::Acquire) {
        return Err("CDP pipe is closed".into());
    }

    let id = bridge.next_id.fetch_add(1, Ordering::Relaxed);
    let (tx, rx) = std::sync::mpsc::channel();
    {
        let mut map = bridge
            .pending
            .lock()
            .map_err(|_| "CDP pending lock poisoned".to_string())?;
        map.insert(id, tx);
    }

    let payload = serde_json::json!({
        "id": id,
        "method": method,
        "params": params,
    });
    let mut bytes = match serde_json::to_vec(&payload) {
        Ok(b) => b,
        Err(e) => {
            if let Ok(mut map) = bridge.pending.lock() {
                map.remove(&id);
            }
            return Err(e.to_string());
        }
    };
    bytes.push(0u8);

    // Non-blocking enqueue to the dedicated bounded CDP writer thread (never blocks the UI thread).
    if let Err(err) = bridge.write_tx.try_send((id, bytes)) {
        if let Ok(mut map) = bridge.pending.lock() {
            map.remove(&id);
        }
        return Err(match err {
            std::sync::mpsc::TrySendError::Full(_) => {
                "CDP writer queue full (pipe backpressure)".into()
            }
            std::sync::mpsc::TrySendError::Disconnected(_) => {
                "CDP pipe writer disconnected".into()
            }
        });
    }

    if pump_ui {
        let start = std::time::Instant::now();
        loop {
            match rx.try_recv() {
                Ok(res) => return res,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    return Err("CDP pipe reader disconnected".into());
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
            }
            if start.elapsed() >= timeout {
                if let Ok(mut map) = bridge.pending.lock() {
                    map.remove(&id);
                }
                return Err(format!(
                    "CDP '{}' timed out after {}ms",
                    method,
                    timeout.as_millis()
                ));
            }
            pump_cef_message_loop();
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
    } else {
        match rx.recv_timeout(timeout) {
            Ok(res) => res,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if let Ok(mut map) = bridge.pending.lock() {
                    map.remove(&id);
                }
                Err(format!(
                    "CDP '{}' timed out after {}ms",
                    method,
                    timeout.as_millis()
                ))
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                Err("CDP pipe reader disconnected".into())
            }
        }
    }
}

fn clean_win_abs_path(path: &Path) -> String {
    let resolved = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let raw = resolved.to_string_lossy().into_owned();
    let stripped = raw.strip_prefix(r"\\?\").unwrap_or(&raw);
    stripped.replace('/', "\\")
}

fn normalize_win_ext_path(raw: &str) -> String {
    let stripped = raw.strip_prefix(r"\\?\").unwrap_or(raw);
    stripped
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_ascii_lowercase()
}

fn query_loaded_unpacked_extensions(pump_ui: bool) -> Option<Vec<(String, String)>> {
    let res = cdp_call(
        "Extensions.getExtensions",
        serde_json::json!({}),
        std::time::Duration::from_millis(2500),
        pump_ui,
    )
    .ok()?;
    let arr = res.get("extensions")?.as_array()?;
    let mut out = Vec::new();
    for item in arr {
        let Some(id) = item.get("id").and_then(|v| v.as_str()) else {
            continue;
        };
        let path = item.get("path").and_then(|v| v.as_str()).unwrap_or("");
        out.push((id.to_ascii_lowercase(), path.to_string()));
    }
    Some(out)
}

/// Returns `true` when Chromium's live dynamic extension bridge (zero-restart) is active.
pub fn is_dynamic_extensions_active() -> bool {
    DYNAMIC_EXTENSIONS_ACTIVE.load(Ordering::Acquire)
}

/// Connects to Chromium's private anonymous CDP pipe immediately after CEF initialization
/// and reconciles `%APPDATA%\.singularity\extensions\` live via `Extensions.loadUnpacked` and
/// `Extensions.uninstall` so extensions can be installed, reloaded, toggled, and removed at
/// runtime with ZERO browser restart.
pub fn init_and_sync_dynamic_extensions_cef(roaming_root: &Path) -> bool {
    // Verify the private CDP pipe is responding before marking dynamic mode active.
    if let Err(err) = cdp_call(
        "Browser.getVersion",
        serde_json::json!({}),
        std::time::Duration::from_millis(3000),
        true,
    ) {
        eprintln!(
            "[singularity-cef] Dynamic extension CDP pipe probe failed ({}); falling back to restart-required mode.",
            err
        );
        DYNAMIC_EXTENSIONS_ACTIVE.store(false, Ordering::Release);
        return false;
    }

    let enabled_root = crate::extensions::enabled_extensions_dir(roaming_root);
    let disabled_root = crate::extensions::disabled_extensions_dir(roaming_root);
    let enabled_prefix = format!("{}\\", normalize_win_ext_path(&clean_win_abs_path(&enabled_root)));
    let disabled_prefix = format!("{}\\", normalize_win_ext_path(&clean_win_abs_path(&disabled_root)));

    let enabled_dirs = collect_enabled_extension_dirs(&enabled_root);
    let mut wanted_by_norm: HashMap<String, (String, PathBuf)> = HashMap::new();
    for dir in &enabled_dirs {
        if let Some(dir_id) = dir.file_name().and_then(|n| n.to_str()) {
            let abs = clean_win_abs_path(dir);
            let norm = normalize_win_ext_path(&abs);
            wanted_by_norm.insert(norm, (dir_id.to_string(), dir.clone()));
        }
    }

    let mut loaded_by_norm: HashMap<String, String> = HashMap::new();
    if let Some(loaded) = query_loaded_unpacked_extensions(true) {
        for (rt_id, loaded_path) in loaded {
            let norm = normalize_win_ext_path(&loaded_path);
            let is_managed = norm.starts_with(&enabled_prefix) || norm.starts_with(&disabled_prefix);
            if is_managed && !wanted_by_norm.contains_key(&norm) {
                let _ = cdp_call(
                    "Extensions.uninstall",
                    serde_json::json!({ "id": rt_id }),
                    std::time::Duration::from_millis(3000),
                    true,
                );
            } else {
                loaded_by_norm.insert(norm, rt_id);
            }
        }
    } else if let Ok(entries) = std::fs::read_dir(&disabled_root) {
        // Fallback cleanup when `Extensions.getExtensions` is unavailable: uninstall known disabled IDs
        for entry in entries.flatten() {
            let p = entry.path();
            if !p.is_dir() {
                continue;
            }
            if let Some(dir_id) = p.file_name().and_then(|n| n.to_str()) {
                if let Some(rt_id) = crate::extensions::read_extension_meta(roaming_root, dir_id).runtime_id {
                    let _ = cdp_call(
                        "Extensions.uninstall",
                        serde_json::json!({ "id": rt_id }),
                        std::time::Duration::from_millis(2000),
                        true,
                    );
                }
            }
        }
    }

    for (norm, (dir_id, dir_path)) in &wanted_by_norm {
        if let Some(rt_id) = loaded_by_norm.get(norm) {
            crate::extensions::save_extension_runtime_id(roaming_root, dir_id, rt_id);
            continue;
        }
        let abs = clean_win_abs_path(dir_path);
        match cdp_call(
            "Extensions.loadUnpacked",
            serde_json::json!({ "path": abs }),
            std::time::Duration::from_millis(5000),
            true,
        ) {
            Ok(val) => {
                if let Some(rt_id) = val.get("id").and_then(|v| v.as_str()) {
                    crate::extensions::save_extension_runtime_id(roaming_root, dir_id, rt_id);
                }
            }
            Err(err) => {
                eprintln!(
                    "[singularity-cef] Dynamic startup load failed for '{}': {}",
                    dir_id, err
                );
            }
        }
    }

    DYNAMIC_EXTENSIONS_ACTIVE.store(true, Ordering::Release);
    true
}

/// Loads (or reloads) an unpacked extension directory LIVE into Chromium with zero restart.
pub fn dynamic_load_extension_cef(
    roaming_root: &Path,
    dir_id: &str,
    install_path: &Path,
    pump_ui: bool,
) -> Result<String, String> {
    if !is_dynamic_extensions_active() {
        return Err("Dynamic extensions bridge is not active".into());
    }
    let abs = clean_win_abs_path(install_path);
    let val = cdp_call(
        "Extensions.loadUnpacked",
        serde_json::json!({ "path": abs }),
        std::time::Duration::from_millis(6000),
        pump_ui,
    )?;
    let rt_id = val
        .get("id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_ascii_lowercase())
        .ok_or_else(|| "Chromium did not return an extension ID from Extensions.loadUnpacked".to_string())?;
    crate::extensions::save_extension_runtime_id(roaming_root, dir_id, &rt_id);
    Ok(rt_id)
}

fn resolve_live_runtime_id(
    roaming_root: &Path,
    dir_id: &str,
    install_path: &Path,
    pump_ui: bool,
) -> Option<String> {
    if let Some(rt_id) = crate::extensions::read_extension_meta(roaming_root, dir_id)
        .runtime_id
        .filter(|id| crate::extensions::is_chrome_store_id(id))
    {
        return Some(rt_id);
    }
    let norm_target = normalize_win_ext_path(&clean_win_abs_path(install_path));
    if let Some(loaded) = query_loaded_unpacked_extensions(pump_ui) {
        for (rt_id, loaded_path) in loaded {
            if normalize_win_ext_path(&loaded_path) == norm_target {
                return Some(rt_id);
            }
        }
    }
    if let Some(rt_id) = crate::extensions::find_runtime_extension_id(
        roaming_root,
        install_path,
        dir_id,
        "",
    ) {
        return Some(rt_id);
    }
    if let Ok(raw) = std::fs::read_to_string(install_path.join("manifest.json")) {
        if let Ok(m) = serde_json::from_str::<serde_json::Value>(raw.trim_start_matches('\u{feff}'))
        {
            if let Some(rt_id) = m
                .get("key")
                .and_then(|v| v.as_str())
                .and_then(crate::extensions::chromium_id_from_public_key_b64)
            {
                return Some(rt_id);
            }
        }
    }
    if crate::extensions::is_chrome_store_id(dir_id) {
        return Some(dir_id.to_ascii_lowercase());
    }
    None
}

/// Unloads and uninstalls an unpacked extension LIVE from Chromium with zero restart.
pub fn dynamic_unload_extension_cef(
    roaming_root: &Path,
    dir_id: &str,
    install_path: &Path,
    pump_ui: bool,
) -> Result<(), String> {
    if !is_dynamic_extensions_active() {
        return Err("Dynamic extensions bridge is not active".into());
    }
    let Some(rt_id) = resolve_live_runtime_id(roaming_root, dir_id, install_path, pump_ui) else {
        return Ok(());
    };
    let res = cdp_call(
        "Extensions.uninstall",
        serde_json::json!({ "id": rt_id }),
        std::time::Duration::from_millis(5000),
        pump_ui,
    );
    match res {
        Ok(_) => {
            // Brief settle so Windows releases any file handle inside the unpacked directory.
            std::thread::sleep(std::time::Duration::from_millis(80));
            Ok(())
        }
        Err(msg) => {
            let low = msg.to_ascii_lowercase();
            if low.contains("not found")
                || low.contains("not installed")
                || low.contains("no extension")
                || low.contains("cannot find")
            {
                Ok(())
            } else {
                Err(msg)
            }
        }
    }
}

/// Hot-reloads an unpacked extension LIVE inside Chromium (uninstall + re-loadUnpacked).
pub fn dynamic_reload_extension_cef(
    roaming_root: &Path,
    dir_id: &str,
    install_path: &Path,
    pump_ui: bool,
) -> Result<String, String> {
    let _ = dynamic_unload_extension_cef(roaming_root, dir_id, install_path, pump_ui);
    dynamic_load_extension_cef(roaming_root, dir_id, install_path, pump_ui)
}
