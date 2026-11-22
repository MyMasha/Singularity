//! Multi-threaded Rust Loopback IPC Server & Frameless Native Dual-WebView Desktop Shell.
//!
//! Security hardening:
//! - Binds strictly to an ephemeral loopback port (`127.0.0.1:0`) with a per-launch 256-bit CSPRNG
//!   `X-Singularity-Token` verified in constant time (`subtle::ConstantTimeEq`).
//! - Strict `Host`, `Origin`, and `Sec-Fetch-Site` validation (blocks DNS rebinding & cross-origin CSRF;
//!   zero `Access-Control-Allow-Origin: *`).
//! - All mutating and secret-handling endpoints require `POST` with JSON bodies (never query strings),
//!   bounded request sizes (`<= 512 KiB`), zeroized request buffers, and bounded concurrency (`<= 96`).
//! - Server-side web proxy enforces strict URL authority parsing, DNS-validated SSRF/kill-switch checks
//!   (native WinHTTP on Windows with zero console spawns; `curl --resolve` on Unix), manual hop-by-hop
//!   redirect validation, opaque `sandbox` CSP isolation, UTF-8-safe `<head>` injection, and HTML escaping.

use crate::browser_import;
#[cfg(target_os = "windows")]
use crate::cef_runtime::{
    self, CefBrowserHandle, CefCallbackEvent, CefDownloadResolver, CefEventSink, CefRuntimeGuard,
};
use crate::extensions;
#[cfg(target_os = "windows")]
use crate::roaming_store::{apply_media_timestamp_to_url, normalize_url_without_media_time};
use crate::roaming_store::{
    is_valid_language, is_valid_theme_id, unix_now, BookmarkEntry, EncryptedAuthTokenRecord,
    SavedTabEntry, SavedTabGroup, TabHandoffPayload, WindowGeometry,
};
use crate::shell::SingularityBrowserShell;
use crate::ui_app::SINGULARITY_UI_HTML;
use rand_core::{OsRng, RngCore};
#[cfg(target_os = "windows")]
use serde::Deserialize;
use serde::Serialize;
use sha2::{Digest, Sha256};
use singularity_core::{
    FilterDecision, HoverIntentSignal, NetworkResourceType, UBlockNetworkEngine,
};
use singularity_settings_registry::schema::{SettingCategory, SettingValue};
use singularity_vault::{generate_totp_code, TotpAlgorithm, VaultCredentialEntry};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
#[cfg(target_os = "windows")]
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::Duration;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const BRAND_LOGO_128_PNG: &[u8] = include_bytes!("../assets/logo_128.png");
const MAX_CONCURRENT_CONNECTIONS: usize = 96;
const HTTP_WORKER_THREADS: usize = 32;
const MAX_KEEPALIVE_REQUESTS_PER_CONN: usize = 64;
const MAX_HTTP_HEADER_BYTES: usize = 16 * 1024;
const MAX_HTTP_BODY_BYTES: usize = 512 * 1024;
const MAX_BOOKMARK_IMPORT_BODY_BYTES: usize = 8 * 1024 * 1024;
const MAX_PROXY_REDIRECTS: usize = 5;
const MAX_PROXY_BODY_BYTES: usize = 5 * 1024 * 1024;

static STATE_REVISION: AtomicU64 = AtomicU64::new(1);

fn bump_state_revision() -> u64 {
    STATE_REVISION.fetch_add(1, Ordering::AcqRel) + 1
}

#[cfg(target_os = "windows")]
const WINDOW_ICON_64_RGBA: &[u8] = include_bytes!("../assets/icon_64.rgba");
#[cfg(target_os = "windows")]
const APPLE_BAR_LOGICAL_HEIGHT: f64 = 46.0;

type AdoptTabCallback = Arc<Mutex<Option<Box<dyn Fn(TabHandoffPayload) + Send + Sync>>>>;

/// Per-window session state stored inside our single low-RAM Chromium (CEF) browser process so
/// multiple open Singularity windows each keep independent tabs, tab groups, active tab, and
/// screen geometry without spawning duplicate Chromium browser/GPU/network trees.
#[derive(Clone, Default)]
struct WindowTabSession {
    saved_tabs: Vec<SavedTabEntry>,
    saved_tab_groups: Vec<SavedTabGroup>,
    active_tab_index: usize,
    geometry: WindowGeometry,
    is_detached_handoff: bool,
    is_secondary_live_window: bool,
    restored_windows_count: usize,
}

#[derive(Clone)]
struct ServerConfig {
    bind_port: u16,
    ipc_token: Arc<String>,
    transfer_token: Arc<String>,
    bootstrap_nonce: Arc<String>,
    bootstrap_consumed: Arc<AtomicBool>,
    extra_bootstrap_nonces: Arc<Mutex<HashSet<String>>>,
    window_sessions: Arc<Mutex<HashMap<String, WindowTabSession>>>,
    rendered_html: Arc<Vec<u8>>,
    adopt_tab_tx: AdoptTabCallback,
}

impl ServerConfig {
    fn new(bind_port: u16) -> Self {
        let mut raw = [0u8; 32];
        OsRng.fill_bytes(&mut raw);
        let token = hex::encode(raw);
        let mut xfer_raw = [0u8; 32];
        OsRng.fill_bytes(&mut xfer_raw);
        let transfer_token = hex::encode(xfer_raw);
        let mut boot_raw = [0u8; 24];
        OsRng.fill_bytes(&mut boot_raw);
        let bootstrap_nonce = hex::encode(boot_raw);
        let rendered_html = SINGULARITY_UI_HTML
            .replace("__SINGULARITY_IPC_TOKEN__", &token)
            .into_bytes();
        Self {
            bind_port,
            ipc_token: Arc::new(token),
            transfer_token: Arc::new(transfer_token),
            bootstrap_nonce: Arc::new(bootstrap_nonce),
            bootstrap_consumed: Arc::new(AtomicBool::new(false)),
            extra_bootstrap_nonces: Arc::new(Mutex::new(HashSet::new())),
            window_sessions: Arc::new(Mutex::new(HashMap::new())),
            rendered_html: Arc::new(rendered_html),
            adopt_tab_tx: Arc::new(Mutex::new(None)),
        }
    }

    #[cfg(target_os = "windows")]
    fn mint_bootstrap_nonce(&self) -> String {
        let mut boot_raw = [0u8; 24];
        OsRng.fill_bytes(&mut boot_raw);
        let fresh = hex::encode(boot_raw);
        if let Ok(mut guard) = self.extra_bootstrap_nonces.lock() {
            if guard.len() > 64 {
                guard.clear();
            }
            guard.insert(fresh.clone());
        }
        fresh
    }

    #[cfg(target_os = "windows")]
    fn set_adopt_tab_handler<F>(&self, handler: F)
    where
        F: Fn(TabHandoffPayload) + Send + Sync + 'static,
    {
        if let Ok(mut guard) = self.adopt_tab_tx.lock() {
            *guard = Some(Box::new(handler));
        }
    }

    fn dispatch_adopt_tab(&self, payload: TabHandoffPayload) -> bool {
        if let Ok(guard) = self.adopt_tab_tx.lock() {
            if let Some(ref f) = *guard {
                f(payload);
                return true;
            }
        }
        false
    }

    fn consume_bootstrap_nonce(&self, provided: Option<&str>) -> bool {
        let Some(nonce) = provided else {
            return false;
        };
        let trimmed = nonce.trim();
        let actual = trimmed.as_bytes();
        let expected = self.bootstrap_nonce.as_bytes();
        if expected.len() == actual.len() && bool::from(expected.ct_eq(actual)) {
            return !self.bootstrap_consumed.swap(true, Ordering::AcqRel);
        }
        if let Ok(mut guard) = self.extra_bootstrap_nonces.lock() {
            if let Some(found) = guard
                .iter()
                .find(|n| n.len() == actual.len() && bool::from(n.as_bytes().ct_eq(actual)))
                .cloned()
            {
                guard.remove(&found);
                return true;
            }
        }
        false
    }

    fn is_valid_host(&self, host_header: &str) -> bool {
        let h = host_header.trim().to_ascii_lowercase();
        h == format!("127.0.0.1:{}", self.bind_port) || h == format!("localhost:{}", self.bind_port)
    }

    fn is_valid_origin(&self, origin_header: &str) -> bool {
        let o = origin_header.trim().to_ascii_lowercase();
        o == format!("http://127.0.0.1:{}", self.bind_port)
            || o == format!("http://localhost:{}", self.bind_port)
    }

    fn verify_token(&self, provided: Option<&str>) -> bool {
        let Some(tok) = provided else {
            return false;
        };
        let expected = self.ipc_token.as_bytes();
        let actual = tok.trim().as_bytes();
        expected.len() == actual.len() && bool::from(expected.ct_eq(actual))
    }

    fn verify_transfer_token(&self, provided: Option<&str>) -> bool {
        let Some(tok) = provided else {
            return false;
        };
        let expected = self.transfer_token.as_bytes();
        let actual = tok.trim().as_bytes();
        expected.len() == actual.len() && bool::from(expected.ct_eq(actual))
    }
}

struct ConnGuard {
    counter: Arc<AtomicUsize>,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Fixed-size warm Rust worker pool for loopback HTTP/IPC requests — eliminates per-request
/// Windows OS thread creation overhead (`CreateThread` + 2 MiB stack + DLL_THREAD_ATTACH).
struct HttpThreadPool {
    queue: Arc<(Mutex<VecDeque<TcpStream>>, Condvar)>,
}

impl HttpThreadPool {
    fn new(
        workers: usize,
        shell: Arc<Mutex<SingularityBrowserShell>>,
        cfg: ServerConfig,
        active_conns: Arc<AtomicUsize>,
    ) -> Self {
        let queue: Arc<(Mutex<VecDeque<TcpStream>>, Condvar)> =
            Arc::new((Mutex::new(VecDeque::with_capacity(MAX_CONCURRENT_CONNECTIONS)), Condvar::new()));
        for idx in 0..workers.max(2) {
            let q = Arc::clone(&queue);
            let s = Arc::clone(&shell);
            let c = cfg.clone();
            let conns = Arc::clone(&active_conns);
            let _ = std::thread::Builder::new()
                .name(format!("singularity-http-{}", idx))
                .stack_size(256 * 1024)
                .spawn(move || loop {
                    let stream = {
                        let (lock, cvar) = &*q;
                        let mut guard = lock.lock().unwrap_or_else(|e| e.into_inner());
                        while guard.is_empty() {
                            guard = cvar.wait(guard).unwrap_or_else(|e| e.into_inner());
                        }
                        guard.pop_front()
                    };
                    if let Some(stream) = stream {
                        let _guard = ConnGuard {
                            counter: Arc::clone(&conns),
                        };
                        let _ = handle_ipc_connection(stream, Arc::clone(&s), &c, &conns);
                    }
                });
        }
        Self { queue }
    }

    fn submit(&self, stream: TcpStream, active_conns: &Arc<AtomicUsize>) {
        let _ = stream.set_nodelay(true);
        let prev = active_conns.fetch_add(1, Ordering::AcqRel);
        if prev >= MAX_CONCURRENT_CONNECTIONS {
            active_conns.fetch_sub(1, Ordering::AcqRel);
            let mut s = stream;
            let _ = write_http_response(
                &mut s,
                &HttpResponse::text("503 Service Unavailable", "Too many concurrent requests"),
                false,
            );
            return;
        }
        let (lock, cvar) = &*self.queue;
        let mut guard = lock.lock().unwrap_or_else(|e| e.into_inner());
        guard.push_back(stream);
        cvar.notify_one();
    }
}

struct ParsedHttpRequest {
    method: String,
    path: String,
    query: String,
    headers: HashMap<String, String>,
    body: Zeroizing<Vec<u8>>,
}

struct HttpResponse {
    status: &'static str,
    content_type: &'static str,
    extra_headers: Vec<(&'static str, String)>,
    body: Zeroizing<Vec<u8>>,
}

impl HttpResponse {
    fn new(status: &'static str, content_type: &'static str, body: Vec<u8>) -> Self {
        Self {
            status,
            content_type,
            extra_headers: Vec::new(),
            body: Zeroizing::new(body),
        }
    }

    fn json(status: &'static str, val: &serde_json::Value) -> Self {
        Self::new(
            status,
            "application/json; charset=utf-8",
            serde_json::to_vec(val).unwrap_or_else(|_| b"{}".to_vec()),
        )
    }

    fn json_bytes(status: &'static str, bytes: &[u8]) -> Self {
        Self::new(status, "application/json; charset=utf-8", bytes.to_vec())
    }

    fn text(status: &'static str, text: &str) -> Self {
        Self::new(status, "text/plain; charset=utf-8", text.as_bytes().to_vec())
    }

    fn with_header(mut self, name: &'static str, value: impl Into<String>) -> Self {
        self.extra_headers.push((name, value.into()));
        self
    }
}

/// Configuration for `--smoke-test-cef` end-to-end Windows Pure Chromium verification.
#[derive(Debug, Clone)]
pub struct CefSmokeTestOptions {
    pub log_path: std::path::PathBuf,
    pub cef_log_path: std::path::PathBuf,
    pub profile_dir: std::path::PathBuf,
    pub timeout_secs: u64,
}

/// Boots the Singularity Rust IPC server on an ephemeral loopback port and opens the desktop shell.
pub fn run_interactive_browser_app(shell: SingularityBrowserShell) -> Result<(), String> {
    run_interactive_browser_app_with_smoke(shell, None)
}

/// Boots the Singularity Rust IPC server and optional real-window CEF smoke-test verifier.
pub fn run_interactive_browser_app_with_smoke(
    shell: SingularityBrowserShell,
    smoke: Option<CefSmokeTestOptions>,
) -> Result<(), String> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|e| format!("Failed to bind local IPC server: {}", e))?;

    let local_addr = listener.local_addr().map_err(|e| e.to_string())?;
    let cfg = ServerConfig::new(local_addr.port());
    let app_url = format!("http://{}/?boot={}", local_addr, cfg.bootstrap_nonce);
    let shared_shell = Arc::new(Mutex::new(shell));
    let active_conns = Arc::new(AtomicUsize::new(0));
    let pool = HttpThreadPool::new(
        HTTP_WORKER_THREADS,
        Arc::clone(&shared_shell),
        cfg.clone(),
        Arc::clone(&active_conns),
    );

    #[cfg(target_os = "windows")]
    {
        let accept_conns = Arc::clone(&active_conns);
        std::thread::Builder::new()
            .name("singularity-http-accept".into())
            .spawn(move || {
                for stream in listener.incoming().flatten() {
                    pool.submit(stream, &accept_conns);
                }
            })
            .map_err(|e| format!("Failed spawning HTTP accept thread: {}", e))?;

        let is_smoke = smoke.is_some();
        if let Err(err) = run_windows_frameless_browser(
            local_addr.port(),
            &cfg,
            Arc::clone(&shared_shell),
            smoke,
        ) {
            eprintln!("Singularity Chromium CEF error: {}", err);
            if is_smoke {
                return Err(err);
            }
            launch_native_chromium_window(&app_url);
            loop {
                std::thread::sleep(Duration::from_secs(3600));
            }
        }
        return Ok(());
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = smoke;
        launch_native_chromium_window(&app_url);
        for stream in listener.incoming().flatten() {
            pool.submit(stream, &active_conns);
        }
        Ok(())
    }
}

#[cfg(target_os = "windows")]
fn run_windows_frameless_browser(
    bind_port: u16,
    server_cfg: &ServerConfig,
    shared_shell: Arc<Mutex<SingularityBrowserShell>>,
    smoke_opt: Option<CefSmokeTestOptions>,
) -> Result<(), String> {
    use tao::dpi::{
        LogicalSize, PhysicalPosition as TaoPhysicalPosition, PhysicalSize as TaoPhysicalSize, Size,
    };
    use tao::event::{ElementState, Event, MouseButton, StartCause, WindowEvent};
    use tao::event_loop::{ControlFlow, EventLoopBuilder, EventLoopProxy, EventLoopWindowTarget};
    use tao::platform::windows::{WindowBuilderExtWindows, WindowExtWindows};
    use tao::window::{Fullscreen, Icon, ResizeDirection, Window, WindowBuilder, WindowId};

    #[derive(Debug)]
    enum WinEvent {
        CefPump(i64),
        CefCallback(WindowId, CefCallbackEvent),
        OpenNewWindowInProcess,
        AdoptExternalTab(TabHandoffPayload),
        UiStartupWatchdog(WindowId),
        SmokeCheckPixels(WindowId),
        SmokeFinalize(WindowId),
        SmokeTimeout,
        CookieHygieneDone {
            win_id: WindowId,
            mode: &'static str,
            trackers: usize,
            ads: usize,
            malicious: usize,
            synced: usize,
        },
        LocalExtensionPicked {
            win_id: WindowId,
            path: String,
        },
    }

    #[derive(Debug, Deserialize)]
    struct CtxGroupItem {
        id: String,
        title: String,
    }

    #[derive(Debug, Deserialize)]
    #[serde(tag = "cmd", rename_all = "snake_case")]
    enum UiIpcCmd {
        UiReady,
        CopyText {
            text: String,
        },
        SmokeProbe {
            #[serde(default)]
            bar_h: i32,
            #[serde(default)]
            bar_w: i32,
            #[serde(default)]
            body_w: i32,
            #[serde(default)]
            body_h: i32,
            #[serde(default)]
            has_url_input: bool,
            #[serde(default)]
            tab_count: i32,
            #[serde(default)]
            codecs: String,
            #[serde(default)]
            h264_ok: bool,
            #[serde(default)]
            aac_ok: bool,
            #[serde(default)]
            mp4_avc_aac_ok: bool,
            #[serde(default)]
            mse_avc_aac_ok: bool,
            #[serde(default)]
            ua: String,
            #[serde(default)]
            webdriver: bool,
        },
        DragWindow,
        DragResize {
            direction: String,
        },
        Minimize,
        ToggleMaximize,
        ToggleFullscreen,
        Close,
        NavigateWeb {
            #[serde(default)]
            tab_id: u64,
            url: String,
            #[serde(default)]
            overlay_open: bool,
        },
        ActivateTab {
            tab_id: u64,
            #[serde(default)]
            url: String,
            #[serde(default)]
            web_visible: bool,
            #[serde(default)]
            overlay_open: bool,
            #[serde(default)]
            resume_time_sec: Option<u64>,
            #[serde(default)]
            resume_scroll_y: Option<u32>,
            #[serde(default)]
            start_paused: bool,
        },
        FocusActiveWeb {
            #[serde(default)]
            toggle_media_play: bool,
        },
        CloseTab {
            tab_id: u64,
        },
        UnloadTab {
            tab_id: u64,
        },
        SyncTabUrl {
            tab_id: u64,
        },
        ReloadExtensions,
        PickLocalExtensionPath {
            #[serde(default)]
            mode: String,
        },
        RestartBrowser,
        ToggleExtensionPopup {
            ext_id: String,
            #[serde(default)]
            anchor_x: Option<f64>,
            #[serde(default)]
            open_options: bool,
        },
        ShowExtensionContextMenu {
            ext_id: String,
            #[serde(default)]
            has_popup: bool,
            #[serde(default)]
            has_options: bool,
            #[serde(default)]
            lang: Option<String>,
        },
        SetViewMode {
            web_visible: bool,
            #[serde(default)]
            overlay_open: bool,
        },
        SetOverlay {
            open: bool,
        },
        SetPrivateMode {
            enabled: bool,
        },
        WebBack,
        WebForward,
        WebZoom {
            action: String,
        },
        WebReload,
        SyncTokens,
        PurgeProviderTokens {
            target: String,
        },
        ClearBrowsingData {
            #[serde(default)]
            clear_tokens: bool,
        },
        RevealDownload {
            path: String,
        },
        OpenNewWindow,
        DetachTab {
            tab_id: u64,
            #[serde(default)]
            url: String,
            #[serde(default)]
            title: String,
            #[serde(default)]
            favicon_url: Option<String>,
            #[serde(default)]
            media_time_sec: Option<u64>,
            #[serde(default)]
            scroll_y: Option<u32>,
            #[serde(default)]
            force_new_window: bool,
            #[serde(default)]
            target_window_id: Option<String>,
            #[serde(default)]
            is_only_tab: bool,
        },
        ShowTabContextMenu {
            kind: String,
            #[serde(default)]
            tab_id: Option<u64>,
            #[serde(default)]
            group_id: Option<String>,
            #[serde(default)]
            tab_in_group: bool,
            #[serde(default)]
            can_reopen: bool,
            #[serde(default)]
            is_unloaded: bool,
            #[serde(default)]
            group_collapsed: bool,
            #[serde(default)]
            groups: Vec<CtxGroupItem>,
            #[serde(default)]
            lang: Option<String>,
        },
    }

    #[derive(Default)]
    struct WebViewLayoutCache {
        ui_visible: Option<bool>,
        ui_bounds: Option<(i32, i32, u32, u32)>,
        tab_visible: HashMap<u64, bool>,
        tab_bounds: HashMap<u64, (i32, i32, u32, u32)>,
    }

    impl WebViewLayoutCache {
        fn invalidate_ui(&mut self) {
            self.ui_visible = None;
            self.ui_bounds = None;
        }

        fn invalidate_tab(&mut self, tab_id: Option<u64>) {
            if let Some(tid) = tab_id {
                self.tab_visible.remove(&tid);
                self.tab_bounds.remove(&tid);
            } else {
                self.tab_visible.clear();
                self.tab_bounds.clear();
            }
        }
    }

    #[derive(Debug, Clone)]
    struct BgLinkIntent {
        kind: String,
        href: String,
        title: String,
        at: std::time::Instant,
    }

    #[derive(Debug, Clone)]
    struct TabNavHistory {
        entries: Vec<String>,
        index: usize,
        cef_can_go_back: bool,
        cef_can_go_forward: bool,
        pending_traversal_at: Option<std::time::Instant>,
    }

    impl TabNavHistory {
        fn new_with_home() -> Self {
            Self {
                entries: vec![String::new()],
                index: 0,
                cef_can_go_back: false,
                cef_can_go_forward: false,
                pending_traversal_at: None,
            }
        }

        fn new_with_url(url: &str) -> Self {
            Self {
                entries: vec![url.to_string()],
                index: 0,
                cef_can_go_back: false,
                cef_can_go_forward: false,
                pending_traversal_at: None,
            }
        }

        fn record_url(&mut self, url: &str) {
            if url.is_empty() {
                return;
            }
            if self.entries.is_empty() {
                self.entries.push(url.to_string());
                self.index = 0;
                return;
            }
            if self.entries.get(self.index).map(String::as_str) == Some(url) {
                return;
            }
            let in_traversal = self
                .pending_traversal_at
                .map(|t| t.elapsed() < Duration::from_millis(1600))
                .unwrap_or(false);
            if in_traversal {
                if self.index > 0 && self.entries.get(self.index - 1).map(String::as_str) == Some(url)
                {
                    self.index -= 1;
                    return;
                }
                if self.index + 1 < self.entries.len()
                    && self.entries.get(self.index + 1).map(String::as_str) == Some(url)
                {
                    self.index += 1;
                    return;
                }
            }
            self.pending_traversal_at = None;
            self.entries.truncate(self.index + 1);
            self.entries.push(url.to_string());
            if self.entries.len() > 50 {
                let overflow = self.entries.len() - 50;
                self.entries.drain(0..overflow);
            }
            self.index = self.entries.len().saturating_sub(1);
        }

        fn can_go_back(&self) -> bool {
            self.cef_can_go_back || self.index > 0
        }

        fn can_go_forward(&self) -> bool {
            self.cef_can_go_forward || self.index + 1 < self.entries.len()
        }
    }

    struct ExtPopupState {
        ext_id: String,
        window_id: WindowId,
        auto_dismiss: bool,
        opened_at: std::time::Instant,
        // Drop order: close & release child CEF browser BEFORE destroying parent popup Window!
        browser: CefBrowserHandle,
        window: Window,
    }

    struct BrowserWindowState {
        session_id: String,
        // Drop order matters on Windows: child CEF browsers (`ui_browser`, `tab_browsers`,
        // `ext_popup`) MUST be closed and released BEFORE the parent `tao::Window` destroys
        // the top-level HWND, preventing use-after-destroy crashes inside Chromium teardown!
        ext_popup: Option<ExtPopupState>,
        tab_browsers: HashMap<u64, CefBrowserHandle>,
        ui_browser: CefBrowserHandle,
        window: Window,
        tab_last_urls: HashMap<u64, String>,
        tab_nav_history: HashMap<u64, TabNavHistory>,
        tab_media_times: HashMap<u64, u64>,
        tab_scroll_ys: HashMap<u64, u32>,
        tab_bg_intents: HashMap<u64, BgLinkIntent>,
        last_favicon_at: HashMap<u64, std::time::Instant>,
        layout_cache: WebViewLayoutCache,
        active_tab_id: u64,
        web_visible: bool,
        overlay_open: bool,
        html_fullscreen: bool,
        user_f11_fullscreen: bool,
        was_maximized_before_fs: bool,
        last_maximized: Option<bool>,
        ui_ready_received: bool,
        ui_recovery_attempts: u8,
        was_minimized: bool,
        last_ext_popup_closed: Option<(String, std::time::Instant)>,
        last_nav_at: Option<std::time::Instant>,
    }

    impl BrowserWindowState {
        fn close_ext_popup(&mut self) {
            if let Some(p) = self.ext_popup.take() {
                self.last_ext_popup_closed = Some((p.ext_id, std::time::Instant::now()));
                drop(p.browser);
                drop(p.window);
            }
        }

        /// Hides the top-level window immediately for instant perceived responsiveness, then
        /// cleanly closes all child CEF browsers before destroying the parent Win32 HWND.
        fn close_cleanly(mut self) {
            self.close_ext_popup();
            self.window.set_visible(false);
            for (_, b) in self.tab_browsers.drain() {
                drop(b);
            }
            self.ui_browser.close_force();
            cef_runtime::pump_cef_message_loop();
            drop(self);
        }

        fn sync_layout(&mut self) {
            // Re-enforce WS_CLIPCHILDREN on tao's parent HWND (tao's WindowFlags::apply_diff
            // strips it on set_visible / set_maximized / set_fullscreen, causing WM_ERASEBKGND
            // to paint solid black directly over child Chromium HWNDs!).
            ensure_win32_clip_children(self.window.hwnd() as *mut core::ffi::c_void);

            let phys = self.window.inner_size();
            if phys.width == 0 || phys.height == 0 {
                return;
            }
            let w = phys.width;
            let h = phys.height;
            let scale = self.window.scale_factor();
            let bar_h = ((APPLE_BAR_LOGICAL_HEIGHT * scale).round() as u32).min(h);
            let content_h = h.saturating_sub(bar_h).max(1);
            let in_fs = self.html_fullscreen || self.user_f11_fullscreen;
            let show_active_web = self.web_visible
                && !self.overlay_open
                && self.tab_browsers.contains_key(&self.active_tab_id);

            self.layout_cache
                .tab_visible
                .retain(|tid, _| self.tab_browsers.contains_key(tid));
            self.layout_cache
                .tab_bounds
                .retain(|tid, _| self.tab_browsers.contains_key(tid));

            fn apply_ui(
                cache: &mut WebViewLayoutCache,
                ui_b: &CefBrowserHandle,
                vis: bool,
                rect: Option<(i32, i32, u32, u32)>,
            ) {
                if let Some(r) = rect {
                    if cache.ui_bounds != Some(r) && ui_b.set_bounds(r.0, r.1, r.2, r.3) {
                        cache.ui_bounds = Some(r);
                    }
                }
                if cache.ui_visible != Some(vis) && ui_b.set_visible(vis) {
                    cache.ui_visible = Some(vis);
                }
            }

            fn apply_tab(
                cache: &mut WebViewLayoutCache,
                tid: u64,
                b: &CefBrowserHandle,
                vis: bool,
                rect: Option<(i32, i32, u32, u32)>,
            ) {
                if let Some(r) = rect {
                    if cache.tab_bounds.get(&tid).copied() != Some(r)
                        && b.set_bounds(r.0, r.1, r.2, r.3)
                    {
                        cache.tab_bounds.insert(tid, r);
                    }
                }
                if cache.tab_visible.get(&tid).copied() != Some(vis) && b.set_visible(vis) {
                    cache.tab_visible.insert(tid, vis);
                }
            }

            if show_active_web && in_fs {
                for (&tid, b) in &self.tab_browsers {
                    if tid == self.active_tab_id {
                        apply_tab(&mut self.layout_cache, tid, b, true, Some((0, 0, w, h)));
                    } else {
                        apply_tab(&mut self.layout_cache, tid, b, false, None);
                    }
                }
                apply_ui(&mut self.layout_cache, &self.ui_browser, false, None);
            } else if show_active_web {
                apply_ui(
                    &mut self.layout_cache,
                    &self.ui_browser,
                    true,
                    Some((0, 0, w, bar_h.max(1))),
                );
                for (&tid, b) in &self.tab_browsers {
                    if tid == self.active_tab_id {
                        apply_tab(
                            &mut self.layout_cache,
                            tid,
                            b,
                            true,
                            Some((0, bar_h as i32, w, content_h)),
                        );
                    } else {
                        apply_tab(&mut self.layout_cache, tid, b, false, None);
                    }
                }
            } else {
                // Show & expand dark OLED UI browser BEFORE hiding content tabs (zero white flash).
                apply_ui(&mut self.layout_cache, &self.ui_browser, true, Some((0, 0, w, h)));
                for (&tid, b) in &self.tab_browsers {
                    apply_tab(&mut self.layout_cache, tid, b, false, None);
                }
                self.ui_browser.focus();
            }
        }

        fn sync_maximized(&mut self, force: bool) {
            let is_max = self.window.is_maximized() || self.window.fullscreen().is_some();
            if force || self.last_maximized != Some(is_max) {
                self.last_maximized = Some(is_max);
                emit_ui_sync(&self.ui_browser, &serde_json::json!({ "maximized": is_max }));
            }
        }

        fn apply_fullscreen(&mut self, prev_fs: bool, next_fs: bool) {
            if !prev_fs && next_fs {
                self.was_maximized_before_fs = self.window.is_maximized();
                self.window.set_fullscreen(Some(Fullscreen::Borderless(None)));
            } else if prev_fs && !next_fs {
                self.window.set_fullscreen(None);
                if self.was_maximized_before_fs {
                    self.window.set_maximized(true);
                }
            }
            ensure_win32_clip_children(self.window.hwnd() as *mut core::ffi::c_void);
            self.layout_cache.invalidate_ui();
            self.sync_layout();
            self.sync_maximized(false);
            emit_ui_sync(&self.ui_browser, &serde_json::json!({ "fullscreen": next_fs }));
        }

        fn capture_geometry(
            &self,
            server_cfg: &ServerConfig,
            shared_shell: &Arc<Mutex<SingularityBrowserShell>>,
        ) {
            if self.window.fullscreen().is_some() {
                return;
            }
            let phys = self.window.inner_size();
            if phys.width == 0 || phys.height == 0 {
                return;
            }
            let is_max = self.window.is_maximized();
            let pos = self.window.outer_position().ok();

            if let Ok(mut map) = server_cfg.window_sessions.lock() {
                if let Some(sess) = map.get_mut(&self.session_id) {
                    sess.geometry.maximized = is_max;
                    if !is_max {
                        if let Some(p) = pos {
                            sess.geometry.pos_x = Some(p.x);
                            sess.geometry.pos_y = Some(p.y);
                        }
                        sess.geometry.width = Some(phys.width.max(480));
                        sess.geometry.height = Some(phys.height.max(360));
                    }
                }
            }
            if let Ok(mut shell) = shared_shell.lock() {
                if shell.roaming.window_id() == self.session_id {
                    shell.roaming.window_geometry.maximized = is_max;
                    if !is_max {
                        if let Some(p) = pos {
                            shell.roaming.window_geometry.pos_x = Some(p.x);
                            shell.roaming.window_geometry.pos_y = Some(p.y);
                        }
                        shell.roaming.window_geometry.width = Some(phys.width.max(480));
                        shell.roaming.window_geometry.height = Some(phys.height.max(360));
                    }
                }
            }
        }
    }

    fn emit_ui_sync(ui_b: &CefBrowserHandle, payload: &serde_json::Value) {
        ui_b.evaluate_script(&format!(
            "window.__singularitySyncWeb && window.__singularitySyncWeb({});",
            payload
        ));
    }

    fn read_live_http_url(b: &CefBrowserHandle) -> Option<String> {
        let u = b.url()?;
        if u.starts_with("https://") || u.starts_with("http://") {
            Some(u)
        } else {
            None
        }
    }

    #[repr(C)]
    struct WinPoint {
        x: i32,
        y: i32,
    }

    #[repr(C)]
    struct WinRect {
        left: i32,
        top: i32,
        right: i32,
        bottom: i32,
    }

    #[link(name = "user32")]
    extern "system" {
        fn GetAsyncKeyState(vkey: i32) -> i16;
        fn CreatePopupMenu() -> *mut core::ffi::c_void;
        fn AppendMenuW(
            hmenu: *mut core::ffi::c_void,
            uflags: u32,
            uid_new_item: usize,
            lp_new_item: *const u16,
        ) -> i32;
        fn TrackPopupMenuEx(
            hmenu: *mut core::ffi::c_void,
            fu_flags: u32,
            x: i32,
            y: i32,
            hwnd: *mut core::ffi::c_void,
            lptpm: *mut core::ffi::c_void,
        ) -> i32;
        fn DestroyMenu(hmenu: *mut core::ffi::c_void) -> i32;
        fn GetCursorPos(lp_point: *mut WinPoint) -> i32;
        fn SetForegroundWindow(hwnd: *mut core::ffi::c_void) -> i32;
        fn PostMessageW(
            hwnd: *mut core::ffi::c_void,
            msg: u32,
            wparam: usize,
            lparam: isize,
        ) -> i32;
        fn GetWindowRect(hwnd: *mut core::ffi::c_void, lp_rect: *mut WinRect) -> i32;
        fn IsWindow(hwnd: *mut core::ffi::c_void) -> i32;
        fn IsWindowVisible(hwnd: *mut core::ffi::c_void) -> i32;
        fn IsIconic(hwnd: *mut core::ffi::c_void) -> i32;
        fn ShowWindow(hwnd: *mut core::ffi::c_void, n_cmd_show: i32) -> i32;
        fn WindowFromPoint(pt: WinPoint) -> *mut core::ffi::c_void;
        fn GetAncestor(hwnd: *mut core::ffi::c_void, ga_flags: u32) -> *mut core::ffi::c_void;
    }

    fn enable_win32_dark_menus() {
        #[link(name = "kernel32")]
        extern "system" {
            fn LoadLibraryExW(
                lp_lib_file_name: *const u16,
                hfile: *mut core::ffi::c_void,
                dw_flags: u32,
            ) -> *mut core::ffi::c_void;
            fn GetProcAddress(
                hmodule: *mut core::ffi::c_void,
                lp_proc_name: *const u8,
            ) -> *mut core::ffi::c_void;
        }
        const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x0000_0800;
        let lib_name: Vec<u16> = "uxtheme.dll\0".encode_utf16().collect();
        unsafe {
            let hmod = LoadLibraryExW(
                lib_name.as_ptr(),
                core::ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_SYSTEM32,
            );
            if hmod.is_null() {
                return;
            }
            let p135 = GetProcAddress(hmod, 135usize as *const u8);
            if !p135.is_null() {
                let set_mode: extern "system" fn(i32) -> i32 = core::mem::transmute(p135);
                let _ = set_mode(2);
            }
            let p136 = GetProcAddress(hmod, 136usize as *const u8);
            if !p136.is_null() {
                let flush: extern "system" fn() = core::mem::transmute(p136);
                flush();
            }
        }
    }

    fn apply_win32_black_class_brush(hwnd: *mut core::ffi::c_void) {
        if hwnd.is_null() {
            return;
        }
        #[link(name = "gdi32")]
        extern "system" {
            fn GetStockObject(i: i32) -> *mut core::ffi::c_void;
        }
        #[link(name = "user32")]
        extern "system" {
            fn SetClassLongPtrW(
                hwnd: *mut core::ffi::c_void,
                n_index: i32,
                dw_new_long: isize,
            ) -> usize;
        }
        const BLACK_BRUSH: i32 = 4;
        const GCLP_HBRBACKGROUND: i32 = -10;
        unsafe {
            let black = GetStockObject(BLACK_BRUSH);
            if !black.is_null() {
                let _ = SetClassLongPtrW(hwnd, GCLP_HBRBACKGROUND, black as isize);
            }
        }
    }

    fn ensure_win32_clip_children(hwnd: *mut core::ffi::c_void) {
        if hwnd.is_null() {
            return;
        }
        #[link(name = "user32")]
        extern "system" {
            fn GetWindowLongPtrW(hwnd: *mut core::ffi::c_void, n_index: i32) -> isize;
            fn SetWindowLongPtrW(
                hwnd: *mut core::ffi::c_void,
                n_index: i32,
                dw_new_long: isize,
            ) -> isize;
            fn SetWindowPos(
                hwnd: *mut core::ffi::c_void,
                hwnd_insert_after: *mut core::ffi::c_void,
                x: i32,
                y: i32,
                cx: i32,
                cy: i32,
                uflags: u32,
            ) -> i32;
        }
        const GWL_STYLE: i32 = -16;
        const WS_CLIPCHILDREN: isize = 0x0200_0000;
        const WS_CLIPSIBLINGS: isize = 0x0400_0000;
        const SWP_NOSIZE: u32 = 0x0001;
        const SWP_NOMOVE: u32 = 0x0002;
        const SWP_NOZORDER: u32 = 0x0004;
        const SWP_NOACTIVATE: u32 = 0x0010;
        const SWP_FRAMECHANGED: u32 = 0x0020;
        unsafe {
            let cur = GetWindowLongPtrW(hwnd, GWL_STYLE);
            let want = cur | WS_CLIPCHILDREN | WS_CLIPSIBLINGS;
            if want != cur {
                let _ = SetWindowLongPtrW(hwnd, GWL_STYLE, want);
                let _ = SetWindowPos(
                    hwnd,
                    core::ptr::null_mut(),
                    0,
                    0,
                    0,
                    0,
                    SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED,
                );
            }
        }
    }

    fn has_win32_clip_children(hwnd: *mut core::ffi::c_void) -> bool {
        if hwnd.is_null() {
            return false;
        }
        #[link(name = "user32")]
        extern "system" {
            fn GetWindowLongPtrW(hwnd: *mut core::ffi::c_void, n_index: i32) -> isize;
        }
        const GWL_STYLE: i32 = -16;
        const WS_CLIPCHILDREN: isize = 0x0200_0000;
        unsafe { (GetWindowLongPtrW(hwnd, GWL_STYLE) & WS_CLIPCHILDREN) != 0 }
    }

    /// Safely destroys ONLY an embedded `WS_CHILD` CEF browser HWND on the main UI thread so
    /// closing a single tab frees 100% of Chromium resources without ever posting `WM_CLOSE` to
    /// the top-level parent `tao` browser window.
    fn destroy_cef_child_hwnd(hwnd_isize: isize) {
        if hwnd_isize == 0 {
            return;
        }
        #[link(name = "user32")]
        extern "system" {
            fn GetWindowLongPtrW(hwnd: *mut core::ffi::c_void, n_index: i32) -> isize;
            fn DestroyWindow(hwnd: *mut core::ffi::c_void) -> i32;
        }
        const GWL_STYLE: i32 = -16;
        const WS_CHILD: isize = 0x4000_0000;
        let hwnd = hwnd_isize as *mut core::ffi::c_void;
        unsafe {
            if IsWindow(hwnd) != 0 && (GetWindowLongPtrW(hwnd, GWL_STYLE) & WS_CHILD) != 0 {
                let _ = DestroyWindow(hwnd);
            }
        }
    }

    /// Captures rendered pixels of a Win32 window via `PrintWindow(PW_RENDERFULLCONTENT)` and
    /// returns `(capture_ok, width, height, bar_non_black_pixels, total_non_black_pixels, max_luma)`.
    fn capture_window_non_black_pixels(
        hwnd: *mut core::ffi::c_void,
    ) -> (bool, i32, i32, usize, usize, u8) {
        if hwnd.is_null() {
            return (false, 0, 0, 0, 0, 0);
        }
        #[repr(C)]
        struct BitmapInfoHeader {
            bi_size: u32,
            bi_width: i32,
            bi_height: i32,
            bi_planes: u16,
            bi_bit_count: u16,
            bi_compression: u32,
            bi_size_image: u32,
            bi_x_pels_per_meter: i32,
            bi_y_pels_per_meter: i32,
            bi_clr_used: u32,
            bi_clr_important: u32,
        }
        #[link(name = "user32")]
        extern "system" {
            fn GetDC(hwnd: *mut core::ffi::c_void) -> *mut core::ffi::c_void;
            fn ReleaseDC(hwnd: *mut core::ffi::c_void, hdc: *mut core::ffi::c_void) -> i32;
            fn PrintWindow(
                hwnd: *mut core::ffi::c_void,
                hdc_blt: *mut core::ffi::c_void,
                n_flags: u32,
            ) -> i32;
        }
        #[link(name = "gdi32")]
        extern "system" {
            fn CreateCompatibleDC(hdc: *mut core::ffi::c_void) -> *mut core::ffi::c_void;
            fn CreateCompatibleBitmap(
                hdc: *mut core::ffi::c_void,
                cx: i32,
                cy: i32,
            ) -> *mut core::ffi::c_void;
            fn SelectObject(
                hdc: *mut core::ffi::c_void,
                h: *mut core::ffi::c_void,
            ) -> *mut core::ffi::c_void;
            fn DeleteObject(ho: *mut core::ffi::c_void) -> i32;
            fn DeleteDC(hdc: *mut core::ffi::c_void) -> i32;
            fn GetDIBits(
                hdc: *mut core::ffi::c_void,
                hbm: *mut core::ffi::c_void,
                start: u32,
                c_lines: u32,
                lpv_bits: *mut core::ffi::c_void,
                lpbmi: *mut BitmapInfoHeader,
                usage: u32,
            ) -> i32;
        }
        const PW_RENDERFULLCONTENT: u32 = 0x0000_0002;
        const BI_RGB: u32 = 0;
        const DIB_RGB_COLORS: u32 = 0;

        let mut rc = WinRect {
            left: 0,
            top: 0,
            right: 0,
            bottom: 0,
        };
        unsafe {
            if GetWindowRect(hwnd, &mut rc) == 0 {
                return (false, 0, 0, 0, 0, 0);
            }
            let w = (rc.right - rc.left).clamp(0, 4096);
            let h = (rc.bottom - rc.top).clamp(0, 4096);
            if w <= 0 || h <= 0 {
                return (false, w, h, 0, 0, 0);
            }
            let wnd_dc = GetDC(hwnd);
            if wnd_dc.is_null() {
                return (false, w, h, 0, 0, 0);
            }
            let mem_dc = CreateCompatibleDC(wnd_dc);
            if mem_dc.is_null() {
                let _ = ReleaseDC(hwnd, wnd_dc);
                return (false, w, h, 0, 0, 0);
            }
            let bmp = CreateCompatibleBitmap(wnd_dc, w, h);
            if bmp.is_null() {
                let _ = DeleteDC(mem_dc);
                let _ = ReleaseDC(hwnd, wnd_dc);
                return (false, w, h, 0, 0, 0);
            }
            let old = SelectObject(mem_dc, bmp);
            let pw_ok = PrintWindow(hwnd, mem_dc, PW_RENDERFULLCONTENT) != 0;
            let mut buf = vec![0u8; (w as usize) * (h as usize) * 4];
            let mut bmi = BitmapInfoHeader {
                bi_size: core::mem::size_of::<BitmapInfoHeader>() as u32,
                bi_width: w,
                bi_height: -h, // top-down DIB
                bi_planes: 1,
                bi_bit_count: 32,
                bi_compression: BI_RGB,
                bi_size_image: 0,
                bi_x_pels_per_meter: 0,
                bi_y_pels_per_meter: 0,
                bi_clr_used: 0,
                bi_clr_important: 0,
            };
            let dib_ok = pw_ok
                && GetDIBits(
                    mem_dc,
                    bmp,
                    0,
                    h as u32,
                    buf.as_mut_ptr() as *mut core::ffi::c_void,
                    &mut bmi,
                    DIB_RGB_COLORS,
                ) > 0;
            let _ = SelectObject(mem_dc, old);
            let _ = DeleteObject(bmp);
            let _ = DeleteDC(mem_dc);
            let _ = ReleaseDC(hwnd, wnd_dc);

            if !dib_ok {
                return (false, w, h, 0, 0, 0);
            }
            let bar_rows = (64i32).min(h) as usize;
            let mut bar_non_black = 0usize;
            let mut total_non_black = 0usize;
            let mut max_luma = 0u8;
            for y in 0..(h as usize) {
                let row_off = y * (w as usize) * 4;
                for x in 0..(w as usize) {
                    let i = row_off + x * 4;
                    let b = buf[i];
                    let g = buf[i + 1];
                    let r = buf[i + 2];
                    let luma = r.max(g).max(b);
                    if luma > max_luma {
                        max_luma = luma;
                    }
                    if luma > 8 {
                        total_non_black += 1;
                        if y < bar_rows {
                            bar_non_black += 1;
                        }
                    }
                }
            }
            (true, w, h, bar_non_black, total_non_black, max_luma)
        }
    }

    fn enable_win32_immersive_dark_window(hwnd: *mut core::ffi::c_void) {
        apply_win32_black_class_brush(hwnd);
        ensure_win32_clip_children(hwnd);
        if hwnd.is_null() {
            return;
        }
        #[link(name = "dwmapi")]
        extern "system" {
            fn DwmSetWindowAttribute(
                hwnd: *mut core::ffi::c_void,
                dw_attribute: u32,
                pv_attribute: *const core::ffi::c_void,
                cb_attribute: u32,
            ) -> i32;
        }
        const DWMWA_USE_IMMERSIVE_DARK_MODE: u32 = 20;
        const DWMWA_BORDER_COLOR: u32 = 34;
        const DWMWA_COLOR_NONE: u32 = 0xFFFF_FFFE;
        let dark: u32 = 1;
        let no_border: u32 = DWMWA_COLOR_NONE;
        unsafe {
            let _ = DwmSetWindowAttribute(
                hwnd,
                DWMWA_USE_IMMERSIVE_DARK_MODE,
                &dark as *const u32 as *const core::ffi::c_void,
                core::mem::size_of::<u32>() as u32,
            );
            let _ = DwmSetWindowAttribute(
                hwnd,
                DWMWA_BORDER_COLOR,
                &no_border as *const u32 as *const core::ffi::c_void,
                core::mem::size_of::<u32>() as u32,
            );
        }
    }

    fn resolve_user_downloads_dir() -> std::path::PathBuf {
        #[repr(C)]
        struct Guid {
            data1: u32,
            data2: u16,
            data3: u16,
            data4: [u8; 8],
        }
        const FOLDERID_DOWNLOADS: Guid = Guid {
            data1: 0x374D_E290,
            data2: 0x123F,
            data3: 0x4565,
            data4: [0x91, 0x64, 0x39, 0xC4, 0x92, 0x5E, 0x46, 0x7B],
        };
        #[link(name = "shell32")]
        extern "system" {
            fn SHGetKnownFolderPath(
                rfid: *const Guid,
                dw_flags: u32,
                h_token: *mut core::ffi::c_void,
                ppsz_path: *mut *mut u16,
            ) -> i32;
        }
        #[link(name = "ole32")]
        extern "system" {
            fn CoTaskMemFree(pv: *mut core::ffi::c_void);
        }
        unsafe {
            let mut ptr: *mut u16 = core::ptr::null_mut();
            let hr = SHGetKnownFolderPath(&FOLDERID_DOWNLOADS, 0, core::ptr::null_mut(), &mut ptr);
            if hr == 0 && !ptr.is_null() {
                let mut len = 0usize;
                while *ptr.add(len) != 0 && len < 4096 {
                    len += 1;
                }
                let slice = core::slice::from_raw_parts(ptr, len);
                let s = String::from_utf16_lossy(slice);
                CoTaskMemFree(ptr as *mut core::ffi::c_void);
                if !s.trim().is_empty() {
                    let p = std::path::PathBuf::from(s.trim());
                    let _ = std::fs::create_dir_all(&p);
                    return p;
                }
            }
        }
        let fallback = std::env::var("USERPROFILE")
            .map(|u| std::path::PathBuf::from(u).join("Downloads"))
            .unwrap_or_else(|_| std::env::temp_dir());
        let _ = std::fs::create_dir_all(&fallback);
        fallback
    }

    fn choose_unique_download_path(
        downloads_dir: &Path,
        suggested_name: &str,
        uri: &str,
    ) -> (std::path::PathBuf, String) {
        let raw_name = if !suggested_name.trim().is_empty() {
            suggested_name.trim().to_string()
        } else {
            uri.split('?')
                .next()
                .and_then(|base| base.rsplit('/').next())
                .filter(|s| !s.trim().is_empty())
                .map(url_decode)
                .unwrap_or_else(|| "download.bin".to_string())
        };

        let clean: String = raw_name
            .chars()
            .filter(|c| {
                !c.is_control()
                    && !matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*')
            })
            .take(180)
            .collect();
        let trimmed = clean.trim().trim_matches('.');
        let safe_base = if trimmed.is_empty() {
            "download.bin".to_string()
        } else {
            trimmed.to_string()
        };

        let candidate = downloads_dir.join(&safe_base);
        if !candidate.exists() {
            return (candidate, safe_base);
        }

        let (stem, ext) = match safe_base.rsplit_once('.') {
            Some((s, e)) if !s.is_empty() && e.len() <= 16 => (s.to_string(), format!(".{}", e)),
            _ => (safe_base.clone(), String::new()),
        };
        for i in 1..=999u32 {
            let numbered = format!("{} ({}){}", stem, i, ext);
            let p = downloads_dir.join(&numbered);
            if !p.exists() {
                return (p, numbered);
            }
        }
        (candidate, safe_base)
    }

    fn reveal_download_in_explorer(raw_path: &str) {
        let trimmed = raw_path.trim();
        if trimmed.is_empty() || trimmed.bytes().any(|b| b <= 0x1f || b == 0x7f || b == b'"') {
            return;
        }
        let target = std::path::Path::new(trimmed);
        let downloads_dir = resolve_user_downloads_dir();
        let valid_target = if target.exists() {
            target.to_path_buf()
        } else if let Some(parent) = target.parent().filter(|p| p.is_dir()) {
            parent.to_path_buf()
        } else {
            downloads_dir
        };

        use std::os::windows::ffi::OsStrExt;
        #[link(name = "shell32")]
        extern "system" {
            fn ShellExecuteW(
                hwnd: *mut core::ffi::c_void,
                lp_operation: *const u16,
                lp_file: *const u16,
                lp_parameters: *const u16,
                lp_directory: *const u16,
                n_show_cmd: i32,
            ) -> isize;
        }
        let op: Vec<u16> = std::ffi::OsStr::new("open").encode_wide().chain(Some(0)).collect();
        if valid_target.is_file() {
            let exe: Vec<u16> = std::ffi::OsStr::new("explorer.exe")
                .encode_wide()
                .chain(Some(0))
                .collect();
            let params_str = format!("/select,\"{}\"", valid_target.display());
            let params: Vec<u16> = std::ffi::OsStr::new(&params_str)
                .encode_wide()
                .chain(Some(0))
                .collect();
            unsafe {
                let _ = ShellExecuteW(
                    core::ptr::null_mut(),
                    op.as_ptr(),
                    exe.as_ptr(),
                    params.as_ptr(),
                    core::ptr::null(),
                    1,
                );
            }
        } else {
            let dir_w: Vec<u16> = valid_target.as_os_str().encode_wide().chain(Some(0)).collect();
            unsafe {
                let _ = ShellExecuteW(
                    core::ptr::null_mut(),
                    op.as_ptr(),
                    dir_w.as_ptr(),
                    core::ptr::null(),
                    core::ptr::null(),
                    1,
                );
            }
        }
    }

    fn get_win32_cursor_pos() -> (i32, i32) {
        let mut pt = WinPoint { x: 0, y: 0 };
        unsafe {
            let _ = GetCursorPos(&mut pt);
        }
        (pt.x, pt.y)
    }

    fn bring_win32_window_to_front(hwnd: isize) {
        if hwnd == 0 {
            return;
        }
        const SW_RESTORE: i32 = 9;
        let ptr = hwnd as *mut core::ffi::c_void;
        unsafe {
            if IsIconic(ptr) != 0 {
                let _ = ShowWindow(ptr, SW_RESTORE);
            }
            let _ = SetForegroundWindow(ptr);
        }
    }

    fn get_win32_foreground_hwnd() -> *mut core::ffi::c_void {
        #[link(name = "user32")]
        extern "system" {
            fn GetForegroundWindow() -> *mut core::ffi::c_void;
        }
        unsafe { GetForegroundWindow() }
    }

    /// Returns `true` when Win32 foreground, active window, or keyboard focus belongs to
    /// `popup_hwnd`, any of its embedded child CEF HWNDs (`Chrome_WidgetWin_0` /
    /// `Chrome_RenderWidgetHostHWND`), or an owned dropdown/dialog window.
    fn is_win32_focus_inside_popup(popup_hwnd: *mut core::ffi::c_void) -> bool {
        if popup_hwnd.is_null() {
            return false;
        }
        #[link(name = "user32")]
        extern "system" {
            fn GetForegroundWindow() -> *mut core::ffi::c_void;
            fn GetFocus() -> *mut core::ffi::c_void;
            fn GetActiveWindow() -> *mut core::ffi::c_void;
            fn IsChild(
                parent: *mut core::ffi::c_void,
                child: *mut core::ffi::c_void,
            ) -> i32;
            fn GetAncestor(
                hwnd: *mut core::ffi::c_void,
                ga_flags: u32,
            ) -> *mut core::ffi::c_void;
            fn GetWindow(
                hwnd: *mut core::ffi::c_void,
                u_cmd: u32,
            ) -> *mut core::ffi::c_void;
        }
        const GA_ROOT: u32 = 2;
        const GA_ROOTOWNER: u32 = 3;
        const GW_OWNER: u32 = 4;
        unsafe {
            let belongs = |h: *mut core::ffi::c_void| -> bool {
                if h.is_null() {
                    return false;
                }
                h == popup_hwnd
                    || IsChild(popup_hwnd, h) != 0
                    || GetAncestor(h, GA_ROOT) == popup_hwnd
                    || GetAncestor(h, GA_ROOTOWNER) == popup_hwnd
                    || GetWindow(h, GW_OWNER) == popup_hwnd
            };
            belongs(GetForegroundWindow())
                || belongs(GetFocus())
                || belongs(GetActiveWindow())
        }
    }

    /// Opens the native Windows file chooser filtered for `manifest.json`, `.crx`, and `.zip`.
    /// Runs with a null owner HWND on a worker thread to avoid cross-thread modal input deadlocks.
    fn pick_win32_extension_file() -> Option<String> {
        #[repr(C)]
        struct OpenFileNameW {
            l_struct_size: u32,
            hwnd_owner: *mut core::ffi::c_void,
            h_instance: *mut core::ffi::c_void,
            lpstr_filter: *const u16,
            lpstr_custom_filter: *mut u16,
            n_max_cust_filter: u32,
            n_filter_index: u32,
            lpstr_file: *mut u16,
            n_max_file: u32,
            lpstr_file_title: *mut u16,
            n_max_file_title: u32,
            lpstr_initial_dir: *const u16,
            lpstr_title: *const u16,
            flags: u32,
            n_file_offset: u16,
            n_file_extension: u16,
            lpstr_def_ext: *const u16,
            l_cust_data: isize,
            lpfn_hook: *const core::ffi::c_void,
            lp_template_name: *const u16,
            pv_reserved: *mut core::ffi::c_void,
            dw_reserved: u32,
            flags_ex: u32,
        }
        #[link(name = "comdlg32")]
        extern "system" {
            fn GetOpenFileNameW(lpofn: *mut OpenFileNameW) -> i32;
        }
        const OFN_NOCHANGEDIR: u32 = 0x0000_0008;
        const OFN_PATHMUSTEXIST: u32 = 0x0000_0800;
        const OFN_FILEMUSTEXIST: u32 = 0x0000_1000;
        const OFN_EXPLORER: u32 = 0x0008_0000;

        let filter: Vec<u16> =
            "Chrome Extension (manifest.json, *.crx, *.zip)\0manifest.json;*.json;*.crx;*.zip\0Extension Manifest (manifest.json, *.json)\0manifest.json;*.json\0All Files (*.*)\0*.*\0\0"
                .encode_utf16()
                .collect();
        let title: Vec<u16> =
            "Select Chrome Extension (manifest.json, .crx, or .zip)\0"
                .encode_utf16()
                .collect();
        let mut file_buf = vec![0u16; 4096];

        let mut ofn = OpenFileNameW {
            l_struct_size: std::mem::size_of::<OpenFileNameW>() as u32,
            hwnd_owner: std::ptr::null_mut(),
            h_instance: std::ptr::null_mut(),
            lpstr_filter: filter.as_ptr(),
            lpstr_custom_filter: std::ptr::null_mut(),
            n_max_cust_filter: 0,
            n_filter_index: 1,
            lpstr_file: file_buf.as_mut_ptr(),
            n_max_file: file_buf.len() as u32,
            lpstr_file_title: std::ptr::null_mut(),
            n_max_file_title: 0,
            lpstr_initial_dir: std::ptr::null(),
            lpstr_title: title.as_ptr(),
            flags: OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR,
            n_file_offset: 0,
            n_file_extension: 0,
            lpstr_def_ext: std::ptr::null(),
            l_cust_data: 0,
            lpfn_hook: std::ptr::null(),
            lp_template_name: std::ptr::null(),
            pv_reserved: std::ptr::null_mut(),
            dw_reserved: 0,
            flags_ex: 0,
        };

        let ok = unsafe { GetOpenFileNameW(&mut ofn) };
        if ok == 0 {
            return None;
        }
        let len = file_buf.iter().position(|&c| c == 0).unwrap_or(file_buf.len());
        if len == 0 {
            return None;
        }
        Some(String::from_utf16_lossy(&file_buf[..len]))
    }

    /// Opens the native Windows folder chooser for an unpacked Chrome extension directory.
    fn pick_win32_extension_folder() -> Option<String> {
        #[repr(C)]
        struct BrowseInfoW {
            hwnd_owner: *mut core::ffi::c_void,
            pidl_root: *const core::ffi::c_void,
            psz_display_name: *mut u16,
            lpsz_title: *const u16,
            ul_flags: u32,
            lpfn: *const core::ffi::c_void,
            lparam: isize,
            i_image: i32,
        }
        #[link(name = "ole32")]
        extern "system" {
            fn CoInitializeEx(pv_reserved: *mut core::ffi::c_void, dw_co_init: u32) -> i32;
            fn CoTaskMemFree(pv: *mut core::ffi::c_void);
            fn CoUninitialize();
        }
        #[link(name = "shell32")]
        extern "system" {
            fn SHBrowseForFolderW(lpbi: *mut BrowseInfoW) -> *mut core::ffi::c_void;
            fn SHGetPathFromIDListW(
                pidl: *const core::ffi::c_void,
                psz_path: *mut u16,
            ) -> i32;
        }
        const COINIT_APARTMENTTHREADED: u32 = 0x2;
        const BIF_RETURNONLYFSDIRS: u32 = 0x0001;
        const BIF_NEWDIALOGSTYLE: u32 = 0x0040;
        const BIF_NONEWFOLDERBUTTON: u32 = 0x0200;

        let hr = unsafe { CoInitializeEx(std::ptr::null_mut(), COINIT_APARTMENTTHREADED) };
        let com_inited = hr == 0 || hr == 1;

        let title: Vec<u16> =
            "Select Unpacked Chrome Extension Folder (containing manifest.json)\0"
                .encode_utf16()
                .collect();
        let mut display_buf = [0u16; 260];
        let mut bi = BrowseInfoW {
            hwnd_owner: std::ptr::null_mut(),
            pidl_root: std::ptr::null(),
            psz_display_name: display_buf.as_mut_ptr(),
            lpsz_title: title.as_ptr(),
            ul_flags: BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE | BIF_NONEWFOLDERBUTTON,
            lpfn: std::ptr::null(),
            lparam: 0,
            i_image: 0,
        };

        let result = unsafe {
            let pidl = SHBrowseForFolderW(&mut bi);
            if pidl.is_null() {
                None
            } else {
                let mut path_buf = vec![0u16; 1024];
                let ok = SHGetPathFromIDListW(pidl, path_buf.as_mut_ptr());
                CoTaskMemFree(pidl);
                if ok != 0 {
                    let len = path_buf
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(path_buf.len());
                    if len > 0 {
                        Some(String::from_utf16_lossy(&path_buf[..len]))
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
        };

        if com_inited {
            unsafe {
                CoUninitialize();
            }
        }
        result
    }

    fn is_cursor_clicking_top_bar(window: &Window) -> bool {
        const VK_LBUTTON: i32 = 0x01;
        let lbutton_down = unsafe { ((GetAsyncKeyState(VK_LBUTTON) as u16) & 0x8000) != 0 };
        if !lbutton_down {
            return false;
        }
        let Ok(inner_pos) = window.inner_position() else {
            return false;
        };
        let size = window.inner_size();
        let scale = window.scale_factor();
        let bar_h = ((APPLE_BAR_LOGICAL_HEIGHT * scale).round() as i32).max(1);
        let (cx, cy) = get_win32_cursor_pos();
        cx >= inner_pos.x
            && cx <= inner_pos.x + size.width as i32
            && cy >= inner_pos.y
            && cy < inner_pos.y + bar_h
    }

    /// Detects whether screen point `(px, py)` lands on another visible in-process Singularity window.
    fn find_peer_in_process_window(
        windows: &HashMap<WindowId, BrowserWindowState>,
        exclude: WindowId,
        px: i32,
        py: i32,
    ) -> Option<WindowId> {
        const GA_ROOT: u32 = 2;
        let hit_root = unsafe {
            let raw = WindowFromPoint(WinPoint { x: px, y: py });
            if raw.is_null() {
                0isize
            } else {
                let root = GetAncestor(raw, GA_ROOT);
                (if root.is_null() { raw } else { root }) as isize
            }
        };
        if hit_root != 0 {
            for (&wid, st) in windows {
                if wid != exclude && st.window.hwnd() == hit_root {
                    return Some(wid);
                }
            }
        }
        for (&wid, st) in windows {
            if wid == exclude {
                continue;
            }
            let ptr = st.window.hwnd() as *mut core::ffi::c_void;
            let mut r = WinRect {
                left: 0,
                top: 0,
                right: 0,
                bottom: 0,
            };
            let ok = unsafe {
                IsWindowVisible(ptr) != 0
                    && IsIconic(ptr) == 0
                    && GetWindowRect(ptr, &mut r) != 0
            };
            if ok && px >= r.left - 8 && px <= r.right + 8 && py >= r.top - 28 && py <= r.bottom + 8
            {
                return Some(wid);
            }
        }
        None
    }

    fn encode_menu_wide(label: &str) -> Vec<u16> {
        let clean: String = label
            .chars()
            .filter(|&c| c != '\0' && (!c.is_control() || c == '\t'))
            .take(80)
            .collect();
        clean.encode_utf16().chain(Some(0)).collect()
    }

    fn escape_menu_ampersand(s: &str, is_fr: bool) -> String {
        let clean: String = s
            .chars()
            .filter(|c| !c.is_control())
            .take(40)
            .collect();
        let trimmed = clean.trim();
        if trimmed.is_empty() {
            if is_fr {
                "Groupe sans nom".to_string()
            } else {
                "Unnamed group".to_string()
            }
        } else {
            trimmed.replace('&', "&&")
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn show_native_tab_context_menu(
        hwnd: *mut core::ffi::c_void,
        kind: &str,
        tab_in_group: bool,
        can_reopen: bool,
        is_unloaded: bool,
        group_collapsed: bool,
        groups: &[CtxGroupItem],
        other_window_ids: &[String],
        is_fr: bool,
    ) -> Option<(&'static str, Option<String>)> {
        const MF_STRING: u32 = 0x0000;
        const MF_GRAYED: u32 = 0x0001;
        const MF_POPUP: u32 = 0x0010;
        const MF_SEPARATOR: u32 = 0x0800;
        const TPM_LEFTALIGN: u32 = 0x0000;
        const TPM_TOPALIGN: u32 = 0x0000;
        const TPM_RIGHTBUTTON: u32 = 0x0002;
        const TPM_RETURNCMD: u32 = 0x0100;
        const WM_NULL: u32 = 0x0000;

        let t = |en: &'static str, fr: &'static str| if is_fr { fr } else { en };

        unsafe {
            let hmenu = CreatePopupMenu();
            if hmenu.is_null() {
                return None;
            }
            let add_item = |m: *mut core::ffi::c_void, id: usize, label: &str, disabled: bool| {
                let wide = encode_menu_wide(label);
                let flags = if disabled {
                    MF_STRING | MF_GRAYED
                } else {
                    MF_STRING
                };
                AppendMenuW(m, flags, id, wide.as_ptr());
            };
            let add_sep = |m: *mut core::ffi::c_void| {
                AppendMenuW(m, MF_SEPARATOR, 0, core::ptr::null());
            };

            let mut group_id_map: Vec<(usize, String)> = Vec::new();
            let mut win_id_map: Vec<(usize, String)> = Vec::new();

            match kind {
                "tab" => {
                    add_item(hmenu, 101, t("New tab to the right", "Nouvel onglet à droite"), false);
                    add_item(hmenu, 102, t("Duplicate tab", "Dupliquer l'onglet"), false);
                    add_item(hmenu, 103, t("Reload\tCtrl+R", "Recharger\tCtrl+R"), false);
                    add_item(
                        hmenu,
                        104,
                        if is_unloaded {
                            t("Wake tab", "Réveiller l'onglet")
                        } else {
                            t("Put to sleep (free RAM)", "Mettre en veille (libérer RAM)")
                        },
                        false,
                    );
                    add_sep(hmenu);
                    add_item(
                        hmenu,
                        109,
                        t("Move tab to new window", "Déplacer dans une nouvelle fenêtre"),
                        false,
                    );
                    if !other_window_ids.is_empty() {
                        let wsub = CreatePopupMenu();
                        if !wsub.is_null() {
                            for (idx, wid_str) in other_window_ids.iter().take(12).enumerate() {
                                let cmd_id = 601 + idx;
                                let label = if is_fr {
                                    format!("Fenêtre Singularity #{}", idx + 1)
                                } else {
                                    format!("Singularity Window #{}", idx + 1)
                                };
                                add_item(wsub, cmd_id, &label, false);
                                win_id_map.push((cmd_id, wid_str.clone()));
                            }
                            let wsub_label = encode_menu_wide(t(
                                "Move tab to another window",
                                "Déplacer vers une autre fenêtre",
                            ));
                            AppendMenuW(hmenu, MF_POPUP, wsub as usize, wsub_label.as_ptr());
                        }
                    }

                    let sub = CreatePopupMenu();
                    if !sub.is_null() {
                        add_item(sub, 200, t("+ New group...", "+ Nouveau groupe..."), false);
                        if !groups.is_empty() {
                            add_sep(sub);
                            for (idx, g) in groups.iter().take(24).enumerate() {
                                let cmd_id = 201 + idx;
                                let safe_title = escape_menu_ampersand(&g.title, is_fr);
                                add_item(sub, cmd_id, &safe_title, false);
                                group_id_map.push((cmd_id, g.id.clone()));
                            }
                        }
                        if tab_in_group {
                            add_sep(sub);
                            add_item(sub, 299, t("Remove from group", "Retirer du groupe"), false);
                        }
                        let sub_label = encode_menu_wide(t("Add tab to group", "Ajouter à un groupe"));
                        AppendMenuW(hmenu, MF_POPUP, sub as usize, sub_label.as_ptr());
                    }

                    add_sep(hmenu);
                    add_item(
                        hmenu,
                        105,
                        t("Reopen closed tab\tCtrl+Shift+T", "Rouvrir l'onglet fermé\tCtrl+Shift+T"),
                        !can_reopen,
                    );
                    add_sep(hmenu);
                    add_item(hmenu, 106, t("Close tab\tCtrl+W", "Fermer l'onglet\tCtrl+W"), false);
                    add_item(hmenu, 107, t("Close other tabs", "Fermer les autres onglets"), false);
                    add_item(hmenu, 108, t("Close tabs to the right", "Fermer les onglets à droite"), false);
                }
                "group" => {
                    add_item(hmenu, 301, t("Rename / Group color...", "Renommer / Couleur du groupe..."), false);
                    add_item(hmenu, 302, t("New tab in group", "Nouvel onglet dans ce groupe"), false);
                    add_item(
                        hmenu,
                        303,
                        if group_collapsed {
                            t("Expand group", "Déplier le groupe")
                        } else {
                            t("Collapse group", "Réduire le groupe")
                        },
                        false,
                    );
                    add_sep(hmenu);
                    add_item(hmenu, 304, t("Ungroup", "Dissocier le groupe"), false);
                    add_item(hmenu, 305, t("Close group", "Fermer le groupe"), false);
                }
                _ => {
                    add_item(hmenu, 401, t("New tab\tCtrl+T", "Nouvel onglet\tCtrl+T"), false);
                    add_item(hmenu, 406, t("New window\tCtrl+N", "Nouvelle fenêtre\tCtrl+N"), false);
                    add_item(
                        hmenu,
                        402,
                        t("Reopen closed tab\tCtrl+Shift+T", "Rouvrir l'onglet fermé\tCtrl+Shift+T"),
                        !can_reopen,
                    );
                    add_sep(hmenu);
                    add_item(hmenu, 403, t("Create new group", "Créer un nouveau groupe"), false);
                    add_item(hmenu, 404, t("Sleep inactive tabs", "Mettre en veille les onglets inactifs"), false);
                    add_sep(hmenu);
                    add_item(hmenu, 405, t("Singularity Settings\tCtrl+,", "Paramètres Singularity\tCtrl+,"), false);
                }
            }

            let mut pt = WinPoint { x: 0, y: 0 };
            let _ = GetCursorPos(&mut pt);
            let _ = SetForegroundWindow(hwnd);
            let selected = TrackPopupMenuEx(
                hmenu,
                TPM_LEFTALIGN | TPM_TOPALIGN | TPM_RIGHTBUTTON | TPM_RETURNCMD,
                pt.x,
                pt.y,
                hwnd,
                core::ptr::null_mut(),
            ) as usize;
            let _ = PostMessageW(hwnd, WM_NULL, 0, 0);
            let _ = DestroyMenu(hmenu);

            if selected == 0 {
                return None;
            }
            if let Some((_, gid)) = group_id_map.into_iter().find(|(id, _)| *id == selected) {
                return Some(("add_to_group", Some(gid)));
            }
            if let Some((_, wid)) = win_id_map.into_iter().find(|(id, _)| *id == selected) {
                return Some(("move_tab_to_window", Some(wid)));
            }
            let action = match selected {
                101 => "new_tab_right",
                102 => "duplicate_tab",
                103 => "reload_tab",
                104 => "unload_tab",
                105 => "reopen_closed_tab",
                106 => "close_tab",
                107 => "close_other_tabs",
                108 => "close_tabs_right",
                109 => "move_tab_new_window",
                200 => "add_to_new_group",
                299 => "remove_from_group",
                301 => "edit_group",
                302 => "new_tab_in_group",
                303 => "toggle_group_collapse",
                304 => "ungroup",
                305 => "close_group",
                401 => "new_tab",
                402 => "reopen_closed_tab",
                403 => "new_group_empty",
                404 => "unload_inactive",
                405 => "open_settings",
                406 => "new_window",
                _ => return None,
            };
            Some((action, None))
        }
    }

    fn show_native_extension_context_menu(
        hwnd: *mut core::ffi::c_void,
        has_popup: bool,
        has_options: bool,
        is_fr: bool,
    ) -> Option<&'static str> {
        const MF_STRING: u32 = 0x0000;
        const MF_GRAYED: u32 = 0x0001;
        const MF_SEPARATOR: u32 = 0x0800;
        const TPM_LEFTALIGN: u32 = 0x0000;
        const TPM_TOPALIGN: u32 = 0x0000;
        const TPM_RIGHTBUTTON: u32 = 0x0002;
        const TPM_RETURNCMD: u32 = 0x0100;
        const WM_NULL: u32 = 0x0000;

        let t = |en: &'static str, fr: &'static str| if is_fr { fr } else { en };

        unsafe {
            let hmenu = CreatePopupMenu();
            if hmenu.is_null() {
                return None;
            }
            let add_item = |m: *mut core::ffi::c_void, id: usize, label: &str, disabled: bool| {
                let wide = encode_menu_wide(label);
                let flags = if disabled {
                    MF_STRING | MF_GRAYED
                } else {
                    MF_STRING
                };
                AppendMenuW(m, flags, id, wide.as_ptr());
            };
            let add_sep = |m: *mut core::ffi::c_void| {
                AppendMenuW(m, MF_SEPARATOR, 0, core::ptr::null());
            };

            add_item(
                hmenu,
                501,
                t("Open extension popup", "Ouvrir le menu de l'extension"),
                !has_popup && !has_options,
            );
            if has_options {
                add_item(hmenu, 502, t("Extension options", "Options de l'extension"), false);
            }
            add_sep(hmenu);
            add_item(hmenu, 503, t("Unpin from toolbar", "Détacher de la barre d'outils"), false);
            add_item(hmenu, 504, t("Disable extension", "Désactiver l'extension"), false);
            add_sep(hmenu);
            add_item(hmenu, 505, t("Manage extensions...", "Gérer les extensions..."), false);

            let mut pt = WinPoint { x: 0, y: 0 };
            let _ = GetCursorPos(&mut pt);
            let _ = SetForegroundWindow(hwnd);
            let selected = TrackPopupMenuEx(
                hmenu,
                TPM_LEFTALIGN | TPM_TOPALIGN | TPM_RIGHTBUTTON | TPM_RETURNCMD,
                pt.x,
                pt.y,
                hwnd,
                core::ptr::null_mut(),
            ) as usize;
            let _ = PostMessageW(hwnd, WM_NULL, 0, 0);
            let _ = DestroyMenu(hmenu);

            match selected {
                501 => Some("open_popup"),
                502 => Some("open_options"),
                503 => Some("unpin_ext"),
                504 => Some("disable_ext"),
                505 => Some("manage_ext"),
                _ => None,
            }
        }
    }

    const EXT_POPUP_INIT_SCRIPT: &str = r##"(function(){
  if (window.__sgExtPopupHooked) return;
  window.__sgExtPopupHooked = true;
  document.addEventListener("keydown", function(e) {
    if (e && e.isTrusted !== false && e.key === "Escape") {
      try {
        window.ipc && window.ipc.postMessage(JSON.stringify({ k: "close_ext_popup" }));
      } catch (_) {}
    }
  }, true);
})();"##;

    const CONTENT_LINK_INTENT_SCRIPT: &str = r##"(function(){
  if (window.__sgLinkHooked) return;
  window.__sgLinkHooked = true;
  const postIpc = (window.ipc && typeof window.ipc.postMessage === "function")
    ? window.ipc.postMessage.bind(window.ipc)
    : null;
  if (!postIpc) return;
  function findAnchor(e) {
    if (typeof e.composedPath === "function") {
      for (const n of e.composedPath()) {
        if (n && n.tagName === "A" && n.href) return n;
      }
    }
    return e.target && e.target.closest ? e.target.closest("a[href]") : null;
  }
  function cleanTitle(s) {
    return String(s || "").replace(/\s+/g, " ").trim().slice(0, 120);
  }
  function extractTitle(a) {
    let t = cleanTitle(a.getAttribute("title") || a.getAttribute("aria-label") || a.innerText);
    if (!t || a.id === "thumbnail" || /^\d{1,2}:\d{2}(?::\d{2})?(?:\s|$)/.test(t)) {
      const card = a.closest(
        "ytd-rich-item-renderer,ytd-video-renderer,ytd-compact-video-renderer,ytd-grid-video-renderer,ytd-playlist-video-renderer,yt-lockup-view-model,article,[role='article']"
      );
      if (card) {
        const el = card.querySelector("#video-title,a#video-title-link,h3,h2,a[title]");
        if (el) {
          t = cleanTitle(el.getAttribute("title") || el.getAttribute("aria-label") || el.innerText);
        }
      }
    }
    return t;
  }
  function report(kind, e) {
    if (!e || e.isTrusted === false) return;
    const a = findAnchor(e);
    if (!a || !/^https?:\/\//i.test(a.href)) return;
    try {
      postIpc(JSON.stringify({ k: kind, u: a.href, t: extractTitle(a) }));
    } catch (_) {}
  }
  document.addEventListener("mousedown", function(e) {
    if (!e || e.isTrusted === false) return;
    if (e.button === 3) {
      sendShortcut("web_back", 0, e);
      return;
    }
    if (e.button === 4) {
      sendShortcut("web_forward", 0, e);
      return;
    }
    if (e.button === 1 || (e.button === 0 && (e.ctrlKey || e.metaKey))) report("bg_click", e);
  }, true);
  document.addEventListener("mouseup", function(e) {
    if (e && e.isTrusted !== false && (e.button === 3 || e.button === 4)) {
      try { e.preventDefault(); e.stopPropagation(); } catch (_) {}
    }
  }, true);
  document.addEventListener("auxclick", function(e) {
    if (!e || e.isTrusted === false) return;
    if (e.button === 3 || e.button === 4) {
      try { e.preventDefault(); e.stopPropagation(); } catch (_) {}
      return;
    }
    if (e.button === 1) report("bg_click", e);
  }, true);
  document.addEventListener("wheel", function(e) {
    if (!e || e.isTrusted === false) return;
    if ((e.ctrlKey || e.metaKey) && !e.altKey && e.deltaY !== 0) {
      sendShortcut(e.deltaY < 0 ? "zoom_in" : "zoom_out", 0, e);
    }
  }, { capture: true, passive: false });
  document.addEventListener("contextmenu", function(e) {
    report("context_link", e);
  }, true);

  function sendShortcut(action, idx, e) {
    try {
      e.preventDefault();
      e.stopPropagation();
    } catch (_) {}
    try {
      const msg = idx ? { k: "shortcut", a: action, n: idx } : { k: "shortcut", a: action };
      postIpc(JSON.stringify(msg));
    } catch (_) {}
  }
  document.addEventListener("keydown", function(e) {
    if (!e || e.isTrusted === false) return;
    const ctrl = (e.ctrlKey || e.metaKey) && !e.altKey;
    const alt = e.altKey && !e.ctrlKey && !e.metaKey;
    const k = String(e.key || "").toLowerCase();
    const code = String(e.code || "");
    if (!e.ctrlKey && !e.altKey && !e.metaKey && !e.shiftKey && (code === "F11" || e.key === "F11")) {
      sendShortcut("toggle_fullscreen", 0, e);
    } else if (ctrl && e.shiftKey && (k === "t" || code === "KeyT")) {
      sendShortcut("reopen_closed_tab", 0, e);
    } else if (ctrl && !e.shiftKey && (k === "t" || code === "KeyT")) {
      sendShortcut("new_tab", 0, e);
    } else if (ctrl && !e.shiftKey && (k === "n" || code === "KeyN")) {
      sendShortcut("new_window", 0, e);
    } else if (ctrl && !e.shiftKey && (k === "w" || code === "KeyW" || code === "F4")) {
      sendShortcut("close_active_tab", 0, e);
    } else if (ctrl && e.shiftKey && (k === "tab" || code === "Tab")) {
      sendShortcut("prev_tab", 0, e);
    } else if (ctrl && !e.shiftKey && (k === "tab" || code === "Tab" || code === "PageDown")) {
      sendShortcut("next_tab", 0, e);
    } else if (ctrl && !e.shiftKey && code === "PageUp") {
      sendShortcut("prev_tab", 0, e);
    } else if ((ctrl && !e.shiftKey && (k === "l" || code === "KeyL")) || (alt && !e.shiftKey && (k === "d" || code === "KeyD")) || (!e.ctrlKey && !e.altKey && !e.metaKey && !e.shiftKey && code === "F6")) {
      sendShortcut("focus_omnibar", 0, e);
    } else if ((ctrl && !e.shiftKey && (k === "r" || code === "KeyR")) || (!e.ctrlKey && !e.altKey && !e.metaKey && !e.shiftKey && code === "F5")) {
      sendShortcut("reload_tab", 0, e);
    } else if (ctrl && !e.shiftKey && (k === "d" || code === "KeyD")) {
      sendShortcut("toggle_bookmark", 0, e);
    } else if (ctrl && !e.shiftKey && (k === "h" || code === "KeyH")) {
      sendShortcut("open_history", 0, e);
    } else if (ctrl && !e.shiftKey && (k === "," || code === "Comma")) {
      sendShortcut("open_settings", 0, e);
    } else if (ctrl && !e.shiftKey && (k === "+" || k === "=" || code === "Equal" || code === "NumpadAdd")) {
      sendShortcut("zoom_in", 0, e);
    } else if (ctrl && !e.shiftKey && (k === "-" || code === "Minus" || code === "NumpadSubtract")) {
      sendShortcut("zoom_out", 0, e);
    } else if (ctrl && !e.shiftKey && (k === "0" || code === "Digit0" || code === "Numpad0")) {
      sendShortcut("zoom_reset", 0, e);
    } else if (ctrl && !e.shiftKey && /^[1-9]$/.test(k)) {
      sendShortcut("jump_tab", parseInt(k, 10), e);
    } else if (ctrl && !e.shiftKey && /^Digit[1-9]$/.test(code)) {
      sendShortcut("jump_tab", parseInt(code.slice(5), 10), e);
    } else if ((alt && !e.shiftKey && e.key === "ArrowLeft") || e.key === "BrowserBack" || code === "BrowserBack") {
      sendShortcut("web_back", 0, e);
    } else if ((alt && !e.shiftKey && e.key === "ArrowRight") || e.key === "BrowserForward" || code === "BrowserForward") {
      sendShortcut("web_forward", 0, e);
    } else if (
      !e.ctrlKey && !e.altKey && !e.metaKey && !e.shiftKey && !e.repeat
      && (code === "Space" || e.key === " ")
      && window.top === window
      && /(^|\.)youtube\.com$/i.test(String(location.hostname || ""))
    ) {
      const ae = document.activeElement;
      const tag = ae && ae.tagName ? ae.tagName.toUpperCase() : "";
      const isInteractive = !!(ae && (
        tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || tag === "BUTTON" || tag === "A" ||
        ae.isContentEditable ||
        (ae.closest && ae.closest("input,textarea,select,button,a,[contenteditable='true'],[contenteditable=''],[role='textbox'],[role='button'],[role='slider'],#movie_player,.html5-video-player"))
      ));
      if (!isInteractive) {
        const player = document.getElementById("movie_player") || document.querySelector(".html5-video-player");
        const video = player ? player.querySelector("video") : document.querySelector("video");
        if (player && video && isFinite(video.duration) && video.duration > 0) {
          const rect = player.getBoundingClientRect();
          if (rect.width > 120 && rect.height > 80) {
            try { e.preventDefault(); e.stopPropagation(); } catch (_) {}
            if (typeof window.__singularityUnlockStartPaused === "function") {
              try { window.__singularityUnlockStartPaused(); } catch (_) {}
            }
            try { player.focus({ preventScroll: true }); } catch (_) {}
            if (video.paused) {
              if (typeof player.playVideo === "function") { try { player.playVideo(); } catch (_) {} }
              if (video.paused) { try { const p = video.play(); if (p && p.catch) p.catch(function(){}); } catch (_) {} }
            } else {
              if (typeof player.pauseVideo === "function") { try { player.pauseVideo(); } catch (_) {} }
              if (!video.paused) { try { video.pause(); } catch (_) {} }
            }
          }
        }
      }
    }
  }, true);

  if (window.top !== window) return;

  let lastFsState = null;
  function reportFullscreen() {
    try {
      const fs = !!(document.fullscreenElement || document.webkitFullscreenElement);
      if (fs !== lastFsState) {
        lastFsState = fs;
        postIpc(JSON.stringify({ k: "fullscreen", fs: fs }));
      }
    } catch (_) {}
  }
  document.addEventListener("fullscreenchange", reportFullscreen, true);
  document.addEventListener("webkitfullscreenchange", reportFullscreen, true);

  let lastFaviconSent = "";
  function reportFavicon() {
    try {
      const sel = "link[rel='icon'][sizes*='32'], link[rel='icon'][sizes*='64'], link[rel~='icon'], link[rel='shortcut icon'], link[rel='apple-touch-icon']";
      const el = document.querySelector(sel);
      let href = el && el.href ? String(el.href) : "";
      if (!/^https?:\/\//i.test(href)) {
        if (/^https?:\/\//i.test(location.origin)) {
          href = location.origin + "/favicon.ico";
        } else {
          return;
        }
      }
      if (href !== lastFaviconSent && href.length <= 512) {
        lastFaviconSent = href;
        postIpc(JSON.stringify({ k: "favicon", u: href }));
      }
    } catch (_) {}
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", reportFavicon, { once: true });
  } else {
    reportFavicon();
  }
  window.addEventListener("load", function() { setTimeout(reportFavicon, 250); }, { once: true });

  let lastSentSec = -1;
  let lastSentScroll = -1;
  let lastSentUrl = "";
  function isAdPlaying() {
    return !!document.querySelector(".html5-video-player.ad-showing, .html5-video-player.ad-interrupting");
  }
  function findPrimaryMedia() {
    const vids = document.querySelectorAll("video, audio");
    if (vids.length === 0) return null;
    if (vids.length === 1) {
      const m = vids[0];
      return (m && isFinite(m.duration) && m.duration >= 15 && isFinite(m.currentTime) && m.currentTime >= 1) ? m : null;
    }
    let best = null;
    let bestScore = -1;
    for (let i = 0; i < vids.length; i++) {
      const m = vids[i];
      if (!m || !isFinite(m.duration) || m.duration < 15) continue;
      if (!isFinite(m.currentTime) || m.currentTime < 1) continue;
      const area = (m.videoWidth || 320) * (m.videoHeight || 180);
      const score = (m.paused ? 0 : 1e9) + area + m.duration;
      if (score > bestScore) {
        bestScore = score;
        best = m;
      }
    }
    return best;
  }
  function reportMediaProgress(force) {
    if (window.__singularityStartPausedLock) return;
    if (!force && document.hidden) return;
    const href = String(location.href || "");
    if (!/^https?:\/\//i.test(href)) return;
    let sec = 0;
    if (!isAdPlaying()) {
      const m = findPrimaryMedia();
      if (m) sec = Math.floor(m.currentTime);
    }
    const sy = Math.max(0, Math.floor(window.scrollY || document.documentElement.scrollTop || 0));
    const urlChanged = href !== lastSentUrl;
    const secChanged = sec >= 2 && (force || urlChanged || Math.abs(sec - lastSentSec) >= 4);
    const scrollChanged = sy >= 80 && (force || Math.abs(sy - lastSentScroll) >= 280);
    if (!secChanged && !scrollChanged) return;
    lastSentUrl = href;
    if (sec >= 2) lastSentSec = sec;
    lastSentScroll = sy;
    try {
      postIpc(JSON.stringify({ k: "media_state", s: sec, sy: sy }));
    } catch (_) {}
  }
  setInterval(function() { reportMediaProgress(false); }, 6000);
  document.addEventListener("pause", function() { reportMediaProgress(true); }, true);
  document.addEventListener("seeked", function() { reportMediaProgress(true); }, true);
  document.addEventListener("visibilitychange", function() {
    if (document.visibilityState === "hidden") reportMediaProgress(true);
  }, true);
  window.addEventListener("pagehide", function() { reportMediaProgress(true); }, true);
})();"##;

    const TOGGLE_ACTIVE_MEDIA_SCRIPT: &str = r##"(function(){
  try {
    const ae = document.activeElement;
    const tag = ae && ae.tagName ? ae.tagName.toUpperCase() : "";
    if (ae && (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || ae.isContentEditable || (ae.closest && ae.closest("input,textarea,select,[contenteditable='true'],[contenteditable=''],[role='textbox']")))) return;
    if (typeof window.__singularityUnlockStartPaused === "function") {
      try { window.__singularityUnlockStartPaused(); } catch (_) {}
    }
    const player = document.getElementById("movie_player") || document.querySelector(".html5-video-player");
    const video = (player && player.querySelector("video")) || document.querySelector("video");
    if (!video || !isFinite(video.duration) || video.duration <= 0) return;
    if (player) { try { player.focus({ preventScroll: true }); } catch (_) {} }
    if (video.paused) {
      if (player && typeof player.playVideo === "function") { try { player.playVideo(); } catch (_) {} }
      if (video.paused) { try { const p = video.play(); if (p && p.catch) p.catch(function(){}); } catch (_) {} }
    } else {
      if (player && typeof player.pauseVideo === "function") { try { player.pauseVideo(); } catch (_) {} }
      if (!video.paused) { try { video.pause(); } catch (_) {} }
    }
  } catch (_) {}
})();"##;

    fn build_resume_init_script(
        target_url: &str,
        resume_time_sec: Option<u64>,
        resume_scroll_y: Option<u32>,
        start_paused: bool,
    ) -> Option<String> {
        let target_sec = resume_time_sec.unwrap_or(0).min(864_000);
        let target_scroll = resume_scroll_y.unwrap_or(0).min(10_000_000);
        if !start_paused && target_sec < 3 && target_scroll < 40 {
            return None;
        }
        let expected_norm = normalize_url_without_media_time(target_url);
        let expected_json = serde_json::to_string(&expected_norm).ok()?;
        let mut rnd = [0u8; 8];
        OsRng.fill_bytes(&mut rnd);
        let nonce_key = format!("__singularity_resumed_{}", hex::encode(rnd));
        let nonce_json = serde_json::to_string(&nonce_key).ok()?;
        let start_paused_js = if start_paused { "true" } else { "false" };
        Some(format!(
            r##"(function(){{
  if (window.top !== window) return;
  const expectedNorm = {expected_json};
  const nonceKey = {nonce_json};
  const targetSec = {target_sec};
  const targetScroll = {target_scroll};
  const startPaused = {start_paused_js};
  function normUrl(raw) {{
    try {{
      const u = new URL(raw);
      u.searchParams.delete("t");
      u.searchParams.delete("time_continue");
      u.searchParams.delete("start");
      u.hash = "";
      return u.toString();
    }} catch (_) {{ return String(raw || ""); }}
  }}
  function matchesTargetPage() {{
    const cur = String(location.href || "");
    if (!cur || !expectedNorm) return false;
    if (normUrl(cur) === expectedNorm) return true;
    try {{
      const a = new URL(expectedNorm);
      const b = new URL(cur);
      if (a.origin !== b.origin || a.pathname !== b.pathname) return false;
      const av = a.searchParams.get("v");
      if (av !== null) return av === b.searchParams.get("v");
      return true;
    }} catch (_) {{ return false; }}
  }}
  if (!matchesTargetPage()) return;
  try {{
    if (window.sessionStorage && sessionStorage.getItem(nonceKey) === "1") return;
    if (window.sessionStorage) sessionStorage.setItem(nonceKey, "1");
  }} catch (_) {{}}
  let mediaDone = targetSec < 3;
  let scrollDone = targetScroll < 40;
  let userPlayIntent = !startPaused;
  let origMediaPlay = null;
  let attempts = 0;

  function restoreOrigPlay() {{
    if (origMediaPlay && typeof HTMLMediaElement !== "undefined" && HTMLMediaElement.prototype) {{
      try {{ HTMLMediaElement.prototype.play = origMediaPlay; }} catch (_) {{}}
      origMediaPlay = null;
    }}
  }}

  function isAdShowing() {{
    return !!document.querySelector(".html5-video-player.ad-showing, .html5-video-player.ad-interrupting");
  }}

  function tryApplyMedia() {{
    if (mediaDone) return;
    if (!matchesTargetPage()) {{ mediaDone = true; return; }}
    if (isAdShowing()) return;
    const list = document.querySelectorAll("video, audio");
    for (let i = 0; i < list.length; i++) {{
      const m = list[i];
      if (!m || !isFinite(m.duration) || m.duration < 15) continue;
      if (targetSec < m.duration - 2) {{
        if (Math.abs(m.currentTime - targetSec) > 2) {{
          try {{ m.currentTime = targetSec; }} catch (_) {{}}
        }}
        mediaDone = true;
        return;
      }}
    }}
  }}

  function tryApplyScroll() {{
    if (scrollDone) return;
    if (!matchesTargetPage()) {{ scrollDone = true; return; }}
    if (window.scrollY < 40 && document.documentElement.scrollHeight > targetScroll + 80) {{
      window.scrollTo(0, targetScroll);
      scrollDone = true;
    }}
  }}

  function pauseAllMediaAndYt() {{
    if (userPlayIntent) return;
    if (!matchesTargetPage()) {{ unlockStartPaused(); return; }}
    const yp = document.getElementById("movie_player") || document.querySelector(".html5-video-player");
    if (yp && typeof yp.pauseVideo === "function") {{
      try {{ yp.pauseVideo(); }} catch (_) {{}}
    }}
    const list = document.querySelectorAll("video, audio");
    for (let i = 0; i < list.length; i++) {{
      const m = list[i];
      if (m && !m.paused) {{
        try {{ m.pause(); }} catch (_) {{}}
      }}
    }}
    tryApplyMedia();
  }}

  function onMediaPlayEvent(e) {{
    if (userPlayIntent) return;
    if (!matchesTargetPage()) {{ unlockStartPaused(); return; }}
    const m = e && e.target;
    if (m && typeof m.pause === "function") {{
      try {{ m.pause(); }} catch (_) {{}}
    }}
    pauseAllMediaAndYt();
  }}

  function onUserKeyUnlock(e) {{
    if (userPlayIntent || !e || e.isTrusted === false) return;
    const k = String(e.key || "").toLowerCase();
    const code = String(e.code || "");
    if (code === "Space" || e.key === " " || k === "k" || e.key === "Enter" || e.key === "MediaPlayPause" || e.key === "MediaPlay") {{
      unlockStartPaused();
    }}
  }}

  function onUserPointerUnlock(e) {{
    if (userPlayIntent || !e || e.isTrusted === false) return;
    if (!matchesTargetPage()) {{ unlockStartPaused(); return; }}
    const tgt = e.target;
    if (!tgt || !tgt.closest) return;
    const anchor = tgt.closest("a[href]");
    if (anchor && anchor.href && normUrl(anchor.href) !== expectedNorm) {{
      unlockStartPaused();
      return;
    }}
    if (tgt.closest("video,audio,#movie_player,.html5-video-player,button,[role='button'],[class*='player'],[id*='player'],[class*='play'],[id*='play'],[aria-label*='Play' i],[aria-label*='Lire' i],[aria-label*='Lecture' i]")) {{
      unlockStartPaused();
    }}
  }}

  function unlockStartPaused() {{
    if (userPlayIntent) return;
    userPlayIntent = true;
    window.__singularityStartPausedLock = false;
    restoreOrigPlay();
    document.removeEventListener("play", onMediaPlayEvent, true);
    document.removeEventListener("playing", onMediaPlayEvent, true);
    window.removeEventListener("keydown", onUserKeyUnlock, true);
    window.removeEventListener("pointerdown", onUserPointerUnlock, true);
    window.removeEventListener("mousedown", onUserPointerUnlock, true);
    window.removeEventListener("touchstart", onUserPointerUnlock, true);
    window.removeEventListener("click", onUserPointerUnlock, true);
    if (!mediaDone) tryApplyMedia();
  }}

  if (startPaused) {{
    window.__singularityStartPausedLock = true;
    window.__singularityUnlockStartPaused = unlockStartPaused;
    if (typeof HTMLMediaElement !== "undefined" && HTMLMediaElement.prototype && typeof HTMLMediaElement.prototype.play === "function") {{
      origMediaPlay = HTMLMediaElement.prototype.play;
      HTMLMediaElement.prototype.play = function() {{
        if (!userPlayIntent && matchesTargetPage()) {{
          try {{ this.pause(); }} catch (_) {{}}
          setTimeout(pauseAllMediaAndYt, 0);
          return Promise.reject(new DOMException("Singularity restored tab starts paused until user plays", "NotAllowedError"));
        }}
        return origMediaPlay.apply(this, arguments);
      }};
    }}
    document.addEventListener("play", onMediaPlayEvent, true);
    document.addEventListener("playing", onMediaPlayEvent, true);
    window.addEventListener("keydown", onUserKeyUnlock, true);
    window.addEventListener("pointerdown", onUserPointerUnlock, true);
    window.addEventListener("mousedown", onUserPointerUnlock, true);
    window.addEventListener("touchstart", onUserPointerUnlock, true);
    window.addEventListener("click", onUserPointerUnlock, true);
  }}

  document.addEventListener("loadedmetadata", function() {{ tryApplyMedia(); if (startPaused && !userPlayIntent) pauseAllMediaAndYt(); }}, true);
  document.addEventListener("loadeddata", function() {{ tryApplyMedia(); if (startPaused && !userPlayIntent) pauseAllMediaAndYt(); }}, true);
  document.addEventListener("canplay", function() {{ tryApplyMedia(); if (startPaused && !userPlayIntent) pauseAllMediaAndYt(); }}, true);
  document.addEventListener("playing", tryApplyMedia, true);
  window.addEventListener("load", function() {{
    tryApplyMedia();
    if (startPaused && !userPlayIntent) pauseAllMediaAndYt();
    setTimeout(tryApplyScroll, 350);
  }}, {{ once: true }});
  const timer = setInterval(function() {{
    attempts++;
    tryApplyMedia();
    tryApplyScroll();
    if (startPaused && !userPlayIntent) pauseAllMediaAndYt();
    if ((mediaDone && scrollDone && (!startPaused || userPlayIntent)) || attempts >= 30) {{
      clearInterval(timer);
    }}
  }}, 500);
}})();"##
        ))
    }

    enable_win32_dark_menus();

    let event_loop = EventLoopBuilder::<WinEvent>::with_user_event().build();
    let proxy = event_loop.create_proxy();

    let adopt_proxy = proxy.clone();
    server_cfg.set_adopt_tab_handler(move |payload| {
        let _ = adopt_proxy.send_event(WinEvent::AdoptExternalTab(payload));
    });

    // 1. Initialize ONE single Pure Chromium (CEF) runtime shared across ALL windows & tabs!
    let (cef_profile_dir, extensions_dir, root_dir, primary_session_id, primary_session, pending_restore_ids, startup_pos) = {
        let mut shell = shared_shell.lock().unwrap_or_else(|e| e.into_inner());
        let detach_pos = shell
            .roaming
            .startup_handoff
            .as_ref()
            .and_then(|h| match (h.pos_x, h.pos_y) {
                (Some(x), Some(y)) => Some((x, y)),
                _ => None,
            });
        let p_sess = WindowTabSession {
            saved_tabs: shell.roaming.profile.saved_tabs.clone(),
            saved_tab_groups: shell.roaming.profile.saved_tab_groups.clone(),
            active_tab_index: shell.roaming.profile.active_tab_index,
            geometry: shell.roaming.window_geometry,
            is_detached_handoff: shell.roaming.startup_handoff.is_some(),
            is_secondary_live_window: shell.roaming.is_secondary_live_window,
            restored_windows_count: shell.roaming.restored_windows_count,
        };
        let restore_ids = std::mem::take(&mut shell.roaming.pending_restore_window_ids);
        (
            shell.roaming.chromium_profile_dir(),
            shell.roaming.extensions_dir(),
            shell.roaming.root_dir().to_path_buf(),
            shell.roaming.window_id().to_string(),
            p_sess,
            restore_ids,
            detach_pos,
        )
    };
    let (cef_profile_dir, cef_log_override, cef_verbose) = if let Some(ref sm) = smoke_opt {
        (sm.profile_dir.clone(), Some(sm.cef_log_path.clone()), true)
    } else {
        (
            cef_profile_dir,
            None,
            std::env::var_os("SINGULARITY_CEF_VERBOSE").is_some(),
        )
    };
    let _ = std::fs::create_dir_all(&cef_profile_dir);
    let _ = std::fs::create_dir_all(&extensions_dir);

    struct SmokeTracker {
        opts: CefSmokeTestOptions,
        started_at: std::time::Instant,
        context_initialized: bool,
        browser_created: bool,
        ui_http_status: Option<i32>,
        ui_ready: bool,
        probe_ok: bool,
        probe_summary: String,
        codecs_summary: String,
        pixel_fail_reasons: Vec<String>,
        close_requested_count: usize,
        smoke_tab_created: bool,
        smoke_tab_closed: bool,
        fatal_error: Option<String>,
        finished: bool,
    }
    impl SmokeTracker {
        fn new(opts: CefSmokeTestOptions) -> Self {
            if let Some(p) = opts.log_path.parent() {
                let _ = std::fs::create_dir_all(p);
            }
            let _ = std::fs::write(&opts.log_path, "");
            Self {
                opts,
                started_at: std::time::Instant::now(),
                context_initialized: false,
                browser_created: false,
                ui_http_status: None,
                ui_ready: false,
                probe_ok: false,
                probe_summary: String::new(),
                codecs_summary: String::new(),
                pixel_fail_reasons: Vec::new(),
                close_requested_count: 0,
                smoke_tab_created: false,
                smoke_tab_closed: false,
                fatal_error: None,
                finished: false,
            }
        }
        fn log(&self, msg: &str) {
            let line = format!("[SMOKE +{:>5}ms] {}\n", self.started_at.elapsed().as_millis(), msg);
            eprint!("{}", line);
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.opts.log_path)
            {
                let _ = f.write_all(line.as_bytes());
                let _ = f.flush();
            }
        }
    }

    let mut smoke_tracker = smoke_opt.clone().map(SmokeTracker::new);
    if let Some(ref sm) = smoke_tracker {
        sm.log(&format!(
            "Starting Singularity v{} CEF smoke test (bind_port={}, profile={}, cef_log={})",
            env!("CARGO_PKG_VERSION"),
            bind_port,
            cef_profile_dir.display(),
            sm.opts.cef_log_path.display()
        ));
    }

    // Capture previous session's `cef.log` tail BEFORE `CefRuntimeGuard::initialize()` opens and
    // truncates `cef.log`, so any real crash report preserves the dead session's actual error lines!
    let prev_cef_log_tail = if smoke_opt.is_none() {
        crate::crash_guard::read_cef_log_tail(&root_dir, 40)
    } else {
        String::new()
    };

    let pump_proxy = proxy.clone();
    let relaunch_proxy = proxy.clone();
    let cef_guard_res = CefRuntimeGuard::initialize(
        &cef_profile_dir,
        &extensions_dir,
        cef_log_override.as_deref(),
        cef_verbose,
        Arc::new(move |delay_ms| {
            let _ = pump_proxy.send_event(WinEvent::CefPump(delay_ms));
        }),
        Arc::new(move || {
            let _ = relaunch_proxy.send_event(WinEvent::OpenNewWindowInProcess);
        }),
    );
    let cef_guard = match cef_guard_res {
        Ok(g) => g,
        Err(e) => {
            if let Some(ref sm) = smoke_tracker {
                sm.log(&format!("FAIL: CefRuntimeGuard::initialize failed: {}", e));
            }
            if smoke_opt.is_none() {
                // If another Singularity instance already owns the CEF profile, CEF forwarded our
                // relaunch via `on_already_running_app_relaunch` (opening a new window in-process).
                let has_other_live = shared_shell
                    .lock()
                    .map(|s| !s.roaming.list_other_live_windows().is_empty())
                    .unwrap_or(false);
                if has_other_live {
                    return Ok(());
                }
            }
            return Err(e);
        }
    };

    // Detect any previous crash (panic, Win32 SEH, or stale dead-PID lock) and arm `running.lock`
    // ONLY after acquiring ownership of the single Chromium profile so relaunches never clobber it.
    let mut pending_crash_report: Option<crate::crash_guard::CrashReport> = if smoke_opt.is_none() {
        crate::crash_guard::detect_previous_crash_and_mark_running_with_cef_log(
            &root_dir,
            &prev_cef_log_tail,
        )
    } else {
        // Also arm `running.lock` inside the isolated smoke profile so CI verifies clean removal!
        let _ = crate::crash_guard::detect_previous_crash_and_mark_running(&cef_profile_dir);
        None
    };

    let ctx_ready = cef_guard.wait_for_context_initialized(Duration::from_secs(5));
    if let Some(ref mut sm) = smoke_tracker {
        sm.context_initialized = ctx_ready;
        sm.log(&format!(
            "CEF initialized (log={}), on_context_initialized={}",
            cef_guard.log_path().display(),
            ctx_ready
        ));
    }

    // Synchronously warm Chromium's persistent SQLite CookieStore AND hydrate any missing encrypted
    // Roaming auth cookies BEFORE initial restored tabs navigate — preventing the "appeared logged
    // out until manual F5 refresh" startup race!
    if smoke_opt.is_none() {
        let _hydrated = cef_runtime::hydrate_cookies_from_roaming_cef_sync(
            &shared_shell,
            Duration::from_millis(1500),
        );
    }

    let download_resolver: CefDownloadResolver = Arc::new(|suggested: &str, uri: &str| {
        let dir = resolve_user_downloads_dir();
        choose_unique_download_path(&dir, suggested, uri)
    });

    let mut incognito_ctx: Option<cef::RequestContext> = None;

    #[allow(clippy::too_many_arguments)]
    fn create_browser_window(
        elwt: &EventLoopWindowTarget<WinEvent>,
        bind_port: u16,
        server_cfg: &ServerConfig,
        shared_shell: &Arc<Mutex<SingularityBrowserShell>>,
        proxy: &EventLoopProxy<WinEvent>,
        download_resolver: &CefDownloadResolver,
        session_id: String,
        session: WindowTabSession,
        override_pos: Option<(i32, i32)>,
    ) -> Result<(WindowId, BrowserWindowState), String> {
        let saved_geom = session.geometry;
        if let Ok(mut map) = server_cfg.window_sessions.lock() {
            map.insert(session_id.clone(), session);
        }

        let effective_pos = override_pos.or_else(|| match (saved_geom.pos_x, saved_geom.pos_y) {
            (Some(x), Some(y)) if !saved_geom.maximized => Some((x, y)),
            _ => None,
        });
        let initial_size = if override_pos.is_none() {
            match (saved_geom.width, saved_geom.height) {
                (Some(w), Some(h)) if w >= 480 && h >= 360 => {
                    Size::Physical(TaoPhysicalSize::new(w.min(7680), h.min(4320)))
                }
                _ => Size::Logical(LogicalSize::new(1440.0, 880.0)),
            }
        } else {
            Size::Logical(LogicalSize::new(1440.0, 880.0))
        };

        let win_icon = Icon::from_rgba(WINDOW_ICON_64_RGBA.to_vec(), 64, 64).ok();
        let mut win_builder = WindowBuilder::new()
            .with_title("Singularity")
            .with_window_icon(win_icon)
            .with_visible(false)
            .with_decorations(false)
            .with_undecorated_shadow(true)
            .with_background_color((0, 0, 0, 255))
            .with_inner_size(initial_size)
            .with_min_inner_size(Size::Logical(LogicalSize::new(480.0, 360.0)));
        if let Some((px, py)) = effective_pos {
            win_builder = win_builder.with_position(TaoPhysicalPosition::new(
                px.max(-32000),
                py.max(-32000),
            ));
        }
        let window = win_builder
            .build(elwt)
            .map_err(|e| format!("Window creation error: {}", e))?;
        let win_id = window.id();
        enable_win32_immersive_dark_window(window.hwnd() as *mut core::ffi::c_void);

        if let (Some((px, py)), Some(mon)) = (effective_pos, window.current_monitor()) {
            let mpos = mon.position();
            let msize = mon.size();
            let wsize = window.outer_size();
            let max_x = (mpos.x + msize.width as i32 - 360).max(mpos.x);
            let max_y = (mpos.y + msize.height as i32 - 200).max(mpos.y);
            let cx = px.clamp(mpos.x - (wsize.width as i32 / 3), max_x);
            let cy = py.clamp(mpos.y, max_y);
            window.set_outer_position(TaoPhysicalPosition::new(cx, cy));
        }

        let phys = window.inner_size();
        let nonce = server_cfg.mint_bootstrap_nonce();
        let ui_url = format!(
            "http://127.0.0.1:{}/?boot={}&win={}",
            bind_port, nonce, session_id
        );
        let ui_proxy = proxy.clone();
        let ui_sink: CefEventSink = Arc::new(move |evt| {
            let _ = ui_proxy.send_event(WinEvent::CefCallback(win_id, evt));
        });
        let ui_browser = cef_runtime::spawn_cef_child_browser(
            window.hwnd(),
            0,
            0,
            phys.width.max(1),
            phys.height.max(1),
            &ui_url,
            true,
            false,
            0,
            bind_port,
            None,
            None,
            None,
            ui_sink,
            Arc::clone(shared_shell),
            Arc::clone(download_resolver),
        )?;

        window.set_visible(true);
        if override_pos.is_none() && saved_geom.maximized {
            window.set_maximized(true);
        }
        // CRITICAL: tao's set_visible() / set_maximized() rewrites GWL_STYLE without
        // WS_CLIPCHILDREN — restore WS_CLIPCHILDREN immediately so tao's WM_ERASEBKGND
        // never paints solid black over the child Chromium HWND!
        ensure_win32_clip_children(window.hwnd() as *mut core::ffi::c_void);
        let _ = ui_browser.set_visible(true);
        ui_browser.focus();

        // One-shot startup watchdog per window
        let wd_proxy = proxy.clone();
        let _ = std::thread::Builder::new()
            .name("singularity-ui-watchdog".into())
            .stack_size(128 * 1024)
            .spawn(move || {
                std::thread::sleep(Duration::from_secs(4));
                let _ = wd_proxy.send_event(WinEvent::UiStartupWatchdog(win_id));
            });

        let mut st = BrowserWindowState {
            session_id,
            window,
            ui_browser,
            tab_browsers: HashMap::new(),
            tab_last_urls: HashMap::new(),
            tab_nav_history: HashMap::new(),
            tab_media_times: HashMap::new(),
            tab_scroll_ys: HashMap::new(),
            tab_bg_intents: HashMap::new(),
            last_favicon_at: HashMap::new(),
            layout_cache: WebViewLayoutCache::default(),
            active_tab_id: 1,
            web_visible: false,
            overlay_open: false,
            html_fullscreen: false,
            user_f11_fullscreen: false,
            was_maximized_before_fs: false,
            last_maximized: None,
            ui_ready_received: false,
            ui_recovery_attempts: 0,
            was_minimized: false,
            ext_popup: None,
            last_ext_popup_closed: None,
            last_nav_at: None,
        };
        st.capture_geometry(server_cfg, shared_shell);
        st.sync_layout();
        cef_runtime::pump_cef_message_loop();
        Ok((win_id, st))
    }

    let mut windows: HashMap<WindowId, BrowserWindowState> = HashMap::new();

    // Create Primary Window #1 inside our single Chromium CEF process
    let (primary_win_id, primary_state) = create_browser_window(
        &event_loop,
        bind_port,
        server_cfg,
        &shared_shell,
        &proxy,
        &download_resolver,
        primary_session_id,
        primary_session,
        startup_pos,
    )?;
    if let Some(ref sm) = smoke_tracker {
        let p_hwnd = primary_state.window.hwnd() as *mut core::ffi::c_void;
        let ui_hwnd = primary_state.ui_browser.hwnd();
        let phys = primary_state.window.inner_size();
        sm.log(&format!(
            "Primary window created (inner={}x{}, parent_ws_clipchildren={}, ui_hwnd=0x{:x}, ui_visible={})",
            phys.width,
            phys.height,
            has_win32_clip_children(p_hwnd),
            ui_hwnd as usize,
            if ui_hwnd.is_null() { 0 } else { unsafe { IsWindowVisible(ui_hwnd) } }
        ));
    }
    if smoke_opt.is_none() {
        let shell = shared_shell.lock().unwrap_or_else(|e| e.into_inner());
        shell.roaming.register_live_window(
            bind_port,
            primary_state.window.hwnd(),
            &server_cfg.transfer_token,
        );
    }
    windows.insert(primary_win_id, primary_state);

    // Multi-window restart: open EVERY restored sibling window separately right inside this
    // SAME single low-RAM Chromium process (zero duplicate Chromium Browser/GPU/Network trees!)
    if smoke_opt.is_none() {
        for rid in pending_restore_ids {
            if let Some(rp) =
                crate::roaming_store::RoamingSingularityStore::consume_window_restore_handoff(
                    &root_dir, &rid,
                )
            {
                let sid = crate::roaming_store::RoamingSingularityStore::new_window_session_id();
                let sess = WindowTabSession {
                    saved_tabs: rp.tabs,
                    saved_tab_groups: rp.tab_groups,
                    active_tab_index: rp.active_tab_index,
                    geometry: rp.geometry,
                    is_detached_handoff: false,
                    is_secondary_live_window: true,
                    restored_windows_count: 1,
                };
                if let Ok((swid, sst)) = create_browser_window(
                    &event_loop,
                    bind_port,
                    server_cfg,
                    &shared_shell,
                    &proxy,
                    &download_resolver,
                    sid,
                    sess,
                    None,
                ) {
                    windows.insert(swid, sst);
                }
            }
        }
    }

    if let Some(ref sm_opts) = smoke_opt {
        let timeout_proxy = proxy.clone();
        let secs = sm_opts.timeout_secs.max(5);
        let _ = std::thread::Builder::new()
            .name("singularity-smoke-timeout".into())
            .stack_size(128 * 1024)
            .spawn(move || {
                std::thread::sleep(Duration::from_secs(secs));
                let _ = timeout_proxy.send_event(WinEvent::SmokeTimeout);
            });
    }

    let cfg_clone = server_cfg.clone();
    let mut cef_guard = Some(cef_guard);
    let mut next_cef_pump: std::time::Instant =
        std::time::Instant::now() + Duration::from_millis(8);
    let mut last_media_disk_flush = std::time::Instant::now()
        .checked_sub(Duration::from_secs(10))
        .unwrap_or_else(std::time::Instant::now);
    let mut last_history_disk_flush = std::time::Instant::now();
    let mut history_dirty = false;
    let mut last_cookie_hygiene_at: Option<std::time::Instant> = None;
    let mut last_shortcut_at = std::time::Instant::now()
        .checked_sub(Duration::from_secs(1))
        .unwrap_or_else(std::time::Instant::now);

    let persist_window_on_close = |st: &BrowserWindowState,
                                   other_windows_alive: bool,
                                   cfg: &ServerConfig,
                                   shared: &Arc<Mutex<SingularityBrowserShell>>| {
        st.capture_geometry(cfg, shared);
        let sess_opt = cfg
            .window_sessions
            .lock()
            .ok()
            .and_then(|mut m| m.remove(&st.session_id));
        let mut shell = shared.lock().unwrap_or_else(|e| e.into_inner());
        if shell.private_browsing_active || !shell.roaming.profile.restore_session {
            return;
        }
        if let Some(mut sess) = sess_opt {
            // Apply latest in-memory media timestamps & scroll offsets before writing close snapshot
            for (&tid, u) in &st.tab_last_urls {
                let t = st.tab_media_times.get(&tid).copied().unwrap_or(0);
                let sy = st.tab_scroll_ys.get(&tid).copied().unwrap_or(0);
                if t >= 2 || sy > 0 {
                    let norm_u = normalize_url_without_media_time(u);
                    for entry in &mut sess.saved_tabs {
                        if normalize_url_without_media_time(&entry.url) == norm_u {
                            if t >= 2 {
                                entry.media_time_sec = Some(t);
                            }
                            if sy > 0 {
                                entry.scroll_y = Some(sy);
                            }
                        }
                    }
                }
            }
            if sess.saved_tabs.is_empty() {
                shell.roaming.delete_window_session_for(&st.session_id);
            } else {
                let _ = shell.roaming.save_window_session_for(
                    &st.session_id,
                    &sess.saved_tabs,
                    &sess.saved_tab_groups,
                    sess.active_tab_index,
                    sess.geometry,
                    other_windows_alive,
                    true,
                );
                if shell.roaming.window_id() == st.session_id {
                    shell.roaming.profile.saved_tabs = sess.saved_tabs;
                    shell.roaming.profile.saved_tab_groups = sess.saved_tab_groups;
                    shell.roaming.profile.active_tab_index = sess.active_tab_index;
                    shell.roaming.window_geometry = sess.geometry;
                    let _ = shell.roaming.save_profile();
                }
            }
        }
    };

    let flush_live_crash_checkpoint = |wins: &HashMap<WindowId, BrowserWindowState>,
                                       cfg: &ServerConfig,
                                       shared: &Arc<Mutex<SingularityBrowserShell>>| {
        let mut live_files: Vec<crate::roaming_store::WindowSessionFile> = Vec::new();
        let pid = std::process::id();
        let now_ts = crate::roaming_store::unix_now();
        if let Ok(mut map) = cfg.window_sessions.lock() {
            for st in wins.values() {
                if let Some(sess) = map.get_mut(&st.session_id) {
                    for (&tid, u) in &st.tab_last_urls {
                        let t = st.tab_media_times.get(&tid).copied().unwrap_or(0);
                        let sy = st.tab_scroll_ys.get(&tid).copied().unwrap_or(0);
                        if t >= 2 || sy > 0 {
                            let norm_u = normalize_url_without_media_time(u);
                            for entry in &mut sess.saved_tabs {
                                if normalize_url_without_media_time(&entry.url) == norm_u {
                                    if t >= 2 {
                                        entry.media_time_sec = Some(t);
                                    }
                                    if sy > 0 {
                                        entry.scroll_y = Some(sy);
                                    }
                                }
                            }
                        }
                    }
                    if !sess.saved_tabs.is_empty() {
                        live_files.push(crate::roaming_store::WindowSessionFile {
                            window_id: st.session_id.clone(),
                            pid,
                            updated_unix: now_ts,
                            active_tab_index: sess.active_tab_index,
                            tabs: sess.saved_tabs.clone(),
                            tab_groups: sess.saved_tab_groups.clone(),
                            geometry: sess.geometry,
                            closed_while_other_live: false,
                        });
                    }
                }
            }
        }
        if !live_files.is_empty() {
            if let Ok(shell) = shared.lock() {
                if !shell.private_browsing_active && shell.roaming.profile.restore_session {
                    shell.roaming.save_crash_checkpoint(&live_files);
                }
            }
        }
    };

    if smoke_opt.is_none() {
        flush_live_crash_checkpoint(&windows, &cfg_clone, &shared_shell);
    }

    #[allow(clippy::too_many_arguments)]
    fn spawn_content_tab_cef(
        win_id: WindowId,
        st: &mut BrowserWindowState,
        tab_id: u64,
        url: &str,
        bind_port: u16,
        is_private: bool,
        incognito_ctx: &mut Option<cef::RequestContext>,
        resume_time_sec: Option<u64>,
        resume_scroll_y: Option<u32>,
        start_paused: bool,
        proxy: &EventLoopProxy<WinEvent>,
        shared_shell: &Arc<Mutex<SingularityBrowserShell>>,
        download_resolver: &CefDownloadResolver,
    ) {
        let phys = st.window.inner_size();
        let scale = st.window.scale_factor();
        let bar_h = ((APPLE_BAR_LOGICAL_HEIGHT * scale).round() as u32).min(phys.height.max(1));
        let effective_url = resume_time_sec
            .filter(|&t| t >= 3)
            .map(|t| apply_media_timestamp_to_url(url, t))
            .unwrap_or_else(|| url.to_string());
        let resume_script =
            build_resume_init_script(url, resume_time_sec, resume_scroll_y, start_paused);

        let req_ctx = if is_private {
            if incognito_ctx.is_none() {
                *incognito_ctx = cef_runtime::create_incognito_request_context();
            }
            incognito_ctx.clone()
        } else {
            None
        };

        let tab_proxy = proxy.clone();
        let sink: CefEventSink = Arc::new(move |evt| {
            let _ = tab_proxy.send_event(WinEvent::CefCallback(win_id, evt));
        });

        if let Ok(browser_handle) = cef_runtime::spawn_cef_child_browser(
            st.window.hwnd(),
            0,
            bar_h as i32,
            phys.width.max(1),
            phys.height.saturating_sub(bar_h).max(1),
            &effective_url,
            false,
            false,
            tab_id,
            bind_port,
            Some(CONTENT_LINK_INTENT_SCRIPT),
            resume_script.as_deref(),
            req_ctx,
            sink,
            Arc::clone(shared_shell),
            Arc::clone(download_resolver),
        ) {
            st.tab_browsers.insert(tab_id, browser_handle);
        }
    }

    fn emit_tab_nav_state(st: &BrowserWindowState, tab_id: u64) {
        let cef_back = st
            .tab_browsers
            .get(&tab_id)
            .map(|b| st.web_visible && b.can_go_back())
            .unwrap_or(false);
        let cef_fwd = st
            .tab_browsers
            .get(&tab_id)
            .map(|b| st.web_visible && b.can_go_forward())
            .unwrap_or(false);
        let (can_back, can_fwd) = st
            .tab_nav_history
            .get(&tab_id)
            .map(|h| (h.can_go_back() || cef_back, h.can_go_forward() || cef_fwd))
            .unwrap_or((cef_back, cef_fwd));
        emit_ui_sync(
            &st.ui_browser,
            &serde_json::json!({
                "tab_id": tab_id,
                "can_go_back": can_back,
                "can_go_forward": can_fwd
            }),
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn perform_tab_go_back(
        win_id: WindowId,
        st: &mut BrowserWindowState,
        bind_port: u16,
        is_private: bool,
        incognito_ctx: &mut Option<cef::RequestContext>,
        proxy: &EventLoopProxy<WinEvent>,
        shared_shell: &Arc<Mutex<SingularityBrowserShell>>,
        download_resolver: &CefDownloadResolver,
    ) {
        let now = std::time::Instant::now();
        if st
            .last_nav_at
            .map(|t| now.duration_since(t) < Duration::from_millis(120))
            .unwrap_or(false)
        {
            return;
        }
        st.last_nav_at = Some(now);
        st.close_ext_popup();

        let tid = st.active_tab_id;
        if st.web_visible {
            if let Some(b) = st.tab_browsers.get(&tid) {
                if b.go_back() {
                    if let Some(nav) = st.tab_nav_history.get_mut(&tid) {
                        nav.pending_traversal_at = Some(now);
                        if nav.index > 0 {
                            nav.index -= 1;
                        }
                    }
                    emit_tab_nav_state(st, tid);
                    return;
                }
            }
        }

        // Fallback via per-tab URL history stack (handles returning to New Tab, RAM-unloaded
        // tabs whose Chromium NavigationController reset, and restored sessions).
        let target_opt = st.tab_nav_history.get_mut(&tid).and_then(|nav| {
            if nav.index > 0 {
                nav.index -= 1;
                nav.pending_traversal_at = Some(now);
                nav.entries.get(nav.index).cloned()
            } else {
                None
            }
        });

        if let Some(target_url) = target_opt {
            if target_url.is_empty() {
                // Smoothly step back to the New Tab page while preserving forward history!
                st.tab_browsers.remove(&tid);
                st.layout_cache.invalidate_tab(Some(tid));
                st.web_visible = false;
                st.sync_layout();
                let (can_back, can_fwd) = st
                    .tab_nav_history
                    .get(&tid)
                    .map(|h| (h.can_go_back(), h.can_go_forward()))
                    .unwrap_or((false, true));
                emit_ui_sync(
                    &st.ui_browser,
                    &serde_json::json!({
                        "tab_id": tid,
                        "nav_to_home": true,
                        "can_go_back": can_back,
                        "can_go_forward": can_fwd,
                        "ram_active_count": st.tab_browsers.len()
                    }),
                );
            } else if parse_http_url_authority(&target_url).is_ok() {
                st.web_visible = true;
                st.tab_last_urls.insert(tid, target_url.clone());
                if let Some(existing) = st.tab_browsers.get(&tid) {
                    existing.load_url(&target_url);
                } else {
                    spawn_content_tab_cef(
                        win_id,
                        st,
                        tid,
                        &target_url,
                        bind_port,
                        is_private,
                        incognito_ctx,
                        None,
                        None,
                        false,
                        proxy,
                        shared_shell,
                        download_resolver,
                    );
                }
                st.sync_layout();
                emit_ui_sync(
                    &st.ui_browser,
                    &serde_json::json!({
                        "tab_id": tid,
                        "url": target_url,
                        "nav_restore_web": true,
                        "ram_active_count": st.tab_browsers.len()
                    }),
                );
                emit_tab_nav_state(st, tid);
            }
            return;
        }

        // Last-resort SPA safety net for client-side hash/pushState history
        if st.web_visible {
            if let Some(b) = st.tab_browsers.get(&tid) {
                b.evaluate_script("if (window.history && window.history.length > 1) window.history.back();");
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn perform_tab_go_forward(
        win_id: WindowId,
        st: &mut BrowserWindowState,
        bind_port: u16,
        is_private: bool,
        incognito_ctx: &mut Option<cef::RequestContext>,
        proxy: &EventLoopProxy<WinEvent>,
        shared_shell: &Arc<Mutex<SingularityBrowserShell>>,
        download_resolver: &CefDownloadResolver,
    ) {
        let now = std::time::Instant::now();
        if st
            .last_nav_at
            .map(|t| now.duration_since(t) < Duration::from_millis(120))
            .unwrap_or(false)
        {
            return;
        }
        st.last_nav_at = Some(now);
        st.close_ext_popup();

        let tid = st.active_tab_id;
        if st.web_visible {
            if let Some(b) = st.tab_browsers.get(&tid) {
                if b.go_forward() {
                    if let Some(nav) = st.tab_nav_history.get_mut(&tid) {
                        nav.pending_traversal_at = Some(now);
                        if nav.index + 1 < nav.entries.len() {
                            nav.index += 1;
                        }
                    }
                    emit_tab_nav_state(st, tid);
                    return;
                }
            }
        }

        let target_opt = st.tab_nav_history.get_mut(&tid).and_then(|nav| {
            if nav.index + 1 < nav.entries.len() {
                nav.index += 1;
                nav.pending_traversal_at = Some(now);
                nav.entries.get(nav.index).cloned()
            } else {
                None
            }
        });

        if let Some(target_url) = target_opt {
            if !target_url.is_empty() && parse_http_url_authority(&target_url).is_ok() {
                st.web_visible = true;
                st.tab_last_urls.insert(tid, target_url.clone());
                if let Some(existing) = st.tab_browsers.get(&tid) {
                    existing.load_url(&target_url);
                } else {
                    spawn_content_tab_cef(
                        win_id,
                        st,
                        tid,
                        &target_url,
                        bind_port,
                        is_private,
                        incognito_ctx,
                        None,
                        None,
                        false,
                        proxy,
                        shared_shell,
                        download_resolver,
                    );
                }
                st.sync_layout();
                if !st.overlay_open {
                    if let Some(b) = st.tab_browsers.get(&tid) {
                        b.focus();
                    }
                }
                emit_ui_sync(
                    &st.ui_browser,
                    &serde_json::json!({
                        "tab_id": tid,
                        "url": target_url,
                        "nav_restore_web": true,
                        "ram_active_count": st.tab_browsers.len()
                    }),
                );
                emit_tab_nav_state(st, tid);
            }
            return;
        }

        if st.web_visible {
            if let Some(b) = st.tab_browsers.get(&tid) {
                b.evaluate_script("if (window.history && window.history.length > 1) window.history.forward();");
            }
        }
    }

    fn perform_tab_zoom(st: &BrowserWindowState, action: &str) {
        if !st.web_visible || st.overlay_open {
            return;
        }
        if let Some(b) = st.tab_browsers.get(&st.active_tab_id) {
            let pct = match action {
                "zoom_in" => b.zoom_step(0.5),
                "zoom_out" => b.zoom_step(-0.5),
                "zoom_reset" => b.zoom_reset(),
                _ => return,
            };
            emit_ui_sync(&st.ui_browser, &serde_json::json!({ "zoom_pct": pct }));
        }
    }

    let mut prev_xbtn1_down = false;
    let mut prev_xbtn2_down = false;

    event_loop.run(move |event, elwt, control_flow| {
        let fallback_pump_ms: u64 = if windows.values().all(|st| st.was_minimized) {
            100
        } else {
            16
        };
        let now_tick = std::time::Instant::now();
        let max_deadline = now_tick + Duration::from_millis(fallback_pump_ms);
        if next_cef_pump > max_deadline {
            next_cef_pump = max_deadline;
        }
        *control_flow = if cef_guard.is_some() {
            ControlFlow::WaitUntil(next_cef_pump)
        } else {
            ControlFlow::Exit
        };

        match event {
            Event::NewEvents(StartCause::ResumeTimeReached { .. }) => {
                cef_runtime::pump_cef_message_loop();
                next_cef_pump = std::time::Instant::now() + Duration::from_millis(fallback_pump_ms);
            }
            Event::MainEventsCleared => {
                let now = std::time::Instant::now();
                if now >= next_cef_pump {
                    cef_runtime::pump_cef_message_loop();
                    next_cef_pump =
                        std::time::Instant::now() + Duration::from_millis(fallback_pump_ms);

                    // Edge-triggered mouse side-button (XBUTTON1 = Back, XBUTTON2 = Forward)
                    // fallback when Singularity is foreground so mouse shortcuts also work over
                    // PDFs, loading pages, and sandboxed cross-origin iframes (debounced with DOM).
                    const VK_XBUTTON1: i32 = 0x05;
                    const VK_XBUTTON2: i32 = 0x06;
                    let x1_down = unsafe { ((GetAsyncKeyState(VK_XBUTTON1) as u16) & 0x8000) != 0 };
                    let x2_down = unsafe { ((GetAsyncKeyState(VK_XBUTTON2) as u16) & 0x8000) != 0 };
                    let x1_edge = x1_down && !prev_xbtn1_down;
                    let x2_edge = x2_down && !prev_xbtn2_down;
                    prev_xbtn1_down = x1_down;
                    prev_xbtn2_down = x2_down;
                    if x1_edge || x2_edge {
                        let fg = get_win32_foreground_hwnd();
                        if !fg.is_null() {
                            let fg_wid = windows
                                .iter()
                                .find(|(_, w)| {
                                    let wh = w.window.hwnd() as *mut core::ffi::c_void;
                                    wh == fg || is_win32_focus_inside_popup(wh)
                                })
                                .map(|(id, _)| *id);
                            if let Some(target_wid) = fg_wid {
                                if let Some(st) = windows.get_mut(&target_wid) {
                                    if !st.overlay_open {
                                        let is_private = shared_shell
                                            .lock()
                                            .map(|s| s.private_browsing_active)
                                            .unwrap_or(false);
                                        if x1_edge {
                                            perform_tab_go_back(
                                                target_wid,
                                                st,
                                                bind_port,
                                                is_private,
                                                &mut incognito_ctx,
                                                &proxy,
                                                &shared_shell,
                                                &download_resolver,
                                            );
                                        } else if x2_edge {
                                            perform_tab_go_forward(
                                                target_wid,
                                                st,
                                                bind_port,
                                                is_private,
                                                &mut incognito_ctx,
                                                &proxy,
                                                &shared_shell,
                                                &download_resolver,
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                *control_flow = if cef_guard.is_some() {
                    ControlFlow::WaitUntil(next_cef_pump)
                } else {
                    ControlFlow::Exit
                };
            }
            Event::WindowEvent {
                window_id,
                event:
                    WindowEvent::MouseInput {
                        state: ElementState::Pressed,
                        button: MouseButton::Other(xbtn),
                        ..
                    },
                ..
            } => {
                if let Some(st) = windows.get_mut(&window_id) {
                    if !st.overlay_open && (xbtn == 1 || xbtn == 2) {
                        let is_private = shared_shell
                            .lock()
                            .map(|s| s.private_browsing_active)
                            .unwrap_or(false);
                        if xbtn == 1 {
                            perform_tab_go_back(
                                window_id,
                                st,
                                bind_port,
                                is_private,
                                &mut incognito_ctx,
                                &proxy,
                                &shared_shell,
                                &download_resolver,
                            );
                        } else {
                            perform_tab_go_forward(
                                window_id,
                                st,
                                bind_port,
                                is_private,
                                &mut incognito_ctx,
                                &proxy,
                                &shared_shell,
                                &download_resolver,
                            );
                        }
                    }
                }
            }
            Event::WindowEvent {
                window_id,
                event: WindowEvent::CloseRequested,
                ..
            } => {
                if let Some(ref mut sm) = smoke_tracker {
                    if windows.contains_key(&window_id) {
                        sm.close_requested_count += 1;
                        sm.log(&format!(
                            "ERROR: Unexpected CloseRequested fired on primary window (count={})!",
                            sm.close_requested_count
                        ));
                    }
                }
                if let Some(mut st) = windows.remove(&window_id) {
                    st.close_ext_popup();
                    let others_alive = !windows.is_empty();
                    persist_window_on_close(&st, others_alive, &cfg_clone, &shared_shell);
                    st.close_cleanly();
                    if windows.is_empty() {
                        if history_dirty {
                            let shell = shared_shell.lock().unwrap_or_else(|e| e.into_inner());
                            let _ = shell.roaming.save_profile();
                            history_dirty = false;
                        }
                        cef_runtime::run_cookie_hygiene_cef(&shared_shell, true, true, None);
                        for _ in 0..8 {
                            cef_runtime::pump_cef_message_loop();
                            std::thread::sleep(Duration::from_millis(8));
                        }
                        cef_runtime::flush_cookie_store_cef_sync(Duration::from_millis(800));
                        {
                            let shell = shared_shell.lock().unwrap_or_else(|e| e.into_inner());
                            shell.roaming.flush_async_persistence();
                            shell.roaming.unregister_live_window();
                        }
                        if smoke_tracker.is_none() {
                            crate::crash_guard::mark_clean_shutdown(&root_dir);
                        }
                        let _ = cef_runtime::drain_browsers_before_shutdown(
                            Duration::from_millis(1200),
                        );
                        drop(incognito_ctx.take());
                        drop(cef_guard.take());
                        *control_flow = ControlFlow::Exit;
                    }
                } else {
                    for st in windows.values_mut() {
                        if st
                            .ext_popup
                            .as_ref()
                            .map(|p| p.window_id == window_id)
                            .unwrap_or(false)
                        {
                            st.close_ext_popup();
                            break;
                        }
                    }
                }
            }
            Event::WindowEvent {
                window_id,
                event: WindowEvent::Focused(true),
                ..
            } => {
                if let Some(st) = windows.get_mut(&window_id) {
                    if let Some(ref p) = st.ext_popup {
                        let inside_popup =
                            is_win32_focus_inside_popup(p.window.hwnd() as *mut core::ffi::c_void);
                        if p.opened_at.elapsed() < Duration::from_millis(500) || inside_popup {
                            return;
                        }
                        if p.auto_dismiss {
                            st.close_ext_popup();
                        }
                    }
                    if st.web_visible
                        && !st.overlay_open
                        && !is_cursor_clicking_top_bar(&st.window)
                    {
                        if let Some(b) = st.tab_browsers.get(&st.active_tab_id) {
                            b.focus();
                        }
                    }
                }
            }
            Event::WindowEvent {
                window_id,
                event: WindowEvent::Focused(false),
                ..
            } => {
                if !windows.contains_key(&window_id) {
                    for st in windows.values_mut() {
                        let should_close = st
                            .ext_popup
                            .as_ref()
                            .map(|p| {
                                p.window_id == window_id
                                    && p.auto_dismiss
                                    && p.opened_at.elapsed() >= Duration::from_millis(500)
                                    && !is_win32_focus_inside_popup(
                                        p.window.hwnd() as *mut core::ffi::c_void,
                                    )
                            })
                            .unwrap_or(false);
                        if should_close {
                            st.close_ext_popup();
                            break;
                        }
                    }
                }
            }
            Event::WindowEvent {
                window_id,
                event: WindowEvent::Resized(new_size),
                ..
            } => {
                if let Some(st) = windows.get_mut(&window_id) {
                    if new_size.width == 0 || new_size.height == 0 {
                        st.was_minimized = true;
                        let _ = st.ui_browser.set_visible(false);
                        st.layout_cache.ui_visible = Some(false);
                        if let Some(b) = st.tab_browsers.get(&st.active_tab_id) {
                            let _ = b.set_visible(false);
                            st.layout_cache.tab_visible.insert(st.active_tab_id, false);
                        }
                        cef_runtime::trim_process_working_set();
                        return;
                    }
                    if st.was_minimized {
                        st.was_minimized = false;
                        st.layout_cache.invalidate_ui();
                        st.layout_cache.invalidate_tab(None);
                    }
                    st.capture_geometry(&cfg_clone, &shared_shell);
                    st.sync_layout();
                    st.sync_maximized(false);
                } else {
                    for st in windows.values() {
                        if let Some(ref p) = st.ext_popup {
                            if p.window_id == window_id {
                                let _ = p.browser.set_bounds(
                                    0,
                                    0,
                                    new_size.width.max(1),
                                    new_size.height.max(1),
                                );
                                break;
                            }
                        }
                    }
                }
            }
            Event::WindowEvent {
                window_id,
                event: WindowEvent::ScaleFactorChanged { .. },
                ..
            } => {
                if let Some(st) = windows.get_mut(&window_id) {
                    st.layout_cache.invalidate_ui();
                    st.layout_cache.invalidate_tab(None);
                    st.capture_geometry(&cfg_clone, &shared_shell);
                    st.sync_layout();
                    st.sync_maximized(false);
                }
            }
            Event::WindowEvent {
                window_id,
                event: WindowEvent::Moved(_),
                ..
            } => {
                if let Some(st) = windows.get_mut(&window_id) {
                    let should_close = st
                        .ext_popup
                        .as_ref()
                        .map(|p| {
                            p.auto_dismiss && p.opened_at.elapsed() >= Duration::from_millis(500)
                        })
                        .unwrap_or(false);
                    if should_close {
                        st.close_ext_popup();
                    }
                    st.capture_geometry(&cfg_clone, &shared_shell);
                    st.sync_maximized(false);
                }
            }
            Event::UserEvent(win_evt) => match win_evt {
                WinEvent::CefPump(delay_ms) => {
                    if delay_ms <= 0 {
                        cef_runtime::pump_cef_message_loop();
                        next_cef_pump =
                            std::time::Instant::now() + Duration::from_millis(fallback_pump_ms);
                        // Auto-dismiss an open extension popup cleanly if the user clicked directly
                        // back onto a main Singularity web tab (where child HWND activation may not
                        // resend WM_SETFOCUS to the top-level parent window).
                        let has_auto_popup = windows.values().any(|w| {
                            w.ext_popup
                                .as_ref()
                                .map(|p| {
                                    p.auto_dismiss
                                        && p.opened_at.elapsed() >= Duration::from_millis(500)
                                })
                                .unwrap_or(false)
                        });
                        if has_auto_popup {
                            let fg = get_win32_foreground_hwnd();
                            let fg_is_main_win = !fg.is_null()
                                && windows
                                    .values()
                                    .any(|w| (w.window.hwnd() as *mut core::ffi::c_void) == fg);
                            if fg_is_main_win {
                                for st in windows.values_mut() {
                                    let should_close = st
                                        .ext_popup
                                        .as_ref()
                                        .map(|p| {
                                            p.auto_dismiss
                                                && p.opened_at.elapsed()
                                                    >= Duration::from_millis(500)
                                                && !is_win32_focus_inside_popup(
                                                    p.window.hwnd() as *mut core::ffi::c_void,
                                                )
                                        })
                                        .unwrap_or(false);
                                    if should_close {
                                        st.close_ext_popup();
                                    }
                                }
                            }
                        }
                    } else {
                        let target = std::time::Instant::now()
                            + Duration::from_millis((delay_ms as u64).min(fallback_pump_ms));
                        if target < next_cef_pump {
                            next_cef_pump = target;
                        }
                    }
                }
                WinEvent::OpenNewWindowInProcess => {
                    let sid = crate::roaming_store::RoamingSingularityStore::new_window_session_id();
                    let sess = WindowTabSession {
                        is_secondary_live_window: true,
                        ..Default::default()
                    };
                    if let Ok((nwid, nst)) = create_browser_window(
                        elwt,
                        bind_port,
                        &cfg_clone,
                        &shared_shell,
                        &proxy,
                        &download_resolver,
                        sid,
                        sess,
                        None,
                    ) {
                        bring_win32_window_to_front(nst.window.hwnd());
                        windows.insert(nwid, nst);
                    }
                }
                WinEvent::AdoptExternalTab(handoff) => {
                    if let Some(st) = windows.values().next() {
                        bring_win32_window_to_front(st.window.hwnd());
                        emit_ui_sync(
                            &st.ui_browser,
                            &serde_json::json!({
                                "adopt_external_tab": {
                                    "url": handoff.url,
                                    "title": handoff.title,
                                    "favicon_url": handoff.favicon_url,
                                    "media_time_sec": handoff.media_time_sec,
                                    "scroll_y": handoff.scroll_y
                                }
                            }),
                        );
                    }
                }
                WinEvent::UiStartupWatchdog(wid) => {
                    if let Some(st) = windows.get_mut(&wid) {
                        if !st.ui_ready_received {
                            if let Some(ref sm) = smoke_tracker {
                                sm.log("UiStartupWatchdog fired (ui_ready not received yet) — reloading UI with fresh nonce");
                            }
                            let fresh_nonce = cfg_clone.mint_bootstrap_nonce();
                            let fresh_url = format!(
                                "http://127.0.0.1:{}/?boot={}&win={}",
                                bind_port, fresh_nonce, st.session_id
                            );
                            st.ui_browser.load_url(&fresh_url);
                            st.layout_cache.invalidate_ui();
                            st.sync_layout();
                            st.ui_browser.focus();
                        }
                    }
                }
                WinEvent::SmokeCheckPixels(wid) => {
                    if let Some(ref mut sm) = smoke_tracker {
                        if sm.finished {
                            return;
                        }
                        let mut fail_reasons: Vec<String> = Vec::new();
                        if !sm.context_initialized {
                            fail_reasons.push("on_context_initialized did not fire".to_string());
                        }
                        if sm.ui_http_status != Some(200) {
                            fail_reasons.push(format!(
                                "ui_browser HTTP status was {:?} (expected Some(200))",
                                sm.ui_http_status
                            ));
                        }
                        if !sm.ui_ready {
                            fail_reasons.push("ui_ready IPC never arrived".to_string());
                        }
                        if !sm.probe_ok {
                            fail_reasons.push(format!(
                                "DOM smoke_probe failed ({})",
                                sm.probe_summary
                            ));
                        }
                        if let Some(ref err) = sm.fatal_error {
                            fail_reasons.push(format!("fatal CEF error: {}", err));
                        }
                        if let Some(st) = windows.get(&wid) {
                            let p_hwnd = st.window.hwnd() as *mut core::ffi::c_void;
                            let ui_hwnd = st.ui_browser.hwnd();
                            let has_clip = has_win32_clip_children(p_hwnd);
                            let ui_vis = !ui_hwnd.is_null() && unsafe { IsWindowVisible(ui_hwnd) } != 0;
                            let mut ui_rc = WinRect {
                                left: 0,
                                top: 0,
                                right: 0,
                                bottom: 0,
                            };
                            let has_rc = !ui_hwnd.is_null()
                                && unsafe { GetWindowRect(ui_hwnd, &mut ui_rc) } != 0;
                            let rc_w = if has_rc { ui_rc.right - ui_rc.left } else { 0 };
                            let rc_h = if has_rc { ui_rc.bottom - ui_rc.top } else { 0 };
                            if !has_clip {
                                fail_reasons.push("parent HWND missing WS_CLIPCHILDREN".to_string());
                            }
                            if ui_hwnd.is_null() || !ui_vis || rc_w < 400 || rc_h < 300 {
                                fail_reasons.push(format!(
                                    "invalid child CEF HWND state (hwnd=0x{:x}, visible={}, rect={}x{})",
                                    ui_hwnd as usize, ui_vis, rc_w, rc_h
                                ));
                            }
                            let (mut pw_ok, mut cw, mut ch, mut bar_px, mut tot_px, mut max_luma) =
                                capture_window_non_black_pixels(p_hwnd);
                            if !pw_ok || tot_px == 0 {
                                let (u_ok, uw, uh, u_bar, u_tot, u_luma) =
                                    capture_window_non_black_pixels(ui_hwnd);
                                if u_ok && u_tot > tot_px {
                                    pw_ok = u_ok;
                                    cw = uw;
                                    ch = uh;
                                    bar_px = u_bar;
                                    tot_px = u_tot;
                                    max_luma = u_luma;
                                }
                            }
                            sm.log(&format!(
                                "Window & pixel check: ws_clipchildren={}, ui_hwnd=0x{:x}, ui_visible={}, ui_rect={}x{}, print_window_ok={}, cap={}x{}, bar_non_black={}, total_non_black={}, max_luma={}, codecs=[{}]",
                                has_clip,
                                ui_hwnd as usize,
                                ui_vis,
                                rc_w,
                                rc_h,
                                pw_ok,
                                cw,
                                ch,
                                bar_px,
                                tot_px,
                                max_luma,
                                sm.codecs_summary
                            ));
                            if pw_ok && tot_px < 50 {
                                fail_reasons.push(format!(
                                    "BLACK SCREEN DETECTED: PrintWindow succeeded ({}x{}) but total_non_black={} (max_luma={})",
                                    cw, ch, tot_px, max_luma
                                ));
                            }
                        } else {
                            fail_reasons.push("primary window missing during pixel check".to_string());
                        }
                        sm.pixel_fail_reasons = fail_reasons;

                        // Phase 2 of CEF smoke test: spawn a real child content tab (9999) and
                        // close ONLY that tab to prove `do_close() == 1` + `DestroyWindow(child)`
                        // NEVER triggers `WM_CLOSE` on the top-level parent `tao` window!
                        if let Some(st) = windows.get_mut(&wid) {
                            let smoke_tab_url = format!("http://127.0.0.1:{}/api/logo.png", bind_port);
                            sm.log("Phase 2: Spawning real content tab 9999 to verify closing 1 tab keeps parent window alive");
                            spawn_content_tab_cef(
                                wid,
                                st,
                                9999,
                                &smoke_tab_url,
                                bind_port,
                                false,
                                &mut incognito_ctx,
                                None,
                                None,
                                false,
                                &proxy,
                                &shared_shell,
                                &download_resolver,
                            );
                        } else {
                            let _ = proxy.send_event(WinEvent::SmokeFinalize(wid));
                        }
                    }
                }
                WinEvent::SmokeFinalize(wid) => {
                    if let Some(ref mut sm) = smoke_tracker {
                        if sm.finished {
                            return;
                        }
                        sm.finished = true;
                        let mut fail_reasons = std::mem::take(&mut sm.pixel_fail_reasons);
                        if !sm.smoke_tab_created || !sm.smoke_tab_closed {
                            fail_reasons.push(format!(
                                "smoke content tab lifecycle incomplete (created={}, closed={})",
                                sm.smoke_tab_created, sm.smoke_tab_closed
                            ));
                        }
                        if sm.close_requested_count > 0 {
                            fail_reasons.push(format!(
                                "CLOSING 1 TAB KILLED PARENT WINDOW: CloseRequested fired {} time(s)!",
                                sm.close_requested_count
                            ));
                        }
                        let parent_alive = windows
                            .get(&wid)
                            .map(|st| {
                                let p_hwnd = st.window.hwnd() as *mut core::ffi::c_void;
                                unsafe { IsWindow(p_hwnd) != 0 && IsWindowVisible(p_hwnd) != 0 }
                            })
                            .unwrap_or(false);
                        if !parent_alive {
                            fail_reasons.push(
                                "parent window disappeared or became invisible after closing single content tab"
                                    .to_string(),
                            );
                        }
                        sm.log(&format!(
                            "Tab-close resilience check: tab_created={}, tab_closed={}, close_requested_count={}, parent_still_alive={}",
                            sm.smoke_tab_created,
                            sm.smoke_tab_closed,
                            sm.close_requested_count,
                            parent_alive
                        ));

                        let exit_code = if fail_reasons.is_empty() {
                            sm.log("RESULT=PASS (Pure Chromium CEF UI rendered cleanly & single-tab close kept parent window alive!)");
                            0
                        } else {
                            sm.log(&format!("RESULT=FAIL: {}", fail_reasons.join(" | ")));
                            1
                        };
                        let drained_wins: Vec<BrowserWindowState> =
                            windows.drain().map(|(_, st)| st).collect();
                        for st in drained_wins {
                            st.close_cleanly();
                        }
                        let remaining_browsers = cef_runtime::drain_browsers_before_shutdown(
                            Duration::from_millis(1200),
                        );
                        sm.log(&format!(
                            "Phase 3 clean shutdown: open_browsers_after_drain={}",
                            remaining_browsers
                        ));
                        if exit_code == 0 {
                            crate::crash_guard::mark_clean_shutdown(&sm.opts.profile_dir);
                        }
                        drop(incognito_ctx.take());
                        drop(cef_guard.take());
                        std::process::exit(exit_code);
                    }
                }
                WinEvent::SmokeTimeout => {
                    if let Some(ref mut sm) = smoke_tracker {
                        if sm.finished {
                            return;
                        }
                        sm.finished = true;
                        sm.log(&format!(
                            "RESULT=FAIL: Timeout ({}s) — ctx_init={}, browser_created={}, http={:?}, ui_ready={}, probe_ok={}, tab_created={}, tab_closed={}, close_req={}, fatal={:?}",
                            sm.opts.timeout_secs,
                            sm.context_initialized,
                            sm.browser_created,
                            sm.ui_http_status,
                            sm.ui_ready,
                            sm.probe_ok,
                            sm.smoke_tab_created,
                            sm.smoke_tab_closed,
                            sm.close_requested_count,
                            sm.fatal_error
                        ));
                        windows.clear();
                        for _ in 0..4 {
                            cef_runtime::pump_cef_message_loop();
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        drop(incognito_ctx.take());
                        drop(cef_guard.take());
                        std::process::exit(1);
                    }
                }
                WinEvent::CookieHygieneDone {
                    win_id,
                    mode,
                    trackers,
                    ads,
                    malicious,
                    synced,
                } => {
                    if synced > 0 {
                        bump_state_revision();
                    }
                    if let Some(st) = windows.get(&win_id) {
                        if mode == "sync_tokens" {
                            emit_ui_sync(
                                &st.ui_browser,
                                &serde_json::json!({ "tokens_synced": synced }),
                            );
                        } else if mode == "trackers_only" {
                            emit_ui_sync(
                                &st.ui_browser,
                                &serde_json::json!({
                                    "browsing_cleared": true,
                                    "mode": "trackers_only",
                                    "trackers_removed": trackers,
                                    "ads_removed": ads,
                                    "malicious_removed": malicious
                                }),
                            );
                        } else if synced > 0 {
                            emit_ui_sync(
                                &st.ui_browser,
                                &serde_json::json!({ "tokens_synced": synced }),
                            );
                        }
                    }
                }
                WinEvent::LocalExtensionPicked { win_id, path } => {
                    if let Some(st) = windows.get(&win_id) {
                        bring_win32_window_to_front(st.window.hwnd());
                        emit_ui_sync(
                            &st.ui_browser,
                            &serde_json::json!({ "picked_local_ext_path": path }),
                        );
                    }
                }
                WinEvent::CefCallback(wid, cb_evt) => match cb_evt {
                    CefCallbackEvent::DestroyChildHwnd { hwnd } => {
                        destroy_cef_child_hwnd(hwnd);
                    }
                    CefCallbackEvent::BrowserCreated { tab_id, is_ui, hwnd } => {
                        if let Some(st) = windows.get_mut(&wid) {
                            if is_ui {
                                st.ui_browser.cache_hwnd(hwnd);
                                st.layout_cache.invalidate_ui();
                                if let Some(ref mut sm) = smoke_tracker {
                                    sm.browser_created = true;
                                    sm.log(&format!("BrowserCreated (ui_browser, hwnd=0x{:x})", hwnd as usize));
                                }
                            } else if tab_id == 0 {
                                if let Some(ref popup) = st.ext_popup {
                                    popup.browser.cache_hwnd(hwnd);
                                    ensure_win32_clip_children(
                                        popup.window.hwnd() as *mut core::ffi::c_void,
                                    );
                                    let psize = popup.window.inner_size();
                                    let _ = popup.browser.set_bounds(
                                        0,
                                        0,
                                        psize.width.max(1),
                                        psize.height.max(1),
                                    );
                                    let _ = popup.browser.set_visible(true);
                                }
                                return;
                            } else if let Some(b) = st.tab_browsers.get(&tab_id) {
                                b.cache_hwnd(hwnd);
                                st.layout_cache.invalidate_tab(Some(tab_id));
                                if tab_id == 9999 {
                                    if let Some(ref mut sm) = smoke_tracker {
                                        if !sm.smoke_tab_closed {
                                            sm.smoke_tab_created = true;
                                            sm.smoke_tab_closed = true;
                                            sm.log(&format!(
                                                "Smoke content tab 9999 created (hwnd=0x{:x}) — closing ONLY tab 9999 now",
                                                hwnd as usize
                                            ));
                                            if let Some(tab_handle) = st.tab_browsers.remove(&9999) {
                                                drop(tab_handle);
                                            }
                                            st.layout_cache.invalidate_tab(Some(9999));
                                            let fin_proxy = proxy.clone();
                                            let _ = std::thread::Builder::new()
                                                .name("singularity-smoke-finalize".into())
                                                .stack_size(128 * 1024)
                                                .spawn(move || {
                                                    std::thread::sleep(Duration::from_millis(550));
                                                    let _ = fin_proxy.send_event(WinEvent::SmokeFinalize(wid));
                                                });
                                            return;
                                        }
                                    }
                                }
                            }
                            st.sync_layout();
                        }
                    }
                    CefCallbackEvent::LoadError {
                        tab_id,
                        is_ui,
                        error_code,
                        error_text,
                        failed_url,
                    } => {
                        eprintln!(
                            "Singularity CEF LoadError (is_ui={}, tab={}, code={}, text={}, url={})",
                            is_ui, tab_id, error_code, error_text, failed_url
                        );
                        if let Some(ref mut sm) = smoke_tracker {
                            let msg = format!(
                                "LoadError(is_ui={}, code={}, text={}, url={})",
                                is_ui, error_code, error_text, failed_url
                            );
                            sm.log(&msg);
                            if is_ui && sm.fatal_error.is_none() {
                                sm.fatal_error = Some(msg);
                            }
                        }
                        if is_ui {
                            if let Some(st) = windows.get_mut(&wid) {
                                if !st.ui_ready_received && st.ui_recovery_attempts < 2 {
                                    st.ui_recovery_attempts += 1;
                                    let fresh_nonce = cfg_clone.mint_bootstrap_nonce();
                                    let fresh_url = format!(
                                        "http://127.0.0.1:{}/?boot={}&win={}",
                                        bind_port, fresh_nonce, st.session_id
                                    );
                                    st.ui_browser.load_url(&fresh_url);
                                    st.layout_cache.invalidate_ui();
                                    st.sync_layout();
                                }
                            }
                        }
                    }
                    CefCallbackEvent::RenderProcessTerminated {
                        tab_id,
                        is_ui,
                        status,
                        error_code,
                        error_string,
                    } => {
                        eprintln!(
                            "Singularity CEF RenderProcessTerminated (is_ui={}, tab={}, status={}, code={}, err={})",
                            is_ui, tab_id, status, error_code, error_string
                        );
                        if let Some(ref mut sm) = smoke_tracker {
                            let msg = format!(
                                "RenderProcessTerminated(is_ui={}, status={}, code={}, err={})",
                                is_ui, status, error_code, error_string
                            );
                            sm.log(&msg);
                            if is_ui && sm.fatal_error.is_none() {
                                sm.fatal_error = Some(msg);
                            }
                        } else {
                            let tab_url = windows
                                .get(&wid)
                                .and_then(|st| st.tab_last_urls.get(&tab_id).cloned())
                                .unwrap_or_default();
                            let kind = if is_ui {
                                "cef_ui_renderer_crash"
                            } else {
                                "cef_tab_renderer_crash"
                            };
                            let summary = format!(
                                "Chromium renderer terminated (is_ui={}, tab={}, status={}, code={})",
                                is_ui, tab_id, status, error_code
                            );
                            let details = format!(
                                "Component  : {}\nTab ID     : {}\nURL        : {}\nStatus     : {}\nError Code : {}\nError Text : {}",
                                if is_ui { "Browser UI Shell" } else { "Web Tab Renderer" },
                                tab_id,
                                if tab_url.is_empty() { "<none>" } else { &tab_url },
                                status,
                                error_code,
                                if error_string.is_empty() { "<none>" } else { &error_string }
                            );
                            let rep = crate::crash_guard::record_runtime_error_report(
                                &root_dir, kind, &summary, &details,
                            );
                            if is_ui {
                                pending_crash_report = Some(rep);
                            } else if let Some(st) = windows.get(&wid) {
                                emit_ui_sync(
                                    &st.ui_browser,
                                    &serde_json::json!({
                                        "crash_report": {
                                            "kind": rep.kind,
                                            "summary": rep.summary,
                                            "text": rep.format_copyable_text()
                                        }
                                    }),
                                );
                            }
                        }
                        if is_ui {
                            if let Some(st) = windows.get_mut(&wid) {
                                if st.ui_recovery_attempts < 2 {
                                    st.ui_recovery_attempts += 1;
                                    let fresh_nonce = cfg_clone.mint_bootstrap_nonce();
                                    let fresh_url = format!(
                                        "http://127.0.0.1:{}/?boot={}&win={}",
                                        bind_port, fresh_nonce, st.session_id
                                    );
                                    st.ui_browser.load_url(&fresh_url);
                                    st.layout_cache.invalidate_ui();
                                    st.sync_layout();
                                }
                            }
                        }
                    }
                    CefCallbackEvent::CloseExtensionPopup => {
                        if let Some(st) = windows.get_mut(&wid) {
                            st.close_ext_popup();
                        }
                    }
                    CefCallbackEvent::NavigationStateChanged {
                        tab_id,
                        can_go_back,
                        can_go_forward,
                    } => {
                        if tab_id == 0 {
                            return;
                        }
                        if let Some(st) = windows.get_mut(&wid) {
                            let nav = st
                                .tab_nav_history
                                .entry(tab_id)
                                .or_insert_with(TabNavHistory::new_with_home);
                            nav.cef_can_go_back = can_go_back;
                            nav.cef_can_go_forward = can_go_forward;
                            if tab_id == st.active_tab_id {
                                emit_tab_nav_state(st, tab_id);
                            }
                        }
                    }
                    CefCallbackEvent::NativeShortcut { tab_id, action } => {
                        if let Some(st) = windows.get_mut(&wid) {
                            if tab_id != 0 && tab_id != st.active_tab_id {
                                return;
                            }
                            if st.overlay_open {
                                return;
                            }
                            match action {
                                "web_back" => {
                                    let is_private = shared_shell
                                        .lock()
                                        .map(|s| s.private_browsing_active)
                                        .unwrap_or(false);
                                    perform_tab_go_back(
                                        wid,
                                        st,
                                        bind_port,
                                        is_private,
                                        &mut incognito_ctx,
                                        &proxy,
                                        &shared_shell,
                                        &download_resolver,
                                    );
                                }
                                "web_forward" => {
                                    let is_private = shared_shell
                                        .lock()
                                        .map(|s| s.private_browsing_active)
                                        .unwrap_or(false);
                                    perform_tab_go_forward(
                                        wid,
                                        st,
                                        bind_port,
                                        is_private,
                                        &mut incognito_ctx,
                                        &proxy,
                                        &shared_shell,
                                        &download_resolver,
                                    );
                                }
                                "zoom_in" | "zoom_out" | "zoom_reset" => {
                                    perform_tab_zoom(st, action);
                                }
                                _ => {}
                            }
                        }
                    }
                    CefCallbackEvent::PageStarted { tab_id, url } => {
                        if tab_id == 0 {
                            if let Some(ref sm) = smoke_tracker {
                                sm.log(&format!("UI PageStarted: {}", url));
                            }
                            return;
                        }
                        if let Some(st) = windows.get_mut(&wid) {
                            if st
                                .tab_last_urls
                                .get(&tab_id)
                                .map(|prev| {
                                    normalize_url_without_media_time(prev)
                                        != normalize_url_without_media_time(&url)
                                })
                                .unwrap_or(false)
                            {
                                st.tab_media_times.remove(&tab_id);
                                st.tab_scroll_ys.remove(&tab_id);
                            }
                            st.tab_last_urls.insert(tab_id, url.clone());
                            st.tab_nav_history
                                .entry(tab_id)
                                .or_insert_with(TabNavHistory::new_with_home)
                                .record_url(&url);
                            emit_ui_sync(
                                &st.ui_browser,
                                &serde_json::json!({ "tab_id": tab_id, "url": url }),
                            );
                            if tab_id == st.active_tab_id {
                                emit_tab_nav_state(st, tab_id);
                            }
                        }
                    }
                    CefCallbackEvent::AddressChanged { tab_id, url } => {
                        if let Some(st) = windows.get_mut(&wid) {
                            if tab_id == 0 {
                                return;
                            }
                            let changed = st
                                .tab_last_urls
                                .get(&tab_id)
                                .map(|p| p != &url)
                                .unwrap_or(true);
                            if changed {
                                if st
                                    .tab_last_urls
                                    .get(&tab_id)
                                    .map(|prev| {
                                        normalize_url_without_media_time(prev)
                                            != normalize_url_without_media_time(&url)
                                    })
                                    .unwrap_or(false)
                                {
                                    st.tab_media_times.remove(&tab_id);
                                    st.tab_scroll_ys.remove(&tab_id);
                                }
                                st.tab_last_urls.insert(tab_id, url.clone());
                                st.tab_nav_history
                                    .entry(tab_id)
                                    .or_insert_with(TabNavHistory::new_with_home)
                                    .record_url(&url);
                                emit_ui_sync(
                                    &st.ui_browser,
                                    &serde_json::json!({ "tab_id": tab_id, "url": url }),
                                );
                                if tab_id == st.active_tab_id {
                                    emit_tab_nav_state(st, tab_id);
                                }
                            }
                        }
                    }
                    CefCallbackEvent::PageFinished {
                        tab_id,
                        url,
                        http_status,
                    } => {
                        if tab_id == 0 {
                            if let Some(ref mut sm) = smoke_tracker {
                                sm.ui_http_status = Some(http_status);
                                sm.log(&format!(
                                    "UI PageFinished (http_status={}, url={})",
                                    http_status, url
                                ));
                            }
                            return;
                        }
                        if let Some(st) = windows.get_mut(&wid) {
                            let final_url = st
                                .tab_browsers
                                .get(&tab_id)
                                .and_then(read_live_http_url)
                                .unwrap_or(url);
                            st.tab_last_urls.insert(tab_id, final_url.clone());
                            let is_private = shared_shell
                                .lock()
                                .map(|s| s.private_browsing_active)
                                .unwrap_or(false);
                            let cookie_hygiene_due = last_cookie_hygiene_at
                                .map(|t| t.elapsed() >= Duration::from_secs(90))
                                .unwrap_or(true);
                            if cookie_hygiene_due {
                                last_cookie_hygiene_at = Some(std::time::Instant::now());
                                let done_proxy = proxy.clone();
                                cef_runtime::run_cookie_hygiene_cef(
                                    &shared_shell,
                                    true,
                                    !is_private,
                                    Some(Arc::new(move |tr, ad, mal, synced| {
                                        let _ = done_proxy.send_event(WinEvent::CookieHygieneDone {
                                            win_id: wid,
                                            mode: "auto",
                                            trackers: tr,
                                            ads: ad,
                                            malicious: mal,
                                            synced,
                                        });
                                    })),
                                );
                            }
                            if !is_private {
                                let mut shell =
                                    shared_shell.lock().unwrap_or_else(|e| e.into_inner());
                                shell.roaming.record_history_in_memory("", &final_url);
                                history_dirty = true;
                                if last_history_disk_flush.elapsed() >= Duration::from_secs(10) {
                                    shell.roaming.schedule_save_profile();
                                    history_dirty = false;
                                    last_history_disk_flush = std::time::Instant::now();
                                }
                            }
                            emit_ui_sync(
                                &st.ui_browser,
                                &serde_json::json!({
                                    "tab_id": tab_id,
                                    "url": final_url
                                }),
                            );
                        }
                    }
                    CefCallbackEvent::TitleChanged { tab_id, title } => {
                        if let Some(st) = windows.get_mut(&wid) {
                            if tab_id == 0 {
                                return;
                            }
                            let live_url = st
                                .tab_browsers
                                .get(&tab_id)
                                .and_then(read_live_http_url)
                                .or_else(|| st.tab_last_urls.get(&tab_id).cloned());
                            if let Some(ref u) = live_url {
                                st.tab_last_urls.insert(tab_id, u.clone());
                                let mut shell =
                                    shared_shell.lock().unwrap_or_else(|e| e.into_inner());
                                if !shell.private_browsing_active {
                                    shell.roaming.record_history_in_memory(&title, u);
                                    history_dirty = true;
                                    if last_history_disk_flush.elapsed() >= Duration::from_secs(10)
                                    {
                                        shell.roaming.schedule_save_profile();
                                        history_dirty = false;
                                        last_history_disk_flush = std::time::Instant::now();
                                    }
                                }
                            }
                            let mut payload = serde_json::json!({
                                "tab_id": tab_id,
                                "title": title
                            });
                            if let Some(u) = live_url {
                                payload["url"] = serde_json::Value::String(u);
                            }
                            emit_ui_sync(&st.ui_browser, &payload);
                        }
                    }
                    CefCallbackEvent::FaviconChanged {
                        tab_id,
                        favicon_url,
                    } => {
                        if let Some(st) = windows.get_mut(&wid) {
                            if tab_id == 0 {
                                return;
                            }
                            let now = std::time::Instant::now();
                            if let Some(prev) = st.last_favicon_at.get(&tab_id) {
                                if now.duration_since(*prev) < Duration::from_millis(1000) {
                                    return;
                                }
                            }
                            st.last_favicon_at.insert(tab_id, now);
                            emit_ui_sync(
                                &st.ui_browser,
                                &serde_json::json!({
                                    "tab_id": tab_id,
                                    "favicon_url": favicon_url
                                }),
                            );
                        }
                    }
                    CefCallbackEvent::FullscreenChanged { tab_id, enabled } => {
                        if let Some(st) = windows.get_mut(&wid) {
                            if enabled
                                && (tab_id != st.active_tab_id
                                    || !st.web_visible
                                    || st.overlay_open)
                            {
                                return;
                            }
                            if enabled {
                                st.close_ext_popup();
                            }
                            let prev_fs = st.html_fullscreen || st.user_f11_fullscreen;
                            st.html_fullscreen = enabled;
                            let next_fs = st.html_fullscreen || st.user_f11_fullscreen;
                            st.apply_fullscreen(prev_fs, next_fs);
                        }
                    }
                    CefCallbackEvent::OpenNewTab { url, background } => {
                        if let Some(st) = windows.get_mut(&wid) {
                            let mut bg = background;
                            let mut title: Option<String> = None;
                            if let Some(intent) = st.tab_bg_intents.remove(&st.active_tab_id) {
                                let age = intent.at.elapsed();
                                if intent.kind == "bg_click" && age <= Duration::from_millis(1800) {
                                    bg = true;
                                    if !intent.title.is_empty() {
                                        title = Some(intent.title);
                                    }
                                } else if intent.kind == "context_link"
                                    && age <= Duration::from_secs(15)
                                    && intent.href == url
                                {
                                    bg = true;
                                    if !intent.title.is_empty() {
                                        title = Some(intent.title);
                                    }
                                }
                            }
                            let mut payload = serde_json::json!({
                                "new_tab_url": url,
                                "new_tab_background": bg
                            });
                            if let Some(t) = title {
                                payload["new_tab_title"] = serde_json::Value::String(t);
                            }
                            emit_ui_sync(&st.ui_browser, &payload);
                        }
                    }
                    CefCallbackEvent::DownloadStarted { filename, path, .. } => {
                        if let Some(st) = windows.get(&wid) {
                            emit_ui_sync(
                                &st.ui_browser,
                                &serde_json::json!({
                                    "download_started": { "filename": filename, "path": path }
                                }),
                            );
                        }
                    }
                    CefCallbackEvent::DownloadCompleted {
                        filename,
                        path,
                        success,
                        ..
                    } => {
                        if let Some(st) = windows.get(&wid) {
                            emit_ui_sync(
                                &st.ui_browser,
                                &serde_json::json!({
                                    "download_completed": {
                                        "filename": filename,
                                        "path": path,
                                        "success": success
                                    }
                                }),
                            );
                        }
                    }
                    CefCallbackEvent::ContentIpc { tab_id, body } => {
                        if body.len() > 2048 || tab_id == 0 {
                            return;
                        }
                        let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) else {
                            return;
                        };
                        let Some(kind) = v.get("k").and_then(|x| x.as_str()) else {
                            return;
                        };
                        match kind {
                            "fullscreen" => {
                                if let (Some(st), Some(enabled)) = (
                                    windows.get_mut(&wid),
                                    v.get("fs").and_then(|x| x.as_bool()),
                                ) {
                                    if enabled
                                        && (tab_id != st.active_tab_id
                                            || !st.web_visible
                                            || st.overlay_open)
                                    {
                                        return;
                                    }
                                    if enabled {
                                        st.close_ext_popup();
                                    }
                                    let prev_fs = st.html_fullscreen || st.user_f11_fullscreen;
                                    st.html_fullscreen = enabled;
                                    let next_fs = st.html_fullscreen || st.user_f11_fullscreen;
                                    st.apply_fullscreen(prev_fs, next_fs);
                                }
                            }
                            "shortcut" => {
                                let Some(action) = v.get("a").and_then(|x| x.as_str()) else {
                                    return;
                                };
                                let allowed = matches!(
                                    action,
                                    "toggle_fullscreen"
                                        | "reopen_closed_tab"
                                        | "new_tab"
                                        | "new_window"
                                        | "close_active_tab"
                                        | "next_tab"
                                        | "prev_tab"
                                        | "focus_omnibar"
                                        | "reload_tab"
                                        | "toggle_bookmark"
                                        | "open_history"
                                        | "open_settings"
                                        | "jump_tab"
                                        | "web_back"
                                        | "web_forward"
                                        | "zoom_in"
                                        | "zoom_out"
                                        | "zoom_reset"
                                );
                                if !allowed {
                                    return;
                                }
                                let now = std::time::Instant::now();
                                if now.duration_since(last_shortcut_at) < Duration::from_millis(60)
                                {
                                    return;
                                }
                                last_shortcut_at = now;
                                if action == "new_window" {
                                    let _ = proxy.send_event(WinEvent::OpenNewWindowInProcess);
                                    return;
                                }
                                let idx = v
                                    .get("n")
                                    .and_then(|x| x.as_u64())
                                    .filter(|&n| (1..=9).contains(&n))
                                    .map(|n| n as u8);
                                if let Some(st) = windows.get_mut(&wid) {
                                    if tab_id != st.active_tab_id
                                        || !st.web_visible
                                        || st.overlay_open
                                    {
                                        return;
                                    }
                                    match action {
                                        "toggle_fullscreen" => {
                                            st.close_ext_popup();
                                            let prev_fs =
                                                st.html_fullscreen || st.user_f11_fullscreen;
                                            if prev_fs {
                                                st.html_fullscreen = false;
                                                st.user_f11_fullscreen = false;
                                                if let Some(b) =
                                                    st.tab_browsers.get(&st.active_tab_id)
                                                {
                                                    b.evaluate_script("document.fullscreenElement && document.exitFullscreen && document.exitFullscreen().catch(()=>{});");
                                                }
                                            } else {
                                                st.user_f11_fullscreen = true;
                                            }
                                            let next_fs =
                                                st.html_fullscreen || st.user_f11_fullscreen;
                                            st.apply_fullscreen(prev_fs, next_fs);
                                            return;
                                        }
                                        "web_back" => {
                                            let is_private = shared_shell
                                                .lock()
                                                .map(|s| s.private_browsing_active)
                                                .unwrap_or(false);
                                            perform_tab_go_back(
                                                wid,
                                                st,
                                                bind_port,
                                                is_private,
                                                &mut incognito_ctx,
                                                &proxy,
                                                &shared_shell,
                                                &download_resolver,
                                            );
                                            return;
                                        }
                                        "web_forward" => {
                                            let is_private = shared_shell
                                                .lock()
                                                .map(|s| s.private_browsing_active)
                                                .unwrap_or(false);
                                            perform_tab_go_forward(
                                                wid,
                                                st,
                                                bind_port,
                                                is_private,
                                                &mut incognito_ctx,
                                                &proxy,
                                                &shared_shell,
                                                &download_resolver,
                                            );
                                            return;
                                        }
                                        "zoom_in" | "zoom_out" | "zoom_reset" => {
                                            perform_tab_zoom(st, action);
                                            return;
                                        }
                                        "reload_tab" => {
                                            if let Some(b) = st.tab_browsers.get(&st.active_tab_id)
                                            {
                                                b.reload();
                                                return;
                                            }
                                        }
                                        "focus_omnibar"
                                        | "new_tab"
                                        | "open_settings"
                                        | "open_history" => {
                                            if st.html_fullscreen || st.user_f11_fullscreen {
                                                st.html_fullscreen = false;
                                                st.user_f11_fullscreen = false;
                                                st.apply_fullscreen(true, false);
                                            }
                                            st.ui_browser.focus();
                                        }
                                        _ => {}
                                    }
                                    emit_ui_sync(
                                        &st.ui_browser,
                                        &serde_json::json!({
                                            "shortcut": action,
                                            "shortcut_index": idx
                                        }),
                                    );
                                }
                            }
                            "favicon" => {
                                if let Some(icon_url) = v.get("u").and_then(|x| x.as_str()) {
                                    if icon_url.len() <= 512
                                        && parse_http_url_authority(icon_url).is_ok()
                                    {
                                        if let Some(st) = windows.get_mut(&wid) {
                                            let now = std::time::Instant::now();
                                            if st
                                                .last_favicon_at
                                                .get(&tab_id)
                                                .is_some_and(|p| {
                                                    now.duration_since(*p)
                                                        < Duration::from_millis(1000)
                                                })
                                            {
                                                return;
                                            }
                                            st.last_favicon_at.insert(tab_id, now);
                                            emit_ui_sync(
                                                &st.ui_browser,
                                                &serde_json::json!({
                                                    "tab_id": tab_id,
                                                    "favicon_url": icon_url
                                                }),
                                            );
                                        }
                                    }
                                }
                            }
                            "media_state" => {
                                let time_sec = v
                                    .get("s")
                                    .and_then(|x| x.as_u64())
                                    .unwrap_or(0)
                                    .min(864_000);
                                let scroll_y = v
                                    .get("sy")
                                    .and_then(|x| x.as_u64())
                                    .unwrap_or(0)
                                    .min(10_000_000) as u32;
                                if let Some(st) = windows.get_mut(&wid) {
                                    let Some(trusted_url) = st
                                        .tab_browsers
                                        .get(&tab_id)
                                        .and_then(read_live_http_url)
                                        .or_else(|| st.tab_last_urls.get(&tab_id).cloned())
                                    else {
                                        return;
                                    };
                                    if time_sec >= 2 {
                                        st.tab_media_times.insert(tab_id, time_sec);
                                    }
                                    if scroll_y > 0 {
                                        st.tab_scroll_ys.insert(tab_id, scroll_y);
                                    }
                                    emit_ui_sync(
                                        &st.ui_browser,
                                        &serde_json::json!({
                                            "tab_id": tab_id,
                                            "media_time_sec": time_sec,
                                            "scroll_y": scroll_y
                                        }),
                                    );
                                    let mut should_flush_checkpoint = false;
                                    if last_media_disk_flush.elapsed() >= Duration::from_secs(6) {
                                        should_flush_checkpoint = true;
                                        let mut shell = shared_shell
                                            .lock()
                                            .unwrap_or_else(|e| e.into_inner());
                                        if !shell.private_browsing_active
                                            && shell.roaming.profile.restore_session
                                            && shell.roaming.update_saved_tab_media_progress(
                                                &trusted_url,
                                                time_sec,
                                                scroll_y,
                                            )
                                        {
                                            shell.roaming.schedule_save_profile();
                                            history_dirty = false;
                                            last_history_disk_flush = std::time::Instant::now();
                                        }
                                        last_media_disk_flush = std::time::Instant::now();
                                    }
                                    if should_flush_checkpoint && smoke_tracker.is_none() {
                                        let _ = st;
                                        flush_live_crash_checkpoint(&windows, &cfg_clone, &shared_shell);
                                    }
                                }
                            }
                            "bg_click" | "context_link" => {
                                let Some(href) = v.get("u").and_then(|x| x.as_str()) else {
                                    return;
                                };
                                if parse_http_url_authority(href).is_err() {
                                    return;
                                }
                                let title: String = v
                                    .get("t")
                                    .and_then(|x| x.as_str())
                                    .unwrap_or("")
                                    .chars()
                                    .filter(|c| !c.is_control())
                                    .take(120)
                                    .collect::<String>()
                                    .trim()
                                    .to_string();
                                if let Some(st) = windows.get_mut(&wid) {
                                    st.tab_bg_intents.insert(
                                        tab_id,
                                        BgLinkIntent {
                                            kind: kind.to_string(),
                                            href: href.to_string(),
                                            title,
                                            at: std::time::Instant::now(),
                                        },
                                    );
                                }
                            }
                            _ => {}
                        }
                    }
                    CefCallbackEvent::UiIpc(raw) => {
                        let Ok(cmd) = serde_json::from_str::<UiIpcCmd>(&raw) else {
                            return;
                        };
                        match cmd {
                            UiIpcCmd::UiReady => {
                                if let Some(st) = windows.get_mut(&wid) {
                                    st.ui_ready_received = true;
                                    st.layout_cache.invalidate_ui();
                                    st.sync_layout();
                                    st.sync_maximized(true);
                                    emit_ui_sync(
                                        &st.ui_browser,
                                        &serde_json::json!({ "ram_active_count": st.tab_browsers.len() }),
                                    );
                                    if smoke_tracker.is_none() {
                                        if let Some(rep) = pending_crash_report.take() {
                                            emit_ui_sync(
                                                &st.ui_browser,
                                                &serde_json::json!({
                                                    "crash_report": {
                                                        "kind": rep.kind,
                                                        "summary": rep.summary,
                                                        "text": rep.format_copyable_text()
                                                    }
                                                }),
                                            );
                                        }
                                    }
                                    if let Some(ref mut sm) = smoke_tracker {
                                        if !sm.ui_ready {
                                            sm.ui_ready = true;
                                            sm.log("UiReady received via native V8 window.ipc.postMessage — running DOM & rAF compositor probe");
                                            st.ui_browser.evaluate_script(
                                                r#"(function(){
                                                    requestAnimationFrame(function(){
                                                        requestAnimationFrame(function(){
                                                            var bar = document.getElementById('apple-titlebar') || document.querySelector('.apple-bar');
                                                            var url = document.querySelector('.omnibar-input') || document.querySelector('input');
                                                            var br = bar ? bar.getBoundingClientRect() : {width:0,height:0};
                                                            var tabs = document.querySelectorAll('.tab-pill').length;
                                                            var vid = document.createElement('video');
                                                            var h264 = vid.canPlayType('video/mp4; codecs="avc1.42E01E"') || 'no';
                                                            var aac = vid.canPlayType('audio/mp4; codecs="mp4a.40.2"') || 'no';
                                                            var mp4AvcAac = vid.canPlayType('video/mp4; codecs="avc1.42E01E, mp4a.40.2"') || 'no';
                                                            var mseAvcAac = (typeof MediaSource !== 'undefined' && typeof MediaSource.isTypeSupported === 'function')
                                                                ? !!MediaSource.isTypeSupported('video/mp4; codecs="avc1.42E01E, mp4a.40.2"')
                                                                : false;
                                                            var vp9 = vid.canPlayType('video/webm; codecs="vp9"') || 'no';
                                                            var av1 = vid.canPlayType('video/mp4; codecs="av01.0.04M.08"') || 'no';
                                                            var hevc = vid.canPlayType('video/mp4; codecs="hvc1.1.6.L93.B0"') || 'no';
                                                            var codecs = 'h264=' + h264
                                                                + ',aac=' + aac
                                                                + ',mp4_avc_aac=' + mp4AvcAac
                                                                + ',mse_avc_aac=' + mseAvcAac
                                                                + ',vp9=' + vp9
                                                                + ',av1=' + av1
                                                                + ',hevc=' + hevc;
                                                            if (window.ipc && window.ipc.postMessage) {
                                                                window.ipc.postMessage(JSON.stringify({
                                                                    cmd: 'smoke_probe',
                                                                    bar_h: Math.round(br.height || 0),
                                                                    bar_w: Math.round(br.width || 0),
                                                                    body_w: Math.round(window.innerWidth || 0),
                                                                    body_h: Math.round(window.innerHeight || 0),
                                                                    has_url_input: !!url,
                                                                    tab_count: tabs,
                                                                    codecs: codecs,
                                                                    h264_ok: h264 !== 'no',
                                                                    aac_ok: aac !== 'no',
                                                                    mp4_avc_aac_ok: mp4AvcAac !== 'no',
                                                                    mse_avc_aac_ok: mseAvcAac,
                                                                    ua: String(navigator.userAgent || ''),
                                                                    webdriver: !!navigator.webdriver
                                                                }));
                                                            }
                                                        });
                                                    });
                                                })();"#,
                                            );
                                        }
                                    }
                                }
                            }
                            UiIpcCmd::CopyText { text } => {
                                let _ = crate::crash_guard::copy_text_to_windows_clipboard(&text);
                            }
                            UiIpcCmd::SmokeProbe {
                                bar_h,
                                bar_w,
                                body_w,
                                body_h,
                                has_url_input,
                                tab_count,
                                codecs,
                                h264_ok,
                                aac_ok,
                                mp4_avc_aac_ok,
                                mse_avc_aac_ok,
                                ua,
                                webdriver,
                            } => {
                                if let Some(ref mut sm) = smoke_tracker {
                                    sm.codecs_summary = codecs.clone();
                                    let summary = format!(
                                        "bar={}x{}, viewport={}x{}, has_url_input={}, tab_count={}, webdriver={}, codecs=[{}], ua=\"{}\"",
                                        bar_w, bar_h, body_w, body_h, has_url_input, tab_count, webdriver, codecs, ua
                                    );
                                    sm.probe_summary = summary.clone();
                                    sm.probe_ok = bar_h >= 40
                                        && bar_w >= 400
                                        && body_w >= 400
                                        && body_h >= 300
                                        && has_url_input
                                        && tab_count >= 1
                                        && h264_ok
                                        && aac_ok
                                        && mp4_avc_aac_ok
                                        && mse_avc_aac_ok
                                        && !webdriver;
                                    sm.log(&format!(
                                        "SmokeProbe (2x rAF completed): ok={}, {}",
                                        sm.probe_ok, summary
                                    ));
                                    let px_proxy = proxy.clone();
                                    let _ = std::thread::Builder::new()
                                        .name("singularity-smoke-pixels".into())
                                        .stack_size(128 * 1024)
                                        .spawn(move || {
                                            std::thread::sleep(Duration::from_millis(450));
                                            let _ = px_proxy.send_event(WinEvent::SmokeCheckPixels(wid));
                                        });
                                }
                            }
                            UiIpcCmd::DragWindow => {
                                if let Some(st) = windows.get_mut(&wid) {
                                    st.close_ext_popup();
                                    cef_runtime::set_cef_nestable_tasks_allowed(true);
                                    let _ = st.window.drag_window();
                                    cef_runtime::set_cef_nestable_tasks_allowed(false);
                                }
                            }
                            UiIpcCmd::DragResize { direction } => {
                                if let Some(st) = windows.get_mut(&wid) {
                                    if st.window.is_maximized() || st.window.fullscreen().is_some()
                                    {
                                        st.sync_maximized(true);
                                    } else {
                                        let dir = match direction.as_str() {
                                            "North" => Some(ResizeDirection::North),
                                            "South" => Some(ResizeDirection::South),
                                            "East" => Some(ResizeDirection::East),
                                            "West" => Some(ResizeDirection::West),
                                            "NorthEast" => Some(ResizeDirection::NorthEast),
                                            "NorthWest" => Some(ResizeDirection::NorthWest),
                                            "SouthEast" => Some(ResizeDirection::SouthEast),
                                            "SouthWest" => Some(ResizeDirection::SouthWest),
                                            _ => None,
                                        };
                                        if let Some(d) = dir {
                                            cef_runtime::set_cef_nestable_tasks_allowed(true);
                                            let _ = st.window.drag_resize_window(d);
                                            cef_runtime::set_cef_nestable_tasks_allowed(false);
                                        }
                                    }
                                }
                            }
                            UiIpcCmd::Minimize => {
                                if let Some(st) = windows.get_mut(&wid) {
                                    st.close_ext_popup();
                                    st.window.set_minimized(true);
                                }
                            }
                            UiIpcCmd::ToggleMaximize => {
                                if let Some(st) = windows.get_mut(&wid) {
                                    let prev_fs = st.html_fullscreen || st.user_f11_fullscreen;
                                    if prev_fs || st.window.fullscreen().is_some() {
                                        st.html_fullscreen = false;
                                        st.user_f11_fullscreen = false;
                                        if let Some(b) = st.tab_browsers.get(&st.active_tab_id) {
                                            b.evaluate_script("document.fullscreenElement && document.exitFullscreen && document.exitFullscreen().catch(()=>{});");
                                        }
                                        st.apply_fullscreen(true, false);
                                    } else {
                                        st.window.set_maximized(!st.window.is_maximized());
                                        ensure_win32_clip_children(
                                            st.window.hwnd() as *mut core::ffi::c_void,
                                        );
                                        st.capture_geometry(&cfg_clone, &shared_shell);
                                        st.sync_layout();
                                        st.sync_maximized(false);
                                    }
                                }
                            }
                            UiIpcCmd::ToggleFullscreen => {
                                if let Some(st) = windows.get_mut(&wid) {
                                    st.close_ext_popup();
                                    let prev_fs = st.html_fullscreen || st.user_f11_fullscreen;
                                    if prev_fs {
                                        st.html_fullscreen = false;
                                        st.user_f11_fullscreen = false;
                                        if let Some(b) = st.tab_browsers.get(&st.active_tab_id) {
                                            b.evaluate_script("document.fullscreenElement && document.exitFullscreen && document.exitFullscreen().catch(()=>{});");
                                        }
                                    } else {
                                        st.user_f11_fullscreen = true;
                                    }
                                    let next_fs = st.html_fullscreen || st.user_f11_fullscreen;
                                    st.apply_fullscreen(prev_fs, next_fs);
                                }
                            }
                            UiIpcCmd::Close => {
                                if let Some(mut st) = windows.remove(&wid) {
                                    st.close_ext_popup();
                                    let others_alive = !windows.is_empty();
                                    persist_window_on_close(
                                        &st,
                                        others_alive,
                                        &cfg_clone,
                                        &shared_shell,
                                    );
                                    st.close_cleanly();
                                    if windows.is_empty() {
                                        if history_dirty {
                                            let shell = shared_shell
                                                .lock()
                                                .unwrap_or_else(|e| e.into_inner());
                                            let _ = shell.roaming.save_profile();
                                            history_dirty = false;
                                        }
                                        cef_runtime::run_cookie_hygiene_cef(
                                            &shared_shell,
                                            true,
                                            true,
                                            None,
                                        );
                                        for _ in 0..8 {
                                            cef_runtime::pump_cef_message_loop();
                                            std::thread::sleep(Duration::from_millis(8));
                                        }
                                        cef_runtime::flush_cookie_store_cef_sync(
                                            Duration::from_millis(800),
                                        );
                                        {
                                            let shell = shared_shell
                                                .lock()
                                                .unwrap_or_else(|e| e.into_inner());
                                            shell.roaming.flush_async_persistence();
                                            shell.roaming.unregister_live_window();
                                        }
                                        if smoke_tracker.is_none() {
                                            crate::crash_guard::mark_clean_shutdown(&root_dir);
                                        }
                                        let _ = cef_runtime::drain_browsers_before_shutdown(
                                            Duration::from_millis(1200),
                                        );
                                        drop(incognito_ctx.take());
                                        drop(cef_guard.take());
                                        *control_flow = ControlFlow::Exit;
                                    }
                                }
                            }
                            UiIpcCmd::NavigateWeb {
                                tab_id,
                                url,
                                overlay_open: ov,
                            } => {
                                if parse_http_url_authority(&url).is_err() {
                                    return;
                                }
                                let is_private = shared_shell
                                    .lock()
                                    .map(|s| s.private_browsing_active)
                                    .unwrap_or(false);
                                if let Some(st) = windows.get_mut(&wid) {
                                    st.close_ext_popup();
                                    let tid = if tab_id == 0 { st.active_tab_id } else { tab_id };
                                    if st.html_fullscreen {
                                        st.html_fullscreen = false;
                                        if !st.user_f11_fullscreen {
                                            st.apply_fullscreen(true, false);
                                        }
                                    }
                                    if tid != st.active_tab_id {
                                        if let Some(prev_b) = st.tab_browsers.get(&st.active_tab_id)
                                        {
                                            if let Some(live_url) = read_live_http_url(prev_b) {
                                                st.tab_last_urls
                                                    .insert(st.active_tab_id, live_url.clone());
                                                emit_ui_sync(
                                                    &st.ui_browser,
                                                    &serde_json::json!({
                                                        "tab_id": st.active_tab_id,
                                                        "url": live_url
                                                    }),
                                                );
                                            }
                                        }
                                    }
                                    if st
                                        .tab_last_urls
                                        .get(&tid)
                                        .map(|prev| {
                                            normalize_url_without_media_time(prev)
                                                != normalize_url_without_media_time(&url)
                                        })
                                        .unwrap_or(true)
                                    {
                                        st.tab_media_times.remove(&tid);
                                        st.tab_scroll_ys.remove(&tid);
                                    }
                                    st.active_tab_id = tid;
                                    st.web_visible = true;
                                    st.overlay_open = ov;
                                    st.tab_last_urls.insert(tid, url.clone());
                                    st.tab_nav_history
                                        .entry(tid)
                                        .or_insert_with(TabNavHistory::new_with_home)
                                        .record_url(&url);

                                    if let Some(existing) = st.tab_browsers.get(&tid) {
                                        existing.load_url(&url);
                                    } else {
                                        spawn_content_tab_cef(
                                            wid,
                                            st,
                                            tid,
                                            &url,
                                            bind_port,
                                            is_private,
                                            &mut incognito_ctx,
                                            None,
                                            None,
                                            false,
                                            &proxy,
                                            &shared_shell,
                                            &download_resolver,
                                        );
                                    }
                                    st.sync_layout();
                                    if st.web_visible && !st.overlay_open {
                                        if let Some(b) = st.tab_browsers.get(&st.active_tab_id) {
                                            b.focus();
                                        }
                                    }
                                    emit_ui_sync(
                                        &st.ui_browser,
                                        &serde_json::json!({
                                            "tab_id": tid,
                                            "unloaded": false,
                                            "ram_active_count": st.tab_browsers.len()
                                        }),
                                    );
                                    emit_tab_nav_state(st, tid);
                                }
                            }
                            UiIpcCmd::ActivateTab {
                                tab_id,
                                url,
                                web_visible: wv_vis,
                                overlay_open: ov,
                                resume_time_sec,
                                resume_scroll_y,
                                start_paused,
                            } => {
                                let is_private = shared_shell
                                    .lock()
                                    .map(|s| s.private_browsing_active)
                                    .unwrap_or(false);
                                if let Some(st) = windows.get_mut(&wid) {
                                    if tab_id != st.active_tab_id {
                                        if st.html_fullscreen {
                                            st.html_fullscreen = false;
                                            if !st.user_f11_fullscreen {
                                                st.apply_fullscreen(true, false);
                                            }
                                        }
                                        if let Some(prev_b) = st.tab_browsers.get(&st.active_tab_id)
                                        {
                                            if let Some(live_url) = read_live_http_url(prev_b) {
                                                st.tab_last_urls
                                                    .insert(st.active_tab_id, live_url.clone());
                                                emit_ui_sync(
                                                    &st.ui_browser,
                                                    &serde_json::json!({
                                                        "tab_id": st.active_tab_id,
                                                        "url": live_url
                                                    }),
                                                );
                                            }
                                        }
                                    }
                                    st.active_tab_id = tab_id;
                                    st.web_visible = wv_vis;
                                    st.overlay_open = ov;

                                    if st.web_visible {
                                        if let Some(existing) = st.tab_browsers.get(&tab_id) {
                                            if let Some(live_url) = read_live_http_url(existing) {
                                                st.tab_last_urls.insert(tab_id, live_url.clone());
                                                st.tab_nav_history
                                                    .entry(tab_id)
                                                    .or_insert_with(|| {
                                                        TabNavHistory::new_with_url(&live_url)
                                                    });
                                                emit_ui_sync(
                                                    &st.ui_browser,
                                                    &serde_json::json!({
                                                        "tab_id": tab_id,
                                                        "url": live_url,
                                                        "unloaded": false,
                                                        "ram_active_count": st.tab_browsers.len()
                                                    }),
                                                );
                                            }
                                        } else if parse_http_url_authority(&url).is_ok() {
                                            let target_sec = resume_time_sec
                                                .filter(|&t| t >= 3)
                                                .or_else(|| {
                                                    st.tab_media_times
                                                        .get(&tab_id)
                                                        .copied()
                                                        .filter(|&t| t >= 3)
                                                });
                                            let target_scroll = resume_scroll_y
                                                .filter(|&sy| sy >= 40)
                                                .or_else(|| {
                                                    st.tab_scroll_ys
                                                        .get(&tab_id)
                                                        .copied()
                                                        .filter(|&sy| sy >= 40)
                                                });
                                            st.tab_last_urls.insert(tab_id, url.clone());
                                            st.tab_nav_history
                                                .entry(tab_id)
                                                .or_insert_with(|| {
                                                    TabNavHistory::new_with_url(&url)
                                                });
                                            if let Some(t) = target_sec {
                                                st.tab_media_times.insert(tab_id, t);
                                            }
                                            if let Some(sy) = target_scroll {
                                                st.tab_scroll_ys.insert(tab_id, sy);
                                            }
                                            spawn_content_tab_cef(
                                                wid,
                                                st,
                                                tab_id,
                                                &url,
                                                bind_port,
                                                is_private,
                                                &mut incognito_ctx,
                                                target_sec,
                                                target_scroll,
                                                start_paused,
                                                &proxy,
                                                &shared_shell,
                                                &download_resolver,
                                            );
                                            emit_ui_sync(
                                                &st.ui_browser,
                                                &serde_json::json!({
                                                    "tab_id": tab_id,
                                                    "unloaded": false,
                                                    "ram_active_count": st.tab_browsers.len()
                                                }),
                                            );
                                        }
                                    } else {
                                        st.tab_nav_history
                                            .entry(tab_id)
                                            .or_insert_with(TabNavHistory::new_with_home);
                                    }
                                    st.sync_layout();
                                    emit_tab_nav_state(st, tab_id);
                                    if st.web_visible && !st.overlay_open {
                                        if let Some(b) = st.tab_browsers.get(&st.active_tab_id) {
                                            b.focus();
                                        }
                                    }
                                }
                            }
                            UiIpcCmd::FocusActiveWeb { toggle_media_play } => {
                                if let Some(st) = windows.get(&wid) {
                                    if st.web_visible && !st.overlay_open {
                                        if let Some(b) = st.tab_browsers.get(&st.active_tab_id) {
                                            b.focus();
                                            if toggle_media_play {
                                                b.evaluate_script(TOGGLE_ACTIVE_MEDIA_SCRIPT);
                                            }
                                        }
                                    }
                                }
                            }
                            UiIpcCmd::CloseTab { tab_id } => {
                                if let Some(st) = windows.get_mut(&wid) {
                                    if tab_id == st.active_tab_id && st.html_fullscreen {
                                        st.html_fullscreen = false;
                                        if !st.user_f11_fullscreen {
                                            st.apply_fullscreen(true, false);
                                        }
                                    }
                                    st.tab_browsers.remove(&tab_id);
                                    st.layout_cache.invalidate_tab(Some(tab_id));
                                    st.tab_last_urls.remove(&tab_id);
                                    st.tab_nav_history.remove(&tab_id);
                                    st.tab_media_times.remove(&tab_id);
                                    st.tab_scroll_ys.remove(&tab_id);
                                    st.tab_bg_intents.remove(&tab_id);
                                    st.last_favicon_at.remove(&tab_id);
                                    emit_ui_sync(
                                        &st.ui_browser,
                                        &serde_json::json!({ "ram_active_count": st.tab_browsers.len() }),
                                    );
                                }
                            }
                            UiIpcCmd::UnloadTab { tab_id } => {
                                if let Some(st) = windows.get_mut(&wid) {
                                    if tab_id == st.active_tab_id
                                        && st.web_visible
                                        && !st.overlay_open
                                    {
                                        return;
                                    }
                                    if let Some(b) = st.tab_browsers.remove(&tab_id) {
                                        let exact_url = read_live_http_url(&b)
                                            .or_else(|| st.tab_last_urls.get(&tab_id).cloned());
                                        drop(b); // Force-closes CEF browser & reclaims 100% renderer RAM!
                                        st.layout_cache.invalidate_tab(Some(tab_id));
                                        let mut payload = serde_json::json!({
                                            "tab_id": tab_id,
                                            "unloaded": true,
                                            "ram_active_count": st.tab_browsers.len()
                                        });
                                        if let Some(u) = exact_url {
                                            st.tab_last_urls.insert(tab_id, u.clone());
                                            payload["url"] = serde_json::Value::String(u);
                                        }
                                        if let Some(&t) = st.tab_media_times.get(&tab_id) {
                                            payload["media_time_sec"] = serde_json::Value::from(t);
                                        }
                                        emit_ui_sync(&st.ui_browser, &payload);
                                    }
                                }
                            }
                            UiIpcCmd::SyncTabUrl { tab_id } => {
                                if let Some(st) = windows.get_mut(&wid) {
                                    if let Some(b) = st.tab_browsers.get(&tab_id) {
                                        if let Some(live_url) = read_live_http_url(b) {
                                            let changed = st
                                                .tab_last_urls
                                                .get(&tab_id)
                                                .map(|prev| prev != &live_url)
                                                .unwrap_or(true);
                                            if changed {
                                                st.tab_last_urls.insert(tab_id, live_url.clone());
                                                emit_ui_sync(
                                                    &st.ui_browser,
                                                    &serde_json::json!({
                                                        "tab_id": tab_id,
                                                        "url": live_url
                                                    }),
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                            UiIpcCmd::ReloadExtensions => {
                                if let Some(st) = windows.get_mut(&wid) {
                                    st.close_ext_popup();
                                    if let Some(b) = st.tab_browsers.get(&st.active_tab_id) {
                                        b.reload();
                                    }
                                }
                            }
                            UiIpcCmd::PickLocalExtensionPath { mode } => {
                                static EXT_PICKER_BUSY: std::sync::atomic::AtomicBool =
                                    std::sync::atomic::AtomicBool::new(false);
                                if EXT_PICKER_BUSY
                                    .compare_exchange(
                                        false,
                                        true,
                                        std::sync::atomic::Ordering::AcqRel,
                                        std::sync::atomic::Ordering::Acquire,
                                    )
                                    .is_err()
                                {
                                    return;
                                }
                                let pick_proxy = proxy.clone();
                                let pick_folder = mode.eq_ignore_ascii_case("folder");
                                if std::thread::Builder::new()
                                    .name("singularity-ext-picker".into())
                                    .spawn(move || {
                                        let picked = if pick_folder {
                                            pick_win32_extension_folder()
                                        } else {
                                            pick_win32_extension_file()
                                        };
                                        EXT_PICKER_BUSY
                                            .store(false, std::sync::atomic::Ordering::Release);
                                        if let Some(path) = picked {
                                            let _ = pick_proxy.send_event(
                                                WinEvent::LocalExtensionPicked { win_id: wid, path },
                                            );
                                        }
                                    })
                                    .is_err()
                                {
                                    EXT_PICKER_BUSY
                                        .store(false, std::sync::atomic::Ordering::Release);
                                }
                            }
                            UiIpcCmd::RestartBrowser => {
                                if smoke_tracker.is_none() {
                                    flush_live_crash_checkpoint(
                                        &windows,
                                        &cfg_clone,
                                        &shared_shell,
                                    );
                                    cef_runtime::flush_cookie_store_cef_sync(
                                        Duration::from_millis(500),
                                    );
                                    if let Ok(shell) = shared_shell.lock() {
                                        let _ = shell.roaming.save_profile();
                                        shell.roaming.flush_async_persistence();
                                    }
                                    crate::crash_guard::mark_planned_restart(&root_dir);
                                    if let Ok(exe) = std::env::current_exe() {
                                        use std::os::windows::process::CommandExt;
                                        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
                                        let _ = Command::new(exe)
                                            .arg("--wait-pid")
                                            .arg(std::process::id().to_string())
                                            .creation_flags(CREATE_NO_WINDOW)
                                            .spawn();
                                    }
                                }
                                for (_, st) in windows.drain() {
                                    st.close_cleanly();
                                }
                                let _ = cef_runtime::drain_browsers_before_shutdown(
                                    Duration::from_millis(1200),
                                );
                                crate::crash_guard::mark_clean_shutdown(&root_dir);
                                drop(incognito_ctx.take());
                                drop(cef_guard.take());
                                *control_flow = ControlFlow::Exit;
                            }
                            UiIpcCmd::ToggleExtensionPopup {
                                ext_id,
                                anchor_x,
                                open_options,
                            } => {
                                if !extensions::is_valid_extension_dir_id(&ext_id) {
                                    return;
                                }
                                let Some(st) = windows.get_mut(&wid) else {
                                    return;
                                };
                                if let Some(open_popup) = st.ext_popup.take() {
                                    let was_same = open_popup.ext_id == ext_id;
                                    drop(open_popup.browser);
                                    drop(open_popup.window);
                                    if was_same && !open_options {
                                        st.last_ext_popup_closed = None;
                                        return;
                                    }
                                }
                                if !open_options {
                                    if let Some((ref prev_id, at)) = st.last_ext_popup_closed {
                                        if prev_id == &ext_id && at.elapsed() < Duration::from_millis(350)
                                        {
                                            st.last_ext_popup_closed = None;
                                            return;
                                        }
                                    }
                                }
                                st.last_ext_popup_closed = None;

                                let Some((popup_url, ext_name)) =
                                    extensions::resolve_extension_runtime_url(
                                        &root_dir,
                                        &ext_id,
                                        open_options,
                                    )
                                else {
                                    emit_ui_sync(
                                        &st.ui_browser,
                                        &serde_json::json!({ "ext_popup_fallback": ext_id }),
                                    );
                                    return;
                                };

                                let (pop_w, pop_h) = if open_options {
                                    (740.0_f64, 580.0_f64)
                                } else {
                                    (400.0_f64, 540.0_f64)
                                };
                                let scale = st.window.scale_factor();
                                let win_pos = st
                                    .window
                                    .outer_position()
                                    .unwrap_or(TaoPhysicalPosition::new(80, 80));
                                let win_size = st.window.inner_size();
                                let pop_phys_w = (pop_w * scale).round() as i32;
                                let pop_phys_h = (pop_h * scale).round() as i32;
                                let bar_phys_h = (APPLE_BAR_LOGICAL_HEIGHT * scale).round() as i32;
                                let margin = (8.0 * scale).round() as i32;
                                let anchor_phys_x = anchor_x
                                    .map(|ax| (ax * scale).round() as i32)
                                    .unwrap_or(
                                        (win_size.width as i32) - (16.0 * scale).round() as i32,
                                    );
                                let raw_x = win_pos.x + anchor_phys_x - pop_phys_w;
                                let min_x = win_pos.x + margin;
                                let max_x =
                                    (win_pos.x + win_size.width as i32 - pop_phys_w - margin)
                                        .max(min_x);
                                let mut px = raw_x.clamp(min_x, max_x);
                                let mut py = win_pos.y + bar_phys_h + (4.0 * scale).round() as i32;
                                if let Some(mon) = st.window.current_monitor() {
                                    let mpos = mon.position();
                                    let msize = mon.size();
                                    let mon_max_x =
                                        (mpos.x + msize.width as i32 - pop_phys_w - margin)
                                            .max(mpos.x + margin);
                                    let mon_max_y =
                                        (mpos.y + msize.height as i32 - pop_phys_h - margin)
                                            .max(mpos.y + margin);
                                    px = px.clamp(mpos.x + margin, mon_max_x);
                                    py = py.clamp(mpos.y + margin, mon_max_y);
                                }

                                let popup_title = format!("{} — Singularity", ext_name);
                                let Ok(popup_win) = WindowBuilder::new()
                                    .with_title(&popup_title)
                                    .with_owner_window(st.window.hwnd())
                                    .with_decorations(open_options)
                                    .with_undecorated_shadow(true)
                                    .with_skip_taskbar(true)
                                    .with_resizable(true)
                                    .with_background_color((16, 17, 22, 255))
                                    .with_inner_size(Size::Logical(LogicalSize::new(pop_w, pop_h)))
                                    .with_position(TaoPhysicalPosition::new(px, py))
                                    .build(elwt)
                                else {
                                    emit_ui_sync(
                                        &st.ui_browser,
                                        &serde_json::json!({ "ext_popup_fallback": ext_id }),
                                    );
                                    return;
                                };
                                enable_win32_immersive_dark_window(
                                    popup_win.hwnd() as *mut core::ffi::c_void,
                                );
                                ensure_win32_clip_children(
                                    popup_win.hwnd() as *mut core::ffi::c_void,
                                );
                                let pphys = popup_win.inner_size();
                                let pop_proxy = proxy.clone();
                                let pop_sink: CefEventSink = Arc::new(move |evt| {
                                    let _ = pop_proxy.send_event(WinEvent::CefCallback(wid, evt));
                                });
                                if let Ok(popup_b) = cef_runtime::spawn_cef_child_browser(
                                    popup_win.hwnd(),
                                    0,
                                    0,
                                    pphys.width.max(1),
                                    pphys.height.max(1),
                                    &popup_url,
                                    false,
                                    true,
                                    0,
                                    bind_port,
                                    Some(EXT_POPUP_INIT_SCRIPT),
                                    None,
                                    None,
                                    pop_sink,
                                    Arc::clone(&shared_shell),
                                    Arc::clone(&download_resolver),
                                ) {
                                    bring_win32_window_to_front(popup_win.hwnd());
                                    popup_b.focus();
                                    let pid = popup_win.id();
                                    st.ext_popup = Some(ExtPopupState {
                                        ext_id,
                                        window_id: pid,
                                        auto_dismiss: !open_options,
                                        opened_at: std::time::Instant::now(),
                                        browser: popup_b,
                                        window: popup_win,
                                    });
                                } else {
                                    drop(popup_win);
                                    emit_ui_sync(
                                        &st.ui_browser,
                                        &serde_json::json!({ "ext_popup_fallback": ext_id }),
                                    );
                                }
                            }
                            UiIpcCmd::ShowExtensionContextMenu {
                                ext_id,
                                has_popup,
                                has_options,
                                lang,
                            } => {
                                if !extensions::is_valid_extension_dir_id(&ext_id) {
                                    return;
                                }
                                let is_fr = lang.as_deref().map(|l| l == "fr").unwrap_or_else(|| {
                                    shared_shell
                                        .lock()
                                        .map(|s| s.roaming.profile.language == "fr")
                                        .unwrap_or(false)
                                });
                                if let Some(st) = windows.get_mut(&wid) {
                                    st.close_ext_popup();
                                    let hwnd = st.window.hwnd() as *mut core::ffi::c_void;
                                    if let Some(action) = show_native_extension_context_menu(
                                        hwnd,
                                        has_popup,
                                        has_options,
                                        is_fr,
                                    ) {
                                        if action == "manage_ext" {
                                            st.ui_browser.focus();
                                        }
                                        emit_ui_sync(
                                            &st.ui_browser,
                                            &serde_json::json!({
                                                "ext_ctx_action": action,
                                                "ext_ctx_id": ext_id
                                            }),
                                        );
                                    }
                                }
                            }
                            UiIpcCmd::SetViewMode {
                                web_visible: wv_vis,
                                overlay_open: ov,
                            } => {
                                if let Some(st) = windows.get_mut(&wid) {
                                    st.web_visible = wv_vis;
                                    st.overlay_open = ov;
                                    if (!st.web_visible || st.overlay_open) && st.html_fullscreen {
                                        st.html_fullscreen = false;
                                        if !st.user_f11_fullscreen {
                                            st.apply_fullscreen(true, false);
                                        }
                                    }
                                    st.sync_layout();
                                    if st.web_visible && !st.overlay_open {
                                        if let Some(b) = st.tab_browsers.get(&st.active_tab_id) {
                                            b.focus();
                                        }
                                    }
                                }
                            }
                            UiIpcCmd::SetOverlay { open } => {
                                if let Some(st) = windows.get_mut(&wid) {
                                    st.overlay_open = open;
                                    if st.overlay_open {
                                        st.close_ext_popup();
                                    }
                                    if st.overlay_open && st.html_fullscreen {
                                        st.html_fullscreen = false;
                                        if !st.user_f11_fullscreen {
                                            st.apply_fullscreen(true, false);
                                        }
                                    }
                                    st.sync_layout();
                                    if st.web_visible && !st.overlay_open {
                                        if let Some(b) = st.tab_browsers.get(&st.active_tab_id) {
                                            b.focus();
                                        }
                                    }
                                }
                            }
                            UiIpcCmd::SetPrivateMode { enabled } => {
                                if enabled {
                                    cef_runtime::run_cookie_hygiene_cef(
                                        &shared_shell,
                                        false,
                                        true,
                                        None,
                                    );
                                }
                                {
                                    let mut shell =
                                        shared_shell.lock().unwrap_or_else(|e| e.into_inner());
                                    shell.private_browsing_active = enabled;
                                }
                                if !enabled {
                                    incognito_ctx = None;
                                }
                                if let Some(st) = windows.get_mut(&wid) {
                                    st.close_ext_popup();
                                    let active_url = st.tab_last_urls.get(&st.active_tab_id).cloned();
                                    let active_sec = st.tab_media_times.get(&st.active_tab_id).copied();
                                    let active_sy = st.tab_scroll_ys.get(&st.active_tab_id).copied();
                                    let active_tid = st.active_tab_id;
                                    st.tab_browsers.clear();
                                    st.layout_cache.invalidate_tab(None);
                                    if st.web_visible {
                                        if let Some(u) = active_url
                                            .filter(|u| parse_http_url_authority(u).is_ok())
                                        {
                                            spawn_content_tab_cef(
                                                wid,
                                                st,
                                                active_tid,
                                                &u,
                                                bind_port,
                                                enabled,
                                                &mut incognito_ctx,
                                                active_sec,
                                                active_sy,
                                                false,
                                                &proxy,
                                                &shared_shell,
                                                &download_resolver,
                                            );
                                        }
                                    }
                                    st.sync_layout();
                                }
                            }
                            UiIpcCmd::WebBack => {
                                if let Some(st) = windows.get_mut(&wid) {
                                    let is_private = shared_shell
                                        .lock()
                                        .map(|s| s.private_browsing_active)
                                        .unwrap_or(false);
                                    perform_tab_go_back(
                                        wid,
                                        st,
                                        bind_port,
                                        is_private,
                                        &mut incognito_ctx,
                                        &proxy,
                                        &shared_shell,
                                        &download_resolver,
                                    );
                                }
                            }
                            UiIpcCmd::WebForward => {
                                if let Some(st) = windows.get_mut(&wid) {
                                    let is_private = shared_shell
                                        .lock()
                                        .map(|s| s.private_browsing_active)
                                        .unwrap_or(false);
                                    perform_tab_go_forward(
                                        wid,
                                        st,
                                        bind_port,
                                        is_private,
                                        &mut incognito_ctx,
                                        &proxy,
                                        &shared_shell,
                                        &download_resolver,
                                    );
                                }
                            }
                            UiIpcCmd::WebZoom { action } => {
                                if let Some(st) = windows.get(&wid) {
                                    perform_tab_zoom(st, action.as_str());
                                }
                            }
                            UiIpcCmd::WebReload => {
                                if let Some(st) = windows.get(&wid) {
                                    if let Some(b) = st.tab_browsers.get(&st.active_tab_id) {
                                        b.reload();
                                    }
                                }
                            }
                            UiIpcCmd::SyncTokens => {
                                let done_proxy = proxy.clone();
                                cef_runtime::run_cookie_hygiene_cef(
                                    &shared_shell,
                                    false,
                                    true,
                                    Some(Arc::new(move |tr, ad, mal, synced| {
                                        let _ = done_proxy.send_event(WinEvent::CookieHygieneDone {
                                            win_id: wid,
                                            mode: "sync_tokens",
                                            trackers: tr,
                                            ads: ad,
                                            malicious: mal,
                                            synced,
                                        });
                                    })),
                                );
                            }
                            UiIpcCmd::PurgeProviderTokens { target } => {
                                cef_runtime::purge_provider_cookies_cef(&target);
                                {
                                    let mut shell =
                                        shared_shell.lock().unwrap_or_else(|e| e.into_inner());
                                    let _ = shell.roaming.remove_tokens_by_provider_or_id(&target);
                                }
                                bump_state_revision();
                                if let Some(st) = windows.get(&wid) {
                                    emit_ui_sync(
                                        &st.ui_browser,
                                        &serde_json::json!({ "tokens_purged": true }),
                                    );
                                }
                            }
                            UiIpcCmd::ClearBrowsingData { clear_tokens } => {
                                if clear_tokens {
                                    cef_runtime::clear_all_cookies_cef();
                                    {
                                        let mut shell =
                                            shared_shell.lock().unwrap_or_else(|e| e.into_inner());
                                        shell.roaming.profile.history.clear();
                                        let _ = shell.roaming.save_profile();
                                        let _ = shell.roaming.clear_all_tokens();
                                    }
                                    history_dirty = false;
                                    last_history_disk_flush = std::time::Instant::now();
                                    bump_state_revision();
                                    if let Some(st) = windows.get(&wid) {
                                        emit_ui_sync(
                                            &st.ui_browser,
                                            &serde_json::json!({
                                                "browsing_cleared": true,
                                                "mode": "full_reset"
                                            }),
                                        );
                                    }
                                } else {
                                    let done_proxy = proxy.clone();
                                    cef_runtime::run_cookie_hygiene_cef(
                                        &shared_shell,
                                        true,
                                        false,
                                        Some(Arc::new(move |tr, ad, mal, synced| {
                                            let _ = done_proxy.send_event(
                                                WinEvent::CookieHygieneDone {
                                                    win_id: wid,
                                                    mode: "trackers_only",
                                                    trackers: tr,
                                                    ads: ad,
                                                    malicious: mal,
                                                    synced,
                                                },
                                            );
                                        })),
                                    );
                                }
                            }
                            UiIpcCmd::RevealDownload { path } => {
                                reveal_download_in_explorer(&path);
                            }
                            UiIpcCmd::OpenNewWindow => {
                                let sid = crate::roaming_store::RoamingSingularityStore::new_window_session_id();
                                let sess = WindowTabSession {
                                    is_secondary_live_window: true,
                                    ..Default::default()
                                };
                                if let Ok((nwid, nst)) = create_browser_window(
                                    elwt,
                                    bind_port,
                                    &cfg_clone,
                                    &shared_shell,
                                    &proxy,
                                    &download_resolver,
                                    sid,
                                    sess,
                                    None,
                                ) {
                                    bring_win32_window_to_front(nst.window.hwnd());
                                    windows.insert(nwid, nst);
                                }
                            }
                            UiIpcCmd::DetachTab {
                                tab_id,
                                url,
                                title,
                                favicon_url,
                                media_time_sec,
                                scroll_y,
                                force_new_window,
                                target_window_id,
                                is_only_tab,
                            } => {
                                let Some((live_url, live_sec, live_sy, clean_favicon, win_outer)) =
                                    windows.get_mut(&wid).map(|st| {
                                        st.close_ext_popup();
                                        let lu = st
                                            .tab_browsers
                                            .get(&tab_id)
                                            .and_then(read_live_http_url)
                                            .or_else(|| {
                                                let trimmed = url.trim();
                                                let is_settings = trimmed
                                                    == "singularity://settings"
                                                    || (trimmed
                                                        .starts_with("singularity://settings/")
                                                        && trimmed.len() <= 64
                                                        && trimmed["singularity://settings/".len()..]
                                                            .bytes()
                                                            .all(|b| {
                                                                b.is_ascii_alphanumeric()
                                                                    || b == b'-'
                                                                    || b == b'_'
                                                            }));
                                                if parse_http_url_authority(trimmed).is_ok()
                                                    || is_settings
                                                {
                                                    Some(trimmed.to_string())
                                                } else {
                                                    None
                                                }
                                            })
                                            .unwrap_or_default();
                                        let ls = st
                                            .tab_media_times
                                            .get(&tab_id)
                                            .copied()
                                            .or(media_time_sec)
                                            .filter(|&s| s >= 2);
                                        let lsy = st
                                            .tab_scroll_ys
                                            .get(&tab_id)
                                            .copied()
                                            .or(scroll_y)
                                            .filter(|&y| y > 0);
                                        let cf = favicon_url.and_then(|u| {
                                            let t = u.trim();
                                            if t.len() <= 512 && parse_http_url_authority(t).is_ok()
                                            {
                                                Some(t.to_string())
                                            } else {
                                                None
                                            }
                                        });
                                        let outer = st.window.outer_position().ok();
                                        (lu, ls, lsy, cf, outer)
                                    })
                                else {
                                    return;
                                };

                                let (cur_x, cur_y) = get_win32_cursor_pos();
                                let target_wid = if let Some(ref wanted_sid) = target_window_id {
                                    windows
                                        .iter()
                                        .find(|(&id, s)| id != wid && &s.session_id == wanted_sid)
                                        .map(|(&id, _)| id)
                                } else if !force_new_window {
                                    find_peer_in_process_window(&windows, wid, cur_x, cur_y)
                                } else {
                                    None
                                };

                                let mut transferred = false;
                                if let Some(twid) = target_wid {
                                    if let Some(target_st) = windows.get(&twid) {
                                        bring_win32_window_to_front(target_st.window.hwnd());
                                        emit_ui_sync(
                                            &target_st.ui_browser,
                                            &serde_json::json!({
                                                "adopt_external_tab": {
                                                    "url": live_url,
                                                    "title": title.chars().take(180).collect::<String>(),
                                                    "favicon_url": clean_favicon,
                                                    "media_time_sec": live_sec,
                                                    "scroll_y": live_sy
                                                }
                                            }),
                                        );
                                        transferred = true;
                                    }
                                } else if is_only_tab && !force_new_window {
                                    if let Some(st) = windows.get(&wid) {
                                        if st.window.is_maximized() {
                                            st.window.set_maximized(false);
                                        }
                                        st.window.set_outer_position(TaoPhysicalPosition::new(
                                            cur_x.saturating_sub(180),
                                            cur_y.saturating_sub(24).max(0),
                                        ));
                                    }
                                } else {
                                    // Instant in-process torn-off window (zero new OS process!)
                                    let drop_pos = if force_new_window {
                                        win_outer.map(|p| (p.x + 36, p.y + 36))
                                    } else {
                                        Some((
                                            cur_x.saturating_sub(180),
                                            cur_y.saturating_sub(24).max(0),
                                        ))
                                    };
                                    let mut detached_tabs = Vec::new();
                                    if !live_url.is_empty() {
                                        detached_tabs.push(SavedTabEntry {
                                            title: if title.trim().is_empty() {
                                                live_url.clone()
                                            } else {
                                                title.trim().chars().take(180).collect()
                                            },
                                            url: live_url,
                                            media_time_sec: live_sec,
                                            scroll_y: live_sy,
                                            group_id: None,
                                            favicon_url: clean_favicon,
                                        });
                                    }
                                    let new_sid = crate::roaming_store::RoamingSingularityStore::new_window_session_id();
                                    let new_sess = WindowTabSession {
                                        saved_tabs: detached_tabs,
                                        saved_tab_groups: Vec::new(),
                                        active_tab_index: 0,
                                        geometry: WindowGeometry::default(),
                                        is_detached_handoff: true,
                                        is_secondary_live_window: true,
                                        restored_windows_count: 0,
                                    };
                                    if let Ok((nwid, nst)) = create_browser_window(
                                        elwt,
                                        bind_port,
                                        &cfg_clone,
                                        &shared_shell,
                                        &proxy,
                                        &download_resolver,
                                        new_sid,
                                        new_sess,
                                        drop_pos,
                                    ) {
                                        bring_win32_window_to_front(nst.window.hwnd());
                                        windows.insert(nwid, nst);
                                        transferred = true;
                                    }
                                }

                                if transferred {
                                    if is_only_tab {
                                        if let Some(st) = windows.remove(&wid) {
                                            if let Ok(mut map) = cfg_clone.window_sessions.lock() {
                                                map.remove(&st.session_id);
                                            }
                                            {
                                                let shell = shared_shell
                                                    .lock()
                                                    .unwrap_or_else(|e| e.into_inner());
                                                shell.roaming.flush_async_persistence();
                                                shell
                                                    .roaming
                                                    .delete_window_session_for(&st.session_id);
                                            }
                                            st.close_cleanly();
                                        }
                                        if windows.is_empty() {
                                            cef_runtime::flush_cookie_store_cef_sync(
                                                Duration::from_millis(800),
                                            );
                                            if smoke_tracker.is_none() {
                                                crate::crash_guard::mark_clean_shutdown(&root_dir);
                                            }
                                            let _ = cef_runtime::drain_browsers_before_shutdown(
                                                Duration::from_millis(1200),
                                            );
                                            drop(incognito_ctx.take());
                                            drop(cef_guard.take());
                                            *control_flow = ControlFlow::Exit;
                                        }
                                    } else if let Some(st) = windows.get_mut(&wid) {
                                        st.tab_browsers.remove(&tab_id);
                                        st.layout_cache.invalidate_tab(Some(tab_id));
                                        st.tab_last_urls.remove(&tab_id);
                                        st.tab_media_times.remove(&tab_id);
                                        st.tab_scroll_ys.remove(&tab_id);
                                        st.tab_bg_intents.remove(&tab_id);
                                        st.last_favicon_at.remove(&tab_id);
                                        emit_ui_sync(
                                            &st.ui_browser,
                                            &serde_json::json!({
                                                "tab_detached": tab_id,
                                                "ram_active_count": st.tab_browsers.len()
                                            }),
                                        );
                                    }
                                }
                            }
                            UiIpcCmd::ShowTabContextMenu {
                                kind,
                                tab_id,
                                group_id,
                                tab_in_group,
                                can_reopen,
                                is_unloaded,
                                group_collapsed,
                                groups,
                                lang,
                            } => {
                                let is_fr = lang.as_deref().map(|l| l == "fr").unwrap_or_else(|| {
                                    shared_shell
                                        .lock()
                                        .map(|s| s.roaming.profile.language == "fr")
                                        .unwrap_or(false)
                                });
                                let other_window_ids: Vec<String> = if kind == "tab" {
                                    windows
                                        .iter()
                                        .filter(|(&id, _)| id != wid)
                                        .map(|(_, s)| s.session_id.clone())
                                        .collect()
                                } else {
                                    Vec::new()
                                };
                                let menu_result = windows.get_mut(&wid).and_then(|st| {
                                    st.close_ext_popup();
                                    let hwnd = st.window.hwnd() as *mut core::ffi::c_void;
                                    show_native_tab_context_menu(
                                        hwnd,
                                        &kind,
                                        tab_in_group,
                                        can_reopen,
                                        is_unloaded,
                                        group_collapsed,
                                        &groups,
                                        &other_window_ids,
                                        is_fr,
                                    )
                                });
                                if let Some((action, target_id)) = menu_result {
                                    if action == "new_window" {
                                        let _ = proxy.send_event(WinEvent::OpenNewWindowInProcess);
                                        return;
                                    }
                                    if let Some(st) = windows.get(&wid) {
                                        if matches!(
                                            action,
                                            "edit_group"
                                                | "add_to_new_group"
                                                | "new_group_empty"
                                                | "new_tab"
                                                | "new_tab_right"
                                                | "new_tab_in_group"
                                                | "open_settings"
                                        ) {
                                            st.ui_browser.focus();
                                        }
                                        emit_ui_sync(
                                            &st.ui_browser,
                                            &serde_json::json!({
                                                "ctx_action": action,
                                                "ctx_tab_id": tab_id,
                                                "ctx_group_id": group_id,
                                                "ctx_target_group_id": if action == "add_to_group" { target_id.as_deref() } else { None },
                                                "ctx_target_window_id": if action == "move_tab_to_window" { target_id.as_deref() } else { None }
                                            }),
                                        );
                                    }
                                }
                            }
                        }
                    }
                },
            },
            Event::LoopDestroyed => {
                // On Windows Shutdown / Restart / Logoff (`WM_ENDSESSION`), `tao` fires
                // `Event::LoopDestroyed` and immediately exits without firing `CloseRequested`.
                // Persist every live window, flush Chromium's cookie store, remove `running.lock`,
                // and arm `planned_restart.flag` so next boot restores all windows cleanly with
                // ZERO false-positive Crash Report popups!
                let had_open_windows = !windows.is_empty();
                if had_open_windows {
                    flush_live_crash_checkpoint(&windows, &cfg_clone, &shared_shell);
                    let drained: Vec<BrowserWindowState> =
                        windows.drain().map(|(_, st)| st).collect();
                    for mut st in drained {
                        st.close_ext_popup();
                        persist_window_on_close(&st, false, &cfg_clone, &shared_shell);
                        st.close_cleanly();
                    }
                    if history_dirty {
                        let shell = shared_shell.lock().unwrap_or_else(|e| e.into_inner());
                        let _ = shell.roaming.save_profile();
                        history_dirty = false;
                    }
                    cef_runtime::flush_cookie_store_cef_sync(Duration::from_millis(500));
                    {
                        let shell = shared_shell.lock().unwrap_or_else(|e| e.into_inner());
                        shell.roaming.flush_async_persistence();
                        shell.roaming.unregister_live_window();
                    }
                }
                if smoke_tracker.is_none() {
                    if had_open_windows {
                        crate::crash_guard::mark_planned_restart(&root_dir);
                    } else {
                        crate::crash_guard::mark_clean_shutdown(&root_dir);
                    }
                }
            }
            _ => {}
        }
    });
}

/// Validates that a URL is safe to pass to an external browser launcher (strict `http(s)://`,
/// valid authority, zero whitespace/control/shell metacharacters).
pub fn is_safe_launch_url(url: &str) -> bool {
    if parse_http_url_authority(url).is_err() {
        return false;
    }
    !url.bytes()
        .any(|b| b <= 0x20 || b == 0x7f || matches!(b, b'"' | b'\'' | b'<' | b'>' | b'|' | b'^' | b'`'))
}

/// Fallback browser launcher when native CEF runtime is unavailable or on non-Windows OSes.
pub fn launch_native_chromium_window(app_url: &str) {
    if !is_safe_launch_url(app_url) {
        return;
    }

    let profile_dir = crate::roaming_store::resolve_roaming_singularity_dir().join("chromium-profile");
    let default_dir = profile_dir.join("Default");
    let _ = std::fs::create_dir_all(&default_dir);

    let prefs_file = default_dir.join("Preferences");
    if !prefs_file.exists() {
        let prefs_json = r#"{
            "browser": {
                "has_seen_welcome_page": true,
                "custom_chrome_frame": false
            },
            "extensions": {
                "theme": { "system_theme": 2 }
            },
            "webkit": {
                "webprefs": { "preferred_color_scheme": 0 }
            }
        }"#;
        let _ = std::fs::write(&prefs_file, prefs_json);
    }

    let profile_arg = format!("--user-data-dir={}", profile_dir.display());
    let app_arg = format!("--app={}", app_url);
    let chromium_flags = [
        app_arg.as_str(),
        profile_arg.as_str(),
        "--window-size=1440,880",
        "--force-dark-mode",
        "--enable-features=WebUIDarkMode",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-sync",
        "--disable-background-networking",
    ];

    #[cfg(target_os = "windows")]
    {
        let win_candidates = [
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",
        ];
        for exe in win_candidates {
            if std::path::Path::new(exe).exists()
                && Command::new(exe).args(chromium_flags).spawn().is_ok()
            {
                return;
            }
        }
        // Safe Win32 ShellExecuteW fallback — NEVER invoke `cmd.exe /C start` (prevents command injection).
        use std::os::windows::ffi::OsStrExt;
        #[link(name = "shell32")]
        extern "system" {
            fn ShellExecuteW(
                hwnd: *mut core::ffi::c_void,
                lpOperation: *const u16,
                lpFile: *const u16,
                lpParameters: *const u16,
                lpDirectory: *const u16,
                nShowCmd: i32,
            ) -> isize;
        }
        let op: Vec<u16> = std::ffi::OsStr::new("open")
            .encode_wide()
            .chain(Some(0))
            .collect();
        let target: Vec<u16> = std::ffi::OsStr::new(app_url)
            .encode_wide()
            .chain(Some(0))
            .collect();
        unsafe {
            let _ = ShellExecuteW(
                core::ptr::null_mut(),
                op.as_ptr(),
                target.as_ptr(),
                core::ptr::null(),
                core::ptr::null(),
                1,
            );
        }
    }

    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("open").arg("--").arg(app_url).spawn();
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        for bin in [
            "chromium",
            "chromium-browser",
            "brave-browser",
            "google-chrome",
        ] {
            if Command::new(bin).args(chromium_flags).spawn().is_ok() {
                return;
            }
        }
        let _ = Command::new("xdg-open").arg(app_url).spawn();
    }
}

fn read_http_request(
    stream: &mut TcpStream,
    idle_timeout: Duration,
) -> Result<Option<ParsedHttpRequest>, HttpResponse> {
    let _ = stream.set_read_timeout(Some(idle_timeout));
    let mut raw = Zeroizing::new(Vec::with_capacity(4096));
    let mut chunk = Zeroizing::new([0u8; 4096]);
    let mut header_end: Option<usize> = None;

    while header_end.is_none() {
        let n = match stream.read(&mut chunk[..]) {
            Ok(0) => {
                if raw.is_empty() {
                    return Ok(None);
                }
                break;
            }
            Ok(n) => n,
            Err(_) => {
                if raw.is_empty() {
                    return Ok(None);
                }
                return Err(HttpResponse::text("400 Bad Request", "Malformed HTTP request"));
            }
        };
        if raw.is_empty() {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        }
        raw.extend_from_slice(&chunk[..n]);
        if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            header_end = Some(pos + 4);
            break;
        }
        if raw.len() > MAX_HTTP_HEADER_BYTES {
            return Err(HttpResponse::text(
                "431 Request Header Fields Too Large",
                "HTTP headers exceed maximum size",
            ));
        }
    }

    let Some(hdr_end) = header_end else {
        return Err(HttpResponse::text("400 Bad Request", "Incomplete HTTP headers"));
    };

    let header_str = String::from_utf8_lossy(&raw[..hdr_end - 4]);
    let mut lines = header_str.split("\r\n");
    let first_line = lines.next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_ascii_uppercase();
    let full_target = parts.next().unwrap_or("");
    if method.is_empty() || !full_target.starts_with('/') {
        return Err(HttpResponse::text("400 Bad Request", "Invalid HTTP request line"));
    }

    let mut headers = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }

    let max_body_bytes = if full_target == "/api/bookmarks/import-file"
        || full_target.starts_with("/api/bookmarks/import-file?")
    {
        MAX_BOOKMARK_IMPORT_BODY_BYTES
    } else {
        MAX_HTTP_BODY_BYTES
    };
    let content_length: usize = match headers.get("content-length") {
        Some(v) => match v.parse::<usize>() {
            Ok(len) if len <= max_body_bytes => len,
            Ok(_) => {
                return Err(HttpResponse::text(
                    "413 Payload Too Large",
                    "Request body exceeds maximum allowed size",
                ));
            }
            Err(_) => {
                return Err(HttpResponse::text("400 Bad Request", "Invalid Content-Length"));
            }
        },
        None => 0,
    };

    let mut body = Zeroizing::new(Vec::with_capacity(content_length));
    body.extend_from_slice(&raw[hdr_end..]);
    while body.len() < content_length {
        let remaining = content_length - body.len();
        let to_read = remaining.min(chunk.len());
        match stream.read(&mut chunk[..to_read]) {
            Ok(0) => break,
            Ok(n) => body.extend_from_slice(&chunk[..n]),
            Err(_) => {
                return Err(HttpResponse::text("400 Bad Request", "Truncated request body"));
            }
        }
    }
    if body.len() > content_length {
        body.truncate(content_length);
    }

    let (path, query) = match full_target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (full_target.to_string(), String::new()),
    };

    Ok(Some(ParsedHttpRequest {
        method,
        path,
        query,
        headers,
        body,
    }))
}

fn handle_ipc_connection(
    mut stream: TcpStream,
    shell_mutex: Arc<Mutex<SingularityBrowserShell>>,
    cfg: &ServerConfig,
    active_conns: &AtomicUsize,
) -> std::io::Result<()> {
    let _ = stream.set_nodelay(true);
    for req_idx in 0..MAX_KEEPALIVE_REQUESTS_PER_CONN {
        let timeout = if req_idx == 0 {
            Duration::from_secs(3)
        } else {
            Duration::from_millis(350)
        };
        match read_http_request(&mut stream, timeout) {
            Ok(Some(req)) => {
                let client_wants_close = req
                    .headers
                    .get("connection")
                    .map(|c| c.to_ascii_lowercase().contains("close"))
                    .unwrap_or(false);
                let pool_has_headroom =
                    active_conns.load(Ordering::Acquire) < (HTTP_WORKER_THREADS / 2);
                let keep_alive = !client_wants_close
                    && pool_has_headroom
                    && (req_idx + 1 < MAX_KEEPALIVE_REQUESTS_PER_CONN);
                let resp = dispatch_http_request(&req, cfg, &shell_mutex);
                write_http_response(&mut stream, &resp, keep_alive)?;
                if !keep_alive {
                    break;
                }
            }
            Ok(None) => break,
            Err(err_resp) => {
                let _ = write_http_response(&mut stream, &err_resp, false);
                break;
            }
        }
    }
    Ok(())
}

fn parse_json_body(req: &ParsedHttpRequest) -> serde_json::Value {
    if req.body.is_empty() {
        return serde_json::Value::Object(serde_json::Map::new());
    }
    serde_json::from_slice(&req.body)
        .unwrap_or_else(|_| serde_json::Value::Object(serde_json::Map::new()))
}

fn generate_unique_cred_id() -> String {
    let mut rnd = [0u8; 8];
    OsRng.fill_bytes(&mut rnd);
    format!("cred-{}-{}", unix_now(), hex::encode(rnd))
}

fn dispatch_http_request(
    req: &ParsedHttpRequest,
    cfg: &ServerConfig,
    shell_mutex: &Arc<Mutex<SingularityBrowserShell>>,
) -> HttpResponse {
    // 1. Strict Host header verification (blocks DNS rebinding attacks)
    let Some(host_hdr) = req.headers.get("host") else {
        return HttpResponse::text("400 Bad Request", "Missing Host header");
    };
    if !cfg.is_valid_host(host_hdr) {
        return HttpResponse::text("403 Forbidden", "Invalid Host header");
    }

    // 2. Reject cross-origin requests and non-same-origin fetches (blocks CSRF & localhost cross-port exfiltration)
    if let Some(origin) = req.headers.get("origin") {
        if !cfg.is_valid_origin(origin) {
            return HttpResponse::text("403 Forbidden", "Cross-origin request denied");
        }
    }
    if let Some(sfs) = req.headers.get("sec-fetch-site") {
        let s = sfs.trim();
        if !s.eq_ignore_ascii_case("same-origin") && !s.eq_ignore_ascii_case("none") {
            return HttpResponse::text("403 Forbidden", "Cross-site or cross-port fetch denied");
        }
    }

    // 3. Static shell HTML, public icons, cross-window tab transfer & sandboxed web proxy
    match req.path.as_str() {
        "/" | "/index.html" => {
            if req.method != "GET" {
                return HttpResponse::text("405 Method Not Allowed", "Method Not Allowed");
            }
            // Require the one-time CSPRNG bootstrap nonce so arbitrary local processes or content
            // tabs cannot harvest the per-session IPC token by issuing GET /.
            let q = parse_query_params(&req.query);
            if !cfg.consume_bootstrap_nonce(q.get("boot").map(String::as_str)) {
                return HttpResponse::text(
                    "403 Forbidden",
                    "Missing, invalid, or already-consumed Singularity bootstrap nonce.",
                );
            }
            return HttpResponse::new(
                "200 OK",
                "text/html; charset=utf-8",
                cfg.rendered_html.as_ref().clone(),
            )
            .with_header("X-Frame-Options", "DENY")
            .with_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';",
            );
        }
        "/api/logo.png" => {
            if req.method != "GET" {
                return HttpResponse::text("405 Method Not Allowed", "Method Not Allowed");
            }
            return HttpResponse::new("200 OK", "image/png", BRAND_LOGO_128_PNG.to_vec())
                .with_header("Cache-Control", "private, max-age=86400");
        }
        "/api/favicon" => {
            if req.method != "GET" {
                return HttpResponse::text("405 Method Not Allowed", "Method Not Allowed");
            }
            return handle_favicon_request(req, shell_mutex);
        }
        "/api/extensions/icon" => {
            if req.method != "GET" {
                return HttpResponse::text("405 Method Not Allowed", "Method Not Allowed");
            }
            let q = parse_query_params(&req.query);
            let ext_id = q.get("id").map(String::as_str).unwrap_or("");
            let root = {
                let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
                shell.roaming.root_dir().to_path_buf()
            };
            if let Some((bytes, mime)) = extensions::read_extension_icon(&root, ext_id) {
                return HttpResponse::new("200 OK", mime, bytes)
                    .with_header("X-Content-Type-Options", "nosniff")
                    .with_header("Cache-Control", "private, max-age=86400")
                    .with_header(
                        "Content-Security-Policy",
                        "default-src 'none'; style-src 'unsafe-inline'; sandbox",
                    );
            }
            return HttpResponse::text("404 Not Found", "Extension icon not found");
        }
        "/api/web_proxy" => {
            if req.method != "GET" {
                return HttpResponse::text("405 Method Not Allowed", "Method Not Allowed");
            }
            return handle_web_proxy(req, shell_mutex);
        }
        "/api/window/adopt_tab" => {
            if req.method != "POST" {
                return HttpResponse::text("405 Method Not Allowed", "POST required");
            }
            // Dedicated least-privilege 256-bit CSPRNG transfer token (separate from ipc_token)
            if !cfg.verify_transfer_token(
                req.headers
                    .get("x-singularity-transfer")
                    .map(String::as_str),
            ) {
                return HttpResponse::json(
                    "403 Forbidden",
                    &serde_json::json!({ "error": "Invalid cross-window transfer token." }),
                );
            }
            let Ok(mut payload) = serde_json::from_slice::<TabHandoffPayload>(&req.body) else {
                return HttpResponse::json(
                    "400 Bad Request",
                    &serde_json::json!({ "error": "Invalid tab handoff payload." }),
                );
            };
            let trimmed_url = payload.url.trim().to_string();
            let is_valid_settings = trimmed_url == "singularity://settings"
                || (trimmed_url.starts_with("singularity://settings/")
                    && trimmed_url.len() <= 64
                    && trimmed_url["singularity://settings/".len()..]
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
            if !trimmed_url.is_empty()
                && parse_http_url_authority(&trimmed_url).is_err()
                && !is_valid_settings
            {
                return HttpResponse::json(
                    "400 Bad Request",
                    &serde_json::json!({ "error": "Unsupported URL scheme." }),
                );
            }
            payload.url = trimmed_url;
            payload.title = payload.title.chars().take(180).collect();
            payload.favicon_url = payload.favicon_url.and_then(|u| {
                let t = u.trim();
                if t.len() <= 512 && parse_http_url_authority(t).is_ok() {
                    Some(t.to_string())
                } else {
                    None
                }
            });
            payload.media_time_sec = payload.media_time_sec.filter(|&s| s >= 2).map(|s| s.min(864_000));
            payload.scroll_y = payload.scroll_y.filter(|&y| y > 0).map(|y| y.min(10_000_000));
            if cfg.dispatch_adopt_tab(payload) {
                return HttpResponse::json_bytes("200 OK", b"{\"ok\":true}");
            }
            return HttpResponse::json(
                "503 Service Unavailable",
                &serde_json::json!({ "error": "Window event loop unavailable." }),
            );
        }
        _ => {}
    }

    // 4. All remaining `/api/*` endpoints REQUIRE the per-session constant-time IPC token
    if !cfg.verify_token(req.headers.get("x-singularity-token").map(String::as_str)) {
        return HttpResponse::json(
            "403 Forbidden",
            &serde_json::json!({ "error": "Missing or invalid Singularity IPC token." }),
        );
    }

    let params = parse_query_params(&req.query);

    // Automatically invalidate cached extension list & bump state rev on mutating POSTs
    if req.method == "POST" {
        if req.path.starts_with("/api/extensions/") {
            extensions::invalidate_extensions_cache();
        }
        if req.path != "/api/profile/save_tabs" && req.path != "/api/preconnect" {
            bump_state_revision();
        }
    }

    // Helper for strict POST enforcement on mutating / secret-handling endpoints
    let require_post = || -> Result<serde_json::Value, HttpResponse> {
        if req.method != "POST" {
            return Err(HttpResponse::json(
                "405 Method Not Allowed",
                &serde_json::json!({ "error": "POST method required." }),
            ));
        }
        Ok(parse_json_body(req))
    };

    match req.path.as_str() {
        "/api/state" => {
            let cur_rev = STATE_REVISION.load(Ordering::Acquire);
            if let Some(client_rev) = params.get("rev").and_then(|s| s.parse::<u64>().ok()) {
                if client_rev == cur_rev {
                    return HttpResponse::json(
                        "200 OK",
                        &serde_json::json!({ "unchanged": true, "rev": cur_rev }),
                    );
                }
            }
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            shell.enforce_vault_auto_lock();
            let ks = shell.core.mullvad_vpn.kill_switch();
            let mv_connected = shell.core.mullvad_vpn.is_tunnel_connected();
            let mv_real_tunnel = shell.core.mullvad_vpn.is_real_os_tunnel_active();
            let ks_blocked = ks.is_emergency_lockdown()
                || (ks.is_strict_enabled() && !ks.is_tunnel_established());

            let mut provider_counts: HashMap<String, usize> = HashMap::new();
            for s in &shell.roaming.tokens.sessions {
                *provider_counts.entry(s.provider.clone()).or_insert(0) += 1;
            }
            let installed_exts = extensions::list_extensions_cached(
                shell.roaming.root_dir(),
                &shell.roaming.profile.pinned_extensions,
            );
            let win_sess = req
                .headers
                .get("x-singularity-window")
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .and_then(|wid| {
                    cfg.window_sessions
                        .lock()
                        .ok()
                        .and_then(|m| m.get(wid).cloned())
                });
            let (
                saved_tabs,
                saved_tab_groups,
                active_tab_index,
                restored_windows_count,
                is_secondary_live_window,
                is_detached_handoff,
            ) = if let Some(sess) = win_sess {
                (
                    sess.saved_tabs,
                    sess.saved_tab_groups,
                    sess.active_tab_index,
                    sess.restored_windows_count,
                    sess.is_secondary_live_window,
                    sess.is_detached_handoff,
                )
            } else {
                (
                    shell.roaming.profile.saved_tabs.clone(),
                    shell.roaming.profile.saved_tab_groups.clone(),
                    shell.roaming.profile.active_tab_index,
                    shell.roaming.restored_windows_count,
                    shell.roaming.is_secondary_live_window,
                    shell.roaming.startup_handoff.is_some(),
                )
            };

            let dto = serde_json::json!({
                "rev": cur_rev,
                "version": env!("CARGO_PKG_VERSION"),
                "roaming_dir": shell.roaming.root_dir().to_string_lossy(),
                "onboarding_completed": shell.roaming.profile.onboarding_completed,
                "tutorial_v1_completed": shell.roaming.profile.tutorial_v1_completed,
                "language": shell.roaming.profile.language,
                "theme_id": shell.roaming.profile.theme_id,
                "default_search_engine": shell.roaming.profile.default_search_engine,
                "restore_session": shell.roaming.profile.restore_session,
                "tab_unload_mode": shell.roaming.profile.tab_unload_mode,
                "tab_unload_custom_minutes": shell.roaming.profile.tab_unload_custom_minutes,
                "tab_unload_effective_seconds": shell.roaming.effective_tab_unload_seconds(),
                "extensions": installed_exts,
                "saved_tabs": saved_tabs,
                "saved_tab_groups": saved_tab_groups,
                "merged_windows_count": shell.roaming.merged_windows_count,
                "restored_windows_count": restored_windows_count,
                "is_secondary_live_window": is_secondary_live_window,
                "is_detached_handoff": is_detached_handoff,
                "active_tab_index": active_tab_index,
                "private_browsing": shell.private_browsing_active,
                "bookmarks": shell.roaming.profile.bookmarks,
                "mullvad_authenticated": shell.core.mullvad_vpn.is_authenticated(),
                "mullvad_connected": mv_connected,
                "mullvad_real_tunnel": mv_real_tunnel,
                "mullvad_route": shell.core.mullvad_vpn.active_route().toolbar_badge_label(),
                "strict_killswitch": ks.is_strict_enabled(),
                "killswitch_blocked": ks_blocked,
                "blocked_requests": shell.core.adblocker.total_blocked_requests(),
                "dropped_packets": ks.dropped_packets(),
                "encrypted_tokens_count": shell.roaming.tokens.sessions.len(),
                "encrypted_providers": provider_counts,
                "vault_has_file": shell.roaming.has_encrypted_vault_on_disk(),
                "vault_locked": shell.vault.is_locked(),
            });
            HttpResponse::json("200 OK", &dto)
        }
        "/api/profile/complete_onboarding" => {
            let body = match require_post() {
                Ok(b) => b,
                Err(r) => return r,
            };
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(lang) = body.get("language").and_then(|v| v.as_str()) {
                if is_valid_language(lang) {
                    shell.roaming.profile.language = lang.to_string();
                }
            }
            if let Some(eng) = body.get("engine").and_then(|v| v.as_str()) {
                if !eng.trim().is_empty() {
                    shell.roaming.profile.default_search_engine = eng.trim().to_string();
                }
            }
            if let Some(theme) = body.get("theme_id").and_then(|v| v.as_str()) {
                if is_valid_theme_id(theme) {
                    shell.roaming.profile.theme_id = theme.to_string();
                }
            }
            if let Some(mode) = body.get("tab_unload_mode").and_then(|v| v.as_str()) {
                if matches!(mode, "low" | "medium" | "hard" | "custom") {
                    shell.roaming.profile.tab_unload_mode = mode.to_string();
                }
            }
            if let Some(mins) = body.get("tab_unload_custom_minutes").and_then(|v| v.as_u64()) {
                shell.roaming.profile.tab_unload_custom_minutes = mins.clamp(1, 43_200);
            }
            let eff_sec = shell.roaming.effective_tab_unload_seconds();
            shell.core.tab_manager.set_freeze_timeout_seconds(eff_sec);
            shell.roaming.profile.onboarding_completed = true;
            shell.roaming.profile.tutorial_v1_completed = true;
            let _ = shell.roaming.save_profile();
            HttpResponse::json(
                "200 OK",
                &serde_json::json!({
                    "ok": true,
                    "language": shell.roaming.profile.language,
                    "theme_id": shell.roaming.profile.theme_id
                }),
            )
        }
        "/api/profile/update_prefs" => {
            let body = match require_post() {
                Ok(b) => b,
                Err(r) => return r,
            };
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(lang) = body.get("language").and_then(|v| v.as_str()) {
                if is_valid_language(lang) {
                    shell.roaming.profile.language = lang.to_string();
                }
            }
            if let Some(eng) = body.get("engine").and_then(|v| v.as_str()) {
                if !eng.trim().is_empty() {
                    shell.roaming.profile.default_search_engine = eng.trim().to_string();
                }
            }
            if let Some(theme) = body.get("theme_id").and_then(|v| v.as_str()) {
                if is_valid_theme_id(theme) {
                    shell.roaming.profile.theme_id = theme.to_string();
                }
            }
            if let Some(tut) = body.get("tutorial_v1_completed").and_then(|v| v.as_bool()) {
                shell.roaming.profile.tutorial_v1_completed = tut;
            }
            if let Some(rs) = body.get("restore_session").and_then(|v| v.as_bool()) {
                shell.roaming.profile.restore_session = rs;
            }
            if let Some(pb) = body.get("private_browsing").and_then(|v| v.as_bool()) {
                shell.private_browsing_active = pb;
            }
            if let Some(mode) = body.get("tab_unload_mode").and_then(|v| v.as_str()) {
                if matches!(mode, "low" | "medium" | "hard" | "custom") {
                    shell.roaming.profile.tab_unload_mode = mode.to_string();
                }
            }
            if let Some(mins) = body.get("tab_unload_custom_minutes").and_then(|v| v.as_u64()) {
                shell.roaming.profile.tab_unload_custom_minutes = mins.clamp(1, 43_200);
            }
            let eff_sec = shell.roaming.effective_tab_unload_seconds();
            shell.core.tab_manager.set_freeze_timeout_seconds(eff_sec);
            let _ = shell.roaming.save_profile();
            let out = serde_json::json!({
                "ok": true,
                "language": shell.roaming.profile.language,
                "theme_id": shell.roaming.profile.theme_id,
                "tab_unload_mode": shell.roaming.profile.tab_unload_mode,
                "tab_unload_custom_minutes": shell.roaming.profile.tab_unload_custom_minutes,
                "tab_unload_effective_seconds": eff_sec
            });
            HttpResponse::json("200 OK", &out)
        }
        "/api/import/browsers" => {
            let browsers = browser_import::scan_installed_browsers();
            HttpResponse::json("200 OK", &serde_json::json!({ "browsers": browsers }))
        }
        "/api/import/execute" => {
            let body = match require_post() {
                Ok(b) => b,
                Err(r) => return r,
            };
            let browser_ids: Vec<String> = body
                .get("browser_ids")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(|s| s.trim().to_string()))
                        .filter(|s| !s.is_empty() && s.len() <= 32)
                        .take(16)
                        .collect()
                })
                .unwrap_or_default();
            let import_tabs = body
                .get("import_tabs")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            let import_bookmarks = body
                .get("import_bookmarks")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);

            let extracted = browser_import::extract_from_browser_ids(&browser_ids);

            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let mut imported_tabs_out: Vec<SavedTabEntry> = Vec::new();
            let mut imported_bm_count = 0usize;

            if import_tabs {
                let mut existing_urls: std::collections::HashSet<String> = shell
                    .roaming
                    .profile
                    .saved_tabs
                    .iter()
                    .map(|t| t.url.clone())
                    .collect();
                for t in extracted.tabs {
                    if shell.roaming.profile.saved_tabs.len() >= 150 {
                        break;
                    }
                    if parse_http_url_authority(&t.url).is_err() {
                        continue;
                    }
                    let entry = SavedTabEntry {
                        title: t.title,
                        url: t.url.clone(),
                        media_time_sec: None,
                        scroll_y: None,
                        group_id: None,
                        favicon_url: None,
                    };
                    if existing_urls.insert(t.url) {
                        shell.roaming.profile.saved_tabs.push(entry.clone());
                    }
                    imported_tabs_out.push(entry);
                }
            }

            if import_bookmarks {
                let mut existing_bms: std::collections::HashSet<String> = shell
                    .roaming
                    .profile
                    .bookmarks
                    .iter()
                    .map(|b| b.url.clone())
                    .collect();
                let ts = unix_now();
                for (i, bm) in extracted.bookmarks.into_iter().enumerate() {
                    if shell.roaming.profile.bookmarks.len() >= 2000 {
                        break;
                    }
                    if parse_http_url_authority(&bm.url).is_err() {
                        continue;
                    }
                    if existing_bms.insert(bm.url.clone()) {
                        shell.roaming.profile.bookmarks.push(BookmarkEntry {
                            id: format!("bm-imp-{}-{}", ts, i),
                            title: bm.title,
                            url: bm.url,
                        });
                        imported_bm_count += 1;
                    }
                }
            }

            let _ = shell.roaming.save_profile();
            let out = serde_json::json!({
                "ok": true,
                "imported_tabs": imported_tabs_out,
                "imported_tabs_count": imported_tabs_out.len(),
                "imported_bookmarks_count": imported_bm_count,
                "bookmarks": shell.roaming.profile.bookmarks
            });
            HttpResponse::json("200 OK", &out)
        }
        "/api/extensions/list" => {
            let (root, pinned) = {
                let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
                (
                    shell.roaming.root_dir().to_path_buf(),
                    shell.roaming.profile.pinned_extensions.clone(),
                )
            };
            let installed = extensions::list_extensions(&root, &pinned);
            let detected = extensions::scan_installed_browsers_extensions();
            let out = serde_json::json!({
                "extensions_dir": extensions::enabled_extensions_dir(&root).to_string_lossy(),
                "installed": installed,
                "catalog": extensions::curated_catalog(),
                "detected_browsers": detected
            });
            HttpResponse::json("200 OK", &out)
        }
        "/api/extensions/install_store" => {
            let body = match require_post() {
                Ok(b) => b,
                Err(r) => return r,
            };
            let input = body.get("input").and_then(|v| v.as_str()).unwrap_or("");
            let (root, pinned) = {
                let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
                (
                    shell.roaming.root_dir().to_path_buf(),
                    shell.roaming.profile.pinned_extensions.clone(),
                )
            };
            match extensions::install_from_chrome_web_store(&root, input, &pinned) {
                Ok(mut info) => {
                    let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
                    if !shell.roaming.profile.pinned_extensions.contains(&info.id) {
                        shell.roaming.profile.pinned_extensions.push(info.id.clone());
                        let _ = shell.roaming.save_profile();
                    }
                    info.pinned = true;
                    let all = extensions::list_extensions(
                        shell.roaming.root_dir(),
                        &shell.roaming.profile.pinned_extensions,
                    );
                    HttpResponse::json(
                        "200 OK",
                        &serde_json::json!({ "ok": true, "extension": info, "installed": all }),
                    )
                }
                Err(e) => HttpResponse::json(
                    "400 Bad Request",
                    &serde_json::json!({ "ok": false, "error": e }),
                ),
            }
        }
        "/api/extensions/install_local" => {
            let body = match require_post() {
                Ok(b) => b,
                Err(r) => return r,
            };
            let path_str = body.get("path").and_then(|v| v.as_str()).unwrap_or("");
            let explicit_id = body.get("id").and_then(|v| v.as_str());
            let (root, pinned) = {
                let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
                (
                    shell.roaming.root_dir().to_path_buf(),
                    shell.roaming.profile.pinned_extensions.clone(),
                )
            };
            match extensions::install_from_local_path(&root, path_str, explicit_id, &pinned) {
                Ok(mut info) => {
                    let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
                    if !shell.roaming.profile.pinned_extensions.contains(&info.id) {
                        shell.roaming.profile.pinned_extensions.push(info.id.clone());
                        let _ = shell.roaming.save_profile();
                    }
                    info.pinned = true;
                    let all = extensions::list_extensions(
                        shell.roaming.root_dir(),
                        &shell.roaming.profile.pinned_extensions,
                    );
                    HttpResponse::json(
                        "200 OK",
                        &serde_json::json!({ "ok": true, "extension": info, "installed": all }),
                    )
                }
                Err(e) => HttpResponse::json(
                    "400 Bad Request",
                    &serde_json::json!({ "ok": false, "error": e }),
                ),
            }
        }
        "/api/extensions/toggle" => {
            let body = match require_post() {
                Ok(b) => b,
                Err(r) => return r,
            };
            let id = body.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let enabled = body.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true);
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            match extensions::set_extension_enabled(shell.roaming.root_dir(), id, enabled) {
                Ok(()) => {
                    let all = extensions::list_extensions(
                        shell.roaming.root_dir(),
                        &shell.roaming.profile.pinned_extensions,
                    );
                    HttpResponse::json(
                        "200 OK",
                        &serde_json::json!({ "ok": true, "installed": all }),
                    )
                }
                Err(e) => HttpResponse::json(
                    "400 Bad Request",
                    &serde_json::json!({ "ok": false, "error": e }),
                ),
            }
        }
        "/api/extensions/pin" => {
            let body = match require_post() {
                Ok(b) => b,
                Err(r) => return r,
            };
            let id = body.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let pinned = body.get("pinned").and_then(|v| v.as_bool()).unwrap_or(true);
            if !extensions::is_valid_extension_dir_id(id) {
                return HttpResponse::json(
                    "400 Bad Request",
                    &serde_json::json!({ "ok": false, "error": "Invalid extension ID." }),
                );
            }
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            if pinned {
                if !shell.roaming.profile.pinned_extensions.iter().any(|p| p == id) {
                    shell.roaming.profile.pinned_extensions.push(id.to_string());
                }
            } else {
                shell.roaming.profile.pinned_extensions.retain(|p| p != id);
            }
            let _ = shell.roaming.save_profile();
            let all = extensions::list_extensions(
                shell.roaming.root_dir(),
                &shell.roaming.profile.pinned_extensions,
            );
            HttpResponse::json(
                "200 OK",
                &serde_json::json!({ "ok": true, "installed": all }),
            )
        }
        "/api/extensions/remove" => {
            let body = match require_post() {
                Ok(b) => b,
                Err(r) => return r,
            };
            let id = body.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            match extensions::remove_extension(shell.roaming.root_dir(), id) {
                Ok(()) => {
                    shell.roaming.profile.pinned_extensions.retain(|p| p != id);
                    let _ = shell.roaming.save_profile();
                    let all = extensions::list_extensions(
                        shell.roaming.root_dir(),
                        &shell.roaming.profile.pinned_extensions,
                    );
                    HttpResponse::json(
                        "200 OK",
                        &serde_json::json!({ "ok": true, "installed": all }),
                    )
                }
                Err(e) => HttpResponse::json(
                    "400 Bad Request",
                    &serde_json::json!({ "ok": false, "error": e }),
                ),
            }
        }
        "/api/profile/save_tabs" => {
            let body = match require_post() {
                Ok(b) => b,
                Err(r) => return r,
            };
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(tabs_val) = body.get("tabs") {
                if let Ok(tabs) = serde_json::from_value::<Vec<SavedTabEntry>>(tabs_val.clone()) {
                    let clean_groups: Vec<SavedTabGroup> = body
                        .get("tab_groups")
                        .and_then(|v| serde_json::from_value::<Vec<SavedTabGroup>>(v.clone()).ok())
                        .unwrap_or_default()
                        .into_iter()
                        .take(32)
                        .filter_map(|mut g| {
                            g.id = g
                                .id
                                .chars()
                                .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
                                .take(48)
                                .collect();
                            if g.id.is_empty() {
                                return None;
                            }
                            g.title = g
                                .title
                                .chars()
                                .filter(|c| !c.is_control())
                                .take(40)
                                .collect::<String>()
                                .trim()
                                .to_string();
                            if !is_valid_hex_color(&g.color) {
                                g.color = "#f0b254".to_string();
                            }
                            Some(g)
                        })
                        .collect();
                    let valid_group_ids: std::collections::HashSet<String> =
                        clean_groups.iter().map(|g| g.id.clone()).collect();

                    let clean_tabs: Vec<SavedTabEntry> = tabs
                        .into_iter()
                        .filter(|t| parse_http_url_authority(&t.url).is_ok())
                        .take(128)
                        .map(|mut t| {
                            t.media_time_sec = t
                                .media_time_sec
                                .filter(|&s| s >= 2)
                                .map(|s| s.min(864_000));
                            t.scroll_y = t
                                .scroll_y
                                .filter(|&y| y > 0)
                                .map(|y| y.min(10_000_000));
                            t.group_id = t
                                .group_id
                                .and_then(|gid| {
                                    if valid_group_ids.contains(&gid) {
                                        Some(gid)
                                    } else {
                                        None
                                    }
                                });
                            t.favicon_url = t.favicon_url.and_then(|u| {
                                let trimmed = u.trim();
                                if trimmed.len() <= 512 && parse_http_url_authority(trimmed).is_ok()
                                {
                                    Some(trimmed.to_string())
                                } else {
                                    None
                                }
                            });
                            t
                        })
                        .collect();
                    let active_idx = body
                        .get("active_index")
                        .and_then(|v| v.as_u64())
                        .map(|i| i as usize)
                        .unwrap_or(0)
                        .min(clean_tabs.len().saturating_sub(1));
                    let req_win_id = req
                        .headers
                        .get("x-singularity-window")
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty());
                    if let Some(wid) = req_win_id {
                        let (geom, all_live_sessions) = if let Ok(mut map) = cfg.window_sessions.lock() {
                            let entry = map.entry(wid.clone()).or_default();
                            entry.saved_tabs = clean_tabs.clone();
                            entry.saved_tab_groups = clean_groups.clone();
                            entry.active_tab_index = active_idx;
                            let g = entry.geometry;
                            let pid = std::process::id();
                            let now_ts = crate::roaming_store::unix_now();
                            let snap: Vec<crate::roaming_store::WindowSessionFile> = map
                                .iter()
                                .filter(|(_, s)| !s.saved_tabs.is_empty())
                                .map(|(id, s)| crate::roaming_store::WindowSessionFile {
                                    window_id: id.clone(),
                                    pid,
                                    updated_unix: now_ts,
                                    active_tab_index: s.active_tab_index,
                                    tabs: s.saved_tabs.clone(),
                                    tab_groups: s.saved_tab_groups.clone(),
                                    geometry: s.geometry,
                                    closed_while_other_live: false,
                                })
                                .collect();
                            (g, snap)
                        } else {
                            (WindowGeometry::default(), Vec::new())
                        };
                        if !shell.private_browsing_active && shell.roaming.profile.restore_session {
                            let _ = shell.roaming.save_window_session_for(
                                &wid,
                                &clean_tabs,
                                &clean_groups,
                                active_idx,
                                geom,
                                false,
                                true,
                            );
                            if !all_live_sessions.is_empty() {
                                shell.roaming.save_crash_checkpoint(&all_live_sessions);
                            }
                        }
                        if shell.roaming.window_id() == wid {
                            shell.roaming.profile.saved_tabs = clean_tabs;
                            shell.roaming.profile.saved_tab_groups = clean_groups;
                            shell.roaming.profile.active_tab_index = active_idx;
                            shell.roaming.schedule_save_profile();
                        }
                    } else {
                        shell.roaming.profile.saved_tabs = clean_tabs;
                        shell.roaming.profile.saved_tab_groups = clean_groups;
                        shell.roaming.profile.active_tab_index = active_idx;
                        shell.roaming.schedule_save_profile();
                    }
                }
            }
            HttpResponse::json_bytes("200 OK", b"{\"ok\":true}")
        }
        "/api/bookmarks/toggle" => {
            let body = match require_post() {
                Ok(b) => b,
                Err(r) => return r,
            };
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let url = body.get("url").and_then(|v| v.as_str()).unwrap_or("");
            let title = body.get("title").and_then(|v| v.as_str()).unwrap_or("");
            let added = shell.roaming.toggle_bookmark(title, url);
            let out = serde_json::json!({
                "added": added,
                "bookmarks": shell.roaming.profile.bookmarks
            });
            HttpResponse::json("200 OK", &out)
        }
        "/api/bookmarks/add" => {
            let body = match require_post() {
                Ok(b) => b,
                Err(r) => return r,
            };
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let mut url = body
                .get("url")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_string();
            let title = body.get("title").and_then(|v| v.as_str()).unwrap_or("");
            if !url.is_empty() && !url.starts_with("http://") && !url.starts_with("https://") {
                url = format!("https://{}", url);
            }
            if parse_http_url_authority(&url).is_ok()
                && !shell.roaming.profile.bookmarks.iter().any(|b| b.url == url)
            {
                let _ = shell.roaming.toggle_bookmark(title, &url);
            }
            let out = serde_json::json!({ "bookmarks": shell.roaming.profile.bookmarks });
            HttpResponse::json("200 OK", &out)
        }
        "/api/bookmarks/delete" => {
            let body = match require_post() {
                Ok(b) => b,
                Err(r) => return r,
            };
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let id = body.get("id").and_then(|v| v.as_str()).unwrap_or("");
            shell.roaming.profile.bookmarks.retain(|b| b.id != id);
            let _ = shell.roaming.save_profile();
            let out = serde_json::json!({ "bookmarks": shell.roaming.profile.bookmarks });
            HttpResponse::json("200 OK", &out)
        }
        "/api/bookmarks/import-file" => {
            let body = match require_post() {
                Ok(b) => b,
                Err(r) => return r,
            };
            let filename = body
                .get("filename")
                .and_then(|v| v.as_str())
                .unwrap_or("bookmarks.html");
            let content = body
                .get("content")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if content.trim().is_empty() {
                return HttpResponse::json(
                    "400 Bad Request",
                    &serde_json::json!({ "error": "Bookmark file content is empty." }),
                );
            }
            let parsed = browser_import::parse_exported_bookmarks_file(filename, content);
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let mut existing_bms: HashSet<String> = shell
                .roaming
                .profile
                .bookmarks
                .iter()
                .map(|b| b.url.clone())
                .collect();
            let ts = unix_now();
            let mut imported_count = 0usize;
            let mut skipped_duplicates = 0usize;
            for (i, bm) in parsed.into_iter().enumerate() {
                if shell.roaming.profile.bookmarks.len() >= 2000 {
                    break;
                }
                if parse_http_url_authority(&bm.url).is_err() {
                    continue;
                }
                if existing_bms.insert(bm.url.clone()) {
                    shell.roaming.profile.bookmarks.push(BookmarkEntry {
                        id: format!("bm-file-{}-{}", ts, i),
                        title: bm.title,
                        url: bm.url,
                    });
                    imported_count += 1;
                } else {
                    skipped_duplicates += 1;
                }
            }
            let _ = shell.roaming.save_profile();
            let out = serde_json::json!({
                "ok": true,
                "imported_count": imported_count,
                "skipped_duplicates": skipped_duplicates,
                "total_count": shell.roaming.profile.bookmarks.len(),
                "bookmarks": shell.roaming.profile.bookmarks
            });
            HttpResponse::json("200 OK", &out)
        }
        "/api/bookmarks/export-html" => {
            if req.method != "GET" {
                return HttpResponse::text("405 Method Not Allowed", "Method Not Allowed");
            }
            let pairs: Vec<(String, String)> = {
                let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
                shell
                    .roaming
                    .profile
                    .bookmarks
                    .iter()
                    .map(|b| (b.title.clone(), b.url.clone()))
                    .collect()
            };
            let html = browser_import::format_netscape_bookmarks_html(&pairs);
            HttpResponse::new("200 OK", "text/html; charset=utf-8", html.into_bytes())
                .with_header(
                    "Content-Disposition",
                    "attachment; filename=\"singularity-bookmarks.html\"",
                )
        }
        "/api/history/list" => {
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let body = serde_json::to_vec(&shell.roaming.profile.history).unwrap_or_default();
            HttpResponse::new("200 OK", "application/json; charset=utf-8", body)
        }
        "/api/history/clear" => {
            if let Err(r) = require_post() {
                return r;
            }
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            shell.roaming.profile.history.clear();
            let _ = shell.roaming.save_profile();
            HttpResponse::json_bytes("200 OK", b"{\"ok\":true}")
        }
        "/api/tokens/list" => {
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            #[derive(Serialize)]
            struct TokenSummaryDto {
                id: String,
                provider: String,
                domain: String,
                token_name: String,
                masked_preview: String,
                http_only: bool,
                secure: bool,
                updated_unix: u64,
                kind: String,
            }
            let items: Vec<TokenSummaryDto> = shell
                .roaming
                .tokens
                .sessions
                .iter()
                .map(|t| TokenSummaryDto {
                    id: t.id.clone(),
                    provider: t.provider.clone(),
                    domain: t.domain.clone(),
                    token_name: t.token_name.clone(),
                    masked_preview: t.masked_preview(),
                    http_only: t.http_only,
                    secure: t.secure,
                    updated_unix: t.updated_unix,
                    kind: t.kind.clone(),
                })
                .collect();
            let out = serde_json::json!({
                "roaming_tokens_file": shell.roaming.tokens_file_path().to_string_lossy(),
                "cipher": if cfg!(target_os = "windows") {
                    "XChaCha20-Poly1305 AEAD + Windows DPAPI (CryptProtectData)"
                } else {
                    "XChaCha20-Poly1305 AEAD (OS Keyring / User-Bound Master Key)"
                },
                "items": items
            });
            HttpResponse::json("200 OK", &out)
        }
        "/api/tokens/add_manual" => {
            let body = match require_post() {
                Ok(b) => b,
                Err(r) => return r,
            };
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let provider = body
                .get("provider")
                .and_then(|v| v.as_str())
                .unwrap_or("OAuth")
                .trim()
                .to_string();
            let domain = body
                .get("domain")
                .and_then(|v| v.as_str())
                .unwrap_or("local.token")
                .trim()
                .to_string();
            let name = body
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("access_token")
                .trim()
                .to_string();
            let secret = body
                .get("secret")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if secret.trim().is_empty() {
                return HttpResponse::json(
                    "400 Bad Request",
                    &serde_json::json!({ "error": "Token value cannot be empty." }),
                );
            }
            let rec = EncryptedAuthTokenRecord {
                id: format!("{}::{}::{}", provider, domain, name),
                provider,
                domain,
                path: "/".to_string(),
                token_name: name,
                secret_value: secret,
                http_only: true,
                secure: true,
                expires_unix: None,
                updated_unix: unix_now(),
                kind: "oauth_token".to_string(),
            };
            match shell.roaming.upsert_token(rec) {
                Ok(_) => HttpResponse::json_bytes("200 OK", b"{\"ok\":true}"),
                Err(e) => HttpResponse::json("500 Internal Server Error", &serde_json::json!({ "error": e })),
            }
        }
        "/api/tokens/delete" => {
            let body = match require_post() {
                Ok(b) => b,
                Err(r) => return r,
            };
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let target = body.get("target").and_then(|v| v.as_str()).unwrap_or("");
            match shell.roaming.remove_tokens_by_provider_or_id(target) {
                Ok(removed) => {
                    HttpResponse::json("200 OK", &serde_json::json!({ "ok": true, "removed": removed }))
                }
                Err(e) => HttpResponse::json(
                    "500 Internal Server Error",
                    &serde_json::json!({ "ok": false, "error": e }),
                ),
            }
        }
        "/api/tokens/clear_all" => {
            if let Err(r) = require_post() {
                return r;
            }
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            match shell.roaming.clear_all_tokens() {
                Ok(()) => HttpResponse::json_bytes("200 OK", b"{\"ok\":true}"),
                Err(e) => HttpResponse::json(
                    "500 Internal Server Error",
                    &serde_json::json!({ "ok": false, "error": e }),
                ),
            }
        }
        "/api/settings/categories" => {
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            #[derive(Serialize)]
            struct CatDto {
                slug: String,
                name: String,
                count: usize,
            }
            let cats: Vec<CatDto> = shell
                .core
                .settings
                .category_counts()
                .into_iter()
                .map(|(c, count)| CatDto {
                    slug: c.slug().to_string(),
                    name: c.display_name().to_string(),
                    count,
                })
                .collect();
            let body = serde_json::to_vec(&cats).unwrap_or_default();
            HttpResponse::new("200 OK", "application/json; charset=utf-8", body)
        }
        "/api/settings/query" => {
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let cat_slug = params.get("cat").map(|s| s.as_str()).unwrap_or("");
            let q = params.get("q").map(|s| s.as_str()).unwrap_or("");
            let scroll: usize = params
                .get("scroll")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            let height: usize = params
                .get("height")
                .and_then(|s| s.parse().ok())
                .unwrap_or(800);
            let row_h: usize = params
                .get("row_h")
                .and_then(|s| s.parse().ok())
                .unwrap_or(56);

            let cat_filter = SettingCategory::ALL
                .into_iter()
                .find(|c| c.slug() == cat_slug);

            let vp = shell
                .core
                .settings
                .query_virtualized(cat_filter, q, scroll, height, row_h);

            #[derive(Serialize)]
            struct RowDto {
                id: usize,
                key: String,
                title: String,
                description: String,
                val_type: String,
                val_raw: String,
                is_modified: bool,
            }
            #[derive(Serialize)]
            struct VpDto {
                total_matching: usize,
                top_spacer_px: usize,
                bottom_spacer_px: usize,
                rows: Vec<RowDto>,
            }

            let rows = vp
                .visible_slice
                .into_iter()
                .map(|e| {
                    let (vt, vr) = match &e.current_value {
                        SettingValue::Bool(b) => ("Bool", b.to_string()),
                        SettingValue::Int(i) => ("Int", i.to_string()),
                        SettingValue::Float(f) => ("Float", format!("{:.2}", f)),
                        SettingValue::Text(s) => ("Text", s.clone()),
                        SettingValue::ColorHex(c) => ("ColorHex", c.clone()),
                    };
                    RowDto {
                        id: e.id,
                        key: e.key.clone(),
                        title: e.title.clone(),
                        description: e.description.clone(),
                        val_type: vt.into(),
                        val_raw: vr,
                        is_modified: e.is_modified(),
                    }
                })
                .collect();

            let out = VpDto {
                total_matching: vp.total_matching_items,
                top_spacer_px: vp.top_spacer_height_px,
                bottom_spacer_px: vp.bottom_spacer_height_px,
                rows,
            };
            let body = serde_json::to_vec(&out).unwrap_or_default();
            HttpResponse::new("200 OK", "application/json; charset=utf-8", body)
        }
        "/api/settings/set" => {
            let body = match require_post() {
                Ok(b) => b,
                Err(r) => return r,
            };
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let key = body.get("key").and_then(|v| v.as_str()).unwrap_or("");
            let vtype = body.get("type").and_then(|v| v.as_str()).unwrap_or("");
            let val = body
                .get("val")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            let parsed_val = match vtype {
                "Bool" => Some(SettingValue::Bool(val == "true")),
                "Int" => val.parse::<i64>().ok().map(SettingValue::Int),
                "Float" => val
                    .parse::<f64>()
                    .ok()
                    .filter(|f| f.is_finite())
                    .map(SettingValue::Float),
                "ColorHex" => Some(SettingValue::ColorHex(val)),
                _ => Some(SettingValue::Text(val)),
            };
            let Some(sv) = parsed_val else {
                return HttpResponse::json(
                    "400 Bad Request",
                    &serde_json::json!({ "ok": false, "error": "Invalid setting value." }),
                );
            };
            match shell.core.settings.set(key, sv) {
                Ok(_) => {
                    shell.sync_runtime_from_settings();
                    if let Ok(toml_str) = shell.core.settings.export_toml(true) {
                        let _ = shell.roaming.save_settings_toml(&toml_str);
                    }
                    HttpResponse::json_bytes("200 OK", b"{\"ok\":true}")
                }
                Err(e) => HttpResponse::json(
                    "400 Bad Request",
                    &serde_json::json!({ "ok": false, "error": e.to_string() }),
                ),
            }
        }
        "/api/settings/reset_all" => {
            if let Err(r) = require_post() {
                return r;
            }
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let count = shell.core.settings.reset_all_to_defaults();
            shell.sync_runtime_from_settings();
            if let Ok(toml_str) = shell.core.settings.export_toml(true) {
                let _ = shell.roaming.save_settings_toml(&toml_str);
            }
            HttpResponse::json(
                "200 OK",
                &serde_json::json!({ "ok": true, "reset_count": count }),
            )
        }
        "/api/settings/export_toml" => {
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let toml_str = shell
                .core
                .settings
                .export_toml(false)
                .unwrap_or_else(|e| e.to_string());
            HttpResponse::text("200 OK", &toml_str)
        }
        "/api/mullvad/status" => {
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let route = shell.core.mullvad_vpn.active_route();
            let entry_label = format!(
                "{} ({})",
                route.entry_relay.country_code.to_uppercase(),
                route.entry_relay.hostname
            );
            let exit_label = format!(
                "{} ({})",
                route.exit_relay.country_code.to_uppercase(),
                route.exit_relay.hostname
            );
            let ks = shell.core.mullvad_vpn.kill_switch();
            let assign = shell.core.mullvad_vpn.device_assignment();
            let body = serde_json::json!({
                "authenticated": shell.core.mullvad_vpn.is_authenticated(),
                "connected": shell.core.mullvad_vpn.is_tunnel_connected(),
                "real_tunnel": shell.core.mullvad_vpn.is_real_os_tunnel_active(),
                "masked_account": shell.core.mullvad_vpn.masked_account().unwrap_or_else(|| "Not configured".into()),
                "pubkey": shell.core.mullvad_vpn.local_public_key_base64(),
                "ipv4": assign.map(|a| a.ipv4_address.as_str()).unwrap_or("Direct (Singularity Shield)"),
                "dns": assign.map(|a| a.in_tunnel_dns_v4.as_str()).unwrap_or("DoH / Local Anti-Tracking"),
                "route_badge": route.toolbar_badge_label(),
                "entry_hostname": route.entry_relay.hostname,
                "exit_hostname": route.exit_relay.hostname,
                "multihop": route.multihop_enabled,
                "entry_label": entry_label,
                "exit_label": exit_label,
                "strict_killswitch": ks.is_strict_enabled(),
                "emergency_lockdown": ks.is_emergency_lockdown(),
                "relays": shell.core.mullvad_vpn.available_relays(),
            });
            HttpResponse::json("200 OK", &body)
        }
        "/api/mullvad/auth" => {
            let body = match require_post() {
                Ok(b) => b,
                Err(r) => return r,
            };
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let acc = body
                .get("account")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let remember = body
                .get("remember")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            match shell.core.mullvad_vpn.authenticate_16_digit_account(&acc) {
                Ok(_) => {
                    let _ = shell.core.mullvad_vpn.connect_tunnel(true, true);
                    if remember {
                        shell.roaming.tokens.saved_mullvad_account = Some(acc);
                        shell.roaming.profile.mullvad_auto_connect = true;
                    } else {
                        shell.roaming.tokens.saved_mullvad_account = None;
                        shell.roaming.profile.mullvad_auto_connect = false;
                    }
                    let _ = shell.roaming.save_tokens();
                    let _ = shell.roaming.save_profile();
                    HttpResponse::json(
                        "200 OK",
                        &serde_json::json!({
                            "ok": true,
                            "real_tunnel": shell.core.mullvad_vpn.is_real_os_tunnel_active()
                        }),
                    )
                }
                Err(e) => HttpResponse::json(
                    "400 Bad Request",
                    &serde_json::json!({ "error": e.to_string() }),
                ),
            }
        }
        "/api/mullvad/disconnect" => {
            if let Err(r) = require_post() {
                return r;
            }
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            shell.core.mullvad_vpn.disconnect_and_engage_killswitch();
            shell.roaming.profile.mullvad_auto_connect = false;
            let _ = shell.roaming.save_profile();
            HttpResponse::json_bytes("200 OK", b"{\"ok\":true}")
        }
        "/api/mullvad/logout" => {
            if let Err(r) = require_post() {
                return r;
            }
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            shell.core.mullvad_vpn.logout();
            shell.core.mullvad_vpn.kill_switch().set_strict_enabled(false);
            shell.core.mullvad_vpn.kill_switch().set_block_lan_rfc1918(false);
            shell.roaming.tokens.saved_mullvad_account = None;
            shell.roaming.profile.mullvad_auto_connect = false;
            shell.roaming.profile.strict_mullvad_killswitch = false;
            let _ = shell.roaming.save_tokens();
            let _ = shell.roaming.save_profile();
            HttpResponse::json_bytes("200 OK", b"{\"ok\":true}")
        }
        "/api/mullvad/switch" => {
            let body = match require_post() {
                Ok(b) => b,
                Err(r) => return r,
            };
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let entry = body
                .get("entry")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let exit = body
                .get("exit")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let multihop = body
                .get("multihop")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            if shell
                .core
                .mullvad_vpn
                .switch_relay_route(&entry, &exit, multihop)
                .is_ok()
            {
                shell.roaming.profile.mullvad_entry_relay = entry;
                shell.roaming.profile.mullvad_exit_relay = exit;
                shell.roaming.profile.mullvad_multihop = multihop;
                let _ = shell.roaming.save_profile();
            }
            HttpResponse::json_bytes("200 OK", b"{\"ok\":true}")
        }
        "/api/mullvad/set_strict_ks" => {
            let body = match require_post() {
                Ok(b) => b,
                Err(r) => return r,
            };
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let strict = body
                .get("strict")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            shell.core.mullvad_vpn.kill_switch().set_strict_enabled(strict);
            shell.core.mullvad_vpn.kill_switch().set_block_lan_rfc1918(strict);
            shell.roaming.profile.strict_mullvad_killswitch = strict;
            let _ = shell.roaming.save_profile();
            HttpResponse::json_bytes("200 OK", b"{\"ok\":true}")
        }
        "/api/mullvad/toggle_killswitch" => {
            if let Err(r) = require_post() {
                return r;
            }
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let ks = shell.core.mullvad_vpn.kill_switch();
            let next = !ks.is_emergency_lockdown();
            ks.set_emergency_lockdown(next);
            HttpResponse::json("200 OK", &serde_json::json!({ "lockdown": next }))
        }
        "/api/mullvad/test_packet" => {
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let sample_http3 =
                b"GET / HTTP/3\r\nHost: am.i.mullvad.net\r\nUser-Agent: Singularity/1.0\r\n\r\n";
            match shell
                .core
                .mullvad_vpn
                .transmit_browser_packet("am.i.mullvad.net", sample_http3)
            {
                Ok(wg_pkt) => {
                    let hex_preview: String = wg_pkt
                        .iter()
                        .take(96)
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(" ");
                    let msg = format!(
                        "WireGuard Type-4 frame encrypted in Rust (local cryptographic simulation — no OS TUN tunnel active)\n\
                         • HTTP/3 payload     : {} bytes\n\
                         • DAITA padded block : 1360 bytes\n\
                         • WireGuard frame    : {} bytes (16B header + 1360B ciphertext + 16B Poly1305 tag)\n\
                         • Preview (96 bytes) : {} ...",
                        sample_http3.len(),
                        wg_pkt.len(),
                        hex_preview
                    );
                    HttpResponse::text("200 OK", &msg)
                }
                Err(e) => HttpResponse::text("200 OK", &e),
            }
        }
        "/api/vault/status" => {
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            shell.enforce_vault_auto_lock();
            let count = shell.vault.credentials().map(|c| c.len()).unwrap_or(0);
            let out = serde_json::json!({
                "has_file": shell.roaming.has_encrypted_vault_on_disk(),
                "vault_path": shell.roaming.vault_file_path().to_string_lossy(),
                "locked": shell.vault.is_locked(),
                "count": count
            });
            HttpResponse::json("200 OK", &out)
        }
        "/api/vault/unlock" => {
            let body = match require_post() {
                Ok(b) => b,
                Err(r) => return r,
            };
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let master = Zeroizing::new(
                body.get("master")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            );
            if master.len() < 4 {
                return HttpResponse::json(
                    "400 Bad Request",
                    &serde_json::json!({ "error": "Master password must be at least 4 characters long." }),
                );
            }

            if shell.roaming.has_encrypted_vault_on_disk() {
                match shell.roaming.read_vault_envelope_from_disk() {
                    Ok(env_str) => match shell.vault.import_and_unlock_vault(&env_str, master.as_bytes()) {
                        Ok(count) => {
                            shell.set_verified_vault_master(master.as_bytes().to_vec());
                            HttpResponse::json(
                                "200 OK",
                                &serde_json::json!({ "ok": true, "count": count }),
                            )
                        }
                        Err(_) => HttpResponse::json(
                            "401 Unauthorized",
                            &serde_json::json!({ "error": "Incorrect master password (AEAD authentication failed)." }),
                        ),
                    },
                    Err(e) => HttpResponse::json(
                        "500 Internal Server Error",
                        &serde_json::json!({ "error": e }),
                    ),
                }
            } else {
                shell.vault.reset_unlocked_empty();
                match shell.vault.export_encrypted_vault(master.as_bytes()) {
                    Ok(sealed) => match shell.roaming.write_vault_envelope_to_disk(&sealed) {
                        Ok(()) => {
                            shell.set_verified_vault_master(master.as_bytes().to_vec());
                            HttpResponse::json_bytes("200 OK", b"{\"ok\":true,\"created\":true}")
                        }
                        Err(e) => {
                            shell.lock_vault();
                            HttpResponse::json(
                                "500 Internal Server Error",
                                &serde_json::json!({ "error": e }),
                            )
                        }
                    },
                    Err(e) => {
                        shell.lock_vault();
                        HttpResponse::json(
                            "500 Internal Server Error",
                            &serde_json::json!({ "error": e.to_string() }),
                        )
                    }
                }
            }
        }
        "/api/vault/lock" => {
            if let Err(r) = require_post() {
                return r;
            }
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            shell.lock_vault();
            HttpResponse::json_bytes("200 OK", b"{\"ok\":true}")
        }
        "/api/vault/list" => {
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            shell.enforce_vault_auto_lock();
            let now_sec = unix_now();

            let Ok(creds) = shell.vault.credentials() else {
                return HttpResponse::json_bytes("200 OK", b"[]");
            };

            let items: Vec<serde_json::Value> = creds
                .iter()
                .map(|c| {
                    let totp_res = c
                        .totp_secret_base32
                        .as_deref()
                        .filter(|s| !s.trim().is_empty())
                        .and_then(|sec| {
                            generate_totp_code(
                                sec,
                                now_sec,
                                c.totp_period_sec,
                                c.totp_digits,
                                c.totp_algorithm,
                            )
                            .ok()
                        });
                    let (totp_code, totp_rem) = match totp_res {
                        Some((code, rem)) => (Some(code), rem),
                        None => (None, c.totp_period_sec.max(1)),
                    };
                    serde_json::json!({
                        "id": c.id,
                        "origin": c.origin_url,
                        "username": c.username,
                        "totp_code": totp_code,
                        "totp_rem": totp_rem,
                    })
                })
                .collect();

            let body = serde_json::to_vec(&items).unwrap_or_else(|_| b"[]".to_vec());
            HttpResponse::new("200 OK", "application/json; charset=utf-8", body)
        }
        "/api/vault/secret" => {
            let body = match require_post() {
                Ok(b) => b,
                Err(r) => return r,
            };
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            shell.enforce_vault_auto_lock();
            let id = body.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let found_secret = shell
                .vault
                .credentials()
                .ok()
                .and_then(|creds| creds.iter().find(|c| c.id == id).map(|c| c.password_secret.clone()));
            if let Some(secret) = found_secret {
                shell.touch_vault_activity();
                return HttpResponse::json(
                    "200 OK",
                    &serde_json::json!({ "ok": true, "secret": secret }),
                );
            }
            HttpResponse::json_bytes("200 OK", b"{\"ok\":false}")
        }
        "/api/vault/add" => {
            let body = match require_post() {
                Ok(b) => b,
                Err(r) => return r,
            };
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            shell.enforce_vault_auto_lock();
            if shell.vault.is_locked() {
                return HttpResponse::json(
                    "401 Unauthorized",
                    &serde_json::json!({ "error": "Vault is locked." }),
                );
            }

            let origin = body.get("origin").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
            let user = body.get("user").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
            let pass = body.get("pass").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let totp = body
                .get("totp")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from);

            if origin.is_empty() || pass.is_empty() {
                return HttpResponse::json(
                    "400 Bad Request",
                    &serde_json::json!({ "error": "Site and password are required." }),
                );
            }

            let id = generate_unique_cred_id();
            if let Err(e) = shell.vault.add_credential(VaultCredentialEntry {
                id: id.clone(),
                origin_url: origin,
                username: user,
                password_secret: pass,
                totp_secret_base32: totp,
                totp_algorithm: TotpAlgorithm::Sha1,
                totp_digits: 6,
                totp_period_sec: 30,
                notes: String::new(),
            }) {
                return HttpResponse::json("400 Bad Request", &serde_json::json!({ "error": e }));
            }

            if let Err(e) = shell.persist_unlocked_vault_to_disk() {
                let _ = shell.vault.remove_credential(&id);
                return HttpResponse::json(
                    "500 Internal Server Error",
                    &serde_json::json!({ "error": format!("Failed to save vault to disk: {}", e) }),
                );
            }
            HttpResponse::json_bytes("200 OK", b"{\"ok\":true}")
        }
        "/api/vault/delete" => {
            let body = match require_post() {
                Ok(b) => b,
                Err(r) => return r,
            };
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            shell.enforce_vault_auto_lock();
            if shell.vault.is_locked() {
                return HttpResponse::json(
                    "401 Unauthorized",
                    &serde_json::json!({ "error": "Vault is locked." }),
                );
            }
            let id = body.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let _ = shell.vault.remove_credential(id);
            if let Err(e) = shell.persist_unlocked_vault_to_disk() {
                return HttpResponse::json(
                    "500 Internal Server Error",
                    &serde_json::json!({ "error": format!("Failed to save vault to disk: {}", e) }),
                );
            }
            HttpResponse::json_bytes("200 OK", b"{\"ok\":true}")
        }
        "/api/vault/audit" => {
            let body = match require_post() {
                Ok(b) => b,
                Err(r) => return r,
            };
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let pw = Zeroizing::new(
                body.get("pw")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            );
            let (breached, entropy) = shell.vault.audit_password_security(&pw);
            HttpResponse::json(
                "200 OK",
                &serde_json::json!({ "breached": breached, "entropy": entropy }),
            )
        }
        "/api/vault/export" => {
            if let Err(r) = require_post() {
                return r;
            }
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            shell.enforce_vault_auto_lock();
            match shell.export_verified_vault() {
                Ok(exported) => HttpResponse::text("200 OK", &exported),
                Err(e) => HttpResponse::text("400 Bad Request", &e),
            }
        }
        "/api/preconnect" => {
            let body = match require_post() {
                Ok(b) => b,
                Err(r) => return r,
            };
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let url = body.get("url").and_then(|v| v.as_str()).unwrap_or("");
            let _ = shell.core.preconnect_pool.evaluate_link_intent(
                url,
                HoverIntentSignal::MouseOver {
                    dwell_ms: 80,
                    velocity_px_per_sec: 50.0,
                },
            );
            HttpResponse::json_bytes("200 OK", b"{\"ok\":true}")
        }
        "/api/open_isolated_window" => {
            let body = match require_post() {
                Ok(b) => b,
                Err(r) => return r,
            };
            let url = body.get("url").and_then(|v| v.as_str()).unwrap_or("");
            if let Ok((host, _port)) = parse_http_url_authority(url) {
                let allowed = {
                    let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
                    shell
                        .core
                        .mullvad_vpn
                        .kill_switch()
                        .authorize_outbound_packet(&host)
                        .is_ok()
                };
                if allowed && is_safe_launch_url(url) {
                    launch_native_chromium_window(url);
                }
            }
            HttpResponse::json_bytes("200 OK", b"{\"ok\":true}")
        }
        "/api/navigate_check" => {
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let raw_url = params.get("url").cloned().unwrap_or_default();
            let scrubbed_url = UBlockNetworkEngine::scrub_tracking_query_params(&raw_url);
            let (host, _port) = match parse_http_url_authority(&scrubbed_url) {
                Ok(hp) => hp,
                Err(reason) => {
                    return HttpResponse::json(
                        "200 OK",
                        &serde_json::json!({
                            "allowed": false,
                            "reason": reason,
                            "scrubbed_url": scrubbed_url,
                        }),
                    );
                }
            };

            if let Err(ks_err) = shell
                .core
                .mullvad_vpn
                .kill_switch()
                .authorize_outbound_packet(&host)
            {
                return HttpResponse::json(
                    "200 OK",
                    &serde_json::json!({
                        "allowed": false,
                        "reason": ks_err.to_string(),
                        "scrubbed_url": scrubbed_url,
                    }),
                );
            }

            let decision = shell.core.adblocker.evaluate_request(
                &scrubbed_url,
                &host,
                &host,
                NetworkResourceType::MainFrameDocument,
            );
            if let FilterDecision::BlockedByDomainRule(rule)
            | FilterDecision::BlockedByPatternRule(rule) = decision
            {
                return HttpResponse::json(
                    "200 OK",
                    &serde_json::json!({
                        "allowed": false,
                        "reason": format!("Ad/tracker domain blocked by Singularity Shield ({})", rule),
                        "scrubbed_url": scrubbed_url,
                    }),
                );
            }

            HttpResponse::json(
                "200 OK",
                &serde_json::json!({
                    "allowed": true,
                    "scrubbed_url": scrubbed_url,
                }),
            )
        }
        "/api/updater/check" => match crate::updater::check_for_updates() {
            Ok(info) => {
                let body = serde_json::to_vec(&info).unwrap_or_default();
                HttpResponse::new("200 OK", "application/json; charset=utf-8", body)
            }
            Err(err) => HttpResponse::json(
                "200 OK",
                &serde_json::json!({ "error": err, "current_version": env!("CARGO_PKG_VERSION") }),
            ),
        },
        "/api/updater/run" => {
            if let Err(r) = require_post() {
                return r;
            }
            match crate::updater::execute_self_update() {
                Ok(msg) => HttpResponse::json(
                    "200 OK",
                    &serde_json::json!({ "status": "ok", "message": msg }),
                ),
                Err(err) => HttpResponse::json(
                    "200 OK",
                    &serde_json::json!({ "status": "error", "error": err }),
                ),
            }
        }
        _ => HttpResponse::text("404 Not Found", "Not Found"),
    }
}

fn handle_web_proxy(
    req: &ParsedHttpRequest,
    shell_mutex: &Arc<Mutex<SingularityBrowserShell>>,
) -> HttpResponse {
    const PROXY_SANDBOX_CSP: &str =
        "sandbox allow-scripts allow-forms allow-popups; base-uri https: http:;";

    let params = parse_query_params(&req.query);
    let raw_url = params
        .get("url")
        .cloned()
        .unwrap_or_else(|| "https://example.com".into());
    let scrubbed_url = UBlockNetworkEngine::scrub_tracking_query_params(&raw_url);

    let (host, port) = match parse_http_url_authority(&scrubbed_url) {
        Ok(hp) => hp,
        Err(reason) => {
            let blocked_html = render_proxy_error_page(&scrubbed_url, "INVALID URL", reason);
            return HttpResponse::new("200 OK", "text/html; charset=utf-8", blocked_html.into_bytes())
                .with_header("Content-Security-Policy", PROXY_SANDBOX_CSP);
        }
    };

    // Clone the lock-free Arc<AtomicSocketKillSwitch> and DROP `shell_mutex` before running
    // blocking DNS so slow DNS never stalls the main UI event loop!
    let kill_switch = {
        let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
        shell.core.mullvad_vpn.kill_switch().clone()
    };
    let initial_ips = match kill_switch.authorize_outbound_host_and_dns(&host, port) {
        Ok(ips) => ips,
        Err(ks_err) => {
            let blocked_html = render_proxy_error_page(
                &scrubbed_url,
                "SSRF / NETWORK KILL-SWITCH ACTIVE",
                &ks_err.to_string(),
            );
            return HttpResponse::new(
                "200 OK",
                "text/html; charset=utf-8",
                blocked_html.into_bytes(),
            )
            .with_header("Content-Security-Policy", PROXY_SANDBOX_CSP);
        }
    };

    {
        let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
        let decision = shell.core.adblocker.evaluate_request(
            &scrubbed_url,
            &host,
            &host,
            NetworkResourceType::MainFrameDocument,
        );
        if let FilterDecision::BlockedByDomainRule(rule)
        | FilterDecision::BlockedByPatternRule(rule) = decision
        {
            let blocked_html = render_proxy_error_page(
                &scrubbed_url,
                "SINGULARITY SHIELD — TRACKER BLOCKED",
                &format!("Filter rule: {}", rule),
            );
            return HttpResponse::new(
                "200 OK",
                "text/html; charset=utf-8",
                blocked_html.into_bytes(),
            )
            .with_header("Content-Security-Policy", PROXY_SANDBOX_CSP);
        }

        if !shell.private_browsing_active {
            shell.roaming.record_history(&host, &scrubbed_url);
        }
    }

    let html = fetch_and_rewrite_external_page(&scrubbed_url, initial_ips, shell_mutex);
    HttpResponse::new("200 OK", "text/html; charset=utf-8", html.into_bytes())
        .with_header("Content-Security-Policy", PROXY_SANDBOX_CSP)
}

/// Spawns `curl` on non-Windows platforms. On Windows, Singularity uses native `winhttp.dll`
/// (`crate::winhttp_client`) so ZERO `curl.exe` child processes are ever spawned at runtime.
#[cfg(not(target_os = "windows"))]
fn system_curl_command() -> Command {
    Command::new("curl")
}

fn fetch_and_rewrite_external_page(
    url: &str,
    initial_ips: Vec<IpAddr>,
    shell_mutex: &Arc<Mutex<SingularityBrowserShell>>,
) -> String {
    let mut current_url = if url.contains("duckduckgo.com")
        && url.contains("q=")
        && !url.contains("html.duckduckgo.com")
    {
        let query_part = url.split_once('?').map(|(_, q)| q).unwrap_or("");
        format!("https://html.duckduckgo.com/html/?{}", query_part)
    } else {
        url.to_string()
    };

    let uniform_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
    let mut pinned_ips = if current_url == url {
        Some(initial_ips)
    } else {
        None
    };

    for _hop in 0..=MAX_PROXY_REDIRECTS {
        let (host, port) = match parse_http_url_authority(&current_url) {
            Ok(hp) => hp,
            Err(reason) => {
                return render_proxy_error_page(&current_url, "REDIRECT BLOCKED", reason);
            }
        };

        let _resolved_ips = match pinned_ips.take() {
            Some(ips) if !ips.is_empty() => ips,
            _ => {
                // Drop `shell_mutex` BEFORE DNS resolution to avoid stalling the UI thread!
                let ks = {
                    let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
                    shell.core.mullvad_vpn.kill_switch().clone()
                };
                let ips = match ks.authorize_outbound_host_and_dns(&host, port) {
                    Ok(ips) => ips,
                    Err(e) => {
                        return render_proxy_error_page(
                            &current_url,
                            "SSRF / KILL-SWITCH REDIRECT BLOCKED",
                            &e.to_string(),
                        );
                    }
                };
                let decision = {
                    let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
                    shell.core.adblocker.evaluate_request(
                        &current_url,
                        &host,
                        &host,
                        NetworkResourceType::MainFrameDocument,
                    )
                };
                if let FilterDecision::BlockedByDomainRule(rule)
                | FilterDecision::BlockedByPatternRule(rule) = decision
                {
                    return render_proxy_error_page(
                        &current_url,
                        "SINGULARITY SHIELD — TRACKER BLOCKED",
                        &format!("Filter rule: {}", rule),
                    );
                }
                ips
            }
        };

        #[cfg(target_os = "windows")]
        let (status_code, location, body_vec) = {
            let Ok(resp) = crate::winhttp_client::winhttp_get_no_redirect(
                &current_url,
                uniform_ua,
                &[
                    (
                        "Accept",
                        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    ),
                    ("Accept-Language", "en-US,en;q=0.9"),
                ],
                5_000,
                10_000,
                MAX_PROXY_BODY_BYTES,
            ) else {
                break;
            };
            (resp.status_code, resp.location, resp.body)
        };

        #[cfg(not(target_os = "windows"))]
        let (status_code, location, body_vec) = {
            let mut cmd = system_curl_command();
            cmd.args([
                "-sS",
                "-i",
                "-g",
                "--proto",
                "=http,https",
                "--proto-redir",
                "=http,https",
                "--max-filesize",
                &MAX_PROXY_BODY_BYTES.to_string(),
                "--connect-timeout",
                "6",
                "--max-time",
                "10",
                "--compressed",
                "-A",
                uniform_ua,
                "-H",
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "-H",
                "Accept-Language: en-US,en;q=0.9",
            ]);

            // Pin curl to the already-validated global IP to defeat TOCTOU DNS rebinding
            let bare_host = host
                .trim_start_matches('[')
                .trim_end_matches(']')
                .trim_end_matches('.');
            if !bare_host.is_empty() && bare_host.parse::<IpAddr>().is_err() {
                if let Some(ip) = _resolved_ips.first() {
                    let ip_str = match ip {
                        IpAddr::V4(v4) => v4.to_string(),
                        IpAddr::V6(v6) => format!("[{}]", v6),
                    };
                    cmd.arg("--resolve")
                        .arg(format!("{}:{}:{}", bare_host, port, ip_str));
                }
            }
            cmd.arg("--").arg(&current_url);

            let Ok(out) = cmd.output() else {
                break;
            };
            if !out.status.success() || out.stdout.is_empty() {
                break;
            }

            let Some((code, loc, body_slice)) = parse_curl_http_response(&out.stdout) else {
                break;
            };
            (code, loc, body_slice.to_vec())
        };

        if matches!(status_code, 301 | 302 | 303 | 307 | 308) {
            let Some(loc) = location else {
                break;
            };
            let Some(next_url) = resolve_redirect_url(&current_url, &loc) else {
                return render_proxy_error_page(
                    &current_url,
                    "INVALID REDIRECT",
                    "The redirect target uses a disallowed scheme or invalid syntax.",
                );
            };
            current_url = UBlockNetworkEngine::scrub_tracking_query_params(&next_url);
            continue;
        }

        let capped = &body_vec[..body_vec.len().min(MAX_PROXY_BODY_BYTES)];
        let raw_html = String::from_utf8_lossy(capped).into_owned();
        let origin_base = escape_html_str(&extract_origin_base(&current_url));

        let base_injection = format!(
            "<base href=\"{}\" target=\"_self\">\
             <style>\
               html {{ color-scheme: dark; }}\
               ::-webkit-scrollbar {{ width: 8px; height: 8px; }}\
               ::-webkit-scrollbar-track {{ background: #050508; }}\
               ::-webkit-scrollbar-thumb {{ background: #262632; border-radius: 4px; }}\
               ::-webkit-scrollbar-thumb:hover {{ background: #f0b254; }}\
             </style>",
            origin_base
        );

        // UTF-8-safe ASCII case-insensitive search (never slices using lowercased byte indices!)
        if let Some(idx) = find_ascii_case_insensitive(&raw_html, "<head>") {
            let insert_pos = idx + 6;
            let mut rewritten = String::with_capacity(raw_html.len() + base_injection.len() + 16);
            rewritten.push_str(&raw_html[..insert_pos]);
            rewritten.push_str(&base_injection);
            rewritten.push_str(&raw_html[insert_pos..]);
            return rewritten;
        }
        return format!("{}{}", base_injection, raw_html);
    }

    render_proxy_error_page(
        &current_url,
        "ISOLATED CONNECTION REQUIRED",
        "The remote site restricts proxy access or exceeded the redirect limit.",
    )
}

/// Parses `curl -i` output (skipping intermediate `1xx` / proxy `CONNECT` headers)
/// into `(status_code, optional Location header, body_slice)`.
#[cfg(not(target_os = "windows"))]
fn parse_curl_http_response(raw: &[u8]) -> Option<(u16, Option<String>, &[u8])> {
    let mut slice = raw;
    loop {
        let sep = slice.windows(4).position(|w| w == b"\r\n\r\n")?;
        let header_block = std::str::from_utf8(&slice[..sep]).ok()?;
        let body = &slice[sep + 4..];

        let mut lines = header_block.split("\r\n");
        let status_line = lines.next()?;
        let mut status_parts = status_line.split_whitespace();
        let _http_ver = status_parts.next()?;
        let code: u16 = status_parts.next()?.parse().ok()?;

        // Skip intermediate `100 Continue` or HTTP proxy `200 Connection established` tunnels
        if (100..200).contains(&code)
            || (code == 200
                && status_line
                    .to_ascii_lowercase()
                    .contains("connection established"))
        {
            slice = body;
            continue;
        }

        let mut location = None;
        for line in lines {
            if let Some((k, v)) = line.split_once(':') {
                if k.trim().eq_ignore_ascii_case("location") {
                    location = Some(v.trim().to_string());
                }
            }
        }
        return Some((code, location, body));
    }
}

fn resolve_redirect_url(base_url: &str, location: &str) -> Option<String> {
    let loc = location.trim();
    if loc.is_empty() {
        return None;
    }
    if loc.starts_with("https://") || loc.starts_with("http://") {
        return Some(loc.to_string());
    }
    if loc.starts_with("//") {
        let scheme = if base_url.starts_with("http://") {
            "http:"
        } else {
            "https:"
        };
        return Some(format!("{}{}", scheme, loc));
    }
    if loc.starts_with('/') {
        let scheme_idx = base_url.find("://")?;
        let after = &base_url[scheme_idx + 3..];
        let auth_end = after.find(&['/', '?', '#'][..]).unwrap_or(after.len());
        let origin = &base_url[..scheme_idx + 3 + auth_end];
        return Some(format!("{}{}", origin, loc));
    }
    if loc.contains(':') {
        // Reject non-HTTP schemes like `javascript:`, `file:`, `data:`
        return None;
    }
    Some(format!("{}{}", extract_origin_base(base_url), loc))
}

/// ASCII case-insensitive byte search that always returns a valid UTF-8 char boundary in `haystack`
/// for any pure-ASCII `needle` (avoids panics on characters like Turkish `'İ'` whose lowercase
/// representation changes UTF-8 byte length).
pub fn find_ascii_case_insensitive(haystack: &str, needle: &str) -> Option<usize> {
    let h = haystack.as_bytes();
    let n = needle.as_bytes();
    if n.is_empty() || n.len() > h.len() {
        return None;
    }
    h.windows(n.len()).position(|w| w.eq_ignore_ascii_case(n))
}

/// Escapes all HTML-significant characters (`&`, `<`, `>`, `"`, `'`) to prevent XSS.
pub fn escape_html_str(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 16);
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

fn render_proxy_error_page(url: &str, title: &str, detail: &str) -> String {
    let safe_title = escape_html_str(title);
    let safe_detail = escape_html_str(detail);
    let safe_url = escape_html_str(url);
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<style>
  body {{
    margin: 0; padding: 48px 24px; background: #000000; color: #f5f3ee;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    display: flex; align-items: center; justify-content: center; min-height: 80vh;
  }}
  .card {{
    max-width: 580px; width: 100%; background: rgba(12, 14, 20, 0.9);
    border: 1px solid rgba(255, 255, 255, 0.09); border-radius: 14px; padding: 26px;
  }}
  .badge {{
    display: inline-block; padding: 3px 9px; border-radius: 6px; font-size: 10.5px;
    font-weight: 600; background: rgba(240, 178, 84, 0.14); color: #ffdf9e;
    border: 1px solid rgba(240, 178, 84, 0.34); margin-bottom: 12px; font-family: monospace;
  }}
  h2 {{ margin: 0 0 8px 0; font-size: 17px; }}
  p {{ color: rgba(226, 224, 218, 0.66); font-size: 12.5px; line-height: 1.6; margin: 0 0 16px 0; }}
  .url-box {{
    background: #05060a; border: 1px solid rgba(255, 255, 255, 0.07); padding: 9px 12px;
    border-radius: 7px; font-family: monospace; font-size: 11.5px; color: #ffdf9e;
    word-break: break-all; margin-bottom: 14px;
  }}
  .hint {{ color: rgba(226, 224, 218, 0.48); font-size: 11.5px; }}
</style>
</head>
<body>
  <div class="card">
    <div class="badge">SINGULARITY • NETWORK PROTECTION</div>
    <h2>{}</h2>
    <p>{}</p>
    <div class="url-box">{}</div>
    <div class="hint">This page is isolated inside a sandbox with no access to the Singularity browser shell.</div>
  </div>
</body>
</html>"#,
        safe_title, safe_detail, safe_url
    )
}

fn is_valid_hex_color(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 7 && b[0] == b'#' && b[1..].iter().all(|c| c.is_ascii_hexdigit())
}

fn detect_favicon_mime(bytes: &[u8]) -> Option<&'static str> {
    if bytes.len() < 4 || bytes.len() > 131_072 {
        return None;
    }
    if bytes.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]) {
        return Some("image/png");
    }
    if bytes.starts_with(&[0x00, 0x00, 0x01, 0x00]) || bytes.starts_with(&[0x00, 0x00, 0x02, 0x00])
    {
        return Some("image/x-icon");
    }
    if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        return Some("image/gif");
    }
    if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return Some("image/jpeg");
    }
    if bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP" {
        return Some("image/webp");
    }
    if let Ok(txt) = std::str::from_utf8(bytes) {
        let trimmed = txt.trim_start_matches('\u{feff}').trim_start();
        if (trimmed.starts_with("<svg") || trimmed.starts_with("<?xml"))
            && find_ascii_case_insensitive(trimmed, "<svg").is_some()
            && find_ascii_case_insensitive(trimmed, "<script").is_none()
            && find_ascii_case_insensitive(trimmed, "foreignobject").is_none()
        {
            return Some("image/svg+xml");
        }
    }
    None
}

fn is_valid_favicon_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.contains('.')
        && !host.starts_with('.')
        && !host.ends_with('.')
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
}

fn favicon_ram_cache() -> &'static Mutex<HashMap<String, (Vec<u8>, &'static str)>> {
    static CACHE: OnceLock<Mutex<HashMap<String, (Vec<u8>, &'static str)>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

static ACTIVE_FAVICON_FETCHES: AtomicUsize = AtomicUsize::new(0);
const MAX_CONCURRENT_FAVICON_FETCHES: usize = 6;

struct FaviconFetchGuard;
impl Drop for FaviconFetchGuard {
    fn drop(&mut self) {
        ACTIVE_FAVICON_FETCHES.fetch_sub(1, Ordering::AcqRel);
    }
}

fn try_acquire_favicon_fetch_slot() -> Option<FaviconFetchGuard> {
    for attempt in 0..8 {
        let cur = ACTIVE_FAVICON_FETCHES.load(Ordering::Acquire);
        if cur < MAX_CONCURRENT_FAVICON_FETCHES
            && ACTIVE_FAVICON_FETCHES
                .compare_exchange(cur, cur + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            return Some(FaviconFetchGuard);
        }
        if attempt < 7 {
            std::thread::sleep(Duration::from_millis(25));
        }
    }
    None
}

fn fetch_favicon_bytes_safe(
    start_url: &str,
    shell_mutex: &Arc<Mutex<SingularityBrowserShell>>,
) -> Option<(Vec<u8>, &'static str)> {
    const MAX_FAVICON_BYTES: usize = 131_072;
    let uniform_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
    let mut current_url = start_url.to_string();

    for _hop in 0..=3 {
        let (host, port) = parse_http_url_authority(&current_url).ok()?;
        // Lock `shell_mutex` ONLY for fast in-memory adblocker + Arc<KillSwitch> clone,
        // then DROP it BEFORE blocking DNS so slow DNS never freezes the UI thread!
        let kill_switch = {
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let decision = shell.core.adblocker.evaluate_request(
                &current_url,
                &host,
                &host,
                NetworkResourceType::Image,
            );
            if matches!(
                decision,
                FilterDecision::BlockedByDomainRule(_) | FilterDecision::BlockedByPatternRule(_)
            ) {
                return None;
            }
            shell.core.mullvad_vpn.kill_switch().clone()
        };
        let _resolved_ips = kill_switch
            .authorize_outbound_host_and_dns(&host, port)
            .ok()?;

        #[cfg(target_os = "windows")]
        let (status_code, location, body_vec) = {
            let resp = crate::winhttp_client::winhttp_get_no_redirect(
                &current_url,
                uniform_ua,
                &[(
                    "Accept",
                    "image/avif,image/webp,image/png,image/svg+xml,image/x-icon,image/*;q=0.8,*/*;q=0.5",
                )],
                1_500,
                2_500,
                MAX_FAVICON_BYTES,
            )
            .ok()?;
            (resp.status_code, resp.location, resp.body)
        };

        #[cfg(not(target_os = "windows"))]
        let (status_code, location, body_vec) = {
            let mut cmd = system_curl_command();
            cmd.args([
                "-sS",
                "-i",
                "-g",
                "--proto",
                "=http,https",
                "--proto-redir",
                "=http,https",
                "--max-filesize",
                &MAX_FAVICON_BYTES.to_string(),
                "--connect-timeout",
                "2",
                "--max-time",
                "4",
                "--compressed",
                "-A",
                uniform_ua,
                "-H",
                "Accept: image/avif,image/webp,image/png,image/svg+xml,image/x-icon,image/*;q=0.8,*/*;q=0.5",
            ]);
            let bare_host = host
                .trim_start_matches('[')
                .trim_end_matches(']')
                .trim_end_matches('.');
            if !bare_host.is_empty() && bare_host.parse::<IpAddr>().is_err() {
                if let Some(ip) = _resolved_ips.first() {
                    let ip_str = match ip {
                        IpAddr::V4(v4) => v4.to_string(),
                        IpAddr::V6(v6) => format!("[{}]", v6),
                    };
                    cmd.arg("--resolve")
                        .arg(format!("{}:{}:{}", bare_host, port, ip_str));
                }
            }
            cmd.arg("--").arg(&current_url);

            let out = cmd.output().ok()?;
            if !out.status.success() || out.stdout.is_empty() {
                return None;
            }
            let (code, loc, body_slice) = parse_curl_http_response(&out.stdout)?;
            (code, loc, body_slice.to_vec())
        };

        if matches!(status_code, 301 | 302 | 303 | 307 | 308) {
            let loc = location?;
            current_url = resolve_redirect_url(&current_url, &loc)?;
            continue;
        }
        if status_code != 200 || body_vec.is_empty() || body_vec.len() > MAX_FAVICON_BYTES {
            return None;
        }
        let mime = detect_favicon_mime(&body_vec)?;
        return Some((body_vec, mime));
    }
    None
}

fn prune_favicon_cache_if_needed(favicons_dir: &std::path::Path) {
    const MAX_CACHED_FAVICONS: usize = 400;
    let Ok(rd) = std::fs::read_dir(favicons_dir) else {
        return;
    };
    let mut entries: Vec<(std::time::SystemTime, std::path::PathBuf)> = Vec::new();
    for entry in rd.flatten() {
        let p = entry.path();
        if p.extension().and_then(|e| e.to_str()) == Some("bin") {
            let mtime = entry
                .metadata()
                .and_then(|m| m.modified())
                .unwrap_or(std::time::UNIX_EPOCH);
            entries.push((mtime, p));
        }
    }
    if entries.len() < MAX_CACHED_FAVICONS {
        return;
    }
    entries.sort_by_key(|(t, _)| *t);
    let to_remove = entries.len().saturating_sub(MAX_CACHED_FAVICONS - 40);
    for (_, p) in entries.into_iter().take(to_remove) {
        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_file(p.with_extension("mime"));
        let _ = std::fs::remove_file(p.with_extension("miss"));
    }
}

fn cache_favicon_in_ram(key: &str, bytes: &[u8], mime: &'static str) {
    if let Ok(mut ram) = favicon_ram_cache().lock() {
        if ram.len() >= 400 {
            ram.clear();
        }
        ram.insert(key.to_string(), (bytes.to_vec(), mime));
    }
}

fn handle_favicon_request(
    req: &ParsedHttpRequest,
    shell_mutex: &Arc<Mutex<SingularityBrowserShell>>,
) -> HttpResponse {
    let q = parse_query_params(&req.query);
    let host_raw = q
        .get("host")
        .map(|s| s.trim().to_ascii_lowercase())
        .unwrap_or_default();
    let icon_raw = q.get("icon").map(|s| s.trim().to_string()).unwrap_or_default();

    let mut candidates: Vec<String> = Vec::new();
    if !icon_raw.is_empty() && icon_raw.len() <= 512 && parse_http_url_authority(&icon_raw).is_ok() {
        candidates.push(icon_raw.clone());
    }
    if is_valid_favicon_host(&host_raw) {
        let root_ico = format!("https://{}/favicon.ico", host_raw);
        if !candidates.contains(&root_ico) {
            candidates.push(root_ico);
        }
    }
    if candidates.is_empty() {
        return HttpResponse::text("400 Bad Request", "Invalid favicon target");
    }

    let mut hasher = Sha256::new();
    hasher.update(candidates[0].as_bytes());
    let key_full = hex::encode(hasher.finalize());
    let key = &key_full[..32];

    // Fast path 1: zero-disk, zero-lock-on-shell RAM cache hit (microseconds across 38+ tabs!)
    if let Ok(ram) = favicon_ram_cache().lock() {
        if let Some((bytes, ct)) = ram.get(key) {
            return HttpResponse::new("200 OK", ct, bytes.clone())
                .with_header("Cache-Control", "private, max-age=86400")
                .with_header(
                    "Content-Security-Policy",
                    "default-src 'none'; style-src 'unsafe-inline'; sandbox",
                );
        }
    }

    let favicons_dir = {
        let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
        shell.roaming.favicons_dir()
    };
    let _ = std::fs::create_dir_all(&favicons_dir);

    let bin_path = favicons_dir.join(format!("{}.bin", key));
    let mime_path = favicons_dir.join(format!("{}.mime", key));
    let miss_path = favicons_dir.join(format!("{}.miss", key));

    if let (Ok(bytes), Ok(mime_str)) = (std::fs::read(&bin_path), std::fs::read_to_string(&mime_path))
    {
        if let Some(verified_mime) = detect_favicon_mime(&bytes) {
            let ct = match mime_str.trim() {
                "image/png" => "image/png",
                "image/x-icon" => "image/x-icon",
                "image/gif" => "image/gif",
                "image/jpeg" => "image/jpeg",
                "image/webp" => "image/webp",
                "image/svg+xml" => "image/svg+xml",
                _ => verified_mime,
            };
            cache_favicon_in_ram(key, &bytes, ct);
            return HttpResponse::new("200 OK", ct, bytes)
                .with_header("Cache-Control", "private, max-age=86400")
                .with_header(
                    "Content-Security-Policy",
                    "default-src 'none'; style-src 'unsafe-inline'; sandbox",
                );
        }
    }

    if let Ok(meta) = std::fs::metadata(&miss_path) {
        if let Ok(modified) = meta.modified() {
            if modified.elapsed().map(|d| d.as_secs() < 1800).unwrap_or(false) {
                return HttpResponse::text("404 Not Found", "Favicon unavailable")
                    .with_header("Cache-Control", "private, max-age=600");
            }
        }
    }

    let Some(_slot_guard) = try_acquire_favicon_fetch_slot() else {
        return HttpResponse::text("503 Service Unavailable", "Favicon fetcher busy")
            .with_header("Cache-Control", "no-store");
    };

    for cand in &candidates {
        if let Some((bytes, mime)) = fetch_favicon_bytes_safe(cand, shell_mutex) {
            prune_favicon_cache_if_needed(&favicons_dir);
            let _ = std::fs::write(&bin_path, &bytes);
            let _ = std::fs::write(&mime_path, mime);
            let _ = std::fs::remove_file(&miss_path);
            cache_favicon_in_ram(key, &bytes, mime);
            return HttpResponse::new("200 OK", mime, bytes)
                .with_header("Cache-Control", "private, max-age=86400")
                .with_header(
                    "Content-Security-Policy",
                    "default-src 'none'; style-src 'unsafe-inline'; sandbox",
                );
        }
    }

    let _ = std::fs::write(&miss_path, b"0");
    HttpResponse::text("404 Not Found", "Favicon not found")
        .with_header("Cache-Control", "private, max-age=600")
}

fn write_http_response(
    stream: &mut TcpStream,
    resp: &HttpResponse,
    keep_alive: bool,
) -> std::io::Result<()> {
    let has_cache_ctrl = resp
        .extra_headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("cache-control"));
    let conn_hdr = if keep_alive {
        "Connection: keep-alive\r\nKeep-Alive: timeout=2, max=64\r\n"
    } else {
        "Connection: close\r\n"
    };
    let mut header = String::with_capacity(256 + resp.extra_headers.len() * 48);
    use std::fmt::Write as _;
    let _ = write!(
        header,
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\n",
        resp.status,
        resp.content_type,
        resp.body.len()
    );
    if !has_cache_ctrl {
        header.push_str("Cache-Control: no-store\r\n");
    }
    header.push_str("X-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\n");
    header.push_str(conn_hdr);
    for (k, v) in &resp.extra_headers {
        header.push_str(k);
        header.push_str(": ");
        header.push_str(v);
        header.push_str("\r\n");
    }
    header.push_str("\r\n");

    // Single contiguous write avoids Nagle / Delayed-ACK 200ms stalls on Windows loopback!
    let mut wire = Vec::with_capacity(header.len() + resp.body.len());
    wire.extend_from_slice(header.as_bytes());
    wire.extend_from_slice(&resp.body);
    stream.write_all(&wire)
}

fn parse_query_params(q: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for pair in q.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        map.insert(url_decode(k), url_decode(v));
    }
    map
}

/// Safe RFC 3986 / form URL decoder that preserves malformed `%` sequences instead of
/// dropping trailing bytes or fabricating NUL (`\0`) bytes.
pub fn url_decode(input: &str) -> String {
    let raw = input.as_bytes();
    let mut bytes = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        match raw[i] {
            b'+' => {
                bytes.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < raw.len() => {
                let hex_pair = &raw[i + 1..i + 3];
                if let Ok(s) = std::str::from_utf8(hex_pair) {
                    if let Ok(val) = u8::from_str_radix(s, 16) {
                        if val != 0 {
                            bytes.push(val);
                        }
                        i += 3;
                        continue;
                    }
                }
                bytes.push(b'%');
                i += 1;
            }
            b => {
                if b != 0 {
                    bytes.push(b);
                }
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Strictly parses an HTTP(S) URL authority into `(host, port)`.
/// Rejects non-HTTP(S) schemes, embedded credentials (`user@host`), backslashes, whitespace,
/// control characters, empty hosts, and invalid ports, while properly supporting IPv6 literals `[::1]`.
pub fn parse_http_url_authority(url: &str) -> Result<(String, u16), &'static str> {
    let trimmed = url.trim();
    let (default_port, after_scheme) = if let Some(rest) = trimmed.strip_prefix("https://") {
        (443u16, rest)
    } else if let Some(rest) = trimmed.strip_prefix("http://") {
        (80u16, rest)
    } else {
        return Err("Only HTTP and HTTPS protocols are allowed.");
    };

    if trimmed.bytes().any(|b| b <= 0x20 || b == 0x7f) {
        return Err("URL contains invalid control characters or whitespace.");
    }

    let authority_end = after_scheme
        .find(&['/', '?', '#'][..])
        .unwrap_or(after_scheme.len());
    let authority = &after_scheme[..authority_end];
    if authority.is_empty() {
        return Err("Missing hostname in URL.");
    }
    if authority.contains('@') || authority.contains('\\') {
        return Err("Embedded credentials (@) and backslashes in the host are rejected.");
    }

    if authority.starts_with('[') {
        let close = authority
            .find(']')
            .ok_or("Malformed IPv6 address in URL.")?;
        let host = &authority[..=close];
        let rest = &authority[close + 1..];
        let port = if rest.is_empty() {
            default_port
        } else if let Some(port_str) = rest.strip_prefix(':') {
            let p: u16 = port_str.parse().map_err(|_| "Invalid network port.")?;
            if p == 0 {
                return Err("Invalid network port.");
            }
            p
        } else {
            return Err("Invalid IPv6 authority.");
        };
        return Ok((host.to_string(), port));
    }

    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p_str)) => {
            if h.contains(':') {
                return Err("Unbracketed IPv6 address.");
            }
            let p: u16 = p_str.parse().map_err(|_| "Invalid network port.")?;
            if p == 0 {
                return Err("Invalid network port.");
            }
            (h, p)
        }
        None => (authority, default_port),
    };

    if host.is_empty() || !host.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-') {
        return Err("Hostname contains disallowed characters.");
    }

    Ok((host.to_ascii_lowercase(), port))
}

fn extract_origin_base(url: &str) -> String {
    if let Some(scheme_idx) = url.find("://") {
        let after_scheme = &url[scheme_idx + 3..];
        if let Some(slash_idx) = after_scheme.find('/') {
            return url[..scheme_idx + 3 + slash_idx + 1].to_string();
        }
        return format!("{}/", url);
    }
    url.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_req(
        method: &str,
        path: &str,
        query: &str,
        host: &str,
        token: Option<&str>,
        origin: Option<&str>,
        body: &str,
    ) -> ParsedHttpRequest {
        let mut headers = HashMap::new();
        headers.insert("host".into(), host.into());
        if let Some(t) = token {
            headers.insert("x-singularity-token".into(), t.into());
        }
        if let Some(o) = origin {
            headers.insert("origin".into(), o.into());
        }
        ParsedHttpRequest {
            method: method.into(),
            path: path.into(),
            query: query.into(),
            headers,
            body: Zeroizing::new(body.as_bytes().to_vec()),
        }
    }

    #[test]
    fn test_ipc_auth_and_dns_rebinding_protection() {
        let shell = Arc::new(Mutex::new(
            SingularityBrowserShell::launch().expect("Launch shell"),
        ));
        let cfg = ServerConfig::new(54321);

        // 1. Reject DNS rebinding Host header
        let bad_host = make_req(
            "GET",
            "/api/state",
            "",
            "evil.attacker.com:54321",
            Some(&cfg.ipc_token),
            None,
            "",
        );
        let resp = dispatch_http_request(&bad_host, &cfg, &shell);
        assert_eq!(resp.status, "403 Forbidden");

        // 2. Reject missing IPC token
        let no_tok = make_req("GET", "/api/state", "", "127.0.0.1:54321", None, None, "");
        let resp = dispatch_http_request(&no_tok, &cfg, &shell);
        assert_eq!(resp.status, "403 Forbidden");

        // 3. Reject cross-origin Origin header
        let bad_origin = make_req(
            "GET",
            "/api/state",
            "",
            "127.0.0.1:54321",
            Some(&cfg.ipc_token),
            Some("https://evil.com"),
            "",
        );
        let resp = dispatch_http_request(&bad_origin, &cfg, &shell);
        assert_eq!(resp.status, "403 Forbidden");

        // 4. Reject GET on POST-only secret/mutating endpoints
        let get_vault = make_req(
            "GET",
            "/api/vault/unlock",
            "master=secret123",
            "127.0.0.1:54321",
            Some(&cfg.ipc_token),
            None,
            "",
        );
        let resp = dispatch_http_request(&get_vault, &cfg, &shell);
        assert_eq!(resp.status, "405 Method Not Allowed");

        // 5. Accept valid same-origin request with token
        let ok_req = make_req(
            "GET",
            "/api/state",
            "",
            "127.0.0.1:54321",
            Some(&cfg.ipc_token),
            Some("http://127.0.0.1:54321"),
            "",
        );
        let resp = dispatch_http_request(&ok_req, &cfg, &shell);
        assert_eq!(resp.status, "200 OK");
    }

    #[test]
    fn test_authority_parser_blocks_userinfo_and_handles_ipv6() {
        assert!(parse_http_url_authority("https://example.com@127.0.0.1/").is_err());
        assert!(parse_http_url_authority("https://evil.com\\@127.0.0.1/").is_err());
        assert!(parse_http_url_authority("file:///etc/passwd").is_err());
        assert!(parse_http_url_authority("javascript:alert(1)").is_err());

        assert_eq!(
            parse_http_url_authority("http://[::1]:8080/test"),
            Ok(("[::1]".to_string(), 8080))
        );
        assert_eq!(
            parse_http_url_authority("https://Example.COM/path"),
            Ok(("example.com".to_string(), 443))
        );
    }

    #[test]
    fn test_unicode_safe_head_search_and_error_page_xss_escaping() {
        // Turkish capital 'İ' (U+0130, 2 UTF-8 bytes) expands to 3 bytes when lowercased (`i\u{307}`).
        // `to_lowercase().find("<head>")` used to panic on slicing the original string!
        let turkish_html = "<!DOCTYPE html><html><!-- İİİİİ --><HeAd><title>OK</title></head></html>";
        let idx = find_ascii_case_insensitive(turkish_html, "<head>").expect("find head");
        assert_eq!(&turkish_html[idx..idx + 6], "<HeAd>");

        let xss_url = "https://x.test/'><script>alert(1)</script>";
        let page = render_proxy_error_page(xss_url, "<b>Title</b>", "Detail 'quote'");
        assert!(!page.contains("<script>"));
        assert!(!page.contains("onclick="));
        assert!(page.contains("&lt;script&gt;"));
        assert!(page.contains("&#39;"));
    }

    #[test]
    fn test_url_decode_preserves_malformed_percent_without_nul() {
        assert_eq!(url_decode("100%"), "100%");
        assert_eq!(url_decode("a%2b+c%20d"), "a+ c d");
        assert_eq!(url_decode("bad%ZZok"), "bad%ZZok");
        assert_eq!(url_decode("no%00nul"), "nonul");
    }

    #[test]
    fn test_bootstrap_nonce_and_sec_fetch_site_lockdown() {
        let shell = Arc::new(Mutex::new(
            SingularityBrowserShell::launch().expect("Launch shell"),
        ));
        let cfg = ServerConfig::new(54322);

        // 1. GET / without ?boot= must be rejected so local processes cannot steal IPC token
        let no_boot = make_req("GET", "/", "", "127.0.0.1:54322", None, None, "");
        assert_eq!(dispatch_http_request(&no_boot, &cfg, &shell).status, "403 Forbidden");

        // 2. GET / with wrong ?boot= must be rejected
        let bad_boot = make_req("GET", "/", "boot=deadbeef", "127.0.0.1:54322", None, None, "");
        assert_eq!(dispatch_http_request(&bad_boot, &cfg, &shell).status, "403 Forbidden");

        // 3. GET / with valid ?boot= succeeds ONCE and injects the IPC token
        let good_query = format!("boot={}", cfg.bootstrap_nonce);
        let ok_boot = make_req("GET", "/", &good_query, "127.0.0.1:54322", None, None, "");
        let ok_resp = dispatch_http_request(&ok_boot, &cfg, &shell);
        assert_eq!(ok_resp.status, "200 OK");
        assert!(String::from_utf8_lossy(&ok_resp.body).contains(cfg.ipc_token.as_str()));

        // 4. Replaying the same ?boot= nonce must be rejected (one-time use)
        let replay = make_req("GET", "/", &good_query, "127.0.0.1:54322", None, None, "");
        assert_eq!(dispatch_http_request(&replay, &cfg, &shell).status, "403 Forbidden");

        // 5. Sec-Fetch-Site: same-site (another localhost port) must be rejected
        let mut same_site = make_req(
            "GET",
            "/api/state",
            "",
            "127.0.0.1:54322",
            Some(&cfg.ipc_token),
            None,
            "",
        );
        same_site.headers.insert("sec-fetch-site".into(), "same-site".into());
        assert_eq!(dispatch_http_request(&same_site, &cfg, &shell).status, "403 Forbidden");

        // 6. Sec-Fetch-Site: same-origin must be accepted
        let mut same_origin = make_req(
            "GET",
            "/api/state",
            "",
            "127.0.0.1:54322",
            Some(&cfg.ipc_token),
            None,
            "",
        );
        same_origin.headers.insert("sec-fetch-site".into(), "same-origin".into());
        assert_eq!(dispatch_http_request(&same_origin, &cfg, &shell).status, "200 OK");
    }
}
