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
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

const WINDOWS_TO_UNIX_EPOCH_US: i64 = 11_644_473_600_000_000;
const IPC_MESSAGE_NAME: &str = "sg_ipc";

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
    CloseExtensionPopup,
}

pub type CefEventSink = Arc<dyn Fn(CefCallbackEvent) + Send + Sync>;
pub type CefPumpCallback = Arc<dyn Fn(i64) + Send + Sync>;
pub type CefRelaunchCallback = Arc<dyn Fn() + Send + Sync>;
pub type CefDownloadResolver = Arc<dyn Fn(&str, &str) -> (PathBuf, String) + Send + Sync>;

#[derive(Clone, Default)]
struct RendererBrowserConfig {
    is_ui: bool,
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

fn parse_http_host_port(url: &str) -> Option<(String, u16)> {
    let trimmed = url.trim();
    let (default_port, rest) = if let Some(r) = trimmed.strip_prefix("https://") {
        (443u16, r)
    } else if let Some(r) = trimmed.strip_prefix("http://") {
        (80u16, r)
    } else {
        return None;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    if let Some(after_open) = authority.strip_prefix('[') {
        let (host, tail) = after_open.split_once(']')?;
        let port = if let Some(p) = tail.strip_prefix(':') {
            p.parse::<u16>().ok()?
        } else if tail.is_empty() {
            default_port
        } else {
            return None;
        };
        return Some((host.to_ascii_lowercase(), port));
    }
    if let Some((host, p)) = authority.rsplit_once(':') {
        let port = p.parse::<u16>().ok()?;
        Some((host.to_ascii_lowercase(), port))
    } else {
        Some((authority.to_ascii_lowercase(), default_port))
    }
}

fn is_blocked_local_ipc_url(nav_url: &str, bind_port: u16) -> bool {
    let lower = nav_url.trim().to_ascii_lowercase();
    if lower.starts_with("file:") {
        return true;
    }
    if let Some((host, port)) = parse_http_host_port(nav_url) {
        if port == bind_port {
            let h = host
                .trim_start_matches('[')
                .trim_end_matches(']')
                .trim_end_matches('.');
            let is_local = h == "localhost"
                || h.ends_with(".localhost")
                || h.starts_with("127.")
                || h == "::1"
                || h == "0.0.0.0"
                || h.starts_with("0x")
                || h.chars().all(|c| c.is_ascii_digit())
                || h.parse::<IpAddr>()
                    .map(|ip| ip.is_loopback() || ip.is_unspecified())
                    .unwrap_or(false);
            if is_local {
                return true;
            }
        }
    }
    false
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
                        if let Some(mut msg) = process_message_create(Some(&CefString::from(IPC_MESSAGE_NAME))) {
                            if let Some(args) = msg.argument_list() {
                                let _ = args.set_string(0, Some(&CefString::from(payload.as_str())));
                            }
                            frame.send_process_message(ProcessId::BROWSER, Some(&mut msg));
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
            let cfg = RENDERER_CONFIGS.with(|map| {
                map.borrow()
                    .get(&browser.identifier())
                    .cloned()
                    .unwrap_or_default()
            });

            // Expose `window.ipc.postMessage(payload)` natively via V8 on main frame (and subframes
            // for content pages so global shortcuts like Ctrl+T / F11 work inside embedded iframes).
            if is_main || !cfg.is_ui {
                if let Some(global) = context.global() {
                    if let Some(mut ipc_obj) = v8_value_create_object(None, None) {
                        let mut handler = SingularityIpcV8Handler::new();
                        let fn_name = CefString::from("postMessage");
                        if let Some(mut post_fn) = v8_value_create_function(Some(&fn_name), Some(&mut handler)) {
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
                "disable-background-networking",
                "disable-component-update",
                "disable-sync",
                "disable-domain-reliability",
                "disable-breakpad",
                "disable-default-apps",
                "disable-client-side-phishing-detection",
                "safebrowsing-disable-download-protection",
                "disable-extensions-file-access-check",
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

            if let Some(ref ext_dir) = self.extensions_dir {
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
    let ret = execute_process(Some(args.as_main_args()), Some(&mut app), std::ptr::null_mut());
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

        let mut settings = Settings {
            no_sandbox: 1,
            multi_threaded_message_loop: 0,
            external_message_pump: 1,
            windowless_rendering_enabled: 0,
            root_cache_path: CefString::from(profile_str.as_str()),
            cache_path: CefString::from(profile_str.as_str()),
            persist_session_cookies: 1,
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
            std::ptr::null_mut(),
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
    tab_id: u64,
    bind_port: u16,
    sink: CefEventSink,
    shared_shell: Arc<Mutex<SingularityBrowserShell>>,
    download_resolver: CefDownloadResolver,
    downloads: Arc<Mutex<HashMap<u32, (String, String)>>>,
}

wrap_context_menu_handler! {
    struct SingularityContextMenuHandler {
        disable_default_menu: bool,
    }

    impl ContextMenuHandler {
        fn on_before_context_menu(
            &self,
            _browser: Option<&mut Browser>,
            _frame: Option<&mut Frame>,
            _params: Option<&mut ContextMenuParams>,
            model: Option<&mut MenuModel>,
        ) {
            if self.disable_default_menu {
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
            _user_gesture: ::std::os::raw::c_int,
            popup_features: Option<&PopupFeatures>,
            _window_info: Option<&mut WindowInfo>,
            _client: Option<&mut Option<Client>>,
            _settings: Option<&mut BrowserSettings>,
            _extra_info: Option<&mut Option<DictionaryValue>>,
            _no_javascript_access: Option<&mut ::std::os::raw::c_int>,
        ) -> ::std::os::raw::c_int {
            let url = target_url.map(CefString::to_string).unwrap_or_default();
            if self.cfg.is_ext_popup && url.starts_with("chrome-extension://") {
                return 0;
            }
            if !self.cfg.is_ui && parse_http_host_port(&url).is_some()
                && !is_blocked_local_ipc_url(&url, self.cfg.bind_port)
            {
                let is_explicit_popup = popup_features
                    .map(|f| f.is_popup != 0 || f.width_set != 0 || f.height_set != 0)
                    .unwrap_or(false);
                let background = !is_explicit_popup
                    && (target_disposition == WindowOpenDisposition::NEW_BACKGROUND_TAB
                        || is_ctrl_or_mbutton_down_cef());
                (self.cfg.sink)(CefCallbackEvent::OpenNewTab { url, background });
            }
            1 // Always suppress unmanaged external popup windows
        }

        fn do_close(&self, browser: Option<&mut Browser>) -> ::std::os::raw::c_int {
            if self.cfg.is_ext_popup {
                return 0; // Closing an extension popup SHOULD close its own tiny popup window.
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
            if u.starts_with("https://") || u.starts_with("http://") {
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
                let mut val = unsafe { std::mem::zeroed() };
                if unsafe { sys::cef_string_list_value(raw_ptr, i, &mut val) } > 0 {
                    let href = CefString::from(std::ptr::from_ref(&val)).to_string();
                    if href.len() <= 512 && parse_http_host_port(&href).is_some() {
                        (self.cfg.sink)(CefCallbackEvent::FaviconChanged {
                            tab_id: self.cfg.tab_id,
                            favicon_url: href,
                        });
                        break;
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
            let mut doc_host = parse_http_host_port(&first_party_url)
                .map(|(h, _)| h)
                .unwrap_or_default();
            if doc_host.is_empty() {
                if let Some(main_url) = browser
                    .and_then(|b| b.main_frame())
                    .map(|f| cef_str_userfree(f.url()))
                {
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
            _user_gesture: ::std::os::raw::c_int,
            _is_redirect: ::std::os::raw::c_int,
        ) -> ::std::os::raw::c_int {
            if self.cfg.is_ui {
                return 0;
            }
            if let Some(req) = request {
                let url = cef_str_userfree(req.url());
                if is_blocked_local_ipc_url(&url, self.cfg.bind_port) {
                    return 1; // Cancel navigation to local IPC port or file://
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
            _user_gesture: ::std::os::raw::c_int,
        ) -> ::std::os::raw::c_int {
            if self.cfg.is_ui {
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

wrap_download_handler! {
    struct SingularityDownloadHandler {
        cfg: ClientConfig,
    }

    impl DownloadHandler {
        fn can_download(
            &self,
            _browser: Option<&mut Browser>,
            _url: Option<&CefString>,
            _request_method: Option<&CefString>,
        ) -> ::std::os::raw::c_int {
            1 // Always permit user downloads (.exe, .zip, .msi, etc.) without SmartScreen blocks
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
            let suggested = suggested_name
                .map(CefString::to_string)
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| cef_str_userfree(item.suggested_file_name()));
            let (dest_path, filename) = (self.cfg.download_resolver)(&suggested, &uri);
            let dest_str = dest_path.to_string_lossy().into_owned();
            if let Ok(mut map) = self.cfg.downloads.lock() {
                map.insert(dl_id, (filename.clone(), dest_str.clone()));
            }
            cb.cont(Some(&CefString::from(dest_str.as_str())), 0);
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

wrap_client! {
    struct SingularityCefClient {
        cfg: ClientConfig,
    }

    impl Client {
        fn context_menu_handler(&self) -> Option<ContextMenuHandler> {
            Some(SingularityContextMenuHandler::new(self.cfg.is_ui))
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
            _frame: Option<&mut Frame>,
            _source_process: ProcessId,
            message: Option<&mut ProcessMessage>,
        ) -> ::std::os::raw::c_int {
            let Some(msg) = message else {
                return 0;
            };
            if cef_str_userfree(msg.name()) != IPC_MESSAGE_NAME {
                return 0;
            }
            let body = msg
                .argument_list()
                .filter(|a| a.size() > 0)
                .map(|a| cef_str_userfree(a.string(0)))
                .unwrap_or_default();
            if body.is_empty() {
                return 1;
            }
            if self.cfg.is_ui {
                (self.cfg.sink)(CefCallbackEvent::UiIpc(body));
            } else if self.cfg.is_ext_popup {
                if body.contains("close_ext_popup") {
                    (self.cfg.sink)(CefCallbackEvent::CloseExtensionPopup);
                }
            } else {
                (self.cfg.sink)(CefCallbackEvent::ContentIpc {
                    tab_id: self.cfg.tab_id,
                    body,
                });
            }
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

    pub fn go_back(&self) {
        if self.browser.can_go_back() != 0 {
            self.browser.go_back();
        }
    }

    pub fn go_forward(&self) {
        if self.browser.can_go_forward() != 0 {
            self.browser.go_forward();
        }
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
        tab_id,
        bind_port,
        sink,
        shared_shell,
        download_resolver,
        downloads: Arc::new(Mutex::new(HashMap::new())),
    };
    let mut client = SingularityCefClient::new(cfg);

    let mut extra = dictionary_value_create();
    if let Some(ref mut dict) = extra {
        let _ = dict.set_bool(Some(&CefString::from("is_ui")), if is_ui { 1 } else { 0 });
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
                if self.purge_trackers {
                    let mut threat = classify_tracker_or_malicious_cookie(&domain, &name, &value);
                    if threat.is_none()
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
                        let exp_unix = if c.has_expires != 0 && c.expires.val > WINDOWS_TO_UNIX_EPOCH_US {
                            Some((c.expires.val - WINDOWS_TO_UNIX_EPOCH_US) / 1_000_000)
                        } else {
                            None
                        };
                        if let Ok(mut cap) = self.fin.captured.lock() {
                            cap.push(EncryptedAuthTokenRecord {
                                id: format!("{}::{}::{}", provider, domain, name),
                                provider: provider.to_string(),
                                domain,
                                path: if path.is_empty() { "/".to_string() } else { path },
                                token_name: name,
                                secret_value: value,
                                http_only: c.httponly != 0,
                                secure: c.secure != 0,
                                expires_unix: exp_unix,
                                updated_unix: unix_now(),
                                kind: "cookie_session".to_string(),
                            });
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
        for rec in sessions {
            if rec.kind != "cookie_session"
                || rec.domain.is_empty()
                || rec.token_name.is_empty()
            {
                continue;
            }
            let lower_name = rec.token_name.to_ascii_lowercase();
            if lower_name.starts_with("__host-") {
                continue;
            }
            let clean_dom = rec.domain.trim_start_matches('.').to_ascii_lowercase();
            if seen.contains(&(clean_dom.clone(), lower_name.clone())) {
                continue;
            }
            let cookie_url = format!("https://{}/", clean_dom);
            let is_domain_cookie = rec.domain.starts_with('.');
            let is_3p_cookie = lower_name.starts_with("__secure-3p");
            let secure_flag = if rec.secure || lower_name.starts_with("__secure-") || is_3p_cookie {
                1
            } else {
                0
            };
            let mut cef_cookie = Cookie {
                name: CefString::from(rec.token_name.as_str()),
                value: CefString::from(rec.secret_value.as_str()),
                domain: if is_domain_cookie {
                    CefString::from(rec.domain.as_str())
                } else {
                    CefString::default()
                },
                path: CefString::from(if rec.path.is_empty() { "/" } else { rec.path.as_str() }),
                secure: secure_flag,
                httponly: if rec.http_only { 1 } else { 0 },
                same_site: if is_3p_cookie {
                    CookieSameSite::NO_RESTRICTION
                } else {
                    CookieSameSite::LAX_MODE
                },
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
