//! Crash Detection, Persistent Crash Reports & Native Copyable Error Dialog for Singularity Browser.
//!
//! Captures:
//! 1. Rust panics (`std::panic::set_hook` with full backtrace)
//! 2. Native Windows SEH exceptions (`SetUnhandledExceptionFilter` — access violations, stack
//!    overflows, C++/CEF crashes)
//! 3. Unclean previous shutdowns (`running.lock` sentinel whose PID is no longer alive)
//! 4. Live CEF renderer crashes (`on_render_process_terminated`)
//!
//! Persists reports to `%APPDATA%\.singularity\crashes\last_crash.json` and `last_crash.txt`,
//! appends recent `cef.log` lines, and surfaces a copyable Crash Report dialog (both a native
//! Win32 modal dialog with 1-click clipboard copy when crashing live, and an in-app modal on
//! restart or renderer crash).

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

static CRASH_ROAMING_ROOT: OnceLock<PathBuf> = OnceLock::new();

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrashReport {
    pub id: String,
    pub timestamp_unix: u64,
    pub version: String,
    pub os_arch: String,
    pub kind: String,
    pub summary: String,
    pub details: String,
    pub cef_log_tail: String,
    #[serde(default)]
    pub acknowledged: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RunningLockFile {
    pid: u32,
    started_unix: u64,
    version: String,
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn crashes_dir(roaming_root: &Path) -> PathBuf {
    roaming_root.join("crashes")
}

fn running_lock_path(roaming_root: &Path) -> PathBuf {
    roaming_root.join("running.lock")
}

fn planned_restart_flag_path(roaming_root: &Path) -> PathBuf {
    roaming_root.join("planned_restart.flag")
}

impl CrashReport {
    pub fn format_copyable_text(&self) -> String {
        let mut out = String::with_capacity(1024);
        out.push_str("=== SINGULARITY BROWSER CRASH REPORT ===\n");
        out.push_str(&format!("Report ID : {}\n", self.id));
        out.push_str(&format!("Version   : v{}\n", self.version));
        out.push_str(&format!("Platform  : {}\n", self.os_arch));
        out.push_str(&format!("Timestamp : {}\n", self.timestamp_unix));
        out.push_str(&format!("Type      : {}\n", self.kind));
        out.push_str(&format!("Summary   : {}\n", self.summary));
        out.push_str("\n--- Details ---\n");
        out.push_str(self.details.trim());
        out.push('\n');
        if !self.cef_log_tail.trim().is_empty() {
            out.push_str("\n--- Recent CEF Log ---\n");
            out.push_str(self.cef_log_tail.trim());
            out.push('\n');
        }
        out.push_str("========================================\n");
        out
    }
}

/// Reads the last `max_lines` lines (capped to 8 KiB) of `%APPDATA%\.singularity\cef.log`.
pub fn read_cef_log_tail(roaming_root: &Path, max_lines: usize) -> String {
    let path = roaming_root.join("cef.log");
    let Ok(bytes) = std::fs::read(&path) else {
        return String::new();
    };
    let tail_slice = if bytes.len() > 16_384 {
        &bytes[bytes.len() - 16_384..]
    } else {
        &bytes[..]
    };
    let text = String::from_utf8_lossy(tail_slice);
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.len().saturating_sub(max_lines);
    lines[start..].join("\n")
}

fn save_crash_report_to_disk(roaming_root: &Path, report: &CrashReport) {
    let dir = crashes_dir(roaming_root);
    let _ = std::fs::create_dir_all(&dir);
    let txt = report.format_copyable_text();
    let _ = std::fs::write(dir.join("last_crash.txt"), &txt);
    let _ = std::fs::write(dir.join(format!("{}.txt", report.id)), &txt);
    if let Ok(json) = serde_json::to_vec_pretty(report) {
        let _ = std::fs::write(dir.join("last_crash.json"), &json);
    }
}

fn build_report(roaming_root: &Path, kind: &str, summary: &str, details: &str) -> CrashReport {
    build_report_with_log(
        kind,
        summary,
        details,
        read_cef_log_tail(roaming_root, 35),
    )
}

fn build_report_with_log(
    kind: &str,
    summary: &str,
    details: &str,
    cef_log_tail: String,
) -> CrashReport {
    let ts = unix_now_secs();
    CrashReport {
        id: format!("crash-{}-{}", ts, std::process::id()),
        timestamp_unix: ts,
        version: env!("CARGO_PKG_VERSION").to_string(),
        os_arch: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
        kind: kind.to_string(),
        summary: summary.to_string(),
        details: details.to_string(),
        cef_log_tail,
        acknowledged: false,
    }
}

/// Records a non-fatal runtime crash (such as a CEF renderer termination) to disk and returns the
/// formatted report so the UI can display a copyable crash modal immediately.
pub fn record_runtime_error_report(
    roaming_root: &Path,
    kind: &str,
    summary: &str,
    details: &str,
) -> CrashReport {
    let mut rep = build_report(roaming_root, kind, summary, details);
    rep.acknowledged = true; // Displayed live immediately in-app
    save_crash_report_to_disk(roaming_root, &rep);
    rep
}

/// Installs global panic and (on Windows) native SEH unhandled-exception crash detectors.
pub fn install_crash_handlers(roaming_root: &Path) {
    let _ = CRASH_ROAMING_ROOT.set(roaming_root.to_path_buf());
    let _ = std::fs::create_dir_all(crashes_dir(roaming_root));

    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let thread = std::thread::current();
        let tname = thread.name().unwrap_or("<unnamed>");
        let payload = if let Some(s) = info.payload().downcast_ref::<&str>() {
            (*s).to_string()
        } else if let Some(s) = info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "Unknown panic payload".to_string()
        };
        let loc = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "<unknown location>".to_string());
        let bt = std::backtrace::Backtrace::force_capture();
        let summary = format!("Rust panic on thread '{}' at {}: {}", tname, loc, payload);
        let details = format!("Location: {}\nThread: {}\nMessage: {}\n\nBacktrace:\n{}", loc, tname, payload, bt);

        if let Some(root) = CRASH_ROAMING_ROOT.get() {
            let report = build_report(root, "rust_panic", &summary, &details);
            save_crash_report_to_disk(root, &report);
            #[cfg(target_os = "windows")]
            show_native_crash_dialog("Singularity — Crash Report / Rapport d'erreur", &report.format_copyable_text());
        }
        prev_hook(info);
    }));

    #[cfg(target_os = "windows")]
    install_windows_seh_filter();
}

#[cfg(target_os = "windows")]
fn is_pid_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    const STILL_ACTIVE: u32 = 259;
    #[link(name = "kernel32")]
    extern "system" {
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut core::ffi::c_void;
        fn GetExitCodeProcess(handle: *mut core::ffi::c_void, code: *mut u32) -> i32;
        fn CloseHandle(handle: *mut core::ffi::c_void) -> i32;
    }
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return false;
        }
        let mut code: u32 = 0;
        let ok = GetExitCodeProcess(h, &mut code);
        let _ = CloseHandle(h);
        ok != 0 && code == STILL_ACTIVE
    }
}

#[cfg(not(target_os = "windows"))]
fn is_pid_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    Path::new(&format!("/proc/{}", pid)).exists()
}

/// Checks whether the previous Singularity run crashed (either an unacknowledged `last_crash.json`
/// or a stale `running.lock` from a dead PID) and writes a fresh `running.lock` for this process.
pub fn detect_previous_crash_and_mark_running(roaming_root: &Path) -> Option<CrashReport> {
    detect_previous_crash_and_mark_running_with_cef_log(roaming_root, "")
}

/// Same as `detect_previous_crash_and_mark_running`, but preserves `prev_cef_log_tail` captured
/// BEFORE `CefRuntimeGuard::initialize()` truncates `cef.log` on startup.
pub fn detect_previous_crash_and_mark_running_with_cef_log(
    roaming_root: &Path,
    prev_cef_log_tail: &str,
) -> Option<CrashReport> {
    let mut detected: Option<CrashReport> = None;

    let last_json = crashes_dir(roaming_root).join("last_crash.json");
    if let Ok(bytes) = std::fs::read(&last_json) {
        if let Ok(mut rep) = serde_json::from_slice::<CrashReport>(&bytes) {
            if !rep.acknowledged {
                rep.acknowledged = true;
                if let Ok(updated) = serde_json::to_vec_pretty(&rep) {
                    let _ = std::fs::write(&last_json, updated);
                }
                detected = Some(rep);
            }
        }
    }

    let lock_path = running_lock_path(roaming_root);
    let my_pid = std::process::id();
    if let Ok(bytes) = std::fs::read(&lock_path) {
        if let Ok(prev) = serde_json::from_slice::<RunningLockFile>(&bytes) {
            if prev.pid != my_pid && !is_pid_alive(prev.pid) && detected.is_none() {
                let summary = format!(
                    "Previous session (v{}, PID {}) terminated unexpectedly without clean shutdown.",
                    prev.version, prev.pid
                );
                let details = format!(
                    "Previous PID: {}\nPrevious Version: v{}\nStarted At (unix): {}\nDetected At (unix): {}\n\nSingularity automatically restored your open windows, tabs, and video timestamps from the last live checkpoint.",
                    prev.pid,
                    prev.version,
                    prev.started_unix,
                    unix_now_secs()
                );
                let log_tail = if !prev_cef_log_tail.trim().is_empty() {
                    prev_cef_log_tail.to_string()
                } else {
                    read_cef_log_tail(roaming_root, 35)
                };
                let mut rep = build_report_with_log("unclean_shutdown", &summary, &details, log_tail);
                rep.acknowledged = true;
                save_crash_report_to_disk(roaming_root, &rep);
                detected = Some(rep);
            }
        }
    }

    let lock = RunningLockFile {
        pid: my_pid,
        started_unix: unix_now_secs(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    };
    if let Ok(bytes) = serde_json::to_vec(&lock) {
        let _ = std::fs::create_dir_all(roaming_root);
        let _ = std::fs::write(&lock_path, bytes);
    }

    detected
}

/// Removes `running.lock` on normal graceful browser exit so the next launch knows no crash occurred.
pub fn mark_clean_shutdown(roaming_root: &Path) {
    let _ = std::fs::remove_file(running_lock_path(roaming_root));
}

/// Marks an intentional shutdown triggered by Windows OS Shutdown/Restart (`WM_ENDSESSION`) or an
/// in-place Singularity self-update/installer upgrade: clears `running.lock` (preventing false
/// crash popups) while writing a single-use `planned_restart.flag` so all live windows & timestamps
/// are restored cleanly from `crash_checkpoint.json` on next launch.
pub fn mark_planned_restart(roaming_root: &Path) {
    mark_clean_shutdown(roaming_root);
    let _ = std::fs::create_dir_all(roaming_root);
    let _ = std::fs::write(planned_restart_flag_path(roaming_root), b"1");
}

/// Consumes `planned_restart.flag` once on startup so OS-shutdown / updater restarts restore every
/// open window from the live checkpoint without surfacing a false Crash Report dialog.
pub fn consume_planned_restart_flag(roaming_root: &Path) -> bool {
    let p = planned_restart_flag_path(roaming_root);
    if p.is_file() {
        let _ = std::fs::remove_file(&p);
        true
    } else {
        false
    }
}

/// Checks whether an unclean previous crash lock exists (read-only, used before session restoration).
pub fn has_unclean_crash_sentinel(roaming_root: &Path) -> bool {
    let last_json = crashes_dir(roaming_root).join("last_crash.json");
    if let Ok(bytes) = std::fs::read(&last_json) {
        if let Ok(rep) = serde_json::from_slice::<CrashReport>(&bytes) {
            if !rep.acknowledged {
                return true;
            }
        }
    }
    let lock_path = running_lock_path(roaming_root);
    let my_pid = std::process::id();
    if let Ok(bytes) = std::fs::read(&lock_path) {
        if let Ok(prev) = serde_json::from_slice::<RunningLockFile>(&bytes) {
            if prev.pid != my_pid && !is_pid_alive(prev.pid) {
                return true;
            }
        }
    }
    false
}

/// Copies UTF-8 text cleanly into the native Windows clipboard (`CF_UNICODETEXT`).
#[cfg(target_os = "windows")]
pub fn copy_text_to_windows_clipboard(text: &str) -> bool {
    use std::os::windows::ffi::OsStrExt;
    const CF_UNICODETEXT: u32 = 13;
    const GMEM_MOVEABLE: u32 = 0x0002;
    #[link(name = "user32")]
    extern "system" {
        fn OpenClipboard(hwnd_new_owner: *mut core::ffi::c_void) -> i32;
        fn EmptyClipboard() -> i32;
        fn SetClipboardData(u_format: u32, h_mem: *mut core::ffi::c_void) -> *mut core::ffi::c_void;
        fn CloseClipboard() -> i32;
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn GlobalAlloc(u_flags: u32, dw_bytes: usize) -> *mut core::ffi::c_void;
        fn GlobalLock(h_mem: *mut core::ffi::c_void) -> *mut core::ffi::c_void;
        fn GlobalUnlock(h_mem: *mut core::ffi::c_void) -> i32;
        fn GlobalFree(h_mem: *mut core::ffi::c_void) -> *mut core::ffi::c_void;
    }
    let wide: Vec<u16> = std::ffi::OsStr::new(text)
        .encode_wide()
        .chain(Some(0))
        .collect();
    let byte_len = wide.len() * core::mem::size_of::<u16>();
    unsafe {
        if OpenClipboard(core::ptr::null_mut()) == 0 {
            return false;
        }
        let _ = EmptyClipboard();
        let hmem = GlobalAlloc(GMEM_MOVEABLE, byte_len);
        if hmem.is_null() {
            let _ = CloseClipboard();
            return false;
        }
        let ptr = GlobalLock(hmem) as *mut u16;
        if ptr.is_null() {
            let _ = GlobalFree(hmem);
            let _ = CloseClipboard();
            return false;
        }
        core::ptr::copy_nonoverlapping(wide.as_ptr(), ptr, wide.len());
        let _ = GlobalUnlock(hmem);
        let res = SetClipboardData(CF_UNICODETEXT, hmem);
        let _ = CloseClipboard();
        if res.is_null() {
            let _ = GlobalFree(hmem);
            return false;
        }
        true
    }
}

#[cfg(not(target_os = "windows"))]
pub fn copy_text_to_windows_clipboard(_text: &str) -> bool {
    false
}

#[cfg(target_os = "windows")]
fn install_windows_seh_filter() {
    #[repr(C)]
    struct ExceptionRecord {
        exception_code: u32,
        exception_flags: u32,
        exception_record: *mut ExceptionRecord,
        exception_address: *mut core::ffi::c_void,
        number_parameters: u32,
        exception_information: [usize; 15],
    }
    #[repr(C)]
    struct ExceptionPointers {
        exception_record: *mut ExceptionRecord,
        context_record: *mut core::ffi::c_void,
    }
    type ExceptionFilterFn = unsafe extern "system" fn(*mut ExceptionPointers) -> i32;

    #[link(name = "kernel32")]
    extern "system" {
        fn SetUnhandledExceptionFilter(filter: ExceptionFilterFn) -> *mut core::ffi::c_void;
    }

    unsafe extern "system" fn seh_handler(ptrs: *mut ExceptionPointers) -> i32 {
        const EXCEPTION_EXECUTE_HANDLER: i32 = 1;
        let (code, addr) = if !ptrs.is_null() && !(*ptrs).exception_record.is_null() {
            let rec = &*(*ptrs).exception_record;
            (rec.exception_code, rec.exception_address as usize)
        } else {
            (0, 0)
        };
        let code_name = match code {
            0xC000_0005 => "EXCEPTION_ACCESS_VIOLATION",
            0xC000_00FD => "EXCEPTION_STACK_OVERFLOW",
            0xC000_001D => "EXCEPTION_ILLEGAL_INSTRUCTION",
            0xC000_0094 => "EXCEPTION_INT_DIVIDE_BY_ZERO",
            0xC000_0374 => "STATUS_HEAP_CORRUPTION",
            0xC000_0409 => "STATUS_STACK_BUFFER_OVERRUN",
            _ => "WINDOWS_SEH_EXCEPTION",
        };
        let summary = format!("{} (0x{:08X}) at 0x{:016X}", code_name, code, addr);
        let details = format!(
            "Exception Code : 0x{:08X} ({})\nFault Address  : 0x{:016X}\nPID            : {}",
            code,
            code_name,
            addr,
            std::process::id()
        );
        if let Some(root) = CRASH_ROAMING_ROOT.get() {
            let report = build_report(root, "windows_seh_exception", &summary, &details);
            save_crash_report_to_disk(root, &report);
            show_native_crash_dialog(
                "Singularity — Crash Report / Rapport d'erreur",
                &report.format_copyable_text(),
            );
        }
        EXCEPTION_EXECUTE_HANDLER
    }

    unsafe {
        let _ = SetUnhandledExceptionFilter(seh_handler);
    }
}

/// Displays a pure native Win32 modal Crash Report window with a selectable read-only error box
/// and a 1-click "Copier l'erreur / Copy Error" button. Works even if Chromium/CEF itself crashed!
#[cfg(target_os = "windows")]
pub fn show_native_crash_dialog(title: &str, report_text: &str) {
    use std::cell::RefCell;
    use std::os::windows::ffi::OsStrExt;

    fn wide(s: &str) -> Vec<u16> {
        std::ffi::OsStr::new(s).encode_wide().chain(Some(0)).collect()
    }

    thread_local! {
        static DIALOG_REPORT_TEXT: RefCell<String> = const { RefCell::new(String::new()) };
        static DIALOG_COPY_BTN: RefCell<*mut core::ffi::c_void> = const { RefCell::new(core::ptr::null_mut()) };
    }

    #[repr(C)]
    struct WndClassExW {
        cb_size: u32,
        style: u32,
        lpfn_wnd_proc: unsafe extern "system" fn(*mut core::ffi::c_void, u32, usize, isize) -> isize,
        cb_cls_extra: i32,
        cb_wnd_extra: i32,
        h_instance: *mut core::ffi::c_void,
        h_icon: *mut core::ffi::c_void,
        h_cursor: *mut core::ffi::c_void,
        hbr_background: *mut core::ffi::c_void,
        lpsz_menu_name: *const u16,
        lpsz_class_name: *const u16,
        h_icon_sm: *mut core::ffi::c_void,
    }
    #[repr(C)]
    struct Msg {
        hwnd: *mut core::ffi::c_void,
        message: u32,
        wparam: usize,
        lparam: isize,
        time: u32,
        pt_x: i32,
        pt_y: i32,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetModuleHandleW(lp_module_name: *const u16) -> *mut core::ffi::c_void;
    }
    #[link(name = "gdi32")]
    extern "system" {
        fn GetStockObject(i: i32) -> *mut core::ffi::c_void;
        fn CreateFontW(
            c_height: i32,
            c_width: i32,
            c_escapement: i32,
            c_orientation: i32,
            c_weight: i32,
            b_italic: u32,
            b_underline: u32,
            b_strike_out: u32,
            i_char_set: u32,
            i_out_precision: u32,
            i_clip_precision: u32,
            i_quality: u32,
            i_pitch_and_family: u32,
            psz_face_name: *const u16,
        ) -> *mut core::ffi::c_void;
        fn DeleteObject(ho: *mut core::ffi::c_void) -> i32;
    }
    #[link(name = "user32")]
    extern "system" {
        fn RegisterClassExW(wc: *const WndClassExW) -> u16;
        fn CreateWindowExW(
            dw_ex_style: u32,
            lp_class_name: *const u16,
            lp_window_name: *const u16,
            dw_style: u32,
            x: i32,
            y: i32,
            n_width: i32,
            n_height: i32,
            hwnd_parent: *mut core::ffi::c_void,
            h_menu: *mut core::ffi::c_void,
            h_instance: *mut core::ffi::c_void,
            lp_param: *mut core::ffi::c_void,
        ) -> *mut core::ffi::c_void;
        fn DefWindowProcW(hwnd: *mut core::ffi::c_void, msg: u32, wp: usize, lp: isize) -> isize;
        fn ShowWindow(hwnd: *mut core::ffi::c_void, n_cmd_show: i32) -> i32;
        fn UpdateWindow(hwnd: *mut core::ffi::c_void) -> i32;
        fn GetMessageW(lp_msg: *mut Msg, hwnd: *mut core::ffi::c_void, min: u32, max: u32) -> i32;
        fn TranslateMessage(lp_msg: *const Msg) -> i32;
        fn DispatchMessageW(lp_msg: *const Msg) -> isize;
        fn PostQuitMessage(exit_code: i32);
        fn DestroyWindow(hwnd: *mut core::ffi::c_void) -> i32;
        fn SendMessageW(hwnd: *mut core::ffi::c_void, msg: u32, wp: usize, lp: isize) -> isize;
        fn SetWindowTextW(hwnd: *mut core::ffi::c_void, lp_string: *const u16) -> i32;
        fn GetSystemMetrics(n_index: i32) -> i32;
        fn LoadCursorW(h_inst: *mut core::ffi::c_void, lp_cursor_name: *const u16) -> *mut core::ffi::c_void;
    }

    const ID_BTN_COPY: usize = 1001;
    const ID_BTN_CLOSE: usize = 1002;
    const WM_COMMAND: u32 = 0x0111;
    const WM_CLOSE: u32 = 0x0010;
    const WM_DESTROY: u32 = 0x0002;
    const WM_SETFONT: u32 = 0x0030;
    const WS_OVERLAPPED: u32 = 0x0000_0000;
    const WS_CAPTION: u32 = 0x00C0_0000;
    const WS_SYSMENU: u32 = 0x0008_0000;
    const WS_VISIBLE: u32 = 0x1000_0000;
    const WS_CHILD: u32 = 0x4000_0000;
    const WS_BORDER: u32 = 0x0080_0000;
    const WS_VSCROLL: u32 = 0x0020_0000;
    const WS_TABSTOP: u32 = 0x0001_0000;
    const WS_EX_TOPMOST: u32 = 0x0000_0008;
    const ES_MULTILINE: u32 = 0x0004;
    const ES_AUTOVSCROLL: u32 = 0x0040;
    const ES_READONLY: u32 = 0x0800;
    const BS_PUSHBUTTON: u32 = 0x0000;
    const BS_DEFPUSHBUTTON: u32 = 0x0001;
    const IDC_ARROW: usize = 32512;
    const DEFAULT_GUI_FONT: i32 = 17;

    unsafe extern "system" fn wnd_proc(
        hwnd: *mut core::ffi::c_void,
        msg: u32,
        wp: usize,
        lp: isize,
    ) -> isize {
        match msg {
            WM_COMMAND => {
                let id = wp & 0xFFFF;
                if id == ID_BTN_COPY {
                    let ok = DIALOG_REPORT_TEXT.with(|t| copy_text_to_windows_clipboard(&t.borrow()));
                    if ok {
                        DIALOG_COPY_BTN.with(|b| {
                            let btn = *b.borrow();
                            if !btn.is_null() {
                                let label = wide("Copié ! / Copied!");
                                let _ = SetWindowTextW(btn, label.as_ptr());
                            }
                        });
                    }
                    return 0;
                } else if id == ID_BTN_CLOSE {
                    let _ = DestroyWindow(hwnd);
                    return 0;
                }
                DefWindowProcW(hwnd, msg, wp, lp)
            }
            WM_CLOSE => {
                let _ = DestroyWindow(hwnd);
                0
            }
            WM_DESTROY => {
                PostQuitMessage(0);
                0
            }
            _ => DefWindowProcW(hwnd, msg, wp, lp),
        }
    }

    let crlf_text = report_text.replace("\r\n", "\n").replace('\n', "\r\n");
    DIALOG_REPORT_TEXT.with(|t| *t.borrow_mut() = crlf_text.clone());

    unsafe {
        let hinst = GetModuleHandleW(core::ptr::null());
        let cls_name = wide("SingularityCrashDialogWnd");
        let wc = WndClassExW {
            cb_size: core::mem::size_of::<WndClassExW>() as u32,
            style: 0,
            lpfn_wnd_proc: wnd_proc,
            cb_cls_extra: 0,
            cb_wnd_extra: 0,
            h_instance: hinst,
            h_icon: core::ptr::null_mut(),
            h_cursor: LoadCursorW(core::ptr::null_mut(), IDC_ARROW as *const u16),
            hbr_background: 16usize as *mut core::ffi::c_void, // COLOR_BTNFACE + 1
            lpsz_menu_name: core::ptr::null(),
            lpsz_class_name: cls_name.as_ptr(),
            h_icon_sm: core::ptr::null_mut(),
        };
        let _ = RegisterClassExW(&wc);

        let w = 680;
        let h = 500;
        let sx = GetSystemMetrics(0);
        let sy = GetSystemMetrics(1);
        let x = ((sx - w) / 2).max(40);
        let y = ((sy - h) / 2).max(40);
        let title_w = wide(title);
        let hwnd = CreateWindowExW(
            WS_EX_TOPMOST,
            cls_name.as_ptr(),
            title_w.as_ptr(),
            WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
            x,
            y,
            w,
            h,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            hinst,
            core::ptr::null_mut(),
        );
        if hwnd.is_null() {
            return;
        }

        let ui_font = GetStockObject(DEFAULT_GUI_FONT);
        let mono_name = wide("Consolas");
        let mono_font = CreateFontW(
            -13,
            0,
            0,
            0,
            400,
            0,
            0,
            0,
            1,
            0,
            0,
            5,
            49,
            mono_name.as_ptr(),
        );

        let static_cls = wide("STATIC");
        let hdr_txt = wide("Singularity a rencontré une erreur. Copiez ce rapport pour l'envoyer :");
        let hdr = CreateWindowExW(
            0,
            static_cls.as_ptr(),
            hdr_txt.as_ptr(),
            WS_CHILD | WS_VISIBLE,
            16,
            14,
            632,
            24,
            hwnd,
            core::ptr::null_mut(),
            hinst,
            core::ptr::null_mut(),
        );
        if !hdr.is_null() && !ui_font.is_null() {
            let _ = SendMessageW(hdr, WM_SETFONT, ui_font as usize, 1);
        }

        let edit_cls = wide("EDIT");
        let body_w = wide(&crlf_text);
        let edit = CreateWindowExW(
            0,
            edit_cls.as_ptr(),
            body_w.as_ptr(),
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
            16,
            42,
            632,
            360,
            hwnd,
            core::ptr::null_mut(),
            hinst,
            core::ptr::null_mut(),
        );
        if !edit.is_null() {
            let f = if !mono_font.is_null() { mono_font } else { ui_font };
            if !f.is_null() {
                let _ = SendMessageW(edit, WM_SETFONT, f as usize, 1);
            }
        }

        let btn_cls = wide("BUTTON");
        let copy_txt = wide("Copier l'erreur / Copy Error");
        let btn_copy = CreateWindowExW(
            0,
            btn_cls.as_ptr(),
            copy_txt.as_ptr(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
            16,
            414,
            230,
            34,
            hwnd,
            ID_BTN_COPY as *mut core::ffi::c_void,
            hinst,
            core::ptr::null_mut(),
        );
        if !btn_copy.is_null() && !ui_font.is_null() {
            let _ = SendMessageW(btn_copy, WM_SETFONT, ui_font as usize, 1);
        }
        DIALOG_COPY_BTN.with(|b| *b.borrow_mut() = btn_copy);

        let close_txt = wide("Fermer / Close");
        let btn_close = CreateWindowExW(
            0,
            btn_cls.as_ptr(),
            close_txt.as_ptr(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            518,
            414,
            130,
            34,
            hwnd,
            ID_BTN_CLOSE as *mut core::ffi::c_void,
            hinst,
            core::ptr::null_mut(),
        );
        if !btn_close.is_null() && !ui_font.is_null() {
            let _ = SendMessageW(btn_close, WM_SETFONT, ui_font as usize, 1);
        }

        let _ = ShowWindow(hwnd, 5);
        let _ = UpdateWindow(hwnd);

        let mut msg = Msg {
            hwnd: core::ptr::null_mut(),
            message: 0,
            wparam: 0,
            lparam: 0,
            time: 0,
            pt_x: 0,
            pt_y: 0,
        };
        while GetMessageW(&mut msg, core::ptr::null_mut(), 0, 0) > 0 {
            let _ = TranslateMessage(&msg);
            let _ = DispatchMessageW(&msg);
        }
        DIALOG_COPY_BTN.with(|b| *b.borrow_mut() = core::ptr::null_mut());
        if !mono_font.is_null() {
            let _ = DeleteObject(mono_font);
        }
    }
}
