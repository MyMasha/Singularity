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
#[cfg(target_os = "windows")]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

static CRASH_ROAMING_ROOT: OnceLock<PathBuf> = OnceLock::new();
#[cfg(target_os = "windows")]
static SEH_CRASH_JSON_PATH_W: OnceLock<Vec<u16>> = OnceLock::new();
#[cfg(target_os = "windows")]
static SEH_CRASH_TXT_PATH_W: OnceLock<Vec<u16>> = OnceLock::new();
#[cfg(target_os = "windows")]
static PANIC_DIALOG_SHOWN: AtomicBool = AtomicBool::new(false);

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

/// Reads the last `max_lines` lines from at most the final 64 KiB of `%APPDATA%\.singularity\cef.log`
/// using `SeekFrom::End` so large log files are never loaded entirely into RAM.
pub fn read_cef_log_tail(roaming_root: &Path, max_lines: usize) -> String {
    use std::io::{Read, Seek, SeekFrom};
    let max_bytes: usize = 64 * 1024;
    let path = roaming_root.join("cef.log");
    let Ok(mut file) = std::fs::File::open(&path) else {
        return String::new();
    };
    let file_len = file.metadata().map(|m| m.len()).unwrap_or(0);
    if file_len == 0 {
        return String::new();
    }
    if file_len > max_bytes as u64 {
        if file.seek(SeekFrom::End(-(max_bytes as i64))).is_err() {
            return String::new();
        }
    }
    let mut bytes = Vec::with_capacity((file_len.min(max_bytes as u64)) as usize);
    if file.take(max_bytes as u64).read_to_end(&mut bytes).is_err() {
        return String::new();
    }
    let text = String::from_utf8_lossy(&bytes);
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
        let _ = std::fs::write(dir.join(format!("{}.json", report.id)), &json);
    }
}

/// Lists all persisted crash reports in `%APPDATA%\.singularity\crashes`, newest first.
pub fn list_crash_reports(roaming_root: &Path) -> Vec<CrashReport> {
    let dir = crashes_dir(roaming_root);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut reports = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !name.ends_with(".json") || name == "last_crash.json" {
            continue;
        }
        if let Ok(bytes) = std::fs::read(&path) {
            if let Ok(rep) = serde_json::from_slice::<CrashReport>(&bytes) {
                reports.push(rep);
            }
        }
    }
    if let Ok(bytes) = std::fs::read(dir.join("last_crash.json")) {
        if let Ok(rep) = serde_json::from_slice::<CrashReport>(&bytes) {
            if reports.is_empty()
                || (!rep.acknowledged && !reports.iter().any(|existing| existing.id == rep.id))
            {
                reports.push(rep);
            }
        }
    }
    reports.sort_by(|a, b| b.timestamp_unix.cmp(&a.timestamp_unix));
    reports
}

/// Deletes a single crash report by ID (`crash-...`) safely without path traversal.
pub fn delete_crash_report(roaming_root: &Path, id: &str) -> bool {
    let clean = id.trim();
    if clean.is_empty()
        || !clean
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return false;
    }
    let dir = crashes_dir(roaming_root);
    let r1 = std::fs::remove_file(dir.join(format!("{clean}.json"))).is_ok();
    let r2 = std::fs::remove_file(dir.join(format!("{clean}.txt"))).is_ok();
    r1 || r2
}

/// Purges all stored crash reports and clears `last_crash.*`.
pub fn purge_all_crash_reports(roaming_root: &Path) -> usize {
    let dir = crashes_dir(roaming_root);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return 0;
    };
    let mut removed = 0usize;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() && std::fs::remove_file(&path).is_ok() {
            removed += 1;
        }
    }
    removed
}

/// Strips OS username and absolute home directory paths from a diagnostic text block.
pub fn anonymize_crash_text(raw: &str) -> String {
    let mut out = raw.to_string();
    for env_key in ["USERPROFILE", "HOME", "USERNAME", "USER"] {
        if let Ok(val) = std::env::var(env_key) {
            if val.len() >= 3 {
                out = out.replace(&val, "<REDACTED>");
            }
        }
    }
    out
}

/// Detects whether two or more crashes occurred within `window_secs` (default 60s) to trigger
/// the selective `singularity://session-restore` anti-crash-loop screen.
pub fn is_crash_loop_detected(roaming_root: &Path, now_unix: u64, window_secs: u64) -> bool {
    let reports = list_crash_reports(roaming_root);
    let recent = reports
        .iter()
        .filter(|r| now_unix.saturating_sub(r.timestamp_unix) <= window_secs)
        .count();
    recent >= 2
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

#[cfg(target_os = "windows")]
fn should_show_native_panic_dialog(thread_name: &str) -> bool {
    if cfg!(test) {
        return false;
    }
    if std::env::var_os("SINGULARITY_HEADLESS").is_some()
        || std::env::var_os("SINGULARITY_NO_CRASH_DIALOG").is_some()
        || std::env::var_os("CI").is_some()
    {
        return false;
    }
    // Only display a blocking Win32 modal dialog for fatal main-thread panics; non-fatal worker
    // panics (including those caught via `catch_unwind`) persist to disk without deadlocking UI/tests.
    thread_name == "main"
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
        let details = format!(
            "Location: {}\nThread: {}\nMessage: {}\n\nBacktrace:\n{}",
            loc, tname, payload, bt
        );

        if let Some(root) = CRASH_ROAMING_ROOT.get() {
            let report = build_report(root, "rust_panic", &summary, &details);
            save_crash_report_to_disk(root, &report);
            #[cfg(target_os = "windows")]
            if should_show_native_panic_dialog(tname)
                && !PANIC_DIALOG_SHOWN.swap(true, Ordering::SeqCst)
            {
                show_native_crash_dialog(
                    "Singularity — Crash Report / Rapport d'erreur",
                    &report.format_copyable_text(),
                );
            }
        }
        prev_hook(info);
    }));

    #[cfg(target_os = "windows")]
    install_windows_seh_filter(roaming_root);
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
    if pid == 0 || pid > i32::MAX as u32 {
        return false;
    }
    extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }
    // POSIX `kill(pid, 0)` works portably across Linux and macOS without relying on `/proc`.
    let rc = unsafe { kill(pid as i32, 0) };
    if rc == 0 {
        return true;
    }
    std::io::Error::last_os_error().kind() == std::io::ErrorKind::PermissionDenied
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

    let dir = crashes_dir(roaming_root);
    let last_json = dir.join("last_crash.json");
    if let Ok(bytes) = std::fs::read(&last_json) {
        if let Ok(mut rep) = serde_json::from_slice::<CrashReport>(&bytes) {
            if !rep.acknowledged {
                rep.acknowledged = true;
                if rep.cef_log_tail.trim().is_empty() {
                    let log_tail = if !prev_cef_log_tail.trim().is_empty() {
                        prev_cef_log_tail.to_string()
                    } else {
                        read_cef_log_tail(roaming_root, 35)
                    };
                    rep.cef_log_tail = log_tail;
                }
                if let Ok(updated) = serde_json::to_vec_pretty(&rep) {
                    let _ = std::fs::write(&last_json, &updated);
                    // Archive SEH (or otherwise unarchived) crash reports under `crashes/<id>.json`
                    // so subsequent crashes do not erase history and `is_crash_loop_detected` works.
                    let id_is_safe = !rep.id.is_empty()
                        && rep
                            .id
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
                    if id_is_safe {
                        let archive_json = dir.join(format!("{}.json", rep.id));
                        if !archive_json.exists() {
                            let _ = std::fs::write(&archive_json, &updated);
                        }
                        let archive_txt = dir.join(format!("{}.txt", rep.id));
                        if !archive_txt.exists() {
                            let _ = std::fs::write(&archive_txt, rep.format_copyable_text());
                        }
                    }
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
fn install_windows_seh_filter(roaming_root: &Path) {
    use std::os::windows::ffi::OsStrExt;

    let cdir = crashes_dir(roaming_root);
    let _ = std::fs::create_dir_all(&cdir);
    let json_wide: Vec<u16> = cdir
        .join("last_crash.json")
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let txt_wide: Vec<u16> = cdir
        .join("last_crash.txt")
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let _ = SEH_CRASH_JSON_PATH_W.set(json_wide);
    let _ = SEH_CRASH_TXT_PATH_W.set(txt_wide);

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
    #[repr(C)]
    struct FileTime {
        dw_low_date_time: u32,
        dw_high_date_time: u32,
    }
    type ExceptionFilterFn = unsafe extern "system" fn(*mut ExceptionPointers) -> i32;

    struct StackBuf<const N: usize> {
        buf: [u8; N],
        len: usize,
    }

    impl<const N: usize> StackBuf<N> {
        const fn new() -> Self {
            Self {
                buf: [0u8; N],
                len: 0,
            }
        }

        fn push_bytes(&mut self, bytes: &[u8]) {
            let mut i = 0;
            while i < bytes.len() && self.len < N {
                self.buf[self.len] = bytes[i];
                self.len += 1;
                i += 1;
            }
        }

        fn push_hex_u32(&mut self, val: u32) {
            const HEX: &[u8; 16] = b"0123456789ABCDEF";
            let mut i = 0;
            while i < 8 {
                let shift = (7 - i) * 4;
                let nib = ((val >> shift) & 0xF) as usize;
                self.push_bytes(&[HEX[nib]]);
                i += 1;
            }
        }

        fn push_hex_u64(&mut self, val: u64) {
            const HEX: &[u8; 16] = b"0123456789ABCDEF";
            let mut i = 0;
            while i < 16 {
                let shift = (15 - i) * 4;
                let nib = ((val >> shift) & 0xF) as usize;
                self.push_bytes(&[HEX[nib]]);
                i += 1;
            }
        }

        fn push_dec_u64(&mut self, mut val: u64) {
            let mut tmp = [0u8; 20];
            let mut n = 0usize;
            if val == 0 {
                self.push_bytes(b"0");
                return;
            }
            while val > 0 && n < tmp.len() {
                tmp[n] = b'0' + (val % 10) as u8;
                val /= 10;
                n += 1;
            }
            while n > 0 {
                n -= 1;
                self.push_bytes(&[tmp[n]]);
            }
        }

        fn as_slice(&self) -> &[u8] {
            &self.buf[..self.len]
        }
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn SetUnhandledExceptionFilter(filter: ExceptionFilterFn) -> *mut core::ffi::c_void;
        fn GetCurrentProcess() -> *mut core::ffi::c_void;
        fn GetCurrentProcessId() -> u32;
        fn GetSystemTimeAsFileTime(lp_system_time_as_file_time: *mut FileTime);
        fn CreateFileW(
            lp_file_name: *const u16,
            dw_desired_access: u32,
            dw_share_mode: u32,
            lp_security_attributes: *mut core::ffi::c_void,
            dw_creation_disposition: u32,
            dw_flags_and_attributes: u32,
            h_template_file: *mut core::ffi::c_void,
        ) -> *mut core::ffi::c_void;
        fn WriteFile(
            h_file: *mut core::ffi::c_void,
            lp_buffer: *const u8,
            n_number_of_bytes_to_write: u32,
            lp_number_of_bytes_written: *mut u32,
            lp_overlapped: *mut core::ffi::c_void,
        ) -> i32;
        fn CloseHandle(h_object: *mut core::ffi::c_void) -> i32;
        fn Sleep(dw_milliseconds: u32);
        fn TerminateProcess(h_process: *mut core::ffi::c_void, u_exit_code: u32) -> i32;
    }

    unsafe fn write_raw_file_w(path_w: *const u16, data: &[u8]) {
        const GENERIC_WRITE: u32 = 0x4000_0000;
        const FILE_SHARE_READ: u32 = 0x0000_0001;
        const CREATE_ALWAYS: u32 = 2;
        const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
        let invalid_handle = (-1isize) as *mut core::ffi::c_void;

        let handle = CreateFileW(
            path_w,
            GENERIC_WRITE,
            FILE_SHARE_READ,
            core::ptr::null_mut(),
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            core::ptr::null_mut(),
        );
        if handle.is_null() || handle == invalid_handle {
            return;
        }
        let mut written: u32 = 0;
        let _ = WriteFile(
            handle,
            data.as_ptr(),
            data.len() as u32,
            &mut written,
            core::ptr::null_mut(),
        );
        let _ = CloseHandle(handle);
    }

    static SEH_IN_PROGRESS: AtomicBool = AtomicBool::new(false);

    // Strictly async/SEH-safe handler: reentrancy-guarded, zero heap allocations, zero `cef.log`
    // reads, and zero Win32 GUI message loop (`GetMessageW`). Writes minimal crash markers via
    // fixed stack buffers & raw Win32 file APIs and terminates cleanly; recovery UI displays on
    // the next Singularity launch.
    unsafe extern "system" fn seh_handler(ptrs: *mut ExceptionPointers) -> i32 {
        const EXCEPTION_EXECUTE_HANDLER: i32 = 1;
        let (code, addr) = if !ptrs.is_null() && !(*ptrs).exception_record.is_null() {
            let rec = &*(*ptrs).exception_record;
            (rec.exception_code, rec.exception_address as usize as u64)
        } else {
            (0u32, 0u64)
        };
        let exit_code = if code != 0 { code } else { 1 };
        if SEH_IN_PROGRESS.swap(true, Ordering::SeqCst) {
            // Allow the first crashing thread to finish flushing `last_crash.json` before exit.
            Sleep(3000);
            let _ = TerminateProcess(GetCurrentProcess(), exit_code);
            return EXCEPTION_EXECUTE_HANDLER;
        }

        let code_name: &[u8] = match code {
            0xC000_0005 => b"EXCEPTION_ACCESS_VIOLATION",
            0xC000_00FD => b"EXCEPTION_STACK_OVERFLOW",
            0xC000_001D => b"EXCEPTION_ILLEGAL_INSTRUCTION",
            0xC000_0094 => b"EXCEPTION_INT_DIVIDE_BY_ZERO",
            0xC000_0374 => b"STATUS_HEAP_CORRUPTION",
            0xC000_0409 => b"STATUS_STACK_BUFFER_OVERRUN",
            _ => b"WINDOWS_SEH_EXCEPTION",
        };
        let pid = GetCurrentProcessId();
        let mut ft = FileTime {
            dw_low_date_time: 0,
            dw_high_date_time: 0,
        };
        GetSystemTimeAsFileTime(&mut ft);
        let ticks_100ns = ((ft.dw_high_date_time as u64) << 32) | (ft.dw_low_date_time as u64);
        const WINDOWS_TO_UNIX_EPOCH_100NS: u64 = 116_444_736_000_000_000;
        let ts_unix = ticks_100ns.saturating_sub(WINDOWS_TO_UNIX_EPOCH_100NS) / 10_000_000;

        if let Some(json_path) = SEH_CRASH_JSON_PATH_W.get() {
            let mut jbuf = StackBuf::<1024>::new();
            jbuf.push_bytes(b"{\"id\":\"seh-");
            jbuf.push_dec_u64(ts_unix);
            jbuf.push_bytes(b"-");
            jbuf.push_dec_u64(pid as u64);
            jbuf.push_bytes(b"-");
            jbuf.push_hex_u32(code);
            jbuf.push_bytes(b"\",\"timestamp_unix\":");
            jbuf.push_dec_u64(ts_unix);
            jbuf.push_bytes(b",\"version\":\"");
            jbuf.push_bytes(env!("CARGO_PKG_VERSION").as_bytes());
            jbuf.push_bytes(b"\",\"os_arch\":\"windows-");
            jbuf.push_bytes(std::env::consts::ARCH.as_bytes());
            jbuf.push_bytes(b"\",\"kind\":\"windows_seh_exception\",\"summary\":\"");
            jbuf.push_bytes(code_name);
            jbuf.push_bytes(b" (0x");
            jbuf.push_hex_u32(code);
            jbuf.push_bytes(b") at 0x");
            jbuf.push_hex_u64(addr);
            jbuf.push_bytes(b"\",\"details\":\"Exception Code : 0x");
            jbuf.push_hex_u32(code);
            jbuf.push_bytes(b" (");
            jbuf.push_bytes(code_name);
            jbuf.push_bytes(b")\\nFault Address  : 0x");
            jbuf.push_hex_u64(addr);
            jbuf.push_bytes(b"\\nPID            : ");
            jbuf.push_dec_u64(pid as u64);
            jbuf.push_bytes(b"\",\"cef_log_tail\":\"\",\"acknowledged\":false}\n");
            write_raw_file_w(json_path.as_ptr(), jbuf.as_slice());
        }

        if let Some(txt_path) = SEH_CRASH_TXT_PATH_W.get() {
            let mut tbuf = StackBuf::<512>::new();
            tbuf.push_bytes(b"=== SINGULARITY BROWSER CRASH REPORT (SEH) ===\nVersion   : v");
            tbuf.push_bytes(env!("CARGO_PKG_VERSION").as_bytes());
            tbuf.push_bytes(b"\nTimestamp : ");
            tbuf.push_dec_u64(ts_unix);
            tbuf.push_bytes(b"\nException : 0x");
            tbuf.push_hex_u32(code);
            tbuf.push_bytes(b" (");
            tbuf.push_bytes(code_name);
            tbuf.push_bytes(b")\nAddress   : 0x");
            tbuf.push_hex_u64(addr);
            tbuf.push_bytes(b"\nPID       : ");
            tbuf.push_dec_u64(pid as u64);
            tbuf.push_bytes(b"\n==============================================\n");
            write_raw_file_w(txt_path.as_ptr(), tbuf.as_slice());
        }

        let _ = TerminateProcess(GetCurrentProcess(), exit_code);
        EXCEPTION_EXECUTE_HANDLER
    }

    unsafe {
        let _ = SetUnhandledExceptionFilter(seh_handler);
    }
}

/// Displays a pure native Win32 modal Crash Report window with a selectable read-only error box
/// and a 1-click "Copy Error / Copier l'erreur" button. Works even if Chromium/CEF itself crashed!
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
                                let label = wide("Copied! / Copié !");
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
        let hdr_txt = wide(
            "Singularity encountered an error — copy this report / Erreur détectée — copiez ce rapport :",
        );
        let hdr = CreateWindowExW(
            0,
            static_cls.as_ptr(),
            hdr_txt.as_ptr(),
            WS_CHILD | WS_VISIBLE,
            16,
            12,
            632,
            28,
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
            44,
            632,
            358,
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
        let copy_txt = wide("Copy Error / Copier l'erreur");
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

        let close_txt = wide("Close / Fermer");
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

#[cfg(target_os = "windows")]
static SHUTDOWN_SENTINEL_ROOT: OnceLock<PathBuf> = OnceLock::new();

/// Hidden top-level Win32 window created AFTER CEF initialization so Windows broadcasts
/// `WM_QUERYENDSESSION` / `WM_ENDSESSION` to it even if Chromium's own hidden shutdown window
/// exits before `tao`'s `Event::LoopDestroyed` finishes. Removes `running.lock` and arms
/// `planned_restart.flag` atomically with zero mutexes and zero CEF re-entrancy.
#[cfg(target_os = "windows")]
pub struct Win32ShutdownSentinel {
    hwnd: isize,
}

#[cfg(target_os = "windows")]
impl Win32ShutdownSentinel {
    pub fn install(roaming_root: &Path) -> Self {
        use std::os::windows::ffi::OsStrExt;
        let _ = SHUTDOWN_SENTINEL_ROOT.set(roaming_root.to_path_buf());

        #[repr(C)]
        struct WndClassExW {
            cb_size: u32,
            style: u32,
            lpfn_wnd_proc:
                unsafe extern "system" fn(*mut core::ffi::c_void, u32, usize, isize) -> isize,
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

        #[link(name = "kernel32")]
        extern "system" {
            fn GetModuleHandleW(lp_module_name: *const u16) -> *mut core::ffi::c_void;
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
            fn DefWindowProcW(
                hwnd: *mut core::ffi::c_void,
                msg: u32,
                wp: usize,
                lp: isize,
            ) -> isize;
        }

        const WM_QUERYENDSESSION: u32 = 0x0011;
        const WM_ENDSESSION: u32 = 0x0016;
        const WS_OVERLAPPED: u32 = 0x0000_0000;
        const WS_EX_TOOLWINDOW: u32 = 0x0000_0080;
        const WS_EX_NOACTIVATE: u32 = 0x0800_0000;

        unsafe extern "system" fn sentinel_wnd_proc(
            hwnd: *mut core::ffi::c_void,
            msg: u32,
            wp: usize,
            lp: isize,
        ) -> isize {
            match msg {
                WM_QUERYENDSESSION => 1, // Ready to shut down; never block Windows shutdown
                WM_ENDSESSION => {
                    if wp != 0 {
                        if let Some(root) = SHUTDOWN_SENTINEL_ROOT.get() {
                            mark_planned_restart(root);
                        }
                    }
                    0
                }
                _ => DefWindowProcW(hwnd, msg, wp, lp),
            }
        }

        let cls: Vec<u16> = std::ffi::OsStr::new("SingularityShutdownSentinelClass")
            .encode_wide()
            .chain(Some(0))
            .collect();
        let title: Vec<u16> = std::ffi::OsStr::new("SingularityShutdownSentinel")
            .encode_wide()
            .chain(Some(0))
            .collect();

        let hwnd = unsafe {
            let hinst = GetModuleHandleW(core::ptr::null());
            let wc = WndClassExW {
                cb_size: core::mem::size_of::<WndClassExW>() as u32,
                style: 0,
                lpfn_wnd_proc: sentinel_wnd_proc,
                cb_cls_extra: 0,
                cb_wnd_extra: 0,
                h_instance: hinst,
                h_icon: core::ptr::null_mut(),
                h_cursor: core::ptr::null_mut(),
                hbr_background: core::ptr::null_mut(),
                lpsz_menu_name: core::ptr::null(),
                lpsz_class_name: cls.as_ptr(),
                h_icon_sm: core::ptr::null_mut(),
            };
            let _ = RegisterClassExW(&wc);
            CreateWindowExW(
                WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE,
                cls.as_ptr(),
                title.as_ptr(),
                WS_OVERLAPPED,
                0,
                0,
                0,
                0,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                hinst,
                core::ptr::null_mut(),
            )
        };
        Self {
            hwnd: hwnd as isize,
        }
    }
}

#[cfg(target_os = "windows")]
impl Drop for Win32ShutdownSentinel {
    fn drop(&mut self) {
        if self.hwnd != 0 {
            #[link(name = "user32")]
            extern "system" {
                fn DestroyWindow(hwnd: *mut core::ffi::c_void) -> i32;
            }
            unsafe {
                let _ = DestroyWindow(self.hwnd as *mut core::ffi::c_void);
            }
            self.hwnd = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seh_consecutive_crashes_archived_and_trigger_crash_loop_detection() {
        let unique = format!(
            "singularity_crash_loop_seh_test_{}_{}",
            std::process::id(),
            unix_now_secs()
        );
        let root = std::env::temp_dir().join(unique);
        let _ = std::fs::remove_dir_all(&root);
        let crashes = crashes_dir(&root);
        std::fs::create_dir_all(&crashes).expect("mkdir crashes");

        let now = unix_now_secs();
        let seh1 = CrashReport {
            id: format!("seh-{}-1001-C0000005", now.saturating_sub(15)),
            timestamp_unix: now.saturating_sub(15),
            version: env!("CARGO_PKG_VERSION").to_string(),
            os_arch: "windows-x86_64".to_string(),
            kind: "windows_seh_exception".to_string(),
            summary: "EXCEPTION_ACCESS_VIOLATION (0xC0000005) at 0x0".to_string(),
            details: "Crash 1".to_string(),
            cef_log_tail: String::new(),
            acknowledged: false,
        };
        std::fs::write(
            crashes.join("last_crash.json"),
            serde_json::to_vec(&seh1).unwrap(),
        )
        .expect("write seh1");

        let d1 = detect_previous_crash_and_mark_running_with_cef_log(&root, "cef line 1")
            .expect("detect seh1");
        assert_eq!(d1.id, seh1.id);
        assert!(crashes.join(format!("{}.json", seh1.id)).is_file());
        assert!(!is_crash_loop_detected(&root, now, 60));

        // Second SEH crash overwrites `last_crash.json` without creating its own archive file.
        let seh2 = CrashReport {
            id: format!("seh-{}-1002-C0000005", now.saturating_sub(5)),
            timestamp_unix: now.saturating_sub(5),
            version: env!("CARGO_PKG_VERSION").to_string(),
            os_arch: "windows-x86_64".to_string(),
            kind: "windows_seh_exception".to_string(),
            summary: "EXCEPTION_ACCESS_VIOLATION (0xC0000005) at 0x10".to_string(),
            details: "Crash 2".to_string(),
            cef_log_tail: String::new(),
            acknowledged: false,
        };
        std::fs::write(
            crashes.join("last_crash.json"),
            serde_json::to_vec(&seh2).unwrap(),
        )
        .expect("write seh2");

        // Even before archiving seh2, crash loop is already detectable, and after archiving both exist.
        assert!(is_crash_loop_detected(&root, now, 60));
        let d2 = detect_previous_crash_and_mark_running_with_cef_log(&root, "cef line 2")
            .expect("detect seh2");
        assert_eq!(d2.id, seh2.id);
        assert!(crashes.join(format!("{}.json", seh2.id)).is_file());
        assert_eq!(list_crash_reports(&root).len(), 2);
        assert!(is_crash_loop_detected(&root, now, 60));

        // Path traversal IDs in `last_crash.json` must never be written outside `crashes/`.
        let bad = CrashReport {
            id: "../escape".to_string(),
            timestamp_unix: now,
            version: env!("CARGO_PKG_VERSION").to_string(),
            os_arch: "windows-x86_64".to_string(),
            kind: "windows_seh_exception".to_string(),
            summary: "bad".to_string(),
            details: "bad".to_string(),
            cef_log_tail: String::new(),
            acknowledged: false,
        };
        std::fs::write(
            crashes.join("last_crash.json"),
            serde_json::to_vec(&bad).unwrap(),
        )
        .expect("write bad");
        let _ = detect_previous_crash_and_mark_running_with_cef_log(&root, "");
        assert!(!root.join("escape.json").exists());

        let _ = std::fs::remove_dir_all(&root);
    }
}

