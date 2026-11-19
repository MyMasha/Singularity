#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! Singularity Official Pure Native Win32 Setup Wizard (`Singularity-Setup.exe`).
//!
//! Engineered with 100% pure Win32 C-ABI (`user32`, `gdi32`, `dwmapi`, `advapi32`, `ole32`, `shell32`):
//! - ZERO WebView2 / Edge subprocesses (eliminates elevated/PCA WebView2 `wait_with_pump` freezes).
//! - ZERO `powershell.exe`, `cmd.exe`, or `taskkill.exe` child processes (eliminates AMSI/stdin hangs).
//! - Embedded `asInvoker` + `PerMonitorV2` Win32 manifest for instant (<10ms) high-DPI launch.
//! - 60 FPS double-buffered SDF + ClearType GDI UI on main thread; 100% of disk, Registry, and COM
//!   `.lnk` shortcut work runs asynchronously on a background worker thread via `PostMessageW`.

use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

const EMBEDDED_SINGULARITY_EXE: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/embedded_singularity.bin"));
const EMBEDDED_SINGULARITY_ICO: &[u8] =
    include_bytes!("../../singularity-ui/assets/singularity.ico");

#[cfg(target_os = "windows")]
const EMBEDDED_LOGO_128_RGBA: &[u8] =
    include_bytes!("../../singularity-ui/assets/logo_128.rgba");

#[derive(Debug, Clone)]
struct InstallOptions {
    install_dir: String,
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    desktop_shortcut: bool,
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    start_menu_shortcut: bool,
    init_roaming_vault: bool,
    launch_after_install: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InstallPhase {
    Idle,
    Running,
    Done,
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    Error,
}

#[derive(Debug, Clone)]
struct SharedProgress {
    phase: InstallPhase,
    target_pct: f32,
    step_label: String,
    installed_exe: String,
    error_msg: String,
}

fn default_install_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            let trimmed = local.trim();
            if !trimmed.is_empty() {
                return PathBuf::from(trimmed).join("Programs").join("Singularity");
            }
        }
        if let Ok(profile) = std::env::var("USERPROFILE") {
            let trimmed = profile.trim();
            if !trimmed.is_empty() {
                return PathBuf::from(trimmed)
                    .join("AppData")
                    .join("Local")
                    .join("Programs")
                    .join("Singularity");
            }
        }
        PathBuf::from(r"C:\Singularity")
    }
    #[cfg(not(target_os = "windows"))]
    {
        if let Ok(home) = std::env::var("HOME") {
            let trimmed = home.trim();
            if !trimmed.is_empty() {
                return PathBuf::from(trimmed).join(".local").join("share").join("Singularity");
            }
        }
        PathBuf::from("/tmp/Singularity")
    }
}

fn roaming_singularity_dir() -> PathBuf {
    if let Ok(override_dir) = std::env::var("SINGULARITY_ROAMING_DIR") {
        let trimmed = override_dir.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    #[cfg(target_os = "windows")]
    {
        if let Ok(appdata) = std::env::var("APPDATA") {
            let trimmed = appdata.trim();
            if !trimmed.is_empty() {
                return PathBuf::from(trimmed).join(".singularity");
            }
        }
        if let Ok(profile) = std::env::var("USERPROFILE") {
            let trimmed = profile.trim();
            if !trimmed.is_empty() {
                return PathBuf::from(trimmed)
                    .join("AppData")
                    .join("Roaming")
                    .join(".singularity");
            }
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        let trimmed = home.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed).join(".singularity");
        }
    }
    std::env::temp_dir().join(".singularity")
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!(
            "Singularity-Setup v{} (native Win32 installer, payload: {} bytes)",
            APP_VERSION,
            EMBEDDED_SINGULARITY_EXE.len()
        );
        return;
    }

    if args.iter().any(|a| a == "--verify-only") {
        assert!(
            EMBEDDED_SINGULARITY_EXE.len() > 512 * 1024,
            "Embedded singularity.exe payload looks truncated"
        );
        assert!(
            EMBEDDED_SINGULARITY_ICO.len() > 4096,
            "Embedded singularity.ico looks truncated"
        );
        println!(
            "[OK] Singularity-Setup v{} (Pure Native Win32) verified — singularity.exe = {:.2} MB, icon = {} KB",
            APP_VERSION,
            EMBEDDED_SINGULARITY_EXE.len() as f64 / (1024.0 * 1024.0),
            EMBEDDED_SINGULARITY_ICO.len() / 1024
        );
        return;
    }

    let silent = args
        .iter()
        .any(|a| a == "--silent" || a.eq_ignore_ascii_case("/s") || a == "--quiet");

    let mut custom_dir: Option<String> = None;
    for i in 1..args.len() {
        if (args[i] == "--dir" || args[i] == "-d") && i + 1 < args.len() {
            custom_dir = Some(args[i + 1].clone());
        }
    }

    if silent || cfg!(not(target_os = "windows")) {
        let opts = InstallOptions {
            install_dir: custom_dir
                .unwrap_or_else(|| default_install_dir().to_string_lossy().into_owned()),
            desktop_shortcut: true,
            start_menu_shortcut: true,
            init_roaming_vault: true,
            launch_after_install: false,
        };
        let progress = Arc::new(Mutex::new(SharedProgress {
            phase: InstallPhase::Idle,
            target_pct: 0.0,
            step_label: String::new(),
            installed_exe: String::new(),
            error_msg: String::new(),
        }));
        if let Err(e) = perform_installation(&opts, &progress, || {}) {
            eprintln!("[Singularity-Setup] Error: {e}");
            std::process::exit(1);
        }
        let g = progress.lock().unwrap_or_else(|e| e.into_inner());
        println!(
            "[Singularity-Setup] Installed Singularity v{} to {}",
            APP_VERSION, g.installed_exe
        );
        return;
    }

    #[cfg(target_os = "windows")]
    {
        if let Err(e) = win32_gui::run_native_installer() {
            eprintln!("[Singularity-Setup] GUI error: {e}");
            std::process::exit(1);
        }
    }
}

fn set_step<F: Fn()>(
    progress: &Arc<Mutex<SharedProgress>>,
    pct: f32,
    label: &str,
    notify: &F,
) {
    {
        let mut g = progress.lock().unwrap_or_else(|e| e.into_inner());
        g.phase = InstallPhase::Running;
        g.target_pct = pct;
        g.step_label = label.to_string();
    }
    notify();
}

fn perform_installation<F: Fn()>(
    opts: &InstallOptions,
    progress: &Arc<Mutex<SharedProgress>>,
    notify: F,
) -> Result<PathBuf, String> {
    if EMBEDDED_SINGULARITY_EXE.is_empty() {
        return Err("Installer binary was built without an embedded singularity payload.".into());
    }
    let target_dir = PathBuf::from(opts.install_dir.trim());
    if target_dir.as_os_str().is_empty() {
        return Err("Installation path is empty.".into());
    }

    let exe_name = if cfg!(target_os = "windows") {
        "singularity.exe"
    } else {
        "singularity"
    };
    let exe_path = target_dir.join(exe_name);
    let ico_path = target_dir.join("singularity.ico");

    set_step(
        progress,
        12.0,
        "Checking for running Singularity processes...",
        &notify,
    );

    #[cfg(target_os = "windows")]
    win32_ops::terminate_running_singularity(&exe_path);

    std::fs::create_dir_all(&target_dir).map_err(|e| {
        format!(
            "Failed to create directory '{}': {e}",
            target_dir.display()
        )
    })?;

    // Chunked write so UI progress updates smoothly in real time without ever stalling
    let extract_label = format!("Extracting native browser {}...", exe_name);
    set_step(progress, 24.0, &extract_label, &notify);
    {
        let mut file = std::fs::File::create(&exe_path).map_err(|e| {
            format!(
                "Failed to write '{}' (close Singularity if it is open): {e}",
                exe_path.display()
            )
        })?;
        let total = EMBEDDED_SINGULARITY_EXE.len().max(1);
        let chunk_size = 131_072; // 128 KB
        let mut written = 0usize;
        for chunk in EMBEDDED_SINGULARITY_EXE.chunks(chunk_size) {
            file.write_all(chunk)
                .map_err(|e| format!("Disk write error: {e}"))?;
            written += chunk.len();
            let pct = 24.0 + (written as f32 / total as f32) * 44.0;
            set_step(progress, pct, &extract_label, &notify);
        }
        let _ = file.flush();
    }

    let _ = std::fs::write(&ico_path, EMBEDDED_SINGULARITY_ICO);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(&exe_path) {
            let mut perms = meta.permissions();
            perms.set_mode(0o755);
            let _ = std::fs::set_permissions(&exe_path, perms);
        }
    }

    if opts.init_roaming_vault {
        set_step(
            progress,
            76.0,
            "Preparing encrypted Roaming\\.singularity profile...",
            &notify,
        );
        let roaming = roaming_singularity_dir();
        let engine_dir = roaming.join("browser-engine");
        let _ = std::fs::create_dir_all(&roaming);
        let _ = std::fs::create_dir_all(&engine_dir);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&roaming, std::fs::Permissions::from_mode(0o700));
            let _ = std::fs::set_permissions(&engine_dir, std::fs::Permissions::from_mode(0o700));
        }
        let readme_sec = roaming.join("SECURITY-README.txt");
        if !readme_sec.exists() {
            let _ = std::fs::write(
                &readme_sec,
                "Singularity Encrypted Roaming Profile (.singularity)\r\n\
                 ====================================================\r\n\
                 - master.dpapi : 256-bit key sealed by Windows DPAPI (CryptProtectData)\r\n\
                 - tokens.enc   : XChaCha20-Poly1305 AEAD encrypted session tokens (Google, Microsoft, GitHub, Discord, OAuth/SSO)\r\n\
                 - vault.singularity-vault : Argon2id + XChaCha20-Poly1305 encrypted password & 2FA vault\r\n\
                 - profile.json : User preferences, bookmarks, and workspace configuration\r\n\
                 - settings.toml: Custom overrides across the 2,165 Singularity engine settings\r\n",
            );
        }
    }

    #[cfg(target_os = "windows")]
    {
        set_step(
            progress,
            88.0,
            "Registering in Windows Installed Apps...",
            &notify,
        );
        win32_ops::register_uninstall_registry(&target_dir, &exe_path, &ico_path);

        if opts.desktop_shortcut || opts.start_menu_shortcut {
            set_step(
                progress,
                95.0,
                "Creating Desktop and Start Menu shortcuts...",
                &notify,
            );
            win32_ops::create_shell_shortcuts(
                &target_dir,
                &exe_path,
                &ico_path,
                opts.desktop_shortcut,
                opts.start_menu_shortcut,
            );
        }
    }

    {
        let mut g = progress.lock().unwrap_or_else(|e| e.into_inner());
        g.phase = InstallPhase::Done;
        g.target_pct = 100.0;
        g.step_label = "Installation complete — Singularity is ready!".to_string();
        g.installed_exe = exe_path.to_string_lossy().into_owned();
        g.error_msg.clear();
    }
    notify();

    if opts.launch_after_install {
        #[cfg(target_os = "windows")]
        win32_ops::launch_exe_detached(&exe_path, &target_dir);
    }

    Ok(exe_path)
}

#[cfg(target_os = "windows")]
mod win32_ops {
    use super::APP_VERSION;
    use super::EMBEDDED_SINGULARITY_EXE;
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::path::{Path, PathBuf};
    use windows::core::{Interface, PCWSTR, PWSTR};
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CoTaskMemFree, CoUninitialize, IPersistFile,
        CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED,
    };
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegSetValueExW, HKEY, HKEY_CURRENT_USER, KEY_WRITE,
        REG_DWORD, REG_OPTION_NON_VOLATILE, REG_SZ,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, TerminateProcess, WaitForSingleObject,
        PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
        PROCESS_TERMINATE,
    };
    use windows::Win32::UI::Shell::{
        FOLDERID_Desktop, FOLDERID_Programs, IShellLinkW, SHGetKnownFolderPath, ShellExecuteW,
        ShellLink, KF_FLAG_DEFAULT,
    };
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    pub fn to_wide(s: &str) -> Vec<u16> {
        OsStr::new(s).encode_wide().chain(Some(0)).collect()
    }

    pub fn path_to_wide(p: &Path) -> Vec<u16> {
        p.as_os_str().encode_wide().chain(Some(0)).collect()
    }

    fn normalize_win_path(p: &Path) -> String {
        let s = std::fs::canonicalize(p)
            .unwrap_or_else(|_| p.to_path_buf())
            .to_string_lossy()
            .into_owned();
        s.strip_prefix(r"\\?\")
            .unwrap_or(&s)
            .replace('/', "\\")
            .to_ascii_lowercase()
    }

    /// Terminates ONLY running `singularity.exe` processes whose full executable path matches
    /// `target_exe`, preventing accidental termination of unrelated programs with the same name.
    pub fn terminate_running_singularity(target_exe: &Path) {
        let expected_path = normalize_win_path(target_exe);
        unsafe {
            let Ok(snap) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else {
                return;
            };
            let my_pid = std::process::id();
            let mut entry = PROCESSENTRY32W {
                dwSize: core::mem::size_of::<PROCESSENTRY32W>() as u32,
                ..Default::default()
            };

            if Process32FirstW(snap, &mut entry).is_ok() {
                loop {
                    if entry.th32ProcessID != my_pid {
                        let nul = entry
                            .szExeFile
                            .iter()
                            .position(|&c| c == 0)
                            .unwrap_or(entry.szExeFile.len());
                        let name = String::from_utf16_lossy(&entry.szExeFile[..nul]);
                        if name.eq_ignore_ascii_case("singularity.exe") {
                            if let Ok(proc_h) = OpenProcess(
                                PROCESS_QUERY_LIMITED_INFORMATION
                                    | PROCESS_TERMINATE
                                    | PROCESS_SYNCHRONIZE,
                                false,
                                entry.th32ProcessID,
                            ) {
                                let mut path_buf = vec![0u16; 1024];
                                let mut len = path_buf.len() as u32;
                                let path_matches = QueryFullProcessImageNameW(
                                    proc_h,
                                    PROCESS_NAME_FORMAT(0),
                                    PWSTR(path_buf.as_mut_ptr()),
                                    &mut len,
                                )
                                .is_ok()
                                    && {
                                        let actual = String::from_utf16_lossy(
                                            &path_buf[..len as usize],
                                        );
                                        normalize_win_path(Path::new(&actual)) == expected_path
                                    };
                                if path_matches {
                                    let _ = TerminateProcess(proc_h, 0);
                                    let _ = WaitForSingleObject(proc_h, 400);
                                }
                                let _ = CloseHandle(proc_h);
                            }
                        }
                    }
                    if Process32NextW(snap, &mut entry).is_err() {
                        break;
                    }
                }
            }
            let _ = CloseHandle(snap);
        }
    }

    /// Writes `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\Singularity` via `advapi32.dll`.
    pub fn register_uninstall_registry(install_dir: &Path, exe_path: &Path, ico_path: &Path) {
        unsafe {
            let subkey = to_wide("Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Singularity");
            let mut hkey = HKEY::default();
            let err = RegCreateKeyExW(
                HKEY_CURRENT_USER,
                PCWSTR(subkey.as_ptr()),
                None,
                PCWSTR::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_WRITE,
                None,
                &mut hkey,
                None,
            );
            if err.0 != 0 {
                return;
            }

            let set_sz = |name: &str, val: &str| {
                let n = to_wide(name);
                let v = to_wide(val);
                let bytes =
                    core::slice::from_raw_parts(v.as_ptr() as *const u8, v.len() * 2);
                let _ = RegSetValueExW(hkey, PCWSTR(n.as_ptr()), None, REG_SZ, Some(bytes));
            };
            let set_dword = |name: &str, val: u32| {
                let n = to_wide(name);
                let bytes = val.to_le_bytes();
                let _ = RegSetValueExW(hkey, PCWSTR(n.as_ptr()), None, REG_DWORD, Some(&bytes));
            };

            let uninst_cmd = format!("\"{}\" --uninstall", exe_path.display());
            let quiet_uninst_cmd = format!("\"{}\" --uninstall --silent", exe_path.display());
            let icon_loc = format!("{},0", ico_path.display());
            let est_kb = ((EMBEDDED_SINGULARITY_EXE.len() / 1024).max(1024)) as u32;

            set_sz("DisplayName", "Singularity");
            set_sz("DisplayVersion", APP_VERSION);
            set_sz("Publisher", "Singularity");
            set_sz("DisplayIcon", &icon_loc);
            set_sz("InstallLocation", &install_dir.to_string_lossy());
            set_sz("UninstallString", &uninst_cmd);
            set_sz("QuietUninstallString", &quiet_uninst_cmd);
            set_dword("EstimatedSize", est_kb);
            set_dword("NoModify", 1);
            set_dword("NoRepair", 1);

            let _ = RegCloseKey(hkey);
        }
    }

    fn known_folder(rfid: *const windows::core::GUID) -> Option<PathBuf> {
        unsafe {
            let pwstr = SHGetKnownFolderPath(rfid, KF_FLAG_DEFAULT, None).ok()?;
            let mut len = 0usize;
            while *pwstr.0.add(len) != 0 {
                len += 1;
            }
            let slice = core::slice::from_raw_parts(pwstr.0, len);
            let s = String::from_utf16_lossy(slice);
            CoTaskMemFree(Some(pwstr.0 as *const _));
            if s.is_empty() {
                None
            } else {
                Some(PathBuf::from(s))
            }
        }
    }

    /// Creates real Windows `.lnk` shortcuts via COM `IShellLinkW` + `IPersistFile` (zero `WScript.Shell`).
    pub fn create_shell_shortcuts(
        install_dir: &Path,
        exe_path: &Path,
        ico_path: &Path,
        desktop: bool,
        start_menu: bool,
    ) {
        unsafe {
            let hr = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
            let need_uninit = hr.is_ok();

            let write_lnk = |lnk_path: &Path| {
                let Ok(link) =
                    CoCreateInstance::<_, IShellLinkW>(&ShellLink, None, CLSCTX_INPROC_SERVER)
                else {
                    return;
                };
                let exe_w = path_to_wide(exe_path);
                let dir_w = path_to_wide(install_dir);
                let ico_w = path_to_wide(ico_path);
                let desc_w = to_wide("Singularity Browser — Privacy & High Performance");

                let _ = link.SetPath(PCWSTR(exe_w.as_ptr()));
                let _ = link.SetWorkingDirectory(PCWSTR(dir_w.as_ptr()));
                let _ = link.SetIconLocation(PCWSTR(ico_w.as_ptr()), 0);
                let _ = link.SetDescription(PCWSTR(desc_w.as_ptr()));

                if let Ok(persist) = link.cast::<IPersistFile>() {
                    let lnk_w = path_to_wide(lnk_path);
                    let _ = persist.Save(PCWSTR(lnk_w.as_ptr()), true);
                }
            };

            if desktop {
                if let Some(desk) = known_folder(&FOLDERID_Desktop) {
                    write_lnk(&desk.join("Singularity.lnk"));
                }
            }
            if start_menu {
                if let Some(progs) = known_folder(&FOLDERID_Programs) {
                    write_lnk(&progs.join("Singularity.lnk"));
                }
            }

            if need_uninit {
                CoUninitialize();
            }
        }
    }

    pub fn launch_exe_detached(exe_path: &Path, work_dir: &Path) {
        unsafe {
            let op = to_wide("open");
            let file = path_to_wide(exe_path);
            let dir = path_to_wide(work_dir);
            let _ = ShellExecuteW(
                None,
                PCWSTR(op.as_ptr()),
                PCWSTR(file.as_ptr()),
                PCWSTR::null(),
                PCWSTR(dir.as_ptr()),
                SW_SHOWNORMAL,
            );
        }
    }
}

#[cfg(target_os = "windows")]
mod win32_gui {
    use super::win32_ops::{launch_exe_detached, to_wide};
    use super::{
        default_install_dir, perform_installation, roaming_singularity_dir, InstallOptions,
        InstallPhase, SharedProgress, APP_VERSION, EMBEDDED_LOGO_128_RGBA,
        EMBEDDED_SINGULARITY_EXE,
    };
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{COLORREF, HWND, LPARAM, LRESULT, POINT, RECT, WPARAM};
    use windows::Win32::Graphics::Dwm::{
        DwmSetWindowAttribute, DWMWA_USE_IMMERSIVE_DARK_MODE, DWMWA_WINDOW_CORNER_PREFERENCE,
        DWMWCP_ROUND,
    };
    use windows::Win32::Graphics::Gdi::{
        BeginPaint, BitBlt, CreateCompatibleDC, CreateDIBSection, CreateFontW, DeleteDC,
        DeleteObject, DrawTextW, EndPaint, InvalidateRect, SelectObject, SetBkMode, SetTextColor,
        UpdateWindow, BITMAPINFO, BITMAPINFOHEADER, BI_RGB, CLEARTYPE_QUALITY, CLIP_DEFAULT_PRECIS,
        DEFAULT_CHARSET, DIB_RGB_COLORS, DT_CALCRECT, DT_END_ELLIPSIS, DT_LEFT, DT_NOPREFIX,
        DT_RIGHT, DT_SINGLELINE, DT_VCENTER, DT_WORDBREAK, FW_BOLD, FW_MEDIUM, FW_NORMAL,
        FW_SEMIBOLD, HFONT, OUT_DEFAULT_PRECIS, PAINTSTRUCT, SRCCOPY, TRANSPARENT,
    };
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CoTaskMemFree, CoUninitialize, CLSCTX_INPROC_SERVER,
        COINIT_APARTMENTTHREADED,
    };
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::UI::HiDpi::GetDpiForWindow;
    use windows::Win32::UI::Input::KeyboardAndMouse::{
        ReleaseCapture, SetCapture, TrackMouseEvent, TME_LEAVE, TRACKMOUSEEVENT,
    };
    use windows::Win32::UI::Shell::{
        FileOpenDialog, IFileOpenDialog, IShellItem, SHCreateItemFromParsingName,
        FOS_FORCEFILESYSTEM, FOS_NOCHANGEDIR, FOS_PICKFOLDERS, SIGDN_FILESYSPATH,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetClientRect,
        GetMessageW, GetSystemMetrics, GetWindowLongPtrW, IsWindow, KillTimer, LoadCursorW,
        LoadIconW, PostMessageW, PostQuitMessage, RegisterClassExW, SetCursor, SetTimer,
        SetWindowLongPtrW, ShowWindow, TranslateMessage, CS_HREDRAW, CS_VREDRAW, GWLP_USERDATA,
        HTCAPTION, HTCLIENT, IDC_ARROW, IDC_HAND, MSG, SM_CXSCREEN, SM_CYSCREEN, SW_MINIMIZE,
        SW_SHOW, WINDOW_EX_STYLE, WM_APP, WM_CLOSE, WM_DESTROY, WM_ERASEBKGND, WM_LBUTTONDOWN,
        WM_LBUTTONUP, WM_MOUSEMOVE, WM_NCHITTEST, WM_PAINT, WM_SETCURSOR, WM_TIMER, WNDCLASSEXW,
        WS_CLIPCHILDREN, WS_MINIMIZEBOX, WS_POPUP, WS_SYSMENU,
    };

    const WM_MOUSELEAVE: u32 = 0x02A3;
    const WM_APP_PROGRESS: u32 = WM_APP + 1;
    const TIMER_ANIM: usize = 1;

    const LOGICAL_W: f32 = 660.0;
    const LOGICAL_H: f32 = 500.0;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum HitZone {
        None,
        CloseDot,
        MinDot,
        BrowseBtn,
        ChkDesktop,
        ChkStartMenu,
        ChkRoaming,
        ChkLaunch,
        CancelBtn,
        PrimaryBtn,
    }

    #[derive(Clone, Copy, Default)]
    struct RectF {
        x0: f32,
        y0: f32,
        x1: f32,
        y1: f32,
    }

    impl RectF {
        fn contains(&self, x: f32, y: f32) -> bool {
            x >= self.x0 && x <= self.x1 && y >= self.y0 && y <= self.y1
        }
        fn to_win_rect(self) -> RECT {
            RECT {
                left: self.x0.round() as i32,
                top: self.y0.round() as i32,
                right: self.x1.round() as i32,
                bottom: self.y1.round() as i32,
            }
        }
    }

    struct Layout {
        scale: f32,
        close_dot: (f32, f32, f32),
        min_dot: (f32, f32, f32),
        dis_dot: (f32, f32, f32),
        titlebar_h: f32,
        logo_rect: RectF,
        card_rect: RectF,
        dir_box: RectF,
        browse_btn: RectF,
        roaming_box: RectF,
        chk_rects: [RectF; 4],
        chk_boxes: [RectF; 4],
        prog_bar: RectF,
        cancel_btn: RectF,
        primary_btn: RectF,
    }

    impl Layout {
        fn compute(w: f32, h: f32, s: f32) -> Self {
            let titlebar_h = 40.0 * s;
            let dot_y = titlebar_h * 0.5;
            let dot_r = 6.2 * s;
            let close_dot = (22.0 * s, dot_y, dot_r);
            let min_dot = (42.0 * s, dot_y, dot_r);
            let dis_dot = (62.0 * s, dot_y, dot_r);

            let pad_x = 30.0 * s;
            let logo_size = 68.0 * s;
            let hero_top = titlebar_h + 20.0 * s;
            let logo_rect = RectF {
                x0: pad_x,
                y0: hero_top,
                x1: pad_x + logo_size,
                y1: hero_top + logo_size,
            };

            let card_top = hero_top + logo_size + 18.0 * s;
            let footer_h = 62.0 * s;
            let card_bot = h - footer_h;
            let card_rect = RectF {
                x0: pad_x,
                y0: card_top,
                x1: w - pad_x,
                y1: card_bot,
            };

            let cx0 = card_rect.x0 + 18.0 * s;
            let cx1 = card_rect.x1 - 18.0 * s;

            let browse_w = 96.0 * s;
            let dir_y0 = card_top + 36.0 * s;
            let dir_y1 = dir_y0 + 34.0 * s;
            let dir_box = RectF {
                x0: cx0,
                y0: dir_y0,
                x1: cx1 - browse_w - 8.0 * s,
                y1: dir_y1,
            };
            let browse_btn = RectF {
                x0: cx1 - browse_w,
                y0: dir_y0,
                x1: cx1,
                y1: dir_y1,
            };

            let roam_y0 = dir_y1 + 12.0 * s;
            let roam_y1 = roam_y0 + 32.0 * s;
            let roaming_box = RectF {
                x0: cx0,
                y0: roam_y0,
                x1: cx1,
                y1: roam_y1,
            };

            let chk_top1 = roam_y1 + 15.0 * s;
            let chk_top2 = chk_top1 + 28.0 * s;
            let mid_x = (cx0 + cx1) * 0.5 + 8.0 * s;
            let box_sz = 16.0 * s;

            let chk_rects = [
                RectF {
                    x0: cx0,
                    y0: chk_top1,
                    x1: mid_x - 8.0 * s,
                    y1: chk_top1 + 22.0 * s,
                },
                RectF {
                    x0: mid_x,
                    y0: chk_top1,
                    x1: cx1,
                    y1: chk_top1 + 22.0 * s,
                },
                RectF {
                    x0: cx0,
                    y0: chk_top2,
                    x1: mid_x - 8.0 * s,
                    y1: chk_top2 + 22.0 * s,
                },
                RectF {
                    x0: mid_x,
                    y0: chk_top2,
                    x1: cx1,
                    y1: chk_top2 + 22.0 * s,
                },
            ];
            let mut chk_boxes = [RectF::default(); 4];
            for i in 0..4 {
                let cy = (chk_rects[i].y0 + chk_rects[i].y1) * 0.5;
                chk_boxes[i] = RectF {
                    x0: chk_rects[i].x0,
                    y0: cy - box_sz * 0.5,
                    x1: chk_rects[i].x0 + box_sz,
                    y1: cy + box_sz * 0.5,
                };
            }

            let prog_y0 = chk_top2 + 38.0 * s;
            let prog_bar = RectF {
                x0: cx0,
                y0: prog_y0 + 20.0 * s,
                x1: cx1,
                y1: prog_y0 + 29.0 * s,
            };

            let btn_h = 36.0 * s;
            let btn_y0 = h - footer_h + (footer_h - btn_h) * 0.5 - 2.0 * s;
            let btn_y1 = btn_y0 + btn_h;
            let prim_w = 205.0 * s;
            let canc_w = 94.0 * s;

            let primary_btn = RectF {
                x0: w - pad_x - prim_w,
                y0: btn_y0,
                x1: w - pad_x,
                y1: btn_y1,
            };
            let cancel_btn = RectF {
                x0: primary_btn.x0 - 10.0 * s - canc_w,
                y0: btn_y0,
                x1: primary_btn.x0 - 10.0 * s,
                y1: btn_y1,
            };

            Self {
                scale: s,
                close_dot,
                min_dot,
                dis_dot,
                titlebar_h,
                logo_rect,
                card_rect,
                dir_box,
                browse_btn,
                roaming_box,
                chk_rects,
                chk_boxes,
                prog_bar,
                cancel_btn,
                primary_btn,
            }
        }

        fn hit_test(&self, x: f32, y: f32, phase: InstallPhase) -> HitZone {
            let pad = 3.0 * self.scale;
            let in_circle = |(cx, cy, r): (f32, f32, f32)| -> bool {
                let dx = x - cx;
                let dy = y - cy;
                let hit_r = r + pad;
                dx * dx + dy * dy <= hit_r * hit_r
            };
            if in_circle(self.close_dot) && phase != InstallPhase::Running {
                return HitZone::CloseDot;
            }
            if in_circle(self.min_dot) {
                return HitZone::MinDot;
            }
            if phase == InstallPhase::Idle || phase == InstallPhase::Error {
                if self.browse_btn.contains(x, y) || self.dir_box.contains(x, y) {
                    return HitZone::BrowseBtn;
                }
                if self.chk_rects[0].contains(x, y) {
                    return HitZone::ChkDesktop;
                }
                if self.chk_rects[1].contains(x, y) {
                    return HitZone::ChkStartMenu;
                }
                if self.chk_rects[2].contains(x, y) {
                    return HitZone::ChkRoaming;
                }
                if self.cancel_btn.contains(x, y) {
                    return HitZone::CancelBtn;
                }
            }
            if phase != InstallPhase::Running && self.chk_rects[3].contains(x, y) {
                return HitZone::ChkLaunch;
            }
            if phase != InstallPhase::Running && self.primary_btn.contains(x, y) {
                return HitZone::PrimaryBtn;
            }
            HitZone::None
        }
    }

    struct AppState {
        install_dir: String,
        roaming_dir: String,
        chk_desktop: bool,
        chk_start_menu: bool,
        chk_roaming: bool,
        chk_launch: bool,
        hover: HitZone,
        pressed: HitZone,
        tracking_mouse: bool,
        visual_pct: f32,
        progress: Arc<Mutex<SharedProgress>>,
        window_alive: Arc<AtomicBool>,
    }

    pub fn run_native_installer() -> Result<(), String> {
        unsafe {
            let co_hr = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
            let hinst = GetModuleHandleW(PCWSTR::null())
                .map_err(|e| format!("GetModuleHandleW: {e}"))?;

            let class_name = to_wide("SingularityNativeSetupWndClass");
            let app_icon = LoadIconW(Some(hinst.into()), PCWSTR(1usize as *const u16)).ok();
            let arrow_cur = LoadCursorW(None, IDC_ARROW).ok();

            let wc = WNDCLASSEXW {
                cbSize: core::mem::size_of::<WNDCLASSEXW>() as u32,
                style: CS_HREDRAW | CS_VREDRAW,
                lpfnWndProc: Some(wnd_proc),
                hInstance: hinst.into(),
                hIcon: app_icon.unwrap_or_default(),
                hIconSm: app_icon.unwrap_or_default(),
                hCursor: arrow_cur.unwrap_or_default(),
                lpszClassName: PCWSTR(class_name.as_ptr()),
                ..Default::default()
            };
            RegisterClassExW(&wc);

            let screen_w = GetSystemMetrics(SM_CXSCREEN);
            let screen_h = GetSystemMetrics(SM_CYSCREEN);

            // Initial size at 96 DPI, resized cleanly once GetDpiForWindow is queried
            let init_w = LOGICAL_W as i32;
            let init_h = LOGICAL_H as i32;
            let init_x = ((screen_w - init_w) / 2).max(0);
            let init_y = ((screen_h - init_h) / 2).max(0);

            let state = Box::new(std::cell::RefCell::new(AppState {
                install_dir: default_install_dir().to_string_lossy().into_owned(),
                roaming_dir: roaming_singularity_dir().to_string_lossy().into_owned(),
                chk_desktop: true,
                chk_start_menu: true,
                chk_roaming: true,
                chk_launch: true,
                hover: HitZone::None,
                pressed: HitZone::None,
                tracking_mouse: false,
                visual_pct: 0.0,
                progress: Arc::new(Mutex::new(SharedProgress {
                    phase: InstallPhase::Idle,
                    target_pct: 0.0,
                    step_label: "Ready to install Singularity on this computer.".into(),
                    installed_exe: String::new(),
                    error_msg: String::new(),
                })),
                window_alive: Arc::new(AtomicBool::new(true)),
            }));
            let state_ptr = Box::into_raw(state);

            let title = to_wide("Singularity Browser Setup");
            let hwnd = CreateWindowExW(
                WINDOW_EX_STYLE(0),
                PCWSTR(class_name.as_ptr()),
                PCWSTR(title.as_ptr()),
                WS_POPUP | WS_SYSMENU | WS_MINIMIZEBOX | WS_CLIPCHILDREN,
                init_x,
                init_y,
                init_w,
                init_h,
                None,
                None,
                Some(hinst.into()),
                None,
            )
            .map_err(|e| {
                let _ = Box::from_raw(state_ptr);
                format!("CreateWindowExW: {e}")
            })?;

            SetWindowLongPtrW(hwnd, GWLP_USERDATA, state_ptr as isize);

            // Scale window cleanly to monitor DPI
            let dpi = GetDpiForWindow(hwnd);
            let scale = if dpi > 0 { dpi as f32 / 96.0 } else { 1.0 };
            if (scale - 1.0).abs() > 0.01 {
                let sw = (LOGICAL_W * scale).round() as i32;
                let sh = (LOGICAL_H * scale).round() as i32;
                let sx = ((screen_w - sw) / 2).max(0);
                let sy = ((screen_h - sh) / 2).max(0);
                let _ = windows::Win32::UI::WindowsAndMessaging::SetWindowPos(
                    hwnd,
                    None,
                    sx,
                    sy,
                    sw,
                    sh,
                    windows::Win32::UI::WindowsAndMessaging::SWP_NOZORDER
                        | windows::Win32::UI::WindowsAndMessaging::SWP_NOACTIVATE,
                );
            }

            // Enable Windows 11 hardware rounded corners + dark window frame
            let dark: i32 = 1;
            let _ = DwmSetWindowAttribute(
                hwnd,
                DWMWA_USE_IMMERSIVE_DARK_MODE,
                &dark as *const _ as *const _,
                4,
            );
            let corner = DWMWCP_ROUND;
            let _ = DwmSetWindowAttribute(
                hwnd,
                DWMWA_WINDOW_CORNER_PREFERENCE,
                &corner as *const _ as *const _,
                4,
            );

            let _ = ShowWindow(hwnd, SW_SHOW);
            let _ = UpdateWindow(hwnd);

            // Exit cleanly on both WM_QUIT (0) and Win32 error (-1)
            let mut msg = MSG::default();
            loop {
                let ret = GetMessageW(&mut msg, None, 0, 0).0;
                if ret <= 0 {
                    break;
                }
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }

            // Ensure GWLP_USERDATA is cleared before reclaiming heap state
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            let _ = Box::from_raw(state_ptr);
            if co_hr.is_ok() {
                CoUninitialize();
            }
            Ok(())
        }
    }

    fn dpi_scale(hwnd: HWND) -> f32 {
        let dpi = unsafe { GetDpiForWindow(hwnd) };
        if dpi > 0 {
            dpi as f32 / 96.0
        } else {
            1.0
        }
    }

    fn pick_folder_dialog(hwnd: HWND, current: &str) -> Option<PathBuf> {
        unsafe {
            let dlg: IFileOpenDialog =
                CoCreateInstance(&FileOpenDialog, None, CLSCTX_INPROC_SERVER).ok()?;
            let opts = dlg.GetOptions().ok()?;
            dlg.SetOptions(opts | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM | FOS_NOCHANGEDIR)
                .ok()?;
            let title = to_wide("Choose Singularity installation folder");
            let _ = dlg.SetTitle(PCWSTR(title.as_ptr()));

            // Pre-select the existing current directory (or its closest existing ancestor)
            let mut seed = PathBuf::from(current.trim());
            while !seed.as_os_str().is_empty() && !seed.exists() {
                if !seed.pop() {
                    break;
                }
            }
            if seed.is_dir() {
                let wide_dir = to_wide(&seed.to_string_lossy());
                if let Ok(folder_item) =
                    SHCreateItemFromParsingName::<_, _, IShellItem>(PCWSTR(wide_dir.as_ptr()), None)
                {
                    let _ = dlg.SetFolder(&folder_item);
                }
            }

            if dlg.Show(Some(hwnd)).is_err() {
                return None;
            }
            let item = dlg.GetResult().ok()?;
            let pwstr = item.GetDisplayName(SIGDN_FILESYSPATH).ok()?;
            let mut len = 0usize;
            while *pwstr.0.add(len) != 0 {
                len += 1;
            }
            let s = String::from_utf16_lossy(core::slice::from_raw_parts(pwstr.0, len));
            CoTaskMemFree(Some(pwstr.0 as *const _));
            if s.trim().is_empty() {
                None
            } else {
                Some(PathBuf::from(s))
            }
        }
    }

    fn start_async_install(hwnd: HWND, cell: &std::cell::RefCell<AppState>) {
        let (opts, prog_bg, alive_bg) = {
            let mut st = cell.borrow_mut();
            {
                let mut g = st.progress.lock().unwrap_or_else(|e| e.into_inner());
                if g.phase == InstallPhase::Running {
                    return;
                }
                g.phase = InstallPhase::Running;
                g.target_pct = 8.0;
                g.step_label = "Starting installation...".into();
                g.error_msg.clear();
            }
            st.visual_pct = 4.0;
            let opts = InstallOptions {
                install_dir: st.install_dir.clone(),
                desktop_shortcut: st.chk_desktop,
                start_menu_shortcut: st.chk_start_menu,
                init_roaming_vault: st.chk_roaming,
                launch_after_install: false,
            };
            let prog_bg = Arc::clone(&st.progress);
            let alive_bg = Arc::clone(&st.window_alive);
            (opts, prog_bg, alive_bg)
        };

        unsafe {
            let _ = SetTimer(Some(hwnd), TIMER_ANIM, 16, None);
            let _ = InvalidateRect(Some(hwnd), None, false);
        }

        let hwnd_raw = hwnd.0 as isize;
        std::thread::spawn(move || {
            let notify = || unsafe {
                if !alive_bg.load(Ordering::Acquire) {
                    return;
                }
                let h = HWND(hwnd_raw as *mut _);
                if IsWindow(Some(h)).as_bool() {
                    let _ = PostMessageW(Some(h), WM_APP_PROGRESS, WPARAM(0), LPARAM(0));
                }
            };
            if let Err(err) = perform_installation(&opts, &prog_bg, notify) {
                {
                    let mut g = prog_bg.lock().unwrap_or_else(|e| e.into_inner());
                    g.phase = InstallPhase::Error;
                    g.error_msg = err;
                }
                notify();
            }
        });
    }

    unsafe extern "system" fn wnd_proc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        let ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *const std::cell::RefCell<AppState>;
        if ptr.is_null() {
            return DefWindowProcW(hwnd, msg, wparam, lparam);
        }
        let cell = &*ptr;

        match msg {
            WM_ERASEBKGND => LRESULT(1),

            WM_NCHITTEST => {
                let screen_x = (lparam.0 & 0xFFFF) as i16 as i32;
                let screen_y = ((lparam.0 >> 16) & 0xFFFF) as i16 as i32;
                let mut pt = POINT {
                    x: screen_x,
                    y: screen_y,
                };
                let _ = windows::Win32::Graphics::Gdi::ScreenToClient(hwnd, &mut pt);
                let mut rc = RECT::default();
                let _ = GetClientRect(hwnd, &mut rc);
                let s = dpi_scale(hwnd);
                let lay = Layout::compute(rc.right as f32, rc.bottom as f32, s);
                let phase = cell
                    .borrow()
                    .progress
                    .lock()
                    .map(|g| g.phase)
                    .unwrap_or(InstallPhase::Idle);

                if pt.y >= 0
                    && (pt.y as f32) < lay.titlebar_h
                    && lay.hit_test(pt.x as f32, pt.y as f32, phase) == HitZone::None
                {
                    return LRESULT(HTCAPTION as isize);
                }
                LRESULT(HTCLIENT as isize)
            }

            WM_SETCURSOR => {
                let hover = cell.borrow().hover;
                let cur_id = if hover != HitZone::None {
                    IDC_HAND
                } else {
                    IDC_ARROW
                };
                if let Ok(c) = LoadCursorW(None, cur_id) {
                    SetCursor(Some(c));
                    return LRESULT(1);
                }
                DefWindowProcW(hwnd, msg, wparam, lparam)
            }

            WM_MOUSEMOVE => {
                let need_track = !cell.borrow().tracking_mouse;
                if need_track {
                    let mut tme = TRACKMOUSEEVENT {
                        cbSize: core::mem::size_of::<TRACKMOUSEEVENT>() as u32,
                        dwFlags: TME_LEAVE,
                        hwndTrack: hwnd,
                        dwHoverTime: 0,
                    };
                    if TrackMouseEvent(&mut tme).is_ok() {
                        cell.borrow_mut().tracking_mouse = true;
                    }
                }
                let mx = (lparam.0 & 0xFFFF) as i16 as f32;
                let my = ((lparam.0 >> 16) & 0xFFFF) as i16 as f32;
                let mut rc = RECT::default();
                let _ = GetClientRect(hwnd, &mut rc);
                let lay = Layout::compute(rc.right as f32, rc.bottom as f32, dpi_scale(hwnd));
                let changed = {
                    let mut st = cell.borrow_mut();
                    let phase = st
                        .progress
                        .lock()
                        .map(|g| g.phase)
                        .unwrap_or(InstallPhase::Idle);
                    let new_hover = lay.hit_test(mx, my, phase);
                    if new_hover != st.hover {
                        st.hover = new_hover;
                        true
                    } else {
                        false
                    }
                };
                if changed {
                    let _ = InvalidateRect(Some(hwnd), None, false);
                }
                LRESULT(0)
            }

            WM_MOUSELEAVE => {
                let changed = {
                    let mut st = cell.borrow_mut();
                    st.tracking_mouse = false;
                    if st.hover != HitZone::None {
                        st.hover = HitZone::None;
                        true
                    } else {
                        false
                    }
                };
                if changed {
                    let _ = InvalidateRect(Some(hwnd), None, false);
                }
                LRESULT(0)
            }

            WM_LBUTTONDOWN => {
                let mx = (lparam.0 & 0xFFFF) as i16 as f32;
                let my = ((lparam.0 >> 16) & 0xFFFF) as i16 as f32;
                let mut rc = RECT::default();
                let _ = GetClientRect(hwnd, &mut rc);
                let lay = Layout::compute(rc.right as f32, rc.bottom as f32, dpi_scale(hwnd));
                let pressed_any = {
                    let mut st = cell.borrow_mut();
                    let phase = st
                        .progress
                        .lock()
                        .map(|g| g.phase)
                        .unwrap_or(InstallPhase::Idle);
                    st.pressed = lay.hit_test(mx, my, phase);
                    st.pressed != HitZone::None
                };
                if pressed_any {
                    SetCapture(hwnd);
                    let _ = InvalidateRect(Some(hwnd), None, false);
                }
                LRESULT(0)
            }

            WM_LBUTTONUP => {
                let _ = ReleaseCapture();
                let mx = (lparam.0 & 0xFFFF) as i16 as f32;
                let my = ((lparam.0 >> 16) & 0xFFFF) as i16 as f32;
                let mut rc = RECT::default();
                let _ = GetClientRect(hwnd, &mut rc);
                let lay = Layout::compute(rc.right as f32, rc.bottom as f32, dpi_scale(hwnd));

                let (phase, clicked, cur_dir) = {
                    let mut st = cell.borrow_mut();
                    let phase = st
                        .progress
                        .lock()
                        .map(|g| g.phase)
                        .unwrap_or(InstallPhase::Idle);
                    let released_on = lay.hit_test(mx, my, phase);
                    let clicked = if st.pressed != HitZone::None && st.pressed == released_on {
                        released_on
                    } else {
                        HitZone::None
                    };
                    st.pressed = HitZone::None;
                    (phase, clicked, st.install_dir.clone())
                };

                match clicked {
                    HitZone::CloseDot | HitZone::CancelBtn => {
                        if phase != InstallPhase::Running {
                            let _ = DestroyWindow(hwnd);
                            return LRESULT(0);
                        }
                    }
                    HitZone::MinDot => {
                        let _ = ShowWindow(hwnd, SW_MINIMIZE);
                    }
                    HitZone::BrowseBtn => {
                        if let Some(chosen) = pick_folder_dialog(hwnd, &cur_dir) {
                            let final_dir = if chosen
                                .file_name()
                                .and_then(|n| n.to_str())
                                .is_some_and(|s| s.eq_ignore_ascii_case("Singularity"))
                            {
                                chosen
                            } else {
                                chosen.join("Singularity")
                            };
                            cell.borrow_mut().install_dir = final_dir.to_string_lossy().into_owned();
                        }
                    }
                    HitZone::ChkDesktop => {
                        let mut st = cell.borrow_mut();
                        st.chk_desktop = !st.chk_desktop;
                    }
                    HitZone::ChkStartMenu => {
                        let mut st = cell.borrow_mut();
                        st.chk_start_menu = !st.chk_start_menu;
                    }
                    HitZone::ChkRoaming => {
                        let mut st = cell.borrow_mut();
                        st.chk_roaming = !st.chk_roaming;
                    }
                    HitZone::ChkLaunch => {
                        let mut st = cell.borrow_mut();
                        st.chk_launch = !st.chk_launch;
                    }
                    HitZone::PrimaryBtn => {
                        if phase == InstallPhase::Done {
                            let (chk_launch, exe) = {
                                let st = cell.borrow();
                                let exe = st
                                    .progress
                                    .lock()
                                    .map(|g| g.installed_exe.clone())
                                    .unwrap_or_default();
                                (st.chk_launch, exe)
                            };
                            if chk_launch && !exe.is_empty() {
                                let p = Path::new(&exe);
                                let wd = p.parent().unwrap_or_else(|| Path::new("."));
                                launch_exe_detached(p, wd);
                            }
                            let _ = DestroyWindow(hwnd);
                            return LRESULT(0);
                        } else if phase == InstallPhase::Idle || phase == InstallPhase::Error {
                            start_async_install(hwnd, cell);
                        }
                    }
                    HitZone::None => {}
                }
                let _ = InvalidateRect(Some(hwnd), None, false);
                LRESULT(0)
            }

            WM_APP_PROGRESS => {
                let _ = InvalidateRect(Some(hwnd), None, false);
                LRESULT(0)
            }

            WM_CLOSE => {
                let phase = cell
                    .borrow()
                    .progress
                    .lock()
                    .map(|g| g.phase)
                    .unwrap_or(InstallPhase::Idle);
                if phase != InstallPhase::Running {
                    let _ = DestroyWindow(hwnd);
                }
                LRESULT(0)
            }

            WM_TIMER => {
                if wparam.0 == TIMER_ANIM {
                    let mut kill = false;
                    let mut redraw = false;
                    {
                        let mut st = cell.borrow_mut();
                        let (phase, target) = {
                            let g = st.progress.lock().unwrap_or_else(|e| e.into_inner());
                            (g.phase, g.target_pct)
                        };
                        let diff = target - st.visual_pct;
                        if diff.abs() > 0.25 {
                            st.visual_pct += diff * 0.24 + diff.signum() * 0.35;
                            if (diff > 0.0 && st.visual_pct > target)
                                || (diff < 0.0 && st.visual_pct < target)
                            {
                                st.visual_pct = target;
                            }
                            redraw = true;
                        } else {
                            st.visual_pct = target;
                            if phase != InstallPhase::Running {
                                kill = true;
                                redraw = true;
                            }
                        }
                    }
                    if kill {
                        let _ = KillTimer(Some(hwnd), TIMER_ANIM);
                    }
                    if redraw {
                        let _ = InvalidateRect(Some(hwnd), None, false);
                    }
                }
                LRESULT(0)
            }

            WM_PAINT => {
                if let Ok(st) = cell.try_borrow() {
                    paint_window(hwnd, &st);
                }
                LRESULT(0)
            }

            WM_DESTROY => {
                if let Ok(st) = cell.try_borrow() {
                    st.window_alive.store(false, Ordering::SeqCst);
                }
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
                let _ = KillTimer(Some(hwnd), TIMER_ANIM);
                PostQuitMessage(0);
                LRESULT(0)
            }

            _ => DefWindowProcW(hwnd, msg, wparam, lparam),
        }
    }

    // -------------------------------------------------------------------------
    // 60 FPS Anti-Aliased SDF Pixel Compositor + ClearType GDI Typography
    // -------------------------------------------------------------------------

    #[inline]
    fn pack_bgra(r: u8, g: u8, b: u8) -> u32 {
        0xFF00_0000 | ((r as u32) << 16) | ((g as u32) << 8) | (b as u32)
    }

    #[inline]
    fn blend_pixel(dst: u32, r: u8, g: u8, b: u8, alpha: f32) -> u32 {
        let a = alpha.clamp(0.0, 1.0);
        if a <= 0.001 {
            return dst;
        }
        if a >= 0.999 {
            return pack_bgra(r, g, b);
        }
        let dr = ((dst >> 16) & 0xFF) as f32;
        let dg = ((dst >> 8) & 0xFF) as f32;
        let db = (dst & 0xFF) as f32;
        let inv = 1.0 - a;
        let or = (r as f32 * a + dr * inv).round() as u8;
        let og = (g as f32 * a + dg * inv).round() as u8;
        let ob = (b as f32 * a + db * inv).round() as u8;
        pack_bgra(or, og, ob)
    }

    #[inline]
    fn sdf_rounded_rect(px: f32, py: f32, r: RectF, rad: f32) -> f32 {
        let cx = (r.x0 + r.x1) * 0.5;
        let cy = (r.y0 + r.y1) * 0.5;
        let hx = (r.x1 - r.x0) * 0.5 - rad;
        let hy = (r.y1 - r.y0) * 0.5 - rad;
        let qx = (px - cx).abs() - hx;
        let qy = (py - cy).abs() - hy;
        let out_x = qx.max(0.0);
        let out_y = qy.max(0.0);
        (out_x * out_x + out_y * out_y).sqrt() + qx.max(qy).min(0.0) - rad
    }

    fn draw_rounded_box(
        buf: &mut [u32],
        bw: usize,
        bh: usize,
        rect: RectF,
        rad: f32,
        fill: (u8, u8, u8, f32),
        border: Option<(u8, u8, u8, f32)>,
    ) {
        let x0 = (rect.x0.floor() as isize - 2).max(0) as usize;
        let y0 = (rect.y0.floor() as isize - 2).max(0) as usize;
        let x1 = (rect.x1.ceil() as usize + 2).min(bw);
        let y1 = (rect.y1.ceil() as usize + 2).min(bh);

        for y in y0..y1 {
            let py = y as f32 + 0.5;
            let row = y * bw;
            for x in x0..x1 {
                let px = x as f32 + 0.5;
                let d = sdf_rounded_rect(px, py, rect, rad);
                if d < 0.75 {
                    let cov = (0.5 - d).clamp(0.0, 1.0);
                    let mut p = buf[row + x];
                    if fill.3 > 0.0 {
                        p = blend_pixel(p, fill.0, fill.1, fill.2, fill.3 * cov);
                    }
                    if let Some((br, bg, bb, ba)) = border {
                        // 1px crisp inner-centered stroke
                        let bd = (d + 0.5).abs();
                        if bd < 0.95 {
                            let bcov = (0.95 - bd).clamp(0.0, 1.0) * cov;
                            p = blend_pixel(p, br, bg, bb, ba * bcov);
                        }
                    }
                    buf[row + x] = p;
                }
            }
        }
    }

    fn draw_gradient_button(
        buf: &mut [u32],
        bw: usize,
        bh: usize,
        rect: RectF,
        rad: f32,
        top_rgb: (u8, u8, u8),
        bot_rgb: (u8, u8, u8),
        alpha: f32,
    ) {
        let x0 = (rect.x0.floor() as isize - 2).max(0) as usize;
        let y0 = (rect.y0.floor() as isize - 2).max(0) as usize;
        let x1 = (rect.x1.ceil() as usize + 2).min(bw);
        let y1 = (rect.y1.ceil() as usize + 2).min(bh);
        let h_span = (rect.y1 - rect.y0).max(1.0);

        for y in y0..y1 {
            let py = y as f32 + 0.5;
            let t = ((py - rect.y0) / h_span).clamp(0.0, 1.0);
            let cr = (top_rgb.0 as f32 * (1.0 - t) + bot_rgb.0 as f32 * t).round() as u8;
            let cg = (top_rgb.1 as f32 * (1.0 - t) + bot_rgb.1 as f32 * t).round() as u8;
            let cb = (top_rgb.2 as f32 * (1.0 - t) + bot_rgb.2 as f32 * t).round() as u8;
            let row = y * bw;
            for x in x0..x1 {
                let px = x as f32 + 0.5;
                let d = sdf_rounded_rect(px, py, rect, rad);
                if d < 0.75 {
                    let cov = (0.5 - d).clamp(0.0, 1.0);
                    buf[row + x] = blend_pixel(buf[row + x], cr, cg, cb, alpha * cov);
                }
            }
        }
    }

    fn draw_circle(
        buf: &mut [u32],
        bw: usize,
        bh: usize,
        cx: f32,
        cy: f32,
        r: f32,
        rgb: (u8, u8, u8),
        alpha: f32,
    ) {
        let x0 = ((cx - r - 2.0).floor() as isize).max(0) as usize;
        let y0 = ((cy - r - 2.0).floor() as isize).max(0) as usize;
        let x1 = ((cx + r + 2.0).ceil() as usize).min(bw);
        let y1 = ((cy + r + 2.0).ceil() as usize).min(bh);

        for y in y0..y1 {
            let dy = y as f32 + 0.5 - cy;
            let row = y * bw;
            for x in x0..x1 {
                let dx = x as f32 + 0.5 - cx;
                let dist = (dx * dx + dy * dy).sqrt() - r;
                if dist < 0.75 {
                    let cov = (0.5 - dist).clamp(0.0, 1.0);
                    buf[row + x] = blend_pixel(buf[row + x], rgb.0, rgb.1, rgb.2, alpha * cov);
                }
            }
        }
    }

    fn draw_segment_aa(
        buf: &mut [u32],
        bw: usize,
        bh: usize,
        ax: f32,
        ay: f32,
        bx: f32,
        by: f32,
        thickness: f32,
        rgb: (u8, u8, u8),
    ) {
        let pad = thickness + 2.0;
        let x0 = ((ax.min(bx) - pad).floor() as isize).max(0) as usize;
        let y0 = ((ay.min(by) - pad).floor() as isize).max(0) as usize;
        let x1 = ((ax.max(bx) + pad).ceil() as usize).min(bw);
        let y1 = ((ay.max(by) + pad).ceil() as usize).min(bh);
        let vx = bx - ax;
        let vy = by - ay;
        let len2 = (vx * vx + vy * vy).max(0.0001);
        let half_t = thickness * 0.5;

        for y in y0..y1 {
            let py = y as f32 + 0.5;
            let row = y * bw;
            for x in x0..x1 {
                let px = x as f32 + 0.5;
                let t = (((px - ax) * vx + (py - ay) * vy) / len2).clamp(0.0, 1.0);
                let dx = px - (ax + t * vx);
                let dy = py - (ay + t * vy);
                let d = (dx * dx + dy * dy).sqrt() - half_t;
                if d < 0.75 {
                    let cov = (0.5 - d).clamp(0.0, 1.0);
                    buf[row + x] = blend_pixel(buf[row + x], rgb.0, rgb.1, rgb.2, cov);
                }
            }
        }
    }

    fn blit_logo_bilinear(buf: &mut [u32], bw: usize, bh: usize, dst: RectF) {
        let x0 = (dst.x0.floor() as isize).max(0) as usize;
        let y0 = (dst.y0.floor() as isize).max(0) as usize;
        let x1 = (dst.x1.ceil() as usize).min(bw);
        let y1 = (dst.y1.ceil() as usize).min(bh);
        let dw = (dst.x1 - dst.x0).max(1.0);
        let dh = (dst.y1 - dst.y0).max(1.0);

        for y in y0..y1 {
            let v = ((y as f32 + 0.5 - dst.y0) / dh * 127.0).clamp(0.0, 127.0);
            let v0 = v.floor() as usize;
            let v1 = (v0 + 1).min(127);
            let fv = v - v0 as f32;
            let row = y * bw;

            for x in x0..x1 {
                let u = ((x as f32 + 0.5 - dst.x0) / dw * 127.0).clamp(0.0, 127.0);
                let u0 = u.floor() as usize;
                let u1 = (u0 + 1).min(127);
                let fu = u - u0 as f32;

                let sample = |sx: usize, sy: usize| -> (f32, f32, f32, f32) {
                    let idx = (sy * 128 + sx) * 4;
                    (
                        EMBEDDED_LOGO_128_RGBA[idx] as f32,
                        EMBEDDED_LOGO_128_RGBA[idx + 1] as f32,
                        EMBEDDED_LOGO_128_RGBA[idx + 2] as f32,
                        EMBEDDED_LOGO_128_RGBA[idx + 3] as f32 / 255.0,
                    )
                };
                let c00 = sample(u0, v0);
                let c10 = sample(u1, v0);
                let c01 = sample(u0, v1);
                let c11 = sample(u1, v1);

                let w00 = (1.0 - fu) * (1.0 - fv);
                let w10 = fu * (1.0 - fv);
                let w01 = (1.0 - fu) * fv;
                let w11 = fu * fv;

                let r = (c00.0 * w00 + c10.0 * w10 + c01.0 * w01 + c11.0 * w11).round() as u8;
                let g = (c00.1 * w00 + c10.1 * w10 + c01.1 * w01 + c11.1 * w11).round() as u8;
                let b = (c00.2 * w00 + c10.2 * w10 + c01.2 * w01 + c11.2 * w11).round() as u8;
                let a = c00.3 * w00 + c10.3 * w10 + c01.3 * w01 + c11.3 * w11;

                buf[row + x] = blend_pixel(buf[row + x], r, g, b, a);
            }
        }
    }

    unsafe fn make_font(px_height: f32, weight: i32, mono: bool) -> HFONT {
        let face = if mono {
            to_wide("Consolas")
        } else {
            to_wide("Segoe UI")
        };
        CreateFontW(
            -(px_height.round() as i32),
            0,
            0,
            0,
            weight,
            0,
            0,
            0,
            DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS,
            CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY,
            0,
            PCWSTR(face.as_ptr()),
        )
    }

    #[inline]
    fn rgb_colorref(r: u8, g: u8, b: u8) -> COLORREF {
        COLORREF((r as u32) | ((g as u32) << 8) | ((b as u32) << 16))
    }

    unsafe fn draw_str(
        hdc: windows::Win32::Graphics::Gdi::HDC,
        font: HFONT,
        color: COLORREF,
        text: &str,
        rect: RectF,
        flags: windows::Win32::Graphics::Gdi::DRAW_TEXT_FORMAT,
    ) {
        let old = SelectObject(hdc, font.into());
        let _ = SetTextColor(hdc, color);
        let mut wide: Vec<u16> = text.encode_utf16().collect();
        let mut rc = rect.to_win_rect();
        let _ = DrawTextW(hdc, &mut wide, &mut rc, flags | DT_NOPREFIX);
        let _ = SelectObject(hdc, old);
    }

    unsafe fn paint_window(hwnd: HWND, st: &AppState) {
        let mut ps = PAINTSTRUCT::default();
        let paint_dc = BeginPaint(hwnd, &mut ps);

        let mut rc = RECT::default();
        let _ = GetClientRect(hwnd, &mut rc);
        let bw = rc.right.max(1) as usize;
        let bh = rc.bottom.max(1) as usize;
        let wf = bw as f32;
        let hf = bh as f32;
        let s = dpi_scale(hwnd);
        let lay = Layout::compute(wf, hf, s);

        let (phase, step_label, err_msg) = {
            let g = st.progress.lock().unwrap_or_else(|e| e.into_inner());
            (g.phase, g.step_label.clone(), g.error_msg.clone())
        };

        let mem_dc = CreateCompatibleDC(Some(paint_dc));
        let bmi = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: core::mem::size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: bw as i32,
                biHeight: -(bh as i32), // top-down DIB
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB.0,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut bits_ptr: *mut core::ffi::c_void = core::ptr::null_mut();
        let Ok(dib) = CreateDIBSection(Some(mem_dc), &bmi, DIB_RGB_COLORS, &mut bits_ptr, None, 0)
        else {
            let _ = DeleteDC(mem_dc);
            let _ = EndPaint(hwnd, &ps);
            return;
        };
        let Some(total_px) = bw.checked_mul(bh) else {
            let _ = DeleteObject(dib.into());
            let _ = DeleteDC(mem_dc);
            let _ = EndPaint(hwnd, &ps);
            return;
        };
        if bits_ptr.is_null() {
            let _ = DeleteObject(dib.into());
            let _ = DeleteDC(mem_dc);
            let _ = EndPaint(hwnd, &ps);
            return;
        }
        let old_bmp = SelectObject(mem_dc, dib.into());
        let pixels = core::slice::from_raw_parts_mut(bits_ptr as *mut u32, total_px);

        // 1. Background `#07070A` + warm gold ambient radial glow top-right & behind logo
        let gx1 = wf * 0.82;
        let gy1 = hf * 0.14;
        let gr1 = 290.0 * s;
        let gx2 = (lay.logo_rect.x0 + lay.logo_rect.x1) * 0.5;
        let gy2 = (lay.logo_rect.y0 + lay.logo_rect.y1) * 0.5;
        let gr2 = 95.0 * s;

        for y in 0..bh {
            let py = y as f32;
            let row = y * bw;
            let in_tb = py < lay.titlebar_h;
            for x in 0..bw {
                let px = x as f32;
                let mut r = if in_tb { 12.0 } else { 7.0 };
                let mut g = if in_tb { 13.0 } else { 7.0 };
                let mut b = if in_tb { 18.0 } else { 10.0 };

                let d1 = ((px - gx1).powi(2) + (py - gy1).powi(2)).sqrt() / gr1;
                if d1 < 1.0 {
                    let k = (1.0 - d1).powi(2) * 0.11;
                    r += 240.0 * k;
                    g += 175.0 * k;
                    b += 85.0 * k;
                }
                let d2 = ((px - gx2).powi(2) + (py - gy2).powi(2)).sqrt() / gr2;
                if d2 < 1.0 {
                    let k = (1.0 - d2).powi(2) * 0.18;
                    r += 240.0 * k;
                    g += 175.0 * k;
                    b += 85.0 * k;
                }

                pixels[row + x] =
                    pack_bgra(r.min(255.0) as u8, g.min(255.0) as u8, b.min(255.0) as u8);
            }
        }

        // Subtle titlebar divider & outer window border
        let tb_row = (lay.titlebar_h.round() as usize).min(bh - 1);
        for x in 0..bw {
            pixels[tb_row * bw + x] = blend_pixel(pixels[tb_row * bw + x], 255, 255, 255, 0.07);
        }
        draw_rounded_box(
            pixels,
            bw,
            bh,
            RectF {
                x0: 0.5,
                y0: 0.5,
                x1: wf - 0.5,
                y1: hf - 0.5,
            },
            8.0 * s,
            (0, 0, 0, 0.0),
            Some((255, 255, 255, 0.13)),
        );

        // 2. Apple 3-dot traffic lights
        let close_col = if st.hover == HitZone::CloseDot {
            (255, 118, 110)
        } else {
            (255, 95, 87)
        };
        let min_col = if st.hover == HitZone::MinDot {
            (255, 206, 84)
        } else {
            (254, 188, 46)
        };
        draw_circle(
            pixels,
            bw,
            bh,
            lay.close_dot.0,
            lay.close_dot.1,
            lay.close_dot.2,
            close_col,
            if phase == InstallPhase::Running {
                0.35
            } else {
                1.0
            },
        );
        draw_circle(
            pixels,
            bw,
            bh,
            lay.min_dot.0,
            lay.min_dot.1,
            lay.min_dot.2,
            min_col,
            1.0,
        );
        draw_circle(
            pixels,
            bw,
            bh,
            lay.dis_dot.0,
            lay.dis_dot.1,
            lay.dis_dot.2,
            (255, 255, 255),
            0.14,
        );

        // 3. Studio Brand Logo + Version Pill (measured dynamically with DT_CALCRECT)
        blit_logo_bilinear(pixels, bw, bh, lay.logo_rect);

        let f_h1 = make_font(21.0 * s, FW_BOLD.0 as i32, false);
        let hx0 = lay.logo_rect.x1 + 18.0 * s;
        let h1_width_px = {
            let old_f = SelectObject(mem_dc, f_h1.into());
            let mut h1_wide: Vec<u16> = "Singularity Browser".encode_utf16().collect();
            let mut mrc = RECT::default();
            let _ = DrawTextW(
                mem_dc,
                &mut h1_wide,
                &mut mrc,
                DT_CALCRECT | DT_SINGLELINE | DT_NOPREFIX,
            );
            let _ = SelectObject(mem_dc, old_f);
            (mrc.right - mrc.left).max((180.0 * s) as i32) as f32
        };
        let pill_x0 = (hx0 + h1_width_px + 10.0 * s).min(wf - 90.0 * s);
        let ver_pill = RectF {
            x0: pill_x0,
            y0: lay.logo_rect.y0 + 3.0 * s,
            x1: pill_x0 + 58.0 * s,
            y1: lay.logo_rect.y0 + 24.0 * s,
        };
        draw_rounded_box(
            pixels,
            bw,
            bh,
            ver_pill,
            10.0 * s,
            (240, 179, 90, 0.15),
            Some((240, 179, 90, 0.38)),
        );

        // 4. Main Configuration Card
        draw_rounded_box(
            pixels,
            bw,
            bh,
            lay.card_rect,
            12.0 * s,
            (16, 17, 24, 0.96),
            Some((255, 255, 255, 0.09)),
        );

        // Install directory box + "Parcourir…" button
        let dir_hover = st.hover == HitZone::BrowseBtn;
        draw_rounded_box(
            pixels,
            bw,
            bh,
            lay.dir_box,
            7.5 * s,
            (9, 10, 15, 1.0),
            Some(if dir_hover {
                (240, 179, 90, 0.55)
            } else {
                (255, 255, 255, 0.13)
            }),
        );
        draw_rounded_box(
            pixels,
            bw,
            bh,
            lay.browse_btn,
            7.5 * s,
            (255, 255, 255, if dir_hover { 0.11 } else { 0.06 }),
            Some((255, 255, 255, 0.14)),
        );

        // Encrypted Roaming\.singularity hint box + vector padlock
        draw_rounded_box(
            pixels,
            bw,
            bh,
            lay.roaming_box,
            7.5 * s,
            (240, 179, 90, 0.07),
            Some((240, 179, 90, 0.22)),
        );
        let lx = lay.roaming_box.x0 + 14.0 * s;
        let ly = (lay.roaming_box.y0 + lay.roaming_box.y1) * 0.5;
        draw_rounded_box(
            pixels,
            bw,
            bh,
            RectF {
                x0: lx - 5.0 * s,
                y0: ly - 1.0 * s,
                x1: lx + 5.0 * s,
                y1: ly + 6.5 * s,
            },
            2.0 * s,
            (240, 179, 90, 0.95),
            None,
        );
        draw_rounded_box(
            pixels,
            bw,
            bh,
            RectF {
                x0: lx - 3.2 * s,
                y0: ly - 6.2 * s,
                x1: lx + 3.2 * s,
                y1: ly,
            },
            3.0 * s,
            (0, 0, 0, 0.0),
            Some((240, 179, 90, 0.95)),
        );

        // 5. Four Interactive Checkboxes
        let checks = [
            (st.chk_desktop, HitZone::ChkDesktop),
            (st.chk_start_menu, HitZone::ChkStartMenu),
            (st.chk_roaming, HitZone::ChkRoaming),
            (st.chk_launch, HitZone::ChkLaunch),
        ];
        for (i, &(checked, zone)) in checks.iter().enumerate() {
            let b = lay.chk_boxes[i];
            let hov = st.hover == zone;
            if checked {
                draw_rounded_box(
                    pixels,
                    bw,
                    bh,
                    b,
                    4.2 * s,
                    (240, 179, 90, if hov { 1.0 } else { 0.93 }),
                    None,
                );
                let bw_box = b.x1 - b.x0;
                let bh_box = b.y1 - b.y0;
                draw_segment_aa(
                    pixels,
                    bw,
                    bh,
                    b.x0 + bw_box * 0.24,
                    b.y0 + bh_box * 0.53,
                    b.x0 + bw_box * 0.44,
                    b.y0 + bh_box * 0.74,
                    1.9 * s,
                    (12, 12, 16),
                );
                draw_segment_aa(
                    pixels,
                    bw,
                    bh,
                    b.x0 + bw_box * 0.44,
                    b.y0 + bh_box * 0.74,
                    b.x0 + bw_box * 0.78,
                    b.y0 + bh_box * 0.28,
                    1.9 * s,
                    (12, 12, 16),
                );
            } else {
                draw_rounded_box(
                    pixels,
                    bw,
                    bh,
                    b,
                    4.2 * s,
                    (9, 10, 15, 1.0),
                    Some(if hov {
                        (240, 179, 90, 0.65)
                    } else {
                        (255, 255, 255, 0.24)
                    }),
                );
            }
        }

        // 6. Progress Bar Track & Smooth Animated Gold Fill
        draw_rounded_box(
            pixels,
            bw,
            bh,
            lay.prog_bar,
            4.5 * s,
            (255, 255, 255, 0.08),
            None,
        );
        let pct_clamped = (st.visual_pct / 100.0).clamp(0.0, 1.0);
        if pct_clamped > 0.005 {
            let fill_w = ((lay.prog_bar.x1 - lay.prog_bar.x0) * pct_clamped).max(9.0 * s);
            let fill_rect = RectF {
                x0: lay.prog_bar.x0,
                y0: lay.prog_bar.y0,
                x1: (lay.prog_bar.x0 + fill_w).min(lay.prog_bar.x1),
                y1: lay.prog_bar.y1,
            };
            draw_gradient_button(
                pixels,
                bw,
                bh,
                fill_rect,
                4.5 * s,
                (246, 196, 120),
                (218, 138, 44),
                1.0,
            );
        }

        // 7. Footer Buttons ("Annuler" + Primary Gold CTA)
        if phase == InstallPhase::Idle || phase == InstallPhase::Error {
            let canc_hov = st.hover == HitZone::CancelBtn;
            draw_rounded_box(
                pixels,
                bw,
                bh,
                lay.cancel_btn,
                8.5 * s,
                (255, 255, 255, if canc_hov { 0.11 } else { 0.05 }),
                Some((255, 255, 255, 0.12)),
            );
        }

        let prim_hov = st.hover == HitZone::PrimaryBtn;
        let prim_top = if prim_hov {
            (250, 200, 122)
        } else {
            (243, 186, 103)
        };
        let prim_bot = if prim_hov {
            (232, 152, 58)
        } else {
            (221, 140, 46)
        };
        draw_gradient_button(
            pixels,
            bw,
            bh,
            lay.primary_btn,
            8.5 * s,
            prim_top,
            prim_bot,
            if phase == InstallPhase::Running {
                0.45
            } else {
                1.0
            },
        );

        // 8. ClearType Typography Overlay
        let _ = SetBkMode(mem_dc, TRANSPARENT);

        let f_titlebar = make_font(12.0 * s, FW_MEDIUM.0 as i32, false);
        let f_badge = make_font(11.5 * s, FW_SEMIBOLD.0 as i32, false);
        let f_sub = make_font(12.5 * s, FW_NORMAL.0 as i32, false);
        let f_label = make_font(11.0 * s, FW_SEMIBOLD.0 as i32, false);
        let f_mono = make_font(12.5 * s, FW_NORMAL.0 as i32, true);
        let f_body = make_font(12.5 * s, FW_NORMAL.0 as i32, false);
        let f_btn = make_font(13.0 * s, FW_SEMIBOLD.0 as i32, false);

        let c_white = rgb_colorref(245, 246, 250);
        let c_muted = rgb_colorref(148, 153, 172);
        let c_gold = rgb_colorref(240, 179, 90);
        let c_dark = rgb_colorref(12, 12, 16);
        let c_soft = rgb_colorref(218, 222, 235);
        let c_err = rgb_colorref(255, 118, 110);

        draw_str(
            mem_dc,
            f_titlebar,
            c_muted,
            "Singularity Official Setup Wizard",
            RectF {
                x0: 84.0 * s,
                y0: 0.0,
                x1: wf - 20.0 * s,
                y1: lay.titlebar_h,
            },
            DT_LEFT | DT_VCENTER | DT_SINGLELINE,
        );

        draw_str(
            mem_dc,
            f_h1,
            c_white,
            "Singularity Browser",
            RectF {
                x0: hx0,
                y0: lay.logo_rect.y0 - 2.0 * s,
                x1: ver_pill.x0 - 4.0 * s,
                y1: lay.logo_rect.y0 + 28.0 * s,
            },
            DT_LEFT | DT_VCENTER | DT_SINGLELINE,
        );
        draw_str(
            mem_dc,
            f_badge,
            c_gold,
            &format!("v{APP_VERSION}"),
            ver_pill,
            windows::Win32::Graphics::Gdi::DT_CENTER | DT_VCENTER | DT_SINGLELINE,
        );
        draw_str(
            mem_dc,
            f_sub,
            c_muted,
            "Native Rust desktop browser with WebView2 rendering, built-in ad & tracker shield, Argon2id vault, and DPAPI-encrypted sessions.",
            RectF {
                x0: hx0,
                y0: lay.logo_rect.y0 + 30.0 * s,
                x1: wf - 30.0 * s,
                y1: lay.logo_rect.y1 + 6.0 * s,
            },
            DT_LEFT | DT_WORDBREAK,
        );

        // Card header labels
        let payload_mb = EMBEDDED_SINGULARITY_EXE.len() as f64 / (1024.0 * 1024.0);
        draw_str(
            mem_dc,
            f_label,
            c_muted,
            "INSTALLATION DIRECTORY",
            RectF {
                x0: lay.dir_box.x0,
                y0: lay.card_rect.y0 + 13.0 * s,
                x1: lay.browse_btn.x0,
                y1: lay.dir_box.y0 - 4.0 * s,
            },
            DT_LEFT | DT_VCENTER | DT_SINGLELINE,
        );
        draw_str(
            mem_dc,
            f_label,
            c_muted,
            &format!("{payload_mb:.1} MB • native x64"),
            RectF {
                x0: lay.browse_btn.x0 - 80.0 * s,
                y0: lay.card_rect.y0 + 13.0 * s,
                x1: lay.browse_btn.x1,
                y1: lay.dir_box.y0 - 4.0 * s,
            },
            DT_RIGHT | DT_VCENTER | DT_SINGLELINE,
        );

        draw_str(
            mem_dc,
            f_mono,
            c_white,
            &st.install_dir,
            RectF {
                x0: lay.dir_box.x0 + 11.0 * s,
                y0: lay.dir_box.y0,
                x1: lay.dir_box.x1 - 10.0 * s,
                y1: lay.dir_box.y1,
            },
            DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS,
        );
        draw_str(
            mem_dc,
            f_body,
            c_soft,
            "Browse…",
            lay.browse_btn,
            windows::Win32::Graphics::Gdi::DT_CENTER | DT_VCENTER | DT_SINGLELINE,
        );

        draw_str(
            mem_dc,
            f_body,
            c_soft,
            &format!(
                "Encrypted session store (DPAPI + XChaCha20): {}",
                st.roaming_dir
            ),
            RectF {
                x0: lay.roaming_box.x0 + 28.0 * s,
                y0: lay.roaming_box.y0,
                x1: lay.roaming_box.x1 - 10.0 * s,
                y1: lay.roaming_box.y1,
            },
            DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS,
        );

        let chk_labels = [
            "Desktop shortcut",
            "Start Menu & Installed Apps",
            "Initialize encrypted Roaming\\.singularity",
            "Launch Singularity after setup",
        ];
        for (i, lbl) in chk_labels.iter().enumerate() {
            let r = lay.chk_rects[i];
            draw_str(
                mem_dc,
                f_body,
                c_soft,
                lbl,
                RectF {
                    x0: lay.chk_boxes[i].x1 + 9.0 * s,
                    y0: r.y0,
                    x1: r.x1,
                    y1: r.y1,
                },
                DT_LEFT | DT_VCENTER | DT_SINGLELINE,
            );
        }

        // Progress status line
        let status_line = if phase == InstallPhase::Error {
            &err_msg
        } else {
            &step_label
        };
        let status_col = if phase == InstallPhase::Error {
            c_err
        } else if phase == InstallPhase::Done {
            c_gold
        } else {
            c_soft
        };
        draw_str(
            mem_dc,
            f_body,
            status_col,
            status_line,
            RectF {
                x0: lay.prog_bar.x0,
                y0: lay.prog_bar.y0 - 22.0 * s,
                x1: lay.prog_bar.x1 - 52.0 * s,
                y1: lay.prog_bar.y0 - 3.0 * s,
            },
            DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS,
        );
        draw_str(
            mem_dc,
            f_btn,
            c_gold,
            &format!("{}%", st.visual_pct.round() as u32),
            RectF {
                x0: lay.prog_bar.x1 - 50.0 * s,
                y0: lay.prog_bar.y0 - 22.0 * s,
                x1: lay.prog_bar.x1,
                y1: lay.prog_bar.y0 - 3.0 * s,
            },
            DT_RIGHT | DT_VCENTER | DT_SINGLELINE,
        );

        // Footer text + buttons
        draw_str(
            mem_dc,
            f_body,
            c_muted,
            "Native per-user install (no UAC elevation) • Clean uninstaller",
            RectF {
                x0: lay.card_rect.x0,
                y0: lay.primary_btn.y0,
                x1: lay.cancel_btn.x0 - 10.0 * s,
                y1: lay.primary_btn.y1,
            },
            DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS,
        );

        if phase == InstallPhase::Idle || phase == InstallPhase::Error {
            draw_str(
                mem_dc,
                f_btn,
                c_soft,
                "Cancel",
                lay.cancel_btn,
                windows::Win32::Graphics::Gdi::DT_CENTER | DT_VCENTER | DT_SINGLELINE,
            );
        }

        let primary_label = match phase {
            InstallPhase::Idle | InstallPhase::Error => "Install Singularity",
            InstallPhase::Running => "Installing…",
            InstallPhase::Done => {
                if st.chk_launch {
                    "Finish & Launch"
                } else {
                    "Finish"
                }
            }
        };
        draw_str(
            mem_dc,
            f_btn,
            c_dark,
            primary_label,
            lay.primary_btn,
            windows::Win32::Graphics::Gdi::DT_CENTER | DT_VCENTER | DT_SINGLELINE,
        );

        // Single tear-free BitBlt to window DC
        let _ = BitBlt(
            paint_dc,
            0,
            0,
            bw as i32,
            bh as i32,
            Some(mem_dc),
            0,
            0,
            SRCCOPY,
        );

        for f in [
            f_titlebar, f_h1, f_badge, f_sub, f_label, f_mono, f_body, f_btn,
        ] {
            let _ = DeleteObject(f.into());
        }
        let _ = SelectObject(mem_dc, old_bmp);
        let _ = DeleteObject(dib.into());
        let _ = DeleteDC(mem_dc);
        let _ = EndPaint(hwnd, &ps);
    }
}
