#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
//! `singularity` — Primary Native Desktop Binary for the Singularity Privacy-Hardened Browser.

use singularity_ui::{
    execute_self_update, execute_uninstall, perform_startup_maintenance,
    run_interactive_browser_app, run_interactive_browser_app_with_smoke, CefSmokeTestOptions,
    SingularityBrowserShell,
};

fn main() {
    // 0. Pure Chromium (CEF) multi-process entry point: renderer, GPU, network, and utility
    //    subprocesses re-execute `singularity.exe --type=...`. Checking `--type=` / `--type` in
    //    pure Rust FIRST prevents delay-loaded `libcef.dll` from being touched during CLI flags
    //    (`--version`, `--update`, `--uninstall`) or self-healing runtime bootstrap!
    #[cfg(target_os = "windows")]
    if std::env::args().any(|a| a.starts_with("--type=") || a == "--type") {
        singularity_ui::updater::configure_local_cef_dll_directory();
        if let Some(exit_code) = singularity_ui::cef_runtime::maybe_run_cef_subprocess() {
            std::process::exit(exit_code);
        }
    }

    if std::env::args().any(|a| a == "--version" || a == "-V") {
        println!("Singularity Browser v{}", env!("CARGO_PKG_VERSION"));
        return;
    }

    if std::env::args().any(|a| a == "--uninstall") {
        let _ = execute_uninstall();
        return;
    }

    // Wait cleanly for previous instance to release CEF profile lock during planned in-app restart
    #[cfg(target_os = "windows")]
    {
        let cli_args: Vec<String> = std::env::args().collect();
        if let Some(pid_str) = cli_args
            .windows(2)
            .find(|w| w[0] == "--wait-pid")
            .map(|w| w[1].as_str())
        {
            if let Ok(pid) = pid_str.parse::<u32>() {
                if pid != 0 && pid != std::process::id() {
                    #[link(name = "kernel32")]
                    extern "system" {
                        fn OpenProcess(
                            dw_desired_access: u32,
                            b_inherit_handle: i32,
                            dw_process_id: u32,
                        ) -> *mut core::ffi::c_void;
                        fn WaitForSingleObject(
                            h_handle: *mut core::ffi::c_void,
                            dw_milliseconds: u32,
                        ) -> u32;
                        fn CloseHandle(h_object: *mut core::ffi::c_void) -> i32;
                    }
                    const SYNCHRONIZE: u32 = 0x0010_0000;
                    unsafe {
                        let h = OpenProcess(SYNCHRONIZE, 0, pid);
                        if !h.is_null() {
                            let _ = WaitForSingleObject(h, 8000);
                            let _ = CloseHandle(h);
                        }
                    }
                    std::thread::sleep(std::time::Duration::from_millis(120));
                }
            }
        }
    }

    // 1. In-binary maintenance: initialize `%APPDATA%\.singularity` and clean up `.old` backup
    perform_startup_maintenance();

    // 2. Embedded 1-Click updater command line flag
    if std::env::args().any(|a| a == "--update") {
        println!("Singularity — Checking for and installing the latest release...");
        match execute_self_update() {
            Ok(msg) => println!("{}", msg),
            Err(e) => eprintln!("Update error: {}", e),
        }
        return;
    }

    let args: Vec<String> = std::env::args().collect();
    let smoke_test_cef = args.iter().any(|a| a == "--smoke-test-cef");
    let verify_only = args.iter().any(|a| a == "--verify-only");
    let force_new_window = args.iter().any(|a| a == "--new-window");

    // Install Rust panic + native Windows SEH unhandled-exception crash detectors with automatic
    // copyable error report popup before booting the browser engine (skipped in headless CI modes).
    if !smoke_test_cef && !verify_only {
        singularity_ui::crash_guard::install_crash_handlers(
            &singularity_ui::resolve_roaming_singularity_dir(),
        );
    }

    let detach_handoff_id = args
        .windows(2)
        .find(|w| w[0] == "--detach-handoff")
        .map(|w| w[1].clone());
    let restore_session_id = args
        .windows(2)
        .find(|w| w[0] == "--restore-session")
        .map(|w| w[1].clone());

    let shell = match SingularityBrowserShell::launch_with_launch_args(
        detach_handoff_id.as_deref(),
        restore_session_id.as_deref(),
        force_new_window,
    ) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to boot Singularity Browser Engine: {}", e);
            if smoke_test_cef {
                std::process::exit(1);
            }
            return;
        }
    };

    if std::env::args().any(|a| a == "--verify-only") {
        println!(
            "Singularity v{} Engine: OK ({} settings wired, roaming dir: {})",
            env!("CARGO_PKG_VERSION"),
            shell.core.settings.len(),
            shell.roaming.root_dir().display()
        );
        return;
    }

    // 3. Self-healing Pure Chromium (CEF) runtime check on Windows:
    //    If a user upgraded in-place from v1.0.x (Edge WebView2) via the in-app updater or ran
    //    standalone `singularity.exe` without `libcef.dll`, automatically download & verify
    //    `Singularity-setup.exe` and silently install the CEF runtime beside `singularity.exe`.
    #[cfg(target_os = "windows")]
    {
        if !singularity_ui::updater::has_local_cef_runtime() {
            if smoke_test_cef {
                eprintln!("Smoke test failed: missing local CEF runtime alongside singularity.exe");
                std::process::exit(1);
            }
            if let Err(err) = singularity_ui::updater::bootstrap_missing_cef_runtime() {
                singularity_ui::updater::show_missing_cef_error_dialog(&err);
            }
            return;
        }
        singularity_ui::updater::configure_local_cef_dll_directory();
    }

    if smoke_test_cef {
        let base_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(std::path::Path::to_path_buf))
            .unwrap_or_else(std::env::temp_dir);
        let log_path = args
            .windows(2)
            .find(|w| w[0] == "--smoke-log")
            .map(|w| std::path::PathBuf::from(&w[1]))
            .unwrap_or_else(|| base_dir.join("singularity-smoke.log"));
        let cef_log_path = args
            .windows(2)
            .find(|w| w[0] == "--smoke-cef-log")
            .map(|w| std::path::PathBuf::from(&w[1]))
            .unwrap_or_else(|| base_dir.join("singularity-smoke-cef.log"));
        let profile_dir = args
            .windows(2)
            .find(|w| w[0] == "--smoke-profile")
            .map(|w| std::path::PathBuf::from(&w[1]))
            .unwrap_or_else(|| std::env::temp_dir().join("singularity-smoke-cef-profile"));
        let opts = CefSmokeTestOptions {
            log_path: log_path.clone(),
            cef_log_path,
            profile_dir,
            timeout_secs: 25,
        };
        if let Err(err) = run_interactive_browser_app_with_smoke(shell, Some(opts)) {
            let _ = std::fs::write(&log_path, format!("[SMOKE] FATAL: {}\n", err));
            eprintln!("Singularity CEF smoke test failed: {}", err);
            std::process::exit(1);
        }
        return;
    }

    if let Err(err) = run_interactive_browser_app(shell) {
        eprintln!("Singularity runtime error: {}", err);
    }
}
