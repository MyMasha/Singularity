#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
//! `singularity` — Primary Native Desktop Binary for the Singularity Privacy-Hardened Browser.

use singularity_ui::{
    execute_self_update, execute_uninstall, perform_startup_maintenance,
    run_interactive_browser_app, SingularityBrowserShell,
};

fn main() {
    // 0. Pure Chromium (CEF) multi-process entry point: renderer, GPU, network, and utility
    //    subprocesses re-execute `singularity.exe --type=...` and MUST return immediately here
    //    before any CLI handling, roaming store access, or window creation.
    #[cfg(target_os = "windows")]
    if let Some(exit_code) = singularity_ui::cef_runtime::maybe_run_cef_subprocess() {
        std::process::exit(exit_code);
    }

    if std::env::args().any(|a| a == "--version" || a == "-V") {
        println!("Singularity Browser v{}", env!("CARGO_PKG_VERSION"));
        return;
    }

    if std::env::args().any(|a| a == "--uninstall") {
        let _ = execute_uninstall();
        return;
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
    let force_new_window = args.iter().any(|a| a == "--new-window");
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

    if let Err(err) = run_interactive_browser_app(shell) {
        eprintln!("Singularity runtime error: {}", err);
    }
}
