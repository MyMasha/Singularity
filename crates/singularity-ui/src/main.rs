#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
//! `singularity` — Primary Native Desktop Binary for the Singularity Privacy-Hardened Browser.

use singularity_ui::{
    execute_self_update, execute_uninstall, perform_startup_maintenance,
    run_interactive_browser_app, SingularityBrowserShell,
};

fn main() {
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

    let shell = match SingularityBrowserShell::launch() {
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
