//! Build script (`build.rs`) for `singularity-chromium-ffi`.
//!
//! 1. Verifies that `../../chromium/args.gn` enforces zero-telemetry invariants.
//! 2. Links external `libchromiumcontent` / `libcef` if `SINGULARITY_CHROMIUM_LIB_DIR` is provided,
//!    or enables the self-contained Rust C-ABI FFI runtime shim for immediate local builds & tests.

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../../chromium/args.gn");
    println!("cargo:rerun-if-changed=../../chromium/strip_telemetry.rs");
    println!("cargo:rerun-if-env-changed=SINGULARITY_CHROMIUM_LIB_DIR");
    println!("cargo:rerun-if-env-changed=SINGULARITY_CHROMIUM_SRC_DIR");

    println!("cargo:rustc-check-cfg=cfg(linked_external_chromium)");

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let args_gn_path = manifest_dir.join("../../chromium/args.gn");

    if args_gn_path.exists() {
        let gn_content = fs::read_to_string(&args_gn_path).expect("Failed to read chromium/args.gn");
        // Enforce mandatory zero-telemetry build invariants at compile time
        for required_flag in [
            "enable_rlz = false",
            "enable_reporting = false",
            "safe_browsing_mode = 0",
            "enable_safe_browsing = false",
            "use_official_google_api_keys = false",
            "v8_enable_sandbox = true",
        ] {
            assert!(
                gn_content.contains(required_flag),
                "SECURITY VIOLATION: chromium/args.gn is missing mandatory hardening flag: {}",
                required_flag
            );
        }
    }

    if let Ok(lib_dir) = env::var("SINGULARITY_CHROMIUM_LIB_DIR") {
        let path = PathBuf::from(&lib_dir);
        if path.exists() {
            println!("cargo:rustc-link-search=native={}", path.display());
            println!("cargo:rustc-link-lib=dylib=chromiumcontent");
            println!("cargo:rustc-cfg=linked_external_chromium");
        }
    }
}
