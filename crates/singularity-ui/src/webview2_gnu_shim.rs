//! Self-contained WebView2Loader bridge for Windows GNU/GNULLVM builds.
//! Embeds Microsoft's signed `WebView2Loader.dll` inside `singularity.exe` so the
//! release binary remains a 100% single-file standalone executable with zero external DLLs.

use core::ffi::c_void;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use subtle::ConstantTimeEq;

const EMBEDDED_WEBVIEW2_LOADER_DLL: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/WebView2Loader.dll"));

const E_FAIL: i32 = 0x8000_4005u32 as i32;

type FnCompareBrowserVersions =
    unsafe extern "system" fn(*const u16, *const u16, *mut i32) -> i32;
type FnCreateCoreWebView2Environment = unsafe extern "system" fn(*mut c_void) -> i32;
type FnCreateCoreWebView2EnvironmentWithOptions =
    unsafe extern "system" fn(*const u16, *const u16, *mut c_void, *mut c_void) -> i32;
type FnGetAvailableCoreWebView2BrowserVersionString =
    unsafe extern "system" fn(*const u16, *mut *mut u16) -> i32;
type FnGetAvailableCoreWebView2BrowserVersionStringWithOptions =
    unsafe extern "system" fn(*const u16, *mut c_void, *mut *mut u16) -> i32;

struct WebView2Exports {
    compare: Option<FnCompareBrowserVersions>,
    create_env: Option<FnCreateCoreWebView2Environment>,
    create_env_opts: Option<FnCreateCoreWebView2EnvironmentWithOptions>,
    get_ver: Option<FnGetAvailableCoreWebView2BrowserVersionString>,
    get_ver_opts: Option<FnGetAvailableCoreWebView2BrowserVersionStringWithOptions>,
}

#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryW(lpLibFileName: *const u16) -> *mut c_void;
    fn GetProcAddress(hModule: *mut c_void, lpProcName: *const u8) -> *mut c_void;
}

static EXPORTS: OnceLock<WebView2Exports> = OnceLock::new();

fn expected_dll_sha256() -> [u8; 32] {
    Sha256::digest(EMBEDDED_WEBVIEW2_LOADER_DLL).into()
}

fn verify_file_sha256(path: &Path, expected: &[u8; 32]) -> bool {
    let Ok(bytes) = std::fs::read(path) else {
        return false;
    };
    if bytes.len() != EMBEDDED_WEBVIEW2_LOADER_DLL.len() {
        return false;
    }
    let actual: [u8; 32] = Sha256::digest(&bytes).into();
    bool::from(actual.ct_eq(expected))
}

fn app_bin_dir() -> Option<PathBuf> {
    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        let trimmed = local.trim();
        if !trimmed.is_empty() {
            return Some(PathBuf::from(trimmed).join("SingularityPro").join("bin"));
        }
    }
    None
}

fn ensure_verified_dll_at(dir: &Path, expected_hash: &[u8; 32]) -> Option<PathBuf> {
    std::fs::create_dir_all(dir).ok()?;
    let hash_prefix = hex::encode(&expected_hash[..8]);
    let dll_path = dir.join(format!("WebView2Loader_{}.dll", hash_prefix));

    if !verify_file_sha256(&dll_path, expected_hash) {
        let mut rnd = [0u8; 8];
        OsRng.fill_bytes(&mut rnd);
        let tmp_path = dir.join(format!(
            "WebView2Loader.{}.{}.tmp",
            std::process::id(),
            hex::encode(rnd)
        ));
        if std::fs::write(&tmp_path, EMBEDDED_WEBVIEW2_LOADER_DLL).is_ok() {
            if std::fs::rename(&tmp_path, &dll_path).is_err() {
                let _ = std::fs::remove_file(&tmp_path);
            }
        }
    }

    if verify_file_sha256(&dll_path, expected_hash) {
        Some(dll_path)
    } else {
        None
    }
}

fn load_exports() -> &'static WebView2Exports {
    EXPORTS.get_or_init(|| {
        let expected_hash = expected_dll_sha256();
        let dll_path = app_bin_dir()
            .and_then(|dir| ensure_verified_dll_at(&dir, &expected_hash))
            .or_else(|| {
                let mut rnd = [0u8; 8];
                OsRng.fill_bytes(&mut rnd);
                let isolated_tmp = std::env::temp_dir().join(format!(
                    "SingularityPro_bin_{}_{}",
                    std::process::id(),
                    hex::encode(rnd)
                ));
                ensure_verified_dll_at(&isolated_tmp, &expected_hash)
            });

        let Some(path) = dll_path else {
            return WebView2Exports {
                compare: None,
                create_env: None,
                create_env_opts: None,
                get_ver: None,
                get_ver_opts: None,
            };
        };

        // Re-verify SHA-256 right before LoadLibraryW to minimize TOCTOU exposure
        if !verify_file_sha256(&path, &expected_hash) {
            return WebView2Exports {
                compare: None,
                create_env: None,
                create_env_opts: None,
                get_ver: None,
                get_ver_opts: None,
            };
        }

        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        unsafe {
            let hmod = LoadLibraryW(wide.as_ptr());
            if hmod.is_null() {
                return WebView2Exports {
                    compare: None,
                    create_env: None,
                    create_env_opts: None,
                    get_ver: None,
                    get_ver_opts: None,
                };
            }

            let p_cmp = GetProcAddress(hmod, b"CompareBrowserVersions\0".as_ptr());
            let p_env = GetProcAddress(hmod, b"CreateCoreWebView2Environment\0".as_ptr());
            let p_env_opts =
                GetProcAddress(hmod, b"CreateCoreWebView2EnvironmentWithOptions\0".as_ptr());
            let p_ver = GetProcAddress(
                hmod,
                b"GetAvailableCoreWebView2BrowserVersionString\0".as_ptr(),
            );
            let p_ver_opts = GetProcAddress(
                hmod,
                b"GetAvailableCoreWebView2BrowserVersionStringWithOptions\0".as_ptr(),
            );

            WebView2Exports {
                compare: (!p_cmp.is_null()).then(|| core::mem::transmute(p_cmp)),
                create_env: (!p_env.is_null()).then(|| core::mem::transmute(p_env)),
                create_env_opts: (!p_env_opts.is_null()).then(|| core::mem::transmute(p_env_opts)),
                get_ver: (!p_ver.is_null()).then(|| core::mem::transmute(p_ver)),
                get_ver_opts: (!p_ver_opts.is_null()).then(|| core::mem::transmute(p_ver_opts)),
            }
        }
    })
}

#[no_mangle]
pub unsafe extern "system" fn CompareBrowserVersions(
    version1: *const u16,
    version2: *const u16,
    result: *mut i32,
) -> i32 {
    match load_exports().compare {
        Some(f) => unsafe { f(version1, version2, result) },
        None => E_FAIL,
    }
}

#[no_mangle]
pub unsafe extern "system" fn CreateCoreWebView2Environment(
    environment_created_handler: *mut c_void,
) -> i32 {
    match load_exports().create_env {
        Some(f) => unsafe { f(environment_created_handler) },
        None => E_FAIL,
    }
}

#[no_mangle]
pub unsafe extern "system" fn CreateCoreWebView2EnvironmentWithOptions(
    browser_executable_folder: *const u16,
    user_data_folder: *const u16,
    environment_options: *mut c_void,
    environment_created_handler: *mut c_void,
) -> i32 {
    match load_exports().create_env_opts {
        Some(f) => unsafe {
            f(
                browser_executable_folder,
                user_data_folder,
                environment_options,
                environment_created_handler,
            )
        },
        None => E_FAIL,
    }
}

#[no_mangle]
pub unsafe extern "system" fn GetAvailableCoreWebView2BrowserVersionString(
    browser_executable_folder: *const u16,
    version_info: *mut *mut u16,
) -> i32 {
    match load_exports().get_ver {
        Some(f) => unsafe { f(browser_executable_folder, version_info) },
        None => E_FAIL,
    }
}

#[no_mangle]
pub unsafe extern "system" fn GetAvailableCoreWebView2BrowserVersionStringWithOptions(
    browser_executable_folder: *const u16,
    environment_options: *mut c_void,
    version_info: *mut *mut u16,
) -> i32 {
    match load_exports().get_ver_opts {
        Some(f) => unsafe { f(browser_executable_folder, environment_options, version_info) },
        None => E_FAIL,
    }
}
