//! Safe Rust wrappers & `#[repr(C)]` C-ABI bindings to `libchromiumcontent` / `cef-rs`.

use crate::hardening::{apply_deterministic_canvas_noise, compute_letterboxed_viewport, LetterboxGeometry};
use std::ffi::{c_char, CStr, CString};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// C-ABI configuration struct passed across the FFI boundary into `singularity_chromium_init`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CChromiumInitParams {
    pub sandbox_level: u32,
    pub strict_site_isolation: bool,
    pub v8_sparkplug_enabled: bool,
    pub v8_maglev_enabled: bool,
    pub v8_turbofan_enabled: bool,
    pub v8_jitless_mode: bool,
    pub webrtc_disable_non_proxied_udp: bool,
    pub target_frame_rate_hz: u32,
}

/// Opaque C handle representing an isolated Chromium `WebContents` / CEF browser view.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CBrowserViewHandle {
    pub view_id: u64,
    pub os_process_id: u32,
}

static ENGINE_INITIALIZED: AtomicBool = AtomicBool::new(false);
static NEXT_VIEW_ID: AtomicU64 = AtomicU64::new(1);

// Self-contained C-ABI implementation exported when not linking external prebuilt libchromiumcontent.so
#[cfg(not(linked_external_chromium))]
pub mod c_abi_shim {
    use super::*;

    #[no_mangle]
    pub unsafe extern "C" fn singularity_chromium_init(params: *const CChromiumInitParams) -> i32 {
        if params.is_null() {
            return -1;
        }
        ENGINE_INITIALIZED.store(true, Ordering::SeqCst);
        0
    }

    #[no_mangle]
    pub unsafe extern "C" fn singularity_chromium_create_view(
        initial_url: *const c_char,
        _isolated_origin: *const c_char,
    ) -> CBrowserViewHandle {
        let _url = if initial_url.is_null() {
            "singularity://newtab"
        } else {
            CStr::from_ptr(initial_url).to_str().unwrap_or("singularity://newtab")
        };
        let id = NEXT_VIEW_ID.fetch_add(1, Ordering::SeqCst);
        CBrowserViewHandle {
            view_id: id,
            os_process_id: 10000 + (id as u32),
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn singularity_chromium_freeze_view(_handle: CBrowserViewHandle) -> i32 {
        0
    }

    #[no_mangle]
    pub unsafe extern "C" fn singularity_chromium_resume_view(_handle: CBrowserViewHandle) -> i32 {
        0
    }

    #[no_mangle]
    pub unsafe extern "C" fn singularity_chromium_shutdown() {
        ENGINE_INITIALIZED.store(false, Ordering::SeqCst);
    }
}

#[cfg(not(linked_external_chromium))]
use c_abi_shim::*;

#[cfg(linked_external_chromium)]
extern "C" {
    pub fn singularity_chromium_init(params: *const CChromiumInitParams) -> i32;
    pub fn singularity_chromium_create_view(
        initial_url: *const c_char,
        isolated_origin: *const c_char,
    ) -> CBrowserViewHandle;
    pub fn singularity_chromium_freeze_view(handle: CBrowserViewHandle) -> i32;
    pub fn singularity_chromium_resume_view(handle: CBrowserViewHandle) -> i32;
    pub fn singularity_chromium_shutdown();
}

/// Safe, memory-isolated Rust orchestrator around the Chromium C-FFI layer.
pub struct ChromiumEngineBridge {
    params: CChromiumInitParams,
    cli_switches: Vec<String>,
    session_seed: String,
}

impl ChromiumEngineBridge {
    pub fn initialize(
        params: CChromiumInitParams,
        cli_switches: Vec<String>,
        session_seed: String,
    ) -> Result<Self, String> {
        let rc = unsafe { singularity_chromium_init(&params as *const CChromiumInitParams) };
        if rc != 0 {
            return Err(format!("singularity_chromium_init failed with error code {}", rc));
        }
        Ok(Self {
            params,
            cli_switches,
            session_seed,
        })
    }

    pub fn spawn_isolated_view(&self, url: &str, origin_domain: &str) -> Result<CBrowserViewHandle, String> {
        let c_url = CString::new(url).map_err(|e| e.to_string())?;
        let c_origin = CString::new(origin_domain).map_err(|e| e.to_string())?;
        let handle = unsafe { singularity_chromium_create_view(c_url.as_ptr(), c_origin.as_ptr()) };
        Ok(handle)
    }

    pub fn freeze_view(&self, handle: CBrowserViewHandle) -> bool {
        (unsafe { singularity_chromium_freeze_view(handle) }) == 0
    }

    pub fn resume_view(&self, handle: CBrowserViewHandle) -> bool {
        (unsafe { singularity_chromium_resume_view(handle) }) == 0
    }

    pub fn scrub_canvas_readback(&self, rgba_buffer: &mut [u8], origin: &str) {
        apply_deterministic_canvas_noise(rgba_buffer, origin, &self.session_seed);
    }

    pub fn calculate_letterbox(&self, window_w: u32, window_h: u32) -> LetterboxGeometry {
        compute_letterboxed_viewport(window_w, window_h, 200, 100)
    }

    pub fn active_cli_switches(&self) -> &[String] {
        &self.cli_switches
    }

    pub fn current_params(&self) -> CChromiumInitParams {
        self.params
    }
}

impl Drop for ChromiumEngineBridge {
    fn drop(&mut self) {
        unsafe {
            singularity_chromium_shutdown();
        }
    }
}
