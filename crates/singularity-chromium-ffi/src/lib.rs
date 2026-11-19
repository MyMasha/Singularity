//! `singularity-chromium-ffi` — Zero-Telemetry Hardened Chromium C-FFI & Anti-Fingerprinting Layer.

pub mod ffi;
pub mod hardening;
#[path = "../../../chromium/strip_telemetry.rs"]
pub mod strip_telemetry;

pub use ffi::{CBrowserViewHandle, CChromiumInitParams, ChromiumEngineBridge};
pub use hardening::{
    apply_audiocontext_frequency_noise, apply_deterministic_canvas_noise,
    compute_letterboxed_viewport, LetterboxGeometry, MullvadAntiFingerprintProfile,
};
pub use strip_telemetry::{
    apply_chromium_telemetry_strip, scrub_source_buffer, StripTelemetryReport,
    CHROMIUM_SOURCE_PATCHES, TELEMETRY_DOMAINS_BLACKLIST,
};

use rand_core::{OsRng, RngCore};
use singularity_settings_registry::SettingsRegistry;

const KNOWN_INSECURE_PLACEHOLDER_SEEDS: &[&str] = &[
    "",
    "singularity_default_ephemeral_seed",
    "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
];

fn generate_ephemeral_session_seed() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Builds a `ChromiumEngineBridge` directly from the live `SettingsRegistry`.
pub fn init_chromium_from_registry(registry: &SettingsRegistry) -> Result<ChromiumEngineBridge, String> {
    let bool_or = |key: &str, def: bool| -> bool {
        registry
            .get(key)
            .and_then(|e| e.current_value.as_bool())
            .unwrap_or(def)
    };
    let int_or = |key: &str, def: i64| -> i64 {
        registry
            .get(key)
            .and_then(|e| e.current_value.as_int())
            .unwrap_or(def)
    };
    let str_or = |key: &str, def: &str| -> String {
        registry
            .get(key)
            .and_then(|e| e.current_value.as_str())
            .unwrap_or(def)
            .to_string()
    };

    let params = CChromiumInitParams {
        sandbox_level: int_or("security.sandbox.level", 4).clamp(1, 4) as u32,
        strict_site_isolation: bool_or("security.site_isolation.strict_origin_keyed_processes", true),
        v8_sparkplug_enabled: bool_or("security.v8.jit.sparkplug_baseline_enabled", true),
        v8_maglev_enabled: bool_or("security.v8.jit.maglev_midtier_enabled", true),
        v8_turbofan_enabled: bool_or("security.v8.jit.turbofan_optimizing_enabled", true),
        v8_jitless_mode: bool_or("security.v8.jitless_strict_mode", false),
        webrtc_disable_non_proxied_udp: true,
        target_frame_rate_hz: int_or("rendering.frame_pacing.target_refresh_rate_hz", 240)
            .clamp(30, 540) as u32,
    };

    let cli_switches = registry.compile_chromium_command_line_switches();
    let configured_seed = str_or("privacy.canvas.session_master_seed", "");
    let seed = if KNOWN_INSECURE_PLACEHOLDER_SEEDS.contains(&configured_seed.trim()) {
        generate_ephemeral_session_seed()
    } else {
        configured_seed
    };

    ChromiumEngineBridge::initialize(params, cli_switches, seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_telemetry_source_scrubber() {
        let sample_cpp = r#"
            const char kSafeBrowsingUrl[] = "https://safebrowsing.googleapis.com/v4/threatListUpdates";
            const char kVariationsUrl[] = "https://chromevariations.googleapis.com/seed";
        "#;
        let (scrubbed, count) = scrub_source_buffer(sample_cpp);
        assert_eq!(count, 2);
        assert!(!scrubbed.contains("safebrowsing.googleapis.com"));
        assert!(!scrubbed.contains("chromevariations.googleapis.com"));
        assert!(scrubbed.contains("0.0.0.0.invalid"));
    }

    #[test]
    fn test_mullvad_letterboxing_and_canvas_noise() {
        let geom = compute_letterboxed_viewport(1920, 1080, 200, 100);
        assert_eq!(geom.spoofed_inner_width, 1800);
        assert_eq!(geom.spoofed_inner_height, 1000);
        assert_eq!(geom.margin_left_px, 60);
        assert_eq!(geom.margin_top_px, 40);

        let mut pixels_a = vec![128u8; 64];
        let mut pixels_b = vec![128u8; 64];
        let mut pixels_other_origin = vec![128u8; 64];

        apply_deterministic_canvas_noise(&mut pixels_a, "https://example.org", "seed123");
        apply_deterministic_canvas_noise(&mut pixels_b, "https://example.org", "seed123");
        apply_deterministic_canvas_noise(&mut pixels_other_origin, "https://tracker.com", "seed123");

        // Deterministic per origin, distinct across origins
        assert_eq!(pixels_a, pixels_b);
        assert_ne!(pixels_a, pixels_other_origin);
    }

    #[test]
    fn test_ffi_bridge_from_registry() {
        let reg = SettingsRegistry::new();
        let bridge = init_chromium_from_registry(&reg).expect("FFI bridge init");
        let view = bridge
            .spawn_isolated_view("https://mullvad.net", "mullvad.net")
            .expect("Spawn view");
        assert!(view.view_id >= 1);
        assert!(bridge.freeze_view(view));
        assert!(bridge.resume_view(view));
    }
}
