//! Anti-fingerprinting hardening hooks inspired by Mullvad Browser:
//! - Dynamic `200x100` viewport letterboxing
//! - Deterministic per-origin Canvas2D RGBA sub-LSB noise injection
//! - AudioContext float frequency noise injection
//! - Uniform WebGL, User-Agent, Timezone (UTC), and Locale (`en-US`) spoofing

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Computed letterboxed viewport geometry with OLED `#000000` matte margins.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LetterboxGeometry {
    pub raw_window_width: u32,
    pub raw_window_height: u32,
    pub spoofed_inner_width: u32,
    pub spoofed_inner_height: u32,
    pub margin_left_px: u32,
    pub margin_top_px: u32,
}

/// Quantizes the physical window size to Mullvad-style steps (default `200px` x `100px`)
/// so `window.innerWidth` and `window.innerHeight` fall into a large anonymity bucket.
pub fn compute_letterboxed_viewport(
    raw_width: u32,
    raw_height: u32,
    step_w: u32,
    step_h: u32,
) -> LetterboxGeometry {
    let sw = step_w.max(1);
    let sh = step_h.max(1);

    let spoofed_w = if raw_width < sw {
        raw_width
    } else {
        (raw_width / sw) * sw
    };
    let spoofed_h = if raw_height < sh {
        raw_height
    } else {
        (raw_height / sh) * sh
    };

    let margin_left = raw_width.saturating_sub(spoofed_w) / 2;
    let margin_top = raw_height.saturating_sub(spoofed_h) / 2;

    LetterboxGeometry {
        raw_window_width: raw_width,
        raw_window_height: raw_height,
        spoofed_inner_width: spoofed_w,
        spoofed_inner_height: spoofed_h,
        margin_left_px: margin_left,
        margin_top_px: margin_top,
    }
}

/// Applies deterministic, per-origin keyed sub-LSB noise to a Canvas2D RGBA buffer (`getImageData`).
/// Identical calls from the same first-party origin within a session produce consistent noise
/// (defeating multi-read statistical averaging), while differing across origins and sessions.
pub fn apply_deterministic_canvas_noise(
    rgba_pixels: &mut [u8],
    first_party_origin: &str,
    session_master_seed: &str,
) {
    if rgba_pixels.is_empty() {
        return;
    }

    let mut hasher = Sha256::new();
    hasher.update(b"SINGULARITY_CANVAS_NOISE_V2:");
    hasher.update((session_master_seed.len() as u64).to_le_bytes());
    hasher.update(session_master_seed.as_bytes());
    hasher.update(b":");
    hasher.update((first_party_origin.len() as u64).to_le_bytes());
    hasher.update(first_party_origin.as_bytes());
    let keystream: [u8; 32] = hasher.finalize().into();

    // Perturb selected RGB channels by +/- 1 LSB deterministically
    for (idx, chunk) in rgba_pixels.chunks_exact_mut(4).enumerate() {
        let mask = keystream[idx & 31];
        if (mask & 0b0000_0111) == 0b0000_0101 {
            let channel = ((mask >> 3) & 0x03) as usize % 3; // R, G, or B
            chunk[channel] ^= 0x01;
        }
    }
}

/// Applies deterministic micro-perturbation to WebAudio `AnalyserNode::getFloatFrequencyData` buffers.
pub fn apply_audiocontext_frequency_noise(
    freq_bins_db: &mut [f32],
    first_party_origin: &str,
    session_master_seed: &str,
    noise_floor_db: f32,
) {
    let mut hasher = Sha256::new();
    hasher.update(b"SINGULARITY_AUDIO_NOISE_V2:");
    hasher.update((session_master_seed.len() as u64).to_le_bytes());
    hasher.update(session_master_seed.as_bytes());
    hasher.update(b":");
    hasher.update((first_party_origin.len() as u64).to_le_bytes());
    hasher.update(first_party_origin.as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();

    let safe_floor = if noise_floor_db.is_finite() {
        noise_floor_db.clamp(-120.0, -40.0)
    } else {
        -90.0
    };
    let scale = 10.0_f32.powf(safe_floor / 20.0);
    for (i, sample) in freq_bins_db.iter_mut().enumerate() {
        let byte = digest[i & 31] as f32 / 255.0 - 0.5;
        *sample += byte * scale;
    }
}

/// Uniform hardened browser identity exposed to Blink/V8 DOM bindings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MullvadAntiFingerprintProfile {
    pub user_agent: String,
    pub platform: String,
    pub accept_language: String,
    pub timezone_iana: String,
    pub hardware_concurrency: u32,
    pub device_memory_gb: u32,
    pub webgl_vendor: String,
    pub webgl_renderer: String,
    pub webrtc_policy: String,
}

impl Default for MullvadAntiFingerprintProfile {
    fn default() -> Self {
        Self {
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36".into(),
            platform: "Win32".into(),
            accept_language: "en-US,en;q=0.9".into(),
            timezone_iana: "Etc/UTC".into(),
            hardware_concurrency: 4,
            device_memory_gb: 8,
            webgl_vendor: "Google Inc. (Generic)".into(),
            webgl_renderer: "ANGLE (Generic, Vulkan 1.3.0)".into(),
            webrtc_policy: "disable_non_proxied_udp".into(),
        }
    }
}
