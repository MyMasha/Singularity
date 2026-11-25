//! Anti-fingerprinting hardening hooks inspired by Mullvad Browser:
//! - Dynamic `200x100` viewport letterboxing
//! - Deterministic aperiodic per-origin Canvas2D RGBA sub-LSB noise injection (SHA-256 CTR)
//! - Deterministic aperiodic AudioContext float frequency noise injection (SHA-256 CTR)
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

fn derive_origin_base_key(domain_sep: &[u8], first_party_origin: &str, session_master_seed: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain_sep);
    hasher.update((session_master_seed.len() as u64).to_le_bytes());
    hasher.update(session_master_seed.as_bytes());
    hasher.update(b":");
    hasher.update((first_party_origin.len() as u64).to_le_bytes());
    hasher.update(first_party_origin.as_bytes());
    hasher.finalize().into()
}

/// Derives an independent aperiodic 32-byte keystream block for `(base_key, block_counter)`
/// via SHA-256 in counter mode, eliminating any periodic modulo-32 noise artifacts.
#[inline]
fn derive_ctr_keystream_block(base_key: &[u8; 32], block_counter: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(base_key);
    hasher.update(block_counter.to_le_bytes());
    hasher.finalize().into()
}

/// Applies deterministic, aperiodic, per-origin keyed sub-LSB noise to a Canvas2D RGBA buffer (`getImageData`).
/// Identical calls from the same first-party origin within a session produce consistent noise
/// (defeating multi-read statistical averaging), while differing across origins, sessions, and
/// every pixel coordinate without modulo-32 periodicity.
pub fn apply_deterministic_canvas_noise(
    rgba_pixels: &mut [u8],
    first_party_origin: &str,
    session_master_seed: &str,
) {
    if rgba_pixels.is_empty() {
        return;
    }

    let base_key = derive_origin_base_key(
        b"SINGULARITY_CANVAS_NOISE_V3_CTR:",
        first_party_origin,
        session_master_seed,
    );

    let mut block = [0u8; 32];
    for (idx, chunk) in rgba_pixels.chunks_exact_mut(4).enumerate() {
        let lane = idx & 31;
        if lane == 0 {
            block = derive_ctr_keystream_block(&base_key, (idx / 32) as u64);
        }
        let mask = block[lane];
        // Perturb ~25% of pixels by +/- 1 LSB in a deterministic RGB channel (alpha untouched)
        if (mask & 0b0000_0011) == 0b0000_0001 {
            let channel = ((mask >> 2) & 0x03) as usize % 3;
            chunk[channel] ^= 0x01;
        }
    }
}

/// Applies deterministic, aperiodic micro-perturbation to WebAudio `AnalyserNode::getFloatFrequencyData` buffers.
pub fn apply_audiocontext_frequency_noise(
    freq_bins_db: &mut [f32],
    first_party_origin: &str,
    session_master_seed: &str,
    noise_floor_db: f32,
) {
    if freq_bins_db.is_empty() {
        return;
    }

    let base_key = derive_origin_base_key(
        b"SINGULARITY_AUDIO_NOISE_V3_CTR:",
        first_party_origin,
        session_master_seed,
    );

    let safe_floor = if noise_floor_db.is_finite() {
        noise_floor_db.clamp(-120.0, -40.0)
    } else {
        -90.0
    };
    let scale = 10.0_f32.powf(safe_floor / 20.0);

    let mut block = [0u8; 32];
    for (i, sample) in freq_bins_db.iter_mut().enumerate() {
        let pair_idx = i & 15; // 16 x u16 values per 32-byte SHA-256 block
        if pair_idx == 0 {
            block = derive_ctr_keystream_block(&base_key, (i / 16) as u64);
        }
        if sample.is_finite() {
            let word = u16::from_le_bytes([block[pair_idx * 2], block[pair_idx * 2 + 1]]);
            let unit = (word as f32 / 65535.0) - 0.5;
            *sample += unit * scale;
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canvas_noise_is_deterministic_and_aperiodic_across_32_pixel_blocks() {
        let mut buf_a = vec![128u8; 256 * 4]; // 256 pixels = 8 blocks of 32 pixels
        let mut buf_b = vec![128u8; 256 * 4];
        apply_deterministic_canvas_noise(&mut buf_a, "https://example.org", "session-seed-99");
        apply_deterministic_canvas_noise(&mut buf_b, "https://example.org", "session-seed-99");
        assert_eq!(buf_a, buf_b);

        // Consecutive 32-pixel (128-byte) blocks MUST NOT repeat periodically
        let block0 = &buf_a[0..128];
        let block1 = &buf_a[128..256];
        let block2 = &buf_a[256..384];
        assert_ne!(block0, block1);
        assert_ne!(block1, block2);
        assert_ne!(block0, block2);

        // Alpha channel (every 4th byte) must remain untouched
        for chunk in buf_a.chunks_exact(4) {
            assert_eq!(chunk[3], 128);
        }
    }

    #[test]
    fn test_audiocontext_noise_is_deterministic_and_aperiodic() {
        let mut bins_a = vec![-60.0f32; 128];
        let mut bins_b = vec![-60.0f32; 128];
        let mut bins_other = vec![-60.0f32; 128];

        apply_audiocontext_frequency_noise(&mut bins_a, "https://example.org", "seed-x", -80.0);
        apply_audiocontext_frequency_noise(&mut bins_b, "https://example.org", "seed-x", -80.0);
        apply_audiocontext_frequency_noise(&mut bins_other, "https://other.org", "seed-x", -80.0);

        assert_eq!(bins_a, bins_b);
        assert_ne!(bins_a, bins_other);
        // Must not repeat with period 32
        assert_ne!(&bins_a[0..32], &bins_a[32..64]);
        assert_ne!(&bins_a[32..64], &bins_a[64..96]);
    }
}
