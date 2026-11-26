//! 10-Band Parametric Biquad Audio Equalizer, 600% Soft-Knee Volume Booster,
//! ITU-R BS.1770-4 / EBU R128 Loudness Normalizer, Dynamic Range Compressor,
//! Built-in Acoustic Presets, and Per-Tab Audio DSP Routing Manager in pure Rust.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::f64::consts::PI;

/// Center frequencies (Hz) for the 10 ISO octave bands in Singularity's audio engine.
pub const ISO_10_BAND_FREQUENCIES_HZ: [f64; 10] = [
    31.25, 62.5, 125.0, 250.0, 500.0, 1000.0, 2000.0, 4000.0, 8000.0, 16000.0,
];

/// Upper bound of the volume boost percentage (`600.0%` = `+15.56 dB`) guarded by the
/// hyperbolic tangent soft-knee brickwall limiter.
pub const MAX_VOLUME_BOOST_PERCENT: f64 = 600.0;

/// Standard EBU R128 / streaming integrated loudness target (`-14.0 LUFS`).
pub const LUFS_TARGET_STREAMING: f64 = -14.0;

/// Standard podcast / mobile spoken-word loudness target (`-16.0 LUFS`).
pub const LUFS_TARGET_PODCAST: f64 = -16.0;

/// ITU-R BS.1770-4 absolute silence gate threshold (`-70.0 LUFS`).
const EBU_R128_ABSOLUTE_GATE_LUFS: f64 = -70.0;

/// Configuration for a single parametric equalizer band.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ParametricBandConfig {
    pub center_freq_hz: f64,
    pub gain_db: f64,
    pub q_factor: f64,
}

/// Six built-in acoustic presets for the 10-band ISO parametric equalizer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub enum EqualizerPreset {
    #[default]
    Flat,
    EventHorizonSubBass,
    HarmanOverEar2018,
    VocalPodcast,
    Cinema,
    Gaming,
}

impl EqualizerPreset {
    /// Returns all 6 built-in presets in UI display order.
    pub const fn all() -> &'static [EqualizerPreset] {
        &[
            Self::Flat,
            Self::EventHorizonSubBass,
            Self::HarmanOverEar2018,
            Self::VocalPodcast,
            Self::Cinema,
            Self::Gaming,
        ]
    }

    /// Human-readable display label for the preset selector UI.
    pub const fn display_name(&self) -> &'static str {
        match self {
            Self::Flat => "Flat (Reference)",
            Self::EventHorizonSubBass => "Event Horizon Sub-Bass",
            Self::HarmanOverEar2018 => "Harman Over-Ear 2018",
            Self::VocalPodcast => "Vocal / Podcast",
            Self::Cinema => "Cinema",
            Self::Gaming => "Gaming",
        }
    }

    /// Returns the 10 ISO band gains in dB (`31.25 Hz` .. `16 kHz`) for this preset.
    pub const fn band_gains_db(&self) -> [f64; 10] {
        match self {
            Self::Flat => [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
            Self::EventHorizonSubBass => [7.5, 6.0, 3.5, 1.0, -1.0, 0.0, 1.0, 2.0, 2.5, 3.0],
            Self::HarmanOverEar2018 => [4.5, 4.0, 2.0, 0.0, -0.5, 0.0, 2.0, 3.5, 1.5, 0.5],
            Self::VocalPodcast => [-4.0, -2.5, -1.0, 0.5, 1.5, 3.0, 4.0, 3.5, 1.0, -1.0],
            Self::Cinema => [5.0, 4.0, 2.0, 0.0, -1.5, 1.5, 2.5, 3.0, 2.5, 2.0],
            Self::Gaming => [1.5, 1.0, -1.0, -0.5, 0.5, 2.0, 4.5, 5.0, 3.5, 2.0],
        }
    }
}

/// Normalized Direct Form II Transposed Biquad Filter state.
#[derive(Debug, Clone, Copy, Default)]
struct BiquadFilter {
    b0: f64,
    b1: f64,
    b2: f64,
    a1: f64,
    a2: f64,
    z1_left: f64,
    z2_left: f64,
    z1_right: f64,
    z2_right: f64,
}

impl BiquadFilter {
    /// Computes peaking EQ biquad coefficients per Robert Bristow-Johnson's Audio EQ Cookbook,
    /// clamping center frequency strictly below Nyquist to guarantee filter stability.
    fn compute_coefficients(
        sample_rate_hz: f64,
        freq_hz: f64,
        gain_db: f64,
        q: f64,
    ) -> (f64, f64, f64, f64, f64) {
        let safe_sr = sanitize_sample_rate(sample_rate_hz);
        let nyquist_cap = (safe_sr * 0.45).max(100.0);
        let safe_freq = if freq_hz.is_finite() {
            freq_hz.clamp(20.0, nyquist_cap)
        } else {
            1000.0
        };
        let safe_gain = if gain_db.is_finite() {
            gain_db.clamp(-24.0, 24.0)
        } else {
            0.0
        };
        let safe_q = if q.is_finite() { q.clamp(0.2, 12.0) } else { 1.414 };

        let a = 10.0_f64.powf(safe_gain / 40.0);
        let omega = 2.0 * PI * (safe_freq / safe_sr);
        let sn = omega.sin();
        let cs = omega.cos();
        let alpha = sn / (2.0 * safe_q);

        let b0 = 1.0 + alpha * a;
        let b1 = -2.0 * cs;
        let b2 = 1.0 - alpha * a;
        let a0 = 1.0 + alpha / a;
        let a1 = -2.0 * cs;
        let a2 = 1.0 - alpha / a;

        (b0 / a0, b1 / a0, b2 / a0, a1 / a0, a2 / a0)
    }

    fn from_peaking_eq(sample_rate_hz: f64, freq_hz: f64, gain_db: f64, q: f64) -> Self {
        let (b0, b1, b2, a1, a2) = Self::compute_coefficients(sample_rate_hz, freq_hz, gain_db, q);
        Self {
            b0,
            b1,
            b2,
            a1,
            a2,
            z1_left: 0.0,
            z2_left: 0.0,
            z1_right: 0.0,
            z2_right: 0.0,
        }
    }

    /// ITU-R BS.1770-4 K-weighting Stage 1 (pre-filter acoustic head high-shelf, ~+4 dB @ 1682 Hz).
    fn k_weighting_stage1(sample_rate_hz: f64) -> Self {
        let sr = sanitize_sample_rate(sample_rate_hz);
        const F0: f64 = 1681.974450955533;
        const G_DB: f64 = 3.999843853973347;
        const Q: f64 = 0.7071752369554196;

        let k = (PI * F0 / sr).tan();
        let vh = 10.0_f64.powf(G_DB / 20.0);
        let vb = vh.powf(0.4996667741545416);
        let a0 = 1.0 + k / Q + k * k;

        Self {
            b0: (vh + vb * k / Q + k * k) / a0,
            b1: 2.0 * (k * k - vh) / a0,
            b2: (vh - vb * k / Q + k * k) / a0,
            a1: 2.0 * (k * k - 1.0) / a0,
            a2: (1.0 - k / Q + k * k) / a0,
            z1_left: 0.0,
            z2_left: 0.0,
            z1_right: 0.0,
            z2_right: 0.0,
        }
    }

    /// ITU-R BS.1770-4 K-weighting Stage 2 (Revised Low-frequency B-curve high-pass @ 38.14 Hz).
    fn k_weighting_stage2(sample_rate_hz: f64) -> Self {
        let sr = sanitize_sample_rate(sample_rate_hz);
        const F0: f64 = 38.13547087602444;
        const Q: f64 = 0.5003270373238773;

        let k = (PI * F0 / sr).tan();
        let a0 = 1.0 + k / Q + k * k;

        Self {
            b0: 1.0,
            b1: -2.0,
            b2: 1.0,
            a1: 2.0 * (k * k - 1.0) / a0,
            a2: (1.0 - k / Q + k * k) / a0,
            z1_left: 0.0,
            z2_left: 0.0,
            z1_right: 0.0,
            z2_right: 0.0,
        }
    }

    /// Updates biquad coefficients in-place while preserving delay registers to avoid clicks/pops.
    fn update_peaking_eq(&mut self, sample_rate_hz: f64, freq_hz: f64, gain_db: f64, q: f64) {
        let (b0, b1, b2, a1, a2) = Self::compute_coefficients(sample_rate_hz, freq_hz, gain_db, q);
        self.b0 = b0;
        self.b1 = b1;
        self.b2 = b2;
        self.a1 = a1;
        self.a2 = a2;
    }

    fn reset(&mut self) {
        self.z1_left = 0.0;
        self.z2_left = 0.0;
        self.z1_right = 0.0;
        self.z2_right = 0.0;
    }

    #[inline]
    fn process_stereo_frame(&mut self, left: f64, right: f64) -> (f64, f64) {
        // Sanitize non-finite inputs and protect delay state against NaN/±Inf propagation
        let safe_l = if left.is_finite() { left } else { 0.0 };
        let safe_r = if right.is_finite() { right } else { 0.0 };

        if !self.z1_left.is_finite() || !self.z2_left.is_finite() {
            self.z1_left = 0.0;
            self.z2_left = 0.0;
        }
        if !self.z1_right.is_finite() || !self.z2_right.is_finite() {
            self.z1_right = 0.0;
            self.z2_right = 0.0;
        }

        let mut out_l = self.b0 * safe_l + self.z1_left;
        let next_z1_l = self.b1 * safe_l - self.a1 * out_l + self.z2_left;
        let next_z2_l = self.b2 * safe_l - self.a2 * out_l;
        if out_l.is_finite() && next_z1_l.is_finite() && next_z2_l.is_finite() {
            self.z1_left = flush_denormal(next_z1_l);
            self.z2_left = flush_denormal(next_z2_l);
        } else {
            self.z1_left = 0.0;
            self.z2_left = 0.0;
            out_l = 0.0;
        }

        let mut out_r = self.b0 * safe_r + self.z1_right;
        let next_z1_r = self.b1 * safe_r - self.a1 * out_r + self.z2_right;
        let next_z2_r = self.b2 * safe_r - self.a2 * out_r;
        if out_r.is_finite() && next_z1_r.is_finite() && next_z2_r.is_finite() {
            self.z1_right = flush_denormal(next_z1_r);
            self.z2_right = flush_denormal(next_z2_r);
        } else {
            self.z1_right = 0.0;
            self.z2_right = 0.0;
            out_r = 0.0;
        }

        (out_l, out_r)
    }
}

#[inline]
fn sanitize_sample_rate(sample_rate_hz: f64) -> f64 {
    if sample_rate_hz.is_finite() {
        sample_rate_hz.clamp(8000.0, 384000.0)
    } else {
        48000.0
    }
}

#[inline]
fn flush_denormal(v: f64) -> f64 {
    if v.abs() < 1e-30 {
        0.0
    } else {
        v
    }
}

/// Hyperbolic tangent soft-knee brickwall limiter guaranteeing output strictly within `[-1.0, 1.0]`,
/// remaining transparent below `0.90` amplitude and smoothly saturating peaks up to `600%` (`+15.6 dB`) boost.
#[inline]
pub fn soft_clip_sample(x: f64) -> f64 {
    if !x.is_finite() {
        return 0.0;
    }
    let clipped = if x.abs() <= 0.90 {
        x
    } else {
        x.signum() * (0.90 + 0.10 * ((x.abs() - 0.90) * 10.0).tanh())
    };
    clipped.clamp(-1.0, 1.0)
}

/// 10-Band Parametric Equalizer and 0%–600% (`+15.6 dB`) Volume Boost DSP Processor.
#[derive(Debug, Clone)]
pub struct TenBandParametricEqualizer {
    sample_rate_hz: f64,
    bands: [ParametricBandConfig; 10],
    filters: [BiquadFilter; 10],
    volume_boost_percent: f64,
    enabled: bool,
}

impl Default for TenBandParametricEqualizer {
    fn default() -> Self {
        Self::new(48000.0)
    }
}

impl TenBandParametricEqualizer {
    pub fn new(sample_rate_hz: f64) -> Self {
        let safe_sr = sanitize_sample_rate(sample_rate_hz);
        let mut bands = [ParametricBandConfig {
            center_freq_hz: 1000.0,
            gain_db: 0.0,
            q_factor: 1.414,
        }; 10];
        let mut filters = [BiquadFilter::default(); 10];

        for (i, &freq) in ISO_10_BAND_FREQUENCIES_HZ.iter().enumerate() {
            bands[i].center_freq_hz = freq;
            filters[i] = BiquadFilter::from_peaking_eq(safe_sr, freq, 0.0, 1.414);
        }

        Self {
            sample_rate_hz: safe_sr,
            bands,
            filters,
            volume_boost_percent: 100.0,
            enabled: true,
        }
    }

    /// Clears all internal biquad delay registers (e.g. on track seek or stream switch).
    pub fn reset(&mut self) {
        for filter in &mut self.filters {
            filter.reset();
        }
    }

    /// Enables or bypasses the 10-band biquad EQ stage (volume boost & soft limiter remain active).
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Applies one of the 6 built-in acoustic [`EqualizerPreset`] curves smoothly in-place.
    pub fn apply_preset(&mut self, preset: EqualizerPreset) {
        let gains = preset.band_gains_db();
        for (idx, &gain_db) in gains.iter().enumerate() {
            self.set_band_gain_db(idx, gain_db, 1.414);
        }
    }

    /// Dynamically updates the DSP sample rate (Hz) and recalculates all 10 biquad filter
    /// coefficients for the new Nyquist frequency.
    pub fn set_sample_rate(&mut self, sample_rate_hz: u32) {
        let safe_sr = (sample_rate_hz as f64).clamp(8000.0, 384000.0);
        if (self.sample_rate_hz - safe_sr).abs() < f64::EPSILON {
            return;
        }
        self.sample_rate_hz = safe_sr;
        for (i, filter) in self.filters.iter_mut().enumerate() {
            let band = self.bands[i];
            filter.update_peaking_eq(safe_sr, band.center_freq_hz, band.gain_db, band.q_factor);
            filter.reset();
        }
    }

    pub fn sample_rate_hz(&self) -> f64 {
        self.sample_rate_hz
    }

    /// Updates the gain (-24.0 dB to +24.0 dB) and Q-factor of one of the 10 bands (0..10).
    pub fn set_band_gain_db(&mut self, band_index: usize, gain_db: f64, q_factor: f64) {
        if band_index < 10 && gain_db.is_finite() && q_factor.is_finite() {
            let clamped_gain = gain_db.clamp(-24.0, 24.0);
            let clamped_q = q_factor.clamp(0.2, 12.0);
            self.bands[band_index].gain_db = clamped_gain;
            self.bands[band_index].q_factor = clamped_q;
            self.filters[band_index].update_peaking_eq(
                self.sample_rate_hz,
                self.bands[band_index].center_freq_hz,
                clamped_gain,
                clamped_q,
            );
        }
    }

    /// Sets the volume boost percentage (`0.0%` to `600.0%`, up to `+15.56 dB`).
    pub fn set_volume_boost_percent(&mut self, percent: f64) {
        if percent.is_finite() {
            self.volume_boost_percent = percent.clamp(0.0, MAX_VOLUME_BOOST_PERCENT);
        }
    }

    pub fn volume_boost_percent(&self) -> f64 {
        self.volume_boost_percent
    }

    /// Returns the equivalent volume boost gain in decibels (`-inf` at `0%`, `+15.56 dB` at `600%`).
    pub fn volume_boost_db(&self) -> f64 {
        if self.volume_boost_percent <= 0.0 {
            f64::NEG_INFINITY
        } else {
            20.0 * (self.volume_boost_percent / 100.0).log10()
        }
    }

    pub fn bands(&self) -> &[ParametricBandConfig; 10] {
        &self.bands
    }

    /// Processes an interleaved stereo float32 PCM buffer through all 10 biquad bands
    /// and applies the 0%–600% volume booster with a soft-knee hyperbolic tangent limiter.
    /// Sanitizes any non-finite (`NaN`/`±Inf`) input samples to `0.0` so filter state is never poisoned.
    pub fn process_interleaved_stereo_pcm(&mut self, pcm_stereo: &mut [f32]) {
        let linear_gain = self.volume_boost_percent / 100.0;

        for frame in pcm_stereo.as_chunks_mut::<2>().0 {
            let mut l = if frame[0].is_finite() {
                frame[0] as f64
            } else {
                0.0
            };
            let mut r = if frame[1].is_finite() {
                frame[1] as f64
            } else {
                0.0
            };

            if self.enabled {
                for filter in &mut self.filters {
                    let (nl, nr) = filter.process_stereo_frame(l, r);
                    l = nl;
                    r = nr;
                }
            }

            l *= linear_gain;
            r *= linear_gain;

            // Soft-knee saturation limiter above 0.90 amplitude to prevent harsh digital clipping up to 600% boost
            frame[0] = soft_clip_sample(l) as f32;
            frame[1] = soft_clip_sample(r) as f32;
        }

        // Sanitize trailing odd sample if buffer length is not a multiple of 2
        if pcm_stereo.len() % 2 == 1 {
            if let Some(last) = pcm_stereo.last_mut() {
                let s = if last.is_finite() {
                    (*last as f64) * linear_gain
                } else {
                    0.0
                };
                *last = soft_clip_sample(s) as f32;
            }
        }
    }
}

// ============================================================================
// ITU-R BS.1770-4 / EBU R128 Sliding-Window Loudness Normalizer
// ============================================================================

/// Real-time ITU-R BS.1770-4 / EBU R128 Loudness Normalizer with 2-stage K-weighting,
/// 400 ms sliding momentary loudness window, `-70 LUFS` silence gate, and smoothed
/// attack/release makeup gain targeting `-14.0 LUFS` (streaming) or `-16.0 LUFS` (podcasts).
#[derive(Debug, Clone)]
pub struct LoudnessNormalizer {
    sample_rate_hz: f64,
    enabled: bool,
    target_lufs: f64,
    max_gain_db: f64,
    min_gain_db: f64,
    attack_ms: f64,
    release_ms: f64,
    stage1_pre: BiquadFilter,
    stage2_rlb: BiquadFilter,
    energy_window: Vec<f64>,
    window_pos: usize,
    filled_frames: usize,
    running_energy_sum: f64,
    current_loudness_lufs: f64,
    current_gain_db: f64,
}

impl Default for LoudnessNormalizer {
    fn default() -> Self {
        Self::new(48000.0, LUFS_TARGET_STREAMING)
    }
}

impl LoudnessNormalizer {
    /// Creates a new EBU R128 loudness normalizer with a 400 ms sliding window.
    pub fn new(sample_rate_hz: f64, target_lufs: f64) -> Self {
        let safe_sr = sanitize_sample_rate(sample_rate_hz);
        let safe_target = if target_lufs.is_finite() {
            target_lufs.clamp(-36.0, -5.0)
        } else {
            LUFS_TARGET_STREAMING
        };
        let window_frames = ((safe_sr * 0.400).round() as usize).max(1);

        Self {
            sample_rate_hz: safe_sr,
            enabled: true,
            target_lufs: safe_target,
            max_gain_db: 18.0,
            min_gain_db: -24.0,
            attack_ms: 40.0,
            release_ms: 250.0,
            stage1_pre: BiquadFilter::k_weighting_stage1(safe_sr),
            stage2_rlb: BiquadFilter::k_weighting_stage2(safe_sr),
            energy_window: vec![0.0; window_frames],
            window_pos: 0,
            filled_frames: 0,
            running_energy_sum: 0.0,
            current_loudness_lufs: -120.0,
            current_gain_db: 0.0,
        }
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Sets the target loudness in LUFS (e.g. `-14.0` for streaming or `-16.0` for podcasts).
    pub fn set_target_lufs(&mut self, target_lufs: f64) {
        if target_lufs.is_finite() {
            self.target_lufs = target_lufs.clamp(-36.0, -5.0);
        }
    }

    pub fn target_lufs(&self) -> f64 {
        self.target_lufs
    }

    /// Limits maximum positive makeup gain (dB) applied to quiet passages.
    pub fn set_max_gain_db(&mut self, max_gain_db: f64) {
        if max_gain_db.is_finite() {
            self.max_gain_db = max_gain_db.clamp(0.0, 24.0);
        }
    }

    pub fn max_gain_db(&self) -> f64 {
        self.max_gain_db
    }

    /// Updates sample rate, recomputes K-weighting biquads, and resizes the 400 ms sliding window.
    pub fn set_sample_rate(&mut self, sample_rate_hz: u32) {
        let safe_sr = sanitize_sample_rate(sample_rate_hz as f64);
        if (self.sample_rate_hz - safe_sr).abs() < f64::EPSILON {
            return;
        }
        self.sample_rate_hz = safe_sr;
        self.stage1_pre = BiquadFilter::k_weighting_stage1(safe_sr);
        self.stage2_rlb = BiquadFilter::k_weighting_stage2(safe_sr);
        let window_frames = ((safe_sr * 0.400).round() as usize).max(1);
        self.energy_window = vec![0.0; window_frames];
        self.reset();
    }

    pub fn sample_rate_hz(&self) -> f64 {
        self.sample_rate_hz
    }

    /// Clears K-weighting delay registers, sliding energy window, and smoothed gain state.
    pub fn reset(&mut self) {
        self.stage1_pre.reset();
        self.stage2_rlb.reset();
        self.energy_window.fill(0.0);
        self.window_pos = 0;
        self.filled_frames = 0;
        self.running_energy_sum = 0.0;
        self.current_loudness_lufs = -120.0;
        self.current_gain_db = 0.0;
    }

    /// Most recently measured K-weighted momentary loudness in LUFS.
    pub fn current_loudness_lufs(&self) -> f64 {
        self.current_loudness_lufs
    }

    /// Currently active smoothed makeup gain in decibels.
    pub fn current_gain_db(&self) -> f64 {
        self.current_gain_db
    }

    /// Measures K-weighted momentary loudness over a stereo buffer and applies smoothed
    /// EBU R128 normalization gain in-place when enabled.
    pub fn process_interleaved_stereo_pcm(&mut self, pcm_stereo: &mut [f32]) {
        if !self.enabled {
            return;
        }

        let attack_coeff = (-1.0 / ((self.attack_ms / 1000.0) * self.sample_rate_hz)).exp();
        let release_coeff = (-1.0 / ((self.release_ms / 1000.0) * self.sample_rate_hz)).exp();
        let window_len = self.energy_window.len().max(1);

        for frame in pcm_stereo.as_chunks_mut::<2>().0 {
            let l = if frame[0].is_finite() {
                frame[0] as f64
            } else {
                0.0
            };
            let r = if frame[1].is_finite() {
                frame[1] as f64
            } else {
                0.0
            };

            // 1. ITU-R BS.1770-4 2-stage K-weighting
            let (s1_l, s1_r) = self.stage1_pre.process_stereo_frame(l, r);
            let (kw_l, kw_r) = self.stage2_rlb.process_stereo_frame(s1_l, s1_r);
            let frame_energy = kw_l * kw_l + kw_r * kw_r;

            // 2. Sliding 400 ms mean-square energy window with periodic exact resummation
            let evicted = self.energy_window[self.window_pos];
            self.energy_window[self.window_pos] = frame_energy;
            self.window_pos += 1;
            if self.filled_frames < window_len {
                self.filled_frames += 1;
            }
            if self.window_pos >= window_len {
                self.window_pos = 0;
                self.running_energy_sum = self.energy_window.iter().sum::<f64>().max(0.0);
            } else {
                self.running_energy_sum =
                    (self.running_energy_sum - evicted + frame_energy).max(0.0);
            }

            let mean_square = self.running_energy_sum / (self.filled_frames as f64);
            let measured_lufs = if mean_square > 1e-12 {
                -0.691 + 10.0 * mean_square.log10()
            } else {
                -120.0
            };
            self.current_loudness_lufs = measured_lufs;

            // 3. Absolute silence gate (-70 LUFS) + smoothed makeup gain
            let target_gain_db = if measured_lufs <= EBU_R128_ABSOLUTE_GATE_LUFS {
                0.0
            } else {
                (self.target_lufs - measured_lufs).clamp(self.min_gain_db, self.max_gain_db)
            };

            let coeff = if target_gain_db < self.current_gain_db {
                attack_coeff
            } else {
                release_coeff
            };
            self.current_gain_db =
                coeff * self.current_gain_db + (1.0 - coeff) * target_gain_db;

            let linear_gain = 10.0_f64.powf(self.current_gain_db / 20.0);
            frame[0] = soft_clip_sample(l * linear_gain) as f32;
            frame[1] = soft_clip_sample(r * linear_gain) as f32;
        }
    }
}

// ============================================================================
// Dynamic Range Compressor (Night Mode / Vocal Clarity)
// ============================================================================

/// Serializable configuration for the [`DynamicRangeCompressor`].
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct CompressorConfig {
    pub enabled: bool,
    /// Compression threshold in dBFS (`-60.0..=0.0`).
    pub threshold_db: f64,
    /// Compression ratio (`1.0..=20.0`, e.g., `4.0` = 4:1).
    pub ratio: f64,
    /// Attack time constant in milliseconds (`0.5..=200.0`).
    pub attack_ms: f64,
    /// Release time constant in milliseconds (`10.0..=2000.0`).
    pub release_ms: f64,
    /// Post-compression makeup gain in dB (`-12.0..=24.0`).
    pub makeup_gain_db: f64,
    /// Soft-knee transition width in dB (`0.0..=24.0`).
    pub knee_db: f64,
}

impl Default for CompressorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            threshold_db: -18.0,
            ratio: 4.0,
            attack_ms: 10.0,
            release_ms: 150.0,
            makeup_gain_db: 3.0,
            knee_db: 6.0,
        }
    }
}

impl CompressorConfig {
    /// Night Mode preset: tames loud explosions while lifting whispers for late-night listening.
    pub fn night_mode() -> Self {
        Self {
            enabled: true,
            threshold_db: -24.0,
            ratio: 6.0,
            attack_ms: 5.0,
            release_ms: 180.0,
            makeup_gain_db: 6.0,
            knee_db: 6.0,
        }
    }

    /// Vocal Clarity preset: gentle compression keeping speech intelligible above music/SFX.
    pub fn vocal_clarity() -> Self {
        Self {
            enabled: true,
            threshold_db: -20.0,
            ratio: 3.5,
            attack_ms: 8.0,
            release_ms: 120.0,
            makeup_gain_db: 3.5,
            knee_db: 4.0,
        }
    }

    /// Clamps all numeric fields to safe DSP ranges, replacing non-finite values with defaults.
    pub fn sanitized(self) -> Self {
        let def = Self::default();
        Self {
            enabled: self.enabled,
            threshold_db: if self.threshold_db.is_finite() {
                self.threshold_db.clamp(-60.0, 0.0)
            } else {
                def.threshold_db
            },
            ratio: if self.ratio.is_finite() {
                self.ratio.clamp(1.0, 20.0)
            } else {
                def.ratio
            },
            attack_ms: if self.attack_ms.is_finite() {
                self.attack_ms.clamp(0.5, 200.0)
            } else {
                def.attack_ms
            },
            release_ms: if self.release_ms.is_finite() {
                self.release_ms.clamp(10.0, 2000.0)
            } else {
                def.release_ms
            },
            makeup_gain_db: if self.makeup_gain_db.is_finite() {
                self.makeup_gain_db.clamp(-12.0, 24.0)
            } else {
                def.makeup_gain_db
            },
            knee_db: if self.knee_db.is_finite() {
                self.knee_db.clamp(0.0, 24.0)
            } else {
                def.knee_db
            },
        }
    }
}

/// Stereo-linked feed-forward Dynamic Range Compressor (Night Mode & Vocal Clarity).
#[derive(Debug, Clone)]
pub struct DynamicRangeCompressor {
    sample_rate_hz: f64,
    config: CompressorConfig,
    smoothed_gain_reduction_db: f64,
}

impl Default for DynamicRangeCompressor {
    fn default() -> Self {
        Self::new(48000.0)
    }
}

impl DynamicRangeCompressor {
    pub fn new(sample_rate_hz: f64) -> Self {
        Self::with_config(sample_rate_hz, CompressorConfig::default())
    }

    pub fn with_config(sample_rate_hz: f64, config: CompressorConfig) -> Self {
        Self {
            sample_rate_hz: sanitize_sample_rate(sample_rate_hz),
            config: config.sanitized(),
            smoothed_gain_reduction_db: 0.0,
        }
    }

    /// Creates a pre-configured Night Mode compressor.
    pub fn night_mode(sample_rate_hz: f64) -> Self {
        Self::with_config(sample_rate_hz, CompressorConfig::night_mode())
    }

    /// Creates a pre-configured Vocal Clarity compressor.
    pub fn vocal_clarity(sample_rate_hz: f64) -> Self {
        Self::with_config(sample_rate_hz, CompressorConfig::vocal_clarity())
    }

    pub fn config(&self) -> CompressorConfig {
        self.config
    }

    pub fn apply_config(&mut self, config: CompressorConfig) {
        self.config = config.sanitized();
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.config.enabled = enabled;
    }

    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    pub fn set_threshold_db(&mut self, threshold_db: f64) {
        if threshold_db.is_finite() {
            self.config.threshold_db = threshold_db.clamp(-60.0, 0.0);
        }
    }

    pub fn set_ratio(&mut self, ratio: f64) {
        if ratio.is_finite() {
            self.config.ratio = ratio.clamp(1.0, 20.0);
        }
    }

    pub fn set_attack_ms(&mut self, attack_ms: f64) {
        if attack_ms.is_finite() {
            self.config.attack_ms = attack_ms.clamp(0.5, 200.0);
        }
    }

    pub fn set_release_ms(&mut self, release_ms: f64) {
        if release_ms.is_finite() {
            self.config.release_ms = release_ms.clamp(10.0, 2000.0);
        }
    }

    pub fn set_makeup_gain_db(&mut self, makeup_gain_db: f64) {
        if makeup_gain_db.is_finite() {
            self.config.makeup_gain_db = makeup_gain_db.clamp(-12.0, 24.0);
        }
    }

    pub fn set_sample_rate(&mut self, sample_rate_hz: u32) {
        self.sample_rate_hz = sanitize_sample_rate(sample_rate_hz as f64);
    }

    pub fn sample_rate_hz(&self) -> f64 {
        self.sample_rate_hz
    }

    /// Returns the instantaneous smoothed gain reduction in dB (`<= 0.0`, e.g. `-8.5 dB`).
    pub fn last_gain_reduction_db(&self) -> f64 {
        self.smoothed_gain_reduction_db
    }

    pub fn reset(&mut self) {
        self.smoothed_gain_reduction_db = 0.0;
    }

    /// Processes interleaved stereo float32 PCM through the stereo-linked soft-knee compressor.
    pub fn process_interleaved_stereo_pcm(&mut self, pcm_stereo: &mut [f32]) {
        if !self.config.enabled {
            return;
        }

        let attack_coeff = (-1.0 / ((self.config.attack_ms / 1000.0) * self.sample_rate_hz)).exp();
        let release_coeff =
            (-1.0 / ((self.config.release_ms / 1000.0) * self.sample_rate_hz)).exp();
        let threshold = self.config.threshold_db;
        let ratio = self.config.ratio;
        let knee = self.config.knee_db;
        let half_knee = knee * 0.5;
        let makeup = self.config.makeup_gain_db;

        for frame in pcm_stereo.as_chunks_mut::<2>().0 {
            let l = if frame[0].is_finite() {
                frame[0] as f64
            } else {
                0.0
            };
            let r = if frame[1].is_finite() {
                frame[1] as f64
            } else {
                0.0
            };

            let peak = l.abs().max(r.abs());
            let level_db = if peak > 1e-9 {
                20.0 * peak.log10()
            } else {
                -180.0
            };

            // Static soft-knee gain reduction curve (<= 0.0 dB)
            let overshoot = level_db - threshold;
            let target_gr_db = if knee > 0.0 && overshoot > -half_knee && overshoot < half_knee {
                let x = overshoot + half_knee;
                ((1.0 / ratio) - 1.0) * (x * x) / (2.0 * knee)
            } else if overshoot >= half_knee {
                overshoot * ((1.0 / ratio) - 1.0)
            } else {
                0.0
            };

            // Smooth gain reduction: attack when compressing deeper, release when recovering
            let coeff = if target_gr_db < self.smoothed_gain_reduction_db {
                attack_coeff
            } else {
                release_coeff
            };
            self.smoothed_gain_reduction_db =
                coeff * self.smoothed_gain_reduction_db + (1.0 - coeff) * target_gr_db;

            let total_gain_db = self.smoothed_gain_reduction_db + makeup;
            let linear_gain = 10.0_f64.powf(total_gain_db / 20.0);

            frame[0] = soft_clip_sample(l * linear_gain) as f32;
            frame[1] = soft_clip_sample(r * linear_gain) as f32;
        }
    }
}

// ============================================================================
// Per-Tab & Global Audio DSP Profile Manager
// ============================================================================

/// Complete audio DSP processing chain for either the global default or an individual browser tab.
#[derive(Debug, Clone)]
pub struct TabAudioDspProfile {
    pub equalizer: TenBandParametricEqualizer,
    pub loudness_normalizer: LoudnessNormalizer,
    pub compressor: DynamicRangeCompressor,
    pub active_preset: EqualizerPreset,
    /// Optional per-tab audio output sink identifier (e.g. headphones vs speakers).
    pub output_device_id: Option<String>,
    pub muted: bool,
}

impl Default for TabAudioDspProfile {
    fn default() -> Self {
        Self::new(48000.0)
    }
}

impl TabAudioDspProfile {
    pub fn new(sample_rate_hz: f64) -> Self {
        let mut loudness = LoudnessNormalizer::new(sample_rate_hz, LUFS_TARGET_STREAMING);
        loudness.set_enabled(false);
        Self {
            equalizer: TenBandParametricEqualizer::new(sample_rate_hz),
            loudness_normalizer: loudness,
            compressor: DynamicRangeCompressor::new(sample_rate_hz),
            active_preset: EqualizerPreset::Flat,
            output_device_id: None,
            muted: false,
        }
    }

    pub fn apply_preset(&mut self, preset: EqualizerPreset) {
        self.active_preset = preset;
        self.equalizer.apply_preset(preset);
    }

    pub fn set_sample_rate(&mut self, sample_rate_hz: u32) {
        self.equalizer.set_sample_rate(sample_rate_hz);
        self.loudness_normalizer.set_sample_rate(sample_rate_hz);
        self.compressor.set_sample_rate(sample_rate_hz);
    }

    pub fn reset(&mut self) {
        self.equalizer.reset();
        self.loudness_normalizer.reset();
        self.compressor.reset();
    }

    /// Runs the full DSP chain: EBU R128 normalization -> Dynamic Range Compressor ->
    /// 10-band Parametric EQ + 0%–600% Volume Boost + Final Soft-Knee Limiter.
    pub fn process_interleaved_stereo_pcm(&mut self, pcm_stereo: &mut [f32]) {
        if self.muted {
            pcm_stereo.fill(0.0);
            return;
        }
        self.loudness_normalizer
            .process_interleaved_stereo_pcm(pcm_stereo);
        self.compressor.process_interleaved_stereo_pcm(pcm_stereo);
        self.equalizer.process_interleaved_stereo_pcm(pcm_stereo);
    }
}

/// Manages global and per-tab (`tab_id`) audio EQ, volume boost (0–600%), loudness normalization,
/// dynamic range compression, and audio output device routing.
#[derive(Debug, Clone)]
pub struct PerTabAudioDspManager {
    sample_rate_hz: f64,
    global_profile: TabAudioDspProfile,
    tab_profiles: HashMap<u64, TabAudioDspProfile>,
}

impl Default for PerTabAudioDspManager {
    fn default() -> Self {
        Self::new(48000.0)
    }
}

impl PerTabAudioDspManager {
    pub fn new(sample_rate_hz: f64) -> Self {
        let safe_sr = sanitize_sample_rate(sample_rate_hz);
        Self {
            sample_rate_hz: safe_sr,
            global_profile: TabAudioDspProfile::new(safe_sr),
            tab_profiles: HashMap::new(),
        }
    }

    pub fn global(&self) -> &TabAudioDspProfile {
        &self.global_profile
    }

    pub fn global_mut(&mut self) -> &mut TabAudioDspProfile {
        &mut self.global_profile
    }

    /// Returns an existing per-tab profile or clones the global profile as the tab's initial baseline.
    pub fn get_or_create_tab(&mut self, tab_id: u64) -> &mut TabAudioDspProfile {
        self.tab_profiles.entry(tab_id).or_insert_with(|| {
            let mut cloned = self.global_profile.clone();
            cloned.reset();
            cloned
        })
    }

    pub fn get_tab(&self, tab_id: u64) -> Option<&TabAudioDspProfile> {
        self.tab_profiles.get(&tab_id)
    }

    pub fn remove_tab(&mut self, tab_id: u64) -> Option<TabAudioDspProfile> {
        self.tab_profiles.remove(&tab_id)
    }

    pub fn set_tab_preset(&mut self, tab_id: u64, preset: EqualizerPreset) {
        self.get_or_create_tab(tab_id).apply_preset(preset);
    }

    pub fn set_tab_volume_boost(&mut self, tab_id: u64, boost_percent: f64) {
        self.get_or_create_tab(tab_id)
            .equalizer
            .set_volume_boost_percent(boost_percent);
    }

    pub fn set_tab_loudness_normalization(
        &mut self,
        tab_id: u64,
        enabled: bool,
        target_lufs: f64,
    ) {
        let tab = self.get_or_create_tab(tab_id);
        tab.loudness_normalizer.set_enabled(enabled);
        tab.loudness_normalizer.set_target_lufs(target_lufs);
    }

    pub fn set_tab_compressor(&mut self, tab_id: u64, config: CompressorConfig) {
        self.get_or_create_tab(tab_id)
            .compressor
            .apply_config(config);
    }

    pub fn set_tab_output_device(&mut self, tab_id: u64, output_device_id: Option<String>) {
        self.get_or_create_tab(tab_id).output_device_id = output_device_id;
    }

    /// Resolves the effective audio output device for `tab_id`, falling back to the global device.
    pub fn effective_output_device(&self, tab_id: u64) -> Option<&str> {
        self.tab_profiles
            .get(&tab_id)
            .and_then(|p| p.output_device_id.as_deref())
            .or(self.global_profile.output_device_id.as_deref())
    }

    /// Processes stereo PCM for `tab_id` using its dedicated override profile if registered,
    /// or the global profile otherwise.
    pub fn process_tab_pcm(&mut self, tab_id: u64, pcm_stereo: &mut [f32]) {
        if let Some(profile) = self.tab_profiles.get_mut(&tab_id) {
            profile.process_interleaved_stereo_pcm(pcm_stereo);
        } else {
            self.global_profile
                .process_interleaved_stereo_pcm(pcm_stereo);
        }
    }

    pub fn active_tab_ids(&self) -> Vec<u64> {
        let mut ids: Vec<u64> = self.tab_profiles.keys().copied().collect();
        ids.sort_unstable();
        ids
    }

    pub fn sample_rate_hz(&self) -> f64 {
        self.sample_rate_hz
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nan_and_inf_sanitization_never_poisons_biquad_state() {
        let mut eq = TenBandParametricEqualizer::default();
        assert_eq!(eq.sample_rate_hz(), 48000.0);
        eq.set_band_gain_db(5, 12.0, 2.0);
        eq.set_volume_boost_percent(200.0);

        // Inject NaN, +Inf, -Inf followed by normal audio frames
        let mut buf = vec![
            f32::NAN,
            f32::INFINITY,
            f32::NEG_INFINITY,
            f32::NAN,
            0.25,
            -0.25,
            0.30,
            -0.30,
        ];
        eq.process_interleaved_stereo_pcm(&mut buf);

        for (i, &s) in buf.iter().enumerate() {
            assert!(s.is_finite(), "Sample {} became non-finite: {}", i, s);
            assert!((-1.0..=1.0).contains(&s), "Sample {} out of range: {}", i, s);
        }
        // Subsequent valid frames must produce real non-zero audio (state not poisoned)
        assert!(buf[4].abs() > 0.1);
        assert!(buf[5].abs() > 0.1);
    }

    #[test]
    fn test_dynamic_sample_rate_recalculates_coefficients_and_reset_and_bypass() {
        let mut eq = TenBandParametricEqualizer::default();
        eq.set_band_gain_db(5, 9.0, 1.5);
        let b0_48k = eq.filters[5].b0;

        // Switching sample rate dynamically recalculates biquad coefficients
        eq.set_sample_rate(44100);
        assert_eq!(eq.sample_rate_hz(), 44100.0);
        assert_ne!(eq.filters[5].b0, b0_48k);

        // Process audio so delay state is non-zero, then reset() clears state cleanly
        let mut frames = vec![0.5f32, -0.5f32, 0.25f32, -0.25f32];
        eq.process_interleaved_stereo_pcm(&mut frames);
        eq.reset();
        for f in &eq.filters {
            assert_eq!(f.z1_left, 0.0);
            assert_eq!(f.z2_left, 0.0);
            assert_eq!(f.z1_right, 0.0);
            assert_eq!(f.z2_right, 0.0);
        }

        // Bypass mode passes unity-gain samples unmodified (when volume boost = 100%)
        eq.set_enabled(false);
        assert!(!eq.is_enabled());
        let mut bypass_buf = vec![0.4f32, -0.3f32];
        eq.process_interleaved_stereo_pcm(&mut bypass_buf);
        assert!((bypass_buf[0] - 0.4).abs() < 1e-6);
        assert!((bypass_buf[1] + 0.3).abs() < 1e-6);
    }

    #[test]
    fn test_600_percent_volume_boost_and_presets() {
        let mut eq = TenBandParametricEqualizer::new(48000.0);
        eq.set_volume_boost_percent(999.0);
        assert_eq!(eq.volume_boost_percent(), 600.0);
        assert!((eq.volume_boost_db() - 15.563).abs() < 0.05);

        eq.apply_preset(EqualizerPreset::EventHorizonSubBass);
        assert_eq!(eq.bands()[0].gain_db, 7.5);
        assert_eq!(EqualizerPreset::all().len(), 6);

        // Extreme full-scale input at 600% boost + heavy sub-bass boost must remain strictly within [-1, 1]
        let mut hot = vec![0.95f32, -0.95f32, 1.0f32, -1.0f32, 0.85f32, -0.85f32];
        eq.process_interleaved_stereo_pcm(&mut hot);
        for &s in &hot {
            assert!(s.is_finite() && (-1.0..=1.0).contains(&s));
        }
    }

    #[test]
    fn test_ebu_r128_loudness_normalizer_converges_quiet_and_loud() {
        let sr = 48000.0;
        // Generate 1.2s stereo 1 kHz sine at -28 dBFS peak (~0.04 amplitude)
        let n_frames = (sr * 1.2) as usize;
        let mut quiet_buf = Vec::with_capacity(n_frames * 2);
        for i in 0..n_frames {
            let s = (0.04 * (2.0 * PI * 1000.0 * (i as f64) / sr).sin()) as f32;
            quiet_buf.push(s);
            quiet_buf.push(s);
        }

        let mut norm = LoudnessNormalizer::new(sr, LUFS_TARGET_STREAMING);
        norm.process_interleaved_stereo_pcm(&mut quiet_buf);
        // Should have measured roughly -28 LUFS and applied positive makeup gain
        assert!(
            norm.current_loudness_lufs() > -31.0 && norm.current_loudness_lufs() < -25.0,
            "Unexpected measured LUFS: {}",
            norm.current_loudness_lufs()
        );
        assert!(
            norm.current_gain_db() > 10.0,
            "Expected positive makeup gain, got {} dB",
            norm.current_gain_db()
        );
        for &s in &quiet_buf {
            assert!(s.is_finite() && (-1.0..=1.0).contains(&s));
        }

        // Loud signal near 0 dBFS should be attenuated down toward -16 LUFS
        let mut loud_buf = Vec::with_capacity(n_frames * 2);
        for i in 0..n_frames {
            let s = (0.90 * (2.0 * PI * 1000.0 * (i as f64) / sr).sin()) as f32;
            loud_buf.push(s);
            loud_buf.push(s);
        }
        let mut norm_podcast = LoudnessNormalizer::new(sr, LUFS_TARGET_PODCAST);
        norm_podcast.process_interleaved_stereo_pcm(&mut loud_buf);
        assert!(
            norm_podcast.current_gain_db() < -10.0,
            "Expected attenuation for loud signal, got {} dB",
            norm_podcast.current_gain_db()
        );
    }

    #[test]
    fn test_dynamic_range_compressor_reduces_peaks() {
        let sr = 48000.0;
        let mut comp = DynamicRangeCompressor::night_mode(sr);
        comp.set_makeup_gain_db(0.0); // isolate pure gain reduction

        let n_frames = (sr * 0.1) as usize;
        let mut loud = Vec::with_capacity(n_frames * 2);
        for i in 0..n_frames {
            let s = (0.9 * (2.0 * PI * 440.0 * (i as f64) / sr).sin()) as f32;
            loud.push(s);
            loud.push(s);
        }
        comp.process_interleaved_stereo_pcm(&mut loud);
        assert!(
            comp.last_gain_reduction_db() < -10.0,
            "Expected heavy night-mode gain reduction, got {} dB",
            comp.last_gain_reduction_db()
        );
        // Steady-state tail peak should be substantially reduced below 0.9
        let tail_peak = loud[loud.len() - 2000..]
            .iter()
            .fold(0.0f32, |acc, &x| acc.max(x.abs()));
        assert!(tail_peak < 0.35, "Expected compressed tail peak < 0.35, got {}", tail_peak);
    }

    #[test]
    fn test_per_tab_audio_dsp_manager_isolation_and_output_routing() {
        let mut mgr = PerTabAudioDspManager::new(48000.0);
        mgr.global_mut().output_device_id = Some("speakers-main".into());
        mgr.set_tab_preset(10, EqualizerPreset::VocalPodcast);
        mgr.set_tab_volume_boost(10, 500.0);
        mgr.set_tab_output_device(10, Some("usb-dac-headphones".into()));

        mgr.set_tab_preset(20, EqualizerPreset::Gaming);
        mgr.set_tab_compressor(20, CompressorConfig::night_mode());

        assert_eq!(mgr.effective_output_device(10), Some("usb-dac-headphones"));
        assert_eq!(mgr.effective_output_device(20), Some("speakers-main"));
        assert_eq!(mgr.effective_output_device(99), Some("speakers-main"));
        assert_eq!(mgr.active_tab_ids(), vec![10, 20]);

        let mut tab10_pcm = vec![0.1f32, -0.1f32, 0.1f32, -0.1f32];
        let mut tab99_pcm = tab10_pcm.clone();
        mgr.process_tab_pcm(10, &mut tab10_pcm);
        mgr.process_tab_pcm(99, &mut tab99_pcm);
        assert!(tab10_pcm[0].abs() > tab99_pcm[0].abs() * 2.0);
    }
}
