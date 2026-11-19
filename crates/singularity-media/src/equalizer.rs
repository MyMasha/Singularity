//! 10-Band Parametric Biquad Audio Equalizer & 400% Soft-Knee Volume Booster in Rust.

use serde::{Deserialize, Serialize};
use std::f64::consts::PI;

/// Center frequencies (Hz) for the 10 ISO octave bands in Singularity's audio engine.
pub const ISO_10_BAND_FREQUENCIES_HZ: [f64; 10] = [
    31.25, 62.5, 125.0, 250.0, 500.0, 1000.0, 2000.0, 4000.0, 8000.0, 16000.0,
];

/// Configuration for a single parametric equalizer band.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ParametricBandConfig {
    pub center_freq_hz: f64,
    pub gain_db: f64,
    pub q_factor: f64,
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
    fn compute_coefficients(sample_rate_hz: f64, freq_hz: f64, gain_db: f64, q: f64) -> (f64, f64, f64, f64, f64) {
        let safe_sr = if sample_rate_hz.is_finite() {
            sample_rate_hz.max(8000.0)
        } else {
            48000.0
        };
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

    /// Updates biquad coefficients in-place while preserving delay registers to avoid clicks/pops.
    fn update_peaking_eq(&mut self, sample_rate_hz: f64, freq_hz: f64, gain_db: f64, q: f64) {
        let (b0, b1, b2, a1, a2) = Self::compute_coefficients(sample_rate_hz, freq_hz, gain_db, q);
        self.b0 = b0;
        self.b1 = b1;
        self.b2 = b2;
        self.a1 = a1;
        self.a2 = a2;
    }

    #[inline]
    fn process_stereo_frame(&mut self, left: f64, right: f64) -> (f64, f64) {
        let out_l = self.b0 * left + self.z1_left;
        self.z1_left = self.b1 * left - self.a1 * out_l + self.z2_left;
        self.z2_left = self.b2 * left - self.a2 * out_l;

        let out_r = self.b0 * right + self.z1_right;
        self.z1_right = self.b1 * right - self.a1 * out_r + self.z2_right;
        self.z2_right = self.b2 * right - self.a2 * out_r;

        (out_l, out_r)
    }
}

/// 10-Band Parametric Equalizer and 0%–400% Volume Boost DSP Processor.
pub struct TenBandParametricEqualizer {
    sample_rate_hz: f64,
    bands: [ParametricBandConfig; 10],
    filters: [BiquadFilter; 10],
    volume_boost_percent: f64,
    enabled: bool,
}

impl Default for TenBandParametricEqualizer {
    fn default() -> Self {
        Self::new(96000.0)
    }
}

impl TenBandParametricEqualizer {
    pub fn new(sample_rate_hz: f64) -> Self {
        let safe_sr = if sample_rate_hz.is_finite() {
            sample_rate_hz.max(8000.0)
        } else {
            48000.0
        };
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

    /// Sets the volume boost percentage (`0.0%` to `400.0%`).
    pub fn set_volume_boost_percent(&mut self, percent: f64) {
        if percent.is_finite() {
            self.volume_boost_percent = percent.clamp(0.0, 400.0);
        }
    }

    pub fn volume_boost_percent(&self) -> f64 {
        self.volume_boost_percent
    }

    pub fn bands(&self) -> &[ParametricBandConfig; 10] {
        &self.bands
    }

    /// Processes an interleaved stereo float32 PCM buffer through all 10 biquad bands
    /// and applies the 400% volume booster with a soft-knee hyperbolic tangent limiter.
    pub fn process_interleaved_stereo_pcm(&mut self, pcm_stereo: &mut [f32]) {
        let linear_gain = self.volume_boost_percent / 100.0;

        for frame in pcm_stereo.chunks_exact_mut(2) {
            let mut l = frame[0] as f64;
            let mut r = frame[1] as f64;

            if self.enabled {
                for filter in &mut self.filters {
                    let (nl, nr) = filter.process_stereo_frame(l, r);
                    l = nl;
                    r = nr;
                }
            }

            l *= linear_gain;
            r *= linear_gain;

            // Soft-knee saturation limiter above 0.95 amplitude to prevent harsh digital clipping at 400% boost
            frame[0] = soft_clip_sample(l) as f32;
            frame[1] = soft_clip_sample(r) as f32;
        }
    }
}

#[inline]
fn soft_clip_sample(x: f64) -> f64 {
    if x.abs() <= 0.90 {
        x
    } else {
        x.signum() * (0.90 + 0.10 * ((x.abs() - 0.90) * 10.0).tanh())
    }
}
