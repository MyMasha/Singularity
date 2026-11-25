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
            sample_rate_hz.clamp(8000.0, 384000.0)
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
fn flush_denormal(v: f64) -> f64 {
    if v.abs() < 1e-30 {
        0.0
    } else {
        v
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
        Self::new(48000.0)
    }
}

impl TenBandParametricEqualizer {
    pub fn new(sample_rate_hz: f64) -> Self {
        let safe_sr = if sample_rate_hz.is_finite() {
            sample_rate_hz.clamp(8000.0, 384000.0)
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
    /// Sanitizes any non-finite (`NaN`/`±Inf`) input samples to `0.0` so filter state is never poisoned.
    pub fn process_interleaved_stereo_pcm(&mut self, pcm_stereo: &mut [f32]) {
        let linear_gain = self.volume_boost_percent / 100.0;

        for frame in pcm_stereo.chunks_exact_mut(2) {
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

            // Soft-knee saturation limiter above 0.90 amplitude to prevent harsh digital clipping at 400% boost
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

#[inline]
fn soft_clip_sample(x: f64) -> f64 {
    if !x.is_finite() {
        return 0.0;
    }
    if x.abs() <= 0.90 {
        x
    } else {
        x.signum() * (0.90 + 0.10 * ((x.abs() - 0.90) * 10.0).tanh())
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
}
