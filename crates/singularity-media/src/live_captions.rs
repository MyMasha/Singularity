//! Real-Time Local Live Captions Frontend (16 kHz PCM Voice Activity Detection,
//! Circular Transcript Segment Buffer, Live Overlay Slicing, and `.srt`/`.txt` Exporters).

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// Standard sample rate (Hz) expected by local Whisper/ASR speech recognition models.
pub const VAD_SAMPLE_RATE_HZ: u32 = 16_000;

/// Default circular buffer capacity (number of retained caption segments).
pub const DEFAULT_CAPTION_BUFFER_CAPACITY: usize = 500;

/// Local on-device speech recognition model footprint tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub enum CaptionModelSize {
    Tiny,
    #[default]
    Base,
    Small,
    Medium,
}

impl CaptionModelSize {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Tiny => "tiny",
            Self::Base => "base",
            Self::Small => "small",
            Self::Medium => "medium",
        }
    }

    /// Approximate RAM/VRAM footprint in MiB for the quantized local ASR model.
    pub const fn approx_memory_mib(&self) -> u32 {
        match self {
            Self::Tiny => 75,
            Self::Base => 145,
            Self::Small => 465,
            Self::Medium => 1_500,
        }
    }
}

/// Configuration for local real-time Live Captions & OLED overlay presentation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveCaptionsConfig {
    pub enabled: bool,
    /// Source spoken language ISO code (e.g. `"auto"`, `"en"`, `"fr"`).
    pub language: String,
    pub model_size: CaptionModelSize,
    /// Optional target language for live translation (`None` = original language only).
    pub translate_target_lang: Option<String>,
    /// Overlay font size in pixels (`12..=72`).
    pub font_size_px: u32,
    /// OLED overlay pill background opacity percentage (`0..=100`).
    pub bg_opacity_pct: u8,
    /// Maximum number of caption lines shown simultaneously (`1..=8`).
    pub max_lines: u8,
}

impl Default for LiveCaptionsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            language: "auto".into(),
            model_size: CaptionModelSize::Base,
            translate_target_lang: None,
            font_size_px: 22,
            bg_opacity_pct: 85,
            max_lines: 3,
        }
    }
}

impl LiveCaptionsConfig {
    /// Returns a clamped copy with safe UI bounds.
    pub fn sanitized(mut self) -> Self {
        if self.language.trim().is_empty() {
            self.language = "auto".into();
        }
        self.font_size_px = self.font_size_px.clamp(12, 72);
        self.bg_opacity_pct = self.bg_opacity_pct.min(100);
        self.max_lines = self.max_lines.clamp(1, 8);
        if let Some(ref lang) = self.translate_target_lang {
            if lang.trim().is_empty() {
                self.translate_target_lang = None;
            }
        }
        self
    }
}

/// A single recognized (and optionally translated) live caption segment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptionSegment {
    pub index: u64,
    pub start_ms: u64,
    pub end_ms: u64,
    pub text: String,
    pub translated_text: Option<String>,
}

impl CaptionSegment {
    /// Returns the translated text when present and non-empty, otherwise the original transcript.
    pub fn display_text(&self) -> &str {
        self.translated_text
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or(&self.text)
    }
}

/// Decision emitted by [`VoiceActivityDetector`] for a single 16 kHz PCM frame.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct VadFrameDecision {
    pub is_speech: bool,
    pub rms: f32,
    pub db_fs: f32,
    pub speech_started: bool,
    pub speech_ended: bool,
}

/// Lightweight pure-Rust RMS-energy Voice Activity Detector (VAD) tuned for 16 kHz mono float32 PCM.
#[derive(Debug, Clone)]
pub struct VoiceActivityDetector {
    sample_rate_hz: u32,
    energy_threshold_rms: f32,
    hangover_frames: usize,
    min_speech_frames: usize,
    speech_active: bool,
    consecutive_above: usize,
    hangover_remaining: usize,
    last_rms: f32,
    last_db_fs: f32,
}

impl Default for VoiceActivityDetector {
    fn default() -> Self {
        Self::new(VAD_SAMPLE_RATE_HZ, 0.015)
    }
}

impl VoiceActivityDetector {
    pub fn new(sample_rate_hz: u32, energy_threshold_rms: f32) -> Self {
        let safe_sr = sample_rate_hz.clamp(8_000, 48_000);
        let safe_thresh = if energy_threshold_rms.is_finite() {
            energy_threshold_rms.clamp(1e-5, 0.95)
        } else {
            0.015
        };
        Self {
            sample_rate_hz: safe_sr,
            energy_threshold_rms: safe_thresh,
            hangover_frames: 8,
            min_speech_frames: 1,
            speech_active: false,
            consecutive_above: 0,
            hangover_remaining: 0,
            last_rms: 0.0,
            last_db_fs: -120.0,
        }
    }

    pub fn with_hangover_frames(mut self, frames: usize) -> Self {
        self.hangover_frames = frames;
        self
    }

    pub fn with_min_speech_frames(mut self, frames: usize) -> Self {
        self.min_speech_frames = frames.max(1);
        self
    }

    pub fn sample_rate_hz(&self) -> u32 {
        self.sample_rate_hz
    }

    pub fn energy_threshold_rms(&self) -> f32 {
        self.energy_threshold_rms
    }

    pub fn set_energy_threshold_rms(&mut self, threshold_rms: f32) {
        if threshold_rms.is_finite() {
            self.energy_threshold_rms = threshold_rms.clamp(1e-5, 0.95);
        }
    }

    /// Computes sanitized Root-Mean-Square (RMS) energy of a mono float32 PCM frame.
    pub fn compute_rms(pcm_mono: &[f32]) -> f32 {
        if pcm_mono.is_empty() {
            return 0.0;
        }
        let mut sum_sq = 0.0_f64;
        for &sample in pcm_mono {
            if sample.is_finite() {
                let s = sample as f64;
                sum_sq += s * s;
            }
        }
        (sum_sq / (pcm_mono.len() as f64)).sqrt() as f32
    }

    /// Evaluates one 16 kHz mono float32 PCM frame and updates speech/hangover state.
    pub fn process_frame(&mut self, pcm_16khz_mono: &[f32]) -> VadFrameDecision {
        let rms = Self::compute_rms(pcm_16khz_mono);
        let db_fs = if rms > 1e-6 {
            20.0 * rms.log10()
        } else {
            -120.0
        };
        self.last_rms = rms;
        self.last_db_fs = db_fs;

        let was_active = self.speech_active;
        if rms >= self.energy_threshold_rms {
            self.consecutive_above = self.consecutive_above.saturating_add(1);
            if self.consecutive_above >= self.min_speech_frames {
                self.speech_active = true;
                self.hangover_remaining = self.hangover_frames;
            }
        } else {
            self.consecutive_above = 0;
            if self.speech_active {
                if self.hangover_remaining > 0 {
                    self.hangover_remaining -= 1;
                } else {
                    self.speech_active = false;
                }
            }
        }

        VadFrameDecision {
            is_speech: self.speech_active,
            rms,
            db_fs,
            speech_started: !was_active && self.speech_active,
            speech_ended: was_active && !self.speech_active,
        }
    }

    /// Convenience helper returning `true` when the processed frame is classified as speech.
    pub fn is_speech_frame(&mut self, pcm_16khz_mono: &[f32]) -> bool {
        self.process_frame(pcm_16khz_mono).is_speech
    }

    pub fn is_speech_active(&self) -> bool {
        self.speech_active
    }

    pub fn last_rms(&self) -> f32 {
        self.last_rms
    }

    pub fn last_db_fs(&self) -> f32 {
        self.last_db_fs
    }

    pub fn reset(&mut self) {
        self.speech_active = false;
        self.consecutive_above = 0;
        self.hangover_remaining = 0;
        self.last_rms = 0.0;
        self.last_db_fs = -120.0;
    }
}

/// Mixes interleaved stereo PCM at `src_sample_rate_hz` down to 16 kHz mono float32 PCM
/// using linear interpolation suitable for feeding [`VoiceActivityDetector`] / local ASR.
pub fn downsample_interleaved_stereo_to_16khz_mono(
    pcm_stereo: &[f32],
    src_sample_rate_hz: u32,
) -> Vec<f32> {
    let stereo_frames = pcm_stereo.len() / 2;
    if stereo_frames == 0 || src_sample_rate_hz == 0 {
        return Vec::new();
    }

    let mut mono = Vec::with_capacity(stereo_frames);
    for frame in pcm_stereo.as_chunks::<2>().0 {
        let l = if frame[0].is_finite() { frame[0] } else { 0.0 };
        let r = if frame[1].is_finite() { frame[1] } else { 0.0 };
        mono.push(0.5 * (l + r));
    }

    if src_sample_rate_hz == VAD_SAMPLE_RATE_HZ {
        return mono;
    }

    let ratio = (src_sample_rate_hz as f64) / (VAD_SAMPLE_RATE_HZ as f64);
    let out_len = ((stereo_frames as f64) / ratio).floor() as usize;
    let mut out = Vec::with_capacity(out_len);
    for i in 0..out_len {
        let src_pos = (i as f64) * ratio;
        let idx = src_pos.floor() as usize;
        let frac = (src_pos - idx as f64) as f32;
        let s0 = mono[idx.min(stereo_frames - 1)];
        let s1 = mono[(idx + 1).min(stereo_frames - 1)];
        out.push(s0 + (s1 - s0) * frac);
    }
    out
}

/// Real-time Live Captions engine combining [`LiveCaptionsConfig`], [`VoiceActivityDetector`],
/// a bounded circular buffer of [`CaptionSegment`] entries, and `.srt`/`.txt` exporters.
#[derive(Debug, Clone)]
pub struct LiveCaptionsEngine {
    pub config: LiveCaptionsConfig,
    pub vad: VoiceActivityDetector,
    segments: VecDeque<CaptionSegment>,
    max_segments: usize,
    next_index: u64,
}

impl Default for LiveCaptionsEngine {
    fn default() -> Self {
        Self::new(LiveCaptionsConfig::default(), DEFAULT_CAPTION_BUFFER_CAPACITY)
    }
}

impl LiveCaptionsEngine {
    pub fn new(config: LiveCaptionsConfig, max_segments: usize) -> Self {
        let cap = max_segments.max(1);
        Self {
            config: config.sanitized(),
            vad: VoiceActivityDetector::default(),
            segments: VecDeque::with_capacity(cap.min(1024)),
            max_segments: cap,
            next_index: 1,
        }
    }

    /// Appends a recognized caption segment to the circular buffer, evicting the oldest segment
    /// once `max_segments` is reached.
    pub fn push_segment(
        &mut self,
        start_ms: u64,
        end_ms: u64,
        text: impl Into<String>,
        translated_text: Option<String>,
    ) -> &CaptionSegment {
        let index = self.next_index;
        self.next_index = self.next_index.saturating_add(1);

        if self.segments.len() >= self.max_segments {
            self.segments.pop_front();
        }
        self.segments.push_back(CaptionSegment {
            index,
            start_ms,
            end_ms: end_ms.max(start_ms),
            text: text.into().trim().to_string(),
            translated_text: translated_text
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
        });
        self.segments.back().expect("just pushed")
    }

    /// Returns all currently buffered segments in chronological order.
    pub fn segments(&self) -> &VecDeque<CaptionSegment> {
        &self.segments
    }

    /// Returns up to `config.max_lines` most recent segments for the live OLED caption overlay.
    pub fn visible_lines(&self) -> Vec<&CaptionSegment> {
        let limit = (self.config.max_lines as usize).max(1);
        let skip = self.segments.len().saturating_sub(limit);
        self.segments.iter().skip(skip).collect()
    }

    pub fn len(&self) -> usize {
        self.segments.len()
    }

    pub fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.max_segments
    }

    pub fn clear(&mut self) {
        self.segments.clear();
        self.next_index = 1;
        self.vad.reset();
    }

    /// Exports all buffered caption segments in standard SubRip (`.srt`) format.
    pub fn export_srt(&self) -> String {
        format_captions_as_srt(self.segments.iter())
    }

    /// Exports all buffered caption segments as a clean plain-text `.txt` transcript.
    pub fn export_txt(&self) -> String {
        format_captions_as_txt(self.segments.iter())
    }

    /// Exports all buffered caption segments as a timestamped `[HH:MM:SS] ...` `.txt` transcript.
    pub fn export_timestamped_txt(&self) -> String {
        let mut out = String::new();
        for seg in &self.segments {
            let text = seg.display_text().trim();
            if text.is_empty() {
                continue;
            }
            let h = seg.start_ms / 3_600_000;
            let m = (seg.start_ms % 3_600_000) / 60_000;
            let s = (seg.start_ms % 60_000) / 1_000;
            out.push_str(&format!("[{:02}:{:02}:{:02}] {}\n", h, m, s, text));
        }
        out
    }
}

fn format_srt_timestamp(ms: u64) -> String {
    let hours = ms / 3_600_000;
    let minutes = (ms % 3_600_000) / 60_000;
    let seconds = (ms % 60_000) / 1_000;
    let millis = ms % 1_000;
    format!("{:02}:{:02}:{:02},{:03}", hours, minutes, seconds, millis)
}

/// Formats an iterator of [`CaptionSegment`] references into a spec-compliant `.srt` document.
pub fn format_captions_as_srt<'a, I>(segments: I) -> String
where
    I: IntoIterator<Item = &'a CaptionSegment>,
{
    let mut out = String::new();
    let mut cue_num: u64 = 1;
    for seg in segments {
        let body = seg.display_text().trim();
        if body.is_empty() {
            continue;
        }
        out.push_str(&format!(
            "{}\n{} --> {}\n{}\n\n",
            cue_num,
            format_srt_timestamp(seg.start_ms),
            format_srt_timestamp(seg.end_ms),
            body
        ));
        cue_num += 1;
    }
    out
}

/// Formats an iterator of [`CaptionSegment`] references into a clean newline-separated `.txt` transcript.
pub fn format_captions_as_txt<'a, I>(segments: I) -> String
where
    I: IntoIterator<Item = &'a CaptionSegment>,
{
    let mut lines = Vec::new();
    for seg in segments {
        let body = seg.display_text().trim();
        if !body.is_empty() {
            lines.push(body);
        }
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::f32::consts::PI;

    #[test]
    fn test_vad_16khz_rms_speech_vs_silence_and_hangover() {
        let mut vad = VoiceActivityDetector::new(VAD_SAMPLE_RATE_HZ, 0.02).with_hangover_frames(2);
        let silence = vec![0.001f32; 480]; // 30 ms @ 16 kHz
        let d0 = vad.process_frame(&silence);
        assert!(!d0.is_speech);
        assert!(!d0.speech_started);

        // 30 ms voiced 300 Hz sine @ 0.25 peak (~0.177 RMS)
        let speech: Vec<f32> = (0..480)
            .map(|i| 0.25 * (2.0 * PI * 300.0 * (i as f32) / 16000.0).sin())
            .collect();
        let d1 = vad.process_frame(&speech);
        assert!(d1.is_speech);
        assert!(d1.speech_started);
        assert!(d1.rms > 0.15);

        // Hangover keeps speech active for 2 silent frames, then ends on 3rd
        assert!(vad.process_frame(&silence).is_speech);
        assert!(vad.process_frame(&silence).is_speech);
        let d_end = vad.process_frame(&silence);
        assert!(!d_end.is_speech);
        assert!(d_end.speech_ended);
    }

    #[test]
    fn test_circular_caption_buffer_and_srt_txt_exporters() {
        let cfg = LiveCaptionsConfig {
            enabled: true,
            language: "en".into(),
            model_size: CaptionModelSize::Small,
            translate_target_lang: Some("fr".into()),
            font_size_px: 24,
            bg_opacity_pct: 90,
            max_lines: 2,
        };
        let mut engine = LiveCaptionsEngine::new(cfg, 3);
        engine.push_segment(0, 1500, "Dropped oldest", None);
        engine.push_segment(2000, 4250, "Hello world", Some("Bonjour le monde".into()));
        engine.push_segment(5000, 7500, "Singularity live", Some("Singularity en direct".into()));
        engine.push_segment(8000, 10200, "Third retained", None);

        // Circular buffer retained only the 3 most recent segments
        assert_eq!(engine.len(), 3);
        assert_eq!(engine.segments().front().unwrap().start_ms, 2000);
        assert_eq!(engine.visible_lines().len(), 2);

        let srt = engine.export_srt();
        assert!(srt.contains("1\n00:00:02,000 --> 00:00:04,250\nBonjour le monde\n"));
        assert!(srt.contains("2\n00:00:05,000 --> 00:00:07,500\nSingularity en direct\n"));
        assert!(srt.contains("3\n00:00:08,000 --> 00:00:10,200\nThird retained\n"));
        assert!(!srt.contains("Dropped oldest"));

        let txt = engine.export_txt();
        assert_eq!(txt, "Bonjour le monde\nSingularity en direct\nThird retained");
    }

    #[test]
    fn test_downsample_48khz_stereo_to_16khz_mono() {
        // 480 stereo frames (10 ms @ 48 kHz) -> 160 mono frames (10 ms @ 16 kHz)
        let stereo = vec![0.5f32; 480 * 2];
        let mono_16k = downsample_interleaved_stereo_to_16khz_mono(&stereo, 48_000);
        assert_eq!(mono_16k.len(), 160);
        assert!((mono_16k[0] - 0.5).abs() < 1e-5);
    }
}
