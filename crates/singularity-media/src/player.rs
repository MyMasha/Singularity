//! OLED Black Floating & Docked Media Player Controller with Picture-in-Picture (PiP),
//! Frame-by-Frame Scrubbing, `0.1x`–`16.0x` Speed Control, A-B Looping, GPU Video Enhancement,
//! Local Media Track Metadata, and Pure-Rust SRT / ASS / WebVTT Subtitle Parsing & Conversion.

use serde::{Deserialize, Serialize};

/// Safe fallback viewport dimensions when physical screen/viewport geometry is not supplied.
pub const DEFAULT_VIEWPORT_WIDTH_PX: u32 = 1280;
pub const DEFAULT_VIEWPORT_HEIGHT_PX: u32 = 720;
pub const DEFAULT_PIP_WIDTH_PX: u32 = 480;
pub const DEFAULT_PIP_HEIGHT_PX: u32 = 270;
pub const PIP_EDGE_MARGIN_PX: u32 = 24;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SubtitleStyleConfig {
    pub font_family: String,
    pub font_size_px: u32,
    pub text_rgba_hex: String,
    pub pill_backdrop_rgba_hex: String,
    pub sync_offset_ms: i64,
}

impl Default for SubtitleStyleConfig {
    fn default() -> Self {
        Self {
            font_family: "Inter Variable".into(),
            font_size_px: 26,
            text_rgba_hex: "#FFFFFFFF".into(),
            pill_backdrop_rgba_hex: "#000000D9".into(),
            sync_offset_ms: 0,
        }
    }
}

/// GPU video super-resolution, sharpening, debanding, ultrawide auto-crop, and color-boost config.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct VideoEnhancementConfig {
    /// NVIDIA RTX Video Super Resolution (VSR) toggle.
    pub rtx_vsr_enabled: bool,
    /// Intel Video Super Resolution (VSR) toggle.
    pub intel_vsr_enabled: bool,
    /// AMD FidelityFX Contrast Adaptive Sharpening (CAS) intensity (`0.0` = off, `1.0` = max).
    pub amd_cas_sharpness: f32,
    /// Real-time OLED gradient debanding shader (`gradfun`).
    pub deband_enabled: bool,
    /// Automatically crops 16:9 letterboxed 21:9 cinema frames to fill ultrawide displays.
    pub auto_crop_21_9: bool,
    /// Contrast multiplier (`1.0` = neutral, clamped to `0.5..=2.0`).
    pub contrast_boost: f32,
    /// Color saturation multiplier (`1.0` = neutral, clamped to `0.0..=2.0`).
    pub saturation_boost: f32,
}

impl Default for VideoEnhancementConfig {
    fn default() -> Self {
        Self {
            rtx_vsr_enabled: false,
            intel_vsr_enabled: false,
            amd_cas_sharpness: 0.0,
            deband_enabled: false,
            auto_crop_21_9: false,
            contrast_boost: 1.0,
            saturation_boost: 1.0,
        }
    }
}

impl VideoEnhancementConfig {
    /// Returns a clamped copy with non-finite floats replaced by safe neutral values.
    pub fn sanitized(self) -> Self {
        Self {
            rtx_vsr_enabled: self.rtx_vsr_enabled,
            intel_vsr_enabled: self.intel_vsr_enabled,
            amd_cas_sharpness: if self.amd_cas_sharpness.is_finite() {
                self.amd_cas_sharpness.clamp(0.0, 1.0)
            } else {
                0.0
            },
            deband_enabled: self.deband_enabled,
            auto_crop_21_9: self.auto_crop_21_9,
            contrast_boost: if self.contrast_boost.is_finite() {
                self.contrast_boost.clamp(0.5, 2.0)
            } else {
                1.0
            },
            saturation_boost: if self.saturation_boost.is_finite() {
                self.saturation_boost.clamp(0.0, 2.0)
            } else {
                1.0
            },
        }
    }

    /// Returns `true` if any GPU video post-processing enhancement is currently active.
    pub fn is_any_enhancement_active(&self) -> bool {
        let s = self.sanitized();
        s.rtx_vsr_enabled
            || s.intel_vsr_enabled
            || s.amd_cas_sharpness > 0.0
            || s.deband_enabled
            || s.auto_crop_21_9
            || (s.contrast_boost - 1.0).abs() > 1e-3
            || (s.saturation_boost - 1.0).abs() > 1e-3
    }

    /// Builds a CSS compositor filter string for contrast/saturation fallback rendering.
    pub fn to_css_filter_string(&self) -> String {
        let s = self.sanitized();
        let mut parts = Vec::new();
        if (s.contrast_boost - 1.0).abs() > 1e-3 {
            parts.push(format!("contrast({:.2})", s.contrast_boost));
        }
        if (s.saturation_boost - 1.0).abs() > 1e-3 {
            parts.push(format!("saturate({:.2})", s.saturation_boost));
        }
        if parts.is_empty() {
            "none".into()
        } else {
            parts.join(" ")
        }
    }
}

/// Metadata describing an audio track embedded in a local or MSE media file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaAudioTrack {
    pub index: u32,
    pub language: String,
    pub title: String,
    pub codec: String,
    pub channels: u8,
    pub sample_rate_hz: u32,
    pub is_default: bool,
}

/// Metadata describing a subtitle/caption track embedded or side-loaded in the player.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaSubtitleTrack {
    pub index: u32,
    pub language: String,
    pub title: String,
    pub format: String,
    pub is_forced: bool,
    pub is_sdh: bool,
}

/// Chapter marker inside a media container (Matroska/MP4/WebM).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaChapterMarker {
    pub index: u32,
    pub title: String,
    pub start_ms: u64,
    pub end_ms: u64,
}

/// Complete track & chapter inventory for local/embedded multi-track media playback.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalMediaTrackInfo {
    pub audio_tracks: Vec<MediaAudioTrack>,
    pub subtitle_tracks: Vec<MediaSubtitleTrack>,
    pub chapters: Vec<MediaChapterMarker>,
    pub active_audio_track: Option<u32>,
    pub active_subtitle_track: Option<u32>,
}

impl LocalMediaTrackInfo {
    /// Selects an audio track by track index if present. Returns `true` on success.
    pub fn select_audio_track(&mut self, index: u32) -> bool {
        if self.audio_tracks.iter().any(|t| t.index == index) {
            self.active_audio_track = Some(index);
            true
        } else {
            false
        }
    }

    /// Selects a subtitle track by index, or `None` to disable subtitles.
    pub fn select_subtitle_track(&mut self, index: Option<u32>) -> bool {
        match index {
            None => {
                self.active_subtitle_track = None;
                true
            }
            Some(idx) => {
                if self.subtitle_tracks.iter().any(|t| t.index == idx) {
                    self.active_subtitle_track = Some(idx);
                    true
                } else {
                    false
                }
            }
        }
    }

    /// Returns the chapter covering `position_ms`, if any.
    pub fn chapter_at_ms(&self, position_ms: u64) -> Option<&MediaChapterMarker> {
        self.chapters
            .iter()
            .find(|c| position_ms >= c.start_ms && position_ms < c.end_ms)
    }

    /// Returns the start timestamp (ms) of the next chapter strictly after `position_ms`.
    pub fn next_chapter_start_ms(&self, position_ms: u64) -> Option<u64> {
        self.chapters
            .iter()
            .filter(|c| c.start_ms > position_ms)
            .map(|c| c.start_ms)
            .min()
    }

    /// Returns the start timestamp (ms) of the previous chapter strictly before `position_ms`.
    pub fn prev_chapter_start_ms(&self, position_ms: u64) -> Option<u64> {
        self.chapters
            .iter()
            .filter(|c| c.start_ms < position_ms)
            .map(|c| c.start_ms)
            .max()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlayerDockMode {
    InlineOledControlBar,
    FloatingPictureInPicture { x: i32, y: i32, width: u32, height: u32 },
    DockedSidebarMiniPlayer,
}

/// Computes bounded bottom-right Picture-in-Picture coordinates guaranteed to remain fully
/// visible inside `viewport_width x viewport_height` (falling back to `1280x720` if zero).
pub fn compute_bounded_pip_rect(
    viewport_width: u32,
    viewport_height: u32,
    desired_width: u32,
    desired_height: u32,
) -> (i32, i32, u32, u32) {
    let vw = if viewport_width == 0 {
        DEFAULT_VIEWPORT_WIDTH_PX
    } else {
        viewport_width
    };
    let vh = if viewport_height == 0 {
        DEFAULT_VIEWPORT_HEIGHT_PX
    } else {
        viewport_height
    };

    let margin_x = PIP_EDGE_MARGIN_PX.min(vw / 10);
    let margin_y = PIP_EDGE_MARGIN_PX.min(vh / 10);
    let max_w = vw.saturating_sub(margin_x.saturating_mul(2)).max(1);
    let max_h = vh.saturating_sub(margin_y.saturating_mul(2)).max(1);

    let width = desired_width.clamp(1, max_w);
    let height = desired_height.clamp(1, max_h);
    let x = vw
        .saturating_sub(width)
        .saturating_sub(margin_x)
        .min(i32::MAX as u32) as i32;
    let y = vh
        .saturating_sub(height)
        .saturating_sub(margin_y)
        .min(i32::MAX as u32) as i32;
    (x, y, width, height)
}

/// Runtime state of Singularity's hardware-accelerated media player.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OledMediaPlayer {
    pub stream_url: String,
    pub is_playing: bool,
    pub current_time_sec: f64,
    pub duration_sec: f64,
    pub stream_fps: f64,
    pub playback_speed: f64,
    pub dock_mode: PlayerDockMode,
    pub subtitle_style: SubtitleStyleConfig,
    /// Optional A-B loop start point in seconds.
    #[serde(default)]
    pub ab_loop_start_sec: Option<f64>,
    /// Optional A-B loop end point in seconds.
    #[serde(default)]
    pub ab_loop_end_sec: Option<f64>,
    /// GPU video enhancement configuration (RTX/Intel VSR, AMD CAS, deband, 21:9 auto-crop).
    #[serde(default)]
    pub video_enhancement: VideoEnhancementConfig,
    /// Embedded/side-loaded audio tracks, subtitle tracks, and chapter markers.
    #[serde(default)]
    pub tracks: LocalMediaTrackInfo,
}

impl Default for OledMediaPlayer {
    fn default() -> Self {
        Self {
            stream_url: String::new(),
            is_playing: false,
            current_time_sec: 0.0,
            duration_sec: 3600.0,
            stream_fps: 60.0,
            playback_speed: 1.0,
            dock_mode: PlayerDockMode::InlineOledControlBar,
            subtitle_style: SubtitleStyleConfig::default(),
            ab_loop_start_sec: None,
            ab_loop_end_sec: None,
            video_enhancement: VideoEnhancementConfig::default(),
            tracks: LocalMediaTrackInfo::default(),
        }
    }
}

impl OledMediaPlayer {
    /// Sets playback speed strictly clamped within the `0.1x` to `16.0x` range.
    pub fn set_playback_speed(&mut self, speed: f64) {
        if speed.is_finite() {
            self.playback_speed = speed.clamp(0.1, 16.0);
        }
    }

    /// Steps forward or backward by an exact number of video frames (`delta_frames`),
    /// automatically pausing playback for frame-accurate inspection.
    pub fn step_frames(&mut self, delta_frames: i64) -> f64 {
        self.is_playing = false;
        let fps = if self.stream_fps.is_finite() {
            self.stream_fps.max(1.0)
        } else {
            60.0
        };
        let max_dur = if self.duration_sec.is_finite() {
            self.duration_sec.max(0.0)
        } else {
            0.0
        };
        let cur = if self.current_time_sec.is_finite() {
            self.current_time_sec
        } else {
            0.0
        };
        let frame_duration = 1.0 / fps;
        let next_time = (cur + (delta_frames as f64) * frame_duration).clamp(0.0, max_dur);
        self.current_time_sec = next_time;
        next_time
    }

    /// Configures an A-B playback loop range `[start_sec, end_sec]` clamped to `[0.0, duration_sec]`.
    /// Swaps endpoints if reversed. Returns `false` if inputs are non-finite or collapse to a zero-length interval.
    pub fn set_ab_loop(&mut self, start_sec: f64, end_sec: f64) -> bool {
        if !start_sec.is_finite() || !end_sec.is_finite() {
            return false;
        }
        let max_dur = if self.duration_sec.is_finite() {
            self.duration_sec.max(0.0)
        } else {
            0.0
        };
        let mut a = start_sec.clamp(0.0, max_dur);
        let mut b = end_sec.clamp(0.0, max_dur);
        if a > b {
            std::mem::swap(&mut a, &mut b);
        }
        if (b - a) <= 1e-6 {
            return false;
        }
        self.ab_loop_start_sec = Some(a);
        self.ab_loop_end_sec = Some(b);
        true
    }

    /// Sets A-B loop point A (`ab_loop_start_sec`), clamped to `[0.0, duration_sec]`.
    pub fn set_ab_loop_point_a(&mut self, start_sec: f64) {
        if start_sec.is_finite() {
            let max_dur = if self.duration_sec.is_finite() {
                self.duration_sec.max(0.0)
            } else {
                0.0
            };
            self.ab_loop_start_sec = Some(start_sec.clamp(0.0, max_dur));
        }
    }

    /// Sets A-B loop point B (`ab_loop_end_sec`), clamped to `[0.0, duration_sec]`.
    pub fn set_ab_loop_point_b(&mut self, end_sec: f64) {
        if end_sec.is_finite() {
            let max_dur = if self.duration_sec.is_finite() {
                self.duration_sec.max(0.0)
            } else {
                0.0
            };
            self.ab_loop_end_sec = Some(end_sec.clamp(0.0, max_dur));
        }
    }

    /// Clears both A-B loop markers.
    pub fn clear_ab_loop(&mut self) {
        self.ab_loop_start_sec = None;
        self.ab_loop_end_sec = None;
    }

    /// Returns `true` if a valid A-B loop (`start < end`) is currently configured.
    pub fn is_ab_loop_active(&self) -> bool {
        match (self.ab_loop_start_sec, self.ab_loop_end_sec) {
            (Some(a), Some(b)) => a.is_finite() && b.is_finite() && b > a,
            _ => false,
        }
    }

    /// Checks whether `current_time_sec` has reached or passed `ab_loop_end_sec`; if so, wraps
    /// `current_time_sec` seamlessly back to `ab_loop_start_sec` and returns `true`.
    pub fn check_ab_loop_wrap(&mut self) -> bool {
        if let (Some(start), Some(end)) = (self.ab_loop_start_sec, self.ab_loop_end_sec) {
            if start.is_finite() && end.is_finite() && end > start && self.current_time_sec >= end {
                self.current_time_sec = start;
                return true;
            }
        }
        false
    }

    /// Advances playback clock by `delta_sec * playback_speed` when playing, applying A-B loop wrap.
    pub fn advance_playback(&mut self, delta_sec: f64) -> f64 {
        if !self.is_playing || !delta_sec.is_finite() || delta_sec <= 0.0 {
            return self.current_time_sec;
        }
        let max_dur = if self.duration_sec.is_finite() {
            self.duration_sec.max(0.0)
        } else {
            0.0
        };
        self.current_time_sec =
            (self.current_time_sec + delta_sec * self.playback_speed).clamp(0.0, max_dur);
        self.check_ab_loop_wrap();
        self.current_time_sec
    }

    /// Toggles borderless OLED Picture-in-Picture (PiP) mode using safe bounded coordinates
    /// inside the default `1280x720` fallback viewport (never off-screen).
    pub fn toggle_picture_in_picture(&mut self) {
        self.toggle_picture_in_picture_in_viewport(
            DEFAULT_VIEWPORT_WIDTH_PX,
            DEFAULT_VIEWPORT_HEIGHT_PX,
        );
    }

    /// Toggles borderless OLED Picture-in-Picture (PiP) mode anchored inside `viewport_width x viewport_height`.
    pub fn toggle_picture_in_picture_in_viewport(
        &mut self,
        viewport_width: u32,
        viewport_height: u32,
    ) {
        self.dock_mode = match self.dock_mode {
            PlayerDockMode::FloatingPictureInPicture { .. } => PlayerDockMode::InlineOledControlBar,
            _ => {
                let (x, y, width, height) = compute_bounded_pip_rect(
                    viewport_width,
                    viewport_height,
                    DEFAULT_PIP_WIDTH_PX,
                    DEFAULT_PIP_HEIGHT_PX,
                );
                PlayerDockMode::FloatingPictureInPicture {
                    x,
                    y,
                    width,
                    height,
                }
            }
        };
    }

    /// Clamps custom PiP position and dimensions strictly inside `viewport_width x viewport_height`.
    pub fn set_picture_in_picture_bounds(
        &mut self,
        x: i32,
        y: i32,
        width: u32,
        height: u32,
        viewport_width: u32,
        viewport_height: u32,
    ) {
        let vw = if viewport_width == 0 {
            DEFAULT_VIEWPORT_WIDTH_PX
        } else {
            viewport_width
        };
        let vh = if viewport_height == 0 {
            DEFAULT_VIEWPORT_HEIGHT_PX
        } else {
            viewport_height
        };
        let clamped_w = width.clamp(1, vw);
        let clamped_h = height.clamp(1, vh);
        let max_x = vw.saturating_sub(clamped_w).min(i32::MAX as u32) as i32;
        let max_y = vh.saturating_sub(clamped_h).min(i32::MAX as u32) as i32;
        self.dock_mode = PlayerDockMode::FloatingPictureInPicture {
            x: x.clamp(0, max_x),
            y: y.clamp(0, max_y),
            width: clamped_w,
            height: clamped_h,
        };
    }
}

// ============================================================================
// Pure-Rust Subtitle Parser & Converter (SRT / ASS / WebVTT)
// ============================================================================

/// A single timed subtitle cue normalized to millisecond timestamps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubtitleCue {
    pub start_ms: u64,
    pub end_ms: u64,
    pub text: String,
    #[serde(default)]
    pub style_name: Option<String>,
}

impl SubtitleCue {
    pub fn new(start_ms: u64, end_ms: u64, text: impl Into<String>) -> Self {
        Self {
            start_ms,
            end_ms: end_ms.max(start_ms),
            text: text.into(),
            style_name: None,
        }
    }
}

fn strip_bom_and_normalize_newlines(input: &str) -> String {
    let trimmed = input.strip_prefix('\u{FEFF}').unwrap_or(input);
    trimmed.replace("\r\n", "\n").replace('\r', "\n")
}

/// Parses `HH:MM:SS,mmm`, `HH:MM:SS.mmm`, `MM:SS.mmm`, or `H:MM:SS.cc` (ASS centiseconds) into ms.
fn parse_subtitle_timestamp_ms(token: &str) -> Option<u64> {
    let clean = token.trim();
    if clean.is_empty() {
        return None;
    }

    let (hms_part, frac_part) = if let Some(idx) = clean.rfind([',', '.']) {
        (&clean[..idx], Some(&clean[idx + 1..]))
    } else {
        (clean, None)
    };

    let parts: Vec<&str> = hms_part.split(':').collect();
    let (hours, minutes, seconds) = match parts.as_slice() {
        [h, m, s] => (
            h.trim().parse::<u64>().ok()?,
            m.trim().parse::<u64>().ok()?,
            s.trim().parse::<u64>().ok()?,
        ),
        [m, s] => (
            0u64,
            m.trim().parse::<u64>().ok()?,
            s.trim().parse::<u64>().ok()?,
        ),
        _ => return None,
    };

    let ms = match frac_part {
        None => 0u64,
        Some(f) => {
            let digits: String = f.chars().take_while(|c| c.is_ascii_digit()).take(3).collect();
            if digits.is_empty() {
                0
            } else {
                let raw = digits.parse::<u64>().ok()?;
                match digits.len() {
                    1 => raw * 100,
                    2 => raw * 10,
                    _ => raw,
                }
            }
        }
    };

    Some(
        hours
            .saturating_mul(3_600_000)
            .saturating_add(minutes.saturating_mul(60_000))
            .saturating_add(seconds.saturating_mul(1_000))
            .saturating_add(ms),
    )
}

fn parse_cue_timing_line(line: &str) -> Option<(u64, u64)> {
    let (left, right_with_settings) = line.split_once("-->")?;
    let start_token = left.split_whitespace().next()?;
    let end_token = right_with_settings.split_whitespace().next()?;
    let start_ms = parse_subtitle_timestamp_ms(start_token)?;
    let end_ms = parse_subtitle_timestamp_ms(end_token)?;
    Some((start_ms, end_ms.max(start_ms)))
}

/// Parses SubRip (`.srt`) subtitle content into [`SubtitleCue`] entries.
pub fn parse_srt(input: &str) -> Vec<SubtitleCue> {
    let normalized = strip_bom_and_normalize_newlines(input);
    let mut cues = Vec::new();

    for block in normalized.split("\n\n") {
        let lines: Vec<&str> = block.lines().collect();
        let Some(timing_idx) = lines.iter().position(|l| l.contains("-->")) else {
            continue;
        };
        let Some((start_ms, end_ms)) = parse_cue_timing_line(lines[timing_idx]) else {
            continue;
        };
        let text = lines[timing_idx + 1..]
            .iter()
            .map(|l| l.trim_end())
            .collect::<Vec<_>>()
            .join("\n")
            .trim()
            .to_string();
        if !text.is_empty() {
            cues.push(SubtitleCue {
                start_ms,
                end_ms,
                text,
                style_name: None,
            });
        }
    }

    cues
}

/// Strips ASS/SSA `{...}` override blocks and translates `\N`, `\n`, and `\h` escape sequences.
fn clean_ass_dialogue_text(raw: &str) -> String {
    let mut stripped = String::with_capacity(raw.len());
    let chars: Vec<char> = raw.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        if chars[i] == '{' {
            if let Some(rel_close) = chars[i + 1..].iter().position(|&c| c == '}') {
                i = i + 1 + rel_close + 1;
                continue;
            }
            // No closing '}' remains anywhere: consume the remainder in a single O(N) pass.
            while i < chars.len() {
                if chars[i] == '\\' && i + 1 < chars.len() {
                    match chars[i + 1] {
                        'N' | 'n' => {
                            stripped.push('\n');
                            i += 2;
                            continue;
                        }
                        'h' => {
                            stripped.push(' ');
                            i += 2;
                            continue;
                        }
                        _ => {}
                    }
                }
                stripped.push(chars[i]);
                i += 1;
            }
            break;
        }
        if chars[i] == '\\' && i + 1 < chars.len() {
            match chars[i + 1] {
                'N' | 'n' => {
                    stripped.push('\n');
                    i += 2;
                    continue;
                }
                'h' => {
                    stripped.push(' ');
                    i += 2;
                    continue;
                }
                _ => {}
            }
        }
        stripped.push(chars[i]);
        i += 1;
    }

    stripped
        .lines()
        .map(|l| l.trim())
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_string()
}

/// Parses SubStation Alpha / Advanced SubStation Alpha (`.ssa` / `.ass`) subtitle content
/// into chronologically ordered [`SubtitleCue`] entries, stripping `{...}` override tags.
pub fn parse_ass(input: &str) -> Vec<SubtitleCue> {
    let normalized = strip_bom_and_normalize_newlines(input);
    let mut cues = Vec::new();

    // Standard ASS v4+ [Events] column defaults
    let mut in_events = true;
    let mut saw_any_section = false;
    let mut start_col: usize = 1;
    let mut end_col: usize = 2;
    let mut style_col: Option<usize> = Some(3);
    let mut text_col: usize = 9;
    let mut total_cols: usize = 10;

    for raw_line in normalized.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            saw_any_section = true;
            let section = &line[1..line.len() - 1].trim();
            in_events = section.eq_ignore_ascii_case("events");
            continue;
        }
        if saw_any_section && !in_events {
            continue;
        }

        if let Some(rest) = strip_ascii_prefix_ignore_case(line, "format:") {
            let cols: Vec<String> = rest
                .split(',')
                .map(|c| c.trim().to_ascii_lowercase())
                .collect();
            if cols.len() >= 3 {
                total_cols = cols.len();
                if let Some(pos) = cols.iter().position(|c| c == "start") {
                    start_col = pos;
                }
                if let Some(pos) = cols.iter().position(|c| c == "end") {
                    end_col = pos;
                }
                style_col = cols.iter().position(|c| c == "style");
                if let Some(pos) = cols.iter().position(|c| c == "text") {
                    text_col = pos;
                } else {
                    text_col = total_cols - 1;
                }
            }
            continue;
        }

        if let Some(rest) = strip_ascii_prefix_ignore_case(line, "dialogue:") {
            let fields: Vec<&str> = rest.trim_start().splitn(total_cols, ',').collect();
            if fields.len() <= start_col || fields.len() <= end_col || fields.len() <= text_col {
                continue;
            }
            let Some(start_ms) = parse_subtitle_timestamp_ms(fields[start_col]) else {
                continue;
            };
            let Some(end_ms) = parse_subtitle_timestamp_ms(fields[end_col]) else {
                continue;
            };
            let style_name = style_col
                .and_then(|idx| fields.get(idx))
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
            let text = clean_ass_dialogue_text(fields[text_col]);
            if !text.is_empty() {
                cues.push(SubtitleCue {
                    start_ms,
                    end_ms: end_ms.max(start_ms),
                    text,
                    style_name,
                });
            }
        }
    }

    cues.sort_by_key(|c| (c.start_ms, c.end_ms));
    cues
}

fn strip_ascii_prefix_ignore_case<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.len() >= prefix.len()
        && s.is_char_boundary(prefix.len())
        && s[..prefix.len()].eq_ignore_ascii_case(prefix)
    {
        return Some(&s[prefix.len()..]);
    }
    None
}

/// Parses WebVTT (`.vtt`) subtitle content into [`SubtitleCue`] entries, skipping `NOTE`, `STYLE`,
/// and `REGION` blocks as well as optional cue settings.
pub fn parse_vtt(input: &str) -> Vec<SubtitleCue> {
    let normalized = strip_bom_and_normalize_newlines(input);
    let mut cues = Vec::new();

    for block in normalized.split("\n\n") {
        let trimmed = block.trim();
        if trimmed.is_empty()
            || trimmed.starts_with("WEBVTT")
            || trimmed.starts_with("NOTE")
            || trimmed.starts_with("STYLE")
            || trimmed.starts_with("REGION")
        {
            continue;
        }

        let lines: Vec<&str> = block.lines().collect();
        let Some(timing_idx) = lines.iter().position(|l| l.contains("-->")) else {
            continue;
        };
        let Some((start_ms, end_ms)) = parse_cue_timing_line(lines[timing_idx]) else {
            continue;
        };
        let text = lines[timing_idx + 1..]
            .iter()
            .map(|l| l.trim_end())
            .collect::<Vec<_>>()
            .join("\n")
            .trim()
            .to_string();
        if !text.is_empty() {
            cues.push(SubtitleCue {
                start_ms,
                end_ms,
                text,
                style_name: None,
            });
        }
    }

    cues
}

/// Formats millisecond duration as a WebVTT timestamp (`HH:MM:SS.mmm`).
fn format_webvtt_timestamp(ms: u64) -> String {
    let hours = ms / 3_600_000;
    let minutes = (ms % 3_600_000) / 60_000;
    let seconds = (ms % 60_000) / 1_000;
    let millis = ms % 1_000;
    format!("{:02}:{:02}:{:02}.{:03}", hours, minutes, seconds, millis)
}

/// Converts normalized [`SubtitleCue`] entries into a spec-compliant WebVTT document,
/// applying an optional signed `sync_offset_ms` (`±ms`) shift.
pub fn format_as_webvtt(cues: &[SubtitleCue], sync_offset_ms: i64) -> String {
    let mut out = String::from("WEBVTT\n\n");

    for cue in cues {
        let shifted_end_i128 = (cue.end_ms as i128) + (sync_offset_ms as i128);
        if shifted_end_i128 <= 0 && cue.end_ms > 0 {
            continue;
        }
        let shifted_start = ((cue.start_ms as i128) + (sync_offset_ms as i128)).max(0) as u64;
        let shifted_end = shifted_end_i128.max(shifted_start as i128) as u64;

        let clean_text: String = cue
            .text
            .lines()
            .map(|l| l.trim_end())
            .filter(|l| !l.is_empty())
            .collect::<Vec<_>>()
            .join("\n");
        if clean_text.is_empty() {
            continue;
        }

        out.push_str(&format_webvtt_timestamp(shifted_start));
        out.push_str(" --> ");
        out.push_str(&format_webvtt_timestamp(shifted_end));
        out.push('\n');
        out.push_str(&clean_text);
        out.push_str("\n\n");
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pip_default_coordinates_stay_inside_1280x720_screen() {
        let mut player = OledMediaPlayer::default();
        player.toggle_picture_in_picture();
        match player.dock_mode {
            PlayerDockMode::FloatingPictureInPicture {
                x,
                y,
                width,
                height,
            } => {
                assert!(x >= 0 && y >= 0);
                assert!(
                    x as u32 + width <= 1280,
                    "PiP right edge off-screen: {}+{}",
                    x,
                    width
                );
                assert!(
                    y as u32 + height <= 720,
                    "PiP bottom edge off-screen: {}+{}",
                    y,
                    height
                );
            }
            other => panic!("Expected FloatingPictureInPicture, got {:?}", other),
        }
    }

    #[test]
    fn test_pip_bounded_for_small_and_ultrawide_viewports() {
        let mut player = OledMediaPlayer::default();

        // Compact 400x300 viewport clamps PiP size & keeps it fully on screen
        player.toggle_picture_in_picture_in_viewport(400, 300);
        if let PlayerDockMode::FloatingPictureInPicture {
            x,
            y,
            width,
            height,
        } = player.dock_mode
        {
            assert!(x >= 0 && y >= 0);
            assert!(x as u32 + width <= 400);
            assert!(y as u32 + height <= 300);
        } else {
            panic!("Expected PiP mode");
        }

        // Clamping explicit off-screen drag coordinates snaps back inside viewport
        player.set_picture_in_picture_bounds(5000, -200, 600, 400, 1280, 720);
        assert_eq!(
            player.dock_mode,
            PlayerDockMode::FloatingPictureInPicture {
                x: 680,
                y: 0,
                width: 600,
                height: 400,
            }
        );
    }

    #[test]
    fn test_srt_ass_vtt_parsing_and_webvtt_offset_conversion() {
        let srt = "\u{FEFF}1\r\n00:00:01,500 --> 00:00:04,250\r\nHello Singularity!\r\nSecond line\r\n\r\n2\r\n00:01:02,000 --> 00:01:05,750\r\nOLED Black UI\r\n";
        let srt_cues = parse_srt(srt);
        assert_eq!(srt_cues.len(), 2);
        assert_eq!(srt_cues[0].start_ms, 1500);
        assert_eq!(srt_cues[0].end_ms, 4250);
        assert_eq!(srt_cues[0].text, "Hello Singularity!\nSecond line");

        let vtt_plus = format_as_webvtt(&srt_cues, 500);
        assert!(vtt_plus.starts_with("WEBVTT\n\n"));
        assert!(vtt_plus.contains("00:00:02.000 --> 00:00:04.750"));
        assert!(vtt_plus.contains("00:01:02.500 --> 00:01:06.250"));

        // Round-trip via parse_vtt
        let reparsed = parse_vtt(&vtt_plus);
        assert_eq!(reparsed.len(), 2);
        assert_eq!(reparsed[0].start_ms, 2000);
        assert_eq!(reparsed[1].end_ms, 66250);

        // Negative offset clamps first cue start to 0 and skips completely negative cues
        let vtt_neg = format_as_webvtt(&srt_cues, -5000);
        let neg_cues = parse_vtt(&vtt_neg);
        assert_eq!(neg_cues.len(), 1);
        assert_eq!(neg_cues[0].start_ms, 57_000);

        // ASS parsing with override tags, commas in dialogue, and \N newlines
        let ass = r#"[Script Info]
Title: Test

[Events]
Format: Layer, Start, End, Style, Name, MarginL, MarginR, MarginV, Effect, Text
Dialogue: 0,0:00:10.50,0:00:14.25,Default,,0,0,0,,{\an8\i1}Bonjour, monde!\N{\b1}Deuxième ligne
Dialogue: 0,0:00:02.00,0:00:05.00,Sign,,0,0,0,,Intro\hCard
"#;
        let ass_cues = parse_ass(ass);
        assert_eq!(ass_cues.len(), 2);
        // Sorted chronologically: Sign (2s) before Default (10.5s)
        assert_eq!(ass_cues[0].start_ms, 2_000);
        assert_eq!(ass_cues[0].text, "Intro Card");
        assert_eq!(ass_cues[0].style_name.as_deref(), Some("Sign"));
        assert_eq!(ass_cues[1].start_ms, 10_500);
        assert_eq!(ass_cues[1].end_ms, 14_250);
        assert_eq!(ass_cues[1].text, "Bonjour, monde!\nDeuxième ligne");
    }

    #[test]
    fn test_ab_loop_video_enhancement_and_tracks() {
        let mut player = OledMediaPlayer {
            duration_sec: 120.0,
            is_playing: true,
            current_time_sec: 15.0,
            ..Default::default()
        };
        assert!(player.set_ab_loop(10.0, 20.0));
        assert!(player.is_ab_loop_active());
        assert!(!player.check_ab_loop_wrap());

        player.current_time_sec = 20.5;
        assert!(player.check_ab_loop_wrap());
        assert!((player.current_time_sec - 10.0).abs() < 1e-9);

        player.video_enhancement = VideoEnhancementConfig {
            rtx_vsr_enabled: true,
            amd_cas_sharpness: 0.65,
            deband_enabled: true,
            auto_crop_21_9: true,
            contrast_boost: 1.15,
            saturation_boost: 1.10,
            ..Default::default()
        };
        assert!(player.video_enhancement.is_any_enhancement_active());
        assert_eq!(
            player.video_enhancement.to_css_filter_string(),
            "contrast(1.15) saturate(1.10)"
        );

        player.tracks.chapters.push(MediaChapterMarker {
            index: 0,
            title: "Opening".into(),
            start_ms: 0,
            end_ms: 30_000,
        });
        player.tracks.chapters.push(MediaChapterMarker {
            index: 1,
            title: "Main Act".into(),
            start_ms: 30_000,
            end_ms: 90_000,
        });
        assert_eq!(
            player.tracks.chapter_at_ms(15_000).map(|c| c.title.as_str()),
            Some("Opening")
        );
        assert_eq!(player.tracks.next_chapter_start_ms(15_000), Some(30_000));
        assert_eq!(player.tracks.prev_chapter_start_ms(45_000), Some(30_000));
    }

    #[test]
    fn test_pip_bounds_large_viewport_no_panic_and_ass_unclosed_braces_linear() {
        let mut player = OledMediaPlayer::default();
        // Viewports > i32::MAX must never wrap negative and panic in i32::clamp
        player.set_picture_in_picture_bounds(500, 300, 480, 270, u32::MAX, u32::MAX);
        assert_eq!(
            player.dock_mode,
            PlayerDockMode::FloatingPictureInPicture {
                x: 500,
                y: 300,
                width: 480,
                height: 270,
            }
        );

        let (bx, by, bw, bh) = compute_bounded_pip_rect(u32::MAX, u32::MAX, 480, 270);
        assert!(bx >= 0 && by >= 0);
        assert_eq!((bw, bh), (480, 270));

        // 50,000 unclosed '{' characters must complete in O(N) while preserving escapes
        let mut adversarial = "{".repeat(50_000);
        adversarial.push_str(r"hello\Nworld\h!");
        let cleaned = clean_ass_dialogue_text(&adversarial);
        assert!(cleaned.starts_with(&"{".repeat(50_000)));
        assert!(cleaned.ends_with("hello\nworld !"));
    }
}
