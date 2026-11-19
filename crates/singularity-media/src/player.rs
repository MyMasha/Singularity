//! OLED Black Floating & Docked Media Player Controller with Picture-in-Picture (PiP),
//! Frame-by-Frame Scrubbing, `0.1x`–`16.0x` Speed Control, and Custom Subtitle Styling.

use serde::{Deserialize, Serialize};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlayerDockMode {
    InlineOledControlBar,
    FloatingPictureInPicture { x: i32, y: i32, width: u32, height: u32 },
    DockedSidebarMiniPlayer,
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

    /// Toggles borderless OLED Picture-in-Picture (PiP) mode.
    pub fn toggle_picture_in_picture(&mut self) {
        self.dock_mode = match self.dock_mode {
            PlayerDockMode::FloatingPictureInPicture { .. } => PlayerDockMode::InlineOledControlBar,
            _ => PlayerDockMode::FloatingPictureInPicture {
                x: 1380,
                y: 760,
                width: 480,
                height: 270,
            },
        };
    }
}
