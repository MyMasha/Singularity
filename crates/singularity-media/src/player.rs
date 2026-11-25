//! OLED Black Floating & Docked Media Player Controller with Picture-in-Picture (PiP),
//! Frame-by-Frame Scrubbing, `0.1x`–`16.0x` Speed Control, and Custom Subtitle Styling.

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
    let x = vw.saturating_sub(width).saturating_sub(margin_x) as i32;
    let y = vh.saturating_sub(height).saturating_sub(margin_y) as i32;
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
        let max_x = vw.saturating_sub(clamped_w) as i32;
        let max_y = vh.saturating_sub(clamped_h) as i32;
        self.dock_mode = PlayerDockMode::FloatingPictureInPicture {
            x: x.clamp(0, max_x),
            y: y.clamp(0, max_y),
            width: clamped_w,
            height: clamped_h,
        };
    }
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
                assert!(x as u32 + width <= 1280, "PiP right edge off-screen: {}+{}", x, width);
                assert!(y as u32 + height <= 720, "PiP bottom edge off-screen: {}+{}", y, height);
            }
            other => panic!("Expected FloatingPictureInPicture, got {:?}", other),
        }
    }

    #[test]
    fn test_pip_bounded_for_small_and_ultrawide_viewports() {
        let mut player = OledMediaPlayer::default();

        // Compact 400x300 viewport clamps PiP size & keeps it fully on screen
        player.toggle_picture_in_picture_in_viewport(400, 300);
        if let PlayerDockMode::FloatingPictureInPicture { x, y, width, height } = player.dock_mode {
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
}
