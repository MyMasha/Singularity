//! Custom Cursor Engine supporting `.cur`, `.ani` (RIFF ACON), `.png`, `.svg`, and animated WGPU Shaders,
//! plus Global & Per-Domain Website CSS Cursor Override Injection.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CursorFormatError {
    #[error("Invalid .cur binary header (expected reserved=0, type=2)")]
    InvalidCurHeader,
    #[error("Invalid .ani RIFF/ACON animated cursor container")]
    InvalidAniContainer,
    #[error("Unsupported cursor asset format")]
    UnsupportedFormat,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CursorAssetFormat {
    WindowsCur {
        width: u16,
        height: u16,
        hotspot_x: u16,
        hotspot_y: u16,
    },
    AnimatedAni {
        frame_count: u32,
        jif_rate_60hz: u32,
    },
    PngBitmap,
    VectorSvg,
    WgpuShader {
        wgsl_entrypoint: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct CursorTrailSample {
    pub x_px: f32,
    pub y_px: f32,
    pub timestamp_ms: f64,
}

/// Manages custom cursor packs, binary `.cur`/`.ani` decoding, per-domain CSS cursor overrides,
/// and 200Hz+ WGPU particle trail kinematics.
pub struct CustomCursorEngine {
    pub global_override_website_css: bool,
    pub scale_multiplier: f32,
    pub hotspot_offset: (i32, i32),
    pub trail_enabled: bool,
    per_domain_overrides: HashMap<String, String>,
    trail_ring_buffer: VecDeque<CursorTrailSample>,
}

impl Default for CustomCursorEngine {
    fn default() -> Self {
        Self {
            global_override_website_css: true,
            scale_multiplier: 1.0,
            hotspot_offset: (4, 4),
            trail_enabled: true,
            per_domain_overrides: HashMap::new(),
            trail_ring_buffer: VecDeque::with_capacity(64),
        }
    }
}

impl CustomCursorEngine {
    /// Parses a binary Windows `.cur` file header and extracts dimensions and native hotspot coordinates.
    pub fn parse_cur_header(bytes: &[u8]) -> Result<CursorAssetFormat, CursorFormatError> {
        // ICONDIR header: [reserved: u16 = 0, type: u16 = 2 (CUR), count: u16 >= 1]
        // ICONDIRENTRY:   [width: u8, height: u8, color_count: u8, reserved: u8, hotspot_x: u16, hotspot_y: u16, ...]
        if bytes.len() < 22 {
            return Err(CursorFormatError::InvalidCurHeader);
        }
        let reserved = u16::from_le_bytes([bytes[0], bytes[1]]);
        let ico_type = u16::from_le_bytes([bytes[2], bytes[3]]);
        let count = u16::from_le_bytes([bytes[4], bytes[5]]);
        if reserved != 0 || ico_type != 2 || count == 0 {
            return Err(CursorFormatError::InvalidCurHeader);
        }

        let width = if bytes[6] == 0 { 256 } else { u16::from(bytes[6]) };
        let height = if bytes[7] == 0 { 256 } else { u16::from(bytes[7]) };
        let hotspot_x = u16::from_le_bytes([bytes[10], bytes[11]]);
        let hotspot_y = u16::from_le_bytes([bytes[12], bytes[13]]);

        Ok(CursorAssetFormat::WindowsCur {
            width,
            height,
            hotspot_x,
            hotspot_y,
        })
    }

    /// Parses a RIFF `ACON` (`.ani`) animated cursor header and extracts `anih` chunk metadata.
    pub fn parse_ani_header(bytes: &[u8]) -> Result<CursorAssetFormat, CursorFormatError> {
        if bytes.len() < 16 || &bytes[0..4] != b"RIFF" || &bytes[8..12] != b"ACON" {
            return Err(CursorFormatError::InvalidAniContainer);
        }
        // Locate the `anih` sub-chunk inside the RIFF ACON container
        let mut pos = 12usize;
        while pos + 4 <= bytes.len() {
            if &bytes[pos..pos + 4] == b"anih" {
                // Full ANIHEADER chunk: 4B tag + 4B chunk_size + 36B struct
                // struct { cbSize(0), cFrames(4), cSteps(8), cx(12), cy(16), cBitCount(20), cPlanes(24), iDispRate(28), bfAttributes(32) }
                if pos + 44 <= bytes.len() {
                    let chunk_size =
                        u32::from_le_bytes(bytes[pos + 4..pos + 8].try_into().unwrap());
                    if chunk_size >= 36 {
                        let base = pos + 8;
                        let frame_count =
                            u32::from_le_bytes(bytes[base + 4..base + 8].try_into().unwrap())
                                .max(1);
                        let jif_rate_60hz =
                            u32::from_le_bytes(bytes[base + 28..base + 32].try_into().unwrap())
                                .max(1);
                        return Ok(CursorAssetFormat::AnimatedAni {
                            frame_count,
                            jif_rate_60hz,
                        });
                    }
                }
                // Minimal 16-byte RIFF/ACON/anih header marker
                return Ok(CursorAssetFormat::AnimatedAni {
                    frame_count: 1,
                    jif_rate_60hz: 1,
                });
            }
            if pos + 8 > bytes.len() {
                break;
            }
            let chunk_len = u32::from_le_bytes(bytes[pos + 4..pos + 8].try_into().unwrap()) as usize;
            let step = 8usize
                .saturating_add(chunk_len)
                .saturating_add(chunk_len & 1);
            if step == 0 {
                break;
            }
            pos = pos.saturating_add(step);
        }
        Err(CursorFormatError::InvalidAniContainer)
    }

    fn is_safe_cursor_uri(uri: &str) -> bool {
        let trimmed = uri.trim();
        if trimmed.is_empty() || trimmed.len() > 2048 {
            return false;
        }
        let lower = trimmed.to_ascii_lowercase();
        let allowed_scheme = lower.starts_with("singularity://")
            || lower.starts_with("https://")
            || lower.starts_with("data:image/");
        if !allowed_scheme {
            return false;
        }
        !trimmed.chars().any(|c| {
            matches!(c, '\'' | '"' | '(' | ')' | '\\' | ';' | '{' | '}' | '\r' | '\n' | '\0')
                || c.is_control()
        })
    }

    /// Registers a per-domain custom cursor override rule (rejects unsafe CSS-injectable URIs).
    pub fn set_domain_cursor_override(&mut self, domain: &str, cursor_asset_uri: &str) {
        if Self::is_safe_cursor_uri(cursor_asset_uri) {
            self.per_domain_overrides.insert(
                domain.to_ascii_lowercase(),
                cursor_asset_uri.trim().to_string(),
            );
        }
    }

    /// Generates the high-specificity CSS stylesheet injected into Blink frames to override
    /// website-defined `cursor:` declarations globally or per-domain.
    pub fn generate_css_cursor_override_sheet(&self, current_domain: &str) -> Option<String> {
        let domain_lower = current_domain.to_ascii_lowercase();
        if let Some(uri) = self.per_domain_overrides.get(&domain_lower) {
            if Self::is_safe_cursor_uri(uri) {
                return Some(format!(
                    "*, *::before, *::after {{ cursor: url('{}') {} {}, auto !important; }}",
                    uri, self.hotspot_offset.0, self.hotspot_offset.1
                ));
            }
        }
        if self.global_override_website_css {
            return Some(format!(
                "html, body, *, a, button, [role='button'] {{ cursor: url('singularity://cursors/active.svg') {} {}, auto !important; }}",
                self.hotspot_offset.0, self.hotspot_offset.1
            ));
        }
        None
    }

    /// Records a 200Hz+ raw pointer sample into the WGPU accretion trail ring buffer.
    pub fn record_pointer_motion(&mut self, x_px: f32, y_px: f32, timestamp_ms: f64) {
        if self.trail_ring_buffer.len() >= 64 {
            self.trail_ring_buffer.pop_front();
        }
        self.trail_ring_buffer.push_back(CursorTrailSample {
            x_px,
            y_px,
            timestamp_ms,
        });
    }

    pub fn trail_samples(&self) -> &VecDeque<CursorTrailSample> {
        &self.trail_ring_buffer
    }
}
