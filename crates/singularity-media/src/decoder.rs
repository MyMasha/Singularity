//! Hardware-Accelerated Video Decoder Backend Selection (VAAPI / NVDEC / Vulkan Video / DXVA2),
//! HDR Color Space Metadata, Live `browser://media-internals` Pipeline Snapshots,
//! and Pure-Rust Platform/Architecture Capability Probing.

use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HardwareDecodeBackend {
    VaapiDrmZeroCopy,
    NvdecCudaDmaBuf,
    VulkanVideoKhr,
    Dxva2D3d11,
    SoftwareDav1dFfmpeg,
}

impl HardwareDecodeBackend {
    /// Returns `true` if this backend executes on fixed-function GPU video decode hardware.
    pub const fn is_hardware_accelerated(&self) -> bool {
        !matches!(self, Self::SoftwareDav1dFfmpeg)
    }

    /// Human-readable label displayed in `browser://media-internals`.
    pub const fn display_name(&self) -> &'static str {
        match self {
            Self::VaapiDrmZeroCopy => "VA-API DRM Zero-Copy",
            Self::NvdecCudaDmaBuf => "NVDEC CUDA DMA-BUF",
            Self::VulkanVideoKhr => "Vulkan Video KHR",
            Self::Dxva2D3d11 => "DXVA2 / D3D11VA",
            Self::SoftwareDav1dFfmpeg => "Software (dav1d / FFmpeg)",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VideoCodec {
    Av1,
    Hevc,
    Vp9,
    H264,
}

impl VideoCodec {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Av1 => "AV1",
            Self::Hevc => "HEVC (H.265)",
            Self::Vp9 => "VP9",
            Self::H264 => "H.264 (AVC)",
        }
    }
}

/// Video dynamic range and color gamut transfer metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub enum HdrColorSpace {
    #[default]
    Sdr,
    Hdr10PqBt2020,
    HlgBt2020,
    DolbyVision,
}

impl HdrColorSpace {
    pub const fn is_hdr(&self) -> bool {
        !matches!(self, Self::Sdr)
    }

    pub const fn bit_depth(&self) -> u8 {
        match self {
            Self::Sdr => 8,
            Self::Hdr10PqBt2020 | Self::HlgBt2020 => 10,
            Self::DolbyVision => 12,
        }
    }

    pub const fn transfer_function_name(&self) -> &'static str {
        match self {
            Self::Sdr => "BT.709",
            Self::Hdr10PqBt2020 => "SMPTE ST 2084 (PQ)",
            Self::HlgBt2020 => "ARIB STD-B67 (HLG)",
            Self::DolbyVision => "Dolby Vision PQ/IPT",
        }
    }

    pub const fn color_primaries_name(&self) -> &'static str {
        match self {
            Self::Sdr => "BT.709",
            Self::Hdr10PqBt2020 | Self::HlgBt2020 | Self::DolbyVision => "BT.2020",
        }
    }
}

/// Active Encrypted Media Extensions (EME) Content Decryption Module (CDM) system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub enum DrmSystemKind {
    #[default]
    None,
    WidevineL1,
    WidevineL3,
    PlayReady,
    FairPlay,
    ClearKey,
}

impl DrmSystemKind {
    pub const fn is_protected(&self) -> bool {
        !matches!(self, Self::None)
    }

    pub const fn display_name(&self) -> &'static str {
        match self {
            Self::None => "None (Clear)",
            Self::WidevineL1 => "Widevine L1 (Hardware TEE)",
            Self::WidevineL3 => "Widevine L3 (Software CDM)",
            Self::PlayReady => "Microsoft PlayReady",
            Self::FairPlay => "Apple FairPlay",
            Self::ClearKey => "W3C ClearKey",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardwareDecoderCapabilities {
    pub active_backend: HardwareDecodeBackend,
    pub zero_copy_dmabuf: bool,
    pub max_resolution: (u32, u32),
    pub max_framerate_fps: u32,
    pub codec_priority: Vec<VideoCodec>,
}

impl Default for HardwareDecoderCapabilities {
    fn default() -> Self {
        Self {
            active_backend: HardwareDecodeBackend::VaapiDrmZeroCopy,
            zero_copy_dmabuf: true,
            max_resolution: (7680, 4320), // 8K60 / 4K240
            max_framerate_fps: 240,
            codec_priority: vec![
                VideoCodec::Av1,
                VideoCodec::Hevc,
                VideoCodec::Vp9,
                VideoCodec::H264,
            ],
        }
    }
}

impl HardwareDecoderCapabilities {
    pub fn is_hardware_accelerated(&self) -> bool {
        self.active_backend.is_hardware_accelerated()
    }

    pub fn supports_codec(&self, codec: VideoCodec) -> bool {
        self.codec_priority.contains(&codec)
    }

    /// Returns the HDR color spaces supported by this decoder backend configuration.
    pub fn supported_hdr_spaces(&self) -> Vec<HdrColorSpace> {
        match self.active_backend {
            HardwareDecodeBackend::NvdecCudaDmaBuf | HardwareDecodeBackend::Dxva2D3d11 => vec![
                HdrColorSpace::Sdr,
                HdrColorSpace::Hdr10PqBt2020,
                HdrColorSpace::HlgBt2020,
                HdrColorSpace::DolbyVision,
            ],
            HardwareDecodeBackend::VaapiDrmZeroCopy | HardwareDecodeBackend::VulkanVideoKhr => {
                vec![
                    HdrColorSpace::Sdr,
                    HdrColorSpace::Hdr10PqBt2020,
                    HdrColorSpace::HlgBt2020,
                ]
            }
            HardwareDecodeBackend::SoftwareDav1dFfmpeg => vec![
                HdrColorSpace::Sdr,
                HdrColorSpace::Hdr10PqBt2020,
            ],
        }
    }
}

/// Live per-pipeline diagnostic snapshot exposed to `browser://media-internals`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MediaPipelineSnapshot {
    pub tab_id: u64,
    pub url: String,
    pub video_codec: VideoCodec,
    pub audio_codec: String,
    pub decoder_backend: HardwareDecodeBackend,
    pub is_hardware_accelerated: bool,
    pub zero_copy_dmabuf: bool,
    pub resolution: (u32, u32),
    pub fps: f64,
    pub decoded_frames: u64,
    pub dropped_frames: u64,
    pub hdr_color_space: HdrColorSpace,
    pub drm_system: DrmSystemKind,
    pub is_drm_protected: bool,
    pub audio_sample_rate_hz: u32,
    pub bitrate_kbps: u32,
    pub buffer_ahead_sec: f64,
}

impl Default for MediaPipelineSnapshot {
    fn default() -> Self {
        Self {
            tab_id: 0,
            url: String::new(),
            video_codec: VideoCodec::Av1,
            audio_codec: "Opus".into(),
            decoder_backend: HardwareDecodeBackend::VaapiDrmZeroCopy,
            is_hardware_accelerated: true,
            zero_copy_dmabuf: true,
            resolution: (1920, 1080),
            fps: 60.0,
            decoded_frames: 0,
            dropped_frames: 0,
            hdr_color_space: HdrColorSpace::Sdr,
            drm_system: DrmSystemKind::None,
            is_drm_protected: false,
            audio_sample_rate_hz: 48_000,
            bitrate_kbps: 0,
            buffer_ahead_sec: 0.0,
        }
    }
}

impl MediaPipelineSnapshot {
    /// Percentage of dropped video frames relative to total decoded frames (`0.0..=100.0`).
    pub fn drop_rate_percent(&self) -> f64 {
        if self.decoded_frames == 0 {
            0.0
        } else {
            ((self.dropped_frames as f64) / (self.decoded_frames as f64) * 100.0).clamp(0.0, 100.0)
        }
    }

    pub fn decoder_label(&self) -> &'static str {
        self.decoder_backend.display_name()
    }

    /// Formats a concise diagnostic readout for `browser://media-internals`.
    pub fn format_internals_summary(&self) -> String {
        format!(
            "tab={} codec={}/{} decoder={} hw={} res={}x{}@{:.2}fps dropped={}/{} ({:.2}%) hdr={:?} drm={}",
            self.tab_id,
            self.video_codec.as_str(),
            self.audio_codec,
            self.decoder_backend.display_name(),
            self.is_hardware_accelerated,
            self.resolution.0,
            self.resolution.1,
            self.fps,
            self.dropped_frames,
            self.decoded_frames,
            self.drop_rate_percent(),
            self.hdr_color_space,
            self.drm_system.display_name()
        )
    }
}

/// Deterministic capability resolver for a given `(os, arch, has_nvidia_device, has_drm_render_node)`.
pub fn probe_capabilities_for_target(
    os: &str,
    arch: &str,
    has_nvidia_device: bool,
    has_drm_render_node: bool,
) -> HardwareDecoderCapabilities {
    let is_64bit_desktop = matches!(arch, "x86_64" | "aarch64");
    match os {
        "linux" => {
            if has_nvidia_device {
                HardwareDecoderCapabilities {
                    active_backend: HardwareDecodeBackend::NvdecCudaDmaBuf,
                    zero_copy_dmabuf: true,
                    max_resolution: (7680, 4320),
                    max_framerate_fps: 240,
                    codec_priority: vec![
                        VideoCodec::Av1,
                        VideoCodec::Hevc,
                        VideoCodec::Vp9,
                        VideoCodec::H264,
                    ],
                }
            } else if has_drm_render_node {
                HardwareDecoderCapabilities {
                    active_backend: HardwareDecodeBackend::VaapiDrmZeroCopy,
                    zero_copy_dmabuf: true,
                    max_resolution: if is_64bit_desktop {
                        (7680, 4320)
                    } else {
                        (3840, 2160)
                    },
                    max_framerate_fps: if is_64bit_desktop { 240 } else { 60 },
                    codec_priority: vec![
                        VideoCodec::Av1,
                        VideoCodec::Vp9,
                        VideoCodec::Hevc,
                        VideoCodec::H264,
                    ],
                }
            } else {
                HardwareDecoderCapabilities {
                    active_backend: HardwareDecodeBackend::SoftwareDav1dFfmpeg,
                    zero_copy_dmabuf: false,
                    max_resolution: (3840, 2160),
                    max_framerate_fps: 60,
                    codec_priority: vec![
                        VideoCodec::Av1,
                        VideoCodec::Vp9,
                        VideoCodec::H264,
                        VideoCodec::Hevc,
                    ],
                }
            }
        }
        "windows" => HardwareDecoderCapabilities {
            active_backend: HardwareDecodeBackend::Dxva2D3d11,
            zero_copy_dmabuf: false,
            max_resolution: if is_64bit_desktop {
                (7680, 4320)
            } else {
                (3840, 2160)
            },
            max_framerate_fps: if is_64bit_desktop { 240 } else { 120 },
            codec_priority: vec![
                VideoCodec::Av1,
                VideoCodec::Hevc,
                VideoCodec::Vp9,
                VideoCodec::H264,
            ],
        },
        "macos" => HardwareDecoderCapabilities {
            active_backend: HardwareDecodeBackend::VulkanVideoKhr,
            zero_copy_dmabuf: false,
            max_resolution: (7680, 4320),
            max_framerate_fps: 120,
            codec_priority: if arch == "aarch64" {
                vec![
                    VideoCodec::Av1,
                    VideoCodec::Hevc,
                    VideoCodec::H264,
                    VideoCodec::Vp9,
                ]
            } else {
                vec![
                    VideoCodec::Hevc,
                    VideoCodec::H264,
                    VideoCodec::Vp9,
                    VideoCodec::Av1,
                ]
            },
        },
        _ => HardwareDecoderCapabilities {
            active_backend: HardwareDecodeBackend::SoftwareDav1dFfmpeg,
            zero_copy_dmabuf: false,
            max_resolution: (3840, 2160),
            max_framerate_fps: 60,
            codec_priority: vec![
                VideoCodec::Av1,
                VideoCodec::Vp9,
                VideoCodec::H264,
                VideoCodec::Hevc,
            ],
        },
    }
}

/// Probes the current host platform, CPU architecture, and GPU device nodes (pure Rust, zero FFI)
/// to determine optimal hardware video decoder capabilities.
pub fn probe_platform_capabilities() -> HardwareDecoderCapabilities {
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    let has_nvidia = if os == "linux" {
        Path::new("/dev/nvidia0").exists() || Path::new("/dev/nvidiactl").exists()
    } else {
        false
    };
    let has_drm_render = if os == "linux" {
        Path::new("/dev/dri/renderD128").exists() || Path::new("/dev/dri/renderD129").exists()
    } else {
        false
    };
    probe_capabilities_for_target(os, arch, has_nvidia, has_drm_render)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hdr_color_space_and_pipeline_snapshot() {
        assert!(!HdrColorSpace::Sdr.is_hdr());
        assert_eq!(HdrColorSpace::Sdr.bit_depth(), 8);
        assert!(HdrColorSpace::Hdr10PqBt2020.is_hdr());
        assert_eq!(HdrColorSpace::Hdr10PqBt2020.bit_depth(), 10);
        assert_eq!(HdrColorSpace::HlgBt2020.color_primaries_name(), "BT.2020");
        assert_eq!(HdrColorSpace::DolbyVision.bit_depth(), 12);

        let snap = MediaPipelineSnapshot {
            tab_id: 3,
            url: "https://example.org/4k-hdr.mp4".into(),
            video_codec: VideoCodec::Av1,
            audio_codec: "Opus".into(),
            decoder_backend: HardwareDecodeBackend::NvdecCudaDmaBuf,
            is_hardware_accelerated: true,
            zero_copy_dmabuf: true,
            resolution: (3840, 2160),
            fps: 60.0,
            decoded_frames: 1000,
            dropped_frames: 5,
            hdr_color_space: HdrColorSpace::Hdr10PqBt2020,
            drm_system: DrmSystemKind::WidevineL1,
            is_drm_protected: true,
            audio_sample_rate_hz: 48_000,
            bitrate_kbps: 24_500,
            buffer_ahead_sec: 12.5,
        };
        assert!((snap.drop_rate_percent() - 0.5).abs() < 1e-6);
        let summary = snap.format_internals_summary();
        assert!(summary.contains("AV1/Opus"));
        assert!(summary.contains("3840x2160"));
        assert!(summary.contains("Hdr10PqBt2020"));
        assert!(summary.contains("Widevine L1"));
    }

    #[test]
    fn test_probe_platform_capabilities_matrix() {
        let linux_nv = probe_capabilities_for_target("linux", "x86_64", true, true);
        assert_eq!(
            linux_nv.active_backend,
            HardwareDecodeBackend::NvdecCudaDmaBuf
        );
        assert!(linux_nv.zero_copy_dmabuf);

        let linux_vaapi = probe_capabilities_for_target("linux", "x86_64", false, true);
        assert_eq!(
            linux_vaapi.active_backend,
            HardwareDecodeBackend::VaapiDrmZeroCopy
        );

        let linux_sw = probe_capabilities_for_target("linux", "x86_64", false, false);
        assert_eq!(
            linux_sw.active_backend,
            HardwareDecodeBackend::SoftwareDav1dFfmpeg
        );
        assert!(!linux_sw.is_hardware_accelerated());

        let win = probe_capabilities_for_target("windows", "x86_64", false, false);
        assert_eq!(win.active_backend, HardwareDecodeBackend::Dxva2D3d11);

        // Live host probe never panics and yields at least one supported codec
        let host = probe_platform_capabilities();
        assert!(!host.codec_priority.is_empty());
        assert!(host.max_resolution.0 >= 1920);
    }
}
