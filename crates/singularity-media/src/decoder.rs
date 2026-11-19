//! Hardware-Accelerated Video Decoder Backend Selection (VAAPI / NVDEC / Vulkan Video / DXVA2).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HardwareDecodeBackend {
    VaapiDrmZeroCopy,
    NvdecCudaDmaBuf,
    VulkanVideoKhr,
    Dxva2D3d11,
    SoftwareDav1dFfmpeg,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VideoCodec {
    Av1,
    Hevc,
    Vp9,
    H264,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
