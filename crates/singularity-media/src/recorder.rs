//! Direct Lossless Stream Downloader & Recorder (MSE / HLS / DASH / WebM / MP4).

use serde::{Deserialize, Serialize};

/// Maximum RAM buffer cap per recording session (256 MiB) to prevent OOM exhaustion.
pub const MAX_RECORDING_BYTES: usize = 256 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StreamContainerFormat {
    MatroskaMkvLossless,
    FragmentedMp4,
    WebmOpusVp9,
}

impl StreamContainerFormat {
    pub fn container_tag(&self) -> &'static [u8] {
        match self {
            Self::MatroskaMkvLossless => b"MKV",
            Self::FragmentedMp4 => b"MP4",
            Self::WebmOpusVp9 => b"WEBM",
        }
    }
}

/// Captures demuxed elementary stream packets directly from the browser media pipeline
/// with bounded RAM usage.
#[derive(Debug, Default)]
pub struct DirectStreamRecorder {
    is_recording: bool,
    target_format: Option<StreamContainerFormat>,
    captured_segments: Vec<Vec<u8>>,
    total_bytes_captured: usize,
    max_capacity_bytes: usize,
}

impl DirectStreamRecorder {
    pub fn new() -> Self {
        Self::with_capacity_limit(MAX_RECORDING_BYTES)
    }

    pub fn with_capacity_limit(max_capacity_bytes: usize) -> Self {
        Self {
            is_recording: false,
            target_format: None,
            captured_segments: Vec::new(),
            total_bytes_captured: 0,
            max_capacity_bytes: max_capacity_bytes.max(1024),
        }
    }

    pub fn start_recording(&mut self, format: StreamContainerFormat) {
        self.is_recording = true;
        self.target_format = Some(format);
        self.captured_segments.clear();
        self.total_bytes_captured = 0;
    }

    /// Ingests an elementary stream packet if within `max_capacity_bytes`. Returns `false` if capped.
    pub fn ingest_stream_segment(&mut self, packet_bytes: &[u8]) -> bool {
        if !self.is_recording {
            return false;
        }
        let limit = if self.max_capacity_bytes == 0 {
            MAX_RECORDING_BYTES
        } else {
            self.max_capacity_bytes
        };
        let next_total = self.total_bytes_captured.saturating_add(packet_bytes.len());
        if next_total > limit {
            self.is_recording = false;
            return false;
        }
        self.total_bytes_captured = next_total;
        self.captured_segments.push(packet_bytes.to_vec());
        true
    }

    pub fn stop_and_finalize(&mut self) -> Vec<u8> {
        self.is_recording = false;
        let fmt_tag = self
            .target_format
            .map(|f| f.container_tag())
            .unwrap_or(b"RAW");
        let mut output = Vec::with_capacity(self.total_bytes_captured + 16 + fmt_tag.len() + 1);
        output.extend_from_slice(b"SINGULARITY-MUX:");
        output.extend_from_slice(fmt_tag);
        output.push(b':');
        for seg in self.captured_segments.drain(..) {
            output.extend_from_slice(&seg);
        }
        self.total_bytes_captured = 0;
        output
    }

    pub fn target_format(&self) -> Option<StreamContainerFormat> {
        self.target_format
    }

    pub fn is_recording(&self) -> bool {
        self.is_recording
    }

    pub fn total_bytes_captured(&self) -> usize {
        self.total_bytes_captured
    }
}
