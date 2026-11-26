//! Direct Lossless Stream Downloader & Recorder (MSE / HLS / DASH / WebM / MP4 / WAV).
//!
//! Supports both bounded in-memory recording and unlimited disk-streaming via `BufWriter<File>`:
//! - EBML/Matroska (`0x1A45DFA3` + Segment/Info/Tracks/Cluster/SimpleBlock) for MKV & WebM (Video or Opus Audio-Only)
//! - ISO BMFF (`ftyp` + `mdat` + `moov` with `mvhd`/`trak`/`stbl` sample tables & dynamic PTS/DTS) for MP4
//! - RIFF/WAVE (`RIFF` + `WAVE` + `fmt ` + `data`) for lossless PCM Audio-Only recordings
//! - DRM protection guard (`drm_protected_tab_guard`) blocking capture on protected EME/DRM tabs

use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs::File;
use std::io::{BufWriter, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Maximum RAM buffer cap per in-memory recording session (256 MiB) to prevent OOM exhaustion.
/// Disk streaming mode (`start_file_recording`) bypasses this ceiling via `BufWriter<File>`.
pub const MAX_RECORDING_BYTES: usize = 256 * 1024 * 1024;

/// Maximum buffered cluster size in RAM during EBML disk streaming before flushing to disk.
const DISK_EBML_CLUSTER_FLUSH_BYTES: usize = 64 * 1024;

/// Default frame timestamp increment (ms) when packets are ingested without explicit PTS/DTS.
const DEFAULT_FRAME_STEP_MS: u64 = 33;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StreamContainerFormat {
    MatroskaMkvLossless,
    FragmentedMp4,
    WebmOpusVp9,
    WebmOpusAudioOnly,
    WavPcmAudioOnly,
}

impl StreamContainerFormat {
    pub fn container_tag(&self) -> &'static [u8] {
        match self {
            Self::MatroskaMkvLossless => b"MKV",
            Self::FragmentedMp4 => b"MP4",
            Self::WebmOpusVp9 | Self::WebmOpusAudioOnly => b"WEBM",
            Self::WavPcmAudioOnly => b"WAV",
        }
    }

    pub fn file_extension(&self) -> &'static str {
        match self {
            Self::MatroskaMkvLossless => "mkv",
            Self::FragmentedMp4 => "mp4",
            Self::WebmOpusVp9 | Self::WebmOpusAudioOnly => "webm",
            Self::WavPcmAudioOnly => "wav",
        }
    }

    pub fn is_audio_only(&self) -> bool {
        matches!(self, Self::WebmOpusAudioOnly | Self::WavPcmAudioOnly)
    }
}

/// Errors produced by stream recording, disk streaming, or DRM protection guards.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecorderError {
    /// Capture refused because the active browser tab contains DRM-protected (EME/Widevine/PlayReady) media.
    DrmProtectedContentBlocked { tab_id: Option<u64>, reason: String },
    /// Filesystem or `BufWriter<File>` I/O error.
    IoError(String),
    /// Operation requires an active recording session.
    NotRecording,
    /// Invalid recording parameters (e.g. empty path or unsupported geometry).
    InvalidParameters(String),
}

impl fmt::Display for RecorderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DrmProtectedContentBlocked { tab_id, reason } => match tab_id {
                Some(id) => write!(f, "DRM guard blocked recording on tab {}: {}", id, reason),
                None => write!(f, "DRM guard blocked recording: {}", reason),
            },
            Self::IoError(msg) => write!(f, "Recorder I/O error: {}", msg),
            Self::NotRecording => write!(f, "Recorder is not currently active"),
            Self::InvalidParameters(msg) => write!(f, "Invalid recorder parameters: {}", msg),
        }
    }
}

impl std::error::Error for RecorderError {}

/// Standalone DRM guard refusing recording on DRM-protected browser tabs (Widevine/PlayReady/FairPlay).
pub fn drm_protected_tab_guard(
    is_drm_protected: bool,
    tab_id: Option<u64>,
) -> Result<(), RecorderError> {
    if is_drm_protected {
        Err(RecorderError::DrmProtectedContentBlocked {
            tab_id,
            reason: "Stream recording is prohibited on DRM/EME protected media tabs".into(),
        })
    } else {
        Ok(())
    }
}

/// Per-packet timing and keyframe metadata for dynamic PTS/DTS muxing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordedPacketMeta {
    pub pts_ms: u64,
    pub dts_ms: u64,
    pub is_keyframe: bool,
}

/// Summary returned upon finalizing a disk-streamed recording session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordingSummary {
    pub path: PathBuf,
    pub format: StreamContainerFormat,
    pub total_payload_bytes: u64,
    pub total_file_bytes: u64,
    pub packet_count: u64,
    pub duration_ms: u64,
    pub width: u32,
    pub height: u32,
    pub audio_only: bool,
}

#[derive(Debug, Clone, Copy)]
struct Mp4DiskSampleRecord {
    size: u32,
    pts_ms: u64,
    dts_ms: u64,
}

#[derive(Debug)]
enum DiskFormatState {
    Ebml {
        segment_size_offset: u64,
        segment_body_start: u64,
        cluster_base_ts_ms: u64,
        cluster_opened: bool,
        current_cluster_body: Vec<u8>,
    },
    Mp4 {
        mdat_slot_offset: u64,
        mdat_payload_offset: u64,
        samples: Vec<Mp4DiskSampleRecord>,
    },
    Wav,
}

#[derive(Debug)]
struct DiskStreamSink {
    path: PathBuf,
    writer: BufWriter<File>,
    format: StreamContainerFormat,
    state: DiskFormatState,
}

#[derive(Debug, Clone)]
struct RamPacket {
    data: Vec<u8>,
    meta: RecordedPacketMeta,
}

/// Captures demuxed elementary stream packets directly from the browser media pipeline
/// in either bounded RAM mode (`start_recording`) or unlimited disk-streaming mode
/// (`start_file_recording` using `BufWriter<File>`), muxing valid binary Matroska/WebM/MP4/WAV containers.
#[derive(Debug)]
pub struct DirectStreamRecorder {
    is_recording: bool,
    target_format: Option<StreamContainerFormat>,
    captured_packets: Vec<RamPacket>,
    total_bytes_captured: usize,
    total_payload_bytes_u64: u64,
    packet_count: u64,
    first_pts_ms: Option<u64>,
    last_pts_ms: u64,
    max_capacity_bytes: usize,
    video_width: u32,
    video_height: u32,
    audio_sample_rate_hz: u32,
    audio_channels: u16,
    audio_bits_per_sample: u16,
    audio_only: bool,
    tab_id: Option<u64>,
    drm_protected_tab: bool,
    disk_sink: Option<DiskStreamSink>,
}

impl Default for DirectStreamRecorder {
    fn default() -> Self {
        Self::new()
    }
}

impl DirectStreamRecorder {
    pub fn new() -> Self {
        Self::with_capacity_limit(MAX_RECORDING_BYTES)
    }

    pub fn with_capacity_limit(max_capacity_bytes: usize) -> Self {
        Self {
            is_recording: false,
            target_format: None,
            captured_packets: Vec::new(),
            total_bytes_captured: 0,
            total_payload_bytes_u64: 0,
            packet_count: 0,
            first_pts_ms: None,
            last_pts_ms: 0,
            max_capacity_bytes: max_capacity_bytes.max(1024),
            video_width: 1920,
            video_height: 1080,
            audio_sample_rate_hz: 48_000,
            audio_channels: 2,
            audio_bits_per_sample: 16,
            audio_only: false,
            tab_id: None,
            drm_protected_tab: false,
            disk_sink: None,
        }
    }

    /// Associates this recorder with a browser tab and its DRM/EME protection state.
    pub fn set_tab_context(&mut self, tab_id: Option<u64>, is_drm_protected: bool) {
        self.tab_id = tab_id;
        self.drm_protected_tab = is_drm_protected;
        if is_drm_protected && self.is_recording {
            // Immediately halt capture if DRM becomes active mid-session
            self.is_recording = false;
            self.disk_sink = None;
            self.captured_packets.clear();
            self.total_bytes_captured = 0;
            self.total_payload_bytes_u64 = 0;
        }
    }

    /// Sets whether the currently bound tab contains DRM-protected media.
    pub fn set_drm_protected_tab(&mut self, is_drm_protected: bool) {
        self.set_tab_context(self.tab_id, is_drm_protected);
    }

    pub fn is_drm_protected_tab(&self) -> bool {
        self.drm_protected_tab
    }

    /// Enforces the DRM protection guard for the recorder's bound tab.
    pub fn drm_protected_tab_guard(&self) -> Result<(), RecorderError> {
        drm_protected_tab_guard(self.drm_protected_tab, self.tab_id)
    }

    /// Configures dynamic video dimensions and audio-only mode for subsequent muxing.
    pub fn configure_stream_geometry(&mut self, width: u32, height: u32, audio_only: bool) {
        self.audio_only = audio_only;
        if !audio_only {
            self.video_width = width.clamp(16, 15360);
            self.video_height = height.clamp(16, 8640);
        } else {
            self.video_width = 0;
            self.video_height = 0;
        }
    }

    /// Configures audio track parameters (used for WAV PCM and WebM/MKV Opus headers).
    pub fn configure_audio_params(
        &mut self,
        sample_rate_hz: u32,
        channels: u16,
        bits_per_sample: u16,
    ) {
        self.audio_sample_rate_hz = sample_rate_hz.clamp(8_000, 384_000);
        self.audio_channels = channels.clamp(1, 8);
        self.audio_bits_per_sample = match bits_per_sample {
            8 | 16 | 24 | 32 => bits_per_sample,
            _ => 16,
        };
    }

    /// Starts an in-memory bounded recording session (up to `max_capacity_bytes`).
    /// Silently refuses activation if `drm_protected_tab` is set.
    pub fn start_recording(&mut self, format: StreamContainerFormat) {
        if self.drm_protected_tab {
            self.is_recording = false;
            return;
        }
        self.disk_sink = None;
        self.is_recording = true;
        self.target_format = Some(format);
        self.audio_only = self.audio_only || format.is_audio_only();
        self.captured_packets.clear();
        self.total_bytes_captured = 0;
        self.total_payload_bytes_u64 = 0;
        self.packet_count = 0;
        self.first_pts_ms = None;
        self.last_pts_ms = 0;
    }

    /// Checked variant of [`start_recording`](Self::start_recording) returning a [`RecorderError`]
    /// if the DRM tab guard blocks capture.
    pub fn start_recording_checked(
        &mut self,
        format: StreamContainerFormat,
    ) -> Result<(), RecorderError> {
        self.drm_protected_tab_guard()?;
        self.start_recording(format);
        Ok(())
    }

    /// Starts a disk-streaming recording session writing packets incrementally via `BufWriter<File>`,
    /// lifting the 256 MiB RAM cap for arbitrarily long recordings.
    ///
    /// Refuses to open or create the output file if the bound tab is DRM-protected.
    pub fn start_file_recording<P: AsRef<Path>>(
        &mut self,
        path: P,
        container: StreamContainerFormat,
        width: u32,
        height: u32,
        audio_only: bool,
    ) -> Result<(), RecorderError> {
        self.drm_protected_tab_guard()?;

        let path_buf = path.as_ref().to_path_buf();
        if path_buf.as_os_str().is_empty() {
            return Err(RecorderError::InvalidParameters(
                "Output file path cannot be empty".into(),
            ));
        }

        let effective_audio_only = audio_only || container.is_audio_only();
        let eff_w = if effective_audio_only {
            0
        } else {
            width.clamp(16, 15360)
        };
        let eff_h = if effective_audio_only {
            0
        } else {
            height.clamp(16, 8640)
        };

        let file = File::create(&path_buf)
            .map_err(|e| RecorderError::IoError(format!("Failed to create output file: {}", e)))?;
        let mut writer = BufWriter::with_capacity(64 * 1024, file);

        let state = match container {
            StreamContainerFormat::MatroskaMkvLossless
            | StreamContainerFormat::WebmOpusVp9
            | StreamContainerFormat::WebmOpusAudioOnly => {
                let (doc_type, codec_id): (&[u8], &[u8]) = match (container, effective_audio_only) {
                    (StreamContainerFormat::MatroskaMkvLossless, false) => (b"matroska", b"V_AV1"),
                    (StreamContainerFormat::MatroskaMkvLossless, true) => (b"matroska", b"A_OPUS"),
                    (_, true) => (b"webm", b"A_OPUS"),
                    (_, false) => (b"webm", b"V_VP9"),
                };
                let ebml_header = build_ebml_header_element(doc_type);
                writer.write_all(&ebml_header).map_err(io_err)?;

                // Segment ID + 8-byte unknown-size VINT placeholder (patched on finalize)
                writer.write_all(&[0x18, 0x53, 0x80, 0x67]).map_err(io_err)?;
                let segment_size_offset = writer.stream_position().map_err(io_err)?;
                writer
                    .write_all(&[0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
                    .map_err(io_err)?;
                let segment_body_start = segment_size_offset + 8;

                let info_and_tracks = build_ebml_info_and_tracks(
                    codec_id,
                    eff_w,
                    eff_h,
                    effective_audio_only,
                    self.audio_sample_rate_hz,
                    self.audio_channels,
                );
                writer.write_all(&info_and_tracks).map_err(io_err)?;

                DiskFormatState::Ebml {
                    segment_size_offset,
                    segment_body_start,
                    cluster_base_ts_ms: 0,
                    cluster_opened: false,
                    current_cluster_body: Vec::with_capacity(DISK_EBML_CLUSTER_FLUSH_BYTES + 1024),
                }
            }
            StreamContainerFormat::FragmentedMp4 => {
                let ftyp = build_mp4_ftyp_box();
                writer.write_all(&ftyp).map_err(io_err)?;
                let mdat_slot_offset = writer.stream_position().map_err(io_err)?;
                // Reserve 16 bytes: [8-byte `free` box] + [8-byte `mdat` header], upgradeable in-place
                // to a single 16-byte 64-bit `mdat` box if payload exceeds 4 GiB.
                let mut mdat_placeholder = [0u8; 16];
                mdat_placeholder[0..4].copy_from_slice(&8u32.to_be_bytes());
                mdat_placeholder[4..8].copy_from_slice(b"free");
                mdat_placeholder[8..12].copy_from_slice(&8u32.to_be_bytes());
                mdat_placeholder[12..16].copy_from_slice(b"mdat");
                writer.write_all(&mdat_placeholder).map_err(io_err)?;

                DiskFormatState::Mp4 {
                    mdat_slot_offset,
                    mdat_payload_offset: mdat_slot_offset + 16,
                    samples: Vec::new(),
                }
            }
            StreamContainerFormat::WavPcmAudioOnly => {
                let header = build_wav_header(
                    0,
                    self.audio_sample_rate_hz,
                    self.audio_channels,
                    self.audio_bits_per_sample,
                );
                writer.write_all(&header).map_err(io_err)?;
                DiskFormatState::Wav
            }
        };

        self.video_width = eff_w;
        self.video_height = eff_h;
        self.audio_only = effective_audio_only;
        self.target_format = Some(container);
        self.captured_packets.clear();
        self.total_bytes_captured = 0;
        self.total_payload_bytes_u64 = 0;
        self.packet_count = 0;
        self.first_pts_ms = None;
        self.last_pts_ms = 0;
        self.disk_sink = Some(DiskStreamSink {
            path: path_buf,
            writer,
            format: container,
            state,
        });
        self.is_recording = true;
        Ok(())
    }

    /// Ingests an elementary stream packet using automatic monotonic timestamps (`+33 ms`/packet).
    /// In RAM mode returns `false` if `max_capacity_bytes` would be exceeded.
    /// In disk-streaming mode streams directly to `BufWriter<File>` without RAM ceiling.
    pub fn ingest_stream_segment(&mut self, packet_bytes: &[u8]) -> bool {
        let auto_ts = self.packet_count.saturating_mul(DEFAULT_FRAME_STEP_MS);
        self.ingest_timed_packet(packet_bytes, auto_ts, auto_ts, true)
    }

    /// Ingests an elementary stream packet with explicit PTS/DTS timestamps (ms) and keyframe flag.
    pub fn ingest_timed_packet(
        &mut self,
        packet_bytes: &[u8],
        pts_ms: u64,
        dts_ms: u64,
        is_keyframe: bool,
    ) -> bool {
        if !self.is_recording || self.drm_protected_tab {
            self.is_recording = false;
            return false;
        }

        if let Some(sink) = self.disk_sink.as_mut() {
            let write_res: std::io::Result<()> = match &mut sink.state {
                DiskFormatState::Ebml {
                    cluster_base_ts_ms,
                    cluster_opened,
                    current_cluster_body,
                    ..
                } => {
                    if !*cluster_opened {
                        *cluster_base_ts_ms = pts_ms;
                        current_cluster_body.clear();
                        push_ebml_uint(current_cluster_body, &[0xE7], *cluster_base_ts_ms);
                        *cluster_opened = true;
                    } else {
                        let rel_ts = pts_ms.saturating_sub(*cluster_base_ts_ms);
                        if pts_ms < *cluster_base_ts_ms
                            || rel_ts > i16::MAX as u64
                            || current_cluster_body.len() >= DISK_EBML_CLUSTER_FLUSH_BYTES
                        {
                            if let Err(e) = write_ebml_element_to(
                                &mut sink.writer,
                                &[0x1F, 0x43, 0xB6, 0x75],
                                current_cluster_body,
                            ) {
                                return {
                                    let _ = e;
                                    self.is_recording = false;
                                    false
                                };
                            }
                            current_cluster_body.clear();
                            *cluster_base_ts_ms = pts_ms;
                            push_ebml_uint(current_cluster_body, &[0xE7], *cluster_base_ts_ms);
                        }
                    }

                    let rel_i16 = pts_ms.saturating_sub(*cluster_base_ts_ms).min(i16::MAX as u64) as i16;
                    let mut simple_block = Vec::with_capacity(4 + packet_bytes.len());
                    simple_block.push(0x81); // Track Number 1 as VINT
                    simple_block.extend_from_slice(&rel_i16.to_be_bytes());
                    simple_block.push(if is_keyframe { 0x80 } else { 0x00 });
                    simple_block.extend_from_slice(packet_bytes);
                    push_ebml_element(current_cluster_body, &[0xA3], &simple_block);
                    Ok(())
                }
                DiskFormatState::Mp4 { samples, .. } => {
                    let res = sink.writer.write_all(packet_bytes);
                    if res.is_ok() {
                        samples.push(Mp4DiskSampleRecord {
                            size: packet_bytes.len().min(u32::MAX as usize) as u32,
                            pts_ms,
                            dts_ms,
                        });
                    }
                    res
                }
                DiskFormatState::Wav => sink.writer.write_all(packet_bytes),
            };

            if write_res.is_err() {
                self.is_recording = false;
                return false;
            }

            self.total_payload_bytes_u64 = self
                .total_payload_bytes_u64
                .saturating_add(packet_bytes.len() as u64);
            self.total_bytes_captured =
                self.total_bytes_captured.saturating_add(packet_bytes.len());
            self.packet_count = self.packet_count.saturating_add(1);
            if self.first_pts_ms.is_none() {
                self.first_pts_ms = Some(pts_ms);
            }
            self.last_pts_ms = self.last_pts_ms.max(pts_ms);
            return true;
        }

        // Bounded RAM recording mode
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
        self.total_payload_bytes_u64 = self
            .total_payload_bytes_u64
            .saturating_add(packet_bytes.len() as u64);
        self.packet_count = self.packet_count.saturating_add(1);
        if self.first_pts_ms.is_none() {
            self.first_pts_ms = Some(pts_ms);
        }
        self.last_pts_ms = self.last_pts_ms.max(pts_ms);
        self.captured_packets.push(RamPacket {
            data: packet_bytes.to_vec(),
            meta: RecordedPacketMeta {
                pts_ms,
                dts_ms,
                is_keyframe,
            },
        });
        true
    }

    /// Finalizes an active disk-streaming recording, patching container headers/indices
    /// (`Segment` VINT size, MP4 `mdat` + `moov`, or WAV `RIFF`/`data` sizes) and flushing to disk.
    pub fn stop_and_finalize_file(&mut self) -> Result<RecordingSummary, RecorderError> {
        self.is_recording = false;
        let Some(mut sink) = self.disk_sink.take() else {
            return Err(RecorderError::NotRecording);
        };

        let payload_bytes = self.total_payload_bytes_u64;
        let packet_count = self.packet_count;
        let duration_ms = match self.first_pts_ms {
            Some(first) => self
                .last_pts_ms
                .saturating_sub(first)
                .saturating_add(DEFAULT_FRAME_STEP_MS),
            None => 0,
        };
        self.total_bytes_captured = 0;
        self.total_payload_bytes_u64 = 0;
        self.packet_count = 0;
        self.first_pts_ms = None;
        self.last_pts_ms = 0;

        match &mut sink.state {
            DiskFormatState::Ebml {
                segment_size_offset,
                segment_body_start,
                cluster_opened,
                current_cluster_body,
                ..
            } => {
                if !*cluster_opened {
                    // Emit empty initial cluster so container always has valid Cluster element
                    push_ebml_uint(current_cluster_body, &[0xE7], 0);
                }
                write_ebml_element_to(
                    &mut sink.writer,
                    &[0x1F, 0x43, 0xB6, 0x75],
                    current_cluster_body,
                )
                .map_err(io_err)?;
                current_cluster_body.clear();
                sink.writer.flush().map_err(io_err)?;

                let end_pos = sink.writer.stream_position().map_err(io_err)?;
                let seg_body_len = end_pos.saturating_sub(*segment_body_start);
                if seg_body_len < 0x00FF_FFFF_FFFF_FFFF {
                    sink.writer
                        .seek(SeekFrom::Start(*segment_size_offset))
                        .map_err(io_err)?;
                    let patched_vint = (0x0100_0000_0000_0000u64 | seg_body_len).to_be_bytes();
                    sink.writer.write_all(&patched_vint).map_err(io_err)?;
                    sink.writer.seek(SeekFrom::End(0)).map_err(io_err)?;
                }
            }
            DiskFormatState::Mp4 {
                mdat_slot_offset,
                mdat_payload_offset,
                samples,
            } => {
                sink.writer.flush().map_err(io_err)?;
                let mdat_end = sink.writer.stream_position().map_err(io_err)?;
                let mdat_payload_len = mdat_end.saturating_sub(*mdat_payload_offset);

                // Patch mdat header in-place (32-bit after 8-byte free box, or 64-bit largesize if >4 GiB)
                if 8u64.saturating_add(mdat_payload_len) <= u32::MAX as u64 {
                    let box_sz = (8u64 + mdat_payload_len) as u32;
                    sink.writer
                        .seek(SeekFrom::Start(*mdat_slot_offset + 8))
                        .map_err(io_err)?;
                    sink.writer.write_all(&box_sz.to_be_bytes()).map_err(io_err)?;
                    sink.writer.write_all(b"mdat").map_err(io_err)?;
                } else {
                    let largesize = 16u64.saturating_add(mdat_payload_len);
                    sink.writer
                        .seek(SeekFrom::Start(*mdat_slot_offset))
                        .map_err(io_err)?;
                    sink.writer.write_all(&1u32.to_be_bytes()).map_err(io_err)?;
                    sink.writer.write_all(b"mdat").map_err(io_err)?;
                    sink.writer
                        .write_all(&largesize.to_be_bytes())
                        .map_err(io_err)?;
                }

                // Append moov box at end of file
                sink.writer.seek(SeekFrom::End(0)).map_err(io_err)?;
                let moov = build_mp4_moov_box(
                    samples,
                    *mdat_payload_offset,
                    self.video_width,
                    self.video_height,
                    self.audio_only,
                    self.audio_sample_rate_hz,
                    self.audio_channels,
                );
                sink.writer.write_all(&moov).map_err(io_err)?;
            }
            DiskFormatState::Wav => {
                sink.writer.flush().map_err(io_err)?;
                let data_u32 = payload_bytes.min((u32::MAX - 36) as u64) as u32;
                let riff_size = data_u32.saturating_add(36);
                sink.writer.seek(SeekFrom::Start(4)).map_err(io_err)?;
                sink.writer
                    .write_all(&riff_size.to_le_bytes())
                    .map_err(io_err)?;
                sink.writer.seek(SeekFrom::Start(40)).map_err(io_err)?;
                sink.writer
                    .write_all(&data_u32.to_le_bytes())
                    .map_err(io_err)?;
                sink.writer.seek(SeekFrom::End(0)).map_err(io_err)?;
            }
        }

        sink.writer.flush().map_err(io_err)?;
        let total_file_bytes = sink.writer.stream_position().map_err(io_err)?;

        Ok(RecordingSummary {
            path: sink.path,
            format: sink.format,
            total_payload_bytes: payload_bytes,
            total_file_bytes,
            packet_count,
            duration_ms,
            width: self.video_width,
            height: self.video_height,
            audio_only: self.audio_only,
        })
    }

    /// Finalizes the in-memory recording into a valid binary media container matching `target_format`:
    /// - `MatroskaMkvLossless` -> EBML/Matroska (`0x1A45DFA3`, DocType `"matroska"`, Segment/Tracks/Cluster/SimpleBlock)
    /// - `WebmOpusVp9` / `WebmOpusAudioOnly` -> EBML/WebM (`0x1A45DFA3`, DocType `"webm"`, Segment/Tracks/Cluster/SimpleBlock)
    /// - `FragmentedMp4` -> ISO BMFF (`ftyp` + `mdat` + `moov`)
    /// - `WavPcmAudioOnly` -> RIFF/WAVE PCM (`RIFF` + `WAVE` + `fmt ` + `data`)
    ///
    /// If a disk-streaming recording is active, finalizes and flushes the file cleanly and returns an empty `Vec`.
    pub fn stop_and_finalize(&mut self) -> Vec<u8> {
        if self.disk_sink.is_some() {
            let _ = self.stop_and_finalize_file();
            return Vec::new();
        }

        self.is_recording = false;
        let packets: Vec<RamPacket> = std::mem::take(&mut self.captured_packets);
        self.total_bytes_captured = 0;
        self.total_payload_bytes_u64 = 0;
        self.packet_count = 0;
        self.first_pts_ms = None;
        self.last_pts_ms = 0;

        match self.target_format {
            Some(StreamContainerFormat::MatroskaMkvLossless) => mux_ebml_matroska_container(
                &packets,
                b"matroska",
                if self.audio_only { b"A_OPUS" } else { b"V_AV1" },
                self.video_width,
                self.video_height,
                self.audio_only,
                self.audio_sample_rate_hz,
                self.audio_channels,
            ),
            Some(StreamContainerFormat::WebmOpusVp9) => mux_ebml_matroska_container(
                &packets,
                b"webm",
                if self.audio_only { b"A_OPUS" } else { b"V_VP9" },
                self.video_width,
                self.video_height,
                self.audio_only,
                self.audio_sample_rate_hz,
                self.audio_channels,
            ),
            Some(StreamContainerFormat::WebmOpusAudioOnly) => mux_ebml_matroska_container(
                &packets,
                b"webm",
                b"A_OPUS",
                0,
                0,
                true,
                self.audio_sample_rate_hz,
                self.audio_channels,
            ),
            Some(StreamContainerFormat::FragmentedMp4) => mux_iso_bmff_mp4_container(
                &packets,
                self.video_width,
                self.video_height,
                self.audio_only,
                self.audio_sample_rate_hz,
                self.audio_channels,
            ),
            Some(StreamContainerFormat::WavPcmAudioOnly) => mux_wav_pcm_container(
                &packets,
                self.audio_sample_rate_hz,
                self.audio_channels,
                self.audio_bits_per_sample,
            ),
            None => Vec::new(),
        }
    }

    pub fn target_format(&self) -> Option<StreamContainerFormat> {
        self.target_format
    }

    pub fn is_recording(&self) -> bool {
        self.is_recording
    }

    pub fn is_file_streaming(&self) -> bool {
        self.disk_sink.is_some()
    }

    pub fn total_bytes_captured(&self) -> usize {
        self.total_bytes_captured
    }

    pub fn total_payload_bytes(&self) -> u64 {
        self.total_payload_bytes_u64
    }

    pub fn packet_count(&self) -> u64 {
        self.packet_count
    }

    pub fn video_dimensions(&self) -> (u32, u32) {
        (self.video_width, self.video_height)
    }

    pub fn is_audio_only(&self) -> bool {
        self.audio_only
    }
}

fn io_err(err: std::io::Error) -> RecorderError {
    RecorderError::IoError(err.to_string())
}

// ============================================================================
// EBML / Matroska / WebM Binary Muxer (RFC 8794 / Matroska v4)
// ============================================================================

fn push_ebml_vint_size(out: &mut Vec<u8>, size: u64) {
    if size < 0x7F {
        out.push(0x80 | (size as u8));
    } else if size < 0x3FFF {
        let v = 0x4000u16 | (size as u16);
        out.extend_from_slice(&v.to_be_bytes());
    } else if size < 0x1F_FFFF {
        let v = 0x20_0000u32 | (size as u32);
        let b = v.to_be_bytes();
        out.extend_from_slice(&b[1..4]);
    } else if size < 0x0FFF_FFFF {
        let v = 0x1000_0000u32 | (size as u32);
        out.extend_from_slice(&v.to_be_bytes());
    } else {
        let v = 0x0100_0000_0000_0000u64 | size;
        out.extend_from_slice(&v.to_be_bytes());
    }
}

fn write_ebml_element_to<W: Write>(writer: &mut W, id: &[u8], payload: &[u8]) -> std::io::Result<()> {
    let mut header = Vec::with_capacity(id.len() + 8);
    header.extend_from_slice(id);
    push_ebml_vint_size(&mut header, payload.len() as u64);
    writer.write_all(&header)?;
    writer.write_all(payload)
}

fn encode_ebml_uint_bytes(value: u64) -> Vec<u8> {
    if value == 0 {
        return vec![0];
    }
    let be = value.to_be_bytes();
    let first_non_zero = be.iter().position(|&b| b != 0).unwrap_or(7);
    be[first_non_zero..].to_vec()
}

fn push_ebml_element(out: &mut Vec<u8>, id: &[u8], payload: &[u8]) {
    out.extend_from_slice(id);
    push_ebml_vint_size(out, payload.len() as u64);
    out.extend_from_slice(payload);
}

fn push_ebml_uint(out: &mut Vec<u8>, id: &[u8], value: u64) {
    let bytes = encode_ebml_uint_bytes(value);
    push_ebml_element(out, id, &bytes);
}

fn build_ebml_header_element(doc_type: &[u8]) -> Vec<u8> {
    let mut ebml_body = Vec::with_capacity(64);
    push_ebml_uint(&mut ebml_body, &[0x42, 0x86], 1); // EBMLVersion
    push_ebml_uint(&mut ebml_body, &[0x42, 0xF7], 1); // EBMLReadVersion
    push_ebml_uint(&mut ebml_body, &[0x42, 0xF2], 4); // EBMLMaxIDLength
    push_ebml_uint(&mut ebml_body, &[0x42, 0xF3], 8); // EBMLMaxSizeLength
    push_ebml_element(&mut ebml_body, &[0x42, 0x82], doc_type); // DocType
    push_ebml_uint(&mut ebml_body, &[0x42, 0x87], 4); // DocTypeVersion
    push_ebml_uint(&mut ebml_body, &[0x42, 0x85], 2); // DocTypeReadVersion

    let mut out = Vec::with_capacity(ebml_body.len() + 12);
    push_ebml_element(&mut out, &[0x1A, 0x45, 0xDF, 0xA3], &ebml_body);
    out
}

fn build_ebml_info_and_tracks(
    codec_id: &[u8],
    width: u32,
    height: u32,
    audio_only: bool,
    sample_rate_hz: u32,
    channels: u16,
) -> Vec<u8> {
    // Segment Info (ID 0x1549A966)
    let mut info_body = Vec::with_capacity(96);
    push_ebml_uint(&mut info_body, &[0x2A, 0xD7, 0xB1], 1_000_000); // TimestampScale = 1ms
    push_ebml_element(&mut info_body, &[0x4D, 0x80], b"Singularity DirectStreamRecorder"); // MuxingApp
    push_ebml_element(&mut info_body, &[0x57, 0x41], b"Singularity Browser"); // WritingApp

    // Tracks (ID 0x1654AE6B) -> TrackEntry (ID 0xAE)
    let mut track_entry_body = Vec::with_capacity(64);
    push_ebml_uint(&mut track_entry_body, &[0xD7], 1); // TrackNumber = 1
    push_ebml_uint(&mut track_entry_body, &[0x73, 0xC5], 1); // TrackUID = 1
    if audio_only {
        push_ebml_uint(&mut track_entry_body, &[0x83], 2); // TrackType = 2 (audio)
        push_ebml_element(&mut track_entry_body, &[0x86], codec_id); // CodecID (e.g. A_OPUS)
        let mut audio_body = Vec::with_capacity(16);
        let sr_f32 = (sample_rate_hz.max(8000) as f32).to_be_bytes();
        push_ebml_element(&mut audio_body, &[0xB5], &sr_f32); // SamplingFrequency (float32)
        push_ebml_uint(&mut audio_body, &[0x9F], channels.max(1) as u64); // Channels
        push_ebml_element(&mut track_entry_body, &[0xE1], &audio_body); // Audio
    } else {
        push_ebml_uint(&mut track_entry_body, &[0x83], 1); // TrackType = 1 (video)
        push_ebml_element(&mut track_entry_body, &[0x86], codec_id); // CodecID
        let mut video_body = Vec::with_capacity(16);
        push_ebml_uint(&mut video_body, &[0xB0], width.max(16) as u64); // PixelWidth
        push_ebml_uint(&mut video_body, &[0xBA], height.max(16) as u64); // PixelHeight
        push_ebml_element(&mut track_entry_body, &[0xE0], &video_body); // Video
    }

    let mut tracks_body = Vec::with_capacity(track_entry_body.len() + 8);
    push_ebml_element(&mut tracks_body, &[0xAE], &track_entry_body);

    let mut out = Vec::with_capacity(info_body.len() + tracks_body.len() + 24);
    push_ebml_element(&mut out, &[0x15, 0x49, 0xA9, 0x66], &info_body);
    push_ebml_element(&mut out, &[0x16, 0x54, 0xAE, 0x6B], &tracks_body);
    out
}

#[allow(clippy::too_many_arguments)]
fn mux_ebml_matroska_container(
    packets: &[RamPacket],
    doc_type: &[u8],
    codec_id: &[u8],
    width: u32,
    height: u32,
    audio_only: bool,
    sample_rate_hz: u32,
    channels: u16,
) -> Vec<u8> {
    let ebml_header = build_ebml_header_element(doc_type);
    let info_and_tracks = build_ebml_info_and_tracks(
        codec_id,
        width,
        height,
        audio_only,
        sample_rate_hz,
        channels,
    );

    // Cluster(s) (ID 0x1F43B675) containing Timestamp (0xE7) + SimpleBlock (0xA3) frames
    let mut clusters_buf = Vec::new();
    let mut cluster_base_ts_ms: u64 = packets.first().map(|p| p.meta.pts_ms).unwrap_or(0);
    let mut current_cluster_body = Vec::new();
    push_ebml_uint(&mut current_cluster_body, &[0xE7], cluster_base_ts_ms);

    for pkt in packets {
        let abs_ts_ms = pkt.meta.pts_ms;
        if abs_ts_ms < cluster_base_ts_ms || abs_ts_ms.saturating_sub(cluster_base_ts_ms) > i16::MAX as u64 {
            push_ebml_element(
                &mut clusters_buf,
                &[0x1F, 0x43, 0xB6, 0x75],
                &current_cluster_body,
            );
            current_cluster_body.clear();
            cluster_base_ts_ms = abs_ts_ms;
            push_ebml_uint(&mut current_cluster_body, &[0xE7], cluster_base_ts_ms);
        }
        let rel_i16 = (abs_ts_ms - cluster_base_ts_ms) as i16;
        let mut simple_block = Vec::with_capacity(4 + pkt.data.len());
        simple_block.push(0x81); // Track Number 1 as VINT
        simple_block.extend_from_slice(&rel_i16.to_be_bytes());
        simple_block.push(if pkt.meta.is_keyframe { 0x80 } else { 0x00 });
        simple_block.extend_from_slice(&pkt.data);
        push_ebml_element(&mut current_cluster_body, &[0xA3], &simple_block);
    }
    push_ebml_element(
        &mut clusters_buf,
        &[0x1F, 0x43, 0xB6, 0x75],
        &current_cluster_body,
    );

    let mut segment_body = Vec::with_capacity(info_and_tracks.len() + clusters_buf.len() + 16);
    segment_body.extend_from_slice(&info_and_tracks);
    segment_body.extend_from_slice(&clusters_buf);

    let mut out = Vec::with_capacity(ebml_header.len() + segment_body.len() + 16);
    out.extend_from_slice(&ebml_header);
    push_ebml_element(&mut out, &[0x18, 0x53, 0x80, 0x67], &segment_body);
    out
}

// ============================================================================
// RIFF / WAVE Lossless PCM Audio-Only Binary Muxer
// ============================================================================

fn build_wav_header(
    data_len: u32,
    sample_rate_hz: u32,
    channels: u16,
    bits_per_sample: u16,
) -> [u8; 44] {
    let sr = sample_rate_hz.max(8_000);
    let ch = channels.max(1);
    let bps = match bits_per_sample {
        8 | 16 | 24 | 32 => bits_per_sample,
        _ => 16,
    };
    let block_align = ch.saturating_mul(bps / 8);
    let byte_rate = sr.saturating_mul(block_align as u32);
    let riff_size = data_len.saturating_add(36);

    let mut hdr = [0u8; 44];
    hdr[0..4].copy_from_slice(b"RIFF");
    hdr[4..8].copy_from_slice(&riff_size.to_le_bytes());
    hdr[8..12].copy_from_slice(b"WAVE");
    hdr[12..16].copy_from_slice(b"fmt ");
    hdr[16..20].copy_from_slice(&16u32.to_le_bytes());
    hdr[20..22].copy_from_slice(&1u16.to_le_bytes()); // PCM linear
    hdr[22..24].copy_from_slice(&ch.to_le_bytes());
    hdr[24..28].copy_from_slice(&sr.to_le_bytes());
    hdr[28..32].copy_from_slice(&byte_rate.to_le_bytes());
    hdr[32..34].copy_from_slice(&block_align.to_le_bytes());
    hdr[34..36].copy_from_slice(&bps.to_le_bytes());
    hdr[36..40].copy_from_slice(b"data");
    hdr[40..44].copy_from_slice(&data_len.to_le_bytes());
    hdr
}

fn mux_wav_pcm_container(
    packets: &[RamPacket],
    sample_rate_hz: u32,
    channels: u16,
    bits_per_sample: u16,
) -> Vec<u8> {
    let total_data: usize = packets.iter().map(|p| p.data.len()).sum();
    let data_u32 = total_data.min((u32::MAX - 36) as usize) as u32;
    let header = build_wav_header(data_u32, sample_rate_hz, channels, bits_per_sample);

    let mut out = Vec::with_capacity(44 + total_data);
    out.extend_from_slice(&header);
    for pkt in packets {
        out.extend_from_slice(&pkt.data);
    }
    out
}

// ============================================================================
// ISO BMFF / MP4 Binary Muxer (ISO/IEC 14496-12: ftyp + mdat + moov)
// ============================================================================

fn build_mp4_box(box_type: &[u8; 4], payload: &[u8]) -> Vec<u8> {
    let total_size = (8usize + payload.len()) as u32;
    let mut b = Vec::with_capacity(total_size as usize);
    b.extend_from_slice(&total_size.to_be_bytes());
    b.extend_from_slice(box_type);
    b.extend_from_slice(payload);
    b
}

fn build_mp4_full_box(box_type: &[u8; 4], version: u8, flags: u32, body: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(4 + body.len());
    payload.push(version);
    payload.push(((flags >> 16) & 0xFF) as u8);
    payload.push(((flags >> 8) & 0xFF) as u8);
    payload.push((flags & 0xFF) as u8);
    payload.extend_from_slice(body);
    build_mp4_box(box_type, &payload)
}

fn build_mp4_ftyp_box() -> Vec<u8> {
    let mut ftyp_payload = Vec::with_capacity(20);
    ftyp_payload.extend_from_slice(b"isom"); // major_brand
    ftyp_payload.extend_from_slice(&0x0000_0200u32.to_be_bytes()); // minor_version
    ftyp_payload.extend_from_slice(b"isom");
    ftyp_payload.extend_from_slice(b"iso2");
    ftyp_payload.extend_from_slice(b"mp41");
    build_mp4_box(b"ftyp", &ftyp_payload)
}

fn push_unity_matrix(buf: &mut Vec<u8>) {
    for &word in &[
        0x0001_0000u32,
        0,
        0,
        0,
        0x0001_0000u32,
        0,
        0,
        0,
        0x4000_0000u32,
    ] {
        buf.extend_from_slice(&word.to_be_bytes());
    }
}

fn build_mp4_moov_box(
    samples: &[Mp4DiskSampleRecord],
    mdat_data_offset: u64,
    width: u32,
    height: u32,
    audio_only: bool,
    sample_rate_hz: u32,
    channels: u16,
) -> Vec<u8> {
    let sample_count = samples.len() as u32;

    // Build run-length encoded stts entries from dynamic DTS deltas
    let mut stts_runs: Vec<(u32, u32)> = Vec::new();
    let mut total_duration_ms: u64 = 0;
    if !samples.is_empty() {
        let mut last_delta = DEFAULT_FRAME_STEP_MS as u32;
        for i in 0..samples.len() {
            let delta = if i + 1 < samples.len() {
                let d = samples[i + 1].dts_ms.saturating_sub(samples[i].dts_ms);
                let clamped = d.clamp(1, u32::MAX as u64) as u32;
                last_delta = clamped;
                clamped
            } else {
                last_delta
            };
            total_duration_ms = total_duration_ms.saturating_add(delta as u64);
            if let Some(last) = stts_runs.last_mut() {
                if last.1 == delta {
                    last.0 += 1;
                    continue;
                }
            }
            stts_runs.push((1, delta));
        }
    }
    let duration_ms_u32 = total_duration_ms.min(u32::MAX as u64) as u32;

    // Check if any sample has PTS != DTS requiring a Composition Time-to-Sample (`ctts`) box
    let has_composition_offsets = samples.iter().any(|s| s.pts_ms != s.dts_ms);
    let mut ctts_runs: Vec<(u32, i32)> = Vec::new();
    if has_composition_offsets {
        for s in samples {
            let diff = (s.pts_ms as i128 - s.dts_ms as i128)
                .clamp(i32::MIN as i128, i32::MAX as i128) as i32;
            if let Some(last) = ctts_runs.last_mut() {
                if last.1 == diff {
                    last.0 += 1;
                    continue;
                }
            }
            ctts_runs.push((1, diff));
        }
    }

    let eff_w = if audio_only { 0 } else { width.max(16) };
    let eff_h = if audio_only { 0 } else { height.max(16) };

    // mvhd (version 0)
    let mut mvhd_body = Vec::with_capacity(96);
    mvhd_body.extend_from_slice(&0u32.to_be_bytes());
    mvhd_body.extend_from_slice(&0u32.to_be_bytes());
    mvhd_body.extend_from_slice(&1000u32.to_be_bytes()); // timescale = 1000 Hz
    mvhd_body.extend_from_slice(&duration_ms_u32.to_be_bytes());
    mvhd_body.extend_from_slice(&0x0001_0000u32.to_be_bytes()); // rate 1.0
    mvhd_body.extend_from_slice(&0x0100u16.to_be_bytes()); // volume 1.0
    mvhd_body.extend_from_slice(&[0u8; 10]);
    push_unity_matrix(&mut mvhd_body);
    mvhd_body.extend_from_slice(&[0u8; 24]);
    mvhd_body.extend_from_slice(&2u32.to_be_bytes()); // next_track_ID
    let mvhd = build_mp4_full_box(b"mvhd", 0, 0, &mvhd_body);

    // tkhd (version 0, flags = 0x000003 enabled | in_movie)
    let mut tkhd_body = Vec::with_capacity(80);
    tkhd_body.extend_from_slice(&0u32.to_be_bytes());
    tkhd_body.extend_from_slice(&0u32.to_be_bytes());
    tkhd_body.extend_from_slice(&1u32.to_be_bytes()); // track_ID
    tkhd_body.extend_from_slice(&0u32.to_be_bytes());
    tkhd_body.extend_from_slice(&duration_ms_u32.to_be_bytes());
    tkhd_body.extend_from_slice(&[0u8; 8]);
    tkhd_body.extend_from_slice(&0u16.to_be_bytes()); // layer
    tkhd_body.extend_from_slice(&0u16.to_be_bytes()); // alternate_group
    tkhd_body.extend_from_slice(&(if audio_only { 0x0100u16 } else { 0u16 }).to_be_bytes());
    tkhd_body.extend_from_slice(&0u16.to_be_bytes());
    push_unity_matrix(&mut tkhd_body);
    tkhd_body.extend_from_slice(&(eff_w << 16).to_be_bytes()); // width 16.16
    tkhd_body.extend_from_slice(&(eff_h << 16).to_be_bytes()); // height 16.16
    let tkhd = build_mp4_full_box(b"tkhd", 0, 0x0000_0003, &tkhd_body);

    // mdhd (version 0)
    let mut mdhd_body = Vec::with_capacity(20);
    mdhd_body.extend_from_slice(&0u32.to_be_bytes());
    mdhd_body.extend_from_slice(&0u32.to_be_bytes());
    mdhd_body.extend_from_slice(&1000u32.to_be_bytes());
    mdhd_body.extend_from_slice(&duration_ms_u32.to_be_bytes());
    mdhd_body.extend_from_slice(&0x55C4u16.to_be_bytes()); // "und"
    mdhd_body.extend_from_slice(&0u16.to_be_bytes());
    let mdhd = build_mp4_full_box(b"mdhd", 0, 0, &mdhd_body);

    // hdlr
    let mut hdlr_body = Vec::with_capacity(40);
    hdlr_body.extend_from_slice(&0u32.to_be_bytes());
    if audio_only {
        hdlr_body.extend_from_slice(b"soun");
        hdlr_body.extend_from_slice(&[0u8; 12]);
        hdlr_body.extend_from_slice(b"Singularity Audio\0");
    } else {
        hdlr_body.extend_from_slice(b"vide");
        hdlr_body.extend_from_slice(&[0u8; 12]);
        hdlr_body.extend_from_slice(b"Singularity Video\0");
    }
    let hdlr = build_mp4_full_box(b"hdlr", 0, 0, &hdlr_body);

    // vmhd / smhd
    let media_hdr = if audio_only {
        build_mp4_full_box(b"smhd", 0, 0, &[0u8; 4])
    } else {
        build_mp4_full_box(b"vmhd", 0, 1, &[0u8; 8])
    };

    // dinf -> dref -> url (flags = 1 self-contained)
    let url_box = build_mp4_full_box(b"url ", 0, 1, &[]);
    let mut dref_body = Vec::with_capacity(4 + url_box.len());
    dref_body.extend_from_slice(&1u32.to_be_bytes());
    dref_body.extend_from_slice(&url_box);
    let dref = build_mp4_full_box(b"dref", 0, 0, &dref_body);
    let dinf = build_mp4_box(b"dinf", &dref);

    // stsd (AudioSampleEntry `Opus` or VisualSampleEntry `av01` with dynamic dimensions)
    let sample_entry = if audio_only {
        let mut opus_payload = Vec::with_capacity(28);
        opus_payload.extend_from_slice(&[0u8; 6]); // reserved
        opus_payload.extend_from_slice(&1u16.to_be_bytes()); // data_reference_index
        opus_payload.extend_from_slice(&[0u8; 8]); // reserved
        opus_payload.extend_from_slice(&channels.max(1).to_be_bytes());
        opus_payload.extend_from_slice(&16u16.to_be_bytes()); // sample size
        opus_payload.extend_from_slice(&0u32.to_be_bytes()); // pre_defined + reserved
        opus_payload.extend_from_slice(&(sample_rate_hz.max(8_000) << 16).to_be_bytes());
        build_mp4_box(b"Opus", &opus_payload)
    } else {
        let mut av01_payload = Vec::with_capacity(78);
        av01_payload.extend_from_slice(&[0u8; 6]);
        av01_payload.extend_from_slice(&1u16.to_be_bytes());
        av01_payload.extend_from_slice(&[0u8; 16]);
        av01_payload.extend_from_slice(&(eff_w.min(u16::MAX as u32) as u16).to_be_bytes());
        av01_payload.extend_from_slice(&(eff_h.min(u16::MAX as u32) as u16).to_be_bytes());
        av01_payload.extend_from_slice(&0x0048_0000u32.to_be_bytes()); // 72 dpi
        av01_payload.extend_from_slice(&0x0048_0000u32.to_be_bytes());
        av01_payload.extend_from_slice(&0u32.to_be_bytes());
        av01_payload.extend_from_slice(&1u16.to_be_bytes()); // frame_count
        av01_payload.extend_from_slice(&[0u8; 32]);
        av01_payload.extend_from_slice(&0x0018u16.to_be_bytes()); // depth
        av01_payload.extend_from_slice(&(-1i16).to_be_bytes());
        build_mp4_box(b"av01", &av01_payload)
    };
    let mut stsd_body = Vec::with_capacity(4 + sample_entry.len());
    stsd_body.extend_from_slice(&1u32.to_be_bytes());
    stsd_body.extend_from_slice(&sample_entry);
    let stsd = build_mp4_full_box(b"stsd", 0, 0, &stsd_body);

    // stts (Time-to-Sample)
    let mut stts_body = Vec::with_capacity(4 + stts_runs.len() * 8);
    stts_body.extend_from_slice(&(stts_runs.len() as u32).to_be_bytes());
    for (count, delta) in stts_runs {
        stts_body.extend_from_slice(&count.to_be_bytes());
        stts_body.extend_from_slice(&delta.to_be_bytes());
    }
    let stts = build_mp4_full_box(b"stts", 0, 0, &stts_body);

    // Optional ctts (Composition Time-to-Sample, version 1 signed offsets)
    let ctts = if has_composition_offsets {
        let mut ctts_body = Vec::with_capacity(4 + ctts_runs.len() * 8);
        ctts_body.extend_from_slice(&(ctts_runs.len() as u32).to_be_bytes());
        for (count, offset) in ctts_runs {
            ctts_body.extend_from_slice(&count.to_be_bytes());
            ctts_body.extend_from_slice(&offset.to_be_bytes());
        }
        Some(build_mp4_full_box(b"ctts", 1, 0, &ctts_body))
    } else {
        None
    };

    // stsc (Sample-to-Chunk)
    let mut stsc_body = Vec::with_capacity(16);
    if sample_count > 0 {
        stsc_body.extend_from_slice(&1u32.to_be_bytes());
        stsc_body.extend_from_slice(&1u32.to_be_bytes());
        stsc_body.extend_from_slice(&sample_count.to_be_bytes());
        stsc_body.extend_from_slice(&1u32.to_be_bytes());
    } else {
        stsc_body.extend_from_slice(&0u32.to_be_bytes());
    }
    let stsc = build_mp4_full_box(b"stsc", 0, 0, &stsc_body);

    // stsz (Sample Sizes)
    let mut stsz_body = Vec::with_capacity(8 + samples.len() * 4);
    stsz_body.extend_from_slice(&0u32.to_be_bytes());
    stsz_body.extend_from_slice(&sample_count.to_be_bytes());
    for s in samples {
        stsz_body.extend_from_slice(&s.size.to_be_bytes());
    }
    let stsz = build_mp4_full_box(b"stsz", 0, 0, &stsz_body);

    // stco (32-bit Chunk Offset) or co64 (64-bit Chunk Offset for >4 GiB recordings)
    let chunk_offset_box = if mdat_data_offset <= u32::MAX as u64 {
        let mut stco_body = Vec::with_capacity(8);
        if sample_count > 0 {
            stco_body.extend_from_slice(&1u32.to_be_bytes());
            stco_body.extend_from_slice(&(mdat_data_offset as u32).to_be_bytes());
        } else {
            stco_body.extend_from_slice(&0u32.to_be_bytes());
        }
        build_mp4_full_box(b"stco", 0, 0, &stco_body)
    } else {
        let mut co64_body = Vec::with_capacity(12);
        if sample_count > 0 {
            co64_body.extend_from_slice(&1u32.to_be_bytes());
            co64_body.extend_from_slice(&mdat_data_offset.to_be_bytes());
        } else {
            co64_body.extend_from_slice(&0u32.to_be_bytes());
        }
        build_mp4_full_box(b"co64", 0, 0, &co64_body)
    };

    let mut stbl_payload = Vec::new();
    stbl_payload.extend_from_slice(&stsd);
    stbl_payload.extend_from_slice(&stts);
    if let Some(ctts_box) = ctts {
        stbl_payload.extend_from_slice(&ctts_box);
    }
    stbl_payload.extend_from_slice(&stsc);
    stbl_payload.extend_from_slice(&stsz);
    stbl_payload.extend_from_slice(&chunk_offset_box);
    let stbl = build_mp4_box(b"stbl", &stbl_payload);

    let mut minf_payload = Vec::new();
    minf_payload.extend_from_slice(&media_hdr);
    minf_payload.extend_from_slice(&dinf);
    minf_payload.extend_from_slice(&stbl);
    let minf = build_mp4_box(b"minf", &minf_payload);

    let mut mdia_payload = Vec::new();
    mdia_payload.extend_from_slice(&mdhd);
    mdia_payload.extend_from_slice(&hdlr);
    mdia_payload.extend_from_slice(&minf);
    let mdia = build_mp4_box(b"mdia", &mdia_payload);

    let mut trak_payload = Vec::new();
    trak_payload.extend_from_slice(&tkhd);
    trak_payload.extend_from_slice(&mdia);
    let trak = build_mp4_box(b"trak", &trak_payload);

    let mut moov_payload = Vec::new();
    moov_payload.extend_from_slice(&mvhd);
    moov_payload.extend_from_slice(&trak);
    build_mp4_box(b"moov", &moov_payload)
}

fn mux_iso_bmff_mp4_container(
    packets: &[RamPacket],
    width: u32,
    height: u32,
    audio_only: bool,
    sample_rate_hz: u32,
    channels: u16,
) -> Vec<u8> {
    let ftyp = build_mp4_ftyp_box();

    let total_payload: usize = packets.iter().map(|p| p.data.len()).sum();
    let mut mdat_payload = Vec::with_capacity(total_payload);
    let mut records = Vec::with_capacity(packets.len());
    for pkt in packets {
        mdat_payload.extend_from_slice(&pkt.data);
        records.push(Mp4DiskSampleRecord {
            size: pkt.data.len().min(u32::MAX as usize) as u32,
            pts_ms: pkt.meta.pts_ms,
            dts_ms: pkt.meta.dts_ms,
        });
    }
    let mdat_data_offset = (ftyp.len() + 8) as u64;
    let mdat = build_mp4_box(b"mdat", &mdat_payload);

    let moov = build_mp4_moov_box(
        &records,
        mdat_data_offset,
        width,
        height,
        audio_only,
        sample_rate_hz,
        channels,
    );

    let mut out = Vec::with_capacity(ftyp.len() + mdat.len() + moov.len());
    out.extend_from_slice(&ftyp);
    out.extend_from_slice(&mdat);
    out.extend_from_slice(&moov);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_ebml_vint_size(data: &[u8]) -> (u64, usize) {
        let first = data[0];
        let width = first.leading_zeros() as usize + 1;
        let mask = if width >= 8 { 0 } else { 0xFFu8 >> width };
        let mut val = (first & mask) as u64;
        for &b in &data[1..width] {
            val = (val << 8) | (b as u64);
        }
        (val, width)
    }

    fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|w| w == needle)
    }

    fn temp_test_file(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "singularity_media_test_{}_{}",
            std::process::id(),
            name
        ));
        p
    }

    #[test]
    fn test_ebml_matroska_and_webm_valid_binary_containers() {
        for (fmt, expected_doctype) in [
            (
                StreamContainerFormat::MatroskaMkvLossless,
                b"matroska".as_slice(),
            ),
            (StreamContainerFormat::WebmOpusVp9, b"webm".as_slice()),
        ] {
            let mut rec = DirectStreamRecorder::with_capacity_limit(4096);
            rec.start_recording(fmt);
            assert!(rec.ingest_stream_segment(b"FRAME_ALPHA_01"));
            assert!(rec.ingest_stream_segment(b"FRAME_BETA_02"));
            let data = rec.stop_and_finalize();

            // Must start with valid EBML magic 0x1A45DFA3 (NOT ASCII SINGULARITY-MUX)
            assert_eq!(&data[0..4], &[0x1A, 0x45, 0xDF, 0xA3]);
            assert!(!data.starts_with(b"SINGULARITY-MUX:"));

            let (ebml_len, ebml_vint_w) = decode_ebml_vint_size(&data[4..]);
            let ebml_end = 4 + ebml_vint_w + (ebml_len as usize);
            let ebml_body = &data[4 + ebml_vint_w..ebml_end];
            assert!(find_subslice(ebml_body, expected_doctype).is_some());

            // Followed directly by Segment (0x18538067) whose size matches exact remainder
            assert_eq!(&data[ebml_end..ebml_end + 4], &[0x18, 0x53, 0x80, 0x67]);
            let (seg_len, seg_vint_w) = decode_ebml_vint_size(&data[ebml_end + 4..]);
            let seg_start = ebml_end + 4 + seg_vint_w;
            assert_eq!(seg_start + (seg_len as usize), data.len());
            let seg_body = &data[seg_start..];

            // Segment contains Info (0x1549A966), Tracks (0x1654AE6B), Cluster (0x1F43B675), and SimpleBlocks
            assert!(find_subslice(seg_body, &[0x15, 0x49, 0xA9, 0x66]).is_some());
            assert!(find_subslice(seg_body, &[0x16, 0x54, 0xAE, 0x6B]).is_some());
            assert!(find_subslice(seg_body, &[0x1F, 0x43, 0xB6, 0x75]).is_some());
            assert!(find_subslice(seg_body, b"FRAME_ALPHA_01").is_some());
            assert!(find_subslice(seg_body, b"FRAME_BETA_02").is_some());
        }
    }

    #[test]
    fn test_iso_bmff_mp4_valid_ftyp_mdat_moov_structure() {
        let mut rec = DirectStreamRecorder::with_capacity_limit(4096);
        rec.start_recording(StreamContainerFormat::FragmentedMp4);
        assert!(rec.ingest_stream_segment(b"NALU_IDR_FRAME"));
        assert!(rec.ingest_stream_segment(b"NALU_P_FRAME_2"));
        let mp4 = rec.stop_and_finalize();

        assert!(!mp4.starts_with(b"SINGULARITY-MUX:"));

        // Walk top-level ISO BMFF boxes and verify exact sizes and box order: ftyp -> mdat -> moov
        let mut pos = 0usize;
        let mut box_types = Vec::new();
        let mut mdat_payload = Vec::new();
        while pos < mp4.len() {
            assert!(pos + 8 <= mp4.len());
            let sz = u32::from_be_bytes([mp4[pos], mp4[pos + 1], mp4[pos + 2], mp4[pos + 3]])
                as usize;
            assert!(sz >= 8 && pos + sz <= mp4.len());
            let btype = &mp4[pos + 4..pos + 8];
            box_types.push(btype.to_vec());
            if btype == b"mdat" {
                mdat_payload.extend_from_slice(&mp4[pos + 8..pos + sz]);
            }
            pos += sz;
        }
        assert_eq!(pos, mp4.len());
        assert_eq!(
            box_types,
            vec![b"ftyp".to_vec(), b"mdat".to_vec(), b"moov".to_vec()]
        );
        assert_eq!(mdat_payload, b"NALU_IDR_FRAMENALU_P_FRAME_2");

        // Verify moov contains mvhd, trak, mdia, stbl, stsz, stco
        assert!(find_subslice(&mp4, b"mvhd").is_some());
        assert!(find_subslice(&mp4, b"trak").is_some());
        assert!(find_subslice(&mp4, b"stsz").is_some());
        assert!(find_subslice(&mp4, b"stco").is_some());
    }

    #[test]
    fn test_disk_streaming_bypasses_ram_cap_and_writes_valid_mkv_and_wav() {
        // Set tiny 1024-byte RAM cap and verify file streaming writes >100 KiB cleanly
        let mkv_path = temp_test_file("stream_bypass.mkv");
        let mut rec = DirectStreamRecorder::with_capacity_limit(1024);
        rec.start_file_recording(
            &mkv_path,
            StreamContainerFormat::MatroskaMkvLossless,
            2560,
            1440,
            false,
        )
        .expect("start_file_recording mkv");
        assert!(rec.is_file_streaming());

        let chunk = vec![0xABu8; 4096];
        for i in 0..30u64 {
            assert!(rec.ingest_timed_packet(&chunk, i * 16, i * 16, i % 10 == 0));
        }
        let summary = rec.stop_and_finalize_file().expect("finalize mkv");
        assert_eq!(summary.total_payload_bytes, 30 * 4096);
        assert_eq!(summary.width, 2560);
        assert_eq!(summary.height, 1440);
        assert!(!summary.audio_only);

        let bytes = std::fs::read(&mkv_path).expect("read streamed mkv");
        let _ = std::fs::remove_file(&mkv_path);
        assert_eq!(&bytes[0..4], &[0x1A, 0x45, 0xDF, 0xA3]);
        let (ebml_len, ebml_w) = decode_ebml_vint_size(&bytes[4..]);
        let seg_off = 4 + ebml_w + (ebml_len as usize);
        assert_eq!(&bytes[seg_off..seg_off + 4], &[0x18, 0x53, 0x80, 0x67]);
        let (seg_len, seg_w) = decode_ebml_vint_size(&bytes[seg_off + 4..]);
        assert_eq!(seg_off + 4 + seg_w + (seg_len as usize), bytes.len());
        // Verify dynamic PixelWidth=2560 (0x0A00) and PixelHeight=1440 (0x05A0) encoded in Tracks
        assert!(find_subslice(&bytes[seg_off..seg_off + 256], &[0xB0, 0x82, 0x0A, 0x00]).is_some());
        assert!(find_subslice(&bytes[seg_off..seg_off + 256], &[0xBA, 0x82, 0x05, 0xA0]).is_some());

        // Audio-only WAV disk streaming
        let wav_path = temp_test_file("audio_only.wav");
        rec.configure_audio_params(48_000, 2, 16);
        rec.start_file_recording(
            &wav_path,
            StreamContainerFormat::WavPcmAudioOnly,
            0,
            0,
            true,
        )
        .expect("start_file_recording wav");
        let pcm_chunk = vec![0x11u8; 2048];
        assert!(rec.ingest_stream_segment(&pcm_chunk));
        assert!(rec.ingest_stream_segment(&pcm_chunk));
        let wav_summary = rec.stop_and_finalize_file().expect("finalize wav");
        assert!(wav_summary.audio_only);
        assert_eq!(wav_summary.total_payload_bytes, 4096);
        assert_eq!(wav_summary.total_file_bytes, 44 + 4096);

        let wav = std::fs::read(&wav_path).expect("read wav");
        let _ = std::fs::remove_file(&wav_path);
        assert_eq!(&wav[0..4], b"RIFF");
        assert_eq!(&wav[8..12], b"WAVE");
        assert_eq!(&wav[36..40], b"data");
        assert_eq!(u32::from_le_bytes([wav[40], wav[41], wav[42], wav[43]]), 4096);
    }

    #[test]
    fn test_drm_protected_tab_guard_blocks_recording() {
        assert!(drm_protected_tab_guard(false, Some(7)).is_ok());
        assert!(matches!(
            drm_protected_tab_guard(true, Some(7)),
            Err(RecorderError::DrmProtectedContentBlocked { tab_id: Some(7), .. })
        ));

        let blocked_path = temp_test_file("should_never_exist.mkv");
        let _ = std::fs::remove_file(&blocked_path);

        let mut rec = DirectStreamRecorder::new();
        rec.set_tab_context(Some(42), true);
        let err = rec
            .start_file_recording(
                &blocked_path,
                StreamContainerFormat::MatroskaMkvLossless,
                1920,
                1080,
                false,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            RecorderError::DrmProtectedContentBlocked { tab_id: Some(42), .. }
        ));
        assert!(!blocked_path.exists());
        assert!(!rec.is_recording());
    }
}
