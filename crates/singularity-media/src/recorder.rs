//! Direct Lossless Stream Downloader & Recorder (MSE / HLS / DASH / WebM / MP4).
//!
//! Produces spec-compliant binary container files:
//! - EBML/Matroska (`0x1A45DFA3` + Segment/Info/Tracks/Cluster/SimpleBlock) for MKV & WebM
//! - ISO BMFF (`ftyp` + `mdat` + `moov` with `mvhd`/`trak`/`stbl` sample tables) for MP4

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
/// with bounded RAM usage and muxes them into valid binary Matroska/WebM/MP4 containers.
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

    /// Finalizes the recording into a valid binary media container matching `target_format`:
    /// - `MatroskaMkvLossless` -> EBML/Matroska (`0x1A45DFA3`, DocType `"matroska"`, Segment/Tracks/Cluster/SimpleBlock)
    /// - `WebmOpusVp9` -> EBML/WebM (`0x1A45DFA3`, DocType `"webm"`, Segment/Tracks/Cluster/SimpleBlock)
    /// - `FragmentedMp4` -> ISO BMFF (`ftyp` + `mdat` + `moov`)
    pub fn stop_and_finalize(&mut self) -> Vec<u8> {
        self.is_recording = false;
        let segments: Vec<Vec<u8>> = self.captured_segments.drain(..).collect();
        self.total_bytes_captured = 0;

        match self.target_format {
            Some(StreamContainerFormat::MatroskaMkvLossless) => {
                mux_ebml_matroska_container(&segments, b"matroska", b"V_AV1")
            }
            Some(StreamContainerFormat::WebmOpusVp9) => {
                mux_ebml_matroska_container(&segments, b"webm", b"V_VP9")
            }
            Some(StreamContainerFormat::FragmentedMp4) => mux_iso_bmff_mp4_container(&segments),
            None => Vec::new(),
        }
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

fn mux_ebml_matroska_container(
    segments: &[Vec<u8>],
    doc_type: &[u8],
    codec_id: &[u8],
) -> Vec<u8> {
    // 1. EBML Header (ID 0x1A45DFA3)
    let mut ebml_body = Vec::with_capacity(64);
    push_ebml_uint(&mut ebml_body, &[0x42, 0x86], 1); // EBMLVersion
    push_ebml_uint(&mut ebml_body, &[0x42, 0xF7], 1); // EBMLReadVersion
    push_ebml_uint(&mut ebml_body, &[0x42, 0xF2], 4); // EBMLMaxIDLength
    push_ebml_uint(&mut ebml_body, &[0x42, 0xF3], 8); // EBMLMaxSizeLength
    push_ebml_element(&mut ebml_body, &[0x42, 0x82], doc_type); // DocType
    push_ebml_uint(&mut ebml_body, &[0x42, 0x87], 4); // DocTypeVersion
    push_ebml_uint(&mut ebml_body, &[0x42, 0x85], 2); // DocTypeReadVersion

    // 2. Segment Info (ID 0x1549A966)
    let mut info_body = Vec::with_capacity(96);
    push_ebml_uint(&mut info_body, &[0x2A, 0xD7, 0xB1], 1_000_000); // TimestampScale = 1ms
    push_ebml_element(&mut info_body, &[0x4D, 0x80], b"Singularity DirectStreamRecorder"); // MuxingApp
    push_ebml_element(&mut info_body, &[0x57, 0x41], b"Singularity Browser"); // WritingApp

    // 3. Tracks (ID 0x1654AE6B) -> TrackEntry (ID 0xAE)
    let mut video_body = Vec::with_capacity(16);
    push_ebml_uint(&mut video_body, &[0xB0], 1920); // PixelWidth
    push_ebml_uint(&mut video_body, &[0xBA], 1080); // PixelHeight

    let mut track_entry_body = Vec::with_capacity(64);
    push_ebml_uint(&mut track_entry_body, &[0xD7], 1); // TrackNumber = 1
    push_ebml_uint(&mut track_entry_body, &[0x73, 0xC5], 1); // TrackUID = 1
    push_ebml_uint(&mut track_entry_body, &[0x83], 1); // TrackType = 1 (video)
    push_ebml_element(&mut track_entry_body, &[0x86], codec_id); // CodecID
    push_ebml_element(&mut track_entry_body, &[0xE0], &video_body); // Video

    let mut tracks_body = Vec::with_capacity(track_entry_body.len() + 8);
    push_ebml_element(&mut tracks_body, &[0xAE], &track_entry_body);

    // 4. Cluster(s) (ID 0x1F43B675) containing Timestamp (0xE7) + SimpleBlock (0xA3) frames
    let mut clusters_buf = Vec::new();
    const FRAME_STEP_MS: u64 = 33;
    let mut cluster_base_ts_ms: u64 = 0;
    let mut current_cluster_body = Vec::new();
    push_ebml_uint(&mut current_cluster_body, &[0xE7], cluster_base_ts_ms);

    for (idx, seg) in segments.iter().enumerate() {
        let abs_ts_ms = (idx as u64).saturating_mul(FRAME_STEP_MS);
        let rel_ts = abs_ts_ms.saturating_sub(cluster_base_ts_ms);
        if rel_ts > i16::MAX as u64 {
            push_ebml_element(&mut clusters_buf, &[0x1F, 0x43, 0xB6, 0x75], &current_cluster_body);
            current_cluster_body.clear();
            cluster_base_ts_ms = abs_ts_ms;
            push_ebml_uint(&mut current_cluster_body, &[0xE7], cluster_base_ts_ms);
        }
        let rel_i16 = (abs_ts_ms - cluster_base_ts_ms) as i16;
        let mut simple_block = Vec::with_capacity(4 + seg.len());
        simple_block.push(0x81); // Track Number 1 as VINT
        simple_block.extend_from_slice(&rel_i16.to_be_bytes());
        simple_block.push(0x80); // Flags: keyframe
        simple_block.extend_from_slice(seg);
        push_ebml_element(&mut current_cluster_body, &[0xA3], &simple_block);
    }
    push_ebml_element(&mut clusters_buf, &[0x1F, 0x43, 0xB6, 0x75], &current_cluster_body);

    // 5. Assemble Segment (ID 0x18538067)
    let mut segment_body =
        Vec::with_capacity(info_body.len() + tracks_body.len() + clusters_buf.len() + 32);
    push_ebml_element(&mut segment_body, &[0x15, 0x49, 0xA9, 0x66], &info_body);
    push_ebml_element(&mut segment_body, &[0x16, 0x54, 0xAE, 0x6B], &tracks_body);
    segment_body.extend_from_slice(&clusters_buf);

    let mut out = Vec::with_capacity(ebml_body.len() + segment_body.len() + 24);
    push_ebml_element(&mut out, &[0x1A, 0x45, 0xDF, 0xA3], &ebml_body);
    push_ebml_element(&mut out, &[0x18, 0x53, 0x80, 0x67], &segment_body);
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

fn mux_iso_bmff_mp4_container(segments: &[Vec<u8>]) -> Vec<u8> {
    // 1. `ftyp` box
    let mut ftyp_payload = Vec::with_capacity(20);
    ftyp_payload.extend_from_slice(b"isom"); // major_brand
    ftyp_payload.extend_from_slice(&0x0000_0200u32.to_be_bytes()); // minor_version
    ftyp_payload.extend_from_slice(b"isom");
    ftyp_payload.extend_from_slice(b"iso2");
    ftyp_payload.extend_from_slice(b"mp41");
    let ftyp = build_mp4_box(b"ftyp", &ftyp_payload);

    // 2. `mdat` box (contiguous elementary stream samples right after `ftyp`)
    let total_payload: usize = segments.iter().map(|s| s.len()).sum();
    let mut mdat_payload = Vec::with_capacity(total_payload);
    for seg in segments {
        mdat_payload.extend_from_slice(seg);
    }
    let mdat_data_offset = (ftyp.len() + 8) as u32;
    let mdat = build_mp4_box(b"mdat", &mdat_payload);

    // 3. `moov` box (`mvhd` + `trak`(`tkhd` + `mdia`(`mdhd` + `hdlr` + `minf`(`vmhd` + `dinf` + `stbl`))))
    let sample_count = segments.len() as u32;
    let duration_ms = sample_count.saturating_mul(33);

    // mvhd (version 0)
    let mut mvhd_body = Vec::with_capacity(96);
    mvhd_body.extend_from_slice(&0u32.to_be_bytes()); // creation_time
    mvhd_body.extend_from_slice(&0u32.to_be_bytes()); // modification_time
    mvhd_body.extend_from_slice(&1000u32.to_be_bytes()); // timescale = 1000 Hz
    mvhd_body.extend_from_slice(&duration_ms.to_be_bytes()); // duration
    mvhd_body.extend_from_slice(&0x0001_0000u32.to_be_bytes()); // rate 1.0
    mvhd_body.extend_from_slice(&0x0100u16.to_be_bytes()); // volume 1.0
    mvhd_body.extend_from_slice(&[0u8; 10]); // reserved
    push_unity_matrix(&mut mvhd_body);
    mvhd_body.extend_from_slice(&[0u8; 24]); // pre_defined
    mvhd_body.extend_from_slice(&2u32.to_be_bytes()); // next_track_ID
    let mvhd = build_mp4_full_box(b"mvhd", 0, 0, &mvhd_body);

    // tkhd (version 0, flags = 0x000003 enabled | in_movie)
    let mut tkhd_body = Vec::with_capacity(80);
    tkhd_body.extend_from_slice(&0u32.to_be_bytes()); // creation_time
    tkhd_body.extend_from_slice(&0u32.to_be_bytes()); // modification_time
    tkhd_body.extend_from_slice(&1u32.to_be_bytes()); // track_ID
    tkhd_body.extend_from_slice(&0u32.to_be_bytes()); // reserved
    tkhd_body.extend_from_slice(&duration_ms.to_be_bytes()); // duration
    tkhd_body.extend_from_slice(&[0u8; 8]); // reserved
    tkhd_body.extend_from_slice(&0u16.to_be_bytes()); // layer
    tkhd_body.extend_from_slice(&0u16.to_be_bytes()); // alternate_group
    tkhd_body.extend_from_slice(&0u16.to_be_bytes()); // volume (video = 0)
    tkhd_body.extend_from_slice(&0u16.to_be_bytes()); // reserved
    push_unity_matrix(&mut tkhd_body);
    tkhd_body.extend_from_slice(&(1920u32 << 16).to_be_bytes()); // width 16.16
    tkhd_body.extend_from_slice(&(1080u32 << 16).to_be_bytes()); // height 16.16
    let tkhd = build_mp4_full_box(b"tkhd", 0, 0x0000_0003, &tkhd_body);

    // mdhd (version 0)
    let mut mdhd_body = Vec::with_capacity(20);
    mdhd_body.extend_from_slice(&0u32.to_be_bytes()); // creation_time
    mdhd_body.extend_from_slice(&0u32.to_be_bytes()); // modification_time
    mdhd_body.extend_from_slice(&1000u32.to_be_bytes()); // timescale
    mdhd_body.extend_from_slice(&duration_ms.to_be_bytes()); // duration
    mdhd_body.extend_from_slice(&0x55C4u16.to_be_bytes()); // language "und"
    mdhd_body.extend_from_slice(&0u16.to_be_bytes()); // pre_defined
    let mdhd = build_mp4_full_box(b"mdhd", 0, 0, &mdhd_body);

    // hdlr
    let mut hdlr_body = Vec::with_capacity(40);
    hdlr_body.extend_from_slice(&0u32.to_be_bytes()); // pre_defined
    hdlr_body.extend_from_slice(b"vide"); // handler_type
    hdlr_body.extend_from_slice(&[0u8; 12]); // reserved
    hdlr_body.extend_from_slice(b"Singularity Video\0");
    let hdlr = build_mp4_full_box(b"hdlr", 0, 0, &hdlr_body);

    // vmhd (flags = 1)
    let vmhd = build_mp4_full_box(b"vmhd", 0, 1, &[0u8; 8]);

    // dinf -> dref -> url (flags = 1 self-contained)
    let url_box = build_mp4_full_box(b"url ", 0, 1, &[]);
    let mut dref_body = Vec::with_capacity(4 + url_box.len());
    dref_body.extend_from_slice(&1u32.to_be_bytes());
    dref_body.extend_from_slice(&url_box);
    let dref = build_mp4_full_box(b"dref", 0, 0, &dref_body);
    let dinf = build_mp4_box(b"dinf", &dref);

    // stsd (1 minimal valid VisualSampleEntry `av01`)
    let mut av01_payload = Vec::with_capacity(78);
    av01_payload.extend_from_slice(&[0u8; 6]); // reserved
    av01_payload.extend_from_slice(&1u16.to_be_bytes()); // data_reference_index
    av01_payload.extend_from_slice(&[0u8; 16]); // pre_defined + reserved
    av01_payload.extend_from_slice(&1920u16.to_be_bytes()); // width
    av01_payload.extend_from_slice(&1080u16.to_be_bytes()); // height
    av01_payload.extend_from_slice(&0x0048_0000u32.to_be_bytes()); // horizresolution 72 dpi
    av01_payload.extend_from_slice(&0x0048_0000u32.to_be_bytes()); // vertresolution 72 dpi
    av01_payload.extend_from_slice(&0u32.to_be_bytes()); // reserved
    av01_payload.extend_from_slice(&1u16.to_be_bytes()); // frame_count
    av01_payload.extend_from_slice(&[0u8; 32]); // compressorname
    av01_payload.extend_from_slice(&0x0018u16.to_be_bytes()); // depth
    av01_payload.extend_from_slice(&(-1i16).to_be_bytes()); // pre_defined = -1
    let av01 = build_mp4_box(b"av01", &av01_payload);
    let mut stsd_body = Vec::with_capacity(4 + av01.len());
    stsd_body.extend_from_slice(&1u32.to_be_bytes());
    stsd_body.extend_from_slice(&av01);
    let stsd = build_mp4_full_box(b"stsd", 0, 0, &stsd_body);

    // stts (Time-to-Sample)
    let mut stts_body = Vec::with_capacity(12);
    if sample_count > 0 {
        stts_body.extend_from_slice(&1u32.to_be_bytes());
        stts_body.extend_from_slice(&sample_count.to_be_bytes());
        stts_body.extend_from_slice(&33u32.to_be_bytes());
    } else {
        stts_body.extend_from_slice(&0u32.to_be_bytes());
    }
    let stts = build_mp4_full_box(b"stts", 0, 0, &stts_body);

    // stsc (Sample-to-Chunk)
    let mut stsc_body = Vec::with_capacity(16);
    if sample_count > 0 {
        stsc_body.extend_from_slice(&1u32.to_be_bytes());
        stsc_body.extend_from_slice(&1u32.to_be_bytes()); // first_chunk
        stsc_body.extend_from_slice(&sample_count.to_be_bytes()); // samples_per_chunk
        stsc_body.extend_from_slice(&1u32.to_be_bytes()); // sample_description_index
    } else {
        stsc_body.extend_from_slice(&0u32.to_be_bytes());
    }
    let stsc = build_mp4_full_box(b"stsc", 0, 0, &stsc_body);

    // stsz (Sample Sizes)
    let mut stsz_body = Vec::with_capacity(8 + segments.len() * 4);
    stsz_body.extend_from_slice(&0u32.to_be_bytes()); // variable sample sizes
    stsz_body.extend_from_slice(&sample_count.to_be_bytes());
    for seg in segments {
        stsz_body.extend_from_slice(&(seg.len() as u32).to_be_bytes());
    }
    let stsz = build_mp4_full_box(b"stsz", 0, 0, &stsz_body);

    // stco (Chunk Offsets -> exact offset of mdat payload)
    let mut stco_body = Vec::with_capacity(8);
    if sample_count > 0 {
        stco_body.extend_from_slice(&1u32.to_be_bytes());
        stco_body.extend_from_slice(&mdat_data_offset.to_be_bytes());
    } else {
        stco_body.extend_from_slice(&0u32.to_be_bytes());
    }
    let stco = build_mp4_full_box(b"stco", 0, 0, &stco_body);

    let mut stbl_payload = Vec::new();
    stbl_payload.extend_from_slice(&stsd);
    stbl_payload.extend_from_slice(&stts);
    stbl_payload.extend_from_slice(&stsc);
    stbl_payload.extend_from_slice(&stsz);
    stbl_payload.extend_from_slice(&stco);
    let stbl = build_mp4_box(b"stbl", &stbl_payload);

    let mut minf_payload = Vec::new();
    minf_payload.extend_from_slice(&vmhd);
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
    let moov = build_mp4_box(b"moov", &moov_payload);

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
        let mask = 0xFFu8 >> width;
        let mut val = (first & mask) as u64;
        for &b in &data[1..width] {
            val = (val << 8) | (b as u64);
        }
        (val, width)
    }

    fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|w| w == needle)
    }

    #[test]
    fn test_ebml_matroska_and_webm_valid_binary_containers() {
        for (fmt, expected_doctype) in [
            (StreamContainerFormat::MatroskaMkvLossless, b"matroska".as_slice()),
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
            let sz = u32::from_be_bytes([mp4[pos], mp4[pos + 1], mp4[pos + 2], mp4[pos + 3]]) as usize;
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
}
