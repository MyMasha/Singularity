//! `singularity-media` — Hardware-Accelerated VAAPI/NVDEC/DXVA2 Media Pipeline,
//! 10-Band Parametric Biquad Audio Equalizer, 600% Volume Booster, ITU-R BS.1770-4 / EBU R128
//! Loudness Normalizer, Dynamic Range Compressor, PiP, A-B Loop, Pure-Rust Subtitle Converter,
//! Disk-Streaming Recorder with DRM Guard, Global Media Controls (SMTC/MPRIS),
//! Read Aloud TTS, and Local Real-Time Live Captions.

pub mod decoder;
pub mod equalizer;
pub mod live_captions;
pub mod media_session;
pub mod player;
pub mod recorder;
pub mod tts_engine;

pub use decoder::{
    probe_capabilities_for_target, probe_platform_capabilities, DrmSystemKind,
    HardwareDecodeBackend, HardwareDecoderCapabilities, HdrColorSpace, MediaPipelineSnapshot,
    VideoCodec,
};
pub use equalizer::{
    soft_clip_sample, CompressorConfig, DynamicRangeCompressor, EqualizerPreset,
    LoudnessNormalizer, ParametricBandConfig, PerTabAudioDspManager, TabAudioDspProfile,
    TenBandParametricEqualizer, ISO_10_BAND_FREQUENCIES_HZ, LUFS_TARGET_PODCAST,
    LUFS_TARGET_STREAMING, MAX_VOLUME_BOOST_PERCENT,
};
pub use live_captions::{
    downsample_interleaved_stereo_to_16khz_mono, format_captions_as_srt, format_captions_as_txt,
    CaptionModelSize, CaptionSegment, LiveCaptionsConfig, LiveCaptionsEngine, VadFrameDecision,
    VoiceActivityDetector, DEFAULT_CAPTION_BUFFER_CAPACITY, VAD_SAMPLE_RATE_HZ,
};
pub use media_session::{
    MediaControlAction, MediaSessionRegistry, OsTransportMetadata, TabMediaSession,
};
pub use player::{
    compute_bounded_pip_rect, format_as_webvtt, parse_ass, parse_srt, parse_vtt,
    LocalMediaTrackInfo, MediaAudioTrack, MediaChapterMarker, MediaSubtitleTrack, OledMediaPlayer,
    PlayerDockMode, SubtitleCue, SubtitleStyleConfig, VideoEnhancementConfig,
};
pub use recorder::{
    drm_protected_tab_guard, DirectStreamRecorder, RecordedPacketMeta, RecorderError,
    RecordingSummary, StreamContainerFormat, MAX_RECORDING_BYTES,
};
pub use tts_engine::{
    segment_text_for_read_aloud, ReadAloudProgress, ReadAloudSession, ReadAloudState,
    TextSentenceSegment, TtsBackendKind, TtsConfig, TtsVoiceInfo, TTS_MAX_RATE, TTS_MIN_RATE,
};

#[cfg(test)]
mod tests {
    use super::*;
    use std::f64::consts::PI;

    #[test]
    fn test_10_band_parametric_eq_and_400_percent_volume_boost() {
        let mut eq = TenBandParametricEqualizer::new(48000.0);
        eq.set_band_gain_db(0, 6.0, 1.414); // +6 dB sub-bass boost at 31.25 Hz
        eq.set_band_gain_db(5, 3.0, 1.414); // +3 dB vocal boost at 1 kHz
        eq.set_volume_boost_percent(400.0); // 400% volume boost

        let mut samples = vec![0.4f32, -0.4f32, 0.5f32, -0.5f32, 0.6f32, -0.6f32];
        eq.process_interleaved_stereo_pcm(&mut samples);

        // Soft limiter prevents any sample from exceeding [-1.0, 1.0] even at 400% boost
        for &s in &samples {
            assert!(
                (-1.0..=1.0).contains(&s),
                "Sample clipped out of bounds: {}",
                s
            );
        }
        assert!(samples[0] > 0.85);
    }

    #[test]
    fn test_frame_by_frame_scrubbing_and_speed_bounds() {
        let mut player = OledMediaPlayer {
            stream_fps: 60.0,
            current_time_sec: 10.0,
            ..Default::default()
        };

        // Step +1 frame at 60fps -> +1/60s
        let t1 = player.step_frames(1);
        assert!((t1 - 10.0166666).abs() < 1e-4);

        // Speed clamping [0.1x, 16.0x]
        player.set_playback_speed(32.0);
        assert_eq!(player.playback_speed, 16.0);
        player.set_playback_speed(0.01);
        assert_eq!(player.playback_speed, 0.1);

        player.toggle_picture_in_picture();
        assert!(matches!(
            player.dock_mode,
            PlayerDockMode::FloatingPictureInPicture { .. }
        ));
    }

    #[test]
    fn test_direct_stream_recorder() {
        let mut rec = DirectStreamRecorder::with_capacity_limit(1024);
        rec.start_recording(StreamContainerFormat::MatroskaMkvLossless);
        assert!(rec.ingest_stream_segment(b"AV1_FRAME_01"));
        assert!(rec.ingest_stream_segment(b"OPUS_PKT_01"));
        // Reject oversized segment exceeding cap
        assert!(!rec.ingest_stream_segment(&vec![0u8; 2048]));
        let muxed = rec.stop_and_finalize();
        assert!(muxed.starts_with(&[0x1A, 0x45, 0xDF, 0xA3]));
        assert!(muxed.windows(b"matroska".len()).any(|w| w == b"matroska"));
        assert!(muxed
            .windows(b"AV1_FRAME_01".len())
            .any(|w| w == b"AV1_FRAME_01"));
        assert!(muxed
            .windows(b"OPUS_PKT_01".len())
            .any(|w| w == b"OPUS_PKT_01"));
    }

    #[test]
    fn test_eq_600_percent_ebu_r128_compressor_and_per_tab_dsp_pipeline() {
        let sr = 48_000.0;
        let mut manager = PerTabAudioDspManager::new(sr);

        // Verify all 6 presets apply cleanly
        for &preset in EqualizerPreset::all() {
            manager.set_tab_preset(1, preset);
            let expected = preset.band_gains_db();
            let actual: [f64; 10] =
                std::array::from_fn(|i| manager.get_tab(1).unwrap().equalizer.bands()[i].gain_db);
            assert_eq!(actual, expected);
        }

        // Configure Tab 1 with 600% boost (+15.6 dB), EBU R128 (-14 LUFS), Night Mode compressor, and custom output
        manager.set_tab_preset(1, EqualizerPreset::HarmanOverEar2018);
        manager.set_tab_volume_boost(1, 600.0);
        manager.set_tab_loudness_normalization(1, true, LUFS_TARGET_STREAMING);
        manager.set_tab_compressor(1, CompressorConfig::night_mode());
        manager.set_tab_output_device(1, Some("studio-dac-out".into()));

        assert_eq!(
            manager.get_tab(1).unwrap().equalizer.volume_boost_percent(),
            600.0
        );
        assert_eq!(manager.effective_output_device(1), Some("studio-dac-out"));

        // Feed 0.6s stereo 1 kHz sine through the entire chain and verify strict [-1, 1] limiter safety
        let frames = (sr * 0.6) as usize;
        let mut pcm = Vec::with_capacity(frames * 2);
        for i in 0..frames {
            let v = (0.35 * (2.0 * PI * 1000.0 * (i as f64) / sr).sin()) as f32;
            pcm.push(v);
            pcm.push(-v);
        }
        manager.process_tab_pcm(1, &mut pcm);

        for &s in &pcm {
            assert!(
                s.is_finite() && (-1.0..=1.0).contains(&s),
                "Pipeline sample exceeded limiter ceiling: {}",
                s
            );
        }

        // Verify silence gate on LoudnessNormalizer never boosts near-zero noise floor
        let mut silent_norm = LoudnessNormalizer::new(sr, LUFS_TARGET_PODCAST);
        let mut silence = vec![1e-6f32; 4800 * 2];
        silent_norm.process_interleaved_stereo_pcm(&mut silence);
        assert!(
            silent_norm.current_gain_db().abs() < 0.1,
            "Silence gate should hold unity gain, got {} dB",
            silent_norm.current_gain_db()
        );
    }

    #[test]
    fn test_srt_and_ass_conversion_to_webvtt_with_sync_offset() {
        let srt = "1\n00:00:03,000 --> 00:00:06,500\nWelcome to Singularity\n\n2\n00:00:07,250 --> 00:00:10,000\nHardware AV1 Active\n";
        let srt_cues = parse_srt(srt);
        assert_eq!(srt_cues.len(), 2);

        let vtt_shifted = format_as_webvtt(&srt_cues, -1000);
        let round_trip = parse_vtt(&vtt_shifted);
        assert_eq!(round_trip.len(), 2);
        assert_eq!(round_trip[0].start_ms, 2_000);
        assert_eq!(round_trip[0].end_ms, 5_500);
        assert_eq!(round_trip[1].start_ms, 6_250);
        assert_eq!(round_trip[1].text, "Hardware AV1 Active");

        let ass = "[Events]\nFormat: Layer, Start, End, Style, Name, MarginL, MarginR, MarginV, Effect, Text\nDialogue: 0,0:00:01.20,0:00:03.80,Main,,0,0,0,,{\\fs32\\an2}Line A, with comma\\NLine B\n";
        let ass_cues = parse_ass(ass);
        assert_eq!(ass_cues.len(), 1);
        assert_eq!(ass_cues[0].start_ms, 1_200);
        assert_eq!(ass_cues[0].end_ms, 3_800);
        assert_eq!(ass_cues[0].text, "Line A, with comma\nLine B");

        let ass_as_vtt = format_as_webvtt(&ass_cues, 250);
        assert!(ass_as_vtt.contains("00:00:01.450 --> 00:00:04.050"));
        assert!(ass_as_vtt.contains("Line A, with comma\nLine B"));
    }

    #[test]
    fn test_disk_streaming_mp4_webm_opus_and_drm_guard() {
        let mut p_mp4 = std::env::temp_dir();
        p_mp4.push(format!("singularity_int_{}_video.mp4", std::process::id()));
        let mut p_webm = std::env::temp_dir();
        p_webm.push(format!(
            "singularity_int_{}_audio.webm",
            std::process::id()
        ));

        // 1. MP4 disk streaming with dynamic 4K dimensions & B-frame PTS != DTS (triggers ctts box)
        let mut rec = DirectStreamRecorder::with_capacity_limit(1024);
        rec.start_file_recording(
            &p_mp4,
            StreamContainerFormat::FragmentedMp4,
            3840,
            2160,
            false,
        )
        .expect("start mp4 disk stream");
        assert!(rec.ingest_timed_packet(b"IDR_KEYFRAME_DATA", 66, 0, true));
        assert!(rec.ingest_timed_packet(b"B_FRAME_DATA_01", 33, 33, false));
        assert!(rec.ingest_timed_packet(b"P_FRAME_DATA_02", 132, 66, false));
        let mp4_summary = rec.stop_and_finalize_file().expect("finalize mp4");
        assert_eq!(mp4_summary.width, 3840);
        assert_eq!(mp4_summary.height, 2160);
        assert_eq!(mp4_summary.packet_count, 3);

        let mp4_bytes = std::fs::read(&p_mp4).expect("read mp4");
        let _ = std::fs::remove_file(&p_mp4);
        assert!(mp4_bytes.windows(4).any(|w| w == b"ftyp"));
        assert!(mp4_bytes.windows(4).any(|w| w == b"mdat"));
        assert!(mp4_bytes.windows(4).any(|w| w == b"moov"));
        assert!(mp4_bytes.windows(4).any(|w| w == b"ctts")); // dynamic PTS/DTS offset table emitted

        // 2. WebM Opus audio-only disk streaming
        rec.start_file_recording(
            &p_webm,
            StreamContainerFormat::WebmOpusAudioOnly,
            0,
            0,
            true,
        )
        .expect("start webm audio-only stream");
        assert!(rec.ingest_stream_segment(b"OPUS_AUDIO_FRAME_1"));
        assert!(rec.ingest_stream_segment(b"OPUS_AUDIO_FRAME_2"));
        let webm_summary = rec.stop_and_finalize_file().expect("finalize webm");
        assert!(webm_summary.audio_only);

        let webm_bytes = std::fs::read(&p_webm).expect("read webm");
        let _ = std::fs::remove_file(&p_webm);
        assert_eq!(&webm_bytes[0..4], &[0x1A, 0x45, 0xDF, 0xA3]);
        assert!(webm_bytes.windows(b"A_OPUS".len()).any(|w| w == b"A_OPUS"));

        // 3. DRM tab guard refuses capture cleanly
        rec.set_tab_context(Some(77), true);
        assert!(matches!(
            rec.drm_protected_tab_guard(),
            Err(RecorderError::DrmProtectedContentBlocked { tab_id: Some(77), .. })
        ));
        assert!(rec
            .start_recording_checked(StreamContainerFormat::MatroskaMkvLossless)
            .is_err());
    }

    #[test]
    fn test_media_session_registry_gmc_and_privacy_scrubbing() {
        let mut reg = MediaSessionRegistry::new();

        let mut music = TabMediaSession::new(101, "Ambient Space", "https://music.example");
        music.artist = "Nebula".into();
        music.is_playing = true;
        music.duration_sec = 240.0;
        reg.register_or_update(music);

        let mut private_vid =
            TabMediaSession::new(202, "Confidential Lecture", "https://private.example");
        private_vid.artwork_url = Some("https://private.example/thumb.jpg".into());
        private_vid.is_playing = true;
        private_vid.has_video = true;
        private_vid.is_private = true;
        private_vid.is_drm = true;
        reg.register_or_update(private_vid);

        // Most recently activated playing session (202) wins OS media keys
        assert_eq!(reg.active_tab_id(), Some(202));

        // Private mode scrubs title, artwork, and origin from OS SMTC/MPRIS metadata
        let meta = reg.os_transport_metadata(true).unwrap();
        assert!(meta.metadata_scrubbed);
        assert_eq!(meta.title, "Private Media");
        assert!(meta.artwork_url.is_none());
        assert!(meta.origin.is_none());

        // TogglePlayPause pauses tab 202 -> OS priority automatically shifts to playing tab 101
        reg.dispatch_action(None, MediaControlAction::TogglePlayPause);
        assert_eq!(reg.active_tab_id(), Some(101));
        let public_meta = reg.os_transport_metadata(true).unwrap();
        assert!(!public_meta.metadata_scrubbed);
        assert_eq!(public_meta.title, "Ambient Space");
    }

    #[test]
    fn test_read_aloud_session_end_to_end() {
        let text = "Singularity est rapide. L'audio reste pur! Profitez-en.";
        let cfg = TtsConfig {
            backend: TtsBackendKind::PiperNeuralLocal,
            rate: 1.25,
            pitch: 1.0,
            voice_id: Some("piper.fr_FR-siwis-medium".into()),
            highlight_sentence: true,
            highlight_word: true,
            auto_scroll: true,
        };
        let mut session = ReadAloudSession::from_text(text, cfg);
        assert_eq!(session.segments().len(), 3);
        assert!(session.play());

        let p = session.progress();
        assert_eq!(p.state, ReadAloudState::Playing);
        assert_eq!(p.current_sentence_index, 0);
        assert!(p.active_sentence_range.is_some());
        assert!(p.active_word_range.is_some());

        assert_eq!(
            session.next_sentence().map(|s| s.text.as_str()),
            Some("L'audio reste pur!")
        );
        assert_eq!(
            session.prev_sentence().map(|s| s.text.as_str()),
            Some("Singularity est rapide.")
        );

        // Drain all words until Finished
        let mut steps = 0usize;
        while session.advance_word().is_some() {
            steps += 1;
            assert!(steps < 50);
        }
        assert_eq!(session.state(), ReadAloudState::Finished);
        assert_eq!(session.progress().progress_ratio, 1.0);
        assert_eq!(session.estimated_remaining_seconds(), 0.0);
    }

    #[test]
    fn test_live_captions_srt_roundtrip_with_player_parser() {
        let mut captions = LiveCaptionsEngine::new(
            LiveCaptionsConfig {
                enabled: true,
                language: "fr".into(),
                model_size: CaptionModelSize::Base,
                translate_target_lang: None,
                font_size_px: 24,
                bg_opacity_pct: 80,
                max_lines: 3,
            },
            16,
        );

        // Verify VAD detects speech frame at 16 kHz PCM
        let speech_frame: Vec<f32> = (0..480)
            .map(|i| (0.2 * (2.0 * PI * 400.0 * (i as f64) / 16000.0).sin()) as f32)
            .collect();
        assert!(captions.vad.is_speech_frame(&speech_frame));

        captions.push_segment(500, 2_750, "Bienvenue dans Singularity.", None);
        captions.push_segment(3_100, 6_400, "Sous-titrage local actif.", None);

        let srt = captions.export_srt();
        let parsed = parse_srt(&srt);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].start_ms, 500);
        assert_eq!(parsed[0].end_ms, 2_750);
        assert_eq!(parsed[0].text, "Bienvenue dans Singularity.");
        assert_eq!(parsed[1].start_ms, 3_100);
        assert_eq!(parsed[1].end_ms, 6_400);
        assert_eq!(parsed[1].text, "Sous-titrage local actif.");

        let txt = captions.export_txt();
        assert_eq!(txt, "Bienvenue dans Singularity.\nSous-titrage local actif.");
    }
}
