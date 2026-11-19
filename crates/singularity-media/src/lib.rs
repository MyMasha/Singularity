//! `singularity-media` — Hardware-Accelerated VAAPI/NVDEC/DXVA2 Media Pipeline,
//! 10-Band Parametric Biquad Audio Equalizer, 400% Volume Booster, PiP, and Stream Recorder.

pub mod decoder;
pub mod equalizer;
pub mod player;
pub mod recorder;

pub use decoder::{HardwareDecodeBackend, HardwareDecoderCapabilities, VideoCodec};
pub use equalizer::{
    ParametricBandConfig, TenBandParametricEqualizer, ISO_10_BAND_FREQUENCIES_HZ,
};
pub use player::{OledMediaPlayer, PlayerDockMode, SubtitleStyleConfig};
pub use recorder::{DirectStreamRecorder, StreamContainerFormat};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_10_band_parametric_eq_and_400_percent_volume_boost() {
        let mut eq = TenBandParametricEqualizer::new(48000.0);
        eq.set_band_gain_db(0, 6.0, 1.414); // +6 dB sub-bass boost at 31.25 Hz
        eq.set_band_gain_db(5, 3.0, 1.414); // +3 dB vocal boost at 1 kHz
        eq.set_volume_boost_percent(400.0); // 400% max volume boost

        let mut samples = vec![0.4f32, -0.4f32, 0.5f32, -0.5f32, 0.6f32, -0.6f32];
        eq.process_interleaved_stereo_pcm(&mut samples);

        // Soft limiter prevents any sample from exceeding [-1.0, 1.0] even at 400% boost
        for &s in &samples {
            assert!(s >= -1.0 && s <= 1.0, "Sample clipped out of bounds: {}", s);
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
        assert!(muxed.starts_with(b"SINGULARITY-MUX:MKV:AV1_FRAME_01OPUS_PKT_01"));
    }
}
