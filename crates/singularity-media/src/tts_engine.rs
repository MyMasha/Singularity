//! Read Aloud / Text-to-Speech (TTS) Engine with Sentence/Word Segmentation for Synchronized
//! `CSS Custom Highlight API` Rendering and Playback State Machine.

use serde::{Deserialize, Serialize};

/// Minimum allowed TTS playback rate multiplier (`0.5x`).
pub const TTS_MIN_RATE: f32 = 0.5;
/// Maximum allowed TTS playback rate multiplier (`3.0x`).
pub const TTS_MAX_RATE: f32 = 3.0;

/// Speech synthesis backend engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub enum TtsBackendKind {
    /// OS native speech synthesis (Windows SAPI/WinRT, Linux Speech Dispatcher, macOS AVSpeechSynthesizer).
    #[default]
    OsNative,
    /// Fully offline local neural ONNX synthesis (Piper TTS).
    PiperNeuralLocal,
}

/// Descriptor for an available TTS voice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TtsVoiceInfo {
    pub voice_id: String,
    pub display_name: String,
    pub language_tag: String,
    pub backend: TtsBackendKind,
    pub is_neural: bool,
    pub is_local_offline: bool,
}

/// User configuration for Read Aloud synthesis, highlighting, and auto-scrolling.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TtsConfig {
    #[serde(default)]
    pub backend: TtsBackendKind,
    /// Speech rate multiplier strictly clamped to `0.5..=3.0` (`1.0` = normal).
    pub rate: f32,
    /// Voice pitch multiplier clamped to `0.5..=2.0` (`1.0` = normal).
    pub pitch: f32,
    pub voice_id: Option<String>,
    pub highlight_sentence: bool,
    pub highlight_word: bool,
    pub auto_scroll: bool,
}

impl Default for TtsConfig {
    fn default() -> Self {
        Self {
            backend: TtsBackendKind::OsNative,
            rate: 1.0,
            pitch: 1.0,
            voice_id: None,
            highlight_sentence: true,
            highlight_word: true,
            auto_scroll: true,
        }
    }
}

impl TtsConfig {
    /// Sets speech rate strictly clamped to `[0.5, 3.0]`.
    pub fn set_rate(&mut self, rate: f32) {
        if rate.is_finite() {
            self.rate = rate.clamp(TTS_MIN_RATE, TTS_MAX_RATE);
        }
    }

    /// Sets voice pitch strictly clamped to `[0.5, 2.0]`.
    pub fn set_pitch(&mut self, pitch: f32) {
        if pitch.is_finite() {
            self.pitch = pitch.clamp(0.5, 2.0);
        }
    }

    /// Returns a clamped copy with non-finite values sanitized to defaults.
    pub fn sanitized(mut self) -> Self {
        self.rate = if self.rate.is_finite() {
            self.rate.clamp(TTS_MIN_RATE, TTS_MAX_RATE)
        } else {
            1.0
        };
        self.pitch = if self.pitch.is_finite() {
            self.pitch.clamp(0.5, 2.0)
        } else {
            1.0
        };
        self
    }
}

/// A single segmented sentence with 0-based Unicode `char` indices into the source text
/// for synchronized `CSS Custom Highlight API` sentence and word highlighting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TextSentenceSegment {
    pub sentence_index: usize,
    /// Inclusive Unicode `char` index of sentence start in the source text.
    pub start_char: usize,
    /// Exclusive Unicode `char` index of sentence end in the source text.
    pub end_char: usize,
    pub text: String,
    /// Unicode `char` index ranges `(start_char, end_char)` in source text for each spoken word,
    /// satisfying `self.start_char <= w.0 < w.1 <= self.end_char`.
    pub word_ranges: Vec<(usize, usize)>,
}

impl TextSentenceSegment {
    /// Extracts the spoken word text at `word_index` using relative `char` coordinates.
    pub fn word_text(&self, word_index: usize) -> Option<String> {
        let &(ws, we) = self.word_ranges.get(word_index)?;
        let rel_start = ws.checked_sub(self.start_char)?;
        let rel_len = we.checked_sub(ws)?;
        Some(self.text.chars().skip(rel_start).take(rel_len).collect())
    }
}

const COMMON_ABBREVIATIONS: &[&str] = &[
    "mr", "mrs", "ms", "dr", "prof", "sr", "jr", "st", "vs", "etc", "fig", "no", "vol", "inc",
    "ltd", "m", "mme", "mlle", "e.g", "i.e",
];

fn is_closing_enclosure(c: char) -> bool {
    matches!(c, '"' | '\'' | '”' | '’' | '»' | ')' | ']' | '}')
}

fn is_sentence_terminator(c: char) -> bool {
    matches!(c, '.' | '!' | '?' | '…' | '。' | '！' | '？')
}

fn is_abbreviation_before_dot(chars: &[char], dot_idx: usize) -> bool {
    // Walk backward across preceding alphabetic characters and interior dots (e.g. "e.g" or "Dr")
    let mut start = dot_idx;
    while start > 0 {
        let prev = chars[start - 1];
        if prev.is_alphabetic() || prev == '.' {
            start -= 1;
        } else {
            break;
        }
    }
    if start == dot_idx {
        return false;
    }
    let token: String = chars[start..dot_idx]
        .iter()
        .map(|c| c.to_ascii_lowercase())
        .collect();
    if COMMON_ABBREVIATIONS.contains(&token.as_str()) {
        return true;
    }
    // Single initial letter like "J." in "J. K. Rowling" or "U.S.A."
    if token.chars().count() == 1 && chars[start].is_ascii_uppercase() {
        return true;
    }
    // Multi-initial acronym like "U.S" when followed by another dot-letter
    if token.contains('.') && token.split('.').all(|part| part.len() == 1) {
        return true;
    }
    false
}

fn extract_word_ranges(chars: &[char], start_char: usize, end_char: usize) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let mut i = start_char;

    while i < end_char {
        if !chars[i].is_alphanumeric() {
            i += 1;
            continue;
        }
        let w_start = i;
        i += 1;
        while i < end_char {
            let c = chars[i];
            if c.is_alphanumeric() {
                i += 1;
            } else if matches!(c, '\'' | '’' | '-')
                && i + 1 < end_char
                && chars[i + 1].is_alphanumeric()
            {
                // Preserve contractions & hyphenated compounds (e.g. "l'horizon", "well-known")
                i += 1;
            } else if matches!(c, '.' | ',')
                && chars[i - 1].is_ascii_digit()
                && i + 1 < end_char
                && chars[i + 1].is_ascii_digit()
            {
                // Preserve numeric literals (e.g. "3.14", "1,000")
                i += 1;
            } else {
                break;
            }
        }
        ranges.push((w_start, i));
    }

    ranges
}

fn push_trimmed_segment(
    segments: &mut Vec<TextSentenceSegment>,
    chars: &[char],
    raw_start: usize,
    raw_end: usize,
) {
    let mut s = raw_start;
    let mut e = raw_end.min(chars.len());
    while s < e && chars[s].is_whitespace() {
        s += 1;
    }
    while e > s && chars[e - 1].is_whitespace() {
        e -= 1;
    }
    if s >= e {
        return;
    }
    let text: String = chars[s..e].iter().collect();
    let word_ranges = extract_word_ranges(chars, s, e);
    let sentence_index = segments.len();
    segments.push(TextSentenceSegment {
        sentence_index,
        start_char: s,
        end_char: e,
        text,
        word_ranges,
    });
}

/// Accurately segments arbitrary Unicode text into sentences and word `char`-index spans
/// suitable for synchronized `CSS Custom Highlight API` rendering during Read Aloud playback.
pub fn segment_text_for_read_aloud(input: &str) -> Vec<TextSentenceSegment> {
    let chars: Vec<char> = input.chars().collect();
    let n = chars.len();
    let mut segments = Vec::new();
    let mut seg_start = 0usize;
    let mut i = 0usize;

    while i < n {
        let ch = chars[i];

        // Split on paragraph breaks (\n\n or \r\n\r\n)
        if ch == '\n' {
            let mut look = i + 1;
            while look < n && (chars[look] == ' ' || chars[look] == '\t' || chars[look] == '\r') {
                look += 1;
            }
            if look < n && chars[look] == '\n' {
                push_trimmed_segment(&mut segments, &chars, seg_start, i);
                while look < n && chars[look].is_whitespace() {
                    look += 1;
                }
                seg_start = look;
                i = look;
                continue;
            }
        }

        if is_sentence_terminator(ch) {
            if ch == '.' {
                // Skip decimal numbers (e.g. 3.14)
                if i > 0
                    && chars[i - 1].is_ascii_digit()
                    && i + 1 < n
                    && chars[i + 1].is_ascii_digit()
                {
                    i += 1;
                    continue;
                }

                // Detect ellipsis ("...")
                let is_ellipsis = i + 1 < n && chars[i + 1] == '.';
                if is_ellipsis {
                    let mut end_dots = i;
                    while end_dots < n && chars[end_dots] == '.' {
                        end_dots += 1;
                    }
                    let mut after = end_dots;
                    while after < n && is_closing_enclosure(chars[after]) {
                        after += 1;
                    }
                    let mut next_non_ws = after;
                    while next_non_ws < n && chars[next_non_ws].is_whitespace() {
                        next_non_ws += 1;
                    }
                    // Only split after ellipsis if followed by end-of-text or uppercase/digit/quote
                    let should_split = next_non_ws >= n
                        || chars[next_non_ws].is_uppercase()
                        || chars[next_non_ws].is_ascii_digit()
                        || matches!(chars[next_non_ws], '"' | '«' | '“');
                    if should_split && (after == n || chars[after].is_whitespace()) {
                        push_trimmed_segment(&mut segments, &chars, seg_start, after);
                        seg_start = after;
                        i = after;
                        continue;
                    } else {
                        i = end_dots;
                        continue;
                    }
                }

                // Skip URLs/identifiers like "singularity.rs" where a non-whitespace follows directly
                if i + 1 < n
                    && !chars[i + 1].is_whitespace()
                    && !is_closing_enclosure(chars[i + 1])
                {
                    i += 1;
                    continue;
                }

                // Skip common abbreviations ("Dr.", "Mr.", "e.g.", "Mme.")
                if is_abbreviation_before_dot(&chars, i) {
                    i += 1;
                    continue;
                }
            }

            // Consume repeated terminators ("?!", "!!!") and attached closing quotes/brackets
            let mut end_idx = i + 1;
            while end_idx < n && (is_sentence_terminator(chars[end_idx]) || is_closing_enclosure(chars[end_idx])) {
                end_idx += 1;
            }

            // Require boundary after CJK terminators or whitespace/EOF for Latin terminators
            let is_cjk_term = matches!(ch, '。' | '！' | '？');
            if is_cjk_term || end_idx >= n || chars[end_idx].is_whitespace() {
                push_trimmed_segment(&mut segments, &chars, seg_start, end_idx);
                seg_start = end_idx;
                i = end_idx;
                continue;
            }
        }

        i += 1;
    }

    if seg_start < n {
        push_trimmed_segment(&mut segments, &chars, seg_start, n);
    }

    segments
}

/// Playback lifecycle state of a [`ReadAloudSession`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ReadAloudState {
    #[default]
    Idle,
    Playing,
    Paused,
    Finished,
}

/// Real-time highlight & progress snapshot emitted by [`ReadAloudSession`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReadAloudProgress {
    pub state: ReadAloudState,
    pub current_sentence_index: usize,
    pub total_sentences: usize,
    pub current_word_index: usize,
    pub total_words_in_sentence: usize,
    /// Source `char` range `(start_char, end_char)` for CSS sentence highlight, if enabled.
    pub active_sentence_range: Option<(usize, usize)>,
    /// Source `char` range `(start_char, end_char)` for CSS word highlight, if enabled.
    pub active_word_range: Option<(usize, usize)>,
    /// Normalized playback completion ratio in `[0.0, 1.0]`.
    pub progress_ratio: f32,
}

/// Interactive Read Aloud / TTS session state machine (`Play` / `Pause` / `Next` / `Prev` / `Stop` / `Progress`).
#[derive(Debug, Clone, Default)]
pub struct ReadAloudSession {
    config: TtsConfig,
    segments: Vec<TextSentenceSegment>,
    state: ReadAloudState,
    current_sentence_index: usize,
    current_word_index: usize,
}

impl ReadAloudSession {
    pub fn new(config: TtsConfig) -> Self {
        Self {
            config: config.sanitized(),
            segments: Vec::new(),
            state: ReadAloudState::Idle,
            current_sentence_index: 0,
            current_word_index: 0,
        }
    }

    pub fn from_text(text: &str, config: TtsConfig) -> Self {
        let mut session = Self::new(config);
        session.load_text(text);
        session
    }

    /// Loads and segments document text, resetting playback cursors to the beginning.
    pub fn load_text(&mut self, text: &str) {
        self.segments = segment_text_for_read_aloud(text);
        self.state = ReadAloudState::Idle;
        self.current_sentence_index = 0;
        self.current_word_index = 0;
    }

    /// Starts or resumes Read Aloud playback. Restarts from sentence 0 if previously `Finished`.
    /// Returns `false` if no text segments are loaded.
    pub fn play(&mut self) -> bool {
        if self.segments.is_empty() {
            self.state = ReadAloudState::Idle;
            return false;
        }
        if self.state == ReadAloudState::Finished {
            self.current_sentence_index = 0;
            self.current_word_index = 0;
        }
        self.state = ReadAloudState::Playing;
        true
    }

    /// Pauses active playback while preserving exact sentence and word highlight cursors.
    pub fn pause(&mut self) {
        if self.state == ReadAloudState::Playing {
            self.state = ReadAloudState::Paused;
        }
    }

    /// Toggles between `Playing` and `Paused`.
    pub fn toggle_play_pause(&mut self) {
        if self.state == ReadAloudState::Playing {
            self.pause();
        } else {
            self.play();
        }
    }

    /// Stops playback and rewinds cursors back to the first sentence.
    pub fn stop(&mut self) {
        self.state = ReadAloudState::Idle;
        self.current_sentence_index = 0;
        self.current_word_index = 0;
    }

    /// Advances to the next sentence, transitioning to `Finished` after the final sentence.
    pub fn next_sentence(&mut self) -> Option<&TextSentenceSegment> {
        if self.segments.is_empty() {
            self.state = ReadAloudState::Idle;
            return None;
        }
        if self.current_sentence_index + 1 < self.segments.len() {
            self.current_sentence_index += 1;
            self.current_word_index = 0;
            if self.state == ReadAloudState::Finished {
                self.state = ReadAloudState::Paused;
            }
            self.segments.get(self.current_sentence_index)
        } else {
            self.current_sentence_index = self.segments.len() - 1;
            self.current_word_index = self.segments[self.current_sentence_index]
                .word_ranges
                .len();
            self.state = ReadAloudState::Finished;
            None
        }
    }

    /// Moves back one sentence (or rewinds current sentence if already at index 0).
    pub fn prev_sentence(&mut self) -> Option<&TextSentenceSegment> {
        if self.segments.is_empty() {
            return None;
        }
        if self.state == ReadAloudState::Finished {
            self.state = ReadAloudState::Paused;
            self.current_sentence_index = self.segments.len() - 1;
            self.current_word_index = 0;
        } else if self.current_sentence_index > 0 {
            self.current_sentence_index -= 1;
            self.current_word_index = 0;
        } else {
            self.current_word_index = 0;
        }
        self.segments.get(self.current_sentence_index)
    }

    /// Jumps directly to `sentence_index` if in bounds.
    pub fn seek_sentence(&mut self, sentence_index: usize) -> bool {
        if sentence_index < self.segments.len() {
            self.current_sentence_index = sentence_index;
            self.current_word_index = 0;
            if self.state == ReadAloudState::Finished {
                self.state = ReadAloudState::Paused;
            }
            true
        } else {
            false
        }
    }

    /// Steps the synchronized word cursor forward by one word, automatically advancing
    /// across sentence boundaries and marking `Finished` once all words have been spoken.
    pub fn advance_word(&mut self) -> Option<(usize, usize)> {
        if self.segments.is_empty() || self.state == ReadAloudState::Finished {
            return None;
        }
        let words_len = self.segments[self.current_sentence_index].word_ranges.len();
        if self.current_word_index + 1 < words_len {
            self.current_word_index += 1;
            self.segments[self.current_sentence_index]
                .word_ranges
                .get(self.current_word_index)
                .copied()
        } else if self.current_sentence_index + 1 < self.segments.len() {
            self.current_sentence_index += 1;
            self.current_word_index = 0;
            self.segments[self.current_sentence_index]
                .word_ranges
                .first()
                .copied()
        } else {
            self.current_word_index = words_len;
            self.state = ReadAloudState::Finished;
            None
        }
    }

    pub fn state(&self) -> ReadAloudState {
        self.state
    }

    pub fn config(&self) -> &TtsConfig {
        &self.config
    }

    pub fn config_mut(&mut self) -> &mut TtsConfig {
        &mut self.config
    }

    pub fn set_rate(&mut self, rate: f32) {
        self.config.set_rate(rate);
    }

    pub fn segments(&self) -> &[TextSentenceSegment] {
        &self.segments
    }

    pub fn current_segment(&self) -> Option<&TextSentenceSegment> {
        self.segments.get(self.current_sentence_index)
    }

    /// Returns the current playback progress and active CSS highlight character ranges.
    pub fn progress(&self) -> ReadAloudProgress {
        let total_sentences = self.segments.len();
        if total_sentences == 0 {
            return ReadAloudProgress {
                state: self.state,
                current_sentence_index: 0,
                total_sentences: 0,
                current_word_index: 0,
                total_words_in_sentence: 0,
                active_sentence_range: None,
                active_word_range: None,
                progress_ratio: 0.0,
            };
        }

        let seg = &self.segments[self.current_sentence_index.min(total_sentences - 1)];
        let total_words_in_sentence = seg.word_ranges.len();

        let total_words: usize = self.segments.iter().map(|s| s.word_ranges.len().max(1)).sum();
        let spoken_words: usize = if self.state == ReadAloudState::Finished {
            total_words
        } else {
            let prior: usize = self.segments[..self.current_sentence_index]
                .iter()
                .map(|s| s.word_ranges.len().max(1))
                .sum();
            prior + self.current_word_index.min(total_words_in_sentence)
        };
        let progress_ratio = if total_words == 0 {
            0.0
        } else {
            (spoken_words as f32 / total_words as f32).clamp(0.0, 1.0)
        };

        let is_highlighting = matches!(self.state, ReadAloudState::Playing | ReadAloudState::Paused);
        let active_sentence_range = if is_highlighting && self.config.highlight_sentence {
            Some((seg.start_char, seg.end_char))
        } else {
            None
        };
        let active_word_range = if is_highlighting && self.config.highlight_word {
            seg.word_ranges.get(self.current_word_index).copied()
        } else {
            None
        };

        ReadAloudProgress {
            state: self.state,
            current_sentence_index: self.current_sentence_index,
            total_sentences,
            current_word_index: self.current_word_index,
            total_words_in_sentence,
            active_sentence_range,
            active_word_range,
            progress_ratio,
        }
    }

    /// Estimates remaining reading duration in seconds at ~160 WPM scaled by `config.rate`.
    pub fn estimated_remaining_seconds(&self) -> f64 {
        if self.segments.is_empty() || self.state == ReadAloudState::Finished {
            return 0.0;
        }
        let current_rem = self.segments[self.current_sentence_index]
            .word_ranges
            .len()
            .saturating_sub(self.current_word_index);
        let future_words: usize = self.segments[self.current_sentence_index + 1..]
            .iter()
            .map(|s| s.word_ranges.len())
            .sum();
        let total_rem_words = (current_rem + future_words) as f64;
        let words_per_sec = (160.0 / 60.0) * (self.config.rate.clamp(TTS_MIN_RATE, TTS_MAX_RATE) as f64);
        total_rem_words / words_per_sec
    }

    /// Built-in offline & OS-native voice catalog descriptors.
    pub fn builtin_voices() -> Vec<TtsVoiceInfo> {
        vec![
            TtsVoiceInfo {
                voice_id: "os.native.default".into(),
                display_name: "System Default Voice".into(),
                language_tag: "en-US".into(),
                backend: TtsBackendKind::OsNative,
                is_neural: false,
                is_local_offline: true,
            },
            TtsVoiceInfo {
                voice_id: "piper.fr_FR-siwis-medium".into(),
                display_name: "Piper Siwis (Français Neural Local)".into(),
                language_tag: "fr-FR".into(),
                backend: TtsBackendKind::PiperNeuralLocal,
                is_neural: true,
                is_local_offline: true,
            },
            TtsVoiceInfo {
                voice_id: "piper.en_US-lessac-medium".into(),
                display_name: "Piper Lessac (English Neural Local)".into(),
                language_tag: "en-US".into(),
                backend: TtsBackendKind::PiperNeuralLocal,
                is_neural: true,
                is_local_offline: true,
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_segment_text_for_read_aloud_unicode_abbreviations_and_word_ranges() {
        let doc = "Dr. Vance déclara : «L'horizon atteint 3.14 rad!» Est-ce exact?\n\nOui, absolument.";
        let chars: Vec<char> = doc.chars().collect();
        let segs = segment_text_for_read_aloud(doc);

        assert_eq!(segs.len(), 3, "Segments: {:?}", segs);
        assert_eq!(segs[0].text, "Dr. Vance déclara : «L'horizon atteint 3.14 rad!»");
        assert_eq!(segs[1].text, "Est-ce exact?");
        assert_eq!(segs[2].text, "Oui, absolument.");

        // Verify exact Unicode char-offset invariants for CSS Custom Highlight API
        for (idx, seg) in segs.iter().enumerate() {
            assert_eq!(seg.sentence_index, idx);
            let slice: String = chars[seg.start_char..seg.end_char].iter().collect();
            assert_eq!(slice, seg.text);
            assert!(!seg.word_ranges.is_empty());
            for (w_idx, &(ws, we)) in seg.word_ranges.iter().enumerate() {
                assert!(seg.start_char <= ws && ws < we && we <= seg.end_char);
                let direct: String = chars[ws..we].iter().collect();
                assert_eq!(seg.word_text(w_idx).as_deref(), Some(direct.as_str()));
            }
        }

        // Verify contractions, decimals, and hyphens stayed intact
        assert_eq!(segs[0].word_text(3).as_deref(), Some("L'horizon"));
        assert_eq!(segs[0].word_text(5).as_deref(), Some("3.14"));
        assert_eq!(segs[1].word_text(0).as_deref(), Some("Est-ce"));
    }

    #[test]
    fn test_read_aloud_session_state_machine_and_rate_clamping() {
        let mut cfg = TtsConfig {
            backend: TtsBackendKind::PiperNeuralLocal,
            rate: 10.0,
            ..Default::default()
        };
        cfg.set_rate(5.5);
        assert_eq!(cfg.rate, 3.0);
        cfg.set_rate(0.1);
        assert_eq!(cfg.rate, 0.5);
        cfg.set_rate(1.5);

        let mut session =
            ReadAloudSession::from_text("First sentence here. Second sentence!", cfg);
        assert_eq!(session.state(), ReadAloudState::Idle);
        assert_eq!(session.segments().len(), 2);

        assert!(session.play());
        assert_eq!(session.state(), ReadAloudState::Playing);
        let p0 = session.progress();
        assert!(p0.active_sentence_range.is_some());
        assert!(p0.active_word_range.is_some());
        assert_eq!(p0.current_sentence_index, 0);

        // Advance through words in first sentence and into second sentence
        assert!(session.advance_word().is_some()); // "sentence"
        assert!(session.advance_word().is_some()); // "here"
        assert!(session.advance_word().is_some()); // rolls over to "Second"
        assert_eq!(session.progress().current_sentence_index, 1);
        assert_eq!(session.progress().current_word_index, 0);

        session.pause();
        assert_eq!(session.state(), ReadAloudState::Paused);
        assert!(session.prev_sentence().is_some());
        assert_eq!(session.progress().current_sentence_index, 0);

        assert!(session.next_sentence().is_some());
        assert_eq!(session.progress().current_sentence_index, 1);
        assert!(session.next_sentence().is_none());
        assert_eq!(session.state(), ReadAloudState::Finished);
        assert_eq!(session.progress().progress_ratio, 1.0);

        session.stop();
        assert_eq!(session.state(), ReadAloudState::Idle);
        assert_eq!(session.progress().current_sentence_index, 0);
        assert!(!ReadAloudSession::builtin_voices().is_empty());
    }
}
