//! Global Media Controls (GMC) Registry & OS Transport Integration (Windows SMTC / Linux MPRIS2).
//!
//! Tracks active audio/video sessions across all open browser tabs, automatically selects the
//! priority session for hardware OS media keys, dispatches playback/seek/volume/PiP/device
//! routing actions, and scrubs private or MPRIS-protected metadata before OS exposure.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::equalizer::MAX_VOLUME_BOOST_PERCENT;

/// Live media session metadata and playback state for a single browser tab.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TabMediaSession {
    pub tab_id: u64,
    pub title: String,
    pub artist: String,
    pub album: String,
    pub artwork_url: Option<String>,
    pub origin: String,
    pub is_playing: bool,
    pub is_muted: bool,
    pub duration_sec: f64,
    pub position_sec: f64,
    pub playback_rate: f64,
    pub volume_pct: f64,
    pub has_video: bool,
    pub pip_active: bool,
    pub output_device_id: Option<String>,
    pub is_private: bool,
    pub is_drm: bool,
}

impl Default for TabMediaSession {
    fn default() -> Self {
        Self {
            tab_id: 0,
            title: String::new(),
            artist: String::new(),
            album: String::new(),
            artwork_url: None,
            origin: String::new(),
            is_playing: false,
            is_muted: false,
            duration_sec: 0.0,
            position_sec: 0.0,
            playback_rate: 1.0,
            volume_pct: 100.0,
            has_video: false,
            pip_active: false,
            output_device_id: None,
            is_private: false,
            is_drm: false,
        }
    }
}

impl TabMediaSession {
    pub fn new(tab_id: u64, title: impl Into<String>, origin: impl Into<String>) -> Self {
        Self {
            tab_id,
            title: title.into(),
            origin: origin.into(),
            ..Default::default()
        }
    }

    /// Produces sanitized OS transport metadata (SMTC / MPRIS2), masking title, artist, album,
    /// artwork URL, and origin when privacy scrubbing applies.
    pub fn to_os_transport_metadata(
        &self,
        scrub_private: bool,
        force_scrub_all: bool,
    ) -> OsTransportMetadata {
        let should_scrub = force_scrub_all || (scrub_private && self.is_private);
        if should_scrub {
            OsTransportMetadata {
                tab_id: self.tab_id,
                title: if self.is_private {
                    "Private Media".into()
                } else {
                    "Singularity Media".into()
                },
                artist: String::new(),
                album: String::new(),
                artwork_url: None,
                origin: None,
                is_playing: self.is_playing,
                duration_sec: self.duration_sec,
                position_sec: self.position_sec,
                playback_rate: self.playback_rate,
                metadata_scrubbed: true,
            }
        } else {
            OsTransportMetadata {
                tab_id: self.tab_id,
                title: self.title.clone(),
                artist: self.artist.clone(),
                album: self.album.clone(),
                artwork_url: self.artwork_url.clone(),
                origin: Some(self.origin.clone()),
                is_playing: self.is_playing,
                duration_sec: self.duration_sec,
                position_sec: self.position_sec,
                playback_rate: self.playback_rate,
                metadata_scrubbed: false,
            }
        }
    }

    fn sanitize(&mut self) {
        self.duration_sec = if self.duration_sec.is_finite() {
            self.duration_sec.max(0.0)
        } else {
            0.0
        };
        self.position_sec = if self.position_sec.is_finite() {
            if self.duration_sec > 0.0 {
                self.position_sec.clamp(0.0, self.duration_sec)
            } else {
                self.position_sec.max(0.0)
            }
        } else {
            0.0
        };
        self.playback_rate = if self.playback_rate.is_finite() {
            self.playback_rate.clamp(0.1, 16.0)
        } else {
            1.0
        };
        self.volume_pct = if self.volume_pct.is_finite() {
            self.volume_pct.clamp(0.0, MAX_VOLUME_BOOST_PERCENT)
        } else {
            100.0
        };
        if !self.has_video {
            self.pip_active = false;
        }
    }
}

/// Control commands dispatched from Global Media Controls UI or OS hardware media keys (SMTC/MPRIS).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum MediaControlAction {
    Play,
    Pause,
    TogglePlayPause,
    SeekTo(f64),
    SeekDelta(f64),
    NextTrack,
    PrevTrack,
    SetVolume(f64),
    SetMuted(bool),
    TogglePip,
    SetOutputDevice(String),
}

/// Metadata payload exposed to OS media transport surfaces (Windows SMTC / Linux MPRIS2 D-Bus).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OsTransportMetadata {
    pub tab_id: u64,
    pub title: String,
    pub artist: String,
    pub album: String,
    pub artwork_url: Option<String>,
    pub origin: Option<String>,
    pub is_playing: bool,
    pub duration_sec: f64,
    pub position_sec: f64,
    pub playback_rate: f64,
    /// `true` if identifying title/artwork/origin metadata was masked for privacy.
    pub metadata_scrubbed: bool,
}

/// Multi-tab Global Media Controls registry & OS media key dispatcher.
#[derive(Debug, Clone, Default)]
pub struct MediaSessionRegistry {
    sessions: HashMap<u64, TabMediaSession>,
    last_active_seq: HashMap<u64, u64>,
    seq_counter: u64,
    pinned_tab_id: Option<u64>,
    /// Global setting (`media_session_mpris_scrub_metadata`) masking OS/MPRIS metadata for all tabs.
    pub media_session_mpris_scrub_metadata: bool,
}

impl MediaSessionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    fn next_seq(&mut self) -> u64 {
        self.seq_counter = self.seq_counter.saturating_add(1);
        self.seq_counter
    }

    /// Registers a new tab media session or updates an existing one.
    pub fn register_or_update(&mut self, mut session: TabMediaSession) {
        session.sanitize();
        let tab_id = session.tab_id;
        let was_playing = self
            .sessions
            .get(&tab_id)
            .map(|prev| prev.is_playing)
            .unwrap_or(false);
        let is_new = !self.sessions.contains_key(&tab_id);

        if is_new || (session.is_playing && !was_playing) || session.is_playing {
            let seq = self.next_seq();
            self.last_active_seq.insert(tab_id, seq);
        }

        self.sessions.insert(tab_id, session);
    }

    /// Removes a closed or idle tab's media session from the registry.
    pub fn remove_tab(&mut self, tab_id: u64) -> Option<TabMediaSession> {
        self.last_active_seq.remove(&tab_id);
        if self.pinned_tab_id == Some(tab_id) {
            self.pinned_tab_id = None;
        }
        self.sessions.remove(&tab_id)
    }

    pub fn get(&self, tab_id: u64) -> Option<&TabMediaSession> {
        self.sessions.get(&tab_id)
    }

    pub fn get_mut(&mut self, tab_id: u64) -> Option<&mut TabMediaSession> {
        self.sessions.get_mut(&tab_id)
    }

    /// Pins a specific tab as preferred target for Global Media Controls & OS media keys.
    pub fn set_pinned_tab(&mut self, tab_id: Option<u64>) {
        self.pinned_tab_id = tab_id.filter(|id| self.sessions.contains_key(id));
    }

    pub fn pinned_tab(&self) -> Option<u64> {
        self.pinned_tab_id
    }

    /// Enables or disables global OS/MPRIS metadata scrubbing (`media_session_mpris_scrub_metadata`).
    pub fn set_mpris_scrub_metadata(&mut self, scrub: bool) {
        self.media_session_mpris_scrub_metadata = scrub;
    }

    pub fn mpris_scrub_metadata(&self) -> bool {
        self.media_session_mpris_scrub_metadata
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn playing_count(&self) -> usize {
        self.sessions.values().filter(|s| s.is_playing).count()
    }

    /// Returns all active sessions ordered by playback priority (playing first, most recent first).
    pub fn sessions(&self) -> Vec<&TabMediaSession> {
        let mut list: Vec<&TabMediaSession> = self.sessions.values().collect();
        list.sort_by(|a, b| {
            let seq_a = self.last_active_seq.get(&a.tab_id).copied().unwrap_or(0);
            let seq_b = self.last_active_seq.get(&b.tab_id).copied().unwrap_or(0);
            b.is_playing
                .cmp(&a.is_playing)
                .then_with(|| a.is_muted.cmp(&b.is_muted))
                .then_with(|| seq_b.cmp(&seq_a))
                .then_with(|| a.tab_id.cmp(&b.tab_id))
        });
        list
    }

    /// Automatically selects the highest-priority tab for OS media keys (SMTC / MPRIS2):
    /// 1. Pinned tab if currently playing
    /// 2. Currently playing unmuted tab with highest recency (falling back to playing muted)
    /// 3. Pinned tab if paused
    /// 4. Most recently active paused tab
    pub fn active_tab_id(&self) -> Option<u64> {
        if let Some(pinned) = self.pinned_tab_id {
            if self.sessions.get(&pinned).is_some_and(|s| s.is_playing) {
                return Some(pinned);
            }
        }

        let best_playing = self
            .sessions
            .values()
            .filter(|s| s.is_playing)
            .max_by(|a, b| {
                let seq_a = self.last_active_seq.get(&a.tab_id).copied().unwrap_or(0);
                let seq_b = self.last_active_seq.get(&b.tab_id).copied().unwrap_or(0);
                (!a.is_muted)
                    .cmp(&(!b.is_muted))
                    .then_with(|| seq_a.cmp(&seq_b))
                    .then_with(|| b.tab_id.cmp(&a.tab_id))
            })
            .map(|s| s.tab_id);

        if best_playing.is_some() {
            return best_playing;
        }

        if let Some(pinned) = self.pinned_tab_id {
            if self.sessions.contains_key(&pinned) {
                return Some(pinned);
            }
        }

        self.sessions
            .keys()
            .copied()
            .max_by(|a, b| {
                let seq_a = self.last_active_seq.get(a).copied().unwrap_or(0);
                let seq_b = self.last_active_seq.get(b).copied().unwrap_or(0);
                seq_a.cmp(&seq_b).then_with(|| b.cmp(a))
            })
    }

    /// Returns the automatically selected priority [`TabMediaSession`].
    pub fn active_session(&self) -> Option<&TabMediaSession> {
        let id = self.active_tab_id()?;
        self.sessions.get(&id)
    }

    /// Dispatches a [`MediaControlAction`] to `target_tab_id` (or the priority session when `None`),
    /// returning the updated [`TabMediaSession`] snapshot.
    pub fn dispatch_action(
        &mut self,
        target_tab_id: Option<u64>,
        action: MediaControlAction,
    ) -> Option<TabMediaSession> {
        let tab_id = target_tab_id.or_else(|| self.active_tab_id())?;
        let mut bump_seq = false;

        let updated = {
            let session = self.sessions.get_mut(&tab_id)?;
            match action {
                MediaControlAction::Play => {
                    session.is_playing = true;
                    bump_seq = true;
                }
                MediaControlAction::Pause => {
                    session.is_playing = false;
                }
                MediaControlAction::TogglePlayPause => {
                    session.is_playing = !session.is_playing;
                    if session.is_playing {
                        bump_seq = true;
                    }
                }
                MediaControlAction::SeekTo(pos) => {
                    if pos.is_finite() {
                        session.position_sec = if session.duration_sec > 0.0 {
                            pos.clamp(0.0, session.duration_sec)
                        } else {
                            pos.max(0.0)
                        };
                    }
                }
                MediaControlAction::SeekDelta(delta) => {
                    if delta.is_finite() {
                        let next = session.position_sec + delta;
                        session.position_sec = if session.duration_sec > 0.0 {
                            next.clamp(0.0, session.duration_sec)
                        } else {
                            next.max(0.0)
                        };
                    }
                }
                MediaControlAction::NextTrack | MediaControlAction::PrevTrack => {
                    session.position_sec = 0.0;
                    bump_seq = true;
                }
                MediaControlAction::SetVolume(pct) => {
                    if pct.is_finite() {
                        session.volume_pct = pct.clamp(0.0, MAX_VOLUME_BOOST_PERCENT);
                    }
                }
                MediaControlAction::SetMuted(muted) => {
                    session.is_muted = muted;
                }
                MediaControlAction::TogglePip => {
                    if session.has_video {
                        session.pip_active = !session.pip_active;
                    }
                }
                MediaControlAction::SetOutputDevice(device_id) => {
                    session.output_device_id = if device_id.trim().is_empty() {
                        None
                    } else {
                        Some(device_id)
                    };
                }
            }
            session.clone()
        };

        if bump_seq {
            let seq = self.next_seq();
            self.last_active_seq.insert(tab_id, seq);
        }

        Some(updated)
    }

    /// Builds the OS transport metadata (SMTC / MPRIS2) for the priority session, masking title,
    /// artist, album, artwork URL, and origin if the tab is private (when `scrub_private` is `true`)
    /// or if `media_session_mpris_scrub_metadata` is enabled globally.
    pub fn os_transport_metadata(&self, scrub_private: bool) -> Option<OsTransportMetadata> {
        let session = self.active_session()?;
        Some(session.to_os_transport_metadata(
            scrub_private,
            self.media_session_mpris_scrub_metadata,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_priority_selection_and_media_actions() {
        let mut reg = MediaSessionRegistry::new();

        let mut tab1 = TabMediaSession::new(1, "Podcast Episode 1", "https://podcasts.example");
        tab1.is_playing = false;
        tab1.duration_sec = 1800.0;
        reg.register_or_update(tab1);

        let mut tab2 = TabMediaSession::new(2, "4K Concert", "https://video.example");
        tab2.artist = "Horizon Orchestra".into();
        tab2.artwork_url = Some("https://video.example/cover.jpg".into());
        tab2.is_playing = true;
        tab2.has_video = true;
        tab2.duration_sec = 3600.0;
        reg.register_or_update(tab2);

        // Playing tab 2 automatically wins over paused tab 1
        assert_eq!(reg.active_tab_id(), Some(2));
        assert_eq!(reg.playing_count(), 1);

        // Dispatch hardware media actions to priority tab
        let updated = reg
            .dispatch_action(None, MediaControlAction::SeekTo(120.0))
            .unwrap();
        assert_eq!(updated.position_sec, 120.0);

        let updated = reg
            .dispatch_action(None, MediaControlAction::SeekDelta(-30.0))
            .unwrap();
        assert_eq!(updated.position_sec, 90.0);

        let updated = reg
            .dispatch_action(None, MediaControlAction::SetVolume(450.0))
            .unwrap();
        assert_eq!(updated.volume_pct, 450.0);

        let updated = reg
            .dispatch_action(None, MediaControlAction::TogglePip)
            .unwrap();
        assert!(updated.pip_active);

        let updated = reg
            .dispatch_action(
                None,
                MediaControlAction::SetOutputDevice("hdmi-oled-tv".into()),
            )
            .unwrap();
        assert_eq!(updated.output_device_id.as_deref(), Some("hdmi-oled-tv"));

        // Pause tab 2 and start tab 1 -> priority flips to tab 1
        reg.dispatch_action(Some(2), MediaControlAction::Pause);
        reg.dispatch_action(Some(1), MediaControlAction::Play);
        assert_eq!(reg.active_tab_id(), Some(1));
    }

    #[test]
    fn test_os_transport_metadata_scrubbing_private_and_global_mpris() {
        let mut reg = MediaSessionRegistry::new();

        let mut priv_tab = TabMediaSession::new(10, "Secret Stream Title", "https://private.example");
        priv_tab.artist = "Secret Artist".into();
        priv_tab.album = "Secret Album".into();
        priv_tab.artwork_url = Some("https://private.example/art.png".into());
        priv_tab.is_playing = true;
        priv_tab.is_private = true;
        reg.register_or_update(priv_tab);

        // Scrubbing enabled for private tabs masks all identifying metadata
        let scrubbed = reg.os_transport_metadata(true).unwrap();
        assert!(scrubbed.metadata_scrubbed);
        assert_ne!(scrubbed.title, "Secret Stream Title");
        assert!(scrubbed.artist.is_empty());
        assert!(scrubbed.album.is_empty());
        assert!(scrubbed.artwork_url.is_none());
        assert!(scrubbed.origin.is_none());

        // Normal tab without global scrub exposes full metadata
        reg.remove_tab(10);
        let mut pub_tab = TabMediaSession::new(11, "Public Symphony", "https://music.example");
        pub_tab.artist = "Composer".into();
        pub_tab.artwork_url = Some("https://music.example/art.png".into());
        pub_tab.is_playing = true;
        reg.register_or_update(pub_tab);

        let clear = reg.os_transport_metadata(true).unwrap();
        assert!(!clear.metadata_scrubbed);
        assert_eq!(clear.title, "Public Symphony");
        assert_eq!(clear.artwork_url.as_deref(), Some("https://music.example/art.png"));

        // Activating media_session_mpris_scrub_metadata masks even public tabs
        reg.set_mpris_scrub_metadata(true);
        let mpris_scrubbed = reg.os_transport_metadata(false).unwrap();
        assert!(mpris_scrubbed.metadata_scrubbed);
        assert_ne!(mpris_scrubbed.title, "Public Symphony");
        assert!(mpris_scrubbed.artwork_url.is_none());
    }
}
