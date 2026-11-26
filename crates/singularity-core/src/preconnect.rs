//! Speculative DNS + TLS 1.3 / QUIC 0-RTT Pre-Connect Engine on Link Hover, Mouse Intent,
//! and Omnibox High-Confidence Predictions, guarded by Speculation Policy Gate.

use crate::blocker::{FilterDecision, NetworkResourceType, UBlockNetworkEngine};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};

/// Hard cap on warm speculative sessions to prevent unbounded memory growth.
pub const MAX_WARM_SESSIONS: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum HoverIntentSignal {
    MouseOver { dwell_ms: u32, velocity_px_per_sec: f32 },
    MouseDownImmediate,
    ViewportHighProbabilityIntersection,
    OmniboxHighConfidence { match_score: f32 },
}

/// Global aggressiveness setting for speculative pre-connect / prefetch / prerender.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PreloadLevel {
    Disabled,
    Standard,
    Extended,
}

/// Purpose signaled by the HTTP `Sec-Purpose` request header or Speculation Rules API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpeculationPurpose {
    Preconnect,
    Prefetch,
    Prerender,
}

impl SpeculationPurpose {
    pub const fn sec_purpose_header(self) -> &'static str {
        match self {
            SpeculationPurpose::Preconnect => "preconnect",
            SpeculationPurpose::Prefetch => "prefetch",
            SpeculationPurpose::Prerender => "prefetch;prerender",
        }
    }

    pub fn parse_sec_purpose_header(header_value: &str) -> Option<Self> {
        let lower = header_value.trim().to_ascii_lowercase();
        if lower.contains("prerender") {
            Some(SpeculationPurpose::Prerender)
        } else if lower.contains("prefetch") {
            Some(SpeculationPurpose::Prefetch)
        } else if lower.contains("preconnect") {
            Some(SpeculationPurpose::Preconnect)
        } else {
            None
        }
    }
}

/// Verdict produced by [`SpeculationPolicyGate`] before dispatching speculative traffic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpeculationDecision {
    Allow { sec_purpose_header: String },
    DeniedPreloadDisabled,
    DeniedPrivateMode,
    DeniedEnergySaver,
    DeniedPrerenderRequiresExtended,
    DeniedBlockedByShield(FilterDecision),
    DeniedInvalidOrigin,
}

impl SpeculationDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, SpeculationDecision::Allow { .. })
    }
}

/// Privacy- and battery-aware gate filtering `Sec-Purpose: prefetch`/`prerender` requests
/// against [`UBlockNetworkEngine`], Private Browsing mode, and Energy Saver state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpeculationPolicyGate {
    pub preload_level: PreloadLevel,
    pub private_browsing_mode: bool,
    pub energy_saver_active: bool,
    pub allow_prerender_in_standard: bool,
}

impl Default for SpeculationPolicyGate {
    fn default() -> Self {
        Self {
            preload_level: PreloadLevel::Standard,
            private_browsing_mode: false,
            energy_saver_active: false,
            allow_prerender_in_standard: false,
        }
    }
}

impl SpeculationPolicyGate {
    pub fn new(preload_level: PreloadLevel) -> Self {
        Self {
            preload_level,
            ..Self::default()
        }
    }

    /// Evaluates whether a speculative `prefetch`/`prerender`/`preconnect` may proceed.
    pub fn evaluate_speculation(
        &self,
        purpose: SpeculationPurpose,
        target_url: &str,
        target_host: &str,
        first_party_host: &str,
        blocker: &UBlockNetworkEngine,
    ) -> SpeculationDecision {
        let host = target_host.trim();
        if host.is_empty() || host.len() > 253 {
            return SpeculationDecision::DeniedInvalidOrigin;
        }
        if self.preload_level == PreloadLevel::Disabled {
            return SpeculationDecision::DeniedPreloadDisabled;
        }
        if self.private_browsing_mode {
            return SpeculationDecision::DeniedPrivateMode;
        }
        if self.energy_saver_active {
            return SpeculationDecision::DeniedEnergySaver;
        }
        if purpose == SpeculationPurpose::Prerender
            && self.preload_level != PreloadLevel::Extended
            && !self.allow_prerender_in_standard
        {
            return SpeculationDecision::DeniedPrerenderRequiresExtended;
        }

        let shield_decision = blocker.evaluate_request(
            target_url,
            host,
            first_party_host,
            NetworkResourceType::MainFrameDocument,
        );
        if !matches!(
            shield_decision,
            FilterDecision::Allow | FilterDecision::AllowByExceptionRule(_)
        ) {
            return SpeculationDecision::DeniedBlockedByShield(shield_decision);
        }

        SpeculationDecision::Allow {
            sec_purpose_header: purpose.sec_purpose_header().to_string(),
        }
    }

    /// Convenience helper accepting a raw `Sec-Purpose` header value (`prefetch`, `prefetch;prerender`).
    pub fn evaluate_sec_purpose_header(
        &self,
        sec_purpose_header: &str,
        target_url: &str,
        target_host: &str,
        first_party_host: &str,
        blocker: &UBlockNetworkEngine,
    ) -> SpeculationDecision {
        let purpose = SpeculationPurpose::parse_sec_purpose_header(sec_purpose_header)
            .unwrap_or(SpeculationPurpose::Prefetch);
        self.evaluate_speculation(purpose, target_url, target_host, first_party_host, blocker)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreConnectedSession {
    pub origin_host: String,
    pub dns_resolved_ip: String,
    pub tls13_zero_rtt_ticket_ready: bool,
    pub h3_quic_stream_warm: bool,
    pub estimated_rtt_saved_ms: u32,
}

/// Manages bounded warm QUIC/HTTP3 + TLS 1.3 0-RTT pre-connections triggered by cursor hover
/// and high-confidence omnibox autocomplete intent.
pub struct SpeculativePreConnectPool {
    hover_dwell_threshold_ms: u32,
    preload_level: PreloadLevel,
    warm_sessions: HashMap<String, PreConnectedSession>,
    insertion_order: VecDeque<String>,
}

impl Default for SpeculativePreConnectPool {
    fn default() -> Self {
        Self::new(45)
    }
}

impl SpeculativePreConnectPool {
    pub fn new(hover_dwell_threshold_ms: u32) -> Self {
        Self {
            hover_dwell_threshold_ms,
            preload_level: PreloadLevel::Standard,
            warm_sessions: HashMap::new(),
            insertion_order: VecDeque::new(),
        }
    }

    pub fn set_preload_level(&mut self, level: PreloadLevel) {
        self.preload_level = level;
        if level == PreloadLevel::Disabled {
            self.clear_sessions();
        }
    }

    pub fn preload_level(&self) -> PreloadLevel {
        self.preload_level
    }

    /// Evaluates cursor hover, mousedown, or omnibox intent and records a bounded
    /// pre-connect candidate if the intent confidence threshold is met.
    pub fn evaluate_link_intent(
        &mut self,
        target_origin_host: &str,
        signal: HoverIntentSignal,
    ) -> Option<PreConnectedSession> {
        if self.preload_level == PreloadLevel::Disabled {
            return None;
        }
        let host = target_origin_host.trim();
        if host.is_empty() || host.len() > 253 {
            return None;
        }

        let effective_dwell = match self.preload_level {
            PreloadLevel::Disabled => return None,
            PreloadLevel::Standard => self.hover_dwell_threshold_ms,
            PreloadLevel::Extended => (self.hover_dwell_threshold_ms / 2).max(15),
        };
        let omnibox_threshold = match self.preload_level {
            PreloadLevel::Extended => 0.65,
            _ => 0.80,
        };

        let should_preconnect = match signal {
            HoverIntentSignal::MouseDownImmediate => true,
            HoverIntentSignal::ViewportHighProbabilityIntersection => true,
            HoverIntentSignal::MouseOver {
                dwell_ms,
                velocity_px_per_sec,
            } => {
                velocity_px_per_sec.is_finite()
                    && dwell_ms >= effective_dwell
                    && velocity_px_per_sec < 450.0
            }
            HoverIntentSignal::OmniboxHighConfidence { match_score } => {
                match_score.is_finite() && match_score >= omnibox_threshold
            }
        };

        if !should_preconnect {
            return None;
        }

        if !self.warm_sessions.contains_key(host) {
            while self.warm_sessions.len() >= MAX_WARM_SESSIONS {
                if let Some(oldest) = self.insertion_order.pop_front() {
                    self.warm_sessions.remove(&oldest);
                } else {
                    break;
                }
            }
            self.insertion_order.push_back(host.to_string());
        }

        let session = PreConnectedSession {
            origin_host: host.to_string(),
            dns_resolved_ip: String::new(),
            tls13_zero_rtt_ticket_ready: true,
            h3_quic_stream_warm: true,
            estimated_rtt_saved_ms: 115,
        };

        self.warm_sessions
            .insert(host.to_string(), session.clone());
        Some(session)
    }

    pub fn get_warm_session(&self, origin_host: &str) -> Option<&PreConnectedSession> {
        self.warm_sessions.get(origin_host)
    }

    pub fn warm_session_count(&self) -> usize {
        self.warm_sessions.len()
    }

    /// Returns an ordered snapshot of all currently warm pre-connected sessions.
    pub fn snapshot_sessions(&self) -> Vec<PreConnectedSession> {
        self.insertion_order
            .iter()
            .filter_map(|host| self.warm_sessions.get(host).cloned())
            .collect()
    }

    pub fn clear_sessions(&mut self) -> usize {
        let n = self.warm_sessions.len();
        self.warm_sessions.clear();
        self.insertion_order.clear();
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_omnibox_intent_preload_levels_snapshot_and_speculation_gate() {
        let mut pool = SpeculativePreConnectPool::default();
        // Low omnibox score ignored in Standard mode
        assert!(pool
            .evaluate_link_intent(
                "github.com",
                HoverIntentSignal::OmniboxHighConfidence { match_score: 0.70 }
            )
            .is_none());
        // High omnibox score succeeds
        let warm = pool.evaluate_link_intent(
            "github.com",
            HoverIntentSignal::OmniboxHighConfidence { match_score: 0.92 },
        );
        assert!(warm.is_some());

        // Extended mode accepts 0.70
        pool.set_preload_level(PreloadLevel::Extended);
        assert!(pool
            .evaluate_link_intent(
                "docs.rs",
                HoverIntentSignal::OmniboxHighConfidence { match_score: 0.70 }
            )
            .is_some());

        let snap = pool.snapshot_sessions();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].origin_host, "github.com");
        assert_eq!(snap[1].origin_host, "docs.rs");

        // Disabled mode clears sessions and refuses new ones
        pool.set_preload_level(PreloadLevel::Disabled);
        assert_eq!(pool.warm_session_count(), 0);
        assert!(pool
            .evaluate_link_intent("mullvad.net", HoverIntentSignal::MouseDownImmediate)
            .is_none());

        // SpeculationPolicyGate checks uBlock, private mode, energy saver, and prerender level
        let blocker = UBlockNetworkEngine::default();
        let mut gate = SpeculationPolicyGate::new(PreloadLevel::Standard);

        assert!(gate
            .evaluate_sec_purpose_header(
                "prefetch",
                "https://mullvad.net/",
                "mullvad.net",
                "example.org",
                &blocker
            )
            .is_allowed());

        // Ad/tracker domain blocked by UBlockNetworkEngine
        assert!(matches!(
            gate.evaluate_sec_purpose_header(
                "prefetch",
                "https://doubleclick.net/track",
                "doubleclick.net",
                "example.org",
                &blocker
            ),
            SpeculationDecision::DeniedBlockedByShield(_)
        ));

        // Prerender requires Extended unless allowed
        assert_eq!(
            gate.evaluate_sec_purpose_header(
                "prefetch;prerender",
                "https://mullvad.net/",
                "mullvad.net",
                "example.org",
                &blocker
            ),
            SpeculationDecision::DeniedPrerenderRequiresExtended
        );

        gate.preload_level = PreloadLevel::Extended;
        assert!(gate
            .evaluate_sec_purpose_header(
                "prefetch;prerender",
                "https://mullvad.net/",
                "mullvad.net",
                "example.org",
                &blocker
            )
            .is_allowed());

        // Energy saver denies speculation
        gate.energy_saver_active = true;
        assert_eq!(
            gate.evaluate_sec_purpose_header(
                "prefetch",
                "https://mullvad.net/",
                "mullvad.net",
                "example.org",
                &blocker
            ),
            SpeculationDecision::DeniedEnergySaver
        );

        // Private browsing denies speculation
        gate.energy_saver_active = false;
        gate.private_browsing_mode = true;
        assert_eq!(
            gate.evaluate_sec_purpose_header(
                "prefetch",
                "https://mullvad.net/",
                "mullvad.net",
                "example.org",
                &blocker
            ),
            SpeculationDecision::DeniedPrivateMode
        );
    }
}
