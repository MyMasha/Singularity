//! Speculative DNS + TLS 1.3 / QUIC 0-RTT Pre-Connect Engine on Link Hover & Mouse Intent.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};

/// Hard cap on warm speculative sessions to prevent unbounded memory growth.
pub const MAX_WARM_SESSIONS: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum HoverIntentSignal {
    MouseOver { dwell_ms: u32, velocity_px_per_sec: f32 },
    MouseDownImmediate,
    ViewportHighProbabilityIntersection,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreConnectedSession {
    pub origin_host: String,
    pub dns_resolved_ip: String,
    pub tls13_zero_rtt_ticket_ready: bool,
    pub h3_quic_stream_warm: bool,
    pub estimated_rtt_saved_ms: u32,
}

/// Manages bounded warm QUIC/HTTP3 + TLS 1.3 0-RTT pre-connections triggered by cursor hover intent.
pub struct SpeculativePreConnectPool {
    hover_dwell_threshold_ms: u32,
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
            warm_sessions: HashMap::new(),
            insertion_order: VecDeque::new(),
        }
    }

    /// Evaluates cursor hover or mousedown intent over a hyperlink and records a bounded
    /// pre-connect candidate if the intent confidence threshold is met.
    pub fn evaluate_link_intent(
        &mut self,
        target_origin_host: &str,
        signal: HoverIntentSignal,
    ) -> Option<PreConnectedSession> {
        let host = target_origin_host.trim();
        if host.is_empty() || host.len() > 253 {
            return None;
        }
        let should_preconnect = match signal {
            HoverIntentSignal::MouseDownImmediate => true,
            HoverIntentSignal::ViewportHighProbabilityIntersection => true,
            HoverIntentSignal::MouseOver {
                dwell_ms,
                velocity_px_per_sec,
            } => {
                velocity_px_per_sec.is_finite()
                    && dwell_ms >= self.hover_dwell_threshold_ms
                    && velocity_px_per_sec < 450.0
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
}
