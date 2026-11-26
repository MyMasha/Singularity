//! Resource Limiter (RAM Soft/Hard Cap, CPU % Cap, EcoQoS, CPU Affinity, Network Throttling),
//! Lock-Free Atomic Token Bucket Bandwidth Shaper, Performance Profiles, and Per-Origin Policies.

use crate::blocker::normalize_host;
use crate::tabs::wildcard_match;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

/// High-level browser performance profile presets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PerformanceProfilePreset {
    MaxPerformance200Hz,
    Balanced,
    EcoEfficiency,
    GamingMode,
    Custom,
}

/// Complete resource-limiting configuration for RAM, CPU, EcoQoS, affinity, and bandwidth caps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceLimiterConfig {
    pub enabled: bool,
    pub ram_soft_cap_mb: Option<u32>,
    pub ram_hard_cap_mb: Option<u32>,
    pub cpu_percent_cap: Option<u8>,
    pub eco_qos_enabled: bool,
    pub cpu_affinity_mask: Option<u64>,
    pub net_download_kbps: Option<u32>,
    pub net_upload_kbps: Option<u32>,
    pub active_profile: PerformanceProfilePreset,
}

impl Default for ResourceLimiterConfig {
    fn default() -> Self {
        Self::from_preset(PerformanceProfilePreset::Balanced)
    }
}

impl ResourceLimiterConfig {
    pub fn from_preset(preset: PerformanceProfilePreset) -> Self {
        match preset {
            PerformanceProfilePreset::MaxPerformance200Hz => Self {
                enabled: false,
                ram_soft_cap_mb: None,
                ram_hard_cap_mb: None,
                cpu_percent_cap: None,
                eco_qos_enabled: false,
                cpu_affinity_mask: None,
                net_download_kbps: None,
                net_upload_kbps: None,
                active_profile: preset,
            },
            PerformanceProfilePreset::Balanced => Self {
                enabled: true,
                ram_soft_cap_mb: Some(4096),
                ram_hard_cap_mb: Some(6144),
                cpu_percent_cap: None,
                eco_qos_enabled: false,
                cpu_affinity_mask: None,
                net_download_kbps: None,
                net_upload_kbps: None,
                active_profile: preset,
            },
            PerformanceProfilePreset::EcoEfficiency => Self {
                enabled: true,
                ram_soft_cap_mb: Some(2048),
                ram_hard_cap_mb: Some(3072),
                cpu_percent_cap: Some(35),
                eco_qos_enabled: true,
                cpu_affinity_mask: None,
                net_download_kbps: None,
                net_upload_kbps: None,
                active_profile: preset,
            },
            PerformanceProfilePreset::GamingMode => Self {
                enabled: true,
                ram_soft_cap_mb: Some(1536),
                ram_hard_cap_mb: Some(2048),
                cpu_percent_cap: Some(15),
                eco_qos_enabled: true,
                cpu_affinity_mask: Some(0x03), // Pin background browser to 2 efficiency cores
                net_download_kbps: Some(4_000),
                net_upload_kbps: Some(1_000),
                active_profile: preset,
            },
            PerformanceProfilePreset::Custom => Self {
                enabled: true,
                ram_soft_cap_mb: Some(4096),
                ram_hard_cap_mb: Some(6144),
                cpu_percent_cap: Some(50),
                eco_qos_enabled: false,
                cpu_affinity_mask: None,
                net_download_kbps: None,
                net_upload_kbps: None,
                active_profile: preset,
            },
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if let (Some(soft), Some(hard)) = (self.ram_soft_cap_mb, self.ram_hard_cap_mb) {
            if soft > hard {
                return Err(format!(
                    "ram_soft_cap_mb ({}) cannot exceed ram_hard_cap_mb ({})",
                    soft, hard
                ));
            }
        }
        if let Some(cpu) = self.cpu_percent_cap {
            if cpu == 0 || cpu > 100 {
                return Err(format!("cpu_percent_cap ({}) must be within 1..=100", cpu));
            }
        }
        if let Some(mask) = self.cpu_affinity_mask {
            if mask == 0 {
                return Err("cpu_affinity_mask cannot be 0 (at least one core required)".into());
            }
        }
        Ok(())
    }
}

/// Lock-free atomic Token Bucket bandwidth shaper (testable with deterministic timestamps).
///
/// Internally stores token balance scaled by `TOKEN_SCALE = 1_000` (milli-bytes) so small
/// millisecond refill increments preserve exact throughput accuracy without floating-point locks.
pub struct BandwidthTokenBucket {
    rate_bytes_per_sec: AtomicU64,
    burst_capacity_scaled: AtomicU64,
    tokens_scaled: AtomicU64,
    last_refill_ms: AtomicU64,
}

const TOKEN_SCALE: u64 = 1_000;

impl BandwidthTokenBucket {
    /// Creates an unlimited (pass-through) token bucket.
    pub fn unlimited() -> Self {
        Self {
            rate_bytes_per_sec: AtomicU64::new(0),
            burst_capacity_scaled: AtomicU64::new(0),
            tokens_scaled: AtomicU64::new(0),
            last_refill_ms: AtomicU64::new(0),
        }
    }

    /// Creates a rate-limited token bucket configured in kilobits per second (`kbps`),
    /// with a burst window of `burst_ms` milliseconds starting at `initial_now_ms`.
    /// Passing `kbps == 0` disables throttling (unlimited).
    pub fn new(kbps: u32, burst_ms: u64, initial_now_ms: u64) -> Self {
        if kbps == 0 {
            return Self::unlimited();
        }
        let bytes_per_sec = ((u64::from(kbps)) * 1_000 / 8).max(1);
        let burst_bytes = ((bytes_per_sec.saturating_mul(burst_ms.max(100))) / 1_000).max(1024);
        Self::from_bytes_per_sec(bytes_per_sec, burst_bytes, initial_now_ms)
    }

    pub fn from_bytes_per_sec(
        bytes_per_sec: u64,
        burst_capacity_bytes: u64,
        initial_now_ms: u64,
    ) -> Self {
        if bytes_per_sec == 0 {
            return Self::unlimited();
        }
        let cap_scaled = burst_capacity_bytes
            .max(1)
            .saturating_mul(TOKEN_SCALE);
        Self {
            rate_bytes_per_sec: AtomicU64::new(bytes_per_sec),
            burst_capacity_scaled: AtomicU64::new(cap_scaled),
            tokens_scaled: AtomicU64::new(cap_scaled),
            last_refill_ms: AtomicU64::new(initial_now_ms),
        }
    }

    pub fn is_unlimited(&self) -> bool {
        self.rate_bytes_per_sec.load(Ordering::Acquire) == 0
    }

    pub fn set_rate_kbps(&self, kbps: u32, burst_ms: u64) {
        if kbps == 0 {
            self.rate_bytes_per_sec.store(0, Ordering::Release);
            self.burst_capacity_scaled.store(0, Ordering::Release);
            self.tokens_scaled.store(0, Ordering::Release);
            return;
        }
        let bytes_per_sec = ((u64::from(kbps)) * 1_000 / 8).max(1);
        let burst_bytes = ((bytes_per_sec.saturating_mul(burst_ms.max(100))) / 1_000).max(1024);
        let cap_scaled = burst_bytes.saturating_mul(TOKEN_SCALE);
        self.rate_bytes_per_sec.store(bytes_per_sec, Ordering::Release);
        self.burst_capacity_scaled.store(cap_scaled, Ordering::Release);
        let _ = self
            .tokens_scaled
            .fetch_min(cap_scaled, Ordering::AcqRel);
    }

    fn refill(&self, now_ms: u64) {
        let rate = self.rate_bytes_per_sec.load(Ordering::Acquire);
        if rate == 0 {
            return;
        }
        let cap = self.burst_capacity_scaled.load(Ordering::Acquire);

        // Lock-free advance of `last_refill_ms`
        let elapsed_ms = loop {
            let prev_ms = self.last_refill_ms.load(Ordering::Acquire);
            if now_ms <= prev_ms {
                return;
            }
            if self
                .last_refill_ms
                .compare_exchange_weak(prev_ms, now_ms, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                break now_ms - prev_ms;
            }
        };

        // rate bytes/sec * elapsed_ms = rate * elapsed_ms milli-bytes (exact for TOKEN_SCALE=1000)
        let added_scaled = rate.saturating_mul(elapsed_ms);
        loop {
            let cur = self.tokens_scaled.load(Ordering::Acquire);
            let next = cur.saturating_add(added_scaled).min(cap);
            if self
                .tokens_scaled
                .compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                break;
            }
        }
    }

    /// Lock-free attempt to consume `bytes` at timestamp `now_ms`.
    /// Returns `true` if allowed immediately, `false` if bandwidth quota is exhausted.
    pub fn try_consume(&self, bytes: u64, now_ms: u64) -> bool {
        if self.is_unlimited() || bytes == 0 {
            return true;
        }
        self.refill(now_ms);
        let needed_scaled = bytes.saturating_mul(TOKEN_SCALE);
        loop {
            let cur = self.tokens_scaled.load(Ordering::Acquire);
            if cur < needed_scaled {
                return false;
            }
            let next = cur - needed_scaled;
            if self
                .tokens_scaled
                .compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                return true;
            }
        }
    }

    /// Returns currently available whole bytes after refilling up to `now_ms`.
    pub fn available_bytes(&self, now_ms: u64) -> u64 {
        if self.is_unlimited() {
            return u64::MAX;
        }
        self.refill(now_ms);
        self.tokens_scaled.load(Ordering::Acquire) / TOKEN_SCALE
    }

    /// Estimates how many milliseconds must elapse before `bytes` can be consumed.
    pub fn estimated_wait_ms(&self, bytes: u64, now_ms: u64) -> u64 {
        let rate = self.rate_bytes_per_sec.load(Ordering::Acquire);
        if rate == 0 || bytes == 0 {
            return 0;
        }
        self.refill(now_ms);
        let needed_scaled = bytes.saturating_mul(TOKEN_SCALE);
        let cur = self.tokens_scaled.load(Ordering::Acquire);
        if cur >= needed_scaled {
            return 0;
        }
        let deficit_scaled = needed_scaled - cur;
        deficit_scaled.div_ceil(rate)
    }
}

/// Per-origin performance policy overriding global throttling (e.g. WebGL/video-call boost).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OriginPerformancePolicy {
    pub origin_pattern: String,
    pub profile_override: PerformanceProfilePreset,
    pub max_fps: Option<u32>,
    pub allow_background_throttling: bool,
    pub ram_cap_override_mb: Option<u32>,
    pub priority_boost: bool,
}

impl OriginPerformancePolicy {
    pub fn matches_host(&self, host: &str) -> bool {
        let norm_host = normalize_host(host);
        let pat = self.origin_pattern.trim().to_ascii_lowercase();
        if norm_host.is_empty() || pat.is_empty() {
            return false;
        }
        if let Some(suffix) = pat.strip_prefix("*.") {
            norm_host == suffix || norm_host.ends_with(&format!(".{}", suffix))
        } else if pat.contains('*') || pat.contains('?') {
            wildcard_match(&pat, &norm_host)
        } else {
            norm_host == pat || norm_host.ends_with(&format!(".{}", pat))
        }
    }
}

/// Orchestrates global [`ResourceLimiterConfig`], download/upload [`BandwidthTokenBucket`]s,
/// and per-origin [`OriginPerformancePolicy`] overrides.
pub struct ResourceLimiterManager {
    config: ResourceLimiterConfig,
    download_bucket: BandwidthTokenBucket,
    upload_bucket: BandwidthTokenBucket,
    origin_policies: Vec<OriginPerformancePolicy>,
}

impl Default for ResourceLimiterManager {
    fn default() -> Self {
        Self::new(ResourceLimiterConfig::default())
    }
}

impl ResourceLimiterManager {
    pub fn new(config: ResourceLimiterConfig) -> Self {
        let dl = config
            .net_download_kbps
            .map(|k| BandwidthTokenBucket::new(k, 1_000, 0))
            .unwrap_or_else(BandwidthTokenBucket::unlimited);
        let ul = config
            .net_upload_kbps
            .map(|k| BandwidthTokenBucket::new(k, 1_000, 0))
            .unwrap_or_else(BandwidthTokenBucket::unlimited);
        Self {
            config,
            download_bucket: dl,
            upload_bucket: ul,
            origin_policies: Vec::new(),
        }
    }

    pub fn config(&self) -> &ResourceLimiterConfig {
        &self.config
    }

    pub fn apply_preset(&mut self, preset: PerformanceProfilePreset) {
        let cfg = ResourceLimiterConfig::from_preset(preset);
        let _ = self.set_config(cfg);
    }

    pub fn set_config(&mut self, config: ResourceLimiterConfig) -> Result<(), String> {
        config.validate()?;
        self.download_bucket
            .set_rate_kbps(config.net_download_kbps.unwrap_or(0), 1_000);
        self.upload_bucket
            .set_rate_kbps(config.net_upload_kbps.unwrap_or(0), 1_000);
        self.config = config;
        Ok(())
    }

    pub fn download_bucket(&self) -> &BandwidthTokenBucket {
        &self.download_bucket
    }

    pub fn upload_bucket(&self) -> &BandwidthTokenBucket {
        &self.upload_bucket
    }

    pub fn add_origin_policy(&mut self, policy: OriginPerformancePolicy) {
        if let Some(pos) = self
            .origin_policies
            .iter()
            .position(|p| p.origin_pattern.eq_ignore_ascii_case(&policy.origin_pattern))
        {
            self.origin_policies[pos] = policy;
        } else {
            self.origin_policies.push(policy);
        }
    }

    pub fn remove_origin_policy(&mut self, origin_pattern: &str) -> bool {
        let before = self.origin_policies.len();
        self.origin_policies
            .retain(|p| !p.origin_pattern.eq_ignore_ascii_case(origin_pattern));
        self.origin_policies.len() != before
    }

    pub fn policy_for_host(&self, host: &str) -> Option<&OriginPerformancePolicy> {
        self.origin_policies.iter().find(|p| p.matches_host(host))
    }

    pub fn origin_policies(&self) -> &[OriginPerformancePolicy] {
        &self.origin_policies
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_presets_validation_origin_policies_and_lockfree_token_bucket() {
        let gaming = ResourceLimiterConfig::from_preset(PerformanceProfilePreset::GamingMode);
        assert!(gaming.validate().is_ok());
        assert!(gaming.eco_qos_enabled);
        assert_eq!(gaming.cpu_percent_cap, Some(15));
        assert_eq!(gaming.net_download_kbps, Some(4_000));

        let mut invalid = gaming.clone();
        invalid.ram_soft_cap_mb = Some(8192);
        invalid.ram_hard_cap_mb = Some(4096);
        assert!(invalid.validate().is_err());

        // Lock-free token bucket: 1000 B/s, burst 1000 B, starting at t=1000ms
        let bucket = BandwidthTokenBucket::from_bytes_per_sec(1_000, 1_000, 1_000);
        assert!(bucket.try_consume(600, 1_000));
        assert!(bucket.try_consume(400, 1_000));
        // Bucket now empty -> next 250 bytes throttled with 250ms wait
        assert!(!bucket.try_consume(250, 1_000));
        assert_eq!(bucket.estimated_wait_ms(250, 1_000), 250);
        // Advance 300ms -> +300 bytes refilled -> 250 bytes allowed
        assert!(bucket.try_consume(250, 1_300));
        assert_eq!(bucket.available_bytes(1_300), 50);

        // Origin performance policy override
        let mut mgr = ResourceLimiterManager::default();
        mgr.add_origin_policy(OriginPerformancePolicy {
            origin_pattern: "*.figma.com".into(),
            profile_override: PerformanceProfilePreset::MaxPerformance200Hz,
            max_fps: Some(200),
            allow_background_throttling: false,
            ram_cap_override_mb: Some(8192),
            priority_boost: true,
        });
        let matched = mgr.policy_for_host("app.figma.com").expect("figma policy");
        assert!(matched.priority_boost);
        assert_eq!(matched.max_fps, Some(200));
    }
}
