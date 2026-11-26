//! Real-Time System Memory Pressure Monitor (`/proc/meminfo` on Linux, Win32 `GlobalMemoryStatusEx`
//! on Windows) and Adaptive Tab Eviction Scorer.

use crate::tabs::TabProtectionFlags;
use serde::{Deserialize, Serialize};

/// Snapshot of physical RAM and swap availability captured from the host OS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemMemorySnapshot {
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub used_bytes: u64,
    pub swap_total_bytes: u64,
    pub swap_free_bytes: u64,
}

/// System-wide memory pressure tier computed from [`SystemMemorySnapshot`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum MemoryPressureLevel {
    Normal,
    Moderate,
    Critical,
}

/// User-selectable memory conservation aggressiveness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AdaptiveMemoryMode {
    Off,
    Moderate,
    Balanced,
    Maximum,
}

impl AdaptiveMemoryMode {
    /// Multiplier applied to base tab freeze timeout given current memory pressure.
    pub fn freeze_timeout_multiplier(self, pressure: MemoryPressureLevel) -> f32 {
        match (self, pressure) {
            (AdaptiveMemoryMode::Off, _) => 1.0,
            (AdaptiveMemoryMode::Moderate, MemoryPressureLevel::Normal) => 1.25,
            (AdaptiveMemoryMode::Moderate, MemoryPressureLevel::Moderate) => 0.75,
            (AdaptiveMemoryMode::Moderate, MemoryPressureLevel::Critical) => 0.40,
            (AdaptiveMemoryMode::Balanced, MemoryPressureLevel::Normal) => 1.0,
            (AdaptiveMemoryMode::Balanced, MemoryPressureLevel::Moderate) => 0.50,
            (AdaptiveMemoryMode::Balanced, MemoryPressureLevel::Critical) => 0.25,
            (AdaptiveMemoryMode::Maximum, MemoryPressureLevel::Normal) => 0.50,
            (AdaptiveMemoryMode::Maximum, MemoryPressureLevel::Moderate) => 0.25,
            (AdaptiveMemoryMode::Maximum, MemoryPressureLevel::Critical) => 0.10,
        }
    }

    pub fn should_evict(self, pressure: MemoryPressureLevel) -> bool {
        match self {
            AdaptiveMemoryMode::Off => false,
            AdaptiveMemoryMode::Moderate => pressure == MemoryPressureLevel::Critical,
            AdaptiveMemoryMode::Balanced => pressure >= MemoryPressureLevel::Moderate,
            AdaptiveMemoryMode::Maximum => true,
        }
    }

    pub fn target_max_ram_fraction(self) -> f64 {
        match self {
            AdaptiveMemoryMode::Off => 1.0,
            AdaptiveMemoryMode::Moderate => 0.80,
            AdaptiveMemoryMode::Balanced => 0.65,
            AdaptiveMemoryMode::Maximum => 0.45,
        }
    }
}

impl SystemMemorySnapshot {
    /// Captures live system memory telemetry from `/proc/meminfo` (Linux),
    /// Win32 `GlobalMemoryStatusEx` (Windows), or a conservative portable fallback.
    pub fn capture() -> Self {
        #[cfg(target_os = "linux")]
        {
            if let Ok(contents) = std::fs::read_to_string("/proc/meminfo") {
                if let Some(snap) = Self::parse_proc_meminfo(&contents) {
                    return snap;
                }
            }
        }

        #[cfg(target_os = "windows")]
        {
            if let Some(snap) = capture_windows_memory_status() {
                return snap;
            }
        }

        Self::portable_fallback()
    }

    pub fn portable_fallback() -> Self {
        let total = 8u64 * 1024 * 1024 * 1024;
        let available = 4u64 * 1024 * 1024 * 1024;
        Self {
            total_bytes: total,
            available_bytes: available,
            used_bytes: total - available,
            swap_total_bytes: 0,
            swap_free_bytes: 0,
        }
    }

    /// Parses Linux `/proc/meminfo` text (kB entries) into a [`SystemMemorySnapshot`].
    pub fn parse_proc_meminfo(contents: &str) -> Option<Self> {
        let mut mem_total_kb: Option<u64> = None;
        let mut mem_available_kb: Option<u64> = None;
        let mut mem_free_kb: u64 = 0;
        let mut buffers_kb: u64 = 0;
        let mut cached_kb: u64 = 0;
        let mut swap_total_kb: u64 = 0;
        let mut swap_free_kb: u64 = 0;

        for line in contents.lines() {
            let Some((key, rest)) = line.split_once(':') else {
                continue;
            };
            let val_kb = rest
                .split_whitespace()
                .next()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);
            match key.trim() {
                "MemTotal" => mem_total_kb = Some(val_kb),
                "MemAvailable" => mem_available_kb = Some(val_kb),
                "MemFree" => mem_free_kb = val_kb,
                "Buffers" => buffers_kb = val_kb,
                "Cached" => cached_kb = val_kb,
                "SwapTotal" => swap_total_kb = val_kb,
                "SwapFree" => swap_free_kb = val_kb,
                _ => {}
            }
        }

        let total_kb = mem_total_kb?;
        if total_kb == 0 {
            return None;
        }
        let avail_kb = mem_available_kb
            .unwrap_or_else(|| mem_free_kb.saturating_add(buffers_kb).saturating_add(cached_kb))
            .min(total_kb);
        let total_bytes = total_kb.saturating_mul(1024);
        let available_bytes = avail_kb.saturating_mul(1024);

        Some(Self {
            total_bytes,
            available_bytes,
            used_bytes: total_bytes.saturating_sub(available_bytes),
            swap_total_bytes: swap_total_kb.saturating_mul(1024),
            swap_free_bytes: swap_free_kb.saturating_mul(1024),
        })
    }

    pub fn used_ratio(&self) -> f64 {
        if self.total_bytes == 0 {
            return 0.0;
        }
        (self.used_bytes as f64 / self.total_bytes as f64).clamp(0.0, 1.0)
    }

    pub fn available_ratio(&self) -> f64 {
        if self.total_bytes == 0 {
            return 1.0;
        }
        (self.available_bytes as f64 / self.total_bytes as f64).clamp(0.0, 1.0)
    }

    pub fn pressure_level(&self) -> MemoryPressureLevel {
        const MIB: u64 = 1024 * 1024;
        let avail_ratio = self.available_ratio();
        if avail_ratio <= 0.10 || self.available_bytes < 512 * MIB {
            MemoryPressureLevel::Critical
        } else if avail_ratio <= 0.25 || self.available_bytes < 1536 * MIB {
            MemoryPressureLevel::Moderate
        } else {
            MemoryPressureLevel::Normal
        }
    }
}

#[cfg(target_os = "windows")]
fn capture_windows_memory_status() -> Option<SystemMemorySnapshot> {
    #[repr(C)]
    struct MemoryStatusEx {
        dw_length: u32,
        dw_memory_load: u32,
        ull_total_phys: u64,
        ull_avail_phys: u64,
        ull_total_page_file: u64,
        ull_avail_page_file: u64,
        ull_total_virtual: u64,
        ull_avail_virtual: u64,
        ull_avail_extended_virtual: u64,
    }
    extern "system" {
        fn GlobalMemoryStatusEx(lp_buffer: *mut MemoryStatusEx) -> i32;
    }

    let mut status = MemoryStatusEx {
        dw_length: std::mem::size_of::<MemoryStatusEx>() as u32,
        dw_memory_load: 0,
        ull_total_phys: 0,
        ull_avail_phys: 0,
        ull_total_page_file: 0,
        ull_avail_page_file: 0,
        ull_total_virtual: 0,
        ull_avail_virtual: 0,
        ull_avail_extended_virtual: 0,
    };
    let ok = unsafe { GlobalMemoryStatusEx(&mut status as *mut MemoryStatusEx) };
    if ok == 0 || status.ull_total_phys == 0 {
        return None;
    }
    let swap_total = status.ull_total_page_file.saturating_sub(status.ull_total_phys);
    let swap_free = status.ull_avail_page_file.saturating_sub(status.ull_avail_phys);
    Some(SystemMemorySnapshot {
        total_bytes: status.ull_total_phys,
        available_bytes: status.ull_avail_phys.min(status.ull_total_phys),
        used_bytes: status.ull_total_phys.saturating_sub(status.ull_avail_phys),
        swap_total_bytes: swap_total,
        swap_free_bytes: swap_free.min(swap_total),
    })
}

/// Candidate metadata fed into [`TabEvictionScorer`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TabEvictionCandidate {
    pub tab_id: u64,
    pub idle_seconds: u64,
    pub rss_bytes: u64,
    pub protection_flags: TabProtectionFlags,
    pub is_active: bool,
    pub is_never_sleep_domain: bool,
    pub is_fast_sleep_domain: bool,
    pub visit_frequency: u32,
}

/// Multi-factor eviction scorer ranking background tabs by RAM footprint, idle age,
/// domain sleep hints, visit frequency, and memory pressure while honoring protections.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TabEvictionScorer {
    pub mode: AdaptiveMemoryMode,
    pub rss_weight: f64,
    pub idle_weight: f64,
    pub frequency_penalty: f64,
}

impl Default for TabEvictionScorer {
    fn default() -> Self {
        Self::new(AdaptiveMemoryMode::Balanced)
    }
}

impl TabEvictionScorer {
    pub fn new(mode: AdaptiveMemoryMode) -> Self {
        Self {
            mode,
            rss_weight: 1.5,
            idle_weight: 1.0,
            frequency_penalty: 0.35,
        }
    }

    /// Computes an eviction priority score (higher = evict sooner).
    /// Returns `None` if the tab is active, protected by flags, never-sleep, or mode is `Off`.
    pub fn score_candidate(
        &self,
        candidate: &TabEvictionCandidate,
        pressure: MemoryPressureLevel,
    ) -> Option<f64> {
        if self.mode == AdaptiveMemoryMode::Off
            || candidate.is_active
            || candidate.is_never_sleep_domain
            || candidate.protection_flags.is_protected()
        {
            return None;
        }

        let rss_mb = candidate.rss_bytes as f64 / (1024.0 * 1024.0);
        let idle_min = candidate.idle_seconds as f64 / 60.0;
        let pressure_mult = match pressure {
            MemoryPressureLevel::Normal => 1.0,
            MemoryPressureLevel::Moderate => 1.5,
            MemoryPressureLevel::Critical => 2.5,
        };
        let mode_mult = match self.mode {
            AdaptiveMemoryMode::Off => 0.0,
            AdaptiveMemoryMode::Moderate => 0.8,
            AdaptiveMemoryMode::Balanced => 1.0,
            AdaptiveMemoryMode::Maximum => 1.4,
        };
        let fast_bonus = if candidate.is_fast_sleep_domain {
            1.6
        } else {
            1.0
        };
        let freq_divisor = 1.0 + (candidate.visit_frequency as f64).ln_1p() * self.frequency_penalty;

        let raw = (rss_mb * self.rss_weight + idle_min * self.idle_weight)
            * pressure_mult
            * mode_mult
            * fast_bonus
            / freq_divisor;

        Some(raw.max(0.0))
    }

    /// Returns eligible eviction candidates sorted from highest priority victim to lowest.
    pub fn rank_eviction_victims(
        &self,
        candidates: &[TabEvictionCandidate],
        pressure: MemoryPressureLevel,
    ) -> Vec<(u64, f64)> {
        let mut ranked: Vec<(u64, f64)> = candidates
            .iter()
            .filter_map(|c| self.score_candidate(c, pressure).map(|s| (c.tab_id, s)))
            .collect();
        ranked.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.cmp(&b.0))
        });
        ranked
    }

    /// Selects the minimal set of highest-priority eviction victims needed to reclaim
    /// at least `target_reclaim_bytes`.
    pub fn select_tabs_to_reclaim(
        &self,
        candidates: &[TabEvictionCandidate],
        target_reclaim_bytes: u64,
        pressure: MemoryPressureLevel,
    ) -> Vec<u64> {
        if target_reclaim_bytes == 0 || !self.mode.should_evict(pressure) {
            return Vec::new();
        }
        let ranked = self.rank_eviction_victims(candidates, pressure);
        let mut selected = Vec::new();
        let mut reclaimed = 0u64;

        for (tab_id, _score) in ranked {
            if let Some(cand) = candidates.iter().find(|c| c.tab_id == tab_id) {
                selected.push(tab_id);
                reclaimed = reclaimed.saturating_add(cand.rss_bytes);
                if reclaimed >= target_reclaim_bytes {
                    break;
                }
            }
        }
        selected
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proc_meminfo_parser_live_capture_and_eviction_scorer() {
        let sample = "\
MemTotal:       16384000 kB
MemFree:         1024000 kB
MemAvailable:    1200000 kB
Buffers:          200000 kB
Cached:           800000 kB
SwapTotal:       4096000 kB
SwapFree:        3500000 kB
";
        let snap = SystemMemorySnapshot::parse_proc_meminfo(sample).expect("parse meminfo");
        assert_eq!(snap.total_bytes, 16_384_000 * 1024);
        assert_eq!(snap.available_bytes, 1_200_000 * 1024);
        assert_eq!(snap.pressure_level(), MemoryPressureLevel::Critical);

        // Live OS capture works without panicking and reports non-zero total RAM
        let live = SystemMemorySnapshot::capture();
        assert!(live.total_bytes > 0);
        assert!(live.available_bytes <= live.total_bytes);

        let scorer = TabEvictionScorer::new(AdaptiveMemoryMode::Balanced);
        let candidates = vec![
            TabEvictionCandidate {
                tab_id: 1,
                idle_seconds: 600,
                rss_bytes: 500 * 1024 * 1024,
                protection_flags: TabProtectionFlags::AUDIO_ACTIVE,
                is_active: false,
                is_never_sleep_domain: false,
                is_fast_sleep_domain: false,
                visit_frequency: 1,
            },
            TabEvictionCandidate {
                tab_id: 2,
                idle_seconds: 900,
                rss_bytes: 400 * 1024 * 1024,
                protection_flags: TabProtectionFlags::NONE,
                is_active: false,
                is_never_sleep_domain: false,
                is_fast_sleep_domain: true,
                visit_frequency: 1,
            },
            TabEvictionCandidate {
                tab_id: 3,
                idle_seconds: 120,
                rss_bytes: 150 * 1024 * 1024,
                protection_flags: TabProtectionFlags::NONE,
                is_active: false,
                is_never_sleep_domain: false,
                is_fast_sleep_domain: false,
                visit_frequency: 20,
            },
            TabEvictionCandidate {
                tab_id: 4,
                idle_seconds: 3000,
                rss_bytes: 900 * 1024 * 1024,
                protection_flags: TabProtectionFlags::NONE,
                is_active: true,
                is_never_sleep_domain: false,
                is_fast_sleep_domain: false,
                visit_frequency: 1,
            },
        ];

        let victims = scorer.rank_eviction_victims(&candidates, MemoryPressureLevel::Moderate);
        // Tab 1 (audio protected) and Tab 4 (active) MUST be excluded
        assert_eq!(victims.len(), 2);
        assert_eq!(victims[0].0, 2); // Heavy + idle + fast-sleep tab evicted first
        assert_eq!(victims[1].0, 3);

        let picked = scorer.select_tabs_to_reclaim(
            &candidates,
            300 * 1024 * 1024,
            MemoryPressureLevel::Moderate,
        );
        assert_eq!(picked, vec![2]);
    }
}
