//! 100% Local Offline Performance Health Detector (Per-Tab CPU/RAM EMA & Anomaly Actions)
//! and Logarithmic-Bucket Histogram Registry (`p50` / `p95` / `p99`, Zero Network Telemetry).

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Overall browser runtime health tier derived from per-tab EMA metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum HealthStatus {
    Healthy,
    Warning,
    Critical,
}

/// Concrete self-healing action recommended by [`PerformanceHealthDetector`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum OptimizationAction {
    ThrottleTabTimers {
        tab_id: u64,
        reason: String,
    },
    FreezeBackgroundTab {
        tab_id: u64,
        ema_cpu_percent: f64,
        ema_ram_mb: f64,
    },
    DiscardHighMemoryTab {
        tab_id: u64,
        ema_ram_mb: f64,
    },
    DowngradeShaders {
        reason: String,
    },
    PurgeAssetCache {
        target_reclaim_mb: u32,
    },
}

/// Instantaneous per-tab resource telemetry sample.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct TabTelemetrySample {
    pub tab_id: u64,
    pub cpu_percent: f64,
    pub ram_mb: f64,
    pub is_active: bool,
    pub timestamp_unix: u64,
}

/// Exponential Moving Average (EMA) state tracked per tab.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TabEmaMetrics {
    pub tab_id: u64,
    pub ema_cpu_percent: f64,
    pub ema_ram_mb: f64,
    pub peak_cpu_percent: f64,
    pub peak_ram_mb: f64,
    pub is_active: bool,
    pub sample_count: u64,
    pub consecutive_anomaly_ticks: u32,
    pub last_updated_unix: u64,
}

/// Aggregated health report and recommended optimization actions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HealthReport {
    pub status: HealthStatus,
    pub total_ema_cpu_percent: f64,
    pub total_ema_ram_mb: f64,
    pub anomalous_tabs: Vec<u64>,
    pub recommended_actions: Vec<OptimizationAction>,
}

/// Detects runaway scripts, memory leaks, and sustained CPU/RAM pressure using per-tab EMA
/// smoothing and recommends non-destructive optimization actions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceHealthDetector {
    ema_alpha: f64,
    tab_cpu_warning_pct: f64,
    tab_cpu_critical_pct: f64,
    tab_ram_warning_mb: f64,
    tab_ram_critical_mb: f64,
    total_ram_warning_mb: f64,
    total_ram_critical_mb: f64,
    tabs: BTreeMap<u64, TabEmaMetrics>,
}

impl Default for PerformanceHealthDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl PerformanceHealthDetector {
    pub fn new() -> Self {
        Self {
            ema_alpha: 0.35,
            tab_cpu_warning_pct: 45.0,
            tab_cpu_critical_pct: 80.0,
            tab_ram_warning_mb: 512.0,
            tab_ram_critical_mb: 1024.0,
            total_ram_warning_mb: 4096.0,
            total_ram_critical_mb: 6144.0,
            tabs: BTreeMap::new(),
        }
    }

    pub fn set_ema_alpha(&mut self, alpha: f64) {
        if alpha.is_finite() {
            self.ema_alpha = alpha.clamp(0.05, 0.95);
        }
    }

    pub fn record_tab_sample(&mut self, sample: TabTelemetrySample) {
        let cpu = if sample.cpu_percent.is_finite() {
            sample.cpu_percent.max(0.0)
        } else {
            0.0
        };
        let ram = if sample.ram_mb.is_finite() {
            sample.ram_mb.max(0.0)
        } else {
            0.0
        };

        let entry = self
            .tabs
            .entry(sample.tab_id)
            .or_insert_with(|| TabEmaMetrics {
                tab_id: sample.tab_id,
                ema_cpu_percent: cpu,
                ema_ram_mb: ram,
                peak_cpu_percent: cpu,
                peak_ram_mb: ram,
                is_active: sample.is_active,
                sample_count: 0,
                consecutive_anomaly_ticks: 0,
                last_updated_unix: sample.timestamp_unix,
            });

        if entry.sample_count > 0 {
            entry.ema_cpu_percent =
                self.ema_alpha * cpu + (1.0 - self.ema_alpha) * entry.ema_cpu_percent;
            entry.ema_ram_mb = self.ema_alpha * ram + (1.0 - self.ema_alpha) * entry.ema_ram_mb;
        } else {
            entry.ema_cpu_percent = cpu;
            entry.ema_ram_mb = ram;
        }
        entry.peak_cpu_percent = entry.peak_cpu_percent.max(cpu);
        entry.peak_ram_mb = entry.peak_ram_mb.max(ram);
        entry.is_active = sample.is_active;
        entry.sample_count = entry.sample_count.saturating_add(1);
        entry.last_updated_unix = sample.timestamp_unix;

        let is_anomalous = entry.ema_cpu_percent >= self.tab_cpu_warning_pct
            || entry.ema_ram_mb >= self.tab_ram_warning_mb;
        if is_anomalous {
            entry.consecutive_anomaly_ticks = entry.consecutive_anomaly_ticks.saturating_add(1);
        } else {
            entry.consecutive_anomaly_ticks = 0;
        }
    }

    pub fn remove_tab(&mut self, tab_id: u64) -> Option<TabEmaMetrics> {
        self.tabs.remove(&tab_id)
    }

    pub fn tab_metrics(&self, tab_id: u64) -> Option<&TabEmaMetrics> {
        self.tabs.get(&tab_id)
    }

    pub fn evaluate_health(&self) -> HealthReport {
        let mut status = HealthStatus::Healthy;
        let mut total_cpu = 0.0;
        let mut total_ram = 0.0;
        let mut anomalous_tabs = Vec::new();
        let mut actions = Vec::new();

        for metrics in self.tabs.values() {
            total_cpu += metrics.ema_cpu_percent;
            total_ram += metrics.ema_ram_mb;

            let cpu_crit = metrics.ema_cpu_percent >= self.tab_cpu_critical_pct;
            let cpu_warn = metrics.ema_cpu_percent >= self.tab_cpu_warning_pct;
            let ram_crit = metrics.ema_ram_mb >= self.tab_ram_critical_mb;
            let ram_warn = metrics.ema_ram_mb >= self.tab_ram_warning_mb;

            if cpu_crit || ram_crit {
                status = HealthStatus::Critical;
                anomalous_tabs.push(metrics.tab_id);
                if !metrics.is_active && ram_crit {
                    actions.push(OptimizationAction::DiscardHighMemoryTab {
                        tab_id: metrics.tab_id,
                        ema_ram_mb: metrics.ema_ram_mb,
                    });
                } else if !metrics.is_active && cpu_crit {
                    actions.push(OptimizationAction::FreezeBackgroundTab {
                        tab_id: metrics.tab_id,
                        ema_cpu_percent: metrics.ema_cpu_percent,
                        ema_ram_mb: metrics.ema_ram_mb,
                    });
                } else {
                    actions.push(OptimizationAction::ThrottleTabTimers {
                        tab_id: metrics.tab_id,
                        reason: format!(
                            "Sustained foreground pressure (CPU {:.1}%, RAM {:.0} MiB)",
                            metrics.ema_cpu_percent, metrics.ema_ram_mb
                        ),
                    });
                }
            } else if (cpu_warn || ram_warn) && metrics.consecutive_anomaly_ticks >= 2 {
                if status < HealthStatus::Warning {
                    status = HealthStatus::Warning;
                }
                anomalous_tabs.push(metrics.tab_id);
                if !metrics.is_active {
                    actions.push(OptimizationAction::FreezeBackgroundTab {
                        tab_id: metrics.tab_id,
                        ema_cpu_percent: metrics.ema_cpu_percent,
                        ema_ram_mb: metrics.ema_ram_mb,
                    });
                } else {
                    actions.push(OptimizationAction::ThrottleTabTimers {
                        tab_id: metrics.tab_id,
                        reason: format!(
                            "Elevated CPU/RAM EMA (CPU {:.1}%, RAM {:.0} MiB)",
                            metrics.ema_cpu_percent, metrics.ema_ram_mb
                        ),
                    });
                }
            }
        }

        if total_ram >= self.total_ram_critical_mb {
            status = HealthStatus::Critical;
            actions.push(OptimizationAction::PurgeAssetCache {
                target_reclaim_mb: 256,
            });
            actions.push(OptimizationAction::DowngradeShaders {
                reason: format!("Total browser RAM {:.0} MiB exceeds critical limit", total_ram),
            });
        } else if total_ram >= self.total_ram_warning_mb {
            if status < HealthStatus::Warning {
                status = HealthStatus::Warning;
            }
            actions.push(OptimizationAction::PurgeAssetCache {
                target_reclaim_mb: 128,
            });
        }

        if total_cpu >= 180.0 {
            if status < HealthStatus::Warning {
                status = HealthStatus::Warning;
            }
            actions.push(OptimizationAction::DowngradeShaders {
                reason: format!("High aggregate CPU EMA ({:.1}%)", total_cpu),
            });
        }

        HealthReport {
            status,
            total_ema_cpu_percent: total_cpu,
            total_ema_ram_mb: total_ram,
            anomalous_tabs,
            recommended_actions: actions,
        }
    }
}

/// Summary snapshot of a local offline logarithmic histogram.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HistogramSummary {
    pub name: String,
    pub count: u64,
    pub min: Option<u64>,
    pub max: Option<u64>,
    pub mean: Option<f64>,
    pub p50: Option<u64>,
    pub p95: Option<u64>,
    pub p99: Option<u64>,
}

/// Constant-memory logarithmic-bucket histogram with exact resolution for 0..=15
/// and 4 sub-buckets per power-of-two octave up to 2^40 (~1 trillion).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogHistogram {
    upper_bounds: Vec<u64>,
    counts: Vec<u64>,
    total_count: u64,
    sum: u128,
    min_val: u64,
    max_val: u64,
}

impl Default for LogHistogram {
    fn default() -> Self {
        Self::new()
    }
}

impl LogHistogram {
    pub fn new() -> Self {
        let mut upper_bounds = Vec::with_capacity(176);
        // Exact integer buckets 0..=15
        for v in 0u64..=15 {
            upper_bounds.push(v);
        }
        // Logarithmic buckets: 4 sub-buckets per power-of-2 octave from 16 up to 2^40
        for exp in 4u32..40 {
            let base = 1u64 << exp;
            let step = base / 4;
            for q in 1u64..=4 {
                upper_bounds.push(base + step * q - 1);
            }
        }
        upper_bounds.push(u64::MAX);
        let counts = vec![0u64; upper_bounds.len()];
        Self {
            upper_bounds,
            counts,
            total_count: 0,
            sum: 0,
            min_val: u64::MAX,
            max_val: 0,
        }
    }

    pub fn record(&mut self, value: u64) {
        let idx = match self.upper_bounds.binary_search(&value) {
            Ok(i) | Err(i) => i.min(self.counts.len() - 1),
        };
        self.counts[idx] = self.counts[idx].saturating_add(1);
        self.total_count = self.total_count.saturating_add(1);
        self.sum = self.sum.saturating_add(u128::from(value));
        if value < self.min_val {
            self.min_val = value;
        }
        if value > self.max_val {
            self.max_val = value;
        }
    }

    pub fn count(&self) -> u64 {
        self.total_count
    }

    pub fn min(&self) -> Option<u64> {
        (self.total_count > 0).then_some(self.min_val)
    }

    pub fn max(&self) -> Option<u64> {
        (self.total_count > 0).then_some(self.max_val)
    }

    pub fn mean(&self) -> Option<f64> {
        if self.total_count == 0 {
            None
        } else {
            Some(self.sum as f64 / self.total_count as f64)
        }
    }

    /// Computes approximate quantile `p` (`0.0..=1.0`, e.g. `0.50`, `0.95`, `0.99`),
    /// clamped within `[min, max]`.
    pub fn percentile(&self, p: f64) -> Option<u64> {
        if self.total_count == 0 {
            return None;
        }
        let clamped_p = p.clamp(0.0, 1.0);
        let rank = ((clamped_p * self.total_count as f64).ceil() as u64).clamp(1, self.total_count);
        let mut cumulative = 0u64;
        for (idx, &c) in self.counts.iter().enumerate() {
            cumulative = cumulative.saturating_add(c);
            if cumulative >= rank {
                let bound = self.upper_bounds[idx];
                return Some(bound.clamp(self.min_val, self.max_val));
            }
        }
        Some(self.max_val)
    }

    pub fn p50(&self) -> Option<u64> {
        self.percentile(0.50)
    }

    pub fn p95(&self) -> Option<u64> {
        self.percentile(0.95)
    }

    pub fn p99(&self) -> Option<u64> {
        self.percentile(0.99)
    }

    pub fn reset(&mut self) {
        self.counts.fill(0);
        self.total_count = 0;
        self.sum = 0;
        self.min_val = u64::MAX;
        self.max_val = 0;
    }
}

/// 100% offline registry of local performance histograms (frame time, DNS RTT, cache latency, etc.).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LocalHistogramRegistry {
    histograms: BTreeMap<String, LogHistogram>,
}

impl LocalHistogramRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, metric_name: &str, value: u64) {
        if metric_name.is_empty() {
            return;
        }
        self.histograms
            .entry(metric_name.to_string())
            .or_default()
            .record(value);
    }

    /// Returns `(p50, p95, p99)` for `metric_name` if at least one sample was recorded.
    pub fn percentiles(&self, metric_name: &str) -> Option<(u64, u64, u64)> {
        let h = self.histograms.get(metric_name)?;
        Some((h.p50()?, h.p95()?, h.p99()?))
    }

    pub fn summary(&self, metric_name: &str) -> Option<HistogramSummary> {
        let h = self.histograms.get(metric_name)?;
        Some(HistogramSummary {
            name: metric_name.to_string(),
            count: h.count(),
            min: h.min(),
            max: h.max(),
            mean: h.mean(),
            p50: h.p50(),
            p95: h.p95(),
            p99: h.p99(),
        })
    }

    pub fn metric_names(&self) -> Vec<String> {
        self.histograms.keys().cloned().collect()
    }

    pub fn clear(&mut self) {
        self.histograms.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_detector_ema_anomalies_and_offline_log_histograms() {
        let mut detector = PerformanceHealthDetector::new();

        // Healthy tab
        detector.record_tab_sample(TabTelemetrySample {
            tab_id: 1,
            cpu_percent: 4.0,
            ram_mb: 120.0,
            is_active: true,
            timestamp_unix: 100,
        });
        assert_eq!(detector.evaluate_health().status, HealthStatus::Healthy);

        // Runaway background tab with sustained CPU/RAM leak
        for tick in 0..4 {
            detector.record_tab_sample(TabTelemetrySample {
                tab_id: 2,
                cpu_percent: 95.0,
                ram_mb: 1400.0,
                is_active: false,
                timestamp_unix: 101 + tick,
            });
        }
        let report = detector.evaluate_health();
        assert_eq!(report.status, HealthStatus::Critical);
        assert!(report.anomalous_tabs.contains(&2));
        assert!(report
            .recommended_actions
            .iter()
            .any(|a| matches!(a, OptimizationAction::DiscardHighMemoryTab { tab_id: 2, .. })));

        // Local logarithmic histogram registry p50 / p95 / p99
        let mut reg = LocalHistogramRegistry::new();
        for v in 1u64..=100 {
            reg.record("dns_lookup_ms", v);
        }
        let (p50, p95, p99) = reg.percentiles("dns_lookup_ms").expect("percentiles");
        assert!((45..=65).contains(&p50), "p50={}", p50);
        assert!((90..=100).contains(&p95), "p95={}", p95);
        assert!((95..=100).contains(&p99), "p99={}", p99);
        let summary = reg.summary("dns_lookup_ms").unwrap();
        assert_eq!(summary.count, 100);
        assert_eq!(summary.min, Some(1));
        assert_eq!(summary.max, Some(100));
    }
}
