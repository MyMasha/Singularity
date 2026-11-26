//! Power Telemetry (`/sys/class/power_supply` on Linux), Energy Saver Activation Policies,
//! Shader Battery Adaptation, and Power Policy Orchestrator.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// Live host power-supply telemetry sampled without external dependencies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PowerTelemetry {
    pub on_ac_power: bool,
    pub battery_percent: Option<u8>,
    pub is_charging: bool,
    pub os_battery_saver: bool,
}

impl Default for PowerTelemetry {
    fn default() -> Self {
        Self {
            on_ac_power: true,
            battery_percent: None,
            is_charging: false,
            os_battery_saver: false,
        }
    }
}

impl PowerTelemetry {
    /// Samples current host AC / battery / OS power-saver status.
    /// On Linux reads `/sys/class/power_supply/*` and `/sys/firmware/acpi/platform_profile`.
    pub fn sample() -> Self {
        #[cfg(target_os = "linux")]
        {
            let mut telemetry = Self::from_sysfs_dir(Path::new("/sys/class/power_supply"));
            if let Ok(profile) = std::fs::read_to_string("/sys/firmware/acpi/platform_profile") {
                if profile.trim().eq_ignore_ascii_case("low-power") {
                    telemetry.os_battery_saver = true;
                }
            }
            telemetry
        }

        #[cfg(not(target_os = "linux"))]
        {
            Self::default()
        }
    }

    /// Parses a Linux-style `power_supply` directory (also used for deterministic unit tests).
    pub fn from_sysfs_dir(power_supply_dir: &Path) -> Self {
        let Ok(entries) = std::fs::read_dir(power_supply_dir) else {
            return Self::default();
        };

        let mut saw_mains = false;
        let mut mains_online = false;
        let mut battery_percents: Vec<u8> = Vec::new();
        let mut any_charging = false;
        let mut any_discharging = false;

        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let supply_type = std::fs::read_to_string(path.join("type"))
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase();

            match supply_type.as_str() {
                "mains" | "usb" => {
                    saw_mains = true;
                    if let Ok(online) = std::fs::read_to_string(path.join("online")) {
                        if online.trim() == "1" {
                            mains_online = true;
                        }
                    }
                }
                "battery" => {
                    if let Ok(cap_str) = std::fs::read_to_string(path.join("capacity")) {
                        if let Ok(cap) = cap_str.trim().parse::<u8>() {
                            battery_percents.push(cap.min(100));
                        }
                    }
                    if let Ok(status) = std::fs::read_to_string(path.join("status")) {
                        let st = status.trim().to_ascii_lowercase();
                        if st == "charging" || st == "full" {
                            any_charging = true;
                        } else if st == "discharging" {
                            any_discharging = true;
                        }
                    }
                }
                _ => {}
            }
        }

        let battery_percent = if battery_percents.is_empty() {
            None
        } else {
            let sum: u32 = battery_percents.iter().map(|&p| u32::from(p)).sum();
            Some((sum / battery_percents.len() as u32).min(100) as u8)
        };

        let on_ac_power = if saw_mains {
            mains_online
        } else if battery_percent.is_some() {
            any_charging && !any_discharging
        } else {
            true
        };

        Self {
            on_ac_power,
            battery_percent,
            is_charging: any_charging && !any_discharging,
            os_battery_saver: false,
        }
    }
}

/// Policy determining when Singularity automatically engages Energy Saver mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnergySaverActivationPolicy {
    Off,
    AlwaysOn,
    OnBatteryOnly,
    BelowBatteryPercent(u8),
    FollowOsBatterySaver,
}

/// GPU shader rendering tier adapted to power state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShaderBatteryMode {
    Full,
    Lite30Fps,
    StaticPaused,
}

/// Concrete browser adaptation directives emitted by [`PowerPolicyOrchestrator`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PowerAdaptationDecision {
    pub energy_saver_engaged: bool,
    pub target_frame_rate_hz: u32,
    pub shader_mode: ShaderBatteryMode,
    pub background_timer_throttle_ms: u32,
    pub disable_speculative_preload: bool,
    pub freeze_timeout_seconds: u64,
    pub prefer_low_power_gpu: bool,
    pub reason: String,
}

/// Evaluates [`PowerTelemetry`] under [`EnergySaverActivationPolicy`] to adapt frame rate,
/// GPU shaders, timer coalescing, speculative preloading, and tab freezing aggressiveness.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PowerPolicyOrchestrator {
    policy: EnergySaverActivationPolicy,
    ac_target_fps: u32,
    battery_target_fps: u32,
    eco_target_fps: u32,
    last_telemetry: PowerTelemetry,
}

impl Default for PowerPolicyOrchestrator {
    fn default() -> Self {
        Self::new(EnergySaverActivationPolicy::BelowBatteryPercent(20))
    }
}

impl PowerPolicyOrchestrator {
    pub fn new(policy: EnergySaverActivationPolicy) -> Self {
        Self {
            policy,
            ac_target_fps: 200,
            battery_target_fps: 60,
            eco_target_fps: 30,
            last_telemetry: PowerTelemetry::default(),
        }
    }

    pub fn set_policy(&mut self, policy: EnergySaverActivationPolicy) {
        self.policy = policy;
    }

    pub fn policy(&self) -> EnergySaverActivationPolicy {
        self.policy
    }

    pub fn set_target_fps_tiers(&mut self, ac_fps: u32, battery_fps: u32, eco_fps: u32) {
        self.ac_target_fps = ac_fps.clamp(30, 360);
        self.battery_target_fps = battery_fps.clamp(24, self.ac_target_fps);
        self.eco_target_fps = eco_fps.clamp(15, self.battery_target_fps);
    }

    pub fn last_telemetry(&self) -> PowerTelemetry {
        self.last_telemetry
    }

    /// Samples live OS power telemetry and evaluates adaptation directives.
    pub fn refresh_and_evaluate(&mut self) -> PowerAdaptationDecision {
        let telemetry = PowerTelemetry::sample();
        self.evaluate(telemetry)
    }

    /// Evaluates adaptation directives for an explicit [`PowerTelemetry`] snapshot.
    pub fn evaluate(&mut self, telemetry: PowerTelemetry) -> PowerAdaptationDecision {
        self.last_telemetry = telemetry;

        // Critical battery emergency (<= 10% discharging) always pauses shaders unless policy is Off.
        let critical_battery = !telemetry.on_ac_power
            && !telemetry.is_charging
            && telemetry.battery_percent.is_some_and(|p| p <= 10);

        let (engage_saver, reason) = match self.policy {
            EnergySaverActivationPolicy::Off => (false, "Energy saver disabled by user".into()),
            EnergySaverActivationPolicy::AlwaysOn => {
                (true, "Energy saver forced always-on".into())
            }
            EnergySaverActivationPolicy::OnBatteryOnly => {
                if !telemetry.on_ac_power {
                    (true, "Running on battery power".into())
                } else {
                    (false, "Connected to AC power".into())
                }
            }
            EnergySaverActivationPolicy::BelowBatteryPercent(threshold) => {
                if telemetry.os_battery_saver {
                    (true, "OS battery saver active".into())
                } else if !telemetry.on_ac_power
                    && telemetry.battery_percent.is_some_and(|p| p <= threshold)
                {
                    (
                        true,
                        format!(
                            "Battery {}% at or below {}% threshold",
                            telemetry.battery_percent.unwrap_or(0),
                            threshold
                        ),
                    )
                } else {
                    (false, "Battery above energy saver threshold".into())
                }
            }
            EnergySaverActivationPolicy::FollowOsBatterySaver => {
                if telemetry.os_battery_saver {
                    (true, "Following OS battery saver".into())
                } else {
                    (false, "OS battery saver inactive".into())
                }
            }
        };

        if critical_battery && self.policy != EnergySaverActivationPolicy::Off {
            return PowerAdaptationDecision {
                energy_saver_engaged: true,
                target_frame_rate_hz: self.eco_target_fps,
                shader_mode: ShaderBatteryMode::StaticPaused,
                background_timer_throttle_ms: 2_000,
                disable_speculative_preload: true,
                freeze_timeout_seconds: 30,
                prefer_low_power_gpu: true,
                reason: "Critical battery level (<= 10%): pausing shaders and aggressive freezing"
                    .into(),
            };
        }

        if engage_saver {
            return PowerAdaptationDecision {
                energy_saver_engaged: true,
                target_frame_rate_hz: self.eco_target_fps,
                shader_mode: ShaderBatteryMode::Lite30Fps,
                background_timer_throttle_ms: 1_000,
                disable_speculative_preload: true,
                freeze_timeout_seconds: 45,
                prefer_low_power_gpu: true,
                reason,
            };
        }

        if !telemetry.on_ac_power {
            return PowerAdaptationDecision {
                energy_saver_engaged: false,
                target_frame_rate_hz: self.battery_target_fps,
                shader_mode: ShaderBatteryMode::Lite30Fps,
                background_timer_throttle_ms: 500,
                disable_speculative_preload: false,
                freeze_timeout_seconds: 90,
                prefer_low_power_gpu: true,
                reason: "Unplugged on battery: balanced 60Hz power profile".into(),
            };
        }

        PowerAdaptationDecision {
            energy_saver_engaged: false,
            target_frame_rate_hz: self.ac_target_fps,
            shader_mode: ShaderBatteryMode::Full,
            background_timer_throttle_ms: 100,
            disable_speculative_preload: false,
            freeze_timeout_seconds: 180,
            prefer_low_power_gpu: false,
            reason,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sysfs_power_supply_parsing_and_policy_orchestrator() {
        let tmp = std::env::temp_dir().join(format!(
            "singularity_power_sysfs_test_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        let ac_dir = tmp.join("AC0");
        let bat_dir = tmp.join("BAT0");
        std::fs::create_dir_all(&ac_dir).unwrap();
        std::fs::create_dir_all(&bat_dir).unwrap();
        std::fs::write(ac_dir.join("type"), "Mains\n").unwrap();
        std::fs::write(ac_dir.join("online"), "0\n").unwrap();
        std::fs::write(bat_dir.join("type"), "Battery\n").unwrap();
        std::fs::write(bat_dir.join("capacity"), "18\n").unwrap();
        std::fs::write(bat_dir.join("status"), "Discharging\n").unwrap();

        let telemetry = PowerTelemetry::from_sysfs_dir(&tmp);
        let _ = std::fs::remove_dir_all(&tmp);

        assert!(!telemetry.on_ac_power);
        assert_eq!(telemetry.battery_percent, Some(18));
        assert!(!telemetry.is_charging);

        let mut orch = PowerPolicyOrchestrator::new(EnergySaverActivationPolicy::BelowBatteryPercent(20));
        let decision = orch.evaluate(telemetry);
        assert!(decision.energy_saver_engaged);
        assert_eq!(decision.shader_mode, ShaderBatteryMode::Lite30Fps);
        assert!(decision.disable_speculative_preload);
        assert_eq!(decision.target_frame_rate_hz, 30);

        // Critical battery pauses shaders statically
        let crit = orch.evaluate(PowerTelemetry {
            on_ac_power: false,
            battery_percent: Some(8),
            is_charging: false,
            os_battery_saver: false,
        });
        assert_eq!(crit.shader_mode, ShaderBatteryMode::StaticPaused);

        // On AC power enables Full shaders and max FPS
        let ac = orch.evaluate(PowerTelemetry {
            on_ac_power: true,
            battery_percent: Some(95),
            is_charging: true,
            os_battery_saver: false,
        });
        assert!(!ac.energy_saver_engaged);
        assert_eq!(ac.shader_mode, ShaderBatteryMode::Full);
        assert_eq!(ac.target_frame_rate_hz, 200);
    }
}
