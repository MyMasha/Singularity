//! Core schema definitions for the Singularity 2,000+ Settings Registry.

use serde::{Deserialize, Serialize};
use std::fmt;

/// The 8 mandatory power-user configuration categories in `singularity://settings` & `singularity://flags`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SettingCategory {
    SecurityHardening,
    PrivacyAntiFingerprinting,
    NetworkDnsHttp3,
    MullvadWireGuard,
    RenderingGpuPerformance,
    PasswordManagerCrypto,
    MediaAudioVideo,
    ThemesCursorsUiUx,
}

impl SettingCategory {
    pub const ALL: [SettingCategory; 8] = [
        SettingCategory::SecurityHardening,
        SettingCategory::PrivacyAntiFingerprinting,
        SettingCategory::NetworkDnsHttp3,
        SettingCategory::MullvadWireGuard,
        SettingCategory::RenderingGpuPerformance,
        SettingCategory::PasswordManagerCrypto,
        SettingCategory::MediaAudioVideo,
        SettingCategory::ThemesCursorsUiUx,
    ];

    pub fn display_name(&self) -> &'static str {
        match self {
            Self::SecurityHardening => "1. Security & Hardening",
            Self::PrivacyAntiFingerprinting => "2. Privacy & Anti-Fingerprinting",
            Self::NetworkDnsHttp3 => "3. Network, DNS & HTTP/3 Optimization",
            Self::MullvadWireGuard => "4. Mullvad VPN & WireGuard Tuning",
            Self::RenderingGpuPerformance => "5. Rendering, GPU & Performance",
            Self::PasswordManagerCrypto => "6. Password Manager & Cryptography",
            Self::MediaAudioVideo => "7. Media, Audio & Video Engine",
            Self::ThemesCursorsUiUx => "8. Themes, Cursors & UI/UX Customization",
        }
    }

    pub fn slug(&self) -> &'static str {
        match self {
            Self::SecurityHardening => "security",
            Self::PrivacyAntiFingerprinting => "privacy",
            Self::NetworkDnsHttp3 => "network",
            Self::MullvadWireGuard => "mullvad",
            Self::RenderingGpuPerformance => "rendering",
            Self::PasswordManagerCrypto => "vault",
            Self::MediaAudioVideo => "media",
            Self::ThemesCursorsUiUx => "ui",
        }
    }
}

impl fmt::Display for SettingCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.display_name())
    }
}

/// Target internal browser subsystem notified on live hot-reload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TargetSubsystem {
    ChromiumSandbox,
    V8Engine,
    BlinkFingerprintingGuard,
    RustNetworkPool,
    MullvadWireGuardTunnel,
    GpuCompositor,
    Argon2Vault,
    MediaPipeline,
    OledThemeEngine,
    CustomCursorEngine,
}

impl TargetSubsystem {
    pub fn slug(&self) -> &'static str {
        match self {
            Self::ChromiumSandbox => "chromium_sandbox",
            Self::V8Engine => "v8_engine",
            Self::BlinkFingerprintingGuard => "blink_fingerprinting_guard",
            Self::RustNetworkPool => "rust_network_pool",
            Self::MullvadWireGuardTunnel => "mullvad_wireguard_tunnel",
            Self::GpuCompositor => "gpu_compositor",
            Self::Argon2Vault => "argon2_vault",
            Self::MediaPipeline => "media_pipeline",
            Self::OledThemeEngine => "oled_theme_engine",
            Self::CustomCursorEngine => "custom_cursor_engine",
        }
    }
}

/// Strongly-typed configuration value supporting booleans, integers, floats, strings, and RGBA hex tokens.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum SettingValue {
    Bool(bool),
    Int(i64),
    Float(f64),
    Text(String),
    ColorHex(String),
}

impl SettingValue {
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<i64> {
        match self {
            Self::Int(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_float(&self) -> Option<f64> {
        match self {
            Self::Float(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Text(s) | Self::ColorHex(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn matches_type(&self, other: &Self) -> bool {
         matches!(
            (self, other),
            (Self::Bool(_), Self::Bool(_))
                | (Self::Int(_), Self::Int(_))
                | (Self::Float(_), Self::Float(_))
                | (Self::Text(_), Self::Text(_))
                | (Self::ColorHex(_), Self::ColorHex(_))
        )
    }
}

impl fmt::Display for SettingValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bool(b) => write!(f, "{}", b),
            Self::Int(i) => write!(f, "{}", i),
            Self::Float(fl) => write!(f, "{:.4}", fl),
            Self::Text(s) => write!(f, "\"{}\"", s),
            Self::ColorHex(c) => write!(f, "{}", c),
        }
    }
}

/// Optional numeric or enum constraint validation rules for a setting.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ValueConstraint {
    Unconstrained,
    IntRange { min: i64, max: i64 },
    FloatRange { min: f64, max: f64 },
    AllowedValues(Vec<String>),
    HexColorFormat,
}

impl ValueConstraint {
    pub fn validate(&self, val: &SettingValue) -> bool {
        if let SettingValue::Float(v) = val {
            if !v.is_finite() {
                return false;
            }
        }
        match (self, val) {
            (Self::Unconstrained, _) => true,
            (Self::IntRange { min, max }, SettingValue::Int(v)) => v >= min && v <= max,
            (Self::FloatRange { min, max }, SettingValue::Float(v)) => v >= min && v <= max,
            (Self::AllowedValues(allowed), SettingValue::Text(s)) => allowed.contains(s),
            (Self::HexColorFormat, SettingValue::ColorHex(c)) => {
                c.starts_with('#') && (c.len() == 7 || c.len() == 9) && c[1..].chars().all(|ch| ch.is_ascii_hexdigit())
            }
            _ => false,
        }
    }
}

/// Complete schema definition and active state for a single setting in `singularity://settings`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettingEntry {
    pub id: usize,
    pub key: String,
    pub category: SettingCategory,
    pub subsystem: TargetSubsystem,
    pub title: String,
    pub description: String,
    pub default_value: SettingValue,
    pub current_value: SettingValue,
    pub constraint: ValueConstraint,
    pub chromium_switch: Option<String>,
    pub hot_reloadable: bool,
}

impl SettingEntry {
    pub fn is_modified(&self) -> bool {
        self.current_value != self.default_value
    }

    /// Formats the corresponding Chromium command-line switch or gn feature override if mapped.
    pub fn to_chromium_cli_arg(&self) -> Option<String> {
        let switch = self.chromium_switch.as_ref()?;
        match &self.current_value {
            SettingValue::Bool(true) => Some(format!("--{}", switch)),
            SettingValue::Bool(false) => Some(format!("--{}=false", switch)),
            SettingValue::Int(v) => Some(format!("--{}={}", switch, v)),
            SettingValue::Float(v) => Some(format!("--{}={:.4}", switch, v)),
            SettingValue::Text(s) | SettingValue::ColorHex(s) => Some(format!("--{}={}", switch, s)),
        }
    }
}

/// Event emitted to live subsystem hooks whenever a setting is mutated at runtime.
#[derive(Debug, Clone)]
pub struct HotReloadEvent {
    pub key: String,
    pub category: SettingCategory,
    pub subsystem: TargetSubsystem,
    pub old_value: SettingValue,
    pub new_value: SettingValue,
    pub chromium_cli_arg: Option<String>,
}
