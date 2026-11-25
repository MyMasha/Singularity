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

const MAX_SETTING_TEXT_LEN: usize = 4096;

/// Chromium switches whose legitimate string values contain internal ASCII spaces.
const SPACE_ALLOWED_CHROMIUM_SWITCHES: &[&str] = &[
    "user-agent",
    "webgl-spoof-vendor",
    "webgl-spoof-renderer",
    "singularity-global-csp",
];

fn contains_control_or_nul(s: &str) -> bool {
    s.bytes().any(|b| b == 0) || s.chars().any(|c| c.is_control())
}

fn is_valid_hex_color(c: &str) -> bool {
    c.starts_with('#')
        && (c.len() == 7 || c.len() == 9)
        && c[1..].chars().all(|ch| ch.is_ascii_hexdigit())
}

fn is_valid_chromium_switch_name(switch: &str) -> bool {
    !switch.is_empty()
        && !switch.starts_with('-')
        && !switch.contains("--")
        && switch
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn is_safe_cli_value(switch: &str, value: &str) -> bool {
    if contains_control_or_nul(value) || value.len() > MAX_SETTING_TEXT_LEN {
        return false;
    }
    if value.is_empty() {
        return true;
    }
    if value.starts_with('-')
        || value.contains("--")
        || value
            .chars()
            .any(|c| matches!(c, '"' | '`' | '\\' | '|' | '&' | '$'))
    {
        return false;
    }

    let sw_lower = switch.to_ascii_lowercase();
    if SPACE_ALLOWED_CHROMIUM_SWITCHES.contains(&sw_lower.as_str()) {
        if value != value.trim() {
            return false;
        }
        if value.chars().any(|c| c.is_whitespace() && c != ' ') {
            return false;
        }
        if value.split(' ').any(|tok| tok.starts_with('-')) {
            return false;
        }
        true
    } else {
        !value
            .chars()
            .any(|c| c.is_whitespace() || matches!(c, '\'' | ';'))
    }
}

fn is_path_sensitive_key(key_lower: &str) -> bool {
    key_lower.contains("path")
        || key_lower.contains("dir")
        || key_lower.contains("file")
        || key_lower.contains("cursor")
        || key_lower.contains("theme")
        || key_lower.contains("vault")
}

fn has_path_traversal(value: &str) -> bool {
    if value.contains("..") || value.starts_with("\\\\") {
        return true;
    }
    let lower = value.to_ascii_lowercase();
    lower.contains("%2e%2e")
        || lower.contains("%2e.")
        || lower.contains(".%2e")
        || lower.contains("%2f")
        || lower.contains("%5c")
}

fn is_endpoint_like_key(key_lower: &str, constraint: &ValueConstraint) -> bool {
    if matches!(constraint, ValueConstraint::AllowedValues(_)) {
        return false;
    }
    if key_lower.starts_with("ui.keybind.") {
        return false;
    }
    key_lower.contains("endpoint")
        || key_lower.contains("url")
        || key_lower.contains("proxy")
        || key_lower.contains("dns")
}

fn is_valid_host_port(host_port: &str) -> bool {
    if host_port.is_empty() {
        return false;
    }
    if let Some(rest) = host_port.strip_prefix('[') {
        let Some((ipv6, after_bracket)) = rest.split_once(']') else {
            return false;
        };
        if ipv6.is_empty()
            || !ipv6.contains(':')
            || !ipv6
                .chars()
                .all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.')
        {
            return false;
        }
        if after_bracket.is_empty() {
            return true;
        }
        let Some(port_str) = after_bracket.strip_prefix(':') else {
            return false;
        };
        return port_str.parse::<u16>().is_ok_and(|p| p > 0);
    }

    let (host, port_opt) = match host_port.split_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (host_port, None),
    };
    if host.is_empty()
        || host.starts_with('.')
        || host.ends_with('.')
        || host.starts_with('-')
        || host.ends_with('-')
        || host.contains("..")
        || !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return false;
    }
    if let Some(port_str) = port_opt {
        if port_str.is_empty() || !port_str.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
        return port_str.parse::<u16>().is_ok_and(|p| p > 0);
    }
    true
}

fn is_valid_endpoint_uri(key_lower: &str, value: &str, default_is_empty: bool) -> bool {
    if value.is_empty() {
        return default_is_empty || key_lower.contains("proxy") || key_lower.contains("fallback");
    }
    if contains_control_or_nul(value)
        || value.chars().any(char::is_whitespace)
        || value.contains("--")
        || value
            .chars()
            .any(|c| matches!(c, '"' | '\'' | '`' | '<' | '>' | ';' | '|' | '\\'))
    {
        return false;
    }

    let Some((scheme, rest)) = value.split_once("://") else {
        return false;
    };
    let scheme_lower = scheme.to_ascii_lowercase();
    let is_proxy = key_lower.contains("proxy");
    let allowed_schemes: &[&str] = if is_proxy {
        &["socks5h", "socks5", "https"]
    } else if key_lower.contains("dns") {
        &["https", "quic", "tls", "h3"]
    } else {
        &["https", "quic", "tls"]
    };
    if !allowed_schemes.contains(&scheme_lower.as_str()) {
        return false;
    }

    if rest.is_empty() || rest.contains("..") {
        return false;
    }

    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() {
        return false;
    }

    let host_port = if let Some((userinfo, hp)) = authority.rsplit_once('@') {
        if !is_proxy || userinfo.is_empty() {
            return false;
        }
        hp
    } else {
        authority
    };

    is_valid_host_port(host_port)
}

impl ValueConstraint {
    pub fn validate(&self, val: &SettingValue) -> bool {
        match val {
            SettingValue::Float(v) if !v.is_finite() => return false,
            SettingValue::Text(s) => {
                if contains_control_or_nul(s) || s.len() > MAX_SETTING_TEXT_LEN {
                    return false;
                }
            }
            SettingValue::ColorHex(c) => {
                if contains_control_or_nul(c) || !is_valid_hex_color(c) {
                    return false;
                }
            }
            _ => {}
        }

        match (self, val) {
            (Self::Unconstrained, _) => true,
            (Self::IntRange { min, max }, SettingValue::Int(v)) => min <= max && v >= min && v <= max,
            (Self::FloatRange { min, max }, SettingValue::Float(v)) => {
                min.is_finite() && max.is_finite() && min <= max && v >= min && v <= max
            }
            (Self::AllowedValues(allowed), SettingValue::Text(s)) => allowed.contains(s),
            (Self::HexColorFormat, SettingValue::ColorHex(c)) => is_valid_hex_color(c),
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

    /// Validates both type/constraint compliance and security invariants (control chars/NUL,
    /// CLI switch argument injection, path traversal, and endpoint/URL/proxy/DNS scheme safety).
    pub fn validate_value(&self, val: &SettingValue) -> bool {
        if !self.default_value.matches_type(val) || !self.constraint.validate(val) {
            return false;
        }

        if let SettingValue::Text(s) = val {
            if contains_control_or_nul(s) || s.len() > MAX_SETTING_TEXT_LEN {
                return false;
            }

            if let Some(ref switch) = self.chromium_switch {
                if !is_valid_chromium_switch_name(switch) || !is_safe_cli_value(switch, s) {
                    return false;
                }
            }

            let key_lower = self.key.to_ascii_lowercase();
            if is_path_sensitive_key(&key_lower) && has_path_traversal(s) {
                return false;
            }

            if is_endpoint_like_key(&key_lower, &self.constraint) {
                let default_is_empty = self.default_value.as_str() == Some("");
                if !is_valid_endpoint_uri(&key_lower, s, default_is_empty) {
                    return false;
                }
            }
        }

        true
    }

    fn switch_expects_bytes_from_mib(&self, switch: &str) -> bool {
        let key_lower = self.key.to_ascii_lowercase();
        let sw_lower = switch.to_ascii_lowercase();
        if sw_lower == "disk-cache-size" || sw_lower == "media-cache-size" {
            return true;
        }
        let key_is_mib = key_lower.ends_with("_mb")
            || key_lower.ends_with("_mib")
            || key_lower.contains("_mb_")
            || key_lower.contains("_mib_");
        let switch_is_bytes = !sw_lower.ends_with("-mb")
            && !sw_lower.ends_with("-mib")
            && !sw_lower.ends_with("-gb")
            && !sw_lower.ends_with("-kb");
        key_is_mib && switch_is_bytes
    }

    /// Formats the corresponding Chromium command-line switch or gn feature override if mapped.
    pub fn to_chromium_cli_arg(&self) -> Option<String> {
        let switch = self.chromium_switch.as_ref()?;
        if !is_valid_chromium_switch_name(switch) {
            return None;
        }

        match &self.current_value {
            SettingValue::Bool(true) => Some(format!("--{}", switch)),
            SettingValue::Bool(false) => None,
            SettingValue::Int(v) => {
                if self.switch_expects_bytes_from_mib(switch) {
                    if *v < 0 {
                        return None;
                    }
                    let bytes = v.saturating_mul(1024 * 1024);
                    Some(format!("--{}={}", switch, bytes))
                } else {
                    Some(format!("--{}={}", switch, v))
                }
            }
            SettingValue::Float(v) => {
                if !v.is_finite() {
                    return None;
                }
                Some(format!("--{}={:.4}", switch, v))
            }
            SettingValue::Text(s) => {
                if s.trim().is_empty() {
                    return None;
                }
                if !is_safe_cli_value(switch, s) || !self.validate_value(&self.current_value) {
                    return None;
                }
                Some(format!("--{}={}", switch, s))
            }
            SettingValue::ColorHex(c) => {
                if c.trim().is_empty() || !is_valid_hex_color(c) || !is_safe_cli_value(switch, c) {
                    return None;
                }
                Some(format!("--{}={}", switch, c))
            }
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
    pub requires_restart: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry(
        key: &str,
        default_value: SettingValue,
        constraint: ValueConstraint,
        chromium_switch: Option<&str>,
    ) -> SettingEntry {
        SettingEntry {
            id: 1,
            key: key.to_string(),
            category: SettingCategory::SecurityHardening,
            subsystem: TargetSubsystem::ChromiumSandbox,
            title: "Test".into(),
            description: "Test".into(),
            current_value: default_value.clone(),
            default_value,
            constraint,
            chromium_switch: chromium_switch.map(str::to_string),
            hot_reloadable: true,
        }
    }

    #[test]
    fn test_value_constraint_rejects_control_nul_and_non_finite() {
        assert!(!ValueConstraint::Unconstrained.validate(&SettingValue::Text("abc\0def".into())));
        assert!(!ValueConstraint::Unconstrained.validate(&SettingValue::Text("abc\ndef".into())));
        assert!(!ValueConstraint::Unconstrained.validate(&SettingValue::Text("abc\rdef".into())));
        assert!(!ValueConstraint::Unconstrained.validate(&SettingValue::Text("abc\x1bdef".into())));
        assert!(!ValueConstraint::Unconstrained.validate(&SettingValue::Float(f64::NAN)));
        assert!(!ValueConstraint::Unconstrained.validate(&SettingValue::Float(f64::INFINITY)));
        assert!(!ValueConstraint::HexColorFormat.validate(&SettingValue::ColorHex("#000000\n".into())));
        assert!(ValueConstraint::HexColorFormat.validate(&SettingValue::ColorHex("#6E00FFFF".into())));
    }

    #[test]
    fn test_validate_value_blocks_cli_injection_path_traversal_and_unsafe_schemes() {
        // CLI flag injection on switch-backed settings
        let proxy = sample_entry(
            "network.proxy.global_socks5_endpoint",
            SettingValue::Text(String::new()),
            ValueConstraint::Unconstrained,
            Some("proxy-server"),
        );
        assert!(proxy.validate_value(&SettingValue::Text(String::new())));
        assert!(proxy.validate_value(&SettingValue::Text("socks5h://10.64.0.1:1080".into())));
        assert!(!proxy.validate_value(&SettingValue::Text("socks5h://10.64.0.1:1080 --no-sandbox".into())));
        assert!(!proxy.validate_value(&SettingValue::Text("--no-sandbox".into())));
        assert!(!proxy.validate_value(&SettingValue::Text("javascript:alert(1)".into())));
        assert!(!proxy.validate_value(&SettingValue::Text("file:///etc/passwd".into())));
        assert!(!proxy.validate_value(&SettingValue::Text("http://127.0.0.1:8080".into())));

        // Space-bearing descriptive switch still blocks CLI option injection & control chars
        let ua = sample_entry(
            "privacy.user_agent.uniform_frozen_string",
            SettingValue::Text("Mozilla/5.0 (Windows NT 10.0)".into()),
            ValueConstraint::Unconstrained,
            Some("user-agent"),
        );
        assert!(ua.validate_value(&SettingValue::Text("Mozilla/5.0 (Windows NT 10.0)".into())));
        assert!(!ua.validate_value(&SettingValue::Text("Mozilla/5.0 --no-sandbox".into())));
        assert!(!ua.validate_value(&SettingValue::Text("Mozilla/5.0 -disable-gpu".into())));
        assert!(!ua.validate_value(&SettingValue::Text("Mozilla/5.0\n--no-sandbox".into())));
        assert!(!ua.validate_value(&SettingValue::Text("Mozilla/5.0\0evil".into())));

        // Path traversal on path/dir/file/cursor/theme/vault keys
        for key in [
            "vault.storage.file_path",
            "ui.theme.hot_reload_toml_path",
            "ui.cursor.active_pack_path",
            "ui.cursor_role.default_arrow.asset_path",
            "custom.cache_dir",
        ] {
            let entry = sample_entry(
                key,
                SettingValue::Text("~/.config/singularity/safe.toml".into()),
                ValueConstraint::Unconstrained,
                None,
            );
            assert!(entry.validate_value(&SettingValue::Text("~/.config/singularity/safe.toml".into())));
            assert!(!entry.validate_value(&SettingValue::Text("../../etc/passwd".into())));
            assert!(!entry.validate_value(&SettingValue::Text("~/.config/singularity/../../etc/shadow".into())));
            assert!(!entry.validate_value(&SettingValue::Text("builtin://cursors/%2e%2e/secret".into())));
            assert!(!entry.validate_value(&SettingValue::Text("\\\\attacker\\share\\theme.toml".into())));
        }

        // Endpoint / URL / DNS scheme validation
        let dns = sample_entry(
            "network.dns.primary_doq_endpoint",
            SettingValue::Text("quic://adblock.dns.mullvad.net:853".into()),
            ValueConstraint::Unconstrained,
            Some("doh-server-uri"),
        );
        assert!(dns.validate_value(&SettingValue::Text("quic://adblock.dns.mullvad.net:853".into())));
        assert!(dns.validate_value(&SettingValue::Text("https://base.dns.mullvad.net/dns-query".into())));
        assert!(dns.validate_value(&SettingValue::Text("tls://dns.quad9.net:853".into())));
        assert!(!dns.validate_value(&SettingValue::Text("http://insecure.dns.example/dns-query".into())));
        assert!(!dns.validate_value(&SettingValue::Text("javascript:alert(1)".into())));
        assert!(!dns.validate_value(&SettingValue::Text("https://api.mullvad.net@evil.example/dns".into())));
        assert!(!dns.validate_value(&SettingValue::Text("https://base.dns.mullvad.net/dns-query --no-sandbox".into())));
        assert!(!dns.validate_value(&SettingValue::Text(String::new())));
    }

    #[test]
    fn test_to_chromium_cli_arg_fixes() {
        // Bool(false) must return None; Bool(true) emits --<switch>
        let mut jitless = sample_entry(
            "security.v8.jitless_strict_mode",
            SettingValue::Bool(false),
            ValueConstraint::Unconstrained,
            Some("jitless"),
        );
        assert_eq!(jitless.to_chromium_cli_arg(), None);
        jitless.current_value = SettingValue::Bool(true);
        assert_eq!(jitless.to_chromium_cli_arg(), Some("--jitless".into()));

        // Empty or whitespace-only Text must return None
        let mut proxy = sample_entry(
            "network.proxy.global_socks5_endpoint",
            SettingValue::Text(String::new()),
            ValueConstraint::Unconstrained,
            Some("proxy-server"),
        );
        assert_eq!(proxy.to_chromium_cli_arg(), None);
        proxy.current_value = SettingValue::Text("   ".into());
        assert_eq!(proxy.to_chromium_cli_arg(), None);
        proxy.current_value = SettingValue::Text("socks5h://10.64.0.1:1080".into());
        assert_eq!(
            proxy.to_chromium_cli_arg(),
            Some("--proxy-server=socks5h://10.64.0.1:1080".into())
        );

        // Injection or control chars directly mutated on entry must be refused
        proxy.current_value = SettingValue::Text("socks5h://10.64.0.1:1080 --no-sandbox".into());
        assert_eq!(proxy.to_chromium_cli_arg(), None);
        proxy.current_value = SettingValue::Text("socks5h://10.64.0.1:1080\n--no-sandbox".into());
        assert_eq!(proxy.to_chromium_cli_arg(), None);
        proxy.current_value = SettingValue::Text("socks5h://10.64.0.1:1080\0".into());
        assert_eq!(proxy.to_chromium_cli_arg(), None);

        // MiB-to-bytes conversion for disk-cache-size and *_mib keys
        let mut cache = sample_entry(
            "network.cache.ram_disk_max_size_mb",
            SettingValue::Int(1024),
            ValueConstraint::IntRange { min: 64, max: 16384 },
            Some("disk-cache-size"),
        );
        assert_eq!(
            cache.to_chromium_cli_arg(),
            Some("--disk-cache-size=1073741824".into())
        );
        cache.current_value = SettingValue::Int(i64::MAX);
        assert_eq!(
            cache.to_chromium_cli_arg(),
            Some(format!("--disk-cache-size={}", i64::MAX))
        );
        cache.current_value = SettingValue::Int(-1);
        assert_eq!(cache.to_chromium_cli_arg(), None);

        let custom_mib = sample_entry(
            "network.cache.custom_limit_mib",
            SettingValue::Int(64),
            ValueConstraint::IntRange { min: 1, max: 4096 },
            Some("custom-cache-bytes"),
        );
        assert_eq!(
            custom_mib.to_chromium_cli_arg(),
            Some("--custom-cache-bytes=67108864".into())
        );
    }
}
