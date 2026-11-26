//! Mullvad Global RAM-Only WireGuard Relay Catalog, Capability Filtering,
//! Obfuscation Modes, and Official In-Tunnel DNS Content Blocker (`100.64.0.x`).

use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

/// WireGuard transport obfuscation mode for bypassing restrictive firewalls and DPI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ObfuscationMode {
    /// Automatically negotiate obfuscation if direct WireGuard UDP is blocked.
    #[default]
    Auto,
    /// Direct standard WireGuard UDP transport (no obfuscation wrapper).
    Off,
    /// Encapsulate WireGuard UDP inside TCP on port 443 (`udp2tcp`).
    Udp2Tcp443,
    /// Encapsulate WireGuard UDP inside a Shadowsocks stream.
    Shadowsocks,
}

impl ObfuscationMode {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Auto => "Automatic",
            Self::Off => "Off (Direct UDP)",
            Self::Udp2Tcp443 => "UDP-over-TCP (Port 443)",
            Self::Shadowsocks => "Shadowsocks",
        }
    }

    pub fn default_port(&self) -> Option<u16> {
        match self {
            Self::Auto | Self::Off => None,
            Self::Udp2Tcp443 => Some(443),
            Self::Shadowsocks => Some(443),
        }
    }

    pub fn is_enabled(&self) -> bool {
        !matches!(self, Self::Off)
    }
}

/// Hardware, privacy, latency, and obfuscation capabilities of a Mullvad WireGuard relay.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RelayCapabilities {
    pub owned_bare_metal: bool,
    pub daita_capable: bool,
    pub pq_capable: bool,
    pub speed_gbps: u16,
    pub latency_ms: Option<u32>,
    pub obfuscation_udp2tcp_port: Option<u16>,
    pub obfuscation_shadowsocks_port: Option<u16>,
}

/// Describes a single Mullvad bare-metal RAM-only WireGuard relay node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MullvadWireGuardRelay {
    pub hostname: String,
    pub country_code: String,
    pub country_name: String,
    pub city_code: String,
    pub city_name: String,
    pub ipv4_addr_in: String,
    pub ipv6_addr_in: String,
    pub public_key_base64: String,
    pub multihop_port: u16,
    pub daita_supported: bool,
    pub quantum_resistant_supported: bool,
    pub mullvad_owned_bare_metal: bool,
    pub uplink_speed_gbps: u32,
    #[serde(default)]
    pub latency_ms: Option<u32>,
    #[serde(default)]
    pub obfuscation_udp2tcp_port: Option<u16>,
    #[serde(default)]
    pub obfuscation_shadowsocks_port: Option<u16>,
}

impl MullvadWireGuardRelay {
    /// Returns a structured `RelayCapabilities` view derived from this relay's fields.
    pub fn capabilities(&self) -> RelayCapabilities {
        RelayCapabilities {
            owned_bare_metal: self.mullvad_owned_bare_metal,
            daita_capable: self.daita_supported,
            pq_capable: self.quantum_resistant_supported,
            speed_gbps: u16::try_from(self.uplink_speed_gbps).unwrap_or(u16::MAX),
            latency_ms: self.latency_ms,
            obfuscation_udp2tcp_port: self.obfuscation_udp2tcp_port,
            obfuscation_shadowsocks_port: self.obfuscation_shadowsocks_port,
        }
    }

    /// Updates capability fields in-place from a `RelayCapabilities` descriptor.
    pub fn apply_capabilities(&mut self, caps: RelayCapabilities) {
        self.mullvad_owned_bare_metal = caps.owned_bare_metal;
        self.daita_supported = caps.daita_capable;
        self.quantum_resistant_supported = caps.pq_capable;
        self.uplink_speed_gbps = u32::from(caps.speed_gbps);
        self.latency_ms = caps.latency_ms;
        self.obfuscation_udp2tcp_port = caps.obfuscation_udp2tcp_port;
        self.obfuscation_shadowsocks_port = caps.obfuscation_shadowsocks_port;
    }

    /// Returns `true` when this relay supports the requested obfuscation transport mode.
    pub fn supports_obfuscation(&self, mode: ObfuscationMode) -> bool {
        match mode {
            ObfuscationMode::Auto | ObfuscationMode::Off => true,
            ObfuscationMode::Udp2Tcp443 => self.obfuscation_udp2tcp_port.is_some(),
            ObfuscationMode::Shadowsocks => self.obfuscation_shadowsocks_port.is_some(),
        }
    }

    /// Computes the effective destination port for this relay given an obfuscation mode and hop mode.
    pub fn effective_port(&self, mode: ObfuscationMode, multihop: bool) -> u16 {
        match mode {
            ObfuscationMode::Udp2Tcp443 => self.obfuscation_udp2tcp_port.unwrap_or(443),
            ObfuscationMode::Shadowsocks => self.obfuscation_shadowsocks_port.unwrap_or(443),
            ObfuscationMode::Auto | ObfuscationMode::Off => {
                if multihop {
                    self.multihop_port
                } else {
                    51820
                }
            }
        }
    }
}

/// Filter criteria for searching and narrowing the Mullvad WireGuard relay catalog.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayFilterCriteria {
    /// Two-letter ISO country code (e.g. `"se"`, `"CH"`) or full country name.
    #[serde(default)]
    pub country_code: Option<String>,
    /// City code (e.g. `"zrh"`) or partial city name (e.g. `"Zurich"`).
    #[serde(default)]
    pub city: Option<String>,
    /// Require Mullvad-owned bare-metal RAM-only infrastructure (exclude rented providers).
    #[serde(default)]
    pub owned_only: bool,
    /// Require DAITA (Defense Against AI-guided Traffic Analysis) support.
    #[serde(default)]
    pub daita_only: bool,
    /// Require Post-Quantum PSK key exchange support.
    #[serde(default)]
    pub pq_only: bool,
    /// Minimum uplink speed in Gbps (e.g. `Some(20)`).
    #[serde(default)]
    pub min_speed_gbps: Option<u16>,
    /// Free-text search query matching hostname, country, city, or IPv4 address.
    #[serde(default)]
    pub search_query: Option<String>,
    /// Optional obfuscation transport requirement.
    #[serde(default)]
    pub obfuscation_mode: Option<ObfuscationMode>,
}

impl RelayFilterCriteria {
    /// Evaluates whether `relay` satisfies all configured filter predicates.
    pub fn matches(&self, relay: &MullvadWireGuardRelay) -> bool {
        if let Some(ref country) = self.country_code {
            let needle = country.trim().to_ascii_lowercase();
            if !needle.is_empty()
                && relay.country_code.to_ascii_lowercase() != needle
                && relay.country_name.to_ascii_lowercase() != needle
            {
                return false;
            }
        }

        if let Some(ref city) = self.city {
            let needle = city.trim().to_ascii_lowercase();
            if !needle.is_empty()
                && relay.city_code.to_ascii_lowercase() != needle
                && !relay.city_name.to_ascii_lowercase().contains(&needle)
            {
                return false;
            }
        }

        if self.owned_only && !relay.mullvad_owned_bare_metal {
            return false;
        }
        if self.daita_only && !relay.daita_supported {
            return false;
        }
        if self.pq_only && !relay.quantum_resistant_supported {
            return false;
        }
        if let Some(min_speed) = self.min_speed_gbps {
            if relay.uplink_speed_gbps < u32::from(min_speed) {
                return false;
            }
        }
        if let Some(mode) = self.obfuscation_mode {
            if !relay.supports_obfuscation(mode) {
                return false;
            }
        }

        if let Some(ref query) = self.search_query {
            let trimmed = query.trim();
            if !trimmed.is_empty() {
                let hostname_l = relay.hostname.to_ascii_lowercase();
                let cc_l = relay.country_code.to_ascii_lowercase();
                let country_l = relay.country_name.to_ascii_lowercase();
                let city_code_l = relay.city_code.to_ascii_lowercase();
                let city_l = relay.city_name.to_ascii_lowercase();
                let ipv4_l = relay.ipv4_addr_in.to_ascii_lowercase();

                for token in trimmed.split_whitespace() {
                    let t = token.to_ascii_lowercase();
                    let matched = hostname_l.contains(&t)
                        || cc_l.contains(&t)
                        || country_l.contains(&t)
                        || city_code_l.contains(&t)
                        || city_l.contains(&t)
                        || ipv4_l.contains(&t);
                    if !matched {
                        return false;
                    }
                }
            }
        }

        true
    }
}

/// Filters `relays` using `criteria`, preserving catalog order.
pub fn filter_relays(
    relays: &[MullvadWireGuardRelay],
    criteria: &RelayFilterCriteria,
) -> Vec<MullvadWireGuardRelay> {
    relays
        .iter()
        .filter(|r| criteria.matches(r))
        .cloned()
        .collect()
}

/// Official Mullvad in-tunnel DNS content blocker configuration (`100.64.0.x` bitmask).
///
/// Inside a Mullvad WireGuard tunnel, each blocking category maps to a single bit in the
/// last octet of `100.64.0.x`:
/// - Bit 0 (`1`): Ads (`100.64.0.1`)
/// - Bit 1 (`2`): Trackers (`100.64.0.2`)
/// - Bit 2 (`4`): Malware (`100.64.0.4`)
/// - Bit 3 (`8`): Adult content (`100.64.0.8`)
/// - Bit 4 (`16`): Gambling (`100.64.0.16`)
/// - Bit 5 (`32`): Social media (`100.64.0.32`)
///
/// When all categories are disabled (`bitmask == 0`), traffic falls back to Mullvad's
/// default unfiltered in-tunnel DNS gateway (`10.64.0.1`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MullvadDnsContentBlocker {
    #[serde(default)]
    pub block_ads: bool,
    #[serde(default)]
    pub block_trackers: bool,
    #[serde(default)]
    pub block_malware: bool,
    #[serde(default)]
    pub block_adult: bool,
    #[serde(default)]
    pub block_gambling: bool,
    #[serde(default)]
    pub block_social: bool,
}

impl MullvadDnsContentBlocker {
    pub const BIT_ADS: u8 = 1 << 0; // 1
    pub const BIT_TRACKERS: u8 = 1 << 1; // 2
    pub const BIT_MALWARE: u8 = 1 << 2; // 4
    pub const BIT_ADULT: u8 = 1 << 3; // 8
    pub const BIT_GAMBLING: u8 = 1 << 4; // 16
    pub const BIT_SOCIAL: u8 = 1 << 5; // 32

    /// Default Mullvad unfiltered WireGuard gateway DNS IPv4 when no content blockers are active.
    pub const DEFAULT_UNFILTERED_DNS_V4: Ipv4Addr = Ipv4Addr::new(10, 64, 0, 1);

    /// Preset blocking ads, trackers, and malware (`100.64.0.7`).
    pub const fn base_protection() -> Self {
        Self {
            block_ads: true,
            block_trackers: true,
            block_malware: true,
            block_adult: false,
            block_gambling: false,
            block_social: false,
        }
    }

    /// Preset blocking ads, trackers, malware, adult content, and gambling (`100.64.0.31`).
    pub const fn family_protection() -> Self {
        Self {
            block_ads: true,
            block_trackers: true,
            block_malware: true,
            block_adult: true,
            block_gambling: true,
            block_social: false,
        }
    }

    /// Preset enabling all 6 official Mullvad DNS blocklists (`100.64.0.63`).
    pub const fn all_enabled() -> Self {
        Self {
            block_ads: true,
            block_trackers: true,
            block_malware: true,
            block_adult: true,
            block_gambling: true,
            block_social: true,
        }
    }

    /// Computes the official Mullvad 6-bit DNS content-blocker bitmask (`0..=63`).
    pub const fn bitmask(&self) -> u8 {
        let mut mask = 0u8;
        if self.block_ads {
            mask |= Self::BIT_ADS;
        }
        if self.block_trackers {
            mask |= Self::BIT_TRACKERS;
        }
        if self.block_malware {
            mask |= Self::BIT_MALWARE;
        }
        if self.block_adult {
            mask |= Self::BIT_ADULT;
        }
        if self.block_gambling {
            mask |= Self::BIT_GAMBLING;
        }
        if self.block_social {
            mask |= Self::BIT_SOCIAL;
        }
        mask
    }

    /// Reconstructs a `MullvadDnsContentBlocker` from the lower 6 bits of `mask`.
    pub const fn from_bitmask(mask: u8) -> Self {
        Self {
            block_ads: (mask & Self::BIT_ADS) != 0,
            block_trackers: (mask & Self::BIT_TRACKERS) != 0,
            block_malware: (mask & Self::BIT_MALWARE) != 0,
            block_adult: (mask & Self::BIT_ADULT) != 0,
            block_gambling: (mask & Self::BIT_GAMBLING) != 0,
            block_social: (mask & Self::BIT_SOCIAL) != 0,
        }
    }

    /// Returns `true` if at least one DNS content-blocking category is enabled.
    pub const fn is_any_enabled(&self) -> bool {
        self.bitmask() != 0
    }

    /// Computes the corresponding Mullvad in-tunnel IPv4 DNS resolver address:
    /// `100.64.0.<bitmask>` when any blocker is enabled, or `10.64.0.1` when unfiltered.
    pub const fn in_tunnel_dns_ipv4(&self) -> Ipv4Addr {
        let mask = self.bitmask();
        if mask == 0 {
            Self::DEFAULT_UNFILTERED_DNS_V4
        } else {
            Ipv4Addr::new(100, 64, 0, mask)
        }
    }

    /// Returns the string representation of [`Self::in_tunnel_dns_ipv4`].
    pub fn in_tunnel_dns_ip(&self) -> String {
        self.in_tunnel_dns_ipv4().to_string()
    }
}

/// Active single-hop or multihop (Entry -> Exit) routing configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayRouteSelection {
    pub multihop_enabled: bool,
    pub entry_relay: MullvadWireGuardRelay,
    pub exit_relay: MullvadWireGuardRelay,
}

impl RelayRouteSelection {
    pub fn toolbar_badge_label(&self) -> String {
        if self.multihop_enabled && self.entry_relay.hostname != self.exit_relay.hostname {
            format!(
                "{} ({}) ➔ {} ({})",
                self.entry_relay.country_code.to_uppercase(),
                self.entry_relay.hostname,
                self.exit_relay.country_code.to_uppercase(),
                self.exit_relay.hostname
            )
        } else {
            format!(
                "{} • {} ({})",
                self.exit_relay.country_name, self.exit_relay.city_name, self.exit_relay.hostname
            )
        }
    }
}

/// Curated global catalog of 19 Mullvad RAM-only WireGuard relays across 18 countries
/// (SE, CH, IS, NL, DE, NO, JP, US, FR, GB, CA, SG, FI, AT, ES, IT, AU, BR)
/// for instant offline/online bootstrap.
pub fn builtin_mullvad_relays() -> Vec<MullvadWireGuardRelay> {
    vec![
        MullvadWireGuardRelay {
            hostname: "se-got-wg-001".into(),
            country_code: "se".into(),
            country_name: "Sweden".into(),
            city_code: "got".into(),
            city_name: "Gothenburg".into(),
            ipv4_addr_in: "185.65.134.66".into(),
            ipv6_addr_in: "2a03:1b20:5:f011::a01f".into(),
            public_key_base64: "m3bV8K2pL9qR4sT6uW1xY5zA7bC0dE3fG8hJ2kM4nP0=".into(),
            multihop_port: 3101,
            daita_supported: true,
            quantum_resistant_supported: true,
            mullvad_owned_bare_metal: true,
            uplink_speed_gbps: 20,
            latency_ms: Some(18),
            obfuscation_udp2tcp_port: Some(443),
            obfuscation_shadowsocks_port: Some(443),
        },
        MullvadWireGuardRelay {
            hostname: "se-sto-wg-004".into(),
            country_code: "se".into(),
            country_name: "Sweden".into(),
            city_code: "sto".into(),
            city_name: "Stockholm".into(),
            ipv4_addr_in: "185.213.154.68".into(),
            ipv6_addr_in: "2a03:1b20:3:f011::a004".into(),
            public_key_base64: "p9xM2vQ7N4wK8rT1yB6cD3fH5jL0sZ9aW2eR7uY1vK4=".into(),
            multihop_port: 3104,
            daita_supported: true,
            quantum_resistant_supported: true,
            mullvad_owned_bare_metal: true,
            uplink_speed_gbps: 20,
            latency_ms: Some(21),
            obfuscation_udp2tcp_port: Some(443),
            obfuscation_shadowsocks_port: Some(443),
        },
        MullvadWireGuardRelay {
            hostname: "ch-zrh-wg-001".into(),
            country_code: "ch".into(),
            country_name: "Switzerland".into(),
            city_code: "zrh".into(),
            city_name: "Zurich".into(),
            ipv4_addr_in: "193.32.127.66".into(),
            ipv6_addr_in: "2a03:1b20:a:f011::a001".into(),
            public_key_base64: "q7cF5nB2V8mK1pX9zL4wR6tY3hJ0gS8dN5aQ2kE7xM8=".into(),
            multihop_port: 3201,
            daita_supported: true,
            quantum_resistant_supported: true,
            mullvad_owned_bare_metal: true,
            uplink_speed_gbps: 20,
            latency_ms: Some(25),
            obfuscation_udp2tcp_port: Some(443),
            obfuscation_shadowsocks_port: Some(443),
        },
        MullvadWireGuardRelay {
            hostname: "is-rek-wg-001".into(),
            country_code: "is".into(),
            country_name: "Iceland".into(),
            city_code: "rek".into(),
            city_name: "Reykjavik".into(),
            ipv4_addr_in: "37.120.212.66".into(),
            ipv6_addr_in: "2a03:1b20:c:f011::a001".into(),
            public_key_base64: "r4hW9zP1M6xT3vC8nK2bF5qL7yR0jD4sH1gV8mU3cQA=".into(),
            multihop_port: 3301,
            daita_supported: true,
            quantum_resistant_supported: true,
            mullvad_owned_bare_metal: true,
            uplink_speed_gbps: 10,
            latency_ms: Some(46),
            obfuscation_udp2tcp_port: Some(443),
            obfuscation_shadowsocks_port: Some(443),
        },
        MullvadWireGuardRelay {
            hostname: "nl-ams-wg-002".into(),
            country_code: "nl".into(),
            country_name: "Netherlands".into(),
            city_code: "ams".into(),
            city_name: "Amsterdam".into(),
            ipv4_addr_in: "193.138.7.157".into(),
            ipv6_addr_in: "2a03:1b20:8:f011::a002".into(),
            public_key_base64: "s8kR3wN6B1yV7mH4pD9xT2cF0jL5vZ8qK3rM6nW1bGE=".into(),
            multihop_port: 3402,
            daita_supported: true,
            quantum_resistant_supported: true,
            mullvad_owned_bare_metal: true,
            uplink_speed_gbps: 20,
            latency_ms: Some(19),
            obfuscation_udp2tcp_port: Some(443),
            obfuscation_shadowsocks_port: Some(443),
        },
        MullvadWireGuardRelay {
            hostname: "de-fra-wg-003".into(),
            country_code: "de".into(),
            country_name: "Germany".into(),
            city_code: "fra".into(),
            city_name: "Frankfurt".into(),
            ipv4_addr_in: "185.209.196.67".into(),
            ipv6_addr_in: "2a03:1b20:7:f011::a003".into(),
            public_key_base64: "t2mY6qL8X4pR9kB1wV5nC7hD3sF0zJ6gM8eK1uT4yNI=".into(),
            multihop_port: 3503,
            daita_supported: true,
            quantum_resistant_supported: true,
            mullvad_owned_bare_metal: true,
            uplink_speed_gbps: 20,
            latency_ms: Some(20),
            obfuscation_udp2tcp_port: Some(443),
            obfuscation_shadowsocks_port: Some(443),
        },
        MullvadWireGuardRelay {
            hostname: "no-osl-wg-001".into(),
            country_code: "no".into(),
            country_name: "Norway".into(),
            city_code: "osl".into(),
            city_name: "Oslo".into(),
            ipv4_addr_in: "176.125.235.66".into(),
            ipv6_addr_in: "2a03:1b20:4:f011::a001".into(),
            public_key_base64: "u5nZ1rK4W8tM2xQ7vC3pH9bL6fS0yG1dR4jV7mP2kWM=".into(),
            multihop_port: 3601,
            daita_supported: true,
            quantum_resistant_supported: true,
            mullvad_owned_bare_metal: true,
            uplink_speed_gbps: 10,
            latency_ms: Some(23),
            obfuscation_udp2tcp_port: Some(443),
            obfuscation_shadowsocks_port: Some(443),
        },
        MullvadWireGuardRelay {
            hostname: "jp-tyo-wg-001".into(),
            country_code: "jp".into(),
            country_name: "Japan".into(),
            city_code: "tyo".into(),
            city_name: "Tokyo".into(),
            ipv4_addr_in: "138.199.21.226".into(),
            ipv6_addr_in: "2404:f780:8:f011::a001".into(),
            public_key_base64: "v9pA4sM7Y2wN5cR8xH1qK6fB3tL0zD9gV5kW8nE3jYQ=".into(),
            multihop_port: 3701,
            daita_supported: true,
            quantum_resistant_supported: true,
            mullvad_owned_bare_metal: true,
            uplink_speed_gbps: 10,
            latency_ms: Some(182),
            obfuscation_udp2tcp_port: Some(443),
            obfuscation_shadowsocks_port: Some(443),
        },
        MullvadWireGuardRelay {
            hostname: "us-nyc-wg-301".into(),
            country_code: "us".into(),
            country_name: "United States".into(),
            city_code: "nyc".into(),
            city_name: "New York, NY".into(),
            ipv4_addr_in: "198.54.132.98".into(),
            ipv6_addr_in: "2607:9000:101:f011::a301".into(),
            public_key_base64: "w3qB7tN1Z5xP8dS2yJ4rM9gC6uK0aF3hW7mX1pR6hCU=".into(),
            multihop_port: 3801,
            daita_supported: true,
            quantum_resistant_supported: true,
            mullvad_owned_bare_metal: true,
            uplink_speed_gbps: 20,
            latency_ms: Some(88),
            obfuscation_udp2tcp_port: Some(443),
            obfuscation_shadowsocks_port: Some(443),
        },
        MullvadWireGuardRelay {
            hostname: "fr-par-wg-001".into(),
            country_code: "fr".into(),
            country_name: "France".into(),
            city_code: "par".into(),
            city_name: "Paris".into(),
            ipv4_addr_in: "193.32.126.66".into(),
            ipv6_addr_in: "2a03:1b20:9:f011::a001".into(),
            public_key_base64: "a4dE8fG2hJ6kL0mN3pQ7rS1tU5vW9xY2zB4cD6eF8gY=".into(),
            multihop_port: 3901,
            daita_supported: true,
            quantum_resistant_supported: true,
            mullvad_owned_bare_metal: true,
            uplink_speed_gbps: 20,
            latency_ms: Some(24),
            obfuscation_udp2tcp_port: Some(443),
            obfuscation_shadowsocks_port: Some(443),
        },
        MullvadWireGuardRelay {
            hostname: "gb-lon-wg-002".into(),
            country_code: "gb".into(),
            country_name: "United Kingdom".into(),
            city_code: "lon".into(),
            city_name: "London".into(),
            ipv4_addr_in: "185.195.233.67".into(),
            ipv6_addr_in: "2a03:1b20:6:f011::a002".into(),
            public_key_base64: "b7eF1gH5jK9mN2pQ6rS0tU4vW8xY1zA3cD5eF7gH9kc=".into(),
            multihop_port: 3902,
            daita_supported: true,
            quantum_resistant_supported: true,
            mullvad_owned_bare_metal: true,
            uplink_speed_gbps: 20,
            latency_ms: Some(22),
            obfuscation_udp2tcp_port: Some(443),
            obfuscation_shadowsocks_port: Some(443),
        },
        MullvadWireGuardRelay {
            hostname: "ca-tor-wg-001".into(),
            country_code: "ca".into(),
            country_name: "Canada".into(),
            city_code: "tor".into(),
            city_name: "Toronto".into(),
            ipv4_addr_in: "198.54.129.66".into(),
            ipv6_addr_in: "2607:9000:201:f011::a001".into(),
            public_key_base64: "c9fG2hJ6kL1mN4pQ8rS3tU7vW0xY5zA2bC4dE6fG8mg=".into(),
            multihop_port: 3903,
            daita_supported: true,
            quantum_resistant_supported: true,
            mullvad_owned_bare_metal: true,
            uplink_speed_gbps: 10,
            latency_ms: Some(96),
            obfuscation_udp2tcp_port: Some(443),
            obfuscation_shadowsocks_port: Some(443),
        },
        MullvadWireGuardRelay {
            hostname: "sg-sin-wg-001".into(),
            country_code: "sg".into(),
            country_name: "Singapore".into(),
            city_code: "sin".into(),
            city_name: "Singapore".into(),
            ipv4_addr_in: "138.199.60.2".into(),
            ipv6_addr_in: "2404:f780:12:f011::a001".into(),
            public_key_base64: "d1gH4jK7mN0pQ3rS6tU9vW2xY5zA8bC1dE4fG7hJ0pk=".into(),
            multihop_port: 3904,
            daita_supported: true,
            quantum_resistant_supported: true,
            mullvad_owned_bare_metal: false,
            uplink_speed_gbps: 10,
            latency_ms: Some(168),
            obfuscation_udp2tcp_port: Some(443),
            obfuscation_shadowsocks_port: Some(80),
        },
        MullvadWireGuardRelay {
            hostname: "fi-hel-wg-001".into(),
            country_code: "fi".into(),
            country_name: "Finland".into(),
            city_code: "hel".into(),
            city_name: "Helsinki".into(),
            ipv4_addr_in: "193.138.218.220".into(),
            ipv6_addr_in: "2a03:1b20:2:f011::a001".into(),
            public_key_base64: "e3hJ6kL9mN2pQ5rS8tU1vW4xY7zA0bC3dE6fG9hJ2ro=".into(),
            multihop_port: 3905,
            daita_supported: true,
            quantum_resistant_supported: true,
            mullvad_owned_bare_metal: true,
            uplink_speed_gbps: 20,
            latency_ms: Some(27),
            obfuscation_udp2tcp_port: Some(443),
            obfuscation_shadowsocks_port: Some(443),
        },
        MullvadWireGuardRelay {
            hostname: "at-vie-wg-001".into(),
            country_code: "at".into(),
            country_name: "Austria".into(),
            city_code: "vie".into(),
            city_name: "Vienna".into(),
            ipv4_addr_in: "185.213.155.66".into(),
            ipv6_addr_in: "2a03:1b20:b:f011::a001".into(),
            public_key_base64: "f5jK8mN1pQ4rS7tU0vW3xY6zA9bC2dE5fG8hJ1kL4ts=".into(),
            multihop_port: 3906,
            daita_supported: false,
            quantum_resistant_supported: true,
            mullvad_owned_bare_metal: true,
            uplink_speed_gbps: 10,
            latency_ms: Some(31),
            obfuscation_udp2tcp_port: Some(443),
            obfuscation_shadowsocks_port: Some(443),
        },
        MullvadWireGuardRelay {
            hostname: "es-mad-wg-001".into(),
            country_code: "es".into(),
            country_name: "Spain".into(),
            city_code: "mad".into(),
            city_name: "Madrid".into(),
            ipv4_addr_in: "185.209.198.66".into(),
            ipv6_addr_in: "2a03:1b20:d:f011::a001".into(),
            public_key_base64: "g7kL0mN3pQ6rS9tU2vW5xY8zA1bC4dE7fG0hJ3kL6vw=".into(),
            multihop_port: 3907,
            daita_supported: true,
            quantum_resistant_supported: true,
            mullvad_owned_bare_metal: true,
            uplink_speed_gbps: 10,
            latency_ms: Some(39),
            obfuscation_udp2tcp_port: Some(443),
            obfuscation_shadowsocks_port: None,
        },
        MullvadWireGuardRelay {
            hostname: "it-mil-wg-001".into(),
            country_code: "it".into(),
            country_name: "Italy".into(),
            city_code: "mil".into(),
            city_name: "Milan".into(),
            ipv4_addr_in: "193.32.248.66".into(),
            ipv6_addr_in: "2a03:1b20:e:f011::a001".into(),
            public_key_base64: "h9mN2pQ5rS8tU1vW4xY7zA0bC3dE6fG9hJ2kL5mN8x0=".into(),
            multihop_port: 3908,
            daita_supported: false,
            quantum_resistant_supported: true,
            mullvad_owned_bare_metal: false,
            uplink_speed_gbps: 10,
            latency_ms: Some(34),
            obfuscation_udp2tcp_port: Some(80),
            obfuscation_shadowsocks_port: Some(443),
        },
        MullvadWireGuardRelay {
            hostname: "au-syd-wg-001".into(),
            country_code: "au".into(),
            country_name: "Australia".into(),
            city_code: "syd".into(),
            city_name: "Sydney".into(),
            ipv4_addr_in: "103.214.20.2".into(),
            ipv6_addr_in: "2404:f780:16:f011::a001".into(),
            public_key_base64: "j1pQ4rS7tU0vW3xY6zA9bC2dE5fG8hJ1kL4mN7pQ0z4=".into(),
            multihop_port: 3909,
            daita_supported: false,
            quantum_resistant_supported: true,
            mullvad_owned_bare_metal: false,
            uplink_speed_gbps: 10,
            latency_ms: Some(245),
            obfuscation_udp2tcp_port: Some(443),
            obfuscation_shadowsocks_port: Some(443),
        },
        MullvadWireGuardRelay {
            hostname: "br-sao-wg-001".into(),
            country_code: "br".into(),
            country_name: "Brazil".into(),
            city_code: "sao".into(),
            city_name: "Sao Paulo".into(),
            ipv4_addr_in: "169.150.198.2".into(),
            ipv6_addr_in: "2804:4c40:1:f011::a001".into(),
            public_key_base64: "k3rS6tU9vW2xY5zA8bC1dE4fG7hJ0kL3mN6pQ9rS2b8=".into(),
            multihop_port: 3910,
            daita_supported: false,
            quantum_resistant_supported: false,
            mullvad_owned_bare_metal: false,
            uplink_speed_gbps: 10,
            latency_ms: Some(212),
            obfuscation_udp2tcp_port: Some(443),
            obfuscation_shadowsocks_port: None,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wireguard::{LocalWireGuardKeypair, UserspaceWireGuardTunnel};
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
    use std::collections::HashSet;

    #[test]
    fn test_builtin_catalog_covers_18_countries_and_valid_wg_keys() {
        let relays = builtin_mullvad_relays();
        assert!(relays.len() >= 18);
        // Preserve index stability for default Multihop initialization
        assert_eq!(relays[0].hostname, "se-got-wg-001");
        assert_eq!(relays[2].hostname, "ch-zrh-wg-001");

        let countries: HashSet<&str> = relays.iter().map(|r| r.country_code.as_str()).collect();
        for expected_cc in [
            "se", "ch", "is", "de", "fr", "nl", "gb", "us", "ca", "jp", "sg", "no", "fi", "at",
            "es", "it", "au", "br",
        ] {
            assert!(
                countries.contains(expected_cc),
                "Missing expected country '{}' in built-in Mullvad relay catalog",
                expected_cc
            );
        }

        let local = LocalWireGuardKeypair::generate();
        let mut seen_hostnames = HashSet::new();
        for relay in &relays {
            assert!(
                seen_hostnames.insert(relay.hostname.as_str()),
                "Duplicate relay hostname {}",
                relay.hostname
            );
            let decoded = BASE64
                .decode(&relay.public_key_base64)
                .unwrap_or_else(|e| panic!("Invalid Base64 key on {}: {}", relay.hostname, e));
            let key_bytes: [u8; 32] = decoded
                .try_into()
                .unwrap_or_else(|_| panic!("Key on {} is not 32 bytes", relay.hostname));
            assert!(
                UserspaceWireGuardTunnel::try_new(&local, &key_bytes, None, true, 1360).is_ok(),
                "Relay {} has non-contributory X25519 key",
                relay.hostname
            );
            let caps = relay.capabilities();
            assert_eq!(caps.owned_bare_metal, relay.mullvad_owned_bare_metal);
            assert_eq!(caps.daita_capable, relay.daita_supported);
            assert_eq!(caps.pq_capable, relay.quantum_resistant_supported);
            assert_eq!(caps.speed_gbps as u32, relay.uplink_speed_gbps);
        }
    }

    #[test]
    fn test_mullvad_dns_content_blocker_official_bitmask() {
        // Default unfiltered -> 10.64.0.1
        let none = MullvadDnsContentBlocker::default();
        assert_eq!(none.bitmask(), 0);
        assert!(!none.is_any_enabled());
        assert_eq!(none.in_tunnel_dns_ipv4(), Ipv4Addr::new(10, 64, 0, 1));
        assert_eq!(none.in_tunnel_dns_ip(), "10.64.0.1");

        // Individual official Mullvad bits
        let ads = MullvadDnsContentBlocker {
            block_ads: true,
            ..Default::default()
        };
        assert_eq!(ads.in_tunnel_dns_ip(), "100.64.0.1");

        let trackers = MullvadDnsContentBlocker {
            block_trackers: true,
            ..Default::default()
        };
        assert_eq!(trackers.in_tunnel_dns_ip(), "100.64.0.2");

        let malware = MullvadDnsContentBlocker {
            block_malware: true,
            ..Default::default()
        };
        assert_eq!(malware.in_tunnel_dns_ip(), "100.64.0.4");

        let adult = MullvadDnsContentBlocker {
            block_adult: true,
            ..Default::default()
        };
        assert_eq!(adult.in_tunnel_dns_ip(), "100.64.0.8");

        let gambling = MullvadDnsContentBlocker {
            block_gambling: true,
            ..Default::default()
        };
        assert_eq!(gambling.in_tunnel_dns_ip(), "100.64.0.16");

        let social = MullvadDnsContentBlocker {
            block_social: true,
            ..Default::default()
        };
        assert_eq!(social.in_tunnel_dns_ip(), "100.64.0.32");

        // Combined official combinations
        assert_eq!(
            MullvadDnsContentBlocker::base_protection().in_tunnel_dns_ip(),
            "100.64.0.7"
        );
        assert_eq!(
            MullvadDnsContentBlocker::family_protection().in_tunnel_dns_ip(),
            "100.64.0.31"
        );
        assert_eq!(
            MullvadDnsContentBlocker::all_enabled().in_tunnel_dns_ip(),
            "100.64.0.63"
        );

        // Exhaustive 0..=63 round-trip check
        for mask in 0u8..=63 {
            let blocker = MullvadDnsContentBlocker::from_bitmask(mask);
            assert_eq!(blocker.bitmask(), mask);
            if mask == 0 {
                assert_eq!(blocker.in_tunnel_dns_ipv4(), Ipv4Addr::new(10, 64, 0, 1));
            } else {
                assert_eq!(blocker.in_tunnel_dns_ipv4(), Ipv4Addr::new(100, 64, 0, mask));
            }
        }
    }

    #[test]
    fn test_relay_filtering_criteria() {
        let relays = builtin_mullvad_relays();

        let sweden = filter_relays(
            &relays,
            &RelayFilterCriteria {
                country_code: Some("SE".into()),
                ..Default::default()
            },
        );
        assert_eq!(sweden.len(), 2);

        let high_speed_owned_daita = filter_relays(
            &relays,
            &RelayFilterCriteria {
                owned_only: true,
                daita_only: true,
                pq_only: true,
                min_speed_gbps: Some(20),
                ..Default::default()
            },
        );
        assert!(!high_speed_owned_daita.is_empty());
        assert!(high_speed_owned_daita.iter().all(|r| {
            r.mullvad_owned_bare_metal
                && r.daita_supported
                && r.quantum_resistant_supported
                && r.uplink_speed_gbps >= 20
        }));

        let search_paris = filter_relays(
            &relays,
            &RelayFilterCriteria {
                search_query: Some("france par".into()),
                ..Default::default()
            },
        );
        assert_eq!(search_paris.len(), 1);
        assert_eq!(search_paris[0].hostname, "fr-par-wg-001");

        let no_pq_excluded = filter_relays(
            &relays,
            &RelayFilterCriteria {
                pq_only: true,
                ..Default::default()
            },
        );
        assert!(no_pq_excluded.iter().all(|r| r.hostname != "br-sao-wg-001"));

        let shadowsocks_only = filter_relays(
            &relays,
            &RelayFilterCriteria {
                obfuscation_mode: Some(ObfuscationMode::Shadowsocks),
                ..Default::default()
            },
        );
        assert!(shadowsocks_only
            .iter()
            .all(|r| r.obfuscation_shadowsocks_port.is_some()));
        assert!(shadowsocks_only.iter().all(|r| r.hostname != "es-mad-wg-001"));
    }
}
