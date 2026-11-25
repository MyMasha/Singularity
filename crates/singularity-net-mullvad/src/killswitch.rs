//! Strict Atomic Socket-Layer Kill-Switch.
//!
//! Guarantees zero cleartext/ISP packet egress if the userspace WireGuard tunnel drops,
//! is rekeying without an active session, or encounters a handshake timeout.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum KillSwitchBlockReason {
    #[error("MULLVAD KILL-SWITCH ACTIVE: WireGuard tunnel is disconnected; packet dropped at Rust socket layer")]
    TunnelDisconnected,
    #[error("MULLVAD KILL-SWITCH ACTIVE: Emergency manual lockdown engaged; all sockets blocked")]
    EmergencyLockdown,
    #[error("MULLVAD KILL-SWITCH ACTIVE: Local LAN / RFC1918 / Loopback access blocked by strict policy")]
    LanAccessBlocked,
}

/// Thread-safe, zero-lock atomic socket gate consulted before any browser packet leaves the process.
pub struct AtomicSocketKillSwitch {
    strict_enabled: AtomicBool,
    tunnel_established: AtomicBool,
    emergency_lockdown: AtomicBool,
    block_lan_rfc1918: AtomicBool,
    dropped_packets_count: AtomicU64,
}

impl Default for AtomicSocketKillSwitch {
    fn default() -> Self {
        Self::new(true, true)
    }
}

impl AtomicSocketKillSwitch {
    pub fn new(strict_enabled: bool, block_lan_rfc1918: bool) -> Self {
        Self {
            strict_enabled: AtomicBool::new(strict_enabled),
            tunnel_established: AtomicBool::new(false),
            emergency_lockdown: AtomicBool::new(false),
            block_lan_rfc1918: AtomicBool::new(block_lan_rfc1918),
            dropped_packets_count: AtomicU64::new(0),
        }
    }

    pub fn set_strict_enabled(&self, enabled: bool) {
        self.strict_enabled.store(enabled, Ordering::SeqCst);
    }

    pub fn is_strict_enabled(&self) -> bool {
        self.strict_enabled.load(Ordering::SeqCst)
    }

    pub fn set_block_lan_rfc1918(&self, block: bool) {
        self.block_lan_rfc1918.store(block, Ordering::SeqCst);
    }

    pub fn is_block_lan_rfc1918(&self) -> bool {
        self.block_lan_rfc1918.load(Ordering::SeqCst)
    }

    pub fn set_tunnel_established(&self, established: bool) {
        self.tunnel_established.store(established, Ordering::SeqCst);
    }

    pub fn is_tunnel_established(&self) -> bool {
        self.tunnel_established.load(Ordering::SeqCst)
    }

    pub fn set_emergency_lockdown(&self, lockdown: bool) {
        self.emergency_lockdown.store(lockdown, Ordering::SeqCst);
    }

    pub fn is_emergency_lockdown(&self) -> bool {
        self.emergency_lockdown.load(Ordering::SeqCst)
    }

    pub fn dropped_packets(&self) -> u64 {
        self.dropped_packets_count.load(Ordering::Relaxed)
    }

    /// Evaluates whether an outbound socket packet to `destination_host` is permitted to leave.
    pub fn authorize_outbound_packet(&self, destination_host: &str) -> Result<(), KillSwitchBlockReason> {
        if self.emergency_lockdown.load(Ordering::SeqCst) {
            self.dropped_packets_count.fetch_add(1, Ordering::Relaxed);
            return Err(KillSwitchBlockReason::EmergencyLockdown);
        }

        if self.block_lan_rfc1918.load(Ordering::SeqCst) && is_rfc1918_or_local(destination_host) {
            self.dropped_packets_count.fetch_add(1, Ordering::Relaxed);
            return Err(KillSwitchBlockReason::LanAccessBlocked);
        }

        if self.strict_enabled.load(Ordering::SeqCst) && !self.tunnel_established.load(Ordering::SeqCst) {
            self.dropped_packets_count.fetch_add(1, Ordering::Relaxed);
            return Err(KillSwitchBlockReason::TunnelDisconnected);
        }

        Ok(())
    }

    /// Evaluates a resolved `IpAddr` directly (blocks loopback, RFC1918, CGNAT, link-local, ULA, IPv4-mapped IPv6).
    pub fn authorize_outbound_ip(&self, ip: IpAddr) -> Result<(), KillSwitchBlockReason> {
        if self.emergency_lockdown.load(Ordering::SeqCst) {
            self.dropped_packets_count.fetch_add(1, Ordering::Relaxed);
            return Err(KillSwitchBlockReason::EmergencyLockdown);
        }
        if is_non_global_ip(ip) {
            self.dropped_packets_count.fetch_add(1, Ordering::Relaxed);
            return Err(KillSwitchBlockReason::LanAccessBlocked);
        }
        if self.strict_enabled.load(Ordering::SeqCst) && !self.tunnel_established.load(Ordering::SeqCst) {
            self.dropped_packets_count.fetch_add(1, Ordering::Relaxed);
            return Err(KillSwitchBlockReason::TunnelDisconnected);
        }
        Ok(())
    }

    /// Resolves `destination_host` via DNS and verifies EVERY returned IP is globally routable,
    /// blocking SSRF and DNS-rebinding attacks against localhost/LAN/metadata endpoints.
    pub fn authorize_outbound_host_and_dns(
        &self,
        destination_host: &str,
        port: u16,
    ) -> Result<Vec<IpAddr>, KillSwitchBlockReason> {
        self.authorize_outbound_packet(destination_host)?;
        if is_rfc1918_or_local(destination_host) {
            self.dropped_packets_count.fetch_add(1, Ordering::Relaxed);
            return Err(KillSwitchBlockReason::LanAccessBlocked);
        }

        let clean = strip_host_brackets_and_dot(destination_host);
        if let Some(ip) = parse_any_ip_representation(clean) {
            if is_non_global_ip(ip) {
                self.dropped_packets_count.fetch_add(1, Ordering::Relaxed);
                return Err(KillSwitchBlockReason::LanAccessBlocked);
            }
            return Ok(vec![ip]);
        }

        let addrs = (clean, port)
            .to_socket_addrs()
            .map_err(|_| KillSwitchBlockReason::LanAccessBlocked)?;
        let mut resolved = Vec::new();
        for sa in addrs {
            let ip = sa.ip();
            if is_non_global_ip(ip) {
                self.dropped_packets_count.fetch_add(1, Ordering::Relaxed);
                return Err(KillSwitchBlockReason::LanAccessBlocked);
            }
            resolved.push(ip);
        }
        if resolved.is_empty() {
            self.dropped_packets_count.fetch_add(1, Ordering::Relaxed);
            return Err(KillSwitchBlockReason::LanAccessBlocked);
        }
        Ok(resolved)
    }
}

fn strip_host_brackets_and_dot(host: &str) -> &str {
    let h = host.trim();
    let h = h.strip_prefix('[').and_then(|s| s.strip_suffix(']')).unwrap_or(h);
    h.trim_end_matches('.')
}

/// Checks whether an IPv4 address is loopback, private (RFC1918), CGNAT (100.64/10),
/// link-local (169.254/16), unspecified (0.0.0.0/8), multicast, broadcast, or reserved.
pub fn is_non_global_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
        || ip.is_multicast()
        || a == 0                                  // 0.0.0.0/8 ("this network")
        || (a == 100 && (64..=127).contains(&b))   // 100.64.0.0/10 CGNAT
        || (a == 192 && b == 0 && c == 0)          // 192.0.0.0/24 IETF protocol assignments
        || (a == 198 && (b == 18 || b == 19))      // 198.18.0.0/15 benchmarking
        || a >= 240                                // 240.0.0.0/4 reserved
}

/// Checks whether an IPv6 address is loopback, unspecified, link-local, ULA (fc00::/7),
/// multicast, documentation, IPv4-mapped/compatible pointing to non-global IPv4,
/// or an IPv6 transition/tunneling prefix (NAT64 `64:ff9b::/96` & `64:ff9b:1::/48`,
/// 6to4 `2002::/16`, Teredo `2001::/32`).
pub fn is_non_global_ipv6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_non_global_ipv4(v4);
    }
    if let Some(v4) = ip.to_ipv4() {
        return is_non_global_ipv4(v4);
    }
    let segs = ip.segments();
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (segs[0] & 0xfe00) == 0xfc00 // fc00::/7 Unique Local Addresses
        || (segs[0] & 0xffc0) == 0xfe80 // fe80::/10 Link-Local
        || (segs[0] == 0x2001 && segs[1] == 0x0db8) // 2001:db8::/32 Documentation
        || (segs[0] == 0x0064
            && segs[1] == 0xff9b
            && segs[2] == 0
            && segs[3] == 0
            && segs[4] == 0
            && segs[5] == 0) // 64:ff9b::/96 NAT64 Well-Known Prefix (RFC 6052)
        || (segs[0] == 0x0064 && segs[1] == 0xff9b && segs[2] == 0x0001) // 64:ff9b:1::/48 NAT64 Local-Use Prefix (RFC 8215)
        || segs[0] == 0x2002 // 2002::/16 6to4 Transition Prefix (RFC 3056)
        || (segs[0] == 0x2001 && segs[1] == 0x0000) // 2001::/32 Teredo Tunneling Prefix (RFC 4380)
}

pub fn is_non_global_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_non_global_ipv4(v4),
        IpAddr::V6(v6) => is_non_global_ipv6(v6),
    }
}

/// Parses standard IPv4/IPv6 plus legacy/obfuscated IPv4 notations (decimal `2130706433`,
/// hex `0x7f000001`, octal `0177.0.0.1`, short-form `127.1`).
pub fn parse_any_ip_representation(host: &str) -> Option<IpAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(ip);
    }
    // Strip IPv6 zone ID (e.g. fe80::1%eth0)
    if let Some((addr_part, _zone)) = host.split_once('%') {
        if let Ok(v6) = addr_part.parse::<Ipv6Addr>() {
            return Some(IpAddr::V6(v6));
        }
    }
    // Parse single-integer or multi-part POSIX inet_aton IPv4 (decimal, 0x hex, 0 octal)
    let parts: Vec<&str> = host.split('.').collect();
    if (1..=4).contains(&parts.len()) && parts.iter().all(|p| !p.is_empty()) {
        let mut vals = Vec::with_capacity(parts.len());
        for p in &parts {
            let v = parse_posix_u32(p)?;
            vals.push(v);
        }
        let ipv4_u32 = match vals.as_slice() {
            [a] => *a,
            [a, b] if *a <= 0xff && *b <= 0x00ff_ffff => (*a << 24) | *b,
            [a, b, c] if *a <= 0xff && *b <= 0xff && *c <= 0xffff => (*a << 24) | (*b << 16) | *c,
            [a, b, c, d] if *a <= 0xff && *b <= 0xff && *c <= 0xff && *d <= 0xff => {
                (*a << 24) | (*b << 16) | (*c << 8) | *d
            }
            _ => return None,
        };
        return Some(IpAddr::V4(Ipv4Addr::from(ipv4_u32)));
    }
    None
}

fn parse_posix_u32(s: &str) -> Option<u32> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).ok()
    } else if s.len() > 1 && s.starts_with('0') {
        u32::from_str_radix(&s[1..], 8).ok()
    } else {
        s.parse::<u32>().ok()
    }
}

pub fn is_rfc1918_or_local(host: &str) -> bool {
    let cleaned = strip_host_brackets_and_dot(host).to_ascii_lowercase();
    if cleaned.is_empty()
        || cleaned == "localhost"
        || cleaned == "ip6-localhost"
        || cleaned == "ip6-loopback"
        || cleaned.ends_with(".localhost")
        || cleaned.ends_with(".local")
        || cleaned.ends_with(".internal")
        || cleaned.ends_with(".home.arpa")
    {
        return true;
    }
    if let Some(ip) = parse_any_ip_representation(&cleaned) {
        return is_non_global_ip(ip);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blocks_ipv6_transition_prefixes_nat64_6to4_teredo() {
        let ks = AtomicSocketKillSwitch::new(true, true);
        ks.set_tunnel_established(true);

        for transition_target in [
            "64:ff9b::127.0.0.1",
            "64:ff9b::7f00:1",
            "64:ff9b::8.8.8.8",
            "64:ff9b:1::10.0.0.1",
            "64:ff9b:1:abcd::1",
            "2002:7f00:0001::1",
            "2002:c0a8:0101::1",
            "2001:0000:4136:e378:8000:63bf:3fff:fdd2",
            "2001::1",
        ] {
            let v6: Ipv6Addr = transition_target.parse().expect("valid ipv6 literal");
            assert!(
                is_non_global_ipv6(v6),
                "Expected transition IPv6 {} to be blocked",
                transition_target
            );
            assert_eq!(
                ks.authorize_outbound_packet(transition_target),
                Err(KillSwitchBlockReason::LanAccessBlocked),
                "KillSwitch must block {}",
                transition_target
            );
            assert_eq!(
                ks.authorize_outbound_ip(IpAddr::V6(v6)),
                Err(KillSwitchBlockReason::LanAccessBlocked)
            );
        }

        // Standard globally routable IPv6 addresses must remain permitted
        for global_v6 in ["2606:4700:4700::1111", "2001:4860:4860::8888", "2001:67c:24ec::78"] {
            let v6: Ipv6Addr = global_v6.parse().expect("valid global ipv6");
            assert!(!is_non_global_ipv6(v6));
            assert!(ks.authorize_outbound_ip(IpAddr::V6(v6)).is_ok());
        }
    }
}
