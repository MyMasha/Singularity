//! Custom Encrypted DNS (DoH RFC 8484 / DoT / DoQ / ODoH) Resolver
//! with CNAME-Cloaking Tracker Unmasking, RFC 9460 SVCB/HTTPS ECH Parsing,
//! Provider Preset Catalogue, Captive Portal Fallback Policy, and Partitioned HSTS Store.

use crate::blocker::{
    domain_hierarchy, extract_etld_plus_one, normalize_host, FilterDecision, NetworkResourceType,
    UBlockNetworkEngine,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
#[cfg(not(target_os = "windows"))]
use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

pub const DNS_TYPE_A: u16 = 1;
pub const DNS_TYPE_CNAME: u16 = 5;
pub const DNS_TYPE_AAAA: u16 = 28;
pub const DNS_TYPE_SVCB: u16 = 64;
pub const DNS_TYPE_HTTPS: u16 = 65;

/// Maximum RFC 8484 DNS-over-HTTPS response payload size (64 KiB).
const MAX_DOH_RESPONSE_BYTES: usize = 65_536;

/// Maximum number of cached DNS records retained in memory by [`EncryptedDnsResolver`].
const MAX_DNS_CACHE_ENTRIES: usize = 4_096;

/// Encrypted DNS transport protocol supported by Singularity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EncryptedDnsProtocol {
    DoH,
    DoT,
    DoQ,
    ODoH,
}

/// Curated catalogue of privacy-focused encrypted DNS resolvers with hardcoded bootstrap IPs
/// so Singularity never leaks cleartext DNS queries even during initial resolver bootstrap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DnsProviderPreset {
    MullvadBase,
    MullvadAdblock,
    MullvadAll,
    Cloudflare,
    CloudflareSecurity,
    Quad9,
    NextDns,
    AdGuard,
    ControlD,
    Wikimedia,
    Custom,
}

/// Full specification of an encrypted DNS provider preset including bootstrap IP addresses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsProviderSpec {
    pub preset: DnsProviderPreset,
    pub display_name: String,
    pub protocol: EncryptedDnsProtocol,
    pub endpoint_url: String,
    pub dot_hostname: Option<String>,
    pub bootstrap_ipv4: Vec<String>,
    pub bootstrap_ipv6: Vec<String>,
    pub blocks_ads: bool,
    pub blocks_malware: bool,
    pub supports_svcb_ech: bool,
}

impl DnsProviderPreset {
    pub fn spec(self) -> DnsProviderSpec {
        match self {
            DnsProviderPreset::MullvadBase => DnsProviderSpec {
                preset: self,
                display_name: "Mullvad DNS (Base)".into(),
                protocol: EncryptedDnsProtocol::DoH,
                endpoint_url: "https://dns.mullvad.net/dns-query".into(),
                dot_hostname: Some("dns.mullvad.net".into()),
                bootstrap_ipv4: vec!["194.242.2.2".into()],
                bootstrap_ipv6: vec!["2a07:e340::2".into()],
                blocks_ads: false,
                blocks_malware: false,
                supports_svcb_ech: true,
            },
            DnsProviderPreset::MullvadAdblock => DnsProviderSpec {
                preset: self,
                display_name: "Mullvad DNS (Adblock + Trackers)".into(),
                protocol: EncryptedDnsProtocol::DoH,
                endpoint_url: "https://adblock.dns.mullvad.net/dns-query".into(),
                dot_hostname: Some("adblock.dns.mullvad.net".into()),
                bootstrap_ipv4: vec!["194.242.2.3".into()],
                bootstrap_ipv6: vec!["2a07:e340::3".into()],
                blocks_ads: true,
                blocks_malware: false,
                supports_svcb_ech: true,
            },
            DnsProviderPreset::MullvadAll => DnsProviderSpec {
                preset: self,
                display_name: "Mullvad DNS (All — Ads, Trackers, Malware, Adult)".into(),
                protocol: EncryptedDnsProtocol::DoH,
                endpoint_url: "https://all.dns.mullvad.net/dns-query".into(),
                dot_hostname: Some("all.dns.mullvad.net".into()),
                bootstrap_ipv4: vec!["194.242.2.9".into()],
                bootstrap_ipv6: vec!["2a07:e340::9".into()],
                blocks_ads: true,
                blocks_malware: true,
                supports_svcb_ech: true,
            },
            DnsProviderPreset::Cloudflare => DnsProviderSpec {
                preset: self,
                display_name: "Cloudflare 1.1.1.1".into(),
                protocol: EncryptedDnsProtocol::DoH,
                endpoint_url: "https://cloudflare-dns.com/dns-query".into(),
                dot_hostname: Some("one.one.one.one".into()),
                bootstrap_ipv4: vec!["1.1.1.1".into(), "1.0.0.1".into()],
                bootstrap_ipv6: vec!["2606:4700:4700::1111".into(), "2606:4700:4700::1001".into()],
                blocks_ads: false,
                blocks_malware: false,
                supports_svcb_ech: true,
            },
            DnsProviderPreset::CloudflareSecurity => DnsProviderSpec {
                preset: self,
                display_name: "Cloudflare Security (1.1.1.2)".into(),
                protocol: EncryptedDnsProtocol::DoH,
                endpoint_url: "https://security.cloudflare-dns.com/dns-query".into(),
                dot_hostname: Some("security.cloudflare-dns.com".into()),
                bootstrap_ipv4: vec!["1.1.1.2".into(), "1.0.0.2".into()],
                bootstrap_ipv6: vec!["2606:4700:4700::1112".into(), "2606:4700:4700::1002".into()],
                blocks_ads: false,
                blocks_malware: true,
                supports_svcb_ech: true,
            },
            DnsProviderPreset::Quad9 => DnsProviderSpec {
                preset: self,
                display_name: "Quad9 (Malware Blocking + DNSSEC)".into(),
                protocol: EncryptedDnsProtocol::DoH,
                endpoint_url: "https://dns.quad9.net/dns-query".into(),
                dot_hostname: Some("dns.quad9.net".into()),
                bootstrap_ipv4: vec!["9.9.9.9".into(), "149.112.112.112".into()],
                bootstrap_ipv6: vec!["2620:fe::fe".into(), "2620:fe::9".into()],
                blocks_ads: false,
                blocks_malware: true,
                supports_svcb_ech: true,
            },
            DnsProviderPreset::NextDns => DnsProviderSpec {
                preset: self,
                display_name: "NextDNS".into(),
                protocol: EncryptedDnsProtocol::DoH,
                endpoint_url: "https://dns.nextdns.io".into(),
                dot_hostname: Some("dns.nextdns.io".into()),
                bootstrap_ipv4: vec!["45.90.28.0".into(), "45.90.30.0".into()],
                bootstrap_ipv6: vec!["2a07:a8c0::".into(), "2a07:a8c1::".into()],
                blocks_ads: true,
                blocks_malware: true,
                supports_svcb_ech: true,
            },
            DnsProviderPreset::AdGuard => DnsProviderSpec {
                preset: self,
                display_name: "AdGuard DNS".into(),
                protocol: EncryptedDnsProtocol::DoQ,
                endpoint_url: "https://dns.adguard-dns.com/dns-query".into(),
                dot_hostname: Some("dns.adguard-dns.com".into()),
                bootstrap_ipv4: vec!["94.140.14.14".into(), "94.140.15.15".into()],
                bootstrap_ipv6: vec!["2a10:50c0::ad1:ff".into(), "2a10:50c0::ad2:ff".into()],
                blocks_ads: true,
                blocks_malware: true,
                supports_svcb_ech: true,
            },
            DnsProviderPreset::ControlD => DnsProviderSpec {
                preset: self,
                display_name: "Control D (Ads & Tracking)".into(),
                protocol: EncryptedDnsProtocol::DoH,
                endpoint_url: "https://freedns.controld.com/p2".into(),
                dot_hostname: Some("p2.freedns.controld.com".into()),
                bootstrap_ipv4: vec!["76.76.2.2".into(), "76.76.10.2".into()],
                bootstrap_ipv6: vec!["2606:1a40::2".into(), "2606:1a40:1::2".into()],
                blocks_ads: true,
                blocks_malware: true,
                supports_svcb_ech: true,
            },
            DnsProviderPreset::Wikimedia => DnsProviderSpec {
                preset: self,
                display_name: "Wikimedia DNS (Zero-Logging)".into(),
                protocol: EncryptedDnsProtocol::DoH,
                endpoint_url: "https://wikimedia-dns.org/dns-query".into(),
                dot_hostname: Some("wikimedia-dns.org".into()),
                bootstrap_ipv4: vec!["185.71.138.138".into()],
                bootstrap_ipv6: vec!["2001:67c:930::1".into()],
                blocks_ads: false,
                blocks_malware: false,
                supports_svcb_ech: true,
            },
            DnsProviderPreset::Custom => DnsProviderSpec {
                preset: self,
                display_name: "Custom Encrypted DNS".into(),
                protocol: EncryptedDnsProtocol::DoH,
                endpoint_url: String::new(),
                dot_hostname: None,
                bootstrap_ipv4: Vec::new(),
                bootstrap_ipv6: Vec::new(),
                blocks_ads: false,
                blocks_malware: false,
                supports_svcb_ech: true,
            },
        }
    }

    pub fn all_presets() -> Vec<DnsProviderSpec> {
        [
            DnsProviderPreset::MullvadBase,
            DnsProviderPreset::MullvadAdblock,
            DnsProviderPreset::MullvadAll,
            DnsProviderPreset::Cloudflare,
            DnsProviderPreset::CloudflareSecurity,
            DnsProviderPreset::Quad9,
            DnsProviderPreset::NextDns,
            DnsProviderPreset::AdGuard,
            DnsProviderPreset::ControlD,
            DnsProviderPreset::Wikimedia,
            DnsProviderPreset::Custom,
        ]
        .into_iter()
        .map(DnsProviderPreset::spec)
        .collect()
    }
}

/// Fail-closed vs alerted fallback / captive-portal temporary bypass policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DnsFallbackPolicy {
    StrictFailClosed,
    AutomaticWithAlert,
    TemporaryCaptivePortalBypass { expires_unix: u64 },
}

/// Detected captive-portal state on public Wi-Fi / hotel networks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaptivePortalState {
    None,
    Suspected {
        detected_at_unix: u64,
        probe_url: String,
    },
    Confirmed {
        portal_url: String,
        bypass_expires_unix: Option<u64>,
    },
}

/// Parsed RFC 9460 TYPE 64 (`SVCB`) or TYPE 65 (`HTTPS`) DNS resource record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SvcbHttpsRecord {
    pub rr_type: u16,
    pub priority: u16,
    pub target_name: String,
    pub alpn: Vec<String>,
    pub no_default_alpn: bool,
    pub port: Option<u16>,
    pub ipv4hint: Vec<String>,
    pub ipv6hint: Vec<String>,
    pub ech: Option<String>,
    pub ttl_seconds: u32,
}

/// Read-only snapshot of an entry in the resolver's TTL-enforced DNS cache.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsCacheEntrySnapshot {
    pub hostname: String,
    pub record: EncryptedDnsRecord,
    pub expires_at_unix: u64,
    pub remaining_ttl_seconds: u64,
}

/// Pluggable encrypted DoH transport callback `(doh_https_url, dns_wire_query) -> Result<response_bytes, error>`.
/// Response bytes may be RFC 1035 DNS wire format (`application/dns-message`) or DoH JSON (`application/dns-json`).
pub type DohTransportFn = Box<dyn Fn(&str, &[u8]) -> Result<Vec<u8>, String> + Send + Sync>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedDnsRecord {
    pub query_hostname: String,
    pub canonical_cname_chain: Vec<String>,
    pub ipv4_addresses: Vec<String>,
    pub ipv6_addresses: Vec<String>,
    pub ech_config_base64: Option<String>,
    pub ttl_seconds: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsResolutionOutcome {
    Resolved(EncryptedDnsRecord),
    BlockedCnameCloakedTracker {
        disguised_first_party_host: String,
        unmasked_tracker_cname: String,
    },
    ResolutionFailed {
        hostname: String,
        reason: String,
    },
}

struct CachedDnsEntry {
    record: EncryptedDnsRecord,
    expires_at_unix: u64,
    inserted_seq: u64,
}

fn now_unix_sec() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Zero-logging DoH/DoT/DoQ/ODoH resolver with TTL-enforced cache, CNAME-cloaking defense,
/// RFC 9460 SVCB/HTTPS ECH support, and strict fail-closed encrypted transport.
pub struct EncryptedDnsResolver {
    primary_doq_endpoint: String,
    protocol: EncryptedDnsProtocol,
    provider_preset: DnsProviderPreset,
    fallback_policy: DnsFallbackPolicy,
    captive_portal_state: CaptivePortalState,
    cache: HashMap<String, CachedDnsEntry>,
    cache_insert_seq: u64,
    custom_transport: Option<DohTransportFn>,
    allow_explicit_loopback: bool,
}

impl Default for EncryptedDnsResolver {
    fn default() -> Self {
        Self::from_preset(DnsProviderPreset::MullvadAdblock)
    }
}

impl EncryptedDnsResolver {
    pub fn new(primary_doq_endpoint: &str) -> Self {
        let protocol = if primary_doq_endpoint.trim().starts_with("quic://") {
            EncryptedDnsProtocol::DoQ
        } else {
            EncryptedDnsProtocol::DoH
        };
        Self {
            primary_doq_endpoint: primary_doq_endpoint.to_string(),
            protocol,
            provider_preset: DnsProviderPreset::Custom,
            fallback_policy: DnsFallbackPolicy::StrictFailClosed,
            captive_portal_state: CaptivePortalState::None,
            cache: HashMap::new(),
            cache_insert_seq: 0,
            custom_transport: None,
            allow_explicit_loopback: false,
        }
    }

    pub fn from_preset(preset: DnsProviderPreset) -> Self {
        let spec = preset.spec();
        Self {
            primary_doq_endpoint: spec.endpoint_url,
            protocol: spec.protocol,
            provider_preset: preset,
            fallback_policy: DnsFallbackPolicy::StrictFailClosed,
            captive_portal_state: CaptivePortalState::None,
            cache: HashMap::new(),
            cache_insert_seq: 0,
            custom_transport: None,
            allow_explicit_loopback: false,
        }
    }

    /// Creates a resolver backed by a custom encrypted transport (e.g. in-process test harness or DoH proxy).
    pub fn with_custom_transport(primary_endpoint: &str, transport: DohTransportFn) -> Self {
        let mut resolver = Self::new(primary_endpoint);
        resolver.custom_transport = Some(transport);
        resolver
    }

    pub fn set_custom_transport(&mut self, transport: DohTransportFn) {
        self.custom_transport = Some(transport);
    }

    pub fn set_protocol(&mut self, protocol: EncryptedDnsProtocol) {
        self.protocol = protocol;
    }

    pub fn protocol(&self) -> EncryptedDnsProtocol {
        self.protocol
    }

    pub fn provider_preset(&self) -> DnsProviderPreset {
        self.provider_preset
    }

    pub fn set_provider_preset(&mut self, preset: DnsProviderPreset) {
        let spec = preset.spec();
        self.provider_preset = preset;
        self.protocol = spec.protocol;
        if !spec.endpoint_url.is_empty() {
            self.primary_doq_endpoint = spec.endpoint_url;
        }
    }

    pub fn set_fallback_policy(&mut self, policy: DnsFallbackPolicy) {
        self.fallback_policy = policy;
    }

    pub fn fallback_policy(&self) -> DnsFallbackPolicy {
        self.fallback_policy
    }

    pub fn set_captive_portal_state(&mut self, state: CaptivePortalState) {
        self.captive_portal_state = state;
    }

    pub fn captive_portal_state(&self) -> &CaptivePortalState {
        &self.captive_portal_state
    }

    pub fn is_captive_portal_bypass_active(&self, now_unix: u64) -> bool {
        matches!(
            self.fallback_policy,
            DnsFallbackPolicy::TemporaryCaptivePortalBypass { expires_unix }
                if expires_unix > now_unix
        )
    }

    /// Explicitly enables/disables local loopback synthesis (`localhost`, `127.0.0.1`, `::1`) without
    /// querying an external DoH resolver. Disabled by default so all lookups stay fail-closed.
    pub fn set_allow_explicit_loopback(&mut self, allow: bool) {
        self.allow_explicit_loopback = allow;
    }

    pub fn insert_cached_record(&mut self, record: EncryptedDnsRecord) {
        let now = now_unix_sec();
        let key = record.query_hostname.to_ascii_lowercase();
        let expires_at_unix = now.saturating_add(u64::from(record.ttl_seconds.max(1)));

        if !self.cache.contains_key(&key) && self.cache.len() >= MAX_DNS_CACHE_ENTRIES {
            // Purge expired entries first before evicting live entries.
            self.cache.retain(|_, entry| entry.expires_at_unix > now);

            // If still at capacity, evict the oldest inserted entries.
            while self.cache.len() >= MAX_DNS_CACHE_ENTRIES {
                let oldest_key = self
                    .cache
                    .iter()
                    .min_by_key(|(_, entry)| (entry.inserted_seq, entry.expires_at_unix))
                    .map(|(k, _)| k.clone());
                match oldest_key {
                    Some(k) => {
                        self.cache.remove(&k);
                    }
                    None => break,
                }
            }
        }

        self.cache_insert_seq = self.cache_insert_seq.saturating_add(1);
        let inserted_seq = self.cache_insert_seq;
        self.cache.insert(
            key,
            CachedDnsEntry {
                record,
                expires_at_unix,
                inserted_seq,
            },
        );
    }

    /// Returns a sorted snapshot of all live (non-expired) DNS cache entries.
    pub fn snapshot_cache_entries(&self) -> Vec<DnsCacheEntrySnapshot> {
        let now = now_unix_sec();
        let mut entries: Vec<DnsCacheEntrySnapshot> = self
            .cache
            .iter()
            .filter(|(_, entry)| entry.expires_at_unix > now)
            .map(|(host, entry)| DnsCacheEntrySnapshot {
                hostname: host.clone(),
                record: entry.record.clone(),
                expires_at_unix: entry.expires_at_unix,
                remaining_ttl_seconds: entry.expires_at_unix.saturating_sub(now),
            })
            .collect();
        entries.sort_by(|a, b| a.hostname.cmp(&b.hostname));
        entries
    }

    /// Clears all entries from the DNS cache and returns the number of entries removed.
    pub fn clear_cache(&mut self) -> usize {
        let n = self.cache.len();
        self.cache.clear();
        n
    }

    /// Normalizes the configured endpoint into a strict HTTPS DoH URL.
    /// Rejects cleartext schemes (`http://`, `udp://`, etc.) to prevent silent downgrade.
    pub fn doh_endpoint_url(&self) -> Result<String, String> {
        let ep = self.primary_doq_endpoint.trim();
        if let Some(rest) = ep.strip_prefix("https://") {
            let host_part = rest.split('/').next().unwrap_or("");
            if host_part.is_empty() || ep.chars().any(|c| c.is_control() || c.is_whitespace()) {
                return Err("Invalid DoH HTTPS endpoint URL".into());
            }
            return Ok(ep.to_string());
        }
        if let Some(rest) = ep.strip_prefix("quic://") {
            let host_and_port = rest.split('/').next().unwrap_or("");
            let host = host_and_port.split(':').next().unwrap_or("");
            if host.is_empty() || host.chars().any(|c| c.is_control() || c.is_whitespace()) {
                return Err("Invalid DoQ endpoint host for DoH HTTPS mapping".into());
            }
            return Ok(format!("https://{}/dns-query", host));
        }
        Err(format!(
            "Refusing non-encrypted DNS endpoint '{}': only https:// (DoH) or quic:// (DoQ->DoH) endpoints are permitted",
            ep
        ))
    }

    /// Resolves `hostname` via encrypted DoH (RFC 8484 / DoH JSON), honoring TTL expiration,
    /// and inspects the full canonical CNAME chain against `UBlockNetworkEngine` to block
    /// third-party trackers disguised as first-party subdomains.
    ///
    /// Fails closed (`DnsResolutionOutcome::ResolutionFailed`) if the encrypted resolver is
    /// unreachable or returns an invalid response — never falls back to cleartext OS DNS.
    pub fn resolve_with_cname_unmasking(
        &mut self,
        hostname: &str,
        blocker: &UBlockNetworkEngine,
    ) -> DnsResolutionOutcome {
        let key = hostname.trim().trim_end_matches('.').to_ascii_lowercase();
        if key.is_empty() {
            return DnsResolutionOutcome::ResolutionFailed {
                hostname: key,
                reason: "Empty hostname".into(),
            };
        }

        let now = now_unix_sec();
        let expired = self
            .cache
            .get(&key)
            .is_some_and(|entry| entry.expires_at_unix <= now);
        if expired {
            self.cache.remove(&key);
        }

        let record = if let Some(cached) = self.cache.get(&key) {
            cached.record.clone()
        } else if self.allow_explicit_loopback && is_explicit_loopback_host(&key) {
            let rec = build_explicit_loopback_record(&key);
            self.insert_cached_record(rec.clone());
            rec
        } else {
            match self.resolve_via_encrypted_doh(&key) {
                Ok(rec) => {
                    if !rec.ipv4_addresses.is_empty()
                        || !rec.ipv6_addresses.is_empty()
                        || !rec.canonical_cname_chain.is_empty()
                        || rec.ech_config_base64.is_some()
                    {
                        self.insert_cached_record(rec.clone());
                    }
                    rec
                }
                Err(reason) => {
                    return DnsResolutionOutcome::ResolutionFailed {
                        hostname: key,
                        reason,
                    };
                }
            }
        };

        for cname_target in &record.canonical_cname_chain {
            let decision = blocker.evaluate_request(
                &format!("https://{}/", cname_target),
                cname_target,
                &key,
                NetworkResourceType::XmlHttpRequestFetch,
            );
            if matches!(
                decision,
                FilterDecision::BlockedByDomainRule(_) | FilterDecision::BlockedByPatternRule(_)
            ) {
                return DnsResolutionOutcome::BlockedCnameCloakedTracker {
                    disguised_first_party_host: key,
                    unmasked_tracker_cname: cname_target.clone(),
                };
            }
        }

        DnsResolutionOutcome::Resolved(record)
    }

    fn resolve_via_encrypted_doh(&self, hostname: &str) -> Result<EncryptedDnsRecord, String> {
        let doh_url = self.doh_endpoint_url()?;
        let query_a = build_dns_wire_query(hostname, DNS_TYPE_A)?;
        let query_aaaa = build_dns_wire_query(hostname, DNS_TYPE_AAAA)?;

        let res_a = self
            .execute_doh_query(&doh_url, &query_a)
            .and_then(|bytes| parse_doh_response_auto(hostname, &bytes));
        let res_aaaa = self
            .execute_doh_query(&doh_url, &query_aaaa)
            .and_then(|bytes| parse_doh_response_auto(hostname, &bytes));

        match (res_a, res_aaaa) {
            (Ok(mut rec_a), Ok(rec_aaaa)) => {
                for cname in rec_aaaa.canonical_cname_chain {
                    if !rec_a.canonical_cname_chain.contains(&cname) {
                        rec_a.canonical_cname_chain.push(cname);
                    }
                }
                for v4 in rec_aaaa.ipv4_addresses {
                    if !rec_a.ipv4_addresses.contains(&v4) {
                        rec_a.ipv4_addresses.push(v4);
                    }
                }
                for v6 in rec_aaaa.ipv6_addresses {
                    if !rec_a.ipv6_addresses.contains(&v6) {
                        rec_a.ipv6_addresses.push(v6);
                    }
                }
                if rec_a.ech_config_base64.is_none() {
                    rec_a.ech_config_base64 = rec_aaaa.ech_config_base64;
                }
                rec_a.ttl_seconds = rec_a.ttl_seconds.min(rec_aaaa.ttl_seconds).max(1);
                Ok(rec_a)
            }
            (Ok(rec), Err(_)) | (Err(_), Ok(rec)) => Ok(rec),
            (Err(err_a), Err(err_aaaa)) => Err(format!(
                "Encrypted DoH lookup failed (fail-closed, no cleartext fallback): A=[{}]; AAAA=[{}]",
                err_a, err_aaaa
            )),
        }
    }

    fn execute_doh_query(&self, doh_url: &str, wire_query: &[u8]) -> Result<Vec<u8>, String> {
        if let Some(ref transport) = self.custom_transport {
            return transport(doh_url, wire_query);
        }
        execute_system_https_doh(doh_url, wire_query)
    }

    pub fn primary_endpoint(&self) -> &str {
        &self.primary_doq_endpoint
    }
}

fn is_explicit_loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]")
}

fn build_explicit_loopback_record(host: &str) -> EncryptedDnsRecord {
    match host {
        "::1" | "[::1]" => EncryptedDnsRecord {
            query_hostname: host.to_string(),
            canonical_cname_chain: Vec::new(),
            ipv4_addresses: Vec::new(),
            ipv6_addresses: vec!["::1".to_string()],
            ech_config_base64: None,
            ttl_seconds: 60,
        },
        "127.0.0.1" => EncryptedDnsRecord {
            query_hostname: host.to_string(),
            canonical_cname_chain: Vec::new(),
            ipv4_addresses: vec!["127.0.0.1".to_string()],
            ipv6_addresses: Vec::new(),
            ech_config_base64: None,
            ttl_seconds: 60,
        },
        _ => EncryptedDnsRecord {
            query_hostname: host.to_string(),
            canonical_cname_chain: Vec::new(),
            ipv4_addresses: vec!["127.0.0.1".to_string()],
            ipv6_addresses: vec!["::1".to_string()],
            ech_config_base64: None,
            ttl_seconds: 60,
        },
    }
}

/// Builds an RFC 1035 / RFC 8484 DNS wire query message (ID=0, RD=1, QCLASS=IN).
pub fn build_dns_wire_query(hostname: &str, qtype: u16) -> Result<Vec<u8>, String> {
    let trimmed = hostname.trim().trim_end_matches('.');
    if trimmed.is_empty() || trimmed.len() > 253 {
        return Err("Invalid DNS query hostname length".into());
    }

    let mut packet = Vec::with_capacity(12 + trimmed.len() + 6);
    packet.extend_from_slice(&[
        0x00, 0x00, // ID = 0
        0x01, 0x00, // Flags: RD = 1
        0x00, 0x01, // QDCOUNT = 1
        0x00, 0x00, // ANCOUNT = 0
        0x00, 0x00, // NSCOUNT = 0
        0x00, 0x00, // ARCOUNT = 0
    ]);

    for label in trimmed.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(format!("Invalid DNS label '{}'", label));
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(format!("Invalid character in DNS label '{}'", label));
        }
        packet.push(label.len() as u8);
        for b in label.bytes() {
            packet.push(b.to_ascii_lowercase());
        }
    }
    packet.push(0x00);
    packet.extend_from_slice(&qtype.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
    Ok(packet)
}

/// Auto-detects DoH JSON (`application/dns-json`) vs RFC 1035 DNS wire (`application/dns-message`).
pub fn parse_doh_response_auto(
    query_hostname: &str,
    payload: &[u8],
) -> Result<EncryptedDnsRecord, String> {
    let first_non_ws = payload.iter().copied().find(|b| !b.is_ascii_whitespace());
    if first_non_ws == Some(b'{') {
        parse_doh_json_response(query_hostname, payload)
    } else {
        parse_dns_wire_response(query_hostname, payload)
    }
}

/// Parses an RFC 9460 TYPE 64 (`SVCB`) or TYPE 65 (`HTTPS`) RDATA section,
/// extracting `alpn` (key 1), `no-default-alpn` (key 2), `port` (key 3),
/// `ipv4hint` (key 4), `ech` (key 5 -> Base64), and `ipv6hint` (key 6).
pub fn parse_svcb_https_rdata(
    rdata: &[u8],
    rr_type: u16,
    ttl_seconds: u32,
) -> Result<SvcbHttpsRecord, String> {
    if rdata.len() < 3 {
        return Err("Truncated SVCB/HTTPS RDATA (< 3 bytes)".into());
    }
    let priority = u16::from_be_bytes([rdata[0], rdata[1]]);
    let (target_name, mut pos) = decode_uncompressed_dns_name(rdata, 2)?;

    let mut alpn = Vec::new();
    let mut no_default_alpn = false;
    let mut port = None;
    let mut ipv4hint = Vec::new();
    let mut ipv6hint = Vec::new();
    let mut ech = None;

    while pos < rdata.len() {
        if pos + 4 > rdata.len() {
            return Err("Truncated SVCB/HTTPS SvcParam header".into());
        }
        let key = u16::from_be_bytes([rdata[pos], rdata[pos + 1]]);
        let val_len = u16::from_be_bytes([rdata[pos + 2], rdata[pos + 3]]) as usize;
        pos += 4;
        if pos + val_len > rdata.len() {
            return Err("Truncated SVCB/HTTPS SvcParam value".into());
        }
        let val = &rdata[pos..pos + val_len];
        pos += val_len;

        match key {
            1 => {
                // alpn: sequence of 1-byte length-prefixed protocol IDs
                let mut i = 0usize;
                while i < val.len() {
                    let plen = val[i] as usize;
                    i += 1;
                    if plen == 0 || i + plen > val.len() {
                        return Err("Malformed SVCB/HTTPS alpn parameter".into());
                    }
                    let proto = std::str::from_utf8(&val[i..i + plen])
                        .map_err(|_| "Non-UTF8 ALPN identifier in SVCB/HTTPS record".to_string())?;
                    alpn.push(proto.to_string());
                    i += plen;
                }
            }
            2 => {
                if val_len != 0 {
                    return Err("SVCB/HTTPS no-default-alpn parameter must have zero length".into());
                }
                no_default_alpn = true;
            }
            3 => {
                if val_len != 2 {
                    return Err("SVCB/HTTPS port parameter must be 2 bytes".into());
                }
                port = Some(u16::from_be_bytes([val[0], val[1]]));
            }
            4 => {
                if val_len == 0 || val_len % 4 != 0 {
                    return Err("SVCB/HTTPS ipv4hint length must be a positive multiple of 4".into());
                }
                for chunk in val.chunks_exact(4) {
                    let ip = Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]).to_string();
                    if !ipv4hint.contains(&ip) {
                        ipv4hint.push(ip);
                    }
                }
            }
            5 => {
                if !val.is_empty() {
                    ech = Some(encode_base64_standard(val));
                }
            }
            6 => {
                if val_len == 0 || val_len % 16 != 0 {
                    return Err(
                        "SVCB/HTTPS ipv6hint length must be a positive multiple of 16".into(),
                    );
                }
                for chunk in val.chunks_exact(16) {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(chunk);
                    let ip = Ipv6Addr::from(octets).to_string();
                    if !ipv6hint.contains(&ip) {
                        ipv6hint.push(ip);
                    }
                }
            }
            _ => {}
        }
    }

    Ok(SvcbHttpsRecord {
        rr_type,
        priority,
        target_name,
        alpn,
        no_default_alpn,
        port,
        ipv4hint,
        ipv6hint,
        ech,
        ttl_seconds,
    })
}

/// Extracts all RFC 9460 TYPE 64 (`SVCB`) & TYPE 65 (`HTTPS`) answer records from a DNS wire packet.
pub fn parse_dns_wire_svcb_https_records(wire: &[u8]) -> Result<Vec<SvcbHttpsRecord>, String> {
    if wire.len() < 12 {
        return Err("Truncated DNS wire response (< 12 bytes)".into());
    }
    let flags = u16::from_be_bytes([wire[2], wire[3]]);
    if (flags & 0x8000) == 0 {
        return Err("DNS wire payload is not a response (QR=0)".into());
    }
    let rcode = flags & 0x000F;
    if rcode != 0 {
        return Err(format!("DNS resolver returned non-zero RCODE={}", rcode));
    }

    let qdcount = u16::from_be_bytes([wire[4], wire[5]]) as usize;
    let ancount = u16::from_be_bytes([wire[6], wire[7]]) as usize;

    let mut offset = 12usize;
    for _ in 0..qdcount {
        let (_qname, next_off) = decode_dns_name(wire, offset)?;
        if next_off + 4 > wire.len() {
            return Err("Truncated DNS question section".into());
        }
        offset = next_off + 4;
    }

    let mut records = Vec::new();
    for _ in 0..ancount {
        let (_name, next_off) = decode_dns_name(wire, offset)?;
        if next_off + 10 > wire.len() {
            return Err("Truncated DNS answer RR header".into());
        }
        let rtype = u16::from_be_bytes([wire[next_off], wire[next_off + 1]]);
        let rclass = u16::from_be_bytes([wire[next_off + 2], wire[next_off + 3]]);
        let ttl = u32::from_be_bytes([
            wire[next_off + 4],
            wire[next_off + 5],
            wire[next_off + 6],
            wire[next_off + 7],
        ]);
        let rdlength = u16::from_be_bytes([wire[next_off + 8], wire[next_off + 9]]) as usize;
        let rdata_start = next_off + 10;
        let rdata_end = rdata_start
            .checked_add(rdlength)
            .ok_or_else(|| "DNS RDLENGTH overflow".to_string())?;
        if rdata_end > wire.len() {
            return Err("Truncated DNS answer RDATA".into());
        }

        if rclass == 1 && (rtype == DNS_TYPE_SVCB || rtype == DNS_TYPE_HTTPS) {
            records.push(parse_svcb_https_rdata(
                &wire[rdata_start..rdata_end],
                rtype,
                ttl,
            )?);
        }
        offset = rdata_end;
    }
    Ok(records)
}

/// Parses an RFC 1035 / RFC 8484 / RFC 9460 binary DNS wire response, extracting CNAME chains (with full
/// RFC 1035 compression pointer decoding and loop defense), A, AAAA, SVCB (64), and HTTPS (65) records.
pub fn parse_dns_wire_response(
    query_hostname: &str,
    wire: &[u8],
) -> Result<EncryptedDnsRecord, String> {
    if wire.len() < 12 {
        return Err("Truncated DNS wire response (< 12 bytes)".into());
    }
    let flags = u16::from_be_bytes([wire[2], wire[3]]);
    let is_response = (flags & 0x8000) != 0;
    if !is_response {
        return Err("DNS wire payload is not a response (QR=0)".into());
    }
    let rcode = flags & 0x000F;
    if rcode != 0 {
        return Err(format!("DNS resolver returned non-zero RCODE={}", rcode));
    }

    let qdcount = u16::from_be_bytes([wire[4], wire[5]]) as usize;
    let ancount = u16::from_be_bytes([wire[6], wire[7]]) as usize;

    let mut offset = 12usize;
    for _ in 0..qdcount {
        let (_qname, next_off) = decode_dns_name(wire, offset)?;
        if next_off + 4 > wire.len() {
            return Err("Truncated DNS question section".into());
        }
        offset = next_off + 4;
    }

    let mut canonical_cname_chain = Vec::new();
    let mut ipv4_addresses = Vec::new();
    let mut ipv6_addresses = Vec::new();
    let mut ech_config_base64: Option<String> = None;
    let mut min_ttl: Option<u32> = None;

    for _ in 0..ancount {
        let (_name, next_off) = decode_dns_name(wire, offset)?;
        if next_off + 10 > wire.len() {
            return Err("Truncated DNS answer RR header".into());
        }
        let rtype = u16::from_be_bytes([wire[next_off], wire[next_off + 1]]);
        let rclass = u16::from_be_bytes([wire[next_off + 2], wire[next_off + 3]]);
        let ttl = u32::from_be_bytes([
            wire[next_off + 4],
            wire[next_off + 5],
            wire[next_off + 6],
            wire[next_off + 7],
        ]);
        let rdlength = u16::from_be_bytes([wire[next_off + 8], wire[next_off + 9]]) as usize;
        let rdata_start = next_off + 10;
        let rdata_end = rdata_start
            .checked_add(rdlength)
            .ok_or_else(|| "DNS RDLENGTH overflow".to_string())?;
        if rdata_end > wire.len() {
            return Err("Truncated DNS answer RDATA".into());
        }

        if rclass == 1 {
            match rtype {
                DNS_TYPE_CNAME => {
                    let (cname, cname_end) = decode_dns_name(wire, rdata_start)?;
                    if cname_end != rdata_end {
                        return Err("Malformed CNAME RDATA length mismatch".into());
                    }
                    let norm = cname.trim_end_matches('.').to_ascii_lowercase();
                    if !norm.is_empty() && !canonical_cname_chain.contains(&norm) {
                        canonical_cname_chain.push(norm);
                    }
                    min_ttl = Some(min_ttl.map_or(ttl, |cur| cur.min(ttl)));
                }
                DNS_TYPE_A => {
                    if rdlength != 4 {
                        return Err("Invalid A record RDLENGTH (expected 4)".into());
                    }
                    let ip = Ipv4Addr::new(
                        wire[rdata_start],
                        wire[rdata_start + 1],
                        wire[rdata_start + 2],
                        wire[rdata_start + 3],
                    )
                    .to_string();
                    if !ipv4_addresses.contains(&ip) {
                        ipv4_addresses.push(ip);
                    }
                    min_ttl = Some(min_ttl.map_or(ttl, |cur| cur.min(ttl)));
                }
                DNS_TYPE_AAAA => {
                    if rdlength != 16 {
                        return Err("Invalid AAAA record RDLENGTH (expected 16)".into());
                    }
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&wire[rdata_start..rdata_end]);
                    let ip = Ipv6Addr::from(octets).to_string();
                    if !ipv6_addresses.contains(&ip) {
                        ipv6_addresses.push(ip);
                    }
                    min_ttl = Some(min_ttl.map_or(ttl, |cur| cur.min(ttl)));
                }
                DNS_TYPE_SVCB | DNS_TYPE_HTTPS => {
                    let svcb = parse_svcb_https_rdata(&wire[rdata_start..rdata_end], rtype, ttl)?;
                    if ech_config_base64.is_none() {
                        ech_config_base64 = svcb.ech;
                    }
                    for v4 in svcb.ipv4hint {
                        if !ipv4_addresses.contains(&v4) {
                            ipv4_addresses.push(v4);
                        }
                    }
                    for v6 in svcb.ipv6hint {
                        if !ipv6_addresses.contains(&v6) {
                            ipv6_addresses.push(v6);
                        }
                    }
                    min_ttl = Some(min_ttl.map_or(ttl, |cur| cur.min(ttl)));
                }
                _ => {}
            }
        }

        offset = rdata_end;
    }

    Ok(EncryptedDnsRecord {
        query_hostname: query_hostname.trim().trim_end_matches('.').to_ascii_lowercase(),
        canonical_cname_chain,
        ipv4_addresses,
        ipv6_addresses,
        ech_config_base64,
        ttl_seconds: min_ttl.unwrap_or(60).clamp(1, 86_400),
    })
}

fn decode_uncompressed_dns_name(buf: &[u8], start: usize) -> Result<(String, usize), String> {
    let mut labels = Vec::new();
    let mut pos = start;
    let mut total_octets = 0usize;
    loop {
        if pos >= buf.len() {
            return Err("SVCB/HTTPS TargetName extends past end of RDATA".into());
        }
        let len = buf[pos];
        if len == 0 {
            return Ok((labels.join("."), pos + 1));
        }
        if (len & 0xC0) != 0 {
            return Err("Compression pointers are forbidden in SVCB/HTTPS TargetName (RFC 9460)".into());
        }
        let label_len = len as usize;
        let end = pos + 1 + label_len;
        if end > buf.len() {
            return Err("Truncated SVCB/HTTPS TargetName label".into());
        }
        total_octets += label_len + 1;
        if total_octets > 255 {
            return Err("SVCB/HTTPS TargetName exceeds 255 octets".into());
        }
        let label = std::str::from_utf8(&buf[pos + 1..end])
            .map_err(|_| "Non-UTF8 SVCB/HTTPS TargetName label".to_string())?;
        labels.push(label.to_ascii_lowercase());
        pos = end;
    }
}

fn decode_dns_name(wire: &[u8], start: usize) -> Result<(String, usize), String> {
    let mut labels = Vec::new();
    let mut pos = start;
    let mut next_after: Option<usize> = None;
    let mut jumps = 0usize;
    let mut total_octets = 0usize;

    loop {
        if pos >= wire.len() {
            return Err("DNS name extends past end of packet".into());
        }
        let len = wire[pos];
        if len == 0 {
            if next_after.is_none() {
                next_after = Some(pos + 1);
            }
            break;
        }
        match len & 0xC0 {
            0xC0 => {
                if pos + 1 >= wire.len() {
                    return Err("Truncated DNS compression pointer".into());
                }
                let ptr = (((len & 0x3F) as usize) << 8) | (wire[pos + 1] as usize);
                if ptr >= wire.len() {
                    return Err("Out-of-bounds DNS compression pointer".into());
                }
                jumps += 1;
                if jumps > 64 {
                    return Err("DNS compression pointer loop detected".into());
                }
                if next_after.is_none() {
                    next_after = Some(pos + 2);
                }
                pos = ptr;
            }
            0x00 => {
                let label_len = len as usize;
                let end = pos + 1 + label_len;
                if end > wire.len() {
                    return Err("Truncated DNS label".into());
                }
                total_octets += label_len + 1;
                if total_octets > 255 {
                    return Err("DNS name exceeds maximum 255 octets".into());
                }
                let label = std::str::from_utf8(&wire[pos + 1..end])
                    .map_err(|_| "Non-UTF8 DNS label".to_string())?;
                labels.push(label.to_ascii_lowercase());
                pos = end;
            }
            _ => return Err("Unsupported DNS label type bits".into()),
        }
    }

    Ok((labels.join("."), next_after.unwrap_or(pos)))
}

fn encode_base64_standard(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = if chunk.len() > 1 { u32::from(chunk[1]) } else { 0 };
        let b2 = if chunk.len() > 2 { u32::from(chunk[2]) } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((triple >> 18) & 0x3F) as usize] as char);
        out.push(TABLE[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(triple & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

#[derive(Deserialize)]
struct DohJsonAnswer {
    #[serde(rename = "type")]
    rr_type: u16,
    #[serde(rename = "TTL", default = "default_ttl")]
    ttl: u32,
    data: String,
}

fn default_ttl() -> u32 {
    60
}

#[derive(Deserialize)]
struct DohJsonResponse {
    #[serde(rename = "Status")]
    status: u16,
    #[serde(rename = "Answer", default)]
    answer: Vec<DohJsonAnswer>,
}

/// Parses an RFC 8484 / Google / Cloudflare / Mullvad DoH JSON response (`application/dns-json`).
pub fn parse_doh_json_response(
    query_hostname: &str,
    json_bytes: &[u8],
) -> Result<EncryptedDnsRecord, String> {
    let parsed: DohJsonResponse = serde_json::from_slice(json_bytes)
        .map_err(|e| format!("Invalid DoH JSON response: {}", e))?;
    if parsed.status != 0 {
        return Err(format!("DoH JSON returned non-zero Status={}", parsed.status));
    }

    let mut canonical_cname_chain = Vec::new();
    let mut ipv4_addresses = Vec::new();
    let mut ipv6_addresses = Vec::new();
    let mut min_ttl: Option<u32> = None;

    for ans in parsed.answer {
        match ans.rr_type {
            DNS_TYPE_CNAME => {
                let cname = ans.data.trim().trim_end_matches('.').to_ascii_lowercase();
                if !cname.is_empty() && !canonical_cname_chain.contains(&cname) {
                    canonical_cname_chain.push(cname);
                }
                min_ttl = Some(min_ttl.map_or(ans.ttl, |cur| cur.min(ans.ttl)));
            }
            DNS_TYPE_A => {
                let ip: Ipv4Addr = ans
                    .data
                    .trim()
                    .parse()
                    .map_err(|_| format!("Invalid IPv4 in DoH JSON answer: '{}'", ans.data))?;
                let ip_s = ip.to_string();
                if !ipv4_addresses.contains(&ip_s) {
                    ipv4_addresses.push(ip_s);
                }
                min_ttl = Some(min_ttl.map_or(ans.ttl, |cur| cur.min(ans.ttl)));
            }
            DNS_TYPE_AAAA => {
                let ip: Ipv6Addr = ans
                    .data
                    .trim()
                    .parse()
                    .map_err(|_| format!("Invalid IPv6 in DoH JSON answer: '{}'", ans.data))?;
                let ip_s = ip.to_string();
                if !ipv6_addresses.contains(&ip_s) {
                    ipv6_addresses.push(ip_s);
                }
                min_ttl = Some(min_ttl.map_or(ans.ttl, |cur| cur.min(ans.ttl)));
            }
            _ => {}
        }
    }

    Ok(EncryptedDnsRecord {
        query_hostname: query_hostname.trim().trim_end_matches('.').to_ascii_lowercase(),
        canonical_cname_chain,
        ipv4_addresses,
        ipv6_addresses,
        ech_config_base64: None,
        ttl_seconds: min_ttl.unwrap_or(60).clamp(1, 86_400),
    })
}

/// Entry stored in [`PartitionedHstsStore`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HstsEntry {
    pub host: String,
    pub first_party_etld: String,
    pub include_subdomains: bool,
    pub expires_at_unix: u64,
    pub preloaded: bool,
}

const PRELOADED_HSTS_DOMAINS: &[(&str, bool)] = &[
    ("mullvad.net", true),
    ("github.com", true),
    ("google.com", true),
    ("gmail.com", true),
    ("accounts.google.com", true),
    ("youtube.com", true),
    ("cloudflare.com", true),
    ("proton.me", true),
    ("signal.org", true),
    ("mozilla.org", true),
    ("wikipedia.org", true),
    ("duckduckgo.com", true),
    ("paypal.com", true),
    ("stripe.com", true),
    ("apple.com", true),
    ("microsoft.com", true),
    ("torproject.org", true),
    ("eff.org", true),
    // HSTS-preloaded TLDs
    ("dev", true),
    ("app", true),
    ("page", true),
    ("bank", true),
];

/// Privacy-preserving HSTS store partitioning dynamic Strict-Transport-Security state
/// by `first_party_etld` (eliminating HSTS supercookie cross-site tracking) alongside
/// a built-in preloaded HSTS list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartitionedHstsStore {
    preloaded: HashMap<String, bool>,
    dynamic_records: HashMap<(String, String), HstsEntry>,
}

impl Default for PartitionedHstsStore {
    fn default() -> Self {
        Self::new()
    }
}

impl PartitionedHstsStore {
    pub fn new() -> Self {
        let mut preloaded = HashMap::new();
        for &(domain, include_subdomains) in PRELOADED_HSTS_DOMAINS {
            preloaded.insert(domain.to_string(), include_subdomains);
        }
        Self {
            preloaded,
            dynamic_records: HashMap::new(),
        }
    }

    /// Queries whether `host` has an active HSTS policy in the `first_party_etld` partition
    /// or in the built-in preload list.
    pub fn query(
        &self,
        first_party_etld: &str,
        host: &str,
        now_unix: u64,
    ) -> Option<HstsEntry> {
        let norm_host = normalize_host(host);
        if norm_host.is_empty() {
            return None;
        }
        let partition = extract_etld_plus_one(first_party_etld);
        let hierarchy = domain_hierarchy(&norm_host);

        // 1. Check dynamic partitioned records (exact match first, then parent with includeSubDomains)
        if !partition.is_empty() {
            for (depth, &candidate) in hierarchy.iter().enumerate() {
                if let Some(entry) = self
                    .dynamic_records
                    .get(&(partition.clone(), candidate.to_string()))
                {
                    if entry.expires_at_unix > now_unix && (depth == 0 || entry.include_subdomains)
                    {
                        return Some(entry.clone());
                    }
                }
            }
        }

        // 2. Check built-in HSTS preload list
        for (depth, &candidate) in hierarchy.iter().enumerate() {
            if let Some(&include_subdomains) = self.preloaded.get(candidate) {
                if depth == 0 || include_subdomains {
                    return Some(HstsEntry {
                        host: candidate.to_string(),
                        first_party_etld: "*".into(),
                        include_subdomains,
                        expires_at_unix: u64::MAX,
                        preloaded: true,
                    });
                }
            }
        }

        None
    }

    pub fn should_upgrade_to_https(
        &self,
        first_party_etld: &str,
        host: &str,
        now_unix: u64,
    ) -> bool {
        self.query(first_party_etld, host, now_unix).is_some()
    }

    /// Records a dynamic HSTS pin isolated to `first_party_etld`.
    /// Per RFC 6797 §6.1.1, `max_age_seconds == 0` removes any existing dynamic pin for that host.
    pub fn add(
        &mut self,
        first_party_etld: &str,
        host: &str,
        max_age_seconds: u64,
        include_subdomains: bool,
        now_unix: u64,
    ) {
        let partition = extract_etld_plus_one(first_party_etld);
        let norm_host = normalize_host(host);
        if partition.is_empty() || norm_host.is_empty() {
            return;
        }
        let key = (partition.clone(), norm_host.clone());
        if max_age_seconds == 0 {
            self.dynamic_records.remove(&key);
            return;
        }
        let expires_at_unix = now_unix.saturating_add(max_age_seconds);
        self.dynamic_records.insert(
            key,
            HstsEntry {
                host: norm_host,
                first_party_etld: partition,
                include_subdomains,
                expires_at_unix,
                preloaded: false,
            },
        );
    }

    pub fn delete(&mut self, first_party_etld: &str, host: &str) -> bool {
        let partition = extract_etld_plus_one(first_party_etld);
        let norm_host = normalize_host(host);
        self.dynamic_records.remove(&(partition, norm_host)).is_some()
    }

    pub fn purge_partition(&mut self, first_party_etld: &str) -> usize {
        let partition = extract_etld_plus_one(first_party_etld);
        let before = self.dynamic_records.len();
        self.dynamic_records.retain(|(p, _), _| p != &partition);
        before - self.dynamic_records.len()
    }

    /// Purges all dynamic HSTS records while preserving the static preload list.
    pub fn purge_all(&mut self) -> usize {
        let n = self.dynamic_records.len();
        self.dynamic_records.clear();
        n
    }

    pub fn dynamic_len(&self) -> usize {
        self.dynamic_records.len()
    }

    pub fn preloaded_len(&self) -> usize {
        self.preloaded.len()
    }
}

#[cfg(not(target_os = "windows"))]
fn execute_system_https_doh(doh_url: &str, wire_query: &[u8]) -> Result<Vec<u8>, String> {
    use std::io::Read;

    let mut child = Command::new("curl")
        .args([
            "--silent",
            "--show-error",
            "--fail",
            "--proto",
            "=https",
            "--tlsv1.2",
            "--max-time",
            "5",
            "--connect-timeout",
            "4",
            "--max-filesize",
            "65536",
            "-X",
            "POST",
            "-H",
            "Content-Type: application/dns-message",
            "-H",
            "Accept: application/dns-message",
            "--data-binary",
            "@-",
            "--",
            doh_url,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn HTTPS DoH transport (curl): {}", e))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(wire_query)
            .map_err(|e| format!("Failed writing DNS wire query to DoH transport: {}", e))?;
    }

    let mut body = Vec::new();
    if let Some(stdout) = child.stdout.take() {
        stdout
            .take((MAX_DOH_RESPONSE_BYTES + 1) as u64)
            .read_to_end(&mut body)
            .map_err(|e| format!("HTTPS DoH transport I/O error: {}", e))?;
    }
    if body.len() > MAX_DOH_RESPONSE_BYTES {
        let _ = child.kill();
        let _ = child.wait();
        return Err(format!(
            "HTTPS DoH response exceeds maximum allowed {} bytes",
            MAX_DOH_RESPONSE_BYTES
        ));
    }

    let mut err_buf = Vec::new();
    if let Some(stderr) = child.stderr.take() {
        let _ = stderr.take(4096).read_to_end(&mut err_buf);
    }

    let status = child
        .wait()
        .map_err(|e| format!("HTTPS DoH transport I/O error: {}", e))?;
    if !status.success() {
        let stderr = String::from_utf8_lossy(&err_buf);
        return Err(format!(
            "HTTPS DoH request failed (status {}): {}",
            status,
            stderr.trim()
        ));
    }
    if body.is_empty() {
        return Err("HTTPS DoH resolver returned an empty body".into());
    }
    Ok(body)
}

#[cfg(target_os = "windows")]
fn execute_system_https_doh(doh_url: &str, wire_query: &[u8]) -> Result<Vec<u8>, String> {
    use std::io::Read;

    let query_hex: String = wire_query.iter().map(|b| format!("{:02x}", b)).collect();
    let ps_script = r#"
$ErrorActionPreference = 'Stop'
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls13
$url = $env:SINGULARITY_DOH_URL
if (-not $url.StartsWith('https://')) { throw 'Non-HTTPS DoH URL rejected' }
$hex = $env:SINGULARITY_DOH_QUERY_HEX
$bytes = New-Object byte[] ($hex.Length / 2)
for ($i = 0; $i -lt $bytes.Length; $i++) { $bytes[$i] = [Convert]::ToByte($hex.Substring($i * 2, 2), 16) }
$req = [System.Net.HttpWebRequest]::Create($url)
$req.Method = 'POST'
$req.Timeout = 5000
$req.ReadWriteTimeout = 5000
$req.AllowAutoRedirect = $false
$req.ContentType = 'application/dns-message'
$req.Accept = 'application/dns-message'
$req.ContentLength = $bytes.Length
$reqStream = $req.GetRequestStream()
$reqStream.Write($bytes, 0, $bytes.Length)
$reqStream.Close()
$resp = $req.GetResponse()
if ([int]$resp.StatusCode -ne 200) {
  $code = [int]$resp.StatusCode
  $resp.Close()
  throw "Unexpected DoH HTTP status $code"
}
$maxBytes = 65536
if ($resp.ContentLength -gt $maxBytes) {
  $resp.Close()
  throw "DoH response exceeds maximum allowed $maxBytes bytes"
}
$stream = $resp.GetResponseStream()
$ms = New-Object System.IO.MemoryStream
$buf = New-Object byte[] 4096
$total = 0
while (($read = $stream.Read($buf, 0, $buf.Length)) -gt 0) {
  $total += $read
  if ($total -gt $maxBytes) {
    $stream.Close()
    $resp.Close()
    throw "DoH response exceeds maximum allowed $maxBytes bytes"
  }
  $ms.Write($buf, 0, $read)
}
$stream.Close()
$resp.Close()
[BitConverter]::ToString($ms.ToArray()).Replace('-', '')
"#;
    let mut child = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", ps_script])
        .env("SINGULARITY_DOH_URL", doh_url)
        .env("SINGULARITY_DOH_QUERY_HEX", &query_hex)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to invoke Windows HTTPS DoH transport: {}", e))?;

    let max_stdout_bytes = MAX_DOH_RESPONSE_BYTES * 2 + 64;
    let mut stdout_buf = Vec::new();
    if let Some(stdout) = child.stdout.take() {
        stdout
            .take((max_stdout_bytes + 1) as u64)
            .read_to_end(&mut stdout_buf)
            .map_err(|e| format!("Windows HTTPS DoH stdout I/O error: {}", e))?;
    }
    if stdout_buf.len() > max_stdout_bytes {
        let _ = child.kill();
        let _ = child.wait();
        return Err(format!(
            "Windows HTTPS DoH response exceeds maximum allowed {} bytes",
            MAX_DOH_RESPONSE_BYTES
        ));
    }

    let mut stderr_buf = Vec::new();
    if let Some(stderr) = child.stderr.take() {
        let _ = stderr.take(4096).read_to_end(&mut stderr_buf);
    }

    let status = child
        .wait()
        .map_err(|e| format!("Windows HTTPS DoH wait error: {}", e))?;
    if !status.success() {
        let stderr = String::from_utf8_lossy(&stderr_buf);
        return Err(format!("Windows HTTPS DoH request failed: {}", stderr.trim()));
    }
    let hex_out = String::from_utf8_lossy(&stdout_buf).trim().to_string();
    decode_hex_bytes(&hex_out)
}

#[cfg(any(target_os = "windows", test))]
fn decode_hex_bytes(s: &str) -> Result<Vec<u8>, String> {
    if !s.is_ascii() || s.is_empty() || s.len() % 2 != 0 {
        return Err("Invalid hex response from Windows DoH transport".into());
    }
    if s.len() > MAX_DOH_RESPONSE_BYTES * 2 {
        return Err(format!(
            "Windows DoH response exceeds maximum allowed {} bytes",
            MAX_DOH_RESPONSE_BYTES
        ));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i + 2], 16)
            .map_err(|_| "Malformed hex byte in Windows DoH response".to_string())?;
        out.push(byte);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_mock_wire_cname_and_a_response(
        qname: &str,
        cname_target: &str,
        ipv4: [u8; 4],
        ttl: u32,
    ) -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[
            0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
        ]);
        for label in qname.split('.') {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0x00);
        pkt.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes());

        pkt.extend_from_slice(&[0xC0, 0x0C]);
        pkt.extend_from_slice(&DNS_TYPE_CNAME.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes());
        pkt.extend_from_slice(&ttl.to_be_bytes());
        let mut cname_rdata = Vec::new();
        for label in cname_target.split('.') {
            cname_rdata.push(label.len() as u8);
            cname_rdata.extend_from_slice(label.as_bytes());
        }
        cname_rdata.push(0x00);
        pkt.extend_from_slice(&(cname_rdata.len() as u16).to_be_bytes());
        let cname_rdata_offset = pkt.len();
        pkt.extend_from_slice(&cname_rdata);

        let ptr = 0xC000u16 | (cname_rdata_offset as u16);
        pkt.extend_from_slice(&ptr.to_be_bytes());
        pkt.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes());
        pkt.extend_from_slice(&ttl.to_be_bytes());
        pkt.extend_from_slice(&4u16.to_be_bytes());
        pkt.extend_from_slice(&ipv4);
        pkt
    }

    #[test]
    fn test_dns_wire_query_and_cname_cloaking_unmasking() {
        let query = build_dns_wire_query("metrics.shop.example", DNS_TYPE_A).expect("wire query");
        assert_eq!(&query[0..2], &[0x00, 0x00]);
        assert_eq!(&query[2..4], &[0x01, 0x00]);

        let wire_resp = build_mock_wire_cname_and_a_response(
            "metrics.shop.example",
            "trk.criteo.com",
            [198, 51, 100, 42],
            180,
        );
        let parsed = parse_dns_wire_response("metrics.shop.example", &wire_resp).expect("parse wire");
        assert_eq!(parsed.canonical_cname_chain, vec!["trk.criteo.com"]);
        assert_eq!(parsed.ipv4_addresses, vec!["198.51.100.42"]);
        assert_eq!(parsed.ttl_seconds, 180);

        let blocker = UBlockNetworkEngine::default();
        let mut resolver = EncryptedDnsResolver::with_custom_transport(
            "https://adblock.dns.mullvad.net/dns-query",
            Box::new(move |_url, _q| Ok(wire_resp.clone())),
        );
        let outcome = resolver.resolve_with_cname_unmasking("metrics.shop.example", &blocker);
        assert_eq!(
            outcome,
            DnsResolutionOutcome::BlockedCnameCloakedTracker {
                disguised_first_party_host: "metrics.shop.example".into(),
                unmasked_tracker_cname: "trk.criteo.com".into(),
            }
        );
    }

    #[test]
    fn test_doh_json_parser_and_clean_resolution() {
        let json_body = br#"{
            "Status": 0,
            "Answer": [
                {"name": "www.mullvad.net.", "type": 5, "TTL": 300, "data": "edge.mullvad.net."},
                {"name": "edge.mullvad.net.", "type": 1, "TTL": 120, "data": "193.138.218.78"},
                {"name": "edge.mullvad.net.", "type": 28, "TTL": 90, "data": "2001:67c:24ec::78"}
            ]
        }"#;
        let rec = parse_doh_json_response("www.mullvad.net", json_body).expect("parse json");
        assert_eq!(rec.canonical_cname_chain, vec!["edge.mullvad.net"]);
        assert_eq!(rec.ipv4_addresses, vec!["193.138.218.78"]);
        assert_eq!(rec.ipv6_addresses, vec!["2001:67c:24ec::78"]);
        assert_eq!(rec.ttl_seconds, 90);

        let blocker = UBlockNetworkEngine::default();
        let mut resolver = EncryptedDnsResolver::with_custom_transport(
            "quic://adblock.dns.mullvad.net:853",
            Box::new(move |url, _q| {
                assert_eq!(url, "https://adblock.dns.mullvad.net/dns-query");
                Ok(json_body.to_vec())
            }),
        );
        let outcome = resolver.resolve_with_cname_unmasking("www.mullvad.net", &blocker);
        assert!(matches!(outcome, DnsResolutionOutcome::Resolved(_)));
    }

    #[test]
    fn test_fail_closed_when_encrypted_transport_unreachable_no_cleartext_fallback() {
        let blocker = UBlockNetworkEngine::default();
        let mut resolver = EncryptedDnsResolver::with_custom_transport(
            "https://adblock.dns.mullvad.net/dns-query",
            Box::new(|_url, _q| Err("simulated TLS/DoH outage".into())),
        );
        let outcome = resolver.resolve_with_cname_unmasking("localhost", &blocker);
        assert!(matches!(
            outcome,
            DnsResolutionOutcome::ResolutionFailed { .. }
        ));

        resolver.set_allow_explicit_loopback(true);
        let local_outcome = resolver.resolve_with_cname_unmasking("localhost", &blocker);
        assert!(matches!(local_outcome, DnsResolutionOutcome::Resolved(_)));

        let ext_outcome = resolver.resolve_with_cname_unmasking("example.com", &blocker);
        assert!(matches!(
            ext_outcome,
            DnsResolutionOutcome::ResolutionFailed { .. }
        ));
    }

    #[test]
    fn test_rejects_cleartext_http_endpoint_and_compression_pointer_loops() {
        let blocker = UBlockNetworkEngine::default();
        let mut cleartext = EncryptedDnsResolver::new("http://1.1.1.1/dns-query");
        assert!(cleartext.doh_endpoint_url().is_err());
        assert!(matches!(
            cleartext.resolve_with_cname_unmasking("example.com", &blocker),
            DnsResolutionOutcome::ResolutionFailed { .. }
        ));

        let loop_pkt = vec![
            0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x0C,
            0x00, 0x01, 0x00, 0x01,
        ];
        assert!(parse_dns_wire_response("evil.test", &loop_pkt).is_err());
    }

    #[test]
    fn test_rfc9460_https_svcb_parsing_presets_cache_snapshot_and_partitioned_hsts() {
        // 1. Verify all DNS provider presets have bootstrap IPs (except Custom)
        let presets = DnsProviderPreset::all_presets();
        assert_eq!(presets.len(), 11);
        for spec in presets {
            if spec.preset != DnsProviderPreset::Custom {
                assert!(!spec.bootstrap_ipv4.is_empty(), "missing IPv4 bootstrap for {:?}", spec.preset);
                assert!(spec.endpoint_url.starts_with("https://"));
            }
        }

        // 2. Build an RFC 9460 TYPE 65 (HTTPS) DNS wire packet with alpn, ipv4hint, ech, ipv6hint
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&1u16.to_be_bytes()); // priority = 1
        rdata.push(0x00); // target = "." (root)
        // key 1: alpn = ["h3", "h2"]
        let alpn_val = [2u8, b'h', b'3', 2u8, b'h', b'2'];
        rdata.extend_from_slice(&1u16.to_be_bytes());
        rdata.extend_from_slice(&(alpn_val.len() as u16).to_be_bytes());
        rdata.extend_from_slice(&alpn_val);
        // key 4: ipv4hint = [104.16.132.229]
        rdata.extend_from_slice(&4u16.to_be_bytes());
        rdata.extend_from_slice(&4u16.to_be_bytes());
        rdata.extend_from_slice(&[104, 16, 132, 229]);
        // key 5: ech = b"ECH!"
        rdata.extend_from_slice(&5u16.to_be_bytes());
        rdata.extend_from_slice(&4u16.to_be_bytes());
        rdata.extend_from_slice(b"ECH!");
        // key 6: ipv6hint = 2606:4700::6810:84e5
        let v6: Ipv6Addr = "2606:4700::6810:84e5".parse().unwrap();
        rdata.extend_from_slice(&6u16.to_be_bytes());
        rdata.extend_from_slice(&16u16.to_be_bytes());
        rdata.extend_from_slice(&v6.octets());

        let mut pkt = vec![
            0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];
        // Question: cloudflare.com TYPE 65
        pkt.push(10);
        pkt.extend_from_slice(b"cloudflare");
        pkt.push(3);
        pkt.extend_from_slice(b"com");
        pkt.push(0);
        pkt.extend_from_slice(&DNS_TYPE_HTTPS.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes());
        // Answer: pointer 0xC00C, TYPE 65, CLASS IN, TTL 300
        pkt.extend_from_slice(&[0xC0, 0x0C]);
        pkt.extend_from_slice(&DNS_TYPE_HTTPS.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes());
        pkt.extend_from_slice(&300u32.to_be_bytes());
        pkt.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        pkt.extend_from_slice(&rdata);

        let svcb_records = parse_dns_wire_svcb_https_records(&pkt).expect("SVCB/HTTPS records");
        assert_eq!(svcb_records.len(), 1);
        assert_eq!(svcb_records[0].alpn, vec!["h3", "h2"]);
        assert_eq!(svcb_records[0].ipv4hint, vec!["104.16.132.229"]);
        assert_eq!(svcb_records[0].ipv6hint, vec!["2606:4700::6810:84e5"]);
        assert_eq!(svcb_records[0].ech.as_deref(), Some("RUNIIQ=="));

        let wire_rec = parse_dns_wire_response("cloudflare.com", &pkt).expect("parse wire");
        assert_eq!(wire_rec.ech_config_base64.as_deref(), Some("RUNIIQ=="));
        assert_eq!(wire_rec.ipv4_addresses, vec!["104.16.132.229"]);
        assert_eq!(wire_rec.ipv6_addresses, vec!["2606:4700::6810:84e5"]);

        // 3. Cache snapshot and clear
        let mut resolver = EncryptedDnsResolver::from_preset(DnsProviderPreset::Cloudflare);
        resolver.insert_cached_record(wire_rec);
        let snap = resolver.snapshot_cache_entries();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].hostname, "cloudflare.com");
        assert_eq!(resolver.clear_cache(), 1);
        assert!(resolver.snapshot_cache_entries().is_empty());

        // 4. Partitioned HSTS Store (prevents HSTS supercookie leakage across first-party partitions)
        let mut hsts = PartitionedHstsStore::new();
        assert!(hsts.should_upgrade_to_https("any.test", "api.mullvad.net", 1000));
        assert!(hsts.should_upgrade_to_https("any.test", "mysite.dev", 1000));

        hsts.add("site-a.test", "cdn.shared.test", 3600, true, 1000);
        assert!(hsts.should_upgrade_to_https("site-a.test", "img.cdn.shared.test", 2000));
        // Different first-party partition MUST NOT see site-a's dynamic HSTS pin
        assert!(!hsts.should_upgrade_to_https("site-b.test", "img.cdn.shared.test", 2000));
        // Expired dynamic pin returns None
        assert!(!hsts.should_upgrade_to_https("site-a.test", "img.cdn.shared.test", 5000));
        assert!(hsts.delete("site-a.test", "cdn.shared.test"));
        assert_eq!(hsts.purge_all(), 0);
    }

    #[test]
    fn test_decode_hex_bytes_rejects_non_ascii_and_oversized() {
        assert_eq!(decode_hex_bytes("deadbeef").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
        // Non-ASCII UTF-8 string of even byte length must return Err without panicking
        assert!(decode_hex_bytes("a\u{00E9}a").is_err());
        // Oversized response (> 64 KiB) must be rejected
        let too_large = "aa".repeat(MAX_DOH_RESPONSE_BYTES + 1);
        assert!(decode_hex_bytes(&too_large).is_err());
    }

    #[test]
    fn test_dns_cache_enforces_max_capacity_and_evicts_oldest() {
        let mut resolver = EncryptedDnsResolver::from_preset(DnsProviderPreset::Cloudflare);
        let overflow = 12usize;
        for i in 0..(MAX_DNS_CACHE_ENTRIES + overflow) {
            resolver.insert_cached_record(EncryptedDnsRecord {
                query_hostname: format!("host-{i}.example.test"),
                canonical_cname_chain: Vec::new(),
                ipv4_addresses: vec!["93.184.216.34".into()],
                ipv6_addresses: Vec::new(),
                ech_config_base64: None,
                ttl_seconds: 300,
            });
        }
        assert_eq!(resolver.cache.len(), MAX_DNS_CACHE_ENTRIES);
        // Oldest entries must have been evicted
        for i in 0..overflow {
            assert!(!resolver.cache.contains_key(&format!("host-{i}.example.test")));
        }
        // Newest entries must still be cached
        assert!(resolver
            .cache
            .contains_key(&format!("host-{}.example.test", MAX_DNS_CACHE_ENTRIES + overflow - 1)));
    }
}
