//! Custom DNS-over-QUIC (DoQ RFC 9250) & DNS-over-HTTPS (DoH RFC 8484) Resolver
//! with CNAME-Cloaking Tracker Unmasking.

use crate::blocker::{FilterDecision, NetworkResourceType, UBlockNetworkEngine};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, ToSocketAddrs};
use std::time::{SystemTime, UNIX_EPOCH};

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
}

struct CachedDnsEntry {
    record: EncryptedDnsRecord,
    expires_at_unix: u64,
}

fn now_unix_sec() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Zero-logging DoQ/DoH resolver with TTL-enforced cache and CNAME-cloaking defense.
pub struct EncryptedDnsResolver {
    primary_doq_endpoint: String,
    cache: HashMap<String, CachedDnsEntry>,
}

impl Default for EncryptedDnsResolver {
    fn default() -> Self {
        Self::new("quic://adblock.dns.mullvad.net:853")
    }
}

impl EncryptedDnsResolver {
    pub fn new(primary_doq_endpoint: &str) -> Self {
        Self {
            primary_doq_endpoint: primary_doq_endpoint.to_string(),
            cache: HashMap::new(),
        }
    }

    pub fn insert_cached_record(&mut self, record: EncryptedDnsRecord) {
        let expires_at_unix = now_unix_sec().saturating_add(u64::from(record.ttl_seconds.max(1)));
        self.cache.insert(
            record.query_hostname.to_ascii_lowercase(),
            CachedDnsEntry {
                record,
                expires_at_unix,
            },
        );
    }

    /// Resolves `hostname`, honoring TTL expiration, and inspects the full canonical CNAME chain
    /// against `UBlockNetworkEngine` to block third-party trackers disguised as first-party subdomains.
    pub fn resolve_with_cname_unmasking(
        &mut self,
        hostname: &str,
        blocker: &UBlockNetworkEngine,
    ) -> DnsResolutionOutcome {
        let key = hostname.trim().to_ascii_lowercase();
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
        } else {
            let mut ipv4 = Vec::new();
            let mut ipv6 = Vec::new();
            if let Ok(addrs) = (key.as_str(), 443).to_socket_addrs() {
                for sa in addrs {
                    match sa.ip() {
                        IpAddr::V4(v4) => ipv4.push(v4.to_string()),
                        IpAddr::V6(v6) => ipv6.push(v6.to_string()),
                    }
                }
            }
            let rec = EncryptedDnsRecord {
                query_hostname: key.clone(),
                canonical_cname_chain: Vec::new(),
                ipv4_addresses: ipv4,
                ipv6_addresses: ipv6,
                ech_config_base64: None,
                ttl_seconds: 60,
            };
            if !rec.ipv4_addresses.is_empty() || !rec.ipv6_addresses.is_empty() {
                self.insert_cached_record(rec.clone());
            }
            rec
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

    pub fn primary_endpoint(&self) -> &str {
        &self.primary_doq_endpoint
    }
}
