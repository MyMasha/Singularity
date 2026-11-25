//! Custom DNS-over-HTTPS (DoH RFC 8484 / JSON) Resolver
//! with CNAME-Cloaking Tracker Unmasking and Fail-Closed Encrypted Transport.

use crate::blocker::{FilterDecision, NetworkResourceType, UBlockNetworkEngine};
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
}

fn now_unix_sec() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Zero-logging DoH/DoQ resolver with TTL-enforced cache, CNAME-cloaking defense,
/// and strict fail-closed encrypted transport (zero cleartext OS DNS fallback).
pub struct EncryptedDnsResolver {
    primary_doq_endpoint: String,
    cache: HashMap<String, CachedDnsEntry>,
    custom_transport: Option<DohTransportFn>,
    allow_explicit_loopback: bool,
}

impl Default for EncryptedDnsResolver {
    fn default() -> Self {
        Self::new("https://adblock.dns.mullvad.net/dns-query")
    }
}

impl EncryptedDnsResolver {
    pub fn new(primary_doq_endpoint: &str) -> Self {
        Self {
            primary_doq_endpoint: primary_doq_endpoint.to_string(),
            cache: HashMap::new(),
            custom_transport: None,
            allow_explicit_loopback: false,
        }
    }

    /// Creates a resolver backed by a custom encrypted transport (e.g. in-process test harness or DoH proxy).
    pub fn with_custom_transport(primary_endpoint: &str, transport: DohTransportFn) -> Self {
        Self {
            primary_doq_endpoint: primary_endpoint.to_string(),
            cache: HashMap::new(),
            custom_transport: Some(transport),
            allow_explicit_loopback: false,
        }
    }

    pub fn set_custom_transport(&mut self, transport: DohTransportFn) {
        self.custom_transport = Some(transport);
    }

    /// Explicitly enables/disables local loopback synthesis (`localhost`, `127.0.0.1`, `::1`) without
    /// querying an external DoH resolver. Disabled by default so all lookups stay fail-closed.
    pub fn set_allow_explicit_loopback(&mut self, allow: bool) {
        self.allow_explicit_loopback = allow;
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
    // RFC 8484 §4.1: ID MUST be 0 for DoH queries
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
    packet.push(0x00); // Root label terminator
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

/// Parses an RFC 1035 / RFC 8484 binary DNS wire response, extracting CNAME chains (with full
/// RFC 1035 compression pointer decoding and loop defense), A, AAAA records, and minimum TTL.
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
        offset = next_off + 4; // QTYPE (2) + QCLASS (2)
    }

    let mut canonical_cname_chain = Vec::new();
    let mut ipv4_addresses = Vec::new();
    let mut ipv6_addresses = Vec::new();
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
        ech_config_base64: None,
        ttl_seconds: min_ttl.unwrap_or(60).clamp(1, 86_400),
    })
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

#[cfg(not(target_os = "windows"))]
fn execute_system_https_doh(doh_url: &str, wire_query: &[u8]) -> Result<Vec<u8>, String> {
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

    let output = child
        .wait_with_output()
        .map_err(|e| format!("HTTPS DoH transport I/O error: {}", e))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "HTTPS DoH request failed (status {}): {}",
            output.status,
            stderr.trim()
        ));
    }
    if output.stdout.is_empty() {
        return Err("HTTPS DoH resolver returned an empty body".into());
    }
    Ok(output.stdout)
}

#[cfg(target_os = "windows")]
fn execute_system_https_doh(doh_url: &str, wire_query: &[u8]) -> Result<Vec<u8>, String> {
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
$req.ContentType = 'application/dns-message'
$req.Accept = 'application/dns-message'
$req.ContentLength = $bytes.Length
$reqStream = $req.GetRequestStream()
$reqStream.Write($bytes, 0, $bytes.Length)
$reqStream.Close()
$resp = $req.GetResponse()
$ms = New-Object System.IO.MemoryStream
$resp.GetResponseStream().CopyTo($ms)
$resp.Close()
[BitConverter]::ToString($ms.ToArray()).Replace('-', '')
"#;
    let output = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", ps_script])
        .env("SINGULARITY_DOH_URL", doh_url)
        .env("SINGULARITY_DOH_QUERY_HEX", &query_hex)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("Failed to invoke Windows HTTPS DoH transport: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Windows HTTPS DoH request failed: {}", stderr.trim()));
    }
    let hex_out = String::from_utf8_lossy(&output.stdout).trim().to_string();
    decode_hex_bytes(&hex_out)
}

#[cfg(target_os = "windows")]
fn decode_hex_bytes(s: &str) -> Result<Vec<u8>, String> {
    if s.is_empty() || s.len() % 2 != 0 {
        return Err("Invalid hex response from Windows DoH transport".into());
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

    /// Helper constructing a valid RFC 1035 DNS wire response with a CNAME chain and A record
    /// including a compression pointer to exercise RFC 1035 pointer decoding.
    fn build_mock_wire_cname_and_a_response(
        qname: &str,
        cname_target: &str,
        ipv4: [u8; 4],
        ttl: u32,
    ) -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[
            0x00, 0x00, // ID
            0x81, 0x80, // Flags: QR=1, RD=1, RA=1, RCODE=0
            0x00, 0x01, // QDCOUNT=1
            0x00, 0x02, // ANCOUNT=2 (CNAME + A)
            0x00, 0x00, // NSCOUNT=0
            0x00, 0x00, // ARCOUNT=0
        ]);
        // Question at offset 12
        for label in qname.split('.') {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0x00);
        pkt.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes());

        // Answer 1: CNAME pointing from QNAME (compression pointer 0xC00C) -> cname_target
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

        // Answer 2: A record for cname_target (compression pointer to cname_rdata_offset)
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
        assert_eq!(&query[0..2], &[0x00, 0x00]); // RFC 8484 ID=0
        assert_eq!(&query[2..4], &[0x01, 0x00]); // RD=1

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
        // Even for "localhost", fail-closed unless explicit loopback mode is enabled
        let outcome = resolver.resolve_with_cname_unmasking("localhost", &blocker);
        assert!(matches!(
            outcome,
            DnsResolutionOutcome::ResolutionFailed { .. }
        ));

        // Explicit loopback mode allows localhost only when opted in
        resolver.set_allow_explicit_loopback(true);
        let local_outcome = resolver.resolve_with_cname_unmasking("localhost", &blocker);
        assert!(matches!(local_outcome, DnsResolutionOutcome::Resolved(_)));

        // Non-loopback host STILL fails closed (never falls back to OS DNS)
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

        // Malicious self-referencing compression pointer at offset 12 (0xC00C)
        let loop_pkt = vec![
            0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x0C,
            0x00, 0x01, 0x00, 0x01,
        ];
        assert!(parse_dns_wire_response("evil.test", &loop_pkt).is_err());
    }
}
