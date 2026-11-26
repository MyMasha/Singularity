//! 100% Local Zero-Telemetry Phishing, Malware, IDN Homograph & Typosquatting Guard.
//! Uses a local SHA-256 hash-prefix lookup table + pure-Rust Bloom filter, RFC 3492 Punycode
//! decoding, multi-script Cyrillic/Greek/Latin confusable detection, and Levenshtein distance.

use crate::blocker::{extract_etld_plus_one, normalize_host};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

/// Source feed classification for local threat ingestion (zero remote lookups at browse time).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThreatFeedKind {
    UrlHaus,
    PhishTank,
    OpenPhish,
    Badware,
    Custom(String),
}

impl ThreatFeedKind {
    pub fn label(&self) -> &str {
        match self {
            ThreatFeedKind::UrlHaus => "URLHaus",
            ThreatFeedKind::PhishTank => "PhishTank",
            ThreatFeedKind::OpenPhish => "OpenPhish",
            ThreatFeedKind::Badware => "Badware",
            ThreatFeedKind::Custom(name) => name.as_str(),
        }
    }

    fn is_malware(&self) -> bool {
        matches!(self, ThreatFeedKind::UrlHaus | ThreatFeedKind::Badware)
    }
}

/// Evaluation verdict returned by [`ThreatGuard::evaluate_url`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatVerdict {
    Safe,
    Phishing {
        matched_rule: String,
        source: String,
    },
    Malware {
        matched_rule: String,
        source: String,
    },
    IdnHomograph {
        suspicious_host: String,
        skeleton: String,
        scripts: Vec<String>,
    },
    Typosquat {
        suspicious_host: String,
        impersonated_domain: String,
        edit_distance: usize,
    },
}

impl ThreatVerdict {
    pub fn is_safe(&self) -> bool {
        matches!(self, ThreatVerdict::Safe)
    }

    pub fn is_threat(&self) -> bool {
        !self.is_safe()
    }
}

/// Pure-Rust Bloom filter using 5 independent bit positions derived from a SHA-256 digest.
#[derive(Debug, Clone)]
pub struct LocalBloomFilter {
    bits: Vec<u64>,
    bit_count: usize,
    item_count: usize,
}

impl LocalBloomFilter {
    pub fn with_bit_count(bit_count: usize) -> Self {
        let clamped_bits = bit_count.max(1024);
        let words = clamped_bits.div_ceil(64);
        Self {
            bits: vec![0u64; words],
            bit_count: words * 64,
            item_count: 0,
        }
    }

    pub fn insert_hash(&mut self, digest: &[u8; 32]) {
        for pos in self.positions(digest) {
            self.bits[pos / 64] |= 1u64 << (pos % 64);
        }
        self.item_count += 1;
    }

    pub fn might_contain_hash(&self, digest: &[u8; 32]) -> bool {
        self.positions(digest)
            .into_iter()
            .all(|pos| (self.bits[pos / 64] & (1u64 << (pos % 64))) != 0)
    }

    pub fn item_count(&self) -> usize {
        self.item_count
    }

    fn positions(&self, digest: &[u8; 32]) -> [usize; 5] {
        let h1 = u64::from_le_bytes(digest[0..8].try_into().unwrap());
        let h2 = u64::from_le_bytes(digest[8..16].try_into().unwrap());
        let h3 = u64::from_le_bytes(digest[16..24].try_into().unwrap());
        let h4 = u64::from_le_bytes(digest[24..32].try_into().unwrap());
        let h5 = h1.wrapping_add(h2.rotate_left(17)) ^ h3.rotate_right(11);
        let m = self.bit_count as u64;
        [
            (h1 % m) as usize,
            (h2 % m) as usize,
            (h3 % m) as usize,
            (h4 % m) as usize,
            (h5 % m) as usize,
        ]
    }
}

#[derive(Debug, Clone)]
struct ThreatIndicatorRecord {
    full_sha256: [u8; 32],
    canonical_indicator: String,
    source: ThreatFeedKind,
}

const DEFAULT_PROTECTED_DOMAINS: &[&str] = &[
    "google.com",
    "apple.com",
    "microsoft.com",
    "paypal.com",
    "github.com",
    "amazon.com",
    "facebook.com",
    "instagram.com",
    "netflix.com",
    "cloudflare.com",
    "mullvad.net",
    "proton.me",
    "binance.com",
    "coinbase.com",
    "chase.com",
    "bankofamerica.com",
    "wellsfargo.com",
    "stripe.com",
    "discord.com",
    "reddit.com",
    "linkedin.com",
    "dropbox.com",
    "mozilla.org",
    "wikipedia.org",
    "openai.com",
    "steampowered.com",
];

const BUILTIN_URLHAUS_MALWARE_SIGNATURES: &str = r#"
malware.testing.google.test
testsafebrowsing.appspot.com/s/malware.html
eicar-malware-drop.invalid
payload-loader.badware.test
"#;

const BUILTIN_PHISHTANK_SIGNATURES: &str = r#"
testsafebrowsing.appspot.com/s/phishing.html
secure-login-verify-paypal.invalid
account-recovery-microsoft.invalid
"#;

const BUILTIN_OPENPHISH_SIGNATURES: &str = r#"
signin-apple-id-alert.invalid
wallet-connect-airdrop.invalid
"#;

const BUILTIN_BADWARE_SIGNATURES: &str = r#"
fake-browser-update.invalid
trojan-installer.badware.test
"#;

/// Local zero-telemetry security engine evaluating URLs against embedded SHA-256 hash-prefix
/// databases, Bloom filter, RFC 3492 IDN homograph checks, and Levenshtein typosquatting.
pub struct ThreatGuard {
    bloom: LocalBloomFilter,
    prefix_table: HashMap<[u8; 8], Vec<ThreatIndicatorRecord>>,
    protected_domains: Vec<String>,
    session_exceptions: HashSet<String>,
}

impl Default for ThreatGuard {
    fn default() -> Self {
        let mut guard = Self::empty();
        guard.ingest_threat_feed(ThreatFeedKind::UrlHaus, BUILTIN_URLHAUS_MALWARE_SIGNATURES);
        guard.ingest_threat_feed(ThreatFeedKind::PhishTank, BUILTIN_PHISHTANK_SIGNATURES);
        guard.ingest_threat_feed(ThreatFeedKind::OpenPhish, BUILTIN_OPENPHISH_SIGNATURES);
        guard.ingest_threat_feed(ThreatFeedKind::Badware, BUILTIN_BADWARE_SIGNATURES);
        guard
    }
}

impl ThreatGuard {
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an empty guard with default protected brand domains but no preloaded threat feeds.
    pub fn empty() -> Self {
        Self {
            bloom: LocalBloomFilter::with_bit_count(65_536),
            prefix_table: HashMap::new(),
            protected_domains: DEFAULT_PROTECTED_DOMAINS
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            session_exceptions: HashSet::new(),
        }
    }

    /// Ingests newline-separated domains or URLs from an offline/cached threat feed
    /// (URLHaus, PhishTank, OpenPhish, Badware) into the local Bloom filter and SHA-256 prefix table.
    pub fn ingest_threat_feed(&mut self, kind: ThreatFeedKind, raw_entries: &str) -> usize {
        let mut added = 0usize;
        for line in raw_entries.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('!') {
                continue;
            }
            let canonical = canonicalize_threat_indicator(trimmed);
            if canonical.is_empty() {
                continue;
            }
            let digest = sha256_bytes(canonical.as_bytes());
            let mut prefix = [0u8; 8];
            prefix.copy_from_slice(&digest[..8]);

            let bucket = self.prefix_table.entry(prefix).or_default();
            if !bucket.iter().any(|r| r.full_sha256 == digest) {
                self.bloom.insert_hash(&digest);
                bucket.push(ThreatIndicatorRecord {
                    full_sha256: digest,
                    canonical_indicator: canonical,
                    source: kind.clone(),
                });
                added += 1;
            }
        }
        added
    }

    pub fn add_protected_domain(&mut self, domain: &str) {
        let norm = extract_etld_plus_one(domain);
        if !norm.is_empty() && !self.protected_domains.contains(&norm) {
            self.protected_domains.push(norm);
        }
    }

    pub fn protected_domains(&self) -> &[String] {
        &self.protected_domains
    }

    /// Adds a temporary session-only bypass for a user-acknowledged host or URL.
    pub fn add_session_exception(&mut self, host_or_url: &str) {
        let canon = canonicalize_threat_indicator(host_or_url);
        if !canon.is_empty() {
            self.session_exceptions.insert(canon);
        }
        let host = normalize_host(host_or_url);
        if !host.is_empty() {
            self.session_exceptions.insert(host);
        }
    }

    pub fn remove_session_exception(&mut self, host_or_url: &str) -> bool {
        let canon = canonicalize_threat_indicator(host_or_url);
        let host = normalize_host(host_or_url);
        let a = self.session_exceptions.remove(&canon);
        let b = self.session_exceptions.remove(&host);
        a || b
    }

    pub fn clear_session_exceptions(&mut self) {
        self.session_exceptions.clear();
    }

    pub fn session_exceptions(&self) -> Vec<String> {
        let mut out: Vec<String> = self.session_exceptions.iter().cloned().collect();
        out.sort();
        out
    }

    pub fn signature_count(&self) -> usize {
        self.bloom.item_count()
    }

    /// Evaluates a candidate URL locally (zero network calls) against:
    /// 1. Session exceptions
    /// 2. Local Bloom filter + SHA-256 prefix table (full URL + host hierarchy)
    /// 3. RFC 3492 IDN / Punycode multi-script homograph detector
    /// 4. Levenshtein & ASCII lookalike typosquatting detector against protected domains
    pub fn evaluate_url(&self, raw_url: &str) -> ThreatVerdict {
        let canonical_url = canonicalize_threat_indicator(raw_url);
        let host = normalize_host(raw_url);
        if host.is_empty() && canonical_url.is_empty() {
            return ThreatVerdict::Safe;
        }

        // 1. Session exception check
        if self.session_exceptions.contains(&canonical_url)
            || self.session_exceptions.contains(&host)
        {
            return ThreatVerdict::Safe;
        }

        // 2. Bloom filter + SHA-256 prefix verification (full canonical URL, then host labels)
        if let Some(rec) = self.lookup_indicator(&canonical_url) {
            return record_to_verdict(rec);
        }
        for candidate_host in host_suffix_candidates(&host) {
            if let Some(rec) = self.lookup_indicator(candidate_host) {
                return record_to_verdict(rec);
            }
        }

        // 3. IDN / Punycode multi-script homograph check
        if let Some(verdict) = self.check_idn_homograph(&host) {
            return verdict;
        }

        // 4. Typosquatting check against protected domains
        if let Some(verdict) = self.check_typosquat(&host) {
            return verdict;
        }

        ThreatVerdict::Safe
    }

    fn lookup_indicator(&self, canonical: &str) -> Option<&ThreatIndicatorRecord> {
        if canonical.is_empty() {
            return None;
        }
        let digest = sha256_bytes(canonical.as_bytes());
        if !self.bloom.might_contain_hash(&digest) {
            return None;
        }
        let mut prefix = [0u8; 8];
        prefix.copy_from_slice(&digest[..8]);
        let bucket = self.prefix_table.get(&prefix)?;
        bucket.iter().find(|r| r.full_sha256 == digest)
    }

    fn check_idn_homograph(&self, raw_host: &str) -> Option<ThreatVerdict> {
        let decoded_host = decode_idn_hostname(raw_host);
        let mut has_non_ascii = false;
        let mut mixed_scripts = false;
        let mut all_scripts: Vec<String> = Vec::new();

        for label in decoded_host.split('.') {
            let mut has_latin = false;
            let mut has_cyrillic = false;
            let mut has_greek = false;

            for ch in label.chars() {
                if !ch.is_ascii() {
                    has_non_ascii = true;
                }
                match classify_script(ch) {
                    CharScript::Latin => has_latin = true,
                    CharScript::Cyrillic => has_cyrillic = true,
                    CharScript::Greek => has_greek = true,
                    CharScript::Neutral => {}
                }
            }

            if has_latin && !all_scripts.iter().any(|s| s == "Latin") {
                all_scripts.push("Latin".into());
            }
            if has_cyrillic && !all_scripts.iter().any(|s| s == "Cyrillic") {
                all_scripts.push("Cyrillic".into());
            }
            if has_greek && !all_scripts.iter().any(|s| s == "Greek") {
                all_scripts.push("Greek".into());
            }

            let script_count = (has_latin as u8) + (has_cyrillic as u8) + (has_greek as u8);
            if script_count >= 2 {
                mixed_scripts = true;
            }
        }

        if !has_non_ascii {
            return None;
        }

        let skeleton = confusable_ascii_skeleton(&decoded_host);
        let skeleton_etld = extract_etld_plus_one(&skeleton);
        let impersonates_protected = self
            .protected_domains
            .iter()
            .any(|p| p == &skeleton_etld || p == &skeleton);

        if mixed_scripts || impersonates_protected {
            return Some(ThreatVerdict::IdnHomograph {
                suspicious_host: raw_host.to_string(),
                skeleton,
                scripts: all_scripts,
            });
        }
        None
    }

    fn check_typosquat(&self, host: &str) -> Option<ThreatVerdict> {
        let etld = extract_etld_plus_one(host);
        if etld.is_empty() {
            return None;
        }
        // Legitimate exact domain or subdomain of a protected domain is safe.
        if self.protected_domains.iter().any(|p| p == &etld) {
            return None;
        }

        let ascii_lookalike = ascii_homoglyph_skeleton(&etld);
        let cand_stem = etld.split('.').next().unwrap_or(&etld);

        for protected in &self.protected_domains {
            let prot_stem = protected.split('.').next().unwrap_or(protected);

            // Visual ASCII lookalike match (e.g. `paypa1.com`, `g00gle.com`, `arnazon.com`)
            if ascii_lookalike == *protected {
                let dist = levenshtein_distance(&etld, protected).max(1);
                return Some(ThreatVerdict::Typosquat {
                    suspicious_host: host.to_string(),
                    impersonated_domain: protected.clone(),
                    edit_distance: dist,
                });
            }

            let dist = levenshtein_distance(&etld, protected);
            let max_allowed_dist = if protected.len() >= 11 { 2 } else { 1 };
            if dist > 0 && dist <= max_allowed_dist && cand_stem.len() >= 4 && prot_stem.len() >= 4
            {
                return Some(ThreatVerdict::Typosquat {
                    suspicious_host: host.to_string(),
                    impersonated_domain: protected.clone(),
                    edit_distance: dist,
                });
            }
        }
        None
    }
}

fn record_to_verdict(rec: &ThreatIndicatorRecord) -> ThreatVerdict {
    if rec.source.is_malware() {
        ThreatVerdict::Malware {
            matched_rule: rec.canonical_indicator.clone(),
            source: rec.source.label().to_string(),
        }
    } else {
        ThreatVerdict::Phishing {
            matched_rule: rec.canonical_indicator.clone(),
            source: rec.source.label().to_string(),
        }
    }
}

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

fn canonicalize_threat_indicator(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let without_scheme = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .unwrap_or(trimmed);
    let without_frag = without_scheme.split('#').next().unwrap_or(without_scheme);
    let without_query = without_frag.split('?').next().unwrap_or(without_frag);
    let lower = without_query.to_ascii_lowercase();
    lower.trim_end_matches('/').to_string()
}

fn host_suffix_candidates(host: &str) -> Vec<&str> {
    let mut out = vec![host];
    for (idx, ch) in host.char_indices() {
        if ch == '.' && idx + 1 < host.len() {
            out.push(&host[idx + 1..]);
        }
    }
    out
}

/// Computes exact Unicode character Levenshtein edit distance between `a` and `b`.
pub fn levenshtein_distance(a: &str, b: &str) -> usize {
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();
    if a_chars.is_empty() {
        return b_chars.len();
    }
    if b_chars.is_empty() {
        return a_chars.len();
    }

    let mut prev: Vec<usize> = (0..=b_chars.len()).collect();
    let mut curr = vec![0usize; b_chars.len() + 1];

    for (i, &ca) in a_chars.iter().enumerate() {
        curr[0] = i + 1;
        for (j, &cb) in b_chars.iter().enumerate() {
            let cost = usize::from(ca != cb);
            curr[j + 1] = (prev[j + 1] + 1)
                .min(curr[j] + 1)
                .min(prev[j] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[b_chars.len()]
}

/// Decodes any `xn--` Punycode labels in `hostname` into Unicode per RFC 3492.
pub fn decode_idn_hostname(hostname: &str) -> String {
    hostname
        .split('.')
        .map(|label| {
            let lower = label.to_ascii_lowercase();
            if let Some(encoded) = lower.strip_prefix("xn--") {
                decode_punycode_label(encoded).unwrap_or(lower)
            } else {
                lower
            }
        })
        .collect::<Vec<_>>()
        .join(".")
}

/// Pure-Rust RFC 3492 Bootstring/Punycode decoder for a single label (without `xn--` prefix).
pub fn decode_punycode_label(input: &str) -> Option<String> {
    const BASE: u32 = 36;
    const TMIN: u32 = 1;
    const TMAX: u32 = 26;
    const SKEW: u32 = 38;
    const DAMP: u32 = 700;
    const INITIAL_BIAS: u32 = 72;
    const INITIAL_N: u32 = 128;

    fn adapt(mut delta: u32, numpoints: u32, firsttime: bool) -> u32 {
        delta = if firsttime { delta / DAMP } else { delta / 2 };
        delta += delta / numpoints;
        let mut k = 0u32;
        while delta > ((BASE - TMIN) * TMAX) / 2 {
            delta /= BASE - TMIN;
            k += BASE;
        }
        k + (((BASE - TMIN + 1) * delta) / (delta + SKEW))
    }

    let bytes = input.as_bytes();
    let (mut output, mut idx): (Vec<char>, usize) = match input.rfind('-') {
        Some(delim) => {
            if !input[..delim].is_ascii() {
                return None;
            }
            (input[..delim].chars().collect(), delim + 1)
        }
        None => (Vec::new(), 0),
    };

    let mut n = INITIAL_N;
    let mut i = 0u32;
    let mut bias = INITIAL_BIAS;

    while idx < bytes.len() {
        let oldi = i;
        let mut w = 1u32;
        let mut k = BASE;
        loop {
            if idx >= bytes.len() {
                return None;
            }
            let b = bytes[idx];
            idx += 1;
            let digit = match b {
                b'a'..=b'z' => (b - b'a') as u32,
                b'A'..=b'Z' => (b - b'A') as u32,
                b'0'..=b'9' => (b - b'0') as u32 + 26,
                _ => return None,
            };
            i = i.checked_add(digit.checked_mul(w)?)?;
            let t = if k <= bias {
                TMIN
            } else if k >= bias + TMAX {
                TMAX
            } else {
                k - bias
            };
            if digit < t {
                break;
            }
            w = w.checked_mul(BASE - t)?;
            k += BASE;
        }
        let out_len = (output.len() + 1) as u32;
        bias = adapt(i - oldi, out_len, oldi == 0);
        n = n.checked_add(i / out_len)?;
        i %= out_len;
        let ch = char::from_u32(n)?;
        output.insert(i as usize, ch);
        i += 1;
    }

    Some(output.into_iter().collect())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CharScript {
    Latin,
    Cyrillic,
    Greek,
    Neutral,
}

fn classify_script(ch: char) -> CharScript {
    let cp = ch as u32;
    match cp {
        0x0041..=0x005A | 0x0061..=0x007A | 0x00C0..=0x024F => CharScript::Latin,
        0x0400..=0x052F => CharScript::Cyrillic,
        0x0370..=0x03FF | 0x1F00..=0x1FFF => CharScript::Greek,
        _ => CharScript::Neutral,
    }
}

/// Maps Cyrillic, Greek, and common diacritic confusables to an ASCII Latin skeleton.
pub fn confusable_ascii_skeleton(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        let mapped = match ch {
            // Cyrillic lookalikes
            'а' | 'А' => 'a',
            'в' | 'В' => 'b',
            'с' | 'С' => 'c',
            'ԁ' | 'Ԁ' => 'd',
            'е' | 'Е' => 'e',
            'ɡ' => 'g',
            'һ' | 'Һ' | 'н' | 'Н' => 'h',
            'і' | 'І' | 'ї' | 'Ї' => 'i',
            'ј' | 'Ј' => 'j',
            'к' | 'К' | 'қ' => 'k',
            'ӏ' | 'Ӏ' => 'l',
            'м' | 'М' => 'm',
            'о' | 'О' => 'o',
            'р' | 'Р' => 'p',
            'ԛ' | 'Ԛ' => 'q',
            'ѕ' | 'Ѕ' => 's',
            'т' | 'Т' => 't',
            'у' | 'У' => 'y',
            'ѵ' | 'Ѵ' => 'v',
            'ԝ' | 'Ԝ' => 'w',
            'х' | 'Х' => 'x',
            // Greek lookalikes
            'α' | 'Α' => 'a',
            'β' | 'Β' => 'b',
            'ε' | 'Ε' => 'e',
            'ζ' | 'Ζ' => 'z',
            'η' | 'Η' => 'n',
            'ι' | 'Ι' => 'i',
            'κ' | 'Κ' => 'k',
            'μ' | 'Μ' => 'm',
            'ν' | 'Ν' => 'v',
            'ο' | 'Ο' => 'o',
            'ρ' | 'Ρ' => 'p',
            'τ' | 'Τ' => 't',
            'υ' | 'Υ' => 'u',
            'χ' | 'Χ' => 'x',
            // Latin diacritics
            'á' | 'à' | 'â' | 'ä' | 'ã' | 'å' => 'a',
            'é' | 'è' | 'ê' | 'ë' => 'e',
            'í' | 'ì' | 'î' | 'ï' | 'ı' => 'i',
            'ó' | 'ò' | 'ô' | 'ö' | 'õ' | 'ø' => 'o',
            'ú' | 'ù' | 'û' | 'ü' => 'u',
            'ç' => 'c',
            'ñ' => 'n',
            other => other.to_ascii_lowercase(),
        };
        out.push(mapped);
    }
    out
}

fn ascii_homoglyph_skeleton(domain: &str) -> String {
    let single_mapped: String = domain
        .chars()
        .map(|c| match c {
            '0' => 'o',
            '1' => 'l',
            '3' => 'e',
            '5' => 's',
            _ => c,
        })
        .collect();
    single_mapped.replace("rn", "m").replace("vv", "w")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bloom_and_sha256_prefix_feed_ingestion_and_session_exceptions() {
        let mut guard = ThreatGuard::default();

        // Built-in URLHaus & PhishTank entries trigger immediately
        assert!(matches!(
            guard.evaluate_url("https://malware.testing.google.test/drop.bin"),
            ThreatVerdict::Malware { .. }
        ));
        assert!(matches!(
            guard.evaluate_url("https://secure-login-verify-paypal.invalid/auth"),
            ThreatVerdict::Phishing { .. }
        ));

        // Custom feed ingestion
        let added = guard.ingest_threat_feed(
            ThreatFeedKind::OpenPhish,
            "https://evil-phish-bank.test/login\n# comment\nstealer.bad.test\n",
        );
        assert_eq!(added, 2);
        assert!(matches!(
            guard.evaluate_url("https://evil-phish-bank.test/login?ref=1"),
            ThreatVerdict::Phishing { .. }
        ));
        assert!(matches!(
            guard.evaluate_url("https://sub.stealer.bad.test/x"),
            ThreatVerdict::Phishing { .. }
        ));

        // Session exception temporarily bypasses warning
        guard.add_session_exception("evil-phish-bank.test");
        assert_eq!(
            guard.evaluate_url("https://evil-phish-bank.test/login"),
            ThreatVerdict::Safe
        );
        guard.clear_session_exceptions();
        assert!(matches!(
            guard.evaluate_url("https://evil-phish-bank.test/login"),
            ThreatVerdict::Phishing { .. }
        ));
    }

    #[test]
    fn test_punycode_idn_homograph_and_levenshtein_typosquat() {
        let guard = ThreatGuard::default();

        // Classic whole-Cyrillic apple.com homograph (`xn--80ak6aa92e.com`)
        let decoded = decode_idn_hostname("xn--80ak6aa92e.com");
        assert_eq!(confusable_ascii_skeleton(&decoded), "apple.com");
        assert!(matches!(
            guard.evaluate_url("https://xn--80ak6aa92e.com/"),
            ThreatVerdict::IdnHomograph { .. }
        ));

        // Mixed Latin + Cyrillic label (`аpple.com` with Cyrillic а U+0430)
        assert!(matches!(
            guard.evaluate_url("https://\u{0430}pple.com/"),
            ThreatVerdict::IdnHomograph { .. }
        ));

        // Levenshtein distance & typosquat detection
        assert_eq!(levenshtein_distance("kitten", "sitting"), 3);
        assert_eq!(levenshtein_distance("goggle.com", "google.com"), 1);

        assert!(matches!(
            guard.evaluate_url("https://paypa1.com/signin"),
            ThreatVerdict::Typosquat {
                impersonated_domain,
                ..
            } if impersonated_domain == "paypal.com"
        ));
        assert!(matches!(
            guard.evaluate_url("https://githob.com/repo"),
            ThreatVerdict::Typosquat {
                impersonated_domain,
                edit_distance: 1,
                ..
            } if impersonated_domain == "github.com"
        ));

        // Legitimate domains & subdomains stay Safe
        assert_eq!(guard.evaluate_url("https://docs.github.com/en"), ThreatVerdict::Safe);
        assert_eq!(guard.evaluate_url("https://am.i.mullvad.net/"), ThreatVerdict::Safe);
    }
}
