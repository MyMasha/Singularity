//! Singularity Omnibox Intelligence Engine — 100% Pure Rust.
//!
//! Provides:
//! - Frecency scoring (`compute_frecency`) and Unicode-safe fuzzy matching (`fuzzy_score`)
//! - Omnibox input classification (`classify_omnibox_input`) & URL display segmenter
//!   (`segment_url_for_display`) with RFC 3492 Punycode decoding & IDN homograph detection
//! - Scoped search (`@tabs`/`%`, `@history`/`^`, `@bookmarks`/`*`, `@settings`, `@extensions`),
//!   Tab-to-Search hints, and bilingual EN/FR Quick Actions
//! - Full Search Engine Registry (`SearchEngineRegistry`) with CRUD, normal vs. private defaults,
//!   safe pure-Rust OpenSearch XML parser (`parse_opensearch_xml`), OpenSearch/DuckDuckGo JSON
//!   suggestion parser, and 115+ built-in offline Bangs (`!w`, `!g`, `!rs`, `!gh`, ...)
//! - 100% Offline Instant Answer engine (`evaluate_instant_answer`):
//!   - Recursive-descent scientific calculator (operators, precedence, functions, factorials, %)
//!   - Bilingual EN/FR unit converter (length, mass, temperature, volume, speed, SI/IEC data, rates)
//!   - 65+ city & abbreviation timezone converter
//!   - Color converter (HEX, RGB, HSL, OKLCH + WCAG 2.1 contrast ratios on `#000000` & `#FFFFFF`)
//!   - Developer tools (radix conversions, bitwise ops, Unix timestamps, `OsRng` UUID v4)
//!   - Offline FX currency converter (`FxRatesCache` + ECB XML feed parser)
//! - Pure-Rust ISO/IEC 18004 QR Code encoder (Versions 1–10, Byte mode, GF(256) Reed-Solomon
//!   EC levels L/M, all 8 masks with penalty scoring) rendering crisp SVG (`generate_qr_svg`)
//! - Unified query engine (`OmniboxEngine::query`) merging all candidate sources.

use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

// ============================================================================
// Errors
// ============================================================================

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum OmniboxError {
    #[error("invalid OpenSearch XML: {0}")]
    InvalidOpenSearchXml(String),
    #[error("invalid ECB FX XML: {0}")]
    InvalidFxXml(String),
    #[error("search engine '{0}' not found")]
    EngineNotFound(String),
    #[error("search engine '{0}' already exists")]
    EngineAlreadyExists(String),
    #[error("cannot delete default search engine '{0}'")]
    CannotDeleteDefaultEngine(String),
    #[error("QR code payload too large ({0} bytes)")]
    QrPayloadTooLarge(usize),
}

// ============================================================================
// Fuzzy Matching & Frecency Scoring
// ============================================================================

/// Scores how well `pattern` fuzzy-matches `text` (case-insensitive over Unicode scalar values).
///
/// Returns `Some((score, matched_char_indices))` if every character in `pattern` appears in
/// order in `text`, or `None` otherwise. Matched indices are 0-based character indices into `text`.
pub fn fuzzy_score(pattern: &str, text: &str) -> Option<(i64, Vec<usize>)> {
    let pat_chars: Vec<char> = pattern.trim().chars().flat_map(|c| c.to_lowercase()).collect();
    if pat_chars.is_empty() {
        return Some((0, Vec::new()));
    }

    let orig_chars: Vec<char> = text.chars().collect();
    // Map each lowercase char back to its original character index in `text`.
    let mut lowered: Vec<(char, usize)> = Vec::with_capacity(orig_chars.len());
    for (idx, ch) in orig_chars.iter().enumerate() {
        for lc in ch.to_lowercase() {
            lowered.push((lc, idx));
        }
    }

    let m = pat_chars.len();
    let n = lowered.len();
    if m > n {
        return None;
    }

    // Fast subsequence pre-check
    {
        let mut pi = 0usize;
        for &(lc, _) in &lowered {
            if lc == pat_chars[pi] {
                pi += 1;
                if pi == m {
                    break;
                }
            }
        }
        if pi < m {
            return None;
        }
    }

    // Precompute boundary bonus per lowered index
    let mut is_boundary = vec![false; n];
    for i in 0..n {
        let orig_idx = lowered[i].1;
        if orig_idx == 0 {
            is_boundary[i] = true;
        } else {
            let prev = orig_chars[orig_idx - 1];
            let curr = orig_chars[orig_idx];
            if matches!(
                prev,
                '/' | '.' | '-' | '_' | ' ' | ':' | '?' | '&' | '=' | '#' | '@' | '+' | '(' | '['
            ) || (prev.is_lowercase() && curr.is_uppercase())
            {
                is_boundary[i] = true;
            }
        }
    }

    // Exact DP alignment for patterns up to 64 chars and texts up to 512 chars
    if m <= 64 && n <= 512 {
        const NEG_INF: i64 = i64::MIN / 4;
        // dp_match[i][j] = best score matching pat[0..=i] with pat[i] matched at lowered[j]
        let mut dp = vec![vec![NEG_INF; n]; m];
        let mut parent = vec![vec![usize::MAX; n]; m];

        for j in 0..n {
            if lowered[j].0 == pat_chars[0] {
                let mut sc: i64 = 16;
                if j == 0 {
                    sc += 32; // prefix match bonus
                } else if is_boundary[j] {
                    sc += 20;
                } else {
                    sc -= (j as i64).min(24);
                }
                dp[0][j] = sc;
            }
        }

        for i in 1..m {
            // Maintain best prefix max over k < j with gap penalty -(j - k - 1) * 2
            // Rewrite: score(k) - 2*(j - k - 1) = (score(k) + 2*k) - 2*j + 2
            let mut best_non_adj_val = NEG_INF;
            let mut best_non_adj_k = usize::MAX;

            for j in i..n {
                if j >= 2 {
                    let k = j - 2;
                    if dp[i - 1][k] > NEG_INF {
                        let cand = dp[i - 1][k] + 2 * (k as i64);
                        if cand > best_non_adj_val {
                            best_non_adj_val = cand;
                            best_non_adj_k = k;
                        }
                    }
                }

                if lowered[j].0 != pat_chars[i] {
                    continue;
                }

                let mut base_bonus: i64 = 16;
                if is_boundary[j] {
                    base_bonus += 18;
                }

                let mut best_here = NEG_INF;
                let mut best_prev = usize::MAX;

                // Consecutive match (k == j - 1)
                if dp[i - 1][j - 1] > NEG_INF {
                    let consec = dp[i - 1][j - 1] + base_bonus + 22;
                    if consec > best_here {
                        best_here = consec;
                        best_prev = j - 1;
                    }
                }

                // Non-consecutive match (k <= j - 2)
                if best_non_adj_k != usize::MAX {
                    let gapped = best_non_adj_val - 2 * (j as i64) + 2 + base_bonus;
                    if gapped > best_here {
                        best_here = gapped;
                        best_prev = best_non_adj_k;
                    }
                }

                dp[i][j] = best_here;
                parent[i][j] = best_prev;
            }
        }

        let mut best_end_score = NEG_INF;
        let mut best_end_j = usize::MAX;
        for j in (m - 1)..n {
            if dp[m - 1][j] > best_end_score {
                best_end_score = dp[m - 1][j];
                best_end_j = j;
            }
        }
        if best_end_j == usize::MAX || best_end_score <= NEG_INF / 2 {
            return None;
        }

        let mut indices = Vec::with_capacity(m);
        let mut cur_j = best_end_j;
        for i in (0..m).rev() {
            let orig_idx = lowered[cur_j].1;
            if indices.last().copied() != Some(orig_idx) {
                indices.push(orig_idx);
            }
            if i > 0 {
                cur_j = parent[i][cur_j];
            }
        }
        indices.reverse();

        // Exact full match bonus + slight length penalty for noisy long strings
        let mut final_score = best_end_score - ((orig_chars.len().saturating_sub(m)) as i64 / 3);
        if m == n {
            final_score += 50;
        }
        return Some((final_score, indices));
    }

    // Greedy fallback for very long inputs
    let mut indices = Vec::with_capacity(m);
    let mut score: i64 = 0;
    let mut pi = 0usize;
    let mut last_j: Option<usize> = None;
    for (j, &(lc, orig_idx)) in lowered.iter().enumerate() {
        if lc == pat_chars[pi] {
            score += 16;
            if let Some(prev) = last_j {
                if j == prev + 1 {
                    score += 20;
                } else {
                    score -= ((j - prev - 1) as i64).min(20);
                }
            } else if j == 0 {
                score += 30;
            }
            if is_boundary[j] {
                score += 15;
            }
            if indices.last().copied() != Some(orig_idx) {
                indices.push(orig_idx);
            }
            last_j = Some(j);
            pi += 1;
            if pi == m {
                break;
            }
        }
    }
    if pi == m {
        Some((score, indices))
    } else {
        None
    }
}

/// Computes a Mozilla-inspired frecency score combining visit frequency, typed intent,
/// exponential recency decay, and bookmark boost.
pub fn compute_frecency(
    visit_count: u32,
    typed_count: u32,
    age_secs: u64,
    is_bookmark: bool,
) -> f64 {
    let visits = visit_count as f64;
    let typed = typed_count as f64;

    let freq_base = visits.ln_1p() * 25.0 + visits.min(300.0) * 1.25;
    let typed_bonus = typed.ln_1p() * 35.0 + typed.min(100.0) * 3.0;
    let bookmark_bonus = if is_bookmark { 55.0 } else { 0.0 };

    // Smooth monotonic recency decay (half-life ~14 days, boosted for last 4h/24h/7d)
    let age_days = (age_secs as f64) / 86_400.0;
    let exp_decay = (-age_days / 20.0).exp();
    let bucket_mult = if age_secs <= 4 * 3600 {
        1.55
    } else if age_secs <= 86_400 {
        1.30
    } else if age_secs <= 7 * 86_400 {
        1.05
    } else if age_secs <= 30 * 86_400 {
        0.75
    } else if age_secs <= 90 * 86_400 {
        0.45
    } else {
        0.25
    };

    let recency_weight = 0.55 * bucket_mult + 0.45 * (0.2 + 1.3 * exp_decay);
    let raw = (freq_base + typed_bonus + 10.0) * recency_weight + bookmark_bonus;
    (raw * 100.0).round() / 100.0
}

// ============================================================================
// Scopes, Input Classifier & URL Display Segmenter (with IDN / Punycode)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OmniboxScope {
    Tabs,
    History,
    Bookmarks,
    Settings,
    Extensions,
}

impl OmniboxScope {
    pub fn display_label(self) -> &'static str {
        match self {
            Self::Tabs => "Tabs",
            Self::History => "History",
            Self::Bookmarks => "Bookmarks",
            Self::Settings => "Settings",
            Self::Extensions => "Extensions",
        }
    }

    pub fn prefix_token(self) -> &'static str {
        match self {
            Self::Tabs => "@tabs",
            Self::History => "@history",
            Self::Bookmarks => "@bookmarks",
            Self::Settings => "@settings",
            Self::Extensions => "@extensions",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OmniboxInputKind {
    InternalUrl { scheme: String, target: String },
    ViewSource { inner_url: String },
    DirectUrl { normalized_url: String },
    LocalHostOrIp { normalized_url: String },
    ScopedQuery { scope: OmniboxScope, query: String },
    BangQuery { bang: String, query: String },
    InstantAnswer { expression: String },
    SearchQuery { query: String },
}

/// Parses scope prefixes (`@tabs`, `%`, `@history`, `^`, `@bookmarks`, `*`, `@settings`, `@extensions`).
pub fn parse_scope_prefix(raw: &str) -> Option<(OmniboxScope, String)> {
    let trimmed = raw.trim_start();
    if trimmed.is_empty() {
        return None;
    }

    let single_char_scopes = [
        ('%', OmniboxScope::Tabs),
        ('^', OmniboxScope::History),
        ('*', OmniboxScope::Bookmarks),
    ];
    for (ch, scope) in single_char_scopes {
        if let Some(rest) = trimmed.strip_prefix(ch) {
            if rest.is_empty() || rest.starts_with(char::is_whitespace) {
                return Some((scope, rest.trim().to_string()));
            }
        }
    }

    if let Some(rest) = trimmed.strip_prefix('@') {
        let split_pos = rest
            .find(char::is_whitespace)
            .unwrap_or(rest.len());
        let token = rest[..split_pos].to_ascii_lowercase();
        let query = rest[split_pos..].trim().to_string();
        let scope = match token.as_str() {
            "tabs" | "tab" | "onglets" => Some(OmniboxScope::Tabs),
            "history" | "hist" | "historique" => Some(OmniboxScope::History),
            "bookmarks" | "bookmark" | "bm" | "favoris" => Some(OmniboxScope::Bookmarks),
            "settings" | "setting" | "config" | "parametres" => Some(OmniboxScope::Settings),
            "extensions" | "ext" | "addons" => Some(OmniboxScope::Extensions),
            _ => None,
        };
        if let Some(sc) = scope {
            return Some((sc, query));
        }
    }

    None
}

/// Classifies raw user input in the omnibox into a structured navigation or query kind.
pub fn classify_omnibox_input(raw: &str) -> OmniboxInputKind {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return OmniboxInputKind::SearchQuery {
            query: String::new(),
        };
    }

    let lower = trimmed.to_ascii_lowercase();

    // 1. view-source:
    if let Some(rest) = strip_ascii_prefix_ci(trimmed, "view-source:") {
        let inner = rest.trim();
        let normalized_inner = if inner.contains("://") {
            inner.to_string()
        } else if !inner.is_empty() {
            format!("https://{}", inner)
        } else {
            String::new()
        };
        return OmniboxInputKind::ViewSource {
            inner_url: normalized_inner,
        };
    }

    // 2. Internal URLs
    for scheme in ["singularity://", "about:", "chrome://", "file://", "edge://"] {
        if lower.starts_with(scheme) {
            let target = trimmed[scheme.len()..].to_string();
            return OmniboxInputKind::InternalUrl {
                scheme: scheme.trim_end_matches("://").trim_end_matches(':').to_string(),
                target,
            };
        }
    }

    // 3. Scoped queries
    if let Some((scope, query)) = parse_scope_prefix(trimmed) {
        return OmniboxInputKind::ScopedQuery { scope, query };
    }

    // 4. Explicit http:// or https://
    if lower.starts_with("http://") || lower.starts_with("https://") {
        let seg = segment_url_for_display(trimmed);
        if is_localhost_or_ip_host(&seg.display_host) {
            return OmniboxInputKind::LocalHostOrIp {
                normalized_url: trimmed.to_string(),
            };
        }
        return OmniboxInputKind::DirectUrl {
            normalized_url: trimmed.to_string(),
        };
    }

    // 5. Bare localhost or IPv4/IPv6 (with optional :port/path)
    if !trimmed.chars().any(char::is_whitespace) && looks_like_localhost_or_ip(trimmed) {
        return OmniboxInputKind::LocalHostOrIp {
            normalized_url: format!("http://{}", trimmed),
        };
    }

    // 6. Bang query (!w rust, rust !w)
    if let Some((bang, query)) = extract_bang_syntax(trimmed) {
        return OmniboxInputKind::BangQuery { bang, query };
    }

    // 7. Offline Instant Answer (calculator, unit, timezone, color, dev, FX)
    if evaluate_instant_answer(trimmed).is_some() {
        return OmniboxInputKind::InstantAnswer {
            expression: trimmed.to_string(),
        };
    }

    // 8. Bare domain / URL without scheme (e.g., rust-lang.org, docs.rs/serde)
    if !trimmed.chars().any(char::is_whitespace) && looks_like_domain_url(trimmed) {
        return OmniboxInputKind::DirectUrl {
            normalized_url: format!("https://{}", trimmed),
        };
    }

    // 9. Fallback: Search query
    OmniboxInputKind::SearchQuery {
        query: trimmed.to_string(),
    }
}

fn strip_ascii_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.len() >= prefix.len() && s.is_char_boundary(prefix.len())
        && s[..prefix.len()].eq_ignore_ascii_case(prefix)
    {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

fn is_valid_ipv4(host: &str) -> bool {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts
        .iter()
        .all(|p| !p.is_empty() && p.len() <= 3 && p.parse::<u8>().is_ok())
}

fn is_localhost_or_ip_host(host: &str) -> bool {
    let h = host.trim_start_matches('[').trim_end_matches(']').to_ascii_lowercase();
    if h == "localhost" || h.ends_with(".localhost") || h.ends_with(".local") {
        return true;
    }
    if is_valid_ipv4(&h) {
        return true;
    }
    // IPv6 check
    if h.contains(':') && h.chars().all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.') {
        return true;
    }
    false
}

fn looks_like_localhost_or_ip(s: &str) -> bool {
    let authority = s.split('/').next().unwrap_or(s);
    if authority.starts_with('[') {
        if let Some(end) = authority.find(']') {
            let host = &authority[1..end];
            let rest = &authority[end + 1..];
            let port_ok = rest.is_empty()
                || rest
                    .strip_prefix(':')
                    .and_then(|p| p.parse::<u16>().ok())
                    .is_some();
            return port_ok && is_localhost_or_ip_host(host);
        }
        return false;
    }
    let (host, port_opt) = match authority.rsplit_once(':') {
        Some((h, p)) if p.parse::<u16>().is_ok() => (h, Some(p)),
        _ => (authority, None),
    };
    let _ = port_opt;
    is_localhost_or_ip_host(host)
}

fn looks_like_domain_url(s: &str) -> bool {
    // Reject obvious arithmetic or decimals (e.g., "3.14", "1.5/2", "0.5")
    if s.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return false;
    }
    if s.starts_with('.') || s.starts_with('/') || s.starts_with('#') || s.starts_with('!') {
        return false;
    }
    // Reject email addresses
    let authority = s.split('/').next().unwrap_or(s).split('?').next().unwrap_or(s);
    if authority.contains('@') {
        return false;
    }
    let (host, has_valid_port) = match authority.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.parse::<u16>().is_ok() => (h, true),
        Some(_) => return false,
        None => (authority, false),
    };

    if host.is_empty() || !host.contains('.') {
        return false;
    }

    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 || labels.iter().any(|l| l.is_empty() || l.len() > 63) {
        return false;
    }
    for label in &labels {
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || !c.is_ascii())
        {
            return false;
        }
    }

    let tld = labels.last().copied().unwrap_or("").to_ascii_lowercase();
    if tld.len() < 2 || tld.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }

    // If it has a path or explicit port, accept any alpha TLD >= 2 chars
    if has_valid_port || s.contains('/') {
        return tld.chars().all(|c| c.is_ascii_alphabetic()) || tld.starts_with("xn--");
    }

    // Otherwise validate against common TLDs or 2-letter ccTLDs (excluding common file extensions
    // only if ambiguous; keep standard ccTLDs & popular gTLDs).
    const KNOWN_TLDS: &[&str] = &[
        "com", "org", "net", "edu", "gov", "mil", "int", "io", "dev", "app", "ai", "co", "me",
        "tv", "gg", "sh", "rs", "fm", "to", "cc", "xyz", "info", "biz", "pro", "tech", "cloud",
        "site", "online", "store", "blog", "news", "wiki", "page", "link", "live", "social",
        "space", "world", "design", "studio", "digital", "media", "systems", "network", "email",
        "fr", "uk", "de", "es", "it", "nl", "be", "ch", "ca", "au", "jp", "kr", "cn", "in", "br",
        "mx", "se", "no", "fi", "dk", "pl", "cz", "at", "pt", "ie", "nz", "sg", "hk", "tw", "eu",
        "ru", "ua", "tr", "za", "ar", "cl", "il", "ae", "sa", "onion", "i2p",
    ];
    KNOWN_TLDS.contains(&tld.as_str()) || tld.starts_with("xn--")
}

/// Segmented URL components suitable for visual emphasis in the omnibox bar
/// (dimming scheme/subdomain/path while highlighting `etld_plus_one`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UrlDisplaySegments {
    pub scheme: String,
    pub subdomain: String,
    pub etld_plus_one: String,
    pub port: Option<u16>,
    pub path: String,
    pub query_and_hash: String,
    pub is_idn_suspicious: bool,
    pub display_host: String,
}

/// Parses a URL into visual display segments and performs RFC 3492 Punycode decoding
/// plus IDN mixed-script / confusable homograph detection.
pub fn segment_url_for_display(raw_url: &str) -> UrlDisplaySegments {
    let trimmed = raw_url.trim();
    let (scheme, after_scheme) = if let Some(idx) = trimmed.find("://") {
        (trimmed[..idx].to_ascii_lowercase(), &trimmed[idx + 3..])
    } else if let Some(idx) = trimmed.find(':') {
        let maybe_scheme = &trimmed[..idx];
        if !maybe_scheme.is_empty()
            && maybe_scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.')
            && !maybe_scheme.contains('.')
            && trimmed[idx + 1..]
                .split('/')
                .next()
                .and_then(|p| p.parse::<u16>().ok())
                .is_none()
        {
            return UrlDisplaySegments {
                scheme: maybe_scheme.to_ascii_lowercase(),
                subdomain: String::new(),
                etld_plus_one: String::new(),
                port: None,
                path: trimmed[idx + 1..].to_string(),
                query_and_hash: String::new(),
                is_idn_suspicious: false,
                display_host: String::new(),
            };
        }
        (String::new(), trimmed)
    } else {
        (String::new(), trimmed)
    };

    // Split authority from path/query/hash
    let authority_end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let authority_raw = &after_scheme[..authority_end];
    let remainder = &after_scheme[authority_end..];

    let qh_start = remainder.find(['?', '#']).unwrap_or(remainder.len());
    let path = remainder[..qh_start].to_string();
    let query_and_hash = remainder[qh_start..].to_string();

    // Strip userinfo if present (user:pass@host)
    let host_port = match authority_raw.rsplit_once('@') {
        Some((_, hp)) => hp,
        None => authority_raw,
    };

    let (raw_host, port) = if host_port.starts_with('[') {
        if let Some(end) = host_port.find(']') {
            let h = &host_port[..=end];
            let p = host_port[end + 1..]
                .strip_prefix(':')
                .and_then(|s| s.parse::<u16>().ok());
            (h.to_string(), p)
        } else {
            (host_port.to_string(), None)
        }
    } else {
        match host_port.rsplit_once(':') {
            Some((h, p)) if p.parse::<u16>().is_ok() => (h.to_string(), p.parse::<u16>().ok()),
            _ => (host_port.to_string(), None),
        }
    };

    let (display_host, is_idn_suspicious) = analyze_idn_host(&raw_host);
    let (subdomain, etld_plus_one) = split_etld_plus_one(&display_host);

    UrlDisplaySegments {
        scheme,
        subdomain,
        etld_plus_one,
        port,
        path,
        query_and_hash,
        is_idn_suspicious,
        display_host,
    }
}

fn split_etld_plus_one(host: &str) -> (String, String) {
    if host.is_empty()
        || host.starts_with('[')
        || is_valid_ipv4(host)
        || !host.contains('.')
    {
        return (String::new(), host.to_string());
    }

    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() <= 2 {
        return (String::new(), host.to_string());
    }

    const MULTI_PART_SUFFIXES: &[&str] = &[
        "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "com.au", "net.au", "org.au",
        "edu.au", "co.jp", "ne.jp", "or.jp", "go.jp", "ac.jp", "com.br", "org.br", "gov.br",
        "gouv.fr", "asso.fr", "co.nz", "org.nz", "com.cn", "net.cn", "org.cn", "co.kr", "or.kr",
        "com.mx", "co.in", "org.in", "com.sg", "com.hk", "com.tw", "co.za", "com.tr", "com.ar",
        "co.il", "github.io", "pages.dev", "vercel.app", "netlify.app",
    ];

    let last_two = format!(
        "{}.{}",
        labels[labels.len() - 2].to_ascii_lowercase(),
        labels[labels.len() - 1].to_ascii_lowercase()
    );
    let suffix_len = if MULTI_PART_SUFFIXES.contains(&last_two.as_str()) {
        3
    } else {
        2
    };

    if labels.len() <= suffix_len {
        return (String::new(), host.to_string());
    }

    let split_at = labels.len() - suffix_len;
    let subdomain = labels[..split_at].join(".");
    let etld_plus_one = labels[split_at..].join(".");
    (subdomain, etld_plus_one)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum CharScript {
    Common,
    Latin,
    Cyrillic,
    Greek,
    Han,
    HiraganaKatakana,
    Hangul,
    Arabic,
    Hebrew,
    Devanagari,
    Other,
}

fn classify_char_script(c: char) -> CharScript {
    let cp = c as u32;
    match cp {
        0x002D | 0x0030..=0x0039 => CharScript::Common,
        0x0041..=0x005A | 0x0061..=0x007A | 0x00C0..=0x024F | 0x1E00..=0x1EFF => {
            CharScript::Latin
        }
        0x0400..=0x052F => CharScript::Cyrillic,
        0x0370..=0x03FF | 0x1F00..=0x1FFF => CharScript::Greek,
        0x4E00..=0x9FFF | 0x3400..=0x4DBF => CharScript::Han,
        0x3040..=0x30FF => CharScript::HiraganaKatakana,
        0xAC00..=0xD7AF | 0x1100..=0x11FF => CharScript::Hangul,
        0x0600..=0x06FF => CharScript::Arabic,
        0x0590..=0x05FF => CharScript::Hebrew,
        0x0900..=0x097F => CharScript::Devanagari,
        _ => CharScript::Other,
    }
}

fn is_invisible_or_bidi(c: char) -> bool {
    matches!(
        c as u32,
        0x00AD
            | 0x034F
            | 0x061C
            | 0x115F
            | 0x1160
            | 0x17B4
            | 0x17B5
            | 0x180E
            | 0x200B..=0x200F
            | 0x202A..=0x202E
            | 0x2060..=0x206F
            | 0xFEFF
    )
}

/// Checks if a Cyrillic/Greek character is a high-risk Latin homoglyph (skeleton confusable).
fn is_latin_confusable_cyrillic_or_greek(c: char) -> bool {
    matches!(
        c,
        // Cyrillic lookalikes for a, c, e, i, j, o, p, s, x, y, h, k, m, t, v, w
        'а' | 'с' | 'е' | 'і' | 'ј' | 'о' | 'р' | 'ѕ' | 'х' | 'у' | 'һ' | 'ӏ' | 'ԁ' | 'ɡ'
            | 'А' | 'В' | 'С' | 'Е' | 'Н' | 'І' | 'Ј' | 'К' | 'М' | 'О' | 'Р' | 'Ѕ' | 'Т' | 'Х'
            | 'Ү'
            // Greek lookalikes
            | 'α' | 'ο' | 'ρ' | 'ν' | 'ι' | 'κ' | 'τ' | 'χ' | 'Α' | 'Β' | 'Ε' | 'Ζ' | 'Η' | 'Ι'
            | 'Κ' | 'Μ' | 'Ν' | 'Ο' | 'Ρ' | 'Τ' | 'Υ' | 'Χ'
    )
}

/// Decodes a single RFC 3492 Punycode label (the part after `xn--`).
pub fn decode_punycode_label(encoded: &str) -> Option<String> {
    const BASE: u32 = 36;
    const TMIN: u32 = 1;
    const TMAX: u32 = 26;
    const SKEW: u32 = 38;
    const DAMP: u32 = 700;
    const INITIAL_BIAS: u32 = 72;
    const INITIAL_N: u32 = 128;

    fn adapt(mut delta: u32, num_points: u32, first_time: bool) -> u32 {
        delta = if first_time { delta / DAMP } else { delta / 2 };
        delta += delta / num_points;
        let mut k = 0u32;
        while delta > ((BASE - TMIN) * TMAX) / 2 {
            delta /= BASE - TMIN;
            k += BASE;
        }
        k + ((BASE - TMIN + 1) * delta) / (delta + SKEW)
    }

    fn decode_digit(b: u8) -> Option<u32> {
        match b {
            b'a'..=b'z' => Some((b - b'a') as u32),
            b'A'..=b'Z' => Some((b - b'A') as u32),
            b'0'..=b'9' => Some((b - b'0') as u32 + 26),
            _ => None,
        }
    }

    let bytes = encoded.as_bytes();
    let mut output: Vec<char> = Vec::new();
    let delim_pos = bytes.iter().rposition(|&b| b == b'-');
    let mut idx = if let Some(pos) = delim_pos {
        for &b in &bytes[..pos] {
            if b >= 0x80 {
                return None;
            }
            output.push(b as char);
        }
        pos + 1
    } else {
        0
    };

    let mut n = INITIAL_N;
    let mut i: u32 = 0;
    let mut bias = INITIAL_BIAS;

    while idx < bytes.len() {
        let old_i = i;
        let mut w: u32 = 1;
        let mut k = BASE;
        loop {
            if idx >= bytes.len() {
                return None;
            }
            let digit = decode_digit(bytes[idx])?;
            idx += 1;
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
        bias = adapt(i - old_i, out_len, old_i == 0);
        n = n.checked_add(i / out_len)?;
        i %= out_len;
        let ch = char::from_u32(n)?;
        output.insert(i as usize, ch);
        i += 1;
    }

    Some(output.into_iter().collect())
}

fn analyze_idn_host(raw_host: &str) -> (String, bool) {
    let lower_ascii = raw_host.to_ascii_lowercase();
    if lower_ascii.is_empty() {
        return (String::new(), false);
    }

    let mut decoded_labels = Vec::new();
    let mut suspicious = false;

    for label in lower_ascii.split('.') {
        let decoded = if let Some(puny) = label.strip_prefix("xn--") {
            match decode_punycode_label(puny) {
                Some(u) => u,
                None => {
                    suspicious = true;
                    label.to_string()
                }
            }
        } else {
            label.to_string()
        };

        if decoded.chars().any(is_invisible_or_bidi) {
            suspicious = true;
        }

        let mut scripts = HashSet::new();
        let mut cyr_or_greek_count = 0usize;
        let mut confusable_count = 0usize;

        for ch in decoded.chars() {
            let sc = classify_char_script(ch);
            if sc != CharScript::Common {
                scripts.insert(sc);
            }
            if sc == CharScript::Cyrillic || sc == CharScript::Greek {
                cyr_or_greek_count += 1;
                if is_latin_confusable_cyrillic_or_greek(ch) {
                    confusable_count += 1;
                }
            }
        }

        // Mixed-script detection (allowing Japanese Han + Kana + Latin or Hangul + Latin)
        if scripts.len() > 1 {
            let is_benign_cjk_latin = scripts.iter().all(|s| {
                matches!(
                    s,
                    CharScript::Latin
                        | CharScript::Han
                        | CharScript::HiraganaKatakana
                        | CharScript::Hangul
                )
            });
            if !is_benign_cjk_latin {
                suspicious = true;
            }
        }

        // Whole-script Cyrillic/Greek spoofing of Latin brand names (e.g. "аpple" or pure Cyrillic "аррӏе")
        if cyr_or_greek_count > 0 && confusable_count == cyr_or_greek_count {
            suspicious = true;
        }

        decoded_labels.push(decoded);
    }

    if suspicious {
        // Keep raw punycode ASCII visible when a homograph attack is suspected
        (lower_ascii, true)
    } else {
        (decoded_labels.join("."), false)
    }
}

// ============================================================================
// Quick Actions (EN / FR) & Tab-to-Search
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuickActionKind {
    ClearBrowsingData,
    OpenSettings,
    OpenExtensions,
    TogglePrivateMode,
    LockVault,
    OpenHistory,
    OpenBookmarks,
    OpenDownloads,
    SwitchTheme,
    ToggleMullvad,
    OpenFlags,
    OpenTaskManager,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuickActionMatch {
    pub kind: QuickActionKind,
    pub title: String,
    pub subtitle: String,
    pub score: i64,
}

struct QuickActionSpec {
    kind: QuickActionKind,
    title: &'static str,
    subtitle: &'static str,
    triggers: &'static [&'static str],
}

const QUICK_ACTIONS: &[QuickActionSpec] = &[
    QuickActionSpec {
        kind: QuickActionKind::ClearBrowsingData,
        title: "Clear Browsing Data",
        subtitle: "Effacer les données de navigation (historique, cache, cookies)",
        triggers: &[
            "clear browsing data",
            "clear history",
            "clear cache",
            "delete cookies",
            "effacer historique",
            "vider cache",
            "supprimer cookies",
            "nettoyer donnees",
        ],
    },
    QuickActionSpec {
        kind: QuickActionKind::OpenSettings,
        title: "Open Settings",
        subtitle: "Ouvrir les paramètres Singularity",
        triggers: &[
            "settings",
            "preferences",
            "options",
            "parametres",
            "reglages",
            "configuration",
        ],
    },
    QuickActionSpec {
        kind: QuickActionKind::OpenExtensions,
        title: "Manage Extensions",
        subtitle: "Gérer les extensions et modules complémentaires",
        triggers: &[
            "extensions",
            "addons",
            "plugins",
            "modules",
            "gerer extensions",
        ],
    },
    QuickActionSpec {
        kind: QuickActionKind::TogglePrivateMode,
        title: "New Private Window",
        subtitle: "Basculer / ouvrir une fenêtre de navigation privée",
        triggers: &[
            "private mode",
            "incognito",
            "private window",
            "navigation privee",
            "fenetre privee",
            "mode prive",
        ],
    },
    QuickActionSpec {
        kind: QuickActionKind::LockVault,
        title: "Lock Password Vault",
        subtitle: "Verrouiller immédiatement le coffre-fort Zero-Knowledge",
        triggers: &[
            "lock vault",
            "vault",
            "passwords",
            "verrouiller coffre",
            "coffre fort",
            "mots de passe",
        ],
    },
    QuickActionSpec {
        kind: QuickActionKind::OpenHistory,
        title: "Open History",
        subtitle: "Afficher l'historique et les parcours thématiques",
        triggers: &["open history", "history", "journeys", "historique", "parcours"],
    },
    QuickActionSpec {
        kind: QuickActionKind::OpenBookmarks,
        title: "Open Bookmarks Manager",
        subtitle: "Ouvrir le gestionnaire de favoris",
        triggers: &[
            "open bookmarks",
            "bookmarks",
            "favorites",
            "favoris",
            "marque pages",
        ],
    },
    QuickActionSpec {
        kind: QuickActionKind::OpenDownloads,
        title: "Open Downloads",
        subtitle: "Afficher les téléchargements récents",
        triggers: &["downloads", "telechargements", "open downloads"],
    },
    QuickActionSpec {
        kind: QuickActionKind::SwitchTheme,
        title: "Switch Theme",
        subtitle: "Changer de thème (OLED Pure Black, Ardoise, Clair...)",
        triggers: &[
            "switch theme",
            "dark mode",
            "light mode",
            "oled theme",
            "changer theme",
            "mode sombre",
            "mode clair",
            "theme",
        ],
    },
    QuickActionSpec {
        kind: QuickActionKind::ToggleMullvad,
        title: "Toggle Mullvad VPN",
        subtitle: "Activer ou désactiver le tunnel Mullvad WireGuard",
        triggers: &[
            "mullvad",
            "vpn",
            "toggle vpn",
            "toggle mullvad",
            "wireguard",
            "activer vpn",
            "couper vpn",
        ],
    },
    QuickActionSpec {
        kind: QuickActionKind::OpenFlags,
        title: "Open Experimental Flags",
        subtitle: "Ouvrir singularity://flags",
        triggers: &[
            "flags",
            "experiments",
            "experimental",
            "drapeaux",
            "experimentations",
        ],
    },
    QuickActionSpec {
        kind: QuickActionKind::OpenTaskManager,
        title: "Open Task Manager",
        subtitle: "Ouvrir le gestionnaire de tâches et ressources mémoire",
        triggers: &[
            "task manager",
            "processes",
            "memory",
            "cpu",
            "gestionnaire de taches",
            "processus",
        ],
    },
];

/// Matches bilingual EN/FR quick actions against the user's query.
pub fn match_quick_actions(query: &str) -> Vec<QuickActionMatch> {
    let trimmed = query.trim();
    if trimmed.len() < 2 {
        return Vec::new();
    }
    let normalized = fold_french_accents(&trimmed.to_lowercase());
    let mut matches = Vec::new();

    for spec in QUICK_ACTIONS {
        let mut best: Option<i64> = None;
        for trigger in spec.triggers {
            if let Some((sc, _)) = fuzzy_score(&normalized, trigger) {
                let adjusted = if trigger.starts_with(&normalized) {
                    sc + 40
                } else {
                    sc
                };
                if best.map_or(true, |b| adjusted > b) {
                    best = Some(adjusted);
                }
            }
        }
        if let Some((sc, _)) = fuzzy_score(&normalized, &fold_french_accents(&spec.title.to_lowercase()))
        {
            if best.map_or(true, |b| sc > b) {
                best = Some(sc);
            }
        }
        if let Some(score) = best {
            if score >= 35 {
                matches.push(QuickActionMatch {
                    kind: spec.kind,
                    title: spec.title.to_string(),
                    subtitle: spec.subtitle.to_string(),
                    score,
                });
            }
        }
    }

    matches.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.title.cmp(&b.title)));
    matches
}

fn fold_french_accents(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'à' | 'â' | 'ä' | 'á' => 'a',
            'é' | 'è' | 'ê' | 'ë' => 'e',
            'î' | 'ï' | 'í' => 'i',
            'ô' | 'ö' | 'ó' => 'o',
            'ù' | 'û' | 'ü' | 'ú' => 'u',
            'ç' => 'c',
            'ñ' => 'n',
            _ => c,
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TabToSearchHint {
    pub engine_id: String,
    pub engine_name: String,
    pub keyword: String,
    pub host: String,
    pub prompt_text: String,
}

// ============================================================================
// Search Engine Registry, OpenSearch XML, Suggestions & 115+ Local Bangs
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum SearchHttpMethod {
    Get,
    Post,
}

impl Default for SearchHttpMethod {
    fn default() -> Self {
        Self::Get
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchEngineEntry {
    pub id: String,
    pub name: String,
    pub keyword: String,
    pub search_url_template: String,
    #[serde(default)]
    pub suggest_url_template: Option<String>,
    #[serde(default)]
    pub method: SearchHttpMethod,
    #[serde(default)]
    pub post_params: Vec<(String, String)>,
    #[serde(default)]
    pub favicon_url: Option<String>,
    #[serde(default = "default_true")]
    pub show_in_one_off_bar: bool,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub is_builtin: bool,
    #[serde(default)]
    pub host: Option<String>,
}

fn default_true() -> bool {
    true
}

impl SearchEngineEntry {
    /// Expands `{searchTerms}` or `%s` placeholders using RFC 3986 percent-encoding.
    pub fn build_search_url(&self, query: &str) -> String {
        let encoded = percent_encode_query(query);
        substitute_search_template(&self.search_url_template, &encoded)
    }

    pub fn build_suggest_url(&self, query: &str) -> Option<String> {
        let tmpl = self.suggest_url_template.as_deref()?;
        let encoded = percent_encode_query(query);
        Some(substitute_search_template(tmpl, &encoded))
    }

    pub fn build_post_body(&self, query: &str) -> Vec<(String, String)> {
        self.post_params
            .iter()
            .map(|(k, v)| {
                let val = v.replace("{searchTerms}", query).replace("%s", query);
                (k.clone(), val)
            })
            .collect()
    }
}

fn substitute_search_template(template: &str, encoded_query: &str) -> String {
    if template.contains("{searchTerms}") {
        template.replace("{searchTerms}", encoded_query)
    } else if template.contains("%s") {
        template.replace("%s", encoded_query)
    } else {
        format!("{}{}", template, encoded_query)
    }
}

/// RFC 3986 percent-encoder for query parameters.
pub fn percent_encode_query(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 16);
    for b in input.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            b' ' => out.push_str("%20"),
            _ => {
                out.push('%');
                out.push(hex_nibble(b >> 4));
                out.push(hex_nibble(b & 0x0F));
            }
        }
    }
    out
}

fn hex_nibble(v: u8) -> char {
    match v {
        0..=9 => (b'0' + v) as char,
        10..=15 => (b'A' + (v - 10)) as char,
        _ => '0',
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchEngineRegistry {
    pub engines: Vec<SearchEngineEntry>,
    pub default_engine_id: String,
    pub default_private_engine_id: String,
}

impl Default for SearchEngineRegistry {
    fn default() -> Self {
        Self::with_builtins()
    }
}

impl SearchEngineRegistry {
    /// Creates a registry pre-populated with privacy-first and developer search engines.
    pub fn with_builtins() -> Self {
        let engines = vec![
            SearchEngineEntry {
                id: "duckduckgo".into(),
                name: "DuckDuckGo".into(),
                keyword: "ddg".into(),
                search_url_template: "https://duckduckgo.com/?q={searchTerms}".into(),
                suggest_url_template: Some("https://duckduckgo.com/ac/?q={searchTerms}&type=list".into()),
                method: SearchHttpMethod::Get,
                post_params: Vec::new(),
                favicon_url: Some("https://duckduckgo.com/favicon.ico".into()),
                show_in_one_off_bar: true,
                enabled: true,
                is_builtin: true,
                host: Some("duckduckgo.com".into()),
            },
            SearchEngineEntry {
                id: "startpage".into(),
                name: "Startpage".into(),
                keyword: "sp".into(),
                search_url_template: "https://www.startpage.com/sp/search?query={searchTerms}".into(),
                suggest_url_template: Some("https://www.startpage.com/osuggestions?q={searchTerms}".into()),
                method: SearchHttpMethod::Get,
                post_params: Vec::new(),
                favicon_url: Some("https://www.startpage.com/favicon.ico".into()),
                show_in_one_off_bar: true,
                enabled: true,
                is_builtin: true,
                host: Some("startpage.com".into()),
            },
            SearchEngineEntry {
                id: "brave".into(),
                name: "Brave Search".into(),
                keyword: "br".into(),
                search_url_template: "https://search.brave.com/search?q={searchTerms}".into(),
                suggest_url_template: Some("https://search.brave.com/api/suggest?q={searchTerms}".into()),
                method: SearchHttpMethod::Get,
                post_params: Vec::new(),
                favicon_url: Some("https://search.brave.com/favicon.ico".into()),
                show_in_one_off_bar: true,
                enabled: true,
                is_builtin: true,
                host: Some("search.brave.com".into()),
            },
            SearchEngineEntry {
                id: "qwant".into(),
                name: "Qwant".into(),
                keyword: "qw".into(),
                search_url_template: "https://www.qwant.com/?q={searchTerms}".into(),
                suggest_url_template: Some("https://api.qwant.com/v3/suggest?q={searchTerms}".into()),
                method: SearchHttpMethod::Get,
                post_params: Vec::new(),
                favicon_url: Some("https://www.qwant.com/favicon.ico".into()),
                show_in_one_off_bar: true,
                enabled: true,
                is_builtin: true,
                host: Some("qwant.com".into()),
            },
            SearchEngineEntry {
                id: "google".into(),
                name: "Google".into(),
                keyword: "g".into(),
                search_url_template: "https://www.google.com/search?q={searchTerms}".into(),
                suggest_url_template: Some("https://suggestqueries.google.com/complete/search?client=firefox&q={searchTerms}".into()),
                method: SearchHttpMethod::Get,
                post_params: Vec::new(),
                favicon_url: Some("https://www.google.com/favicon.ico".into()),
                show_in_one_off_bar: true,
                enabled: true,
                is_builtin: true,
                host: Some("google.com".into()),
            },
            SearchEngineEntry {
                id: "wikipedia".into(),
                name: "Wikipedia".into(),
                keyword: "w".into(),
                search_url_template: "https://en.wikipedia.org/wiki/Special:Search?search={searchTerms}".into(),
                suggest_url_template: Some("https://en.wikipedia.org/w/api.php?action=opensearch&search={searchTerms}".into()),
                method: SearchHttpMethod::Get,
                post_params: Vec::new(),
                favicon_url: Some("https://en.wikipedia.org/favicon.ico".into()),
                show_in_one_off_bar: true,
                enabled: true,
                is_builtin: true,
                host: Some("wikipedia.org".into()),
            },
            SearchEngineEntry {
                id: "youtube".into(),
                name: "YouTube".into(),
                keyword: "yt".into(),
                search_url_template: "https://www.youtube.com/results?search_query={searchTerms}".into(),
                suggest_url_template: None,
                method: SearchHttpMethod::Get,
                post_params: Vec::new(),
                favicon_url: Some("https://www.youtube.com/favicon.ico".into()),
                show_in_one_off_bar: true,
                enabled: true,
                is_builtin: true,
                host: Some("youtube.com".into()),
            },
            SearchEngineEntry {
                id: "github".into(),
                name: "GitHub".into(),
                keyword: "gh".into(),
                search_url_template: "https://github.com/search?q={searchTerms}".into(),
                suggest_url_template: None,
                method: SearchHttpMethod::Get,
                post_params: Vec::new(),
                favicon_url: Some("https://github.com/favicon.ico".into()),
                show_in_one_off_bar: true,
                enabled: true,
                is_builtin: true,
                host: Some("github.com".into()),
            },
            SearchEngineEntry {
                id: "crates".into(),
                name: "crates.io".into(),
                keyword: "crates".into(),
                search_url_template: "https://crates.io/search?q={searchTerms}".into(),
                suggest_url_template: None,
                method: SearchHttpMethod::Get,
                post_params: Vec::new(),
                favicon_url: Some("https://crates.io/favicon.ico".into()),
                show_in_one_off_bar: false,
                enabled: true,
                is_builtin: true,
                host: Some("crates.io".into()),
            },
            SearchEngineEntry {
                id: "mdn".into(),
                name: "MDN Web Docs".into(),
                keyword: "mdn".into(),
                search_url_template: "https://developer.mozilla.org/en-US/search?q={searchTerms}".into(),
                suggest_url_template: None,
                method: SearchHttpMethod::Get,
                post_params: Vec::new(),
                favicon_url: Some("https://developer.mozilla.org/favicon.ico".into()),
                show_in_one_off_bar: false,
                enabled: true,
                is_builtin: true,
                host: Some("developer.mozilla.org".into()),
            },
            SearchEngineEntry {
                id: "kagi".into(),
                name: "Kagi".into(),
                keyword: "kagi".into(),
                search_url_template: "https://kagi.com/search?q={searchTerms}".into(),
                suggest_url_template: Some("https://kagi.com/api/autosuggest?q={searchTerms}".into()),
                method: SearchHttpMethod::Get,
                post_params: Vec::new(),
                favicon_url: Some("https://kagi.com/favicon.ico".into()),
                show_in_one_off_bar: false,
                enabled: true,
                is_builtin: true,
                host: Some("kagi.com".into()),
            },
            SearchEngineEntry {
                id: "ecosia".into(),
                name: "Ecosia".into(),
                keyword: "eco".into(),
                search_url_template: "https://www.ecosia.org/search?q={searchTerms}".into(),
                suggest_url_template: None,
                method: SearchHttpMethod::Get,
                post_params: Vec::new(),
                favicon_url: Some("https://www.ecosia.org/favicon.ico".into()),
                show_in_one_off_bar: false,
                enabled: true,
                is_builtin: true,
                host: Some("ecosia.org".into()),
            },
        ];

        Self {
            engines,
            default_engine_id: "duckduckgo".into(),
            default_private_engine_id: "startpage".into(),
        }
    }

    pub fn add_engine(&mut self, mut entry: SearchEngineEntry) -> Result<(), OmniboxError> {
        if self.engines.iter().any(|e| e.id == entry.id) {
            return Err(OmniboxError::EngineAlreadyExists(entry.id));
        }
        if entry.host.is_none() {
            let seg = segment_url_for_display(&entry.search_url_template);
            if !seg.etld_plus_one.is_empty() {
                entry.host = Some(seg.display_host);
            }
        }
        self.engines.push(entry);
        Ok(())
    }

    pub fn update_engine(&mut self, updated: SearchEngineEntry) -> Result<(), OmniboxError> {
        let slot = self
            .engines
            .iter_mut()
            .find(|e| e.id == updated.id)
            .ok_or_else(|| OmniboxError::EngineNotFound(updated.id.clone()))?;
        *slot = updated;
        Ok(())
    }

    pub fn remove_engine(&mut self, id: &str) -> Result<SearchEngineEntry, OmniboxError> {
        if id == self.default_engine_id || id == self.default_private_engine_id {
            return Err(OmniboxError::CannotDeleteDefaultEngine(id.to_string()));
        }
        let pos = self
            .engines
            .iter()
            .position(|e| e.id == id)
            .ok_or_else(|| OmniboxError::EngineNotFound(id.to_string()))?;
        Ok(self.engines.remove(pos))
    }

    pub fn get_engine(&self, id: &str) -> Option<&SearchEngineEntry> {
        self.engines.iter().find(|e| e.id == id)
    }

    pub fn set_default_engine(&mut self, id: &str, private: bool) -> Result<(), OmniboxError> {
        if !self.engines.iter().any(|e| e.id == id && e.enabled) {
            return Err(OmniboxError::EngineNotFound(id.to_string()));
        }
        if private {
            self.default_private_engine_id = id.to_string();
        } else {
            self.default_engine_id = id.to_string();
        }
        Ok(())
    }

    pub fn default_engine(&self, is_private: bool) -> Option<&SearchEngineEntry> {
        let target_id = if is_private {
            &self.default_private_engine_id
        } else {
            &self.default_engine_id
        };
        self.engines
            .iter()
            .find(|e| e.id == *target_id && e.enabled)
            .or_else(|| self.engines.iter().find(|e| e.enabled))
    }

    pub fn one_off_engines(&self) -> Vec<&SearchEngineEntry> {
        self.engines
            .iter()
            .filter(|e| e.enabled && e.show_in_one_off_bar)
            .collect()
    }

    pub fn find_by_keyword(&self, keyword: &str) -> Option<&SearchEngineEntry> {
        let kw = keyword.trim().to_ascii_lowercase();
        self.engines
            .iter()
            .find(|e| e.enabled && e.keyword.eq_ignore_ascii_case(&kw))
    }

    pub fn find_tab_to_search_hint(&self, input: &str) -> Option<TabToSearchHint> {
        let trimmed = input.trim().to_ascii_lowercase();
        if trimmed.len() < 2 || trimmed.contains(char::is_whitespace) {
            return None;
        }
        let stripped = trimmed
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_start_matches("www.");

        for engine in &self.engines {
            if !engine.enabled {
                continue;
            }
            let kw_match = engine.keyword.eq_ignore_ascii_case(stripped);
            let host_match = engine.host.as_deref().map_or(false, |h| {
                let hl = h.to_ascii_lowercase();
                let h_bare = hl.trim_start_matches("www.");
                h_bare == stripped
                    || (stripped.len() >= 3 && h_bare.starts_with(stripped))
                    || engine.name.to_ascii_lowercase() == stripped
            });
            if kw_match || host_match {
                return Some(TabToSearchHint {
                    engine_id: engine.id.clone(),
                    engine_name: engine.name.clone(),
                    keyword: engine.keyword.clone(),
                    host: engine.host.clone().unwrap_or_default(),
                    prompt_text: format!("Press Tab to search {}", engine.name),
                });
            }
        }
        None
    }

    pub fn build_search_url(&self, query: &str, is_private: bool) -> String {
        if let Some(engine) = self.default_engine(is_private) {
            engine.build_search_url(query)
        } else {
            format!("https://duckduckgo.com/?q={}", percent_encode_query(query))
        }
    }

    /// Resolves a bang trigger against custom registered keywords first, then the 115+ built-in bangs.
    pub fn resolve_bang(&self, bang: &str, query: &str) -> Option<(String, String)> {
        let trigger = bang.trim_start_matches('!').to_ascii_lowercase();
        if let Some(engine) = self.find_by_keyword(&trigger) {
            return Some((engine.name.clone(), engine.build_search_url(query)));
        }
        if let Some(def) = lookup_bang(&trigger) {
            let encoded = percent_encode_query(query);
            let url = substitute_search_template(def.url_template, &encoded);
            return Some((def.name.to_string(), url));
        }
        None
    }
}

/// Safe pure-Rust OpenSearch 1.1 XML description parser (`<OpenSearchDescription>`).
///
/// Rejects XXE / DOCTYPE entity expansion, enforces bounded size, and extracts `ShortName`,
/// `text/html` search URL template (GET/POST + `<Param>`), `application/x-suggestions+json`
/// suggest URL template, and `<Image>` favicon.
pub fn parse_opensearch_xml(xml: &str) -> Result<SearchEngineEntry, OmniboxError> {
    if xml.len() > 256 * 1024 {
        return Err(OmniboxError::InvalidOpenSearchXml(
            "OpenSearch document exceeds 256 KiB limit".into(),
        ));
    }
    let upper = xml.to_ascii_uppercase();
    if upper.contains("<!ENTITY") || upper.contains("<!DOCTYPE") {
        return Err(OmniboxError::InvalidOpenSearchXml(
            "DOCTYPE/ENTITY declarations are rejected for security".into(),
        ));
    }

    let short_name = extract_xml_tag_text(xml, "ShortName")
        .map(|s| decode_xml_entities(s.trim()))
        .filter(|s| !s.is_empty())
        .ok_or_else(|| OmniboxError::InvalidOpenSearchXml("missing <ShortName>".into()))?;

    let mut search_template: Option<String> = None;
    let mut suggest_template: Option<String> = None;
    let mut method = SearchHttpMethod::Get;
    let mut post_params: Vec<(String, String)> = Vec::new();

    // Scan all <Url ...> tags (self-closing or container with <Param .../>)
    let mut cursor = 0usize;
    while let Some(rel_start) = find_xml_open_tag(&xml[cursor..], "Url") {
        let tag_start = cursor + rel_start;
        let Some(rel_end) = xml[tag_start..].find('>') else {
            break;
        };
        let open_tag_end = tag_start + rel_end;
        let open_tag = &xml[tag_start..=open_tag_end];
        let self_closing = open_tag.ends_with("/>");

        let url_type = extract_xml_attr(open_tag, "type")
            .unwrap_or_default()
            .to_ascii_lowercase();
        let template = extract_xml_attr(open_tag, "template")
            .map(|s| decode_xml_entities(&s));
        let attr_method = extract_xml_attr(open_tag, "method")
            .unwrap_or_else(|| "GET".to_string());

        let mut inner_params = Vec::new();
        let next_cursor = if self_closing {
            open_tag_end + 1
        } else if let Some(rel_close) = find_xml_close_tag(&xml[open_tag_end + 1..], "Url") {
            let body = &xml[open_tag_end + 1..open_tag_end + 1 + rel_close];
            let mut pcur = 0usize;
            while let Some(ps) = find_xml_open_tag(&body[pcur..], "Param") {
                let p_abs = pcur + ps;
                if let Some(pe) = body[p_abs..].find('>') {
                    let ptag = &body[p_abs..=p_abs + pe];
                    if let (Some(k), Some(v)) = (
                        extract_xml_attr(ptag, "name"),
                        extract_xml_attr(ptag, "value"),
                    ) {
                        inner_params.push((decode_xml_entities(&k), decode_xml_entities(&v)));
                    }
                    pcur = p_abs + pe + 1;
                } else {
                    break;
                }
            }
            open_tag_end + 1 + rel_close + 6
        } else {
            open_tag_end + 1
        };

        if let Some(tmpl) = template {
            if is_safe_http_template(&tmpl) {
                if url_type.contains("x-suggestions+json") || url_type.contains("suggestions+json")
                {
                    if suggest_template.is_none() {
                        suggest_template = Some(tmpl);
                    }
                } else if (url_type.is_empty() || url_type.contains("text/html"))
                    && search_template.is_none()
                {
                    search_template = Some(tmpl);
                    method = if attr_method.eq_ignore_ascii_case("POST") {
                        SearchHttpMethod::Post
                    } else {
                        SearchHttpMethod::Get
                    };
                    post_params = inner_params;
                }
            }
        }

        cursor = next_cursor.min(xml.len());
    }

    let search_url_template = search_template.ok_or_else(|| {
        OmniboxError::InvalidOpenSearchXml("missing valid http(s) <Url type=\"text/html\">".into())
    })?;

    let favicon_url = extract_xml_tag_text(xml, "Image")
        .map(|s| decode_xml_entities(s.trim()))
        .filter(|u| is_safe_http_template(u));

    let seg = segment_url_for_display(&search_url_template);
    let slug: String = short_name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .take(24)
        .collect();
    let id = if slug.is_empty() {
        "custom_engine".to_string()
    } else {
        slug.clone()
    };
    let keyword = slug.chars().take(6).collect();

    Ok(SearchEngineEntry {
        id,
        name: short_name,
        keyword,
        search_url_template,
        suggest_url_template: suggest_template,
        method,
        post_params,
        favicon_url,
        show_in_one_off_bar: true,
        enabled: true,
        is_builtin: false,
        host: if seg.display_host.is_empty() {
            None
        } else {
            Some(seg.display_host)
        },
    })
}

fn is_safe_http_template(url: &str) -> bool {
    let l = url.trim().to_ascii_lowercase();
    l.starts_with("https://") || l.starts_with("http://")
}

fn find_xml_open_tag(haystack: &str, tag_name: &str) -> Option<usize> {
    let bytes = haystack.as_bytes();
    let needle = tag_name.as_bytes();
    let mut i = 0;
    while i + needle.len() + 1 < bytes.len() {
        if bytes[i] == b'<' {
            let after = &bytes[i + 1..];
            // Support optional namespace prefix like os:Url
            let match_at = if after.len() >= needle.len()
                && after[..needle.len()].eq_ignore_ascii_case(needle)
            {
                Some(needle.len())
            } else if let Some(colon) = after
                .iter()
                .take(16)
                .position(|&b| b == b':')
            {
                let rest = &after[colon + 1..];
                if rest.len() >= needle.len() && rest[..needle.len()].eq_ignore_ascii_case(needle)
                {
                    Some(colon + 1 + needle.len())
                } else {
                    None
                }
            } else {
                None
            };
            if let Some(end_offset) = match_at {
                let next_b = after.get(end_offset).copied().unwrap_or(b' ');
                if matches!(next_b, b' ' | b'\t' | b'\r' | b'\n' | b'>' | b'/') {
                    return Some(i);
                }
            }
        }
        i += 1;
    }
    None
}

fn find_xml_close_tag(haystack: &str, tag_name: &str) -> Option<usize> {
    let lower = haystack.to_ascii_lowercase();
    let target = format!("</{}>", tag_name.to_ascii_lowercase());
    if let Some(pos) = lower.find(&target) {
        return Some(pos);
    }
    // Also check namespace-prefixed close tags like </os:ShortName>
    let suff = format!(":{}>", tag_name.to_ascii_lowercase());
    if let Some(pos) = lower.find(&suff) {
        if let Some(open) = lower[..pos].rfind("</") {
            return Some(open);
        }
    }
    None
}

fn extract_xml_tag_text<'a>(xml: &'a str, tag_name: &str) -> Option<&'a str> {
    let start = find_xml_open_tag(xml, tag_name)?;
    let open_end = start + xml[start..].find('>')?;
    if xml[start..=open_end].ends_with("/>") {
        return Some("");
    }
    let body = &xml[open_end + 1..];
    let close_rel = find_xml_close_tag(body, tag_name)?;
    Some(&body[..close_rel])
}

fn extract_xml_attr(tag: &str, attr_name: &str) -> Option<String> {
    let lower_tag = tag.to_ascii_lowercase();
    let lower_attr = attr_name.to_ascii_lowercase();
    let bytes = lower_tag.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if let Some(pos) = lower_tag[i..].find(&lower_attr) {
            let abs = i + pos;
            let before_ok = abs == 0
                || matches!(bytes[abs - 1], b' ' | b'\t' | b'\r' | b'\n');
            let after_idx = abs + lower_attr.len();
            if before_ok && after_idx < bytes.len() {
                let mut eq = after_idx;
                while eq < bytes.len() && bytes[eq].is_ascii_whitespace() {
                    eq += 1;
                }
                if eq < bytes.len() && bytes[eq] == b'=' {
                    eq += 1;
                    while eq < bytes.len() && bytes[eq].is_ascii_whitespace() {
                        eq += 1;
                    }
                    if eq < bytes.len() && (bytes[eq] == b'"' || bytes[eq] == b'\'') {
                        let quote = bytes[eq];
                        let val_start = eq + 1;
                        if let Some(rel_end) = tag[val_start..].find(quote as char) {
                            return Some(tag[val_start..val_start + rel_end].to_string());
                        }
                    }
                }
            }
            i = after_idx;
        } else {
            break;
        }
    }
    None
}

fn decode_xml_entities(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let after = &rest[amp + 1..];
        if let Some(semi) = after.find(';') {
            let entity = &after[..semi];
            match entity {
                "amp" => out.push('&'),
                "lt" => out.push('<'),
                "gt" => out.push('>'),
                "quot" => out.push('"'),
                "apos" => out.push('\''),
                _ if entity.starts_with("#x") || entity.starts_with("#X") => {
                    if let Some(ch) = u32::from_str_radix(&entity[2..], 16)
                        .ok()
                        .and_then(char::from_u32)
                    {
                        out.push(ch);
                    }
                }
                _ if entity.starts_with('#') => {
                    if let Some(ch) = entity[1..].parse::<u32>().ok().and_then(char::from_u32) {
                        out.push(ch);
                    }
                }
                _ => {
                    out.push('&');
                    out.push_str(entity);
                    out.push(';');
                }
            }
            rest = &after[semi + 1..];
        } else {
            out.push('&');
            rest = after;
        }
    }
    out.push_str(rest);
    out
}

/// Parses search suggestions from OpenSearch JSON (`["query", ["s1", "s2"]]`),
/// DuckDuckGo autocomplete JSON (`[{"phrase": "s1"}]`), or Qwant JSON (`{"data": {"items": [{"value": "s1"}]}}`).
pub fn parse_search_suggestions_json(raw_json: &str) -> Vec<String> {
    let Ok(val) = serde_json::from_str::<serde_json::Value>(raw_json) else {
        return Vec::new();
    };
    let mut out = Vec::new();

    match val {
        serde_json::Value::Array(arr) => {
            // OpenSearch JSON format: ["query", ["suggestion1", "suggestion2", ...]]
            if arr.len() >= 2 && arr[0].is_string() {
                if let Some(list) = arr[1].as_array() {
                    for item in list {
                        if let Some(s) = item.as_str() {
                            push_unique_suggestion(&mut out, s);
                        }
                    }
                    return out;
                }
            }
            // DuckDuckGo format: [{"phrase": "..."}, ...]
            for item in arr {
                if let Some(phrase) = item.get("phrase").and_then(|v| v.as_str()) {
                    push_unique_suggestion(&mut out, phrase);
                } else if let Some(s) = item.as_str() {
                    push_unique_suggestion(&mut out, s);
                }
            }
        }
        serde_json::Value::Object(obj) => {
            // Qwant format: {"data": {"items": [{"value": "..."}]}}
            if let Some(items) = obj
                .get("data")
                .and_then(|d| d.get("items"))
                .and_then(|i| i.as_array())
            {
                for item in items {
                    if let Some(v) = item.get("value").and_then(|x| x.as_str()) {
                        push_unique_suggestion(&mut out, v);
                    }
                }
            } else if let Some(list) = obj.get("suggestions").and_then(|s| s.as_array()) {
                for item in list {
                    if let Some(s) = item.as_str() {
                        push_unique_suggestion(&mut out, s);
                    }
                }
            }
        }
        _ => {}
    }

    out
}

fn push_unique_suggestion(out: &mut Vec<String>, raw: &str) {
    let cleaned = raw.trim();
    if cleaned.is_empty() || out.len() >= 12 {
        return;
    }
    if !out.iter().any(|x| x.eq_ignore_ascii_case(cleaned)) {
        out.push(cleaned.to_string());
    }
}

/// Local offline Bang definition (e.g., `!w`, `!gh`, `!rs`, `!yt`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct BangDefinition {
    pub trigger: &'static str,
    pub name: &'static str,
    pub category: &'static str,
    pub url_template: &'static str,
}

/// Built-in offline catalog of 116 high-utility Bangs across Search, Knowledge, Dev, Media, Maps,
/// Translation, Shopping, Social, and Security/Web tools.
pub const BUILTIN_BANGS: &[BangDefinition] = &[
    // --- General Search ---
    BangDefinition { trigger: "g", name: "Google", category: "Search", url_template: "https://www.google.com/search?q={searchTerms}" },
    BangDefinition { trigger: "ddg", name: "DuckDuckGo", category: "Search", url_template: "https://duckduckgo.com/?q={searchTerms}" },
    BangDefinition { trigger: "br", name: "Brave Search", category: "Search", url_template: "https://search.brave.com/search?q={searchTerms}" },
    BangDefinition { trigger: "sp", name: "Startpage", category: "Search", url_template: "https://www.startpage.com/sp/search?query={searchTerms}" },
    BangDefinition { trigger: "qw", name: "Qwant", category: "Search", url_template: "https://www.qwant.com/?q={searchTerms}" },
    BangDefinition { trigger: "bing", name: "Bing", category: "Search", url_template: "https://www.bing.com/search?q={searchTerms}" },
    BangDefinition { trigger: "eco", name: "Ecosia", category: "Search", url_template: "https://www.ecosia.org/search?q={searchTerms}" },
    BangDefinition { trigger: "kagi", name: "Kagi", category: "Search", url_template: "https://kagi.com/search?q={searchTerms}" },
    BangDefinition { trigger: "ya", name: "Yandex", category: "Search", url_template: "https://yandex.com/search/?text={searchTerms}" },
    BangDefinition { trigger: "gi", name: "Google Images", category: "Search", url_template: "https://www.google.com/search?tbm=isch&q={searchTerms}" },
    BangDefinition { trigger: "gn", name: "Google News", category: "Search", url_template: "https://news.google.com/search?q={searchTerms}" },
    BangDefinition { trigger: "perplexity", name: "Perplexity", category: "Search", url_template: "https://www.perplexity.ai/search?q={searchTerms}" },
    BangDefinition { trigger: "mj", name: "Mojeek", category: "Search", url_template: "https://www.mojeek.com/search?q={searchTerms}" },
    // --- Knowledge & Reference ---
    BangDefinition { trigger: "w", name: "Wikipedia (EN)", category: "Knowledge", url_template: "https://en.wikipedia.org/wiki/Special:Search?search={searchTerms}" },
    BangDefinition { trigger: "wen", name: "Wikipedia (EN)", category: "Knowledge", url_template: "https://en.wikipedia.org/wiki/Special:Search?search={searchTerms}" },
    BangDefinition { trigger: "wf", name: "Wikipédia (FR)", category: "Knowledge", url_template: "https://fr.wikipedia.org/wiki/Special:Search?search={searchTerms}" },
    BangDefinition { trigger: "wfr", name: "Wikipédia (FR)", category: "Knowledge", url_template: "https://fr.wikipedia.org/wiki/Special:Search?search={searchTerms}" },
    BangDefinition { trigger: "wde", name: "Wikipedia (DE)", category: "Knowledge", url_template: "https://de.wikipedia.org/wiki/Spezial:Suche?search={searchTerms}" },
    BangDefinition { trigger: "wes", name: "Wikipedia (ES)", category: "Knowledge", url_template: "https://es.wikipedia.org/wiki/Especial:Buscar?search={searchTerms}" },
    BangDefinition { trigger: "wp", name: "Wikipedia", category: "Knowledge", url_template: "https://en.wikipedia.org/wiki/Special:Search?search={searchTerms}" },
    BangDefinition { trigger: "wikt", name: "Wiktionary", category: "Knowledge", url_template: "https://en.wiktionary.org/wiki/Special:Search?search={searchTerms}" },
    BangDefinition { trigger: "wa", name: "Wolfram|Alpha", category: "Knowledge", url_template: "https://www.wolframalpha.com/input?i={searchTerms}" },
    BangDefinition { trigger: "arxiv", name: "arXiv", category: "Knowledge", url_template: "https://arxiv.org/search/?query={searchTerms}&searchtype=all" },
    BangDefinition { trigger: "scholar", name: "Google Scholar", category: "Knowledge", url_template: "https://scholar.google.com/scholar?q={searchTerms}" },
    BangDefinition { trigger: "pubmed", name: "PubMed", category: "Knowledge", url_template: "https://pubmed.ncbi.nlm.nih.gov/?term={searchTerms}" },
    BangDefinition { trigger: "doi", name: "DOI Resolver", category: "Knowledge", url_template: "https://doi.org/{searchTerms}" },
    BangDefinition { trigger: "oeis", name: "OEIS", category: "Knowledge", url_template: "https://oeis.org/search?q={searchTerms}" },
    BangDefinition { trigger: "eb", name: "Britannica", category: "Knowledge", url_template: "https://www.britannica.com/search?query={searchTerms}" },
    BangDefinition { trigger: "goodreads", name: "Goodreads", category: "Knowledge", url_template: "https://www.goodreads.com/search?q={searchTerms}" },
    // --- Development & Programming ---
    BangDefinition { trigger: "gh", name: "GitHub", category: "Dev", url_template: "https://github.com/search?q={searchTerms}" },
    BangDefinition { trigger: "ghc", name: "GitHub Code", category: "Dev", url_template: "https://github.com/search?type=code&q={searchTerms}" },
    BangDefinition { trigger: "gl", name: "GitLab", category: "Dev", url_template: "https://gitlab.com/search?search={searchTerms}" },
    BangDefinition { trigger: "rs", name: "Rust std docs", category: "Dev", url_template: "https://doc.rust-lang.org/std/?search={searchTerms}" },
    BangDefinition { trigger: "docsrs", name: "docs.rs", category: "Dev", url_template: "https://docs.rs/releases/search?query={searchTerms}" },
    BangDefinition { trigger: "crates", name: "crates.io", category: "Dev", url_template: "https://crates.io/search?q={searchTerms}" },
    BangDefinition { trigger: "lib", name: "lib.rs", category: "Dev", url_template: "https://lib.rs/search?q={searchTerms}" },
    BangDefinition { trigger: "mdn", name: "MDN Web Docs", category: "Dev", url_template: "https://developer.mozilla.org/en-US/search?q={searchTerms}" },
    BangDefinition { trigger: "so", name: "Stack Overflow", category: "Dev", url_template: "https://stackoverflow.com/search?q={searchTerms}" },
    BangDefinition { trigger: "npm", name: "npm", category: "Dev", url_template: "https://www.npmjs.com/search?q={searchTerms}" },
    BangDefinition { trigger: "pypi", name: "PyPI", category: "Dev", url_template: "https://pypi.org/search/?q={searchTerms}" },
    BangDefinition { trigger: "py", name: "Python Docs", category: "Dev", url_template: "https://docs.python.org/3/search.html?q={searchTerms}" },
    BangDefinition { trigger: "go", name: "pkg.go.dev", category: "Dev", url_template: "https://pkg.go.dev/search?q={searchTerms}" },
    BangDefinition { trigger: "cpp", name: "cppreference", category: "Dev", url_template: "https://en.cppreference.com/mwiki/index.php?search={searchTerms}" },
    BangDefinition { trigger: "ts", name: "TypeScript Docs", category: "Dev", url_template: "https://www.typescriptlang.org/search?q={searchTerms}" },
    BangDefinition { trigger: "arch", name: "Arch Wiki", category: "Dev", url_template: "https://wiki.archlinux.org/index.php?search={searchTerms}" },
    BangDefinition { trigger: "aur", name: "Arch AUR", category: "Dev", url_template: "https://aur.archlinux.org/packages?K={searchTerms}" },
    BangDefinition { trigger: "nix", name: "NixOS Packages", category: "Dev", url_template: "https://search.nixos.org/packages?query={searchTerms}" },
    BangDefinition { trigger: "nixopt", name: "NixOS Options", category: "Dev", url_template: "https://search.nixos.org/options?query={searchTerms}" },
    BangDefinition { trigger: "deb", name: "Debian Packages", category: "Dev", url_template: "https://packages.debian.org/search?keywords={searchTerms}" },
    BangDefinition { trigger: "ubuntu", name: "Ubuntu Packages", category: "Dev", url_template: "https://packages.ubuntu.com/search?keywords={searchTerms}" },
    BangDefinition { trigger: "brew", name: "Homebrew Formulae", category: "Dev", url_template: "https://formulae.brew.sh/formula/{searchTerms}" },
    BangDefinition { trigger: "docker", name: "Docker Hub", category: "Dev", url_template: "https://hub.docker.com/search?q={searchTerms}" },
    BangDefinition { trigger: "k8s", name: "Kubernetes Docs", category: "Dev", url_template: "https://kubernetes.io/search/?q={searchTerms}" },
    BangDefinition { trigger: "caniuse", name: "Can I Use", category: "Dev", url_template: "https://caniuse.com/?search={searchTerms}" },
    BangDefinition { trigger: "devdocs", name: "DevDocs", category: "Dev", url_template: "https://devdocs.io/#q={searchTerms}" },
    BangDefinition { trigger: "rfc", name: "IETF Datatracker", category: "Dev", url_template: "https://datatracker.ietf.org/doc/search?name={searchTerms}" },
    BangDefinition { trigger: "cve", name: "NVD CVE Search", category: "Dev", url_template: "https://nvd.nist.gov/vuln/search/results?query={searchTerms}" },
    BangDefinition { trigger: "man", name: "Linux Man Pages", category: "Dev", url_template: "https://man7.org/linux/man-pages/dir_all_alphabetic.html#{searchTerms}" },
    BangDefinition { trigger: "hf", name: "Hugging Face", category: "Dev", url_template: "https://huggingface.co/search/full-text?q={searchTerms}" },
    BangDefinition { trigger: "kaggle", name: "Kaggle", category: "Dev", url_template: "https://www.kaggle.com/search?q={searchTerms}" },
    BangDefinition { trigger: "wgsl", name: "WebGPU / WGSL Spec", category: "Dev", url_template: "https://www.google.com/search?q=site:w3.org/TR/WGSL+{searchTerms}" },
    BangDefinition { trigger: "godbolt", name: "Compiler Explorer", category: "Dev", url_template: "https://godbolt.org/#g:!((g:!((g:!((h:codeEditor,i:(source:'{searchTerms}'))))))" },
    // --- Media, Video, Music, Gaming ---
    BangDefinition { trigger: "yt", name: "YouTube", category: "Media", url_template: "https://www.youtube.com/results?search_query={searchTerms}" },
    BangDefinition { trigger: "tw", name: "Twitch", category: "Media", url_template: "https://www.twitch.tv/search?term={searchTerms}" },
    BangDefinition { trigger: "twitch", name: "Twitch", category: "Media", url_template: "https://www.twitch.tv/search?term={searchTerms}" },
    BangDefinition { trigger: "vimeo", name: "Vimeo", category: "Media", url_template: "https://vimeo.com/search?q={searchTerms}" },
    BangDefinition { trigger: "dm", name: "Dailymotion", category: "Media", url_template: "https://www.dailymotion.com/search/{searchTerms}" },
    BangDefinition { trigger: "sc", name: "SoundCloud", category: "Media", url_template: "https://soundcloud.com/search?q={searchTerms}" },
    BangDefinition { trigger: "spotify", name: "Spotify", category: "Media", url_template: "https://open.spotify.com/search/{searchTerms}" },
    BangDefinition { trigger: "bc", name: "Bandcamp", category: "Media", url_template: "https://bandcamp.com/search?q={searchTerms}" },
    BangDefinition { trigger: "discogs", name: "Discogs", category: "Media", url_template: "https://www.discogs.com/search/?q={searchTerms}" },
    BangDefinition { trigger: "imdb", name: "IMDb", category: "Media", url_template: "https://www.imdb.com/find/?q={searchTerms}" },
    BangDefinition { trigger: "tmdb", name: "TMDB", category: "Media", url_template: "https://www.themoviedb.org/search?query={searchTerms}" },
    BangDefinition { trigger: "lb", name: "Letterboxd", category: "Media", url_template: "https://letterboxd.com/search/{searchTerms}/" },
    BangDefinition { trigger: "rt", name: "Rotten Tomatoes", category: "Media", url_template: "https://www.rottentomatoes.com/search?search={searchTerms}" },
    BangDefinition { trigger: "mal", name: "MyAnimeList", category: "Media", url_template: "https://myanimelist.net/search/all?q={searchTerms}" },
    BangDefinition { trigger: "ani", name: "AniList", category: "Media", url_template: "https://anilist.co/search/anime?search={searchTerms}" },
    BangDefinition { trigger: "steam", name: "Steam Store", category: "Gaming", url_template: "https://store.steampowered.com/search/?term={searchTerms}" },
    BangDefinition { trigger: "protondb", name: "ProtonDB", category: "Gaming", url_template: "https://www.protondb.com/search?q={searchTerms}" },
    BangDefinition { trigger: "pcgw", name: "PCGamingWiki", category: "Gaming", url_template: "https://www.pcgamingwiki.com/w/index.php?search={searchTerms}" },
    BangDefinition { trigger: "hltb", name: "HowLongToBeat", category: "Gaming", url_template: "https://howlongtobeat.com/?q={searchTerms}" },
    BangDefinition { trigger: "nexus", name: "Nexus Mods", category: "Gaming", url_template: "https://www.nexusmods.com/search/?gsearch={searchTerms}" },
    // --- Social & Communities ---
    BangDefinition { trigger: "rd", name: "Reddit", category: "Social", url_template: "https://www.reddit.com/search/?q={searchTerms}" },
    BangDefinition { trigger: "r", name: "Subreddit", category: "Social", url_template: "https://www.reddit.com/r/{searchTerms}" },
    BangDefinition { trigger: "hn", name: "Hacker News (Algolia)", category: "Social", url_template: "https://hn.algolia.com/?q={searchTerms}" },
    BangDefinition { trigger: "lobsters", name: "Lobsters", category: "Social", url_template: "https://lobste.rs/search?q={searchTerms}" },
    BangDefinition { trigger: "x", name: "X / Twitter", category: "Social", url_template: "https://x.com/search?q={searchTerms}" },
    BangDefinition { trigger: "bsky", name: "Bluesky", category: "Social", url_template: "https://bsky.app/search?q={searchTerms}" },
    BangDefinition { trigger: "li", name: "LinkedIn", category: "Social", url_template: "https://www.linkedin.com/search/results/all/?keywords={searchTerms}" },
    BangDefinition { trigger: "med", name: "Medium", category: "Social", url_template: "https://medium.com/search?q={searchTerms}" },
    // --- Maps & Translation & Dictionaries ---
    BangDefinition { trigger: "maps", name: "Google Maps", category: "Maps", url_template: "https://www.google.com/maps/search/{searchTerms}" },
    BangDefinition { trigger: "osm", name: "OpenStreetMap", category: "Maps", url_template: "https://www.openstreetmap.org/search?query={searchTerms}" },
    BangDefinition { trigger: "tr", name: "Google Translate", category: "Translate", url_template: "https://translate.google.com/?sl=auto&tl=fr&text={searchTerms}" },
    BangDefinition { trigger: "tren", name: "Google Translate (to EN)", category: "Translate", url_template: "https://translate.google.com/?sl=auto&tl=en&text={searchTerms}" },
    BangDefinition { trigger: "deepl", name: "DeepL", category: "Translate", url_template: "https://www.deepl.com/translator#auto/fr/{searchTerms}" },
    BangDefinition { trigger: "linguee", name: "Linguee", category: "Translate", url_template: "https://www.linguee.com/english-french/search?query={searchTerms}" },
    BangDefinition { trigger: "wr", name: "WordReference", category: "Translate", url_template: "https://www.wordreference.com/enfr/{searchTerms}" },
    BangDefinition { trigger: "larousse", name: "Larousse", category: "Translate", url_template: "https://www.larousse.fr/dictionnaires/francais/{searchTerms}" },
    BangDefinition { trigger: "cnrtl", name: "CNRTL", category: "Translate", url_template: "https://www.cnrtl.fr/definition/{searchTerms}" },
    BangDefinition { trigger: "ud", name: "Urban Dictionary", category: "Translate", url_template: "https://www.urbandictionary.com/define.php?term={searchTerms}" },
    // --- Shopping & Finance ---
    BangDefinition { trigger: "amz", name: "Amazon", category: "Shopping", url_template: "https://www.amazon.com/s?k={searchTerms}" },
    BangDefinition { trigger: "amzfr", name: "Amazon FR", category: "Shopping", url_template: "https://www.amazon.fr/s?k={searchTerms}" },
    BangDefinition { trigger: "ebay", name: "eBay", category: "Shopping", url_template: "https://www.ebay.com/sch/i.html?_nkw={searchTerms}" },
    BangDefinition { trigger: "ldlc", name: "LDLC", category: "Shopping", url_template: "https://www.ldlc.com/recherche/{searchTerms}/" },
    BangDefinition { trigger: "fnac", name: "Fnac", category: "Shopping", url_template: "https://www.fnac.com/SearchResult/ResultList.aspx?Search={searchTerms}" },
    BangDefinition { trigger: "ikea", name: "IKEA", category: "Shopping", url_template: "https://www.ikea.com/fr/fr/search/?q={searchTerms}" },
    BangDefinition { trigger: "yf", name: "Yahoo Finance", category: "Finance", url_template: "https://finance.yahoo.com/quote/{searchTerms}" },
    BangDefinition { trigger: "tv", name: "TradingView", category: "Finance", url_template: "https://www.tradingview.com/symbols/{searchTerms}/" },
    BangDefinition { trigger: "cg", name: "CoinGecko", category: "Finance", url_template: "https://www.coingecko.com/en/search?query={searchTerms}" },
    // --- Design, Archive & Web Tools ---
    BangDefinition { trigger: "unsplash", name: "Unsplash", category: "Design", url_template: "https://unsplash.com/s/photos/{searchTerms}" },
    BangDefinition { trigger: "pexels", name: "Pexels", category: "Design", url_template: "https://www.pexels.com/search/{searchTerms}/" },
    BangDefinition { trigger: "lucide", name: "Lucide Icons", category: "Design", url_template: "https://lucide.dev/icons/?search={searchTerms}" },
    BangDefinition { trigger: "fonts", name: "Google Fonts", category: "Design", url_template: "https://fonts.google.com/?query={searchTerms}" },
    BangDefinition { trigger: "wayback", name: "Wayback Machine", category: "Web", url_template: "https://web.archive.org/web/*/{searchTerms}" },
    BangDefinition { trigger: "archive", name: "archive.today", category: "Web", url_template: "https://archive.today/{searchTerms}" },
    BangDefinition { trigger: "whois", name: "WHOIS Lookup", category: "Web", url_template: "https://who.is/whois/{searchTerms}" },
];

pub fn builtin_bangs() -> &'static [BangDefinition] {
    BUILTIN_BANGS
}

pub fn lookup_bang(trigger: &str) -> Option<&'static BangDefinition> {
    let norm = trigger.trim_start_matches('!').to_ascii_lowercase();
    BUILTIN_BANGS.iter().find(|b| b.trigger == norm)
}

/// Extracts a bang at the beginning (`!w rust`) or end (`rust !w`) of a query.
/// Does NOT misclassify math factorials like `5!` as bangs.
pub fn extract_bang_syntax(raw: &str) -> Option<(String, String)> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Leading bang: `!w rust` or `!gh`
    if let Some(rest) = trimmed.strip_prefix('!') {
        let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        let token = &rest[..end];
        if !token.is_empty()
            && token.len() <= 20
            && token.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            && token.chars().any(|c| c.is_ascii_alphabetic())
        {
            let query = rest[end..].trim().to_string();
            return Some((token.to_ascii_lowercase(), query));
        }
    }

    // Trailing bang: `rust !w` (must be preceded by whitespace so `5!` is ignored)
    if let Some(ws_idx) = trimmed.rfind(char::is_whitespace) {
        let last_tok = trimmed[ws_idx..].trim();
        if let Some(bang_tok) = last_tok.strip_prefix('!') {
            if !bang_tok.is_empty()
                && bang_tok.len() <= 20
                && bang_tok
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_')
                && bang_tok.chars().any(|c| c.is_ascii_alphabetic())
            {
                let query = trimmed[..ws_idx].trim().to_string();
                return Some((bang_tok.to_ascii_lowercase(), query));
            }
        }
    }

    None
}

// ============================================================================
// Offline FX Rates Cache (with ECB XML Parser)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FxRatesCache {
    pub base: String,
    pub updated_date: String,
    /// Currency code (uppercase ISO 4217) -> units per 1 EUR
    pub rates_per_eur: HashMap<String, f64>,
}

impl Default for FxRatesCache {
    fn default() -> Self {
        let mut rates = HashMap::new();
        for &(code, rate) in &[
            ("EUR", 1.0),
            ("USD", 1.085),
            ("GBP", 0.855),
            ("JPY", 164.5),
            ("CHF", 0.965),
            ("CAD", 1.485),
            ("AUD", 1.655),
            ("NZD", 1.805),
            ("CNY", 7.85),
            ("HKD", 8.48),
            ("SGD", 1.455),
            ("SEK", 11.45),
            ("NOK", 11.65),
            ("DKK", 7.46),
            ("PLN", 4.30),
            ("CZK", 25.25),
            ("HUF", 395.0),
            ("RON", 4.97),
            ("BGN", 1.9558),
            ("CHF", 0.965),
            ("INR", 90.8),
            ("KRW", 1485.0),
            ("BRL", 5.85),
            ("MXN", 19.5),
            ("ZAR", 20.1),
            ("TRY", 36.5),
            ("AED", 3.98),
            ("SAR", 4.07),
            ("THB", 38.8),
            ("MYR", 5.05),
            ("IDR", 17100.0),
            ("PHP", 62.5),
            ("ILS", 4.02),
        ] {
            rates.insert(code.to_string(), rate);
        }
        Self {
            base: "EUR".to_string(),
            updated_date: "offline-default".to_string(),
            rates_per_eur: rates,
        }
    }
}

impl FxRatesCache {
    /// Parses the official European Central Bank daily XML feed (`eurofxref-daily.xml`).
    pub fn parse_ecb_xml(xml: &str) -> Result<Self, OmniboxError> {
        if xml.len() > 1024 * 1024 {
            return Err(OmniboxError::InvalidFxXml("ECB XML exceeds 1 MiB".into()));
        }
        let upper = xml.to_ascii_uppercase();
        if upper.contains("<!ENTITY") || upper.contains("<!DOCTYPE") {
            return Err(OmniboxError::InvalidFxXml(
                "DOCTYPE/ENTITY rejected".into(),
            ));
        }

        let mut rates = HashMap::new();
        rates.insert("EUR".to_string(), 1.0);
        let mut updated_date = String::from("unknown");

        let mut cursor = 0usize;
        while let Some(rel) = find_xml_open_tag(&xml[cursor..], "Cube") {
            let start = cursor + rel;
            let Some(rel_end) = xml[start..].find('>') else {
                break;
            };
            let tag = &xml[start..=start + rel_end];
            if let Some(t) = extract_xml_attr(tag, "time") {
                updated_date = t;
            }
            if let (Some(curr), Some(rate_str)) = (
                extract_xml_attr(tag, "currency"),
                extract_xml_attr(tag, "rate"),
            ) {
                if let Ok(rate) = rate_str.parse::<f64>() {
                    if rate.is_finite() && rate > 0.0 {
                        rates.insert(curr.to_ascii_uppercase(), rate);
                    }
                }
            }
            cursor = start + rel_end + 1;
        }

        if rates.len() <= 1 {
            return Err(OmniboxError::InvalidFxXml(
                "no <Cube currency=... rate=.../> entries found".into(),
            ));
        }

        Ok(Self {
            base: "EUR".to_string(),
            updated_date,
            rates_per_eur: rates,
        })
    }

    pub fn convert(&self, amount: f64, from: &str, to: &str) -> Option<f64> {
        let f = self.rates_per_eur.get(&from.to_ascii_uppercase())?;
        let t = self.rates_per_eur.get(&to.to_ascii_uppercase())?;
        if *f <= 0.0 || !f.is_finite() || !t.is_finite() {
            return None;
        }
        Some(amount * (*t / *f))
    }
}

// ============================================================================
// 100% Offline Instant Answer Engine
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstantAnswerKind {
    Calculation,
    UnitConversion,
    TimezoneConversion,
    ColorConversion,
    DevBaseConversion,
    DevBitwise,
    UnixTimestamp,
    UuidGenerator,
    CurrencyConversion,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstantAnswer {
    pub kind: InstantAnswerKind,
    pub headline: String,
    pub result: String,
    pub copy_value: String,
    pub details: Vec<(String, String)>,
    #[serde(default)]
    pub color_preview_hex: Option<String>,
}

/// Evaluates an omnibox query locally with zero network access using the default offline FX rates.
pub fn evaluate_instant_answer(raw: &str) -> Option<InstantAnswer> {
    let default_fx = FxRatesCache::default();
    evaluate_instant_answer_with_fx(raw, &default_fx, current_unix_secs())
}

/// Evaluates an omnibox query locally with an injected `FxRatesCache` and reference Unix timestamp.
pub fn evaluate_instant_answer_with_fx(
    raw: &str,
    fx: &FxRatesCache,
    now_unix: u64,
) -> Option<InstantAnswer> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 256 {
        return None;
    }

    // 1. UUID v4 generator
    if let Some(ans) = try_uuid_generator(trimmed) {
        return Some(ans);
    }

    // 2. Unix timestamp tool
    if let Some(ans) = try_unix_timestamp(trimmed, now_unix) {
        return Some(ans);
    }

    // 3. Color converter (HEX / RGB / HSL -> HEX, RGB, HSL, OKLCH + WCAG 2.1)
    if let Some(ans) = try_color_conversion(trimmed) {
        return Some(ans);
    }

    // 4. Developer base conversions & bitwise ops
    if let Some(ans) = try_dev_radix_or_bitwise(trimmed) {
        return Some(ans);
    }

    // 5. Currency converter
    if let Some(ans) = try_currency_conversion(trimmed, fx) {
        return Some(ans);
    }

    // 6. Unit converter (EN / FR)
    if let Some(ans) = try_unit_conversion(trimmed) {
        return Some(ans);
    }

    // 7. Timezone converter
    if let Some(ans) = try_timezone_conversion(trimmed, now_unix) {
        return Some(ans);
    }

    // 8. Scientific calculator (with percentages)
    if let Some(ans) = try_scientific_calculator(trimmed) {
        return Some(ans);
    }

    None
}

fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// --- 1. UUID v4 ---

fn try_uuid_generator(input: &str) -> Option<InstantAnswer> {
    let lower = input.to_ascii_lowercase();
    if !matches!(
        lower.as_str(),
        "uuid" | "uuid4" | "uuid v4" | "guid" | "new uuid" | "generate uuid"
    ) {
        return None;
    }
    let uuid = generate_uuid_v4();
    Some(InstantAnswer {
        kind: InstantAnswerKind::UuidGenerator,
        headline: "UUID v4 (CSPRNG OsRng)".into(),
        result: uuid.clone(),
        copy_value: uuid,
        details: vec![("Standard".into(), "RFC 4122 / RFC 9562 v4".into())],
        color_preview_hex: None,
    })
}

/// Generates a cryptographically secure RFC 4122 UUID v4 using `rand_core::OsRng`.
pub fn generate_uuid_v4() -> String {
    let mut b = [0u8; 16];
    OsRng.fill_bytes(&mut b);
    b[6] = (b[6] & 0x0F) | 0x40; // version 4
    b[8] = (b[8] & 0x3F) | 0x80; // variant 10xx
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3],
        b[4], b[5],
        b[6], b[7],
        b[8], b[9],
        b[10], b[11], b[12], b[13], b[14], b[15]
    )
}

// --- 2. Unix Timestamp ---

fn try_unix_timestamp(input: &str, now_unix: u64) -> Option<InstantAnswer> {
    let lower = input.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "unix now" | "epoch now" | "timestamp now" | "ts now" | "unix timestamp"
    ) {
        let iso = format_unix_iso8601(now_unix as i64);
        return Some(InstantAnswer {
            kind: InstantAnswerKind::UnixTimestamp,
            headline: "Current Unix Timestamp".into(),
            result: now_unix.to_string(),
            copy_value: now_unix.to_string(),
            details: vec![
                ("ISO-8601 UTC".into(), iso),
                ("Milliseconds".into(), (now_unix * 1000).to_string()),
            ],
            color_preview_hex: None,
        });
    }

    for prefix in ["ts ", "unix ", "epoch ", "timestamp "] {
        if let Some(rest) = lower.strip_prefix(prefix) {
            let num_str = rest.trim();
            if let Ok(raw_num) = num_str.parse::<i64>() {
                // Auto-detect milliseconds if >= 1e12
                let (secs, unit_label) = if raw_num.abs() >= 1_000_000_000_000 {
                    (raw_num / 1000, "milliseconds")
                } else {
                    (raw_num, "seconds")
                };
                let iso = format_unix_iso8601(secs);
                return Some(InstantAnswer {
                    kind: InstantAnswerKind::UnixTimestamp,
                    headline: format!("Unix Timestamp ({})", unit_label),
                    result: iso.clone(),
                    copy_value: iso,
                    details: vec![
                        ("Seconds".into(), secs.to_string()),
                        ("UTC".into(), format_unix_human_utc(secs)),
                    ],
                    color_preview_hex: None,
                });
            }
        }
    }
    None
}

/// Howard Hinnant's civil-from-days algorithm: converts Unix seconds to `(year, month, day, h, m, s)`.
pub fn unix_to_utc_components(secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400) as u32;
    let hour = sod / 3600;
    let minute = (sod % 3600) / 60;
    let second = sod % 60;

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32; // [1, 12]
    let year = y + if m <= 2 { 1 } else { 0 };
    (year, m, d, hour, minute, second)
}

fn format_unix_iso8601(secs: i64) -> String {
    let (y, m, d, hh, mm, ss) = unix_to_utc_components(secs);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, m, d, hh, mm, ss)
}

fn format_unix_human_utc(secs: i64) -> String {
    let (y, m, d, hh, mm, ss) = unix_to_utc_components(secs);
    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC", y, m, d, hh, mm, ss)
}

// --- 3. Color Converter (HEX / RGB / HSL -> HEX, RGB, HSL, OKLCH + WCAG 2.1) ---

fn try_color_conversion(input: &str) -> Option<InstantAnswer> {
    let (r, g, b, a_opt) = parse_color_rgba(input)?;
    let hex = if let Some(a) = a_opt {
        format!("#{:02X}{:02X}{:02X}{:02X}", r, g, b, (a * 255.0).round() as u8)
    } else {
        format!("#{:02X}{:02X}{:02X}", r, g, b)
    };
    let preview_hex = format!("#{:02X}{:02X}{:02X}", r, g, b);
    let (h, s, l) = rgb_to_hsl(r, g, b);
    let (ok_l, ok_c, ok_h) = rgb_to_oklch(r, g, b);

    let lum = relative_luminance(r, g, b);
    let contrast_black = (lum + 0.05) / 0.05;
    let contrast_white = 1.05 / (lum + 0.05);

    let wcag_badge = |ratio: f64| -> &'static str {
        if ratio >= 7.0 {
            "AAA"
        } else if ratio >= 4.5 {
            "AA"
        } else if ratio >= 3.0 {
            "AA Large"
        } else {
            "Fail"
        }
    };

    let rgb_str = format!("rgb({}, {}, {})", r, g, b);
    let hsl_str = format!("hsl({:.0}, {:.1}%, {:.1}%)", h, s * 100.0, l * 100.0);
    let oklch_str = format!("oklch({:.3} {:.3} {:.1})", ok_l, ok_c, ok_h);

    Some(InstantAnswer {
        kind: InstantAnswerKind::ColorConversion,
        headline: format!("Color {}", preview_hex),
        result: format!("{} · {} · {}", hex, rgb_str, hsl_str),
        copy_value: hex.clone(),
        details: vec![
            ("HEX".into(), hex),
            ("RGB".into(), rgb_str),
            ("HSL".into(), hsl_str),
            ("OKLCH".into(), oklch_str),
            (
                "WCAG on #000000".into(),
                format!("{:.2}:1 ({})", contrast_black, wcag_badge(contrast_black)),
            ),
            (
                "WCAG on #FFFFFF".into(),
                format!("{:.2}:1 ({})", contrast_white, wcag_badge(contrast_white)),
            ),
        ],
        color_preview_hex: Some(preview_hex),
    })
}

fn parse_color_rgba(input: &str) -> Option<(u8, u8, u8, Option<f64>)> {
    let t = input.trim();
    if let Some(hex) = t.strip_prefix('#') {
        let bytes = hex.as_bytes();
        if !bytes.iter().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        return match bytes.len() {
            3 => {
                let r = u8::from_str_radix(&hex[0..1], 16).ok()? * 17;
                let g = u8::from_str_radix(&hex[1..2], 16).ok()? * 17;
                let b = u8::from_str_radix(&hex[2..3], 16).ok()? * 17;
                Some((r, g, b, None))
            }
            4 => {
                let r = u8::from_str_radix(&hex[0..1], 16).ok()? * 17;
                let g = u8::from_str_radix(&hex[1..2], 16).ok()? * 17;
                let b = u8::from_str_radix(&hex[2..3], 16).ok()? * 17;
                let a = (u8::from_str_radix(&hex[3..4], 16).ok()? * 17) as f64 / 255.0;
                Some((r, g, b, Some(a)))
            }
            6 => {
                let r = u8::from_str_radix(&hex[0..2], 16).ok()?;
                let g = u8::from_str_radix(&hex[2..4], 16).ok()?;
                let b = u8::from_str_radix(&hex[4..6], 16).ok()?;
                Some((r, g, b, None))
            }
            8 => {
                let r = u8::from_str_radix(&hex[0..2], 16).ok()?;
                let g = u8::from_str_radix(&hex[2..4], 16).ok()?;
                let b = u8::from_str_radix(&hex[4..6], 16).ok()?;
                let a = u8::from_str_radix(&hex[6..8], 16).ok()? as f64 / 255.0;
                Some((r, g, b, Some(a)))
            }
            _ => None,
        };
    }

    let lower = t.to_ascii_lowercase();
    if let Some(inner) = lower
        .strip_prefix("rgb(")
        .or_else(|| lower.strip_prefix("rgba("))
        .and_then(|s| s.strip_suffix(')'))
    {
        let parts: Vec<&str> = inner
            .split([',', '/', ' '])
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        if parts.len() == 3 || parts.len() == 4 {
            let r = parts[0].parse::<u8>().ok()?;
            let g = parts[1].parse::<u8>().ok()?;
            let b = parts[2].parse::<u8>().ok()?;
            let a = if parts.len() == 4 {
                Some(parts[3].trim_end_matches('%').parse::<f64>().ok()?.clamp(0.0, 1.0))
            } else {
                None
            };
            return Some((r, g, b, a));
        }
    }

    if let Some(inner) = lower
        .strip_prefix("hsl(")
        .or_else(|| lower.strip_prefix("hsla("))
        .and_then(|s| s.strip_suffix(')'))
    {
        let parts: Vec<&str> = inner
            .split([',', '/', ' '])
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        if parts.len() == 3 || parts.len() == 4 {
            let h = parts[0].trim_end_matches("deg").parse::<f64>().ok()?;
            let s = parts[1].trim_end_matches('%').parse::<f64>().ok()? / 100.0;
            let l = parts[2].trim_end_matches('%').parse::<f64>().ok()? / 100.0;
            let (r, g, b) = hsl_to_rgb(h, s.clamp(0.0, 1.0), l.clamp(0.0, 1.0));
            let a = if parts.len() == 4 {
                Some(parts[3].trim_end_matches('%').parse::<f64>().ok()?.clamp(0.0, 1.0))
            } else {
                None
            };
            return Some((r, g, b, a));
        }
    }

    None
}

fn rgb_to_hsl(r: u8, g: u8, b: u8) -> (f64, f64, f64) {
    let rf = r as f64 / 255.0;
    let gf = g as f64 / 255.0;
    let bf = b as f64 / 255.0;
    let max = rf.max(gf).max(bf);
    let min = rf.min(gf).min(bf);
    let l = (max + min) / 2.0;
    let d = max - min;
    if d.abs() < 1e-9 {
        return (0.0, 0.0, l);
    }
    let s = if l > 0.5 {
        d / (2.0 - max - min)
    } else {
        d / (max + min)
    };
    let mut h = if (max - rf).abs() < 1e-9 {
        (gf - bf) / d + if gf < bf { 6.0 } else { 0.0 }
    } else if (max - gf).abs() < 1e-9 {
        (bf - rf) / d + 2.0
    } else {
        (rf - gf) / d + 4.0
    };
    h *= 60.0;
    (h, s, l)
}

fn hsl_to_rgb(h: f64, s: f64, l: f64) -> (u8, u8, u8) {
    let h = h.rem_euclid(360.0);
    let c = (1.0 - (2.0 * l - 1.0).abs()) * s;
    let x = c * (1.0 - ((h / 60.0) % 2.0 - 1.0).abs());
    let m = l - c / 2.0;
    let (r1, g1, b1) = if h < 60.0 {
        (c, x, 0.0)
    } else if h < 120.0 {
        (x, c, 0.0)
    } else if h < 180.0 {
        (0.0, c, x)
    } else if h < 240.0 {
        (0.0, x, c)
    } else if h < 300.0 {
        (x, 0.0, c)
    } else {
        (c, 0.0, x)
    };
    (
        ((r1 + m) * 255.0).round().clamp(0.0, 255.0) as u8,
        ((g1 + m) * 255.0).round().clamp(0.0, 255.0) as u8,
        ((b1 + m) * 255.0).round().clamp(0.0, 255.0) as u8,
    )
}

fn srgb_to_linear(v: u8) -> f64 {
    let c = v as f64 / 255.0;
    if c <= 0.04045 {
        c / 12.92
    } else {
        ((c + 0.055) / 1.055).powf(2.4)
    }
}

fn relative_luminance(r: u8, g: u8, b: u8) -> f64 {
    0.2126 * srgb_to_linear(r) + 0.7152 * srgb_to_linear(g) + 0.0722 * srgb_to_linear(b)
}

fn rgb_to_oklch(r: u8, g: u8, b: u8) -> (f64, f64, f64) {
    let lr = srgb_to_linear(r);
    let lg = srgb_to_linear(g);
    let lb = srgb_to_linear(b);

    let l = 0.4122214708 * lr + 0.5363325363 * lg + 0.0514459929 * lb;
    let m = 0.2119034982 * lr + 0.6806995451 * lg + 0.1073969566 * lb;
    let s = 0.0883024619 * lr + 0.2817188376 * lg + 0.6299787005 * lb;

    let l_ = l.cbrt();
    let m_ = m.cbrt();
    let s_ = s.cbrt();

    let ok_l = 0.2104542553 * l_ + 0.7936177850 * m_ - 0.0040720468 * s_;
    let ok_a = 1.9779984951 * l_ - 2.4285922050 * m_ + 0.4505937099 * s_;
    let ok_b = 0.0259040371 * l_ + 0.7827717662 * m_ - 0.8086757660 * s_;

    let c = (ok_a * ok_a + ok_b * ok_b).sqrt();
    let mut h = ok_b.atan2(ok_a).to_degrees();
    if h < 0.0 {
        h += 360.0;
    }
    if c < 1e-5 {
        h = 0.0;
    }
    (ok_l.clamp(0.0, 1.0), c, h)
}

// --- 4. Dev Radix & Bitwise ---

fn parse_prefixed_int(s: &str) -> Option<(i128, u32)> {
    let t = s.trim().replace('_', "");
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        i128::from_str_radix(hex, 16).ok().map(|v| (v, 16))
    } else if let Some(bin) = t.strip_prefix("0b").or_else(|| t.strip_prefix("0B")) {
        i128::from_str_radix(bin, 2).ok().map(|v| (v, 2))
    } else if let Some(oct) = t.strip_prefix("0o").or_else(|| t.strip_prefix("0O")) {
        i128::from_str_radix(oct, 8).ok().map(|v| (v, 8))
    } else {
        t.parse::<i128>().ok().map(|v| (v, 10))
    }
}

fn try_dev_radix_or_bitwise(input: &str) -> Option<InstantAnswer> {
    let t = input.trim();

    // Direct radix literal: 0xFF, 0b1010, 0o755
    if (t.starts_with("0x")
        || t.starts_with("0X")
        || t.starts_with("0b")
        || t.starts_with("0B")
        || t.starts_with("0o")
        || t.starts_with("0O"))
        && !t.contains(char::is_whitespace)
    {
        if let Some((val, base)) = parse_prefixed_int(t) {
            return Some(format_radix_answer(val, base, None));
        }
    }

    // Explicit conversion: `255 to hex`, `42 in bin`, `0xFF en dec`, `755 to oct`
    let lower = t.to_ascii_lowercase();
    for sep in [" to ", " in ", " en ", " -> "] {
        if let Some((left, right)) = lower.split_once(sep) {
            let target_base = match right.trim() {
                "hex" | "hexadecimal" | "base16" | "16" => Some(16u32),
                "bin" | "binary" | "binaire" | "base2" | "2" => Some(2u32),
                "oct" | "octal" | "base8" | "8" => Some(8u32),
                "dec" | "decimal" | "base10" | "10" => Some(10u32),
                _ => None,
            };
            if let Some(tb) = target_base {
                if let Some((val, src_base)) = parse_prefixed_int(left.trim()) {
                    return Some(format_radix_answer(val, src_base, Some(tb)));
                }
            }
        }
    }

    // Bitwise binary operators: `<<`, `>>`, `&`, `|`, ` xor `
    for (op_sym, op_name) in [
        ("<<", "SHL"),
        (">>", "SHR"),
        ("&", "AND"),
        ("|", "OR"),
        (" xor ", "XOR"),
    ] {
        if let Some((lhs_s, rhs_s)) = lower.split_once(op_sym) {
            if let (Some((a, _)), Some((b, _))) =
                (parse_prefixed_int(lhs_s.trim()), parse_prefixed_int(rhs_s.trim()))
            {
                let res = match op_name {
                    "SHL" => {
                        if !(0..=63).contains(&b) {
                            return None;
                        }
                        a.checked_shl(b as u32)?
                    }
                    "SHR" => {
                        if !(0..=63).contains(&b) {
                            return None;
                        }
                        a.checked_shr(b as u32)?
                    }
                    "AND" => a & b,
                    "OR" => a | b,
                    "XOR" => a ^ b,
                    _ => return None,
                };
                return Some(InstantAnswer {
                    kind: InstantAnswerKind::DevBitwise,
                    headline: format!("Bitwise {}", op_name),
                    result: format!("{} (0x{:X})", res, res),
                    copy_value: res.to_string(),
                    details: vec![
                        ("DEC".into(), res.to_string()),
                        ("HEX".into(), format!("0x{:X}", res)),
                        ("BIN".into(), format!("0b{:b}", res)),
                        ("OCT".into(), format!("0o{:o}", res)),
                    ],
                    color_preview_hex: None,
                });
            }
        }
    }

    None
}

fn format_radix_answer(val: i128, src_base: u32, target_base: Option<u32>) -> InstantAnswer {
    let hex_s = if val < 0 {
        format!("-0x{:X}", val.unsigned_abs())
    } else {
        format!("0x{:X}", val)
    };
    let bin_s = if val < 0 {
        format!("-0b{:b}", val.unsigned_abs())
    } else {
        format!("0b{:b}", val)
    };
    let oct_s = if val < 0 {
        format!("-0o{:o}", val.unsigned_abs())
    } else {
        format!("0o{:o}", val)
    };
    let dec_s = val.to_string();

    let primary = match target_base {
        Some(16) => hex_s.clone(),
        Some(2) => bin_s.clone(),
        Some(8) => oct_s.clone(),
        Some(10) | None => {
            if src_base == 10 {
                hex_s.clone()
            } else {
                dec_s.clone()
            }
        }
        _ => dec_s.clone(),
    };

    InstantAnswer {
        kind: InstantAnswerKind::DevBaseConversion,
        headline: "Base Conversion".into(),
        result: primary.clone(),
        copy_value: primary,
        details: vec![
            ("DEC".into(), dec_s),
            ("HEX".into(), hex_s),
            ("BIN".into(), bin_s),
            ("OCT".into(), oct_s),
        ],
        color_preview_hex: None,
    }
}

// --- 5. Currency Conversion ---

fn parse_currency_code(raw: &str) -> Option<&'static str> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "eur" | "euro" | "euros" | "€" => Some("EUR"),
        "usd" | "dollar" | "dollars" | "$" | "us$" => Some("USD"),
        "gbp" | "pound" | "pounds" | "£" => Some("GBP"),
        "jpy" | "yen" | "¥" => Some("JPY"),
        "chf" | "franc" | "francs" => Some("CHF"),
        "cad" | "ca$" => Some("CAD"),
        "aud" | "au$" => Some("AUD"),
        "nzd" => Some("NZD"),
        "cny" | "rmb" | "yuan" => Some("CNY"),
        "hkd" => Some("HKD"),
        "sgd" => Some("SGD"),
        "sek" => Some("SEK"),
        "nok" => Some("NOK"),
        "dkk" => Some("DKK"),
        "pln" => Some("PLN"),
        "czk" => Some("CZK"),
        "huf" => Some("HUF"),
        "ron" => Some("RON"),
        "inr" | "₹" => Some("INR"),
        "krw" | "₩" => Some("KRW"),
        "brl" | "r$" => Some("BRL"),
        "mxn" => Some("MXN"),
        "zar" => Some("ZAR"),
        "try" => Some("TRY"),
        "aed" => Some("AED"),
        "sar" => Some("SAR"),
        "thb" => Some("THB"),
        "myr" => Some("MYR"),
        "idr" => Some("IDR"),
        "php" => Some("PHP"),
        "ils" => Some("ILS"),
        _ => None,
    }
}

fn try_currency_conversion(input: &str, fx: &FxRatesCache) -> Option<InstantAnswer> {
    let lower = input.trim().to_ascii_lowercase();
    let (left, right) = split_conversion_connector(&lower)?;
    let to_code = parse_currency_code(right)?;
    let (amount, from_token) = split_leading_number_and_unit(left)?;
    let from_code = parse_currency_code(from_token)?;

    let converted = fx.convert(amount, from_code, to_code)?;
    let formatted = format!("{:.2} {}", converted, to_code);
    let unit_rate = fx.convert(1.0, from_code, to_code).unwrap_or(0.0);

    Some(InstantAnswer {
        kind: InstantAnswerKind::CurrencyConversion,
        headline: format!("{} {} → {}", format_clean_float(amount), from_code, to_code),
        result: formatted.clone(),
        copy_value: format!("{:.2}", converted),
        details: vec![
            (
                "Rate".into(),
                format!("1 {} = {:.4} {}", from_code, unit_rate, to_code),
            ),
            ("FX Snapshot".into(), fx.updated_date.clone()),
        ],
        color_preview_hex: None,
    })
}

// --- 6. Unit Converter (EN / FR) ---

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnitCategory {
    Length,
    Mass,
    Temperature,
    Volume,
    Speed,
    DataSize,
    DataRate,
}

#[derive(Debug, Clone, Copy)]
struct UnitSpec {
    category: UnitCategory,
    canonical_symbol: &'static str,
    /// Factor to convert 1 unit -> category SI base unit (ignored for Temperature)
    to_base: f64,
}

fn lookup_unit(raw: &str) -> Option<UnitSpec> {
    let key = fold_french_accents(&raw.trim().to_ascii_lowercase());
    let u = match key.as_str() {
        // Length (base: meter)
        "m" | "meter" | "meters" | "metre" | "metres" => UnitSpec { category: UnitCategory::Length, canonical_symbol: "m", to_base: 1.0 },
        "km" | "kilometer" | "kilometers" | "kilometre" | "kilometres" => UnitSpec { category: UnitCategory::Length, canonical_symbol: "km", to_base: 1000.0 },
        "cm" | "centimeter" | "centimeters" | "centimetre" | "centimetres" => UnitSpec { category: UnitCategory::Length, canonical_symbol: "cm", to_base: 0.01 },
        "mm" | "millimeter" | "millimeters" | "millimetre" | "millimetres" => UnitSpec { category: UnitCategory::Length, canonical_symbol: "mm", to_base: 0.001 },
        "um" | "µm" | "micrometer" | "micron" => UnitSpec { category: UnitCategory::Length, canonical_symbol: "µm", to_base: 1e-6 },
        "nm" | "nanometer" => UnitSpec { category: UnitCategory::Length, canonical_symbol: "nm", to_base: 1e-9 },
        "mi" | "mile" | "miles" => UnitSpec { category: UnitCategory::Length, canonical_symbol: "mi", to_base: 1609.344 },
        "ft" | "foot" | "feet" | "pied" | "pieds" => UnitSpec { category: UnitCategory::Length, canonical_symbol: "ft", to_base: 0.3048 },
        "in" | "inch" | "inches" | "pouce" | "pouces" => UnitSpec { category: UnitCategory::Length, canonical_symbol: "in", to_base: 0.0254 },
        "yd" | "yard" | "yards" => UnitSpec { category: UnitCategory::Length, canonical_symbol: "yd", to_base: 0.9144 },
        "nmi" | "nmile" | "nautical mile" => UnitSpec { category: UnitCategory::Length, canonical_symbol: "nmi", to_base: 1852.0 },
        // Mass (base: kilogram)
        "kg" | "kilogram" | "kilograms" | "kilogramme" | "kilogrammes" | "kilo" | "kilos" => UnitSpec { category: UnitCategory::Mass, canonical_symbol: "kg", to_base: 1.0 },
        "g" | "gram" | "grams" | "gramme" | "grammes" => UnitSpec { category: UnitCategory::Mass, canonical_symbol: "g", to_base: 0.001 },
        "mg" | "milligram" | "milligramme" => UnitSpec { category: UnitCategory::Mass, canonical_symbol: "mg", to_base: 1e-6 },
        "t" | "tonne" | "tonnes" | "metric ton" => UnitSpec { category: UnitCategory::Mass, canonical_symbol: "t", to_base: 1000.0 },
        "lb" | "lbs" | "pound" | "pounds" | "livre" | "livres" => UnitSpec { category: UnitCategory::Mass, canonical_symbol: "lb", to_base: 0.45359237 },
        "oz" | "ounce" | "ounces" | "once" | "onces" => UnitSpec { category: UnitCategory::Mass, canonical_symbol: "oz", to_base: 0.028349523125 },
        "st" | "stone" => UnitSpec { category: UnitCategory::Mass, canonical_symbol: "st", to_base: 6.35029318 },
        // Temperature
        "c" | "°c" | "degc" | "celsius" => UnitSpec { category: UnitCategory::Temperature, canonical_symbol: "°C", to_base: 1.0 },
        "f" | "°f" | "degf" | "fahrenheit" => UnitSpec { category: UnitCategory::Temperature, canonical_symbol: "°F", to_base: 2.0 },
        "k" | "kelvin" => UnitSpec { category: UnitCategory::Temperature, canonical_symbol: "K", to_base: 3.0 },
        // Volume (base: liter)
        "l" | "liter" | "liters" | "litre" | "litres" => UnitSpec { category: UnitCategory::Volume, canonical_symbol: "L", to_base: 1.0 },
        "ml" | "milliliter" | "millilitre" => UnitSpec { category: UnitCategory::Volume, canonical_symbol: "mL", to_base: 0.001 },
        "cl" | "centiliter" | "centilitre" => UnitSpec { category: UnitCategory::Volume, canonical_symbol: "cL", to_base: 0.01 },
        "dl" | "deciliter" | "decilitre" => UnitSpec { category: UnitCategory::Volume, canonical_symbol: "dL", to_base: 0.1 },
        "m3" => UnitSpec { category: UnitCategory::Volume, canonical_symbol: "m³", to_base: 1000.0 },
        "gal" | "gallon" | "gallons" => UnitSpec { category: UnitCategory::Volume, canonical_symbol: "gal", to_base: 3.785411784 },
        "floz" | "fl oz" | "fl.oz" => UnitSpec { category: UnitCategory::Volume, canonical_symbol: "fl oz", to_base: 0.0295735295625 },
        "cup" | "cups" | "tasse" | "tasses" => UnitSpec { category: UnitCategory::Volume, canonical_symbol: "cup", to_base: 0.2365882365 },
        "pt" | "pint" | "pints" | "pinte" => UnitSpec { category: UnitCategory::Volume, canonical_symbol: "pt", to_base: 0.473176473 },
        // Speed (base: m/s)
        "m/s" | "mps" => UnitSpec { category: UnitCategory::Speed, canonical_symbol: "m/s", to_base: 1.0 },
        "km/h" | "kmh" | "kph" => UnitSpec { category: UnitCategory::Speed, canonical_symbol: "km/h", to_base: 1.0 / 3.6 },
        "mph" => UnitSpec { category: UnitCategory::Speed, canonical_symbol: "mph", to_base: 0.44704 },
        "kt" | "kn" | "knot" | "knots" | "noeud" | "noeuds" => UnitSpec { category: UnitCategory::Speed, canonical_symbol: "kn", to_base: 1852.0 / 3600.0 },
        // Data Size (base: Byte) — SI (1000) & IEC (1024) + French octets
        "b" | "byte" | "bytes" | "o" | "octet" | "octets" => UnitSpec { category: UnitCategory::DataSize, canonical_symbol: "B", to_base: 1.0 },
        "bit" | "bits" => UnitSpec { category: UnitCategory::DataSize, canonical_symbol: "bit", to_base: 0.125 },
        "kb" | "ko" => UnitSpec { category: UnitCategory::DataSize, canonical_symbol: "KB", to_base: 1_000.0 },
        "mb" | "mo" => UnitSpec { category: UnitCategory::DataSize, canonical_symbol: "MB", to_base: 1_000_000.0 },
        "gb" | "go" => UnitSpec { category: UnitCategory::DataSize, canonical_symbol: "GB", to_base: 1_000_000_000.0 },
        "tb" | "to" => UnitSpec { category: UnitCategory::DataSize, canonical_symbol: "TB", to_base: 1_000_000_000_000.0 },
        "pb" | "po" => UnitSpec { category: UnitCategory::DataSize, canonical_symbol: "PB", to_base: 1e15 },
        "kib" | "kio" => UnitSpec { category: UnitCategory::DataSize, canonical_symbol: "KiB", to_base: 1024.0 },
        "mib" | "mio" => UnitSpec { category: UnitCategory::DataSize, canonical_symbol: "MiB", to_base: 1_048_576.0 },
        "gib" | "gio" => UnitSpec { category: UnitCategory::DataSize, canonical_symbol: "GiB", to_base: 1_073_741_824.0 },
        "tib" | "tio" => UnitSpec { category: UnitCategory::DataSize, canonical_symbol: "TiB", to_base: 1_099_511_627_776.0 },
        // Data Rate (base: bits per second)
        "bps" | "bit/s" => UnitSpec { category: UnitCategory::DataRate, canonical_symbol: "bps", to_base: 1.0 },
        "kbps" | "kbit/s" => UnitSpec { category: UnitCategory::DataRate, canonical_symbol: "kbps", to_base: 1_000.0 },
        "mbps" | "mbit/s" => UnitSpec { category: UnitCategory::DataRate, canonical_symbol: "Mbps", to_base: 1_000_000.0 },
        "gbps" | "gbit/s" => UnitSpec { category: UnitCategory::DataRate, canonical_symbol: "Gbps", to_base: 1_000_000_000.0 },
        "b/s" | "o/s" => UnitSpec { category: UnitCategory::DataRate, canonical_symbol: "B/s", to_base: 8.0 },
        "kb/s" | "ko/s" => UnitSpec { category: UnitCategory::DataRate, canonical_symbol: "KB/s", to_base: 8_000.0 },
        "mb/s" | "mo/s" => UnitSpec { category: UnitCategory::DataRate, canonical_symbol: "MB/s", to_base: 8_000_000.0 },
        "gb/s" | "go/s" => UnitSpec { category: UnitCategory::DataRate, canonical_symbol: "GB/s", to_base: 8_000_000_000.0 },
        "mib/s" | "mio/s" => UnitSpec { category: UnitCategory::DataRate, canonical_symbol: "MiB/s", to_base: 8_388_608.0 },
        _ => return None,
    };
    Some(u)
}

fn split_conversion_connector(lower: &str) -> Option<(&str, &str)> {
    for sep in [" to ", " in ", " en ", " vers ", " -> ", " => "] {
        if let Some((l, r)) = lower.split_once(sep) {
            if !l.trim().is_empty() && !r.trim().is_empty() {
                return Some((l.trim(), r.trim()));
            }
        }
    }
    None
}

fn split_leading_number_and_unit(s: &str) -> Option<(f64, &str)> {
    let trimmed = s.trim();
    // Handle prefix currency symbol like `$50` or `€100`
    if let Some(first) = trimmed.chars().next() {
        if matches!(first, '$' | '€' | '£' | '¥' | '₹' | '₩') {
            let num_part = trimmed[first.len_utf8()..].trim().replace(',', ".");
            if let Ok(v) = num_part.parse::<f64>() {
                if v.is_finite() {
                    return Some((v, &trimmed[..first.len_utf8()]));
                }
            }
        }
    }

    let mut end = 0usize;
    let bytes = trimmed.as_bytes();
    if end < bytes.len() && (bytes[end] == b'-' || bytes[end] == b'+') {
        end += 1;
    }
    let mut saw_digit = false;
    let mut saw_dot = false;
    while end < bytes.len() {
        let b = bytes[end];
        if b.is_ascii_digit() {
            saw_digit = true;
            end += 1;
        } else if (b == b'.' || b == b',') && !saw_dot {
            saw_dot = true;
            end += 1;
        } else {
            break;
        }
    }
    if !saw_digit {
        return None;
    }
    let num_str = trimmed[..end].replace(',', ".");
    let val = num_str.parse::<f64>().ok()?;
    if !val.is_finite() {
        return None;
    }
    let unit = trimmed[end..].trim();
    if unit.is_empty() {
        return None;
    }
    Some((val, unit))
}

fn try_unit_conversion(input: &str) -> Option<InstantAnswer> {
    let lower = input.trim().to_ascii_lowercase();
    let (left, right) = split_conversion_connector(&lower)?;
    let (value, from_raw) = split_leading_number_and_unit(left)?;
    let from_u = lookup_unit(from_raw)?;
    let to_u = lookup_unit(right)?;

    if from_u.category != to_u.category {
        return None;
    }

    let result = if from_u.category == UnitCategory::Temperature {
        let celsius = match from_u.canonical_symbol {
            "°C" => value,
            "°F" => (value - 32.0) * 5.0 / 9.0,
            "K" => value - 273.15,
            _ => return None,
        };
        match to_u.canonical_symbol {
            "°C" => celsius,
            "°F" => celsius * 9.0 / 5.0 + 32.0,
            "K" => celsius + 273.15,
            _ => return None,
        }
    } else {
        (value * from_u.to_base) / to_u.to_base
    };

    let clean = format_clean_float(result);
    let formatted = format!("{} {}", clean, to_u.canonical_symbol);
    Some(InstantAnswer {
        kind: InstantAnswerKind::UnitConversion,
        headline: format!(
            "{} {} → {}",
            format_clean_float(value),
            from_u.canonical_symbol,
            to_u.canonical_symbol
        ),
        result: formatted,
        copy_value: clean,
        details: vec![("Category".into(), format!("{:?}", from_u.category))],
        color_preview_hex: None,
    })
}

// --- 7. Timezone Converter (~65 Cities & Abbreviations) ---

struct TimezoneEntry {
    keys: &'static [&'static str],
    label: &'static str,
    offset_minutes: i32,
}

const TIMEZONES: &[TimezoneEntry] = &[
    TimezoneEntry { keys: &["utc", "gmt", "z", "reykjavik"], label: "UTC / GMT", offset_minutes: 0 },
    TimezoneEntry { keys: &["wet", "london", "londres", "lisbon", "lisbonne", "dublin"], label: "London / WET (UTC+0)", offset_minutes: 0 },
    TimezoneEntry { keys: &["bst"], label: "BST (UTC+1)", offset_minutes: 60 },
    TimezoneEntry { keys: &["cet", "paris", "berlin", "madrid", "rome", "roma", "amsterdam", "brussels", "bruxelles", "zurich", "geneva", "geneve", "vienna", "vienne", "stockholm", "oslo", "warsaw", "varsovie", "prague", "budapest", "milan", "lyon", "marseille", "lagos"], label: "CET / Paris (UTC+1)", offset_minutes: 60 },
    TimezoneEntry { keys: &["cest"], label: "CEST (UTC+2)", offset_minutes: 120 },
    TimezoneEntry { keys: &["eet", "athens", "athenes", "helsinki", "cairo", "le caire", "johannesburg", "bucharest", "kyiv", "kiev", "sofia", "jerusalem", "tel aviv"], label: "EET / Athens (UTC+2)", offset_minutes: 120 },
    TimezoneEntry { keys: &["eest"], label: "EEST (UTC+3)", offset_minutes: 180 },
    TimezoneEntry { keys: &["msk", "moscow", "moscou", "istanbul", "riyadh", "doha", "nairobi"], label: "MSK / Istanbul (UTC+3)", offset_minutes: 180 },
    TimezoneEntry { keys: &["gst", "dubai", "abu dhabi", "baku"], label: "Dubai / GST (UTC+4)", offset_minutes: 240 },
    TimezoneEntry { keys: &["pkt", "karachi", "tashkent"], label: "PKT (UTC+5)", offset_minutes: 300 },
    TimezoneEntry { keys: &["ist", "mumbai", "delhi", "new delhi", "bengaluru", "bangalore", "kolkata", "india", "inde"], label: "India / IST (UTC+5:30)", offset_minutes: 330 },
    TimezoneEntry { keys: &["dhaka", "almaty"], label: "BST/ALMT (UTC+6)", offset_minutes: 360 },
    TimezoneEntry { keys: &["ict", "bangkok", "hanoi", "jakarta", "ho chi minh"], label: "Bangkok / ICT (UTC+7)", offset_minutes: 420 },
    TimezoneEntry { keys: &["sgt", "hkt", "cst-cn", "singapore", "singapour", "hong kong", "hongkong", "beijing", "pekin", "shanghai", "taipei", "kuala lumpur", "manila", "perth"], label: "Singapore / Beijing (UTC+8)", offset_minutes: 480 },
    TimezoneEntry { keys: &["jst", "kst", "tokyo", "osaka", "kyoto", "seoul"], label: "Tokyo / Seoul (UTC+9)", offset_minutes: 540 },
    TimezoneEntry { keys: &["aest", "sydney", "melbourne", "brisbane", "canberra"], label: "Sydney / AEST (UTC+10)", offset_minutes: 600 },
    TimezoneEntry { keys: &["aedt"], label: "AEDT (UTC+11)", offset_minutes: 660 },
    TimezoneEntry { keys: &["nzst", "auckland", "wellington"], label: "Auckland / NZST (UTC+12)", offset_minutes: 720 },
    TimezoneEntry { keys: &["brt", "art", "sao paulo", "rio", "buenos aires", "montevideo"], label: "BRT / Buenos Aires (UTC-3)", offset_minutes: -180 },
    TimezoneEntry { keys: &["ast", "santiago", "halifax", "caracas"], label: "AST / Santiago (UTC-4)", offset_minutes: -240 },
    TimezoneEntry { keys: &["edt"], label: "EDT (UTC-4)", offset_minutes: -240 },
    TimezoneEntry { keys: &["est", "new york", "nyc", "toronto", "montreal", "miami", "boston", "washington", "atlanta", "detroit", "bogota", "lima"], label: "New York / EST (UTC-5)", offset_minutes: -300 },
    TimezoneEntry { keys: &["cdt"], label: "CDT (UTC-5)", offset_minutes: -300 },
    TimezoneEntry { keys: &["cst", "chicago", "dallas", "houston", "austin", "mexico", "mexico city"], label: "Chicago / CST (UTC-6)", offset_minutes: -360 },
    TimezoneEntry { keys: &["mdt"], label: "MDT (UTC-6)", offset_minutes: -360 },
    TimezoneEntry { keys: &["mst", "denver", "phoenix", "calgary", "salt lake city"], label: "Denver / MST (UTC-7)", offset_minutes: -420 },
    TimezoneEntry { keys: &["pdt"], label: "PDT (UTC-7)", offset_minutes: -420 },
    TimezoneEntry { keys: &["pst", "los angeles", "la", "san francisco", "sf", "seattle", "vancouver", "portland", "las vegas"], label: "Los Angeles / PST (UTC-8)", offset_minutes: -480 },
    TimezoneEntry { keys: &["akst", "anchorage"], label: "Anchorage / AKST (UTC-9)", offset_minutes: -540 },
    TimezoneEntry { keys: &["hst", "honolulu", "hawaii"], label: "Honolulu / HST (UTC-10)", offset_minutes: -600 },
];

fn lookup_timezone(raw: &str) -> Option<&'static TimezoneEntry> {
    let key = fold_french_accents(&raw.trim().to_ascii_lowercase());
    TIMEZONES
        .iter()
        .find(|tz| tz.keys.iter().any(|&k| k == key))
}

fn format_utc_offset(offset_minutes: i32) -> String {
    let sign = if offset_minutes >= 0 { '+' } else { '-' };
    let abs = offset_minutes.abs();
    let h = abs / 60;
    let m = abs % 60;
    if m == 0 {
        format!("UTC{}{}", sign, h)
    } else {
        format!("UTC{}{}:{:02}", sign, h, m)
    }
}

fn try_timezone_conversion(input: &str, now_unix: u64) -> Option<InstantAnswer> {
    let folded = fold_french_accents(&input.trim().to_ascii_lowercase());

    // Pattern A: `time in tokyo` / `heure a paris` / `heure paris` / `now in nyc`
    for prefix in [
        "time in ",
        "time ",
        "now in ",
        "heure a ",
        "heure en ",
        "heure ",
        "quelle heure a ",
    ] {
        if let Some(city) = folded.strip_prefix(prefix) {
            if let Some(tz) = lookup_timezone(city.trim_end_matches('?')) {
                let shifted = (now_unix as i64) + (tz.offset_minutes as i64) * 60;
                let (y, m, d, hh, mm, _) = unix_to_utc_components(shifted);
                let time_str = format!("{:02}:{:02}", hh, mm);
                return Some(InstantAnswer {
                    kind: InstantAnswerKind::TimezoneConversion,
                    headline: format!("Local Time — {}", tz.label),
                    result: format!("{} ({:04}-{:02}-{:02})", time_str, y, m, d),
                    copy_value: time_str,
                    details: vec![("Offset".into(), format_utc_offset(tz.offset_minutes))],
                    color_preview_hex: None,
                });
            }
        }
    }

    // Pattern B: `14:30 EST to CET` or `18h00 Paris en Tokyo` or `9am PST to UTC`
    if let Some((left, right)) = split_conversion_connector(&folded) {
        let target_tz = lookup_timezone(right)?;
        let (hh, mm, src_tz_str) = parse_time_and_zone(left)?;
        let src_tz = lookup_timezone(src_tz_str)?;

        let src_total_min = (hh as i32) * 60 + (mm as i32);
        let diff_min = target_tz.offset_minutes - src_tz.offset_minutes;
        let raw_target_min = src_total_min + diff_min;
        let day_shift = raw_target_min.div_euclid(1440);
        let target_mod = raw_target_min.rem_euclid(1440);
        let th = target_mod / 60;
        let tm = target_mod % 60;

        let day_note = match day_shift {
            1 => " (+1 day)",
            -1 => " (-1 day)",
            0 => "",
            d if d > 0 => " (+days)",
            _ => " (-days)",
        };
        let result = format!("{:02}:{:02}{}", th, tm, day_note);
        return Some(InstantAnswer {
            kind: InstantAnswerKind::TimezoneConversion,
            headline: format!("{:02}:{:02} {} → {}", hh, mm, src_tz.label, target_tz.label),
            result: result.clone(),
            copy_value: format!("{:02}:{:02}", th, tm),
            details: vec![
                ("From".into(), format_utc_offset(src_tz.offset_minutes)),
                ("To".into(), format_utc_offset(target_tz.offset_minutes)),
                (
                    "Delta".into(),
                    format!("{:+.1}h", (diff_min as f64) / 60.0),
                ),
            ],
            color_preview_hex: None,
        });
    }

    None
}

fn parse_time_and_zone(left: &str) -> Option<(u32, u32, &str)> {
    let trimmed = left.trim();
    let ws = trimmed.find(char::is_whitespace)?;
    let time_tok = trimmed[..ws].trim();
    let zone_tok = trimmed[ws..].trim();
    if zone_tok.is_empty() {
        return None;
    }

    let (is_pm, is_am, core) = if let Some(c) = time_tok.strip_suffix("pm") {
        (true, false, c)
    } else if let Some(c) = time_tok.strip_suffix("am") {
        (false, true, c)
    } else {
        (false, false, time_tok)
    };

    let (mut hh, mm) = if let Some((h_s, m_s)) = core.split_once(':').or_else(|| core.split_once('h')) {
        let h = h_s.parse::<u32>().ok()?;
        let m = if m_s.is_empty() { 0 } else { m_s.parse::<u32>().ok()? };
        (h, m)
    } else if is_am || is_pm {
        (core.parse::<u32>().ok()?, 0)
    } else {
        return None;
    };

    if mm >= 60 {
        return None;
    }
    if is_pm && hh < 12 {
        hh += 12;
    } else if is_am && hh == 12 {
        hh = 0;
    }
    if hh >= 24 {
        return None;
    }
    Some((hh, mm, zone_tok))
}

// --- 8. Scientific Calculator (Recursive Descent Parser) ---

fn try_scientific_calculator(input: &str) -> Option<InstantAnswer> {
    let trimmed = input.trim().trim_start_matches('=').trim();
    if trimmed.is_empty() {
        return None;
    }

    // Special natural percentage forms: `15% of 360`, `15% de 360`
    let lower = trimmed.to_ascii_lowercase();
    for kw in ["% of ", "% de "] {
        if let Some((pct_s, base_s)) = lower.split_once(kw) {
            let pct = eval_math_expr(pct_s.trim())?;
            let base = eval_math_expr(base_s.trim())?;
            let res = (pct / 100.0) * base;
            if res.is_finite() {
                let clean = format_clean_float(res);
                return Some(InstantAnswer {
                    kind: InstantAnswerKind::Calculation,
                    headline: trimmed.to_string(),
                    result: format!("= {}", clean),
                    copy_value: clean,
                    details: vec![("Formula".into(), format!("({} / 100) × {}", pct, base))],
                    color_preview_hex: None,
                });
            }
        }
    }

    // Require at least one operator, function, constant, factorial, or percent sign
    // so bare numbers like `42` or `2026` aren't hijacked as calculations.
    let has_math_cue = trimmed.contains(['+', '-', '*', '/', '%', '^', '(', ')', '!'])
        || trimmed.contains('×')
        || trimmed.contains('÷')
        || trimmed.contains('π')
        || matches!(lower.as_str(), "pi" | "tau" | "phi");
    if !has_math_cue {
        return None;
    }

    let val = eval_math_expr(trimmed)?;
    if !val.is_finite() {
        return None;
    }
    let clean = format_clean_float(val);
    Some(InstantAnswer {
        kind: InstantAnswerKind::Calculation,
        headline: trimmed.to_string(),
        result: format!("= {}", clean),
        copy_value: clean,
        details: Vec::new(),
        color_preview_hex: None,
    })
}

#[derive(Debug, Clone, PartialEq)]
enum MathToken {
    Number(f64),
    Ident(String),
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    Caret,
    Bang,
    LParen,
    RParen,
    Comma,
}

fn tokenize_math(input: &str) -> Option<Vec<MathToken>> {
    let chars: Vec<char> = input.chars().collect();
    let mut tokens = Vec::new();
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        if c.is_ascii_digit() || (c == '.' && i + 1 < chars.len() && chars[i + 1].is_ascii_digit())
        {
            let start = i;
            let mut saw_dot = c == '.';
            i += 1;
            while i < chars.len() {
                if chars[i].is_ascii_digit() {
                    i += 1;
                } else if chars[i] == '.' && !saw_dot {
                    saw_dot = true;
                    i += 1;
                } else if (chars[i] == 'e' || chars[i] == 'E')
                    && i + 1 < chars.len()
                    && (chars[i + 1].is_ascii_digit()
                        || ((chars[i + 1] == '+' || chars[i + 1] == '-')
                            && i + 2 < chars.len()
                            && chars[i + 2].is_ascii_digit()))
                {
                    i += 1;
                    if chars[i] == '+' || chars[i] == '-' {
                        i += 1;
                    }
                } else {
                    break;
                }
            }
            let s: String = chars[start..i].iter().collect();
            let v = s.parse::<f64>().ok()?;
            tokens.push(MathToken::Number(v));
            continue;
        }

        if c.is_ascii_alphabetic() || c == 'π' {
            if c == 'π' {
                tokens.push(MathToken::Ident("pi".into()));
                i += 1;
                continue;
            }
            let start = i;
            i += 1;
            while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            let ident: String = chars[start..i].iter().collect();
            tokens.push(MathToken::Ident(ident.to_ascii_lowercase()));
            continue;
        }

        match c {
            '+' => tokens.push(MathToken::Plus),
            '-' | '−' => tokens.push(MathToken::Minus),
            '*' | '×' => tokens.push(MathToken::Star),
            '/' | '÷' => tokens.push(MathToken::Slash),
            '%' => tokens.push(MathToken::Percent),
            '^' => tokens.push(MathToken::Caret),
            '!' => tokens.push(MathToken::Bang),
            '(' => tokens.push(MathToken::LParen),
            ')' => tokens.push(MathToken::RParen),
            ',' => tokens.push(MathToken::Comma),
            _ => return None,
        }
        i += 1;
    }

    Some(tokens)
}

struct MathParser<'a> {
    tokens: &'a [MathToken],
    pos: usize,
    depth: usize,
}

impl<'a> MathParser<'a> {
    fn peek(&self) -> Option<&MathToken> {
        self.tokens.get(self.pos)
    }

    fn next_tok(&mut self) -> Option<&MathToken> {
        let t = self.tokens.get(self.pos)?;
        self.pos += 1;
        Some(t)
    }

    /// Additive expression, including `85 + 20%` -> `85 * 1.2` and `100 - 15%` -> `85`.
    fn parse_expr(&mut self) -> Option<f64> {
        self.depth += 1;
        if self.depth > 64 {
            return None;
        }
        let mut lhs = self.parse_term()?;
        while let Some(tok) = self.peek().cloned() {
            match tok {
                MathToken::Plus | MathToken::Minus => {
                    self.next_tok();
                    let (rhs, was_pct) = self.parse_term_with_pct_flag()?;
                    if was_pct {
                        if tok == MathToken::Plus {
                            lhs += lhs * rhs;
                        } else {
                            lhs -= lhs * rhs;
                        }
                    } else if tok == MathToken::Plus {
                        lhs += rhs;
                    } else {
                        lhs -= rhs;
                    }
                }
                _ => break,
            }
        }
        self.depth -= 1;
        Some(lhs)
    }

    fn parse_term(&mut self) -> Option<f64> {
        self.parse_term_with_pct_flag().map(|(v, _)| v)
    }

    fn parse_term_with_pct_flag(&mut self) -> Option<(f64, bool)> {
        let (mut lhs, mut simple_pct) = self.parse_power_with_pct_flag()?;
        loop {
            match self.peek() {
                Some(MathToken::Star) => {
                    self.next_tok();
                    lhs *= self.parse_power()?;
                    simple_pct = false;
                }
                Some(MathToken::Slash) => {
                    self.next_tok();
                    let rhs = self.parse_power()?;
                    if rhs == 0.0 {
                        return None;
                    }
                    lhs /= rhs;
                    simple_pct = false;
                }
                Some(MathToken::Percent) => {
                    // Distinguish modulo `10 % 3` from postfix percent `20%`
                    if self.is_binary_modulo_ahead() {
                        self.next_tok();
                        let rhs = self.parse_power()?;
                        if rhs == 0.0 {
                            return None;
                        }
                        lhs %= rhs;
                        simple_pct = false;
                    } else {
                        break;
                    }
                }
                // Implicit multiplication: `2pi`, `2(3+4)`, `(2+1)(3+1)`
                Some(MathToken::LParen) | Some(MathToken::Ident(_)) => {
                    lhs *= self.parse_power()?;
                    simple_pct = false;
                }
                _ => break,
            }
        }
        Some((lhs, simple_pct))
    }

    fn is_binary_modulo_ahead(&self) -> bool {
        matches!(
            self.tokens.get(self.pos + 1),
            Some(MathToken::Number(_))
                | Some(MathToken::Ident(_))
                | Some(MathToken::LParen)
                | Some(MathToken::Minus)
                | Some(MathToken::Plus)
        )
    }

    fn parse_power(&mut self) -> Option<f64> {
        self.parse_power_with_pct_flag().map(|(v, _)| v)
    }

    fn parse_power_with_pct_flag(&mut self) -> Option<(f64, bool)> {
        let (base, is_pct) = self.parse_unary_with_pct_flag()?;
        if matches!(self.peek(), Some(MathToken::Caret)) {
            self.next_tok();
            let exp = self.parse_power()?; // right-associative
            return Some((base.powf(exp), false));
        }
        Some((base, is_pct))
    }

    fn parse_unary_with_pct_flag(&mut self) -> Option<(f64, bool)> {
        match self.peek() {
            Some(MathToken::Plus) => {
                self.next_tok();
                self.parse_unary_with_pct_flag()
            }
            Some(MathToken::Minus) => {
                self.next_tok();
                let (v, p) = self.parse_unary_with_pct_flag()?;
                Some((-v, p))
            }
            _ => self.parse_postfix(),
        }
    }

    fn parse_postfix(&mut self) -> Option<(f64, bool)> {
        let mut val = self.parse_primary()?;
        let mut is_pct = false;
        loop {
            match self.peek() {
                Some(MathToken::Bang) => {
                    self.next_tok();
                    val = compute_factorial(val)?;
                    is_pct = false;
                }
                Some(MathToken::Percent) if !self.is_binary_modulo_ahead() => {
                    self.next_tok();
                    val /= 100.0;
                    is_pct = true;
                }
                _ => break,
            }
        }
        Some((val, is_pct))
    }

    fn parse_primary(&mut self) -> Option<f64> {
        match self.next_tok()?.clone() {
            MathToken::Number(v) => Some(v),
            MathToken::LParen => {
                let inner = self.parse_expr()?;
                if matches!(self.next_tok(), Some(MathToken::RParen)) {
                    Some(inner)
                } else {
                    None
                }
            }
            MathToken::Ident(name) => {
                if matches!(self.peek(), Some(MathToken::LParen)) {
                    self.next_tok(); // consume '('
                    let mut args = Vec::new();
                    if !matches!(self.peek(), Some(MathToken::RParen)) {
                        loop {
                            args.push(self.parse_expr()?);
                            if matches!(self.peek(), Some(MathToken::Comma)) {
                                self.next_tok();
                            } else {
                                break;
                            }
                        }
                    }
                    if !matches!(self.next_tok(), Some(MathToken::RParen)) {
                        return None;
                    }
                    eval_math_func(&name, &args)
                } else {
                    match name.as_str() {
                        "pi" => Some(std::f64::consts::PI),
                        "e" => Some(std::f64::consts::E),
                        "tau" => Some(std::f64::consts::TAU),
                        "phi" => Some(1.618_033_988_749_895),
                        _ => None,
                    }
                }
            }
            _ => None,
        }
    }
}

fn compute_factorial(v: f64) -> Option<f64> {
    if v < 0.0 || v > 170.0 || (v - v.round()).abs() > 1e-9 {
        return None;
    }
    let n = v.round() as u32;
    let mut acc = 1.0_f64;
    for k in 2..=n {
        acc *= k as f64;
    }
    Some(acc)
}

fn eval_math_func(name: &str, args: &[f64]) -> Option<f64> {
    match (name, args.len()) {
        ("sqrt", 1) if args[0] >= 0.0 => Some(args[0].sqrt()),
        ("cbrt", 1) => Some(args[0].cbrt()),
        ("sin", 1) => Some(args[0].sin()),
        ("cos", 1) => Some(args[0].cos()),
        ("tan", 1) => Some(args[0].tan()),
        ("asin", 1) => Some(args[0].asin()),
        ("acos", 1) => Some(args[0].acos()),
        ("atan", 1) => Some(args[0].atan()),
        ("sinh", 1) => Some(args[0].sinh()),
        ("cosh", 1) => Some(args[0].cosh()),
        ("tanh", 1) => Some(args[0].tanh()),
        ("ln", 1) if args[0] > 0.0 => Some(args[0].ln()),
        ("log10" | "log", 1) if args[0] > 0.0 => Some(args[0].log10()),
        ("log2", 1) if args[0] > 0.0 => Some(args[0].log2()),
        ("exp", 1) => Some(args[0].exp()),
        ("abs", 1) => Some(args[0].abs()),
        ("floor", 1) => Some(args[0].floor()),
        ("ceil", 1) => Some(args[0].ceil()),
        ("round", 1) => Some(args[0].round()),
        ("rad", 1) => Some(args[0].to_radians()),
        ("deg", 1) => Some(args[0].to_degrees()),
        ("pow", 2) => Some(args[0].powf(args[1])),
        ("min", n) if n >= 1 => args.iter().copied().reduce(f64::min),
        ("max", n) if n >= 1 => args.iter().copied().reduce(f64::max),
        _ => None,
    }
}

/// Evaluates a scientific math expression cleanly using recursive descent parsing.
pub fn eval_math_expr(expr: &str) -> Option<f64> {
    let tokens = tokenize_math(expr)?;
    if tokens.is_empty() {
        return None;
    }
    let mut parser = MathParser {
        tokens: &tokens,
        pos: 0,
        depth: 0,
    };
    let val = parser.parse_expr()?;
    if parser.pos != tokens.len() || !val.is_finite() {
        return None;
    }
    Some(val)
}

fn format_clean_float(val: f64) -> String {
    if !val.is_finite() {
        return val.to_string();
    }
    let rounded_int = val.round();
    if (val - rounded_int).abs() < 1e-10 && rounded_int.abs() < 1e15 {
        return format!("{}", rounded_int as i64);
    }
    // Round to 10 significant decimal digits to suppress IEEE-754 representation dust (e.g. 0.30000000000000004)
    let s = format!("{:.10}", val);
    let trimmed = s.trim_end_matches('0').trim_end_matches('.');
    if trimmed == "-0" {
        "0".to_string()
    } else {
        trimmed.to_string()
    }
}

// ============================================================================
// Pure-Rust ISO/IEC 18004 QR Code Encoder (Versions 1–10, Byte Mode, L/M) -> SVG
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QrEcLevel {
    /// ~7% error recovery capacity
    L,
    /// ~15% error recovery capacity
    M,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QrMatrix {
    pub version: u8,
    pub size: usize,
    pub modules: Vec<bool>,
}

impl QrMatrix {
    pub fn get(&self, x: usize, y: usize) -> bool {
        self.modules[y * self.size + x]
    }
}

struct QrVersionSpec {
    version: u8,
    total_codewords: usize,
    ec_per_block_l: usize,
    blocks_l: (usize, usize), // (group1_blocks, group2_blocks)
    ec_per_block_m: usize,
    blocks_m: (usize, usize),
    alignment_centers: &'static [usize],
}

// ISO/IEC 18004 Table 9 specs for Versions 1..=10 (EC levels L and M)
const QR_SPECS: &[QrVersionSpec] = &[
    QrVersionSpec { version: 1, total_codewords: 26, ec_per_block_l: 7, blocks_l: (1, 0), ec_per_block_m: 10, blocks_m: (1, 0), alignment_centers: &[] },
    QrVersionSpec { version: 2, total_codewords: 44, ec_per_block_l: 10, blocks_l: (1, 0), ec_per_block_m: 16, blocks_m: (1, 0), alignment_centers: &[6, 18] },
    QrVersionSpec { version: 3, total_codewords: 70, ec_per_block_l: 15, blocks_l: (1, 0), ec_per_block_m: 26, blocks_m: (1, 0), alignment_centers: &[6, 22] },
    QrVersionSpec { version: 4, total_codewords: 100, ec_per_block_l: 20, blocks_l: (1, 0), ec_per_block_m: 18, blocks_m: (2, 0), alignment_centers: &[6, 26] },
    QrVersionSpec { version: 5, total_codewords: 134, ec_per_block_l: 26, blocks_l: (1, 0), ec_per_block_m: 24, blocks_m: (2, 0), alignment_centers: &[6, 30] },
    QrVersionSpec { version: 6, total_codewords: 172, ec_per_block_l: 18, blocks_l: (2, 0), ec_per_block_m: 16, blocks_m: (4, 0), alignment_centers: &[6, 34] },
    QrVersionSpec { version: 7, total_codewords: 196, ec_per_block_l: 20, blocks_l: (2, 0), ec_per_block_m: 18, blocks_m: (4, 0), alignment_centers: &[6, 22, 38] },
    QrVersionSpec { version: 8, total_codewords: 242, ec_per_block_l: 24, blocks_l: (2, 0), ec_per_block_m: 22, blocks_m: (2, 2), alignment_centers: &[6, 24, 42] },
    QrVersionSpec { version: 9, total_codewords: 292, ec_per_block_l: 30, blocks_l: (2, 0), ec_per_block_m: 22, blocks_m: (3, 2), alignment_centers: &[6, 26, 46] },
    QrVersionSpec { version: 10, total_codewords: 346, ec_per_block_l: 18, blocks_l: (2, 2), ec_per_block_m: 26, blocks_m: (4, 1), alignment_centers: &[6, 28, 50] },
];

fn gf_mul(a: u8, b: u8) -> u8 {
    let mut x = a as u16;
    let mut y = b as u16;
    let mut res = 0u16;
    while y > 0 {
        if (y & 1) != 0 {
            res ^= x;
        }
        x <<= 1;
        if (x & 0x100) != 0 {
            x ^= 0x11D; // primitive polynomial x^8 + x^4 + x^3 + x^2 + 1
        }
        y >>= 1;
    }
    res as u8
}

fn rs_compute_remainder(data: &[u8], degree: usize) -> Vec<u8> {
    // Build generator polynomial in descending degree order (monic, omitting leading 1)
    let mut gen = vec![1u8];
    let mut root = 1u8;
    for _ in 0..degree {
        let mut next = vec![0u8; gen.len() + 1];
        for (i, &c) in gen.iter().enumerate() {
            next[i] ^= c;
            next[i + 1] ^= gf_mul(c, root);
        }
        gen = next;
        root = gf_mul(root, 0x02);
    }

    let mut rem = vec![0u8; degree];
    for &b in data {
        let factor = b ^ rem[0];
        rem.rotate_left(1);
        rem[degree - 1] = 0;
        for (i, &g) in gen[1..].iter().enumerate() {
            rem[i] ^= gf_mul(g, factor);
        }
    }
    rem
}

/// Encodes `data` into a standard QR Code bit matrix (Byte mode, Versions 1–10).
pub fn encode_qr_matrix(data: &str, ec_level: QrEcLevel) -> Result<QrMatrix, OmniboxError> {
    let payload = data.as_bytes();

    // Select smallest version that fits Byte mode header (4 mode + char_count bits + 8*len)
    let chosen = QR_SPECS
        .iter()
        .find(|spec| {
            let (ec_per_blk, (g1, g2)) = match ec_level {
                QrEcLevel::L => (spec.ec_per_block_l, spec.blocks_l),
                QrEcLevel::M => (spec.ec_per_block_m, spec.blocks_m),
            };
            let total_blocks = g1 + g2;
            let data_codewords = spec.total_codewords - ec_per_blk * total_blocks;
            let count_bits = if spec.version <= 9 { 8 } else { 16 };
            let required_bits = 4 + count_bits + payload.len() * 8;
            required_bits <= data_codewords * 8
        })
        .ok_or(OmniboxError::QrPayloadTooLarge(payload.len()))?;

    let version = chosen.version;
    let size = (version as usize) * 4 + 17;
    let (ec_per_blk, (g1, g2)) = match ec_level {
        QrEcLevel::L => (chosen.ec_per_block_l, chosen.blocks_l),
        QrEcLevel::M => (chosen.ec_per_block_m, chosen.blocks_m),
    };
    let total_blocks = g1 + g2;
    let total_data_cw = chosen.total_codewords - ec_per_blk * total_blocks;

    // 1. Build bit stream: Mode 0100 (Byte), Char count, Data bytes, Terminator, Pad bytes
    let mut bits: Vec<bool> = Vec::with_capacity(total_data_cw * 8);
    push_bits(&mut bits, 0b0100, 4);
    let count_bits = if version <= 9 { 8 } else { 16 };
    push_bits(&mut bits, payload.len() as u32, count_bits);
    for &b in payload {
        push_bits(&mut bits, b as u32, 8);
    }
    let capacity_bits = total_data_cw * 8;
    let term_len = (capacity_bits - bits.len()).min(4);
    push_bits(&mut bits, 0, term_len);
    while bits.len() % 8 != 0 {
        bits.push(false);
    }
    let mut data_codewords = Vec::with_capacity(total_data_cw);
    for chunk in bits.chunks_exact(8) {
        let mut byte = 0u8;
        for &bit in chunk {
            byte = (byte << 1) | u8::from(bit);
        }
        data_codewords.push(byte);
    }
    let pad_cycle = [0xECu8, 0x11u8];
    let mut pad_i = 0;
    while data_codewords.len() < total_data_cw {
        data_codewords.push(pad_cycle[pad_i & 1]);
        pad_i += 1;
    }

    // 2. Split into blocks, compute Reed-Solomon EC codewords, and interleave
    let short_block_len = total_data_cw / total_blocks;
    let mut data_blocks: Vec<Vec<u8>> = Vec::with_capacity(total_blocks);
    let mut ec_blocks: Vec<Vec<u8>> = Vec::with_capacity(total_blocks);
    let mut offset = 0usize;
    for blk_idx in 0..total_blocks {
        let blk_len = if blk_idx < g1 {
            short_block_len
        } else {
            short_block_len + 1
        };
        let slice = &data_codewords[offset..offset + blk_len];
        offset += blk_len;
        ec_blocks.push(rs_compute_remainder(slice, ec_per_blk));
        data_blocks.push(slice.to_vec());
    }

    let mut interleaved: Vec<u8> = Vec::with_capacity(chosen.total_codewords);
    let max_data_blk_len = data_blocks.iter().map(|b| b.len()).max().unwrap_or(0);
    for i in 0..max_data_blk_len {
        for blk in &data_blocks {
            if i < blk.len() {
                interleaved.push(blk[i]);
            }
        }
    }
    for i in 0..ec_per_blk {
        for ec in &ec_blocks {
            interleaved.push(ec[i]);
        }
    }

    // 3. Draw function patterns & reserve format/version areas
    let mut base_modules = vec![false; size * size];
    let mut is_function = vec![false; size * size];

    // Timing patterns
    for i in 0..size {
        set_fn_module(&mut base_modules, &mut is_function, size, 6, i, i % 2 == 0);
        set_fn_module(&mut base_modules, &mut is_function, size, i, 6, i % 2 == 0);
    }

    // Finder patterns + 1-module separators
    draw_finder(&mut base_modules, &mut is_function, size, 3, 3);
    draw_finder(&mut base_modules, &mut is_function, size, size - 4, 3);
    draw_finder(&mut base_modules, &mut is_function, size, 3, size - 4);

    // Alignment patterns (Versions >= 2)
    let centers = chosen.alignment_centers;
    for (ri, &cy) in centers.iter().enumerate() {
        for (ci, &cx) in centers.iter().enumerate() {
            // Skip the 3 corners occupied by finder patterns
            let is_finder_corner = (ri == 0 && ci == 0)
                || (ri == 0 && ci == centers.len() - 1)
                || (ri == centers.len() - 1 && ci == 0);
            if !is_finder_corner {
                draw_alignment(&mut base_modules, &mut is_function, size, cx, cy);
            }
        }
    }

    // Reserve format info cells (values filled per mask below)
    draw_format_bits(&mut base_modules, &mut is_function, size, ec_level, 0);

    // Version info for Versions >= 7
    if version >= 7 {
        draw_version_bits(&mut base_modules, &mut is_function, size, version);
    }

    // 4. Zig-zag bit placement
    let mut bit_idx = 0usize;
    let total_bits = interleaved.len() * 8;
    let mut right = (size as isize) - 1;
    let mut upward = true;
    while right >= 1 {
        if right == 6 {
            right -= 1; // skip vertical timing column
        }
        for vert in 0..size {
            let y = if upward { size - 1 - vert } else { vert };
            for dx in 0..2 {
                let x = (right - dx) as usize;
                if !is_function[y * size + x] {
                    let dark = if bit_idx < total_bits {
                        ((interleaved[bit_idx >> 3] >> (7 - (bit_idx & 7))) & 1) != 0
                    } else {
                        false
                    };
                    base_modules[y * size + x] = dark;
                    bit_idx += 1;
                }
            }
        }
        upward = !upward;
        right -= 2;
    }

    // 5. Evaluate all 8 standard masks and pick the lowest penalty
    let mut best_modules = base_modules.clone();
    let mut best_penalty = u32::MAX;

    for mask in 0u8..8 {
        let mut candidate = base_modules.clone();
        for y in 0..size {
            for x in 0..size {
                if !is_function[y * size + x] && qr_mask_bit(mask, x, y) {
                    candidate[y * size + x] = !candidate[y * size + x];
                }
            }
        }
        let mut dummy_fn = is_function.clone();
        draw_format_bits(&mut candidate, &mut dummy_fn, size, ec_level, mask);
        let penalty = qr_penalty_score(&candidate, size);
        if penalty < best_penalty {
            best_penalty = penalty;
            best_modules = candidate;
        }
    }

    Ok(QrMatrix {
        version,
        size,
        modules: best_modules,
    })
}

fn push_bits(bits: &mut Vec<bool>, val: u32, len: usize) {
    for i in (0..len).rev() {
        bits.push(((val >> i) & 1) != 0);
    }
}

fn set_fn_module(
    modules: &mut [bool],
    is_fn: &mut [bool],
    size: usize,
    x: usize,
    y: usize,
    dark: bool,
) {
    modules[y * size + x] = dark;
    is_fn[y * size + x] = true;
}

fn draw_finder(modules: &mut [bool], is_fn: &mut [bool], size: usize, cx: usize, cy: usize) {
    for dy in -4isize..=4 {
        for dx in -4isize..=4 {
            let x = cx as isize + dx;
            let y = cy as isize + dy;
            if x >= 0 && x < size as isize && y >= 0 && y < size as isize {
                let dist = dx.abs().max(dy.abs());
                let dark = dist != 2 && dist != 4;
                set_fn_module(modules, is_fn, size, x as usize, y as usize, dark);
            }
        }
    }
}

fn draw_alignment(modules: &mut [bool], is_fn: &mut [bool], size: usize, cx: usize, cy: usize) {
    for dy in -2isize..=2 {
        for dx in -2isize..=2 {
            let dist = dx.abs().max(dy.abs());
            let dark = dist != 1;
            set_fn_module(
                modules,
                is_fn,
                size,
                (cx as isize + dx) as usize,
                (cy as isize + dy) as usize,
                dark,
            );
        }
    }
}

fn draw_format_bits(
    modules: &mut [bool],
    is_fn: &mut [bool],
    size: usize,
    ec_level: QrEcLevel,
    mask: u8,
) {
    let ec_bits: u32 = match ec_level {
        QrEcLevel::L => 0b01,
        QrEcLevel::M => 0b00,
    };
    let data = (ec_bits << 3) | (mask as u32 & 0b111);
    let mut rem = data;
    for _ in 0..10 {
        rem = (rem << 1) ^ ((rem >> 9) * 0x537);
    }
    let bits = ((data << 10) | rem) ^ 0x5412;

    // First copy around top-left finder
    for i in 0..=5 {
        set_fn_module(modules, is_fn, size, 8, i, ((bits >> i) & 1) != 0);
    }
    set_fn_module(modules, is_fn, size, 8, 7, ((bits >> 6) & 1) != 0);
    set_fn_module(modules, is_fn, size, 8, 8, ((bits >> 7) & 1) != 0);
    set_fn_module(modules, is_fn, size, 7, 8, ((bits >> 8) & 1) != 0);
    for i in 9..15 {
        set_fn_module(modules, is_fn, size, 14 - i, 8, ((bits >> i) & 1) != 0);
    }

    // Second copy around bottom-left and top-right finders
    for i in 0..8 {
        set_fn_module(modules, is_fn, size, size - 1 - i, 8, ((bits >> i) & 1) != 0);
    }
    for i in 8..15 {
        set_fn_module(modules, is_fn, size, 8, size - 15 + i, ((bits >> i) & 1) != 0);
    }
    // Fixed dark module
    set_fn_module(modules, is_fn, size, 8, size - 8, true);
}

fn draw_version_bits(modules: &mut [bool], is_fn: &mut [bool], size: usize, version: u8) {
    let mut rem = version as u32;
    for _ in 0..12 {
        rem = (rem << 1) ^ ((rem >> 11) * 0x1F25);
    }
    let bits = ((version as u32) << 12) | rem;
    for i in 0..18 {
        let dark = ((bits >> i) & 1) != 0;
        let a = size - 11 + (i % 3);
        let b = i / 3;
        set_fn_module(modules, is_fn, size, a, b, dark);
        set_fn_module(modules, is_fn, size, b, a, dark);
    }
}

fn qr_mask_bit(mask: u8, x: usize, y: usize) -> bool {
    match mask {
        0 => (x + y) % 2 == 0,
        1 => y % 2 == 0,
        2 => x % 3 == 0,
        3 => (x + y) % 3 == 0,
        4 => ((y / 2) + (x / 3)) % 2 == 0,
        5 => ((x * y) % 2) + ((x * y) % 3) == 0,
        6 => (((x * y) % 2) + ((x * y) % 3)) % 2 == 0,
        7 => (((x + y) % 2) + ((x * y) % 3)) % 2 == 0,
        _ => false,
    }
}

fn qr_penalty_score(modules: &[bool], size: usize) -> u32 {
    let mut penalty = 0u32;

    // Rule 1: 5+ consecutive same-color modules in rows & columns
    for y in 0..size {
        let mut run_color = modules[y * size];
        let mut run_len = 1u32;
        for x in 1..size {
            let c = modules[y * size + x];
            if c == run_color {
                run_len += 1;
                if run_len == 5 {
                    penalty += 3;
                } else if run_len > 5 {
                    penalty += 1;
                }
            } else {
                run_color = c;
                run_len = 1;
            }
        }
    }
    for x in 0..size {
        let mut run_color = modules[x];
        let mut run_len = 1u32;
        for y in 1..size {
            let c = modules[y * size + x];
            if c == run_color {
                run_len += 1;
                if run_len == 5 {
                    penalty += 3;
                } else if run_len > 5 {
                    penalty += 1;
                }
            } else {
                run_color = c;
                run_len = 1;
            }
        }
    }

    // Rule 2: 2x2 blocks of same color
    for y in 0..size - 1 {
        for x in 0..size - 1 {
            let c = modules[y * size + x];
            if c == modules[y * size + x + 1]
                && c == modules[(y + 1) * size + x]
                && c == modules[(y + 1) * size + x + 1]
            {
                penalty += 3;
            }
        }
    }

    // Rule 3: Finder-like 1:1:3:1:1 patterns
    const PAT_A: [bool; 11] = [true, false, true, true, true, false, true, false, false, false, false];
    const PAT_B: [bool; 11] = [false, false, false, false, true, false, true, true, true, false, true];
    for y in 0..size {
        for x in 0..=size.saturating_sub(11) {
            let slice = &modules[y * size + x..y * size + x + 11];
            if slice == PAT_A || slice == PAT_B {
                penalty += 40;
            }
        }
    }
    for x in 0..size {
        for y in 0..=size.saturating_sub(11) {
            let mut match_a = true;
            let mut match_b = true;
            for k in 0..11 {
                let v = modules[(y + k) * size + x];
                if v != PAT_A[k] {
                    match_a = false;
                }
                if v != PAT_B[k] {
                    match_b = false;
                }
            }
            if match_a || match_b {
                penalty += 40;
            }
        }
    }

    // Rule 4: Dark/light balance deviation from 50%
    let dark_count = modules.iter().filter(|&&m| m).count();
    let total = size * size;
    let pct_diff = ((dark_count as i32 * 200 - total as i32 * 100).abs()) / (total as i32 * 10);
    penalty += (pct_diff as u32) * 10;

    penalty
}

/// Encodes `data` into a crisp, self-contained, offline SVG QR Code (quiet zone = 4 modules).
/// Automatically falls back from EC Level M to EC Level L for longer URLs.
pub fn generate_qr_svg(data: &str) -> String {
    let matrix = encode_qr_matrix(data, QrEcLevel::M)
        .or_else(|_| encode_qr_matrix(data, QrEcLevel::L))
        .unwrap_or_else(|_| {
            // Safely truncate to max UTF-8 boundary that fits Version 10-L (~271 bytes)
            let mut end = data.len().min(270);
            while end > 0 && !data.is_char_boundary(end) {
                end -= 1;
            }
            encode_qr_matrix(&data[..end], QrEcLevel::L).expect("truncated QR must encode")
        });

    let quiet = 4usize;
    let dim = matrix.size + quiet * 2;
    let mut path = String::with_capacity(matrix.size * matrix.size * 4);
    for y in 0..matrix.size {
        let mut x = 0;
        while x < matrix.size {
            if matrix.get(x, y) {
                let run_start = x;
                while x < matrix.size && matrix.get(x, y) {
                    x += 1;
                }
                let run_len = x - run_start;
                path.push_str(&format!(
                    "M{},{}h{}v1h-{}z",
                    run_start + quiet,
                    y + quiet,
                    run_len,
                    run_len
                ));
            } else {
                x += 1;
            }
        }
    }

    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {dim} {dim}" shape-rendering="crispEdges" role="img" aria-label="QR Code"><rect width="{dim}" height="{dim}" fill="#FFFFFF"/><path d="{path}" fill="#000000"/></svg>"##,
        dim = dim,
        path = path
    )
}

// ============================================================================
// Unified Omnibox Query Engine (`OmniboxEngine`)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OmniboxOpenTab {
    pub tab_id: String,
    pub title: String,
    pub url: String,
    #[serde(default)]
    pub favicon_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OmniboxHistoryCandidate {
    pub url: String,
    pub title: String,
    pub visit_count: u32,
    pub typed_count: u32,
    pub last_visit_unix: u64,
    #[serde(default)]
    pub favicon_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OmniboxBookmarkCandidate {
    pub id: String,
    pub title: String,
    pub url: String,
    #[serde(default)]
    pub nickname: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub visit_count: u32,
    #[serde(default)]
    pub last_visited_unix: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OmniboxSettingCandidate {
    pub key: String,
    pub label: String,
    pub category: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OmniboxExtensionCandidate {
    pub id: String,
    pub name: String,
    pub description: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Default)]
pub struct OmniboxQueryContext {
    pub open_tabs: Vec<OmniboxOpenTab>,
    pub history: Vec<OmniboxHistoryCandidate>,
    pub bookmarks: Vec<OmniboxBookmarkCandidate>,
    pub settings: Vec<OmniboxSettingCandidate>,
    pub extensions: Vec<OmniboxExtensionCandidate>,
    pub remote_suggestions: Vec<String>,
    pub is_private: bool,
    pub now_unix: u64,
    pub max_results: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OmniboxItemKind {
    NavigateUrl,
    Search,
    BangSearch,
    InstantAnswer,
    SwitchToTab,
    History,
    Bookmark,
    QuickAction,
    Setting,
    Extension,
    SearchSuggestion,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OmniboxItem {
    pub kind: OmniboxItemKind,
    pub title: String,
    pub subtitle: String,
    pub url: Option<String>,
    pub tab_id: Option<String>,
    pub quick_action: Option<QuickActionKind>,
    pub favicon_url: Option<String>,
    pub score: f64,
    pub match_indices: Vec<usize>,
    pub is_bookmark: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OmniboxResponse {
    pub input_kind: OmniboxInputKind,
    pub inline_completion: Option<String>,
    pub items: Vec<OmniboxItem>,
    pub tab_to_search_hint: Option<TabToSearchHint>,
    pub active_scope: Option<OmniboxScope>,
    pub instant_answer: Option<InstantAnswer>,
}

#[derive(Debug, Clone, Default)]
pub struct OmniboxEngine {
    pub search_engines: SearchEngineRegistry,
    pub fx_rates: FxRatesCache,
}

impl OmniboxEngine {
    pub fn new(search_engines: SearchEngineRegistry, fx_rates: FxRatesCache) -> Self {
        Self {
            search_engines,
            fx_rates,
        }
    }

    /// Merges all sources (instant answers, URL/bang classification, scoped search,
    /// open tabs, bookmarks, history frecency, quick actions, remote suggestions) into
    /// a ranked `OmniboxResponse`.
    pub fn query(&self, raw_input: &str, ctx: &OmniboxQueryContext) -> OmniboxResponse {
        let now_unix = if ctx.now_unix == 0 {
            current_unix_secs()
        } else {
            ctx.now_unix
        };
        let max_results = if ctx.max_results == 0 {
            10
        } else {
            ctx.max_results
        };

        let trimmed = raw_input.trim();
        let input_kind = classify_omnibox_input(trimmed);
        let tab_to_search_hint = self.search_engines.find_tab_to_search_hint(trimmed);

        let mut active_scope: Option<OmniboxScope> = None;
        let effective_query: String;

        match &input_kind {
            OmniboxInputKind::ScopedQuery { scope, query } => {
                active_scope = Some(*scope);
                effective_query = query.clone();
            }
            _ => {
                effective_query = trimmed.to_string();
            }
        }

        let instant_answer = if active_scope.is_none() {
            evaluate_instant_answer_with_fx(trimmed, &self.fx_rates, now_unix)
        } else {
            None
        };

        let mut items: Vec<OmniboxItem> = Vec::new();
        let mut seen_urls: HashSet<String> = HashSet::new();

        // 1. Instant answer top item
        if let Some(ref ans) = instant_answer {
            items.push(OmniboxItem {
                kind: OmniboxItemKind::InstantAnswer,
                title: ans.result.clone(),
                subtitle: ans.headline.clone(),
                url: None,
                tab_id: None,
                quick_action: None,
                favicon_url: None,
                score: 10_000.0,
                match_indices: Vec::new(),
                is_bookmark: false,
            });
        }

        // 2. Primary action for classified non-scoped input
        if active_scope.is_none() && !trimmed.is_empty() {
            match &input_kind {
                OmniboxInputKind::DirectUrl { normalized_url }
                | OmniboxInputKind::LocalHostOrIp { normalized_url } => {
                    seen_urls.insert(normalized_url.to_ascii_lowercase());
                    items.push(OmniboxItem {
                        kind: OmniboxItemKind::NavigateUrl,
                        title: trimmed.to_string(),
                        subtitle: format!("Go to {}", normalized_url),
                        url: Some(normalized_url.clone()),
                        tab_id: None,
                        quick_action: None,
                        favicon_url: None,
                        score: 9_500.0,
                        match_indices: Vec::new(),
                        is_bookmark: false,
                    });
                }
                OmniboxInputKind::InternalUrl { scheme, target } => {
                    let full = if scheme == "about" {
                        format!("about:{}", target)
                    } else {
                        format!("{}://{}", scheme, target)
                    };
                    seen_urls.insert(full.to_ascii_lowercase());
                    items.push(OmniboxItem {
                        kind: OmniboxItemKind::NavigateUrl,
                        title: full.clone(),
                        subtitle: "Singularity internal page".into(),
                        url: Some(full),
                        tab_id: None,
                        quick_action: None,
                        favicon_url: None,
                        score: 9_600.0,
                        match_indices: Vec::new(),
                        is_bookmark: false,
                    });
                }
                OmniboxInputKind::ViewSource { inner_url } => {
                    let full = format!("view-source:{}", inner_url);
                    items.push(OmniboxItem {
                        kind: OmniboxItemKind::NavigateUrl,
                        title: full.clone(),
                        subtitle: "Inspect page source".into(),
                        url: Some(full),
                        tab_id: None,
                        quick_action: None,
                        favicon_url: None,
                        score: 9_600.0,
                        match_indices: Vec::new(),
                        is_bookmark: false,
                    });
                }
                OmniboxInputKind::BangQuery { bang, query } => {
                    if let Some((engine_name, url)) = self.search_engines.resolve_bang(bang, query)
                    {
                        items.push(OmniboxItem {
                            kind: OmniboxItemKind::BangSearch,
                            title: if query.is_empty() {
                                format!("Search {}", engine_name)
                            } else {
                                format!("Search {} for \"{}\"", engine_name, query)
                            },
                            subtitle: format!("!{} · {}", bang, engine_name),
                            url: Some(url),
                            tab_id: None,
                            quick_action: None,
                            favicon_url: None,
                            score: 9_800.0,
                            match_indices: Vec::new(),
                            is_bookmark: false,
                        });
                    }
                }
                OmniboxInputKind::SearchQuery { query } => {
                    let engine_name = self
                        .search_engines
                        .default_engine(ctx.is_private)
                        .map(|e| e.name.as_str())
                        .unwrap_or("Search");
                    let url = self.search_engines.build_search_url(query, ctx.is_private);
                    items.push(OmniboxItem {
                        kind: OmniboxItemKind::Search,
                        title: query.clone(),
                        subtitle: format!("Search with {}", engine_name),
                        url: Some(url),
                        tab_id: None,
                        quick_action: None,
                        favicon_url: None,
                        score: 2_000.0,
                        match_indices: Vec::new(),
                        is_bookmark: false,
                    });
                }
                OmniboxInputKind::InstantAnswer { .. } | OmniboxInputKind::ScopedQuery { .. } => {}
            }
        }

        // 3. Open Tabs (in Tabs scope or global search)
        if active_scope.is_none() || active_scope == Some(OmniboxScope::Tabs) {
            for tab in &ctx.open_tabs {
                let matched = if effective_query.is_empty() {
                    Some((500, Vec::new()))
                } else {
                    best_fuzzy_pair(&effective_query, &tab.title, &tab.url)
                };
                if let Some((fscore, indices)) = matched {
                    items.push(OmniboxItem {
                        kind: OmniboxItemKind::SwitchToTab,
                        title: tab.title.clone(),
                        subtitle: format!("Switch to tab · {}", tab.url),
                        url: Some(tab.url.clone()),
                        tab_id: Some(tab.tab_id.clone()),
                        quick_action: None,
                        favicon_url: tab.favicon_url.clone(),
                        score: 4_500.0 + fscore as f64,
                        match_indices: indices,
                        is_bookmark: false,
                    });
                }
            }
        }

        // 4. Bookmarks
        let mut bookmark_urls: HashSet<String> = HashSet::new();
        for bm in &ctx.bookmarks {
            bookmark_urls.insert(bm.url.to_ascii_lowercase());
        }

        if active_scope.is_none() || active_scope == Some(OmniboxScope::Bookmarks) {
            for bm in &ctx.bookmarks {
                // Exact nickname match gets huge priority
                let nickname_exact = bm
                    .nickname
                    .as_deref()
                    .map_or(false, |n| !n.is_empty() && n.eq_ignore_ascii_case(&effective_query));
                let matched = if effective_query.is_empty() {
                    Some((300, Vec::new()))
                } else if nickname_exact {
                    Some((1200, Vec::new()))
                } else {
                    best_fuzzy_pair(&effective_query, &bm.title, &bm.url)
                };

                if let Some((fscore, indices)) = matched {
                    let age = now_unix.saturating_sub(bm.last_visited_unix.unwrap_or(0));
                    let frecency = compute_frecency(bm.visit_count, 0, age, true);
                    let norm_url = bm.url.to_ascii_lowercase();
                    if seen_urls.insert(norm_url) {
                        items.push(OmniboxItem {
                            kind: OmniboxItemKind::Bookmark,
                            title: bm.title.clone(),
                            subtitle: bm.url.clone(),
                            url: Some(bm.url.clone()),
                            tab_id: None,
                            quick_action: None,
                            favicon_url: None,
                            score: 3_000.0 + frecency * 4.0 + fscore as f64 * 5.0,
                            match_indices: indices,
                            is_bookmark: true,
                        });
                    }
                }
            }
        }

        // 5. History
        let mut best_inline: Option<(f64, String)> = None;
        if active_scope.is_none() || active_scope == Some(OmniboxScope::History) {
            for h in &ctx.history {
                let matched = if effective_query.is_empty() {
                    Some((200, Vec::new()))
                } else {
                    best_fuzzy_pair(&effective_query, &h.title, &h.url)
                };
                if let Some((fscore, indices)) = matched {
                    let age = now_unix.saturating_sub(h.last_visit_unix);
                    let is_bm = bookmark_urls.contains(&h.url.to_ascii_lowercase());
                    let frecency = compute_frecency(h.visit_count, h.typed_count, age, is_bm);
                    let total_score = 2_500.0 + frecency * 5.0 + fscore as f64 * 4.0;

                    // Compute inline URL autocompletion when user typed a clean host prefix
                    if active_scope.is_none()
                        && trimmed.len() >= 2
                        && !trimmed.contains(char::is_whitespace)
                    {
                        let stripped_url = h
                            .url
                            .trim_start_matches("https://")
                            .trim_start_matches("http://")
                            .trim_start_matches("www.");
                        let lower_in = trimmed.to_ascii_lowercase();
                        if stripped_url.to_ascii_lowercase().starts_with(&lower_in)
                            && stripped_url.len() > trimmed.len()
                        {
                            let completion = format!("{}{}", trimmed, &stripped_url[trimmed.len()..]);
                            if best_inline.as_ref().map_or(true, |(s, _)| total_score > *s) {
                                best_inline = Some((total_score, completion));
                            }
                        }
                    }

                    if seen_urls.insert(h.url.to_ascii_lowercase()) {
                        items.push(OmniboxItem {
                            kind: OmniboxItemKind::History,
                            title: h.title.clone(),
                            subtitle: h.url.clone(),
                            url: Some(h.url.clone()),
                            tab_id: None,
                            quick_action: None,
                            favicon_url: h.favicon_url.clone(),
                            score: total_score,
                            match_indices: indices,
                            is_bookmark: is_bm,
                        });
                    }
                }
            }
        }

        // 6. Settings scope
        if active_scope == Some(OmniboxScope::Settings) {
            for s in &ctx.settings {
                let matched = if effective_query.is_empty() {
                    Some((200, Vec::new()))
                } else {
                    best_fuzzy_pair(&effective_query, &s.label, &s.key)
                };
                if let Some((fscore, indices)) = matched {
                    items.push(OmniboxItem {
                        kind: OmniboxItemKind::Setting,
                        title: s.label.clone(),
                        subtitle: format!("{} · {}", s.category, s.key),
                        url: Some(format!("singularity://settings#{}", s.key)),
                        tab_id: None,
                        quick_action: None,
                        favicon_url: None,
                        score: 3_500.0 + fscore as f64 * 4.0,
                        match_indices: indices,
                        is_bookmark: false,
                    });
                }
            }
        }

        // 7. Extensions scope
        if active_scope == Some(OmniboxScope::Extensions) {
            for ext in &ctx.extensions {
                let matched = if effective_query.is_empty() {
                    Some((200, Vec::new()))
                } else {
                    best_fuzzy_pair(&effective_query, &ext.name, &ext.description)
                };
                if let Some((fscore, indices)) = matched {
                    let state = if ext.enabled { "Enabled" } else { "Disabled" };
                    items.push(OmniboxItem {
                        kind: OmniboxItemKind::Extension,
                        title: ext.name.clone(),
                        subtitle: format!("{} · {}", state, ext.description),
                        url: Some(format!("singularity://extensions#{}", ext.id)),
                        tab_id: None,
                        quick_action: None,
                        favicon_url: None,
                        score: 3_500.0 + fscore as f64 * 4.0,
                        match_indices: indices,
                        is_bookmark: false,
                    });
                }
            }
        }

        // 8. Quick Actions EN/FR (when not in narrow non-matching scope)
        if active_scope.is_none() && !trimmed.is_empty() {
            for qa in match_quick_actions(trimmed).into_iter().take(2) {
                items.push(OmniboxItem {
                    kind: OmniboxItemKind::QuickAction,
                    title: qa.title,
                    subtitle: qa.subtitle,
                    url: None,
                    tab_id: None,
                    quick_action: Some(qa.kind),
                    favicon_url: None,
                    score: 3_800.0 + qa.score as f64 * 3.0,
                    match_indices: Vec::new(),
                    is_bookmark: false,
                });
            }
        }

        // 9. Remote search suggestions (when not scoped)
        if active_scope.is_none() && !trimmed.is_empty() {
            for (idx, sugg) in ctx.remote_suggestions.iter().take(5).enumerate() {
                if sugg.eq_ignore_ascii_case(trimmed) {
                    continue;
                }
                let url = self.search_engines.build_search_url(sugg, ctx.is_private);
                items.push(OmniboxItem {
                    kind: OmniboxItemKind::SearchSuggestion,
                    title: sugg.clone(),
                    subtitle: "Search suggestion".into(),
                    url: Some(url),
                    tab_id: None,
                    quick_action: None,
                    favicon_url: None,
                    score: 1_500.0 - (idx as f64 * 50.0),
                    match_indices: Vec::new(),
                    is_bookmark: false,
                });
            }
        }

        items.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.title.cmp(&b.title))
        });
        items.truncate(max_results);

        OmniboxResponse {
            input_kind,
            inline_completion: best_inline.map(|(_, c)| c),
            items,
            tab_to_search_hint,
            active_scope,
            instant_answer,
        }
    }
}

fn best_fuzzy_pair(query: &str, primary: &str, secondary: &str) -> Option<(i64, Vec<usize>)> {
    let m1 = fuzzy_score(query, primary);
    let m2 = fuzzy_score(query, secondary);
    match (m1, m2) {
        (Some((s1, i1)), Some((s2, _))) => {
            if s1 >= s2 {
                Some((s1 + 25, i1))
            } else {
                Some((s2, Vec::new()))
            }
        }
        (Some((s1, i1)), None) => Some((s1 + 25, i1)),
        (None, Some((s2, _))) => Some((s2, Vec::new())),
        (None, None) => None,
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fuzzy_score_boundaries_and_ranking() {
        let (s_exact, idx_exact) = fuzzy_score("rust", "rust-lang.org").expect("exact prefix");
        let (s_scattered, _) = fuzzy_score("rust", "r_u_s_t_scattered").expect("scattered");
        assert!(s_exact > s_scattered);
        assert_eq!(idx_exact, vec![0, 1, 2, 3]);
        assert!(fuzzy_score("xyz", "rust-lang.org").is_none());
        // Unicode safety
        let (s_uni, idx_uni) = fuzzy_score("é", "Café Singularity").expect("unicode");
        assert!(s_uni > 0);
        assert_eq!(idx_uni, vec![3]);
    }

    #[test]
    fn test_frecency_monotonic_decay_and_bonuses() {
        let fresh = compute_frecency(10, 3, 600, false);
        let old = compute_frecency(10, 3, 60 * 86_400, false);
        let bookmarked = compute_frecency(10, 3, 600, true);
        let typed = compute_frecency(10, 8, 600, false);
        assert!(fresh > old);
        assert!(bookmarked > fresh);
        assert!(typed > fresh);
    }

    #[test]
    fn test_classify_omnibox_input_all_variants() {
        assert!(matches!(
            classify_omnibox_input("singularity://settings"),
            OmniboxInputKind::InternalUrl { .. }
        ));
        assert!(matches!(
            classify_omnibox_input("view-source:https://example.com"),
            OmniboxInputKind::ViewSource { .. }
        ));
        assert!(matches!(
            classify_omnibox_input("https://rust-lang.org"),
            OmniboxInputKind::DirectUrl { .. }
        ));
        assert!(matches!(
            classify_omnibox_input("rust-lang.org/learn"),
            OmniboxInputKind::DirectUrl { .. }
        ));
        assert!(matches!(
            classify_omnibox_input("localhost:3000/api"),
            OmniboxInputKind::LocalHostOrIp { .. }
        ));
        assert!(matches!(
            classify_omnibox_input("127.0.0.1:8080"),
            OmniboxInputKind::LocalHostOrIp { .. }
        ));
        assert_eq!(
            classify_omnibox_input("@tabs rust"),
            OmniboxInputKind::ScopedQuery {
                scope: OmniboxScope::Tabs,
                query: "rust".into()
            }
        );
        assert_eq!(
            classify_omnibox_input("* docs"),
            OmniboxInputKind::ScopedQuery {
                scope: OmniboxScope::Bookmarks,
                query: "docs".into()
            }
        );
        assert_eq!(
            classify_omnibox_input("!w black hole"),
            OmniboxInputKind::BangQuery {
                bang: "w".into(),
                query: "black hole".into()
            }
        );
        assert_eq!(
            classify_omnibox_input("serde !crates"),
            OmniboxInputKind::BangQuery {
                bang: "crates".into(),
                query: "serde".into()
            }
        );
        // Factorial must NOT be misclassified as a bang
        assert!(matches!(
            classify_omnibox_input("5!"),
            OmniboxInputKind::InstantAnswer { .. }
        ));
        assert!(matches!(
            classify_omnibox_input("how do black holes evaporate"),
            OmniboxInputKind::SearchQuery { .. }
        ));
    }

    #[test]
    fn test_url_segmenter_and_idn_homograph_detection() {
        let seg = segment_url_for_display("https://docs.api.example.co.uk:8443/v1/search?q=1#top");
        assert_eq!(seg.scheme, "https");
        assert_eq!(seg.subdomain, "docs.api");
        assert_eq!(seg.etld_plus_one, "example.co.uk");
        assert_eq!(seg.port, Some(8443));
        assert_eq!(seg.path, "/v1/search");
        assert_eq!(seg.query_and_hash, "?q=1#top");
        assert!(!seg.is_idn_suspicious);

        // Punycode decoding of legitimate French IDN `café.fr` -> `xn--caf-dma.fr`
        assert_eq!(decode_punycode_label("caf-dma").as_deref(), Some("café"));
        let benign = segment_url_for_display("https://xn--caf-dma.fr/menu");
        assert!(!benign.is_idn_suspicious);
        assert_eq!(benign.display_host, "café.fr");

        // Classic Cyrillic homograph attack: `xn--80ak6aa92e.com` = Cyrillic `аррӏе.com`
        let spoof = segment_url_for_display("https://xn--80ak6aa92e.com/login");
        assert!(spoof.is_idn_suspicious);
        assert_eq!(spoof.display_host, "xn--80ak6aa92e.com");

        // Mixed Latin + Cyrillic label
        let mixed = segment_url_for_display("https://pаypal.com"); // second char is Cyrillic 'а'
        assert!(mixed.is_idn_suspicious);
    }

    #[test]
    fn test_opensearch_xml_and_suggestions_parsing() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
        <OpenSearchDescription xmlns="http://a9.com/-/spec/opensearch/1.1/">
            <ShortName>Singularity Docs</ShortName>
            <Url type="text/html" method="POST" template="https://docs.singularity.test/search">
                <Param name="q" value="{searchTerms}"/>
                <Param name="lang" value="en"/>
            </Url>
            <Url type="application/x-suggestions+json" template="https://docs.singularity.test/ac?q={searchTerms}"/>
            <Image height="16" width="16">https://docs.singularity.test/favicon.ico</Image>
        </OpenSearchDescription>"#;

        let entry = parse_opensearch_xml(xml).expect("valid OpenSearch XML");
        assert_eq!(entry.name, "Singularity Docs");
        assert_eq!(entry.method, SearchHttpMethod::Post);
        assert_eq!(entry.post_params.len(), 2);
        assert!(entry.suggest_url_template.is_some());

        // XXE rejection
        let xxe = r#"<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><OpenSearchDescription><ShortName>&xxe;</ShortName></OpenSearchDescription>"#;
        assert!(parse_opensearch_xml(xxe).is_err());

        // OpenSearch JSON suggestions
        let os_json = r#"["rust", ["rust lang", "rust book", "rust playground"]]"#;
        assert_eq!(
            parse_search_suggestions_json(os_json),
            vec!["rust lang", "rust book", "rust playground"]
        );

        // DuckDuckGo JSON suggestions
        let ddg_json = r#"[{"phrase":"singularity browser"},{"phrase":"singularity physics"}]"#;
        assert_eq!(
            parse_search_suggestions_json(ddg_json),
            vec!["singularity browser", "singularity physics"]
        );
    }

    #[test]
    fn test_bangs_catalog_and_registry_crud() {
        assert!(builtin_bangs().len() >= 100);
        let mut reg = SearchEngineRegistry::with_builtins();
        assert_ne!(
            reg.default_engine(false).unwrap().id,
            reg.default_engine(true).unwrap().id
        );
        let (name, url) = reg.resolve_bang("rs", "HashMap").expect("!rs bang");
        assert_eq!(name, "Rust std docs");
        assert!(url.contains("HashMap"));

        let custom = SearchEngineEntry {
            id: "mysearch".into(),
            name: "My Search".into(),
            keyword: "ms".into(),
            search_url_template: "https://my.search/?q={searchTerms}".into(),
            suggest_url_template: None,
            method: SearchHttpMethod::Get,
            post_params: Vec::new(),
            favicon_url: None,
            show_in_one_off_bar: true,
            enabled: true,
            is_builtin: false,
            host: Some("my.search".into()),
        };
        reg.add_engine(custom).expect("add");
        assert!(reg.find_tab_to_search_hint("my.search").is_some());
        assert!(reg.remove_engine("duckduckgo").is_err()); // default protected
        assert!(reg.remove_engine("mysearch").is_ok());
    }

    #[test]
    fn test_instant_answers_calculator_units_tz_color_dev_fx() {
        // Scientific calculator
        let c1 = evaluate_instant_answer("2 + 3 * 4^2").unwrap();
        assert_eq!(c1.copy_value, "50");
        let c2 = evaluate_instant_answer("sqrt(144) + 5!").unwrap();
        assert_eq!(c2.copy_value, "132");
        let c3 = evaluate_instant_answer("15% of 360").unwrap();
        assert_eq!(c3.copy_value, "54");
        let c4 = evaluate_instant_answer("85 + 20%").unwrap();
        assert_eq!(c4.copy_value, "102");
        let c5 = evaluate_instant_answer("sin(0) + cos(0) + ln(e)").unwrap();
        assert_eq!(c5.copy_value, "2");

        // Unit conversion EN/FR
        let u1 = evaluate_instant_answer("100 km en miles").unwrap();
        assert_eq!(u1.kind, InstantAnswerKind::UnitConversion);
        assert!(u1.copy_value.starts_with("62.137"));
        let u2 = evaluate_instant_answer("100 C to F").unwrap();
        assert_eq!(u2.copy_value, "212");
        let u3 = evaluate_instant_answer("1 GiB to MiB").unwrap();
        assert_eq!(u3.copy_value, "1024");
        let u4 = evaluate_instant_answer("100 Mbps to MB/s").unwrap();
        assert_eq!(u4.copy_value, "12.5");

        // Timezone conversion
        let tz1 = evaluate_instant_answer("14:30 EST to CET").unwrap();
        assert_eq!(tz1.kind, InstantAnswerKind::TimezoneConversion);
        assert_eq!(tz1.copy_value, "20:30");
        let tz2 = evaluate_instant_answer("heure à Tokyo").unwrap();
        assert_eq!(tz2.kind, InstantAnswerKind::TimezoneConversion);

        // Color converter + WCAG
        let col = evaluate_instant_answer("#38D9F5").unwrap();
        assert_eq!(col.kind, InstantAnswerKind::ColorConversion);
        assert_eq!(col.color_preview_hex.as_deref(), Some("#38D9F5"));
        assert!(col.details.iter().any(|(k, _)| k == "OKLCH"));
        assert!(col.details.iter().any(|(k, _)| k == "WCAG on #000000"));

        // Dev tools: radix, bitwise, unix timestamp, uuid
        let hex = evaluate_instant_answer("255 to hex").unwrap();
        assert_eq!(hex.copy_value, "0xFF");
        let bin = evaluate_instant_answer("0xFF").unwrap();
        assert_eq!(bin.copy_value, "255");
        let bit = evaluate_instant_answer("1 << 10").unwrap();
        assert_eq!(bit.copy_value, "1024");
        let ts = evaluate_instant_answer("ts 1700000000").unwrap();
        assert_eq!(ts.copy_value, "2023-11-14T22:13:20Z");
        let uuid = evaluate_instant_answer("uuid").unwrap();
        assert_eq!(uuid.copy_value.len(), 36);
        assert_eq!(&uuid.copy_value[14..15], "4");

        // FX ECB XML parser & currency conversion
        let ecb_xml = r#"<gesmes:Envelope><Cube><Cube time="2026-11-26">
            <Cube currency="USD" rate="1.10"/>
            <Cube currency="GBP" rate="0.85"/>
        </Cube></Cube></gesmes:Envelope>"#;
        let fx = FxRatesCache::parse_ecb_xml(ecb_xml).expect("parse ECB XML");
        assert_eq!(fx.updated_date, "2026-11-26");
        let conv = evaluate_instant_answer_with_fx("100 EUR to USD", &fx, 1_700_000_000).unwrap();
        assert_eq!(conv.copy_value, "110.00");
    }

    #[test]
    fn test_qr_code_encoder_and_svg() {
        let m1 = encode_qr_matrix("https://singularity.dev", QrEcLevel::M).expect("QR V2");
        assert!(m1.version >= 1 && m1.version <= 6);
        assert_eq!(m1.size, (m1.version as usize) * 4 + 17);
        // Verify top-left finder pattern center 3x3 is dark and ring at dist 2 is light
        assert!(m1.get(3, 3));
        assert!(m1.get(0, 0));
        assert!(!m1.get(1, 1));
        assert!(!m1.get(7, 0)); // separator

        let svg = generate_qr_svg("https://rust-lang.org");
        assert!(svg.starts_with("<svg "));
        assert!(svg.contains("<path d=\"M"));
        assert!(svg.ends_with("</svg>"));
    }

    #[test]
    fn test_omnibox_engine_unified_query_and_quick_actions() {
        let engine = OmniboxEngine::default();
        let ctx = OmniboxQueryContext {
            open_tabs: vec![OmniboxOpenTab {
                tab_id: "tab-1".into(),
                title: "Rust Programming Language".into(),
                url: "https://www.rust-lang.org/".into(),
                favicon_url: None,
            }],
            history: vec![OmniboxHistoryCandidate {
                url: "https://rust-lang.org/learn".into(),
                title: "Learn Rust".into(),
                visit_count: 25,
                typed_count: 10,
                last_visit_unix: 1_700_000_000,
                favicon_url: None,
            }],
            bookmarks: vec![OmniboxBookmarkCandidate {
                id: "bm-1".into(),
                title: "Rust Standard Library".into(),
                url: "https://doc.rust-lang.org/std/".into(),
                nickname: Some("rstd".into()),
                tags: vec!["rust".into()],
                visit_count: 15,
                last_visited_unix: Some(1_700_000_000),
            }],
            remote_suggestions: vec!["rust async".into(), "rust book".into()],
            now_unix: 1_700_000_100,
            max_results: 10,
            ..Default::default()
        };

        let resp = engine.query("rust", &ctx);
        assert!(resp.inline_completion.as_deref() == Some("rust-lang.org/learn"));
        assert!(resp.items.iter().any(|i| i.kind == OmniboxItemKind::SwitchToTab));
        assert!(resp.items.iter().any(|i| i.kind == OmniboxItemKind::Bookmark));
        assert!(resp.items.iter().any(|i| i.kind == OmniboxItemKind::History));

        let qa_fr = match_quick_actions("effacer historique");
        assert_eq!(qa_fr[0].kind, QuickActionKind::ClearBrowsingData);
        let qa_en = match_quick_actions("toggle mullvad");
        assert_eq!(qa_en[0].kind, QuickActionKind::ToggleMullvad);
    }

    #[test]
    fn test_qr_reed_solomon_iso_vector_and_multiversion() {
        // Official ISO/IEC 18004 Table I.1 Version 1-M test vector
        let data = [16u8, 32, 12, 86, 97, 128, 236, 17, 236, 17, 236, 17, 236, 17, 236, 17];
        assert_eq!(
            rs_compute_remainder(&data, 10),
            vec![165, 36, 212, 193, 237, 54, 199, 135, 44, 85]
        );

        // Verify Versions 1..=6 across L & M error correction levels
        for (len, ec, expected_min_ver) in [
            (10usize, QrEcLevel::M, 1u8),
            (25, QrEcLevel::M, 2),
            (40, QrEcLevel::M, 3),
            (60, QrEcLevel::M, 4),
            (80, QrEcLevel::M, 5),
            (100, QrEcLevel::M, 6),
            (130, QrEcLevel::L, 6),
        ] {
            let payload = "a".repeat(len);
            let m = encode_qr_matrix(&payload, ec).expect("encode QR");
            assert!(m.version >= expected_min_ver);
            assert_eq!(m.size, (m.version as usize) * 4 + 17);
            // Fixed dark module at (8, size - 8)
            assert!(m.get(8, m.size - 8));
        }

        // Very long URL gracefully degrades without panicking
        let huge = format!("https://example.org/{}", "x".repeat(400));
        let svg = generate_qr_svg(&huge);
        assert!(svg.starts_with("<svg ") && svg.ends_with("</svg>"));
    }

    #[test]
    fn test_omnibox_scoped_settings_extensions_and_bangs() {
        let engine = OmniboxEngine::default();
        let ctx = OmniboxQueryContext {
            settings: vec![OmniboxSettingCandidate {
                key: "privacy.mullvad.kill_switch".into(),
                label: "Mullvad WireGuard Kill Switch".into(),
                category: "Privacy".into(),
            }],
            extensions: vec![OmniboxExtensionCandidate {
                id: "ublock".into(),
                name: "uBlock Origin".into(),
                description: "Wide-spectrum content blocker".into(),
                enabled: true,
            }],
            now_unix: 1_700_000_000,
            max_results: 10,
            ..Default::default()
        };

        let s_resp = engine.query("@settings mullvad", &ctx);
        assert_eq!(s_resp.active_scope, Some(OmniboxScope::Settings));
        assert_eq!(s_resp.items.len(), 1);
        assert_eq!(s_resp.items[0].kind, OmniboxItemKind::Setting);

        let e_resp = engine.query("@extensions ublock", &ctx);
        assert_eq!(e_resp.active_scope, Some(OmniboxScope::Extensions));
        assert_eq!(e_resp.items[0].kind, OmniboxItemKind::Extension);

        let b_resp = engine.query("!gh tokio", &ctx);
        assert_eq!(b_resp.items[0].kind, OmniboxItemKind::BangSearch);
        assert!(b_resp.items[0]
            .url
            .as_deref()
            .unwrap()
            .contains("github.com/search?q=tokio"));

        let tts = engine.query("github.com", &ctx);
        assert!(tts.tab_to_search_hint.is_some());
    }
}
