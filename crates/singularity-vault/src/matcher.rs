//! Multi-URI Autofill Matcher, eTLD+1 Extraction, RFC 3492 Punycode & Homograph
//! Anti-Phishing Engine, Levenshtein Typosquatting Detector, and Unlocked Vault Fuzzy Search.

use crate::format::{VaultItem, VaultItemKind};
use serde::{Deserialize, Serialize};

/// Matching strategy for a URI attached to a vault login item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UriMatchRule {
    #[default]
    BaseDomain,
    Host,
    StartsWith,
    Exact,
    GlobRegex,
    Never,
}

impl UriMatchRule {
    /// Priority rank used to sort autofill suggestions (higher is more specific).
    pub fn specificity_score(self) -> u8 {
        match self {
            UriMatchRule::Exact => 100,
            UriMatchRule::StartsWith => 85,
            UriMatchRule::Host => 70,
            UriMatchRule::BaseDomain => 50,
            UriMatchRule::GlobRegex => 40,
            UriMatchRule::Never => 0,
        }
    }
}

/// A single URI entry with its matching rule attached to a `LoginPayload`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultUriEntry {
    pub uri: String,
    #[serde(default)]
    pub match_rule: UriMatchRule,
}

impl VaultUriEntry {
    pub fn new(uri: impl Into<String>, match_rule: UriMatchRule) -> Self {
        Self {
            uri: uri.into(),
            match_rule,
        }
    }

    pub fn base_domain(uri: impl Into<String>) -> Self {
        Self::new(uri, UriMatchRule::BaseDomain)
    }
}

/// Parsed URI components extracted without external URL dependencies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedUri {
    pub scheme: Option<String>,
    pub host: String,
    pub port: Option<u16>,
    pub path_and_query: String,
    pub etld_plus_one: String,
    pub is_ip: bool,
    pub is_secure: bool,
}

/// Multi-label Public Suffix List subset covering common ccSLDs and platform hosting suffixes.
const MULTI_LABEL_PUBLIC_SUFFIXES: &[&str] = &[
    // 3-label suffixes
    "s3.amazonaws.com",
    "compute.amazonaws.com",
    "execute-api.amazonaws.com",
    // 2-label ccTLDs & common hosting public suffixes
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "ltd.uk", "plc.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "ed.jp", "gr.jp",
    "com.br", "net.br", "org.br", "gov.br", "edu.br",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
    "com.mx", "org.mx", "gob.mx", "edu.mx",
    "com.tr", "org.tr", "gov.tr", "edu.tr", "gen.tr",
    "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz",
    "co.in", "net.in", "org.in", "gov.in", "ac.in", "res.in",
    "co.za", "org.za", "gov.za", "ac.za", "net.za",
    "co.kr", "or.kr", "go.kr", "ac.kr", "ne.kr",
    "com.sg", "org.sg", "gov.sg", "edu.sg",
    "com.hk", "org.hk", "gov.hk", "edu.hk",
    "com.tw", "org.tw", "gov.tw", "edu.tw",
    "com.ar", "org.ar", "gob.ar", "edu.ar",
    "com.ua", "org.ua", "gov.ua", "net.ua",
    "com.pl", "net.pl", "org.pl", "gov.pl", "edu.pl",
    "gouv.fr", "asso.fr", "tm.fr", "nom.fr",
    "com.es", "org.es", "gob.es", "edu.es",
    "co.il", "org.il", "gov.il", "ac.il",
    "co.id", "or.id", "go.id", "ac.id",
    "com.my", "org.my", "gov.my", "edu.my",
    "com.ph", "org.ph", "gov.ph", "edu.ph",
    "com.vn", "org.vn", "gov.vn", "edu.vn",
    "com.co", "org.co", "gov.co", "edu.co",
    "com.pe", "org.pe", "gob.pe", "edu.pe",
    "com.ve", "org.ve", "gob.ve",
    "com.eg", "org.eg", "gov.eg",
    "com.ng", "org.ng", "gov.ng",
    "co.ke", "or.ke", "go.ke",
    "com.sa", "org.sa", "gov.sa",
    "co.th", "or.th", "go.th", "ac.th",
    // Cloud / platform public suffixes (PSL private section)
    "github.io", "gitlab.io", "pages.dev", "workers.dev", "vercel.app", "netlify.app",
    "herokuapp.com", "appspot.com", "cloudfront.net", "azurewebsites.net", "blogspot.com",
    "wordpress.com", "firebaseapp.com", "web.app", "fly.dev", "onrender.com", "railway.app",
    "eu.org", "us.org", "uk.com", "eu.com",
];

fn is_ipv4_host(host: &str) -> bool {
    let parts: Vec<&str> = host.split('.').collect();
    parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok())
}

fn is_ipv6_host(host: &str) -> bool {
    host.starts_with('[') && host.ends_with(']') && host.contains(':')
}

/// Parses a URL or bare host string into normalized URI components including `eTLD+1`.
pub fn parse_uri_components(input: &str) -> Option<ParsedUri> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }

    let (scheme, after_scheme) = if let Some((s, rest)) = trimmed.split_once("://") {
        let s_lower = s.trim().to_ascii_lowercase();
        if s_lower.is_empty()
            || !s_lower
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
        {
            return None;
        }
        (Some(s_lower), rest)
    } else {
        (None, trimmed)
    };

    // Split authority vs path/query/fragment
    let split_idx = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let authority_raw = &after_scheme[..split_idx];
    let path_and_query = after_scheme[split_idx..].to_string();

    // Strip optional userinfo@
    let host_port = authority_raw
        .rsplit_once('@')
        .map(|(_, hp)| hp)
        .unwrap_or(authority_raw);
    if host_port.is_empty() {
        return None;
    }

    let (host_raw, port) = if let Some(rest) = host_port.strip_prefix('[') {
        let (v6, after_bracket) = rest.split_once(']')?;
        let port = if let Some(p_str) = after_bracket.strip_prefix(':') {
            Some(p_str.parse::<u16>().ok()?)
        } else if after_bracket.is_empty() {
            None
        } else {
            return None;
        };
        (format!("[{}]", v6), port)
    } else if let Some((h, p_str)) = host_port.rsplit_once(':') {
        if !p_str.is_empty() && p_str.bytes().all(|b| b.is_ascii_digit()) {
            (h.to_string(), Some(p_str.parse::<u16>().ok()?))
        } else {
            (host_port.to_string(), None)
        }
    } else {
        (host_port.to_string(), None)
    };

    let host = host_raw.trim().trim_end_matches('.').to_lowercase();
    if host.is_empty() || host.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return None;
    }

    let is_ip = is_ipv4_host(&host) || is_ipv6_host(&host);
    let etld_plus_one = compute_etld_plus_one_from_host(&host, is_ip);
    let is_secure = match scheme.as_deref() {
        Some("https") | Some("wss") => true,
        Some("http") | Some("ws") => matches!(host.as_str(), "localhost" | "127.0.0.1" | "[::1]"),
        None => true, // bare domain defaults to HTTPS semantics
        _ => false,
    };

    Some(ParsedUri {
        scheme,
        host,
        port,
        path_and_query,
        etld_plus_one,
        is_ip,
        is_secure,
    })
}

fn compute_etld_plus_one_from_host(host: &str, is_ip: bool) -> String {
    if is_ip || !host.contains('.') {
        return host.to_string();
    }
    let labels: Vec<&str> = host.split('.').filter(|l| !l.is_empty()).collect();
    if labels.len() <= 2 {
        return labels.join(".");
    }

    // Check 3-label public suffix first
    if labels.len() >= 4 {
        let last3 = labels[labels.len() - 3..].join(".");
        if MULTI_LABEL_PUBLIC_SUFFIXES.contains(&last3.as_str()) {
            return labels[labels.len() - 4..].join(".");
        }
    }

    // Check 2-label public suffix
    let last2 = labels[labels.len() - 2..].join(".");
    if MULTI_LABEL_PUBLIC_SUFFIXES.contains(&last2.as_str()) {
        return labels[labels.len() - 3..].join(".");
    }

    last2
}

/// Extracts the effective top-level domain + 1 label (`eTLD+1`) from a URL or hostname.
/// Examples: `"https://login.app.example.co.uk/auth"` -> `Some("example.co.uk")`,
/// `"https://gist.github.com/user"` -> `Some("github.com")`.
pub fn extract_etld_plus_one(input: &str) -> Option<String> {
    parse_uri_components(input).map(|p| p.etld_plus_one)
}

fn normalized_uri_string(p: &ParsedUri) -> String {
    let scheme = p.scheme.as_deref().unwrap_or("https");
    let effective_port = match (scheme, p.port) {
        ("https", Some(443)) | ("http", Some(80)) => None,
        (_, port) => port,
    };
    let mut s = format!("{}://{}", scheme, p.host);
    if let Some(port) = effective_port {
        s.push_str(&format!(":{}", port));
    }
    s.push_str(&p.path_and_query);
    s
}

/// Linear-time DP glob matcher (`*` matches 0+ chars, `?` matches 1 char, all else literal).
fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (m, n) = (p.len(), t.len());
    let mut dp = vec![false; n + 1];
    dp[0] = true;
    for i in 0..m {
        if p[i] == '*' {
            for j in 1..=n {
                dp[j] = dp[j] || dp[j - 1];
            }
        } else {
            let mut next = vec![false; n + 1];
            for j in 1..=n {
                if p[i] == '?' || p[i].eq_ignore_ascii_case(&t[j - 1]) {
                    next[j] = dp[j - 1];
                }
            }
            dp = next;
        }
    }
    dp[n]
}

const MAX_REGEX_STEPS: usize = 10_000;

/// Bounded regex subset matcher supporting `^`, `$`, `.`, `.*`, `.+`, `?`, `\*`, `\.`,
/// character classes `[a-z0-9]`, and top-level alternation `(a|b)`.
fn simple_regex_match(pattern: &str, text: &str) -> bool {
    let mut remaining_steps = MAX_REGEX_STEPS;
    simple_regex_match_budgeted(pattern, text, &mut remaining_steps)
}

fn simple_regex_match_budgeted(
    pattern: &str,
    text: &str,
    remaining_steps: &mut usize,
) -> bool {
    if *remaining_steps == 0 {
        return false;
    }
    *remaining_steps -= 1;

    let anchored_start = pattern.starts_with('^');
    let anchored_end = pattern.ends_with('$') && !pattern.ends_with("\\$");
    let core = pattern.strip_prefix('^').unwrap_or(pattern);
    let core = if anchored_end {
        core.strip_suffix('$').unwrap_or(core)
    } else {
        core
    };

    // Expand simple top-level or single parenthesized alternation `(a|b)` into branches
    if let Some((before, rest)) = core.split_once('(') {
        if let Some((group, after)) = rest.split_once(')') {
            if !group.contains('(') {
                for alt in group.split('|') {
                    if *remaining_steps == 0 {
                        return false;
                    }
                    let expanded = format!(
                        "{}{}{}{}{}",
                        if anchored_start { "^" } else { "" },
                        before,
                        alt,
                        after,
                        if anchored_end { "$" } else { "" }
                    );
                    if simple_regex_match_budgeted(&expanded, text, remaining_steps) {
                        return true;
                    }
                }
                return false;
            }
        }
    }

    #[derive(Clone)]
    enum Atom {
        Any,
        Literal(char),
        Class(Vec<(char, char)>, bool), // inclusive (start, end) ranges, negated
    }

    #[derive(Clone)]
    enum Quant {
        One,
        ZeroOrMore,
        OneOrMore,
        ZeroOrOne,
    }

    let chars: Vec<char> = core.chars().collect();
    let mut tokens: Vec<(Atom, Quant)> = Vec::new();
    let mut i = 0usize;
    while i < chars.len() {
        if *remaining_steps == 0 {
            return false;
        }
        *remaining_steps -= 1;

        let atom = if chars[i] == '\\' && i + 1 < chars.len() {
            i += 1;
            let escaped = chars[i];
            match escaped {
                'd' => Atom::Class(vec![('0', '9')], false),
                'w' => Atom::Class(
                    vec![('a', 'z'), ('A', 'Z'), ('0', '9'), ('_', '_')],
                    false,
                ),
                c => Atom::Literal(c),
            }
        } else if chars[i] == '.' {
            Atom::Any
        } else if chars[i] == '[' {
            i += 1;
            let negated = if i < chars.len() && chars[i] == '^' {
                i += 1;
                true
            } else {
                false
            };
            let mut ranges: Vec<(char, char)> = Vec::new();
            while i < chars.len() && chars[i] != ']' {
                if *remaining_steps == 0 {
                    return false;
                }
                *remaining_steps -= 1;
                if i + 2 < chars.len() && chars[i + 1] == '-' && chars[i + 2] != ']' {
                    let start = chars[i];
                    let end = chars[i + 2];
                    if start <= end {
                        ranges.push((start, end));
                    }
                    i += 3;
                } else {
                    ranges.push((chars[i], chars[i]));
                    i += 1;
                }
            }
            Atom::Class(ranges, negated)
        } else {
            Atom::Literal(chars[i])
        };
        i += 1;

        let quant = if i < chars.len() {
            match chars[i] {
                '*' => {
                    i += 1;
                    Quant::ZeroOrMore
                }
                '+' => {
                    i += 1;
                    Quant::OneOrMore
                }
                '?' => {
                    i += 1;
                    Quant::ZeroOrOne
                }
                _ => Quant::One,
            }
        } else {
            Quant::One
        };
        tokens.push((atom, quant));
    }

    let atom_matches = |atom: &Atom, c: char| -> bool {
        match atom {
            Atom::Any => true,
            Atom::Literal(lc) => lc.eq_ignore_ascii_case(&c),
            Atom::Class(ranges, neg) => {
                let hit = if c.is_ascii_alphabetic() {
                    let lo = c.to_ascii_lowercase();
                    let hi = c.to_ascii_uppercase();
                    ranges
                        .iter()
                        .any(|&(s, e)| (s <= lo && lo <= e) || (s <= hi && hi <= e))
                } else {
                    ranges.iter().any(|&(s, e)| s <= c && c <= e)
                };
                if *neg { !hit } else { hit }
            }
        }
    };

    let t: Vec<char> = text.chars().collect();
    let n = t.len();
    let m = tokens.len();

    let mut reachable = if anchored_start {
        let mut r = vec![false; n + 1];
        r[0] = true;
        r
    } else {
        vec![true; n + 1]
    };

    let token_step_cost = 1 + (n / 32);
    for ti in 0..m {
        if *remaining_steps < token_step_cost {
            *remaining_steps = 0;
            return false;
        }
        *remaining_steps -= token_step_cost;

        let (ref atom, ref quant) = tokens[ti];
        let mut next = vec![false; n + 1];
        match quant {
            Quant::One => {
                for pos in 0..n {
                    if reachable[pos] && atom_matches(atom, t[pos]) {
                        next[pos + 1] = true;
                    }
                }
            }
            Quant::ZeroOrOne => {
                for pos in 0..=n {
                    if reachable[pos] {
                        next[pos] = true;
                        if pos < n && atom_matches(atom, t[pos]) {
                            next[pos + 1] = true;
                        }
                    }
                }
            }
            Quant::ZeroOrMore => {
                for pos in 0..=n {
                    if reachable[pos] {
                        next[pos] = true;
                    }
                }
                for pos in 0..n {
                    if next[pos] && atom_matches(atom, t[pos]) {
                        next[pos + 1] = true;
                    }
                }
            }
            Quant::OneOrMore => {
                for pos in 0..n {
                    if (reachable[pos] || next[pos]) && atom_matches(atom, t[pos]) {
                        next[pos + 1] = true;
                    }
                }
            }
        }
        reachable = next;
    }

    if anchored_end {
        reachable[n]
    } else {
        reachable.iter().any(|&b| b)
    }
}

fn is_regex_like(pattern: &str) -> bool {
    pattern.starts_with('^')
        || pattern.ends_with('$')
        || pattern.contains("\\.")
        || pattern.contains(".*")
        || pattern.contains(".+")
        || pattern.contains('[')
        || pattern.contains('(')
        || pattern.contains("\\d")
        || pattern.contains("\\w")
}

fn is_web_scheme_compatible(stored: &ParsedUri, target: &ParsedUri) -> bool {
    let stored_scheme = match stored.scheme.as_deref() {
        Some("https") | None => "https",
        Some("http") => "http",
        _ => return false,
    };
    let target_scheme = match target.scheme.as_deref() {
        Some("https") => "https",
        Some("http") => "http",
        _ => return false,
    };
    // Never downgrade an HTTPS-stored credential to an insecure HTTP target URL
    if stored_scheme == "https" && target_scheme == "http" {
        return false;
    }
    true
}

/// Evaluates whether `target_uri` matches `stored_uri` under `rule`.
pub fn matches_uri_rule(stored_uri: &str, rule: UriMatchRule, target_uri: &str) -> bool {
    if rule == UriMatchRule::Never {
        return false;
    }
    if rule == UriMatchRule::GlobRegex {
        let pat = stored_uri.trim();
        let tgt = target_uri.trim();
        if pat.is_empty() || tgt.is_empty() {
            return false;
        }
        return if is_regex_like(pat) {
            simple_regex_match(pat, tgt)
        } else {
            glob_match(pat, tgt)
        };
    }

    let (Some(stored), Some(target)) = (
        parse_uri_components(stored_uri),
        parse_uri_components(target_uri),
    ) else {
        return false;
    };

    match rule {
        UriMatchRule::Never | UriMatchRule::GlobRegex => unreachable!(),
        UriMatchRule::BaseDomain => {
            is_web_scheme_compatible(&stored, &target)
                && stored.etld_plus_one == target.etld_plus_one
        }
        UriMatchRule::Host => {
            if !is_web_scheme_compatible(&stored, &target) || stored.host != target.host {
                return false;
            }
            let stored_port = stored.port.or(match stored.scheme.as_deref() {
                Some("http") => Some(80),
                _ => Some(443),
            });
            let target_port = target.port.or(match target.scheme.as_deref() {
                Some("http") => Some(80),
                _ => Some(443),
            });
            stored_port == target_port
        }
        UriMatchRule::StartsWith => {
            let s_norm = normalized_uri_string(&stored);
            let t_norm = normalized_uri_string(&target);
            t_norm.starts_with(&s_norm)
        }
        UriMatchRule::Exact => {
            let s_norm = normalized_uri_string(&stored);
            let t_norm = normalized_uri_string(&target);
            s_norm.trim_end_matches('/') == t_norm.trim_end_matches('/')
        }
    }
}

/// Autofill match result pairing a vault item with the matched URI entry and specificity score.
#[derive(Debug, Clone)]
pub struct UriMatchResult<'a> {
    pub item: &'a VaultItem,
    pub matched_uri: String,
    pub match_rule: UriMatchRule,
    pub score: u16,
}

/// Matches all active (non-trashed) `Login` items against `target_uri` across all their URIs,
/// sorted by match specificity descending (with favorites boosted).
pub fn match_items_for_uri<'a>(
    items: &'a [VaultItem],
    target_uri: &str,
) -> Vec<UriMatchResult<'a>> {
    let mut results = Vec::new();
    for item in items {
        if item.is_trashed() {
            continue;
        }
        let VaultItemKind::Login(ref login) = item.kind else {
            continue;
        };

        let mut best: Option<(String, UriMatchRule, u16)> = None;
        for entry in &login.uris {
            if matches_uri_rule(&entry.uri, entry.match_rule, target_uri) {
                let mut score = u16::from(entry.match_rule.specificity_score());
                if item.favorite {
                    score += 10;
                }
                if best.as_ref().map(|b| score > b.2).unwrap_or(true) {
                    best = Some((entry.uri.clone(), entry.match_rule, score));
                }
            }
        }

        if let Some((matched_uri, match_rule, score)) = best {
            results.push(UriMatchResult {
                item,
                matched_uri,
                match_rule,
                score,
            });
        }
    }

    results.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| a.item.name.to_lowercase().cmp(&b.item.name.to_lowercase()))
    });
    results
}

// --- Levenshtein Distance, RFC 3492 Punycode Decoder & Anti-Phishing Engine ---

/// Computes exact Unicode character-level Levenshtein edit distance between `a` and `b`.
pub fn levenshtein_distance(a: &str, b: &str) -> usize {
    let ac: Vec<char> = a.chars().collect();
    let bc: Vec<char> = b.chars().collect();
    let (m, n) = (ac.len(), bc.len());
    if m == 0 {
        return n;
    }
    if n == 0 {
        return m;
    }

    let mut prev: Vec<usize> = (0..=n).collect();
    let mut curr = vec![0usize; n + 1];

    for i in 1..=m {
        curr[0] = i;
        for j in 1..=n {
            let cost = usize::from(ac[i - 1] != bc[j - 1]);
            curr[j] = (prev[j] + 1)
                .min(curr[j - 1] + 1)
                .min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[n]
}

/// Pure-Rust RFC 3492 Punycode decoder for a single DNS label (e.g. `"xn--pple-43d"` -> `"аpple"`).
pub fn decode_punycode_label(label: &str) -> Option<String> {
    let lower = label.to_ascii_lowercase();
    let encoded = lower.strip_prefix("xn--")?;

    const BASE: u32 = 36;
    const TMIN: u32 = 1;
    const TMAX: u32 = 26;
    const SKEW: u32 = 38;
    const DAMP: u32 = 700;

    let adapt = |mut delta: u32, num_points: u32, first_time: bool| -> u32 {
        delta = if first_time { delta / DAMP } else { delta / 2 };
        delta += delta / num_points;
        let mut k = 0u32;
        while delta > ((BASE - TMIN) * TMAX) / 2 {
            delta /= BASE - TMIN;
            k += BASE;
        }
        k + ((BASE - TMIN + 1) * delta) / (delta + SKEW)
    };

    let mut output: Vec<char> = Vec::new();
    let (basic_part, delta_part) = match encoded.rfind('-') {
        Some(pos) => (&encoded[..pos], &encoded[pos + 1..]),
        None => ("", encoded),
    };
    for ch in basic_part.chars() {
        if !ch.is_ascii() {
            return None;
        }
        output.push(ch);
    }

    let mut n: u32 = 128;
    let mut i: u32 = 0;
    let mut bias: u32 = 72;
    let bytes = delta_part.as_bytes();
    let mut idx = 0usize;

    while idx < bytes.len() {
        let old_i = i;
        let mut w: u32 = 1;
        let mut k: u32 = BASE;
        loop {
            if idx >= bytes.len() {
                return None;
            }
            let b = bytes[idx];
            idx += 1;
            let digit: u32 = match b {
                b'a'..=b'z' => u32::from(b - b'a'),
                b'0'..=b'9' => u32::from(b - b'0') + 26,
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
        bias = adapt(i - old_i, out_len, old_i == 0);
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
    Other,
}

fn classify_letter_script(ch: char) -> Option<CharScript> {
    if !ch.is_alphabetic() {
        return None;
    }
    let cp = ch as u32;
    if (0x0041..=0x024F).contains(&cp) || (0x1E00..=0x1EFF).contains(&cp) {
        Some(CharScript::Latin)
    } else if (0x0400..=0x052F).contains(&cp) {
        Some(CharScript::Cyrillic)
    } else if (0x0370..=0x03FF).contains(&cp) || (0x1F00..=0x1FFF).contains(&cp) {
        Some(CharScript::Greek)
    } else {
        Some(CharScript::Other)
    }
}

/// Computes a confusable ASCII skeleton for homograph and visual lookalike comparison.
pub fn confusable_skeleton(domain: &str) -> String {
    let mut mapped = String::with_capacity(domain.len());
    for ch in domain.chars() {
        let lower = ch.to_lowercase().next().unwrap_or(ch);
        let ascii = match lower {
            // Cyrillic lookalikes
            'а' | 'ӓ' => 'a',
            'в' => 'b',
            'с' | 'ҫ' => 'c',
            'ԁ' => 'd',
            'е' | 'ё' | 'є' => 'e',
            'ɡ' => 'g',
            'һ' | 'н' => 'h',
            'і' | 'ї' | 'ӏ' => 'i',
            'ј' => 'j',
            'к' | 'қ' => 'k',
            'м' => 'm',
            'о' | 'ө' => 'o',
            'р' => 'p',
            'ԛ' => 'q',
            'ѕ' => 's',
            'т' => 't',
            'у' | 'ү' => 'y',
            'ѵ' => 'v',
            'ԝ' => 'w',
            'х' => 'x',
            // Greek lookalikes
            'α' => 'a',
            'β' => 'b',
            'ε' => 'e',
            'ι' => 'i',
            'κ' => 'k',
            'ν' => 'v',
            'ο' => 'o',
            'ρ' => 'p',
            'τ' => 't',
            'υ' => 'u',
            'χ' => 'x',
            // Latin extended lookalikes
            'ı' | 'ł' => 'l',
            'á' | 'à' | 'â' | 'ä' | 'ã' | 'å' => 'a',
            'é' | 'è' | 'ê' | 'ë' => 'e',
            'í' | 'ì' | 'î' | 'ï' => 'i',
            'ó' | 'ò' | 'ô' | 'ö' | 'õ' | 'ø' => 'o',
            'ú' | 'ù' | 'û' | 'ü' => 'u',
            'ñ' => 'n',
            'ç' => 'c',
            // Visual digit lookalikes
            '0' => 'o',
            '1' => 'l',
            '3' => 'e',
            '5' => 's',
            other => other,
        };
        mapped.push(ascii);
    }
    // Common multi-character visual spoofs
    mapped.replace("rn", "m").replace("vv", "w")
}

/// Specific anti-phishing risk signal detected on a candidate URL/domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PhishingRiskKind {
    PunycodeIdn { decoded_domain: String },
    MixedScriptHomograph { label: String },
    ConfusableSkeletonMatch { legitimate_domain: String },
    Typosquatting { legitimate_domain: String, distance: usize },
    InsecureHttp,
}

/// Aggregated anti-phishing assessment for a candidate URL before autofill.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhishingAssessment {
    pub candidate_host: String,
    pub decoded_unicode_host: String,
    pub normalized_skeleton: String,
    pub is_suspicious: bool,
    pub risk_score: u8,
    pub risks: Vec<PhishingRiskKind>,
}

/// Evaluates `candidate_uri` for IDN Punycode homographs, mixed-script attacks, visual skeleton
/// spoofing, Levenshtein typosquatting against `known_vault_domains`, and insecure HTTP.
pub fn assess_phishing_risk(
    candidate_uri: &str,
    known_vault_domains: &[String],
) -> PhishingAssessment {
    let Some(parsed) = parse_uri_components(candidate_uri) else {
        return PhishingAssessment {
            candidate_host: candidate_uri.to_string(),
            decoded_unicode_host: candidate_uri.to_string(),
            normalized_skeleton: String::new(),
            is_suspicious: true,
            risk_score: 50,
            risks: Vec::new(),
        };
    };

    let mut risks = Vec::new();
    let mut risk_score: u8 = 0;

    if !parsed.is_secure {
        risks.push(PhishingRiskKind::InsecureHttp);
        risk_score = risk_score.saturating_add(25);
    }

    // Decode Punycode labels and check for mixed scripts
    let mut decoded_labels = Vec::new();
    let mut has_punycode = false;
    for label in parsed.host.split('.') {
        let decoded = if label.starts_with("xn--") {
            has_punycode = true;
            decode_punycode_label(label).unwrap_or_else(|| label.to_string())
        } else {
            label.to_string()
        };

        let mut scripts = Vec::new();
        for ch in decoded.chars() {
            if let Some(script) = classify_letter_script(ch) {
                if !scripts.contains(&script) {
                    scripts.push(script);
                }
            }
        }
        if scripts.len() > 1 {
            risks.push(PhishingRiskKind::MixedScriptHomograph {
                label: decoded.clone(),
            });
            risk_score = risk_score.saturating_add(65);
        }
        decoded_labels.push(decoded);
    }

    let decoded_unicode_host = decoded_labels.join(".");
    if has_punycode {
        risks.push(PhishingRiskKind::PunycodeIdn {
            decoded_domain: decoded_unicode_host.clone(),
        });
        risk_score = risk_score.saturating_add(30);
    }

    let decoded_etld = compute_etld_plus_one_from_host(&decoded_unicode_host, parsed.is_ip);
    let cand_skeleton = confusable_skeleton(&decoded_etld);

    // Compare against known vault domains
    let mut seen_known = Vec::new();
    for raw_known in known_vault_domains {
        let Some(known_parsed) = parse_uri_components(raw_known) else {
            continue;
        };
        let known_etld = known_parsed.etld_plus_one;
        if seen_known.contains(&known_etld) {
            continue;
        }
        seen_known.push(known_etld.clone());

        // Exact same eTLD+1 is legitimate (not phishing)
        if parsed.etld_plus_one == known_etld || decoded_etld == known_etld {
            continue;
        }

        let known_skeleton = confusable_skeleton(&known_etld);
        if !cand_skeleton.is_empty() && cand_skeleton == known_skeleton {
            risks.push(PhishingRiskKind::ConfusableSkeletonMatch {
                legitimate_domain: known_etld,
            });
            risk_score = risk_score.saturating_add(80);
            continue;
        }

        // Check Levenshtein typosquatting on the registrable label (before TLD) and full eTLD+1
        let cand_label = decoded_etld.split('.').next().unwrap_or(&decoded_etld);
        let known_label = known_etld.split('.').next().unwrap_or(&known_etld);
        let max_typo_dist = if known_label.chars().count() >= 6 {
            2
        } else if known_label.chars().count() >= 4 {
            1
        } else {
            0
        };
        if max_typo_dist > 0 {
            let full_dist = levenshtein_distance(&decoded_etld, &known_etld);
            let label_dist = levenshtein_distance(cand_label, known_label);
            let best_dist = full_dist.min(label_dist);
            if best_dist > 0 && best_dist <= max_typo_dist {
                risks.push(PhishingRiskKind::Typosquatting {
                    legitimate_domain: known_etld,
                    distance: best_dist,
                });
                risk_score = risk_score.saturating_add(if best_dist == 1 { 60 } else { 40 });
            }
        }
    }

    let capped_score = risk_score.min(100);
    PhishingAssessment {
        candidate_host: parsed.host,
        decoded_unicode_host,
        normalized_skeleton: cand_skeleton,
        is_suspicious: !risks.is_empty(),
        risk_score: capped_score,
        risks,
    }
}

// --- Fuzzy Search on Unlocked Vault ---

/// Fuzzy search match over an unlocked vault item.
#[derive(Debug, Clone)]
pub struct FuzzySearchHit<'a> {
    pub item: &'a VaultItem,
    pub score: i32,
    pub matched_fields: Vec<&'static str>,
}

fn fuzzy_field_score(query_lower: &str, field_text: &str) -> i32 {
    if query_lower.is_empty() || field_text.is_empty() {
        return 0;
    }
    let text_lower = field_text.to_lowercase();
    if text_lower == query_lower {
        return 120;
    }
    if text_lower.starts_with(query_lower) {
        return 95;
    }
    if text_lower.contains(query_lower) {
        return 75;
    }

    // Subsequence fuzzy match (e.g. "ghb" -> "github")
    let mut q_chars = query_lower.chars().peekable();
    let mut consecutive = 0i32;
    let mut max_consecutive = 0i32;
    for ch in text_lower.chars() {
        if q_chars.peek() == Some(&ch) {
            q_chars.next();
            consecutive += 1;
            max_consecutive = max_consecutive.max(consecutive);
        } else {
            consecutive = 0;
        }
    }
    if q_chars.peek().is_none() {
        return 40 + (max_consecutive * 5).min(30);
    }

    // Token-level Levenshtein typo tolerance (distance <= 2 for tokens >= 4 chars)
    let q_len = query_lower.chars().count();
    if q_len >= 4 {
        for token in text_lower.split(|c: char| !c.is_alphanumeric()) {
            if token.chars().count() >= 3 {
                let d = levenshtein_distance(query_lower, token);
                if d == 1 {
                    return 55;
                } else if d == 2 && q_len >= 5 {
                    return 35;
                }
            }
        }
    }
    0
}

/// Performs multi-field fuzzy search over unlocked vault items (non-secret searchable metadata only).
pub fn fuzzy_search_items<'a>(
    items: &'a [VaultItem],
    query: &str,
    include_trashed: bool,
) -> Vec<FuzzySearchHit<'a>> {
    let q = query.trim().to_lowercase();
    let tokens: Vec<&str> = q.split_whitespace().collect();

    let mut hits = Vec::new();
    for item in items {
        if !include_trashed && item.is_trashed() {
            continue;
        }
        if tokens.is_empty() {
            hits.push(FuzzySearchHit {
                item,
                score: if item.favorite { 10 } else { 0 },
                matched_fields: Vec::new(),
            });
            continue;
        }

        // Collect non-secret searchable (field_label, text) pairs
        let mut fields: Vec<(&'static str, String)> = vec![("name", item.name.clone())];
        for tag in &item.tags {
            fields.push(("tag", tag.clone()));
        }
        match &item.kind {
            VaultItemKind::Login(l) => {
                fields.push(("username", l.username.clone()));
                for u in &l.uris {
                    fields.push(("uri", u.uri.clone()));
                }
            }
            VaultItemKind::Card(c) => {
                fields.push(("cardholder", c.cardholder_name.clone()));
                fields.push(("brand", c.brand.display_name().to_string()));
            }
            VaultItemKind::Identity(id) => {
                fields.push((
                    "full_name",
                    format!("{} {}", id.first_name, id.last_name).trim().to_string(),
                ));
                fields.push(("email", id.email.clone()));
                fields.push(("company", id.company.clone()));
                fields.push(("city", id.city.clone()));
            }
            VaultItemKind::SecureNote(_) => {}
            VaultItemKind::SshKey(s) => {
                fields.push(("fingerprint", s.fingerprint_sha256.clone()));
                fields.push(("key_type", s.key_type.clone()));
            }
            VaultItemKind::ApiSecret(a) => {
                fields.push(("service", a.service_name.clone()));
                if let Some(ref ep) = a.endpoint_url {
                    fields.push(("endpoint", ep.clone()));
                }
            }
            VaultItemKind::License(lic) => {
                fields.push(("product", lic.product_name.clone()));
                fields.push(("licensed_to", lic.licensed_to.clone()));
            }
            VaultItemKind::Wifi(w) => {
                fields.push(("ssid", w.ssid.clone()));
            }
        }

        let mut total_score = 0i32;
        let mut matched_fields = Vec::new();
        let mut all_tokens_matched = true;

        for tok in &tokens {
            let mut best_tok_score = 0i32;
            let mut best_field: Option<&'static str> = None;
            for (label, text) in &fields {
                let s = fuzzy_field_score(tok, text);
                if s > best_tok_score {
                    best_tok_score = s;
                    best_field = Some(*label);
                }
            }
            if best_tok_score == 0 {
                all_tokens_matched = false;
                break;
            }
            total_score += best_tok_score;
            if let Some(f) = best_field {
                if !matched_fields.contains(&f) {
                    matched_fields.push(f);
                }
            }
        }

        if all_tokens_matched {
            if item.favorite {
                total_score += 15;
            }
            hits.push(FuzzySearchHit {
                item,
                score: total_score,
                matched_fields,
            });
        }
    }

    hits.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| a.item.name.to_lowercase().cmp(&b.item.name.to_lowercase()))
    });
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_etld_plus_one_and_uri_match_rules() {
        assert_eq!(
            extract_etld_plus_one("https://auth.app.example.co.uk:8443/login"),
            Some("example.co.uk".to_string())
        );
        assert_eq!(
            extract_etld_plus_one("https://gist.github.com/alice"),
            Some("github.com".to_string())
        );
        assert_eq!(
            extract_etld_plus_one("https://alice.github.io/blog"),
            Some("alice.github.io".to_string())
        );

        assert!(matches_uri_rule(
            "https://github.com",
            UriMatchRule::BaseDomain,
            "https://gist.github.com/login"
        ));
        assert!(!matches_uri_rule(
            "https://github.com",
            UriMatchRule::Host,
            "https://gist.github.com/login"
        ));
        assert!(matches_uri_rule(
            "https://github.com/login",
            UriMatchRule::StartsWith,
            "https://github.com/login/oauth?code=1"
        ));
        assert!(matches_uri_rule(
            "https://github.com/login",
            UriMatchRule::Exact,
            "https://github.com/login"
        ));
        assert!(!matches_uri_rule(
            "https://github.com/login",
            UriMatchRule::Exact,
            "https://github.com/login/oauth"
        ));
        assert!(matches_uri_rule(
            "https://*.corp.example.com/admin/*",
            UriMatchRule::GlobRegex,
            "https://eu.corp.example.com/admin/panel"
        ));
        assert!(matches_uri_rule(
            r"^https://(app|auth)\.example\.com/v[0-9]+/.*$",
            UriMatchRule::GlobRegex,
            "https://auth.example.com/v2/session"
        ));
        assert!(!matches_uri_rule(
            "https://github.com",
            UriMatchRule::Never,
            "https://github.com"
        ));
    }

    #[test]
    fn test_punycode_homograph_and_levenshtein_typosquatting() {
        assert_eq!(levenshtein_distance("github.com", "githbu.com"), 2);
        assert_eq!(levenshtein_distance("paypal.com", "paypa1.com"), 1);
        assert_eq!(decode_punycode_label("xn--mnchen-3ya").as_deref(), Some("münchen"));
        // "xn--pple-43d" decodes to Cyrillic 'а' (U+0430) + "pple"
        assert_eq!(decode_punycode_label("xn--pple-43d").as_deref(), Some("аpple"));

        let known = vec![
            "https://apple.com".to_string(),
            "https://github.com".to_string(),
            "https://paypal.com".to_string(),
        ];

        // Punycode Cyrillic homograph spoof of apple.com
        let homograph = assess_phishing_risk("https://xn--pple-43d.com/signin", &known);
        assert!(homograph.is_suspicious);
        assert!(homograph.risk_score >= 80);
        assert!(homograph
            .risks
            .iter()
            .any(|r| matches!(r, PhishingRiskKind::MixedScriptHomograph { .. })));
        assert!(homograph
            .risks
            .iter()
            .any(|r| matches!(r, PhishingRiskKind::ConfusableSkeletonMatch { legitimate_domain } if legitimate_domain == "apple.com")));

        // Typosquatting githbu.com vs github.com
        let typo = assess_phishing_risk("https://githbu.com/login", &known);
        assert!(typo.is_suspicious);
        assert!(typo
            .risks
            .iter()
            .any(|r| matches!(r, PhishingRiskKind::Typosquatting { legitimate_domain, distance: 2 } if legitimate_domain == "github.com")));

        // Legitimate subdomain of github.com over HTTPS is clean
        let legit = assess_phishing_risk("https://gist.github.com/login", &known);
        assert!(!legit.is_suspicious);
        assert_eq!(legit.risk_score, 0);
    }

    #[test]
    fn test_multi_uri_ranking_and_fuzzy_search_across_item_types() {
        use crate::format::{LoginPayload, WifiPayload};

        let mut l_base = LoginPayload::default();
        l_base.username = "user-base".into();
        l_base.uris = vec![VaultUriEntry::new("https://github.com", UriMatchRule::BaseDomain)];
        let it_base = VaultItem::new("i1", "GitHub Base", VaultItemKind::Login(l_base), 100);

        let mut l_exact = LoginPayload::default();
        l_exact.username = "user-exact".into();
        l_exact.uris = vec![
            VaultUriEntry::new("https://never.github.com", UriMatchRule::Never),
            VaultUriEntry::new("https://gist.github.com/auth", UriMatchRule::Exact),
        ];
        let it_exact = VaultItem::new("i2", "Gist Auth", VaultItemKind::Login(l_exact), 100);

        let mut w = WifiPayload::default();
        w.ssid = "Singularity-Lab-6G".into();
        w.password = "super-secret-wifi".into();
        let mut it_wifi = VaultItem::new("i3", "Office Wi-Fi", VaultItemKind::Wifi(w), 100);
        it_wifi.tags = vec!["network".into()];

        let items = vec![it_base, it_exact, it_wifi];
        let matched = match_items_for_uri(&items, "https://gist.github.com/auth");
        assert_eq!(matched.len(), 2);
        // Exact match ranks above BaseDomain match
        assert_eq!(matched[0].item.id, "i2");
        assert_eq!(matched[1].item.id, "i1");

        // Fuzzy search finds Wi-Fi by SSID subsequence & tag without matching secret password
        let wifi_hits = fuzzy_search_items(&items, "singularity network", false);
        assert_eq!(wifi_hits.len(), 1);
        assert_eq!(wifi_hits[0].item.id, "i3");

        let secret_hits = fuzzy_search_items(&items, "super-secret-wifi", false);
        assert!(secret_hits.is_empty(), "Fuzzy search must never index secret password values");
    }

    #[test]
    fn test_regex_budget_stops_redos_and_unicode_ranges_do_not_materialize() {
        // 30 chained alternation groups = 2^30 branches without a step budget
        let evil_pattern = format!("^{}$", "(a|b)".repeat(30));
        assert!(!matches_uri_rule(
            &evil_pattern,
            UriMatchRule::GlobRegex,
            "cccccccccccccccccccccccccccccc"
        ));

        // Wide Unicode range [\u{0}-\u{10FFFF}] must match in O(1) without materializing 1.1M chars
        let wide_range = "^https://example\\.com/[\u{0000}-\u{10FFFF}]+$";
        assert!(matches_uri_rule(
            wide_range,
            UriMatchRule::GlobRegex,
            "https://example.com/hello-世界"
        ));
    }

    #[test]
    fn test_base_domain_and_host_block_https_downgrade_and_non_web_schemes() {
        // HTTPS stored credential MUST NOT match HTTP target (prevents MITM downgrade autofill)
        assert!(!matches_uri_rule(
            "https://github.com",
            UriMatchRule::BaseDomain,
            "http://github.com/login"
        ));
        assert!(!matches_uri_rule(
            "github.com",
            UriMatchRule::BaseDomain,
            "http://gist.github.com/login"
        ));
        assert!(!matches_uri_rule(
            "https://github.com:8443",
            UriMatchRule::Host,
            "http://github.com:8443/login"
        ));

        // Non-web schemes MUST NOT match in BaseDomain or Host
        for bad_target in [
            "ftp://github.com/pub",
            "javascript://github.com/%0aalert(1)",
            "file://github.com/etc/passwd",
        ] {
            assert!(
                !matches_uri_rule("https://github.com", UriMatchRule::BaseDomain, bad_target),
                "BaseDomain must reject non-web target {}",
                bad_target
            );
            assert!(
                !matches_uri_rule("https://github.com", UriMatchRule::Host, bad_target),
                "Host must reject non-web target {}",
                bad_target
            );
        }

        // Legitimate HTTP->HTTP and bare-domain->HTTPS continue to match
        assert!(matches_uri_rule(
            "http://intranet.local:8080",
            UriMatchRule::Host,
            "http://intranet.local:8080/dashboard"
        ));
        assert!(matches_uri_rule(
            "github.com",
            UriMatchRule::BaseDomain,
            "https://gist.github.com/login"
        ));
    }
}
