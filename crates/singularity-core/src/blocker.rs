//! Multi-Threaded Rust Network-Layer Ad, Tracker & Script Blocker
//! (uBlock Origin / EasyList / EasyPrivacy compatible) + Tracking Query Parameter Scrubber.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};

/// Resource context type evaluated by the network-layer blocker before Chromium parses DOM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkResourceType {
    MainFrameDocument,
    Script,
    Stylesheet,
    Image,
    XmlHttpRequestFetch,
    SubFrame,
    WebSocket,
    PingBeacon,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FilterDecision {
    Allow,
    AllowByExceptionRule(String),
    BlockedByDomainRule(String),
    BlockedByPatternRule(String),
    BlockedBeaconOrPing,
}

const TRACKING_QUERY_PARAMS: &[&str] = &[
    "fbclid", "gclid", "dclid", "msclkid", "twclid", "yclid", "mc_eid", "mc_cid",
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "utm_id",
    "_hsenc", "_hsmi", "hsCtaTracking", "vero_id", "oly_enc_id", "oly_anon_id",
    "rb_clickid", "s_kwcid", "wickedid", "igshid",
];

/// Comprehensive table of multi-label ICANN & Private Public Suffix List (PSL) entries
/// used for accurate eTLD+1 / `same_site` computation.
const MULTI_LABEL_PUBLIC_SUFFIXES: &[&str] = &[
    // United Kingdom
    "co.uk", "org.uk", "ac.uk", "gov.uk", "net.uk", "me.uk", "ltd.uk", "plc.uk", "nhs.uk",
    "police.uk", "sch.uk", "blogspot.co.uk",
    // Australia
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
    // Japan
    "co.jp", "ne.jp", "or.jp", "go.jp", "ac.jp", "ed.jp", "gr.jp", "lg.jp",
    // Brazil
    "com.br", "net.br", "org.br", "gov.br", "edu.br", "mil.br", "art.br", "blog.br", "dev.br",
    // New Zealand
    "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz", "gen.nz", "geek.nz", "school.nz",
    // South Africa
    "co.za", "org.za", "net.za", "gov.za", "ac.za", "web.za", "nom.za",
    // China, Taiwan, Hong Kong, Singapore
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
    "com.tw", "org.tw", "net.tw", "edu.tw", "gov.tw", "idv.tw",
    "com.hk", "org.hk", "net.hk", "edu.hk", "gov.hk", "idv.hk",
    "com.sg", "net.sg", "org.sg", "edu.sg", "gov.sg", "per.sg",
    // Latin America
    "com.mx", "org.mx", "gob.mx", "edu.mx", "net.mx",
    "com.ar", "net.ar", "org.ar", "gob.ar", "edu.ar",
    "com.co", "org.co", "edu.co", "gov.co", "net.co",
    "com.pe", "org.pe", "gob.pe", "edu.pe",
    "com.ve", "com.ec", "com.uy", "com.py", "com.bo",
    // India & South Korea
    "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in", "ac.in", "edu.in", "res.in",
    "gov.in", "nic.in",
    "co.kr", "or.kr", "ne.kr", "go.kr", "re.kr", "pe.kr", "ac.kr",
    // Europe, Middle East, Africa, Southeast Asia
    "com.tr", "gen.tr", "org.tr", "gov.tr", "edu.tr", "net.tr",
    "com.ua", "org.ua", "net.ua", "gov.ua", "edu.ua",
    "com.pl", "net.pl", "org.pl", "edu.pl", "gov.pl",
    "co.il", "org.il", "net.il", "ac.il", "gov.il",
    "co.id", "or.id", "ac.id", "go.id", "web.id",
    "com.my", "net.my", "org.my", "gov.my", "edu.my",
    "com.ph", "org.ph", "net.ph", "gov.ph", "edu.ph",
    "co.th", "in.th", "ac.th", "go.th", "or.th",
    "com.vn", "net.vn", "org.vn", "edu.vn", "gov.vn",
    "com.sa", "com.eg", "com.ng", "co.ke", "co.tz", "com.pk", "com.bd",
    "com.ru", "org.ru", "net.ru", "pp.ru", "spb.ru", "msk.ru",
    "com.es", "nom.es", "org.es", "gob.es", "edu.es",
    "asso.fr", "tm.fr", "gouv.fr",
    "co.at", "or.at", "gv.at", "ac.at",
    "eu.org",
    // Private Hosting, Cloud, PaaS & Static Site Platforms (PSL Private Section)
    "github.io", "gitlab.io", "pages.dev", "vercel.app", "netlify.app", "netlify.com",
    "amazonaws.com", "s3.amazonaws.com", "compute.amazonaws.com",
    "cloudfront.net", "herokuapp.com", "herokudns.com",
    "appspot.com", "googleusercontent.com", "storage.googleapis.com",
    "azurewebsites.net", "azurestaticapps.net", "blob.core.windows.net",
    "firebaseapp.com", "web.app", "workers.dev", "r2.dev",
    "fly.dev", "onrender.com", "railway.app", "surge.sh", "glitch.me",
    "blogspot.com", "wordpress.com", "tumblr.com",
    "akamaized.net", "fastly.net", "b-cdn.net",
    "readthedocs.io", "gitbook.io", "itch.io", "neocities.org",
    "duckdns.org", "ddns.net", "ngrok.io", "myshopify.com",
];

#[derive(Debug, Clone, Default)]
struct RuleOptions {
    third_party_only: bool,
    first_party_only: bool,
    resource_types: Vec<NetworkResourceType>,
}

impl RuleOptions {
    fn parse(raw: &str) -> Self {
        let mut opts = Self::default();
        for tok in raw.split(',') {
            match tok.trim().to_ascii_lowercase().as_str() {
                "third-party" | "3p" => opts.third_party_only = true,
                "~third-party" | "first-party" | "1p" => opts.first_party_only = true,
                "script" => opts.resource_types.push(NetworkResourceType::Script),
                "stylesheet" => opts.resource_types.push(NetworkResourceType::Stylesheet),
                "image" => opts.resource_types.push(NetworkResourceType::Image),
                "xmlhttprequest" | "xhr" => opts.resource_types.push(NetworkResourceType::XmlHttpRequestFetch),
                "subdocument" => opts.resource_types.push(NetworkResourceType::SubFrame),
                "websocket" => opts.resource_types.push(NetworkResourceType::WebSocket),
                "ping" => opts.resource_types.push(NetworkResourceType::PingBeacon),
                _ => {}
            }
        }
        opts
    }

    fn matches(&self, is_third_party: bool, resource_type: NetworkResourceType) -> bool {
        if self.third_party_only && !is_third_party {
            return false;
        }
        if self.first_party_only && is_third_party {
            return false;
        }
        if !self.resource_types.is_empty() && !self.resource_types.contains(&resource_type) {
            return false;
        }
        true
    }
}

#[derive(Debug, Clone)]
struct DomainPathRule {
    path_prefix: String,
    require_separator_end: bool,
    options: RuleOptions,
}

impl DomainPathRule {
    fn matches_path(&self, req_path_lower: &str) -> bool {
        if !req_path_lower.starts_with(&self.path_prefix) {
            return false;
        }
        if !self.require_separator_end {
            return true;
        }
        match req_path_lower.as_bytes().get(self.path_prefix.len()) {
            None => true,
            Some(&b) => is_abp_separator(b),
        }
    }
}

fn is_abp_separator(b: u8) -> bool {
    !(b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.' || b == b'%')
}

/// Thread-safe Rust network filter engine evaluating uBlock Origin rules at wire speed.
pub struct UBlockNetworkEngine {
    blocked_domains: HashMap<String, Vec<RuleOptions>>,
    blocked_domain_paths: HashMap<String, Vec<DomainPathRule>>,
    exception_domains: HashMap<String, Vec<RuleOptions>>,
    exception_domain_paths: HashMap<String, Vec<DomainPathRule>>,
    url_substrings: Vec<(String, RuleOptions)>,
    blocked_count: AtomicU64,
}

impl Default for UBlockNetworkEngine {
    fn default() -> Self {
        let mut engine = Self::new();
        engine.load_filter_list(DEFAULT_UBLOCK_FILTER_RULES);
        engine
    }
}

pub const DEFAULT_UBLOCK_FILTER_RULES: &str = r#"
! Singularity Built-In uBlock Origin & EasyPrivacy Core Rules
||doubleclick.net^
||googlesyndication.com^
||google-analytics.com^
||googletagmanager.com^
||googleadservices.com^
||facebook.net^$third-party
||connect.facebook.net^$third-party
||analytics.tiktok.com^$third-party
||ads-twitter.com^
||amazon-adsystem.com^
||adnxs.com^
||criteo.com^
||taboola.com^
||outbrain.com^
||scorecardresearch.com^
||quantserve.com^
||hotjar.com^
||mouseflow.com^
||fullstory.com^
||mixpanel.com^
||segment.io^
||amplitude.com^
||sentry-cdn.com^
||bugsnag.com^
||newrelic.com^
||nr-data.net^
/pagead/js/adsbygoogle.js
/analytics.js
/gtag/js
/fbevents.js
/pixel.gif
@@||mullvad.net^
"#;

impl UBlockNetworkEngine {
    pub fn new() -> Self {
        Self {
            blocked_domains: HashMap::new(),
            blocked_domain_paths: HashMap::new(),
            exception_domains: HashMap::new(),
            exception_domain_paths: HashMap::new(),
            url_substrings: Vec::new(),
            blocked_count: AtomicU64::new(0),
        }
    }

    /// Parses uBlock Origin / Adblock Plus network filter list rules into O(1) hash tables,
    /// properly skipping cosmetic rules (`##`, `#@#`, `#?#`, `#$#`), preserving `||domain/path`
    /// path-prefix rules without truncating to the whole domain, and honoring `$options`.
    pub fn load_filter_list(&mut self, raw_list: &str) -> usize {
        let mut added = 0;
        for line in raw_list.lines() {
            let rule = line.trim();
            if rule.is_empty()
                || rule.starts_with('!')
                || rule.starts_with('[')
                || rule.contains("##")
                || rule.contains("#@#")
                || rule.contains("#?#")
                || rule.contains("#$#")
            {
                continue;
            }

            let (rule_body, options) = match rule.split_once('$') {
                Some((body, opt_str)) => (body, RuleOptions::parse(opt_str)),
                None => (rule, RuleOptions::default()),
            };

            if let Some(exc) = rule_body.strip_prefix("@@||") {
                let opts_clone = options.clone();
                if let Some((domain, path_rule_opt)) = parse_domain_anchored_rule(exc, options) {
                    match path_rule_opt {
                        Some(path_rule) => {
                            self.exception_domain_paths
                                .entry(domain)
                                .or_default()
                                .push(path_rule);
                        }
                        None => {
                            self.exception_domains
                                .entry(domain)
                                .or_default()
                                .push(opts_clone);
                        }
                    }
                    added += 1;
                }
            } else if let Some(dom_rule) = rule_body.strip_prefix("||") {
                let opts_clone = options.clone();
                if let Some((domain, path_rule_opt)) = parse_domain_anchored_rule(dom_rule, options)
                {
                    match path_rule_opt {
                        Some(path_rule) => {
                            self.blocked_domain_paths
                                .entry(domain)
                                .or_default()
                                .push(path_rule);
                        }
                        None => {
                            self.blocked_domains
                                .entry(domain)
                                .or_default()
                                .push(opts_clone);
                        }
                    }
                    added += 1;
                }
            } else {
                let pattern = rule_body.to_ascii_lowercase();
                if !pattern.is_empty() {
                    self.url_substrings.push((pattern, options));
                    added += 1;
                }
            }
        }
        added
    }

    /// Evaluates a candidate network request before socket dispatch.
    pub fn evaluate_request(
        &self,
        request_url: &str,
        request_host: &str,
        first_party_host: &str,
        resource_type: NetworkResourceType,
    ) -> FilterDecision {
        let host_lower = request_host.trim().trim_end_matches('.').to_ascii_lowercase();
        let fp_lower = first_party_host
            .trim()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        let is_third_party = !fp_lower.is_empty() && !same_site(&host_lower, &fp_lower);

        if resource_type == NetworkResourceType::PingBeacon && is_third_party {
            self.blocked_count.fetch_add(1, Ordering::Relaxed);
            return FilterDecision::BlockedBeaconOrPing;
        }

        let url_lower = request_url.to_ascii_lowercase();
        let req_path_lower = extract_url_path_lower(&url_lower);
        let hierarchy = domain_hierarchy(&host_lower);

        // Check exception rules (`@@||domain^` and `@@||domain/path`) across domain and parent labels
        for &candidate in &hierarchy {
            if let Some(opts_list) = self.exception_domains.get(candidate) {
                if opts_list
                    .iter()
                    .any(|opts| opts.matches(is_third_party, resource_type))
                {
                    return FilterDecision::AllowByExceptionRule(candidate.to_string());
                }
            }
            if let Some(path_rules) = self.exception_domain_paths.get(candidate) {
                for rule in path_rules {
                    if rule.options.matches(is_third_party, resource_type)
                        && rule.matches_path(req_path_lower)
                    {
                        return FilterDecision::AllowByExceptionRule(format!(
                            "{}{}",
                            candidate, rule.path_prefix
                        ));
                    }
                }
            }
        }

        // Check blocked whole-domain rules (`||domain^`) across domain and parent labels
        for &candidate in &hierarchy {
            if let Some(opts_list) = self.blocked_domains.get(candidate) {
                if opts_list
                    .iter()
                    .any(|opts| opts.matches(is_third_party, resource_type))
                {
                    self.blocked_count.fetch_add(1, Ordering::Relaxed);
                    return FilterDecision::BlockedByDomainRule(candidate.to_string());
                }
            }
        }

        // Check blocked domain+path prefix rules (`||domain/path`) without blocking unrelated paths
        for &candidate in &hierarchy {
            if let Some(path_rules) = self.blocked_domain_paths.get(candidate) {
                for rule in path_rules {
                    if rule.options.matches(is_third_party, resource_type)
                        && rule.matches_path(req_path_lower)
                    {
                        self.blocked_count.fetch_add(1, Ordering::Relaxed);
                        return FilterDecision::BlockedByPatternRule(format!(
                            "||{}{}",
                            candidate, rule.path_prefix
                        ));
                    }
                }
            }
        }

        for (pat, opts) in &self.url_substrings {
            if opts.matches(is_third_party, resource_type) && url_lower.contains(pat) {
                self.blocked_count.fetch_add(1, Ordering::Relaxed);
                return FilterDecision::BlockedByPatternRule(pat.clone());
            }
        }

        FilterDecision::Allow
    }

    /// Strips tracking query parameters (`fbclid`, `gclid`, `utm_*`, etc.) from a URL.
    /// Domain-specific tracking params like `si` are only stripped on known platforms (YouTube/Spotify).
    pub fn scrub_tracking_query_params(raw_url: &str) -> String {
        let Some((base, query_and_frag)) = raw_url.split_once('?') else {
            return raw_url.to_string();
        };

        let (query, fragment_opt) = match query_and_frag.split_once('#') {
            Some((q, f)) => (q, Some(f)),
            None => (query_and_frag, None),
        };

        let base_lower = base.to_ascii_lowercase();
        let strip_si = base_lower.contains("youtube.com/")
            || base_lower.contains("youtu.be/")
            || base_lower.contains("open.spotify.com/");

        let retained_pairs: Vec<&str> = query
            .split('&')
            .filter(|pair| {
                let key = pair.split('=').next().unwrap_or("");
                if strip_si && key.eq_ignore_ascii_case("si") {
                    return false;
                }
                !TRACKING_QUERY_PARAMS
                    .iter()
                    .any(|&trk| trk.eq_ignore_ascii_case(key))
            })
            .collect();

        let mut cleaned = base.to_string();
        if !retained_pairs.is_empty() {
            cleaned.push('?');
            cleaned.push_str(&retained_pairs.join("&"));
        }
        if let Some(frag) = fragment_opt {
            cleaned.push('#');
            cleaned.push_str(frag);
        }
        cleaned
    }

    pub fn total_blocked_requests(&self) -> u64 {
        self.blocked_count.load(Ordering::Relaxed)
    }
}

/// Parses the body after `||` or `@@||` into `(domain, Option<DomainPathRule>)`.
/// Pure domain rules like `example.com^` return `(domain, None)`;
/// domain+path rules like `example.com/ads/tracker.js` keep the path prefix intact.
fn parse_domain_anchored_rule(
    raw: &str,
    options: RuleOptions,
) -> Option<(String, Option<DomainPathRule>)> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    let first_delim = trimmed.find(['/', '^']);
    match first_delim {
        None => {
            let domain = trimmed.trim_end_matches('.').to_ascii_lowercase();
            if domain.is_empty() {
                None
            } else {
                Some((domain, None))
            }
        }
        Some(idx) => {
            let domain = trimmed[..idx].trim_end_matches('.').to_ascii_lowercase();
            if domain.is_empty() {
                return None;
            }
            let tail = &trimmed[idx..];
            let path_part = if let Some(after_caret) = tail.strip_prefix('^') {
                if after_caret.is_empty() {
                    return Some((domain, None));
                }
                after_caret
            } else {
                tail
            };

            if path_part.starts_with('/') {
                let require_separator_end = path_part.ends_with('^');
                let cleaned_path = path_part.trim_end_matches('^').to_ascii_lowercase();
                if cleaned_path == "/" && !require_separator_end {
                    return Some((domain, None));
                }
                Some((
                    domain,
                    Some(DomainPathRule {
                        path_prefix: cleaned_path,
                        require_separator_end,
                        options,
                    }),
                ))
            } else {
                Some((domain, None))
            }
        }
    }
}

fn extract_url_path_lower(url_lower: &str) -> &str {
    let after_scheme = if let Some((_, rest)) = url_lower.split_once("://") {
        rest
    } else if let Some(rest) = url_lower.strip_prefix("//") {
        rest
    } else {
        url_lower
    };
    match after_scheme.find('/') {
        Some(idx) => &after_scheme[idx..],
        None => "/",
    }
}

fn is_multi_label_public_suffix(candidate: &str) -> bool {
    MULTI_LABEL_PUBLIC_SUFFIXES.contains(&candidate)
}

fn same_site(a: &str, b: &str) -> bool {
    let norm_a = a.trim().trim_end_matches('.');
    let norm_b = b.trim().trim_end_matches('.');
    if norm_a.is_empty() || norm_b.is_empty() {
        return false;
    }
    if norm_a == norm_b {
        return true;
    }
    let reg_a = registrable_suffix(norm_a);
    let reg_b = registrable_suffix(norm_b);
    !reg_a.is_empty() && reg_a == reg_b
}

/// Computes the registrable domain (eTLD+1) using a multi-label Public Suffix table
/// (covering ccSLDs like `.co.uk`, `.com.au`, `.co.jp` and private hosting suffixes like
/// `.github.io`, `.pages.dev`, `.vercel.app`, `.amazonaws.com`, `.cloudfront.net`, etc.).
fn registrable_suffix(host: &str) -> &str {
    let h = host.trim_end_matches('.');
    if h.is_empty() || h.parse::<IpAddr>().is_ok() {
        return h;
    }
    // If the host itself is a known multi-label public suffix, do not collapse it further.
    if is_multi_label_public_suffix(h) {
        return h;
    }

    // Walk proper suffixes from longest to shortest so 3-label suffixes (e.g. s3.amazonaws.com)
    // match before shorter 2-label suffixes (e.g. amazonaws.com).
    for (dot_idx, ch) in h.char_indices() {
        if ch == '.' && dot_idx + 1 < h.len() {
            let suffix = &h[dot_idx + 1..];
            if is_multi_label_public_suffix(suffix) {
                let prefix = &h[..dot_idx];
                return match prefix.rfind('.') {
                    Some(prev_dot) => &h[prev_dot + 1..],
                    None => h,
                };
            }
        }
    }

    // Standard single-label TLD fallback: return last 2 labels (eTLD+1).
    let mut dots = h.rmatch_indices('.');
    let _last = dots.next();
    match dots.next() {
        Some((idx, _)) => &h[idx + 1..],
        None => h,
    }
}

fn domain_hierarchy(host: &str) -> Vec<&str> {
    let mut slices = vec![host];
    for (idx, ch) in host.char_indices() {
        if ch == '.' && idx + 1 < host.len() {
            slices.push(&host[idx + 1..]);
        }
    }
    slices
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_suffix_same_site_distinguishes_independent_tenants() {
        // Multi-label ccTLDs must NOT collapse to `.co.uk`, `.com.au`, `.co.jp`, etc.
        assert!(!same_site("bank.co.uk", "tracker.co.uk"));
        assert!(same_site("cdn.bank.co.uk", "www.bank.co.uk"));
        assert!(!same_site("shop.com.au", "ads.com.au"));
        assert!(!same_site("site-a.co.jp", "site-b.co.jp"));
        assert!(!same_site("a.com.br", "b.com.br"));
        assert!(!same_site("a.co.nz", "b.co.nz"));
        assert!(!same_site("a.co.za", "b.co.za"));
        assert!(!same_site("a.com.cn", "b.com.cn"));
        assert!(!same_site("a.co.in", "b.co.in"));
        assert!(!same_site("a.co.kr", "b.co.kr"));

        // Private hosting PSL suffixes must isolate different customer origins
        assert!(!same_site("alice.github.io", "bob.github.io"));
        assert!(same_site("docs.alice.github.io", "alice.github.io"));
        assert!(!same_site("app1.vercel.app", "app2.vercel.app"));
        assert!(!same_site("site1.pages.dev", "site2.pages.dev"));
        assert!(!same_site("site1.netlify.app", "site2.netlify.app"));
        assert!(!same_site("d1.cloudfront.net", "d2.cloudfront.net"));
        assert!(!same_site("bucket1.s3.amazonaws.com", "bucket2.s3.amazonaws.com"));
        assert!(!same_site("blog1.blogspot.com", "blog2.blogspot.com"));
        assert!(!same_site("app1.workers.dev", "app2.workers.dev"));
        assert!(!same_site("app1.firebaseapp.com", "app2.firebaseapp.com"));
        assert!(!same_site("app1.web.app", "app2.web.app"));
        assert!(!same_site("app1.azurewebsites.net", "app2.azurewebsites.net"));
    }

    #[test]
    fn test_third_party_ping_blocked_across_multi_label_psl() {
        let engine = UBlockNetworkEngine::default();
        // Two distinct tenants on `.co.uk` and `.github.io` are third-party to each other
        assert_eq!(
            engine.evaluate_request(
                "https://tracker.co.uk/beacon",
                "tracker.co.uk",
                "shop.co.uk",
                NetworkResourceType::PingBeacon,
            ),
            FilterDecision::BlockedBeaconOrPing
        );
        assert_eq!(
            engine.evaluate_request(
                "https://evil.github.io/collect",
                "evil.github.io",
                "victim.github.io",
                NetworkResourceType::PingBeacon,
            ),
            FilterDecision::BlockedBeaconOrPing
        );
        // Same tenant subdomain remains first-party
        assert_eq!(
            engine.evaluate_request(
                "https://api.shop.co.uk/beacon",
                "api.shop.co.uk",
                "www.shop.co.uk",
                NetworkResourceType::PingBeacon,
            ),
            FilterDecision::Allow
        );
    }

    #[test]
    fn test_domain_path_rules_do_not_truncate_to_entire_domain() {
        let mut engine = UBlockNetworkEngine::new();
        engine.load_filter_list(
            r#"
            ||example.org/ads/banner.js
            ||cdn.example.net/track^$script
            @@||example.org/ads/banner.js?allow=1
            "#,
        );

        // Matching domain + path prefix MUST be blocked
        assert!(matches!(
            engine.evaluate_request(
                "https://example.org/ads/banner.js",
                "example.org",
                "news.test",
                NetworkResourceType::Script,
            ),
            FilterDecision::BlockedByPatternRule(_)
        ));
        // Path-specific exception rule `@@||example.org/ads/banner.js?allow=1` MUST allow it
        assert!(matches!(
            engine.evaluate_request(
                "https://example.org/ads/banner.js?allow=1",
                "example.org",
                "news.test",
                NetworkResourceType::Script,
            ),
            FilterDecision::AllowByExceptionRule(_)
        ));
        // Unrelated path on the SAME domain MUST be allowed (NOT truncated to ||example.org^)
        assert_eq!(
            engine.evaluate_request(
                "https://example.org/app/main.js",
                "example.org",
                "news.test",
                NetworkResourceType::Script,
            ),
            FilterDecision::Allow
        );
        // Trailing separator `^` on path prefix respects boundary
        assert!(matches!(
            engine.evaluate_request(
                "https://sub.cdn.example.net/track?id=1",
                "sub.cdn.example.net",
                "news.test",
                NetworkResourceType::Script,
            ),
            FilterDecision::BlockedByPatternRule(_)
        ));
        assert_eq!(
            engine.evaluate_request(
                "https://sub.cdn.example.net/tracker_docs.js",
                "sub.cdn.example.net",
                "news.test",
                NetworkResourceType::Script,
            ),
            FilterDecision::Allow
        );
    }
}
