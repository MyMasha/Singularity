//! Multi-Threaded Rust Network-Layer Ad, Tracker & Script Blocker
//! (uBlock Origin / EasyList / EasyPrivacy compatible) + Tracking Query Parameter Scrubber.

use serde::{Deserialize, Serialize};
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

/// Thread-safe Rust network filter engine evaluating uBlock Origin rules at wire speed.
pub struct UBlockNetworkEngine {
    blocked_domains: std::collections::HashMap<String, RuleOptions>,
    exception_domains: std::collections::HashMap<String, RuleOptions>,
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
||facebook.net^
||connect.facebook.net^
||analytics.tiktok.com^
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
            blocked_domains: std::collections::HashMap::new(),
            exception_domains: std::collections::HashMap::new(),
            url_substrings: Vec::new(),
            blocked_count: AtomicU64::new(0),
        }
    }

    /// Parses uBlock Origin / Adblock Plus network filter list rules into O(1) hash tables,
    /// properly skipping cosmetic rules (`##`, `#@#`, `#?#`, `#$#`) and honoring `$options`.
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
                let domain = exc
                    .split(&['^', '/'][..])
                    .next()
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if !domain.is_empty() {
                    self.exception_domains.insert(domain, options);
                    added += 1;
                }
            } else if let Some(dom_rule) = rule_body.strip_prefix("||") {
                let domain = dom_rule
                    .split(&['^', '/'][..])
                    .next()
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if !domain.is_empty() {
                    self.blocked_domains.insert(domain, options);
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
        if resource_type == NetworkResourceType::PingBeacon {
            self.blocked_count.fetch_add(1, Ordering::Relaxed);
            return FilterDecision::BlockedBeaconOrPing;
        }

        let host_lower = request_host.trim().to_ascii_lowercase();
        let fp_lower = first_party_host.trim().to_ascii_lowercase();
        let is_third_party = !fp_lower.is_empty() && !same_site(&host_lower, &fp_lower);

        // Check exception rules (`@@||domain^`) across domain and parent labels
        for candidate in domain_hierarchy(&host_lower) {
            if let Some(opts) = self.exception_domains.get(candidate) {
                if opts.matches(is_third_party, resource_type) {
                    return FilterDecision::AllowByExceptionRule(candidate.to_string());
                }
            }
        }

        // Check blocked domain rules (`||domain^`) across domain and parent labels
        for candidate in domain_hierarchy(&host_lower) {
            if let Some(opts) = self.blocked_domains.get(candidate) {
                if opts.matches(is_third_party, resource_type) {
                    self.blocked_count.fetch_add(1, Ordering::Relaxed);
                    return FilterDecision::BlockedByDomainRule(candidate.to_string());
                }
            }
        }

        let url_lower = request_url.to_ascii_lowercase();
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

fn same_site(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    let reg_a = registrable_suffix(a);
    let reg_b = registrable_suffix(b);
    !reg_a.is_empty() && reg_a == reg_b
}

fn registrable_suffix(host: &str) -> &str {
    let mut dots = host.rmatch_indices('.');
    let _last = dots.next();
    match dots.next() {
        Some((idx, _)) => &host[idx + 1..],
        None => host,
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
