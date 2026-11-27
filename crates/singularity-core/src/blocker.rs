//! Multi-Threaded Rust Network-Layer Ad, Tracker & Script Blocker
//! (uBlock Origin / EasyList / EasyPrivacy compatible), Cosmetic & Procedural Filter Engine,
//! Surrogate Scriptlet Catalogue, Extended ClearURLs + Anti-Bounce Debouncer,
//! uBlock Dynamic Filtering Matrix, Per-Site Shields Policies, and Bounded Live Logger.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Hard cap on buffered real-time shield log events to bound memory footprint.
pub const MAX_SHIELD_LOG_EVENTS: usize = 2_000;

/// Resource context type evaluated by the network-layer blocker before Chromium parses DOM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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

/// Built-in and user-defined filter list categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FilterListKind {
    EasyList,
    EasyPrivacy,
    UBlockCore,
    UBlockPrivacy,
    UBlockBadware,
    UBlockUnbreak,
    UBlockAnnoyances,
    EasyListCookie,
    FanboyAnnoyances,
    ListeFr,
    Custom,
}

/// Metadata and HTTP caching validators for an installed filter list subscription.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilterListSubscription {
    pub id: String,
    pub name: String,
    pub kind: FilterListKind,
    pub source_url: String,
    pub enabled: bool,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub rule_count: usize,
    pub last_updated_unix: u64,
}

/// Summary counters returned by [`UBlockNetworkEngine::load_filter_list_text`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilterListLoadStats {
    pub network_rules_added: usize,
    pub exception_rules_added: usize,
    pub badfilter_rules_added: usize,
    pub csp_rules_added: usize,
    pub removeparam_rules_added: usize,
    pub redirect_rules_added: usize,
    pub cosmetic_rules_added: usize,
    pub procedural_rules_added: usize,
    pub scriptlet_rules_added: usize,
    pub total_added: usize,
}

/// Procedural cosmetic filter operator parsed from `#?#` or extended `##` selectors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProceduralOperator {
    HasText(String),
    Upward(String),
    Style(String),
    Remove,
}

/// Parsed procedural cosmetic rule targeted at DOM nodes on matching hosts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProceduralCosmeticRule {
    pub base_selector: String,
    pub operators: Vec<ProceduralOperator>,
    pub raw_selector: String,
}

/// Scriptlet injection instruction (`domain##+js(name, arg1, arg2)`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScriptletInjection {
    pub name: String,
    pub args: Vec<String>,
    pub resolved_source: Option<String>,
}

/// Aggregated cosmetic hiding selectors, procedural filters, and scriptlets for a host.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CosmeticResources {
    pub css_selectors: Vec<String>,
    pub procedural_rules: Vec<ProceduralCosmeticRule>,
    pub scriptlets: Vec<ScriptletInjection>,
}

/// Embedded `$redirect=` surrogate resource returned instead of a blocked tracker asset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SurrogateResource {
    pub name: String,
    pub mime_type: String,
    pub body: String,
    pub is_base64: bool,
}

/// Three-state dynamic filtering action compatible with uBlock Origin Medium Mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DynamicRuleAction {
    Block,
    Noop,
    Allow,
}

/// Resource granularity column in the uBlock dynamic filtering matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DynamicResourceKind {
    All,
    InlineScript,
    FirstPartyScript,
    ThirdParty,
    ThirdPartyScript,
    ThirdPartyFrame,
}

/// uBlock Origin-compatible dynamic filtering matrix (`(source_site, dest_domain, kind) -> action`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DynamicRuleMatrix {
    rules: HashMap<(String, String, DynamicResourceKind), DynamicRuleAction>,
}

impl DynamicRuleMatrix {
    pub fn new() -> Self {
        Self::default()
    }

    /// Enables uBlock Medium Mode defaults: globally blocks 3rd-party scripts and 3rd-party frames
    /// while allowing per-site `Noop` / `Allow` overrides.
    pub fn enable_medium_mode(&mut self) {
        self.set_rule("*", "*", DynamicResourceKind::ThirdPartyScript, DynamicRuleAction::Block);
        self.set_rule("*", "*", DynamicResourceKind::ThirdPartyFrame, DynamicRuleAction::Block);
    }

    pub fn set_rule(
        &mut self,
        source_site: &str,
        dest_domain: &str,
        kind: DynamicResourceKind,
        action: DynamicRuleAction,
    ) {
        let src = normalize_matrix_scope(source_site);
        let dst = normalize_matrix_scope(dest_domain);
        self.rules.insert((src, dst, kind), action);
    }

    pub fn remove_rule(
        &mut self,
        source_site: &str,
        dest_domain: &str,
        kind: DynamicResourceKind,
    ) -> bool {
        let src = normalize_matrix_scope(source_site);
        let dst = normalize_matrix_scope(dest_domain);
        self.rules.remove(&(src, dst, kind)).is_some()
    }

    pub fn clear(&mut self) {
        self.rules.clear();
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn rules(&self) -> Vec<(String, String, DynamicResourceKind, DynamicRuleAction)> {
        let mut out: Vec<_> = self
            .rules
            .iter()
            .map(|((s, d, k), &a)| (s.clone(), d.clone(), *k, a))
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        out
    }

    /// Evaluates dynamic filtering precedence for a request:
    /// most specific `(source_hierarchy, dest_hierarchy, specific_kind)` wins over coarser/global rules.
    pub fn evaluate(
        &self,
        source_site: &str,
        dest_domain: &str,
        is_third_party: bool,
        resource_type: NetworkResourceType,
    ) -> Option<DynamicRuleAction> {
        if self.rules.is_empty() {
            return None;
        }
        let src_norm = normalize_host(source_site);
        let dst_norm = normalize_host(dest_domain);

        let mut src_candidates: Vec<&str> = if src_norm.is_empty() {
            Vec::new()
        } else {
            domain_hierarchy(&src_norm)
        };
        src_candidates.push("*");

        let mut dst_candidates: Vec<&str> = if dst_norm.is_empty() {
            Vec::new()
        } else {
            domain_hierarchy(&dst_norm)
        };
        dst_candidates.push("*");

        let mut kinds = Vec::with_capacity(3);
        if is_third_party {
            match resource_type {
                NetworkResourceType::Script => {
                    kinds.push(DynamicResourceKind::ThirdPartyScript);
                    kinds.push(DynamicResourceKind::ThirdParty);
                }
                NetworkResourceType::SubFrame => {
                    kinds.push(DynamicResourceKind::ThirdPartyFrame);
                    kinds.push(DynamicResourceKind::ThirdParty);
                }
                _ => {
                    kinds.push(DynamicResourceKind::ThirdParty);
                }
            }
        } else if resource_type == NetworkResourceType::Script {
            kinds.push(DynamicResourceKind::FirstPartyScript);
        }
        kinds.push(DynamicResourceKind::All);

        // Local site rules beat global (`*`) rules; more specific destination domains beat wildcard `*`.
        for src in &src_candidates {
            for dst in &dst_candidates {
                for &kind in &kinds {
                    if let Some(&action) =
                        self.rules
                            .get(&((*src).to_string(), (*dst).to_string(), kind))
                    {
                        return Some(action);
                    }
                }
            }
        }
        None
    }
}

fn normalize_matrix_scope(scope: &str) -> String {
    let trimmed = scope.trim();
    if trimmed == "*" || trimmed.is_empty() {
        "*".to_string()
    } else {
        normalize_host(trimmed)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdblockLevel {
    Off,
    Standard,
    Aggressive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FingerprintProtectionLevel {
    Off,
    Standard,
    Strict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CookieBlockingLevel {
    AllowAll,
    BlockThirdParty,
    BlockAll,
}

/// Per-site Singularity Shields configuration overriding global defaults.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiteShieldsPolicy {
    pub enabled: bool,
    pub adblock_level: AdblockLevel,
    pub fingerprint_level: FingerprintProtectionLevel,
    pub cookie_level: CookieBlockingLevel,
    pub block_all_scripts: bool,
    pub allowed_script_domains: Vec<String>,
    pub forgetful_browsing: bool,
    pub block_cookie_notices: bool,
}

impl Default for SiteShieldsPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            adblock_level: AdblockLevel::Standard,
            fingerprint_level: FingerprintProtectionLevel::Standard,
            cookie_level: CookieBlockingLevel::BlockThirdParty,
            block_all_scripts: false,
            allowed_script_domains: Vec::new(),
            forgetful_browsing: false,
            block_cookie_notices: true,
        }
    }
}

/// Structured network-blocking event captured in the bounded real-time logger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldLogEvent {
    pub timestamp_unix_ms: u64,
    pub first_party_host: String,
    pub request_host: String,
    pub request_url: String,
    pub resource_type: NetworkResourceType,
    pub decision: FilterDecision,
    pub redirect_resource: Option<String>,
    pub dynamic_rule_matched: bool,
}

/// Detailed network evaluation outcome including `$redirect=`, `$csp=`, and dynamic rule metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilterEvaluationResult {
    pub decision: FilterDecision,
    pub redirect_resource: Option<SurrogateResource>,
    pub csp_directives: Vec<String>,
    pub dynamic_action: Option<DynamicRuleAction>,
    pub rewritten_url: Option<String>,
}

/// Global ClearURLs tracking query parameters stripped across all domains (90+ parameters).
pub const GLOBAL_TRACKING_QUERY_PARAMS: &[&str] = &[
    // Meta / Facebook / Instagram
    "fbclid", "fb_action_ids", "fb_action_types", "fb_ref", "fb_source", "igshid", "igsh",
    // Google / DoubleClick / Ads / GA4
    "gclid", "dclid", "gbraid", "wbraid", "gclsrc", "srsltid", "_ga", "_gl", "_gac",
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "utm_id",
    "utm_source_platform", "utm_creative_format", "utm_marketing_tactic", "utm_reader",
    "utm_name", "utm_place", "utm_pubreferrer", "utm_swu", "utm_viz_id", "utm_cid",
    // Microsoft / Bing / LinkedIn
    "msclkid", "li_fat_id", "trk", "trkinfo",
    // X / Twitter / TikTok / Snapchat / Pinterest / Reddit
    "twclid", "ttclid", "sclid", "sccid", "epik", "rdt_cid",
    // Yandex / Baidu / Mail.ru
    "yclid", "ymclid", "_openstat", "frommarket", "ysclid", "bd_vid",
    // Email marketing & CRM (Mailchimp, HubSpot, Marketo, Klaviyo, Braze, Vero, Olytics, Drip, Sailthru, Iterable)
    "mc_eid", "mc_cid", "_hsenc", "_hsmi", "hsctatracking", "__hssc", "__hstc", "__hsfp",
    "mkt_tok", "_kx", "vero_id", "vero_conv", "oly_enc_id", "oly_anon_id",
    "__s", "ml_subscriber", "ml_subscriber_hash", "ck_subscriber_id",
    "oft_id", "oft_k", "oft_lk", "oft_d", "oft_c", "oft_ck", "oft_ids", "oft_sk",
    // Ad networks & Attribution (Adobe, WickedReports, Rakuten, Outbrain, Taboola, Criteo, Matomo, Parsely)
    "rb_clickid", "s_kwcid", "s_cid", "wickedid", "wickedsource", "ef_id", "icid", "irclickid",
    "mtm_source", "mtm_medium", "mtm_campaign", "mtm_keyword", "mtm_cid", "mtm_content",
    "pk_source", "pk_medium", "pk_campaign", "pk_kwd", "pk_content", "pk_cid",
    "oborigurl", "tblci", "dicbo", "at_medium", "at_campaign", "at_custom1", "at_custom2",
    "ns_mchannel", "ns_source", "ns_campaign", "ns_linkname", "ns_fee",
    "guce_referrer", "guce_referrer_sig", "guccounter", "cmpid", "ncid", "ocid", "cvid",
    "ref_src", "ref_url", "hsa_acc", "hsa_cam", "hsa_grp", "hsa_ad", "hsa_src", "hsa_net",
    "hsa_ver", "hsa_la", "hsa_ol", "hsa_kw", "hsa_mt", "hsa_tgt",
];

/// Domain-scoped ClearURLs tracking query parameters (60+ additional platform-specific parameters).
pub const DOMAIN_SCOPED_TRACKING_PARAMS: &[(&str, &[&str])] = &[
    ("youtube.com", &["si", "feature", "pp", "kw", "embeds_referring_euri"]),
    ("youtu.be", &["si", "feature", "pp"]),
    ("spotify.com", &["si", "context", "sp_cid", "nd", "dlsi"]),
    (
        "amazon.com",
        &[
            "tag", "ref_", "pf_rd_r", "pf_rd_p", "pf_rd_m", "pf_rd_s", "pf_rd_t", "pf_rd_i",
            "pd_rd_r", "pd_rd_w", "pd_rd_wg", "qid", "sr", "dib", "dib_tag", "sprefix", "crid",
            "psc", "smid", "linkcode", "camp", "creative", "creativeasin", "ascsubtag",
        ],
    ),
    (
        "amazon.fr",
        &[
            "tag", "ref_", "pf_rd_r", "pf_rd_p", "pd_rd_r", "pd_rd_w", "pd_rd_wg", "qid", "sr",
            "dib", "dib_tag", "sprefix", "crid",
        ],
    ),
    (
        "aliexpress.com",
        &[
            "spm", "algo_pvid", "algo_exp_id", "btsid", "ws_ab_test", "aff_fcid", "aff_fsk",
            "aff_platform", "aff_trace_key", "terminal_id", "pdp_npi",
        ],
    ),
    (
        "ebay.com",
        &[
            "_trkparms", "_trksid", "_from", "mkcid", "mkrid", "campid", "toolid", "customid",
            "mkevt", "amdata",
        ],
    ),
    ("twitter.com", &["s", "t", "cxt", "cn", "refsrc"]),
    ("x.com", &["s", "t", "cxt", "cn", "refsrc"]),
    ("reddit.com", &["share_id", "rdt", "correlation_id", "ref_campaign", "ref_source"]),
    ("instagram.com", &["img_index", "utm_medium"]),
    ("facebook.com", &["__cft__[0]", "__tn__", "mibextid", "refsrc", "hc_ref", "fref", "eav"]),
    ("linkedin.com", &["lipi", "licu", "midtoken", "midsig", "otptoken", "rcm", "trackingid"]),
    ("tiktok.com", &["_t", "_r", "is_from_webapp", "sender_device", "sender_web_id"]),
    ("substack.com", &["triedredirect", "publication_id", "post_id", "isFreemail"]),
    ("medium.com", &["source", "sk"]),
    ("github.com", &["ref_cta", "ref_loc", "ref_page"]),
    ("nytimes.com", &["smid", "smtyp", "unlocked_article_code"]),
    ("booking.com", &["aid", "label", "sid", "ucfs"]),
    ("netflix.com", &["trackid", "tctx", "jbv"]),
    ("steampowered.com", &["snr", "curator_clanid"]),
    ("bing.com", &["cvid", "form", "pq", "sc", "sp", "qs", "sk"]),
    ("google.com", &["ei", "ved", "uact", "oq", "gs_lcp", "sclient", "bih", "biw", "sca_esv"]),
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
    important: bool,
    badfilter: bool,
    resource_types: Vec<NetworkResourceType>,
    excluded_resource_types: Vec<NetworkResourceType>,
    include_domains: Vec<String>,
    exclude_domains: Vec<String>,
    csp: Option<String>,
    removeparam: Option<String>,
    redirect: Option<String>,
    canonical_key: String,
}

impl RuleOptions {
    fn parse(raw: &str, canonical_key: String) -> Self {
        let mut opts = Self {
            canonical_key,
            ..Self::default()
        };
        for tok in split_options_preserving_values(raw) {
            let trimmed = tok.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Some(dom_list) = strip_ascii_prefix_ci(trimmed, "domain=") {
                for dom in dom_list.split('|') {
                    let d = dom.trim().to_ascii_lowercase();
                    if let Some(exc) = d.strip_prefix('~') {
                        if !exc.is_empty() {
                            opts.exclude_domains.push(exc.trim_end_matches('.').to_string());
                        }
                    } else if !d.is_empty() {
                        opts.include_domains.push(d.trim_end_matches('.').to_string());
                    }
                }
                continue;
            }
            if let Some(csp_val) = strip_ascii_prefix_ci(trimmed, "csp=") {
                let v = csp_val.trim();
                if !v.is_empty() {
                    opts.csp = Some(v.to_string());
                }
                continue;
            }
            if let Some(rp_val) = strip_ascii_prefix_ci(trimmed, "removeparam=") {
                opts.removeparam = Some(rp_val.trim().to_string());
                continue;
            }
            if let Some(redir) = strip_ascii_prefix_ci(trimmed, "redirect=")
                .or_else(|| strip_ascii_prefix_ci(trimmed, "redirect-rule="))
            {
                let v = redir.trim();
                if !v.is_empty() {
                    opts.redirect = Some(v.to_string());
                }
                continue;
            }

            let lower = trimmed.to_ascii_lowercase();
            match lower.as_str() {
                "third-party" | "3p" => opts.third_party_only = true,
                "~third-party" | "first-party" | "1p" => opts.first_party_only = true,
                "important" => opts.important = true,
                "badfilter" => opts.badfilter = true,
                "removeparam" => opts.removeparam = Some("*".to_string()),
                "script" => opts.resource_types.push(NetworkResourceType::Script),
                "~script" => opts.excluded_resource_types.push(NetworkResourceType::Script),
                "stylesheet" | "css" => opts.resource_types.push(NetworkResourceType::Stylesheet),
                "~stylesheet" | "~css" => {
                    opts.excluded_resource_types
                        .push(NetworkResourceType::Stylesheet)
                }
                "image" => opts.resource_types.push(NetworkResourceType::Image),
                "~image" => opts.excluded_resource_types.push(NetworkResourceType::Image),
                "xmlhttprequest" | "xhr" => {
                    opts.resource_types.push(NetworkResourceType::XmlHttpRequestFetch)
                }
                "~xmlhttprequest" | "~xhr" => {
                    opts.excluded_resource_types
                        .push(NetworkResourceType::XmlHttpRequestFetch)
                }
                "subdocument" | "frame" => opts.resource_types.push(NetworkResourceType::SubFrame),
                "~subdocument" | "~frame" => {
                    opts.excluded_resource_types.push(NetworkResourceType::SubFrame)
                }
                "websocket" => opts.resource_types.push(NetworkResourceType::WebSocket),
                "~websocket" => {
                    opts.excluded_resource_types
                        .push(NetworkResourceType::WebSocket)
                }
                "ping" | "beacon" => opts.resource_types.push(NetworkResourceType::PingBeacon),
                "~ping" | "~beacon" => {
                    opts.excluded_resource_types
                        .push(NetworkResourceType::PingBeacon)
                }
                "document" | "doc" => {
                    opts.resource_types
                        .push(NetworkResourceType::MainFrameDocument)
                }
                _ => {}
            }
        }
        opts
    }

    fn matches(
        &self,
        is_third_party: bool,
        resource_type: NetworkResourceType,
        first_party_host: &str,
    ) -> bool {
        if self.third_party_only && !is_third_party {
            return false;
        }
        if self.first_party_only && is_third_party {
            return false;
        }
        if !self.resource_types.is_empty() && !self.resource_types.contains(&resource_type) {
            return false;
        }
        if self.excluded_resource_types.contains(&resource_type) {
            return false;
        }
        if !self.include_domains.is_empty() || !self.exclude_domains.is_empty() {
            if first_party_host.is_empty() {
                return self.include_domains.is_empty();
            }
            let fp_hierarchy = domain_hierarchy(first_party_host);
            if self
                .exclude_domains
                .iter()
                .any(|exc| fp_hierarchy.contains(&exc.as_str()))
            {
                return false;
            }
            if !self.include_domains.is_empty()
                && !self
                    .include_domains
                    .iter()
                    .any(|inc| fp_hierarchy.contains(&inc.as_str()))
            {
                return false;
            }
        }
        true
    }
}

fn strip_ascii_prefix_ci<'a>(s: &'a str, prefix_lower: &str) -> Option<&'a str> {
    if s.len() >= prefix_lower.len()
        && s.is_char_boundary(prefix_lower.len())
        && s[..prefix_lower.len()].eq_ignore_ascii_case(prefix_lower)
    {
        Some(&s[prefix_lower.len()..])
    } else {
        None
    }
}

/// Splits `$opt1,opt2,csp=script-src 'self',domain=a.com|b.com` on commas,
/// while preserving commas inside `$csp=...` or `$removeparam=/.../` if present.
fn split_options_preserving_values(raw: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let bytes = raw.as_bytes();
    let mut start = 0usize;
    let mut in_regex = false;
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'/' && (i == 0 || bytes[i - 1] != b'\\') {
            in_regex = !in_regex;
        } else if b == b',' && !in_regex {
            parts.push(&raw[start..i]);
            start = i + 1;
        }
        i += 1;
    }
    if start <= raw.len() {
        parts.push(&raw[start..]);
    }
    parts
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

#[derive(Debug, Clone)]
struct CspRule {
    domain_anchor: Option<String>,
    url_pattern: Option<String>,
    directive: String,
    options: RuleOptions,
    is_exception: bool,
}

#[derive(Debug, Clone)]
struct RemoveParamRule {
    domain_anchor: Option<String>,
    url_pattern: Option<String>,
    param_spec: String,
    options: RuleOptions,
}

#[derive(Debug, Clone)]
struct CosmeticEntry {
    include_domains: Vec<String>,
    exclude_domains: Vec<String>,
    selector: String,
}

#[derive(Debug, Clone)]
struct ProceduralCosmeticEntry {
    include_domains: Vec<String>,
    exclude_domains: Vec<String>,
    rule: ProceduralCosmeticRule,
}

#[derive(Debug, Clone)]
struct ScriptletEntry {
    include_domains: Vec<String>,
    exclude_domains: Vec<String>,
    name: String,
    args: Vec<String>,
}

fn is_abp_separator(b: u8) -> bool {
    !(b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.' || b == b'%')
}

/// Thread-safe Rust network + cosmetic filter engine evaluating uBlock Origin rules at wire speed.
pub struct UBlockNetworkEngine {
    blocked_domains: HashMap<String, Vec<RuleOptions>>,
    blocked_domain_paths: HashMap<String, Vec<DomainPathRule>>,
    exception_domains: HashMap<String, Vec<RuleOptions>>,
    exception_domain_paths: HashMap<String, Vec<DomainPathRule>>,
    url_substrings: Vec<(String, RuleOptions)>,
    exception_substrings: Vec<(String, RuleOptions)>,
    badfilter_keys: HashSet<String>,
    csp_rules: Vec<CspRule>,
    removeparam_rules: Vec<RemoveParamRule>,
    cosmetic_rules: Vec<CosmeticEntry>,
    cosmetic_exceptions: Vec<CosmeticEntry>,
    procedural_rules: Vec<ProceduralCosmeticEntry>,
    scriptlet_rules: Vec<ScriptletEntry>,
    subscriptions: Vec<FilterListSubscription>,
    dynamic_matrix: DynamicRuleMatrix,
    site_policies: HashMap<String, SiteShieldsPolicy>,
    logger_enabled: AtomicBool,
    log_buffer: Mutex<VecDeque<ShieldLogEvent>>,
    blocked_count: AtomicU64,
}

impl Default for UBlockNetworkEngine {
    fn default() -> Self {
        let mut engine = Self::new();
        let stats = engine.load_filter_list_text(DEFAULT_UBLOCK_FILTER_RULES);
        if let Some(sub) = engine
            .subscriptions
            .iter_mut()
            .find(|s| s.kind == FilterListKind::UBlockCore)
        {
            sub.rule_count = stats.total_added;
        }
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
            exception_substrings: Vec::new(),
            badfilter_keys: HashSet::new(),
            csp_rules: Vec::new(),
            removeparam_rules: Vec::new(),
            cosmetic_rules: Vec::new(),
            cosmetic_exceptions: Vec::new(),
            procedural_rules: Vec::new(),
            scriptlet_rules: Vec::new(),
            subscriptions: Self::default_subscriptions(),
            dynamic_matrix: DynamicRuleMatrix::new(),
            site_policies: HashMap::new(),
            logger_enabled: AtomicBool::new(false),
            log_buffer: Mutex::new(VecDeque::new()),
            blocked_count: AtomicU64::new(0),
        }
    }

    /// Returns the built-in catalogue of standard uBlock / EasyList / Privacy / Annoyance lists.
    pub fn default_subscriptions() -> Vec<FilterListSubscription> {
        vec![
            FilterListSubscription {
                id: "easylist".into(),
                name: "EasyList".into(),
                kind: FilterListKind::EasyList,
                source_url: "https://easylist.to/easylist/easylist.txt".into(),
                enabled: true,
                etag: None,
                last_modified: None,
                rule_count: 0,
                last_updated_unix: 0,
            },
            FilterListSubscription {
                id: "easyprivacy".into(),
                name: "EasyPrivacy".into(),
                kind: FilterListKind::EasyPrivacy,
                source_url: "https://easylist.to/easylist/easyprivacy.txt".into(),
                enabled: true,
                etag: None,
                last_modified: None,
                rule_count: 0,
                last_updated_unix: 0,
            },
            FilterListSubscription {
                id: "ublock-filters".into(),
                name: "uBlock filters — Ads".into(),
                kind: FilterListKind::UBlockCore,
                source_url: "https://ublockorigin.github.io/uAssets/filters/filters.txt".into(),
                enabled: true,
                etag: None,
                last_modified: None,
                rule_count: 0,
                last_updated_unix: 0,
            },
            FilterListSubscription {
                id: "ublock-privacy".into(),
                name: "uBlock filters — Privacy".into(),
                kind: FilterListKind::UBlockPrivacy,
                source_url: "https://ublockorigin.github.io/uAssets/filters/privacy.txt".into(),
                enabled: true,
                etag: None,
                last_modified: None,
                rule_count: 0,
                last_updated_unix: 0,
            },
            FilterListSubscription {
                id: "ublock-badware".into(),
                name: "uBlock filters — Badware risks".into(),
                kind: FilterListKind::UBlockBadware,
                source_url: "https://ublockorigin.github.io/uAssets/filters/badware.txt".into(),
                enabled: true,
                etag: None,
                last_modified: None,
                rule_count: 0,
                last_updated_unix: 0,
            },
            FilterListSubscription {
                id: "ublock-unbreak".into(),
                name: "uBlock filters — Unbreak".into(),
                kind: FilterListKind::UBlockUnbreak,
                source_url: "https://ublockorigin.github.io/uAssets/filters/unbreak.txt".into(),
                enabled: true,
                etag: None,
                last_modified: None,
                rule_count: 0,
                last_updated_unix: 0,
            },
            FilterListSubscription {
                id: "ublock-annoyances".into(),
                name: "uBlock filters — Annoyances".into(),
                kind: FilterListKind::UBlockAnnoyances,
                source_url: "https://ublockorigin.github.io/uAssets/filters/annoyances.txt".into(),
                enabled: true,
                etag: None,
                last_modified: None,
                rule_count: 0,
                last_updated_unix: 0,
            },
            FilterListSubscription {
                id: "easylist-cookie".into(),
                name: "EasyList Cookie Notices".into(),
                kind: FilterListKind::EasyListCookie,
                source_url: "https://secure.fanboy.co.nz/fanboy-cookiemonster.txt".into(),
                enabled: true,
                etag: None,
                last_modified: None,
                rule_count: 0,
                last_updated_unix: 0,
            },
            FilterListSubscription {
                id: "fanboy-annoyances".into(),
                name: "Fanboy's Annoyance List".into(),
                kind: FilterListKind::FanboyAnnoyances,
                source_url: "https://easylist.to/easylist/fanboy-annoyance.txt".into(),
                enabled: false,
                etag: None,
                last_modified: None,
                rule_count: 0,
                last_updated_unix: 0,
            },
            FilterListSubscription {
                id: "liste-fr".into(),
                name: "FRA: Liste FR".into(),
                kind: FilterListKind::ListeFr,
                source_url: "https://easylist-downloads.adblockplus.org/liste_fr.txt".into(),
                enabled: true,
                etag: None,
                last_modified: None,
                rule_count: 0,
                last_updated_unix: 0,
            },
        ]
    }

    pub fn subscriptions(&self) -> &[FilterListSubscription] {
        &self.subscriptions
    }

    pub fn set_subscription_enabled(&mut self, id: &str, enabled: bool) -> bool {
        if let Some(sub) = self.subscriptions.iter_mut().find(|s| s.id == id) {
            sub.enabled = enabled;
            true
        } else {
            false
        }
    }

    pub fn add_custom_subscription(
        &mut self,
        id: &str,
        name: &str,
        source_url: &str,
    ) -> &FilterListSubscription {
        if let Some(idx) = self.subscriptions.iter().position(|s| s.id == id) {
            self.subscriptions[idx].name = name.to_string();
            self.subscriptions[idx].source_url = source_url.to_string();
            self.subscriptions[idx].enabled = true;
            return &self.subscriptions[idx];
        }
        self.subscriptions.push(FilterListSubscription {
            id: id.to_string(),
            name: name.to_string(),
            kind: FilterListKind::Custom,
            source_url: source_url.to_string(),
            enabled: true,
            etag: None,
            last_modified: None,
            rule_count: 0,
            last_updated_unix: 0,
        });
        self.subscriptions.last().expect("just pushed")
    }

    pub fn remove_subscription(&mut self, id: &str) -> bool {
        let before = self.subscriptions.len();
        self.subscriptions.retain(|s| s.id != id);
        self.subscriptions.len() != before
    }

    /// Loads freshly fetched text into a subscription, updating ETag, Last-Modified, and rule counts.
    pub fn update_subscription_content(
        &mut self,
        id: &str,
        raw_list: &str,
        etag: Option<String>,
        last_modified: Option<String>,
        now_unix: u64,
    ) -> Option<FilterListLoadStats> {
        let idx = self.subscriptions.iter().position(|s| s.id == id)?;
        let stats = self.load_filter_list_text(raw_list);
        let sub = &mut self.subscriptions[idx];
        sub.etag = etag;
        sub.last_modified = last_modified;
        sub.rule_count = stats.total_added;
        sub.last_updated_unix = now_unix;
        Some(stats)
    }

    /// Parses uBlock Origin / Adblock Plus filter list rules (backward-compatible entrypoint).
    pub fn load_filter_list(&mut self, raw_list: &str) -> usize {
        self.load_filter_list_text(raw_list).total_added
    }

    /// Complete uBlock Origin filter parser supporting network rules (`$domain=`, `$badfilter`,
    /// `$important`, `$csp=`, `$removeparam=`, `$redirect=`), CSS cosmetic rules (`##`, `#@#`),
    /// procedural cosmetic selectors (`#?#`, `:has-text()`, `:upward()`, `:style()`, `:remove()`),
    /// and scriptlets (`##+js(...)`).
    pub fn load_filter_list_text(&mut self, raw_list: &str) -> FilterListLoadStats {
        let mut stats = FilterListLoadStats::default();
        for line in raw_list.lines() {
            let rule = line.trim();
            if rule.is_empty() || rule.starts_with('!') || rule.starts_with('[') {
                continue;
            }

            // 1. Cosmetic exception rules: `[domains]#@#selector`
            if let Some((dom_part, selector)) = rule.split_once("#@#") {
                let sel = selector.trim();
                if !sel.is_empty() {
                    let (inc, exc) = parse_cosmetic_domains(dom_part);
                    self.cosmetic_exceptions.push(CosmeticEntry {
                        include_domains: inc,
                        exclude_domains: exc,
                        selector: sel.to_string(),
                    });
                    stats.cosmetic_rules_added += 1;
                    stats.total_added += 1;
                }
                continue;
            }

            // 2. Explicit procedural cosmetic rules: `[domains]#?#selector`
            if let Some((dom_part, selector)) = rule.split_once("#?#") {
                let sel = selector.trim();
                if let Some(parsed) = parse_procedural_selector(sel) {
                    let (inc, exc) = parse_cosmetic_domains(dom_part);
                    self.procedural_rules.push(ProceduralCosmeticEntry {
                        include_domains: inc,
                        exclude_domains: exc,
                        rule: parsed,
                    });
                    stats.procedural_rules_added += 1;
                    stats.total_added += 1;
                }
                continue;
            }

            // 3. CSS cosmetic, scriptlet (`##+js(...)`), or inline procedural (`##...:has-text(...)`)
            if let Some((dom_part, selector)) = rule.split_once("##") {
                let sel = selector.trim();
                if sel.is_empty() {
                    continue;
                }
                let (inc, exc) = parse_cosmetic_domains(dom_part);
                if let Some(js_inner) = sel.strip_prefix("+js(").and_then(|s| s.strip_suffix(')')) {
                    let mut parts = split_scriptlet_args(js_inner);
                    if !parts.is_empty() {
                        let name = parts.remove(0);
                        self.scriptlet_rules.push(ScriptletEntry {
                            include_domains: inc,
                            exclude_domains: exc,
                            name,
                            args: parts,
                        });
                        stats.scriptlet_rules_added += 1;
                        stats.total_added += 1;
                    }
                    continue;
                }
                if contains_procedural_operator(sel) {
                    if let Some(parsed) = parse_procedural_selector(sel) {
                        self.procedural_rules.push(ProceduralCosmeticEntry {
                            include_domains: inc,
                            exclude_domains: exc,
                            rule: parsed,
                        });
                        stats.procedural_rules_added += 1;
                        stats.total_added += 1;
                    }
                    continue;
                }
                self.cosmetic_rules.push(CosmeticEntry {
                    include_domains: inc,
                    exclude_domains: exc,
                    selector: sel.to_string(),
                });
                stats.cosmetic_rules_added += 1;
                stats.total_added += 1;
                continue;
            }

            // Skip unsupported legacy ABP snippet syntax `#$#`
            if rule.contains("#$#") {
                continue;
            }

            // 4. Network filter rules
            let (rule_body, options) = match split_network_rule_and_options(rule) {
                Some((body, opt_str)) => {
                    let key = canonical_network_rule_key(body);
                    (body, RuleOptions::parse(opt_str, key))
                }
                None => {
                    let key = canonical_network_rule_key(rule);
                    (
                        rule,
                        RuleOptions {
                            canonical_key: key,
                            ..RuleOptions::default()
                        },
                    )
                }
            };

            if options.badfilter {
                self.badfilter_keys.insert(options.canonical_key.clone());
                stats.badfilter_rules_added += 1;
                stats.total_added += 1;
                continue;
            }

            // Handle `$csp=...` directives (document header injection, does not block request itself)
            if let Some(ref directive) = options.csp {
                let is_exception = rule_body.starts_with("@@");
                let cleaned_body = rule_body.strip_prefix("@@").unwrap_or(rule_body);
                let (domain_anchor, url_pattern) = if let Some(dom_part) =
                    cleaned_body.strip_prefix("||")
                {
                    let d = dom_part
                        .split(['/', '^'])
                        .next()
                        .unwrap_or("")
                        .trim_end_matches('.')
                        .to_ascii_lowercase();
                    (if d.is_empty() { None } else { Some(d) }, None)
                } else if !cleaned_body.is_empty() && cleaned_body != "*" {
                    (None, Some(cleaned_body.to_ascii_lowercase()))
                } else {
                    (None, None)
                };
                self.csp_rules.push(CspRule {
                    domain_anchor,
                    url_pattern,
                    directive: directive.clone(),
                    options: options.clone(),
                    is_exception,
                });
                stats.csp_rules_added += 1;
                stats.total_added += 1;
                continue;
            }

            // Handle `$removeparam=...` URL query parameter stripping rules
            if let Some(ref param_spec) = options.removeparam {
                let cleaned_body = rule_body.strip_prefix("@@").unwrap_or(rule_body);
                let (domain_anchor, url_pattern) = if let Some(dom_part) =
                    cleaned_body.strip_prefix("||")
                {
                    let d = dom_part
                        .split(['/', '^'])
                        .next()
                        .unwrap_or("")
                        .trim_end_matches('.')
                        .to_ascii_lowercase();
                    (if d.is_empty() { None } else { Some(d) }, None)
                } else if !cleaned_body.is_empty() && cleaned_body != "*" {
                    (None, Some(cleaned_body.to_ascii_lowercase()))
                } else {
                    (None, None)
                };
                self.removeparam_rules.push(RemoveParamRule {
                    domain_anchor,
                    url_pattern,
                    param_spec: param_spec.clone(),
                    options: options.clone(),
                });
                stats.removeparam_rules_added += 1;
                stats.total_added += 1;
                continue;
            }

            let has_redirect = options.redirect.is_some();

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
                    stats.exception_rules_added += 1;
                    stats.total_added += 1;
                }
            } else if let Some(exc_pat) = rule_body.strip_prefix("@@") {
                let pattern = exc_pat.to_ascii_lowercase();
                if !pattern.is_empty() {
                    self.exception_substrings.push((pattern, options));
                    stats.exception_rules_added += 1;
                    stats.total_added += 1;
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
                    stats.network_rules_added += 1;
                    if has_redirect {
                        stats.redirect_rules_added += 1;
                    }
                    stats.total_added += 1;
                }
            } else {
                let pattern = rule_body.to_ascii_lowercase();
                if !pattern.is_empty() {
                    self.url_substrings.push((pattern, options));
                    stats.network_rules_added += 1;
                    if has_redirect {
                        stats.redirect_rules_added += 1;
                    }
                    stats.total_added += 1;
                }
            }
        }
        stats
    }

    /// Evaluates a candidate network request before socket dispatch (100% backward compatible).
    pub fn evaluate_request(
        &self,
        request_url: &str,
        request_host: &str,
        first_party_host: &str,
        resource_type: NetworkResourceType,
    ) -> FilterDecision {
        self.evaluate_request_detailed(request_url, request_host, first_party_host, resource_type)
            .decision
    }

    /// Full evaluation returning decision, `$redirect=` surrogate resource, `$csp=` headers,
    /// dynamic matrix outcome, and `$removeparam=` URL rewrite.
    pub fn evaluate_request_detailed(
        &self,
        request_url: &str,
        request_host: &str,
        first_party_host: &str,
        resource_type: NetworkResourceType,
    ) -> FilterEvaluationResult {
        let host_lower = normalize_host(request_host);
        let fp_lower = normalize_host(first_party_host);
        let is_third_party = !fp_lower.is_empty() && !same_site(&host_lower, &fp_lower);

        let csp_directives = self.csp_directives_for_request(
            request_url,
            &host_lower,
            &fp_lower,
            is_third_party,
            resource_type,
        );
        let rewritten_url = self.apply_removeparam_rules(
            request_url,
            &host_lower,
            &fp_lower,
            is_third_party,
            resource_type,
        );

        // 1. Check Per-Site Shields Policy
        let site_policy = self.lookup_site_policy(&fp_lower);
        if let Some(policy) = site_policy {
            if !policy.enabled || policy.adblock_level == AdblockLevel::Off {
                let decision = FilterDecision::Allow;
                self.record_log_if_enabled(
                    &fp_lower,
                    &host_lower,
                    request_url,
                    resource_type,
                    &decision,
                    None,
                    false,
                );
                return FilterEvaluationResult {
                    decision,
                    redirect_resource: None,
                    csp_directives,
                    dynamic_action: None,
                    rewritten_url,
                };
            }
            if policy.block_all_scripts && resource_type == NetworkResourceType::Script {
                let script_allowed = policy
                    .allowed_script_domains
                    .iter()
                    .any(|allowed| host_matches_domain(&host_lower, allowed));
                if !script_allowed {
                    self.blocked_count.fetch_add(1, Ordering::Relaxed);
                    let decision = FilterDecision::BlockedByPatternRule(
                        "site-policy:block_all_scripts".to_string(),
                    );
                    self.record_log_if_enabled(
                        &fp_lower,
                        &host_lower,
                        request_url,
                        resource_type,
                        &decision,
                        None,
                        false,
                    );
                    return FilterEvaluationResult {
                        decision,
                        redirect_resource: None,
                        csp_directives,
                        dynamic_action: None,
                        rewritten_url,
                    };
                }
            }
        }

        let url_lower = request_url.to_ascii_lowercase();
        let req_path_lower = extract_url_path_lower(&url_lower);
        let hierarchy = domain_hierarchy(&host_lower);

        // 2. `$important` blocking rules take precedence even over `@@` exceptions and dynamic rules
        if let Some((decision, redir)) = self.match_static_block_rules(
            &hierarchy,
            &url_lower,
            req_path_lower,
            is_third_party,
            resource_type,
            &fp_lower,
            true,
        ) {
            self.blocked_count.fetch_add(1, Ordering::Relaxed);
            let redirect_resource = redir.as_deref().and_then(lookup_surrogate_resource);
            self.record_log_if_enabled(
                &fp_lower,
                &host_lower,
                request_url,
                resource_type,
                &decision,
                redirect_resource.as_ref().map(|r| r.name.clone()),
                false,
            );
            return FilterEvaluationResult {
                decision,
                redirect_resource,
                csp_directives,
                dynamic_action: None,
                rewritten_url,
            };
        }

        // 3. Dynamic Filtering Matrix (uBlock Medium Mode: Allow / Noop / Block)
        let dynamic_action =
            self.dynamic_matrix
                .evaluate(&fp_lower, &host_lower, is_third_party, resource_type);
        match dynamic_action {
            Some(DynamicRuleAction::Allow) => {
                let decision =
                    FilterDecision::AllowByExceptionRule(format!("dynamic-allow:{}", host_lower));
                self.record_log_if_enabled(
                    &fp_lower,
                    &host_lower,
                    request_url,
                    resource_type,
                    &decision,
                    None,
                    true,
                );
                return FilterEvaluationResult {
                    decision,
                    redirect_resource: None,
                    csp_directives,
                    dynamic_action,
                    rewritten_url,
                };
            }
            Some(DynamicRuleAction::Block) => {
                self.blocked_count.fetch_add(1, Ordering::Relaxed);
                let decision =
                    FilterDecision::BlockedByDomainRule(format!("dynamic-block:{}", host_lower));
                self.record_log_if_enabled(
                    &fp_lower,
                    &host_lower,
                    request_url,
                    resource_type,
                    &decision,
                    None,
                    true,
                );
                return FilterEvaluationResult {
                    decision,
                    redirect_resource: None,
                    csp_directives,
                    dynamic_action,
                    rewritten_url,
                };
            }
            Some(DynamicRuleAction::Noop) | None => {}
        }

        // 4. PingBeacon defense (3rd-party always blocked; 1st-party blocked under Aggressive policy)
        if resource_type == NetworkResourceType::PingBeacon {
            let aggressive = site_policy
                .is_some_and(|p| p.adblock_level == AdblockLevel::Aggressive);
            if is_third_party || aggressive {
                self.blocked_count.fetch_add(1, Ordering::Relaxed);
                let decision = FilterDecision::BlockedBeaconOrPing;
                self.record_log_if_enabled(
                    &fp_lower,
                    &host_lower,
                    request_url,
                    resource_type,
                    &decision,
                    None,
                    false,
                );
                return FilterEvaluationResult {
                    decision,
                    redirect_resource: None,
                    csp_directives,
                    dynamic_action,
                    rewritten_url,
                };
            }
        }

        // 5. Static exception rules (`@@||domain^`, `@@||domain/path`, `@@pattern`)
        for &candidate in &hierarchy {
            if let Some(opts_list) = self.exception_domains.get(candidate) {
                if opts_list.iter().any(|opts| {
                    !self.badfilter_keys.contains(&opts.canonical_key)
                        && opts.matches(is_third_party, resource_type, &fp_lower)
                }) {
                    let decision = FilterDecision::AllowByExceptionRule(candidate.to_string());
                    self.record_log_if_enabled(
                        &fp_lower,
                        &host_lower,
                        request_url,
                        resource_type,
                        &decision,
                        None,
                        false,
                    );
                    return FilterEvaluationResult {
                        decision,
                        redirect_resource: None,
                        csp_directives,
                        dynamic_action,
                        rewritten_url,
                    };
                }
            }
            if let Some(path_rules) = self.exception_domain_paths.get(candidate) {
                for rule in path_rules {
                    if !self.badfilter_keys.contains(&rule.options.canonical_key)
                        && rule
                            .options
                            .matches(is_third_party, resource_type, &fp_lower)
                        && rule.matches_path(req_path_lower)
                    {
                        let decision = FilterDecision::AllowByExceptionRule(format!(
                            "{}{}",
                            candidate, rule.path_prefix
                        ));
                        self.record_log_if_enabled(
                            &fp_lower,
                            &host_lower,
                            request_url,
                            resource_type,
                            &decision,
                            None,
                            false,
                        );
                        return FilterEvaluationResult {
                            decision,
                            redirect_resource: None,
                            csp_directives,
                            dynamic_action,
                            rewritten_url,
                        };
                    }
                }
            }
        }
        for (pat, opts) in &self.exception_substrings {
            if !self.badfilter_keys.contains(&opts.canonical_key)
                && opts.matches(is_third_party, resource_type, &fp_lower)
                && url_lower.contains(pat)
            {
                let decision = FilterDecision::AllowByExceptionRule(pat.clone());
                self.record_log_if_enabled(
                    &fp_lower,
                    &host_lower,
                    request_url,
                    resource_type,
                    &decision,
                    None,
                    false,
                );
                return FilterEvaluationResult {
                    decision,
                    redirect_resource: None,
                    csp_directives,
                    dynamic_action,
                    rewritten_url,
                };
            }
        }

        // 6. Standard static blocking rules (skipping `$badfilter` disabled rules)
        if let Some((decision, redir)) = self.match_static_block_rules(
            &hierarchy,
            &url_lower,
            req_path_lower,
            is_third_party,
            resource_type,
            &fp_lower,
            false,
        ) {
            self.blocked_count.fetch_add(1, Ordering::Relaxed);
            let redirect_resource = redir.as_deref().and_then(lookup_surrogate_resource);
            self.record_log_if_enabled(
                &fp_lower,
                &host_lower,
                request_url,
                resource_type,
                &decision,
                redirect_resource.as_ref().map(|r| r.name.clone()),
                false,
            );
            return FilterEvaluationResult {
                decision,
                redirect_resource,
                csp_directives,
                dynamic_action,
                rewritten_url,
            };
        }

        let decision = FilterDecision::Allow;
        self.record_log_if_enabled(
            &fp_lower,
            &host_lower,
            request_url,
            resource_type,
            &decision,
            None,
            dynamic_action.is_some(),
        );
        FilterEvaluationResult {
            decision,
            redirect_resource: None,
            csp_directives,
            dynamic_action,
            rewritten_url,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn match_static_block_rules(
        &self,
        hierarchy: &[&str],
        url_lower: &str,
        req_path_lower: &str,
        is_third_party: bool,
        resource_type: NetworkResourceType,
        fp_lower: &str,
        only_important: bool,
    ) -> Option<(FilterDecision, Option<String>)> {
        for &candidate in hierarchy {
            if let Some(opts_list) = self.blocked_domains.get(candidate) {
                for opts in opts_list {
                    if only_important && !opts.important {
                        continue;
                    }
                    if self.badfilter_keys.contains(&opts.canonical_key) {
                        continue;
                    }
                    if opts.matches(is_third_party, resource_type, fp_lower) {
                        return Some((
                            FilterDecision::BlockedByDomainRule(candidate.to_string()),
                            opts.redirect.clone(),
                        ));
                    }
                }
            }
        }

        for &candidate in hierarchy {
            if let Some(path_rules) = self.blocked_domain_paths.get(candidate) {
                for rule in path_rules {
                    if only_important && !rule.options.important {
                        continue;
                    }
                    if self.badfilter_keys.contains(&rule.options.canonical_key) {
                        continue;
                    }
                    if rule
                        .options
                        .matches(is_third_party, resource_type, fp_lower)
                        && rule.matches_path(req_path_lower)
                    {
                        return Some((
                            FilterDecision::BlockedByPatternRule(format!(
                                "||{}{}",
                                candidate, rule.path_prefix
                            )),
                            rule.options.redirect.clone(),
                        ));
                    }
                }
            }
        }

        for (pat, opts) in &self.url_substrings {
            if only_important && !opts.important {
                continue;
            }
            if self.badfilter_keys.contains(&opts.canonical_key) {
                continue;
            }
            if opts.matches(is_third_party, resource_type, fp_lower) && url_lower.contains(pat) {
                return Some((
                    FilterDecision::BlockedByPatternRule(pat.clone()),
                    opts.redirect.clone(),
                ));
            }
        }

        None
    }

    fn csp_directives_for_request(
        &self,
        request_url: &str,
        host_lower: &str,
        fp_lower: &str,
        is_third_party: bool,
        resource_type: NetworkResourceType,
    ) -> Vec<String> {
        if self.csp_rules.is_empty() {
            return Vec::new();
        }
        let url_lower = request_url.to_ascii_lowercase();
        let hierarchy = domain_hierarchy(host_lower);

        let mut excluded_directives: HashSet<String> = HashSet::new();
        for rule in &self.csp_rules {
            if !rule.is_exception {
                continue;
            }
            if self.badfilter_keys.contains(&rule.options.canonical_key) {
                continue;
            }
            if csp_or_rp_matches(
                &rule.domain_anchor,
                &rule.url_pattern,
                &rule.options,
                &hierarchy,
                &url_lower,
                is_third_party,
                resource_type,
                fp_lower,
            ) {
                excluded_directives.insert(rule.directive.clone());
            }
        }

        let mut directives = Vec::new();
        for rule in &self.csp_rules {
            if rule.is_exception {
                continue;
            }
            if self.badfilter_keys.contains(&rule.options.canonical_key) {
                continue;
            }
            if excluded_directives.contains(&rule.directive) {
                continue;
            }
            if csp_or_rp_matches(
                &rule.domain_anchor,
                &rule.url_pattern,
                &rule.options,
                &hierarchy,
                &url_lower,
                is_third_party,
                resource_type,
                fp_lower,
            ) && !directives.contains(&rule.directive)
            {
                directives.push(rule.directive.clone());
            }
        }
        directives
    }

    fn apply_removeparam_rules(
        &self,
        request_url: &str,
        host_lower: &str,
        fp_lower: &str,
        is_third_party: bool,
        resource_type: NetworkResourceType,
    ) -> Option<String> {
        if self.removeparam_rules.is_empty() || !request_url.contains('?') {
            return None;
        }
        let url_lower = request_url.to_ascii_lowercase();
        let hierarchy = domain_hierarchy(host_lower);
        let mut specs_to_remove: Vec<&str> = Vec::new();
        for rule in &self.removeparam_rules {
            if self.badfilter_keys.contains(&rule.options.canonical_key) {
                continue;
            }
            if csp_or_rp_matches(
                &rule.domain_anchor,
                &rule.url_pattern,
                &rule.options,
                &hierarchy,
                &url_lower,
                is_third_party,
                resource_type,
                fp_lower,
            ) {
                specs_to_remove.push(&rule.param_spec);
            }
        }
        if specs_to_remove.is_empty() {
            return None;
        }
        let (base, query_and_frag) = request_url.split_once('?')?;
        let (query, frag_opt) = match query_and_frag.split_once('#') {
            Some((q, f)) => (q, Some(f)),
            None => (query_and_frag, None),
        };
        let mut changed = false;
        let kept: Vec<&str> = query
            .split('&')
            .filter(|pair| {
                if pair.is_empty() {
                    return false;
                }
                let key = pair.split('=').next().unwrap_or("");
                let should_drop = specs_to_remove.iter().any(|spec| {
                    if *spec == "*" {
                        true
                    } else if let Some(neg) = spec.strip_prefix('~') {
                        !key.eq_ignore_ascii_case(neg)
                    } else if let Some(prefix) = spec.strip_suffix('*') {
                        key.to_ascii_lowercase().starts_with(&prefix.to_ascii_lowercase())
                    } else {
                        key.eq_ignore_ascii_case(spec)
                    }
                });
                if should_drop {
                    changed = true;
                    false
                } else {
                    true
                }
            })
            .collect();
        if !changed {
            return None;
        }
        let mut out = base.to_string();
        if !kept.is_empty() {
            out.push('?');
            out.push_str(&kept.join("&"));
        }
        if let Some(frag) = frag_opt {
            out.push('#');
            out.push_str(frag);
        }
        Some(out)
    }

    /// Computes CSS hiding selectors, procedural cosmetic rules, and scriptlet injections for `host`.
    pub fn cosmetic_resources_for_host(&self, host: &str) -> CosmeticResources {
        let host_lower = normalize_host(host);
        if host_lower.is_empty() {
            return CosmeticResources::default();
        }
        if let Some(policy) = self.lookup_site_policy(&host_lower) {
            if !policy.enabled || policy.adblock_level == AdblockLevel::Off {
                return CosmeticResources::default();
            }
        }

        let hierarchy = domain_hierarchy(&host_lower);

        let mut excluded_selectors: HashSet<&str> = HashSet::new();
        for exc in &self.cosmetic_exceptions {
            if cosmetic_domains_match(&exc.include_domains, &exc.exclude_domains, &hierarchy) {
                excluded_selectors.insert(exc.selector.as_str());
            }
        }

        let mut css_selectors = Vec::new();
        let mut seen_css = HashSet::new();
        for entry in &self.cosmetic_rules {
            if cosmetic_domains_match(&entry.include_domains, &entry.exclude_domains, &hierarchy)
                && !excluded_selectors.contains(entry.selector.as_str())
                && seen_css.insert(entry.selector.as_str())
            {
                css_selectors.push(entry.selector.clone());
            }
        }

        let mut procedural_rules = Vec::new();
        for entry in &self.procedural_rules {
            if cosmetic_domains_match(&entry.include_domains, &entry.exclude_domains, &hierarchy)
                && !excluded_selectors.contains(entry.rule.raw_selector.as_str())
            {
                procedural_rules.push(entry.rule.clone());
            }
        }

        let mut scriptlets = Vec::new();
        for entry in &self.scriptlet_rules {
            if cosmetic_domains_match(&entry.include_domains, &entry.exclude_domains, &hierarchy) {
                let resolved_source = render_scriptlet(&entry.name, &entry.args);
                scriptlets.push(ScriptletInjection {
                    name: entry.name.clone(),
                    args: entry.args.clone(),
                    resolved_source,
                });
            }
        }

        CosmeticResources {
            css_selectors,
            procedural_rules,
            scriptlets,
        }
    }

    /// Validates a user-authored custom CSS or procedural cosmetic selector before injection.
    pub fn validate_custom_cosmetic_selector(selector: &str) -> Result<(), String> {
        let trimmed = selector.trim();
        if trimmed.is_empty() {
            return Err("Cosmetic selector cannot be empty".into());
        }
        if trimmed.len() > 2048 {
            return Err("Cosmetic selector exceeds maximum length (2048 chars)".into());
        }
        if trimmed.chars().any(|c| c.is_control()) {
            return Err("Cosmetic selector contains disallowed control characters".into());
        }
        let lower = trimmed.to_ascii_lowercase();
        for forbidden in [
            "</style",
            "<script",
            "javascript:",
            "expression(",
            "@import",
            "behavior:",
            "-moz-binding",
            "url(",
        ] {
            if lower.contains(forbidden) {
                return Err(format!(
                    "Cosmetic selector contains forbidden token '{}'",
                    forbidden
                ));
            }
        }

        // Curly braces `{}` are forbidden in plain CSS selectors to prevent rule breakout.
        if trimmed.contains('{') || trimmed.contains('}') {
            return Err("Cosmetic selector must not contain raw '{' or '}' blocks".into());
        }

        // Verify balanced brackets, parentheses, and quotes.
        let mut paren_depth: i32 = 0;
        let mut bracket_depth: i32 = 0;
        let mut in_single = false;
        let mut in_double = false;
        let mut escaped = false;

        for ch in trimmed.chars() {
            if escaped {
                escaped = false;
                continue;
            }
            if ch == '\\' {
                escaped = true;
                continue;
            }
            if in_single {
                if ch == '\'' {
                    in_single = false;
                }
                continue;
            }
            if in_double {
                if ch == '"' {
                    in_double = false;
                }
                continue;
            }
            match ch {
                '\'' => in_single = true,
                '"' => in_double = true,
                '(' => paren_depth += 1,
                ')' => {
                    paren_depth -= 1;
                    if paren_depth < 0 {
                        return Err("Unmatched closing parenthesis ')' in selector".into());
                    }
                }
                '[' => bracket_depth += 1,
                ']' => {
                    bracket_depth -= 1;
                    if bracket_depth < 0 {
                        return Err("Unmatched closing bracket ']' in selector".into());
                    }
                }
                _ => {}
            }
        }

        if in_single || in_double {
            return Err("Unterminated string literal in cosmetic selector".into());
        }
        if paren_depth != 0 {
            return Err("Unbalanced parentheses in cosmetic selector".into());
        }
        if bracket_depth != 0 {
            return Err("Unbalanced attribute brackets in cosmetic selector".into());
        }
        Ok(())
    }

    pub fn dynamic_matrix(&self) -> &DynamicRuleMatrix {
        &self.dynamic_matrix
    }

    pub fn dynamic_matrix_mut(&mut self) -> &mut DynamicRuleMatrix {
        &mut self.dynamic_matrix
    }

    pub fn set_site_policy(&mut self, site: &str, policy: SiteShieldsPolicy) {
        let key = normalize_host(site);
        if !key.is_empty() {
            self.site_policies.insert(key, policy);
        }
    }

    pub fn get_site_policy(&self, site: &str) -> SiteShieldsPolicy {
        let key = normalize_host(site);
        self.lookup_site_policy(&key).cloned().unwrap_or_default()
    }

    pub fn remove_site_policy(&mut self, site: &str) -> Option<SiteShieldsPolicy> {
        let key = normalize_host(site);
        self.site_policies.remove(&key)
    }

    pub fn site_policies(&self) -> &HashMap<String, SiteShieldsPolicy> {
        &self.site_policies
    }

    fn lookup_site_policy(&self, host_lower: &str) -> Option<&SiteShieldsPolicy> {
        if host_lower.is_empty() || self.site_policies.is_empty() {
            return None;
        }
        for candidate in domain_hierarchy(host_lower) {
            if let Some(p) = self.site_policies.get(candidate) {
                return Some(p);
            }
        }
        None
    }

    /// Enables or disables the bounded real-time network logger (cap: 2 000 events).
    pub fn set_logger_enabled(&self, enabled: bool) {
        self.logger_enabled.store(enabled, Ordering::Relaxed);
    }

    pub fn is_logger_enabled(&self) -> bool {
        self.logger_enabled.load(Ordering::Relaxed)
    }

    pub fn recent_log_events(&self) -> Vec<ShieldLogEvent> {
        match self.log_buffer.lock() {
            Ok(guard) => guard.iter().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    pub fn clear_log(&self) {
        if let Ok(mut guard) = self.log_buffer.lock() {
            guard.clear();
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn record_log_if_enabled(
        &self,
        fp_lower: &str,
        host_lower: &str,
        request_url: &str,
        resource_type: NetworkResourceType,
        decision: &FilterDecision,
        redirect_resource: Option<String>,
        dynamic_rule_matched: bool,
    ) {
        if !self.logger_enabled.load(Ordering::Relaxed) {
            return;
        }
        let ts_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        if let Ok(mut buf) = self.log_buffer.lock() {
            while buf.len() >= MAX_SHIELD_LOG_EVENTS {
                buf.pop_front();
            }
            buf.push_back(ShieldLogEvent {
                timestamp_unix_ms: ts_ms,
                first_party_host: fp_lower.to_string(),
                request_host: host_lower.to_string(),
                request_url: request_url.to_string(),
                resource_type,
                decision: decision.clone(),
                redirect_resource,
                dynamic_rule_matched,
            });
        }
    }

    /// Returns total count of distinct global + domain-scoped ClearURLs tracking parameters.
    pub fn tracking_param_count() -> usize {
        let mut unique: HashSet<String> = GLOBAL_TRACKING_QUERY_PARAMS
            .iter()
            .map(|p| p.to_ascii_lowercase())
            .collect();
        for (_, params) in DOMAIN_SCOPED_TRACKING_PARAMS {
            for p in *params {
                unique.insert(p.to_ascii_lowercase());
            }
        }
        unique.len()
    }

    /// Strips 120+ global and domain-scoped ClearURLs tracking query parameters from a URL.
    pub fn scrub_tracking_query_params(raw_url: &str) -> String {
        let Some((base, query_and_frag)) = raw_url.split_once('?') else {
            return raw_url.to_string();
        };

        let (query, fragment_opt) = match query_and_frag.split_once('#') {
            Some((q, f)) => (q, Some(f)),
            None => (query_and_frag, None),
        };

        let host_lower = extract_url_host_lower(base);
        let etld = registrable_suffix(&host_lower);

        let domain_params: Vec<&str> = DOMAIN_SCOPED_TRACKING_PARAMS
            .iter()
            .filter(|(dom, _)| host_lower == *dom || etld == *dom || host_lower.ends_with(&format!(".{}", dom)))
            .flat_map(|(_, params)| params.iter().copied())
            .collect();

        let retained_pairs: Vec<&str> = query
            .split('&')
            .filter(|pair| {
                let key = pair.split('=').next().unwrap_or("");
                if key.is_empty() {
                    return !pair.is_empty();
                }
                let is_global_trk = GLOBAL_TRACKING_QUERY_PARAMS
                    .iter()
                    .any(|&trk| trk.eq_ignore_ascii_case(key));
                if is_global_trk {
                    return false;
                }
                let is_domain_trk = domain_params
                    .iter()
                    .any(|&trk| trk.eq_ignore_ascii_case(key));
                !is_domain_trk
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

    /// Unwraps known bounce-tracking redirectors (`l.facebook.com`, `out.reddit.com`,
    /// `google.com/url`, `t.co`, `click.*`, Outlook SafeLinks, YouTube/Steam/VK redirectors)
    /// and scrubs tracking query parameters from the destination URL.
    pub fn debounce_tracking_redirect(raw_url: &str) -> Option<String> {
        debounce_tracking_redirect(raw_url)
    }

    pub fn total_blocked_requests(&self) -> u64 {
        self.blocked_count.load(Ordering::Relaxed)
    }
}

/// Unwraps bounce-tracking redirector URLs safely (up to 4 hops, HTTP/HTTPS destinations only).
pub fn debounce_tracking_redirect(raw_url: &str) -> Option<String> {
    let mut current = raw_url.trim().to_string();
    let mut unwrapped_any = false;

    for _hop in 0..4 {
        let Some(next) = unwrap_single_bounce_hop(&current) else {
            break;
        };
        let cleaned = UBlockNetworkEngine::scrub_tracking_query_params(&next);
        if cleaned == current {
            break;
        }
        current = cleaned;
        unwrapped_any = true;
    }

    if unwrapped_any {
        Some(current)
    } else {
        None
    }
}

fn unwrap_single_bounce_hop(raw_url: &str) -> Option<String> {
    let (base, query_and_frag) = raw_url.split_once('?')?;
    let query = query_and_frag.split('#').next().unwrap_or("");
    if query.is_empty() {
        return None;
    }

    let host = extract_url_host_lower(base);
    let path = extract_url_path_lower(&base.to_ascii_lowercase()).to_string();

    let candidate_param_keys: &[&str] = if host == "l.facebook.com"
        || host == "lm.facebook.com"
        || host == "l.instagram.com"
        || host == "l.messenger.com"
    {
        &["u"]
    } else if host == "out.reddit.com" {
        &["url"]
    } else if (host == "google.com"
        || host == "www.google.com"
        || host.starts_with("www.google.")
        || host.starts_with("google."))
        && (path == "/url" || path.starts_with("/url/"))
    {
        &["q", "url"]
    } else if host == "t.co" || host.ends_with(".t.co") {
        &["url", "u", "redirect", "target"]
    } else if host.starts_with("click.") {
        &["url", "u", "murl", "dest", "destination", "redirect", "target", "r", "redir"]
    } else if host.ends_with("safelinks.protection.outlook.com") {
        &["url"]
    } else if (host == "youtube.com" || host == "www.youtube.com") && path.starts_with("/redirect") {
        &["q"]
    } else if host == "vk.com" && path.starts_with("/away.php") {
        &["to"]
    } else if host == "steamcommunity.com" && path.starts_with("/linkfilter") {
        &["u", "url"]
    } else if host == "t.umblr.com" && path.starts_with("/redirect") {
        &["z"]
    } else if host == "gate.sc" || host == "exit.sc" || host == "disq.us" {
        &["url"]
    } else {
        return None;
    };

    for pair in query.split('&') {
        let Some((k, v)) = pair.split_once('=') else {
            continue;
        };
        if candidate_param_keys
            .iter()
            .any(|&want| k.eq_ignore_ascii_case(want))
        {
            let decoded = percent_decode_url_component(v);
            let trimmed = decoded.trim();
            let lower = trimmed.to_ascii_lowercase();
            if lower.starts_with("https://") || lower.starts_with("http://") {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

fn percent_decode_url_component(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        } else if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Looks up an embedded `$redirect=` surrogate resource by canonical name or uBlock alias.
pub fn lookup_surrogate_resource(name: &str) -> Option<SurrogateResource> {
    let key = name.trim().to_ascii_lowercase();
    match key.as_str() {
        "noopjs" | "noop.js" => Some(SurrogateResource {
            name: "noopjs".into(),
            mime_type: "application/javascript".into(),
            body: "(function(){})();".into(),
            is_base64: false,
        }),
        "noopcss" | "noop.css" => Some(SurrogateResource {
            name: "noopcss".into(),
            mime_type: "text/css".into(),
            body: String::new(),
            is_base64: false,
        }),
        "1x1.gif" | "1x1-transparent.gif" => Some(SurrogateResource {
            name: "1x1.gif".into(),
            mime_type: "image/gif".into(),
            body: "R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw==".into(),
            is_base64: true,
        }),
        "noopmp4-1s" | "noop-1s.mp4" => Some(SurrogateResource {
            name: "noopmp4-1s".into(),
            mime_type: "video/mp4".into(),
            body: "AAAAIGZ0eXBpc29tAAACAGlzb21pc28yYXZjMW1wNDEAAAAIZnJlZQAAAAhtZGF0".into(),
            is_base64: true,
        }),
        "googlesyndication_adsbygoogle.js" | "googlesyndication.com/adsbygoogle.js" => {
            Some(SurrogateResource {
                name: "googlesyndication_adsbygoogle.js".into(),
                mime_type: "application/javascript".into(),
                body: "(function(){window.adsbygoogle=window.adsbygoogle||{loaded:true,push:function(o){if(o&&typeof o.callback==='function'){try{o.callback();}catch(_){}}return 0;}};})();".into(),
                is_base64: false,
            })
        }
        "google-analytics_analytics.js" | "google-analytics.com/analytics.js" => {
            Some(SurrogateResource {
                name: "google-analytics_analytics.js".into(),
                mime_type: "application/javascript".into(),
                body: "(function(){var noop=function(){};var ga=function(){var a=arguments[arguments.length-1];if(a&&typeof a.hitCallback==='function'){try{a.hitCallback();}catch(_){}}};ga.create=function(){return {get:noop,set:noop,send:noop};};ga.getByName=ga.create;ga.getAll=function(){return[];};ga.remove=noop;ga.loaded=true;window.ga=ga;})();".into(),
                is_base64: false,
            })
        }
        "abort-on-property-read" | "aopr" => Some(SurrogateResource {
            name: "abort-on-property-read".into(),
            mime_type: "application/javascript".into(),
            body: render_scriptlet("abort-on-property-read", &[]).unwrap_or_default(),
            is_base64: false,
        }),
        "set-constant" | "set" => Some(SurrogateResource {
            name: "set-constant".into(),
            mime_type: "application/javascript".into(),
            body: render_scriptlet("set-constant", &[]).unwrap_or_default(),
            is_base64: false,
        }),
        "json-prune" => Some(SurrogateResource {
            name: "json-prune".into(),
            mime_type: "application/javascript".into(),
            body: render_scriptlet("json-prune", &[]).unwrap_or_default(),
            is_base64: false,
        }),
        "no-fetch-if" => Some(SurrogateResource {
            name: "no-fetch-if".into(),
            mime_type: "application/javascript".into(),
            body: render_scriptlet("no-fetch-if", &[]).unwrap_or_default(),
            is_base64: false,
        }),
        _ => None,
    }
}

/// Renders an executable JS scriptlet body from the embedded Singularity scriptlet catalogue.
pub fn render_scriptlet(name: &str, args: &[String]) -> Option<String> {
    let norm = name
        .trim()
        .trim_end_matches(".js")
        .to_ascii_lowercase();
    match norm.as_str() {
        "abort-on-property-read" | "aopr" => {
            let prop = js_escape_string(args.first().map(String::as_str).unwrap_or(""));
            Some(format!(
                "(function(){{var p='{prop}';if(!p)return;var m='SingularityAbort_'+Math.random().toString(36).slice(2);var parts=p.split('.');var cur=window;for(var i=0;i<parts.length-1;i++){{cur=cur[parts[i]];if(!cur)return;}}Object.defineProperty(cur,parts[parts.length-1],{{get:function(){{throw new ReferenceError(m);}},set:function(){{}}}});}})();"
            ))
        }
        "set-constant" | "set" => {
            let prop = js_escape_string(args.first().map(String::as_str).unwrap_or(""));
            let raw_val = args.get(1).map(String::as_str).unwrap_or("undefined");
            let js_val = match raw_val {
                "true" => "true".to_string(),
                "false" => "false".to_string(),
                "null" => "null".to_string(),
                "undefined" => "undefined".to_string(),
                "noopFunc" => "function(){}".to_string(),
                "trueFunc" => "function(){return true;}".to_string(),
                "falseFunc" => "function(){return false;}".to_string(),
                "emptyArr" => "[]".to_string(),
                "emptyObj" => "{}".to_string(),
                "''" | "" => "''".to_string(),
                other if other.parse::<f64>().is_ok() => other.to_string(),
                other => format!("'{}'", js_escape_string(other)),
            };
            Some(format!(
                "(function(){{var p='{prop}';if(!p)return;var parts=p.split('.');var cur=window;for(var i=0;i<parts.length-1;i++){{if(cur[parts[i]]==null)cur[parts[i]]={{}};cur=cur[parts[i]];}}Object.defineProperty(cur,parts[parts.length-1],{{value:{js_val},writable:false,configurable:true}});}})();"
            ))
        }
        "json-prune" => {
            let props = js_escape_string(args.first().map(String::as_str).unwrap_or(""));
            Some(format!(
                "(function(){{var keys='{props}'.split(/\\s+/).filter(Boolean);if(!keys.length)return;var orig=JSON.parse;JSON.parse=function(){{var obj=orig.apply(this,arguments);if(obj&&typeof obj==='object'){{for(var i=0;i<keys.length;i++){{var segs=keys[i].split('.');var c=obj;for(var j=0;j<segs.length-1&&c;j++)c=c[segs[j]];if(c&&segs.length)delete c[segs[segs.length-1]];}}}}return obj;}};}})();"
            ))
        }
        "no-fetch-if" => {
            let needle = js_escape_string(args.first().map(String::as_str).unwrap_or(""));
            Some(format!(
                "(function(){{var needle='{needle}';var orig=window.fetch;if(!orig)return;window.fetch=function(input,init){{var u=typeof input==='string'?input:(input&&input.url)||'';if(!needle||u.indexOf(needle)!==-1){{return Promise.resolve(new Response('',{{status:200}}));}}return orig.apply(this,arguments);}};}})();"
            ))
        }
        "noopjs" | "noop" => Some("(function(){})();".into()),
        _ => None,
    }
}

fn js_escape_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            _ => out.push(ch),
        }
    }
    out
}

fn canonical_network_rule_key(rule_body: &str) -> String {
    rule_body.trim().to_ascii_lowercase()
}

fn split_network_rule_and_options(rule: &str) -> Option<(&str, &str)> {
    // Avoid splitting on `$` inside regex literals `/.../`
    if rule.starts_with('/') && rule.ends_with('/') {
        return None;
    }
    let idx = rule.rfind('$')?;
    let body = &rule[..idx];
    let opts = &rule[idx + 1..];
    if opts.is_empty() {
        return None;
    }
    Some((body, opts))
}

fn parse_cosmetic_domains(dom_part: &str) -> (Vec<String>, Vec<String>) {
    let mut inc = Vec::new();
    let mut exc = Vec::new();
    for raw in dom_part.split(',') {
        let d = raw.trim().to_ascii_lowercase();
        if d.is_empty() {
            continue;
        }
        if let Some(neg) = d.strip_prefix('~') {
            if !neg.is_empty() {
                exc.push(neg.trim_end_matches('.').to_string());
            }
        } else {
            inc.push(d.trim_end_matches('.').to_string());
        }
    }
    (inc, exc)
}

fn cosmetic_domains_match(
    include_domains: &[String],
    exclude_domains: &[String],
    host_hierarchy: &[&str],
) -> bool {
    if exclude_domains
        .iter()
        .any(|d| host_hierarchy.contains(&d.as_str()))
    {
        return false;
    }
    if include_domains.is_empty() {
        return true;
    }
    include_domains
        .iter()
        .any(|d| host_hierarchy.contains(&d.as_str()))
}

fn split_scriptlet_args(inner: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut escaped = false;
    for ch in inner.chars() {
        if escaped {
            cur.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == ',' {
            out.push(cur.trim().to_string());
            cur.clear();
        } else {
            cur.push(ch);
        }
    }
    if !cur.trim().is_empty() || !out.is_empty() {
        out.push(cur.trim().to_string());
    }
    out
}

fn contains_procedural_operator(sel: &str) -> bool {
    sel.contains(":has-text(")
        || sel.contains(":upward(")
        || sel.contains(":style(")
        || sel.contains(":remove()")
}

fn parse_procedural_selector(raw: &str) -> Option<ProceduralCosmeticRule> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let op_markers = [":has-text(", ":upward(", ":style(", ":remove()"];
    let first_op_pos = op_markers
        .iter()
        .filter_map(|m| trimmed.find(m))
        .min()?;
    let base_selector = trimmed[..first_op_pos].trim().to_string();
    let mut rest = &trimmed[first_op_pos..];
    let mut operators = Vec::new();

    while !rest.is_empty() {
        if let Some(after) = rest.strip_prefix(":remove()") {
            operators.push(ProceduralOperator::Remove);
            rest = after.trim_start();
        } else if let Some(after) = rest.strip_prefix(":has-text(") {
            let (arg, tail) = take_balanced_paren_arg(after)?;
            operators.push(ProceduralOperator::HasText(arg));
            rest = tail.trim_start();
        } else if let Some(after) = rest.strip_prefix(":upward(") {
            let (arg, tail) = take_balanced_paren_arg(after)?;
            operators.push(ProceduralOperator::Upward(arg));
            rest = tail.trim_start();
        } else if let Some(after) = rest.strip_prefix(":style(") {
            let (arg, tail) = take_balanced_paren_arg(after)?;
            operators.push(ProceduralOperator::Style(arg));
            rest = tail.trim_start();
        } else {
            // Skip ahead to next procedural marker if chained combinators appear
            if let Some(next_pos) = op_markers.iter().filter_map(|m| rest.find(m)).min() {
                if next_pos == 0 {
                    break;
                }
                rest = &rest[next_pos..];
            } else {
                break;
            }
        }
    }

    if operators.is_empty() {
        return None;
    }

    Some(ProceduralCosmeticRule {
        base_selector,
        operators,
        raw_selector: trimmed.to_string(),
    })
}

fn take_balanced_paren_arg(s: &str) -> Option<(String, &str)> {
    let mut depth = 1i32;
    let mut escaped = false;
    for (idx, ch) in s.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some((s[..idx].to_string(), &s[idx + 1..]));
                }
            }
            _ => {}
        }
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn csp_or_rp_matches(
    domain_anchor: &Option<String>,
    url_pattern: &Option<String>,
    options: &RuleOptions,
    hierarchy: &[&str],
    url_lower: &str,
    is_third_party: bool,
    resource_type: NetworkResourceType,
    fp_lower: &str,
) -> bool {
    if !options.matches(is_third_party, resource_type, fp_lower) {
        return false;
    }
    if let Some(ref anchor) = domain_anchor {
        if !hierarchy.contains(&anchor.as_str()) {
            return false;
        }
    }
    if let Some(ref pat) = url_pattern {
        if !url_lower.contains(pat.as_str()) {
            return false;
        }
    }
    true
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

pub(crate) fn normalize_host(raw: &str) -> String {
    let trimmed = raw.trim().trim_end_matches('.');
    // Strip scheme if a caller accidentally passed a URL
    let without_scheme = trimmed
        .split_once("://")
        .map(|(_, r)| r)
        .unwrap_or(trimmed);
    let authority = without_scheme.split('/').next().unwrap_or("");
    let host_only = if authority.starts_with('[') {
        authority
            .split(']')
            .next()
            .unwrap_or(authority)
            .trim_start_matches('[')
    } else {
        authority.split(':').next().unwrap_or(authority)
    };
    host_only.trim_end_matches('.').to_ascii_lowercase()
}

pub(crate) fn extract_url_host_lower(url: &str) -> String {
    normalize_host(url)
}

fn host_matches_domain(host_lower: &str, rule_domain: &str) -> bool {
    let norm = normalize_host(rule_domain);
    if norm.is_empty() {
        return false;
    }
    host_lower == norm || host_lower.ends_with(&format!(".{}", norm))
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

/// Public helper checking whether two hostnames share the same registrable site (eTLD+1).
pub fn same_site_hosts(a: &str, b: &str) -> bool {
    same_site(&normalize_host(a), &normalize_host(b))
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

/// Extracts the normalized registrable domain (eTLD+1) from a hostname or URL.
pub fn extract_etld_plus_one(host_or_url: &str) -> String {
    let host = normalize_host(host_or_url);
    registrable_suffix(&host).to_string()
}

/// Computes the registrable domain (eTLD+1) using a multi-label Public Suffix table
/// (covering ccSLDs like `.co.uk`, `.com.au`, `.co.jp` and private hosting suffixes like
/// `.github.io`, `.pages.dev`, `.vercel.app`, `.amazonaws.com`, `.cloudfront.net`, etc.).
pub(crate) fn registrable_suffix(host: &str) -> &str {
    let h = host.trim_end_matches('.');
    if h.is_empty() || h.parse::<IpAddr>().is_ok() {
        return h;
    }
    if is_multi_label_public_suffix(h) {
        return h;
    }

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

    let mut dots = h.rmatch_indices('.');
    let _last = dots.next();
    match dots.next() {
        Some((idx, _)) => &h[idx + 1..],
        None => h,
    }
}

pub(crate) fn domain_hierarchy(host: &str) -> Vec<&str> {
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

        assert!(matches!(
            engine.evaluate_request(
                "https://example.org/ads/banner.js",
                "example.org",
                "news.test",
                NetworkResourceType::Script,
            ),
            FilterDecision::BlockedByPatternRule(_)
        ));
        assert!(matches!(
            engine.evaluate_request(
                "https://example.org/ads/banner.js?allow=1",
                "example.org",
                "news.test",
                NetworkResourceType::Script,
            ),
            FilterDecision::AllowByExceptionRule(_)
        ));
        assert_eq!(
            engine.evaluate_request(
                "https://example.org/app/main.js",
                "example.org",
                "news.test",
                NetworkResourceType::Script,
            ),
            FilterDecision::Allow
        );
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

    #[test]
    fn test_advanced_ublock_options_domain_badfilter_important_csp_removeparam_redirect() {
        let mut engine = UBlockNetworkEngine::new();
        let stats = engine.load_filter_list_text(
            r#"
            ||ads.scoped.test^$domain=news.test|~vip.news.test
            ||legacy-tracker.test^
            ||legacy-tracker.test^$badfilter
            @@||override.test^
            ||override.test^$important
            ||cdn.ads.test/adsbygoogle.js$script,redirect=googlesyndication_adsbygoogle.js
            ||strict-site.test^$csp=script-src 'self'
            ||shop.test^$removeparam=ref_code
            "#,
        );
        assert!(stats.total_added >= 8);
        assert_eq!(stats.badfilter_rules_added, 1);
        assert_eq!(stats.csp_rules_added, 1);
        assert_eq!(stats.removeparam_rules_added, 1);
        assert_eq!(stats.redirect_rules_added, 1);

        // $domain= scoping + exclusion
        assert!(matches!(
            engine.evaluate_request(
                "https://ads.scoped.test/a.js",
                "ads.scoped.test",
                "news.test",
                NetworkResourceType::Script
            ),
            FilterDecision::BlockedByDomainRule(_)
        ));
        assert_eq!(
            engine.evaluate_request(
                "https://ads.scoped.test/a.js",
                "ads.scoped.test",
                "vip.news.test",
                NetworkResourceType::Script
            ),
            FilterDecision::Allow
        );
        assert_eq!(
            engine.evaluate_request(
                "https://ads.scoped.test/a.js",
                "ads.scoped.test",
                "other.test",
                NetworkResourceType::Script
            ),
            FilterDecision::Allow
        );

        // $badfilter disables previous blocking rule
        assert_eq!(
            engine.evaluate_request(
                "https://legacy-tracker.test/p.js",
                "legacy-tracker.test",
                "site.test",
                NetworkResourceType::Script
            ),
            FilterDecision::Allow
        );

        // $important beats @@ exception
        assert!(matches!(
            engine.evaluate_request(
                "https://override.test/s.js",
                "override.test",
                "site.test",
                NetworkResourceType::Script
            ),
            FilterDecision::BlockedByDomainRule(_)
        ));

        // $redirect= returns surrogate resource
        let redir_eval = engine.evaluate_request_detailed(
            "https://cdn.ads.test/adsbygoogle.js",
            "cdn.ads.test",
            "blog.test",
            NetworkResourceType::Script,
        );
        assert!(matches!(
            redir_eval.decision,
            FilterDecision::BlockedByPatternRule(_)
        ));
        assert_eq!(
            redir_eval.redirect_resource.as_ref().map(|r| r.name.as_str()),
            Some("googlesyndication_adsbygoogle.js")
        );

        // $csp= injects header directives
        let csp_eval = engine.evaluate_request_detailed(
            "https://strict-site.test/",
            "strict-site.test",
            "strict-site.test",
            NetworkResourceType::MainFrameDocument,
        );
        assert_eq!(csp_eval.csp_directives, vec!["script-src 'self'"]);

        // $removeparam= strips configured parameter
        let rp_eval = engine.evaluate_request_detailed(
            "https://shop.test/item?id=7&ref_code=abc123",
            "shop.test",
            "shop.test",
            NetworkResourceType::MainFrameDocument,
        );
        assert_eq!(
            rp_eval.rewritten_url.as_deref(),
            Some("https://shop.test/item?id=7")
        );
    }

    #[test]
    fn test_cosmetic_procedural_scriptlets_and_validator() {
        let mut engine = UBlockNetworkEngine::new();
        engine.load_filter_list_text(
            r#"
            ##.global-ad-banner
            example.com##.site-popup
            example.com#@#.global-ad-banner
            example.com#?#article:has-text(Sponsored):upward(2):remove()
            example.com##.hero-ad:style(display: none !important)
            example.com##+js(abort-on-property-read, adBlockDetected)
            example.com##+js(set-constant, adsEnabled, false)
            "#,
        );

        let res = engine.cosmetic_resources_for_host("www.example.com");
        assert!(!res.css_selectors.contains(&".global-ad-banner".to_string()));
        assert!(res.css_selectors.contains(&".site-popup".to_string()));
        assert_eq!(res.procedural_rules.len(), 2);
        assert_eq!(res.procedural_rules[0].base_selector, "article");
        assert_eq!(res.procedural_rules[0].operators.len(), 3);
        assert_eq!(res.scriptlets.len(), 2);
        assert!(res.scriptlets[0]
            .resolved_source
            .as_deref()
            .unwrap()
            .contains("adBlockDetected"));
        assert!(res.scriptlets[1]
            .resolved_source
            .as_deref()
            .unwrap()
            .contains("false"));

        // Validator accepts safe selectors and rejects injection hazards
        assert!(UBlockNetworkEngine::validate_custom_cosmetic_selector("div.ad-slot > span[data-ad='1']").is_ok());
        assert!(UBlockNetworkEngine::validate_custom_cosmetic_selector("").is_err());
        assert!(UBlockNetworkEngine::validate_custom_cosmetic_selector("div { background: red }").is_err());
        assert!(UBlockNetworkEngine::validate_custom_cosmetic_selector("div</style><script>alert(1)</script>").is_err());
        assert!(UBlockNetworkEngine::validate_custom_cosmetic_selector("div[unclosed").is_err());
    }

    #[test]
    fn test_clearurls_120_plus_and_antibounce_debouncer() {
        assert!(UBlockNetworkEngine::tracking_param_count() >= 120);

        let amazon = "https://www.amazon.com/dp/B001?tag=aff-20&pf_rd_r=123&qid=999&color=black";
        assert_eq!(
            UBlockNetworkEngine::scrub_tracking_query_params(amazon),
            "https://www.amazon.com/dp/B001?color=black"
        );

        let yt = "https://www.youtube.com/watch?v=dQw4w9WgXcQ&si=abcdef123&pp=ygU";
        assert_eq!(
            UBlockNetworkEngine::scrub_tracking_query_params(yt),
            "https://www.youtube.com/watch?v=dQw4w9WgXcQ"
        );

        let fb_bounce = "https://l.facebook.com/l.php?u=https%3A%2F%2Fexample.org%2Fnews%3Fid%3D9%26fbclid%3D12345&h=AT0";
        assert_eq!(
            UBlockNetworkEngine::debounce_tracking_redirect(fb_bounce).as_deref(),
            Some("https://example.org/news?id=9")
        );

        let google_bounce = "https://www.google.com/url?q=https%3A%2F%2Fmullvad.net%2Fen%3Futm_source%3Dsearch&sa=U";
        assert_eq!(
            UBlockNetworkEngine::debounce_tracking_redirect(google_bounce).as_deref(),
            Some("https://mullvad.net/en")
        );

        let reddit_bounce = "https://out.reddit.com/t3_123?url=https%3A%2F%2Frust-lang.org%2F%3Futm_campaign%3Dshare";
        assert_eq!(
            UBlockNetworkEngine::debounce_tracking_redirect(reddit_bounce).as_deref(),
            Some("https://rust-lang.org/")
        );

        let click_bounce = "https://click.email.shop.test/track?dest=https%3A%2F%2Fshop.test%2Fdeal%3Fgclid%3Dxyz";
        assert_eq!(
            UBlockNetworkEngine::debounce_tracking_redirect(click_bounce).as_deref(),
            Some("https://shop.test/deal")
        );

        // Rejects javascript: bounce injection
        let xss_bounce = "https://l.facebook.com/l.php?u=javascript%3Aalert(1)";
        assert!(UBlockNetworkEngine::debounce_tracking_redirect(xss_bounce).is_none());
    }

    #[test]
    fn test_dynamic_matrix_site_policy_and_bounded_logger() {
        let mut engine = UBlockNetworkEngine::default();
        engine.dynamic_matrix_mut().enable_medium_mode();

        // Medium mode blocks arbitrary 3rd-party scripts
        assert!(matches!(
            engine.evaluate_request(
                "https://cdn.thirdparty.test/app.js",
                "cdn.thirdparty.test",
                "news.test",
                NetworkResourceType::Script
            ),
            FilterDecision::BlockedByDomainRule(_)
        ));

        // Per-site Noop relaxes dynamic block so non-tracker CDN is allowed
        engine.dynamic_matrix_mut().set_rule(
            "news.test",
            "cdn.thirdparty.test",
            DynamicResourceKind::All,
            DynamicRuleAction::Noop,
        );
        assert_eq!(
            engine.evaluate_request(
                "https://cdn.thirdparty.test/app.js",
                "cdn.thirdparty.test",
                "news.test",
                NetworkResourceType::Script
            ),
            FilterDecision::Allow
        );

        // Site Shields Policy: disabled shields allow trackers on that site
        engine.set_site_policy(
            "trusted.test",
            SiteShieldsPolicy {
                enabled: false,
                ..SiteShieldsPolicy::default()
            },
        );
        assert_eq!(
            engine.evaluate_request(
                "https://doubleclick.net/ad.js",
                "doubleclick.net",
                "trusted.test",
                NetworkResourceType::Script
            ),
            FilterDecision::Allow
        );

        // Bounded live logger cap 2000
        engine.set_logger_enabled(true);
        for i in 0..(MAX_SHIELD_LOG_EVENTS + 50) {
            let _ = engine.evaluate_request(
                &format!("https://example.org/res/{}", i),
                "example.org",
                "example.org",
                NetworkResourceType::Image,
            );
        }
        assert_eq!(engine.recent_log_events().len(), MAX_SHIELD_LOG_EVENTS);
        engine.clear_log();
        assert!(engine.recent_log_events().is_empty());
    }

    #[test]
    fn test_strip_ascii_prefix_ci_non_ascii_boundary_safe() {
        assert_eq!(
            strip_ascii_prefix_ci("DOMAIN=example.com", "domain="),
            Some("example.com")
        );
        // Multi-byte UTF-8 input where prefix_lower.len() lands mid-character must return None, not panic
        assert_eq!(strip_ascii_prefix_ci("\u{00E9}\u{00E9}\u{00E9}\u{00E9}", "domain="), None);
        let mut engine = UBlockNetworkEngine::new();
        let _ = engine.load_filter_list_text("example.com$\u{00E9}\u{00E9}\u{00E9}\u{00E9}");
    }
}
