//! Singularity High-Capacity Relational History Store & Chrome Journeys Engine — 100% Pure Rust.
//!
//! Features:
//! - High-capacity persistent relational store (`history_store.json` + atomic `.tmp`/`.bak`
//!   writes with automatic `.bak` recovery), default capacity 100,000 visits (configurable)
//! - Normalized `HistoryUrlRecord` + `HistoryVisitRecord` tables with dwell time tracking
//! - Fuzzy search & query operators (`site:`, `before:`, `after:`, `type:`) with virtualized
//!   pagination (`HistoryQueryParams` -> `HistoryQueryPage`)
//! - Local thematic clustering (`build_history_journeys`) combining `referrer_visit_id` chains,
//!   45-minute inactivity windows, and shared content/search keywords
//! - Granular deletion (`delete_visits`, `delete_domain`, `delete_time_range`, `clear_all`)
//! - Retention policy & domain exclusions (`HistoryRetentionPolicy` + `enforce_retention`)
//! - Local privacy-preserving analytics (`compute_visit_stats`: top 15 domains, 24h hourly
//!   distribution, daily volume, total reading/dwell time)
//! - Export to JSON (`export_json`) and RFC 4180 CSV (`export_csv`).

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

pub const HISTORY_STORE_FILENAME: &str = "history_store.json";
pub const DEFAULT_MAX_VISITS: usize = 100_000;
pub const JOURNEY_INACTIVITY_WINDOW_SECS: u64 = 45 * 60;
const HISTORY_SCHEMA_VERSION: u32 = 1;

// ============================================================================
// Errors
// ============================================================================

#[derive(Debug, Error)]
pub enum HistoryStoreError {
    #[error("I/O error accessing history store: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON serialization/deserialization error: {0}")]
    Json(#[from] serde_json::Error),
}

// ============================================================================
// Core Relational Records & Policies
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VisitTransitionType {
    Link,
    Typed,
    Bookmark,
    AutoSubframe,
    Reload,
    Generated,
    FormSubmit,
    Keyword,
    Redirect,
    Other,
}

impl Default for VisitTransitionType {
    fn default() -> Self {
        Self::Link
    }
}

impl VisitTransitionType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Link => "link",
            Self::Typed => "typed",
            Self::Bookmark => "bookmark",
            Self::AutoSubframe => "auto_subframe",
            Self::Reload => "reload",
            Self::Generated => "generated",
            Self::FormSubmit => "form_submit",
            Self::Keyword => "keyword",
            Self::Redirect => "redirect",
            Self::Other => "other",
        }
    }

    pub fn from_filter_token(token: &str) -> Option<Self> {
        match token.trim().to_ascii_lowercase().as_str() {
            "link" | "click" => Some(Self::Link),
            "typed" | "omnibox" => Some(Self::Typed),
            "bookmark" | "bm" | "favori" => Some(Self::Bookmark),
            "subframe" | "auto_subframe" => Some(Self::AutoSubframe),
            "reload" | "refresh" => Some(Self::Reload),
            "generated" | "search" => Some(Self::Generated),
            "form" | "form_submit" => Some(Self::FormSubmit),
            "keyword" | "bang" => Some(Self::Keyword),
            "redirect" => Some(Self::Redirect),
            "other" => Some(Self::Other),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryUrlRecord {
    pub id: u64,
    pub url: String,
    pub title: String,
    pub domain: String,
    pub visit_count: u32,
    pub typed_count: u32,
    pub last_visit_unix: u64,
    #[serde(default)]
    pub favicon_url: Option<String>,
    #[serde(default)]
    pub total_dwell_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryVisitRecord {
    pub id: u64,
    pub url_id: u64,
    pub visit_time_unix: u64,
    #[serde(default)]
    pub transition_type: VisitTransitionType,
    #[serde(default)]
    pub referrer_visit_id: Option<u64>,
    #[serde(default)]
    pub dwell_time_ms: u64,
    #[serde(default)]
    pub search_query: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryRetentionPolicy {
    /// Maximum age in days before visits are purged. `None` keeps history indefinitely.
    #[serde(default)]
    pub max_age_days: Option<u32>,
    #[serde(default)]
    pub clear_on_exit: bool,
    #[serde(default)]
    pub excluded_domains: Vec<String>,
}

impl Default for HistoryRetentionPolicy {
    fn default() -> Self {
        Self {
            max_age_days: Some(365),
            clear_on_exit: false,
            excluded_domains: Vec::new(),
        }
    }
}

impl HistoryRetentionPolicy {
    /// Returns `true` if `domain` matches any entry in `excluded_domains` (exact or subdomain).
    pub fn is_domain_excluded(&self, domain: &str) -> bool {
        let d = domain.trim().to_ascii_lowercase();
        if d.is_empty() {
            return false;
        }
        self.excluded_domains.iter().any(|excl| {
            let e = excl.trim().trim_start_matches('.').to_ascii_lowercase();
            !e.is_empty() && (d == e || d.ends_with(&format!(".{}", e)))
        })
    }
}

// ============================================================================
// Query Params, Virtualized Pages, Journeys & Analytics Models
// ============================================================================

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HistoryQueryParams {
    #[serde(default)]
    pub query: String,
    #[serde(default)]
    pub offset: usize,
    #[serde(default = "default_page_limit")]
    pub limit: usize,
    #[serde(default)]
    pub since_unix: Option<u64>,
    #[serde(default)]
    pub until_unix: Option<u64>,
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub transition_type: Option<VisitTransitionType>,
    /// When `true`, returns at most one (most recent) matching visit per unique URL.
    #[serde(default)]
    pub deduplicate_urls: bool,
}

fn default_page_limit() -> usize {
    50
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryQueryItem {
    pub visit_id: u64,
    pub url_id: u64,
    pub url: String,
    pub title: String,
    pub domain: String,
    pub visit_time_unix: u64,
    pub transition_type: VisitTransitionType,
    pub referrer_visit_id: Option<u64>,
    pub dwell_time_ms: u64,
    pub search_query: Option<String>,
    pub visit_count: u32,
    pub typed_count: u32,
    pub favicon_url: Option<String>,
    pub match_score: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryQueryPage {
    pub items: Vec<HistoryQueryItem>,
    pub total_matches: usize,
    pub offset: usize,
    pub limit: usize,
    pub has_more: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryJourney {
    pub id: String,
    pub title: String,
    pub keywords: Vec<String>,
    pub primary_domain: String,
    pub start_unix: u64,
    pub end_unix: u64,
    pub total_dwell_ms: u64,
    pub visit_count: usize,
    pub items: Vec<HistoryQueryItem>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainVisitStat {
    pub domain: String,
    pub visit_count: usize,
    pub unique_urls: usize,
    pub total_dwell_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DailyVisitStat {
    pub date: String,
    pub visit_count: usize,
    pub total_dwell_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryVisitStats {
    pub range_days: u32,
    pub total_visits: usize,
    pub unique_urls: usize,
    pub unique_domains: usize,
    pub total_dwell_ms: u64,
    pub top_domains: Vec<DomainVisitStat>,
    pub hourly_distribution: [usize; 24],
    pub daily_volume: Vec<DailyVisitStat>,
}

// ============================================================================
// Persistent Envelope & Store Implementation
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HistoryStoreDiskFormat {
    schema_version: u32,
    max_visits: usize,
    next_url_id: u64,
    next_visit_id: u64,
    retention: HistoryRetentionPolicy,
    urls: Vec<HistoryUrlRecord>,
    visits: Vec<HistoryVisitRecord>,
}

#[derive(Debug, Clone)]
pub struct HistoryStore {
    pub max_visits: usize,
    pub retention: HistoryRetentionPolicy,
    next_url_id: u64,
    next_visit_id: u64,
    urls: HashMap<u64, HistoryUrlRecord>,
    url_to_id: HashMap<String, u64>,
    visits: Vec<HistoryVisitRecord>,
}

impl Default for HistoryStore {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_VISITS)
    }
}

impl HistoryStore {
    pub fn new(max_visits: usize) -> Self {
        Self {
            max_visits: max_visits.max(100),
            retention: HistoryRetentionPolicy::default(),
            next_url_id: 1,
            next_visit_id: 1,
            urls: HashMap::new(),
            url_to_id: HashMap::new(),
            visits: Vec::new(),
        }
    }

    /// Loads `history_store.json` from `dir`, automatically falling back to `.bak` on corruption.
    pub fn load_from_dir(dir: &Path) -> Result<Self, HistoryStoreError> {
        let primary = dir.join(HISTORY_STORE_FILENAME);
        Self::load_from_path(&primary)
    }

    pub fn load_from_path(path: &Path) -> Result<Self, HistoryStoreError> {
        let backup = backup_path_for(path);
        if path.exists() {
            match Self::read_single_file(path) {
                Ok(store) => return Ok(store),
                Err(_) if backup.exists() => {
                    return Self::read_single_file(&backup);
                }
                Err(e) => return Err(e),
            }
        }
        if backup.exists() {
            return Self::read_single_file(&backup);
        }
        Ok(Self::default())
    }

    fn read_single_file(path: &Path) -> Result<Self, HistoryStoreError> {
        let raw = std::fs::read_to_string(path)?;
        let disk: HistoryStoreDiskFormat = serde_json::from_str(&raw)?;
        let mut urls = HashMap::with_capacity(disk.urls.len());
        let mut url_to_id = HashMap::with_capacity(disk.urls.len());
        let mut max_uid = disk.next_url_id;
        for rec in disk.urls {
            max_uid = max_uid.max(rec.id + 1);
            url_to_id.insert(rec.url.clone(), rec.id);
            urls.insert(rec.id, rec);
        }
        let mut max_vid = disk.next_visit_id;
        for v in &disk.visits {
            max_vid = max_vid.max(v.id + 1);
        }
        Ok(Self {
            max_visits: disk.max_visits.max(100),
            retention: disk.retention,
            next_url_id: max_uid,
            next_visit_id: max_vid,
            urls,
            url_to_id,
            visits: disk.visits,
        })
    }

    /// Atomically persists `history_store.json` inside `dir`, rotating the previous version to `.bak`.
    pub fn save_to_dir(&self, dir: &Path) -> Result<PathBuf, HistoryStoreError> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join(HISTORY_STORE_FILENAME);
        self.save_to_path(&path)?;
        Ok(path)
    }

    pub fn save_to_path(&self, path: &Path) -> Result<(), HistoryStoreError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut urls_sorted: Vec<HistoryUrlRecord> = self.urls.values().cloned().collect();
        urls_sorted.sort_by_key(|u| u.id);

        let disk = HistoryStoreDiskFormat {
            schema_version: HISTORY_SCHEMA_VERSION,
            max_visits: self.max_visits,
            next_url_id: self.next_url_id,
            next_visit_id: self.next_visit_id,
            retention: self.retention.clone(),
            urls: urls_sorted,
            visits: self.visits.clone(),
        };
        let bytes = serde_json::to_vec(&disk)?;
        atomic_write_with_backup(path, &bytes)?;
        Ok(())
    }

    pub fn url_count(&self) -> usize {
        self.urls.len()
    }

    pub fn visit_count(&self) -> usize {
        self.visits.len()
    }

    pub fn get_url_record(&self, url_id: u64) -> Option<&HistoryUrlRecord> {
        self.urls.get(&url_id)
    }

    pub fn all_url_records(&self) -> Vec<&HistoryUrlRecord> {
        self.urls.values().collect()
    }

    pub fn all_visits(&self) -> &[HistoryVisitRecord] {
        &self.visits
    }

    /// Records a new visit. Returns `None` if the URL is empty, internal non-recordable,
    /// or its domain is in `retention.excluded_domains`.
    #[allow(clippy::too_many_arguments)]
    pub fn record_visit(
        &mut self,
        url: &str,
        title: &str,
        transition_type: VisitTransitionType,
        referrer_visit_id: Option<u64>,
        favicon_url: Option<String>,
        search_query: Option<String>,
        visit_time_unix: u64,
    ) -> Option<u64> {
        let trimmed_url = url.trim();
        if trimmed_url.is_empty() || trimmed_url.len() > 8192 {
            return None;
        }
        let domain = extract_domain(trimmed_url);
        if self.retention.is_domain_excluded(&domain) {
            return None;
        }

        let clean_title = if title.trim().is_empty() {
            domain.clone()
        } else {
            title.trim().chars().take(300).collect()
        };

        let is_typed = matches!(
            transition_type,
            VisitTransitionType::Typed | VisitTransitionType::Keyword
        );

        let url_id = if let Some(&existing_id) = self.url_to_id.get(trimmed_url) {
            if let Some(rec) = self.urls.get_mut(&existing_id) {
                rec.visit_count = rec.visit_count.saturating_add(1);
                if is_typed {
                    rec.typed_count = rec.typed_count.saturating_add(1);
                }
                rec.last_visit_unix = rec.last_visit_unix.max(visit_time_unix);
                if !title.trim().is_empty() {
                    rec.title = clean_title;
                }
                if favicon_url.is_some() {
                    rec.favicon_url = favicon_url;
                }
            }
            existing_id
        } else {
            let id = self.next_url_id;
            self.next_url_id += 1;
            let rec = HistoryUrlRecord {
                id,
                url: trimmed_url.to_string(),
                title: clean_title,
                domain,
                visit_count: 1,
                typed_count: u32::from(is_typed),
                last_visit_unix: visit_time_unix,
                favicon_url,
                total_dwell_ms: 0,
            };
            self.url_to_id.insert(trimmed_url.to_string(), id);
            self.urls.insert(id, rec);
            id
        };

        let visit_id = self.next_visit_id;
        self.next_visit_id += 1;
        let inferred_search = search_query.or_else(|| infer_search_query_from_url(trimmed_url));

        self.visits.push(HistoryVisitRecord {
            id: visit_id,
            url_id,
            visit_time_unix,
            transition_type,
            referrer_visit_id,
            dwell_time_ms: 0,
            search_query: inferred_search,
        });

        // Enforce configurable visit capacity (no hardcoded 400 cap!)
        if self.visits.len() > self.max_visits {
            let overflow = self.visits.len() - self.max_visits;
            self.visits.drain(0..overflow);
            self.reconcile_url_aggregates();
        }

        Some(visit_id)
    }

    /// Accumulates reading/dwell time (in ms) on a visit and its parent URL record.
    pub fn add_dwell_time(&mut self, visit_id: u64, delta_ms: u64) -> bool {
        if delta_ms == 0 {
            return false;
        }
        if let Some(v) = self.visits.iter_mut().find(|v| v.id == visit_id) {
            v.dwell_time_ms = v.dwell_time_ms.saturating_add(delta_ms);
            if let Some(u) = self.urls.get_mut(&v.url_id) {
                u.total_dwell_ms = u.total_dwell_ms.saturating_add(delta_ms);
            }
            return true;
        }
        false
    }

    /// Updates the title for a known URL (e.g., once `<title>` finishes loading).
    pub fn update_title(&mut self, url: &str, new_title: &str) -> bool {
        let trimmed = new_title.trim();
        if trimmed.is_empty() {
            return false;
        }
        if let Some(&uid) = self.url_to_id.get(url.trim()) {
            if let Some(rec) = self.urls.get_mut(&uid) {
                rec.title = trimmed.chars().take(300).collect();
                return true;
            }
        }
        false
    }

    // ------------------------------------------------------------------------
    // Fuzzy Search + Operators (`site:`, `before:`, `after:`, `type:`) + Pagination
    // ------------------------------------------------------------------------

    pub fn query(&self, params: &HistoryQueryParams) -> HistoryQueryPage {
        let parsed = parse_history_query(&params.query);
        let effective_site = params
            .domain
            .as_deref()
            .map(|d| d.trim().to_ascii_lowercase())
            .filter(|d| !d.is_empty())
            .or(parsed.site);
        let effective_since = match (params.since_unix, parsed.after_unix) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        };
        let effective_until = match (params.until_unix, parsed.before_unix) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        let effective_type = params.transition_type.or(parsed.transition_type);

        let limit = if params.limit == 0 { 50 } else { params.limit.min(500) };

        let mut matched: Vec<HistoryQueryItem> = Vec::new();
        let mut seen_urls: HashSet<u64> = HashSet::new();

        // Iterate newest first
        for visit in self.visits.iter().rev() {
            if let Some(since) = effective_since {
                if visit.visit_time_unix < since {
                    continue;
                }
            }
            if let Some(until) = effective_until {
                if visit.visit_time_unix > until {
                    continue;
                }
            }
            if let Some(tfilter) = effective_type {
                if visit.transition_type != tfilter {
                    continue;
                }
            }

            let Some(url_rec) = self.urls.get(&visit.url_id) else {
                continue;
            };

            if let Some(ref site) = effective_site {
                let dl = url_rec.domain.to_ascii_lowercase();
                if dl != *site && !dl.ends_with(&format!(".{}", site)) {
                    continue;
                }
            }

            let mut total_score = 0i64;
            if !parsed.terms.is_empty() {
                let mut all_ok = true;
                for term in &parsed.terms {
                    let s_title = simple_fuzzy_score(term, &url_rec.title);
                    let s_url = simple_fuzzy_score(term, &url_rec.url);
                    let s_sq = visit
                        .search_query
                        .as_deref()
                        .and_then(|sq| simple_fuzzy_score(term, sq));
                    let best = [s_title.map(|s| s + 25), s_url, s_sq.map(|s| s + 20)]
                        .into_iter()
                        .flatten()
                        .max();
                    match best {
                        Some(sc) => total_score += sc,
                        None => {
                            all_ok = false;
                            break;
                        }
                    }
                }
                if !all_ok {
                    continue;
                }
            }

            if params.deduplicate_urls && !seen_urls.insert(url_rec.id) {
                continue;
            }

            matched.push(HistoryQueryItem {
                visit_id: visit.id,
                url_id: url_rec.id,
                url: url_rec.url.clone(),
                title: url_rec.title.clone(),
                domain: url_rec.domain.clone(),
                visit_time_unix: visit.visit_time_unix,
                transition_type: visit.transition_type,
                referrer_visit_id: visit.referrer_visit_id,
                dwell_time_ms: visit.dwell_time_ms,
                search_query: visit.search_query.clone(),
                visit_count: url_rec.visit_count,
                typed_count: url_rec.typed_count,
                favicon_url: url_rec.favicon_url.clone(),
                match_score: total_score,
            });
        }

        // Sort: when query terms are provided, blend relevance and recency; otherwise strictly newest first
        if !parsed.terms.is_empty() {
            matched.sort_by(|a, b| {
                b.match_score
                    .cmp(&a.match_score)
                    .then_with(|| b.visit_time_unix.cmp(&a.visit_time_unix))
                    .then_with(|| b.visit_id.cmp(&a.visit_id))
            });
        } else {
            matched.sort_by(|a, b| {
                b.visit_time_unix
                    .cmp(&a.visit_time_unix)
                    .then_with(|| b.visit_id.cmp(&a.visit_id))
            });
        }

        let total_matches = matched.len();
        let start = params.offset.min(total_matches);
        let end = (start + limit).min(total_matches);
        let page_items = matched[start..end].to_vec();

        HistoryQueryPage {
            items: page_items,
            total_matches,
            offset: start,
            limit,
            has_more: end < total_matches,
        }
    }

    // ------------------------------------------------------------------------
    // Chrome Journeys — Local Thematic Clustering
    // ------------------------------------------------------------------------

    /// Builds thematic browsing journeys locally by clustering visits using:
    /// 1. Direct `referrer_visit_id` navigation chains
    /// 2. 45-minute inactivity session windows (`JOURNEY_INACTIVITY_WINDOW_SECS`)
    /// 3. Shared domain or shared content/search keywords within a session.
    pub fn build_history_journeys(&self, max_journeys: usize) -> Vec<HistoryJourney> {
        if self.visits.is_empty() {
            return Vec::new();
        }

        // Build chronologically sorted joined items
        let mut sorted_visits: Vec<&HistoryVisitRecord> = self.visits.iter().collect();
        sorted_visits.sort_by_key(|v| (v.visit_time_unix, v.id));

        let n = sorted_visits.len();
        let mut id_to_idx: HashMap<u64, usize> = HashMap::with_capacity(n);
        let mut kw_sets: Vec<HashSet<String>> = Vec::with_capacity(n);
        let mut domains: Vec<String> = Vec::with_capacity(n);

        for (i, v) in sorted_visits.iter().enumerate() {
            id_to_idx.insert(v.id, i);
            if let Some(u) = self.urls.get(&v.url_id) {
                domains.push(u.domain.clone());
                let mut kws = extract_keywords(&u.title);
                if let Some(ref sq) = v.search_query {
                    kws.extend(extract_keywords(sq));
                }
                kw_sets.push(kws);
            } else {
                domains.push(String::new());
                kw_sets.push(HashSet::new());
            }
        }

        // Union-Find for clustering
        let mut parent: Vec<usize> = (0..n).collect();
        fn find(p: &mut [usize], mut x: usize) -> usize {
            while p[x] != x {
                p[x] = p[p[x]];
                x = p[x];
            }
            x
        }
        fn union(p: &mut [usize], a: usize, b: usize) {
            let ra = find(p, a);
            let rb = find(p, b);
            if ra != rb {
                p[rb] = ra;
            }
        }

        // Pass 1: link explicit referrer chains regardless of keyword overlap (within 4h cap)
        for (i, v) in sorted_visits.iter().enumerate() {
            if let Some(ref_id) = v.referrer_visit_id {
                if let Some(&ref_idx) = id_to_idx.get(&ref_id) {
                    let gap = v
                        .visit_time_unix
                        .saturating_sub(sorted_visits[ref_idx].visit_time_unix);
                    if gap <= 4 * 3600 {
                        union(&mut parent, ref_idx, i);
                    }
                }
            }
        }

        // Pass 2: link visits within 45-minute inactivity window sharing domain or >= 1 keyword
        for i in 1..n {
            let t_curr = sorted_visits[i].visit_time_unix;
            // Scan backwards within the 45-minute window
            let mut j = i;
            while j > 0 {
                j -= 1;
                let gap = t_curr.saturating_sub(sorted_visits[j].visit_time_unix);
                if gap > JOURNEY_INACTIVITY_WINDOW_SECS {
                    break;
                }
                let same_domain = !domains[i].is_empty() && domains[i] == domains[j];
                let shared_kw = !kw_sets[i].is_empty()
                    && kw_sets[i].iter().any(|k| kw_sets[j].contains(k));
                if same_domain || shared_kw {
                    union(&mut parent, j, i);
                }
            }
        }

        // Collect clusters
        let mut clusters: HashMap<usize, Vec<usize>> = HashMap::new();
        for i in 0..n {
            let root = find(&mut parent, i);
            clusters.entry(root).or_default().push(i);
        }

        let mut journeys = Vec::new();
        for (_, indices) in clusters {
            if indices.is_empty() {
                continue;
            }
            let mut items = Vec::with_capacity(indices.len());
            let mut start_unix = u64::MAX;
            let mut end_unix = 0u64;
            let mut total_dwell_ms = 0u64;
            let mut kw_freq: HashMap<String, usize> = HashMap::new();
            let mut dom_freq: HashMap<String, usize> = HashMap::new();
            let mut latest_search_query: Option<(u64, String)> = None;

            for &idx in &indices {
                let v = sorted_visits[idx];
                let Some(u) = self.urls.get(&v.url_id) else {
                    continue;
                };
                start_unix = start_unix.min(v.visit_time_unix);
                end_unix = end_unix.max(v.visit_time_unix);
                total_dwell_ms = total_dwell_ms.saturating_add(v.dwell_time_ms);

                if !u.domain.is_empty() {
                    *dom_freq.entry(u.domain.clone()).or_insert(0) += 1;
                }
                for kw in &kw_sets[idx] {
                    *kw_freq.entry(kw.clone()).or_insert(0) += 1;
                }
                if let Some(ref sq) = v.search_query {
                    if !sq.trim().is_empty()
                        && latest_search_query
                            .as_ref()
                            .map_or(true, |(t, _)| v.visit_time_unix >= *t)
                    {
                        latest_search_query = Some((v.visit_time_unix, sq.trim().to_string()));
                    }
                }

                items.push(HistoryQueryItem {
                    visit_id: v.id,
                    url_id: u.id,
                    url: u.url.clone(),
                    title: u.title.clone(),
                    domain: u.domain.clone(),
                    visit_time_unix: v.visit_time_unix,
                    transition_type: v.transition_type,
                    referrer_visit_id: v.referrer_visit_id,
                    dwell_time_ms: v.dwell_time_ms,
                    search_query: v.search_query.clone(),
                    visit_count: u.visit_count,
                    typed_count: u.typed_count,
                    favicon_url: u.favicon_url.clone(),
                    match_score: 0,
                });
            }

            if items.is_empty() {
                continue;
            }
            // Show items newest-first inside each journey
            items.sort_by(|a, b| {
                b.visit_time_unix
                    .cmp(&a.visit_time_unix)
                    .then_with(|| b.visit_id.cmp(&a.visit_id))
            });

            let mut top_kws: Vec<(String, usize)> = kw_freq.into_iter().collect();
            top_kws.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            let keywords: Vec<String> = top_kws.into_iter().take(5).map(|(k, _)| k).collect();

            let primary_domain = dom_freq
                .into_iter()
                .max_by(|a, b| a.1.cmp(&b.1).then_with(|| b.0.cmp(&a.0)))
                .map(|(d, _)| d)
                .unwrap_or_default();

            let title = if let Some((_, sq)) = latest_search_query {
                sq
            } else if !keywords.is_empty() {
                capitalize_words(&keywords.iter().take(3).cloned().collect::<Vec<_>>().join(" "))
            } else if !primary_domain.is_empty() {
                primary_domain.clone()
            } else {
                items[0].title.clone()
            };

            let first_id = items.last().map(|i| i.visit_id).unwrap_or(0);
            journeys.push(HistoryJourney {
                id: format!("journey-{}-{}", start_unix, first_id),
                title,
                keywords,
                primary_domain,
                start_unix,
                end_unix,
                total_dwell_ms,
                visit_count: items.len(),
                items,
            });
        }

        // Most recent journeys first
        journeys.sort_by(|a, b| {
            b.end_unix
                .cmp(&a.end_unix)
                .then_with(|| b.visit_count.cmp(&a.visit_count))
        });
        if max_journeys > 0 {
            journeys.truncate(max_journeys);
        }
        journeys
    }

    // ------------------------------------------------------------------------
    // Granular Deletion & Retention Policy
    // ------------------------------------------------------------------------

    /// Deletes specific visit IDs and reconciles URL counters / removes orphaned URL records.
    pub fn delete_visits(&mut self, visit_ids: &[u64]) -> usize {
        if visit_ids.is_empty() {
            return 0;
        }
        let target: HashSet<u64> = visit_ids.iter().copied().collect();
        let before = self.visits.len();
        self.visits.retain(|v| !target.contains(&v.id));
        let removed = before - self.visits.len();
        if removed > 0 {
            self.reconcile_url_aggregates();
        }
        removed
    }

    /// Deletes all visits and URL records belonging to `domain` (exact or subdomain match).
    pub fn delete_domain(&mut self, domain: &str) -> usize {
        let target = domain.trim().trim_start_matches('.').to_ascii_lowercase();
        if target.is_empty() {
            return 0;
        }
        let suffix = format!(".{}", target);
        let matching_url_ids: HashSet<u64> = self
            .urls
            .values()
            .filter(|u| {
                let d = u.domain.to_ascii_lowercase();
                d == target || d.ends_with(&suffix)
            })
            .map(|u| u.id)
            .collect();

        if matching_url_ids.is_empty() {
            return 0;
        }

        let before = self.visits.len();
        self.visits.retain(|v| !matching_url_ids.contains(&v.url_id));
        let removed = before - self.visits.len();
        self.reconcile_url_aggregates();
        removed
    }

    /// Deletes all visits with timestamps in the inclusive range `[since_unix, until_unix]`.
    pub fn delete_time_range(&mut self, since_unix: u64, until_unix: u64) -> usize {
        let lo = since_unix.min(until_unix);
        let hi = since_unix.max(until_unix);
        let before = self.visits.len();
        self.visits
            .retain(|v| v.visit_time_unix < lo || v.visit_time_unix > hi);
        let removed = before - self.visits.len();
        if removed > 0 {
            self.reconcile_url_aggregates();
        }
        removed
    }

    /// Clears all history visits and URL records.
    pub fn clear_all(&mut self) {
        self.visits.clear();
        self.urls.clear();
        self.url_to_id.clear();
    }

    /// Applies `retention` (`max_age_days` and `excluded_domains`), returning the count of removed visits.
    pub fn enforce_retention(&mut self, now_unix: u64) -> usize {
        let cutoff = self
            .retention
            .max_age_days
            .map(|days| now_unix.saturating_sub((days as u64) * 86_400));

        let excluded_url_ids: HashSet<u64> = self
            .urls
            .values()
            .filter(|u| self.retention.is_domain_excluded(&u.domain))
            .map(|u| u.id)
            .collect();

        let before = self.visits.len();
        self.visits.retain(|v| {
            if excluded_url_ids.contains(&v.url_id) {
                return false;
            }
            if let Some(min_ts) = cutoff {
                if v.visit_time_unix < min_ts {
                    return false;
                }
            }
            true
        });
        let removed = before - self.visits.len();
        if removed > 0 || !excluded_url_ids.is_empty() {
            self.reconcile_url_aggregates();
        }
        removed
    }

    fn reconcile_url_aggregates(&mut self) {
        // Recompute visit_count, typed_count, last_visit_unix, total_dwell_ms from live visits
        let mut agg: HashMap<u64, (u32, u32, u64, u64)> = HashMap::new();
        for v in &self.visits {
            let is_typed = matches!(
                v.transition_type,
                VisitTransitionType::Typed | VisitTransitionType::Keyword
            );
            let entry = agg.entry(v.url_id).or_insert((0, 0, 0, 0));
            entry.0 = entry.0.saturating_add(1);
            if is_typed {
                entry.1 = entry.1.saturating_add(1);
            }
            entry.2 = entry.2.max(v.visit_time_unix);
            entry.3 = entry.3.saturating_add(v.dwell_time_ms);
        }

        self.urls.retain(|id, rec| {
            if let Some(&(vc, tc, last_ts, dwell)) = agg.get(id) {
                rec.visit_count = vc;
                rec.typed_count = tc;
                rec.last_visit_unix = last_ts;
                rec.total_dwell_ms = dwell;
                true
            } else {
                false
            }
        });
        self.url_to_id.retain(|_, id| self.urls.contains_key(id));
    }

    // ------------------------------------------------------------------------
    // Local Analytics (`compute_visit_stats`)
    // ------------------------------------------------------------------------

    /// Computes local visit statistics over the past `range_days` days using current system UTC time.
    pub fn compute_visit_stats(&self, range_days: u32) -> HistoryVisitStats {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.compute_visit_stats_at(range_days, now)
    }

    /// Deterministic variant of `compute_visit_stats` taking an explicit reference Unix timestamp.
    pub fn compute_visit_stats_at(&self, range_days: u32, now_unix: u64) -> HistoryVisitStats {
        let days = range_days.max(1);
        let since_unix = now_unix.saturating_sub((days as u64) * 86_400);

        let mut total_visits = 0usize;
        let mut unique_urls: HashSet<u64> = HashSet::new();
        let mut total_dwell_ms = 0u64;
        let mut hourly_distribution = [0usize; 24];
        let mut domain_agg: HashMap<String, (usize, HashSet<u64>, u64)> = HashMap::new();
        let mut daily_agg: BTreeMap<String, (usize, u64)> = BTreeMap::new();

        for v in &self.visits {
            if v.visit_time_unix < since_unix || v.visit_time_unix > now_unix + 86_400 {
                continue;
            }
            let Some(u) = self.urls.get(&v.url_id) else {
                continue;
            };
            total_visits += 1;
            unique_urls.insert(u.id);
            total_dwell_ms = total_dwell_ms.saturating_add(v.dwell_time_ms);

            let (year, month, day, hour, _, _) = unix_to_utc_parts(v.visit_time_unix as i64);
            hourly_distribution[(hour as usize).min(23)] += 1;

            let date_key = format!("{:04}-{:02}-{:02}", year, month, day);
            let day_entry = daily_agg.entry(date_key).or_insert((0, 0));
            day_entry.0 += 1;
            day_entry.1 = day_entry.1.saturating_add(v.dwell_time_ms);

            if !u.domain.is_empty() {
                let dom_entry = domain_agg
                    .entry(u.domain.clone())
                    .or_insert_with(|| (0, HashSet::new(), 0));
                dom_entry.0 += 1;
                dom_entry.1.insert(u.id);
                dom_entry.2 = dom_entry.2.saturating_add(v.dwell_time_ms);
            }
        }

        let unique_domains = domain_agg.len();
        let mut top_domains: Vec<DomainVisitStat> = domain_agg
            .into_iter()
            .map(|(domain, (vc, u_set, dwell))| DomainVisitStat {
                domain,
                visit_count: vc,
                unique_urls: u_set.len(),
                total_dwell_ms: dwell,
            })
            .collect();
        top_domains.sort_by(|a, b| {
            b.visit_count
                .cmp(&a.visit_count)
                .then_with(|| b.total_dwell_ms.cmp(&a.total_dwell_ms))
                .then_with(|| a.domain.cmp(&b.domain))
        });
        top_domains.truncate(15);

        let daily_volume: Vec<DailyVisitStat> = daily_agg
            .into_iter()
            .map(|(date, (vc, dwell))| DailyVisitStat {
                date,
                visit_count: vc,
                total_dwell_ms: dwell,
            })
            .collect();

        HistoryVisitStats {
            range_days: days,
            total_visits,
            unique_urls: unique_urls.len(),
            unique_domains,
            total_dwell_ms,
            top_domains,
            hourly_distribution,
            daily_volume,
        }
    }

    // ------------------------------------------------------------------------
    // Export JSON & CSV
    // ------------------------------------------------------------------------

    pub fn export_json(&self) -> Result<String, HistoryStoreError> {
        let mut joined: Vec<HistoryQueryItem> = self
            .visits
            .iter()
            .filter_map(|v| {
                let u = self.urls.get(&v.url_id)?;
                Some(HistoryQueryItem {
                    visit_id: v.id,
                    url_id: u.id,
                    url: u.url.clone(),
                    title: u.title.clone(),
                    domain: u.domain.clone(),
                    visit_time_unix: v.visit_time_unix,
                    transition_type: v.transition_type,
                    referrer_visit_id: v.referrer_visit_id,
                    dwell_time_ms: v.dwell_time_ms,
                    search_query: v.search_query.clone(),
                    visit_count: u.visit_count,
                    typed_count: u.typed_count,
                    favicon_url: u.favicon_url.clone(),
                    match_score: 0,
                })
            })
            .collect();
        joined.sort_by(|a, b| b.visit_time_unix.cmp(&a.visit_time_unix));
        Ok(serde_json::to_string_pretty(&joined)?)
    }

    pub fn export_csv(&self) -> String {
        let mut out = String::from(
            "visit_id,url_id,visit_time_unix,visit_time_iso,url,title,domain,transition_type,dwell_time_ms,search_query\n",
        );
        let mut visits_sorted: Vec<&HistoryVisitRecord> = self.visits.iter().collect();
        visits_sorted.sort_by(|a, b| b.visit_time_unix.cmp(&a.visit_time_unix));

        for v in visits_sorted {
            let Some(u) = self.urls.get(&v.url_id) else {
                continue;
            };
            let (y, m, d, hh, mm, ss) = unix_to_utc_parts(v.visit_time_unix as i64);
            let iso = format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, m, d, hh, mm, ss);
            out.push_str(&format!(
                "{},{},{},{},{},{},{},{},{},{}\n",
                v.id,
                u.id,
                v.visit_time_unix,
                iso,
                csv_escape(&u.url),
                csv_escape(&u.title),
                csv_escape(&u.domain),
                v.transition_type.as_str(),
                v.dwell_time_ms,
                csv_escape(v.search_query.as_deref().unwrap_or("")),
            ));
        }
        out
    }
}

// ============================================================================
// Internal Helpers (Query Parser, Date Parsing, Keywords, Atomic Persistence)
// ============================================================================

#[derive(Debug, Default)]
struct ParsedHistoryQuery {
    site: Option<String>,
    before_unix: Option<u64>,
    after_unix: Option<u64>,
    transition_type: Option<VisitTransitionType>,
    terms: Vec<String>,
}

fn parse_history_query(raw: &str) -> ParsedHistoryQuery {
    let mut parsed = ParsedHistoryQuery::default();
    for tok in raw.split_whitespace() {
        let lower = tok.to_ascii_lowercase();
        if let Some(site) = lower.strip_prefix("site:") {
            let cleaned = site.trim().trim_start_matches('.').to_string();
            if !cleaned.is_empty() {
                parsed.site = Some(cleaned);
            }
        } else if let Some(val) = lower.strip_prefix("before:") {
            if let Some(ts) = parse_date_or_unix(val, true) {
                parsed.before_unix = Some(ts);
            }
        } else if let Some(val) = lower.strip_prefix("after:") {
            if let Some(ts) = parse_date_or_unix(val, false) {
                parsed.after_unix = Some(ts);
            }
        } else if let Some(val) = lower.strip_prefix("type:") {
            if let Some(tt) = VisitTransitionType::from_filter_token(val) {
                parsed.transition_type = Some(tt);
            }
        } else if !tok.is_empty() {
            parsed.terms.push(tok.to_string());
        }
    }
    parsed
}

/// Parses either a raw Unix timestamp or `YYYY-MM-DD` (end-of-day if `end_of_day == true`).
fn parse_date_or_unix(raw: &str, end_of_day: bool) -> Option<u64> {
    let t = raw.trim();
    if let Ok(ts) = t.parse::<u64>() {
        return Some(ts);
    }
    let parts: Vec<&str> = t.split('-').collect();
    if parts.len() == 3 {
        let y: i64 = parts[0].parse().ok()?;
        let m: u32 = parts[1].parse().ok()?;
        let d: u32 = parts[2].parse().ok()?;
        if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
            return None;
        }
        let days = days_from_civil(y, m, d);
        if days < 0 {
            return None;
        }
        let base = (days as u64) * 86_400;
        return Some(if end_of_day { base + 86_399 } else { base });
    }
    None
}

/// Howard Hinnant's civil-to-days algorithm (days since 1970-01-01).
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = year - if month <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let m = month as u64;
    let d = day as u64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + (doe as i64) - 719_468
}

fn unix_to_utc_parts(secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400) as u32;
    let hour = sod / 3600;
    let minute = (sod % 3600) / 60;
    let second = sod % 60;

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let year = y + if m <= 2 { 1 } else { 0 };
    (year, m, d, hour, minute, second)
}

fn extract_domain(url: &str) -> String {
    let after = url
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(url);
    let authority = after.split(['/', '?', '#']).next().unwrap_or("");
    let host_port = authority
        .rsplit_once('@')
        .map(|(_, hp)| hp)
        .unwrap_or(authority);
    let host = if host_port.starts_with('[') {
        host_port
            .find(']')
            .map(|e| &host_port[..=e])
            .unwrap_or(host_port)
    } else {
        host_port.split(':').next().unwrap_or(host_port)
    };
    host.trim_start_matches("www.").to_ascii_lowercase()
}

fn infer_search_query_from_url(url: &str) -> Option<String> {
    let (_, query_part) = url.split_once('?')?;
    let query_no_hash = query_part.split('#').next().unwrap_or(query_part);
    for pair in query_no_hash.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if matches!(k, "q" | "query" | "search_query" | "search" | "text" | "k") {
                let decoded = percent_decode_plus(v);
                let trimmed = decoded.trim();
                if !trimmed.is_empty() && trimmed.len() <= 200 {
                    return Some(trimmed.to_string());
                }
            }
        }
    }
    None
}

fn percent_decode_plus(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
        } else if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(val) = u8::from_str_radix(&raw[i + 1..i + 3], 16) {
                out.push(val);
                i += 3;
                continue;
            }
            out.push(bytes[i]);
            i += 1;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn simple_fuzzy_score(pattern: &str, text: &str) -> Option<i64> {
    let pat: Vec<char> = pattern.chars().flat_map(|c| c.to_lowercase()).collect();
    if pat.is_empty() {
        return Some(0);
    }
    let hay: Vec<char> = text.chars().flat_map(|c| c.to_lowercase()).collect();
    if pat.len() > hay.len() {
        return None;
    }

    // Fast exact substring boost
    let pat_str: String = pat.iter().collect();
    let hay_str: String = hay.iter().collect();
    if let Some(pos) = hay_str.find(&pat_str) {
        let bonus = if pos == 0 { 120 } else { 85 };
        return Some(bonus + (pat.len() as i64) * 15);
    }

    // Ordered fuzzy subsequence match
    let mut pi = 0usize;
    let mut score = 0i64;
    let mut prev_match: Option<usize> = None;
    for (hi, &ch) in hay.iter().enumerate() {
        if ch == pat[pi] {
            score += 12;
            if let Some(pm) = prev_match {
                if hi == pm + 1 {
                    score += 16;
                } else {
                    score -= ((hi - pm - 1) as i64).min(12);
                }
            } else if hi == 0 {
                score += 24;
            }
            prev_match = Some(hi);
            pi += 1;
            if pi == pat.len() {
                return Some(score);
            }
        }
    }
    None
}

fn extract_keywords(text: &str) -> HashSet<String> {
    const STOP_WORDS: &[&str] = &[
        "the", "and", "for", "with", "from", "that", "this", "your", "have", "about", "into",
        "home", "page", "search", "results", "www", "http", "https", "com", "org", "net",
        "les", "des", "une", "pour", "dans", "avec", "sur", "par", "plus", "vous", "nous",
        "qui", "que", "est", "sont", "aux", "accueil", "recherche",
    ];
    let mut out = HashSet::new();
    for word in text.split(|c: char| !c.is_alphanumeric()) {
        let lower = word.to_lowercase();
        if lower.chars().count() >= 3 && !STOP_WORDS.contains(&lower.as_str()) {
            out.insert(lower);
        }
    }
    out
}

fn capitalize_words(s: &str) -> String {
    s.split_whitespace()
        .map(|w| {
            let mut chars = w.chars();
            match chars.next() {
                Some(first) => format!("{}{}", first.to_uppercase(), chars.as_str()),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn csv_escape(field: &str) -> String {
    if field.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}

fn backup_path_for(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_default();
    name.push(".bak");
    path.with_file_name(name)
}

fn atomic_write_with_backup(path: &Path, data: &[u8]) -> Result<(), std::io::Error> {
    let mut tmp_name = path
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_default();
    tmp_name.push(".tmp");
    let tmp_path = path.with_file_name(tmp_name);
    let bak_path = backup_path_for(path);

    {
        let mut f = std::fs::File::create(&tmp_path)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    if path.exists() {
        let _ = std::fs::copy(path, &bak_path);
    }
    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_test_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "singularity_hist_test_{}_{}",
            tag,
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_high_capacity_storage_and_atomic_bak_recovery() {
        let mut store = HistoryStore::new(50_000);
        // Verify well beyond the old 400 cap
        for i in 0..1_200u64 {
            let ts = 1_700_000_000 + i * 10;
            store.record_visit(
                &format!("https://example.org/article/{}", i),
                &format!("Article {}", i),
                VisitTransitionType::Link,
                None,
                None,
                None,
                ts,
            );
        }
        assert_eq!(store.visit_count(), 1_200);
        assert_eq!(store.url_count(), 1_200);

        let dir = temp_test_dir("atomic");
        let path = store.save_to_dir(&dir).expect("first save");
        // Second save creates .bak
        store.save_to_dir(&dir).expect("second save");
        assert!(backup_path_for(&path).exists());

        // Corrupt primary file and ensure automatic fallback to .bak
        std::fs::write(&path, b"{corrupt json!!!").unwrap();
        let recovered = HistoryStore::load_from_dir(&dir).expect("recover from .bak");
        assert_eq!(recovered.visit_count(), 1_200);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_query_operators_and_virtualized_pagination() {
        let mut store = HistoryStore::default();
        // 2026-01-10T12:00:00Z = 1768046400
        let day1 = parse_date_or_unix("2026-01-10", false).unwrap() + 3600;
        let day2 = parse_date_or_unix("2026-01-20", false).unwrap() + 3600;

        store.record_visit(
            "https://docs.rust-lang.org/book/ch04.html",
            "Understanding Ownership - Rust Book",
            VisitTransitionType::Typed,
            None,
            None,
            None,
            day1,
        );
        store.record_visit(
            "https://crates.io/crates/serde",
            "serde - crates.io",
            VisitTransitionType::Link,
            None,
            None,
            None,
            day2,
        );
        store.record_visit(
            "https://doc.rust-lang.org/std/vec/struct.Vec.html",
            "Vec in std::vec - Rust",
            VisitTransitionType::Typed,
            None,
            None,
            None,
            day2 + 120,
        );

        let page = store.query(&HistoryQueryParams {
            query: "site:rust-lang.org type:typed after:2026-01-15".into(),
            offset: 0,
            limit: 10,
            ..Default::default()
        });
        assert_eq!(page.total_matches, 1);
        assert!(page.items[0].title.contains("Vec"));

        // Pagination check
        let p1 = store.query(&HistoryQueryParams {
            offset: 0,
            limit: 2,
            ..Default::default()
        });
        assert_eq!(p1.items.len(), 2);
        assert!(p1.has_more);
        let p2 = store.query(&HistoryQueryParams {
            offset: 2,
            limit: 2,
            ..Default::default()
        });
        assert_eq!(p2.items.len(), 1);
        assert!(!p2.has_more);
    }

    #[test]
    fn test_chrome_journeys_clustering() {
        let mut store = HistoryStore::default();
        let t0 = 1_750_000_000u64;

        // Cluster 1: Rust async research linked via referrer & keywords within 45 min
        let v1 = store
            .record_visit(
                "https://duckduckgo.com/?q=rust+tokio+runtime",
                "rust tokio runtime at DuckDuckGo",
                VisitTransitionType::Generated,
                None,
                None,
                None,
                t0,
            )
            .unwrap();
        let v2 = store
            .record_visit(
                "https://tokio.rs/tokio/tutorial",
                "Tokio Rust Async Runtime Tutorial",
                VisitTransitionType::Link,
                Some(v1),
                None,
                None,
                t0 + 60,
            )
            .unwrap();
        store.add_dwell_time(v2, 95_000);
        store.record_visit(
            "https://docs.rs/tokio/latest/tokio/",
            "tokio runtime docs",
            VisitTransitionType::Link,
            None,
            None,
            None,
            t0 + 600,
        );

        // Cluster 2: Unrelated cooking session 3 hours later
        let t1 = t0 + 3 * 3600;
        store.record_visit(
            "https://marmiton.org/recettes/tarte-pommes",
            "Recette Tarte aux Pommes Classique",
            VisitTransitionType::Link,
            None,
            None,
            None,
            t1,
        );

        let journeys = store.build_history_journeys(10);
        assert_eq!(journeys.len(), 2);
        // Most recent journey first
        assert_eq!(journeys[0].primary_domain, "marmiton.org");
        assert_eq!(journeys[1].visit_count, 3);
        assert_eq!(journeys[1].title, "rust tokio runtime");
        assert_eq!(journeys[1].total_dwell_ms, 95_000);
    }

    #[test]
    fn test_granular_deletion_retention_stats_and_exports() {
        let mut store = HistoryStore::default();
        store.retention.excluded_domains.push("bank.secret.test".into());
        store.retention.max_age_days = Some(30);

        let now = 1_760_000_000u64;
        // Excluded domain should be dropped on record
        assert!(store
            .record_visit(
                "https://login.bank.secret.test/account",
                "Bank",
                VisitTransitionType::Typed,
                None,
                None,
                None,
                now
            )
            .is_none());

        // Old visit (>30 days)
        store.record_visit(
            "https://old.example.com/page",
            "Old Page",
            VisitTransitionType::Link,
            None,
            None,
            None,
            now - 45 * 86_400,
        );
        // Recent visits
        let v_a = store
            .record_visit(
                "https://github.com/MyMasha/Singularity",
                "Singularity Repo",
                VisitTransitionType::Typed,
                None,
                None,
                None,
                now - 3600,
            )
            .unwrap();
        store.add_dwell_time(v_a, 120_000);
        let v_b = store
            .record_visit(
                "https://news.ycombinator.com/",
                "Hacker News",
                VisitTransitionType::Link,
                None,
                None,
                None,
                now - 1800,
            )
            .unwrap();

        let purged = store.enforce_retention(now);
        assert_eq!(purged, 1);
        assert_eq!(store.visit_count(), 2);

        let stats = store.compute_visit_stats_at(7, now);
        assert_eq!(stats.total_visits, 2);
        assert_eq!(stats.total_dwell_ms, 120_000);
        assert_eq!(stats.top_domains.len(), 2);
        assert_eq!(stats.hourly_distribution.iter().sum::<usize>(), 2);

        let json = store.export_json().expect("export json");
        assert!(json.contains("Singularity Repo"));
        let csv = store.export_csv();
        assert!(csv.starts_with("visit_id,url_id,"));
        assert!(csv.contains("github.com"));

        // Granular deletions
        assert_eq!(store.delete_visits(&[v_b]), 1);
        assert_eq!(store.delete_domain("github.com"), 1);
        assert_eq!(store.visit_count(), 0);
        assert_eq!(store.url_count(), 0);
    }

    #[test]
    fn test_delete_time_range_before_operator_and_clear_all() {
        let mut store = HistoryStore::default();
        let t1 = parse_date_or_unix("2026-02-01", false).unwrap() + 100;
        let t2 = parse_date_or_unix("2026-02-10", false).unwrap() + 100;
        let t3 = parse_date_or_unix("2026-02-20", false).unwrap() + 100;

        store.record_visit("https://a.test/1", "One", VisitTransitionType::Link, None, None, None, t1);
        store.record_visit("https://a.test/1", "One", VisitTransitionType::Reload, None, None, None, t2);
        store.record_visit("https://b.test/2", "Two", VisitTransitionType::Typed, None, None, None, t3);

        let before_page = store.query(&HistoryQueryParams {
            query: "before:2026-02-12".into(),
            deduplicate_urls: true,
            ..Default::default()
        });
        assert_eq!(before_page.total_matches, 1);

        assert_eq!(store.delete_time_range(t1, t2), 2);
        assert_eq!(store.visit_count(), 1);
        assert_eq!(store.url_count(), 1);

        store.clear_all();
        assert_eq!(store.visit_count(), 0);
        assert_eq!(store.url_count(), 0);
    }
}
