//! Automatic Tab Organizer: eTLD+1 Domain Auto-Grouping, Glob URL Grouping Rules,
//! Normalized Duplicate Tab Detection, and Domain Clustering.

use crate::blocker::{extract_etld_plus_one, normalize_host, UBlockNetworkEngine};
use crate::tabs::{wildcard_match, BrowserTab, TabLifecycleState};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

/// Visual color token assigned to an automatic or user-defined tab group.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TabGroupColor {
    Cyan,
    Blue,
    Purple,
    Pink,
    Red,
    Orange,
    Yellow,
    Green,
    Grey,
    Custom(String),
}

impl TabGroupColor {
    /// Picks a deterministic vibrant color from a domain/group key.
    pub fn from_key(key: &str) -> Self {
        const PALETTE: [TabGroupColor; 8] = [
            TabGroupColor::Cyan,
            TabGroupColor::Blue,
            TabGroupColor::Purple,
            TabGroupColor::Pink,
            TabGroupColor::Orange,
            TabGroupColor::Green,
            TabGroupColor::Yellow,
            TabGroupColor::Red,
        ];
        let mut hash: u64 = 14695981039346656037;
        for b in key.as_bytes() {
            hash ^= u64::from(*b);
            hash = hash.wrapping_mul(1099511628211);
        }
        PALETTE[(hash as usize) % PALETTE.len()].clone()
    }
}

/// Glob / URL-pattern rule mapping matching tabs into a named, colored group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutoGroupRule {
    pub id: String,
    pub pattern: String,
    pub group_name: String,
    pub color: TabGroupColor,
    pub enabled: bool,
}

impl AutoGroupRule {
    pub fn new(
        id: impl Into<String>,
        pattern: impl Into<String>,
        group_name: impl Into<String>,
        color: TabGroupColor,
    ) -> Self {
        Self {
            id: id.into(),
            pattern: pattern.into(),
            group_name: group_name.into(),
            color,
            enabled: true,
        }
    }

    /// Evaluates whether `url` (or its host) matches this rule's glob/wildcard pattern.
    pub fn matches_url(&self, url: &str) -> bool {
        if !self.enabled {
            return false;
        }
        let pat = self.pattern.trim().to_ascii_lowercase();
        if pat.is_empty() {
            return false;
        }
        let url_lower = url.trim().to_ascii_lowercase();
        let host_lower = normalize_host(&url_lower);

        if pat.contains("://") || pat.contains('/') {
            glob_matches(&pat, &url_lower)
        } else if let Some(suffix) = pat.strip_prefix("*.") {
            host_lower == suffix || host_lower.ends_with(&format!(".{}", suffix))
        } else if pat.contains('*') || pat.contains('?') {
            glob_matches(&pat, &host_lower) || glob_matches(&pat, &url_lower)
        } else {
            host_lower == pat || host_lower.ends_with(&format!(".{}", pat))
        }
    }
}

/// Suggested tab group computed by domain clustering or custom [`AutoGroupRule`] matching.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuggestedTabGroup {
    pub group_key: String,
    pub title: String,
    pub color: TabGroupColor,
    pub tab_ids: Vec<u64>,
    pub matched_rule_id: Option<String>,
}

/// Cluster of tabs pointing to the same canonical normalized URL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DuplicateTabCluster {
    pub normalized_url: String,
    pub canonical_tab_id: u64,
    pub duplicate_tab_ids: Vec<u64>,
}

/// Evaluates a glob pattern supporting `*` and `?` wildcards (case-insensitive).
pub fn glob_matches(pattern: &str, text: &str) -> bool {
    wildcard_match(&pattern.to_ascii_lowercase(), &text.to_ascii_lowercase())
}

/// Produces a canonical URL representation for duplicate-tab detection:
/// - Strips tracking query parameters via ClearURLs
/// - Lowercases scheme and hostname
/// - Strips default ports (`:80` for http, `:443` for https)
/// - Strips fragment (`#...`)
/// - Normalizes trailing path slash (preserving root `/`)
/// - Sorts remaining query parameters deterministically
pub fn normalize_url_for_dedup(raw_url: &str) -> String {
    let scrubbed = UBlockNetworkEngine::scrub_tracking_query_params(raw_url.trim());
    let without_frag = scrubbed.split('#').next().unwrap_or(&scrubbed).trim();
    if without_frag.is_empty() {
        return String::new();
    }

    let (scheme, rest) = match without_frag.split_once("://") {
        Some((s, r)) => (s.to_ascii_lowercase(), r),
        None => return without_frag.to_ascii_lowercase(),
    };

    let (authority_raw, path_and_query) = match rest.find(['/', '?']) {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, ""),
    };

    let authority_lower = authority_raw.to_ascii_lowercase();
    let authority = match (scheme.as_str(), authority_lower.rsplit_once(':')) {
        ("http", Some((host, "80"))) | ("https", Some((host, "443"))) => {
            host.trim_end_matches('.').to_string()
        }
        _ => authority_lower.trim_end_matches('.').to_string(),
    };

    let (path_raw, query_opt) = match path_and_query.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (path_and_query, None),
    };

    let normalized_path = if path_raw.is_empty() || path_raw == "/" {
        "/".to_string()
    } else {
        path_raw.trim_end_matches('/').to_string()
    };

    let mut out = format!("{}://{}{}", scheme, authority, normalized_path);
    if let Some(q) = query_opt {
        let mut pairs: Vec<&str> = q.split('&').filter(|p| !p.is_empty()).collect();
        pairs.sort_unstable();
        if !pairs.is_empty() {
            out.push('?');
            out.push_str(&pairs.join("&"));
        }
    }
    out
}

fn tab_etld(tab: &BrowserTab) -> String {
    let from_url = extract_etld_plus_one(&tab.url);
    if !from_url.is_empty() {
        from_url
    } else {
        extract_etld_plus_one(&tab.first_party_etld)
    }
}

/// Groups all tabs into an ordered map keyed by registrable domain (`eTLD+1`).
pub fn group_tabs_by_domain(tabs: &[BrowserTab]) -> BTreeMap<String, Vec<u64>> {
    let mut grouped: BTreeMap<String, Vec<u64>> = BTreeMap::new();
    for tab in tabs {
        let key = tab_etld(tab);
        if key.is_empty() {
            continue;
        }
        grouped.entry(key).or_default().push(tab.tab_id);
    }
    grouped
}

/// Suggests automatic tab groups by `eTLD+1` for domains with at least `min_tabs_per_group` tabs.
pub fn suggest_domain_groups(
    tabs: &[BrowserTab],
    min_tabs_per_group: usize,
) -> Vec<SuggestedTabGroup> {
    let threshold = min_tabs_per_group.max(1);
    let grouped = group_tabs_by_domain(tabs);
    let mut suggestions: Vec<SuggestedTabGroup> = grouped
        .into_iter()
        .filter(|(_, ids)| ids.len() >= threshold)
        .map(|(etld, tab_ids)| SuggestedTabGroup {
            color: TabGroupColor::from_key(&etld),
            title: etld.clone(),
            group_key: etld,
            tab_ids,
            matched_rule_id: None,
        })
        .collect();

    suggestions.sort_by(|a, b| {
        b.tab_ids
            .len()
            .cmp(&a.tab_ids.len())
            .then_with(|| a.title.cmp(&b.title))
    });
    suggestions
}

/// Detects duplicate open tabs after canonical URL normalization.
/// Preserves the foreground active tab (or pinned / oldest tab) as `canonical_tab_id`.
pub fn find_duplicate_tabs(tabs: &[BrowserTab]) -> Vec<DuplicateTabCluster> {
    let mut buckets: HashMap<String, Vec<&BrowserTab>> = HashMap::new();
    for tab in tabs {
        let norm = normalize_url_for_dedup(&tab.url);
        if norm.is_empty() {
            continue;
        }
        buckets.entry(norm).or_default().push(tab);
    }

    let mut clusters = Vec::new();
    for (normalized_url, mut members) in buckets {
        if members.len() < 2 {
            continue;
        }
        // Rank best tab to keep: ActiveForeground > Pinned > lowest tab_id
        members.sort_by_key(|t| {
            let active_rank = if matches!(t.lifecycle, TabLifecycleState::ActiveForeground) {
                0u8
            } else {
                1u8
            };
            let pinned_rank = if t.pinned { 0u8 } else { 1u8 };
            (active_rank, pinned_rank, t.tab_id)
        });
        let canonical_tab_id = members[0].tab_id;
        let duplicate_tab_ids = members[1..].iter().map(|t| t.tab_id).collect();
        clusters.push(DuplicateTabCluster {
            normalized_url,
            canonical_tab_id,
            duplicate_tab_ids,
        });
    }
    clusters.sort_by(|a, b| a.canonical_tab_id.cmp(&b.canonical_tab_id));
    clusters
}

/// Stateful organizer combining custom [`AutoGroupRule`]s, `eTLD+1` auto-grouping,
/// and duplicate tab detection.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TabOrganizer {
    rules: Vec<AutoGroupRule>,
}

impl TabOrganizer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_rule(&mut self, rule: AutoGroupRule) {
        if let Some(pos) = self.rules.iter().position(|r| r.id == rule.id) {
            self.rules[pos] = rule;
        } else {
            self.rules.push(rule);
        }
    }

    pub fn remove_rule(&mut self, rule_id: &str) -> bool {
        let before = self.rules.len();
        self.rules.retain(|r| r.id != rule_id);
        self.rules.len() != before
    }

    pub fn rules(&self) -> &[AutoGroupRule] {
        &self.rules
    }

    /// Evaluates custom [`AutoGroupRule`]s first, then groups remaining tabs by `eTLD+1`.
    pub fn suggest_groups(
        &self,
        tabs: &[BrowserTab],
        min_domain_group_size: usize,
    ) -> Vec<SuggestedTabGroup> {
        let mut rule_buckets: HashMap<String, (&AutoGroupRule, Vec<u64>)> = HashMap::new();
        let mut unmatched_tabs: Vec<BrowserTab> = Vec::new();

        for tab in tabs {
            if let Some(rule) = self.rules.iter().find(|r| r.matches_url(&tab.url)) {
                rule_buckets
                    .entry(rule.id.clone())
                    .or_insert_with(|| (rule, Vec::new()))
                    .1
                    .push(tab.tab_id);
            } else {
                unmatched_tabs.push(tab.clone());
            }
        }

        let mut results: Vec<SuggestedTabGroup> = rule_buckets
            .into_iter()
            .map(|(rule_id, (rule, tab_ids))| SuggestedTabGroup {
                group_key: format!("rule:{}", rule_id),
                title: rule.group_name.clone(),
                color: rule.color.clone(),
                tab_ids,
                matched_rule_id: Some(rule_id),
            })
            .collect();

        results.extend(suggest_domain_groups(&unmatched_tabs, min_domain_group_size));
        results.sort_by(|a, b| {
            b.matched_rule_id
                .is_some()
                .cmp(&a.matched_rule_id.is_some())
                .then_with(|| b.tab_ids.len().cmp(&a.tab_ids.len()))
                .then_with(|| a.title.cmp(&b.title))
        });
        results
    }

    pub fn find_duplicates(&self, tabs: &[BrowserTab]) -> Vec<DuplicateTabCluster> {
        find_duplicate_tabs(tabs)
    }

    pub fn group_by_domain(&self, tabs: &[BrowserTab]) -> BTreeMap<String, Vec<u64>> {
        group_tabs_by_domain(tabs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tab(id: u64, url: &str, etld: &str, active: bool) -> BrowserTab {
        BrowserTab {
            tab_id: id,
            title: format!("Tab {}", id),
            url: url.to_string(),
            first_party_etld: etld.to_string(),
            scroll_position_y_px: 0.0,
            playing_audio: false,
            pinned: false,
            mullvad_isolated_relay: None,
            lifecycle: if active {
                TabLifecycleState::ActiveForeground
            } else {
                TabLifecycleState::BackgroundWarm { idle_seconds: 10 }
            },
            view_handle_id: id,
        }
    }

    #[test]
    fn test_domain_grouping_custom_rules_and_duplicate_detection() {
        let tabs = vec![
            make_tab(1, "https://docs.github.com/en/actions", "github.com", false),
            make_tab(2, "https://github.com/MyMasha/Singularity", "github.com", false),
            make_tab(3, "https://shop.co.uk/item?b=2&a=1&utm_source=x#top", "shop.co.uk", false),
            make_tab(4, "https://SHOP.CO.UK:443/item/?a=1&b=2&fbclid=zzz", "shop.co.uk", true),
            make_tab(5, "https://api.rust-lang.org/std", "rust-lang.org", false),
            make_tab(6, "https://play.rust-lang.org/", "rust-lang.org", false),
        ];

        // Auto-group by eTLD+1
        let domain_groups = suggest_domain_groups(&tabs, 2);
        assert_eq!(domain_groups.len(), 3);
        assert!(domain_groups.iter().any(|g| g.group_key == "github.com" && g.tab_ids == vec![1, 2]));
        assert!(domain_groups.iter().any(|g| g.group_key == "shop.co.uk" && g.tab_ids == vec![3, 4]));
        assert!(domain_groups.iter().any(|g| g.group_key == "rust-lang.org" && g.tab_ids == vec![5, 6]));

        // Duplicate detection normalizes port, case, trailing slash, fragment, param order & tracking params
        let dups = find_duplicate_tabs(&tabs);
        assert_eq!(dups.len(), 1);
        assert_eq!(dups[0].canonical_tab_id, 4); // ActiveForeground wins!
        assert_eq!(dups[0].duplicate_tab_ids, vec![3]);

        // Custom AutoGroupRule matches glob URL patterns
        let mut organizer = TabOrganizer::new();
        organizer.add_rule(AutoGroupRule::new(
            "dev-rust",
            "*.rust-lang.org",
            "Rust Dev",
            TabGroupColor::Orange,
        ));
        let suggested = organizer.suggest_groups(&tabs, 2);
        let rust_group = suggested
            .iter()
            .find(|g| g.matched_rule_id.as_deref() == Some("dev-rust"))
            .expect("Rust rule matched");
        assert_eq!(rust_group.title, "Rust Dev");
        assert_eq!(rust_group.color, TabGroupColor::Orange);
        assert_eq!(rust_group.tab_ids, vec![5, 6]);
    }
}
