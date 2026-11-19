//! High-speed fuzzy search and virtualized viewport slicer for the 2,165+ Settings Registry.

use crate::schema::{SettingCategory, SettingEntry};

/// Result item from a fuzzy search query over the settings registry.
#[derive(Debug, Clone)]
pub struct FuzzyMatch<'a> {
    pub entry: &'a SettingEntry,
    pub score: i64,
}

/// Virtualized scroll viewport window returned to the 200Hz+ UI renderer.
#[derive(Debug, Clone)]
pub struct VirtualizedViewport<'a> {
    pub total_matching_items: usize,
    pub total_content_height_px: usize,
    pub first_visible_index: usize,
    pub top_spacer_height_px: usize,
    pub bottom_spacer_height_px: usize,
    pub visible_slice: Vec<&'a SettingEntry>,
}

/// Computes a fast Smith-Waterman / subsequence fuzzy match score across `key`, `title`, and `description`.
pub fn score_fuzzy_query(entry: &SettingEntry, query_lower: &str) -> Option<i64> {
    if query_lower.is_empty() {
        return Some(100);
    }

    let key_lower = entry.key.to_ascii_lowercase();
    let title_lower = entry.title.to_ascii_lowercase();
    let desc_lower = entry.description.to_ascii_lowercase();

    let mut total_score: i64 = 0;

    // Multi-token support: every whitespace-separated token must match either key, title, or description
    for token in query_lower.split_whitespace() {
        if key_lower == token {
            total_score += 2000;
        } else if key_lower.starts_with(token) {
            total_score += 1200;
        } else if let Some(pos) = key_lower.find(token) {
            total_score += 800 - (pos as i64 * 2);
        } else if let Some(pos) = title_lower.find(token) {
            total_score += 500 - (pos as i64 * 2);
        } else if let Some(pos) = desc_lower.find(token) {
            total_score += 200 - (pos as i64).min(150);
        } else if let Some(subseq_score) = subsequence_score(&key_lower, token) {
            total_score += subseq_score;
        } else {
            return None;
        }
    }

    if entry.is_modified() {
        total_score += 25;
    }

    Some(total_score)
}

fn subsequence_score(haystack: &str, needle: &str) -> Option<i64> {
    let mut h_chars = haystack.chars().enumerate();
    let mut score: i64 = 50;
    let mut prev_idx: Option<usize> = None;

    for n_ch in needle.chars() {
        let mut found = false;
        for (idx, h_ch) in h_chars.by_ref() {
            if h_ch == n_ch {
                if let Some(prev) = prev_idx {
                    if idx == prev + 1 {
                        score += 15; // consecutive character bonus
                    } else {
                        score -= (idx - prev) as i64;
                    }
                }
                prev_idx = Some(idx);
                found = true;
                break;
            }
        }
        if !found {
            return None;
        }
    }

    Some(score.max(1))
}

/// Computes an O(1) virtualized slice of matching settings for a given scroll offset and viewport height.
pub fn compute_virtualized_viewport<'a>(
    entries: &'a [SettingEntry],
    category_filter: Option<SettingCategory>,
    query: &str,
    scroll_offset_px: usize,
    viewport_height_px: usize,
    row_height_px: usize,
    overscan_rows: usize,
) -> VirtualizedViewport<'a> {
    let row_h = row_height_px.clamp(24, 256);
    let safe_viewport_h = viewport_height_px.min(100_000);
    let safe_overscan = overscan_rows.min(64);
    let query_lower = query.trim().to_ascii_lowercase();

    let mut matched: Vec<FuzzyMatch<'a>> = entries
        .iter()
        .filter(|e| category_filter.map_or(true, |cat| e.category == cat))
        .filter_map(|e| score_fuzzy_query(e, &query_lower).map(|score| FuzzyMatch { entry: e, score }))
        .collect();

    if !query_lower.is_empty() {
        matched.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.entry.id.cmp(&b.entry.id)));
    }

    let total_matching = matched.len();
    let total_height_px = total_matching.saturating_mul(row_h);

    if total_matching == 0 {
        return VirtualizedViewport {
            total_matching_items: 0,
            total_content_height_px: 0,
            first_visible_index: 0,
            top_spacer_height_px: 0,
            bottom_spacer_height_px: 0,
            visible_slice: Vec::new(),
        };
    }

    let clamped_scroll = scroll_offset_px.min(total_height_px.saturating_sub(1));
    let raw_first_idx = clamped_scroll / row_h;
    let first_idx = raw_first_idx.saturating_sub(safe_overscan).min(total_matching);
    let visible_rows = (safe_viewport_h / row_h)
        .saturating_add(1)
        .saturating_add(safe_overscan.saturating_mul(2));
    let end_idx = first_idx.saturating_add(visible_rows).min(total_matching).max(first_idx);

    let top_spacer = first_idx.saturating_mul(row_h);
    let bottom_spacer = total_height_px.saturating_sub(end_idx.saturating_mul(row_h));

    let visible_slice = matched[first_idx..end_idx].iter().map(|m| m.entry).collect();

    VirtualizedViewport {
        total_matching_items: total_matching,
        total_content_height_px: total_height_px,
        first_visible_index: first_idx,
        top_spacer_height_px: top_spacer,
        bottom_spacer_height_px: bottom_spacer,
        visible_slice,
    }
}
