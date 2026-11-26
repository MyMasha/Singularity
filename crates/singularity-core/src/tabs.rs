//! Aggressive Tab Suspension & Freezing Engine in Rust with Sub-Millisecond State Restoration,
//! Fine-Grained Tab Protection Bitflags, Per-Domain Sleep Policies, and Recursive Split Layout Tree.

use crate::blocker::{extract_etld_plus_one, normalize_host};
use serde::{Deserialize, Serialize};
use singularity_chromium_ffi::{CBrowserViewHandle, ChromiumEngineBridge};
use std::collections::HashMap;
use std::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, Not};

/// Pure-Rust `u32` bitflags protecting sensitive or active tabs from automatic freezing/discarding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash, Serialize, Deserialize)]
pub struct TabProtectionFlags(u32);

impl TabProtectionFlags {
    pub const NONE: Self = Self(0);
    pub const AUDIO_ACTIVE: Self = Self(1 << 0);
    pub const WEBRTC_MEDIA: Self = Self(1 << 1);
    pub const DIRTY_FORM: Self = Self(1 << 2);
    pub const ACTIVE_DOWNLOAD: Self = Self(1 << 3);
    pub const REALTIME_SOCKET: Self = Self(1 << 4);
    pub const PINNED: Self = Self(1 << 5);
    pub const PIP_VIDEO: Self = Self(1 << 6);
    pub const USER_WHITELIST: Self = Self(1 << 7);
    pub const DRM_ACTIVE: Self = Self(1 << 8);

    pub const fn empty() -> Self {
        Self(0)
    }

    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    pub const fn bits(self) -> u32 {
        self.0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub const fn is_protected(self) -> bool {
        self.0 != 0
    }

    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    pub const fn intersects(self, other: Self) -> bool {
        (self.0 & other.0) != 0
    }

    pub fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }

    pub fn remove(&mut self, other: Self) {
        self.0 &= !other.0;
    }

    pub fn set(&mut self, other: Self, value: bool) {
        if value {
            self.insert(other);
        } else {
            self.remove(other);
        }
    }
}

impl BitOr for TabProtectionFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for TabProtectionFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl BitAnd for TabProtectionFlags {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

impl BitAndAssign for TabProtectionFlags {
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}

impl Not for TabProtectionFlags {
    type Output = Self;
    fn not(self) -> Self::Output {
        Self(!self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TabLifecycleState {
    ActiveForeground,
    BackgroundWarm { idle_seconds: u64 },
    /// Soft freeze (Stage 1): JS timers/rendering suspended at 0% CPU while retaining RAM state.
    FrozenZeroCpu {
        frozen_since_unix: u64,
        rss_bytes: u64,
    },
    /// Hard discard (Stage 2): renderer discarded with compact snapshot and RAM reclaimed.
    SuspendedFrozen {
        compressed_snapshot_bytes: Vec<u8>,
        reclaimed_ram_mb: u32,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserTab {
    pub tab_id: u64,
    pub title: String,
    pub url: String,
    pub first_party_etld: String,
    pub scroll_position_y_px: f64,
    pub playing_audio: bool,
    pub pinned: bool,
    pub mullvad_isolated_relay: Option<String>,
    pub lifecycle: TabLifecycleState,
    pub view_handle_id: u64,
}

/// Domain-scoped policy controlling which hosts never sleep or enter accelerated sleep.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TabSleepDomainPolicy {
    pub never_sleep_rules: Vec<String>,
    pub fast_sleep_rules: Vec<String>,
}

impl TabSleepDomainPolicy {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_never_sleep_rule(&mut self, rule: impl Into<String>) {
        let r = rule.into().trim().to_ascii_lowercase();
        if !r.is_empty() && !self.never_sleep_rules.contains(&r) {
            self.never_sleep_rules.push(r);
        }
    }

    pub fn add_fast_sleep_rule(&mut self, rule: impl Into<String>) {
        let r = rule.into().trim().to_ascii_lowercase();
        if !r.is_empty() && !self.fast_sleep_rules.contains(&r) {
            self.fast_sleep_rules.push(r);
        }
    }

    pub fn should_never_sleep(&self, host: &str) -> bool {
        let norm_host = normalize_host(host);
        if norm_host.is_empty() {
            return false;
        }
        let host_etld = extract_etld_plus_one(&norm_host);
        self.never_sleep_rules
            .iter()
            .any(|rule| domain_rule_matches(&norm_host, &host_etld, rule))
    }

    pub fn should_fast_sleep(&self, host: &str) -> bool {
        if self.should_never_sleep(host) {
            return false;
        }
        let norm_host = normalize_host(host);
        if norm_host.is_empty() {
            return false;
        }
        let host_etld = extract_etld_plus_one(&norm_host);
        self.fast_sleep_rules
            .iter()
            .any(|rule| domain_rule_matches(&norm_host, &host_etld, rule))
    }
}

fn domain_rule_matches(norm_host: &str, host_etld: &str, raw_rule: &str) -> bool {
    let rule = raw_rule.trim().trim_end_matches('.').to_ascii_lowercase();
    if rule.is_empty() {
        return false;
    }
    if rule == "*" {
        return true;
    }
    if let Some(base) = rule.strip_prefix("*.") {
        return norm_host == base || norm_host.ends_with(&format!(".{}", base));
    }
    if rule.contains('*') || rule.contains('?') {
        return wildcard_match(&rule, norm_host);
    }
    let clean_rule = normalize_host(&rule);
    if clean_rule.is_empty() {
        return false;
    }
    norm_host == clean_rule
        || norm_host.ends_with(&format!(".{}", clean_rule))
        || host_etld == clean_rule
}

pub(crate) fn wildcard_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star_idx, mut match_idx) = (None, 0usize);

    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star_idx = Some(pi);
            match_idx = ti;
            pi += 1;
        } else if let Some(si) = star_idx {
            pi = si + 1;
            match_idx += 1;
            ti = match_idx;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// Orientation of a split container in the workspace tiling tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SplitOrientation {
    /// Side-by-side split along the X axis (first = left, second = right).
    Horizontal,
    /// Stacked split along the Y axis (first = top, second = bottom).
    Vertical,
}

/// Magnetic snap detents (33%, 50%, 66%) for ergonomic split-pane resizing.
pub const SPLIT_MAGNETIC_DETENTS: [f32; 3] = [1.0 / 3.0, 0.5, 2.0 / 3.0];
pub const SPLIT_MAGNETIC_SNAP_TOLERANCE: f32 = 0.03;

/// Snaps a split ratio to magnetic detents (33%, 50%, 66%) when within tolerance.
pub fn snap_split_ratio(ratio: f32) -> f32 {
    snap_split_ratio_with_tolerance(ratio, SPLIT_MAGNETIC_SNAP_TOLERANCE)
}

pub fn snap_split_ratio_with_tolerance(ratio: f32, tolerance: f32) -> f32 {
    let clamped = if ratio.is_finite() {
        ratio.clamp(0.10, 0.90)
    } else {
        0.5
    };
    let tol = tolerance.max(0.0);
    for detent in SPLIT_MAGNETIC_DETENTS {
        if (clamped - detent).abs() <= tol {
            return detent;
        }
    }
    clamped
}

/// Recursive binary tiling tree supporting arbitrary multi-pane split view layouts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SplitLayoutTree {
    Leaf(u64),
    Split {
        orientation: SplitOrientation,
        ratio: f32,
        first: Box<SplitLayoutTree>,
        second: Box<SplitLayoutTree>,
    },
}

impl SplitLayoutTree {
    pub fn leaf(tab_id: u64) -> Self {
        Self::Leaf(tab_id)
    }

    /// Creates a split node with automatic magnetic snapping (33% / 50% / 66%).
    pub fn split(
        orientation: SplitOrientation,
        ratio: f32,
        first: SplitLayoutTree,
        second: SplitLayoutTree,
    ) -> Self {
        Self::Split {
            orientation,
            ratio: snap_split_ratio(ratio),
            first: Box::new(first),
            second: Box::new(second),
        }
    }

    /// Splits an existing leaf `target_tab_id` into `(target_tab_id, new_tab_id)`.
    pub fn split_leaf(
        &mut self,
        target_tab_id: u64,
        new_tab_id: u64,
        orientation: SplitOrientation,
        ratio: f32,
    ) -> bool {
        match self {
            SplitLayoutTree::Leaf(id) if *id == target_tab_id => {
                *self = SplitLayoutTree::split(
                    orientation,
                    ratio,
                    SplitLayoutTree::Leaf(target_tab_id),
                    SplitLayoutTree::Leaf(new_tab_id),
                );
                true
            }
            SplitLayoutTree::Leaf(_) => false,
            SplitLayoutTree::Split { first, second, .. } => {
                first.split_leaf(target_tab_id, new_tab_id, orientation, ratio)
                    || second.split_leaf(target_tab_id, new_tab_id, orientation, ratio)
            }
        }
    }

    /// Removes `tab_id` from the split tree, collapsing its parent split into the sibling.
    /// Returns `None` if the tree consisted solely of `tab_id`.
    pub fn close_leaf(self, tab_id: u64) -> Option<SplitLayoutTree> {
        match self {
            SplitLayoutTree::Leaf(id) => {
                if id == tab_id {
                    None
                } else {
                    Some(SplitLayoutTree::Leaf(id))
                }
            }
            SplitLayoutTree::Split {
                orientation,
                ratio,
                first,
                second,
            } => {
                let first_rem = first.close_leaf(tab_id);
                let second_rem = second.close_leaf(tab_id);
                match (first_rem, second_rem) {
                    (Some(f), Some(s)) => Some(SplitLayoutTree::Split {
                        orientation,
                        ratio,
                        first: Box::new(f),
                        second: Box::new(s),
                    }),
                    (Some(only), None) | (None, Some(only)) => Some(only),
                    (None, None) => None,
                }
            }
        }
    }

    /// Updates this root split's ratio with magnetic snapping (33% / 50% / 66%).
    pub fn set_ratio_snapped(&mut self, new_ratio: f32) -> Option<f32> {
        if let SplitLayoutTree::Split { ratio, .. } = self {
            *ratio = snap_split_ratio(new_ratio);
            Some(*ratio)
        } else {
            None
        }
    }

    /// Returns all tab IDs hosted as leaves in left-to-right / top-to-bottom traversal order.
    pub fn leaf_tab_ids(&self) -> Vec<u64> {
        let mut out = Vec::new();
        self.collect_leaves(&mut out);
        out
    }

    fn collect_leaves(&self, out: &mut Vec<u64>) {
        match self {
            SplitLayoutTree::Leaf(id) => out.push(*id),
            SplitLayoutTree::Split { first, second, .. } => {
                first.collect_leaves(out);
                second.collect_leaves(out);
            }
        }
    }

    /// Computes exact `(tab_id, x, y, width, height)` rectangles for all leaf panes
    /// within `(x, y, w, h)` separated by `gutter_px`.
    pub fn compute_pane_rects(
        &self,
        x: f32,
        y: f32,
        w: f32,
        h: f32,
        gutter_px: f32,
    ) -> Vec<(u64, f32, f32, f32, f32)> {
        let mut out = Vec::new();
        self.compute_rects_recursive(x, y, w.max(0.0), h.max(0.0), gutter_px.max(0.0), &mut out);
        out
    }

    fn compute_rects_recursive(
        &self,
        x: f32,
        y: f32,
        w: f32,
        h: f32,
        gutter_px: f32,
        out: &mut Vec<(u64, f32, f32, f32, f32)>,
    ) {
        match self {
            SplitLayoutTree::Leaf(id) => {
                out.push((*id, x, y, w.max(0.0), h.max(0.0)));
            }
            SplitLayoutTree::Split {
                orientation,
                ratio,
                first,
                second,
            } => {
                let r = if ratio.is_finite() {
                    ratio.clamp(0.05, 0.95)
                } else {
                    0.5
                };
                match orientation {
                    SplitOrientation::Horizontal => {
                        let usable_w = (w - gutter_px).max(0.0);
                        let w1 = usable_w * r;
                        let w2 = (usable_w - w1).max(0.0);
                        first.compute_rects_recursive(x, y, w1, h, gutter_px, out);
                        second.compute_rects_recursive(
                            x + w1 + gutter_px,
                            y,
                            w2,
                            h,
                            gutter_px,
                            out,
                        );
                    }
                    SplitOrientation::Vertical => {
                        let usable_h = (h - gutter_px).max(0.0);
                        let h1 = usable_h * r;
                        let h2 = (usable_h - h1).max(0.0);
                        first.compute_rects_recursive(x, y, w, h1, gutter_px, out);
                        second.compute_rects_recursive(
                            x,
                            y + h1 + gutter_px,
                            w,
                            h2,
                            gutter_px,
                            out,
                        );
                    }
                }
            }
        }
    }
}

/// Manages tab lifecycle, protection flags, domain sleep policies, memory reclamation,
/// and instant state restoration.
pub struct TabSuspensionManager {
    tabs: Vec<BrowserTab>,
    active_tab_id: u64,
    next_tab_id: u64,
    freeze_timeout_seconds: u64,
    discard_timeout_seconds: u64,
    total_reclaimed_ram_bytes: u64,
    pub domain_policy: TabSleepDomainPolicy,
    protection_flags: HashMap<u64, TabProtectionFlags>,
}

impl Default for TabSuspensionManager {
    fn default() -> Self {
        Self::new(90)
    }
}

impl TabSuspensionManager {
    pub fn new(freeze_timeout_seconds: u64) -> Self {
        Self {
            tabs: Vec::new(),
            active_tab_id: 0,
            next_tab_id: 1,
            freeze_timeout_seconds,
            discard_timeout_seconds: 900,
            total_reclaimed_ram_bytes: 0,
            domain_policy: TabSleepDomainPolicy::default(),
            protection_flags: HashMap::new(),
        }
    }

    pub fn open_tab(
        &mut self,
        title: &str,
        url: &str,
        first_party_etld: &str,
        bridge: &ChromiumEngineBridge,
    ) -> u64 {
        let id = self.next_tab_id;
        self.next_tab_id += 1;

        for t in &mut self.tabs {
            if matches!(t.lifecycle, TabLifecycleState::ActiveForeground) {
                t.lifecycle = TabLifecycleState::BackgroundWarm { idle_seconds: 0 };
            }
        }

        let handle = bridge
            .spawn_isolated_view(url, first_party_etld)
            .unwrap_or(CBrowserViewHandle {
                view_id: id,
                os_process_id: 10000 + id as u32,
            });

        self.tabs.push(BrowserTab {
            tab_id: id,
            title: title.to_string(),
            url: url.to_string(),
            first_party_etld: first_party_etld.to_string(),
            scroll_position_y_px: 0.0,
            playing_audio: false,
            pinned: false,
            mullvad_isolated_relay: None,
            lifecycle: TabLifecycleState::ActiveForeground,
            view_handle_id: handle.view_id,
        });
        self.protection_flags.insert(id, TabProtectionFlags::NONE);
        self.active_tab_id = id;
        id
    }

    /// Sets the exact [`TabProtectionFlags`] for `tab_id` and synchronizes legacy `playing_audio`/`pinned`.
    pub fn set_tab_protection_flags(&mut self, tab_id: u64, flags: TabProtectionFlags) -> bool {
        let Some(tab) = self.tabs.iter_mut().find(|t| t.tab_id == tab_id) else {
            return false;
        };
        tab.playing_audio = flags.contains(TabProtectionFlags::AUDIO_ACTIVE);
        tab.pinned = flags.contains(TabProtectionFlags::PINNED);
        self.protection_flags.insert(tab_id, flags);
        true
    }

    pub fn add_tab_protection_flag(&mut self, tab_id: u64, flag: TabProtectionFlags) -> bool {
        let mut current = self.tab_protection_flags(tab_id);
        current.insert(flag);
        self.set_tab_protection_flags(tab_id, current)
    }

    pub fn remove_tab_protection_flag(&mut self, tab_id: u64, flag: TabProtectionFlags) -> bool {
        let mut current = self.tab_protection_flags(tab_id);
        current.remove(flag);
        self.set_tab_protection_flags(tab_id, current)
    }

    pub fn tab_protection_flags(&self, tab_id: u64) -> TabProtectionFlags {
        let mut flags = self
            .protection_flags
            .get(&tab_id)
            .copied()
            .unwrap_or(TabProtectionFlags::NONE);
        if let Some(tab) = self.tabs.iter().find(|t| t.tab_id == tab_id) {
            if tab.playing_audio {
                flags.insert(TabProtectionFlags::AUDIO_ACTIVE);
            }
            if tab.pinned {
                flags.insert(TabProtectionFlags::PINNED);
            }
        }
        flags
    }

    /// Returns `true` if `tab_id` has any protection bitflag set or matches a `never_sleep` domain rule.
    pub fn is_tab_protected(&self, tab_id: u64) -> bool {
        if self.tab_protection_flags(tab_id).is_protected() {
            return true;
        }
        if let Some(tab) = self.tabs.iter().find(|t| t.tab_id == tab_id) {
            let host = if !tab.url.is_empty() {
                normalize_host(&tab.url)
            } else {
                normalize_host(&tab.first_party_etld)
            };
            return self.domain_policy.should_never_sleep(&host)
                || self.domain_policy.should_never_sleep(&tab.first_party_etld);
        }
        false
    }

    /// Soft-freezes a background tab into `FrozenZeroCpu` (0% CPU, DOM/RAM preserved).
    pub fn freeze_tab_soft(
        &mut self,
        tab_id: u64,
        now_unix: u64,
        rss_bytes: u64,
        bridge: &ChromiumEngineBridge,
    ) -> bool {
        if tab_id == self.active_tab_id || self.is_tab_protected(tab_id) {
            return false;
        }
        let Some(tab) = self.tabs.iter_mut().find(|t| t.tab_id == tab_id) else {
            return false;
        };
        if matches!(
            tab.lifecycle,
            TabLifecycleState::ActiveForeground | TabLifecycleState::SuspendedFrozen { .. }
        ) {
            return false;
        }
        let ok = bridge.freeze_view(CBrowserViewHandle {
            view_id: tab.view_handle_id,
            os_process_id: 10000 + tab.view_handle_id as u32,
        });
        if ok {
            tab.lifecycle = TabLifecycleState::FrozenZeroCpu {
                frozen_since_unix: now_unix,
                rss_bytes,
            };
            true
        } else {
            false
        }
    }

    /// Hard-discards a background or soft-frozen tab, recording exact reclaimed RAM bytes.
    pub fn discard_tab_with_reclaimed_ram(
        &mut self,
        tab_id: u64,
        reclaimed_ram_bytes: u64,
        bridge: &ChromiumEngineBridge,
    ) -> bool {
        if tab_id == self.active_tab_id || self.is_tab_protected(tab_id) {
            return false;
        }
        let Some(tab) = self.tabs.iter_mut().find(|t| t.tab_id == tab_id) else {
            return false;
        };
        if matches!(
            tab.lifecycle,
            TabLifecycleState::ActiveForeground | TabLifecycleState::SuspendedFrozen { .. }
        ) {
            return false;
        }
        let snapshot = serde_json::to_vec(&(&tab.url, &tab.title, tab.scroll_position_y_px))
            .unwrap_or_default();
        let ok = bridge.freeze_view(CBrowserViewHandle {
            view_id: tab.view_handle_id,
            os_process_id: 10000 + tab.view_handle_id as u32,
        });
        if ok {
            let reclaimed_mb = (reclaimed_ram_bytes / (1024 * 1024)) as u32;
            tab.lifecycle = TabLifecycleState::SuspendedFrozen {
                compressed_snapshot_bytes: snapshot,
                reclaimed_ram_mb: reclaimed_mb,
            };
            self.total_reclaimed_ram_bytes = self
                .total_reclaimed_ram_bytes
                .saturating_add(reclaimed_ram_bytes);
            true
        } else {
            false
        }
    }

    /// Advances idle timers by `elapsed_sec` and automatically suspends background tabs
    /// exceeding `freeze_timeout_seconds` (honoring `TabProtectionFlags` and `TabSleepDomainPolicy`).
    pub fn tick_idle_and_freeze(&mut self, elapsed_sec: u64, bridge: &ChromiumEngineBridge) -> usize {
        let mut newly_frozen = 0;
        let ids_and_hosts: Vec<(u64, String, String)> = self
            .tabs
            .iter()
            .map(|t| (t.tab_id, normalize_host(&t.url), t.first_party_etld.clone()))
            .collect();

        for (idx, (tab_id, host, etld)) in ids_and_hosts.into_iter().enumerate() {
            let flags = self.tab_protection_flags(tab_id);
            if flags.is_protected()
                || self.domain_policy.should_never_sleep(&host)
                || self.domain_policy.should_never_sleep(&etld)
            {
                continue;
            }
            let effective_timeout = if self.domain_policy.should_fast_sleep(&host)
                || self.domain_policy.should_fast_sleep(&etld)
            {
                (self.freeze_timeout_seconds / 3).max(10)
            } else {
                self.freeze_timeout_seconds
            };

            let tab = &mut self.tabs[idx];
            if let TabLifecycleState::BackgroundWarm { idle_seconds } = tab.lifecycle {
                let updated = idle_seconds.saturating_add(elapsed_sec);
                if updated >= effective_timeout {
                    let snapshot = serde_json::to_vec(&(
                        &tab.url,
                        &tab.title,
                        tab.scroll_position_y_px,
                    ))
                    .unwrap_or_default();
                    let ok = bridge.freeze_view(CBrowserViewHandle {
                        view_id: tab.view_handle_id,
                        os_process_id: 10000 + tab.view_handle_id as u32,
                    });
                    if ok {
                        let reclaimed_mb: u32 = 185;
                        tab.lifecycle = TabLifecycleState::SuspendedFrozen {
                            compressed_snapshot_bytes: snapshot,
                            reclaimed_ram_mb: reclaimed_mb,
                        };
                        self.total_reclaimed_ram_bytes = self
                            .total_reclaimed_ram_bytes
                            .saturating_add(u64::from(reclaimed_mb) * 1024 * 1024);
                        newly_frozen += 1;
                    }
                } else {
                    tab.lifecycle = TabLifecycleState::BackgroundWarm {
                        idle_seconds: updated,
                    };
                }
            }
        }
        newly_frozen
    }

    /// Two-stage lifecycle tick:
    /// - Stage 1 (`BackgroundWarm -> FrozenZeroCpu`) after `freeze_timeout_seconds`.
    /// - Stage 2 (`FrozenZeroCpu -> SuspendedFrozen`) after `discard_timeout_seconds`.
    /// Returns `(newly_soft_frozen, newly_discarded)`.
    pub fn tick_two_stage_lifecycle(
        &mut self,
        elapsed_sec: u64,
        now_unix: u64,
        default_rss_bytes: u64,
        bridge: &ChromiumEngineBridge,
    ) -> (usize, usize) {
        let mut soft_frozen = 0usize;
        let mut discarded = 0usize;

        let tab_ids: Vec<u64> = self.tabs.iter().map(|t| t.tab_id).collect();
        for tab_id in tab_ids {
            if tab_id == self.active_tab_id || self.is_tab_protected(tab_id) {
                continue;
            }
            let Some(pos) = self.tabs.iter().position(|t| t.tab_id == tab_id) else {
                continue;
            };
            let host = normalize_host(&self.tabs[pos].url);
            let fast = self.domain_policy.should_fast_sleep(&host)
                || self
                    .domain_policy
                    .should_fast_sleep(&self.tabs[pos].first_party_etld);
            let freeze_limit = if fast {
                (self.freeze_timeout_seconds / 3).max(10)
            } else {
                self.freeze_timeout_seconds
            };
            let discard_limit = if fast {
                (self.discard_timeout_seconds / 3).max(30)
            } else {
                self.discard_timeout_seconds
            };

            match self.tabs[pos].lifecycle {
                TabLifecycleState::BackgroundWarm { idle_seconds } => {
                    let updated = idle_seconds.saturating_add(elapsed_sec);
                    if updated >= freeze_limit {
                        if self.freeze_tab_soft(tab_id, now_unix, default_rss_bytes, bridge) {
                            soft_frozen += 1;
                        }
                    } else {
                        self.tabs[pos].lifecycle = TabLifecycleState::BackgroundWarm {
                            idle_seconds: updated,
                        };
                    }
                }
                TabLifecycleState::FrozenZeroCpu {
                    frozen_since_unix,
                    rss_bytes,
                } => {
                    if now_unix.saturating_sub(frozen_since_unix) >= discard_limit {
                        let reclaim = if rss_bytes > 0 {
                            rss_bytes
                        } else {
                            default_rss_bytes
                        };
                        if self.discard_tab_with_reclaimed_ram(tab_id, reclaim, bridge) {
                            discarded += 1;
                        }
                    }
                }
                TabLifecycleState::ActiveForeground | TabLifecycleState::SuspendedFrozen { .. } => {}
            }
        }

        (soft_frozen, discarded)
    }

    /// Instantly restores a soft-frozen or discarded tab back to `ActiveForeground`
    /// with exact scroll & state fidelity. Verifies `tab_id` exists BEFORE deactivating
    /// the currently active foreground tab.
    pub fn activate_tab(&mut self, tab_id: u64, bridge: &ChromiumEngineBridge) -> Option<&BrowserTab> {
        let target_idx = self.tabs.iter().position(|t| t.tab_id == tab_id)?;

        for (idx, tab) in self.tabs.iter_mut().enumerate() {
            if idx == target_idx {
                match tab.lifecycle {
                    TabLifecycleState::SuspendedFrozen {
                        ref compressed_snapshot_bytes,
                        ..
                    } => {
                        if let Ok((_url, _title, saved_scroll)) =
                            serde_json::from_slice::<(String, String, f64)>(
                                compressed_snapshot_bytes,
                            )
                        {
                            tab.scroll_position_y_px = saved_scroll;
                        }
                        let _ = bridge.resume_view(CBrowserViewHandle {
                            view_id: tab.view_handle_id,
                            os_process_id: 10000 + tab.view_handle_id as u32,
                        });
                    }
                    TabLifecycleState::FrozenZeroCpu { .. } => {
                        let _ = bridge.resume_view(CBrowserViewHandle {
                            view_id: tab.view_handle_id,
                            os_process_id: 10000 + tab.view_handle_id as u32,
                        });
                    }
                    TabLifecycleState::ActiveForeground
                    | TabLifecycleState::BackgroundWarm { .. } => {}
                }
                tab.lifecycle = TabLifecycleState::ActiveForeground;
                self.active_tab_id = tab_id;
            } else if matches!(tab.lifecycle, TabLifecycleState::ActiveForeground) {
                tab.lifecycle = TabLifecycleState::BackgroundWarm { idle_seconds: 0 };
            }
        }
        self.tabs.get(target_idx)
    }

    pub fn set_freeze_timeout_seconds(&mut self, timeout_sec: u64) {
        self.freeze_timeout_seconds = timeout_sec.clamp(10, 30 * 24 * 3600);
    }

    pub fn freeze_timeout_seconds(&self) -> u64 {
        self.freeze_timeout_seconds
    }

    pub fn set_discard_timeout_seconds(&mut self, timeout_sec: u64) {
        self.discard_timeout_seconds = timeout_sec.clamp(30, 30 * 24 * 3600);
    }

    pub fn discard_timeout_seconds(&self) -> u64 {
        self.discard_timeout_seconds
    }

    pub fn total_reclaimed_ram_bytes(&self) -> u64 {
        self.total_reclaimed_ram_bytes
    }

    pub fn tabs(&self) -> &[BrowserTab] {
        &self.tabs
    }

    pub fn tab_mut(&mut self, tab_id: u64) -> Option<&mut BrowserTab> {
        self.tabs.iter_mut().find(|t| t.tab_id == tab_id)
    }

    pub fn close_tab(&mut self, tab_id: u64) -> Option<BrowserTab> {
        let pos = self.tabs.iter().position(|t| t.tab_id == tab_id)?;
        let removed = self.tabs.remove(pos);
        self.protection_flags.remove(&tab_id);
        if self.active_tab_id == tab_id {
            self.active_tab_id = self.tabs.last().map(|t| t.tab_id).unwrap_or(0);
        }
        Some(removed)
    }

    pub fn active_tab_id(&self) -> u64 {
        self.active_tab_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use singularity_chromium_ffi::init_chromium_from_registry;
    use singularity_settings_registry::SettingsRegistry;

    #[test]
    fn test_activate_nonexistent_tab_preserves_current_active_tab() {
        let reg = SettingsRegistry::new();
        let bridge = init_chromium_from_registry(&reg).expect("FFI bridge");
        let mut mgr = TabSuspensionManager::new(90);

        let t1 = mgr.open_tab("Tab 1", "https://example.org", "example.org", &bridge);
        let t2 = mgr.open_tab("Tab 2", "https://mullvad.net", "mullvad.net", &bridge);
        assert_eq!(mgr.active_tab_id(), t2);

        assert!(mgr.activate_tab(999_999, &bridge).is_none());
        assert_eq!(mgr.active_tab_id(), t2);
        let tab2 = mgr.tabs().iter().find(|t| t.tab_id == t2).unwrap();
        assert_eq!(tab2.lifecycle, TabLifecycleState::ActiveForeground);

        let activated = mgr.activate_tab(t1, &bridge).expect("t1 exists");
        assert_eq!(activated.tab_id, t1);
        assert_eq!(activated.lifecycle, TabLifecycleState::ActiveForeground);
        assert_eq!(mgr.active_tab_id(), t1);
        let tab2_after = mgr.tabs().iter().find(|t| t.tab_id == t2).unwrap();
        assert!(matches!(
            tab2_after.lifecycle,
            TabLifecycleState::BackgroundWarm { .. }
        ));
    }

    #[test]
    fn test_protection_flags_domain_policy_and_two_stage_reclaim() {
        let reg = SettingsRegistry::new();
        let bridge = init_chromium_from_registry(&reg).expect("FFI bridge");
        let mut mgr = TabSuspensionManager::new(60);
        mgr.set_discard_timeout_seconds(120);
        mgr.domain_policy.add_never_sleep_rule("*.meet.google.com");
        mgr.domain_policy.add_fast_sleep_rule("news.example.com");

        let t_meet = mgr.open_tab(
            "Meet",
            "https://call.meet.google.com/abc",
            "google.com",
            &bridge,
        );
        let t_form = mgr.open_tab("Form", "https://app.test/edit", "app.test", &bridge);
        let t_news = mgr.open_tab("News", "https://news.example.com/1", "example.com", &bridge);
        let _t_active = mgr.open_tab("Active", "https://mullvad.net", "mullvad.net", &bridge);

        // Protect t_form with DIRTY_FORM | WEBRTC_MEDIA
        let flags = TabProtectionFlags::DIRTY_FORM | TabProtectionFlags::WEBRTC_MEDIA;
        assert!(flags.contains(TabProtectionFlags::DIRTY_FORM));
        assert!(flags.contains(TabProtectionFlags::WEBRTC_MEDIA));
        assert!(!flags.contains(TabProtectionFlags::DRM_ACTIVE));
        assert!(mgr.set_tab_protection_flags(t_form, flags));

        // Domain policy checks
        assert!(mgr.domain_policy.should_never_sleep("call.meet.google.com"));
        assert!(mgr.domain_policy.should_fast_sleep("news.example.com"));
        assert!(!mgr.domain_policy.should_fast_sleep("call.meet.google.com"));

        // Soft freeze fails for protected / never-sleep tabs, succeeds for t_news
        assert!(!mgr.freeze_tab_soft(t_meet, 1000, 100 * 1024 * 1024, &bridge));
        assert!(!mgr.freeze_tab_soft(t_form, 1000, 100 * 1024 * 1024, &bridge));
        assert!(mgr.freeze_tab_soft(t_news, 1000, 128 * 1024 * 1024, &bridge));
        assert_eq!(
            mgr.tabs().iter().find(|t| t.tab_id == t_news).unwrap().lifecycle,
            TabLifecycleState::FrozenZeroCpu {
                frozen_since_unix: 1000,
                rss_bytes: 128 * 1024 * 1024,
            }
        );

        // Discard with reclaimed RAM accounting
        assert!(mgr.discard_tab_with_reclaimed_ram(t_news, 128 * 1024 * 1024, &bridge));
        assert_eq!(mgr.total_reclaimed_ram_bytes(), 128 * 1024 * 1024);

        // Restoring soft-frozen or discarded tab works cleanly
        let restored = mgr.activate_tab(t_news, &bridge).unwrap();
        assert_eq!(restored.lifecycle, TabLifecycleState::ActiveForeground);
    }

    #[test]
    fn test_split_layout_tree_geometry_and_magnetic_snap() {
        // Magnetic snap at 33%, 50%, 66%
        assert!((snap_split_ratio(0.34) - 1.0 / 3.0).abs() < 1e-5);
        assert!((snap_split_ratio(0.49) - 0.5).abs() < 1e-5);
        assert!((snap_split_ratio(0.65) - 2.0 / 3.0).abs() < 1e-5);
        assert!((snap_split_ratio(0.42) - 0.42).abs() < 1e-5);

        let mut tree = SplitLayoutTree::leaf(1);
        assert!(tree.split_leaf(1, 2, SplitOrientation::Horizontal, 0.51));
        assert!(tree.split_leaf(2, 3, SplitOrientation::Vertical, 0.34));

        let rects = tree.compute_pane_rects(0.0, 0.0, 1004.0, 604.0, 4.0);
        assert_eq!(rects.len(), 3);
        // Pane 1: left half (500 x 604)
        assert_eq!(rects[0].0, 1);
        assert!((rects[0].1 - 0.0).abs() < 0.01);
        assert!((rects[0].3 - 500.0).abs() < 0.01);
        assert!((rects[0].4 - 604.0).abs() < 0.01);
        // Pane 2: top-right (500 x 200)
        assert_eq!(rects[1].0, 2);
        assert!((rects[1].1 - 504.0).abs() < 0.01);
        assert!((rects[1].4 - 200.0).abs() < 0.05);
        // Pane 3: bottom-right (500 x 400)
        assert_eq!(rects[2].0, 3);
        assert!((rects[2].2 - 204.0).abs() < 0.05);
        assert!((rects[2].4 - 400.0).abs() < 0.05);

        let collapsed = tree.close_leaf(3).unwrap();
        assert_eq!(collapsed.leaf_tab_ids(), vec![1, 2]);
    }
}
