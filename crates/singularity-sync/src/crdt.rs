//! Conflict-Free Replicated Data Type (CRDT): LWW-Element-Set + Vector Clock.
//!
//! Guarantees deterministic, commutative, associative, and idempotent convergence of
//! concurrent offline browser mutations (add, edit, delete with tombstones) across
//! all 10 independently toggleable `SyncCollectionKind` datasets.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CrdtError {
    #[error("Collection mismatch: document is {expected:?}, delta packet is {actual:?}")]
    CollectionMismatch {
        expected: SyncCollectionKind,
        actual: SyncCollectionKind,
    },
}

/// The 10 independently toggleable browser synchronization collections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SyncCollectionKind {
    Bookmarks,
    History,
    OpenTabs,
    TabGroupsAndWorkspaces,
    VaultCredentials,
    Extensions,
    Settings,
    ThemesAndBoosts,
    KeybindsAndChains,
    ZoomAndSitePrefs,
}

impl SyncCollectionKind {
    /// Complete ordered list of all 10 independently toggleable collections.
    pub const ALL: [SyncCollectionKind; 10] = [
        Self::Bookmarks,
        Self::History,
        Self::OpenTabs,
        Self::TabGroupsAndWorkspaces,
        Self::VaultCredentials,
        Self::Extensions,
        Self::Settings,
        Self::ThemesAndBoosts,
        Self::KeybindsAndChains,
        Self::ZoomAndSitePrefs,
    ];

    /// Stable canonical ASCII identifier used in AAD bindings and encrypted delta filenames.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Bookmarks => "bookmarks",
            Self::History => "history",
            Self::OpenTabs => "open_tabs",
            Self::TabGroupsAndWorkspaces => "tab_groups_and_workspaces",
            Self::VaultCredentials => "vault_credentials",
            Self::Extensions => "extensions",
            Self::Settings => "settings",
            Self::ThemesAndBoosts => "themes_and_boosts",
            Self::KeybindsAndChains => "keybinds_and_chains",
            Self::ZoomAndSitePrefs => "zoom_and_site_prefs",
        }
    }

    pub fn from_str_id(id: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == id)
    }
}

/// Per-collection opt-in toggle state allowing users to independently enable or disable
/// any of the 10 `SyncCollectionKind` categories.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncCollectionPrefs {
    enabled: BTreeSet<SyncCollectionKind>,
}

impl Default for SyncCollectionPrefs {
    fn default() -> Self {
        Self::all_enabled()
    }
}

impl SyncCollectionPrefs {
    pub fn all_enabled() -> Self {
        Self {
            enabled: SyncCollectionKind::ALL.into_iter().collect(),
        }
    }

    pub fn none_enabled() -> Self {
        Self {
            enabled: BTreeSet::new(),
        }
    }

    pub fn set_enabled(&mut self, kind: SyncCollectionKind, enabled: bool) {
        if enabled {
            self.enabled.insert(kind);
        } else {
            self.enabled.remove(&kind);
        }
    }

    pub fn is_enabled(&self, kind: SyncCollectionKind) -> bool {
        self.enabled.contains(&kind)
    }

    pub fn enabled_collections(&self) -> Vec<SyncCollectionKind> {
        self.enabled.iter().copied().collect()
    }
}

/// Logical Vector Clock tracking the highest observed sequence counter per device.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VectorClock {
    pub entries: BTreeMap<String, u64>,
}

impl VectorClock {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, device_id: &str) -> u64 {
        self.entries.get(device_id).copied().unwrap_or(0)
    }

    /// Increments the logical counter for `device_id` and returns the new sequence number.
    pub fn tick(&mut self, device_id: &str) -> u64 {
        let next = self.get(device_id).saturating_add(1);
        self.entries.insert(device_id.to_string(), next);
        next
    }

    /// Records an observed sequence number for `device_id` (join = pointwise max).
    pub fn observe(&mut self, device_id: &str, seq: u64) {
        let entry = self.entries.entry(device_id.to_string()).or_insert(0);
        if seq > *entry {
            *entry = seq;
        }
    }

    /// Semilattice join (pointwise maximum): commutative, associative, and idempotent.
    pub fn merge(&mut self, other: &VectorClock) {
        for (device_id, &seq) in &other.entries {
            self.observe(device_id, seq);
        }
    }

    /// Returns `true` if `self` is greater than or equal to `other` on every device coordinate.
    pub fn dominates(&self, other: &VectorClock) -> bool {
        other
            .entries
            .iter()
            .all(|(device_id, &seq)| self.get(device_id) >= seq)
    }

    /// Returns `true` if neither clock dominates the other (true concurrent offline divergence).
    pub fn is_concurrent_with(&self, other: &VectorClock) -> bool {
        !self.dominates(other) && !other.dominates(self)
    }
}

/// Deterministic Hybrid Logical Clock (HLC) timestamp providing a strict total order
/// across offline devices.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LwwTimestamp {
    pub wall_time_ms: u64,
    pub logical_counter: u64,
    pub device_id: String,
}

impl Ord for LwwTimestamp {
    fn cmp(&self, other: &Self) -> Ordering {
        self.wall_time_ms
            .cmp(&other.wall_time_ms)
            .then_with(|| self.logical_counter.cmp(&other.logical_counter))
            .then_with(|| self.device_id.cmp(&other.device_id))
    }
}

impl PartialOrd for LwwTimestamp {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Last-Write-Wins add record holding payload value, HLC timestamp, and deterministic tie-break hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LwwAddRecord {
    pub value: serde_json::Value,
    pub timestamp: LwwTimestamp,
    pub value_digest_hex: String,
}

impl LwwAddRecord {
    pub fn new(value: serde_json::Value, timestamp: LwwTimestamp) -> Self {
        let canonical = serde_json::to_vec(&value).unwrap_or_default();
        let digest_hex = hex::encode(Sha256::digest(&canonical));
        Self {
            value,
            timestamp,
            value_digest_hex: digest_hex,
        }
    }

    fn cmp_deterministic(&self, other: &Self) -> Ordering {
        self.timestamp
            .cmp(&other.timestamp)
            .then_with(|| self.value_digest_hex.cmp(&other.value_digest_hex))
    }
}

/// State of a single item in the LWW-Element-Set (tracks highest add and highest remove tombstone).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LwwElementState {
    pub add: Option<LwwAddRecord>,
    pub remove: Option<LwwTimestamp>,
}

impl LwwElementState {
    /// Returns `true` if the item is currently present (not deleted by a newer or equal tombstone).
    pub fn is_alive(&self) -> bool {
        match (&self.add, &self.remove) {
            (Some(_), None) => true,
            (Some(add_rec), Some(rem_ts)) => add_rec.timestamp > *rem_ts,
            (None, _) => false,
        }
    }

    /// Returns `true` if the item has an active tombstone dominating any add record.
    pub fn is_tombstoned(&self) -> bool {
        self.remove.is_some() && !self.is_alive()
    }

    /// Returns the live JSON payload if the element is alive.
    pub fn live_value(&self) -> Option<&serde_json::Value> {
        if self.is_alive() {
            self.add.as_ref().map(|r| &r.value)
        } else {
            None
        }
    }

    /// Pointwise join of two `LwwElementState` instances (strictly commutative, associative, idempotent).
    pub fn merge(&mut self, other: &Self) {
        if let Some(other_add) = &other.add {
            let should_replace = match &self.add {
                None => true,
                Some(current_add) => {
                    other_add.cmp_deterministic(current_add) == Ordering::Greater
                }
            };
            if should_replace {
                self.add = Some(other_add.clone());
            }
        }

        if let Some(other_rem) = &other.remove {
            let should_replace = match &self.remove {
                None => true,
                Some(current_rem) => other_rem > current_rem,
            };
            if should_replace {
                self.remove = Some(other_rem.clone());
            }
        }
    }
}

/// Operation variant inside a `CrdtOperation`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CrdtOperationKind {
    Upsert {
        item_id: String,
        value: serde_json::Value,
        timestamp: LwwTimestamp,
    },
    Delete {
        item_id: String,
        timestamp: LwwTimestamp,
    },
}

/// An atomic replicated CRDT operation tagged with its originating `(device_id, device_seq)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrdtOperation {
    pub device_id: String,
    pub device_seq: u64,
    pub kind: CrdtOperationKind,
}

impl CrdtOperation {
    pub fn timestamp(&self) -> &LwwTimestamp {
        match &self.kind {
            CrdtOperationKind::Upsert { timestamp, .. } => timestamp,
            CrdtOperationKind::Delete { timestamp, .. } => timestamp,
        }
    }

    pub fn item_id(&self) -> &str {
        match &self.kind {
            CrdtOperationKind::Upsert { item_id, .. } => item_id,
            CrdtOperationKind::Delete { item_id, .. } => item_id,
        }
    }
}

/// Wire-ready delta packet containing CRDT operations and the sender's vector clock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrdtDeltaPacket {
    pub collection: SyncCollectionKind,
    pub origin_device_id: String,
    pub vector_clock: VectorClock,
    pub operations: Vec<CrdtOperation>,
}

/// Replicated LWW-Element-Set + Vector Clock document for one `SyncCollectionKind`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrdtDocument {
    pub collection: SyncCollectionKind,
    pub vector_clock: VectorClock,
    max_wall_ms: u64,
    max_logical: u64,
    elements: BTreeMap<String, LwwElementState>,
    op_log: BTreeMap<(String, u64), CrdtOperation>,
}

impl CrdtDocument {
    pub fn new(collection: SyncCollectionKind) -> Self {
        Self {
            collection,
            vector_clock: VectorClock::new(),
            max_wall_ms: 0,
            max_logical: 0,
            elements: BTreeMap::new(),
            op_log: BTreeMap::new(),
        }
    }

    fn next_hlc_timestamp(&mut self, device_id: &str, local_wall_ms: u64) -> LwwTimestamp {
        if local_wall_ms > self.max_wall_ms {
            self.max_wall_ms = local_wall_ms;
            self.max_logical = 0;
        } else {
            self.max_logical = self.max_logical.saturating_add(1);
        }
        LwwTimestamp {
            wall_time_ms: self.max_wall_ms,
            logical_counter: self.max_logical,
            device_id: device_id.to_string(),
        }
    }

    fn observe_hlc_timestamp(&mut self, ts: &LwwTimestamp) {
        if ts.wall_time_ms > self.max_wall_ms {
            self.max_wall_ms = ts.wall_time_ms;
            self.max_logical = ts.logical_counter;
        } else if ts.wall_time_ms == self.max_wall_ms && ts.logical_counter > self.max_logical {
            self.max_logical = ts.logical_counter;
        }
    }

    /// Creates and applies a local Upsert (add or update) operation.
    pub fn upsert(
        &mut self,
        device_id: &str,
        item_id: impl Into<String>,
        value: serde_json::Value,
        local_wall_ms: u64,
    ) -> CrdtOperation {
        let seq = self.vector_clock.tick(device_id);
        let timestamp = self.next_hlc_timestamp(device_id, local_wall_ms);
        let op = CrdtOperation {
            device_id: device_id.to_string(),
            device_seq: seq,
            kind: CrdtOperationKind::Upsert {
                item_id: item_id.into(),
                value,
                timestamp,
            },
        };
        self.apply_operation(op.clone());
        op
    }

    /// Creates and applies a local Delete (tombstone) operation.
    pub fn delete(
        &mut self,
        device_id: &str,
        item_id: impl Into<String>,
        local_wall_ms: u64,
    ) -> CrdtOperation {
        let seq = self.vector_clock.tick(device_id);
        let timestamp = self.next_hlc_timestamp(device_id, local_wall_ms);
        let op = CrdtOperation {
            device_id: device_id.to_string(),
            device_seq: seq,
            kind: CrdtOperationKind::Delete {
                item_id: item_id.into(),
                timestamp,
            },
        };
        self.apply_operation(op.clone());
        op
    }

    /// Idempotently applies a single `CrdtOperation`. Returns `true` if this operation
    /// had not been seen previously.
    pub fn apply_operation(&mut self, op: CrdtOperation) -> bool {
        let key = (op.device_id.clone(), op.device_seq);
        let is_new = !self.op_log.contains_key(&key);

        self.vector_clock.observe(&op.device_id, op.device_seq);
        self.observe_hlc_timestamp(op.timestamp());

        match &op.kind {
            CrdtOperationKind::Upsert {
                item_id,
                value,
                timestamp,
            } => {
                let incoming = LwwElementState {
                    add: Some(LwwAddRecord::new(value.clone(), timestamp.clone())),
                    remove: None,
                };
                self.elements
                    .entry(item_id.clone())
                    .or_default()
                    .merge(&incoming);
            }
            CrdtOperationKind::Delete { item_id, timestamp } => {
                let incoming = LwwElementState {
                    add: None,
                    remove: Some(timestamp.clone()),
                };
                self.elements
                    .entry(item_id.clone())
                    .or_default()
                    .merge(&incoming);
            }
        }

        if is_new {
            self.op_log.insert(key, op);
        }
        is_new
    }

    /// Merges an incoming `CrdtDeltaPacket` into this document.
    /// Returns the number of newly applied operations.
    pub fn merge_delta(&mut self, delta: &CrdtDeltaPacket) -> Result<usize, CrdtError> {
        if delta.collection != self.collection {
            return Err(CrdtError::CollectionMismatch {
                expected: self.collection,
                actual: delta.collection,
            });
        }
        let mut newly_applied = 0usize;
        for op in &delta.operations {
            if self.apply_operation(op.clone()) {
                newly_applied += 1;
            }
        }
        self.vector_clock.merge(&delta.vector_clock);
        Ok(newly_applied)
    }

    /// Merges another full `CrdtDocument` into `self` (commutative, associative, idempotent).
    pub fn merge_document(&mut self, other: &CrdtDocument) -> Result<(), CrdtError> {
        if other.collection != self.collection {
            return Err(CrdtError::CollectionMismatch {
                expected: self.collection,
                actual: other.collection,
            });
        }
        for (item_id, state) in &other.elements {
            self.elements
                .entry(item_id.clone())
                .or_default()
                .merge(state);
        }
        for (key, op) in &other.op_log {
            self.op_log.entry(key.clone()).or_insert_with(|| op.clone());
            self.observe_hlc_timestamp(op.timestamp());
        }
        self.vector_clock.merge(&other.vector_clock);
        if other.max_wall_ms > self.max_wall_ms {
            self.max_wall_ms = other.max_wall_ms;
            self.max_logical = other.max_logical;
        } else if other.max_wall_ms == self.max_wall_ms && other.max_logical > self.max_logical {
            self.max_logical = other.max_logical;
        }
        Ok(())
    }

    /// Exports a `CrdtDeltaPacket` containing only operations not yet observed by `peer_clock`.
    pub fn export_delta_since(
        &self,
        origin_device_id: &str,
        peer_clock: &VectorClock,
    ) -> CrdtDeltaPacket {
        let operations = self
            .op_log
            .values()
            .filter(|op| op.device_seq > peer_clock.get(&op.device_id))
            .cloned()
            .collect();
        CrdtDeltaPacket {
            collection: self.collection,
            origin_device_id: origin_device_id.to_string(),
            vector_clock: self.vector_clock.clone(),
            operations,
        }
    }

    /// Exports all known operations in this document as a `CrdtDeltaPacket`.
    pub fn export_full_delta(&self, origin_device_id: &str) -> CrdtDeltaPacket {
        self.export_delta_since(origin_device_id, &VectorClock::new())
    }

    /// Returns a map of all currently alive (non-tombstoned) items and their JSON payloads.
    pub fn active_items(&self) -> BTreeMap<String, serde_json::Value> {
        self.elements
            .iter()
            .filter_map(|(k, v)| v.live_value().map(|val| (k.clone(), val.clone())))
            .collect()
    }

    /// Fetches the current live payload for `item_id`, if present and not tombstoned.
    pub fn get(&self, item_id: &str) -> Option<&serde_json::Value> {
        self.elements.get(item_id).and_then(|s| s.live_value())
    }

    /// Returns `true` if `item_id` is explicitly deleted via a tombstone.
    pub fn is_tombstoned(&self, item_id: &str) -> bool {
        self.elements
            .get(item_id)
            .map(|s| s.is_tombstoned())
            .unwrap_or(false)
    }

    /// Returns the total number of tracked items including tombstones.
    pub fn total_tracked_items(&self) -> usize {
        self.elements.len()
    }

    /// Returns the total number of live items.
    pub fn live_item_count(&self) -> usize {
        self.elements.values().filter(|s| s.is_alive()).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ten_sync_collections_independently_toggleable() {
        assert_eq!(SyncCollectionKind::ALL.len(), 10);
        let mut prefs = SyncCollectionPrefs::all_enabled();
        assert!(prefs.is_enabled(SyncCollectionKind::VaultCredentials));
        prefs.set_enabled(SyncCollectionKind::History, false);
        prefs.set_enabled(SyncCollectionKind::OpenTabs, false);
        assert!(!prefs.is_enabled(SyncCollectionKind::History));
        assert!(!prefs.is_enabled(SyncCollectionKind::OpenTabs));
        assert!(prefs.is_enabled(SyncCollectionKind::Bookmarks));
        assert_eq!(prefs.enabled_collections().len(), 8);
    }

    #[test]
    fn crdt_is_commutative_associative_and_idempotent() {
        let mut a = CrdtDocument::new(SyncCollectionKind::Bookmarks);
        let mut b = CrdtDocument::new(SyncCollectionKind::Bookmarks);
        let mut c = CrdtDocument::new(SyncCollectionKind::Bookmarks);

        // Concurrent offline mutations across 3 devices, including identical timestamps & delete
        a.upsert("dev-a", "bm-1", json!({"url": "https://a.example"}), 1000);
        a.upsert("dev-a", "bm-2", json!({"url": "https://keep.example"}), 1005);

        b.upsert("dev-b", "bm-1", json!({"url": "https://b.example"}), 1000);
        b.delete("dev-b", "bm-2", 1010);

        c.upsert("dev-c", "bm-3", json!({"url": "https://c.example"}), 1002);
        c.upsert("dev-c", "bm-2", json!({"url": "https://resurrect.example"}), 1020);

        assert!(a.vector_clock.is_concurrent_with(&b.vector_clock));

        // Commutativity: merge(A, B) == merge(B, A)
        let mut ab = a.clone();
        ab.merge_document(&b).unwrap();
        let mut ba = b.clone();
        ba.merge_document(&a).unwrap();
        assert_eq!(ab.active_items(), ba.active_items());
        assert_eq!(ab.vector_clock, ba.vector_clock);

        // Associativity: merge(merge(A, B), C) == merge(A, merge(B, C))
        let mut ab_c = ab.clone();
        ab_c.merge_document(&c).unwrap();

        let mut bc = b.clone();
        bc.merge_document(&c).unwrap();
        let mut a_bc = a.clone();
        a_bc.merge_document(&bc).unwrap();

        assert_eq!(ab_c.active_items(), a_bc.active_items());
        assert_eq!(ab_c.vector_clock, a_bc.vector_clock);

        // bm-1 tie-broken deterministically in favor of "dev-b" > "dev-a"
        assert_eq!(ab_c.get("bm-1"), Some(&json!({"url": "https://b.example"})));
        // bm-2 was resurrected at t=1020 after delete at t=1010
        assert_eq!(ab_c.get("bm-2"), Some(&json!({"url": "https://resurrect.example"})));

        // Idempotence: merging a delta twice changes nothing
        let delta_c = c.export_full_delta("dev-c");
        let before = ab_c.active_items();
        let newly = ab_c.merge_delta(&delta_c).unwrap();
        assert_eq!(newly, 0);
        assert_eq!(ab_c.active_items(), before);
    }

    #[test]
    fn tombstone_persists_across_delta_exchange() {
        let mut dev1 = CrdtDocument::new(SyncCollectionKind::Settings);
        let mut dev2 = CrdtDocument::new(SyncCollectionKind::Settings);

        dev1.upsert("dev-1", "theme", json!("midnight"), 500);
        let d1 = dev1.export_full_delta("dev-1");
        dev2.merge_delta(&d1).unwrap();
        assert_eq!(dev2.get("theme"), Some(&json!("midnight")));

        dev2.delete("dev-2", "theme", 600);
        assert!(dev2.is_tombstoned("theme"));
        assert_eq!(dev2.get("theme"), None);

        let d2 = dev2.export_delta_since("dev-2", &dev1.vector_clock);
        assert_eq!(d2.operations.len(), 1);
        dev1.merge_delta(&d2).unwrap();
        assert!(dev1.is_tombstoned("theme"));
        assert_eq!(dev1.get("theme"), None);
    }
}
