//! Zero-Copy In-Memory RAM Disk Cache & Partitioned B-Tree Indexed Asset Storage.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::Arc;

/// Cached web asset stored in the first-party partitioned B-Tree RAM index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedAsset {
    pub partition_etld_plus_one: String,
    pub url: String,
    pub mime_type: String,
    pub payload: Arc<Vec<u8>>,
    pub sha256_integrity_hex: String,
    pub expires_at_unix_sec: u64,
}

/// Partitioned B-Tree + RAM Disk Asset Cache delivering sub-millisecond asset retrieval
/// while strictly isolating cache state per top-level first-party domain and using LRU eviction.
pub struct BTreeRamAssetCache {
    max_capacity_bytes: usize,
    current_size_bytes: usize,
    access_seq: u64,
    index: BTreeMap<(String, String), (CachedAsset, u64)>,
    hits: u64,
    misses: u64,
}

impl Default for BTreeRamAssetCache {
    fn default() -> Self {
        Self::new(512 * 1024 * 1024) // 512 MiB default RAM cache
    }
}

impl BTreeRamAssetCache {
    pub fn new(max_capacity_bytes: usize) -> Self {
        Self {
            max_capacity_bytes,
            current_size_bytes: 0,
            access_seq: 0,
            index: BTreeMap::new(),
            hits: 0,
            misses: 0,
        }
    }

    /// Inserts an asset into the B-Tree index keyed by `(first_party_etld, url)`.
    pub fn put(
        &mut self,
        first_party_etld: &str,
        url: &str,
        mime_type: &str,
        payload: Vec<u8>,
        expires_at_unix_sec: u64,
    ) -> bool {
        if payload.len() > self.max_capacity_bytes {
            return false;
        }

        let key = (first_party_etld.to_string(), url.to_string());
        if let Some((old, _)) = self.index.remove(&key) {
            self.current_size_bytes = self.current_size_bytes.saturating_sub(old.payload.len());
        }

        while self.current_size_bytes.saturating_add(payload.len()) > self.max_capacity_bytes {
            let lru_key = self
                .index
                .iter()
                .min_by_key(|(_, (_, seq))| *seq)
                .map(|(k, _)| k.clone());
            if let Some(evict_key) = lru_key {
                if let Some((removed, _)) = self.index.remove(&evict_key) {
                    self.current_size_bytes =
                        self.current_size_bytes.saturating_sub(removed.payload.len());
                }
            } else {
                break;
            }
        }

        let digest = Sha256::digest(&payload);
        let sha256_hex = format!("{:x}", digest);
        let size = payload.len();

        let asset = CachedAsset {
            partition_etld_plus_one: first_party_etld.to_string(),
            url: url.to_string(),
            mime_type: mime_type.to_string(),
            payload: Arc::new(payload),
            sha256_integrity_hex: sha256_hex,
            expires_at_unix_sec,
        };

        self.access_seq = self.access_seq.wrapping_add(1);
        self.index.insert(key, (asset, self.access_seq));
        self.current_size_bytes = self.current_size_bytes.saturating_add(size);
        true
    }

    /// Retrieves a zero-copy `Arc<Vec<u8>>` reference to the cached asset in O(log N) B-Tree time,
    /// evicting expired entries immediately.
    pub fn get(
        &mut self,
        first_party_etld: &str,
        url: &str,
        now_unix_sec: u64,
    ) -> Option<CachedAsset> {
        let key = (first_party_etld.to_string(), url.to_string());
        let expired = self
            .index
            .get(&key)
            .is_some_and(|(entry, _)| entry.expires_at_unix_sec < now_unix_sec);
        if expired {
            if let Some((removed, _)) = self.index.remove(&key) {
                self.current_size_bytes =
                    self.current_size_bytes.saturating_sub(removed.payload.len());
            }
            self.misses += 1;
            return None;
        }
        if let Some((entry, seq)) = self.index.get_mut(&key) {
            self.access_seq = self.access_seq.wrapping_add(1);
            *seq = self.access_seq;
            self.hits += 1;
            return Some(entry.clone());
        }
        self.misses += 1;
        None
    }

    /// Wipes all cached assets belonging to `first_party_etld` when the domain's last tab closes.
    pub fn purge_first_party_partition(&mut self, first_party_etld: &str) -> usize {
        let keys_to_remove: Vec<(String, String)> = self
            .index
            .range((first_party_etld.to_string(), String::new())..)
            .take_while(|((etld, _), _)| etld == first_party_etld)
            .map(|(k, _)| k.clone())
            .collect();

        let count = keys_to_remove.len();
        for k in keys_to_remove {
            if let Some((removed, _)) = self.index.remove(&k) {
                self.current_size_bytes =
                    self.current_size_bytes.saturating_sub(removed.payload.len());
            }
        }
        count
    }

    pub fn stats(&self) -> (u64, u64, usize) {
        (self.hits, self.misses, self.current_size_bytes)
    }
}
