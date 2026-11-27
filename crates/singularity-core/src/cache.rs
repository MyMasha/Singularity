//! Zero-Copy In-Memory RAM Disk Cache & Partitioned B-Tree Indexed Asset Storage
//! with Pure-Rust Lossless RLE/LZ-Compact Compression, Quota Configuration, and Age-Based Purging.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Fixed per-entry metadata overhead (B-Tree node, sequence counter, SHA-256 digest, Arc header)
/// so even 0-byte payload entries are strictly bounded and evicted under LRU pressure.
pub const ENTRY_METADATA_OVERHEAD_BYTES: usize = 64;

const COMPRESSED_MAGIC: [u8; 4] = *b"SLZ1";
const MIN_COMPRESS_PAYLOAD_BYTES: usize = 64;
const MAX_DECOMPRESSED_BYTES: usize = 256 * 1024 * 1024;

fn now_unix_sec() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn accounted_entry_bytes(first_party_etld: &str, url: &str, stored_payload_len: usize) -> usize {
    first_party_etld
        .len()
        .saturating_add(url.len())
        .saturating_add(ENTRY_METADATA_OVERHEAD_BYTES)
        .saturating_add(stored_payload_len)
}

/// Classifies whether a MIME type represents compressible text/structured web content
/// (HTML, CSS, JavaScript, JSON, SVG, XML, plain text) vs already-compressed binary media.
pub fn is_compressible_mime(mime_type: &str) -> bool {
    let base = mime_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if base.is_empty() {
        return false;
    }
    if base.starts_with("text/") {
        return true;
    }
    matches!(
        base.as_str(),
        "application/javascript"
            | "application/x-javascript"
            | "application/ecmascript"
            | "application/json"
            | "application/ld+json"
            | "application/manifest+json"
            | "application/xml"
            | "application/xhtml+xml"
            | "application/rss+xml"
            | "application/atom+xml"
            | "image/svg+xml"
    ) || base.ends_with("+json")
        || base.ends_with("+xml")
}

/// Pure-Rust lossless RLE + LZ77-compact compressor tuned for HTML/CSS/JS/JSON/SVG cache assets.
pub fn compress_lossless(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + input.len() / 2);
    out.extend_from_slice(&COMPRESSED_MAGIC);
    out.extend_from_slice(&(input.len() as u32).to_le_bytes());

    if input.is_empty() {
        return out;
    }

    const HASH_BITS: usize = 12;
    const HASH_SIZE: usize = 1 << HASH_BITS;
    let mut hash_table = vec![u32::MAX; HASH_SIZE];

    let mut pos = 0usize;
    let mut literals: Vec<u8> = Vec::with_capacity(128);

    let flush_literals = |lits: &mut Vec<u8>, dst: &mut Vec<u8>| {
        let mut idx = 0;
        while idx < lits.len() {
            let chunk = (lits.len() - idx).min(128);
            dst.push((chunk - 1) as u8); // 0x00..=0x7F => 1..=128 literal bytes
            dst.extend_from_slice(&lits[idx..idx + chunk]);
            idx += chunk;
        }
        lits.clear();
    };

    while pos < input.len() {
        // 1. Check RLE run (3..=66 identical consecutive bytes)
        let b = input[pos];
        let mut rle_len = 1usize;
        while pos + rle_len < input.len() && rle_len < 66 && input[pos + rle_len] == b {
            rle_len += 1;
        }

        // 2. Check LZ77 3-byte hash match (4..=67 bytes within 65535-byte window)
        let mut best_lz_len = 0usize;
        let mut best_lz_dist = 0usize;
        if pos + 4 <= input.len() {
            let h = hash3(input[pos], input[pos + 1], input[pos + 2], HASH_BITS);
            let prev = hash_table[h];
            hash_table[h] = pos as u32;

            if prev != u32::MAX {
                let prev_pos = prev as usize;
                let dist = pos - prev_pos;
                if dist >= 1 && dist <= u16::MAX as usize {
                    let max_match = (input.len() - pos).min(67);
                    let mut mlen = 0usize;
                    while mlen < max_match && input[prev_pos + mlen] == input[pos + mlen] {
                        mlen += 1;
                    }
                    if mlen >= 4 {
                        best_lz_len = mlen;
                        best_lz_dist = dist;
                    }
                }
            }
        }

        if rle_len >= 3 && rle_len >= best_lz_len {
            flush_literals(&mut literals, &mut out);
            out.push(0x80 | ((rle_len - 3) as u8));
            out.push(b);
            pos += rle_len;
        } else if best_lz_len >= 4 {
            flush_literals(&mut literals, &mut out);
            out.push(0xC0 | ((best_lz_len - 4) as u8));
            out.extend_from_slice(&(best_lz_dist as u16).to_le_bytes());
            // Index intermediate positions for better compression density
            let end_idx = (pos + best_lz_len).min(input.len().saturating_sub(3));
            for p in (pos + 1)..end_idx {
                let h = hash3(input[p], input[p + 1], input[p + 2], HASH_BITS);
                hash_table[h] = p as u32;
            }
            pos += best_lz_len;
        } else {
            literals.push(b);
            if literals.len() == 128 {
                flush_literals(&mut literals, &mut out);
            }
            pos += 1;
        }
    }

    flush_literals(&mut literals, &mut out);
    out
}

/// Decompresses a payload produced by [`compress_lossless`], verifying length and bounds.
pub fn decompress_lossless(encoded: &[u8]) -> Result<Vec<u8>, String> {
    if encoded.len() < 8 {
        return Err("Truncated SLZ1 header".into());
    }
    if encoded[0..4] != COMPRESSED_MAGIC {
        return Err("Invalid SLZ1 compression magic".into());
    }
    let expected_len = u32::from_le_bytes([encoded[4], encoded[5], encoded[6], encoded[7]]) as usize;
    if expected_len > MAX_DECOMPRESSED_BYTES {
        return Err("SLZ1 payload exceeds maximum allowed decompressed size".into());
    }

    let initial_cap = expected_len
        .min(64 * 1024)
        .min(encoded.len().saturating_mul(16).max(64));
    let mut out = Vec::with_capacity(initial_cap);
    let mut pos = 8usize;

    while pos < encoded.len() {
        let tag = encoded[pos];
        pos += 1;
        if tag < 0x80 {
            let lit_len = (tag as usize) + 1;
            if !matches!(pos.checked_add(lit_len), Some(end) if end <= encoded.len()) {
                return Err("Truncated SLZ1 literal run".into());
            }
            if !matches!(out.len().checked_add(lit_len), Some(new_len) if new_len <= expected_len) {
                return Err("SLZ1 literal run exceeds declared output size".into());
            }
            out.extend_from_slice(&encoded[pos..pos + lit_len]);
            pos += lit_len;
        } else if tag < 0xC0 {
            let rle_len = (tag - 0x80) as usize + 3;
            if pos >= encoded.len() {
                return Err("Truncated SLZ1 RLE byte".into());
            }
            let val = encoded[pos];
            pos += 1;
            if out.len().saturating_add(rle_len) > expected_len {
                return Err("SLZ1 RLE expansion exceeds declared output size".into());
            }
            out.resize(out.len() + rle_len, val);
        } else {
            let lz_len = (tag - 0xC0) as usize + 4;
            if pos + 2 > encoded.len() {
                return Err("Truncated SLZ1 back-reference offset".into());
            }
            let dist = u16::from_le_bytes([encoded[pos], encoded[pos + 1]]) as usize;
            pos += 2;
            if dist == 0 || dist > out.len() {
                return Err("Invalid SLZ1 back-reference distance".into());
            }
            if out.len().saturating_add(lz_len) > expected_len {
                return Err("SLZ1 back-reference exceeds declared output size".into());
            }
            for _ in 0..lz_len {
                let copy_byte = out[out.len() - dist];
                out.push(copy_byte);
            }
        }
    }

    if out.len() != expected_len {
        return Err(format!(
            "SLZ1 decoded size mismatch: expected {}, got {}",
            expected_len,
            out.len()
        ));
    }
    Ok(out)
}

#[inline]
fn hash3(b0: u8, b1: u8, b2: u8, bits: usize) -> usize {
    let v = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
    ((v.wrapping_mul(2654435761u32)) >> (32 - bits)) as usize
}

/// Configurable multi-tier cache quotas for RAM, Disk, Media, V8 Code Cache, and GPU Shaders.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheQuotaConfig {
    pub ram_max_mb: u32,
    pub disk_max_mb: u32,
    pub media_max_mb: u32,
    pub ram_only_mode: bool,
    pub custom_cache_dir: Option<String>,
    pub v8_code_cache_enabled: bool,
    pub gpu_shader_cache_max_mb: u32,
}

impl Default for CacheQuotaConfig {
    fn default() -> Self {
        Self {
            ram_max_mb: 512,
            disk_max_mb: 2048,
            media_max_mb: 512,
            ram_only_mode: false,
            custom_cache_dir: None,
            v8_code_cache_enabled: true,
            gpu_shader_cache_max_mb: 256,
        }
    }
}

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

#[derive(Debug, Clone)]
struct StoredCacheEntry {
    asset: CachedAsset,
    compressed: bool,
    uncompressed_len: usize,
    stored_at_unix_sec: u64,
    access_seq: u64,
}

impl StoredCacheEntry {
    fn accounted_bytes(&self) -> usize {
        accounted_entry_bytes(
            &self.asset.partition_etld_plus_one,
            &self.asset.url,
            self.asset.payload.len(),
        )
    }

    fn materialize(&self) -> Option<CachedAsset> {
        if !self.compressed {
            return Some(self.asset.clone());
        }
        let raw = decompress_lossless(&self.asset.payload).ok()?;
        Some(CachedAsset {
            partition_etld_plus_one: self.asset.partition_etld_plus_one.clone(),
            url: self.asset.url.clone(),
            mime_type: self.asset.mime_type.clone(),
            payload: Arc::new(raw),
            sha256_integrity_hex: self.asset.sha256_integrity_hex.clone(),
            expires_at_unix_sec: self.asset.expires_at_unix_sec,
        })
    }
}

/// Partitioned B-Tree + RAM Disk Asset Cache delivering sub-millisecond asset retrieval
/// while strictly isolating cache state per top-level first-party domain, using LRU eviction
/// and automatic pure-Rust lossless compression for text web assets.
pub struct BTreeRamAssetCache {
    max_capacity_bytes: usize,
    current_size_bytes: usize,
    access_seq: u64,
    index: BTreeMap<(String, String), StoredCacheEntry>,
    hits: u64,
    misses: u64,
    quota_config: CacheQuotaConfig,
}

impl Default for BTreeRamAssetCache {
    fn default() -> Self {
        Self::new(512 * 1024 * 1024)
    }
}

impl BTreeRamAssetCache {
    pub fn new(max_capacity_bytes: usize) -> Self {
        let mut quota_config = CacheQuotaConfig::default();
        quota_config.ram_max_mb = (max_capacity_bytes / (1024 * 1024)) as u32;
        Self {
            max_capacity_bytes,
            current_size_bytes: 0,
            access_seq: 0,
            index: BTreeMap::new(),
            hits: 0,
            misses: 0,
            quota_config,
        }
    }

    pub fn with_quota_config(config: CacheQuotaConfig) -> Self {
        let max_bytes = (config.ram_max_mb as usize)
            .saturating_mul(1024 * 1024)
            .max(1024);
        Self {
            max_capacity_bytes: max_bytes,
            current_size_bytes: 0,
            access_seq: 0,
            index: BTreeMap::new(),
            hits: 0,
            misses: 0,
            quota_config: config,
        }
    }

    pub fn quota_config(&self) -> &CacheQuotaConfig {
        &self.quota_config
    }

    pub fn set_quota_config(&mut self, config: CacheQuotaConfig) {
        self.max_capacity_bytes = (config.ram_max_mb as usize)
            .saturating_mul(1024 * 1024)
            .max(1024);
        self.quota_config = config;
        self.evict_until_within_capacity(0);
    }

    /// Inserts an asset into the B-Tree index keyed by `(first_party_etld, url)`,
    /// automatically compressing compressible MIME payloads >= 64 bytes when smaller.
    pub fn put(
        &mut self,
        first_party_etld: &str,
        url: &str,
        mime_type: &str,
        payload: Vec<u8>,
        expires_at_unix_sec: u64,
    ) -> bool {
        self.put_with_timestamp(
            first_party_etld,
            url,
            mime_type,
            payload,
            now_unix_sec(),
            expires_at_unix_sec,
        )
    }

    /// Inserts an asset with an explicit creation timestamp (`stored_at_unix_sec`).
    pub fn put_with_timestamp(
        &mut self,
        first_party_etld: &str,
        url: &str,
        mime_type: &str,
        payload: Vec<u8>,
        stored_at_unix_sec: u64,
        expires_at_unix_sec: u64,
    ) -> bool {
        let uncompressed_len = payload.len();
        let digest = Sha256::digest(&payload);
        let sha256_hex = format!("{:x}", digest);

        let (stored_bytes, compressed) =
            if is_compressible_mime(mime_type) && payload.len() >= MIN_COMPRESS_PAYLOAD_BYTES {
                let candidate = compress_lossless(&payload);
                if candidate.len() < payload.len() {
                    (candidate, true)
                } else {
                    (payload, false)
                }
            } else {
                (payload, false)
            };

        let entry_size = accounted_entry_bytes(first_party_etld, url, stored_bytes.len());
        if entry_size > self.max_capacity_bytes {
            return false;
        }

        let key = (first_party_etld.to_string(), url.to_string());
        if let Some(old) = self.index.remove(&key) {
            self.current_size_bytes = self
                .current_size_bytes
                .saturating_sub(old.accounted_bytes());
        }

        self.evict_until_within_capacity(entry_size);

        let asset = CachedAsset {
            partition_etld_plus_one: first_party_etld.to_string(),
            url: url.to_string(),
            mime_type: mime_type.to_string(),
            payload: Arc::new(stored_bytes),
            sha256_integrity_hex: sha256_hex,
            expires_at_unix_sec,
        };

        self.access_seq = self.access_seq.wrapping_add(1);
        let stored = StoredCacheEntry {
            asset,
            compressed,
            uncompressed_len,
            stored_at_unix_sec,
            access_seq: self.access_seq,
        };
        self.index.insert(key, stored);
        self.current_size_bytes = self.current_size_bytes.saturating_add(entry_size);
        true
    }

    fn evict_until_within_capacity(&mut self, incoming_bytes: usize) {
        while self.current_size_bytes.saturating_add(incoming_bytes) > self.max_capacity_bytes {
            let lru_key = self
                .index
                .iter()
                .min_by_key(|(_, entry)| entry.access_seq)
                .map(|(k, _)| k.clone());
            if let Some(evict_key) = lru_key {
                if let Some(removed) = self.index.remove(&evict_key) {
                    self.current_size_bytes = self
                        .current_size_bytes
                        .saturating_sub(removed.accounted_bytes());
                }
            } else {
                break;
            }
        }
    }

    /// Retrieves a cached asset in O(log N) B-Tree time (transparently decompressing if stored
    /// compressed), evicting expired entries immediately.
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
            .is_some_and(|entry| entry.asset.expires_at_unix_sec < now_unix_sec);
        if expired {
            if let Some(removed) = self.index.remove(&key) {
                self.current_size_bytes = self
                    .current_size_bytes
                    .saturating_sub(removed.accounted_bytes());
            }
            self.misses += 1;
            return None;
        }
        if let Some(entry) = self.index.get_mut(&key) {
            self.access_seq = self.access_seq.wrapping_add(1);
            entry.access_seq = self.access_seq;
            if let Some(materialized) = entry.materialize() {
                self.hits += 1;
                return Some(materialized);
            }
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
            if let Some(removed) = self.index.remove(&k) {
                self.current_size_bytes = self
                    .current_size_bytes
                    .saturating_sub(removed.accounted_bytes());
            }
        }
        count
    }

    /// Purges all entries stored strictly before `cutoff_unix` (seconds since Unix epoch).
    pub fn purge_older_than(&mut self, cutoff_unix: u64) -> usize {
        let keys_to_remove: Vec<(String, String)> = self
            .index
            .iter()
            .filter(|(_, entry)| entry.stored_at_unix_sec < cutoff_unix)
            .map(|(k, _)| k.clone())
            .collect();

        let count = keys_to_remove.len();
        for k in keys_to_remove {
            if let Some(removed) = self.index.remove(&k) {
                self.current_size_bytes = self
                    .current_size_bytes
                    .saturating_sub(removed.accounted_bytes());
            }
        }
        count
    }

    /// Returns `(total_bytes_saved_by_compression, compressed_entry_count)`.
    pub fn compression_stats(&self) -> (usize, usize) {
        let mut saved = 0usize;
        let mut count = 0usize;
        for entry in self.index.values() {
            if entry.compressed {
                count += 1;
                saved = saved.saturating_add(
                    entry
                        .uncompressed_len
                        .saturating_sub(entry.asset.payload.len()),
                );
            }
        }
        (saved, count)
    }

    pub fn stats(&self) -> (u64, u64, usize) {
        (self.hits, self.misses, self.current_size_bytes)
    }

    pub fn len(&self) -> usize {
        self.index.len()
    }

    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_byte_entries_account_key_and_metadata_and_evict_lru() {
        let mut cache = BTreeRamAssetCache::new(200);
        assert!(cache.put("a.test", "https://a.test/1", "text/plain", vec![], 9999));
        assert!(cache.put("a.test", "https://a.test/2", "text/plain", vec![], 9999));
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.stats().2, 86 * 2);

        assert!(cache.put("a.test", "https://a.test/3", "text/plain", vec![], 9999));
        assert_eq!(cache.len(), 2);
        assert!(cache.stats().2 <= 200);
        assert!(cache.get("a.test", "https://a.test/1", 100).is_none());
        assert!(cache.get("a.test", "https://a.test/2", 100).is_some());
        assert!(cache.get("a.test", "https://a.test/3", 100).is_some());

        let huge_url = format!("https://a.test/{}", "x".repeat(300));
        assert!(!cache.put("a.test", &huge_url, "text/plain", vec![], 9999));

        assert_eq!(cache.purge_first_party_partition("a.test"), 2);
        assert_eq!(cache.stats().2, 0);
        assert!(cache.is_empty());
    }

    #[test]
    fn test_lossless_compression_mime_classifier_quota_and_purge_older_than() {
        assert!(is_compressible_mime("text/html; charset=utf-8"));
        assert!(is_compressible_mime("text/css"));
        assert!(is_compressible_mime("application/javascript"));
        assert!(is_compressible_mime("application/json"));
        assert!(is_compressible_mime("image/svg+xml"));
        assert!(!is_compressible_mime("image/png"));
        assert!(!is_compressible_mime("video/mp4"));
        assert!(!is_compressible_mime("application/wasm"));

        let html = "<html><body><div class=\"card\">Singularity Browser Fast Engine</div>"
            .repeat(40)
            .into_bytes();
        let compressed = compress_lossless(&html);
        assert!(compressed.len() < html.len() / 2);
        let roundtrip = decompress_lossless(&compressed).expect("decompress");
        assert_eq!(roundtrip, html);

        let mut cache = BTreeRamAssetCache::with_quota_config(CacheQuotaConfig {
            ram_max_mb: 16,
            ram_only_mode: true,
            ..CacheQuotaConfig::default()
        });
        assert!(cache.quota_config().ram_only_mode);

        assert!(cache.put_with_timestamp(
            "example.com",
            "https://example.com/index.html",
            "text/html; charset=utf-8",
            html.clone(),
            1000,
            5000,
        ));
        assert!(cache.put_with_timestamp(
            "example.com",
            "https://example.com/fresh.json",
            "application/json",
            br#"{"items":["a","b","c"],"status":"ok","items_dup":["a","b","c","d","e","f","g"]}"#
                .repeat(8),
            2000,
            5000,
        ));

        let (saved_bytes, compressed_count) = cache.compression_stats();
        assert!(saved_bytes > 500);
        assert_eq!(compressed_count, 2);

        // Transparent decompression returns exact original HTML bytes
        let got = cache
            .get("example.com", "https://example.com/index.html", 1500)
            .expect("cache hit");
        assert_eq!(*got.payload, html);

        // Purge older than 1500 removes index.html (ts=1000) and keeps fresh.json (ts=2000)
        assert_eq!(cache.purge_older_than(1500), 1);
        assert_eq!(cache.len(), 1);
        assert!(cache
            .get("example.com", "https://example.com/index.html", 1500)
            .is_none());
        assert!(cache
            .get("example.com", "https://example.com/fresh.json", 2500)
            .is_some());
    }

    #[test]
    fn test_slz1_rejects_oom_header_and_literal_overflow() {
        // 8-byte header claiming 256 MiB output must fail cleanly without pre-allocating 256 MiB
        let mut bomb = Vec::from(*b"SLZ1");
        bomb.extend_from_slice(&(MAX_DECOMPRESSED_BYTES as u32).to_le_bytes());
        assert!(decompress_lossless(&bomb).is_err());

        // Literal run exceeding declared expected_len must fail immediately
        let mut lit_overflow = Vec::from(*b"SLZ1");
        lit_overflow.extend_from_slice(&2u32.to_le_bytes());
        lit_overflow.push(0x04); // 5 literal bytes
        lit_overflow.extend_from_slice(b"abcde");
        let err = decompress_lossless(&lit_overflow).unwrap_err();
        assert!(err.contains("exceeds declared output size"));
    }
}
