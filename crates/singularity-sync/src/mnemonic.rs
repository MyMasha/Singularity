//! BIP-39-style 24-word (256-bit entropy + SHA-256 checksum) mnemonic generator/validator,
//! Brave Sync v2-style daily rotating 25th anti-replay word, and RFC 5869 HKDF-SHA256
//! domain-separated key hierarchy.

use crate::wordlist::WORDLIST;
use ed25519_dalek::{SigningKey, VerifyingKey};
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::fmt;
use subtle::ConstantTimeEq;
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

type HmacSha256 = Hmac<Sha256>;

/// Number of permanent seed words (24 × 11 bits = 264 bits = 256-bit entropy + 8-bit SHA-256 checksum).
pub const PERMANENT_WORD_COUNT: usize = 24;
/// Number of words in a time-bound enrollment phrase (24 permanent + 1 daily rotating anti-replay word).
pub const ENROLLMENT_WORD_COUNT: usize = 25;

const HKDF_SALT: &[u8] = b"singularity-sync-v1-hkdf-salt";
const DOMAIN_DAILY_WORD: &[u8] = b"singularity-sync/v1/daily-25th-word";
const DOMAIN_CHAIN_ID: &[u8] = b"singularity-sync/v1/chain-id";
const DOMAIN_ED25519_IDENTITY: &[u8] = b"singularity-sync/v1/ed25519-identity";
const DOMAIN_CONTENT_KEY: &[u8] = b"singularity-sync/v1/xchacha20-content";
const DOMAIN_VAULT_SUBKEY: &[u8] = b"singularity-sync/v1/vault-subkey";
const DOMAIN_X25519_P2P: &[u8] = b"singularity-sync/v1/x25519-p2p";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MnemonicError {
    #[error("Invalid mnemonic word count: expected {expected}, got {actual}")]
    InvalidWordCount { expected: usize, actual: usize },
    #[error("Unknown word at position {index}: '{word}' is not in the Singularity 2048-word dictionary")]
    UnknownWord { index: usize, word: String },
    #[error("Mnemonic SHA-256 checksum verification failed (typo or corrupted phrase)")]
    ChecksumMismatch,
    #[error("25th daily rotating anti-replay word is expired or invalid for UTC date {utc_date}")]
    ExpiredOrInvalid25thWord { utc_date: String },
    #[error("HKDF-SHA256 output length {0} exceeds RFC 5869 maximum (8160 bytes)")]
    HkdfInvalidLength(usize),
}

/// 256-bit secret key material that is automatically zeroized from RAM when dropped
/// and redacted in `Debug` output.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey32 {
    bytes: [u8; 32],
}

impl SecretKey32 {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    pub fn ct_eq_bytes(&self, other: &Self) -> bool {
        bool::from(self.bytes.ct_eq(&other.bytes))
    }
}

impl fmt::Debug for SecretKey32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey32([REDACTED])")
    }
}

/// Complete domain-separated key hierarchy derived from a 24-word sync mnemonic via HKDF-SHA256.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SyncMasterKeys {
    /// Public 64-char hex chain identifier safe for routing/discovery (reveals no key material).
    #[zeroize(skip)]
    pub chain_id: String,
    identity_seed: SecretKey32,
    content_encryption_key: SecretKey32,
    vault_subkey: SecretKey32,
    p2p_x25519_seed: SecretKey32,
    hkdf_prk: SecretKey32,
}

impl fmt::Debug for SyncMasterKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SyncMasterKeys")
            .field("chain_id", &self.chain_id)
            .field("identity_seed", &"[REDACTED]")
            .field("content_encryption_key", &"[REDACTED]")
            .field("vault_subkey", &"[REDACTED]")
            .field("p2p_x25519_seed", &"[REDACTED]")
            .finish()
    }
}

impl SyncMasterKeys {
    /// Returns the chain's Ed25519 identity signing key.
    pub fn identity_signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(self.identity_seed.as_bytes())
    }

    /// Returns the chain's Ed25519 identity verifying (public) key.
    pub fn identity_verifying_key(&self) -> VerifyingKey {
        self.identity_signing_key().verifying_key()
    }

    /// Returns the chain's Ed25519 public key encoded as lowercase hex.
    pub fn identity_pubkey_hex(&self) -> String {
        hex::encode(self.identity_verifying_key().as_bytes())
    }

    /// Returns the 256-bit XChaCha20-Poly1305 content encryption key (`ZeroizeOnDrop`).
    pub fn content_encryption_key(&self) -> &SecretKey32 {
        &self.content_encryption_key
    }

    /// Returns the domain-separated 256-bit Vault synchronization sub-key (`ZeroizeOnDrop`).
    pub fn vault_subkey(&self) -> &SecretKey32 {
        &self.vault_subkey
    }

    /// Returns the chain's static X25519 secret key for P2P peer handshakes.
    pub fn p2p_x25519_secret(&self) -> X25519StaticSecret {
        X25519StaticSecret::from(*self.p2p_x25519_seed.as_bytes())
    }

    /// Returns the chain's static X25519 public key.
    pub fn p2p_x25519_public(&self) -> X25519PublicKey {
        X25519PublicKey::from(&self.p2p_x25519_secret())
    }

    /// Derives an additional 32-byte domain-separated subkey from the HKDF PRK.
    pub fn derive_custom_subkey(&self, domain_info: &[u8]) -> SecretKey32 {
        let mut out = [0u8; 32];
        hkdf_sha256_expand(self.hkdf_prk.as_bytes(), domain_info, &mut out)
            .expect("32-byte HKDF output is always within RFC 5869 bounds");
        SecretKey32::from_bytes(out)
    }
}

/// A validated 256-bit zero-knowledge sync mnemonic (24 permanent words + daily rotating 25th word).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SyncMnemonic {
    entropy: [u8; 32],
}

impl fmt::Debug for SyncMnemonic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SyncMnemonic([REDACTED 256-BIT ENTROPY])")
    }
}

impl SyncMnemonic {
    /// Generates a brand-new cryptographically random 256-bit mnemonic using `OsRng`.
    pub fn generate() -> Self {
        let mut entropy = [0u8; 32];
        OsRng.fill_bytes(&mut entropy);
        Self { entropy }
    }

    /// Creates a mnemonic directly from raw 256-bit entropy bytes.
    pub fn from_entropy(entropy: [u8; 32]) -> Self {
        Self { entropy }
    }

    /// Exposes the raw 256-bit entropy slice (handle with care; zeroized on drop).
    pub fn entropy_bytes(&self) -> &[u8; 32] {
        &self.entropy
    }

    /// Encodes the 256-bit entropy + 8-bit SHA-256 checksum into 24 words from `WORDLIST`.
    pub fn to_24_words(&self) -> [&'static str; PERMANENT_WORD_COUNT] {
        let checksum_byte = Sha256::digest(self.entropy)[0];
        let mut bits_264 = [0u8; 33];
        bits_264[..32].copy_from_slice(&self.entropy);
        bits_264[32] = checksum_byte;

        let mut words = [""; PERMANENT_WORD_COUNT];
        for (i, slot) in words.iter_mut().enumerate() {
            let idx = extract_11_bits(&bits_264, i * 11) as usize;
            *slot = WORDLIST[idx];
        }
        bits_264.zeroize();
        words
    }

    /// Returns the space-separated 24-word permanent sync phrase.
    pub fn to_24_word_phrase(&self) -> String {
        self.to_24_words().join(" ")
    }

    /// Computes the Brave Sync v2-style 25th daily rotating anti-replay word for `utc_unix_secs`.
    pub fn daily_25th_word(&self, utc_unix_secs: u64) -> &'static str {
        compute_daily_25th_word(&self.entropy, utc_unix_secs)
    }

    /// Returns the 25-word time-bound enrollment phrase (24 permanent words + daily 25th word).
    pub fn to_25_word_phrase(&self, utc_unix_secs: u64) -> String {
        let mut words = Vec::with_capacity(ENROLLMENT_WORD_COUNT);
        words.extend_from_slice(&self.to_24_words());
        words.push(self.daily_25th_word(utc_unix_secs));
        words.join(" ")
    }

    /// Parses and validates a permanent 24-word mnemonic phrase (verifying the 8-bit SHA-256 checksum).
    pub fn from_24_words(phrase: &str) -> Result<Self, MnemonicError> {
        let tokens: Vec<String> = phrase
            .split_whitespace()
            .map(|w| w.trim().to_ascii_lowercase())
            .collect();
        if tokens.len() != PERMANENT_WORD_COUNT {
            return Err(MnemonicError::InvalidWordCount {
                expected: PERMANENT_WORD_COUNT,
                actual: tokens.len(),
            });
        }

        let mut bits_264 = [0u8; 33];
        for (i, token) in tokens.iter().enumerate() {
            let idx = lookup_word_index(token).ok_or_else(|| MnemonicError::UnknownWord {
                index: i,
                word: token.clone(),
            })?;
            write_11_bits(&mut bits_264, i * 11, idx as u16);
        }

        let mut entropy = [0u8; 32];
        entropy.copy_from_slice(&bits_264[..32]);
        let provided_checksum = bits_264[32];
        bits_264.zeroize();

        let expected_checksum = Sha256::digest(entropy)[0];
        if !bool::from(provided_checksum.ct_eq(&expected_checksum)) {
            entropy.zeroize();
            return Err(MnemonicError::ChecksumMismatch);
        }

        Ok(Self { entropy })
    }

    /// Parses and strictly validates a 25-word enrollment phrase against `utc_unix_secs`
    /// (exact UTC calendar day match; rejects replayed phrases from earlier/future days).
    pub fn from_25_words(phrase: &str, utc_unix_secs: u64) -> Result<Self, MnemonicError> {
        Self::from_25_words_with_day_tolerance(phrase, utc_unix_secs, 0)
    }

    /// Parses and validates a 25-word enrollment phrase allowing up to `tolerance_days`
    /// (e.g., `1` for midnight UTC clock skew; `0` for strict same-day anti-replay).
    pub fn from_25_words_with_day_tolerance(
        phrase: &str,
        utc_unix_secs: u64,
        tolerance_days: u64,
    ) -> Result<Self, MnemonicError> {
        let tokens: Vec<String> = phrase
            .split_whitespace()
            .map(|w| w.trim().to_ascii_lowercase())
            .collect();
        if tokens.len() != ENROLLMENT_WORD_COUNT {
            return Err(MnemonicError::InvalidWordCount {
                expected: ENROLLMENT_WORD_COUNT,
                actual: tokens.len(),
            });
        }

        let permanent_phrase = tokens[..PERMANENT_WORD_COUNT].join(" ");
        let mnemonic = Self::from_24_words(&permanent_phrase)?;

        let provided_25th = &tokens[PERMANENT_WORD_COUNT];
        let provided_idx = lookup_word_index(provided_25th).ok_or_else(|| {
            MnemonicError::UnknownWord {
                index: PERMANENT_WORD_COUNT,
                word: provided_25th.clone(),
            }
        })? as u16;

        let today = utc_day_number(utc_unix_secs);
        let min_day = today.saturating_sub(tolerance_days);
        let max_day = today.saturating_add(tolerance_days);

        let mut matched = subtle::Choice::from(0u8);
        for day in min_day..=max_day {
            let expected_idx = compute_daily_25th_word_index(&mnemonic.entropy, day);
            matched |= provided_idx.ct_eq(&expected_idx);
        }

        if !bool::from(matched) {
            return Err(MnemonicError::ExpiredOrInvalid25thWord {
                utc_date: format_utc_date(utc_unix_secs),
            });
        }

        Ok(mnemonic)
    }

    /// Derives the complete domain-separated `SyncMasterKeys` hierarchy using RFC 5869 HKDF-SHA256.
    pub fn derive_master_keys(&self) -> SyncMasterKeys {
        self.derive_master_keys_with_passphrase(b"")
    }

    /// Derives `SyncMasterKeys` using RFC 5869 HKDF-SHA256 with an optional extra user passphrase.
    pub fn derive_master_keys_with_passphrase(&self, optional_passphrase: &[u8]) -> SyncMasterKeys {
        let mut salt = Vec::with_capacity(HKDF_SALT.len() + 1 + optional_passphrase.len());
        salt.extend_from_slice(HKDF_SALT);
        if !optional_passphrase.is_empty() {
            salt.push(0x00);
            salt.extend_from_slice(optional_passphrase);
        }

        let prk = hkdf_sha256_extract(&salt, &self.entropy);
        salt.zeroize();

        let mut chain_id_bytes = [0u8; 32];
        let mut identity_seed = [0u8; 32];
        let mut content_key = [0u8; 32];
        let mut vault_subkey = [0u8; 32];
        let mut x25519_seed = [0u8; 32];

        hkdf_sha256_expand(&prk, DOMAIN_CHAIN_ID, &mut chain_id_bytes)
            .expect("32-byte HKDF output");
        hkdf_sha256_expand(&prk, DOMAIN_ED25519_IDENTITY, &mut identity_seed)
            .expect("32-byte HKDF output");
        hkdf_sha256_expand(&prk, DOMAIN_CONTENT_KEY, &mut content_key)
            .expect("32-byte HKDF output");
        hkdf_sha256_expand(&prk, DOMAIN_VAULT_SUBKEY, &mut vault_subkey)
            .expect("32-byte HKDF output");
        hkdf_sha256_expand(&prk, DOMAIN_X25519_P2P, &mut x25519_seed)
            .expect("32-byte HKDF output");

        let chain_id = hex::encode(chain_id_bytes);
        chain_id_bytes.zeroize();

        SyncMasterKeys {
            chain_id,
            identity_seed: SecretKey32::from_bytes(identity_seed),
            content_encryption_key: SecretKey32::from_bytes(content_key),
            vault_subkey: SecretKey32::from_bytes(vault_subkey),
            p2p_x25519_seed: SecretKey32::from_bytes(x25519_seed),
            hkdf_prk: SecretKey32::from_bytes(prk),
        }
    }
}

/// Returns the number of whole UTC days since the Unix epoch (1970-01-01).
pub fn utc_day_number(utc_unix_secs: u64) -> u64 {
    utc_unix_secs / 86_400
}

/// Formats `utc_unix_secs` as an ISO-8601 UTC date string (`YYYY-MM-DD`) in pure Rust.
pub fn format_utc_date(utc_unix_secs: u64) -> String {
    // Howard Hinnant's civil-from-days algorithm (exact for all proleptic Gregorian dates).
    let z = utc_day_number(utc_unix_secs) as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = y + if m <= 2 { 1 } else { 0 };
    format!("{year:04}-{m:02}-{d:02}")
}

/// Computes the 25th daily rotating word bound to the sync chain entropy and the UTC calendar day.
pub fn compute_daily_25th_word(entropy: &[u8; 32], utc_unix_secs: u64) -> &'static str {
    let idx = compute_daily_25th_word_index(entropy, utc_day_number(utc_unix_secs)) as usize;
    WORDLIST[idx]
}

fn compute_daily_25th_word_index(entropy: &[u8; 32], utc_day: u64) -> u16 {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(entropy)
        .expect("HMAC-SHA256 accepts any key length");
    mac.update(DOMAIN_DAILY_WORD);
    mac.update(&utc_day.to_be_bytes());
    let tag = mac.finalize().into_bytes();
    let raw = u16::from_be_bytes([tag[0], tag[1]]);
    raw & 0x07FF // 11 bits -> 0..2048
}

/// Looks up a lowercase word in the sorted 2048-word dictionary in O(log n).
pub fn lookup_word_index(word: &str) -> Option<usize> {
    WORDLIST.binary_search(&word).ok()
}

/// RFC 5869 HKDF-Extract using HMAC-SHA256.
pub fn hkdf_sha256_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let effective_salt = if salt.is_empty() { &[0u8; 32][..] } else { salt };
    let mut mac = <HmacSha256 as Mac>::new_from_slice(effective_salt)
        .expect("HMAC-SHA256 accepts any key length");
    mac.update(ikm);
    let result = mac.finalize().into_bytes();
    let mut prk = [0u8; 32];
    prk.copy_from_slice(&result);
    prk
}

/// RFC 5869 HKDF-Expand using HMAC-SHA256.
pub fn hkdf_sha256_expand(prk: &[u8; 32], info: &[u8], okm: &mut [u8]) -> Result<(), MnemonicError> {
    const HASH_LEN: usize = 32;
    const MAX_OUT: usize = 255 * HASH_LEN;
    if okm.len() > MAX_OUT {
        return Err(MnemonicError::HkdfInvalidLength(okm.len()));
    }
    if okm.is_empty() {
        return Ok(());
    }

    let mut prev: [u8; HASH_LEN] = [0u8; HASH_LEN];
    let mut has_prev = false;
    let mut offset = 0usize;
    let mut counter: u8 = 1;

    while offset < okm.len() {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(prk)
            .expect("HMAC-SHA256 accepts 32-byte PRK");
        if has_prev {
            mac.update(&prev);
        }
        mac.update(info);
        mac.update(&[counter]);
        let block = mac.finalize().into_bytes();
        prev.copy_from_slice(&block);
        has_prev = true;

        let take = (okm.len() - offset).min(HASH_LEN);
        okm[offset..offset + take].copy_from_slice(&prev[..take]);
        offset += take;
        counter = counter.wrapping_add(1);
    }
    prev.zeroize();
    Ok(())
}

fn extract_11_bits(data: &[u8], bit_offset: usize) -> u16 {
    let mut value: u16 = 0;
    for i in 0..11 {
        let pos = bit_offset + i;
        let byte = data[pos / 8];
        let bit = (byte >> (7 - (pos % 8))) & 1;
        value = (value << 1) | u16::from(bit);
    }
    value
}

fn write_11_bits(data: &mut [u8], bit_offset: usize, value: u16) {
    for i in 0..11 {
        let pos = bit_offset + i;
        let bit = ((value >> (10 - i)) & 1) as u8;
        if bit == 1 {
            data[pos / 8] |= 1 << (7 - (pos % 8));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn wordlist_is_exact_2048_unique_and_sorted() {
        assert_eq!(WORDLIST.len(), 2048);
        let unique: HashSet<&str> = WORDLIST.iter().copied().collect();
        assert_eq!(unique.len(), 2048);
        for pair in WORDLIST.windows(2) {
            assert!(pair[0] < pair[1], "Wordlist not strictly sorted: {} >= {}", pair[0], pair[1]);
        }
    }

    #[test]
    fn mnemonic_24_and_25_word_roundtrip_and_anti_replay() {
        let m = SyncMnemonic::generate();
        let phrase_24 = m.to_24_word_phrase();
        assert_eq!(phrase_24.split_whitespace().count(), 24);

        let restored_24 = SyncMnemonic::from_24_words(&phrase_24).expect("Valid 24-word phrase");
        assert_eq!(restored_24.entropy_bytes(), m.entropy_bytes());

        // Day 2026-11-26 UTC (~1795651200)
        let day_1 = 1_795_651_200u64;
        assert_eq!(format_utc_date(day_1), "2026-11-26");
        let phrase_25 = m.to_25_word_phrase(day_1);
        assert_eq!(phrase_25.split_whitespace().count(), 25);

        // Same day (different hour) succeeds
        let restored_25 =
            SyncMnemonic::from_25_words(&phrase_25, day_1 + 43_200).expect("Same UTC day");
        assert_eq!(restored_25.entropy_bytes(), m.entropy_bytes());

        // Previous day or next day fails strict anti-replay check
        assert!(matches!(
            SyncMnemonic::from_25_words(&phrase_25, day_1 + 86_400),
            Err(MnemonicError::ExpiredOrInvalid25thWord { .. })
        ));
        assert!(matches!(
            SyncMnemonic::from_25_words(&phrase_25, day_1 - 86_400),
            Err(MnemonicError::ExpiredOrInvalid25thWord { .. })
        ));

        // Tolerance of 1 day accepts midnight boundary skew
        assert!(SyncMnemonic::from_25_words_with_day_tolerance(&phrase_25, day_1 + 86_400, 1).is_ok());

        // Tampering with one word fails checksum
        let mut tampered: Vec<&str> = phrase_24.split_whitespace().collect();
        tampered[0] = if tampered[0] == WORDLIST[0] { WORDLIST[1] } else { WORDLIST[0] };
        assert!(matches!(
            SyncMnemonic::from_24_words(&tampered.join(" ")),
            Err(MnemonicError::ChecksumMismatch)
        ));
    }

    #[test]
    fn hkdf_domain_separation_produces_distinct_keys() {
        let m = SyncMnemonic::from_entropy([0x42u8; 32]);
        let k1 = m.derive_master_keys();
        let k2 = m.derive_master_keys();
        assert_eq!(k1.chain_id, k2.chain_id);
        assert_eq!(k1.chain_id.len(), 64);
        assert!(k1.content_encryption_key().ct_eq_bytes(k2.content_encryption_key()));
        assert!(k1.vault_subkey().ct_eq_bytes(k2.vault_subkey()));

        // Domain separation: content key != vault subkey != identity seed
        assert!(!k1.content_encryption_key().ct_eq_bytes(k1.vault_subkey()));
        assert_ne!(
            k1.content_encryption_key().as_bytes(),
            k1.identity_signing_key().to_bytes().as_slice()
        );

        // Passphrase changes all derived keys
        let k_pass = m.derive_master_keys_with_passphrase(b"extra-passphrase");
        assert_ne!(k1.chain_id, k_pass.chain_id);
        assert!(!k1.content_encryption_key().ct_eq_bytes(k_pass.content_encryption_key()));

        // Debug redaction check
        let dbg = format!("{k1:?}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains(&hex::encode(k1.content_encryption_key().as_bytes())));
    }
}
