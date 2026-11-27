//! Argon2id Key Derivation (RFC 9106), HKDF-SHA256 (RFC 5869), XChaCha20-Poly1305 AEAD,
//! Multi-Slot DEK/KEK Wrapping, STREAM AEAD Attachments, and Ephemeral Singularity Send.

use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key, XChaCha20Poly1305, XNonce,
};
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fmt;
use subtle::ConstantTimeEq;
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Error)]
pub enum VaultCryptoError {
    #[error("Invalid Argon2id parameters: {0}")]
    InvalidArgon2Params(String),
    #[error("Argon2id key derivation failed: {0}")]
    KdfFailed(String),
    #[error("XChaCha20-Poly1305 AEAD encryption failed")]
    EncryptionFailed,
    #[error("XChaCha20-Poly1305 AEAD authentication/decryption failed (wrong master password or tampered vault)")]
    DecryptionFailed,
    #[error("Invalid key length or encoding: {0}")]
    InvalidKey(String),
    #[error("Invalid recovery key format: {0}")]
    InvalidRecoveryKey(String),
    #[error("PIN slot has been permanently destroyed after reaching maximum failed attempts")]
    PinSlotDestroyed,
    #[error("Requested DEK wrapping slot was not found: {0}")]
    SlotNotFound(String),
    #[error("STREAM attachment error: {0}")]
    StreamAttachmentError(String),
    #[error("Ephemeral Singularity Send expired or view limit reached: {0}")]
    SendExpiredOrExhausted(String),
    #[error("Unsupported vault schema version: {0}")]
    UnsupportedVersion(String),
}

/// Safe bounds for untrusted `.singularity-vault` Argon2id headers (prevents OOM/CPU DoS).
pub const MIN_ARGON2_MEMORY_KIB: u32 = 4_096;
pub const MAX_ARGON2_MEMORY_KIB: u32 = 1_048_576; // 1 GiB
pub const MIN_ARGON2_ITERATIONS: u32 = 1;
pub const MAX_ARGON2_ITERATIONS: u32 = 64;
pub const MIN_ARGON2_PARALLELISM: u32 = 1;
pub const MAX_ARGON2_PARALLELISM: u32 = 16;

/// Default maximum failed attempts for PIN DEK slot before automatic slot destruction.
pub const DEFAULT_PIN_MAX_ATTEMPTS: u8 = 5;

/// Standard STREAM AEAD chunk size for encrypted vault attachments (64 KiB).
pub const ATTACHMENT_CHUNK_SIZE: usize = 64 * 1024;

/// Constant-time byte slice comparison backed by `subtle::ConstantTimeEq`.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    bool::from(a.ct_eq(b))
}

/// RFC 5869 HKDF-Extract using HMAC-SHA256.
pub fn hkdf_sha256_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let effective_salt: &[u8] = if salt.is_empty() { &[0u8; 32] } else { salt };
    let mut mac = <HmacSha256 as Mac>::new_from_slice(effective_salt)
        .expect("HMAC-SHA256 accepts any key size");
    mac.update(ikm);
    let mut prk = [0u8; 32];
    prk.copy_from_slice(&mac.finalize().into_bytes());
    prk
}

/// RFC 5869 HKDF-Expand using HMAC-SHA256 (supports up to 255 * 32 = 8160 bytes).
pub fn hkdf_sha256_expand(
    prk: &[u8; 32],
    info: &[u8],
    okm: &mut [u8],
) -> Result<(), VaultCryptoError> {
    if okm.len() > 255 * 32 {
        return Err(VaultCryptoError::KdfFailed(
            "HKDF-SHA256 output length exceeds 255 * 32 bytes".into(),
        ));
    }
    if okm.is_empty() {
        return Ok(());
    }
    let mut prev: Vec<u8> = Vec::new();
    let mut offset = 0usize;
    let mut counter: u8 = 1;

    while offset < okm.len() {
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(prk).expect("HMAC-SHA256 accepts any key size");
        mac.update(&prev);
        mac.update(info);
        mac.update(&[counter]);
        let mut block = mac.finalize().into_bytes();

        let take = (okm.len() - offset).min(block.len());
        okm[offset..offset + take].copy_from_slice(&block[..take]);

        prev.zeroize();
        prev.clear();
        prev.extend_from_slice(&block);
        block.zeroize();

        offset += take;
        counter = counter.wrapping_add(1);
    }
    prev.zeroize();
    Ok(())
}

/// One-shot RFC 5869 HKDF-SHA256 (Extract + Expand).
pub fn hkdf_sha256(
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
    okm: &mut [u8],
) -> Result<(), VaultCryptoError> {
    let mut prk = hkdf_sha256_extract(salt, ikm);
    let res = hkdf_sha256_expand(&prk, info, okm);
    prk.zeroize();
    res
}

/// Argon2id tuning parameters persisted in the `.singularity-vault` header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Argon2idConfig {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Argon2idConfig {
    pub fn validate_bounds(&self) -> Result<(), VaultCryptoError> {
        if !(MIN_ARGON2_MEMORY_KIB..=MAX_ARGON2_MEMORY_KIB).contains(&self.memory_kib) {
            return Err(VaultCryptoError::InvalidArgon2Params(format!(
                "memory_kib {} out of allowed range {}..={}",
                self.memory_kib, MIN_ARGON2_MEMORY_KIB, MAX_ARGON2_MEMORY_KIB
            )));
        }
        if !(MIN_ARGON2_ITERATIONS..=MAX_ARGON2_ITERATIONS).contains(&self.iterations) {
            return Err(VaultCryptoError::InvalidArgon2Params(format!(
                "iterations {} out of allowed range {}..={}",
                self.iterations, MIN_ARGON2_ITERATIONS, MAX_ARGON2_ITERATIONS
            )));
        }
        if !(MIN_ARGON2_PARALLELISM..=MAX_ARGON2_PARALLELISM).contains(&self.parallelism) {
            return Err(VaultCryptoError::InvalidArgon2Params(format!(
                "parallelism {} out of allowed range {}..={}",
                self.parallelism, MIN_ARGON2_PARALLELISM, MAX_ARGON2_PARALLELISM
            )));
        }
        Ok(())
    }
}

impl Default for Argon2idConfig {
    fn default() -> Self {
        Self {
            memory_kib: 19456, // OWASP recommended minimum Argon2id memory cost (19 MiB fast default; configurable up to 1 GiB)
            iterations: 2,
            parallelism: 2,
        }
    }
}

/// 256-bit derived master key that is automatically zeroized from RAM when dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DerivedVaultKey {
    bytes: [u8; 32],
}

impl fmt::Debug for DerivedVaultKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DerivedVaultKey([REDACTED])")
    }
}

impl DerivedVaultKey {
    /// Constructs a `DerivedVaultKey` from raw 32-byte key material.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Returns a borrowed view of the 32-byte key material.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Derives a domain-separated 256-bit subkey via HKDF-SHA256.
    pub fn derive_subkey(&self, salt: &[u8], info: &[u8]) -> Result<Self, VaultCryptoError> {
        let mut okm = [0u8; 32];
        hkdf_sha256(salt, &self.bytes, info, &mut okm)?;
        Ok(Self { bytes: okm })
    }

    /// Derives a 256-bit key from `master_password` and a 256-bit random `salt` via Argon2id v0x13.
    pub fn derive_argon2id(
        master_password: &[u8],
        salt: &[u8; 32],
        cfg: Argon2idConfig,
    ) -> Result<Self, VaultCryptoError> {
        cfg.validate_bounds()?;
        let params = Params::new(cfg.memory_kib, cfg.iterations, cfg.parallelism, Some(32))
            .map_err(|e| VaultCryptoError::InvalidArgon2Params(e.to_string()))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut derived = Self { bytes: [0u8; 32] };
        argon2
            .hash_password_into(master_password, salt, &mut derived.bytes)
            .map_err(|e| VaultCryptoError::KdfFailed(e.to_string()))?;

        Ok(derived)
    }

    /// Encrypts `plaintext` with 192-bit nonce XChaCha20-Poly1305 and authenticated associated data (`aad`).
    pub fn encrypt_xchacha20_poly1305(
        &self,
        plaintext: &[u8],
        nonce_24: &[u8; 24],
        aad: &[u8],
    ) -> Result<Vec<u8>, VaultCryptoError> {
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&self.bytes));
        let nonce = XNonce::from_slice(nonce_24);
        cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| VaultCryptoError::EncryptionFailed)
    }

    /// Decrypts and verifies `ciphertext` with 192-bit nonce XChaCha20-Poly1305 and `aad`.
    pub fn decrypt_xchacha20_poly1305(
        &self,
        ciphertext: &[u8],
        nonce_24: &[u8; 24],
        aad: &[u8],
    ) -> Result<Vec<u8>, VaultCryptoError> {
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&self.bytes));
        let nonce = XNonce::from_slice(nonce_24);
        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| VaultCryptoError::DecryptionFailed)
    }
}

/// Generates a cryptographically random 256-bit salt and 192-bit XChaCha20 nonce.
pub fn generate_salt_and_xnonce() -> ([u8; 32], [u8; 24]) {
    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);
    (salt, nonce)
}

/// Random 256-bit Vault Data Encryption Key (DEK) wrapped by one or more KEK slots.
/// Automatically zeroized from memory when dropped.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DataEncryptionKey {
    bytes: [u8; 32],
}

impl fmt::Debug for DataEncryptionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DataEncryptionKey([REDACTED])")
    }
}

impl DataEncryptionKey {
    /// Generates a fresh cryptographically random 256-bit DEK from `OsRng`.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self { bytes }
    }

    /// Wraps raw 32-byte key material as a `DataEncryptionKey`.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Returns the raw 32-byte DEK slice.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Derives a domain-separated 256-bit subkey from this DEK using HKDF-SHA256.
    pub fn derive_subkey(
        &self,
        salt: &[u8],
        info: &[u8],
    ) -> Result<DerivedVaultKey, VaultCryptoError> {
        let mut okm = [0u8; 32];
        hkdf_sha256(salt, &self.bytes, info, &mut okm)?;
        Ok(DerivedVaultKey::from_bytes(okm))
    }

    /// Encrypts `plaintext` directly with this DEK using XChaCha20-Poly1305.
    pub fn encrypt_xchacha20_poly1305(
        &self,
        plaintext: &[u8],
        nonce_24: &[u8; 24],
        aad: &[u8],
    ) -> Result<Vec<u8>, VaultCryptoError> {
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&self.bytes));
        let nonce = XNonce::from_slice(nonce_24);
        cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| VaultCryptoError::EncryptionFailed)
    }

    /// Decrypts `ciphertext` directly with this DEK using XChaCha20-Poly1305.
    pub fn decrypt_xchacha20_poly1305(
        &self,
        ciphertext: &[u8],
        nonce_24: &[u8; 24],
        aad: &[u8],
    ) -> Result<Vec<u8>, VaultCryptoError> {
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&self.bytes));
        let nonce = XNonce::from_slice(nonce_24);
        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| VaultCryptoError::DecryptionFailed)
    }
}

/// 256-bit emergency recovery key formatted in human-readable RFC 4648 Base32 groups.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RecoveryKey256 {
    bytes: [u8; 32],
}

impl fmt::Debug for RecoveryKey256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryKey256([REDACTED])")
    }
}

const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Encodes a 256-bit key into 13 hyphen-separated groups of 4 uppercase RFC 4648 Base32 characters.
pub fn format_recovery_key_base32(key: &[u8; 32]) -> String {
    let mut raw = String::with_capacity(52);
    let mut bit_buffer: u32 = 0;
    let mut bit_count: u8 = 0;

    for &byte in key {
        bit_buffer = (bit_buffer << 8) | u32::from(byte);
        bit_count += 8;
        while bit_count >= 5 {
            bit_count -= 5;
            let idx = ((bit_buffer >> bit_count) & 0x1F) as usize;
            raw.push(BASE32_ALPHABET[idx] as char);
        }
    }
    if bit_count > 0 {
        let idx = ((bit_buffer << (5 - bit_count)) & 0x1F) as usize;
        raw.push(BASE32_ALPHABET[idx] as char);
    }

    let mut grouped = String::with_capacity(64);
    for (i, ch) in raw.chars().enumerate() {
        if i > 0 && i % 4 == 0 {
            grouped.push('-');
        }
        grouped.push(ch);
    }
    raw.zeroize();
    grouped
}

/// Parses a Base32-grouped 256-bit emergency recovery key (case-insensitive, ignores spaces/hyphens).
pub fn parse_recovery_key_base32(formatted: &str) -> Result<[u8; 32], VaultCryptoError> {
    let mut bit_buffer: u32 = 0;
    let mut bit_count: u8 = 0;
    let mut out = Vec::with_capacity(32);

    for ch in formatted.chars() {
        if ch == '-' || ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' || ch == '=' {
            continue;
        }
        let val: u32 = match ch.to_ascii_uppercase() {
            'A'..='Z' => (ch.to_ascii_uppercase() as u32) - ('A' as u32),
            '2'..='7' => (ch as u32) - ('2' as u32) + 26,
            other => {
                out.zeroize();
                return Err(VaultCryptoError::InvalidRecoveryKey(format!(
                    "Invalid Base32 character '{}'",
                    other
                )));
            }
        };
        bit_buffer = (bit_buffer << 5) | val;
        bit_count += 5;
        if bit_count >= 8 {
            bit_count -= 8;
            out.push(((bit_buffer >> bit_count) & 0xFF) as u8);
        }
    }

    // Verify canonical zero padding bits
    if bit_count > 0 && (bit_buffer & ((1u32 << bit_count) - 1)) != 0 {
        out.zeroize();
        return Err(VaultCryptoError::InvalidRecoveryKey(
            "Non-zero trailing padding bits in Base32 recovery key".into(),
        ));
    }

    if out.len() != 32 {
        let len = out.len();
        out.zeroize();
        return Err(VaultCryptoError::InvalidRecoveryKey(format!(
            "Expected 32-byte (256-bit) recovery key, decoded {} bytes",
            len
        )));
    }

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    out.zeroize();
    Ok(arr)
}

impl RecoveryKey256 {
    /// Generates a new cryptographically random 256-bit emergency recovery key.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self { bytes }
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    pub fn to_formatted_base32(&self) -> String {
        format_recovery_key_base32(&self.bytes)
    }

    pub fn from_formatted_base32(formatted: &str) -> Result<Self, VaultCryptoError> {
        Ok(Self {
            bytes: parse_recovery_key_base32(formatted)?,
        })
    }
}

/// Kind of Key Encryption Key (KEK) slot wrapping the Vault DEK in V2 envelopes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "slot_type", rename_all = "snake_case")]
pub enum DekSlotKind {
    MasterPassword {
        kdf_config: Argon2idConfig,
        salt_base64: String,
    },
    BiometricOs {
        key_label: String,
        salt_base64: String,
    },
    PinCode {
        kdf_config: Argon2idConfig,
        salt_base64: String,
        failed_attempts: u8,
        max_attempts: u8,
    },
    RecoveryKey256 {
        salt_base64: String,
    },
}

/// A wrapped DEK slot allowing independent unlock methods (Master Password, OS Biometrics,
/// PIN with automatic destruction after `max_attempts`, and 256-bit Recovery Key).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedDekSlot {
    pub slot_id: String,
    pub kind: DekSlotKind,
    pub wrap_xnonce_base64: String,
    pub wrapped_dek_base64: String,
    pub created_at_unix: u64,
    #[serde(default)]
    pub destroyed: bool,
}

fn build_slot_aad(
    slot_id: &str,
    slot_tag: &str,
    salt: &[u8; 32],
    xnonce: &[u8; 24],
    extra: &[u8],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(64 + slot_id.len() + slot_tag.len() + extra.len());
    aad.extend_from_slice(b"SINGULARITY-DEK-SLOT-V2:");
    aad.extend_from_slice(slot_tag.as_bytes());
    aad.push(b':');
    aad.extend_from_slice(slot_id.as_bytes());
    aad.extend_from_slice(salt);
    aad.extend_from_slice(xnonce);
    aad.extend_from_slice(extra);
    aad
}

fn decode_32_b64(s: &str) -> Result<[u8; 32], VaultCryptoError> {
    let v = BASE64
        .decode(s)
        .map_err(|_| VaultCryptoError::DecryptionFailed)?;
    v.try_into().map_err(|_| VaultCryptoError::DecryptionFailed)
}

fn decode_24_b64(s: &str) -> Result<[u8; 24], VaultCryptoError> {
    let v = BASE64
        .decode(s)
        .map_err(|_| VaultCryptoError::DecryptionFailed)?;
    v.try_into().map_err(|_| VaultCryptoError::DecryptionFailed)
}

impl WrappedDekSlot {
    /// Returns `true` if this slot has been permanently destroyed (e.g. PIN exceeded attempts).
    pub fn is_destroyed(&self) -> bool {
        self.destroyed
    }

    /// Permanently destroys this slot by wiping its wrapped ciphertext and nonce.
    pub fn destroy(&mut self) {
        self.wrapped_dek_base64.zeroize();
        self.wrapped_dek_base64.clear();
        self.wrap_xnonce_base64.zeroize();
        self.wrap_xnonce_base64.clear();
        self.destroyed = true;
    }

    /// Wraps `dek` in a `MasterPassword` Argon2id KEK slot.
    pub fn wrap_master_password(
        slot_id: impl Into<String>,
        dek: &DataEncryptionKey,
        master_password: &[u8],
        kdf_config: Argon2idConfig,
        created_at_unix: u64,
    ) -> Result<Self, VaultCryptoError> {
        kdf_config.validate_bounds()?;
        let slot_id = slot_id.into();
        let (salt, xnonce) = generate_salt_and_xnonce();
        let kek = DerivedVaultKey::derive_argon2id(master_password, &salt, kdf_config)?;
        let mut extra = Vec::with_capacity(12);
        extra.extend_from_slice(&kdf_config.memory_kib.to_le_bytes());
        extra.extend_from_slice(&kdf_config.iterations.to_le_bytes());
        extra.extend_from_slice(&kdf_config.parallelism.to_le_bytes());
        let aad = build_slot_aad(&slot_id, "master_password", &salt, &xnonce, &extra);
        let wrapped = kek.encrypt_xchacha20_poly1305(dek.as_bytes(), &xnonce, &aad)?;

        Ok(Self {
            slot_id,
            kind: DekSlotKind::MasterPassword {
                kdf_config,
                salt_base64: BASE64.encode(salt),
            },
            wrap_xnonce_base64: BASE64.encode(xnonce),
            wrapped_dek_base64: BASE64.encode(wrapped),
            created_at_unix,
            destroyed: false,
        })
    }

    /// Wraps `dek` in an OS Biometric Keychain KEK slot (using HKDF-SHA256 over the OS secret).
    pub fn wrap_biometric_os(
        slot_id: impl Into<String>,
        dek: &DataEncryptionKey,
        key_label: impl Into<String>,
        biometric_os_secret: &[u8],
        created_at_unix: u64,
    ) -> Result<Self, VaultCryptoError> {
        if biometric_os_secret.len() < 16 {
            return Err(VaultCryptoError::InvalidKey(
                "OS biometric secret must be at least 16 bytes".into(),
            ));
        }
        let slot_id = slot_id.into();
        let key_label = key_label.into();
        let (salt, xnonce) = generate_salt_and_xnonce();
        let mut kek_bytes = [0u8; 32];
        hkdf_sha256(
            &salt,
            biometric_os_secret,
            b"singularity-vault-v2-biometric-kek",
            &mut kek_bytes,
        )?;
        let kek = DerivedVaultKey::from_bytes(kek_bytes);
        kek_bytes.zeroize();

        let aad = build_slot_aad(
            &slot_id,
            "biometric_os",
            &salt,
            &xnonce,
            key_label.as_bytes(),
        );
        let wrapped = kek.encrypt_xchacha20_poly1305(dek.as_bytes(), &xnonce, &aad)?;

        Ok(Self {
            slot_id,
            kind: DekSlotKind::BiometricOs {
                key_label,
                salt_base64: BASE64.encode(salt),
            },
            wrap_xnonce_base64: BASE64.encode(xnonce),
            wrapped_dek_base64: BASE64.encode(wrapped),
            created_at_unix,
            destroyed: false,
        })
    }

    /// Wraps `dek` in a PIN Code slot with bounded attempts (default 5) and automatic self-destruction.
    pub fn wrap_pin_code(
        slot_id: impl Into<String>,
        dek: &DataEncryptionKey,
        pin: &[u8],
        kdf_config: Argon2idConfig,
        max_attempts: u8,
        created_at_unix: u64,
    ) -> Result<Self, VaultCryptoError> {
        kdf_config.validate_bounds()?;
        if pin.is_empty() {
            return Err(VaultCryptoError::InvalidKey("PIN cannot be empty".into()));
        }
        let effective_max = if max_attempts == 0 {
            DEFAULT_PIN_MAX_ATTEMPTS
        } else {
            max_attempts
        };
        let slot_id = slot_id.into();
        let (salt, xnonce) = generate_salt_and_xnonce();
        let kek = DerivedVaultKey::derive_argon2id(pin, &salt, kdf_config)?;
        let mut extra = Vec::with_capacity(13);
        extra.extend_from_slice(&kdf_config.memory_kib.to_le_bytes());
        extra.extend_from_slice(&kdf_config.iterations.to_le_bytes());
        extra.extend_from_slice(&kdf_config.parallelism.to_le_bytes());
        extra.push(effective_max);
        let aad = build_slot_aad(&slot_id, "pin_code", &salt, &xnonce, &extra);
        let wrapped = kek.encrypt_xchacha20_poly1305(dek.as_bytes(), &xnonce, &aad)?;

        Ok(Self {
            slot_id,
            kind: DekSlotKind::PinCode {
                kdf_config,
                salt_base64: BASE64.encode(salt),
                failed_attempts: 0,
                max_attempts: effective_max,
            },
            wrap_xnonce_base64: BASE64.encode(xnonce),
            wrapped_dek_base64: BASE64.encode(wrapped),
            created_at_unix,
            destroyed: false,
        })
    }

    /// Wraps `dek` in a 256-bit Emergency Recovery Key slot.
    pub fn wrap_recovery_key(
        slot_id: impl Into<String>,
        dek: &DataEncryptionKey,
        recovery_key: &RecoveryKey256,
        created_at_unix: u64,
    ) -> Result<Self, VaultCryptoError> {
        let slot_id = slot_id.into();
        let (salt, xnonce) = generate_salt_and_xnonce();
        let mut kek_bytes = [0u8; 32];
        hkdf_sha256(
            &salt,
            recovery_key.as_bytes(),
            b"singularity-vault-v2-recovery-kek",
            &mut kek_bytes,
        )?;
        let kek = DerivedVaultKey::from_bytes(kek_bytes);
        kek_bytes.zeroize();

        let aad = build_slot_aad(&slot_id, "recovery_key_256", &salt, &xnonce, &[]);
        let wrapped = kek.encrypt_xchacha20_poly1305(dek.as_bytes(), &xnonce, &aad)?;

        Ok(Self {
            slot_id,
            kind: DekSlotKind::RecoveryKey256 {
                salt_base64: BASE64.encode(salt),
            },
            wrap_xnonce_base64: BASE64.encode(xnonce),
            wrapped_dek_base64: BASE64.encode(wrapped),
            created_at_unix,
            destroyed: false,
        })
    }

    /// Unwraps the DEK from a `MasterPassword` slot.
    pub fn unwrap_master_password(
        &self,
        master_password: &[u8],
    ) -> Result<DataEncryptionKey, VaultCryptoError> {
        if self.destroyed {
            return Err(VaultCryptoError::DecryptionFailed);
        }
        let DekSlotKind::MasterPassword {
            kdf_config,
            ref salt_base64,
        } = self.kind
        else {
            return Err(VaultCryptoError::SlotNotFound("master_password".into()));
        };
        kdf_config.validate_bounds()?;
        let salt = decode_32_b64(salt_base64)?;
        let xnonce = decode_24_b64(&self.wrap_xnonce_base64)?;
        let ciphertext = BASE64
            .decode(&self.wrapped_dek_base64)
            .map_err(|_| VaultCryptoError::DecryptionFailed)?;

        let kek = DerivedVaultKey::derive_argon2id(master_password, &salt, kdf_config)?;
        let mut extra = Vec::with_capacity(12);
        extra.extend_from_slice(&kdf_config.memory_kib.to_le_bytes());
        extra.extend_from_slice(&kdf_config.iterations.to_le_bytes());
        extra.extend_from_slice(&kdf_config.parallelism.to_le_bytes());
        let aad = build_slot_aad(&self.slot_id, "master_password", &salt, &xnonce, &extra);

        let mut pt = kek.decrypt_xchacha20_poly1305(&ciphertext, &xnonce, &aad)?;
        if pt.len() != 32 {
            pt.zeroize();
            return Err(VaultCryptoError::DecryptionFailed);
        }
        let mut dek_arr = [0u8; 32];
        dek_arr.copy_from_slice(&pt);
        pt.zeroize();
        let dek = DataEncryptionKey::from_bytes(dek_arr);
        dek_arr.zeroize();
        Ok(dek)
    }

    /// Unwraps the DEK from an OS Biometric slot.
    pub fn unwrap_biometric_os(
        &self,
        biometric_os_secret: &[u8],
    ) -> Result<DataEncryptionKey, VaultCryptoError> {
        if self.destroyed {
            return Err(VaultCryptoError::DecryptionFailed);
        }
        let DekSlotKind::BiometricOs {
            ref key_label,
            ref salt_base64,
        } = self.kind
        else {
            return Err(VaultCryptoError::SlotNotFound("biometric_os".into()));
        };
        let salt = decode_32_b64(salt_base64)?;
        let xnonce = decode_24_b64(&self.wrap_xnonce_base64)?;
        let ciphertext = BASE64
            .decode(&self.wrapped_dek_base64)
            .map_err(|_| VaultCryptoError::DecryptionFailed)?;

        let mut kek_bytes = [0u8; 32];
        hkdf_sha256(
            &salt,
            biometric_os_secret,
            b"singularity-vault-v2-biometric-kek",
            &mut kek_bytes,
        )?;
        let kek = DerivedVaultKey::from_bytes(kek_bytes);
        kek_bytes.zeroize();

        let aad = build_slot_aad(
            &self.slot_id,
            "biometric_os",
            &salt,
            &xnonce,
            key_label.as_bytes(),
        );
        let mut pt = kek.decrypt_xchacha20_poly1305(&ciphertext, &xnonce, &aad)?;
        if pt.len() != 32 {
            pt.zeroize();
            return Err(VaultCryptoError::DecryptionFailed);
        }
        let mut dek_arr = [0u8; 32];
        dek_arr.copy_from_slice(&pt);
        pt.zeroize();
        let dek = DataEncryptionKey::from_bytes(dek_arr);
        dek_arr.zeroize();
        Ok(dek)
    }

    /// Unwraps the DEK from a `PinCode` slot.
    /// Increments `failed_attempts` on incorrect PIN and permanently destroys the slot once
    /// `failed_attempts >= max_attempts` (default 5). Resets `failed_attempts` to 0 on success.
    pub fn unwrap_pin_code(&mut self, pin: &[u8]) -> Result<DataEncryptionKey, VaultCryptoError> {
        if self.destroyed {
            return Err(VaultCryptoError::PinSlotDestroyed);
        }
        let (kdf_config, salt_base64, failed_attempts, max_attempts) = match self.kind {
            DekSlotKind::PinCode {
                kdf_config,
                ref salt_base64,
                failed_attempts,
                max_attempts,
            } => (kdf_config, salt_base64.clone(), failed_attempts, max_attempts),
            _ => return Err(VaultCryptoError::SlotNotFound("pin_code".into())),
        };
        let effective_max = max_attempts.max(1);
        if failed_attempts >= effective_max {
            self.destroy();
            return Err(VaultCryptoError::PinSlotDestroyed);
        }
        kdf_config.validate_bounds()?;
        let salt = decode_32_b64(&salt_base64)?;
        let xnonce = decode_24_b64(&self.wrap_xnonce_base64)?;
        let ciphertext = BASE64
            .decode(&self.wrapped_dek_base64)
            .map_err(|_| VaultCryptoError::DecryptionFailed)?;

        let kek = DerivedVaultKey::derive_argon2id(pin, &salt, kdf_config)?;
        let mut extra = Vec::with_capacity(13);
        extra.extend_from_slice(&kdf_config.memory_kib.to_le_bytes());
        extra.extend_from_slice(&kdf_config.iterations.to_le_bytes());
        extra.extend_from_slice(&kdf_config.parallelism.to_le_bytes());
        extra.push(effective_max);
        let aad = build_slot_aad(&self.slot_id, "pin_code", &salt, &xnonce, &extra);

        match kek.decrypt_xchacha20_poly1305(&ciphertext, &xnonce, &aad) {
            Ok(mut pt) if pt.len() == 32 => {
                if let DekSlotKind::PinCode {
                    ref mut failed_attempts,
                    ..
                } = self.kind
                {
                    *failed_attempts = 0;
                }
                let mut dek_arr = [0u8; 32];
                dek_arr.copy_from_slice(&pt);
                pt.zeroize();
                let dek = DataEncryptionKey::from_bytes(dek_arr);
                dek_arr.zeroize();
                Ok(dek)
            }
            Ok(mut pt) => {
                pt.zeroize();
                Err(VaultCryptoError::DecryptionFailed)
            }
            Err(_) => {
                let mut should_destroy = false;
                if let DekSlotKind::PinCode {
                    ref mut failed_attempts,
                    ..
                } = self.kind
                {
                    *failed_attempts = failed_attempts.saturating_add(1);
                    if *failed_attempts >= effective_max {
                        should_destroy = true;
                    }
                }
                if should_destroy {
                    self.destroy();
                    Err(VaultCryptoError::PinSlotDestroyed)
                } else {
                    Err(VaultCryptoError::DecryptionFailed)
                }
            }
        }
    }

    /// Unwraps the DEK from a `RecoveryKey256` slot using a Base32-formatted recovery key.
    pub fn unwrap_recovery_key(
        &self,
        recovery_key_base32: &str,
    ) -> Result<DataEncryptionKey, VaultCryptoError> {
        if self.destroyed {
            return Err(VaultCryptoError::DecryptionFailed);
        }
        let DekSlotKind::RecoveryKey256 { ref salt_base64 } = self.kind else {
            return Err(VaultCryptoError::SlotNotFound("recovery_key_256".into()));
        };
        let recovery_key = RecoveryKey256::from_formatted_base32(recovery_key_base32)?;
        let salt = decode_32_b64(salt_base64)?;
        let xnonce = decode_24_b64(&self.wrap_xnonce_base64)?;
        let ciphertext = BASE64
            .decode(&self.wrapped_dek_base64)
            .map_err(|_| VaultCryptoError::DecryptionFailed)?;

        let mut kek_bytes = [0u8; 32];
        hkdf_sha256(
            &salt,
            recovery_key.as_bytes(),
            b"singularity-vault-v2-recovery-kek",
            &mut kek_bytes,
        )?;
        let kek = DerivedVaultKey::from_bytes(kek_bytes);
        kek_bytes.zeroize();

        let aad = build_slot_aad(&self.slot_id, "recovery_key_256", &salt, &xnonce, &[]);
        let mut pt = kek.decrypt_xchacha20_poly1305(&ciphertext, &xnonce, &aad)?;
        if pt.len() != 32 {
            pt.zeroize();
            return Err(VaultCryptoError::DecryptionFailed);
        }
        let mut dek_arr = [0u8; 32];
        dek_arr.copy_from_slice(&pt);
        pt.zeroize();
        let dek = DataEncryptionKey::from_bytes(dek_arr);
        dek_arr.zeroize();
        Ok(dek)
    }
}

/// Encrypted STREAM AEAD attachment sealed in 64 KiB XChaCha20-Poly1305 chunks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedAttachment {
    pub attachment_id: String,
    pub filename: String,
    pub mime_type: String,
    pub plaintext_size: u64,
    pub chunk_size: usize,
    pub salt_base64: String,
    pub nonce_prefix_base64: String,
    pub chunks_base64: Vec<String>,
}

fn build_stream_chunk_nonce(prefix_15: &[u8; 15], chunk_index: u64, is_final: bool) -> [u8; 24] {
    let mut nonce = [0u8; 24];
    nonce[..15].copy_from_slice(prefix_15);
    nonce[15..23].copy_from_slice(&chunk_index.to_le_bytes());
    nonce[23] = u8::from(is_final);
    nonce
}

fn build_stream_chunk_aad(
    attachment_id: &str,
    filename: &str,
    mime_type: &str,
    chunk_index: u64,
    is_final: bool,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(48 + attachment_id.len() + filename.len() + mime_type.len());
    aad.extend_from_slice(b"SINGULARITY-STREAM-ATTACHMENT-V2:");
    aad.extend_from_slice(attachment_id.as_bytes());
    aad.push(0);
    aad.extend_from_slice(filename.as_bytes());
    aad.push(0);
    aad.extend_from_slice(mime_type.as_bytes());
    aad.push(0);
    aad.extend_from_slice(&chunk_index.to_le_bytes());
    aad.push(u8::from(is_final));
    aad
}

/// Seals `plaintext` as an authenticated STREAM AEAD attachment in 64 KiB `XChaCha20-Poly1305` chunks
/// using a per-attachment HKDF-SHA256 subkey derived from `dek`.
pub fn seal_attachment_chunks(
    dek: &DataEncryptionKey,
    attachment_id: &str,
    filename: &str,
    mime_type: &str,
    plaintext: &[u8],
) -> Result<SealedAttachment, VaultCryptoError> {
    seal_attachment_chunks_with_chunk_size(
        dek,
        attachment_id,
        filename,
        mime_type,
        plaintext,
        ATTACHMENT_CHUNK_SIZE,
    )
}

/// Seals `plaintext` as an authenticated STREAM AEAD attachment with an explicit `chunk_size`.
pub fn seal_attachment_chunks_with_chunk_size(
    dek: &DataEncryptionKey,
    attachment_id: &str,
    filename: &str,
    mime_type: &str,
    plaintext: &[u8],
    chunk_size: usize,
) -> Result<SealedAttachment, VaultCryptoError> {
    if chunk_size == 0 {
        return Err(VaultCryptoError::StreamAttachmentError(
            "chunk_size must be greater than 0".into(),
        ));
    }
    if attachment_id.trim().is_empty() {
        return Err(VaultCryptoError::StreamAttachmentError(
            "attachment_id cannot be empty".into(),
        ));
    }

    let mut salt = [0u8; 32];
    let mut nonce_prefix = [0u8; 15];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce_prefix);

    let info = format!("singularity-vault-v2-attachment:{}", attachment_id);
    let subkey = dek.derive_subkey(&salt, info.as_bytes())?;

    let mut chunks_base64 = Vec::new();
    if plaintext.is_empty() {
        let nonce = build_stream_chunk_nonce(&nonce_prefix, 0, true);
        let aad = build_stream_chunk_aad(attachment_id, filename, mime_type, 0, true);
        let ct = subkey.encrypt_xchacha20_poly1305(&[], &nonce, &aad)?;
        chunks_base64.push(BASE64.encode(ct));
    } else {
        let total_chunks = plaintext.len().div_ceil(chunk_size);
        chunks_base64.reserve(total_chunks);
        for (idx, chunk) in plaintext.chunks(chunk_size).enumerate() {
            let is_final = idx + 1 == total_chunks;
            let nonce = build_stream_chunk_nonce(&nonce_prefix, idx as u64, is_final);
            let aad = build_stream_chunk_aad(attachment_id, filename, mime_type, idx as u64, is_final);
            let ct = subkey.encrypt_xchacha20_poly1305(chunk, &nonce, &aad)?;
            chunks_base64.push(BASE64.encode(ct));
        }
    }

    Ok(SealedAttachment {
        attachment_id: attachment_id.to_string(),
        filename: filename.to_string(),
        mime_type: mime_type.to_string(),
        plaintext_size: plaintext.len() as u64,
        chunk_size,
        salt_base64: BASE64.encode(salt),
        nonce_prefix_base64: BASE64.encode(nonce_prefix),
        chunks_base64,
    })
}

/// Unseals and authenticates a STREAM AEAD attachment, defeating chunk reordering, truncation,
/// or cross-attachment splicing.
pub fn unseal_attachment_chunks(
    dek: &DataEncryptionKey,
    sealed: &SealedAttachment,
) -> Result<Vec<u8>, VaultCryptoError> {
    if sealed.chunks_base64.is_empty() {
        return Err(VaultCryptoError::StreamAttachmentError(
            "Sealed attachment has no chunks".into(),
        ));
    }
    let salt = decode_32_b64(&sealed.salt_base64)?;
    let prefix_vec = BASE64
        .decode(&sealed.nonce_prefix_base64)
        .map_err(|_| VaultCryptoError::DecryptionFailed)?;
    let nonce_prefix: [u8; 15] = prefix_vec
        .try_into()
        .map_err(|_| VaultCryptoError::DecryptionFailed)?;

    let info = format!("singularity-vault-v2-attachment:{}", sealed.attachment_id);
    let subkey = dek.derive_subkey(&salt, info.as_bytes())?;

    let total_chunks = sealed.chunks_base64.len();
    let mut output = Zeroizing::new(Vec::with_capacity(
        sealed.plaintext_size.min(64 * 1024 * 1024) as usize,
    ));

    for (idx, chunk_b64) in sealed.chunks_base64.iter().enumerate() {
        let is_final = idx + 1 == total_chunks;
        let ct = BASE64
            .decode(chunk_b64)
            .map_err(|_| VaultCryptoError::DecryptionFailed)?;
        let nonce = build_stream_chunk_nonce(&nonce_prefix, idx as u64, is_final);
        let aad = build_stream_chunk_aad(
            &sealed.attachment_id,
            &sealed.filename,
            &sealed.mime_type,
            idx as u64,
            is_final,
        );
        let pt = Zeroizing::new(subkey.decrypt_xchacha20_poly1305(&ct, &nonce, &aad)?);
        output.extend_from_slice(&pt);
    }

    if output.len() as u64 != sealed.plaintext_size {
        return Err(VaultCryptoError::StreamAttachmentError(
            "Authenticated plaintext length mismatch".into(),
        ));
    }

    Ok(std::mem::take(&mut *output))
}

/// X25519 keypair used for asymmetric encrypted `Singularity Send` and CXP sharing.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SendX25519Keypair {
    secret_bytes: [u8; 32],
    #[zeroize(skip)]
    public_bytes: [u8; 32],
}

impl fmt::Debug for SendX25519Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SendX25519Keypair")
            .field("public_key_base64", &BASE64.encode(self.public_bytes))
            .field("secret_bytes", &"[REDACTED]")
            .finish()
    }
}

impl SendX25519Keypair {
    /// Generates a fresh random X25519 keypair using `OsRng`.
    pub fn generate() -> Self {
        let secret = X25519StaticSecret::random_from_rng(OsRng);
        let public = X25519PublicKey::from(&secret);
        Self {
            secret_bytes: secret.to_bytes(),
            public_bytes: public.to_bytes(),
        }
    }

    pub fn from_secret_bytes(secret_bytes: [u8; 32]) -> Self {
        let secret = X25519StaticSecret::from(secret_bytes);
        let public = X25519PublicKey::from(&secret);
        Self {
            secret_bytes: secret.to_bytes(),
            public_bytes: public.to_bytes(),
        }
    }

    pub fn public_key_bytes(&self) -> &[u8; 32] {
        &self.public_bytes
    }

    pub fn public_key_base64(&self) -> String {
        BASE64.encode(self.public_bytes)
    }

    pub fn secret_key_bytes(&self) -> &[u8; 32] {
        &self.secret_bytes
    }
}

/// Type of content transported inside an ephemeral `Singularity Send`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SendPayloadType {
    Text,
    File { filename: String, mime_type: String },
    VaultItem,
}

/// Protection mechanism for a `Singularity Send` envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum SendProtection {
    Password {
        kdf_config: Argon2idConfig,
        salt_base64: String,
    },
    X25519 {
        ephemeral_public_key_base64: String,
        salt_base64: String,
    },
}

/// Ephemeral encrypted sharing envelope (`Singularity Send`) protected by password (Argon2id)
/// or recipient X25519 public key, enforcing authenticated TTL and maximum view count.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SingularitySendEnvelope {
    pub send_id: String,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
    pub max_views: u32,
    pub current_views: u32,
    pub payload_type: SendPayloadType,
    pub protection: SendProtection,
    pub xnonce_base64: String,
    pub ciphertext_base64: String,
}

fn build_send_aad(
    send_id: &str,
    created_at_unix: u64,
    expires_at_unix: u64,
    max_views: u32,
    payload_type: &SendPayloadType,
    protection_bytes: &[u8],
    xnonce: &[u8; 24],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(96 + send_id.len() + protection_bytes.len());
    aad.extend_from_slice(b"SINGULARITY-SEND-V1:");
    aad.extend_from_slice(send_id.as_bytes());
    aad.extend_from_slice(&created_at_unix.to_le_bytes());
    aad.extend_from_slice(&expires_at_unix.to_le_bytes());
    aad.extend_from_slice(&max_views.to_le_bytes());
    match payload_type {
        SendPayloadType::Text => aad.extend_from_slice(b"text"),
        SendPayloadType::VaultItem => aad.extend_from_slice(b"vault_item"),
        SendPayloadType::File {
            filename,
            mime_type,
        } => {
            aad.extend_from_slice(b"file:");
            aad.extend_from_slice(filename.as_bytes());
            aad.push(0);
            aad.extend_from_slice(mime_type.as_bytes());
        }
    }
    aad.extend_from_slice(protection_bytes);
    aad.extend_from_slice(xnonce);
    aad
}

impl SingularitySendEnvelope {
    /// Returns `true` if the Send has expired at `now_unix` or exhausted its view budget.
    pub fn is_expired_or_exhausted(&self, now_unix: u64) -> bool {
        now_unix > self.expires_at_unix
            || self.current_views >= self.max_views
            || self.ciphertext_base64.is_empty()
    }

    /// Returns the number of remaining views before automatic self-destruction.
    pub fn remaining_views(&self) -> u32 {
        self.max_views.saturating_sub(self.current_views)
    }

    /// Creates a password-protected ephemeral `Singularity Send`.
    pub fn seal_with_password(
        send_id: impl Into<String>,
        plaintext: &[u8],
        payload_type: SendPayloadType,
        password: &[u8],
        kdf_config: Argon2idConfig,
        created_at_unix: u64,
        ttl_secs: u64,
        max_views: u32,
    ) -> Result<Self, VaultCryptoError> {
        if ttl_secs == 0 || max_views == 0 {
            return Err(VaultCryptoError::SendExpiredOrExhausted(
                "ttl_secs and max_views must be greater than 0".into(),
            ));
        }
        kdf_config.validate_bounds()?;
        let send_id = send_id.into();
        let expires_at_unix = created_at_unix.saturating_add(ttl_secs);
        let (salt, xnonce) = generate_salt_and_xnonce();
        let key = DerivedVaultKey::derive_argon2id(password, &salt, kdf_config)?;

        let mut prot_bytes = Vec::with_capacity(44);
        prot_bytes.extend_from_slice(b"pwd");
        prot_bytes.extend_from_slice(&kdf_config.memory_kib.to_le_bytes());
        prot_bytes.extend_from_slice(&kdf_config.iterations.to_le_bytes());
        prot_bytes.extend_from_slice(&kdf_config.parallelism.to_le_bytes());
        prot_bytes.extend_from_slice(&salt);

        let aad = build_send_aad(
            &send_id,
            created_at_unix,
            expires_at_unix,
            max_views,
            &payload_type,
            &prot_bytes,
            &xnonce,
        );
        let ct = key.encrypt_xchacha20_poly1305(plaintext, &xnonce, &aad)?;

        Ok(Self {
            send_id,
            created_at_unix,
            expires_at_unix,
            max_views,
            current_views: 0,
            payload_type,
            protection: SendProtection::Password {
                kdf_config,
                salt_base64: BASE64.encode(salt),
            },
            xnonce_base64: BASE64.encode(xnonce),
            ciphertext_base64: BASE64.encode(ct),
        })
    }

    /// Creates an X25519 public-key encrypted ephemeral `Singularity Send` using an ephemeral sender key.
    pub fn seal_with_x25519(
        send_id: impl Into<String>,
        plaintext: &[u8],
        payload_type: SendPayloadType,
        recipient_public_key: &[u8; 32],
        created_at_unix: u64,
        ttl_secs: u64,
        max_views: u32,
    ) -> Result<Self, VaultCryptoError> {
        if ttl_secs == 0 || max_views == 0 {
            return Err(VaultCryptoError::SendExpiredOrExhausted(
                "ttl_secs and max_views must be greater than 0".into(),
            ));
        }
        let send_id = send_id.into();
        let expires_at_unix = created_at_unix.saturating_add(ttl_secs);
        let (salt, xnonce) = generate_salt_and_xnonce();

        let eph_secret = X25519StaticSecret::random_from_rng(OsRng);
        let eph_public = X25519PublicKey::from(&eph_secret);
        let recipient_pub = X25519PublicKey::from(*recipient_public_key);
        let shared = eph_secret.diffie_hellman(&recipient_pub);
        if !shared.was_contributory() {
            return Err(VaultCryptoError::InvalidKey(
                "Non-contributory X25519 public key rejected".into(),
            ));
        }

        let mut info = Vec::with_capacity(96);
        info.extend_from_slice(b"singularity-send-v1-x25519:");
        info.extend_from_slice(eph_public.as_bytes());
        info.extend_from_slice(recipient_pub.as_bytes());

        let mut key_bytes = [0u8; 32];
        hkdf_sha256(&salt, shared.as_bytes(), &info, &mut key_bytes)?;
        let key = DerivedVaultKey::from_bytes(key_bytes);
        key_bytes.zeroize();

        let mut prot_bytes = Vec::with_capacity(72);
        prot_bytes.extend_from_slice(b"x25519");
        prot_bytes.extend_from_slice(eph_public.as_bytes());
        prot_bytes.extend_from_slice(&salt);

        let aad = build_send_aad(
            &send_id,
            created_at_unix,
            expires_at_unix,
            max_views,
            &payload_type,
            &prot_bytes,
            &xnonce,
        );
        let ct = key.encrypt_xchacha20_poly1305(plaintext, &xnonce, &aad)?;

        Ok(Self {
            send_id,
            created_at_unix,
            expires_at_unix,
            max_views,
            current_views: 0,
            payload_type,
            protection: SendProtection::X25519 {
                ephemeral_public_key_base64: BASE64.encode(eph_public.as_bytes()),
                salt_base64: BASE64.encode(salt),
            },
            xnonce_base64: BASE64.encode(xnonce),
            ciphertext_base64: BASE64.encode(ct),
        })
    }

    /// Opens a password-protected `Singularity Send`, enforcing TTL and max views.
    /// Automatically wipes ciphertext when the final allowed view is consumed.
    pub fn open_with_password(
        &mut self,
        password: &[u8],
        now_unix: u64,
    ) -> Result<Vec<u8>, VaultCryptoError> {
        if now_unix > self.expires_at_unix {
            self.ciphertext_base64.zeroize();
            self.ciphertext_base64.clear();
            return Err(VaultCryptoError::SendExpiredOrExhausted(
                "Send TTL has expired".into(),
            ));
        }
        if self.current_views >= self.max_views || self.ciphertext_base64.is_empty() {
            return Err(VaultCryptoError::SendExpiredOrExhausted(
                "Send view limit reached".into(),
            ));
        }

        let SendProtection::Password {
            kdf_config,
            ref salt_base64,
        } = self.protection
        else {
            return Err(VaultCryptoError::DecryptionFailed);
        };
        kdf_config.validate_bounds()?;
        let salt = decode_32_b64(salt_base64)?;
        let xnonce = decode_24_b64(&self.xnonce_base64)?;
        let ct = BASE64
            .decode(&self.ciphertext_base64)
            .map_err(|_| VaultCryptoError::DecryptionFailed)?;

        let key = DerivedVaultKey::derive_argon2id(password, &salt, kdf_config)?;
        let mut prot_bytes = Vec::with_capacity(44);
        prot_bytes.extend_from_slice(b"pwd");
        prot_bytes.extend_from_slice(&kdf_config.memory_kib.to_le_bytes());
        prot_bytes.extend_from_slice(&kdf_config.iterations.to_le_bytes());
        prot_bytes.extend_from_slice(&kdf_config.parallelism.to_le_bytes());
        prot_bytes.extend_from_slice(&salt);

        let aad = build_send_aad(
            &self.send_id,
            self.created_at_unix,
            self.expires_at_unix,
            self.max_views,
            &self.payload_type,
            &prot_bytes,
            &xnonce,
        );
        let pt = key.decrypt_xchacha20_poly1305(&ct, &xnonce, &aad)?;

        self.current_views = self.current_views.saturating_add(1);
        if self.current_views >= self.max_views {
            self.ciphertext_base64.zeroize();
            self.ciphertext_base64.clear();
        }
        Ok(pt)
    }

    /// Opens an X25519-protected `Singularity Send` using the recipient's 32-byte private key.
    pub fn open_with_x25519(
        &mut self,
        recipient_secret_bytes: &[u8; 32],
        now_unix: u64,
    ) -> Result<Vec<u8>, VaultCryptoError> {
        if now_unix > self.expires_at_unix {
            self.ciphertext_base64.zeroize();
            self.ciphertext_base64.clear();
            return Err(VaultCryptoError::SendExpiredOrExhausted(
                "Send TTL has expired".into(),
            ));
        }
        if self.current_views >= self.max_views || self.ciphertext_base64.is_empty() {
            return Err(VaultCryptoError::SendExpiredOrExhausted(
                "Send view limit reached".into(),
            ));
        }

        let SendProtection::X25519 {
            ref ephemeral_public_key_base64,
            ref salt_base64,
        } = self.protection
        else {
            return Err(VaultCryptoError::DecryptionFailed);
        };
        let eph_pub_bytes = decode_32_b64(ephemeral_public_key_base64)?;
        let salt = decode_32_b64(salt_base64)?;
        let xnonce = decode_24_b64(&self.xnonce_base64)?;
        let ct = BASE64
            .decode(&self.ciphertext_base64)
            .map_err(|_| VaultCryptoError::DecryptionFailed)?;

        let recipient_secret = X25519StaticSecret::from(*recipient_secret_bytes);
        let recipient_pub = X25519PublicKey::from(&recipient_secret);
        let eph_pub = X25519PublicKey::from(eph_pub_bytes);
        let shared = recipient_secret.diffie_hellman(&eph_pub);
        if !shared.was_contributory() {
            return Err(VaultCryptoError::DecryptionFailed);
        }

        let mut info = Vec::with_capacity(96);
        info.extend_from_slice(b"singularity-send-v1-x25519:");
        info.extend_from_slice(eph_pub.as_bytes());
        info.extend_from_slice(recipient_pub.as_bytes());

        let mut key_bytes = [0u8; 32];
        hkdf_sha256(&salt, shared.as_bytes(), &info, &mut key_bytes)?;
        let key = DerivedVaultKey::from_bytes(key_bytes);
        key_bytes.zeroize();

        let mut prot_bytes = Vec::with_capacity(72);
        prot_bytes.extend_from_slice(b"x25519");
        prot_bytes.extend_from_slice(eph_pub.as_bytes());
        prot_bytes.extend_from_slice(&salt);

        let aad = build_send_aad(
            &self.send_id,
            self.created_at_unix,
            self.expires_at_unix,
            self.max_views,
            &self.payload_type,
            &prot_bytes,
            &xnonce,
        );
        let pt = key.decrypt_xchacha20_poly1305(&ct, &xnonce, &aad)?;

        self.current_views = self.current_views.saturating_add(1);
        if self.current_views >= self.max_views {
            self.ciphertext_base64.zeroize();
            self.ciphertext_base64.clear();
        }
        Ok(pt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast_kdf() -> Argon2idConfig {
        Argon2idConfig {
            memory_kib: 4096,
            iterations: 1,
            parallelism: 1,
        }
    }

    #[test]
    fn test_hkdf_sha256_rfc5869_test_vector_1() {
        // RFC 5869 Appendix A.1 Test Case 1
        let ikm = [0x0bu8; 22];
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let mut okm = [0u8; 42];
        hkdf_sha256(&salt, &ikm, &info, &mut okm).unwrap();
        assert_eq!(
            hex::encode(okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    #[test]
    fn test_recovery_key_base32_roundtrip_and_formatting() {
        let rk = RecoveryKey256::generate();
        let formatted = rk.to_formatted_base32();
        // 52 Base32 chars split into 13 groups of 4 with 12 hyphens => 64 chars
        assert_eq!(formatted.len(), 64);
        assert_eq!(formatted.split('-').count(), 13);
        assert!(formatted.split('-').all(|g| g.len() == 4));

        // Lowercase and spaces accepted
        let parsed = RecoveryKey256::from_formatted_base32(&formatted.to_lowercase().replace('-', " "))
            .expect("parse recovery key");
        assert_eq!(parsed.as_bytes(), rk.as_bytes());
        assert_eq!(format!("{:?}", rk), "RecoveryKey256([REDACTED])");
    }

    #[test]
    fn test_dek_multi_slots_and_pin_auto_destruction() {
        let dek = DataEncryptionKey::generate();
        let rk = RecoveryKey256::generate();
        let bio_secret = [0x42u8; 32];

        let master_slot =
            WrappedDekSlot::wrap_master_password("slot-master", &dek, b"MasterPass!2026", fast_kdf(), 1000)
                .unwrap();
        let bio_slot =
            WrappedDekSlot::wrap_biometric_os("slot-bio", &dek, "touchid-main", &bio_secret, 1000)
                .unwrap();
        let mut pin_slot =
            WrappedDekSlot::wrap_pin_code("slot-pin", &dek, b"951753", fast_kdf(), 5, 1000)
                .unwrap();
        let rec_slot =
            WrappedDekSlot::wrap_recovery_key("slot-rec", &dek, &rk, 1000).unwrap();

        assert_eq!(
            master_slot.unwrap_master_password(b"MasterPass!2026").unwrap().as_bytes(),
            dek.as_bytes()
        );
        assert_eq!(
            bio_slot.unwrap_biometric_os(&bio_secret).unwrap().as_bytes(),
            dek.as_bytes()
        );
        assert_eq!(
            rec_slot.unwrap_recovery_key(&rk.to_formatted_base32()).unwrap().as_bytes(),
            dek.as_bytes()
        );

        // 4 wrong PIN attempts still leave 1 attempt; correct PIN resets counter
        for _ in 0..4 {
            assert!(matches!(
                pin_slot.unwrap_pin_code(b"000000"),
                Err(VaultCryptoError::DecryptionFailed)
            ));
            assert!(!pin_slot.is_destroyed());
        }
        assert_eq!(
            pin_slot.unwrap_pin_code(b"951753").unwrap().as_bytes(),
            dek.as_bytes()
        );

        // 5 consecutive wrong PIN attempts permanently self-destruct the PIN slot
        for i in 0..4 {
            assert!(
                matches!(
                    pin_slot.unwrap_pin_code(b"111111"),
                    Err(VaultCryptoError::DecryptionFailed)
                ),
                "attempt {} should fail without destroying yet",
                i + 1
            );
        }
        assert!(matches!(
            pin_slot.unwrap_pin_code(b"111111"),
            Err(VaultCryptoError::PinSlotDestroyed)
        ));
        assert!(pin_slot.is_destroyed());
        assert!(pin_slot.wrapped_dek_base64.is_empty());

        // Even the real PIN now fails permanently
        assert!(matches!(
            pin_slot.unwrap_pin_code(b"951753"),
            Err(VaultCryptoError::PinSlotDestroyed)
        ));
    }

    #[test]
    fn test_stream_aead_attachments_multi_chunk_and_tamper_detection() {
        let dek = DataEncryptionKey::generate();
        // 150 KiB payload -> 3 chunks (64 KiB + 64 KiB + 22 KiB)
        let data: Vec<u8> = (0..(150 * 1024)).map(|i| (i % 251) as u8).collect();

        let sealed = seal_attachment_chunks(&dek, "att-1", "passport.pdf", "application/pdf", &data)
            .expect("seal attachment");
        assert_eq!(sealed.chunks_base64.len(), 3);
        let unsealed = unseal_attachment_chunks(&dek, &sealed).expect("unseal attachment");
        assert_eq!(unsealed, data);

        // Empty attachment roundtrip
        let empty = seal_attachment_chunks(&dek, "att-empty", "empty.txt", "text/plain", &[])
            .expect("seal empty");
        assert_eq!(unseal_attachment_chunks(&dek, &empty).unwrap(), Vec::<u8>::new());

        // Truncation attack (dropping final chunk) MUST fail
        let mut truncated = sealed.clone();
        truncated.chunks_base64.pop();
        truncated.plaintext_size = (128 * 1024) as u64;
        assert!(unseal_attachment_chunks(&dek, &truncated).is_err());

        // Chunk reordering attack MUST fail
        let mut reordered = sealed.clone();
        reordered.chunks_base64.swap(0, 1);
        assert!(unseal_attachment_chunks(&dek, &reordered).is_err());
    }

    #[test]
    fn test_singularity_send_password_and_x25519_with_ttl_and_max_views() {
        // Password mode with max_views = 2
        let mut send_pwd = SingularitySendEnvelope::seal_with_password(
            "send-1",
            b"top-secret-api-token",
            SendPayloadType::Text,
            b"share-pass",
            fast_kdf(),
            1_000,
            300,
            2,
        )
        .unwrap();

        assert_eq!(
            send_pwd.open_with_password(b"share-pass", 1_010).unwrap(),
            b"top-secret-api-token"
        );
        assert_eq!(send_pwd.remaining_views(), 1);
        assert_eq!(
            send_pwd.open_with_password(b"share-pass", 1_020).unwrap(),
            b"top-secret-api-token"
        );
        assert_eq!(send_pwd.remaining_views(), 0);
        assert!(send_pwd.ciphertext_base64.is_empty());
        assert!(matches!(
            send_pwd.open_with_password(b"share-pass", 1_025),
            Err(VaultCryptoError::SendExpiredOrExhausted(_))
        ));

        // X25519 mode with TTL expiration & AAD tampering rejection
        let alice = SendX25519Keypair::generate();
        let bob = SendX25519Keypair::generate();
        let mut send_x = SingularitySendEnvelope::seal_with_x25519(
            "send-2",
            b"x25519-encrypted-secret",
            SendPayloadType::File {
                filename: "key.pem".into(),
                mime_type: "application/x-pem-file".into(),
            },
            alice.public_key_bytes(),
            2_000,
            60,
            1,
        )
        .unwrap();

        // Tampering with expires_at_unix must fail AEAD AAD check
        let mut tampered = send_x.clone();
        tampered.expires_at_unix = 9_999_999;
        assert!(tampered.open_with_x25519(alice.secret_key_bytes(), 2_010).is_err());

        // Wrong recipient key fails
        assert!(send_x.open_with_x25519(bob.secret_key_bytes(), 2_010).is_err());

        // Expired timestamp fails
        let mut expired = send_x.clone();
        assert!(matches!(
            expired.open_with_x25519(alice.secret_key_bytes(), 2_061),
            Err(VaultCryptoError::SendExpiredOrExhausted(_))
        ));

        // Valid recipient within TTL succeeds and burns single view
        assert_eq!(
            send_x.open_with_x25519(alice.secret_key_bytes(), 2_030).unwrap(),
            b"x25519-encrypted-secret"
        );
        assert!(send_x.is_expired_or_exhausted(2_031));
    }
}
