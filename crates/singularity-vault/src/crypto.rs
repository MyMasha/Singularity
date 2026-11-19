//! Argon2id Key Derivation (RFC 9106) and XChaCha20-Poly1305 Authenticated Encryption.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key, XChaCha20Poly1305, XNonce,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

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
}

/// Safe bounds for untrusted `.singularity-vault` Argon2id headers (prevents OOM/CPU DoS).
pub const MIN_ARGON2_MEMORY_KIB: u32 = 4_096;
pub const MAX_ARGON2_MEMORY_KIB: u32 = 1_048_576; // 1 GiB
pub const MIN_ARGON2_ITERATIONS: u32 = 1;
pub const MAX_ARGON2_ITERATIONS: u32 = 64;
pub const MIN_ARGON2_PARALLELISM: u32 = 1;
pub const MAX_ARGON2_PARALLELISM: u32 = 16;

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

impl DerivedVaultKey {
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
