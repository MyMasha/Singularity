//! Encrypted `.singularity-vault` File Envelope Serialization & Authenticated Associated Data (AAD).

use crate::crypto::{
    generate_salt_and_xnonce, Argon2idConfig, DerivedVaultKey, VaultCryptoError,
};
use crate::passkey::StoredPasskeyCredential;
use crate::totp::TotpAlgorithm;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

pub const SINGULARITY_VAULT_MAGIC_HEADER: &str = "SINGULARITY-VAULT-V1-XCHACHA20-POLY1305";

/// A single decrypted login credential + optional TOTP 2FA secret stored inside the vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultCredentialEntry {
    pub id: String,
    pub origin_url: String,
    pub username: String,
    pub password_secret: String,
    pub totp_secret_base32: Option<String>,
    pub totp_algorithm: TotpAlgorithm,
    pub totp_digits: u32,
    pub totp_period_sec: u64,
    pub notes: String,
}

impl Drop for VaultCredentialEntry {
    fn drop(&mut self) {
        self.password_secret.zeroize();
        if let Some(ref mut t) = self.totp_secret_base32 {
            t.zeroize();
        }
    }
}

/// Complete decrypted payload inside an unlocked `.singularity-vault`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VaultPlaintextPayload {
    pub credentials: Vec<VaultCredentialEntry>,
    pub passkeys: Vec<StoredPasskeyCredential>,
}

/// Outer encrypted `.singularity-vault` container written to disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedSingularityVaultEnvelope {
    pub magic: String,
    pub kdf_config: Argon2idConfig,
    pub salt_base64: String,
    pub xnonce_base64: String,
    pub ciphertext_base64: String,
}

fn build_authenticated_header_aad(
    magic: &str,
    kdf_config: Argon2idConfig,
    salt: &[u8; 32],
    xnonce: &[u8; 24],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(magic.len() + 12 + 32 + 24);
    aad.extend_from_slice(magic.as_bytes());
    aad.extend_from_slice(&kdf_config.memory_kib.to_le_bytes());
    aad.extend_from_slice(&kdf_config.iterations.to_le_bytes());
    aad.extend_from_slice(&kdf_config.parallelism.to_le_bytes());
    aad.extend_from_slice(salt);
    aad.extend_from_slice(xnonce);
    aad
}

impl EncryptedSingularityVaultEnvelope {
    /// Seals and encrypts `payload` into a `.singularity-vault` JSON document using Argon2id + XChaCha20-Poly1305.
    pub fn seal(
        payload: &VaultPlaintextPayload,
        master_password: &[u8],
        kdf_config: Argon2idConfig,
    ) -> Result<String, VaultCryptoError> {
        kdf_config.validate_bounds()?;
        let (salt, xnonce) = generate_salt_and_xnonce();
        let key = DerivedVaultKey::derive_argon2id(master_password, &salt, kdf_config)?;
        let mut plaintext_json =
            serde_json::to_vec(payload).map_err(|_| VaultCryptoError::EncryptionFailed)?;

        let aad = build_authenticated_header_aad(
            SINGULARITY_VAULT_MAGIC_HEADER,
            kdf_config,
            &salt,
            &xnonce,
        );
        let enc_result = key.encrypt_xchacha20_poly1305(&plaintext_json, &xnonce, &aad);
        plaintext_json.zeroize();
        let ciphertext = enc_result?;

        let envelope = Self {
            magic: SINGULARITY_VAULT_MAGIC_HEADER.to_string(),
            kdf_config,
            salt_base64: BASE64.encode(salt),
            xnonce_base64: BASE64.encode(xnonce),
            ciphertext_base64: BASE64.encode(ciphertext),
        };

        serde_json::to_string_pretty(&envelope).map_err(|_| VaultCryptoError::EncryptionFailed)
    }

    /// Unseals and authenticates a `.singularity-vault` document using `master_password`.
    pub fn unseal(
        encrypted_vault_str: &str,
        master_password: &[u8],
    ) -> Result<VaultPlaintextPayload, VaultCryptoError> {
        let envelope: Self = serde_json::from_str(encrypted_vault_str)
            .map_err(|_| VaultCryptoError::DecryptionFailed)?;

        if envelope.magic != SINGULARITY_VAULT_MAGIC_HEADER {
            return Err(VaultCryptoError::DecryptionFailed);
        }

        // Enforce strict Argon2id memory/CPU bounds BEFORE running KDF to defeat DoS
        envelope.kdf_config.validate_bounds()?;

        let salt_vec = BASE64
            .decode(&envelope.salt_base64)
            .map_err(|_| VaultCryptoError::DecryptionFailed)?;
        let nonce_vec = BASE64
            .decode(&envelope.xnonce_base64)
            .map_err(|_| VaultCryptoError::DecryptionFailed)?;
        let ciphertext = BASE64
            .decode(&envelope.ciphertext_base64)
            .map_err(|_| VaultCryptoError::DecryptionFailed)?;

        let salt: [u8; 32] = salt_vec
            .try_into()
            .map_err(|_| VaultCryptoError::DecryptionFailed)?;
        let xnonce: [u8; 24] = nonce_vec
            .try_into()
            .map_err(|_| VaultCryptoError::DecryptionFailed)?;

        let key = DerivedVaultKey::derive_argon2id(master_password, &salt, envelope.kdf_config)?;
        let aad = build_authenticated_header_aad(
            &envelope.magic,
            envelope.kdf_config,
            &salt,
            &xnonce,
        );
        // Verify full-header AAD first; fall back to legacy magic-only AAD for existing vaults on disk
        let mut plaintext = match key.decrypt_xchacha20_poly1305(&ciphertext, &xnonce, &aad) {
            Ok(pt) => pt,
            Err(_) => key.decrypt_xchacha20_poly1305(
                &ciphertext,
                &xnonce,
                envelope.magic.as_bytes(),
            )?,
        };

        let parse_result = serde_json::from_slice::<VaultPlaintextPayload>(&plaintext);
        plaintext.zeroize();
        let payload = parse_result.map_err(|_| VaultCryptoError::DecryptionFailed)?;

        Ok(payload)
    }
}
