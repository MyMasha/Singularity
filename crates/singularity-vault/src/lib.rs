//! `singularity-vault` — Local-First Zero-Knowledge Encrypted Password, TOTP (2FA),
//! and WebAuthn Passkey Vault using Argon2id and XChaCha20-Poly1305.

pub mod breach;
pub mod crypto;
pub mod format;
pub mod passkey;
pub mod totp;

pub use breach::{estimate_password_entropy_bits, OfflineBreachBloomFilter};
pub use crypto::{Argon2idConfig, DerivedVaultKey, VaultCryptoError};
pub use format::{
    EncryptedSingularityVaultEnvelope, VaultCredentialEntry, VaultPlaintextPayload,
    SINGULARITY_VAULT_MAGIC_HEADER,
};
pub use passkey::{PasskeyAssertionResponse, StoredPasskeyCredential};
pub use totp::{decode_base32_secret, generate_totp_code, TotpAlgorithm, TotpError};

/// High-level runtime vault controller supporting lock/unlock, TOTP generation, Passkey emulation,
/// offline breach auditing, and `.singularity-vault` import/export.
pub struct SingularityVault {
    kdf_config: Argon2idConfig,
    unlocked_payload: Option<VaultPlaintextPayload>,
    breach_filter: OfflineBreachBloomFilter,
}

impl Default for SingularityVault {
    fn default() -> Self {
        Self::new(Argon2idConfig::default())
    }
}

impl SingularityVault {
    pub fn new(kdf_config: Argon2idConfig) -> Self {
        Self {
            kdf_config,
            unlocked_payload: Some(VaultPlaintextPayload::default()),
            breach_filter: OfflineBreachBloomFilter::default(),
        }
    }

    pub fn new_locked(kdf_config: Argon2idConfig) -> Self {
        Self {
            kdf_config,
            unlocked_payload: None,
            breach_filter: OfflineBreachBloomFilter::default(),
        }
    }

    pub fn set_kdf_config(&mut self, kdf_config: Argon2idConfig) {
        self.kdf_config = kdf_config;
    }

    pub fn is_locked(&self) -> bool {
        self.unlocked_payload.is_none()
    }

    /// Immediately locks the vault and zeroizes all decrypted credentials in memory.
    pub fn lock(&mut self) {
        self.unlocked_payload = None;
    }

    pub fn reset_unlocked_empty(&mut self) {
        self.unlocked_payload = Some(VaultPlaintextPayload::default());
    }

    pub fn credentials(&self) -> Result<&[VaultCredentialEntry], String> {
        let payload = self
            .unlocked_payload
            .as_ref()
            .ok_or_else(|| "Vault is locked".to_string())?;
        Ok(&payload.credentials)
    }

    pub fn add_credential(&mut self, entry: VaultCredentialEntry) -> Result<(), String> {
        let payload = self
            .unlocked_payload
            .as_mut()
            .ok_or_else(|| "Vault is locked".to_string())?;
        if let Some(existing) = payload.credentials.iter_mut().find(|c| c.id == entry.id) {
            *existing = entry;
        } else {
            payload.credentials.push(entry);
        }
        Ok(())
    }

    pub fn remove_credential(&mut self, id: &str) -> Result<bool, String> {
        let payload = self
            .unlocked_payload
            .as_mut()
            .ok_or_else(|| "Vault is locked".to_string())?;
        let before = payload.credentials.len();
        payload.credentials.retain(|c| c.id != id);
        Ok(payload.credentials.len() < before)
    }

    pub fn enroll_passkey(
        &mut self,
        rp_id: &str,
        user_display_name: &str,
    ) -> Result<StoredPasskeyCredential, String> {
        let payload = self
            .unlocked_payload
            .as_mut()
            .ok_or_else(|| "Vault is locked".to_string())?;
        let pk = StoredPasskeyCredential::enroll_new(rp_id, user_display_name);
        payload.passkeys.push(pk.clone());
        Ok(pk)
    }

    pub fn audit_password_security(&self, password: &str) -> (bool, f64) {
        let breached = self.breach_filter.is_likely_breached(password);
        let entropy = estimate_password_entropy_bits(password);
        (breached, entropy)
    }

    /// Exports the current vault to an Argon2id + XChaCha20-Poly1305 encrypted `.singularity-vault` string.
    pub fn export_encrypted_vault(&self, master_password: &[u8]) -> Result<String, VaultCryptoError> {
        let payload = self
            .unlocked_payload
            .as_ref()
            .ok_or(VaultCryptoError::EncryptionFailed)?;
        EncryptedSingularityVaultEnvelope::seal(payload, master_password, self.kdf_config)
    }

    /// Unlocks and loads a `.singularity-vault` container into memory.
    pub fn import_and_unlock_vault(
        &mut self,
        encrypted_vault_str: &str,
        master_password: &[u8],
    ) -> Result<usize, VaultCryptoError> {
        let payload = EncryptedSingularityVaultEnvelope::unseal(encrypted_vault_str, master_password)?;
        let count = payload.credentials.len() + payload.passkeys.len();
        self.unlocked_payload = Some(payload);
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_argon2id_xchacha20_poly1305_vault_roundtrip() {
        let fast_cfg = Argon2idConfig {
            memory_kib: 4096,
            iterations: 1,
            parallelism: 1,
        };
        let mut vault = SingularityVault::new(fast_cfg);

        vault
            .add_credential(VaultCredentialEntry {
                id: "cred-1".into(),
                origin_url: "https://mullvad.net".into(),
                username: "9876543210987654".into(),
                password_secret: "V9#xK2!mQ8@pL5$zR7&wN4*b".into(),
                totp_secret_base32: Some("JBSWY3DPEHPK3PXP".into()),
                totp_algorithm: TotpAlgorithm::Sha1,
                totp_digits: 6,
                totp_period_sec: 30,
                notes: "Mullvad Account Vault Entry".into(),
            })
            .expect("Add credential");

        vault
            .enroll_passkey("github.com", "singularity-architect")
            .expect("Enroll passkey");

        let exported = vault
            .export_encrypted_vault(b"correct-horse-battery-staple-singularity")
            .expect("Encrypt vault");

        vault.lock();
        assert!(vault.is_locked());

        // Wrong master password must fail AEAD authentication
        assert!(vault
            .import_and_unlock_vault(&exported, b"wrong-password")
            .is_err());

        // Correct master password unlocks and restores both credential and passkey
        let restored_items = vault
            .import_and_unlock_vault(&exported, b"correct-horse-battery-staple-singularity")
            .expect("Unlock vault");
        assert_eq!(restored_items, 2);
    }

    #[test]
    fn test_rfc6238_totp_and_offline_breach_bloom_filter() {
        let (code, remaining) =
            generate_totp_code("JBSWY3DPEHPK3PXP", 1700000000, 30, 6, TotpAlgorithm::Sha1)
                .expect("Generate TOTP");
        assert_eq!(code.len(), 6);
        assert!(remaining <= 30 && remaining >= 1);

        let vault = SingularityVault::default();
        let (is_breached_weak, _) = vault.audit_password_security("password123");
        assert!(is_breached_weak);

        let (is_breached_strong, entropy_strong) =
            vault.audit_password_security("Singularity#99!EventHorizon$2026^XChaCha");
        assert!(!is_breached_strong);
        assert!(entropy_strong > 180.0);

        // Repetitive password must be flagged and score low entropy
        let (is_breached_rep, entropy_rep) = vault.audit_password_security("aaaaaaaaaaaa");
        assert!(is_breached_rep);
        assert!(entropy_rep < 10.0);
    }

    #[test]
    fn test_kdf_dos_bounds_and_ed25519_passkey_verification() {
        let mut pk = StoredPasskeyCredential::enroll_new("github.com", "alice");
        let client_data = br#"{"type":"webauthn.get","challenge":"abc"}"#;
        let assertion = pk
            .sign_webauthn_assertion("github.com", client_data)
            .expect("Ed25519 assertion");
        assert!(StoredPasskeyCredential::verify_webauthn_assertion(
            &pk.public_key_hex,
            "github.com",
            client_data,
            &assertion
        )
        .is_ok());
        assert!(StoredPasskeyCredential::verify_webauthn_assertion(
            &pk.public_key_hex,
            "evil.example",
            client_data,
            &assertion
        )
        .is_err());

        // Oversized Argon2id memory_kib in untrusted vault JSON must be rejected before allocation
        let malicious_vault = r#"{
            "magic": "SINGULARITY-VAULT-V1-XCHACHA20-POLY1305",
            "kdf_config": { "memory_kib": 4294967295, "iterations": 999999, "parallelism": 1 },
            "salt_base64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "xnonce_base64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "ciphertext_base64": "AAAA"
        }"#;
        assert!(matches!(
            EncryptedSingularityVaultEnvelope::unseal(malicious_vault, b"test"),
            Err(VaultCryptoError::InvalidArgon2Params(_))
        ));
    }
}
