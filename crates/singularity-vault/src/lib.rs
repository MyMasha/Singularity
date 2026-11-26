//! `singularity-vault` — Local-First Zero-Knowledge Encrypted Password, TOTP/HOTP/Steam 2FA,
//! FIDO2/WebAuthn Level 3 Passkey, Payment Card, STREAM AEAD Attachments, Ephemeral Send,
//! Offline Breach/Health Auditor, FIDO CXF/CXP, and Multi-Manager Import/Export Vault.

pub mod breach;
pub mod crypto;
pub mod cxf;
pub mod format;
pub mod generator;
pub mod importers;
pub mod matcher;
pub mod passkey;
pub mod payment;
pub mod totp;

// V1 Backwards-Compatible Public Re-Exports
pub use breach::{
    analyze_password_weaknesses, estimate_password_entropy_bits, generate_vault_health_report,
    lookup_site_security_support, parse_hibp_range_response, HealthIssueCategory, HealthSeverity,
    OfflineBreachBloomFilter, SiteSecuritySupport, VaultHealthIssue, VaultHealthReport,
    WeakPasswordReason,
};
pub use crypto::{
    constant_time_eq, format_recovery_key_base32, hkdf_sha256, parse_recovery_key_base32,
    seal_attachment_chunks, unseal_attachment_chunks, Argon2idConfig, DataEncryptionKey,
    DekSlotKind, DerivedVaultKey, RecoveryKey256, SealedAttachment, SendPayloadType,
    SendProtection, SendX25519Keypair, SingularitySendEnvelope, VaultCryptoError, WrappedDekSlot,
    ATTACHMENT_CHUNK_SIZE, DEFAULT_PIN_MAX_ATTEMPTS,
};
pub use cxf::{
    deserialize_cxf_json, export_vault_to_cxf, import_cxf_to_vault_parts, serialize_cxf_json,
    CxfAccount, CxfCollection, CxfCredential, CxfError, CxfExportDocument, CxfItem,
    CxpEncryptedEnvelope, CxpProtection,
};
pub use format::{
    detect_vault_schema_version, ApiSecretPayload, CardPayload, CustomField, CustomFieldKind,
    EncryptedSingularityVaultEnvelope, EncryptedSingularityVaultEnvelopeV2, GeneratedSecretRecord,
    IdentityPayload, LicensePayload, LoginPayload, PasswordHistoryEntry, SecureNotePayload,
    SshKeyPayload, VaultCredentialEntry, VaultFolder, VaultItem, VaultItemKind,
    VaultPlaintextPayload, VaultPlaintextPayloadV2, VaultSchemaVersion, WifiPayload,
    GENERATOR_HISTORY_CAP, PASSWORD_HISTORY_CAP, SINGULARITY_VAULT_MAGIC_HEADER,
    SINGULARITY_VAULT_V2_MAGIC_HEADER, TRASH_RETENTION_SECONDS,
};
pub use generator::{
    calculate_passphrase_entropy_bits, generate_passphrase, generate_password, GeneratedSecret,
    GeneratorError, PassphraseConfig, PasswordGeneratorConfig, WordCapitalization,
    WordlistLanguage,
};
pub use importers::{
    apply_import_atomic, detect_import_format, export_to_csv, export_to_encrypted_json,
    export_to_plain_json, import_from_encrypted_json, parse_csv_rfc4180, preview_import,
    ConflictResolution, ImportApplyResult, ImportConflict, ImportError, ImportFormat,
    ImportPreview,
};
pub use matcher::{
    assess_phishing_risk, decode_punycode_label, extract_etld_plus_one, fuzzy_search_items,
    levenshtein_distance, match_items_for_uri, matches_uri_rule, parse_uri_components,
    FuzzySearchHit, ParsedUri, PhishingAssessment, PhishingRiskKind, UriMatchResult, UriMatchRule,
    VaultUriEntry,
};
pub use passkey::{
    build_authenticator_data, encode_cbor_attestation_object, encode_cose_ed25519_public_key,
    signal_all_accepted_credentials, signal_current_user_details, signal_unknown_credential,
    validate_rp_id, PasskeyAlgorithm, PasskeyAssertionResponse, PasskeyAttestationObject,
    PasskeyAuditEvent, PrfExtensionOutput, StoredPasskeyCredential, SINGULARITY_PASSKEY_AAGUID,
    WEBAUTHN_FLAG_AT, WEBAUTHN_FLAG_BE, WEBAUTHN_FLAG_BS, WEBAUTHN_FLAG_ED, WEBAUTHN_FLAG_UP,
    WEBAUTHN_FLAG_UV,
};
pub use payment::{
    detect_card_brand, is_card_expired, mask_card_number, validate_luhn, CardBrand,
    ReauthTokenGuard, DEFAULT_REAUTH_TTL_SECS,
};
pub use totp::{
    decode_base32_secret, encode_base32_secret, format_otpauth_uri, generate_hotp_code,
    generate_otp_with_next, generate_steam_code, generate_totp_code, generate_totp_with_next,
    parse_otpauth_migration_uri, parse_otpauth_uri, verify_totp_code_with_skew, OtpAuthConfig,
    OtpKind, TotpAlgorithm, TotpError,
};

use rand_core::{OsRng, RngCore};

/// High-level runtime vault controller supporting V1 & V2 `.singularity-vault` containers,
/// multi-slot DEK/KEK unlock (Master Password, PIN, Biometrics, Recovery Key), polymorphic items,
/// folders, 30-day trash, TOTP/HOTP/Steam 2FA, WebAuthn Level 3 passkeys, generator history,
/// STREAM attachments, offline breach/health auditing, FIDO CXF/CXP, and multi-manager import/export.
pub struct SingularityVault {
    kdf_config: Argon2idConfig,
    vault_id: String,
    unlocked_payload: Option<VaultPlaintextPayload>,
    unlocked_v2: Option<VaultPlaintextPayloadV2>,
    active_dek: Option<DataEncryptionKey>,
    dek_slots: Vec<WrappedDekSlot>,
    reauth_guard: Option<ReauthTokenGuard>,
    breach_filter: OfflineBreachBloomFilter,
}

fn generate_random_hex_id(prefix: &str) -> String {
    let mut bytes = [0u8; 8];
    OsRng.fill_bytes(&mut bytes);
    format!("{}-{}", prefix, hex::encode(bytes))
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
            vault_id: generate_random_hex_id("vault"),
            unlocked_payload: Some(VaultPlaintextPayload::default()),
            unlocked_v2: Some(VaultPlaintextPayloadV2::default()),
            active_dek: Some(DataEncryptionKey::generate()),
            dek_slots: Vec::new(),
            reauth_guard: None,
            breach_filter: OfflineBreachBloomFilter::default(),
        }
    }

    pub fn new_locked(kdf_config: Argon2idConfig) -> Self {
        Self {
            kdf_config,
            vault_id: generate_random_hex_id("vault"),
            unlocked_payload: None,
            unlocked_v2: None,
            active_dek: None,
            dek_slots: Vec::new(),
            reauth_guard: None,
            breach_filter: OfflineBreachBloomFilter::default(),
        }
    }

    pub fn set_kdf_config(&mut self, kdf_config: Argon2idConfig) {
        self.kdf_config = kdf_config;
    }

    pub fn vault_id(&self) -> &str {
        &self.vault_id
    }

    pub fn is_locked(&self) -> bool {
        self.unlocked_payload.is_none() || self.unlocked_v2.is_none()
    }

    /// Immediately locks the vault and zeroizes all decrypted credentials, V2 items,
    /// active DEK, and step-up reauth tokens in memory.
    pub fn lock(&mut self) {
        self.unlocked_payload = None;
        self.unlocked_v2 = None;
        self.active_dek = None;
        if let Some(ref mut g) = self.reauth_guard {
            g.revoke();
        }
        self.reauth_guard = None;
    }

    pub fn reset_unlocked_empty(&mut self) {
        self.unlocked_payload = Some(VaultPlaintextPayload::default());
        self.unlocked_v2 = Some(VaultPlaintextPayloadV2::default());
        self.active_dek = Some(DataEncryptionKey::generate());
        self.dek_slots.clear();
        self.reauth_guard = None;
    }

    fn sync_v1_projection(&mut self) {
        if let Some(ref v2) = self.unlocked_v2 {
            self.unlocked_payload = Some(v2.to_v1());
        }
    }

    // ========================================================================
    // V1 BACKWARDS-COMPATIBLE API
    // ========================================================================

    pub fn credentials(&self) -> Result<&[VaultCredentialEntry], String> {
        let payload = self
            .unlocked_payload
            .as_ref()
            .ok_or_else(|| "Vault is locked".to_string())?;
        Ok(&payload.credentials)
    }

    pub fn add_credential(&mut self, entry: VaultCredentialEntry) -> Result<(), String> {
        let v2 = self
            .unlocked_v2
            .as_mut()
            .ok_or_else(|| "Vault is locked".to_string())?;

        let v2_item = VaultItem::from_v1_credential(&entry, v2.updated_at_unix);
        if let Some(existing) = v2.items.iter_mut().find(|it| it.id == entry.id) {
            // Preserve password history on overwrite
            if let (VaultItemKind::Login(ref mut ex_l), VaultItemKind::Login(ref new_l)) =
                (&mut existing.kind, &v2_item.kind)
            {
                let mut updated = new_l.clone();
                updated.password_history = ex_l.password_history.clone();
                let old_pw = ex_l.password.clone();
                let new_pw = new_l.password.clone();
                updated.password = old_pw;
                updated.update_password(new_pw, v2.updated_at_unix);
                existing.kind = VaultItemKind::Login(updated);
                existing.name = v2_item.name;
                existing.trashed_at = None;
                existing.revision = existing.revision.saturating_add(1);
            } else {
                *existing = v2_item;
            }
        } else {
            v2.items.push(v2_item);
        }
        v2.revision = v2.revision.saturating_add(1);
        self.sync_v1_projection();
        Ok(())
    }

    pub fn remove_credential(&mut self, id: &str) -> Result<bool, String> {
        let v2 = self
            .unlocked_v2
            .as_mut()
            .ok_or_else(|| "Vault is locked".to_string())?;
        let before = v2.items.len();
        v2.items.retain(|it| it.id != id);
        let removed = v2.items.len() < before;
        if removed {
            v2.revision = v2.revision.saturating_add(1);
        }
        self.sync_v1_projection();
        Ok(removed)
    }

    pub fn enroll_passkey(
        &mut self,
        rp_id: &str,
        user_display_name: &str,
    ) -> Result<StoredPasskeyCredential, String> {
        let v2 = self
            .unlocked_v2
            .as_mut()
            .ok_or_else(|| "Vault is locked".to_string())?;
        let pk = StoredPasskeyCredential::enroll_new(rp_id, user_display_name);
        v2.passkeys.push(pk.clone());
        v2.revision = v2.revision.saturating_add(1);
        self.sync_v1_projection();
        Ok(pk)
    }

    pub fn audit_password_security(&self, password: &str) -> (bool, f64) {
        let breached = self.breach_filter.is_likely_breached(password);
        let entropy = estimate_password_entropy_bits(password);
        (breached, entropy)
    }

    /// Exports the current vault to a V1 Argon2id + XChaCha20-Poly1305 encrypted `.singularity-vault` string.
    pub fn export_encrypted_vault(&self, master_password: &[u8]) -> Result<String, VaultCryptoError> {
        let payload = self
            .unlocked_payload
            .as_ref()
            .ok_or(VaultCryptoError::EncryptionFailed)?;
        EncryptedSingularityVaultEnvelope::seal(payload, master_password, self.kdf_config)
    }

    /// Unlocks and loads either a V1 or V2 `.singularity-vault` container into memory using `master_password`.
    pub fn import_and_unlock_vault(
        &mut self,
        encrypted_vault_str: &str,
        master_password: &[u8],
    ) -> Result<usize, VaultCryptoError> {
        match detect_vault_schema_version(encrypted_vault_str) {
            Ok(VaultSchemaVersion::V2) => {
                let env = EncryptedSingularityVaultEnvelopeV2::from_json(encrypted_vault_str)?;
                self.unlock_v2_envelope_with_master_password(&env, master_password)
            }
            _ => {
                // Delegate directly to V1 unseal (preserves exact DoS InvalidArgon2Params error behavior)
                let payload =
                    EncryptedSingularityVaultEnvelope::unseal(encrypted_vault_str, master_password)?;
                let count = payload.credentials.len() + payload.passkeys.len();
                let v2 = VaultPlaintextPayloadV2::from_v1(&payload, 0);
                self.unlocked_payload = Some(payload);
                self.unlocked_v2 = Some(v2);
                self.active_dek = Some(DataEncryptionKey::generate());
                self.dek_slots.clear();
                Ok(count)
            }
        }
    }

    // ========================================================================
    // V2 MULTI-SLOT DEK/KEK ENVELOPE & UNLOCK METHODS
    // ========================================================================

    pub fn dek_slots(&self) -> &[WrappedDekSlot] {
        &self.dek_slots
    }

    /// Wraps the active 256-bit DEK in a `MasterPassword` KEK slot (replacing any prior master slot).
    pub fn setup_master_password_slot(
        &mut self,
        master_password: &[u8],
        now_unix: u64,
    ) -> Result<(), VaultCryptoError> {
        let dek = self
            .active_dek
            .as_ref()
            .ok_or(VaultCryptoError::EncryptionFailed)?;
        let slot = WrappedDekSlot::wrap_master_password(
            "master-primary",
            dek,
            master_password,
            self.kdf_config,
            now_unix,
        )?;
        self.dek_slots
            .retain(|s| !matches!(s.kind, DekSlotKind::MasterPassword { .. }));
        self.dek_slots.insert(0, slot);
        Ok(())
    }

    /// Fast master password rotation: re-wraps the existing DEK without re-encrypting vault data.
    pub fn change_master_password(
        &mut self,
        new_master_password: &[u8],
        now_unix: u64,
    ) -> Result<(), VaultCryptoError> {
        self.setup_master_password_slot(new_master_password, now_unix)
    }

    /// Adds or replaces the PIN unlock slot (default 5 max attempts with auto-destruction on exhaustion).
    pub fn setup_pin_slot(
        &mut self,
        pin: &[u8],
        max_attempts: u8,
        now_unix: u64,
    ) -> Result<(), VaultCryptoError> {
        let dek = self
            .active_dek
            .as_ref()
            .ok_or(VaultCryptoError::EncryptionFailed)?;
        let slot = WrappedDekSlot::wrap_pin_code(
            "pin-primary",
            dek,
            pin,
            self.kdf_config,
            max_attempts,
            now_unix,
        )?;
        self.dek_slots
            .retain(|s| !matches!(s.kind, DekSlotKind::PinCode { .. }));
        self.dek_slots.push(slot);
        Ok(())
    }

    /// Adds or replaces an OS Biometric Keychain unlock slot.
    pub fn setup_biometric_slot(
        &mut self,
        key_label: &str,
        biometric_secret: &[u8],
        now_unix: u64,
    ) -> Result<(), VaultCryptoError> {
        let dek = self
            .active_dek
            .as_ref()
            .ok_or(VaultCryptoError::EncryptionFailed)?;
        let slot = WrappedDekSlot::wrap_biometric_os(
            "bio-primary",
            dek,
            key_label,
            biometric_secret,
            now_unix,
        )?;
        self.dek_slots
            .retain(|s| !matches!(s.kind, DekSlotKind::BiometricOs { .. }));
        self.dek_slots.push(slot);
        Ok(())
    }

    /// Generates a new 256-bit emergency recovery key, binds a `RecoveryKey256` slot to the active DEK,
    /// and returns the human-readable Base32 grouped recovery key string for user backup.
    pub fn generate_and_bind_recovery_key(
        &mut self,
        now_unix: u64,
    ) -> Result<String, VaultCryptoError> {
        let dek = self
            .active_dek
            .as_ref()
            .ok_or(VaultCryptoError::EncryptionFailed)?;
        let rk = RecoveryKey256::generate();
        let slot = WrappedDekSlot::wrap_recovery_key("recovery-primary", dek, &rk, now_unix)?;
        self.dek_slots
            .retain(|s| !matches!(s.kind, DekSlotKind::RecoveryKey256 { .. }));
        self.dek_slots.push(slot);
        Ok(rk.to_formatted_base32())
    }

    /// Seals the unlocked V2 vault into an [`EncryptedSingularityVaultEnvelopeV2`] using all active DEK slots.
    pub fn seal_v2_envelope(
        &self,
        now_unix: u64,
    ) -> Result<EncryptedSingularityVaultEnvelopeV2, VaultCryptoError> {
        let payload = self
            .unlocked_v2
            .as_ref()
            .ok_or(VaultCryptoError::EncryptionFailed)?;
        let dek = self
            .active_dek
            .as_ref()
            .ok_or(VaultCryptoError::EncryptionFailed)?;
        if self.dek_slots.is_empty() {
            return Err(VaultCryptoError::SlotNotFound(
                "At least one DEK slot (e.g. master password) must be configured before sealing".into(),
            ));
        }
        EncryptedSingularityVaultEnvelopeV2::seal_with_dek(
            payload,
            dek,
            self.dek_slots.clone(),
            self.vault_id.clone(),
            now_unix,
        )
    }

    /// Ensures a `MasterPassword` slot is bound (if none exists yet) and exports a serialized V2 envelope JSON.
    pub fn export_encrypted_vault_v2(
        &mut self,
        master_password: &[u8],
        now_unix: u64,
    ) -> Result<String, VaultCryptoError> {
        if !self
            .dek_slots
            .iter()
            .any(|s| matches!(s.kind, DekSlotKind::MasterPassword { .. }) && !s.is_destroyed())
        {
            self.setup_master_password_slot(master_password, now_unix)?;
        }
        self.seal_v2_envelope(now_unix)?.to_json_pretty()
    }

    fn install_unlocked_v2(
        &mut self,
        env: &EncryptedSingularityVaultEnvelopeV2,
        payload: VaultPlaintextPayloadV2,
        dek: DataEncryptionKey,
    ) -> usize {
        let active_count = payload.items.iter().filter(|i| !i.is_trashed()).count()
            + payload.passkeys.iter().filter(|p| !p.is_trashed()).count();
        self.vault_id = env.vault_id.clone();
        self.dek_slots = env.slots.clone();
        self.active_dek = Some(dek);
        self.unlocked_payload = Some(payload.to_v1());
        self.unlocked_v2 = Some(payload);
        active_count
    }

    pub fn unlock_v2_envelope_with_master_password(
        &mut self,
        env: &EncryptedSingularityVaultEnvelopeV2,
        master_password: &[u8],
    ) -> Result<usize, VaultCryptoError> {
        let (payload, dek) = env.unseal_with_master_password(master_password)?;
        Ok(self.install_unlocked_v2(env, payload, dek))
    }

    pub fn unlock_v2_envelope_with_pin(
        &mut self,
        env: &mut EncryptedSingularityVaultEnvelopeV2,
        pin: &[u8],
    ) -> Result<usize, VaultCryptoError> {
        let (payload, dek) = env.unseal_with_pin(pin)?;
        Ok(self.install_unlocked_v2(env, payload, dek))
    }

    pub fn unlock_v2_envelope_with_biometric(
        &mut self,
        env: &EncryptedSingularityVaultEnvelopeV2,
        biometric_secret: &[u8],
    ) -> Result<usize, VaultCryptoError> {
        let (payload, dek) = env.unseal_with_biometric(biometric_secret)?;
        Ok(self.install_unlocked_v2(env, payload, dek))
    }

    pub fn unlock_v2_envelope_with_recovery_key(
        &mut self,
        env: &EncryptedSingularityVaultEnvelopeV2,
        recovery_key_base32: &str,
    ) -> Result<usize, VaultCryptoError> {
        let (payload, dek) = env.unseal_with_recovery_key(recovery_key_base32)?;
        Ok(self.install_unlocked_v2(env, payload, dek))
    }

    // ========================================================================
    // V2 POLYMORPHIC ITEMS, FOLDERS, TRASH, NEVER-SAVE DOMAINS
    // ========================================================================

    pub fn v2_payload(&self) -> Result<&VaultPlaintextPayloadV2, String> {
        self.unlocked_v2
            .as_ref()
            .ok_or_else(|| "Vault is locked".to_string())
    }

    pub fn items(&self) -> Result<&[VaultItem], String> {
        Ok(&self.v2_payload()?.items)
    }

    pub fn active_items(&self) -> Result<Vec<&VaultItem>, String> {
        Ok(self
            .v2_payload()?
            .items
            .iter()
            .filter(|i| !i.is_trashed())
            .collect())
    }

    pub fn trashed_items(&self) -> Result<Vec<&VaultItem>, String> {
        Ok(self
            .v2_payload()?
            .items
            .iter()
            .filter(|i| i.is_trashed())
            .collect())
    }

    pub fn get_item(&self, id: &str) -> Result<Option<&VaultItem>, String> {
        Ok(self.v2_payload()?.items.iter().find(|i| i.id == id))
    }

    pub fn upsert_item(&mut self, mut item: VaultItem, now_unix: u64) -> Result<(), String> {
        let v2 = self
            .unlocked_v2
            .as_mut()
            .ok_or_else(|| "Vault is locked".to_string())?;
        if let Some(existing) = v2.items.iter_mut().find(|i| i.id == item.id) {
            item.revision = existing.revision.saturating_add(1);
            item.updated_at_unix = now_unix;
            if let (VaultItemKind::Login(ref ex_l), VaultItemKind::Login(ref mut new_l)) =
                (&existing.kind, &mut item.kind)
            {
                if ex_l.password != new_l.password && !ex_l.password.is_empty() {
                    let new_pw = new_l.password.clone();
                    new_l.password_history = ex_l.password_history.clone();
                    new_l.password = ex_l.password.clone();
                    new_l.update_password(new_pw, now_unix);
                    item.password_updated_at_unix = Some(now_unix);
                }
            }
            *existing = item;
        } else {
            v2.items.push(item);
        }
        v2.bump_revision(now_unix);
        self.sync_v1_projection();
        Ok(())
    }

    pub fn trash_item(&mut self, id: &str, now_unix: u64) -> Result<bool, String> {
        let v2 = self
            .unlocked_v2
            .as_mut()
            .ok_or_else(|| "Vault is locked".to_string())?;
        if let Some(item) = v2.items.iter_mut().find(|i| i.id == id) {
            item.move_to_trash(now_unix);
            v2.bump_revision(now_unix);
            self.sync_v1_projection();
            return Ok(true);
        }
        Ok(false)
    }

    pub fn restore_item(&mut self, id: &str, now_unix: u64) -> Result<bool, String> {
        let v2 = self
            .unlocked_v2
            .as_mut()
            .ok_or_else(|| "Vault is locked".to_string())?;
        if let Some(item) = v2.items.iter_mut().find(|i| i.id == id) {
            item.restore_from_trash(now_unix);
            v2.bump_revision(now_unix);
            self.sync_v1_projection();
            return Ok(true);
        }
        Ok(false)
    }

    pub fn delete_item_permanently(&mut self, id: &str, now_unix: u64) -> Result<bool, String> {
        let v2 = self
            .unlocked_v2
            .as_mut()
            .ok_or_else(|| "Vault is locked".to_string())?;
        let before = v2.items.len();
        v2.items.retain(|i| i.id != id);
        let removed = v2.items.len() < before;
        if removed {
            v2.bump_revision(now_unix);
            self.sync_v1_projection();
        }
        Ok(removed)
    }

    pub fn purge_expired_trash(&mut self, now_unix: u64) -> Result<usize, String> {
        let v2 = self
            .unlocked_v2
            .as_mut()
            .ok_or_else(|| "Vault is locked".to_string())?;
        let purged = v2.purge_expired_trash(now_unix);
        if purged > 0 {
            self.sync_v1_projection();
        }
        Ok(purged)
    }

    pub fn folders(&self) -> Result<&[VaultFolder], String> {
        Ok(&self.v2_payload()?.folders)
    }

    pub fn upsert_folder(&mut self, mut folder: VaultFolder, now_unix: u64) -> Result<(), String> {
        let v2 = self
            .unlocked_v2
            .as_mut()
            .ok_or_else(|| "Vault is locked".to_string())?;
        if let Some(existing) = v2.folders.iter_mut().find(|f| f.id == folder.id) {
            folder.revision = existing.revision.saturating_add(1);
            folder.updated_at_unix = now_unix;
            *existing = folder;
        } else {
            folder.updated_at_unix = now_unix;
            v2.folders.push(folder);
        }
        v2.bump_revision(now_unix);
        Ok(())
    }

    pub fn remove_folder(&mut self, folder_id: &str, now_unix: u64) -> Result<bool, String> {
        let v2 = self
            .unlocked_v2
            .as_mut()
            .ok_or_else(|| "Vault is locked".to_string())?;
        let before = v2.folders.len();
        v2.folders.retain(|f| f.id != folder_id);
        let removed = v2.folders.len() < before;
        if removed {
            for item in &mut v2.items {
                if item.folder_id.as_deref() == Some(folder_id) {
                    item.folder_id = None;
                }
            }
            for child in &mut v2.folders {
                if child.parent_id.as_deref() == Some(folder_id) {
                    child.parent_id = None;
                }
            }
            v2.bump_revision(now_unix);
        }
        Ok(removed)
    }

    pub fn add_never_save_domain(
        &mut self,
        domain_or_uri: &str,
        now_unix: u64,
    ) -> Result<bool, String> {
        let v2 = self
            .unlocked_v2
            .as_mut()
            .ok_or_else(|| "Vault is locked".to_string())?;
        Ok(v2.add_never_save_domain(domain_or_uri, now_unix))
    }

    pub fn is_never_save_domain(&self, domain_or_uri: &str) -> Result<bool, String> {
        Ok(self.v2_payload()?.is_never_save_domain(domain_or_uri))
    }

    pub fn never_save_domains(&self) -> Result<&[String], String> {
        Ok(&self.v2_payload()?.never_save_domains)
    }

    // ========================================================================
    // AUTOFILL MATCHING, ANTI-PHISHING & FUZZY SEARCH
    // ========================================================================

    pub fn match_for_uri(&self, target_uri: &str) -> Result<Vec<UriMatchResult<'_>>, String> {
        Ok(match_items_for_uri(&self.v2_payload()?.items, target_uri))
    }

    pub fn assess_uri_phishing(&self, candidate_uri: &str) -> Result<PhishingAssessment, String> {
        let v2 = self.v2_payload()?;
        let mut known_domains = Vec::new();
        for item in &v2.items {
            if item.is_trashed() {
                continue;
            }
            if let VaultItemKind::Login(ref l) = item.kind {
                for u in &l.uris {
                    known_domains.push(u.uri.clone());
                }
            }
        }
        for pk in &v2.passkeys {
            if !pk.is_trashed() {
                known_domains.push(format!("https://{}", pk.rp_id));
            }
        }
        Ok(assess_phishing_risk(candidate_uri, &known_domains))
    }

    pub fn search_items(
        &self,
        query: &str,
        include_trashed: bool,
    ) -> Result<Vec<FuzzySearchHit<'_>>, String> {
        Ok(fuzzy_search_items(
            &self.v2_payload()?.items,
            query,
            include_trashed,
        ))
    }

    // ========================================================================
    // GENERATOR + HISTORY (CAP 50)
    // ========================================================================

    pub fn generate_and_record_password(
        &mut self,
        cfg: &PasswordGeneratorConfig,
        origin_hint: Option<String>,
        now_unix: u64,
    ) -> Result<GeneratedSecret, String> {
        let generated = generate_password(cfg).map_err(|e| e.to_string())?;
        let v2 = self
            .unlocked_v2
            .as_mut()
            .ok_or_else(|| "Vault is locked".to_string())?;
        v2.push_generator_history(GeneratedSecretRecord {
            id: generate_random_hex_id("gen"),
            secret: generated.value.clone(),
            kind: "password".to_string(),
            entropy_bits: generated.entropy_bits,
            origin_hint,
            created_at_unix: now_unix,
        });
        v2.bump_revision(now_unix);
        Ok(generated)
    }

    pub fn generate_and_record_passphrase(
        &mut self,
        cfg: &PassphraseConfig,
        origin_hint: Option<String>,
        now_unix: u64,
    ) -> Result<GeneratedSecret, String> {
        let generated = generate_passphrase(cfg).map_err(|e| e.to_string())?;
        let v2 = self
            .unlocked_v2
            .as_mut()
            .ok_or_else(|| "Vault is locked".to_string())?;
        v2.push_generator_history(GeneratedSecretRecord {
            id: generate_random_hex_id("gen"),
            secret: generated.value.clone(),
            kind: "passphrase".to_string(),
            entropy_bits: generated.entropy_bits,
            origin_hint,
            created_at_unix: now_unix,
        });
        v2.bump_revision(now_unix);
        Ok(generated)
    }

    pub fn generator_history(&self) -> Result<&[GeneratedSecretRecord], String> {
        Ok(&self.v2_payload()?.generator_history)
    }

    // ========================================================================
    // STREAM AEAD ATTACHMENTS
    // ========================================================================

    pub fn seal_and_attach_file(
        &mut self,
        item_id: &str,
        attachment_id: &str,
        filename: &str,
        mime_type: &str,
        plaintext: &[u8],
        now_unix: u64,
    ) -> Result<SealedAttachment, VaultCryptoError> {
        let dek = self
            .active_dek
            .as_ref()
            .ok_or(VaultCryptoError::EncryptionFailed)?;
        let sealed = seal_attachment_chunks(dek, attachment_id, filename, mime_type, plaintext)?;
        let v2 = self
            .unlocked_v2
            .as_mut()
            .ok_or(VaultCryptoError::EncryptionFailed)?;
        v2.attachments.retain(|a| a.attachment_id != attachment_id);
        v2.attachments.push(sealed.clone());
        if let Some(item) = v2.items.iter_mut().find(|i| i.id == item_id) {
            if !item.attachment_ids.iter().any(|id| id == attachment_id) {
                item.attachment_ids.push(attachment_id.to_string());
                item.updated_at_unix = now_unix;
                item.revision = item.revision.saturating_add(1);
            }
        }
        v2.bump_revision(now_unix);
        Ok(sealed)
    }

    pub fn unseal_attachment(&self, attachment_id: &str) -> Result<Vec<u8>, VaultCryptoError> {
        let dek = self
            .active_dek
            .as_ref()
            .ok_or(VaultCryptoError::DecryptionFailed)?;
        let v2 = self
            .unlocked_v2
            .as_ref()
            .ok_or(VaultCryptoError::DecryptionFailed)?;
        let sealed = v2
            .attachments
            .iter()
            .find(|a| a.attachment_id == attachment_id)
            .ok_or_else(|| {
                VaultCryptoError::StreamAttachmentError(format!(
                    "Attachment '{}' not found",
                    attachment_id
                ))
            })?;
        unseal_attachment_chunks(dek, sealed)
    }

    // ========================================================================
    // HEALTH REPORT & STEP-UP REAUTHENTICATION
    // ========================================================================

    pub fn generate_health_report(&self, now_unix: u64) -> Result<VaultHealthReport, String> {
        let v2 = self.v2_payload()?;
        Ok(generate_vault_health_report(
            &v2.items,
            &v2.passkeys,
            &self.breach_filter,
            now_unix,
        ))
    }

    pub fn issue_reauth_token(&mut self, now_unix: u64) -> String {
        let guard = ReauthTokenGuard::issue(now_unix);
        let hex_tok = guard.token_hex();
        self.reauth_guard = Some(guard);
        hex_tok
    }

    pub fn verify_reauth_token(&self, token_hex: &str, now_unix: u64) -> bool {
        self.reauth_guard
            .as_ref()
            .map(|g| g.verify(token_hex, now_unix))
            .unwrap_or(false)
    }

    // ========================================================================
    // PASSKEY MANAGEMENT & WEBAUTHN LEVEL 3 SIGNAL API
    // ========================================================================

    pub fn passkeys(&self) -> Result<&[StoredPasskeyCredential], String> {
        Ok(&self.v2_payload()?.passkeys)
    }

    pub fn enroll_passkey_v2(
        &mut self,
        rp_id: &str,
        rp_name: &str,
        user_name: &str,
        user_display_name: &str,
        algorithm: PasskeyAlgorithm,
        linked_item_id: Option<String>,
        now_unix: u64,
    ) -> Result<StoredPasskeyCredential, String> {
        let normalized_rp = validate_rp_id(rp_id)?;
        let v2 = self
            .unlocked_v2
            .as_mut()
            .ok_or_else(|| "Vault is locked".to_string())?;
        let pk = StoredPasskeyCredential::enroll_new_with_metadata(
            &normalized_rp,
            rp_name,
            user_name,
            user_display_name,
            algorithm,
            linked_item_id.clone(),
            now_unix,
        );
        if let Some(ref item_id) = linked_item_id {
            if let Some(item) = v2.items.iter_mut().find(|i| &i.id == item_id) {
                if let VaultItemKind::Login(ref mut l) = item.kind {
                    if !l.passkey_ids.contains(&pk.credential_id_hex) {
                        l.passkey_ids.push(pk.credential_id_hex.clone());
                    }
                }
            }
        }
        v2.passkeys.push(pk.clone());
        v2.bump_revision(now_unix);
        self.sync_v1_projection();
        Ok(pk)
    }

    pub fn signal_unknown_credential(
        &mut self,
        rp_id: &str,
        credential_id_hex: &str,
        now_unix: u64,
    ) -> Result<bool, String> {
        let v2 = self
            .unlocked_v2
            .as_mut()
            .ok_or_else(|| "Vault is locked".to_string())?;
        let found =
            signal_unknown_credential(&mut v2.passkeys, rp_id, credential_id_hex, now_unix)?;
        if found {
            v2.bump_revision(now_unix);
            self.sync_v1_projection();
        }
        Ok(found)
    }

    pub fn signal_all_accepted_credentials(
        &mut self,
        rp_id: &str,
        user_handle_hex: &str,
        accepted_credential_ids: &[String],
        now_unix: u64,
    ) -> Result<usize, String> {
        let v2 = self
            .unlocked_v2
            .as_mut()
            .ok_or_else(|| "Vault is locked".to_string())?;
        let count = signal_all_accepted_credentials(
            &mut v2.passkeys,
            rp_id,
            user_handle_hex,
            accepted_credential_ids,
            now_unix,
        )?;
        if count > 0 {
            v2.bump_revision(now_unix);
            self.sync_v1_projection();
        }
        Ok(count)
    }

    pub fn signal_current_user_details(
        &mut self,
        rp_id: &str,
        user_handle_hex: &str,
        new_user_name: &str,
        new_display_name: &str,
        now_unix: u64,
    ) -> Result<usize, String> {
        let v2 = self
            .unlocked_v2
            .as_mut()
            .ok_or_else(|| "Vault is locked".to_string())?;
        let count = signal_current_user_details(
            &mut v2.passkeys,
            rp_id,
            user_handle_hex,
            new_user_name,
            new_display_name,
            now_unix,
        )?;
        if count > 0 {
            v2.bump_revision(now_unix);
            self.sync_v1_projection();
        }
        Ok(count)
    }

    // ========================================================================
    // IMPORT / EXPORT & FIDO CXF
    // ========================================================================

    pub fn preview_import(
        &self,
        input: &str,
        format_override: Option<ImportFormat>,
        now_unix: u64,
    ) -> Result<ImportPreview, String> {
        let v2 = self.v2_payload()?;
        preview_import(&v2.items, input, format_override, now_unix).map_err(|e| e.to_string())
    }

    pub fn apply_import(
        &mut self,
        preview: ImportPreview,
        resolution: ConflictResolution,
        now_unix: u64,
    ) -> Result<ImportApplyResult, String> {
        let v2 = self
            .unlocked_v2
            .as_mut()
            .ok_or_else(|| "Vault is locked".to_string())?;
        let res = apply_import_atomic(v2, preview, resolution, now_unix);
        self.sync_v1_projection();
        Ok(res)
    }

    pub fn export_csv(&self) -> Result<String, String> {
        let v2 = self.v2_payload()?;
        Ok(export_to_csv(&v2.items, &v2.folders))
    }

    pub fn export_plain_json(&self) -> Result<String, String> {
        let v2 = self.v2_payload()?;
        export_to_plain_json(v2).map_err(|e| e.to_string())
    }

    pub fn export_encrypted_json(
        &self,
        export_password: &[u8],
        now_unix: u64,
    ) -> Result<String, String> {
        let v2 = self.v2_payload()?;
        export_to_encrypted_json(v2, export_password, self.kdf_config, now_unix)
            .map_err(|e| e.to_string())
    }

    pub fn export_cxf(
        &self,
        account_email: &str,
        now_unix: u64,
    ) -> Result<CxfExportDocument, String> {
        let v2 = self.v2_payload()?;
        Ok(export_vault_to_cxf(v2, account_email, now_unix))
    }

    pub fn import_cxf(
        &mut self,
        doc: &CxfExportDocument,
        resolution: ConflictResolution,
        now_unix: u64,
    ) -> Result<ImportApplyResult, String> {
        let json = serialize_cxf_json(doc).map_err(|e| e.to_string())?;
        let preview = self.preview_import(&json, Some(ImportFormat::FidoCxf), now_unix)?;
        self.apply_import(preview, resolution, now_unix)
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
    fn test_argon2id_xchacha20_poly1305_vault_roundtrip() {
        let mut vault = SingularityVault::new(fast_kdf());

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

    #[test]
    fn test_v2_end_to_end_multi_slot_polymorphic_workflow() {
        let now = 1_750_000_000u64;
        let mut vault = SingularityVault::new(fast_kdf());

        // Setup all 4 DEK slots: MasterPassword, PIN (5 attempts), BiometricOs, RecoveryKey256
        vault
            .setup_master_password_slot(b"InitialMaster!2026", now)
            .unwrap();
        vault.setup_pin_slot(b"8426", 5, now).unwrap();
        let os_bio = [0x99u8; 32];
        vault
            .setup_biometric_slot("windows-hello", &os_bio, now)
            .unwrap();
        let recovery_b32 = vault.generate_and_bind_recovery_key(now).unwrap();

        // Add folder, never-save domain, polymorphic Login + Card + SSH Key + Wifi + Attachment
        vault
            .upsert_folder(
                VaultFolder {
                    id: "f-dev".into(),
                    name: "Engineering".into(),
                    parent_id: None,
                    icon: Some("code".into()),
                    color: Some("#6366f1".into()),
                    revision: 1,
                    updated_at_unix: now,
                },
                now,
            )
            .unwrap();
        vault
            .add_never_save_domain("https://internal.intranet.local/login", now)
            .unwrap();
        assert!(vault.is_never_save_domain("intranet.local").unwrap());

        let gen_pw = vault
            .generate_and_record_password(
                &PasswordGeneratorConfig::default(),
                Some("github.com".into()),
                now,
            )
            .unwrap();
        let _gen_pp = vault
            .generate_and_record_passphrase(
                &PassphraseConfig {
                    language: WordlistLanguage::French,
                    ..Default::default()
                },
                None,
                now,
            )
            .unwrap();
        assert_eq!(vault.generator_history().unwrap().len(), 2);

        let mut gh_login = LoginPayload::default();
        gh_login.username = "alice@singularity.dev".into();
        gh_login.password = gen_pw.value.clone();
        gh_login.uris = vec![
            VaultUriEntry::new("https://github.com", UriMatchRule::BaseDomain),
            VaultUriEntry::new("https://gist.github.com/login", UriMatchRule::Exact),
        ];
        gh_login.totp_secret_base32 = Some("JBSWY3DPEHPK3PXP".into());
        let mut gh_item = VaultItem::new(
            "gh-1",
            "GitHub Enterprise",
            VaultItemKind::Login(gh_login),
            now,
        );
        gh_item.folder_id = Some("f-dev".into());
        gh_item.favorite = true;
        gh_item.tags = vec!["dev".into(), "oss".into()];
        vault.upsert_item(gh_item, now).unwrap();

        let mut card_payload = CardPayload::default();
        card_payload.cardholder_name = "Alice".into();
        card_payload.number = "4970 1234 5678 9012".into();
        card_payload.brand = detect_card_brand("4970 1234 5678 9012");
        card_payload.exp_month = 11;
        card_payload.exp_year = 2029;
        card_payload.cvv = "456".into();
        let card = VaultItem::new("card-1", "Corporate CB", VaultItemKind::Card(card_payload), now);
        vault.upsert_item(card, now).unwrap();

        // Attach a 96 KiB STREAM AEAD encrypted file
        let blob = vec![0xABu8; 96 * 1024];
        vault
            .seal_and_attach_file(
                "gh-1",
                "att-key",
                "recovery-codes.txt",
                "text/plain",
                &blob,
                now,
            )
            .unwrap();

        // Enroll V2 passkey linked to GitHub login
        let pk = vault
            .enroll_passkey_v2(
                "github.com",
                "GitHub",
                "alice@singularity.dev",
                "Alice",
                PasskeyAlgorithm::Ed25519,
                Some("gh-1".into()),
                now,
            )
            .unwrap();

        // Autofill matching, fuzzy search, phishing detection, health report
        let matches = vault.match_for_uri("https://gist.github.com/login").unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].match_rule, UriMatchRule::Exact);

        let hits = vault.search_items("githb", false).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].item.id, "gh-1");

        let phish = vault.assess_uri_phishing("https://githbu.com/login").unwrap();
        assert!(phish.is_suspicious);

        let health = vault.generate_health_report(now).unwrap();
        assert_eq!(health.global_score, 100);

        // Step-up reauth token (60s TTL)
        let tok = vault.issue_reauth_token(now);
        assert!(vault.verify_reauth_token(&tok, now + 59));
        assert!(!vault.verify_reauth_token(&tok, now + 60));

        // Fast master password change + seal V2 envelope
        vault.change_master_password(b"RotatedMaster!2026", now + 10).unwrap();
        let mut env = vault.seal_v2_envelope(now + 10).unwrap();
        let env_json = env.to_json_pretty().unwrap();

        // Lock vault and unlock via all 4 independent methods!
        vault.lock();
        assert!(vault.is_locked());

        // 1) Auto-detected V2 unlock via import_and_unlock_vault with new master password
        assert!(vault
            .import_and_unlock_vault(&env_json, b"InitialMaster!2026")
            .is_err());
        let cnt = vault
            .import_and_unlock_vault(&env_json, b"RotatedMaster!2026")
            .unwrap();
        assert_eq!(cnt, 3); // 2 items + 1 passkey
        assert_eq!(vault.unseal_attachment("att-key").unwrap(), blob);

        // 2) Unlock via Biometric OS slot
        vault.lock();
        assert_eq!(
            vault.unlock_v2_envelope_with_biometric(&env, &os_bio).unwrap(),
            3
        );

        // 3) Unlock via 256-bit Base32 Recovery Key
        vault.lock();
        assert_eq!(
            vault
                .unlock_v2_envelope_with_recovery_key(&env, &recovery_b32)
                .unwrap(),
            3
        );

        // 4) Unlock via PIN slot, then verify 5 wrong attempts auto-destroy the PIN slot
        vault.lock();
        assert_eq!(vault.unlock_v2_envelope_with_pin(&mut env, b"8426").unwrap(), 3);
        vault.lock();
        for _ in 0..4 {
            assert!(matches!(
                vault.unlock_v2_envelope_with_pin(&mut env, b"0000"),
                Err(VaultCryptoError::DecryptionFailed)
            ));
        }
        assert!(matches!(
            vault.unlock_v2_envelope_with_pin(&mut env, b"0000"),
            Err(VaultCryptoError::PinSlotDestroyed)
        ));
        // Real PIN no longer works, but Recovery Key STILL unlocks!
        assert!(matches!(
            vault.unlock_v2_envelope_with_pin(&mut env, b"8426"),
            Err(VaultCryptoError::PinSlotDestroyed)
        ));
        assert_eq!(
            vault
                .unlock_v2_envelope_with_recovery_key(&env, &recovery_b32)
                .unwrap(),
            3
        );

        // Trash + 30-day purge + Signal API
        assert!(vault.trash_item("card-1", now + 100).unwrap());
        assert_eq!(vault.trashed_items().unwrap().len(), 1);
        assert!(vault
            .signal_unknown_credential("github.com", &pk.credential_id_hex, now + 100)
            .unwrap());
        assert_eq!(
            vault
                .purge_expired_trash(now + 100 + TRASH_RETENTION_SECONDS)
                .unwrap(),
            2
        );
        assert_eq!(vault.items().unwrap().len(), 1);
        assert_eq!(vault.passkeys().unwrap().len(), 0);

        // CXF Export + Import roundtrip
        let cxf_doc = vault.export_cxf("alice@singularity.dev", now + 200).unwrap();
        let mut vault2 = SingularityVault::new(fast_kdf());
        let imp_res = vault2
            .import_cxf(&cxf_doc, ConflictResolution::Overwrite, now + 200)
            .unwrap();
        assert_eq!(imp_res.added, 1);
    }
}
