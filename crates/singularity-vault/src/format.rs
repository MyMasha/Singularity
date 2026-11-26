//! Encrypted `.singularity-vault` V1 (Legacy) & V2 (Multi-Slot DEK/KEK Polymorphic Vault)
//! Envelope Serialization, Zeroizing Item Models, Folders, Trash, History, and AAD Binding.

use crate::crypto::{
    generate_salt_and_xnonce, Argon2idConfig, DataEncryptionKey, DekSlotKind, DerivedVaultKey,
    SealedAttachment, VaultCryptoError, WrappedDekSlot,
};
use crate::matcher::{extract_etld_plus_one, UriMatchRule, VaultUriEntry};
use crate::passkey::StoredPasskeyCredential;
use crate::payment::{mask_card_number, CardBrand};
use crate::totp::{OtpKind, TotpAlgorithm};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroize;

pub const SINGULARITY_VAULT_MAGIC_HEADER: &str = "SINGULARITY-VAULT-V1-XCHACHA20-POLY1305";
pub const SINGULARITY_VAULT_V2_MAGIC_HEADER: &str = "SINGULARITY-VAULT-V2-DEK-XCHACHA20-POLY1305";

/// Maximum retained historical passwords per login item.
pub const PASSWORD_HISTORY_CAP: usize = 20;
/// Maximum retained generated secrets in the vault generator history.
pub const GENERATOR_HISTORY_CAP: usize = 50;
/// Trash retention window before automatic purge (30 days in seconds).
pub const TRASH_RETENTION_SECONDS: u64 = 30 * 24 * 60 * 60;

/// Schema version tag supporting both V1 backwards compatibility and V2 polymorphic DEK vaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum VaultSchemaVersion {
    V1 = 1,
    #[default]
    V2 = 2,
}

// ============================================================================
// V1 LEGACY STRUCTURES (100% BACKWARDS COMPATIBLE)
// ============================================================================

/// A single decrypted login credential + optional TOTP 2FA secret stored inside a V1 vault.
#[derive(Clone, Serialize, Deserialize)]
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

impl fmt::Debug for VaultCredentialEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultCredentialEntry")
            .field("id", &self.id)
            .field("origin_url", &self.origin_url)
            .field("username", &self.username)
            .field("password_secret", &"[REDACTED]")
            .field(
                "totp_secret_base32",
                &self.totp_secret_base32.as_ref().map(|_| "[REDACTED]"),
            )
            .field("totp_algorithm", &self.totp_algorithm)
            .field("totp_digits", &self.totp_digits)
            .field("totp_period_sec", &self.totp_period_sec)
            .field("notes", &"[REDACTED]")
            .finish()
    }
}

impl Drop for VaultCredentialEntry {
    fn drop(&mut self) {
        self.password_secret.zeroize();
        if let Some(ref mut t) = self.totp_secret_base32 {
            t.zeroize();
        }
        self.notes.zeroize();
    }
}

/// Complete decrypted payload inside an unlocked V1 `.singularity-vault`.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct VaultPlaintextPayload {
    pub credentials: Vec<VaultCredentialEntry>,
    pub passkeys: Vec<StoredPasskeyCredential>,
}

impl fmt::Debug for VaultPlaintextPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultPlaintextPayload")
            .field("credentials", &self.credentials)
            .field("passkeys", &self.passkeys)
            .finish()
    }
}

/// Outer encrypted V1 `.singularity-vault` container written to disk.
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
    /// Seals and encrypts `payload` into a V1 `.singularity-vault` JSON document using Argon2id + XChaCha20-Poly1305.
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

    /// Unseals and authenticates a V1 `.singularity-vault` document using `master_password`.
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

// ============================================================================
// V2 POLYMORPHIC VAULT ITEM MODELS (ALL ZEROIZE ON DROP + [REDACTED] DEBUG)
// ============================================================================

/// Historical password entry kept on a `LoginPayload` (capped at 20 entries).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordHistoryEntry {
    pub password: String,
    pub changed_at_unix: u64,
}

impl fmt::Debug for PasswordHistoryEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasswordHistoryEntry")
            .field("password", &"[REDACTED]")
            .field("changed_at_unix", &self.changed_at_unix)
            .finish()
    }
}

impl Drop for PasswordHistoryEntry {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

/// Login item payload with multi-URI autofill rules, OTP configuration, passkey links,
/// and bounded password history (cap 20).
#[derive(Clone, Serialize, Deserialize)]
pub struct LoginPayload {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub uris: Vec<VaultUriEntry>,
    #[serde(default)]
    pub totp_secret_base32: Option<String>,
    #[serde(default)]
    pub totp_algorithm: TotpAlgorithm,
    #[serde(default = "default_totp_digits")]
    pub totp_digits: u32,
    #[serde(default = "default_totp_period")]
    pub totp_period_sec: u64,
    #[serde(default)]
    pub otp_kind: OtpKind,
    #[serde(default)]
    pub password_history: Vec<PasswordHistoryEntry>,
    #[serde(default)]
    pub passkey_ids: Vec<String>,
    #[serde(default)]
    pub autofill_on_page_load: bool,
    #[serde(default)]
    pub notes: String,
}

fn default_totp_digits() -> u32 {
    6
}

fn default_totp_period() -> u64 {
    30
}

fn default_revision() -> u64 {
    1
}

impl Default for LoginPayload {
    fn default() -> Self {
        Self {
            username: String::new(),
            password: String::new(),
            uris: Vec::new(),
            totp_secret_base32: None,
            totp_algorithm: TotpAlgorithm::Sha1,
            totp_digits: 6,
            totp_period_sec: 30,
            otp_kind: OtpKind::Totp,
            password_history: Vec::new(),
            passkey_ids: Vec::new(),
            autofill_on_page_load: false,
            notes: String::new(),
        }
    }
}

impl LoginPayload {
    /// Updates the login password while recording the previous password into `password_history`
    /// (capped at [`PASSWORD_HISTORY_CAP`] = 20 entries).
    pub fn update_password(&mut self, new_password: String, now_unix: u64) {
        if !self.password.is_empty() && self.password != new_password {
            self.password_history.insert(
                0,
                PasswordHistoryEntry {
                    password: self.password.clone(),
                    changed_at_unix: now_unix,
                },
            );
            if self.password_history.len() > PASSWORD_HISTORY_CAP {
                self.password_history.truncate(PASSWORD_HISTORY_CAP);
            }
        }
        self.password.zeroize();
        self.password = new_password;
    }

    /// Returns the primary URI string if at least one URI is attached.
    pub fn primary_uri(&self) -> Option<&str> {
        self.uris.first().map(|u| u.uri.as_str())
    }
}

impl fmt::Debug for LoginPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginPayload")
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .field("uris", &self.uris)
            .field(
                "totp_secret_base32",
                &self.totp_secret_base32.as_ref().map(|_| "[REDACTED]"),
            )
            .field("totp_algorithm", &self.totp_algorithm)
            .field("totp_digits", &self.totp_digits)
            .field("totp_period_sec", &self.totp_period_sec)
            .field("otp_kind", &self.otp_kind)
            .field("password_history_len", &self.password_history.len())
            .field("passkey_ids", &self.passkey_ids)
            .field("notes", &"[REDACTED]")
            .finish()
    }
}

impl Drop for LoginPayload {
    fn drop(&mut self) {
        self.password.zeroize();
        if let Some(ref mut t) = self.totp_secret_base32 {
            t.zeroize();
        }
        self.notes.zeroize();
    }
}

/// Payment card payload with automatic zeroization and masked debug output.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct CardPayload {
    pub cardholder_name: String,
    pub number: String,
    #[serde(default)]
    pub brand: CardBrand,
    pub exp_month: u8,
    pub exp_year: u16,
    pub cvv: String,
    #[serde(default)]
    pub pin: Option<String>,
    #[serde(default)]
    pub billing_address: Option<String>,
    #[serde(default)]
    pub notes: String,
}

impl fmt::Debug for CardPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CardPayload")
            .field("cardholder_name", &self.cardholder_name)
            .field("number", &mask_card_number(&self.number))
            .field("brand", &self.brand)
            .field("exp_month", &self.exp_month)
            .field("exp_year", &self.exp_year)
            .field("cvv", &"[REDACTED]")
            .field("pin", &self.pin.as_ref().map(|_| "[REDACTED]"))
            .field(
                "billing_address",
                &self.billing_address.as_ref().map(|_| "[REDACTED]"),
            )
            .field("notes", &"[REDACTED]")
            .finish()
    }
}

impl Drop for CardPayload {
    fn drop(&mut self) {
        self.number.zeroize();
        self.cvv.zeroize();
        if let Some(ref mut p) = self.pin {
            p.zeroize();
        }
        if let Some(ref mut b) = self.billing_address {
            b.zeroize();
        }
        self.notes.zeroize();
    }
}

/// Personal identity & address autofill payload with automatic zeroization.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct IdentityPayload {
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub first_name: String,
    #[serde(default)]
    pub middle_name: String,
    #[serde(default)]
    pub last_name: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub phone: String,
    #[serde(default)]
    pub company: String,
    #[serde(default)]
    pub address1: String,
    #[serde(default)]
    pub address2: String,
    #[serde(default)]
    pub city: String,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub postal_code: String,
    #[serde(default)]
    pub country: String,
    #[serde(default)]
    pub birth_date: Option<String>,
    #[serde(default)]
    pub national_id: Option<String>,
    #[serde(default)]
    pub passport_number: Option<String>,
    #[serde(default)]
    pub driver_license: Option<String>,
    #[serde(default)]
    pub notes: String,
}

impl fmt::Debug for IdentityPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdentityPayload")
            .field("first_name", &self.first_name)
            .field("last_name", &self.last_name)
            .field("email", &self.email)
            .field("phone", &"[REDACTED]")
            .field("address1", &"[REDACTED]")
            .field("birth_date", &self.birth_date.as_ref().map(|_| "[REDACTED]"))
            .field("national_id", &self.national_id.as_ref().map(|_| "[REDACTED]"))
            .field(
                "passport_number",
                &self.passport_number.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "driver_license",
                &self.driver_license.as_ref().map(|_| "[REDACTED]"),
            )
            .field("notes", &"[REDACTED]")
            .finish()
    }
}

impl Drop for IdentityPayload {
    fn drop(&mut self) {
        self.phone.zeroize();
        self.address1.zeroize();
        self.address2.zeroize();
        if let Some(ref mut v) = self.birth_date {
            v.zeroize();
        }
        if let Some(ref mut v) = self.national_id {
            v.zeroize();
        }
        if let Some(ref mut v) = self.passport_number {
            v.zeroize();
        }
        if let Some(ref mut v) = self.driver_license {
            v.zeroize();
        }
        self.notes.zeroize();
    }
}

/// Encrypted free-form secure note payload.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct SecureNotePayload {
    pub body: String,
    #[serde(default)]
    pub markdown: bool,
}

impl fmt::Debug for SecureNotePayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecureNotePayload")
            .field("body", &"[REDACTED]")
            .field("markdown", &self.markdown)
            .finish()
    }
}

impl Drop for SecureNotePayload {
    fn drop(&mut self) {
        self.body.zeroize();
    }
}

/// SSH private/public keypair payload.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct SshKeyPayload {
    pub private_key_pem: String,
    pub public_key_openssh: String,
    #[serde(default)]
    pub fingerprint_sha256: String,
    #[serde(default)]
    pub passphrase: Option<String>,
    #[serde(default)]
    pub key_type: String,
    #[serde(default)]
    pub notes: String,
}

impl fmt::Debug for SshKeyPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SshKeyPayload")
            .field("private_key_pem", &"[REDACTED]")
            .field("public_key_openssh", &self.public_key_openssh)
            .field("fingerprint_sha256", &self.fingerprint_sha256)
            .field("passphrase", &self.passphrase.as_ref().map(|_| "[REDACTED]"))
            .field("key_type", &self.key_type)
            .field("notes", &"[REDACTED]")
            .finish()
    }
}

impl Drop for SshKeyPayload {
    fn drop(&mut self) {
        self.private_key_pem.zeroize();
        if let Some(ref mut p) = self.passphrase {
            p.zeroize();
        }
        self.notes.zeroize();
    }
}

/// API key / token / OAuth client secret payload.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct ApiSecretPayload {
    pub service_name: String,
    #[serde(default)]
    pub endpoint_url: Option<String>,
    pub api_key: String,
    #[serde(default)]
    pub api_secret: Option<String>,
    #[serde(default)]
    pub access_token: Option<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub expires_at_unix: Option<u64>,
    #[serde(default)]
    pub notes: String,
}

impl fmt::Debug for ApiSecretPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiSecretPayload")
            .field("service_name", &self.service_name)
            .field("endpoint_url", &self.endpoint_url)
            .field("api_key", &"[REDACTED]")
            .field("api_secret", &self.api_secret.as_ref().map(|_| "[REDACTED]"))
            .field(
                "access_token",
                &self.access_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("scopes", &self.scopes)
            .field("expires_at_unix", &self.expires_at_unix)
            .field("notes", &"[REDACTED]")
            .finish()
    }
}

impl Drop for ApiSecretPayload {
    fn drop(&mut self) {
        self.api_key.zeroize();
        if let Some(ref mut s) = self.api_secret {
            s.zeroize();
        }
        if let Some(ref mut t) = self.access_token {
            t.zeroize();
        }
        self.notes.zeroize();
    }
}

/// Software license key payload.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct LicensePayload {
    pub product_name: String,
    #[serde(default)]
    pub version: Option<String>,
    pub license_key: String,
    #[serde(default)]
    pub licensed_to: String,
    #[serde(default)]
    pub registered_email: Option<String>,
    #[serde(default)]
    pub purchase_date: Option<String>,
    #[serde(default)]
    pub expires_at_unix: Option<u64>,
    #[serde(default)]
    pub notes: String,
}

impl fmt::Debug for LicensePayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LicensePayload")
            .field("product_name", &self.product_name)
            .field("version", &self.version)
            .field("license_key", &"[REDACTED]")
            .field("licensed_to", &self.licensed_to)
            .field("registered_email", &self.registered_email)
            .field("purchase_date", &self.purchase_date)
            .field("expires_at_unix", &self.expires_at_unix)
            .field("notes", &"[REDACTED]")
            .finish()
    }
}

impl Drop for LicensePayload {
    fn drop(&mut self) {
        self.license_key.zeroize();
        self.notes.zeroize();
    }
}

/// Wi-Fi network credentials payload.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct WifiPayload {
    pub ssid: String,
    pub password: String,
    #[serde(default)]
    pub security_protocol: String,
    #[serde(default)]
    pub hidden: bool,
    #[serde(default)]
    pub notes: String,
}

impl fmt::Debug for WifiPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WifiPayload")
            .field("ssid", &self.ssid)
            .field("password", &"[REDACTED]")
            .field("security_protocol", &self.security_protocol)
            .field("hidden", &self.hidden)
            .field("notes", &"[REDACTED]")
            .finish()
    }
}

impl Drop for WifiPayload {
    fn drop(&mut self) {
        self.password.zeroize();
        self.notes.zeroize();
    }
}

/// Polymorphic vault item variant.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "item_type", content = "payload", rename_all = "snake_case")]
pub enum VaultItemKind {
    Login(LoginPayload),
    Card(CardPayload),
    Identity(IdentityPayload),
    SecureNote(SecureNotePayload),
    SshKey(SshKeyPayload),
    ApiSecret(ApiSecretPayload),
    License(LicensePayload),
    Wifi(WifiPayload),
}

impl VaultItemKind {
    pub fn type_name(&self) -> &'static str {
        match self {
            VaultItemKind::Login(_) => "login",
            VaultItemKind::Card(_) => "card",
            VaultItemKind::Identity(_) => "identity",
            VaultItemKind::SecureNote(_) => "secure_note",
            VaultItemKind::SshKey(_) => "ssh_key",
            VaultItemKind::ApiSecret(_) => "api_secret",
            VaultItemKind::License(_) => "license",
            VaultItemKind::Wifi(_) => "wifi",
        }
    }
}

/// Kind of custom field attached to a `VaultItem`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CustomFieldKind {
    #[default]
    Text,
    Hidden,
    Boolean,
    Linked,
}

/// Custom field key/value pair attached to a `VaultItem` (zeroized on drop, hidden redacted in Debug).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomField {
    pub name: String,
    pub value: String,
    #[serde(default)]
    pub kind: CustomFieldKind,
}

impl fmt::Debug for CustomField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let shown: &str = match self.kind {
            CustomFieldKind::Hidden => "[REDACTED]",
            _ => &self.value,
        };
        f.debug_struct("CustomField")
            .field("name", &self.name)
            .field("value", &shown)
            .field("kind", &self.kind)
            .finish()
    }
}

impl Drop for CustomField {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

/// Hierarchical folder organizing vault items.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultFolder {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub parent_id: Option<String>,
    #[serde(default)]
    pub icon: Option<String>,
    #[serde(default)]
    pub color: Option<String>,
    #[serde(default = "default_revision")]
    pub revision: u64,
    #[serde(default)]
    pub updated_at_unix: u64,
}

/// Record stored in the vault's secret generator history (capped at 50 entries).
#[derive(Clone, Serialize, Deserialize)]
pub struct GeneratedSecretRecord {
    pub id: String,
    pub secret: String,
    pub kind: String,
    pub entropy_bits: f64,
    #[serde(default)]
    pub origin_hint: Option<String>,
    pub created_at_unix: u64,
}

impl fmt::Debug for GeneratedSecretRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GeneratedSecretRecord")
            .field("id", &self.id)
            .field("secret", &"[REDACTED]")
            .field("kind", &self.kind)
            .field("entropy_bits", &self.entropy_bits)
            .field("origin_hint", &self.origin_hint)
            .field("created_at_unix", &self.created_at_unix)
            .finish()
    }
}

impl Drop for GeneratedSecretRecord {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// Complete V2 polymorphic vault item with folder, tags, favorites, custom fields,
/// soft-delete trash (30-day retention), and CRDT/delta-sync revision metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultItem {
    pub id: String,
    pub name: String,
    pub kind: VaultItemKind,
    #[serde(default)]
    pub folder_id: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub favorite: bool,
    #[serde(default)]
    pub custom_fields: Vec<CustomField>,
    #[serde(default)]
    pub attachment_ids: Vec<String>,
    #[serde(default)]
    pub created_at_unix: u64,
    #[serde(default)]
    pub updated_at_unix: u64,
    #[serde(default)]
    pub password_updated_at_unix: Option<u64>,
    #[serde(default)]
    pub trashed_at: Option<u64>,
    #[serde(default = "default_revision")]
    pub revision: u64,
    #[serde(default)]
    pub reprompt_master_password: bool,
}

impl VaultItem {
    pub fn new(id: impl Into<String>, name: impl Into<String>, kind: VaultItemKind, now_unix: u64) -> Self {
        let pwd_ts = if matches!(kind, VaultItemKind::Login(_)) {
            Some(now_unix)
        } else {
            None
        };
        Self {
            id: id.into(),
            name: name.into(),
            kind,
            folder_id: None,
            tags: Vec::new(),
            favorite: false,
            custom_fields: Vec::new(),
            attachment_ids: Vec::new(),
            created_at_unix: now_unix,
            updated_at_unix: now_unix,
            password_updated_at_unix: pwd_ts,
            trashed_at: None,
            revision: 1,
            reprompt_master_password: false,
        }
    }

    pub fn is_trashed(&self) -> bool {
        self.trashed_at.is_some()
    }

    pub fn move_to_trash(&mut self, now_unix: u64) {
        self.trashed_at = Some(now_unix);
        self.updated_at_unix = now_unix;
        self.revision = self.revision.saturating_add(1);
    }

    pub fn restore_from_trash(&mut self, now_unix: u64) {
        self.trashed_at = None;
        self.updated_at_unix = now_unix;
        self.revision = self.revision.saturating_add(1);
    }

    /// Converts a legacy V1 `VaultCredentialEntry` into a V2 `VaultItem::Login`.
    pub fn from_v1_credential(entry: &VaultCredentialEntry, now_unix: u64) -> Self {
        let display_name = extract_etld_plus_one(&entry.origin_url)
            .unwrap_or_else(|| entry.origin_url.clone());
        let uris = if entry.origin_url.trim().is_empty() {
            Vec::new()
        } else {
            vec![VaultUriEntry::new(
                entry.origin_url.clone(),
                UriMatchRule::BaseDomain,
            )]
        };
        Self::new(
            entry.id.clone(),
            display_name,
            VaultItemKind::Login(LoginPayload {
                username: entry.username.clone(),
                password: entry.password_secret.clone(),
                uris,
                totp_secret_base32: entry.totp_secret_base32.clone(),
                totp_algorithm: entry.totp_algorithm,
                totp_digits: entry.totp_digits,
                totp_period_sec: entry.totp_period_sec,
                otp_kind: OtpKind::Totp,
                password_history: Vec::new(),
                passkey_ids: Vec::new(),
                autofill_on_page_load: false,
                notes: entry.notes.clone(),
            }),
            now_unix,
        )
    }

    /// Projects an active `Login` item back to a legacy V1 `VaultCredentialEntry`.
    pub fn to_v1_credential(&self) -> Option<VaultCredentialEntry> {
        if self.is_trashed() {
            return None;
        }
        let VaultItemKind::Login(ref l) = self.kind else {
            return None;
        };
        let origin_url = l
            .primary_uri()
            .map(String::from)
            .unwrap_or_else(|| self.name.clone());
        Some(VaultCredentialEntry {
            id: self.id.clone(),
            origin_url,
            username: l.username.clone(),
            password_secret: l.password.clone(),
            totp_secret_base32: l.totp_secret_base32.clone(),
            totp_algorithm: l.totp_algorithm,
            totp_digits: l.totp_digits,
            totp_period_sec: l.totp_period_sec,
            notes: l.notes.clone(),
        })
    }
}

/// Complete decrypted V2 vault payload containing polymorphic items, folders, passkeys,
/// generator history, never-save domains, and sealed STREAM attachments.
#[derive(Clone, Serialize, Deserialize)]
pub struct VaultPlaintextPayloadV2 {
    #[serde(default)]
    pub schema_version: VaultSchemaVersion,
    #[serde(default = "default_revision")]
    pub revision: u64,
    #[serde(default)]
    pub updated_at_unix: u64,
    #[serde(default)]
    pub items: Vec<VaultItem>,
    #[serde(default)]
    pub folders: Vec<VaultFolder>,
    #[serde(default)]
    pub passkeys: Vec<StoredPasskeyCredential>,
    #[serde(default)]
    pub generator_history: Vec<GeneratedSecretRecord>,
    #[serde(default)]
    pub never_save_domains: Vec<String>,
    #[serde(default)]
    pub attachments: Vec<SealedAttachment>,
}

impl Default for VaultPlaintextPayloadV2 {
    fn default() -> Self {
        Self {
            schema_version: VaultSchemaVersion::V2,
            revision: 1,
            updated_at_unix: 0,
            items: Vec::new(),
            folders: Vec::new(),
            passkeys: Vec::new(),
            generator_history: Vec::new(),
            never_save_domains: Vec::new(),
            attachments: Vec::new(),
        }
    }
}

impl fmt::Debug for VaultPlaintextPayloadV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultPlaintextPayloadV2")
            .field("schema_version", &self.schema_version)
            .field("revision", &self.revision)
            .field("updated_at_unix", &self.updated_at_unix)
            .field("items", &self.items)
            .field("folders", &self.folders)
            .field("passkeys", &self.passkeys)
            .field("generator_history", &self.generator_history)
            .field("never_save_domains", &self.never_save_domains)
            .field("attachments_len", &self.attachments.len())
            .finish()
    }
}

impl VaultPlaintextPayloadV2 {
    /// Migrates a V1 plaintext payload losslessly into a V2 payload.
    pub fn from_v1(v1: &VaultPlaintextPayload, now_unix: u64) -> Self {
        let items = v1
            .credentials
            .iter()
            .map(|c| VaultItem::from_v1_credential(c, now_unix))
            .collect();
        Self {
            schema_version: VaultSchemaVersion::V2,
            revision: 1,
            updated_at_unix: now_unix,
            items,
            folders: Vec::new(),
            passkeys: v1.passkeys.clone(),
            generator_history: Vec::new(),
            never_save_domains: Vec::new(),
            attachments: Vec::new(),
        }
    }

    /// Projects active Login items and active passkeys into a V1 payload for backwards compatibility.
    pub fn to_v1(&self) -> VaultPlaintextPayload {
        let credentials = self
            .items
            .iter()
            .filter_map(VaultItem::to_v1_credential)
            .collect();
        let passkeys = self
            .passkeys
            .iter()
            .filter(|pk| !pk.is_trashed())
            .cloned()
            .collect();
        VaultPlaintextPayload {
            credentials,
            passkeys,
        }
    }

    /// Increments the CRDT/delta-sync vault revision counter and records `now_unix`.
    pub fn bump_revision(&mut self, now_unix: u64) {
        self.revision = self.revision.saturating_add(1);
        if now_unix > 0 {
            self.updated_at_unix = now_unix;
        }
    }

    /// Permanently removes trashed items and trashed passkeys whose `trashed_at` is older than
    /// 30 days (`TRASH_RETENTION_SECONDS`) relative to `now_unix`. Returns total purged count.
    pub fn purge_expired_trash(&mut self, now_unix: u64) -> usize {
        let before_items = self.items.len();
        self.items.retain(|item| match item.trashed_at {
            Some(ts) => now_unix.saturating_sub(ts) < TRASH_RETENTION_SECONDS,
            None => true,
        });
        let purged_items = before_items - self.items.len();

        let before_pks = self.passkeys.len();
        self.passkeys.retain(|pk| match pk.trashed_at {
            Some(ts) => now_unix.saturating_sub(ts) < TRASH_RETENTION_SECONDS,
            None => true,
        });
        let purged_pks = before_pks - self.passkeys.len();

        let total = purged_items + purged_pks;
        if total > 0 {
            self.bump_revision(now_unix);
        }
        total
    }

    /// Pushes a generated secret into `generator_history`, enforcing the 50-entry cap.
    pub fn push_generator_history(&mut self, record: GeneratedSecretRecord) {
        self.generator_history.insert(0, record);
        if self.generator_history.len() > GENERATOR_HISTORY_CAP {
            self.generator_history.truncate(GENERATOR_HISTORY_CAP);
        }
    }

    /// Registers a domain in `never_save_domains` (normalized to eTLD+1 or lowercase host).
    pub fn add_never_save_domain(&mut self, domain_or_uri: &str, now_unix: u64) -> bool {
        let normalized = extract_etld_plus_one(domain_or_uri)
            .unwrap_or_else(|| domain_or_uri.trim().to_ascii_lowercase());
        if normalized.is_empty() {
            return false;
        }
        if !self.never_save_domains.iter().any(|d| d == &normalized) {
            self.never_save_domains.push(normalized);
            self.bump_revision(now_unix);
            return true;
        }
        false
    }

    /// Checks whether `domain_or_uri` matches an entry in `never_save_domains`.
    pub fn is_never_save_domain(&self, domain_or_uri: &str) -> bool {
        let normalized = extract_etld_plus_one(domain_or_uri)
            .unwrap_or_else(|| domain_or_uri.trim().to_ascii_lowercase());
        let raw_lower = domain_or_uri.trim().to_ascii_lowercase();
        self.never_save_domains
            .iter()
            .any(|d| d == &normalized || d == &raw_lower)
    }
}

/// Outer encrypted V2 `.singularity-vault` container using DEK / multi-slot KEK architecture.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedSingularityVaultEnvelopeV2 {
    pub magic: String,
    pub schema_version: VaultSchemaVersion,
    pub vault_id: String,
    pub revision: u64,
    pub updated_at_unix: u64,
    pub slots: Vec<WrappedDekSlot>,
    pub payload_xnonce_base64: String,
    pub ciphertext_base64: String,
}

fn build_v2_envelope_aad(
    magic: &str,
    vault_id: &str,
    revision: u64,
    updated_at_unix: u64,
    payload_xnonce: &[u8; 24],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(magic.len() + vault_id.len() + 44);
    aad.extend_from_slice(magic.as_bytes());
    aad.push(0);
    aad.extend_from_slice(vault_id.as_bytes());
    aad.push(0);
    aad.extend_from_slice(&revision.to_le_bytes());
    aad.extend_from_slice(&updated_at_unix.to_le_bytes());
    aad.extend_from_slice(payload_xnonce);
    aad
}

/// Inspects a serialized `.singularity-vault` JSON document to detect V1 vs V2 schema version.
pub fn detect_vault_schema_version(vault_json: &str) -> Result<VaultSchemaVersion, VaultCryptoError> {
    let val: serde_json::Value =
        serde_json::from_str(vault_json).map_err(|_| VaultCryptoError::DecryptionFailed)?;
    let magic = val
        .get("magic")
        .and_then(|v| v.as_str())
        .ok_or_else(|| VaultCryptoError::UnsupportedVersion("Missing 'magic' header".into()))?;
    if magic == SINGULARITY_VAULT_MAGIC_HEADER {
        Ok(VaultSchemaVersion::V1)
    } else if magic == SINGULARITY_VAULT_V2_MAGIC_HEADER {
        Ok(VaultSchemaVersion::V2)
    } else {
        Err(VaultCryptoError::UnsupportedVersion(magic.to_string()))
    }
}

impl EncryptedSingularityVaultEnvelopeV2 {
    /// Seals `payload` with an existing 256-bit `dek` and pre-wrapped `slots`.
    pub fn seal_with_dek(
        payload: &VaultPlaintextPayloadV2,
        dek: &DataEncryptionKey,
        slots: Vec<WrappedDekSlot>,
        vault_id: impl Into<String>,
        now_unix: u64,
    ) -> Result<Self, VaultCryptoError> {
        let vault_id = vault_id.into();
        let mut payload_xnonce = [0u8; 24];
        OsRng.fill_bytes(&mut payload_xnonce);

        let mut plaintext_json =
            serde_json::to_vec(payload).map_err(|_| VaultCryptoError::EncryptionFailed)?;
        let aad = build_v2_envelope_aad(
            SINGULARITY_VAULT_V2_MAGIC_HEADER,
            &vault_id,
            payload.revision,
            now_unix,
            &payload_xnonce,
        );
        let enc_res = dek.encrypt_xchacha20_poly1305(&plaintext_json, &payload_xnonce, &aad);
        plaintext_json.zeroize();
        let ciphertext = enc_res?;

        Ok(Self {
            magic: SINGULARITY_VAULT_V2_MAGIC_HEADER.to_string(),
            schema_version: VaultSchemaVersion::V2,
            vault_id,
            revision: payload.revision,
            updated_at_unix: now_unix,
            slots,
            payload_xnonce_base64: BASE64.encode(payload_xnonce),
            ciphertext_base64: BASE64.encode(ciphertext),
        })
    }

    /// Generates a fresh 256-bit DEK, wraps it in a `MasterPassword` slot, and seals `payload`.
    pub fn seal_with_master_password(
        payload: &VaultPlaintextPayloadV2,
        master_password: &[u8],
        kdf_config: Argon2idConfig,
        vault_id: impl Into<String>,
        now_unix: u64,
    ) -> Result<(Self, DataEncryptionKey), VaultCryptoError> {
        let dek = DataEncryptionKey::generate();
        let slot = WrappedDekSlot::wrap_master_password(
            "master-primary",
            &dek,
            master_password,
            kdf_config,
            now_unix,
        )?;
        let env = Self::seal_with_dek(payload, &dek, vec![slot], vault_id, now_unix)?;
        Ok((env, dek))
    }

    /// Serializes this V2 envelope to pretty JSON.
    pub fn to_json_pretty(&self) -> Result<String, VaultCryptoError> {
        serde_json::to_string_pretty(self).map_err(|_| VaultCryptoError::EncryptionFailed)
    }

    /// Parses a V2 envelope from JSON.
    pub fn from_json(json: &str) -> Result<Self, VaultCryptoError> {
        let env: Self =
            serde_json::from_str(json).map_err(|_| VaultCryptoError::DecryptionFailed)?;
        if env.magic != SINGULARITY_VAULT_V2_MAGIC_HEADER {
            return Err(VaultCryptoError::UnsupportedVersion(env.magic));
        }
        Ok(env)
    }

    /// Unseals the ciphertext payload directly with an unwrapped 256-bit `dek`.
    pub fn unseal_with_dek(
        &self,
        dek: &DataEncryptionKey,
    ) -> Result<VaultPlaintextPayloadV2, VaultCryptoError> {
        if self.magic != SINGULARITY_VAULT_V2_MAGIC_HEADER {
            return Err(VaultCryptoError::UnsupportedVersion(self.magic.clone()));
        }
        let nonce_vec = BASE64
            .decode(&self.payload_xnonce_base64)
            .map_err(|_| VaultCryptoError::DecryptionFailed)?;
        let payload_xnonce: [u8; 24] = nonce_vec
            .try_into()
            .map_err(|_| VaultCryptoError::DecryptionFailed)?;
        let ciphertext = BASE64
            .decode(&self.ciphertext_base64)
            .map_err(|_| VaultCryptoError::DecryptionFailed)?;

        let aad = build_v2_envelope_aad(
            &self.magic,
            &self.vault_id,
            self.revision,
            self.updated_at_unix,
            &payload_xnonce,
        );
        let mut plaintext = dek.decrypt_xchacha20_poly1305(&ciphertext, &payload_xnonce, &aad)?;
        let parsed = serde_json::from_slice::<VaultPlaintextPayloadV2>(&plaintext);
        plaintext.zeroize();
        parsed.map_err(|_| VaultCryptoError::DecryptionFailed)
    }

    /// Unlocks this V2 envelope using its `MasterPassword` KEK slot.
    pub fn unseal_with_master_password(
        &self,
        master_password: &[u8],
    ) -> Result<(VaultPlaintextPayloadV2, DataEncryptionKey), VaultCryptoError> {
        let slot = self
            .slots
            .iter()
            .find(|s| matches!(s.kind, DekSlotKind::MasterPassword { .. }) && !s.is_destroyed())
            .ok_or_else(|| VaultCryptoError::SlotNotFound("master_password".into()))?;
        let dek = slot.unwrap_master_password(master_password)?;
        let payload = self.unseal_with_dek(&dek)?;
        Ok((payload, dek))
    }

    /// Unlocks this V2 envelope using its `PinCode` slot (mutating `failed_attempts` and
    /// permanently self-destructing the slot upon reaching `max_attempts`).
    pub fn unseal_with_pin(
        &mut self,
        pin: &[u8],
    ) -> Result<(VaultPlaintextPayloadV2, DataEncryptionKey), VaultCryptoError> {
        let slot_idx = self
            .slots
            .iter()
            .position(|s| matches!(s.kind, DekSlotKind::PinCode { .. }))
            .ok_or_else(|| VaultCryptoError::SlotNotFound("pin_code".into()))?;
        let dek = self.slots[slot_idx].unwrap_pin_code(pin)?;
        let payload = self.unseal_with_dek(&dek)?;
        Ok((payload, dek))
    }

    /// Unlocks this V2 envelope using an OS Biometric Keychain slot.
    pub fn unseal_with_biometric(
        &self,
        biometric_secret: &[u8],
    ) -> Result<(VaultPlaintextPayloadV2, DataEncryptionKey), VaultCryptoError> {
        let slot = self
            .slots
            .iter()
            .find(|s| matches!(s.kind, DekSlotKind::BiometricOs { .. }) && !s.is_destroyed())
            .ok_or_else(|| VaultCryptoError::SlotNotFound("biometric_os".into()))?;
        let dek = slot.unwrap_biometric_os(biometric_secret)?;
        let payload = self.unseal_with_dek(&dek)?;
        Ok((payload, dek))
    }

    /// Unlocks this V2 envelope using its 256-bit Base32 Emergency Recovery Key slot.
    pub fn unseal_with_recovery_key(
        &self,
        recovery_key_base32: &str,
    ) -> Result<(VaultPlaintextPayloadV2, DataEncryptionKey), VaultCryptoError> {
        let slot = self
            .slots
            .iter()
            .find(|s| matches!(s.kind, DekSlotKind::RecoveryKey256 { .. }) && !s.is_destroyed())
            .ok_or_else(|| VaultCryptoError::SlotNotFound("recovery_key_256".into()))?;
        let dek = slot.unwrap_recovery_key(recovery_key_base32)?;
        let payload = self.unseal_with_dek(&dek)?;
        Ok((payload, dek))
    }

    /// Fast master password rotation: re-wraps the existing `dek` into a fresh `MasterPassword` slot
    /// WITHOUT re-encrypting the vault ciphertext or attachments.
    pub fn rotate_master_password_slot(
        &mut self,
        dek: &DataEncryptionKey,
        new_master_password: &[u8],
        kdf_config: Argon2idConfig,
        now_unix: u64,
    ) -> Result<(), VaultCryptoError> {
        let new_slot = WrappedDekSlot::wrap_master_password(
            "master-primary",
            dek,
            new_master_password,
            kdf_config,
            now_unix,
        )?;
        self.slots
            .retain(|s| !matches!(s.kind, DekSlotKind::MasterPassword { .. }));
        self.slots.insert(0, new_slot);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::RecoveryKey256;

    fn fast_kdf() -> Argon2idConfig {
        Argon2idConfig {
            memory_kib: 4096,
            iterations: 1,
            parallelism: 1,
        }
    }

    #[test]
    fn test_vault_debug_redacts_secrets() {
        let entry = VaultCredentialEntry {
            id: "c1".into(),
            origin_url: "https://example.org".into(),
            username: "alice".into(),
            password_secret: "SuperSecretPassword!99".into(),
            totp_secret_base32: Some("JBSWY3DPEHPK3PXP".into()),
            totp_algorithm: TotpAlgorithm::Sha1,
            totp_digits: 6,
            totp_period_sec: 30,
            notes: "recovery-code-123456".into(),
        };
        let pk = StoredPasskeyCredential::enroll_new("example.org", "alice");
        let seed_copy = pk.secret_seed_hex.clone();

        let dbg_entry = format!("{:?}", entry);
        assert!(dbg_entry.contains("[REDACTED]"));
        assert!(!dbg_entry.contains("SuperSecretPassword!99"));
        assert!(!dbg_entry.contains("JBSWY3DPEHPK3PXP"));
        assert!(!dbg_entry.contains("recovery-code-123456"));

        let payload = VaultPlaintextPayload {
            credentials: vec![entry],
            passkeys: vec![pk],
        };
        let dbg_payload = format!("{:?}", payload);
        assert!(dbg_payload.contains("[REDACTED]"));
        assert!(!dbg_payload.contains("SuperSecretPassword!99"));
        assert!(!dbg_payload.contains("JBSWY3DPEHPK3PXP"));
        assert!(!dbg_payload.contains(&seed_copy));
    }

    #[test]
    fn test_v2_all_polymorphic_item_kinds_redact_debug_and_enforce_caps() {
        let mut login = LoginPayload::default();
        login.username = "alice".into();
        login.password = "initial-secret-0".into();
        login.uris = vec![VaultUriEntry::base_domain("https://github.com")];
        login.totp_secret_base32 = Some("JBSWY3DPEHPK3PXP".into());
        login.notes = "secret-login-note".into();
        // Push 25 password rotations -> history capped at 20
        for i in 1..=25 {
            login.update_password(format!("rotated-secret-{}", i), 1_000 + i);
        }
        assert_eq!(login.password_history.len(), PASSWORD_HISTORY_CAP);
        assert_eq!(login.password, "rotated-secret-25");
        assert!(!format!("{:?}", login).contains("rotated-secret-25"));
        assert!(!format!("{:?}", login).contains("secret-login-note"));

        let card = CardPayload {
            cardholder_name: "Alice".into(),
            number: "4242424242424242".into(),
            brand: CardBrand::Visa,
            exp_month: 12,
            exp_year: 2029,
            cvv: "987".into(),
            pin: Some("1357".into()),
            billing_address: Some("10 Rue Rivoli".into()),
            notes: "card-secret-note".into(),
        };
        let card_dbg = format!("{:?}", card);
        assert!(card_dbg.contains("•••• •••• •••• 4242"));
        assert!(!card_dbg.contains("4242424242424242"));
        assert!(!card_dbg.contains("987"));
        assert!(!card_dbg.contains("1357"));

        let mut id_item = IdentityPayload::default();
        id_item.first_name = "Alice".into();
        id_item.last_name = "Liddell".into();
        id_item.national_id = Some("1850575123456".into());
        id_item.passport_number = Some("19AB12345".into());
        assert!(!format!("{:?}", id_item).contains("1850575123456"));
        assert!(!format!("{:?}", id_item).contains("19AB12345"));

        let note = SecureNotePayload {
            body: "seed-phrase-ultra-secret".into(),
            markdown: true,
        };
        assert!(!format!("{:?}", note).contains("seed-phrase-ultra-secret"));

        let mut ssh = SshKeyPayload::default();
        ssh.private_key_pem = "-----BEGIN OPENSSH PRIVATE KEY-----SECRET".into();
        ssh.public_key_openssh = "ssh-ed25519 AAAAC3Nza".into();
        ssh.passphrase = Some("ssh-pass-secret".into());
        assert!(!format!("{:?}", ssh).contains("PRIVATE KEY-----SECRET"));
        assert!(!format!("{:?}", ssh).contains("ssh-pass-secret"));

        let mut api = ApiSecretPayload::default();
        api.service_name = "Stripe".into();
        api.api_key = "sk_live_verysecret".into();
        api.api_secret = Some("whsec_secret".into());
        assert!(!format!("{:?}", api).contains("sk_live_verysecret"));
        assert!(!format!("{:?}", api).contains("whsec_secret"));

        let mut lic = LicensePayload::default();
        lic.product_name = "JetBrains".into();
        lic.license_key = "LIC-SECRET-9999".into();
        assert!(!format!("{:?}", lic).contains("LIC-SECRET-9999"));

        let mut wifi = WifiPayload::default();
        wifi.ssid = "Singularity-5G".into();
        wifi.password = "wifi-wpa3-secret".into();
        wifi.security_protocol = "WPA3-SAE".into();
        assert!(!format!("{:?}", wifi).contains("wifi-wpa3-secret"));

        let hidden_cf = CustomField {
            name: "Security Answer".into(),
            value: "fluffy-dog".into(),
            kind: CustomFieldKind::Hidden,
        };
        assert!(!format!("{:?}", hidden_cf).contains("fluffy-dog"));
    }

    #[test]
    fn test_v2_envelope_fast_password_change_trash_purge_and_generator_cap() {
        let mut payload = VaultPlaintextPayloadV2::default();
        let mut old_item = VaultItem::new(
            "item-trash",
            "Expired Trash",
            VaultItemKind::SecureNote(SecureNotePayload {
                body: "old".into(),
                markdown: false,
            }),
            1_000,
        );
        old_item.move_to_trash(1_000);
        let active_item = VaultItem::new(
            "item-active",
            "Active Note",
            VaultItemKind::SecureNote(SecureNotePayload {
                body: "keep".into(),
                markdown: false,
            }),
            1_000,
        );
        payload.items.push(old_item);
        payload.items.push(active_item);

        // Push 60 generator history entries -> capped at 50
        for i in 0..60 {
            payload.push_generator_history(GeneratedSecretRecord {
                id: format!("gen-{}", i),
                secret: format!("Secret#{}", i),
                kind: "password".into(),
                entropy_bits: 120.0,
                origin_hint: None,
                created_at_unix: 1_000 + i as u64,
            });
        }
        assert_eq!(payload.generator_history.len(), GENERATOR_HISTORY_CAP);

        // Before 30 days: not purged; after 30 days: purged
        assert_eq!(payload.purge_expired_trash(1_000 + TRASH_RETENTION_SECONDS - 1), 0);
        assert_eq!(payload.purge_expired_trash(1_000 + TRASH_RETENTION_SECONDS), 1);
        assert_eq!(payload.items.len(), 1);

        // Seal V2 with master password, attach recovery key, rotate master password WITHOUT changing ciphertext
        let (mut env, dek) = EncryptedSingularityVaultEnvelopeV2::seal_with_master_password(
            &payload,
            b"old-master-pass",
            fast_kdf(),
            "vault-uuid-1",
            5_000,
        )
        .unwrap();
        let orig_ct = env.ciphertext_base64.clone();
        let rk = RecoveryKey256::generate();
        env.slots.push(
            WrappedDekSlot::wrap_recovery_key("rec-1", &dek, &rk, 5_000).unwrap(),
        );

        env.rotate_master_password_slot(&dek, b"brand-new-master-pass", fast_kdf(), 6_000)
            .unwrap();
        // Ciphertext untouched -> O(1) instant master password rotation!
        assert_eq!(env.ciphertext_base64, orig_ct);
        assert!(env.unseal_with_master_password(b"old-master-pass").is_err());

        let (unlocked_mp, _) = env
            .unseal_with_master_password(b"brand-new-master-pass")
            .unwrap();
        assert_eq!(unlocked_mp.items.len(), 1);
        let (unlocked_rk, _) = env
            .unseal_with_recovery_key(&rk.to_formatted_base32())
            .unwrap();
        assert_eq!(unlocked_rk.items.len(), 1);

        let json = env.to_json_pretty().unwrap();
        assert_eq!(
            detect_vault_schema_version(&json).unwrap(),
            VaultSchemaVersion::V2
        );
    }
}
