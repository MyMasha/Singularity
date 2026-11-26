//! FIDO Alliance Credential Exchange Format (CXF v1.0) Serialization/Deserialization
//! and Credential Exchange Protocol (CXP) Authenticated Encrypted Envelope.

use crate::crypto::{
    generate_salt_and_xnonce, hkdf_sha256, Argon2idConfig, DerivedVaultKey, VaultCryptoError,
};
use crate::format::{
    CardPayload, IdentityPayload, LoginPayload, SecureNotePayload, VaultFolder, VaultItem,
    VaultItemKind, VaultPlaintextPayloadV2,
};
use crate::matcher::VaultUriEntry;
use crate::passkey::{PasskeyAlgorithm, StoredPasskeyCredential};
use crate::payment::{detect_card_brand, mask_card_number, CardBrand};
use crate::totp::{OtpKind, TotpAlgorithm};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::Zeroize;

pub const CXP_ENVELOPE_MAGIC: &str = "SINGULARITY-CXP-V1-XCHACHA20-POLY1305";

#[derive(Debug, Error)]
pub enum CxfError {
    #[error("CXF JSON serialization/deserialization error: {0}")]
    Json(String),
    #[error("Unsupported CXF version {major}.{minor}")]
    UnsupportedVersion { major: u16, minor: u16 },
    #[error("CXP cryptographic error: {0}")]
    Crypto(#[from] VaultCryptoError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CxfVersion {
    pub major: u16,
    pub minor: u16,
}

impl Default for CxfVersion {
    fn default() -> Self {
        Self { major: 1, minor: 0 }
    }
}

/// Top-level FIDO Alliance Credential Exchange Format (`CXF`) export document.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CxfExportDocument {
    #[serde(default)]
    pub version: CxfVersion,
    pub exporter: String,
    pub timestamp: u64,
    #[serde(default)]
    pub accounts: Vec<CxfAccount>,
}

/// Account container inside a CXF export document.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CxfAccount {
    pub id: String,
    #[serde(default)]
    pub user_name: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub full_name: Option<String>,
    #[serde(default)]
    pub collections: Vec<CxfCollection>,
    #[serde(default)]
    pub items: Vec<CxfItem>,
}

/// Collection / folder grouping inside a CXF account.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CxfCollection {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub sub_collections: Vec<String>,
    #[serde(default)]
    pub items: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CxfScope {
    #[serde(default)]
    pub urls: Vec<String>,
}

/// A single transferable CXF item containing one or more typed credentials.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CxfItem {
    pub id: String,
    #[serde(default)]
    pub creation_at: Option<u64>,
    #[serde(default)]
    pub modified_at: Option<u64>,
    pub title: String,
    #[serde(default)]
    pub subtitle: Option<String>,
    #[serde(default)]
    pub favorite: Option<bool>,
    #[serde(default)]
    pub scope: Option<CxfScope>,
    #[serde(default)]
    pub credentials: Vec<CxfCredential>,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CxfPasskeyCredential {
    pub credential_id: String,
    pub rp_id: String,
    #[serde(default)]
    pub user_name: String,
    #[serde(default)]
    pub user_display_name: String,
    pub user_handle: String,
    pub key: String,
    #[serde(default)]
    pub public_key: Option<String>,
    #[serde(default = "default_ed25519_alg")]
    pub algorithm: i32,
    #[serde(default)]
    pub sign_count: u32,
}

fn default_ed25519_alg() -> i32 {
    PasskeyAlgorithm::Ed25519.cose_alg_id()
}

impl fmt::Debug for CxfPasskeyCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CxfPasskeyCredential")
            .field("credential_id", &self.credential_id)
            .field("rp_id", &self.rp_id)
            .field("user_name", &self.user_name)
            .field("key", &"[REDACTED]")
            .field("algorithm", &self.algorithm)
            .finish()
    }
}

impl Drop for CxfPasskeyCredential {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CxfBasicAuthCredential {
    #[serde(default)]
    pub user_name: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub urls: Vec<String>,
}

impl fmt::Debug for CxfBasicAuthCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CxfBasicAuthCredential")
            .field("user_name", &self.user_name)
            .field("password", &"[REDACTED]")
            .field("urls", &self.urls)
            .finish()
    }
}

impl Drop for CxfBasicAuthCredential {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CxfTotpCredential {
    pub secret: String,
    #[serde(default = "default_period_30")]
    pub period: u64,
    #[serde(default = "default_digits_6")]
    pub digits: u32,
    #[serde(default = "default_sha1_str")]
    pub algorithm: String,
    #[serde(default)]
    pub issuer: Option<String>,
}

fn default_period_30() -> u64 {
    30
}
fn default_digits_6() -> u32 {
    6
}
fn default_sha1_str() -> String {
    "SHA1".to_string()
}

impl fmt::Debug for CxfTotpCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CxfTotpCredential")
            .field("secret", &"[REDACTED]")
            .field("period", &self.period)
            .field("digits", &self.digits)
            .field("algorithm", &self.algorithm)
            .field("issuer", &self.issuer)
            .finish()
    }
}

impl Drop for CxfTotpCredential {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CxfNoteCredential {
    pub content: String,
}

impl fmt::Debug for CxfNoteCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CxfNoteCredential")
            .field("content", &"[REDACTED]")
            .finish()
    }
}

impl Drop for CxfNoteCredential {
    fn drop(&mut self) {
        self.content.zeroize();
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CxfCreditCardCredential {
    pub number: String,
    #[serde(default)]
    pub full_name: String,
    #[serde(default)]
    pub card_type: String,
    #[serde(default)]
    pub verification_number: String,
    #[serde(default)]
    pub expiry_date: String, // "YYYY-MM"
}

impl fmt::Debug for CxfCreditCardCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CxfCreditCardCredential")
            .field("number", &mask_card_number(&self.number))
            .field("full_name", &self.full_name)
            .field("card_type", &self.card_type)
            .field("verification_number", &"[REDACTED]")
            .field("expiry_date", &self.expiry_date)
            .finish()
    }
}

impl Drop for CxfCreditCardCredential {
    fn drop(&mut self) {
        self.number.zeroize();
        self.verification_number.zeroize();
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CxfAddressCredential {
    #[serde(default)]
    pub full_name: String,
    #[serde(default)]
    pub street: String,
    #[serde(default)]
    pub city: String,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub zip: String,
    #[serde(default)]
    pub country: String,
    #[serde(default)]
    pub tel: String,
    #[serde(default)]
    pub email: String,
}

impl fmt::Debug for CxfAddressCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CxfAddressCredential")
            .field("full_name", &self.full_name)
            .field("street", &"[REDACTED]")
            .field("city", &self.city)
            .field("tel", &"[REDACTED]")
            .field("email", &self.email)
            .finish()
    }
}

impl Drop for CxfAddressCredential {
    fn drop(&mut self) {
        self.street.zeroize();
        self.tel.zeroize();
    }
}

/// FIDO Alliance CXF credential union supporting `passkey`, `basic-auth`, `totp`, `note`,
/// `credit-card`, and `address`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum CxfCredential {
    #[serde(rename = "passkey")]
    Passkey(CxfPasskeyCredential),
    #[serde(rename = "basic-auth")]
    BasicAuth(CxfBasicAuthCredential),
    #[serde(rename = "totp")]
    Totp(CxfTotpCredential),
    #[serde(rename = "note")]
    Note(CxfNoteCredential),
    #[serde(rename = "credit-card")]
    CreditCard(CxfCreditCardCredential),
    #[serde(rename = "address")]
    Address(CxfAddressCredential),
}

/// Exports an unlocked V2 vault payload into a FIDO Alliance CXF v1.0 document.
pub fn export_vault_to_cxf(
    payload: &VaultPlaintextPayloadV2,
    account_email: &str,
    now_unix: u64,
) -> CxfExportDocument {
    let mut cxf_items: Vec<CxfItem> = Vec::new();
    let mut exported_passkey_ids: Vec<String> = Vec::new();

    for item in &payload.items {
        if item.is_trashed() {
            continue;
        }
        let mut creds = Vec::new();
        let mut urls = Vec::new();

        match &item.kind {
            VaultItemKind::Login(l) => {
                urls = l.uris.iter().map(|u| u.uri.clone()).collect();
                creds.push(CxfCredential::BasicAuth(CxfBasicAuthCredential {
                    user_name: l.username.clone(),
                    password: l.password.clone(),
                    urls: urls.clone(),
                }));
                if let Some(ref secret) = l.totp_secret_base32 {
                    if !secret.trim().is_empty() {
                        creds.push(CxfCredential::Totp(CxfTotpCredential {
                            secret: secret.clone(),
                            period: l.totp_period_sec,
                            digits: l.totp_digits,
                            algorithm: l.totp_algorithm.as_otpauth_str().to_string(),
                            issuer: Some(item.name.clone()),
                        }));
                    }
                }
                if !l.notes.trim().is_empty() {
                    creds.push(CxfCredential::Note(CxfNoteCredential {
                        content: l.notes.clone(),
                    }));
                }
                for pk in &payload.passkeys {
                    if !pk.is_trashed()
                        && (l.passkey_ids.contains(&pk.credential_id_hex)
                            || pk.linked_item_id.as_deref() == Some(item.id.as_str()))
                    {
                        exported_passkey_ids.push(pk.credential_id_hex.clone());
                        creds.push(CxfCredential::Passkey(CxfPasskeyCredential {
                            credential_id: pk.credential_id_hex.clone(),
                            rp_id: pk.rp_id.clone(),
                            user_name: pk.user_name.clone(),
                            user_display_name: pk.user_display_name.clone(),
                            user_handle: pk.user_handle_hex.clone(),
                            key: pk.secret_seed_hex.clone(),
                            public_key: Some(pk.public_key_hex.clone()),
                            algorithm: pk.algorithm.cose_alg_id(),
                            sign_count: pk.sign_count,
                        }));
                    }
                }
            }
            VaultItemKind::Card(c) => {
                let expiry_date = format!("{:04}-{:02}", c.exp_year, c.exp_month);
                creds.push(CxfCredential::CreditCard(CxfCreditCardCredential {
                    number: c.number.clone(),
                    full_name: c.cardholder_name.clone(),
                    card_type: c.brand.display_name().to_string(),
                    verification_number: c.cvv.clone(),
                    expiry_date,
                }));
                if !c.notes.trim().is_empty() {
                    creds.push(CxfCredential::Note(CxfNoteCredential {
                        content: c.notes.clone(),
                    }));
                }
            }
            VaultItemKind::Identity(id) => {
                let full_name = format!("{} {}", id.first_name, id.last_name)
                    .trim()
                    .to_string();
                creds.push(CxfCredential::Address(CxfAddressCredential {
                    full_name,
                    street: id.address1.clone(),
                    city: id.city.clone(),
                    state: id.state.clone(),
                    zip: id.postal_code.clone(),
                    country: id.country.clone(),
                    tel: id.phone.clone(),
                    email: id.email.clone(),
                }));
            }
            VaultItemKind::SecureNote(n) => {
                creds.push(CxfCredential::Note(CxfNoteCredential {
                    content: n.body.clone(),
                }));
            }
            VaultItemKind::SshKey(s) => {
                creds.push(CxfCredential::Note(CxfNoteCredential {
                    content: format!(
                        "[SSH KEY {}]\n{}\n{}",
                        s.key_type, s.public_key_openssh, s.private_key_pem
                    ),
                }));
            }
            VaultItemKind::ApiSecret(a) => {
                creds.push(CxfCredential::Note(CxfNoteCredential {
                    content: format!("service={}\napi_key={}", a.service_name, a.api_key),
                }));
            }
            VaultItemKind::License(lic) => {
                creds.push(CxfCredential::Note(CxfNoteCredential {
                    content: format!("product={}\nlicense={}", lic.product_name, lic.license_key),
                }));
            }
            VaultItemKind::Wifi(w) => {
                creds.push(CxfCredential::Note(CxfNoteCredential {
                    content: format!(
                        "ssid={}\nsecurity={}\npassword={}",
                        w.ssid, w.security_protocol, w.password
                    ),
                }));
            }
        }

        cxf_items.push(CxfItem {
            id: item.id.clone(),
            creation_at: Some(item.created_at_unix),
            modified_at: Some(item.updated_at_unix),
            title: item.name.clone(),
            subtitle: None,
            favorite: Some(item.favorite),
            scope: if urls.is_empty() {
                None
            } else {
                Some(CxfScope { urls })
            },
            credentials: creds,
            tags: item.tags.clone(),
        });
    }

    // Export standalone passkeys not linked to a Login item
    for pk in &payload.passkeys {
        if pk.is_trashed() || exported_passkey_ids.contains(&pk.credential_id_hex) {
            continue;
        }
        cxf_items.push(CxfItem {
            id: format!("passkey-{}", pk.credential_id_hex),
            creation_at: Some(pk.created_at_unix),
            modified_at: pk.last_used_at_unix,
            title: if pk.rp_name.is_empty() {
                pk.rp_id.clone()
            } else {
                pk.rp_name.clone()
            },
            subtitle: Some(pk.user_display_name.clone()),
            favorite: Some(false),
            scope: Some(CxfScope {
                urls: vec![format!("https://{}", pk.rp_id)],
            }),
            credentials: vec![CxfCredential::Passkey(CxfPasskeyCredential {
                credential_id: pk.credential_id_hex.clone(),
                rp_id: pk.rp_id.clone(),
                user_name: pk.user_name.clone(),
                user_display_name: pk.user_display_name.clone(),
                user_handle: pk.user_handle_hex.clone(),
                key: pk.secret_seed_hex.clone(),
                public_key: Some(pk.public_key_hex.clone()),
                algorithm: pk.algorithm.cose_alg_id(),
                sign_count: pk.sign_count,
            })],
            tags: vec!["passkey".to_string()],
        });
    }

    // Build collections from VaultFolders
    let collections: Vec<CxfCollection> = payload
        .folders
        .iter()
        .map(|f| {
            let sub_collections: Vec<String> = payload
                .folders
                .iter()
                .filter(|child| child.parent_id.as_deref() == Some(f.id.as_str()))
                .map(|child| child.id.clone())
                .collect();
            let items: Vec<String> = payload
                .items
                .iter()
                .filter(|it| !it.is_trashed() && it.folder_id.as_deref() == Some(f.id.as_str()))
                .map(|it| it.id.clone())
                .collect();
            CxfCollection {
                id: f.id.clone(),
                title: f.name.clone(),
                sub_collections,
                items,
            }
        })
        .collect();

    CxfExportDocument {
        version: CxfVersion::default(),
        exporter: "Singularity Vault".to_string(),
        timestamp: now_unix,
        accounts: vec![CxfAccount {
            id: "singularity-primary".to_string(),
            user_name: account_email.to_string(),
            email: account_email.to_string(),
            full_name: None,
            collections,
            items: cxf_items,
        }],
    }
}

/// Converts a FIDO CXF document back into V2 `VaultItem`s, `VaultFolder`s, and `StoredPasskeyCredential`s.
pub fn import_cxf_to_vault_parts(
    doc: &CxfExportDocument,
    now_unix: u64,
) -> (Vec<VaultItem>, Vec<VaultFolder>, Vec<StoredPasskeyCredential>) {
    let mut items = Vec::new();
    let mut folders = Vec::new();
    let mut passkeys = Vec::new();

    for account in &doc.accounts {
        // Reconstruct folder parent relationships from collections
        let mut parent_map: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        let mut item_folder_map: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();

        for col in &account.collections {
            for sub in &col.sub_collections {
                parent_map.insert(sub.clone(), col.id.clone());
            }
            for item_id in &col.items {
                item_folder_map.insert(item_id.clone(), col.id.clone());
            }
        }
        for col in &account.collections {
            folders.push(VaultFolder {
                id: col.id.clone(),
                name: col.title.clone(),
                parent_id: parent_map.get(&col.id).cloned(),
                icon: None,
                color: None,
                revision: 1,
                updated_at_unix: now_unix,
            });
        }

        for cxf_item in &account.items {
            let created = cxf_item.creation_at.unwrap_or(now_unix);
            let modified = cxf_item.modified_at.unwrap_or(now_unix);

            let mut basic_auth: Option<&CxfBasicAuthCredential> = None;
            let mut totp: Option<&CxfTotpCredential> = None;
            let mut note: Option<&CxfNoteCredential> = None;
            let mut card: Option<&CxfCreditCardCredential> = None;
            let mut addr: Option<&CxfAddressCredential> = None;
            let mut item_passkeys: Vec<String> = Vec::new();

            for cred in &cxf_item.credentials {
                match cred {
                    CxfCredential::BasicAuth(b) => basic_auth = Some(b),
                    CxfCredential::Totp(t) => totp = Some(t),
                    CxfCredential::Note(n) => note = Some(n),
                    CxfCredential::CreditCard(c) => card = Some(c),
                    CxfCredential::Address(a) => addr = Some(a),
                    CxfCredential::Passkey(pk) => {
                        item_passkeys.push(pk.credential_id.clone());
                        passkeys.push(StoredPasskeyCredential {
                            credential_id_hex: pk.credential_id.clone(),
                            rp_id: pk.rp_id.clone(),
                            user_handle_hex: pk.user_handle.clone(),
                            user_display_name: pk.user_display_name.clone(),
                            public_key_hex: pk.public_key.clone().unwrap_or_default(),
                            secret_seed_hex: pk.key.clone(),
                            sign_count: pk.sign_count,
                            algorithm: PasskeyAlgorithm::from_cose_alg_id(pk.algorithm)
                                .unwrap_or(PasskeyAlgorithm::Ed25519),
                            rp_name: cxf_item.title.clone(),
                            user_name: pk.user_name.clone(),
                            created_at_unix: created,
                            last_used_at_unix: cxf_item.modified_at,
                            linked_item_id: Some(cxf_item.id.clone()),
                            trashed_at: None,
                            audit_log: Vec::new(),
                        });
                    }
                }
            }

            let kind = if let Some(b) = basic_auth {
                let mut uris: Vec<VaultUriEntry> = b
                    .urls
                    .iter()
                    .map(|u| VaultUriEntry::base_domain(u.clone()))
                    .collect();
                if uris.is_empty() {
                    if let Some(ref scope) = cxf_item.scope {
                        uris = scope
                            .urls
                            .iter()
                            .map(|u| VaultUriEntry::base_domain(u.clone()))
                            .collect();
                    }
                }
                let (totp_secret, totp_alg, totp_digits, totp_period) = match totp {
                    Some(t) => (
                        Some(t.secret.clone()),
                        TotpAlgorithm::from_otpauth_str(&t.algorithm).unwrap_or(TotpAlgorithm::Sha1),
                        t.digits,
                        t.period,
                    ),
                    None => (None, TotpAlgorithm::Sha1, 6, 30),
                };
                Some(VaultItemKind::Login(LoginPayload {
                    username: b.user_name.clone(),
                    password: b.password.clone(),
                    uris,
                    totp_secret_base32: totp_secret,
                    totp_algorithm: totp_alg,
                    totp_digits,
                    totp_period_sec: totp_period,
                    otp_kind: OtpKind::Totp,
                    password_history: Vec::new(),
                    passkey_ids: item_passkeys,
                    autofill_on_page_load: false,
                    notes: note.map(|n| n.content.clone()).unwrap_or_default(),
                }))
            } else if let Some(c) = card {
                let (exp_year, exp_month) = parse_cxf_expiry(&c.expiry_date);
                let brand = match CardBrand::from_name(&c.card_type) {
                    CardBrand::Unknown => detect_card_brand(&c.number),
                    known => known,
                };
                Some(VaultItemKind::Card(CardPayload {
                    cardholder_name: c.full_name.clone(),
                    number: c.number.clone(),
                    brand,
                    exp_month,
                    exp_year,
                    cvv: c.verification_number.clone(),
                    pin: None,
                    billing_address: None,
                    notes: note.map(|n| n.content.clone()).unwrap_or_default(),
                }))
            } else if let Some(a) = addr {
                let (first, last) = match a.full_name.trim().split_once(' ') {
                    Some((f, l)) => (f.to_string(), l.to_string()),
                    None => (a.full_name.clone(), String::new()),
                };
                let mut idp = IdentityPayload::default();
                idp.first_name = first;
                idp.last_name = last;
                idp.email = a.email.clone();
                idp.phone = a.tel.clone();
                idp.address1 = a.street.clone();
                idp.city = a.city.clone();
                idp.state = a.state.clone();
                idp.postal_code = a.zip.clone();
                idp.country = a.country.clone();
                Some(VaultItemKind::Identity(idp))
            } else if let Some(n) = note {
                Some(VaultItemKind::SecureNote(SecureNotePayload {
                    body: n.content.clone(),
                    markdown: false,
                }))
            } else if let Some(t) = totp {
                // Standalone TOTP item
                let uris = cxf_item
                    .scope
                    .as_ref()
                    .map(|s| {
                        s.urls
                            .iter()
                            .map(|u| VaultUriEntry::base_domain(u.clone()))
                            .collect()
                    })
                    .unwrap_or_default();
                let mut lp = LoginPayload::default();
                lp.username = cxf_item.subtitle.clone().unwrap_or_default();
                lp.uris = uris;
                lp.totp_secret_base32 = Some(t.secret.clone());
                lp.totp_algorithm =
                    TotpAlgorithm::from_otpauth_str(&t.algorithm).unwrap_or(TotpAlgorithm::Sha1);
                lp.totp_digits = t.digits;
                lp.totp_period_sec = t.period;
                lp.otp_kind = OtpKind::Totp;
                Some(VaultItemKind::Login(lp))
            } else {
                None
            };

            if let Some(item_kind) = kind {
                let mut item = VaultItem::new(cxf_item.id.clone(), cxf_item.title.clone(), item_kind, created);
                item.updated_at_unix = modified;
                item.favorite = cxf_item.favorite.unwrap_or(false);
                item.tags = cxf_item.tags.clone();
                item.folder_id = item_folder_map.get(&cxf_item.id).cloned();
                items.push(item);
            }
        }
    }

    (items, folders, passkeys)
}

fn parse_cxf_expiry(expiry: &str) -> (u16, u8) {
    let trimmed = expiry.trim();
    if let Some((y, m)) = trimmed.split_once('-') {
        if let (Ok(yv), Ok(mv)) = (y.parse::<u16>(), m.parse::<u8>()) {
            return (yv, mv);
        }
    }
    if let Some((m, y)) = trimmed.split_once('/') {
        if let (Ok(mv), Ok(yv)) = (m.parse::<u8>(), y.parse::<u16>()) {
            let full_y = if yv < 100 { 2000 + yv } else { yv };
            return (full_y, mv);
        }
    }
    (0, 0)
}

pub fn serialize_cxf_json(doc: &CxfExportDocument) -> Result<String, CxfError> {
    serde_json::to_string_pretty(doc).map_err(|e| CxfError::Json(e.to_string()))
}

pub fn deserialize_cxf_json(json: &str) -> Result<CxfExportDocument, CxfError> {
    let doc: CxfExportDocument =
        serde_json::from_str(json).map_err(|e| CxfError::Json(e.to_string()))?;
    if doc.version.major != 1 {
        return Err(CxfError::UnsupportedVersion {
            major: doc.version.major,
            minor: doc.version.minor,
        });
    }
    Ok(doc)
}

// ============================================================================
// CXP AUTHENTICATED ENCRYPTED ENVELOPE
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum CxpProtection {
    Password {
        kdf_config: Argon2idConfig,
        salt_base64: String,
    },
    X25519 {
        ephemeral_public_key_base64: String,
        salt_base64: String,
    },
}

/// FIDO CXP encrypted transfer envelope wrapping a `CxfExportDocument` with XChaCha20-Poly1305.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CxpEncryptedEnvelope {
    pub magic: String,
    pub cxf_version: CxfVersion,
    pub exporter: String,
    pub timestamp: u64,
    pub protection: CxpProtection,
    pub xnonce_base64: String,
    pub ciphertext_base64: String,
}

fn build_cxp_aad(
    magic: &str,
    version: CxfVersion,
    exporter: &str,
    timestamp: u64,
    extra: &[u8],
    xnonce: &[u8; 24],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(64 + magic.len() + exporter.len() + extra.len());
    aad.extend_from_slice(magic.as_bytes());
    aad.extend_from_slice(&version.major.to_le_bytes());
    aad.extend_from_slice(&version.minor.to_le_bytes());
    aad.extend_from_slice(exporter.as_bytes());
    aad.extend_from_slice(&timestamp.to_le_bytes());
    aad.extend_from_slice(extra);
    aad.extend_from_slice(xnonce);
    aad
}

impl CxpEncryptedEnvelope {
    /// Seals a `CxfExportDocument` into a password-protected CXP envelope (Argon2id + XChaCha20-Poly1305).
    pub fn seal_with_password(
        doc: &CxfExportDocument,
        password: &[u8],
        kdf_config: Argon2idConfig,
    ) -> Result<Self, CxfError> {
        kdf_config.validate_bounds()?;
        let (salt, xnonce) = generate_salt_and_xnonce();
        let key = DerivedVaultKey::derive_argon2id(password, &salt, kdf_config)?;

        let mut pt = serde_json::to_vec(doc).map_err(|e| CxfError::Json(e.to_string()))?;
        let mut extra = Vec::with_capacity(48);
        extra.extend_from_slice(b"pwd");
        extra.extend_from_slice(&kdf_config.memory_kib.to_le_bytes());
        extra.extend_from_slice(&kdf_config.iterations.to_le_bytes());
        extra.extend_from_slice(&kdf_config.parallelism.to_le_bytes());
        extra.extend_from_slice(&salt);

        let aad = build_cxp_aad(
            CXP_ENVELOPE_MAGIC,
            doc.version,
            &doc.exporter,
            doc.timestamp,
            &extra,
            &xnonce,
        );
        let enc = key.encrypt_xchacha20_poly1305(&pt, &xnonce, &aad);
        pt.zeroize();
        let ciphertext = enc?;

        Ok(Self {
            magic: CXP_ENVELOPE_MAGIC.to_string(),
            cxf_version: doc.version,
            exporter: doc.exporter.clone(),
            timestamp: doc.timestamp,
            protection: CxpProtection::Password {
                kdf_config,
                salt_base64: BASE64.encode(salt),
            },
            xnonce_base64: BASE64.encode(xnonce),
            ciphertext_base64: BASE64.encode(ciphertext),
        })
    }

    /// Seals a `CxfExportDocument` into an X25519-encrypted CXP envelope for a recipient public key.
    pub fn seal_with_x25519(
        doc: &CxfExportDocument,
        recipient_public_key: &[u8; 32],
    ) -> Result<Self, CxfError> {
        let (salt, xnonce) = generate_salt_and_xnonce();
        let eph_secret = X25519StaticSecret::random_from_rng(OsRng);
        let eph_pub = X25519PublicKey::from(&eph_secret);
        let rec_pub = X25519PublicKey::from(*recipient_public_key);
        let shared = eph_secret.diffie_hellman(&rec_pub);
        if !shared.was_contributory() {
            return Err(VaultCryptoError::InvalidKey("Non-contributory X25519 key".into()).into());
        }

        let mut info = Vec::with_capacity(96);
        info.extend_from_slice(b"singularity-cxp-v1-x25519:");
        info.extend_from_slice(eph_pub.as_bytes());
        info.extend_from_slice(rec_pub.as_bytes());
        let mut key_bytes = [0u8; 32];
        hkdf_sha256(&salt, shared.as_bytes(), &info, &mut key_bytes)?;
        let key = DerivedVaultKey::from_bytes(key_bytes);
        key_bytes.zeroize();

        let mut pt = serde_json::to_vec(doc).map_err(|e| CxfError::Json(e.to_string()))?;
        let mut extra = Vec::with_capacity(72);
        extra.extend_from_slice(b"x25519");
        extra.extend_from_slice(eph_pub.as_bytes());
        extra.extend_from_slice(&salt);

        let aad = build_cxp_aad(
            CXP_ENVELOPE_MAGIC,
            doc.version,
            &doc.exporter,
            doc.timestamp,
            &extra,
            &xnonce,
        );
        let enc = key.encrypt_xchacha20_poly1305(&pt, &xnonce, &aad);
        pt.zeroize();
        let ciphertext = enc?;

        Ok(Self {
            magic: CXP_ENVELOPE_MAGIC.to_string(),
            cxf_version: doc.version,
            exporter: doc.exporter.clone(),
            timestamp: doc.timestamp,
            protection: CxpProtection::X25519 {
                ephemeral_public_key_base64: BASE64.encode(eph_pub.as_bytes()),
                salt_base64: BASE64.encode(salt),
            },
            xnonce_base64: BASE64.encode(xnonce),
            ciphertext_base64: BASE64.encode(ciphertext),
        })
    }

    /// Unseals a password-protected CXP envelope back into a `CxfExportDocument`.
    pub fn unseal_with_password(&self, password: &[u8]) -> Result<CxfExportDocument, CxfError> {
        if self.magic != CXP_ENVELOPE_MAGIC {
            return Err(VaultCryptoError::DecryptionFailed.into());
        }
        let CxpProtection::Password {
            kdf_config,
            ref salt_base64,
        } = self.protection
        else {
            return Err(VaultCryptoError::DecryptionFailed.into());
        };
        kdf_config.validate_bounds()?;
        let salt: [u8; 32] = BASE64
            .decode(salt_base64)
            .map_err(|_| VaultCryptoError::DecryptionFailed)?
            .try_into()
            .map_err(|_| VaultCryptoError::DecryptionFailed)?;
        let xnonce: [u8; 24] = BASE64
            .decode(&self.xnonce_base64)
            .map_err(|_| VaultCryptoError::DecryptionFailed)?
            .try_into()
            .map_err(|_| VaultCryptoError::DecryptionFailed)?;
        let ct = BASE64
            .decode(&self.ciphertext_base64)
            .map_err(|_| VaultCryptoError::DecryptionFailed)?;

        let key = DerivedVaultKey::derive_argon2id(password, &salt, kdf_config)?;
        let mut extra = Vec::with_capacity(48);
        extra.extend_from_slice(b"pwd");
        extra.extend_from_slice(&kdf_config.memory_kib.to_le_bytes());
        extra.extend_from_slice(&kdf_config.iterations.to_le_bytes());
        extra.extend_from_slice(&kdf_config.parallelism.to_le_bytes());
        extra.extend_from_slice(&salt);

        let aad = build_cxp_aad(
            &self.magic,
            self.cxf_version,
            &self.exporter,
            self.timestamp,
            &extra,
            &xnonce,
        );
        let mut pt = key.decrypt_xchacha20_poly1305(&ct, &xnonce, &aad)?;
        let parsed = serde_json::from_slice::<CxfExportDocument>(&pt)
            .map_err(|e| CxfError::Json(e.to_string()));
        pt.zeroize();
        parsed
    }

    /// Unseals an X25519-protected CXP envelope using the recipient's 32-byte private key.
    pub fn unseal_with_x25519(
        &self,
        recipient_secret_bytes: &[u8; 32],
    ) -> Result<CxfExportDocument, CxfError> {
        if self.magic != CXP_ENVELOPE_MAGIC {
            return Err(VaultCryptoError::DecryptionFailed.into());
        }
        let CxpProtection::X25519 {
            ref ephemeral_public_key_base64,
            ref salt_base64,
        } = self.protection
        else {
            return Err(VaultCryptoError::DecryptionFailed.into());
        };
        let eph_pub_arr: [u8; 32] = BASE64
            .decode(ephemeral_public_key_base64)
            .map_err(|_| VaultCryptoError::DecryptionFailed)?
            .try_into()
            .map_err(|_| VaultCryptoError::DecryptionFailed)?;
        let salt: [u8; 32] = BASE64
            .decode(salt_base64)
            .map_err(|_| VaultCryptoError::DecryptionFailed)?
            .try_into()
            .map_err(|_| VaultCryptoError::DecryptionFailed)?;
        let xnonce: [u8; 24] = BASE64
            .decode(&self.xnonce_base64)
            .map_err(|_| VaultCryptoError::DecryptionFailed)?
            .try_into()
            .map_err(|_| VaultCryptoError::DecryptionFailed)?;
        let ct = BASE64
            .decode(&self.ciphertext_base64)
            .map_err(|_| VaultCryptoError::DecryptionFailed)?;

        let rec_secret = X25519StaticSecret::from(*recipient_secret_bytes);
        let rec_pub = X25519PublicKey::from(&rec_secret);
        let eph_pub = X25519PublicKey::from(eph_pub_arr);
        let shared = rec_secret.diffie_hellman(&eph_pub);
        if !shared.was_contributory() {
            return Err(VaultCryptoError::DecryptionFailed.into());
        }

        let mut info = Vec::with_capacity(96);
        info.extend_from_slice(b"singularity-cxp-v1-x25519:");
        info.extend_from_slice(eph_pub.as_bytes());
        info.extend_from_slice(rec_pub.as_bytes());
        let mut key_bytes = [0u8; 32];
        hkdf_sha256(&salt, shared.as_bytes(), &info, &mut key_bytes)?;
        let key = DerivedVaultKey::from_bytes(key_bytes);
        key_bytes.zeroize();

        let mut extra = Vec::with_capacity(72);
        extra.extend_from_slice(b"x25519");
        extra.extend_from_slice(eph_pub.as_bytes());
        extra.extend_from_slice(&salt);

        let aad = build_cxp_aad(
            &self.magic,
            self.cxf_version,
            &self.exporter,
            self.timestamp,
            &extra,
            &xnonce,
        );
        let mut pt = key.decrypt_xchacha20_poly1305(&ct, &xnonce, &aad)?;
        let parsed = serde_json::from_slice::<CxfExportDocument>(&pt)
            .map_err(|e| CxfError::Json(e.to_string()));
        pt.zeroize();
        parsed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SendX25519Keypair;

    #[test]
    fn test_cxf_export_import_roundtrip_and_cxp_encrypted_envelopes() {
        let mut payload = VaultPlaintextPayloadV2::default();
        payload.folders.push(VaultFolder {
            id: "f-work".into(),
            name: "Work".into(),
            parent_id: None,
            icon: None,
            color: None,
            revision: 1,
            updated_at_unix: 100,
        });
        let pk = StoredPasskeyCredential::enroll_new("github.com", "alice");
        let mut lp = LoginPayload::default();
        lp.username = "alice@example.com".into();
        lp.password = "CxfSecret!Password#99".into();
        lp.uris = vec![VaultUriEntry::base_domain("https://github.com")];
        lp.totp_secret_base32 = Some("JBSWY3DPEHPK3PXP".into());
        lp.passkey_ids = vec![pk.credential_id_hex.clone()];
        let mut login_item = VaultItem::new("it-1", "GitHub", VaultItemKind::Login(lp), 1_000);
        login_item.folder_id = Some("f-work".into());

        let mut cp = CardPayload::default();
        cp.cardholder_name = "Alice Liddell".into();
        cp.number = "4242424242424242".into();
        cp.brand = CardBrand::Visa;
        cp.exp_month = 8;
        cp.exp_year = 2029;
        cp.cvv = "321".into();
        let card_item = VaultItem::new("it-2", "Main Visa", VaultItemKind::Card(cp), 1_000);
        payload.items.push(login_item);
        payload.items.push(card_item);
        payload.passkeys.push(pk);

        let doc = export_vault_to_cxf(&payload, "alice@example.com", 2_000);
        let json = serialize_cxf_json(&doc).expect("serialize CXF");
        assert!(json.contains("\"basic-auth\""));
        assert!(json.contains("\"totp\""));
        assert!(json.contains("\"passkey\""));
        assert!(json.contains("\"credit-card\""));

        let parsed = deserialize_cxf_json(&json).expect("deserialize CXF");
        let (items, folders, passkeys) = import_cxf_to_vault_parts(&parsed, 3_000);
        assert_eq!(items.len(), 2);
        assert_eq!(folders.len(), 1);
        assert_eq!(passkeys.len(), 1);

        // CXP Password Envelope
        let fast_kdf = Argon2idConfig {
            memory_kib: 4096,
            iterations: 1,
            parallelism: 1,
        };
        let cxp_pwd = CxpEncryptedEnvelope::seal_with_password(&doc, b"transfer-code", fast_kdf)
            .expect("seal CXP pwd");
        assert!(cxp_pwd.unseal_with_password(b"wrong").is_err());
        let unsealed_pwd = cxp_pwd.unseal_with_password(b"transfer-code").unwrap();
        assert_eq!(unsealed_pwd.accounts[0].items.len(), 2);

        // CXP X25519 Envelope
        let recipient = SendX25519Keypair::generate();
        let cxp_x = CxpEncryptedEnvelope::seal_with_x25519(&doc, recipient.public_key_bytes())
            .expect("seal CXP x25519");
        let unsealed_x = cxp_x.unseal_with_x25519(recipient.secret_key_bytes()).unwrap();
        assert_eq!(unsealed_x.accounts[0].items.len(), 2);
    }
}
