//! FIDO2 / WebAuthn Level 3 Software Passkey Authenticator (Asymmetric Ed25519 / COSE EdDSA -8,
//! Canonical CTAP2 CBOR/COSE Attestation Encoding, `prf`/`hmac-secret` HKDF Extension,
//! Strict RP ID Validation, and WebAuthn Signal API Level 3).

use crate::crypto::hkdf_sha256;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// WebAuthn authenticatorData flag bits (W3C WebAuthn Level 2/3 §6.1).
pub const WEBAUTHN_FLAG_UP: u8 = 0x01; // User Present
pub const WEBAUTHN_FLAG_UV: u8 = 0x04; // User Verified
pub const WEBAUTHN_FLAG_BE: u8 = 0x08; // Backup Eligible
pub const WEBAUTHN_FLAG_BS: u8 = 0x10; // Backup State
pub const WEBAUTHN_FLAG_AT: u8 = 0x40; // Attested Credential Data Included
pub const WEBAUTHN_FLAG_ED: u8 = 0x80; // Extension Data Included

/// 16-byte Singularity Vault Software Authenticator AAGUID (UUID `53696e67-756c-4a72-8974-795661756c74`).
pub const SINGULARITY_PASSKEY_AAGUID: [u8; 16] = [
    0x53, 0x69, 0x6e, 0x67, 0x75, 0x6c, 0x4a, 0x72, 0x89, 0x74, 0x79, 0x56, 0x61, 0x75, 0x6c, 0x74,
];

/// COSE algorithm identifier supported for stored passkeys (IANA COSE Algorithms Registry).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[repr(i32)]
pub enum PasskeyAlgorithm {
    #[default]
    Ed25519 = -8,
    Es256 = -7,
    Rs256 = -257,
}

impl PasskeyAlgorithm {
    pub fn cose_alg_id(self) -> i32 {
        self as i32
    }

    pub fn from_cose_alg_id(alg: i32) -> Option<Self> {
        match alg {
            -8 => Some(PasskeyAlgorithm::Ed25519),
            -7 => Some(PasskeyAlgorithm::Es256),
            -257 => Some(PasskeyAlgorithm::Rs256),
            _ => None,
        }
    }
}

/// Audit log entry recording passkey lifecycle and authentication events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeyAuditEvent {
    pub timestamp_unix: u64,
    pub action: String,
    pub rp_id: String,
    pub origin: Option<String>,
    pub user_verified: bool,
}

/// Resident Passkey credential stored inside the encrypted `.singularity-vault`.
#[derive(Clone, Serialize, Deserialize)]
pub struct StoredPasskeyCredential {
    pub credential_id_hex: String,
    pub rp_id: String,
    pub user_handle_hex: String,
    pub user_display_name: String,
    #[serde(default)]
    pub public_key_hex: String,
    pub secret_seed_hex: String,
    pub sign_count: u32,
    #[serde(default)]
    pub algorithm: PasskeyAlgorithm,
    #[serde(default)]
    pub rp_name: String,
    #[serde(default)]
    pub user_name: String,
    #[serde(default)]
    pub created_at_unix: u64,
    #[serde(default)]
    pub last_used_at_unix: Option<u64>,
    #[serde(default)]
    pub linked_item_id: Option<String>,
    #[serde(default)]
    pub trashed_at: Option<u64>,
    #[serde(default)]
    pub audit_log: Vec<PasskeyAuditEvent>,
}

impl fmt::Debug for StoredPasskeyCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredPasskeyCredential")
            .field("credential_id_hex", &self.credential_id_hex)
            .field("rp_id", &self.rp_id)
            .field("rp_name", &self.rp_name)
            .field("user_handle_hex", &self.user_handle_hex)
            .field("user_name", &self.user_name)
            .field("user_display_name", &self.user_display_name)
            .field("public_key_hex", &self.public_key_hex)
            .field("secret_seed_hex", &"[REDACTED]")
            .field("sign_count", &self.sign_count)
            .field("algorithm", &self.algorithm)
            .field("created_at_unix", &self.created_at_unix)
            .field("last_used_at_unix", &self.last_used_at_unix)
            .field("linked_item_id", &self.linked_item_id)
            .field("trashed_at", &self.trashed_at)
            .field("audit_log_len", &self.audit_log.len())
            .finish()
    }
}

impl Drop for StoredPasskeyCredential {
    fn drop(&mut self) {
        self.secret_seed_hex.zeroize();
    }
}

/// WebAuthn `AuthenticatorAssertionResponse` produced by Singularity's Ed25519 passkey authenticator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeyAssertionResponse {
    pub credential_id_hex: String,
    pub rp_id_hash_hex: String,
    pub public_key_hex: String,
    pub flags_byte: u8,
    pub sign_count: u32,
    pub authenticator_data_hex: String,
    pub signature_hex: String,
}

/// WebAuthn registration attestation output containing canonical CBOR attestationObject & COSE key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeyAttestationObject {
    pub credential_id_hex: String,
    pub aaguid_hex: String,
    pub cose_public_key_cbor: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub attestation_object_cbor: Vec<u8>,
}

/// Output of the WebAuthn `prf` / CTAP2 `hmac-secret` extension derived via HKDF-SHA256.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PrfExtensionOutput {
    pub first: [u8; 32],
    pub second: Option<[u8; 32]>,
}

impl fmt::Debug for PrfExtensionOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrfExtensionOutput")
            .field("first", &"[REDACTED]")
            .field("second", &self.second.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

/// Validates a WebAuthn Relying Party ID (`rpId`) per W3C WebAuthn Level 3 §5.4.2:
/// must be a valid domain string (or `localhost`), lowercased, with no scheme, port, path,
/// wildcard, whitespace, or raw IP address.
pub fn validate_rp_id(rp_id: &str) -> Result<String, String> {
    let normalized = rp_id.trim().to_ascii_lowercase();
    if normalized.is_empty() || normalized.len() > 253 {
        return Err("WebAuthn rp_id must be 1..=253 ASCII characters".into());
    }
    if normalized.contains("://")
        || normalized.contains('/')
        || normalized.contains(':')
        || normalized.contains('*')
        || normalized.contains('@')
        || normalized.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(format!("Invalid WebAuthn rp_id '{}'", rp_id));
    }
    if normalized.starts_with('.') || normalized.ends_with('.') || normalized.contains("..") {
        return Err(format!("Malformed domain labels in rp_id '{}'", rp_id));
    }
    // Reject raw IPv4 addresses (all-numeric labels like 127.0.0.1)
    let labels: Vec<&str> = normalized.split('.').collect();
    if labels.len() == 4 && labels.iter().all(|l| l.parse::<u8>().is_ok()) {
        return Err(format!(
            "Raw IPv4 address '{}' is not a valid WebAuthn rp_id",
            rp_id
        ));
    }
    if normalized.starts_with('[') || normalized.ends_with(']') {
        return Err(format!(
            "Raw IPv6 address '{}' is not a valid WebAuthn rp_id",
            rp_id
        ));
    }
    for label in &labels {
        if label.is_empty() || label.len() > 63 {
            return Err(format!("Invalid label length in rp_id '{}'", rp_id));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(format!(
                "Domain label '{}' in rp_id cannot start or end with '-'",
                label
            ));
        }
        if !label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return Err(format!(
                "Invalid character in rp_id label '{}'",
                label
            ));
        }
    }
    Ok(normalized)
}

// --- Pure-Rust Canonical CTAP2 CBOR Encoder (RFC 8949 §4.2) ---

fn cbor_write_type_and_arg(major: u8, arg: u64, out: &mut Vec<u8>) {
    let major_bits = major << 5;
    if arg < 24 {
        out.push(major_bits | (arg as u8));
    } else if arg <= u8::MAX as u64 {
        out.push(major_bits | 24);
        out.push(arg as u8);
    } else if arg <= u16::MAX as u64 {
        out.push(major_bits | 25);
        out.extend_from_slice(&(arg as u16).to_be_bytes());
    } else if arg <= u32::MAX as u64 {
        out.push(major_bits | 26);
        out.extend_from_slice(&(arg as u32).to_be_bytes());
    } else {
        out.push(major_bits | 27);
        out.extend_from_slice(&arg.to_be_bytes());
    }
}

fn cbor_write_uint(v: u64, out: &mut Vec<u8>) {
    cbor_write_type_and_arg(0, v, out);
}

fn cbor_write_int(v: i64, out: &mut Vec<u8>) {
    if v >= 0 {
        cbor_write_type_and_arg(0, v as u64, out);
    } else {
        // CBOR negative int encodes (-1 - n) as major 1 with argument n
        let n = (-1i128 - i128::from(v)) as u64;
        cbor_write_type_and_arg(1, n, out);
    }
}

fn cbor_write_bytes(bytes: &[u8], out: &mut Vec<u8>) {
    cbor_write_type_and_arg(2, bytes.len() as u64, out);
    out.extend_from_slice(bytes);
}

fn cbor_write_text(text: &str, out: &mut Vec<u8>) {
    cbor_write_type_and_arg(3, text.len() as u64, out);
    out.extend_from_slice(text.as_bytes());
}

fn cbor_write_map_header(len: usize, out: &mut Vec<u8>) {
    cbor_write_type_and_arg(5, len as u64, out);
}

/// Encodes a 32-byte Ed25519 public key into a CTAP2 canonical CBOR COSE_Key (OKP / EdDSA -8 / Ed25519).
/// Map entries in canonical CTAP2 key order: `{ 1: 1 (OKP), 3: -8 (EdDSA), -1: 6 (Ed25519), -2: bstr(x) }`.
pub fn encode_cose_ed25519_public_key(public_key: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(48);
    cbor_write_map_header(4, &mut out);
    // 1: kty = 1 (OKP)
    cbor_write_uint(1, &mut out);
    cbor_write_uint(1, &mut out);
    // 3: alg = -8 (EdDSA)
    cbor_write_uint(3, &mut out);
    cbor_write_int(-8, &mut out);
    // -1: crv = 6 (Ed25519)
    cbor_write_int(-1, &mut out);
    cbor_write_uint(6, &mut out);
    // -2: x = 32-byte public key
    cbor_write_int(-2, &mut out);
    cbor_write_bytes(public_key, &mut out);
    out
}

/// Encodes an uncompressed P-256 (ES256, alg -7) public key `(x, y)` into canonical CTAP2 COSE_Key CBOR.
pub fn encode_cose_es256_public_key(x: &[u8; 32], y: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(80);
    cbor_write_map_header(5, &mut out);
    cbor_write_uint(1, &mut out);
    cbor_write_uint(2, &mut out); // EC2
    cbor_write_uint(3, &mut out);
    cbor_write_int(-7, &mut out); // ES256
    cbor_write_int(-1, &mut out);
    cbor_write_uint(1, &mut out); // P-256
    cbor_write_int(-2, &mut out);
    cbor_write_bytes(x, &mut out);
    cbor_write_int(-3, &mut out);
    cbor_write_bytes(y, &mut out);
    out
}

/// Encodes an RSA (RS256, alg -257) public key `(n, e)` into canonical CTAP2 COSE_Key CBOR.
pub fn encode_cose_rs256_public_key(modulus_n: &[u8], exponent_e: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + modulus_n.len() + exponent_e.len());
    cbor_write_map_header(4, &mut out);
    cbor_write_uint(1, &mut out);
    cbor_write_uint(3, &mut out); // RSA
    cbor_write_uint(3, &mut out);
    cbor_write_int(-257, &mut out); // RS256
    cbor_write_int(-1, &mut out);
    cbor_write_bytes(modulus_n, &mut out);
    cbor_write_int(-2, &mut out);
    cbor_write_bytes(exponent_e, &mut out);
    out
}

/// Builds a W3C WebAuthn `authenticatorData` byte buffer.
/// When `attested_cred_data` is `Some((aaguid, credential_id, cose_public_key_cbor))`,
/// sets the `AT` (`0x40`) flag and appends `aaguid || u16_be(cred_id.len()) || cred_id || cose_public_key_cbor`.
pub fn build_authenticator_data(
    rp_id: &str,
    flags: u8,
    sign_count: u32,
    attested_cred_data: Option<(&[u8; 16], &[u8], &[u8])>,
) -> Result<Vec<u8>, String> {
    let normalized_rp = validate_rp_id(rp_id)?;
    let rp_id_hash: [u8; 32] = Sha256::digest(normalized_rp.as_bytes()).into();

    let mut effective_flags = flags;
    if attested_cred_data.is_some() {
        effective_flags |= WEBAUTHN_FLAG_AT;
    }

    let extra_len = attested_cred_data
        .map(|(_, cid, pk)| 16 + 2 + cid.len() + pk.len())
        .unwrap_or(0);
    let mut auth_data = Vec::with_capacity(37 + extra_len);
    auth_data.extend_from_slice(&rp_id_hash);
    auth_data.push(effective_flags);
    auth_data.extend_from_slice(&sign_count.to_be_bytes());

    if let Some((aaguid, cred_id, cose_pub_key)) = attested_cred_data {
        let cred_len: u16 = cred_id
            .len()
            .try_into()
            .map_err(|_| "WebAuthn credential ID exceeds 65535 bytes".to_string())?;
        auth_data.extend_from_slice(aaguid);
        auth_data.extend_from_slice(&cred_len.to_be_bytes());
        auth_data.extend_from_slice(cred_id);
        auth_data.extend_from_slice(cose_pub_key);
    }

    Ok(auth_data)
}

/// Encodes a WebAuthn `"none"` CBOR `attestationObject` in canonical CTAP2 key order:
/// `{ "fmt": "none", "attStmt": {}, "authData": bstr(auth_data) }`.
pub fn encode_cbor_attestation_object(auth_data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(36 + auth_data.len());
    cbor_write_map_header(3, &mut out);
    // Canonical CTAP2 CBOR text-key order: shorter byte length first, then lexicographic:
    // "fmt" (3) < "attStmt" (7) < "authData" (8)
    cbor_write_text("fmt", &mut out);
    cbor_write_text("none", &mut out);
    cbor_write_text("attStmt", &mut out);
    cbor_write_map_header(0, &mut out);
    cbor_write_text("authData", &mut out);
    cbor_write_bytes(auth_data, &mut out);
    out
}

impl StoredPasskeyCredential {
    /// Enrolls a new resident FIDO2/WebAuthn Ed25519 passkey for `rp_id`.
    pub fn enroll_new(rp_id: &str, user_display_name: &str) -> Self {
        Self::enroll_new_with_metadata(
            rp_id,
            rp_id,
            user_display_name,
            user_display_name,
            PasskeyAlgorithm::Ed25519,
            None,
            0,
        )
    }

    /// Enrolls a new resident passkey with full V2 metadata and initial audit event.
    pub fn enroll_new_with_metadata(
        rp_id: &str,
        rp_name: &str,
        user_name: &str,
        user_display_name: &str,
        algorithm: PasskeyAlgorithm,
        linked_item_id: Option<String>,
        now_unix: u64,
    ) -> Self {
        let mut cred_id = [0u8; 16];
        let mut user_handle = [0u8; 16];
        let mut secret_seed = [0u8; 32];
        OsRng.fill_bytes(&mut cred_id);
        OsRng.fill_bytes(&mut user_handle);
        OsRng.fill_bytes(&mut secret_seed);

        let signing_key = SigningKey::from_bytes(&secret_seed);
        let pub_hex = hex::encode(signing_key.verifying_key().as_bytes());
        let seed_hex = hex::encode(secret_seed);
        secret_seed.zeroize();

        let normalized_rp = validate_rp_id(rp_id).unwrap_or_else(|_| rp_id.trim().to_ascii_lowercase());

        Self {
            credential_id_hex: hex::encode(cred_id),
            rp_id: normalized_rp.clone(),
            user_handle_hex: hex::encode(user_handle),
            user_display_name: user_display_name.to_string(),
            public_key_hex: pub_hex,
            secret_seed_hex: seed_hex,
            sign_count: 0,
            algorithm,
            rp_name: rp_name.to_string(),
            user_name: user_name.to_string(),
            created_at_unix: now_unix,
            last_used_at_unix: None,
            linked_item_id,
            trashed_at: None,
            audit_log: vec![PasskeyAuditEvent {
                timestamp_unix: now_unix,
                action: "enrolled".to_string(),
                rp_id: normalized_rp,
                origin: None,
                user_verified: true,
            }],
        }
    }

    /// Returns `true` if this passkey has been moved to trash or revoked via Signal API.
    pub fn is_trashed(&self) -> bool {
        self.trashed_at.is_some()
    }

    /// Produces a WebAuthn registration `attestationObject` (`fmt: "none"`, `AT=0x40`, Singularity AAGUID,
    /// and canonical CBOR COSE_Key) for this Ed25519 passkey.
    pub fn build_attestation_object(
        &self,
        user_verified: bool,
    ) -> Result<PasskeyAttestationObject, String> {
        let pub_bytes = hex::decode(&self.public_key_hex).map_err(|e| e.to_string())?;
        let pub_arr: [u8; 32] = pub_bytes
            .try_into()
            .map_err(|_| "Invalid Ed25519 public key length (expected 32 bytes)".to_string())?;
        let cred_id_bytes = hex::decode(&self.credential_id_hex).map_err(|e| e.to_string())?;
        let cose_public_key_cbor = encode_cose_ed25519_public_key(&pub_arr);

        let mut flags = WEBAUTHN_FLAG_UP | WEBAUTHN_FLAG_BE | WEBAUTHN_FLAG_BS | WEBAUTHN_FLAG_AT;
        if user_verified {
            flags |= WEBAUTHN_FLAG_UV;
        }

        let authenticator_data = build_authenticator_data(
            &self.rp_id,
            flags,
            self.sign_count,
            Some((&SINGULARITY_PASSKEY_AAGUID, &cred_id_bytes, &cose_public_key_cbor)),
        )?;
        let attestation_object_cbor = encode_cbor_attestation_object(&authenticator_data);

        Ok(PasskeyAttestationObject {
            credential_id_hex: self.credential_id_hex.clone(),
            aaguid_hex: hex::encode(SINGULARITY_PASSKEY_AAGUID),
            cose_public_key_cbor,
            authenticator_data,
            attestation_object_cbor,
        })
    }

    /// Derives deterministic 32-byte WebAuthn `prf` / CTAP2 `hmac-secret` extension outputs
    /// using HKDF-SHA256 bound to this credential's private seed, `rp_id`, and `credential_id`.
    pub fn derive_prf_extension(
        &self,
        salt1: &[u8],
        salt2: Option<&[u8]>,
    ) -> Result<PrfExtensionOutput, String> {
        if self.is_trashed() {
            return Err("Cannot evaluate PRF extension on trashed passkey".into());
        }
        if salt1.is_empty() {
            return Err("WebAuthn PRF salt1 cannot be empty".into());
        }
        if let Some(s2) = salt2 {
            if s2.is_empty() {
                return Err("WebAuthn PRF salt2 cannot be empty when present".into());
            }
        }

        let mut seed_bytes = hex::decode(&self.secret_seed_hex).map_err(|e| e.to_string())?;
        if seed_bytes.len() != 32 {
            seed_bytes.zeroize();
            return Err("Invalid passkey seed length (expected 32 bytes)".into());
        }

        let ctx_info = format!("singularity-prf-root:{}:{}", self.rp_id, self.credential_id_hex);
        let mut prf_root = [0u8; 32];
        hkdf_sha256(
            b"singularity-webauthn-prf-v1",
            &seed_bytes,
            ctx_info.as_bytes(),
            &mut prf_root,
        )
        .map_err(|e| e.to_string())?;
        seed_bytes.zeroize();

        let mut first = [0u8; 32];
        hkdf_sha256(salt1, &prf_root, b"WebAuthn PRF\0", &mut first).map_err(|e| e.to_string())?;

        let second = if let Some(s2) = salt2 {
            let mut out2 = [0u8; 32];
            hkdf_sha256(s2, &prf_root, b"WebAuthn PRF\0", &mut out2).map_err(|e| e.to_string())?;
            Some(out2)
        } else {
            None
        };
        prf_root.zeroize();

        Ok(PrfExtensionOutput { first, second })
    }

    /// Generates an asymmetric Ed25519 WebAuthn CTAP2 assertion over `client_data_json`
    /// verifying strict RP ID binding. Does NOT falsely assert `UV=1` without user verification;
    /// use [`Self::sign_webauthn_assertion_with_uv`] after explicit biometric/PIN verification.
    pub fn sign_webauthn_assertion(
        &mut self,
        requesting_rp_id: &str,
        client_data_json: &[u8],
    ) -> Result<PasskeyAssertionResponse, String> {
        self.sign_webauthn_assertion_with_uv(requesting_rp_id, client_data_json, false)
    }

    /// Generates an asymmetric Ed25519 WebAuthn CTAP2 assertion over `client_data_json`,
    /// setting the `UV` (User Verified) flag strictly according to `user_verified`.
    pub fn sign_webauthn_assertion_with_uv(
        &mut self,
        requesting_rp_id: &str,
        client_data_json: &[u8],
        user_verified: bool,
    ) -> Result<PasskeyAssertionResponse, String> {
        self.sign_webauthn_assertion_audited(requesting_rp_id, client_data_json, user_verified, 0)
    }

    /// Generates an asymmetric Ed25519 WebAuthn CTAP2 assertion and records an audit event at `now_unix`.
    pub fn sign_webauthn_assertion_audited(
        &mut self,
        requesting_rp_id: &str,
        client_data_json: &[u8],
        user_verified: bool,
        now_unix: u64,
    ) -> Result<PasskeyAssertionResponse, String> {
        if self.is_trashed() {
            return Err("Cannot assert with a trashed or revoked passkey".into());
        }
        let normalized_req = validate_rp_id(requesting_rp_id)?;
        let normalized_self = validate_rp_id(&self.rp_id)?;
        if normalized_self != normalized_req {
            return Err(format!(
                "WebAuthn Phishing Guard: passkey bound to '{}' cannot assert for '{}'",
                self.rp_id, requesting_rp_id
            ));
        }

        let next_count = self
            .sign_count
            .checked_add(1)
            .ok_or_else(|| "WebAuthn sign_count overflow; credential must be rotated".to_string())?;

        let mut seed_bytes = hex::decode(&self.secret_seed_hex).map_err(|e| e.to_string())?;
        if seed_bytes.len() != 32 {
            seed_bytes.zeroize();
            return Err("Invalid Ed25519 passkey seed length (expected 32 bytes)".into());
        }
        let mut seed_arr = [0u8; 32];
        seed_arr.copy_from_slice(&seed_bytes);
        seed_bytes.zeroize();

        let signing_key = SigningKey::from_bytes(&seed_arr);
        seed_arr.zeroize();

        let verifying_key = signing_key.verifying_key();
        let pub_hex = hex::encode(verifying_key.as_bytes());
        if self.public_key_hex.is_empty() {
            self.public_key_hex = pub_hex.clone();
        }
        self.sign_count = next_count;
        if now_unix > 0 {
            self.last_used_at_unix = Some(now_unix);
        }

        let rp_id_hash: [u8; 32] = Sha256::digest(normalized_self.as_bytes()).into();
        let mut flags_byte: u8 = WEBAUTHN_FLAG_UP | WEBAUTHN_FLAG_BE | WEBAUTHN_FLAG_BS;
        if user_verified {
            flags_byte |= WEBAUTHN_FLAG_UV;
        }

        let auth_data = build_authenticator_data(&normalized_self, flags_byte, self.sign_count, None)?;

        let client_data_hash: [u8; 32] = Sha256::digest(client_data_json).into();
        let mut signed_payload = Vec::with_capacity(auth_data.len() + 32);
        signed_payload.extend_from_slice(&auth_data);
        signed_payload.extend_from_slice(&client_data_hash);

        let signature: Signature = signing_key.sign(&signed_payload);

        let origin_opt = serde_json::from_slice::<serde_json::Value>(client_data_json)
            .ok()
            .and_then(|v| v.get("origin").and_then(|o| o.as_str()).map(String::from));
        self.audit_log.push(PasskeyAuditEvent {
            timestamp_unix: now_unix,
            action: "assertion".to_string(),
            rp_id: normalized_self,
            origin: origin_opt,
            user_verified,
        });
        if self.audit_log.len() > 100 {
            let drain = self.audit_log.len() - 100;
            self.audit_log.drain(0..drain);
        }

        Ok(PasskeyAssertionResponse {
            credential_id_hex: self.credential_id_hex.clone(),
            rp_id_hash_hex: hex::encode(rp_id_hash),
            public_key_hex: pub_hex,
            flags_byte,
            sign_count: self.sign_count,
            authenticator_data_hex: hex::encode(auth_data),
            signature_hex: hex::encode(signature.to_bytes()),
        })
    }

    /// Verifies an Ed25519 WebAuthn assertion using only the public key (Relying Party side),
    /// validating RP ID hash, `UP` flag, `authenticatorData` integrity, `clientDataJSON`
    /// (`type == "webauthn.get"`, non-empty `challenge`, and `origin`/`rp_id` coherence when
    /// present), and the Ed25519 signature.
    pub fn verify_webauthn_assertion(
        public_key_hex: &str,
        expected_rp_id: &str,
        client_data_json: &[u8],
        assertion: &PasskeyAssertionResponse,
    ) -> Result<(), String> {
        Self::verify_webauthn_assertion_with_policy(
            public_key_hex,
            expected_rp_id,
            client_data_json,
            assertion,
            None,
            false,
            false,
        )
    }

    /// Full Relying Party WebAuthn assertion verifier enforcing:
    /// - `UP` flag (always mandatory) and `UV` flag (when `require_user_verification == true`)
    /// - Monotonic `sign_count` (accepting `0 -> 0` or strictly increasing, rejecting rollback/cloning)
    /// - `clientDataJSON` parsing (`type == "webauthn.get"`, non-empty `challenge`, `origin`/`rp_id` coherence)
    /// - Ed25519 signature over `authenticatorData || SHA-256(clientDataJSON)`.
    pub fn verify_webauthn_assertion_with_policy(
        public_key_hex: &str,
        expected_rp_id: &str,
        client_data_json: &[u8],
        assertion: &PasskeyAssertionResponse,
        previous_sign_count: Option<u32>,
        require_user_verification: bool,
        require_origin: bool,
    ) -> Result<(), String> {
        let normalized_rp = validate_rp_id(expected_rp_id)?;
        let pub_bytes = hex::decode(public_key_hex).map_err(|e| e.to_string())?;
        let pub_arr: [u8; 32] = pub_bytes
            .try_into()
            .map_err(|_| "Invalid Ed25519 public key length".to_string())?;
        let verifying_key =
            VerifyingKey::from_bytes(&pub_arr).map_err(|e| format!("Invalid public key: {}", e))?;

        let expected_rp_hash: [u8; 32] = Sha256::digest(normalized_rp.as_bytes()).into();
        let auth_data = hex::decode(&assertion.authenticator_data_hex).map_err(|e| e.to_string())?;
        if auth_data.len() < 37 || auth_data[..32] != expected_rp_hash {
            return Err("RP ID hash mismatch in authenticatorData".into());
        }
        if !assertion.rp_id_hash_hex.is_empty()
            && !assertion
                .rp_id_hash_hex
                .eq_ignore_ascii_case(&hex::encode(expected_rp_hash))
        {
            return Err("RP ID hash field mismatch with authenticatorData".into());
        }

        // Validate UP (mandatory) and UV (if required) flags from signed authenticatorData[32]
        let auth_flags = auth_data[32];
        if auth_flags != assertion.flags_byte {
            return Err("Assertion flags_byte does not match authenticatorData".into());
        }
        if (auth_flags & WEBAUTHN_FLAG_UP) == 0 {
            return Err("WebAuthn User Present (UP) flag is not set".into());
        }
        if require_user_verification && (auth_flags & WEBAUTHN_FLAG_UV) == 0 {
            return Err("WebAuthn User Verified (UV) flag required but not set".into());
        }

        // Validate sign_count consistency & monotonic progression (0->0 or strictly increasing)
        let auth_sign_count =
            u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]]);
        if auth_sign_count != assertion.sign_count {
            return Err("Assertion sign_count does not match authenticatorData".into());
        }
        if let Some(prev) = previous_sign_count {
            let monotonic_ok = (prev == 0 && auth_sign_count == 0) || auth_sign_count > prev;
            if !monotonic_ok {
                return Err(format!(
                    "WebAuthn sign_count regression/cloning detected (prev={}, got={})",
                    prev, auth_sign_count
                ));
            }
        }

        // Validate clientDataJSON structure, type, challenge, and origin/rp_id coherence
        validate_client_data_json(client_data_json, &normalized_rp, require_origin)?;

        let sig_bytes = hex::decode(&assertion.signature_hex).map_err(|e| e.to_string())?;
        let sig_arr: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| "Invalid Ed25519 signature length".to_string())?;
        let signature = Signature::from_bytes(&sig_arr);

        let client_data_hash: [u8; 32] = Sha256::digest(client_data_json).into();
        let mut signed_payload = Vec::with_capacity(auth_data.len() + 32);
        signed_payload.extend_from_slice(&auth_data);
        signed_payload.extend_from_slice(&client_data_hash);

        verifying_key
            .verify(&signed_payload, &signature)
            .map_err(|_| "Ed25519 WebAuthn signature verification failed".to_string())
    }
}

// --- WebAuthn Level 3 Signal API ---

/// WebAuthn Signal API Level 3 `PublicKeyCredential.signalUnknownCredential`:
/// Marks a credential rejected by the Relying Party as trashed/revoked.
pub fn signal_unknown_credential(
    passkeys: &mut [StoredPasskeyCredential],
    rp_id: &str,
    credential_id_hex: &str,
    now_unix: u64,
) -> Result<bool, String> {
    let normalized_rp = validate_rp_id(rp_id)?;
    let target_id = credential_id_hex.trim().to_ascii_lowercase();
    let mut found = false;

    for pk in passkeys.iter_mut() {
        if pk.rp_id.eq_ignore_ascii_case(&normalized_rp)
            && pk.credential_id_hex.eq_ignore_ascii_case(&target_id)
            && pk.trashed_at.is_none()
        {
            pk.trashed_at = Some(now_unix);
            pk.audit_log.push(PasskeyAuditEvent {
                timestamp_unix: now_unix,
                action: "signal_unknown_credential".to_string(),
                rp_id: normalized_rp.clone(),
                origin: None,
                user_verified: false,
            });
            found = true;
        }
    }
    Ok(found)
}

/// WebAuthn Signal API Level 3 `PublicKeyCredential.signalAllAcceptedCredentials`:
/// Synchronizes the vault's credentials for `(rp_id, user_handle_hex)` by trashing any credential
/// not present in `accepted_credential_ids_hex`. Returns count of newly trashed credentials.
pub fn signal_all_accepted_credentials(
    passkeys: &mut [StoredPasskeyCredential],
    rp_id: &str,
    user_handle_hex: &str,
    accepted_credential_ids_hex: &[String],
    now_unix: u64,
) -> Result<usize, String> {
    let normalized_rp = validate_rp_id(rp_id)?;
    let target_handle = user_handle_hex.trim().to_ascii_lowercase();
    let accepted: HashSet<String> = accepted_credential_ids_hex
        .iter()
        .map(|id| id.trim().to_ascii_lowercase())
        .collect();

    let mut trashed_count = 0usize;
    for pk in passkeys.iter_mut() {
        if pk.rp_id.eq_ignore_ascii_case(&normalized_rp)
            && pk.user_handle_hex.eq_ignore_ascii_case(&target_handle)
            && pk.trashed_at.is_none()
            && !accepted.contains(&pk.credential_id_hex.to_ascii_lowercase())
        {
            pk.trashed_at = Some(now_unix);
            pk.audit_log.push(PasskeyAuditEvent {
                timestamp_unix: now_unix,
                action: "signal_all_accepted_credentials_removed".to_string(),
                rp_id: normalized_rp.clone(),
                origin: None,
                user_verified: false,
            });
            trashed_count += 1;
        }
    }
    Ok(trashed_count)
}

/// WebAuthn Signal API Level 3 `PublicKeyCredential.signalCurrentUserDetails`:
/// Updates `user_name` and `user_display_name` across all active passkeys for `(rp_id, user_handle_hex)`.
/// Returns count of updated credentials.
pub fn signal_current_user_details(
    passkeys: &mut [StoredPasskeyCredential],
    rp_id: &str,
    user_handle_hex: &str,
    new_user_name: &str,
    new_display_name: &str,
    now_unix: u64,
) -> Result<usize, String> {
    let normalized_rp = validate_rp_id(rp_id)?;
    let target_handle = user_handle_hex.trim().to_ascii_lowercase();

    let mut updated = 0usize;
    for pk in passkeys.iter_mut() {
        if pk.rp_id.eq_ignore_ascii_case(&normalized_rp)
            && pk.user_handle_hex.eq_ignore_ascii_case(&target_handle)
            && pk.trashed_at.is_none()
        {
            pk.user_name = new_user_name.to_string();
            pk.user_display_name = new_display_name.to_string();
            pk.audit_log.push(PasskeyAuditEvent {
                timestamp_unix: now_unix,
                action: "signal_current_user_details".to_string(),
                rp_id: normalized_rp.clone(),
                origin: None,
                user_verified: false,
            });
            updated += 1;
        }
    }
    Ok(updated)
}

fn validate_client_data_json(
    client_data_json: &[u8],
    expected_rp_id: &str,
    require_origin: bool,
) -> Result<(), String> {
    let val: serde_json::Value = serde_json::from_slice(client_data_json)
        .map_err(|e| format!("Invalid clientDataJSON: {}", e))?;
    let obj = val
        .as_object()
        .ok_or_else(|| "clientDataJSON must be a JSON object".to_string())?;

    let typ = obj
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "clientDataJSON missing string 'type'".to_string())?;
    if typ != "webauthn.get" {
        return Err(format!(
            "Invalid clientDataJSON type '{}' (expected 'webauthn.get')",
            typ
        ));
    }

    let challenge = obj
        .get("challenge")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "clientDataJSON missing string 'challenge'".to_string())?;
    if challenge.trim().is_empty() {
        return Err("clientDataJSON 'challenge' must not be empty".into());
    }

    match obj.get("origin") {
        Some(origin_val) => {
            let origin = origin_val
                .as_str()
                .ok_or_else(|| "clientDataJSON 'origin' must be a string".to_string())?;
            validate_origin_matches_rp_id(origin, expected_rp_id)?;
        }
        None if require_origin => {
            return Err("clientDataJSON missing required 'origin'".into());
        }
        None => {}
    }

    Ok(())
}

fn validate_origin_matches_rp_id(origin: &str, expected_rp_id: &str) -> Result<(), String> {
    let rp_lower = validate_rp_id(expected_rp_id)?;

    let (scheme, authority) = origin
        .split_once("://")
        .ok_or_else(|| format!("Malformed WebAuthn origin '{}'", origin))?;
    if authority.is_empty()
        || authority.contains('/')
        || authority.contains('?')
        || authority.contains('#')
        || authority.contains('@')
        || authority.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(format!("Invalid WebAuthn origin authority '{}'", origin));
    }

    let host = if let Some(rest) = authority.strip_prefix('[') {
        let (v6, after) = rest
            .split_once(']')
            .ok_or_else(|| "Malformed IPv6 WebAuthn origin".to_string())?;
        if !after.is_empty() {
            let port_str = after
                .strip_prefix(':')
                .ok_or_else(|| "Malformed port in IPv6 WebAuthn origin".to_string())?;
            let port: u16 = port_str
                .parse()
                .map_err(|_| "Invalid port in WebAuthn origin".to_string())?;
            if port == 0 {
                return Err("Invalid port 0 in WebAuthn origin".into());
            }
        }
        format!("[{}]", v6).to_ascii_lowercase()
    } else if let Some((h, port_str)) = authority.rsplit_once(':') {
        let port: u16 = port_str
            .parse()
            .map_err(|_| "Invalid port in WebAuthn origin".to_string())?;
        if port == 0 {
            return Err("Invalid port 0 in WebAuthn origin".into());
        }
        h.to_ascii_lowercase()
    } else {
        authority.to_ascii_lowercase()
    };

    let scheme_lower = scheme.to_ascii_lowercase();
    let is_secure_scheme = scheme_lower == "https"
        || (scheme_lower == "http" && matches!(host.as_str(), "localhost" | "127.0.0.1" | "[::1]"));
    if !is_secure_scheme {
        return Err(format!(
            "WebAuthn origin '{}' must use https:// (or http://localhost)",
            origin
        ));
    }

    let host_matches = host == rp_lower || host.ends_with(&format!(".{}", rp_lower));
    if !host_matches {
        return Err(format!(
            "WebAuthn origin host '{}' is not coherent with rp_id '{}'",
            host, rp_lower
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_honest_uv_flag_and_strict_verification_checks() {
        let mut pk = StoredPasskeyCredential::enroll_new("github.com", "alice");
        let client_data =
            br#"{"type":"webauthn.get","challenge":"Y2hhbGxlbmdl","origin":"https://auth.github.com"}"#;

        // Default sign_webauthn_assertion MUST NOT force UV=1 without user verification
        let no_uv = pk
            .sign_webauthn_assertion("github.com", client_data)
            .expect("sign without UV");
        assert_ne!(no_uv.flags_byte & WEBAUTHN_FLAG_UP, 0);
        assert_eq!(no_uv.flags_byte & WEBAUTHN_FLAG_UV, 0);

        // Passes when UV is not required, fails when UV IS required
        assert!(StoredPasskeyCredential::verify_webauthn_assertion_with_policy(
            &pk.public_key_hex,
            "github.com",
            client_data,
            &no_uv,
            Some(0),
            false,
            true,
        )
        .is_ok());
        assert!(StoredPasskeyCredential::verify_webauthn_assertion_with_policy(
            &pk.public_key_hex,
            "github.com",
            client_data,
            &no_uv,
            Some(0),
            true,
            true,
        )
        .is_err());

        // Signing with explicit user_verified=true sets UV=1 and passes strict check with monotonic sign_count
        let with_uv = pk
            .sign_webauthn_assertion_with_uv("github.com", client_data, true)
            .expect("sign with UV");
        assert_ne!(with_uv.flags_byte & WEBAUTHN_FLAG_UV, 0);
        assert_eq!(with_uv.sign_count, 2);
        assert!(StoredPasskeyCredential::verify_webauthn_assertion_with_policy(
            &pk.public_key_hex,
            "github.com",
            client_data,
            &with_uv,
            Some(1),
            true,
            true,
        )
        .is_ok());

        // Cloned / non-advancing sign_count (2 -> 2 or 3 -> 2) MUST be rejected
        assert!(StoredPasskeyCredential::verify_webauthn_assertion_with_policy(
            &pk.public_key_hex,
            "github.com",
            client_data,
            &with_uv,
            Some(2),
            true,
            true,
        )
        .is_err());
        assert!(StoredPasskeyCredential::verify_webauthn_assertion_with_policy(
            &pk.public_key_hex,
            "github.com",
            client_data,
            &with_uv,
            Some(5),
            true,
            true,
        )
        .is_err());
    }

    #[test]
    fn test_client_data_json_origin_type_challenge_and_up_validation() {
        let mut pk = StoredPasskeyCredential::enroll_new("github.com", "bob");

        // Wrong type ("webauthn.create") must fail even with valid signature
        let bad_type =
            br#"{"type":"webauthn.create","challenge":"abc","origin":"https://github.com"}"#;
        let a_type = pk
            .sign_webauthn_assertion_with_uv("github.com", bad_type, true)
            .unwrap();
        assert!(StoredPasskeyCredential::verify_webauthn_assertion(
            &pk.public_key_hex,
            "github.com",
            bad_type,
            &a_type,
        )
        .is_err());

        // Mismatched origin ("https://evilgithub.com") must fail
        let bad_origin =
            br#"{"type":"webauthn.get","challenge":"abc","origin":"https://evilgithub.com"}"#;
        let a_origin = pk
            .sign_webauthn_assertion_with_uv("github.com", bad_origin, true)
            .unwrap();
        assert!(StoredPasskeyCredential::verify_webauthn_assertion(
            &pk.public_key_hex,
            "github.com",
            bad_origin,
            &a_origin,
        )
        .is_err());

        // Insecure http:// non-localhost origin must fail
        let http_origin =
            br#"{"type":"webauthn.get","challenge":"abc","origin":"http://github.com"}"#;
        let a_http = pk
            .sign_webauthn_assertion_with_uv("github.com", http_origin, true)
            .unwrap();
        assert!(StoredPasskeyCredential::verify_webauthn_assertion(
            &pk.public_key_hex,
            "github.com",
            http_origin,
            &a_http,
        )
        .is_err());

        // Missing UP flag (0x00) must fail even if properly signed by authenticator key
        let seed_bytes = hex::decode(&pk.secret_seed_hex).unwrap();
        let signing_key = SigningKey::from_bytes(&seed_bytes.try_into().unwrap());
        let good_cd =
            br#"{"type":"webauthn.get","challenge":"abc","origin":"https://github.com"}"#;
        let rp_hash: [u8; 32] = Sha256::digest(b"github.com").into();
        let mut auth_data = Vec::with_capacity(37);
        auth_data.extend_from_slice(&rp_hash);
        auth_data.push(0x00); // UP=0!
        auth_data.extend_from_slice(&0u32.to_be_bytes()); // sign_count = 0
        let cd_hash: [u8; 32] = Sha256::digest(good_cd).into();
        let mut msg = auth_data.clone();
        msg.extend_from_slice(&cd_hash);
        let sig = signing_key.sign(&msg);
        let forged_no_up = PasskeyAssertionResponse {
            credential_id_hex: pk.credential_id_hex.clone(),
            rp_id_hash_hex: hex::encode(rp_hash),
            public_key_hex: pk.public_key_hex.clone(),
            flags_byte: 0x00,
            sign_count: 0,
            authenticator_data_hex: hex::encode(&auth_data),
            signature_hex: hex::encode(sig.to_bytes()),
        };
        assert!(StoredPasskeyCredential::verify_webauthn_assertion_with_policy(
            &pk.public_key_hex,
            "github.com",
            good_cd,
            &forged_no_up,
            Some(0),
            false,
            true,
        )
        .is_err());

        // Sign count 0 -> 0 with UP=1 IS accepted per WebAuthn spec
        auth_data[32] = WEBAUTHN_FLAG_UP;
        let mut msg0 = auth_data.clone();
        msg0.extend_from_slice(&cd_hash);
        let sig0 = signing_key.sign(&msg0);
        let zero_counter_ok = PasskeyAssertionResponse {
            credential_id_hex: pk.credential_id_hex.clone(),
            rp_id_hash_hex: hex::encode(rp_hash),
            public_key_hex: pk.public_key_hex.clone(),
            flags_byte: WEBAUTHN_FLAG_UP,
            sign_count: 0,
            authenticator_data_hex: hex::encode(&auth_data),
            signature_hex: hex::encode(sig0.to_bytes()),
        };
        assert!(StoredPasskeyCredential::verify_webauthn_assertion_with_policy(
            &pk.public_key_hex,
            "github.com",
            good_cd,
            &zero_counter_ok,
            Some(0),
            false,
            true,
        )
        .is_ok());

        // Debug redaction hides Ed25519 secret seed
        let dbg_pk = format!("{:?}", pk);
        assert!(dbg_pk.contains("[REDACTED]"));
        assert!(!dbg_pk.contains(&pk.secret_seed_hex));
    }

    #[test]
    fn test_cbor_attestation_cose_key_prf_and_signal_api_level3() {
        // Strict rp_id validation
        assert_eq!(validate_rp_id("GitHub.COM").unwrap(), "github.com");
        assert_eq!(validate_rp_id("localhost").unwrap(), "localhost");
        assert!(validate_rp_id("https://github.com").is_err());
        assert!(validate_rp_id("127.0.0.1").is_err());
        assert!(validate_rp_id("*.github.com").is_err());
        assert!(validate_rp_id("github.com:443").is_err());

        // Canonical CBOR COSE_Key and AttestationObject
        let pk1 = StoredPasskeyCredential::enroll_new_with_metadata(
            "github.com",
            "GitHub",
            "alice@example.com",
            "Alice",
            PasskeyAlgorithm::Ed25519,
            Some("item-1".into()),
            10_000,
        );
        let att = pk1.build_attestation_object(true).expect("build attestation");
        // Ed25519 COSE key is exact 42 bytes starting with 0xA4 0x01 0x01 0x03 0x27 0x20 0x06 0x21 0x58 0x20
        assert_eq!(att.cose_public_key_cbor.len(), 42);
        assert_eq!(
            &att.cose_public_key_cbor[..10],
            &[0xA4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21, 0x58, 0x20]
        );
        // authenticatorData has AT flag (0x40), UV flag (0x04), and Singularity AAGUID at bytes 37..53
        assert_ne!(att.authenticator_data[32] & WEBAUTHN_FLAG_AT, 0);
        assert_ne!(att.authenticator_data[32] & WEBAUTHN_FLAG_UV, 0);
        assert_eq!(&att.authenticator_data[37..53], &SINGULARITY_PASSKEY_AAGUID);
        // Attestation object starts with map(3), "fmt", "none", "attStmt", {}
        assert_eq!(att.attestation_object_cbor[0], 0xA3);
        assert!(att
            .attestation_object_cbor
            .windows(4)
            .any(|w| w == b"none"));

        // PRF / hmac-secret deterministic derivation
        let prf_a = pk1.derive_prf_extension(b"salt-one", Some(b"salt-two")).unwrap();
        let prf_b = pk1.derive_prf_extension(b"salt-one", Some(b"salt-two")).unwrap();
        assert_eq!(prf_a.first, prf_b.first);
        assert_eq!(prf_a.second, prf_b.second);
        assert_ne!(prf_a.first, prf_a.second.unwrap());
        assert!(format!("{:?}", prf_a).contains("[REDACTED]"));

        // Signal API Level 3
        let mut pk2 = StoredPasskeyCredential::enroll_new("github.com", "Alice");
        pk2.user_handle_hex = pk1.user_handle_hex.clone();
        let mut pk3 = StoredPasskeyCredential::enroll_new("github.com", "Alice");
        pk3.user_handle_hex = pk1.user_handle_hex.clone();

        let keep_id = pk1.credential_id_hex.clone();
        let handle = pk1.user_handle_hex.clone();
        let mut list = vec![pk1, pk2, pk3];

        // signal_current_user_details updates all 3
        let updated = signal_current_user_details(
            &mut list,
            "github.com",
            &handle,
            "alice.new@example.com",
            "Alice Updated",
            20_000,
        )
        .unwrap();
        assert_eq!(updated, 3);
        assert_eq!(list[0].user_display_name, "Alice Updated");
        assert_eq!(list[0].user_name, "alice.new@example.com");

        // signal_all_accepted_credentials trashes the 2 stale credentials
        let removed = signal_all_accepted_credentials(
            &mut list,
            "github.com",
            &handle,
            &[keep_id.clone()],
            21_000,
        )
        .unwrap();
        assert_eq!(removed, 2);
        assert!(!list[0].is_trashed());
        assert!(list[1].is_trashed());
        assert!(list[2].is_trashed());

        // signal_unknown_credential trashes the remaining credential
        assert!(signal_unknown_credential(&mut list, "github.com", &keep_id, 22_000).unwrap());
        assert!(list[0].is_trashed());
    }

    #[test]
    fn test_v1_passkey_json_backcompat_and_cose_es256_rs256() {
        // Legacy V1 StoredPasskeyCredential JSON (without V2 fields) must deserialize cleanly
        let pk_live = StoredPasskeyCredential::enroll_new("example.org", "alice");
        let v1_json = serde_json::json!({
            "credential_id_hex": pk_live.credential_id_hex,
            "rp_id": pk_live.rp_id,
            "user_handle_hex": pk_live.user_handle_hex,
            "user_display_name": pk_live.user_display_name,
            "public_key_hex": pk_live.public_key_hex,
            "secret_seed_hex": pk_live.secret_seed_hex,
            "sign_count": 3
        })
        .to_string();
        let restored: StoredPasskeyCredential =
            serde_json::from_str(&v1_json).expect("deserialize legacy V1 passkey");
        assert_eq!(restored.algorithm, PasskeyAlgorithm::Ed25519);
        assert_eq!(restored.sign_count, 3);
        assert!(!restored.is_trashed());

        // ES256 & RS256 COSE key encoders
        let es256 = encode_cose_es256_public_key(&[0x11u8; 32], &[0x22u8; 32]);
        assert_eq!(es256[0], 0xA5); // map(5)
        assert_eq!(es256[3], 0x03); // key 3 (alg)
        assert_eq!(es256[4], 0x26); // -7 (ES256)

        let rs256 = encode_cose_rs256_public_key(&[0xAAu8; 32], &[0x01, 0x00, 0x01]);
        assert_eq!(rs256[0], 0xA4); // map(4)
        assert_eq!(PasskeyAlgorithm::from_cose_alg_id(-257), Some(PasskeyAlgorithm::Rs256));
    }
}
