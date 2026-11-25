//! FIDO2 / WebAuthn CTAP2.1 Software Passkey Authenticator (Asymmetric Ed25519 / COSE EdDSA -8).

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use zeroize::Zeroize;

/// WebAuthn authenticatorData flag bits (W3C WebAuthn Level 2/3 §6.1).
pub const WEBAUTHN_FLAG_UP: u8 = 0x01; // User Present
pub const WEBAUTHN_FLAG_UV: u8 = 0x04; // User Verified
pub const WEBAUTHN_FLAG_BE: u8 = 0x08; // Backup Eligible
pub const WEBAUTHN_FLAG_BS: u8 = 0x10; // Backup State

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
}

impl fmt::Debug for StoredPasskeyCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredPasskeyCredential")
            .field("credential_id_hex", &self.credential_id_hex)
            .field("rp_id", &self.rp_id)
            .field("user_handle_hex", &self.user_handle_hex)
            .field("user_display_name", &self.user_display_name)
            .field("public_key_hex", &self.public_key_hex)
            .field("secret_seed_hex", &"[REDACTED]")
            .field("sign_count", &self.sign_count)
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

impl StoredPasskeyCredential {
    /// Enrolls a new resident FIDO2/WebAuthn Ed25519 passkey for `rp_id`.
    pub fn enroll_new(rp_id: &str, user_display_name: &str) -> Self {
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

        Self {
            credential_id_hex: hex::encode(cred_id),
            rp_id: rp_id.to_string(),
            user_handle_hex: hex::encode(user_handle),
            user_display_name: user_display_name.to_string(),
            public_key_hex: pub_hex,
            secret_seed_hex: seed_hex,
            sign_count: 0,
        }
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
        if self.rp_id != requesting_rp_id {
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

        let rp_id_hash: [u8; 32] = Sha256::digest(self.rp_id.as_bytes()).into();
        let mut flags_byte: u8 = WEBAUTHN_FLAG_UP | WEBAUTHN_FLAG_BE | WEBAUTHN_FLAG_BS;
        if user_verified {
            flags_byte |= WEBAUTHN_FLAG_UV;
        }

        let mut auth_data = Vec::with_capacity(37);
        auth_data.extend_from_slice(&rp_id_hash);
        auth_data.push(flags_byte);
        auth_data.extend_from_slice(&self.sign_count.to_be_bytes());

        let client_data_hash: [u8; 32] = Sha256::digest(client_data_json).into();
        let mut signed_payload = Vec::with_capacity(auth_data.len() + 32);
        signed_payload.extend_from_slice(&auth_data);
        signed_payload.extend_from_slice(&client_data_hash);

        let signature: Signature = signing_key.sign(&signed_payload);

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
        let pub_bytes = hex::decode(public_key_hex).map_err(|e| e.to_string())?;
        let pub_arr: [u8; 32] = pub_bytes
            .try_into()
            .map_err(|_| "Invalid Ed25519 public key length".to_string())?;
        let verifying_key =
            VerifyingKey::from_bytes(&pub_arr).map_err(|e| format!("Invalid public key: {}", e))?;

        let expected_rp_hash: [u8; 32] = Sha256::digest(expected_rp_id.as_bytes()).into();
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
        validate_client_data_json(client_data_json, expected_rp_id, require_origin)?;

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
    let rp_lower = expected_rp_id.trim().to_ascii_lowercase();
    if rp_lower.is_empty()
        || rp_lower.contains('/')
        || rp_lower.contains(':')
        || rp_lower.chars().any(|c| c.is_whitespace())
    {
        return Err("Invalid expected_rp_id".into());
    }

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
}
