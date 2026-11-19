//! FIDO2 / WebAuthn CTAP2.1 Software Passkey Authenticator (Asymmetric Ed25519 / COSE EdDSA -8).

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

/// Resident Passkey credential stored inside the encrypted `.singularity-vault`.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// verifying strict RP ID binding.
    pub fn sign_webauthn_assertion(
        &mut self,
        requesting_rp_id: &str,
        client_data_json: &[u8],
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
        // Flags: UP (0x01) | UV (0x04) | BE (0x08) | BS (0x10) = 0x1D
        let flags_byte: u8 = 0x1D;

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

    /// Verifies an Ed25519 WebAuthn assertion using only the public key (Relying Party side).
    pub fn verify_webauthn_assertion(
        public_key_hex: &str,
        expected_rp_id: &str,
        client_data_json: &[u8],
        assertion: &PasskeyAssertionResponse,
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
