//! End-to-End Encrypted Sync Transport Layer.
//!
//! Provides:
//! - `SealedSyncEnvelope`: Ed25519 device signature + XChaCha20-Poly1305 AEAD with canonical AAD
//!   `(chain_id, collection, device_id, seq)` + monotonic per-device anti-replay protection.
//! - `EncryptedFolderBackend`: Atomic `.singularity-delta.enc` filesystem synchronization backend.
//! - `LanSyncTransport`: Pure-Rust UDP discovery beacons and length-prefixed TCP envelope exchange.
//! - `SendTabPayload`: Encrypted instant tab handoff with optional media playback position.
//! - `DeviceRegistry` / `SyncDeviceInfo`: Member device registry with instant cryptographic revocation.
//! - Strict `respect_mullvad_killswitch` enforcement blocking all network sockets when engaged.

use crate::crdt::{CrdtDeltaPacket, SyncCollectionKind};
use crate::mnemonic::{SecretKey32, SyncMasterKeys};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key, XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::time::Duration;
use subtle::ConstantTimeEq;
use thiserror::Error;

/// File suffix used by the Encrypted Folder synchronization backend.
pub const ENCRYPTED_DELTA_EXTENSION: &str = ".singularity-delta.enc";
/// 4-byte wire framing magic for LAN TCP envelope exchange.
pub const LAN_FRAME_MAGIC: &[u8; 4] = b"SSYN";
/// Maximum accepted envelope wire size over TCP/disk (16 MiB DoS cap).
pub const MAX_ENVELOPE_WIRE_BYTES: usize = 16 * 1024 * 1024;
/// Current sealed envelope format version.
pub const SEALED_ENVELOPE_VERSION: u8 = 1;

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("Network sync operation blocked because Mullvad Kill-Switch is active and respect_mullvad_killswitch=true")]
    BlockedByMullvadKillSwitch,
    #[error("Envelope chain_id mismatch (belongs to a different sync chain)")]
    ChainIdMismatch,
    #[error("Envelope version {0} is unsupported")]
    UnsupportedVersion(u8),
    #[error("Sender device '{0}' has been revoked from this sync chain")]
    DeviceRevoked(String),
    #[error("Sender public key mismatch for registered device '{0}'")]
    DeviceKeyMismatch(String),
    #[error("Invalid Ed25519 public key or signature: {0}")]
    InvalidSignature(String),
    #[error("Replay attack detected for device '{device_id}' on stream '{stream}': seq {received_seq} <= last_seen {last_seen_seq}")]
    ReplayDetected {
        device_id: String,
        stream: String,
        received_seq: u64,
        last_seen_seq: u64,
    },
    #[error("Sequence number must be >= 1")]
    ZeroSequenceNumber,
    #[error("XChaCha20-Poly1305 AEAD encryption failed")]
    EncryptionFailed,
    #[error("XChaCha20-Poly1305 AEAD decryption/authentication failed (wrong key or tampered AAD/ciphertext)")]
    DecryptionFailed,
    #[error("Payload serialization error: {0}")]
    Serialization(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Malformed wire frame: {0}")]
    MalformedFrame(String),
    #[error("Invalid identifier or path component: {0}")]
    InvalidIdentifier(String),
}

/// Supported synchronization transport modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncTransportMode {
    /// Local network discovery & encrypted peer-to-peer exchange only (zero internet relays).
    P2pLanOnly,
    /// Prefer direct LAN P2P, falling back to an encrypted zero-knowledge relay.
    P2pWithRelay,
    /// Connect strictly to a user-controlled self-hosted blind relay URL.
    SelfHostedRelay,
    /// Pure filesystem sync via atomic `.singularity-delta.enc` files (e.g. Syncthing/Nextcloud/USB).
    EncryptedFolder,
}

/// Configuration for the sync transport layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncTransportConfig {
    pub mode: SyncTransportMode,
    pub encrypted_folder_path: Option<PathBuf>,
    pub self_hosted_relay_url: Option<String>,
    pub lan_discovery_port: u16,
    /// When `true` (default), all network sync sockets (LAN/Relay) are strictly halted while
    /// Mullvad Kill-Switch is active. Local `EncryptedFolder` disk I/O remains unaffected.
    pub respect_mullvad_killswitch: bool,
}

impl Default for SyncTransportConfig {
    fn default() -> Self {
        Self {
            mode: SyncTransportMode::P2pLanOnly,
            encrypted_folder_path: None,
            self_hosted_relay_url: None,
            lan_discovery_port: 47_821,
            respect_mullvad_killswitch: true,
        }
    }
}

/// Encrypted payload for instant tab handoff between member devices in the sync chain.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SendTabPayload {
    pub payload_id: String,
    pub url: String,
    pub title: String,
    /// Optional media playback resume timestamp in seconds (e.g. video/podcast seek position).
    pub media_time_sec: Option<f64>,
    /// Target member `device_id`, or `"*"` to broadcast to all devices in the chain.
    pub target_device_id: String,
    pub sender_device_id: String,
    pub created_at_ms: u64,
}

/// Metadata for a member device enrolled in a sync chain, supporting revocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncDeviceInfo {
    pub device_id: String,
    pub device_name: String,
    pub platform: String,
    pub ed25519_pubkey_hex: String,
    pub enrolled_at_ms: u64,
    pub last_seen_ms: u64,
    pub revoked: bool,
    pub revoked_at_ms: Option<u64>,
}

/// Member device registry enforcing Ed25519 public key pinning and instant revocation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRegistry {
    devices: BTreeMap<String, SyncDeviceInfo>,
}

impl DeviceRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers or updates a device entry. If the device was previously revoked, revocation is preserved.
    pub fn register_device(&mut self, mut info: SyncDeviceInfo) {
        if let Some(existing) = self.devices.get(&info.device_id) {
            if existing.revoked {
                info.revoked = true;
                info.revoked_at_ms = existing.revoked_at_ms;
            }
        }
        self.devices.insert(info.device_id.clone(), info);
    }

    /// Permanently marks `device_id` as revoked so future envelopes from it are rejected immediately.
    pub fn revoke_device(&mut self, device_id: &str, revoked_at_ms: u64) -> bool {
        if let Some(dev) = self.devices.get_mut(device_id) {
            dev.revoked = true;
            dev.revoked_at_ms = Some(revoked_at_ms);
            true
        } else {
            false
        }
    }

    pub fn is_revoked(&self, device_id: &str) -> bool {
        self.devices
            .get(device_id)
            .map(|d| d.revoked)
            .unwrap_or(false)
    }

    pub fn get(&self, device_id: &str) -> Option<&SyncDeviceInfo> {
        self.devices.get(device_id)
    }

    pub fn active_devices(&self) -> Vec<&SyncDeviceInfo> {
        self.devices.values().filter(|d| !d.revoked).collect()
    }

    pub fn all_devices(&self) -> Vec<&SyncDeviceInfo> {
        self.devices.values().collect()
    }

    /// Validates that `device_id` is not revoked and, if already enrolled, matches its pinned Ed25519 public key.
    pub fn verify_authorized_sender(
        &self,
        device_id: &str,
        sender_pubkey_hex: &str,
    ) -> Result<(), TransportError> {
        if let Some(existing) = self.devices.get(device_id) {
            if existing.revoked {
                return Err(TransportError::DeviceRevoked(device_id.to_string()));
            }
            if !bool::from(
                existing
                    .ed25519_pubkey_hex
                    .as_bytes()
                    .ct_eq(sender_pubkey_hex.as_bytes()),
            ) {
                return Err(TransportError::DeviceKeyMismatch(device_id.to_string()));
            }
        }
        Ok(())
    }

    /// Updates `last_seen_ms` for an enrolled active device.
    pub fn touch_last_seen(&mut self, device_id: &str, seen_ms: u64) {
        if let Some(dev) = self.devices.get_mut(device_id) {
            if seen_ms > dev.last_seen_ms {
                dev.last_seen_ms = seen_ms;
            }
        }
    }
}

/// Monotonic sequence tracker preventing replay attacks per `(device_id, stream)`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayGuard {
    last_seen: BTreeMap<(String, String), u64>,
}

impl ReplayGuard {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn last_seen_seq(&self, device_id: &str, stream: &str) -> u64 {
        self.last_seen
            .get(&(device_id.to_string(), stream.to_string()))
            .copied()
            .unwrap_or(0)
    }

    /// Checks whether `seq` is strictly greater than the last accepted sequence number.
    pub fn check(&self, device_id: &str, stream: &str, seq: u64) -> Result<(), TransportError> {
        if seq == 0 {
            return Err(TransportError::ZeroSequenceNumber);
        }
        let last = self.last_seen_seq(device_id, stream);
        if seq <= last {
            return Err(TransportError::ReplayDetected {
                device_id: device_id.to_string(),
                stream: stream.to_string(),
                received_seq: seq,
                last_seen_seq: last,
            });
        }
        Ok(())
    }

    /// Records `seq` as accepted. Must only be called AFTER signature & AEAD verification succeed.
    pub fn commit(&mut self, device_id: &str, stream: &str, seq: u64) {
        let key = (device_id.to_string(), stream.to_string());
        let entry = self.last_seen.entry(key).or_insert(0);
        if seq > *entry {
            *entry = seq;
        }
    }
}

/// Discriminator describing what encrypted inner payload a `SealedSyncEnvelope` carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnvelopePayloadKind {
    CrdtDelta,
    SendTab,
}

impl EnvelopePayloadKind {
    fn tag_byte(&self) -> u8 {
        match self {
            Self::CrdtDelta => 0x01,
            Self::SendTab => 0x02,
        }
    }
}

/// Decrypted inner payload carried inside a `SealedSyncEnvelope`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SyncEnvelopePayload {
    CrdtDelta(CrdtDeltaPacket),
    SendTab(SendTabPayload),
}

impl SyncEnvelopePayload {
    pub fn kind(&self) -> EnvelopePayloadKind {
        match self {
            Self::CrdtDelta(_) => EnvelopePayloadKind::CrdtDelta,
            Self::SendTab(_) => EnvelopePayloadKind::SendTab,
        }
    }
}

/// Authenticated, Ed25519-signed, XChaCha20-Poly1305 encrypted synchronization envelope.
///
/// Security properties:
/// - **Confidentiality + Integrity**: `XChaCha20-Poly1305` (192-bit random `OsRng` nonce) with
///   canonical Associated Authenticated Data (AAD) binding `(chain_id, collection, device_id, seq)`.
/// - **Sender Authenticity**: `Ed25519` signature by the emitting device over all header fields,
///   AAD, nonce, and ciphertext.
/// - **Anti-Replay**: Monotonic `seq` checked via `ReplayGuard`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedSyncEnvelope {
    pub version: u8,
    pub chain_id: String,
    pub collection: SyncCollectionKind,
    pub payload_kind: EnvelopePayloadKind,
    pub device_id: String,
    pub sender_pubkey_hex: String,
    pub seq: u64,
    pub xnonce_base64: String,
    pub ciphertext_base64: String,
    pub signature_base64: String,
}

impl SealedSyncEnvelope {
    /// Selects the appropriate domain-separated AEAD key from `SyncMasterKeys`:
    /// `VaultCredentials` uses the isolated `vault_subkey`; all other collections use `content_encryption_key`.
    pub fn key_for_collection(
        master_keys: &SyncMasterKeys,
        collection: SyncCollectionKind,
    ) -> &SecretKey32 {
        match collection {
            SyncCollectionKind::VaultCredentials => master_keys.vault_subkey(),
            _ => master_keys.content_encryption_key(),
        }
    }

    /// Seals `payload` with XChaCha20-Poly1305 + AAD `(chain_id, collection, device_id, seq)`
    /// and signs the complete envelope using the sender device's Ed25519 signing key.
    pub fn seal(
        master_keys: &SyncMasterKeys,
        sender_signing_key: &SigningKey,
        device_id: &str,
        collection: SyncCollectionKind,
        seq: u64,
        payload: &SyncEnvelopePayload,
    ) -> Result<Self, TransportError> {
        let key = Self::key_for_collection(master_keys, collection);
        Self::seal_with_key(
            &master_keys.chain_id,
            key,
            sender_signing_key,
            device_id,
            collection,
            seq,
            payload,
        )
    }

    /// Seals `payload` using an explicit 256-bit `SecretKey32` and Ed25519 `SigningKey`.
    pub fn seal_with_key(
        chain_id: &str,
        aead_key: &SecretKey32,
        sender_signing_key: &SigningKey,
        device_id: &str,
        collection: SyncCollectionKind,
        seq: u64,
        payload: &SyncEnvelopePayload,
    ) -> Result<Self, TransportError> {
        if seq == 0 {
            return Err(TransportError::ZeroSequenceNumber);
        }
        validate_identifier(device_id)?;
        validate_identifier(chain_id)?;

        let payload_kind = payload.kind();
        let plaintext =
            serde_json::to_vec(payload).map_err(|e| TransportError::Serialization(e.to_string()))?;

        let mut nonce_bytes = [0u8; 24];
        OsRng.fill_bytes(&mut nonce_bytes);

        let aad = build_canonical_aad(chain_id, collection, device_id, seq);
        let cipher = XChaCha20Poly1305::new(Key::from_slice(aead_key.as_bytes()));
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce_bytes),
                Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| TransportError::EncryptionFailed)?;

        let sender_pubkey_hex = hex::encode(sender_signing_key.verifying_key().as_bytes());
        let transcript = build_signature_transcript(
            SEALED_ENVELOPE_VERSION,
            payload_kind,
            &aad,
            &sender_pubkey_hex,
            &nonce_bytes,
            &ciphertext,
        );
        let signature: Signature = sender_signing_key.sign(&transcript);

        Ok(Self {
            version: SEALED_ENVELOPE_VERSION,
            chain_id: chain_id.to_string(),
            collection,
            payload_kind,
            device_id: device_id.to_string(),
            sender_pubkey_hex,
            seq,
            xnonce_base64: BASE64.encode(nonce_bytes),
            ciphertext_base64: BASE64.encode(ciphertext),
            signature_base64: BASE64.encode(signature.to_bytes()),
        })
    }

    /// Stream key used by `ReplayGuard` for monotonic anti-replay tracking.
    pub fn replay_stream_key(&self) -> String {
        match self.payload_kind {
            EnvelopePayloadKind::CrdtDelta => format!("crdt:{}", self.collection.as_str()),
            EnvelopePayloadKind::SendTab => "send_tab".to_string(),
        }
    }

    /// Verifies chain membership, device revocation, monotonic anti-replay, Ed25519 signature,
    /// and XChaCha20-Poly1305 AEAD tag + AAD, returning the decrypted `SyncEnvelopePayload`.
    pub fn unseal(
        &self,
        master_keys: &SyncMasterKeys,
        registry: &DeviceRegistry,
        replay_guard: &mut ReplayGuard,
    ) -> Result<SyncEnvelopePayload, TransportError> {
        let key = Self::key_for_collection(master_keys, self.collection);
        self.unseal_with_key(&master_keys.chain_id, key, registry, replay_guard)
    }

    /// Unseals using an explicit `chain_id` and 256-bit `SecretKey32`.
    pub fn unseal_with_key(
        &self,
        expected_chain_id: &str,
        aead_key: &SecretKey32,
        registry: &DeviceRegistry,
        replay_guard: &mut ReplayGuard,
    ) -> Result<SyncEnvelopePayload, TransportError> {
        if self.version != SEALED_ENVELOPE_VERSION {
            return Err(TransportError::UnsupportedVersion(self.version));
        }
        if !bool::from(
            self.chain_id
                .as_bytes()
                .ct_eq(expected_chain_id.as_bytes()),
        ) {
            return Err(TransportError::ChainIdMismatch);
        }

        // 1. Check device authorization & revocation
        registry.verify_authorized_sender(&self.device_id, &self.sender_pubkey_hex)?;

        // 2. Pre-check monotonic anti-replay sequence
        let stream_key = self.replay_stream_key();
        replay_guard.check(&self.device_id, &stream_key, self.seq)?;

        // 3. Decode cryptographic fields
        let pubkey_vec = hex::decode(&self.sender_pubkey_hex)
            .map_err(|e| TransportError::InvalidSignature(e.to_string()))?;
        let pubkey_arr: [u8; 32] = pubkey_vec
            .try_into()
            .map_err(|_| TransportError::InvalidSignature("public key must be 32 bytes".into()))?;
        let verifying_key = VerifyingKey::from_bytes(&pubkey_arr)
            .map_err(|e| TransportError::InvalidSignature(e.to_string()))?;

        let sig_vec = BASE64
            .decode(&self.signature_base64)
            .map_err(|e| TransportError::InvalidSignature(e.to_string()))?;
        let sig_arr: [u8; 64] = sig_vec
            .try_into()
            .map_err(|_| TransportError::InvalidSignature("signature must be 64 bytes".into()))?;
        let signature = Signature::from_bytes(&sig_arr);

        let nonce_vec = BASE64
            .decode(&self.xnonce_base64)
            .map_err(|_| TransportError::DecryptionFailed)?;
        let nonce_arr: [u8; 24] = nonce_vec
            .try_into()
            .map_err(|_| TransportError::DecryptionFailed)?;

        let ciphertext = BASE64
            .decode(&self.ciphertext_base64)
            .map_err(|_| TransportError::DecryptionFailed)?;

        // 4. Verify Ed25519 signature over canonical transcript BEFORE decrypting
        let aad = build_canonical_aad(&self.chain_id, self.collection, &self.device_id, self.seq);
        let transcript = build_signature_transcript(
            self.version,
            self.payload_kind,
            &aad,
            &self.sender_pubkey_hex,
            &nonce_arr,
            &ciphertext,
        );
        verifying_key
            .verify(&transcript, &signature)
            .map_err(|e| TransportError::InvalidSignature(e.to_string()))?;

        // 5. Authenticate & decrypt XChaCha20-Poly1305 ciphertext with canonical AAD
        let cipher = XChaCha20Poly1305::new(Key::from_slice(aead_key.as_bytes()));
        let plaintext = cipher
            .decrypt(
                XNonce::from_slice(&nonce_arr),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| TransportError::DecryptionFailed)?;

        let payload: SyncEnvelopePayload = serde_json::from_slice(&plaintext)
            .map_err(|e| TransportError::Serialization(e.to_string()))?;

        if payload.kind() != self.payload_kind {
            return Err(TransportError::DecryptionFailed);
        }

        // 6. Advance monotonic replay watermark only after full cryptographic verification
        replay_guard.commit(&self.device_id, &stream_key, self.seq);

        Ok(payload)
    }
}

/// Builds the length-prefixed canonical AAD binding `(chain_id, collection, device_id, seq)`.
pub fn build_canonical_aad(
    chain_id: &str,
    collection: SyncCollectionKind,
    device_id: &str,
    seq: u64,
) -> Vec<u8> {
    let col = collection.as_str();
    let mut aad = Vec::with_capacity(32 + chain_id.len() + col.len() + device_id.len());
    aad.extend_from_slice(b"SINGULARITY-SYNC-AAD-V1");
    append_len_prefixed(&mut aad, chain_id.as_bytes());
    append_len_prefixed(&mut aad, col.as_bytes());
    append_len_prefixed(&mut aad, device_id.as_bytes());
    aad.extend_from_slice(&seq.to_be_bytes());
    aad
}

fn build_signature_transcript(
    version: u8,
    payload_kind: EnvelopePayloadKind,
    aad: &[u8],
    sender_pubkey_hex: &str,
    nonce_24: &[u8; 24],
    ciphertext: &[u8],
) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(64 + aad.len() + sender_pubkey_hex.len() + 24 + ciphertext.len());
    out.extend_from_slice(b"SINGULARITY-SYNC-SIG-V1");
    out.push(version);
    out.push(payload_kind.tag_byte());
    append_len_prefixed(&mut out, aad);
    append_len_prefixed(&mut out, sender_pubkey_hex.as_bytes());
    out.extend_from_slice(nonce_24);
    append_len_prefixed(&mut out, ciphertext);
    out
}

fn append_len_prefixed(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(bytes);
}

fn validate_identifier(id: &str) -> Result<(), TransportError> {
    if id.is_empty()
        || id.len() > 128
        || !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(TransportError::InvalidIdentifier(id.to_string()));
    }
    Ok(())
}

/// Atomic filesystem synchronization backend reading and writing `.singularity-delta.enc` files.
///
/// Ideal for zero-knowledge synchronization over local drives, USB, Syncthing, Nextcloud, or SMB
/// without ever exposing plaintext metadata or relying on a cloud vendor account.
pub struct EncryptedFolderBackend {
    root_dir: PathBuf,
}

impl EncryptedFolderBackend {
    pub fn new(root_dir: impl Into<PathBuf>) -> Self {
        Self {
            root_dir: root_dir.into(),
        }
    }

    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    /// Atomically writes a `SealedSyncEnvelope` to a `.singularity-delta.enc` file via
    /// write-to-temp + `sync_all()` + atomic rename.
    pub fn write_envelope_atomic(
        &self,
        envelope: &SealedSyncEnvelope,
    ) -> Result<PathBuf, TransportError> {
        validate_identifier(&envelope.chain_id)?;
        validate_identifier(&envelope.device_id)?;
        fs::create_dir_all(&self.root_dir)?;

        let chain_prefix = &envelope.chain_id[..envelope.chain_id.len().min(12)];
        let kind_tag = match envelope.payload_kind {
            EnvelopePayloadKind::CrdtDelta => envelope.collection.as_str(),
            EnvelopePayloadKind::SendTab => "send_tab",
        };
        let final_name = format!(
            "{chain_prefix}_{}_{kind_tag}_{:020}{ENCRYPTED_DELTA_EXTENSION}",
            envelope.device_id, envelope.seq
        );
        let final_path = self.root_dir.join(&final_name);

        let mut rand_suffix = [0u8; 8];
        OsRng.fill_bytes(&mut rand_suffix);
        let tmp_name = format!(".{final_name}.tmp.{}", hex::encode(rand_suffix));
        let tmp_path = self.root_dir.join(&tmp_name);

        let serialized = serde_json::to_vec_pretty(envelope)
            .map_err(|e| TransportError::Serialization(e.to_string()))?;

        {
            let mut file = File::create(&tmp_path)?;
            file.write_all(&serialized)?;
            file.sync_all()?;
        }

        fs::rename(&tmp_path, &final_path)?;
        Ok(final_path)
    }

    /// Scans the directory and reads all `*.singularity-delta.enc` envelopes in deterministic order.
    pub fn read_all_envelopes(&self) -> Result<Vec<SealedSyncEnvelope>, TransportError> {
        if !self.root_dir.exists() {
            return Ok(Vec::new());
        }
        let mut paths: Vec<PathBuf> = Vec::new();
        for entry in fs::read_dir(&self.root_dir)? {
            let entry = entry?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if !name.starts_with('.') && name.ends_with(ENCRYPTED_DELTA_EXTENSION) {
                    paths.push(path);
                }
            }
        }
        paths.sort();

        let mut envelopes = Vec::with_capacity(paths.len());
        for path in paths {
            let meta = fs::metadata(&path)?;
            if meta.len() as usize > MAX_ENVELOPE_WIRE_BYTES {
                return Err(TransportError::MalformedFrame(format!(
                    "Delta file {:?} exceeds {} byte safety cap",
                    path.file_name(),
                    MAX_ENVELOPE_WIRE_BYTES
                )));
            }
            let bytes = fs::read(&path)?;
            let env: SealedSyncEnvelope = serde_json::from_slice(&bytes)
                .map_err(|e| TransportError::Serialization(e.to_string()))?;
            envelopes.push(env);
        }
        Ok(envelopes)
    }
}

/// UDP LAN discovery beacon identifying a peer on the same sync chain (carries zero secrets).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LanDiscoveryBeacon {
    pub protocol_version: u8,
    pub chain_id: String,
    pub device_id: String,
    pub device_name: String,
    pub tcp_port: u16,
    pub x25519_pubkey_hex: String,
}

/// Pure-Rust UDP discovery and framed TCP exchange transport for local P2P synchronization.
///
/// Strictly honors `respect_mullvad_killswitch`: when enabled and the kill-switch is engaged,
/// zero sockets are opened or transmitted.
pub struct LanSyncTransport;

impl LanSyncTransport {
    /// Checks whether network transport is permitted under the Mullvad kill-switch policy.
    pub fn ensure_network_allowed(
        respect_mullvad_killswitch: bool,
        mullvad_killswitch_active: bool,
    ) -> Result<(), TransportError> {
        if respect_mullvad_killswitch && mullvad_killswitch_active {
            return Err(TransportError::BlockedByMullvadKillSwitch);
        }
        Ok(())
    }

    /// Encodes a `LanDiscoveryBeacon` into a compact UDP datagram payload.
    pub fn encode_beacon(beacon: &LanDiscoveryBeacon) -> Result<Vec<u8>, TransportError> {
        let body = serde_json::to_vec(beacon)
            .map_err(|e| TransportError::Serialization(e.to_string()))?;
        let mut frame = Vec::with_capacity(4 + body.len());
        frame.extend_from_slice(LAN_FRAME_MAGIC);
        frame.extend_from_slice(&body);
        Ok(frame)
    }

    /// Decodes a `LanDiscoveryBeacon` from a received UDP datagram.
    pub fn decode_beacon(datagram: &[u8]) -> Result<LanDiscoveryBeacon, TransportError> {
        if datagram.len() < 5 || &datagram[..4] != LAN_FRAME_MAGIC {
            return Err(TransportError::MalformedFrame(
                "Invalid LAN discovery beacon magic".into(),
            ));
        }
        serde_json::from_slice(&datagram[4..])
            .map_err(|e| TransportError::Serialization(e.to_string()))
    }

    /// Sends a single UDP discovery beacon to `target_addr` (broadcast or unicast peer).
    pub fn send_udp_beacon(
        target_addr: SocketAddr,
        beacon: &LanDiscoveryBeacon,
        respect_mullvad_killswitch: bool,
        mullvad_killswitch_active: bool,
    ) -> Result<usize, TransportError> {
        Self::ensure_network_allowed(respect_mullvad_killswitch, mullvad_killswitch_active)?;
        let payload = Self::encode_beacon(beacon)?;
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        if target_addr.ip().is_unspecified()
            || matches!(target_addr.ip(), std::net::IpAddr::V4(v4) if v4.is_broadcast())
        {
            socket.set_broadcast(true)?;
        }
        let sent = socket.send_to(&payload, target_addr)?;
        Ok(sent)
    }

    /// Receives a single UDP discovery beacon from an already-bound `UdpSocket`.
    pub fn receive_udp_beacon(
        socket: &UdpSocket,
        timeout: Duration,
        respect_mullvad_killswitch: bool,
        mullvad_killswitch_active: bool,
    ) -> Result<(LanDiscoveryBeacon, SocketAddr), TransportError> {
        Self::ensure_network_allowed(respect_mullvad_killswitch, mullvad_killswitch_active)?;
        socket.set_read_timeout(Some(timeout))?;
        let mut buf = [0u8; 4096];
        let (len, peer) = socket.recv_from(&mut buf)?;
        let beacon = Self::decode_beacon(&buf[..len])?;
        Ok((beacon, peer))
    }

    /// Sends a `SealedSyncEnvelope` over a length-prefixed TCP frame to `peer_addr`.
    pub fn send_envelope_tcp(
        peer_addr: SocketAddr,
        envelope: &SealedSyncEnvelope,
        timeout: Duration,
        respect_mullvad_killswitch: bool,
        mullvad_killswitch_active: bool,
    ) -> Result<(), TransportError> {
        Self::ensure_network_allowed(respect_mullvad_killswitch, mullvad_killswitch_active)?;
        let body = serde_json::to_vec(envelope)
            .map_err(|e| TransportError::Serialization(e.to_string()))?;
        if body.len() > MAX_ENVELOPE_WIRE_BYTES {
            return Err(TransportError::MalformedFrame(
                "Envelope exceeds maximum TCP frame size".into(),
            ));
        }

        let mut stream = TcpStream::connect_timeout(&peer_addr, timeout)?;
        stream.set_write_timeout(Some(timeout))?;
        stream.write_all(LAN_FRAME_MAGIC)?;
        stream.write_all(&(body.len() as u32).to_be_bytes())?;
        stream.write_all(&body)?;
        stream.flush()?;
        Ok(())
    }

    /// Accepts one TCP connection on `listener` and reads a single framed `SealedSyncEnvelope`.
    pub fn receive_envelope_tcp(
        listener: &TcpListener,
        timeout: Duration,
        respect_mullvad_killswitch: bool,
        mullvad_killswitch_active: bool,
    ) -> Result<(SealedSyncEnvelope, SocketAddr), TransportError> {
        Self::ensure_network_allowed(respect_mullvad_killswitch, mullvad_killswitch_active)?;
        let (mut stream, peer) = listener.accept()?;
        stream.set_read_timeout(Some(timeout))?;

        let mut header = [0u8; 8];
        stream.read_exact(&mut header)?;
        if &header[..4] != LAN_FRAME_MAGIC {
            return Err(TransportError::MalformedFrame(
                "Invalid LAN TCP frame magic".into(),
            ));
        }
        let body_len = u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as usize;
        if body_len == 0 || body_len > MAX_ENVELOPE_WIRE_BYTES {
            return Err(TransportError::MalformedFrame(format!(
                "Invalid TCP frame length: {body_len}"
            )));
        }

        let mut body = vec![0u8; body_len];
        stream.read_exact(&mut body)?;
        let envelope: SealedSyncEnvelope = serde_json::from_slice(&body)
            .map_err(|e| TransportError::Serialization(e.to_string()))?;
        Ok((envelope, peer))
    }
}
