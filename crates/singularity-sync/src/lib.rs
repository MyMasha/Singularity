//! `singularity-sync` — Zero-Knowledge, End-to-End Encrypted P2P Browser Synchronization.
//!
//! Zero third-party accounts, zero cloud telemetry:
//! - 24-word BIP-39-style mnemonic (256-bit `OsRng` entropy + SHA-256 checksum) +
//!   daily rotating 25th anti-replay word (Brave Sync v2 model)
//! - RFC 5869 HKDF-SHA256 domain-separated key hierarchy (`chain_id`, `Ed25519` identity,
//!   `XChaCha20-Poly1305` content key, isolated Vault subkey, `X25519` P2P key)
//! - Deterministic LWW-Element-Set + Vector Clock CRDT across 10 independently toggleable collections
//! - `SealedSyncEnvelope` (Ed25519 device signature + XChaCha20-Poly1305 with canonical AAD + anti-replay)
//! - Atomic Encrypted Folder (`.singularity-delta.enc`) & LAN UDP/TCP transports respecting Mullvad Kill-Switch
//! - End-to-end encrypted `SendTabPayload` (instant tab & media timestamp handoff)

pub mod crdt;
pub mod mnemonic;
pub mod transport;
pub(crate) mod wordlist;

pub use crdt::{
    CrdtDeltaPacket, CrdtDocument, CrdtError, CrdtOperation, CrdtOperationKind, LwwAddRecord,
    LwwElementState, LwwTimestamp, SyncCollectionKind, SyncCollectionPrefs, VectorClock,
};
pub use mnemonic::{
    compute_daily_25th_word, format_utc_date, hkdf_sha256_expand, hkdf_sha256_extract,
    lookup_word_index, utc_day_number, MnemonicError, SecretKey32, SyncMasterKeys, SyncMnemonic,
    ENROLLMENT_WORD_COUNT, PERMANENT_WORD_COUNT,
};
pub use transport::{
    build_canonical_aad, DeviceRegistry, EncryptedFolderBackend, EnvelopePayloadKind,
    LanDiscoveryBeacon, LanSyncTransport, ReplayGuard, SealedSyncEnvelope, SendTabPayload,
    SyncDeviceInfo, SyncEnvelopePayload, SyncTransportConfig, SyncTransportMode, TransportError,
    ENCRYPTED_DELTA_EXTENSION, LAN_FRAME_MAGIC, MAX_ENVELOPE_WIRE_BYTES, SEALED_ENVELOPE_VERSION,
};

use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};
use std::collections::BTreeMap;
use std::net::{SocketAddr, TcpListener};
use std::path::Path;
use std::time::Duration;
use thiserror::Error;
use zeroize::Zeroize;

#[derive(Debug, Error)]
pub enum SyncError {
    #[error(transparent)]
    Mnemonic(#[from] MnemonicError),
    #[error(transparent)]
    Crdt(#[from] CrdtError),
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error("Collection {0:?} is disabled in local sync preferences")]
    CollectionDisabled(SyncCollectionKind),
}

/// Result returned when ingesting a verified `SealedSyncEnvelope` into `SingularitySyncEngine`.
#[derive(Debug, Clone, PartialEq)]
pub enum IngestOutcome {
    /// CRDT delta merged; carries the collection and count of newly applied operations.
    DeltaMerged {
        collection: SyncCollectionKind,
        newly_applied_ops: usize,
    },
    /// Encrypted `SendTabPayload` delivered to this device.
    TabReceived(SendTabPayload),
    /// Envelope belonged to this device itself or targeted a different `SendTab` recipient.
    IgnoredSelfOrOtherTarget,
    /// Envelope was cryptographically valid, but the target collection is locally toggled off.
    SkippedDisabledCollection(SyncCollectionKind),
}

/// Summary of an Encrypted Folder pull synchronization pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FolderSyncReport {
    pub envelopes_scanned: usize,
    pub envelopes_applied: usize,
    pub envelopes_skipped_duplicate_or_self: usize,
    pub tabs_received: usize,
}

/// Unified Zero-Knowledge P2P / E2EE Synchronization Engine for Singularity Browser.
pub struct SingularitySyncEngine {
    mnemonic: SyncMnemonic,
    master_keys: SyncMasterKeys,
    local_device_id: String,
    local_device_name: String,
    local_signing_key: SigningKey,
    collection_prefs: SyncCollectionPrefs,
    transport_config: SyncTransportConfig,
    documents: BTreeMap<SyncCollectionKind, CrdtDocument>,
    device_registry: DeviceRegistry,
    replay_guard: ReplayGuard,
    send_seq_by_stream: BTreeMap<String, u64>,
    received_tabs: Vec<SendTabPayload>,
    mullvad_killswitch_active: bool,
}

impl SingularitySyncEngine {
    /// Creates a brand-new sync chain with fresh 256-bit `OsRng` entropy and enrolls this device.
    /// Returns `(engine, permanent_24_word_phrase, daily_25_word_enrollment_phrase)`.
    pub fn create_new_chain(
        device_name: impl Into<String>,
        platform: impl Into<String>,
        now_unix_secs: u64,
    ) -> (Self, String, String) {
        let mnemonic = SyncMnemonic::generate();
        let phrase_24 = mnemonic.to_24_word_phrase();
        let phrase_25 = mnemonic.to_25_word_phrase(now_unix_secs);
        let engine = Self::from_mnemonic(mnemonic, device_name, platform, now_unix_secs * 1000);
        (engine, phrase_24, phrase_25)
    }

    /// Joins an existing sync chain by validating a time-bound 25-word enrollment phrase
    /// (verifying both the SHA-256 checksum and the daily rotating 25th anti-replay word).
    pub fn join_from_25_words(
        phrase_25: &str,
        now_unix_secs: u64,
        device_name: impl Into<String>,
        platform: impl Into<String>,
    ) -> Result<Self, SyncError> {
        let mnemonic = SyncMnemonic::from_25_words(phrase_25, now_unix_secs)?;
        Ok(Self::from_mnemonic(
            mnemonic,
            device_name,
            platform,
            now_unix_secs * 1000,
        ))
    }

    /// Joins/recovers a sync chain directly from its permanent 24-word backup phrase.
    pub fn join_from_24_words(
        phrase_24: &str,
        now_unix_secs: u64,
        device_name: impl Into<String>,
        platform: impl Into<String>,
    ) -> Result<Self, SyncError> {
        let mnemonic = SyncMnemonic::from_24_words(phrase_24)?;
        Ok(Self::from_mnemonic(
            mnemonic,
            device_name,
            platform,
            now_unix_secs * 1000,
        ))
    }

    /// Constructs an engine from a validated `SyncMnemonic`.
    pub fn from_mnemonic(
        mnemonic: SyncMnemonic,
        device_name: impl Into<String>,
        platform: impl Into<String>,
        now_ms: u64,
    ) -> Self {
        let master_keys = mnemonic.derive_master_keys();
        let mut dev_seed = [0u8; 32];
        OsRng.fill_bytes(&mut dev_seed);
        let local_signing_key = SigningKey::from_bytes(&dev_seed);
        dev_seed.zeroize();

        let mut id_bytes = [0u8; 8];
        OsRng.fill_bytes(&mut id_bytes);
        let local_device_id = format!("dev-{}", hex::encode(id_bytes));
        let local_device_name = device_name.into();
        let pubkey_hex = hex::encode(local_signing_key.verifying_key().as_bytes());

        let mut device_registry = DeviceRegistry::new();
        device_registry.register_device(SyncDeviceInfo {
            device_id: local_device_id.clone(),
            device_name: local_device_name.clone(),
            platform: platform.into(),
            ed25519_pubkey_hex: pubkey_hex,
            enrolled_at_ms: now_ms,
            last_seen_ms: now_ms,
            revoked: false,
            revoked_at_ms: None,
        });

        let mut documents = BTreeMap::new();
        for kind in SyncCollectionKind::ALL {
            documents.insert(kind, CrdtDocument::new(kind));
        }

        Self {
            mnemonic,
            master_keys,
            local_device_id,
            local_device_name,
            local_signing_key,
            collection_prefs: SyncCollectionPrefs::all_enabled(),
            transport_config: SyncTransportConfig::default(),
            documents,
            device_registry,
            replay_guard: ReplayGuard::new(),
            send_seq_by_stream: BTreeMap::new(),
            received_tabs: Vec::new(),
            mullvad_killswitch_active: false,
        }
    }

    pub fn chain_id(&self) -> &str {
        &self.master_keys.chain_id
    }

    pub fn local_device_id(&self) -> &str {
        &self.local_device_id
    }

    pub fn local_device_pubkey_hex(&self) -> String {
        hex::encode(self.local_signing_key.verifying_key().as_bytes())
    }

    pub fn master_keys(&self) -> &SyncMasterKeys {
        &self.master_keys
    }

    pub fn current_25_word_phrase(&self, now_unix_secs: u64) -> String {
        self.mnemonic.to_25_word_phrase(now_unix_secs)
    }

    pub fn permanent_24_word_phrase(&self) -> String {
        self.mnemonic.to_24_word_phrase()
    }

    pub fn transport_config(&self) -> &SyncTransportConfig {
        &self.transport_config
    }

    pub fn set_transport_config(&mut self, config: SyncTransportConfig) {
        self.transport_config = config;
    }

    pub fn set_mullvad_killswitch_active(&mut self, active: bool) {
        self.mullvad_killswitch_active = active;
    }

    pub fn is_mullvad_killswitch_active(&self) -> bool {
        self.mullvad_killswitch_active
    }

    pub fn set_collection_enabled(&mut self, kind: SyncCollectionKind, enabled: bool) {
        self.collection_prefs.set_enabled(kind, enabled);
    }

    pub fn is_collection_enabled(&self, kind: SyncCollectionKind) -> bool {
        self.collection_prefs.is_enabled(kind)
    }

    pub fn device_registry(&self) -> &DeviceRegistry {
        &self.device_registry
    }

    pub fn register_peer_device(&mut self, info: SyncDeviceInfo) {
        self.device_registry.register_device(info);
    }

    /// Revokes a member device so any future envelopes signed by it are rejected immediately.
    pub fn revoke_device(&mut self, device_id: &str, revoked_at_ms: u64) -> bool {
        self.device_registry.revoke_device(device_id, revoked_at_ms)
    }

    /// Returns a read-only reference to the CRDT document for `collection`.
    pub fn document(&self, collection: SyncCollectionKind) -> &CrdtDocument {
        self.documents
            .get(&collection)
            .expect("All 10 SyncCollectionKind documents are pre-initialized")
    }

    /// Records a local CRDT upsert (add or update) for `collection`.
    pub fn upsert_item(
        &mut self,
        collection: SyncCollectionKind,
        item_id: impl Into<String>,
        value: serde_json::Value,
        now_ms: u64,
    ) -> CrdtOperation {
        let dev_id = self.local_device_id.clone();
        self.documents
            .get_mut(&collection)
            .expect("All 10 documents initialized")
            .upsert(&dev_id, item_id, value, now_ms)
    }

    /// Records a local CRDT delete (tombstone) for `collection`.
    pub fn delete_item(
        &mut self,
        collection: SyncCollectionKind,
        item_id: impl Into<String>,
        now_ms: u64,
    ) -> CrdtOperation {
        let dev_id = self.local_device_id.clone();
        self.documents
            .get_mut(&collection)
            .expect("All 10 documents initialized")
            .delete(&dev_id, item_id, now_ms)
    }

    fn next_send_seq(&mut self, stream: &str) -> u64 {
        let entry = self
            .send_seq_by_stream
            .entry(stream.to_string())
            .or_insert(0);
        *entry = entry.saturating_add(1);
        *entry
    }

    /// Seals the full CRDT delta for `collection` into an Ed25519-signed, XChaCha20-Poly1305 envelope.
    pub fn seal_collection_delta(
        &mut self,
        collection: SyncCollectionKind,
    ) -> Result<SealedSyncEnvelope, SyncError> {
        self.seal_collection_delta_since(collection, &VectorClock::new())
    }

    /// Seals only operations newer than `peer_clock` for `collection`.
    pub fn seal_collection_delta_since(
        &mut self,
        collection: SyncCollectionKind,
        peer_clock: &VectorClock,
    ) -> Result<SealedSyncEnvelope, SyncError> {
        if !self.collection_prefs.is_enabled(collection) {
            return Err(SyncError::CollectionDisabled(collection));
        }
        let delta = self
            .document(collection)
            .export_delta_since(&self.local_device_id, peer_clock);
        let stream = format!("crdt:{}", collection.as_str());
        let seq = self.next_send_seq(&stream);
        let envelope = SealedSyncEnvelope::seal(
            &self.master_keys,
            &self.local_signing_key,
            &self.local_device_id,
            collection,
            seq,
            &SyncEnvelopePayload::CrdtDelta(delta),
        )?;
        Ok(envelope)
    }

    /// Seals a `SendTabPayload` (instant tab & media timestamp handoff) into an E2EE envelope.
    pub fn create_send_tab_envelope(
        &mut self,
        url: impl Into<String>,
        title: impl Into<String>,
        media_time_sec: Option<f64>,
        target_device_id: impl Into<String>,
        now_ms: u64,
    ) -> Result<SealedSyncEnvelope, SyncError> {
        let mut rand_id = [0u8; 8];
        OsRng.fill_bytes(&mut rand_id);
        let tab = SendTabPayload {
            payload_id: format!("tab-{}", hex::encode(rand_id)),
            url: url.into(),
            title: title.into(),
            media_time_sec,
            target_device_id: target_device_id.into(),
            sender_device_id: self.local_device_id.clone(),
            created_at_ms: now_ms,
        };
        let seq = self.next_send_seq("send_tab");
        let envelope = SealedSyncEnvelope::seal(
            &self.master_keys,
            &self.local_signing_key,
            &self.local_device_id,
            SyncCollectionKind::OpenTabs,
            seq,
            &SyncEnvelopePayload::SendTab(tab),
        )?;
        Ok(envelope)
    }

    /// Verifies and ingests an incoming `SealedSyncEnvelope` (checking revocation, Ed25519 signature,
    /// XChaCha20-Poly1305 AEAD + AAD, and monotonic anti-replay).
    pub fn ingest_envelope(
        &mut self,
        envelope: &SealedSyncEnvelope,
        now_ms: u64,
    ) -> Result<IngestOutcome, SyncError> {
        if envelope.device_id == self.local_device_id {
            return Ok(IngestOutcome::IgnoredSelfOrOtherTarget);
        }

        let payload = envelope.unseal(
            &self.master_keys,
            &self.device_registry,
            &mut self.replay_guard,
        )?;

        // Auto-enroll valid peer devices that proved knowledge of the chain AEAD key + signed validly,
        // strictly refusing any revoked public key or silent TOFU enrollment after a revocation event.
        if self.device_registry.get(&envelope.device_id).is_none() {
            if self
                .device_registry
                .is_pubkey_revoked(&envelope.sender_pubkey_hex)
                || self.device_registry.has_revoked_devices()
            {
                return Err(SyncError::Transport(TransportError::DeviceRevoked(
                    envelope.device_id.clone(),
                )));
            }
            self.device_registry.register_device(SyncDeviceInfo {
                device_id: envelope.device_id.clone(),
                device_name: envelope.device_id.clone(),
                platform: "peer".to_string(),
                ed25519_pubkey_hex: envelope.sender_pubkey_hex.clone(),
                enrolled_at_ms: now_ms,
                last_seen_ms: now_ms,
                revoked: false,
                revoked_at_ms: None,
            });
        } else {
            self.device_registry
                .touch_last_seen(&envelope.device_id, now_ms);
        }

        match payload {
            SyncEnvelopePayload::CrdtDelta(delta) => {
                if delta.collection != envelope.collection
                    || delta.origin_device_id != envelope.device_id
                {
                    return Err(SyncError::Transport(TransportError::DecryptionFailed));
                }
                if !self.collection_prefs.is_enabled(delta.collection) {
                    return Ok(IngestOutcome::SkippedDisabledCollection(delta.collection));
                }
                let doc = self
                    .documents
                    .get_mut(&delta.collection)
                    .expect("All 10 collections initialized");
                let newly_applied_ops = doc.merge_delta(&delta)?;
                Ok(IngestOutcome::DeltaMerged {
                    collection: delta.collection,
                    newly_applied_ops,
                })
            }
            SyncEnvelopePayload::SendTab(tab) => {
                if envelope.collection != SyncCollectionKind::OpenTabs
                    || tab.sender_device_id != envelope.device_id
                {
                    return Err(SyncError::Transport(TransportError::DecryptionFailed));
                }
                if tab.target_device_id == "*" || tab.target_device_id == self.local_device_id {
                    self.received_tabs.push(tab.clone());
                    Ok(IngestOutcome::TabReceived(tab))
                } else {
                    Ok(IngestOutcome::IgnoredSelfOrOtherTarget)
                }
            }
        }
    }

    /// Drains and returns all received `SendTabPayload` items queued for this device.
    pub fn take_received_tabs(&mut self) -> Vec<SendTabPayload> {
        std::mem::take(&mut self.received_tabs)
    }

    /// Pushes encrypted deltas for all enabled non-empty collections to `folder_dir` atomically
    /// as `.singularity-delta.enc` files. Works completely offline even when Mullvad Kill-Switch is active.
    pub fn push_to_encrypted_folder(&mut self, folder_dir: &Path) -> Result<usize, SyncError> {
        let backend = EncryptedFolderBackend::new(folder_dir);
        let enabled = self.collection_prefs.enabled_collections();
        let mut written = 0usize;
        for kind in enabled {
            if self.document(kind).total_tracked_items() == 0 {
                continue;
            }
            let env = self.seal_collection_delta(kind)?;
            backend.write_envelope_atomic(&env)?;
            written += 1;
        }
        Ok(written)
    }

    /// Pulls and merges all unseen `.singularity-delta.enc` envelopes from `folder_dir`.
    pub fn pull_from_encrypted_folder(
        &mut self,
        folder_dir: &Path,
        now_ms: u64,
    ) -> Result<FolderSyncReport, SyncError> {
        let backend = EncryptedFolderBackend::new(folder_dir);
        let envelopes = backend.read_all_envelopes()?;
        let mut report = FolderSyncReport {
            envelopes_scanned: envelopes.len(),
            ..Default::default()
        };

        for env in envelopes {
            if env.device_id == self.local_device_id {
                report.envelopes_skipped_duplicate_or_self += 1;
                continue;
            }
            match self.ingest_envelope(&env, now_ms) {
                Ok(IngestOutcome::DeltaMerged { .. }) => {
                    report.envelopes_applied += 1;
                }
                Ok(IngestOutcome::TabReceived(_)) => {
                    report.envelopes_applied += 1;
                    report.tabs_received += 1;
                }
                Ok(IngestOutcome::IgnoredSelfOrOtherTarget)
                | Ok(IngestOutcome::SkippedDisabledCollection(_)) => {
                    report.envelopes_skipped_duplicate_or_self += 1;
                }
                Err(SyncError::Transport(TransportError::ReplayDetected { .. })) => {
                    // Already ingested from folder in an earlier poll pass
                    report.envelopes_skipped_duplicate_or_self += 1;
                }
                Err(
                    SyncError::Transport(TransportError::DeviceRevoked(_))
                    | SyncError::Transport(TransportError::DeviceKeyMismatch(_))
                    | SyncError::Transport(TransportError::InvalidSignature(_))
                    | SyncError::Transport(TransportError::DecryptionFailed)
                    | SyncError::Transport(TransportError::ChainIdMismatch)
                    | SyncError::Transport(TransportError::UnsupportedVersion(_))
                    | SyncError::Transport(TransportError::ZeroSequenceNumber)
                    | SyncError::Transport(TransportError::MalformedFrame(_))
                    | SyncError::Transport(TransportError::Serialization(_))
                    | SyncError::Transport(TransportError::InvalidIdentifier(_))
                    | SyncError::Crdt(_),
                ) => {
                    // Skip corrupted, tampered, foreign-chain, or revoked-device envelopes
                    // individually so one bad file cannot block valid peers in the folder.
                    report.envelopes_skipped_duplicate_or_self += 1;
                }
                Err(other) => return Err(other),
            }
        }
        Ok(report)
    }

    /// Builds a zero-secret LAN discovery beacon for this device.
    pub fn build_lan_beacon(&self, tcp_port: u16) -> LanDiscoveryBeacon {
        LanDiscoveryBeacon {
            protocol_version: SEALED_ENVELOPE_VERSION,
            chain_id: self.master_keys.chain_id.clone(),
            device_id: self.local_device_id.clone(),
            device_name: self.local_device_name.clone(),
            tcp_port,
            x25519_pubkey_hex: hex::encode(self.master_keys.p2p_x25519_public().as_bytes()),
        }
    }

    /// Sends a sealed envelope over LAN TCP while strictly respecting `respect_mullvad_killswitch`.
    pub fn send_envelope_over_lan(
        &self,
        peer_addr: SocketAddr,
        envelope: &SealedSyncEnvelope,
        timeout: Duration,
    ) -> Result<(), SyncError> {
        LanSyncTransport::send_envelope_tcp(
            peer_addr,
            envelope,
            timeout,
            self.transport_config.respect_mullvad_killswitch,
            self.mullvad_killswitch_active,
        )?;
        Ok(())
    }

    /// Receives and ingests one sealed envelope over LAN TCP while strictly respecting `respect_mullvad_killswitch`.
    pub fn receive_and_ingest_over_lan(
        &mut self,
        listener: &TcpListener,
        timeout: Duration,
        now_ms: u64,
    ) -> Result<(IngestOutcome, SocketAddr), SyncError> {
        let (envelope, peer) = LanSyncTransport::receive_envelope_tcp(
            listener,
            timeout,
            self.transport_config.respect_mullvad_killswitch,
            self.mullvad_killswitch_active,
        )?;
        let outcome = self.ingest_envelope(&envelope, now_ms)?;
        Ok((outcome, peer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::net::UdpSocket;
    use std::thread;

    fn unique_temp_dir(label: &str) -> std::path::PathBuf {
        let mut r = [0u8; 8];
        OsRng.fill_bytes(&mut r);
        let dir = std::env::temp_dir().join(format!("singularity_sync_{label}_{}", hex::encode(r)));
        std::fs::create_dir_all(&dir).expect("create temp test dir");
        dir
    }

    #[test]
    fn full_two_device_sync_join_and_crdt_convergence() {
        let now_sec = 1_795_651_200u64; // 2026-11-26 UTC
        let (mut laptop, _phrase_24, phrase_25) =
            SingularitySyncEngine::create_new_chain("ThinkPad-Linux", "linux", now_sec);

        // Phone joins using the daily 25-word phrase
        let mut phone =
            SingularitySyncEngine::join_from_25_words(&phrase_25, now_sec + 3600, "Pixel", "android")
                .expect("Join with valid 25-word phrase");
        assert_eq!(laptop.chain_id(), phone.chain_id());

        // Offline edits on both devices
        laptop.upsert_item(
            SyncCollectionKind::Bookmarks,
            "bm-rust",
            json!({"title": "Rust Lang", "url": "https://www.rust-lang.org"}),
            10_000,
        );
        laptop.upsert_item(
            SyncCollectionKind::Bookmarks,
            "bm-shared",
            json!({"title": "Old Title"}),
            10_005,
        );

        phone.upsert_item(
            SyncCollectionKind::Bookmarks,
            "bm-shared",
            json!({"title": "Newer Phone Title"}),
            10_050,
        );
        phone.upsert_item(
            SyncCollectionKind::VaultCredentials,
            "cred-1",
            json!({"site": "example.org", "user": "alice"}),
            10_060,
        );

        // Exchange sealed envelopes
        let env_laptop = laptop
            .seal_collection_delta(SyncCollectionKind::Bookmarks)
            .unwrap();
        let env_phone_bm = phone
            .seal_collection_delta(SyncCollectionKind::Bookmarks)
            .unwrap();
        let env_phone_vault = phone
            .seal_collection_delta(SyncCollectionKind::VaultCredentials)
            .unwrap();

        phone.ingest_envelope(&env_laptop, 10_100).unwrap();
        laptop.ingest_envelope(&env_phone_bm, 10_100).unwrap();
        laptop.ingest_envelope(&env_phone_vault, 10_100).unwrap();

        // Both devices converged identically
        assert_eq!(
            laptop.document(SyncCollectionKind::Bookmarks).active_items(),
            phone.document(SyncCollectionKind::Bookmarks).active_items()
        );
        assert_eq!(
            laptop.document(SyncCollectionKind::Bookmarks).get("bm-shared"),
            Some(&json!({"title": "Newer Phone Title"}))
        );
        assert_eq!(
            laptop
                .document(SyncCollectionKind::VaultCredentials)
                .get("cred-1"),
            Some(&json!({"site": "example.org", "user": "alice"}))
        );
    }

    #[test]
    fn envelope_rejects_tampered_aad_replay_and_revoked_devices() {
        let now_sec = 1_795_651_200u64;
        let (mut dev_a, phrase_24, _) =
            SingularitySyncEngine::create_new_chain("Desktop", "linux", now_sec);
        let mut dev_b =
            SingularitySyncEngine::join_from_24_words(&phrase_24, now_sec, "Laptop", "linux")
                .unwrap();

        dev_a.upsert_item(
            SyncCollectionKind::Settings,
            "doh_enabled",
            json!(true),
            20_000,
        );
        let env1 = dev_a
            .seal_collection_delta(SyncCollectionKind::Settings)
            .unwrap();

        // Tamper with seq (AAD + signed field) -> rejected
        let mut tampered_seq = env1.clone();
        tampered_seq.seq = 999;
        assert!(matches!(
            dev_b.ingest_envelope(&tampered_seq, 20_010),
            Err(SyncError::Transport(TransportError::InvalidSignature(_)))
        ));

        // Valid ingest succeeds
        let outcome = dev_b.ingest_envelope(&env1, 20_010).unwrap();
        assert!(matches!(
            outcome,
            IngestOutcome::DeltaMerged {
                collection: SyncCollectionKind::Settings,
                newly_applied_ops: 1
            }
        ));

        // Replaying the exact same envelope is rejected monotonically
        assert!(matches!(
            dev_b.ingest_envelope(&env1, 20_020),
            Err(SyncError::Transport(TransportError::ReplayDetected { .. }))
        ));

        // Revoking dev_a immediately blocks subsequent valid envelopes from dev_a
        assert!(dev_b.revoke_device(dev_a.local_device_id(), 20_030));
        dev_a.upsert_item(
            SyncCollectionKind::Settings,
            "theme",
            json!("obsidian"),
            20_040,
        );
        let env2 = dev_a
            .seal_collection_delta(SyncCollectionKind::Settings)
            .unwrap();
        assert!(matches!(
            dev_b.ingest_envelope(&env2, 20_050),
            Err(SyncError::Transport(TransportError::DeviceRevoked(_)))
        ));
    }

    #[test]
    fn encrypted_folder_backend_roundtrip_and_zero_plaintext_leakage() {
        let dir = unique_temp_dir("folder_backend");
        let now_sec = 1_795_651_200u64;

        let (mut dev_a, phrase_24, _) =
            SingularitySyncEngine::create_new_chain("Workstation", "linux", now_sec);
        let mut dev_b =
            SingularitySyncEngine::join_from_24_words(&phrase_24, now_sec, "Travel", "linux")
                .unwrap();

        let secret_marker = "SUPER_SECRET_VAULT_TOKEN_9942";
        dev_a.upsert_item(
            SyncCollectionKind::VaultCredentials,
            "secret-entry",
            json!({"token": secret_marker}),
            30_000,
        );
        dev_a.upsert_item(
            SyncCollectionKind::KeybindsAndChains,
            "cmd-close",
            json!({"keys": "Ctrl+W"}),
            30_001,
        );

        let pushed = dev_a.push_to_encrypted_folder(&dir).unwrap();
        assert_eq!(pushed, 2);

        // Verify files on disk have .singularity-delta.enc extension and zero plaintext leakage
        let entries: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        assert_eq!(entries.len(), 2);
        for path in &entries {
            assert!(path
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .ends_with(ENCRYPTED_DELTA_EXTENSION));
            let raw = std::fs::read_to_string(path).unwrap();
            assert!(!raw.contains(secret_marker));
            assert!(!raw.contains("Ctrl+W"));
        }

        // Device B pulls from encrypted folder
        let report = dev_b.pull_from_encrypted_folder(&dir, 30_100).unwrap();
        assert_eq!(report.envelopes_scanned, 2);
        assert_eq!(report.envelopes_applied, 2);
        assert_eq!(
            dev_b
                .document(SyncCollectionKind::VaultCredentials)
                .get("secret-entry"),
            Some(&json!({"token": secret_marker}))
        );

        // Second pull is cleanly idempotent (replay guard skips already-seen files)
        let report2 = dev_b.pull_from_encrypted_folder(&dir, 30_200).unwrap();
        assert_eq!(report2.envelopes_applied, 0);
        assert_eq!(report2.envelopes_skipped_duplicate_or_self, 2);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn send_tab_lan_tcp_udp_beacon_and_mullvad_killswitch_guard() {
        let now_sec = 1_795_651_200u64;
        let (mut sender, phrase_24, _) =
            SingularitySyncEngine::create_new_chain("Desktop", "linux", now_sec);
        let mut receiver =
            SingularitySyncEngine::join_from_24_words(&phrase_24, now_sec, "LivingRoom", "linux")
                .unwrap();

        let tab_env = sender
            .create_send_tab_envelope(
                "https://video.example/watch?v=42",
                "Deep Space Documentary",
                Some(1425.5),
                receiver.local_device_id(),
                40_000,
            )
            .unwrap();

        // Bind a real loopback TCP listener for LAN P2P exchange
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        // When Mullvad kill-switch is active and respected, LAN send must be strictly blocked
        sender.set_mullvad_killswitch_active(true);
        assert!(matches!(
            sender.send_envelope_over_lan(addr, &tab_env, Duration::from_secs(2)),
            Err(SyncError::Transport(TransportError::BlockedByMullvadKillSwitch))
        ));

        // Disengaging kill-switch permits LAN P2P TCP delivery
        sender.set_mullvad_killswitch_active(false);
        let tab_env_clone = tab_env.clone();
        let handle = thread::spawn(move || {
            sender
                .send_envelope_over_lan(addr, &tab_env_clone, Duration::from_secs(2))
                .expect("LAN TCP send");
        });

        let (outcome, _peer) = receiver
            .receive_and_ingest_over_lan(&listener, Duration::from_secs(2), 40_100)
            .expect("LAN TCP receive");
        handle.join().unwrap();

        match outcome {
            IngestOutcome::TabReceived(tab) => {
                assert_eq!(tab.url, "https://video.example/watch?v=42");
                assert_eq!(tab.title, "Deep Space Documentary");
                assert_eq!(tab.media_time_sec, Some(1425.5));
            }
            other => panic!("Expected TabReceived, got {other:?}"),
        }
        assert_eq!(receiver.take_received_tabs().len(), 1);

        // Verify UDP LAN discovery beacon roundtrip & killswitch guard
        let udp_rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let udp_addr = udp_rx.local_addr().unwrap();
        let beacon = receiver.build_lan_beacon(addr.port());
        assert!(matches!(
            LanSyncTransport::send_udp_beacon(udp_addr, &beacon, true, true),
            Err(TransportError::BlockedByMullvadKillSwitch)
        ));
        LanSyncTransport::send_udp_beacon(udp_addr, &beacon, true, false).unwrap();
        let (decoded, _) =
            LanSyncTransport::receive_udp_beacon(&udp_rx, Duration::from_secs(2), true, false)
                .unwrap();
        assert_eq!(decoded, beacon);
    }

    #[test]
    fn revoked_device_cannot_bypass_via_new_device_id_or_auto_enroll() {
        let now_sec = 1_795_651_200u64;
        let (mut dev_a, phrase_24, _) =
            SingularitySyncEngine::create_new_chain("Desktop", "linux", now_sec);
        let mut dev_b =
            SingularitySyncEngine::join_from_24_words(&phrase_24, now_sec, "Laptop", "linux")
                .unwrap();

        dev_a.upsert_item(
            SyncCollectionKind::Settings,
            "k1",
            json!("v1"),
            20_000,
        );
        let env1 = dev_a
            .seal_collection_delta(SyncCollectionKind::Settings)
            .unwrap();
        dev_b.ingest_envelope(&env1, 20_010).unwrap();
        assert!(dev_b.revoke_device(dev_a.local_device_id(), 20_030));

        // 1. Same revoked Ed25519 pubkey attempting to re-enroll under a brand-new device_id
        let mut forged_doc = CrdtDocument::new(SyncCollectionKind::Settings);
        forged_doc.upsert("dev-a-reborn", "evil", json!(true), 20_040);
        let forged_delta = forged_doc.export_delta_since("dev-a-reborn", &VectorClock::new());
        let env_same_key_new_id = SealedSyncEnvelope::seal(
            dev_a.master_keys(),
            &dev_a.local_signing_key,
            "dev-a-reborn",
            SyncCollectionKind::Settings,
            1,
            &SyncEnvelopePayload::CrdtDelta(forged_delta),
        )
        .unwrap();
        assert!(matches!(
            dev_b.ingest_envelope(&env_same_key_new_id, 20_050),
            Err(SyncError::Transport(TransportError::DeviceRevoked(_)))
        ));
        assert!(dev_b.device_registry().get("dev-a-reborn").is_none());

        // 2. Uppercase hex variant of the revoked pubkey is also rejected
        let upper_pk = dev_a.local_device_pubkey_hex().to_ascii_uppercase();
        assert!(matches!(
            dev_b
                .device_registry()
                .verify_authorized_sender("dev-a-upper", &upper_pk),
            Err(TransportError::DeviceRevoked(_))
        ));

        // 3. Unknown device with a fresh Ed25519 key cannot silently TOFU auto-enroll after revocation
        let mut fresh_seed = [0u8; 32];
        OsRng.fill_bytes(&mut fresh_seed);
        let fresh_sk = SigningKey::from_bytes(&fresh_seed);
        fresh_seed.zeroize();
        let mut fresh_doc = CrdtDocument::new(SyncCollectionKind::Settings);
        fresh_doc.upsert("dev-a-fresh", "evil2", json!(true), 20_060);
        let fresh_delta = fresh_doc.export_delta_since("dev-a-fresh", &VectorClock::new());
        let env_fresh_key = SealedSyncEnvelope::seal(
            dev_a.master_keys(),
            &fresh_sk,
            "dev-a-fresh",
            SyncCollectionKind::Settings,
            1,
            &SyncEnvelopePayload::CrdtDelta(fresh_delta),
        )
        .unwrap();
        assert!(matches!(
            dev_b.ingest_envelope(&env_fresh_key, 20_070),
            Err(SyncError::Transport(TransportError::DeviceRevoked(_)))
        ));
        assert!(dev_b.device_registry().get("dev-a-fresh").is_none());
    }

    #[test]
    fn vault_subkey_isolation_rejects_collection_and_origin_mismatch() {
        let now_sec = 1_795_651_200u64;
        let (_dev_a, phrase_24, _) =
            SingularitySyncEngine::create_new_chain("Desktop", "linux", now_sec);
        let mut dev_b =
            SingularitySyncEngine::join_from_24_words(&phrase_24, now_sec, "Laptop", "linux")
                .unwrap();

        let mut rogue_seed = [0u8; 32];
        OsRng.fill_bytes(&mut rogue_seed);
        let rogue_sk = SigningKey::from_bytes(&rogue_seed);
        rogue_seed.zeroize();

        // Attacker holds only content_encryption_key (NOT vault_subkey) and seals a VaultCredentials
        // CRDT delta inside a Bookmarks envelope header.
        let mut vault_doc = CrdtDocument::new(SyncCollectionKind::VaultCredentials);
        vault_doc.upsert("dev-rogue", "cred-injected", json!({"pw": "evil"}), 50_000);
        let vault_delta = vault_doc.export_delta_since("dev-rogue", &VectorClock::new());

        let forged_env = SealedSyncEnvelope::seal_with_key(
            dev_b.chain_id(),
            dev_b.master_keys().content_encryption_key(),
            &rogue_sk,
            "dev-rogue",
            SyncCollectionKind::Bookmarks,
            1,
            &SyncEnvelopePayload::CrdtDelta(vault_delta),
        )
        .unwrap();

        assert!(matches!(
            dev_b.ingest_envelope(&forged_env, 50_010),
            Err(SyncError::Transport(TransportError::DecryptionFailed))
        ));
        assert!(dev_b
            .document(SyncCollectionKind::VaultCredentials)
            .active_items()
            .is_empty());

        // Spoofed origin_device_id inside a matching collection is also rejected.
        let mut bm_doc = CrdtDocument::new(SyncCollectionKind::Bookmarks);
        bm_doc.upsert("dev-victim", "bm-spoof", json!({"url": "https://evil.example"}), 50_020);
        let spoofed_delta = bm_doc.export_delta_since("dev-victim", &VectorClock::new());
        let spoofed_env = SealedSyncEnvelope::seal_with_key(
            dev_b.chain_id(),
            dev_b.master_keys().content_encryption_key(),
            &rogue_sk,
            "dev-rogue",
            SyncCollectionKind::Bookmarks,
            2,
            &SyncEnvelopePayload::CrdtDelta(spoofed_delta),
        )
        .unwrap();
        assert!(matches!(
            dev_b.ingest_envelope(&spoofed_env, 50_030),
            Err(SyncError::Transport(TransportError::DecryptionFailed))
        ));
    }

    #[test]
    fn encrypted_folder_skips_corrupted_and_revoked_envelopes_without_blocking_valid_peers() {
        let dir = unique_temp_dir("folder_resilience");
        let now_sec = 1_795_651_200u64;

        let (mut dev_revoked, phrase_24, _) =
            SingularitySyncEngine::create_new_chain("RevokedLaptop", "linux", now_sec);
        let mut dev_good =
            SingularitySyncEngine::join_from_24_words(&phrase_24, now_sec, "GoodDesktop", "linux")
                .unwrap();
        let mut dev_receiver =
            SingularitySyncEngine::join_from_24_words(&phrase_24, now_sec, "Receiver", "linux")
                .unwrap();

        // First enroll both dev_revoked and dev_good on receiver before any revocation event
        // (post-revocation silent TOFU enrollment is strictly forbidden by security policy),
        // then revoke dev_revoked.
        dev_revoked.upsert_item(
            SyncCollectionKind::Bookmarks,
            "bm-before-revoke",
            json!({"title": "Initial"}),
            10_000,
        );
        let initial_env = dev_revoked
            .seal_collection_delta(SyncCollectionKind::Bookmarks)
            .unwrap();
        dev_receiver.ingest_envelope(&initial_env, 10_010).unwrap();

        dev_good.upsert_item(
            SyncCollectionKind::Bookmarks,
            "bm-good-init",
            json!({"title": "Good Peer Enrolled"}),
            10_012,
        );
        let good_init_env = dev_good
            .seal_collection_delta(SyncCollectionKind::Bookmarks)
            .unwrap();
        dev_receiver.ingest_envelope(&good_init_env, 10_015).unwrap();

        assert!(dev_receiver.revoke_device(dev_revoked.local_device_id(), 10_020));

        // 1. Write a corrupted JSON file with an early sorting name
        std::fs::write(
            dir.join("000_corrupt.singularity-delta.enc"),
            b"{not valid json!!!",
        )
        .unwrap();

        // 2. Write a subsequent envelope from the revoked device
        dev_revoked.upsert_item(
            SyncCollectionKind::Bookmarks,
            "bm-evil",
            json!({"title": "Revoked"}),
            10_050,
        );
        dev_revoked.push_to_encrypted_folder(&dir).unwrap();

        // 3. Write a valid envelope from dev_good
        dev_good.upsert_item(
            SyncCollectionKind::Bookmarks,
            "bm-good",
            json!({"title": "Valid Peer Bookmark"}),
            10_060,
        );
        dev_good.push_to_encrypted_folder(&dir).unwrap();

        // Pull must skip the corrupted JSON and revoked device envelope and still merge dev_good
        let report = dev_receiver
            .pull_from_encrypted_folder(&dir, 10_100)
            .expect("pull must not abort on corrupted or revoked files");
        assert_eq!(report.envelopes_applied, 1);
        assert_eq!(
            dev_receiver
                .document(SyncCollectionKind::Bookmarks)
                .get("bm-good"),
            Some(&json!({"title": "Valid Peer Bookmark"}))
        );
        assert!(dev_receiver
            .document(SyncCollectionKind::Bookmarks)
            .get("bm-evil")
            .is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
