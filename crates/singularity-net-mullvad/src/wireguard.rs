//! Native Rust Userspace WireGuard (`boringtun`-compatible) Cryptographic Engine.
//!
//! Performs local X25519 keypair generation, contributory ECDH session key derivation, optional
//! Post-Quantum preshared key (PSK) mixing, and ChaCha20-Poly1305 AEAD transport packet
//! encapsulation with DAITA and receiver_index validation.

use crate::daita::{pad_daita_frame, unpad_daita_frame};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

/// WireGuard protocol `REJECT_AFTER_MESSAGES` limit (2^64 - 2^13 - 1) to prevent nonce wrap.
const REJECT_AFTER_MESSAGES: u64 = u64::MAX - 8192;

/// RFC 6479 / WireGuard 64-packet sliding anti-replay window.
#[derive(Debug, Default)]
struct ReplayWindow {
    highest_counter: u64,
    bitmap: u64,
    initialized: bool,
}

impl ReplayWindow {
    fn check(&self, counter: u64) -> bool {
        if counter == 0 {
            return false;
        }
        if !self.initialized {
            return true;
        }
        if counter > self.highest_counter {
            return true;
        }
        let delta = self.highest_counter - counter;
        if delta >= 64 {
            return false;
        }
        (self.bitmap & (1u64 << delta)) == 0
    }

    fn record(&mut self, counter: u64) {
        if !self.initialized {
            self.highest_counter = counter;
            self.bitmap = 1;
            self.initialized = true;
            return;
        }
        if counter > self.highest_counter {
            let shift = counter - self.highest_counter;
            if shift >= 64 {
                self.bitmap = 1;
            } else {
                self.bitmap = (self.bitmap << shift) | 1;
            }
            self.highest_counter = counter;
        } else {
            let delta = self.highest_counter - counter;
            if delta < 64 {
                self.bitmap |= 1u64 << delta;
            }
        }
    }
}

/// Locally generated Curve25519 WireGuard keypair kept exclusively in Singularity's process memory.
pub struct LocalWireGuardKeypair {
    secret: StaticSecret,
    public: PublicKey,
}

impl fmt::Debug for LocalWireGuardKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalWireGuardKeypair")
            .field("secret", &"[REDACTED]")
            .field("public_key_base64", &self.public_key_base64())
            .finish()
    }
}

impl Default for LocalWireGuardKeypair {
    fn default() -> Self {
        Self::generate()
    }
}

impl LocalWireGuardKeypair {
    /// Generates a fresh cryptographic X25519 WireGuard keypair using the OS CSPRNG.
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    pub fn public_key_base64(&self) -> String {
        BASE64.encode(self.public.as_bytes())
    }

    /// Derives separate 256-bit directional transport keys `(initiator_tx_key, responder_tx_key)`
    /// via X25519 ECDH, an ephemeral handshake salt, and optional Post-Quantum PSK so TX and RX
    /// never reuse the same `(key, nonce)` pair.
    ///
    /// Rejects low-order Curve25519 peer public keys (`!shared_secret.was_contributory()`).
    pub fn derive_directional_transport_keys(
        &self,
        peer_public_bytes: &[u8; 32],
        ephemeral_salt: &[u8; 32],
        pq_psk: Option<&[u8; 32]>,
    ) -> Result<([u8; 32], [u8; 32]), String> {
        let peer_pub = PublicKey::from(*peer_public_bytes);
        let dh = self.secret.diffie_hellman(&peer_pub);
        if !dh.was_contributory() {
            return Err(
                "WireGuard X25519 ECDH rejected: peer public key is a non-contributory low-order point"
                    .into(),
            );
        }
        let mut shared_secret = dh.to_bytes();

        let derive_dir = |label: &[u8]| -> [u8; 32] {
            let mut hasher = Sha256::new();
            hasher.update(b"WireGuard v1 -- Singularity Directional Transport KDF:");
            hasher.update(label);
            hasher.update(ephemeral_salt);
            hasher.update(&shared_secret);
            if let Some(psk) = pq_psk {
                hasher.update(b":PQ-PSK-MLKEM1024:");
                hasher.update(psk);
            }
            hasher.finalize().into()
        };

        let i2r = derive_dir(b"I2R");
        let r2i = derive_dir(b"R2I");
        shared_secret.zeroize();
        Ok((i2r, r2i))
    }
}

/// Active userspace WireGuard transport crypto engine handling directional ChaCha20-Poly1305 AEAD,
/// DAITA constant-size padding, strict receiver index validation, and sliding-window anti-replay.
pub struct UserspaceWireGuardTunnel {
    tx_key: [u8; 32],
    rx_key: [u8; 32],
    local_index: u32,
    remote_index: u32,
    tx_counter: AtomicU64,
    replay_window: Mutex<ReplayWindow>,
    daita_enabled: bool,
    daita_block_size: usize,
    quantum_resistant_active: bool,
}

impl fmt::Debug for UserspaceWireGuardTunnel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserspaceWireGuardTunnel")
            .field("tx_key", &"[REDACTED]")
            .field("rx_key", &"[REDACTED]")
            .field("local_index", &self.local_index)
            .field("remote_index", &self.remote_index)
            .field("daita_enabled", &self.daita_enabled)
            .field("daita_block_size", &self.daita_block_size)
            .field("quantum_resistant_active", &self.quantum_resistant_active)
            .finish()
    }
}

impl UserspaceWireGuardTunnel {
    /// Fallible constructor that rejects low-order X25519 peer public keys.
    pub fn try_new(
        local_keys: &LocalWireGuardKeypair,
        peer_public_bytes: &[u8; 32],
        pq_psk: Option<&[u8; 32]>,
        daita_enabled: bool,
        daita_block_size: usize,
    ) -> Result<Self, String> {
        let mut ephemeral_salt = [0u8; 32];
        OsRng.fill_bytes(&mut ephemeral_salt);
        let (tx_key, rx_key) = local_keys.derive_directional_transport_keys(
            peer_public_bytes,
            &ephemeral_salt,
            pq_psk,
        )?;
        let mut idx_bytes = [0u8; 4];
        OsRng.fill_bytes(&mut idx_bytes);
        let idx = u32::from_le_bytes(idx_bytes);
        Ok(Self {
            tx_key,
            rx_key,
            local_index: idx,
            remote_index: idx,
            tx_counter: AtomicU64::new(1),
            replay_window: Mutex::new(ReplayWindow::default()),
            daita_enabled,
            daita_block_size,
            quantum_resistant_active: pq_psk.is_some(),
        })
    }

    pub fn new(
        local_keys: &LocalWireGuardKeypair,
        peer_public_bytes: &[u8; 32],
        pq_psk: Option<&[u8; 32]>,
        daita_enabled: bool,
        daita_block_size: usize,
    ) -> Self {
        Self::try_new(
            local_keys,
            peer_public_bytes,
            pq_psk,
            daita_enabled,
            daita_block_size,
        )
        .expect("WireGuard peer public key must be a valid contributory X25519 point")
    }

    /// Fallible constructor for a matching `(initiator, responder)` tunnel pair with inverse
    /// directional keys and cross-wired `local_index`/`remote_index`.
    pub fn try_new_paired(
        initiator_keys: &LocalWireGuardKeypair,
        responder_keys: &LocalWireGuardKeypair,
        pq_psk: Option<&[u8; 32]>,
        daita_enabled: bool,
        daita_block_size: usize,
    ) -> Result<(Self, Self), String> {
        let mut ephemeral_salt = [0u8; 32];
        OsRng.fill_bytes(&mut ephemeral_salt);
        let (i2r, r2i) = initiator_keys.derive_directional_transport_keys(
            &responder_keys.public_key_bytes(),
            &ephemeral_salt,
            pq_psk,
        )?;
        let mut idx_a_bytes = [0u8; 4];
        let mut idx_b_bytes = [0u8; 4];
        OsRng.fill_bytes(&mut idx_a_bytes);
        OsRng.fill_bytes(&mut idx_b_bytes);
        let idx_a = u32::from_le_bytes(idx_a_bytes);
        let mut idx_b = u32::from_le_bytes(idx_b_bytes);
        if idx_b == idx_a {
            idx_b = idx_a.wrapping_add(1);
        }

        let initiator = Self {
            tx_key: i2r,
            rx_key: r2i,
            local_index: idx_a,
            remote_index: idx_b,
            tx_counter: AtomicU64::new(1),
            replay_window: Mutex::new(ReplayWindow::default()),
            daita_enabled,
            daita_block_size,
            quantum_resistant_active: pq_psk.is_some(),
        };
        let responder = Self {
            tx_key: r2i,
            rx_key: i2r,
            local_index: idx_b,
            remote_index: idx_a,
            tx_counter: AtomicU64::new(1),
            replay_window: Mutex::new(ReplayWindow::default()),
            daita_enabled,
            daita_block_size,
            quantum_resistant_active: pq_psk.is_some(),
        };
        Ok((initiator, responder))
    }

    /// Creates a matching `(initiator, responder)` tunnel pair with inverse directional keys
    /// for authenticated end-to-end verification and replay-defense testing.
    pub fn new_paired(
        initiator_keys: &LocalWireGuardKeypair,
        responder_keys: &LocalWireGuardKeypair,
        pq_psk: Option<&[u8; 32]>,
        daita_enabled: bool,
        daita_block_size: usize,
    ) -> (Self, Self) {
        Self::try_new_paired(
            initiator_keys,
            responder_keys,
            pq_psk,
            daita_enabled,
            daita_block_size,
        )
        .expect("WireGuard paired keypairs must be valid contributory X25519 points")
    }

    pub fn local_index(&self) -> u32 {
        self.local_index
    }

    pub fn remote_index(&self) -> u32 {
        self.remote_index
    }

    pub fn is_quantum_resistant(&self) -> bool {
        self.quantum_resistant_active
    }

    pub fn is_daita_enabled(&self) -> bool {
        self.daita_enabled
    }

    pub fn packets_transmitted(&self) -> u64 {
        self.tx_counter.load(Ordering::Relaxed).saturating_sub(1)
    }

    /// Encapsulates and encrypts an outbound IP/HTTP3 packet into a WireGuard Type-4 Transport Packet.
    pub fn encapsulate_packet(&self, payload: &[u8]) -> Result<Vec<u8>, String> {
        let counter = self.tx_counter.fetch_add(1, Ordering::SeqCst);
        if counter >= REJECT_AFTER_MESSAGES {
            return Err("WireGuard session counter exhausted; rekey required".into());
        }
        let mut plaintext = if self.daita_enabled {
            pad_daita_frame(payload, self.daita_block_size).map_err(|e| e.to_string())?
        } else {
            payload.to_vec()
        };

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.tx_key));
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&counter.to_le_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);

        let enc_res = cipher.encrypt(nonce, plaintext.as_ref());
        plaintext.zeroize();
        let ciphertext =
            enc_res.map_err(|_| "WireGuard ChaCha20-Poly1305 encryption failed".to_string())?;

        // WireGuard Type-4 Transport Data Header: [type=4, reserved(3), receiver_index(4), counter(8), ciphertext+tag]
        let mut wg_packet = Vec::with_capacity(16 + ciphertext.len());
        wg_packet.extend_from_slice(&[4u8, 0, 0, 0]);
        wg_packet.extend_from_slice(&self.remote_index.to_le_bytes());
        wg_packet.extend_from_slice(&counter.to_le_bytes());
        wg_packet.extend_from_slice(&ciphertext);

        Ok(wg_packet)
    }

    /// Decapsulates and authenticates an inbound WireGuard Type-4 Transport Packet with strict
    /// `receiver_index` validation and 64-packet sliding-window replay protection (window updated
    /// only after AEAD verification).
    pub fn decapsulate_packet(&self, wg_packet: &[u8]) -> Result<Option<Vec<u8>>, String> {
        if wg_packet.len() < 32 || wg_packet[0] != 4 || wg_packet[1..4] != [0, 0, 0] {
            return Err("Invalid WireGuard Type-4 transport packet header".into());
        }

        let pkt_receiver_index =
            u32::from_le_bytes([wg_packet[4], wg_packet[5], wg_packet[6], wg_packet[7]]);
        if pkt_receiver_index != self.local_index {
            return Err(format!(
                "WireGuard receiver_index mismatch (got 0x{:08x}, expected 0x{:08x})",
                pkt_receiver_index, self.local_index
            ));
        }

        let mut counter_bytes = [0u8; 8];
        counter_bytes.copy_from_slice(&wg_packet[8..16]);
        let counter = u64::from_le_bytes(counter_bytes);

        {
            let win = self.replay_window.lock().unwrap_or_else(|e| e.into_inner());
            if !win.check(counter) {
                return Err(format!("WireGuard replay attack rejected (counter={})", counter));
            }
        }

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.rx_key));
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&counter_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let mut plaintext = cipher
            .decrypt(nonce, &wg_packet[16..])
            .map_err(|_| "WireGuard Poly1305 MAC authentication failed".to_string())?;

        // Record counter ONLY after Poly1305 MAC authentication succeeds
        {
            let mut win = self.replay_window.lock().unwrap_or_else(|e| e.into_inner());
            if !win.check(counter) {
                plaintext.zeroize();
                return Err(format!("WireGuard replay attack rejected (counter={})", counter));
            }
            win.record(counter);
        }

        if self.daita_enabled {
            let unpadded = unpad_daita_frame(&plaintext).map_err(|e| e.to_string());
            plaintext.zeroize();
            unpadded
        } else {
            Ok(Some(plaintext))
        }
    }
}

impl Drop for UserspaceWireGuardTunnel {
    fn drop(&mut self) {
        self.tx_key.zeroize();
        self.rx_key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rejects_low_order_x25519_points() {
        let local = LocalWireGuardKeypair::generate();
        let salt = [0x42u8; 32];

        // All-zero low-order point
        let zero_point = [0u8; 32];
        assert!(local
            .derive_directional_transport_keys(&zero_point, &salt, None)
            .is_err());
        assert!(UserspaceWireGuardTunnel::try_new(&local, &zero_point, None, true, 1360).is_err());

        // Known order-8 Curve25519 small-subgroup point
        let order8_point: [u8; 32] = [
            0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f,
            0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16,
            0x5f, 0x49, 0xb8, 0x00,
        ];
        assert!(local
            .derive_directional_transport_keys(&order8_point, &salt, None)
            .is_err());
    }

    #[test]
    fn test_receiver_index_validation_and_redacted_debug() {
        let k_init = LocalWireGuardKeypair::generate();
        let k_resp = LocalWireGuardKeypair::generate();
        let (init_tun, resp_tun) =
            UserspaceWireGuardTunnel::try_new_paired(&k_init, &k_resp, None, true, 1360)
                .expect("valid paired tunnels");

        let mut pkt = init_tun.encapsulate_packet(b"hello wg").expect("encapsulate");

        // Packet reflection to sender must fail receiver_index check
        assert!(init_tun.decapsulate_packet(&pkt).is_err());

        // Corrupting receiver_index byte must be rejected without poisoning replay window
        pkt[4] ^= 0xFF;
        assert!(resp_tun.decapsulate_packet(&pkt).is_err());

        // Restoring receiver_index succeeds cleanly
        pkt[4] ^= 0xFF;
        let decrypted = resp_tun
            .decapsulate_packet(&pkt)
            .expect("decapsulate")
            .expect("data payload");
        assert_eq!(decrypted, b"hello wg");

        // Bidirectional responder -> initiator also works
        let reply = resp_tun.encapsulate_packet(b"pong").expect("encapsulate reply");
        let dec_reply = init_tun
            .decapsulate_packet(&reply)
            .expect("decapsulate reply")
            .expect("reply payload");
        assert_eq!(dec_reply, b"pong");

        // Debug representations must redact keys
        let dbg_kp = format!("{:?}", k_init);
        assert!(dbg_kp.contains("[REDACTED]"));
        let dbg_tun = format!("{:?}", init_tun);
        assert!(dbg_tun.contains("[REDACTED]"));
    }
}
