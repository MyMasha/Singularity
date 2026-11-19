//! `singularity-net-mullvad` — Native Userspace WireGuard (`boringtun`), 16-Digit Mullvad Account
//! Client, DAITA Traffic-Analysis Defense, and Atomic Socket-Layer Kill-Switch.

pub mod account;
pub mod daita;
pub mod killswitch;
pub mod relays;
pub mod wireguard;

pub use account::{
    MullvadAccountError, MullvadAccountToken, MullvadDeviceAssignment,
    WireGuardDeviceRegistrationRequest,
};
pub use daita::{pad_daita_frame, synthesize_daita_cover_packet, unpad_daita_frame, DaitaError};
pub use killswitch::{AtomicSocketKillSwitch, KillSwitchBlockReason};
pub use relays::{builtin_mullvad_relays, MullvadWireGuardRelay, RelayRouteSelection};
pub use wireguard::{LocalWireGuardKeypair, UserspaceWireGuardTunnel};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use rand_core::{OsRng, RngCore};
use std::collections::HashMap;
use std::sync::Arc;
use zeroize::Zeroize;

/// High-level Mullvad VPN & Userspace WireGuard Controller wired into the Singularity toolbar.
pub struct MullvadVpnController {
    account: Option<MullvadAccountToken>,
    local_keypair: LocalWireGuardKeypair,
    device_assignment: Option<MullvadDeviceAssignment>,
    relays: Vec<MullvadWireGuardRelay>,
    active_route: RelayRouteSelection,
    tunnel: Option<UserspaceWireGuardTunnel>,
    kill_switch: Arc<AtomicSocketKillSwitch>,
    per_tab_relay_overrides: HashMap<u64, String>,
    real_os_tunnel_active: bool,
}

impl Default for MullvadVpnController {
    fn default() -> Self {
        Self::new()
    }
}

impl MullvadVpnController {
    pub fn new() -> Self {
        let relays = builtin_mullvad_relays();
        let entry_relay = relays[0].clone(); // se-got-wg-001
        let exit_relay = relays[2].clone(); // ch-zrh-wg-001
        Self {
            account: None,
            local_keypair: LocalWireGuardKeypair::generate(),
            device_assignment: None,
            relays,
            active_route: RelayRouteSelection {
                multihop_enabled: true,
                entry_relay,
                exit_relay,
            },
            tunnel: None,
            kill_switch: Arc::new(AtomicSocketKillSwitch::new(true, true)),
            per_tab_relay_overrides: HashMap::new(),
            real_os_tunnel_active: false,
        }
    }

    /// Authenticates locally via the user's 16-digit Mullvad Account Number, generates a fresh
    /// local Curve25519 keypair, and prepares the local crypto sandbox assignment.
    /// Note: Real Mullvad API registration requires an external OS WireGuard daemon or TUN socket.
    pub fn authenticate_16_digit_account(
        &mut self,
        raw_16_digit_account: &str,
    ) -> Result<MullvadDeviceAssignment, MullvadAccountError> {
        let token = MullvadAccountToken::parse(raw_16_digit_account)?;
        self.local_keypair = LocalWireGuardKeypair::generate();
        let pubkey_b64 = self.local_keypair.public_key_base64();

        let assignment = MullvadDeviceAssignment {
            device_name: "Singularity Local WireGuard Crypto Engine".into(),
            pubkey_base64: pubkey_b64,
            ipv4_address: "Local simulation (no OS tunnel active)".into(),
            ipv6_address: "Local simulation (no OS tunnel active)".into(),
            in_tunnel_dns_v4: "System DNS (OS tunnel not established)".into(),
            socks5_exit_proxy: "Disconnected".into(),
        };

        self.account = Some(token);
        self.device_assignment = Some(assignment.clone());
        Ok(assignment)
    }

    /// Initializes the local userspace WireGuard cryptographic engine using the selected relay's
    /// decoded Curve25519 public key and a CSPRNG ephemeral PQ-PSK.
    /// Does NOT claim a live OS/TUN VPN tunnel is routing WebView2 traffic (`real_os_tunnel_active` stays `false`).
    pub fn connect_tunnel(&mut self, enable_pq_psk: bool, enable_daita: bool) -> Result<(), String> {
        if self.account.is_none() {
            return Err("Cannot establish Mullvad tunnel without valid 16-digit account number".into());
        }

        let peer_pub_vec = BASE64
            .decode(&self.active_route.exit_relay.public_key_base64)
            .map_err(|_| "Selected relay has invalid Base64 public key".to_string())?;
        let peer_pub: [u8; 32] = peer_pub_vec
            .try_into()
            .map_err(|_| "Selected relay public key is not 32 bytes".to_string())?;

        let mut pq_psk = if enable_pq_psk {
            let mut key = [0u8; 32];
            OsRng.fill_bytes(&mut key);
            Some(key)
        } else {
            None
        };

        let tunnel = UserspaceWireGuardTunnel::new(
            &self.local_keypair,
            &peer_pub,
            pq_psk.as_ref(),
            enable_daita,
            1360,
        );
        if let Some(ref mut psk) = pq_psk {
            psk.zeroize();
        }

        self.tunnel = Some(tunnel);
        self.real_os_tunnel_active = false;
        self.kill_switch.set_tunnel_established(true);
        Ok(())
    }

    /// Drops the WireGuard tunnel and immediately engages the atomic socket kill-switch.
    pub fn disconnect_and_engage_killswitch(&mut self) {
        self.kill_switch.set_tunnel_established(false);
        self.real_os_tunnel_active = false;
        self.tunnel = None;
    }

    /// 1-click toolbar country/city/multihop server switcher.
    pub fn switch_relay_route(
        &mut self,
        entry_hostname: &str,
        exit_hostname: &str,
        multihop: bool,
    ) -> Result<&RelayRouteSelection, String> {
        let entry = self
            .relays
            .iter()
            .find(|r| r.hostname == entry_hostname)
            .ok_or_else(|| format!("Entry relay '{}' not found in Mullvad catalog", entry_hostname))?
            .clone();
        let exit = self
            .relays
            .iter()
            .find(|r| r.hostname == exit_hostname)
            .ok_or_else(|| format!("Exit relay '{}' not found in Mullvad catalog", exit_hostname))?
            .clone();

        self.active_route = RelayRouteSelection {
            multihop_enabled: multihop,
            entry_relay: entry,
            exit_relay: exit,
        };

        if let Some(t) = &self.tunnel {
            let pq = t.is_quantum_resistant();
            let daita = t.is_daita_enabled();
            self.connect_tunnel(pq, daita)?;
        }

        Ok(&self.active_route)
    }

    /// Pins a specific browser tab ID to a dedicated Mullvad exit relay hostname.
    pub fn set_tab_split_tunnel_relay(&mut self, tab_id: u64, relay_hostname: &str) {
        self.per_tab_relay_overrides
            .insert(tab_id, relay_hostname.to_string());
    }

    /// Sends a browser packet through the strict kill-switch and WireGuard DAITA tunnel.
    pub fn transmit_browser_packet(
        &self,
        destination_host: &str,
        raw_packet: &[u8],
    ) -> Result<Vec<u8>, String> {
        self.kill_switch
            .authorize_outbound_packet(destination_host)
            .map_err(|e| e.to_string())?;

        let tunnel = self
            .tunnel
            .as_ref()
            .ok_or_else(|| "WireGuard tunnel unavailable".to_string())?;
        tunnel.encapsulate_packet(raw_packet)
    }

    pub fn kill_switch(&self) -> &Arc<AtomicSocketKillSwitch> {
        &self.kill_switch
    }

    pub fn active_route(&self) -> &RelayRouteSelection {
        &self.active_route
    }

    pub fn available_relays(&self) -> &[MullvadWireGuardRelay] {
        &self.relays
    }

    pub fn local_public_key_base64(&self) -> String {
        self.local_keypair.public_key_base64()
    }

    pub fn is_authenticated(&self) -> bool {
        self.account.is_some()
    }

    pub fn masked_account(&self) -> Option<String> {
        self.account.as_ref().map(|a| a.masked_display())
    }

    /// Returns true when the local WireGuard cryptographic engine is initialized.
    pub fn is_tunnel_connected(&self) -> bool {
        self.tunnel.is_some() && self.kill_switch.is_tunnel_established()
    }

    /// Explicitly reports whether a live OS/TUN WireGuard interface is actually routing system traffic.
    pub fn is_real_os_tunnel_active(&self) -> bool {
        self.real_os_tunnel_active
    }

    pub fn device_assignment(&self) -> Option<&MullvadDeviceAssignment> {
        self.device_assignment.as_ref()
    }

    pub fn logout(&mut self) {
        self.kill_switch.set_tunnel_established(false);
        self.real_os_tunnel_active = false;
        self.tunnel = None;
        self.device_assignment = None;
        self.account = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_16_digit_mullvad_account_validation() {
        assert!(MullvadAccountToken::parse("1234 5678 9012 3456").is_ok());
        assert!(MullvadAccountToken::parse("1234-5678-9012-3456").is_ok());
        assert_eq!(
            MullvadAccountToken::parse("12345"),
            Err(MullvadAccountError::InvalidDigitLength(5))
        );
        assert_eq!(
            MullvadAccountToken::parse("123456789012345a"),
            Err(MullvadAccountError::NonNumericCharacter('a'))
        );
        assert_eq!(
            MullvadAccountToken::parse("0000000000000000"),
            Err(MullvadAccountError::AllZeroAccountNumber)
        );
    }

    #[test]
    fn test_strict_kill_switch_and_wireguard_daita_tunnel() {
        let mut controller = MullvadVpnController::new();

        // Before connecting tunnel, strict kill-switch MUST block all packets
        let blocked = controller.transmit_browser_packet("example.com", b"GET / HTTP/3");
        assert!(blocked.is_err());
        assert_eq!(controller.kill_switch().dropped_packets(), 1);

        // Verify extended RFC1918, CGNAT, IPv6, and obfuscated IPv4 blocking
        for local_target in [
            "10.255.0.1",
            "172.17.0.1",
            "172.31.255.254",
            "0.0.0.0",
            "100.64.0.1",
            "::1",
            "[::1]",
            "fe80::1",
            "fc00::1",
            "::ffff:127.0.0.1",
            "2130706433",
            "0x7f000001",
            "0177.0.0.1",
            "127.1",
            "localhost.",
        ] {
            assert_eq!(
                controller.kill_switch().authorize_outbound_packet(local_target),
                Err(KillSwitchBlockReason::LanAccessBlocked),
                "Failed to block local target {}",
                local_target
            );
        }

        // Authenticate with 16-digit Mullvad account and initialize PQ+DAITA local crypto engine
        controller
            .authenticate_16_digit_account("9876 5432 1098 7654")
            .expect("Valid 16-digit account");
        controller
            .connect_tunnel(true, true)
            .expect("Connect WireGuard tunnel");
        assert!(!controller.is_real_os_tunnel_active());

        // Switch multihop route: Sweden (se-got-wg-001) -> Iceland (is-rek-wg-001)
        controller
            .switch_relay_route("se-got-wg-001", "is-rek-wg-001", true)
            .expect("Switch multihop route");
        assert!(controller
            .active_route()
            .toolbar_badge_label()
            .contains("SE (se-got-wg-001) ➔ IS (is-rek-wg-001)"));

        // Transmit packet: DAITA pads to constant 1360 bytes + 16B WG header + 16B Poly1305 tag = 1392 bytes
        let encrypted_wg = controller
            .transmit_browser_packet("mullvad.net", b"GET / HTTP/3")
            .expect("Encrypted WG packet");
        assert_eq!(encrypted_wg.len(), 1360 + 16 + 16);

        // Verify paired directional transport & strict anti-replay protection
        let k_init = LocalWireGuardKeypair::generate();
        let k_resp = LocalWireGuardKeypair::generate();
        let (init_tun, resp_tun) =
            UserspaceWireGuardTunnel::new_paired(&k_init, &k_resp, None, true, 1360);
        let pkt = init_tun.encapsulate_packet(b"GET / HTTP/3").expect("Encapsulate");
        let dec = resp_tun
            .decapsulate_packet(&pkt)
            .expect("Decapsulate")
            .expect("Data frame");
        assert_eq!(dec, b"GET / HTTP/3");
        // Replaying the identical packet MUST be rejected
        assert!(resp_tun.decapsulate_packet(&pkt).is_err());

        // Disconnect tunnel -> kill-switch immediately drops subsequent packets
        controller.disconnect_and_engage_killswitch();
        assert!(controller
            .transmit_browser_packet("mullvad.net", b"GET / HTTP/3")
            .is_err());
    }
}
