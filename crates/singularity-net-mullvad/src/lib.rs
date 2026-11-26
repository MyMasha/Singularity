//! `singularity-net-mullvad` — Native Userspace WireGuard (`boringtun`), 16-Digit Mullvad Account
//! Client, DAITA Traffic-Analysis Defense, Atomic Socket-Layer Kill-Switch, Advanced Proxy Engine,
//! Split-Tunneling Router, and Pure-Rust Loopback SOCKS5h / HTTP CONNECT Proxy Bridge.

pub mod account;
pub mod daita;
pub mod killswitch;
pub mod proxy_bridge;
pub mod relays;
pub mod wireguard;

pub use account::{
    MullvadAccountError, MullvadAccountToken, MullvadDeviceAssignment,
    WireGuardDeviceRegistrationRequest,
};
pub use daita::{pad_daita_frame, synthesize_daita_cover_packet, unpad_daita_frame, DaitaError};
pub use killswitch::{AtomicSocketKillSwitch, KillSwitchBlockReason};
pub use proxy_bridge::{
    host_matches_pattern, is_onion_host, resolve_route_for_request, LoopbackBridgeStatus,
    LoopbackProxyBridge, ProxyBridgeError, ProxyMode, ProxyProfileConfig, ProxyScheme,
    RouteDecision, RouteSource, SplitTunnelPolicy, SplitTunnelRule, SplitTunnelTarget,
    TorOnionProxyConfig,
};
pub use relays::{
    builtin_mullvad_relays, filter_relays, MullvadDnsContentBlocker, MullvadWireGuardRelay,
    ObfuscationMode, RelayCapabilities, RelayFilterCriteria, RelayRouteSelection,
};
pub use wireguard::{LocalWireGuardKeypair, UserspaceWireGuardTunnel};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use rand_core::{OsRng, RngCore};
use std::collections::HashMap;
use std::net::Ipv4Addr;
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
    pub dns_blocker: MullvadDnsContentBlocker,
    pub obfuscation_mode: ObfuscationMode,
    pub proxy_configs: HashMap<String, ProxyProfileConfig>,
    pub split_tunnel_domain_rules: Vec<SplitTunnelRule>,
    pub container_relay_overrides: HashMap<String, String>,
    container_split_targets: HashMap<String, SplitTunnelTarget>,
    pub tor_onion_config: TorOnionProxyConfig,
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
        let mut proxy_configs = HashMap::new();
        proxy_configs.insert("default".to_string(), ProxyProfileConfig::direct());

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
            dns_blocker: MullvadDnsContentBlocker::default(),
            obfuscation_mode: ObfuscationMode::Auto,
            proxy_configs,
            split_tunnel_domain_rules: Vec::new(),
            container_relay_overrides: HashMap::new(),
            container_split_targets: HashMap::new(),
            tor_onion_config: TorOnionProxyConfig::default(),
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

    /// Removes a per-tab split-tunnel relay override.
    pub fn clear_tab_split_tunnel_relay(&mut self, tab_id: u64) -> Option<String> {
        self.per_tab_relay_overrides.remove(&tab_id)
    }

    pub fn per_tab_relay_overrides(&self) -> &HashMap<u64, String> {
        &self.per_tab_relay_overrides
    }

    /// Pins a container identity (e.g. `"work"`, `"banking"`) to a dedicated Mullvad exit relay.
    pub fn set_container_relay_override(
        &mut self,
        container_id: impl Into<String>,
        relay_hostname: impl Into<String>,
    ) {
        let cid = container_id.into();
        self.container_split_targets.remove(&cid);
        self.container_relay_overrides
            .insert(cid, relay_hostname.into());
    }

    pub fn clear_container_relay_override(&mut self, container_id: &str) -> Option<String> {
        self.container_relay_overrides.remove(container_id)
    }

    pub fn container_relay_overrides(&self) -> &HashMap<String, String> {
        &self.container_relay_overrides
    }

    /// Assigns an arbitrary [`SplitTunnelTarget`] (bypass, proxy profile, relay, or block) to a container.
    pub fn set_container_split_target(
        &mut self,
        container_id: impl Into<String>,
        target: SplitTunnelTarget,
    ) {
        let cid = container_id.into();
        match target {
            SplitTunnelTarget::ForceRelay(relay) => {
                self.container_split_targets.remove(&cid);
                self.container_relay_overrides.insert(cid, relay);
            }
            other => {
                self.container_relay_overrides.remove(&cid);
                self.container_split_targets.insert(cid, other);
            }
        }
    }

    pub fn clear_container_split_target(
        &mut self,
        container_id: &str,
    ) -> Option<SplitTunnelTarget> {
        if let Some(t) = self.container_split_targets.remove(container_id) {
            return Some(t);
        }
        self.container_relay_overrides
            .remove(container_id)
            .map(SplitTunnelTarget::ForceRelay)
    }

    pub fn add_split_tunnel_domain_rule(&mut self, rule: SplitTunnelRule) {
        self.split_tunnel_domain_rules.push(rule);
    }

    pub fn set_split_tunnel_domain_rules(&mut self, rules: Vec<SplitTunnelRule>) {
        self.split_tunnel_domain_rules = rules;
    }

    pub fn clear_split_tunnel_domain_rules(&mut self) {
        self.split_tunnel_domain_rules.clear();
    }

    pub fn split_tunnel_domain_rules(&self) -> &[SplitTunnelRule] {
        &self.split_tunnel_domain_rules
    }

    pub fn dns_blocker(&self) -> &MullvadDnsContentBlocker {
        &self.dns_blocker
    }

    pub fn set_dns_blocker(&mut self, blocker: MullvadDnsContentBlocker) {
        self.dns_blocker = blocker;
    }

    /// Returns the official Mullvad in-tunnel IPv4 DNS server corresponding to `self.dns_blocker`
    /// (`100.64.0.<bitmask>` when blockers are enabled, or `10.64.0.1` unfiltered).
    pub fn effective_in_tunnel_dns_ipv4(&self) -> Ipv4Addr {
        self.dns_blocker.in_tunnel_dns_ipv4()
    }

    pub fn obfuscation_mode(&self) -> ObfuscationMode {
        self.obfuscation_mode
    }

    pub fn set_obfuscation_mode(&mut self, mode: ObfuscationMode) {
        self.obfuscation_mode = mode;
    }

    pub fn proxy_configs(&self) -> &HashMap<String, ProxyProfileConfig> {
        &self.proxy_configs
    }

    pub fn set_proxy_config(
        &mut self,
        profile_name: impl Into<String>,
        config: ProxyProfileConfig,
    ) {
        self.proxy_configs.insert(profile_name.into(), config);
    }

    pub fn get_proxy_config(&self, profile_name: &str) -> Option<&ProxyProfileConfig> {
        self.proxy_configs.get(profile_name)
    }

    pub fn remove_proxy_config(&mut self, profile_name: &str) -> Option<ProxyProfileConfig> {
        self.proxy_configs.remove(profile_name)
    }

    pub fn tor_onion_config(&self) -> &TorOnionProxyConfig {
        &self.tor_onion_config
    }

    pub fn set_tor_onion_config(&mut self, config: TorOnionProxyConfig) {
        self.tor_onion_config = config;
    }

    /// Filters the built-in/loaded Mullvad relay catalog using [`RelayFilterCriteria`].
    pub fn filtered_relays(&self, criteria: &RelayFilterCriteria) -> Vec<MullvadWireGuardRelay> {
        filter_relays(&self.relays, criteria)
    }

    /// Builds a snapshot [`SplitTunnelPolicy`] reflecting this controller's active route,
    /// domain rules, container overrides, per-tab overrides, and Tor `.onion` config.
    pub fn split_tunnel_policy(&self) -> SplitTunnelPolicy {
        let mut container_rules = self.container_split_targets.clone();
        for (cid, relay) in &self.container_relay_overrides {
            container_rules.insert(cid.clone(), SplitTunnelTarget::ForceRelay(relay.clone()));
        }
        SplitTunnelPolicy {
            domain_rules: self.split_tunnel_domain_rules.clone(),
            container_rules,
            per_tab_relay_overrides: self.per_tab_relay_overrides.clone(),
            default_relay_hostname: Some(self.active_route.exit_relay.hostname.clone()),
            tor_onion_config: Some(self.tor_onion_config.clone()),
        }
    }

    /// Resolves the effective route for a request originating from `(tab_id, container_id)` to `host`.
    /// Immediately returns [`RouteDecision::Blocked`] if the emergency kill-switch lockdown is engaged.
    pub fn resolve_effective_route(
        &self,
        tab_id: Option<u64>,
        container_id: Option<&str>,
        host: &str,
    ) -> RouteDecision {
        if self.kill_switch.is_emergency_lockdown() {
            return RouteDecision::Blocked {
                reason: KillSwitchBlockReason::EmergencyLockdown.to_string(),
            };
        }
        self.split_tunnel_policy()
            .resolve_route_for_request(tab_id, container_id, host)
    }

    /// Creates a [`LoopbackProxyBridge`] pre-wired with this controller's atomic kill-switch,
    /// split-tunneling policy, Tor `.onion` config, and named proxy profiles.
    pub fn create_loopback_proxy_bridge(&self) -> LoopbackProxyBridge {
        LoopbackProxyBridge::new(
            Arc::clone(&self.kill_switch),
            self.split_tunnel_policy(),
            self.proxy_configs.clone(),
        )
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
    use std::io::{Read, Write};
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::thread;

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

    #[test]
    fn test_controller_dns_blocker_obfuscation_filters_and_split_tunneling() {
        let mut controller = MullvadVpnController::new();

        // DNS content blocker bitmask calculation
        assert_eq!(controller.effective_in_tunnel_dns_ipv4(), Ipv4Addr::new(10, 64, 0, 1));
        controller.set_dns_blocker(MullvadDnsContentBlocker {
            block_ads: true,
            block_trackers: true,
            block_malware: true,
            block_adult: false,
            block_gambling: true,
            block_social: false,
        });
        // 1 + 2 + 4 + 16 = 23 -> 100.64.0.23
        assert_eq!(controller.effective_in_tunnel_dns_ipv4(), Ipv4Addr::new(100, 64, 0, 23));

        // Obfuscation mode
        assert_eq!(controller.obfuscation_mode(), ObfuscationMode::Auto);
        controller.set_obfuscation_mode(ObfuscationMode::Udp2Tcp443);
        assert_eq!(controller.obfuscation_mode(), ObfuscationMode::Udp2Tcp443);
        assert_eq!(
            controller
                .active_route()
                .exit_relay
                .effective_port(controller.obfuscation_mode(), true),
            443
        );

        // Filtered relays across 19 global catalog entries
        let fast_owned = controller.filtered_relays(&RelayFilterCriteria {
            owned_only: true,
            daita_only: true,
            min_speed_gbps: Some(20),
            ..Default::default()
        });
        assert!(fast_owned.len() >= 6);
        assert!(fast_owned.iter().any(|r| r.hostname == "fr-par-wg-001"));
        assert!(fast_owned.iter().any(|r| r.hostname == "gb-lon-wg-002"));

        // Proxy profile storage & CIDR bypass
        controller.set_proxy_config(
            "corp",
            ProxyProfileConfig::manual(
                ProxyScheme::Https,
                "proxy.corp.example",
                8443,
                true,
                Some("jdoe".into()),
                Some("vault:corp-proxy-key".into()),
                vec!["192.168.0.0/16".into(), "*.corp.local".into(), "localhost".into()],
            ),
        );
        let corp = controller.get_proxy_config("corp").expect("corp proxy config");
        assert!(corp.should_bypass("192.168.12.34"));
        assert!(corp.should_bypass("wiki.corp.local"));
        assert!(!corp.should_bypass("github.com"));

        // Split-tunneling: domain -> tab -> container -> default relay
        controller.add_split_tunnel_domain_rule(SplitTunnelRule::bypass_direct("*.intranet.local"));
        controller.add_split_tunnel_domain_rule(SplitTunnelRule::force_relay("nhk.or.jp", "jp-tyo-wg-001"));
        controller.set_container_relay_override("eu-work", "fr-par-wg-001");
        controller.set_tab_split_tunnel_relay(101, "fi-hel-wg-001");

        assert!(matches!(
            controller.resolve_effective_route(Some(101), Some("eu-work"), "hr.intranet.local"),
            RouteDecision::BypassDirect { .. }
        ));
        assert_eq!(
            controller.resolve_effective_route(Some(101), Some("eu-work"), "www3.nhk.or.jp"),
            RouteDecision::MullvadRelay {
                relay_hostname: "jp-tyo-wg-001".into(),
                source: RouteSource::DomainRule,
            }
        );
        assert_eq!(
            controller.resolve_effective_route(Some(101), Some("eu-work"), "example.org"),
            RouteDecision::MullvadRelay {
                relay_hostname: "fi-hel-wg-001".into(),
                source: RouteSource::TabOverride,
            }
        );
        assert_eq!(
            controller.resolve_effective_route(Some(202), Some("eu-work"), "example.org"),
            RouteDecision::MullvadRelay {
                relay_hostname: "fr-par-wg-001".into(),
                source: RouteSource::ContainerRule,
            }
        );
        assert_eq!(
            controller.resolve_effective_route(None, None, "example.org"),
            RouteDecision::MullvadRelay {
                relay_hostname: "ch-zrh-wg-001".into(),
                source: RouteSource::DefaultTunnel,
            }
        );

        // Emergency lockdown overrides every route decision
        controller.kill_switch().set_emergency_lockdown(true);
        assert!(matches!(
            controller.resolve_effective_route(Some(101), Some("eu-work"), "hr.intranet.local"),
            RouteDecision::Blocked { .. }
        ));
    }

    #[test]
    fn test_controller_loopback_bridge_tor_onion_socks5h_chaining() {
        // Spawn a mock local Tor SOCKS5h daemon that records received RFC 1929 isolation key
        // and ATYP=0x03 `.onion` domain, then echoes bytes back.
        let mock_tor = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind mock tor");
        let mock_tor_port = mock_tor.local_addr().unwrap().port();

        let tor_handle = thread::spawn(move || {
            let (mut s, _) = mock_tor.accept().expect("accept bridge->tor");
            // Greeting
            let mut hdr = [0u8; 2];
            s.read_exact(&mut hdr).unwrap();
            assert_eq!(hdr[0], 0x05);
            let mut methods = vec![0u8; hdr[1] as usize];
            s.read_exact(&mut methods).unwrap();
            assert!(methods.contains(&0x02));
            s.write_all(&[0x05, 0x02]).unwrap();

            // RFC 1929 auth (Tor IsolateSOCKSAuth)
            let mut vu = [0u8; 2];
            s.read_exact(&mut vu).unwrap();
            assert_eq!(vu[0], 0x01);
            let mut uname = vec![0u8; vu[1] as usize];
            s.read_exact(&mut uname).unwrap();
            let mut pl = [0u8; 1];
            s.read_exact(&mut pl).unwrap();
            let mut pass = vec![0u8; pl[0] as usize];
            s.read_exact(&mut pass).unwrap();
            s.write_all(&[0x01, 0x00]).unwrap();

            let iso_user = String::from_utf8(uname).unwrap();
            assert_eq!(iso_user, "singularity-onion:c=research:t=77");

            // CONNECT request MUST carry ATYP=0x03 with the raw `.onion` hostname (zero local DNS leak)
            let mut req_hdr = [0u8; 4];
            s.read_exact(&mut req_hdr).unwrap();
            assert_eq!(req_hdr, [0x05, 0x01, 0x00, 0x03]);
            let mut dlen = [0u8; 1];
            s.read_exact(&mut dlen).unwrap();
            let mut dom = vec![0u8; dlen[0] as usize];
            s.read_exact(&mut dom).unwrap();
            let mut pbuf = [0u8; 2];
            s.read_exact(&mut pbuf).unwrap();
            assert_eq!(String::from_utf8(dom).unwrap(), "singularitytestv3address.onion");
            assert_eq!(u16::from_be_bytes(pbuf), 80);

            // Reply success and echo payload
            s.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x23, 0x5a])
                .unwrap();
            let mut buf = [0u8; 1024];
            while let Ok(n) = s.read(&mut buf) {
                if n == 0 {
                    break;
                }
                s.write_all(&buf[..n]).unwrap();
            }
        });

        let mut controller = MullvadVpnController::new();
        controller
            .authenticate_16_digit_account("1111 2222 3333 4444")
            .unwrap();
        controller.connect_tunnel(true, true).unwrap();
        controller.set_tor_onion_config(TorOnionProxyConfig::enabled_local(mock_tor_port));

        let mut bridge = controller.create_loopback_proxy_bridge();
        let bridge_port = bridge.start().expect("start loopback bridge");

        let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, bridge_port)).unwrap();
        client.write_all(&[0x05, 0x01, 0x02]).unwrap();
        let mut m = [0u8; 2];
        client.read_exact(&mut m).unwrap();
        assert_eq!(m, [0x05, 0x02]);

        let scoped_user = bridge.format_scoped_username(Some(77), Some("research"));
        let mut auth = vec![0x01, scoped_user.len() as u8];
        auth.extend_from_slice(scoped_user.as_bytes());
        auth.push(bridge.session_token().len() as u8);
        auth.extend_from_slice(bridge.session_token().as_bytes());
        client.write_all(&auth).unwrap();
        let mut aresp = [0u8; 2];
        client.read_exact(&mut aresp).unwrap();
        assert_eq!(aresp, [0x01, 0x00]);

        let onion = b"singularitytestv3address.onion";
        let mut req = vec![0x05, 0x01, 0x00, 0x03, onion.len() as u8];
        req.extend_from_slice(onion);
        req.extend_from_slice(&80u16.to_be_bytes());
        client.write_all(&req).unwrap();

        let mut rep = [0u8; 10];
        client.read_exact(&mut rep).unwrap();
        assert_eq!(rep[0], 0x05);
        assert_eq!(rep[1], 0x00, "Expected Tor .onion SOCKS5h chaining success");

        let payload = b"GET / HTTP/1.1\r\nHost: singularitytestv3address.onion\r\n\r\n";
        client.write_all(payload).unwrap();
        client.shutdown(Shutdown::Write).unwrap();

        let mut echoed = Vec::new();
        client.read_to_end(&mut echoed).unwrap();
        assert_eq!(echoed, payload);

        tor_handle.join().expect("mock tor exited cleanly");
        let snap = bridge.snapshot();
        assert!(snap.running);
        assert_eq!(snap.port, Some(bridge_port));
        assert!(snap.tor_onion_enabled);
        assert!(snap.bytes_sent >= payload.len() as u64);
        assert!(snap.bytes_received >= payload.len() as u64);
        bridge.stop();
        assert!(!bridge.is_running());
    }
}
