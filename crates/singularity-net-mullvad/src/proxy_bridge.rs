//! Complete Proxy Profile Engine (HTTP / HTTPS / SOCKS4 / SOCKS5 / SOCKS5h / PAC / NO_PROXY),
//! Tab / Container / Domain Split-Tunneling Router, Tor `.onion` Isolation Config,
//! and Pure-Rust Loopback TCP Proxy Bridge (`127.0.0.1:0` — SOCKS5 RFC 1928 + RFC 1929 & HTTP CONNECT).

use crate::killswitch::{parse_any_ip_representation, AtomicSocketKillSwitch};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_HTTP_HEADER_BYTES: usize = 16 * 1024;
const MAX_CONCURRENT_CONNECTIONS: usize = 256;

fn default_true() -> bool {
    true
}

/// Supported manual proxy transport schemes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProxyScheme {
    Http,
    Https,
    Socks4,
    Socks5,
    Socks5h,
}

impl ProxyScheme {
    pub fn as_scheme_str(&self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
            Self::Socks4 => "socks4",
            Self::Socks5 => "socks5",
            Self::Socks5h => "socks5h",
        }
    }

    /// Returns the Chromium/CEF `fixed_servers` server URI scheme.
    pub fn cef_server_scheme(&self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
            Self::Socks4 => "socks4",
            Self::Socks5 | Self::Socks5h => "socks5",
        }
    }

    /// Returns `true` if DNS resolution is performed remotely by the proxy by default.
    pub fn is_remote_dns_default(&self) -> bool {
        matches!(self, Self::Http | Self::Https | Self::Socks5h)
    }
}

/// Proxy resolution mode for a Singularity profile or container.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ProxyMode {
    /// Direct connection without an external proxy.
    #[default]
    Direct,
    /// Inherit operating-system proxy settings.
    System,
    /// Explicit manual proxy endpoint (passwords are referenced via opaque vault IDs only).
    Manual {
        scheme: ProxyScheme,
        host: String,
        port: u16,
        remote_dns: bool,
        username: Option<String>,
        encrypted_password_ref: Option<String>,
    },
    /// Proxy Auto-Configuration (PAC) JavaScript URL with optional offline cached script.
    PacScript {
        url: String,
        cached_script: Option<String>,
    },
}

/// Complete proxy profile configuration including `NO_PROXY` / CIDR / wildcard bypass rules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyProfileConfig {
    pub mode: ProxyMode,
    #[serde(default)]
    pub bypass_list: Vec<String>,
}

impl Default for ProxyProfileConfig {
    fn default() -> Self {
        Self::direct()
    }
}

impl ProxyProfileConfig {
    pub fn direct() -> Self {
        Self {
            mode: ProxyMode::Direct,
            bypass_list: default_local_bypass_list(),
        }
    }

    pub fn system() -> Self {
        Self {
            mode: ProxyMode::System,
            bypass_list: default_local_bypass_list(),
        }
    }

    pub fn manual(
        scheme: ProxyScheme,
        host: impl Into<String>,
        port: u16,
        remote_dns: bool,
        username: Option<String>,
        encrypted_password_ref: Option<String>,
        bypass_list: Vec<String>,
    ) -> Self {
        Self {
            mode: ProxyMode::Manual {
                scheme,
                host: host.into(),
                port,
                remote_dns,
                username,
                encrypted_password_ref,
            },
            bypass_list,
        }
    }

    pub fn pac(url: impl Into<String>, cached_script: Option<String>) -> Self {
        Self {
            mode: ProxyMode::PacScript {
                url: url.into(),
                cached_script,
            },
            bypass_list: Vec::new(),
        }
    }

    /// Evaluates whether `host` matches any entry in `bypass_list`
    /// (supports exact domains, wildcards `*.local`, CIDR IPv4/IPv6 `192.168.0.0/16`, `localhost`, `<local>`).
    pub fn should_bypass(&self, host: &str) -> bool {
        self.bypass_list
            .iter()
            .any(|rule| host_matches_pattern(host, rule))
    }

    /// Serializes this proxy configuration into Chromium/CEF `proxy` preference JSON
    /// (`CefRequestContext::SetPreference("proxy", ...)`). Never embeds password material or vault refs.
    pub fn to_cef_proxy_pref_json(&self) -> String {
        match &self.mode {
            ProxyMode::Direct => r#"{"mode":"direct"}"#.to_string(),
            ProxyMode::System => r#"{"mode":"system"}"#.to_string(),
            ProxyMode::PacScript { url, cached_script } => {
                let effective_url = if !url.trim().is_empty() {
                    url.trim().to_string()
                } else if let Some(script) = cached_script {
                    format!(
                        "data:application/x-ns-proxy-autoconfig;base64,{}",
                        BASE64.encode(script.as_bytes())
                    )
                } else {
                    String::new()
                };
                let mandatory = !effective_url.is_empty();
                format!(
                    r#"{{"mode":"pac_script","pac_url":"{}","pac_mandatory":{}}}"#,
                    escape_json_str(&effective_url),
                    mandatory
                )
            }
            ProxyMode::Manual {
                scheme,
                host,
                port,
                remote_dns,
                ..
            } => {
                let formatted_host = format_host_for_uri(host);
                let server = format!("{}://{}:{}", scheme.cef_server_scheme(), formatted_host, port);
                let bypass = self.bypass_list.join(";");
                let effective_remote_dns = *remote_dns || *scheme == ProxyScheme::Socks5h;
                format!(
                    r#"{{"mode":"fixed_servers","server":"{}","bypass_list":"{}","scheme":"{}","remote_dns":{}}}"#,
                    escape_json_str(&server),
                    escape_json_str(&bypass),
                    scheme.as_scheme_str(),
                    effective_remote_dns
                )
            }
        }
    }
}

fn default_local_bypass_list() -> Vec<String> {
    vec![
        "localhost".into(),
        "127.0.0.1".into(),
        "::1".into(),
        "*.local".into(),
    ]
}

/// Dedicated Tor `.onion` hidden-service SOCKS5h routing configuration with per-tab/container
/// circuit isolation (Tor `IsolateSOCKSAuth` over RFC 1929).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TorOnionProxyConfig {
    pub enabled: bool,
    pub socks5h_host: String,
    pub socks5h_port: u16,
    /// Fail-closed protection: reject `.onion` requests when Tor routing is disabled so
    /// `.onion` domains never leak to clearnet DNS resolvers.
    #[serde(default = "default_true")]
    pub block_onion_when_disabled: bool,
    /// Assign distinct RFC 1929 credentials per `(container_id, tab_id)` for Tor stream isolation.
    #[serde(default = "default_true")]
    pub isolate_by_container_and_tab: bool,
}

impl Default for TorOnionProxyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            socks5h_host: "127.0.0.1".into(),
            socks5h_port: 9050,
            block_onion_when_disabled: true,
            isolate_by_container_and_tab: true,
        }
    }
}

impl TorOnionProxyConfig {
    /// Creates an enabled local Tor SOCKS5h configuration (default Tor daemon port `9050`).
    pub fn enabled_local(port: u16) -> Self {
        Self {
            enabled: true,
            socks5h_host: "127.0.0.1".into(),
            socks5h_port: port,
            block_onion_when_disabled: true,
            isolate_by_container_and_tab: true,
        }
    }

    /// Computes a deterministic stream-isolation credential for Tor `IsolateSOCKSAuth`.
    pub fn stream_isolation_key(&self, tab_id: Option<u64>, container_id: Option<&str>) -> String {
        if !self.isolate_by_container_and_tab {
            return "singularity-onion:shared".to_string();
        }
        let c = container_id
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("default");
        match tab_id {
            Some(tid) => format!("singularity-onion:c={}:t={}", c, tid),
            None => format!("singularity-onion:c={}", c),
        }
    }

    /// Exports this Tor config as a strict `ProxyProfileConfig` (`socks5h`, `remote_dns: true`, empty bypass list).
    pub fn to_proxy_profile_config(&self, isolation_user: Option<&str>) -> ProxyProfileConfig {
        ProxyProfileConfig {
            mode: ProxyMode::Manual {
                scheme: ProxyScheme::Socks5h,
                host: self.socks5h_host.clone(),
                port: self.socks5h_port,
                remote_dns: true,
                username: isolation_user.map(|s| s.to_string()),
                encrypted_password_ref: None,
            },
            bypass_list: Vec::new(),
        }
    }
}

/// Returns `true` if `host` is a `.onion` hidden-service hostname (RFC 7686).
pub fn is_onion_host(host: &str) -> bool {
    let (clean_host, _) = split_host_and_port(host);
    let normalized = clean_host.trim_end_matches('.').to_ascii_lowercase();
    normalized.len() > ".onion".len() && normalized.ends_with(".onion")
}

/// Target routing action for split-tunneling rules (domain, container, or tab).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SplitTunnelTarget {
    /// Bypass the VPN tunnel and connect directly (still subject to kill-switch emergency lockdown / LAN policy).
    BypassDirect,
    /// Pin matching traffic to a specific Mullvad WireGuard relay hostname (e.g. `"ch-zrh-wg-001"`).
    ForceRelay(String),
    /// Route matching traffic through a named [`ProxyProfileConfig`].
    UseProxyProfile(String),
    /// Explicitly block matching traffic regardless of tunnel state.
    Block,
}

/// Domain/IP/CIDR split-tunneling rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitTunnelRule {
    /// Domain, wildcard (`*.example.com`, `*.local`), IP, or CIDR (`192.168.0.0/16`).
    pub pattern: String,
    pub target: SplitTunnelTarget,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub note: Option<String>,
}

impl SplitTunnelRule {
    pub fn bypass_direct(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            target: SplitTunnelTarget::BypassDirect,
            enabled: true,
            note: None,
        }
    }

    pub fn force_relay(pattern: impl Into<String>, relay_hostname: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            target: SplitTunnelTarget::ForceRelay(relay_hostname.into()),
            enabled: true,
            note: None,
        }
    }

    pub fn use_proxy_profile(pattern: impl Into<String>, profile_name: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            target: SplitTunnelTarget::UseProxyProfile(profile_name.into()),
            enabled: true,
            note: None,
        }
    }

    pub fn block(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            target: SplitTunnelTarget::Block,
            enabled: true,
            note: None,
        }
    }

    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }

    pub fn matches_host(&self, host: &str) -> bool {
        self.enabled && host_matches_pattern(host, &self.pattern)
    }
}

/// Indicates which routing layer produced a [`RouteDecision`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RouteSource {
    TorOnionIsolation,
    DomainRule,
    TabOverride,
    ContainerRule,
    DefaultTunnel,
}

/// Effective routing decision for a browser/socket request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RouteDecision {
    BypassDirect {
        reason: String,
    },
    MullvadRelay {
        relay_hostname: String,
        source: RouteSource,
    },
    ProxyProfile {
        profile_name: String,
        source: RouteSource,
    },
    TorOnionSocks5h {
        socks5h_host: String,
        socks5h_port: u16,
        stream_isolation_key: String,
    },
    Blocked {
        reason: String,
    },
}

/// Aggregated split-tunneling policy combining domain rules, container rules, per-tab overrides,
/// default relay fallback, and optional Tor `.onion` isolation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitTunnelPolicy {
    #[serde(default)]
    pub domain_rules: Vec<SplitTunnelRule>,
    #[serde(default)]
    pub container_rules: HashMap<String, SplitTunnelTarget>,
    #[serde(default)]
    pub per_tab_relay_overrides: HashMap<u64, String>,
    #[serde(default)]
    pub default_relay_hostname: Option<String>,
    #[serde(default)]
    pub tor_onion_config: Option<TorOnionProxyConfig>,
}

impl SplitTunnelPolicy {
    /// Resolves the effective route for a request using deterministic precedence:
    /// 1. `.onion` isolation (Tor SOCKS5h or fail-closed block)
    /// 2. Domain split-tunnel rules
    /// 3. Per-tab relay overrides
    /// 4. Per-container rules
    /// 5. Default Mullvad relay (or direct if none configured)
    pub fn resolve_route_for_request(
        &self,
        tab_id: Option<u64>,
        container_id: Option<&str>,
        host: &str,
    ) -> RouteDecision {
        resolve_route_for_request(
            tab_id,
            container_id,
            host,
            &self.domain_rules,
            &self.container_rules,
            &self.per_tab_relay_overrides,
            self.default_relay_hostname.as_deref(),
            self.tor_onion_config.as_ref(),
        )
    }
}

/// Pure function resolving the effective route for `(tab_id, container_id, host)`.
#[allow(clippy::too_many_arguments)]
pub fn resolve_route_for_request(
    tab_id: Option<u64>,
    container_id: Option<&str>,
    host: &str,
    domain_rules: &[SplitTunnelRule],
    container_rules: &HashMap<String, SplitTunnelTarget>,
    per_tab_relay_overrides: &HashMap<u64, String>,
    default_relay_hostname: Option<&str>,
    tor_onion_config: Option<&TorOnionProxyConfig>,
) -> RouteDecision {
    // 1. Strict `.onion` hidden-service isolation
    if is_onion_host(host) {
        if let Some(tor_cfg) = tor_onion_config {
            if tor_cfg.enabled {
                return RouteDecision::TorOnionSocks5h {
                    socks5h_host: tor_cfg.socks5h_host.clone(),
                    socks5h_port: tor_cfg.socks5h_port,
                    stream_isolation_key: tor_cfg.stream_isolation_key(tab_id, container_id),
                };
            } else if tor_cfg.block_onion_when_disabled {
                return RouteDecision::Blocked {
                    reason: "Tor .onion routing is disabled (fail-closed to prevent clearnet DNS leak)".into(),
                };
            }
        }
    }

    // 2. Domain-level split-tunnel rules (first matching enabled rule wins)
    for rule in domain_rules {
        if rule.matches_host(host) {
            return target_to_decision(
                &rule.target,
                RouteSource::DomainRule,
                format!("Matched domain rule '{}'", rule.pattern),
            );
        }
    }

    // 3. Per-tab relay override
    if let Some(tid) = tab_id {
        if let Some(relay_hostname) = per_tab_relay_overrides.get(&tid) {
            return RouteDecision::MullvadRelay {
                relay_hostname: relay_hostname.clone(),
                source: RouteSource::TabOverride,
            };
        }
    }

    // 4. Per-container split-tunnel target
    if let Some(cid) = container_id {
        if let Some(target) = container_rules.get(cid) {
            return target_to_decision(
                target,
                RouteSource::ContainerRule,
                format!("Matched container '{}' rule", cid),
            );
        }
    }

    // 5. Default active Mullvad relay or direct fallback
    if let Some(default_relay) = default_relay_hostname {
        RouteDecision::MullvadRelay {
            relay_hostname: default_relay.to_string(),
            source: RouteSource::DefaultTunnel,
        }
    } else {
        RouteDecision::BypassDirect {
            reason: "No default Mullvad relay configured".into(),
        }
    }
}

fn target_to_decision(
    target: &SplitTunnelTarget,
    source: RouteSource,
    reason: String,
) -> RouteDecision {
    match target {
        SplitTunnelTarget::BypassDirect => RouteDecision::BypassDirect { reason },
        SplitTunnelTarget::ForceRelay(relay) => RouteDecision::MullvadRelay {
            relay_hostname: relay.clone(),
            source,
        },
        SplitTunnelTarget::UseProxyProfile(profile) => RouteDecision::ProxyProfile {
            profile_name: profile.clone(),
            source,
        },
        SplitTunnelTarget::Block => RouteDecision::Blocked { reason },
    }
}

/// Errors returned by [`LoopbackProxyBridge`].
#[derive(Debug, Error)]
pub enum ProxyBridgeError {
    #[error("Failed to bind loopback proxy listener: {0}")]
    BindFailed(#[from] io::Error),
    #[error("Loopback proxy bridge refuses non-loopback bind address")]
    NonLoopbackBindForbidden,
}

/// Serializable live telemetry snapshot of [`LoopbackProxyBridge`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoopbackBridgeStatus {
    pub running: bool,
    pub port: Option<u16>,
    pub require_auth: bool,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub active_connections: usize,
    pub total_connections: u64,
    pub blocked_requests: u64,
    pub auth_failures: u64,
    pub tor_onion_enabled: bool,
}

/// Zeroize-on-drop wrapper for the loopback bridge's ephemeral RFC 1929 / Basic session token.
#[derive(Zeroize, ZeroizeOnDrop)]
struct SessionToken(String);

impl SessionToken {
    fn generate() -> Self {
        let mut raw = [0u8; 24];
        OsRng.fill_bytes(&mut raw);
        let encoded = BASE64.encode(raw);
        raw.zeroize();
        Self(encoded)
    }

    fn as_str(&self) -> &str {
        &self.0
    }

    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

struct BridgeSharedState {
    kill_switch: Arc<AtomicSocketKillSwitch>,
    policy: RwLock<SplitTunnelPolicy>,
    proxy_profiles: RwLock<HashMap<String, ProxyProfileConfig>>,
    upstream_vpn_socks5: RwLock<Option<SocketAddr>>,
    session_username: String,
    session_token: SessionToken,
    require_auth: bool,
    running: AtomicBool,
    bound_port: AtomicU16,
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    active_connections: AtomicUsize,
    total_connections: AtomicU64,
    blocked_requests: AtomicU64,
    auth_failures: AtomicU64,
}

/// Pure-Rust local TCP loopback proxy bridge (`127.0.0.1:0`) supporting both:
/// - **SOCKS5** (RFC 1928 CONNECT + RFC 1929 session-token authentication + remote DNS `ATYP=0x03`)
/// - **HTTP CONNECT** (RFC 9110 + `Proxy-Authorization: Basic` session-token authentication)
///
/// Strictly enforces [`AtomicSocketKillSwitch::authorize_outbound_packet`] and [`SplitTunnelPolicy`]
/// before opening any upstream socket, with atomic sent/received byte counters and isolated Tor `.onion`
/// SOCKS5h chaining.
pub struct LoopbackProxyBridge {
    state: Arc<BridgeSharedState>,
    accept_thread: Option<JoinHandle<()>>,
}

impl fmt::Debug for LoopbackProxyBridge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoopbackProxyBridge")
            .field("running", &self.is_running())
            .field("port", &self.running_port())
            .field("session_username", &self.state.session_username)
            .field("session_token", &"[REDACTED]")
            .field("require_auth", &self.state.require_auth)
            .field("bytes_sent", &self.bytes_sent())
            .field("bytes_received", &self.bytes_received())
            .field("blocked_requests", &self.blocked_requests())
            .finish()
    }
}

impl LoopbackProxyBridge {
    /// Creates a stopped loopback proxy bridge with a fresh CSPRNG RFC 1929 session token.
    pub fn new(
        kill_switch: Arc<AtomicSocketKillSwitch>,
        policy: SplitTunnelPolicy,
        proxy_profiles: HashMap<String, ProxyProfileConfig>,
    ) -> Self {
        Self::with_options(kill_switch, policy, proxy_profiles, "singularity", true)
    }

    /// Creates a stopped loopback proxy bridge with custom username and authentication toggle.
    pub fn with_options(
        kill_switch: Arc<AtomicSocketKillSwitch>,
        policy: SplitTunnelPolicy,
        proxy_profiles: HashMap<String, ProxyProfileConfig>,
        session_username: impl Into<String>,
        require_auth: bool,
    ) -> Self {
        let state = Arc::new(BridgeSharedState {
            kill_switch,
            policy: RwLock::new(policy),
            proxy_profiles: RwLock::new(proxy_profiles),
            upstream_vpn_socks5: RwLock::new(None),
            session_username: session_username.into(),
            session_token: SessionToken::generate(),
            require_auth,
            running: AtomicBool::new(false),
            bound_port: AtomicU16::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            active_connections: AtomicUsize::new(0),
            total_connections: AtomicU64::new(0),
            blocked_requests: AtomicU64::new(0),
            auth_failures: AtomicU64::new(0),
        });
        Self {
            state,
            accept_thread: None,
        }
    }

    /// Starts the TCP listener on `127.0.0.1:0` (OS-assigned ephemeral loopback port) and returns the bound port.
    /// Idempotent if already running.
    pub fn start(&mut self) -> Result<u16, ProxyBridgeError> {
        if self.state.running.load(Ordering::SeqCst) {
            if let Some(port) = self.running_port() {
                return Ok(port);
            }
        }

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let local_addr = listener.local_addr()?;
        if !local_addr.ip().is_loopback() {
            return Err(ProxyBridgeError::NonLoopbackBindForbidden);
        }
        let port = local_addr.port();

        self.state.bound_port.store(port, Ordering::SeqCst);
        self.state.running.store(true, Ordering::SeqCst);

        let shared = Arc::clone(&self.state);
        let handle = thread::Builder::new()
            .name(format!("singularity-loopback-proxy-{}", port))
            .spawn(move || accept_loop(listener, shared))?;
        self.accept_thread = Some(handle);
        Ok(port)
    }

    /// Cleanly stops the TCP listener and joins the accept thread. Idempotent.
    pub fn stop(&mut self) {
        let was_running = self.state.running.swap(false, Ordering::SeqCst);
        let port = self.state.bound_port.swap(0, Ordering::SeqCst);
        if was_running && port != 0 {
            let wake_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
            let _ = TcpStream::connect_timeout(&wake_addr, Duration::from_millis(200));
        }
        if let Some(handle) = self.accept_thread.take() {
            let _ = handle.join();
        }
    }

    pub fn is_running(&self) -> bool {
        self.state.running.load(Ordering::SeqCst)
    }

    pub fn running_port(&self) -> Option<u16> {
        let p = self.state.bound_port.load(Ordering::SeqCst);
        if self.is_running() && p != 0 {
            Some(p)
        } else {
            None
        }
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.running_port()
            .map(|p| SocketAddr::from((Ipv4Addr::LOCALHOST, p)))
    }

    pub fn session_username(&self) -> &str {
        &self.state.session_username
    }

    /// Returns the ephemeral process-local RFC 1929 / Basic session token for CEF/browser configuration.
    pub fn session_token(&self) -> &str {
        self.state.session_token.as_str()
    }

    /// Formats a structured SOCKS5/HTTP username encoding optional per-tab and per-container routing context.
    pub fn format_scoped_username(
        &self,
        tab_id: Option<u64>,
        container_id: Option<&str>,
    ) -> String {
        let mut out = self.state.session_username.clone();
        if let Some(tid) = tab_id {
            out.push_str(&format!(":t={}", tid));
        }
        if let Some(cid) = container_id.map(str::trim).filter(|s| !s.is_empty()) {
            out.push_str(&format!(":c={}", cid));
        }
        out
    }

    pub fn bytes_sent(&self) -> u64 {
        self.state.bytes_sent.load(Ordering::Relaxed)
    }

    pub fn bytes_received(&self) -> u64 {
        self.state.bytes_received.load(Ordering::Relaxed)
    }

    pub fn active_connections(&self) -> usize {
        self.state.active_connections.load(Ordering::Relaxed)
    }

    pub fn total_connections(&self) -> u64 {
        self.state.total_connections.load(Ordering::Relaxed)
    }

    pub fn blocked_requests(&self) -> u64 {
        self.state.blocked_requests.load(Ordering::Relaxed)
    }

    pub fn auth_failures(&self) -> u64 {
        self.state.auth_failures.load(Ordering::Relaxed)
    }

    /// Hot-updates the split-tunneling policy without restarting the loopback listener.
    pub fn set_split_tunnel_policy(&self, policy: SplitTunnelPolicy) {
        let mut guard = self.state.policy.write().unwrap_or_else(|e| e.into_inner());
        *guard = policy;
    }

    /// Hot-updates the Tor `.onion` SOCKS5h isolation config.
    pub fn set_tor_onion_config(&self, config: TorOnionProxyConfig) {
        let mut guard = self.state.policy.write().unwrap_or_else(|e| e.into_inner());
        guard.tor_onion_config = Some(config);
    }

    /// Hot-updates the named proxy profile table.
    pub fn set_proxy_profiles(&self, profiles: HashMap<String, ProxyProfileConfig>) {
        let mut guard = self
            .state
            .proxy_profiles
            .write()
            .unwrap_or_else(|e| e.into_inner());
        *guard = profiles;
    }

    /// Configures an optional upstream Mullvad WireGuard SOCKS5 exit proxy (e.g. `10.64.0.1:1080`).
    pub fn set_upstream_vpn_socks5(&self, addr: Option<SocketAddr>) {
        let mut guard = self
            .state
            .upstream_vpn_socks5
            .write()
            .unwrap_or_else(|e| e.into_inner());
        *guard = addr;
    }

    /// Exports a `ProxyProfileConfig` targeting this running loopback bridge via SOCKS5h.
    pub fn to_socks5h_proxy_profile(&self) -> Option<ProxyProfileConfig> {
        let port = self.running_port()?;
        Some(ProxyProfileConfig {
            mode: ProxyMode::Manual {
                scheme: ProxyScheme::Socks5h,
                host: "127.0.0.1".into(),
                port,
                remote_dns: true,
                username: Some(self.state.session_username.clone()),
                encrypted_password_ref: Some("ephemeral-loopback-session-token".into()),
            },
            bypass_list: Vec::new(),
        })
    }

    /// Returns a serializable status snapshot for UI telemetry.
    pub fn snapshot(&self) -> LoopbackBridgeStatus {
        let tor_enabled = self
            .state
            .policy
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .tor_onion_config
            .as_ref()
            .map(|c| c.enabled)
            .unwrap_or(false);
        LoopbackBridgeStatus {
            running: self.is_running(),
            port: self.running_port(),
            require_auth: self.state.require_auth,
            bytes_sent: self.bytes_sent(),
            bytes_received: self.bytes_received(),
            active_connections: self.active_connections(),
            total_connections: self.total_connections(),
            blocked_requests: self.blocked_requests(),
            auth_failures: self.auth_failures(),
            tor_onion_enabled: tor_enabled,
        }
    }
}

impl Drop for LoopbackProxyBridge {
    fn drop(&mut self) {
        self.stop();
    }
}

struct ActiveConnGuard {
    counter: Arc<BridgeSharedState>,
}

impl Drop for ActiveConnGuard {
    fn drop(&mut self) {
        self.counter.active_connections.fetch_sub(1, Ordering::AcqRel);
    }
}

fn accept_loop(listener: TcpListener, state: Arc<BridgeSharedState>) {
    while state.running.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, peer_addr)) => {
                if !state.running.load(Ordering::SeqCst) {
                    drop(stream);
                    break;
                }
                // Defense-in-depth: strictly enforce loopback-only clients
                if !peer_addr.ip().is_loopback() {
                    state.blocked_requests.fetch_add(1, Ordering::Relaxed);
                    drop(stream);
                    continue;
                }
                let prev = state.active_connections.fetch_add(1, Ordering::AcqRel);
                if prev >= MAX_CONCURRENT_CONNECTIONS {
                    state.active_connections.fetch_sub(1, Ordering::AcqRel);
                    state.blocked_requests.fetch_add(1, Ordering::Relaxed);
                    drop(stream);
                    continue;
                }
                state.total_connections.fetch_add(1, Ordering::Relaxed);
                let client_state = Arc::clone(&state);
                let _ = thread::Builder::new()
                    .name("singularity-proxy-conn".into())
                    .spawn(move || {
                        let _guard = ActiveConnGuard {
                            counter: Arc::clone(&client_state),
                        };
                        handle_client_connection(stream, &client_state);
                    });
            }
            Err(_) => {
                if !state.running.load(Ordering::SeqCst) {
                    break;
                }
                thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

fn handle_client_connection(mut stream: TcpStream, state: &Arc<BridgeSharedState>) {
    let _ = stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT));
    let _ = stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT));
    let _ = stream.set_nodelay(true);

    let mut first = [0u8; 1];
    if stream.read_exact(&mut first).is_err() {
        return;
    }

    match first[0] {
        0x05 => {
            let _ = handle_socks5(&mut stream, state);
        }
        b'A'..=b'Z' => {
            let _ = handle_http_connect(&mut stream, first[0], state);
        }
        _ => {}
    }
}

#[derive(Debug, Default)]
struct RequestRoutingContext {
    tab_id: Option<u64>,
    container_id: Option<String>,
}

/// Validates RFC 1929 / HTTP Basic credentials with constant-time token comparison and extracts
/// optional `:t=<tab_id>:c=<container_id>` routing tags from the username.
fn verify_session_credentials(
    username: &str,
    password: &[u8],
    expected_username: &str,
    expected_token: &[u8],
) -> Option<RequestRoutingContext> {
    if !constant_time_eq(password, expected_token) {
        return None;
    }

    let mut parts = username.split(':');
    let base_user = parts.next()?;
    if base_user != expected_username {
        return None;
    }

    let mut ctx = RequestRoutingContext::default();
    for segment in parts {
        if let Some(tab_str) = segment.strip_prefix("t=") {
            ctx.tab_id = tab_str.parse::<u64>().ok();
        } else if let Some(cid) = segment.strip_prefix("c=") {
            if !cid.is_empty() {
                ctx.container_id = Some(cid.to_string());
            }
        }
    }
    Some(ctx)
}

fn handle_socks5(stream: &mut TcpStream, state: &Arc<BridgeSharedState>) -> io::Result<()> {
    // RFC 1928 method greeting (VER=0x05 already consumed)
    let mut nmethods_buf = [0u8; 1];
    stream.read_exact(&mut nmethods_buf)?;
    let nmethods = nmethods_buf[0] as usize;
    if nmethods == 0 {
        stream.write_all(&[0x05, 0xFF])?;
        return Ok(());
    }
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods)?;

    let mut ctx = RequestRoutingContext::default();

    if state.require_auth {
        if !methods.contains(&0x02) {
            state.auth_failures.fetch_add(1, Ordering::Relaxed);
            stream.write_all(&[0x05, 0xFF])?;
            return Ok(());
        }
        // Select RFC 1929 Username/Password authentication (0x02)
        stream.write_all(&[0x05, 0x02])?;
        stream.flush()?;

        match perform_rfc1929_server_auth(stream, state)? {
            Some(verified_ctx) => ctx = verified_ctx,
            None => return Ok(()),
        }
    } else if methods.contains(&0x02) {
        stream.write_all(&[0x05, 0x02])?;
        stream.flush()?;
        match perform_rfc1929_server_auth(stream, state)? {
            Some(verified_ctx) => ctx = verified_ctx,
            None => return Ok(()),
        }
    } else if methods.contains(&0x00) {
        stream.write_all(&[0x05, 0x00])?;
        stream.flush()?;
    } else {
        stream.write_all(&[0x05, 0xFF])?;
        return Ok(());
    }

    // RFC 1928 Request: [VER, CMD, RSV, ATYP]
    let mut req_hdr = [0u8; 4];
    stream.read_exact(&mut req_hdr)?;
    if req_hdr[0] != 0x05 || req_hdr[2] != 0x00 {
        send_socks5_reply(stream, 0x01, None)?;
        return Ok(());
    }
    if req_hdr[1] != 0x01 {
        // Only CONNECT (0x01) is supported
        send_socks5_reply(stream, 0x07, None)?;
        return Ok(());
    }

    let dest_host = match req_hdr[3] {
        0x01 => {
            let mut ip4 = [0u8; 4];
            stream.read_exact(&mut ip4)?;
            Ipv4Addr::from(ip4).to_string()
        }
        0x03 => {
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf)?;
            let len = len_buf[0] as usize;
            if len == 0 {
                send_socks5_reply(stream, 0x01, None)?;
                return Ok(());
            }
            let mut domain_bytes = vec![0u8; len];
            stream.read_exact(&mut domain_bytes)?;
            match String::from_utf8(domain_bytes) {
                Ok(d) => d,
                Err(_) => {
                    send_socks5_reply(stream, 0x01, None)?;
                    return Ok(());
                }
            }
        }
        0x04 => {
            let mut ip6 = [0u8; 16];
            stream.read_exact(&mut ip6)?;
            Ipv6Addr::from(ip6).to_string()
        }
        _ => {
            send_socks5_reply(stream, 0x08, None)?;
            return Ok(());
        }
    };

    let mut port_buf = [0u8; 2];
    stream.read_exact(&mut port_buf)?;
    let dest_port = u16::from_be_bytes(port_buf);
    if dest_port == 0 {
        send_socks5_reply(stream, 0x01, None)?;
        return Ok(());
    }

    // Strictly enforce Split-Tunnel Policy + AtomicSocketKillSwitch before dialing upstream
    let decision = match authorize_and_route(
        state,
        ctx.tab_id,
        ctx.container_id.as_deref(),
        &dest_host,
    ) {
        Ok(d) => d,
        Err(_) => {
            // 0x02 = Connection not allowed by ruleset
            send_socks5_reply(stream, 0x02, None)?;
            return Ok(());
        }
    };

    let upstream = match dial_upstream(state, &decision, &dest_host, dest_port) {
        Ok(u) => u,
        Err(e) => {
            let rep = match e.kind() {
                io::ErrorKind::PermissionDenied => 0x02,
                io::ErrorKind::ConnectionRefused => 0x05,
                io::ErrorKind::TimedOut => 0x04,
                _ => 0x01,
            };
            send_socks5_reply(stream, rep, None)?;
            return Ok(());
        }
    };

    let bound_addr = upstream.local_addr().ok();
    send_socks5_reply(stream, 0x00, bound_addr)?;
    relay_bidirectional(stream, upstream, state)
}

fn perform_rfc1929_server_auth(
    stream: &mut TcpStream,
    state: &BridgeSharedState,
) -> io::Result<Option<RequestRoutingContext>> {
    let mut ver_ulen = [0u8; 2];
    stream.read_exact(&mut ver_ulen)?;
    if ver_ulen[0] != 0x01 {
        state.auth_failures.fetch_add(1, Ordering::Relaxed);
        stream.write_all(&[0x01, 0x01])?;
        return Ok(None);
    }

    let ulen = ver_ulen[1] as usize;
    let mut uname_bytes = vec![0u8; ulen];
    stream.read_exact(&mut uname_bytes)?;

    let mut plen_buf = [0u8; 1];
    stream.read_exact(&mut plen_buf)?;
    let plen = plen_buf[0] as usize;
    let mut pass_bytes = vec![0u8; plen];
    stream.read_exact(&mut pass_bytes)?;

    let verified = std::str::from_utf8(&uname_bytes).ok().and_then(|uname| {
        verify_session_credentials(
            uname,
            &pass_bytes,
            &state.session_username,
            state.session_token.as_bytes(),
        )
    });
    pass_bytes.zeroize();

    match verified {
        Some(ctx) => {
            stream.write_all(&[0x01, 0x00])?;
            stream.flush()?;
            Ok(Some(ctx))
        }
        None => {
            state.auth_failures.fetch_add(1, Ordering::Relaxed);
            stream.write_all(&[0x01, 0x01])?;
            stream.flush()?;
            Ok(None)
        }
    }
}

fn send_socks5_reply(
    stream: &mut TcpStream,
    reply_code: u8,
    bind_addr: Option<SocketAddr>,
) -> io::Result<()> {
    let mut buf = Vec::with_capacity(22);
    buf.extend_from_slice(&[0x05, reply_code, 0x00]);
    match bind_addr {
        Some(SocketAddr::V4(v4)) => {
            buf.push(0x01);
            buf.extend_from_slice(&v4.ip().octets());
            buf.extend_from_slice(&v4.port().to_be_bytes());
        }
        Some(SocketAddr::V6(v6)) => {
            buf.push(0x04);
            buf.extend_from_slice(&v6.ip().octets());
            buf.extend_from_slice(&v6.port().to_be_bytes());
        }
        None => {
            buf.push(0x01);
            buf.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        }
    }
    stream.write_all(&buf)?;
    stream.flush()
}

fn handle_http_connect(
    stream: &mut TcpStream,
    first_byte: u8,
    state: &Arc<BridgeSharedState>,
) -> io::Result<()> {
    let mut raw = Vec::with_capacity(512);
    raw.push(first_byte);
    let mut byte = [0u8; 1];
    while !raw.ends_with(b"\r\n\r\n") {
        if raw.len() >= MAX_HTTP_HEADER_BYTES {
            stream.write_all(b"HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\n\r\n")?;
            return Ok(());
        }
        stream.read_exact(&mut byte)?;
        raw.push(byte[0]);
    }

    let header_text = match std::str::from_utf8(&raw) {
        Ok(s) => s,
        Err(_) => {
            stream.write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")?;
            return Ok(());
        }
    };

    let mut lines = header_text.split("\r\n");
    let request_line = match lines.next() {
        Some(l) => l,
        None => {
            stream.write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")?;
            return Ok(());
        }
    };

    let mut req_parts = request_line.split_whitespace();
    let method = req_parts.next().unwrap_or("");
    let authority = req_parts.next().unwrap_or("");
    let version = req_parts.next().unwrap_or("");

    if method != "CONNECT" {
        stream.write_all(b"HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n")?;
        return Ok(());
    }
    if !version.starts_with("HTTP/1.") {
        stream.write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")?;
        return Ok(());
    }

    let (dest_host, dest_port) = match parse_connect_authority(authority) {
        Some((h, p)) => (h.to_string(), p),
        None => {
            stream.write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")?;
            return Ok(());
        }
    };

    let mut proxy_auth_header: Option<String> = None;
    let mut header_tab_id: Option<u64> = None;
    let mut header_container_id: Option<String> = None;

    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            let name_l = name.trim().to_ascii_lowercase();
            let val = value.trim();
            match name_l.as_str() {
                "proxy-authorization" => proxy_auth_header = Some(val.to_string()),
                "x-singularity-tab-id" => header_tab_id = val.parse::<u64>().ok(),
                "x-singularity-container-id" if !val.is_empty() => {
                    header_container_id = Some(val.to_string());
                }
                _ => {}
            }
        }
    }

    let mut ctx = RequestRoutingContext::default();
    if state.require_auth {
        let verified = proxy_auth_header
            .as_deref()
            .and_then(|hdr| verify_http_proxy_basic_auth(hdr, state));
        match verified {
            Some(c) => ctx = c,
            None => {
                state.auth_failures.fetch_add(1, Ordering::Relaxed);
                stream.write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                      Proxy-Authenticate: Basic realm=\"Singularity Loopback Bridge\"\r\n\
                      Connection: close\r\n\r\n",
                )?;
                return Ok(());
            }
        }
    }

    if ctx.tab_id.is_none() {
        ctx.tab_id = header_tab_id;
    }
    if ctx.container_id.is_none() {
        ctx.container_id = header_container_id;
    }

    // Strictly enforce Split-Tunnel Policy + AtomicSocketKillSwitch
    let decision = match authorize_and_route(
        state,
        ctx.tab_id,
        ctx.container_id.as_deref(),
        &dest_host,
    ) {
        Ok(d) => d,
        Err(reason) => {
            let safe_reason: String = reason
                .chars()
                .filter(|&c| c != '\r' && c != '\n')
                .take(180)
                .collect();
            let resp = format!(
                "HTTP/1.1 403 Forbidden\r\nX-Singularity-Block-Reason: {}\r\nConnection: close\r\n\r\n",
                safe_reason
            );
            stream.write_all(resp.as_bytes())?;
            return Ok(());
        }
    };

    let upstream = match dial_upstream(state, &decision, &dest_host, dest_port) {
        Ok(u) => u,
        Err(_) => {
            stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")?;
            return Ok(());
        }
    };

    stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
    stream.flush()?;
    relay_bidirectional(stream, upstream, state)
}

fn verify_http_proxy_basic_auth(
    header_val: &str,
    state: &BridgeSharedState,
) -> Option<RequestRoutingContext> {
    let mut parts = header_val.splitn(2, char::is_whitespace);
    let scheme = parts.next()?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let b64 = parts.next()?.trim();
    let mut decoded = BASE64.decode(b64).ok()?;
    let result = std::str::from_utf8(&decoded).ok().and_then(|cred| {
        let (user, pass) = cred.split_once(':')?;
        verify_session_credentials(
            user,
            pass.as_bytes(),
            &state.session_username,
            state.session_token.as_bytes(),
        )
    });
    decoded.zeroize();
    result
}

fn authorize_and_route(
    state: &BridgeSharedState,
    tab_id: Option<u64>,
    container_id: Option<&str>,
    dest_host: &str,
) -> Result<RouteDecision, String> {
    let decision = {
        let policy = state.policy.read().unwrap_or_else(|e| e.into_inner());
        policy.resolve_route_for_request(tab_id, container_id, dest_host)
    };

    if let RouteDecision::Blocked { reason } = &decision {
        state.blocked_requests.fetch_add(1, Ordering::Relaxed);
        return Err(reason.clone());
    }

    if let Err(block_reason) = state.kill_switch.authorize_outbound_packet(dest_host) {
        state.blocked_requests.fetch_add(1, Ordering::Relaxed);
        return Err(block_reason.to_string());
    }

    Ok(decision)
}

fn dial_upstream(
    state: &BridgeSharedState,
    decision: &RouteDecision,
    dest_host: &str,
    dest_port: u16,
) -> io::Result<TcpStream> {
    match decision {
        RouteDecision::Blocked { reason } => {
            Err(io::Error::new(io::ErrorKind::PermissionDenied, reason.clone()))
        }
        RouteDecision::TorOnionSocks5h {
            socks5h_host,
            socks5h_port,
            stream_isolation_key,
        } => {
            let auth = Some((stream_isolation_key.as_str(), stream_isolation_key.as_str()));
            dial_via_upstream_socks5h(socks5h_host, *socks5h_port, auth, dest_host, dest_port)
        }
        RouteDecision::ProxyProfile { profile_name, .. } => {
            let profile = state
                .proxy_profiles
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .get(profile_name)
                .cloned()
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!("Referenced proxy profile '{}' not found (fail-closed)", profile_name),
                    )
                })?;

            if profile.should_bypass(dest_host) {
                return dial_direct_checked(&state.kill_switch, dest_host, dest_port);
            }

            match profile.mode {
                ProxyMode::Direct | ProxyMode::System => {
                    dial_direct_checked(&state.kill_switch, dest_host, dest_port)
                }
                ProxyMode::Manual {
                    scheme,
                    host,
                    port,
                    username,
                    ..
                } => match scheme {
                    ProxyScheme::Socks5 | ProxyScheme::Socks5h => {
                        let auth = username.as_deref().map(|u| (u, ""));
                        dial_via_upstream_socks5h(&host, port, auth, dest_host, dest_port)
                    }
                    ProxyScheme::Socks4 => {
                        dial_via_upstream_socks4a(
                            &host,
                            port,
                            username.as_deref().unwrap_or(""),
                            dest_host,
                            dest_port,
                        )
                    }
                    ProxyScheme::Http => {
                        dial_via_upstream_http_connect(&host, port, dest_host, dest_port)
                    }
                    ProxyScheme::Https => Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "Upstream HTTPS TLS proxy requires Chromium/CEF BoringSSL stack (export via to_cef_proxy_pref_json)",
                    )),
                },
                ProxyMode::PacScript { .. } => Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "PAC JavaScript evaluation requires Chromium/CEF proxy resolver (export via to_cef_proxy_pref_json)",
                )),
            }
        }
        RouteDecision::MullvadRelay { .. } => {
            let upstream_socks = *state
                .upstream_vpn_socks5
                .read()
                .unwrap_or_else(|e| e.into_inner());
            if let Some(socks_addr) = upstream_socks {
                dial_via_upstream_socks5h(
                    &socks_addr.ip().to_string(),
                    socks_addr.port(),
                    None,
                    dest_host,
                    dest_port,
                )
            } else {
                dial_direct_checked(&state.kill_switch, dest_host, dest_port)
            }
        }
        RouteDecision::BypassDirect { .. } => {
            dial_direct_checked(&state.kill_switch, dest_host, dest_port)
        }
    }
}

fn dial_direct_checked(
    kill_switch: &AtomicSocketKillSwitch,
    dest_host: &str,
    dest_port: u16,
) -> io::Result<TcpStream> {
    if kill_switch.is_block_lan_rfc1918() {
        let verified_ips = kill_switch
            .authorize_outbound_host_and_dns(dest_host, dest_port)
            .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e.to_string()))?;
        let mut last_err = io::Error::new(io::ErrorKind::AddrNotAvailable, "No resolved addresses");
        for ip in verified_ips {
            let addr = SocketAddr::new(ip, dest_port);
            match TcpStream::connect_timeout(&addr, UPSTREAM_CONNECT_TIMEOUT) {
                Ok(s) => {
                    let _ = s.set_nodelay(true);
                    return Ok(s);
                }
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    } else {
        let mut last_err = io::Error::new(io::ErrorKind::AddrNotAvailable, "No resolved addresses");
        for addr in (dest_host, dest_port).to_socket_addrs()? {
            match TcpStream::connect_timeout(&addr, UPSTREAM_CONNECT_TIMEOUT) {
                Ok(s) => {
                    let _ = s.set_nodelay(true);
                    return Ok(s);
                }
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }
}

/// Outbound SOCKS5h client handshake (RFC 1928 + optional RFC 1929) always transmitting hostnames
/// as `ATYP = 0x03` so `.onion` and proxied DNS names NEVER resolve locally.
fn dial_via_upstream_socks5h(
    proxy_host: &str,
    proxy_port: u16,
    credentials: Option<(&str, &str)>,
    dest_host: &str,
    dest_port: u16,
) -> io::Result<TcpStream> {
    let addr = (proxy_host, proxy_port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "Upstream proxy unresolvable"))?;
    let mut stream = TcpStream::connect_timeout(&addr, UPSTREAM_CONNECT_TIMEOUT)?;
    let _ = stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT));
    let _ = stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT));
    let _ = stream.set_nodelay(true);

    // Greeting
    if credentials.is_some() {
        stream.write_all(&[0x05, 0x02, 0x00, 0x02])?;
    } else {
        stream.write_all(&[0x05, 0x01, 0x00])?;
    }
    stream.flush()?;

    let mut method_resp = [0u8; 2];
    stream.read_exact(&mut method_resp)?;
    if method_resp[0] != 0x05 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid upstream SOCKS5 version"));
    }

    match method_resp[1] {
        0x00 => {}
        0x02 => {
            let (user, pass) = credentials.ok_or_else(|| {
                io::Error::new(io::ErrorKind::PermissionDenied, "Upstream SOCKS5 requires auth")
            })?;
            let u_bytes = user.as_bytes();
            let p_bytes = pass.as_bytes();
            if u_bytes.len() > 255 || p_bytes.len() > 255 {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "RFC 1929 credential too long"));
            }
            let mut auth_req = Vec::with_capacity(3 + u_bytes.len() + p_bytes.len());
            auth_req.push(0x01);
            auth_req.push(u_bytes.len() as u8);
            auth_req.extend_from_slice(u_bytes);
            auth_req.push(p_bytes.len() as u8);
            auth_req.extend_from_slice(p_bytes);
            stream.write_all(&auth_req)?;
            stream.flush()?;

            let mut auth_resp = [0u8; 2];
            stream.read_exact(&mut auth_resp)?;
            if auth_resp[0] != 0x01 || auth_resp[1] != 0x00 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Upstream SOCKS5 authentication failed",
                ));
            }
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Upstream SOCKS5 rejected auth methods",
            ));
        }
    }

    // CONNECT request using ATYP=0x03 (remote DNS) for hostnames, or IPv4/IPv6 if literal IP
    let mut req = Vec::with_capacity(7 + dest_host.len());
    req.extend_from_slice(&[0x05, 0x01, 0x00]);
    if let Ok(IpAddr::V4(v4)) = dest_host.parse::<IpAddr>() {
        req.push(0x01);
        req.extend_from_slice(&v4.octets());
    } else if let Ok(IpAddr::V6(v6)) = dest_host.parse::<IpAddr>() {
        req.push(0x04);
        req.extend_from_slice(&v6.octets());
    } else {
        let host_bytes = dest_host.as_bytes();
        if host_bytes.is_empty() || host_bytes.len() > 255 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid SOCKS5h hostname length"));
        }
        req.push(0x03);
        req.push(host_bytes.len() as u8);
        req.extend_from_slice(host_bytes);
    }
    req.extend_from_slice(&dest_port.to_be_bytes());
    stream.write_all(&req)?;
    stream.flush()?;

    let mut reply_hdr = [0u8; 4];
    stream.read_exact(&mut reply_hdr)?;
    if reply_hdr[0] != 0x05 || reply_hdr[1] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("Upstream SOCKS5h CONNECT failed with REP=0x{:02x}", reply_hdr[1]),
        ));
    }

    // Drain BND.ADDR + BND.PORT
    match reply_hdr[3] {
        0x01 => {
            let mut skip = [0u8; 6];
            stream.read_exact(&mut skip)?;
        }
        0x03 => {
            let mut l = [0u8; 1];
            stream.read_exact(&mut l)?;
            let mut skip = vec![0u8; l[0] as usize + 2];
            stream.read_exact(&mut skip)?;
        }
        0x04 => {
            let mut skip = [0u8; 18];
            stream.read_exact(&mut skip)?;
        }
        _ => {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid upstream SOCKS5 ATYP"));
        }
    }

    Ok(stream)
}

fn dial_via_upstream_http_connect(
    proxy_host: &str,
    proxy_port: u16,
    dest_host: &str,
    dest_port: u16,
) -> io::Result<TcpStream> {
    let addr = (proxy_host, proxy_port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "Upstream HTTP proxy unresolvable"))?;
    let mut stream = TcpStream::connect_timeout(&addr, UPSTREAM_CONNECT_TIMEOUT)?;
    let _ = stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT));
    let _ = stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT));
    let _ = stream.set_nodelay(true);

    let authority = format!("{}:{}", format_host_for_uri(dest_host), dest_port);
    let req = format!(
        "CONNECT {} HTTP/1.1\r\nHost: {}\r\nProxy-Connection: Keep-Alive\r\n\r\n",
        authority, authority
    );
    stream.write_all(req.as_bytes())?;
    stream.flush()?;

    let mut resp = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    while !resp.ends_with(b"\r\n\r\n") {
        if resp.len() >= MAX_HTTP_HEADER_BYTES {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Upstream HTTP response too large"));
        }
        stream.read_exact(&mut byte)?;
        resp.push(byte[0]);
    }
    let status_line = std::str::from_utf8(&resp)
        .ok()
        .and_then(|s| s.lines().next())
        .unwrap_or("");
    if !status_line.contains(" 200") {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("Upstream HTTP CONNECT failed: {}", status_line),
        ));
    }
    Ok(stream)
}

/// Outbound SOCKS4 / SOCKS4a client handshake (uses `0.0.0.1` sentinel for remote DNS on hostnames).
fn dial_via_upstream_socks4a(
    proxy_host: &str,
    proxy_port: u16,
    user_id: &str,
    dest_host: &str,
    dest_port: u16,
) -> io::Result<TcpStream> {
    let addr = (proxy_host, proxy_port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "Upstream SOCKS4 proxy unresolvable"))?;
    let mut stream = TcpStream::connect_timeout(&addr, UPSTREAM_CONNECT_TIMEOUT)?;
    let _ = stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT));
    let _ = stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT));
    let _ = stream.set_nodelay(true);

    let mut req = Vec::with_capacity(16 + user_id.len() + dest_host.len());
    req.push(0x04); // VN = 4
    req.push(0x01); // CD = CONNECT
    req.extend_from_slice(&dest_port.to_be_bytes());
    if let Ok(v4) = dest_host.parse::<Ipv4Addr>() {
        req.extend_from_slice(&v4.octets());
        req.extend_from_slice(user_id.as_bytes());
        req.push(0x00);
    } else {
        // SOCKS4a sentinel IP 0.0.0.1 -> append NUL-terminated domain name
        req.extend_from_slice(&[0, 0, 0, 1]);
        req.extend_from_slice(user_id.as_bytes());
        req.push(0x00);
        req.extend_from_slice(dest_host.as_bytes());
        req.push(0x00);
    }
    stream.write_all(&req)?;
    stream.flush()?;

    let mut resp = [0u8; 8];
    stream.read_exact(&mut resp)?;
    if resp[0] != 0x00 || resp[1] != 0x5A {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("Upstream SOCKS4/4a CONNECT rejected (CD=0x{:02x})", resp[1]),
        ));
    }
    Ok(stream)
}

fn relay_bidirectional(
    client: &mut TcpStream,
    upstream: TcpStream,
    state: &Arc<BridgeSharedState>,
) -> io::Result<()> {
    let _ = client.set_read_timeout(None);
    let _ = client.set_write_timeout(None);
    let _ = upstream.set_read_timeout(None);
    let _ = upstream.set_write_timeout(None);

    let mut client_write = client.try_clone()?;
    let mut upstream_read = upstream.try_clone()?;
    let mut upstream_write = upstream;

    let rx_state = Arc::clone(state);
    let down_handle = thread::spawn(move || {
        let mut buf = [0u8; 16 * 1024];
        loop {
            match upstream_read.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if client_write.write_all(&buf[..n]).is_err() {
                        break;
                    }
                    rx_state
                        .bytes_received
                        .fetch_add(n as u64, Ordering::Relaxed);
                }
                Err(_) => break,
            }
        }
        let _ = client_write.shutdown(Shutdown::Write);
    });

    let mut buf = [0u8; 16 * 1024];
    loop {
        match client.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if upstream_write.write_all(&buf[..n]).is_err() {
                    break;
                }
                state.bytes_sent.fetch_add(n as u64, Ordering::Relaxed);
            }
            Err(_) => break,
        }
    }
    let _ = upstream_write.shutdown(Shutdown::Write);
    let _ = down_handle.join();
    Ok(())
}

/// Evaluates whether `host` (domain, `host:port`, IPv4, IPv6, `[ipv6]:port`) matches a bypass/split-tunnel
/// pattern (domain, `*.wildcard`, `.suffix`, `localhost`, `<local>`, exact IP, IPv4/IPv6 CIDR, or glob `*`).
pub fn host_matches_pattern(host: &str, pattern: &str) -> bool {
    let raw_rule = pattern.trim();
    if raw_rule.is_empty() {
        return false;
    }

    let (raw_host, host_port) = split_host_and_port(host);
    let clean_host = raw_host.trim_end_matches('.').to_ascii_lowercase();
    if clean_host.is_empty() {
        return false;
    }

    if raw_rule == "*" {
        return true;
    }

    if raw_rule.eq_ignore_ascii_case("<local>") {
        if let Some(ip) = parse_host_ip(&clean_host) {
            return ip.is_loopback();
        }
        return !clean_host.contains('.');
    }

    // CIDR check (e.g. `192.168.0.0/16`, `10.0.0.0/8`, `fe80::/10`)
    if raw_rule.contains('/') {
        return match parse_host_ip(&clean_host) {
            Some(ip) => ip_matches_cidr(ip, raw_rule),
            None => false,
        };
    }

    let (raw_rule_host, rule_port) = split_host_and_port(raw_rule);
    if let Some(rp) = rule_port {
        if host_port != Some(rp) {
            return false;
        }
    }

    let clean_rule = raw_rule_host.trim_end_matches('.').to_ascii_lowercase();
    if clean_rule.is_empty() {
        return false;
    }

    // Explicit `localhost` rule matches `localhost` and `*.localhost`
    if clean_rule == "localhost" {
        return clean_host == "localhost" || clean_host.ends_with(".localhost");
    }

    // Exact IP literal comparison (including IPv4-mapped IPv6 normalization)
    if let (Some(h_ip), Some(r_ip)) = (parse_host_ip(&clean_host), parse_host_ip(&clean_rule)) {
        return normalize_ip(h_ip) == normalize_ip(r_ip);
    }

    // Leading wildcard subdomain: `*.local` or `*.example.com`
    if let Some(suffix) = clean_rule.strip_prefix("*.") {
        if !suffix.contains('*') {
            return clean_host.len() > suffix.len() + 1
                && clean_host.ends_with(suffix)
                && clean_host.as_bytes()[clean_host.len() - suffix.len() - 1] == b'.';
        }
    }

    // Leading dot suffix: `.example.com` matches `example.com` and `sub.example.com`
    if let Some(suffix) = clean_rule.strip_prefix('.') {
        if !suffix.contains('*') {
            return clean_host == suffix
                || (clean_host.len() > suffix.len() + 1
                    && clean_host.ends_with(suffix)
                    && clean_host.as_bytes()[clean_host.len() - suffix.len() - 1] == b'.');
        }
    }

    // General wildcard glob (e.g. `192.168.*`, `api-*.internal`)
    if clean_rule.contains('*') {
        return glob_match(&clean_rule, &clean_host);
    }

    // Standard domain/suffix match (`example.com` matches `example.com` and `sub.example.com`)
    clean_host == clean_rule
        || (clean_host.len() > clean_rule.len() + 1
            && clean_host.ends_with(&clean_rule)
            && clean_host.as_bytes()[clean_host.len() - clean_rule.len() - 1] == b'.')
}

fn parse_host_ip(host: &str) -> Option<IpAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(ip);
    }
    if let Some((addr_part, _zone)) = host.split_once('%') {
        if let Ok(v6) = addr_part.parse::<Ipv6Addr>() {
            return Some(IpAddr::V6(v6));
        }
    }
    parse_any_ip_representation(host)
}

fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

fn ip_matches_cidr(ip: IpAddr, cidr: &str) -> bool {
    let Some((net_str, prefix_str)) = cidr.split_once('/') else {
        return false;
    };
    let Ok(prefix_len) = prefix_str.trim().parse::<u32>() else {
        return false;
    };
    let Some(net_ip) = parse_host_ip(net_str.trim()) else {
        return false;
    };

    match (normalize_ip(ip), normalize_ip(net_ip)) {
        (IpAddr::V4(host_v4), IpAddr::V4(net_v4)) => {
            if prefix_len > 32 {
                return false;
            }
            let mask = if prefix_len == 0 {
                0u32
            } else {
                !0u32 << (32 - prefix_len)
            };
            (u32::from(host_v4) & mask) == (u32::from(net_v4) & mask)
        }
        (IpAddr::V6(host_v6), IpAddr::V6(net_v6)) => {
            if prefix_len > 128 {
                return false;
            }
            let mask = if prefix_len == 0 {
                0u128
            } else {
                !0u128 << (128 - prefix_len)
            };
            (u128::from(host_v6) & mask) == (u128::from(net_v6) & mask)
        }
        _ => false,
    }
}

fn split_host_and_port(input: &str) -> (&str, Option<u16>) {
    let s = input.trim();
    if let Some(rest) = s.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let host = &rest[..end];
            let tail = &rest[end + 1..];
            let port = tail.strip_prefix(':').and_then(|p| p.parse::<u16>().ok());
            return (host, port);
        }
    }
    let colon_count = s.bytes().filter(|&b| b == b':').count();
    if colon_count == 1 {
        if let Some((h, p)) = s.rsplit_once(':') {
            if let Ok(port) = p.parse::<u16>() {
                return (h, Some(port));
            }
        }
    }
    (s, None)
}

fn parse_connect_authority(authority: &str) -> Option<(&str, u16)> {
    let (host, port) = split_host_and_port(authority);
    let port = port?;
    if host.is_empty() || port == 0 {
        return None;
    }
    Some((host, port))
}

fn format_host_for_uri(host: &str) -> String {
    let trimmed = host.trim();
    if trimmed.contains(':') && !trimmed.starts_with('[') && !trimmed.ends_with(']') {
        format!("[{}]", trimmed)
    } else {
        trimmed.to_string()
    }
}

fn glob_match(pattern: &str, text: &str) -> bool {
    let p = pattern.as_bytes();
    let t = text.as_bytes();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star_idx, mut match_idx) = (None, 0usize);

    while ti < t.len() {
        if pi < p.len() && p[pi] == t[ti] {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star_idx = Some(pi);
            match_idx = ti;
            pi += 1;
        } else if let Some(si) = star_idx {
            pi = si + 1;
            match_idx += 1;
            ti = match_idx;
        } else {
            return false;
        }
    }

    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn escape_json_str(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '"' => out.push_str(r#"\""#),
            '\\' => out.push_str(r#"\\"#),
            '\n' => out.push_str(r#"\n"#),
            '\r' => out.push_str(r#"\r"#),
            '\t' => out.push_str(r#"\t"#),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!(r#"\u{:04x}"#, c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spawn_loopback_echo_server() -> (u16, JoinHandle<()>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind echo server");
        let port = listener.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 4096];
                while let Ok(n) = stream.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    if stream.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            }
        });
        (port, handle)
    }

    #[test]
    fn test_proxy_profile_bypass_cidr_wildcards_localhost_and_cef_json() {
        let cfg = ProxyProfileConfig::manual(
            ProxyScheme::Socks5h,
            "127.0.0.1",
            1080,
            true,
            Some("alice".into()),
            Some("vault-ref-secret-99".into()),
            vec![
                "localhost".into(),
                "*.local".into(),
                "192.168.0.0/16".into(),
                "10.0.0.0/8".into(),
                "fe80::/10".into(),
                "corp.internal".into(),
            ],
        );

        // Should bypass
        assert!(cfg.should_bypass("localhost"));
        assert!(cfg.should_bypass("LOCALHOST."));
        assert!(cfg.should_bypass("dev.localhost"));
        assert!(cfg.should_bypass("printer.local"));
        assert!(cfg.should_bypass("a.b.local"));
        assert!(cfg.should_bypass("192.168.42.7"));
        assert!(cfg.should_bypass("192.168.0.1:8443"));
        assert!(cfg.should_bypass("::ffff:192.168.10.20"));
        assert!(cfg.should_bypass("10.255.0.5"));
        assert!(cfg.should_bypass("fe80::1"));
        assert!(cfg.should_bypass("corp.internal"));
        assert!(cfg.should_bypass("git.corp.internal"));

        // Must NOT bypass
        assert!(!cfg.should_bypass("local"));
        assert!(!cfg.should_bypass("mylocal"));
        assert!(!cfg.should_bypass("192.169.0.1"));
        assert!(!cfg.should_bypass("11.0.0.1"));
        assert!(!cfg.should_bypass("evilcorp.internal"));
        assert!(!cfg.should_bypass("mullvad.net"));

        // CEF preference JSON must never expose vault refs / secrets
        let cef_json = cfg.to_cef_proxy_pref_json();
        assert!(cef_json.contains(r#""mode":"fixed_servers""#));
        assert!(cef_json.contains(r#""server":"socks5://127.0.0.1:1080""#));
        assert!(cef_json.contains(r#""remote_dns":true"#));
        assert!(cef_json.contains(r#"192.168.0.0/16"#));
        assert!(!cef_json.contains("vault-ref-secret-99"));

        assert_eq!(ProxyProfileConfig::direct().to_cef_proxy_pref_json(), r#"{"mode":"direct"}"#);
        assert_eq!(ProxyProfileConfig::system().to_cef_proxy_pref_json(), r#"{"mode":"system"}"#);

        let pac = ProxyProfileConfig::pac("https://proxy.corp.example/wpad.dat", None);
        let pac_json = pac.to_cef_proxy_pref_json();
        assert!(pac_json.contains(r#""mode":"pac_script""#));
        assert!(pac_json.contains(r#""pac_url":"https://proxy.corp.example/wpad.dat""#));
    }

    #[test]
    fn test_split_tunnel_precedence_and_tor_onion_isolation() {
        let mut policy = SplitTunnelPolicy {
            domain_rules: vec![
                SplitTunnelRule::bypass_direct("*.bank.local"),
                SplitTunnelRule::force_relay("bbc.co.uk", "gb-lon-wg-002"),
                SplitTunnelRule::block("telemetry.evil.test"),
            ],
            container_rules: HashMap::from([
                ("work".into(), SplitTunnelTarget::ForceRelay("de-fra-wg-003".into())),
                ("direct-lab".into(), SplitTunnelTarget::BypassDirect),
            ]),
            per_tab_relay_overrides: HashMap::from([(42, "is-rek-wg-001".into())]),
            default_relay_hostname: Some("ch-zrh-wg-001".into()),
            tor_onion_config: Some(TorOnionProxyConfig::enabled_local(9050)),
        };

        // 1. `.onion` always routes via isolated Tor SOCKS5h with distinct circuit keys
        assert_eq!(
            policy.resolve_route_for_request(
                Some(42),
                Some("work"),
                "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"
            ),
            RouteDecision::TorOnionSocks5h {
                socks5h_host: "127.0.0.1".into(),
                socks5h_port: 9050,
                stream_isolation_key: "singularity-onion:c=work:t=42".into(),
            }
        );

        // 2. Domain rule beats tab & container overrides
        assert!(matches!(
            policy.resolve_route_for_request(Some(42), Some("work"), "app.bank.local"),
            RouteDecision::BypassDirect { .. }
        ));
        assert_eq!(
            policy.resolve_route_for_request(Some(42), Some("work"), "news.bbc.co.uk"),
            RouteDecision::MullvadRelay {
                relay_hostname: "gb-lon-wg-002".into(),
                source: RouteSource::DomainRule,
            }
        );
        assert!(matches!(
            policy.resolve_route_for_request(Some(42), Some("work"), "telemetry.evil.test"),
            RouteDecision::Blocked { .. }
        ));

        // 3. Tab override beats container rule
        assert_eq!(
            policy.resolve_route_for_request(Some(42), Some("work"), "example.com"),
            RouteDecision::MullvadRelay {
                relay_hostname: "is-rek-wg-001".into(),
                source: RouteSource::TabOverride,
            }
        );

        // 4. Container rule beats default relay
        assert_eq!(
            policy.resolve_route_for_request(Some(7), Some("work"), "example.com"),
            RouteDecision::MullvadRelay {
                relay_hostname: "de-fra-wg-003".into(),
                source: RouteSource::ContainerRule,
            }
        );
        assert!(matches!(
            policy.resolve_route_for_request(Some(7), Some("direct-lab"), "example.com"),
            RouteDecision::BypassDirect { .. }
        ));

        // 5. Default relay fallback
        assert_eq!(
            policy.resolve_route_for_request(Some(99), Some("personal"), "example.com"),
            RouteDecision::MullvadRelay {
                relay_hostname: "ch-zrh-wg-001".into(),
                source: RouteSource::DefaultTunnel,
            }
        );

        // Disabled Tor config fails closed for `.onion`
        policy.tor_onion_config = Some(TorOnionProxyConfig::default());
        assert!(matches!(
            policy.resolve_route_for_request(None, None, "examplehiddenservice.onion"),
            RouteDecision::Blocked { .. }
        ));
    }

    #[test]
    fn test_loopback_socks5_rfc1928_rfc1929_and_killswitch_enforcement() {
        let (echo_port, echo_handle) = spawn_loopback_echo_server();

        let ks = Arc::new(AtomicSocketKillSwitch::new(true, true));
        let policy = SplitTunnelPolicy {
            domain_rules: vec![SplitTunnelRule::block("blocked.example")],
            default_relay_hostname: Some("ch-zrh-wg-001".into()),
            ..Default::default()
        };

        let mut bridge = LoopbackProxyBridge::new(Arc::clone(&ks), policy, HashMap::new());
        assert!(!bridge.is_running());
        assert_eq!(bridge.running_port(), None);

        let port = bridge.start().expect("start loopback proxy bridge");
        assert!(bridge.is_running());
        assert_eq!(bridge.running_port(), Some(port));

        // Debug representation must redact the ephemeral session token
        let dbg = format!("{:?}", bridge);
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains(bridge.session_token()));

        // (A) Invalid RFC 1929 session token MUST be rejected with status 0x01
        {
            let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
            client.write_all(&[0x05, 0x01, 0x02]).unwrap();
            let mut m = [0u8; 2];
            client.read_exact(&mut m).unwrap();
            assert_eq!(m, [0x05, 0x02]);

            let uname = b"singularity";
            let bad_pass = b"wrong-token";
            let mut auth = vec![0x01, uname.len() as u8];
            auth.extend_from_slice(uname);
            auth.push(bad_pass.len() as u8);
            auth.extend_from_slice(bad_pass);
            client.write_all(&auth).unwrap();

            let mut resp = [0u8; 2];
            client.read_exact(&mut resp).unwrap();
            assert_eq!(resp, [0x01, 0x01]);
        }
        assert!(bridge.auth_failures() >= 1);

        // (B) Valid auth, but strict Kill-Switch is disconnected -> MUST return REP = 0x02
        {
            let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
            client.write_all(&[0x05, 0x01, 0x02]).unwrap();
            let mut m = [0u8; 2];
            client.read_exact(&mut m).unwrap();
            assert_eq!(m, [0x05, 0x02]);

            let uname = bridge.session_username().as_bytes();
            let tok = bridge.session_token().as_bytes();
            let mut auth = vec![0x01, uname.len() as u8];
            auth.extend_from_slice(uname);
            auth.push(tok.len() as u8);
            auth.extend_from_slice(tok);
            client.write_all(&auth).unwrap();
            let mut aresp = [0u8; 2];
            client.read_exact(&mut aresp).unwrap();
            assert_eq!(aresp, [0x01, 0x00]);

            // CONNECT to example.com:443 via ATYP=0x03 (SOCKS5h domain)
            let domain = b"example.com";
            let mut req = vec![0x05, 0x01, 0x00, 0x03, domain.len() as u8];
            req.extend_from_slice(domain);
            req.extend_from_slice(&443u16.to_be_bytes());
            client.write_all(&req).unwrap();

            let mut rep = [0u8; 10];
            client.read_exact(&mut rep).unwrap();
            assert_eq!(rep[0], 0x05);
            assert_eq!(rep[1], 0x02, "Kill-switch disconnected must yield REP=0x02");
        }
        assert!(bridge.blocked_requests() >= 1);

        // (C) Tunnel connected + LAN allowed for local echo server test -> full SOCKS5 tunnel relay!
        ks.set_tunnel_established(true);
        ks.set_block_lan_rfc1918(false);
        {
            let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
            client.write_all(&[0x05, 0x02, 0x00, 0x02]).unwrap();
            let mut m = [0u8; 2];
            client.read_exact(&mut m).unwrap();
            assert_eq!(m, [0x05, 0x02]);

            let scoped_user = bridge.format_scoped_username(Some(12), Some("work"));
            let uname = scoped_user.as_bytes();
            let tok = bridge.session_token().as_bytes();
            let mut auth = vec![0x01, uname.len() as u8];
            auth.extend_from_slice(uname);
            auth.push(tok.len() as u8);
            auth.extend_from_slice(tok);
            client.write_all(&auth).unwrap();
            let mut aresp = [0u8; 2];
            client.read_exact(&mut aresp).unwrap();
            assert_eq!(aresp, [0x01, 0x00]);

            // CONNECT to 127.0.0.1:<echo_port>
            let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
            req.extend_from_slice(&echo_port.to_be_bytes());
            client.write_all(&req).unwrap();

            let mut rep = [0u8; 10];
            client.read_exact(&mut rep).unwrap();
            assert_eq!(rep[0], 0x05);
            assert_eq!(rep[1], 0x00, "Expected SOCKS5 CONNECT success");

            let payload = b"Singularity SOCKS5h loopback echo test payload!";
            client.write_all(payload).unwrap();
            client.shutdown(Shutdown::Write).unwrap();

            let mut echoed = Vec::new();
            client.read_to_end(&mut echoed).unwrap();
            assert_eq!(echoed, payload);
        }

        let _ = echo_handle.join();
        // Wait briefly for relay thread counters to flush
        thread::sleep(Duration::from_millis(30));
        assert!(bridge.bytes_sent() >= 47);
        assert!(bridge.bytes_received() >= 47);

        bridge.stop();
        assert!(!bridge.is_running());
        assert_eq!(bridge.running_port(), None);
    }

    #[test]
    fn test_loopback_http_connect_auth_killswitch_and_relay() {
        let (echo_port, echo_handle) = spawn_loopback_echo_server();

        let ks = Arc::new(AtomicSocketKillSwitch::new(true, true));
        let mut bridge = LoopbackProxyBridge::new(
            Arc::clone(&ks),
            SplitTunnelPolicy::default(),
            HashMap::new(),
        );
        let port = bridge.start().expect("start bridge");

        // (A) Missing Proxy-Authorization -> 407 Proxy Authentication Required
        {
            let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
            let req = format!(
                "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
                echo_port, echo_port
            );
            client.write_all(req.as_bytes()).unwrap();
            let mut resp = String::new();
            client.read_to_string(&mut resp).unwrap();
            assert!(resp.starts_with("HTTP/1.1 407 Proxy Authentication Required"));
        }

        // (B) Valid Proxy-Authorization, but kill-switch LAN block + tunnel down -> 403 Forbidden
        let auth_b64 = BASE64.encode(format!(
            "{}:{}",
            bridge.session_username(),
            bridge.session_token()
        ));
        {
            let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
            let req = format!(
                "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nProxy-Authorization: Basic {}\r\n\r\n",
                echo_port, echo_port, auth_b64
            );
            client.write_all(req.as_bytes()).unwrap();
            let mut resp = String::new();
            client.read_to_string(&mut resp).unwrap();
            assert!(resp.starts_with("HTTP/1.1 403 Forbidden"));
        }

        // (C) Tunnel connected & LAN allowed -> 200 Connection Established + full relay
        ks.set_tunnel_established(true);
        ks.set_block_lan_rfc1918(false);
        {
            let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
            let req = format!(
                "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nProxy-Authorization: Basic {}\r\n\r\n",
                echo_port, echo_port, auth_b64
            );
            client.write_all(req.as_bytes()).unwrap();

            // Read up to \r\n\r\n
            let mut hdr = Vec::new();
            let mut b = [0u8; 1];
            while !hdr.ends_with(b"\r\n\r\n") {
                client.read_exact(&mut b).unwrap();
                hdr.push(b[0]);
            }
            let hdr_str = std::str::from_utf8(&hdr).unwrap();
            assert!(hdr_str.starts_with("HTTP/1.1 200 Connection Established"));

            let msg = b"HTTP CONNECT tunnel bytes";
            client.write_all(msg).unwrap();
            client.shutdown(Shutdown::Write).unwrap();

            let mut echoed = Vec::new();
            client.read_to_end(&mut echoed).unwrap();
            assert_eq!(echoed, msg);
        }

        let _ = echo_handle.join();
        thread::sleep(Duration::from_millis(30));
        assert!(bridge.bytes_sent() >= 25);
        assert!(bridge.bytes_received() >= 25);

        bridge.stop();
    }

    #[test]
    fn test_loopback_split_tunnel_block_socks4a_chaining_and_pac_offline_json() {
        // Offline PAC cached script -> base64 data URI in CEF JSON
        let offline_pac = ProxyProfileConfig::pac(
            "",
            Some("function FindProxyForURL(url, host) { return \"DIRECT\"; }".into()),
        );
        let pac_json = offline_pac.to_cef_proxy_pref_json();
        assert!(pac_json.contains(r#""mode":"pac_script""#));
        assert!(pac_json.contains("data:application/x-ns-proxy-autoconfig;base64,"));
        assert!(pac_json.contains(r#""pac_mandatory":true"#));

        // IPv6 manual proxy address gets properly bracketed in CEF JSON
        let ipv6_proxy = ProxyProfileConfig::manual(
            ProxyScheme::Socks5h,
            "::1",
            1080,
            true,
            None,
            None,
            vec!["<local>".into()],
        );
        assert!(ipv6_proxy.should_bypass("intranet"));
        assert!(ipv6_proxy.should_bypass("127.0.0.1"));
        assert!(ipv6_proxy
            .to_cef_proxy_pref_json()
            .contains(r#""server":"socks5://[::1]:1080""#));

        // Mock SOCKS4a server validating 0.0.0.1 remote DNS sentinel & echoing payload
        let mock_socks4 = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind mock socks4a");
        let mock_socks4_port = mock_socks4.local_addr().unwrap().port();
        let socks4_handle = thread::spawn(move || {
            let (mut s, _) = mock_socks4.accept().expect("accept bridge->socks4a");
            let mut hdr = [0u8; 8];
            s.read_exact(&mut hdr).unwrap();
            assert_eq!(hdr[0], 0x04);
            assert_eq!(hdr[1], 0x01);
            assert_eq!(u16::from_be_bytes([hdr[2], hdr[3]]), 443);
            assert_eq!(&hdr[4..8], &[0, 0, 0, 1]);

            let read_cstr = |stream: &mut TcpStream| -> String {
                let mut out = Vec::new();
                let mut b = [0u8; 1];
                loop {
                    stream.read_exact(&mut b).unwrap();
                    if b[0] == 0 {
                        break;
                    }
                    out.push(b[0]);
                }
                String::from_utf8(out).unwrap()
            };
            assert_eq!(read_cstr(&mut s), "corpuser");
            assert_eq!(read_cstr(&mut s), "partner.example.org");

            // Grant request (VN=0x00, CD=0x5A)
            s.write_all(&[0x00, 0x5A, 0x01, 0xBB, 127, 0, 0, 1]).unwrap();
            let mut buf = [0u8; 1024];
            while let Ok(n) = s.read(&mut buf) {
                if n == 0 {
                    break;
                }
                s.write_all(&buf[..n]).unwrap();
            }
        });

        let ks = Arc::new(AtomicSocketKillSwitch::new(true, true));
        ks.set_tunnel_established(true);

        let policy = SplitTunnelPolicy {
            domain_rules: vec![SplitTunnelRule::block("blocked.example")],
            container_rules: HashMap::from([(
                "corp-socks4".into(),
                SplitTunnelTarget::UseProxyProfile("socks4-gw".into()),
            )]),
            default_relay_hostname: Some("ch-zrh-wg-001".into()),
            ..Default::default()
        };
        let profiles = HashMap::from([(
            "socks4-gw".into(),
            ProxyProfileConfig::manual(
                ProxyScheme::Socks4,
                "127.0.0.1",
                mock_socks4_port,
                true,
                Some("corpuser".into()),
                None,
                Vec::new(),
            ),
        )]);

        let mut bridge = LoopbackProxyBridge::new(Arc::clone(&ks), policy, profiles);
        let bridge_port = bridge.start().expect("start bridge");

        // (1) Domain blocked by SplitTunnelRule MUST fail with REP=0x02 even when tunnel is up
        {
            let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, bridge_port)).unwrap();
            client.write_all(&[0x05, 0x01, 0x02]).unwrap();
            let mut m = [0u8; 2];
            client.read_exact(&mut m).unwrap();
            assert_eq!(m, [0x05, 0x02]);

            let uname = bridge.session_username().as_bytes();
            let tok = bridge.session_token().as_bytes();
            let mut auth = vec![0x01, uname.len() as u8];
            auth.extend_from_slice(uname);
            auth.push(tok.len() as u8);
            auth.extend_from_slice(tok);
            client.write_all(&auth).unwrap();
            let mut aresp = [0u8; 2];
            client.read_exact(&mut aresp).unwrap();
            assert_eq!(aresp, [0x01, 0x00]);

            let dom = b"blocked.example";
            let mut req = vec![0x05, 0x01, 0x00, 0x03, dom.len() as u8];
            req.extend_from_slice(dom);
            req.extend_from_slice(&443u16.to_be_bytes());
            client.write_all(&req).unwrap();

            let mut rep = [0u8; 10];
            client.read_exact(&mut rep).unwrap();
            assert_eq!(rep[1], 0x02, "SplitTunnelRule::block must yield REP=0x02");
        }

        // (2) Container-scoped SOCKS5h request routes via SOCKS4a upstream proxy profile
        {
            let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, bridge_port)).unwrap();
            client.write_all(&[0x05, 0x01, 0x02]).unwrap();
            let mut m = [0u8; 2];
            client.read_exact(&mut m).unwrap();
            assert_eq!(m, [0x05, 0x02]);

            let scoped = bridge.format_scoped_username(None, Some("corp-socks4"));
            let mut auth = vec![0x01, scoped.len() as u8];
            auth.extend_from_slice(scoped.as_bytes());
            auth.push(bridge.session_token().len() as u8);
            auth.extend_from_slice(bridge.session_token().as_bytes());
            client.write_all(&auth).unwrap();
            let mut aresp = [0u8; 2];
            client.read_exact(&mut aresp).unwrap();
            assert_eq!(aresp, [0x01, 0x00]);

            let dom = b"partner.example.org";
            let mut req = vec![0x05, 0x01, 0x00, 0x03, dom.len() as u8];
            req.extend_from_slice(dom);
            req.extend_from_slice(&443u16.to_be_bytes());
            client.write_all(&req).unwrap();

            let mut rep = [0u8; 10];
            client.read_exact(&mut rep).unwrap();
            assert_eq!(rep[1], 0x00, "Expected SOCKS4a proxy profile chaining success");

            let msg = b"SOCKS4a chained payload";
            client.write_all(msg).unwrap();
            client.shutdown(Shutdown::Write).unwrap();
            let mut echoed = Vec::new();
            client.read_to_end(&mut echoed).unwrap();
            assert_eq!(echoed, msg);
        }

        socks4_handle.join().expect("mock socks4a exited cleanly");
        bridge.stop();
    }
}
