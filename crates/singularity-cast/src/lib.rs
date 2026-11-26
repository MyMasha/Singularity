//! `singularity-cast` — Privacy-First Opt-In Local Media Casting Controller.
//!
//! Zero passive LAN reconnaissance:
//! - Guarantees **zero active multicast/UDP discovery sockets at rest** (`is_discovery_active() == false`
//!   and `active_socket_count() == 0` by default).
//! - SSDP/UPnP (`239.255.255.250:1900`) and mDNS (`224.0.0.251:5353`) probing activates
//!   exclusively inside an explicit user-triggered `begin_user_discovery_session()` window and
//!   closes all sockets immediately at `end_discovery_session()` (or on `Drop`).
//! - Provides targeted single-host (`/32` or `/128`) Mullvad Kill-Switch LAN exception helpers
//!   authorizing ONLY the unicast IP/port of the user-selected receiver.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket};
use thiserror::Error;

/// Standard SSDP multicast address (`239.255.255.250:1900`).
pub const SSDP_MULTICAST_ADDR: &str = "239.255.255.250:1900";
/// Standard mDNS multicast address (`224.0.0.251:5353`).
pub const MDNS_MULTICAST_ADDR: &str = "224.0.0.251:5353";
/// Default mDNS service type for Chromecast receivers.
pub const MDNS_SERVICE_CHROMECAST: &str = "_googlecast._tcp.local";
/// Default mDNS service type for AirPlay receivers.
pub const MDNS_SERVICE_AIRPLAY: &str = "_airplay._tcp.local";
/// Default SSDP search target for DLNA/UPnP MediaRenderer devices.
pub const SSDP_ST_MEDIA_RENDERER: &str = "urn:schemas-upnp-org:device:MediaRenderer:1";
/// Default SSDP search target for DIAL (Chromecast/Smart TV) devices.
pub const SSDP_ST_DIAL: &str = "urn:dial-multiscreen-org:service:dial:1";

const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_PTR: u16 = 12;
const DNS_TYPE_TXT: u16 = 16;
const DNS_TYPE_AAAA: u16 = 28;
const DNS_TYPE_SRV: u16 = 33;
const DNS_CLASS_IN: u16 = 1;
const MAX_DNS_COMPRESSION_HOPS: usize = 16;

#[derive(Debug, Error, PartialEq)]
pub enum CastError {
    #[error("Discovery session is inactive; call begin_user_discovery_session() first")]
    DiscoveryInactive,
    #[error("Device '{0}' was not found in discovered receivers")]
    DeviceNotFound(String),
    #[error("No active cast receiver connected")]
    NoActiveSession,
    #[error("Receiver IP {0} is not a private/local LAN address (refusing non-LAN cast target)")]
    NonLocalReceiverIp(IpAddr),
    #[error("Unsupported or unsafe media URL '{0}' (only http:// and https:// URLs are permitted)")]
    InvalidMediaUrl(String),
    #[error("Invalid playback parameter: {0}")]
    InvalidParameter(String),
    #[error("Malformed SSDP packet: {0}")]
    MalformedSsdp(String),
    #[error("Malformed mDNS packet: {0}")]
    MalformedMdns(String),
    #[error("Socket I/O error: {0}")]
    SocketIo(String),
}

/// Local casting protocols supported by Singularity Browser.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CastProtocol {
    Chromecast,
    DlnaUpnp,
    AirPlay,
}

impl CastProtocol {
    pub fn default_port(&self) -> u16 {
        match self {
            Self::Chromecast => 8009,
            Self::DlnaUpnp => 1400,
            Self::AirPlay => 7000,
        }
    }
}

/// Discovered local network casting receiver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CastDevice {
    pub id: String,
    pub friendly_name: String,
    pub protocol: CastProtocol,
    pub ip_addr: IpAddr,
    pub port: u16,
    pub model_name: Option<String>,
    pub location_url: Option<String>,
    pub service_type: Option<String>,
    pub discovered_at_ms: u64,
}

/// Playback session state tracked by `OptInCastController`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CastSessionState {
    Idle,
    Connecting {
        device_id: String,
    },
    Playing {
        device_id: String,
        media_url: String,
        title: String,
        position_sec: f64,
        volume: f32,
    },
    Paused {
        device_id: String,
        media_url: String,
        title: String,
        position_sec: f64,
        volume: f32,
    },
    Stopped {
        device_id: String,
    },
    Error(String),
}

/// Media playback control command issued to the active local cast receiver.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CastPlaybackCommand {
    LoadMedia {
        url: String,
        title: String,
        content_type: String,
        start_position_sec: f64,
    },
    Play,
    Pause,
    Seek(f64),
    SetVolume(f32),
    Stop,
}

/// Protocol-specific wire command serialized for the selected receiver transport.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CastWireCommand {
    pub protocol: CastProtocol,
    pub target_ip: IpAddr,
    pub target_port: u16,
    pub endpoint_hint: String,
    pub payload: String,
}

/// Single-host LAN firewall exception descriptor for Mullvad Kill-Switch integration.
///
/// Strictly scoped to a single receiver IP (`/32` IPv4 or `/128` IPv6) with `allow_multicast = false`
/// so enabling casting never opens the entire LAN subnet or leaks background multicast traffic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MullvadLanException {
    pub device_id: String,
    pub protocol: CastProtocol,
    pub target_ip: IpAddr,
    pub target_port: u16,
    /// Strict single-host CIDR (`x.x.x.x/32` or `xxxx::xxxx/128`).
    pub single_host_cidr: String,
    /// Always `false`: exception permits unicast to the chosen receiver only.
    pub allow_multicast: bool,
}

/// Parsed question entry from an mDNS query packet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MdnsQuestion {
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
    pub unicast_response: bool,
}

struct ActiveDiscoveryHandle {
    /// Ephemeral non-blocking UDP probe socket; dropped immediately on `end_discovery_session()`.
    ephemeral_socket: Option<UdpSocket>,
    started_at_ms: u64,
    queries_emitted: u32,
}

/// Opt-in local media casting controller guaranteeing zero passive mDNS/SSDP sockets at rest.
pub struct OptInCastController {
    discovery: Option<ActiveDiscoveryHandle>,
    discovered_devices: BTreeMap<String, CastDevice>,
    active_device_id: Option<String>,
    session_state: CastSessionState,
    current_volume: f32,
}

impl Default for OptInCastController {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for OptInCastController {
    fn drop(&mut self) {
        self.end_discovery_session();
    }
}

impl OptInCastController {
    /// Creates a new controller in completely silent resting state:
    /// `is_discovery_active() == false` and zero open sockets.
    pub fn new() -> Self {
        Self {
            discovery: None,
            discovered_devices: BTreeMap::new(),
            active_device_id: None,
            session_state: CastSessionState::Idle,
            current_volume: 1.0,
        }
    }

    /// Returns `true` ONLY during an explicit user-triggered discovery session.
    /// Always `false` at rest.
    pub fn is_discovery_active(&self) -> bool {
        self.discovery.is_some()
    }

    /// Returns the number of live UDP discovery sockets currently held by this controller
    /// (guaranteed `0` at rest and immediately `0` after `end_discovery_session()`).
    pub fn active_socket_count(&self) -> usize {
        self.discovery
            .as_ref()
            .and_then(|d| d.ephemeral_socket.as_ref())
            .map(|_| 1)
            .unwrap_or(0)
    }

    pub fn session_state(&self) -> &CastSessionState {
        &self.session_state
    }

    pub fn discovered_devices(&self) -> Vec<&CastDevice> {
        self.discovered_devices.values().collect()
    }

    pub fn active_device(&self) -> Option<&CastDevice> {
        self.active_device_id
            .as_deref()
            .and_then(|id| self.discovered_devices.get(id))
    }

    /// Explicitly opens a short-lived user-initiated discovery session (SSDP + mDNS).
    /// Binds a single ephemeral non-blocking UDP socket (`0.0.0.0:0`) with no persistent listener.
    pub fn begin_user_discovery_session(&mut self, now_ms: u64) -> Result<Vec<Vec<u8>>, CastError> {
        if self.discovery.is_none() {
            let socket = UdpSocket::bind("0.0.0.0:0")
                .map_err(|e| CastError::SocketIo(e.to_string()))?;
            let _ = socket.set_nonblocking(true);
            self.discovery = Some(ActiveDiscoveryHandle {
                ephemeral_socket: Some(socket),
                started_at_ms: now_ms,
                queries_emitted: 0,
            });
        }

        let probes = vec![
            build_ssdp_msearch_request(SSDP_ST_MEDIA_RENDERER, 2),
            build_ssdp_msearch_request(SSDP_ST_DIAL, 2),
            build_mdns_ptr_query(MDNS_SERVICE_CHROMECAST)?,
            build_mdns_ptr_query(MDNS_SERVICE_AIRPLAY)?,
        ];

        if let Some(handle) = self.discovery.as_mut() {
            handle.queries_emitted = handle.queries_emitted.saturating_add(probes.len() as u32);
        }
        Ok(probes)
    }

    /// Returns the timestamp when the current discovery session began, if active.
    pub fn discovery_started_at_ms(&self) -> Option<u64> {
        self.discovery.as_ref().map(|d| d.started_at_ms)
    }

    /// Immediately closes any active discovery socket and returns the controller to silent resting state.
    pub fn end_discovery_session(&mut self) {
        if let Some(mut handle) = self.discovery.take() {
            handle.ephemeral_socket.take();
        }
    }

    /// Parses and registers an SSDP `M-SEARCH` response ONLY while discovery is explicitly active.
    pub fn ingest_ssdp_packet(
        &mut self,
        raw: &[u8],
        source_ip: IpAddr,
        now_ms: u64,
    ) -> Result<CastDevice, CastError> {
        if !self.is_discovery_active() {
            return Err(CastError::DiscoveryInactive);
        }
        let device = parse_ssdp_response(raw, source_ip, now_ms)?;
        if !is_local_lan_ip(device.ip_addr) {
            return Err(CastError::NonLocalReceiverIp(device.ip_addr));
        }
        self.discovered_devices
            .insert(device.id.clone(), device.clone());
        Ok(device)
    }

    /// Parses and registers mDNS response records ONLY while discovery is explicitly active.
    pub fn ingest_mdns_packet(
        &mut self,
        raw: &[u8],
        source_ip: IpAddr,
        now_ms: u64,
    ) -> Result<Vec<CastDevice>, CastError> {
        if !self.is_discovery_active() {
            return Err(CastError::DiscoveryInactive);
        }
        let devices = parse_mdns_response(raw, source_ip, now_ms)?;
        let mut accepted = Vec::new();
        for device in devices {
            if is_local_lan_ip(device.ip_addr) {
                self.discovered_devices
                    .insert(device.id.clone(), device.clone());
                accepted.push(device);
            }
        }
        Ok(accepted)
    }

    /// Selects a discovered local LAN receiver, closes the discovery session immediately,
    /// and prepares an active unicast cast session.
    pub fn connect_device(&mut self, device_id: &str) -> Result<MullvadLanException, CastError> {
        let device = self
            .discovered_devices
            .get(device_id)
            .ok_or_else(|| CastError::DeviceNotFound(device_id.to_string()))?
            .clone();

        let exception = mullvad_lan_exception_for_device(&device)
            .ok_or(CastError::NonLocalReceiverIp(device.ip_addr))?;

        // Close discovery sockets as soon as the user picks a receiver
        self.end_discovery_session();
        self.active_device_id = Some(device.id.clone());
        self.session_state = CastSessionState::Connecting {
            device_id: device.id,
        };
        Ok(exception)
    }

    /// Disconnects the current receiver and revokes any targeted Mullvad LAN exception.
    pub fn disconnect(&mut self) {
        self.active_device_id = None;
        self.session_state = CastSessionState::Idle;
    }

    /// Returns the targeted single-host Mullvad Kill-Switch LAN exception for the currently
    /// selected receiver, or `None` when no local LAN receiver is active.
    pub fn mullvad_lan_exception_target(&self) -> Option<MullvadLanException> {
        let device = self.active_device()?;
        mullvad_lan_exception_for_device(device)
    }

    /// Applies a `CastPlaybackCommand` to the active session and renders the protocol wire payload.
    pub fn send_command(
        &mut self,
        command: CastPlaybackCommand,
    ) -> Result<CastWireCommand, CastError> {
        let device = self
            .active_device()
            .ok_or(CastError::NoActiveSession)?
            .clone();

        match &command {
            CastPlaybackCommand::LoadMedia {
                url,
                title,
                start_position_sec,
                ..
            } => {
                validate_media_url(url)?;
                if !start_position_sec.is_finite() || *start_position_sec < 0.0 {
                    return Err(CastError::InvalidParameter(
                        "start_position_sec must be finite and >= 0.0".into(),
                    ));
                }
                self.session_state = CastSessionState::Playing {
                    device_id: device.id.clone(),
                    media_url: url.clone(),
                    title: title.clone(),
                    position_sec: *start_position_sec,
                    volume: self.current_volume,
                };
            }
            CastPlaybackCommand::Play => match &self.session_state {
                CastSessionState::Paused {
                    device_id,
                    media_url,
                    title,
                    position_sec,
                    volume,
                } => {
                    self.session_state = CastSessionState::Playing {
                        device_id: device_id.clone(),
                        media_url: media_url.clone(),
                        title: title.clone(),
                        position_sec: *position_sec,
                        volume: *volume,
                    };
                }
                CastSessionState::Playing { .. } => {}
                _ => {
                    return Err(CastError::InvalidParameter(
                        "Cannot Play before LoadMedia".into(),
                    ));
                }
            },
            CastPlaybackCommand::Pause => match &self.session_state {
                CastSessionState::Playing {
                    device_id,
                    media_url,
                    title,
                    position_sec,
                    volume,
                } => {
                    self.session_state = CastSessionState::Paused {
                        device_id: device_id.clone(),
                        media_url: media_url.clone(),
                        title: title.clone(),
                        position_sec: *position_sec,
                        volume: *volume,
                    };
                }
                CastSessionState::Paused { .. } => {}
                _ => {
                    return Err(CastError::InvalidParameter(
                        "Cannot Pause before LoadMedia".into(),
                    ));
                }
            },
            CastPlaybackCommand::Seek(pos) => {
                if !pos.is_finite() || *pos < 0.0 {
                    return Err(CastError::InvalidParameter(
                        "Seek position must be finite and >= 0.0".into(),
                    ));
                }
                match &mut self.session_state {
                    CastSessionState::Playing { position_sec, .. }
                    | CastSessionState::Paused { position_sec, .. } => {
                        *position_sec = *pos;
                    }
                    _ => {
                        return Err(CastError::InvalidParameter(
                            "Cannot Seek without loaded media".into(),
                        ));
                    }
                }
            }
            CastPlaybackCommand::SetVolume(vol) => {
                if !vol.is_finite() {
                    return Err(CastError::InvalidParameter(
                        "Volume must be a finite float".into(),
                    ));
                }
                let clamped = vol.clamp(0.0, 1.0);
                self.current_volume = clamped;
                match &mut self.session_state {
                    CastSessionState::Playing { volume, .. }
                    | CastSessionState::Paused { volume, .. } => {
                        *volume = clamped;
                    }
                    _ => {}
                }
            }
            CastPlaybackCommand::Stop => {
                self.session_state = CastSessionState::Stopped {
                    device_id: device.id.clone(),
                };
            }
        }

        Ok(build_protocol_wire_command(&device, &command))
    }
}

/// Returns `true` iff `ip` is a local unicast LAN address (RFC 1918 IPv4, IPv4 link-local,
/// IPv6 ULA `fc00::/7`, or IPv6 link-local `fe80::/10`) and NOT multicast/broadcast/unspecified/public.
pub fn is_local_lan_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !v4.is_unspecified()
                && !v4.is_broadcast()
                && !v4.is_multicast()
                && !v4.is_loopback()
                && (v4.is_private() || v4.is_link_local())
        }
        IpAddr::V6(v6) => {
            if v6.is_unspecified() || v6.is_multicast() || v6.is_loopback() {
                return false;
            }
            if let Some(mapped_v4) = v6.to_ipv4_mapped() {
                return is_local_lan_ip(IpAddr::V4(mapped_v4));
            }
            let seg0 = v6.segments()[0];
            let is_ula = (seg0 & 0xFE00) == 0xFC00;
            let is_link_local = (seg0 & 0xFFC0) == 0xFE80;
            is_ula || is_link_local
        }
    }
}

/// Builds a strict single-host (`/32` or `/128`) Mullvad Kill-Switch LAN exception for `device`,
/// returning `None` if `device.ip_addr` is not a genuine local LAN unicast IP.
pub fn mullvad_lan_exception_for_device(device: &CastDevice) -> Option<MullvadLanException> {
    if !is_local_lan_ip(device.ip_addr) {
        return None;
    }
    let single_host_cidr = match device.ip_addr {
        IpAddr::V4(v4) => format!("{v4}/32"),
        IpAddr::V6(v6) => format!("{v6}/128"),
    };
    Some(MullvadLanException {
        device_id: device.id.clone(),
        protocol: device.protocol,
        target_ip: device.ip_addr,
        target_port: device.port,
        single_host_cidr,
        allow_multicast: false,
    })
}

/// Builds an RFC/UPnP SSDP `M-SEARCH` UDP request datagram for `search_target`.
pub fn build_ssdp_msearch_request(search_target: &str, mx_secs: u8) -> Vec<u8> {
    let mx = mx_secs.clamp(1, 5);
    format!(
        "M-SEARCH * HTTP/1.1\r\n\
         HOST: {SSDP_MULTICAST_ADDR}\r\n\
         MAN: \"ssdp:discover\"\r\n\
         MX: {mx}\r\n\
         ST: {search_target}\r\n\
         USER-AGENT: Singularity/2.0 UPnP/1.1\r\n\
         \r\n"
    )
    .into_bytes()
}

/// Parses an SSDP `HTTP/1.1 200 OK` or `NOTIFY * HTTP/1.1` UPnP/DIAL response into a `CastDevice`.
pub fn parse_ssdp_response(
    raw: &[u8],
    source_ip: IpAddr,
    now_ms: u64,
) -> Result<CastDevice, CastError> {
    let text = std::str::from_utf8(raw)
        .map_err(|_| CastError::MalformedSsdp("Response is not valid UTF-8".into()))?;
    let mut lines = text.lines();
    let status_line = lines
        .next()
        .ok_or_else(|| CastError::MalformedSsdp("Empty SSDP response".into()))?
        .trim();

    let upper_status = status_line.to_ascii_uppercase();
    if !(upper_status.starts_with("HTTP/1.1 200")
        || upper_status.starts_with("HTTP/1.0 200")
        || upper_status.starts_with("NOTIFY * HTTP/1.1"))
    {
        return Err(CastError::MalformedSsdp(format!(
            "Unsupported SSDP start line: '{status_line}'"
        )));
    }

    let mut headers: BTreeMap<String, String> = BTreeMap::new();
    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }
        if let Some((k, v)) = trimmed.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }

    let location = headers.get("location").cloned();
    let st = headers
        .get("st")
        .or_else(|| headers.get("nt"))
        .cloned();
    let usn = headers.get("usn").cloned();
    let server = headers.get("server").cloned();

    if location.is_none() && usn.is_none() && st.is_none() {
        return Err(CastError::MalformedSsdp(
            "Missing required LOCATION / USN / ST headers".into(),
        ));
    }

    let combined_hints = format!(
        "{} {} {}",
        st.as_deref().unwrap_or(""),
        server.as_deref().unwrap_or(""),
        usn.as_deref().unwrap_or("")
    )
    .to_ascii_lowercase();

    let protocol = if combined_hints.contains("dial-multiscreen")
        || combined_hints.contains("googlecast")
        || combined_hints.contains("eureka")
        || combined_hints.contains("chromecast")
    {
        CastProtocol::Chromecast
    } else if combined_hints.contains("airplay") || combined_hints.contains("raop") {
        CastProtocol::AirPlay
    } else {
        CastProtocol::DlnaUpnp
    };

    let (ip_addr, port) = location
        .as_deref()
        .and_then(extract_ip_and_port_from_http_url)
        .unwrap_or((source_ip, protocol.default_port()));

    let id = usn
        .as_deref()
        .map(|u| u.split("::").next().unwrap_or(u).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("ssdp-{ip_addr}-{port}"));

    let friendly_name = headers
        .get("friendlyname.dlna.org")
        .cloned()
        .or_else(|| {
            server.as_deref().map(|s| {
                s.split_whitespace()
                    .last()
                    .unwrap_or("UPnP Receiver")
                    .to_string()
            })
        })
        .unwrap_or_else(|| format!("{protocol:?} ({ip_addr})"));

    let model_name = headers.get("modelname.dlna.org").cloned().or(server);

    Ok(CastDevice {
        id,
        friendly_name,
        protocol,
        ip_addr,
        port,
        model_name,
        location_url: location,
        service_type: st,
        discovered_at_ms: now_ms,
    })
}

/// Builds an RFC 6762 mDNS PTR query packet for a service name (e.g., `_googlecast._tcp.local`).
pub fn build_mdns_ptr_query(service_name: &str) -> Result<Vec<u8>, CastError> {
    let trimmed = service_name.trim().trim_end_matches('.');
    if trimmed.is_empty() {
        return Err(CastError::MalformedMdns("Empty service name".into()));
    }

    let mut pkt = Vec::with_capacity(64);
    // 12-byte DNS header: ID=0, Flags=0 (standard query), QDCOUNT=1, AN/NS/AR=0
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());

    for label in trimmed.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(CastError::MalformedMdns(format!(
                "Invalid DNS label '{label}' in '{service_name}'"
            )));
        }
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0x00); // Root label terminator

    pkt.extend_from_slice(&DNS_TYPE_PTR.to_be_bytes());
    // Request unicast-response bit (QU = 0x8000 | IN) to minimize LAN multicast chatter
    let qu_in = 0x8000u16 | DNS_CLASS_IN;
    pkt.extend_from_slice(&qu_in.to_be_bytes());
    Ok(pkt)
}

/// Parses the Question section of an mDNS query packet.
pub fn parse_mdns_query(raw: &[u8]) -> Result<Vec<MdnsQuestion>, CastError> {
    if raw.len() < 12 {
        return Err(CastError::MalformedMdns(
            "Packet shorter than 12-byte DNS header".into(),
        ));
    }
    let qdcount = u16::from_be_bytes([raw[4], raw[5]]) as usize;
    let mut offset = 12usize;
    let mut questions = Vec::with_capacity(qdcount.min(32));

    for _ in 0..qdcount {
        let (qname, next_off) = read_dns_name(raw, offset)?;
        offset = next_off;
        if offset + 4 > raw.len() {
            return Err(CastError::MalformedMdns("Truncated mDNS question".into()));
        }
        let qtype = u16::from_be_bytes([raw[offset], raw[offset + 1]]);
        let raw_qclass = u16::from_be_bytes([raw[offset + 2], raw[offset + 3]]);
        offset += 4;
        questions.push(MdnsQuestion {
            qname,
            qtype,
            qclass: raw_qclass & 0x7FFF,
            unicast_response: (raw_qclass & 0x8000) != 0,
        });
    }
    Ok(questions)
}

/// Parses an RFC 6762 mDNS response packet (`PTR`, `SRV`, `TXT`, `A`, `AAAA`) into discovered
/// Chromecast / AirPlay `CastDevice` entries, with full DNS compression pointer loop protection.
pub fn parse_mdns_response(
    raw: &[u8],
    source_ip: IpAddr,
    now_ms: u64,
) -> Result<Vec<CastDevice>, CastError> {
    if raw.len() < 12 {
        return Err(CastError::MalformedMdns(
            "Packet shorter than 12-byte DNS header".into(),
        ));
    }
    let qdcount = u16::from_be_bytes([raw[4], raw[5]]) as usize;
    let ancount = u16::from_be_bytes([raw[6], raw[7]]) as usize;
    let nscount = u16::from_be_bytes([raw[8], raw[9]]) as usize;
    let arcount = u16::from_be_bytes([raw[10], raw[11]]) as usize;

    let mut offset = 12usize;
    for _ in 0..qdcount {
        let (_, next_off) = read_dns_name(raw, offset)?;
        offset = next_off.checked_add(4).ok_or_else(|| {
            CastError::MalformedMdns("Offset overflow in DNS question".into())
        })?;
        if offset > raw.len() {
            return Err(CastError::MalformedMdns("Truncated DNS question".into()));
        }
    }

    let total_rrs = ancount
        .saturating_add(nscount)
        .saturating_add(arcount);

    // Maps assembled across Answer + Authority + Additional records
    let mut ptr_instances: Vec<(String, String)> = Vec::new(); // (service_type, instance_name)
    let mut srv_map: BTreeMap<String, (u16, String)> = BTreeMap::new(); // instance -> (port, target_host)
    let mut txt_map: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    let mut host_ips: BTreeMap<String, IpAddr> = BTreeMap::new();

    for _ in 0..total_rrs {
        if offset >= raw.len() {
            break;
        }
        let (rr_name, next_off) = read_dns_name(raw, offset)?;
        offset = next_off;
        if offset + 10 > raw.len() {
            return Err(CastError::MalformedMdns("Truncated DNS resource record header".into()));
        }
        let rtype = u16::from_be_bytes([raw[offset], raw[offset + 1]]);
        let rdlength = u16::from_be_bytes([raw[offset + 8], raw[offset + 9]]) as usize;
        offset += 10;

        let rdata_end = offset
            .checked_add(rdlength)
            .ok_or_else(|| CastError::MalformedMdns("RDLENGTH overflow".into()))?;
        if rdata_end > raw.len() {
            return Err(CastError::MalformedMdns("Truncated DNS RDATA".into()));
        }

        let name_lower = rr_name.to_ascii_lowercase();
        match rtype {
            DNS_TYPE_PTR => {
                let (target, _) = read_dns_name(raw, offset)?;
                ptr_instances.push((name_lower, target));
            }
            DNS_TYPE_SRV => {
                if rdlength < 7 {
                    return Err(CastError::MalformedMdns("Invalid SRV RDATA length".into()));
                }
                let port = u16::from_be_bytes([raw[offset + 4], raw[offset + 5]]);
                let (target_host, _) = read_dns_name(raw, offset + 6)?;
                srv_map.insert(name_lower, (port, target_host.to_ascii_lowercase()));
            }
            DNS_TYPE_TXT => {
                let kv = parse_dns_txt_rdata(&raw[offset..rdata_end]);
                txt_map.entry(name_lower).or_default().extend(kv);
            }
            DNS_TYPE_A if rdlength == 4 => {
                let ip = IpAddr::V4(Ipv4Addr::new(
                    raw[offset],
                    raw[offset + 1],
                    raw[offset + 2],
                    raw[offset + 3],
                ));
                host_ips.insert(name_lower, ip);
            }
            DNS_TYPE_AAAA if rdlength == 16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&raw[offset..rdata_end]);
                host_ips.insert(name_lower, IpAddr::V6(Ipv6Addr::from(octets)));
            }
            _ => {}
        }

        offset = rdata_end;
    }

    // If no explicit PTR records appeared, synthesize from SRV keys that match known services
    if ptr_instances.is_empty() {
        for instance_key in srv_map.keys() {
            if let Some(svc) = infer_service_from_instance(instance_key) {
                ptr_instances.push((svc.to_string(), instance_key.clone()));
            }
        }
    }

    let mut devices = Vec::new();
    for (service_type, instance_raw) in ptr_instances {
        let protocol = match classify_mdns_service(&service_type, &instance_raw) {
            Some(p) => p,
            None => continue,
        };
        let instance_key = instance_raw.to_ascii_lowercase();
        let (port, target_host) = srv_map
            .get(&instance_key)
            .cloned()
            .unwrap_or_else(|| (protocol.default_port(), String::new()));

        let ip_addr = if !target_host.is_empty() {
            host_ips.get(&target_host).copied().unwrap_or(source_ip)
        } else {
            source_ip
        };

        let txt = txt_map.get(&instance_key);
        let id = txt
            .and_then(|m| m.get("id").or_else(|| m.get("deviceid")).cloned())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| format!("mdns-{instance_key}"));

        let default_label = instance_raw
            .split('.')
            .next()
            .unwrap_or(&instance_raw)
            .to_string();
        let friendly_name = txt
            .and_then(|m| m.get("fn").cloned())
            .filter(|s| !s.is_empty())
            .unwrap_or(default_label);

        let model_name = txt
            .and_then(|m| m.get("md").or_else(|| m.get("model")).cloned())
            .filter(|s| !s.is_empty());

        devices.push(CastDevice {
            id,
            friendly_name,
            protocol,
            ip_addr,
            port,
            model_name,
            location_url: None,
            service_type: Some(service_type),
            discovered_at_ms: now_ms,
        });
    }

    Ok(devices)
}

fn classify_mdns_service(service_type: &str, instance_name: &str) -> Option<CastProtocol> {
    let lower_s = service_type.to_ascii_lowercase();
    let lower_i = instance_name.to_ascii_lowercase();
    if lower_s.contains("_googlecast") || lower_i.contains("_googlecast") {
        Some(CastProtocol::Chromecast)
    } else if lower_s.contains("_airplay")
        || lower_s.contains("_raop")
        || lower_i.contains("_airplay")
        || lower_i.contains("_raop")
    {
        Some(CastProtocol::AirPlay)
    } else {
        None
    }
}

fn infer_service_from_instance(instance: &str) -> Option<&'static str> {
    if instance.contains("_googlecast._tcp.local") {
        Some(MDNS_SERVICE_CHROMECAST)
    } else if instance.contains("_airplay._tcp.local") {
        Some(MDNS_SERVICE_AIRPLAY)
    } else {
        None
    }
}

fn read_dns_name(packet: &[u8], start_offset: usize) -> Result<(String, usize), CastError> {
    let mut labels = Vec::new();
    let mut offset = start_offset;
    let mut end_offset = start_offset;
    let mut jumped = false;
    let mut hops = 0usize;

    loop {
        if offset >= packet.len() {
            return Err(CastError::MalformedMdns("DNS name out of bounds".into()));
        }
        let len_byte = packet[offset];
        if len_byte == 0 {
            if !jumped {
                end_offset = offset + 1;
            }
            break;
        }
        // RFC 1035 compression pointer (`11xxxxxx xxxxxxxx`)
        if (len_byte & 0xC0) == 0xC0 {
            if offset + 1 >= packet.len() {
                return Err(CastError::MalformedMdns(
                    "Truncated DNS compression pointer".into(),
                ));
            }
            hops += 1;
            if hops > MAX_DNS_COMPRESSION_HOPS {
                return Err(CastError::MalformedMdns(
                    "DNS compression pointer loop detected".into(),
                ));
            }
            let ptr = (u16::from(len_byte & 0x3F) << 8) | u16::from(packet[offset + 1]);
            let ptr_usize = ptr as usize;
            if ptr_usize >= packet.len() {
                return Err(CastError::MalformedMdns(
                    "DNS compression pointer target out of bounds".into(),
                ));
            }
            if !jumped {
                end_offset = offset + 2;
                jumped = true;
            }
            offset = ptr_usize;
        } else if (len_byte & 0xC0) != 0 {
            return Err(CastError::MalformedMdns(
                "Invalid DNS label length prefix bits".into(),
            ));
        } else {
            let label_len = len_byte as usize;
            let label_start = offset + 1;
            let label_end = label_start
                .checked_add(label_len)
                .ok_or_else(|| CastError::MalformedMdns("DNS label overflow".into()))?;
            if label_end > packet.len() {
                return Err(CastError::MalformedMdns("DNS label exceeds packet length".into()));
            }
            let label = std::str::from_utf8(&packet[label_start..label_end])
                .map_err(|_| CastError::MalformedMdns("Non-UTF-8 DNS label".into()))?;
            labels.push(label.to_string());
            offset = label_end;
            if !jumped {
                end_offset = offset;
            }
        }
    }

    Ok((labels.join("."), end_offset))
}

fn parse_dns_txt_rdata(rdata: &[u8]) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    let mut i = 0usize;
    while i < rdata.len() {
        let len = rdata[i] as usize;
        i += 1;
        if len == 0 || i + len > rdata.len() {
            break;
        }
        if let Ok(entry) = std::str::from_utf8(&rdata[i..i + len]) {
            if let Some((k, v)) = entry.split_once('=') {
                map.insert(k.to_ascii_lowercase(), v.to_string());
            }
        }
        i += len;
    }
    map
}

fn extract_ip_and_port_from_http_url(url: &str) -> Option<(IpAddr, u16)> {
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))?;
    let default_port = if url.starts_with("https://") { 443 } else { 80 };
    let authority = rest.split('/').next()?;
    if let Some(bracketed) = authority.strip_prefix('[') {
        let (ip_str, after) = bracketed.split_once(']')?;
        let ip: IpAddr = ip_str.parse().ok()?;
        let port = after
            .strip_prefix(':')
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(default_port);
        Some((ip, port))
    } else if let Some((host, port_str)) = authority.rsplit_once(':') {
        let ip: IpAddr = host.parse().ok()?;
        let port: u16 = port_str.parse().ok()?;
        Some((ip, port))
    } else {
        let ip: IpAddr = authority.parse().ok()?;
        Some((ip, default_port))
    }
}

fn validate_media_url(url: &str) -> Result<(), CastError> {
    let trimmed = url.trim();
    if !(trimmed.starts_with("http://") || trimmed.starts_with("https://")) {
        return Err(CastError::InvalidMediaUrl(url.to_string()));
    }
    if trimmed.len() <= 10 || trimmed.chars().any(|c| c.is_control()) {
        return Err(CastError::InvalidMediaUrl(url.to_string()));
    }
    Ok(())
}

fn build_protocol_wire_command(
    device: &CastDevice,
    command: &CastPlaybackCommand,
) -> CastWireCommand {
    match device.protocol {
        CastProtocol::Chromecast => {
            let (namespace, payload) = match command {
                CastPlaybackCommand::LoadMedia {
                    url,
                    title,
                    content_type,
                    start_position_sec,
                } => (
                    "urn:x-cast:com.google.cast.media",
                    serde_json::json!({
                        "type": "LOAD",
                        "autoplay": true,
                        "currentTime": start_position_sec,
                        "media": {
                            "contentId": url,
                            "contentType": content_type,
                            "streamType": "BUFFERED",
                            "metadata": { "title": title }
                        }
                    })
                    .to_string(),
                ),
                CastPlaybackCommand::Play => (
                    "urn:x-cast:com.google.cast.media",
                    serde_json::json!({"type": "PLAY"}).to_string(),
                ),
                CastPlaybackCommand::Pause => (
                    "urn:x-cast:com.google.cast.media",
                    serde_json::json!({"type": "PAUSE"}).to_string(),
                ),
                CastPlaybackCommand::Seek(pos) => (
                    "urn:x-cast:com.google.cast.media",
                    serde_json::json!({"type": "SEEK", "currentTime": pos}).to_string(),
                ),
                CastPlaybackCommand::SetVolume(vol) => (
                    "urn:x-cast:com.google.cast.receiver",
                    serde_json::json!({"type": "SET_VOLUME", "volume": {"level": vol.clamp(0.0, 1.0)}})
                        .to_string(),
                ),
                CastPlaybackCommand::Stop => (
                    "urn:x-cast:com.google.cast.media",
                    serde_json::json!({"type": "STOP"}).to_string(),
                ),
            };
            CastWireCommand {
                protocol: CastProtocol::Chromecast,
                target_ip: device.ip_addr,
                target_port: device.port,
                endpoint_hint: namespace.to_string(),
                payload,
            }
        }
        CastProtocol::DlnaUpnp => {
            let (action, soap_body) = match command {
                CastPlaybackCommand::LoadMedia { url, .. } => (
                    "AVTransport#SetAVTransportURI",
                    format!(
                        "<u:SetAVTransportURI xmlns:u=\"urn:schemas-upnp-org:service:AVTransport:1\">\
                         <InstanceID>0</InstanceID><CurrentURI>{}</CurrentURI>\
                         <CurrentURIMetaData></CurrentURIMetaData></u:SetAVTransportURI>",
                        escape_xml(url)
                    ),
                ),
                CastPlaybackCommand::Play => (
                    "AVTransport#Play",
                    "<u:Play xmlns:u=\"urn:schemas-upnp-org:service:AVTransport:1\">\
                     <InstanceID>0</InstanceID><Speed>1</Speed></u:Play>"
                        .to_string(),
                ),
                CastPlaybackCommand::Pause => (
                    "AVTransport#Pause",
                    "<u:Pause xmlns:u=\"urn:schemas-upnp-org:service:AVTransport:1\">\
                     <InstanceID>0</InstanceID></u:Pause>"
                        .to_string(),
                ),
                CastPlaybackCommand::Seek(pos) => {
                    let secs = pos.max(0.0).floor() as u64;
                    let h = secs / 3600;
                    let m = (secs % 3600) / 60;
                    let s = secs % 60;
                    (
                        "AVTransport#Seek",
                        format!(
                            "<u:Seek xmlns:u=\"urn:schemas-upnp-org:service:AVTransport:1\">\
                             <InstanceID>0</InstanceID><Unit>REL_TIME</Unit>\
                             <Target>{h:02}:{m:02}:{s:02}</Target></u:Seek>"
                        ),
                    )
                }
                CastPlaybackCommand::SetVolume(vol) => {
                    let pct = (vol.clamp(0.0, 1.0) * 100.0).round() as u8;
                    (
                        "RenderingControl#SetVolume",
                        format!(
                            "<u:SetVolume xmlns:u=\"urn:schemas-upnp-org:service:RenderingControl:1\">\
                             <InstanceID>0</InstanceID><Channel>Master</Channel>\
                             <DesiredVolume>{pct}</DesiredVolume></u:SetVolume>"
                        ),
                    )
                }
                CastPlaybackCommand::Stop => (
                    "AVTransport#Stop",
                    "<u:Stop xmlns:u=\"urn:schemas-upnp-org:service:AVTransport:1\">\
                     <InstanceID>0</InstanceID></u:Stop>"
                        .to_string(),
                ),
            };
            CastWireCommand {
                protocol: CastProtocol::DlnaUpnp,
                target_ip: device.ip_addr,
                target_port: device.port,
                endpoint_hint: action.to_string(),
                payload: soap_body,
            }
        }
        CastProtocol::AirPlay => {
            let (endpoint, body) = match command {
                CastPlaybackCommand::LoadMedia {
                    url,
                    start_position_sec,
                    ..
                } => (
                    "POST /play",
                    format!("Content-Location: {url}\nStart-Position: {start_position_sec}\n"),
                ),
                CastPlaybackCommand::Play => ("POST /rate?value=1.0", String::new()),
                CastPlaybackCommand::Pause => ("POST /rate?value=0.0", String::new()),
                CastPlaybackCommand::Seek(pos) => (
                    "POST /scrub",
                    format!("position={pos:.3}"),
                ),
                CastPlaybackCommand::SetVolume(vol) => (
                    "POST /volume",
                    format!("volume={:.3}", vol.clamp(0.0, 1.0)),
                ),
                CastPlaybackCommand::Stop => ("POST /stop", String::new()),
            };
            CastWireCommand {
                protocol: CastProtocol::AirPlay,
                target_ip: device.ip_addr,
                target_port: device.port,
                endpoint_hint: endpoint.to_string(),
                payload: body,
            }
        }
    }
}

fn escape_xml(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_dns_labels(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in name.trim_end_matches('.').split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    fn push_rr(buf: &mut Vec<u8>, name: &str, rtype: u16, rdata: &[u8]) {
        buf.extend_from_slice(&encode_dns_labels(name));
        buf.extend_from_slice(&rtype.to_be_bytes());
        buf.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        buf.extend_from_slice(&120u32.to_be_bytes()); // TTL
        buf.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        buf.extend_from_slice(rdata);
    }

    fn build_synthetic_chromecast_mdns_response() -> Vec<u8> {
        let instance = "Chromecast-LivingRoom._googlecast._tcp.local";
        let host = "chromecast-living.local";

        let mut pkt = Vec::new();
        // Header: ID=0, Flags=0x8400 (response+AA), QD=0, AN=1, NS=0, AR=3
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&0x8400u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&3u16.to_be_bytes());

        // AN1: PTR _googlecast._tcp.local -> Chromecast-LivingRoom._googlecast._tcp.local
        let ptr_rdata = encode_dns_labels(instance);
        push_rr(&mut pkt, MDNS_SERVICE_CHROMECAST, DNS_TYPE_PTR, &ptr_rdata);

        // AR1: SRV -> port 8009, target chromecast-living.local
        let mut srv_rdata = Vec::new();
        srv_rdata.extend_from_slice(&0u16.to_be_bytes()); // priority
        srv_rdata.extend_from_slice(&0u16.to_be_bytes()); // weight
        srv_rdata.extend_from_slice(&8009u16.to_be_bytes());
        srv_rdata.extend_from_slice(&encode_dns_labels(host));
        push_rr(&mut pkt, instance, DNS_TYPE_SRV, &srv_rdata);

        // AR2: TXT -> id=cc-abc123, fn=Living Room TV, md=Chromecast Ultra
        let mut txt_rdata = Vec::new();
        for kv in ["id=cc-abc123", "fn=Living Room TV", "md=Chromecast Ultra"] {
            txt_rdata.push(kv.len() as u8);
            txt_rdata.extend_from_slice(kv.as_bytes());
        }
        push_rr(&mut pkt, instance, DNS_TYPE_TXT, &txt_rdata);

        // AR3: A -> 192.168.1.42
        push_rr(&mut pkt, host, DNS_TYPE_A, &[192, 168, 1, 42]);

        pkt
    }

    #[test]
    fn zero_passive_sockets_at_rest_and_opt_in_discovery_lifecycle() {
        let mut ctrl = OptInCastController::new();
        assert!(!ctrl.is_discovery_active());
        assert_eq!(ctrl.active_socket_count(), 0);
        assert_eq!(ctrl.mullvad_lan_exception_target(), None);

        // Packet ingestion while discovery is inactive must be strictly rejected
        let ssdp_raw = b"HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.20:1400/desc.xml\r\nST: urn:schemas-upnp-org:device:MediaRenderer:1\r\nUSN: uuid:speaker-1::urn:schemas-upnp-org:device:MediaRenderer:1\r\n\r\n";
        assert_eq!(
            ctrl.ingest_ssdp_packet(ssdp_raw, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)), 1000),
            Err(CastError::DiscoveryInactive)
        );

        // Explicit user opt-in activates discovery and produces SSDP + mDNS probes
        let probes = ctrl.begin_user_discovery_session(1000).expect("Start discovery");
        assert!(ctrl.is_discovery_active());
        assert_eq!(ctrl.active_socket_count(), 1);
        assert_eq!(probes.len(), 4);

        // Ending discovery closes sockets immediately
        ctrl.end_discovery_session();
        assert!(!ctrl.is_discovery_active());
        assert_eq!(ctrl.active_socket_count(), 0);
    }

    #[test]
    fn ssdp_msearch_builder_and_response_parser() {
        let req = build_ssdp_msearch_request(SSDP_ST_MEDIA_RENDERER, 3);
        let req_str = std::str::from_utf8(&req).unwrap();
        assert!(req_str.starts_with("M-SEARCH * HTTP/1.1\r\n"));
        assert!(req_str.contains("MAN: \"ssdp:discover\""));
        assert!(req_str.contains("ST: urn:schemas-upnp-org:device:MediaRenderer:1"));

        let dlna_resp = b"HTTP/1.1 200 OK\r\n\
            CACHE-CONTROL: max-age=1800\r\n\
            LOCATION: http://192.168.10.55:49152/description.xml\r\n\
            SERVER: Linux/5.15 UPnP/1.1 MiniDLNA/1.3\r\n\
            ST: urn:schemas-upnp-org:device:MediaRenderer:1\r\n\
            USN: uuid:4d696e69-444c-164e-9d41::urn:schemas-upnp-org:device:MediaRenderer:1\r\n\
            FRIENDLYNAME.DLNA.ORG: Studio HiFi Renderer\r\n\r\n";

        let dev = parse_ssdp_response(
            dlna_resp,
            IpAddr::V4(Ipv4Addr::new(192, 168, 10, 55)),
            2000,
        )
        .expect("Parse DLNA SSDP");

        assert_eq!(dev.protocol, CastProtocol::DlnaUpnp);
        assert_eq!(dev.friendly_name, "Studio HiFi Renderer");
        assert_eq!(dev.ip_addr, IpAddr::V4(Ipv4Addr::new(192, 168, 10, 55)));
        assert_eq!(dev.port, 49152);
        assert_eq!(dev.id, "uuid:4d696e69-444c-164e-9d41");

        // Malformed SSDP packet rejected cleanly
        assert!(matches!(
            parse_ssdp_response(b"GARBAGE", IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 2000),
            Err(CastError::MalformedSsdp(_))
        ));
    }

    #[test]
    fn mdns_query_builder_response_parser_and_pointer_loop_dos_protection() {
        let query = build_mdns_ptr_query(MDNS_SERVICE_CHROMECAST).expect("Build mDNS query");
        let questions = parse_mdns_query(&query).expect("Parse own mDNS query");
        assert_eq!(questions.len(), 1);
        assert_eq!(questions[0].qname, MDNS_SERVICE_CHROMECAST);
        assert_eq!(questions[0].qtype, DNS_TYPE_PTR);
        assert!(questions[0].unicast_response);

        let resp = build_synthetic_chromecast_mdns_response();
        let devices = parse_mdns_response(
            &resp,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 42)),
            5000,
        )
        .expect("Parse Chromecast mDNS response");
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].protocol, CastProtocol::Chromecast);
        assert_eq!(devices[0].id, "cc-abc123");
        assert_eq!(devices[0].friendly_name, "Living Room TV");
        assert_eq!(devices[0].model_name.as_deref(), Some("Chromecast Ultra"));
        assert_eq!(devices[0].ip_addr, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 42)));
        assert_eq!(devices[0].port, 8009);

        // Malicious self-referential DNS compression pointer loop (0xC0 0x0C pointing to byte 12)
        let mut loop_pkt = vec![0u8; 12];
        loop_pkt[5] = 1; // QDCOUNT = 1
        loop_pkt.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x0C, 0x00, 0x01]);
        assert!(matches!(
            parse_mdns_query(&loop_pkt),
            Err(CastError::MalformedMdns(_))
        ));
    }

    #[test]
    fn playback_state_machine_and_single_host_mullvad_lan_exception() {
        let mut ctrl = OptInCastController::new();
        ctrl.begin_user_discovery_session(1000).unwrap();

        let resp = build_synthetic_chromecast_mdns_response();
        let discovered = ctrl
            .ingest_mdns_packet(&resp, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 42)), 1100)
            .unwrap();
        assert_eq!(discovered.len(), 1);

        // Connect to chosen Chromecast -> closes discovery socket & produces strict /32 LAN exception
        let exc = ctrl.connect_device("cc-abc123").expect("Connect device");
        assert!(!ctrl.is_discovery_active());
        assert_eq!(ctrl.active_socket_count(), 0);
        assert_eq!(exc.target_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 42)));
        assert_eq!(exc.target_port, 8009);
        assert_eq!(exc.single_host_cidr, "192.168.1.42/32");
        assert!(!exc.allow_multicast);
        assert_eq!(ctrl.mullvad_lan_exception_target(), Some(exc));

        // LoadMedia -> Play -> Pause -> Seek -> SetVolume -> Stop
        let load_wire = ctrl
            .send_command(CastPlaybackCommand::LoadMedia {
                url: "https://media.example/stream.mp4".into(),
                title: "Singularity Demo".into(),
                content_type: "video/mp4".into(),
                start_position_sec: 12.5,
            })
            .expect("LoadMedia");
        assert!(load_wire.payload.contains("\"LOAD\""));

        ctrl.send_command(CastPlaybackCommand::Pause).expect("Pause");
        assert!(matches!(ctrl.session_state(), CastSessionState::Paused { .. }));

        ctrl.send_command(CastPlaybackCommand::Seek(95.0)).expect("Seek");
        ctrl.send_command(CastPlaybackCommand::SetVolume(0.75))
            .expect("SetVolume");
        ctrl.send_command(CastPlaybackCommand::Play).expect("Play");
        match ctrl.session_state() {
            CastSessionState::Playing {
                position_sec,
                volume,
                ..
            } => {
                assert_eq!(*position_sec, 95.0);
                assert_eq!(*volume, 0.75);
            }
            other => panic!("Expected Playing, got {other:?}"),
        }

        // Unsafe URL schemes must be rejected
        assert!(matches!(
            ctrl.send_command(CastPlaybackCommand::LoadMedia {
                url: "file:///etc/passwd".into(),
                title: "bad".into(),
                content_type: "text/plain".into(),
                start_position_sec: 0.0,
            }),
            Err(CastError::InvalidMediaUrl(_))
        ));

        ctrl.send_command(CastPlaybackCommand::Stop).expect("Stop");
        assert!(matches!(ctrl.session_state(), CastSessionState::Stopped { .. }));

        // Disconnect clears the Mullvad LAN exception immediately
        ctrl.disconnect();
        assert_eq!(ctrl.mullvad_lan_exception_target(), None);
        assert_eq!(ctrl.session_state(), &CastSessionState::Idle);

        // Non-LAN public IP must NEVER get a Mullvad LAN exception
        let public_dev = CastDevice {
            id: "evil-wan".into(),
            friendly_name: "External".into(),
            protocol: CastProtocol::Chromecast,
            ip_addr: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            port: 8009,
            model_name: None,
            location_url: None,
            service_type: None,
            discovered_at_ms: 0,
        };
        assert_eq!(mullvad_lan_exception_for_device(&public_dev), None);
    }

    #[test]
    fn airplay_mdns_and_dlna_airplay_wire_commands() {
        let instance = "Bedroom-AppleTV._airplay._tcp.local";
        let host = "bedroom-tv.local";
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&0x8400u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&3u16.to_be_bytes());

        let ptr_rdata = encode_dns_labels(instance);
        push_rr(&mut pkt, MDNS_SERVICE_AIRPLAY, DNS_TYPE_PTR, &ptr_rdata);

        let mut srv_rdata = Vec::new();
        srv_rdata.extend_from_slice(&0u16.to_be_bytes());
        srv_rdata.extend_from_slice(&0u16.to_be_bytes());
        srv_rdata.extend_from_slice(&7000u16.to_be_bytes());
        srv_rdata.extend_from_slice(&encode_dns_labels(host));
        push_rr(&mut pkt, instance, DNS_TYPE_SRV, &srv_rdata);

        let mut txt_rdata = Vec::new();
        for kv in ["deviceid=AA:BB:CC:DD:EE:FF", "model=AppleTV6,2"] {
            txt_rdata.push(kv.len() as u8);
            txt_rdata.extend_from_slice(kv.as_bytes());
        }
        push_rr(&mut pkt, instance, DNS_TYPE_TXT, &txt_rdata);
        push_rr(&mut pkt, host, DNS_TYPE_A, &[10, 0, 0, 88]);

        let mut ctrl = OptInCastController::new();
        ctrl.begin_user_discovery_session(10).unwrap();
        let found = ctrl
            .ingest_mdns_packet(&pkt, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 88)), 20)
            .unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].protocol, CastProtocol::AirPlay);
        assert_eq!(found[0].id, "AA:BB:CC:DD:EE:FF");
        assert_eq!(found[0].model_name.as_deref(), Some("AppleTV6,2"));

        let exc = ctrl.connect_device("AA:BB:CC:DD:EE:FF").unwrap();
        assert_eq!(exc.single_host_cidr, "10.0.0.88/32");
        let airplay_wire = ctrl
            .send_command(CastPlaybackCommand::LoadMedia {
                url: "https://cdn.example/video.m3u8".into(),
                title: "Stream".into(),
                content_type: "application/x-mpegURL".into(),
                start_position_sec: 5.0,
            })
            .unwrap();
        assert_eq!(airplay_wire.endpoint_hint, "POST /play");
        assert!(airplay_wire.payload.contains("https://cdn.example/video.m3u8"));

        // DLNA SOAP command check
        ctrl.begin_user_discovery_session(30).unwrap();
        let ssdp = b"HTTP/1.1 200 OK\r\nLOCATION: http://192.168.50.9:1400/desc.xml\r\nST: urn:schemas-upnp-org:device:MediaRenderer:1\r\nUSN: uuid:dlna-tv::urn:schemas-upnp-org:device:MediaRenderer:1\r\n\r\n";
        ctrl.ingest_ssdp_packet(ssdp, IpAddr::V4(Ipv4Addr::new(192, 168, 50, 9)), 35)
            .unwrap();
        ctrl.connect_device("uuid:dlna-tv").unwrap();
        let dlna_wire = ctrl
            .send_command(CastPlaybackCommand::SetVolume(0.5))
            .unwrap();
        assert_eq!(dlna_wire.endpoint_hint, "RenderingControl#SetVolume");
        assert!(dlna_wire.payload.contains("<DesiredVolume>50</DesiredVolume>"));
    }
}
