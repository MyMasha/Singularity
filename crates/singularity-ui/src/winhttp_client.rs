//! Zero-Subprocess Native Win32 HTTPS/HTTP Client (`winhttp.dll`).
//!
//! Eliminates ALL `curl.exe` and `powershell.exe` child process spawns on Windows during
//! browsing, favicon fetching, update checks, self-updates, and Chrome Web Store installs —
//! making flashing terminal/console windows 100% impossible while delivering native TLS 1.2/1.3
//! performance, disabling WPAD auto-proxy hijacking (`WINHTTP_ACCESS_TYPE_NO_PROXY`), and
//! enforcing post-connect remote IP verification (`WINHTTP_OPTION_CONNECTION_INFO`) against
//! DNS rebinding TOCTOU attacks.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedHttpUrl {
    pub is_https: bool,
    pub host: String,
    pub port: u16,
    pub path_and_query: String,
}

#[derive(Debug, Clone)]
pub struct WinHttpResponse {
    pub status_code: u16,
    pub location: Option<String>,
    pub body: Vec<u8>,
}

/// Parses an `http://` or `https://` URL (case-insensitive scheme) into host, port, and
/// path+query components. Rejects embedded userinfo (`@`), control characters, non-HTTP schemes,
/// and empty hosts.
pub fn parse_http_url_parts(raw_url: &str) -> Result<ParsedHttpUrl, String> {
    let trimmed = raw_url.trim();
    if trimmed.is_empty() || trimmed.bytes().any(|b| b <= 0x1f || b == 0x7f) {
        return Err("URL contains invalid control characters".into());
    }
    let (scheme, rest) = trimmed
        .split_once("://")
        .ok_or_else(|| "Only http:// and https:// URLs are supported".to_string())?;
    let is_https = if scheme.eq_ignore_ascii_case("https") {
        true
    } else if scheme.eq_ignore_ascii_case("http") {
        false
    } else {
        return Err("Only http:// and https:// URLs are supported".into());
    };

    let without_frag = rest.split('#').next().unwrap_or(rest);
    let (authority, path_and_query) = match without_frag.find(['/', '?']) {
        Some(idx) => {
            let (a, p) = without_frag.split_at(idx);
            if p.starts_with('?') {
                (a, format!("/{}", p))
            } else {
                (a, p.to_string())
            }
        }
        None => (without_frag, "/".to_string()),
    };

    if authority.is_empty() || authority.contains('@') || authority.contains('\\') {
        return Err("Invalid URL authority".into());
    }

    let default_port = if is_https { 443 } else { 80 };
    let (host, port) = if authority.starts_with('[') {
        let close = authority
            .find(']')
            .ok_or_else(|| "Unclosed IPv6 bracket in URL".to_string())?;
        let host_part = authority[1..close].to_string();
        let after = &authority[close + 1..];
        let port_val = if let Some(p_str) = after.strip_prefix(':') {
            p_str
                .parse::<u16>()
                .ok()
                .filter(|&p| p > 0)
                .ok_or_else(|| "Invalid URL port".to_string())?
        } else if after.is_empty() {
            default_port
        } else {
            return Err("Invalid URL authority suffix".into());
        };
        (host_part, port_val)
    } else if let Some((h, p_str)) = authority.rsplit_once(':') {
        if h.contains(':') {
            return Err("Unbracketed IPv6 literal in URL".into());
        }
        let port_val = p_str
            .parse::<u16>()
            .ok()
            .filter(|&p| p > 0)
            .ok_or_else(|| "Invalid URL port".to_string())?;
        (h.to_string(), port_val)
    } else {
        (authority.to_string(), default_port)
    };

    if host.is_empty() {
        return Err("Empty host in URL".into());
    }

    Ok(ParsedHttpUrl {
        is_https,
        host,
        port,
        path_and_query,
    })
}

/// Compares full RFC 6454 origin tuple `(scheme, host, port)` so `Authorization` headers are
/// stripped on cross-scheme, cross-host, OR cross-port redirects.
pub fn is_same_origin(a: &ParsedHttpUrl, b: &ParsedHttpUrl) -> bool {
    a.is_https == b.is_https && a.port == b.port && a.host.eq_ignore_ascii_case(&b.host)
}

/// Normalizes IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) into their underlying `IpAddr::V4`.
pub fn normalize_ip_addr(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
    }
}

/// Returns `true` strictly for globally routable public IPv4/IPv6 addresses (blocks loopback,
/// RFC 1918 private networks, link-local / cloud metadata `169.254.0.0/16`, CGNAT `100.64.0.0/10`,
/// ULA `fc00::/7`, IPv4-mapped private IPv6, NAT64 embedded private IPv4, multicast, and reserved ranges).
pub fn is_public_routable_ip(ip: IpAddr) -> bool {
    match normalize_ip_addr(ip) {
        IpAddr::V4(v4) => {
            let oct = v4.octets();
            if v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                || oct[0] == 0
                || (oct[0] == 100 && (oct[1] & 0xC0) == 64) // CGNAT 100.64.0.0/10
                || (oct[0] == 192 && oct[1] == 0 && oct[2] == 0) // IETF Protocol Assignments
                || (oct[0] == 198 && (oct[1] & 0xFE) == 18) // Benchmarking 198.18.0.0/15
                || oct[0] >= 240 // Reserved / Class E
            {
                return false;
            }
            true
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() {
                return false;
            }
            let seg = v6.segments();
            // Reject deprecated IPv4-compatible IPv6 (`::a.b.c.d`)
            if seg[0..6] == [0, 0, 0, 0, 0, 0] {
                return false;
            }
            // Unique Local Addresses (fc00::/7)
            if (seg[0] & 0xfe00) == 0xfc00 {
                return false;
            }
            // Link-local unicast (fe80::/10) and deprecated site-local (fec0::/10)
            if (seg[0] & 0xffc0) == 0xfe80 || (seg[0] & 0xffc0) == 0xfec0 {
                return false;
            }
            // Documentation (2001:db8::/32)
            if seg[0] == 0x2001 && seg[1] == 0x0db8 {
                return false;
            }
            // Discard-Only (100::/64)
            if seg[0] == 0x0100 && seg[1] == 0 && seg[2] == 0 && seg[3] == 0 {
                return false;
            }
            // NAT64 well-known prefix (64:ff9b::/96) — verify embedded IPv4 is public
            if seg[0] == 0x0064 && seg[1] == 0xff9b {
                if seg[2..6] == [0, 0, 0, 0] {
                    let embedded = Ipv4Addr::new(
                        (seg[6] >> 8) as u8,
                        seg[6] as u8,
                        (seg[7] >> 8) as u8,
                        seg[7] as u8,
                    );
                    return is_public_routable_ip(IpAddr::V4(embedded));
                }
                // Local-use NAT64 (64:ff9b:1::/48)
                if seg[2] == 1 {
                    return false;
                }
            }
            true
        }
    }
}

/// Validates a connected peer IP against `allowed_ip_check` (defaulting to `is_public_routable_ip`)
/// and, for plaintext HTTP with `pinned_ip`, verifies an exact match with the pinned IP.
pub fn is_remote_ip_allowed(
    remote_ip: IpAddr,
    is_https: bool,
    pinned_ip: Option<IpAddr>,
    allowed_ip_check: Option<fn(IpAddr) -> bool>,
) -> bool {
    let norm_remote = normalize_ip_addr(remote_ip);
    let policy_ok = match allowed_ip_check {
        Some(check) => check(norm_remote),
        None => is_public_routable_ip(norm_remote),
    };
    if !policy_ok {
        return false;
    }
    if !is_https {
        if let Some(pin) = pinned_ip {
            if norm_remote != normalize_ip_addr(pin) {
                return false;
            }
        }
    }
    true
}

/// Official Win32 `WINHTTP_OPTION_CONNECTION_INFO` option ID (`winhttp.h` = 93).
pub(crate) const WINHTTP_OPTION_CONNECTION_INFO: u32 = 93;

/// Exact Win32 `SOCKADDR_STORAGE` layout (128 bytes, 8-byte aligned) used by
/// `WINHTTP_CONNECTION_INFO` (`WINHTTP_OPTION_CONNECTION_INFO = 93`).
#[allow(dead_code)]
#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub(crate) struct Win32SockAddrStorage {
    pub ss_family: u16,
    pub data: [u8; 126],
}

/// Exact Win32 `WINHTTP_CONNECTION_INFO` layout (264 bytes on 64-bit MSVC ABI; 260 bytes packed(4) on x86).
#[allow(dead_code)]
#[cfg_attr(target_arch = "x86", repr(C, packed(4)))]
#[cfg_attr(not(target_arch = "x86"), repr(C))]
#[derive(Clone, Copy)]
pub(crate) struct Win32WinHttpConnectionInfo {
    pub cb_size: u32,
    pub local_address: Win32SockAddrStorage,
    pub remote_address: Win32SockAddrStorage,
}

/// Extracts an `IpAddr` from a Win32 `SOCKADDR_STORAGE` (`AF_INET = 2`, `AF_INET6 = 23`),
/// normalizing IPv4-mapped IPv6 addresses to `IpAddr::V4`.
#[allow(dead_code)]
pub(crate) fn parse_win32_sockaddr_storage_ip(sa: &Win32SockAddrStorage) -> Option<IpAddr> {
    const WIN32_AF_INET: u16 = 2;
    const WIN32_AF_INET6: u16 = 23;
    match sa.ss_family {
        WIN32_AF_INET => {
            // SOCKADDR_IN: ss_family (2) | sin_port (data[0..2]) | sin_addr (data[2..6])
            let ip = Ipv4Addr::new(sa.data[2], sa.data[3], sa.data[4], sa.data[5]);
            Some(IpAddr::V4(ip))
        }
        WIN32_AF_INET6 => {
            // SOCKADDR_IN6: ss_family (2) | sin6_port (data[0..2]) | sin6_flowinfo (data[2..6]) | sin6_addr (data[6..22])
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&sa.data[6..22]);
            let ip6 = Ipv6Addr::from(octets);
            Some(normalize_ip_addr(IpAddr::V6(ip6)))
        }
        _ => None,
    }
}

/// Resolves a relative or absolute HTTP `Location` redirect target against `base_url`.
pub fn resolve_http_redirect(base_url: &str, location: &str) -> Option<String> {
    let loc = location.trim();
    if loc.is_empty() || loc.bytes().any(|b| b <= 0x1f || b == 0x7f) {
        return None;
    }
    if let Some((scheme, _)) = loc.split_once("://") {
        if scheme.eq_ignore_ascii_case("https") || scheme.eq_ignore_ascii_case("http") {
            return Some(loc.to_string());
        }
    }
    let parsed = parse_http_url_parts(base_url).ok()?;
    let scheme = if parsed.is_https { "https" } else { "http" };
    if let Some(rest) = loc.strip_prefix("//") {
        return Some(format!("{}://{}", scheme, rest));
    }
    let default_port = if parsed.is_https { 443 } else { 80 };
    let host_fmt = if parsed.host.contains(':') {
        format!("[{}]", parsed.host)
    } else {
        parsed.host
    };
    let origin = if parsed.port == default_port {
        format!("{}://{}", scheme, host_fmt)
    } else {
        format!("{}://{}:{}", scheme, host_fmt, parsed.port)
    };
    if loc.starts_with('/') {
        Some(format!("{}{}", origin, loc))
    } else if loc.starts_with('?') {
        let base_path = parsed
            .path_and_query
            .split('?')
            .next()
            .unwrap_or("/");
        Some(format!("{}{}{}", origin, base_path, loc))
    } else {
        // Reject non-HTTP URI schemes (e.g. `file:///...`, `javascript:...`, `data:...`)
        let first_seg = loc.split(['/', '?', '#']).next().unwrap_or(loc);
        if first_seg.contains(':') {
            return None;
        }
        let base_path = parsed
            .path_and_query
            .split('?')
            .next()
            .unwrap_or("/");
        let dir = match base_path.rfind('/') {
            Some(idx) => &base_path[..=idx],
            None => "/",
        };
        Some(format!("{}{}{}", origin, dir, loc))
    }
}

#[cfg(target_os = "windows")]
mod win32_impl {
    use super::{
        is_public_routable_ip, is_remote_ip_allowed, is_same_origin, normalize_ip_addr,
        parse_http_url_parts, parse_win32_sockaddr_storage_ip, resolve_http_redirect,
        Win32SockAddrStorage, Win32WinHttpConnectionInfo, WinHttpResponse,
        WINHTTP_OPTION_CONNECTION_INFO,
    };
    use rand_core::{OsRng, RngCore};
    use std::ffi::c_void;
    use std::io::Write;
    use std::net::IpAddr;
    use std::path::{Path, PathBuf};

    type HInternet = *mut c_void;

    const WINHTTP_ACCESS_TYPE_NO_PROXY: u32 = 1;
    const WINHTTP_FLAG_SECURE: u32 = 0x0080_0000;
    const WINHTTP_OPTION_SECURE_PROTOCOLS: u32 = 84;
    const WINHTTP_OPTION_REDIRECT_POLICY: u32 = 88;
    const WINHTTP_OPTION_REDIRECT_POLICY_NEVER: u32 = 0;
    const WINHTTP_OPTION_DECOMPRESSION: u32 = 118;
    const WINHTTP_DECOMPRESSION_FLAG_ALL: u32 = 0x0000_0003;
    const WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2: u32 = 0x0000_0800;
    const WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3: u32 = 0x0000_2000;
    const WINHTTP_QUERY_CONTENT_LENGTH: u32 = 5;
    const WINHTTP_QUERY_STATUS_CODE: u32 = 19;
    const WINHTTP_QUERY_LOCATION: u32 = 33;
    const WINHTTP_QUERY_FLAG_NUMBER: u32 = 0x2000_0000;
    const WINHTTP_ADDREQ_FLAG_ADD: u32 = 0x2000_0000;
    const WINHTTP_ADDREQ_FLAG_REPLACE: u32 = 0x8000_0000;

    #[link(name = "kernel32")]
    extern "system" {
        fn GetLastError() -> u32;
    }

    #[link(name = "winhttp")]
    extern "system" {
        fn WinHttpOpen(
            psz_agent_w: *const u16,
            dw_access_type: u32,
            psz_proxy_w: *const u16,
            psz_proxy_bypass_w: *const u16,
            dw_flags: u32,
        ) -> HInternet;
        fn WinHttpSetTimeouts(
            h_internet: HInternet,
            n_resolve_timeout: i32,
            n_connect_timeout: i32,
            n_send_timeout: i32,
            n_receive_timeout: i32,
        ) -> i32;
        fn WinHttpConnect(
            h_session: HInternet,
            pswz_server_name: *const u16,
            n_server_port: u16,
            dw_reserved: u32,
        ) -> HInternet;
        fn WinHttpOpenRequest(
            h_connect: HInternet,
            pwsz_verb: *const u16,
            pwsz_object_name: *const u16,
            pwsz_version: *const u16,
            pwsz_referrer: *const u16,
            ppwsz_accept_types: *const *const u16,
            dw_flags: u32,
        ) -> HInternet;
        fn WinHttpSetOption(
            h_internet: HInternet,
            dw_option: u32,
            lp_buffer: *const c_void,
            dw_buffer_length: u32,
        ) -> i32;
        fn WinHttpQueryOption(
            h_internet: HInternet,
            dw_option: u32,
            lp_buffer: *mut c_void,
            lpdw_buffer_length: *mut u32,
        ) -> i32;
        fn WinHttpAddRequestHeaders(
            h_request: HInternet,
            lpsz_headers: *const u16,
            dw_headers_length: u32,
            dw_modifiers: u32,
        ) -> i32;
        fn WinHttpSendRequest(
            h_request: HInternet,
            lpsz_headers: *const u16,
            dw_headers_length: u32,
            lp_optional: *const c_void,
            dw_optional_length: u32,
            dw_total_length: u32,
            dw_context: usize,
        ) -> i32;
        fn WinHttpReceiveResponse(h_request: HInternet, lp_reserved: *mut c_void) -> i32;
        fn WinHttpQueryHeaders(
            h_request: HInternet,
            dw_info_level: u32,
            pwsz_name: *const u16,
            lp_buffer: *mut c_void,
            lpdw_buffer_length: *mut u32,
            lpdw_index: *mut u32,
        ) -> i32;
        fn WinHttpQueryDataAvailable(h_request: HInternet, lpdw_number_of_bytes_available: *mut u32) -> i32;
        fn WinHttpReadData(
            h_request: HInternet,
            lp_buffer: *mut c_void,
            dw_number_of_bytes_to_read: u32,
            lpdw_number_of_bytes_read: *mut u32,
        ) -> i32;
        fn WinHttpCloseHandle(h_internet: HInternet) -> i32;
    }

    struct HandleGuard(HInternet);
    impl Drop for HandleGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    let _ = WinHttpCloseHandle(self.0);
                }
            }
        }
    }

    struct TempFileGuard {
        path: Option<PathBuf>,
    }

    impl TempFileGuard {
        fn new(path: PathBuf) -> Self {
            Self { path: Some(path) }
        }
        fn disarm(&mut self) {
            self.path = None;
        }
    }

    impl Drop for TempFileGuard {
        fn drop(&mut self) {
            if let Some(ref p) = self.path {
                let _ = std::fs::remove_file(p);
            }
        }
    }

    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    fn query_remote_connection_ip(h_req: HInternet) -> Result<IpAddr, String> {
        let mut info = Win32WinHttpConnectionInfo {
            cb_size: core::mem::size_of::<Win32WinHttpConnectionInfo>() as u32,
            local_address: Win32SockAddrStorage {
                ss_family: 0,
                data: [0u8; 126],
            },
            remote_address: Win32SockAddrStorage {
                ss_family: 0,
                data: [0u8; 126],
            },
        };
        let mut buf_len = core::mem::size_of::<Win32WinHttpConnectionInfo>() as u32;
        let ok = unsafe {
            WinHttpQueryOption(
                h_req,
                WINHTTP_OPTION_CONNECTION_INFO,
                &mut info as *mut Win32WinHttpConnectionInfo as *mut c_void,
                &mut buf_len,
            )
        };
        if ok == 0 {
            let err_code = unsafe { GetLastError() };
            return Err(format!(
                "DNS rebinding protection: WinHttpQueryOption(WINHTTP_OPTION_CONNECTION_INFO) failed (win32={})",
                err_code
            ));
        }
        parse_win32_sockaddr_storage_ip(&info.remote_address)
            .ok_or_else(|| "DNS rebinding protection: unsupported remote SOCKADDR family".to_string())
    }

    fn query_location_header(h_req: HInternet) -> Option<String> {
        let mut byte_len: u32 = 0;
        let mut idx: u32 = 0;
        unsafe {
            let _ = WinHttpQueryHeaders(
                h_req,
                WINHTTP_QUERY_LOCATION,
                core::ptr::null(),
                core::ptr::null_mut(),
                &mut byte_len,
                &mut idx,
            );
            if byte_len < 2 || byte_len > 16_384 {
                return None;
            }
            let mut buf = vec![0u16; (byte_len as usize / 2) + 2];
            let mut actual_bytes = (buf.len() * 2) as u32;
            idx = 0;
            if WinHttpQueryHeaders(
                h_req,
                WINHTTP_QUERY_LOCATION,
                core::ptr::null(),
                buf.as_mut_ptr() as *mut c_void,
                &mut actual_bytes,
                &mut idx,
            ) == 0
            {
                return None;
            }
            let u16_len = (actual_bytes as usize / 2).min(buf.len());
            let s = String::from_utf16_lossy(&buf[..u16_len]);
            let trimmed = s.trim_end_matches('\0').trim().to_string();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        }
    }

    fn query_content_length_header(h_req: HInternet) -> Option<u64> {
        let mut buf = [0u16; 64];
        let mut byte_len = (buf.len() * 2) as u32;
        let mut idx: u32 = 0;
        let ok = unsafe {
            WinHttpQueryHeaders(
                h_req,
                WINHTTP_QUERY_CONTENT_LENGTH,
                core::ptr::null(),
                buf.as_mut_ptr() as *mut c_void,
                &mut byte_len,
                &mut idx,
            )
        };
        if ok == 0 || byte_len < 2 {
            return None;
        }
        let u16_len = (byte_len as usize / 2).min(buf.len());
        let s = String::from_utf16_lossy(&buf[..u16_len]);
        s.trim_end_matches('\0').trim().parse::<u64>().ok()
    }

    /// Executes a single HTTP/HTTPS GET without following redirects, writing body chunks into `sink`.
    /// Disables WPAD (`WINHTTP_ACCESS_TYPE_NO_PROXY`), pins plaintext HTTP connections directly to
    /// `pinned_ip` with an explicit `Host:` header, and validates the real connected peer IP via
    /// `WINHTTP_OPTION_CONNECTION_INFO` BEFORE reading any response body bytes.
    #[allow(clippy::too_many_arguments)]
    fn single_hop_get<F>(
        url: &str,
        user_agent: &str,
        extra_headers: &[(&str, &str)],
        connect_timeout_ms: i32,
        receive_timeout_ms: i32,
        max_bytes: usize,
        pinned_ip: Option<IpAddr>,
        allowed_ip_check: Option<fn(IpAddr) -> bool>,
        mut on_chunk: F,
    ) -> Result<(u16, Option<String>), String>
    where
        F: FnMut(&[u8], u64, u64) -> Result<(), String>,
    {
        let parsed = parse_http_url_parts(url)?;

        // Pre-validate pinned_ip before initiating any outbound socket connection.
        if let Some(pin) = pinned_ip {
            let norm_pin = normalize_ip_addr(pin);
            let pin_ok = match allowed_ip_check {
                Some(check) => check(norm_pin),
                None => is_public_routable_ip(norm_pin),
            };
            if !pin_ok {
                return Err(format!(
                    "DNS rebinding protection: refused connection to disallowed pinned IP {}",
                    norm_pin
                ));
            }
        }

        let ua_w = to_wide(user_agent);

        // Strictly disable WPAD auto-proxy discovery to prevent local LAN proxy hijacking.
        let h_session = unsafe {
            WinHttpOpen(
                ua_w.as_ptr(),
                WINHTTP_ACCESS_TYPE_NO_PROXY,
                core::ptr::null(),
                core::ptr::null(),
                0,
            )
        };
        if h_session.is_null() {
            return Err("WinHttpOpen failed".into());
        }
        let _session_guard = HandleGuard(h_session);

        unsafe {
            let _ = WinHttpSetTimeouts(
                h_session,
                connect_timeout_ms,
                connect_timeout_ms,
                receive_timeout_ms,
                receive_timeout_ms,
            );
            // Prefer TLS 1.2 + TLS 1.3 (fallback gracefully to TLS 1.2 if OS predates TLS 1.3 flag)
            let tls_12_13 = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
            if WinHttpSetOption(
                h_session,
                WINHTTP_OPTION_SECURE_PROTOCOLS,
                &tls_12_13 as *const u32 as *const c_void,
                4,
            ) == 0
            {
                let tls_12 = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
                let _ = WinHttpSetOption(
                    h_session,
                    WINHTTP_OPTION_SECURE_PROTOCOLS,
                    &tls_12 as *const u32 as *const c_void,
                    4,
                );
            }
            let decomp = WINHTTP_DECOMPRESSION_FLAG_ALL;
            let _ = WinHttpSetOption(
                h_session,
                WINHTTP_OPTION_DECOMPRESSION,
                &decomp as *const u32 as *const c_void,
                4,
            );
        }

        // For plaintext HTTP with a pinned IP, connect directly to the pinned IP and pass the
        // original host in the `Host:` header (for HTTPS, pass the hostname for TLS SNI + cert check
        // and verify the actual connected peer IP via `WINHTTP_OPTION_CONNECTION_INFO` below).
        let (connect_target, explicit_host_header) = if !parsed.is_https {
            if let Some(pin) = pinned_ip {
                let target = match normalize_ip_addr(pin) {
                    IpAddr::V4(v4) => v4.to_string(),
                    IpAddr::V6(v6) => format!("[{}]", v6),
                };
                let host_fmt = if parsed.host.contains(':') {
                    format!("[{}]", parsed.host)
                } else {
                    parsed.host.clone()
                };
                let host_hdr = if parsed.port == 80 {
                    host_fmt
                } else {
                    format!("{}:{}", host_fmt, parsed.port)
                };
                (target, Some(host_hdr))
            } else {
                let target = if parsed.host.contains(':') {
                    format!("[{}]", parsed.host)
                } else {
                    parsed.host.clone()
                };
                (target, None)
            }
        } else {
            let target = if parsed.host.contains(':') {
                format!("[{}]", parsed.host)
            } else {
                parsed.host.clone()
            };
            (target, None)
        };

        let host_w = to_wide(&connect_target);
        let h_connect = unsafe { WinHttpConnect(h_session, host_w.as_ptr(), parsed.port, 0) };
        if h_connect.is_null() {
            return Err("WinHttpConnect failed".into());
        }
        let _connect_guard = HandleGuard(h_connect);

        let verb_w = to_wide("GET");
        let path_w = to_wide(&parsed.path_and_query);
        let req_flags = if parsed.is_https {
            WINHTTP_FLAG_SECURE
        } else {
            0
        };
        let h_request = unsafe {
            WinHttpOpenRequest(
                h_connect,
                verb_w.as_ptr(),
                path_w.as_ptr(),
                core::ptr::null(),
                core::ptr::null(),
                core::ptr::null(),
                req_flags,
            )
        };
        if h_request.is_null() {
            return Err("WinHttpOpenRequest failed".into());
        }
        let _req_guard = HandleGuard(h_request);

        unsafe {
            let no_redir = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
            let _ = WinHttpSetOption(
                h_request,
                WINHTTP_OPTION_REDIRECT_POLICY,
                &no_redir as *const u32 as *const c_void,
                4,
            );
        }

        if let Some(ref host_hdr) = explicit_host_header {
            let hdr_w = to_wide(&format!("Host: {}\r\n", host_hdr));
            unsafe {
                let _ = WinHttpAddRequestHeaders(
                    h_request,
                    hdr_w.as_ptr(),
                    u32::MAX,
                    WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE,
                );
            }
        }

        for &(k, v) in extra_headers {
            if k.is_empty()
                || v.is_empty()
                || k.bytes().any(|b| matches!(b, b'\r' | b'\n' | b'\0' | b':'))
                || v.bytes().any(|b| matches!(b, b'\r' | b'\n' | b'\0'))
            {
                continue;
            }
            if explicit_host_header.is_some() && k.eq_ignore_ascii_case("host") {
                continue;
            }
            let hdr_w = to_wide(&format!("{}: {}\r\n", k, v));
            unsafe {
                let _ = WinHttpAddRequestHeaders(
                    h_request,
                    hdr_w.as_ptr(),
                    u32::MAX,
                    WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE,
                );
            }
        }

        let sent = unsafe {
            WinHttpSendRequest(
                h_request,
                core::ptr::null(),
                0,
                core::ptr::null(),
                0,
                0,
                0,
            )
        };
        if sent == 0 {
            let err_code = unsafe { GetLastError() };
            return Err(format!("WinHttpSendRequest failed (win32={})", err_code));
        }
        if unsafe { WinHttpReceiveResponse(h_request, core::ptr::null_mut()) } == 0 {
            let err_code = unsafe { GetLastError() };
            return Err(format!("WinHttpReceiveResponse failed (win32={})", err_code));
        }

        // Anti-DNS-rebinding TOCTOU verification: inspect the ACTUAL connected remote IP from
        // `WINHTTP_OPTION_CONNECTION_INFO` BEFORE reading any headers/body bytes.
        let remote_ip = query_remote_connection_ip(h_request)?;
        if !is_remote_ip_allowed(remote_ip, parsed.is_https, pinned_ip, allowed_ip_check) {
            return Err(format!(
                "DNS rebinding detected: connected remote IP {} is not permitted",
                remote_ip
            ));
        }

        let mut status_u32: u32 = 0;
        let mut status_len: u32 = 4;
        let mut idx: u32 = 0;
        if unsafe {
            WinHttpQueryHeaders(
                h_request,
                WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                core::ptr::null(),
                &mut status_u32 as *mut u32 as *mut c_void,
                &mut status_len,
                &mut idx,
            )
        } == 0
        {
            return Err("WinHttpQueryHeaders(status) failed".into());
        }
        let status_code = status_u32 as u16;
        let location = if matches!(status_code, 301 | 302 | 303 | 307 | 308) {
            query_location_header(h_request)
        } else {
            None
        };

        if matches!(status_code, 301 | 302 | 303 | 307 | 308) {
            return Ok((status_code, location));
        }

        let content_length = query_content_length_header(h_request).unwrap_or(0);
        let mut total_read: usize = 0;
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            let mut avail: u32 = 0;
            if unsafe { WinHttpQueryDataAvailable(h_request, &mut avail) } == 0 {
                return Err("WinHttpQueryDataAvailable failed".into());
            }
            if avail == 0 {
                break;
            }
            let want = (avail as usize).min(buf.len());
            let mut got: u32 = 0;
            if unsafe {
                WinHttpReadData(
                    h_request,
                    buf.as_mut_ptr() as *mut c_void,
                    want as u32,
                    &mut got,
                )
            } == 0
            {
                return Err("WinHttpReadData failed".into());
            }
            if got == 0 {
                break;
            }
            let n = got as usize;
            total_read = total_read.saturating_add(n);
            if total_read > max_bytes {
                return Err("HTTP response exceeded maximum allowed size".into());
            }
            on_chunk(&buf[..n], total_read as u64, content_length)?;
        }

        Ok((status_code, location))
    }

    /// Single-hop GET (never follows redirects — caller validates every redirect hop for SSRF).
    pub fn winhttp_get_no_redirect(
        url: &str,
        user_agent: &str,
        extra_headers: &[(&str, &str)],
        connect_timeout_ms: i32,
        receive_timeout_ms: i32,
        max_bytes: usize,
    ) -> Result<WinHttpResponse, String> {
        let mut body = Vec::new();
        let (status_code, location) = single_hop_get(
            url,
            user_agent,
            extra_headers,
            connect_timeout_ms,
            receive_timeout_ms,
            max_bytes,
            None,
            None,
            |chunk, _, _| {
                body.extend_from_slice(chunk);
                Ok(())
            },
        )?;
        Ok(WinHttpResponse {
            status_code,
            location,
            body,
        })
    }

    /// Single-hop GET with explicit anti-DNS-rebinding IP pinning (`pinned_ip`) and/or peer IP
    /// policy validation (`allowed_ip_check`) checked via `WINHTTP_OPTION_CONNECTION_INFO`.
    pub fn winhttp_get_no_redirect_pinned(
        url: &str,
        max_bytes: usize,
        user_agent: &str,
        timeout_ms: u32,
        pinned_ip: Option<IpAddr>,
        allowed_ip_check: Option<fn(IpAddr) -> bool>,
    ) -> Result<WinHttpResponse, String> {
        let t_ms = timeout_ms.min(i32::MAX as u32) as i32;
        let mut body = Vec::new();
        let (status_code, location) = single_hop_get(
            url,
            user_agent,
            &[],
            t_ms,
            t_ms,
            max_bytes,
            pinned_ip,
            allowed_ip_check,
            |chunk, _, _| {
                body.extend_from_slice(chunk);
                Ok(())
            },
        )?;
        Ok(WinHttpResponse {
            status_code,
            location,
            body,
        })
    }

    /// HTTPS-only GET following up to 6 redirects (strictly blocks downgrade to plaintext HTTP
    /// and strips `Authorization` headers when redirecting to a different `(scheme, host, port)` origin).
    pub fn winhttp_get_https_bytes(
        start_url: &str,
        user_agent: &str,
        extra_headers: &[(&str, &str)],
        connect_timeout_ms: i32,
        receive_timeout_ms: i32,
        max_bytes: usize,
    ) -> Result<Vec<u8>, String> {
        let initial = parse_http_url_parts(start_url)?;
        let mut current = start_url.to_string();

        for _ in 0..=6 {
            let parsed = parse_http_url_parts(&current)?;
            if !parsed.is_https {
                return Err("Refused non-HTTPS URL".into());
            }
            let same_origin = is_same_origin(&initial, &parsed);
            let filtered_headers: Vec<(&str, &str)> = extra_headers
                .iter()
                .copied()
                .filter(|(k, _)| same_origin || !k.eq_ignore_ascii_case("authorization"))
                .collect();

            let resp = winhttp_get_no_redirect(
                &current,
                user_agent,
                &filtered_headers,
                connect_timeout_ms,
                receive_timeout_ms,
                max_bytes,
            )?;
            if matches!(resp.status_code, 301 | 302 | 303 | 307 | 308) {
                let loc = resp
                    .location
                    .ok_or_else(|| "Redirect response missing Location header".to_string())?;
                current = resolve_http_redirect(&current, &loc)
                    .ok_or_else(|| "Invalid redirect target".to_string())?;
                continue;
            }
            if !(200..300).contains(&resp.status_code) {
                return Err(format!("HTTP error status {}", resp.status_code));
            }
            return Ok(resp.body);
        }
        Err("Too many HTTPS redirects".into())
    }

    /// Streams an HTTPS-only download into a unique temporary file and atomically renames it to
    /// `dest_path` ONLY upon complete HTTP 2xx success (never leaves a truncated file on disk).
    #[allow(clippy::too_many_arguments)]
    pub fn winhttp_download_https_to_file_with_progress<F>(
        start_url: &str,
        dest_path: &Path,
        user_agent: &str,
        extra_headers: &[(&str, &str)],
        connect_timeout_ms: i32,
        receive_timeout_ms: i32,
        max_bytes: usize,
        mut on_progress: F,
    ) -> Result<(), String>
    where
        F: FnMut(u64, u64),
    {
        let initial = parse_http_url_parts(start_url)?;
        let parent = dest_path.parent().unwrap_or_else(|| Path::new("."));
        let base_name = dest_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("download");
        let mut current = start_url.to_string();

        for _ in 0..=6 {
            let parsed = parse_http_url_parts(&current)?;
            if !parsed.is_https {
                return Err("Refused non-HTTPS download URL".into());
            }
            let same_origin = is_same_origin(&initial, &parsed);
            let filtered_headers: Vec<(&str, &str)> = extra_headers
                .iter()
                .copied()
                .filter(|(k, _)| same_origin || !k.eq_ignore_ascii_case("authorization"))
                .collect();

            let mut rnd = [0u8; 8];
            OsRng.fill_bytes(&mut rnd);
            let tmp_path = parent.join(format!(
                ".{}.{}.{}.dl.tmp",
                base_name,
                std::process::id(),
                hex::encode(rnd)
            ));
            let mut tmp_guard = TempFileGuard::new(tmp_path.clone());
            let mut file_opt: Option<std::fs::File> = None;

            let (status_code, location) = single_hop_get(
                &current,
                user_agent,
                &filtered_headers,
                connect_timeout_ms,
                receive_timeout_ms,
                max_bytes,
                None,
                None,
                |chunk, downloaded, total| {
                    if file_opt.is_none() {
                        let f = std::fs::OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .open(&tmp_path)
                            .map_err(|e| {
                                format!("Failed creating temp file {}: {}", tmp_path.display(), e)
                            })?;
                        file_opt = Some(f);
                    }
                    if let Some(ref mut f) = file_opt {
                        f.write_all(chunk)
                            .map_err(|e| format!("Failed writing download: {}", e))?;
                    }
                    on_progress(downloaded, total);
                    Ok(())
                },
            )?;

            if matches!(status_code, 301 | 302 | 303 | 307 | 308) {
                drop(file_opt);
                drop(tmp_guard);
                let loc = location
                    .ok_or_else(|| "Redirect response missing Location header".to_string())?;
                current = resolve_http_redirect(&current, &loc)
                    .ok_or_else(|| "Invalid redirect target".to_string())?;
                continue;
            }
            if !(200..300).contains(&status_code) {
                drop(file_opt);
                drop(tmp_guard);
                return Err(format!("HTTP download error status {}", status_code));
            }

            if let Some(mut f) = file_opt.take() {
                f.flush()
                    .map_err(|e| format!("Failed flushing download: {}", e))?;
                f.sync_all()
                    .map_err(|e| format!("Failed syncing download: {}", e))?;
            } else {
                let f = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&tmp_path)
                    .map_err(|e| {
                        format!("Failed creating empty download {}: {}", tmp_path.display(), e)
                    })?;
                f.sync_all()
                    .map_err(|e| format!("Failed syncing download: {}", e))?;
            }

            // Atomic commit after file handle is closed (required on Windows NTFS).
            std::fs::rename(&tmp_path, dest_path)
                .map_err(|e| format!("Failed committing download {}: {}", dest_path.display(), e))?;
            tmp_guard.disarm();
            return Ok(());
        }
        Err("Too many HTTPS redirects".into())
    }

    /// Streams an HTTPS-only download directly to `dest_path` (following up to 6 HTTPS redirects).
    pub fn winhttp_download_https_to_file(
        start_url: &str,
        dest_path: &Path,
        user_agent: &str,
        extra_headers: &[(&str, &str)],
        connect_timeout_ms: i32,
        receive_timeout_ms: i32,
        max_bytes: usize,
    ) -> Result<(), String> {
        winhttp_download_https_to_file_with_progress(
            start_url,
            dest_path,
            user_agent,
            extra_headers,
            connect_timeout_ms,
            receive_timeout_ms,
            max_bytes,
            |_, _| {},
        )
    }
}

#[cfg(target_os = "windows")]
pub use win32_impl::{
    winhttp_download_https_to_file, winhttp_download_https_to_file_with_progress,
    winhttp_get_https_bytes, winhttp_get_no_redirect, winhttp_get_no_redirect_pinned,
};

#[cfg(not(target_os = "windows"))]
pub fn winhttp_get_no_redirect_pinned(
    _url: &str,
    _max_bytes: usize,
    _user_agent: &str,
    _timeout_ms: u32,
    _pinned_ip: Option<IpAddr>,
    _allowed_ip_check: Option<fn(IpAddr) -> bool>,
) -> Result<WinHttpResponse, String> {
    Err("WinHTTP is only available on Windows".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_case_insensitive_scheme_and_same_origin_tuple() {
        let upper = parse_http_url_parts("HTTPS://API.GitHub.COM:443/repos/a/b").unwrap();
        assert!(upper.is_https);
        assert_eq!(upper.host, "API.GitHub.COM");
        assert_eq!(upper.port, 443);

        let lower = parse_http_url_parts("https://api.github.com/other").unwrap();
        assert!(is_same_origin(&upper, &lower));

        // Cross-port MUST NOT be considered same-origin (prevents Authorization leak)
        let cross_port = parse_http_url_parts("https://api.github.com:8443/other").unwrap();
        assert!(!is_same_origin(&upper, &cross_port));

        // Cross-scheme MUST NOT be same-origin
        let http_same_host = parse_http_url_parts("Http://api.github.com:443/other").unwrap();
        assert!(!http_same_host.is_https);
        assert!(!is_same_origin(&upper, &http_same_host));

        // Cross-host MUST NOT be same-origin
        let other_host = parse_http_url_parts("https://objects.githubusercontent.com/x").unwrap();
        assert!(!is_same_origin(&upper, &other_host));

        // Case-insensitive redirect target resolution
        assert_eq!(
            resolve_http_redirect("https://github.com/a", "HTTPS://objects.githubusercontent.com/x"),
            Some("HTTPS://objects.githubusercontent.com/x".to_string())
        );
    }

    #[test]
    fn test_public_ip_and_win32_connection_info_dns_rebinding_guard() {
        assert_eq!(WINHTTP_OPTION_CONNECTION_INFO, 93);
        assert_eq!(core::mem::size_of::<Win32SockAddrStorage>(), 128);
        assert_eq!(core::mem::align_of::<Win32SockAddrStorage>(), 8);
        assert_eq!(core::mem::size_of::<Win32WinHttpConnectionInfo>(), 264);

        // Public routable IPs allowed
        assert!(is_public_routable_ip("1.1.1.1".parse().unwrap()));
        assert!(is_public_routable_ip("140.82.121.4".parse().unwrap()));
        assert!(is_public_routable_ip("2606:4700:4700::1111".parse().unwrap()));

        // Loopback, RFC1918, metadata, CGNAT, ULA, link-local, IPv4-mapped private, NAT64 private blocked
        for blocked in [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "::1",
            "::",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.5",
            "::ffff:169.254.169.254",
            "64:ff9b::127.0.0.1",
            "64:ff9b::10.0.0.1",
        ] {
            let ip: IpAddr = blocked.parse().unwrap();
            assert!(!is_public_routable_ip(ip), "must block private/non-public IP {}", blocked);
        }

        // Parse Win32 AF_INET remote sockaddr
        let mut sa4 = Win32SockAddrStorage {
            ss_family: 2,
            data: [0u8; 126],
        };
        sa4.data[2..6].copy_from_slice(&[169, 254, 169, 254]);
        let extracted4 = parse_win32_sockaddr_storage_ip(&sa4).unwrap();
        assert_eq!(extracted4, IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)));
        assert!(!is_remote_ip_allowed(extracted4, true, None, None));

        // Parse Win32 AF_INET6 with IPv4-mapped loopback (::ffff:127.0.0.1)
        let mut sa6 = Win32SockAddrStorage {
            ss_family: 23,
            data: [0u8; 126],
        };
        sa6.data[16] = 0xff;
        sa6.data[17] = 0xff;
        sa6.data[18..22].copy_from_slice(&[127, 0, 0, 1]);
        let extracted6 = parse_win32_sockaddr_storage_ip(&sa6).unwrap();
        assert_eq!(extracted6, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(!is_remote_ip_allowed(extracted6, true, None, None));

        // HTTP pinned IP mismatch blocked even if both public
        let pub_a: IpAddr = "1.1.1.1".parse().unwrap();
        let pub_b: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(is_remote_ip_allowed(pub_a, false, Some(pub_a), None));
        assert!(!is_remote_ip_allowed(pub_b, false, Some(pub_a), None));

        // Custom allowed_ip_check respected
        fn only_cloudflare(ip: IpAddr) -> bool {
            ip == IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))
        }
        assert!(is_remote_ip_allowed(pub_a, true, None, Some(only_cloudflare)));
        assert!(!is_remote_ip_allowed(pub_b, true, None, Some(only_cloudflare)));
    }
}
