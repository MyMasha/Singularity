//! Zero-Subprocess Native Win32 HTTPS/HTTP Client (`winhttp.dll`).
//!
//! Eliminates ALL `curl.exe` and `powershell.exe` child process spawns on Windows during
//! browsing, favicon fetching, update checks, self-updates, and Chrome Web Store installs —
//! making flashing terminal/console windows 100% impossible while delivering native TLS 1.2/1.3
//! performance and respecting Windows system proxy settings.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedHttpUrl {
    pub is_https: bool,
    pub host: String,
    pub port: u16,
    pub path_and_query: String,
}

/// Parses an `http://` or `https://` URL into host, port, and path+query components.
/// Rejects embedded userinfo (`@`), control characters, non-HTTP schemes, and empty hosts.
pub fn parse_http_url_parts(raw_url: &str) -> Result<ParsedHttpUrl, String> {
    let trimmed = raw_url.trim();
    if trimmed.is_empty() || trimmed.bytes().any(|b| b <= 0x1f || b == 0x7f) {
        return Err("URL contains invalid control characters".into());
    }
    let (is_https, rest) = if let Some(r) = trimmed.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = trimmed.strip_prefix("http://") {
        (false, r)
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

/// Resolves a relative or absolute HTTP `Location` redirect target against `base_url`.
pub fn resolve_http_redirect(base_url: &str, location: &str) -> Option<String> {
    let loc = location.trim();
    if loc.is_empty() || loc.bytes().any(|b| b <= 0x1f || b == 0x7f) {
        return None;
    }
    let lower = loc.to_ascii_lowercase();
    if lower.starts_with("https://") || lower.starts_with("http://") {
        return Some(loc.to_string());
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
pub struct WinHttpResponse {
    pub status_code: u16,
    pub location: Option<String>,
    pub body: Vec<u8>,
}

#[cfg(target_os = "windows")]
mod win32_impl {
    use super::{parse_http_url_parts, resolve_http_redirect, WinHttpResponse};
    use std::ffi::c_void;
    use std::io::Write;
    use std::path::Path;

    type HInternet = *mut c_void;

    const WINHTTP_ACCESS_TYPE_DEFAULT_PROXY: u32 = 0;
    const WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY: u32 = 4;
    const WINHTTP_FLAG_SECURE: u32 = 0x0080_0000;
    const WINHTTP_OPTION_SECURE_PROTOCOLS: u32 = 84;
    const WINHTTP_OPTION_REDIRECT_POLICY: u32 = 88;
    const WINHTTP_OPTION_REDIRECT_POLICY_NEVER: u32 = 0;
    const WINHTTP_OPTION_DECOMPRESSION: u32 = 118;
    const WINHTTP_DECOMPRESSION_FLAG_ALL: u32 = 0x0000_0003;
    const WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2: u32 = 0x0000_0800;
    const WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3: u32 = 0x0000_2000;
    const WINHTTP_QUERY_STATUS_CODE: u32 = 19;
    const WINHTTP_QUERY_LOCATION: u32 = 33;
    const WINHTTP_QUERY_FLAG_NUMBER: u32 = 0x2000_0000;
    const WINHTTP_ADDREQ_FLAG_ADD: u32 = 0x2000_0000;
    const WINHTTP_ADDREQ_FLAG_REPLACE: u32 = 0x8000_0000;

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

    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
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

    /// Executes a single HTTP/HTTPS GET without following redirects, writing body chunks into `sink`.
    fn single_hop_get<F>(
        url: &str,
        user_agent: &str,
        extra_headers: &[(&str, &str)],
        connect_timeout_ms: i32,
        receive_timeout_ms: i32,
        max_bytes: usize,
        mut on_chunk: F,
    ) -> Result<(u16, Option<String>), String>
    where
        F: FnMut(&[u8]) -> Result<(), String>,
    {
        let parsed = parse_http_url_parts(url)?;
        let ua_w = to_wide(user_agent);

        let h_session = unsafe {
            let s = WinHttpOpen(
                ua_w.as_ptr(),
                WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                core::ptr::null(),
                core::ptr::null(),
                0,
            );
            if !s.is_null() {
                s
            } else {
                WinHttpOpen(
                    ua_w.as_ptr(),
                    WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                    core::ptr::null(),
                    core::ptr::null(),
                    0,
                )
            }
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

        let host_w = to_wide(&parsed.host);
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

        for &(k, v) in extra_headers {
            if k.is_empty()
                || v.is_empty()
                || k.bytes().any(|b| matches!(b, b'\r' | b'\n' | b'\0' | b':'))
                || v.bytes().any(|b| matches!(b, b'\r' | b'\n' | b'\0'))
            {
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
            return Err("WinHttpSendRequest failed".into());
        }
        if unsafe { WinHttpReceiveResponse(h_request, core::ptr::null_mut()) } == 0 {
            return Err("WinHttpReceiveResponse failed".into());
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
            on_chunk(&buf[..n])?;
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
            |chunk| {
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
    /// and strips `Authorization` headers when redirecting to a different host such as GitHub CDN).
    pub fn winhttp_get_https_bytes(
        start_url: &str,
        user_agent: &str,
        extra_headers: &[(&str, &str)],
        connect_timeout_ms: i32,
        receive_timeout_ms: i32,
        max_bytes: usize,
    ) -> Result<Vec<u8>, String> {
        let initial_host = parse_http_url_parts(start_url)?.host.to_ascii_lowercase();
        let mut current = start_url.to_string();

        for _ in 0..=6 {
            let parsed = parse_http_url_parts(&current)?;
            if !parsed.is_https {
                return Err("Refused non-HTTPS URL".into());
            }
            let same_origin = parsed.host.eq_ignore_ascii_case(&initial_host);
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
        let initial_host = parse_http_url_parts(start_url)?.host.to_ascii_lowercase();
        let mut current = start_url.to_string();

        for _ in 0..=6 {
            let parsed = parse_http_url_parts(&current)?;
            if !parsed.is_https {
                return Err("Refused non-HTTPS download URL".into());
            }
            let same_origin = parsed.host.eq_ignore_ascii_case(&initial_host);
            let filtered_headers: Vec<(&str, &str)> = extra_headers
                .iter()
                .copied()
                .filter(|(k, _)| same_origin || !k.eq_ignore_ascii_case("authorization"))
                .collect();

            let mut file_opt: Option<std::fs::File> = None;
            let (status_code, location) = single_hop_get(
                &current,
                user_agent,
                &filtered_headers,
                connect_timeout_ms,
                receive_timeout_ms,
                max_bytes,
                |chunk| {
                    if file_opt.is_none() {
                        let f = std::fs::File::create(dest_path)
                            .map_err(|e| format!("Failed creating {}: {}", dest_path.display(), e))?;
                        file_opt = Some(f);
                    }
                    if let Some(ref mut f) = file_opt {
                        f.write_all(chunk)
                            .map_err(|e| format!("Failed writing download: {}", e))?;
                    }
                    Ok(())
                },
            )?;
            if matches!(status_code, 301 | 302 | 303 | 307 | 308) {
                let _ = std::fs::remove_file(dest_path);
                let loc = location
                    .ok_or_else(|| "Redirect response missing Location header".to_string())?;
                current = resolve_http_redirect(&current, &loc)
                    .ok_or_else(|| "Invalid redirect target".to_string())?;
                continue;
            }
            if !(200..300).contains(&status_code) {
                let _ = std::fs::remove_file(dest_path);
                return Err(format!("HTTP download error status {}", status_code));
            }
            if let Some(mut f) = file_opt {
                let _ = f.flush();
            } else {
                let _ = std::fs::File::create(dest_path);
            }
            return Ok(());
        }
        let _ = std::fs::remove_file(dest_path);
        Err("Too many HTTPS redirects".into())
    }
}

#[cfg(target_os = "windows")]
pub use win32_impl::{
    winhttp_download_https_to_file, winhttp_get_https_bytes, winhttp_get_no_redirect,
};
