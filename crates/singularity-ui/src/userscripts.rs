//! Native Userscript Engine (`==UserScript==` Metadata Parser, Chromium Match Pattern
//! & Glob Engine, SRI Integrity Verifier, Security Risk Analyzer, Isolated-World `GM_*`
//! / `GM.*` Wrapper Generator, and Tampermonkey/Violentmonkey JSON+ZIP Backup Manager).
//!
//! 100% pure Rust, zero external runtime dependencies.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::collections::BTreeMap;
use std::fs;
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Maximum single userscript size accepted on import (4 MiB).
pub const MAX_USERSCRIPT_BYTES: usize = 4 * 1024 * 1024;
/// Maximum number of entries accepted from a userscript ZIP backup.
const MAX_ZIP_IMPORT_ENTRIES: usize = 256;
/// Maximum cumulative decompressed bytes accepted from a userscript ZIP backup (16 MiB).
const MAX_ZIP_IMPORT_TOTAL_BYTES: usize = 16 * 1024 * 1024;

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ============================================================================
// 1. Metadata Types & `==UserScript==` Block Parser
// ============================================================================

/// Execution timing corresponding to `@run-at`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RunAt {
    DocumentStart,
    DocumentBody,
    DocumentEnd,
    DocumentIdle,
    ContextMenu,
}

impl Default for RunAt {
    fn default() -> Self {
        Self::DocumentEnd
    }
}

impl RunAt {
    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "document-start" => Self::DocumentStart,
            "document-body" => Self::DocumentBody,
            "document-end" => Self::DocumentEnd,
            "document-idle" => Self::DocumentIdle,
            "context-menu" => Self::ContextMenu,
            _ => Self::DocumentEnd,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DocumentStart => "document-start",
            Self::DocumentBody => "document-body",
            Self::DocumentEnd => "document-end",
            Self::DocumentIdle => "document-idle",
            Self::ContextMenu => "context-menu",
        }
    }
}

/// Complete parsed metadata from a `// ==UserScript== ... // ==/UserScript==` header.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserScriptMeta {
    pub name: String,
    #[serde(default)]
    pub localized_names: BTreeMap<String, String>,
    pub namespace: Option<String>,
    pub version: Option<String>,
    pub description: Option<String>,
    #[serde(default)]
    pub localized_descriptions: BTreeMap<String, String>,
    pub author: Option<String>,
    pub icon: Option<String>,
    #[serde(default)]
    pub matches: Vec<String>,
    #[serde(default)]
    pub includes: Vec<String>,
    #[serde(default)]
    pub excludes: Vec<String>,
    #[serde(default)]
    pub exclude_matches: Vec<String>,
    #[serde(default)]
    pub grants: Vec<String>,
    #[serde(default)]
    pub requires: Vec<String>,
    #[serde(default)]
    pub resources: BTreeMap<String, String>,
    pub run_at: RunAt,
    #[serde(default)]
    pub connects: Vec<String>,
    #[serde(default)]
    pub noframes: bool,
    pub update_url: Option<String>,
    pub download_url: Option<String>,
    pub homepage_url: Option<String>,
    /// Raw metadata header block preserved verbatim for `GM_info.scriptMetaStr`.
    #[serde(default)]
    pub raw_meta_block: String,
}

impl UserScriptMeta {
    /// Returns `@name:<lang>` (or base language prefix) if available, otherwise `@name`.
    pub fn display_name(&self, lang: &str) -> &str {
        let lower = lang.trim().to_ascii_lowercase();
        if let Some(loc) = self.localized_names.get(&lower) {
            return loc.as_str();
        }
        if let Some(base) = lower.split(['-', '_']).next() {
            if let Some(loc) = self.localized_names.get(base) {
                return loc.as_str();
            }
        }
        self.name.as_str()
    }

    /// Returns `@description:<lang>` if available, otherwise `@description`.
    pub fn display_description(&self, lang: &str) -> Option<&str> {
        let lower = lang.trim().to_ascii_lowercase();
        if let Some(loc) = self.localized_descriptions.get(&lower) {
            return Some(loc.as_str());
        }
        if let Some(base) = lower.split(['-', '_']).next() {
            if let Some(loc) = self.localized_descriptions.get(base) {
                return Some(loc.as_str());
            }
        }
        self.description.as_deref()
    }

    /// Checks whether a specific `GM_*` or `GM.*` API was requested via `@grant`.
    pub fn has_grant(&self, grant_name: &str) -> bool {
        self.grants.iter().any(|g| g == grant_name)
    }

    /// Deterministic stable script ID derived from `@namespace` + `@name` (SHA-256 prefix).
    pub fn compute_id(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.namespace.as_deref().unwrap_or("singularity:default").as_bytes());
        hasher.update(b"\0");
        hasher.update(self.name.as_bytes());
        let digest = hasher.finalize();
        hex::encode(&digest[..16])
    }
}

/// Parses a `==UserScript==` metadata block from userscript JavaScript source.
pub fn parse_userscript_metadata(source: &str) -> Result<UserScriptMeta, String> {
    if source.len() > MAX_USERSCRIPT_BYTES {
        return Err(format!(
            "Userscript exceeds maximum size of {} bytes",
            MAX_USERSCRIPT_BYTES
        ));
    }

    let mut in_block = false;
    let mut found_end = false;
    let mut raw_lines: Vec<&str> = Vec::new();
    let mut meta = UserScriptMeta::default();

    for raw_line in source.lines() {
        let line = raw_line.trim_end_matches('\r');
        let trimmed = line.trim();

        if !in_block {
            if let Some(rest) = trimmed.strip_prefix("//") {
                if rest.trim() == "==UserScript==" {
                    in_block = true;
                    raw_lines.push(line);
                }
            }
            continue;
        }

        raw_lines.push(line);
        let Some(comment_body) = trimmed.strip_prefix("//") else {
            continue;
        };
        let body = comment_body.trim();
        if body == "==/UserScript==" {
            found_end = true;
            break;
        }
        let Some(directive) = body.strip_prefix('@') else {
            continue;
        };

        let (key, val) = match directive.find(|c: char| c.is_whitespace()) {
            Some(idx) => (directive[..idx].trim(), directive[idx..].trim()),
            None => (directive.trim(), ""),
        };

        if let Some(locale) = key.strip_prefix("name:") {
            let loc = locale.trim().to_ascii_lowercase();
            if !loc.is_empty() && !val.is_empty() {
                meta.localized_names.insert(loc, val.to_string());
            }
            continue;
        }
        if let Some(locale) = key.strip_prefix("description:") {
            let loc = locale.trim().to_ascii_lowercase();
            if !loc.is_empty() && !val.is_empty() {
                meta.localized_descriptions.insert(loc, val.to_string());
            }
            continue;
        }

        match key {
            "name" => {
                if meta.name.is_empty() && !val.is_empty() {
                    meta.name = val.to_string();
                }
            }
            "namespace" => {
                if !val.is_empty() {
                    meta.namespace = Some(val.to_string());
                }
            }
            "version" => {
                if !val.is_empty() {
                    meta.version = Some(val.to_string());
                }
            }
            "description" => {
                if meta.description.is_none() && !val.is_empty() {
                    meta.description = Some(val.to_string());
                }
            }
            "author" => {
                if !val.is_empty() {
                    meta.author = Some(val.to_string());
                }
            }
            "icon" | "iconURL" | "icon64" | "icon64URL" => {
                if meta.icon.is_none() && !val.is_empty() {
                    meta.icon = Some(val.to_string());
                }
            }
            "match" => {
                if !val.is_empty() {
                    meta.matches.push(val.to_string());
                }
            }
            "include" => {
                if !val.is_empty() {
                    meta.includes.push(val.to_string());
                }
            }
            "exclude" => {
                if !val.is_empty() {
                    meta.excludes.push(val.to_string());
                }
            }
            "exclude-match" => {
                if !val.is_empty() {
                    meta.exclude_matches.push(val.to_string());
                }
            }
            "grant" => {
                if !val.is_empty() && !meta.grants.iter().any(|g| g == val) {
                    meta.grants.push(val.to_string());
                }
            }
            "require" => {
                if !val.is_empty() {
                    meta.requires.push(val.to_string());
                }
            }
            "resource" => {
                let mut parts = val.split_whitespace();
                if let (Some(res_name), Some(res_url)) = (parts.next(), parts.next()) {
                    meta.resources
                        .insert(res_name.to_string(), res_url.to_string());
                }
            }
            "run-at" => {
                meta.run_at = RunAt::parse(val);
            }
            "connect" => {
                if !val.is_empty() && !meta.connects.iter().any(|c| c == val) {
                    meta.connects.push(val.to_string());
                }
            }
            "noframes" => {
                meta.noframes = true;
            }
            "updateURL" => {
                if !val.is_empty() {
                    meta.update_url = Some(val.to_string());
                }
            }
            "downloadURL" => {
                if !val.is_empty() {
                    meta.download_url = Some(val.to_string());
                }
            }
            "homepageURL" | "homepage" | "website" | "source" => {
                if meta.homepage_url.is_none() && !val.is_empty() {
                    meta.homepage_url = Some(val.to_string());
                }
            }
            _ => {}
        }
    }

    if !in_block || !found_end {
        return Err("Missing complete // ==UserScript== ... // ==/UserScript== header block".into());
    }
    if meta.name.trim().is_empty() {
        return Err("Userscript metadata is missing required @name directive".into());
    }
    if meta.grants.is_empty() {
        meta.grants.push("none".into());
    }
    meta.raw_meta_block = raw_lines.join("\n");
    Ok(meta)
}

// ============================================================================
// 2. URL Matching Engine (Chromium Match Patterns + Wildcard Globs + Excludes)
// ============================================================================

#[derive(Debug, Clone)]
struct ParsedUrlParts<'a> {
    scheme: &'a str,
    host: &'a str,
    path_and_query: &'a str,
}

fn split_url_parts(url: &str) -> Option<ParsedUrlParts<'_>> {
    let sep = url.find("://")?;
    let scheme = &url[..sep];
    if scheme.is_empty() {
        return None;
    }
    let after_scheme = &url[sep + 3..];
    if scheme.eq_ignore_ascii_case("file") {
        return Some(ParsedUrlParts {
            scheme,
            host: "",
            path_and_query: after_scheme,
        });
    }
    let (authority, path_and_query) = match after_scheme.find('/') {
        Some(idx) => (&after_scheme[..idx], &after_scheme[idx..]),
        None => (after_scheme, "/"),
    };
    // Strip userinfo@ and :port from host
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    let host = if host_port.starts_with('[') {
        // IPv6 literal [::1]:8080
        host_port
            .find(']')
            .map(|end| &host_port[..=end])
            .unwrap_or(host_port)
    } else {
        host_port.split(':').next().unwrap_or(host_port)
    };
    Some(ParsedUrlParts {
        scheme,
        host,
        path_and_query,
    })
}

/// Evaluates a Chromium match pattern such as `*://*.example.com/*`, `<all_urls>`,
/// `https://example.com/docs/*`, or `file:///home/*`.
pub fn match_chromium_pattern(pattern: &str, url: &str) -> bool {
    let pat = pattern.trim();
    if pat.is_empty() {
        return false;
    }
    let Some(u) = split_url_parts(url) else {
        return false;
    };
    let u_scheme = u.scheme.to_ascii_lowercase();

    if pat == "<all_urls>" {
        return matches!(
            u_scheme.as_str(),
            "http" | "https" | "file" | "ftp" | "ws" | "wss"
        );
    }

    let Some(sep) = pat.find("://") else {
        return false;
    };
    let p_scheme = pat[..sep].to_ascii_lowercase();
    let rest = &pat[sep + 3..];

    // Scheme check: `*` matches http and https only per Chromium spec
    let scheme_ok = if p_scheme == "*" {
        u_scheme == "http" || u_scheme == "https"
    } else {
        p_scheme == u_scheme
    };
    if !scheme_ok {
        return false;
    }

    if p_scheme == "file" {
        return glob_match(rest, u.path_and_query);
    }

    let Some(slash_idx) = rest.find('/') else {
        return false;
    };
    let p_host_raw = &rest[..slash_idx];
    let p_host = p_host_raw
        .split(':')
        .next()
        .unwrap_or(p_host_raw)
        .to_ascii_lowercase();
    let p_path = &rest[slash_idx..];

    let u_host = u.host.to_ascii_lowercase();
    let host_ok = if p_host == "*" {
        !u_host.is_empty()
    } else if let Some(base) = p_host.strip_prefix("*.") {
        !base.is_empty() && (u_host == base || u_host.ends_with(&format!(".{}", base)))
    } else {
        u_host == p_host
    };
    if !host_ok {
        return false;
    }

    // Strip fragment from URL before path matching
    let url_path_no_hash = u
        .path_and_query
        .split('#')
        .next()
        .unwrap_or(u.path_and_query);
    glob_match(p_path, url_path_no_hash)
}

/// Evaluates a `@include` / `@exclude` wildcard glob pattern (supports `*` and `.tld`).
pub fn match_glob_url(pattern: &str, url: &str) -> bool {
    let pat = pattern.trim();
    if pat.is_empty() {
        return false;
    }
    if pat == "*" || pat == "<all_urls>" {
        return true;
    }
    // Support Greasemonkey `.tld/` magic TLD by expanding to `.*`
    let expanded = pat.replace(".tld/", ".*/").replace(".tld:", ".*:");
    glob_match(&expanded, url)
}

fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star_pi: Option<usize> = None;
    let mut star_ti = 0usize;

    while ti < t.len() {
        if pi < p.len() && p[pi] == t[ti] {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star_pi = Some(pi);
            pi += 1;
            star_ti = ti;
        } else if let Some(sp) = star_pi {
            pi = sp + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

fn extract_url_host(url: &str) -> Option<&str> {
    let sep = url.find("://")?;
    let after_scheme = &url[sep + 3..];
    let authority_end = after_scheme
        .find(['/', '?', '#', '\\'])
        .unwrap_or(after_scheme.len());
    let authority = &after_scheme[..authority_end];
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    if host_port.starts_with('[') {
        let host = host_port
            .find(']')
            .map(|end| &host_port[..=end])
            .unwrap_or(host_port);
        Some(host)
    } else {
        Some(host_port.split(':').next().unwrap_or(host_port))
    }
}

fn parse_single_int_ipv4(s: &str) -> Option<u32> {
    if let Some(hex) = s.strip_prefix("0x") {
        u32::from_str_radix(hex, 16).ok()
    } else if s.starts_with('0') && s.len() > 1 && s.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
        u32::from_str_radix(s, 8).ok()
    } else if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) {
        s.parse::<u32>().ok()
    } else {
        None
    }
}

fn is_ipv6_mapped_loopback_or_unspecified(v6: std::net::Ipv6Addr) -> bool {
    let segs = v6.segments();
    if segs[0..5] == [0, 0, 0, 0, 0] && segs[5] == 0xffff {
        let v4 = std::net::Ipv4Addr::new(
            (segs[6] >> 8) as u8,
            (segs[6] & 0xff) as u8,
            (segs[7] >> 8) as u8,
            (segs[7] & 0xff) as u8,
        );
        return v4.is_loopback() || v4.is_unspecified();
    }
    false
}

fn is_loopback_or_local_host(raw_host: &str) -> bool {
    let trimmed = raw_host.trim().trim_end_matches('.').to_ascii_lowercase();
    if trimmed.is_empty() {
        return false;
    }
    let bare = trimmed.trim_start_matches('[').trim_end_matches(']');
    if bare == "localhost"
        || bare.ends_with(".localhost")
        || bare == "127.0.0.1"
        || bare == "0.0.0.0"
        || bare == "::1"
        || bare == "::"
        || bare.starts_with("127.")
    {
        return true;
    }
    if let Ok(ip) = bare.parse::<std::net::IpAddr>() {
        return match ip {
            std::net::IpAddr::V4(v4) => v4.is_loopback() || v4.is_unspecified(),
            std::net::IpAddr::V6(v6) => {
                v6.is_loopback()
                    || v6.is_unspecified()
                    || is_ipv6_mapped_loopback_or_unspecified(v6)
            }
        };
    }
    if let Some(n) = parse_single_int_ipv4(bare) {
        let v4 = std::net::Ipv4Addr::from(n);
        if v4.is_loopback() || v4.is_unspecified() {
            return true;
        }
    }
    false
}

/// Determines whether a userscript should run on `url` (respecting `@noframes`,
/// `@exclude`, `@exclude-match`, `@match`, and `@include`).
pub fn matches_url(meta: &UserScriptMeta, url: &str, is_main_frame: bool) -> bool {
    if meta.noframes && !is_main_frame {
        return false;
    }
    // Never inject userscripts into internal browser pages, non-web schemes,
    // or local loopback origins (which host the privileged Singularity UI server).
    let trimmed = url.trim();
    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("browser://")
        || lower.starts_with("singularity://")
        || lower.starts_with("chrome://")
        || lower.starts_with("chrome-extension://")
        || lower.starts_with("edge://")
        || lower.starts_with("devtools://")
        || lower.starts_with("view-source:")
        || lower.starts_with("javascript:")
        || lower.starts_with("data:")
        || lower.starts_with("about:")
        || lower.starts_with("blob:")
        || lower.starts_with("file:")
        || lower.starts_with("filesystem:")
    {
        return false;
    }
    if let Some(host) = extract_url_host(trimmed) {
        if is_loopback_or_local_host(host) {
            return false;
        }
    }

    // Exclusions take absolute precedence
    for ex in &meta.exclude_matches {
        if match_chromium_pattern(ex, url) {
            return false;
        }
    }
    for ex in &meta.excludes {
        if match_glob_url(ex, url) {
            return false;
        }
    }

    // Must satisfy at least one @match or @include rule
    if meta.matches.iter().any(|m| match_chromium_pattern(m, url)) {
        return true;
    }
    if meta.includes.iter().any(|inc| match_glob_url(inc, url)) {
        return true;
    }
    false
}

// ============================================================================
// 3. Subresource Integrity (SRI) Verifier for `@require` / `@resource`
// ============================================================================

/// Verifies downloaded bytes against a Userscript SRI hash fragment (`#sha256=<hex|b64>`,
/// `#sha384=...`, `#sha512=...`, or HTML SRI `sha256-<b64>`).
///
/// Accepts either a full `@require` URL containing `#sha256=...` or a bare SRI spec.
/// Returns `Ok(true)` when the digest matches in constant time, `Ok(false)` on mismatch,
/// or `Err` when the spec is missing/unsupported/malformed.
pub fn verify_sri_hash(bytes: &[u8], sri_spec: &str) -> Result<bool, String> {
    let spec_part = match sri_spec.find('#') {
        Some(idx) => &sri_spec[idx + 1..],
        None => sri_spec.trim(),
    };
    if spec_part.is_empty() {
        return Err("Missing SRI hash specification".into());
    }

    // Support comma/semicolon-separated Tampermonkey fragments (e.g. `#sha256=abc,md5=xyz`)
    // and standard HTML SRI tokens (`sha256-<base64=>`) without misparsing Base64 `=` padding.
    let mut evaluated_any = false;
    for token in spec_part.split([',', ';', ' ']).filter(|s| !s.is_empty()) {
        let Some((alg, encoded)) = extract_sri_alg_and_digest(token) else {
            continue;
        };

        let computed: Vec<u8> = match alg {
            "sha256" => Sha256::digest(bytes).to_vec(),
            "sha384" => Sha384::digest(bytes).to_vec(),
            "sha512" => Sha512::digest(bytes).to_vec(),
            _ => continue,
        };

        let expected = decode_digest_bytes(encoded, computed.len())
            .ok_or_else(|| format!("Invalid {} digest encoding '{}'", alg, encoded))?;

        evaluated_any = true;
        if !ct_eq(&computed, &expected) {
            return Ok(false);
        }
    }

    if !evaluated_any {
        return Err(format!(
            "No supported SHA-256/384/512 SRI hash found in '{}'",
            sri_spec
        ));
    }
    Ok(true)
}

fn extract_sri_alg_and_digest(token: &str) -> Option<(&'static str, &str)> {
    const PREFIXES: &[(&str, &str)] = &[
        ("sha256=", "sha256"),
        ("sha-256=", "sha256"),
        ("sha256-", "sha256"),
        ("sha384=", "sha384"),
        ("sha-384=", "sha384"),
        ("sha384-", "sha384"),
        ("sha512=", "sha512"),
        ("sha-512=", "sha512"),
        ("sha512-", "sha512"),
    ];
    let trimmed = token.trim();
    for &(prefix, canonical_alg) in PREFIXES {
        if trimmed.len() > prefix.len()
            && trimmed.as_bytes()[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes())
        {
            return Some((canonical_alg, trimmed[prefix.len()..].trim()));
        }
    }
    None
}

fn decode_digest_bytes(encoded: &str, expected_len: usize) -> Option<Vec<u8>> {
    if encoded.len() == expected_len * 2 && encoded.bytes().all(|b| b.is_ascii_hexdigit()) {
        return hex::decode(encoded).ok();
    }
    let decoded = BASE64.decode(encoded).ok()?;
    if decoded.len() == expected_len {
        Some(decoded)
    } else {
        None
    }
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ============================================================================
// 4. Security Risk Badge Analyzer
// ============================================================================

/// Risk severity shown in the Userscript Manager UI before enabling/installing a script.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Security risk badge surfaced to the user for a userscript.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScriptRiskBadge {
    pub code: String,
    pub severity: RiskSeverity,
    pub title_en: String,
    pub title_fr: String,
    pub detail: String,
}

/// Inspects parsed metadata and source code to produce actionable security risk badges.
pub fn analyze_script_risks(meta: &UserScriptMeta, source: &str) -> Vec<ScriptRiskBadge> {
    let mut badges = Vec::new();

    let has_xhr = meta.has_grant("GM_xmlhttpRequest") || meta.has_grant("GM.xmlHttpRequest");
    if has_xhr {
        let wildcard_connect = meta.connects.is_empty() || meta.connects.iter().any(|c| c == "*");
        badges.push(ScriptRiskBadge {
            code: if wildcard_connect {
                "gm_xhr_wildcard".into()
            } else {
                "gm_xhr".into()
            },
            severity: if wildcard_connect {
                RiskSeverity::Critical
            } else {
                RiskSeverity::High
            },
            title_en: "Cross-Origin Network Requests".into(),
            title_fr: "Requêtes réseau inter-origines".into(),
            detail: if wildcard_connect {
                "Script requests GM_xmlhttpRequest with unrestricted @connect * access.".into()
            } else {
                format!(
                    "Script can send cross-origin requests to: {}",
                    meta.connects.join(", ")
                )
            },
        });
    }

    if meta.has_grant("unsafeWindow") {
        badges.push(ScriptRiskBadge {
            code: "unsafe_window".into(),
            severity: RiskSeverity::High,
            title_en: "Direct Page Context Access (unsafeWindow)".into(),
            title_fr: "Accès direct au contexte de la page (unsafeWindow)".into(),
            detail: "Bypasses isolated-world boundary and shares JavaScript objects with the host webpage.".into(),
        });
    }

    if meta.has_grant("GM_cookie") || meta.has_grant("GM.cookie") {
        badges.push(ScriptRiskBadge {
            code: "gm_cookie".into(),
            severity: RiskSeverity::Critical,
            title_en: "Cookie Jar Access (GM_cookie)".into(),
            title_fr: "Accès aux cookies (GM_cookie)".into(),
            detail: "Can read or modify authentication cookies on matched sites.".into(),
        });
    }

    if meta.has_grant("GM_download") || meta.has_grant("GM.download") {
        badges.push(ScriptRiskBadge {
            code: "gm_download".into(),
            severity: RiskSeverity::High,
            title_en: "File Download Capability (GM_download)".into(),
            title_fr: "Téléchargement de fichiers (GM_download)".into(),
            detail: "Can trigger background downloads directly to disk.".into(),
        });
    }

    if meta.has_grant("GM_setClipboard") || meta.has_grant("GM.setClipboard") {
        badges.push(ScriptRiskBadge {
            code: "gm_clipboard".into(),
            severity: RiskSeverity::Medium,
            title_en: "Clipboard Write Access".into(),
            title_fr: "Accès en écriture au presse-papiers".into(),
            detail: "Can overwrite the system clipboard contents.".into(),
        });
    }

    let broad_scope = meta
        .matches
        .iter()
        .chain(meta.includes.iter())
        .any(|p| p == "<all_urls>" || p == "*://*/*" || p == "*" || p == "http*://*/*");
    if broad_scope {
        badges.push(ScriptRiskBadge {
            code: "broad_match_all_sites".into(),
            severity: RiskSeverity::Medium,
            title_en: "Runs on All Websites".into(),
            title_fr: "Exécuté sur tous les sites web".into(),
            detail: "Script matches every website instead of specific domains.".into(),
        });
    }

    let unverified_requires: Vec<&String> = meta
        .requires
        .iter()
        .filter(|r| {
            let low = r.to_ascii_lowercase();
            !low.contains("#sha256=") && !low.contains("#sha384=") && !low.contains("#sha512=")
        })
        .collect();
    if !unverified_requires.is_empty() {
        badges.push(ScriptRiskBadge {
            code: "unverified_require".into(),
            severity: RiskSeverity::Medium,
            title_en: "External @require Without SRI Hash".into(),
            title_fr: "Dépendance @require sans empreinte SRI".into(),
            detail: format!(
                "{} external @require script(s) lack a #sha256/#sha384/#sha512 integrity pin.",
                unverified_requires.len()
            ),
        });
    }

    if source.contains("eval(") || source.contains("new Function(") {
        badges.push(ScriptRiskBadge {
            code: "dynamic_code_eval".into(),
            severity: RiskSeverity::High,
            title_en: "Dynamic Code Execution (eval / Function)".into(),
            title_fr: "Exécution dynamique de code (eval / Function)".into(),
            detail: "Script body invokes eval() or new Function().".into(),
        });
    }

    badges.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.code.cmp(&b.code)));
    badges
}

// ============================================================================
// 5. Isolated-World JS Wrapper Generator (`GM_*` / `GM.*`)
// ============================================================================

fn escape_json_for_js_embed(json: &str) -> String {
    json.replace('<', "\\u003C")
        .replace('>', "\\u003E")
        .replace('&', "\\u0026")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}

/// Generates an isolated-world IIFE JavaScript wrapper that exposes the requested
/// `GM_*` and Promise-based `GM.*` APIs strictly gated by `@grant` and `@connect`.
pub fn generate_isolated_wrapper_js(record: &UserScriptRecord) -> String {
    let kv_json = escape_json_for_js_embed(
        &serde_json::to_string(&record.kv_storage).unwrap_or_else(|_| "{}".into()),
    );
    let grants_json = escape_json_for_js_embed(
        &serde_json::to_string(&record.meta.grants).unwrap_or_else(|_| "[]".into()),
    );
    let mut allowed_hosts = record.meta.connects.clone();
    for h in &record.granted_connect_hosts {
        if !allowed_hosts.iter().any(|x| x == h) {
            allowed_hosts.push(h.clone());
        }
    }
    let connects_json = escape_json_for_js_embed(
        &serde_json::to_string(&allowed_hosts).unwrap_or_else(|_| "[]".into()),
    );
    let gm_info_json = escape_json_for_js_embed(
        &serde_json::json!({
            "scriptHandler": "Singularity",
            "version": env!("CARGO_PKG_VERSION"),
            "scriptMetaStr": record.meta.raw_meta_block,
            "script": {
                "id": record.id,
                "name": record.meta.name,
                "namespace": record.meta.namespace,
                "version": record.meta.version,
                "description": record.meta.description,
                "author": record.meta.author,
                "matches": record.meta.matches,
                "includes": record.meta.includes,
                "excludes": record.meta.excludes,
                "grants": record.meta.grants,
                "run-at": record.meta.run_at.as_str(),
            }
        })
        .to_string(),
    );
    let script_id_json = escape_json_for_js_embed(
        &serde_json::to_string(&record.id).unwrap_or_else(|_| "\"\"".into()),
    );

    format!(
        r#"/* Singularity Isolated-World Userscript Runtime */
(function() {{
  "use strict";
  const __runtime = (function() {{
    const __SCRIPT_ID__ = {script_id_json};
    const __freeze = Object.freeze;
    const __hasOwn = Object.prototype.hasOwnProperty;
    const __arrayIncludes = Array.prototype.includes;
    const __arraySome = Array.prototype.some;
    const __jsonParse = JSON.parse;
    const __jsonStringify = JSON.stringify;
    const __promiseResolve = Promise.resolve.bind(Promise);

    function __deepFreeze(obj) {{
      if (obj && typeof obj === "object") {{
        __freeze(obj);
        const keys = Object.keys(obj);
        for (let i = 0; i < keys.length; i += 1) {{
          __deepFreeze(obj[keys[i]]);
        }}
      }}
      return obj;
    }}

    const __GRANTS__ = __freeze({grants_json}.slice());
    const __CONNECT_ALLOW__ = __freeze({connects_json}.slice());
    const __KV__ = Object.assign(Object.create(null), {kv_json});
    const __RAW_WINDOW__ = typeof window !== "undefined" ? window : undefined;
    const __BRIDGE__ = (__RAW_WINDOW__ && __RAW_WINDOW__.__singularityUserscriptBridge) || null;
    const __BRIDGE_INVOKE__ = (__BRIDGE__ && typeof __BRIDGE__.invoke === "function")
      ? __BRIDGE__.invoke.bind(__BRIDGE__)
      : null;
    const __BRIDGE_BIND_MENU__ = (__BRIDGE__ && typeof __BRIDGE__.bindMenuCallback === "function")
      ? __BRIDGE__.bindMenuCallback.bind(__BRIDGE__)
      : null;

    function __hasGrant(name) {{
      return __arrayIncludes.call(__GRANTS__, name);
    }}

    function __assertGrant(syncName, asyncName) {{
      if (!__hasGrant(syncName) && !__hasGrant(asyncName)) {{
        throw new Error("[Singularity Userscript] Missing @grant for " + syncName);
      }}
    }}

    function __postBridge(action, payload) {{
      if (__BRIDGE_INVOKE__) {{
        return __BRIDGE_INVOKE__(__SCRIPT_ID__, action, payload);
      }}
      return __promiseResolve(null);
    }}

    function __isHostAllowed(targetUrl) {{
      try {{
        const baseHref = (__RAW_WINDOW__ && __RAW_WINDOW__.location && __RAW_WINDOW__.location.href) || "about:blank";
        const parsed = new URL(targetUrl, baseHref);
        const host = parsed.hostname.toLowerCase();
        if (__arrayIncludes.call(__CONNECT_ALLOW__, "*")) return true;
        if (
          __arrayIncludes.call(__CONNECT_ALLOW__, "self")
          && __RAW_WINDOW__
          && __RAW_WINDOW__.location
          && parsed.origin === __RAW_WINDOW__.location.origin
        ) {{
          return true;
        }}
        return __arraySome.call(__CONNECT_ALLOW__, (rule) => {{
          const r = String(rule).toLowerCase();
          return host === r || host.endsWith("." + r);
        }});
      }} catch (_) {{
        return false;
      }}
    }}

    const GM_info = __deepFreeze({gm_info_json});

    function GM_getValue(key, defaultValue) {{
      __assertGrant("GM_getValue", "GM.getValue");
      const k = String(key);
      if (!__hasOwn.call(__KV__, k)) return defaultValue;
      try {{ return __jsonParse(__KV__[k]); }} catch (_) {{ return __KV__[k]; }}
    }}

    function GM_setValue(key, value) {{
      __assertGrant("GM_setValue", "GM.setValue");
      const k = String(key);
      const serialized = __jsonStringify(value);
      __KV__[k] = serialized;
      __postBridge("kv_set", {{ key: k, value: serialized }});
    }}

    function GM_deleteValue(key) {{
      __assertGrant("GM_deleteValue", "GM.deleteValue");
      const k = String(key);
      delete __KV__[k];
      __postBridge("kv_delete", {{ key: k }});
    }}

    function GM_listValues() {{
      __assertGrant("GM_listValues", "GM.listValues");
      return Object.keys(__KV__);
    }}

    function GM_addStyle(css) {{
      __assertGrant("GM_addStyle", "GM.addStyle");
      const style = document.createElement("style");
      style.setAttribute("data-singularity-userscript", __SCRIPT_ID__);
      style.textContent = String(css || "");
      (document.head || document.documentElement).appendChild(style);
      return style;
    }}

    function GM_xmlhttpRequest(details) {{
      __assertGrant("GM_xmlhttpRequest", "GM.xmlHttpRequest");
      if (!details || typeof details.url !== "string") {{
        throw new Error("[Singularity Userscript] GM_xmlhttpRequest requires details.url");
      }}
      const reqUrl = String(details.url);
      if (!__isHostAllowed(reqUrl)) {{
        const err = new Error("[Singularity Userscript] Host blocked by @connect policy: " + reqUrl);
        if (typeof details.onerror === "function") details.onerror(err);
        return {{ abort() {{}} }};
      }}
      const reqPayload = Object.assign({{}}, details, {{ url: reqUrl }});
      __postBridge("xhr", reqPayload).then((resp) => {{
        if (typeof details.onload === "function") details.onload(resp);
      }}).catch((err) => {{
        if (typeof details.onerror === "function") details.onerror(err);
      }});
      return {{ abort() {{ __postBridge("xhr_abort", {{ url: reqUrl }}); }} }};
    }}

    function GM_registerMenuCommand(caption, callback, accessKey) {{
      __assertGrant("GM_registerMenuCommand", "GM.registerMenuCommand");
      const cmdId = __SCRIPT_ID__ + ":menu:" + String(caption);
      __postBridge("register_menu", {{ id: cmdId, caption: String(caption), accessKey: accessKey || null }});
      if (__BRIDGE_BIND_MENU__) {{
        __BRIDGE_BIND_MENU__(cmdId, callback);
      }}
      return cmdId;
    }}

    function GM_notification(textOrOpts, title, image, onclick) {{
      __assertGrant("GM_notification", "GM.notification");
      const opts = typeof textOrOpts === "object" && textOrOpts !== null
        ? textOrOpts
        : {{ text: String(textOrOpts || ""), title: title || GM_info.script.name, image: image || null }};
      __postBridge("notification", opts).then(() => {{
        if (typeof onclick === "function") onclick();
        else if (typeof opts.onclick === "function") opts.onclick();
      }});
    }}

    function GM_setClipboard(data, info) {{
      __assertGrant("GM_setClipboard", "GM.setClipboard");
      __postBridge("clipboard_set", {{ data: String(data || ""), info: info || "text/plain" }});
    }}

    const gmAsync = Object.create(null);
    gmAsync.info = GM_info;
    if (__hasGrant("GM_getValue") || __hasGrant("GM.getValue")) {{
      gmAsync.getValue = (k, d) => __promiseResolve(GM_getValue(k, d));
    }}
    if (__hasGrant("GM_setValue") || __hasGrant("GM.setValue")) {{
      gmAsync.setValue = (k, v) => __promiseResolve(GM_setValue(k, v));
    }}
    if (__hasGrant("GM_deleteValue") || __hasGrant("GM.deleteValue")) {{
      gmAsync.deleteValue = (k) => __promiseResolve(GM_deleteValue(k));
    }}
    if (__hasGrant("GM_listValues") || __hasGrant("GM.listValues")) {{
      gmAsync.listValues = () => __promiseResolve(GM_listValues());
    }}
    if (__hasGrant("GM_addStyle") || __hasGrant("GM.addStyle")) {{
      gmAsync.addStyle = (css) => __promiseResolve(GM_addStyle(css));
    }}
    if (__hasGrant("GM_xmlhttpRequest") || __hasGrant("GM.xmlHttpRequest")) {{
      gmAsync.xmlHttpRequest = (details) => GM_xmlhttpRequest(details);
    }}
    if (__hasGrant("GM_registerMenuCommand") || __hasGrant("GM.registerMenuCommand")) {{
      gmAsync.registerMenuCommand = (c, cb, ak) => __promiseResolve(GM_registerMenuCommand(c, cb, ak));
    }}
    if (__hasGrant("GM_notification") || __hasGrant("GM.notification")) {{
      gmAsync.notification = (o, t, i, fn) => __promiseResolve(GM_notification(o, t, i, fn));
    }}
    if (__hasGrant("GM_setClipboard") || __hasGrant("GM.setClipboard")) {{
      gmAsync.setClipboard = (d, info) => __promiseResolve(GM_setClipboard(d, info));
    }}
    const GM = __freeze(gmAsync);

    const __hasUnsafeWindow = __hasGrant("unsafeWindow");
    const __sandboxGlobals = Object.create(null);
    const __sandboxWindow = (__RAW_WINDOW__ && typeof Proxy === "function")
      ? new Proxy(__sandboxGlobals, {{
          get(target, prop) {{
            if (prop === "__singularityUserscriptBridge") return undefined;
            if (prop === "window" || prop === "self" || prop === "globalThis") return __sandboxWindow;
            if (__hasOwn.call(target, prop)) return target[prop];
            const val = Reflect.get(__RAW_WINDOW__, prop, __RAW_WINDOW__);
            return (typeof val === "function" && !("prototype" in val)) ? val.bind(__RAW_WINDOW__) : val;
          }},
          set(target, prop, value) {{
            if (prop === "__singularityUserscriptBridge") return false;
            target[prop] = value;
            return true;
          }},
          has(target, prop) {{
            if (prop === "__singularityUserscriptBridge") return false;
            return __hasOwn.call(target, prop) || Reflect.has(__RAW_WINDOW__, prop);
          }},
        }})
      : undefined;

    return __freeze({{
      GM,
      GM_info,
      GM_getValue: (__hasGrant("GM_getValue") || __hasGrant("GM.getValue")) ? GM_getValue : undefined,
      GM_setValue: (__hasGrant("GM_setValue") || __hasGrant("GM.setValue")) ? GM_setValue : undefined,
      GM_deleteValue: (__hasGrant("GM_deleteValue") || __hasGrant("GM.deleteValue")) ? GM_deleteValue : undefined,
      GM_listValues: (__hasGrant("GM_listValues") || __hasGrant("GM.listValues")) ? GM_listValues : undefined,
      GM_addStyle: (__hasGrant("GM_addStyle") || __hasGrant("GM.addStyle")) ? GM_addStyle : undefined,
      GM_xmlhttpRequest: (__hasGrant("GM_xmlhttpRequest") || __hasGrant("GM.xmlHttpRequest")) ? GM_xmlhttpRequest : undefined,
      GM_registerMenuCommand: (__hasGrant("GM_registerMenuCommand") || __hasGrant("GM.registerMenuCommand")) ? GM_registerMenuCommand : undefined,
      GM_notification: (__hasGrant("GM_notification") || __hasGrant("GM.notification")) ? GM_notification : undefined,
      GM_setClipboard: (__hasGrant("GM_setClipboard") || __hasGrant("GM.setClipboard")) ? GM_setClipboard : undefined,
      unsafeWindow: __hasUnsafeWindow ? __RAW_WINDOW__ : undefined,
      window: __hasUnsafeWindow ? __RAW_WINDOW__ : __sandboxWindow,
    }});
  }})();

  (function(
    GM,
    GM_info,
    GM_getValue,
    GM_setValue,
    GM_deleteValue,
    GM_listValues,
    GM_addStyle,
    GM_xmlhttpRequest,
    GM_registerMenuCommand,
    GM_notification,
    GM_setClipboard,
    unsafeWindow,
    window,
    self,
    globalThis,
    __runtime
  ) {{
    "use strict";
    // --- Begin UserScript Body ---
{source}
    // --- End UserScript Body ---
  }})(
    __runtime.GM,
    __runtime.GM_info,
    __runtime.GM_getValue,
    __runtime.GM_setValue,
    __runtime.GM_deleteValue,
    __runtime.GM_listValues,
    __runtime.GM_addStyle,
    __runtime.GM_xmlhttpRequest,
    __runtime.GM_registerMenuCommand,
    __runtime.GM_notification,
    __runtime.GM_setClipboard,
    __runtime.unsafeWindow,
    __runtime.window,
    __runtime.window,
    __runtime.window
  );
}})();
"#,
        script_id_json = script_id_json,
        grants_json = grants_json,
        connects_json = connects_json,
        kv_json = kv_json,
        gm_info_json = gm_info_json,
        source = record.source
    )
}

// ============================================================================
// 6. UserscriptManager (Disk Storage, KV Storage, JSON & ZIP Import/Export)
// ============================================================================

/// Installed userscript record including persistent `GM_getValue`/`GM_setValue` KV store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserScriptRecord {
    pub id: String,
    pub meta: UserScriptMeta,
    pub source: String,
    pub enabled: bool,
    #[serde(default)]
    pub kv_storage: BTreeMap<String, String>,
    #[serde(default)]
    pub granted_connect_hosts: Vec<String>,
    pub installed_unix: u64,
    pub updated_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UserscriptIndexEntry {
    id: String,
    meta: UserScriptMeta,
    enabled: bool,
    kv_storage: BTreeMap<String, String>,
    granted_connect_hosts: Vec<String>,
    installed_unix: u64,
    updated_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UserscriptExportBundle {
    format: String,
    exported_unix: u64,
    scripts: Vec<UserScriptRecord>,
}

/// Manages installed userscripts under `<root>/userscripts/`.
#[derive(Debug, Clone)]
pub struct UserscriptManager {
    root_dir: PathBuf,
    scripts: BTreeMap<String, UserScriptRecord>,
}

impl UserscriptManager {
    /// Opens or initializes `<root>/userscripts/` and loads all persisted scripts.
    pub fn open_at(root: &Path) -> Result<Self, String> {
        let dir = root.join("userscripts");
        fs::create_dir_all(&dir)
            .map_err(|e| format!("Failed to create userscripts directory: {}", e))?;
        let mut mgr = Self {
            root_dir: dir,
            scripts: BTreeMap::new(),
        };
        let index_path = mgr.root_dir.join("index.json");
        if index_path.is_file() {
            let raw = fs::read_to_string(&index_path)
                .map_err(|e| format!("Failed to read userscripts index: {}", e))?;
            let entries: Vec<UserscriptIndexEntry> = serde_json::from_str(&raw)
                .map_err(|e| format!("Corrupt userscripts index.json: {}", e))?;
            for entry in entries {
                let src_path = mgr.root_dir.join(format!("{}.user.js", entry.id));
                let source = fs::read_to_string(&src_path).unwrap_or_default();
                if source.is_empty() {
                    continue;
                }
                mgr.scripts.insert(
                    entry.id.clone(),
                    UserScriptRecord {
                        id: entry.id,
                        meta: entry.meta,
                        source,
                        enabled: entry.enabled,
                        kv_storage: entry.kv_storage,
                        granted_connect_hosts: entry.granted_connect_hosts,
                        installed_unix: entry.installed_unix,
                        updated_unix: entry.updated_unix,
                    },
                );
            }
        }
        Ok(mgr)
    }

    pub fn storage_dir(&self) -> &Path {
        &self.root_dir
    }

    /// Installs or updates a userscript from source text, preserving existing KV storage on update.
    pub fn install_source(&mut self, source: &str) -> Result<UserScriptRecord, String> {
        let meta = parse_userscript_metadata(source)?;
        let id = meta.compute_id();
        let now = unix_now();

        let (enabled, kv_storage, granted_connect_hosts, installed_unix) =
            if let Some(prev) = self.scripts.get(&id) {
                (
                    prev.enabled,
                    prev.kv_storage.clone(),
                    prev.granted_connect_hosts.clone(),
                    prev.installed_unix,
                )
            } else {
                (true, BTreeMap::new(), Vec::new(), now)
            };

        let rec = UserScriptRecord {
            id: id.clone(),
            meta,
            source: source.to_string(),
            enabled,
            kv_storage,
            granted_connect_hosts,
            installed_unix,
            updated_unix: now,
        };
        self.scripts.insert(id, rec.clone());
        self.save()?;
        Ok(rec)
    }

    pub fn remove(&mut self, id: &str) -> Result<bool, String> {
        let existed = self.scripts.remove(id).is_some();
        if existed {
            let _ = fs::remove_file(self.root_dir.join(format!("{}.user.js", id)));
            self.save()?;
        }
        Ok(existed)
    }

    pub fn set_enabled(&mut self, id: &str, enabled: bool) -> Result<(), String> {
        let rec = self
            .scripts
            .get_mut(id)
            .ok_or_else(|| format!("Userscript '{}' not found", id))?;
        rec.enabled = enabled;
        rec.updated_unix = unix_now();
        self.save()
    }

    pub fn grant_connect_host(&mut self, id: &str, host: &str) -> Result<(), String> {
        let clean = host.trim().to_ascii_lowercase();
        if clean.is_empty() {
            return Err("Connect host cannot be empty".into());
        }
        let rec = self
            .scripts
            .get_mut(id)
            .ok_or_else(|| format!("Userscript '{}' not found", id))?;
        if !rec.granted_connect_hosts.iter().any(|h| h == &clean) {
            rec.granted_connect_hosts.push(clean);
            self.save()?;
        }
        Ok(())
    }

    /// Persistent `GM_getValue` backend.
    pub fn kv_get(&self, script_id: &str, key: &str) -> Option<&str> {
        self.scripts
            .get(script_id)
            .and_then(|s| s.kv_storage.get(key))
            .map(|s| s.as_str())
    }

    /// Persistent `GM_setValue` backend.
    pub fn kv_set(&mut self, script_id: &str, key: &str, value: String) -> Result<(), String> {
        let rec = self
            .scripts
            .get_mut(script_id)
            .ok_or_else(|| format!("Userscript '{}' not found", script_id))?;
        rec.kv_storage.insert(key.to_string(), value);
        self.save()
    }

    /// Persistent `GM_deleteValue` backend.
    pub fn kv_delete(&mut self, script_id: &str, key: &str) -> Result<bool, String> {
        let rec = self
            .scripts
            .get_mut(script_id)
            .ok_or_else(|| format!("Userscript '{}' not found", script_id))?;
        let removed = rec.kv_storage.remove(key).is_some();
        if removed {
            self.save()?;
        }
        Ok(removed)
    }

    /// Persistent `GM_listValues` backend.
    pub fn kv_list(&self, script_id: &str) -> Vec<String> {
        self.scripts
            .get(script_id)
            .map(|s| s.kv_storage.keys().cloned().collect())
            .unwrap_or_default()
    }

    pub fn get(&self, id: &str) -> Option<&UserScriptRecord> {
        self.scripts.get(id)
    }

    pub fn list(&self) -> Vec<&UserScriptRecord> {
        self.scripts.values().collect()
    }

    /// Returns all enabled userscripts matching `(url, is_main_frame, run_at)`.
    pub fn scripts_for_url(
        &self,
        url: &str,
        is_main_frame: bool,
        run_at: Option<RunAt>,
    ) -> Vec<&UserScriptRecord> {
        self.scripts
            .values()
            .filter(|rec| {
                rec.enabled
                    && run_at.map_or(true, |r| rec.meta.run_at == r)
                    && matches_url(&rec.meta, url, is_main_frame)
            })
            .collect()
    }

    /// Exports all installed scripts + KV storage as portable JSON.
    pub fn export_json(&self) -> Result<String, String> {
        let bundle = UserscriptExportBundle {
            format: "singularity-userscripts-v1".into(),
            exported_unix: unix_now(),
            scripts: self.scripts.values().cloned().collect(),
        };
        serde_json::to_string_pretty(&bundle)
            .map_err(|e| format!("Failed to serialize userscripts JSON: {}", e))
    }

    /// Imports scripts from Singularity JSON or Tampermonkey/Violentmonkey JSON export.
    pub fn import_json(&mut self, raw_json: &str) -> Result<usize, String> {
        if let Ok(bundle) = serde_json::from_str::<UserscriptExportBundle>(raw_json) {
            let mut imported = 0usize;
            for rec in bundle.scripts {
                let meta = parse_userscript_metadata(&rec.source)?;
                let existing_grants = self
                    .scripts
                    .get(&meta.compute_id())
                    .map(|prev| prev.granted_connect_hosts.clone())
                    .unwrap_or_default();
                let installed = self.install_source(&rec.source)?;
                if let Some(entry) = self.scripts.get_mut(&installed.id) {
                    entry.enabled = rec.enabled;
                    entry.kv_storage.extend(rec.kv_storage);
                    // Never trust `granted_connect_hosts` from an imported JSON export;
                    // preserve only hosts already granted locally on this device.
                    entry.granted_connect_hosts = existing_grants;
                }
                imported += 1;
            }
            self.save()?;
            return Ok(imported);
        }

        // Tampermonkey/Violentmonkey generic JSON fallback (`{ "scripts": [{ "source": "...", ... }] }`)
        let val: serde_json::Value =
            serde_json::from_str(raw_json).map_err(|e| format!("Invalid JSON backup: {}", e))?;
        let arr = val
            .get("scripts")
            .and_then(|v| v.as_array())
            .ok_or_else(|| "Unrecognized userscript JSON backup format".to_string())?;
        let mut count = 0usize;
        for item in arr {
            let src = item
                .get("source")
                .or_else(|| item.get("code"))
                .and_then(|v| v.as_str());
            if let Some(code) = src {
                let rec = self.install_source(code)?;
                if let Some(storage) = item.get("storage").and_then(|s| s.get("data")).and_then(|d| d.as_object()) {
                    if let Some(entry) = self.scripts.get_mut(&rec.id) {
                        for (k, v) in storage {
                            entry.kv_storage.insert(k.clone(), v.to_string());
                        }
                    }
                }
                count += 1;
            }
        }
        self.save()?;
        Ok(count)
    }

    /// Exports a Tampermonkey/Violentmonkey-compatible ZIP archive containing `<slug>.user.js`,
    /// `<slug>.storage.json`, `<slug>.options.json`, plus `singularity-userscripts.json`.
    pub fn export_zip(&self) -> Result<Vec<u8>, String> {
        let mut buf = Vec::new();
        {
            let mut zw = zip::ZipWriter::new(Cursor::new(&mut buf));
            let opts = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);

            for rec in self.scripts.values() {
                let stem = sanitize_filename_stem(&rec.meta.name, &rec.id);
                zw.start_file(format!("{}.user.js", stem), opts)
                    .map_err(|e| e.to_string())?;
                zw.write_all(rec.source.as_bytes())
                    .map_err(|e| e.to_string())?;

                let storage_payload = serde_json::json!({ "data": rec.kv_storage });
                zw.start_file(format!("{}.storage.json", stem), opts)
                    .map_err(|e| e.to_string())?;
                zw.write_all(storage_payload.to_string().as_bytes())
                    .map_err(|e| e.to_string())?;

                let options_payload = serde_json::json!({
                    "enabled": rec.enabled,
                    "granted_connect_hosts": rec.granted_connect_hosts
                });
                zw.start_file(format!("{}.options.json", stem), opts)
                    .map_err(|e| e.to_string())?;
                zw.write_all(options_payload.to_string().as_bytes())
                    .map_err(|e| e.to_string())?;
            }

            let manifest_json = self.export_json()?;
            zw.start_file("singularity-userscripts.json", opts)
                .map_err(|e| e.to_string())?;
            zw.write_all(manifest_json.as_bytes())
                .map_err(|e| e.to_string())?;

            zw.finish().map_err(|e| e.to_string())?;
        }
        Ok(buf)
    }

    /// Imports a Singularity, Tampermonkey, or Violentmonkey `.zip` backup archive.
    pub fn import_zip(&mut self, zip_bytes: &[u8]) -> Result<usize, String> {
        let mut archive = zip::ZipArchive::new(Cursor::new(zip_bytes))
            .map_err(|e| format!("Invalid ZIP archive: {}", e))?;

        if archive.len() > MAX_ZIP_IMPORT_ENTRIES {
            return Err(format!(
                "ZIP archive exceeds maximum entry limit ({})",
                MAX_ZIP_IMPORT_ENTRIES
            ));
        }

        let mut user_js_files: BTreeMap<String, String> = BTreeMap::new();
        let mut storage_files: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
        let mut options_enabled: BTreeMap<String, bool> = BTreeMap::new();
        let mut native_manifest: Option<String> = None;
        let mut total_decompressed: usize = 0;

        for i in 0..archive.len() {
            let file = archive.by_index(i).map_err(|e| e.to_string())?;
            if file.is_dir() {
                continue;
            }
            let name = file.name().to_string();
            let remaining_budget = MAX_ZIP_IMPORT_TOTAL_BYTES.saturating_sub(total_decompressed);
            let per_entry_limit = MAX_USERSCRIPT_BYTES.min(remaining_budget);
            let mut raw_buf = Vec::new();
            if file
                .take((per_entry_limit as u64).saturating_add(1))
                .read_to_end(&mut raw_buf)
                .is_err()
            {
                continue;
            }
            if raw_buf.len() > MAX_USERSCRIPT_BYTES {
                return Err(format!(
                    "ZIP entry '{}' exceeds maximum userscript size ({} bytes)",
                    name, MAX_USERSCRIPT_BYTES
                ));
            }
            if total_decompressed.saturating_add(raw_buf.len()) > MAX_ZIP_IMPORT_TOTAL_BYTES {
                return Err(format!(
                    "ZIP archive exceeds cumulative decompressed size limit ({} bytes)",
                    MAX_ZIP_IMPORT_TOTAL_BYTES
                ));
            }
            total_decompressed += raw_buf.len();
            let Ok(text) = String::from_utf8(raw_buf) else {
                continue;
            };

            if name == "singularity-userscripts.json" {
                native_manifest = Some(text);
                continue;
            }
            if let Some(stem) = name.strip_suffix(".user.js") {
                user_js_files.insert(stem.to_string(), text);
            } else if let Some(stem) = name.strip_suffix(".storage.json") {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&text) {
                    if let Some(obj) = val.get("data").and_then(|d| d.as_object()) {
                        let mut kv = BTreeMap::new();
                        for (k, v) in obj {
                            let s = v.as_str().map(String::from).unwrap_or_else(|| v.to_string());
                            kv.insert(k.clone(), s);
                        }
                        storage_files.insert(stem.to_string(), kv);
                    }
                }
            } else if let Some(stem) = name.strip_suffix(".options.json") {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&text) {
                    if let Some(en) = val.get("enabled").and_then(|b| b.as_bool()) {
                        options_enabled.insert(stem.to_string(), en);
                    }
                }
            }
        }

        if let Some(manifest) = native_manifest {
            return self.import_json(&manifest);
        }

        let mut imported = 0usize;
        for (stem, src) in user_js_files {
            let rec = self.install_source(&src)?;
            if let Some(entry) = self.scripts.get_mut(&rec.id) {
                if let Some(kv) = storage_files.remove(&stem) {
                    entry.kv_storage.extend(kv);
                }
                if let Some(en) = options_enabled.remove(&stem) {
                    entry.enabled = en;
                }
            }
            imported += 1;
        }
        self.save()?;
        Ok(imported)
    }

    fn save(&self) -> Result<(), String> {
        let mut index = Vec::with_capacity(self.scripts.len());
        for rec in self.scripts.values() {
            let src_path = self.root_dir.join(format!("{}.user.js", rec.id));
            atomic_write_file(&src_path, rec.source.as_bytes())?;
            index.push(UserscriptIndexEntry {
                id: rec.id.clone(),
                meta: rec.meta.clone(),
                enabled: rec.enabled,
                kv_storage: rec.kv_storage.clone(),
                granted_connect_hosts: rec.granted_connect_hosts.clone(),
                installed_unix: rec.installed_unix,
                updated_unix: rec.updated_unix,
            });
        }
        let json = serde_json::to_string_pretty(&index)
            .map_err(|e| format!("Failed to serialize userscripts index: {}", e))?;
        atomic_write_file(&self.root_dir.join("index.json"), json.as_bytes())
    }
}

fn sanitize_filename_stem(name: &str, fallback_id: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .take(48)
        .collect();
    if cleaned.trim_matches('_').is_empty() {
        fallback_id.to_string()
    } else {
        cleaned
    }
}

fn atomic_write_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let tmp = path.with_file_name(format!(
        ".{}.tmp.{}",
        path.file_name().and_then(|s| s.to_str()).unwrap_or("us"),
        std::process::id()
    ));
    {
        let mut f = fs::File::create(&tmp).map_err(|e| e.to_string())?;
        f.write_all(bytes).map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())?;
    }
    fs::rename(&tmp, path).map_err(|e| e.to_string())
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_SCRIPT: &str = r#"// ==UserScript==
// @name         Singularity Enhancer
// @name:fr      Améliorateur Singularity
// @namespace    https://singularity.browser/scripts
// @version      1.4.2
// @description  Clean OLED tweaks
// @description:fr Améliorations OLED propres
// @author       Singularity Team
// @icon         https://example.com/icon.png
// @match        *://*.example.com/*
// @include      https://docs.rs/*
// @exclude      *://admin.example.com/*
// @exclude-match https://billing.example.com/*
// @grant        GM_getValue
// @grant        GM_setValue
// @grant        GM_addStyle
// @grant        GM_xmlhttpRequest
// @grant        unsafeWindow
// @require      https://cdn.example.com/lib.js#sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
// @resource     themeCss https://cdn.example.com/oled.css
// @run-at       document-start
// @connect      api.example.com
// @noframes
// @updateURL    https://example.com/enhancer.meta.js
// @downloadURL  https://example.com/enhancer.user.js
// @homepageURL  https://example.com/enhancer
// ==/UserScript==

GM_addStyle("body { background: #000 !important; }");
"#;

    #[test]
    fn test_parse_userscript_metadata_and_localization() {
        let meta = parse_userscript_metadata(SAMPLE_SCRIPT).expect("parse metadata");
        assert_eq!(meta.name, "Singularity Enhancer");
        assert_eq!(meta.display_name("fr"), "Améliorateur Singularity");
        assert_eq!(meta.display_name("fr-FR"), "Améliorateur Singularity");
        assert_eq!(meta.display_name("de"), "Singularity Enhancer");
        assert_eq!(meta.version.as_deref(), Some("1.4.2"));
        assert_eq!(meta.author.as_deref(), Some("Singularity Team"));
        assert_eq!(meta.run_at, RunAt::DocumentStart);
        assert!(meta.noframes);
        assert_eq!(meta.resources.get("themeCss").map(String::as_str), Some("https://cdn.example.com/oled.css"));
        assert_eq!(meta.connects, vec!["api.example.com"]);
        assert_eq!(meta.update_url.as_deref(), Some("https://example.com/enhancer.meta.js"));
        assert_eq!(meta.download_url.as_deref(), Some("https://example.com/enhancer.user.js"));
        assert_eq!(meta.homepage_url.as_deref(), Some("https://example.com/enhancer"));
    }

    #[test]
    fn test_url_matching_patterns_excludes_and_noframes() {
        let meta = parse_userscript_metadata(SAMPLE_SCRIPT).unwrap();

        assert!(matches_url(&meta, "https://example.com/home", true));
        assert!(matches_url(&meta, "http://sub.example.com/path?a=1", true));
        assert!(matches_url(&meta, "https://docs.rs/serde/latest", true));

        // @noframes blocks iframes
        assert!(!matches_url(&meta, "https://example.com/home", false));

        // @exclude and @exclude-match block matching URLs
        assert!(!matches_url(&meta, "https://admin.example.com/panel", true));
        assert!(!matches_url(&meta, "https://billing.example.com/pay", true));

        // Unrelated hosts and internal pages never match
        assert!(!matches_url(&meta, "https://evil-example.com/", true));
        assert!(!matches_url(&meta, "browser://settings", true));
    }

    #[test]
    fn test_sri_hash_verification_sha256_hex_and_base64() {
        let payload = b"console.log('singularity');";
        let sha_hex = hex::encode(Sha256::digest(payload));
        let sha_b64 = BASE64.encode(Sha256::digest(payload));

        assert!(verify_sri_hash(payload, &format!("https://cdn.test/a.js#sha256={}", sha_hex)).unwrap());
        assert!(verify_sri_hash(payload, &format!("#sha256={}", sha_b64)).unwrap());
        assert!(verify_sri_hash(payload, &format!("sha256-{}", sha_b64)).unwrap());

        // Tampered payload fails
        assert!(!verify_sri_hash(b"tampered", &format!("#sha256={}", sha_hex)).unwrap());
        // Missing SRI errors cleanly
        assert!(verify_sri_hash(payload, "https://cdn.test/a.js").is_err());
    }

    #[test]
    fn test_risk_analysis_and_isolated_wrapper_generation() {
        let meta = parse_userscript_metadata(SAMPLE_SCRIPT).unwrap();
        let risks = analyze_script_risks(&meta, SAMPLE_SCRIPT);
        assert!(risks.iter().any(|r| r.code == "gm_xhr"));
        assert!(risks.iter().any(|r| r.code == "unsafe_window"));
        // Has #sha256= on @require -> should NOT flag unverified_require
        assert!(!risks.iter().any(|r| r.code == "unverified_require"));

        let rec = UserScriptRecord {
            id: meta.compute_id(),
            meta,
            source: SAMPLE_SCRIPT.into(),
            enabled: true,
            kv_storage: BTreeMap::from([("theme".into(), "\"oled\"".into())]),
            granted_connect_hosts: vec!["api.example.com".into()],
            installed_unix: 100,
            updated_unix: 100,
        };
        let wrapped = generate_isolated_wrapper_js(&rec);
        assert!(wrapped.contains("GM_getValue"));
        assert!(wrapped.contains("GM_setValue"));
        assert!(wrapped.contains("GM_xmlhttpRequest"));
        assert!(wrapped.contains("GM_registerMenuCommand"));
        assert!(wrapped.contains("GM_notification"));
        assert!(wrapped.contains("GM_setClipboard"));
        assert!(wrapped.contains("GM_info"));
        assert!(wrapped.contains("xmlHttpRequest"));
        assert!(wrapped.contains("__isHostAllowed"));
    }

    #[test]
    fn test_userscript_manager_disk_kv_json_and_zip_roundtrip() {
        let dir1 = std::env::temp_dir().join(format!("singularity_us_1_{}", std::process::id()));
        let dir2 = std::env::temp_dir().join(format!("singularity_us_2_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir1);
        let _ = fs::remove_dir_all(&dir2);

        let mut mgr = UserscriptManager::open_at(&dir1).expect("open mgr1");
        let rec = mgr.install_source(SAMPLE_SCRIPT).expect("install");
        mgr.kv_set(&rec.id, "counter", "42".into()).expect("kv_set");
        assert_eq!(mgr.kv_get(&rec.id, "counter"), Some("42"));
        assert_eq!(mgr.kv_list(&rec.id), vec!["counter".to_string()]);

        // Reopen from disk verifies persistence
        let reloaded = UserscriptManager::open_at(&dir1).expect("reopen");
        assert_eq!(reloaded.list().len(), 1);
        assert_eq!(reloaded.kv_get(&rec.id, "counter"), Some("42"));

        // ZIP export + import into clean manager
        let zip_bytes = reloaded.export_zip().expect("export zip");
        let mut mgr2 = UserscriptManager::open_at(&dir2).expect("open mgr2");
        let imported = mgr2.import_zip(&zip_bytes).expect("import zip");
        assert_eq!(imported, 1);
        assert_eq!(mgr2.kv_get(&rec.id, "counter"), Some("42"));

        // JSON export + import
        let json = mgr2.export_json().expect("export json");
        mgr2.remove(&rec.id).expect("remove");
        assert!(mgr2.list().is_empty());
        assert_eq!(mgr2.import_json(&json).expect("import json"), 1);

        let _ = fs::remove_dir_all(&dir1);
        let _ = fs::remove_dir_all(&dir2);
    }

    #[test]
    fn test_matches_url_blocks_loopback_and_non_web_schemes() {
        let broad_script = r#"// ==UserScript==
// @name         Broad Script
// @match        *://*/*
// @match        <all_urls>
// @match        http://127.0.0.1/*
// @include      *
// ==/UserScript==
console.log("hi");
"#;
        let meta = parse_userscript_metadata(broad_script).unwrap();

        // Legitimate public web pages still match
        assert!(matches_url(&meta, "https://example.com/page", true));

        // Privileged local UI server / loopback origins are unconditionally excluded
        assert!(!matches_url(&meta, "http://127.0.0.1:8080/", true));
        assert!(!matches_url(&meta, "http://127.0.0.1:8080/browser/settings", true));
        assert!(!matches_url(&meta, "http://127.0.0.2:9000/", true));
        assert!(!matches_url(&meta, "http://localhost:3000/api", true));
        assert!(!matches_url(&meta, "https://sub.localhost/app", true));
        assert!(!matches_url(&meta, "http://[::1]:8080/", true));
        assert!(!matches_url(&meta, "http://0.0.0.0:8080/", true));

        // Non-web schemes are unconditionally excluded
        assert!(!matches_url(&meta, "about:blank", true));
        assert!(!matches_url(&meta, "blob:https://example.com/uuid", true));
        assert!(!matches_url(&meta, "file:///etc/passwd", true));
    }

    #[test]
    fn test_isolated_wrapper_separates_runtime_state_from_userscript_scope() {
        let meta = parse_userscript_metadata(SAMPLE_SCRIPT).unwrap();
        let rec = UserScriptRecord {
            id: meta.compute_id(),
            meta,
            source: "console.log('isolated-body');".into(),
            enabled: true,
            kv_storage: BTreeMap::new(),
            granted_connect_hosts: vec![],
            installed_unix: 100,
            updated_unix: 100,
        };
        let wrapped = generate_isolated_wrapper_js(&rec);

        // Policy snapshots are frozen inside the closed outer IIFE
        assert!(wrapped.contains("const __runtime = (function() {"));
        assert!(wrapped.contains("const __GRANTS__ = __freeze("));
        assert!(wrapped.contains("const __CONNECT_ALLOW__ = __freeze("));
        assert!(wrapped.contains("const GM = __freeze(gmAsync);"));

        // UserScript body executes in a separate sibling function scope with __runtime shadowed
        let runtime_close_idx = wrapped
            .find("})();\n\n  (function(")
            .expect("closed outer runtime IIFE before sibling userscript scope");
        let body_idx = wrapped
            .find("console.log('isolated-body');")
            .expect("userscript body present");
        assert!(body_idx > runtime_close_idx);
        assert!(wrapped[runtime_close_idx..body_idx].contains("__runtime"));
    }

    #[test]
    fn test_import_json_strips_untrusted_connect_grants_and_preserves_local_grants() {
        let dir = std::env::temp_dir().join(format!(
            "singularity_us_grants_test_{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);

        let mut mgr = UserscriptManager::open_at(&dir).expect("open mgr");
        let rec = mgr.install_source(SAMPLE_SCRIPT).expect("install");
        mgr.grant_connect_host(&rec.id, "trusted.local.test")
            .expect("grant local host");

        // Craft an untrusted JSON bundle attempting to grant wildcard "*"
        let mut exported: serde_json::Value =
            serde_json::from_str(&mgr.export_json().expect("export")).expect("parse export");
        exported["scripts"][0]["granted_connect_hosts"] = serde_json::json!(["*", "evil.test"]);
        let tampered_json = serde_json::to_string(&exported).expect("serialize tampered");

        // Updating an already-installed script keeps ONLY its pre-existing local grants
        assert_eq!(mgr.import_json(&tampered_json).expect("reimport"), 1);
        assert_eq!(
            mgr.get(&rec.id).unwrap().granted_connect_hosts,
            vec!["trusted.local.test".to_string()]
        );

        // Fresh import into a clean manager resets granted_connect_hosts to empty
        mgr.remove(&rec.id).expect("remove");
        assert_eq!(mgr.import_json(&tampered_json).expect("fresh import"), 1);
        assert!(mgr.get(&rec.id).unwrap().granted_connect_hosts.is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_import_zip_enforces_entry_and_decompressed_size_limits() {
        let dir = std::env::temp_dir().join(format!(
            "singularity_us_zip_limits_{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        let mut mgr = UserscriptManager::open_at(&dir).expect("open mgr");

        // 1. Entry count > MAX_ZIP_IMPORT_ENTRIES (256) is rejected
        let mut many_buf = Vec::new();
        {
            let mut zw = zip::ZipWriter::new(Cursor::new(&mut many_buf));
            let opts = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            for i in 0..=MAX_ZIP_IMPORT_ENTRIES {
                zw.start_file(format!("f{}.txt", i), opts).unwrap();
                zw.write_all(b"x").unwrap();
            }
            zw.finish().unwrap();
        }
        assert!(mgr.import_zip(&many_buf).is_err());

        // 2. Single entry exceeding MAX_USERSCRIPT_BYTES (4 MiB) is rejected via bounded read
        let mut big_entry_buf = Vec::new();
        {
            let mut zw = zip::ZipWriter::new(Cursor::new(&mut big_entry_buf));
            let opts = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);
            zw.start_file("bomb.user.js", opts).unwrap();
            let chunk = vec![b'a'; 64 * 1024];
            for _ in 0..((MAX_USERSCRIPT_BYTES / (64 * 1024)) + 1) {
                zw.write_all(&chunk).unwrap();
            }
            zw.finish().unwrap();
        }
        assert!(mgr.import_zip(&big_entry_buf).is_err());

        // 3. Cumulative decompressed size exceeding MAX_ZIP_IMPORT_TOTAL_BYTES (16 MiB) is rejected
        let mut cumulative_buf = Vec::new();
        {
            let mut zw = zip::ZipWriter::new(Cursor::new(&mut cumulative_buf));
            let opts = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);
            let chunk = vec![b'b'; 64 * 1024];
            for idx in 0..5 {
                zw.start_file(format!("part_{}.txt", idx), opts).unwrap();
                for _ in 0..(MAX_USERSCRIPT_BYTES / (64 * 1024)) {
                    zw.write_all(&chunk).unwrap();
                }
            }
            zw.finish().unwrap();
        }
        assert!(mgr.import_zip(&cumulative_buf).is_err());

        let _ = fs::remove_dir_all(&dir);
    }
}
