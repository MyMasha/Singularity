//! Progressive Web Apps (PWA) Manifest Parser, Site-to-App Synthesizer,
//! Deterministic SHA-256 App IDs, Anti-Phishing Scope Guard, WHATWG Protocol &
//! Anti-Executable File Handler Validators, and Linux `.desktop` / Windows AUMID
//! Shortcut Generators.
//!
//! 100% pure Rust, atomic persistence to `apps/registry.json`.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Errors produced by PWA parsing, validation, or registry persistence.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PwaError {
    #[error("Invalid URL '{0}': {1}")]
    InvalidUrl(String, String),
    #[error("Invalid manifest JSON: {0}")]
    InvalidManifestJson(String),
    #[error("Cross-origin manifest URL rejected: {0}")]
    CrossOriginRejected(String),
    #[error("start_url '{0}' is outside manifest scope '{1}'")]
    StartUrlOutOfScope(String, String),
    #[error("Disallowed protocol handler scheme '{0}': {1}")]
    InvalidProtocolHandler(String, String),
    #[error("Disallowed or executable file handler rejected: {0}")]
    InvalidFileHandler(String),
    #[error("PWA '{0}' not found")]
    NotFound(String),
    #[error("I/O error: {0}")]
    Io(String),
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ============================================================================
// 1. W3C Web App Manifest Schema
// ============================================================================

/// W3C Manifest `display` and `display_override` presentation modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PwaDisplayMode {
    Fullscreen,
    Standalone,
    MinimalUi,
    Browser,
    WindowControlsOverlay,
    Tabbed,
}

impl Default for PwaDisplayMode {
    fn default() -> Self {
        Self::Standalone
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestIcon {
    pub src: String,
    #[serde(default)]
    pub sizes: Option<String>,
    #[serde(rename = "type", default)]
    pub mime_type: Option<String>,
    #[serde(default)]
    pub purpose: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestScreenshot {
    pub src: String,
    #[serde(default)]
    pub sizes: Option<String>,
    #[serde(rename = "type", default)]
    pub mime_type: Option<String>,
    #[serde(default)]
    pub form_factor: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestShortcut {
    pub name: String,
    #[serde(default)]
    pub short_name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    pub url: String,
    #[serde(default)]
    pub icons: Vec<ManifestIcon>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestProtocolHandler {
    pub protocol: String,
    pub url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestFileHandler {
    pub action: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub accept: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub icons: Vec<ManifestIcon>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareTargetParams {
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestShareTarget {
    pub action: String,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub enctype: Option<String>,
    #[serde(default)]
    pub params: ShareTargetParams,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestLaunchHandler {
    #[serde(default)]
    pub client_mode: Vec<String>,
}

/// Complete normalized W3C Web App Manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebAppManifest {
    pub name: String,
    pub short_name: Option<String>,
    pub description: Option<String>,
    pub start_url: String,
    pub scope: String,
    pub id: String,
    pub display: PwaDisplayMode,
    #[serde(default)]
    pub display_override: Vec<PwaDisplayMode>,
    pub theme_color: Option<String>,
    pub background_color: Option<String>,
    #[serde(default)]
    pub icons: Vec<ManifestIcon>,
    #[serde(default)]
    pub screenshots: Vec<ManifestScreenshot>,
    #[serde(default)]
    pub shortcuts: Vec<ManifestShortcut>,
    #[serde(default)]
    pub protocol_handlers: Vec<ManifestProtocolHandler>,
    #[serde(default)]
    pub file_handlers: Vec<ManifestFileHandler>,
    pub share_target: Option<ManifestShareTarget>,
    pub launch_handler: Option<ManifestLaunchHandler>,
}

impl WebAppManifest {
    /// Display title prioritizing `name`, falling back to `short_name` or host.
    pub fn display_title(&self) -> &str {
        if !self.name.trim().is_empty() {
            self.name.as_str()
        } else if let Some(s) = self.short_name.as_deref() {
            if !s.trim().is_empty() {
                return s;
            }
            self.start_url.as_str()
        } else {
            self.start_url.as_str()
        }
    }
}

// ============================================================================
// 2. Pure-Rust URL Parsing, Resolution, Deterministic ID & Scope Guard
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedOriginUrl {
    scheme: String,
    host: String,
    port: u16,
    path: String,
    query: Option<String>,
}

impl ParsedOriginUrl {
    fn parse(raw: &str) -> Result<Self, PwaError> {
        let trimmed = raw.trim();
        let Some(sep) = trimmed.find("://") else {
            return Err(PwaError::InvalidUrl(
                raw.to_string(),
                "missing scheme://".into(),
            ));
        };
        let scheme = trimmed[..sep].to_ascii_lowercase();
        if scheme != "http" && scheme != "https" {
            return Err(PwaError::InvalidUrl(
                raw.to_string(),
                format!("unsupported scheme '{}'", scheme),
            ));
        }
        let rest = &trimmed[sep + 3..];
        let no_frag = rest.split('#').next().unwrap_or(rest);
        let (authority, path_query) = match no_frag.find('/') {
            Some(idx) => (&no_frag[..idx], &no_frag[idx..]),
            None => (no_frag, "/"),
        };
        if authority.is_empty() || authority.contains('@') {
            return Err(PwaError::InvalidUrl(
                raw.to_string(),
                "invalid or empty authority".into(),
            ));
        }
        let default_port = if scheme == "https" { 443 } else { 80 };
        let (host, port) = if authority.starts_with('[') {
            let end = authority
                .find(']')
                .ok_or_else(|| PwaError::InvalidUrl(raw.into(), "unclosed IPv6 literal".into()))?;
            let h = authority[..=end].to_ascii_lowercase();
            let p = if let Some(port_s) = authority[end + 1..].strip_prefix(':') {
                port_s
                    .parse::<u16>()
                    .map_err(|_| PwaError::InvalidUrl(raw.into(), "invalid port".into()))?
            } else {
                default_port
            };
            (h, p)
        } else if let Some((h, p_s)) = authority.rsplit_once(':') {
            let p = p_s
                .parse::<u16>()
                .map_err(|_| PwaError::InvalidUrl(raw.into(), "invalid port".into()))?;
            (h.to_ascii_lowercase(), p)
        } else {
            (authority.to_ascii_lowercase(), default_port)
        };

        if host.is_empty() || host.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(PwaError::InvalidUrl(raw.into(), "invalid host".into()));
        }

        let (raw_path, query) = match path_query.split_once('?') {
            Some((p, q)) => (p, Some(q.to_string())),
            None => (path_query, None),
        };
        let path = normalize_dot_segments(raw_path);
        Ok(Self {
            scheme,
            host,
            port,
            path,
            query,
        })
    }

    fn origin_string(&self) -> String {
        let default_port = if self.scheme == "https" { 443 } else { 80 };
        if self.port == default_port {
            format!("{}://{}", self.scheme, self.host)
        } else {
            format!("{}://{}:{}", self.scheme, self.host, self.port)
        }
    }

    fn same_origin(&self, other: &Self) -> bool {
        self.scheme == other.scheme && self.host == other.host && self.port == other.port
    }

    fn to_canonical_url(&self) -> String {
        match &self.query {
            Some(q) => format!("{}{}?{}", self.origin_string(), self.path, q),
            None => format!("{}{}", self.origin_string(), self.path),
        }
    }

    fn parent_dir_url(&self) -> String {
        let dir = match self.path.rfind('/') {
            Some(idx) => &self.path[..=idx],
            None => "/",
        };
        format!("{}{}", self.origin_string(), dir)
    }

    fn is_secure_context(&self) -> bool {
        self.scheme == "https"
            || self.host == "localhost"
            || self.host == "127.0.0.1"
            || self.host == "[::1]"
    }
}

fn normalize_dot_segments(raw_path: &str) -> String {
    let trailing_slash = raw_path.ends_with('/') && raw_path.len() > 1;
    let mut segs: Vec<&str> = Vec::new();
    for seg in raw_path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                segs.pop();
            }
            s => segs.push(s),
        }
    }
    if segs.is_empty() {
        "/".into()
    } else if trailing_slash {
        format!("/{}/", segs.join("/"))
    } else {
        format!("/{}", segs.join("/"))
    }
}

/// Resolves a relative or absolute manifest URL against `base_url`.
pub fn resolve_manifest_url(base_url: &str, candidate: &str) -> Result<String, PwaError> {
    let base = ParsedOriginUrl::parse(base_url)?;
    let trimmed = candidate.trim();
    if trimmed.is_empty() {
        return Ok(base.to_canonical_url());
    }
    if trimmed.contains("://") {
        return Ok(ParsedOriginUrl::parse(trimmed)?.to_canonical_url());
    }
    if let Some(after_slashes) = trimmed.strip_prefix("//") {
        let full = format!("{}:{}", base.scheme, format!("//{}", after_slashes));
        return Ok(ParsedOriginUrl::parse(&full)?.to_canonical_url());
    }
    if trimmed.starts_with('/') {
        let full = format!("{}{}", base.origin_string(), trimmed);
        return Ok(ParsedOriginUrl::parse(&full)?.to_canonical_url());
    }
    if trimmed.starts_with('?') {
        let full = format!("{}{}{}", base.origin_string(), base.path, trimmed);
        return Ok(ParsedOriginUrl::parse(&full)?.to_canonical_url());
    }
    if trimmed.starts_with('#') {
        return Ok(base.to_canonical_url());
    }
    let dir = base.parent_dir_url();
    let full = format!("{}{}", dir, trimmed);
    Ok(ParsedOriginUrl::parse(&full)?.to_canonical_url())
}

/// Computes a deterministic 32-hex-char SHA-256 PWA identifier from a canonical manifest `id`.
pub fn compute_pwa_id(canonical_id_url: &str) -> String {
    let digest = Sha256::digest(canonical_id_url.as_bytes());
    hex::encode(&digest[..16])
}

/// Anti-phishing scope guard: returns `true` ONLY when `url` shares the exact same
/// scheme, host, and normalized port as `scope`, and its path falls strictly within
/// the scope path boundary (so `/app` NEVER matches `/app-evil`).
pub fn is_url_within_scope(url: &str, scope: &str) -> bool {
    let (Ok(u), Ok(s)) = (ParsedOriginUrl::parse(url), ParsedOriginUrl::parse(scope)) else {
        return false;
    };
    if !u.same_origin(&s) {
        return false;
    }
    if s.path == "/" {
        return true;
    }
    if s.path.ends_with('/') {
        u.path.starts_with(&s.path)
            || u.path == s.path.trim_end_matches('/')
    } else {
        u.path == s.path
            || u.path.starts_with(&format!("{}/", s.path))
    }
}

// ============================================================================
// 3. Strict WHATWG Protocol Handler & Anti-Executable File Handler Validators
// ============================================================================

/// WHATWG HTML Living Standard safelisted schemes (excluding `web+*`).
const WHATWG_SAFELISTED_SCHEMES: &[&str] = &[
    "bitcoin",
    "cabal",
    "dat",
    "dweb",
    "ftp",
    "ftps",
    "geo",
    "gopher",
    "im",
    "ipfs",
    "ipns",
    "irc",
    "ircs",
    "magnet",
    "mailto",
    "matrix",
    "news",
    "nntp",
    "openpgp4fpr",
    "sip",
    "sms",
    "smsto",
    "ssb",
    "ssh",
    "tel",
    "urn",
    "webcal",
    "wtai",
    "xmpp",
];

/// Explicitly dangerous/blocked extensions for PWA `file_handlers` (Windows, Linux, macOS).
const BLOCKED_EXECUTABLE_EXTENSIONS: &[&str] = &[
    ".action",
    ".apk",
    ".app",
    ".appimage",
    ".bat",
    ".bash",
    ".bin",
    ".cmd",
    ".com",
    ".command",
    ".cpl",
    ".csh",
    ".deb",
    ".desktop",
    ".dll",
    ".dmg",
    ".drv",
    ".dylib",
    ".elf",
    ".exe",
    ".gadget",
    ".hta",
    ".img",
    ".inf",
    ".iso",
    ".jar",
    ".jse",
    ".js",
    ".ksh",
    ".lnk",
    ".mjs",
    ".msc",
    ".msi",
    ".msp",
    ".pif",
    ".pkg",
    ".ps1",
    ".psm1",
    ".reg",
    ".rpm",
    ".run",
    ".scf",
    ".scr",
    ".sh",
    ".so",
    ".sys",
    ".url",
    ".vbe",
    ".vbs",
    ".vhd",
    ".vhdx",
    ".workflow",
    ".wsf",
    ".wsh",
    ".zsh",
];

const BLOCKED_EXECUTABLE_MIMES: &[&str] = &[
    "application/x-msdownload",
    "application/x-msdos-program",
    "application/x-executable",
    "application/x-dosexec",
    "application/x-sh",
    "application/x-shellscript",
    "application/x-csh",
    "application/x-bat",
    "application/x-msi",
    "application/java-archive",
    "application/vnd.microsoft.portable-executable",
    "application/x-mach-binary",
    "application/x-elf",
    "application/x-sharedlib",
    "application/x-apple-diskimage",
    "application/x-debian-package",
    "application/x-rpm",
    "application/x-desktop",
    "text/javascript",
    "application/javascript",
];

/// Strictly validates a PWA `protocol_handlers` entry per WHATWG rules:
/// - Allows ONLY `web+<lowercase-ascii>` or WHATWG safelisted schemes (`mailto`, `magnet`, etc.).
/// - Explicitly rejects `file`, `javascript`, `http`, `https`, `data`, `blob`, `chrome`, etc.
/// - Requires `%s` placeholder and same-origin secure target URL.
pub fn validate_protocol_handler(
    handler: &ManifestProtocolHandler,
    origin_url: &str,
) -> Result<(), PwaError> {
    let raw_proto = handler.protocol.trim();
    if raw_proto.is_empty() {
        return Err(PwaError::InvalidProtocolHandler(
            String::new(),
            "protocol cannot be empty".into(),
        ));
    }

    let proto = raw_proto.to_ascii_lowercase();
    let scheme_allowed = if let Some(suffix) = raw_proto.strip_prefix("web+") {
        !suffix.is_empty()
            && suffix.len() <= 32
            && suffix.bytes().all(|b| b.is_ascii_lowercase())
    } else if proto.starts_with("web+") {
        // Reject uppercase prefix such as WEB+foo
        false
    } else {
        WHATWG_SAFELISTED_SCHEMES.contains(&proto.as_str())
    };

    if !scheme_allowed {
        return Err(PwaError::InvalidProtocolHandler(
            raw_proto.to_string(),
            "scheme is not a WHATWG safelisted or valid web+ custom protocol".into(),
        ));
    }

    if !handler.url.contains("%s") {
        return Err(PwaError::InvalidProtocolHandler(
            proto,
            "handler URL must include '%s' substitution token".into(),
        ));
    }

    let base = ParsedOriginUrl::parse(origin_url)?;
    let target = ParsedOriginUrl::parse(&handler.url)?;
    if !target.is_secure_context() {
        return Err(PwaError::InvalidProtocolHandler(
            proto,
            "handler URL must use https:// or localhost".into(),
        ));
    }
    if !base.same_origin(&target) {
        return Err(PwaError::CrossOriginRejected(handler.url.clone()));
    }
    Ok(())
}

/// Strictly validates a PWA `file_handlers` entry against executable extensions and MIME types.
pub fn validate_file_handler(
    handler: &ManifestFileHandler,
    origin_url: &str,
) -> Result<(), PwaError> {
    let base = ParsedOriginUrl::parse(origin_url)?;
    let action = ParsedOriginUrl::parse(&handler.action)?;
    if !base.same_origin(&action) {
        return Err(PwaError::CrossOriginRejected(handler.action.clone()));
    }
    if handler.accept.is_empty() {
        return Err(PwaError::InvalidFileHandler(
            "file handler must declare at least one accepted MIME type".into(),
        ));
    }

    for (mime, exts) in &handler.accept {
        let mime_low = mime.trim().to_ascii_lowercase();
        if !mime_low.contains('/')
            || mime_low.contains('*')
            || mime_low.chars().any(|c| c.is_whitespace() || c.is_control())
        {
            return Err(PwaError::InvalidFileHandler(format!(
                "invalid or wildcard MIME type '{}'",
                mime
            )));
        }
        if BLOCKED_EXECUTABLE_MIMES.contains(&mime_low.as_str()) {
            return Err(PwaError::InvalidFileHandler(format!(
                "executable MIME type '{}' is forbidden",
                mime
            )));
        }
        if exts.is_empty() {
            return Err(PwaError::InvalidFileHandler(format!(
                "MIME '{}' must specify at least one file extension",
                mime
            )));
        }
        for ext in exts {
            let e = ext.trim().to_ascii_lowercase();
            if !e.starts_with('.')
                || e.len() < 2
                || e.len() > 16
                || !e[1..].bytes().all(|b| b.is_ascii_alphanumeric())
            {
                return Err(PwaError::InvalidFileHandler(format!(
                    "malformed file extension '{}'",
                    ext
                )));
            }
            if BLOCKED_EXECUTABLE_EXTENSIONS.contains(&e.as_str()) {
                return Err(PwaError::InvalidFileHandler(format!(
                    "executable/script extension '{}' is forbidden",
                    ext
                )));
            }
        }
    }
    Ok(())
}

// ============================================================================
// 4. Manifest Parser & "Install Any Site as App" Synthesizer
// ============================================================================

#[derive(Debug, Deserialize)]
struct RawManifestJson {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    short_name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    start_url: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    display: Option<PwaDisplayMode>,
    #[serde(default)]
    display_override: Vec<PwaDisplayMode>,
    #[serde(default)]
    theme_color: Option<String>,
    #[serde(default)]
    background_color: Option<String>,
    #[serde(default)]
    icons: Vec<ManifestIcon>,
    #[serde(default)]
    screenshots: Vec<ManifestScreenshot>,
    #[serde(default)]
    shortcuts: Vec<ManifestShortcut>,
    #[serde(default)]
    protocol_handlers: Vec<ManifestProtocolHandler>,
    #[serde(default)]
    file_handlers: Vec<ManifestFileHandler>,
    #[serde(default)]
    share_target: Option<ManifestShareTarget>,
    #[serde(default)]
    launch_handler: Option<RawLaunchHandler>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawClientMode {
    One(String),
    Many(Vec<String>),
}

#[derive(Debug, Deserialize)]
struct RawLaunchHandler {
    #[serde(default)]
    client_mode: Option<RawClientMode>,
}

/// Parses and normalizes a W3C `manifest.json` against `base_url`, resolving relative URLs,
/// enforcing same-origin & scope invariants, and strictly filtering invalid handlers.
pub fn parse_web_app_manifest(json: &str, base_url: &str) -> Result<WebAppManifest, PwaError> {
    let base = ParsedOriginUrl::parse(base_url)?;
    let raw: RawManifestJson =
        serde_json::from_str(json).map_err(|e| PwaError::InvalidManifestJson(e.to_string()))?;

    let start_url = match raw.start_url.as_deref() {
        Some(su) if !su.trim().is_empty() => resolve_manifest_url(base_url, su)?,
        _ => base.to_canonical_url(),
    };
    let start_parsed = ParsedOriginUrl::parse(&start_url)?;
    if !base.same_origin(&start_parsed) {
        return Err(PwaError::CrossOriginRejected(start_url));
    }

    let scope = match raw.scope.as_deref() {
        Some(sc) if !sc.trim().is_empty() => resolve_manifest_url(base_url, sc)?,
        _ => start_parsed.parent_dir_url(),
    };
    let scope_parsed = ParsedOriginUrl::parse(&scope)?;
    if !base.same_origin(&scope_parsed) {
        return Err(PwaError::CrossOriginRejected(scope));
    }
    if !is_url_within_scope(&start_url, &scope) {
        return Err(PwaError::StartUrlOutOfScope(start_url, scope));
    }

    let canonical_id_url = match raw.id.as_deref() {
        Some(id_str) if !id_str.trim().is_empty() => {
            let resolved = resolve_manifest_url(&base.origin_string(), id_str)?;
            let id_parsed = ParsedOriginUrl::parse(&resolved)?;
            if !base.same_origin(&id_parsed) {
                return Err(PwaError::CrossOriginRejected(resolved));
            }
            resolved
        }
        _ => start_url.clone(),
    };

    let name = raw
        .name
        .filter(|s| !s.trim().is_empty())
        .or_else(|| raw.short_name.clone().filter(|s| !s.trim().is_empty()))
        .unwrap_or_else(|| base.host.clone());

    let icons = raw
        .icons
        .into_iter()
        .filter_map(|mut ic| {
            ic.src = resolve_manifest_url(base_url, &ic.src).ok()?;
            Some(ic)
        })
        .collect();

    let screenshots = raw
        .screenshots
        .into_iter()
        .filter_map(|mut sc| {
            sc.src = resolve_manifest_url(base_url, &sc.src).ok()?;
            Some(sc)
        })
        .collect();

    let shortcuts = raw
        .shortcuts
        .into_iter()
        .filter_map(|mut sh| {
            let resolved = resolve_manifest_url(base_url, &sh.url).ok()?;
            if !is_url_within_scope(&resolved, &scope) {
                return None;
            }
            sh.url = resolved;
            sh.icons = sh
                .icons
                .into_iter()
                .filter_map(|mut ic| {
                    ic.src = resolve_manifest_url(base_url, &ic.src).ok()?;
                    Some(ic)
                })
                .collect();
            Some(sh)
        })
        .collect();

    let mut protocol_handlers = Vec::new();
    for mut ph in raw.protocol_handlers {
        if let Ok(resolved) = resolve_manifest_url(base_url, &ph.url) {
            ph.url = resolved;
            if validate_protocol_handler(&ph, base_url).is_ok() {
                ph.protocol = ph.protocol.trim().to_ascii_lowercase();
                protocol_handlers.push(ph);
            }
        }
    }

    let mut file_handlers = Vec::new();
    for mut fh in raw.file_handlers {
        if let Ok(resolved) = resolve_manifest_url(base_url, &fh.action) {
            fh.action = resolved;
            if validate_file_handler(&fh, base_url).is_ok() {
                file_handlers.push(fh);
            }
        }
    }

    let share_target = raw.share_target.and_then(|mut st| {
        let resolved = resolve_manifest_url(base_url, &st.action).ok()?;
        let parsed = ParsedOriginUrl::parse(&resolved).ok()?;
        if !base.same_origin(&parsed) {
            return None;
        }
        st.action = resolved;
        Some(st)
    });

    let launch_handler = raw.launch_handler.map(|lh| ManifestLaunchHandler {
        client_mode: match lh.client_mode {
            Some(RawClientMode::One(s)) => vec![s],
            Some(RawClientMode::Many(v)) => v,
            None => Vec::new(),
        },
    });

    Ok(WebAppManifest {
        name,
        short_name: raw.short_name,
        description: raw.description,
        start_url,
        scope,
        id: canonical_id_url,
        display: raw.display.unwrap_or(PwaDisplayMode::Standalone),
        display_override: raw.display_override,
        theme_color: raw.theme_color,
        background_color: raw.background_color,
        icons,
        screenshots,
        shortcuts,
        protocol_handlers,
        file_handlers,
        share_target,
        launch_handler,
    })
}

/// Synthesizes a valid standalone manifest for any arbitrary website ("Install any site as an app").
pub fn synthesize_manifest_for_site(
    url: &str,
    title: &str,
    theme_color: Option<&str>,
) -> Result<WebAppManifest, PwaError> {
    let parsed = ParsedOriginUrl::parse(url)?;
    let start_url = parsed.to_canonical_url();
    let scope = format!("{}/", parsed.origin_string());
    let clean_title = title.trim();
    let final_name = if clean_title.is_empty() {
        parsed.host.clone()
    } else {
        clean_title.to_string()
    };

    Ok(WebAppManifest {
        name: final_name,
        short_name: None,
        description: Some(format!("Installed web application for {}", parsed.host)),
        start_url: start_url.clone(),
        scope,
        id: start_url,
        display: PwaDisplayMode::Standalone,
        display_override: vec![PwaDisplayMode::Standalone],
        theme_color: theme_color
            .map(String::from)
            .or_else(|| Some("#000000".into())),
        background_color: Some("#000000".into()),
        icons: Vec::new(),
        screenshots: Vec::new(),
        shortcuts: Vec::new(),
        protocol_handlers: Vec::new(),
        file_handlers: Vec::new(),
        share_target: None,
        launch_handler: Some(ManifestLaunchHandler {
            client_mode: vec!["navigate-existing".into()],
        }),
    })
}

// ============================================================================
// 5. PwaRegistry (`apps/registry.json`) & OS Shortcut Integration
// ============================================================================

/// Installed PWA record tracked in `<root>/apps/registry.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledPwa {
    pub id: String,
    pub manifest: WebAppManifest,
    pub is_synthetic: bool,
    pub open_in_window: bool,
    pub launch_at_os_login: bool,
    pub capture_links: bool,
    pub badge_count: u32,
    pub installed_unix: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct RegistryFilePayload {
    apps: BTreeMap<String, InstalledPwa>,
}

/// Persistent PWA installation registry backed by `<root>/apps/registry.json`.
#[derive(Debug, Clone)]
pub struct PwaRegistry {
    registry_path: PathBuf,
    apps: BTreeMap<String, InstalledPwa>,
}

impl PwaRegistry {
    /// Opens or initializes `<root>/apps/registry.json`.
    pub fn open_at(root: &Path) -> Result<Self, PwaError> {
        let apps_dir = root.join("apps");
        fs::create_dir_all(&apps_dir).map_err(|e| PwaError::Io(e.to_string()))?;
        let registry_path = apps_dir.join("registry.json");

        let apps = if registry_path.is_file() {
            let raw = fs::read_to_string(&registry_path).map_err(|e| PwaError::Io(e.to_string()))?;
            let payload: RegistryFilePayload = serde_json::from_str(&raw)
                .map_err(|e| PwaError::InvalidManifestJson(e.to_string()))?;
            payload.apps
        } else {
            BTreeMap::new()
        };

        Ok(Self {
            registry_path,
            apps,
        })
    }

    pub fn registry_path(&self) -> &Path {
        &self.registry_path
    }

    /// Installs or updates a PWA from a parsed [`WebAppManifest`].
    pub fn install_manifest(
        &mut self,
        manifest: WebAppManifest,
        is_synthetic: bool,
    ) -> Result<InstalledPwa, PwaError> {
        let app_id = compute_pwa_id(&manifest.id);
        let now = unix_now();
        let record = InstalledPwa {
            id: app_id.clone(),
            manifest,
            is_synthetic,
            open_in_window: true,
            launch_at_os_login: false,
            capture_links: true,
            badge_count: 0,
            installed_unix: now,
        };
        self.apps.insert(app_id, record.clone());
        self.save()?;
        Ok(record)
    }

    /// Convenience helper: synthesizes a manifest and installs any site as a standalone PWA.
    pub fn install_site_as_app(
        &mut self,
        url: &str,
        title: &str,
        theme_color: Option<&str>,
    ) -> Result<InstalledPwa, PwaError> {
        let manifest = synthesize_manifest_for_site(url, title, theme_color)?;
        self.install_manifest(manifest, true)
    }

    pub fn uninstall(&mut self, app_id: &str) -> Result<bool, PwaError> {
        let removed = self.apps.remove(app_id).is_some();
        if removed {
            self.save()?;
        }
        Ok(removed)
    }

    pub fn get(&self, app_id: &str) -> Option<&InstalledPwa> {
        self.apps.get(app_id)
    }

    pub fn list(&self) -> Vec<&InstalledPwa> {
        self.apps.values().collect()
    }

    pub fn set_badge_count(&mut self, app_id: &str, count: u32) -> Result<(), PwaError> {
        let app = self
            .apps
            .get_mut(app_id)
            .ok_or_else(|| PwaError::NotFound(app_id.to_string()))?;
        app.badge_count = count;
        self.save()
    }

    pub fn set_launch_at_os_login(&mut self, app_id: &str, enabled: bool) -> Result<(), PwaError> {
        let app = self
            .apps
            .get_mut(app_id)
            .ok_or_else(|| PwaError::NotFound(app_id.to_string()))?;
        app.launch_at_os_login = enabled;
        self.save()
    }

    pub fn set_capture_links(&mut self, app_id: &str, enabled: bool) -> Result<(), PwaError> {
        let app = self
            .apps
            .get_mut(app_id)
            .ok_or_else(|| PwaError::NotFound(app_id.to_string()))?;
        app.capture_links = enabled;
        self.save()
    }

    /// Finds the most specific installed PWA capturing links for `url`.
    pub fn find_capturing_app_for_url(&self, url: &str) -> Option<&InstalledPwa> {
        self.apps
            .values()
            .filter(|a| a.capture_links && is_url_within_scope(url, &a.manifest.scope))
            .max_by_key(|a| a.manifest.scope.len())
    }

    /// Finds an installed PWA registered to handle a custom protocol scheme (e.g. `web+notes`).
    pub fn find_protocol_handler(&self, protocol: &str) -> Option<(&InstalledPwa, &ManifestProtocolHandler)> {
        let p = protocol.trim().to_ascii_lowercase();
        for app in self.apps.values() {
            if let Some(h) = app
                .manifest
                .protocol_handlers
                .iter()
                .find(|h| h.protocol.eq_ignore_ascii_case(&p))
            {
                return Some((app, h));
            }
        }
        None
    }

    fn save(&self) -> Result<(), PwaError> {
        let payload = RegistryFilePayload {
            apps: self.apps.clone(),
        };
        let json = serde_json::to_string_pretty(&payload)
            .map_err(|e| PwaError::InvalidManifestJson(e.to_string()))?;
        let tmp = self.registry_path.with_file_name(format!(
            ".registry.json.tmp.{}",
            std::process::id()
        ));
        {
            let mut f = fs::File::create(&tmp).map_err(|e| PwaError::Io(e.to_string()))?;
            f.write_all(json.as_bytes())
                .map_err(|e| PwaError::Io(e.to_string()))?;
            f.sync_all().map_err(|e| PwaError::Io(e.to_string()))?;
        }
        fs::rename(&tmp, &self.registry_path).map_err(|e| PwaError::Io(e.to_string()))
    }
}

fn sanitize_xdg_value(raw: &str) -> String {
    raw.chars()
        .filter(|&c| c != '\r' && c != '\n' && !c.is_control())
        .collect()
}

/// Generates a Linux XDG `.desktop` entry for an installed PWA, including `Actions=`
/// jump-list shortcuts and `MimeType=` registrations for validated protocol & file handlers.
pub fn generate_linux_desktop_file(
    app: &InstalledPwa,
    executable_path: &str,
    icon_path: Option<&str>,
) -> String {
    let exe = sanitize_xdg_value(executable_path);
    let name = sanitize_xdg_value(app.manifest.display_title());
    let comment = sanitize_xdg_value(
        app.manifest
            .description
            .as_deref()
            .unwrap_or("Singularity Installed Web Application"),
    );
    let icon = sanitize_xdg_value(icon_path.unwrap_or("singularity"));

    let mut action_ids = Vec::new();
    for idx in 0..app.manifest.shortcuts.len() {
        action_ids.push(format!("shortcut-{}", idx));
    }

    let mut mime_types: Vec<String> = Vec::new();
    for ph in &app.manifest.protocol_handlers {
        if validate_protocol_handler(ph, &app.manifest.start_url).is_ok() {
            mime_types.push(format!("x-scheme-handler/{}", ph.protocol.to_ascii_lowercase()));
        }
    }
    for fh in &app.manifest.file_handlers {
        if validate_file_handler(fh, &app.manifest.start_url).is_ok() {
            for mime in fh.accept.keys() {
                let m = mime.trim().to_ascii_lowercase();
                if !mime_types.contains(&m) {
                    mime_types.push(m);
                }
            }
        }
    }

    let mut out = format!(
        "[Desktop Entry]\n\
         Version=1.0\n\
         Type=Application\n\
         Name={name}\n\
         Comment={comment}\n\
         Exec=\"{exe}\" --app-id={id} %u\n\
         Icon={icon}\n\
         Terminal=false\n\
         Categories=Network;WebBrowser;\n\
         StartupWMClass=singularity-pwa-{id}\n",
        name = name,
        comment = comment,
        exe = exe,
        id = app.id,
        icon = icon,
    );

    if !mime_types.is_empty() {
        out.push_str(&format!("MimeType={};\n", mime_types.join(";")));
    }
    if !action_ids.is_empty() {
        out.push_str(&format!("Actions={};\n", action_ids.join(";")));
        for (idx, shortcut) in app.manifest.shortcuts.iter().enumerate() {
            out.push_str(&format!(
                "\n[Desktop Action shortcut-{idx}]\n\
                 Name={sname}\n\
                 Exec=\"{exe}\" --app-id={id} --app-url=\"{surl}\"\n",
                idx = idx,
                sname = sanitize_xdg_value(&shortcut.name),
                exe = exe,
                id = app.id,
                surl = sanitize_xdg_value(&shortcut.url).replace('"', ""),
            ));
        }
    }

    out
}

/// Jump List task attached to a Windows Start Menu / Taskbar PWA shortcut.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsJumpListTask {
    pub title: String,
    pub arguments: String,
}

/// Windows Shell Link (`.lnk`) & AppUserModelID descriptor (`Singularity.PWA.<id>`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsShortcutDescriptor {
    pub app_user_model_id: String,
    pub target_executable: String,
    pub arguments: String,
    pub display_name: String,
    pub description: String,
    pub icon_location: Option<String>,
    pub jump_list_tasks: Vec<WindowsJumpListTask>,
    pub registered_protocols: Vec<String>,
    pub registered_extensions: Vec<String>,
}

/// Builds the Windows shortcut descriptor with deterministic `AppUserModelID = Singularity.PWA.<id>`.
pub fn generate_windows_shortcut_descriptor(
    app: &InstalledPwa,
    executable_path: &str,
    icon_path: Option<&str>,
) -> WindowsShortcutDescriptor {
    let jump_list_tasks = app
        .manifest
        .shortcuts
        .iter()
        .map(|s| WindowsJumpListTask {
            title: sanitize_xdg_value(&s.name),
            arguments: format!(
                "--app-id={} --app-url=\"{}\"",
                app.id,
                sanitize_xdg_value(&s.url).replace('"', "")
            ),
        })
        .collect();

    let registered_protocols = app
        .manifest
        .protocol_handlers
        .iter()
        .filter(|ph| validate_protocol_handler(ph, &app.manifest.start_url).is_ok())
        .map(|ph| ph.protocol.to_ascii_lowercase())
        .collect();

    let mut registered_extensions = Vec::new();
    for fh in &app.manifest.file_handlers {
        if validate_file_handler(fh, &app.manifest.start_url).is_ok() {
            for exts in fh.accept.values() {
                for ext in exts {
                    let e = ext.trim().to_ascii_lowercase();
                    if !registered_extensions.contains(&e) {
                        registered_extensions.push(e);
                    }
                }
            }
        }
    }

    WindowsShortcutDescriptor {
        app_user_model_id: format!("Singularity.PWA.{}", app.id),
        target_executable: executable_path.to_string(),
        arguments: format!("--app-id={}", app.id),
        display_name: sanitize_xdg_value(app.manifest.display_title()),
        description: sanitize_xdg_value(
            app.manifest
                .description
                .as_deref()
                .unwrap_or("Singularity Installed Web Application"),
        ),
        icon_location: icon_path.map(String::from),
        jump_list_tasks,
        registered_protocols,
        registered_extensions,
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    const RICH_MANIFEST: &str = r##"{
        "name": "Singularity Notes",
        "short_name": "Notes",
        "description": "Offline-first Markdown PWA",
        "start_url": "/app/index.html",
        "scope": "/app/",
        "id": "/app/",
        "display": "standalone",
        "display_override": ["window-controls-overlay", "standalone"],
        "theme_color": "#000000",
        "background_color": "#000000",
        "icons": [
            { "src": "/icons/512.png", "sizes": "512x512", "type": "image/png", "purpose": "any maskable" }
        ],
        "screenshots": [
            { "src": "/shots/desk.png", "sizes": "1280x720", "type": "image/png", "form_factor": "wide", "label": "Desktop" }
        ],
        "shortcuts": [
            { "name": "New Note", "url": "/app/new" }
        ],
        "protocol_handlers": [
            { "protocol": "web+note", "url": "/app/open?uri=%s" },
            { "protocol": "mailto", "url": "/app/mail?to=%s" },
            { "protocol": "javascript", "url": "/app/xss?u=%s" },
            { "protocol": "file", "url": "/app/file?u=%s" },
            { "protocol": "https", "url": "/app/hijack?u=%s" }
        ],
        "file_handlers": [
            { "action": "/app/open-md", "name": "Markdown", "accept": { "text/markdown": [".md", ".markdown"] } },
            { "action": "/app/evil-exe", "name": "Evil", "accept": { "application/octet-stream": [".exe"] } }
        ],
        "share_target": {
            "action": "/app/share",
            "method": "GET",
            "params": { "title": "t", "text": "body", "url": "u" }
        },
        "launch_handler": { "client_mode": ["focus-existing", "auto"] }
    }"##;

    #[test]
    fn test_manifest_parsing_security_filters_and_scope_guard() {
        let m = parse_web_app_manifest(RICH_MANIFEST, "https://notes.example.com/manifest.json")
            .expect("parse manifest");

        assert_eq!(m.name, "Singularity Notes");
        assert_eq!(m.start_url, "https://notes.example.com/app/index.html");
        assert_eq!(m.scope, "https://notes.example.com/app/");
        assert_eq!(m.icons[0].src, "https://notes.example.com/icons/512.png");
        assert_eq!(m.shortcuts.len(), 1);
        assert_eq!(m.shortcuts[0].url, "https://notes.example.com/app/new");

        // Strict WHATWG filtering kept web+note & mailto, rejected javascript/file/https
        let protos: Vec<&str> = m
            .protocol_handlers
            .iter()
            .map(|p| p.protocol.as_str())
            .collect();
        assert_eq!(protos, vec!["web+note", "mailto"]);

        // Strict anti-executable filtering kept .md, rejected .exe
        assert_eq!(m.file_handlers.len(), 1);
        assert!(m.file_handlers[0].accept.contains_key("text/markdown"));

        // Anti-phishing scope checks
        assert!(is_url_within_scope("https://notes.example.com/app/doc/1", &m.scope));
        assert!(is_url_within_scope("https://notes.example.com/app", &m.scope));
        assert!(!is_url_within_scope("https://notes.example.com/app-evil/phish", &m.scope));
        assert!(!is_url_within_scope("https://notes.example.com.evil.com/app/", &m.scope));
        assert!(!is_url_within_scope("http://notes.example.com/app/", &m.scope));
    }

    #[test]
    fn test_explicit_protocol_and_file_handler_validators() {
        let origin = "https://safe.example.org/app";
        for forbidden in ["file", "javascript", "http", "https", "data", "web+", "web+UPPER"] {
            let h = ManifestProtocolHandler {
                protocol: forbidden.into(),
                url: "https://safe.example.org/handle?q=%s".into(),
            };
            assert!(
                validate_protocol_handler(&h, origin).is_err(),
                "scheme '{}' must be rejected",
                forbidden
            );
        }

        let magnet = ManifestProtocolHandler {
            protocol: "magnet".into(),
            url: "https://safe.example.org/open?m=%s".into(),
        };
        assert!(validate_protocol_handler(&magnet, origin).is_ok());

        for bad_ext in [".exe", ".bat", ".sh", ".ps1", ".dll", ".desktop", ".appimage", ".jar"] {
            let fh = ManifestFileHandler {
                action: "https://safe.example.org/open".into(),
                name: None,
                accept: BTreeMap::from([("text/plain".into(), vec![bad_ext.into()])]),
                icons: vec![],
            };
            assert!(
                validate_file_handler(&fh, origin).is_err(),
                "extension '{}' must be rejected",
                bad_ext
            );
        }
    }

    #[test]
    fn test_synthesize_registry_persistence_and_os_shortcuts() {
        let dir = std::env::temp_dir().join(format!("singularity_pwa_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);

        let mut reg = PwaRegistry::open_at(&dir).expect("open registry");
        let manifest =
            parse_web_app_manifest(RICH_MANIFEST, "https://notes.example.com/manifest.json")
                .unwrap();
        let installed = reg.install_manifest(manifest, false).expect("install");
        assert_eq!(installed.id.len(), 32);

        // Synthetic site install
        let synth = reg
            .install_site_as_app("https://news.ycombinator.com/newest", "Hacker News", None)
            .expect("install synthetic");
        assert!(synth.is_synthetic);
        assert_eq!(synth.manifest.display, PwaDisplayMode::Standalone);

        // Persistence round-trip
        let reloaded = PwaRegistry::open_at(&dir).expect("reopen");
        assert_eq!(reloaded.list().len(), 2);
        let found = reloaded
            .find_capturing_app_for_url("https://notes.example.com/app/42")
            .expect("capture");
        assert_eq!(found.id, installed.id);

        // Linux .desktop contains Actions= & MimeType=
        let desktop = generate_linux_desktop_file(
            &installed,
            "/usr/bin/singularity",
            Some("/icons/notes.png"),
        );
        assert!(desktop.contains("Actions=shortcut-0;"));
        assert!(desktop.contains("[Desktop Action shortcut-0]"));
        assert!(desktop.contains("MimeType=x-scheme-handler/web+note;x-scheme-handler/mailto;text/markdown;"));

        // Windows shortcut descriptor has exact AppUserModelID = Singularity.PWA.<id>
        let win = generate_windows_shortcut_descriptor(
            &installed,
            r"C:\Program Files\Singularity\singularity.exe",
            None,
        );
        assert_eq!(win.app_user_model_id, format!("Singularity.PWA.{}", installed.id));
        assert_eq!(win.jump_list_tasks.len(), 1);
        assert!(win.registered_protocols.contains(&"web+note".to_string()));
        assert!(win.registered_extensions.contains(&".md".to_string()));

        let _ = fs::remove_dir_all(&dir);
    }
}
