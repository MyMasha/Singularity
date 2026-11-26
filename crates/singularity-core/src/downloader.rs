//! Download Manager: Concurrency Queue (`max_concurrent`), Pause/Resume/Cancel/Retry,
//! Multi-Segment HTTP `Range` Planner, Constant-Time SHA-256 Verifier, Security Danger Analyzer
//! (Double Extensions, Unicode RLO U+202E, Mixed Downloads, ThreatGuard), Smart Compound Renaming,
//! Template Routing Rules, and Mark-of-the-Web (MOTW `Zone.Identifier` / `user.xdg.origin.url`).

use crate::blocker::normalize_host;
use crate::tabs::wildcard_match;
use crate::threat_guard::{ThreatGuard, ThreatVerdict};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Lifecycle state of a download item in [`DownloadManager`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DownloadState {
    Queued,
    InProgress,
    Paused,
    Completed,
    Failed { reason: String },
    Canceled,
    BlockedDanger { reason: String },
}

/// High-level file category used for smart routing and UI organization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DownloadCategory {
    Documents,
    Images,
    Audio,
    Video,
    Archives,
    Executables,
    Code,
    Other,
}

impl DownloadCategory {
    pub const fn as_folder_name(self) -> &'static str {
        match self {
            DownloadCategory::Documents => "documents",
            DownloadCategory::Images => "images",
            DownloadCategory::Audio => "audio",
            DownloadCategory::Video => "video",
            DownloadCategory::Archives => "archives",
            DownloadCategory::Executables => "executables",
            DownloadCategory::Code => "code",
            DownloadCategory::Other => "other",
        }
    }
}

/// Security classification emitted by [`classify_download_danger`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DownloadDangerLevel {
    Safe,
    Uncommon {
        reason: String,
    },
    PotentiallyDangerousExecutable {
        extension: String,
    },
    DangerousDoubleExtension {
        filename: String,
    },
    DangerousUnicodeSpoofing {
        codepoint: String,
    },
    MixedContentDownload {
        page_url: String,
        download_url: String,
    },
    Malicious {
        reason: String,
    },
}

impl DownloadDangerLevel {
    pub fn is_safe(&self) -> bool {
        matches!(self, DownloadDangerLevel::Safe)
    }

    pub fn should_auto_block(&self) -> bool {
        matches!(
            self,
            DownloadDangerLevel::Malicious { .. }
                | DownloadDangerLevel::DangerousUnicodeSpoofing { .. }
        )
    }
}

/// Strategy when a destination filename already exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CollisionPolicy {
    AutoRename,
    Overwrite,
    Skip,
    Prompt,
}

/// Automatic routing & smart filename template rule based on category, extension, or source domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DownloadRoutingRule {
    pub id: String,
    pub category: Option<DownloadCategory>,
    pub extension_glob: Option<String>,
    pub source_domain_glob: Option<String>,
    pub target_dir: String,
    pub filename_template: Option<String>,
    pub enabled: bool,
}

impl DownloadRoutingRule {
    pub fn matches(&self, category: DownloadCategory, ext: &str, source_host: &str) -> bool {
        if !self.enabled {
            return false;
        }
        if let Some(cat) = self.category {
            if cat != category {
                return false;
            }
        }
        if let Some(ref ext_glob) = self.extension_glob {
            if !wildcard_match(
                &ext_glob.trim().to_ascii_lowercase(),
                &ext.trim().to_ascii_lowercase(),
            ) {
                return false;
            }
        }
        if let Some(ref dom_glob) = self.source_domain_glob {
            let pat = dom_glob.trim().to_ascii_lowercase();
            let host = normalize_host(source_host);
            let matched = if let Some(suffix) = pat.strip_prefix("*.") {
                host == suffix || host.ends_with(&format!(".{}", suffix))
            } else if pat.contains('*') || pat.contains('?') {
                wildcard_match(&pat, &host)
            } else {
                host == pat || host.ends_with(&format!(".{}", pat))
            };
            if !matched {
                return false;
            }
        }
        true
    }
}

/// Inclusive HTTP `Range` byte segment scheduled for parallel download acceleration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DownloadSegmentPlan {
    pub index: usize,
    pub start_byte: u64,
    pub end_byte: u64,
    pub range_header: String,
}

impl DownloadSegmentPlan {
    pub fn byte_len(&self) -> u64 {
        self.end_byte.saturating_sub(self.start_byte).saturating_add(1)
    }
}

/// Complete record of a managed download item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DownloadRecord {
    pub id: u64,
    pub url: String,
    pub referring_page_url: Option<String>,
    pub filename: String,
    pub destination_path: String,
    pub mime_type: Option<String>,
    pub category: DownloadCategory,
    pub danger_level: DownloadDangerLevel,
    pub state: DownloadState,
    pub total_bytes: Option<u64>,
    pub received_bytes: u64,
    pub expected_sha256: Option<String>,
    pub segments: Vec<DownloadSegmentPlan>,
    pub created_at_unix: u64,
    pub updated_at_unix: u64,
    pub retry_count: u32,
}

/// Result returned by [`write_mark_of_the_web`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MotwWriteOutcome {
    WindowsZoneIdentifierAds(String),
    LinuxXattrApplied,
    SidecarZoneIdentifierFallback(String),
}

const COMPOUND_EXTENSIONS: &[&str] = &[
    ".tar.gz",
    ".tar.xz",
    ".tar.bz2",
    ".tar.zst",
    ".tar.lz4",
    ".tar.lz",
    ".tar.br",
    ".user.js",
    ".d.ts",
];

const DANGEROUS_EXECUTABLE_EXTENSIONS: &[&str] = &[
    "exe", "msi", "msp", "bat", "cmd", "scr", "pif", "com", "vbs", "vbe", "js", "jse", "wsf",
    "wsh", "ps1", "psm1", "hta", "lnk", "reg", "dll", "cpl", "jar", "appimage", "sh", "bash",
    "deb", "rpm", "dmg", "pkg", "apk", "iso", "img",
];

const BENIGN_DECOY_EXTENSIONS: &[&str] = &[
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "csv", "jpg", "jpeg",
    "png", "gif", "webp", "svg", "mp3", "mp4", "wav", "avi", "mkv", "zip", "rar", "7z",
];

/// Splits a filename into `(stem, extension)` while preserving compound extensions
/// such as `.tar.gz`, `.tar.xz`, `.tar.bz2`, `.tar.zst`, `.user.js`, `.d.ts`.
pub fn split_compound_filename(filename: &str) -> (&str, &str) {
    let lower = filename.to_ascii_lowercase();
    for &compound in COMPOUND_EXTENSIONS {
        if lower.ends_with(compound) && filename.len() > compound.len() {
            let split_at = filename.len() - compound.len();
            return (&filename[..split_at], &filename[split_at..]);
        }
    }
    if let Some(dot) = filename.rfind('.') {
        if dot > 0 && dot + 1 < filename.len() {
            return (&filename[..dot], &filename[dot..]);
        }
    }
    (filename, "")
}

/// Sanitizes a filename fragment to remove directory traversal, control chars, and bidi spoofers.
pub fn sanitize_filename_component(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if ch.is_control()
            || is_bidi_spoofing_char(ch)
            || matches!(ch, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|')
        {
            out.push('_');
        } else {
            out.push(ch);
        }
    }
    let trimmed = out.trim().trim_matches('.');
    if trimmed.is_empty() {
        "download".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Renders a smart filename template supporting `{name}`, `{stem}`, `{ext}`, `{domain}`, `{date}`, `{category}`.
pub fn render_filename_template(
    template: &str,
    filename: &str,
    domain: &str,
    date_ymd: &str,
    category: DownloadCategory,
) -> String {
    let clean_name = sanitize_filename_component(filename);
    let (stem, ext) = split_compound_filename(&clean_name);
    let clean_domain = sanitize_filename_component(domain);
    let clean_date = sanitize_filename_component(date_ymd);

    let rendered = template
        .replace("{name}", &clean_name)
        .replace("{stem}", stem)
        .replace("{ext}", ext)
        .replace("{domain}", &clean_domain)
        .replace("{date}", &clean_date)
        .replace("{category}", category.as_folder_name());

    sanitize_filename_component(&rendered)
}

/// Resolves filename collisions while respecting compound extensions (`archive.tar.gz` -> `archive (1).tar.gz`).
pub fn resolve_collision_filename(
    desired_name: &str,
    existing_names: &[String],
    policy: CollisionPolicy,
) -> Option<String> {
    let exists = |cand: &str| {
        existing_names
            .iter()
            .any(|e| e.eq_ignore_ascii_case(cand))
    };

    if !exists(desired_name) {
        return Some(desired_name.to_string());
    }

    match policy {
        CollisionPolicy::Overwrite | CollisionPolicy::Prompt => Some(desired_name.to_string()),
        CollisionPolicy::Skip => None,
        CollisionPolicy::AutoRename => {
            let (stem, ext) = split_compound_filename(desired_name);
            for n in 1u32..=10_000 {
                let candidate = format!("{} ({}){}", stem, n, ext);
                if !exists(&candidate) {
                    return Some(candidate);
                }
            }
            None
        }
    }
}

/// Classifies a download into a [`DownloadCategory`] based on compound extension and MIME type.
pub fn classify_category(filename: &str, mime_type: Option<&str>) -> DownloadCategory {
    let (_, ext_with_dot) = split_compound_filename(filename);
    let ext = ext_with_dot.trim_start_matches('.').to_ascii_lowercase();

    match ext.as_str() {
        "pdf" | "doc" | "docx" | "odt" | "rtf" | "txt" | "md" | "xls" | "xlsx" | "csv" | "ppt"
        | "pptx" | "epub" => return DownloadCategory::Documents,
        "png" | "jpg" | "jpeg" | "gif" | "webp" | "avif" | "svg" | "bmp" | "ico" | "tiff" => {
            return DownloadCategory::Images
        }
        "mp3" | "flac" | "ogg" | "opus" | "wav" | "aac" | "m4a" => return DownloadCategory::Audio,
        "mp4" | "mkv" | "webm" | "mov" | "avi" | "m4v" => return DownloadCategory::Video,
        "zip" | "tar" | "tar.gz" | "tgz" | "tar.xz" | "tar.bz2" | "tar.zst" | "tar.lz4"
        | "tar.lz" | "tar.br" | "gz" | "xz" | "bz2" | "zst" | "7z" | "rar" => {
            return DownloadCategory::Archives
        }
        "exe" | "msi" | "appimage" | "deb" | "rpm" | "dmg" | "pkg" | "apk" | "bat" | "cmd"
        | "sh" | "ps1" => return DownloadCategory::Executables,
        "rs" | "py" | "js" | "ts" | "d.ts" | "user.js" | "c" | "cpp" | "h" | "hpp" | "go"
        | "java" | "json" | "toml" | "yaml" | "yml" | "html" | "css" | "sql" => {
            return DownloadCategory::Code
        }
        _ => {}
    }

    if let Some(mime) = mime_type {
        let lower = mime.to_ascii_lowercase();
        if lower.starts_with("image/") {
            return DownloadCategory::Images;
        }
        if lower.starts_with("audio/") {
            return DownloadCategory::Audio;
        }
        if lower.starts_with("video/") {
            return DownloadCategory::Video;
        }
        if lower.contains("pdf") || lower.starts_with("text/plain") {
            return DownloadCategory::Documents;
        }
        if lower.contains("zip") || lower.contains("gzip") || lower.contains("tar") {
            return DownloadCategory::Archives;
        }
    }
    DownloadCategory::Other
}

fn is_bidi_spoofing_char(ch: char) -> bool {
    matches!(
        ch as u32,
        0x200E | 0x200F | 0x202A..=0x202E | 0x2066..=0x2069
    )
}

/// Comprehensive download security analyzer detecting:
/// - Local [`ThreatGuard`] phishing/malware matches
/// - Unicode bidirectional spoofing (including RLO `U+202E`)
/// - Mixed-content insecure downloads (`https://` page triggering `http://` download)
/// - Double-extension masquerading (e.g. `invoice.pdf.exe`, `photo.jpg.scr`)
/// - Potentially dangerous executable / script file extensions
pub fn classify_download_danger(
    filename: &str,
    download_url: &str,
    referring_page_url: Option<&str>,
    threat_guard: Option<&ThreatGuard>,
) -> DownloadDangerLevel {
    // 1. ThreatGuard URL check
    if let Some(guard) = threat_guard {
        match guard.evaluate_url(download_url) {
            ThreatVerdict::Safe => {}
            ThreatVerdict::Malware { matched_rule, source } => {
                return DownloadDangerLevel::Malicious {
                    reason: format!("Matched {} malware signature '{}'", source, matched_rule),
                };
            }
            ThreatVerdict::Phishing { matched_rule, source } => {
                return DownloadDangerLevel::Malicious {
                    reason: format!("Matched {} phishing signature '{}'", source, matched_rule),
                };
            }
            ThreatVerdict::IdnHomograph { suspicious_host, .. } => {
                return DownloadDangerLevel::Malicious {
                    reason: format!("IDN homograph download host '{}'", suspicious_host),
                };
            }
            ThreatVerdict::Typosquat {
                impersonated_domain,
                ..
            } => {
                return DownloadDangerLevel::Uncommon {
                    reason: format!("Download originates from typosquat of '{}'", impersonated_domain),
                };
            }
        }
    }

    // 2. Unicode RLO (U+202E) / bidi override spoofing check
    for ch in filename.chars() {
        if is_bidi_spoofing_char(ch) {
            return DownloadDangerLevel::DangerousUnicodeSpoofing {
                codepoint: format!("U+{:04X}", ch as u32),
            };
        }
    }

    // 3. Mixed-content download check (HTTPS page -> cleartext HTTP download)
    if let Some(page) = referring_page_url {
        let page_l = page.trim().to_ascii_lowercase();
        let dl_l = download_url.trim().to_ascii_lowercase();
        if page_l.starts_with("https://") && dl_l.starts_with("http://") {
            return DownloadDangerLevel::MixedContentDownload {
                page_url: page.to_string(),
                download_url: download_url.to_string(),
            };
        }
    }

    // 4. Double-extension masquerading check (e.g. `report.pdf.exe`, `photo.jpg.vbs`)
    let trimmed_name = filename.trim().trim_end_matches('.');
    let lower_name = trimmed_name.to_ascii_lowercase();
    let parts: Vec<&str> = lower_name.split('.').filter(|p| !p.is_empty()).collect();
    if parts.len() >= 3 {
        let final_ext = parts[parts.len() - 1];
        let prev_ext = parts[parts.len() - 2];
        if DANGEROUS_EXECUTABLE_EXTENSIONS.contains(&final_ext)
            && BENIGN_DECOY_EXTENSIONS.contains(&prev_ext)
        {
            return DownloadDangerLevel::DangerousDoubleExtension {
                filename: filename.to_string(),
            };
        }
    }

    // 5. Potentially dangerous executable extension check
    if let Some(final_ext) = parts.last().filter(|_| parts.len() >= 2) {
        if DANGEROUS_EXECUTABLE_EXTENSIONS.contains(final_ext) {
            return DownloadDangerLevel::PotentiallyDangerousExecutable {
                extension: (*final_ext).to_string(),
            };
        }
    }

    DownloadDangerLevel::Safe
}

/// Plans contiguous, non-overlapping HTTP `Range` segments covering `0..total_bytes`
/// for parallel multi-connection download acceleration.
pub fn plan_parallel_segments(
    total_bytes: u64,
    max_segments: usize,
    min_segment_bytes: u64,
    supports_range: bool,
) -> Vec<DownloadSegmentPlan> {
    if total_bytes == 0 {
        return Vec::new();
    }
    let min_seg = min_segment_bytes.max(1);
    if !supports_range || max_segments <= 1 || total_bytes < min_seg.saturating_mul(2) {
        return vec![DownloadSegmentPlan {
            index: 0,
            start_byte: 0,
            end_byte: total_bytes - 1,
            range_header: format!("bytes=0-{}", total_bytes - 1),
        }];
    }

    let max_by_size = (total_bytes / min_seg) as usize;
    let segment_count = max_segments.min(max_by_size).max(1);
    let base_chunk = total_bytes / (segment_count as u64);
    let remainder = total_bytes % (segment_count as u64);

    let mut plans = Vec::with_capacity(segment_count);
    let mut cursor = 0u64;
    for idx in 0..segment_count {
        let extra = u64::from((idx as u64) < remainder);
        let len = base_chunk + extra;
        let end = cursor + len - 1;
        plans.push(DownloadSegmentPlan {
            index: idx,
            start_byte: cursor,
            end_byte: end,
            range_header: format!("bytes={}-{}", cursor, end),
        });
        cursor = end + 1;
    }
    plans
}

/// Constant-time byte-slice equality preventing timing side-channel leaks.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Computes the lowercase SHA-256 hex digest of a file on disk using streaming 64 KiB reads.
pub fn sha256_file_hex(path: &Path) -> Result<String, String> {
    let bytes = sha256_file_bytes(path)?;
    Ok(bytes.iter().map(|b| format!("{:02x}", b)).collect())
}

fn sha256_file_bytes(path: &Path) -> Result<[u8; 32], String> {
    let mut file =
        File::open(path).map_err(|e| format!("Failed to open '{}' for SHA-256: {}", path.display(), e))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65_536];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| format!("Failed reading '{}' for SHA-256: {}", path.display(), e))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
}

fn decode_sha256_hex(hex_str: &str) -> Result<[u8; 32], String> {
    let clean = hex_str.trim();
    if clean.len() != 64 {
        return Err(format!(
            "Expected 64-character SHA-256 hex digest, got {} characters",
            clean.len()
        ));
    }
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        let byte = u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16)
            .map_err(|_| "Malformed hex character in expected SHA-256 digest".to_string())?;
        *slot = byte;
    }
    Ok(out)
}

/// Cryptographically verifies a downloaded file against `expected_hex` using constant-time comparison.
pub fn verify_file_sha256(path: &Path, expected_hex: &str) -> Result<bool, String> {
    let expected = decode_sha256_hex(expected_hex)?;
    let actual = sha256_file_bytes(path)?;
    Ok(constant_time_eq(&actual, &expected))
}

/// Formats a standard Mark-of-the-Web `Zone.Identifier` payload (ZoneId=3: Internet Zone).
pub fn format_zone_identifier(source_url: &str, referrer_url: Option<&str>) -> String {
    let clean_src = source_url.replace(['\r', '\n'], "");
    let mut content = format!("[ZoneTransfer]\r\nZoneId=3\r\nHostUrl={}\r\n", clean_src);
    if let Some(ref_url) = referrer_url {
        let clean_ref = ref_url.replace(['\r', '\n'], "");
        if !clean_ref.is_empty() {
            content.push_str(&format!("ReferrerUrl={}\r\n", clean_ref));
        }
    }
    content
}

/// Writes Mark-of-the-Web provenance metadata onto a downloaded file:
/// - Windows: NTFS Alternate Data Stream `<file>:Zone.Identifier`
/// - Linux: `user.xdg.origin.url` (+ `user.xdg.referrer.url`) extended attributes via `setxattr`,
///   falling back gracefully to `<file>.Zone.Identifier` sidecar on filesystems without xattr support.
pub fn write_mark_of_the_web(
    file_path: &Path,
    source_url: &str,
    referrer_url: Option<&str>,
) -> Result<MotwWriteOutcome, String> {
    if !file_path.exists() {
        return Err(format!(
            "Cannot apply MOTW to non-existent file '{}'",
            file_path.display()
        ));
    }

    let zone_payload = format_zone_identifier(source_url, referrer_url);

    #[cfg(target_os = "windows")]
    {
        let ads_path = format!("{}:Zone.Identifier", file_path.display());
        std::fs::write(&ads_path, zone_payload.as_bytes())
            .map_err(|e| format!("Failed writing NTFS Zone.Identifier ADS: {}", e))?;
        return Ok(MotwWriteOutcome::WindowsZoneIdentifierAds(ads_path));
    }

    #[cfg(target_os = "linux")]
    {
        if apply_linux_xdg_origin_xattr(file_path, source_url, referrer_url) {
            return Ok(MotwWriteOutcome::LinuxXattrApplied);
        }
        let sidecar = sidecar_zone_path(file_path);
        std::fs::write(&sidecar, zone_payload.as_bytes())
            .map_err(|e| format!("Failed writing Zone.Identifier sidecar fallback: {}", e))?;
        Ok(MotwWriteOutcome::SidecarZoneIdentifierFallback(
            sidecar.to_string_lossy().into_owned(),
        ))
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        let sidecar = sidecar_zone_path(file_path);
        std::fs::write(&sidecar, zone_payload.as_bytes())
            .map_err(|e| format!("Failed writing Zone.Identifier sidecar: {}", e))?;
        Ok(MotwWriteOutcome::SidecarZoneIdentifierFallback(
            sidecar.to_string_lossy().into_owned(),
        ))
    }
}

#[cfg(not(target_os = "windows"))]
fn sidecar_zone_path(file_path: &Path) -> PathBuf {
    let mut os = file_path.as_os_str().to_os_string();
    os.push(".Zone.Identifier");
    PathBuf::from(os)
}

#[cfg(target_os = "linux")]
fn apply_linux_xdg_origin_xattr(
    file_path: &Path,
    source_url: &str,
    referrer_url: Option<&str>,
) -> bool {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    extern "C" {
        fn setxattr(
            path: *const std::ffi::c_char,
            name: *const std::ffi::c_char,
            value: *const std::ffi::c_void,
            size: usize,
            flags: std::ffi::c_int,
        ) -> std::ffi::c_int;
    }

    let Ok(c_path) = CString::new(file_path.as_os_str().as_bytes()) else {
        return false;
    };
    let Ok(c_attr) = CString::new("user.xdg.origin.url") else {
        return false;
    };
    let clean_src = source_url.replace(['\r', '\n', '\0'], "");
    let rc = unsafe {
        setxattr(
            c_path.as_ptr(),
            c_attr.as_ptr(),
            clean_src.as_ptr() as *const std::ffi::c_void,
            clean_src.len(),
            0,
        )
    };
    if rc != 0 {
        return false;
    }

    if let Some(ref_url) = referrer_url {
        let clean_ref = ref_url.replace(['\r', '\n', '\0'], "");
        if !clean_ref.is_empty() {
            if let Ok(c_ref_attr) = CString::new("user.xdg.referrer.url") {
                let _ = unsafe {
                    setxattr(
                        c_path.as_ptr(),
                        c_ref_attr.as_ptr(),
                        clean_ref.as_ptr() as *const std::ffi::c_void,
                        clean_ref.len(),
                        0,
                    )
                };
            }
        }
    }
    true
}

/// Manages queued and concurrent downloads, routing rules, security classification,
/// smart collision renaming, pause/resume/cancel/retry, and multi-segment Range scheduling.
pub struct DownloadManager {
    default_download_dir: String,
    max_concurrent: usize,
    max_segments_per_download: usize,
    min_segment_bytes: u64,
    collision_policy: CollisionPolicy,
    routing_rules: Vec<DownloadRoutingRule>,
    records: Vec<DownloadRecord>,
    next_id: u64,
}

impl Default for DownloadManager {
    fn default() -> Self {
        Self::new("./Downloads", 4)
    }
}

impl DownloadManager {
    pub fn new(default_download_dir: impl Into<String>, max_concurrent: usize) -> Self {
        Self {
            default_download_dir: default_download_dir.into(),
            max_concurrent: max_concurrent.max(1),
            max_segments_per_download: 8,
            min_segment_bytes: 1024 * 1024, // 1 MiB minimum segment size
            collision_policy: CollisionPolicy::AutoRename,
            routing_rules: Vec::new(),
            records: Vec::new(),
            next_id: 1,
        }
    }

    pub fn set_max_concurrent(&mut self, max_concurrent: usize) {
        self.max_concurrent = max_concurrent.max(1);
        self.promote_queued_downloads(0);
    }

    pub fn max_concurrent(&self) -> usize {
        self.max_concurrent
    }

    pub fn set_collision_policy(&mut self, policy: CollisionPolicy) {
        self.collision_policy = policy;
    }

    pub fn collision_policy(&self) -> CollisionPolicy {
        self.collision_policy
    }

    pub fn add_routing_rule(&mut self, rule: DownloadRoutingRule) {
        if let Some(pos) = self.routing_rules.iter().position(|r| r.id == rule.id) {
            self.routing_rules[pos] = rule;
        } else {
            self.routing_rules.push(rule);
        }
    }

    pub fn routing_rules(&self) -> &[DownloadRoutingRule] {
        &self.routing_rules
    }

    /// Enqueues a new download, classifying danger level, applying routing & filename templates,
    /// resolving filename collisions, planning HTTP `Range` segments, and starting immediately
    /// if an active concurrency slot is free.
    #[allow(clippy::too_many_arguments)]
    pub fn enqueue_download(
        &mut self,
        url: &str,
        raw_filename: &str,
        referring_page_url: Option<&str>,
        mime_type: Option<&str>,
        total_bytes: Option<u64>,
        supports_range: bool,
        threat_guard: Option<&ThreatGuard>,
        now_unix: u64,
    ) -> u64 {
        let id = self.next_id;
        self.next_id += 1;

        let danger_level =
            classify_download_danger(raw_filename, url, referring_page_url, threat_guard);
        let safe_raw_name = sanitize_filename_component(raw_filename);
        let category = classify_category(&safe_raw_name, mime_type);
        let (_, ext_with_dot) = split_compound_filename(&safe_raw_name);
        let ext = ext_with_dot.trim_start_matches('.');
        let source_host = normalize_host(url);

        let matched_rule = self
            .routing_rules
            .iter()
            .find(|r| r.matches(category, ext, &source_host));

        let target_dir = matched_rule
            .map(|r| r.target_dir.clone())
            .unwrap_or_else(|| self.default_download_dir.clone());

        let templated_name = matched_rule
            .and_then(|r| r.filename_template.as_deref())
            .map(|tpl| {
                let date_ymd = format_unix_date_ymd(now_unix);
                render_filename_template(tpl, &safe_raw_name, &source_host, &date_ymd, category)
            })
            .unwrap_or(safe_raw_name);

        let existing_in_dir: Vec<String> = self
            .records
            .iter()
            .filter(|r| {
                Path::new(&r.destination_path)
                    .parent()
                    .is_some_and(|p| p == Path::new(&target_dir))
            })
            .map(|r| r.filename.clone())
            .collect();

        let final_filename =
            resolve_collision_filename(&templated_name, &existing_in_dir, self.collision_policy)
                .unwrap_or_else(|| templated_name.clone());

        let dest_path = Path::new(&target_dir)
            .join(&final_filename)
            .to_string_lossy()
            .into_owned();

        let segments = total_bytes
            .map(|size| {
                plan_parallel_segments(
                    size,
                    self.max_segments_per_download,
                    self.min_segment_bytes,
                    supports_range,
                )
            })
            .unwrap_or_default();

        let initial_state = if danger_level.should_auto_block() {
            DownloadState::BlockedDanger {
                reason: format!("{:?}", danger_level),
            }
        } else if self.active_count() < self.max_concurrent {
            DownloadState::InProgress
        } else {
            DownloadState::Queued
        };

        self.records.push(DownloadRecord {
            id,
            url: url.to_string(),
            referring_page_url: referring_page_url.map(str::to_string),
            filename: final_filename,
            destination_path: dest_path,
            mime_type: mime_type.map(str::to_string),
            category,
            danger_level,
            state: initial_state,
            total_bytes,
            received_bytes: 0,
            expected_sha256: None,
            segments,
            created_at_unix: now_unix,
            updated_at_unix: now_unix,
            retry_count: 0,
        });
        id
    }

    pub fn set_expected_sha256(&mut self, id: u64, sha256_hex: impl Into<String>) -> bool {
        if let Some(rec) = self.records.iter_mut().find(|r| r.id == id) {
            rec.expected_sha256 = Some(sha256_hex.into());
            true
        } else {
            false
        }
    }

    pub fn pause(&mut self, id: u64, now_unix: u64) -> bool {
        let Some(rec) = self.records.iter_mut().find(|r| r.id == id) else {
            return false;
        };
        if !matches!(rec.state, DownloadState::InProgress | DownloadState::Queued) {
            return false;
        }
        rec.state = DownloadState::Paused;
        rec.updated_at_unix = now_unix;
        self.promote_queued_downloads(now_unix);
        true
    }

    pub fn resume(&mut self, id: u64, now_unix: u64) -> bool {
        let can_start = self.active_count() < self.max_concurrent;
        let Some(rec) = self.records.iter_mut().find(|r| r.id == id) else {
            return false;
        };
        if !matches!(rec.state, DownloadState::Paused) {
            return false;
        }
        rec.state = if can_start {
            DownloadState::InProgress
        } else {
            DownloadState::Queued
        };
        rec.updated_at_unix = now_unix;
        true
    }

    pub fn cancel(&mut self, id: u64, now_unix: u64) -> bool {
        let Some(rec) = self.records.iter_mut().find(|r| r.id == id) else {
            return false;
        };
        if matches!(rec.state, DownloadState::Completed | DownloadState::Canceled) {
            return false;
        }
        rec.state = DownloadState::Canceled;
        rec.updated_at_unix = now_unix;
        self.promote_queued_downloads(now_unix);
        true
    }

    pub fn retry(&mut self, id: u64, now_unix: u64) -> bool {
        let can_start = self.active_count() < self.max_concurrent;
        let Some(rec) = self.records.iter_mut().find(|r| r.id == id) else {
            return false;
        };
        if !matches!(
            rec.state,
            DownloadState::Failed { .. } | DownloadState::Canceled
        ) {
            return false;
        }
        rec.retry_count = rec.retry_count.saturating_add(1);
        rec.state = if can_start {
            DownloadState::InProgress
        } else {
            DownloadState::Queued
        };
        rec.updated_at_unix = now_unix;
        true
    }

    pub fn update_progress(
        &mut self,
        id: u64,
        received_bytes: u64,
        total_bytes: Option<u64>,
        now_unix: u64,
    ) -> bool {
        let Some(rec) = self.records.iter_mut().find(|r| r.id == id) else {
            return false;
        };
        rec.received_bytes = received_bytes;
        if let Some(total) = total_bytes {
            rec.total_bytes = Some(total);
        }
        rec.updated_at_unix = now_unix;
        true
    }

    pub fn mark_completed(&mut self, id: u64, now_unix: u64) -> bool {
        let Some(rec) = self.records.iter_mut().find(|r| r.id == id) else {
            return false;
        };
        rec.state = DownloadState::Completed;
        if let Some(total) = rec.total_bytes {
            rec.received_bytes = total;
        }
        rec.updated_at_unix = now_unix;
        self.promote_queued_downloads(now_unix);
        true
    }

    pub fn mark_failed(&mut self, id: u64, reason: impl Into<String>, now_unix: u64) -> bool {
        let Some(rec) = self.records.iter_mut().find(|r| r.id == id) else {
            return false;
        };
        rec.state = DownloadState::Failed {
            reason: reason.into(),
        };
        rec.updated_at_unix = now_unix;
        self.promote_queued_downloads(now_unix);
        true
    }

    fn promote_queued_downloads(&mut self, now_unix: u64) {
        let mut active = self.active_count();
        for rec in &mut self.records {
            if active >= self.max_concurrent {
                break;
            }
            if rec.state == DownloadState::Queued {
                rec.state = DownloadState::InProgress;
                if now_unix > 0 {
                    rec.updated_at_unix = now_unix;
                }
                active += 1;
            }
        }
    }

    pub fn active_count(&self) -> usize {
        self.records
            .iter()
            .filter(|r| r.state == DownloadState::InProgress)
            .count()
    }

    pub fn queued_count(&self) -> usize {
        self.records
            .iter()
            .filter(|r| r.state == DownloadState::Queued)
            .count()
    }

    pub fn get(&self, id: u64) -> Option<&DownloadRecord> {
        self.records.iter().find(|r| r.id == id)
    }

    pub fn records(&self) -> &[DownloadRecord] {
        &self.records
    }
}

/// Converts Unix seconds into `YYYY-MM-DD` (Howard Hinnant civil-from-days algorithm, zero deps).
fn format_unix_date_ymd(unix_sec: u64) -> String {
    let z = (unix_sec / 86_400) as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = y + i64::from(m <= 2);
    format!("{:04}-{:02}-{:02}", year, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_download_queue_concurrency_pause_resume_cancel_retry_and_routing() {
        let mut mgr = DownloadManager::new("/tmp/singularity-dl", 2);
        mgr.add_routing_rule(DownloadRoutingRule {
            id: "archives".into(),
            category: Some(DownloadCategory::Archives),
            extension_glob: None,
            source_domain_glob: Some("*.github.com".into()),
            target_dir: "/tmp/singularity-dl/archives".into(),
            filename_template: Some("{date}_{domain}_{stem}{ext}".into()),
            enabled: true,
        });

        let guard = ThreatGuard::default();
        let d1 = mgr.enqueue_download(
            "https://releases.github.com/app/singularity.tar.gz",
            "singularity.tar.gz",
            Some("https://github.com/MyMasha/Singularity"),
            Some("application/gzip"),
            Some(10 * 1024 * 1024),
            true,
            Some(&guard),
            1_700_000_000,
        );
        let d2 = mgr.enqueue_download(
            "https://releases.github.com/app/singularity.tar.gz",
            "singularity.tar.gz",
            Some("https://github.com/MyMasha/Singularity"),
            Some("application/gzip"),
            Some(5 * 1024 * 1024),
            true,
            Some(&guard),
            1_700_000_000,
        );
        let d3 = mgr.enqueue_download(
            "https://example.org/manual.pdf",
            "manual.pdf",
            Some("https://example.org/docs"),
            Some("application/pdf"),
            Some(2 * 1024 * 1024),
            false,
            Some(&guard),
            1_700_000_005,
        );

        assert_eq!(mgr.active_count(), 2);
        assert_eq!(mgr.queued_count(), 1);
        assert_eq!(mgr.get(d1).unwrap().state, DownloadState::InProgress);
        assert_eq!(mgr.get(d2).unwrap().state, DownloadState::InProgress);
        assert_eq!(mgr.get(d3).unwrap().state, DownloadState::Queued);

        // Smart compound renaming + routing template preserved `.tar.gz` cleanly
        assert_eq!(
            mgr.get(d1).unwrap().filename,
            "2023-11-14_releases.github.com_singularity.tar.gz"
        );
        assert_eq!(
            mgr.get(d2).unwrap().filename,
            "2023-11-14_releases.github.com_singularity (1).tar.gz"
        );
        assert_eq!(mgr.get(d1).unwrap().segments.len(), 8);

        // Pausing d1 immediately promotes queued d3
        assert!(mgr.pause(d1, 1_700_000_010));
        assert_eq!(mgr.get(d1).unwrap().state, DownloadState::Paused);
        assert_eq!(mgr.get(d3).unwrap().state, DownloadState::InProgress);

        // Resuming d1 queues it since 2 slots are full; canceling d2 promotes d1
        assert!(mgr.resume(d1, 1_700_000_011));
        assert_eq!(mgr.get(d1).unwrap().state, DownloadState::Queued);
        assert!(mgr.cancel(d2, 1_700_000_012));
        assert_eq!(mgr.get(d1).unwrap().state, DownloadState::InProgress);

        // Fail & retry
        assert!(mgr.mark_failed(d3, "connection reset", 1_700_000_020));
        assert!(mgr.retry(d3, 1_700_000_025));
        assert_eq!(mgr.get(d3).unwrap().retry_count, 1);
        assert_eq!(mgr.get(d3).unwrap().state, DownloadState::InProgress);
    }

    #[test]
    fn test_danger_classifier_segments_sha256_and_motw() {
        let guard = ThreatGuard::default();

        // Double extension
        assert!(matches!(
            classify_download_danger("invoice.pdf.exe", "https://example.org/a", None, Some(&guard)),
            DownloadDangerLevel::DangerousDoubleExtension { .. }
        ));
        // Unicode RLO U+202E spoofing (`report_gpj.exe` rendered as `report_exe.jpg`)
        assert!(matches!(
            classify_download_danger(
                "report_\u{202E}gpj.exe",
                "https://example.org/b",
                None,
                Some(&guard)
            ),
            DownloadDangerLevel::DangerousUnicodeSpoofing { codepoint } if codepoint == "U+202E"
        ));
        // Mixed content download
        assert!(matches!(
            classify_download_danger(
                "archive.tar.xz",
                "http://cdn.example.org/archive.tar.xz",
                Some("https://example.org/download"),
                Some(&guard)
            ),
            DownloadDangerLevel::MixedContentDownload { .. }
        ));
        // ThreatGuard malware match
        assert!(matches!(
            classify_download_danger(
                "setup.bin",
                "https://malware.testing.google.test/setup.bin",
                None,
                Some(&guard)
            ),
            DownloadDangerLevel::Malicious { .. }
        ));

        // Parallel Range segments cover every byte contiguously with zero gaps
        let segs = plan_parallel_segments(10_000_003, 4, 1_000_000, true);
        assert_eq!(segs.len(), 4);
        assert_eq!(segs[0].start_byte, 0);
        assert_eq!(segs.last().unwrap().end_byte, 10_000_002);
        let covered: u64 = segs.iter().map(DownloadSegmentPlan::byte_len).sum();
        assert_eq!(covered, 10_000_003);
        for pair in segs.windows(2) {
            assert_eq!(pair[0].end_byte + 1, pair[1].start_byte);
        }

        // Streaming constant-time SHA-256 verification + MOTW writing
        let tmp_file = std::env::temp_dir().join(format!(
            "singularity_dl_verify_{}.tar.xz",
            std::process::id()
        ));
        std::fs::write(&tmp_file, b"Singularity verified download payload").unwrap();
        let hex_digest = sha256_file_hex(&tmp_file).expect("sha256");
        assert!(verify_file_sha256(&tmp_file, &hex_digest).expect("verify true"));
        let wrong = "0".repeat(64);
        assert!(!verify_file_sha256(&tmp_file, &wrong).expect("verify false"));

        let motw = write_mark_of_the_web(
            &tmp_file,
            "https://example.org/release.tar.xz",
            Some("https://example.org/releases"),
        )
        .expect("MOTW write");
        if let MotwWriteOutcome::SidecarZoneIdentifierFallback(ref sidecar) = motw {
            let text = std::fs::read_to_string(sidecar).unwrap();
            assert!(text.contains("ZoneId=3"));
            assert!(text.contains("HostUrl=https://example.org/release.tar.xz"));
            let _ = std::fs::remove_file(sidecar);
        }
        let _ = std::fs::remove_file(&tmp_file);
    }
}
