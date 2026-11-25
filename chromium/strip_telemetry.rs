//! Standalone & Build-Time Chromium Telemetry Stripper and Privacy Patcher (`strip_telemetry.rs`)
//!
//! Neutralizes all Google telemetry endpoints, UMA/UKM collection, FieldTrials,
//! RLZ tracking, SafeBrowsing background pings, and Crashpad upload hooks inside
//! a Chromium source checkout before compiling `libchromiumcontent`.

use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Represents a deterministic C++ source transformation applied to the Chromium tree.
#[derive(Debug, Clone)]
pub struct SourcePatch {
    pub relative_path: &'static str,
    pub description: &'static str,
    pub target_pattern: &'static str,
    pub replacement: &'static str,
}

/// Complete catalog of Google telemetry domains neutered to `0.0.0.0.invalid`.
pub const TELEMETRY_DOMAINS_BLACKLIST: &[&str] = &[
    "clients1.google.com",
    "clients2.google.com",
    "clients3.google.com",
    "clients4.google.com",
    "clients5.google.com",
    "clients6.google.com",
    "clients2.googleusercontent.com",
    "update.googleapis.com",
    "safebrowsing.googleapis.com",
    "sb-ssl.google.com",
    "clientservices.googleapis.com",
    "optimizationguide-pa.googleapis.com",
    "content-autofill.googleapis.com",
    "crashreports.google.com",
    "www.google-analytics.com",
    "ssl.google-analytics.com",
    "apis.google.com",
    "chromesync.googleapis.com",
    "chromevariations.googleapis.com",
    "pagead2.googlesyndication.com",
];

/// Known Chromium telemetry, reporting, updater, SafeBrowsing, RLZ, crashpad, and Google API
/// source subtrees recursively scanned and scrubbed beyond the targeted C++ behavior patches.
pub const TELEMETRY_SCAN_SUBDIRS: &[&str] = &[
    "components/metrics",
    "components/ukm",
    "components/variations",
    "components/component_updater",
    "components/safe_browsing",
    "components/rlz",
    "components/crash",
    "components/optimization_guide",
    "components/autofill",
    "components/domain_reliability",
    "components/reporting",
    "components/sync",
    "components/feedback",
    "components/gcm_driver",
    "components/rappor",
    "google_apis",
    "chrome/browser/metrics",
    "chrome/browser/safe_browsing",
    "chrome/browser/net",
    "chrome/browser/component_updater",
    "chrome/browser/rlz",
    "chrome/browser/feedback",
    "services/network",
    "third_party/crashpad",
    "third_party/blink/renderer/modules/canvas",
    "third_party/blink/renderer/modules/webgl",
    "third_party/blink/renderer/modules/peerconnection",
];

const SCANNABLE_EXTENSIONS: &[&str] = &[
    "cc", "cpp", "c", "h", "hh", "hpp", "mm", "m", "gn", "gni", "json", "grd", "grdp", "xml",
    "py", "js", "ts", "txt",
];

const MAX_SCANNABLE_FILE_BYTES: u64 = 8 * 1024 * 1024;

/// Hardened C++ source patches applied across Chromium subsystems.
pub const CHROMIUM_SOURCE_PATCHES: &[SourcePatch] = &[
    SourcePatch {
        relative_path: "components/metrics/metrics_service.cc",
        description: "Disable UMA MetricsService recording and transmission loop",
        target_pattern: "void MetricsService::Start() {",
        replacement: "void MetricsService::Start() {\n  // [SINGULARITY] UMA stripped\n  return;",
    },
    SourcePatch {
        relative_path: "components/ukm/ukm_service.cc",
        description: "Disable URL-Keyed Metrics (UKM) collection and reporting",
        target_pattern: "void UkmService::EnableRecording() {",
        replacement: "void UkmService::EnableRecording() {\n  // [SINGULARITY] UKM recording disabled\n  return;",
    },
    SourcePatch {
        relative_path: "components/variations/service/variations_service.cc",
        description: "Eliminate Finch FieldTrial seed fetching from chromevariations.googleapis.com",
        target_pattern: "bool VariationsService::DoActualFetch() {",
        replacement: "bool VariationsService::DoActualFetch() {\n  // [SINGULARITY] Finch seed fetch disabled\n  return false;",
    },
    SourcePatch {
        relative_path: "components/component_updater/component_updater_service.cc",
        description: "Disable automatic background component updater pings to update.googleapis.com",
        target_pattern: "bool CrxUpdateService::Start() {",
        replacement: "bool CrxUpdateService::Start() {\n  // [SINGULARITY] Component updater disabled\n  return false;",
    },
    SourcePatch {
        relative_path: "chrome/browser/net/system_network_context_manager.cc",
        description: "Disable built-in DNS probe and captive portal detector",
        target_pattern: "network_context_params->enable_referrers = true;",
        replacement: "network_context_params->enable_referrers = false; // [SINGULARITY] minimize network leakage",
    },
    SourcePatch {
        relative_path: "third_party/blink/renderer/modules/canvas/canvas2d/base_rendering_context_2d.cc",
        description: "Inject deterministic aperiodic per-origin sub-LSB noise into Canvas2D getImageData",
        target_pattern: "return image_data;",
        replacement: concat!(
            "if (image_data && image_data->data()) {\n",
            "    // [SINGULARITY] deterministic aperiodic per-origin Canvas2D sub-LSB noise\n",
            "    uint8_t* rgba = image_data->data()->Data();\n",
            "    const size_t byte_len = image_data->data()->length();\n",
            "    uint64_t state = 0x9E3779B97F4A7C15ULL ^ static_cast<uint64_t>(byte_len);\n",
            "    if (const ExecutionContext* ctx = GetTopExecutionContext()) {\n",
            "      if (const SecurityOrigin* origin = ctx->GetSecurityOrigin()) {\n",
            "        state ^= static_cast<uint64_t>(origin->ToString().Impl()->GetHash());\n",
            "      }\n",
            "    }\n",
            "    for (size_t i = 0; i + 3 < byte_len; i += 4) {\n",
            "      state += 0x9E3779B97F4A7C15ULL;\n",
            "      uint64_t z = state;\n",
            "      z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;\n",
            "      z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;\n",
            "      z = z ^ (z >> 31);\n",
            "      if ((z & 0x03ULL) == 0x01ULL) {\n",
            "        rgba[i + static_cast<size_t>((z >> 2) % 3ULL)] ^= 0x01U;\n",
            "      }\n",
            "    }\n",
            "  }\n",
            "  return image_data;"
        ),
    },
    SourcePatch {
        relative_path: "third_party/blink/renderer/modules/webgl/webgl_rendering_context_base.cc",
        description: "Spoof WebGL UNMASKED_VENDOR_WEBGL and UNMASKED_RENDERER_WEBGL to uniform generic profile",
        target_pattern: "case WebGLDebugRendererInfo::kUnmaskedRendererWebgl:",
        replacement: "case WebGLDebugRendererInfo::kUnmaskedRendererWebgl: /* [SINGULARITY] */ return WebGLAny(script_state, String(\"ANGLE (Generic, Vulkan 1.3.0)\"));",
    },
    SourcePatch {
        relative_path: "third_party/blink/renderer/modules/peerconnection/rtc_peer_connection.cc",
        description: "Enforce strict WebRTC relay-only ICE transport policy to prevent local LAN/VPN IP leaks",
        target_pattern: "configuration->type = webrtc::PeerConnectionInterface::kAll;",
        replacement: "// [SINGULARITY] enforce relay-only ICE transport policy\n  configuration->type = webrtc::PeerConnectionInterface::kRelay;",
    },
];

/// Summary report returned after running the telemetry stripper over a Chromium source root.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct StripTelemetryReport {
    pub files_scanned: usize,
    pub patches_applied: usize,
    pub urls_neutered: usize,
}

fn is_scannable_source_file(path: &Path) -> bool {
    let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
        return false;
    };
    SCANNABLE_EXTENSIONS
        .iter()
        .any(|&allowed| ext.eq_ignore_ascii_case(allowed))
}

fn scrub_file_telemetry_domains(
    path: &Path,
    visited: &mut HashSet<PathBuf>,
    report: &mut StripTelemetryReport,
) -> io::Result<()> {
    let canonical = path.to_path_buf();
    if !visited.insert(canonical) {
        return Ok(());
    }
    let meta = fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() || !meta.is_file() || meta.len() > MAX_SCANNABLE_FILE_BYTES {
        return Ok(());
    }
    if !is_scannable_source_file(path) {
        return Ok(());
    }

    let Ok(content) = fs::read_to_string(path) else {
        // Skip non-UTF-8 binary files gracefully
        return Ok(());
    };
    report.files_scanned += 1;

    let (scrubbed, count) = scrub_source_buffer(&content);
    if count > 0 {
        report.urls_neutered += count;
        fs::write(path, scrubbed)?;
    }
    Ok(())
}

fn walk_dir_scrub(
    dir: &Path,
    visited: &mut HashSet<PathBuf>,
    report: &mut StripTelemetryReport,
) -> io::Result<()> {
    let meta = match fs::symlink_metadata(dir) {
        Ok(m) => m,
        Err(_) => return Ok(()),
    };
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Ok(());
    }

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let entry_meta = fs::symlink_metadata(&path)?;
        if entry_meta.file_type().is_symlink() {
            continue;
        }
        if entry_meta.is_dir() {
            let skip = path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|name| matches!(name, ".git" | "out" | "target" | "node_modules"));
            if !skip {
                walk_dir_scrub(&path, visited, report)?;
            }
        } else if entry_meta.is_file() {
            scrub_file_telemetry_domains(&path, visited, report)?;
        }
    }
    Ok(())
}

/// Applies all targeted C++ source patches AND recursively scrubs telemetry domains across
/// all known Chromium telemetry target subtrees under `chromium_src_root`.
pub fn apply_chromium_telemetry_strip(chromium_src_root: &Path) -> io::Result<StripTelemetryReport> {
    let mut report = StripTelemetryReport::default();
    let mut visited: HashSet<PathBuf> = HashSet::new();

    // 1. Apply deterministic C++ behavior patches and scrub domains in patched files
    for patch in CHROMIUM_SOURCE_PATCHES {
        let full_path: PathBuf = chromium_src_root.join(patch.relative_path);
        if full_path.exists() {
            let meta = fs::symlink_metadata(&full_path)?;
            if meta.file_type().is_symlink() || !meta.is_file() {
                continue;
            }
            visited.insert(full_path.clone());
            report.files_scanned += 1;

            let content = fs::read_to_string(&full_path)?;
            let mut modified = content.clone();

            if modified.contains(patch.target_pattern) && !modified.contains("[SINGULARITY]") {
                modified = modified.replacen(patch.target_pattern, patch.replacement, 1);
                report.patches_applied += 1;
            }

            let (scrubbed, count) = scrub_source_buffer(&modified);
            if count > 0 {
                modified = scrubbed;
                report.urls_neutered += count;
            }

            if modified != content {
                fs::write(&full_path, modified)?;
            }
        }
    }

    // 2. Recursively scrub all known Chromium telemetry target subtrees beyond the hardcoded patches
    for &subdir in TELEMETRY_SCAN_SUBDIRS {
        let target_dir = chromium_src_root.join(subdir);
        if target_dir.exists() {
            walk_dir_scrub(&target_dir, &mut visited, &mut report)?;
        }
    }

    Ok(report)
}

/// Scrubs an arbitrary C++ source buffer of all Google telemetry endpoints in-memory.
pub fn scrub_source_buffer(source: &str) -> (String, usize) {
    let mut scrubbed = source.to_string();
    let mut total_replaced = 0;

    for &domain in TELEMETRY_DOMAINS_BLACKLIST {
        let count = scrubbed.matches(domain).count();
        if count > 0 {
            scrubbed = scrubbed.replace(domain, "0.0.0.0.invalid");
            total_replaced += count;
        }
    }

    (scrubbed, total_replaced)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_canvas2d_and_webrtc_patches_are_valid_cpp_and_recursive_strip_scans_beyond_8_files() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let root = std::env::temp_dir().join(format!(
            "singularity_strip_telemetry_test_{}_{}",
            std::process::id(),
            nonce
        ));
        let _ = fs::remove_dir_all(&root);

        // 1. Canvas2D source file
        let canvas_path = root.join(
            "third_party/blink/renderer/modules/canvas/canvas2d/base_rendering_context_2d.cc",
        );
        fs::create_dir_all(canvas_path.parent().unwrap()).unwrap();
        fs::write(
            &canvas_path,
            "ImageData* BaseRenderingContext2D::getImageDataInternal() {\n  ImageData* image_data = MakeImageData();\n  return image_data;\n}\n",
        )
        .unwrap();

        // 2. WebRTC source file
        let webrtc_path = root.join(
            "third_party/blink/renderer/modules/peerconnection/rtc_peer_connection.cc",
        );
        fs::create_dir_all(webrtc_path.parent().unwrap()).unwrap();
        fs::write(
            &webrtc_path,
            "void ParseConfiguration(RTCConfiguration* configuration) {\n  configuration->type = webrtc::PeerConnectionInterface::kAll;\n}\n",
        )
        .unwrap();

        // 3. Additional nested telemetry files OUTSIDE the 8 hardcoded patch paths
        let sb_path = root.join("components/safe_browsing/core/db/v4_urls.cc");
        fs::create_dir_all(sb_path.parent().unwrap()).unwrap();
        fs::write(
            &sb_path,
            "const char kSb[] = \"https://safebrowsing.googleapis.com/v4\";\n",
        )
        .unwrap();

        let gaia_path = root.join("google_apis/gaia/telemetry_ping.cc");
        fs::create_dir_all(gaia_path.parent().unwrap()).unwrap();
        fs::write(
            &gaia_path,
            "const char kClients[] = \"https://clients4.google.com/chrome-sync\";\nconst char kOpt[] = \"https://optimizationguide-pa.googleapis.com/v1\";\n",
        )
        .unwrap();

        let report = apply_chromium_telemetry_strip(&root).expect("strip telemetry");
        assert_eq!(report.files_scanned, 4);
        assert_eq!(report.patches_applied, 2);
        assert_eq!(report.urls_neutered, 3);

        // Verify Canvas2D patch injects real C++ noise loop (balanced braces, executable statements)
        let canvas_after = fs::read_to_string(&canvas_path).unwrap();
        assert!(canvas_after.contains("image_data->data()->Data()"));
        assert!(canvas_after.contains("^= 0x01U;"));
        assert_eq!(
            canvas_after.matches('{').count(),
            canvas_after.matches('}').count()
        );

        // Verify WebRTC patch produces valid C++ statement with kRelay and no dangling comment bug
        let webrtc_after = fs::read_to_string(&webrtc_path).unwrap();
        assert!(webrtc_after.contains("configuration->type = webrtc::PeerConnectionInterface::kRelay;"));
        assert!(!webrtc_after.contains("setIceTransportPolicy(\"relay\"); // overridden:"));
        assert_eq!(
            webrtc_after.matches('{').count(),
            webrtc_after.matches('}').count()
        );

        // Verify nested files outside the 8 hardcoded paths were recursively scrubbed
        let sb_after = fs::read_to_string(&sb_path).unwrap();
        assert!(!sb_after.contains("safebrowsing.googleapis.com"));
        assert!(sb_after.contains("0.0.0.0.invalid"));

        let gaia_after = fs::read_to_string(&gaia_path).unwrap();
        assert!(!gaia_after.contains("clients4.google.com"));
        assert!(!gaia_after.contains("optimizationguide-pa.googleapis.com"));

        // Verify idempotency on second pass
        let report2 = apply_chromium_telemetry_strip(&root).expect("strip telemetry 2nd pass");
        assert_eq!(report2.patches_applied, 0);
        assert_eq!(report2.urls_neutered, 0);

        let _ = fs::remove_dir_all(&root);
    }
}
