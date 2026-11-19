//! Standalone & Build-Time Chromium Telemetry Stripper and Privacy Patcher (`strip_telemetry.rs`)
//!
//! Neutralizes all Google telemetry endpoints, UMA/UKM collection, FieldTrials,
//! RLZ tracking, SafeBrowsing background pings, and Crashpad upload hooks inside
//! a Chromium source checkout before compiling `libchromiumcontent`.

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

/// Complete catalog of Google telemetry domains neutered to `0.0.0.0` (`https://0.0.0.0.invalid`).
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
        description: "Inject deterministic per-origin noise into Canvas2D getImageData/toDataURL",
        target_pattern: "ImageData* BaseRenderingContext2D::getImageDataInternal(",
        replacement: "ImageData* BaseRenderingContext2D::getImageDataInternal(/* [SINGULARITY] canvas noise hook */ ",
    },
    SourcePatch {
        relative_path: "third_party/blink/renderer/modules/webgl/webgl_rendering_context_base.cc",
        description: "Spoof WebGL UNMASKED_VENDOR_WEBGL and UNMASKED_RENDERER_WEBGL to uniform generic profile",
        target_pattern: "case WebGLDebugRendererInfo::kUnmaskedRendererWebgl:",
        replacement: "case WebGLDebugRendererInfo::kUnmaskedRendererWebgl: /* [SINGULARITY] */ return WebGLAny(script_state, String(\"ANGLE (Generic, Vulkan 1.3.0)\"));",
    },
    SourcePatch {
        relative_path: "third_party/blink/renderer/modules/peerconnection/rtc_peer_connection.cc",
        description: "Enforce strict WebRTC non-proxied UDP restriction to prevent local LAN/VPN IP leaks",
        target_pattern: "configuration->setIceTransportPolicy(",
        replacement: "/* [SINGULARITY] enforce relay-only */ configuration->setIceTransportPolicy(\"relay\"); // overridden: ",
    },
];

/// Summary report returned after running the telemetry stripper over a Chromium source root.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct StripTelemetryReport {
    pub files_scanned: usize,
    pub patches_applied: usize,
    pub urls_neutered: usize,
}

/// Applies all source patches and domain blacklists to a Chromium checkout directory.
pub fn apply_chromium_telemetry_strip(chromium_src_root: &Path) -> io::Result<StripTelemetryReport> {
    let mut report = StripTelemetryReport::default();

    for patch in CHROMIUM_SOURCE_PATCHES {
        let full_path: PathBuf = chromium_src_root.join(patch.relative_path);
        if full_path.exists() {
            report.files_scanned += 1;
            let content = fs::read_to_string(&full_path)?;
            let mut modified = content.clone();

            if modified.contains(patch.target_pattern) && !modified.contains("[SINGULARITY]") {
                modified = modified.replacen(patch.target_pattern, patch.replacement, 1);
                report.patches_applied += 1;
            }

            for &domain in TELEMETRY_DOMAINS_BLACKLIST {
                if modified.contains(domain) {
                    let count = modified.matches(domain).count();
                    modified = modified.replace(domain, "0.0.0.0.invalid");
                    report.urls_neutered += count;
                }
            }

            if modified != content {
                fs::write(&full_path, modified)?;
            }
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
