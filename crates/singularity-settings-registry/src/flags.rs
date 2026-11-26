//! Experimental feature flags engine powering `browser://flags` and `singularity://flags`.
//!
//! Manages both upstream Chromium Blink/Skia/Net experiment flags and native Singularity Rust
//! subsystem flags, compiling modified flags into `--enable-features`, `--disable-features`,
//! and extra Chromium command-line switches.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

/// Origin runtime that owns and interprets an experimental flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FlagOrigin {
    Chromium,
    SingularityRust,
}

impl FlagOrigin {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Chromium => "Chromium",
            Self::SingularityRust => "Singularity Rust",
        }
    }
}

/// Complete definition and runtime state of an experimental flag shown in `browser://flags`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExperimentFlag {
    pub id: String,
    pub title: String,
    pub description: String,
    pub origin: FlagOrigin,
    pub platforms: Vec<String>,
    pub options: Vec<String>,
    pub default_index: usize,
    pub current_index: usize,
    pub chromium_enable_feature: Option<String>,
    pub chromium_disable_feature: Option<String>,
    pub chromium_switch: Option<String>,
}

impl ExperimentFlag {
    /// Returns `true` when the flag has been changed from its built-in default option.
    pub fn is_modified(&self) -> bool {
        self.current_index != self.default_index
    }

    /// Returns the currently selected option label.
    pub fn current_option(&self) -> &str {
        self.options
            .get(self.current_index)
            .map(String::as_str)
            .unwrap_or("Default")
    }

    /// Returns the default option label.
    pub fn default_option(&self) -> &str {
        self.options
            .get(self.default_index)
            .map(String::as_str)
            .unwrap_or("Default")
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct FlagsTomlSnapshot {
    version: String,
    overrides: BTreeMap<String, usize>,
}

fn is_safe_flag_token(token: &str) -> bool {
    !token.is_empty()
        && !token.starts_with('-')
        && !token.contains("--")
        && token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | ':' | '/' | '.'))
}

fn sanitize_mode_slug(raw: &str) -> Option<String> {
    let inner = raw
        .split_once('(')
        .and_then(|(_, rest)| rest.strip_suffix(')'))
        .map(str::trim)?;
    if inner.is_empty() {
        return None;
    }
    let mut slug = String::with_capacity(inner.len());
    let mut last_dash = false;
    for ch in inner.chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
            last_dash = false;
        } else if !last_dash && !slug.is_empty() {
            slug.push('-');
            last_dash = true;
        }
    }
    while slug.ends_with('-') {
        slug.pop();
    }
    if slug.is_empty() {
        None
    } else {
        Some(slug)
    }
}

fn push_unique(target: &mut Vec<String>, value: String) {
    if !target.contains(&value) {
        target.push(value);
    }
}

/// Persistent in-memory store for `browser://flags` with search, pinning, TOML persistence,
/// restart tracking, and Chromium CLI compilation.
#[derive(Debug, Clone)]
pub struct FlagsStore {
    flags: Vec<ExperimentFlag>,
    id_to_index: HashMap<String, usize>,
    boot_indices: HashMap<String, usize>,
}

impl Default for FlagsStore {
    fn default() -> Self {
        Self::new()
    }
}

impl FlagsStore {
    /// Creates a new `FlagsStore` pre-populated with Chromium and Singularity Rust experiment flags.
    pub fn new() -> Self {
        let flags = build_default_flags_catalog();
        let mut id_to_index = HashMap::with_capacity(flags.len());
        let mut boot_indices = HashMap::with_capacity(flags.len());
        for (idx, flag) in flags.iter().enumerate() {
            id_to_index.insert(flag.id.clone(), idx);
            boot_indices.insert(flag.id.clone(), flag.current_index);
        }
        Self {
            flags,
            id_to_index,
            boot_indices,
        }
    }

    /// Total number of registered experiment flags.
    pub fn len(&self) -> usize {
        self.flags.len()
    }

    /// Returns `true` if no flags are registered.
    pub fn is_empty(&self) -> bool {
        self.flags.is_empty()
    }

    /// Returns all flags in catalog order.
    pub fn all_flags(&self) -> &[ExperimentFlag] {
        &self.flags
    }

    /// Looks up a flag by its unique kebab-case identifier in O(1) time.
    pub fn get(&self, id: &str) -> Option<&ExperimentFlag> {
        let &idx = self.id_to_index.get(id)?;
        self.flags.get(idx)
    }

    /// Returns the number of flags currently differing from their factory default.
    pub fn modified_count(&self) -> usize {
        self.flags.iter().filter(|f| f.is_modified()).count()
    }

    /// Filters flags by optional multi-token search query and `modified_only`,
    /// always pinning modified flags at the top of the result list.
    pub fn list_filtered(&self, query: &str, modified_only: bool) -> Vec<&ExperimentFlag> {
        let q = query.trim().to_ascii_lowercase();
        let tokens: Vec<&str> = q.split_whitespace().collect();

        let mut results: Vec<&ExperimentFlag> = self
            .flags
            .iter()
            .filter(|flag| {
                if modified_only && !flag.is_modified() {
                    return false;
                }
                if tokens.is_empty() {
                    return true;
                }
                let id_l = flag.id.to_ascii_lowercase();
                let title_l = flag.title.to_ascii_lowercase();
                let desc_l = flag.description.to_ascii_lowercase();
                let origin_l = flag.origin.label().to_ascii_lowercase();
                let platforms_l = flag.platforms.join(" ").to_ascii_lowercase();
                let feat_en = flag
                    .chromium_enable_feature
                    .as_deref()
                    .unwrap_or("")
                    .to_ascii_lowercase();
                let feat_dis = flag
                    .chromium_disable_feature
                    .as_deref()
                    .unwrap_or("")
                    .to_ascii_lowercase();
                let switch_l = flag
                    .chromium_switch
                    .as_deref()
                    .unwrap_or("")
                    .to_ascii_lowercase();

                tokens.iter().all(|tok| {
                    id_l.contains(tok)
                        || title_l.contains(tok)
                        || desc_l.contains(tok)
                        || origin_l.contains(tok)
                        || platforms_l.contains(tok)
                        || feat_en.contains(tok)
                        || feat_dis.contains(tok)
                        || switch_l.contains(tok)
                })
            })
            .collect();

        // Stable partition: modified flags pinned first, preserving catalog order within each group.
        results.sort_by_key(|flag| !flag.is_modified());
        results
    }

    /// Sets the active option index of a flag by ID, validating bounds.
    pub fn set_flag(&mut self, id: &str, option_index: usize) -> Result<(), String> {
        let &idx = self
            .id_to_index
            .get(id)
            .ok_or_else(|| format!("Unknown experiment flag: '{}'", id))?;
        let flag = &mut self.flags[idx];
        if option_index >= flag.options.len() {
            return Err(format!(
                "Option index {} out of range for flag '{}' (options: {})",
                option_index,
                id,
                flag.options.len()
            ));
        }
        flag.current_index = option_index;
        Ok(())
    }

    /// Resets a single flag back to its default option index.
    pub fn reset_flag(&mut self, id: &str) -> Result<(), String> {
        let &idx = self
            .id_to_index
            .get(id)
            .ok_or_else(|| format!("Unknown experiment flag: '{}'", id))?;
        let flag = &mut self.flags[idx];
        flag.current_index = flag.default_index;
        Ok(())
    }

    /// Resets all modified flags back to their factory defaults and returns how many were changed.
    pub fn reset_all(&mut self) -> usize {
        let mut count = 0usize;
        for flag in &mut self.flags {
            if flag.current_index != flag.default_index {
                flag.current_index = flag.default_index;
                count += 1;
            }
        }
        count
    }

    /// Returns `true` if any flag differs from the state active at browser boot/last restart.
    pub fn has_pending_restart(&self) -> bool {
        self.flags.iter().any(|flag| {
            self.boot_indices
                .get(&flag.id)
                .copied()
                .unwrap_or(flag.default_index)
                != flag.current_index
        })
    }

    /// Marks the current flag configuration as applied after a browser restart.
    pub fn clear_pending_restart(&mut self) {
        for flag in &self.flags {
            self.boot_indices.insert(flag.id.clone(), flag.current_index);
        }
    }

    /// Exports all modified flags to a deterministic TOML document.
    pub fn export_toml(&self) -> Result<String, String> {
        let mut overrides = BTreeMap::new();
        for flag in &self.flags {
            if flag.is_modified() {
                overrides.insert(flag.id.clone(), flag.current_index);
            }
        }
        let snapshot = FlagsTomlSnapshot {
            version: "1.0.0".to_string(),
            overrides,
        };
        toml::to_string_pretty(&snapshot)
            .map_err(|e| format!("Failed to serialize flags TOML: {}", e))
    }

    /// Imports flag overrides from a TOML snapshot, skipping unknown IDs or out-of-range indices
    /// and returning the number of valid flags applied.
    pub fn import_toml(&mut self, toml_str: &str) -> Result<usize, String> {
        let snapshot: FlagsTomlSnapshot = toml::from_str(toml_str)
            .map_err(|e| format!("Failed to parse flags TOML: {}", e))?;
        let mut applied = 0usize;
        for (id, option_index) in snapshot.overrides {
            if self.set_flag(&id, option_index).is_ok() {
                applied += 1;
            }
        }
        Ok(applied)
    }

    /// Compiles modified flags into `(enable_features, disable_features, extra_switches)`
    /// suitable for constructing Chromium launch flags (`--enable-features=...`,
    /// `--disable-features=...`, plus individual switches).
    pub fn compile_chromium_args(&self) -> (Vec<String>, Vec<String>, Vec<String>) {
        let mut enable_features = Vec::new();
        let mut disable_features = Vec::new();
        let mut extra_switches = Vec::new();

        for flag in &self.flags {
            if !flag.is_modified() {
                continue;
            }

            let opt_raw = flag.current_option();
            let opt_lower = opt_raw.to_ascii_lowercase();
            let is_enabled = opt_lower.starts_with("enabled");
            let is_disabled = opt_lower.starts_with("disabled");

            if is_enabled {
                if let Some(ref feat) = flag.chromium_enable_feature {
                    if is_safe_flag_token(feat) {
                        push_unique(&mut enable_features, feat.clone());
                    }
                }
                if let Some(ref dis_feat) = flag.chromium_disable_feature {
                    if flag.chromium_enable_feature.as_deref() != Some(dis_feat.as_str())
                        && is_safe_flag_token(dis_feat)
                    {
                        push_unique(&mut disable_features, dis_feat.clone());
                    }
                }
                if let Some(ref sw) = flag.chromium_switch {
                    if is_safe_flag_token(sw) {
                        let arg = if let Some(slug) = sanitize_mode_slug(opt_raw) {
                            format!("--{}={}", sw, slug)
                        } else {
                            format!("--{}", sw)
                        };
                        push_unique(&mut extra_switches, arg);
                    }
                }
            } else if is_disabled {
                if let Some(ref feat) = flag.chromium_enable_feature {
                    if is_safe_flag_token(feat) {
                        push_unique(&mut disable_features, feat.clone());
                    }
                }
                if let Some(ref dis_feat) = flag.chromium_disable_feature {
                    if flag.chromium_enable_feature.as_deref() != Some(dis_feat.as_str())
                        && is_safe_flag_token(dis_feat)
                    {
                        push_unique(&mut enable_features, dis_feat.clone());
                    }
                }
            }
        }

        (enable_features, disable_features, extra_switches)
    }
}

fn all_desktop_platforms() -> Vec<String> {
    vec!["Windows".into(), "Linux".into(), "macOS".into()]
}

fn tri_state_options() -> Vec<String> {
    vec!["Default".into(), "Enabled".into(), "Disabled".into()]
}

#[allow(clippy::too_many_arguments)]
fn make_flag(
    id: &str,
    title: &str,
    description: &str,
    origin: FlagOrigin,
    platforms: Vec<String>,
    options: Vec<String>,
    chromium_enable_feature: Option<&str>,
    chromium_disable_feature: Option<&str>,
    chromium_switch: Option<&str>,
) -> ExperimentFlag {
    ExperimentFlag {
        id: id.to_string(),
        title: title.to_string(),
        description: description.to_string(),
        origin,
        platforms,
        options,
        default_index: 0,
        current_index: 0,
        chromium_enable_feature: chromium_enable_feature.map(str::to_string),
        chromium_disable_feature: chromium_disable_feature.map(str::to_string),
        chromium_switch: chromium_switch.map(str::to_string),
    }
}

fn build_default_flags_catalog() -> Vec<ExperimentFlag> {
    vec![
        // --- Chromium Graphics, Rendering & Hardware Acceleration ---
        make_flag(
            "enable-unsafe-webgpu",
            "WebGPU Experimental Compute & Rendering API",
            "Exposes the WebGPU API backed by Dawn/Vulkan/DX12/Metal for GPU compute shaders and next-gen 3D pipelines.",
            FlagOrigin::Chromium,
            all_desktop_platforms(),
            tri_state_options(),
            Some("WebGPU"),
            None,
            Some("enable-unsafe-webgpu"),
        ),
        make_flag(
            "enable-skia-graphite",
            "Skia Graphite Dawn Compositor",
            "Switches 2D canvas and browser UI rasterization from legacy Skia Ganesh to the modern Dawn-backed Skia Graphite backend.",
            FlagOrigin::Chromium,
            all_desktop_platforms(),
            tri_state_options(),
            Some("SkiaGraphite"),
            None,
            None,
        ),
        make_flag(
            "enable-vulkan",
            "Vulkan Graphics Backend",
            "Uses Vulkan as the primary low-overhead GPU command queue for compositing and OOP rasterization.",
            FlagOrigin::Chromium,
            vec!["Linux".into(), "Windows".into()],
            tri_state_options(),
            Some("Vulkan"),
            None,
            None,
        ),
        make_flag(
            "enable-accelerated-video-decode",
            "Hardware-Accelerated Video Decode",
            "Offloads AV1, HEVC, VP9, and H.264 video bitstream decoding to NVDEC/VA-API/DXVA/VideoToolbox silicon.",
            FlagOrigin::Chromium,
            all_desktop_platforms(),
            tri_state_options(),
            Some("VaapiVideoDecodeLinuxGL"),
            None,
            Some("enable-accelerated-video-decode"),
        ),
        make_flag(
            "smooth-scrolling",
            "Smooth Scrolling Physics",
            "Animates wheel and keyboard scrolling smoothly at native 120Hz-240Hz display refresh intervals.",
            FlagOrigin::Chromium,
            all_desktop_platforms(),
            tri_state_options(),
            Some("SmoothScrolling"),
            None,
            None,
        ),
        make_flag(
            "enable-zero-copy",
            "Zero-Copy GPU Texture Rasterizer",
            "Writes rasterized tile bitmaps directly into GPU DMA-BUF / shared textures without CPU staging copies.",
            FlagOrigin::Chromium,
            all_desktop_platforms(),
            tri_state_options(),
            None,
            None,
            Some("enable-zero-copy"),
        ),
        make_flag(
            "enable-gpu-rasterization",
            "GPU Tile Rasterization",
            "Uses GPU shaders to rasterize web content tiles instead of CPU software Skia threads.",
            FlagOrigin::Chromium,
            all_desktop_platforms(),
            tri_state_options(),
            Some("GpuRasterization"),
            None,
            Some("enable-gpu-rasterization"),
        ),
        make_flag(
            "enable-force-dark",
            "Auto Dark Mode for Web Contents (WebContentsForceDark)",
            "Automatically inverts light websites into OLED-friendly dark themes using selectable perceptual color algorithms.",
            FlagOrigin::Chromium,
            all_desktop_platforms(),
            vec![
                "Default".into(),
                "Enabled".into(),
                "Enabled (Simple HSL)".into(),
                "Enabled (CIELAB Selective)".into(),
                "Disabled".into(),
            ],
            Some("WebContentsForceDark"),
            None,
            None,
        ),
        make_flag(
            "ozone-wayland-explicit-sync",
            "Wayland Explicit DMA-BUF Sync & Per-Surface Scale",
            "Enables explicit GPU fence synchronization and fractional per-monitor scaling under Wayland Ozone.",
            FlagOrigin::Chromium,
            vec!["Linux".into()],
            tri_state_options(),
            Some("WaylandPerSurfaceScale"),
            None,
            None,
        ),
        // --- Chromium Networking, Navigation & Downloads ---
        make_flag(
            "enable-parallel-downloading",
            "Parallel Multi-Segment Downloading",
            "Splits large file downloads into concurrent HTTP range-request segments to saturate high-bandwidth links.",
            FlagOrigin::Chromium,
            all_desktop_platforms(),
            tri_state_options(),
            Some("ParallelDownloading"),
            None,
            None,
        ),
        make_flag(
            "partitioned-cookies",
            "Partitioned Cookies (CHIPS)",
            "Partitions third-party cookies by top-level site origin to eliminate cross-site tracking while keeping embedded logins functional.",
            FlagOrigin::Chromium,
            all_desktop_platforms(),
            tri_state_options(),
            Some("PartitionedCookies"),
            None,
            None,
        ),
        make_flag(
            "back-forward-cache",
            "Back-Forward Cache (BackForwardCache)",
            "Keeps recently navigated pages frozen in memory for instant 0ms back/forward history restoration.",
            FlagOrigin::Chromium,
            all_desktop_platforms(),
            vec![
                "Default".into(),
                "Enabled".into(),
                "Enabled (Ignore Cache-Control)".into(),
                "Disabled".into(),
            ],
            Some("BackForwardCache"),
            None,
            None,
        ),
        make_flag(
            "prerender2",
            "Speculative Prerender2 Navigation Engine",
            "Prerenders high-confidence omnibox and Speculation Rules links in isolated hidden WebContents.",
            FlagOrigin::Chromium,
            all_desktop_platforms(),
            tri_state_options(),
            Some("Prerender2"),
            None,
            None,
        ),
        make_flag(
            "encrypted-client-hello",
            "TLS 1.3 Encrypted Client Hello (ECH)",
            "Encrypts the TLS SNI hostname inside the ClientHello handshake using DNS HTTPS records.",
            FlagOrigin::Chromium,
            all_desktop_platforms(),
            tri_state_options(),
            Some("EncryptedClientHello"),
            None,
            None,
        ),
        make_flag(
            "enable-zstd-content-encoding",
            "Zstandard (zstd) HTTP Content-Encoding",
            "Advertises `zstd` in Accept-Encoding for faster, tighter HTTP response decompression than Brotli/Gzip.",
            FlagOrigin::Chromium,
            all_desktop_platforms(),
            tri_state_options(),
            Some("ZstdContentEncoding"),
            None,
            None,
        ),
        make_flag(
            "enable-quic",
            "Experimental QUIC / HTTP/3 Transport",
            "Enables UDP-based HTTP/3 QUIC transport with 0-RTT connection resumption and loss recovery.",
            FlagOrigin::Chromium,
            all_desktop_platforms(),
            tri_state_options(),
            Some("QuicTransport"),
            None,
            Some("enable-quic"),
        ),
        make_flag(
            "tls13-post-quantum-mlkem",
            "TLS 1.3 Post-Quantum Key Agreement (X25519MLKEM768)",
            "Protects TLS 1.3 handshakes against harvest-now-decrypt-later quantum attacks via hybrid ML-KEM768.",
            FlagOrigin::Chromium,
            all_desktop_platforms(),
            tri_state_options(),
            Some("UseMLKEM"),
            None,
            None,
        ),
        make_flag(
            "dns-httpssvc-alpn",
            "DNS HTTPS/SVCB Record Resolution",
            "Queries DNS HTTPS resource records to discover HTTP/3 ALPN endpoints and ECH configs in one round-trip.",
            FlagOrigin::Chromium,
            all_desktop_platforms(),
            tri_state_options(),
            Some("UseDnsHttpsSvcb"),
            None,
            None,
        ),
        // --- Chromium Security, Privacy, Extensions & Platform ---
        make_flag(
            "extension-manifest-v2",
            "Extension Manifest V2 Compatibility (ExtensionManifestV2)",
            "Preserves full Manifest V2 extension support including blocking webRequest APIs alongside Manifest V3.",
            FlagOrigin::Chromium,
            all_desktop_platforms(),
            tri_state_options(),
            Some("AllowLegacyMV2Extensions"),
            Some("ExtensionManifestV2Unsupported"),
            None,
        ),
        make_flag(
            "strict-origin-isolation",
            "Strict Origin Isolation",
            "Enforces process-per-origin (scheme + host + port) isolation rather than site-level eTLD+1 grouping.",
            FlagOrigin::Chromium,
            all_desktop_platforms(),
            tri_state_options(),
            Some("StrictOriginIsolation"),
            None,
            Some("strict-origin-isolation"),
        ),
        make_flag(
            "block-insecure-private-network-requests",
            "Block Insecure Private Network Requests",
            "Prevents public websites from making unauthenticated CSRF requests to localhost or RFC1918 LAN devices.",
            FlagOrigin::Chromium,
            all_desktop_platforms(),
            tri_state_options(),
            Some("BlockInsecurePrivateNetworkRequests"),
            None,
            None,
        ),
        make_flag(
            "pwa-window-controls-overlay",
            "PWA Window Controls Overlay (PwaWindowControlsOverlay)",
            "Allows installed Progressive Web Apps to render custom titlebar UI into the native window caption region.",
            FlagOrigin::Chromium,
            all_desktop_platforms(),
            tri_state_options(),
            Some("WebAppWindowControlsOverlay"),
            None,
            None,
        ),
        make_flag(
            "pwa-tabbed-application-mode",
            "PWA Tabbed Desktop Window Mode",
            "Permits installed PWAs with `display_override: [\"tabbed\"]` to host multiple document tabs inside one app window.",
            FlagOrigin::Chromium,
            all_desktop_platforms(),
            tri_state_options(),
            Some("DesktopPWAsTabStrip"),
            None,
            None,
        ),
        make_flag(
            "pdf-ocr-local-extraction",
            "Built-In PDF Local OCR Text Extraction",
            "Runs on-device OCR on scanned PDF images to make text selectable and screen-reader accessible.",
            FlagOrigin::Chromium,
            all_desktop_platforms(),
            tri_state_options(),
            Some("PdfOcr"),
            None,
            None,
        ),
        make_flag(
            "tab-groups-save-v2",
            "Persistent Tab Groups & Workspace Snapshots V2",
            "Persists named tab groups and workspace layouts across restarts and zero-knowledge sync.",
            FlagOrigin::Chromium,
            all_desktop_platforms(),
            tri_state_options(),
            Some("TabGroupsSaveV2"),
            None,
            None,
        ),
        make_flag(
            "enable-hardware-media-key-handling",
            "OS Hardware Media Keys & MPRIS Integration",
            "Routes keyboard Play/Pause/Next/Previous keys and OS media session overlays to active browser playback.",
            FlagOrigin::Chromium,
            all_desktop_platforms(),
            tri_state_options(),
            Some("HardwareMediaKeyHandling"),
            None,
            None,
        ),
        make_flag(
            "enable-experimental-web-platform-features",
            "Experimental Web Platform Features",
            "Enables upcoming W3C/WHATWG CSS, WebAssembly, and DOM APIs currently in Chromium origin trials.",
            FlagOrigin::Chromium,
            all_desktop_platforms(),
            tri_state_options(),
            None,
            None,
            Some("enable-experimental-web-platform-features"),
        ),
        make_flag(
            "web-bluetooth-new-permissions",
            "Web Bluetooth Persistent Permissions Backend",
            "Uses the hardened per-origin device permission store when Web Bluetooth is explicitly allowed.",
            FlagOrigin::Chromium,
            all_desktop_platforms(),
            tri_state_options(),
            Some("WebBluetoothNewPermissionsBackend"),
            None,
            None,
        ),
        // --- Singularity Native Rust Engine Flags ---
        make_flag(
            "singularity-wgpu-shaders-200hz",
            "Singularity WGPU 200Hz+ Black-Hole & Cursor Shaders (WgpuShaders200Hz)",
            "Drives the Singularity OLED UI effects, accretion disk NTP, and custom cursor trails via a dedicated 200Hz+ wgpu pass.",
            FlagOrigin::SingularityRust,
            all_desktop_platforms(),
            vec![
                "Default".into(),
                "Enabled".into(),
                "Enabled (240Hz VRR)".into(),
                "Disabled".into(),
            ],
            None,
            None,
            Some("singularity-wgpu-shaders-200hz"),
        ),
        make_flag(
            "singularity-hover-preconnect-0rtt",
            "Hover Preconnect & 0-RTT Speculative Dialer (HoverPreconnect0Rtt)",
            "Triggers Rust QUIC 0-RTT handshakes and DoQ DNS resolution after 65ms of intentional cursor hover on links.",
            FlagOrigin::SingularityRust,
            all_desktop_platforms(),
            tri_state_options(),
            None,
            None,
            Some("singularity-hover-preconnect-0rtt"),
        ),
        make_flag(
            "singularity-aggressive-tab-freezer",
            "Aggressive Zstd Tab Freezer & Memory Discarder (AggressiveTabFreezer)",
            "Suspends idle background renderers and compresses DOM/scroll checkpoints with Zstd to cut RAM usage by 70%+.",
            FlagOrigin::SingularityRust,
            all_desktop_platforms(),
            vec![
                "Default".into(),
                "Enabled".into(),
                "Enabled (Ultra-Low RAM)".into(),
                "Disabled".into(),
            ],
            None,
            None,
            Some("singularity-aggressive-tab-freezer"),
        ),
        make_flag(
            "singularity-cname-unmasking-strict",
            "Strict Rust DNS CNAME Cloaking Unmasking (CnameUnmaskingStrict)",
            "Inspects live DNS CNAME chains inside the Rust resolver to block disguised first-party analytics subdomains.",
            FlagOrigin::SingularityRust,
            all_desktop_platforms(),
            tri_state_options(),
            None,
            None,
            Some("singularity-cname-unmasking-strict"),
        ),
        make_flag(
            "singularity-daita-experimental",
            "Mullvad DAITA Experimental Traffic-Analysis Defense (DaitaExperimental)",
            "Enables adaptive Maybenot state-machine packet padding and decoy frames over the embedded WireGuard tunnel.",
            FlagOrigin::SingularityRust,
            all_desktop_platforms(),
            vec![
                "Default".into(),
                "Enabled".into(),
                "Enabled (Constant-Rate)".into(),
                "Disabled".into(),
            ],
            None,
            None,
            Some("singularity-daita-experimental"),
        ),
        make_flag(
            "singularity-local-translate-offline",
            "Offline On-Device Neural Page Translation (LocalTranslateOffline)",
            "Translates web pages locally with quantized Bergamot/Wasm models with zero external cloud telemetry.",
            FlagOrigin::SingularityRust,
            all_desktop_platforms(),
            tri_state_options(),
            None,
            None,
            Some("singularity-local-translate-offline"),
        ),
        make_flag(
            "singularity-zero-knowledge-sync",
            "Zero-Knowledge E2EE Sync Chain (ZeroKnowledgeSync)",
            "Synchronizes bookmarks, tabs, vault records, and settings across devices using BIP-39 derived XChaCha20-Poly1305 keys.",
            FlagOrigin::SingularityRust,
            all_desktop_platforms(),
            tri_state_options(),
            None,
            None,
            Some("singularity-zero-knowledge-sync"),
        ),
        make_flag(
            "singularity-native-userscripts",
            "Native Rust Userscripts Runtime (NativeUserscripts)",
            "Executes Tampermonkey/Violentmonkey-compatible `GM_*` userscripts natively in isolated Blink worlds.",
            FlagOrigin::SingularityRust,
            all_desktop_platforms(),
            tri_state_options(),
            None,
            None,
            Some("singularity-native-userscripts"),
        ),
        make_flag(
            "singularity-remote-debugging-pipe-mux",
            "CDP Remote Debugging Pipe Multiplexer (RemoteDebuggingPipeMux)",
            "Multiplexes DevTools Protocol clients over a hardened loopback pipe with per-target capability filtering.",
            FlagOrigin::SingularityRust,
            all_desktop_platforms(),
            tri_state_options(),
            None,
            None,
            Some("singularity-cdp-pipe-mux"),
        ),
        make_flag(
            "singularity-split-view-tiling",
            "Native Multi-Pane Split View Tiling",
            "Displays 2 to 4 live Chromium WebContents side-by-side inside a single Singularity tab with synchronized scroll.",
            FlagOrigin::SingularityRust,
            all_desktop_platforms(),
            tri_state_options(),
            None,
            None,
            Some("singularity-split-view-tiling"),
        ),
        make_flag(
            "singularity-command-chains-macro",
            "Command Chains & Macro Automation Engine",
            "Allows chaining multiple browser actions, URL opens, and tiling layouts into a single shortcut or palette item.",
            FlagOrigin::SingularityRust,
            all_desktop_platforms(),
            tri_state_options(),
            None,
            None,
            Some("singularity-command-chains-macro"),
        ),
        make_flag(
            "singularity-mouse-gestures-wgpu",
            "Hardware-Accelerated Mouse Gestures Overlay",
            "Renders low-latency stroke trails and executes directional mouse & rocker gestures natively.",
            FlagOrigin::SingularityRust,
            all_desktop_platforms(),
            tri_state_options(),
            None,
            None,
            Some("singularity-mouse-gestures-wgpu"),
        ),
        make_flag(
            "singularity-boosts-injector",
            "Per-Site Boosts CSS/JS & Element Zapper",
            "Applies persistent per-domain typography, OLED color overrides, and element zap rules on navigation.",
            FlagOrigin::SingularityRust,
            all_desktop_platforms(),
            tri_state_options(),
            None,
            None,
            Some("singularity-boosts-injector"),
        ),
        make_flag(
            "singularity-forgetful-browsing",
            "Forgetful Browsing Automatic Storage Purge",
            "Automatically wipes cookies, LocalStorage, and IndexedDB for tagged origins shortly after closing their last tab.",
            FlagOrigin::SingularityRust,
            all_desktop_platforms(),
            tri_state_options(),
            None,
            None,
            Some("singularity-forgetful-browsing"),
        ),
        make_flag(
            "singularity-live-captions-offline",
            "Offline On-Device Live Captions ASR",
            "Transcribes browser audio streams locally in real time for accessibility without sending audio to cloud APIs.",
            FlagOrigin::SingularityRust,
            all_desktop_platforms(),
            tri_state_options(),
            None,
            None,
            Some("singularity-live-captions-offline"),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_flags_catalog_richness_and_uniqueness() {
        let store = FlagsStore::new();
        assert!(
            store.len() >= 35,
            "Expected >= 35 experiment flags, got {}",
            store.len()
        );
        let mut ids = HashSet::new();
        for flag in store.all_flags() {
            assert!(ids.insert(flag.id.as_str()), "Duplicate flag id: {}", flag.id);
            assert!(!flag.options.is_empty());
            assert!(flag.default_index < flag.options.len());
            assert_eq!(flag.current_index, flag.default_index);
            assert!(!flag.is_modified());
        }
        assert!(!store.has_pending_restart());
    }

    #[test]
    fn test_flags_pinning_filter_restart_and_toml_roundtrip() {
        let mut store = FlagsStore::new();
        store.set_flag("singularity-daita-experimental", 2).unwrap();
        store.set_flag("enable-vulkan", 1).unwrap();
        assert!(store.has_pending_restart());
        assert_eq!(store.modified_count(), 2);

        // Modified flags must be pinned at the top of list_filtered
        let all_listed = store.list_filtered("", false);
        assert!(all_listed[0].is_modified());
        assert!(all_listed[1].is_modified());
        assert!(!all_listed[2].is_modified());

        // modified_only filter returns strictly the 2 modified flags
        let mod_only = store.list_filtered("", true);
        assert_eq!(mod_only.len(), 2);

        // Search query matches across title/id/description/origin
        let search_res = store.list_filtered("daita", false);
        assert_eq!(search_res.len(), 1);
        assert_eq!(search_res[0].id, "singularity-daita-experimental");

        // Out-of-bounds option index and unknown flag return errors
        assert!(store.set_flag("enable-vulkan", 99).is_err());
        assert!(store.set_flag("nonexistent-flag", 1).is_err());

        // Export & import TOML roundtrip
        let toml_out = store.export_toml().expect("Export flags TOML");
        assert!(toml_out.contains("singularity-daita-experimental"));
        assert!(toml_out.contains("enable-vulkan"));

        let mut store2 = FlagsStore::new();
        let imported = store2.import_toml(&toml_out).expect("Import flags TOML");
        assert_eq!(imported, 2);
        assert_eq!(
            store2.get("singularity-daita-experimental").unwrap().current_index,
            2
        );
        assert_eq!(store2.get("enable-vulkan").unwrap().current_index, 1);
        assert!(store2.has_pending_restart());

        // Reset single flag and reset all
        store2.reset_flag("enable-vulkan").unwrap();
        assert_eq!(store2.modified_count(), 1);
        let reset_count = store2.reset_all();
        assert_eq!(reset_count, 1);
        assert_eq!(store2.modified_count(), 0);
        assert!(!store2.has_pending_restart());
    }

    #[test]
    fn test_flags_compile_chromium_args() {
        let mut store = FlagsStore::new();
        store.set_flag("enable-skia-graphite", 1).unwrap(); // Enabled
        store.set_flag("prerender2", 2).unwrap(); // Disabled
        store.set_flag("extension-manifest-v2", 1).unwrap(); // Enables AllowLegacyMV2Extensions, disables ExtensionManifestV2Unsupported
        store.set_flag("singularity-wgpu-shaders-200hz", 2).unwrap(); // Enabled (240Hz VRR)

        let (enable_feats, disable_feats, switches) = store.compile_chromium_args();
        assert!(enable_feats.contains(&"SkiaGraphite".to_string()));
        assert!(enable_feats.contains(&"AllowLegacyMV2Extensions".to_string()));
        assert!(disable_feats.contains(&"Prerender2".to_string()));
        assert!(disable_feats.contains(&"ExtensionManifestV2Unsupported".to_string()));
        assert!(switches.contains(&"--singularity-wgpu-shaders-200hz=240hz-vrr".to_string()));
    }
}
