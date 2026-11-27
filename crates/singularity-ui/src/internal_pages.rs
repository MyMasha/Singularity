//! Unified Internal Browser Pages Registry (`browser://`, `singularity://`, `chrome://`)
//! and Hardened OLED Pure Black (`#000000`) Interactive HTML Renderer.
//!
//! 100% pure Rust, zero external network assets, strict HTML/JS escaping, CSP-enforced,
//! bilingual EN/FR, with live local filtering, JSON copy/export, and `X-Singularity-Token`
//! authenticated `/api/...` actions.

use serde::{Deserialize, Serialize};

// ============================================================================
// 1. Internal Page Registry & Canonical URL Normalization
// ============================================================================

/// High-level grouping displayed on `browser://urls`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InternalPageCategory {
    Settings,
    Diagnostics,
    Security,
    Productivity,
    Media,
    Developer,
    Errors,
}

impl InternalPageCategory {
    pub fn label_en(&self) -> &'static str {
        match self {
            Self::Settings => "Settings & Configuration",
            Self::Diagnostics => "Diagnostics & Telemetry",
            Self::Security => "Security & Privacy",
            Self::Productivity => "Productivity & Library",
            Self::Media => "Reader & Media Tools",
            Self::Developer => "Developer & Extensions",
            Self::Errors => "Security Interstitials",
        }
    }

    pub fn label_fr(&self) -> &'static str {
        match self {
            Self::Settings => "Paramètres & Configuration",
            Self::Diagnostics => "Diagnostics & Télémétrie",
            Self::Security => "Sécurité & Vie Privée",
            Self::Productivity => "Productivité & Bibliothèque",
            Self::Media => "Lecture & Outils Média",
            Self::Developer => "Développeur & Extensions",
            Self::Errors => "Pages d'alerte sécurité",
        }
    }
}

/// Specification of a canonical internal browser page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InternalPageSpec {
    pub slug: &'static str,
    pub category: InternalPageCategory,
    pub title_en: &'static str,
    pub title_fr: &'static str,
    pub description_en: &'static str,
    pub description_fr: &'static str,
    pub aliases: &'static [&'static str],
}

/// Complete registry of all 36 internal pages accessible via `browser://<slug>`,
/// `singularity://<slug>`, or `chrome://<slug>`.
pub const INTERNAL_PAGE_REGISTRY: &[InternalPageSpec] = &[
    InternalPageSpec {
        slug: "settings",
        category: InternalPageCategory::Settings,
        title_en: "Settings",
        title_fr: "Paramètres",
        description_en: "Virtualized 2,165+ engine preferences, privacy shield, VPN, and appearance.",
        description_fr: "2 165+ paramètres moteur, bouclier vie privée, VPN et apparence.",
        aliases: &["preferences", "options", "config"],
    },
    InternalPageSpec {
        slug: "flags",
        category: InternalPageCategory::Settings,
        title_en: "Experimental Flags",
        title_fr: "Options Expérimentales (Flags)",
        description_en: "Toggle experimental engine features, GPU pipelines, and hardening overrides.",
        description_fr: "Activer les fonctionnalités expérimentales, pipelines GPU et durcissements.",
        aliases: &["experiments"],
    },
    InternalPageSpec {
        slug: "urls",
        category: InternalPageCategory::Diagnostics,
        title_en: "Internal Browser URLs",
        title_fr: "URLs Internes du Navigateur",
        description_en: "Directory of all built-in diagnostic, settings, productivity, and developer pages.",
        description_fr: "Annuaire de toutes les pages de diagnostic, paramètres et outils développeur.",
        aliases: &["about", "about-urls", "browser-urls", "chrome-urls"],
    },
    InternalPageSpec {
        slug: "version",
        category: InternalPageCategory::Diagnostics,
        title_en: "About Version",
        title_fr: "À propos de la version",
        description_en: "Singularity build metadata, runtime engine version, OS, profile & binary paths.",
        description_fr: "Métadonnées de compilation Singularity, moteur, OS, profil et exécutable.",
        aliases: &["about-version", "info"],
    },
    InternalPageSpec {
        slug: "gpu",
        category: InternalPageCategory::Diagnostics,
        title_en: "GPU & 200Hz Compositor",
        title_fr: "GPU & Compositeur 200Hz",
        description_en: "Hardware acceleration status, WebGPU/WGSL shaders, display refresh & decoder status.",
        description_fr: "Accélération matérielle, shaders WebGPU/WGSL, fréquence d'affichage et décodeurs.",
        aliases: &["gpu-internals"],
    },
    InternalPageSpec {
        slug: "process-manager",
        category: InternalPageCategory::Diagnostics,
        title_en: "Browser Process Manager",
        title_fr: "Gestionnaire de Processus",
        description_en: "Live CPU, private RAM, GPU memory and tab hibernation controls per process.",
        description_fr: "CPU, RAM privée, mémoire GPU et mise en veille par processus en direct.",
        aliases: &["task-manager", "tasks", "processes"],
    },
    InternalPageSpec {
        slug: "net-internals",
        category: InternalPageCategory::Diagnostics,
        title_en: "Network Internals",
        title_fr: "Diagnostics Réseau",
        description_en: "DoH/DoQ resolver cache, Mullvad WireGuard routing, sockets, and TLS sessions.",
        description_fr: "Cache DNS DoH/DoQ, routage Mullvad WireGuard, sockets et sessions TLS.",
        aliases: &["network", "dns", "sockets"],
    },
    InternalPageSpec {
        slug: "crashes",
        category: InternalPageCategory::Diagnostics,
        title_en: "Crash Reports",
        title_fr: "Rapports de Plantage",
        description_en: "Local-only crash guard journal and session recovery dumps (zero telemetry upload).",
        description_fr: "Journal local Crash Guard et sauvegardes de récupération (zéro télémétrie).",
        aliases: &["crash-reports"],
    },
    InternalPageSpec {
        slug: "components",
        category: InternalPageCategory::Diagnostics,
        title_en: "Components & Lists",
        title_fr: "Composants & Listes",
        description_en: "Adblock filter lists, HSTS preload, Widevine CDM, dictionaries, and updater signatures.",
        description_fr: "Listes de blocage, HSTS preload, Widevine CDM, dictionnaires et signatures.",
        aliases: &["updates"],
    },
    InternalPageSpec {
        slug: "sandbox",
        category: InternalPageCategory::Security,
        title_en: "Sandbox & Process Isolation",
        title_fr: "Bac à Sable & Isolation",
        description_en: "OS sandbox layers, Site Isolation, seccomp/JobObject restrictions, and token hardening.",
        description_fr: "Couches sandbox OS, Site Isolation, restrictions et durcissement IPC.",
        aliases: &["security-sandbox"],
    },
    InternalPageSpec {
        slug: "media-internals",
        category: InternalPageCategory::Diagnostics,
        title_en: "Media Internals",
        title_fr: "Diagnostics Média",
        description_en: "Active AV1/HEVC/VP9 pipelines, audio sinks, hardware decode, and DRM playback status.",
        description_fr: "Pipelines AV1/HEVC/VP9, sorties audio, décodage matériel et état DRM.",
        aliases: &["media"],
    },
    InternalPageSpec {
        slug: "policy",
        category: InternalPageCategory::Security,
        title_en: "Enterprise & Hardening Policies",
        title_fr: "Politiques de Durcissement",
        description_en: "Active security policies, locked preferences, and zero-telemetry enforcement.",
        description_fr: "Politiques de sécurité actives, préférences verrouillées et zéro télémétrie.",
        aliases: &["policies"],
    },
    InternalPageSpec {
        slug: "tracing",
        category: InternalPageCategory::Developer,
        title_en: "Performance Tracing",
        title_fr: "Traçage de Performances",
        description_en: "Capture frame-time traces, IPC latency spans, and export Chrome Trace JSON.",
        description_fr: "Capturer les traces frame-time, latences IPC et exporter en JSON.",
        aliases: &["trace", "profiler"],
    },
    InternalPageSpec {
        slug: "histograms",
        category: InternalPageCategory::Diagnostics,
        title_en: "Local Histograms",
        title_fr: "Histogrammes Locaux",
        description_en: "In-memory latency distributions for startup, tab switch, and shield filtering.",
        description_fr: "Distributions locales de latence au démarrage, changement d'onglet et filtrage.",
        aliases: &["metrics"],
    },
    InternalPageSpec {
        slug: "discards",
        category: InternalPageCategory::Diagnostics,
        title_en: "Tab Discards & RAM Saver",
        title_fr: "Veille d'Onglets & Économie RAM",
        description_en: "Inspect tab hibernation eligibility, memory reclaimed, and trigger manual unload.",
        description_fr: "Inspecter la mise en veille des onglets, la RAM libérée et décharger à la demande.",
        aliases: &["tab-discards", "memory-saver"],
    },
    InternalPageSpec {
        slug: "system",
        category: InternalPageCategory::Diagnostics,
        title_en: "System Diagnostics",
        title_fr: "Diagnostics Système",
        description_en: "Hardware, OS environment, display DPI, and storage directory summary.",
        description_fr: "Matériel, environnement OS, DPI d'écran et répertoires de stockage.",
        aliases: &["sysinfo"],
    },
    InternalPageSpec {
        slug: "credits",
        category: InternalPageCategory::Settings,
        title_en: "Open-Source Credits & Licenses",
        title_fr: "Crédits Open-Source & Licences",
        description_en: "MPL-2.0 Singularity license and third-party Rust & Chromium open-source notices.",
        description_fr: "Licence MPL-2.0 Singularity et mentions open-source Rust & Chromium.",
        aliases: &["licenses", "oss"],
    },
    InternalPageSpec {
        slug: "omnibox",
        category: InternalPageCategory::Developer,
        title_en: "Omnibox Ranking Debugger",
        title_fr: "Débogueur de Classement Omnibox",
        description_en: "Inspect URL autocomplete scoring, bang shortcuts, and local history frecency.",
        description_fr: "Inspecter le scoring d'autocomplétion URL, bangs et fréquences locales.",
        aliases: &["omnibox-debug"],
    },
    InternalPageSpec {
        slug: "inspect",
        category: InternalPageCategory::Developer,
        title_en: "Inspect DevTools Targets",
        title_fr: "Inspecter les Cibles DevTools",
        description_en: "Inspect pages, WebWorkers, ServiceWorkers, extensions, and installed PWAs.",
        description_fr: "Inspecter pages, WebWorkers, ServiceWorkers, extensions et PWA installées.",
        aliases: &["devtools-inspect", "targets"],
    },
    InternalPageSpec {
        slug: "performance",
        category: InternalPageCategory::Diagnostics,
        title_en: "Performance & 200Hz Monitor",
        title_fr: "Moniteur Performances & 200Hz",
        description_en: "Real-time frame pacing, RSS memory budget, active timers, and battery mode.",
        description_fr: "Frame pacing en temps réel, budget mémoire RSS, timers actifs et mode batterie.",
        aliases: &["perf", "fps"],
    },
    InternalPageSpec {
        slug: "logger",
        category: InternalPageCategory::Developer,
        title_en: "Shield & Network Logger",
        title_fr: "Journal Bouclier & Réseau",
        description_en: "Live filter log of blocked trackers, cosmetic rules, CSP upgrades, and script events.",
        description_fr: "Journal en direct des traqueurs bloqués, règles cosmétiques et requêtes.",
        aliases: &["logs", "console-log", "shield-log"],
    },
    InternalPageSpec {
        slug: "diff",
        category: InternalPageCategory::Settings,
        title_en: "Modified Settings Diff",
        title_fr: "Diff des Paramètres Modifiés",
        description_en: "Compare every user-customized preference against hardened defaults with one-click reset.",
        description_fr: "Comparer chaque préférence modifiée aux valeurs par défaut avec réinitialisation.",
        aliases: &["settings-diff", "changes"],
    },
    InternalPageSpec {
        slug: "apps",
        category: InternalPageCategory::Developer,
        title_en: "Installed Web Apps (PWAs)",
        title_fr: "Applications Web Installées (PWA)",
        description_en: "Manage installed PWAs, standalone window launch, protocol/file handlers, and shortcuts.",
        description_fr: "Gérer les PWA installées, fenêtres dédiées, gestionnaires de protocoles et raccourcis.",
        aliases: &["pwa", "web-apps"],
    },
    InternalPageSpec {
        slug: "userscripts",
        category: InternalPageCategory::Developer,
        title_en: "Userscripts Manager",
        title_fr: "Gestionnaire de Userscripts",
        description_en: "Manage isolated-world GM_* userscripts, security risk badges, and JSON/ZIP backups.",
        description_fr: "Gérer les scripts GM_* isolés, badges de risque sécurité et sauvegardes JSON/ZIP.",
        aliases: &["scripts", "grease"],
    },
    InternalPageSpec {
        slug: "bookmarks",
        category: InternalPageCategory::Productivity,
        title_en: "Bookmarks Manager",
        title_fr: "Gestionnaire de Favoris",
        description_en: "Organize folders, tags, Netscape HTML import/export, and deduplication.",
        description_fr: "Organiser dossiers, étiquettes, import/export HTML et déduplication.",
        aliases: &["favorites", "favoris"],
    },
    InternalPageSpec {
        slug: "history",
        category: InternalPageCategory::Productivity,
        title_en: "Browsing History",
        title_fr: "Historique de Navigation",
        description_en: "Search local browsing history with time-range and domain purge controls.",
        description_fr: "Rechercher l'historique local avec suppression par période ou domaine.",
        aliases: &["historique"],
    },
    InternalPageSpec {
        slug: "downloads",
        category: InternalPageCategory::Productivity,
        title_en: "Downloads",
        title_fr: "Téléchargements",
        description_en: "Monitor active downloads, SHA-256 verification, and open downloaded files.",
        description_fr: "Suivre les téléchargements, vérifications SHA-256 et fichiers locaux.",
        aliases: &["telechargements"],
    },
    InternalPageSpec {
        slug: "collections",
        category: InternalPageCategory::Productivity,
        title_en: "Collections",
        title_fr: "Collections",
        description_en: "Curated web clippings, links, and project boards.",
        description_fr: "Extraits web, liens organisés et tableaux de projet.",
        aliases: &["spaces"],
    },
    InternalPageSpec {
        slug: "notes",
        category: InternalPageCategory::Productivity,
        title_en: "Markdown Notes",
        title_fr: "Notes Markdown",
        description_en: "Encrypted local notes linked to pages and screenshots.",
        description_fr: "Notes locales chiffrées liées aux pages et captures d'écran.",
        aliases: &["notepad"],
    },
    InternalPageSpec {
        slug: "reading-list",
        category: InternalPageCategory::Productivity,
        title_en: "Reading List",
        title_fr: "Liste de Lecture",
        description_en: "Offline articles saved for distraction-free reading.",
        description_fr: "Articles hors ligne enregistrés pour une lecture sans distraction.",
        aliases: &["read-later"],
    },
    InternalPageSpec {
        slug: "sessions",
        category: InternalPageCategory::Productivity,
        title_en: "Session & Workspace Manager",
        title_fr: "Gestionnaire de Sessions",
        description_en: "Restore named snapshots, inspect workspaces, and reopen recently closed tabs.",
        description_fr: "Restaurer des sessions nommées, espaces de travail et onglets fermés.",
        aliases: &["session-manager"],
    },
    InternalPageSpec {
        slug: "reader",
        category: InternalPageCategory::Media,
        title_en: "Reader Mode",
        title_fr: "Mode Lecture",
        description_en: "Distraction-free OLED typography view with Read Aloud (TTS) controls.",
        description_fr: "Vue typographique OLED sans distraction avec lecture vocale (TTS).",
        aliases: &["reader-mode"],
    },
    InternalPageSpec {
        slug: "pdf",
        category: InternalPageCategory::Media,
        title_en: "Native PDF Viewer",
        title_fr: "Visionneuse PDF Native",
        description_en: "Sandboxed OLED PDF reader with outline, search, and dark-page inversion.",
        description_fr: "Lecteur PDF isolé avec sommaire, recherche et inversion OLED.",
        aliases: &["pdf-viewer"],
    },
    InternalPageSpec {
        slug: "capture-editor",
        category: InternalPageCategory::Media,
        title_en: "Screenshot Annotation Editor",
        title_fr: "Éditeur d'Annotation de Capture",
        description_en: "Crop, blur sensitive regions, draw arrows, and export PNG/WebP captures.",
        description_fr: "Recadrer, flouter les zones sensibles, annoter et exporter en PNG/WebP.",
        aliases: &["screenshot", "capture"],
    },
    InternalPageSpec {
        slug: "cert-error",
        category: InternalPageCategory::Errors,
        title_en: "TLS Certificate Error",
        title_fr: "Erreur de Certificat TLS",
        description_en: "Hardened interstitial warning for expired, mismatched, or untrusted TLS certificates.",
        description_fr: "Page d'alerte durcie pour certificats TLS expirés, invalides ou non approuvés.",
        aliases: &["ssl-error", "tls-error"],
    },
    InternalPageSpec {
        slug: "https-warning",
        category: InternalPageCategory::Errors,
        title_en: "HTTPS-Only Mode Warning",
        title_fr: "Avertissement Mode HTTPS-Only",
        description_en: "Interstitial blocking plaintext HTTP navigation unless explicitly permitted.",
        description_fr: "Interstitiel bloquant la navigation HTTP en clair sans autorisation explicite.",
        aliases: &["insecure-warning", "http-warning"],
    },
];

/// Looks up a page specification by canonical slug or any registered alias (case-insensitive).
pub fn find_internal_page(slug_or_alias: &str) -> Option<&'static InternalPageSpec> {
    let key = slug_or_alias.trim().to_ascii_lowercase();
    if key.is_empty() {
        return None;
    }
    INTERNAL_PAGE_REGISTRY.iter().find(|spec| {
        spec.slug == key || spec.aliases.iter().any(|&alias| alias == key)
    })
}

/// Unifies `browser://<page>`, `singularity://<page>`, and `chrome://<page>` into
/// `browser://<canonical_slug>` (preserving optional safe subpaths/queries/fragments).
///
/// Returns `None` for non-internal schemes, unknown slugs, or malformed/control input.
pub fn normalize_internal_url(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.chars().any(|c| c.is_control()) {
        return None;
    }

    let lower = trimmed.to_ascii_lowercase();
    let prefix_len = if lower.starts_with("browser://") {
        "browser://".len()
    } else if lower.starts_with("singularity://") {
        "singularity://".len()
    } else if lower.starts_with("chrome://") {
        "chrome://".len()
    } else {
        return None;
    };

    let rest = &trimmed[prefix_len..];
    if rest.is_empty() {
        return None;
    }

    // Separate page slug from optional `/subpath`, `?query`, or `#fragment`
    let delim_pos = rest.find(['/', '?', '#']);
    let (raw_slug, suffix) = match delim_pos {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, ""),
    };

    let spec = find_internal_page(raw_slug)?;

    // Reject path traversal segments in optional suffix
    if suffix.contains("..") {
        return None;
    }

    let clean_suffix = if suffix == "/" { "" } else { suffix };
    Some(format!("browser://{}{}", spec.slug, clean_suffix))
}

/// Extracts `(canonical_slug, optional_suffix)` from an internal URL.
pub fn extract_internal_slug(raw: &str) -> Option<(&'static str, Option<String>)> {
    let norm = normalize_internal_url(raw)?;
    let rest = &norm["browser://".len()..];
    match rest.find(['/', '?', '#']) {
        Some(idx) => {
            let spec = find_internal_page(&rest[..idx])?;
            Some((spec.slug, Some(rest[idx..].to_string())))
        }
        None => {
            let spec = find_internal_page(rest)?;
            Some((spec.slug, None))
        }
    }
}

// ============================================================================
// 2. Render Context Models
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlagEntry {
    pub id: String,
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub default_enabled: bool,
    pub category: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuDiagnosticInfo {
    pub vendor: String,
    pub renderer: String,
    pub api_backend: String,
    pub refresh_rate_hz: u32,
    pub hardware_video_decode: bool,
    pub webgpu_enabled: bool,
    pub wgsl_black_hole_active: bool,
    pub oled_pure_black_verified: bool,
}

impl Default for GpuDiagnosticInfo {
    fn default() -> Self {
        Self {
            vendor: "Hardware Compositor".into(),
            renderer: "Singularity DirectComposition / Vulkan".into(),
            api_backend: "WebGPU / WGSL".into(),
            refresh_rate_hz: 200,
            hardware_video_decode: true,
            webgpu_enabled: true,
            wgsl_black_hole_active: true,
            oled_pure_black_verified: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEntry {
    pub pid: u32,
    pub kind: String,
    pub title: String,
    pub cpu_percent: f32,
    pub memory_mb: f64,
    pub gpu_mb: f64,
    pub hibernated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetDiagnosticEntry {
    pub timestamp: String,
    pub protocol: String,
    pub host: String,
    pub status: String,
    pub latency_ms: u32,
    pub via_mullvad: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrashReportEntry {
    pub id: String,
    pub timestamp: String,
    pub process_kind: String,
    pub reason: String,
    pub recovered_tabs: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentEntry {
    pub id: String,
    pub name: String,
    pub version: String,
    pub status: String,
    pub signature_verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxLayerEntry {
    pub layer: String,
    pub enabled: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaStreamEntry {
    pub tab_title: String,
    pub codec: String,
    pub resolution: String,
    pub hardware_decoded: bool,
    pub drm_system: Option<String>,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEntry {
    pub key: String,
    pub value: String,
    pub source: String,
    pub mandatory: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEventEntry {
    pub name: String,
    pub category: String,
    pub duration_ms: f64,
    pub ts_us: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistogramEntry {
    pub name: String,
    pub samples: u64,
    pub mean_ms: f64,
    pub p95_ms: f64,
    pub max_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TabDiscardEntry {
    pub tab_id: String,
    pub title: String,
    pub url: String,
    pub memory_mb: f64,
    pub idle_seconds: u64,
    pub discarded: bool,
    pub auto_discardable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InspectTargetEntry {
    pub id: String,
    pub target_type: String,
    pub title: String,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceSnapshot {
    pub fps_current: f32,
    pub fps_target: u32,
    pub frame_time_ms: f32,
    pub total_rss_mb: f64,
    pub active_tabs: usize,
    pub hibernated_tabs: usize,
    pub shield_blocked_session: u64,
}

impl Default for PerformanceSnapshot {
    fn default() -> Self {
        Self {
            fps_current: 200.0,
            fps_target: 200,
            frame_time_ms: 5.0,
            total_rss_mb: 184.0,
            active_tabs: 1,
            hibernated_tabs: 0,
            shield_blocked_session: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: String,
    pub level: String,
    pub source: String,
    pub target: String,
    pub rule: String,
    pub action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettingDiffEntry {
    pub key: String,
    pub default_value: String,
    pub current_value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PwaSummaryEntry {
    pub id: String,
    pub name: String,
    pub start_url: String,
    pub scope: String,
    pub open_in_window: bool,
    pub is_synthetic: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserscriptSummaryEntry {
    pub id: String,
    pub name: String,
    pub version: String,
    pub enabled: bool,
    pub matches: Vec<String>,
    pub risk_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertErrorContext {
    pub target_url: String,
    pub host: String,
    pub error_code: String,
    pub issuer: String,
    pub valid_range: String,
    pub spki_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpsWarningContext {
    pub target_url: String,
    pub host: String,
    pub reason: String,
}

/// Runtime data bag passed into [`render_internal_page_html`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalPageContext {
    pub language: String,
    pub api_token: String,
    pub api_base_url: String,
    pub app_version: String,
    pub engine_version: String,
    pub os_info: String,
    pub arch: String,
    pub profile_path: String,
    pub executable_path: String,
    pub flags: Vec<FlagEntry>,
    pub gpu_info: GpuDiagnosticInfo,
    pub processes: Vec<ProcessEntry>,
    pub net_events: Vec<NetDiagnosticEntry>,
    pub crashes: Vec<CrashReportEntry>,
    pub components: Vec<ComponentEntry>,
    pub sandbox_layers: Vec<SandboxLayerEntry>,
    pub media_streams: Vec<MediaStreamEntry>,
    pub policies: Vec<PolicyEntry>,
    pub trace_events: Vec<TraceEventEntry>,
    pub histograms: Vec<HistogramEntry>,
    pub tab_discards: Vec<TabDiscardEntry>,
    pub system_kv: Vec<(String, String)>,
    pub inspect_targets: Vec<InspectTargetEntry>,
    pub perf_metrics: PerformanceSnapshot,
    pub log_entries: Vec<LogEntry>,
    pub diff_entries: Vec<SettingDiffEntry>,
    pub pwa_apps: Vec<PwaSummaryEntry>,
    pub userscripts: Vec<UserscriptSummaryEntry>,
    pub cert_error: Option<CertErrorContext>,
    pub https_warning: Option<HttpsWarningContext>,
}

impl Default for InternalPageContext {
    fn default() -> Self {
        Self {
            language: "en".into(),
            api_token: String::new(),
            api_base_url: String::new(),
            app_version: env!("CARGO_PKG_VERSION").into(),
            engine_version: "Chromium/CEF + Singularity Rust Core".into(),
            os_info: std::env::consts::OS.into(),
            arch: std::env::consts::ARCH.into(),
            profile_path: "~/.singularity/profiles/default".into(),
            executable_path: "singularity".into(),
            flags: vec![
                FlagEntry {
                    id: "oled.pure_black_force".into(),
                    name: "OLED Pure Black (#000000) Surface Lock".into(),
                    description: "Forces pure zero-nit black surfaces across internal chrome and dark reader.".into(),
                    enabled: true,
                    default_enabled: true,
                    category: "Rendering".into(),
                },
                FlagEntry {
                    id: "net.https_only_strict".into(),
                    name: "Strict HTTPS-Only Upgrade Mode".into(),
                    description: "Upgrades all top-level requests to HTTPS and shows browser://https-warning on fallback.".into(),
                    enabled: true,
                    default_enabled: true,
                    category: "Security".into(),
                },
                FlagEntry {
                    id: "privacy.canvas_noise_per_origin".into(),
                    name: "Deterministic Per-Origin Canvas Fingerprint Noise".into(),
                    description: "Injects subtle session-seeded canvas/WebGL/AudioContext noise per eTLD+1.".into(),
                    enabled: true,
                    default_enabled: true,
                    category: "Privacy".into(),
                },
            ],
            gpu_info: GpuDiagnosticInfo::default(),
            processes: Vec::new(),
            net_events: Vec::new(),
            crashes: Vec::new(),
            components: vec![
                ComponentEntry {
                    id: "singularity-shield-lists".into(),
                    name: "Singularity Privacy Shield Filter Lists".into(),
                    version: "2026.11".into(),
                    status: "Up-to-date".into(),
                    signature_verified: true,
                },
                ComponentEntry {
                    id: "hsts-preload".into(),
                    name: "HSTS Preload List".into(),
                    version: "2026.11".into(),
                    status: "Active".into(),
                    signature_verified: true,
                },
                ComponentEntry {
                    id: "ed25519-updater-pubkey".into(),
                    name: "Ed25519 Signed Release Verifier".into(),
                    version: env!("CARGO_PKG_VERSION").into(),
                    status: "Pinned".into(),
                    signature_verified: true,
                },
            ],
            sandbox_layers: vec![
                SandboxLayerEntry {
                    layer: "Renderer Process Sandbox".into(),
                    enabled: true,
                    detail: "Restricted token / seccomp-bpf isolation active".into(),
                },
                SandboxLayerEntry {
                    layer: "Strict Site Isolation (OOPIF)".into(),
                    enabled: true,
                    detail: "Each eTLD+1 origin isolated into its own renderer process".into(),
                },
                SandboxLayerEntry {
                    layer: "Constant-Time IPC Token Guard".into(),
                    enabled: true,
                    detail: "X-Singularity-Token verified in constant time per session".into(),
                },
                SandboxLayerEntry {
                    layer: "Zero-Knowledge Argon2id + XChaCha20 Vault".into(),
                    enabled: true,
                    detail: "Master key zeroized on lock; never exposed to page JS".into(),
                },
            ],
            media_streams: Vec::new(),
            policies: vec![
                PolicyEntry {
                    key: "telemetry.upload_enabled".into(),
                    value: "false".into(),
                    source: "Hardened Built-in".into(),
                    mandatory: true,
                },
                PolicyEntry {
                    key: "webrtc.ip_handling_policy".into(),
                    value: "disable_non_proxied_udp".into(),
                    source: "Privacy Default".into(),
                    mandatory: false,
                },
            ],
            trace_events: Vec::new(),
            histograms: Vec::new(),
            tab_discards: Vec::new(),
            system_kv: vec![
                ("OS".into(), std::env::consts::OS.into()),
                ("Architecture".into(), std::env::consts::ARCH.into()),
                ("Family".into(), std::env::consts::FAMILY.into()),
                ("Singularity Version".into(), env!("CARGO_PKG_VERSION").into()),
            ],
            inspect_targets: Vec::new(),
            perf_metrics: PerformanceSnapshot::default(),
            log_entries: Vec::new(),
            diff_entries: Vec::new(),
            pwa_apps: Vec::new(),
            userscripts: Vec::new(),
            cert_error: None,
            https_warning: None,
        }
    }
}

// ============================================================================
// 3. Escaping & OLED Pure Black HTML Page Generator
// ============================================================================

/// Strictly escapes HTML special characters to prevent XSS in text and attribute contexts.
pub fn html_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

/// Escapes a JSON string so it can be embedded safely inside an inline `<script>` tag.
fn safe_json_for_script(json: &str) -> String {
    json.replace('<', "\\u003C")
        .replace('>', "\\u003E")
        .replace('&', "\\u0026")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}

/// Renders a complete, self-contained, OLED Pure Black (`#000000`) interactive HTML document
/// for any of the 25 supported diagnostic, management, and security-interstitial internal pages.
///
/// Accepts either a canonical slug (`"process-manager"`), an alias (`"task-manager"`), or a
/// full internal URL (`"chrome://gpu"`, `"singularity://flags"`). Returns `None` for unknown
/// slugs or pages handled directly by the native shell chrome.
pub fn render_internal_page_html(slug_or_url: &str, ctx: &InternalPageContext) -> Option<String> {
    let canonical = if slug_or_url.contains("://") {
        extract_internal_slug(slug_or_url)?.0
    } else {
        find_internal_page(slug_or_url)?.slug
    };
    let spec = find_internal_page(canonical)?;
    let is_fr = ctx.language.trim().to_ascii_lowercase().starts_with("fr");

    let (body_html, export_json, page_script) = match canonical {
        "urls" => render_urls_body(is_fr),
        "version" => render_version_body(ctx, is_fr),
        "flags" => render_flags_body(ctx, is_fr),
        "gpu" => render_gpu_body(ctx, is_fr),
        "process-manager" => render_process_manager_body(ctx, is_fr),
        "net-internals" => render_net_internals_body(ctx, is_fr),
        "crashes" => render_crashes_body(ctx, is_fr),
        "components" => render_components_body(ctx, is_fr),
        "sandbox" => render_sandbox_body(ctx, is_fr),
        "media-internals" => render_media_internals_body(ctx, is_fr),
        "policy" => render_policy_body(ctx, is_fr),
        "tracing" => render_tracing_body(ctx, is_fr),
        "histograms" => render_histograms_body(ctx, is_fr),
        "discards" => render_discards_body(ctx, is_fr),
        "system" => render_system_body(ctx, is_fr),
        "credits" => render_credits_body(is_fr),
        "omnibox" => render_omnibox_body(is_fr),
        "inspect" => render_inspect_body(ctx, is_fr),
        "performance" => render_performance_body(ctx, is_fr),
        "logger" => render_logger_body(ctx, is_fr),
        "diff" => render_diff_body(ctx, is_fr),
        "apps" => render_apps_body(ctx, is_fr),
        "userscripts" => render_userscripts_body(ctx, is_fr),
        "cert-error" => render_cert_error_body(ctx, is_fr),
        "https-warning" => render_https_warning_body(ctx, is_fr),
        _ => return None,
    };

    let title = if is_fr { spec.title_fr } else { spec.title_en };
    let desc = if is_fr {
        spec.description_fr
    } else {
        spec.description_en
    };

    Some(wrap_oled_shell(
        canonical,
        title,
        desc,
        &body_html,
        &export_json,
        &page_script,
        ctx,
        is_fr,
    ))
}

#[allow(clippy::too_many_arguments)]
fn wrap_oled_shell(
    slug: &str,
    title: &str,
    description: &str,
    body_html: &str,
    export_json: &str,
    page_script: &str,
    ctx: &InternalPageContext,
    is_fr: bool,
) -> String {
    let lang = if is_fr { "fr" } else { "en" };
    let filter_ph = if is_fr {
        "Filtrer cette page..."
    } else {
        "Filter this page..."
    };
    let copy_lbl = if is_fr { "Copier JSON" } else { "Copy JSON" };
    let export_lbl = if is_fr { "Exporter JSON" } else { "Export JSON" };
    let all_urls_lbl = if is_fr {
        "Toutes les URLs"
    } else {
        "All URLs"
    };
    let token_json = safe_json_for_script(
        &serde_json::to_string(&ctx.api_token).unwrap_or_else(|_| "\"\"".into()),
    );
    let api_base_json = safe_json_for_script(
        &serde_json::to_string(&ctx.api_base_url).unwrap_or_else(|_| "\"\"".into()),
    );
    let export_payload_js = safe_json_for_script(export_json);

    format!(
        r#"<!DOCTYPE html>
<html lang="{lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'self' 'nonce-__CSP_NONCE__'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none';">
<title>browser://{slug} — {title}</title>
<style>
:root {{
  --bg: #000000;
  --surface: #0C0D12;
  --surface-hover: #13151D;
  --border: #1A1B20;
  --text: #F5F3EE;
  --muted: #8E919B;
  --gold: #F0B254;
  --cyan: #38D9F5;
  --violet: #B975FF;
  --ok: #22C55E;
  --warn: #F59E0B;
  --danger: #EF4444;
}}
* {{ box-sizing: border-box; }}
html, body {{
  margin: 0; padding: 0;
  background: var(--bg); color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", "Segoe UI", system-ui, sans-serif;
  font-size: 14px; line-height: 1.5;
}}
a {{ color: var(--cyan); text-decoration: none; }}
a:hover {{ text-decoration: underline; }}
code, pre {{
  font-family: "SF Mono", "Cascadia Code", Consolas, ui-monospace, monospace;
}}
.sg-wrap {{ max-width: 1180px; margin: 0 auto; padding: 28px 24px 64px; }}
.sg-header {{
  display: flex; flex-wrap: wrap; align-items: flex-start; justify-content: space-between;
  gap: 16px; padding-bottom: 18px; border-bottom: 1px solid var(--border); margin-bottom: 22px;
}}
.sg-badge {{
  display: inline-block; padding: 3px 9px; border-radius: 999px;
  font-size: 11px; font-weight: 600; letter-spacing: 0.04em;
  background: rgba(240,178,84,0.12); color: var(--gold); border: 1px solid rgba(240,178,84,0.32);
}}
.sg-badge.ok {{ background: rgba(34,197,94,0.12); color: var(--ok); border-color: rgba(34,197,94,0.35); }}
.sg-badge.warn {{ background: rgba(245,158,11,0.12); color: var(--warn); border-color: rgba(245,158,11,0.35); }}
.sg-badge.danger {{ background: rgba(239,68,68,0.14); color: var(--danger); border-color: rgba(239,68,68,0.4); }}
.sg-badge.cyan {{ background: rgba(56,217,245,0.12); color: var(--cyan); border-color: rgba(56,217,245,0.35); }}
h1 {{ margin: 8px 0 4px; font-size: 24px; font-weight: 700; letter-spacing: -0.02em; }}
.sg-desc {{ margin: 0; color: var(--muted); font-size: 13px; }}
.sg-toolbar {{
  display: flex; flex-wrap: wrap; align-items: center; gap: 10px;
}}
.sg-input {{
  background: var(--surface); color: var(--text);
  border: 1px solid var(--border); border-radius: 8px;
  padding: 8px 12px; min-width: 240px; outline: none;
}}
.sg-input:focus {{ border-color: var(--gold); }}
.sg-btn {{
  background: var(--surface); color: var(--text);
  border: 1px solid var(--border); border-radius: 8px;
  padding: 8px 13px; cursor: pointer; font-size: 12.5px; font-weight: 600;
}}
.sg-btn:hover {{ background: var(--surface-hover); border-color: var(--gold); }}
.sg-btn.primary {{ background: rgba(240,178,84,0.16); border-color: var(--gold); color: var(--gold); }}
.sg-btn.danger {{ background: rgba(239,68,68,0.16); border-color: var(--danger); color: var(--danger); }}
.sg-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(290px, 1fr)); gap: 14px; }}
.sg-card {{
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 12px; padding: 16px;
}}
.sg-card h2, .sg-card h3 {{ margin: 0 0 8px; font-size: 15px; }}
.sg-table {{ width: 100%; border-collapse: collapse; background: var(--surface); border-radius: 12px; overflow: hidden; border: 1px solid var(--border); }}
.sg-table th, .sg-table td {{ padding: 10px 12px; text-align: left; border-bottom: 1px solid var(--border); font-size: 13px; }}
.sg-table th {{ color: var(--muted); font-weight: 600; font-size: 11.5px; text-transform: uppercase; letter-spacing: 0.05em; }}
.sg-table tr:hover td {{ background: var(--surface-hover); }}
.sg-toast {{
  position: fixed; bottom: 20px; right: 20px;
  background: #0C0D12; color: var(--gold); border: 1px solid var(--gold);
  padding: 9px 14px; border-radius: 10px; font-size: 12.5px; display: none; z-index: 99;
}}
.sg-interstitial {{
  max-width: 680px; margin: 36px auto; background: var(--surface);
  border: 1px solid var(--danger); border-radius: 14px; padding: 28px;
}}
.sg-muted {{ color: var(--muted); }}
.sg-kv {{ display: grid; grid-template-columns: 220px 1fr; gap: 8px 16px; }}
.sg-kv dt {{ color: var(--muted); font-weight: 600; }}
.sg-kv dd {{ margin: 0; word-break: break-all; }}
</style>
</head>
<body data-page="{slug}">
<div class="sg-wrap">
  <header class="sg-header">
    <div>
      <span class="sg-badge">browser://{slug}</span>
      <h1>{title}</h1>
      <p class="sg-desc">{description}</p>
    </div>
    <div class="sg-toolbar">
      <input id="sg-filter" class="sg-input" type="search" placeholder="{filter_ph}" autocomplete="off">
      <button id="sg-copy-json" class="sg-btn" type="button">{copy_lbl}</button>
      <button id="sg-export-json" class="sg-btn" type="button">{export_lbl}</button>
      <a class="sg-btn" href="browser://urls">{all_urls_lbl}</a>
    </div>
  </header>
  <main id="sg-main">
    {body_html}
  </main>
</div>
<div id="sg-toast" class="sg-toast" role="status"></div>
<script nonce="__CSP_NONCE__">
(function() {{
  "use strict";
  const SG_TOKEN = {token_json};
  const SG_API_BASE = {api_base_json};
  const SG_SLUG = "{slug}";
  const SG_DATA = {export_payload_js};

  function showToast(msg) {{
    const el = document.getElementById("sg-toast");
    if (!el) return;
    el.textContent = String(msg);
    el.style.display = "block";
    clearTimeout(el.__t);
    el.__t = setTimeout(() => {{ el.style.display = "none"; }}, 2600);
  }}

  const __sgPendingReqs = new Map();
  let __sgReqSeq = 0;

  window.addEventListener("message", (ev) => {{
    const msg = ev && ev.data;
    if (!msg || msg.type !== "sg-internal-api-reply" || !msg.reqId) return;
    const entry = __sgPendingReqs.get(msg.reqId);
    if (!entry) return;
    __sgPendingReqs.delete(msg.reqId);
    clearTimeout(entry.timer);
    entry.resolve(msg);
  }});

  window.sgApi = async function(path, method, payload) {{
    const m = method || "POST";
    if (window.parent && window.parent !== window && window.location.origin === "null") {{
      const reqId = "sg-" + (++__sgReqSeq) + "-" + Date.now();
      return new Promise((resolve) => {{
        const timer = setTimeout(() => {{
          __sgPendingReqs.delete(reqId);
          showToast("API timeout: " + path);
          resolve({{ ok: false, status: 504, text: "Request timed out" }});
        }}, 15000);
        __sgPendingReqs.set(reqId, {{
          timer,
          resolve: (reply) => {{
            const ok = Boolean(reply.ok);
            const status = typeof reply.status === "number" ? reply.status : (ok ? 200 : 500);
            const txt = reply.error
              ? String(reply.error)
              : (typeof reply.data === "string"
                  ? reply.data
                  : (reply.data !== undefined ? JSON.stringify(reply.data) : ""));
            showToast(ok ? ("OK: " + path) : ("HTTP " + status + ": " + txt.slice(0, 120)));
            resolve({{ ok, status, text: txt, data: reply.data }});
          }},
        }});
        window.parent.postMessage(
          {{ type: "sg-internal-api", reqId, method: m, path, body: payload }},
          "*"
        );
      }});
    }}
    const headers = {{ "Content-Type": "application/json" }};
    if (SG_TOKEN) headers["X-Singularity-Token"] = SG_TOKEN;
    try {{
      const res = await fetch(SG_API_BASE + path, {{
        method: m,
        headers,
        body: (m.toUpperCase() !== "GET" && payload !== undefined) ? JSON.stringify(payload) : undefined,
      }});
      const txt = await res.text();
      showToast(res.ok ? ("OK: " + path) : ("HTTP " + res.status + ": " + txt.slice(0, 120)));
      return {{ ok: res.ok, status: res.status, text: txt }};
    }} catch (err) {{
      showToast("API error: " + String(err));
      return {{ ok: false, status: 0, text: String(err) }};
    }}
  }};

  const filterEl = document.getElementById("sg-filter");
  if (filterEl) {{
    filterEl.addEventListener("input", () => {{
      const q = filterEl.value.trim().toLowerCase();
      document.querySelectorAll("[data-filterable]").forEach((node) => {{
        const hay = (node.getAttribute("data-filterable") || node.textContent || "").toLowerCase();
        node.style.display = !q || hay.includes(q) ? "" : "none";
      }});
    }});
  }}

  const copyBtn = document.getElementById("sg-copy-json");
  if (copyBtn) {{
    copyBtn.addEventListener("click", async () => {{
      const txt = JSON.stringify(SG_DATA, null, 2);
      try {{
        await navigator.clipboard.writeText(txt);
        showToast("JSON copied");
      }} catch (_) {{
        showToast("Clipboard unavailable");
      }}
    }});
  }}

  const exportBtn = document.getElementById("sg-export-json");
  if (exportBtn) {{
    exportBtn.addEventListener("click", () => {{
      const blob = new Blob([JSON.stringify(SG_DATA, null, 2)], {{ type: "application/json" }});
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "singularity-" + SG_SLUG + ".json";
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      showToast("Exported singularity-" + SG_SLUG + ".json");
    }});
  }}

  document.addEventListener("click", (ev) => {{
    const backBtn = ev.target.closest("[data-action=\"history-back\"]");
    if (backBtn) {{
      history.back();
      return;
    }}
    const btn = ev.target.closest("[data-api-action]");
    if (!btn) return;
    const path = btn.getAttribute("data-api-action");
    const method = btn.getAttribute("data-api-method") || "POST";
    const rawPayload = btn.getAttribute("data-api-payload");
    let payload = undefined;
    if (method.toUpperCase() !== "GET" && rawPayload) {{
      try {{ payload = JSON.parse(rawPayload); }} catch (_) {{ payload = rawPayload; }}
    }}
    window.sgApi(path, method, payload);
  }});

  {page_script}
}})();
</script>
</body>
</html>
"#,
        lang = lang,
        slug = html_escape(slug),
        title = html_escape(title),
        description = html_escape(description),
        filter_ph = html_escape(filter_ph),
        copy_lbl = html_escape(copy_lbl),
        export_lbl = html_escape(export_lbl),
        all_urls_lbl = html_escape(all_urls_lbl),
        body_html = body_html,
        token_json = token_json,
        api_base_json = api_base_json,
        export_payload_js = export_payload_js,
        page_script = page_script,
    )
}

// --- Per-page Body Builders ---

fn render_urls_body(is_fr: bool) -> (String, String, String) {
    let mut cards = String::from("<div class=\"sg-grid\">");
    let mut export_list = Vec::new();
    for spec in INTERNAL_PAGE_REGISTRY {
        let title = if is_fr { spec.title_fr } else { spec.title_en };
        let desc = if is_fr {
            spec.description_fr
        } else {
            spec.description_en
        };
        let cat = if is_fr {
            spec.category.label_fr()
        } else {
            spec.category.label_en()
        };
        let hay = format!("{} {} {} {}", spec.slug, title, desc, spec.aliases.join(" "));
        cards.push_str(&format!(
            "<div class=\"sg-card\" data-filterable=\"{hay}\">\
             <span class=\"sg-badge cyan\">{cat}</span>\
             <h3><a href=\"browser://{slug}\">browser://{slug}</a></h3>\
             <div style=\"font-weight:600;margin-bottom:4px\">{title}</div>\
             <p class=\"sg-desc\">{desc}</p>\
             </div>",
            hay = html_escape(&hay),
            cat = html_escape(cat),
            slug = html_escape(spec.slug),
            title = html_escape(title),
            desc = html_escape(desc),
        ));
        export_list.push(serde_json::json!({
            "url": format!("browser://{}", spec.slug),
            "title": title,
            "category": cat,
            "aliases": spec.aliases,
        }));
    }
    cards.push_str("</div>");
    (cards, serde_json::json!(export_list).to_string(), String::new())
}

fn render_version_body(ctx: &InternalPageContext, is_fr: bool) -> (String, String, String) {
    let rows = [
        ("Singularity", ctx.app_version.as_str()),
        (if is_fr { "Moteur" } else { "Engine" }, ctx.engine_version.as_str()),
        ("OS", ctx.os_info.as_str()),
        ("Arch", ctx.arch.as_str()),
        (if is_fr { "Profil actif" } else { "Profile Path" }, ctx.profile_path.as_str()),
        (if is_fr { "Exécutable" } else { "Executable" }, ctx.executable_path.as_str()),
        ("License", "MPL-2.0 (100% Zero-Telemetry)"),
    ];
    let mut html = String::from("<div class=\"sg-card\"><dl class=\"sg-kv\">");
    for (k, v) in rows {
        html.push_str(&format!(
            "<dt data-filterable=\"{k} {v}\">{k}</dt><dd data-filterable=\"{k} {v}\"><code>{v}</code></dd>",
            k = html_escape(k),
            v = html_escape(v),
        ));
    }
    html.push_str("</dl></div>");
    let export = serde_json::json!({
        "app_version": ctx.app_version,
        "engine_version": ctx.engine_version,
        "os": ctx.os_info,
        "arch": ctx.arch,
        "profile_path": ctx.profile_path,
        "executable_path": ctx.executable_path,
    })
    .to_string();
    (html, export, String::new())
}

fn render_flags_body(ctx: &InternalPageContext, is_fr: bool) -> (String, String, String) {
    let reset_lbl = if is_fr {
        "Tout réinitialiser par défaut"
    } else {
        "Reset All Flags to Default"
    };
    let mut html = format!(
        "<div style=\"margin-bottom:14px\">\
         <button class=\"sg-btn danger\" data-api-action=\"/api/flags/reset_all\" data-api-payload=\"{{}}\">{}</button>\
         </div><div class=\"sg-grid\">",
        html_escape(reset_lbl)
    );
    for flag in &ctx.flags {
        let next_idx: u64 = if flag.enabled { 0 } else { 1 };
        let payload = serde_json::json!({ "id": flag.id, "option_index": next_idx }).to_string();
        let state_badge = if flag.enabled {
            "<span class=\"sg-badge ok\">ENABLED</span>"
        } else {
            "<span class=\"sg-badge warn\">DISABLED</span>"
        };
        let toggle_lbl = if flag.enabled {
            if is_fr { "Désactiver" } else { "Disable" }
        } else if is_fr {
            "Activer"
        } else {
            "Enable"
        };
        html.push_str(&format!(
            "<div class=\"sg-card\" data-filterable=\"{id} {name} {desc} {cat}\">\
             <div style=\"display:flex;justify-content:space-between;align-items:center;gap:8px\">\
             <span class=\"sg-badge cyan\">{cat}</span>{state_badge}</div>\
             <h3 style=\"margin-top:8px\">{name}</h3>\
             <p class=\"sg-desc\" style=\"margin-bottom:10px\">{desc}</p>\
             <div style=\"display:flex;justify-content:space-between;align-items:center\">\
             <code class=\"sg-muted\">{id}</code>\
             <button class=\"sg-btn primary\" data-api-action=\"/api/flags/set\" data-api-payload=\"{payload}\">{toggle_lbl}</button>\
             </div></div>",
            id = html_escape(&flag.id),
            name = html_escape(&flag.name),
            desc = html_escape(&flag.description),
            cat = html_escape(&flag.category),
            state_badge = state_badge,
            payload = html_escape(&payload),
            toggle_lbl = html_escape(toggle_lbl),
        ));
    }
    html.push_str("</div>");
    let export = serde_json::to_string(&ctx.flags).unwrap_or_else(|_| "[]".into());
    (html, export, String::new())
}

fn render_gpu_body(ctx: &InternalPageContext, _is_fr: bool) -> (String, String, String) {
    let g = &ctx.gpu_info;
    let bool_badge = |ok: bool| {
        if ok {
            "<span class=\"sg-badge ok\">ACTIVE</span>"
        } else {
            "<span class=\"sg-badge warn\">SOFTWARE</span>"
        }
    };
    let html = format!(
        "<div class=\"sg-card\"><dl class=\"sg-kv\">\
         <dt>Vendor</dt><dd>{vendor}</dd>\
         <dt>Renderer</dt><dd>{renderer}</dd>\
         <dt>Backend API</dt><dd>{api}</dd>\
         <dt>Target Refresh Rate</dt><dd><strong>{hz} Hz</strong></dd>\
         <dt>Hardware Video Decode</dt><dd>{hwdec}</dd>\
         <dt>WebGPU Pipeline</dt><dd>{webgpu}</dd>\
         <dt>WGSL Black Hole Shader</dt><dd>{wgsl}</dd>\
         <dt>OLED Pure Black (#000000)</dt><dd>{oled}</dd>\
         </dl></div>",
        vendor = html_escape(&g.vendor),
        renderer = html_escape(&g.renderer),
        api = html_escape(&g.api_backend),
        hz = g.refresh_rate_hz,
        hwdec = bool_badge(g.hardware_video_decode),
        webgpu = bool_badge(g.webgpu_enabled),
        wgsl = bool_badge(g.wgsl_black_hole_active),
        oled = bool_badge(g.oled_pure_black_verified),
    );
    let export = serde_json::to_string(g).unwrap_or_else(|_| "{}".into());
    (html, export, String::new())
}

fn render_process_manager_body(ctx: &InternalPageContext, is_fr: bool) -> (String, String, String) {
    let mut html = String::from(
        "<table class=\"sg-table\"><thead><tr>\
         <th>PID</th><th>Type</th><th>Title</th><th>CPU %</th><th>RAM (MB)</th><th>GPU (MB)</th><th>Actions</th>\
         </tr></thead><tbody>",
    );
    for p in &ctx.processes {
        let kill_payload = serde_json::json!({ "pid": p.pid, "action": "terminate" }).to_string();
        let sleep_payload = serde_json::json!({ "pid": p.pid, "action": "hibernate" }).to_string();
        let sleep_lbl = if is_fr { "Veille" } else { "Hibernate" };
        let kill_lbl = if is_fr { "Terminer" } else { "End Process" };
        html.push_str(&format!(
            "<tr data-filterable=\"{pid} {kind} {title}\">\
             <td><code>{pid}</code></td>\
             <td><span class=\"sg-badge cyan\">{kind}</span></td>\
             <td>{title}</td>\
             <td>{cpu:.1}%</td>\
             <td>{ram:.1}</td>\
             <td>{gpu:.1}</td>\
             <td>\
               <button class=\"sg-btn\" data-api-action=\"/api/process/action\" data-api-payload=\"{sleep_payload}\">{sleep_lbl}</button> \
               <button class=\"sg-btn danger\" data-api-action=\"/api/process/action\" data-api-payload=\"{kill_payload}\">{kill_lbl}</button>\
             </td></tr>",
            pid = p.pid,
            kind = html_escape(&p.kind),
            title = html_escape(&p.title),
            cpu = p.cpu_percent,
            ram = p.memory_mb,
            gpu = p.gpu_mb,
            sleep_payload = html_escape(&sleep_payload),
            sleep_lbl = html_escape(sleep_lbl),
            kill_payload = html_escape(&kill_payload),
            kill_lbl = html_escape(kill_lbl),
        ));
    }
    if ctx.processes.is_empty() {
        html.push_str("<tr><td colspan=\"7\" class=\"sg-muted\">No live child processes reported yet.</td></tr>");
    }
    html.push_str("</tbody></table>");
    let export = serde_json::to_string(&ctx.processes).unwrap_or_else(|_| "[]".into());
    (html, export, String::new())
}

fn render_net_internals_body(ctx: &InternalPageContext, is_fr: bool) -> (String, String, String) {
    let flush_lbl = if is_fr { "Vider le cache DNS" } else { "Flush DNS Cache" };
    let mut html = format!(
        "<div style=\"margin-bottom:14px\">\
         <button class=\"sg-btn primary\" data-api-action=\"/api/dns/clear_cache\" data-api-payload=\"{{}}\">{}</button>\
         </div>\
         <table class=\"sg-table\"><thead><tr>\
         <th>Time</th><th>Protocol</th><th>Host</th><th>Status</th><th>Latency</th><th>Mullvad</th>\
         </tr></thead><tbody>",
        html_escape(flush_lbl)
    );
    for e in &ctx.net_events {
        let vpn = if e.via_mullvad {
            "<span class=\"sg-badge ok\">WIREGUARD</span>"
        } else {
            "<span class=\"sg-badge\">DIRECT</span>"
        };
        html.push_str(&format!(
            "<tr data-filterable=\"{proto} {host} {status}\">\
             <td><code>{ts}</code></td><td>{proto}</td><td><code>{host}</code></td>\
             <td>{status}</td><td>{lat} ms</td><td>{vpn}</td></tr>",
            ts = html_escape(&e.timestamp),
            proto = html_escape(&e.protocol),
            host = html_escape(&e.host),
            status = html_escape(&e.status),
            lat = e.latency_ms,
            vpn = vpn,
        ));
    }
    if ctx.net_events.is_empty() {
        html.push_str("<tr><td colspan=\"6\" class=\"sg-muted\">No recent network socket events recorded.</td></tr>");
    }
    html.push_str("</tbody></table>");
    let export = serde_json::to_string(&ctx.net_events).unwrap_or_else(|_| "[]".into());
    (html, export, String::new())
}

fn render_crashes_body(ctx: &InternalPageContext, _is_fr: bool) -> (String, String, String) {
    let mut html = String::from(
        "<div style=\"margin-bottom:14px\">\
         <button class=\"sg-btn danger\" data-api-action=\"/api/crashes/purge\" data-api-payload=\"{}\">Clear Local Crash Journal</button>\
         </div><table class=\"sg-table\"><thead><tr>\
         <th>ID</th><th>Timestamp</th><th>Process</th><th>Reason</th><th>Recovered Tabs</th>\
         </tr></thead><tbody>",
    );
    for c in &ctx.crashes {
        html.push_str(&format!(
            "<tr data-filterable=\"{id} {proc} {reason}\">\
             <td><code>{id}</code></td><td>{ts}</td><td>{proc}</td><td>{reason}</td><td>{tabs}</td></tr>",
            id = html_escape(&c.id),
            ts = html_escape(&c.timestamp),
            proc = html_escape(&c.process_kind),
            reason = html_escape(&c.reason),
            tabs = c.recovered_tabs,
        ));
    }
    if ctx.crashes.is_empty() {
        html.push_str("<tr><td colspan=\"5\" class=\"sg-muted\">Zero crashes recorded. Local-only Crash Guard active.</td></tr>");
    }
    html.push_str("</tbody></table>");
    let export = serde_json::to_string(&ctx.crashes).unwrap_or_else(|_| "[]".into());
    (html, export, String::new())
}

fn render_components_body(ctx: &InternalPageContext, _is_fr: bool) -> (String, String, String) {
    let mut html = String::from("<div class=\"sg-grid\">");
    for c in &ctx.components {
        let sig = if c.signature_verified {
            "<span class=\"sg-badge ok\">ED25519 VERIFIED</span>"
        } else {
            "<span class=\"sg-badge warn\">UNVERIFIED</span>"
        };
        html.push_str(&format!(
            "<div class=\"sg-card\" data-filterable=\"{id} {name} {ver}\">\
             <div style=\"display:flex;justify-content:space-between;align-items:center\">\
             <span class=\"sg-badge cyan\">v{ver}</span>{sig}</div>\
             <h3 style=\"margin-top:8px\">{name}</h3>\
             <p class=\"sg-desc\">Status: {status}</p>\
             <button class=\"sg-btn\" style=\"margin-top:10px\" data-api-action=\"/api/internal/components\" data-api-method=\"GET\">Check Update</button>\
             </div>",
            id = html_escape(&c.id),
            name = html_escape(&c.name),
            ver = html_escape(&c.version),
            sig = sig,
            status = html_escape(&c.status),
        ));
    }
    html.push_str("</div>");
    let export = serde_json::to_string(&ctx.components).unwrap_or_else(|_| "[]".into());
    (html, export, String::new())
}

fn render_sandbox_body(ctx: &InternalPageContext, _is_fr: bool) -> (String, String, String) {
    let mut html = String::from("<div class=\"sg-grid\">");
    for s in &ctx.sandbox_layers {
        let badge = if s.enabled {
            "<span class=\"sg-badge ok\">ENFORCED</span>"
        } else {
            "<span class=\"sg-badge danger\">DISABLED</span>"
        };
        html.push_str(&format!(
            "<div class=\"sg-card\" data-filterable=\"{layer} {detail}\">\
             {badge}<h3 style=\"margin-top:8px\">{layer}</h3><p class=\"sg-desc\">{detail}</p></div>",
            badge = badge,
            layer = html_escape(&s.layer),
            detail = html_escape(&s.detail),
        ));
    }
    html.push_str("</div>");
    let export = serde_json::to_string(&ctx.sandbox_layers).unwrap_or_else(|_| "[]".into());
    (html, export, String::new())
}

fn render_media_internals_body(ctx: &InternalPageContext, _is_fr: bool) -> (String, String, String) {
    let mut html = String::from(
        "<table class=\"sg-table\"><thead><tr>\
         <th>Tab</th><th>Codec</th><th>Resolution</th><th>HW Decode</th><th>DRM</th><th>State</th>\
         </tr></thead><tbody>",
    );
    for m in &ctx.media_streams {
        let hw = if m.hardware_decoded { "GPU" } else { "CPU" };
        let drm = m.drm_system.as_deref().unwrap_or("None");
        html.push_str(&format!(
            "<tr data-filterable=\"{tab} {codec} {drm}\">\
             <td>{tab}</td><td><code>{codec}</code></td><td>{res}</td><td>{hw}</td><td>{drm}</td><td>{state}</td></tr>",
            tab = html_escape(&m.tab_title),
            codec = html_escape(&m.codec),
            res = html_escape(&m.resolution),
            hw = hw,
            drm = html_escape(drm),
            state = html_escape(&m.state),
        ));
    }
    if ctx.media_streams.is_empty() {
        html.push_str("<tr><td colspan=\"6\" class=\"sg-muted\">No active audio/video playback pipelines.</td></tr>");
    }
    html.push_str("</tbody></table>");
    let export = serde_json::to_string(&ctx.media_streams).unwrap_or_else(|_| "[]".into());
    (html, export, String::new())
}

fn render_policy_body(ctx: &InternalPageContext, _is_fr: bool) -> (String, String, String) {
    let mut html = String::from(
        "<table class=\"sg-table\"><thead><tr>\
         <th>Policy Key</th><th>Value</th><th>Source</th><th>Enforcement</th>\
         </tr></thead><tbody>",
    );
    for p in &ctx.policies {
        let enf = if p.mandatory {
            "<span class=\"sg-badge ok\">MANDATORY</span>"
        } else {
            "<span class=\"sg-badge cyan\">RECOMMENDED</span>"
        };
        html.push_str(&format!(
            "<tr data-filterable=\"{k} {v} {s}\">\
             <td><code>{k}</code></td><td><code>{v}</code></td><td>{s}</td><td>{enf}</td></tr>",
            k = html_escape(&p.key),
            v = html_escape(&p.value),
            s = html_escape(&p.source),
            enf = enf,
        ));
    }
    html.push_str("</tbody></table>");
    let export = serde_json::to_string(&ctx.policies).unwrap_or_else(|_| "[]".into());
    (html, export, String::new())
}

fn render_tracing_body(ctx: &InternalPageContext, is_fr: bool) -> (String, String, String) {
    let start_lbl = if is_fr { "Démarrer Trace" } else { "Start Trace" };
    let stop_lbl = if is_fr { "Arrêter Trace" } else { "Stop Trace" };
    let mut html = format!(
        "<div style=\"margin-bottom:14px;display:flex;gap:10px\">\
         <button class=\"sg-btn primary\" data-api-action=\"/api/tracing/toggle\" data-api-payload='{{\"active\":true}}'>{start}</button>\
         <button class=\"sg-btn\" data-api-action=\"/api/tracing/toggle\" data-api-payload='{{\"active\":false}}'>{stop}</button>\
         </div><table class=\"sg-table\"><thead><tr>\
         <th>Event</th><th>Category</th><th>Duration (ms)</th><th>Timestamp (us)</th>\
         </tr></thead><tbody>",
        start = html_escape(start_lbl),
        stop = html_escape(stop_lbl),
    );
    for t in &ctx.trace_events {
        html.push_str(&format!(
            "<tr data-filterable=\"{n} {c}\"><td>{n}</td><td>{c}</td><td>{d:.3}</td><td><code>{ts}</code></td></tr>",
            n = html_escape(&t.name),
            c = html_escape(&t.category),
            d = t.duration_ms,
            ts = t.ts_us,
        ));
    }
    if ctx.trace_events.is_empty() {
        html.push_str("<tr><td colspan=\"4\" class=\"sg-muted\">Click Start Trace to record local frame & IPC spans.</td></tr>");
    }
    html.push_str("</tbody></table>");
    let export = serde_json::to_string(&ctx.trace_events).unwrap_or_else(|_| "[]".into());
    (html, export, String::new())
}

fn render_histograms_body(ctx: &InternalPageContext, _is_fr: bool) -> (String, String, String) {
    let mut html = String::from(
        "<table class=\"sg-table\"><thead><tr>\
         <th>Histogram</th><th>Samples</th><th>Mean (ms)</th><th>P95 (ms)</th><th>Max (ms)</th>\
         </tr></thead><tbody>",
    );
    for h in &ctx.histograms {
        html.push_str(&format!(
            "<tr data-filterable=\"{n}\"><td><code>{n}</code></td><td>{s}</td><td>{m:.2}</td><td>{p95:.2}</td><td>{max:.2}</td></tr>",
            n = html_escape(&h.name),
            s = h.samples,
            m = h.mean_ms,
            p95 = h.p95_ms,
            max = h.max_ms,
        ));
    }
    if ctx.histograms.is_empty() {
        html.push_str("<tr><td colspan=\"5\" class=\"sg-muted\">No local histogram samples collected yet.</td></tr>");
    }
    html.push_str("</tbody></table>");
    let export = serde_json::to_string(&ctx.histograms).unwrap_or_else(|_| "[]".into());
    (html, export, String::new())
}

fn render_discards_body(ctx: &InternalPageContext, is_fr: bool) -> (String, String, String) {
    let discard_lbl = if is_fr { "Mettre en veille" } else { "Discard Now" };
    let mut html = String::from(
        "<table class=\"sg-table\"><thead><tr>\
         <th>Tab</th><th>RAM (MB)</th><th>Idle (s)</th><th>State</th><th>Action</th>\
         </tr></thead><tbody>",
    );
    for d in &ctx.tab_discards {
        let payload = serde_json::json!({ "tab_id": d.tab_id }).to_string();
        let badge = if d.discarded {
            "<span class=\"sg-badge ok\">HIBERNATED</span>"
        } else {
            "<span class=\"sg-badge cyan\">ACTIVE</span>"
        };
        html.push_str(&format!(
            "<tr data-filterable=\"{t} {u}\">\
             <td><div>{t}</div><code class=\"sg-muted\">{u}</code></td>\
             <td>{mem:.1}</td><td>{idle}</td><td>{badge}</td>\
             <td><button class=\"sg-btn\" data-api-action=\"/api/tabs/discard\" data-api-payload=\"{payload}\">{lbl}</button></td></tr>",
            t = html_escape(&d.title),
            u = html_escape(&d.url),
            mem = d.memory_mb,
            idle = d.idle_seconds,
            badge = badge,
            payload = html_escape(&payload),
            lbl = html_escape(discard_lbl),
        ));
    }
    if ctx.tab_discards.is_empty() {
        html.push_str("<tr><td colspan=\"5\" class=\"sg-muted\">All open tabs are currently active.</td></tr>");
    }
    html.push_str("</tbody></table>");
    let export = serde_json::to_string(&ctx.tab_discards).unwrap_or_else(|_| "[]".into());
    (html, export, String::new())
}

fn render_system_body(ctx: &InternalPageContext, _is_fr: bool) -> (String, String, String) {
    let mut html = String::from("<div class=\"sg-card\"><dl class=\"sg-kv\">");
    for (k, v) in &ctx.system_kv {
        html.push_str(&format!(
            "<dt data-filterable=\"{k} {v}\">{k}</dt><dd data-filterable=\"{k} {v}\"><code>{v}</code></dd>",
            k = html_escape(k),
            v = html_escape(v),
        ));
    }
    html.push_str("</dl></div>");
    let export = serde_json::to_string(&ctx.system_kv).unwrap_or_else(|_| "[]".into());
    (html, export, String::new())
}

fn render_credits_body(_is_fr: bool) -> (String, String, String) {
    let components = [
        ("Singularity Browser", "MPL-2.0", "Pure-Rust OLED privacy shell, Vault, Mullvad WireGuard & Shield"),
        ("Chromium / CEF", "BSD-3-Clause", "Web rendering engine and sandboxing runtime"),
        ("serde / serde_json / toml", "MIT OR Apache-2.0", "Zero-copy Rust serialization"),
        ("RustCrypto (sha2, chacha20poly1305, argon2)", "MIT OR Apache-2.0", "Authenticated encryption and KDF primitives"),
        ("dalek-cryptography (ed25519-dalek, x25519-dalek)", "BSD-3-Clause", "Signed updates and WireGuard key exchange"),
        ("zip-rs", "MIT", "Pure-Rust ZIP/CRX archive extraction"),
    ];
    let mut html = String::from("<div class=\"sg-grid\">");
    let mut json_items = Vec::new();
    for (name, lic, desc) in components {
        html.push_str(&format!(
            "<div class=\"sg-card\" data-filterable=\"{name} {lic} {desc}\">\
             <span class=\"sg-badge\">{lic}</span><h3 style=\"margin-top:8px\">{name}</h3>\
             <p class=\"sg-desc\">{desc}</p></div>",
            name = html_escape(name),
            lic = html_escape(lic),
            desc = html_escape(desc),
        ));
        json_items.push(serde_json::json!({ "name": name, "license": lic, "description": desc }));
    }
    html.push_str("</div>");
    (html, serde_json::json!(json_items).to_string(), String::new())
}

fn render_omnibox_body(is_fr: bool) -> (String, String, String) {
    let lbl = if is_fr {
        "Tester une requête Omnibox (ex. !ddg rust, browser://gpu)"
    } else {
        "Probe an Omnibox input (e.g. !ddg rust, browser://gpu)"
    };
    let html = format!(
        "<div class=\"sg-card\">\
         <div style=\"display:flex;gap:10px;margin-bottom:14px\">\
         <input id=\"omni-probe\" class=\"sg-input\" style=\"flex:1\" placeholder=\"{lbl}\">\
         <button id=\"omni-run\" class=\"sg-btn primary\" type=\"button\">Analyze</button>\
         </div><pre id=\"omni-out\" class=\"sg-muted\">Ready.</pre></div>",
        lbl = html_escape(lbl),
    );
    let script = r#"
const probeIn = document.getElementById("omni-probe");
const probeBtn = document.getElementById("omni-run");
const probeOut = document.getElementById("omni-out");
if (probeBtn && probeIn && probeOut) {
  probeBtn.addEventListener("click", async () => {
    const q = probeIn.value.trim();
    const res = await window.sgApi("/api/omnibox/suggest?q=" + encodeURIComponent(q), "GET");
    probeOut.textContent = res.text || JSON.stringify({ query: q, ok: res.ok }, null, 2);
  });
}
"#;
    (html, serde_json::json!({"tool": "omnibox-debugger"}).to_string(), script.into())
}

fn render_inspect_body(ctx: &InternalPageContext, _is_fr: bool) -> (String, String, String) {
    let mut html = String::from("<div class=\"sg-grid\">");
    for t in &ctx.inspect_targets {
        let payload = serde_json::json!({ "target_id": t.id }).to_string();
        html.push_str(&format!(
            "<div class=\"sg-card\" data-filterable=\"{ty} {title} {url}\">\
             <span class=\"sg-badge cyan\">{ty}</span>\
             <h3 style=\"margin-top:8px\">{title}</h3>\
             <p class=\"sg-desc\"><code>{url}</code></p>\
             <button class=\"sg-btn primary\" style=\"margin-top:10px\" data-api-action=\"/api/devtools/inspect\" data-api-payload=\"{payload}\">Inspect</button>\
             </div>",
            ty = html_escape(&t.target_type),
            title = html_escape(&t.title),
            url = html_escape(&t.url),
            payload = html_escape(&payload),
        ));
    }
    if ctx.inspect_targets.is_empty() {
        html.push_str("<div class=\"sg-card sg-muted\">No active inspectable DevTools targets.</div>");
    }
    html.push_str("</div>");
    let export = serde_json::to_string(&ctx.inspect_targets).unwrap_or_else(|_| "[]".into());
    (html, export, String::new())
}

fn render_performance_body(ctx: &InternalPageContext, _is_fr: bool) -> (String, String, String) {
    let m = &ctx.perf_metrics;
    let html = format!(
        "<div class=\"sg-grid\">\
         <div class=\"sg-card\"><span class=\"sg-badge ok\">FRAME PACING</span>\
         <h2 style=\"font-size:28px;margin-top:10px\">{fps:.1} FPS</h2>\
         <p class=\"sg-desc\">Target: {target} Hz · Frame time: {ft:.2} ms</p></div>\
         <div class=\"sg-card\"><span class=\"sg-badge cyan\">MEMORY RSS</span>\
         <h2 style=\"font-size:28px;margin-top:10px\">{rss:.1} MB</h2>\
         <p class=\"sg-desc\">Active tabs: {act} · Hibernated: {hib}</p></div>\
         <div class=\"sg-card\"><span class=\"sg-badge\">SHIELD BLOCKED</span>\
         <h2 style=\"font-size:28px;margin-top:10px\">{blk}</h2>\
         <p class=\"sg-desc\">Trackers & ads neutralized in current session</p></div>\
         </div>",
        fps = m.fps_current,
        target = m.fps_target,
        ft = m.frame_time_ms,
        rss = m.total_rss_mb,
        act = m.active_tabs,
        hib = m.hibernated_tabs,
        blk = m.shield_blocked_session,
    );
    let export = serde_json::to_string(m).unwrap_or_else(|_| "{}".into());
    (html, export, String::new())
}

fn render_logger_body(ctx: &InternalPageContext, _is_fr: bool) -> (String, String, String) {
    let mut html = String::from(
        "<div style=\"margin-bottom:14px\">\
         <button class=\"sg-btn\" data-api-action=\"/api/shields/logger_toggle\" data-api-payload='{\"enabled\":true,\"clear\":true}'>Clear Log</button>\
         </div><table class=\"sg-table\"><thead><tr>\
         <th>Time</th><th>Level</th><th>Source</th><th>Target</th><th>Rule</th><th>Action</th>\
         </tr></thead><tbody>",
    );
    for l in &ctx.log_entries {
        html.push_str(&format!(
            "<tr data-filterable=\"{lvl} {src} {tgt} {rule} {act}\">\
             <td><code>{ts}</code></td><td><span class=\"sg-badge\">{lvl}</span></td>\
             <td>{src}</td><td><code>{tgt}</code></td><td><code>{rule}</code></td><td>{act}</td></tr>",
            ts = html_escape(&l.timestamp),
            lvl = html_escape(&l.level),
            src = html_escape(&l.source),
            tgt = html_escape(&l.target),
            rule = html_escape(&l.rule),
            act = html_escape(&l.action),
        ));
    }
    if ctx.log_entries.is_empty() {
        html.push_str("<tr><td colspan=\"6\" class=\"sg-muted\">No shield or network log entries recorded yet.</td></tr>");
    }
    html.push_str("</tbody></table>");
    let export = serde_json::to_string(&ctx.log_entries).unwrap_or_else(|_| "[]".into());
    (html, export, String::new())
}

fn render_diff_body(ctx: &InternalPageContext, is_fr: bool) -> (String, String, String) {
    let reset_lbl = if is_fr { "Réinitialiser" } else { "Reset" };
    let mut html = String::from(
        "<table class=\"sg-table\"><thead><tr>\
         <th>Setting Key</th><th>Default</th><th>Current Override</th><th>Action</th>\
         </tr></thead><tbody>",
    );
    for d in &ctx.diff_entries {
        let payload = serde_json::json!({ "key": d.key }).to_string();
        html.push_str(&format!(
            "<tr data-filterable=\"{k} {def} {cur}\">\
             <td><code>{k}</code></td><td class=\"sg-muted\"><code>{def}</code></td>\
             <td><code style=\"color:var(--gold)\">{cur}</code></td>\
             <td><button class=\"sg-btn\" data-api-action=\"/api/settings/reset_key\" data-api-payload=\"{payload}\">{lbl}</button></td></tr>",
            k = html_escape(&d.key),
            def = html_escape(&d.default_value),
            cur = html_escape(&d.current_value),
            payload = html_escape(&payload),
            lbl = html_escape(reset_lbl),
        ));
    }
    if ctx.diff_entries.is_empty() {
        html.push_str("<tr><td colspan=\"4\" class=\"sg-muted\">All 2,165+ settings match hardened defaults.</td></tr>");
    }
    html.push_str("</tbody></table>");
    let export = serde_json::to_string(&ctx.diff_entries).unwrap_or_else(|_| "[]".into());
    (html, export, String::new())
}

fn render_apps_body(ctx: &InternalPageContext, is_fr: bool) -> (String, String, String) {
    let launch_lbl = if is_fr { "Lancer" } else { "Launch" };
    let remove_lbl = if is_fr { "Désinstaller" } else { "Uninstall" };
    let mut html = String::from("<div class=\"sg-grid\">");
    for a in &ctx.pwa_apps {
        let launch_p = serde_json::json!({ "id": a.id }).to_string();
        let del_p = serde_json::json!({ "id": a.id }).to_string();
        let kind_badge = if a.is_synthetic {
            "<span class=\"sg-badge cyan\">SITE APP</span>"
        } else {
            "<span class=\"sg-badge ok\">PWA MANIFEST</span>"
        };
        html.push_str(&format!(
            "<div class=\"sg-card\" data-filterable=\"{name} {url} {id}\">\
             {kind_badge}<h3 style=\"margin-top:8px\">{name}</h3>\
             <p class=\"sg-desc\"><code>{url}</code></p>\
             <div style=\"margin-top:12px;display:flex;gap:8px\">\
             <button class=\"sg-btn primary\" data-api-action=\"/api/pwa/launch\" data-api-payload=\"{launch_p}\">{launch_lbl}</button>\
             <button class=\"sg-btn danger\" data-api-action=\"/api/pwa/uninstall\" data-api-payload=\"{del_p}\">{remove_lbl}</button>\
             </div></div>",
            kind_badge = kind_badge,
            name = html_escape(&a.name),
            url = html_escape(&a.start_url),
            id = html_escape(&a.id),
            launch_p = html_escape(&launch_p),
            del_p = html_escape(&del_p),
            launch_lbl = html_escape(launch_lbl),
            remove_lbl = html_escape(remove_lbl),
        ));
    }
    if ctx.pwa_apps.is_empty() {
        html.push_str("<div class=\"sg-card sg-muted\">No Web Apps installed yet.</div>");
    }
    html.push_str("</div>");
    let export = serde_json::to_string(&ctx.pwa_apps).unwrap_or_else(|_| "[]".into());
    (html, export, String::new())
}

fn render_userscripts_body(ctx: &InternalPageContext, is_fr: bool) -> (String, String, String) {
    let mut html = String::from("<div class=\"sg-grid\">");
    for s in &ctx.userscripts {
        let toggle_p = serde_json::json!({ "id": s.id, "enabled": !s.enabled }).to_string();
        let del_p = serde_json::json!({ "id": s.id }).to_string();
        let toggle_lbl = if s.enabled {
            if is_fr { "Désactiver" } else { "Disable" }
        } else if is_fr {
            "Activer"
        } else {
            "Enable"
        };
        let risk_cls = match s.risk_level.to_ascii_lowercase().as_str() {
            "critical" | "high" => "danger",
            "medium" => "warn",
            _ => "ok",
        };
        html.push_str(&format!(
            "<div class=\"sg-card\" data-filterable=\"{name} {matches} {risk}\">\
             <div style=\"display:flex;justify-content:space-between\">\
             <span class=\"sg-badge cyan\">v{ver}</span>\
             <span class=\"sg-badge {risk_cls}\">RISK: {risk}</span></div>\
             <h3 style=\"margin-top:8px\">{name}</h3>\
             <p class=\"sg-desc\"><code>{matches}</code></p>\
             <div style=\"margin-top:12px;display:flex;gap:8px\">\
             <button class=\"sg-btn primary\" data-api-action=\"/api/userscripts/toggle\" data-api-payload=\"{toggle_p}\">{toggle_lbl}</button>\
             <button class=\"sg-btn danger\" data-api-action=\"/api/userscripts/delete\" data-api-payload=\"{del_p}\">Remove</button>\
             </div></div>",
            name = html_escape(&s.name),
            ver = html_escape(&s.version),
            risk = html_escape(&s.risk_level),
            risk_cls = risk_cls,
            matches = html_escape(&s.matches.join(", ")),
            toggle_p = html_escape(&toggle_p),
            del_p = html_escape(&del_p),
            toggle_lbl = html_escape(toggle_lbl),
        ));
    }
    if ctx.userscripts.is_empty() {
        html.push_str("<div class=\"sg-card sg-muted\">No userscripts installed.</div>");
    }
    html.push_str("</div>");
    let export = serde_json::to_string(&ctx.userscripts).unwrap_or_else(|_| "[]".into());
    (html, export, String::new())
}

fn render_cert_error_body(ctx: &InternalPageContext, is_fr: bool) -> (String, String, String) {
    let info = ctx.cert_error.clone().unwrap_or(CertErrorContext {
        target_url: "https://invalid.example".into(),
        host: "invalid.example".into(),
        error_code: "ERR_CERT_AUTHORITY_INVALID".into(),
        issuer: "Unknown".into(),
        valid_range: "N/A".into(),
        spki_sha256: "N/A".into(),
    });
    let heading = if is_fr {
        "Votre connexion n'est pas privée"
    } else {
        "Your connection is not private"
    };
    let back_lbl = if is_fr {
        "Retour en sécurité"
    } else {
        "Back to Safety"
    };
    let proceed_payload = serde_json::json!({
        "host": info.host,
        "url": info.target_url,
        "error_code": info.error_code
    })
    .to_string();

    let html = format!(
        "<div class=\"sg-interstitial\">\
         <span class=\"sg-badge danger\">{code}</span>\
         <h2 style=\"margin:12px 0 8px;font-size:22px\">{heading}</h2>\
         <p class=\"sg-desc\">Target host: <code>{host}</code></p>\
         <dl class=\"sg-kv\" style=\"margin:16px 0\">\
           <dt>Issuer</dt><dd><code>{issuer}</code></dd>\
           <dt>Validity</dt><dd><code>{valid}</code></dd>\
           <dt>SPKI SHA-256</dt><dd><code>{spki}</code></dd>\
         </dl>\
         <div style=\"display:flex;gap:12px;margin-top:20px\">\
           <button class=\"sg-btn primary\" type=\"button\" data-action=\"history-back\">{back_lbl}</button>\
           <button class=\"sg-btn danger\" type=\"button\" data-api-action=\"/api/security/cert_bypass\" data-api-payload=\"{proceed_payload}\">Proceed Temporarily (Unsafe)</button>\
         </div></div>",
        code = html_escape(&info.error_code),
        heading = html_escape(heading),
        host = html_escape(&info.host),
        issuer = html_escape(&info.issuer),
        valid = html_escape(&info.valid_range),
        spki = html_escape(&info.spki_sha256),
        back_lbl = html_escape(back_lbl),
        proceed_payload = html_escape(&proceed_payload),
    );
    let export = serde_json::to_string(&info).unwrap_or_else(|_| "{}".into());
    (html, export, String::new())
}

fn render_https_warning_body(ctx: &InternalPageContext, is_fr: bool) -> (String, String, String) {
    let info = ctx.https_warning.clone().unwrap_or(HttpsWarningContext {
        target_url: "http://example.com".into(),
        host: "example.com".into(),
        reason: "HTTPS upgrade failed or unsupported by server".into(),
    });
    let heading = if is_fr {
        "Connexion HTTP non chiffrée bloquée"
    } else {
        "Unencrypted HTTP connection blocked"
    };
    let back_lbl = if is_fr {
        "Retour en sécurité"
    } else {
        "Back to Safety"
    };
    let allow_payload = serde_json::json!({
        "host": info.host,
        "url": info.target_url,
        "scope": "session"
    })
    .to_string();

    let html = format!(
        "<div class=\"sg-interstitial\" style=\"border-color:var(--warn)\">\
         <span class=\"sg-badge warn\">HTTPS-ONLY MODE</span>\
         <h2 style=\"margin:12px 0 8px;font-size:22px\">{heading}</h2>\
         <p class=\"sg-desc\"><code>{url}</code></p>\
         <p style=\"margin:14px 0\">{reason}</p>\
         <div style=\"display:flex;gap:12px;margin-top:20px\">\
           <button class=\"sg-btn primary\" type=\"button\" data-action=\"history-back\">{back_lbl}</button>\
           <button class=\"sg-btn\" type=\"button\" data-api-action=\"/api/security/allow_http_once\" data-api-payload=\"{allow_payload}\">Continue to HTTP Site (Session Only)</button>\
         </div></div>",
        heading = html_escape(heading),
        url = html_escape(&info.target_url),
        reason = html_escape(&info.reason),
        back_lbl = html_escape(back_lbl),
        allow_payload = html_escape(&allow_payload),
    );
    let export = serde_json::to_string(&info).unwrap_or_else(|_| "{}".into());
    (html, export, String::new())
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_internal_page_registry_completeness_and_normalization() {
        let required_slugs = [
            "settings",
            "flags",
            "urls",
            "version",
            "gpu",
            "process-manager",
            "net-internals",
            "crashes",
            "components",
            "sandbox",
            "media-internals",
            "policy",
            "tracing",
            "histograms",
            "discards",
            "system",
            "credits",
            "omnibox",
            "inspect",
            "performance",
            "logger",
            "diff",
            "apps",
            "userscripts",
            "bookmarks",
            "history",
            "downloads",
            "collections",
            "notes",
            "reading-list",
            "sessions",
            "reader",
            "pdf",
            "capture-editor",
            "cert-error",
            "https-warning",
        ];
        for slug in required_slugs {
            assert!(
                find_internal_page(slug).is_some(),
                "Missing required internal page slug '{}'",
                slug
            );
        }

        // Cross-scheme normalization + aliases
        assert_eq!(
            normalize_internal_url("chrome://task-manager").as_deref(),
            Some("browser://process-manager")
        );
        assert_eq!(
            normalize_internal_url("singularity://settings/appearance").as_deref(),
            Some("browser://settings/appearance")
        );
        assert_eq!(
            normalize_internal_url("BROWSER://GPU/").as_deref(),
            Some("browser://gpu")
        );
        assert_eq!(
            normalize_internal_url("chrome://chrome-urls").as_deref(),
            Some("browser://urls")
        );

        // Rejects external schemes, unknown slugs, path traversal, and control chars
        assert!(normalize_internal_url("https://example.com").is_none());
        assert!(normalize_internal_url("browser://does-not-exist").is_none());
        assert!(normalize_internal_url("browser://settings/../../etc/passwd").is_none());
        assert!(normalize_internal_url("browser://flags\r\nEvil: 1").is_none());
    }

    #[test]
    fn test_render_all_25_interactive_oled_pages_and_xss_hardening() {
        let mut ctx = InternalPageContext::default();
        ctx.api_token = "tok_test_12345".into();
        ctx.cert_error = Some(CertErrorContext {
            target_url: "https://evil.test/<script>alert(1)</script>".into(),
            host: "evil.test\"><script>alert(1)</script>".into(),
            error_code: "ERR_CERT_REVOKED".into(),
            issuer: "Evil CA </script><img src=x onerror=alert(1)>".into(),
            valid_range: "2020-2021".into(),
            spki_sha256: "deadbeef".into(),
        });

        let rendered_slugs = [
            "urls",
            "version",
            "flags",
            "gpu",
            "process-manager",
            "net-internals",
            "crashes",
            "components",
            "sandbox",
            "media-internals",
            "policy",
            "tracing",
            "histograms",
            "discards",
            "system",
            "credits",
            "omnibox",
            "inspect",
            "performance",
            "logger",
            "diff",
            "apps",
            "userscripts",
            "cert-error",
            "https-warning",
        ];

        for slug in rendered_slugs {
            let html = render_internal_page_html(slug, &ctx)
                .unwrap_or_else(|| panic!("Expected rendered HTML for '{}'", slug));
            assert!(html.contains("#000000"), "{} must use OLED pure black", slug);
            assert!(html.contains("X-Singularity-Token"), "{} must pass IPC token", slug);
            assert!(html.contains("id=\"sg-filter\""), "{} must include filter box", slug);
            assert!(html.contains("id=\"sg-export-json\""), "{} must include export JSON", slug);
            assert!(html.contains("Content-Security-Policy"), "{} must enforce CSP", slug);
            assert!(!html.contains("onclick="), "{} must not use inline onclick handlers", slug);
            assert!(
                !html.contains("script-src 'unsafe-inline'"),
                "{} must not use unsafe-inline in script-src",
                slug
            );
            assert!(
                !html.contains("http://127.0.0.1:*"),
                "{} must not use wildcard loopback connect-src",
                slug
            );
            assert!(
                html.contains("sg-internal-api") && html.contains("sg-internal-api-reply"),
                "{} must support sandboxed iframe postMessage relay",
                slug
            );
        }

        // Verify cert-error thoroughly escapes malicious host/issuer payloads & uses data-action
        let cert_html = render_internal_page_html("cert-error", &ctx).unwrap();
        assert!(!cert_html.contains("<script>alert(1)</script>"));
        assert!(!cert_html.contains("<img src=x onerror=alert(1)>"));
        assert!(cert_html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(cert_html.contains("data-action=\"history-back\""));
        let https_html = render_internal_page_html("https-warning", &ctx).unwrap();
        assert!(https_html.contains("data-action=\"history-back\""));

        // Verify aligned internal page API routes
        let flags_html = render_internal_page_html("flags", &ctx).unwrap();
        assert!(flags_html.contains("/api/flags/reset_all"));
        assert!(flags_html.contains("/api/flags/set"));
        let net_html = render_internal_page_html("net-internals", &ctx).unwrap();
        assert!(net_html.contains("/api/dns/clear_cache"));
        let crashes_html = render_internal_page_html("crashes", &ctx).unwrap();
        assert!(crashes_html.contains("/api/crashes/purge"));
        let omni_html = render_internal_page_html("omnibox", &ctx).unwrap();
        assert!(omni_html.contains("/api/omnibox/suggest?q="));
        let logger_html = render_internal_page_html("logger", &ctx).unwrap();
        assert!(logger_html.contains("/api/shields/logger_toggle"));
        ctx.userscripts.push(UserscriptSummaryEntry {
            id: "us-1".into(),
            name: "Sample".into(),
            version: "1.0".into(),
            enabled: true,
            matches: vec!["https://example.com/*".into()],
            risk_level: "Standard".into(),
        });
        let us_html = render_internal_page_html("userscripts", &ctx).unwrap();
        assert!(us_html.contains("/api/userscripts/delete"));
        assert!(!us_html.contains("/api/userscripts/remove"));

        // French rendering works cleanly
        ctx.language = "fr".into();
        let fr_urls = render_internal_page_html("chrome://urls", &ctx).unwrap();
        assert!(fr_urls.contains("<html lang=\"fr\">"));
        assert!(fr_urls.contains("Copier JSON"));

        // Unknown slug returns None
        assert!(render_internal_page_html("unknown-page", &ctx).is_none());
    }
}
