//! Unified HTTP API v3.0 & Internal Pages (`browser://`) Router for Singularity Browser.
//!
//! Covers all 10 functional parity domains behind `server.rs`'s existing
//! constant-time `X-Singularity-Token`, `Host`, `Origin`, and `Sec-Fetch-Site` guards.

use crate::bookmarks_store::{
    BookmarkNodeKind, BookmarkNodeUpdate, NewBookmarkNode, ROOT_BOOKMARK_BAR,
};
use crate::crash_guard::{delete_crash_report, list_crash_reports, purge_all_crash_reports};
use crate::drm_webview::inspect_widevine_status;
use crate::extensions::{
    clear_extension_errors, describe_extension_permissions, get_extension_errors,
    parse_edge_addons_id, set_extension_action_badge, set_extension_command_shortcut,
    set_extension_privacy_flags, set_extension_site_access, stage_extension_for_review,
    SiteAccessMode,
};
use crate::history_store::{HistoryQueryParams, VisitTransitionType};
use crate::internal_pages::{
    render_internal_page_html, ComponentEntry, CrashReportEntry, FlagEntry, InternalPageContext,
    PolicyEntry, ProcessEntry, PwaSummaryEntry, SettingDiffEntry, UserscriptSummaryEntry,
    INTERNAL_PAGE_REGISTRY,
};
use crate::keybinds::{CommandChain, KeymapPreset};
use crate::omnibox::{
    generate_qr_svg, OmniboxBookmarkCandidate, OmniboxExtensionCandidate, OmniboxHistoryCandidate,
    OmniboxOpenTab, OmniboxQueryContext, OmniboxSettingCandidate, SearchEngineEntry,
};
use crate::page_tools::{
    build_text_fragment_url, compute_line_diff, evaluate_jsonpath, evaluate_xpath_simple,
    extract_rss_feeds_from_html, format_smart_copy, parse_xml_tree, render_safe_markdown_html,
    CollectionItemKind, ReaderModeExtractor, ReaderRenderOptions, ReaderTheme, SmartCopyFormat,
};
use crate::profiles::{
    ContainerTabProfile, CustomThemeManifest, PermissionDecision, PermissionKind, PermissionScope,
    SiteBoostRule, WebPanelConfig, WorkspaceRecord,
};
use crate::roaming_store::unix_now;
use crate::server::{HttpResponse, ParsedHttpRequest, ServerConfig};
use crate::shell::SingularityBrowserShell;
use singularity_cast::CastPlaybackCommand;
use singularity_core::{
    classify_download_danger, verify_file_sha256, AdblockLevel, CookieBlockingLevel,
    DnsProviderPreset, DownloadRoutingRule, EnergySaverActivationPolicy,
    FingerprintProtectionLevel, PerformanceProfilePreset, ResourceLimiterConfig, SiteShieldsPolicy,
    SystemMemorySnapshot, TabLifecycleState, UBlockNetworkEngine,
};
use singularity_media::{
    format_as_webvtt, parse_ass, parse_srt, parse_vtt, probe_platform_capabilities,
    EqualizerPreset, LiveCaptionsConfig, MediaControlAction, TabMediaSession, TtsConfig,
};
use singularity_net_mullvad::{
    MullvadDnsContentBlocker, ObfuscationMode, ProxyProfileConfig, RelayFilterCriteria,
    SplitTunnelRule,
};
use singularity_settings_registry::schema::SettingCategory;
use singularity_sync::{SingularitySyncEngine, SyncCollectionKind};
use singularity_translate::TranslationPrefs;
use singularity_vault::{
    serialize_cxf_json, ConflictResolution, PasskeyAlgorithm, PassphraseConfig,
    PasswordGeneratorConfig, SendPayloadType, SingularitySendEnvelope, VaultFolder, VaultItem,
    WordCapitalization, WordlistLanguage,
};
use rand_core::{OsRng, RngCore};
use std::collections::HashMap;
use std::path::{Component, Path};
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

const MAX_STAGE_REVIEW_CRX_BYTES: u64 = 32 * 1024 * 1024;

fn is_unc_or_device_path(raw: &str) -> bool {
    let trimmed = raw.trim();
    trimmed.is_empty()
        || trimmed.bytes().any(|b| b <= 0x1f || b == 0x7f)
        || trimmed.starts_with("\\\\")
        || trimmed.starts_with("//")
        || trimmed.starts_with("\\\\?\\")
        || trimmed.starts_with("\\\\.\\")
        || trimmed.starts_with("//?/")
        || trimmed.starts_with("//./")
}

fn has_parent_dir_component(raw: &str) -> bool {
    raw.split(['/', '\\']).any(|seg| seg == "..")
        || Path::new(raw)
            .components()
            .any(|c| matches!(c, Component::ParentDir))
}

fn is_symlink_or_reparse_meta(meta: &std::fs::Metadata) -> bool {
    if meta.file_type().is_symlink() {
        return true;
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        if (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            return true;
        }
    }
    false
}

fn parse_body(req: &ParsedHttpRequest) -> serde_json::Value {
    if req.body.is_empty() {
        return serde_json::Value::Object(serde_json::Map::new());
    }
    serde_json::from_slice(&req.body)
        .unwrap_or_else(|_| serde_json::Value::Object(serde_json::Map::new()))
}

fn require_post(req: &ParsedHttpRequest) -> Result<serde_json::Value, HttpResponse> {
    if req.method != "POST" {
        return Err(HttpResponse::json(
            "405 Method Not Allowed",
            &serde_json::json!({ "error": "POST method required." }),
        ));
    }
    Ok(parse_body(req))
}

fn ok_json<T: serde::Serialize>(val: &T) -> HttpResponse {
    match serde_json::to_vec(val) {
        Ok(bytes) => HttpResponse::new("200 OK", "application/json; charset=utf-8", bytes),
        Err(e) => HttpResponse::json(
            "500 Internal Server Error",
            &serde_json::json!({ "error": e.to_string() }),
        ),
    }
}

fn err_json(status: &'static str, msg: impl Into<String>) -> HttpResponse {
    HttpResponse::json(status, &serde_json::json!({ "error": msg.into() }))
}

/// Builds a live [`InternalPageContext`] snapshot from `shell` for `browser://*` OLED HTML pages.
pub(crate) fn build_internal_page_context(
    shell: &SingularityBrowserShell,
    api_token: &str,
) -> InternalPageContext {
    let mut ctx = InternalPageContext::default();
    ctx.language = shell.roaming.profile.language.clone();
    ctx.api_token = api_token.to_string();
    ctx.profile_path = shell.roaming.root_dir().to_string_lossy().to_string();
    ctx.executable_path = std::env::current_exe()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "singularity".to_string());

    ctx.flags = shell
        .flags
        .all_flags()
        .iter()
        .map(|f| FlagEntry {
            id: f.id.clone(),
            name: f.title.clone(),
            description: f.description.clone(),
            enabled: f.current_index != 0,
            default_enabled: f.default_index != 0,
            category: f.origin.label().to_string(),
        })
        .collect();

    ctx.processes = shell
        .core
        .tab_manager
        .tabs()
        .iter()
        .map(|t| {
            let mem_mb = match &t.lifecycle {
                TabLifecycleState::FrozenZeroCpu { rss_bytes, .. } => {
                    (*rss_bytes as f64) / (1024.0 * 1024.0)
                }
                TabLifecycleState::SuspendedFrozen { .. } => 0.5,
                _ => 48.0,
            };
            ProcessEntry {
                pid: t.tab_id as u32,
                kind: "Tab".to_string(),
                title: t.title.clone(),
                cpu_percent: 0.0,
                memory_mb: mem_mb,
                gpu_mb: 0.0,
                hibernated: matches!(
                    t.lifecycle,
                    TabLifecycleState::SuspendedFrozen { .. }
                        | TabLifecycleState::FrozenZeroCpu { .. }
                ),
            }
        })
        .collect();

    ctx.crashes = list_crash_reports(shell.roaming.root_dir())
        .into_iter()
        .map(|c| CrashReportEntry {
            id: c.id,
            timestamp: c.timestamp_unix.to_string(),
            process_kind: c.kind,
            reason: c.summary,
            recovered_tabs: 0,
        })
        .collect();

    let cef_profile_dir = shell.roaming.chromium_profile_dir();
    let wv = inspect_widevine_status(&cef_profile_dir);
    ctx.components.push(ComponentEntry {
        id: "widevine-cdm".to_string(),
        name: "Widevine Content Decryption Module".to_string(),
        version: wv
            .detected_version
            .unwrap_or_else(|| "bundled/pending".to_string()),
        status: if wv.cef_widevine_ready {
            "Ready".to_string()
        } else {
            "Not seeded".to_string()
        },
        signature_verified: wv.cef_widevine_ready,
    });

    for entry in shell.policy.list_policies() {
        ctx.policies.push(PolicyEntry {
            key: entry.key.clone(),
            value: format!("{:?}", entry.value),
            source: format!("{:?}", entry.source),
            mandatory: entry.enforcement
                == singularity_settings_registry::PolicyEnforcement::Mandatory,
        });
    }

    ctx.diff_entries = shell
        .core
        .settings
        .diff_modified_settings()
        .into_iter()
        .map(|d| SettingDiffEntry {
            key: d.key,
            default_value: format!("{:?}", d.default_value),
            current_value: format!("{:?}", d.current_value),
        })
        .collect();

    ctx.pwa_apps = shell
        .pwas
        .list()
        .into_iter()
        .map(|p| PwaSummaryEntry {
            id: p.id.clone(),
            name: p.manifest.display_title().to_string(),
            start_url: p.manifest.start_url.clone(),
            scope: p.manifest.scope.clone(),
            open_in_window: p.open_in_window,
            is_synthetic: p.is_synthetic,
        })
        .collect();

    ctx.userscripts = shell
        .userscripts
        .list()
        .into_iter()
        .map(|u| UserscriptSummaryEntry {
            id: u.id.clone(),
            name: u.meta.name.clone(),
            version: u
                .meta
                .version
                .clone()
                .unwrap_or_else(|| "1.0.0".to_string()),
            enabled: u.enabled,
            matches: u.meta.matches.clone(),
            risk_level: if u.meta.grants.iter().any(|g| g.contains("xmlhttpRequest")) {
                "Elevated".to_string()
            } else {
                "Standard".to_string()
            },
        })
        .collect();

    ctx
}

/// Serves `GET /browser/<slug>` OLED internal pages cleanly (session cookie or IPC token required).
pub(crate) fn handle_browser_internal_page(
    slug: &str,
    shell_mutex: &Arc<Mutex<SingularityBrowserShell>>,
    api_token: &str,
) -> HttpResponse {
    let ctx = {
        let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
        build_internal_page_context(&shell, api_token)
    };
    let normalized_slug = slug.trim().trim_start_matches('/').to_ascii_lowercase();
    let target = if normalized_slug.is_empty() {
        "urls"
    } else {
        normalized_slug.as_str()
    };
    match render_internal_page_html(target, &ctx) {
        Some(html) => {
            let mut csp_nonce_raw = [0u8; 16];
            OsRng.fill_bytes(&mut csp_nonce_raw);
            let csp_nonce = hex::encode(csp_nonce_raw);
            let html_with_nonce = crate::server::inject_csp_nonce(&html, &csp_nonce);
            let csp_header = format!(
                "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'nonce-{}'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'self';",
                csp_nonce
            );
            HttpResponse::new(
                "200 OK",
                "text/html; charset=utf-8",
                html_with_nonce.into_bytes(),
            )
            .with_header("Content-Security-Policy", csp_header)
            .with_header("X-Frame-Options", "SAMEORIGIN")
        }
        None => HttpResponse::text("404 Not Found", "Unknown browser:// internal page"),
    }
}

fn enforce_v3_vault_auto_lock(shell: &mut SingularityBrowserShell, cfg: Option<&ServerConfig>) {
    if let Some(c) = cfg {
        crate::server::enforce_vault_auto_lock_and_sync(shell, c);
    } else {
        shell.enforce_vault_auto_lock();
    }
}

/// Dispatches all v3.0 API routes across all 10 domains (test-only 3-arg convenience wrapper).
/// Production callers MUST use [`try_handle_v3_route_with_config`] with `Some(cfg)`.
#[cfg(test)]
pub(crate) fn try_handle_v3_route(
    req: &ParsedHttpRequest,
    params: &HashMap<String, String>,
    shell_mutex: &Arc<Mutex<SingularityBrowserShell>>,
) -> Option<HttpResponse> {
    try_handle_v3_route_with_config(req, params, shell_mutex, None)
}

/// Dispatches all v3.0 API routes with optional `ServerConfig` so every `/api/vault/*` route
/// enforces auto-lock synchronization, activity touch, and `vault_op_lock` serialization
/// matching `server.rs`'s strict lock hierarchy (`vault_op_lock -> shell_mutex -> vault_session_cache`).
pub(crate) fn try_handle_v3_route_with_config(
    req: &ParsedHttpRequest,
    params: &HashMap<String, String>,
    shell_mutex: &Arc<Mutex<SingularityBrowserShell>>,
    cfg: Option<&ServerConfig>,
) -> Option<HttpResponse> {
    let path = req.path.as_str();
    let resp = match path {
        // ====================================================================
        // DOMAIN 8: INTERNAL PAGES, FLAGS, CRASHES, POLICY, SETTINGS DIFF/JSON
        // ====================================================================
        "/api/internal/urls" => ok_json(&serde_json::json!({
            "pages": INTERNAL_PAGE_REGISTRY.iter().map(|p| serde_json::json!({
                "slug": p.slug,
                "url": format!("browser://{}", p.slug),
                "category": p.category.label_en(),
                "category_fr": p.category.label_fr(),
                "title_en": p.title_en,
                "title_fr": p.title_fr,
                "aliases": p.aliases,
            })).collect::<Vec<_>>()
        })),
        "/api/internal/version" => {
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            ok_json(&serde_json::json!({
                "version": env!("CARGO_PKG_VERSION"),
                "os": std::env::consts::OS,
                "arch": std::env::consts::ARCH,
                "settings_count": shell.core.settings.len(),
                "flags_count": shell.flags.len(),
                "profile_dir": shell.roaming.root_dir().to_string_lossy(),
                "telemetry_enabled": false,
                "engine": "Pure Rust + Chromium CEF 150.2.1",
            }))
        }
        "/api/internal/flags" => {
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let q = params.get("q").map(String::as_str).unwrap_or("");
            let modified_only = params
                .get("modified_only")
                .is_some_and(|v| v == "1" || v == "true");
            let flags = shell.flags.list_filtered(q, modified_only);
            let (ef, df, sw) = shell.flags.compile_chromium_args();
            ok_json(&serde_json::json!({
                "flags": flags,
                "total": shell.flags.len(),
                "modified_count": shell.flags.modified_count(),
                "pending_restart": shell.flags.has_pending_restart(),
                "compiled_args": { "enable_features": ef, "disable_features": df, "switches": sw }
            }))
        }
        "/api/flags/set" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let id = body.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let idx = body
                .get("option_index")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as usize;
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            match shell.flags.set_flag(id, idx) {
                Ok(()) => {
                    let _ = shell.save_flags();
                    ok_json(&serde_json::json!({
                        "ok": true,
                        "pending_restart": shell.flags.has_pending_restart(),
                        "modified_count": shell.flags.modified_count()
                    }))
                }
                Err(e) => err_json("400 Bad Request", e),
            }
        }
        "/api/flags/reset_all" => {
            if let Err(r) = require_post(req) {
                return Some(r);
            }
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let count = shell.flags.reset_all();
            let _ = shell.save_flags();
            ok_json(&serde_json::json!({ "ok": true, "reset_count": count }))
        }
        "/api/internal/crashes" => {
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let list = list_crash_reports(shell.roaming.root_dir());
            ok_json(&serde_json::json!({ "crashes": list }))
        }
        "/api/crashes/delete" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let id = body.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let removed = delete_crash_report(shell.roaming.root_dir(), id);
            ok_json(&serde_json::json!({ "ok": removed }))
        }
        "/api/crashes/purge" => {
            if let Err(r) = require_post(req) {
                return Some(r);
            }
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let removed = purge_all_crash_reports(shell.roaming.root_dir());
            ok_json(&serde_json::json!({ "ok": true, "removed": removed }))
        }
        "/api/internal/process-manager" => {
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let mem = SystemMemorySnapshot::capture();
            let (_, _, cache_bytes) = shell.core.asset_cache.stats();
            let tasks: Vec<_> = shell
                .core
                .tab_manager
                .tabs()
                .iter()
                .map(|t| {
                    serde_json::json!({
                        "tab_id": t.tab_id,
                        "title": t.title,
                        "url": t.url,
                        "origin": t.first_party_etld,
                        "ram_bytes": match &t.lifecycle {
                            TabLifecycleState::FrozenZeroCpu { rss_bytes, .. } => *rss_bytes,
                            TabLifecycleState::SuspendedFrozen { .. } => 512 * 1024,
                            _ => 48 * 1024 * 1024,
                        },
                        "state": format!("{:?}", t.lifecycle),
                        "pinned": t.pinned,
                        "audible": t.playing_audio,
                    })
                })
                .collect();
            ok_json(&serde_json::json!({
                "tasks": tasks,
                "system_memory": mem,
                "reclaimed_ram_bytes": shell.core.tab_manager.total_reclaimed_ram_bytes(),
                "ram_cache_bytes": cache_bytes,
            }))
        }
        "/api/internal/net-internals" => {
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            ok_json(&serde_json::json!({
                "dns_cache": shell.core.dns_resolver.snapshot_cache_entries(),
                "preconnect_sessions": shell.core.preconnect_pool.snapshot_sessions(),
                "mullvad_dns_ip": shell.core.mullvad_vpn.effective_in_tunnel_dns_ipv4(),
            }))
        }
        "/api/internal/policy" => {
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            ok_json(&serde_json::json!({
                "sources": shell.policy.loaded_sources(),
                "entries": shell.policy.list_policies()
            }))
        }
        "/api/internal/histograms" => {
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let items: Vec<_> = shell
                .core
                .histograms
                .metric_names()
                .into_iter()
                .filter_map(|m| shell.core.histograms.summary(&m))
                .collect();
            ok_json(&serde_json::json!({ "histograms": items }))
        }
        "/api/internal/components" => {
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let cef_profile_dir = shell.roaming.chromium_profile_dir();
            let wv = inspect_widevine_status(&cef_profile_dir);
            ok_json(&serde_json::json!({
                "widevine": wv,
                "filter_lists": shell.core.adblocker.subscriptions(),
                "threat_signatures": shell.core.threat_guard.signature_count(),
                "translate_pairs": shell.translate_engine.available_pairs(),
            }))
        }
        "/api/settings/diff" => {
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let rows = shell.core.settings.diff_modified_settings();
            ok_json(&serde_json::json!({ "modified": rows, "count": rows.len() }))
        }
        "/api/settings/reset_key" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let key = body.get("key").and_then(|v| v.as_str()).unwrap_or("");
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            match shell.core.settings.reset_to_default(key) {
                Ok(_) => {
                    shell.sync_runtime_from_settings();
                    if let Ok(toml) = shell.core.settings.export_toml(true) {
                        let _ = shell.roaming.save_settings_toml(&toml);
                    }
                    ok_json(&serde_json::json!({ "ok": true }))
                }
                Err(e) => err_json("400 Bad Request", e.to_string()),
            }
        }
        "/api/settings/reset_category" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let cat_str = body.get("category").and_then(|v| v.as_str()).unwrap_or("");
            let cat = serde_json::from_value::<SettingCategory>(serde_json::Value::String(
                cat_str.to_string(),
            ));
            let Ok(category) = cat else {
                return Some(err_json("400 Bad Request", "Unknown settings category"));
            };
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let count = shell.core.settings.reset_category(category);
            shell.sync_runtime_from_settings();
            if let Ok(toml) = shell.core.settings.export_toml(true) {
                let _ = shell.roaming.save_settings_toml(&toml);
            }
            ok_json(&serde_json::json!({ "ok": true, "reset_count": count }))
        }
        "/api/settings/export_json" => {
            let modified_only = params
                .get("modified_only")
                .is_some_and(|v| v == "1" || v == "true");
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            match shell.core.settings.export_json(modified_only) {
                Ok(json) => HttpResponse::new(
                    "200 OK",
                    "application/json; charset=utf-8",
                    json.into_bytes(),
                ),
                Err(e) => err_json("500 Internal Server Error", e),
            }
        }
        "/api/settings/import_json" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let raw = body.get("json").and_then(|v| v.as_str()).unwrap_or("");
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            match shell.core.settings.import_json(raw) {
                Ok(applied) => {
                    shell.sync_runtime_from_settings();
                    if let Ok(toml) = shell.core.settings.export_toml(true) {
                        let _ = shell.roaming.save_settings_toml(&toml);
                    }
                    ok_json(&serde_json::json!({ "ok": true, "applied": applied }))
                }
                Err(e) => err_json("400 Bad Request", e),
            }
        }

        // ====================================================================
        // DOMAIN 2: OMNIBOX, SEARCH ENGINES, QR CODE & HISTORY
        // ====================================================================
        "/api/omnibox/suggest" => {
            let q = params.get("q").map(String::as_str).unwrap_or("");
            let max_results = params
                .get("limit")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(10)
                .clamp(1, 30);
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let open_tabs: Vec<OmniboxOpenTab> = shell
                .roaming
                .profile
                .saved_tabs
                .iter()
                .enumerate()
                .map(|(idx, t)| OmniboxOpenTab {
                    tab_id: (idx + 1).to_string(),
                    title: t.title.clone(),
                    url: t.url.clone(),
                    favicon_url: t.favicon_url.clone(),
                })
                .collect();
            let history: Vec<OmniboxHistoryCandidate> = shell
                .history_store
                .query(&HistoryQueryParams {
                    query: q.to_string(),
                    limit: 64,
                    ..Default::default()
                })
                .items
                .into_iter()
                .map(|h| OmniboxHistoryCandidate {
                    url: h.url,
                    title: h.title,
                    visit_count: h.visit_count,
                    typed_count: h.typed_count,
                    last_visit_unix: h.visit_time_unix,
                    favicon_url: None,
                })
                .collect();
            let bookmarks: Vec<OmniboxBookmarkCandidate> = shell
                .bookmarks_store
                .search(q)
                .into_iter()
                .filter_map(|b| {
                    b.url.as_ref().map(|u| OmniboxBookmarkCandidate {
                        id: b.id.clone(),
                        url: u.clone(),
                        title: b.title.clone(),
                        nickname: b.nickname.clone(),
                        tags: b.tags.clone(),
                        visit_count: b.visit_count,
                        last_visited_unix: b.last_visited_unix,
                    })
                })
                .collect();
            let settings: Vec<OmniboxSettingCandidate> = shell
                .core
                .settings
                .query_virtualized(None, q, 0, 400, 50)
                .visible_slice
                .into_iter()
                .take(8)
                .map(|s| OmniboxSettingCandidate {
                    key: s.key.clone(),
                    label: s.description.clone(),
                    category: s.category.display_name().to_string(),
                })
                .collect();
            let extensions: Vec<OmniboxExtensionCandidate> =
                crate::extensions::list_extensions_cached(
                    shell.roaming.root_dir(),
                    &shell.roaming.profile.pinned_extensions,
                )
                .into_iter()
                .map(|e| OmniboxExtensionCandidate {
                    id: e.id,
                    name: e.name,
                    description: e.description,
                    enabled: e.enabled,
                })
                .collect();
            let ctx = OmniboxQueryContext {
                open_tabs,
                history,
                bookmarks,
                settings,
                extensions,
                remote_suggestions: Vec::new(),
                is_private: shell.private_browsing_active,
                now_unix: unix_now(),
                max_results,
            };
            let result = shell.omnibox.query(q, &ctx);
            ok_json(&result)
        }
        "/api/omnibox/qr" => {
            let data = params.get("data").map(String::as_str).unwrap_or("");
            if data.is_empty() || data.len() > 2048 {
                return Some(err_json("400 Bad Request", "QR data must be 1..=2048 bytes"));
            }
            let svg = generate_qr_svg(data);
            ok_json(&serde_json::json!({ "ok": true, "svg": svg }))
        }
        "/api/search_engines/list" => {
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            ok_json(&serde_json::json!({
                "engines": shell.omnibox.search_engines.engines,
                "default_normal": shell.omnibox.search_engines.default_engine(false),
                "default_private": shell.omnibox.search_engines.default_engine(true),
            }))
        }
        "/api/search_engines/upsert" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let Ok(entry) = serde_json::from_value::<SearchEngineEntry>(body) else {
                return Some(err_json("400 Bad Request", "Invalid SearchEngineEntry JSON"));
            };
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let _ = shell.omnibox.search_engines.remove_engine(&entry.id);
            match shell.omnibox.search_engines.add_engine(entry) {
                Ok(()) => ok_json(&serde_json::json!({ "ok": true })),
                Err(e) => err_json("400 Bad Request", e.to_string()),
            }
        }
        "/api/search_engines/delete" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let id = body.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            match shell.omnibox.search_engines.remove_engine(id) {
                Ok(_) => ok_json(&serde_json::json!({ "ok": true })),
                Err(e) => err_json("400 Bad Request", e.to_string()),
            }
        }
        "/api/search_engines/set_default" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let id = body.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let is_private = body
                .get("private")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            match shell.omnibox.search_engines.set_default_engine(id, is_private) {
                Ok(()) => ok_json(&serde_json::json!({ "ok": true })),
                Err(e) => err_json("400 Bad Request", e.to_string()),
            }
        }
        "/api/history/query" => {
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let qp = HistoryQueryParams {
                query: params.get("q").cloned().unwrap_or_default(),
                offset: params.get("offset").and_then(|v| v.parse().ok()).unwrap_or(0),
                limit: params
                    .get("limit")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(50)
                    .clamp(1, 200),
                since_unix: params.get("since").and_then(|v| v.parse().ok()),
                until_unix: params.get("until").and_then(|v| v.parse().ok()),
                domain: params.get("domain").cloned(),
                ..Default::default()
            };
            let page = shell.history_store.query(&qp);
            ok_json(&page)
        }
        "/api/history/journeys" => {
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let max = params.get("limit").and_then(|v| v.parse().ok()).unwrap_or(20);
            let journeys = shell.history_store.build_history_journeys(max);
            ok_json(&serde_json::json!({ "journeys": journeys }))
        }
        "/api/history/stats" => {
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let days = params.get("days").and_then(|v| v.parse().ok()).unwrap_or(30);
            ok_json(&shell.history_store.compute_visit_stats(days))
        }
        "/api/history/record" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let url = body.get("url").and_then(|v| v.as_str()).unwrap_or("");
            let title = body.get("title").and_then(|v| v.as_str()).unwrap_or(url);
            let typed = body.get("typed").and_then(|v| v.as_bool()).unwrap_or(false);
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            if shell.private_browsing_active {
                return Some(ok_json(&serde_json::json!({
                    "ok": true,
                    "skipped_private": true
                })));
            }
            let transition = if typed {
                VisitTransitionType::Typed
            } else {
                VisitTransitionType::Link
            };
            match shell.history_store.record_visit(
                url,
                title,
                transition,
                None,
                None,
                None,
                unix_now(),
            ) {
                Some(vid) => {
                    let _ = shell.save_history_store();
                    ok_json(&serde_json::json!({ "ok": true, "visit_id": vid }))
                }
                None => err_json("400 Bad Request", "Invalid URL or excluded domain"),
            }
        }
        "/api/history/delete" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let removed = if let Some(dom) = body.get("domain").and_then(|v| v.as_str()) {
                shell.history_store.delete_domain(dom)
            } else if let (Some(s), Some(u)) = (
                body.get("since_unix").and_then(|v| v.as_u64()),
                body.get("until_unix").and_then(|v| v.as_u64()),
            ) {
                shell.history_store.delete_time_range(s, u)
            } else if let Some(ids) = body.get("visit_ids").and_then(|v| v.as_array()) {
                let list: Vec<u64> = ids.iter().filter_map(|x| x.as_u64()).collect();
                shell.history_store.delete_visits(&list)
            } else {
                0
            };
            let _ = shell.save_history_store();
            ok_json(&serde_json::json!({ "ok": true, "removed": removed }))
        }
        "/api/history/export" => {
            let fmt = params.get("format").map(String::as_str).unwrap_or("json");
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            if fmt.eq_ignore_ascii_case("csv") {
                HttpResponse::new(
                    "200 OK",
                    "text/csv; charset=utf-8",
                    shell.history_store.export_csv().into_bytes(),
                )
            } else {
                match shell.history_store.export_json() {
                    Ok(j) => HttpResponse::new(
                        "200 OK",
                        "application/json; charset=utf-8",
                        j.into_bytes(),
                    ),
                    Err(e) => err_json("500 Internal Server Error", e.to_string()),
                }
            }
        }

        // ====================================================================
        // DOMAIN 3: BOOKMARKS TREE, COLLECTIONS, NOTES, READING LIST, READER & PAGE TOOLS
        // ====================================================================
        "/api/bookmarks/tree" => {
            let parent = params
                .get("parent_id")
                .map(String::as_str)
                .unwrap_or(ROOT_BOOKMARK_BAR);
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            ok_json(&serde_json::json!({
                "parent_id": parent,
                "children": shell.bookmarks_store.children_of(parent),
                "total_nodes": shell.bookmarks_store.node_count(),
                "can_undo": shell.bookmarks_store.can_undo(),
                "can_redo": shell.bookmarks_store.can_redo(),
            }))
        }
        "/api/bookmarks/search" => {
            let q = params.get("q").map(String::as_str).unwrap_or("");
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            ok_json(&serde_json::json!({ "items": shell.bookmarks_store.search(q) }))
        }
        "/api/bookmarks/add" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let input = NewBookmarkNode {
                parent_id: body
                    .get("parent_id")
                    .or_else(|| body.get("folder_id"))
                    .and_then(|v| v.as_str())
                    .unwrap_or(ROOT_BOOKMARK_BAR)
                    .to_string(),
                position: body
                    .get("position")
                    .and_then(|v| v.as_u64())
                    .map(|n| n as usize),
                kind: match body.get("kind").and_then(|v| v.as_str()).unwrap_or("url") {
                    "folder" => BookmarkNodeKind::Folder,
                    "separator" => BookmarkNodeKind::Separator,
                    _ => BookmarkNodeKind::Url,
                },
                title: body
                    .get("title")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                url: body.get("url").and_then(|v| v.as_str()).map(String::from),
                nickname: body
                    .get("nickname")
                    .and_then(|v| v.as_str())
                    .map(String::from),
                description: body
                    .get("description")
                    .and_then(|v| v.as_str())
                    .map(String::from),
                tags: body
                    .get("tags")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default(),
                icon_only: body
                    .get("icon_only")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
                custom_icon: body
                    .get("custom_icon")
                    .and_then(|v| v.as_str())
                    .map(String::from),
            };
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            match shell.bookmarks_store.add_node(input, unix_now()) {
                Ok(id) => {
                    let _ = shell.save_bookmarks_store();
                    ok_json(&serde_json::json!({ "ok": true, "id": id }))
                }
                Err(e) => err_json("400 Bad Request", e.to_string()),
            }
        }
        "/api/bookmarks/update" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let id = body.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let update: BookmarkNodeUpdate =
                serde_json::from_value(body.clone()).unwrap_or_default();
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            match shell.bookmarks_store.update_node(id, update, unix_now()) {
                Ok(()) => {
                    let _ = shell.save_bookmarks_store();
                    ok_json(&serde_json::json!({ "ok": true }))
                }
                Err(e) => err_json("400 Bad Request", e.to_string()),
            }
        }
        "/api/bookmarks/move" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let id = body.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let new_parent = body
                .get("parent_id")
                .and_then(|v| v.as_str())
                .unwrap_or(ROOT_BOOKMARK_BAR);
            let pos = body.get("position").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            match shell
                .bookmarks_store
                .move_node(id, new_parent, pos, unix_now())
            {
                Ok(()) => {
                    let _ = shell.save_bookmarks_store();
                    ok_json(&serde_json::json!({ "ok": true }))
                }
                Err(e) => err_json("400 Bad Request", e.to_string()),
            }
        }
        "/api/bookmarks/delete" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let id = body.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            match shell.bookmarks_store.soft_delete(id, unix_now()) {
                Ok(()) => {
                    let _ = shell.save_bookmarks_store();
                    ok_json(&serde_json::json!({ "ok": true }))
                }
                Err(e) => err_json("400 Bad Request", e.to_string()),
            }
        }
        "/api/bookmarks/undo" => {
            if let Err(r) = require_post(req) {
                return Some(r);
            }
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let ok = shell.bookmarks_store.undo();
            let _ = shell.save_bookmarks_store();
            ok_json(&serde_json::json!({ "ok": ok }))
        }
        "/api/bookmarks/redo" => {
            if let Err(r) = require_post(req) {
                return Some(r);
            }
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let ok = shell.bookmarks_store.redo();
            let _ = shell.save_bookmarks_store();
            ok_json(&serde_json::json!({ "ok": ok }))
        }
        "/api/bookmarks/duplicates" => {
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            ok_json(&serde_json::json!({
                "groups": shell.bookmarks_store.find_duplicate_groups()
            }))
        }
        "/api/bookmarks/merge_duplicates" => {
            if let Err(r) = require_post(req) {
                return Some(r);
            }
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let merged = shell.bookmarks_store.merge_duplicates(unix_now());
            let _ = shell.save_bookmarks_store();
            ok_json(&serde_json::json!({ "ok": true, "merged": merged }))
        }
        "/api/bookmarks/bookmark_all_tabs" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let folder_name = body
                .get("folder_name")
                .and_then(|v| v.as_str())
                .unwrap_or("Saved Session");
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let tabs: Vec<(String, String)> = shell
                .roaming
                .profile
                .saved_tabs
                .iter()
                .map(|t| (t.title.clone(), t.url.clone()))
                .collect();
            match shell
                .bookmarks_store
                .bookmark_all_tabs(folder_name, ROOT_BOOKMARK_BAR, &tabs, unix_now())
            {
                Ok(fid) => {
                    let _ = shell.save_bookmarks_store();
                    ok_json(&serde_json::json!({
                        "ok": true,
                        "folder_id": fid,
                        "count": tabs.len()
                    }))
                }
                Err(e) => err_json("400 Bad Request", e.to_string()),
            }
        }
        "/api/bookmarks/export_netscape" => {
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            HttpResponse::new(
                "200 OK",
                "text/html; charset=utf-8",
                shell
                    .bookmarks_store
                    .export_netscape_html_tree()
                    .into_bytes(),
            )
        }
        "/api/bookmarks/import_netscape" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let html = body.get("html").and_then(|v| v.as_str()).unwrap_or("");
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            match shell
                .bookmarks_store
                .import_netscape_html(html, ROOT_BOOKMARK_BAR, true, unix_now())
            {
                Ok(count) => {
                    let _ = shell.save_bookmarks_store();
                    ok_json(&serde_json::json!({ "ok": true, "imported": count }))
                }
                Err(e) => err_json("400 Bad Request", e.to_string()),
            }
        }
        "/api/collections/list" => {
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            ok_json(&serde_json::json!({ "collections": shell.collections.collections }))
        }
        "/api/collections/create" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let title = body
                .get("title")
                .and_then(|v| v.as_str())
                .unwrap_or("Collection");
            let desc = body
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let color = body.get("color").and_then(|v| v.as_str());
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let id = shell
                .collections
                .create_collection(title, desc, color, unix_now());
            let _ = shell.save_collections();
            ok_json(&serde_json::json!({ "ok": true, "id": id }))
        }
        "/api/collections/add_item" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let col_id = body
                .get("collection_id")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let kind = match body.get("kind").and_then(|v| v.as_str()).unwrap_or("page_link") {
                "note" => CollectionItemKind::Note {
                    markdown: body
                        .get("content")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                },
                "text_excerpt" => CollectionItemKind::TextExcerpt {
                    text: body
                        .get("content")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    source_url: body.get("url").and_then(|v| v.as_str()).map(String::from),
                    source_title: body.get("title").and_then(|v| v.as_str()).map(String::from),
                },
                _ => CollectionItemKind::PageLink {
                    url: body
                        .get("url")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    title: body
                        .get("title")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    favicon_url: None,
                },
            };
            let color_tag = body
                .get("color_tag")
                .and_then(|v| v.as_str())
                .map(String::from);
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            match shell
                .collections
                .add_item(col_id, kind, color_tag, unix_now())
            {
                Ok(item_id) => {
                    let _ = shell.save_collections();
                    ok_json(&serde_json::json!({ "ok": true, "id": item_id }))
                }
                Err(e) => err_json("400 Bad Request", e.to_string()),
            }
        }
        "/api/notes/list" => {
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let notes: Vec<_> = shell
                .notes
                .notes
                .iter()
                .filter(|n| n.trashed_unix.is_none())
                .collect();
            ok_json(&serde_json::json!({ "notes": notes }))
        }
        "/api/notes/create" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let title = body
                .get("title")
                .and_then(|v| v.as_str())
                .unwrap_or("Untitled Note");
            let md = body.get("markdown").and_then(|v| v.as_str()).unwrap_or("");
            let source_url = body
                .get("source_url")
                .and_then(|v| v.as_str())
                .map(String::from);
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let id = shell
                .notes
                .create_note(title, md, None, source_url, Vec::new(), unix_now());
            let _ = shell.save_notes();
            ok_json(&serde_json::json!({ "ok": true, "id": id }))
        }
        "/api/notes/render_markdown" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let md = body.get("markdown").and_then(|v| v.as_str()).unwrap_or("");
            ok_json(&serde_json::json!({ "html": render_safe_markdown_html(md) }))
        }
        "/api/reading_list/list" => {
            let only_unread = params
                .get("unread")
                .is_some_and(|v| v == "1" || v == "true");
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            ok_json(&serde_json::json!({ "items": shell.reading_list.list(only_unread) }))
        }
        "/api/reading_list/add" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let url = body.get("url").and_then(|v| v.as_str()).unwrap_or("");
            let title = body.get("title").and_then(|v| v.as_str()).unwrap_or(url);
            let html = body.get("html").and_then(|v| v.as_str());
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let id = shell.reading_list.add_or_update(url, title, html, unix_now());
            let _ = shell.save_reading_list();
            ok_json(&serde_json::json!({ "ok": true, "id": id }))
        }
        "/api/reader/extract" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let url = body
                .get("url")
                .and_then(|v| v.as_str())
                .unwrap_or("https://example.com");
            let html = body.get("html").and_then(|v| v.as_str()).unwrap_or("");
            let theme = match body.get("theme").and_then(|v| v.as_str()).unwrap_or("oled") {
                "sepia" => ReaderTheme::Sepia,
                "slate" => ReaderTheme::Slate,
                "light" => ReaderTheme::Light,
                "wcag_aaa" => ReaderTheme::WcagAaa,
                _ => ReaderTheme::OledBlack,
            };
            let opts = ReaderRenderOptions {
                theme,
                use_open_dyslexic: body
                    .get("dyslexic")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
                font_size_px: body
                    .get("font_size_px")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(18) as u8,
                line_focus_lines: body
                    .get("line_focus")
                    .and_then(|v| v.as_u64())
                    .map(|n| n as u8),
                ..Default::default()
            };
            let article = ReaderModeExtractor::extract_article(url, html);
            let rendered = ReaderModeExtractor::render_reader_page_html(&article, &opts);
            ok_json(&serde_json::json!({ "article": article, "html": rendered }))
        }
        "/api/page_tools/text_fragment" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let page_url = body.get("url").and_then(|v| v.as_str()).unwrap_or("");
            let page_text = body.get("page_text").and_then(|v| v.as_str()).unwrap_or("");
            let selected = body.get("selected").and_then(|v| v.as_str()).unwrap_or("");
            match build_text_fragment_url(page_url, page_text, selected) {
                Some(frag_url) => ok_json(&serde_json::json!({ "ok": true, "url": frag_url })),
                None => err_json("400 Bad Request", "Unable to build text fragment"),
            }
        }
        "/api/page_tools/smart_copy" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let title = body.get("title").and_then(|v| v.as_str()).unwrap_or("");
            let url = body.get("url").and_then(|v| v.as_str()).unwrap_or("");
            let fmt = match body
                .get("format")
                .and_then(|v| v.as_str())
                .unwrap_or("markdown")
            {
                "plain" => SmartCopyFormat::Plain,
                "clean" => SmartCopyFormat::Clean,
                "html" => SmartCopyFormat::HtmlRich,
                _ => SmartCopyFormat::Markdown,
            };
            ok_json(&serde_json::json!({ "output": format_smart_copy(title, url, fmt) }))
        }
        "/api/page_tools/diff" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let left = body.get("left").and_then(|v| v.as_str()).unwrap_or("");
            let right = body.get("right").and_then(|v| v.as_str()).unwrap_or("");
            ok_json(&serde_json::json!({ "lines": compute_line_diff(left, right) }))
        }
        "/api/page_tools/jsonpath" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let data = body.get("data").cloned().unwrap_or(serde_json::Value::Null);
            let expr = body.get("expr").and_then(|v| v.as_str()).unwrap_or("$");
            let matches = evaluate_jsonpath(&data, expr);
            ok_json(&serde_json::json!({ "matches": matches }))
        }
        "/api/page_tools/xml" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let xml = body.get("xml").and_then(|v| v.as_str()).unwrap_or("");
            let xpath = body.get("xpath").and_then(|v| v.as_str()).unwrap_or("");
            match parse_xml_tree(xml) {
                Ok(root) => {
                    let nodes = if xpath.is_empty() {
                        Vec::new()
                    } else {
                        evaluate_xpath_simple(&root, xpath)
                    };
                    ok_json(&serde_json::json!({ "root": root, "xpath_matches": nodes }))
                }
                Err(e) => err_json("400 Bad Request", e.to_string()),
            }
        }
        "/api/page_tools/rss" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let html = body.get("html").and_then(|v| v.as_str()).unwrap_or("");
            ok_json(&serde_json::json!({ "feeds": extract_rss_feeds_from_html(html) }))
        }

        // ====================================================================
        // DOMAIN 4: PRIVACY SHIELDS, THREAT GUARD, PERMISSIONS, DNS & HSTS
        // ====================================================================
        "/api/shields/site_policy" => {
            if req.method == "POST" {
                let body = parse_body(req);
                let site = body.get("site").and_then(|v| v.as_str()).unwrap_or("");
                if site.is_empty() {
                    return Some(err_json("400 Bad Request", "Missing site"));
                }
                let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
                let mut pol = shell.core.adblocker.get_site_policy(site);
                if let Some(v) = body.get("enabled").and_then(|x| x.as_bool()) {
                    pol.enabled = v;
                }
                if let Some(lvl) = body.get("adblock_level").and_then(|x| x.as_str()) {
                    pol.adblock_level = match lvl {
                        "disabled" | "off" => AdblockLevel::Off,
                        "aggressive" => AdblockLevel::Aggressive,
                        _ => AdblockLevel::Standard,
                    };
                }
                if let Some(lvl) = body.get("fingerprint_level").and_then(|x| x.as_str()) {
                    pol.fingerprint_level = match lvl {
                        "disabled" | "off" => FingerprintProtectionLevel::Off,
                        "strict" => FingerprintProtectionLevel::Strict,
                        _ => FingerprintProtectionLevel::Standard,
                    };
                }
                if let Some(lvl) = body.get("cookie_level").and_then(|x| x.as_str()) {
                    pol.cookie_level = match lvl {
                        "allow_all" => CookieBlockingLevel::AllowAll,
                        "block_all" => CookieBlockingLevel::BlockAll,
                        _ => CookieBlockingLevel::BlockThirdParty,
                    };
                }
                if let Some(v) = body.get("block_all_scripts").and_then(|x| x.as_bool()) {
                    pol.block_all_scripts = v;
                }
                if let Some(v) = body.get("forgetful_browsing").and_then(|x| x.as_bool()) {
                    pol.forgetful_browsing = v;
                }
                shell.core.adblocker.set_site_policy(site, pol.clone());
                ok_json(&serde_json::json!({ "ok": true, "policy": pol }))
            } else {
                let site = params.get("site").map(String::as_str).unwrap_or("");
                let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
                let pol: SiteShieldsPolicy = shell.core.adblocker.get_site_policy(site);
                ok_json(&serde_json::json!({
                    "site": site,
                    "policy": pol,
                    "total_blocked": shell.core.adblocker.total_blocked_requests(),
                }))
            }
        }
        "/api/shields/filter_lists" => {
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            ok_json(&serde_json::json!({ "lists": shell.core.adblocker.subscriptions() }))
        }
        "/api/shields/cosmetic" => {
            let host = params.get("host").map(String::as_str).unwrap_or("");
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            ok_json(&shell.core.adblocker.cosmetic_resources_for_host(host))
        }
        "/api/shields/logger" => {
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            ok_json(&serde_json::json!({
                "enabled": shell.core.adblocker.is_logger_enabled(),
                "events": shell.core.adblocker.recent_log_events(),
            }))
        }
        "/api/shields/logger_toggle" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let enabled = body
                .get("enabled")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            shell.core.adblocker.set_logger_enabled(enabled);
            if body.get("clear").and_then(|v| v.as_bool()).unwrap_or(false) {
                shell.core.adblocker.clear_log();
            }
            ok_json(&serde_json::json!({ "ok": true, "enabled": enabled }))
        }
        "/api/shields/threat_check" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let url = body.get("url").and_then(|v| v.as_str()).unwrap_or("");
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let verdict = shell.core.threat_guard.evaluate_url(url);
            let debounced = UBlockNetworkEngine::debounce_tracking_redirect(url);
            ok_json(&serde_json::json!({
                "verdict": verdict,
                "is_safe": verdict.is_safe(),
                "debounced_url": debounced,
            }))
        }
        "/api/permissions/list" => {
            let origin = params.get("origin").map(String::as_str).unwrap_or("");
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            ok_json(&serde_json::json!({
                "origin": origin,
                "grants": shell.permissions.list_for_origin(origin),
            }))
        }
        "/api/permissions/set" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let origin = body.get("origin").and_then(|v| v.as_str()).unwrap_or("");
            let Ok(kind) = serde_json::from_value::<PermissionKind>(
                body.get("kind").cloned().unwrap_or(serde_json::Value::Null),
            ) else {
                return Some(err_json("400 Bad Request", "Invalid PermissionKind"));
            };
            let Ok(decision) = serde_json::from_value::<PermissionDecision>(
                body.get("decision")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null),
            ) else {
                return Some(err_json("400 Bad Request", "Invalid PermissionDecision"));
            };
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            shell.permissions.set_permission(
                origin,
                kind,
                decision,
                PermissionScope::Permanent,
                unix_now(),
            );
            let _ = shell.save_permissions();
            ok_json(&serde_json::json!({ "ok": true }))
        }
        "/api/permissions/reset_site" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let origin = body.get("origin").and_then(|v| v.as_str()).unwrap_or("");
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let removed = shell.permissions.reset_origin(origin);
            let _ = shell.save_permissions();
            ok_json(&serde_json::json!({ "ok": true, "removed": removed }))
        }
        "/api/dns/presets" => ok_json(&serde_json::json!({
            "presets": DnsProviderPreset::all_presets()
        })),
        "/api/dns/cache" => {
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            ok_json(&serde_json::json!({
                "entries": shell.core.dns_resolver.snapshot_cache_entries()
            }))
        }
        "/api/dns/clear_cache" => {
            if let Err(r) = require_post(req) {
                return Some(r);
            }
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let cleared = shell.core.dns_resolver.clear_cache();
            ok_json(&serde_json::json!({ "ok": true, "cleared": cleared }))
        }
        "/api/privacy/shred_site" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let domain = body
                .get("domain")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            if domain.is_empty() {
                return Some(err_json("400 Bad Request", "Missing domain"));
            }
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let hist_removed = shell.history_store.delete_domain(domain);
            let perm_removed = shell
                .permissions
                .reset_origin(&format!("https://{}", domain));
            shell.core.hsts_store.purge_partition(domain);
            shell.core.adblocker.remove_site_policy(domain);
            let _ = shell.save_history_store();
            let _ = shell.save_permissions();
            ok_json(&serde_json::json!({
                "ok": true,
                "domain": domain,
                "history_removed": hist_removed,
                "permissions_removed": perm_removed,
            }))
        }

        // ====================================================================
        // DOMAIN 5: VAULT V2, GENERATOR, HEALTH, PASSKEYS, TOTP, IMPORT/EXPORT, CXF, SEND
        // ====================================================================
        "/api/vault/items" => {
            let _vault_op = cfg.map(|c| c.vault_op_lock.lock().unwrap_or_else(|e| e.into_inner()));
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            enforce_v3_vault_auto_lock(&mut shell, cfg);
            let q = params.get("q").map(String::as_str).unwrap_or("");
            if shell.vault.is_locked() {
                return Some(err_json("423 Locked", "Vault is locked"));
            }
            shell.touch_vault_activity();
            let items = if q.is_empty() {
                match shell.vault.active_items() {
                    Ok(list) => list.into_iter().cloned().collect::<Vec<_>>(),
                    Err(e) => return Some(err_json("423 Locked", e)),
                }
            } else {
                match shell.vault.search_items(q, false) {
                    Ok(hits) => hits.into_iter().take(50).map(|h| h.item.clone()).collect(),
                    Err(e) => return Some(err_json("423 Locked", e)),
                }
            };
            let trashed = shell.vault.trashed_items().map(|v| v.len()).unwrap_or(0);
            ok_json(&serde_json::json!({ "items": items, "trashed_count": trashed }))
        }
        "/api/vault/items/upsert" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let Ok(item) = serde_json::from_value::<VaultItem>(body) else {
                return Some(err_json("400 Bad Request", "Invalid VaultItem JSON"));
            };
            let _vault_op = cfg.map(|c| c.vault_op_lock.lock().unwrap_or_else(|e| e.into_inner()));
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            enforce_v3_vault_auto_lock(&mut shell, cfg);
            if shell.vault.is_locked() {
                return Some(err_json("423 Locked", "Vault is locked"));
            }
            match shell.vault.upsert_item(item, unix_now()) {
                Ok(()) => {
                    shell.touch_vault_activity();
                    let _ = shell.persist_unlocked_vault_to_disk();
                    ok_json(&serde_json::json!({ "ok": true }))
                }
                Err(e) => err_json("400 Bad Request", e),
            }
        }
        "/api/vault/items/trash" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let id = body.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let _vault_op = cfg.map(|c| c.vault_op_lock.lock().unwrap_or_else(|e| e.into_inner()));
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            enforce_v3_vault_auto_lock(&mut shell, cfg);
            if shell.vault.is_locked() {
                return Some(err_json("423 Locked", "Vault is locked"));
            }
            match shell.vault.trash_item(id, unix_now()) {
                Ok(ok) => {
                    shell.touch_vault_activity();
                    let _ = shell.persist_unlocked_vault_to_disk();
                    ok_json(&serde_json::json!({ "ok": ok }))
                }
                Err(e) => err_json("400 Bad Request", e),
            }
        }
        "/api/vault/items/restore" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let id = body.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let _vault_op = cfg.map(|c| c.vault_op_lock.lock().unwrap_or_else(|e| e.into_inner()));
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            enforce_v3_vault_auto_lock(&mut shell, cfg);
            if shell.vault.is_locked() {
                return Some(err_json("423 Locked", "Vault is locked"));
            }
            match shell.vault.restore_item(id, unix_now()) {
                Ok(ok) => {
                    shell.touch_vault_activity();
                    let _ = shell.persist_unlocked_vault_to_disk();
                    ok_json(&serde_json::json!({ "ok": ok }))
                }
                Err(e) => err_json("400 Bad Request", e),
            }
        }
        "/api/vault/folders" => {
            let _vault_op = cfg.map(|c| c.vault_op_lock.lock().unwrap_or_else(|e| e.into_inner()));
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            enforce_v3_vault_auto_lock(&mut shell, cfg);
            if shell.vault.is_locked() {
                return Some(err_json("423 Locked", "Vault is locked"));
            }
            shell.touch_vault_activity();
            match shell.vault.folders() {
                Ok(f) => ok_json(&serde_json::json!({ "folders": f })),
                Err(e) => err_json("423 Locked", e),
            }
        }
        "/api/vault/folders/upsert" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let Ok(folder) = serde_json::from_value::<VaultFolder>(body) else {
                return Some(err_json("400 Bad Request", "Invalid VaultFolder JSON"));
            };
            let _vault_op = cfg.map(|c| c.vault_op_lock.lock().unwrap_or_else(|e| e.into_inner()));
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            enforce_v3_vault_auto_lock(&mut shell, cfg);
            if shell.vault.is_locked() {
                return Some(err_json("423 Locked", "Vault is locked"));
            }
            match shell.vault.upsert_folder(folder, unix_now()) {
                Ok(()) => {
                    shell.touch_vault_activity();
                    let _ = shell.persist_unlocked_vault_to_disk();
                    ok_json(&serde_json::json!({ "ok": true }))
                }
                Err(e) => err_json("400 Bad Request", e),
            }
        }
        "/api/vault/generate" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let mode = body
                .get("mode")
                .and_then(|v| v.as_str())
                .unwrap_or("password");
            let origin = body
                .get("origin")
                .and_then(|v| v.as_str())
                .map(String::from);
            let _vault_op = cfg.map(|c| c.vault_op_lock.lock().unwrap_or_else(|e| e.into_inner()));
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            enforce_v3_vault_auto_lock(&mut shell, cfg);
            if mode == "passphrase" {
                let pp_cfg = PassphraseConfig {
                    word_count: body.get("words").and_then(|v| v.as_u64()).unwrap_or(5) as usize,
                    separator: body
                        .get("separator")
                        .and_then(|v| v.as_str())
                        .unwrap_or("-")
                        .to_string(),
                    capitalization: match body
                        .get("capitalization")
                        .and_then(|v| v.as_str())
                        .unwrap_or("title")
                    {
                        "lower" => WordCapitalization::Lowercase,
                        "upper" => WordCapitalization::Uppercase,
                        _ => WordCapitalization::TitleCase,
                    },
                    include_number: body
                        .get("include_number")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(true),
                    language: if body.get("language").and_then(|v| v.as_str()) == Some("fr") {
                        WordlistLanguage::French
                    } else {
                        WordlistLanguage::English
                    },
                };
                let res = if !shell.vault.is_locked() {
                    shell.touch_vault_activity();
                    shell
                        .vault
                        .generate_and_record_passphrase(&pp_cfg, origin, unix_now())
                } else {
                    singularity_vault::generate_passphrase(&pp_cfg).map_err(|e| e.to_string())
                };
                match res {
                    Ok(g) => ok_json(&serde_json::json!({
                        "secret": g.value,
                        "entropy_bits": g.entropy_bits,
                    })),
                    Err(e) => err_json("400 Bad Request", e),
                }
            } else {
                let mut pw_cfg = PasswordGeneratorConfig::default();
                if let Some(len) = body.get("length").and_then(|v| v.as_u64()) {
                    pw_cfg.length = len.clamp(8, 128) as usize;
                }
                if let Some(v) = body.get("exclude_ambiguous").and_then(|v| v.as_bool()) {
                    pw_cfg.exclude_ambiguous = v;
                }
                if let Some(v) = body.get("include_symbols").and_then(|v| v.as_bool()) {
                    pw_cfg.symbols = v;
                }
                let res = if !shell.vault.is_locked() {
                    shell.touch_vault_activity();
                    shell
                        .vault
                        .generate_and_record_password(&pw_cfg, origin, unix_now())
                } else {
                    singularity_vault::generate_password(&pw_cfg).map_err(|e| e.to_string())
                };
                match res {
                    Ok(g) => ok_json(&serde_json::json!({
                        "secret": g.value,
                        "entropy_bits": g.entropy_bits,
                    })),
                    Err(e) => err_json("400 Bad Request", e),
                }
            }
        }
        "/api/vault/generator_history" => {
            let _vault_op = cfg.map(|c| c.vault_op_lock.lock().unwrap_or_else(|e| e.into_inner()));
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            enforce_v3_vault_auto_lock(&mut shell, cfg);
            if shell.vault.is_locked() {
                return Some(err_json("423 Locked", "Vault is locked"));
            }
            shell.touch_vault_activity();
            match shell.vault.generator_history() {
                Ok(h) => ok_json(&serde_json::json!({ "history": h })),
                Err(e) => err_json("423 Locked", e),
            }
        }
        "/api/vault/health" => {
            let _vault_op = cfg.map(|c| c.vault_op_lock.lock().unwrap_or_else(|e| e.into_inner()));
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            enforce_v3_vault_auto_lock(&mut shell, cfg);
            if shell.vault.is_locked() {
                return Some(err_json("423 Locked", "Vault is locked"));
            }
            shell.touch_vault_activity();
            match shell.vault.generate_health_report(unix_now()) {
                Ok(report) => ok_json(&report),
                Err(e) => err_json("423 Locked", e),
            }
        }
        "/api/vault/passkeys" => {
            let _vault_op = cfg.map(|c| c.vault_op_lock.lock().unwrap_or_else(|e| e.into_inner()));
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            enforce_v3_vault_auto_lock(&mut shell, cfg);
            if shell.vault.is_locked() {
                return Some(err_json("423 Locked", "Vault is locked"));
            }
            shell.touch_vault_activity();
            match shell.vault.passkeys() {
                Ok(list) => ok_json(&serde_json::json!({ "passkeys": list })),
                Err(e) => err_json("423 Locked", e),
            }
        }
        "/api/vault/passkeys/enroll" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let rp_id = body.get("rp_id").and_then(|v| v.as_str()).unwrap_or("");
            let rp_name = body.get("rp_name").and_then(|v| v.as_str()).unwrap_or(rp_id);
            let user_name = body.get("user_name").and_then(|v| v.as_str()).unwrap_or("");
            let display_name = body
                .get("display_name")
                .and_then(|v| v.as_str())
                .unwrap_or(user_name);
            let _vault_op = cfg.map(|c| c.vault_op_lock.lock().unwrap_or_else(|e| e.into_inner()));
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            enforce_v3_vault_auto_lock(&mut shell, cfg);
            if shell.vault.is_locked() {
                return Some(err_json("423 Locked", "Vault is locked"));
            }
            match shell.vault.enroll_passkey_v2(
                rp_id,
                rp_name,
                user_name,
                display_name,
                PasskeyAlgorithm::Ed25519,
                None,
                unix_now(),
            ) {
                Ok(cred) => {
                    shell.touch_vault_activity();
                    let _ = shell.persist_unlocked_vault_to_disk();
                    ok_json(&serde_json::json!({ "ok": true, "passkey": cred }))
                }
                Err(e) => err_json("400 Bad Request", e),
            }
        }
        "/api/vault/totp_live" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let _vault_op = cfg.map(|c| c.vault_op_lock.lock().unwrap_or_else(|e| e.into_inner()));
            {
                let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
                enforce_v3_vault_auto_lock(&mut shell, cfg);
                if !shell.vault.is_locked() {
                    shell.touch_vault_activity();
                }
            }
            let secret = Zeroizing::new(
                body.get("secret")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            );
            let digits = body.get("digits").and_then(|v| v.as_u64()).unwrap_or(6) as u32;
            let period = body.get("period").and_then(|v| v.as_u64()).unwrap_or(30);
            match singularity_vault::generate_totp_with_next(
                secret.as_str(),
                unix_now(),
                period,
                digits,
                singularity_vault::TotpAlgorithm::Sha1,
            ) {
                Ok((current, next, remaining)) => ok_json(&serde_json::json!({
                    "code": current,
                    "next_code": next,
                    "remaining_seconds": remaining,
                })),
                Err(e) => err_json("400 Bad Request", e.to_string()),
            }
        }
        "/api/vault/recovery_key" => {
            if let Err(r) = require_post(req) {
                return Some(r);
            }
            let _vault_op = cfg.map(|c| c.vault_op_lock.lock().unwrap_or_else(|e| e.into_inner()));
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            enforce_v3_vault_auto_lock(&mut shell, cfg);
            if shell.vault.is_locked() {
                return Some(err_json("423 Locked", "Vault is locked"));
            }
            match shell.vault.generate_and_bind_recovery_key(unix_now()) {
                Ok(key_str) => {
                    shell.touch_vault_activity();
                    let key_zero = Zeroizing::new(key_str);
                    #[derive(serde::Serialize)]
                    struct RecoveryKeyResp<'a> {
                        ok: bool,
                        recovery_key: &'a str,
                    }
                    let json_bytes = serde_json::to_vec(&RecoveryKeyResp {
                        ok: true,
                        recovery_key: key_zero.as_str(),
                    })
                    .unwrap_or_else(|_| b"{\"ok\":false}".to_vec());
                    HttpResponse::new("200 OK", "application/json; charset=utf-8", json_bytes)
                }
                Err(e) => err_json("400 Bad Request", e.to_string()),
            }
        }
        "/api/vault/import_preview" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let raw = Zeroizing::new(
                body.get("data")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            );
            let _vault_op = cfg.map(|c| c.vault_op_lock.lock().unwrap_or_else(|e| e.into_inner()));
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            enforce_v3_vault_auto_lock(&mut shell, cfg);
            if shell.vault.is_locked() {
                return Some(err_json("423 Locked", "Vault is locked"));
            }
            shell.touch_vault_activity();
            match shell.vault.preview_import(raw.as_str(), None, unix_now()) {
                Ok(prev) => ok_json(&prev),
                Err(e) => err_json("400 Bad Request", e),
            }
        }
        "/api/vault/import_commit" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let raw = Zeroizing::new(
                body.get("data")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            );
            let strategy = match body
                .get("strategy")
                .and_then(|v| v.as_str())
                .unwrap_or("skip")
            {
                "overwrite" => ConflictResolution::Overwrite,
                "keep_both" => ConflictResolution::KeepBoth,
                _ => ConflictResolution::Skip,
            };
            let now = unix_now();
            let _vault_op = cfg.map(|c| c.vault_op_lock.lock().unwrap_or_else(|e| e.into_inner()));
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            enforce_v3_vault_auto_lock(&mut shell, cfg);
            if shell.vault.is_locked() {
                return Some(err_json("423 Locked", "Vault is locked"));
            }
            let preview = match shell.vault.preview_import(raw.as_str(), None, now) {
                Ok(p) => p,
                Err(e) => return Some(err_json("400 Bad Request", e)),
            };
            match shell.vault.apply_import(preview, strategy, now) {
                Ok(res) => {
                    shell.touch_vault_activity();
                    let _ = shell.persist_unlocked_vault_to_disk();
                    ok_json(&res)
                }
                Err(e) => err_json("400 Bad Request", e),
            }
        }
        "/api/vault/export_format" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let fmt = body
                .get("format")
                .and_then(|v| v.as_str())
                .or_else(|| params.get("format").map(String::as_str))
                .unwrap_or("json");
            let _vault_op = cfg.map(|c| c.vault_op_lock.lock().unwrap_or_else(|e| e.into_inner()));
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            enforce_v3_vault_auto_lock(&mut shell, cfg);
            if shell.vault.is_locked() {
                return Some(err_json("423 Locked", "Vault is locked"));
            }
            shell.touch_vault_activity();
            let res = match fmt {
                "csv" => shell.vault.export_csv().map(Zeroizing::new),
                "cxf" => shell
                    .vault
                    .export_cxf("local@singularity.browser", unix_now())
                    .and_then(|doc| serialize_cxf_json(&doc).map_err(|e| e.to_string()))
                    .map(Zeroizing::new),
                _ => shell.vault.export_plain_json().map(Zeroizing::new),
            };
            match res {
                Ok(data) => {
                    #[derive(serde::Serialize)]
                    struct VaultExportFormatResp<'a> {
                        ok: bool,
                        format: &'a str,
                        data: &'a str,
                    }
                    match serde_json::to_vec(&VaultExportFormatResp {
                        ok: true,
                        format: fmt,
                        data: data.as_str(),
                    }) {
                        Ok(bytes) => {
                            HttpResponse::new("200 OK", "application/json; charset=utf-8", bytes)
                        }
                        Err(e) => err_json("500 Internal Server Error", e.to_string()),
                    }
                }
                Err(e) => err_json("400 Bad Request", e),
            }
        }
        "/api/vault/send_create" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let _vault_op = cfg.map(|c| c.vault_op_lock.lock().unwrap_or_else(|e| e.into_inner()));
            {
                let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
                enforce_v3_vault_auto_lock(&mut shell, cfg);
                if !shell.vault.is_locked() {
                    shell.touch_vault_activity();
                }
            }
            let text = Zeroizing::new(
                body.get("text")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            );
            let password = Zeroizing::new(
                body.get("password")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            );
            let ttl_secs = body
                .get("ttl_secs")
                .and_then(|v| v.as_u64())
                .unwrap_or(3600)
                .max(60);
            let max_views = body
                .get("max_views")
                .and_then(|v| v.as_u64())
                .unwrap_or(1)
                .max(1) as u32;
            let now = unix_now();
            match SingularitySendEnvelope::seal_with_password(
                format!("send-{}", now),
                text.as_bytes(),
                SendPayloadType::Text,
                password.as_bytes(),
                crate::shell::DESKTOP_VAULT_KDF,
                now,
                ttl_secs,
                max_views,
            ) {
                Ok(env) => ok_json(&env),
                Err(e) => err_json("400 Bad Request", e.to_string()),
            }
        }

        // ====================================================================
        // DOMAIN 6: DOWNLOADS, GLOBAL MEDIA CONTROLS, DSP EQ 600%, TTS, CAPTIONS, CAST
        // ====================================================================
        "/api/downloads/list" => {
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            ok_json(&serde_json::json!({
                "records": shell.core.download_manager.records(),
                "active_count": shell.core.download_manager.active_count(),
                "queued_count": shell.core.download_manager.queued_count(),
                "max_concurrent": shell.core.download_manager.max_concurrent(),
                "rules": shell.core.download_manager.routing_rules(),
            }))
        }
        "/api/downloads/enqueue" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let url = body.get("url").and_then(|v| v.as_str()).unwrap_or("");
            let filename = body
                .get("filename")
                .and_then(|v| v.as_str())
                .unwrap_or("download.bin");
            let referrer = body.get("referrer").and_then(|v| v.as_str());
            let mime = body.get("mime").and_then(|v| v.as_str());
            let total = body.get("total_bytes").and_then(|v| v.as_u64());
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let core = &mut shell.core;
            let danger = classify_download_danger(
                filename,
                url,
                referrer,
                Some(&core.threat_guard),
            );
            let id = core.download_manager.enqueue_download(
                url,
                filename,
                referrer,
                mime,
                total,
                false,
                Some(&core.threat_guard),
                unix_now(),
            );
            let rec = core.download_manager.get(id).cloned();
            ok_json(&serde_json::json!({ "ok": true, "id": id, "record": rec, "danger": danger }))
        }
        "/api/downloads/action" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let id = body.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
            let action = body.get("action").and_then(|v| v.as_str()).unwrap_or("");
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let now = unix_now();
            let ok = match action {
                "pause" => shell.core.download_manager.pause(id, now),
                "resume" => shell.core.download_manager.resume(id, now),
                "cancel" => shell.core.download_manager.cancel(id, now),
                "retry" => shell.core.download_manager.retry(id, now),
                _ => false,
            };
            ok_json(&serde_json::json!({ "ok": ok }))
        }
        "/api/downloads/verify_sha256" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let raw_path = body.get("path").and_then(|v| v.as_str()).unwrap_or("");
            let expected = body
                .get("expected_sha256")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let trimmed = raw_path.trim();
            if is_unc_or_device_path(trimmed) || has_parent_dir_component(trimmed) {
                return Some(err_json(
                    "400 Bad Request",
                    "Invalid or disallowed download path",
                ));
            }
            let target = Path::new(trimmed);
            let meta = match std::fs::symlink_metadata(target) {
                Ok(m) => m,
                Err(e) => {
                    return Some(err_json(
                        "400 Bad Request",
                        format!("Cannot inspect download file: {}", e),
                    ))
                }
            };
            if is_symlink_or_reparse_meta(&meta) || !meta.file_type().is_file() {
                return Some(err_json(
                    "400 Bad Request",
                    "Download verification target must be a regular file",
                ));
            }
            let Ok(canon_target) = std::fs::canonicalize(target) else {
                return Some(err_json("400 Bad Request", "Unable to resolve download path"));
            };
            if canon_target
                .to_string_lossy()
                .to_ascii_uppercase()
                .starts_with("\\\\?\\UNC\\")
            {
                return Some(err_json(
                    "400 Bad Request",
                    "UNC network paths are not permitted",
                ));
            }
            let mut allowed_roots = Vec::new();
            if let Ok(canon_dl) = std::fs::canonicalize(crate::server::resolve_downloads_dir()) {
                allowed_roots.push(canon_dl);
            }
            {
                let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
                let profile_dl = shell.roaming.root_dir().join("downloads");
                if let Ok(canon_pdl) = std::fs::canonicalize(profile_dl) {
                    allowed_roots.push(canon_pdl);
                }
            }
            if !allowed_roots
                .iter()
                .any(|root| canon_target.starts_with(root))
            {
                return Some(err_json(
                    "403 Forbidden",
                    "File path must reside inside the configured downloads directory",
                ));
            }
            match verify_file_sha256(&canon_target, expected) {
                Ok(matched) => ok_json(&serde_json::json!({ "ok": true, "matched": matched })),
                Err(e) => err_json("400 Bad Request", e),
            }
        }
        "/api/downloads/rules" => {
            if req.method == "POST" {
                let body = parse_body(req);
                let Ok(rule) = serde_json::from_value::<DownloadRoutingRule>(body) else {
                    return Some(err_json("400 Bad Request", "Invalid DownloadRoutingRule"));
                };
                let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
                shell.core.download_manager.add_routing_rule(rule);
                ok_json(&serde_json::json!({ "ok": true }))
            } else {
                let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
                ok_json(&serde_json::json!({
                    "rules": shell.core.download_manager.routing_rules()
                }))
            }
        }
        "/api/media/sessions" => {
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            ok_json(&serde_json::json!({
                "sessions": shell.media_sessions.sessions(),
                "os_transport": shell.media_sessions.os_transport_metadata(shell.private_browsing_active),
            }))
        }
        "/api/media/session_upsert" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let Ok(session) = serde_json::from_value::<TabMediaSession>(body) else {
                return Some(err_json("400 Bad Request", "Invalid TabMediaSession"));
            };
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            shell.media_sessions.register_or_update(session);
            ok_json(&serde_json::json!({ "ok": true }))
        }
        "/api/media/control" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let tab_id = body.get("tab_id").and_then(|v| v.as_u64());
            let Ok(action) = serde_json::from_value::<MediaControlAction>(
                body.get("action")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null),
            ) else {
                return Some(err_json("400 Bad Request", "Invalid MediaControlAction"));
            };
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let applied = shell.media_sessions.dispatch_action(tab_id, action);
            ok_json(&serde_json::json!({ "ok": applied.is_some(), "session": applied }))
        }
        "/api/media/capabilities" => ok_json(&probe_platform_capabilities()),
        "/api/media/equalizer" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(boost) = body.get("volume_boost_percent").and_then(|v| v.as_f64()) {
                shell.equalizer.set_volume_boost_percent(boost);
            }
            if let Some(preset_str) = body.get("preset").and_then(|v| v.as_str()) {
                let preset = match preset_str {
                    "event_horizon" | "sub_bass" => EqualizerPreset::EventHorizonSubBass,
                    "harman" => EqualizerPreset::HarmanOverEar2018,
                    "vocal" | "podcast" => EqualizerPreset::VocalPodcast,
                    "cinema" => EqualizerPreset::Cinema,
                    "gaming" => EqualizerPreset::Gaming,
                    _ => EqualizerPreset::Flat,
                };
                shell.equalizer.apply_preset(preset);
            }
            if let Some(gains) = body.get("bands_db").and_then(|v| v.as_array()) {
                for (i, g) in gains.iter().take(10).enumerate() {
                    if let Some(db) = g.as_f64() {
                        shell.equalizer.set_band_gain_db(i, db, 1.41);
                    }
                }
            }
            ok_json(&serde_json::json!({
                "ok": true,
                "volume_boost_percent": shell.equalizer.volume_boost_percent(),
                "bands_db": shell.equalizer.bands().iter().map(|b| b.gain_db).collect::<Vec<_>>(),
            }))
        }
        "/api/media/subtitles_convert" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let raw = body.get("text").and_then(|v| v.as_str()).unwrap_or("");
            let fmt = body.get("format").and_then(|v| v.as_str()).unwrap_or("srt");
            let offset_ms = body.get("offset_ms").and_then(|v| v.as_i64()).unwrap_or(0);
            let cues = match fmt {
                "ass" | "ssa" => parse_ass(raw),
                "vtt" => parse_vtt(raw),
                _ => parse_srt(raw),
            };
            ok_json(&serde_json::json!({
                "cue_count": cues.len(),
                "webvtt": format_as_webvtt(&cues, offset_ms),
            }))
        }
        "/api/media/tts/state" => {
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            ok_json(&serde_json::json!({
                "state": shell.tts_session.state(),
                "progress": shell.tts_session.progress(),
                "current_segment": shell.tts_session.current_segment(),
                "config": shell.tts_session.config(),
            }))
        }
        "/api/media/tts/control" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let action = body.get("action").and_then(|v| v.as_str()).unwrap_or("");
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            match action {
                "load" => {
                    let text = body.get("text").and_then(|v| v.as_str()).unwrap_or("");
                    shell.tts_session.load_text(text);
                }
                "play" => {
                    let _ = shell.tts_session.play();
                }
                "pause" => shell.tts_session.pause(),
                "stop" => shell.tts_session.stop(),
                "next" => {
                    let _ = shell.tts_session.next_sentence();
                }
                "prev" => {
                    let _ = shell.tts_session.prev_sentence();
                }
                "config" => {
                    if let Ok(cfg) = serde_json::from_value::<TtsConfig>(
                        body.get("config")
                            .cloned()
                            .unwrap_or(serde_json::Value::Null),
                    ) {
                        *shell.tts_session.config_mut() = cfg.sanitized();
                    }
                }
                _ => {}
            }
            ok_json(&serde_json::json!({
                "ok": true,
                "state": shell.tts_session.state(),
                "progress": shell.tts_session.progress(),
                "current_segment": shell.tts_session.current_segment(),
            }))
        }
        "/api/media/captions/state" => {
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            ok_json(&serde_json::json!({
                "config": shell.live_captions.config,
                "visible_lines": shell.live_captions.visible_lines(),
            }))
        }
        "/api/media/captions/config" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let Ok(cfg) = serde_json::from_value::<LiveCaptionsConfig>(body) else {
                return Some(err_json("400 Bad Request", "Invalid LiveCaptionsConfig"));
            };
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            shell.live_captions.config = cfg;
            ok_json(&serde_json::json!({ "ok": true }))
        }
        "/api/media/captions/export" => {
            let fmt = params.get("format").map(String::as_str).unwrap_or("srt");
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let out = if fmt == "txt" {
                shell.live_captions.export_txt()
            } else {
                shell.live_captions.export_srt()
            };
            HttpResponse::text("200 OK", &out)
        }
        "/api/cast/status" => {
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            ok_json(&serde_json::json!({
                "discovery_active": shell.cast_controller.is_discovery_active(),
                "active_sockets": shell.cast_controller.active_socket_count(),
                "devices": shell.cast_controller.discovered_devices(),
                "session": shell.cast_controller.session_state(),
                "mullvad_lan_exception": shell.cast_controller.mullvad_lan_exception_target(),
            }))
        }
        "/api/cast/discover_start" => {
            if let Err(r) = require_post(req) {
                return Some(r);
            }
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let res = shell
                .cast_controller
                .begin_user_discovery_session(unix_now().saturating_mul(1000));
            ok_json(&serde_json::json!({
                "ok": res.is_ok(),
                "discovery_active": shell.cast_controller.is_discovery_active(),
            }))
        }
        "/api/cast/discover_stop" => {
            if let Err(r) = require_post(req) {
                return Some(r);
            }
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            shell.cast_controller.end_discovery_session();
            ok_json(&serde_json::json!({
                "ok": true,
                "discovery_active": shell.cast_controller.is_discovery_active(),
                "active_sockets": shell.cast_controller.active_socket_count(),
            }))
        }
        "/api/cast/command" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let Ok(cmd) = serde_json::from_value::<CastPlaybackCommand>(body) else {
                return Some(err_json("400 Bad Request", "Invalid CastPlaybackCommand"));
            };
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            match shell.cast_controller.send_command(cmd) {
                Ok(wire) => ok_json(&serde_json::json!({
                    "ok": true,
                    "wire_bytes": wire.payload.len(),
                    "endpoint": wire.endpoint_hint
                })),
                Err(e) => err_json("400 Bad Request", e.to_string()),
            }
        }

        // ====================================================================
        // DOMAIN 7: GRANULAR EXTENSIONS, USERSCRIPTS & PWA
        // ====================================================================
        "/api/extensions/site_access" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let id = body.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let mode = match body
                .get("mode")
                .and_then(|v| v.as_str())
                .unwrap_or("on_all_sites")
            {
                "on_click" => SiteAccessMode::OnClick,
                "on_specific_sites" => SiteAccessMode::OnSpecificSites,
                _ => SiteAccessMode::OnAllSites,
            };
            let sites: Vec<String> = body
                .get("allowed_sites")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            match set_extension_site_access(shell.roaming.root_dir(), id, mode, sites) {
                Ok(()) => ok_json(&serde_json::json!({ "ok": true })),
                Err(e) => err_json("400 Bad Request", e),
            }
        }
        "/api/extensions/privacy_flags" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let id = body.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            match set_extension_privacy_flags(
                shell.roaming.root_dir(),
                id,
                body.get("allow_in_incognito").and_then(|v| v.as_bool()),
                body.get("allow_file_urls").and_then(|v| v.as_bool()),
                body.get("allow_user_scripts").and_then(|v| v.as_bool()),
            ) {
                Ok(()) => ok_json(&serde_json::json!({ "ok": true })),
                Err(e) => err_json("400 Bad Request", e),
            }
        }
        "/api/extensions/shortcut" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let id = body.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let cmd_name = body.get("command").and_then(|v| v.as_str()).unwrap_or("");
            let shortcut = body
                .get("shortcut")
                .and_then(|v| v.as_str())
                .map(String::from);
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            match set_extension_command_shortcut(shell.roaming.root_dir(), id, cmd_name, shortcut) {
                Ok(()) => ok_json(&serde_json::json!({ "ok": true })),
                Err(e) => err_json("400 Bad Request", e),
            }
        }
        "/api/extensions/errors" => {
            let id = params.get("id").map(String::as_str).unwrap_or("");
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            ok_json(&serde_json::json!({
                "errors": get_extension_errors(shell.roaming.root_dir(), id)
            }))
        }
        "/api/extensions/errors_clear" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let id = body.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            match clear_extension_errors(shell.roaming.root_dir(), id) {
                Ok(()) => ok_json(&serde_json::json!({ "ok": true })),
                Err(e) => err_json("400 Bad Request", e),
            }
        }
        "/api/extensions/badge" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let id = body.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let text = body
                .get("text")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let bg = body
                .get("bg_color")
                .and_then(|v| v.as_str())
                .map(String::from);
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            match set_extension_action_badge(shell.roaming.root_dir(), id, text, bg) {
                Ok(()) => ok_json(&serde_json::json!({ "ok": true })),
                Err(e) => err_json("400 Bad Request", e),
            }
        }
        "/api/extensions/stage_review" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            if let Some(p) = body.get("path").and_then(|v| v.as_str()) {
                let trimmed = p.trim();
                if is_unc_or_device_path(trimmed) || has_parent_dir_component(trimmed) {
                    return Some(err_json(
                        "400 Bad Request",
                        "Invalid or disallowed extension package path",
                    ));
                }
                let target = Path::new(trimmed);
                let meta = match std::fs::symlink_metadata(target) {
                    Ok(m) => m,
                    Err(e) => {
                        return Some(err_json(
                            "400 Bad Request",
                            format!("Cannot inspect extension package: {}", e),
                        ))
                    }
                };
                if is_symlink_or_reparse_meta(&meta) || !meta.file_type().is_file() {
                    return Some(err_json(
                        "400 Bad Request",
                        "Extension review target must be a regular local file",
                    ));
                }
                if meta.len() > MAX_STAGE_REVIEW_CRX_BYTES {
                    return Some(err_json(
                        "400 Bad Request",
                        "Extension package exceeds 32 MiB limit",
                    ));
                }
                let Ok(canon_target) = std::fs::canonicalize(target) else {
                    return Some(err_json(
                        "400 Bad Request",
                        "Unable to resolve extension package path",
                    ));
                };
                if canon_target
                    .to_string_lossy()
                    .to_ascii_uppercase()
                    .starts_with("\\\\?\\UNC\\")
                {
                    return Some(err_json(
                        "400 Bad Request",
                        "UNC network paths are not permitted",
                    ));
                }
                match stage_extension_for_review(&canon_target) {
                    Ok(rev) => ok_json(&rev),
                    Err(e) => err_json("400 Bad Request", e),
                }
            } else {
                let perms: Vec<String> = body
                    .get("permissions")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();
                let hosts: Vec<String> = body
                    .get("host_permissions")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();
                ok_json(&serde_json::json!({
                    "warnings": describe_extension_permissions(&perms, &hosts)
                }))
            }
        }
        "/api/extensions/parse_edge_id" => {
            let input = params.get("input").map(String::as_str).unwrap_or("");
            ok_json(&serde_json::json!({ "id": parse_edge_addons_id(input) }))
        }
        "/api/userscripts/list" => {
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            ok_json(&serde_json::json!({ "scripts": shell.userscripts.list() }))
        }
        "/api/userscripts/install" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let source = body.get("source").and_then(|v| v.as_str()).unwrap_or("");
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            match shell.userscripts.install_source(source) {
                Ok(rec) => ok_json(&serde_json::json!({ "ok": true, "script": rec })),
                Err(e) => err_json("400 Bad Request", e),
            }
        }
        "/api/userscripts/toggle" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let id = body.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let enabled = body
                .get("enabled")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            match shell.userscripts.set_enabled(id, enabled) {
                Ok(()) => ok_json(&serde_json::json!({ "ok": true })),
                Err(e) => err_json("400 Bad Request", e),
            }
        }
        "/api/userscripts/delete" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let id = body.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            match shell.userscripts.remove(id) {
                Ok(removed) => ok_json(&serde_json::json!({ "ok": removed })),
                Err(e) => err_json("400 Bad Request", e),
            }
        }
        "/api/pwa/list" => {
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            ok_json(&serde_json::json!({ "apps": shell.pwas.list() }))
        }
        "/api/pwa/install" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let url = body.get("url").and_then(|v| v.as_str()).unwrap_or("");
            let title = body
                .get("title")
                .and_then(|v| v.as_str())
                .unwrap_or("Singularity App");
            let theme_color = body.get("theme_color").and_then(|v| v.as_str());
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            match shell.pwas.install_site_as_app(url, title, theme_color) {
                Ok(app) => ok_json(&serde_json::json!({ "ok": true, "app": app })),
                Err(e) => err_json("400 Bad Request", e.to_string()),
            }
        }
        "/api/pwa/uninstall" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let id = body.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            match shell.pwas.uninstall(id) {
                Ok(removed) => ok_json(&serde_json::json!({ "ok": removed })),
                Err(e) => err_json("400 Bad Request", e.to_string()),
            }
        }
        "/api/pwa/launch" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let id = body
                .get("id")
                .or_else(|| body.get("app_id"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            match shell.pwas.get(id) {
                Some(app) => ok_json(&serde_json::json!({
                    "ok": true,
                    "app": app,
                    "start_url": app.manifest.start_url,
                })),
                None => err_json("404 Not Found", "Installed PWA not found"),
            }
        }
        "/api/process/action" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let pid = body.get("pid").and_then(|v| v.as_u64()).unwrap_or(0);
            let action = body.get("action").and_then(|v| v.as_str()).unwrap_or("");
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let core = &mut shell.core;
            let ok = match action {
                "hibernate" => core.tab_manager.freeze_tab_soft(
                    pid,
                    unix_now(),
                    48 * 1024 * 1024,
                    &core.chromium_bridge,
                ),
                "terminate" => core.tab_manager.close_tab(pid).is_some(),
                _ => return Some(err_json("400 Bad Request", "Unsupported process action")),
            };
            ok_json(&serde_json::json!({ "ok": ok, "pid": pid, "action": action }))
        }
        "/api/tabs/discard" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let tab_id = body
                .get("tab_id")
                .and_then(|v| {
                    v.as_u64()
                        .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
                })
                .unwrap_or(0);
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let core = &mut shell.core;
            let discarded = core.tab_manager.discard_tab_with_reclaimed_ram(
                tab_id,
                48 * 1024 * 1024,
                &core.chromium_bridge,
            );
            ok_json(&serde_json::json!({ "ok": discarded, "tab_id": tab_id }))
        }
        "/api/tracing/toggle" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let active = body
                .get("active")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            ok_json(&serde_json::json!({ "ok": true, "active": active }))
        }
        "/api/devtools/inspect" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let target_id = body
                .get("target_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            if target_id.is_empty() {
                return Some(err_json("400 Bad Request", "Missing target_id"));
            }
            ok_json(&serde_json::json!({ "ok": true, "target_id": target_id }))
        }
        "/api/security/cert_bypass" | "/api/security/allow_http_once" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let host = body
                .get("host")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            let url = body
                .get("url")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            let indicator = if !url.is_empty() { url } else { host };
            if indicator.is_empty() {
                return Some(err_json("400 Bad Request", "Missing host or url"));
            }
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            shell.core.threat_guard.add_session_exception(indicator);
            ok_json(&serde_json::json!({
                "ok": true,
                "scope": "session",
                "host": host,
                "url": url,
            }))
        }

        // ====================================================================
        // DOMAIN 1 & 9: TABS ORGANIZER, PERFORMANCE, LIMITERS, POWER, MULLVAD
        // ====================================================================
        "/api/tabs/organize_suggest" => {
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let tabs = shell.core.tab_manager.tabs();
            let suggested = singularity_core::suggest_domain_groups(tabs, 2);
            let duplicates = singularity_core::find_duplicate_tabs(tabs);
            ok_json(&serde_json::json!({
                "suggested_groups": suggested,
                "duplicates": duplicates
            }))
        }
        "/api/performance/status" => {
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let power = shell.core.power_orchestrator.refresh_and_evaluate();
            let mem = SystemMemorySnapshot::capture();
            let health = shell.core.health_detector.evaluate_health();
            let (_, _, cache_bytes) = shell.core.asset_cache.stats();
            ok_json(&serde_json::json!({
                "limiter": shell.core.resource_limiter.config(),
                "power": power,
                "memory": mem,
                "health": health,
                "reclaimed_ram_bytes": shell.core.tab_manager.total_reclaimed_ram_bytes(),
                "cache_bytes": cache_bytes,
            }))
        }
        "/api/performance/profile" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let preset = match body
                .get("preset")
                .and_then(|v| v.as_str())
                .unwrap_or("balanced")
            {
                "eco" | "battery" => PerformanceProfilePreset::EcoEfficiency,
                "gaming" => PerformanceProfilePreset::GamingMode,
                "ultra" | "max" => PerformanceProfilePreset::MaxPerformance200Hz,
                _ => PerformanceProfilePreset::Balanced,
            };
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            shell.core.resource_limiter.apply_preset(preset);
            ok_json(&serde_json::json!({
                "ok": true,
                "limiter": shell.core.resource_limiter.config(),
            }))
        }
        "/api/performance/limiter" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let Ok(cfg) = serde_json::from_value::<ResourceLimiterConfig>(body) else {
                return Some(err_json("400 Bad Request", "Invalid ResourceLimiterConfig"));
            };
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            match shell.core.resource_limiter.set_config(cfg) {
                Ok(()) => ok_json(&serde_json::json!({ "ok": true })),
                Err(e) => err_json("400 Bad Request", e),
            }
        }
        "/api/performance/power_policy" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let pol = match body
                .get("policy")
                .and_then(|v| v.as_str())
                .unwrap_or("unplugged")
            {
                "always" => EnergySaverActivationPolicy::AlwaysOn,
                "never" | "off" => EnergySaverActivationPolicy::Off,
                "threshold" => EnergySaverActivationPolicy::BelowBatteryPercent(
                    body.get("percent").and_then(|v| v.as_u64()).unwrap_or(20) as u8,
                ),
                "follow_os" => EnergySaverActivationPolicy::FollowOsBatterySaver,
                _ => EnergySaverActivationPolicy::OnBatteryOnly,
            };
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            shell.core.power_orchestrator.set_policy(pol);
            let decision = shell.core.power_orchestrator.refresh_and_evaluate();
            ok_json(&serde_json::json!({ "ok": true, "decision": decision }))
        }
        "/api/mullvad/relays_filtered" => {
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let criteria = RelayFilterCriteria {
                country_code: params.get("country").cloned(),
                city: params.get("city").cloned(),
                owned_only: params
                    .get("owned")
                    .is_some_and(|v| v == "1" || v == "true"),
                daita_only: params
                    .get("daita")
                    .is_some_and(|v| v == "1" || v == "true"),
                pq_only: params.get("pq").is_some_and(|v| v == "1" || v == "true"),
                min_speed_gbps: params.get("min_speed").and_then(|v| v.parse().ok()),
                search_query: params.get("q").cloned(),
                obfuscation_mode: None,
            };
            ok_json(&serde_json::json!({
                "relays": shell.core.mullvad_vpn.filtered_relays(&criteria),
                "dns_ip": shell.core.mullvad_vpn.effective_in_tunnel_dns_ipv4(),
            }))
        }
        "/api/mullvad/dns_blocker" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let Ok(blocker) = serde_json::from_value::<MullvadDnsContentBlocker>(body) else {
                return Some(err_json("400 Bad Request", "Invalid MullvadDnsContentBlocker"));
            };
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            shell.core.mullvad_vpn.set_dns_blocker(blocker);
            ok_json(&serde_json::json!({
                "ok": true,
                "dns_ip": shell.core.mullvad_vpn.effective_in_tunnel_dns_ipv4(),
            }))
        }
        "/api/mullvad/obfuscation" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let mode = match body.get("mode").and_then(|v| v.as_str()).unwrap_or("auto") {
                "off" => ObfuscationMode::Off,
                "udp2tcp" => ObfuscationMode::Udp2Tcp443,
                "shadowsocks" => ObfuscationMode::Shadowsocks,
                _ => ObfuscationMode::Auto,
            };
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            shell.core.mullvad_vpn.set_obfuscation_mode(mode);
            ok_json(&serde_json::json!({ "ok": true, "mode": mode }))
        }
        "/api/mullvad/split_tunnel" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let Ok(rule) = serde_json::from_value::<SplitTunnelRule>(body) else {
                return Some(err_json("400 Bad Request", "Invalid SplitTunnelRule"));
            };
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            shell.core.mullvad_vpn.add_split_tunnel_domain_rule(rule);
            ok_json(&serde_json::json!({ "ok": true }))
        }
        "/api/mullvad/proxy_config" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let profile_id = body
                .get("profile_id")
                .and_then(|v| v.as_str())
                .unwrap_or("default")
                .to_string();
            let Ok(cfg) = serde_json::from_value::<ProxyProfileConfig>(
                body.get("config")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null),
            ) else {
                return Some(err_json("400 Bad Request", "Invalid ProxyProfileConfig"));
            };
            let cef_pref = cfg.to_cef_proxy_pref_json();
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            shell.core.mullvad_vpn.set_proxy_config(profile_id, cfg);
            ok_json(&serde_json::json!({ "ok": true, "cef_proxy_pref": cef_pref }))
        }

        // ====================================================================
        // DOMAIN 10: PROFILES, CONTAINERS, WORKSPACES, PALETTE, KEYBINDS, CHAINS,
        // GESTURES, CUSTOMIZATION, OFFLINE TRANSLATE & ZERO-KNOWLEDGE P2P SYNC
        // ====================================================================
        "/api/profiles/list" => {
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            ok_json(&shell.profiles)
        }
        "/api/profiles/create" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let id = body.get("id").and_then(|v| v.as_str());
            let name = body
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("Profile");
            let avatar = body
                .get("avatar")
                .and_then(|v| v.as_str())
                .unwrap_or("cosmic-orb");
            let color = body
                .get("color")
                .and_then(|v| v.as_str())
                .unwrap_or("#7C3AED");
            let theme = body
                .get("theme_id")
                .and_then(|v| v.as_str())
                .unwrap_or("trou-noir");
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            match shell.profiles.create_profile(id, name, avatar, color, theme) {
                Ok(prof) => {
                    let _ = shell.save_profiles();
                    ok_json(&serde_json::json!({ "ok": true, "profile": prof }))
                }
                Err(e) => err_json("400 Bad Request", e.to_string()),
            }
        }
        "/api/profiles/switch" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let id = body.get("id").and_then(|v| v.as_str()).unwrap_or("default");
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            match shell.profiles.switch_profile(id).cloned() {
                Ok(prof) => {
                    let _ = shell.save_profiles();
                    ok_json(&serde_json::json!({ "ok": true, "profile": prof }))
                }
                Err(e) => err_json("400 Bad Request", e.to_string()),
            }
        }
        "/api/containers/list" => {
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            ok_json(&shell.containers)
        }
        "/api/containers/upsert" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let Ok(container) = serde_json::from_value::<ContainerTabProfile>(body) else {
                return Some(err_json("400 Bad Request", "Invalid ContainerTabProfile"));
            };
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            match shell.containers.add_custom(container) {
                Ok(()) => {
                    let _ = shell.save_containers();
                    ok_json(&serde_json::json!({ "ok": true }))
                }
                Err(e) => err_json("400 Bad Request", e.to_string()),
            }
        }
        "/api/workspaces/list" => {
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            ok_json(&shell.workspaces)
        }
        "/api/workspaces/upsert" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let Ok(ws) = serde_json::from_value::<WorkspaceRecord>(body) else {
                return Some(err_json("400 Bad Request", "Invalid WorkspaceRecord"));
            };
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            match shell.workspaces.upsert_workspace(ws) {
                Ok(()) => {
                    let _ = shell.save_workspaces();
                    ok_json(&serde_json::json!({ "ok": true }))
                }
                Err(e) => err_json("400 Bad Request", e.to_string()),
            }
        }
        "/api/workspaces/closed_stack" => {
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            ok_json(&serde_json::json!({
                "entries": shell.workspaces.closed_stack.as_slice()
            }))
        }
        "/api/palette/query" => {
            let q = params.get("q").map(String::as_str).unwrap_or("");
            let limit = params.get("limit").and_then(|v| v.parse().ok()).unwrap_or(20);
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let cmds: Vec<_> = shell
                .commands
                .search_commands(q)
                .into_iter()
                .take(limit)
                .map(|hit| {
                    let c = &hit.command;
                    let shortcut = shell
                        .keybinds
                        .binding_for(&c.id)
                        .map(|s| s.to_canonical_string());
                    serde_json::json!({
                        "id": c.id,
                        "category": c.category,
                        "label_en": c.title_en,
                        "label_fr": c.title_fr,
                        "score": hit.score,
                        "shortcut": shortcut,
                    })
                })
                .collect();
            ok_json(&serde_json::json!({ "commands": cmds }))
        }
        "/api/keybinds/list" => {
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let bindings: HashMap<String, String> = shell
                .keybinds
                .effective_bindings()
                .into_iter()
                .map(|(k, v)| (k, v.to_canonical_string()))
                .collect();
            ok_json(&serde_json::json!({
                "preset": shell.keybinds.preset,
                "bindings": bindings,
                "conflicts": shell.keybinds.find_conflicts(),
            }))
        }
        "/api/keybinds/set" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let cmd_id = body.get("command_id").and_then(|v| v.as_str()).unwrap_or("");
            let seq = body.get("sequence").and_then(|v| v.as_str()).unwrap_or("");
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let res = if seq.is_empty() {
                shell.keybinds.unbind(cmd_id);
                Ok(())
            } else {
                shell.keybinds.bind_override_str(cmd_id, seq)
            };
            match res {
                Ok(()) => {
                    let _ = shell.save_keybinds();
                    ok_json(&serde_json::json!({
                        "ok": true,
                        "conflicts": shell.keybinds.find_conflicts(),
                    }))
                }
                Err(e) => err_json("400 Bad Request", e.to_string()),
            }
        }
        "/api/keybinds/preset" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let preset = match body
                .get("preset")
                .and_then(|v| v.as_str())
                .unwrap_or("chrome_edge")
            {
                "vivaldi" => KeymapPreset::Vivaldi,
                "arc" => KeymapPreset::Arc,
                "vim" => KeymapPreset::VimModal,
                _ => KeymapPreset::ChromeEdge,
            };
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            shell.keybinds = crate::keybinds::KeymapTable::from_preset(preset);
            let _ = shell.save_keybinds();
            ok_json(&serde_json::json!({ "ok": true, "preset": preset }))
        }
        "/api/command_chains/list" => {
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            ok_json(&serde_json::json!({ "chains": shell.command_chains.list() }))
        }
        "/api/command_chains/upsert" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let Ok(chain) = serde_json::from_value::<CommandChain>(body) else {
                return Some(err_json("400 Bad Request", "Invalid CommandChain"));
            };
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            match shell.command_chains.upsert(chain) {
                Ok(()) => {
                    let _ = shell.save_command_chains();
                    ok_json(&serde_json::json!({ "ok": true }))
                }
                Err(e) => err_json("400 Bad Request", e.to_string()),
            }
        }
        "/api/gestures/recognize" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let pts: Vec<(f64, f64)> = body
                .get("points")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|p| {
                            let x = p.get(0).and_then(|n| n.as_f64())?;
                            let y = p.get(1).and_then(|n| n.as_f64())?;
                            Some((x, y))
                        })
                        .collect()
                })
                .unwrap_or_default();
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let code = shell.gestures.gesture_code_from_points(&pts);
            let cmd = shell.gestures.recognize(&pts);
            ok_json(&serde_json::json!({ "code": code, "command_id": cmd }))
        }
        "/api/customization/state" => {
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            ok_json(&shell.customization)
        }
        "/api/customization/theme" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let Ok(theme) = serde_json::from_value::<CustomThemeManifest>(body) else {
                return Some(err_json("400 Bad Request", "Invalid CustomThemeManifest"));
            };
            let contrast = theme.primary_text_contrast();
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            shell.customization.saved_themes.retain(|t| t.id != theme.id);
            shell.customization.saved_themes.push(theme);
            let _ = shell.save_customization();
            ok_json(&serde_json::json!({ "ok": true, "primary_contrast_ratio": contrast }))
        }
        "/api/customization/boost" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let Ok(rule) = serde_json::from_value::<SiteBoostRule>(body) else {
                return Some(err_json("400 Bad Request", "Invalid SiteBoostRule"));
            };
            let compiled = rule.compile_css();
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            shell.customization.site_boosts.retain(|r| r.id != rule.id);
            shell.customization.site_boosts.push(rule);
            let _ = shell.save_customization();
            ok_json(&serde_json::json!({ "ok": true, "compiled_css": compiled }))
        }
        "/api/customization/web_panel" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let Ok(panel) = serde_json::from_value::<WebPanelConfig>(body) else {
                return Some(err_json("400 Bad Request", "Invalid WebPanelConfig"));
            };
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            shell.customization.web_panels.retain(|p| p.id != panel.id);
            shell.customization.web_panels.push(panel);
            let _ = shell.save_customization();
            ok_json(&serde_json::json!({ "ok": true }))
        }
        "/api/customization/zoom" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let origin = body.get("origin").and_then(|v| v.as_str()).unwrap_or("");
            let action = body.get("action").and_then(|v| v.as_str()).unwrap_or("get");
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let factor = match action {
                "in" => shell.customization.zoom.zoom_in(origin),
                "out" => shell.customization.zoom.zoom_out(origin),
                "reset" => shell.customization.zoom.reset(origin),
                "set" => {
                    let f = body.get("factor").and_then(|v| v.as_f64()).unwrap_or(1.0);
                    shell.customization.zoom.set(origin, f)
                }
                _ => shell.customization.zoom.get(origin),
            };
            let _ = shell.save_customization();
            ok_json(&serde_json::json!({ "ok": true, "origin": origin, "factor": factor }))
        }
        "/api/translate/detect" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let text = body.get("text").and_then(|v| v.as_str()).unwrap_or("");
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            ok_json(&shell.translate_engine.detect_language(text))
        }
        "/api/translate/batch" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let source = body
                .get("source_lang")
                .and_then(|v| v.as_str())
                .unwrap_or("en");
            let target = body
                .get("target_lang")
                .and_then(|v| v.as_str())
                .unwrap_or("fr");
            let segments: Vec<String> = body
                .get("segments")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            match shell
                .translate_engine
                .translate_batch(source, target, &segments)
            {
                Ok(translated) => {
                    ok_json(&serde_json::json!({ "ok": true, "segments": translated }))
                }
                Err(e) => err_json("400 Bad Request", e.to_string()),
            }
        }
        "/api/translate/prefs" => {
            if req.method == "POST" {
                let body = parse_body(req);
                let Ok(prefs) = serde_json::from_value::<TranslationPrefs>(body) else {
                    return Some(err_json("400 Bad Request", "Invalid TranslationPrefs"));
                };
                let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
                *shell.translate_engine.prefs_mut() = prefs;
                ok_json(&serde_json::json!({ "ok": true }))
            } else {
                let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
                ok_json(&serde_json::json!({
                    "prefs": shell.translate_engine.prefs(),
                    "available_pairs": shell.translate_engine.available_pairs(),
                    "installed_packs": shell.translate_engine.installed_packs(),
                }))
            }
        }
        "/api/sync/status" => {
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(ref sync) = shell.sync_engine {
                // Never expose the secret 25-word daily sync phrase on GET (use POST /api/sync/daily_phrase).
                ok_json(&serde_json::json!({
                    "linked": true,
                    "chain_id": sync.chain_id(),
                    "device_id": sync.local_device_id(),
                    "daily_25_word_phrase": serde_json::Value::Null,
                    "transport": sync.transport_config(),
                    "devices": sync.device_registry().all_devices(),
                }))
            } else {
                ok_json(&serde_json::json!({ "linked": false }))
            }
        }
        "/api/sync/daily_phrase" => {
            if let Err(r) = require_post(req) {
                return Some(r);
            }
            let shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let Some(ref sync) = shell.sync_engine else {
                return Some(err_json("400 Bad Request", "Sync chain not initialized"));
            };
            let phrase = Zeroizing::new(sync.current_25_word_phrase(unix_now()));
            #[derive(serde::Serialize)]
            struct DailySyncPhraseResp<'a> {
                ok: bool,
                daily_25_word_phrase: &'a str,
            }
            match serde_json::to_vec(&DailySyncPhraseResp {
                ok: true,
                daily_25_word_phrase: phrase.as_str(),
            }) {
                Ok(bytes) => {
                    HttpResponse::new("200 OK", "application/json; charset=utf-8", bytes)
                }
                Err(e) => err_json("500 Internal Server Error", e.to_string()),
            }
        }
        "/api/sync/create_chain" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let device_name = body
                .get("device_name")
                .and_then(|v| v.as_str())
                .unwrap_or("Singularity Desktop");
            let now = unix_now();
            let (engine, permanent_24, daily_25) =
                SingularitySyncEngine::create_new_chain(device_name, std::env::consts::OS, now);
            let chain_id = engine.chain_id().to_string();
            let device_id = engine.local_device_id().to_string();
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            shell.sync_engine = Some(engine);
            ok_json(&serde_json::json!({
                "ok": true,
                "chain_id": chain_id,
                "device_id": device_id,
                "permanent_24_words": permanent_24,
                "daily_25_words": daily_25,
            }))
        }
        "/api/sync/join_chain" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let phrase = body.get("phrase").and_then(|v| v.as_str()).unwrap_or("");
            let device_name = body
                .get("device_name")
                .and_then(|v| v.as_str())
                .unwrap_or("Singularity Desktop");
            let now = unix_now();
            let word_count = phrase.split_whitespace().count();
            let res = if word_count == 25 {
                SingularitySyncEngine::join_from_25_words(
                    phrase,
                    now,
                    device_name,
                    std::env::consts::OS,
                )
            } else {
                SingularitySyncEngine::join_from_24_words(
                    phrase,
                    now,
                    device_name,
                    std::env::consts::OS,
                )
            };
            match res {
                Ok(engine) => {
                    let chain_id = engine.chain_id().to_string();
                    let device_id = engine.local_device_id().to_string();
                    let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
                    shell.sync_engine = Some(engine);
                    ok_json(&serde_json::json!({
                        "ok": true,
                        "chain_id": chain_id,
                        "device_id": device_id,
                    }))
                }
                Err(e) => err_json("400 Bad Request", e.to_string()),
            }
        }
        "/api/sync/leave_chain" => {
            if let Err(r) = require_post(req) {
                return Some(r);
            }
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            shell.sync_engine = None;
            ok_json(&serde_json::json!({ "ok": true, "linked": false }))
        }
        "/api/sync/types" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let Ok(kind) = serde_json::from_value::<SyncCollectionKind>(
                body.get("collection")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null),
            ) else {
                return Some(err_json("400 Bad Request", "Invalid SyncCollectionKind"));
            };
            let enabled = body
                .get("enabled")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let Some(ref mut sync) = shell.sync_engine else {
                return Some(err_json("400 Bad Request", "Sync chain not initialized"));
            };
            sync.set_collection_enabled(kind, enabled);
            ok_json(&serde_json::json!({
                "ok": true,
                "enabled": sync.is_collection_enabled(kind)
            }))
        }
        "/api/sync/send_tab" => {
            let body = match require_post(req) {
                Ok(v) => v,
                Err(r) => return Some(r),
            };
            let url = body.get("url").and_then(|v| v.as_str()).unwrap_or("");
            let title = body.get("title").and_then(|v| v.as_str()).unwrap_or(url);
            let target_device_id = body
                .get("target_device_id")
                .and_then(|v| v.as_str())
                .unwrap_or("*");
            let media_time_sec = body.get("media_time_sec").and_then(|v| v.as_f64());
            let mut shell = shell_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let Some(ref mut sync) = shell.sync_engine else {
                return Some(err_json("400 Bad Request", "Sync chain not initialized"));
            };
            match sync.create_send_tab_envelope(
                url,
                title,
                media_time_sec,
                target_device_id,
                unix_now().saturating_mul(1000),
            ) {
                Ok(env) => ok_json(&serde_json::json!({ "ok": true, "envelope": env })),
                Err(e) => err_json("400 Bad Request", e.to_string()),
            }
        }
        _ => return None,
    };
    Some(resp)
}
