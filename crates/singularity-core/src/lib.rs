//! `singularity-core` — Instant Page Load Pipeline, Speculative 0-RTT Hover Pre-Connect,
//! B-Tree RAM Asset Cache, uBlock Network/Cosmetic/Dynamic Ad & Tracker Blocker,
//! Local Zero-Telemetry Threat Guard, Encrypted DoH/DoT/DoQ/ODoH DNS + Partitioned HSTS,
//! Tab Suspension & Split-View Engine, Tab Organizer, Memory Pressure Monitor,
//! Resource Limiter, Power Policy Orchestrator, Local Telemetry & Histograms, and Download Manager.

pub mod blocker;
pub mod cache;
pub mod dns;
pub mod downloader;
pub mod limiter;
pub mod memory_pressure;
pub mod power;
pub mod preconnect;
pub mod tab_organizer;
pub mod tabs;
pub mod telemetry;
pub mod threat_guard;

pub use blocker::{
    debounce_tracking_redirect, extract_etld_plus_one, lookup_surrogate_resource,
    render_scriptlet, same_site_hosts, AdblockLevel, CookieBlockingLevel, CosmeticResources,
    DynamicResourceKind, DynamicRuleAction, DynamicRuleMatrix, FilterDecision,
    FilterEvaluationResult, FilterListKind, FilterListLoadStats, FilterListSubscription,
    FingerprintProtectionLevel, NetworkResourceType, ProceduralCosmeticRule, ProceduralOperator,
    ScriptletInjection, ShieldLogEvent, SiteShieldsPolicy, SurrogateResource, UBlockNetworkEngine,
    DEFAULT_UBLOCK_FILTER_RULES, DOMAIN_SCOPED_TRACKING_PARAMS, GLOBAL_TRACKING_QUERY_PARAMS,
    MAX_SHIELD_LOG_EVENTS,
};
pub use cache::{
    compress_lossless, decompress_lossless, is_compressible_mime, BTreeRamAssetCache,
    CacheQuotaConfig, CachedAsset, ENTRY_METADATA_OVERHEAD_BYTES,
};
pub use dns::{
    build_dns_wire_query, parse_dns_wire_response, parse_dns_wire_svcb_https_records,
    parse_doh_json_response, parse_doh_response_auto, parse_svcb_https_rdata, CaptivePortalState,
    DnsCacheEntrySnapshot, DnsFallbackPolicy, DnsProviderPreset, DnsProviderSpec,
    DnsResolutionOutcome, EncryptedDnsProtocol, EncryptedDnsRecord, EncryptedDnsResolver,
    HstsEntry, PartitionedHstsStore, SvcbHttpsRecord, DNS_TYPE_A, DNS_TYPE_AAAA, DNS_TYPE_CNAME,
    DNS_TYPE_HTTPS, DNS_TYPE_SVCB,
};
pub use downloader::{
    classify_category, classify_download_danger, constant_time_eq, format_zone_identifier,
    plan_parallel_segments, render_filename_template, resolve_collision_filename,
    sanitize_filename_component, sha256_file_hex, split_compound_filename, verify_file_sha256,
    write_mark_of_the_web, CollisionPolicy, DownloadCategory, DownloadDangerLevel, DownloadManager,
    DownloadRecord, DownloadRoutingRule, DownloadSegmentPlan, DownloadState, MotwWriteOutcome,
};
pub use limiter::{
    BandwidthTokenBucket, OriginPerformancePolicy, PerformanceProfilePreset, ResourceLimiterConfig,
    ResourceLimiterManager,
};
pub use memory_pressure::{
    AdaptiveMemoryMode, MemoryPressureLevel, SystemMemorySnapshot, TabEvictionCandidate,
    TabEvictionScorer,
};
pub use power::{
    EnergySaverActivationPolicy, PowerAdaptationDecision, PowerPolicyOrchestrator, PowerTelemetry,
    ShaderBatteryMode,
};
pub use preconnect::{
    HoverIntentSignal, PreConnectedSession, PreloadLevel, SpeculationDecision,
    SpeculationPolicyGate, SpeculationPurpose, SpeculativePreConnectPool, MAX_WARM_SESSIONS,
};
pub use tab_organizer::{
    find_duplicate_tabs, glob_matches, group_tabs_by_domain, normalize_url_for_dedup,
    suggest_domain_groups, AutoGroupRule, DuplicateTabCluster, SuggestedTabGroup, TabGroupColor,
    TabOrganizer,
};
pub use tabs::{
    snap_split_ratio, snap_split_ratio_with_tolerance, BrowserTab, SplitLayoutTree,
    SplitOrientation, TabLifecycleState, TabProtectionFlags, TabSleepDomainPolicy,
    TabSuspensionManager, SPLIT_MAGNETIC_DETENTS, SPLIT_MAGNETIC_SNAP_TOLERANCE,
};
pub use telemetry::{
    HealthReport, HealthStatus, HistogramSummary, LocalHistogramRegistry, LogHistogram,
    OptimizationAction, PerformanceHealthDetector, TabEmaMetrics, TabTelemetrySample,
};
pub use threat_guard::{
    confusable_ascii_skeleton, decode_idn_hostname, decode_punycode_label, levenshtein_distance,
    LocalBloomFilter, ThreatFeedKind, ThreatGuard, ThreatVerdict,
};

use singularity_chromium_ffi::{init_chromium_from_registry, ChromiumEngineBridge};
use singularity_net_mullvad::MullvadVpnController;
use singularity_settings_registry::SettingsRegistry;

/// Top-level Singularity Core Orchestrator connecting the Settings Registry,
/// Zero-Telemetry Chromium FFI, Mullvad WireGuard Tunnel, Instant Load Pipeline,
/// Privacy Shields, Local Threat Guard, Performance/Power Governors, and Download Manager.
pub struct SingularityCoreOrchestrator {
    pub settings: SettingsRegistry,
    pub chromium_bridge: ChromiumEngineBridge,
    pub mullvad_vpn: MullvadVpnController,
    pub preconnect_pool: SpeculativePreConnectPool,
    pub speculation_gate: SpeculationPolicyGate,
    pub asset_cache: BTreeRamAssetCache,
    pub adblocker: UBlockNetworkEngine,
    pub threat_guard: ThreatGuard,
    pub dns_resolver: EncryptedDnsResolver,
    pub hsts_store: PartitionedHstsStore,
    pub tab_manager: TabSuspensionManager,
    pub tab_organizer: TabOrganizer,
    pub memory_scorer: TabEvictionScorer,
    pub resource_limiter: ResourceLimiterManager,
    pub power_orchestrator: PowerPolicyOrchestrator,
    pub health_detector: PerformanceHealthDetector,
    pub histograms: LocalHistogramRegistry,
    pub download_manager: DownloadManager,
}

impl SingularityCoreOrchestrator {
    pub fn boot() -> Result<Self, String> {
        let settings = SettingsRegistry::new();
        let chromium_bridge = init_chromium_from_registry(&settings)?;
        let mullvad_vpn = MullvadVpnController::new();
        let preconnect_pool = SpeculativePreConnectPool::default();
        let speculation_gate = SpeculationPolicyGate::default();
        let asset_cache = BTreeRamAssetCache::default();
        let adblocker = UBlockNetworkEngine::default();
        let threat_guard = ThreatGuard::default();
        let dns_resolver = EncryptedDnsResolver::default();
        let hsts_store = PartitionedHstsStore::default();
        let tab_manager = TabSuspensionManager::default();
        let tab_organizer = TabOrganizer::default();
        let memory_scorer = TabEvictionScorer::default();
        let resource_limiter = ResourceLimiterManager::default();
        let power_orchestrator = PowerPolicyOrchestrator::default();
        let health_detector = PerformanceHealthDetector::default();
        let histograms = LocalHistogramRegistry::default();
        let download_manager = DownloadManager::default();

        Ok(Self {
            settings,
            chromium_bridge,
            mullvad_vpn,
            preconnect_pool,
            speculation_gate,
            asset_cache,
            adblocker,
            threat_guard,
            dns_resolver,
            hsts_store,
            tab_manager,
            tab_organizer,
            memory_scorer,
            resource_limiter,
            power_orchestrator,
            health_detector,
            histograms,
            download_manager,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_instant_load_pipeline_and_ublock_cname_unmasking() {
        let mut core = SingularityCoreOrchestrator::boot().expect("Boot Singularity Core");

        // 1. Test tracking query parameter scrubbing
        let dirty_url = "https://example.com/article?id=42&utm_source=twitter&fbclid=IwAR12345&gclid=999#section1";
        let clean_url = UBlockNetworkEngine::scrub_tracking_query_params(dirty_url);
        assert_eq!(clean_url, "https://example.com/article?id=42#section1");

        // 2. Test uBlock Origin network-layer ad/tracker blocking
        let decision = core.adblocker.evaluate_request(
            "https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js",
            "pagead2.googlesyndication.com",
            "example.com",
            NetworkResourceType::Script,
        );
        assert!(matches!(decision, FilterDecision::BlockedByDomainRule(_)));

        // 3. Test DNS CNAME-cloaking unmasking
        core.dns_resolver.insert_cached_record(EncryptedDnsRecord {
            query_hostname: "metrics.news-site.org".into(),
            canonical_cname_chain: vec!["tracker.criteo.com".into()],
            ipv4_addresses: vec!["1.2.3.4".into()],
            ipv6_addresses: vec![],
            ech_config_base64: None,
            ttl_seconds: 120,
        });
        let dns_outcome = core
            .dns_resolver
            .resolve_with_cname_unmasking("metrics.news-site.org", &core.adblocker);
        assert!(matches!(
            dns_outcome,
            DnsResolutionOutcome::BlockedCnameCloakedTracker { .. }
        ));

        // 4. Test speculative 0-RTT pre-connect on link hover
        let session = core.preconnect_pool.evaluate_link_intent(
            "mullvad.net",
            HoverIntentSignal::MouseOver {
                dwell_ms: 65,
                velocity_px_per_sec: 120.0,
            },
        );
        assert!(session.is_some());
        assert!(session.unwrap().tls13_zero_rtt_ticket_ready);

        // 5. Test zero-copy B-Tree RAM cache partitioned by first-party eTLD+1
        core.asset_cache.put(
            "mullvad.net",
            "https://mullvad.net/app.wasm",
            "application/wasm",
            vec![0x00, 0x61, 0x73, 0x6d],
            2000000000,
        );
        let hit = core
            .asset_cache
            .get("mullvad.net", "https://mullvad.net/app.wasm", 1700000000);
        assert!(hit.is_some());
        let cross_partition =
            core.asset_cache
                .get("evil-tracker.com", "https://mullvad.net/app.wasm", 1700000000);
        assert!(cross_partition.is_none());

        // 6. Test aggressive tab freezing & instant state restoration
        let t1 = core.tab_manager.open_tab(
            "Singularity Docs",
            "https://singularity.browser/docs",
            "singularity.browser",
            &core.chromium_bridge,
        );
        let _t2 = core.tab_manager.open_tab(
            "Mullvad Status",
            "https://am.i.mullvad.net",
            "mullvad.net",
            &core.chromium_bridge,
        );
        let frozen_count = core
            .tab_manager
            .tick_idle_and_freeze(120, &core.chromium_bridge);
        assert_eq!(frozen_count, 1);

        let restored = core
            .tab_manager
            .activate_tab(t1, &core.chromium_bridge)
            .unwrap();
        assert_eq!(restored.lifecycle, TabLifecycleState::ActiveForeground);
    }

    #[test]
    fn test_orchestrator_master_roadmap_integration_all_engines() {
        let mut core = SingularityCoreOrchestrator::boot().expect("Boot Singularity Core");

        // 1. Tab organizer + duplicate detection + two-stage suspension + split tree
        let t1 = core.tab_manager.open_tab(
            "Repo",
            "https://github.com/MyMasha/Singularity?utm_source=share",
            "github.com",
            &core.chromium_bridge,
        );
        let t2 = core.tab_manager.open_tab(
            "Repo Duplicate",
            "https://github.com/MyMasha/Singularity#readme",
            "github.com",
            &core.chromium_bridge,
        );
        let t3 = core.tab_manager.open_tab(
            "Docs",
            "https://docs.github.com/en/get-started",
            "github.com",
            &core.chromium_bridge,
        );

        let dups = core.tab_organizer.find_duplicates(core.tab_manager.tabs());
        assert_eq!(dups.len(), 1);
        assert_eq!(dups[0].canonical_tab_id, t1);
        assert_eq!(dups[0].duplicate_tab_ids, vec![t2]);

        let groups = core
            .tab_organizer
            .suggest_groups(core.tab_manager.tabs(), 2);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].group_key, "github.com");
        assert_eq!(groups[0].tab_ids.len(), 3);

        core.tab_manager
            .add_tab_protection_flag(t1, TabProtectionFlags::DIRTY_FORM);
        assert!(!core.tab_manager.freeze_tab_soft(
            t1,
            1000,
            150 * 1024 * 1024,
            &core.chromium_bridge
        ));
        assert!(core.tab_manager.freeze_tab_soft(
            t2,
            1000,
            150 * 1024 * 1024,
            &core.chromium_bridge
        ));
        assert!(core.tab_manager.discard_tab_with_reclaimed_ram(
            t2,
            150 * 1024 * 1024,
            &core.chromium_bridge
        ));
        assert!(core.tab_manager.total_reclaimed_ram_bytes() >= 150 * 1024 * 1024);

        let split = SplitLayoutTree::split(
            SplitOrientation::Horizontal,
            0.51,
            SplitLayoutTree::leaf(t1),
            SplitLayoutTree::leaf(t3),
        );
        let rects = split.compute_pane_rects(0.0, 0.0, 1208.0, 800.0, 8.0);
        assert_eq!(rects.len(), 2);
        assert!((rects[0].3 - 600.0).abs() < 0.01);

        // 2. Threat guard + Partitioned HSTS + Speculation Gate
        assert!(core
            .threat_guard
            .evaluate_url("https://xn--80ak6aa92e.com/")
            .is_threat());
        assert!(core
            .hsts_store
            .should_upgrade_to_https("github.com", "api.github.com", 1000));
        assert!(core
            .speculation_gate
            .evaluate_speculation(
                SpeculationPurpose::Prefetch,
                "https://docs.github.com/",
                "docs.github.com",
                "github.com",
                &core.adblocker,
            )
            .is_allowed());

        // 3. Memory pressure + Power orchestrator + Resource limiter + Health telemetry + Histograms
        let mem_snap = SystemMemorySnapshot::capture();
        assert!(mem_snap.total_bytes > 0);

        let pwr = core.power_orchestrator.evaluate(PowerTelemetry {
            on_ac_power: false,
            battery_percent: Some(15),
            is_charging: false,
            os_battery_saver: true,
        });
        assert!(pwr.energy_saver_engaged);
        assert!(pwr.disable_speculative_preload);

        core.resource_limiter
            .apply_preset(PerformanceProfilePreset::GamingMode);
        assert!(core
            .resource_limiter
            .download_bucket()
            .try_consume(1024, 1000));

        core.health_detector.record_tab_sample(TabTelemetrySample {
            tab_id: t3,
            cpu_percent: 12.0,
            ram_mb: 200.0,
            is_active: true,
            timestamp_unix: 1000,
        });
        assert_eq!(
            core.health_detector.evaluate_health().status,
            HealthStatus::Healthy
        );

        core.histograms.record("frame_time_us", 4_900);
        core.histograms.record("frame_time_us", 5_100);
        assert!(core.histograms.percentiles("frame_time_us").is_some());

        // 4. Download manager with ThreatGuard integration
        let blocked_dl = core.download_manager.enqueue_download(
            "https://malware.testing.google.test/payload.exe",
            "payload.exe",
            Some("https://example.org"),
            None,
            Some(4096),
            true,
            Some(&core.threat_guard),
            1_700_000_000,
        );
        assert!(matches!(
            core.download_manager.get(blocked_dl).unwrap().state,
            DownloadState::BlockedDanger { .. }
        ));
    }

    #[test]
    fn test_all_surrogates_subscriptions_site_script_policy_and_tco_debounce() {
        // Verify all 10 required surrogate resources & scriptlets resolve cleanly
        for name in [
            "noopjs",
            "noopcss",
            "1x1.gif",
            "noopmp4-1s",
            "googlesyndication_adsbygoogle.js",
            "google-analytics_analytics.js",
            "abort-on-property-read",
            "set-constant",
            "json-prune",
            "no-fetch-if",
        ] {
            let res = lookup_surrogate_resource(name)
                .unwrap_or_else(|| panic!("Missing surrogate resource '{}'", name));
            assert_eq!(res.name, name);
        }

        // Verify parameterized scriptlet rendering for json-prune & no-fetch-if
        let jp = render_scriptlet("json-prune", &["adPlacements playerAds".into()]).unwrap();
        assert!(jp.contains("adPlacements playerAds"));
        let nfi = render_scriptlet("no-fetch-if", &["/telemetry/".into()]).unwrap();
        assert!(nfi.contains("/telemetry/"));

        // Verify filter list subscriptions catalogue (all 10 standard lists + custom CRUD + ETag)
        let mut engine = UBlockNetworkEngine::default();
        assert_eq!(engine.subscriptions().len(), 10);
        engine.add_custom_subscription(
            "custom-corp",
            "Corporate Ad Filter",
            "https://filters.internal.test/list.txt",
        );
        assert_eq!(engine.subscriptions().len(), 11);
        let load_stats = engine
            .update_subscription_content(
                "custom-corp",
                "||internal-tracker.test^\n",
                Some("\"etag-v1\"".into()),
                Some("Wed, 26 Nov 2026 12:00:00 GMT".into()),
                1_700_000_123,
            )
            .expect("updated subscription");
        assert_eq!(load_stats.total_added, 1);
        let sub = engine
            .subscriptions()
            .iter()
            .find(|s| s.id == "custom-corp")
            .unwrap();
        assert_eq!(sub.etag.as_deref(), Some("\"etag-v1\""));
        assert_eq!(sub.rule_count, 1);
        assert!(engine.set_subscription_enabled("custom-corp", false));
        assert!(engine.remove_subscription("custom-corp"));

        // Verify SiteShieldsPolicy block_all_scripts + allowed_script_domains
        engine.set_site_policy(
            "strict-app.test",
            SiteShieldsPolicy {
                enabled: true,
                adblock_level: AdblockLevel::Aggressive,
                fingerprint_level: FingerprintProtectionLevel::Strict,
                cookie_level: CookieBlockingLevel::BlockAll,
                block_all_scripts: true,
                allowed_script_domains: vec!["trusted-cdn.test".into()],
                forgetful_browsing: true,
                block_cookie_notices: true,
            },
        );
        assert!(matches!(
            engine.evaluate_request(
                "https://random-cdn.test/app.js",
                "random-cdn.test",
                "strict-app.test",
                NetworkResourceType::Script
            ),
            FilterDecision::BlockedByPatternRule(_)
        ));
        assert_eq!(
            engine.evaluate_request(
                "https://js.trusted-cdn.test/app.js",
                "js.trusted-cdn.test",
                "strict-app.test",
                NetworkResourceType::Script
            ),
            FilterDecision::Allow
        );

        // Verify t.co debouncing
        assert_eq!(
            debounce_tracking_redirect(
                "https://t.co/xyz?url=https%3A%2F%2Frust-lang.org%2Flearn%3Futm_medium%3Dsocial"
            )
            .as_deref(),
            Some("https://rust-lang.org/learn")
        );
    }

    #[test]
    fn test_all_protection_flags_two_stage_tick_svcb64_binary_lz_and_concurrent_bucket() {
        // 1. All 9 TabProtectionFlags are distinct non-zero bits
        let all_flags = [
            TabProtectionFlags::AUDIO_ACTIVE,
            TabProtectionFlags::WEBRTC_MEDIA,
            TabProtectionFlags::DIRTY_FORM,
            TabProtectionFlags::ACTIVE_DOWNLOAD,
            TabProtectionFlags::REALTIME_SOCKET,
            TabProtectionFlags::PINNED,
            TabProtectionFlags::PIP_VIDEO,
            TabProtectionFlags::USER_WHITELIST,
            TabProtectionFlags::DRM_ACTIVE,
        ];
        let mut combined = TabProtectionFlags::NONE;
        for f in all_flags {
            assert_ne!(f.bits(), 0);
            assert!(!combined.intersects(f));
            combined |= f;
        }
        assert_eq!(combined.bits().count_ones(), 9);

        // 2. Two-stage lifecycle tick: BackgroundWarm -> FrozenZeroCpu -> SuspendedFrozen
        let reg = SettingsRegistry::new();
        let bridge = init_chromium_from_registry(&reg).expect("bridge");
        let mut tm = TabSuspensionManager::new(30);
        tm.set_discard_timeout_seconds(60);
        let bg = tm.open_tab("Bg", "https://example.org/a", "example.org", &bridge);
        let _fg = tm.open_tab("Fg", "https://example.org/b", "example.org", &bridge);

        let (frozen1, disc1) = tm.tick_two_stage_lifecycle(35, 1000, 64 * 1024 * 1024, &bridge);
        assert_eq!((frozen1, disc1), (1, 0));
        assert!(matches!(
            tm.tabs().iter().find(|t| t.tab_id == bg).unwrap().lifecycle,
            TabLifecycleState::FrozenZeroCpu {
                frozen_since_unix: 1000,
                ..
            }
        ));

        let (frozen2, disc2) = tm.tick_two_stage_lifecycle(10, 1070, 64 * 1024 * 1024, &bridge);
        assert_eq!((frozen2, disc2), (0, 1));
        assert!(matches!(
            tm.tabs().iter().find(|t| t.tab_id == bg).unwrap().lifecycle,
            TabLifecycleState::SuspendedFrozen { .. }
        ));
        assert_eq!(tm.total_reclaimed_ram_bytes(), 64 * 1024 * 1024);

        // 3. DNS TYPE 64 (SVCB) RDATA + Captive portal temporary bypass
        let mut svcb_rdata = Vec::new();
        svcb_rdata.extend_from_slice(&1u16.to_be_bytes());
        svcb_rdata.push(4);
        svcb_rdata.extend_from_slice(b"svc1");
        svcb_rdata.push(4);
        svcb_rdata.extend_from_slice(b"test");
        svcb_rdata.push(0);
        // port = 8443 (key 3)
        svcb_rdata.extend_from_slice(&3u16.to_be_bytes());
        svcb_rdata.extend_from_slice(&2u16.to_be_bytes());
        svcb_rdata.extend_from_slice(&8443u16.to_be_bytes());
        let svcb = parse_svcb_https_rdata(&svcb_rdata, DNS_TYPE_SVCB, 120).expect("SVCB 64");
        assert_eq!(svcb.rr_type, DNS_TYPE_SVCB);
        assert_eq!(svcb.target_name, "svc1.test");
        assert_eq!(svcb.port, Some(8443));

        let mut resolver = EncryptedDnsResolver::default();
        resolver.set_protocol(EncryptedDnsProtocol::ODoH);
        resolver.set_fallback_policy(DnsFallbackPolicy::TemporaryCaptivePortalBypass {
            expires_unix: 2000,
        });
        resolver.set_captive_portal_state(CaptivePortalState::Confirmed {
            portal_url: "http://wifi.airport.local/login".into(),
            bypass_expires_unix: Some(2000),
        });
        assert!(resolver.is_captive_portal_bypass_active(1500));
        assert!(!resolver.is_captive_portal_bypass_active(2500));

        // 4. Greek mixed-script IDN homograph check (`gοοgle.com` with Greek omicron U+03BF)
        let guard = ThreatGuard::default();
        assert!(matches!(
            guard.evaluate_url("https://g\u{03BF}\u{03BF}gle.com/"),
            ThreatVerdict::IdnHomograph { .. }
        ));

        // 5. Lossless codec edge cases: empty + all 256 byte values + overlapping repeating pattern
        assert_eq!(
            decompress_lossless(&compress_lossless(&[])).unwrap(),
            Vec::<u8>::new()
        );
        let all_bytes: Vec<u8> = (0u8..=255).collect();
        assert_eq!(
            decompress_lossless(&compress_lossless(&all_bytes)).unwrap(),
            all_bytes
        );
        let pattern = b"ab".repeat(500);
        let comp = compress_lossless(&pattern);
        assert!(comp.len() < pattern.len() / 5);
        assert_eq!(decompress_lossless(&comp).unwrap(), pattern);

        // 6. Multi-threaded lock-free BandwidthTokenBucket never over-allocates burst tokens
        use std::sync::Arc;
        let bucket = Arc::new(BandwidthTokenBucket::from_bytes_per_sec(1_000, 10_000, 100));
        let mut handles = Vec::new();
        for _ in 0..4 {
            let b = Arc::clone(&bucket);
            handles.push(std::thread::spawn(move || {
                let mut granted = 0u64;
                for _ in 0..50 {
                    if b.try_consume(100, 100) {
                        granted += 100;
                    }
                }
                granted
            }));
        }
        let total_granted: u64 = handles.into_iter().map(|h| h.join().unwrap()).sum();
        assert_eq!(total_granted, 10_000);
    }
}
