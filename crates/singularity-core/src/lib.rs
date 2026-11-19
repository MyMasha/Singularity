//! `singularity-core` — Instant Page Load Pipeline, Speculative 0-RTT Hover Pre-Connect,
//! B-Tree RAM Asset Cache, uBlock Network Ad/Tracker Blocker, Encrypted DoQ/DoH DNS, and Tab Freezer.

pub mod blocker;
pub mod cache;
pub mod dns;
pub mod preconnect;
pub mod tabs;

pub use blocker::{
    FilterDecision, NetworkResourceType, UBlockNetworkEngine, DEFAULT_UBLOCK_FILTER_RULES,
};
pub use cache::{BTreeRamAssetCache, CachedAsset};
pub use dns::{DnsResolutionOutcome, EncryptedDnsRecord, EncryptedDnsResolver};
pub use preconnect::{HoverIntentSignal, PreConnectedSession, SpeculativePreConnectPool};
pub use tabs::{BrowserTab, TabLifecycleState, TabSuspensionManager};

use singularity_chromium_ffi::{init_chromium_from_registry, ChromiumEngineBridge};
use singularity_net_mullvad::MullvadVpnController;
use singularity_settings_registry::SettingsRegistry;

/// Top-level Singularity Core Orchestrator connecting the 2,165+ Settings Registry,
/// Zero-Telemetry Chromium FFI, Mullvad WireGuard Tunnel, and Instant Load Pipeline.
pub struct SingularityCoreOrchestrator {
    pub settings: SettingsRegistry,
    pub chromium_bridge: ChromiumEngineBridge,
    pub mullvad_vpn: MullvadVpnController,
    pub preconnect_pool: SpeculativePreConnectPool,
    pub asset_cache: BTreeRamAssetCache,
    pub adblocker: UBlockNetworkEngine,
    pub dns_resolver: EncryptedDnsResolver,
    pub tab_manager: TabSuspensionManager,
}

impl SingularityCoreOrchestrator {
    pub fn boot() -> Result<Self, String> {
        let settings = SettingsRegistry::new();
        let chromium_bridge = init_chromium_from_registry(&settings)?;
        let mullvad_vpn = MullvadVpnController::new();
        let preconnect_pool = SpeculativePreConnectPool::default();
        let asset_cache = BTreeRamAssetCache::default();
        let adblocker = UBlockNetworkEngine::default();
        let dns_resolver = EncryptedDnsResolver::default();
        let tab_manager = TabSuspensionManager::default();

        Ok(Self {
            settings,
            chromium_bridge,
            mullvad_vpn,
            preconnect_pool,
            asset_cache,
            adblocker,
            dns_resolver,
            tab_manager,
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
        // Cross-origin partition cannot read mullvad.net's cached entry
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
}
