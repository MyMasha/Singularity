//! `singularity-ui` — OLED Pure Black (`#000000`) 200Hz+ Native UI Shell,
//! Custom Cursor Engine, Black Hole WGSL Shader, Vim Modal Navigation, and 2,165+ Virtualized Settings UI.

pub mod api_v3;
pub mod bookmarks_store;
pub mod browser_import;
pub mod crash_guard;
pub mod cursor;
pub mod drm_webview;
pub mod extensions;
pub mod history_store;
pub mod internal_pages;
pub mod keybinds;
pub mod omnibox;
pub mod page_tools;
pub mod profiles;
pub mod pwa;
pub mod roaming_store;
pub mod server;
pub mod shaders;
pub mod shell;
pub mod theme;
pub mod ui_app;
pub mod updater;
pub mod userscripts;
pub mod vim;
#[cfg(target_os = "windows")]
pub mod cef_runtime;
pub mod winhttp_client;

pub use bookmarks_store::{BookmarkNode, BookmarkNodeKind, BookmarksStore, SmartFolderRule};
pub use browser_import::{
    parse_chromium_bookmarks, parse_chromium_snss_session, parse_firefox_bookmarks_lz4,
    parse_firefox_session, scan_installed_browsers, DetectedBrowserInfo, ImportedBookmark,
    ImportedTab,
};
pub use cursor::{CursorAssetFormat, CursorFormatError, CursorTrailSample, CustomCursorEngine};
pub use history_store::{HistoryJourney, HistoryRetentionPolicy, HistoryStore, VisitTransitionType};
pub use internal_pages::{
    normalize_internal_url, render_internal_page_html, InternalPageContext, InternalPageSpec,
    INTERNAL_PAGE_REGISTRY,
};
pub use keybinds::{
    CommandChainStore, CommandRegistry, KeymapPreset, KeymapTable, MouseGestureRecognizer,
    MruTabCycler,
};
pub use omnibox::{
    evaluate_instant_answer, generate_qr_svg, FxRatesCache, OmniboxEngine, OmniboxScope,
    SearchEngineEntry, SearchEngineRegistry,
};
pub use page_tools::{
    build_text_fragment_url, compute_line_diff, format_smart_copy, render_safe_markdown_html,
    CollectionsStore, NotesStore, PdfAnnotationStore, ReaderModeExtractor, ReadingListStore,
};
pub use profiles::{
    ContainerRegistry, ContainerTabProfile, CustomizationStore, PermissionDecision, PermissionKind,
    ProfileRegistry, SitePermissionsStore, WorkspaceSessionStore,
};
pub use pwa::{InstalledPwa, PwaRegistry, WebAppManifest};
pub use roaming_store::{
    apply_media_timestamp_to_url, classify_auth_cookie, classify_tracker_or_malicious_cookie,
    ensure_roaming_dir_initialized, is_protected_session_or_functional_cookie, is_valid_theme_id,
    normalize_url_without_media_time, resolve_roaming_singularity_dir, CookieThreatKind,
    EncryptedAuthTokenRecord, RoamingSingularityStore, SavedTabEntry, SavedTabGroup,
    WindowGeometry, WindowRestorePayload, WindowSessionFile,
};
pub use server::{
    run_interactive_browser_app, run_interactive_browser_app_with_smoke, CefSmokeTestOptions,
};
pub use shaders::{BLACK_HOLE_LENSING_WGSL_SHADER, CURSOR_ACCRETION_TRAIL_WGSL_SHADER};
pub use shell::SingularityBrowserShell;
pub use theme::{
    ReaderThemePreset, SingularityThemeManifest, TabBarPlacement, ThemeColorScheme, UiDensity,
    WindowBackdropMaterial, ACCRETION_CYAN, ACCRETION_VIOLET, OBSIDIAN_BORDER, OLED_PURE_BLACK,
};
pub use ui_app::SINGULARITY_UI_HTML;
pub use updater::{check_for_updates, execute_self_update, execute_uninstall, perform_startup_maintenance};
pub use userscripts::{UserScriptMeta, UserScriptRecord, UserscriptManager};
pub use vim::{LinkHintBadge, VimAction, VimModalEngine, VimMode};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cur_and_ani_binary_cursor_parsing() {
        // Construct a valid 22-byte Windows .cur header (32x32, hotspot at (8, 12))
        let cur_bytes: [u8; 22] = [
            0, 0, // reserved = 0
            2, 0, // type = 2 (.cur)
            1, 0, // count = 1
            32, 32, 0, 0, // 32x32
            8, 0, // hotspot_x = 8
            12, 0, // hotspot_y = 12
            0, 0, 0, 0, 22, 0, 0, 0,
        ];
        let parsed = CustomCursorEngine::parse_cur_header(&cur_bytes).expect("Parse .cur");
        assert_eq!(
            parsed,
            CursorAssetFormat::WindowsCur {
                width: 32,
                height: 32,
                hotspot_x: 8,
                hotspot_y: 12
            }
        );

        let ani_bytes = b"RIFF\x24\x00\x00\x00ACONanih";
        assert!(CustomCursorEngine::parse_ani_header(ani_bytes).is_ok());
    }

    #[test]
    fn test_vim_modal_navigation_and_home_row_link_hints() {
        let mut vim = VimModalEngine::default();
        vim.generate_home_row_hints(&[
            ("https://mullvad.net".into(), 100, 200),
            ("https://rust-lang.org".into(), 300, 400),
        ]);

        assert_eq!(
            vim.handle_key_press("f"),
            VimAction::EnterLinkHintMode { new_tab: false }
        );
        assert_eq!(
            vim.handle_key_press("s"),
            VimAction::ActivateLinkUrl {
                url: "https://mullvad.net".into(),
                new_tab: false
            }
        );
    }

    #[test]
    fn test_full_singularity_browser_shell_launch() {
        let mut shell = SingularityBrowserShell::launch().expect("Launch shell");
        assert_eq!(shell.theme.background_oled_hex, "#000000");
        assert!(shell.core.settings.len() >= 2165);

        shell.settings_search_query = "argon2id".into();
        let vp = shell.render_virtualized_settings_viewport(600);
        assert!(vp.total_matching_items >= 3);
    }

    #[test]
    fn test_cursor_css_injection_rejected_and_ani_anih_parsed() {
        let mut eng = CustomCursorEngine::default();
        eng.global_override_website_css = false;
        eng.set_domain_cursor_override("evil.test", "javascript:alert(1)");
        eng.set_domain_cursor_override(
            "evil.test",
            "https://a.test/x.cur'); background:url('https://evil.test",
        );
        assert!(eng.generate_css_cursor_override_sheet("evil.test").is_none());

        eng.set_domain_cursor_override("safe.test", "singularity://cursors/custom.cur");
        let css = eng
            .generate_css_cursor_override_sheet("safe.test")
            .expect("safe cursor sheet");
        assert!(css.contains("singularity://cursors/custom.cur"));

        // Full 48-byte RIFF ACON with 36-byte anih chunk (cFrames=12, iDispRate=6 jiffies)
        let mut ani = Vec::new();
        ani.extend_from_slice(b"RIFF");
        ani.extend_from_slice(&40u32.to_le_bytes());
        ani.extend_from_slice(b"ACON");
        ani.extend_from_slice(b"anih");
        ani.extend_from_slice(&36u32.to_le_bytes());
        ani.extend_from_slice(&36u32.to_le_bytes()); // cbSize
        ani.extend_from_slice(&12u32.to_le_bytes()); // cFrames
        ani.extend_from_slice(&12u32.to_le_bytes()); // cSteps
        ani.extend_from_slice(&32u32.to_le_bytes()); // iWidth
        ani.extend_from_slice(&32u32.to_le_bytes()); // iHeight
        ani.extend_from_slice(&32u32.to_le_bytes()); // iBitCount
        ani.extend_from_slice(&1u32.to_le_bytes()); // cPlanes
        ani.extend_from_slice(&6u32.to_le_bytes()); // iDispRate
        ani.extend_from_slice(&1u32.to_le_bytes()); // bfAttributes
        assert_eq!(
            CustomCursorEngine::parse_ani_header(&ani).expect("Parse full .ani"),
            CursorAssetFormat::AnimatedAni {
                frame_count: 12,
                jif_rate_60hz: 6
            }
        );
    }

    #[test]
    fn test_vim_hints_unique_above_196_links_and_backspace() {
        let mut vim = VimModalEngine::default();
        let links: Vec<(String, u32, u32)> = (0..260u32)
            .map(|i| (format!("https://example.org/{}", i), i, i))
            .collect();
        vim.generate_home_row_hints(&links);
        let unique: std::collections::HashSet<&str> = vim
            .active_hints
            .iter()
            .map(|h| h.label.as_str())
            .collect();
        assert_eq!(unique.len(), 260);

        // Enter hint mode, type a prefix, backspace, and verify invalid prefix resets to Normal
        assert_eq!(
            vim.handle_key_press("f"),
            VimAction::EnterLinkHintMode { new_tab: false }
        );
        assert_eq!(vim.handle_key_press("s"), VimAction::NoOp);
        assert_eq!(vim.handle_key_press("Backspace"), VimAction::NoOp);
        assert_eq!(vim.handle_key_press("z"), VimAction::NoOp);
        assert_eq!(vim.mode, VimMode::Normal);
    }

    #[test]
    fn test_updater_semver_and_sha256_verification() {
        assert!(updater::is_newer_semver("3.0.10", "3.0.2"));
        assert!(!updater::is_newer_semver("3.0.1", "3.0.1"));
        assert!(updater::is_newer_semver("3.0.1", "3.0.1-rc.1"));
        assert!(!updater::is_newer_semver("3.0.1-beta.1", "3.0.1"));

        let sums = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  singularity.exe\n";
        let expected = updater::parse_sha256sums_for_asset(sums, "singularity.exe").expect("parse");
        assert_eq!(expected.len(), 32);
    }

    #[test]
    fn test_roaming_cookie_smsv_classification_and_ui_hardening() {
        assert_eq!(classify_auth_cookie(".google.com", "SMSV"), Some("Google"));
        assert_eq!(classify_auth_cookie(".google.com", "smsv"), Some("Google"));
        // Verify UI HTML enforces hardened sandbox and no JS master cache
        assert!(!SINGULARITY_UI_HTML.contains("allow-same-origin"));
        assert!(!SINGULARITY_UI_HTML.contains("sessionMasterCache"));
        assert!(SINGULARITY_UI_HTML.contains("__SINGULARITY_IPC_TOKEN__"));
    }

    #[test]
    fn test_windows_frameless_titlebar_and_maximized_resize_lock() {
        // Native WebView2 non-client drag region + explicit no-drag overrides for WebView2 v152+
        assert!(SINGULARITY_UI_HTML.contains("app-region: drag;"));
        assert!(SINGULARITY_UI_HTML.contains("-webkit-app-region: drag;"));
        assert!(SINGULARITY_UI_HTML.contains("app-region: no-drag;"));
        assert!(SINGULARITY_UI_HTML.contains("-webkit-app-region: no-drag;"));
        // Resize handles completely hidden & guarded when maximized/fullscreen
        assert!(SINGULARITY_UI_HTML.contains("body.is-maximized .rz"));
        assert!(SINGULARITY_UI_HTML.contains("if (e.button !== 0 || isWindowMaximized) return;"));
        assert!(SINGULARITY_UI_HTML.contains("typeof msg.maximized === \"boolean\""));
        // Double-click-safe titlebar fallback (never triggers drag immediately on mousedown)
        assert!(SINGULARITY_UI_HTML.contains("triggerTitlebarMaximize"));
    }

    #[test]
    fn test_ram_unloader_four_modes_and_v302_ui_features() {
        assert_eq!(roaming_store::tab_unload_timeout_seconds("low", 120), 2 * 3600);
        assert_eq!(roaming_store::tab_unload_timeout_seconds("medium", 120), 15 * 60);
        assert_eq!(roaming_store::tab_unload_timeout_seconds("hard", 120), 3 * 60);
        assert_eq!(roaming_store::tab_unload_timeout_seconds("custom", 45), 45 * 60);
        assert_eq!(roaming_store::tab_unload_timeout_seconds("custom", 0), 60);
        assert_eq!(
            roaming_store::tab_unload_timeout_seconds("custom", 999_999),
            43_200 * 60
        );

        // Overflow-proof tab bar + always-centered 3-column grid omnibar
        assert!(SINGULARITY_UI_HTML.contains("grid-template-columns: minmax(0, 1fr)"));
        assert!(SINGULARITY_UI_HTML.contains("tabs-bar-wrap"));
        assert!(SINGULARITY_UI_HTML.contains("tabs-scroll-left"));
        assert!(SINGULARITY_UI_HTML.contains("tabs-scroll-right"));

        // Per-tab zero-reload IPC + background lazy middle-click tabs + 4-mode RAM UI + Chrome Extensions UI
        assert!(SINGULARITY_UI_HTML.contains("activate_tab"));
        assert!(SINGULARITY_UI_HTML.contains("sync_tab_url"));
        assert!(SINGULARITY_UI_HTML.contains("openBackgroundLazyTab"));
        assert!(SINGULARITY_UI_HTML.contains("new_tab_background"));
        assert!(SINGULARITY_UI_HTML.contains("selectRamMode"));
        assert!(SINGULARITY_UI_HTML.contains("ext-toolbar-strip"));
        assert!(SINGULARITY_UI_HTML.contains("pane-extensions"));
    }

    #[test]
    fn test_selective_cookie_scrubbing_preserves_tokens_and_removes_threats() {
        // 1. User login tokens, Google/YouTube consent & security, CSRF, Cloudflare, and normal cookies MUST be preserved
        let must_keep = [
            (".google.com", "SID", "val"),
            (".google.fr", "SOCS", "CAESHAgBEhJnd3NfMjAyNjA1MTUtMF9SQzIaAmZyIAEaBgiA"),
            (".google.fr", "CONSENT", "YES+cb"),
            (".google.fr", "AEC", "AZ6Zc-token"),
            (".google.com", "NID", "511=abc"),
            ("accounts.google.com", "__Host-GAPS", "1:abc"),
            (".google.com", "__Secure-1PSID", "g.a000..."),
            (".youtube.com", "VISITOR_INFO1_LIVE", "xyz"),
            (".youtube.com", "LOGIN_INFO", "AFmmF2sw..."),
            (".github.com", "user_session", "sess123"),
            (".discord.com", "__dcfduid", "dc123"),
            (".twitch.tv", "auth-token", "tw123"),
            ("example.org", "cf_clearance", "cf123"),
            ("example.org", "csrftoken", "csrf123"),
            ("bank.example.fr", "PHPSESSID", "php123"),
            ("shop.example.fr", "cart_items", "3"),
        ];
        for (dom, name, val) in must_keep {
            assert_eq!(
                classify_tracker_or_malicious_cookie(dom, name, val),
                None,
                "Legitimate cookie ({}, {}) must NEVER be deleted!",
                dom,
                name
            );
        }

        // 2. Advertising cookies MUST be removed
        assert_eq!(
            classify_tracker_or_malicious_cookie(".doubleclick.net", "IDE", "AHWqTUm"),
            Some(CookieThreatKind::Advertising)
        );
        assert_eq!(
            classify_tracker_or_malicious_cookie(".criteo.com", "uid", "123"),
            Some(CookieThreatKind::Advertising)
        );
        assert_eq!(
            classify_tracker_or_malicious_cookie(".example.com", "_fbp", "fb.1.12345"),
            Some(CookieThreatKind::Advertising)
        );
        assert_eq!(
            classify_tracker_or_malicious_cookie(".example.com", "_gcl_au", "1.1.999"),
            Some(CookieThreatKind::Advertising)
        );

        // 3. Tracker / analytics cookies MUST be removed
        assert_eq!(
            classify_tracker_or_malicious_cookie(".example.com", "_ga", "GA1.1.12345"),
            Some(CookieThreatKind::Tracker)
        );
        assert_eq!(
            classify_tracker_or_malicious_cookie(".example.com", "_ga_XYZ123", "GS1.1"),
            Some(CookieThreatKind::Tracker)
        );
        assert_eq!(
            classify_tracker_or_malicious_cookie(".hotjar.com", "_hjid", "uuid"),
            Some(CookieThreatKind::Tracker)
        );
        assert_eq!(
            classify_tracker_or_malicious_cookie(".example.com", "mp_abc123_mixpanel", "blob"),
            Some(CookieThreatKind::Tracker)
        );

        // 4. Malicious domains, XSS payloads, and >8KiB cookie bombs MUST be removed
        assert_eq!(
            classify_tracker_or_malicious_cookie(".coinhive.com", "miner", "1"),
            Some(CookieThreatKind::Malicious)
        );
        assert_eq!(
            classify_tracker_or_malicious_cookie(".propellerads.com", "pu", "1"),
            Some(CookieThreatKind::Malicious)
        );
        assert_eq!(
            classify_tracker_or_malicious_cookie("example.com", "note", "<script>alert(1)</script>"),
            Some(CookieThreatKind::Malicious)
        );
        assert_eq!(
            classify_tracker_or_malicious_cookie("example.com", "bomb", &"A".repeat(9000)),
            Some(CookieThreatKind::Malicious)
        );
    }

    #[test]
    fn test_crash_proof_session_backup_and_video_timestamp_resume() {
        // 1. YouTube watch / youtu.be / Twitch VOD timestamp injection + stale `t=` replacement
        assert_eq!(
            apply_media_timestamp_to_url("https://www.youtube.com/watch?v=dQw4w9WgXcQ", 742),
            "https://www.youtube.com/watch?v=dQw4w9WgXcQ&t=742s"
        );
        assert_eq!(
            apply_media_timestamp_to_url(
                "https://www.youtube.com/watch?v=dQw4w9WgXcQ&t=15s&list=PL123",
                742
            ),
            "https://www.youtube.com/watch?v=dQw4w9WgXcQ&list=PL123&t=742s"
        );
        assert_eq!(
            apply_media_timestamp_to_url("https://youtu.be/dQw4w9WgXcQ?t=10", 125),
            "https://youtu.be/dQw4w9WgXcQ?t=125s"
        );
        assert_eq!(
            apply_media_timestamp_to_url("https://www.twitch.tv/videos/2233445566", 3723),
            "https://www.twitch.tv/videos/2233445566?t=1h2m3s"
        );
        // Non-video sites & tiny (< 3s) offsets stay untouched
        assert_eq!(
            apply_media_timestamp_to_url("https://github.com/MyMasha/Singularity", 742),
            "https://github.com/MyMasha/Singularity"
        );
        assert_eq!(
            apply_media_timestamp_to_url("https://www.youtube.com/watch?v=dQw4w9WgXcQ", 2),
            "https://www.youtube.com/watch?v=dQw4w9WgXcQ"
        );

        // 2. Normalization ignores transient t=/time_continue=/start=/#hash
        assert_eq!(
            normalize_url_without_media_time(
                "https://www.youtube.com/watch?v=abc123&t=742s&start=5#player"
            ),
            normalize_url_without_media_time("https://www.youtube.com/watch?v=abc123")
        );

        // 3. Crash-proof atomic mirror (`profile.json` + `profile.json.bak`) recovery after power cut
        let test_dir = std::env::temp_dir().join(format!(
            "singularity_session_crash_test_{}_{}",
            std::process::id(),
            roaming_store::unix_now()
        ));
        let _ = std::fs::remove_dir_all(&test_dir);

        {
            let mut store =
                RoamingSingularityStore::open_at(test_dir.clone()).expect("open fresh store");
            // Restore session is enabled by default out of the box
            assert!(store.profile.restore_session);
            store.profile.saved_tabs = vec![
                SavedTabEntry {
                    title: "GitHub".into(),
                    url: "https://github.com/MyMasha/Singularity".into(),
                    media_time_sec: None,
                    scroll_y: Some(640),
                    group_id: None,
                    favicon_url: None,
                },
                SavedTabEntry {
                    title: "YouTube Video".into(),
                    url: "https://www.youtube.com/watch?v=abc123".into(),
                    media_time_sec: Some(420),
                    scroll_y: Some(120),
                    group_id: None,
                    favicon_url: None,
                },
            ];
            store.profile.active_tab_index = 1;
            store.save_profile().expect("save profile + backup");
            assert!(store.profile_file_path().is_file());
            assert!(store.profile_backup_file_path().is_file());

            // Live periodic media update modifies matching tab without losing the other tabs
            assert!(store.update_saved_tab_media_progress(
                "https://www.youtube.com/watch?v=abc123&t=420s",
                742,
                180
            ));
            store.save_profile().expect("save updated media time");
        }

        // Simulate abrupt PC power-cut corrupting `profile.json` mid-write
        std::fs::write(test_dir.join("profile.json"), b"{truncated-power-loss")
            .expect("corrupt primary profile.json");

        let recovered =
            RoamingSingularityStore::open_at(test_dir.clone()).expect("recover from .bak");
        assert!(recovered.profile.restore_session);
        assert_eq!(recovered.profile.active_tab_index, 1);
        assert_eq!(recovered.profile.saved_tabs.len(), 2);
        assert_eq!(recovered.profile.saved_tabs[0].scroll_y, Some(640));
        assert_eq!(recovered.profile.saved_tabs[1].media_time_sec, Some(742));
        assert_eq!(recovered.profile.saved_tabs[1].scroll_y, Some(180));

        // 4. Legacy v3.0.3 profile migration enables restore_session once automatically
        let legacy_dir = std::env::temp_dir().join(format!(
            "singularity_session_migrate_test_{}_{}",
            std::process::id(),
            roaming_store::unix_now()
        ));
        let _ = std::fs::remove_dir_all(&legacy_dir);
        std::fs::create_dir_all(&legacy_dir).expect("create legacy dir");
        std::fs::write(
            legacy_dir.join("profile.json"),
            r#"{"onboarding_completed":true,"default_search_engine":"ddg","restore_session":false,"strict_mullvad_killswitch":false,"mullvad_auto_connect":false,"mullvad_entry_relay":"se","mullvad_exit_relay":"ch","mullvad_multihop":true,"bookmarks":[],"history":[],"saved_tabs":[]}"#,
        )
        .expect("write legacy v3.0.3 profile");
        {
            let mut migrated =
                RoamingSingularityStore::open_at(legacy_dir.clone()).expect("migrate legacy");
            assert!(migrated.profile.restore_session);
            assert!(migrated.profile.session_restore_v2_migrated);
            // User explicitly turns OFF after migration -> must stay OFF on next boot!
            migrated.profile.restore_session = false;
            migrated.save_profile().expect("save explicit off");
        }
        let after_explicit_off =
            RoamingSingularityStore::open_at(legacy_dir.clone()).expect("reopen after off");
        assert!(!after_explicit_off.profile.restore_session);

        // 5. Verify UI HTML includes resume_time_sec, active_tab_index, and formatMediaTimestamp
        assert!(SINGULARITY_UI_HTML.contains("resume_time_sec"));
        assert!(SINGULARITY_UI_HTML.contains("active_tab_index"));
        assert!(SINGULARITY_UI_HTML.contains("formatMediaTimestamp"));

        let _ = std::fs::remove_dir_all(&test_dir);
        let _ = std::fs::remove_dir_all(&legacy_dir);
    }

    #[test]
    fn test_v305_ux_toast_tutorial_themes_settings_tab_and_middle_click() {
        // 1. Theme validation & persistence
        for valid in ["singularity", "soleil", "pulsar", "nebuleuse", "eclipse", "aurore"] {
            assert!(is_valid_theme_id(valid), "theme {} must be valid", valid);
        }
        assert!(!is_valid_theme_id("invalid_theme"));

        // 2. Non-clipped bar-only toast pill (fits strictly inside 46px bar: top 7px, height 32px)
        assert!(SINGULARITY_UI_HTML.contains("body.bar-only #toast"));
        assert!(SINGULARITY_UI_HTML.contains("top: 7px;"));
        assert!(SINGULARITY_UI_HTML.contains("height: 32px;"));

        // 3. Delegated capture-phase middle-click tab close + no-drag on tab strip
        assert!(SINGULARITY_UI_HTML.contains("wireTabsStripInteractions"));
        assert!(SINGULARITY_UI_HTML.contains("strip.addEventListener(\"pointerup\", onMidUpOrAux, true)"));
        assert!(SINGULARITY_UI_HTML.contains(".tabs-strip,"));

        // 4. Animated center-to-right URL bar when many tabs are open
        assert!(SINGULARITY_UI_HTML.contains(".apple-bar.tabs-expanded"));
        assert!(SINGULARITY_UI_HTML.contains("function syncOmnibarLayout("));

        // 5. Full-page settings tab (`singularity://settings`) + Brave-style sidebar + 6 cosmic themes (incl. Soleil 3D)
        assert!(SINGULARITY_UI_HTML.contains("function isInternalSettingsUrl("));
        assert!(SINGULARITY_UI_HTML.contains("singularity://settings/appearance"));
        assert!(SINGULARITY_UI_HTML.contains("data-theme=\"soleil\""));
        assert!(SINGULARITY_UI_HTML.contains("renderSolarOrEclipse"));
        assert!(SINGULARITY_UI_HTML.contains("settings-sidebar"));

        // 6. Launch tutorial wizard + installed browser open-tab importer + new-tab search auto-focus
        assert!(SINGULARITY_UI_HTML.contains("openTutorialWizard"));
        assert!(SINGULARITY_UI_HTML.contains("/api/import/browsers"));
        assert!(SINGULARITY_UI_HTML.contains("/api/import/execute"));
        assert!(SINGULARITY_UI_HTML.contains("focusSearchForNewTab"));
    }

    #[test]
    fn test_v306_multi_window_merge_favicons_groups_context_menu_and_shortcuts() {
        // 1. Multi-window separate restoration: 2 previously open Singularity windows with different
        //    tabs, groups, and screen geometry MUST reopen as 2 separate windows (Window #1 loads
        //    win-a's exact tabs & geometry and queues a single-use `--restore-session` handoff for
        //    Window #2 carrying win-b's exact tabs & geometry — NEVER merging them into 1 window!).
        let merge_dir = std::env::temp_dir().join(format!(
            "singularity_multiwin_restore_test_{}_{}",
            std::process::id(),
            roaming_store::unix_now()
        ));
        let _ = std::fs::remove_dir_all(&merge_dir);
        let sessions_dir = merge_dir.join("sessions");
        std::fs::create_dir_all(&sessions_dir).expect("create sessions dir");

        let win_a = WindowSessionFile {
            window_id: "win-a".into(),
            pid: 999_991, // non-existent dead PID
            updated_unix: 1000,
            active_tab_index: 1,
            tabs: vec![
                SavedTabEntry {
                    title: "GitHub".into(),
                    url: "https://github.com/MyMasha/Singularity".into(),
                    media_time_sec: None,
                    scroll_y: Some(300),
                    group_id: Some("grp-1".into()),
                    favicon_url: None,
                },
                SavedTabEntry {
                    title: "Video A".into(),
                    url: "https://www.youtube.com/watch?v=xyz789".into(),
                    media_time_sec: Some(120),
                    scroll_y: Some(50),
                    group_id: None,
                    favicon_url: None,
                },
            ],
            tab_groups: vec![SavedTabGroup {
                id: "grp-1".into(),
                title: "Dev".into(),
                color: "#3b82f6".into(),
                collapsed: false,
            }],
            geometry: WindowGeometry {
                pos_x: Some(40),
                pos_y: Some(40),
                width: Some(1280),
                height: Some(800),
                maximized: false,
            },
            closed_while_other_live: false,
        };

        let win_b = WindowSessionFile {
            window_id: "win-b".into(),
            pid: 999_992, // non-existent dead PID
            updated_unix: 1050,
            active_tab_index: 1,
            tabs: vec![
                SavedTabEntry {
                    title: "Video B".into(),
                    url: "https://www.youtube.com/watch?v=abc123&t=480s".into(),
                    media_time_sec: Some(480),
                    scroll_y: Some(90),
                    group_id: Some("grp-1".into()),
                    favicon_url: None,
                },
                SavedTabEntry {
                    title: "Twitch".into(),
                    url: "https://www.twitch.tv/videos/987654".into(),
                    media_time_sec: Some(615),
                    scroll_y: None,
                    group_id: Some("grp-1".into()),
                    favicon_url: None,
                },
            ],
            tab_groups: vec![SavedTabGroup {
                id: "grp-1".into(),
                title: "Videos".into(),
                color: "#ef4444".into(),
                collapsed: true,
            }],
            geometry: WindowGeometry {
                pos_x: Some(1320),
                pos_y: Some(60),
                width: Some(1100),
                height: Some(760),
                maximized: true,
            },
            closed_while_other_live: false,
        };

        std::fs::write(
            sessions_dir.join("win-a.json"),
            serde_json::to_vec(&win_a).expect("ser win_a"),
        )
        .expect("write win_a");
        std::fs::write(
            sessions_dir.join("win-b.json"),
            serde_json::to_vec(&win_b).expect("ser win_b"),
        )
        .expect("write win_b");

        let restored_1 = RoamingSingularityStore::open_at(merge_dir.clone()).expect("restore win 1");
        assert_eq!(restored_1.restored_windows_count, 2);
        assert!(!restored_1.is_secondary_live_window);
        assert_eq!(restored_1.profile.saved_tabs.len(), 2);
        assert_eq!(restored_1.profile.saved_tabs[0].title, "GitHub");
        assert_eq!(restored_1.profile.saved_tabs[1].media_time_sec, Some(120));
        assert_eq!(restored_1.profile.saved_tab_groups.len(), 1);
        assert_eq!(restored_1.profile.saved_tab_groups[0].title, "Dev");
        assert_eq!(restored_1.window_geometry.pos_x, Some(40));
        assert_eq!(restored_1.window_geometry.width, Some(1280));
        assert!(!restored_1.window_geometry.maximized);
        assert_eq!(restored_1.pending_restore_window_ids.len(), 1);
        // Old dead session files are cleaned up after claiming
        assert!(!sessions_dir.join("win-a.json").exists());
        assert!(!sessions_dir.join("win-b.json").exists());

        // Sibling Window #2 consumes the single-use `--restore-session <id>` handoff cleanly
        let sibling_id = restored_1.pending_restore_window_ids[0].clone();
        let restored_2 = RoamingSingularityStore::open_at_with_launch_args(
            merge_dir.clone(),
            None,
            Some(&sibling_id),
            false,
        )
        .expect("restore win 2");
        assert!(restored_2.is_secondary_live_window);
        assert_eq!(restored_2.profile.saved_tabs.len(), 2);
        assert_eq!(restored_2.profile.saved_tabs[0].media_time_sec, Some(480));
        assert_eq!(restored_2.profile.saved_tabs[1].title, "Twitch");
        assert_eq!(restored_2.profile.saved_tab_groups.len(), 1);
        assert_eq!(restored_2.profile.saved_tab_groups[0].title, "Videos");
        assert_eq!(restored_2.window_geometry.pos_x, Some(1320));
        assert!(restored_2.window_geometry.maximized);
        // Single-use restore handoff cannot be consumed twice
        assert!(RoamingSingularityStore::consume_window_restore_handoff(&merge_dir, &sibling_id).is_none());

        // 2. Verify noisy token-encryption pop-up toast is completely removed
        assert!(!SINGULARITY_UI_HTML.contains("token(s) de connexion chiffré(s) dans .singularity"));

        // 3. Verify crisp tab favicons, compact density, tab groups, right-click menu & global shortcuts
        assert!(SINGULARITY_UI_HTML.contains("/api/favicon?host="));
        assert!(SINGULARITY_UI_HTML.contains("createTabFaviconNode"));
        assert!(SINGULARITY_UI_HTML.contains("tab-favicon"));
        assert!(SINGULARITY_UI_HTML.contains("tab-group-pill"));
        assert!(SINGULARITY_UI_HTML.contains("group-editor-bar"));
        assert!(SINGULARITY_UI_HTML.contains("createTabGroupForTab"));
        assert!(SINGULARITY_UI_HTML.contains("show_tab_context_menu"));
        assert!(SINGULARITY_UI_HTML.contains("executeTabContextAction"));
        assert!(SINGULARITY_UI_HTML.contains("reopenLastClosedTab"));
        assert!(SINGULARITY_UI_HTML.contains("closedTabsStack"));
        assert!(SINGULARITY_UI_HTML.contains("handleBrowserShortcut"));
        assert!(SINGULARITY_UI_HTML.contains("reopen_closed_tab"));

        let _ = std::fs::remove_dir_all(&merge_dir);
    }

    #[test]
    fn test_v307_fullscreen_extension_popups_zero_terminal_curl_and_security_hardening() {
        // 1. Verify CRX3 protobuf public-key extraction & deterministic 32-char Chromium ID derivation
        let fake_pk = vec![0x30u8; 64];
        // AsymmetricKeyProof { field 1 (bytes): fake_pk } => tag 0x0A, len 64, payload
        let mut proof = vec![0x0Au8, fake_pk.len() as u8];
        proof.extend_from_slice(&fake_pk);
        // CrxFileHeader { field 2 (bytes): proof } => tag 0x12, len, proof
        let mut hdr = vec![0x12u8, proof.len() as u8];
        hdr.extend_from_slice(&proof);
        let mut crx3 = Vec::new();
        crx3.extend_from_slice(b"Cr24");
        crx3.extend_from_slice(&3u32.to_le_bytes());
        crx3.extend_from_slice(&(hdr.len() as u32).to_le_bytes());
        crx3.extend_from_slice(&hdr);
        crx3.extend_from_slice(b"PK\x03\x04");

        let extracted_b64 =
            extensions::extract_crx_public_key_b64(&crx3).expect("extract CRX3 pubkey");
        let derived_id = extensions::chromium_id_from_public_key_b64(&extracted_b64)
            .expect("derive chromium ID");
        assert_eq!(derived_id.len(), 32);
        assert!(derived_id.bytes().all(|b| (b'a'..=b'p').contains(&b)));

        // 2. Verify resolve_extension_runtime_url resolves popup & options chrome-extension:// URLs
        let tmp_root = std::env::temp_dir().join(format!(
            "singularity-v307-ext-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&tmp_root);
        let ext_dir = tmp_root.join("extensions").join(&derived_id);
        std::fs::create_dir_all(&ext_dir).expect("mkdir ext_dir");
        std::fs::write(
            ext_dir.join("manifest.json"),
            serde_json::json!({
                "manifest_version": 3,
                "name": "Test Popup Extension",
                "version": "1.2.3",
                "key": extracted_b64,
                "action": { "default_popup": "popup.html" },
                "options_ui": { "page": "options.html" }
            })
            .to_string(),
        )
        .expect("write manifest");
        std::fs::write(ext_dir.join("popup.html"), "<html>popup</html>").expect("write popup");
        std::fs::write(ext_dir.join("options.html"), "<html>options</html>").expect("write opt");

        let (pop_url, pop_name) =
            extensions::resolve_extension_runtime_url(&tmp_root, &derived_id, false)
                .expect("resolve popup url");
        assert_eq!(pop_url, format!("chrome-extension://{}/popup.html", derived_id));
        assert_eq!(pop_name, "Test Popup Extension");

        let (opt_url, _) =
            extensions::resolve_extension_runtime_url(&tmp_root, &derived_id, true)
                .expect("resolve options url");
        assert_eq!(opt_url, format!("chrome-extension://{}/options.html", derived_id));
        let _ = std::fs::remove_dir_all(&tmp_root);

        // 3. Verify UI hooks for extension popups, context menus, and F11 fullscreen
        assert!(SINGULARITY_UI_HTML.contains("toggle_extension_popup"));
        assert!(SINGULARITY_UI_HTML.contains("show_extension_context_menu"));
        assert!(SINGULARITY_UI_HTML.contains("openExtensionPopupUI"));
        assert!(SINGULARITY_UI_HTML.contains("executeExtensionContextAction"));
        assert!(SINGULARITY_UI_HTML.contains("toggle_fullscreen"));
        assert!(SINGULARITY_UI_HTML.contains("toggleNativeFullscreen"));

        // 4. Verify source-level regressions never return (native WinHTTP on Windows, System32 DLL, public GitHub Releases)
        let server_src = include_str!("server.rs");
        assert!(server_src.contains("winhttp_get_no_redirect"));
        assert!(!server_src.contains("Command::new(\"curl.exe\")"));
        assert!(server_src.contains("LOAD_LIBRARY_SEARCH_SYSTEM32"));
        assert!(server_src.contains("Fullscreen::Borderless(None)"));
        assert!(server_src.contains("CefCallbackEvent::FullscreenChanged"));
        assert!(server_src.contains("consume_bootstrap_nonce"));

        let updater_src = include_str!("updater.rs");
        assert!(updater_src.contains("https://github.com/MyMasha/Singularity"));
        assert!(updater_src.contains("winhttp_get_allowed_https_bytes"));
        assert!(updater_src.contains("winhttp_get_no_redirect"));
        assert!(updater_src.contains("winhttp_download_https_to_file"));
        assert!(!updater_src.contains("/contents/dist/"));
    }

    #[test]
    fn test_v100_public_release_english_i18n_mandatory_onboarding_ed25519_and_zero_pat() {
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
        use ed25519_dalek::{Signer, SigningKey};

        // 1. Zero hardcoded GitHub PATs across Rust updater and update scripts
        let updater_src = include_str!("updater.rs");
        let ps_updater = include_str!("../../../dist/Update-Singularity.ps1");
        let sh_updater = include_str!("../../../dist/update-singularity.sh");
        for (name, src) in [
            ("updater.rs", updater_src),
            ("Update-Singularity.ps1", ps_updater),
            ("update-singularity.sh", sh_updater),
        ] {
            assert!(
                !src.contains("github_pat_"),
                "{} must NEVER contain a hardcoded GitHub PAT",
                name
            );
            assert!(
                !src.contains("PRIVATE_REPO_READONLY_TOKEN"),
                "{} must NEVER define PRIVATE_REPO_READONLY_TOKEN",
                name
            );
            assert!(
                src.contains("https://github.com/MyMasha/Singularity"),
                "{} must target public https://github.com/MyMasha/Singularity",
                name
            );
        }

        // 2. Ed25519 manifest signature verification round-trip & tamper rejection
        let signing_key = SigningKey::from_bytes(&[0x42u8; 32]);
        let verifying_hex = hex::encode(signing_key.verifying_key().to_bytes());
        let manifest = b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  singularity.exe\n";
        let sig = signing_key.sign(manifest);
        let sig_b64 = BASE64.encode(sig.to_bytes());

        assert!(updater::verify_sha256sums_ed25519(manifest, &sig_b64, &verifying_hex).is_ok());
        assert!(
            updater::verify_sha256sums_ed25519(b"tampered manifest", &sig_b64, &verifying_hex)
                .is_err()
        );
        assert!(updater::verify_sha256sums_ed25519(manifest, "AAAA", &verifying_hex).is_err());

        // 3. English default language & validation
        let prof = roaming_store::UserProfile::default();
        assert_eq!(prof.language, "en");
        assert!(roaming_store::is_valid_language("en"));
        assert!(roaming_store::is_valid_language("fr"));
        assert!(!roaming_store::is_valid_language("xx"));
        assert_eq!(env!("CARGO_PKG_VERSION"), "3.0.4");

        // 4. English HTML default, live EN/FR i18n, mandatory Step 1 language+theme gate, and zero bundled brand SVGs
        assert!(SINGULARITY_UI_HTML.contains("<html lang=\"en\">"));
        assert!(SINGULARITY_UI_HTML.contains("v3.0.4"));
        assert!(SINGULARITY_UI_HTML.contains("function applyLanguage("));
        assert!(SINGULARITY_UI_HTML.contains("function selectLanguage("));
        assert!(SINGULARITY_UI_HTML.contains("function pickOnboardLanguage("));
        assert!(SINGULARITY_UI_HTML.contains("function updateMandatoryStep1Gate("));
        assert!(SINGULARITY_UI_HTML.contains("tutorialMandatoryLock"));
        assert!(SINGULARITY_UI_HTML.contains("onboardLanguagePicked"));
        assert!(SINGULARITY_UI_HTML.contains("onboardThemePicked"));
        assert!(SINGULARITY_UI_HTML.contains("openTutorialWizard(0, true)"));
        assert!(!SINGULARITY_UI_HTML.contains("M12.24 10.285V14.4h6.806"));
        assert!(!SINGULARITY_UI_HTML.contains("M23.498 6.186a3.016"));
        assert!(!SINGULARITY_UI_HTML.contains("M20.317 4.37a19.791"));
        assert!(!SINGULARITY_UI_HTML.contains("M11.571 4.714h1.715"));
        // Verify no hardcoded non-zero 16-digit Mullvad account pattern (XXXX XXXX XXXX XXXX) exists in UI HTML
        let html_bytes = SINGULARITY_UI_HTML.as_bytes();
        let has_hardcoded_16digit_account = html_bytes.windows(19).any(|w| {
            w[4] == b' '
                && w[9] == b' '
                && w[14] == b' '
                && w.iter()
                    .enumerate()
                    .all(|(i, b)| i == 4 || i == 9 || i == 14 || b.is_ascii_digit())
                && w != b"0000 0000 0000 0000"
                && w != b"1234 5678 9012 3456"
        });
        assert!(
            !has_hardcoded_16digit_account,
            "SINGULARITY_UI_HTML must not contain any hardcoded real 16-digit Mullvad account number"
        );
    }

    #[test]
    fn test_v101_exe_downloads_zero_terminal_winhttp_fast_boot_and_no_white_flash() {
        // 1. WinHTTP URL parser & redirect resolution unit tests
        let parsed = winhttp_client::parse_http_url_parts(
            "https://github.com/MyMasha/Singularity/releases/download/v1.0.1/Singularity-setup.exe?dl=1#frag",
        )
        .expect("parse https url");
        assert!(parsed.is_https);
        assert_eq!(parsed.host, "github.com");
        assert_eq!(parsed.port, 443);
        assert_eq!(
            parsed.path_and_query,
            "/MyMasha/Singularity/releases/download/v1.0.1/Singularity-setup.exe?dl=1"
        );

        let ipv6 = winhttp_client::parse_http_url_parts("http://[::1]:8080/health")
            .expect("parse ipv6 url");
        assert!(!ipv6.is_https);
        assert_eq!(ipv6.host, "::1");
        assert_eq!(ipv6.port, 8080);
        assert_eq!(ipv6.path_and_query, "/health");

        assert!(winhttp_client::parse_http_url_parts("javascript:alert(1)").is_err());
        assert!(winhttp_client::parse_http_url_parts("https://user:pass@evil.example/x").is_err());
        assert!(winhttp_client::parse_http_url_parts("https://example.com/\r\nInject: 1").is_err());

        assert_eq!(
            winhttp_client::resolve_http_redirect(
                "https://github.com/MyMasha/Singularity/releases/latest",
                "/MyMasha/Singularity/releases/tag/v1.0.1"
            ),
            Some("https://github.com/MyMasha/Singularity/releases/tag/v1.0.1".to_string())
        );
        assert_eq!(
            winhttp_client::resolve_http_redirect(
                "https://github.com/a/b",
                "//objects.githubusercontent.com/file.exe"
            ),
            Some("https://objects.githubusercontent.com/file.exe".to_string())
        );
        assert_eq!(
            winhttp_client::resolve_http_redirect("https://github.com/a/b", "file:///C:/Windows"),
            None
        );

        // 2. Native .exe download handling (Pure Chromium CEF), dark Win32 background & cookie hygiene
        let server_src = include_str!("server.rs");
        let cef_src = include_str!("cef_runtime.rs");
        assert!(cef_src.contains("on_before_download"));
        assert!(cef_src.contains("on_download_updated"));
        assert!(!cef_src.contains("safebrowsing-disable-download-protection"));
        assert!(!cef_src.contains("disable-client-side-phishing-detection"));
        assert!(!cef_src.contains("disable-extensions-file-access-check"));
        assert!(!cef_src.contains("no_sandbox: 1"));
        assert!(server_src.contains("SHGetKnownFolderPath"));
        assert!(server_src.contains("reveal_download_in_explorer"));
        assert!(server_src.contains("apply_win32_black_class_brush"));
        assert!(server_src.contains("enable_win32_immersive_dark_window"));
        assert!(cef_src.contains("background_color: 0xFF00_0000"));
        assert!(cef_src.contains("run_cookie_hygiene_cef"));
        assert!(server_src.contains("favicon_ram_cache"));
        assert!(server_src.contains("try_acquire_favicon_fetch_slot"));
        assert!(server_src.contains("record_history_in_memory"));

        // 3. Zero runtime PowerShell/curl subprocesses on Windows across extensions & updater
        let ext_src = include_str!("extensions.rs");
        assert!(ext_src.contains("winhttp_download_https_to_file"));
        assert!(!ext_src.contains("powershell.exe"));

        // 4. UI flicker-free New Tab WebGL lifecycle, lazy favicons & download toasts
        assert!(SINGULARITY_UI_HTML.contains("revealCanvasAfterDraw"));
        assert!(SINGULARITY_UI_HTML.contains("syncCanvasSize"));
        assert!(SINGULARITY_UI_HTML.contains("img.loading = \"lazy\""));
        assert!(SINGULARITY_UI_HTML.contains("download_started"));
        assert!(SINGULARITY_UI_HTML.contains("download_completed"));
        assert!(SINGULARITY_UI_HTML.contains("reveal_download"));
        assert!(!SINGULARITY_UI_HTML.contains("c.style.display = susp ? \"none\" : \"block\""));
    }

    #[test]
    fn test_v102_tab_drag_detach_cross_window_and_rust_performance_optimizations() {
        // 1. Cross-window tab detach handoff round-trip (one-time consume, isolated single-tab boot, validation)
        let test_dir = std::env::temp_dir().join(format!(
            "singularity_v102_detach_perf_test_{}_{}",
            std::process::id(),
            roaming_store::unix_now()
        ));
        let _ = std::fs::remove_dir_all(&test_dir);

        assert!(!roaming_store::is_valid_handoff_id(""));
        assert!(!roaming_store::is_valid_handoff_id("../escape"));
        assert!(!roaming_store::is_valid_handoff_id("foo/bar"));
        assert!(!roaming_store::is_valid_handoff_id("handoff-1234-abcdef"));
        assert!(roaming_store::is_valid_handoff_id("0123456789abcdef0123456789abcdef"));

        let mut win_a = RoamingSingularityStore::open_at(test_dir.clone()).expect("open win_a");
        win_a.profile.saved_tabs = vec![
            SavedTabEntry {
                title: "Window A Tab 1".into(),
                url: "https://rust-lang.org".into(),
                media_time_sec: None,
                scroll_y: None,
                group_id: None,
                favicon_url: None,
            },
            SavedTabEntry {
                title: "Window A Tab 2".into(),
                url: "https://github.com/MyMasha/Singularity".into(),
                media_time_sec: None,
                scroll_y: None,
                group_id: None,
                favicon_url: None,
            },
        ];
        // Test background coalescing persistence worker (`schedule_save_profile` + `flush_async_persistence`)
        win_a.schedule_save_profile();
        win_a.profile.active_tab_index = 1;
        win_a.schedule_save_profile();
        win_a.flush_async_persistence();
        assert!(win_a.profile_file_path().is_file());
        let persisted_raw = std::fs::read_to_string(win_a.profile_file_path()).expect("read profile");
        assert!(persisted_raw.contains("\"active_tab_index\":1"));

        // Register a live window descriptor + verify dead-PID cleanup & unregister
        win_a.register_live_window(55123, 0x1234, "deadbeef_token_001");
        let dead_peer = roaming_store::LiveWindowDescriptor {
            window_id: "win-dead-999999".into(),
            pid: 999_999,
            port: 55124,
            hwnd: 0x5678,
            transfer_token: "stale_token".into(),
            updated_unix: 1,
        };
        let dead_path = win_a.windows_dir().join("win-dead-999999.json");
        std::fs::write(&dead_path, serde_json::to_vec(&dead_peer).expect("ser dead"))
            .expect("write dead peer");
        let peers = win_a.list_other_live_windows();
        assert!(peers.is_empty(), "dead peer windows must be pruned automatically");
        assert!(!dead_path.exists());
        win_a.unregister_live_window();

        // Write detach handoff and boot a torn-off window
        let handoff = roaming_store::TabHandoffPayload {
            url: "https://www.youtube.com/watch?v=v102perf".into(),
            title: "Detached Video".into(),
            favicon_url: Some("https://www.youtube.com/favicon.ico".into()),
            media_time_sec: Some(321),
            scroll_y: Some(140),
            pos_x: Some(320),
            pos_y: Some(120),
        };
        let hid = win_a.write_detach_handoff(&handoff).expect("write handoff");
        assert!(roaming_store::is_valid_handoff_id(&hid));

        let detached = RoamingSingularityStore::open_at_with_options(
            test_dir.clone(),
            Some(&hid),
            false,
        )
        .expect("open detached window");
        assert!(detached.is_secondary_live_window);
        let sh = detached.startup_handoff.as_ref().expect("startup_handoff");
        assert_eq!(sh.pos_x, Some(320));
        assert_eq!(sh.pos_y, Some(120));
        // Must ONLY contain the detached tab — never duplicate Window A's tabs!
        assert_eq!(detached.profile.saved_tabs.len(), 1);
        assert_eq!(detached.profile.saved_tabs[0].url, "https://www.youtube.com/watch?v=v102perf");
        assert_eq!(detached.profile.saved_tabs[0].media_time_sec, Some(321));
        assert_eq!(detached.profile.saved_tabs[0].scroll_y, Some(140));
        // Handoff file is strictly one-time consume
        assert!(RoamingSingularityStore::consume_detach_handoff(&test_dir, &hid).is_none());

        // Blank `--new-window` starts clean with zero stolen tabs
        let blank_win = RoamingSingularityStore::open_at_with_options(test_dir.clone(), None, true)
            .expect("open blank new window");
        assert!(blank_win.is_secondary_live_window);
        assert!(blank_win.profile.saved_tabs.is_empty());

        // RAM extensions cache sanity check
        extensions::invalidate_extensions_cache();
        let exts_a = extensions::list_extensions_cached(&test_dir, &[]);
        let exts_b = extensions::list_extensions_cached(&test_dir, &[]);
        assert_eq!(exts_a.len(), exts_b.len());

        // 2. Real-Rust HTTP, IPC, Win32 & Pure Chromium CEF performance engine assertions
        let server_src = include_str!("server.rs");
        assert!(server_src.contains("struct HttpThreadPool"));
        assert!(server_src.contains("set_nodelay(true)"));
        assert!(server_src.contains("MAX_KEEPALIVE_REQUESTS_PER_CONN"));
        assert!(server_src.contains("Connection: keep-alive"));
        assert!(server_src.contains("STATE_REVISION"));
        assert!(server_src.contains("struct WebViewLayoutCache"));
        assert!(server_src.contains("/api/window/adopt_tab"));
        assert!(server_src.contains("schedule_save_profile"));
        assert!(server_src.contains("is_detached_handoff"));

        // 3. UI Chrome-grade tab drag/tear-off, keyed DOM reconciliation & 60fps shader cap
        assert!(SINGULARITY_UI_HTML.contains("detachTabToWindow"));
        assert!(SINGULARITY_UI_HTML.contains("removeDetachedTabFromList"));
        assert!(SINGULARITY_UI_HTML.contains("adopt_external_tab"));
        assert!(SINGULARITY_UI_HTML.contains("tab_detached"));
        assert!(SINGULARITY_UI_HTML.contains("move_tab_new_window"));
        assert!(SINGULARITY_UI_HTML.contains("move_tab_to_window"));
        assert!(SINGULARITY_UI_HTML.contains("open_new_window"));
        assert!(SINGULARITY_UI_HTML.contains("updateSingleTabPill"));
        assert!(SINGULARITY_UI_HTML.contains("syncTabPillElement"));
        assert!(SINGULARITY_UI_HTML.contains("lastStateRev"));
        assert!(SINGULARITY_UI_HTML.contains("MIN_FRAME_MS"));
        assert!(SINGULARITY_UI_HTML.contains("visibilitychange"));
        assert!(SINGULARITY_UI_HTML.contains("1280 / iw"));
        assert!(SINGULARITY_UI_HTML.contains("for (int i = 0; i < 32; i++)"));
        assert!(SINGULARITY_UI_HTML.contains("contain: layout style;"));

        let _ = std::fs::remove_dir_all(&test_dir);
    }

    #[test]
    fn test_v103_borderless_dwm_and_http_pool_headroom() {
        // Verify borderless DWM color-none (zero blue Win98 border regression!), hidden-until-ready
        // window creation, and 32-worker HTTP thread pool headroom.
        let server_src = include_str!("server.rs");
        assert!(server_src.contains("HTTP_WORKER_THREADS: usize = 32"));
        assert!(server_src.contains("DWMWA_BORDER_COLOR"));
        assert!(server_src.contains("DWMWA_COLOR_NONE"));
        assert!(!server_src.contains("WM_NCPAINT"));
        assert!(!server_src.contains("SetWindowSubclass"));
        assert!(server_src.contains("WebViewLayoutCache"));
        assert!(server_src.contains(".with_visible(false)"));
    }

    #[test]
    fn test_v105_separate_multi_window_restore_start_paused_and_auto_web_focus() {
        let test_dir = std::env::temp_dir().join(format!(
            "singularity_v105_test_{}_{}",
            std::process::id(),
            roaming_store::unix_now()
        ));
        let _ = std::fs::remove_dir_all(&test_dir);
        let sessions_dir = test_dir.join("sessions");
        std::fs::create_dir_all(&sessions_dir).expect("create sessions dir");

        // 1. Stale window manually closed >20s before shutdown MUST be pruned, while 2 windows
        //    closed together during Windows Restart (within 20s) MUST BOTH reopen separately!
        let old_closed = WindowSessionFile {
            window_id: "win-old-manual".into(),
            pid: 999_981,
            updated_unix: 1000,
            active_tab_index: 0,
            tabs: vec![SavedTabEntry {
                title: "Old Manually Closed".into(),
                url: "https://example.org/old".into(),
                media_time_sec: None,
                scroll_y: None,
                group_id: None,
                favicon_url: None,
            }],
            tab_groups: Vec::new(),
            geometry: WindowGeometry::default(),
            closed_while_other_live: true,
        };
        let restart_win_1 = WindowSessionFile {
            window_id: "win-restart-1".into(),
            pid: 999_982,
            updated_unix: 2000,
            active_tab_index: 0,
            tabs: vec![SavedTabEntry {
                title: "YouTube Watch".into(),
                url: "https://www.youtube.com/watch?v=paused123".into(),
                media_time_sec: Some(345),
                scroll_y: None,
                group_id: None,
                favicon_url: None,
            }],
            tab_groups: Vec::new(),
            geometry: WindowGeometry {
                pos_x: Some(10),
                pos_y: Some(20),
                width: Some(1000),
                height: Some(720),
                maximized: false,
            },
            closed_while_other_live: true, // closed 5s before win-restart-2 during Windows Restart!
        };
        let restart_win_2 = WindowSessionFile {
            window_id: "win-restart-2".into(),
            pid: 999_983,
            updated_unix: 2005,
            active_tab_index: 0,
            tabs: vec![SavedTabEntry {
                title: "Docs".into(),
                url: "https://doc.rust-lang.org".into(),
                media_time_sec: None,
                scroll_y: Some(240),
                group_id: None,
                favicon_url: None,
            }],
            tab_groups: Vec::new(),
            geometry: WindowGeometry {
                pos_x: Some(1020),
                pos_y: Some(20),
                width: Some(900),
                height: Some(720),
                maximized: false,
            },
            closed_while_other_live: false,
        };
        for (name, s) in [
            ("win-old-manual.json", &old_closed),
            ("win-restart-1.json", &restart_win_1),
            ("win-restart-2.json", &restart_win_2),
        ] {
            std::fs::write(sessions_dir.join(name), serde_json::to_vec(s).expect("ser"))
                .expect("write sess");
        }

        let w1 = RoamingSingularityStore::open_at(test_dir.clone()).expect("open w1");
        assert_eq!(w1.restored_windows_count, 2, "must reopen the 2 restart windows and prune old_closed");
        assert_eq!(w1.profile.saved_tabs.len(), 1);
        assert_eq!(w1.profile.saved_tabs[0].url, "https://www.youtube.com/watch?v=paused123");
        assert_eq!(w1.profile.saved_tabs[0].media_time_sec, Some(345));
        assert_eq!(w1.pending_restore_window_ids.len(), 1);

        let w2 = RoamingSingularityStore::open_at_with_launch_args(
            test_dir.clone(),
            None,
            Some(&w1.pending_restore_window_ids[0]),
            false,
        )
        .expect("open w2");
        assert_eq!(w2.profile.saved_tabs.len(), 1);
        assert_eq!(w2.profile.saved_tabs[0].url, "https://doc.rust-lang.org");
        assert_eq!(w2.window_geometry.pos_x, Some(1020));

        // 2. delete_window_session removes both .json and .json.bak cleanly
        w2.save_window_session().expect("save w2 session");
        assert!(w2.window_session_file_path().is_file());
        w2.delete_window_session();
        assert!(!w2.window_session_file_path().exists());
        assert!(!w2.window_session_file_path().with_extension("json.bak").exists());

        // 3. Verify server.rs start-paused video gate, auto-focus, YouTube Spacebar, and multi-window persistence
        let server_src = include_str!("server.rs");
        assert!(server_src.contains("start_paused: bool"));
        assert!(server_src.contains("__singularityStartPausedLock"));
        assert!(server_src.contains("__singularityUnlockStartPaused"));
        assert!(server_src.contains("NotAllowedError"));
        assert!(server_src.contains("FocusActiveWeb"));
        assert!(server_src.contains("TOGGLE_ACTIVE_MEDIA_SCRIPT"));
        assert!(server_src.contains("WindowEvent::Focused(true)"));
        assert!(server_src.contains("is_cursor_clicking_top_bar"));
        assert!(server_src.contains("save_window_session_for"));
        assert!(server_src.contains("delete_window_session_for"));
        assert!(server_src.contains("restored_windows_count"));
        assert!(!server_src.contains("WM_NCPAINT"));
        assert!(!server_src.contains("SetWindowSubclass"));

        // 4. Verify UI startPaused propagation, active-tab refocus, and top-bar Spacebar forwarding
        assert!(SINGULARITY_UI_HTML.contains("startPaused: !isDetachedHandoff"));
        assert!(SINGULARITY_UI_HTML.contains("start_paused: shouldStartPaused"));
        assert!(SINGULARITY_UI_HTML.contains("focus_active_web"));
        assert!(SINGULARITY_UI_HTML.contains("toggle_media_play"));
        assert!(SINGULARITY_UI_HTML.contains("restored_windows_count"));
        assert!(SINGULARITY_UI_HTML.contains("v3.0.4"));

        let _ = std::fs::remove_dir_all(&test_dir);
    }

    #[test]
    fn test_v200_pure_chromium_cef_zero_edge_and_ram_optimizations() {
        // 1. Primary browser engine is Pure Chromium CEF; WebView2 (`wry`) is strictly isolated
        // inside `drm_webview.rs` for on-demand signed VMP/PlayReady DRM tabs only (never in `server.rs`).
        let ui_cargo = include_str!("../Cargo.toml");
        assert!(ui_cargo.contains("cef = "));
        assert!(ui_cargo.contains("wry = "));

        let build_rs = include_str!("../build.rs");
        assert!(build_rs.contains("/DELAYLOAD:libcef.dll"));

        let server_src = include_str!("server.rs");
        assert!(!server_src.contains("msedge.exe"));
        assert!(!server_src.contains("msedgewebview2"));
        assert!(!server_src.contains("WebView2Loader"));
        assert!(!server_src.contains("use wry::"));
        assert!(server_src.contains("CefRuntimeGuard"));
        assert!(server_src.contains("drm_webview"));
        assert!(server_src.contains("ToggleTabDrm"));

        // Hybrid DRM invariants: CEF Widevine CDM enabled + args.gn Widevine enabled + UI DRM badge
        let drm_src = include_str!("drm_webview.rs");
        assert!(drm_src.contains("requires_vmp_drm_engine"));
        assert!(drm_src.contains("ensure_cef_widevine_ready"));
        assert!(drm_src.contains("ContainsFullScreenElementChanged"));
        assert!(!drm_src.contains("with_ipc_handler"));
        assert!(SINGULARITY_UI_HTML.contains("btn-drm-mode"));
        assert!(SINGULARITY_UI_HTML.contains("toggle_tab_drm"));
        assert!(server_src.contains("window_sessions"));
        assert!(server_src.contains("x-singularity-window"));
        assert!(server_src.contains("ensure_win32_clip_children"));
        assert!(server_src.contains("WS_CLIPCHILDREN"));
        assert!(server_src.contains("wait_for_context_initialized"));
        assert!(server_src.contains("PrintWindow"));

        let main_src = include_str!("main.rs");
        assert!(main_src.contains("maybe_run_cef_subprocess"));
        assert!(main_src.contains("has_local_cef_runtime"));
        assert!(main_src.contains("bootstrap_missing_cef_runtime"));
        assert!(main_src.contains("configure_local_cef_dll_directory"));
        assert!(main_src.contains("--smoke-test-cef"));

        // 2. Pure Chromium CEF low-RAM flags, real network-layer uBlock, and black-screen invariants
        let cef_src = include_str!("cef_runtime.rs");
        assert!(cef_src.contains("process-per-site"));
        assert!(cef_src.contains("BackForwardCache"));
        assert!(cef_src.contains("on_before_resource_load"));
        assert!(!cef_src.contains("host.was_hidden("));
        assert!(!cef_src.contains("args.as_cmd_line()"));
        assert!(cef_src.contains("on_context_initialized"));
        assert!(cef_src.contains("on_after_created"));
        assert!(cef_src.contains("on_load_error"));
        assert!(cef_src.contains("on_render_process_terminated"));
        assert!(cef_src.contains("IN_CEF_PUMP"));
        assert!(cef_src.contains("browser_subprocess_path"));
        assert!(cef_src.contains("K32EmptyWorkingSet"));
        assert!(cef_src.contains("trim_process_working_set"));
        assert!(cef_src.contains("on_already_running_app_relaunch"));
        assert!(cef_src.contains("RuntimeStyle::ALLOY"));

        // 3. UI WebGL2 1x1 framebuffer shrink when hidden, background tab RAM cap, and X-Singularity-Window header
        assert!(SINGULARITY_UI_HTML.contains("WINDOW_SESSION_ID"));
        assert!(SINGULARITY_UI_HTML.contains("X-Singularity-Window"));
        assert!(SINGULARITY_UI_HTML.contains("c.width = 1;"));
        assert!(SINGULARITY_UI_HTML.contains("maxActiveBackgroundTabsForMode"));

        // 4. Self-updater & installer bundle Pure Chromium CEF ZIP + self-healing bootstrap
        let updater_src = include_str!("updater.rs");
        assert!(updater_src.contains("Singularity-setup.exe"));
        assert!(updater_src.contains("\"--launch\""));
        assert!(updater_src.contains("SetDllDirectoryW"));
        assert!(updater_src.contains("bootstrap_missing_cef_runtime"));
        let installer_src = include_str!("../../singularity-installer/src/main.rs");
        assert!(installer_src.contains("zip::ZipArchive"));
        assert!(installer_src.contains("libcef.dll"));
        assert!(installer_src.contains("--launch"));
    }

    #[test]
    fn test_v203_tab_close_auth_hydration_tiktok_and_crash_guard() {
        use singularity_core::{FilterDecision, NetworkResourceType, UBlockNetworkEngine};

        // 1. TikTok auth cookies + functional anti-bot cookies are preserved, while 3rd-party pixels stay blocked
        assert_eq!(classify_auth_cookie(".tiktok.com", "sessionid"), Some("TikTok"));
        assert_eq!(classify_auth_cookie(".tiktok.com", "sid_tt"), Some("TikTok"));
        for (dom, name, val) in [
            (".tiktok.com", "_ttp", "abc123"),
            (".tiktok.com", "ttwid", "1%7Cxyz"),
            (".tiktok.com", "msToken", "tok123"),
            (".tiktok.com", "s_v_web_id", "verify_123"),
            (".tiktok.com", "sessionid", "sess_tiktok"),
            (".analytics.tiktok.com", "tt_csrf_token", "csrf"),
            (".byteoversea.com", "odin_tt", "odin"),
            (".tiktokw.us", "tt_chain_token", "chain"),
            ("example.org", "ak_bmsc", "waf"),
            ("example.org", "datadome", "dd"),
        ] {
            assert_eq!(
                classify_tracker_or_malicious_cookie(dom, name, val),
                None,
                "TikTok / WAF cookie ({}, {}) must NEVER be deleted",
                dom,
                name
            );
        }

        let blocker = UBlockNetworkEngine::default();
        // First-party TikTok analytics & PingBeacon allowed; third-party TikTok pixel & beacon blocked
        assert!(matches!(
            blocker.evaluate_request(
                "https://analytics.tiktok.com/api/v2/report",
                "analytics.tiktok.com",
                "analytics.tiktok.com",
                NetworkResourceType::XmlHttpRequestFetch,
            ),
            FilterDecision::Allow | FilterDecision::AllowByExceptionRule(_)
        ));
        assert!(matches!(
            blocker.evaluate_request(
                "https://www.tiktok.com/api/v1/beacon",
                "www.tiktok.com",
                "www.tiktok.com",
                NetworkResourceType::PingBeacon,
            ),
            FilterDecision::Allow | FilterDecision::AllowByExceptionRule(_)
        ));
        assert!(matches!(
            blocker.evaluate_request(
                "https://analytics.tiktok.com/i18n/pixel/events.js",
                "analytics.tiktok.com",
                "news.example.com",
                NetworkResourceType::Script,
            ),
            FilterDecision::BlockedByDomainRule(_)
        ));
        assert!(matches!(
            blocker.evaluate_request(
                "https://telemetry.other.test/beacon",
                "telemetry.other.test",
                "news.example.com",
                NetworkResourceType::PingBeacon,
            ),
            FilterDecision::BlockedBeaconOrPing
        ));

        // 2. Crash detection, copyable error report formatting, cef.log tail, and full checkpoint recovery
        let tmp_dir = std::env::temp_dir().join(format!(
            "singularity_v203_crash_test_{}_{}",
            std::process::id(),
            roaming_store::unix_now()
        ));
        let _ = std::fs::remove_dir_all(&tmp_dir);
        std::fs::create_dir_all(&tmp_dir).expect("mkdir tmp_dir");
        std::fs::write(
            tmp_dir.join("cef.log"),
            "[INFO] boot ok\n[ERROR] simulated crash line\n",
        )
        .expect("write cef.log");

        // Write a stale dead-PID running.lock AND a crash_checkpoint.json with 2 windows + video timestamps
        std::fs::write(
            tmp_dir.join("running.lock"),
            r#"{"pid":999997,"started_unix":1700000000,"version":"3.0.1"}"#,
        )
        .expect("write stale lock");
        assert!(crash_guard::has_unclean_crash_sentinel(&tmp_dir));

        let checkpoint_windows = vec![
            WindowSessionFile {
                window_id: "win-crash-1".into(),
                pid: 999_997,
                updated_unix: 1000,
                active_tab_index: 0,
                tabs: vec![SavedTabEntry {
                    title: "Long YouTube Video".into(),
                    url: "https://www.youtube.com/watch?v=recover999".into(),
                    media_time_sec: Some(1337),
                    scroll_y: Some(250),
                    group_id: None,
                    favicon_url: None,
                }],
                tab_groups: Vec::new(),
                geometry: WindowGeometry::default(),
                closed_while_other_live: true, // Even if stale flag was true, crash recovery MUST restore it!
            },
            WindowSessionFile {
                window_id: "win-crash-2".into(),
                pid: 999_997,
                updated_unix: 1100,
                active_tab_index: 0,
                tabs: vec![SavedTabEntry {
                    title: "TikTok Feed".into(),
                    url: "https://www.tiktok.com/".into(),
                    media_time_sec: None,
                    scroll_y: None,
                    group_id: None,
                    favicon_url: None,
                }],
                tab_groups: Vec::new(),
                geometry: WindowGeometry::default(),
                closed_while_other_live: false,
            },
        ];
        let sessions_dir = tmp_dir.join("sessions");
        std::fs::create_dir_all(&sessions_dir).expect("mkdir sessions");
        std::fs::write(
            sessions_dir.join("crash_checkpoint.json"),
            serde_json::to_vec(&checkpoint_windows).expect("ser checkpoint"),
        )
        .expect("write checkpoint");

        // Opening store during crash recovery restores BOTH windows and exact 1337s video timestamp!
        let restored = RoamingSingularityStore::open_at(tmp_dir.clone()).expect("open after crash");
        assert_eq!(restored.restored_windows_count, 2);
        assert_eq!(restored.pending_restore_window_ids.len(), 1);
        let mut all_urls: Vec<String> = restored
            .profile
            .saved_tabs
            .iter()
            .map(|t| t.url.clone())
            .collect();
        let mut all_times: Vec<Option<u64>> = restored
            .profile
            .saved_tabs
            .iter()
            .map(|t| t.media_time_sec)
            .collect();
        let win2 = RoamingSingularityStore::open_at_with_launch_args(
            tmp_dir.clone(),
            None,
            Some(&restored.pending_restore_window_ids[0]),
            false,
        )
        .expect("open crash sibling");
        all_urls.extend(win2.profile.saved_tabs.iter().map(|t| t.url.clone()));
        all_times.extend(win2.profile.saved_tabs.iter().map(|t| t.media_time_sec));
        assert!(all_urls.iter().any(|u| u.contains("recover999")));
        assert!(all_urls.iter().any(|u| u.contains("tiktok.com")));
        assert!(all_times.contains(&Some(1337)));

        // detect_previous_crash_and_mark_running emits copyable CrashReport including cef.log tail
        let rep = crash_guard::detect_previous_crash_and_mark_running(&tmp_dir)
            .expect("detect previous crash");
        assert_eq!(rep.kind, "unclean_shutdown");
        let txt = rep.format_copyable_text();
        assert!(txt.contains("=== SINGULARITY BROWSER CRASH REPORT ==="));
        assert!(txt.contains("simulated crash line"));
        assert!(txt.contains("v3.0.4"));

        // Clean shutdown clears running.lock sentinel
        crash_guard::mark_clean_shutdown(&tmp_dir);
        assert!(!crash_guard::has_unclean_crash_sentinel(&tmp_dir));

        let _ = std::fs::remove_dir_all(&tmp_dir);

        // 3. Verify v2.0.3 source-level & UI invariants
        let cef_src = include_str!("cef_runtime.rs");
        assert!(cef_src.contains("DestroyChildHwnd"));
        assert!(cef_src.contains("is_same_platform_ecosystem"));
        assert!(cef_src.contains("hydrate_cookies_from_roaming_cef_sync"));
        assert!(cef_src.contains("flush_cookie_store_cef_sync"));
        assert!(cef_src.contains("CookieSameSite::NO_RESTRICTION"));

        let server_src = include_str!("server.rs");
        assert!(server_src.contains("destroy_cef_child_hwnd"));
        assert!(server_src.contains("DestroyWindow"));
        assert!(server_src.contains("WS_CHILD"));
        assert!(server_src.contains("detect_previous_crash_and_mark_running"));
        assert!(server_src.contains("mark_clean_shutdown"));
        assert!(server_src.contains("flush_live_crash_checkpoint"));
        assert!(server_src.contains("SmokeFinalize"));
        assert!(server_src.contains("close_requested_count"));

        let main_src = include_str!("main.rs");
        assert!(main_src.contains("install_crash_handlers"));

        assert!(SINGULARITY_UI_HTML.contains("crash-report-modal"));
        assert!(SINGULARITY_UI_HTML.contains("openCrashReportModal"));
        assert!(SINGULARITY_UI_HTML.contains("copyCrashReport"));
        assert!(SINGULARITY_UI_HTML.contains("closeCrashReportModal"));
        assert!(SINGULARITY_UI_HTML.contains("copy_text"));
        assert!(SINGULARITY_UI_HTML.contains("v3.0.4"));
    }

    #[test]
    fn test_v204_proprietary_codecs_obs_cef_and_tiktok_media() {
        // 1. Expanded EU/US TikTok & ByteDance CDN domains keep first-party session cookies protected
        for (dom, name, val) in [
            (".tiktokv.eu", "_ttp", "eu_tok"),
            (".tiktokv.us", "ttwid", "us_tok"),
            (".tiktokw.eu", "msToken", "eu_ms"),
            (".muscdn.com", "tt_chain_token", "cdn_tok"),
            (".ttlivecdn.com", "odin_tt", "live_tok"),
            (".byteimg.com", "s_v_web_id", "img_tok"),
            (".bytedance.com", "tt_csrf_token", "bd_tok"),
        ] {
            assert_eq!(
                classify_tracker_or_malicious_cookie(dom, name, val),
                None,
                "Expanded TikTok ecosystem cookie ({}, {}) must NEVER be scrubbed",
                dom,
                name
            );
        }

        // 2. Cargo.toml pins cef = "=150.2.1" matching OBS Studio 33's proprietary-codec CEF 150/7871
        let ui_cargo = include_str!("../Cargo.toml");
        assert!(ui_cargo.contains(r#"cef = { version = "=150.2.1""#));

        // 3. Staging script pins OBS CEF 7871 archive by exact SHA-256 and produces download-cef archive.json
        let prep_py = include_str!("../../../scripts/prepare-cef-win64.py");
        assert!(prep_py.contains("cef_binary_7871_windows_x64.zip"));
        assert!(prep_py.contains("54cd191a3f56bb1f05be22b95e1fa8041061b38bd5fe94e0776fb34dd599f341"));
        assert!(prep_py.contains("archive.json"));
        assert!(prep_py.contains("EXPECTED_CEF_MAJOR = 150"));

        // 4. CEF runtime enables hardware HEVC support, suppresses webdriver flag, and allows regional TikTok CDNs
        let cef_src = include_str!("cef_runtime.rs");
        assert!(cef_src.contains("PlatformHEVCDecoderSupport"));
        assert!(cef_src.contains("AutomationControlled"));
        assert!(cef_src.contains("\"tiktokv.eu\""));
        assert!(cef_src.contains("\"tiktokw.eu\""));
        assert!(cef_src.contains("\"muscdn.com\""));
        assert!(cef_src.contains("\"ttlivecdn.com\""));

        // 5. Real Windows CEF smoke test hard-gates on H.264, AAC, combined MP4 AVC+AAC, MSE MP4, and !webdriver
        let server_src = include_str!("server.rs");
        assert!(server_src.contains("h264_ok"));
        assert!(server_src.contains("aac_ok"));
        assert!(server_src.contains("mp4_avc_aac_ok"));
        assert!(server_src.contains("mse_avc_aac_ok"));
        assert!(server_src.contains("MediaSource.isTypeSupported"));
        assert!(server_src.contains("&& !webdriver"));

        // 6. Release workflow stages OBS CEF 7871 and blocks silent Spotify CDN fallback
        let workflow = include_str!("../../../.github/workflows/release.yml");
        assert!(workflow.contains("prepare-cef-win64.py"));
        assert!(workflow.contains("CEF_DOWNLOAD_URL=http://127.0.0.1:1/forbidden-spotify-fallback"));
        assert!(workflow.contains("cef-win64-obs-7871-54cd191a"));
    }

    #[test]
    fn test_v205_os_shutdown_update_clean_restart_and_prev_cef_log() {
        let tmp_dir = std::env::temp_dir().join(format!(
            "singularity_v205_restart_test_{}_{}",
            std::process::id(),
            roaming_store::unix_now()
        ));
        let _ = std::fs::remove_dir_all(&tmp_dir);
        std::fs::create_dir_all(&tmp_dir).expect("mkdir tmp_dir");

        // 1. Simulate Windows Shutdown (`WM_ENDSESSION`) or in-place update while 2 windows are open:
        // `mark_planned_restart` clears `running.lock` and arms `planned_restart.flag` so ALL open
        // windows + timestamps restore cleanly WITHOUT surfacing a false-positive crash dialog!
        std::fs::write(
            tmp_dir.join("running.lock"),
            r#"{"pid":999996,"started_unix":1700000000,"version":"3.0.1"}"#,
        )
        .expect("write running.lock");
        let sessions_dir = tmp_dir.join("sessions");
        std::fs::create_dir_all(&sessions_dir).expect("mkdir sessions");
        let checkpoint_windows = vec![
            WindowSessionFile {
                window_id: "win-os-1".into(),
                pid: 999_996,
                updated_unix: 2000,
                active_tab_index: 0,
                tabs: vec![SavedTabEntry {
                    title: "Video Window 1".into(),
                    url: "https://www.youtube.com/watch?v=osshutdown1".into(),
                    media_time_sec: Some(420),
                    scroll_y: None,
                    group_id: None,
                    favicon_url: None,
                }],
                tab_groups: Vec::new(),
                geometry: WindowGeometry::default(),
                closed_while_other_live: true,
            },
            WindowSessionFile {
                window_id: "win-os-2".into(),
                pid: 999_996,
                updated_unix: 2001,
                active_tab_index: 0,
                tabs: vec![SavedTabEntry {
                    title: "TikTok Window 2".into(),
                    url: "https://www.tiktok.com/".into(),
                    media_time_sec: None,
                    scroll_y: None,
                    group_id: None,
                    favicon_url: None,
                }],
                tab_groups: Vec::new(),
                geometry: WindowGeometry::default(),
                closed_while_other_live: false,
            },
        ];
        std::fs::write(
            sessions_dir.join("crash_checkpoint.json"),
            serde_json::to_vec(&checkpoint_windows).expect("ser checkpoint"),
        )
        .expect("write checkpoint");

        crash_guard::mark_planned_restart(&tmp_dir);
        assert!(!crash_guard::has_unclean_crash_sentinel(&tmp_dir));
        assert!(
            crash_guard::detect_previous_crash_and_mark_running_with_cef_log(&tmp_dir, "").is_none(),
            "Planned OS shutdown / update must NEVER produce a false crash report!"
        );

        let restored = RoamingSingularityStore::open_at(tmp_dir.clone()).expect("open after planned restart");
        assert_eq!(restored.restored_windows_count, 2);
        assert_eq!(restored.pending_restore_window_ids.len(), 1);
        assert!(
            !crash_guard::consume_planned_restart_flag(&tmp_dir),
            "planned_restart.flag must be single-use and consumed on startup"
        );

        // 2. When a REAL crash happens, pre-CEF-init log snapshot preserves the dead session's CEF log
        // even after the new process truncates `cef.log`!
        std::fs::write(
            tmp_dir.join("running.lock"),
            r#"{"pid":999995,"started_unix":1700000000,"version":"3.0.1"}"#,
        )
        .expect("write dead lock");
        std::fs::write(tmp_dir.join("cef.log"), "[NEW_PID] fresh boot warning\n")
            .expect("overwrite cef.log");
        let rep = crash_guard::detect_previous_crash_and_mark_running_with_cef_log(
            &tmp_dir,
            "[DEAD_PID] FATAL: actual crash reason from previous session",
        )
        .expect("real crash detected");
        assert!(rep.cef_log_tail.contains("DEAD_PID"));
        assert!(!rep.cef_log_tail.contains("NEW_PID"));

        let _ = std::fs::remove_dir_all(&tmp_dir);

        // 3. Verify source-level invariants for OS shutdown, installer/updater, and CEF drain
        let server_src = include_str!("server.rs");
        assert!(server_src.contains("Event::LoopDestroyed"));
        assert!(server_src.contains("detect_previous_crash_and_mark_running_with_cef_log"));
        assert!(server_src.contains("fn close_cleanly("));
        assert!(server_src.contains("drain_browsers_before_shutdown"));
        assert!(server_src.contains("mark_planned_restart"));

        let cef_src = include_str!("cef_runtime.rs");
        assert!(cef_src.contains("on_before_close"));
        assert!(cef_src.contains("OPEN_CEF_BROWSERS"));
        assert!(cef_src.contains("drain_browsers_before_shutdown"));

        let updater_src = include_str!("updater.rs");
        assert!(updater_src.contains("mark_planned_restart"));

        let installer_src = include_str!("../../singularity-installer/src/main.rs");
        assert!(installer_src.contains("planned_restart.flag"));
        assert!(installer_src.contains("terminated_live"));
    }

    #[test]
    fn test_v206_extension_popups_persistence_bookmarks_and_navigation() {
        let tmp_dir = std::env::temp_dir().join(format!(
            "singularity_v206_test_{}_{}",
            std::process::id(),
            roaming_store::unix_now()
        ));
        let _ = std::fs::remove_dir_all(&tmp_dir);

        // 1. Extension runtime ID lookup resolves from CEF's `cef-profile/Default/Preferences`
        let ext_dir = tmp_dir.join("extensions").join("my_cashback_ext");
        let cef_def = tmp_dir.join("cef-profile").join("Default");
        std::fs::create_dir_all(&ext_dir).expect("create ext dir");
        std::fs::create_dir_all(&cef_def).expect("create cef profile dir");
        std::fs::write(
            ext_dir.join("manifest.json"),
            r#"{
                "manifest_version": 3,
                "name": "Cashback Helper",
                "version": "1.2.3",
                "action": { "default_popup": "popup.html" },
                "host_permissions": [
                    "https://*.cashback-example.com/*",
                    "<all_urls>",
                    "*://*/*"
                ],
                "homepage_url": "https://portal.cashback-example.org/login"
            }"#,
        )
        .expect("write manifest");
        std::fs::write(ext_dir.join("popup.html"), "<html><body>Popup</body></html>")
            .expect("write popup");
        let rt_id = "abcdefghijklmnopabcdefghijklmnop";
        std::fs::write(
            cef_def.join("Preferences"),
            serde_json::json!({
                "extensions": {
                    "settings": {
                        rt_id: {
                            "path": ext_dir.to_string_lossy().to_string(),
                            "manifest": { "name": "Cashback Helper" }
                        }
                    }
                }
            })
            .to_string(),
        )
        .expect("write CEF Preferences");

        let resolved =
            extensions::find_runtime_extension_id(&tmp_dir, &ext_dir, "my_cashback_ext", "Cashback Helper");
        assert_eq!(resolved.as_deref(), Some(rt_id));

        // 2. Extension host domain extraction collects concrete host_permissions & excludes homepage_url/wildcards (N3 #25)
        extensions::invalidate_extensions_cache();
        let ext_domains = extensions::collect_installed_extension_host_domains(&tmp_dir);
        assert!(ext_domains.contains(&"cashback-example.com".to_string()));
        assert!(!ext_domains.contains(&"portal.cashback-example.org".to_string()));
        assert!(!ext_domains.iter().any(|d| d.contains('*') || d == "<all_urls>"));
        assert!(extensions::host_matches_extension_domains(
            "api.cashback-example.com",
            &ext_domains
        ));
        assert!(!extensions::host_matches_extension_domains(
            "doubleclick.net",
            &ext_domains
        ));

        // 3. Expanded auth cookie protection protects extension/site login tokens while keeping trackers blocked
        for (dom, name) in [
            (".bitwarden.com", "bw_refresh_token"),
            (".proton.me", "jwt_access"),
            (".example.org", "remember_user_id"),
            (".cashback-example.com", "logged_in_member"),
            (".vault.example.com", "oauth_bearer"),
        ] {
            assert!(
                is_protected_session_or_functional_cookie(dom, name),
                "expected auth cookie {} on {} to be protected",
                name,
                dom
            );
            assert_eq!(
                classify_tracker_or_malicious_cookie(dom, name, "valid_secret_value"),
                None
            );
        }
        assert_eq!(
            classify_tracker_or_malicious_cookie(".example.com", "_ga", "GA1.1.12345"),
            Some(CookieThreatKind::Tracker)
        );
        assert_eq!(
            classify_tracker_or_malicious_cookie(".example.com", "_fbp", "fb.1.12345"),
            Some(CookieThreatKind::Advertising)
        );
        assert_eq!(
            classify_tracker_or_malicious_cookie(".example.com", "_hjsession_123", "abc"),
            Some(CookieThreatKind::Tracker)
        );
        assert_eq!(
            classify_tracker_or_malicious_cookie(".doubleclick.net", "IDE", "abc"),
            Some(CookieThreatKind::Advertising)
        );

        let _ = std::fs::remove_dir_all(&tmp_dir);

        // 4. Verify UI & runtime invariants for all 5 v2.0.6 fixes/features
        assert!(SINGULARITY_UI_HTML.contains("id=\"ntp-bookmarks-bar\""));
        assert!(SINGULARITY_UI_HTML.contains("id=\"bm-file-input\""));
        assert!(SINGULARITY_UI_HTML.contains("/api/bookmarks/import-file"));
        assert!(SINGULARITY_UI_HTML.contains("/api/bookmarks/export-html"));
        assert!(SINGULARITY_UI_HTML.contains("id=\"btn-nav-back\""));
        assert!(SINGULARITY_UI_HTML.contains("id=\"btn-nav-fwd\""));
        assert!(SINGULARITY_UI_HTML.contains("e.button === 3"));
        assert!(SINGULARITY_UI_HTML.contains("e.button === 4"));
        assert!(SINGULARITY_UI_HTML.contains("nav_to_home"));
        assert!(SINGULARITY_UI_HTML.contains("nav_restore_web"));

        let server_src = include_str!("server.rs");
        assert!(server_src.contains("struct ExtPopupState"));
        assert!(server_src.contains("fn is_win32_focus_inside_popup"));
        assert!(server_src.contains("struct TabNavHistory"));
        assert!(server_src.contains("fn perform_tab_go_back"));
        assert!(server_src.contains("fn perform_tab_go_forward"));
        assert!(server_src.contains("fn perform_tab_zoom"));
        assert!(server_src.contains("MouseButton::Other(xbtn)"));
        assert!(server_src.contains("VK_XBUTTON1"));
        assert!(server_src.contains("VK_XBUTTON2"));
        assert!(server_src.contains("/api/bookmarks/import-file"));
        assert!(server_src.contains("/api/bookmarks/export-html"));

        let cef_src = include_str!("cef_runtime.rs");
        assert!(cef_src.contains("cookieable_schemes_list"));
        assert!(cef_src.contains("chrome-extension"));
        assert!(!cef_src.contains("\"disable-background-networking\""));
        assert!(cef_src.contains("collect_installed_extension_host_domains"));
        assert!(cef_src.contains("flush_store"));
        assert!(cef_src.contains("SingularityKeyboardHandler"));
        assert!(cef_src.contains("on_loading_state_change"));
        assert!(cef_src.contains("pub fn zoom_step"));
    }

    #[test]
    fn test_v207_manifest_json_local_extension_loading_and_restart() {
        let tmp_dir = std::env::temp_dir().join(format!(
            "singularity_v207_manifest_ext_{}_{}",
            std::process::id(),
            roaming_store::unix_now()
        ));
        let _ = std::fs::remove_dir_all(&tmp_dir);
        let roaming = tmp_dir.join("roaming");
        std::fs::create_dir_all(&roaming).expect("mkdir roaming");

        // 1. Direct path to manifest.json inside an unpacked extension folder (with spaces + .git)
        let ext_src = tmp_dir.join("My Cool Extension");
        std::fs::create_dir_all(ext_src.join("icons")).expect("mkdir icons");
        std::fs::create_dir_all(ext_src.join(".git")).expect("mkdir .git");
        std::fs::write(ext_src.join(".git").join("HEAD"), "ref: refs/heads/main\n")
            .expect("write .git/HEAD");
        std::fs::write(ext_src.join("popup.html"), "<html><body>Hi</body></html>")
            .expect("write popup");
        std::fs::write(ext_src.join("icons").join("icon16.png"), b"\x89PNG\r\n\x1a\n")
            .expect("write icon");
        let manifest_path = ext_src.join("manifest.json");
        std::fs::write(
            &manifest_path,
            "\u{feff}{\"manifest_version\":3,\"name\":\"Manifest Direct Ext\",\"version\":\"1.2.3\",\"action\":{\"default_popup\":\"popup.html\"},\"icons\":{\"16\":\"icons/icon16.png\"}}",
        )
        .expect("write manifest.json");

        let info = extensions::install_from_local_path(
            &roaming,
            &format!("\"{}\"", manifest_path.display()),
            None,
            &[],
        )
        .expect("install from quoted manifest.json path");
        assert_eq!(info.name, "Manifest Direct Ext");
        assert_eq!(info.version, "1.2.3");
        assert_eq!(info.popup_path.as_deref(), Some("popup.html"));
        let installed_dir = roaming.join("extensions").join(&info.id);
        assert!(installed_dir.join("manifest.json").is_file());
        assert!(installed_dir.join("popup.html").is_file());
        assert!(installed_dir.join("icons").join("icon16.png").is_file());
        assert!(
            !installed_dir.join(".git").exists(),
            ".git directory must be skipped when copying unpacked extensions"
        );

        // 2. Re-picking the already-installed manifest.json must NOT self-delete
        let re_info = extensions::install_from_local_path(
            &roaming,
            &installed_dir.join("manifest.json").to_string_lossy(),
            None,
            &[],
        )
        .expect("re-installing same manifest.json must succeed safely");
        assert_eq!(re_info.id, info.id);
        assert!(installed_dir.join("manifest.json").is_file());

        // 3. file:/// URI with %20 encoded spaces loads cleanly
        let uri = format!(
            "file:///{}",
            manifest_path
                .to_string_lossy()
                .trim_start_matches('/')
                .replace('\\', "/")
                .replace(' ', "%20")
        );
        let uri_info = extensions::install_from_local_path(&roaming, &uri, None, &[])
            .expect("install from file:/// manifest.json URI");
        assert_eq!(uri_info.name, "Manifest Direct Ext");

        // 4. Standalone renamed manifest inside Downloads copies ONLY manifest + referenced files
        let downloads_dir = tmp_dir.join("Downloads");
        std::fs::create_dir_all(downloads_dir.join("scripts")).expect("mkdir downloads/scripts");
        std::fs::write(downloads_dir.join("unrelated_movie.bin"), b"DO_NOT_COPY")
            .expect("write unrelated file");
        std::fs::write(downloads_dir.join("scripts").join("inject.js"), b"console.log(1);")
            .expect("write referenced script");
        let renamed_manifest = downloads_dir.join("manifest (1).json");
        std::fs::write(
            &renamed_manifest,
            r#"{"manifest_version":3,"name":"Downloads Manifest Only","version":"0.9.0","content_scripts":[{"matches":["<all_urls>"],"js":["./scripts/inject.js"]}]}"#,
        )
        .expect("write manifest (1).json");

        let dl_info = extensions::install_from_local_path(
            &roaming,
            &renamed_manifest.to_string_lossy(),
            None,
            &[],
        )
        .expect("install standalone manifest (1).json from Downloads");
        assert_eq!(dl_info.name, "Downloads Manifest Only");
        let dl_installed = roaming.join("extensions").join(&dl_info.id);
        assert!(dl_installed.join("manifest.json").is_file());
        assert!(dl_installed.join("scripts").join("inject.js").is_file());
        assert!(
            !dl_installed.join("unrelated_movie.bin").exists(),
            "Unrelated files in Downloads must NEVER be copied!"
        );

        // 5. Invalid JSON and non-manifest JSON files are rejected with clear errors
        let bad_manifest = tmp_dir.join("bad_ext").join("manifest.json");
        std::fs::create_dir_all(bad_manifest.parent().unwrap()).expect("mkdir bad_ext");
        std::fs::write(&bad_manifest, "{ not valid json").expect("write bad json");
        let err_bad = extensions::install_from_local_path(
            &roaming,
            &bad_manifest.to_string_lossy(),
            None,
            &[],
        )
        .unwrap_err();
        assert!(err_bad.contains("Invalid manifest.json JSON syntax"));

        let pkg_json = tmp_dir.join("bad_ext").join("package.json");
        std::fs::write(&pkg_json, r#"{"name":"not-an-ext","version":"1.0.0"}"#)
            .expect("write package.json");
        let err_pkg = extensions::install_from_local_path(
            &roaming,
            &pkg_json.to_string_lossy(),
            None,
            &[],
        )
        .unwrap_err();
        assert!(err_pkg.contains("manifest_version"));

        // 6. .zip archive with __MACOSX + single root folder unwraps cleanly
        let zip_path = tmp_dir.join("wrapped_ext.zip");
        {
            let file = std::fs::File::create(&zip_path).expect("create zip");
            let mut zw = zip::ZipWriter::new(file);
            let opts = zip::write::SimpleFileOptions::default();
            zw.start_file("__MACOSX/._manifest.json", opts).unwrap();
            std::io::Write::write_all(&mut zw, b"mac-junk").unwrap();
            zw.start_file("wrapper-dir/manifest.json", opts).unwrap();
            std::io::Write::write_all(
                &mut zw,
                br#"{"manifest_version":3,"name":"Zip Wrapped Ext","version":"2.0.0"}"#,
            )
            .unwrap();
            zw.finish().unwrap();
        }
        let zip_info = extensions::install_from_local_path(
            &roaming,
            &zip_path.to_string_lossy(),
            None,
            &[],
        )
        .expect("install wrapped zip with __MACOSX");
        assert_eq!(zip_info.name, "Zip Wrapped Ext");

        let _ = std::fs::remove_dir_all(&tmp_dir);

        // 7. Verify UI, IPC, Win32 picker, and clean --wait-pid restart invariants
        assert_eq!(env!("CARGO_PKG_VERSION"), "3.0.4");
        assert!(SINGULARITY_UI_HTML.contains("v3.0.4"));
        assert!(SINGULARITY_UI_HTML.contains("id=\"btn-pick-ext-file\""));
        assert!(SINGULARITY_UI_HTML.contains("id=\"btn-pick-ext-folder\""));
        assert!(SINGULARITY_UI_HTML.contains("id=\"ext-restart-banner\""));
        assert!(SINGULARITY_UI_HTML.contains("id=\"btn-ext-restart-now\""));
        assert!(SINGULARITY_UI_HTML.contains("picked_local_ext_path"));
        assert!(SINGULARITY_UI_HTML.contains("pick_local_extension_path"));
        assert!(SINGULARITY_UI_HTML.contains("restart_browser"));

        let server_src = include_str!("server.rs");
        assert!(server_src.contains("fn pick_win32_extension_file"));
        assert!(server_src.contains("fn pick_win32_extension_folder"));
        assert!(server_src.contains("PickLocalExtensionPath"));
        assert!(server_src.contains("RestartBrowser"));
        assert!(server_src.contains("LocalExtensionPicked"));

        let main_src = include_str!("main.rs");
        assert!(main_src.contains("--wait-pid"));
    }

    #[test]
    fn test_v208_stable_tabs_update_progress_and_dynamic_extensions() {
        let tmp_dir = std::env::temp_dir().join(format!(
            "singularity_v208_test_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&tmp_dir);
        let roaming = tmp_dir.join("roaming");
        let src_dir = tmp_dir.join("dev-ext");
        std::fs::create_dir_all(&src_dir).expect("create dev-ext");

        // 1. Install local extension from manifest.json -> persists source_path
        let manifest_path = src_dir.join("manifest.json");
        std::fs::write(
            &manifest_path,
            r#"{"manifest_version":3,"name":"Dev Hot Reload Ext","version":"1.0.0","action":{"default_popup":"popup.html"}}"#,
        )
        .unwrap();
        std::fs::write(src_dir.join("popup.html"), "<html>v1</html>").unwrap();

        let info1 = extensions::install_from_local_path(
            &roaming,
            &manifest_path.to_string_lossy(),
            None,
            &[],
        )
        .expect("install local manifest.json");
        assert_eq!(info1.version, "1.0.0");
        assert!(info1.source_path.is_some());

        // Persist a simulated live Chromium 32-char runtime_id from Extensions.loadUnpacked
        let fake_rt_id = "abcdefghijklmnopabcdefghijklmnop";
        extensions::save_extension_runtime_id(&roaming, &info1.id, fake_rt_id);
        let (popup_url, popup_name) =
            extensions::resolve_extension_runtime_url(&roaming, &info1.id, false)
                .expect("resolve popup url from persisted runtime_id");
        assert_eq!(popup_url, format!("chrome-extension://{}/popup.html", fake_rt_id));
        assert_eq!(popup_name, "Dev Hot Reload Ext");

        // 2. Edit original source files and call refresh_installed_extension -> re-copies & keeps runtime_id
        std::fs::write(
            &manifest_path,
            r#"{"manifest_version":3,"name":"Dev Hot Reload Ext","version":"1.2.0","action":{"default_popup":"popup.html"}}"#,
        )
        .unwrap();
        std::fs::write(src_dir.join("popup.html"), "<html>v1.2</html>").unwrap();

        let info2 = extensions::refresh_installed_extension(&roaming, &info1.id, &[])
            .expect("refresh installed extension from source");
        assert_eq!(info2.version, "1.2.0");
        assert_eq!(info2.runtime_id.as_deref(), Some(fake_rt_id));
        let copied_popup = std::fs::read_to_string(
            extensions::enabled_extensions_dir(&roaming)
                .join(&info1.id)
                .join("popup.html"),
        )
        .unwrap();
        assert_eq!(copied_popup, "<html>v1.2</html>");

        // 3. Refreshing a disabled extension refreshes files while keeping it disabled
        extensions::set_extension_enabled(&roaming, &info1.id, false).expect("disable ext");
        std::fs::write(
            &manifest_path,
            r#"{"manifest_version":3,"name":"Dev Hot Reload Ext","version":"1.3.0","action":{"default_popup":"popup.html"}}"#,
        )
        .unwrap();
        let info3 = extensions::refresh_installed_extension(&roaming, &info1.id, &[])
            .expect("refresh disabled ext");
        assert!(!info3.enabled);
        assert_eq!(info3.version, "1.3.0");

        // 4. Removing extension cleans up extensions_meta/<id>.json
        extensions::remove_extension(&roaming, &info1.id).expect("remove ext");
        let meta_after = extensions::read_extension_meta(&roaming, &info1.id);
        assert!(meta_after.source_path.is_none());
        assert!(meta_after.runtime_id.is_none());

        let _ = std::fs::remove_dir_all(&tmp_dir);

        // 5. Updater progress snapshot serializes cleanly
        let prog = updater::get_update_progress();
        let prog_json = serde_json::to_value(&prog).expect("serialize UpdateProgressSnapshot");
        assert!(prog_json.get("phase").is_some());
        assert!(prog_json.get("downloaded_bytes").is_some());
        assert!(prog_json.get("total_bytes").is_some());
        assert!(prog_json.get("percent").is_some());
        assert!(prog_json.get("speed_bps").is_some());

        // 6. Verify v3.0.1 UI, tab-stability, update progress bar, and zero-restart dynamic extension invariants
        assert_eq!(env!("CARGO_PKG_VERSION"), "3.0.4");
        assert!(SINGULARITY_UI_HTML.contains("v3.0.4"));
        assert!(SINGULARITY_UI_HTML.contains("if ((ev.buttons & 1) === 0)"));
        assert!(SINGULARITY_UI_HTML.contains("window.addEventListener(\"pointerup\""));
        assert!(SINGULARITY_UI_HTML.contains("lostpointercapture"));
        assert!(SINGULARITY_UI_HTML.contains("flex: 0 1 172px;"));
        assert!(SINGULARITY_UI_HTML.contains("width: 172px;"));
        assert!(!SINGULARITY_UI_HTML.contains("|| strip.scrollWidth > strip.clientWidth + 4"));
        assert!(SINGULARITY_UI_HTML.contains("id=\"update-progress-wrap\""));
        assert!(SINGULARITY_UI_HTML.contains("id=\"update-progress-bar-fill\""));
        assert!(SINGULARITY_UI_HTML.contains("id=\"update-floating-bar\""));
        assert!(SINGULARITY_UI_HTML.contains("id=\"topbar-update-line\""));
        assert!(SINGULARITY_UI_HTML.contains("/api/updater/progress"));
        assert!(SINGULARITY_UI_HTML.contains("startUpdateProgressPolling"));
        assert!(SINGULARITY_UI_HTML.contains("/api/extensions/reload"));
        assert!(SINGULARITY_UI_HTML.contains("reloadExtensionUI"));
        assert!(SINGULARITY_UI_HTML.contains("hideExtensionRestartBanner"));
        assert!(SINGULARITY_UI_HTML.contains("reload_ext"));

        let server_src = include_str!("server.rs");
        assert!(server_src.contains("\"/api/updater/progress\""));
        assert!(server_src.contains("\"/api/extensions/reload\""));
        assert!(server_src.contains("init_and_sync_dynamic_extensions_cef"));
        assert!(server_src.contains("dynamic_ext_ok"));
        assert!(server_src.contains("Some(\"reload_ext\")"));

        let cef_src = include_str!("cef_runtime.rs");
        assert!(cef_src.contains("remote-debugging-pipe"));
        assert!(cef_src.contains("remote-debugging-io-pipes"));
        assert!(cef_src.contains("enable-unsafe-extension-debugging"));
        assert!(cef_src.contains("Extensions.loadUnpacked"));
        assert!(cef_src.contains("Extensions.uninstall"));
    }

    #[test]
    fn test_windows_updater_and_cef_renderer_stability_invariants() {
        // 1. Official Win32 WINHTTP_OPTION_CONNECTION_INFO must be 93 (not invalid 120),
        //    otherwise every Windows update check / download fails with ERROR_WINHTTP_INVALID_OPTION.
        assert_eq!(winhttp_client::WINHTTP_OPTION_CONNECTION_INFO, 93);

        // 2. Windows MSVC binary must reserve an 8 MiB stack so CEF renderer subprocesses do not
        //    hit STATUS_STACK_OVERFLOW (`status=2, code=-36861, Crashpad_NotConnectedToHandler`).
        let build_src = include_str!("../build.rs");
        assert!(build_src.contains("/STACK:0x800000"));
        assert!(build_src.contains("/DEPENDENTLOADFLAG:0x800"));

        // 3. CEF Alloy runtime must disable RenderDocument alongside BackForwardCache (cef#4348)
        //    and guard frame validity before accessing frame URLs or executing JS in renderer.
        let cef_src = include_str!("cef_runtime.rs");
        assert!(cef_src.contains("BackForwardCache,RenderDocument,"));
        assert!(cef_src.contains("if frame.is_valid() == 0"));

        // 4. Web tabs and extension popups must not inject dead JS scripts referencing removed window.ipc,
        //    and RenderProcessTerminated must ignore closed tabs and support single-shot tab reload.
        let server_src = include_str!("server.rs");
        assert!(!server_src.contains("CONTENT_LINK_INTENT_SCRIPT"));
        assert!(!server_src.contains("EXT_POPUP_INIT_SCRIPT"));
        assert!(server_src.contains("tab_crash_recoveries"));

        // 5. WebGL renderSolarOrEclipse uses a structured single-return variable (zero ANGLE HLSL X4000).
        assert!(SINGULARITY_UI_HTML.contains("vec3 result = vec3(0.0);"));
        assert!(SINGULARITY_UI_HTML.contains("return result;"));
    }

    #[test]
    fn test_v300_master_roadmap_full_10_domain_api_and_shell_integration() {
        use crate::server::ParsedHttpRequest;
        use std::collections::HashMap;
        use std::sync::{Arc, Mutex};
        use zeroize::Zeroizing;

        let tmp_dir = std::env::temp_dir().join(format!(
            "singularity_v300_e2e_test_{}_{}",
            std::process::id(),
            roaming_store::unix_now()
        ));
        let _ = std::fs::remove_dir_all(&tmp_dir);

        // 1. Hermetic shell launch wires all 27 subsystems across the 11 workspace crates
        let shell = SingularityBrowserShell::launch_at_dir(tmp_dir.clone())
            .expect("launch isolated v3.0 shell");
        assert!(shell.core.settings.len() >= 2500);
        assert!(shell.flags.len() >= 40);
        assert!(shell.commands.len() >= 80);
        assert_eq!(shell.cast_controller.active_socket_count(), 0);
        assert!(shell.sync_engine.is_none());

        let shell_arc = Arc::new(Mutex::new(shell));

        let call_get = |path: &str, query: &[(&str, &str)]| -> (String, serde_json::Value) {
            let mut params = HashMap::new();
            for (k, v) in query {
                params.insert((*k).to_string(), (*v).to_string());
            }
            let req = ParsedHttpRequest {
                method: "GET".to_string(),
                path: path.to_string(),
                query: String::new(),
                headers: HashMap::new(),
                body: Zeroizing::new(Vec::new()),
            };
            let resp = api_v3::try_handle_v3_route(&req, &params, &shell_arc)
                .unwrap_or_else(|| panic!("GET {} was not routed", path));
            let val: serde_json::Value =
                serde_json::from_slice(&resp.body).unwrap_or(serde_json::Value::Null);
            (resp.status.to_string(), val)
        };

        let call_post = |path: &str, payload: serde_json::Value| -> (String, serde_json::Value) {
            let req = ParsedHttpRequest {
                method: "POST".to_string(),
                path: path.to_string(),
                query: String::new(),
                headers: HashMap::new(),
                body: Zeroizing::new(serde_json::to_vec(&payload).expect("serialize payload")),
            };
            let resp = api_v3::try_handle_v3_route(&req, &HashMap::new(), &shell_arc)
                .unwrap_or_else(|| panic!("POST {} was not routed", path));
            let val: serde_json::Value =
                serde_json::from_slice(&resp.body).unwrap_or(serde_json::Value::Null);
            (resp.status.to_string(), val)
        };

        // Domain 8: Internal browser:// pages + flags + version + process manager
        for slug in ["urls", "flags", "version", "process-manager", "net-internals", "components", "crashes", "policy"] {
            let page = api_v3::handle_browser_internal_page(slug, &shell_arc, "tok_test_v3");
            assert_eq!(page.status, "200 OK", "browser://{} must render 200 OK", slug);
            let html = String::from_utf8_lossy(&page.body);
            assert!(html.contains("<html"), "browser://{} must output HTML", slug);
            assert!(
                page.extra_headers
                    .iter()
                    .any(|(k, v)| *k == "X-Frame-Options" && v == "SAMEORIGIN")
            );
        }
        let missing_page = api_v3::handle_browser_internal_page("does-not-exist", &shell_arc, "tok");
        assert_eq!(missing_page.status, "404 Not Found");

        let (st, urls_json) = call_get("/api/internal/urls", &[]);
        assert_eq!(st, "200 OK");
        assert!(urls_json["pages"].as_array().unwrap().len() >= 25);

        let (st, flags_json) = call_get("/api/internal/flags", &[]);
        assert_eq!(st, "200 OK");
        let first_flag_id = flags_json["flags"][0]["id"].as_str().unwrap().to_string();
        let (st, set_flag_json) = call_post(
            "/api/flags/set",
            serde_json::json!({ "id": first_flag_id, "option_index": 1 }),
        );
        assert_eq!(st, "200 OK");
        assert_eq!(set_flag_json["ok"], true);
        let (st, reset_json) = call_post("/api/flags/reset_all", serde_json::json!({}));
        assert_eq!(st, "200 OK");
        assert_eq!(reset_json["ok"], true);

        // Domain 2: History, Omnibox unified search + calculator + QR SVG, Search Engines
        let (st, rec_json) = call_post(
            "/api/history/record",
            serde_json::json!({
                "url": "https://www.rust-lang.org/learn",
                "title": "Learn Rust",
                "typed": true
            }),
        );
        assert_eq!(st, "200 OK");
        assert_eq!(rec_json["ok"], true);

        let (st, hist_json) = call_get("/api/history/query", &[("q", "rust")]);
        assert_eq!(st, "200 OK");
        assert!(!hist_json["items"].as_array().unwrap().is_empty());

        let (st, omni_calc) = call_get("/api/omnibox/suggest", &[("q", "21 * 2")]);
        assert_eq!(st, "200 OK");
        assert!(omni_calc.to_string().contains("42"));

        let (st, qr_json) = call_get("/api/omnibox/qr", &[("data", "https://github.com/MyMasha/Singularity")]);
        assert_eq!(st, "200 OK");
        assert!(qr_json["svg"].as_str().unwrap().contains("<svg"));

        let (st, engines_json) = call_get("/api/search_engines/list", &[]);
        assert_eq!(st, "200 OK");
        assert!(!engines_json["engines"].as_array().unwrap().is_empty());

        // Domain 3: Bookmarks tree + undo/redo + Reading List + Reader Mode + Page Tools
        let (st, bm_add) = call_post(
            "/api/bookmarks/add",
            serde_json::json!({
                "title": "Singularity Repo",
                "url": "https://github.com/MyMasha/Singularity",
                "tags": ["rust", "browser"]
            }),
        );
        assert_eq!(st, "200 OK");
        assert_eq!(bm_add["ok"], true);
        let (st, bm_tree) = call_get("/api/bookmarks/tree", &[]);
        assert_eq!(st, "200 OK");
        assert!(!bm_tree["children"].as_array().unwrap().is_empty());
        let (st, undo_json) = call_post("/api/bookmarks/undo", serde_json::json!({}));
        assert_eq!(st, "200 OK");
        assert_eq!(undo_json["ok"], true);
        let (st, redo_json) = call_post("/api/bookmarks/redo", serde_json::json!({}));
        assert_eq!(st, "200 OK");
        assert_eq!(redo_json["ok"], true);

        let (st, rl_add) = call_post(
            "/api/reading_list/add",
            serde_json::json!({
                "url": "https://doc.rust-lang.org/book/",
                "title": "The Rust Book",
                "html": "<article><h1>The Rust Book</h1><p>Memory safety without garbage collection across systems programming workloads.</p></article>"
            }),
        );
        assert_eq!(st, "200 OK");
        assert_eq!(rl_add["ok"], true);

        let (st, reader_json) = call_post(
            "/api/reader/extract",
            serde_json::json!({
                "url": "https://example.org/article",
                "html": "<html><body><article><h1>OLED Reader</h1><p>Singularity Reader Mode renders distraction-free typography on true black displays for extended reading sessions.</p></article></body></html>",
                "theme": "oled"
            }),
        );
        assert_eq!(st, "200 OK");
        assert!(reader_json["html"].as_str().unwrap().contains("OLED Reader"));

        let (st, copy_json) = call_post(
            "/api/page_tools/smart_copy",
            serde_json::json!({
                "title": "Singularity",
                "url": "https://github.com/MyMasha/Singularity",
                "format": "markdown"
            }),
        );
        assert_eq!(st, "200 OK");
        assert!(copy_json["output"].as_str().unwrap().contains("[Singularity]"));

        // Domain 4: Shields per-site policy, threat check, granular permissions, DoH presets
        let (st, sh_set) = call_post(
            "/api/shields/site_policy",
            serde_json::json!({
                "site": "tracker.example.com",
                "adblock_level": "aggressive",
                "fingerprint_level": "strict",
                "forgetful_browsing": true
            }),
        );
        assert_eq!(st, "200 OK");
        assert_eq!(sh_set["ok"], true);

        let (st, threat_json) = call_post(
            "/api/shields/threat_check",
            serde_json::json!({ "url": "https://www.rust-lang.org/" }),
        );
        assert_eq!(st, "200 OK");
        assert_eq!(threat_json["is_safe"], true);

        let (st, perm_set) = call_post(
            "/api/permissions/set",
            serde_json::json!({
                "origin": "https://meet.example.com",
                "kind": "camera",
                "decision": "allow"
            }),
        );
        assert_eq!(st, "200 OK");
        assert_eq!(perm_set["ok"], true);
        let (st, perm_list) = call_get("/api/permissions/list", &[("origin", "https://meet.example.com")]);
        assert_eq!(st, "200 OK");
        assert!(perm_list["grants"].as_object().unwrap().contains_key("camera"));

        let (st, dns_json) = call_get("/api/dns/presets", &[]);
        assert_eq!(st, "200 OK");
        assert!(dns_json["presets"].as_array().unwrap().len() >= 4);

        // Domain 5: Vault password & Diceware passphrase generation
        let (st, pw_json) = call_post(
            "/api/vault/generate",
            serde_json::json!({ "mode": "password", "length": 24, "include_symbols": true }),
        );
        assert_eq!(st, "200 OK");
        assert_eq!(pw_json["secret"].as_str().unwrap().len(), 24);
        let (st, pp_json) = call_post(
            "/api/vault/generate",
            serde_json::json!({ "mode": "passphrase", "words": 5, "language": "fr" }),
        );
        assert_eq!(st, "200 OK");
        assert!(pp_json["entropy_bits"].as_f64().unwrap() > 40.0);

        // Domain 6: Downloads queue, Media DSP 600% EQ, Platform capabilities, Opt-in Cast
        let (st, dl_enq) = call_post(
            "/api/downloads/enqueue",
            serde_json::json!({
                "url": "https://github.com/MyMasha/Singularity/releases/download/v3.0.1/singularity.zip",
                "filename": "singularity.zip",
                "total_bytes": 1048576
            }),
        );
        assert_eq!(st, "200 OK");
        let dl_id = dl_enq["id"].as_u64().unwrap();
        let (st, dl_list) = call_get("/api/downloads/list", &[]);
        assert_eq!(st, "200 OK");
        assert!(!dl_list["records"].as_array().unwrap().is_empty());
        let (st, dl_pause) = call_post(
            "/api/downloads/action",
            serde_json::json!({ "id": dl_id, "action": "pause" }),
        );
        assert_eq!(st, "200 OK");
        assert_eq!(dl_pause["ok"], true);

        let (st, eq_json) = call_post(
            "/api/media/equalizer",
            serde_json::json!({ "volume_boost_percent": 600.0, "preset": "cinema" }),
        );
        assert_eq!(st, "200 OK");
        assert!((eq_json["volume_boost_percent"].as_f64().unwrap() - 600.0).abs() < 0.01);

        let (st, cast_json) = call_get("/api/cast/status", &[]);
        assert_eq!(st, "200 OK");
        assert_eq!(cast_json["discovery_active"], false);
        assert_eq!(cast_json["active_sockets"], 0);

        // Domain 7: Userscripts, PWA registry, Extensions helpers
        let (st, us_inst) = call_post(
            "/api/userscripts/install",
            serde_json::json!({
                "source": "// ==UserScript==\n// @name OLED Helper\n// @match https://example.org/*\n// @version 1.0\n// ==/UserScript==\nconsole.log('ok');\n"
            }),
        );
        assert_eq!(st, "200 OK");
        assert_eq!(us_inst["ok"], true);
        let (st, us_list) = call_get("/api/userscripts/list", &[]);
        assert_eq!(st, "200 OK");
        assert_eq!(us_list["scripts"].as_array().unwrap().len(), 1);

        let (st, pwa_inst) = call_post(
            "/api/pwa/install",
            serde_json::json!({
                "url": "https://app.example.org/",
                "title": "Example OLED App",
                "theme_color": "#000000"
            }),
        );
        assert_eq!(st, "200 OK");
        assert_eq!(pwa_inst["ok"], true);
        let (st, pwa_list) = call_get("/api/pwa/list", &[]);
        assert_eq!(st, "200 OK");
        assert_eq!(pwa_list["apps"].as_array().unwrap().len(), 1);

        // Domain 1 & 9: Tab organizer, Performance profiles, Mullvad relay filter & DNS blocker
        let (st, perf_json) = call_post(
            "/api/performance/profile",
            serde_json::json!({ "preset": "gaming" }),
        );
        assert_eq!(st, "200 OK");
        assert_eq!(perf_json["ok"], true);

        let (st, relays_json) = call_get("/api/mullvad/relays_filtered", &[("owned", "true")]);
        assert_eq!(st, "200 OK");
        assert!(!relays_json["relays"].as_array().unwrap().is_empty());

        let (st, m_dns) = call_post(
            "/api/mullvad/dns_blocker",
            serde_json::json!({
                "block_ads": true,
                "block_trackers": true,
                "block_malware": true,
                "block_adult": false,
                "block_gambling": false,
                "block_social": false
            }),
        );
        assert_eq!(st, "200 OK");
        assert_eq!(m_dns["dns_ip"], "100.64.0.7");

        // Domain 10: Multi-profiles, Command Palette, Offline Translate, Zero-Knowledge Sync Chain
        let (st, prof_create) = call_post(
            "/api/profiles/create",
            serde_json::json!({ "name": "Work Vault", "color": "#00D4FF" }),
        );
        assert_eq!(st, "200 OK");
        assert_eq!(prof_create["ok"], true);

        let (st, pal_json) = call_get("/api/palette/query", &[("q", "reader")]);
        assert_eq!(st, "200 OK");
        assert!(!pal_json["commands"].as_array().unwrap().is_empty());

        let (st, tr_det) = call_post(
            "/api/translate/detect",
            serde_json::json!({ "text": "Bonjour, bienvenue dans le navigateur Singularity avec confidentialité totale." }),
        );
        assert_eq!(st, "200 OK");
        assert_eq!(tr_det["language"], "fr");

        let (st, tr_batch) = call_post(
            "/api/translate/batch",
            serde_json::json!({
                "source_lang": "en",
                "target_lang": "fr",
                "segments": ["Hello world"]
            }),
        );
        assert_eq!(st, "200 OK");
        assert_eq!(tr_batch["ok"], true);

        let (st, sync_create) = call_post(
            "/api/sync/create_chain",
            serde_json::json!({ "device_name": "Singularity Test Node" }),
        );
        assert_eq!(st, "200 OK");
        assert_eq!(sync_create["ok"], true);
        assert_eq!(
            sync_create["permanent_24_words"]
                .as_str()
                .unwrap()
                .split_whitespace()
                .count(),
            24
        );
        assert_eq!(
            sync_create["daily_25_words"]
                .as_str()
                .unwrap()
                .split_whitespace()
                .count(),
            25
        );
        let (st, sync_st) = call_get("/api/sync/status", &[]);
        assert_eq!(st, "200 OK");
        assert_eq!(sync_st["linked"], true);
        let (st, sync_leave) = call_post("/api/sync/leave_chain", serde_json::json!({}));
        assert_eq!(st, "200 OK");
        assert_eq!(sync_leave["ok"], true);

        // 2. Verify new extensions.rs & drm_webview.rs helpers
        assert_eq!(
            extensions::parse_edge_addons_id(
                "https://microsoftedge.microsoft.com/addons/detail/ublock-origin/odfafepnkmbhccpbejgmiehpchacaeak"
            )
            .as_deref(),
            Some("odfafepnkmbhccpbejgmiehpchacaeak")
        );
        let perm_warnings = extensions::describe_extension_permissions(
            &["tabs".into(), "cookies".into()],
            &["<all_urls>".into()],
        );
        assert!(perm_warnings.len() >= 2);
        let omaha_xml = r#"<?xml version="1.0"?><gupdate><app appid="cjpalhdlnbpafiamejdnhcphjbkeiagm"><updatecheck codebase="https://clients2.googleusercontent.com/crx/ext.crx" version="1.62.0"/></app></gupdate>"#;
        let updates = extensions::parse_omaha_update_xml(omaha_xml);
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].version, "1.62.0");

        extensions::set_extension_site_access(
            &tmp_dir,
            "cjpalhdlnbpafiamejdnhcphjbkeiagm",
            extensions::SiteAccessMode::OnSpecificSites,
            vec!["https://example.org/*".into()],
        )
        .expect("set site access");
        extensions::set_extension_privacy_flags(
            &tmp_dir,
            "cjpalhdlnbpafiamejdnhcphjbkeiagm",
            Some(true),
            Some(false),
            Some(true),
        )
        .expect("set privacy flags");
        let ext_meta = extensions::read_extension_meta(&tmp_dir, "cjpalhdlnbpafiamejdnhcphjbkeiagm");
        assert_eq!(ext_meta.site_access_mode, extensions::SiteAccessMode::OnSpecificSites);
        assert!(ext_meta.allow_in_incognito);
        assert!(ext_meta.allow_user_scripts);

        let wv_status = drm_webview::inspect_widevine_status(&tmp_dir);
        assert!(!wv_status.cef_widevine_ready);
        assert!(wv_status.supported_vmp_domains_count > 0);

        // 3. Verify v3.0 OLED UI shell & Windows CEF/DRM source-level invariants
        for marker in [
            "id=\"omnibox-dropdown\"",
            "id=\"v3-vertical-rail\"",
            "id=\"v3-sidebar\"",
            "id=\"command-palette-modal\"",
            "id=\"tab-search-modal\"",
            "id=\"find-in-page-bar\"",
            "id=\"v3-popover-panel\"",
            "id=\"v3-internal-frame-modal\"",
            "id=\"pane-profiles\"",
            "id=\"pane-performance\"",
            "id=\"pane-ecosystem\"",
            "id=\"pane-sync\"",
            "id=\"pane-internals\"",
            "initSingularityV3Shell",
            "window.__v3",
        ] {
            assert!(
                SINGULARITY_UI_HTML.contains(marker),
                "SINGULARITY_UI_HTML missing v3.0 element: {}",
                marker
            );
        }
        assert!(!SINGULARITY_UI_HTML.contains("allow-same-origin"));
        assert!(!SINGULARITY_UI_HTML.contains("sessionMasterCache"));

        let drm_src = include_str!("drm_webview.rs");
        assert!(drm_src.contains("OpenDevToolsWindow"));
        assert!(!drm_src.contains("self.webview.open_devtools()"));

        let cef_src = include_str!("cef_runtime.rs");
        assert!(cef_src.contains("create_isolated_request_context"));
        assert!(cef_src.contains("Sec-GPC"));
        assert!(cef_src.contains("NEW_PICTURE_IN_PICTURE"));
        assert!(cef_src.contains("flags.toml"));

        let server_src = include_str!("server.rs");
        assert!(server_src.contains("try_handle_v3_route"));
        assert!(server_src.contains("handle_browser_internal_page"));
        assert!(server_src.contains("compute_pane_rects"));

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_windows_shutdown_sentinel_and_cef_popup_client_invariants() {
        let crash_src = include_str!("crash_guard.rs");
        assert!(crash_src.contains("pub struct Win32ShutdownSentinel"));
        assert!(crash_src.contains("WM_QUERYENDSESSION"));
        assert!(crash_src.contains("WM_ENDSESSION"));
        assert!(crash_src.contains("SingularityShutdownSentinelClass"));

        let server_src = include_str!("server.rs");
        assert!(server_src.contains("Win32ShutdownSentinel::install"));
        assert!(!server_src.contains("SetWindowSubclass"));
        // Verify Event::LoopDestroyed clears running.lock (mark_planned_restart) BEFORE close_cleanly
        let loop_pos = server_src
            .find("Event::LoopDestroyed =>")
            .expect("Event::LoopDestroyed handler");
        let loop_body = &server_src[loop_pos..];
        let mark_pos = loop_body
            .find("mark_planned_restart(&root_dir)")
            .expect("mark_planned_restart inside LoopDestroyed");
        let close_pos = loop_body
            .find("st.close_cleanly()")
            .expect("close_cleanly inside LoopDestroyed");
        assert!(
            mark_pos < close_pos,
            "Event::LoopDestroyed must clear running.lock via mark_planned_restart BEFORE CEF/Win32 teardown"
        );

        let cef_src = include_str!("cef_runtime.rs");
        assert!(cef_src.contains("IPH_ExtensionsZeroStatePromo"));
        assert!(cef_src.contains("wi.runtime_style = RuntimeStyle::ALLOY"));
        assert!(cef_src.contains("ext_popup_cfg"));
        assert!(cef_src.contains("req.referrer_url()"));

        // Satisfying GPU-composited motion & accessibility invariants
        for marker in [
            "--ease-spring:",
            "@keyframes sgTabEnter",
            "@keyframes sgModalPop",
            "@keyframes sgStarPop",
            "@keyframes sgRipple",
            "id=\"v3-load-progress\"",
            "initSingularitySatisfyingMotion",
            "prefers-reduced-motion: reduce",
        ] {
            assert!(
                SINGULARITY_UI_HTML.contains(marker),
                "SINGULARITY_UI_HTML missing motion marker: {}",
                marker
            );
        }
    }

    #[test]
    fn test_two_bar_classic_layout_and_visual_bug_fixes() {
        let server_src = include_str!("server.rs");
        assert!(
            server_src.contains("const APPLE_BAR_LOGICAL_HEIGHT: f64 = 80.0;"),
            "server.rs must set APPLE_BAR_LOGICAL_HEIGHT to 80.0 for the two-bar classic layout"
        );
        assert!(
            server_src.contains("APPLE_BAR_LOGICAL_HEIGHT + st.top_bar_extra_logical_px as f64"),
            "spawn_content_tab must include top_bar_extra_logical_px in initial bar_h"
        );

        // Two-bar classic architecture preserving Singularity OLED cosmic aesthetic
        for marker in [
            "color-scheme: dark;",
            "--tab-row-height: 38px;",
            "--nav-row-height: 42px;",
            "--bar-height: 80px;",
            "--bar-tabstrip-bg:",
            "--bar-toolbar-bg:",
            "class=\"tab-strip-row\"",
            "class=\"nav-toolbar-row\"",
            "id=\"btn-tab-search-chevron\"",
            "id=\"v3-overlay-scrim\"",
            "top: var(--bar-height);",
            "top: calc(var(--bar-height) + 4px);",
            "top: calc(var(--bar-height) + 6px);",
            "body.bar-only #find-in-page-bar",
            "textarea.sheet-search",
            "body.v3-sb-open #settings-modal",
            "function anyOverlayActive()",
            "syncOverlayState",
            "ultra-compact",
            "::-webkit-scrollbar-thumb",
        ] {
            assert!(
                SINGULARITY_UI_HTML.contains(marker),
                "SINGULARITY_UI_HTML missing two-bar/visual-fix marker: {}",
                marker
            );
        }

        // Zero stale hardcoded single-bar 46/48/50px overlay offsets
        assert!(!SINGULARITY_UI_HTML.contains("top: 46px;"));
        assert!(!SINGULARITY_UI_HTML.contains("top: 48px;"));
        assert!(!SINGULARITY_UI_HTML.contains("top: 50px;"));

        // Fluid full-width tab sizing: tabs always expand to fill 100% of available bar width
        // (no artificial 48px/82px/132px max-width caps leaving dead space on wide monitors)
        assert!(SINGULARITY_UI_HTML.contains(".tab-strip-row .tab-pill"));
        assert!(SINGULARITY_UI_HTML.contains("flex: 1 1 220px;"));
        assert!(SINGULARITY_UI_HTML.contains("function syncTabDensityClasses("));
        assert!(!SINGULARITY_UI_HTML.contains("max-width: 48px;"));
        assert!(!SINGULARITY_UI_HTML.contains("max-width: 82px;"));
        assert!(!SINGULARITY_UI_HTML.contains("max-width: 132px;"));
    }
}



