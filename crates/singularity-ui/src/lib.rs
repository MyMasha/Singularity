//! `singularity-ui` — OLED Pure Black (`#000000`) 200Hz+ Native UI Shell,
//! Custom Cursor Engine, Black Hole WGSL Shader, Vim Modal Navigation, and 2,165+ Virtualized Settings UI.

pub mod browser_import;
pub mod cursor;
pub mod extensions;
pub mod roaming_store;
pub mod server;
pub mod shaders;
pub mod shell;
pub mod theme;
pub mod ui_app;
pub mod updater;
pub mod vim;
#[cfg(all(target_os = "windows", not(target_env = "msvc")))]
pub mod webview2_gnu_shim;
pub mod winhttp_client;

pub use browser_import::{
    parse_chromium_bookmarks, parse_chromium_snss_session, parse_firefox_bookmarks_lz4,
    parse_firefox_session, scan_installed_browsers, DetectedBrowserInfo, ImportedBookmark,
    ImportedTab,
};
pub use cursor::{CursorAssetFormat, CursorFormatError, CursorTrailSample, CustomCursorEngine};
pub use roaming_store::{
    apply_media_timestamp_to_url, classify_auth_cookie, classify_tracker_or_malicious_cookie,
    ensure_roaming_dir_initialized, is_protected_session_or_functional_cookie, is_valid_theme_id,
    normalize_url_without_media_time, resolve_roaming_singularity_dir, CookieThreatKind,
    EncryptedAuthTokenRecord, RoamingSingularityStore, SavedTabEntry, SavedTabGroup,
    WindowSessionFile,
};
pub use server::run_interactive_browser_app;
pub use shaders::{BLACK_HOLE_LENSING_WGSL_SHADER, CURSOR_ACCRETION_TRAIL_WGSL_SHADER};
pub use shell::SingularityBrowserShell;
pub use theme::{
    SingularityThemeManifest, TabBarPlacement, ACCRETION_CYAN, ACCRETION_VIOLET, OBSIDIAN_BORDER,
    OLED_PURE_BLACK,
};
pub use ui_app::SINGULARITY_UI_HTML;
pub use updater::{check_for_updates, execute_self_update, execute_uninstall, perform_startup_maintenance};
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
        assert_eq!(roaming_store::tab_unload_timeout_seconds("low", 120), 7 * 24 * 3600);
        assert_eq!(roaming_store::tab_unload_timeout_seconds("medium", 120), 24 * 3600);
        assert_eq!(roaming_store::tab_unload_timeout_seconds("hard", 120), 90 * 60);
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
        // 1. Multi-window session merge: 2 previously open Singularity windows with different
        //    tabs, colliding group IDs, and one shared video at different timestamps MUST combine
        //    into ONE single session with all tabs, remapped groups, and freshest video second!
        let merge_dir = std::env::temp_dir().join(format!(
            "singularity_multiwin_merge_test_{}_{}",
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
                    title: "Video Shared".into(),
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
        };

        let win_b = WindowSessionFile {
            window_id: "win-b".into(),
            pid: 999_992, // non-existent dead PID
            updated_unix: 1050,
            active_tab_index: 1,
            tabs: vec![
                SavedTabEntry {
                    title: "Video Shared (Later)".into(),
                    url: "https://www.youtube.com/watch?v=xyz789&t=480s".into(),
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
                id: "grp-1".into(), // intentionally collides with win_a's "grp-1"!
                title: "Videos".into(),
                color: "#ef4444".into(),
                collapsed: true,
            }],
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

        let merged = RoamingSingularityStore::open_at(merge_dir.clone()).expect("merge sessions");
        assert_eq!(merged.merged_windows_count, 2);
        assert!(!merged.is_secondary_live_window);
        assert_eq!(merged.profile.saved_tabs.len(), 3);
        assert_eq!(merged.profile.saved_tab_groups.len(), 2);
        // Colliding group IDs must have been remapped into 2 distinct group IDs
        assert_ne!(
            merged.profile.saved_tab_groups[0].id,
            merged.profile.saved_tab_groups[1].id
        );
        // Shared YouTube video keeps the highest media_time_sec (480s)
        let yt = merged
            .profile
            .saved_tabs
            .iter()
            .find(|t| t.url.contains("xyz789"))
            .expect("merged yt tab");
        assert_eq!(yt.media_time_sec, Some(480));
        assert_eq!(yt.scroll_y, Some(90));
        // Twitch tab belongs to the remapped "Videos" group
        let tw = merged
            .profile
            .saved_tabs
            .iter()
            .find(|t| t.url.contains("twitch.tv"))
            .expect("merged twitch tab");
        assert_eq!(
            tw.group_id.as_deref(),
            Some(merged.profile.saved_tab_groups[1].id.as_str())
        );
        // Old dead session files are cleaned up after combining
        assert!(!sessions_dir.join("win-a.json").exists());
        assert!(!sessions_dir.join("win-b.json").exists());

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
        assert!(server_src.contains("fullscreenchange"));
        assert!(server_src.contains("consume_bootstrap_nonce"));

        let updater_src = include_str!("updater.rs");
        assert!(updater_src.contains("https://github.com/MyMasha/Singularity"));
        assert!(updater_src.contains("winhttp_get_https_bytes"));
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
        assert_eq!(env!("CARGO_PKG_VERSION"), "1.0.2");

        // 4. English HTML default, live EN/FR i18n, mandatory Step 1 language+theme gate, and zero bundled brand SVGs
        assert!(SINGULARITY_UI_HTML.contains("<html lang=\"en\">"));
        assert!(SINGULARITY_UI_HTML.contains("v1.0.2"));
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

        // 2. Native .exe download handling, dark Win32 background & shared WebView2 environment
        let server_src = include_str!("server.rs");
        assert!(server_src.contains("with_download_started_handler"));
        assert!(server_src.contains("with_download_completed_handler"));
        assert!(server_src.contains("safebrowsing-disable-download-protection"));
        assert!(server_src.contains("SHGetKnownFolderPath"));
        assert!(server_src.contains("reveal_download_in_explorer"));
        assert!(server_src.contains("apply_win32_black_class_brush"));
        assert!(server_src.contains("enable_win32_immersive_dark_window"));
        assert!(server_src.contains("with_background_color((0, 0, 0, 255))"));
        assert!(server_src.contains("with_environment(Clone::clone(env))"));
        assert!(server_src.contains("run_combined_cookie_hygiene_and_snapshot"));
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

        // 2. Real-Rust HTTP, IPC, Win32 & WebView2 performance engine assertions
        let server_src = include_str!("server.rs");
        assert!(server_src.contains("struct HttpThreadPool"));
        assert!(server_src.contains("set_nodelay(true)"));
        assert!(server_src.contains("MAX_KEEPALIVE_REQUESTS_PER_CONN"));
        assert!(server_src.contains("Connection: keep-alive"));
        assert!(server_src.contains("STATE_REVISION"));
        assert!(server_src.contains("struct WebViewLayoutCache"));
        assert!(server_src.contains("msEdgeTelemetry"));
        assert!(server_src.contains("/api/window/adopt_tab"));
        assert!(server_src.contains("find_peer_window_at_point"));
        assert!(server_src.contains("send_adopt_tab_to_peer"));
        assert!(server_src.contains("spawn_detached_singularity_window"));
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
}
