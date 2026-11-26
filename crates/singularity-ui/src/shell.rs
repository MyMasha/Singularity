//! Singularity OLED Pure Black (`#000000`) 200Hz+ Native UI Shell Orchestrator.

use crate::bookmarks_store::BookmarksStore;
use crate::cursor::CustomCursorEngine;
use crate::history_store::HistoryStore;
use crate::keybinds::{
    CommandChainStore, CommandRegistry, KeymapTable, MouseGestureRecognizer, MruTabCycler,
};
use crate::omnibox::OmniboxEngine;
use crate::page_tools::{CollectionsStore, NotesStore, PdfAnnotationStore, ReadingListStore};
use crate::profiles::{
    ContainerRegistry, CustomizationStore, ProfileRegistry, SitePermissionsStore,
    WorkspaceSessionStore,
};
use crate::pwa::PwaRegistry;
use crate::roaming_store::{RoamingSingularityStore, SavedTabEntry, TabHandoffPayload};
use crate::theme::SingularityThemeManifest;
use crate::userscripts::UserscriptManager;
use crate::vim::VimModalEngine;
use singularity_cast::OptInCastController;
use singularity_core::SingularityCoreOrchestrator;
use singularity_media::{
    DirectStreamRecorder, LiveCaptionsConfig, LiveCaptionsEngine, MediaSessionRegistry,
    OledMediaPlayer, PerTabAudioDspManager, ReadAloudSession, TenBandParametricEqualizer,
    TtsConfig,
};
use singularity_settings_registry::{
    schema::{SettingCategory, SettingValue},
    search::VirtualizedViewport,
    storage::TomlSettingsSnapshot,
    FlagsStore, PolicyEngine,
};
use singularity_sync::SingularitySyncEngine;
use singularity_translate::{OfflineTranslationEngine, TranslationPrefs};
use singularity_vault::{Argon2idConfig, SingularityVault};
use std::sync::Arc;
use std::time::Instant;
use zeroize::Zeroizing;

/// Interactive Argon2id parameters (19 MiB OWASP recommended profile for fast desktop unlock + strong GPU resistance).
pub const DESKTOP_VAULT_KDF: Argon2idConfig = Argon2idConfig {
    memory_kib: 19_456,
    iterations: 2,
    parallelism: 1,
};

/// Default vault auto-lock timeout (15 minutes of inactivity).
pub const DEFAULT_VAULT_AUTO_LOCK_SECS: u64 = 900;

/// Complete Singularity Browser Shell integrating all architectural subsystems and `%APPDATA%\.singularity`.
pub struct SingularityBrowserShell {
    pub core: SingularityCoreOrchestrator,
    pub vault: SingularityVault,
    pub roaming: RoamingSingularityStore,
    pub equalizer: TenBandParametricEqualizer,
    pub audio_dsp: PerTabAudioDspManager,
    pub media_player: OledMediaPlayer,
    pub stream_recorder: DirectStreamRecorder,
    pub media_sessions: MediaSessionRegistry,
    pub tts_session: ReadAloudSession,
    pub live_captions: LiveCaptionsEngine,
    pub theme: SingularityThemeManifest,
    pub cursor_engine: CustomCursorEngine,
    pub vim_engine: VimModalEngine,
    pub flags: FlagsStore,
    pub policy: PolicyEngine,
    pub sync_engine: Option<SingularitySyncEngine>,
    pub translate_engine: OfflineTranslationEngine,
    pub cast_controller: OptInCastController,
    pub omnibox: OmniboxEngine,
    pub history_store: HistoryStore,
    pub bookmarks_store: BookmarksStore,
    pub collections: CollectionsStore,
    pub notes: NotesStore,
    pub reading_list: ReadingListStore,
    pub pdf_annotations: PdfAnnotationStore,
    pub commands: CommandRegistry,
    pub keybinds: KeymapTable,
    pub command_chains: CommandChainStore,
    pub gestures: MouseGestureRecognizer,
    pub mru_cycler: MruTabCycler,
    pub profiles: ProfileRegistry,
    pub containers: ContainerRegistry,
    pub workspaces: WorkspaceSessionStore,
    pub permissions: SitePermissionsStore,
    pub customization: CustomizationStore,
    pub userscripts: UserscriptManager,
    pub pwas: PwaRegistry,
    pub settings_search_query: String,
    pub settings_category_filter: Option<SettingCategory>,
    pub settings_scroll_offset_px: usize,
    pub private_browsing_active: bool,
    /// Verified master password kept strictly in zeroized Rust memory (never cached in JS).
    verified_vault_master: Option<Zeroizing<Vec<u8>>>,
    /// Monotonic clock timestamp immune to wall-clock / NTP jumps.
    vault_last_activity: Instant,
    pub vault_auto_lock_secs: u64,
}

impl SingularityBrowserShell {
    pub fn launch() -> Result<Self, String> {
        Self::launch_with_launch_args(None, None, false)
    }

    pub fn launch_with_options(
        detach_handoff_id: Option<&str>,
        force_new_window: bool,
    ) -> Result<Self, String> {
        Self::launch_with_launch_args(detach_handoff_id, None, force_new_window)
    }

    /// Launches a browser shell anchored to an isolated profile directory.
    pub fn launch_at_dir(root_dir: std::path::PathBuf) -> Result<Self, String> {
        let roaming = RoamingSingularityStore::open_at(root_dir)?;
        Self::launch_with_roaming(roaming)
    }

    pub fn launch_with_launch_args(
        detach_handoff_id: Option<&str>,
        restore_session_id: Option<&str>,
        force_new_window: bool,
    ) -> Result<Self, String> {
        let roaming = RoamingSingularityStore::open_default_with_launch_args(
            detach_handoff_id,
            restore_session_id,
            force_new_window,
        )?;
        Self::launch_with_roaming(roaming)
    }

    fn launch_with_roaming(mut roaming: RoamingSingularityStore) -> Result<Self, String> {
        let mut core = SingularityCoreOrchestrator::boot()?;

        // Restore persisted user overrides across the 2,500+ settings registry from `%APPDATA%\.singularity\settings.toml`
        // and inspect any explicit `mullvad.killswitch.*` entries so they are never clobbered by default `false`.
        let mut toml_strict_override: Option<bool> = None;
        let mut toml_block_lan_override: Option<bool> = None;
        if let Some(saved_toml) = roaming.load_settings_toml() {
            if let Ok(snap) = TomlSettingsSnapshot::from_toml_str(&saved_toml) {
                for key in [
                    "mullvad.killswitch.strict_socket_drop",
                    "mullvad.killswitch.strict_fail_closed",
                ] {
                    if let Some(SettingValue::Bool(b)) = snap.overrides.get(key) {
                        toml_strict_override = Some(*b);
                    }
                }
                for key in [
                    "mullvad.killswitch.block_lan_traffic",
                    "mullvad.killswitch.block_lan_rfc1918",
                ] {
                    if let Some(SettingValue::Bool(b)) = snap.overrides.get(key) {
                        toml_block_lan_override = Some(*b);
                    }
                }
            }
            let _ = core.settings.import_toml(&saved_toml);
        }

        // Load enterprise/managed policy overlay (read-only if present)
        let policy = PolicyEngine::load_default_linux_policies();
        let _ = core.settings.apply_policy_engine(&policy);

        // Configure Mullvad Kill-Switch for real end users:
        // By default, users without a Mullvad subscription browse freely with Singularity Shields active.
        // Preserve strict kill-switch activation from EITHER `roaming.profile.strict_mullvad_killswitch`
        // OR explicit `mullvad.killswitch.*` overrides in `settings.toml` (never overwrite an enabled
        // `settings.toml` kill-switch with the profile's default `false`).
        let effective_strict =
            roaming.profile.strict_mullvad_killswitch || toml_strict_override.unwrap_or(false);
        let effective_block_lan = toml_block_lan_override.unwrap_or(effective_strict);
        core.mullvad_vpn
            .kill_switch()
            .set_strict_enabled(effective_strict);
        core.mullvad_vpn
            .kill_switch()
            .set_block_lan_rfc1918(effective_block_lan);
        roaming.profile.strict_mullvad_killswitch = effective_strict;

        // Wire live hot-reload hook so kill-switch changes in the Settings Registry apply immediately
        let ks_arc = Arc::clone(core.mullvad_vpn.kill_switch());
        core.settings.register_hot_reload_hook(Arc::new(move |evt| {
            if let SettingValue::Bool(b) = evt.new_value {
                match evt.key.as_str() {
                    "mullvad.killswitch.strict_socket_drop"
                    | "mullvad.killswitch.strict_fail_closed" => ks_arc.set_strict_enabled(b),
                    "mullvad.killswitch.block_lan_traffic"
                    | "mullvad.killswitch.block_lan_rfc1918" => ks_arc.set_block_lan_rfc1918(b),
                    _ => {}
                }
            }
        }));

        let _ = core.mullvad_vpn.switch_relay_route(
            &roaming.profile.mullvad_entry_relay,
            &roaming.profile.mullvad_exit_relay,
            roaming.profile.mullvad_multihop,
        );

        if let Some(ref saved_acc) = roaming.tokens.saved_mullvad_account {
            if core
                .mullvad_vpn
                .authenticate_16_digit_account(saved_acc)
                .is_ok()
                && roaming.profile.mullvad_auto_connect
            {
                let _ = core.mullvad_vpn.connect_tunnel(true, true);
            }
        }

        // Always start locked until the user authenticates or creates a master password
        let vault = SingularityVault::new_locked(DESKTOP_VAULT_KDF);

        let initial_tab_title = if roaming.profile.language.eq_ignore_ascii_case("fr") {
            "Singularity • Nouvel onglet"
        } else {
            "Singularity • New Tab"
        };
        core.tab_manager.open_tab(
            initial_tab_title,
            "singularity://newtab",
            "singularity.internal",
            &core.chromium_bridge,
        );

        let root_dir = roaming.root_dir().to_path_buf();
        let mut flags = FlagsStore::new();
        if let Ok(raw_flags) = std::fs::read_to_string(root_dir.join("flags.toml")) {
            let _ = flags.import_toml(&raw_flags);
        }
        let history_store =
            HistoryStore::load_from_dir(&root_dir).unwrap_or_else(|_| HistoryStore::new(100_000));
        let bookmarks_store =
            BookmarksStore::load_from_dir(&root_dir).unwrap_or_else(|_| BookmarksStore::new());
        let collections = CollectionsStore::load_from_path(&root_dir.join("collections.json"))
            .unwrap_or_else(|_| CollectionsStore::new());
        let notes = NotesStore::load_from_path(&root_dir.join("notes.json"))
            .unwrap_or_else(|_| NotesStore::new());
        let reading_list = ReadingListStore::load_from_path(&root_dir.join("reading_list.json"))
            .unwrap_or_else(|_| ReadingListStore::new());
        let keybinds = KeymapTable::load_or_default(&root_dir.join("keybinds.json"));
        let command_chains =
            CommandChainStore::load_from_path(&root_dir.join("command_chains.json"))
                .unwrap_or_else(|_| CommandChainStore::new());
        let profiles = ProfileRegistry::load_from_path(&root_dir.join("profiles.json"))
            .unwrap_or_else(|_| ProfileRegistry::new_default());
        let containers = ContainerRegistry::load_from_path(&root_dir.join("containers.json"))
            .unwrap_or_else(|_| ContainerRegistry::new());
        let workspaces =
            WorkspaceSessionStore::load_from_path(&root_dir.join("workspaces.json"))
                .unwrap_or_default();
        let permissions =
            SitePermissionsStore::load_from_path(&root_dir.join("permissions.json"))
                .unwrap_or_else(|_| SitePermissionsStore::new_hardened());
        let customization =
            CustomizationStore::load_from_path(&root_dir.join("customization.json"))
                .unwrap_or_default();
        let userscripts = UserscriptManager::open_at(&root_dir)
            .unwrap_or_else(|_| UserscriptManager::open_at(&std::env::temp_dir().join("singularity-userscripts")).expect("temp userscripts"));
        let pwas = PwaRegistry::open_at(&root_dir)
            .unwrap_or_else(|_| PwaRegistry::open_at(&std::env::temp_dir().join("singularity-pwas")).expect("temp pwas"));
        let mut translate_prefs = TranslationPrefs::default();
        if !roaming.profile.language.trim().is_empty() {
            translate_prefs.target_lang = roaming.profile.language.trim().to_ascii_lowercase();
        }
        let translate_engine = OfflineTranslationEngine::new(translate_prefs);

        let mut shell = Self {
            core,
            vault,
            roaming,
            equalizer: TenBandParametricEqualizer::default(),
            audio_dsp: PerTabAudioDspManager::new(48_000.0),
            media_player: OledMediaPlayer::default(),
            stream_recorder: DirectStreamRecorder::new(),
            media_sessions: MediaSessionRegistry::new(),
            tts_session: ReadAloudSession::new(TtsConfig::default()),
            live_captions: LiveCaptionsEngine::new(LiveCaptionsConfig::default(), 256),
            theme: SingularityThemeManifest::default(),
            cursor_engine: CustomCursorEngine::default(),
            vim_engine: VimModalEngine::default(),
            flags,
            policy,
            sync_engine: None,
            translate_engine,
            cast_controller: OptInCastController::new(),
            omnibox: OmniboxEngine::default(),
            history_store,
            bookmarks_store,
            collections,
            notes,
            reading_list,
            pdf_annotations: PdfAnnotationStore::new(),
            commands: CommandRegistry::new(),
            keybinds,
            command_chains,
            gestures: MouseGestureRecognizer::default(),
            mru_cycler: MruTabCycler::new(),
            profiles,
            containers,
            workspaces,
            permissions,
            customization,
            userscripts,
            pwas,
            settings_search_query: String::new(),
            settings_category_filter: None,
            settings_scroll_offset_px: 0,
            private_browsing_active: false,
            verified_vault_master: None,
            vault_last_activity: Instant::now(),
            vault_auto_lock_secs: DEFAULT_VAULT_AUTO_LOCK_SECS,
        };
        shell.sync_runtime_from_settings();
        Ok(shell)
    }

    /// Enqueues validated positional URLs passed on the CLI (e.g. Linux `.desktop` `%U` or OS
    /// default-browser invocation) so the browser opens and focuses them immediately on launch.
    pub fn enqueue_cli_launch_urls(&mut self, urls: &[String]) {
        let mut valid_urls: Vec<String> = Vec::new();
        for raw in urls.iter().take(32) {
            let trimmed = raw.trim();
            if trimmed.is_empty()
                || trimmed.len() > 8192
                || trimmed.chars().any(|c| c.is_control())
            {
                continue;
            }
            let lower = trimmed.to_ascii_lowercase();
            let is_http = (lower.starts_with("https://") && trimmed.len() > 8)
                || (lower.starts_with("http://") && trimmed.len() > 7);
            let is_safe_settings = lower == "singularity://settings"
                || (lower.starts_with("singularity://settings/")
                    && trimmed.len() <= 64
                    && trimmed["singularity://settings/".len()..]
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
            if (is_http || is_safe_settings) && !valid_urls.iter().any(|u| u == trimmed) {
                valid_urls.push(trimmed.to_string());
            }
        }
        if valid_urls.is_empty() {
            return;
        }
        if !self.roaming.profile.restore_session && self.roaming.startup_handoff.is_none() {
            self.roaming.profile.saved_tabs.clear();
            self.roaming.profile.saved_tab_groups.clear();
            self.roaming.profile.active_tab_index = 0;
        }
        let first_idx = self.roaming.profile.saved_tabs.len();
        for url in &valid_urls {
            let title = url
                .split("://")
                .nth(1)
                .and_then(|rest| rest.split('/').next())
                .filter(|host| !host.is_empty())
                .unwrap_or(url.as_str())
                .to_string();
            self.roaming.profile.saved_tabs.push(SavedTabEntry {
                title,
                url: url.clone(),
                media_time_sec: None,
                scroll_y: None,
                group_id: None,
                favicon_url: None,
            });
        }
        self.roaming.profile.active_tab_index = first_idx;
        if !self.roaming.profile.restore_session && self.roaming.startup_handoff.is_none() {
            if let Some(first) = self.roaming.profile.saved_tabs.get(first_idx) {
                self.roaming.startup_handoff = Some(TabHandoffPayload {
                    url: first.url.clone(),
                    title: first.title.clone(),
                    favicon_url: None,
                    media_time_sec: None,
                    scroll_y: None,
                    pos_x: None,
                    pos_y: None,
                });
            }
        }
    }

    /// Synchronizes live subsystem settings (media EQ boost, tab freezer timeout, vault KDF, auto-lock,
    /// and Mullvad kill-switch profile persistence) from the 2,165 Settings Registry so UI changes
    /// take immediate runtime effect and survive restarts coherently.
    pub fn sync_runtime_from_settings(&mut self) {
        if let Some(boost) = self
            .core
            .settings
            .get("media.audio.volume_boost_percent")
            .and_then(|e| e.current_value.as_float())
        {
            self.equalizer.set_volume_boost_percent(boost);
        }
        if let Some(timeout) = self
            .core
            .settings
            .get("rendering.tabs.auto_freeze_idle_seconds")
            .and_then(|e| e.current_value.as_int())
        {
            if timeout > 0 {
                self.core.tab_manager.set_freeze_timeout_seconds(timeout as u64);
            }
        }
        if let Some(mem) = self
            .core
            .settings
            .get("vault.kdf.argon2id_memory_kib")
            .and_then(|e| e.current_value.as_int())
        {
            let iters = self
                .core
                .settings
                .get("vault.kdf.argon2id_iterations")
                .and_then(|e| e.current_value.as_int())
                .unwrap_or(DESKTOP_VAULT_KDF.iterations as i64);
            let par = self
                .core
                .settings
                .get("vault.kdf.argon2id_parallelism")
                .and_then(|e| e.current_value.as_int())
                .unwrap_or(DESKTOP_VAULT_KDF.parallelism as i64);
            let cfg = Argon2idConfig {
                memory_kib: mem.clamp(4_096, 1_048_576) as u32,
                iterations: iters.clamp(1, 64) as u32,
                parallelism: par.clamp(1, 16) as u32,
            };
            self.vault.set_kdf_config(cfg);
        }
        if let Some(mins) = self
            .core
            .settings
            .get("vault.security.auto_lock_minutes")
            .and_then(|e| e.current_value.as_int())
        {
            if mins > 0 {
                self.vault_auto_lock_secs = (mins as u64).saturating_mul(60);
            }
        }
        let ks_strict = self.core.mullvad_vpn.kill_switch().is_strict_enabled();
        if self.roaming.profile.strict_mullvad_killswitch != ks_strict {
            self.roaming.profile.strict_mullvad_killswitch = ks_strict;
            let _ = self.roaming.save_profile();
        }
    }

    /// Locks the vault automatically if monotonic inactivity exceeds `vault_auto_lock_secs`.
    pub fn enforce_vault_auto_lock(&mut self) {
        if !self.vault.is_locked() && self.vault_auto_lock_secs > 0 {
            if self.vault_last_activity.elapsed().as_secs() >= self.vault_auto_lock_secs {
                self.lock_vault();
            }
        }
    }

    pub fn touch_vault_activity(&mut self) {
        self.vault_last_activity = Instant::now();
    }

    pub fn set_verified_vault_master(&mut self, master: Vec<u8>) {
        self.verified_vault_master = Some(Zeroizing::new(master));
        self.vault_last_activity = Instant::now();
    }

    pub fn lock_vault(&mut self) {
        self.vault.lock();
        self.verified_vault_master = None;
    }

    /// Persists the unlocked vault to disk using the verified in-memory Rust master password.
    pub fn persist_unlocked_vault_to_disk(&mut self) -> Result<(), String> {
        let master = self
            .verified_vault_master
            .as_ref()
            .ok_or_else(|| "Vault is locked or master key is absent from the session".to_string())?;
        let sealed = self
            .vault
            .export_encrypted_vault(master.as_slice())
            .map_err(|e| e.to_string())?;
        self.roaming.write_vault_envelope_to_disk(&sealed)?;
        self.vault_last_activity = Instant::now();
        Ok(())
    }

    /// Exports the unlocked vault using the verified in-memory Rust master password.
    pub fn export_verified_vault(&mut self) -> Result<String, String> {
        let master = self
            .verified_vault_master
            .as_ref()
            .ok_or_else(|| "Vault is locked".to_string())?;
        self.vault_last_activity = Instant::now();
        self.vault
            .export_encrypted_vault(master.as_slice())
            .map_err(|e| e.to_string())
    }

    /// Queries the 2,500+ settings registry with virtualized scrolling for `singularity://settings`.
    pub fn render_virtualized_settings_viewport(
        &self,
        viewport_height_px: usize,
    ) -> VirtualizedViewport<'_> {
        self.core.settings.query_virtualized(
            self.settings_category_filter,
            &self.settings_search_query,
            self.settings_scroll_offset_px,
            viewport_height_px,
            54,
        )
    }

    pub fn save_flags(&self) -> Result<(), String> {
        let toml = self.flags.export_toml()?;
        std::fs::write(self.roaming.root_dir().join("flags.toml"), toml).map_err(|e| e.to_string())
    }

    pub fn save_history_store(&self) -> Result<(), String> {
        self.history_store
            .save_to_dir(self.roaming.root_dir())
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    pub fn save_bookmarks_store(&self) -> Result<(), String> {
        self.bookmarks_store
            .save_to_dir(self.roaming.root_dir())
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    pub fn save_collections(&self) -> Result<(), String> {
        self.collections
            .save_to_path(&self.roaming.root_dir().join("collections.json"))
            .map_err(|e| e.to_string())
    }

    pub fn save_notes(&self) -> Result<(), String> {
        self.notes
            .save_to_path(&self.roaming.root_dir().join("notes.json"))
            .map_err(|e| e.to_string())
    }

    pub fn save_reading_list(&self) -> Result<(), String> {
        self.reading_list
            .save_to_path(&self.roaming.root_dir().join("reading_list.json"))
            .map_err(|e| e.to_string())
    }

    pub fn save_keybinds(&self) -> Result<(), String> {
        self.keybinds
            .save_to_path(&self.roaming.root_dir().join("keybinds.json"))
            .map_err(|e| e.to_string())
    }

    pub fn save_command_chains(&self) -> Result<(), String> {
        self.command_chains
            .save_to_path(&self.roaming.root_dir().join("command_chains.json"))
            .map_err(|e| e.to_string())
    }

    pub fn save_profiles(&self) -> Result<(), String> {
        self.profiles
            .save_to_path(&self.roaming.root_dir().join("profiles.json"))
            .map_err(|e| e.to_string())
    }

    pub fn save_containers(&self) -> Result<(), String> {
        self.containers
            .save_to_path(&self.roaming.root_dir().join("containers.json"))
            .map_err(|e| e.to_string())
    }

    pub fn save_workspaces(&self) -> Result<(), String> {
        self.workspaces
            .save_to_path(&self.roaming.root_dir().join("workspaces.json"))
            .map_err(|e| e.to_string())
    }

    pub fn save_permissions(&self) -> Result<(), String> {
        self.permissions
            .save_to_path(&self.roaming.root_dir().join("permissions.json"))
            .map_err(|e| e.to_string())
    }

    pub fn save_customization(&self) -> Result<(), String> {
        self.customization
            .save_to_path(&self.roaming.root_dir().join("customization.json"))
            .map_err(|e| e.to_string())
    }

    pub fn verified_vault_master_bytes(&self) -> Option<&[u8]> {
        self.verified_vault_master.as_deref().map(|v| v.as_slice())
    }
}
