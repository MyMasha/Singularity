//! Singularity OLED Pure Black (`#000000`) 200Hz+ Native UI Shell Orchestrator.

use crate::cursor::CustomCursorEngine;
use crate::roaming_store::{unix_now, RoamingSingularityStore};
use crate::theme::SingularityThemeManifest;
use crate::vim::VimModalEngine;
use singularity_core::SingularityCoreOrchestrator;
use singularity_media::{DirectStreamRecorder, OledMediaPlayer, TenBandParametricEqualizer};
use singularity_settings_registry::{
    schema::{SettingCategory, SettingValue},
    search::VirtualizedViewport,
};
use singularity_vault::{Argon2idConfig, SingularityVault};
use std::sync::Arc;
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
    pub media_player: OledMediaPlayer,
    pub stream_recorder: DirectStreamRecorder,
    pub theme: SingularityThemeManifest,
    pub cursor_engine: CustomCursorEngine,
    pub vim_engine: VimModalEngine,
    pub settings_search_query: String,
    pub settings_category_filter: Option<SettingCategory>,
    pub settings_scroll_offset_px: usize,
    pub private_browsing_active: bool,
    /// Verified master password kept strictly in zeroized Rust memory (never cached in JS).
    verified_vault_master: Option<Zeroizing<Vec<u8>>>,
    vault_last_activity_unix: u64,
    pub vault_auto_lock_secs: u64,
}

impl SingularityBrowserShell {
    pub fn launch() -> Result<Self, String> {
        let mut core = SingularityCoreOrchestrator::boot()?;
        let roaming = RoamingSingularityStore::open_default()?;

        // Restore persisted user overrides across the 2,165 settings registry from `%APPDATA%\.singularity\settings.toml`
        if let Some(saved_toml) = roaming.load_settings_toml() {
            let _ = core.settings.import_toml(&saved_toml);
        }

        // Configure Mullvad Kill-Switch for real end users:
        // By default, users without a Mullvad subscription browse freely with Singularity Shields active.
        // If the user enabled strict kill-switch or auto-connect with a saved encrypted Mullvad account, restore it.
        core.mullvad_vpn
            .kill_switch()
            .set_strict_enabled(roaming.profile.strict_mullvad_killswitch);
        core.mullvad_vpn
            .kill_switch()
            .set_block_lan_rfc1918(roaming.profile.strict_mullvad_killswitch);

        // Wire live hot-reload hook so kill-switch changes in the 2,165 Settings Registry apply immediately
        let ks_arc = Arc::clone(core.mullvad_vpn.kill_switch());
        core.settings.register_hot_reload_hook(Arc::new(move |evt| {
            if let SettingValue::Bool(b) = evt.new_value {
                match evt.key.as_str() {
                    "mullvad.killswitch.strict_fail_closed" => ks_arc.set_strict_enabled(b),
                    "mullvad.killswitch.block_lan_rfc1918" => ks_arc.set_block_lan_rfc1918(b),
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

        core.tab_manager.open_tab(
            "Singularity • Nouvel onglet",
            "singularity://newtab",
            "singularity.internal",
            &core.chromium_bridge,
        );

        let mut shell = Self {
            core,
            vault,
            roaming,
            equalizer: TenBandParametricEqualizer::default(),
            media_player: OledMediaPlayer::default(),
            stream_recorder: DirectStreamRecorder::new(),
            theme: SingularityThemeManifest::default(),
            cursor_engine: CustomCursorEngine::default(),
            vim_engine: VimModalEngine::default(),
            settings_search_query: String::new(),
            settings_category_filter: None,
            settings_scroll_offset_px: 0,
            private_browsing_active: false,
            verified_vault_master: None,
            vault_last_activity_unix: unix_now(),
            vault_auto_lock_secs: DEFAULT_VAULT_AUTO_LOCK_SECS,
        };
        shell.sync_runtime_from_settings();
        Ok(shell)
    }

    /// Synchronizes live subsystem settings (media EQ boost, tab freezer timeout, vault KDF, auto-lock)
    /// from the 2,165 Settings Registry so UI changes take immediate runtime effect.
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
    }

    /// Locks the vault automatically if inactivity exceeds `vault_auto_lock_secs`.
    pub fn enforce_vault_auto_lock(&mut self) {
        if !self.vault.is_locked() && self.vault_auto_lock_secs > 0 {
            let now = unix_now();
            if now.saturating_sub(self.vault_last_activity_unix) >= self.vault_auto_lock_secs {
                self.lock_vault();
            }
        }
    }

    pub fn touch_vault_activity(&mut self) {
        self.vault_last_activity_unix = unix_now();
    }

    pub fn set_verified_vault_master(&mut self, master: Vec<u8>) {
        self.verified_vault_master = Some(Zeroizing::new(master));
        self.vault_last_activity_unix = unix_now();
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
        self.vault_last_activity_unix = unix_now();
        Ok(())
    }

    /// Exports the unlocked vault using the verified in-memory Rust master password.
    pub fn export_verified_vault(&mut self) -> Result<String, String> {
        let master = self
            .verified_vault_master
            .as_ref()
            .ok_or_else(|| "Vault is locked".to_string())?;
        self.vault_last_activity_unix = unix_now();
        self.vault
            .export_encrypted_vault(master.as_slice())
            .map_err(|e| e.to_string())
    }

    /// Queries the 2,165+ settings registry with virtualized scrolling for `singularity://settings`.
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
}
