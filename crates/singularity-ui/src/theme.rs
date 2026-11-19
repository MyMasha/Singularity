//! Hot-Reloadable TOML/JSON OLED Pure Black (`#000000`) Theme & Token Engine.

use serde::{Deserialize, Serialize};

pub const OLED_PURE_BLACK: &str = "#000000";
pub const OBSIDIAN_BORDER: &str = "#141414";
pub const ACCRETION_VIOLET: &str = "#6E00FF";
pub const ACCRETION_CYAN: &str = "#00F0FF";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TabBarPlacement {
    TopCompact,
    VerticalLeftCollapsible,
    VerticalRightCollapsible,
    HiddenZeroChrome,
}

/// Complete hot-reloadable theme manifest for the Singularity UI shell.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SingularityThemeManifest {
    pub theme_name: String,
    pub background_oled_hex: String,
    pub surface_elevated_hex: String,
    pub border_obsidian_hex: String,
    pub accent_violet_hex: String,
    pub accent_cyan_hex: String,
    pub text_primary_hex: String,
    pub text_muted_hex: String,
    pub ui_font_family: String,
    pub mono_font_family: String,
    pub target_refresh_rate_hz: u32,
    pub tab_bar_placement: TabBarPlacement,
    pub black_hole_schwarzschild_radius: f32,
    pub black_hole_kerr_spin: f32,
}

impl Default for SingularityThemeManifest {
    fn default() -> Self {
        Self {
            theme_name: "Singularity Event Horizon OLED".into(),
            background_oled_hex: OLED_PURE_BLACK.into(),
            surface_elevated_hex: "#070709".into(),
            border_obsidian_hex: OBSIDIAN_BORDER.into(),
            accent_violet_hex: ACCRETION_VIOLET.into(),
            accent_cyan_hex: ACCRETION_CYAN.into(),
            text_primary_hex: "#F4F4F6".into(),
            text_muted_hex: "#7A7A85".into(),
            ui_font_family: "Geist Sans".into(),
            mono_font_family: "JetBrains Mono".into(),
            target_refresh_rate_hz: 240,
            tab_bar_placement: TabBarPlacement::VerticalLeftCollapsible,
            black_hole_schwarzschild_radius: 1.0,
            black_hole_kerr_spin: 0.94,
        }
    }
}

impl SingularityThemeManifest {
    pub fn to_toml(&self) -> Result<String, toml::ser::Error> {
        toml::to_string_pretty(self)
    }

    pub fn from_toml(raw: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(raw)
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}
