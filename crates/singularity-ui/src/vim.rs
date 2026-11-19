//! Native Rust Vimium-Style Modal Keyboard Navigation Engine.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VimMode {
    Normal,
    InsertPassThrough,
    LinkHintOverlay { open_in_new_tab: bool, typed_prefix: String },
    CommandPrompt { buffer: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkHintBadge {
    pub label: String,
    pub target_url: String,
    pub x_px: u32,
    pub y_px: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VimAction {
    NoOp,
    ScrollVerticalPx(i32),
    ScrollToTop,
    ScrollToBottom,
    EnterLinkHintMode { new_tab: bool },
    ActivateLinkUrl { url: String, new_tab: bool },
    NextTab,
    PreviousTab,
    CloseCurrentTab,
    OpenNewTab,
    FocusOmnibox,
    ToggleMullvadQuickHop,
}

/// Processes modal Vim key chords and generates home-row GPU link hint overlays.
pub struct VimModalEngine {
    pub mode: VimMode,
    pub pending_g_chord: bool,
    pub active_hints: Vec<LinkHintBadge>,
}

impl Default for VimModalEngine {
    fn default() -> Self {
        Self {
            mode: VimMode::Normal,
            pending_g_chord: false,
            active_hints: Vec::new(),
        }
    }
}

impl VimModalEngine {
    /// Generates unique prefix-free home-row link hint labels (`s`, `a`, ..., `sa`, `sd`, ..., `ssa`...)
    pub fn generate_home_row_hints(&mut self, links: &[(String, u32, u32)]) -> &[LinkHintBadge] {
        const ALPHABET: &[u8] = b"sadfjklewcmpgh";
        let base = ALPHABET.len();
        self.active_hints.clear();

        let width = if links.len() <= base {
            1
        } else if links.len() <= base * base {
            2
        } else {
            3
        };

        for (idx, (url, x, y)) in links.iter().enumerate() {
            if idx >= base * base * base {
                break;
            }
            let mut label = String::with_capacity(width);
            let mut rem = idx;
            let mut chars = vec!['s'; width];
            for pos in (0..width).rev() {
                chars[pos] = ALPHABET[rem % base] as char;
                rem /= base;
            }
            for ch in chars {
                label.push(ch);
            }
            self.active_hints.push(LinkHintBadge {
                label,
                target_url: url.clone(),
                x_px: *x,
                y_px: *y,
            });
        }

        &self.active_hints
    }

    pub fn handle_key_press(&mut self, key: &str) -> VimAction {
        match &mut self.mode {
            VimMode::Normal => {
                if self.pending_g_chord {
                    self.pending_g_chord = false;
                    if key == "g" {
                        return VimAction::ScrollToTop;
                    }
                }
                match key {
                    "j" => VimAction::ScrollVerticalPx(90),
                    "k" => VimAction::ScrollVerticalPx(-90),
                    "d" => VimAction::ScrollVerticalPx(450),
                    "u" => VimAction::ScrollVerticalPx(-450),
                    "g" => {
                        self.pending_g_chord = true;
                        VimAction::NoOp
                    }
                    "G" => VimAction::ScrollToBottom,
                    "f" => {
                        self.mode = VimMode::LinkHintOverlay {
                            open_in_new_tab: false,
                            typed_prefix: String::new(),
                        };
                        VimAction::EnterLinkHintMode { new_tab: false }
                    }
                    "F" => {
                        self.mode = VimMode::LinkHintOverlay {
                            open_in_new_tab: true,
                            typed_prefix: String::new(),
                        };
                        VimAction::EnterLinkHintMode { new_tab: true }
                    }
                    "J" => VimAction::PreviousTab,
                    "K" => VimAction::NextTab,
                    "x" => VimAction::CloseCurrentTab,
                    "t" => VimAction::OpenNewTab,
                    "o" => VimAction::FocusOmnibox,
                    "M" => VimAction::ToggleMullvadQuickHop,
                    _ => VimAction::NoOp,
                }
            }
            VimMode::LinkHintOverlay {
                open_in_new_tab,
                typed_prefix,
            } => {
                if key == "Escape" {
                    self.mode = VimMode::Normal;
                    return VimAction::NoOp;
                }
                if key == "Backspace" {
                    typed_prefix.pop();
                    return VimAction::NoOp;
                }
                if key.chars().count() != 1 {
                    return VimAction::NoOp;
                }
                typed_prefix.push_str(key);
                let current_prefix = typed_prefix.clone();
                let new_tab = *open_in_new_tab;

                if let Some(exact) = self
                    .active_hints
                    .iter()
                    .find(|h| h.label == current_prefix)
                    .cloned()
                {
                    self.mode = VimMode::Normal;
                    return VimAction::ActivateLinkUrl {
                        url: exact.target_url,
                        new_tab,
                    };
                }
                // Cancel overlay cleanly if no remaining hint starts with typed_prefix
                if !self
                    .active_hints
                    .iter()
                    .any(|h| h.label.starts_with(&current_prefix))
                {
                    self.mode = VimMode::Normal;
                }
                VimAction::NoOp
            }
            VimMode::InsertPassThrough | VimMode::CommandPrompt { .. } => {
                if key == "Escape" {
                    self.mode = VimMode::Normal;
                }
                VimAction::NoOp
            }
        }
    }
}
