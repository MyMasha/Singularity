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
    EnterYankLinkHintMode,
    ActivateLinkUrl { url: String, new_tab: bool },
    YankLinkUrl { url: String },
    NextTab,
    PreviousTab,
    CloseCurrentTab,
    ReopenClosedTab,
    DuplicateCurrentTab,
    OpenNewTab,
    FocusOmnibox,
    FocusFirstInput,
    HistoryBack,
    HistoryForward,
    YankCurrentUrl,
    OpenClipboardUrl { new_tab: bool },
    EnterFindMode,
    FindNext,
    FindPrev,
    EnterInsertMode,
    EnterCommandPrompt,
    ExecuteCommand(String),
    FreezeActiveTab,
    ToggleMullvadQuickHop,
}

/// Processes modal Vim key chords and generates home-row GPU link hint overlays.
pub struct VimModalEngine {
    pub mode: VimMode,
    pub pending_g_chord: bool,
    pub pending_y_chord: bool,
    pub pending_z_chord: bool,
    pub active_hints: Vec<LinkHintBadge>,
    pub hint_yank_only: bool,
    pub excluded_domains: Vec<String>,
}

impl Default for VimModalEngine {
    fn default() -> Self {
        Self {
            mode: VimMode::Normal,
            pending_g_chord: false,
            pending_y_chord: false,
            pending_z_chord: false,
            active_hints: Vec::new(),
            hint_yank_only: false,
            excluded_domains: vec![
                "mail.google.com".into(),
                "docs.google.com".into(),
                "figma.com".into(),
                "notion.so".into(),
            ],
        }
    }
}

impl VimModalEngine {
    /// Returns true if Vim modal shortcuts should pass through to the web app on `host`.
    pub fn is_domain_excluded(&self, host: &str) -> bool {
        let lower = host.trim().to_ascii_lowercase();
        self.excluded_domains.iter().any(|rule| {
            let r = rule.trim().to_ascii_lowercase();
            !r.is_empty() && (lower == r || lower.ends_with(&format!(".{r}")))
        })
    }

    pub fn set_excluded_domains_csv(&mut self, csv: &str) {
        self.excluded_domains = csv
            .split([',', ';', '\n'])
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
    }

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
                    return match key {
                        "g" => VimAction::ScrollToTop,
                        "i" => VimAction::FocusFirstInput,
                        _ => VimAction::NoOp,
                    };
                }
                if self.pending_y_chord {
                    self.pending_y_chord = false;
                    return match key {
                        "y" => VimAction::YankCurrentUrl,
                        "t" => VimAction::DuplicateCurrentTab,
                        "f" => {
                            self.hint_yank_only = true;
                            self.mode = VimMode::LinkHintOverlay {
                                open_in_new_tab: false,
                                typed_prefix: String::new(),
                            };
                            VimAction::EnterYankLinkHintMode
                        }
                        _ => VimAction::NoOp,
                    };
                }
                if self.pending_z_chord {
                    self.pending_z_chord = false;
                    return match key {
                        "f" => VimAction::FreezeActiveTab,
                        _ => VimAction::NoOp,
                    };
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
                    "y" => {
                        self.pending_y_chord = true;
                        VimAction::NoOp
                    }
                    "z" => {
                        self.pending_z_chord = true;
                        VimAction::NoOp
                    }
                    "G" => VimAction::ScrollToBottom,
                    "f" => {
                        self.hint_yank_only = false;
                        self.mode = VimMode::LinkHintOverlay {
                            open_in_new_tab: false,
                            typed_prefix: String::new(),
                        };
                        VimAction::EnterLinkHintMode { new_tab: false }
                    }
                    "F" => {
                        self.hint_yank_only = false;
                        self.mode = VimMode::LinkHintOverlay {
                            open_in_new_tab: true,
                            typed_prefix: String::new(),
                        };
                        VimAction::EnterLinkHintMode { new_tab: true }
                    }
                    "H" => VimAction::HistoryBack,
                    "L" => VimAction::HistoryForward,
                    "J" => VimAction::PreviousTab,
                    "K" => VimAction::NextTab,
                    "x" => VimAction::CloseCurrentTab,
                    "X" => VimAction::ReopenClosedTab,
                    "t" => VimAction::OpenNewTab,
                    "o" => VimAction::FocusOmnibox,
                    "p" => VimAction::OpenClipboardUrl { new_tab: false },
                    "P" => VimAction::OpenClipboardUrl { new_tab: true },
                    "/" => VimAction::EnterFindMode,
                    "n" => VimAction::FindNext,
                    "N" => VimAction::FindPrev,
                    "i" => {
                        self.mode = VimMode::InsertPassThrough;
                        VimAction::EnterInsertMode
                    }
                    ":" => {
                        self.mode = VimMode::CommandPrompt {
                            buffer: String::new(),
                        };
                        VimAction::EnterCommandPrompt
                    }
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
                    self.hint_yank_only = false;
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
                    let yank_only = self.hint_yank_only;
                    self.hint_yank_only = false;
                    self.mode = VimMode::Normal;
                    return if yank_only {
                        VimAction::YankLinkUrl {
                            url: exact.target_url,
                        }
                    } else {
                        VimAction::ActivateLinkUrl {
                            url: exact.target_url,
                            new_tab,
                        }
                    };
                }
                // Cancel overlay cleanly if no remaining hint starts with typed_prefix
                if !self
                    .active_hints
                    .iter()
                    .any(|h| h.label.starts_with(&current_prefix))
                {
                    self.mode = VimMode::Normal;
                    self.hint_yank_only = false;
                }
                VimAction::NoOp
            }
            VimMode::InsertPassThrough => {
                if key == "Escape" {
                    self.mode = VimMode::Normal;
                }
                VimAction::NoOp
            }
            VimMode::CommandPrompt { buffer } => {
                if key == "Escape" {
                    self.mode = VimMode::Normal;
                    return VimAction::NoOp;
                }
                if key == "Backspace" {
                    buffer.pop();
                    return VimAction::NoOp;
                }
                if key == "Enter" {
                    let cmd = buffer.trim().to_string();
                    self.mode = VimMode::Normal;
                    return if cmd.is_empty() {
                        VimAction::NoOp
                    } else {
                        VimAction::ExecuteCommand(cmd)
                    };
                }
                if key.chars().count() == 1 {
                    buffer.push_str(key);
                }
                VimAction::NoOp
            }
        }
    }
}
