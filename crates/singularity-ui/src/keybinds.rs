//! Global Command Palette Registry (`Ctrl+K` / `F2`), Multi-Chord Keymap Table,
//! User Command Chains (Macros), and Mouse / Rocker / MRU-Wheel Gesture Recognizer.
//!
//! 100% pure Rust implementation designed for the Singularity OLED UI shell.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::Path;
use thiserror::Error;

/// Maximum number of steps permitted in a single expanded command chain.
pub const MAX_CHAIN_STEPS: usize = 64;
/// Maximum nested recursion depth when a command chain invokes another chain.
pub const MAX_CHAIN_RECURSION_DEPTH: usize = 16;

/// Errors produced by keybinding parsing, persistence, or command chain validation.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum KeybindError {
    #[error("Invalid key chord syntax: {0}")]
    InvalidChord(String),
    #[error("Empty key sequence")]
    EmptySequence,
    #[error("Command chain '{0}' not found")]
    ChainNotFound(String),
    #[error("Command chain '{0}' exceeds maximum of {1} steps")]
    TooManySteps(String, usize),
    #[error("Command chain recursion limit ({0}) exceeded")]
    RecursionDepthExceeded(usize),
    #[error("Circular recursion detected in command chain '{0}'")]
    CyclicChain(String),
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("I/O error: {0}")]
    Io(String),
}

// ============================================================================
// 1. CommandRegistry & Fuzzy Search (Command Palette Ctrl+K / F2)
// ============================================================================

/// Functional grouping of browser commands in the Command Palette and Shortcuts UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandCategory {
    Navigation,
    Tabs,
    SplitView,
    Workspaces,
    Sidebar,
    Zoom,
    Reader,
    Translate,
    TextToSpeech,
    Capture,
    Print,
    DevTools,
    Profiles,
    Vault,
    Shield,
    Mullvad,
    Sync,
    Themes,
    Flags,
    TaskManager,
    Window,
}

impl CommandCategory {
    pub fn label_en(&self) -> &'static str {
        match self {
            Self::Navigation => "Navigation",
            Self::Tabs => "Tabs",
            Self::SplitView => "Split View",
            Self::Workspaces => "Workspaces",
            Self::Sidebar => "Sidebar",
            Self::Zoom => "Zoom",
            Self::Reader => "Reader Mode",
            Self::Translate => "Translation",
            Self::TextToSpeech => "Read Aloud (TTS)",
            Self::Capture => "Capture & Screenshot",
            Self::Print => "Print & Page",
            Self::DevTools => "Developer Tools",
            Self::Profiles => "Profiles",
            Self::Vault => "Password Vault",
            Self::Shield => "Privacy Shield",
            Self::Mullvad => "Mullvad VPN",
            Self::Sync => "Sync",
            Self::Themes => "Themes & Appearance",
            Self::Flags => "Flags & Internal",
            Self::TaskManager => "Task Manager & Diagnostics",
            Self::Window => "Window & Layout",
        }
    }

    pub fn label_fr(&self) -> &'static str {
        match self {
            Self::Navigation => "Navigation",
            Self::Tabs => "Onglets",
            Self::SplitView => "Vue Scindée",
            Self::Workspaces => "Espaces de travail",
            Self::Sidebar => "Barre latérale",
            Self::Zoom => "Zoom",
            Self::Reader => "Mode Lecture",
            Self::Translate => "Traduction",
            Self::TextToSpeech => "Lecture vocale (TTS)",
            Self::Capture => "Capture d'écran",
            Self::Print => "Impression & Page",
            Self::DevTools => "Outils Développeur",
            Self::Profiles => "Profils",
            Self::Vault => "Coffre-fort",
            Self::Shield => "Bouclier Vie Privée",
            Self::Mullvad => "Mullvad VPN",
            Self::Sync => "Synchronisation",
            Self::Themes => "Thèmes & Apparence",
            Self::Flags => "Flags & Pages Internes",
            Self::TaskManager => "Gestionnaire de tâches",
            Self::Window => "Fenêtre & Affichage",
        }
    }
}

/// Metadata descriptor for an executable browser command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserCommand {
    pub id: String,
    pub title_en: String,
    pub title_fr: String,
    pub category: CommandCategory,
    pub keywords: Vec<String>,
    pub default_shortcut: Option<String>,
    pub icon: String,
}

/// Ranked result item returned by [`CommandRegistry::search_commands`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandSearchResult {
    pub command: BrowserCommand,
    pub score: i32,
}

/// Central searchable catalog of built-in and user/extension browser commands.
#[derive(Debug, Clone)]
pub struct CommandRegistry {
    commands: Vec<BrowserCommand>,
    index_by_id: HashMap<String, usize>,
}

impl Default for CommandRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl CommandRegistry {
    /// Creates a registry pre-populated with 80+ built-in browser commands.
    pub fn new() -> Self {
        let mut reg = Self {
            commands: Vec::with_capacity(96),
            index_by_id: HashMap::with_capacity(96),
        };
        for cmd in Self::builtin_commands() {
            reg.register(cmd);
        }
        reg
    }

    /// Registers or updates a command by ID.
    pub fn register(&mut self, cmd: BrowserCommand) {
        if let Some(&idx) = self.index_by_id.get(&cmd.id) {
            self.commands[idx] = cmd;
        } else {
            let idx = self.commands.len();
            self.index_by_id.insert(cmd.id.clone(), idx);
            self.commands.push(cmd);
        }
    }

    pub fn get(&self, id: &str) -> Option<&BrowserCommand> {
        self.index_by_id.get(id).map(|&i| &self.commands[i])
    }

    pub fn all(&self) -> &[BrowserCommand] {
        &self.commands
    }

    pub fn len(&self) -> usize {
        self.commands.len()
    }

    pub fn is_empty(&self) -> bool {
        self.commands.is_empty()
    }

    pub fn by_category(&self, category: CommandCategory) -> Vec<&BrowserCommand> {
        self.commands
            .iter()
            .filter(|c| c.category == category)
            .collect()
    }

    /// Instant accent-folding fuzzy search across ID, English title, French title,
    /// category names, and keyword tags for the Command Palette (`Ctrl+K` / `F2`).
    pub fn search_commands(&self, query: &str) -> Vec<CommandSearchResult> {
        let normalized_query = fold_ascii_lowercase(query.trim());
        if normalized_query.is_empty() {
            return self
                .commands
                .iter()
                .enumerate()
                .map(|(i, cmd)| CommandSearchResult {
                    command: cmd.clone(),
                    score: 1000 - (i as i32),
                })
                .collect();
        }

        let tokens: Vec<&str> = normalized_query.split_whitespace().collect();
        let mut results = Vec::new();

        for cmd in &self.commands {
            let id_fold = fold_ascii_lowercase(&cmd.id);
            let en_fold = fold_ascii_lowercase(&cmd.title_en);
            let fr_fold = fold_ascii_lowercase(&cmd.title_fr);
            let cat_en = fold_ascii_lowercase(cmd.category.label_en());
            let cat_fr = fold_ascii_lowercase(cmd.category.label_fr());
            let kw_folds: Vec<String> = cmd
                .keywords
                .iter()
                .map(|k| fold_ascii_lowercase(k))
                .collect();

            let mut total_score: i32 = 0;
            let mut all_tokens_matched = true;

            for token in &tokens {
                let mut best_token_score: Option<i32> = None;

                let mut consider = |candidate: Option<i32>| {
                    if let Some(s) = candidate {
                        best_token_score = Some(best_token_score.map_or(s, |prev| prev.max(s)));
                    }
                };

                consider(fuzzy_field_score(token, &id_fold, 140));
                consider(fuzzy_field_score(token, &en_fold, 130));
                consider(fuzzy_field_score(token, &fr_fold, 130));
                consider(fuzzy_field_score(token, &cat_en, 70));
                consider(fuzzy_field_score(token, &cat_fr, 70));
                for kw in &kw_folds {
                    consider(fuzzy_field_score(token, kw, 100));
                }

                if let Some(s) = best_token_score {
                    total_score += s;
                } else {
                    all_tokens_matched = false;
                    break;
                }
            }

            if all_tokens_matched {
                // Full-phrase bonus on titles or ID
                if id_fold == normalized_query
                    || en_fold == normalized_query
                    || fr_fold == normalized_query
                {
                    total_score += 500;
                } else if en_fold.starts_with(&normalized_query)
                    || fr_fold.starts_with(&normalized_query)
                {
                    total_score += 200;
                }
                results.push(CommandSearchResult {
                    command: cmd.clone(),
                    score: total_score,
                });
            }
        }

        results.sort_by(|a, b| {
            b.score
                .cmp(&a.score)
                .then_with(|| a.command.id.cmp(&b.command.id))
        });
        results
    }

    /// Full built-in catalog covering all 21 browser subsystems (84 commands).
    pub fn builtin_commands() -> Vec<BrowserCommand> {
        fn c(
            id: &str,
            title_en: &str,
            title_fr: &str,
            category: CommandCategory,
            keywords: &[&str],
            default_shortcut: Option<&str>,
            icon: &str,
        ) -> BrowserCommand {
            BrowserCommand {
                id: id.into(),
                title_en: title_en.into(),
                title_fr: title_fr.into(),
                category,
                keywords: keywords.iter().map(|s| (*s).into()).collect(),
                default_shortcut: default_shortcut.map(String::from),
                icon: icon.into(),
            }
        }

        use CommandCategory::*;
        vec![
            // --- Navigation (10) ---
            c("nav.back", "Navigate Back", "Page précédente", Navigation, &["back", "retour", "history"], Some("Alt+ArrowLeft"), "arrow-left"),
            c("nav.forward", "Navigate Forward", "Page suivante", Navigation, &["forward", "avancer", "history"], Some("Alt+ArrowRight"), "arrow-right"),
            c("nav.reload", "Reload Page", "Actualiser la page", Navigation, &["refresh", "recharger", "f5"], Some("Ctrl+R"), "rotate-cw"),
            c("nav.hard_reload", "Hard Reload (Bypass Cache)", "Rechargement forcé (sans cache)", Navigation, &["cache", "force", "reload"], Some("Ctrl+Shift+R"), "refresh-ccw"),
            c("nav.stop", "Stop Loading", "Arrêter le chargement", Navigation, &["cancel", "stop", "esc"], Some("Escape"), "x-circle"),
            c("nav.home", "Open Home Page", "Ouvrir la page d'accueil", Navigation, &["home", "accueil", "start"], Some("Alt+Home"), "home"),
            c("nav.focus_omnibox", "Focus Address Bar", "Focus barre d'adresse", Navigation, &["url", "omnibox", "search", "adresse"], Some("Ctrl+L"), "search"),
            c("nav.copy_url", "Copy Current URL", "Copier l'URL actuelle", Navigation, &["clipboard", "link", "lien", "share"], Some("Ctrl+Shift+C"), "link"),
            c("nav.open_file", "Open Local File", "Ouvrir un fichier local", Navigation, &["file", "fichier", "html"], Some("Ctrl+O"), "folder-open"),
            c("nav.save_page", "Save Page As...", "Enregistrer la page sous...", Navigation, &["save", "enregistrer", "download", "mhtml"], Some("Ctrl+S"), "save"),

            // --- Tabs (18) ---
            c("tab.new", "New Tab", "Nouvel onglet", Tabs, &["open", "create", "onglet"], Some("Ctrl+T"), "plus"),
            c("tab.close", "Close Current Tab", "Fermer l'onglet actif", Tabs, &["close", "fermer", "kill"], Some("Ctrl+W"), "x"),
            c("tab.reopen_closed", "Reopen Last Closed Tab", "Rouvrir le dernier onglet fermé", Tabs, &["undo", "restore", "annuler", "fermé"], Some("Ctrl+Shift+T"), "undo"),
            c("tab.duplicate", "Duplicate Current Tab", "Dupliquer l'onglet actif", Tabs, &["clone", "copy", "dupliquer"], Some("Ctrl+Shift+D"), "copy"),
            c("tab.pin_toggle", "Pin / Unpin Tab", "Épingler / Désépingler l'onglet", Tabs, &["pin", "epingler", "lock"], Some("Alt+P"), "pin"),
            c("tab.mute_toggle", "Mute / Unmute Tab Audio", "Couper / Activer le son de l'onglet", Tabs, &["audio", "sound", "muet", "silence"], Some("Ctrl+M"), "volume-x"),
            c("tab.next", "Next Tab", "Onglet suivant", Tabs, &["switch", "right", "suivant"], Some("Ctrl+Tab"), "chevron-right"),
            c("tab.prev", "Previous Tab", "Onglet précédent", Tabs, &["switch", "left", "precedent"], Some("Ctrl+Shift+Tab"), "chevron-left"),
            c("tab.mru_next", "Cycle Recent Tabs (MRU)", "Basculer vers l'onglet récent (MRU)", Tabs, &["recent", "mru", "cycle"], Some("Alt+Tab"), "layers"),
            c("tab.move_left", "Move Tab Left", "Déplacer l'onglet à gauche", Tabs, &["reorder", "gauche"], Some("Ctrl+Shift+PageUp"), "arrow-left-circle"),
            c("tab.move_right", "Move Tab Right", "Déplacer l'onglet à droite", Tabs, &["reorder", "droite"], Some("Ctrl+Shift+PageDown"), "arrow-right-circle"),
            c("tab.close_others", "Close Other Tabs", "Fermer les autres onglets", Tabs, &["cleanup", "autres"], None, "x-square"),
            c("tab.close_right", "Close Tabs to the Right", "Fermer les onglets à droite", Tabs, &["cleanup", "droite"], None, "arrow-right-to-line"),
            c("tab.hibernate", "Hibernate / Discard Tab (Save RAM)", "Mettre l'onglet en veille (RAM)", Tabs, &["sleep", "memory", "ram", "discard", "veille"], Some("Alt+Shift+H"), "moon"),
            c("tab.group_new", "Add Tab to New Group", "Ajouter l'onglet à un nouveau groupe", Tabs, &["group", "groupe", "organize"], Some("Ctrl+Shift+G"), "folder-plus"),
            c("tab.group_toggle_collapse", "Collapse / Expand Tab Group", "Replier / Déplier le groupe d'onglets", Tabs, &["group", "collapse", "replier"], None, "chevrons-up-down"),
            c("tab.search", "Search Open Tabs", "Rechercher dans les onglets ouverts", Tabs, &["find", "tabs", "switch", "chercher"], Some("Ctrl+Shift+A"), "list-filter"),
            c("tab.jump_last", "Jump to Last Tab", "Aller au dernier onglet", Tabs, &["last", "end", "dernier"], Some("Ctrl+9"), "skip-forward"),

            // --- Split View (5) ---
            c("split.vertical", "Split View Side-by-Side", "Vue scindée côte à côte", SplitView, &["tile", "side", "pane", "scinder"], Some("Ctrl+Alt+V"), "columns"),
            c("split.horizontal", "Split View Top & Bottom", "Vue scindée haut / bas", SplitView, &["tile", "stack", "pane", "scinder"], Some("Ctrl+Alt+H"), "rows"),
            c("split.grid", "Tile Tabs in 2x2 Grid", "Disposition en grille 2x2", SplitView, &["grid", "grille", "quad"], Some("Ctrl+Alt+G"), "layout-grid"),
            c("split.swap", "Swap Split View Panes", "Inverser les panneaux scindés", SplitView, &["swap", "inverser", "flip"], Some("Ctrl+Alt+S"), "arrow-left-right"),
            c("split.close", "Close Split View", "Quitter la vue scindée", SplitView, &["unsplit", "merge", "fermer"], Some("Ctrl+Alt+X"), "maximize-2"),

            // --- Workspaces (5) ---
            c("workspace.picker", "Switch Workspace", "Changer d'espace de travail", Workspaces, &["space", "espace", "project"], Some("Ctrl+Shift+W"), "briefcase"),
            c("workspace.next", "Next Workspace", "Espace de travail suivant", Workspaces, &["space", "suivant"], Some("Ctrl+Alt+ArrowRight"), "chevron-right"),
            c("workspace.prev", "Previous Workspace", "Espace de travail précédent", Workspaces, &["space", "precedent"], Some("Ctrl+Alt+ArrowLeft"), "chevron-left"),
            c("workspace.new", "Create New Workspace", "Créer un nouvel espace de travail", Workspaces, &["space", "new", "nouveau"], None, "folder-plus"),
            c("workspace.move_tab", "Move Tab to Another Workspace", "Déplacer l'onglet vers un espace", Workspaces, &["send", "move", "espace"], None, "send"),

            // --- Sidebar (7) ---
            c("sidebar.toggle", "Toggle Sidebar", "Afficher / Masquer la barre latérale", Sidebar, &["panel", "dock", "laterale"], Some("Ctrl+B"), "panel-left"),
            c("sidebar.bookmarks", "Open Bookmarks Panel", "Ouvrir les favoris", Sidebar, &["favorites", "favoris", "stars"], Some("Ctrl+Shift+O"), "bookmark"),
            c("sidebar.history", "Open History", "Ouvrir l'historique", Sidebar, &["recent", "visited", "historique"], Some("Ctrl+H"), "clock"),
            c("sidebar.downloads", "Open Downloads", "Ouvrir les téléchargements", Sidebar, &["files", "telechargements"], Some("Ctrl+J"), "download"),
            c("sidebar.notes", "Open Notes Panel", "Ouvrir le panneau Notes", Sidebar, &["markdown", "memo", "notes"], Some("Alt+Shift+N"), "file-text"),
            c("sidebar.reading_list", "Open Reading List", "Ouvrir la liste de lecture", Sidebar, &["read later", "articles", "lecture"], Some("Alt+Shift+R"), "book-open"),
            c("sidebar.web_panel", "Toggle Active Web Panel", "Basculer le panneau Web latéral", Sidebar, &["webpanel", "messenger", "whatsapp", "discord"], Some("F4"), "sidebar"),

            // --- Zoom (3) ---
            c("zoom.in", "Zoom In", "Agrandir le zoom", Zoom, &["magnify", "bigger", "plus"], Some("Ctrl+="), "zoom-in"),
            c("zoom.out", "Zoom Out", "Réduire le zoom", Zoom, &["shrink", "smaller", "minus"], Some("Ctrl+-"), "zoom-out"),
            c("zoom.reset", "Reset Zoom (100%)", "Réinitialiser le zoom (100%)", Zoom, &["100%", "default", "normal"], Some("Ctrl+0"), "maximize"),

            // --- Reader / Translate / TTS (5) ---
            c("reader.toggle", "Toggle Reader Mode", "Activer / Quitter le mode lecture", Reader, &["article", "distraction", "lecture", "clean"], Some("Alt+R"), "book"),
            c("translate.page", "Translate Current Page", "Traduire la page active", Translate, &["language", "langue", "traduire"], Some("Alt+T"), "languages"),
            c("translate.selection", "Translate Selected Text", "Traduire le texte sélectionné", Translate, &["selection", "langue", "traduire"], None, "globe"),
            c("tts.read_aloud", "Read Page Aloud (TTS)", "Lire la page à voix haute (TTS)", TextToSpeech, &["speech", "voice", "audio", "voix", "tts"], Some("Ctrl+Shift+U"), "volume-2"),
            c("tts.stop", "Stop Read Aloud", "Arrêter la lecture vocale", TextToSpeech, &["tts", "stop", "silence"], None, "square"),

            // --- Capture & Print (7) ---
            c("capture.visible", "Capture Visible Area", "Capturer la zone visible", Capture, &["screenshot", "screen", "capture"], Some("Ctrl+Shift+S"), "camera"),
            c("capture.full_page", "Capture Full Scrolling Page", "Capturer toute la page", Capture, &["fullpage", "scroll", "screenshot"], Some("Ctrl+Alt+P"), "image"),
            c("capture.region", "Capture Selected Region", "Capturer une région", Capture, &["crop", "area", "selection", "screenshot"], None, "crop"),
            c("capture.open_editor", "Open Capture Annotation Editor", "Ouvrir l'éditeur d'annotation", Capture, &["annotate", "draw", "edit"], None, "edit-3"),
            c("page.print", "Print Page", "Imprimer la page", Print, &["printer", "imprimer"], Some("Ctrl+P"), "printer"),
            c("page.export_pdf", "Export Page as PDF", "Exporter la page en PDF", Print, &["pdf", "document", "export"], None, "file-down"),
            c("page.find_in_page", "Find in Page", "Rechercher dans la page", Print, &["search", "ctrl+f", "trouver"], Some("Ctrl+F"), "search"),

            // --- DevTools (5) ---
            c("devtools.toggle", "Toggle Developer Tools", "Ouvrir / Fermer les outils développeur", DevTools, &["inspect", "f12", "debug", "dev"], Some("F12"), "code"),
            c("devtools.elements", "Inspect Element", "Inspecter l'élément", DevTools, &["dom", "css", "inspector"], Some("Ctrl+Shift+I"), "mouse-pointer"),
            c("devtools.console", "Open JavaScript Console", "Ouvrir la console JavaScript", DevTools, &["js", "logs", "console"], Some("Ctrl+Shift+J"), "terminal"),
            c("devtools.network", "Open Network Inspector", "Ouvrir l'inspecteur réseau", DevTools, &["http", "requests", "xhr", "reseau"], Some("Ctrl+Shift+E"), "activity"),
            c("page.view_source", "View Page Source", "Afficher le code source", DevTools, &["html", "source"], Some("Ctrl+U"), "file-code"),

            // --- Profiles & Window (7) ---
            c("profile.switch", "Switch User Profile", "Changer de profil utilisateur", Profiles, &["account", "profil", "identity"], Some("Ctrl+Shift+M"), "users"),
            c("profile.new_guest", "Open Ephemeral Guest Window", "Ouvrir une fenêtre Invité éphémère", Profiles, &["guest", "invite", "ephemeral"], None, "user-x"),
            c("window.new", "New Browser Window", "Nouvelle fenêtre", Window, &["window", "fenetre"], Some("Ctrl+N"), "app-window"),
            c("window.new_private", "New Private Window", "Nouvelle fenêtre privée", Window, &["incognito", "private", "privee"], Some("Ctrl+Shift+N"), "eye-off"),
            c("window.fullscreen", "Toggle Fullscreen", "Activer / Quitter le plein écran", Window, &["f11", "fullscreen", "plein ecran"], Some("F11"), "maximize"),
            c("window.zen_mode", "Toggle Zen Mode (Zero Chrome)", "Activer le mode Zen (sans interface)", Window, &["focus", "minimal", "hide", "zen"], Some("Ctrl+Shift+Z"), "sparkles"),
            c("window.pip", "Toggle Picture-in-Picture", "Activer l'incrustation vidéo (PiP)", Window, &["video", "pip", "floating"], Some("Alt+Shift+P"), "picture-in-picture"),

            // --- Vault (4) ---
            c("vault.open", "Open Password & 2FA Vault", "Ouvrir le coffre-fort mots de passe & 2FA", Vault, &["passwords", "totp", "argon2", "coffre"], Some("Ctrl+Shift+L"), "key"),
            c("vault.lock", "Lock Vault Immediately", "Verrouiller le coffre-fort", Vault, &["lock", "verrouiller", "zeroize"], None, "lock"),
            c("vault.autofill", "Autofill Credentials", "Remplissage automatique des identifiants", Vault, &["login", "fill", "password"], Some("Ctrl+Shift+F"), "log-in"),
            c("vault.generate_password", "Generate Strong Password", "Générer un mot de passe fort", Vault, &["diceware", "random", "generator"], None, "dices"),

            // --- Shield (4) ---
            c("shield.toggle_site", "Toggle Privacy Shield for Site", "Activer / Couper le Bouclier sur ce site", Shield, &["adblock", "trackers", "bouclier", "ublock"], Some("Alt+Shift+S"), "shield"),
            c("shield.element_zapper", "Launch Element Zapper", "Lancer le Zappeur d'éléments", Shield, &["cosmetic", "hide", "picker", "zapper"], Some("Alt+Z"), "zap"),
            c("shield.clear_browsing_data", "Clear Browsing Data", "Effacer les données de navigation", Shield, &["cookies", "cache", "history", "nettoyer"], Some("Ctrl+Shift+Delete"), "trash-2"),
            c("shield.toggle_dark_reader", "Toggle Native OLED Dark Mode for Site", "Activer le mode sombre OLED sur ce site", Shield, &["dark", "oled", "night", "sombre"], Some("Alt+Shift+D"), "contrast"),

            // --- Mullvad VPN (3) ---
            c("mullvad.toggle", "Connect / Disconnect Mullvad VPN", "Connecter / Déconnecter Mullvad VPN", Mullvad, &["vpn", "wireguard", "tunnel"], Some("Alt+Shift+M"), "shield-check"),
            c("mullvad.quick_hop", "Mullvad Quick Multi-Hop Relay", "Changement rapide de relais Mullvad", Mullvad, &["relay", "hop", "country", "vpn"], Some("Alt+M"), "shuffle"),
            c("mullvad.toggle_killswitch", "Toggle Strict Mullvad Kill-Switch", "Basculer le Kill-Switch Mullvad", Mullvad, &["killswitch", "leak", "block"], None, "power"),

            // --- Sync & Themes (4) ---
            c("sync.now", "Sync Encrypted Profile Now", "Synchroniser le profil chiffré", Sync, &["backup", "cloud", "sync"], None, "refresh-cw"),
            c("sync.settings", "Open Sync Settings", "Ouvrir les paramètres de synchronisation", Sync, &["devices", "pair", "sync"], None, "cloud"),
            c("theme.cycle", "Cycle Cosmic OLED Theme", "Changer de thème cosmique OLED", Themes, &["soleil", "pulsar", "nebuleuse", "eclipse", "aurore", "theme"], Some("Alt+Shift+T"), "palette"),
            c("theme.open_customizer", "Open Theme & Boost Customizer", "Ouvrir la personnalisation des thèmes", Themes, &["appearance", "css", "boost", "theme"], None, "sliders"),

            // --- Flags, Internal Pages & Task Manager (10) ---
            c("ui.command_palette", "Open Command Palette", "Ouvrir la palette de commandes", Flags, &["palette", "quick", "commands", "f2"], Some("Ctrl+K"), "command"),
            c("ui.shortcuts_help", "Show Keyboard Shortcuts", "Afficher les raccourcis clavier", Flags, &["keybinds", "cheatsheet", "help", "raccourcis"], Some("Ctrl+K, Ctrl+S"), "keyboard"),
            c("internal.settings", "Open Settings", "Ouvrir les paramètres", Flags, &["preferences", "config", "parametres"], Some("Ctrl+,"), "settings"),
            c("internal.flags", "Open Experimental Flags", "Ouvrir les options expérimentales (Flags)", Flags, &["experiments", "browser://flags"], None, "flag"),
            c("internal.urls", "List All Internal Pages", "Lister toutes les pages internes", Flags, &["browser://urls", "chrome://urls", "about"], None, "compass"),
            c("internal.extensions", "Manage Extensions", "Gérer les extensions", Flags, &["addons", "crx", "extensions"], None, "puzzle"),
            c("internal.userscripts", "Manage Userscripts", "Gérer les scripts utilisateurs (Userscripts)", Flags, &["tampermonkey", "violentmonkey", "gm", "scripts"], None, "scroll"),
            c("internal.apps", "Manage Installed Web Apps (PWAs)", "Gérer les applications Web (PWA)", Flags, &["pwa", "install", "apps"], None, "grid"),
            c("internal.process_manager", "Open Browser Task Manager", "Ouvrir le gestionnaire de tâches", TaskManager, &["processes", "cpu", "ram", "memory", "taches"], Some("Shift+Escape"), "cpu"),
            c("internal.performance", "Open Performance & 200Hz Monitor", "Ouvrir le moniteur de performances", TaskManager, &["fps", "gpu", "tracing", "perf"], None, "gauge"),
        ]
    }
}

/// Folds common Latin accents and lowercases for bilingual EN/FR fuzzy matching.
fn fold_ascii_lowercase(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars().flat_map(|c| c.to_lowercase()) {
        let mapped = match ch {
            'à' | 'á' | 'â' | 'ã' | 'ä' | 'å' => 'a',
            'ç' => 'c',
            'è' | 'é' | 'ê' | 'ë' => 'e',
            'ì' | 'í' | 'î' | 'ï' => 'i',
            'ñ' => 'n',
            'ò' | 'ó' | 'ô' | 'õ' | 'ö' => 'o',
            'ù' | 'ú' | 'û' | 'ü' => 'u',
            'ý' | 'ÿ' => 'y',
            'œ' => {
                out.push_str("oe");
                continue;
            }
            'æ' => {
                out.push_str("ae");
                continue;
            }
            other => other,
        };
        out.push(mapped);
    }
    out
}

/// Scores a folded query token against a folded target field.
fn fuzzy_field_score(token: &str, field: &str, weight: i32) -> Option<i32> {
    if token.is_empty() || field.is_empty() {
        return None;
    }
    if field == token {
        return Some(weight * 4);
    }
    if field.starts_with(token) {
        return Some(weight * 3 + 30);
    }
    if let Some(pos) = field.find(token) {
        let boundary = pos == 0
            || matches!(
                field.as_bytes().get(pos.saturating_sub(1)),
                Some(b' ' | b'.' | b'_' | b'-' | b'/')
            );
        let bonus = if boundary { 25 } else { 0 };
        return Some(weight * 2 + bonus - (pos as i32).min(40));
    }

    // Subsequence fuzzy match with consecutive-character & word-boundary bonuses
    let q_chars: Vec<char> = token.chars().collect();
    let f_chars: Vec<char> = field.chars().collect();
    let mut qi = 0usize;
    let mut streak = 0i32;
    let mut subseq_bonus = 0i32;
    let mut last_match_idx: Option<usize> = None;

    for (fi, &fc) in f_chars.iter().enumerate() {
        if qi < q_chars.len() && fc == q_chars[qi] {
            if last_match_idx.map_or(false, |prev| prev + 1 == fi) {
                streak += 1;
                subseq_bonus += 8 * streak;
            } else {
                streak = 0;
            }
            if fi == 0 || matches!(f_chars[fi - 1], ' ' | '.' | '_' | '-' | '/') {
                subseq_bonus += 12;
            }
            last_match_idx = Some(fi);
            qi += 1;
        }
    }

    if qi == q_chars.len() {
        let penalty = (f_chars.len().saturating_sub(q_chars.len()) as i32).min(60);
        Some((weight + subseq_bonus - penalty).max(1))
    } else {
        None
    }
}

// ============================================================================
// 2. KeyChord, KeySequence, KeymapPreset & KeymapTable
// ============================================================================

/// Single keyboard combination (modifiers + canonical key name).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct KeyChord {
    #[serde(default)]
    pub ctrl: bool,
    #[serde(default)]
    pub alt: bool,
    #[serde(default)]
    pub shift: bool,
    #[serde(default)]
    pub meta: bool,
    pub key: String,
}

impl KeyChord {
    pub fn new(ctrl: bool, alt: bool, shift: bool, meta: bool, key: &str) -> Result<Self, KeybindError> {
        let canonical = canonicalize_key_name(key)?;
        Ok(Self {
            ctrl,
            alt,
            shift,
            meta,
            key: canonical,
        })
    }

    /// Parses strings like `"Ctrl+Shift+T"`, `"Alt+ArrowLeft"`, `"F2"`, `"Ctrl++"`.
    pub fn parse(raw: &str) -> Result<Self, KeybindError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(KeybindError::InvalidChord("empty chord".into()));
        }

        // Special handling when literal '+' is the final key (e.g. "Ctrl++" or "+")
        let (parts_str, trailing_plus) = if trimmed == "+" {
            ("", true)
        } else if let Some(prefix) = trimmed.strip_suffix("++") {
            (prefix, true)
        } else {
            (trimmed, false)
        };

        let mut ctrl = false;
        let mut alt = false;
        let mut shift = false;
        let mut meta = false;
        let mut key: Option<String> = if trailing_plus {
            Some("+".into())
        } else {
            None
        };

        for part in parts_str.split('+').filter(|p| !p.trim().is_empty()) {
            let p = part.trim();
            match p.to_ascii_lowercase().as_str() {
                "ctrl" | "control" => ctrl = true,
                "alt" | "option" => alt = true,
                "shift" => shift = true,
                "meta" | "cmd" | "command" | "super" | "win" => meta = true,
                _ => {
                    if key.is_some() {
                        return Err(KeybindError::InvalidChord(format!(
                            "multiple non-modifier keys in '{}'",
                            raw
                        )));
                    }
                    key = Some(canonicalize_key_name(p)?);
                }
            }
        }

        let final_key = key.ok_or_else(|| {
            KeybindError::InvalidChord(format!("missing primary key in '{}'", raw))
        })?;

        Ok(Self {
            ctrl,
            alt,
            shift,
            meta,
            key: final_key,
        })
    }

    /// Formats the chord in canonical deterministic order (`Ctrl+Alt+Shift+Meta+Key`).
    pub fn to_canonical_string(&self) -> String {
        let mut parts: Vec<&str> = Vec::with_capacity(5);
        if self.ctrl {
            parts.push("Ctrl");
        }
        if self.alt {
            parts.push("Alt");
        }
        if self.shift {
            parts.push("Shift");
        }
        if self.meta {
            parts.push("Meta");
        }
        parts.push(&self.key);
        parts.join("+")
    }
}

fn canonicalize_key_name(raw: &str) -> Result<String, KeybindError> {
    let k = raw.trim();
    if k.is_empty() {
        return Err(KeybindError::InvalidChord("empty key".into()));
    }
    let lower = k.to_ascii_lowercase();
    let normalized = match lower.as_str() {
        "esc" | "escape" => "Escape".into(),
        "tab" => "Tab".into(),
        "enter" | "return" => "Enter".into(),
        "space" | "spacebar" => "Space".into(),
        "backspace" | "bksp" => "Backspace".into(),
        "del" | "delete" => "Delete".into(),
        "ins" | "insert" => "Insert".into(),
        "home" => "Home".into(),
        "end" => "End".into(),
        "pgup" | "pageup" => "PageUp".into(),
        "pgdn" | "pagedown" => "PageDown".into(),
        "left" | "arrowleft" => "ArrowLeft".into(),
        "right" | "arrowright" => "ArrowRight".into(),
        "up" | "arrowup" => "ArrowUp".into(),
        "down" | "arrowdown" => "ArrowDown".into(),
        "plus" => "+".into(),
        "minus" => "-".into(),
        "comma" => ",".into(),
        "period" => ".".into(),
        "slash" => "/".into(),
        _ if lower.starts_with('f') && lower.len() <= 3 && lower[1..].chars().all(|c| c.is_ascii_digit()) => {
            let num: u8 = lower[1..]
                .parse()
                .map_err(|_| KeybindError::InvalidChord(raw.into()))?;
            if (1..=24).contains(&num) {
                format!("F{}", num)
            } else {
                return Err(KeybindError::InvalidChord(raw.into()));
            }
        }
        _ if k.chars().count() == 1 => {
            let ch = k.chars().next().unwrap();
            if ch.is_ascii_alphabetic() {
                ch.to_ascii_uppercase().to_string()
            } else {
                ch.to_string()
            }
        }
        _ => k.to_string(),
    };
    Ok(normalized)
}

/// Ordered sequence of 1 or more key chords, supporting VS Code / Vim multi-key chords
/// such as `Ctrl+K, Ctrl+S` or `G, G`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct KeySequence(pub Vec<KeyChord>);

impl KeySequence {
    /// Parses a comma-separated sequence of key chords (e.g. `"Ctrl+K, Ctrl+S"`).
    /// Also correctly handles a literal comma key like `"Ctrl+,"`.
    pub fn parse(raw: &str) -> Result<Self, KeybindError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(KeybindError::EmptySequence);
        }

        // Split on ", " (or comma that is NOT immediately preceded by '+' or standalone ",")
        let mut segments = Vec::new();
        let mut current = String::new();
        let chars: Vec<char> = trimmed.chars().collect();
        let mut i = 0usize;
        while i < chars.len() {
            let ch = chars[i];
            if ch == ',' {
                let prev_is_plus = current.trim_end().ends_with('+');
                let current_empty = current.trim().is_empty();
                if prev_is_plus || (current_empty && i + 1 == chars.len()) {
                    current.push(ch);
                } else {
                    if !current.trim().is_empty() {
                        segments.push(current.trim().to_string());
                    }
                    current.clear();
                }
            } else {
                current.push(ch);
            }
            i += 1;
        }
        if !current.trim().is_empty() {
            segments.push(current.trim().to_string());
        }

        if segments.is_empty() {
            return Err(KeybindError::EmptySequence);
        }

        let mut chords = Vec::with_capacity(segments.len());
        for seg in segments {
            chords.push(KeyChord::parse(&seg)?);
        }
        Ok(Self(chords))
    }

    pub fn to_canonical_string(&self) -> String {
        self.0
            .iter()
            .map(KeyChord::to_canonical_string)
            .collect::<Vec<_>>()
            .join(", ")
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn starts_with(&self, prefix: &[KeyChord]) -> bool {
        !prefix.is_empty() && self.0.len() >= prefix.len() && self.0[..prefix.len()] == *prefix
    }
}

/// Complete built-in keymap presets selectable by the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeymapPreset {
    ChromeEdge,
    Vivaldi,
    Arc,
    VimModal,
}

impl Default for KeymapPreset {
    fn default() -> Self {
        Self::ChromeEdge
    }
}

/// Conflict report item returned by [`KeymapTable::find_conflicts`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyConflict {
    pub sequence: KeySequence,
    pub command_ids: Vec<String>,
    /// True when `sequence` is a strict prefix of one or more longer multi-key chords.
    pub is_prefix_shadow: bool,
    pub shadowed_command_ids: Vec<String>,
}

/// Outcome of evaluating an in-progress chord buffer against a [`KeymapTable`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChordResolution {
    Matched(String),
    PendingPrefix(Vec<String>),
    NoMatch,
}

/// Keybinding table combining a base [`KeymapPreset`] with a persistent `user_overrides` layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeymapTable {
    pub preset: KeymapPreset,
    /// `Some(seq)` binds/overrides a command; `None` explicitly unbinds a preset shortcut.
    #[serde(default)]
    pub user_overrides: BTreeMap<String, Option<KeySequence>>,
}

impl Default for KeymapTable {
    fn default() -> Self {
        Self::from_preset(KeymapPreset::ChromeEdge)
    }
}

impl KeymapTable {
    pub fn from_preset(preset: KeymapPreset) -> Self {
        Self {
            preset,
            user_overrides: BTreeMap::new(),
        }
    }

    /// Returns the base bindings for a preset before `user_overrides` are layered.
    pub fn preset_bindings(preset: KeymapPreset) -> BTreeMap<String, KeySequence> {
        let mut map = BTreeMap::new();
        let mut add = |cmd: &str, seq: &str| {
            if let Ok(parsed) = KeySequence::parse(seq) {
                map.insert(cmd.to_string(), parsed);
            }
        };

        // Shared core bindings across presets
        add("nav.back", "Alt+ArrowLeft");
        add("nav.forward", "Alt+ArrowRight");
        add("nav.reload", "Ctrl+R");
        add("nav.hard_reload", "Ctrl+Shift+R");
        add("nav.stop", "Escape");
        add("nav.focus_omnibox", "Ctrl+L");
        add("nav.open_file", "Ctrl+O");
        add("tab.new", "Ctrl+T");
        add("tab.close", "Ctrl+W");
        add("tab.reopen_closed", "Ctrl+Shift+T");
        add("tab.next", "Ctrl+Tab");
        add("tab.prev", "Ctrl+Shift+Tab");
        add("tab.jump_last", "Ctrl+9");
        add("zoom.in", "Ctrl+=");
        add("zoom.out", "Ctrl+-");
        add("zoom.reset", "Ctrl+0");
        add("page.print", "Ctrl+P");
        add("page.find_in_page", "Ctrl+F");
        add("devtools.toggle", "F12");
        add("devtools.elements", "Ctrl+Shift+I");
        add("devtools.console", "Ctrl+Shift+J");
        add("page.view_source", "Ctrl+U");
        add("window.new", "Ctrl+N");
        add("window.new_private", "Ctrl+Shift+N");
        add("window.fullscreen", "F11");
        add("internal.settings", "Ctrl+,");
        add("internal.process_manager", "Shift+Escape");
        add("sidebar.history", "Ctrl+H");
        add("sidebar.downloads", "Ctrl+J");
        add("shield.clear_browsing_data", "Ctrl+Shift+Delete");
        add("vault.open", "Ctrl+Shift+L");
        add("mullvad.toggle", "Alt+Shift+M");
        add("mullvad.quick_hop", "Alt+M");

        match preset {
            KeymapPreset::ChromeEdge => {
                add("nav.save_page", "Ctrl+S");
                add("nav.copy_url", "Ctrl+Shift+C");
                add("sidebar.toggle", "Ctrl+B");
                add("sidebar.bookmarks", "Ctrl+Shift+O");
                add("tab.search", "Ctrl+Shift+A");
                add("tab.mute_toggle", "Ctrl+M");
                add("tab.duplicate", "Ctrl+Shift+D");
                add("reader.toggle", "Alt+R");
                add("capture.visible", "Ctrl+Shift+S");
                add("ui.command_palette", "Ctrl+K, Ctrl+P");
                add("ui.shortcuts_help", "Ctrl+K, Ctrl+S");
                add("split.vertical", "Ctrl+Alt+V");
                add("split.horizontal", "Ctrl+Alt+H");
                add("workspace.picker", "Ctrl+Shift+W");
            }
            KeymapPreset::Vivaldi => {
                add("ui.command_palette", "F2");
                add("ui.shortcuts_help", "Ctrl+K, Ctrl+S");
                add("sidebar.toggle", "F4");
                add("sidebar.bookmarks", "Ctrl+Shift+B");
                add("sidebar.notes", "Ctrl+Shift+O");
                add("split.vertical", "Ctrl+F9");
                add("split.horizontal", "Ctrl+F8");
                add("split.grid", "Ctrl+F7");
                add("split.close", "Ctrl+F6");
                add("window.zen_mode", "Ctrl+F11");
                add("tab.hibernate", "Alt+Shift+H");
                add("tab.search", "Ctrl+E");
                add("capture.full_page", "Ctrl+Shift+S");
                add("workspace.picker", "Ctrl+Shift+W");
            }
            KeymapPreset::Arc => {
                add("sidebar.toggle", "Ctrl+S");
                add("nav.copy_url", "Ctrl+Shift+C");
                add("ui.command_palette", "Ctrl+K");
                add("ui.shortcuts_help", "Alt+/");
                add("split.vertical", "Ctrl+Shift+D");
                add("split.swap", "Ctrl+Alt+S");
                add("split.close", "Ctrl+Alt+X");
                add("workspace.next", "Ctrl+Alt+ArrowRight");
                add("workspace.prev", "Ctrl+Alt+ArrowLeft");
                add("workspace.picker", "Ctrl+Shift+W");
                add("window.zen_mode", "Ctrl+Shift+Z");
                add("theme.open_customizer", "Ctrl+Shift+B");
                add("tab.pin_toggle", "Alt+P");
                add("capture.visible", "Ctrl+Shift+2");
            }
            KeymapPreset::VimModal => {
                add("ui.command_palette", "Space, P");
                add("ui.shortcuts_help", "Space, ?");
                add("tab.next", "G, T");
                add("tab.prev", "G, Shift+T");
                add("nav.home", "G, H");
                add("nav.copy_url", "Y, Y");
                add("tab.reopen_closed", "Shift+U");
                add("split.vertical", "Space, W, V");
                add("split.horizontal", "Space, W, S");
                add("split.close", "Space, W, Q");
                add("workspace.next", "Space, N");
                add("workspace.prev", "Space, B");
                add("sidebar.toggle", "Space, E");
                add("mullvad.quick_hop", "Space, M");
                add("vault.open", "Space, V");
                add("shield.element_zapper", "Space, Z");
                add("reader.toggle", "Space, R");
            }
        }

        map
    }

    /// Computes effective command -> sequence map after applying `user_overrides`.
    pub fn effective_bindings(&self) -> BTreeMap<String, KeySequence> {
        let mut effective = Self::preset_bindings(self.preset);
        for (cmd_id, override_seq) in &self.user_overrides {
            match override_seq {
                Some(seq) => {
                    effective.insert(cmd_id.clone(), seq.clone());
                }
                None => {
                    effective.remove(cmd_id);
                }
            }
        }
        effective
    }

    pub fn bind_override(&mut self, command_id: &str, sequence: KeySequence) {
        self.user_overrides
            .insert(command_id.to_string(), Some(sequence));
    }

    pub fn bind_override_str(&mut self, command_id: &str, sequence: &str) -> Result<(), KeybindError> {
        let parsed = KeySequence::parse(sequence)?;
        self.bind_override(command_id, parsed);
        Ok(())
    }

    pub fn unbind(&mut self, command_id: &str) {
        self.user_overrides.insert(command_id.to_string(), None);
    }

    pub fn reset_override(&mut self, command_id: &str) {
        self.user_overrides.remove(command_id);
    }

    pub fn reset_all_overrides(&mut self) {
        self.user_overrides.clear();
    }

    pub fn binding_for(&self, command_id: &str) -> Option<KeySequence> {
        self.effective_bindings().remove(command_id)
    }

    /// Resolves an active multi-chord key buffer into an exact match, pending prefix, or no match.
    pub fn resolve_input(&self, buffer: &[KeyChord]) -> ChordResolution {
        if buffer.is_empty() {
            return ChordResolution::NoMatch;
        }
        let effective = self.effective_bindings();
        let mut prefix_candidates = Vec::new();
        for (cmd_id, seq) in &effective {
            if seq.0 == buffer {
                return ChordResolution::Matched(cmd_id.clone());
            }
            if seq.len() > buffer.len() && seq.starts_with(buffer) {
                prefix_candidates.push(cmd_id.clone());
            }
        }
        if !prefix_candidates.is_empty() {
            ChordResolution::PendingPrefix(prefix_candidates)
        } else {
            ChordResolution::NoMatch
        }
    }

    /// Detects both exact duplicate shortcuts and prefix-shadowing conflicts
    /// (e.g., `Ctrl+K` shadowing `Ctrl+K, Ctrl+S`).
    pub fn find_conflicts(&self) -> Vec<KeyConflict> {
        let effective = self.effective_bindings();
        let mut by_seq: BTreeMap<KeySequence, Vec<String>> = BTreeMap::new();
        for (cmd_id, seq) in &effective {
            by_seq.entry(seq.clone()).or_default().push(cmd_id.clone());
        }

        let mut conflicts = Vec::new();
        for (seq, cmds) in &by_seq {
            let mut shadowed = Vec::new();
            for (other_seq, other_cmds) in &by_seq {
                if other_seq.len() > seq.len() && other_seq.starts_with(&seq.0) {
                    shadowed.extend(other_cmds.iter().cloned());
                }
            }
            shadowed.sort();
            shadowed.dedup();

            if cmds.len() > 1 || !shadowed.is_empty() {
                conflicts.push(KeyConflict {
                    sequence: seq.clone(),
                    command_ids: cmds.clone(),
                    is_prefix_shadow: !shadowed.is_empty(),
                    shadowed_command_ids: shadowed,
                });
            }
        }
        conflicts
    }

    pub fn to_json(&self) -> Result<String, KeybindError> {
        serde_json::to_string_pretty(self)
            .map_err(|e| KeybindError::Serialization(e.to_string()))
    }

    pub fn from_json(raw: &str) -> Result<Self, KeybindError> {
        serde_json::from_str(raw).map_err(|e| KeybindError::Serialization(e.to_string()))
    }

    /// Persists `keybinds.json` atomically via write + flush + sync + rename.
    pub fn save_to_path(&self, path: &Path) -> Result<(), KeybindError> {
        let json = self.to_json()?;
        atomic_write_bytes(path, json.as_bytes())
    }

    pub fn load_from_path(path: &Path) -> Result<Self, KeybindError> {
        let raw = fs::read_to_string(path).map_err(|e| KeybindError::Io(e.to_string()))?;
        Self::from_json(&raw)
    }

    pub fn load_or_default(path: &Path) -> Self {
        Self::load_from_path(path).unwrap_or_default()
    }
}

// ============================================================================
// 3. CommandChainStore (User Macros with Anti-Recursion & Step Guards)
// ============================================================================

/// Individual step inside a user-defined [`CommandChain`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChainStep {
    ExecuteCommand {
        command_id: String,
        #[serde(default)]
        arg: Option<String>,
    },
    DelayMs(u64),
}

/// Named user macro executing a sequence of browser commands and optional delays.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandChain {
    pub id: String,
    pub name: String,
    pub icon: String,
    pub steps: Vec<ChainStep>,
}

/// Persistent catalog of user command chains with cycle, depth, and step-count guards.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandChainStore {
    pub chains: BTreeMap<String, CommandChain>,
}

impl CommandChainStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn upsert(&mut self, chain: CommandChain) -> Result<(), KeybindError> {
        if chain.id.trim().is_empty() {
            return Err(KeybindError::Serialization("chain id cannot be empty".into()));
        }
        if chain.steps.len() > MAX_CHAIN_STEPS {
            return Err(KeybindError::TooManySteps(chain.id, MAX_CHAIN_STEPS));
        }
        let mut clone = self.clone();
        clone.chains.insert(chain.id.clone(), chain.clone());
        // Validate that inserting this chain introduces no cycles or limit overflows
        clone.expand_chain(&chain.id)?;
        self.chains.insert(chain.id.clone(), chain);
        Ok(())
    }

    pub fn get(&self, id: &str) -> Option<&CommandChain> {
        self.chains.get(id)
    }

    pub fn remove(&mut self, id: &str) -> Option<CommandChain> {
        self.chains.remove(id)
    }

    pub fn list(&self) -> Vec<&CommandChain> {
        self.chains.values().collect()
    }

    /// Expands a command chain into a flat sequence of atomic steps, resolving nested
    /// `chain:<id>` invocations while enforcing `MAX_CHAIN_STEPS` (64),
    /// `MAX_CHAIN_RECURSION_DEPTH` (16), and cycle detection.
    pub fn expand_chain(&self, chain_id: &str) -> Result<Vec<ChainStep>, KeybindError> {
        let mut out = Vec::new();
        let mut visiting = HashSet::new();
        self.expand_recursive(chain_id, 0, &mut visiting, &mut out)?;
        Ok(out)
    }

    fn expand_recursive(
        &self,
        chain_id: &str,
        depth: usize,
        visiting: &mut HashSet<String>,
        out: &mut Vec<ChainStep>,
    ) -> Result<(), KeybindError> {
        if depth >= MAX_CHAIN_RECURSION_DEPTH {
            return Err(KeybindError::RecursionDepthExceeded(
                MAX_CHAIN_RECURSION_DEPTH,
            ));
        }
        if !visiting.insert(chain_id.to_string()) {
            return Err(KeybindError::CyclicChain(chain_id.to_string()));
        }

        let chain = self
            .chains
            .get(chain_id)
            .ok_or_else(|| KeybindError::ChainNotFound(chain_id.to_string()))?;

        for step in &chain.steps {
            match step {
                ChainStep::ExecuteCommand { command_id, .. }
                    if command_id.starts_with("chain:") =>
                {
                    let nested_id = &command_id["chain:".len()..];
                    self.expand_recursive(nested_id, depth + 1, visiting, out)?;
                }
                other => {
                    if out.len() >= MAX_CHAIN_STEPS {
                        visiting.remove(chain_id);
                        return Err(KeybindError::TooManySteps(
                            chain_id.to_string(),
                            MAX_CHAIN_STEPS,
                        ));
                    }
                    out.push(other.clone());
                }
            }
        }

        visiting.remove(chain_id);
        Ok(())
    }

    pub fn to_json(&self) -> Result<String, KeybindError> {
        serde_json::to_string_pretty(self)
            .map_err(|e| KeybindError::Serialization(e.to_string()))
    }

    pub fn from_json(raw: &str) -> Result<Self, KeybindError> {
        let parsed: Self = serde_json::from_str(raw)
            .map_err(|e| KeybindError::Serialization(e.to_string()))?;
        for id in parsed.chains.keys() {
            parsed.expand_chain(id)?;
        }
        Ok(parsed)
    }

    pub fn save_to_path(&self, path: &Path) -> Result<(), KeybindError> {
        let json = self.to_json()?;
        atomic_write_bytes(path, json.as_bytes())
    }

    pub fn load_from_path(path: &Path) -> Result<Self, KeybindError> {
        let raw = fs::read_to_string(path).map_err(|e| KeybindError::Io(e.to_string()))?;
        Self::from_json(&raw)
    }
}

// ============================================================================
// 4. MouseGestureRecognizer, Rocker Gestures & MRU Wheel Cycling
// ============================================================================

/// Recognized stroke direction segment for mouse gestures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GestureDirection {
    Up,
    Down,
    Left,
    Right,
    UpLeft,
    UpRight,
    DownLeft,
    DownRight,
}

impl GestureDirection {
    /// Short gesture code. Cardinal codes are single letters (`U`, `D`, `L`, `R`)
    /// so chains like `"DR"` (`Down` then `Right`) remain unambiguous; optional
    /// diagonals use compass codes (`NW`, `NE`, `SW`, `SE`).
    pub fn code(&self) -> &'static str {
        match self {
            Self::Up => "U",
            Self::Down => "D",
            Self::Left => "L",
            Self::Right => "R",
            Self::UpLeft => "NW",
            Self::UpRight => "NE",
            Self::DownLeft => "SW",
            Self::DownRight => "SE",
        }
    }
}

/// Mouse button identifiers for Rocker Gestures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MouseButton {
    Left,
    Right,
    Middle,
}

/// Opera/Vivaldi-style Rocker Gestures (hold one button, click the other).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RockerGesture {
    /// Right button held + Left button clicked (default: navigate back).
    RockerLeft,
    /// Left button held + Right button clicked (default: navigate forward).
    RockerRight,
}

/// Stateful MRU (Most-Recently-Used) wheel tab cycler (Right-Click + Scroll Wheel).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MruTabCycler {
    /// Tab IDs ordered from most-recently-used (`index 0`) to oldest.
    mru_order: Vec<String>,
    /// Active cycle cursor while the user is holding right-click and scrolling.
    active_cursor: Option<usize>,
}

impl MruTabCycler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn touch_tab(&mut self, tab_id: &str) {
        self.mru_order.retain(|id| id != tab_id);
        self.mru_order.insert(0, tab_id.to_string());
    }

    pub fn remove_tab(&mut self, tab_id: &str) {
        self.mru_order.retain(|id| id != tab_id);
        if let Some(cursor) = self.active_cursor {
            if self.mru_order.is_empty() {
                self.active_cursor = None;
            } else if cursor >= self.mru_order.len() {
                self.active_cursor = Some(self.mru_order.len() - 1);
            }
        }
    }

    pub fn mru_order(&self) -> &[String] {
        &self.mru_order
    }

    /// Steps through MRU tabs on mouse-wheel scroll (`delta > 0` = older, `delta < 0` = newer).
    pub fn wheel_step(&mut self, delta: i32) -> Option<String> {
        let len = self.mru_order.len();
        if len == 0 {
            return None;
        }
        let current = self.active_cursor.unwrap_or(0) as isize;
        let step = if delta > 0 {
            1isize
        } else if delta < 0 {
            -1isize
        } else {
            0isize
        };
        let next = (current + step).rem_euclid(len as isize) as usize;
        self.active_cursor = Some(next);
        self.mru_order.get(next).cloned()
    }

    /// Finalizes the wheel cycle, promoting the selected tab to MRU position 0.
    pub fn commit_cycle(&mut self) -> Option<String> {
        let idx = self.active_cursor.take()?;
        let selected = self.mru_order.get(idx).cloned()?;
        self.touch_tab(&selected);
        Some(selected)
    }

    pub fn cancel_cycle(&mut self) {
        self.active_cursor = None;
    }
}

/// Mouse gesture, Rocker gesture, and MRU wheel-cycle recognizer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MouseGestureRecognizer {
    pub enabled: bool,
    pub allow_diagonals: bool,
    pub min_stroke_length_px: f64,
    pub bindings: HashMap<String, String>,
    pub rocker_enabled: bool,
    pub rocker_left_command: String,
    pub rocker_right_command: String,
    pub wheel_mru_enabled: bool,
    #[serde(skip)]
    left_down: bool,
    #[serde(skip)]
    right_down: bool,
    #[serde(skip)]
    pub mru_cycler: MruTabCycler,
}

impl Default for MouseGestureRecognizer {
    fn default() -> Self {
        let mut bindings = HashMap::new();
        bindings.insert("L".into(), "nav.back".into());
        bindings.insert("R".into(), "nav.forward".into());
        bindings.insert("D".into(), "tab.new".into());
        bindings.insert("DR".into(), "tab.close".into());
        bindings.insert("UD".into(), "nav.reload".into());
        bindings.insert("RU".into(), "tab.reopen_closed".into());
        bindings.insert("U".into(), "nav.stop".into());
        bindings.insert("DU".into(), "tab.duplicate".into());
        bindings.insert("LU".into(), "tab.prev".into());
        bindings.insert("LD".into(), "tab.next".into());
        bindings.insert("RL".into(), "zoom.reset".into());

        Self {
            enabled: true,
            allow_diagonals: false,
            min_stroke_length_px: 24.0,
            bindings,
            rocker_enabled: true,
            rocker_left_command: "nav.back".into(),
            rocker_right_command: "nav.forward".into(),
            wheel_mru_enabled: true,
            left_down: false,
            right_down: false,
            mru_cycler: MruTabCycler::new(),
        }
    }
}

impl MouseGestureRecognizer {
    /// Extracts deduplicated stroke directions from raw `(x, y)` pointer coordinates
    /// (screen space: +x right, +y down).
    pub fn directions_from_points(&self, points: &[(f64, f64)]) -> Vec<GestureDirection> {
        if points.len() < 2 {
            return Vec::new();
        }
        let min_len = self.min_stroke_length_px.max(4.0);
        let min_len_sq = min_len * min_len;

        let mut dirs: Vec<GestureDirection> = Vec::new();
        let mut anchor = points[0];

        for &(x, y) in &points[1..] {
            let dx = x - anchor.0;
            let dy = y - anchor.1;
            let dist_sq = dx * dx + dy * dy;
            if dist_sq < min_len_sq {
                continue;
            }
            let dir = classify_direction(dx, dy, self.allow_diagonals);
            if dirs.last().copied() != Some(dir) {
                dirs.push(dir);
            }
            anchor = (x, y);
        }

        dirs
    }

    /// Converts raw coordinates into a gesture code string such as `"DR"` or `"RU"`.
    pub fn gesture_code_from_points(&self, points: &[(f64, f64)]) -> String {
        self.directions_from_points(points)
            .into_iter()
            .map(|d| d.code())
            .collect::<Vec<_>>()
            .join("")
    }

    /// Recognizes a stroke from raw `(x, y)` samples and returns the mapped command ID.
    pub fn recognize(&self, points: &[(f64, f64)]) -> Option<String> {
        if !self.enabled {
            return None;
        }
        let code = self.gesture_code_from_points(points);
        if code.is_empty() {
            return None;
        }
        self.bindings.get(&code).cloned()
    }

    /// Resolves a [`RockerGesture`] directly to its configured command ID.
    pub fn resolve_rocker(&self, gesture: RockerGesture) -> Option<&str> {
        if !self.rocker_enabled {
            return None;
        }
        let cmd = match gesture {
            RockerGesture::RockerLeft => self.rocker_left_command.as_str(),
            RockerGesture::RockerRight => self.rocker_right_command.as_str(),
        };
        if cmd.is_empty() { None } else { Some(cmd) }
    }

    /// Stateful mouse-down handler detecting Rocker Gestures (`RockerLeft` / `RockerRight`).
    pub fn on_mouse_down(&mut self, button: MouseButton) -> Option<(RockerGesture, String)> {
        match button {
            MouseButton::Left => {
                self.left_down = true;
                if self.right_down && self.rocker_enabled {
                    return self
                        .resolve_rocker(RockerGesture::RockerLeft)
                        .map(|cmd| (RockerGesture::RockerLeft, cmd.to_string()));
                }
            }
            MouseButton::Right => {
                self.right_down = true;
                if self.left_down && self.rocker_enabled {
                    return self
                        .resolve_rocker(RockerGesture::RockerRight)
                        .map(|cmd| (RockerGesture::RockerRight, cmd.to_string()));
                }
            }
            MouseButton::Middle => {}
        }
        None
    }

    /// Stateful mouse-up handler; commits any active MRU wheel cycle when right button releases.
    pub fn on_mouse_up(&mut self, button: MouseButton) -> Option<String> {
        match button {
            MouseButton::Left => {
                self.left_down = false;
                None
            }
            MouseButton::Right => {
                self.right_down = false;
                self.mru_cycler.commit_cycle()
            }
            MouseButton::Middle => None,
        }
    }

    /// Handles mouse-wheel scrolling while the right button is held for MRU tab cycling.
    pub fn on_wheel_while_right_held(&mut self, delta: i32) -> Option<String> {
        if !self.wheel_mru_enabled || !self.right_down {
            return None;
        }
        self.mru_cycler.wheel_step(delta)
    }
}

fn classify_direction(dx: f64, dy: f64, allow_diagonals: bool) -> GestureDirection {
    // Screen coordinates: +x right (0 rad), +y down (+pi/2 rad)
    let angle_deg = dy.atan2(dx).to_degrees(); // -180..=180
    if allow_diagonals {
        if (-22.5..22.5).contains(&angle_deg) {
            GestureDirection::Right
        } else if (22.5..67.5).contains(&angle_deg) {
            GestureDirection::DownRight
        } else if (67.5..112.5).contains(&angle_deg) {
            GestureDirection::Down
        } else if (112.5..157.5).contains(&angle_deg) {
            GestureDirection::DownLeft
        } else if (-67.5..-22.5).contains(&angle_deg) {
            GestureDirection::UpRight
        } else if (-112.5..-67.5).contains(&angle_deg) {
            GestureDirection::Up
        } else if (-157.5..-112.5).contains(&angle_deg) {
            GestureDirection::UpLeft
        } else {
            GestureDirection::Left
        }
    } else if dx.abs() >= dy.abs() {
        if dx >= 0.0 {
            GestureDirection::Right
        } else {
            GestureDirection::Left
        }
    } else if dy >= 0.0 {
        GestureDirection::Down
    } else {
        GestureDirection::Up
    }
}

/// Atomic file writer (temp sibling + flush + sync_all + rename).
fn atomic_write_bytes(path: &Path, bytes: &[u8]) -> Result<(), KeybindError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| KeybindError::Io(e.to_string()))?;
        }
    }
    let tmp_name = format!(
        ".{}.tmp.{}",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("keybinds"),
        std::process::id()
    );
    let tmp_path = path.with_file_name(tmp_name);
    {
        let mut f = fs::File::create(&tmp_path).map_err(|e| KeybindError::Io(e.to_string()))?;
        f.write_all(bytes)
            .map_err(|e| KeybindError::Io(e.to_string()))?;
        f.sync_all().map_err(|e| KeybindError::Io(e.to_string()))?;
    }
    fs::rename(&tmp_path, path).map_err(|e| KeybindError::Io(e.to_string()))
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_registry_catalog_and_bilingual_fuzzy_search() {
        let reg = CommandRegistry::new();
        assert!(
            reg.len() >= 60,
            "CommandRegistry must contain at least 60 commands, got {}",
            reg.len()
        );
        // Ensure every ID is unique
        let ids: HashSet<&str> = reg.all().iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids.len(), reg.len());

        // French accent-insensitive query
        let fr_hits = reg.search_commands("vue scindee");
        assert!(!fr_hits.is_empty());
        assert!(fr_hits[0].command.id.starts_with("split."));

        // Subsequence fuzzy query ("mld hp" -> Mullvad Quick Multi-Hop Relay)
        let fuzzy = reg.search_commands("mullvad hop");
        assert_eq!(fuzzy[0].command.id, "mullvad.quick_hop");

        // Command palette lookup
        let palette = reg.search_commands("palette");
        assert!(palette.iter().any(|r| r.command.id == "ui.command_palette"));

        // Task manager lookup
        let tm = reg.search_commands("gestionnaire taches");
        assert_eq!(tm[0].command.id, "internal.process_manager");
    }

    #[test]
    fn test_key_sequence_parsing_multi_chords_and_conflicts() {
        let seq = KeySequence::parse("ctrl+k, ctrl+s").expect("parse multi-chord");
        assert_eq!(seq.len(), 2);
        assert_eq!(seq.to_canonical_string(), "Ctrl+K, Ctrl+S");

        // Literal comma shortcut
        let settings_seq = KeySequence::parse("Ctrl+,").expect("parse Ctrl+,");
        assert_eq!(settings_seq.len(), 1);
        assert_eq!(settings_seq.to_canonical_string(), "Ctrl+,");

        // Literal plus shortcut
        let plus_seq = KeySequence::parse("Ctrl++").expect("parse Ctrl++");
        assert_eq!(plus_seq.to_canonical_string(), "Ctrl++");

        // Verify all 4 presets build cleanly and have zero built-in conflicts
        for preset in [
            KeymapPreset::ChromeEdge,
            KeymapPreset::Vivaldi,
            KeymapPreset::Arc,
            KeymapPreset::VimModal,
        ] {
            let table = KeymapTable::from_preset(preset);
            let conflicts = table.find_conflicts();
            assert!(
                conflicts.is_empty(),
                "Preset {:?} must have zero default conflicts, found: {:?}",
                preset,
                conflicts
            );
        }

        // Introduce both exact duplicate conflict and prefix shadow conflict
        let mut table = KeymapTable::from_preset(KeymapPreset::ChromeEdge);
        table
            .bind_override_str("nav.home", "Ctrl+T")
            .expect("override");
        table
            .bind_override_str("tab.pin_toggle", "Ctrl+K")
            .expect("prefix shadow");

        let conflicts = table.find_conflicts();
        assert!(conflicts.iter().any(|c| {
            c.sequence.to_canonical_string() == "Ctrl+T"
                && c.command_ids.contains(&"tab.new".to_string())
                && c.command_ids.contains(&"nav.home".to_string())
        }));
        assert!(conflicts.iter().any(|c| {
            c.sequence.to_canonical_string() == "Ctrl+K"
                && c.is_prefix_shadow
                && c.shadowed_command_ids
                    .contains(&"ui.shortcuts_help".to_string())
        }));

        // Multi-chord resolution test
        let vim = KeymapTable::from_preset(KeymapPreset::VimModal);
        let c1 = KeyChord::parse("Space").unwrap();
        let c2 = KeyChord::parse("W").unwrap();
        let c3 = KeyChord::parse("V").unwrap();
        assert!(matches!(
            vim.resolve_input(&[c1.clone()]),
            ChordResolution::PendingPrefix(_)
        ));
        assert!(matches!(
            vim.resolve_input(&[c1.clone(), c2.clone()]),
            ChordResolution::PendingPrefix(_)
        ));
        assert_eq!(
            vim.resolve_input(&[c1, c2, c3]),
            ChordResolution::Matched("split.vertical".into())
        );
    }

    #[test]
    fn test_keymap_atomic_persistence_and_json_roundtrip() {
        let mut table = KeymapTable::from_preset(KeymapPreset::Arc);
        table.bind_override_str("nav.reload", "F5").unwrap();
        table.unbind("page.print");

        let tmp = std::env::temp_dir().join(format!(
            "singularity_keybinds_test_{}.json",
            std::process::id()
        ));
        let _ = fs::remove_file(&tmp);

        table.save_to_path(&tmp).expect("atomic save");
        let loaded = KeymapTable::load_from_path(&tmp).expect("load");
        assert_eq!(loaded, table);
        assert_eq!(
            loaded.binding_for("nav.reload").unwrap().to_canonical_string(),
            "F5"
        );
        assert!(loaded.binding_for("page.print").is_none());

        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn test_command_chain_store_and_anti_recursion_guards() {
        let mut store = CommandChainStore::new();
        store
            .upsert(CommandChain {
                id: "focus_mode".into(),
                name: "Deep Focus".into(),
                icon: "sparkles".into(),
                steps: vec![
                    ChainStep::ExecuteCommand {
                        command_id: "window.zen_mode".into(),
                        arg: None,
                    },
                    ChainStep::DelayMs(150),
                    ChainStep::ExecuteCommand {
                        command_id: "reader.toggle".into(),
                        arg: None,
                    },
                ],
            })
            .expect("insert focus_mode");

        store
            .upsert(CommandChain {
                id: "research_routine".into(),
                name: "Research".into(),
                icon: "book".into(),
                steps: vec![
                    ChainStep::ExecuteCommand {
                        command_id: "mullvad.toggle".into(),
                        arg: Some("se".into()),
                    },
                    ChainStep::ExecuteCommand {
                        command_id: "chain:focus_mode".into(),
                        arg: None,
                    },
                ],
            })
            .expect("insert nested chain");

        let expanded = store.expand_chain("research_routine").expect("expand");
        assert_eq!(expanded.len(), 4);

        // Direct self-cycle rejected
        let err = store.upsert(CommandChain {
            id: "self_loop".into(),
            name: "Loop".into(),
            icon: "x".into(),
            steps: vec![ChainStep::ExecuteCommand {
                command_id: "chain:self_loop".into(),
                arg: None,
            }],
        });
        assert!(matches!(err, Err(KeybindError::CyclicChain(_))));

        // Max steps (> 64) rejected
        let too_many = (0..65)
            .map(|_| ChainStep::DelayMs(10))
            .collect::<Vec<_>>();
        let err = store.upsert(CommandChain {
            id: "huge".into(),
            name: "Huge".into(),
            icon: "x".into(),
            steps: too_many,
        });
        assert!(matches!(err, Err(KeybindError::TooManySteps(_, 64))));

        // Max recursion depth (> 16) rejected
        let mut deep_store = CommandChainStore::new();
        deep_store
            .upsert(CommandChain {
                id: "c0".into(),
                name: "c0".into(),
                icon: "dot".into(),
                steps: vec![ChainStep::DelayMs(1)],
            })
            .unwrap();
        for i in 1..=15 {
            deep_store
                .upsert(CommandChain {
                    id: format!("c{}", i),
                    name: format!("c{}", i),
                    icon: "dot".into(),
                    steps: vec![ChainStep::ExecuteCommand {
                        command_id: format!("chain:c{}", i - 1),
                        arg: None,
                    }],
                })
                .unwrap();
        }
        let depth_err = deep_store.upsert(CommandChain {
            id: "c16".into(),
            name: "c16".into(),
            icon: "dot".into(),
            steps: vec![ChainStep::ExecuteCommand {
                command_id: "chain:c15".into(),
                arg: None,
            }],
        });
        assert!(matches!(
            depth_err,
            Err(KeybindError::RecursionDepthExceeded(16))
        ));

        // JSON import/export round-trip
        let json = store.to_json().expect("export json");
        let reimported = CommandChainStore::from_json(&json).expect("import json");
        assert_eq!(reimported, store);
    }

    #[test]
    fn test_mouse_gestures_rocker_and_mru_wheel_cycling() {
        let mut rec = MouseGestureRecognizer::default();

        // Down then Right ("DR") -> tab.close
        let dr_stroke = vec![
            (100.0, 100.0),
            (102.0, 110.0), // noise below min_stroke_length_px
            (100.0, 150.0), // Down
            (100.0, 190.0), // continued Down (deduped)
            (150.0, 190.0), // Right
        ];
        assert_eq!(rec.gesture_code_from_points(&dr_stroke), "DR");
        assert_eq!(rec.recognize(&dr_stroke).as_deref(), Some("tab.close"));

        // Right then Up ("RU") -> tab.reopen_closed
        let ru_stroke = vec![(0.0, 100.0), (60.0, 100.0), (60.0, 40.0)];
        assert_eq!(rec.recognize(&ru_stroke).as_deref(), Some("tab.reopen_closed"));

        // Optional diagonals
        rec.allow_diagonals = true;
        let diag_stroke = vec![(0.0, 0.0), (40.0, 40.0)];
        assert_eq!(rec.directions_from_points(&diag_stroke), vec![GestureDirection::DownRight]);
        assert_eq!(rec.gesture_code_from_points(&diag_stroke), "SE");

        // Rocker gestures
        assert_eq!(rec.on_mouse_down(MouseButton::Right), None);
        assert_eq!(
            rec.on_mouse_down(MouseButton::Left),
            Some((RockerGesture::RockerLeft, "nav.back".into()))
        );
        rec.on_mouse_up(MouseButton::Left);
        rec.on_mouse_up(MouseButton::Right);

        assert_eq!(rec.on_mouse_down(MouseButton::Left), None);
        assert_eq!(
            rec.on_mouse_down(MouseButton::Right),
            Some((RockerGesture::RockerRight, "nav.forward".into()))
        );
        rec.on_mouse_up(MouseButton::Right);
        rec.on_mouse_up(MouseButton::Left);

        // MRU wheel cycling while holding right mouse button
        rec.mru_cycler.touch_tab("tab-a");
        rec.mru_cycler.touch_tab("tab-b");
        rec.mru_cycler.touch_tab("tab-c");
        assert_eq!(rec.mru_cycler.mru_order(), &["tab-c", "tab-b", "tab-a"]);

        rec.on_mouse_down(MouseButton::Right);
        assert_eq!(rec.on_wheel_while_right_held(1).as_deref(), Some("tab-b"));
        assert_eq!(rec.on_wheel_while_right_held(1).as_deref(), Some("tab-a"));
        let committed = rec.on_mouse_up(MouseButton::Right);
        assert_eq!(committed.as_deref(), Some("tab-a"));
        assert_eq!(rec.mru_cycler.mru_order(), &["tab-a", "tab-c", "tab-b"]);
    }
}
