# Feuille de Route — Ce qu'il reste à faire (`v3.0.3` → `v3.x`)

Le socle complet des **10 domaines fonctionnels** (11 crates Rust, 161 endpoints API v3, 25 pages `browser://`, Vault v2, Sync P2P E2EE, Translate offline, Cast opt-in, Hybrid DRM, interface classique 2 barres OLED + animations GPU) est en place et testé (`283 / 283`).

Voici ce qu'il reste à approfondir, brancher nativement sur CEF ou polir au quotidien, classé par priorité.

---

## P0 — Finitions Visuelles & UX Quotidienne (Impact immédiat)

- [ ] **Indicateur audio & sourdine par onglet directement sur `.tab-pill`** : afficher une petite icône haut-parleur / muet cliquable sur chaque onglet qui joue du son (branchée sur `set_tab_audio_muted` déjà présent côté IPC).
- [ ] **Cartes d'aperçu d'onglet au survol (Hover Cards)** : tooltip riche stylisé OLED affichant titre complet, domaine, consommation RAM estimée / état veille (`sleeping`) et miniature de la page (sans gêner le mode `bar-only`).
- [ ] **Barre de favoris optionnelle persistante en mode page web** : aujourd'hui `#ntp-bookmarks-bar` n'apparaît que sur la page Nouvel Onglet (`#ntp-view`). Ajouter une option `Toujours afficher la barre de favoris` (`Ctrl+Shift+B`) utilisant `set_chrome_layout { top_bar_extra_px: 34 }` + drag & drop de dossiers imbriqués.
- [ ] **Panneau Sécurité & Certificat SSL cliquable sur le cadenas de l'Omnibar** : afficher protocole TLS, émetteur du certificat, trackers bloqués sur le site courant (compteur `blocker.rs`), et permissions granulaires du domaine (caméra, micro, géolocalisation, notifications, presse-papiers).
- [ ] **Épinglage d'onglets (Pinned Tabs)** : support visuel compact (favicon seul à gauche de `#tabs-strip`, protégé contre la fermeture accidentelle) + persistance dans `roaming_store.rs`.
- [ ] **Enrichir les panneaux Sidebar (`v3-sidebar`)** : recherche instantanée dans Favoris/Historique, suppression/ouverture nouvel onglet, aperçu progression téléchargements temps réel et boutons d'action (ouvrir dossier, pause/reprise, annuler).
- [ ] **Sélecteur rapide de Profil / Workspace / Conteneur dans le header** : badge discret de profil/workspace actif permettant de basculer sans ouvrir les paramètres.

---

## P1 — Branchements Natifs CEF 150 Approfondis

- [ ] **Mode Lecture (`F9`) sur le vrai DOM de la page active** : actuellement `openReaderPreview()` dans `ui_app.rs` envoie un HTML de démonstration à `/api/reader/extract`. Brancher l'extraction réelle via un pont JS/IPC CEF (`frame.execute_java_script` → `document.documentElement.outerHTML`) pour lire n'importe quel article web en OLED WCAG AAA + choix police/taille/interligne/Line Focus/TTS intégré.
- [ ] **Pont Autofill Vault ↔ Formulaires Web** : connecter `singularity-vault` (`matcher.rs`, `format.rs`, `passkey.rs`) aux champs `<input type="password">` / `autocomplete="username"` / WebAuthn des pages CEF via un content script isolé (avec confirmation utilisateur explicite et zéro exposition du mot de passe maître).
- [ ] **Capture d'écran intégrée (Zone / Page entière)** : brancher `page_tools.rs` sur `Page.captureScreenshot` (DevTools Protocol CEF) avec outil de sélection de zone + copie presse-papiers + sauvegarde PNG/PDF/MHTML.
- [ ] **Lecteur PDF natif enrichi** : activer/styler la barre PDF (zoom, recherche, table des matières, rotation, annotations légères) en cohérence avec le thème OLED.
- [ ] **Transport réseau réel pour `singularity-sync`** : le moteur CRDT + chiffrement XChaCha20-Poly1305 + phrases 24+1 mots est prêt ; ajouter la synchronisation LAN mDNS/QUIC ou relais chiffré zero-knowledge auto-hébergeable entre appareils.
- [ ] **Téléchargements CEF → `singularity-core::downloader`** : unifier le suivi de progression temps réel des téléchargements CEF natifs avec le popover Downloads (`Ctrl+J`), la pause/reprise, le scan SHA-256 et le badge de progression sur `#btn-v3-downloads`.
- [ ] **Traduction de page complète en 1 clic** : brancher `singularity-translate` sur les nœuds texte de la page active CEF pour traduire un site entier hors-ligne avec bannière dans l'Omnibar.

---

## P2 — Multi-Plateforme & Distribution Production

- [ ] **Interface native Linux Desktop (CEF Linux / GTK / Wayland-X11)** : aujourd'hui Linux compile le binaire statique musl et les paquets `.deb`/`.rpm`, mais la boucle de fenêtrage native `tao` + CEF est `#[cfg(target_os = "windows")]` ; porter le shell graphique natif sous Linux.
- [ ] **Support macOS (`aarch64-apple-darwin` / `x86_64-apple-darwin`)** : intégration CEF macOS + bundle `.app` / `.dmg` + feux tricolores natifs.
- [ ] **Signature Authenticode Windows** : signer `singularity.exe` et `Singularity-setup.exe` avec un certificat code-signing (en plus d'Ed25519 interne) pour éliminer les alertes Windows Defender SmartScreen.
- [ ] **Migration GitHub Actions Node 24** : mettre à jour `actions/checkout`, `actions/cache`, `actions/upload-artifact` et `actions/download-artifact` dans `.github/workflows/release.yml` pour éliminer les annotations de dépréciation Node.js 20.

---

## P3 — Refactoring & Dette Technique

- [ ] **Découper `crates/singularity-ui/src/ui_app.rs` (~11 730 LOC)** : séparer CSS, HTML et JS en fichiers dédiés (`assets/ui/*.css`, `*.html`, `*.js`) assemblés via `concat!(include_str!(...))` pour conserver `pub const SINGULARITY_UI_HTML: &str` sans rien casser dans les tests tout en rendant l'édition 10× plus confortable (coloration syntaxique, linter JS/CSS natif).
- [ ] **Découper `crates/singularity-ui/src/server.rs` (~12 960 LOC)** : extraire `ipc_handlers.rs`, `window_loop.rs`, `http_router.rs` et `cef_callbacks.rs` en sous-modules propres.
- [ ] **Nettoyer le warning Linux** : `WINHTTP_OPTION_CONNECTION_INFO` inutilisé dans `crates/singularity-ui/src/winhttp_client.rs:222` (ajouter `#[cfg(target_os = "windows")]` ou `#[allow(dead_code)]`).
- [ ] **Tests E2E UI automatisés** : ajouter un harnais headless Chromium/Playwright optionnel en CI pour vérifier les captures visuelles (1 onglet, 35 onglets, mode `bar-only`, Sidebar, Omnibox dropdown, Find Bar, 6 thèmes).
