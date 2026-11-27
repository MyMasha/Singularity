# Arborescence & Architecture Technique — Singularity Browser (`v3.0.3`)

Total codebase : **~134 850 lignes de Rust/HTML/CSS/JS** réparties en **11 crates Cargo** + scripts de build/packaging multi-OS.

---

## 1. Arborescence complète du dépôt

```text
Singularity/
├── .agent/                               # Contexte persistant & documentation de reprise (ce dossier)
│   ├── README.md                         # Point d'entrée, commandes locales et règles projet
│   ├── ARCHITECTURE_TREE.md              # Arborescence détaillée et architecture des 11 crates
│   ├── ART_DIRECTION.md                  # Direction artistique OLED cosmique & design system
│   ├── CODE_DIRECTION.md                 # Standards de code, sécurité, invariants et workflow release
│   ├── ROADMAP_TODO.md                   # Backlog priorisé (P0 → P3)
│   └── KNOWN_ISSUES.md                   # Problèmes connus, pièges CEF/Win32/CSS et historique
├── .agents/plugins/                      # Plugins Antigravity (orchestrateur & context-restart-meter)
├── .cargo/config.toml                    # Configuration Cargo workspace
├── .github/workflows/release.yml         # CI/CD : Ed25519 key, Linux musl (.deb/.rpm), Windows CEF 150 + smoke tests + Release
├── assets/                               # Logo source & icône Windows (.ico / .png)
├── chromium/                             # Configuration de durcissement Chromium
│   ├── args.gn                           # Flags GN Chromium (zéro télémétrie)
│   └── strip_telemetry.rs                # Script/règles de suppression télémétrie
├── dist/                                 # Scripts utilitaires utilisateur (Launch / Update .bat/.ps1/.sh)
├── scripts/                              # Scripts de build & packaging CI/local
│   ├── prepare-cef-win64.py              # Téléchargement & staging SDK CEF 150 (OBS 7871 H.264/AAC)
│   ├── package-windows-cef.py            # Assemblage du bundle Windows + scellement SFX
│   └── package-linux.sh                  # Packaging Debian, Ubuntu, Mint (.deb) et Bazzite (.rpm)
├── Cargo.toml                            # Manifeste workspace (11 crates, version 3.0.3, LTO fat)
├── Cargo.lock                            # Verrouillage exact des dépendances (--locked obligatoire)
├── README.md / SECURITY.md / LICENSE / THIRD_PARTY_NOTICES.md
└── crates/
    ├── singularity-ui/                   # [Binaire principal `singularity`] Shell natif + serveur IPC + Frontend
    ├── singularity-installer/            # [Binaire `Singularity-setup.exe`] Installeur SFX auto-extractible SGX1 signé
    ├── singularity-core/                 # Moteur cœur : onglets, bloqueur, DNS chiffré, téléchargements, RAM/énergie
    ├── singularity-vault/                # Coffre-fort Zero-Knowledge (Argon2id + XChaCha20-Poly1305), Passkeys, TOTP
    ├── singularity-net-mullvad/          # WireGuard, Kill-Switch, DAITA, relais, pont proxy par profil/onglet
    ├── singularity-media/                # EQ 10 bandes 600%, MediaSession, TTS offline, Live Captions, Capture/Rec
    ├── singularity-settings-registry/    # Registre 2 500+ paramètres, flags expérimentaux, politiques & recherche
    ├── singularity-chromium-ffi/         # Durcissement FFI & profils sécurité Chromium
    ├── singularity-sync/                 # Sync P2P E2EE Zero-Knowledge (24+1 mots BIP-39, CRDT, XChaCha20)
    ├── singularity-translate/            # Détection de langue & traduction 100 % hors-ligne
    └── singularity-cast/                 # Découverte Cast/DLNA strictement opt-in (0 socket par défaut)
```

---

## 2. Détail des 11 crates et fichiers clés

### `crates/singularity-ui/` — Shell navigateur, CEF 150, API v3 & Frontend
| Fichier | Lignes | Rôle exact |
| :--- | ---: | :--- |
| `src/server.rs` | ~12 960 | Cœur runtime : boucle `tao` Windows, gestion multi-fenêtres/onglets/Split View, serveur HTTP loopback authentifié (`X-Singularity-Token`), routage IPC natif (`UiIpcCmd`), `APPLE_BAR_LOGICAL_HEIGHT = 80.0`, `Event::LoopDestroyed` & checkpoints. |
| `src/ui_app.rs` | ~11 730 | Frontend complet embarqué (`SINGULARITY_UI_HTML`) : CSS 6 thèmes OLED, header 2 barres, onglets fluides, NTP WebGL2 3D, Paramètres 13 onglets, Sidebar, Palette, Tab Search, Find Bar, Animations GPU. |
| `src/omnibox.rs` | ~5 230 | Moteur Omnibox : frecency, bangs (`!yt`, `@gh`), calculs/conversions instantanés, QR Code SVG, scopes. |
| `src/cef_runtime.rs` | ~4 190 | Intégration Pure Chromium CEF 150 (`RuntimeStyle::ALLOY`, `SingularityCefClient` sur chaque popup, `Sec-GPC`, `flags.toml`, hydratation cookies, PiP). |
| `src/extensions.rs` | ~4 105 | Gestionnaire extensions Chrome (Web Store CRX, dossiers locaux `manifest.json`, hot-reload, permissions par site, popups natifs). |
| `src/page_tools.rs` | ~4 085 | Mode Lecture (extraction + thème OLED WCAG AAA), Collections, Liste de lecture hors-ligne, Notes Markdown, outils PDF/capture. |
| `src/roaming_store.rs` | ~3 845 | Stockage chiffré `%APPDATA%\.singularity` (sessions/tokens OAuth, profils, sauvegarde d'onglets + timestamps vidéo, 4 modes RAM unloader). |
| `src/api_v3.rs` | ~3 040 | 161 endpoints REST loopback v3 couvrant les 10 domaines fonctionnels. |
| `src/bookmarks_store.rs` | ~2 795 | Arbre de favoris hiérarchique, dossiers imbriqués, import/export HTML/JSON. |
| `src/lib.rs` | ~2 725 | Exports crate + **111 tests unitaires & invariants** (UI, sécurité, updater, CEF, crash guard, 2 barres). |
| `src/profiles.rs` | ~2 175 | Multi-profils, Onglets Conteneurs isolés, Workspaces et permissions par site. |
| `src/internal_pages.rs` | ~2 150 | 25 pages internes `browser://*` (`flags`, `urls`, `process-manager`, `net-internals`, etc.). |
| `src/keybinds.rs` | ~1 830 | Raccourcis clavier remappables + presets (Chrome/Edge, Vivaldi, Arc, Vim). |
| `src/updater.rs` | ~1 760 | Auto-updater GitHub Releases fail-closed (vérification SHA-256 + signature Ed25519, suivi progression temps réel). |
| `src/history_store.rs` | ~1 700 | Historique complet, recherche floue, filtrage domaine/date, Privacy Shredder par site. |
| `src/browser_import.rs` | ~1 635 | Détection & import depuis Chrome, Brave, Edge, Firefox (favoris, onglets ouverts, historique). |
| `src/userscripts.rs` | ~1 580 | Moteur Userscripts natif (`GM_*` sandbox isolé, SRI, analyse de risque). |
| `src/drm_webview.rs` | ~1 435 | Moteur Hybrid DRM Windows (WebView2 signé pour Widevine VMP / PlayReady — Netflix `M7701-1003`, Prime, Disney+). |
| `src/crash_guard.rs` | ~1 300 | Détection crash réel, `Win32ShutdownSentinel` (`WM_QUERYENDSESSION`/`WM_ENDSESSION`), rapport copiable avec fin de `cef.log`. |
| `src/winhttp_client.rs` | ~1 235 | Client HTTPS natif WinHTTP (zéro terminal, protection DNS rebinding). |
| `src/shell.rs` | ~595 | État partagé `SingularityBrowserShell` & orchestration des sous-systèmes. |
| `src/vim.rs` / `src/main.rs` / `src/cursor.rs` / `src/theme.rs` / `src/shaders.rs` | ~1 125 | Mode Vim modal (link hints), entrée binaire, curseurs `.cur`/`.ani`, thèmes & shaders. |
| `build.rs` | ~290 | Génération ressources Win32 (`VERSIONINFO`, icône, manifeste DPI). |

### Autres crates du workspace
* **`singularity-core`** (~10 800 LOC) : `blocker.rs` (EasyList/uBlock/cosmétique), `dns.rs` (DoH/DoT/DoQ/ODoH), `downloader.rs` (file multi-segments), `tabs.rs` (SplitLayoutTree, groupes, hibernation), `threat_guard.rs`, `cache.rs`, `telemetry.rs`, `limiter.rs`, `memory_pressure.rs`, `preconnect.rs`, `tab_organizer.rs`, `power.rs`.
* **`singularity-vault`** (~12 800 LOC) : `crypto.rs` (Argon2id + XChaCha20-Poly1305 + HKDF + multi-slots DEK), `importers.rs` (12 gestionnaires), `format.rs`, `passkey.rs` (WebAuthn/CTAP2/PRF), `matcher.rs`, `cxf.rs` (Credential Exchange), `totp.rs` (RFC 6238/HOTP/Steam/Google Auth), `breach.rs` (HIBP k-anonymity + Bloom offline), `generator.rs`, `payment.rs`.
* **`singularity-settings-registry`** (~10 470 LOC) : `catalog.rs` (2 500+ réglages typés), `flags.rs`, `schema.rs`, `policy.rs`, `search.rs`, `storage.rs`, `macros.rs`.
* **`singularity-net-mullvad`** (~5 330 LOC) : `proxy_bridge.rs` (routage proxy/VPN par profil/onglet), `relays.rs`, `wireguard.rs`, `killswitch.rs`, `daita.rs`, `account.rs`.
* **`singularity-media`** (~6 660 LOC) : `recorder.rs`, `equalizer.rs` (10 bandes + boost 600 %), `player.rs`, `tts_engine.rs`, `live_captions.rs`, `media_session.rs`, `decoder.rs`.
* **`singularity-installer`** (~4 280 LOC) : `main.rs` — Installeur natif Windows Win32 auto-extractible (`SGX1` overlay + vérification Ed25519 + raccourcis + désinstalleur propre).
* **`singularity-sync`** (~3 090 LOC) : `transport.rs`, `crdt.rs`, `mnemonic.rs` (24+1 mots), `wordlist.rs`.
* **`singularity-translate`** (~2 480 LOC) : `engine.rs`, `detect.rs`.
* **`singularity-cast`** (~1 490 LOC) : découverte mDNS/SSDP opt-in uniquement.
* **`singularity-chromium-ffi`** (~505 LOC) : `hardening.rs`, `ffi.rs`.

---

## 3. Architecture d'exécution & Flux de données (Windows CEF 150)

```text
┌─────────────────────────────────────────────────────────────────────────┐
│ Fenêtre Frameless tao (Win32 HWND + WS_CLIPCHILDREN + DWM dark)        │
├─────────────────────────────────────────────────────────────────────────┤
│ ui_browser (CEF Alloy) — Charge http://127.0.0.1:<port>/ (ui_app.rs)    │
│  ├─ Mode NTP / Paramètres / Overlay : plein écran (0, 0, W, H)          │
│  ├─ Mode Web (`body.bar-only`)      : bande top (0, 0, W, bar_h)        │
│  │   • bar_h = (80px + top_bar_extra_px) * scale                        │
│  │   • Si sidebar/vertical-rail ouvert : (0, 0, W, H)                   │
│  └─ IPC natif : window.ipc.postMessage(JSON) → UiIpcCmd (server.rs)     │
├─────────────────────────────────────────────────────────────────────────┤
│ tab_browsers[tab_id] (enfants Win32 positionnés sous bar_h)             │
│  ├─ TabBrowser::Cef(CefBrowserHandle)  → Sites web standard (CEF 150)   │
│  ├─ TabBrowser::Drm(DrmWebViewHandle)  → Sites DRM VMP (WebView2 signé) │
│  └─ Split View : 2+ panneaux calculés via SplitLayoutTree::compute_rects│
├─────────────────────────────────────────────────────────────────────────┤
│ Serveur HTTP Loopback 127.0.0.1:<ephemeral_port>                        │
│  ├─ Exige header `X-Singularity-Token` (256-bit aléatoire par session)  │
│  └─ /api/* (roaming, vault, mullvad, extensions, updater, 161 routes v3) │
└─────────────────────────────────────────────────────────────────────────┘
```
