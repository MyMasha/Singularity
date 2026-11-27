# Problèmes Connus, Pièges Techniques & Historique des Correctifs

Ce document recense **toutes les limites actuelles**, les **pièges subtils spécifiques à CEF 150 / Win32 / CSS** dans Singularity, ainsi que les incidents majeurs déjà résolus afin d'éviter toute régression lors du développement local.

---

## 1. Limitations & Problèmes Ouverts Actuels

| Sévérité | Zone | Description | Piste de résolution |
| :---: | :--- | :--- | :--- |
| **Moyenne** | Mode Lecture (`ui_app.rs:11236`) | `openReaderPreview()` passe encore un extrait HTML statique à `/api/reader/extract` au lieu d'extraire le vrai DOM de la page active CEF. | Ajouter une commande IPC `extract_active_dom` via `cef_runtime.rs` retournant `document.documentElement.outerHTML` au backend. |
| **Moyenne** | Autofill Vault | Le coffre-fort `singularity-vault` (Argon2id, Passkeys, TOTP, 12 importeurs) est complet côté Rust/Settings, mais l'auto-remplissage inline dans les formulaires des sites web CEF n'est pas encore injecté automatiquement. | Injecter un content script isolé sur focus `<input>` communiquant via IPC sécurisé avec `matcher.rs`. |
| **Moyenne** | Sync P2P (`singularity-sync`) | Le moteur CRDT + chiffrement XChaCha20-Poly1305 + phrases 24+1 mots est opérationnel localement ; le transport pair-à-pair réseau entre machines réelles reste à brancher. | Ajouter transport QUIC/WebSocket LAN + relais E2EE chiffré optionnel. |
| **Moyenne** | Linux GUI | Sur Linux, `singularity` compile en binaire statique musl et sert l'interface HTTP loopback, mais le fenêtrage natif `tao` + CEF 150 est actuellement `#[cfg(target_os = "windows")]`. | Porter `window_loop` / CEF Linux (X11/Wayland) derrière un feature flag dédié. |
| **Basse** | Maintenabilité | `server.rs` (~12 960 LOC) et `ui_app.rs` (~11 730 LOC) sont très volumineux : un oubli d'accolade ou de virgule JS dans une raw string Rust est coûteux à diagnostiquer sans `node --check`. | Découper `ui_app.rs` via `include_str!` et `server.rs` en sous-modules. |
| **Basse** | Warning compilation Linux | `crates/singularity-ui/src/winhttp_client.rs:222` : `warning: constant WINHTTP_OPTION_CONNECTION_INFO is never used` (utilisé uniquement sous Windows). | Gater la constante sous `#[cfg(target_os = "windows")]`. |
| **Basse** | GitHub Actions CI | Annotations de dépréciation Node.js 20 sur `actions/checkout`, `actions/cache`, `actions/upload-artifact`, `actions/download-artifact` (forcés sur Node 24 par GitHub). | Mettre à jour les SHAs vers les versions Node 24 officielles. |
| **Basse** | SmartScreen Windows | `Singularity-setup.exe` est signé en Ed25519 interne (vérifié par l'auto-updater), mais sans certificat Authenticode payant Microsoft. | Signer via certificat EV / Azure Trusted Signing lors d'une diffusion grand public. |

---

## 2. Pièges Techniques Critiques (À connaître absolument avant de modifier le code)

### A. Le mode `body.bar-only` et le découpage des fenêtres Win32
* Quand l'utilisateur navigue sur un site web (`https://...`), `ui_browser` (la couche HTML de Singularity) est **redimensionné à `(0, 0, W, 80px * scale)`** pour laisser toute la place au `HWND` enfant CEF/WebView2 en dessous !
* **Conséquence directe :** tout élément HTML positionné sous `y = 80px` est **totalement invisible/coupé** tant que :
  1. `set_overlay { open: true }` n'a pas été envoyé (ce qui cache temporairement la page web et étend `ui_browser` en plein écran — utilisé par Omnibox dropdown, popovers, Palette, Tab Search, Modales), **OU**
  2. `set_chrome_layout { top_bar_extra_px, left_sidebar_px, ... }` n'a pas été envoyé (ce qui réserve de la place autour de la page web sans la cacher — utilisé par la barre `Ctrl+F`, la Sidebar `340px` et le Rail vertical `230px`).
* **Attention au focus & fermeture :** toujours remettre `set_overlay { open: false }` dès qu'un popup/dropdown se ferme (clic sur `#v3-overlay-scrim`, `Escape`, `blur`, changement d'onglet), sinon la page web reste masquée !

### B. WebGL2 Canvas (`#singularity-canvas`) en mode `bar-only`
* Lorsqu'on ouvre `Ctrl+F` sur une page web, `window.innerHeight` de `ui_browser` passe de `80px` à `122px` (`80 + 42`).
* **Piège :** ne jamais réduire le seuil de garde WebGL2 sous `160px` et toujours garder `document.body.classList.contains("bar-only")` dans `syncCanvasSize()` / `revealCanvasAfterDraw()` / `scheduleNextFrame()` pour éviter de réveiller le shader 3D en arrière-plan d'une page web.

### C. Flexbox de la barre d'onglets (`#tabs-strip` & `.tab-pill`)
* **Piège déjà rencontré (v3.0.2 → corrigé v3.0.3) :** mettre `max-width: 48px` / `82px` / `132px` sur `.compact-tabs`/`.very-compact`/`.ultra-compact` empêche les onglets de remplir la barre sur écran 1440p/4K (31 % de vide à droite !).
* **Règle :** garder `.tab-strip-row .tab-pill { flex: 1 1 220px; width: 220px; max-width: 220px; min-width: 34px; }` et ne modifier que padding/gap/visibilité du bouton `×` via `syncTabDensityClasses()`.
* **Piège bouton `×` :** ne jamais utiliser `top: 50%; transform: translateY(-50%)` avec `:hover { transform: scale(1.12) }` — `scale()` écrase `translateY(-50%)` et fait sauter la croix vers le bas ! Toujours centrer avec `top: 0; bottom: 0; margin: auto 0;`.

### D. `position: relative` sur `.apple-bar` & Offsets d'overlays
* `.apple-bar` **doit** conserver `position: relative;` : sinon `#v3-load-progress` et `#topbar-update-line` (`position: absolute; bottom: 0;`) se collent tout en bas de l'écran au lieu du bas de la barre de navigation.
* Tous les overlays doivent utiliser `var(--bar-height)` (`80px`), jamais de pixels en dur.

### E. CEF 150 & Windows Shutdown
* **Popups CEF sans client :** créer un navigateur CEF sans `SingularityCefClient` ou sans `RuntimeStyle::ALLOY` provoque les warnings `Creating a chrome browser without a client` et `IPH_ExtensionsZeroStatePromo` puis des instabilités de frames spéculatifs.
* **Shutdown Windows :** Windows ferme les processus via `WM_ENDSESSION` sans déclencher `CloseRequested`. `Event::LoopDestroyed` doit impérativement nettoyer `running.lock` (`mark_planned_restart`) **avant** tout teardown CEF/COM lent.

---

## 3. Incidents Historiques Résolus (Référence Rapide)

| Version | Problème initial | Correctif appliqué |
| :--- | :--- | :--- |
| **v2.0.9** | Erreur Netflix `M7701-1003` (Widevine VMP absent sur CEF non signé) + 58 points d'audit sécurité | Moteur **Hybrid DRM** (`drm_webview.rs` WebView2 signé) + signature Ed25519 + durcissement complet. |
| **v2.0.10** | Échecs vérif update WinHTTP + crashs renderer CEF | Correctifs client WinHTTP natif et cycle de vie renderer CEF. |
| **v3.0.0** | Parité fonctionnelle navigateur moderne (10 domaines) | Ajout de 3 crates (`sync`, `translate`, `cast`), 161 endpoints API v3, 25 pages `browser://`, Vault v2, Split View, Sidebar, Palette. |
| **v3.0.1** | Faux crash report `unclean_shutdown` au redémarrage Windows + popups CEF sans client + UX statique | `Win32ShutdownSentinel`, réordonnancement `Event::LoopDestroyed`, `RuntimeStyle::ALLOY` sur tous les popups, animations GPU à ressort. |
| **v3.0.2** | Barre unique `46px` trop chargée + barres de progression en bas d'écran + overlays coupés en `bar-only` + scrollbars blancs | Refonte **classique deux barres (`80px`)**, `position: relative`, `var(--bar-height)`, scrim overlay, Find Bar ancrée `42px`, `color-scheme: dark`. |
| **v3.0.3** | 31 % d'espace vide à droite des onglets sur écran large (`ultra-compact` plafonné à `48px`) | Distribution fluide `flex: 1 1 220px; width: 220px;` sans plafond fixe + `syncTabDensityClasses()` + Omnibar jusqu'à `1080px`. |
