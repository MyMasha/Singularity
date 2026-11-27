# Direction de Code, Sécurité & Workflow — Singularity Browser

---

## 1. Principes d'architecture Rust

* **100 % Rust natif (Edition 2021, resolver 2)** : zéro Electron, zéro Node.js au runtime, zéro bundler frontend.
* **Dépendances centralisées** dans le `[workspace.dependencies]` du `Cargo.toml` racine ; toujours exécuter builds et tests avec `--locked`.
* **Profil release durci** (`Cargo.toml`) : `opt-level = 3`, `lto = "fat"`, `codegen-units = 1`, `panic = "abort"`, `strip = "symbols"`, `overflow-checks = true`.
* **Séparation des responsabilités par crate** :
  * Logique métier pure (cryptographie, filtres réseau, DNS, CRDT, traduction, media DSP, registre paramètres) → crates dédiés sans dépendance Win32/GUI, 100 % testables sur Linux et Windows.
  * Orchestration OS, CEF 150, WebView2 DRM, boucle `tao` et serveur HTTP loopback → `crates/singularity-ui`.
* **Zéro panic silencieux sur entrées non fiables** : gérer toutes les erreurs réseau, parsing JSON/HTML/manifest, I/O disque et FFI proprement (`Result`, `Option`, fail-closed sur la sécurité).

---

## 2. Invariants de Sécurité Non-Négociables

Ces invariants sont vérifiés automatiquement par les tests dans `crates/singularity-ui/src/lib.rs` :

1. **Sandbox strict des iframes** : `SINGULARITY_UI_HTML` ne doit **jamais** contenir `allow-same-origin`.
2. **Zéro secret maître en JS** : ne **jamais** stocker `sessionMasterCache` ou le mot de passe maître du Vault côté JavaScript ; le chiffrement Argon2id + XChaCha20-Poly1305 vit exclusivement en Rust avec `zeroize::Zeroizing`.
3. **IPC Loopback authentifié** : chaque requête `/api/*` exige le header `X-Singularity-Token` (jeton aléatoire 256-bit généré au démarrage, remplacé dans `__SINGULARITY_IPC_TOKEN__`) + protection contre le DNS rebinding.
4. **Auto-updater fail-closed** : vérification obligatoire de l'hôte HTTPS GitHub allowlisté, du hash `SHA256SUMS.txt` et de la signature **Ed25519** (`SHA256SUMS.txt.sig`) avec clé publique embarquée à la compilation.
5. **Confidentialité par défaut** :
   * Cast (`singularity-cast`) : **0 socket réseau ouvert** tant que l'utilisateur n'a pas déclenché une découverte opt-in.
   * Traduction (`singularity-translate`) & Breach Bloom : 100 % local/offline.
   * `Sec-GPC: 1` injecté dans CEF ; zéro télémétrie Chromium (`chromium/args.gn`).
6. **Sécurité DOM frontend** : préférer `textContent`, `createElement` et `replaceChildren()` à `innerHTML` sur toute donnée venant d'URLs, titres de pages, historique, extensions ou API.

---

## 3. Règles Frontend (`crates/singularity-ui/src/ui_app.rs`)

* **Vanilla HTML/CSS/JS embarqué** dans la constante `SINGULARITY_UI_HTML`.
* **Performance haute densité (30–50+ onglets)** :
  * Réconciliation DOM incrémentale par clé (`data-tab-id`) dans `renderTabs()` et mise à jour O(1) d'un onglet unique via `updateSingleTabPill()` — ne jamais reconstruire tout le strip sur un changement de titre/favicon.
  * Aucun reflow coûteux sur `scroll` / `mousemove` ; écouteurs `passive: true` lorsque `preventDefault()` n'est pas nécessaire.
* **Synchronisation `bar-only` ↔ `set_overlay` / `set_chrome_layout`** :
  * Quand une page web CEF est active (`body.bar-only`), `ui_browser` est réduit à `80px` de haut.
  * Tout menu qui déborde sous les `80px` (suggestions Omnibox, popovers, modales, palette) **doit** passer par `anyOverlayActive()` + `syncOverlayState()` (`set_overlay: true/false`) et activer `#v3-overlay-scrim` pour fermeture au clic extérieur.
  * Tout bandeau persistant qui doit laisser la page web visible dessous (ex. `Ctrl+F` Find Bar) **doit** utiliser `set_chrome_layout { top_bar_extra_px }` au lieu de `set_overlay: true`.
  * Toute sidebar ancrée (Sidebar `340px`, Rail vertical `230px`) **doit** synchroniser `left_sidebar_px` via `syncChromeInsets()` ET décaler `#stage-viewport` / `#settings-modal` via classes `body.v3-sb-open` / `body.vertical-tabs`.
* **Validation obligatoire avant commit** :
  * Extraire `<script>` et passer `node --check` (0 erreur syntaxique).
  * Vérifier l'équilibre des accolades `{` / `}` du bloc `<style>`.
  * Vérifier l'unicité de tous les `id="..."` HTML (0 doublon).

---

## 4. Règles Windows CEF 150 & Stabilité Processus

* **Pure Chromium CEF Alloy** : toujours définir `wi.runtime_style = RuntimeStyle::ALLOY` et attacher un `SingularityCefClient` valide sur tous les navigateurs et popups (y compris popups d'extensions).
* **Win32 Compositing** : conserver `WS_CLIPCHILDREN` (`ensure_win32_clip_children`) sur la fenêtre parente `tao` afin qu'elle ne repeigne jamais en noir par-dessus les `HWND` enfants CEF/WebView2.
* **Shutdown propre garanti** :
  * Conserver `Win32ShutdownSentinel` (`WM_QUERYENDSESSION` / `WM_ENDSESSION`) dans `crash_guard.rs`.
  * Dans `Event::LoopDestroyed` (`server.rs`), appeler `flush_live_crash_checkpoint` et `mark_planned_restart` **AVANT** `st.close_cleanly()` afin qu'un redémarrage Windows ne génère jamais de faux rapport de crash.
* **Hybrid DRM** : router les domaines Widevine VMP / PlayReady (Netflix, etc.) vers `drm_webview.rs` (WebView2 signé) et les autres sites vers `cef_runtime.rs`.

---

## 5. Invariants de Tests à Préserver (`crates/singularity-ui/src/lib.rs`)

Avant toute modification de `ui_app.rs` ou `server.rs`, vérifier que les assertions suivantes restent intactes :
* `APPLE_BAR_LOGICAL_HEIGHT: f64 = 80.0` et `APPLE_BAR_LOGICAL_HEIGHT + st.top_bar_extra_logical_px as f64`
* `app-region: drag;` / `-webkit-app-region: drag;` / `app-region: no-drag;` / `-webkit-app-region: no-drag;`
* `body.is-maximized .rz`, `triggerTitlebarMaximize`
* `body.bar-only #toast` avec `top: 7px;` et `height: 32px;`
* `.tab-pill` de base conservant `flex: 0 1 172px;` et `width: 172px;` (surchargé par `.tab-strip-row .tab-pill { flex: 1 1 220px; width: 220px; ... }`)
* `.apple-bar.tabs-expanded`, `function syncOmnibarLayout(`
* `grid-template-columns: minmax(0, 1fr)` sur `.nav-toolbar-row`
* Absence de `|| strip.scrollWidth > strip.clientWidth + 4`, `top: 46px;`, `top: 48px;`, `top: 50px;`, `max-width: 48px;`, `max-width: 82px;`, `max-width: 132px;`
* Marqueurs v3 (`initSingularityV3Shell`, `window.__v3`), motion (`--ease-spring:`, `initSingularitySatisfyingMotion`, `prefers-reduced-motion: reduce`) et version synchronisée (`env!("CARGO_PKG_VERSION")` et `vX.Y.Z` dans `#sidebar-ver-label`).

---

## 6. Procédure de Release Systématique (À chaque grosse modification)

Lors du passage en version `X.Y.Z`, mettre à jour **tous** ces fichiers ensemble :
1. `Cargo.toml` → `version = "X.Y.Z"`
2. `crates/singularity-ui/build.rs` → `FILEVERSION X,Y,Z,0`, `PRODUCTVERSION X,Y,Z,0`, `FileVersion`, `ProductVersion`
3. `crates/singularity-installer/build.rs` → mêmes 4 champs RC Windows
4. `crates/singularity-ui/src/ui_app.rs` → `#sidebar-ver-label` (`vX.Y.Z`)
5. `crates/singularity-ui/src/lib.rs` → assertions `CARGO_PKG_VERSION`, `vX.Y.Z` dans `SINGULARITY_UI_HTML` et crash report test
6. `.github/workflows/release.yml` → commentaire d'exemple `e.g. vX.Y.Z`
7. `Cargo.lock` → régénérer via `cargo metadata --format-version 1 > /dev/null`
8. Vérifier : `node --check` + `cargo test --workspace --locked` (0 échec)
9. Publier :
   ```bash
   git add -A
   git commit -m "feat/fix(...): description (vX.Y.Z)"
   git tag -a vX.Y.Z -m "Singularity Browser vX.Y.Z — Titre"
   git push origin main vX.Y.Z
   ```
10. Suivre le workflow GitHub Actions `Build & Publish Verified Release Assets` (`gh run watch <id> -R MyMasha/Singularity --exit-status`) puis éditer le changelog sur GitHub Releases (`gh release edit vX.Y.Z`).
