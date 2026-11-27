# Direction Artistique & Design System — Singularity Browser

---

## 1. Identité visuelle (« Cosmic OLED Craft »)

Singularity marie l'ergonomie immédiatement familière d'un **navigateur classique à deux barres** (référence : Brave / Chrome desktop) avec une esthétique **OLED sombre cinématographique** inspirée d'Interstellar / macOS haut de gamme :

* **Noir absolu & profondeur** : fond OLED `#000000` (`--void-0`), surfaces chromées sombres à contraste fin (`--bg-tabstrip: #07080c`, `--bg-toolbar: #10121a`, `--page-bg: #0c0d12`), bordures hairline subtiles (`rgba(255, 255, 255, 0.08)`).
* **Accent chaud maîtrisé** : or solaire (`--gold-core: #f0b254`, `--gold-bright: #ffdf9e`) pour l'état actif, le focus, la couronne d'onglet actif et la barre de chargement — **jamais de néons criards, jamais de violet "AI slop" par défaut**.
* **Signature Singularity** :
  * Feux tricolores Apple (`.tl-close` `#ff5f57`, `.tl-min` `#febc2e`, `.tl-max` `#28c840`) avec glyphes au survol dans le coin supérieur gauche.
  * Logo Singularity dans la barre d'onglets.
  * Fond **WebGL2 temps réel** sur la page Nouvel Onglet (`#singularity-canvas` : trou noir Schwarzschild Gargantua / Couronne Solaire 3D / Éclipse / Pulsar, plafonné à 60 fps et automatiquement mis en veille `1×1` en navigation web pour libérer la VRAM).

---

## 2. Les 6 Thèmes Cosmiques 3D (`:root[data-theme="..."]`)

Chaque thème redéfinit l'intégralité des tokens de surface (`--bar-tabstrip-bg`, `--bar-toolbar-bg`, `--bg-tabstrip`, `--bg-toolbar`, `--page-bg`, `--page-sidebar`, `--glass-panel`), la couleur d'accent (`--gold-core`, `--gold-bright`, `--border-warm`) et les uniformes du shader 3D :

| ID thème | Nom | Palette d'accent | Fond barre 1 / barre 2 (`bar-only`) |
| :--- | :--- | :--- | :--- |
| `singularity` *(défaut)* | Gargantua (Trou Noir 3D) | Or solaire `#f0b254` / `#ffdf9e` | `#07080c` / `#10121a` |
| `soleil` | Soleil (Couronne 3D) | Ambre `#ff9f2e` / `#ffe699` | `#0f0803` / `#1b0f06` |
| `pulsar` | Pulsar Cyan | Cyan `#38d9f5` / `#a8f3ff` | `#050b13` / `#0b1624` |
| `nebuleuse` | Nébuleuse Violette | Lavande `#b975ff` / `#e4c7ff` | `#0b0613` / `#160e24` |
| `eclipse` | Éclipse Sanguine | Cramoisi `#ff4d5e` / `#ffadb6` | `#0f0508` / `#1c0b0f` |
| `aurore` | Aurore Émeraude | Émeraude `#34d399` / `#a7f3d0` | `#040e0a` / `#0a1b14` |

> **Règle d'or thèmes :** toute nouvelle surface UI doit utiliser les CSS custom properties (`var(--page-bg)`, `var(--gold-core)`, `var(--border-warm)`, `var(--bg-toolbar)`, etc.) et jamais de couleurs en dur incompatibles avec les 6 thèmes.

---

## 3. Architecture Chrome Deux Barres (`80px` logiques)

Constantes synchronisées entre Rust (`APPLE_BAR_LOGICAL_HEIGHT = 80.0` dans `server.rs`) et CSS (`--bar-height: 80px` dans `ui_app.rs`) :

### Rangée 1 — `.tab-strip-row` (`38px`, `app-region: drag`)
* **Gauche** : `.traffic-lights` (3 boutons macOS) + `.brand-home-btn` (logo).
* **Centre (`flex: 1 1 auto`)** : `.tabs-bar-wrap` contenant `#tabs-scroll-left`, `#tabs-strip`, `#tabs-scroll-right`, `#btn-new-tab` (`+`).
  * **Distribution fluide 100 % largeur** : `.tab-strip-row .tab-pill` utilise `flex: 1 1 220px; width: 220px; max-width: 220px; min-width: 34px;`. Les onglets occupent **toujours 100 % de la largeur disponible** dès qu'ils dépassent la largeur naturelle, sans jamais laisser d'espace mort à droite.
  * **Onglet actif soudé à la Rangée 2** : `height: 33px; margin-bottom: 0; border-radius: 9px 9px 0 0; background: var(--bar-toolbar-bg);` + couronne lumineuse supérieure `2px` (`::before` en `var(--gold-core)`).
  * **Densité pilotée par largeur réelle** : `syncTabDensityClasses()` active `.compact-tabs` (`< 145px/onglet`), `.very-compact` (`< 96px/onglet`), `.ultra-compact` (`< 58px/onglet`) — ces classes ne réduisent **jamais** `max-width`, elles ajustent uniquement les marges et le bouton `×` au survol.
* **Droite** : `.tab-strip-right` avec le bouton chevron `#btn-tab-search-chevron` (`Ctrl+Shift+A`).

### Rangée 2 — `.nav-toolbar-row` (`42px`, `app-region: no-drag`)
* Grille 3 colonnes : `grid-template-columns: minmax(0, 1fr) clamp(280px, 50vw, 1080px) minmax(max-content, 1fr);`
* **Gauche (`.nav-left-group`)** : Précédent, Suivant, Recharger (`#btn-reload-page`), séparateur `1px`, Sidebar (`F4`), Onglets verticaux.
* **Centre (`.omnibar-wrap`)** : `.safari-omnibar` (`height: 30px`, `border-radius: 10px`, `max-width: 1080px`) avec cadenas SSL, `#omnibar-input`, pill `DRM`, Mode Lecture, QR Code, Favori étoilé.
* **Droite (`.toolbar-right-wrap`)** : `#ext-toolbar-strip`, Split View, Téléchargements, Média/EQ, Palette (`Ctrl+K`), séparateur `1px`, Extensions, Mode Privé, Sessions `.singularity`, Shield/WireGuard, Coffre-fort, Paramètres.
* **Breakpoints responsives** : `1120px`, `860px`, `640px` (Windows 11 Snap Layouts jusqu'à `480px`).

---

## 4. Motion Design & Micro-Interactions (GPU 120–200 Hz)

* **Courbes officielles** :
  * `--ease-spring: cubic-bezier(0.22, 1.28, 0.36, 1)` (ressort tactile : popovers, modales, onglets, étoile favori)
  * `--ease-snappy: cubic-bezier(0.2, 0.9, 0.25, 1)` (hover/active rapides)
  * `--ease-silk: cubic-bezier(0.16, 1, 0.3, 1)` (glissements fluides : sidebars, barres de progression, panneaux)
* **Règles de performance animation** :
  * Uniquement `transform` et `opacity` (zéro reflow layout par frame).
  * Animations dédiées : `sgTabEnter`, `sgOmniDrop`, `sgModalPop`, `sgPopoverPop`, `sgSlideLeft`, `sgSpin360` (reload), `sgStarPop` + `sgStarRing` (favori), `sgTogglePop`, `sgRipple` (onde radiale au point de clic).
  * Barre de chargement fine `#v3-load-progress` (`2px`, `scaleX`) collée au bas de `.apple-bar`.
  * Accessibilité : `@media (prefers-reduced-motion: reduce)` désactive proprement animations et transitions.

---

## 5. Hiérarchie `z-index` officielle

| Couche | `z-index` | Éléments |
| :--- | ---: | :--- |
| Canvas 3D & Vignette | `0` – `1` | `#singularity-canvas`, `.cinema-vignette` |
| Shell & Barre supérieure | `2` – `40` | `#app-shell`, `.apple-bar` (`30`), `#topbar-update-line` (`40`) |
| Page Paramètres & Poignées resize | `60` – `95` | `#settings-modal` (`60`), `.rz` (`90`), `#v3-load-progress` (`95`) |
| Rails latéraux ancrés | `8600` – `8800` | `#v3-vertical-rail` (`8600`), `#v3-sidebar` (`8800`) |
| Bulle de statut & Scrim overlay | `9300` – `9350` | `#v3-status-bubble` (`9300`), `#v3-overlay-scrim` (`9350`) |
| Dropdowns, Find Bar & Popovers | `9400` – `9550` | `#omnibox-dropdown` (`9400`), `#find-in-page-bar` (`9500`), `#v3-popover-panel` (`9550`) |
| Modales v3, Éditeur groupe, Menu | `9600` – `9800` | `#command-palette-modal`, `#tab-search-modal`, `#v3-internal-frame-modal` (`9600`), `#update-floating-bar` (`9700`), `#group-editor-bar` (`9750`), `#tab-context-menu` (`9800`) |
| Onboarding & Notifications | `9900` – `10500` | `#onboarding-overlay` (`9900`), `#toast` (`10500`) |
| Rapport de crash critique | `12000` | `#crash-report-modal` (`12000`) |

---

## 6. Règles strictes UI (À faire / À éviter)

* **TOUJOURS** définir `color-scheme: dark;` et styler les scrollbars (`::-webkit-scrollbar*`), `<select>`, `<option>`, `input[type="range"]` en OLED sombre.
* **TOUJOURS** positionner les overlays avec `var(--bar-height)` (jamais `top: 46px` / `48px` / `50px` en dur).
* **TOUJOURS** vérifier le comportement en mode `body.bar-only` (quand une vraie page web CEF est affichée sous la barre de `80px`).
* **NE JAMAIS** mettre de `max-width` fixe inférieur à `220px` sur `.compact-tabs` / `.very-compact` / `.ultra-compact` (sinon les onglets laissent un trou vide à droite sur grand écran).
* **NE JAMAIS** utiliser `translateY(-50%)` sur `.tab-close-btn` combiné avec `:hover { transform: scale(...) }` (utiliser `top: 0; bottom: 0; margin: auto 0;`).
