//! Singularity v1.0 — Production End-User Frontend.
//! - Real-time WebGL2 3D Schwarzschild Gargantua raymarcher (512x512 tileable FBM/ridge noise + RK2 geodesic integrator)
//! - Frameless macOS Safari-inspired unified bar with three-color Apple traffic-light controls & studio Singularity logo
//! - Encrypted `%APPDATA%\.singularity` session/token manager (Google, Microsoft, GitHub, Discord, etc.)
//! - Zero-knowledge Argon2id Vault, Local WireGuard/Kill-Switch module, Bookmarks/History, Mandatory Onboarding & 2,165+ Settings

pub const SINGULARITY_UI_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Singularity</title>
<style>
  :root {
    --void-0: #000000;
    --void-1: #06070b;
    --page-bg: #0c0d12;
    --page-sidebar: #090a0f;
    --page-card: rgba(255, 255, 255, 0.032);
    --glass-panel: rgba(10, 12, 18, 0.84);
    --glass-hover: rgba(255, 255, 255, 0.065);
    --bar-bg-top: rgba(12, 13, 18, 0.88);
    --bar-bg-bot: rgba(8, 9, 14, 0.74);

    --border-hairline: rgba(255, 255, 255, 0.08);
    --border-strong: rgba(255, 255, 255, 0.16);
    --border-warm: rgba(240, 178, 84, 0.40);

    --text-primary: #f5f3ee;
    --text-secondary: rgba(226, 224, 218, 0.72);
    --text-muted: rgba(180, 182, 192, 0.48);

    --gold-bright: #ffdf9e;
    --gold-core: #f0b254;
    --gold-soft-bg: rgba(240, 178, 84, 0.15);
    --btn-grad-top: #f3be69;
    --btn-grad-bot: #d89638;
    --btn-ink: #09090b;
    --status-ok: #34d399;
    --status-danger: #f87171;

    --bar-height: 46px;
    --ease-cinema: cubic-bezier(0.16, 1, 0.3, 1);
    --font-sans: -apple-system, BlinkMacSystemFont, "SF Pro Text", "Segoe UI Variable Display", "Segoe UI", system-ui, sans-serif;
    --font-mono: "SF Mono", "Cascadia Code", "Consolas", ui-monospace, monospace;
  }

  /* Theme 2: Soleil (Couronne Solaire 3D) */
  :root[data-theme="soleil"] {
    --void-1: #120903;
    --page-bg: #130c06;
    --page-sidebar: #0e0804;
    --page-card: rgba(255, 194, 96, 0.048);
    --glass-panel: rgba(22, 13, 6, 0.88);
    --bar-bg-top: rgba(24, 14, 6, 0.90);
    --bar-bg-bot: rgba(16, 9, 4, 0.78);
    --border-warm: rgba(255, 176, 59, 0.48);
    --gold-bright: #ffe699;
    --gold-core: #ff9f2e;
    --gold-soft-bg: rgba(255, 159, 46, 0.18);
    --btn-grad-top: #ffc24d;
    --btn-grad-bot: #e67b17;
    --btn-ink: #120903;
  }

  /* Theme 3: Pulsar Cyan */
  :root[data-theme="pulsar"] {
    --void-1: #040a12;
    --page-bg: #070d16;
    --page-sidebar: #050a11;
    --page-card: rgba(56, 217, 245, 0.042);
    --glass-panel: rgba(7, 15, 25, 0.88);
    --bar-bg-top: rgba(8, 17, 29, 0.90);
    --bar-bg-bot: rgba(5, 11, 20, 0.78);
    --border-warm: rgba(56, 217, 245, 0.44);
    --gold-bright: #a8f3ff;
    --gold-core: #38d9f5;
    --gold-soft-bg: rgba(56, 217, 245, 0.16);
    --btn-grad-top: #67e8f9;
    --btn-grad-bot: #0891b2;
    --btn-ink: #031117;
  }

  /* Theme 4: Nébuleuse Violette */
  :root[data-theme="nebuleuse"] {
    --void-1: #0b0614;
    --page-bg: #0f0a19;
    --page-sidebar: #0b0713;
    --page-card: rgba(185, 117, 255, 0.046);
    --glass-panel: rgba(16, 10, 26, 0.88);
    --bar-bg-top: rgba(18, 11, 30, 0.90);
    --bar-bg-bot: rgba(11, 7, 20, 0.78);
    --border-warm: rgba(185, 117, 255, 0.44);
    --gold-bright: #e4c7ff;
    --gold-core: #b975ff;
    --gold-soft-bg: rgba(185, 117, 255, 0.16);
    --btn-grad-top: #c88fff;
    --btn-grad-bot: #8b3dff;
    --btn-ink: #0c0514;
  }

  /* Theme 5: Éclipse Sanguine */
  :root[data-theme="eclipse"] {
    --void-1: #120507;
    --page-bg: #13080a;
    --page-sidebar: #0e0507;
    --page-card: rgba(255, 77, 94, 0.046);
    --glass-panel: rgba(22, 8, 11, 0.88);
    --bar-bg-top: rgba(24, 9, 12, 0.90);
    --bar-bg-bot: rgba(15, 6, 8, 0.78);
    --border-warm: rgba(255, 77, 94, 0.46);
    --gold-bright: #ffadb6;
    --gold-core: #ff4d5e;
    --gold-soft-bg: rgba(255, 77, 94, 0.16);
    --btn-grad-top: #ff6b79;
    --btn-grad-bot: #d62839;
    --btn-ink: #160507;
  }

  /* Theme 6: Aurore Émeraude */
  :root[data-theme="aurore"] {
    --void-1: #040f0c;
    --page-bg: #07120e;
    --page-sidebar: #050d0a;
    --page-card: rgba(52, 211, 153, 0.044);
    --glass-panel: rgba(7, 19, 15, 0.88);
    --bar-bg-top: rgba(8, 22, 17, 0.90);
    --bar-bg-bot: rgba(5, 14, 11, 0.78);
    --border-warm: rgba(52, 211, 153, 0.44);
    --gold-bright: #a7f3d0;
    --gold-core: #34d399;
    --gold-soft-bg: rgba(52, 211, 153, 0.16);
    --btn-grad-top: #5eead4;
    --btn-grad-bot: #059669;
    --btn-ink: #03120c;
  }

  * {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
    user-select: none;
    -webkit-user-select: none;
  }

  html, body {
    width: 100%;
    height: 100%;
    overflow: hidden;
    background: #000000;
    color: var(--text-primary);
    font-family: var(--font-sans);
    font-size: 13px;
    line-height: 1.45;
    -webkit-font-smoothing: antialiased;
  }

  /* ==========================================================================
   * FULL-BLEED 3D CELESTIAL CANVAS (TROU NOIR / SOLEIL / ÉCLIPSE / PULSAR)
   * ========================================================================== */
  #singularity-canvas {
    position: fixed;
    inset: 0;
    width: 100vw;
    height: 100vh;
    display: block;
    z-index: 0;
    background: #000000;
  }

  .cinema-vignette {
    position: fixed;
    inset: 0;
    z-index: 1;
    pointer-events: none;
    background:
      radial-gradient(circle at 58% 47%, rgba(0, 0, 0, 0) 40%, rgba(0, 0, 0, 0.26) 78%, rgba(0, 0, 0, 0.64) 100%),
      linear-gradient(90deg, rgba(2, 3, 6, 0.62) 0%, rgba(2, 3, 6, 0.16) 30%, rgba(2, 3, 6, 0.0) 50%),
      linear-gradient(180deg, rgba(2, 3, 6, 0.48) 0%, rgba(2, 3, 6, 0.0) 14%, rgba(2, 3, 6, 0.0) 82%, rgba(2, 3, 6, 0.72) 100%);
  }

  #app-shell {
    position: relative;
    z-index: 2;
    width: 100vw;
    height: 100vh;
    display: flex;
    flex-direction: column;
  }

  /* ==========================================================================
   * UNIFIED APPLE MACOS SAFARI BAR WITH THREE COLORED TRAFFIC LIGHTS
   * Centered URL bar by default; glides smoothly to the right when many tabs open!
   * ========================================================================== */
  .apple-bar {
    height: var(--bar-height);
    min-height: var(--bar-height);
    min-width: 0;
    overflow: hidden;
    padding: 0 14px 0 16px;
    display: grid;
    grid-template-columns: minmax(0, 1fr) clamp(230px, 27vw, 440px) minmax(0, 1fr);
    align-items: center;
    gap: 10px;
    background: linear-gradient(180deg, var(--bar-bg-top) 0%, var(--bar-bg-bot) 100%);
    border-bottom: 1px solid rgba(255, 255, 255, 0.07);
    backdrop-filter: blur(8px);
    -webkit-backdrop-filter: blur(8px);
    contain: layout style;
    z-index: 30;
    app-region: drag;
    -webkit-app-region: drag;
  }
  body.bar-only .apple-bar {
    backdrop-filter: none;
    -webkit-backdrop-filter: none;
    background: #0b0c10;
  }
  .apple-bar.tabs-expanded {
    grid-template-columns: minmax(0, 1fr) clamp(190px, 22vw, 330px) auto;
  }

  .toolbar-left {
    min-width: 0;
    height: 100%;
    display: flex;
    align-items: center;
    gap: 8px;
    overflow: hidden;
  }

  .toolbar-right-wrap {
    min-width: 0;
    height: 100%;
    display: flex;
    align-items: center;
    justify-content: flex-end;
    overflow: hidden;
  }

  .apple-bar button,
  .apple-bar input,
  .apple-bar select,
  .apple-bar a,
  .traffic-lights,
  .safari-nav-group,
  .tabs-bar-wrap,
  .tabs-strip,
  .tab-pill,
  .tab-pill *,
  .tab-group-pill,
  .tab-group-pill *,
  .tab-close-btn,
  .safari-omnibar,
  .toolbar-right,
  .rz,
  #group-editor-bar,
  #group-editor-bar *,
  #tab-context-menu,
  #tab-context-menu *,
  #settings-modal,
  #onboarding-overlay,
  #toast {
    app-region: no-drag;
    -webkit-app-region: no-drag;
  }

  .traffic-lights {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    padding: 4px 2px;
    margin-right: 4px;
    flex-shrink: 0;
  }

  .tl-dot {
    width: 12px;
    height: 12px;
    border-radius: 50%;
    border: 0.5px solid rgba(0, 0, 0, 0.28);
    display: inline-flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
    padding: 0;
    position: relative;
    transition: filter 0.12s ease, transform 0.12s ease;
  }

  .tl-dot svg {
    width: 7px;
    height: 7px;
    opacity: 0;
    transition: opacity 0.12s ease;
    pointer-events: none;
  }

  .traffic-lights:hover .tl-dot svg { opacity: 1; }
  .tl-dot:active { filter: brightness(0.84); transform: scale(0.95); }

  .tl-close { background: #ff5f57; box-shadow: inset 0 0 0 0.5px rgba(224, 68, 62, 0.55); color: #4c0002; }
  .tl-min   { background: #febc2e; box-shadow: inset 0 0 0 0.5px rgba(222, 161, 35, 0.55); color: #5c3c00; }
  .tl-max   { background: #28c840; box-shadow: inset 0 0 0 0.5px rgba(26, 171, 41, 0.55); color: #004d0d; }

  .safari-nav-group {
    display: inline-flex;
    align-items: center;
    gap: 2px;
    flex-shrink: 0;
  }

  .brand-home-btn {
    width: 28px;
    height: 28px;
    border: none;
    border-radius: 7px;
    background: transparent;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
    padding: 3px;
    transition: background 0.15s ease, transform 0.15s ease;
    flex-shrink: 0;
  }
  .brand-home-btn:hover { background: var(--glass-hover); transform: scale(1.04); }
  .brand-home-btn img { width: 21px; height: 21px; border-radius: 5px; display: block; pointer-events: none; }

  .icon-btn {
    width: 28px;
    height: 28px;
    border: none;
    border-radius: 6px;
    background: transparent;
    color: var(--text-secondary);
    display: inline-flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
    position: relative;
    transition: background 0.15s ease, color 0.15s ease;
    flex-shrink: 0;
  }
  .icon-btn:hover { background: var(--glass-hover); color: #ffffff; }
  .icon-btn.active-gold { color: var(--gold-bright); background: rgba(240, 178, 84, 0.14); }

  .mini-badge {
    position: absolute;
    top: 2px;
    right: 2px;
    min-width: 13px;
    height: 13px;
    padding: 0 3px;
    border-radius: 99px;
    background: var(--gold-core);
    color: #08080a;
    font-size: 9px;
    font-weight: 700;
    font-family: var(--font-mono);
    display: none;
    align-items: center;
    justify-content: center;
  }

  /* Overflow-Proof Multi-Tab Bar (Classic Chrome/Brave readability + Tab Groups + Favicons) */
  .tabs-bar-wrap {
    flex: 1 1 auto;
    min-width: 0;
    height: 100%;
    display: flex;
    align-items: center;
    gap: 3px;
    overflow: hidden;
  }

  .tabs-scroll-btn {
    width: 20px;
    height: 26px;
    border: none;
    border-radius: 5px;
    background: rgba(255, 255, 255, 0.05);
    color: var(--text-secondary);
    display: none;
    align-items: center;
    justify-content: center;
    cursor: pointer;
    flex-shrink: 0;
    transition: background 0.14s ease, color 0.14s ease;
  }
  .tabs-scroll-btn.visible { display: inline-flex; }
  .tabs-scroll-btn:hover { background: rgba(255, 255, 255, 0.12); color: #ffffff; }

  .tabs-strip {
    flex: 0 1 auto;
    max-width: 100%;
    display: flex;
    align-items: center;
    gap: 3px;
    min-width: 0;
    overflow-x: auto;
    scrollbar-width: none;
    scroll-behavior: smooth;
    padding: 2px 0;
  }
  .tabs-strip::-webkit-scrollbar { display: none; }

  /* Colored Collapsible Tab Group Header Pill */
  .tab-group-pill {
    flex: 0 0 auto;
    height: 22px;
    max-width: 120px;
    min-width: 22px;
    padding: 0 8px;
    margin-left: 3px;
    border-radius: 6px;
    border: none;
    background: var(--group-color, #f0b254);
    color: #090a0e;
    font-family: inherit;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: -0.01em;
    display: inline-flex;
    align-items: center;
    gap: 4px;
    cursor: pointer;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    box-shadow: 0 1px 6px rgba(0, 0, 0, 0.35);
    transition: filter 0.14s ease, transform 0.12s ease;
  }
  .tab-group-pill:hover { filter: brightness(1.1); }
  .tab-group-pill:active { transform: scale(0.96); }
  .tab-group-pill.collapsed { opacity: 0.9; }
  .tab-group-pill.dot-only {
    width: 16px;
    height: 16px;
    min-width: 16px;
    padding: 0;
    border-radius: 50%;
  }
  .tab-group-count {
    font-size: 10px;
    font-weight: 800;
    padding: 0 4px;
    border-radius: 4px;
    background: rgba(0, 0, 0, 0.22);
    color: #090a0e;
  }

  .tab-pill {
    position: relative;
    flex: 1 1 168px;
    height: 30px;
    max-width: 204px;
    min-width: 68px;
    padding: 0 6px 0 8px;
    border-radius: 8px;
    background: rgba(255, 255, 255, 0.028);
    border: 1px solid transparent;
    color: var(--text-secondary);
    font-size: 11.5px;
    font-weight: 500;
    display: inline-flex;
    align-items: center;
    gap: 6px;
    cursor: pointer;
    contain: layout style;
    transition: background 0.14s ease, color 0.14s ease, border-color 0.14s ease, opacity 0.14s ease;
  }
  .tab-pill.dragging {
    opacity: 0.55;
    cursor: grabbing;
  }
  .tab-pill.detaching {
    opacity: 1;
    background: rgba(240, 178, 84, 0.22);
    border-color: var(--gold-bright);
    color: #ffffff;
    box-shadow: 0 0 0 1px var(--gold-bright), 0 0 14px rgba(240, 178, 84, 0.45);
    cursor: grabbing;
  }
  .tab-pill.drop-before {
    box-shadow: inset 2.5px 0 0 0 var(--gold-bright);
  }
  .tab-pill.drop-after {
    box-shadow: inset -2.5px 0 0 0 var(--gold-bright);
  }
  .tab-pill::after {
    content: "";
    position: absolute;
    right: -2px;
    top: 7px;
    bottom: 7px;
    width: 1px;
    background: rgba(255, 255, 255, 0.1);
    pointer-events: none;
    transition: opacity 0.12s ease;
  }
  .tab-pill:last-child::after,
  .tab-pill.active::after,
  .tab-pill:hover::after,
  .tab-pill:has(+ .tab-pill.active)::after,
  .tab-pill:has(+ .tab-group-pill)::after {
    opacity: 0;
  }
  .tab-pill:hover { background: rgba(255, 255, 255, 0.075); color: var(--text-primary); }
  .tab-pill.active {
    background: rgba(255, 255, 255, 0.13);
    border-color: rgba(255, 255, 255, 0.16);
    color: #ffffff;
    box-shadow: 0 1px 6px rgba(0, 0, 0, 0.28);
  }
  .tab-pill.in-group {
    border-bottom: 2px solid var(--group-color, #f0b254);
    border-bottom-left-radius: 6px;
    border-bottom-right-radius: 6px;
  }
  .tab-pill.in-group.active {
    background: rgba(255, 255, 255, 0.145);
    border-bottom-color: var(--group-color, #f0b254);
  }
  .tab-pill.sleeping {
    opacity: 0.72;
  }
  .tab-pill.sleeping:hover { opacity: 0.96; }

  /* Crisp 16x16 Site Favicon with Brand Fallback & Corner Sleep Indicator */
  .tab-icon-wrap {
    position: relative;
    width: 16px;
    height: 16px;
    flex-shrink: 0;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    pointer-events: none;
  }
  .tab-favicon {
    position: absolute;
    inset: 0;
    width: 16px;
    height: 16px;
    border-radius: 3px;
    object-fit: contain;
    display: block;
    opacity: 0;
    transition: opacity 0.14s ease;
  }
  .tab-favicon.loaded { opacity: 1; }
  .tab-icon-fallback {
    width: 16px;
    height: 16px;
    border-radius: 4px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    font-size: 9.5px;
    font-weight: 800;
    color: #ffffff;
    line-height: 1;
    overflow: hidden;
  }
  .tab-icon-fallback svg { width: 14px; height: 14px; display: block; }
  .tab-icon-fallback img { width: 15px; height: 15px; border-radius: 3px; display: block; }
  .tab-sleep-badge {
    position: absolute;
    right: -2px;
    bottom: -2px;
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--gold-core);
    border: 1.5px solid #0b0c10;
    pointer-events: none;
  }

  .tab-label {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    pointer-events: none;
    flex: 1 1 0;
    min-width: 0;
    line-height: 1.2;
  }
  .tab-close-btn {
    width: 16px; height: 16px; border: none; border-radius: 4px; background: transparent;
    color: var(--text-muted); display: inline-flex; align-items: center; justify-content: center;
    cursor: pointer; opacity: 0.7; flex-shrink: 0;
    transition: background 0.12s ease, color 0.12s ease, opacity 0.12s ease;
  }
  .tab-close-btn:hover { background: rgba(255, 255, 255, 0.16); color: #ffffff; opacity: 1; }

  /* Compact Brave/Chrome Tab Density when many tabs are open:
     Favicons stay 100% crisp; close button reveals on hover so every tab stays recognizable! */
  .tabs-strip.compact-tabs .tab-pill {
    flex: 1 1 118px;
    min-width: 38px;
    padding: 0 6px 0 7px;
    gap: 5px;
  }
  .tabs-strip.compact-tabs .tab-pill:not(.active) .tab-close-btn {
    display: none;
    position: absolute;
    right: 4px;
    background: rgba(22, 24, 32, 0.94);
    box-shadow: -4px 0 6px rgba(14, 16, 22, 0.9);
  }
  .tabs-strip.compact-tabs .tab-pill:not(.active):hover .tab-close-btn {
    display: inline-flex;
    opacity: 0.95;
  }
  .tabs-strip.very-compact .tab-pill:not(.active) {
    min-width: 34px;
    max-width: 96px;
    padding: 0 7px;
  }
  .tabs-strip.very-compact .tab-pill.active {
    min-width: 78px;
  }

  /* Inline Tab Group Name/Color Editor (Strictly fits inside 46px bar, never clipped!) */
  #group-editor-bar {
    position: fixed;
    top: 6px;
    left: 50%;
    transform: translateX(-50%);
    z-index: 160;
    height: 34px;
    padding: 0 8px 0 10px;
    border-radius: 10px;
    background: rgba(14, 16, 24, 0.98);
    border: 1px solid rgba(240, 178, 84, 0.45);
    box-shadow: 0 8px 28px rgba(0, 0, 0, 0.72);
    display: none;
    align-items: center;
    gap: 7px;
    max-width: calc(100vw - 24px);
  }
  #group-editor-bar.open { display: inline-flex; }
  .grp-ed-input {
    width: 138px;
    height: 24px;
    padding: 0 8px;
    border-radius: 6px;
    border: 1px solid rgba(255, 255, 255, 0.14);
    background: rgba(255, 255, 255, 0.06);
    color: #ffffff;
    font-family: inherit;
    font-size: 11.5px;
    outline: none;
  }
  .grp-ed-input:focus { border-color: var(--gold-core); }
  .grp-ed-colors {
    display: inline-flex;
    align-items: center;
    gap: 4px;
  }
  .grp-color-dot {
    width: 14px;
    height: 14px;
    border-radius: 50%;
    border: 2px solid transparent;
    cursor: pointer;
    padding: 0;
    transition: transform 0.12s ease, border-color 0.12s ease;
  }
  .grp-color-dot:hover { transform: scale(1.16); }
  .grp-color-dot.selected { border-color: #ffffff; transform: scale(1.18); }
  .grp-ed-btn {
    height: 24px;
    padding: 0 8px;
    border-radius: 6px;
    border: 1px solid rgba(255, 255, 255, 0.12);
    background: rgba(255, 255, 255, 0.08);
    color: var(--text-primary);
    font-family: inherit;
    font-size: 11px;
    font-weight: 600;
    cursor: pointer;
    white-space: nowrap;
  }
  .grp-ed-btn.primary { background: var(--gold-core); border-color: var(--gold-core); color: #090a0e; }
  .grp-ed-btn:hover { filter: brightness(1.12); }

  /* Non-native Linux/Chromium fallback HTML Tab Context Menu */
  #tab-context-menu {
    position: fixed;
    z-index: 260;
    min-width: 226px;
    padding: 5px;
    border-radius: 10px;
    background: rgba(15, 17, 24, 0.98);
    border: 1px solid rgba(255, 255, 255, 0.14);
    box-shadow: 0 14px 36px rgba(0, 0, 0, 0.78);
    backdrop-filter: blur(18px);
    display: none;
    flex-direction: column;
    gap: 1px;
  }
  #tab-context-menu.open { display: flex; }
  .tctx-item {
    width: 100%;
    border: none;
    border-radius: 6px;
    background: transparent;
    color: var(--text-primary);
    font-family: inherit;
    font-size: 12px;
    padding: 6px 10px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    cursor: pointer;
    text-align: left;
  }
  .tctx-item:hover { background: rgba(255, 255, 255, 0.1); color: #ffffff; }
  .tctx-item:disabled { opacity: 0.4; cursor: default; }
  .tctx-item:disabled:hover { background: transparent; }
  .tctx-item.danger { color: #ff8080; }
  .tctx-item.danger:hover { background: rgba(239, 68, 68, 0.18); color: #ff9c9c; }
  .tctx-kbd { font-family: var(--font-mono); font-size: 10px; color: var(--text-muted); }
  .tctx-sep { height: 1px; background: rgba(255, 255, 255, 0.09); margin: 4px 6px; }
  .tctx-header { font-size: 10px; font-weight: 700; color: var(--text-muted); padding: 4px 10px 2px; text-transform: uppercase; letter-spacing: 0.05em; }
  .tctx-dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; margin-right: 6px; flex-shrink: 0; }

  /* Center Unified Safari Omnibar (Always Mathematically Centered via 1fr / center / 1fr Grid) */
  .omnibar-wrap {
    width: 100%;
    height: 100%;
    padding: 0;
    display: flex;
    align-items: center;
    justify-content: center;
    min-width: 0;
  }

  .safari-omnibar {
    width: 100%;
    max-width: 440px;
    height: 30px;
    padding: 0 5px 0 10px;
    border-radius: 8px;
    background: rgba(255, 255, 255, 0.055);
    border: 1px solid var(--border-hairline);
    display: flex;
    align-items: center;
    gap: 6px;
    transition: background 0.16s ease, border-color 0.16s ease;
  }
  .safari-omnibar:focus-within {
    background: rgba(14, 16, 24, 0.92);
    border-color: rgba(240, 178, 84, 0.42);
  }
  .omnibar-lead-icon { color: var(--text-muted); display: inline-flex; align-items: center; flex-shrink: 0; }
  .omnibar-input {
    flex: 1; min-width: 0; background: transparent; border: none; outline: none;
    color: var(--text-primary); font-family: inherit; font-size: 12.5px;
    user-select: text; -webkit-user-select: text;
  }
  .omnibar-input::placeholder { color: var(--text-muted); }

  .omnibar-act-btn {
    width: 22px; height: 22px; border: none; border-radius: 5px; background: transparent;
    color: var(--text-muted); display: inline-flex; align-items: center; justify-content: center;
    cursor: pointer; transition: color 0.14s ease, background 0.14s ease; flex-shrink: 0;
  }
  .omnibar-act-btn:hover { color: var(--text-primary); background: rgba(255, 255, 255, 0.07); }
  .omnibar-act-btn.starred { color: var(--gold-bright); }

  /* Right Utility Controls & Pinned Chrome Extension Icons */
  .toolbar-right { display: inline-flex; align-items: center; gap: 4px; flex-shrink: 0; max-width: 100%; }

  .ext-toolbar-strip {
    display: inline-flex;
    align-items: center;
    gap: 2px;
    padding-right: 4px;
    margin-right: 2px;
    border-right: 1px solid rgba(255, 255, 255, 0.08);
    max-width: 170px;
    overflow: hidden;
  }
  .ext-toolbar-strip:empty { display: none; }
  .ext-pin-btn {
    width: 26px;
    height: 26px;
    border: none;
    border-radius: 6px;
    background: transparent;
    color: var(--text-primary);
    display: inline-flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
    position: relative;
    transition: background 0.14s ease, transform 0.12s ease;
    flex-shrink: 0;
  }
  .ext-pin-btn:hover { background: var(--glass-hover); transform: scale(1.05); }
  .ext-pin-btn img { width: 16px; height: 16px; border-radius: 3px; object-fit: contain; pointer-events: none; }
  .ext-pin-fallback {
    width: 17px; height: 17px; border-radius: 4px;
    background: rgba(240, 178, 84, 0.22); color: var(--gold-bright);
    font-size: 10px; font-weight: 700; display: inline-flex; align-items: center; justify-content: center;
    pointer-events: none;
  }

  /* 4-Mode RAM Tab Unloader Grid */
  .ram-mode-grid {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 8px;
    margin-top: 4px;
  }
  .ram-mode-btn {
    padding: 10px 10px;
    border-radius: 9px;
    background: rgba(255, 255, 255, 0.035);
    border: 1px solid var(--border-hairline);
    color: var(--text-secondary);
    text-align: left;
    cursor: pointer;
    display: flex;
    flex-direction: column;
    gap: 3px;
    transition: all 0.14s ease;
    font-family: inherit;
  }
  .ram-mode-btn:hover { background: rgba(255, 255, 255, 0.065); color: var(--text-primary); }
  .ram-mode-btn.selected {
    background: rgba(240, 178, 84, 0.15);
    border-color: var(--border-warm);
    color: var(--gold-bright);
  }
  .ram-mode-title { font-size: 12px; font-weight: 600; }
  .ram-mode-desc { font-size: 10.5px; color: var(--text-muted); line-height: 1.35; }
  .ram-mode-btn.selected .ram-mode-desc { color: rgba(255, 223, 158, 0.8); }

  .ext-icon-lg {
    width: 28px; height: 28px; border-radius: 7px; flex-shrink: 0;
    background: rgba(255, 255, 255, 0.06); display: inline-flex; align-items: center; justify-content: center;
    font-weight: 700; color: var(--gold-bright); overflow: hidden;
  }
  .ext-icon-lg img { width: 22px; height: 22px; object-fit: contain; }

  .status-pill {
    height: 28px;
    padding: 0 10px;
    border-radius: 7px;
    background: rgba(12, 15, 22, 0.72);
    border: 1px solid var(--border-hairline);
    color: var(--text-secondary);
    font-family: inherit;
    font-size: 11.5px;
    font-weight: 500;
    display: inline-flex;
    align-items: center;
    gap: 6px;
    cursor: pointer;
    transition: border-color 0.15s ease, color 0.15s ease, background 0.15s ease;
  }
  .status-pill:hover {
    background: rgba(20, 24, 34, 0.88);
    border-color: var(--border-strong);
    color: var(--text-primary);
  }

  .status-dot { width: 6px; height: 6px; border-radius: 50%; background: var(--status-ok); flex-shrink: 0; }
  .status-dot.locked { background: var(--status-danger); }

  /* ==========================================================================
   * MAIN STAGE & NEW TAB PAGE (MATCHING IMAGE 1 EDITORIAL COMPOSITION)
   * ========================================================================== */
  #stage-viewport { position: relative; flex: 1; min-height: 0; width: 100%; display: flex; }

  #ntp-view {
    width: 100%;
    height: 100%;
    padding: 28px 32px;
    display: flex;
    flex-direction: column;
    justify-content: flex-end;
    align-items: flex-start;
    pointer-events: none;
  }

  .ntp-cluster {
    pointer-events: auto;
    max-width: 610px;
    display: flex;
    flex-direction: column;
    gap: 10px;
  }

  .hero-kicker {
    display: inline-flex;
    align-items: center;
    gap: 7px;
    font-family: var(--font-mono);
    font-variant-numeric: tabular-nums;
    font-size: 11px;
    color: var(--text-secondary);
    letter-spacing: 0.04em;
  }

  .hero-title {
    font-size: 40px;
    font-weight: 700;
    letter-spacing: 0.045em;
    line-height: 0.98;
    color: var(--text-primary);
    text-shadow: 0 8px 32px rgba(0, 0, 0, 0.85);
  }

  .ntp-search-bar {
    margin-top: 2px;
    width: 100%;
    max-width: 490px;
    height: 38px;
    padding: 0 6px 0 13px;
    border-radius: 10px;
    background: rgba(10, 12, 18, 0.84);
    border: 1px solid rgba(255, 255, 255, 0.11);
    backdrop-filter: blur(8px);
    -webkit-backdrop-filter: blur(8px);
    display: flex;
    align-items: center;
    gap: 9px;
    box-shadow: 0 12px 32px rgba(0, 0, 0, 0.55);
    transition: border-color 0.18s ease, background 0.18s ease;
  }
  .ntp-search-bar:focus-within {
    background: rgba(12, 14, 22, 0.92);
    border-color: var(--border-warm);
  }

  .ntp-search-input {
    flex: 1; min-width: 0; background: transparent; border: none; outline: none;
    color: var(--text-primary); font-family: inherit; font-size: 12.5px;
    user-select: text; -webkit-user-select: text;
  }
  .ntp-search-input::placeholder { color: var(--text-muted); }

  .engine-pill-select {
    height: 26px; padding: 0 8px; border-radius: 6px;
    background: rgba(255, 255, 255, 0.06); border: 1px solid rgba(255, 255, 255, 0.08);
    color: var(--text-secondary); font-family: inherit; font-size: 11px; font-weight: 500;
    outline: none; cursor: pointer;
  }
  .engine-pill-select option { background: #0d1017; color: var(--text-primary); }

  /* Quick-Launch Bookmarks Strip */
  .quick-row { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-top: 2px; }
  .quick-strip {
    display: inline-flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 2px;
    padding: 3px;
    border-radius: 9px;
    background: rgba(10, 12, 18, 0.82);
    border: 1px solid rgba(255, 255, 255, 0.085);
    backdrop-filter: blur(8px);
    -webkit-backdrop-filter: blur(8px);
  }

  .quick-pill {
    height: 28px;
    padding: 0 10px;
    border: none;
    border-radius: 6px;
    background: transparent;
    color: var(--text-secondary);
    font-family: inherit;
    font-size: 11.5px;
    font-weight: 500;
    display: inline-flex;
    align-items: center;
    gap: 6px;
    cursor: pointer;
    transition: background 0.14s ease, color 0.14s ease;
  }
  .quick-pill:hover { background: rgba(255, 255, 255, 0.08); color: #ffffff; }
  .quick-pill svg { width: 13px; height: 13px; opacity: 0.85; flex-shrink: 0; }

  #web-view { display: none; width: 100%; height: 100%; background: #000000; }
  #web-frame { width: 100%; height: 100%; border: none; background: #0a0a0d; }

  /* ==========================================================================
   * FIRST-LAUNCH INTERACTIVE TUTORIAL WIZARD (4 STEPS + BROWSER IMPORT)
   * ========================================================================== */
  #onboarding-overlay {
    position: fixed;
    inset: var(--bar-height) 0 0 0;
    z-index: 95;
    background: rgba(0, 0, 0, 0.70);
    backdrop-filter: blur(14px);
    -webkit-backdrop-filter: blur(14px);
    display: none;
    align-items: center;
    justify-content: center;
    padding: 20px;
  }
  #onboarding-overlay.open { display: flex; }

  .welcome-card {
    width: 100%;
    max-width: 640px;
    max-height: calc(100vh - var(--bar-height) - 36px);
    overflow-y: auto;
    background: var(--glass-panel);
    border: 1px solid rgba(255, 255, 255, 0.13);
    border-radius: 18px;
    padding: 26px 28px 22px;
    box-shadow: 0 32px 96px rgba(0, 0, 0, 0.90);
    display: flex;
    flex-direction: column;
    gap: 15px;
  }
  .tuto-top-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
  }
  .tuto-step-dots {
    display: inline-flex;
    align-items: center;
    gap: 7px;
  }
  .tuto-dot {
    width: 24px;
    height: 4px;
    border-radius: 99px;
    background: rgba(255, 255, 255, 0.14);
    transition: background 0.2s ease, width 0.2s ease;
  }
  .tuto-dot.active { width: 38px; background: var(--gold-core); }
  .tuto-dot.done { background: var(--status-ok); }

  .tuto-pane { display: none; flex-direction: column; gap: 13px; }
  .tuto-pane.active { display: flex; }

  .tuto-hero-head {
    display: flex;
    align-items: center;
    gap: 14px;
  }
  .welcome-logo {
    width: 54px;
    height: 54px;
    border-radius: 14px;
    box-shadow: 0 10px 28px rgba(0, 0, 0, 0.65);
    flex-shrink: 0;
  }
  .welcome-title { font-size: 20px; font-weight: 700; letter-spacing: 0.01em; }
  .welcome-sub { font-size: 12.5px; color: var(--text-secondary); line-height: 1.55; }

  .tuto-feature-grid {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 9px;
  }
  .tuto-feature-box {
    padding: 11px 12px;
    border-radius: 11px;
    background: rgba(255, 255, 255, 0.035);
    border: 1px solid rgba(255, 255, 255, 0.08);
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  .tuto-feature-title { font-size: 12px; font-weight: 600; color: var(--gold-bright); }
  .tuto-feature-desc { font-size: 11px; color: var(--text-secondary); line-height: 1.45; }

  .engine-grid {
    width: 100%;
    display: grid;
    grid-template-columns: repeat(5, minmax(0, 1fr));
    gap: 7px;
  }
  .eng-choice {
    padding: 9px 6px;
    border-radius: 8px;
    background: rgba(255, 255, 255, 0.04);
    border: 1px solid var(--border-hairline);
    color: var(--text-secondary);
    font-size: 11.5px;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.14s ease;
  }
  .eng-choice:hover { background: rgba(255, 255, 255, 0.08); color: #fff; }
  .eng-choice.selected {
    background: var(--gold-soft-bg);
    border-color: var(--border-warm);
    color: var(--gold-bright);
  }

  /* Browser Tab Importer Cards (inside Tutorial & Settings) */
  .import-browser-list {
    display: flex;
    flex-direction: column;
    gap: 8px;
    max-height: 245px;
    overflow-y: auto;
    padding-right: 2px;
  }
  .import-browser-card {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    padding: 11px 13px;
    border-radius: 11px;
    background: rgba(255, 255, 255, 0.035);
    border: 1px solid rgba(255, 255, 255, 0.08);
    cursor: pointer;
    transition: border-color 0.15s ease, background 0.15s ease;
  }
  .import-browser-card:hover { background: rgba(255, 255, 255, 0.06); }
  .import-browser-card.selected {
    background: var(--gold-soft-bg);
    border-color: var(--border-warm);
  }
  .import-browser-badge {
    width: 34px;
    height: 34px;
    border-radius: 9px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    font-weight: 700;
    font-size: 13px;
    color: #fff;
    flex-shrink: 0;
  }
  .import-check-box {
    width: 18px;
    height: 18px;
    border-radius: 5px;
    border: 1.5px solid var(--border-strong);
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    font-size: 11px;
    font-weight: 700;
    color: var(--btn-ink);
    background: transparent;
  }
  .import-browser-card.selected .import-check-box {
    background: var(--gold-core);
    border-color: var(--gold-bright);
  }

  .tuto-footer {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    padding-top: 10px;
    border-top: 1px solid rgba(255, 255, 255, 0.07);
  }

  /* Cosmic Theme Cards Gallery (Settings & Tutorial) */
  .theme-gallery-grid {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 11px;
  }
  .theme-card {
    padding: 12px;
    border-radius: 12px;
    background: rgba(255, 255, 255, 0.03);
    border: 1px solid rgba(255, 255, 255, 0.08);
    cursor: pointer;
    text-align: left;
    color: var(--text-primary);
    font-family: inherit;
    display: flex;
    flex-direction: column;
    gap: 8px;
    transition: transform 0.14s ease, border-color 0.16s ease, background 0.16s ease;
  }
  .theme-card:hover { background: rgba(255, 255, 255, 0.06); transform: translateY(-1px); }
  .theme-card.selected {
    background: var(--gold-soft-bg);
    border-color: var(--border-warm);
    box-shadow: 0 0 0 1px var(--border-warm);
  }
  .theme-preview-orb {
    width: 100%;
    height: 54px;
    border-radius: 8px;
    position: relative;
    overflow: hidden;
    border: 1px solid rgba(255, 255, 255, 0.09);
  }
  .theme-card-name { font-size: 12.5px; font-weight: 600; display: flex; align-items: center; justify-content: space-between; }
  .theme-card-desc { font-size: 11px; color: var(--text-secondary); line-height: 1.35; }

  .lang-choice-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 10px;
  }
  .lang-choice-card {
    padding: 12px 14px;
    border-radius: 12px;
    background: rgba(255, 255, 255, 0.035);
    border: 1px solid rgba(255, 255, 255, 0.09);
    color: var(--text-primary);
    font-family: inherit;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    text-align: left;
    transition: transform 0.14s ease, border-color 0.16s ease, background 0.16s ease;
  }
  .lang-choice-card:hover { background: rgba(255, 255, 255, 0.07); transform: translateY(-1px); }
  .lang-choice-card.selected {
    background: var(--gold-soft-bg);
    border-color: var(--border-warm);
    box-shadow: 0 0 0 1px var(--border-warm);
  }
  .lang-code-pill {
    width: 34px;
    height: 34px;
    border-radius: 9px;
    background: rgba(255, 255, 255, 0.08);
    border: 1px solid rgba(255, 255, 255, 0.12);
    color: var(--gold-bright);
    font-family: var(--font-mono);
    font-size: 12px;
    font-weight: 700;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }
  .lang-choice-card.selected .lang-code-pill {
    background: var(--gold-core);
    border-color: var(--gold-bright);
    color: var(--btn-ink);
  }
  .tuto-step-req-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
  }
  .tuto-required-badge {
    font-size: 10px;
    font-family: var(--font-mono);
    padding: 2px 7px;
    border-radius: 999px;
    background: rgba(255, 255, 255, 0.06);
    border: 1px solid rgba(255, 255, 255, 0.12);
    color: var(--text-muted);
    transition: all 0.16s ease;
  }
  .tuto-required-badge.done {
    background: rgba(52, 211, 153, 0.15);
    border-color: rgba(52, 211, 153, 0.40);
    color: var(--status-ok);
  }
  .bm-icon-wrap {
    width: 15px;
    height: 15px;
    border-radius: 4px;
    position: relative;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    overflow: hidden;
    flex-shrink: 0;
    font-size: 9.5px;
    font-weight: 800;
    color: #fff;
  }
  .bm-icon-wrap img {
    position: absolute;
    inset: 0;
    width: 100%;
    height: 100%;
    object-fit: contain;
    opacity: 0;
    transition: opacity 0.15s ease;
  }
  .bm-icon-wrap img.loaded { opacity: 1; }

  .btn-gold {
    height: 34px;
    padding: 0 18px;
    border-radius: 9px;
    border: 1px solid var(--border-warm);
    background: linear-gradient(180deg, var(--btn-grad-top) 0%, var(--btn-grad-bot) 100%);
    color: var(--btn-ink);
    font-family: inherit;
    font-size: 12.5px;
    font-weight: 600;
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 7px;
    transition: filter 0.14s ease, transform 0.12s ease, opacity 0.14s ease;
  }
  .btn-gold:hover:not(:disabled) { filter: brightness(1.07); }
  .btn-gold:active:not(:disabled) { transform: scale(0.98); }
  .btn-gold:disabled {
    opacity: 0.40;
    cursor: not-allowed;
    filter: grayscale(0.45);
  }

  /* ==========================================================================
   * FULL-PAGE SETTINGS TAB (`singularity://settings` — BRAVE/CHROME LAYOUT)
   * ========================================================================== */
  #settings-modal {
    position: fixed;
    inset: var(--bar-height) 0 0 0;
    z-index: 60;
    background: var(--page-bg);
    display: none;
    flex-direction: row;
    overflow: hidden;
  }
  #settings-modal.open { display: flex; }

  .glass-sheet {
    width: 100%;
    height: 100%;
    background: var(--page-bg);
    display: flex;
    flex-direction: row;
    overflow: hidden;
  }

  .settings-sidebar {
    width: 244px;
    min-width: 220px;
    background: var(--page-sidebar);
    border-right: 1px solid rgba(255, 255, 255, 0.07);
    display: flex;
    flex-direction: column;
    padding: 18px 12px 14px;
    gap: 4px;
    overflow-y: auto;
    flex-shrink: 0;
  }
  .settings-brand-head {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 4px 10px 14px;
    margin-bottom: 4px;
    border-bottom: 1px solid rgba(255, 255, 255, 0.06);
  }
  .settings-brand-head img { width: 24px; height: 24px; border-radius: 6px; }
  .settings-brand-title { font-size: 15px; font-weight: 700; letter-spacing: 0.01em; }

  .sheet-tabs {
    display: flex;
    flex-direction: column;
    gap: 3px;
    flex: 1;
  }
  .sheet-tab-btn {
    width: 100%;
    height: 36px;
    padding: 0 12px;
    border: 1px solid transparent;
    border-radius: 9px;
    background: transparent;
    color: var(--text-secondary);
    font-family: inherit;
    font-size: 12.5px;
    font-weight: 500;
    cursor: pointer;
    display: flex;
    align-items: center;
    gap: 10px;
    text-align: left;
    transition: all 0.14s ease;
  }
  .sheet-tab-btn svg { width: 15px; height: 15px; opacity: 0.8; flex-shrink: 0; }
  .sheet-tab-btn:hover { color: var(--text-primary); background: rgba(255, 255, 255, 0.05); }
  .sheet-tab-btn.active {
    background: var(--gold-soft-bg);
    border-color: var(--border-warm);
    color: var(--gold-bright);
    font-weight: 600;
  }
  .sheet-tab-btn.active svg { opacity: 1; }

  .settings-sidebar-footer {
    margin-top: auto;
    padding: 12px 10px 4px;
    border-top: 1px solid rgba(255, 255, 255, 0.06);
    display: flex;
    flex-direction: column;
    gap: 2px;
    font-size: 11px;
    color: var(--text-muted);
  }

  .settings-main-col {
    flex: 1;
    min-width: 0;
    height: 100%;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }

  .sheet-header {
    padding: 14px 28px;
    border-bottom: 1px solid rgba(255, 255, 255, 0.06);
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 14px;
    flex-shrink: 0;
  }
  .settings-page-heading {
    font-size: 16px;
    font-weight: 600;
    color: var(--text-primary);
  }

  .sheet-search {
    width: min(380px, 46vw);
    height: 34px;
    padding: 0 13px;
    border-radius: 9px;
    background: rgba(255, 255, 255, 0.05);
    border: 1px solid var(--border-hairline);
    color: var(--text-primary);
    font-family: inherit;
    font-size: 12.5px;
    outline: none;
    user-select: text;
    -webkit-user-select: text;
  }
  .sheet-search:focus { border-color: var(--border-warm); background: rgba(255, 255, 255, 0.075); }

  .text-field {
    height: 32px;
    padding: 0 11px;
    border-radius: 7px;
    background: rgba(255, 255, 255, 0.05);
    border: 1px solid var(--border-hairline);
    color: var(--text-primary);
    font-family: inherit;
    font-size: 12px;
    outline: none;
    user-select: text;
    -webkit-user-select: text;
  }
  .text-field:focus { border-color: var(--border-warm); }

  .sheet-body { flex: 1; display: none; min-height: 0; overflow: hidden; }
  .cats-sidebar {
    width: 240px;
    border-right: 1px solid rgba(255, 255, 255, 0.07);
    padding: 12px;
    overflow-y: auto;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .cat-btn {
    padding: 8px 10px; border: none; border-radius: 7px; background: transparent;
    color: var(--text-secondary); font-family: inherit; font-size: 12px; text-align: left;
    display: flex; align-items: center; justify-content: space-between; cursor: pointer;
  }
  .cat-btn:hover { background: rgba(255, 255, 255, 0.05); color: var(--text-primary); }
  .cat-btn.active { background: rgba(255, 255, 255, 0.09); color: #ffffff; font-weight: 500; }
  .cat-count { font-family: var(--font-mono); font-size: 10.5px; color: var(--text-muted); }

  .rows-pane { flex: 1; overflow-y: auto; padding: 14px 26px; }
  .setting-item {
    padding: 11px 6px;
    border-bottom: 1px solid rgba(255, 255, 255, 0.05);
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
  }
  .setting-title { font-size: 12.5px; font-weight: 500; color: var(--text-primary); }
  .setting-desc  { font-size: 11px; color: var(--text-muted); margin-top: 2px; }

  .toggle-pill {
    min-width: 48px; height: 26px; padding: 0 10px; border-radius: 6px;
    border: 1px solid var(--border-hairline); background: rgba(255, 255, 255, 0.05);
    color: var(--text-secondary); font-family: var(--font-mono); font-size: 11px; cursor: pointer;
  }
  .toggle-pill.on {
    background: var(--gold-soft-bg);
    border-color: var(--border-warm);
    color: var(--gold-bright);
  }

  .panel-grid {
    flex: 1;
    padding: 24px 32px 36px;
    overflow-y: auto;
    display: none;
    flex-direction: column;
    gap: 16px;
    align-items: center;
  }
  .panel-grid > * {
    width: 100%;
    max-width: 840px;
  }

  .info-card {
    padding: 16px 18px;
    border-radius: 12px;
    background: var(--page-card);
    border: 1px solid rgba(255, 255, 255, 0.075);
    display: flex;
    flex-direction: column;
    gap: 10px;
  }

  .card-label {
    font-size: 10.5px;
    font-family: var(--font-mono);
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--text-muted);
  }

  .mono-val { font-family: var(--font-mono); font-size: 12px; color: var(--gold-bright); word-break: break-all; }

  .btn-subtle {
    height: 30px; padding: 0 12px; border-radius: 7px;
    border: 1px solid var(--border-hairline); background: rgba(255, 255, 255, 0.055);
    color: var(--text-primary); font-family: inherit; font-size: 11.5px; font-weight: 500;
    cursor: pointer; display: inline-flex; align-items: center; gap: 6px;
  }
  .btn-subtle:hover { background: rgba(255, 255, 255, 0.10); border-color: var(--border-strong); }
  .btn-danger { border-color: rgba(248, 113, 113, 0.32); color: #fca5a5; }
  .btn-danger:hover { background: rgba(248, 113, 113, 0.14); border-color: rgba(248, 113, 113, 0.5); }

  .token-row {
    padding: 9px 12px;
    border-radius: 8px;
    background: rgba(0, 0, 0, 0.35);
    border: 1px solid rgba(255, 255, 255, 0.06);
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    flex-wrap: wrap;
  }
  .prov-badge {
    padding: 2px 8px;
    border-radius: 5px;
    background: var(--gold-soft-bg);
    border: 1px solid var(--border-warm);
    color: var(--gold-bright);
    font-size: 11px;
    font-weight: 600;
  }

  /* Toast Notification — Never Clipped (Adapts cleanly when bar-only 46px strip is active!) */
  #toast {
    position: fixed;
    bottom: 22px;
    right: 24px;
    z-index: 200;
    max-width: min(460px, calc(100vw - 48px));
    padding: 9px 15px;
    border-radius: 10px;
    background: rgba(14, 16, 24, 0.96);
    border: 1px solid var(--border-warm);
    color: var(--text-primary);
    font-size: 12px;
    line-height: 1.35;
    display: inline-flex;
    align-items: center;
    gap: 8px;
    box-shadow: 0 12px 34px rgba(0,0,0,0.72);
    opacity: 0;
    transform: translateY(8px);
    pointer-events: none;
    transition: opacity 0.18s ease, transform 0.18s ease;
  }
  #toast::before {
    content: "";
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--gold-core);
    box-shadow: 0 0 8px var(--gold-core);
    flex-shrink: 0;
  }
  #toast.show { opacity: 1; transform: translateY(0); }
  #toast.show.clickable { pointer-events: auto; cursor: pointer; }
  #toast.show.clickable:hover { border-color: var(--gold-bright); }

  /* When browsing a web page (`body.bar-only`), ui_webview is 46px tall:
     render a crisp centered 32px pill strictly within y=7..39px so it is NEVER cut off! */
  body.bar-only #toast {
    top: 7px;
    bottom: auto;
    left: 50%;
    right: auto;
    height: 32px;
    padding: 0 14px;
    max-width: min(560px, calc(100vw - 140px));
    border-radius: 999px;
    font-size: 11.5px;
    line-height: 1;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.58);
    transform: translateX(-50%) translateY(-6px);
  }
  body.bar-only #toast.show {
    opacity: 1;
    transform: translateX(-50%) translateY(0);
  }

  /* Frameless window border resize handles */
  .rz { position: fixed; z-index: 90; }
  .rz-n  { top: 0; left: 6px; right: 6px; height: 3px; cursor: ns-resize; }
  .rz-s  { bottom: 0; left: 6px; right: 6px; height: 4px; cursor: ns-resize; }
  .rz-w  { left: 0; top: 6px; bottom: 6px; width: 4px; cursor: ew-resize; }
  .rz-e  { right: 0; top: 6px; bottom: 6px; width: 4px; cursor: ew-resize; }
  .rz-nw { top: 0; left: 0; width: 8px; height: 8px; cursor: nwse-resize; }
  .rz-ne { top: 0; right: 0; width: 8px; height: 8px; cursor: nesw-resize; }
  .rz-sw { bottom: 0; left: 0; width: 8px; height: 8px; cursor: nesw-resize; }
  .rz-se { bottom: 0; right: 0; width: 8px; height: 8px; cursor: nwse-resize; }
  body.bar-only .rz-s, body.bar-only .rz-sw, body.bar-only .rz-se { display: none; }
  body.is-maximized .rz { display: none !important; pointer-events: none !important; }

  /* Responsive top bar for narrow Windows 11 Snap Layout zones (down to 480px) */
  @media (max-width: 860px) {
    .apple-bar {
      padding: 0 10px;
      gap: 6px;
      grid-template-columns: minmax(0, 1fr) clamp(175px, 28vw, 290px) minmax(0, 1fr);
    }
    .apple-bar.tabs-expanded {
      grid-template-columns: minmax(0, 1fr) clamp(145px, 24vw, 220px) auto;
    }
    .toolbar-left { gap: 5px; }
    .tab-pill { min-width: 54px; max-width: 112px; padding: 0 5px 0 7px; }
    .status-pill { padding: 0 7px; }
    .status-pill #vpn-label { display: none; }
    .ext-toolbar-strip { max-width: 84px; }
    .ram-mode-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .theme-gallery-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .tuto-feature-grid { grid-template-columns: 1fr; }
    .settings-sidebar { width: 196px; min-width: 180px; }
  }
  @media (max-width: 640px) {
    .apple-bar, .apple-bar.tabs-expanded {
      padding: 0 8px;
      gap: 4px;
      grid-template-columns: minmax(0, 1fr) clamp(110px, 30vw, 180px) auto;
    }
    .traffic-lights { gap: 6px; margin-right: 0; }
    .icon-btn, .brand-home-btn { width: 24px; height: 24px; }
    .tab-pill { min-width: 46px; max-width: 84px; }
    .ext-toolbar-strip { display: none; }
    body.bar-only #toast { max-width: calc(100vw - 24px); }
  }
</style>
</head>
<body>

  <!-- Frameless Window Resize Grips -->
  <div class="rz rz-n" onmousedown="startResize('North', event)"></div>
  <div class="rz rz-s" onmousedown="startResize('South', event)"></div>
  <div class="rz rz-w" onmousedown="startResize('West', event)"></div>
  <div class="rz rz-e" onmousedown="startResize('East', event)"></div>
  <div class="rz rz-nw" onmousedown="startResize('NorthWest', event)"></div>
  <div class="rz rz-ne" onmousedown="startResize('NorthEast', event)"></div>
  <div class="rz rz-sw" onmousedown="startResize('SouthWest', event)"></div>
  <div class="rz rz-se" onmousedown="startResize('SouthEast', event)"></div>

  <!-- 3D Schwarzschild Gargantua Black Hole Canvas (Reference Image 1) -->
  <canvas id="singularity-canvas"></canvas>
  <div class="cinema-vignette" id="cinema-vignette"></div>

  <div id="app-shell">
    <!-- UNIFIED APPLE SAFARI TOP BAR (3-column symmetric Grid keeps URL bar centered always) -->
    <header class="apple-bar" id="apple-titlebar">
      <!-- Left Column: Traffic Lights + Navigation + Overflow-Proof Tabs -->
      <div class="toolbar-left">
        <!-- Three Colored Apple Traffic Lights -->
        <div class="traffic-lights" role="group" aria-label="Window controls" data-i18n-aria="win_controls">
          <button type="button" class="tl-dot tl-close" title="Close" data-i18n-title="win_close" onclick="winAction('close')">
            <svg viewBox="0 0 10 10" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round">
              <path d="M2.2 2.2l5.6 5.6M7.8 2.2L2.2 7.8"/>
            </svg>
          </button>
          <button type="button" class="tl-dot tl-min" title="Minimize" data-i18n-title="win_min" onclick="winAction('minimize')">
            <svg viewBox="0 0 10 10" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round">
              <path d="M1.8 5h6.4"/>
            </svg>
          </button>
          <button type="button" class="tl-dot tl-max" title="Maximize" data-i18n-title="win_max" onclick="winAction('toggle_maximize')">
            <svg viewBox="0 0 10 10" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round">
              <path d="M2.2 5.8V7.8h2M7.8 4.2V2.2h-2"/>
            </svg>
          </button>
        </div>

        <!-- Studio Brand Logo + Safari Navigation Chevrons -->
        <div class="safari-nav-group">
          <button type="button" class="brand-home-btn" title="Singularity Home" data-i18n-title="nav_home" onclick="openHomeInActiveTab()">
            <img src="/api/logo.png" alt="Singularity" />
          </button>
          <button type="button" class="icon-btn" title="Back" data-i18n-title="nav_back" onclick="historyBack()">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">
              <polyline points="15 18 9 12 15 6"/>
            </svg>
          </button>
          <button type="button" class="icon-btn" title="Forward" data-i18n-title="nav_forward" onclick="historyForward()">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">
              <polyline points="9 18 15 12 9 6"/>
            </svg>
          </button>
        </div>

        <!-- Overflow-Proof Multi-Tab Bar -->
        <div class="tabs-bar-wrap">
          <button type="button" class="tabs-scroll-btn" id="tabs-scroll-left" title="Scroll tabs left" data-i18n-title="tabs_scroll_left" onclick="scrollTabsStrip(-200)">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <polyline points="15 18 9 12 15 6"/>
            </svg>
          </button>
          <div class="tabs-strip" id="tabs-strip"></div>
          <button type="button" class="tabs-scroll-btn" id="tabs-scroll-right" title="Scroll tabs right" data-i18n-title="tabs_scroll_right" onclick="scrollTabsStrip(200)">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <polyline points="9 18 15 12 9 6"/>
            </svg>
          </button>
          <button type="button" class="icon-btn" title="New tab (Ctrl+T)" data-i18n-title="nav_new_tab" onclick="createNewTab()">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round">
              <line x1="12" y1="5" x2="12" y2="19"/>
              <line x1="5" y1="12" x2="19" y2="12"/>
            </svg>
          </button>
        </div>
      </div>

      <!-- Center Column: Always-Centered Unified Safari Omnibar -->
      <div class="omnibar-wrap">
        <div class="safari-omnibar">
          <span class="omnibar-lead-icon">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">
              <rect x="5" y="11" width="14" height="10" rx="2"/>
              <path d="M8 11V7a4 4 0 0 1 8 0v4"/>
            </svg>
          </span>
          <input id="omnibar-input" class="omnibar-input" type="text" spellcheck="false"
                 placeholder="Search or enter website address"
                 data-i18n-placeholder="omnibar_placeholder"
                 onkeydown="if(event.key==='Enter') navigateInput(this.value)" />
          <button type="button" class="omnibar-act-btn" id="btn-bookmark-star" title="Bookmark this page (Ctrl+D)" data-i18n-title="nav_bookmark" onclick="toggleActiveBookmark()">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">
              <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/>
            </svg>
          </button>
          <button type="button" class="omnibar-act-btn" title="Reload (Ctrl+R)" data-i18n-title="nav_reload" onclick="reloadActivePage()">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
              <path d="M21 12a9 9 0 1 1-2.64-6.36"/>
              <polyline points="21 3 21 9 15 9"/>
            </svg>
          </button>
        </div>
      </div>

      <!-- Right Column: Utility Actions & Chrome Extensions -->
      <div class="toolbar-right-wrap">
        <div class="toolbar-right">
          <div class="ext-toolbar-strip" id="ext-toolbar-strip"></div>

          <button type="button" class="icon-btn" id="btn-extensions" title="Chrome Extensions (Web Store & local)" data-i18n-title="nav_extensions" onclick="openSheet('extensions')">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.65" stroke-linecap="round" stroke-linejoin="round">
              <path d="M19.439 7.85c-.049.322.059.648.289.878l1.568 1.568c.47.47.706 1.087.706 1.704s-.235 1.233-.706 1.704l-1.611 1.611a.98.98 0 0 1-.837.276c-.47-.07-.802-.48-.968-.925a2.501 2.501 0 1 0-3.214 3.214c.446.166.855.497.925.968a.979.979 0 0 1-.276.837l-1.61 1.61a2.404 2.404 0 0 1-1.705.707 2.402 2.402 0 0 1-1.704-.706l-1.568-1.568a1.026 1.026 0 0 0-.877-.29c-.493.074-.84.504-1.02.968a2.5 2.5 0 1 1-3.237-3.237c.464-.18.894-.527.967-1.02a1.026 1.026 0 0 0-.289-.877l-1.568-1.568A2.402 2.402 0 0 1 1.998 12c0-.617.236-1.234.706-1.704L4.23 8.77c.24-.24.581-.353.917-.303.515.077.877.528 1.073 1.01a2.5 2.5 0 1 0 3.259-3.259c-.482-.196-.933-.558-1.01-1.073-.05-.336.062-.676.303-.917l1.525-1.525A2.402 2.402 0 0 1 12 2c.617 0 1.234.236 1.704.706l1.568 1.568c.23.23.556.338.877.29.493-.074.84-.504 1.02-.968a2.5 2.5 0 1 1 3.237 3.237c-.464.18-.894.527-.967 1.02Z"/>
            </svg>
            <span class="mini-badge" id="ext-count-badge">0</span>
          </button>

          <button type="button" class="icon-btn" id="btn-private-mode" title="Private Browsing (ephemeral)" data-i18n-title="nav_private" onclick="togglePrivateMode()">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.65" stroke-linecap="round" stroke-linejoin="round">
              <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/>
              <path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/>
              <line x1="1" y1="1" x2="23" y2="23"/>
            </svg>
          </button>

          <button type="button" class="icon-btn" id="btn-roaming-tokens" title="Encrypted Sessions & Tokens (.singularity)" data-i18n-title="nav_tokens" onclick="openSheet('tokens')">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.65" stroke-linecap="round" stroke-linejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
            <span class="mini-badge" id="tokens-count-badge">0</span>
          </button>

          <button type="button" class="status-pill" title="Network Shield & WireGuard" data-i18n-title="nav_shield" onclick="openSheet('mullvad')">
            <span class="status-dot" id="vpn-dot"></span>
            <span id="vpn-label">Shield</span>
          </button>

          <button type="button" class="icon-btn" title="Argon2id Vault & 2FA" data-i18n-title="nav_vault" onclick="openSheet('vault')">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.65" stroke-linecap="round" stroke-linejoin="round">
              <circle cx="7.5" cy="15.5" r="4.5"/>
              <path d="M10.7 12.3 19 4"/>
              <path d="M16 7l3 3"/>
            </svg>
          </button>

          <button type="button" class="icon-btn" title="Control Center & Settings (Ctrl+,)" data-i18n-title="nav_settings" onclick="openSheet('general')">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.65" stroke-linecap="round" stroke-linejoin="round">
              <line x1="4" y1="21" x2="4" y2="14"/>
              <line x1="4" y1="10" x2="4" y2="3"/>
              <line x1="12" y1="21" x2="12" y2="12"/>
              <line x1="12" y1="8" x2="12" y2="3"/>
              <line x1="20" y1="21" x2="20" y2="16"/>
              <line x1="20" y1="12" x2="20" y2="3"/>
              <line x1="2" y1="14" x2="6" y2="14"/>
              <line x1="10" y1="8" x2="14" y2="8"/>
              <line x1="18" y1="16" x2="22" y2="16"/>
            </svg>
          </button>
        </div>
      </div>
    </header>

    <!-- VIEWPORT STAGE -->
    <main id="stage-viewport">
      <!-- NEW TAB PAGE -->
      <section id="ntp-view">
        <div class="ntp-cluster">
          <div class="hero-kicker">
            <span class="status-dot" id="ntp-kicker-dot"></span>
            <span id="ntp-kicker-text">Singularity &middot; Encrypted .singularity Vault</span>
          </div>
          <h1 class="hero-title">SINGULARITY</h1>

          <div class="ntp-search-bar">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text-muted);flex-shrink:0;">
              <circle cx="11" cy="11" r="7.5"/>
              <line x1="20" y1="20" x2="16.35" y2="16.35"/>
            </svg>
            <input id="ntp-search-input" class="ntp-search-input" type="text" spellcheck="false"
                   placeholder="Search the web or enter a URL..."
                   data-i18n-placeholder="ntp_placeholder"
                   onkeydown="if(event.key==='Enter') executeNtpSearch(this.value)" />
            <select id="search-engine" class="engine-pill-select" aria-label="Search engine" data-i18n-aria="search_engine_aria" onchange="saveDefaultEngine(this.value)">
              <option value="ddg">DuckDuckGo</option>
              <option value="google">Google</option>
              <option value="brave">Brave</option>
              <option value="qwant">Qwant</option>
              <option value="startpage">Startpage</option>
            </select>
          </div>

          <!-- Dynamic User Bookmarks Strip -->
          <div class="quick-row">
            <div class="quick-strip" id="ntp-bookmarks-strip"></div>
          </div>
        </div>
      </section>

      <!-- FALLBACK WEB VIEWPORT (NON-NATIVE MODE — STRICT OPAQUE SANDBOX) -->
      <section id="web-view">
        <iframe id="web-frame" src="about:blank" sandbox="allow-scripts allow-forms allow-popups allow-modals allow-presentation allow-downloads"></iframe>
      </section>
    </main>
  </div>

  <!-- FIRST-LAUNCH INTERACTIVE ONBOARDING WIZARD (STEP 1 MANDATORY: LANGUAGE & COLOR THEME) -->
  <div id="onboarding-overlay" data-mandatory="true">
    <div class="welcome-card">
      <div class="tuto-top-row">
        <div class="tuto-step-dots" id="tuto-step-dots">
          <span class="tuto-dot active" data-step="0"></span>
          <span class="tuto-dot" data-step="1"></span>
          <span class="tuto-dot" data-step="2"></span>
        </div>
        <button type="button" class="btn-subtle" id="btn-tuto-skip" style="height:26px;font-size:11px;display:none;" data-i18n="tuto_skip" onclick="skipTutorial()">Skip remaining steps</button>
      </div>

      <!-- STEP 1 (MANDATORY): LANGUAGE & COLOR THEME -->
      <div class="tuto-pane active" id="tuto-step-0">
        <div class="tuto-hero-head">
          <img src="/api/logo.png" alt="Singularity Logo" class="welcome-logo" />
          <div>
            <div class="welcome-title" data-i18n="tuto0_title">Welcome to Singularity</div>
            <div class="welcome-sub" data-i18n="tuto0_sub">
              Choose your display language and color theme to get started. Both selections are required before continuing.
            </div>
          </div>
        </div>

        <div class="tuto-step-req-row">
          <span class="card-label" data-i18n="tuto0_lang_label">1. Display Language</span>
          <span class="tuto-required-badge" id="tuto-req-lang" data-i18n="tuto_required">Required</span>
        </div>
        <div class="lang-choice-grid" id="onboard-lang-grid">
          <button type="button" class="lang-choice-card" data-lang="en" onclick="pickOnboardLanguage('en')">
            <div style="display:flex;align-items:center;gap:10px;">
              <span class="lang-code-pill">EN</span>
              <div>
                <div style="font-size:13px;font-weight:600;">English</div>
                <div style="font-size:11px;color:var(--text-secondary);">Default interface language</div>
              </div>
            </div>
            <span class="tuto-required-badge" data-lang-check="en"></span>
          </button>
          <button type="button" class="lang-choice-card" data-lang="fr" onclick="pickOnboardLanguage('fr')">
            <div style="display:flex;align-items:center;gap:10px;">
              <span class="lang-code-pill">FR</span>
              <div>
                <div style="font-size:13px;font-weight:600;">Français</div>
                <div style="font-size:11px;color:var(--text-secondary);">Interface en français</div>
              </div>
            </div>
            <span class="tuto-required-badge" data-lang-check="fr"></span>
          </button>
        </div>

        <div class="tuto-step-req-row" style="margin-top:2px;">
          <span class="card-label" data-i18n="tuto0_theme_label">2. Color Theme &amp; 3D Backdrop</span>
          <span class="tuto-required-badge" id="tuto-req-theme" data-i18n="tuto_required">Required</span>
        </div>
        <div class="theme-gallery-grid" id="tuto-theme-grid"></div>
        <div id="tuto-mandatory-hint" style="font-size:11.5px;color:var(--gold-bright);text-align:center;" data-i18n="tuto0_hint">
          Select both a language and a color theme to unlock Continue.
        </div>
      </div>

      <!-- STEP 2 (OPTIONAL): IMPORT OPEN TABS & BOOKMARKS FROM INSTALLED BROWSERS -->
      <div class="tuto-pane" id="tuto-step-1">
        <div style="display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;">
          <div>
            <div class="welcome-title" style="font-size:18px;" data-i18n="tuto1_title">Import your open tabs &amp; bookmarks?</div>
            <div class="welcome-sub" data-i18n="tuto1_sub">
              Detected browsers on this PC (local read-only scan, zero files modified). Imported tabs start sleeping in RAM so videos never autoplay.
            </div>
          </div>
          <button type="button" class="btn-subtle" style="height:28px;" data-i18n="btn_refresh" onclick="scanInstalledBrowsersForTutorial()">Refresh</button>
        </div>
        <div class="import-browser-list" id="tuto-browsers-list">
          <div style="font-size:12px;color:var(--text-muted);padding:14px;text-align:center;" data-i18n="tuto1_scanning">Scanning installed browsers on this PC...</div>
        </div>
        <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;">
          <label style="display:inline-flex;align-items:center;gap:7px;font-size:12px;color:var(--text-secondary);cursor:pointer;">
            <input type="checkbox" id="tuto-import-bookmarks" checked />
            <span data-i18n="tuto1_also_bookmarks">Also import bookmarks from selected browsers</span>
          </label>
          <button type="button" class="btn-gold" style="height:31px;padding:0 14px;" id="btn-tuto-import-now" data-i18n="tuto1_import_btn" onclick="executeTutorialBrowserImport()">
            Import selected tabs
          </button>
        </div>
        <div id="tuto-import-result" style="font-size:11.5px;color:var(--status-ok);display:none;"></div>
      </div>

      <!-- STEP 3 (OPTIONAL): SEARCH ENGINE, SMART RAM SAVER & QUICK TIPS -->
      <div class="tuto-pane" id="tuto-step-2">
        <div class="tuto-hero-head">
          <img src="/api/logo.png" alt="Singularity Logo" class="welcome-logo" />
          <div>
            <div class="welcome-title" style="font-size:19px;" data-i18n="tuto2_title">Search Engine &amp; Smart RAM Saver</div>
            <div class="welcome-sub" id="tuto-summary-text" data-i18n="tuto2_sub">Customize your default search engine and automatic tab memory sleep.</div>
          </div>
        </div>
        <div class="card-label" data-i18n="tuto2_engine_label">Default Search Engine</div>
        <div class="engine-grid" id="onboard-engines">
          <button type="button" class="eng-choice selected" data-eng="ddg" onclick="pickOnboardEngine('ddg', this)">DuckDuckGo</button>
          <button type="button" class="eng-choice" data-eng="google" onclick="pickOnboardEngine('google', this)">Google</button>
          <button type="button" class="eng-choice" data-eng="brave" onclick="pickOnboardEngine('brave', this)">Brave</button>
          <button type="button" class="eng-choice" data-eng="qwant" onclick="pickOnboardEngine('qwant', this)">Qwant</button>
          <button type="button" class="eng-choice" data-eng="startpage" onclick="pickOnboardEngine('startpage', this)">Startpage</button>
        </div>
        <div class="card-label" style="margin-top:2px;" data-i18n="tuto2_ram_label">Inactive Tab RAM Unloader</div>
        <div class="ram-mode-grid" id="tuto-ram-grid">
          <button type="button" class="ram-mode-btn" data-ram-mode="low" onclick="selectRamMode('low')">
            <span class="ram-mode-title">Low</span>
            <span class="ram-mode-desc" data-i18n="ram_low_short">Unload after 2h</span>
          </button>
          <button type="button" class="ram-mode-btn selected" data-ram-mode="medium" onclick="selectRamMode('medium')">
            <span class="ram-mode-title">Medium</span>
            <span class="ram-mode-desc" data-i18n="ram_med_short">Unload after 15 min</span>
          </button>
          <button type="button" class="ram-mode-btn" data-ram-mode="hard" onclick="selectRamMode('hard')">
            <span class="ram-mode-title">Hard</span>
            <span class="ram-mode-desc" data-i18n="ram_hard_short">Unload after 3 min</span>
          </button>
          <button type="button" class="ram-mode-btn" data-ram-mode="custom" onclick="selectRamMode('custom')">
            <span class="ram-mode-title" data-i18n="ram_custom_title">Custom</span>
            <span class="ram-mode-desc" data-i18n="ram_custom_short">Configure in Settings</span>
          </button>
        </div>
        <div class="tuto-feature-grid">
          <div class="tuto-feature-box">
            <span class="tuto-feature-title" data-i18n="tuto_f1_title">Crash-Proof Restore</span>
            <span class="tuto-feature-desc" data-i18n="tuto_f1_desc">Shut down without closing: your tabs and exact video timestamps return next launch.</span>
          </div>
          <div class="tuto-feature-box">
            <span class="tuto-feature-title" data-i18n="tuto_f2_title">Selective Cookies</span>
            <span class="tuto-feature-desc" data-i18n="tuto_f2_desc">Purges trackers, ad cookies, and malicious cookies while preserving signed-in accounts.</span>
          </div>
          <div class="tuto-feature-box">
            <span class="tuto-feature-title" data-i18n="tuto_f3_title">Adaptive Bar &amp; Groups</span>
            <span class="tuto-feature-desc" data-i18n="tuto_f3_desc">Right-click tabs for groups, middle-click to close, and press Ctrl+, for full-page Settings.</span>
          </div>
        </div>
      </div>

      <div class="tuto-footer">
        <button type="button" class="btn-subtle" id="btn-tuto-prev" style="visibility:hidden;" data-i18n="btn_back" onclick="tutorialPrevStep()">Back</button>
        <div style="font-size:11.5px;color:var(--text-muted);" id="tuto-step-label">Step 1 / 3</div>
        <div style="display:flex;gap:8px;">
          <button type="button" class="btn-gold" id="btn-tuto-next" disabled onclick="tutorialNextStep()">Continue &rarr;</button>
        </div>
      </div>
    </div>
  </div>

  <!-- FULL-PAGE SETTINGS TAB (`singularity://settings` — BRAVE/CHROME SIDEBAR LAYOUT) -->
  <div id="settings-modal">
    <div class="glass-sheet">
      <aside class="settings-sidebar">
        <div class="settings-brand-head">
          <img src="/api/logo.png" alt="Singularity" />
          <span class="settings-brand-title" data-i18n="settings_brand">Settings</span>
        </div>
        <nav class="sheet-tabs" aria-label="Settings sections" data-i18n-aria="settings_nav_aria">
          <button type="button" class="sheet-tab-btn active" id="stab-general" onclick="switchSheetTab('general')">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9c.26.6.85 1 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
            <span data-i18n="stab_general">General &amp; Startup</span>
          </button>
          <button type="button" class="sheet-tab-btn" id="stab-appearance" onclick="switchSheetTab('appearance')">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>
            <span data-i18n="stab_appearance">Appearance &amp; Themes</span>
          </button>
          <button type="button" class="sheet-tab-btn" id="stab-extensions" onclick="switchSheetTab('extensions')">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M19.439 7.85c-.049.322.059.648.289.878l1.568 1.568a2.4 2.4 0 0 1 0 3.408l-1.611 1.611a.98.98 0 0 1-.837.276c-.47-.07-.802-.48-.968-.925a2.5 2.5 0 1 0-3.214 3.214c.446.166.855.497.925.968a.98.98 0 0 1-.276.837l-1.61 1.61a2.4 2.4 0 0 1-3.409 0l-1.568-1.568a1.03 1.03 0 0 0-.877-.29c-.493.074-.84.504-1.02.968a2.5 2.5 0 1 1-3.237-3.237c.464-.18.894-.527.967-1.02a1.03 1.03 0 0 0-.289-.877L2.704 13.704a2.4 2.4 0 0 1 0-3.408L4.23 8.77c.24-.24.581-.353.917-.303.515.077.877.528 1.073 1.01a2.5 2.5 0 1 0 3.259-3.259c-.482-.196-.933-.558-1.01-1.073-.05-.336.062-.676.303-.917l1.525-1.525a2.4 2.4 0 0 1 3.408 0l1.568 1.568c.23.23.556.338.877.29.493-.074.84-.504 1.02-.968a2.5 2.5 0 1 1 3.237 3.237c-.464.18-.894.527-.967 1.02Z"/></svg>
            <span data-i18n="stab_extensions">Chrome Extensions</span>
          </button>
          <button type="button" class="sheet-tab-btn" id="stab-tokens" onclick="switchSheetTab('tokens')">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            <span data-i18n="stab_tokens">Accounts &amp; .singularity</span>
          </button>
          <button type="button" class="sheet-tab-btn" id="stab-bookmarks" onclick="switchSheetTab('bookmarks')">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>
            <span data-i18n="stab_bookmarks">Bookmarks &amp; History</span>
          </button>
          <button type="button" class="sheet-tab-btn" id="stab-vault" onclick="switchSheetTab('vault')">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="7.5" cy="15.5" r="4.5"/><path d="M10.7 12.3 19 4"/><path d="M16 7l3 3"/></svg>
            <span data-i18n="stab_vault">Vault &amp; 2FA</span>
          </button>
          <button type="button" class="sheet-tab-btn" id="stab-mullvad" onclick="switchSheetTab('mullvad')">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
            <span data-i18n="stab_mullvad">Shield &amp; WireGuard</span>
          </button>
          <button type="button" class="sheet-tab-btn" id="stab-settings" onclick="switchSheetTab('settings')">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><line x1="4" y1="21" x2="4" y2="14"/><line x1="4" y1="10" x2="4" y2="3"/><line x1="12" y1="21" x2="12" y2="12"/><line x1="12" y1="8" x2="12" y2="3"/><line x1="20" y1="21" x2="20" y2="16"/><line x1="20" y1="12" x2="20" y2="3"/></svg>
            <span id="stab-settings-label" data-i18n="stab_engine">Engine (2,165+ settings)</span>
          </button>
        </nav>
        <div class="settings-sidebar-footer">
          <div style="color:var(--text-secondary);font-weight:600;" data-i18n="about_singularity">About Singularity</div>
          <div id="sidebar-ver-label" style="font-family:var(--font-mono);color:var(--gold-bright);">v2.0.1</div>
        </div>
      </aside>

      <div class="settings-main-col">
        <div class="sheet-header">
          <div class="settings-page-heading" id="settings-page-heading">General &amp; Startup</div>
          <input id="settings-search" class="sheet-search" type="search"
                 placeholder="Search 2,165+ browser settings..."
                 data-i18n-placeholder="settings_search_ph"
                 oninput="onSettingsGlobalSearch(this.value)" />
        </div>

      <!-- TAB 1: GENERAL & STARTUP -->
      <div class="panel-grid" id="pane-general" style="display:flex;">
        <div class="info-card" style="flex-direction:row;align-items:center;justify-content:space-between;flex-wrap:wrap;">
          <div style="display:flex;align-items:center;gap:14px;">
            <img src="/api/logo.png" alt="Singularity" style="width:46px;height:46px;border-radius:11px;" />
            <div>
              <div style="font-size:15px;font-weight:600;">Singularity Browser <span id="gen-ver" style="color:var(--gold-bright);font-family:var(--font-mono);font-size:12px;"></span></div>
              <div style="font-size:11.5px;color:var(--text-secondary);"><span data-i18n="gen_active_profile">Active encrypted profile:</span> <span class="mono-val" id="gen-roaming-dir">—</span></div>
            </div>
          </div>
          <div style="display:flex;gap:8px;flex-wrap:wrap;">
            <button type="button" class="btn-subtle" data-i18n="btn_check_updates" onclick="checkUpdatesUI()">Check for updates</button>
            <button type="button" class="btn-gold" style="height:30px;padding:0 14px;" data-i18n="btn_update_now" onclick="triggerUpdate()">Update</button>
          </div>
        </div>
        <div id="update-check-banner" style="display:none;" class="info-card"></div>

        <div class="info-card">
          <div class="card-label" data-i18n="gen_startup_card">Language, Startup &amp; Browser Import</div>
          <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;">
            <span data-i18n="gen_lang_row">Display language</span>
            <select id="gen-language-select" class="engine-pill-select" style="height:30px;padding:0 10px;" onchange="selectLanguage(this.value)">
              <option value="en">English</option>
              <option value="fr">Français</option>
            </select>
          </div>
          <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;">
            <span data-i18n="gen_engine_row">Default search engine</span>
            <select id="gen-engine-select" class="engine-pill-select" style="height:30px;padding:0 10px;" onchange="saveDefaultEngine(this.value)">
              <option value="ddg">DuckDuckGo</option>
              <option value="google">Google</option>
              <option value="brave">Brave Search</option>
              <option value="qwant">Qwant</option>
              <option value="startpage">Startpage</option>
            </select>
          </div>
          <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;">
            <span data-i18n="gen_restore_row">Restore tabs &amp; exact video timestamps after restart or power loss</span>
            <button type="button" class="toggle-pill on" id="btn-restore-session" onclick="toggleRestoreSession()">ON</button>
          </div>
          <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;padding-top:6px;border-top:1px solid rgba(255,255,255,0.06);">
            <span data-i18n="gen_import_row">Import open tabs and bookmarks from another installed browser</span>
            <div style="display:flex;gap:8px;flex-wrap:wrap;">
              <button type="button" class="btn-subtle" data-i18n="btn_import_tabs" onclick="reopenTutorialAtStep(1)">Import tabs...</button>
              <button type="button" class="btn-subtle" data-i18n="btn_reopen_wizard" onclick="reopenTutorialAtStep(0)">Re-run setup wizard</button>
            </div>
          </div>
        </div>

        <div class="info-card">
          <div style="display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;">
            <span class="card-label" data-i18n="ram_card_title">RAM Manager &amp; Automatic Tab Unloading</span>
            <span style="font-size:11px;color:var(--text-secondary);font-family:var(--font-mono);" id="ram-status-badge">0 active · 0 unloaded</span>
          </div>
          <div style="font-size:11.5px;color:var(--text-secondary);" data-i18n="ram_card_desc">
            Every tab keeps its exact URL, video timestamp, and session. Inactive tabs are released from RAM after your chosen delay and reload right where you left off when clicked.
          </div>
          <div class="ram-mode-grid" id="ram-mode-grid">
            <button type="button" class="ram-mode-btn" data-ram-mode="low" onclick="selectRamMode('low')">
              <span class="ram-mode-title" data-i18n="ram_low_title">Low (2h)</span>
              <span class="ram-mode-desc" data-i18n="ram_low_desc">Keep more tabs in RAM (unload after 2h).</span>
            </button>
            <button type="button" class="ram-mode-btn selected" data-ram-mode="medium" onclick="selectRamMode('medium')">
              <span class="ram-mode-title" data-i18n="ram_med_title">Medium (15 min)</span>
              <span class="ram-mode-desc" data-i18n="ram_med_desc">Balanced: unload idle tabs after 15 min (max 6 background).</span>
            </button>
            <button type="button" class="ram-mode-btn" data-ram-mode="hard" onclick="selectRamMode('hard')">
              <span class="ram-mode-title" data-i18n="ram_hard_title">Hard (3 min)</span>
              <span class="ram-mode-desc" data-i18n="ram_hard_desc">Ultra-low RAM: unload idle tabs after 3 min (max 3 background).</span>
            </button>
            <button type="button" class="ram-mode-btn" data-ram-mode="custom" onclick="selectRamMode('custom')">
              <span class="ram-mode-title" data-i18n="ram_custom_title">Custom</span>
              <span class="ram-mode-desc" data-i18n="ram_custom_desc">Set your exact inactivity delay before unloading.</span>
            </button>
          </div>
          <div id="ram-custom-row" style="display:none;align-items:center;gap:8px;flex-wrap:wrap;margin-top:4px;padding-top:8px;border-top:1px solid rgba(255,255,255,0.06);">
            <span style="font-size:12px;color:var(--text-secondary);" data-i18n="ram_unload_after">Unload after:</span>
            <input id="ram-custom-val" class="text-field" style="width:90px;text-align:right;font-family:var(--font-mono);" type="number" min="1" max="43200" value="15" />
            <select id="ram-custom-unit" class="engine-pill-select" style="height:32px;">
              <option value="minutes" selected data-i18n="unit_minutes">minutes</option>
              <option value="hours" data-i18n="unit_hours">hours</option>
            </select>
            <button type="button" class="btn-gold" style="height:30px;padding:0 12px;" data-i18n="btn_apply" onclick="saveCustomRamDelay()">Apply</button>
            <span style="font-size:11px;color:var(--text-muted);" data-i18n="ram_presets">Presets:</span>
            <button type="button" class="btn-subtle" style="height:26px;padding:0 8px;" onclick="applyRamPresetMinutes(3)">3 min</button>
            <button type="button" class="btn-subtle" style="height:26px;padding:0 8px;" onclick="applyRamPresetMinutes(15)">15 min</button>
            <button type="button" class="btn-subtle" style="height:26px;padding:0 8px;" onclick="applyRamPresetMinutes(60)">1 h</button>
            <button type="button" class="btn-subtle" style="height:26px;padding:0 8px;" onclick="applyRamPresetMinutes(120)">2 h</button>
          </div>
          <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap;margin-top:4px;">
            <span style="font-size:11.5px;color:var(--text-muted);" id="ram-effective-label">Active mode: Medium (15 min)</span>
            <button type="button" class="btn-subtle" data-i18n="btn_unload_now" onclick="unloadInactiveTabsNow()">Unload inactive tabs now</button>
          </div>
        </div>

        <div class="info-card">
          <div class="card-label" data-i18n="shield_card_title">Anti-Tracking Shield &amp; Selective Cookies</div>
          <div style="font-size:12px;color:var(--text-secondary);">
            <span data-i18n="shield_blocked_lbl">Ad and tracker requests blocked this session:</span> <b style="color:var(--gold-bright);" id="gen-blocked-count">0</b>
          </div>
          <div style="font-size:11.5px;color:var(--text-muted);line-height:1.5;" data-i18n="shield_card_desc">
            Surgical cookie cleanup active: only trackers, ad cookies, and malicious cookies are purged automatically. Your auth tokens, Google/YouTube/Discord/GitHub sessions, and functional cookies are preserved.
          </div>
          <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:4px;">
            <button type="button" class="btn-subtle" data-i18n="btn_purge_trackers" onclick="clearBrowsingDataUI(false)">Purge trackers, ad &amp; malicious cookies (keep sessions)</button>
            <button type="button" class="btn-subtle btn-danger" data-i18n="btn_full_reset" onclick="clearBrowsingDataUI(true)">Full reset (sign out all accounts)</button>
          </div>
        </div>
      </div>

      <!-- TAB 2: APPEARANCE & 3D COSMIC THEMES -->
      <div class="panel-grid" id="pane-appearance">
        <div class="info-card">
          <div style="display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;">
            <div>
              <div class="card-label" data-i18n="app_themes_title">Cosmic Themes &amp; WebGL2 3D Backdrop</div>
              <div style="font-size:12px;color:var(--text-secondary);margin-top:3px;" data-i18n="app_themes_desc">
                Each theme transforms the entire browser palette and live 3D New Tab scene (Black Hole, Solar Corona, Blood Eclipse, Cyan Pulsar, Amethyst Nebula, Emerald Aurora).
              </div>
            </div>
            <button type="button" class="btn-subtle" data-i18n="btn_preview_ntp" onclick="createNewTab()">Preview on New Tab</button>
          </div>
          <div class="theme-gallery-grid" id="settings-theme-grid" style="margin-top:4px;"></div>
        </div>

        <div class="info-card">
          <div class="card-label" data-i18n="app_bar_title">Adaptive Address Bar &amp; Tabs</div>
          <div style="font-size:12px;color:var(--text-secondary);line-height:1.5;" data-i18n="app_bar_desc">
            With a few tabs open, the address bar stays centered. Once you open 4 or more tabs, it smoothly glides to the right to maximize visible tab space.
          </div>
        </div>
      </div>

      <!-- TAB 3: CHROME EXTENSIONS (MANIFEST V3 / CRX / WEB STORE / LOCAL IMPORT) -->
      <div class="panel-grid" id="pane-extensions">
        <div class="info-card">
          <div class="card-label" data-i18n="ext_install_title">Install a Chrome Extension (Chrome Web Store)</div>
          <div style="font-size:12px;color:var(--text-secondary);">
            <span data-i18n="ext_install_desc">Paste a Chrome Web Store URL or 32-letter extension ID: Singularity downloads the official .crx package, verifies it, and loads it natively in Pure Chromium</span> (<span class="mono-val" id="ext-dir-path">—</span>).
          </div>
          <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:2px;">
            <input id="ext-store-input" class="text-field" style="flex:1;min-width:260px;" type="text"
                   placeholder="Chrome Web Store URL or 32-letter ID (e.g. ddkjiahejlhfcafbddmgiahcphecmpfh)"
                   data-i18n-placeholder="ext_store_ph"
                   onkeydown="if(event.key==='Enter') installExtensionFromStoreUI()" />
            <button type="button" class="btn-gold" style="height:32px;padding:0 16px;" id="btn-ext-install-store" data-i18n="btn_install" onclick="installExtensionFromStoreUI()">Install</button>
          </div>
          <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:4px;">
            <input id="ext-local-input" class="text-field" style="flex:1;min-width:260px;" type="text"
                   placeholder="Or local path to an unpacked folder (manifest.json) / .crx / .zip file"
                   data-i18n-placeholder="ext_local_ph"
                   onkeydown="if(event.key==='Enter') installExtensionFromLocalUI()" />
            <button type="button" class="btn-subtle" style="height:32px;" data-i18n="btn_load_local" onclick="installExtensionFromLocalUI()">Load local</button>
          </div>
        </div>

        <div class="info-card">
          <div class="card-label" data-i18n="ext_installed_title">Installed &amp; Pinned Extensions</div>
          <div id="ext-installed-list" style="display:flex;flex-direction:column;gap:7px;"></div>
        </div>

        <div class="info-card">
          <div class="card-label" data-i18n="ext_catalog_title">Quick Install — Popular Chrome Extensions</div>
          <div id="ext-catalog-list" style="display:flex;flex-direction:column;gap:6px;"></div>
        </div>

        <div class="info-card" id="ext-detected-card" style="display:none;">
          <div class="card-label" data-i18n="ext_detected_title">1-Click Import from Chrome / Brave / Edge</div>
          <div id="ext-detected-list" style="display:flex;flex-direction:column;gap:6px;"></div>
        </div>
      </div>

      <!-- TAB 4: ENCRYPTED ACCOUNTS & TOKENS (.SINGULARITY) -->
      <div class="panel-grid" id="pane-tokens">
        <div class="info-card">
          <div class="card-label" data-i18n="tok_vault_title">Encrypted Session Store (.singularity)</div>
          <div style="font-size:12px;color:var(--text-secondary);" data-i18n="tok_vault_desc">
            Your sign-in session tokens (Google, Microsoft, GitHub, Discord, Twitch, etc.) are automatically encrypted at rest inside:
          </div>
          <div class="mono-val" id="tok-file-path">—</div>
          <div style="font-size:11px;color:var(--text-muted);" id="tok-cipher-label"></div>
          <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:4px;">
            <button type="button" class="btn-subtle" onclick="connectProviderLogin('https://accounts.google.com', 'Google Sign-In')">Google</button>
            <button type="button" class="btn-subtle" onclick="connectProviderLogin('https://login.live.com', 'Microsoft Sign-In')">Microsoft</button>
            <button type="button" class="btn-subtle" onclick="connectProviderLogin('https://github.com/login', 'GitHub Sign-In')">GitHub</button>
            <button type="button" class="btn-subtle" onclick="connectProviderLogin('https://discord.com/login', 'Discord Sign-In')">Discord</button>
            <button type="button" class="btn-gold" style="height:30px;padding:0 12px;" data-i18n="btn_sync_now" onclick="forceSyncTokens()">Sync now</button>
          </div>
        </div>

        <div class="info-card">
          <div class="card-label" data-i18n="tok_saved_title">Saved Encrypted Tokens &amp; Sessions</div>
          <div id="tok-list" style="display:flex;flex-direction:column;gap:6px;"></div>
        </div>

        <div class="info-card">
          <div class="card-label" data-i18n="tok_manual_title">Add an OAuth Token / Key Manually</div>
          <div style="display:flex;gap:8px;flex-wrap:wrap;">
            <select id="manual-tok-provider" class="engine-pill-select" style="height:32px;">
              <option value="Google">Google</option>
              <option value="Microsoft">Microsoft</option>
              <option value="GitHub">GitHub</option>
              <option value="Discord">Discord</option>
              <option value="OAuth">Other OAuth / API</option>
            </select>
            <input id="manual-tok-domain" class="text-field" style="width:170px;" type="text" placeholder="Domain (e.g. google.com)" data-i18n-placeholder="tok_dom_ph" />
            <input id="manual-tok-name" class="text-field" style="width:150px;" type="text" placeholder="Name (e.g. oauth_token)" data-i18n-placeholder="tok_name_ph" />
            <input id="manual-tok-secret" class="text-field" style="flex:1;min-width:180px;" type="password" placeholder="Token value to encrypt..." data-i18n-placeholder="tok_sec_ph" />
            <button type="button" class="btn-subtle" data-i18n="btn_encrypt_save" onclick="addManualEncryptedToken()">Encrypt &amp; Save</button>
          </div>
        </div>
      </div>

      <!-- TAB 5: BOOKMARKS & HISTORY -->
      <div class="panel-grid" id="pane-bookmarks">
        <div class="info-card">
          <div class="card-label" data-i18n="bm_add_title">Add Quick Bookmark</div>
          <div style="display:flex;gap:8px;flex-wrap:wrap;">
            <input id="bm-new-title" class="text-field" style="width:190px;" type="text" placeholder="Title (e.g. ProtonMail)" data-i18n-placeholder="bm_title_ph" />
            <input id="bm-new-url" class="text-field" style="flex:1;min-width:220px;" type="text" placeholder="URL (e.g. https://mail.proton.me)" data-i18n-placeholder="bm_url_ph" />
            <button type="button" class="btn-subtle" data-i18n="btn_add" onclick="addBookmarkFromSheet()">Add</button>
          </div>
          <div id="bm-sheet-list" style="display:flex;flex-direction:column;gap:6px;margin-top:6px;"></div>
        </div>

        <div class="info-card">
          <div style="display:flex;align-items:center;justify-content:space-between;">
            <span class="card-label" data-i18n="hist_title">Recent Browsing History</span>
            <button type="button" class="btn-subtle btn-danger" style="height:26px;" data-i18n="btn_clear_hist" onclick="clearHistoryOnly()">Clear history</button>
          </div>
          <div id="hist-sheet-list" style="display:flex;flex-direction:column;gap:5px;max-height:240px;overflow-y:auto;"></div>
        </div>
      </div>

      <!-- TAB 6: ARGON2ID + XCHACHA20-POLY1305 VAULT -->
      <div class="panel-grid" id="pane-vault">
        <div class="info-card" id="vault-auth-card">
          <div class="card-label" id="vault-status-label" data-i18n="vault_title">Zero-Knowledge Vault (Argon2id + XChaCha20-Poly1305)</div>
          <div style="font-size:12px;color:var(--text-secondary);" id="vault-status-desc"></div>
          <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
            <input id="vault-master-input" class="text-field" style="flex:1;min-width:220px;" type="password"
                   placeholder="Vault master password..."
                   data-i18n-placeholder="vault_master_ph"
                   onkeydown="if(event.key==='Enter') unlockOrCreateVault()" />
            <button type="button" class="btn-gold" style="height:32px;" id="btn-vault-unlock" onclick="unlockOrCreateVault()">Unlock</button>
            <button type="button" class="btn-subtle" id="btn-vault-lock" style="display:none;" data-i18n="btn_lock" onclick="lockVaultUI()">Lock</button>
          </div>
        </div>

        <div class="info-card" id="vault-unlocked-area" style="display:none;">
          <div class="card-label" data-i18n="vault_save_title">Save Credential &amp; 2FA TOTP Key</div>
          <div style="display:flex;gap:8px;flex-wrap:wrap;">
            <input id="v-origin" class="text-field" style="width:180px;" type="text" placeholder="Site (e.g. https://github.com)" data-i18n-placeholder="v_origin_ph" />
            <input id="v-user" class="text-field" style="width:170px;" type="text" placeholder="Username / Email" data-i18n-placeholder="v_user_ph" />
            <input id="v-pass" class="text-field" style="flex:1;min-width:160px;" type="password" placeholder="Password" data-i18n-placeholder="v_pass_ph" />
            <button type="button" class="btn-subtle" data-i18n="btn_generate" onclick="generateStrongPassword()">Generate</button>
            <input id="v-totp" class="text-field" style="width:170px;" type="text" placeholder="Base32 2FA Secret (optional)" data-i18n-placeholder="v_totp_ph" />
            <button type="button" class="btn-gold" style="height:32px;padding:0 14px;" data-i18n="btn_save" onclick="addVaultEntryUI()">Save</button>
          </div>
          <div id="vault-entries" style="display:flex;flex-direction:column;gap:6px;margin-top:8px;"></div>
        </div>

        <div class="info-card">
          <div class="card-label" data-i18n="vault_audit_title">Offline Entropy Audit &amp; Breach Filter</div>
          <div style="display:flex;gap:8px;align-items:center;">
            <input id="vault-audit-input" class="text-field" style="flex:1;" type="password" placeholder="Check password strength offline..." data-i18n-placeholder="vault_audit_ph" />
            <button type="button" class="btn-subtle" data-i18n="btn_analyze" onclick="runVaultAudit()">Analyze</button>
          </div>
          <div id="vault-audit-result" style="font-size:11.5px;color:var(--text-secondary);"></div>
        </div>
      </div>

      <!-- TAB 7: MULLVAD WIREGUARD + DAITA (LOCAL CRYPTO SIMULATION / KILL-SWITCH) -->
      <div class="panel-grid" id="pane-mullvad">
        <div class="info-card">
          <div class="card-label" data-i18n="mv_title">Mullvad WireGuard + DAITA Engine (Local Cryptographic Simulation)</div>
          <div style="font-size:12px;color:var(--text-secondary);" id="mv-honest-notice" data-i18n="mv_notice">
            Singularity protects your browsing with its anti-tracking shield and application kill-switch. Note: the embedded WireGuard module currently operates as a local cryptographic simulation (no OS-level TUN interface redirects WebView traffic yet). For full system-wide VPN routing, use the official Mullvad VPN client.
          </div>
          <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;">
            <input id="mv-account-input" class="text-field" style="width:220px;font-family:var(--font-mono);" type="text" placeholder="1234 5678 9012 3456" />
            <button type="button" class="btn-gold" style="height:32px;" data-i18n="mv_btn_connect" onclick="connectMullvadUI()">Start WireGuard Session</button>
            <button type="button" class="btn-subtle" data-i18n="mv_btn_disconnect" onclick="disconnectMullvadUI()">Disconnect</button>
            <button type="button" class="btn-subtle btn-danger" data-i18n="mv_btn_forget" onclick="logoutMullvadUI()">Forget account</button>
          </div>
        </div>

        <div class="info-card">
          <div class="card-label" data-i18n="mv_route_title">Route Status &amp; Multi-Hop Relays</div>
          <div class="mono-val" id="mv-route">Direct (Singularity Shield)</div>
          <div style="font-size:11.5px;color:var(--text-secondary);" id="mv-endpoints"></div>
          <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:4px;">
            <span style="font-size:11.5px;color:var(--text-muted);" data-i18n="mv_entry">Entry:</span>
            <select id="mv-entry-sel" class="engine-pill-select" style="height:30px;"></select>
            <span style="font-size:11.5px;color:var(--text-muted);" data-i18n="mv_exit">Exit:</span>
            <select id="mv-exit-sel" class="engine-pill-select" style="height:30px;"></select>
            <button type="button" class="btn-subtle" data-i18n="mv_apply_route" onclick="applyMullvadRelays()">Apply route</button>
          </div>
        </div>

        <div class="info-card">
          <div class="card-label" data-i18n="mv_sec_title">Socket Security &amp; Packet Inspection</div>
          <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;">
            <button type="button" class="toggle-pill" id="btn-strict-ks" onclick="toggleStrictKillSwitchUI()">Strict Kill-Switch: OFF</button>
            <button type="button" class="btn-subtle" data-i18n="mv_emergency" onclick="toggleKillSwitch()">Emergency Lockdown</button>
            <button type="button" class="btn-subtle" data-i18n="mv_inspect" onclick="testWireGuardPacket()">Inspect DAITA Frame (1360B)</button>
          </div>
          <pre class="info-card" id="mv-packet-out" style="display:none;font-family:var(--font-mono);font-size:11px;color:var(--text-secondary);white-space:pre-wrap;"></pre>
        </div>
      </div>

      <!-- TAB 8: ENGINE SETTINGS REGISTRY (VIRTUALIZED SCROLLING) -->
      <div class="sheet-body" id="pane-settings">
        <div class="cats-sidebar">
          <div id="modal-cats-list" style="display:flex;flex-direction:column;gap:2px;"></div>
          <div style="margin-top:auto;padding-top:12px;display:flex;flex-direction:column;gap:6px;">
            <button type="button" class="btn-subtle" style="width:100%;justify-content:center;" data-i18n="btn_export_toml" onclick="exportSettingsToml()">Export settings.toml</button>
            <button type="button" class="btn-subtle btn-danger" id="btn-reset-all-settings" style="width:100%;justify-content:center;" data-i18n="btn_reset_all" onclick="resetAllSettingsUI()">Reset all</button>
          </div>
        </div>
        <div class="rows-pane" id="modal-rows-list"></div>
      </div>
      </div>
    </div>
  </div>

  <div id="group-editor-bar" role="dialog" aria-label="Edit tab group" data-i18n-aria="grp_edit_aria">
    <input id="group-editor-name" class="grp-ed-input" type="text" maxlength="40" placeholder="Group name..." data-i18n-placeholder="grp_name_ph" />
    <div id="group-editor-colors" class="grp-ed-colors"></div>
    <button type="button" class="grp-ed-btn primary" onclick="closeGroupEditor()">OK</button>
    <button type="button" class="grp-ed-btn" data-i18n="btn_ungroup" onclick="ungroupEditingGroup()">Ungroup</button>
  </div>

  <div id="tab-context-menu" role="menu"></div>

  <div id="toast"></div>

<script>
  /* ============================================================================
   * AUTHENTICATED LOOPBACK IPC CLIENT (PER-SESSION 256-BIT TOKEN + POST JSON)
   * ============================================================================ */
  const SINGULARITY_IPC_TOKEN = "__SINGULARITY_IPC_TOKEN__";
  const WINDOW_SESSION_ID = (() => {
    try {
      return new URLSearchParams(window.location.search || "").get("win") || "";
    } catch (_) {
      return "";
    }
  })();
  try {
    const qs = String((window.location && window.location.search) || "");
    if (qs.includes("boot=") || qs.includes("win=")) {
      window.history.replaceState(null, "", "/");
    }
  } catch (_) {}

  function apiFetch(url, opts) {
    const o = Object.assign({}, opts || {});
    const headers = Object.assign({}, o.headers || {}, {
      "X-Singularity-Token": SINGULARITY_IPC_TOKEN
    });
    if (WINDOW_SESSION_ID) {
      headers["X-Singularity-Window"] = WINDOW_SESSION_ID;
    }
    o.headers = headers;
    return fetch(url, o);
  }

  function apiPost(url, payload) {
    return apiFetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload || {})
    });
  }

  /* ============================================================================
   * NATIVE IPC BRIDGE (TAO + PURE CHROMIUM CEF SINGLE-PROCESS SHELL)
   * ============================================================================ */
  function hasNativeIpc() {
    return !!(window.ipc && typeof window.ipc.postMessage === "function");
  }

  function sendNativeIpc(payload) {
    if (hasNativeIpc()) {
      window.ipc.postMessage(JSON.stringify(payload));
      return true;
    }
    return false;
  }

  function showToast(msg, onClick, durationMs) {
    const el = document.getElementById("toast");
    el.textContent = msg;
    if (typeof onClick === "function") {
      el.classList.add("clickable");
      el.onclick = () => {
        el.classList.remove("show", "clickable");
        el.onclick = null;
        try { onClick(); } catch (_) {}
      };
    } else {
      el.classList.remove("clickable");
      el.onclick = null;
    }
    el.classList.add("show");
    clearTimeout(window.__toastTimer);
    window.__toastTimer = setTimeout(() => {
      el.classList.remove("show", "clickable");
      el.onclick = null;
    }, typeof durationMs === "number" && durationMs > 0 ? durationMs : 2600);
  }

  /* ============================================================================
   * LIVE INTERNATIONALIZATION ENGINE (DEFAULT: ENGLISH, LIVE SWITCH: EN / FR)
   * ============================================================================ */
  let currentLang = "en";

  function L(enText, frText) {
    return currentLang === "fr" ? frText : enText;
  }

  const I18N_FR = {
    win_controls: "Contrôles de fenêtre",
    win_close: "Fermer",
    win_min: "Réduire",
    win_max: "Agrandir",
    nav_home: "Accueil Singularity",
    nav_back: "Précédent",
    nav_forward: "Suivant",
    tabs_scroll_left: "Faire défiler les onglets vers la gauche",
    tabs_scroll_right: "Faire défiler les onglets vers la droite",
    nav_new_tab: "Nouvel onglet (Ctrl+T)",
    omnibar_placeholder: "Rechercher ou saisir une adresse",
    nav_bookmark: "Ajouter aux favoris (Ctrl+D)",
    nav_reload: "Actualiser (Ctrl+R)",
    nav_extensions: "Extensions Chrome (Web Store & locales)",
    nav_private: "Navigation Privée (éphémère)",
    nav_tokens: "Sessions & Tokens chiffrés (.singularity)",
    nav_shield: "Bouclier Réseau & WireGuard",
    nav_vault: "Coffre-fort Argon2id & 2FA",
    nav_settings: "Centre de contrôle & Paramètres (Ctrl+,)",
    ntp_placeholder: "Rechercher sur le Web ou saisir une URL...",
    search_engine_aria: "Moteur de recherche",
    tuto_skip: "Passer la suite",
    tuto0_title: "Bienvenue sur Singularity",
    tuto0_sub: "Choisissez votre langue d'affichage et votre thème couleur pour commencer. Ces deux choix sont obligatoires avant de continuer.",
    tuto0_lang_label: "1. Langue d'affichage",
    tuto0_theme_label: "2. Thème couleur & Arrière-plan 3D",
    tuto_required: "Obligatoire",
    tuto0_hint: "Sélectionnez une langue et un thème couleur pour déverrouiller Continuer.",
    tuto1_title: "Importer vos onglets ouverts & favoris ?",
    tuto1_sub: "Navigateurs détectés sur ce PC (lecture locale seule, aucun fichier modifié). Les onglets importés démarrent en veille RAM sans lancer les vidéos.",
    btn_refresh: "Actualiser",
    tuto1_scanning: "Analyse des navigateurs installés sur ce PC...",
    tuto1_also_bookmarks: "Importer aussi les favoris des navigateurs sélectionnés",
    tuto1_import_btn: "Importer les onglets sélectionnés",
    tuto2_title: "Moteur de recherche & Économie de RAM",
    tuto2_sub: "Personnalisez votre moteur par défaut et la mise en veille automatique des onglets inactifs.",
    tuto2_engine_label: "Moteur de recherche par défaut",
    tuto2_ram_label: "Déchargement RAM des onglets inactifs",
    ram_low_short: "Décharge après 2h",
    ram_med_short: "Décharge après 15 min",
    ram_hard_short: "Décharge après 3 min",
    ram_custom_title: "Personnalisé",
    ram_custom_short: "Configurable dans Paramètres",
    tuto_f1_title: "Restauration anti-coupure",
    tuto_f1_desc: "Éteignez votre PC sans fermer : vos onglets et la seconde exacte de vos vidéos reviennent au lancement suivant.",
    tuto_f2_title: "Cookies sélectifs",
    tuto_f2_desc: "Supprime traqueurs, cookies publicitaires et malveillants tout en gardant vos comptes connectés.",
    tuto_f3_title: "Barre adaptative & Groupes",
    tuto_f3_desc: "Clic droit sur les onglets pour les grouper, clic molette pour fermer, Ctrl+, pour les Paramètres.",
    btn_back: "Précédent",
    settings_brand: "Paramètres",
    settings_nav_aria: "Sections des paramètres",
    stab_general: "Général & Démarrage",
    stab_appearance: "Apparence & Thèmes",
    stab_extensions: "Extensions Chrome",
    stab_tokens: "Comptes & .singularity",
    stab_bookmarks: "Favoris & Historique",
    stab_vault: "Coffre-fort & 2FA",
    stab_mullvad: "Bouclier & WireGuard",
    stab_engine: "Moteur (2 165+ réglages)",
    about_singularity: "À propos de Singularity",
    settings_search_ph: "Rechercher dans les 2 165+ paramètres...",
    gen_active_profile: "Profil chiffré actif :",
    btn_check_updates: "Vérifier les mises à jour",
    btn_update_now: "Mettre à jour",
    gen_startup_card: "Langue, Démarrage & Import Navigateur",
    gen_lang_row: "Langue d'affichage",
    gen_engine_row: "Moteur de recherche par défaut",
    gen_restore_row: "Restaurer les onglets et le moment exact des vidéos après redémarrage ou coupure PC",
    gen_import_row: "Importer vos onglets ouverts et favoris depuis un autre navigateur installé",
    btn_import_tabs: "Importer des onglets...",
    btn_reopen_wizard: "Relancer l'assistant",
    ram_card_title: "Gestionnaire de RAM & Déchargement automatique des onglets",
    ram_card_desc: "Chaque onglet conserve son URL exacte, le moment de la vidéo et sa session. Les onglets inactifs sont libérés de la RAM après le délai choisi et reprennent exactement où vous étiez.",
    ram_low_title: "Low (2h)",
    ram_low_desc: "Garde plus d'onglets en RAM (décharge après 2h).",
    ram_med_title: "Medium (15 min)",
    ram_med_desc: "Équilibré : décharge après 15 min (max 6 onglets en arrière-plan).",
    ram_hard_title: "Hard (3 min)",
    ram_hard_desc: "Ultra-basse RAM : décharge après 3 min (max 3 onglets en arrière-plan).",
    ram_custom_desc: "Choisissez exactement le délai d'inactivité avant déchargement.",
    ram_unload_after: "Décharger après :",
    unit_minutes: "minutes",
    unit_hours: "heures",
    btn_apply: "Appliquer",
    ram_presets: "Raccourcis :",
    btn_unload_now: "Décharger les onglets inactifs maintenant",
    shield_card_title: "Bouclier Anti-Pistage & Cookies Sélectifs",
    shield_blocked_lbl: "Requêtes publicitaires et traqueurs bloqués cette session :",
    shield_card_desc: "Nettoyage chirurgical actif : seuls les traqueurs, cookies publicitaires et cookies malveillants sont supprimés automatiquement. Vos tokens et sessions Google/YouTube/Discord/GitHub restent intacts.",
    btn_purge_trackers: "Nettoyer trackers, pubs & cookies malveillants (garder mes sessions)",
    btn_full_reset: "Réinitialisation complète (déconnecter tous les comptes)",
    app_themes_title: "Thèmes Cosmiques & Arrière-Plan WebGL2 3D",
    app_themes_desc: "Chaque thème transforme instantanément la palette du navigateur et l'astre 3D du Nouvel onglet (Trou Noir, Soleil ardent, Éclipse sanguine, Pulsar Cyan, Nébuleuse Violette, Aurore Émeraude).",
    btn_preview_ntp: "Voir sur Nouvel onglet",
    app_bar_title: "Barre d'adresse adaptative & Onglets",
    app_bar_desc: "Avec peu d'onglets, la barre d'URL reste centrée. Dès 4 onglets ouverts, elle glisse avec une animation fluide vers la droite pour afficher un maximum d'onglets.",
    ext_install_title: "Installer une Extension Chrome (Chrome Web Store)",
    ext_install_desc: "Collez une URL du Chrome Web Store ou un ID à 32 lettres : Singularity télécharge le paquet .crx officiel, le vérifie et le charge nativement dans Chromium pur",
    ext_store_ph: "URL Chrome Web Store ou ID à 32 lettres (ex: ddkjiahejlhfcafbddmgiahcphecmpfh)",
    btn_install: "Installer",
    ext_local_ph: "Ou chemin local d'un dossier décompressé (manifest.json) / .crx / .zip",
    btn_load_local: "Charger en local",
    ext_installed_title: "Extensions Installées & Épinglées dans la Barre",
    ext_catalog_title: "Installation Rapide — Extensions Chrome Populaires",
    ext_detected_title: "Importer en 1 Clic depuis Chrome / Brave / Edge",
    tok_vault_title: "Coffre de Sessions Chiffré (.singularity)",
    tok_vault_desc: "Vos tokens de connexion (Google, Microsoft, GitHub, Discord, Twitch, etc.) sont automatiquement sauvegardés chiffrés dans :",
    btn_sync_now: "Synchroniser maintenant",
    tok_saved_title: "Tokens & Sessions Chiffrés Enregistrés",
    tok_manual_title: "Ajouter un Token OAuth / Clé Manuellement",
    tok_dom_ph: "Domaine (ex: google.com)",
    tok_name_ph: "Nom (ex: oauth_token)",
    tok_sec_ph: "Valeur du token à chiffrer...",
    btn_encrypt_save: "Chiffrer & Sauvegarder",
    bm_add_title: "Ajouter un Favori Rapide",
    bm_title_ph: "Nom (ex: ProtonMail)",
    bm_url_ph: "URL (ex: https://mail.proton.me)",
    btn_add: "Ajouter",
    hist_title: "Historique de Navigation Récent",
    btn_clear_hist: "Effacer l'historique",
    vault_title: "Coffre-fort Zero-Knowledge (Argon2id + XChaCha20-Poly1305)",
    vault_master_ph: "Mot de passe maître du coffre-fort...",
    btn_lock: "Verrouiller",
    vault_save_title: "Enregistrer un Identifiant & Clé 2FA TOTP",
    v_origin_ph: "Site (ex: https://github.com)",
    v_user_ph: "Identifiant / E-mail",
    v_pass_ph: "Mot de passe",
    btn_generate: "Générer",
    v_totp_ph: "Clé 2FA Base32 (optionnel)",
    btn_save: "Sauvegarder",
    vault_audit_title: "Audit d'entropie & filtre de fuites hors-ligne",
    vault_audit_ph: "Vérifier la robustesse d'un mot de passe hors-ligne...",
    btn_analyze: "Analyser",
    mv_title: "Moteur Mullvad WireGuard + DAITA (Simulation Cryptographique Locale)",
    mv_notice: "Singularity protège votre navigation via son bouclier anti-traqueurs et son kill-switch applicatif. Note : le moteur WireGuard embarqué fonctionne actuellement en simulation cryptographique locale (aucune interface TUN système ne redirige le trafic WebView). Pour un routage VPN système complet, utilisez l'application officielle Mullvad VPN.",
    mv_btn_connect: "Activer la session WireGuard",
    mv_btn_disconnect: "Déconnecter",
    mv_btn_forget: "Oublier le compte",
    mv_route_title: "État de la Route & Relais Multi-Hop",
    mv_entry: "Entrée :",
    mv_exit: "Sortie :",
    mv_apply_route: "Appliquer la route",
    mv_sec_title: "Sécurité Socket & Inspection",
    mv_emergency: "Verrouillage d'urgence",
    mv_inspect: "Inspecter trame DAITA (1360B)",
    btn_export_toml: "Exporter settings.toml",
    btn_reset_all: "Réinitialiser tout",
    grp_edit_aria: "Modifier le groupe d'onglets",
    grp_name_ph: "Nom du groupe...",
    btn_ungroup: "Dissocier"
  };

  const I18N_EN_CACHE = {};
  function captureEnglishDefaults() {
    document.querySelectorAll("[data-i18n]").forEach(el => {
      const k = el.getAttribute("data-i18n");
      if (k && !(k in I18N_EN_CACHE)) I18N_EN_CACHE[k] = el.textContent;
    });
    document.querySelectorAll("[data-i18n-placeholder]").forEach(el => {
      const k = el.getAttribute("data-i18n-placeholder");
      if (k && !(k in I18N_EN_CACHE)) I18N_EN_CACHE[k] = el.getAttribute("placeholder") || "";
    });
    document.querySelectorAll("[data-i18n-title]").forEach(el => {
      const k = el.getAttribute("data-i18n-title");
      if (k && !(k in I18N_EN_CACHE)) I18N_EN_CACHE[k] = el.getAttribute("title") || "";
    });
    document.querySelectorAll("[data-i18n-aria]").forEach(el => {
      const k = el.getAttribute("data-i18n-aria");
      if (k && !(k in I18N_EN_CACHE)) I18N_EN_CACHE[k] = el.getAttribute("aria-label") || "";
    });
  }

  function applyLanguage(lang) {
    captureEnglishDefaults();
    currentLang = (lang === "fr") ? "fr" : "en";
    document.documentElement.lang = currentLang;

    const dict = currentLang === "fr" ? I18N_FR : I18N_EN_CACHE;
    document.querySelectorAll("[data-i18n]").forEach(el => {
      const k = el.getAttribute("data-i18n");
      if (k && k in dict) el.textContent = dict[k];
    });
    document.querySelectorAll("[data-i18n-placeholder]").forEach(el => {
      const k = el.getAttribute("data-i18n-placeholder");
      if (k && k in dict) el.setAttribute("placeholder", dict[k]);
    });
    document.querySelectorAll("[data-i18n-title]").forEach(el => {
      const k = el.getAttribute("data-i18n-title");
      if (k && k in dict) el.setAttribute("title", dict[k]);
    });
    document.querySelectorAll("[data-i18n-aria]").forEach(el => {
      const k = el.getAttribute("data-i18n-aria");
      if (k && k in dict) el.setAttribute("aria-label", dict[k]);
    });

    const langSel = document.getElementById("gen-language-select");
    if (langSel) langSel.value = currentLang;

    // Retranslate blank default tabs & settings tabs smoothly
    for (const t of tabs) {
      if (!t.url && (t.title === "New Tab" || t.title === "Nouvel onglet")) {
        t.title = L("New Tab", "Nouvel onglet");
      } else if (isInternalSettingsUrl(t.url)) {
        t.title = tabTitleForSection(sectionFromInternalUrl(t.url));
      }
    }

    const headingEl = document.getElementById("settings-page-heading");
    if (headingEl && typeof getSettingsSectionHeading === "function") {
      headingEl.textContent = getSettingsSectionHeading(currentSettingsSection);
    }

    applyMaximizedState(isWindowMaximized);
    if (typeof renderThemeGalleries === "function") renderThemeGalleries();
    if (typeof syncRamModeUI === "function") syncRamModeUI();
    if (typeof renderBookmarksStrip === "function") renderBookmarksStrip();
    if (typeof renderTabs === "function") renderTabs(false);
    if (typeof renderTutorialStep === "function" && anyModalOpen()) {
      renderTutorialStep();
      renderTutorialBrowsersList();
    }
    if (typeof refreshHeaderState === "function" && bootInitialized) {
      refreshHeaderState();
    }
  }

  async function selectLanguage(lang) {
    const clean = (lang === "fr") ? "fr" : "en";
    applyLanguage(clean);
    await apiPost("/api/profile/update_prefs", { language: clean }).catch(() => {});
    showToast(clean === "fr" ? "Langue définie : Français" : "Language set to English");
  }

  let isWindowMaximized = false;

  function applyMaximizedState(maximized) {
    isWindowMaximized = !!maximized;
    document.body.classList.toggle("is-maximized", isWindowMaximized);
    const maxBtn = document.querySelector(".tl-max");
    if (maxBtn) {
      maxBtn.title = isWindowMaximized ? L("Restore", "Restaurer") : L("Maximize", "Agrandir");
      maxBtn.setAttribute("aria-pressed", String(isWindowMaximized));
    }
  }

  document.addEventListener("fullscreenchange", () => {
    if (!hasNativeIpc()) {
      applyMaximizedState(!!document.fullscreenElement);
    }
  });

  function winAction(action) {
    if (!sendNativeIpc({ cmd: action })) {
      if (action === "close") window.close();
      else if (action === "toggle_maximize") {
        if (!document.fullscreenElement) document.documentElement.requestFullscreen().catch(() => {});
        else document.exitFullscreen().catch(() => {});
      }
    }
  }

  function startResize(direction, e) {
    if (e.button !== 0 || isWindowMaximized) return;
    if (sendNativeIpc({ cmd: "drag_resize", direction })) {
      e.preventDefault();
    }
  }

  // Fallback titlebar double-click & drag handler (native WebView2 uses CSS `app-region: drag`
  // directly for Win11 Snap Bar, Aero Snap, drag-from-maximized, and double-click maximize).
  const appleBar = document.getElementById("apple-titlebar");
  const TITLEBAR_INTERACTIVE_SELECTOR =
    "button, input, select, a, .tab-pill, .tab-group-pill, #group-editor-bar, #tab-context-menu, .traffic-lights, .safari-nav-group, .safari-omnibar, .toolbar-right";
  let lastTitlebarClick = { time: 0, x: 0, y: 0 };
  let lastTitlebarToggleAt = 0;

  function triggerTitlebarMaximize() {
    const now = performance.now();
    if (now - lastTitlebarToggleAt < 350) return;
    lastTitlebarToggleAt = now;
    winAction("toggle_maximize");
  }

  appleBar.addEventListener("mousedown", (e) => {
    if (e.button !== 0) return;
    if (e.target.closest(TITLEBAR_INTERACTIVE_SELECTOR)) return;

    const now = performance.now();
    const isDoubleClick =
      e.detail >= 2 ||
      (now - lastTitlebarClick.time <= 400 &&
        Math.hypot(e.screenX - lastTitlebarClick.x, e.screenY - lastTitlebarClick.y) <= 8);

    if (isDoubleClick) {
      lastTitlebarClick = { time: 0, x: 0, y: 0 };
      e.preventDefault();
      triggerTitlebarMaximize();
      return;
    }

    lastTitlebarClick = { time: now, x: e.screenX, y: e.screenY };

    // Only invoke fallback drag_window once pointer actually moves >= 5px, never on click #1
    // so double-click is never swallowed.
    const startX = e.screenX;
    const startY = e.screenY;
    const onMove = (mv) => {
      if ((mv.buttons & 1) === 0) {
        cleanup();
        return;
      }
      if (Math.hypot(mv.screenX - startX, mv.screenY - startY) >= 5) {
        cleanup();
        sendNativeIpc({ cmd: "drag_window" });
      }
    };
    const cleanup = () => {
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", cleanup);
      window.removeEventListener("blur", cleanup);
    };
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", cleanup);
    window.addEventListener("blur", cleanup);
  });

  appleBar.addEventListener("dblclick", (e) => {
    if (e.target.closest(TITLEBAR_INTERACTIVE_SELECTOR)) return;
    e.preventDefault();
    triggerTitlebarMaximize();
  });

  /* ============================================================================
   * BROWSER STATE, TABS, TAB GROUPS, RAM UNLOADER (4 MODES), EXTENSIONS & ONBOARDING
   * ============================================================================ */
  const TAB_GROUP_COLORS = [
    { hex: "#f0b254", nameEn: "Gold", nameFr: "Or" },
    { hex: "#3b82f6", nameEn: "Blue", nameFr: "Bleu" },
    { hex: "#ef4444", nameEn: "Red", nameFr: "Rouge" },
    { hex: "#22c55e", nameEn: "Green", nameFr: "Vert" },
    { hex: "#a855f7", nameEn: "Purple", nameFr: "Violet" },
    { hex: "#06b6d4", nameEn: "Cyan", nameFr: "Cyan" },
    { hex: "#ec4899", nameEn: "Pink", nameFr: "Rose" },
    { hex: "#f97316", nameEn: "Orange", nameFr: "Orange" }
  ];
  let tabs = [{ id: 1, title: "New Tab", url: "", mediaTimeSec: 0, scrollY: 0, groupId: null, faviconUrl: "", lastActiveAt: Date.now(), unloaded: false }];
  let tabGroups = [];
  let closedTabsStack = [];
  let editingGroupId = null;
  const faviconLoadCache = new Map();
  let activeTabId = 1;
  let nextTabId = 2;
  let bhSuspended = false;
  let bhResumeFn = null;
  let activeSettingsCat = "";
  let currentBookmarks = [];
  let installedExtensions = [];
  let privateMode = false;
  let restoreSessionEnabled = true;
  let tabUnloadMode = "medium";
  let tabUnloadCustomMinutes = 15;
  let tabUnloadEffectiveSeconds = 900;
  let nativeRamActiveCount = 0;
  let onboardEngine = "ddg";
  let vaultTotpTimer = null;
  let settingsScrollRaf = 0;
  let settingsQuerySeq = 0;
  let persistTabsTimer = null;
  const SETTINGS_ROW_H = 62;

  function escapeHtml(str) {
    return String(str || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function formatMediaTimestamp(sec) {
    const s = Math.max(0, Math.floor(sec || 0));
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    const r = s % 60;
    if (h > 0) return `${h}:${String(m).padStart(2, "0")}:${String(r).padStart(2, "0")}`;
    return `${m}:${String(r).padStart(2, "0")}`;
  }

  function normalizeUrlNoTime(raw) {
    try {
      const u = new URL(raw);
      u.searchParams.delete("t");
      u.searchParams.delete("time_continue");
      u.searchParams.delete("start");
      u.hash = "";
      return u.toString();
    } catch (_) {
      return String(raw || "");
    }
  }

  function copySensitiveToClipboard(secret, label) {
    if (!navigator.clipboard || !navigator.clipboard.writeText) {
      showToast(L("Clipboard unavailable", "Presse-papiers indisponible"));
      return;
    }
    navigator.clipboard.writeText(secret).then(() => {
      showToast(label + L(" (auto-clears in 30s)", " (effacement auto dans 30s)"));
      clearTimeout(window.__clipClearTimer);
      window.__clipClearTimer = setTimeout(() => {
        navigator.clipboard.writeText("").catch(() => {});
      }, 30000);
    }).catch(() => {
      showToast(L("Unable to copy to clipboard", "Impossible de copier dans le presse-papiers"));
    });
  }

  function isInternalSettingsUrl(url) {
    return typeof url === "string" && url.startsWith("singularity://");
  }

  function sectionFromInternalUrl(url) {
    const u = String(url || "").toLowerCase();
    if (u.includes("appearance") || u.includes("themes")) return "appearance";
    if (u.includes("extensions")) return "extensions";
    if (u.includes("tokens")) return "tokens";
    if (u.includes("bookmarks") || u.includes("history")) return "bookmarks";
    if (u.includes("vault")) return "vault";
    if (u.includes("mullvad") || u.includes("vpn")) return "mullvad";
    if (u.includes("engine")) return "settings";
    return "general";
  }

  function internalUrlForSection(sec) {
    if (sec === "appearance") return "singularity://settings/appearance";
    if (sec === "extensions") return "singularity://settings/extensions";
    if (sec === "tokens") return "singularity://settings/tokens";
    if (sec === "bookmarks") return "singularity://settings/bookmarks";
    if (sec === "vault") return "singularity://settings/vault";
    if (sec === "mullvad") return "singularity://settings/mullvad";
    if (sec === "settings") return "singularity://settings/engine";
    return "singularity://settings";
  }

  function tabTitleForSection(sec) {
    if (sec === "appearance") return L("Settings · Themes", "Paramètres · Thèmes");
    if (sec === "extensions") return L("Chrome Extensions", "Extensions Chrome");
    if (sec === "tokens") return L("Accounts & .singularity", "Comptes & .singularity");
    if (sec === "bookmarks") return L("Bookmarks & History", "Favoris & Historique");
    if (sec === "vault") return L("Vault & 2FA", "Coffre-fort & 2FA");
    if (sec === "mullvad") return L("Shield & WireGuard", "Bouclier & WireGuard");
    if (sec === "settings") return L("Settings · Engine", "Paramètres · Moteur");
    return L("Settings", "Paramètres");
  }

  function getActiveTab() {
    return tabs.find(t => t.id === activeTabId) || tabs[0];
  }

  function flushOpenTabsNow() {
    if (privateMode || !bootInitialized || !restoreSessionEnabled) return;
    if (persistTabsTimer) {
      clearTimeout(persistTabsTimer);
      persistTabsTimer = null;
    }
    const webTabs = tabs.filter(t => !!t.url && /^https?:\/\//i.test(t.url));
    const activeWebIdx = Math.max(0, webTabs.findIndex(t => t.id === activeTabId));
    const usedGroupIds = new Set();
    const clean = webTabs.map(t => {
      const entry = { title: t.title || t.url, url: t.url };
      if (t.mediaTimeSec && t.mediaTimeSec >= 2) entry.media_time_sec = Math.floor(t.mediaTimeSec);
      if (t.scrollY && t.scrollY > 0) entry.scroll_y = Math.floor(t.scrollY);
      if (t.groupId) {
        entry.group_id = t.groupId;
        usedGroupIds.add(t.groupId);
      }
      if (t.faviconUrl && /^https?:\/\//i.test(t.faviconUrl)) {
        entry.favicon_url = t.faviconUrl;
      }
      return entry;
    });
    const cleanGroups = tabGroups
      .filter(g => usedGroupIds.has(g.id))
      .map(g => ({
        id: g.id,
        title: g.title || "",
        color: g.color || "#f0b254",
        collapsed: !!g.collapsed
      }));
    apiPost("/api/profile/save_tabs", {
      tabs: clean,
      tab_groups: cleanGroups,
      active_index: activeWebIdx
    }).catch(() => {});
  }

  function persistOpenTabsIfEnabled(deferred) {
    if (privateMode || !bootInitialized || !restoreSessionEnabled) return;
    if (deferred) {
      if (persistTabsTimer) return;
      persistTabsTimer = setTimeout(flushOpenTabsNow, 3000);
    } else {
      flushOpenTabsNow();
    }
  }

  window.addEventListener("beforeunload", () => {
    flushOpenTabsNow();
  });

  function updateBookmarkStarState() {
    const tab = getActiveTab();
    const btn = document.getElementById("btn-bookmark-star");
    const isStarred = !!(tab && tab.url && !isInternalSettingsUrl(tab.url) && currentBookmarks.some(b => b.url === tab.url));
    btn.classList.toggle("starred", isStarred);
    btn.querySelector("polygon").setAttribute("fill", isStarred ? "currentColor" : "none");
  }

  function createBookmarkIconNode(url) {
    const wrap = document.createElement("span");
    wrap.className = "bm-icon-wrap";
    const brand = brandIconForUrl(url);
    wrap.style.background = brand.bg;

    const fb = document.createElement("span");
    fb.innerHTML = brand.html;
    wrap.appendChild(fb);

    if (url && /^https?:\/\//i.test(url)) {
      let host = "";
      try { host = new URL(url).hostname.toLowerCase(); } catch (_) {}
      if (host) {
        const src = "/api/favicon?host=" + encodeURIComponent(host);
        const cached = faviconLoadCache.get(src);
        if (cached !== "err") {
          const img = document.createElement("img");
          img.alt = "";
          img.decoding = "async";
          if (cached === "ok") {
            img.classList.add("loaded");
            fb.style.opacity = "0";
          }
          img.addEventListener("load", () => {
            if (img.naturalWidth > 0) {
              faviconLoadCache.set(src, "ok");
              img.classList.add("loaded");
              fb.style.opacity = "0";
            }
          });
          img.addEventListener("error", () => {
            faviconLoadCache.set(src, "err");
            img.remove();
            fb.style.opacity = "1";
          });
          img.src = src;
          wrap.appendChild(img);
        }
      }
    }
    return wrap;
  }

  function deriveTitleFromUrl(url) {
    if (isInternalSettingsUrl(url)) return tabTitleForSection(sectionFromInternalUrl(url));
    try {
      const u = new URL(url);
      const host = u.hostname.replace(/^www\./, "");
      if (host.includes("youtube.com") && u.pathname === "/watch") {
        return L("YouTube · Standby", "YouTube · En attente");
      }
      return host || url;
    } catch (_) {
      return url || L("New Tab", "Nouvel onglet");
    }
  }

  function renderBookmarksStrip() {
    const strip = document.getElementById("ntp-bookmarks-strip");
    strip.replaceChildren();
    for (const b of currentBookmarks) {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "quick-pill";
      btn.appendChild(createBookmarkIconNode(b.url));
      const sp = document.createElement("span");
      sp.textContent = b.title || b.url;
      btn.appendChild(sp);
      btn.addEventListener("click", (e) => {
        if (e.ctrlKey || e.metaKey) {
          e.preventDefault();
          openBackgroundLazyTab(b.url, b.title);
          return;
        }
        openUrlInActiveTab(b.url, b.title);
      });
      btn.addEventListener("mousedown", (e) => { if (e.button === 1) e.preventDefault(); });
      btn.addEventListener("auxclick", (e) => {
        if (e.button === 1) {
          e.preventDefault();
          openBackgroundLazyTab(b.url, b.title);
        }
      });
      strip.appendChild(btn);
    }
    const addBtn = document.createElement("button");
    addBtn.type = "button";
    addBtn.className = "quick-pill";
    addBtn.title = L("Manage bookmarks", "Gérer les favoris");
    const plus = document.createElement("span");
    plus.textContent = "+";
    addBtn.appendChild(plus);
    addBtn.addEventListener("click", () => openSheet("bookmarks"));
    strip.appendChild(addBtn);
    updateBookmarkStarState();
  }

  function updateTabsScrollArrows() {
    const strip = document.getElementById("tabs-strip");
    const leftBtn = document.getElementById("tabs-scroll-left");
    const rightBtn = document.getElementById("tabs-scroll-right");
    if (!strip || !leftBtn || !rightBtn) return;
    const overflows = strip.scrollWidth > strip.clientWidth + 2;
    leftBtn.classList.toggle("visible", overflows && strip.scrollLeft > 2);
    rightBtn.classList.toggle("visible", overflows && (strip.scrollLeft + strip.clientWidth < strip.scrollWidth - 2));
  }

  function scrollTabsStrip(deltaPx) {
    const strip = document.getElementById("tabs-strip");
    if (!strip) return;
    strip.scrollBy({ left: deltaPx, behavior: "smooth" });
    setTimeout(updateTabsScrollArrows, 220);
  }

  // Smooth hardware-accelerated FLIP animation moving the URL bar from dead-center
  // to the right whenever many tabs are open (doubling visible tab strip width!).
  let isOmnibarDockedRight = false;
  function syncOmnibarLayout(allowAnimate) {
    if (!appleBar) return;
    const omniWrap = appleBar.querySelector(".omnibar-wrap");
    const strip = document.getElementById("tabs-strip");
    if (!omniWrap || !strip) return;

    const narrow = window.innerWidth < 960;
    const wantRight = isOmnibarDockedRight
      ? (tabs.length >= 4 || (narrow && tabs.length >= 3))
      : (tabs.length >= 4 || (narrow && tabs.length >= 3) || strip.scrollWidth > strip.clientWidth + 4);

    if (wantRight === isOmnibarDockedRight) return;

    const before = omniWrap.getBoundingClientRect();
    isOmnibarDockedRight = wantRight;
    appleBar.classList.toggle("tabs-expanded", wantRight);
    const after = omniWrap.getBoundingClientRect();

    if (allowAnimate && before.width > 0 && after.width > 0) {
      const beforeCx = before.left + before.width * 0.5;
      const afterCx = after.left + after.width * 0.5;
      const dx = beforeCx - afterCx;
      if (Math.abs(dx) > 2 && typeof omniWrap.animate === "function") {
        omniWrap.getAnimations().forEach(a => a.cancel());
        omniWrap.animate(
          [
            { transform: `translateX(${dx}px)` },
            { transform: "translateX(0px)" }
          ],
          { duration: 380, easing: "cubic-bezier(0.22, 1, 0.36, 1)" }
        );
      }
    }
    requestAnimationFrame(updateTabsScrollArrows);
  }

  /* ============================================================================
   * TAB GROUPS, FAVICONS, RIGHT-CLICK CONTEXT MENU & GLOBAL SHORTCUTS ENGINE
   * ============================================================================ */
  function findTabGroup(groupId) {
    if (!groupId) return null;
    return tabGroups.find(g => g.id === groupId) || null;
  }

  function pruneEmptyGroups() {
    const used = new Set(tabs.map(t => t.groupId).filter(Boolean));
    tabGroups = tabGroups.filter(g => used.has(g.id));
    if (editingGroupId && !used.has(editingGroupId)) {
      closeGroupEditor();
    }
  }

  function nextGroupColor() {
    const used = new Set(tabGroups.map(g => g.color));
    for (const c of TAB_GROUP_COLORS) {
      if (!used.has(c.hex)) return c.hex;
    }
    return TAB_GROUP_COLORS[tabGroups.length % TAB_GROUP_COLORS.length].hex;
  }

  function createTabGroupForTab(tabId, openEditorNow) {
    const tab = tabs.find(t => t.id === tabId);
    if (!tab) return null;
    const grp = {
      id: "grp-" + Date.now().toString(36) + "-" + Math.floor(Math.random() * 1e5).toString(36),
      title: "",
      color: nextGroupColor(),
      collapsed: false
    };
    tabGroups.push(grp);
    tab.groupId = grp.id;
    pruneEmptyGroups();
    renderTabs(false);
    persistOpenTabsIfEnabled(false);
    if (openEditorNow !== false) {
      openGroupEditor(grp.id);
    }
    return grp;
  }

  function assignTabToGroup(tabId, groupId) {
    const idx = tabs.findIndex(t => t.id === tabId);
    const grp = findTabGroup(groupId);
    if (idx === -1 || !grp) return;
    const [tab] = tabs.splice(idx, 1);
    tab.groupId = grp.id;
    let lastInGrp = -1;
    for (let i = 0; i < tabs.length; i++) {
      if (tabs[i].groupId === grp.id) lastInGrp = i;
    }
    if (lastInGrp >= 0) {
      tabs.splice(lastInGrp + 1, 0, tab);
    } else {
      tabs.splice(Math.min(idx, tabs.length), 0, tab);
    }
    grp.collapsed = false;
    pruneEmptyGroups();
    renderTabs(false);
    persistOpenTabsIfEnabled(false);
  }

  function removeTabFromGroup(tabId) {
    const tab = tabs.find(t => t.id === tabId);
    if (!tab || !tab.groupId) return;
    tab.groupId = null;
    pruneEmptyGroups();
    renderTabs(false);
    persistOpenTabsIfEnabled(false);
  }

  function toggleTabGroupCollapsed(groupId) {
    const grp = findTabGroup(groupId);
    if (!grp) return;
    grp.collapsed = !grp.collapsed;
    if (grp.collapsed) {
      const act = getActiveTab();
      if (act && act.groupId === grp.id) {
        const visibleOther = tabs.find(t => {
          if (t.groupId === grp.id) return false;
          const tg = findTabGroup(t.groupId);
          return !tg || !tg.collapsed;
        });
        if (visibleOther) {
          activeTabId = visibleOther.id;
          syncViewportToActiveTab("activate");
          return;
        }
      }
    }
    renderTabs(false);
    persistOpenTabsIfEnabled(false);
  }

  function ungroupTabs(groupId) {
    if (!groupId) return;
    for (const t of tabs) {
      if (t.groupId === groupId) t.groupId = null;
    }
    tabGroups = tabGroups.filter(g => g.id !== groupId);
    if (editingGroupId === groupId) closeGroupEditor();
    renderTabs(false);
    persistOpenTabsIfEnabled(false);
  }

  function closeTabGroup(groupId) {
    const members = tabs.filter(t => t.groupId === groupId);
    if (members.length === 0) return;
    for (const m of members) {
      pushClosedTab(m, tabs.indexOf(m));
      sendNativeIpc({ cmd: "close_tab", tab_id: m.id });
    }
    tabs = tabs.filter(t => t.groupId !== groupId);
    tabGroups = tabGroups.filter(g => g.id !== groupId);
    if (editingGroupId === groupId) closeGroupEditor();
    if (tabs.length === 0) {
      const nid = nextTabId++;
      tabs = [{ id: nid, title: L("New Tab", "Nouvel onglet"), url: "", mediaTimeSec: 0, scrollY: 0, groupId: null, faviconUrl: "", lastActiveAt: Date.now(), unloaded: false }];
      activeTabId = nid;
      syncViewportToActiveTab("view");
      focusSearchForNewTab();
      return;
    }
    if (!tabs.some(t => t.id === activeTabId)) {
      activeTabId = tabs[0].id;
      const g = findTabGroup(tabs[0].groupId);
      if (g) g.collapsed = false;
      syncViewportToActiveTab("activate");
    } else {
      renderTabs(false);
      persistOpenTabsIfEnabled(false);
    }
  }

  function openGroupEditor(groupId) {
    const grp = findTabGroup(groupId);
    const bar = document.getElementById("group-editor-bar");
    const inp = document.getElementById("group-editor-name");
    const pal = document.getElementById("group-editor-colors");
    if (!grp || !bar || !inp || !pal) return;
    editingGroupId = grp.id;
    inp.value = grp.title || "";
    pal.replaceChildren();
    for (const c of TAB_GROUP_COLORS) {
      const dot = document.createElement("button");
      dot.type = "button";
      dot.className = "grp-color-dot" + (grp.color === c.hex ? " selected" : "");
      dot.style.background = c.hex;
      dot.title = L(c.nameEn, c.nameFr);
      dot.addEventListener("click", () => {
        grp.color = c.hex;
        pal.querySelectorAll(".grp-color-dot").forEach(el => el.classList.remove("selected"));
        dot.classList.add("selected");
        renderTabs(false);
        persistOpenTabsIfEnabled(false);
      });
      pal.appendChild(dot);
    }
    bar.classList.add("open");
    setTimeout(() => {
      inp.focus();
      inp.select();
    }, 10);
  }

  function closeGroupEditor() {
    const bar = document.getElementById("group-editor-bar");
    if (bar) bar.classList.remove("open");
    editingGroupId = null;
  }

  function ungroupEditingGroup() {
    if (editingGroupId) {
      ungroupTabs(editingGroupId);
    }
  }

  (function wireGroupEditor() {
    const inp = document.getElementById("group-editor-name");
    if (!inp) return;
    inp.addEventListener("input", () => {
      const grp = findTabGroup(editingGroupId);
      if (!grp) return;
      grp.title = inp.value.slice(0, 40);
      renderTabs(false);
      persistOpenTabsIfEnabled(true);
    });
    inp.addEventListener("keydown", (ev) => {
      if (ev.key === "Enter" || ev.key === "Escape") {
        ev.preventDefault();
        ev.stopPropagation();
        closeGroupEditor();
        persistOpenTabsIfEnabled(false);
      }
    });
    document.addEventListener("mousedown", (ev) => {
      const bar = document.getElementById("group-editor-bar");
      if (bar && bar.classList.contains("open") && !bar.contains(ev.target)) {
        closeGroupEditor();
        persistOpenTabsIfEnabled(false);
      }
    });
  })();

  // Clean monogram letter-badge fallbacks (zero bundled third-party brand SVGs;
  // live favicons are always fetched from `/api/favicon` and seamlessly replace the badge).
  function brandIconForUrl(url) {
    if (!url) {
      return { bg: "transparent", html: `<img src="/api/logo.png" alt="" />`, preferFallback: true };
    }
    if (isInternalSettingsUrl(url)) {
      return {
        bg: "rgba(240, 178, 84, 0.18)",
        html: `<svg viewBox="0 0 24 24" fill="none" stroke="#f0b254" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9c.26.6.85 1 1.51 1H21a2 2 0 1 1 0 4h-.09c-.66 0-1.25.4-1.51 1z"/></svg>`,
        preferFallback: true
      };
    }
    let host = "";
    try { host = new URL(url).hostname.toLowerCase(); } catch (_) { host = ""; }
    const h = host.replace(/^www\./, "");
    if (h === "youtube.com" || h.endsWith(".youtube.com") || h === "youtu.be") {
      return { bg: "#dc2626", html: `<span style="color:#fff;font-weight:900;font-size:10px;">Y</span>`, preferFallback: false };
    }
    if (h === "github.com" || h.endsWith(".github.com")) {
      return { bg: "#24292f", html: `<span style="color:#f0f2f5;font-weight:800;font-size:9px;">GH</span>`, preferFallback: false };
    }
    if (h === "twitch.tv" || h.endsWith(".twitch.tv")) {
      return { bg: "#7c3aed", html: `<span style="color:#fff;font-weight:800;font-size:10px;">T</span>`, preferFallback: false };
    }
    if (h === "discord.com" || h.endsWith(".discord.com")) {
      return { bg: "#5865f2", html: `<span style="color:#fff;font-weight:800;font-size:10px;">D</span>`, preferFallback: false };
    }
    if (h === "google.com" || h === "google.fr" || /^google\.[a-z.]{2,6}$/.test(h) || h.endsWith(".google.com")) {
      return { bg: "#2563eb", html: `<span style="color:#fff;font-weight:800;font-size:10px;">G</span>`, preferFallback: false };
    }
    if (h.includes("wikipedia.org")) {
      return { bg: "#eceef2", html: `<span style="color:#111;font-family:Georgia,serif;font-weight:900;font-size:11px;">W</span>`, preferFallback: false };
    }
    if (h === "duckduckgo.com" || h.endsWith(".duckduckgo.com")) {
      return { bg: "#de5833", html: `<span style="color:#fff;font-weight:800;font-size:10px;">D</span>`, preferFallback: false };
    }
    if (h === "reddit.com" || h.endsWith(".reddit.com")) {
      return { bg: "#ff4500", html: `<span style="color:#fff;font-weight:800;font-size:10px;">r</span>`, preferFallback: false };
    }
    if (h === "x.com" || h === "twitter.com") {
      return { bg: "#111216", html: `<span style="color:#fff;font-weight:800;font-size:10px;">X</span>`, preferFallback: false };
    }
    if (h === "netflix.com" || h.endsWith(".netflix.com")) {
      return { bg: "#141414", html: `<span style="color:#e50914;font-weight:900;font-size:11px;">N</span>`, preferFallback: false };
    }
    if (h === "spotify.com" || h.endsWith(".spotify.com")) {
      return { bg: "#1db954", html: `<span style="color:#0a0b0e;font-weight:900;font-size:10px;">S</span>`, preferFallback: false };
    }
    if (h === "chatgpt.com" || h.endsWith(".openai.com")) {
      return { bg: "#10a37f", html: `<span style="color:#fff;font-weight:800;font-size:10px;">AI</span>`, preferFallback: false };
    }
    const label = (h || "S").replace(/^m\./, "");
    const letter = (label.charAt(0) || "S").toUpperCase();
    let hash = 0;
    for (let i = 0; i < label.length; i++) hash = ((hash << 5) - hash + label.charCodeAt(i)) | 0;
    const palette = ["#3b82f6", "#8b5cf6", "#10b981", "#f59e0b", "#ec4899", "#06b6d4", "#f97316", "#6366f1"];
    const bg = palette[Math.abs(hash) % palette.length];
    return { bg, html: `<span>${escapeHtml(letter)}</span>`, preferFallback: false };
  }

  function createTabFaviconNode(tab) {
    const wrap = document.createElement("span");
    wrap.className = "tab-icon-wrap";
    const brand = brandIconForUrl(tab.url);

    const fb = document.createElement("span");
    fb.className = "tab-icon-fallback";
    fb.style.background = brand.bg;
    fb.innerHTML = brand.html;
    wrap.appendChild(fb);

    if (tab.url && /^https?:\/\//i.test(tab.url) && !brand.preferFallback) {
      let host = "";
      try { host = new URL(tab.url).hostname.toLowerCase(); } catch (_) {}
      if (host) {
        let src = "/api/favicon?host=" + encodeURIComponent(host);
        if (tab.faviconUrl && /^https?:\/\//i.test(tab.faviconUrl)) {
          src += "&icon=" + encodeURIComponent(tab.faviconUrl);
        }
        const cached = faviconLoadCache.get(src);
        if (cached !== "err") {
          const img = document.createElement("img");
          img.className = "tab-favicon" + (cached === "ok" ? " loaded" : "");
          img.alt = "";
          img.loading = "lazy";
          img.decoding = "async";
          if (cached === "ok") fb.style.opacity = "0";
          img.addEventListener("load", () => {
            if (img.naturalWidth > 0) {
              faviconLoadCache.set(src, "ok");
              img.classList.add("loaded");
              fb.style.opacity = "0";
            }
          });
          img.addEventListener("error", () => {
            faviconLoadCache.set(src, "err");
            img.remove();
            fb.style.opacity = "1";
          });
          img.src = src;
          wrap.appendChild(img);
        }
      }
    }

    if (tab.unloaded) {
      const badge = document.createElement("span");
      badge.className = "tab-sleep-badge";
      wrap.appendChild(badge);
    }
    return wrap;
  }

  function closeHtmlTabContextMenu() {
    const menu = document.getElementById("tab-context-menu");
    if (menu) menu.classList.remove("open");
  }

  function openHtmlTabContextMenu(x, y, opts) {
    const menu = document.getElementById("tab-context-menu");
    if (!menu) return;
    menu.replaceChildren();
    const addBtn = (label, kbd, onClick, disabled, danger) => {
      const b = document.createElement("button");
      b.type = "button";
      b.className = "tctx-item" + (danger ? " danger" : "");
      b.disabled = !!disabled;
      const left = document.createElement("span");
      left.textContent = label;
      b.appendChild(left);
      if (kbd) {
        const right = document.createElement("span");
        right.className = "tctx-kbd";
        right.textContent = kbd;
        b.appendChild(right);
      }
      b.addEventListener("click", () => {
        closeHtmlTabContextMenu();
        onClick();
      });
      menu.appendChild(b);
    };
    const addSep = () => {
      const s = document.createElement("div");
      s.className = "tctx-sep";
      menu.appendChild(s);
    };

    if (opts.kind === "tab") {
      const t = tabs.find(x => x.id === opts.tabId);
      if (!t) return;
      addBtn(L("New tab to the right", "Nouvel onglet à droite"), "", () => executeTabContextAction("new_tab_right", t.id, null, null));
      addBtn(L("Duplicate tab", "Dupliquer l'onglet"), "", () => executeTabContextAction("duplicate_tab", t.id, null, null));
      addBtn(L("Reload", "Recharger"), "Ctrl+R", () => executeTabContextAction("reload_tab", t.id, null, null));
      addBtn(t.unloaded ? L("Wake tab", "Réveiller l'onglet") : L("Put to sleep (RAM)", "Mettre en veille (RAM)"), "", () => executeTabContextAction("unload_tab", t.id, null, null));
      addSep();
      addBtn(L("Move tab to new window", "Déplacer dans une nouvelle fenêtre"), "", () => executeTabContextAction("move_tab_new_window", t.id, null, null, null));
      addSep();
      const hdr = document.createElement("div");
      hdr.className = "tctx-header";
      hdr.textContent = L("Tab groups", "Groupes d'onglets");
      menu.appendChild(hdr);
      addBtn(L("+ New group...", "+ Nouveau groupe..."), "", () => executeTabContextAction("add_to_new_group", t.id, null, null));
      for (const g of tabGroups) {
        const b = document.createElement("button");
        b.type = "button";
        b.className = "tctx-item";
        const sp = document.createElement("span");
        sp.style.cssText = "display:inline-flex;align-items:center;";
        const dot = document.createElement("span");
        dot.className = "tctx-dot";
        dot.style.background = g.color || "#f0b254";
        sp.appendChild(dot);
        sp.appendChild(document.createTextNode(g.title || L("Unnamed group", "Groupe sans nom")));
        b.appendChild(sp);
        b.addEventListener("click", () => {
          closeHtmlTabContextMenu();
          executeTabContextAction("add_to_group", t.id, null, g.id);
        });
        menu.appendChild(b);
      }
      if (t.groupId) {
        addBtn(L("Remove from group", "Retirer du groupe"), "", () => executeTabContextAction("remove_from_group", t.id, null, null));
      }
      addSep();
      addBtn(L("Reopen closed tab", "Rouvrir l'onglet fermé"), "Ctrl+Shift+T", () => executeTabContextAction("reopen_closed_tab", null, null, null), closedTabsStack.length === 0);
      addSep();
      addBtn(L("Close tab", "Fermer l'onglet"), "Ctrl+W", () => executeTabContextAction("close_tab", t.id, null, null), false, true);
      addBtn(L("Close other tabs", "Fermer les autres onglets"), "", () => executeTabContextAction("close_other_tabs", t.id, null, null), tabs.length <= 1);
      addBtn(L("Close tabs to the right", "Fermer les onglets à droite"), "", () => executeTabContextAction("close_tabs_right", t.id, null, null));
    } else if (opts.kind === "group") {
      const g = findTabGroup(opts.groupId);
      if (!g) return;
      addBtn(L("Rename / Color...", "Renommer / Couleur..."), "", () => executeTabContextAction("edit_group", null, g.id, null));
      addBtn(L("New tab in group", "Nouvel onglet dans ce groupe"), "", () => executeTabContextAction("new_tab_in_group", null, g.id, null));
      addBtn(g.collapsed ? L("Expand group", "Déplier le groupe") : L("Collapse group", "Réduire le groupe"), "", () => executeTabContextAction("toggle_group_collapse", null, g.id, null));
      addSep();
      addBtn(L("Ungroup", "Dissocier le groupe"), "", () => executeTabContextAction("ungroup", null, g.id, null));
      addBtn(L("Close group", "Fermer le groupe"), "", () => executeTabContextAction("close_group", null, g.id, null), false, true);
    } else {
      addBtn(L("New tab", "Nouvel onglet"), "Ctrl+T", () => executeTabContextAction("new_tab", null, null, null));
      addBtn(L("New window", "Nouvelle fenêtre"), "Ctrl+N", () => executeTabContextAction("new_window", null, null, null));
      addBtn(L("Reopen closed tab", "Rouvrir l'onglet fermé"), "Ctrl+Shift+T", () => executeTabContextAction("reopen_closed_tab", null, null, null), closedTabsStack.length === 0);
      addSep();
      addBtn(L("Create new group", "Créer un nouveau groupe"), "", () => executeTabContextAction("new_group_empty", null, null, null));
      addBtn(L("Sleep inactive tabs", "Mettre en veille les inactifs"), "", () => executeTabContextAction("unload_inactive", null, null, null));
      addSep();
      addBtn(L("Singularity Settings", "Paramètres Singularity"), "Ctrl+,", () => executeTabContextAction("open_settings", null, null, null));
    }

    menu.classList.add("open");
    const rect = menu.getBoundingClientRect();
    const px = Math.max(8, Math.min(x, window.innerWidth - rect.width - 8));
    const py = Math.max(8, Math.min(y, window.innerHeight - rect.height - 8));
    menu.style.left = px + "px";
    menu.style.top = py + "px";
  }

  function detachTabToWindow(tabId, opts) {
    const t = tabs.find(x => x.id === tabId);
    if (!t) return;
    const forceNewWindow = !!(opts && opts.forceNewWindow);
    const targetWindowId = (opts && opts.targetWindowId) ? String(opts.targetWindowId) : null;
    if (hasNativeIpc()) {
      sendNativeIpc({
        cmd: "detach_tab",
        tab_id: t.id,
        url: (t.url && /^https?:\/\//i.test(t.url)) ? t.url : "",
        title: t.title || "",
        favicon_url: (t.faviconUrl && /^https?:\/\//i.test(t.faviconUrl)) ? t.faviconUrl : null,
        media_time_sec: t.mediaTimeSec >= 2 ? Math.floor(t.mediaTimeSec) : null,
        scroll_y: t.scrollY > 0 ? Math.floor(t.scrollY) : null,
        force_new_window: forceNewWindow,
        target_window_id: targetWindowId,
        is_only_tab: tabs.length <= 1
      });
    } else if (t.url && /^https?:\/\//i.test(t.url)) {
      window.open(t.url, "_blank", "noopener");
      if (tabs.length > 1) removeDetachedTabFromList(t.id);
    }
  }

  function removeDetachedTabFromList(tabId) {
    const idx = tabs.findIndex(t => t.id === tabId);
    if (idx === -1) return;
    if (tabs.length <= 1) {
      sendNativeIpc({ cmd: "close" });
      return;
    }
    tabs.splice(idx, 1);
    pruneEmptyGroups();
    if (activeTabId === tabId) {
      const next = tabs[Math.min(idx, tabs.length - 1)];
      activeTabId = next.id;
      syncViewportToActiveTab("activate");
    } else {
      renderTabs(false);
      persistOpenTabsIfEnabled(false);
    }
  }

  function executeTabContextAction(action, tabId, groupId, targetGroupId, targetWindowId) {
    switch (action) {
      case "new_tab":
        createNewTab();
        break;
      case "new_window":
        if (hasNativeIpc()) sendNativeIpc({ cmd: "open_new_window" });
        else window.open(window.location.href, "_blank");
        break;
      case "move_tab_new_window":
        if (tabId) detachTabToWindow(tabId, { forceNewWindow: true });
        break;
      case "move_tab_to_window":
        if (tabId && targetWindowId) detachTabToWindow(tabId, { targetWindowId });
        break;
      case "new_tab_right": {
        const idx = tabs.findIndex(t => t.id === tabId);
        const ref = idx >= 0 ? tabs[idx] : null;
        createNewTab("", "", { insertIndex: idx >= 0 ? idx + 1 : tabs.length, groupId: ref ? ref.groupId : null });
        break;
      }
      case "new_tab_in_group": {
        const grp = findTabGroup(groupId);
        if (!grp) return;
        grp.collapsed = false;
        let lastIdx = -1;
        for (let i = 0; i < tabs.length; i++) {
          if (tabs[i].groupId === grp.id) lastIdx = i;
        }
        createNewTab("", "", { insertIndex: lastIdx >= 0 ? lastIdx + 1 : tabs.length, groupId: grp.id });
        break;
      }
      case "duplicate_tab": {
        const idx = tabs.findIndex(t => t.id === tabId);
        if (idx === -1) return;
        const src = tabs[idx];
        createNewTab(src.url || "", src.title || "", { insertIndex: idx + 1, groupId: src.groupId || null });
        break;
      }
      case "reload_tab":
        if (tabId && tabId !== activeTabId) activateTab(tabId);
        reloadActivePage();
        break;
      case "unload_tab": {
        const t = tabs.find(x => x.id === tabId);
        if (!t) return;
        if (t.unloaded) {
          activateTab(t.id);
        } else {
          if (t.id === activeTabId) {
            showToast(L("Active tab cannot be put to sleep", "L'onglet actif ne peut pas être mis en veille"));
            return;
          }
          if (!t.url || isInternalSettingsUrl(t.url)) return;
          t.unloaded = true;
          sendNativeIpc({ cmd: "unload_tab", tab_id: t.id });
          updateSingleTabPill(t);
          updateRamStatusUI();
          showToast(L(`Tab put to sleep: ${t.title || t.url}`, `Onglet mis en veille : ${t.title || t.url}`));
        }
        break;
      }
      case "unload_inactive":
        unloadInactiveTabsNow();
        break;
      case "add_to_new_group":
        if (tabId) createTabGroupForTab(tabId, true);
        break;
      case "new_group_empty": {
        const id = createNewTab();
        createTabGroupForTab(id, true);
        break;
      }
      case "add_to_group":
        if (tabId && targetGroupId) assignTabToGroup(tabId, targetGroupId);
        break;
      case "remove_from_group":
        if (tabId) removeTabFromGroup(tabId);
        break;
      case "edit_group":
        if (groupId) openGroupEditor(groupId);
        break;
      case "toggle_group_collapse":
        if (groupId) toggleTabGroupCollapsed(groupId);
        break;
      case "ungroup":
        if (groupId) ungroupTabs(groupId);
        break;
      case "close_group":
        if (groupId) closeTabGroup(groupId);
        break;
      case "reopen_closed_tab":
        reopenLastClosedTab();
        break;
      case "close_tab":
        if (tabId) closeTab(tabId);
        break;
      case "close_other_tabs": {
        const keep = tabs.find(t => t.id === tabId);
        if (!keep) return;
        for (let i = tabs.length - 1; i >= 0; i--) {
          if (tabs[i].id !== keep.id) {
            pushClosedTab(tabs[i], i);
            sendNativeIpc({ cmd: "close_tab", tab_id: tabs[i].id });
          }
        }
        tabs = [keep];
        pruneEmptyGroups();
        activeTabId = keep.id;
        syncViewportToActiveTab("activate");
        break;
      }
      case "close_tabs_right": {
        const idx = tabs.findIndex(t => t.id === tabId);
        if (idx === -1 || idx >= tabs.length - 1) return;
        const removed = tabs.splice(idx + 1);
        for (let i = 0; i < removed.length; i++) {
          pushClosedTab(removed[i], idx + 1 + i);
          sendNativeIpc({ cmd: "close_tab", tab_id: removed[i].id });
        }
        pruneEmptyGroups();
        if (!tabs.some(t => t.id === activeTabId)) {
          activeTabId = tabs[idx].id;
          syncViewportToActiveTab("activate");
        } else {
          renderTabs(false);
          persistOpenTabsIfEnabled(false);
        }
        break;
      }
      case "open_settings":
        openSheet("general");
        break;
    }
  }

  let suppressTabClickUntil = 0;

  // Delegated clicks, pointer-capture tab dragging (reorder + tear-off + cross-window drop),
  // bulletproof middle-click tab close, wheel scroll & native right-click context menu
  (function wireTabsStripInteractions() {
    const strip = document.getElementById("tabs-strip");
    const barWrap = document.querySelector(".tabs-bar-wrap");
    if (!strip || !barWrap) return;

    let midDownTabId = null;
    let midHandled = false;

    function onMidDown(ev) {
      if (ev.button !== 1) return;
      const pill = ev.target && ev.target.closest ? ev.target.closest(".tab-pill") : null;
      if (!pill) return;
      ev.preventDefault();
      ev.stopPropagation();
      midDownTabId = Number(pill.dataset.tabId || 0) || null;
      midHandled = false;
    }

    function onMidUpOrAux(ev) {
      if (ev.button !== 1) return;
      if (midHandled) {
        ev.preventDefault();
        ev.stopPropagation();
        return;
      }
      const pill = ev.target && ev.target.closest ? ev.target.closest(".tab-pill") : null;
      const pillId = pill ? (Number(pill.dataset.tabId || 0) || null) : null;
      const targetId = pillId || midDownTabId;
      if (!targetId) return;
      if (midDownTabId && pillId && midDownTabId !== pillId) {
        midDownTabId = null;
        return;
      }
      midHandled = true;
      midDownTabId = null;
      ev.preventDefault();
      ev.stopPropagation();
      closeTab(targetId);
    }

    strip.addEventListener("pointerdown", onMidDown, true);
    strip.addEventListener("mousedown", onMidDown, true);
    strip.addEventListener("pointerup", onMidUpOrAux, true);
    strip.addEventListener("mouseup", onMidUpOrAux, true);
    strip.addEventListener("auxclick", onMidUpOrAux, true);

    // Delegated left-click handler for tabs, close buttons, and group pills (zero per-tab closures!)
    strip.addEventListener("click", (ev) => {
      if (ev.button !== 0) return;
      if (performance.now() < suppressTabClickUntil) {
        ev.preventDefault();
        ev.stopPropagation();
        return;
      }
      const closeBtn = ev.target && ev.target.closest ? ev.target.closest(".tab-close-btn") : null;
      if (closeBtn) {
        const p = closeBtn.closest(".tab-pill");
        const tid = p ? Number(p.dataset.tabId || 0) : 0;
        if (tid) {
          ev.stopPropagation();
          closeTab(tid);
        }
        return;
      }
      const grpBtn = ev.target && ev.target.closest ? ev.target.closest(".tab-group-pill") : null;
      if (grpBtn && grpBtn.dataset.groupId) {
        ev.stopPropagation();
        toggleTabGroupCollapsed(grpBtn.dataset.groupId);
        return;
      }
      const pill = ev.target && ev.target.closest ? ev.target.closest(".tab-pill") : null;
      if (pill) {
        const tid = Number(pill.dataset.tabId || 0);
        if (tid) activateTab(tid);
      }
    });

    strip.addEventListener("dblclick", (ev) => {
      const grpBtn = ev.target && ev.target.closest ? ev.target.closest(".tab-group-pill") : null;
      if (grpBtn && grpBtn.dataset.groupId) {
        ev.stopPropagation();
        openGroupEditor(grpBtn.dataset.groupId);
      }
    });

    // Chrome-grade Pointer-Capture Tab Drag Engine:
    // - Drag horizontally along the tab strip => smooth live reorder
    // - Drag vertically out of the tab bar (or outside the window) => release on another Singularity
    //   window to move the tab there, OR release on the desktop to tear off into a brand-new window!
    let dragState = null;

    function clearDropMarkers() {
      const marked = strip.querySelectorAll(".drop-before, .drop-after");
      for (let i = 0; i < marked.length; i++) {
        marked[i].classList.remove("drop-before", "drop-after");
      }
    }

    function finishTabDrag(cancelled) {
      if (!dragState) return;
      const st = dragState;
      dragState = null;
      clearDropMarkers();
      if (st.pill) {
        st.pill.classList.remove("dragging", "detaching");
      }
      try {
        if (strip.hasPointerCapture && strip.hasPointerCapture(st.pointerId)) {
          strip.releasePointerCapture(st.pointerId);
        }
      } catch (_) {}

      if (!st.started || cancelled) return;
      suppressTabClickUntil = performance.now() + 200;

      if (st.detaching) {
        detachTabToWindow(st.tabId, { forceNewWindow: false });
        return;
      }

      if (st.targetTabId && st.targetTabId !== st.tabId) {
        const fromIdx = tabs.findIndex(t => t.id === st.tabId);
        const toIdxOrig = tabs.findIndex(t => t.id === st.targetTabId);
        if (fromIdx !== -1 && toIdxOrig !== -1 && fromIdx !== toIdxOrig) {
          const targetGroup = tabs[toIdxOrig].groupId || null;
          const [moved] = tabs.splice(fromIdx, 1);
          let insertIdx = tabs.findIndex(t => t.id === st.targetTabId);
          if (insertIdx === -1) insertIdx = tabs.length;
          else if (st.insertAfter) insertIdx += 1;
          moved.groupId = targetGroup;
          tabs.splice(insertIdx, 0, moved);
          pruneEmptyGroups();
          renderTabs(false);
          persistOpenTabsIfEnabled(false);
        }
      }
    }

    strip.addEventListener("pointerdown", (ev) => {
      if (ev.button !== 0) return;
      if (ev.target && ev.target.closest && ev.target.closest(".tab-close-btn")) return;
      const pill = ev.target && ev.target.closest ? ev.target.closest(".tab-pill") : null;
      if (!pill) return;
      const tabId = Number(pill.dataset.tabId || 0);
      if (!tabId) return;
      dragState = {
        tabId,
        pill,
        pointerId: ev.pointerId,
        startX: ev.clientX,
        startY: ev.clientY,
        started: false,
        detaching: false,
        targetTabId: null,
        insertAfter: false
      };
    });

    strip.addEventListener("pointermove", (ev) => {
      if (!dragState || ev.pointerId !== dragState.pointerId) return;
      const dx = ev.clientX - dragState.startX;
      const dy = ev.clientY - dragState.startY;
      if (!dragState.started) {
        if (dx * dx + dy * dy < 36) return; // 6px deadzone keeps clicks instantaneous
        dragState.started = true;
        dragState.pill.classList.add("dragging");
        try { strip.setPointerCapture(ev.pointerId); } catch (_) {}
      }

      const barRect = barWrap.getBoundingClientRect();
      const outVert = ev.clientY > barRect.bottom + 26 || ev.clientY < barRect.top - 22 || Math.abs(dy) >= 34;
      const outHoriz = ev.clientX < -20 || ev.clientX > window.innerWidth + 20;
      const wantDetach = outVert || outHoriz;

      if (wantDetach !== dragState.detaching) {
        dragState.detaching = wantDetach;
        dragState.pill.classList.toggle("detaching", wantDetach);
        if (wantDetach) {
          clearDropMarkers();
          dragState.targetTabId = null;
          showToast(
            L("Release to move tab to another window or open a new window", "Relâchez pour déplacer vers une autre fenêtre ou en créer une nouvelle"),
            null,
            1800
          );
        }
      }

      if (dragState.detaching) return;

      // Compute horizontal insertion marker across visible tab pills
      clearDropMarkers();
      dragState.targetTabId = null;
      const pills = strip.querySelectorAll(".tab-pill");
      let bestPill = null;
      let bestDist = Infinity;
      let after = false;
      for (let i = 0; i < pills.length; i++) {
        const p = pills[i];
        const pid = Number(p.dataset.tabId || 0);
        if (pid === dragState.tabId) continue;
        const r = p.getBoundingClientRect();
        const mid = (r.left + r.right) * 0.5;
        const dist = Math.abs(ev.clientX - mid);
        if (dist < bestDist) {
          bestDist = dist;
          bestPill = p;
          after = ev.clientX >= mid;
        }
      }
      if (bestPill) {
        dragState.targetTabId = Number(bestPill.dataset.tabId || 0) || null;
        dragState.insertAfter = after;
        bestPill.classList.add(after ? "drop-after" : "drop-before");
      }
    });

    strip.addEventListener("pointerup", (ev) => {
      if (!dragState || ev.pointerId !== dragState.pointerId) return;
      finishTabDrag(false);
    });
    strip.addEventListener("pointercancel", (ev) => {
      if (!dragState || ev.pointerId !== dragState.pointerId) return;
      finishTabDrag(true);
    });

    barWrap.addEventListener("contextmenu", (ev) => {
      ev.preventDefault();
      ev.stopPropagation();
      const grpEl = ev.target && ev.target.closest ? ev.target.closest(".tab-group-pill") : null;
      const tabEl = ev.target && ev.target.closest ? ev.target.closest(".tab-pill") : null;
      const kind = grpEl ? "group" : (tabEl ? "tab" : "strip");
      const tabId = tabEl ? (Number(tabEl.dataset.tabId || 0) || null) : null;
      const groupId = grpEl ? (grpEl.dataset.groupId || null) : null;
      const tabObj = tabId ? tabs.find(t => t.id === tabId) : null;
      const grpObj = groupId ? findTabGroup(groupId) : null;

      if (hasNativeIpc()) {
        sendNativeIpc({
          cmd: "show_tab_context_menu",
          kind,
          tab_id: tabId,
          group_id: groupId,
          tab_in_group: !!(tabObj && tabObj.groupId),
          can_reopen: closedTabsStack.length > 0,
          is_unloaded: !!(tabObj && tabObj.unloaded),
          group_collapsed: !!(grpObj && grpObj.collapsed),
          groups: tabGroups.map(g => ({ id: g.id, title: g.title || L("Unnamed group", "Groupe sans nom") })),
          lang: currentLang
        });
      } else {
        openHtmlTabContextMenu(ev.clientX, ev.clientY, { kind, tabId, groupId });
      }
    });

    document.addEventListener("mousedown", (ev) => {
      const m = document.getElementById("tab-context-menu");
      if (m && m.classList.contains("open") && !m.contains(ev.target)) {
        closeHtmlTabContextMenu();
      }
    });

    strip.addEventListener("wheel", (e) => {
      if (strip.scrollWidth > strip.clientWidth + 2) {
        e.preventDefault();
        strip.scrollLeft += (Math.abs(e.deltaY) > Math.abs(e.deltaX) ? e.deltaY : e.deltaX);
        updateTabsScrollArrows();
      }
    }, { passive: false });
    strip.addEventListener("scroll", updateTabsScrollArrows, { passive: true });
    window.addEventListener("resize", () => {
      syncOmnibarLayout(false);
      updateTabsScrollArrows();
    });
  })();

  const TAB_CLOSE_SVG = `<svg width="9" height="9" viewBox="0 0 10 10" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><path d="M2 2l6 6M8 2L2 8"/></svg>`;

  function buildTabPillTooltip(t, grp) {
    const timeHint = t.mediaTimeSec >= 3
      ? L(` · resumes at ${formatMediaTimestamp(t.mediaTimeSec)}`, ` · reprise à ${formatMediaTimestamp(t.mediaTimeSec)}`)
      : "";
    const grpHint = grp && grp.title ? ` [${grp.title}]` : "";
    return (t.title || L("New Tab", "Nouvel onglet"))
      + grpHint
      + timeHint
      + (t.unloaded ? L(" (sleeping / RAM freed — click to wake)", " (en veille / RAM libérée — cliquez pour charger)") : "")
      + L(" · Drag out: move to new/other window · Middle-click: close", " · Glisser hors barre : nouvelle/autre fenêtre · Clic molette : fermer");
  }

  function faviconSignatureForTab(t) {
    return `${t.url || ""}|${t.faviconUrl || ""}|${t.unloaded ? "1" : "0"}`;
  }

  function syncTabPillElement(pill, t, grp) {
    const isAct = t.id === activeTabId;
    pill.classList.toggle("active", isAct);
    pill.classList.toggle("sleeping", !!t.unloaded);
    pill.classList.toggle("in-group", !!grp);
    if (grp) {
      pill.style.setProperty("--group-color", grp.color || "#f0b254");
    } else {
      pill.style.removeProperty("--group-color");
    }
    const nextTitle = buildTabPillTooltip(t, grp);
    if (pill.title !== nextTitle) pill.title = nextTitle;

    const favSig = faviconSignatureForTab(t);
    if (pill.dataset.favSig !== favSig) {
      pill.dataset.favSig = favSig;
      const oldIcon = pill.querySelector(".tab-icon-wrap");
      const newIcon = createTabFaviconNode(t);
      if (oldIcon) oldIcon.replaceWith(newIcon);
      else pill.prepend(newIcon);
    }
    const lbl = pill.querySelector(".tab-label");
    const nextLabel = t.title || L("New Tab", "Nouvel onglet");
    if (lbl && lbl.textContent !== nextLabel) lbl.textContent = nextLabel;
  }

  // O(1) in-place update for a single tab's title / favicon / sleep state without touching other tabs!
  function updateSingleTabPill(t) {
    if (!t) return;
    const strip = document.getElementById("tabs-strip");
    if (!strip) return;
    const pill = strip.querySelector(`.tab-pill[data-tab-id="${t.id}"]`);
    if (!pill) return;
    syncTabPillElement(pill, t, findTabGroup(t.groupId));
  }

  function createTabPillElement(t, grp) {
    const pill = document.createElement("div");
    pill.dataset.tabId = String(t.id);
    pill.className = "tab-pill";
    pill.dataset.favSig = faviconSignatureForTab(t);

    pill.appendChild(createTabFaviconNode(t));

    const lbl = document.createElement("span");
    lbl.className = "tab-label";
    lbl.textContent = t.title || L("New Tab", "Nouvel onglet");
    pill.appendChild(lbl);

    const cls = document.createElement("span");
    cls.className = "tab-close-btn";
    cls.title = L("Close tab (Ctrl+W)", "Fermer l'onglet (Ctrl+W)");
    cls.innerHTML = TAB_CLOSE_SVG;
    pill.appendChild(cls);

    syncTabPillElement(pill, t, grp);
    return pill;
  }

  // Keyed incremental DOM reconciliation: reuses existing `.tab-pill` elements & cached favicons
  // so 38+ open tabs never suffer full DOM destruction/rebuild jank!
  function renderTabs(scrollActiveIntoView) {
    const strip = document.getElementById("tabs-strip");
    const existingPills = new Map();
    const existingGroups = new Map();
    for (let i = 0; i < strip.children.length; i++) {
      const ch = strip.children[i];
      if (ch.dataset && ch.dataset.tabId) existingPills.set(Number(ch.dataset.tabId), ch);
      else if (ch.dataset && ch.dataset.groupId) existingGroups.set(ch.dataset.groupId, ch);
    }

    let visibleTabCount = 0;
    const groupMemberCounts = new Map();
    for (let i = 0; i < tabs.length; i++) {
      const t = tabs[i];
      const g = findTabGroup(t.groupId);
      if (!g || !g.collapsed) visibleTabCount++;
      if (t.groupId) groupMemberCounts.set(t.groupId, (groupMemberCounts.get(t.groupId) || 0) + 1);
    }
    strip.classList.toggle("compact-tabs", visibleTabCount >= 6);
    strip.classList.toggle("very-compact", visibleTabCount >= 12);

    const desiredNodes = [];
    let activePill = null;
    let lastGroupId = null;

    for (let i = 0; i < tabs.length; i++) {
      const t = tabs[i];
      const grp = findTabGroup(t.groupId);
      const curGroupId = grp ? grp.id : null;

      if (curGroupId && curGroupId !== lastGroupId) {
        let gBtn = existingGroups.get(grp.id);
        if (!gBtn) {
          gBtn = document.createElement("button");
          gBtn.type = "button";
          gBtn.dataset.groupId = grp.id;
        }
        const hasTitle = !!(grp.title && grp.title.trim());
        gBtn.className = "tab-group-pill"
          + (grp.collapsed ? " collapsed" : "")
          + (!hasTitle && !grp.collapsed ? " dot-only" : "");
        gBtn.style.setProperty("--group-color", grp.color || "#f0b254");
        const cnt = groupMemberCounts.get(grp.id) || 0;
        gBtn.title = L(
          `${hasTitle ? grp.title : "Group"} (${cnt} tab${cnt > 1 ? "s" : ""}) · Click: collapse/expand · Double-click: rename · Right-click: menu`,
          `${hasTitle ? grp.title : "Groupe"} (${cnt} onglet${cnt > 1 ? "s" : ""}) · Clic: réduire/déplier · Double-clic: renommer · Clic droit: options`
        );
        const gSig = `${hasTitle ? grp.title.trim() : ""}|${grp.collapsed ? cnt : ""}`;
        if (gBtn.dataset.gSig !== gSig) {
          gBtn.dataset.gSig = gSig;
          gBtn.replaceChildren();
          if (hasTitle) {
            const sp = document.createElement("span");
            sp.textContent = grp.title.trim();
            gBtn.appendChild(sp);
          }
          if (grp.collapsed) {
            const cntEl = document.createElement("span");
            cntEl.className = "tab-group-count";
            cntEl.textContent = String(cnt);
            gBtn.appendChild(cntEl);
          }
        }
        desiredNodes.push(gBtn);
      }
      lastGroupId = curGroupId;

      if (grp && grp.collapsed) continue;

      let pill = existingPills.get(t.id);
      if (pill) {
        syncTabPillElement(pill, t, grp);
      } else {
        pill = createTabPillElement(t, grp);
      }
      desiredNodes.push(pill);
      if (t.id === activeTabId) activePill = pill;
    }

    // Minimal DOM reconciliation: only move/insert/remove nodes that actually changed order!
    const desiredSet = new Set(desiredNodes);
    for (let i = strip.children.length - 1; i >= 0; i--) {
      if (!desiredSet.has(strip.children[i])) {
        strip.children[i].remove();
      }
    }
    for (let i = 0; i < desiredNodes.length; i++) {
      const node = desiredNodes[i];
      if (strip.children[i] !== node) {
        strip.insertBefore(node, strip.children[i] || null);
      }
    }

    syncOmnibarLayout(bootInitialized);
    if (scrollActiveIntoView && activePill) {
      activePill.scrollIntoView({ behavior: "smooth", block: "nearest", inline: "nearest" });
    }
    requestAnimationFrame(updateTabsScrollArrows);
    updateRamStatusUI();
  }

  function setBlackHoleSuspended(susp) {
    if (bhSuspended === susp) return;
    bhSuspended = susp;
    const c = document.getElementById("singularity-canvas");
    const v = document.getElementById("cinema-vignette");
    if (susp) {
      // Keep the WebGL2 context alive (no display:none flash) while shrinking the backing
      // framebuffer to 1x1 so Chromium releases ~15-30 MB of GPU VRAM/RAM on normal web tabs.
      if (c) {
        c.style.opacity = "0";
        c.style.visibility = "hidden";
        c.width = 1;
        c.height = 1;
      }
      if (v) { v.style.opacity = "0"; v.style.visibility = "hidden"; }
    } else {
      if (v) { v.style.visibility = "visible"; v.style.opacity = "1"; }
      if (typeof bhResumeFn === "function") {
        bhResumeFn();
      } else if (c) {
        c.style.visibility = "visible";
        c.style.opacity = "1";
      }
    }
  }

  function anyModalOpen() {
    return document.getElementById("onboarding-overlay").classList.contains("open");
  }

  // `actionMode`: "navigate" (new URL in active tab), "activate" (zero-reload tab switch), or "view" (overlay/home)
  function syncViewportToActiveTab(actionMode) {
    const tab = getActiveTab();
    tab.lastActiveAt = Date.now();
    const grp = findTabGroup(tab.groupId);
    if (grp && grp.collapsed) grp.collapsed = false;
    const omni = document.getElementById("omnibar-input");
    omni.value = tab.url || "";
    renderTabs(true);
    updateBookmarkStarState();
    persistOpenTabsIfEnabled(false);

    const tutorialOpen = anyModalOpen();
    const settingsPageEl = document.getElementById("settings-modal");

    if (isInternalSettingsUrl(tab.url)) {
      document.body.classList.remove("bar-only");
      document.getElementById("ntp-view").style.display = "none";
      document.getElementById("web-view").style.display = "none";
      document.getElementById("web-frame").src = "about:blank";
      settingsPageEl.classList.add("open");
      setBlackHoleSuspended(!tutorialOpen);
      sendNativeIpc({
        cmd: "activate_tab",
        tab_id: tab.id,
        url: "",
        web_visible: false,
        overlay_open: tutorialOpen
      });
      switchSheetTab(sectionFromInternalUrl(tab.url), true);
    } else if (!tab.url) {
      settingsPageEl.classList.remove("open");
      stopVaultTotpTicker();
      document.body.classList.remove("bar-only");
      document.getElementById("ntp-view").style.display = "flex";
      document.getElementById("web-view").style.display = "none";
      document.getElementById("web-frame").src = "about:blank";
      setBlackHoleSuspended(false);
      sendNativeIpc({
        cmd: "activate_tab",
        tab_id: tab.id,
        url: "",
        web_visible: false,
        overlay_open: tutorialOpen
      });
    } else {
      settingsPageEl.classList.remove("open");
      stopVaultTotpTicker();
      document.getElementById("ntp-view").style.display = "none";
      if (hasNativeIpc()) {
        document.body.classList.toggle("bar-only", !tutorialOpen);
        setBlackHoleSuspended(!tutorialOpen);
        if (actionMode === "navigate") {
          tab.unloaded = false;
          tab.startPaused = false;
          sendNativeIpc({
            cmd: "navigate_web",
            tab_id: tab.id,
            url: tab.url,
            overlay_open: tutorialOpen
          });
        } else {
          const shouldStartPaused = !!tab.startPaused;
          tab.unloaded = false;
          tab.startPaused = false;
          sendNativeIpc({
            cmd: "activate_tab",
            tab_id: tab.id,
            url: tab.url,
            web_visible: true,
            overlay_open: tutorialOpen,
            resume_time_sec: tab.mediaTimeSec >= 3 ? Math.floor(tab.mediaTimeSec) : null,
            resume_scroll_y: tab.scrollY >= 40 ? Math.floor(tab.scrollY) : null,
            start_paused: shouldStartPaused
          });
        }
        sweepInactiveTabsForRam();
      } else {
        document.body.classList.remove("bar-only");
        setBlackHoleSuspended(true);
        document.getElementById("web-view").style.display = "block";
        if (actionMode === "navigate" || actionMode === "activate") {
          document.getElementById("web-frame").src = "/api/web_proxy?url=" + encodeURIComponent(tab.url);
        }
      }
    }
  }

  // Opens a link in a deferred background tab (middle-click / Ctrl+click):
  // stays strictly on the current tab and NEVER loads or autoplays media until clicked!
  function openBackgroundLazyTab(url, explicitTitle) {
    if (!url || !/^https?:\/\//i.test(url)) return;
    const id = nextTabId++;
    const title = (explicitTitle && explicitTitle.trim())
      ? explicitTitle.trim()
      : deriveTitleFromUrl(url);
    const activeIdx = tabs.findIndex(t => t.id === activeTabId);
    const opener = activeIdx >= 0 ? tabs[activeIdx] : null;
    let insertIdx = activeIdx >= 0 ? activeIdx + 1 : tabs.length;
    while (insertIdx < tabs.length && tabs[insertIdx].openerTabId === activeTabId) {
      insertIdx++;
    }
    tabs.splice(insertIdx, 0, {
      id,
      title,
      url,
      mediaTimeSec: 0,
      scrollY: 0,
      groupId: opener ? (opener.groupId || null) : null,
      faviconUrl: "",
      openerTabId: activeTabId,
      lastActiveAt: Date.now(),
      unloaded: true
    });
    renderTabs(false);
    persistOpenTabsIfEnabled(false);
  }

  function focusSearchForNewTab() {
    if (anyModalOpen()) return;
    const focusNow = () => {
      const ntpInput = document.getElementById("ntp-search-input");
      const omni = document.getElementById("omnibar-input");
      const target = (ntpInput && document.getElementById("ntp-view").style.display !== "none")
        ? ntpInput
        : omni;
      if (target) {
        target.value = "";
        target.focus();
        if (typeof target.select === "function") target.select();
      }
    };
    focusNow();
    requestAnimationFrame(focusNow);
    setTimeout(focusNow, 45);
  }

  function createNewTab(initialUrl, initialTitle, opts) {
    const prev = getActiveTab();
    if (prev) prev.lastActiveAt = Date.now();
    const id = nextTabId++;
    const label = (initialTitle && initialTitle.trim())
      ? initialTitle.trim()
      : (initialUrl ? deriveTitleFromUrl(initialUrl) : L("New Tab", "Nouvel onglet"));
    const entry = {
      id,
      title: label,
      url: initialUrl || "",
      mediaTimeSec: 0,
      scrollY: 0,
      groupId: opts && opts.groupId ? opts.groupId : null,
      faviconUrl: "",
      lastActiveAt: Date.now(),
      unloaded: false
    };
    if (opts && typeof opts.insertIndex === "number") {
      const idx = Math.max(0, Math.min(opts.insertIndex, tabs.length));
      tabs.splice(idx, 0, entry);
    } else {
      tabs.push(entry);
    }
    activeTabId = id;
    syncViewportToActiveTab(initialUrl ? "navigate" : "activate");
    if (!initialUrl) {
      focusSearchForNewTab();
    }
    return id;
  }

  function activateTab(id) {
    if (activeTabId === id) {
      const cur = getActiveTab();
      if (cur && cur.url && !isInternalSettingsUrl(cur.url) && !anyModalOpen() && hasNativeIpc()) {
        sendNativeIpc({ cmd: "focus_active_web", toggle_media_play: false });
      }
      return;
    }
    const prev = getActiveTab();
    if (prev) prev.lastActiveAt = Date.now();
    activeTabId = id;
    syncViewportToActiveTab("activate");
  }

  function pushClosedTab(tab, closedIndex) {
    if (!tab || !tab.url || !/^https?:\/\//i.test(tab.url)) return;
    closedTabsStack.push({
      title: tab.title || deriveTitleFromUrl(tab.url),
      url: tab.url,
      mediaTimeSec: tab.mediaTimeSec || 0,
      scrollY: tab.scrollY || 0,
      groupId: tab.groupId || null,
      faviconUrl: tab.faviconUrl || "",
      closedIndex: Math.max(0, closedIndex || 0)
    });
    if (closedTabsStack.length > 30) {
      closedTabsStack.shift();
    }
  }

  function reopenLastClosedTab() {
    if (closedTabsStack.length === 0) {
      showToast(L("No recently closed tabs", "Aucun onglet fermé récemment"));
      return;
    }
    const item = closedTabsStack.pop();
    const grp = findTabGroup(item.groupId);
    if (grp) grp.collapsed = false;
    const id = nextTabId++;
    const idx = Math.max(0, Math.min(item.closedIndex, tabs.length));
    tabs.splice(idx, 0, {
      id,
      title: item.title,
      url: item.url,
      mediaTimeSec: item.mediaTimeSec || 0,
      scrollY: item.scrollY || 0,
      groupId: grp ? grp.id : null,
      faviconUrl: item.faviconUrl || "",
      lastActiveAt: Date.now(),
      unloaded: false
    });
    activeTabId = id;
    syncViewportToActiveTab("activate");
  }

  function getVisibleTabsList() {
    return tabs.filter(t => {
      const g = findTabGroup(t.groupId);
      return !g || !g.collapsed || t.id === activeTabId;
    });
  }

  function handleBrowserShortcut(action, index) {
    switch (action) {
      case "reopen_closed_tab":
        reopenLastClosedTab();
        break;
      case "new_tab":
        createNewTab();
        break;
      case "new_window":
        if (hasNativeIpc()) sendNativeIpc({ cmd: "open_new_window" });
        else window.open(window.location.href, "_blank");
        break;
      case "close_active_tab":
        closeTab(activeTabId);
        break;
      case "next_tab": {
        const list = getVisibleTabsList();
        if (list.length <= 1) break;
        const cur = list.findIndex(t => t.id === activeTabId);
        activateTab(list[(cur + 1) % list.length].id);
        break;
      }
      case "prev_tab": {
        const list = getVisibleTabsList();
        if (list.length <= 1) break;
        const cur = list.findIndex(t => t.id === activeTabId);
        activateTab(list[(cur - 1 + list.length) % list.length].id);
        break;
      }
      case "jump_tab": {
        const list = getVisibleTabsList();
        if (list.length === 0 || !index) break;
        const target = index === 9 ? list[list.length - 1] : list[index - 1];
        if (target) activateTab(target.id);
        break;
      }
      case "focus_omnibar": {
        const omni = document.getElementById("omnibar-input");
        if (omni) {
          omni.focus();
          omni.select();
        }
        break;
      }
      case "reload_tab":
        reloadActivePage();
        break;
      case "toggle_bookmark":
        toggleActiveBookmark();
        break;
      case "open_history":
        openSheet("bookmarks");
        break;
      case "open_settings":
        openSheet("general");
        break;
      case "toggle_private":
        togglePrivateMode();
        break;
      case "toggle_fullscreen":
        toggleNativeFullscreen();
        break;
      case "web_back":
        historyBack();
        break;
      case "web_forward":
        historyForward();
        break;
    }
  }

  function closeTab(id) {
    if (tabs.length <= 1) {
      pushClosedTab(tabs[0], 0);
      sendNativeIpc({ cmd: "close_tab", tab_id: tabs[0].id });
      tabs[0].url = "";
      tabs[0].title = L("New Tab", "Nouvel onglet");
      tabs[0].mediaTimeSec = 0;
      tabs[0].scrollY = 0;
      tabs[0].groupId = null;
      tabs[0].faviconUrl = "";
      tabs[0].unloaded = false;
      tabs[0].lastActiveAt = Date.now();
      pruneEmptyGroups();
      syncViewportToActiveTab("view");
      return;
    }
    const idx = tabs.findIndex(t => t.id === id);
    if (idx === -1) return;
    pushClosedTab(tabs[idx], idx);
    sendNativeIpc({ cmd: "close_tab", tab_id: id });
    tabs.splice(idx, 1);
    pruneEmptyGroups();
    if (activeTabId === id) {
      const next = tabs[Math.max(0, idx - 1)];
      activeTabId = next.id;
      const g = findTabGroup(next.groupId);
      if (g) g.collapsed = false;
      syncViewportToActiveTab("activate");
    } else {
      renderTabs(false);
      persistOpenTabsIfEnabled(false);
    }
  }

  function openHomeInActiveTab() {
    const tab = getActiveTab();
    sendNativeIpc({ cmd: "close_tab", tab_id: tab.id });
    tab.url = "";
    tab.title = L("New Tab", "Nouvel onglet");
    tab.mediaTimeSec = 0;
    tab.scrollY = 0;
    tab.faviconUrl = "";
    tab.unloaded = false;
    tab.lastActiveAt = Date.now();
    syncViewportToActiveTab("view");
    focusSearchForNewTab();
  }

  async function openUrlInActiveTab(rawUrl, explicitTitle) {
    if (!rawUrl) return;
    let finalUrl = rawUrl;
    try {
      const res = await apiFetch("/api/navigate_check?url=" + encodeURIComponent(rawUrl));
      const check = await res.json();
      if (check && check.allowed === false) {
        showToast(L("Navigation blocked: ", "Navigation bloquée : ") + (check.reason || ""));
        return;
      }
      if (check && check.scrubbed_url) finalUrl = check.scrubbed_url;
    } catch (_) {}

    const tab = getActiveTab();
    if (normalizeUrlNoTime(tab.url) !== normalizeUrlNoTime(finalUrl)) {
      tab.mediaTimeSec = 0;
      tab.scrollY = 0;
      tab.faviconUrl = "";
    }
    tab.url = finalUrl;
    tab.unloaded = false;
    tab.lastActiveAt = Date.now();
    if (explicitTitle) {
      tab.title = explicitTitle;
    } else {
      try {
        tab.title = new URL(finalUrl).hostname.replace(/^www\./, "");
      } catch (_) {
        tab.title = finalUrl;
      }
    }
    syncViewportToActiveTab("navigate");
  }

  function searchUrlForEngine(query, eng) {
    const q = encodeURIComponent(query);
    if (eng === "google") return "https://www.google.com/search?q=" + q;
    if (eng === "brave") return "https://search.brave.com/search?q=" + q;
    if (eng === "qwant") return "https://www.qwant.com/?q=" + q;
    if (eng === "startpage") return "https://www.startpage.com/sp/search?query=" + q;
    return "https://duckduckgo.com/?q=" + q;
  }

  function navigateInput(raw) {
    if (!raw) return;
    const val = raw.trim();
    if (!val || val === "singularity://newtab" || val === "about:newtab" || val === "about:blank") {
      openHomeInActiveTab();
      return;
    }
    if (val.startsWith("singularity://extensions") || val.startsWith("chrome://extensions")) {
      openSheet("extensions");
      return;
    }
    if (val.startsWith("singularity://")) {
      openSheet(sectionFromInternalUrl(val));
      return;
    }
    let url = val;
    if (!/^https?:\/\//i.test(url)) {
      if (url.includes(".") && !url.includes(" ")) {
        url = "https://" + url;
      } else {
        const eng = document.getElementById("search-engine").value || "ddg";
        url = searchUrlForEngine(url, eng);
      }
    }
    openUrlInActiveTab(url);
  }

  function executeNtpSearch(q) {
    if (!q || !q.trim()) return;
    const query = q.trim();
    if (/^https?:\/\//i.test(query) || (query.includes(".") && !query.includes(" "))) {
      navigateInput(query);
      return;
    }
    const eng = document.getElementById("search-engine").value || "ddg";
    openUrlInActiveTab(searchUrlForEngine(query, eng), query);
  }

  function historyBack() {
    const tab = getActiveTab();
    if (!tab.url) return;
    if (!sendNativeIpc({ cmd: "web_back" })) {
      openHomeInActiveTab();
    }
  }

  function historyForward() {
    const tab = getActiveTab();
    if (!tab.url) return;
    sendNativeIpc({ cmd: "web_forward" });
  }

  function reloadActivePage() {
    const tab = getActiveTab();
    if (!tab.url) return;
    if (!sendNativeIpc({ cmd: "web_reload" })) {
      document.getElementById("web-frame").src = "/api/web_proxy?url=" + encodeURIComponent(tab.url);
    }
  }

  async function toggleActiveBookmark() {
    const tab = getActiveTab();
    if (!tab || !tab.url) {
      openSheet("bookmarks");
      return;
    }
    try {
      const res = await apiPost("/api/bookmarks/toggle", {
        url: tab.url,
        title: tab.title || tab.url
      });
      const d = await res.json();
      currentBookmarks = d.bookmarks || [];
      renderBookmarksStrip();
      showToast(d.added ? L("Added to bookmarks", "Ajouté aux favoris") : L("Removed from bookmarks", "Retiré des favoris"));
    } catch (_) {}
  }

  async function togglePrivateMode() {
    privateMode = !privateMode;
    document.getElementById("btn-private-mode").classList.toggle("active-gold", privateMode);
    await apiPost("/api/profile/update_prefs", { private_browsing: privateMode });
    sendNativeIpc({ cmd: "set_private_mode", enabled: privateMode });
    showToast(privateMode
      ? L("Private Browsing enabled (isolated ephemeral session)", "Mode Navigation Privée activé (session éphémère isolée)")
      : L("Standard browsing mode restored", "Mode standard réactivé"));
    refreshHeaderState();
  }

  async function saveDefaultEngine(eng) {
    document.getElementById("search-engine").value = eng;
    document.getElementById("gen-engine-select").value = eng;
    await apiPost("/api/profile/update_prefs", { engine: eng });
  }

  async function toggleRestoreSession() {
    restoreSessionEnabled = !restoreSessionEnabled;
    const btn = document.getElementById("btn-restore-session");
    btn.classList.toggle("on", restoreSessionEnabled);
    btn.textContent = restoreSessionEnabled ? "ON" : "OFF";
    await apiPost("/api/profile/update_prefs", { restore_session: restoreSessionEnabled });
    if (restoreSessionEnabled) {
      persistOpenTabsIfEnabled(false);
      showToast(L("Automatic tab & video timestamp restore enabled", "Sauvegarde automatique des onglets et positions vidéo activée"));
    } else {
      if (persistTabsTimer) {
        clearTimeout(persistTabsTimer);
        persistTabsTimer = null;
      }
      showToast(L("Automatic session restore disabled", "Restauration automatique des onglets désactivée"));
    }
  }

  /* --- 4-MODE RAM TAB UNLOADER (LOW / MEDIUM 24H / HARD 1H30 / CUSTOM) --- */
  function formatDurationLocalized(seconds) {
    const mins = Math.max(1, Math.round(seconds / 60));
    if (mins >= 1440 && mins % 1440 === 0) {
      const d = mins / 1440;
      return currentLang === "fr"
        ? d + (d > 1 ? " jours" : " jour")
        : d + (d > 1 ? " days" : " day");
    }
    if (mins >= 60) {
      const h = Math.floor(mins / 60);
      const r = mins % 60;
      return r > 0 ? `${h}h${String(r).padStart(2, "0")}` : `${h}h`;
    }
    return `${mins} min`;
  }

  function syncRamModeUI() {
    document.querySelectorAll("#ram-mode-grid .ram-mode-btn, #tuto-ram-grid .ram-mode-btn").forEach(btn => {
      btn.classList.toggle("selected", btn.dataset.ramMode === tabUnloadMode);
    });
    const customRow = document.getElementById("ram-custom-row");
    if (customRow) {
      customRow.style.display = tabUnloadMode === "custom" ? "flex" : "none";
    }
    const valInp = document.getElementById("ram-custom-val");
    const unitSel = document.getElementById("ram-custom-unit");
    if (valInp && unitSel && document.activeElement !== valInp) {
      if (tabUnloadCustomMinutes >= 60 && tabUnloadCustomMinutes % 60 === 0) {
        unitSel.value = "hours";
        valInp.value = String(tabUnloadCustomMinutes / 60);
      } else {
        unitSel.value = "minutes";
        valInp.value = String(tabUnloadCustomMinutes);
      }
    }
    const lbl = document.getElementById("ram-effective-label");
    if (lbl) {
      const names = currentLang === "fr"
        ? { low: "Low (Faible)", medium: "Medium (Équilibré)", hard: "Hard (Agressif)", custom: "Personnalisé" }
        : { low: "Low", medium: "Medium (Balanced)", hard: "Hard (Aggressive)", custom: "Custom" };
      const dur = formatDurationLocalized(tabUnloadEffectiveSeconds);
      lbl.textContent = currentLang === "fr"
        ? `Mode actif : ${names[tabUnloadMode] || tabUnloadMode} — décharge après ${dur} d'inactivité`
        : `Active mode: ${names[tabUnloadMode] || tabUnloadMode} — unloads after ${dur} idle`;
    }
    updateRamStatusUI();
  }

  function updateRamStatusUI() {
    const badge = document.getElementById("ram-status-badge");
    if (!badge) return;
    const webTabs = tabs.filter(t => !!t.url && !isInternalSettingsUrl(t.url));
    const unloadedCount = webTabs.filter(t => t.unloaded).length;
    const activeCount = hasNativeIpc()
      ? nativeRamActiveCount
      : Math.max(0, webTabs.length - unloadedCount);
    badge.textContent = currentLang === "fr"
      ? `${activeCount} actif${activeCount > 1 ? "s" : ""} en RAM · ${unloadedCount} déchargé${unloadedCount > 1 ? "s" : ""}`
      : `${activeCount} active in RAM · ${unloadedCount} sleeping`;
  }

  async function selectRamMode(mode) {
    tabUnloadMode = mode;
    const res = await apiPost("/api/profile/update_prefs", {
      tab_unload_mode: mode,
      tab_unload_custom_minutes: tabUnloadCustomMinutes
    });
    try {
      const d = await res.json();
      if (d.tab_unload_effective_seconds) {
        tabUnloadEffectiveSeconds = d.tab_unload_effective_seconds;
      }
    } catch (_) {}
    syncRamModeUI();
    sweepInactiveTabsForRam();
    showToast(L(`RAM mode saved: ${formatDurationLocalized(tabUnloadEffectiveSeconds)}`, `Mode RAM enregistré : ${formatDurationLocalized(tabUnloadEffectiveSeconds)}`));
  }

  async function applyRamPresetMinutes(mins) {
    tabUnloadMode = "custom";
    tabUnloadCustomMinutes = Math.max(1, Math.min(43200, Math.floor(mins)));
    const res = await apiPost("/api/profile/update_prefs", {
      tab_unload_mode: "custom",
      tab_unload_custom_minutes: tabUnloadCustomMinutes
    });
    try {
      const d = await res.json();
      if (d.tab_unload_effective_seconds) {
        tabUnloadEffectiveSeconds = d.tab_unload_effective_seconds;
      }
    } catch (_) {}
    syncRamModeUI();
    sweepInactiveTabsForRam();
    showToast(L(`Custom unload delay: ${formatDurationLocalized(tabUnloadEffectiveSeconds)}`, `Déchargement personnalisé : ${formatDurationLocalized(tabUnloadEffectiveSeconds)}`));
  }

  async function saveCustomRamDelay() {
    const raw = parseInt(document.getElementById("ram-custom-val").value || "60", 10);
    const unit = document.getElementById("ram-custom-unit").value;
    if (!Number.isFinite(raw) || raw < 1) {
      showToast(L("Enter a valid duration (>= 1)", "Saisissez une durée valide (>= 1)"));
      return;
    }
    const mins = unit === "hours" ? raw * 60 : raw;
    await applyRamPresetMinutes(mins);
  }

  function maxActiveBackgroundTabsForMode() {
    if (tabUnloadMode === "hard") return 3;
    if (tabUnloadMode === "medium") return 6;
    return 12;
  }

  function sweepInactiveTabsForRam() {
    const thresholdMs = Math.max(60, tabUnloadEffectiveSeconds) * 1000;
    const now = Date.now();
    let unloadedNow = 0;
    const liveBackground = [];
    for (const t of tabs) {
      if (t.id === activeTabId || !t.url || isInternalSettingsUrl(t.url) || t.unloaded) continue;
      if (now - (t.lastActiveAt || now) >= thresholdMs) {
        t.unloaded = true;
        sendNativeIpc({ cmd: "unload_tab", tab_id: t.id });
        unloadedNow++;
      } else {
        liveBackground.push(t);
      }
    }
    // Hard cap on concurrent background Chromium renderers so RAM never balloons with 15+ tabs
    const maxBg = maxActiveBackgroundTabsForMode();
    if (liveBackground.length > maxBg) {
      liveBackground.sort((a, b) => (a.lastActiveAt || 0) - (b.lastActiveAt || 0));
      const excess = liveBackground.length - maxBg;
      for (let i = 0; i < excess; i++) {
        const victim = liveBackground[i];
        victim.unloaded = true;
        sendNativeIpc({ cmd: "unload_tab", tab_id: victim.id });
        unloadedNow++;
      }
    }
    if (unloadedNow > 0) {
      renderTabs(false);
    }
  }

  function unloadInactiveTabsNow() {
    let count = 0;
    for (const t of tabs) {
      if (t.id === activeTabId || !t.url || isInternalSettingsUrl(t.url) || t.unloaded) continue;
      t.unloaded = true;
      sendNativeIpc({ cmd: "unload_tab", tab_id: t.id });
      count++;
    }
    renderTabs(false);
    showToast(count > 0
      ? L(`${count} inactive tab(s) unloaded from RAM`, `${count} onglet(s) inactif(s) déchargé(s) de la RAM`)
      : L("No inactive tabs to unload", "Aucun onglet inactif à décharger"));
  }

  /* ============================================================================
   * 6 COSMIC 3D THEMES ENGINE (BLACK HOLE / SOLAR / PULSAR / NEBULA / ECLIPSE / AURORA)
   * ============================================================================ */
  const COSMIC_THEMES = [
    {
      id: "singularity",
      nameEn: "Black Hole",
      nameFr: "Trou Noir",
      descEn: "Gargantua golden accretion disk & pure OLED black.",
      descFr: "Disque d'accrétion doré Gargantua & OLED noir pur.",
      preview: "radial-gradient(circle at 50% 50%, #000 0%, #000 22%, #f0b254 34%, #7a2d08 58%, #040407 82%)",
      shaderMode: 0,
      colHot: [1.44, 1.28, 0.98],
      colMid: [1.08, 0.65, 0.22],
      colOuter: [0.58, 0.18, 0.04],
      colGlow: [1.18, 0.88, 0.52],
      bgTint: [0.00, 0.00, 0.00]
    },
    {
      id: "soleil",
      nameEn: "Solar Corona",
      nameFr: "Soleil",
      descEn: "Blazing 3D star, turbulent plasma & golden corona.",
      descFr: "Étoile 3D ardente, plasma bouillonnant & couronne solaire.",
      preview: "radial-gradient(circle at 50% 50%, #fff6cc 0%, #ffc44d 28%, #e85d04 54%, #3d0f02 80%, #120602 100%)",
      shaderMode: 1,
      colHot: [1.65, 1.48, 1.02],
      colMid: [1.35, 0.68, 0.14],
      colOuter: [0.92, 0.22, 0.03],
      colGlow: [1.45, 0.84, 0.28],
      bgTint: [0.06, 0.025, 0.005]
    },
    {
      id: "pulsar",
      nameEn: "Cyan Pulsar",
      nameFr: "Pulsar Cyan",
      descEn: "Electric cyan relativistic ring & deep abyssal space.",
      descFr: "Anneau relativiste bleu-cyan électrique & espace abyssal.",
      preview: "radial-gradient(circle at 50% 50%, #020810 0%, #020810 21%, #7df3ff 33%, #0ea5e9 56%, #030914 82%)",
      shaderMode: 0,
      colHot: [1.20, 1.50, 1.60],
      colMid: [0.22, 0.82, 1.18],
      colOuter: [0.05, 0.24, 0.64],
      colGlow: [0.46, 0.96, 1.28],
      bgTint: [0.005, 0.025, 0.05]
    },
    {
      id: "nebuleuse",
      nameEn: "Amethyst Nebula",
      nameFr: "Nébuleuse",
      descEn: "Amethyst violet quasar & cosmic nebula glow.",
      descFr: "Quasar violet améthyste & halo nébulaire cosmique.",
      preview: "radial-gradient(circle at 50% 50%, #05020c 0%, #05020c 21%, #e4b4ff 33%, #9333ea 56%, #090414 82%)",
      shaderMode: 0,
      colHot: [1.48, 1.18, 1.56],
      colMid: [0.84, 0.36, 1.22],
      colOuter: [0.36, 0.08, 0.62],
      colGlow: [0.96, 0.56, 1.32],
      bgTint: [0.028, 0.01, 0.05]
    },
    {
      id: "eclipse",
      nameEn: "Blood Eclipse",
      nameFr: "Éclipse",
      descEn: "Total crimson eclipse with blazing diamond ring.",
      descFr: "Éclipse totale sanguine avec anneau de diamant incandescent.",
      preview: "radial-gradient(circle at 50% 50%, #050203 0%, #050203 28%, #ff4d5e 37%, #8b0c1e 60%, #100305 85%)",
      shaderMode: 2,
      colHot: [1.55, 1.18, 1.05],
      colMid: [1.28, 0.20, 0.24],
      colOuter: [0.68, 0.05, 0.10],
      colGlow: [1.32, 0.28, 0.34],
      bgTint: [0.045, 0.008, 0.012]
    },
    {
      id: "aurore",
      nameEn: "Emerald Aurora",
      nameFr: "Aurore",
      descEn: "Boreal emerald-jade ring & polar shimmer.",
      descFr: "Anneau boréal émeraude-jade & reflets polaires.",
      preview: "radial-gradient(circle at 50% 50%, #020806 0%, #020806 21%, #86efac 33%, #10b981 56%, #030d09 82%)",
      shaderMode: 0,
      colHot: [1.18, 1.52, 1.34],
      colMid: [0.18, 0.98, 0.68],
      colOuter: [0.04, 0.38, 0.34],
      colGlow: [0.36, 1.18, 0.84],
      bgTint: [0.005, 0.032, 0.022]
    }
  ];

  let activeThemeId = "singularity";
  function getActiveThemeConfig() {
    return COSMIC_THEMES.find(t => t.id === activeThemeId) || COSMIC_THEMES[0];
  }
  function themeDisplayName(t) {
    return currentLang === "fr" ? t.nameFr : t.nameEn;
  }
  function themeDisplayDesc(t) {
    return currentLang === "fr" ? t.descFr : t.descEn;
  }

  function applyCosmicTheme(themeId) {
    const found = COSMIC_THEMES.find(t => t.id === themeId) || COSMIC_THEMES[0];
    activeThemeId = found.id;
    if (found.id === "singularity") {
      document.documentElement.removeAttribute("data-theme");
    } else {
      document.documentElement.setAttribute("data-theme", found.id);
    }
    renderThemeGalleries();
  }

  async function selectCosmicTheme(themeId, fromOnboarding) {
    if (fromOnboarding) {
      onboardThemePicked = true;
    }
    applyCosmicTheme(themeId);
    const t = getActiveThemeConfig();
    await apiPost("/api/profile/update_prefs", { theme_id: t.id }).catch(() => {});
    if (fromOnboarding) {
      updateMandatoryStep1Gate();
    } else {
      showToast(L(`Theme applied: ${themeDisplayName(t)}`, `Thème appliqué : ${themeDisplayName(t)}`));
    }
  }

  function renderThemeGalleries() {
    ["settings-theme-grid", "tuto-theme-grid"].forEach(gridId => {
      const grid = document.getElementById(gridId);
      if (!grid) return;
      const isTutoGrid = gridId === "tuto-theme-grid";
      const hidePreselection = isTutoGrid && tutorialMandatoryLock && !onboardThemePicked;
      grid.replaceChildren();
      for (const t of COSMIC_THEMES) {
        const isSelected = !hidePreselection && t.id === activeThemeId;
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = "theme-card" + (isSelected ? " selected" : "");
        btn.dataset.themeId = t.id;
        btn.onclick = () => selectCosmicTheme(t.id, isTutoGrid);

        const orb = document.createElement("div");
        orb.className = "theme-preview-orb";
        orb.style.background = t.preview;
        btn.appendChild(orb);

        const nm = document.createElement("div");
        nm.className = "theme-card-name";
        const sp = document.createElement("span");
        sp.textContent = themeDisplayName(t);
        nm.appendChild(sp);
        if (isSelected) {
          const tag = document.createElement("span");
          tag.style.cssText = "font-size:10px;color:var(--gold-bright);font-family:var(--font-mono);";
          tag.textContent = L("ACTIVE", "ACTIF");
          nm.appendChild(tag);
        }
        btn.appendChild(nm);

        const ds = document.createElement("div");
        ds.className = "theme-card-desc";
        ds.textContent = themeDisplayDesc(t);
        btn.appendChild(ds);
        grid.appendChild(btn);
      }
    });
  }

  /* ============================================================================
   * 3-STEP ONBOARDING WIZARD (STEP 1 MANDATORY: LANGUAGE & COLOR THEME)
   * ============================================================================ */
  let tutorialStep = 0;
  let tutorialMandatoryLock = false;
  let onboardLanguagePicked = false;
  let onboardThemePicked = false;
  let detectedImportBrowsers = [];
  let selectedImportBrowserIds = new Set();
  let tutorialImportedTabsCount = 0;
  let tutorialImportedBookmarksCount = 0;

  function pickOnboardEngine(eng, btn) {
    onboardEngine = eng;
    document.querySelectorAll("#onboard-engines .eng-choice").forEach(b => {
      b.classList.toggle("selected", b.dataset.eng === eng);
    });
  }

  async function pickOnboardLanguage(lang) {
    const clean = (lang === "fr") ? "fr" : "en";
    onboardLanguagePicked = true;
    applyLanguage(clean);
    await apiPost("/api/profile/update_prefs", { language: clean }).catch(() => {});
    updateMandatoryStep1Gate();
  }

  function updateMandatoryStep1Gate() {
    const hideLangPre = tutorialMandatoryLock && !onboardLanguagePicked;
    document.querySelectorAll("#onboard-lang-grid .lang-choice-card").forEach(card => {
      const code = card.getAttribute("data-lang");
      const isSel = !hideLangPre && code === currentLang;
      card.classList.toggle("selected", isSel);
      const chk = card.querySelector("[data-lang-check]");
      if (chk) {
        chk.classList.toggle("done", isSel);
        chk.textContent = isSel ? "✓" : "";
      }
    });

    const langReq = document.getElementById("tuto-req-lang");
    if (langReq) {
      const done = onboardLanguagePicked || !tutorialMandatoryLock;
      langReq.classList.toggle("done", done);
      langReq.textContent = done ? L("✓ Selected", "✓ Choisi") : L("Required", "Obligatoire");
    }
    const themeReq = document.getElementById("tuto-req-theme");
    if (themeReq) {
      const done = onboardThemePicked || !tutorialMandatoryLock;
      themeReq.classList.toggle("done", done);
      themeReq.textContent = done ? L("✓ Selected", "✓ Choisi") : L("Required", "Obligatoire");
    }

    const canAdvanceStep1 = !tutorialMandatoryLock || (onboardLanguagePicked && onboardThemePicked);
    const hint = document.getElementById("tuto-mandatory-hint");
    if (hint) {
      hint.style.display = (tutorialStep === 0 && !canAdvanceStep1) ? "block" : "none";
      if (!onboardLanguagePicked && !onboardThemePicked) {
        hint.textContent = L(
          "Select both a language and a color theme to unlock Continue.",
          "Sélectionnez une langue et un thème couleur pour déverrouiller Continuer."
        );
      } else if (!onboardLanguagePicked) {
        hint.textContent = L(
          "Please select a display language above to continue.",
          "Veuillez sélectionner une langue d'affichage ci-dessus pour continuer."
        );
      } else if (!onboardThemePicked) {
        hint.textContent = L(
          "Please select a color theme above to continue.",
          "Veuillez sélectionner un thème couleur ci-dessus pour continuer."
        );
      }
    }

    const skipBtn = document.getElementById("btn-tuto-skip");
    if (skipBtn) {
      // Strictly hide Skip on mandatory Step 1; allow skipping optional Steps 2 & 3 once Step 1 is done
      skipBtn.style.display = (tutorialStep === 0 && tutorialMandatoryLock) ? "none" : "inline-flex";
    }

    const nextBtn = document.getElementById("btn-tuto-next");
    if (nextBtn && tutorialStep === 0) {
      nextBtn.disabled = !canAdvanceStep1;
    }
  }

  function openTutorialWizard(startStep, isFirstLaunchMandatory) {
    tutorialMandatoryLock = !!isFirstLaunchMandatory;
    if (tutorialMandatoryLock) {
      tutorialStep = 0;
      onboardLanguagePicked = false;
      onboardThemePicked = false;
    } else {
      tutorialStep = Math.max(0, Math.min(2, Number(startStep || 0)));
      onboardLanguagePicked = true;
      onboardThemePicked = true;
    }
    document.getElementById("onboarding-overlay").classList.add("open");
    document.body.classList.remove("bar-only");
    setBlackHoleSuspended(false);
    sendNativeIpc({ cmd: "set_overlay", open: true });
    renderThemeGalleries();
    syncRamModeUI();
    pickOnboardEngine(onboardEngine);
    renderTutorialStep();
    scanInstalledBrowsersForTutorial();
  }

  function reopenTutorialAtStep(step) {
    openTutorialWizard(step || 0, false);
  }

  function renderTutorialStep() {
    for (let i = 0; i < 3; i++) {
      const pane = document.getElementById("tuto-step-" + i);
      if (pane) pane.classList.toggle("active", i === tutorialStep);
    }
    document.querySelectorAll("#tuto-step-dots .tuto-dot").forEach((dot, idx) => {
      dot.classList.toggle("active", idx === tutorialStep);
      dot.classList.toggle("done", idx < tutorialStep);
    });
    const prevBtn = document.getElementById("btn-tuto-prev");
    const nextBtn = document.getElementById("btn-tuto-next");
    const lbl = document.getElementById("tuto-step-label");
    if (prevBtn) prevBtn.style.visibility = tutorialStep > 0 ? "visible" : "hidden";
    if (lbl) lbl.textContent = L(`Step ${tutorialStep + 1} / 3`, `Étape ${tutorialStep + 1} / 3`);
    if (nextBtn) {
      if (tutorialStep === 0) {
        nextBtn.textContent = L("Continue →", "Continuer →");
      } else if (tutorialStep === 1) {
        nextBtn.textContent = L("Next", "Suivant");
        nextBtn.disabled = false;
      } else {
        nextBtn.textContent = L("Start Browsing", "Commencer à naviguer");
        nextBtn.disabled = false;
      }
    }
    if (tutorialStep === 2) {
      const themeName = themeDisplayName(getActiveThemeConfig());
      const langLabel = currentLang === "fr" ? "Français" : "English";
      const impPart = tutorialImportedTabsCount > 0
        ? L(` · ${tutorialImportedTabsCount} tab(s) imported`, ` · ${tutorialImportedTabsCount} onglet(s) importé(s)`)
        : "";
      const sumEl = document.getElementById("tuto-summary-text");
      if (sumEl) {
        sumEl.textContent = L(
          `Language: ${langLabel} · Theme: ${themeName} · Engine: ${onboardEngine.toUpperCase()}${impPart}`,
          `Langue : ${langLabel} · Thème : ${themeName} · Moteur : ${onboardEngine.toUpperCase()}${impPart}`
        );
      }
    }
    updateMandatoryStep1Gate();
  }

  function tutorialPrevStep() {
    if (tutorialStep > 0) {
      tutorialStep--;
      renderTutorialStep();
    }
  }

  async function tutorialNextStep() {
    if (tutorialStep === 0) {
      if (tutorialMandatoryLock && !(onboardLanguagePicked && onboardThemePicked)) {
        showToast(L("Please select both a language and a color theme first", "Choisissez d'abord une langue et un thème couleur"));
        return;
      }
      await apiPost("/api/profile/update_prefs", {
        language: currentLang,
        theme_id: activeThemeId
      }).catch(() => {});
      tutorialMandatoryLock = false;
      tutorialStep = 1;
      renderTutorialStep();
    } else if (tutorialStep < 2) {
      tutorialStep++;
      renderTutorialStep();
    } else {
      await finishOnboarding();
    }
  }

  async function skipTutorial() {
    if (tutorialMandatoryLock && !(onboardLanguagePicked && onboardThemePicked)) {
      showToast(L("Language and color theme are required before continuing", "La langue et le thème couleur sont obligatoires avant de continuer"));
      return;
    }
    await finishOnboarding();
  }

  async function scanInstalledBrowsersForTutorial() {
    const listEl = document.getElementById("tuto-browsers-list");
    if (!listEl) return;
    listEl.replaceChildren();
    const loading = document.createElement("div");
    loading.style.cssText = "font-size:12px;color:var(--text-muted);padding:14px;text-align:center;";
    loading.textContent = L("Scanning installed browsers on this PC...", "Analyse des navigateurs installés sur ce PC...");
    listEl.appendChild(loading);

    try {
      const res = await apiFetch("/api/import/browsers");
      const d = await res.json();
      detectedImportBrowsers = Array.isArray(d.browsers) ? d.browsers : [];
      selectedImportBrowserIds = new Set();
      const firstWithTabs = detectedImportBrowsers.find(b => b.open_tabs_count > 0);
      if (firstWithTabs) selectedImportBrowserIds.add(firstWithTabs.id);
      renderTutorialBrowsersList();
    } catch (_) {
      listEl.replaceChildren();
      const err = document.createElement("div");
      err.style.cssText = "font-size:12px;color:var(--text-muted);padding:12px;text-align:center;";
      err.textContent = L("Unable to scan local browsers.", "Impossible d'analyser les navigateurs locaux.");
      listEl.appendChild(err);
    }
  }

  function renderTutorialBrowsersList() {
    const listEl = document.getElementById("tuto-browsers-list");
    const importBtn = document.getElementById("btn-tuto-import-now");
    if (!listEl) return;
    listEl.replaceChildren();

    if (!detectedImportBrowsers.length) {
      const empty = document.createElement("div");
      empty.style.cssText = "font-size:12px;color:var(--text-muted);padding:16px;text-align:center;border:1px dashed rgba(255,255,255,0.1);border-radius:10px;";
      empty.textContent = L(
        "No other browser detected on this PC (Chrome, Edge, Opera GX, Opera, Brave, Firefox, Vivaldi, Arc, Zen...).",
        "Aucun autre navigateur détecté sur ce PC (Chrome, Edge, Opera GX, Opera, Brave, Firefox, Vivaldi, Arc, Zen...)."
      );
      listEl.appendChild(empty);
      if (importBtn) {
        importBtn.disabled = true;
        importBtn.textContent = L("No browser detected", "Aucun navigateur détecté");
      }
      return;
    }

    let totalSelTabs = 0;
    for (const b of detectedImportBrowsers) {
      const isSel = selectedImportBrowserIds.has(b.id);
      if (isSel) totalSelTabs += Number(b.open_tabs_count || 0);

      const card = document.createElement("div");
      card.className = "import-browser-card" + (isSel ? " selected" : "");
      card.onclick = () => {
        if (selectedImportBrowserIds.has(b.id)) selectedImportBrowserIds.delete(b.id);
        else selectedImportBrowserIds.add(b.id);
        renderTutorialBrowsersList();
      };

      const left = document.createElement("div");
      left.style.cssText = "display:flex;align-items:center;gap:11px;min-width:0;flex:1;";

      const badge = document.createElement("span");
      badge.className = "import-browser-badge";
      badge.style.background = b.accent || "var(--gold-core)";
      badge.textContent = (b.name || "?").slice(0, 2).toUpperCase();
      left.appendChild(badge);

      const meta = document.createElement("div");
      meta.style.cssText = "min-width:0;flex:1;";
      const nameRow = document.createElement("div");
      nameRow.style.cssText = "font-size:13px;font-weight:600;color:var(--text-primary);display:flex;align-items:center;gap:8px;flex-wrap:wrap;";
      const nm = document.createElement("span");
      nm.textContent = b.name;
      nameRow.appendChild(nm);

      const stats = document.createElement("span");
      stats.style.cssText = "font-size:11px;font-family:var(--font-mono);color:var(--gold-bright);";
      stats.textContent = currentLang === "fr"
        ? `${b.open_tabs_count} onglet${b.open_tabs_count > 1 ? "s" : ""} · ${b.bookmarks_count} favori${b.bookmarks_count > 1 ? "s" : ""}`
        : `${b.open_tabs_count} tab${b.open_tabs_count === 1 ? "" : "s"} · ${b.bookmarks_count} bookmark${b.bookmarks_count === 1 ? "" : "s"}`;
      nameRow.appendChild(stats);
      meta.appendChild(nameRow);

      const preview = document.createElement("div");
      preview.style.cssText = "font-size:11px;color:var(--text-muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin-top:2px;";
      preview.textContent = Array.isArray(b.sample_titles) && b.sample_titles.length > 0
        ? b.sample_titles.join(" · ")
        : (b.open_tabs_count > 0
          ? L("Active session detected", "Session active détectée")
          : L("Installed (no open tabs right now)", "Installé (aucun onglet ouvert actuellement)"));
      meta.appendChild(preview);

      left.appendChild(meta);
      card.appendChild(left);

      const chk = document.createElement("span");
      chk.className = "import-check-box";
      chk.textContent = isSel ? "✓" : "";
      card.appendChild(chk);

      listEl.appendChild(card);
    }

    if (importBtn) {
      importBtn.disabled = selectedImportBrowserIds.size === 0;
      importBtn.textContent = totalSelTabs > 0
        ? L(`Import my tabs (${totalSelTabs})`, `Récupérer mes onglets (${totalSelTabs})`)
        : L("Import selection", "Importer la sélection");
    }
  }

  async function executeTutorialBrowserImport() {
    const ids = Array.from(selectedImportBrowserIds);
    if (!ids.length) {
      showToast(L("Select at least one browser from the list", "Sélectionnez au moins un navigateur dans la liste"));
      return;
    }
    const importBookmarks = !!document.getElementById("tuto-import-bookmarks")?.checked;
    const btn = document.getElementById("btn-tuto-import-now");
    if (btn) { btn.disabled = true; btn.textContent = L("Importing...", "Importation en cours..."); }
    try {
      const res = await apiPost("/api/import/execute", {
        browser_ids: ids,
        import_tabs: true,
        import_bookmarks: importBookmarks
      });
      const d = await res.json();
      if (d.ok) {
        const imported = Array.isArray(d.imported_tabs) ? d.imported_tabs : [];
        if (Array.isArray(d.bookmarks)) {
          currentBookmarks = d.bookmarks;
          renderBookmarksStrip();
        }
        if (imported.length > 0) {
          const existingUrls = new Set(tabs.map(t => t.url));
          const now = Date.now();
          const hadOnlyBlank = tabs.length === 1 && !tabs[0].url;
          if (hadOnlyBlank) tabs = [];
          for (const it of imported) {
            if (!it.url || existingUrls.has(it.url)) continue;
            existingUrls.add(it.url);
            tabs.push({
              id: nextTabId++,
              title: it.title || deriveTitleFromUrl(it.url),
              url: it.url,
              mediaTimeSec: 0,
              scrollY: 0,
              groupId: null,
              faviconUrl: "",
              lastActiveAt: now,
              unloaded: true
            });
          }
          if (tabs.length === 0) {
            tabs.push({ id: nextTabId++, title: L("New Tab", "Nouvel onglet"), url: "", mediaTimeSec: 0, scrollY: 0, groupId: null, faviconUrl: "", lastActiveAt: now, unloaded: false });
          }
          if (hadOnlyBlank && tabs.length > 0) {
            activeTabId = tabs[0].id;
          }
          renderTabs(false);
        }
        tutorialImportedTabsCount += Number(d.imported_tabs_count || 0);
        tutorialImportedBookmarksCount += Number(d.imported_bookmarks_count || 0);

        const resEl = document.getElementById("tuto-import-result");
        if (resEl) {
          resEl.style.display = "block";
          resEl.textContent = L(
            `Imported ${d.imported_tabs_count} tab(s) and ${d.imported_bookmarks_count} bookmark(s) successfully!`,
            `${d.imported_tabs_count} onglet(s) et ${d.imported_bookmarks_count} favori(s) importé(s) avec succès !`
          );
        }
        showToast(L(`${d.imported_tabs_count} tab(s) imported (sleeping in RAM)`, `${d.imported_tabs_count} onglet(s) récupéré(s) en veille RAM`));
        if (tutorialStep === 1) {
          setTimeout(() => {
            if (tutorialStep === 1) {
              tutorialStep = 2;
              renderTutorialStep();
            }
          }, 650);
        }
      }
    } catch (_) {
      showToast(L("Error importing tabs", "Erreur lors de l'import des onglets"));
    } finally {
      renderTutorialBrowsersList();
    }
  }

  async function finishOnboarding() {
    await apiPost("/api/profile/complete_onboarding", {
      language: currentLang,
      engine: onboardEngine,
      theme_id: activeThemeId,
      tab_unload_mode: tabUnloadMode,
      tab_unload_custom_minutes: tabUnloadCustomMinutes
    });
    tutorialMandatoryLock = false;
    document.getElementById("onboarding-overlay").classList.remove("open");
    document.getElementById("search-engine").value = onboardEngine;
    document.getElementById("gen-engine-select").value = onboardEngine;
    sendNativeIpc({ cmd: "set_overlay", open: false });
    syncViewportToActiveTab("activate");
    showToast(L("Welcome to Singularity! Preferences saved", "Bienvenue sur Singularity ! Configuration enregistrée"));
  }

  // Native WebView2 per-tab synchronization callback
  window.__singularitySyncWeb = function(msg) {
    if (!msg) return;
    if (typeof msg.maximized === "boolean") {
      applyMaximizedState(msg.maximized);
    }
    if (typeof msg.fullscreen === "boolean") {
      document.documentElement.classList.toggle("is-fullscreen", msg.fullscreen);
    }
    if (typeof msg.ram_active_count === "number") {
      nativeRamActiveCount = msg.ram_active_count;
      updateRamStatusUI();
    }
    if (msg.shortcut) {
      handleBrowserShortcut(msg.shortcut, msg.shortcut_index || 0);
      return;
    }
    if (msg.ctx_action) {
      executeTabContextAction(
        msg.ctx_action,
        msg.ctx_tab_id || null,
        msg.ctx_group_id || null,
        msg.ctx_target_group_id || null,
        msg.ctx_target_window_id || null
      );
      return;
    }
    if (typeof msg.tab_detached === "number") {
      removeDetachedTabFromList(Number(msg.tab_detached));
      return;
    }
    if (msg.adopt_external_tab) {
      const ext = msg.adopt_external_tab;
      const rawUrl = typeof ext.url === "string" ? ext.url.trim() : "";
      const safeUrl = (/^https?:\/\//i.test(rawUrl) || isInternalSettingsUrl(rawUrl)) ? rawUrl : "";
      const id = nextTabId++;
      tabs.push({
        id,
        title: (ext.title && String(ext.title).trim()) || (safeUrl ? deriveTitleFromUrl(safeUrl) : L("New Tab", "Nouvel onglet")),
        url: safeUrl,
        mediaTimeSec: Math.max(0, Math.floor(Number(ext.media_time_sec || 0))),
        scrollY: Math.max(0, Math.floor(Number(ext.scroll_y || 0))),
        groupId: null,
        faviconUrl: (ext.favicon_url && /^https?:\/\//i.test(ext.favicon_url)) ? ext.favicon_url : "",
        lastActiveAt: Date.now(),
        unloaded: false
      });
      activeTabId = id;
      syncViewportToActiveTab("activate");
      if (!safeUrl) focusSearchForNewTab();
      showToast(L("Tab moved to this window", "Onglet déplacé dans cette fenêtre"));
      return;
    }
    if (msg.ext_ctx_action && msg.ext_ctx_id) {
      executeExtensionContextAction(msg.ext_ctx_action, msg.ext_ctx_id);
      return;
    }
    if (msg.ext_popup_fallback) {
      const extObj = installedExtensions.find(e => e.id === msg.ext_popup_fallback);
      showToast(extObj
        ? L(`${extObj.name} runs in the background (no dedicated popup menu)`, `${extObj.name} fonctionne en arrière-plan (sans menu popup dédié)`)
        : L("This extension runs in the background — opening manager", "Cette extension fonctionne en arrière-plan — ouverture du gestionnaire"));
      openSheet("extensions");
      return;
    }
    // Silent background token encryption sync (never interrupts browsing with a noisy pop-up)
    if (msg.tokens_synced && msg.tokens_synced > 0) {
      refreshHeaderState();
      if (document.getElementById("pane-tokens").style.display === "flex") loadTokensPanel();
    }
    if (msg.tokens_purged) {
      refreshHeaderState();
      loadTokensPanel();
      showToast(L("Session removed from .singularity store", "Session supprimée du coffre .singularity"));
    }
    if (msg.browsing_cleared) {
      refreshHeaderState();
      if (msg.mode === "trackers_only") {
        const tr = Number(msg.trackers_removed || 0);
        const ad = Number(msg.ads_removed || 0);
        const mal = Number(msg.malicious_removed || 0);
        const total = tr + ad + mal;
        showToast(total > 0
          ? L(
              `${total} unwanted cookie(s) purged (${tr} tracker, ${ad} ad, ${mal} malicious) — sessions kept`,
              `${total} cookie(s) nuisible(s) supprimé(s) (${tr} traqueur, ${ad} pub, ${mal} malveillant) — sessions intactes`
            )
          : L(
              "No trackers, ad cookies, or malicious cookies found — all sessions intact",
              "Aucun tracker, cookie pub ou malveillant détecté — toutes vos sessions sont intactes"
            ));
      } else {
        showToast(L("Full reset completed", "Réinitialisation complète effectuée"));
      }
    }
    if (msg.download_started && msg.download_started.filename) {
      const fn = String(msg.download_started.filename);
      showToast(L(`Downloading ${fn}...`, `Téléchargement de ${fn}...`), null, 3400);
      return;
    }
    if (msg.download_completed && msg.download_completed.filename) {
      const fn = String(msg.download_completed.filename);
      const dlPath = String(msg.download_completed.path || "");
      if (msg.download_completed.success) {
        showToast(
          L(`Downloaded ${fn} — click to open folder`, `${fn} téléchargé — cliquer pour ouvrir le dossier`),
          dlPath ? () => sendNativeIpc({ cmd: "reveal_download", path: dlPath }) : null,
          6500
        );
      } else {
        showToast(L(`Download failed: ${fn}`, `Échec du téléchargement : ${fn}`), null, 4500);
      }
      return;
    }
    if (msg.new_tab_url && /^https?:\/\//i.test(msg.new_tab_url)) {
      if (msg.new_tab_background) {
        openBackgroundLazyTab(msg.new_tab_url, msg.new_tab_title || "");
      } else {
        createNewTab(msg.new_tab_url, msg.new_tab_title || "");
      }
      return;
    }

    const targetTab = typeof msg.tab_id === "number"
      ? tabs.find(t => t.id === msg.tab_id)
      : getActiveTab();
    if (!targetTab) return;

    let pillDirty = false;
    if (typeof msg.unloaded === "boolean" && targetTab.unloaded !== msg.unloaded) {
      targetTab.unloaded = msg.unloaded;
      pillDirty = true;
    }
    if (msg.favicon_url && /^https?:\/\//i.test(msg.favicon_url) && targetTab.url) {
      if (targetTab.faviconUrl !== msg.favicon_url) {
        targetTab.faviconUrl = msg.favicon_url;
        pillDirty = true;
        persistOpenTabsIfEnabled(true);
      }
    }
    if (msg.url && /^https?:\/\//i.test(msg.url) && targetTab.url) {
      if (targetTab.url !== msg.url) {
        let hostChanged = false;
        try {
          hostChanged = new URL(targetTab.url).hostname !== new URL(msg.url).hostname;
        } catch (_) {}
        if (normalizeUrlNoTime(targetTab.url) !== normalizeUrlNoTime(msg.url)) {
          targetTab.mediaTimeSec = 0;
          targetTab.scrollY = 0;
        }
        if (hostChanged) {
          targetTab.faviconUrl = "";
          pillDirty = true;
        }
        targetTab.url = msg.url;
        persistOpenTabsIfEnabled(false);
      }
      if (targetTab.id === activeTabId) {
        const omni = document.getElementById("omnibar-input");
        if (document.activeElement !== omni) omni.value = msg.url;
        updateBookmarkStarState();
      }
    }
    let mediaChanged = false;
    if (typeof msg.media_time_sec === "number" && msg.media_time_sec >= 2) {
      const sec = Math.floor(msg.media_time_sec);
      if (targetTab.mediaTimeSec !== sec) {
        targetTab.mediaTimeSec = sec;
        mediaChanged = true;
      }
    }
    if (typeof msg.scroll_y === "number" && msg.scroll_y > 0) {
      const sy = Math.floor(msg.scroll_y);
      if (targetTab.scrollY !== sy) {
        targetTab.scrollY = sy;
        mediaChanged = true;
      }
    }
    if (mediaChanged) {
      persistOpenTabsIfEnabled(true);
    }
    if (msg.title && msg.title.trim() && targetTab.url) {
      if (targetTab.title !== msg.title.trim()) {
        targetTab.title = msg.title.trim();
        pillDirty = true;
        persistOpenTabsIfEnabled(false);
      }
    }
    if (pillDirty) {
      // O(1) single-pill DOM sync instead of re-rendering the entire tab strip
      updateSingleTabPill(targetTab);
    }
  };

  function toggleNativeFullscreen() {
    if (hasNativeIpc()) {
      sendNativeIpc({ cmd: "toggle_fullscreen" });
    } else if (document.fullscreenElement) {
      document.exitFullscreen && document.exitFullscreen().catch(() => {});
    } else if (document.documentElement && document.documentElement.requestFullscreen) {
      document.documentElement.requestFullscreen().catch(() => {});
    }
  }

  window.addEventListener("keydown", (e) => {
    if (tutorialMandatoryLock && anyModalOpen()) {
      if (e.key === "Escape") {
        e.preventDefault();
        e.stopPropagation();
      }
      return;
    }
    const ctrl = (e.ctrlKey || e.metaKey) && !e.altKey;
    const alt = e.altKey && !e.ctrlKey && !e.metaKey;
    const k = String(e.key || "").toLowerCase();
    const code = String(e.code || "");

    if (!e.ctrlKey && !e.altKey && !e.metaKey && !e.shiftKey && (code === "F11" || e.key === "F11")) {
      e.preventDefault();
      handleBrowserShortcut("toggle_fullscreen", 0);
    } else if (ctrl && e.shiftKey && (k === "t" || code === "KeyT")) {
      e.preventDefault();
      handleBrowserShortcut("reopen_closed_tab", 0);
    } else if (ctrl && !e.shiftKey && (k === "t" || code === "KeyT")) {
      e.preventDefault();
      handleBrowserShortcut("new_tab", 0);
    } else if (ctrl && !e.shiftKey && (k === "n" || code === "KeyN")) {
      e.preventDefault();
      handleBrowserShortcut("new_window", 0);
    } else if (ctrl && !e.shiftKey && (k === "w" || code === "KeyW" || code === "F4")) {
      e.preventDefault();
      handleBrowserShortcut("close_active_tab", 0);
    } else if (ctrl && e.shiftKey && (k === "tab" || code === "Tab")) {
      e.preventDefault();
      handleBrowserShortcut("prev_tab", 0);
    } else if (ctrl && !e.shiftKey && (k === "tab" || code === "Tab" || code === "PageDown")) {
      e.preventDefault();
      handleBrowserShortcut("next_tab", 0);
    } else if (ctrl && !e.shiftKey && code === "PageUp") {
      e.preventDefault();
      handleBrowserShortcut("prev_tab", 0);
    } else if ((ctrl && !e.shiftKey && (k === "l" || code === "KeyL")) || (alt && !e.shiftKey && (k === "d" || code === "KeyD")) || (!e.ctrlKey && !e.altKey && !e.metaKey && !e.shiftKey && code === "F6")) {
      e.preventDefault();
      handleBrowserShortcut("focus_omnibar", 0);
    } else if ((ctrl && !e.shiftKey && (k === "r" || code === "KeyR")) || (!e.ctrlKey && !e.altKey && !e.metaKey && !e.shiftKey && code === "F5")) {
      e.preventDefault();
      handleBrowserShortcut("reload_tab", 0);
    } else if (ctrl && !e.shiftKey && (k === "d" || code === "KeyD")) {
      e.preventDefault();
      handleBrowserShortcut("toggle_bookmark", 0);
    } else if (ctrl && !e.shiftKey && (k === "h" || code === "KeyH")) {
      e.preventDefault();
      handleBrowserShortcut("open_history", 0);
    } else if (ctrl && !e.shiftKey && (k === "," || code === "Comma")) {
      e.preventDefault();
      handleBrowserShortcut("open_settings", 0);
    } else if (ctrl && e.shiftKey && (k === "n" || code === "KeyN")) {
      e.preventDefault();
      handleBrowserShortcut("toggle_private", 0);
    } else if (ctrl && !e.shiftKey && /^[1-9]$/.test(k)) {
      e.preventDefault();
      handleBrowserShortcut("jump_tab", parseInt(k, 10));
    } else if (ctrl && !e.shiftKey && /^Digit[1-9]$/.test(code)) {
      e.preventDefault();
      handleBrowserShortcut("jump_tab", parseInt(code.slice(5), 10));
    } else if (alt && !e.shiftKey && e.key === "ArrowLeft") {
      e.preventDefault();
      handleBrowserShortcut("web_back", 0);
    } else if (alt && !e.shiftKey && e.key === "ArrowRight") {
      e.preventDefault();
      handleBrowserShortcut("web_forward", 0);
    } else if (
      !e.ctrlKey && !e.altKey && !e.metaKey && !e.shiftKey && !e.repeat
      && (code === "Space" || e.key === " ")
      && document.body.classList.contains("bar-only")
      && !anyModalOpen()
      && hasNativeIpc()
    ) {
      const ae = document.activeElement;
      const tag = ae && ae.tagName ? ae.tagName.toUpperCase() : "";
      const isEditing = !!(ae && (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || tag === "BUTTON" || ae.isContentEditable));
      if (!isEditing) {
        e.preventDefault();
        sendNativeIpc({ cmd: "focus_active_web", toggle_media_play: true });
      }
    } else if (e.key === "Escape") {
      closeHtmlTabContextMenu();
      closeGroupEditor();
      closeSheet();
    }
  }, true);

  /* ============================================================================
   * CHROME EXTENSIONS TOOLBAR & MANAGER UI
   * ============================================================================ */
  function openExtensionPopupUI(ext, anchorEl, openOptions) {
    if (!ext || !ext.id) return;
    if (!hasNativeIpc()) {
      openSheet("extensions");
      return;
    }
    if (!ext.popup_path && !ext.options_path) {
      showToast(L(
        `${ext.name || ext.id} runs in the background (no dedicated popup menu)`,
        `${ext.name || ext.id} fonctionne en arrière-plan (sans menu popup dédié)`
      ));
      openSheet("extensions");
      return;
    }
    let anchorX = null;
    if (anchorEl && typeof anchorEl.getBoundingClientRect === "function") {
      const r = anchorEl.getBoundingClientRect();
      if (r && isFinite(r.right) && r.right > 0) anchorX = r.right;
    }
    sendNativeIpc({
      cmd: "toggle_extension_popup",
      ext_id: ext.id,
      anchor_x: anchorX,
      open_options: !!openOptions
    });
  }

  function executeExtensionContextAction(action, extId) {
    const ext = installedExtensions.find(e => e.id === extId);
    const btn = document.querySelector(`.ext-pin-btn[data-ext-id="${CSS.escape ? CSS.escape(extId) : extId}"]`);
    if (action === "open_popup") {
      if (ext) openExtensionPopupUI(ext, btn, false);
    } else if (action === "open_options") {
      if (ext) openExtensionPopupUI(ext, btn, true);
    } else if (action === "unpin_ext") {
      toggleExtensionPinnedUI(extId, false);
    } else if (action === "disable_ext") {
      toggleExtensionEnabledUI(extId, false);
    } else if (action === "manage_ext") {
      openSheet("extensions");
    }
  }

  function renderExtensionsToolbar(list) {
    installedExtensions = Array.isArray(list) ? list : [];
    const strip = document.getElementById("ext-toolbar-strip");
    const badge = document.getElementById("ext-count-badge");
    const activeExts = installedExtensions.filter(e => e.enabled);
    if (badge) {
      if (activeExts.length > 0) {
        badge.style.display = "inline-flex";
        badge.textContent = String(activeExts.length);
      } else {
        badge.style.display = "none";
      }
    }
    if (!strip) return;
    strip.replaceChildren();
    for (const ext of activeExts.filter(e => e.pinned)) {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "ext-pin-btn";
      btn.dataset.extId = ext.id;
      const hasMenu = !!(ext.popup_path || ext.options_path);
      btn.title = hasMenu
        ? L(
            `${ext.name} v${ext.version} — Left-click: menu · Right-click: options`,
            `${ext.name} v${ext.version} — Clic gauche : menu · Clic droit : options`
          )
        : L(
            `${ext.name} v${ext.version} (Active in background — Right-click: options)`,
            `${ext.name} v${ext.version} (Active en arrière-plan — Clic droit : options)`
          );
      if (ext.has_icon) {
        const img = document.createElement("img");
        img.src = "/api/extensions/icon?id=" + encodeURIComponent(ext.id);
        img.alt = ext.name;
        btn.appendChild(img);
      } else {
        const fb = document.createElement("span");
        fb.className = "ext-pin-fallback";
        fb.textContent = (ext.name || "E").slice(0, 1).toUpperCase();
        btn.appendChild(fb);
      }
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        openExtensionPopupUI(ext, btn, false);
      });
      btn.addEventListener("contextmenu", (e) => {
        e.preventDefault();
        e.stopPropagation();
        if (hasNativeIpc()) {
          sendNativeIpc({
            cmd: "show_extension_context_menu",
            ext_id: ext.id,
            has_popup: !!ext.popup_path,
            has_options: !!ext.options_path,
            lang: currentLang
          });
        } else {
          openSheet("extensions");
        }
      });
      strip.appendChild(btn);
    }
  }

  async function loadExtensionsPanel() {
    try {
      const res = await apiFetch("/api/extensions/list");
      const d = await res.json();
      const dirEl = document.getElementById("ext-dir-path");
      if (dirEl) dirEl.textContent = d.extensions_dir || "";
      renderExtensionsToolbar(d.installed || []);

      const instBox = document.getElementById("ext-installed-list");
      instBox.replaceChildren();
      const installed = d.installed || [];
      if (installed.length === 0) {
        const empty = document.createElement("div");
        empty.style.cssText = "font-size:12px;color:var(--text-muted);";
        empty.textContent = L(
          "No Chrome extensions installed yet. Install one from the Chrome Web Store or import your Chrome/Brave/Edge extensions below.",
          "Aucune extension Chrome installée pour le moment. Installez-en une depuis le Chrome Web Store ou importez vos extensions Chrome/Brave/Edge ci-dessous."
        );
        instBox.appendChild(empty);
      } else {
        for (const ext of installed) {
          const row = document.createElement("div");
          row.className = "token-row";

          const left = document.createElement("div");
          left.style.cssText = "display:flex;align-items:center;gap:10px;min-width:0;flex:1;";

          const ico = document.createElement("div");
          ico.className = "ext-icon-lg";
          if (ext.has_icon) {
            const img = document.createElement("img");
            img.src = "/api/extensions/icon?id=" + encodeURIComponent(ext.id);
            img.alt = ext.name;
            ico.appendChild(img);
          } else {
            ico.textContent = (ext.name || "E").slice(0, 1).toUpperCase();
          }
          left.appendChild(ico);

          const meta = document.createElement("div");
          meta.style.minWidth = "0";
          const titleLine = document.createElement("div");
          titleLine.style.cssText = "display:flex;align-items:center;gap:7px;flex-wrap:wrap;";
          const nm = document.createElement("span");
          nm.style.fontWeight = "600";
          nm.textContent = ext.name || ext.id;
          const ver = document.createElement("span");
          ver.className = "prov-badge";
          ver.textContent = `v${ext.version} · MV${ext.manifest_version || 3}`;
          titleLine.appendChild(nm);
          titleLine.appendChild(ver);

          const desc = document.createElement("div");
          desc.style.cssText = "font-size:11px;color:var(--text-muted);margin-top:2px;";
          desc.textContent = ext.description || ext.id;
          meta.appendChild(titleLine);
          meta.appendChild(desc);
          left.appendChild(meta);

          const acts = document.createElement("div");
          acts.style.cssText = "display:flex;align-items:center;gap:6px;flex-wrap:wrap;";

          if (ext.enabled && (ext.popup_path || ext.options_path)) {
            const openBtn = document.createElement("button");
            openBtn.type = "button";
            openBtn.className = "btn-subtle";
            openBtn.style.height = "26px";
            openBtn.textContent = ext.popup_path ? "Menu" : "Options";
            openBtn.addEventListener("click", () => openExtensionPopupUI(ext, openBtn, !ext.popup_path));
            acts.appendChild(openBtn);
          }
          if (ext.enabled && ext.popup_path && ext.options_path) {
            const optBtn = document.createElement("button");
            optBtn.type = "button";
            optBtn.className = "btn-subtle";
            optBtn.style.height = "26px";
            optBtn.textContent = "Options";
            optBtn.addEventListener("click", () => openExtensionPopupUI(ext, optBtn, true));
            acts.appendChild(optBtn);
          }

          const pinBtn = document.createElement("button");
          pinBtn.type = "button";
          pinBtn.className = "toggle-pill" + (ext.pinned ? " on" : "");
          pinBtn.textContent = ext.pinned ? L("Pinned", "Épinglée") : L("Pin", "Épingler");
          pinBtn.addEventListener("click", () => toggleExtensionPinnedUI(ext.id, !ext.pinned));
          acts.appendChild(pinBtn);

          const togBtn = document.createElement("button");
          togBtn.type = "button";
          togBtn.className = "toggle-pill" + (ext.enabled ? " on" : "");
          togBtn.textContent = ext.enabled ? "ON" : "OFF";
          togBtn.addEventListener("click", () => toggleExtensionEnabledUI(ext.id, !ext.enabled));
          acts.appendChild(togBtn);

          const delBtn = document.createElement("button");
          delBtn.type = "button";
          delBtn.className = "btn-subtle btn-danger";
          delBtn.style.height = "26px";
          delBtn.textContent = L("Remove", "Supprimer");
          delBtn.addEventListener("click", () => removeExtensionUI(ext.id));
          acts.appendChild(delBtn);

          row.appendChild(left);
          row.appendChild(acts);
          instBox.appendChild(row);
        }
      }

      const installedIds = new Set(installed.map(e => e.id));
      const catBox = document.getElementById("ext-catalog-list");
      catBox.replaceChildren();
      for (const c of (d.catalog || [])) {
        const row = document.createElement("div");
        row.className = "token-row";
        const info = document.createElement("div");
        info.style.cssText = "display:flex;flex-direction:column;gap:2px;flex:1;min-width:200px;";
        const top = document.createElement("div");
        top.style.cssText = "display:flex;align-items:center;gap:8px;flex-wrap:wrap;";
        const nm = document.createElement("span");
        nm.style.fontWeight = "600";
        nm.textContent = c.name;
        const badge = document.createElement("span");
        badge.className = "prov-badge";
        badge.textContent = c.category;
        top.appendChild(nm);
        top.appendChild(badge);
        const desc = document.createElement("div");
        desc.style.cssText = "font-size:11px;color:var(--text-muted);";
        desc.textContent = c.description;
        info.appendChild(top);
        info.appendChild(desc);

        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = installedIds.has(c.id) ? "btn-subtle" : "btn-gold";
        btn.style.cssText = "height:28px;padding:0 12px;";
        btn.textContent = installedIds.has(c.id) ? L("Reinstall", "Réinstaller") : L("Install", "Installer");
        btn.addEventListener("click", () => installExtensionByIdUI(c.id, c.name, btn));
        row.appendChild(info);
        row.appendChild(btn);
        catBox.appendChild(row);
      }

      const detCard = document.getElementById("ext-detected-card");
      const detList = document.getElementById("ext-detected-list");
      const detected = (d.detected_browsers || []).filter(x => !installedIds.has(x.id));
      detList.replaceChildren();
      if (detected.length > 0) {
        detCard.style.display = "flex";
        for (const ext of detected) {
          const row = document.createElement("div");
          row.className = "token-row";
          const info = document.createElement("div");
          info.style.cssText = "display:flex;flex-direction:column;gap:2px;flex:1;";
          const top = document.createElement("div");
          top.style.cssText = "display:flex;align-items:center;gap:8px;flex-wrap:wrap;";
          const nm = document.createElement("span");
          nm.style.fontWeight = "600";
          nm.textContent = ext.name;
          const b = document.createElement("span");
          b.className = "prov-badge";
          b.textContent = `${ext.browser} · v${ext.version}`;
          top.appendChild(nm);
          top.appendChild(b);
          const desc = document.createElement("div");
          desc.style.cssText = "font-size:11px;color:var(--text-muted);";
          desc.textContent = ext.description || ext.id;
          info.appendChild(top);
          info.appendChild(desc);

          const btn = document.createElement("button");
          btn.type = "button";
          btn.className = "btn-subtle";
          btn.style.height = "28px";
          btn.textContent = L("Import", "Importer");
          btn.addEventListener("click", async () => {
            btn.disabled = true;
            btn.textContent = L("Importing...", "Import...");
            const r = await apiPost("/api/extensions/install_local", { path: ext.source_dir, id: ext.id });
            const out = await r.json();
            if (out.ok) {
              sendNativeIpc({ cmd: "reload_extensions" });
              showToast(L(`Extension "${ext.name}" imported and enabled`, `Extension « ${ext.name} » importée et activée`));
              await loadExtensionsPanel();
            } else {
              btn.disabled = false;
              btn.textContent = L("Import", "Importer");
              showToast(out.error || L("Import failed", "Erreur d'importation"));
            }
          });
          row.appendChild(info);
          row.appendChild(btn);
          detList.appendChild(row);
        }
      } else {
        detCard.style.display = "none";
      }
    } catch (_) {}
  }

  async function installExtensionByIdUI(id, label, btn) {
    if (btn) { btn.disabled = true; btn.textContent = L("Downloading...", "Téléchargement..."); }
    showToast(L(`Downloading ${label || id} from Chrome Web Store...`, `Téléchargement de ${label || id} depuis le Chrome Web Store...`));
    try {
      const res = await apiPost("/api/extensions/install_store", { input: id });
      const d = await res.json();
      if (d.ok) {
        sendNativeIpc({ cmd: "reload_extensions" });
        showToast(L(`Extension "${d.extension.name}" installed and enabled`, `Extension « ${d.extension.name} » installée et activée`));
        await loadExtensionsPanel();
      } else {
        showToast(d.error || L("Installation failed", "Échec d'installation"));
        if (btn) { btn.disabled = false; btn.textContent = L("Install", "Installer"); }
      }
    } catch (_) {
      showToast(L("Network error while downloading", "Erreur réseau lors du téléchargement"));
      if (btn) { btn.disabled = false; btn.textContent = L("Install", "Installer"); }
    }
  }

  async function installExtensionFromStoreUI() {
    const inp = document.getElementById("ext-store-input");
    const val = (inp.value || "").trim();
    if (!val) { showToast(L("Paste a Chrome Web Store URL or 32-letter ID", "Collez une URL Chrome Web Store ou un ID à 32 lettres")); return; }
    const btn = document.getElementById("btn-ext-install-store");
    await installExtensionByIdUI(val, val, btn);
    inp.value = "";
    if (btn) { btn.disabled = false; btn.textContent = L("Install", "Installer"); }
  }

  async function installExtensionFromLocalUI() {
    const inp = document.getElementById("ext-local-input");
    const val = (inp.value || "").trim();
    if (!val) { showToast(L("Enter a local folder or .crx/.zip file path", "Saisissez le chemin d'un dossier ou fichier .crx/.zip")); return; }
    const res = await apiPost("/api/extensions/install_local", { path: val });
    const d = await res.json();
    if (d.ok) {
      inp.value = "";
      sendNativeIpc({ cmd: "reload_extensions" });
      showToast(L(`Extension "${d.extension.name}" loaded`, `Extension « ${d.extension.name} » chargée`));
      await loadExtensionsPanel();
    } else {
      showToast(d.error || L("Local load failed", "Erreur de chargement local"));
    }
  }

  async function toggleExtensionEnabledUI(id, enabled) {
    const res = await apiPost("/api/extensions/toggle", { id, enabled });
    const d = await res.json();
    if (d.ok) {
      sendNativeIpc({ cmd: "reload_extensions" });
      showToast(enabled
        ? L("Extension enabled", "Extension activée")
        : L("Extension disabled (effective on next restart)", "Extension désactivée (effectif au prochain redémarrage)"));
      await loadExtensionsPanel();
    } else {
      showToast(d.error || L("Error", "Erreur"));
    }
  }

  async function toggleExtensionPinnedUI(id, pinned) {
    const res = await apiPost("/api/extensions/pin", { id, pinned });
    const d = await res.json();
    if (d.ok) {
      renderExtensionsToolbar(d.installed || []);
      await loadExtensionsPanel();
    }
  }

  async function removeExtensionUI(id) {
    const res = await apiPost("/api/extensions/remove", { id });
    const d = await res.json();
    if (d.ok) {
      renderExtensionsToolbar(d.installed || []);
      showToast(L("Extension removed", "Extension supprimée"));
      await loadExtensionsPanel();
    } else {
      showToast(d.error || L("Failed to remove extension", "Erreur de suppression"));
    }
  }

  /* ============================================================================
   * UNIFIED CONTROL SHEET LOGIC
   * ============================================================================ */
  function stopVaultTotpTicker() {
    if (vaultTotpTimer) {
      clearInterval(vaultTotpTimer);
      vaultTotpTimer = null;
    }
  }

  async function openSheet(tabName) {
    const sec = tabName || "general";
    const targetUrl = internalUrlForSection(sec);
    const targetTitle = tabTitleForSection(sec);

    // Reuse an already-open Settings tab if one exists; otherwise open a fresh tab
    // (or turn the current blank New Tab into the Settings tab, just like Brave/Chrome).
    let settingsTab = tabs.find(t => isInternalSettingsUrl(t.url));
    if (settingsTab) {
      const prev = getActiveTab();
      if (prev && prev.id !== settingsTab.id) prev.lastActiveAt = Date.now();
      settingsTab.url = targetUrl;
      settingsTab.title = targetTitle;
      settingsTab.unloaded = false;
      activeTabId = settingsTab.id;
    } else {
      const cur = getActiveTab();
      if (cur && !cur.url) {
        cur.url = targetUrl;
        cur.title = targetTitle;
        cur.unloaded = false;
        activeTabId = cur.id;
      } else {
        if (cur) cur.lastActiveAt = Date.now();
        const id = nextTabId++;
        tabs.push({
          id,
          title: targetTitle,
          url: targetUrl,
          mediaTimeSec: 0,
          scrollY: 0,
          lastActiveAt: Date.now(),
          unloaded: false
        });
        activeTabId = id;
      }
    }
    syncViewportToActiveTab("activate");
  }

  function closeSheet() {
    if (document.getElementById("onboarding-overlay").classList.contains("open")) {
      return;
    }
    const tab = getActiveTab();
    if (tab && isInternalSettingsUrl(tab.url)) {
      closeTab(tab.id);
    }
  }

  let currentSettingsSection = "general";
  function getSettingsSectionHeading(sec) {
    const map = {
      general: L("General & Startup", "Général & Démarrage"),
      appearance: L("Appearance & 3D Cosmic Themes", "Apparence & Thèmes Cosmiques 3D"),
      extensions: L("Chrome Extensions", "Extensions Chrome"),
      tokens: L("Accounts & .singularity Store", "Comptes & Coffre .singularity"),
      bookmarks: L("Bookmarks & History", "Favoris & Historique"),
      vault: L("Zero-Knowledge Vault & 2FA", "Coffre-fort Zero-Knowledge & 2FA"),
      mullvad: L("Network Shield & WireGuard", "Bouclier Réseau & WireGuard"),
      settings: L("Singularity Engine (2,165+ settings)", "Moteur Singularity (2 165+ réglages)")
    };
    return map[sec] || L("Settings", "Paramètres");
  }

  async function onSettingsGlobalSearch(q) {
    if (q && q.trim() && currentSettingsSection !== "settings") {
      await switchSheetTab("settings", false);
    }
    await querySettings(true);
  }

  async function switchSheetTab(tab, fromSync) {
    const sec = tab || "general";
    currentSettingsSection = sec;
    stopVaultTotpTicker();

    const allTabs = ["general", "appearance", "extensions", "tokens", "bookmarks", "vault", "mullvad", "settings"];
    allTabs.forEach(k => {
      const btn = document.getElementById("stab-" + k);
      const pane = document.getElementById("pane-" + k);
      if (btn) btn.classList.toggle("active", k === sec);
      if (pane) pane.style.display = k === sec ? "flex" : "none";
    });

    const headingEl = document.getElementById("settings-page-heading");
    if (headingEl) {
      headingEl.textContent = getSettingsSectionHeading(sec);
    }

    // Keep the active settings tab URL & title synchronized with the chosen sidebar section
    if (!fromSync) {
      const active = getActiveTab();
      if (active && isInternalSettingsUrl(active.url)) {
        active.url = internalUrlForSection(sec);
        active.title = tabTitleForSection(sec);
        const omni = document.getElementById("omnibar-input");
        if (omni && document.activeElement !== omni) omni.value = active.url;
        renderTabs(false);
      }
    }

    if (sec === "general") await refreshHeaderState();
    else if (sec === "appearance") renderThemeGalleries();
    else if (sec === "extensions") await loadExtensionsPanel();
    else if (sec === "tokens") await loadTokensPanel();
    else if (sec === "bookmarks") await loadBookmarksAndHistoryPanel();
    else if (sec === "vault") await loadVaultPanel();
    else if (sec === "mullvad") await loadMullvadPanel();
    else if (sec === "settings") { await loadCategories(); await querySettings(true); }
  }

  /* --- TAB 1: GENERAL & UPDATES --- */
  async function checkUpdatesUI() {
    const box = document.getElementById("update-check-banner");
    box.style.display = "flex";
    box.textContent = L("Checking GitHub Releases...", "Vérification auprès de GitHub Releases...");
    try {
      const res = await apiFetch("/api/updater/check");
      const d = await res.json();
      box.replaceChildren();
      if (d.error) {
        box.textContent = d.error;
      } else if (d.update_available) {
        const sp = document.createElement("span");
        sp.style.color = "var(--gold-bright)";
        sp.textContent = L(
          `New version available: v${d.latest_version} (current: v${d.current_version})`,
          `Nouvelle version disponible : v${d.latest_version} (actuelle : v${d.current_version})`
        );
        box.appendChild(sp);
      } else {
        const sp = document.createElement("span");
        sp.style.color = "var(--status-ok)";
        sp.textContent = L(
          `Singularity is up to date (v${d.current_version}).`,
          `Singularity est à jour (v${d.current_version}).`
        );
        box.appendChild(sp);
      }
    } catch (_) {
      box.textContent = L("Unable to check for updates.", "Impossible de vérifier les mises à jour.");
    }
  }

  async function triggerUpdate() {
    showToast(L("Downloading, verifying SHA-256, and installing...", "Téléchargement, vérification SHA-256 et installation..."));
    try {
      const res = await apiPost("/api/updater/run", {});
      const data = await res.json();
      if (data.status !== "ok") showToast(data.error || L("Update error", "Erreur de mise à jour"));
    } catch (_) {}
  }

  async function clearBrowsingDataUI(clearTokens) {
    if (clearTokens) {
      if (!window.confirm(L(
        "Sign out of all accounts and remove all saved sessions?",
        "Déconnecter tous vos comptes et supprimer toutes les sessions enregistrées ?"
      ))) {
        return;
      }
    }
    if (!sendNativeIpc({ cmd: "clear_browsing_data", clear_tokens: clearTokens })) {
      if (clearTokens) {
        await apiPost("/api/history/clear", {});
        await apiPost("/api/tokens/clear_all", {});
      }
      await refreshHeaderState();
      showToast(clearTokens
        ? L("History and encrypted sessions cleared", "Historique et sessions chiffrées effacés")
        : L("Trackers, ad cookies, and malicious cookies purged (sessions kept)", "Nettoyage trackers/pubs/malveillants terminé (sessions conservées)"));
    }
  }

  /* --- TAB 2: ENCRYPTED ROAMING\.SINGULARITY TOKENS --- */
  function connectProviderLogin(url, title) {
    createNewTab(url, title);
    showToast(L("Sign in: your session tokens will be encrypted automatically in .singularity", "Connectez-vous : vos tokens seront chiffrés automatiquement dans .singularity"));
  }

  function forceSyncTokens() {
    if (!sendNativeIpc({ cmd: "sync_tokens" })) {
      loadTokensPanel();
      showToast(L("Sync completed", "Synchronisation terminée"));
    }
  }

  async function loadTokensPanel() {
    try {
      const res = await apiFetch("/api/tokens/list");
      const d = await res.json();
      document.getElementById("tok-file-path").textContent = d.roaming_tokens_file || "";
      document.getElementById("tok-cipher-label").textContent = L("Active cipher: ", "Chiffrement actif : ") + (d.cipher || "");
      const list = document.getElementById("tok-list");
      list.replaceChildren();
      if (!d.items || d.items.length === 0) {
        const empty = document.createElement("div");
        empty.style.fontSize = "12px";
        empty.style.color = "var(--text-muted)";
        empty.textContent = L(
          "No saved sessions yet. Sign in to Google, Microsoft, GitHub, or Discord to automatically encrypt your session tokens.",
          "Aucune session enregistrée pour le moment. Connectez-vous à Google, Microsoft, GitHub ou Discord pour chiffrer automatiquement vos tokens de session."
        );
        list.appendChild(empty);
        return;
      }
      for (const it of d.items) {
        const row = document.createElement("div");
        row.className = "token-row";

        const meta = document.createElement("div");
        meta.style.cssText = "display:flex;align-items:center;gap:10px;flex-wrap:wrap;";

        const badge = document.createElement("span");
        badge.className = "prov-badge";
        badge.textContent = it.provider || "";
        meta.appendChild(badge);

        const nameEl = document.createElement("span");
        nameEl.style.fontWeight = "500";
        nameEl.textContent = it.token_name || "";
        meta.appendChild(nameEl);

        const domEl = document.createElement("span");
        domEl.style.cssText = "font-size:11px;color:var(--text-muted);";
        domEl.textContent = it.domain || "";
        meta.appendChild(domEl);

        const maskEl = document.createElement("span");
        maskEl.className = "mono-val";
        maskEl.style.fontSize = "11px";
        maskEl.textContent = it.masked_preview || "";
        meta.appendChild(maskEl);

        const delBtn = document.createElement("button");
        delBtn.type = "button";
        delBtn.className = "btn-subtle btn-danger";
        delBtn.style.height = "26px";
        delBtn.textContent = L("Remove", "Supprimer");
        delBtn.addEventListener("click", () => purgeTokenItem(it.id));

        row.appendChild(meta);
        row.appendChild(delBtn);
        list.appendChild(row);
      }
    } catch (_) {}
  }

  async function addManualEncryptedToken() {
    const prov = document.getElementById("manual-tok-provider").value;
    const dom = document.getElementById("manual-tok-domain").value || "local.oauth";
    const name = document.getElementById("manual-tok-name").value || "oauth_token";
    const sec = document.getElementById("manual-tok-secret").value || "";
    if (!sec.trim()) { showToast(L("Enter a token to encrypt", "Saisissez un token à chiffrer")); return; }
    const res = await apiPost("/api/tokens/add_manual", {
      provider: prov,
      domain: dom,
      name: name,
      secret: sec
    });
    const d = await res.json();
    if (d.error) { showToast(d.error); return; }
    document.getElementById("manual-tok-secret").value = "";
    await loadTokensPanel();
    await refreshHeaderState();
    showToast(L("Token encrypted in .singularity/tokens.enc", "Token chiffré dans .singularity/tokens.enc"));
  }

  async function purgeTokenItem(targetId) {
    if (!sendNativeIpc({ cmd: "purge_provider_tokens", target: targetId })) {
      await apiPost("/api/tokens/delete", { target: targetId });
      await loadTokensPanel();
      await refreshHeaderState();
    }
  }

  /* --- TAB 3: BOOKMARKS & HISTORY --- */
  async function loadBookmarksAndHistoryPanel() {
    const bmBox = document.getElementById("bm-sheet-list");
    bmBox.replaceChildren();
    for (const b of currentBookmarks) {
      const row = document.createElement("div");
      row.className = "token-row";

      const linkArea = document.createElement("div");
      linkArea.style.cssText = "display:flex;align-items:center;gap:10px;cursor:pointer;";
      linkArea.addEventListener("click", () => {
        createNewTab(b.url, b.title);
      });

      const titleEl = document.createElement("span");
      titleEl.style.fontWeight = "500";
      titleEl.textContent = b.title || b.url;
      linkArea.appendChild(titleEl);

      const urlEl = document.createElement("span");
      urlEl.className = "mono-val";
      urlEl.style.fontSize = "11px";
      urlEl.textContent = b.url || "";
      linkArea.appendChild(urlEl);

      const rmBtn = document.createElement("button");
      rmBtn.type = "button";
      rmBtn.className = "btn-subtle btn-danger";
      rmBtn.style.height = "26px";
      rmBtn.textContent = L("Remove", "Retirer");
      rmBtn.addEventListener("click", () => deleteBookmarkById(b.id));

      row.appendChild(linkArea);
      row.appendChild(rmBtn);
      bmBox.appendChild(row);
    }

    try {
      const hRes = await apiFetch("/api/history/list");
      const hist = await hRes.json();
      const hBox = document.getElementById("hist-sheet-list");
      hBox.replaceChildren();
      if (!hist || hist.length === 0) {
        const empty = document.createElement("div");
        empty.style.cssText = "font-size:12px;color:var(--text-muted);";
        empty.textContent = L("No browsing history recorded.", "Aucun historique enregistré.");
        hBox.appendChild(empty);
      } else {
        for (const h of hist.slice(0, 80)) {
          const row = document.createElement("div");
          row.className = "token-row";
          row.style.cssText = "padding:7px 10px;cursor:pointer;";
          row.addEventListener("click", () => {
            createNewTab(h.url, h.title);
          });

          const tEl = document.createElement("span");
          tEl.style.fontWeight = "500";
          tEl.textContent = h.title || h.url;
          row.appendChild(tEl);

          const uEl = document.createElement("span");
          uEl.className = "mono-val";
          uEl.style.fontSize = "11px";
          uEl.textContent = h.url || "";
          row.appendChild(uEl);
          hBox.appendChild(row);
        }
      }
    } catch (_) {}
  }

  async function addBookmarkFromSheet() {
    const t = document.getElementById("bm-new-title").value.trim();
    const u = document.getElementById("bm-new-url").value.trim();
    if (!u) return;
    const res = await apiPost("/api/bookmarks/add", { title: t || u, url: u });
    const d = await res.json();
    currentBookmarks = d.bookmarks || [];
    document.getElementById("bm-new-title").value = "";
    document.getElementById("bm-new-url").value = "";
    renderBookmarksStrip();
    loadBookmarksAndHistoryPanel();
  }

  async function deleteBookmarkById(id) {
    const res = await apiPost("/api/bookmarks/delete", { id });
    const d = await res.json();
    currentBookmarks = d.bookmarks || [];
    renderBookmarksStrip();
    loadBookmarksAndHistoryPanel();
  }

  async function clearHistoryOnly() {
    await apiPost("/api/history/clear", {});
    loadBookmarksAndHistoryPanel();
    showToast(L("History cleared", "Historique effacé"));
  }

  /* --- TAB 4: ZERO-KNOWLEDGE VAULT (MASTER KEPT STRICTLY IN ZEROIZED RUST MEMORY) --- */
  async function loadVaultPanel() {
    stopVaultTotpTicker();
    try {
      const stRes = await apiFetch("/api/vault/status");
      const st = await stRes.json();
      const desc = document.getElementById("vault-status-desc");
      const btnUnlock = document.getElementById("btn-vault-unlock");
      const btnLock = document.getElementById("btn-vault-lock");
      const area = document.getElementById("vault-unlocked-area");

      if (!st.has_file) {
        desc.textContent = L(
          "No vault on disk yet. Set a master password to create your encrypted vault in .singularity/vault.singularity-vault.",
          "Aucun coffre-fort sur le disque. Définissez un mot de passe maître pour créer votre coffre chiffré dans .singularity/vault.singularity-vault."
        );
        btnUnlock.textContent = L("Create Vault", "Créer mon coffre-fort");
        btnUnlock.style.display = "inline-flex";
        btnLock.style.display = "none";
        area.style.display = "none";
      } else if (st.locked) {
        desc.textContent = L(
          "Encrypted vault locked (" + st.vault_path + "). Enter your master password.",
          "Coffre-fort chiffré verrouillé (" + st.vault_path + "). Saisissez votre mot de passe maître."
        );
        btnUnlock.textContent = L("Unlock", "Déverrouiller");
        btnUnlock.style.display = "inline-flex";
        btnLock.style.display = "none";
        area.style.display = "none";
      } else {
        desc.textContent = L(
          "Vault unlocked in RAM (" + st.count + " encrypted credential(s)).",
          "Coffre-fort déverrouillé en mémoire vive (" + st.count + " identifiant(s) chiffré(s))."
        );
        btnUnlock.style.display = "none";
        btnLock.style.display = "inline-flex";
        area.style.display = "flex";
        await refreshVaultEntries();
        vaultTotpTimer = setInterval(tickVaultTotpCountdowns, 1000);
      }
    } catch (_) {}
  }

  function tickVaultTotpCountdowns() {
    const badges = document.querySelectorAll("[data-totp-rem]");
    let needsRefresh = false;
    badges.forEach(el => {
      const cur = parseInt(el.dataset.totpRem || "0", 10);
      const next = cur - 1;
      if (next <= 0) {
        needsRefresh = true;
      } else {
        el.dataset.totpRem = String(next);
        el.textContent = ` (${next}s)`;
      }
    });
    if (needsRefresh && document.getElementById("pane-vault").style.display === "flex") {
      refreshVaultEntries();
    }
  }

  async function unlockOrCreateVault() {
    const inp = document.getElementById("vault-master-input");
    const pw = inp.value;
    if (!pw || pw.length < 4) { showToast(L("Minimum 4 characters required", "4 caractères minimum requis")); return; }
    const res = await apiPost("/api/vault/unlock", { master: pw });
    const d = await res.json();
    inp.value = "";
    if (d.error) { showToast(d.error); return; }
    await loadVaultPanel();
    showToast(d.created
      ? L("Encrypted vault created!", "Coffre-fort chiffré créé !")
      : L("Vault unlocked", "Coffre-fort déverrouillé"));
  }

  async function lockVaultUI() {
    stopVaultTotpTicker();
    await apiPost("/api/vault/lock", {});
    await loadVaultPanel();
    showToast(L("Vault locked and memory wiped", "Coffre-fort verrouillé et mémoire nettoyée"));
  }

  function generateStrongPassword() {
    const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+";
    const len = charset.length;
    const limit = Math.floor(0x100000000 / len) * len;
    const buf = new Uint32Array(1);
    let out = "";
    while (out.length < 24) {
      crypto.getRandomValues(buf);
      if (buf[0] < limit) {
        out += charset[buf[0] % len];
      }
    }
    const inp = document.getElementById("v-pass");
    inp.type = "text";
    inp.value = out;
  }

  async function addVaultEntryUI() {
    const origin = document.getElementById("v-origin").value.trim();
    const user = document.getElementById("v-user").value.trim();
    const pass = document.getElementById("v-pass").value;
    const totp = document.getElementById("v-totp").value.trim();
    if (!origin || !pass) { showToast(L("Site and password are required", "Site et mot de passe requis")); return; }
    const res = await apiPost("/api/vault/add", { origin, user, pass, totp });
    const d = await res.json();
    if (d.error) { showToast(d.error); return; }
    document.getElementById("v-origin").value = "";
    document.getElementById("v-user").value = "";
    document.getElementById("v-pass").value = "";
    document.getElementById("v-pass").type = "password";
    document.getElementById("v-totp").value = "";
    await refreshVaultEntries();
    showToast(L("Credential encrypted and saved", "Identifiant chiffré et sauvegardé"));
  }

  async function refreshVaultEntries() {
    const res = await apiFetch("/api/vault/list");
    const items = await res.json();
    const box = document.getElementById("vault-entries");
    box.replaceChildren();
    if (!items || items.length === 0) {
      const empty = document.createElement("div");
      empty.style.cssText = "font-size:12px;color:var(--text-muted);";
      empty.textContent = L("No credentials saved yet.", "Aucun identifiant enregistré.");
      box.appendChild(empty);
      return;
    }
    for (const it of items) {
      const row = document.createElement("div");
      row.className = "token-row";

      const info = document.createElement("div");
      const origEl = document.createElement("div");
      origEl.style.fontWeight = "500";
      origEl.textContent = it.origin || "";
      const userEl = document.createElement("div");
      userEl.style.cssText = "font-size:11.5px;color:var(--text-secondary);";
      userEl.textContent = it.username || "";
      info.appendChild(origEl);
      info.appendChild(userEl);

      const actions = document.createElement("div");
      actions.style.cssText = "display:flex;align-items:center;gap:8px;flex-wrap:wrap;";

      if (it.totp_code) {
        const totpBtn = document.createElement("button");
        totpBtn.type = "button";
        totpBtn.className = "btn-subtle";
        totpBtn.title = L("Copy 2FA code", "Copier le code 2FA");
        const codeSpan = document.createElement("span");
        codeSpan.className = "mono-val";
        codeSpan.textContent = it.totp_code;
        const remSpan = document.createElement("span");
        remSpan.dataset.totpRem = String(it.totp_rem || 30);
        remSpan.textContent = ` (${it.totp_rem || 30}s)`;
        totpBtn.appendChild(codeSpan);
        totpBtn.appendChild(remSpan);
        totpBtn.addEventListener("click", () => copySensitiveToClipboard(it.totp_code, L("2FA code copied", "Code 2FA copié")));
        actions.appendChild(totpBtn);
      }

      const copyBtn = document.createElement("button");
      copyBtn.type = "button";
      copyBtn.className = "btn-subtle";
      copyBtn.textContent = L("Copy PW", "Copier MDP");
      copyBtn.addEventListener("click", () => copyVaultPassword(it.id));
      actions.appendChild(copyBtn);

      const delBtn = document.createElement("button");
      delBtn.type = "button";
      delBtn.className = "btn-subtle btn-danger";
      delBtn.textContent = L("Remove", "Supprimer");
      delBtn.addEventListener("click", () => deleteVaultEntryUI(it.id));
      actions.appendChild(delBtn);

      row.appendChild(info);
      row.appendChild(actions);
      box.appendChild(row);
    }
  }

  async function copyVaultPassword(id) {
    const res = await apiPost("/api/vault/secret", { id });
    const d = await res.json();
    if (d.ok && d.secret) {
      copySensitiveToClipboard(d.secret, L("Password copied", "Mot de passe copié"));
    }
  }

  async function deleteVaultEntryUI(id) {
    const res = await apiPost("/api/vault/delete", { id });
    const d = await res.json();
    if (d.error) showToast(d.error);
    await refreshVaultEntries();
  }

  async function runVaultAudit() {
    const pw = document.getElementById("vault-audit-input").value || "";
    const res = await apiPost("/api/vault/audit", { pw });
    const d = await res.json();
    document.getElementById("vault-audit-result").textContent = L(
      `Entropy: ${Number(d.entropy || 0).toFixed(1)} bits — ${d.breached ? "Found in offline k-anonymity breach filter" : "No known offline breach detected"}`,
      `Entropie : ${Number(d.entropy || 0).toFixed(1)} bits — ${d.breached ? "Compromis dans le filtre k-anonymat" : "Aucune fuite connue détectée hors-ligne"}`
    );
  }

  /* --- TAB 5: MULLVAD WIREGUARD --- */
  async function loadMullvadPanel() {
    try {
      const res = await apiFetch("/api/mullvad/status");
      const d = await res.json();
      const modeTag = d.real_tunnel
        ? L("OS tunnel active", "Tunnel système actif")
        : L("Local cryptographic simulation", "Simulation cryptographique locale");
      document.getElementById("mv-route").textContent = d.connected
        ? L(`${d.route_badge} [${modeTag}] • Account ${d.masked_account}`, `${d.route_badge} [${modeTag}] • Compte ${d.masked_account}`)
        : L(`Direct Mode (Anti-Tracker Shield Active) • Account: ${d.masked_account}`, `Mode Direct (Bouclier Anti-Traqueurs Actif) • Compte : ${d.masked_account}`);
      document.getElementById("mv-endpoints").textContent =
        `IPv4: ${d.ipv4}  •  DNS: ${d.dns}`;

      const ksBtn = document.getElementById("btn-strict-ks");
      ksBtn.classList.toggle("on", !!d.strict_killswitch);
      ksBtn.textContent = d.strict_killswitch
        ? L("Strict Kill-Switch: ON", "Kill-Switch Strict: ON")
        : L("Strict Kill-Switch: OFF", "Kill-Switch Strict: OFF");

      const relays = d.relays || [];
      const enSel = document.getElementById("mv-entry-sel");
      const exSel = document.getElementById("mv-exit-sel");
      enSel.replaceChildren();
      exSel.replaceChildren();
      for (const r of relays) {
        const label = `${(r.country_code || "").toUpperCase()} - ${r.city_name || r.hostname} (${r.hostname})`;
        const opt1 = document.createElement("option");
        opt1.value = r.hostname;
        opt1.textContent = label;
        const opt2 = opt1.cloneNode(true);
        enSel.appendChild(opt1);
        exSel.appendChild(opt2);
      }
      if (d.entry_hostname) enSel.value = d.entry_hostname;
      if (d.exit_hostname) exSel.value = d.exit_hostname;
    } catch (_) {}
  }

  async function connectMullvadUI() {
    const acc = document.getElementById("mv-account-input").value.trim();
    if (!acc) { showToast(L("Enter your 16-digit Mullvad account number", "Saisissez vos 16 chiffres Mullvad")); return; }
    const res = await apiPost("/api/mullvad/auth", { account: acc, remember: true });
    const d = await res.json();
    if (d.error) { showToast(d.error); return; }
    document.getElementById("mv-account-input").value = "";
    await loadMullvadPanel();
    await refreshHeaderState();
    showToast(d.real_tunnel
      ? L("WireGuard + DAITA tunnel connected", "Tunnel WireGuard + DAITA connecté")
      : L("WireGuard session (local cryptographic simulation) enabled", "Session WireGuard (simulation cryptographique) activée"));
  }

  async function disconnectMullvadUI() {
    await apiPost("/api/mullvad/disconnect", {});
    await loadMullvadPanel();
    await refreshHeaderState();
    showToast(L("WireGuard session disconnected", "Session WireGuard déconnectée"));
  }

  async function logoutMullvadUI() {
    await apiPost("/api/mullvad/logout", {});
    await loadMullvadPanel();
    await refreshHeaderState();
    showToast(L("Mullvad account forgotten", "Compte Mullvad oublié"));
  }

  async function applyMullvadRelays() {
    const en = document.getElementById("mv-entry-sel").value;
    const ex = document.getElementById("mv-exit-sel").value;
    await apiPost("/api/mullvad/switch", { entry: en, exit: ex, multihop: true });
    await loadMullvadPanel();
    await refreshHeaderState();
    showToast(L("Multi-Hop route updated", "Route Multi-Hop mise à jour"));
  }

  async function toggleStrictKillSwitchUI() {
    const ksBtn = document.getElementById("btn-strict-ks");
    const next = !ksBtn.classList.contains("on");
    await apiPost("/api/mullvad/set_strict_ks", { strict: next });
    await loadMullvadPanel();
    await refreshHeaderState();
  }

  async function toggleKillSwitch() {
    const res = await apiPost("/api/mullvad/toggle_killswitch", {});
    const d = await res.json();
    await refreshHeaderState();
    const out = document.getElementById("mv-packet-out");
    out.style.display = "block";
    out.textContent = d.lockdown
      ? L("Emergency lockdown ACTIVE (all outbound traffic blocked).", "Verrouillage d'urgence ACTIF (tout trafic sortant bloqué).")
      : L("Emergency lockdown disabled.", "Verrouillage d'urgence désactivé.");
  }

  async function testWireGuardPacket() {
    const res = await apiFetch("/api/mullvad/test_packet");
    const txt = await res.text();
    const out = document.getElementById("mv-packet-out");
    out.style.display = "block";
    out.textContent = txt;
  }

  /* --- TAB 6: ENGINE SETTINGS REGISTRY WITH TRUE VIRTUALIZED SCROLLING --- */
  async function loadCategories() {
    try {
      const res = await apiFetch("/api/settings/categories");
      const cats = await res.json();
      const total = cats.reduce((sum, c) => sum + (c.count || 0), 0);
      const formattedTotal = total.toLocaleString(currentLang === "fr" ? "fr-FR" : "en-US");
      const stabLbl = document.getElementById("stab-settings-label");
      if (stabLbl) stabLbl.textContent = L(`Engine (${formattedTotal})`, `Moteur (${formattedTotal})`);
      document.getElementById("settings-search").placeholder = L(
        `Filter ${formattedTotal} browser settings...`,
        `Filtrer les ${formattedTotal} réglages...`
      );
      const resetBtn = document.getElementById("btn-reset-all-settings");
      if (resetBtn) resetBtn.textContent = L(`Reset all (${formattedTotal})`, `Réinitialiser (${formattedTotal})`);

      const box = document.getElementById("modal-cats-list");
      box.replaceChildren();

      const allBtn = document.createElement("button");
      allBtn.type = "button";
      allBtn.className = "cat-btn" + (activeSettingsCat === "" ? " active" : "");
      const allLbl = document.createElement("span");
      allLbl.textContent = L("All settings", "Tous les réglages");
      const allCnt = document.createElement("span");
      allCnt.className = "cat-count";
      allCnt.textContent = String(total);
      allBtn.appendChild(allLbl);
      allBtn.appendChild(allCnt);
      allBtn.addEventListener("click", () => selectCat("", allBtn));
      box.appendChild(allBtn);

      for (const c of cats) {
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = "cat-btn" + (activeSettingsCat === c.slug ? " active" : "");
        const lbl = document.createElement("span");
        lbl.textContent = c.name;
        const cnt = document.createElement("span");
        cnt.className = "cat-count";
        cnt.textContent = String(c.count);
        btn.appendChild(lbl);
        btn.appendChild(cnt);
        btn.addEventListener("click", () => selectCat(c.slug, btn));
        box.appendChild(btn);
      }
    } catch (_) {}
  }

  function selectCat(slug, btn) {
    activeSettingsCat = slug;
    document.querySelectorAll(".cat-btn").forEach(b => b.classList.remove("active"));
    if (btn) btn.classList.add("active");
    querySettings(true);
  }

  const settingsRowsPane = document.getElementById("modal-rows-list");
  if (settingsRowsPane) {
    settingsRowsPane.addEventListener("scroll", () => {
      if (settingsScrollRaf) return;
      settingsScrollRaf = requestAnimationFrame(() => {
        settingsScrollRaf = 0;
        querySettings(false);
      });
    }, { passive: true });
  }

  async function querySettings(resetScroll) {
    const q = document.getElementById("settings-search").value || "";
    const list = document.getElementById("modal-rows-list");
    if (resetScroll) {
      list.scrollTop = 0;
    }
    const scrollPx = Math.max(0, Math.floor(list.scrollTop || 0));
    const viewH = Math.max(500, Math.floor(list.clientHeight || 560));
    const seq = ++settingsQuerySeq;

    try {
      const res = await apiFetch(
        `/api/settings/query?cat=${encodeURIComponent(activeSettingsCat)}&q=${encodeURIComponent(q)}&scroll=${scrollPx}&height=${viewH}&row_h=${SETTINGS_ROW_H}`
      );
      const vp = await res.json();
      if (seq !== settingsQuerySeq) return;

      const frag = document.createDocumentFragment();
      if (vp.top_spacer_px > 0) {
        const topSpacer = document.createElement("div");
        topSpacer.style.height = vp.top_spacer_px + "px";
        frag.appendChild(topSpacer);
      }

      for (const r of (vp.rows || [])) {
        const item = document.createElement("div");
        item.className = "setting-item";
        item.style.minHeight = SETTINGS_ROW_H + "px";

        const meta = document.createElement("div");
        const titleEl = document.createElement("div");
        titleEl.className = "setting-title";
        titleEl.textContent = r.title + " ";
        if (r.is_modified) {
          const mod = document.createElement("span");
          mod.style.cssText = "color:var(--gold-bright);font-size:10px;";
          mod.textContent = L("● modified", "● modifié");
          titleEl.appendChild(mod);
        }
        const descEl = document.createElement("div");
        descEl.className = "setting-desc";
        descEl.textContent = r.description || "";
        meta.appendChild(titleEl);
        meta.appendChild(descEl);
        item.appendChild(meta);

        if (r.val_type === "Bool") {
          const isOn = r.val_raw === "true";
          const btn = document.createElement("button");
          btn.type = "button";
          btn.className = "toggle-pill" + (isOn ? " on" : "");
          btn.textContent = isOn ? "ON" : "OFF";
          btn.addEventListener("click", () => updateSetting(r.key, "Bool", String(!isOn)));
          item.appendChild(btn);
        } else if (r.val_type === "Int" || r.val_type === "Float") {
          const inp = document.createElement("input");
          inp.type = "number";
          inp.step = r.val_type === "Float" ? "0.1" : "1";
          inp.className = "text-field";
          inp.style.cssText = "width:110px;text-align:right;font-family:var(--font-mono);";
          inp.value = r.val_raw;
          inp.addEventListener("change", () => updateSetting(r.key, r.val_type, inp.value));
          item.appendChild(inp);
        } else if (r.val_type === "ColorHex") {
          const inp = document.createElement("input");
          inp.type = "color";
          inp.value = (r.val_raw && r.val_raw.startsWith("#") && r.val_raw.length >= 7) ? r.val_raw.slice(0, 7) : "#f0b254";
          inp.style.cssText = "width:42px;height:28px;border:none;background:transparent;cursor:pointer;";
          inp.addEventListener("change", () => updateSetting(r.key, "ColorHex", inp.value));
          item.appendChild(inp);
        } else {
          const inp = document.createElement("input");
          inp.type = "text";
          inp.className = "text-field";
          inp.style.cssText = "width:170px;font-family:var(--font-mono);";
          inp.value = r.val_raw || "";
          inp.addEventListener("change", () => updateSetting(r.key, "Text", inp.value));
          item.appendChild(inp);
        }
        frag.appendChild(item);
      }

      if (vp.bottom_spacer_px > 0) {
        const botSpacer = document.createElement("div");
        botSpacer.style.height = vp.bottom_spacer_px + "px";
        frag.appendChild(botSpacer);
      }

      list.replaceChildren(frag);
    } catch (_) {}
  }

  async function updateSetting(key, vtype, nextVal) {
    const res = await apiPost("/api/settings/set", {
      key: key,
      type: vtype,
      val: String(nextVal)
    });
    const d = await res.json();
    if (d.error) showToast(d.error);
    else await querySettings(false);
  }

  async function exportSettingsToml() {
    try {
      const res = await apiFetch("/api/settings/export_toml");
      const tomlTxt = await res.text();
      const blob = new Blob([tomlTxt], { type: "text/plain;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "singularity-settings.toml";
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 2000);
      showToast(L("settings.toml exported", "settings.toml exporté"));
    } catch (_) {
      showToast(L("Error exporting TOML", "Erreur lors de l'export TOML"));
    }
  }

  async function resetAllSettingsUI() {
    const res = await apiPost("/api/settings/reset_all", {});
    const d = await res.json();
    await querySettings(true);
    showToast(L(`${d.reset_count || 0} setting(s) reset`, `${d.reset_count || 0} réglage(s) réinitialisé(s)`));
  }

  /* ============================================================================
   * BOOTSTRAP & LIVE STATE SYNC
   * ============================================================================ */
  let bootInitialized = false;
  let lastStateRev = 0;

  async function refreshHeaderState(forceFull) {
    try {
      const qs = (bootInitialized && !forceFull && lastStateRev > 0) ? `?rev=${lastStateRev}` : "";
      const res = await apiFetch("/api/state" + qs);
      const st = await res.json();
      if (typeof st.rev === "number") lastStateRev = st.rev;
      if (st.unchanged && bootInitialized) return;

      if (!bootInitialized && typeof st.language === "string") {
        currentLang = st.language === "fr" ? "fr" : "en";
      }

      const ver = st.version || "";
      document.getElementById("gen-ver").textContent = ver ? ("v" + ver) : "";
      const sideVer = document.getElementById("sidebar-ver-label");
      if (sideVer && ver) sideVer.textContent = "v" + ver;
      document.getElementById("gen-roaming-dir").textContent = st.roaming_dir || "";
      document.getElementById("gen-blocked-count").textContent = st.blocked_requests || 0;

      const tokBadge = document.getElementById("tokens-count-badge");
      if (st.encrypted_tokens_count > 0) {
        tokBadge.style.display = "inline-flex";
        tokBadge.textContent = st.encrypted_tokens_count;
      } else {
        tokBadge.style.display = "none";
      }

      const dot = document.getElementById("vpn-dot");
      const kdot = document.getElementById("ntp-kicker-dot");
      const lbl = document.getElementById("vpn-label");
      const ktext = document.getElementById("ntp-kicker-text");

      if (st.killswitch_blocked) {
        dot.classList.add("locked");
        kdot.classList.add("locked");
        lbl.textContent = "Kill-Switch";
        ktext.textContent = L(`Singularity ${ver} · Kill-Switch Active`, `Singularity ${ver} · Kill-Switch Actif`);
      } else if (st.mullvad_connected) {
        dot.classList.remove("locked");
        kdot.classList.remove("locked");
        lbl.textContent = st.mullvad_real_tunnel ? "WireGuard" : "WG (Sim)";
        ktext.textContent = st.mullvad_real_tunnel
          ? `Singularity ${ver} · WireGuard (${st.mullvad_route})`
          : `Singularity ${ver} · WireGuard Simulation (${st.mullvad_route})`;
      } else {
        dot.classList.remove("locked");
        kdot.classList.remove("locked");
        lbl.textContent = L("Shield", "Bouclier");
        ktext.textContent = L(
          `Singularity ${ver} · .singularity Vault (${st.encrypted_tokens_count} session${st.encrypted_tokens_count === 1 ? "" : "s"})`,
          `Singularity ${ver} · Coffre .singularity (${st.encrypted_tokens_count} session${st.encrypted_tokens_count > 1 ? "s" : ""})`
        );
      }

      if (Array.isArray(st.extensions)) {
        renderExtensionsToolbar(st.extensions);
      }
      if (st.tab_unload_mode) {
        tabUnloadMode = st.tab_unload_mode;
      }
      if (typeof st.tab_unload_custom_minutes === "number") {
        tabUnloadCustomMinutes = st.tab_unload_custom_minutes;
      }
      if (typeof st.tab_unload_effective_seconds === "number") {
        tabUnloadEffectiveSeconds = st.tab_unload_effective_seconds;
      }
      syncRamModeUI();

      if (!bootInitialized) {
        bootInitialized = true;
        currentBookmarks = st.bookmarks || [];
        restoreSessionEnabled = !!st.restore_session;
        privateMode = !!st.private_browsing;
        applyLanguage(st.language || "en");
        applyCosmicTheme(st.theme_id || "singularity");
        document.getElementById("btn-private-mode").classList.toggle("active-gold", privateMode);
        const eng = st.default_search_engine || "ddg";
        onboardEngine = eng;
        document.getElementById("search-engine").value = eng;
        document.getElementById("gen-engine-select").value = eng;
        const rsBtn = document.getElementById("btn-restore-session");
        rsBtn.classList.toggle("on", restoreSessionEnabled);
        rsBtn.textContent = restoreSessionEnabled ? "ON" : "OFF";
        renderBookmarksStrip();

        let restoredCount = 0;
        let restoredActiveMedia = 0;
        const restoredWins = Math.floor(Number(st.restored_windows_count || 0));
        const isDetachedHandoff = !!st.is_detached_handoff;
        if ((restoreSessionEnabled || isDetachedHandoff) && Array.isArray(st.saved_tabs) && st.saved_tabs.length > 0) {
          const now = Date.now();
          if (Array.isArray(st.saved_tab_groups)) {
            tabGroups = st.saved_tab_groups
              .filter(g => g && g.id)
              .map(g => ({
                id: String(g.id),
                title: String(g.title || ""),
                color: /^#[0-9a-fA-F]{6}$/.test(g.color || "") ? g.color : "#f0b254",
                collapsed: !!g.collapsed
              }));
          }
          const validGroupIds = new Set(tabGroups.map(g => g.id));
          const savedActiveIdx = Math.max(
            0,
            Math.min(Math.floor(Number(st.active_tab_index || 0)), st.saved_tabs.length - 1)
          );
          tabs = st.saved_tabs.map((t, idx) => ({
            id: idx + 1,
            title: t.title || deriveTitleFromUrl(t.url),
            url: t.url,
            mediaTimeSec: Math.max(0, Math.floor(Number(t.media_time_sec || 0))),
            scrollY: Math.max(0, Math.floor(Number(t.scroll_y || 0))),
            groupId: (t.group_id && validGroupIds.has(t.group_id)) ? t.group_id : null,
            faviconUrl: (t.favicon_url && /^https?:\/\//i.test(t.favicon_url)) ? t.favicon_url : "",
            lastActiveAt: now,
            unloaded: idx !== savedActiveIdx,
            startPaused: !isDetachedHandoff
          }));
          pruneEmptyGroups();
          nextTabId = tabs.length + 1;
          activeTabId = tabs[savedActiveIdx].id;
          restoredCount = tabs.length;
          restoredActiveMedia = tabs[savedActiveIdx].mediaTimeSec;
        }

        if (!st.onboarding_completed || !st.tutorial_v1_completed) {
          renderTabs(false);
          openTutorialWizard(0, true);
        } else if (restoredCount > 0) {
          syncViewportToActiveTab("activate");
          if (!isDetachedHandoff) {
            const mediaNote = restoredActiveMedia >= 3
              ? L(` · video paused at ${formatMediaTimestamp(restoredActiveMedia)}`, ` · vidéo en pause à ${formatMediaTimestamp(restoredActiveMedia)}`)
              : "";
            const winNote = restoredWins > 1
              ? L(`${restoredWins} windows · `, `${restoredWins} fenêtres · `)
              : "";
            showToast(L(
              `Session restored (${winNote}${restoredCount} tab${restoredCount === 1 ? "" : "s"}${mediaNote})`,
              `Session restaurée (${winNote}${restoredCount} onglet${restoredCount > 1 ? "s" : ""}${mediaNote})`
            ));
          }
        } else {
          focusSearchForNewTab();
        }
      }
    } catch (_) {}
  }

  /* ============================================================================
   * 3D COSMIC WEBGL2 RENDERER (BLACK HOLE / SOLAR CORONA / ECLIPSE / PULSAR / AURORA)
   * ============================================================================ */
  let mouseTargetX = 0.0, mouseTargetY = 0.0;
  let mouseSmoothX = 0.0, mouseSmoothY = 0.0;

  window.addEventListener("mousemove", (e) => {
    const w = Math.max(1, window.innerWidth);
    const h = Math.max(1, window.innerHeight);
    mouseTargetX = (e.clientX / w - 0.5) * 2.0;
    mouseTargetY = (0.5 - e.clientY / h) * 2.0;
  });

  function buildTileableNoiseRGBA(size) {
    const data = new Uint8Array(size * size * 4);
    function hashGrid(ix, iy, period, seed) {
      const x = ((ix % period) + period) % period;
      const y = ((iy % period) + period) % period;
      let h = (x * 374761393 + y * 668265263 + seed * 1442695041) | 0;
      h = Math.imul(h ^ (h >>> 13), 1274126177);
      return ((h ^ (h >>> 16)) >>> 0) / 4294967295.0;
    }
    function valueNoise(u, v, period, seed) {
      const px = u * period, py = v * period;
      const ix = Math.floor(px), iy = Math.floor(py);
      const fx = px - ix, fy = py - iy;
      const sx = fx * fx * (3.0 - 2.0 * fx);
      const sy = fy * fy * (3.0 - 2.0 * fy);
      const a = hashGrid(ix, iy, period, seed);
      const b = hashGrid(ix + 1, iy, period, seed);
      const c = hashGrid(ix, iy + 1, period, seed);
      const d = hashGrid(ix + 1, iy + 1, period, seed);
      return (a + (b - a) * sx) + ((c + (d - c) * sx) - (a + (b - a) * sx)) * sy;
    }
    function tileFbm(u, v, basePeriod, seed) {
      let sum = 0.0, amp = 0.52, norm = 0.0, p = basePeriod;
      for (let o = 0; o < 5; o++) {
        sum += amp * valueNoise(u, v, p, seed + o * 31);
        norm += amp; p *= 2; amp *= 0.5;
      }
      return sum / norm;
    }
    let ptr = 0;
    for (let y = 0; y < size; y++) {
      const v = y / size;
      for (let x = 0; x < size; x++) {
        const u = x / size;
        const coarse = tileFbm(u, v, 8, 101);
        const fine = tileFbm(u, v, 20, 409);
        const ridge = 1.0 - Math.abs(tileFbm(u, v, 12, 733) * 2.0 - 1.0);
        data[ptr++] = Math.max(0, Math.min(255, (coarse * 255.0) | 0));
        data[ptr++] = Math.max(0, Math.min(255, (fine * 255.0) | 0));
        data[ptr++] = Math.max(0, Math.min(255, (ridge * 255.0) | 0));
        data[ptr++] = 255;
      }
    }
    return data;
  }

  function initBlackHoleRenderer() {
    const canvas = document.getElementById("singularity-canvas");
    const ctxOpts = {
      antialias: false,
      depth: false,
      stencil: false,
      alpha: true,
      premultipliedAlpha: true,
      powerPreference: "high-performance"
    };
    const gl = canvas.getContext("webgl2", ctxOpts) || canvas.getContext("webgl", ctxOpts);
    if (!gl) { initCanvas2DFallback(canvas); return; }
    gl.clearColor(0.0, 0.0, 0.0, 1.0);
    gl.clear(gl.COLOR_BUFFER_BIT);

    const vsSource = `attribute vec2 a_pos; void main() { gl_Position = vec4(a_pos, 0.0, 1.0); }`;
    const fsSource = `
      precision highp float;
      uniform vec2 u_res;
      uniform float u_time;
      uniform float u_plunge;
      uniform vec2 u_mouse;
      uniform float u_offsetX;
      uniform float u_themeMode;
      uniform vec3 u_colHot;
      uniform vec3 u_colMid;
      uniform vec3 u_colOuter;
      uniform vec3 u_colGlow;
      uniform vec3 u_bgTint;
      uniform sampler2D u_noise;

      vec3 hash33(vec3 p) {
        p = fract(p * vec3(0.1031, 0.1030, 0.0973));
        p += dot(p, p.yxz + 33.33);
        return fract((p.xxy + p.yxx) * p.zyx);
      }

      vec3 renderStarfield(vec3 dir, float plunge) {
        vec3 d = normalize(dir);
        vec3 col = vec3(0.0);
        vec3 grid1 = d * 78.0;
        vec3 id1 = floor(grid1);
        vec3 f1 = fract(grid1) - 0.5;
        vec3 rnd1 = hash33(id1);
        if (rnd1.x > 0.968) {
          vec3 jitter = (rnd1 - 0.5) * 0.52;
          float dist2 = dot(f1 - jitter, f1 - jitter);
          float core = exp(-dist2 * 95.0) * smoothstep(0.968, 0.999, rnd1.x);
          vec3 tint = mix(vec3(0.84, 0.90, 1.0), vec3(1.0, 0.90, 0.74), rnd1.y);
          col += tint * core * (0.95 + plunge * 0.65);
        }
        vec3 grid2 = d * 142.0 + 19.3;
        vec3 id2 = floor(grid2);
        vec3 f2 = fract(grid2) - 0.5;
        vec3 rnd2 = hash33(id2);
        if (rnd2.x > 0.976) {
          vec3 jitter2 = (rnd2 - 0.5) * 0.48;
          float dist2 = dot(f2 - jitter2, f2 - jitter2);
          float core2 = exp(-dist2 * 125.0) * smoothstep(0.976, 0.999, rnd2.x);
          col += vec3(0.92, 0.94, 0.98) * core2 * 0.58;
        }
        return col;
      }

      vec3 geodesicAccel(vec3 p, float h2) {
        float r2 = max(dot(p, p), 0.04);
        float r = sqrt(r2);
        return (-1.5 * h2 / (r2 * r2 * r)) * p;
      }

      vec4 evaluateAccretionDisk(vec3 hit, vec3 rayDir, float spinPhase) {
        float r = length(hit.xz);
        const float rIn = 1.82;
        const float rOut = 9.60;
        if (r < rIn || r > rOut) return vec4(0.0);

        float normR = clamp((r - rIn) / (rOut - rIn), 0.0, 1.0);
        float angle = atan(hit.z, hit.x);
        float omega = 2.70 / pow(max(r, 1.5), 1.35);
        float theta = angle + spinPhase * omega;

        vec2 uv1 = vec2(normR * 2.35 - spinPhase * 0.032, theta * 0.318309886);
        vec2 uv2 = vec2(normR * 5.20 + spinPhase * 0.021, theta * 0.795774715);
        vec3 tex1 = texture2D(u_noise, uv1).rgb;
        vec3 tex2 = texture2D(u_noise, uv2).rgb;
        float filaments = smoothstep(0.16, 0.88, tex1.r * 0.56 + tex2.g * 0.30 + tex1.b * 0.14);

        float innerFade = smoothstep(rIn, rIn + 0.56, r);
        float outerFade = pow(max(1.0 - normR, 0.0), 1.95);
        float iscoRing = exp(-pow((r - 2.26) / 0.42, 2.0)) * 0.86;
        float density = (innerFade * outerFade * (0.38 + 0.86 * filaments) + iscoRing) * 0.94;

        vec3 tangent = normalize(vec3(-hit.z, 0.0, hit.x));
        float beta = clamp(0.66 / sqrt(max(r - 0.85, 0.40)), 0.0, 0.78);
        float cosTheta = dot(tangent, -normalize(rayDir));
        float gamma = inversesqrt(max(1.0 - beta * beta, 0.12));
        float doppler = 1.0 / max(gamma * (1.0 - beta * cosTheta), 0.24);
        float beaming = pow(clamp(doppler, 0.28, 2.35), 2.50);

        vec3 baseCol = mix(u_colHot, u_colMid, smoothstep(0.0, 0.35, normR));
        baseCol = mix(baseCol, u_colOuter, smoothstep(0.33, 0.94, normR));

        float shiftT = clamp((doppler - 0.74) * 0.64, 0.0, 1.0);
        vec3 beamedCol = mix(
          baseCol * vec3(0.95, 0.62, 0.52),
          mix(baseCol, vec3(1.14, 1.18, 1.26), 0.34),
          shiftT
        );

        float alpha = clamp(density * clamp(0.42 + 0.50 * beaming, 0.22, 1.55), 0.0, 0.96);
        return vec4(beamedCol * density * beaming * 1.10, alpha);
      }

      vec3 renderSolarOrEclipse(vec3 ro, vec3 rd, vec2 uv, bool isEclipse) {
        float radius = isEclipse ? 2.48 : 2.72;
        float b = dot(ro, rd);
        float c = dot(ro, ro) - radius * radius;
        float disc = b * b - c;
        float minD = length(cross(ro, rd));
        float dOut = max(minD - radius, 0.0);

        float cAng = atan(uv.y, uv.x);
        vec3 cn1 = texture2D(u_noise, vec2(cAng * 0.318309 + u_time * 0.012, minD * 0.13 - u_time * 0.036)).rgb;
        vec3 cn2 = texture2D(u_noise, vec2(cAng * 0.9549 - u_time * 0.020, minD * 0.25 - u_time * 0.055)).rgb;
        float rays = smoothstep(0.14, 0.90, cn1.r * 0.54 + cn2.b * 0.46);
        float streamers = smoothstep(0.32, 0.94, cn1.b * 0.60 + cn2.g * 0.40);

        vec3 corona = u_colHot * exp(-dOut * 2.4) * (0.72 + 0.95 * rays)
                    + u_colMid * exp(-dOut * 0.62) * (0.34 + 0.68 * streamers)
                    + u_colOuter * exp(-dOut * 0.24) * (0.18 + 0.36 * rays);

        if (isEclipse) {
          // Diamond-ring solar prominence flare at upper-right limb
          vec2 flareDir = normalize(vec2(0.74, 0.58));
          vec2 uvDir = normalize(uv + vec2(1e-5));
          float align = pow(max(dot(uvDir, flareDir), 0.0), 18.0);
          float ringDist = abs(minD - (radius + 0.06));
          float diamond = exp(-ringDist * 5.2) * align * 3.4;
          corona += u_colHot * diamond + u_colGlow * exp(-dOut * 5.8) * 1.15;
        }

        if (disc > 0.0) {
          float tHit = -b - sqrt(disc);
          vec3 hitP = ro + rd * tHit;
          vec3 n = normalize(hitP);
          float ndv = clamp(dot(n, -rd), 0.0, 1.0);

          if (isEclipse) {
            float rim = pow(1.0 - ndv, 5.5);
            vec3 moonNoise = texture2D(u_noise, vec2(atan(n.z, n.x) * 0.45, asin(clamp(n.y, -1.0, 1.0)) * 0.8)).rgb;
            vec3 earthshine = vec3(0.022, 0.008, 0.012) * (0.6 + 0.6 * moonNoise.r);
            return earthshine + u_colGlow * rim * 1.65;
          }

          float lon = atan(n.z, n.x) + u_time * 0.065;
          float lat = asin(clamp(n.y, -1.0, 1.0));
          vec2 suv1 = vec2(lon * 0.318309, lat * 0.63662 + u_time * 0.010);
          vec2 suv2 = vec2(lon * 0.79577 - u_time * 0.024, lat * 1.48 - u_time * 0.015);
          vec3 s1 = texture2D(u_noise, suv1).rgb;
          vec3 s2 = texture2D(u_noise, suv2).rgb;
          float gran = s1.r * 0.48 + s2.g * 0.34 + s2.b * 0.18;
          float spots = smoothstep(0.22, 0.35, s1.r * 0.62 + s1.b * 0.38);
          float activeFlares = smoothstep(0.66, 0.92, s1.b * 0.56 + s2.r * 0.44);
          float limbDark = pow(ndv, 0.44);
          float chromoRim = pow(1.0 - ndv, 3.0);

          vec3 surf = mix(u_colOuter, u_colMid, clamp(gran * 1.30 * spots, 0.0, 1.0));
          surf = mix(surf, u_colHot, clamp(limbDark * (0.42 + 0.58 * gran) + activeFlares * 0.88, 0.0, 1.0));
          surf += u_colGlow * chromoRim * 1.35;
          return surf * 1.24;
        }

        vec3 sky = renderStarfield(rd, 0.0) * 0.78 + u_bgTint * exp(-length(uv) * 1.25);
        return sky + corona;
      }

      void main() {
        vec2 uv = (gl_FragCoord.xy - 0.5 * u_res) / max(min(u_res.x, u_res.y), 1.0);
        float p = clamp(u_plunge, 0.0, 1.0);
        float pSmooth = p * p * (3.0 - 2.0 * p);
        float pDive = pow(p, 1.85);

        uv.x -= u_offsetX * (1.0 - pSmooth);

        float camDist = mix(15.6, 0.82, pDive);
        float elev = mix(0.176 + u_mouse.y * 0.04, 0.052, pSmooth);
        float azim = u_time * 0.032 + u_mouse.x * 0.07 * (1.0 - pSmooth) + pDive * 0.65;

        vec3 ro = vec3(
          camDist * cos(elev) * sin(azim),
          camDist * sin(elev),
          camDist * cos(elev) * cos(azim)
        );

        vec3 forward = normalize(-ro);
        vec3 worldUp = vec3(0.0, 1.0, 0.0);
        float roll = -0.155 * (1.0 - pSmooth) + pDive * 0.42;
        vec3 right0 = normalize(cross(forward, worldUp));
        vec3 up0 = cross(right0, forward);
        vec3 right = right0 * cos(roll) + up0 * sin(roll);
        vec3 up = -right0 * sin(roll) + up0 * cos(roll);

        float focal = mix(1.56, 0.64, clamp(pow(p, 0.82), 0.0, 1.0));
        vec3 rd = normalize(forward * focal + uv.x * right + uv.y * up);

        vec3 accumColor = vec3(0.0);

        if (u_themeMode >= 0.5) {
          accumColor = renderSolarOrEclipse(ro, rd, uv, u_themeMode >= 1.5);
        } else {
          vec3 pos = ro;
          vec3 vel = rd;
          vec3 hVec = cross(pos, vel);
          float h2 = dot(hVec, hVec);

          float transmittance = 1.0;
          float captured = 0.0;
          float closestR = 100.0;
          float spinPhase = u_time * 0.56 + pDive * 2.2;

          for (int i = 0; i < 32; i++) {
            float r = length(pos);
            closestR = min(closestR, r);
            if (r <= 1.015) { captured = 1.0; break; }
            if (r > 26.0 && i > 6) { break; }

            float dt = clamp(0.22 * (r - 0.90), 0.075, 1.15);
            vec3 a1 = geodesicAccel(pos, h2);
            vec3 midPos = pos + vel * (0.5 * dt);
            vec3 midVel = vel + a1 * (0.5 * dt);
            vec3 a2 = geodesicAccel(midPos, h2);

            vec3 prevPos = pos;
            pos += midVel * dt;
            vel = normalize(vel + a2 * dt);

            if (prevPos.y * pos.y <= 0.0) {
              float frac = abs(prevPos.y) / (abs(prevPos.y) + abs(pos.y) + 1e-6);
              vec3 hit = mix(prevPos, pos, frac);
              if (length(hit) > 1.03) {
                vec4 disk = evaluateAccretionDisk(hit, vel, spinPhase);
                accumColor += disk.rgb * transmittance;
                transmittance *= (1.0 - disk.a);
                if (transmittance < 0.025) break;
              }
            }
          }

          float photonGlow = exp(-max(closestR - 1.50, 0.0) * 8.4) * (1.0 - captured);
          accumColor += u_colGlow * photonGlow * 0.44 * transmittance;

          if (captured < 0.5 && transmittance > 0.01) {
            float nebGlow = exp(-length(uv) * 1.6);
            accumColor += (renderStarfield(vel, pSmooth) + u_bgTint * nebGlow) * transmittance;
          }
        }

        vec3 x = max(vec3(0.0), accumColor);
        vec3 mapped = (x * (2.51 * x + 0.03)) / (x * (2.43 * x + 0.59) + 0.14);
        mapped = pow(clamp(mapped, 0.0, 1.0), vec3(0.92));
        gl_FragColor = vec4(mapped, 1.0);
      }
    `;

    function compileShader(type, src) {
      const s = gl.createShader(type);
      gl.shaderSource(s, src);
      gl.compileShader(s);
      if (!gl.getShaderParameter(s, gl.COMPILE_STATUS)) { gl.deleteShader(s); return null; }
      return s;
    }

    const vs = compileShader(gl.VERTEX_SHADER, vsSource);
    const fs = compileShader(gl.FRAGMENT_SHADER, fsSource);
    if (!vs || !fs) { initCanvas2DFallback(canvas); return; }

    const prog = gl.createProgram();
    gl.attachShader(prog, vs);
    gl.attachShader(prog, fs);
    gl.linkProgram(prog);
    if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) { initCanvas2DFallback(canvas); return; }

    const NOISE_DIM = 128;
    const noiseTex = gl.createTexture();
    gl.activeTexture(gl.TEXTURE0);
    gl.bindTexture(gl.TEXTURE_2D, noiseTex);
    gl.texImage2D(
      gl.TEXTURE_2D, 0, gl.RGBA, 1, 1, 0, gl.RGBA, gl.UNSIGNED_BYTE,
      new Uint8Array([128, 128, 128, 255])
    );
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.REPEAT);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.REPEAT);

    // Build tileable 128x128 FBM/ridge noise off the initial paint critical path (4x faster boot)
    setTimeout(() => {
      try {
        const data = buildTileableNoiseRGBA(NOISE_DIM);
        gl.activeTexture(gl.TEXTURE0);
        gl.bindTexture(gl.TEXTURE_2D, noiseTex);
        gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, NOISE_DIM, NOISE_DIM, 0, gl.RGBA, gl.UNSIGNED_BYTE, data);
      } catch (_) {}
    }, 80);

    const quadBuf = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, quadBuf);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);

    const aPos = gl.getAttribLocation(prog, "a_pos");
    const uRes = gl.getUniformLocation(prog, "u_res");
    const uTime = gl.getUniformLocation(prog, "u_time");
    const uPlunge = gl.getUniformLocation(prog, "u_plunge");
    const uMouse = gl.getUniformLocation(prog, "u_mouse");
    const uOffsetX = gl.getUniformLocation(prog, "u_offsetX");
    const uThemeMode = gl.getUniformLocation(prog, "u_themeMode");
    const uColHot = gl.getUniformLocation(prog, "u_colHot");
    const uColMid = gl.getUniformLocation(prog, "u_colMid");
    const uColOuter = gl.getUniformLocation(prog, "u_colOuter");
    const uColGlow = gl.getUniformLocation(prog, "u_colGlow");
    const uBgTint = gl.getUniformLocation(prog, "u_bgTint");
    const uNoise = gl.getUniformLocation(prog, "u_noise");

    // Static WebGL pipeline state bound once instead of every frame
    gl.useProgram(prog);
    gl.uniform1i(uNoise, 0);
    gl.enableVertexAttribArray(aPos);
    gl.vertexAttribPointer(aPos, 2, gl.FLOAT, false, 0, 0);

    const MIN_FRAME_MS = 15.8; // Smooth 60fps cap so 144Hz/240Hz monitors never burn excess GPU
    const bootMs = performance.now();
    let lastFrameMs = bootMs;
    let lastDrawMs = 0;
    let rafPending = false;
    let lensOffsetCurrentX = 0.14;

    function syncCanvasSize() {
      const iw = Math.max(1, window.innerWidth);
      const ih = Math.max(1, window.innerHeight);
      // Do not shrink the WebGL2 backing buffer while ui_webview is collapsed to the 46px top bar!
      if (ih < 120) return false;
      const dpr = Math.min(window.devicePixelRatio || 1, 1.0, 1280 / iw, 720 / ih);
      const w = Math.max(1, Math.floor(iw * dpr));
      const h = Math.max(1, Math.floor(ih * dpr));
      if (canvas.width !== w || canvas.height !== h) {
        canvas.width = w;
        canvas.height = h;
        gl.viewport(0, 0, w, h);
        gl.clearColor(0.0, 0.0, 0.0, 1.0);
        gl.clear(gl.COLOR_BUFFER_BIT);
        return true;
      }
      return false;
    }

    function drawScene(nowMs) {
      const rawDtMs = Math.max(0.0, nowMs - lastFrameMs);
      const clampedDtMs = Math.min(rawDtMs, 33.34);
      lastFrameMs = nowMs;
      lastDrawMs = nowMs;

      const smoothFactor = 1.0 - Math.exp(-clampedDtMs * 0.0045);
      mouseSmoothX += (mouseTargetX - mouseSmoothX) * smoothFactor;
      mouseSmoothY += (mouseTargetY - mouseSmoothY) * smoothFactor;

      const targetOffsetX = anyModalOpen() ? 0.0 : 0.14;
      lensOffsetCurrentX += (targetOffsetX - lensOffsetCurrentX) * (1.0 - Math.exp(-clampedDtMs * 0.006));

      const tSec = (nowMs - bootMs) * 0.001;
      const th = getActiveThemeConfig();

      gl.uniform2f(uRes, canvas.width, canvas.height);
      gl.uniform1f(uTime, tSec);
      gl.uniform1f(uPlunge, 0.0);
      gl.uniform2f(uMouse, mouseSmoothX, mouseSmoothY);
      gl.uniform1f(uOffsetX, lensOffsetCurrentX);
      gl.uniform1f(uThemeMode, th.shaderMode || 0);
      gl.uniform3fv(uColHot, th.colHot);
      gl.uniform3fv(uColMid, th.colMid);
      gl.uniform3fv(uColOuter, th.colOuter);
      gl.uniform3fv(uColGlow, th.colGlow);
      gl.uniform3fv(uBgTint, th.bgTint);

      gl.drawArrays(gl.TRIANGLES, 0, 3);
    }

    function revealCanvasAfterDraw() {
      if (document.hidden || window.innerHeight < 120) return;
      syncCanvasSize();
      drawScene(performance.now());
      canvas.style.visibility = "visible";
      canvas.style.opacity = "1";
    }

    function scheduleNextFrame() {
      if (!rafPending && !bhSuspended && !document.hidden && window.innerHeight >= 120) {
        rafPending = true;
        requestAnimationFrame(frame);
      }
    }

    window.addEventListener("resize", () => {
      if (window.innerHeight < 120) return;
      syncCanvasSize();
      if (!bhSuspended && !document.hidden) {
        revealCanvasAfterDraw();
        scheduleNextFrame();
      }
    });

    document.addEventListener("visibilitychange", () => {
      if (!document.hidden && !bhSuspended && window.innerHeight >= 120) {
        lastFrameMs = performance.now();
        lastDrawMs = 0;
        revealCanvasAfterDraw();
        scheduleNextFrame();
      }
    });

    bhResumeFn = function() {
      lastFrameMs = performance.now();
      lastDrawMs = 0;
      if (!document.hidden && window.innerHeight >= 120) {
        revealCanvasAfterDraw();
      }
      scheduleNextFrame();
    };

    function frame(nowMs) {
      rafPending = false;
      if (bhSuspended || document.hidden || window.innerHeight < 120) return;
      if (lastDrawMs > 0 && (nowMs - lastDrawMs) < MIN_FRAME_MS) {
        scheduleNextFrame();
        return;
      }
      syncCanvasSize();
      drawScene(nowMs);
      if (canvas.style.visibility === "hidden" || canvas.style.opacity === "0") {
        canvas.style.visibility = "visible";
        canvas.style.opacity = "1";
      }
      scheduleNextFrame();
    }

    syncCanvasSize();
    frame(bootMs);
  }

  function initCanvas2DFallback(canvas) {
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    ctx.fillStyle = "#000000";
    ctx.fillRect(0, 0, canvas.width, canvas.height);
  }

  renderThemeGalleries();
  renderTabs(false);
  initBlackHoleRenderer();
  refreshHeaderState();
  setInterval(() => {
    if (!document.hidden) refreshHeaderState(false);
  }, 10000);
  // Keep exact SPA URLs (YouTube watch?v=..., Twitch, Discord) synced with minimal IPC overhead
  setInterval(() => {
    if (document.hidden) return;
    const t = getActiveTab();
    if (t && t.url && !isInternalSettingsUrl(t.url) && !anyModalOpen()) {
      sendNativeIpc({ cmd: "sync_tab_url", tab_id: t.id });
    }
  }, 8000);
  // Periodically unload inactive tabs from RAM according to the active 4-mode RAM policy
  setInterval(sweepInactiveTabsForRam, 30000);
  sendNativeIpc({ cmd: "ui_ready" });
</script>
</body>
</html>
"##;
