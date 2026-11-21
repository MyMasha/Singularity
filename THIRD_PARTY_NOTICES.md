# Third-Party Notices & Attributions

Singularity Browser is licensed under the **Mozilla Public License Version 2.0 (MPL-2.0)** (see [`LICENSE`](LICENSE)).

This software incorporates and/or links against the following third-party open-source libraries, assets, and platform redistributables. All Rust crate dependencies are permissively licensed (MIT, Apache-2.0, BSD-3-Clause, ISC, Zlib, or Unicode-3.0).

---

## 1. Embedded Browser Engine Runtime (Windows)

### Chromium Embedded Framework (CEF) & Chromium
- **Copyright**: Copyright (c) 2008–2026 Marshall A. Greenblatt and The Chromium Authors. All rights reserved.
- **License**: BSD 3-Clause License (CEF) and Chromium open-source licenses (`https://bitbucket.org/chromiumembedded/cef/src/master/LICENSE.txt`).
- **Usage**: Bundled by Singularity on Windows via `cef` / `cef-dll-sys` (`tauri-apps/cef-rs`, Apache-2.0 OR MIT) to render web content tabs and Chrome extensions using Pure Chromium (zero Microsoft Edge / WebView2 dependency). Official prebuilt CEF binaries from Spotify CDN include open media codecs (VP8/VP9/AV1/Opus/Vorbis/WebM) and exclude proprietary H.264/AAC software decoders.

---

## 2. Embedded Shaders & UI Iconography

### Procedural Hash Utility (`hash33`)
- **Author**: Dave Hoskins
- **License**: MIT License
- **Usage**: Used in the WebGL black-hole procedural starfield shader in `crates/singularity-ui/src/ui_app.rs`.

### UI Icon Paths
- **Sources**: Feather Icons (MIT License) & Lucide Icons (ISC License), plus custom geometric SVG paths.
- **Usage**: Inline SVG toolbar, sidebar, and control iconography in `crates/singularity-ui/src/ui_app.rs`.

---

## 3. Rust Workspace Dependencies

The complete dependency tree is pinned in [`Cargo.lock`](Cargo.lock). Key direct & transitive dependencies include:

| Crate(s) | License |
| --- | --- |
| `serde`, `serde_json`, `toml`, `thiserror`, `hex`, `base64`, `rand_core`, `sha1`, `sha2`, `hmac`, `argon2`, `chacha20poly1305`, `zeroize`, `zip`, `tao`, `cef`, `cef-dll-sys`, `windows`, `windows-sys`, `windows-core` | MIT OR Apache-2.0 |
| `subtle`, `curve25519-dalek`, `ed25519-dalek`, `x25519-dalek` | BSD-3-Clause |
| `unicode-ident`, `unicode-xid`, `icu_*` | MIT / Apache-2.0 / Unicode-3.0 |

To inspect the full license list for your build target, run:
```bash
cargo metadata --format-version 1 | jq -r '.packages[] | "\(.name) \(.version): \(.license)"' | sort -u
```
