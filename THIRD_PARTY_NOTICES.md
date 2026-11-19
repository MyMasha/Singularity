# Third-Party Notices & Attributions

Singularity Browser is licensed under the **Mozilla Public License Version 2.0 (MPL-2.0)** (see [`LICENSE`](LICENSE)).

This software incorporates and/or links against the following third-party open-source libraries, assets, and platform redistributables. All Rust crate dependencies are permissively licensed (MIT, Apache-2.0, BSD-3-Clause, ISC, Zlib, or Unicode-3.0).

---

## 1. Platform Runtime Redistributables (Windows)

### Microsoft Edge WebView2 SDK (`WebView2Loader.dll`)
- **Copyright**: Copyright (c) Microsoft Corporation. All rights reserved.
- **License**: Microsoft Edge WebView2 SDK Redistributable License (`webview2-com-sys`).
- **Usage**: Loaded by Singularity on Windows via `wry` to render web content tabs and Chrome extensions using the system-installed Microsoft Edge WebView2 Runtime.

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
| `serde`, `serde_json`, `toml`, `thiserror`, `hex`, `base64`, `rand_core`, `sha1`, `sha2`, `hmac`, `argon2`, `chacha20poly1305`, `zeroize`, `zip`, `tao`, `wry`, `windows`, `windows-sys`, `windows-core` | MIT OR Apache-2.0 |
| `subtle`, `curve25519-dalek`, `ed25519-dalek`, `x25519-dalek` | BSD-3-Clause |
| `webview2-com`, `webview2-com-sys` | MIT (with Microsoft WebView2 redistributable loader binary) |
| `unicode-ident`, `unicode-xid`, `icu_*` | MIT / Apache-2.0 / Unicode-3.0 |

To inspect the full license list for your build target, run:
```bash
cargo metadata --format-version 1 | jq -r '.packages[] | "\(.name) \(.version): \(.license)"' | sort -u
```
