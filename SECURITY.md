# Security Policy — Singularity Browser

## Supported Versions

Only the latest tagged release on the `main` branch receives security updates.

| Version | Supported |
| --- | --- |
| `1.0.x` (latest) | Yes |
| `< 1.0.0` | No |

## Security Architecture Highlights

- **Local IPC isolation**: Ephemeral loopback port (`127.0.0.1:0`), one-time CSPRNG bootstrap nonce on `GET /`, constant-time 256-bit `X-Singularity-Token` verification (`subtle::ConstantTimeEq`), strict `Host` / `Origin` / `Sec-Fetch-Site` (`same-origin` / `none`) checks, and WebView2 navigation blocking against Singularity's IPC port.
- **Encrypted local storage**:
  - Zero-knowledge password & 2FA vault (`Argon2id` + `XChaCha20-Poly1305` + `Zeroizing` buffers).
  - Session token store (`tokens.enc`) protected by `XChaCha20-Poly1305` AEAD with OS-backed master key storage: **Windows DPAPI** (`CryptProtectData` → `master.dpapi`), **Linux Secret Service** (`secret-tool`), or **macOS Keychain** (`security`), falling back to `0600` user-only `master.key` on headless environments without a keyring daemon.
- **Dual-WebView privilege separation**: The Singularity UI shell (`browser-ui`) runs separately from web content & Chrome extensions (`browser-engine`), with sandboxed CSP headers on proxied favicons and extension icons.
- **Verified self-updates (SHA-256 + optional Ed25519)**:
  - The self-updater connects directly to public GitHub Releases (`https://github.com/MyMasha/Singularity`) over HTTPS with zero hardcoded tokens.
  - Every binary download is checked in constant time against `SHA256SUMS.txt` from the exact same release before replacing any executable.
  - **Out-of-band Ed25519 signing**: Maintainers can enable cryptographic manifest signatures by:
    1. Generating an Ed25519 PKCS#8 PEM private key (`openssl genpkey -algorithm ed25519 -out ed25519.pem`) and storing its PEM content in the repository's GitHub Actions secret `SINGULARITY_RELEASE_SIGNING_KEY` (automatically signs `SHA256SUMS.txt` → base64 `SHA256SUMS.txt.sig` via `openssl pkeyutl -sign -rawin` in `.github/workflows/release.yml`).
    2. Embedding the corresponding raw 32-byte (64-hex-character) Ed25519 public key in `RELEASE_SIGNING_PUBKEY_HEX` (`crates/singularity-ui/src/updater.rs`). When set, the updater enforces detached Ed25519 verification over `SHA256SUMS.txt` before applying any update.
- **Transparent module status**: The embedded WireGuard + DAITA crate (`singularity-net-mullvad`) currently provides local cryptographic packet framing, relay route selection, and an application-level socket/SSRF kill-switch (not an OS-level TUN VPN interface).

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Instead, report security issues privately using **GitHub Security Advisories** (`Security` → `Advisories` → `Report a vulnerability` on this repository).

Please include:
1. Affected version (`singularity --version` or release tag) and OS.
2. Clear reproduction steps or a minimal proof of concept.
3. Expected security impact.

We aim to acknowledge reports within 72 hours and provide a fix or mitigation plan as quickly as possible.
