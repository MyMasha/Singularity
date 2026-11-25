# Security Policy — Singularity Browser

## Supported Versions

Only the latest tagged release on the `main` branch receives security updates.

| Version | Supported |
| --- | --- |
| `2.0.x` (latest) | Yes |
| `< 2.0.0` | No |

## Security Architecture Highlights

- **Local IPC isolation**: Ephemeral loopback port (`127.0.0.1:0`), one-time CSPRNG bootstrap nonce on `GET /`, constant-time 256-bit `X-Singularity-Token` verification (`subtle::ConstantTimeEq`), strict `Host` / `Origin` / `Sec-Fetch-Site` (`same-origin` / `none`) checks, and navigation blocking against Singularity's IPC port.
- **Encrypted local storage**:
  - Zero-knowledge password & 2FA vault (`Argon2id` + `XChaCha20-Poly1305` + `Zeroizing` buffers).
  - Session token store (`tokens.enc`) protected by `XChaCha20-Poly1305` AEAD with OS-backed master key storage: **Windows DPAPI** (`CryptProtectData` → `master.dpapi`), **Linux Secret Service** (`secret-tool`), or **macOS Keychain** (`security`), falling back to `0600` user-only `master.key` on headless environments without a keyring daemon.
- **Process & installer hardening**: The Singularity UI shell runs with Pure Chromium (CEF), sandboxed CSP headers on proxied favicons and extension icons, DLL search order hardening (`/DEPENDENTLOADFLAG:0x800` + `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)`), symlink/reparse-point refusal during extraction, and authenticated `SGX1` SFX ZIP overlay trailers (SHA-256 + Ed25519).
- **Verified self-updates (SHA-256 + Ed25519)**:
  - The self-updater and `dist/` helper scripts connect directly to public GitHub Releases (`https://github.com/MyMasha/Singularity`) over allowlisted HTTPS GitHub hosts with zero hardcoded tokens, staging downloads inside private per-user directories.
  - Every binary download is checked in constant time against `SHA256SUMS.txt` from the exact same release (with SemVer anti-downgrade protection) before replacing any executable.
  - **Out-of-band Ed25519 signing**: Maintainers enable cryptographic manifest & SFX signatures by storing an Ed25519 PKCS#8 PEM private key (`openssl genpkey -algorithm ed25519 -out ed25519.pem`) in the repository's GitHub Actions secret `SINGULARITY_RELEASE_SIGNING_KEY`. `.github/workflows/release.yml` automatically derives the raw 32-byte (64-hex) public key into `SINGULARITY_RELEASE_SIGNING_PUBKEY_HEX` for all release builds, signs the Windows installer's `SGX1` SFX trailer, and signs `SHA256SUMS.txt` → base64 `SHA256SUMS.txt.sig` via `openssl pkeyutl -sign -rawin`. The `dist/` updaters require Ed25519 signature verification by default in production (`SINGULARITY_RELEASE_SIGNING_PUBKEY_HEX`).
- **Transparent module status**: The embedded WireGuard + DAITA crate (`singularity-net-mullvad`) currently provides local cryptographic packet framing, relay route selection, and an application-level socket/SSRF kill-switch (not an OS-level TUN VPN interface).

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Instead, report security issues privately using **GitHub Security Advisories** (`Security` → `Advisories` → `Report a vulnerability` on this repository).

Please include:
1. Affected version (`singularity --version` or release tag) and OS.
2. Clear reproduction steps or a minimal proof of concept.
3. Expected security impact.

We aim to acknowledge reports within 72 hours and provide a fix or mitigation plan as quickly as possible.
