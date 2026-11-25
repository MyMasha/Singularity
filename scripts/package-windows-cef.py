#!/usr/bin/env python3
"""Stages release singularity.exe + Pure Chromium (CEF) runtime files (EN/FR locales only),
compresses them into dist/singularity-bundle.zip, and attaches the ZIP as an authenticated
SGX1 self-extracting PE overlay onto Singularity-Setup.exe (SHA-256 + optional Ed25519)."""

from __future__ import annotations

import base64
import glob
import hashlib
import hmac
import os
import shutil
import struct
import sys
import zipfile
from pathlib import Path

# Fixed 116-byte SGX1 SFX trailer synchronized with crates/singularity-installer/src/main.rs:
#   [0..4]    b"SGX1"
#   [4..12]   zip_len (uint64 LE)
#   [12..44]  zip_sha256 (32 bytes)
#   [44]      flags (0x00 = SHA-256 sealed, 0x01 = SHA-256 + Ed25519 signed)
#   [45..48]  reserved (3 zero bytes)
#   [48..112] ed25519_sig over [0..48] (64 bytes, or 64 zero bytes when unsigned)
#   [112..116] b"SGX1"
SFX_TRAILER_MAGIC = b"SGX1"
SFX_FLAG_ED25519_SIGNED = 0x01

# RFC 8032 Ed25519 curve constants (zero third-party dependencies)
_ED_P = 2**255 - 19
_ED_L = 2**252 + 27742317777372353535851937790883648493
_ED_D = (-121665 * pow(121666, _ED_P - 2, _ED_P)) % _ED_P
_ED_I = pow(2, (_ED_P - 1) // 4, _ED_P)


def _ed_xrecover(y: int) -> int:
    xx = (y * y - 1) * pow(_ED_D * y * y + 1, _ED_P - 2, _ED_P) % _ED_P
    x = pow(xx, (_ED_P + 3) // 8, _ED_P)
    if (x * x - xx) % _ED_P != 0:
        x = (x * _ED_I) % _ED_P
    if (x * x - xx) % _ED_P != 0:
        raise ValueError("Ed25519 base point recovery failed")
    if x % 2 != 0:
        x = _ED_P - x
    return x


_ED_BY = (4 * pow(5, _ED_P - 2, _ED_P)) % _ED_P
_ED_BX = _ed_xrecover(_ED_BY)
_ED_B = (_ED_BX % _ED_P, _ED_BY % _ED_P, 1, (_ED_BX * _ED_BY) % _ED_P)


def _ed_point_add(
    p1: tuple[int, int, int, int], p2: tuple[int, int, int, int]
) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = ((y1 - x1) * (y2 - x2)) % _ED_P
    b = ((y1 + x1) * (y2 + x2)) % _ED_P
    c = (2 * _ED_D * t1 * t2) % _ED_P
    d = (2 * z1 * z2) % _ED_P
    e = (b - a) % _ED_P
    f = (d - c) % _ED_P
    g = (d + c) % _ED_P
    h = (b + a) % _ED_P
    return ((e * f) % _ED_P, (g * h) % _ED_P, (f * g) % _ED_P, (e * h) % _ED_P)


def _ed_scalarmult(pt: tuple[int, int, int, int], e: int) -> tuple[int, int, int, int]:
    q = (0, 1, 1, 0)
    while e > 0:
        if e & 1:
            q = _ed_point_add(q, pt)
        pt = _ed_point_add(pt, pt)
        e >>= 1
    return q


def _ed_encodepoint(pt: tuple[int, int, int, int]) -> bytes:
    x, y, z, _ = pt
    zi = pow(z, _ED_P - 2, _ED_P)
    ax = (x * zi) % _ED_P
    ay = (y * zi) % _ED_P
    enc = bytearray(ay.to_bytes(32, "little"))
    enc[31] |= (ax & 1) << 7
    return bytes(enc)


def _parse_asn1_tlv(buf: bytes, offset: int) -> tuple[int, bytes, int]:
    if offset + 2 > len(buf):
        raise ValueError("Truncated ASN.1 DER object")
    tag = buf[offset]
    length = buf[offset + 1]
    pos = offset + 2
    if length & 0x80:
        nbytes = length & 0x7F
        if nbytes == 0 or pos + nbytes > len(buf):
            raise ValueError("Invalid ASN.1 DER length encoding")
        length = int.from_bytes(buf[pos : pos + nbytes], "big")
        pos += nbytes
    if pos + length > len(buf):
        raise ValueError("ASN.1 DER value exceeds buffer")
    return tag, buf[pos : pos + length], pos + length


def parse_ed25519_pkcs8_pem(pem_text: str) -> bytes:
    """Extracts the 32-byte raw Ed25519 seed from a PKCS#8 PEM private key (RFC 8410)."""
    lines = [
        line.strip()
        for line in pem_text.strip().splitlines()
        if line.strip() and not line.strip().startswith("-----")
    ]
    if not lines:
        raise ValueError("Empty Ed25519 PEM private key")
    der = base64.b64decode("".join(lines), validate=True)

    tag, seq, end = _parse_asn1_tlv(der, 0)
    if tag != 0x30 or end != len(der):
        raise ValueError("PKCS#8 private key must be an ASN.1 SEQUENCE")

    # version INTEGER (0 or 1)
    v_tag, v_val, pos = _parse_asn1_tlv(seq, 0)
    if v_tag != 0x02 or v_val not in (b"\x00", b"\x01"):
        raise ValueError("Unsupported PKCS#8 version for Ed25519 private key")

    # privateKeyAlgorithm AlgorithmIdentifier SEQUENCE { OID 1.3.101.112 }
    alg_tag, alg_val, pos = _parse_asn1_tlv(seq, pos)
    if alg_tag != 0x30 or alg_val != bytes.fromhex("06032b6570"):
        raise ValueError("PKCS#8 private key algorithm is not Ed25519 (OID 1.3.101.112)")

    # privateKey OCTET STRING wrapping CurvePrivateKey OCTET STRING (32-byte seed)
    pk_tag, pk_val, _ = _parse_asn1_tlv(seq, pos)
    if pk_tag != 0x04:
        raise ValueError("Missing PKCS#8 privateKey OCTET STRING")
    inner_tag, seed, inner_end = _parse_asn1_tlv(pk_val, 0)
    if inner_tag != 0x04 or inner_end != len(pk_val) or len(seed) != 32:
        raise ValueError("Invalid Ed25519 CurvePrivateKey seed length")
    return seed


def ed25519_derive_pubkey_and_sign(seed32: bytes, msg: bytes) -> tuple[bytes, bytes]:
    """Returns (32-byte public key, 64-byte RFC 8032 Ed25519 signature over msg)."""
    h = hashlib.sha512(seed32).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    prefix = h[32:]
    pub = _ed_encodepoint(_ed_scalarmult(_ED_B, a))
    r = int.from_bytes(hashlib.sha512(prefix + msg).digest(), "little") % _ED_L
    r_enc = _ed_encodepoint(_ed_scalarmult(_ED_B, r))
    k = int.from_bytes(hashlib.sha512(r_enc + pub + msg).digest(), "little") % _ED_L
    s = (r + k * a) % _ED_L
    return pub, r_enc + s.to_bytes(32, "little")


def find_cef_runtime_dir() -> str | None:
    """Locate the release directory containing libcef.dll and icudtl.dat (never target/debug)."""
    candidates: list[str] = []
    cef_env = os.environ.get("CEF_PATH", "").strip()
    if cef_env and os.path.isdir(cef_env):
        candidates.append(cef_env)
    candidates.extend([
        os.path.join("target", "release"),
        os.path.join("target", "release", "build"),
    ])

    for root in candidates:
        if not os.path.isdir(root):
            continue
        if (
            os.path.isfile(os.path.join(root, "libcef.dll"))
            and os.path.isfile(os.path.join(root, "icudtl.dat"))
        ):
            return root
        for dp, dns, fns in os.walk(root):
            dns[:] = [
                d
                for d in dns
                if d not in ("include", "libcef_dll", "cmake", "out", "CMakeFiles")
            ]
            if "libcef.dll" in fns and "icudtl.dat" in fns:
                return dp
    return None


def _is_debug_target_path(path_str: str) -> bool:
    parts = [p.lower() for p in Path(path_str).parts]
    for idx in range(len(parts) - 1):
        if parts[idx] == "target" and parts[idx + 1] == "debug":
            return True
    return False


def attach_sfx(
    stub_exe: str,
    bundle_zip: str,
    output_exe: str,
    signing_key_file: str | None = None,
) -> int:
    if not os.path.isfile(stub_exe):
        print(f"ERROR: Missing release installer stub: {stub_exe}", file=sys.stderr)
        return 1
    if _is_debug_target_path(stub_exe):
        print(
            f"ERROR: Refusing debug installer stub '{stub_exe}'. Build with `cargo build --release --bin Singularity-Setup`.",
            file=sys.stderr,
        )
        return 1
    if not os.path.isfile(bundle_zip):
        print(f"ERROR: Missing CEF bundle archive: {bundle_zip}", file=sys.stderr)
        return 1

    signing_pem = ""
    if signing_key_file:
        signing_pem = Path(signing_key_file).read_text(encoding="utf-8").strip()
    else:
        signing_pem = os.environ.get("SINGULARITY_RELEASE_SIGNING_KEY", "").strip()

    expected_pub_hex = os.environ.get("SINGULARITY_RELEASE_SIGNING_PUBKEY_HEX", "").strip().lower()
    if expected_pub_hex and not signing_pem:
        print(
            "ERROR: SINGULARITY_RELEASE_SIGNING_PUBKEY_HEX is set (installer requires Ed25519 signature), "
            "but neither --signing-key-file nor SINGULARITY_RELEASE_SIGNING_KEY was provided.",
            file=sys.stderr,
        )
        return 1

    os.makedirs(os.path.dirname(output_exe) or ".", exist_ok=True)
    zip_hasher = hashlib.sha256()
    zip_len = 0

    with open(output_exe, "wb") as out_f:
        with open(stub_exe, "rb") as stub_f:
            shutil.copyfileobj(stub_f, out_f, 1024 * 1024)
        with open(bundle_zip, "rb") as zip_f:
            while True:
                chunk = zip_f.read(1024 * 1024)
                if not chunk:
                    break
                out_f.write(chunk)
                zip_hasher.update(chunk)
                zip_len += len(chunk)

        zip_sha256 = zip_hasher.digest()
        flags = SFX_FLAG_ED25519_SIGNED if signing_pem else 0x00
        signed_header = (
            SFX_TRAILER_MAGIC
            + struct.pack("<Q", zip_len)
            + zip_sha256
            + bytes([flags, 0, 0, 0])
        )
        assert len(signed_header) == 48

        if signing_pem:
            seed32 = parse_ed25519_pkcs8_pem(signing_pem)
            pub32, sig64 = ed25519_derive_pubkey_and_sign(seed32, signed_header)
            derived_hex = pub32.hex()
            if expected_pub_hex and not hmac.compare_digest(derived_hex, expected_pub_hex):
                print(
                    f"ERROR: Ed25519 signing key public key mismatch! derived={derived_hex} expected={expected_pub_hex}",
                    file=sys.stderr,
                )
                return 1
            auth_desc = f"SGX1 SHA-256 + Ed25519 (pubkey {derived_hex[:12]}...)"
        else:
            sig64 = b"\x00" * 64
            auth_desc = "SGX1 SHA-256 sealed (unsigned dev/dry-run build)"

        trailer = signed_header + sig64 + SFX_TRAILER_MAGIC
        assert len(trailer) == 116
        out_f.write(trailer)

    total_mb = os.path.getsize(output_exe) / 1048576.0
    print(
        f"[OK] Built self-extracting Windows installer {output_exe}: {total_mb:.2f} MB "
        f"[{auth_desc}, zip_sha256={zip_hasher.hexdigest()}]"
    )
    return 0


def main() -> int:
    if len(sys.argv) >= 5 and sys.argv[1] == "--attach-sfx":
        signing_key_file: str | None = None
        if len(sys.argv) == 7 and sys.argv[5] == "--signing-key-file":
            signing_key_file = sys.argv[6]
        elif len(sys.argv) != 5:
            print(
                "Usage: package-windows-cef.py --attach-sfx <stub_exe> <bundle_zip> <output_exe> [--signing-key-file <pem>]",
                file=sys.stderr,
            )
            return 2
        return attach_sfx(sys.argv[2], sys.argv[3], sys.argv[4], signing_key_file)

    release_dir = os.path.join("target", "release")
    stage_dir = os.path.join("dist", "stage")
    locales_dst = os.path.join(stage_dir, "locales")
    bundle_zip = os.path.join("dist", "singularity-bundle.zip")

    if os.path.isdir(stage_dir):
        shutil.rmtree(stage_dir)
    if os.path.isfile(bundle_zip):
        os.remove(bundle_zip)
    os.makedirs(locales_dst, exist_ok=True)

    exe_src = os.path.join(release_dir, "singularity.exe")
    if not os.path.isfile(exe_src):
        print(
            f"ERROR: Missing required release binary '{exe_src}'. "
            "Silent fallback to target/debug is disabled; build with `cargo build --release --bin singularity`.",
            file=sys.stderr,
        )
        return 1
    shutil.copy2(exe_src, os.path.join(stage_dir, "singularity.exe"))

    cef_dir = find_cef_runtime_dir()
    if not cef_dir:
        print(
            f"ERROR: Could not locate release Pure Chromium CEF runtime directory "
            f"(CEF_PATH={os.environ.get('CEF_PATH', '')}; target/debug fallback is disabled)",
            file=sys.stderr,
        )
        return 1
    print(f"[INFO] Staging Pure Chromium (CEF) runtime from: {cef_dir}")

    staged_names: set[str] = set()
    for pattern in ("*.dll", "*.dat", "*.bin", "*.pak", "vk_swiftshader_icd.json"):
        for src in glob.glob(os.path.join(cef_dir, pattern)):
            if os.path.isfile(src):
                name = os.path.basename(src)
                shutil.copy2(src, os.path.join(stage_dir, name))
                staged_names.add(name)

    skipped = sorted(
        entry
        for entry in os.listdir(cef_dir)
        if entry not in staged_names and entry != "locales"
    )
    print(f"[INFO] Staged CEF root files ({len(staged_names)}): {', '.join(sorted(staged_names))}")
    if skipped:
        print(f"[INFO] Unstaged entries in CEF dir: {', '.join(skipped[:20])}")

    locales_src = os.path.join(cef_dir, "locales")
    for loc in ("en-US.pak", "fr.pak"):
        src = os.path.join(locales_src, loc)
        if os.path.isfile(src):
            shutil.copy2(src, os.path.join(locales_dst, loc))

    for required in ("singularity.exe", "libcef.dll", "icudtl.dat", "resources.pak"):
        path = os.path.join(stage_dir, required)
        if not os.path.isfile(path):
            print(f"ERROR: Missing required Pure Chromium runtime file: {path}", file=sys.stderr)
            return 1

    raw_bytes = 0
    file_count = 0
    with zipfile.ZipFile(bundle_zip, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for dp, _, fns in os.walk(stage_dir):
            for fn in sorted(fns):
                full = os.path.join(dp, fn)
                rel = os.path.relpath(full, stage_dir).replace("\\", "/")
                raw_bytes += os.path.getsize(full)
                file_count += 1
                zf.write(full, rel)

    zip_bytes = os.path.getsize(bundle_zip)
    print(
        f"[OK] Packaged {file_count} Pure Chromium CEF runtime files into {bundle_zip}: "
        f"{zip_bytes / 1048576:.2f} MB compressed ({raw_bytes / 1048576:.2f} MB uncompressed)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
