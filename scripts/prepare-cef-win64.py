#!/usr/bin/env python3
"""Downloads, SHA-256-verifies, and stages OBS Studio's proprietary-codec-enabled
Pure Chromium (CEF 150 / branch 7871) Windows x64 SDK into CEF_PATH in the exact
flattened directory layout expected by `cef-dll-sys` (`=150.2.1+150.0.14`) and
`scripts/package-windows-cef.py`.

Why OBS's official CEF 150/7871 build instead of Spotify's default CEF CDN?
Spotify's prebuilt binaries compile with `proprietary_codecs=false`, stripping H.264
(`avc1`) and AAC (`mp4a`) decoders so MP4 / MSE videos on TikTok, Instagram, X, and
Twitch fail to play. OBS Studio's official CEF 150/7871 build is pure Chromium with
`proprietary_codecs=true` and `ffmpeg_branding=Chrome`, pinned by exact SHA-256 from
`obsproject/obs-studio` `CMakePresets.json`.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import time
import urllib.request
import zipfile
from pathlib import Path

OBS_CEF_URL = "https://cdn-fastly.obsproject.com/downloads/cef_binary_7871_windows_x64.zip"
OBS_CEF_SHA256 = "54cd191a3f56bb1f05be22b95e1fa8041061b38bd5fe94e0776fb34dd599f341"
EXPECTED_CEF_MAJOR = 150
# `download-cef` validates `archive <= expected` where `cef-dll-sys = 150.2.1+150.0.14`
# expects `<= 150.0.14`. Keeping `150.0.14` here guarantees `cef-dll-sys` uses our
# staged CEF_PATH directly without ever falling back to Spotify CDN.
ARCHIVE_JSON_NAME = "cef_binary_150.0.14+obs-7871_windows64_minimal.tar.bz2"
STAMP_FILENAME = ".singularity-cef-stamp.json"

REQUIRED_STAGED_FILES = (
    "archive.json",
    "CMakeLists.txt",
    "libcef.dll",
    "libcef.lib",
    "icudtl.dat",
    "resources.pak",
    os.path.join("include", "cef_version.h"),
    os.path.join("include", "cef_api_versions.h"),
    os.path.join("libcef_dll", "CMakeLists.txt"),
    os.path.join("cmake", "cef_variables.cmake"),
    os.path.join("locales", "en-US.pak"),
    os.path.join("locales", "fr.pak"),
)


def is_already_staged(cef_dir: Path) -> bool:
    stamp_path = cef_dir / STAMP_FILENAME
    if not stamp_path.is_file():
        return False
    try:
        stamp = json.loads(stamp_path.read_text(encoding="utf-8"))
    except Exception:
        return False
    if stamp.get("sha256") != OBS_CEF_SHA256 or stamp.get("archive_name") != ARCHIVE_JSON_NAME:
        return False
    # Ensure no versioned Spotify fallback subdirectory lingers inside CEF_PATH
    if (cef_dir / "150.0.14").exists():
        return False
    for rel in REQUIRED_STAGED_FILES:
        if not (cef_dir / rel).is_file():
            return False
    return True


def download_with_hashes(url: str, dest: Path) -> tuple[str, str, int]:
    last_err: Exception | None = None
    for attempt in range(1, 4):
        try:
            print(f"[INFO] Downloading Pure Chromium CEF 150/7871 SDK (attempt {attempt}/3): {url}")
            req = urllib.request.Request(url, headers={"User-Agent": "Singularity-CI/2.0.5"})
            sha256 = hashlib.sha256()
            sha1 = hashlib.sha1()
            total = 0
            with urllib.request.urlopen(req, timeout=120) as resp, dest.open("wb") as out:
                content_len = int(resp.headers.get("Content-Length") or 0)
                last_pct = -10
                while True:
                    chunk = resp.read(1024 * 1024)
                    if not chunk:
                        break
                    out.write(chunk)
                    sha256.update(chunk)
                    sha1.update(chunk)
                    total += len(chunk)
                    if content_len > 0:
                        pct = int(total * 100 / content_len)
                        if pct >= last_pct + 20:
                            last_pct = pct
                            print(
                                f"[INFO]   {pct}% ({total / 1048576:.1f} / {content_len / 1048576:.1f} MB)"
                            )
            return sha256.hexdigest(), sha1.hexdigest(), total
        except Exception as exc:
            last_err = exc
            print(f"[WARN] Download attempt {attempt} failed: {exc}", file=sys.stderr)
            if attempt < 3:
                time.sleep(5 * attempt)
    raise RuntimeError(f"Failed to download {url} after 3 attempts: {last_err}")


def safe_extract_zip(zip_path: Path, dest_dir: Path) -> None:
    dest_resolved = dest_dir.resolve()
    with zipfile.ZipFile(zip_path, "r") as zf:
        for info in zf.infolist():
            target = (dest_dir / info.filename).resolve()
            if target != dest_resolved and dest_resolved not in target.parents:
                raise RuntimeError(f"Refusing Zip Slip entry: {info.filename}")
        zf.extractall(dest_dir)


def find_sdk_root(extract_dir: Path) -> Path:
    if (extract_dir / "CMakeLists.txt").is_file() and (extract_dir / "include").is_dir():
        return extract_dir
    for child in sorted(extract_dir.iterdir()):
        if child.is_dir() and (child / "CMakeLists.txt").is_file() and (child / "include").is_dir():
            return child
    entries = [p.name for p in sorted(extract_dir.iterdir())]
    raise RuntimeError(f"Could not locate CEF SDK root inside {extract_dir} (entries: {entries})")


def copy_tree_flattened(src_dir: Path, dst_dir: Path, *, skip_pdbs: bool = True) -> None:
    if not src_dir.is_dir():
        raise RuntimeError(f"Missing expected directory in CEF archive: {src_dir}")
    for entry in sorted(src_dir.iterdir()):
        if skip_pdbs and entry.is_file() and entry.suffix.lower() == ".pdb":
            continue
        target = dst_dir / entry.name
        if entry.is_dir():
            if target.exists():
                shutil.rmtree(target)
            shutil.copytree(entry, target)
        else:
            shutil.copy2(entry, target)


def inspect_cef_headers(cef_dir: Path) -> tuple[str, int, int]:
    ver_header = (cef_dir / "include" / "cef_version.h").read_text(encoding="utf-8", errors="replace")
    api_header = (cef_dir / "include" / "cef_api_versions.h").read_text(encoding="utf-8", errors="replace")

    m_ver = re.search(r'#define\s+CEF_VERSION\s+"([^"]+)"', ver_header)
    m_maj = re.search(r"#define\s+CEF_VERSION_MAJOR\s+(\d+)", ver_header)
    m_api = re.search(r"#define\s+CEF_API_VERSION_LAST\s+(\d+)", api_header)

    cef_ver = m_ver.group(1) if m_ver else "unknown"
    cef_maj = int(m_maj.group(1)) if m_maj else -1
    api_last = int(m_api.group(1)) if m_api else -1
    return cef_ver, cef_maj, api_last


def print_staged_summary(cef_dir: Path) -> None:
    cef_ver, cef_maj, api_last = inspect_cef_headers(cef_dir)
    print(
        f"[OK] Staged CEF SDK at {cef_dir}: CEF_VERSION={cef_ver}, "
        f"CEF_VERSION_MAJOR={cef_maj}, CEF_API_VERSION_LAST={api_last}"
    )
    if cef_maj != EXPECTED_CEF_MAJOR:
        raise RuntimeError(
            f"Unexpected CEF_VERSION_MAJOR={cef_maj} (expected {EXPECTED_CEF_MAJOR})"
        )
    files = sorted(p for p in cef_dir.iterdir() if p.is_file())
    summary = ", ".join(f"{p.name} ({p.stat().st_size / 1048576:.1f} MB)" for p in files)
    print(f"[INFO] Root files ({len(files)}): {summary}")


def stage_sdk(cef_dir: Path) -> int:
    if is_already_staged(cef_dir):
        print(f"[OK] Reusing cached proprietary-codec CEF 150/7871 SDK at {cef_dir}")
        print_staged_summary(cef_dir)
        return 0

    cef_dir.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=".singularity-obs-cef-", dir=str(cef_dir.parent)
    ) as tmp:
        tmp_path = Path(tmp)
        zip_path = tmp_path / "cef_binary_7871_windows_x64.zip"
        got_sha256, got_sha1, total_bytes = download_with_hashes(OBS_CEF_URL, zip_path)
        print(f"[INFO] Downloaded {total_bytes / 1048576:.2f} MB (SHA-256: {got_sha256})")
        if got_sha256.lower() != OBS_CEF_SHA256.lower():
            raise RuntimeError(
                f"SHA-256 mismatch for {OBS_CEF_URL}: expected {OBS_CEF_SHA256}, got {got_sha256}"
            )
        print("[OK] Verified SHA-256 matches OBS Studio CMakePresets.json pin")

        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir(parents=True, exist_ok=True)
        print("[INFO] Extracting CEF archive...")
        safe_extract_zip(zip_path, extract_dir)
        sdk_root = find_sdk_root(extract_dir)
        root_entries = ", ".join(p.name for p in sorted(sdk_root.iterdir()))
        print(f"[INFO] Located CEF SDK root: {sdk_root.name} (entries: {root_entries})")

        staging = tmp_path / "staged"
        staging.mkdir(parents=True, exist_ok=True)

        # Match `download-cef`'s exact flattened layout: Release/* + Resources/* + CMake/headers/wrapper
        copy_tree_flattened(sdk_root / "Release", staging, skip_pdbs=True)
        copy_tree_flattened(sdk_root / "Resources", staging, skip_pdbs=True)

        for req_dir in ("cmake", "include", "libcef_dll"):
            src = sdk_root / req_dir
            if not src.is_dir():
                raise RuntimeError(f"Missing required CEF SDK directory: {src}")
            shutil.copytree(src, staging / req_dir)

        shutil.copy2(sdk_root / "CMakeLists.txt", staging / "CMakeLists.txt")
        for opt_file in ("CREDITS.html", "LICENSE.txt", "README.txt"):
            opt_src = sdk_root / opt_file
            if opt_src.is_file():
                shutil.copy2(opt_src, staging / opt_file)

        # Write `archive.json` compatible with `download-cef 2.3.2` (`CefFile`)
        archive_meta = {
            "type": "minimal",
            "name": ARCHIVE_JSON_NAME,
            "sha1": got_sha1,
        }
        (staging / "archive.json").write_text(
            json.dumps(archive_meta, indent=2) + "\n", encoding="utf-8"
        )

        stamp = {
            "url": OBS_CEF_URL,
            "sha256": OBS_CEF_SHA256,
            "sha1": got_sha1,
            "archive_name": ARCHIVE_JSON_NAME,
        }
        (staging / STAMP_FILENAME).write_text(
            json.dumps(stamp, indent=2) + "\n", encoding="utf-8"
        )

        for rel in REQUIRED_STAGED_FILES:
            if not (staging / rel).is_file():
                raise RuntimeError(f"Staged CEF SDK missing required file: {rel}")

        if cef_dir.exists():
            shutil.rmtree(cef_dir)
        shutil.move(str(staging), str(cef_dir))

    print_staged_summary(cef_dir)
    return 0


def main() -> int:
    if len(sys.argv) >= 2 and sys.argv[1].strip():
        target_dir = Path(sys.argv[1].strip())
    elif os.environ.get("CEF_PATH", "").strip():
        target_dir = Path(os.environ["CEF_PATH"].strip())
    else:
        print("Usage: prepare-cef-win64.py <CEF_PATH>", file=sys.stderr)
        return 2
    return stage_sdk(target_dir)


if __name__ == "__main__":
    raise SystemExit(main())
