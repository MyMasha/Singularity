#!/usr/bin/env python3
"""Stages singularity.exe + Pure Chromium (CEF) runtime files (EN/FR locales only),
compresses them into dist/singularity-bundle.zip, and optionally attaches the ZIP
as a standard self-extracting PE overlay onto Singularity-Setup.exe."""

import glob
import os
import shutil
import sys
import zipfile


def find_cef_runtime_dir() -> str | None:
    """Locate the directory containing libcef.dll, icudtl.dat, and resources.pak."""
    candidates: list[str] = []
    cef_env = os.environ.get("CEF_PATH", "").strip()
    if cef_env and os.path.isdir(cef_env):
        candidates.append(cef_env)
    candidates.extend([
        os.path.join("target", "release"),
        os.path.join("target", "release", "build"),
        os.path.join("target", "debug"),
        os.path.join("target", "debug", "build"),
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
            dns[:] = [d for d in dns if d not in ("include", "libcef_dll", "cmake", "out", "CMakeFiles")]
            if "libcef.dll" in fns and "icudtl.dat" in fns:
                return dp
    return None


def attach_sfx(stub_exe: str, bundle_zip: str, output_exe: str) -> int:
    os.makedirs(os.path.dirname(output_exe) or ".", exist_ok=True)
    with open(output_exe, "wb") as out_f:
        with open(stub_exe, "rb") as stub_f:
            shutil.copyfileobj(stub_f, out_f, 1024 * 1024)
        with open(bundle_zip, "rb") as zip_f:
            shutil.copyfileobj(zip_f, out_f, 1024 * 1024)
    total_mb = os.path.getsize(output_exe) / 1048576.0
    print(f"[OK] Built self-extracting Windows installer {output_exe}: {total_mb:.2f} MB")
    return 0


def main() -> int:
    if len(sys.argv) == 5 and sys.argv[1] == "--attach-sfx":
        return attach_sfx(sys.argv[2], sys.argv[3], sys.argv[4])

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
        print(f"ERROR: Missing {exe_src}", file=sys.stderr)
        return 1
    shutil.copy2(exe_src, os.path.join(stage_dir, "singularity.exe"))

    cef_dir = find_cef_runtime_dir()
    if not cef_dir:
        print(
            f"ERROR: Could not locate Pure Chromium CEF runtime directory (CEF_PATH={os.environ.get('CEF_PATH', '')})",
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
