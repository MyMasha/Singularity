#!/usr/bin/env python3
"""Stages singularity.exe + Pure Chromium (CEF) runtime files (EN/FR locales only)
and compresses them into dist/singularity-bundle.zip for Singularity-Setup.exe."""

import glob
import os
import shutil
import sys
import zipfile


def main() -> int:
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

    for pattern in ("*.dll", "*.dat", "*.bin", "*.pak", "vk_swiftshader_icd.json"):
        for src in glob.glob(os.path.join(release_dir, pattern)):
            if os.path.isfile(src):
                shutil.copy2(src, os.path.join(stage_dir, os.path.basename(src)))

    locales_src = os.path.join(release_dir, "locales")
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
