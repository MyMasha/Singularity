use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=SINGULARITY_RELEASE_SIGNING_PUBKEY_HEX");
    let target_is_windows = std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows");
    let rel_payload = if target_is_windows {
        "../../dist/singularity-bundle.zip"
    } else {
        "../../dist/singularity-linux-x86_64"
    };
    println!("cargo:rerun-if-changed={rel_payload}");
    println!("cargo:rerun-if-changed=../singularity-ui/assets/singularity.ico");
    println!("cargo:rerun-if-changed=../singularity-ui/assets/logo_128.rgba");

    if let (Ok(manifest_dir), Ok(out_dir)) = (
        std::env::var("CARGO_MANIFEST_DIR"),
        std::env::var("OUT_DIR"),
    ) {
        let raw_src = Path::new(&manifest_dir).join(rel_payload);
        let dst = Path::new(&out_dir).join("embedded_singularity.bin");
        if target_is_windows {
            // Pure Chromium CEF bundle is attached as an authenticated SGX1 PE SFX ZIP overlay
            // after linking (`scripts/package-windows-cef.py --attach-sfx`), avoiding 100+ MB
            // LLVM LTO bitcode bloat and keeping installer startup <5ms.
            std::fs::write(&dst, b"").expect("Failed to write empty embedded_singularity.bin stub");
        } else if raw_src.is_file() {
            std::fs::copy(&raw_src, &dst)
                .expect("Failed to copy Linux payload into embedded_singularity.bin");
        } else {
            std::fs::write(&dst, b"").expect("Failed to write empty embedded_singularity.bin");
        }
    }

    if target_is_windows {
        let is_msvc = std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc");
        if is_msvc {
            // Restrict Windows PE loader dependent DLL search to System32 (0x800 = LOAD_LIBRARY_SEARCH_SYSTEM32)
            // before CRT / main() runs, neutralizing DLL hijacking from Downloads / current directory.
            println!("cargo:rustc-link-arg=/DEPENDENTLOADFLAG:0x800");
        }
        embed_windows_exe_resources(is_msvc);
    }
}

fn embed_windows_exe_resources(is_msvc: bool) {
    let manifest_dir =
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set");
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR must be set");

    let ico_path = Path::new(&manifest_dir)
        .join("..")
        .join("singularity-ui")
        .join("assets")
        .join("singularity.ico");
    let ico_escaped = ico_path.to_string_lossy().replace('\\', "/");
    let icon_line = if ico_path.is_file() {
        format!("1 ICON \"{ico_escaped}\"\r\n")
    } else {
        String::new()
    };

    let out_path = PathBuf::from(&out_dir);

    // Explicit `asInvoker` + `PerMonitorV2` manifest prevents Windows UAC Installer Detection / PCA
    // from freezing or elevating `Singularity-Setup.exe` and enables sharp High-DPI rendering.
    let manifest_path = out_path.join("singularity_setup.manifest");
    let manifest_xml = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0" xmlns:asmv3="urn:schemas-microsoft-com:asm.v3">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
    </application>
  </compatibility>
  <asmv3:application>
    <asmv3:windowsSettings>
      <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true/pm</dpiAware>
      <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2,PerMonitor</dpiAwareness>
    </asmv3:windowsSettings>
  </asmv3:application>
</assembly>
"#;
    std::fs::write(&manifest_path, manifest_xml)
        .expect("Failed to write Windows asInvoker manifest file");
    let manifest_escaped = manifest_path.to_string_lossy().replace('\\', "/");

    let rc_path = out_path.join("singularity_setup_res.rc");
    let rc_content = format!(
        "#pragma code_page(65001)\r\n\
         {icon_line}\
         1 24 \"{manifest_escaped}\"\r\n\
         1 VERSIONINFO\r\n\
         FILEVERSION 3,0,2,0\r\n\
         PRODUCTVERSION 3,0,2,0\r\n\
         FILEFLAGSMASK 0x3fL\r\n\
         FILEFLAGS 0x0L\r\n\
         FILEOS 0x40004L\r\n\
         FILETYPE 0x1L\r\n\
         FILESUBTYPE 0x0L\r\n\
         BEGIN\r\n\
           BLOCK \"StringFileInfo\"\r\n\
           BEGIN\r\n\
             BLOCK \"040904b0\"\r\n\
             BEGIN\r\n\
               VALUE \"CompanyName\", \"Singularity\\0\"\r\n\
               VALUE \"FileDescription\", \"Singularity Setup\\0\"\r\n\
               VALUE \"FileVersion\", \"3.0.2.0\\0\"\r\n\
               VALUE \"InternalName\", \"Singularity-Setup\\0\"\r\n\
               VALUE \"OriginalFilename\", \"Singularity-Setup.exe\\0\"\r\n\
               VALUE \"ProductName\", \"Singularity\\0\"\r\n\
               VALUE \"ProductVersion\", \"3.0.2.0\\0\"\r\n\
             END\r\n\
           END\r\n\
           BLOCK \"VarFileInfo\"\r\n\
           BEGIN\r\n\
             VALUE \"Translation\", 0x0409, 1200\r\n\
           END\r\n\
         END\r\n"
    );
    std::fs::write(&rc_path, rc_content)
        .expect("Failed to write Windows resource script (singularity_setup_res.rc)");

    if is_msvc {
        let res_path = out_path.join("singularity_setup_res.res");
        let compiled_rc = find_msvc_rc_exe()
            .is_some_and(|rc_exe| {
                Command::new(rc_exe)
                    .args([
                        "/nologo",
                        "/fo",
                        res_path.to_string_lossy().as_ref(),
                        rc_path.to_string_lossy().as_ref(),
                    ])
                    .status()
                    .is_ok_and(|s| s.success())
            })
            || Command::new("llvm-rc")
                .args([
                    rc_path.to_string_lossy().as_ref(),
                    "/fo",
                    res_path.to_string_lossy().as_ref(),
                ])
                .status()
                .is_ok_and(|s| s.success());
        if !compiled_rc || !res_path.is_file() {
            let allow_cross_check_skip = !cfg!(target_os = "windows")
                && std::env::var("PROFILE").as_deref() != Ok("release")
                && std::env::var("SINGULARITY_CROSS_CHECK_SKIP_RC").as_deref() == Ok("1");
            if allow_cross_check_skip {
                println!("cargo:warning=Skipping Windows .rc compilation during non-Windows debug cross-check (SINGULARITY_CROSS_CHECK_SKIP_RC=1).");
                return;
            }
            panic!(
                "Failed to compile Windows asInvoker manifest resource '{}' with rc.exe or llvm-rc. \
                 Refusing to build Singularity-Setup.exe without an embedded asInvoker manifest.",
                rc_path.display()
            );
        }
        println!(
            "cargo:rustc-link-arg-bin=Singularity-Setup={}",
            res_path.display()
        );
        return;
    }

    let Some(windres) = find_windres_exe() else {
        panic!(
            "No Windows resource compiler (x86_64-w64-mingw32-windres / llvm-windres) found. \
             Refusing to build Singularity-Setup.exe without an embedded asInvoker manifest."
        );
    };
    let obj_output = out_path.join("singularity_setup_res.o");
    let compiled = Command::new(&windres)
        .arg("-i")
        .arg(&rc_path)
        .arg("-o")
        .arg(&obj_output)
        .status()
        .is_ok_and(|s| s.success());
    if !compiled || !obj_output.is_file() {
        panic!(
            "Failed to compile Windows asInvoker manifest resource '{}' with '{}'. \
             Refusing to build Singularity-Setup.exe without an embedded asInvoker manifest.",
            rc_path.display(),
            windres.display()
        );
    }
    println!(
        "cargo:rustc-link-arg-bin=Singularity-Setup={}",
        obj_output.display()
    );
}

fn find_msvc_rc_exe() -> Option<PathBuf> {
    if Command::new("rc.exe").arg("/?").output().is_ok() {
        return Some(PathBuf::from("rc.exe"));
    }
    let kits = PathBuf::from(r"C:\Program Files (x86)\Windows Kits\10\bin");
    let mut versions: Vec<PathBuf> = std::fs::read_dir(&kits)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    versions.sort();
    versions.reverse();
    for ver in versions {
        let cand = ver.join("x64").join("rc.exe");
        if cand.is_file() {
            return Some(cand);
        }
    }
    None
}

fn find_windres_exe() -> Option<PathBuf> {
    let mut candidates = vec![
        PathBuf::from("x86_64-w64-mingw32-windres"),
        PathBuf::from("llvm-windres"),
    ];
    if let Ok(home) = std::env::var("HOME") {
        candidates.insert(
            0,
            Path::new(&home)
                .join(".cache")
                .join("llvm-mingw")
                .join("bin")
                .join("x86_64-w64-mingw32-windres"),
        );
    }
    for cand in candidates {
        if Command::new(&cand).arg("--version").output().is_ok() {
            return Some(cand);
        }
    }
    None
}
