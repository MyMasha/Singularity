use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let target_is_windows = std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows");
    let rel_payload = if target_is_windows {
        "../../dist/singularity.exe"
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
        let src = Path::new(&manifest_dir).join(rel_payload);
        let dst = Path::new(&out_dir).join("embedded_singularity.bin");
        if src.is_file() {
            let _ = std::fs::copy(&src, &dst);
        } else {
            let _ = std::fs::write(&dst, b"");
            if std::env::var("PROFILE").as_deref() == Ok("release") {
                println!(
                    "cargo:warning=Singularity payload ({rel_payload}) not found; build `singularity` first and stage it to `dist/` before packaging Singularity-Setup."
                );
            }
        }
    }

    if target_is_windows {
        embed_windows_exe_resources();
    }
}

fn embed_windows_exe_resources() {
    let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") else {
        return;
    };
    let Ok(out_dir) = std::env::var("OUT_DIR") else {
        return;
    };

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
    let _ = std::fs::write(&manifest_path, manifest_xml);
    let manifest_escaped = manifest_path.to_string_lossy().replace('\\', "/");

    let rc_path = out_path.join("singularity_setup_res.rc");
    let rc_content = format!(
        "#pragma code_page(65001)\r\n\
         {icon_line}\
         1 24 \"{manifest_escaped}\"\r\n\
         1 VERSIONINFO\r\n\
         FILEVERSION 1,0,4,0\r\n\
         PRODUCTVERSION 1,0,4,0\r\n\
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
               VALUE \"FileVersion\", \"1.0.4.0\\0\"\r\n\
               VALUE \"InternalName\", \"Singularity-Setup\\0\"\r\n\
               VALUE \"OriginalFilename\", \"Singularity-Setup.exe\\0\"\r\n\
               VALUE \"ProductName\", \"Singularity\\0\"\r\n\
               VALUE \"ProductVersion\", \"1.0.4.0\\0\"\r\n\
             END\r\n\
           END\r\n\
           BLOCK \"VarFileInfo\"\r\n\
           BEGIN\r\n\
             VALUE \"Translation\", 0x0409, 1200\r\n\
           END\r\n\
         END\r\n"
    );
    let _ = std::fs::write(&rc_path, rc_content);

    let is_msvc = std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc");
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
        if compiled_rc && res_path.is_file() {
            println!(
                "cargo:rustc-link-arg-bin=Singularity-Setup={}",
                res_path.display()
            );
            return;
        }
    }

    if let Some(windres) = find_windres_exe() {
        let obj_output = out_path.join("singularity_setup_res.o");
        let compiled = Command::new(&windres)
            .arg("-i")
            .arg(&rc_path)
            .arg("-o")
            .arg(&obj_output)
            .status()
            .is_ok_and(|s| s.success());

        if (!compiled || !obj_output.is_file()) && !icon_line.is_empty() {
            let _ = std::fs::write(&rc_path, &icon_line);
            let _ = Command::new(&windres)
                .arg("-i")
                .arg(&rc_path)
                .arg("-o")
                .arg(&obj_output)
                .status();
        }

        if obj_output.is_file() {
            println!(
                "cargo:rustc-link-arg-bin=Singularity-Setup={}",
                obj_output.display()
            );
        }
    }
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
