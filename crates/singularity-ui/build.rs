use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=assets/singularity.ico");
    println!("cargo:rerun-if-changed=assets/icon_64.rgba");
    println!("cargo:rerun-if-changed=assets/logo_128.png");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        embed_windows_exe_resources();
        if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() != Ok("msvc") {
            stage_webview2_loader_dll_for_gnu();
        }
    }
}

fn embed_windows_exe_resources() {
    let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") else {
        return;
    };
    let Ok(out_dir) = std::env::var("OUT_DIR") else {
        return;
    };

    let ico_path = Path::new(&manifest_dir).join("assets").join("singularity.ico");
    let ico_escaped = ico_path.to_string_lossy().replace('\\', "/");
    let icon_line = if ico_path.is_file() {
        format!("1 ICON \"{ico_escaped}\"\r\n")
    } else {
        String::new()
    };

    let out_path = PathBuf::from(&out_dir);
    let manifest_path = out_path.join("singularity.manifest");
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

    let rc_path = out_path.join("singularity_res.rc");
    let rc_content = format!(
        "#pragma code_page(65001)\r\n\
         {icon_line}\
         1 24 \"{manifest_escaped}\"\r\n\
         1 VERSIONINFO\r\n\
         FILEVERSION 1,0,3,0\r\n\
         PRODUCTVERSION 1,0,3,0\r\n\
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
               VALUE \"FileDescription\", \"Singularity Browser\\0\"\r\n\
               VALUE \"FileVersion\", \"1.0.3.0\\0\"\r\n\
               VALUE \"InternalName\", \"singularity\\0\"\r\n\
               VALUE \"OriginalFilename\", \"singularity.exe\\0\"\r\n\
               VALUE \"ProductName\", \"Singularity\\0\"\r\n\
               VALUE \"ProductVersion\", \"1.0.3.0\\0\"\r\n\
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
        let res_path = out_path.join("singularity_res.res");
        let obj_path = out_path.join("singularity_res.o");
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
            let cvt = Command::new("llvm-cvtres")
                .args([
                    res_path.to_string_lossy().as_ref(),
                    &format!("/out:{}", obj_path.display()),
                ])
                .status()
                .is_ok_and(|s| s.success());
            if cvt && obj_path.is_file() {
                println!("cargo:rustc-link-arg-bin=singularity={}", obj_path.display());
                return;
            }
            println!("cargo:rustc-link-arg-bin=singularity={}", res_path.display());
            return;
        }
    }

    if let Some(windres) = find_windres_exe() {
        let obj_output = out_path.join("singularity_res.o");
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
                "cargo:rustc-link-arg-bin=singularity={}",
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

fn stage_webview2_loader_dll_for_gnu() {
    let Ok(out_dir) = std::env::var("OUT_DIR") else {
        return;
    };
    let dest = Path::new(&out_dir).join("WebView2Loader.dll");
    if dest.is_file() {
        return;
    }

    let mut cargo_roots = Vec::new();
    if let Ok(ch) = std::env::var("CARGO_HOME") {
        cargo_roots.push(PathBuf::from(ch));
    }
    if let Ok(home) = std::env::var("HOME") {
        cargo_roots.push(Path::new(&home).join(".cargo"));
    }
    if let Ok(up) = std::env::var("USERPROFILE") {
        cargo_roots.push(PathBuf::from(up).join(".cargo"));
    }

    let arch_dir = match std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("aarch64") => "arm64",
        Ok("x86") => "x86",
        _ => "x64",
    };

    for root in cargo_roots {
        let reg_src = root.join("registry").join("src");
        let Ok(indices) = std::fs::read_dir(&reg_src) else {
            continue;
        };
        for idx in indices.flatten() {
            let Ok(crates) = std::fs::read_dir(idx.path()) else {
                continue;
            };
            let mut matches: Vec<PathBuf> = crates
                .flatten()
                .map(|e| e.path())
                .filter(|p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|s| s.starts_with("webview2-com-sys-"))
                })
                .collect();
            matches.sort();
            matches.reverse();
            for crate_dir in matches {
                let dll = crate_dir.join(arch_dir).join("WebView2Loader.dll");
                if dll.is_file() && std::fs::copy(&dll, &dest).is_ok() {
                    return;
                }
            }
        }
    }
    panic!("WebView2Loader.dll ({arch_dir}) not found in Cargo registry cache for webview2-com-sys");
}
