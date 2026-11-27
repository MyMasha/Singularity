<#
.SYNOPSIS
    Bootstraps a reproducible local Windows x64 development environment for Singularity Browser.
.DESCRIPTION
    1. Stages OBS Studio's proprietary-codec (H.264/AAC) CEF 150/7871 SDK into `<repo>\.cef-sdk`
       (picked up automatically by `.cargo/config.toml` when `CEF_PATH` is not already set).
    2. Ensures `ninja.exe` (required by `cef-dll-sys` CMake build) is reachable on `PATH`,
       auto-discovering Visual Studio's bundled Ninja if needed.
.EXAMPLE
    . .\scripts\dev-env-win64.ps1
    cargo test --workspace --locked
#>
[CmdletBinding()]
param(
    [switch]$InstallLocalNinja
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$cefDir = Join-Path $repoRoot ".cef-sdk"
$prepareScript = Join-Path $PSScriptRoot "prepare-cef-win64.py"

Write-Host "[Singularity] Staging CEF 150 (OBS 7871, H.264/AAC) SDK into $cefDir ..."
& python $prepareScript $cefDir
if ($LASTEXITCODE -ne 0) {
    throw "prepare-cef-win64.py failed with exit code $LASTEXITCODE"
}

if (-not (Get-Command ninja -ErrorAction SilentlyContinue)) {
    $vsRoots = @(
        "C:\Program Files\Microsoft Visual Studio",
        "C:\Program Files (x86)\Microsoft Visual Studio"
    ) | Where-Object { Test-Path $_ }

    $vsNinja = $vsRoots |
        ForEach-Object { Get-ChildItem -Path $_ -Recurse -Filter "ninja.exe" -ErrorAction SilentlyContinue } |
        Select-Object -First 1

    if (-not $vsNinja) {
        throw "ninja.exe not found on PATH or in Visual Studio installations. Install Ninja (e.g. 'winget install Ninja-build.Ninja' or VS CMake tools)."
    }

    $localBin = Join-Path $env:USERPROFILE ".local\bin"
    if ($InstallLocalNinja -and (Test-Path $localBin)) {
        Copy-Item -Path $vsNinja.FullName -Destination (Join-Path $localBin "ninja.exe") -Force
        Write-Host "[Singularity] Installed ninja.exe into $localBin"
    }

    $env:PATH = "$($vsNinja.DirectoryName);$env:PATH"
    Write-Host "[Singularity] Added Visual Studio Ninja to session PATH: $($vsNinja.DirectoryName)"
}

$env:CEF_DOWNLOAD_URL = "http://127.0.0.1:1/forbidden-spotify-fallback"
Write-Host "[Singularity] Ready. Run: cargo test --workspace --locked"
