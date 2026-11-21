# Singularity Browser — Official Public Windows Self-Updater (SHA-256 Verified)
# Downloads directly from https://github.com/MyMasha/Singularity/releases (zero embedded tokens)
param(
    [string]$InstallDir = $PSScriptRoot,
    [string]$Token = $env:SINGULARITY_GITHUB_TOKEN
)

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Repo = "MyMasha/Singularity"
$ApiUrl = "https://api.github.com/repos/$Repo/releases/latest"
$SetupExe = Join-Path ([System.IO.Path]::GetTempPath()) "Singularity-setup-update.exe"
$SumsFile = Join-Path ([System.IO.Path]::GetTempPath()) "Singularity-SHA256SUMS.txt"
$Ua = "Singularity-Updater/2.0"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  SINGULARITY BROWSER — VERIFIED AUTO-UPDATER (SHA-256)" -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Cyan

$pubHeaders = @{ "User-Agent" = $Ua }
$apiHeaders = @{
    "User-Agent" = $Ua
    "Accept"     = "application/vnd.github+json"
}
if ($Token -and $Token.Trim().Length -gt 0) {
    $apiHeaders["Authorization"] = "Bearer $($Token.Trim())"
}

Write-Host "[1/4] Checking latest public release at https://github.com/$Repo ..." -ForegroundColor Gray
try {
    $release = Invoke-RestMethod -Uri $ApiUrl -Headers $apiHeaders -UseBasicParsing -TimeoutSec 15
} catch {
    if ($apiHeaders.ContainsKey("Authorization")) {
        $apiHeaders.Remove("Authorization")
        $release = Invoke-RestMethod -Uri $ApiUrl -Headers $apiHeaders -UseBasicParsing -TimeoutSec 15
    } else {
        throw
    }
}

$tag = $release.tag_name
if (-not ($tag -match '^[A-Za-z0-9._-]+$')) {
    throw "Invalid GitHub release tag: $tag"
}
Write-Host "      Release found: $tag" -ForegroundColor Green

$setupAsset = $release.assets | Where-Object { $_.name -eq "Singularity-setup.exe" } | Select-Object -First 1
$sumAsset = $release.assets | Where-Object { $_.name -eq "SHA256SUMS.txt" } | Select-Object -First 1

if ($null -eq $setupAsset -or $null -eq $sumAsset) {
    throw "Required release assets (Singularity-setup.exe and SHA256SUMS.txt) are not attached to release $tag yet."
}
if (-not $setupAsset.browser_download_url.StartsWith("https://") -or -not $sumAsset.browser_download_url.StartsWith("https://")) {
    throw "Refused non-HTTPS download URL."
}

Write-Host "[2/4] Downloading Singularity-setup.exe (Pure Chromium CEF bundle) and SHA256SUMS.txt..." -ForegroundColor Gray
Invoke-WebRequest -Uri $setupAsset.browser_download_url -Headers $pubHeaders -OutFile $SetupExe -UseBasicParsing -TimeoutSec 180
Invoke-WebRequest -Uri $sumAsset.browser_download_url -Headers $pubHeaders -OutFile $SumsFile -UseBasicParsing -TimeoutSec 30

Write-Host "[3/4] Verifying SHA-256 cryptographic integrity..." -ForegroundColor Gray
$expectedHash = $null
foreach ($line in (Get-Content -LiteralPath $SumsFile)) {
    if ($line -match '^\s*([A-Fa-f0-9]{64})\s+\*?Singularity-setup\.exe\s*$') {
        $expectedHash = $Matches[1].ToLowerInvariant()
        break
    }
}
Remove-Item -LiteralPath $SumsFile -Force -ErrorAction SilentlyContinue

if (-not $expectedHash) {
    Remove-Item -LiteralPath $SetupExe -Force -ErrorAction SilentlyContinue
    throw "SHA-256 checksum for Singularity-setup.exe missing in SHA256SUMS.txt."
}

$actualHash = (Get-FileHash -LiteralPath $SetupExe -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualHash -ne $expectedHash) {
    Remove-Item -LiteralPath $SetupExe -Force -ErrorAction SilentlyContinue
    throw "SHA-256 mismatch! Expected=$expectedHash Actual=$actualHash. Update aborted."
}
Write-Host "      SHA-256 verified: $actualHash" -ForegroundColor Green

Write-Host "[4/4] Installing Singularity $tag + Pure Chromium runtime into $InstallDir ..." -ForegroundColor Gray
& $SetupExe --silent --dir $InstallDir --launch
Remove-Item -LiteralPath $SetupExe -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "[OK] Singularity $tag installed and verified." -ForegroundColor Green
