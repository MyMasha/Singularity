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
$TargetExe = Join-Path $InstallDir "singularity.exe"
$NewExe = Join-Path $InstallDir "singularity.new.exe"
$OldExe = Join-Path $InstallDir "singularity.exe.old"
$SumsFile = Join-Path $InstallDir "SHA256SUMS.new.txt"
$Ua = "Singularity-Updater/1.0"

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

$binAsset = $release.assets | Where-Object { $_.name -eq "singularity.exe" } | Select-Object -First 1
$sumAsset = $release.assets | Where-Object { $_.name -eq "SHA256SUMS.txt" } | Select-Object -First 1

if ($null -eq $binAsset -or $null -eq $sumAsset) {
    throw "Required release assets (singularity.exe and SHA256SUMS.txt) are not attached to release $tag yet."
}
if (-not $binAsset.browser_download_url.StartsWith("https://") -or -not $sumAsset.browser_download_url.StartsWith("https://")) {
    throw "Refused non-HTTPS download URL."
}

Write-Host "[2/4] Downloading singularity.exe and SHA256SUMS.txt..." -ForegroundColor Gray
Invoke-WebRequest -Uri $binAsset.browser_download_url -Headers $pubHeaders -OutFile $NewExe -UseBasicParsing -TimeoutSec 60
Invoke-WebRequest -Uri $sumAsset.browser_download_url -Headers $pubHeaders -OutFile $SumsFile -UseBasicParsing -TimeoutSec 30

Write-Host "[3/4] Verifying SHA-256 cryptographic integrity..." -ForegroundColor Gray
$expectedHash = $null
foreach ($line in (Get-Content -LiteralPath $SumsFile)) {
    if ($line -match '^\s*([A-Fa-f0-9]{64})\s+\*?singularity\.exe\s*$') {
        $expectedHash = $Matches[1].ToLowerInvariant()
        break
    }
}
Remove-Item -LiteralPath $SumsFile -Force -ErrorAction SilentlyContinue

if (-not $expectedHash) {
    Remove-Item -LiteralPath $NewExe -Force -ErrorAction SilentlyContinue
    throw "SHA-256 checksum for singularity.exe missing in SHA256SUMS.txt."
}

$actualHash = (Get-FileHash -LiteralPath $NewExe -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualHash -ne $expectedHash) {
    Remove-Item -LiteralPath $NewExe -Force -ErrorAction SilentlyContinue
    throw "SHA-256 mismatch! Expected=$expectedHash Actual=$actualHash. Update aborted."
}
Write-Host "      SHA-256 verified: $actualHash" -ForegroundColor Green

Write-Host "[4/4] Stopping running Singularity instances and updating..." -ForegroundColor Gray
Get-Process -Name "singularity" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 600

if (Test-Path -LiteralPath $OldExe) { Remove-Item -LiteralPath $OldExe -Force -ErrorAction SilentlyContinue }
if (Test-Path -LiteralPath $TargetExe) { Move-Item -LiteralPath $TargetExe -Destination $OldExe -Force }
Move-Item -LiteralPath $NewExe -Destination $TargetExe -Force

Write-Host ""
Write-Host "[OK] Singularity $tag installed and verified." -ForegroundColor Green
Write-Host "     Launching Singularity..." -ForegroundColor Cyan
Start-Process -FilePath $TargetExe
