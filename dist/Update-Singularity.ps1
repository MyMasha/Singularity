# Singularity Browser - Official Public Windows Self-Updater (Ed25519 + SHA-256 Verified)
# Downloads directly from https://github.com/MyMasha/Singularity/releases (zero embedded tokens)
param(
    [string]$InstallDir = $PSScriptRoot,
    [string]$Token = $env:SINGULARITY_GITHUB_TOKEN,
    [string]$ReleasePubKeyHex = $env:SINGULARITY_RELEASE_SIGNING_PUBKEY_HEX,
    [switch]$AllowUnsigned
)

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Optional pinned 64-hex-character Ed25519 release signing public key (can also be provided via
# -ReleasePubKeyHex or the SINGULARITY_RELEASE_SIGNING_PUBKEY_HEX environment variable).
$DefaultReleasePubKeyHex = "3af87c325effee5f8f23e1ba7d9b8c5e7cebda70388718e87cf308237e70c155"
$Repo = "MyMasha/Singularity"
$ApiUrl = "https://api.github.com/repos/$Repo/releases/latest"
$Ua = "Singularity-Updater/3.0.1"
$AllowedDownloadHosts = @(
    "github.com",
    "api.github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
    "github-releases.githubusercontent.com"
)
$MaxUpdateRedirects = 5

function Test-ReparsePoint {
    param([Parameter(Mandatory = $true)][string]$PathToCheck)
    if (Test-Path -LiteralPath $PathToCheck) {
        $item = Get-Item -LiteralPath $PathToCheck -Force
        return (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)
    }
    return $false
}

function Assert-AllowedHttpsUrl {
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $uri = $null
    if (-not [System.Uri]::TryCreate($Url, [System.UriKind]::Absolute, [ref]$uri)) {
        throw "Refused malformed URL for ${Label}: $Url"
    }
    if ($uri.Scheme -ne "https") {
        throw "Refused non-HTTPS URL for ${Label}: $Url"
    }
    if (-not $uri.IsDefaultPort -and $uri.Port -ne 443) {
        throw "Refused non-443 HTTPS port '$($uri.Port)' for ${Label}: $Url"
    }
    if (-not [string]::IsNullOrEmpty($uri.UserInfo)) {
        throw "Refused URL containing embedded credentials for ${Label}."
    }
    $hostLower = $uri.Host.ToLowerInvariant()
    if ($AllowedDownloadHosts -notcontains $hostLower) {
        throw "Refused untrusted download host '$hostLower' for ${Label}."
    }
}

function Resolve-AllowedRedirectUrl {
    param(
        [Parameter(Mandatory = $true)][string]$CurrentUrl,
        [Parameter(Mandatory = $true)][string]$Location,
        [Parameter(Mandatory = $true)][string]$Label
    )
    if ([string]::IsNullOrWhiteSpace($Location) -or $Location -match '[\x00-\x1F\x7F]') {
        throw "Refused malformed redirect Location header for ${Label}."
    }
    $baseUri = [System.Uri]$CurrentUrl
    $nextUri = $null
    if (-not [System.Uri]::TryCreate($baseUri, $Location.Trim(), [ref]$nextUri)) {
        throw "Refused unparseable redirect Location '$Location' for ${Label}."
    }
    $resolved = $nextUri.AbsoluteUri
    Assert-AllowedHttpsUrl -Url $resolved -Label "${Label} redirect"
    return $resolved
}

function Invoke-AllowedHttpsRequest {
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [Parameter(Mandatory = $true)][string]$Label,
        [hashtable]$Headers = @{},
        [string]$OutFile = "",
        [int]$TimeoutSec = 30
    )
    Assert-AllowedHttpsUrl -Url $Url -Label $Label
    $initialUri = [System.Uri]$Url
    $currentUrl = $Url

    for ($hop = 0; $hop -le $MaxUpdateRedirects; $hop++) {
        Assert-AllowedHttpsUrl -Url $currentUrl -Label $Label
        $curUri = [System.Uri]$currentUrl
        $sameOrigin = ($curUri.Scheme -eq $initialUri.Scheme) -and
            ($curUri.Host.ToLowerInvariant() -eq $initialUri.Host.ToLowerInvariant()) -and
            ($curUri.Port -eq $initialUri.Port)

        $req = [System.Net.HttpWebRequest]::Create($currentUrl)
        $req.Method = "GET"
        $req.AllowAutoRedirect = $false
        $req.Timeout = $TimeoutSec * 1000
        $req.ReadWriteTimeout = $TimeoutSec * 1000
        $req.UserAgent = $Ua

        foreach ($k in $Headers.Keys) {
            if ($k -ieq "User-Agent") {
                $req.UserAgent = [string]$Headers[$k]
            } elseif ($k -ieq "Accept") {
                $req.Accept = [string]$Headers[$k]
            } elseif ($k -ieq "Authorization") {
                if ($sameOrigin) {
                    $req.Headers.Add("Authorization", [string]$Headers[$k])
                }
            } else {
                $req.Headers.Add($k, [string]$Headers[$k])
            }
        }

        $resp = $null
        try {
            try {
                $resp = [System.Net.HttpWebResponse]$req.GetResponse()
            } catch [System.Net.WebException] {
                if ($null -ne $_.Exception.Response) {
                    $resp = [System.Net.HttpWebResponse]$_.Exception.Response
                } else {
                    throw
                }
            }

            $status = [int]$resp.StatusCode
            if ($status -in @(301, 302, 303, 307, 308)) {
                $loc = $resp.Headers["Location"]
                if ([string]::IsNullOrWhiteSpace($loc)) {
                    throw "Redirect response ($status) missing Location header for ${Label}."
                }
                if ($hop -ge $MaxUpdateRedirects) {
                    throw "Too many HTTP redirects (exceeded maximum of $MaxUpdateRedirects hops) for ${Label}."
                }
                $currentUrl = Resolve-AllowedRedirectUrl -CurrentUrl $currentUrl -Location $loc -Label $Label
                continue
            }

            if ($status -lt 200 -or $status -ge 300) {
                throw "HTTP request failed with status $status for ${Label}."
            }

            $stream = $resp.GetResponseStream()
            try {
                if (-not [string]::IsNullOrEmpty($OutFile)) {
                    $fs = [System.IO.File]::Open($OutFile, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
                    try {
                        $stream.CopyTo($fs)
                    } finally {
                        $fs.Dispose()
                    }
                    return $null
                } else {
                    $reader = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::UTF8)
                    try {
                        return $reader.ReadToEnd()
                    } finally {
                        $reader.Dispose()
                    }
                }
            } finally {
                if ($null -ne $stream) { $stream.Dispose() }
            }
        } finally {
            if ($null -ne $resp) { $resp.Close() }
        }
    }

    throw "Too many HTTP redirects (exceeded maximum of $MaxUpdateRedirects hops) for ${Label}."
}

function Resolve-SafeInstallDir {
    param([Parameter(Mandatory = $true)][string]$RawDir)
    if ([string]::IsNullOrWhiteSpace($RawDir)) {
        throw "InstallDir must not be empty."
    }
    $trimmed = $RawDir.Trim()
    if ($trimmed.StartsWith("-") -or $trimmed.StartsWith("/")) {
        throw "Refused InstallDir starting with CLI option prefix: $trimmed"
    }
    if ($trimmed -match '[\x00-\x1F"*?<>|]') {
        throw "Refused InstallDir containing illegal or control characters: $trimmed"
    }
    $full = [System.IO.Path]::GetFullPath($trimmed)
    $root = [System.IO.Path]::GetPathRoot($full)
    if ($full.TrimEnd('\') -eq $root.TrimEnd('\')) {
        throw "Refused drive-root installation directory: $full"
    }
    $clean = $full.TrimEnd('\')
    if (Test-ReparsePoint -PathToCheck $clean) {
        throw "Refused symbolic link / junction InstallDir: $clean"
    }
    return $clean
}

function ConvertTo-Win32QuotedArg {
    param([Parameter(Mandatory = $true)][string]$Value)
    # RFC / Win32 CommandLineToArgvW quoting: double backslashes before '"' and before closing '"'
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('"')
    $bsCount = 0
    for ($i = 0; $i -lt $Value.Length; $i++) {
        $ch = $Value[$i]
        if ($ch -eq '\') {
            $bsCount++
        } elseif ($ch -eq '"') {
            [void]$sb.Append('\', $bsCount * 2 + 1)
            [void]$sb.Append('"')
            $bsCount = 0
        } else {
            if ($bsCount -gt 0) {
                [void]$sb.Append('\', $bsCount)
                $bsCount = 0
            }
            [void]$sb.Append($ch)
        }
    }
    if ($bsCount -gt 0) {
        [void]$sb.Append('\', $bsCount * 2)
    }
    [void]$sb.Append('"')
    return $sb.ToString()
}

function Parse-StrictSemVer {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$VerText)
    $trimmed = $VerText.Trim()
    if ($trimmed -match '^v?([0-9]+)\.([0-9]+)\.([0-9]+)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$') {
        [uint64]$maj = 0; [uint64]$min = 0; [uint64]$pat = 0
        if ([uint64]::TryParse($Matches[1], [ref]$maj) -and
            [uint64]::TryParse($Matches[2], [ref]$min) -and
            [uint64]::TryParse($Matches[3], [ref]$pat)) {
            $norm = if ($trimmed.StartsWith("v")) { $trimmed.Substring(1) } else { $trimmed }
            return @{
                Major      = $maj
                Minor      = $min
                Patch      = $pat
                Pre        = if ($Matches[4]) { $Matches[4] } else { "" }
                Normalized = $norm
            }
        }
    }
    return $null
}

function Parse-SemVer {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$VerText)
    $strict = Parse-StrictSemVer -VerText $VerText
    if ($null -ne $strict) { return $strict }
    if ($VerText -match 'v?([0-9]+)\.([0-9]+)\.([0-9]+)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?') {
        [uint64]$maj = 0; [uint64]$min = 0; [uint64]$pat = 0
        if ([uint64]::TryParse($Matches[1], [ref]$maj) -and
            [uint64]::TryParse($Matches[2], [ref]$min) -and
            [uint64]::TryParse($Matches[3], [ref]$pat)) {
            $preStr = if ($Matches[4]) { $Matches[4] } else { "" }
            return @{
                Major      = $maj
                Minor      = $min
                Patch      = $pat
                Pre        = $preStr
                Normalized = if ($preStr) { "$maj.$min.$pat-$preStr" } else { "$maj.$min.$pat" }
            }
        }
    }
    return $null
}

function Compare-SemVerPrerelease {
    param([string]$A, [string]$B)
    $partsA = $A.Split('.')
    $partsB = $B.Split('.')
    $maxLen = [Math]::Max($partsA.Length, $partsB.Length)
    for ($i = 0; $i -lt $maxLen; $i++) {
        if ($i -ge $partsA.Length) { return -1 }
        if ($i -ge $partsB.Length) { return 1 }
        $sa = $partsA[$i]
        $sb = $partsB[$i]
        $aNum = $sa -match '^[0-9]+$'
        $bNum = $sb -match '^[0-9]+$'
        if ($aNum -and $bNum) {
            $na = $sa.TrimStart('0')
            $nb = $sb.TrimStart('0')
            if ($na.Length -ne $nb.Length) {
                return $(if ($na.Length -lt $nb.Length) { -1 } else { 1 })
            }
            $c = [string]::Compare($na, $nb, [System.StringComparison]::Ordinal)
            if ($c -ne 0) { return $(if ($c -lt 0) { -1 } else { 1 }) }
        } elseif ($aNum -and -not $bNum) {
            return -1
        } elseif (-not $aNum -and $bNum) {
            return 1
        } else {
            $c = [string]::Compare($sa, $sb, [System.StringComparison]::Ordinal)
            if ($c -ne 0) { return $(if ($c -lt 0) { -1 } else { 1 }) }
        }
    }
    return 0
}

function Compare-SemVer {
    param($A, $B)
    if ($null -eq $A -or $null -eq $B) {
        throw "Refusing SemVer comparison on malformed version."
    }
    foreach ($k in @("Major", "Minor", "Patch")) {
        if ($A[$k] -lt $B[$k]) { return -1 }
        if ($A[$k] -gt $B[$k]) { return 1 }
    }
    if ([string]::IsNullOrEmpty($A.Pre) -and [string]::IsNullOrEmpty($B.Pre)) { return 0 }
    if ([string]::IsNullOrEmpty($A.Pre) -and -not [string]::IsNullOrEmpty($B.Pre)) { return 1 }
    if (-not [string]::IsNullOrEmpty($A.Pre) -and [string]::IsNullOrEmpty($B.Pre)) { return -1 }
    return (Compare-SemVerPrerelease -A $A.Pre -B $B.Pre)
}

function Get-SignedReleaseHeaderVersion {
    param([Parameter(Mandatory = $true)][string]$SumsText)
    $found = $null
    foreach ($line in ($SumsText -split "`r?`n")) {
        $trimmed = $line.Trim()
        if ($trimmed -match '(?i)^#\s*Singularity-Release\s*:\s*(.*)$') {
            if ($null -ne $found) {
                throw "Duplicate '# Singularity-Release:' header in SHA256SUMS.txt. Update aborted."
            }
            $verVal = $Matches[1].Trim()
            $parsed = Parse-StrictSemVer -VerText $verVal
            if ($null -eq $parsed) {
                throw "Malformed '# Singularity-Release:' SemVer header '$verVal' in SHA256SUMS.txt. Update aborted."
            }
            $found = @{ Raw = $verVal; SemVer = $parsed }
        }
    }
    return $found
}

function New-PrivateUpdateWorkDir {
    $localApp = $env:LOCALAPPDATA
    if ([string]::IsNullOrWhiteSpace($localApp) -and -not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
        $localApp = Join-Path $env:USERPROFILE "AppData\Local"
    }
    if ([string]::IsNullOrWhiteSpace($localApp)) {
        throw "Cannot create private update directory: LOCALAPPDATA and USERPROFILE are unset (refusing shared %TEMP%)."
    }
    $singularityDir = Join-Path $localApp "Singularity"
    $updatesRoot = Join-Path $singularityDir "updates"
    foreach ($p in @($singularityDir, $updatesRoot)) {
        if (Test-ReparsePoint -PathToCheck $p) {
            throw "Refused symbolic link / junction in update directory path: $p"
        }
        if (-not (Test-Path -LiteralPath $p)) {
            [void](New-Item -ItemType Directory -Path $p -Force)
        }
        if (Test-ReparsePoint -PathToCheck $p) {
            throw "Detected reparse point after creation: $p"
        }
    }
    $workDir = Join-Path $updatesRoot ([System.Guid]::NewGuid().ToString("N"))
    [void](New-Item -ItemType Directory -Path $workDir -Force)
    if (Test-ReparsePoint -PathToCheck $workDir) {
        throw "Refused symbolic link / junction staging directory: $workDir"
    }
    try {
        $acl = New-Object System.Security.AccessControl.DirectorySecurity
        $acl.SetAccessRuleProtection($true, $false)
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
        $systemSid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
        $adminsSid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
        $rights = [System.Security.AccessControl.FileSystemRights]::FullControl
        $inherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
        $prop = [System.Security.AccessControl.PropagationFlags]::None
        $allow = [System.Security.AccessControl.AccessControlType]::Allow
        foreach ($sid in @($currentUser, $systemSid, $adminsSid)) {
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, $rights, $inherit, $prop, $allow)
            $acl.AddAccessRule($rule)
        }
        Set-Acl -LiteralPath $workDir -AclObject $acl
    } catch {
        # Best-effort ACL tightening on non-NTFS / restricted contexts while keeping per-user LOCALAPPDATA GUID isolation
    }
    return $workDir
}

# Pure .NET RFC 8032 Ed25519 Verifier (works natively on Windows PowerShell 5.1 and PowerShell 7+)
$Ed25519VerifierCs = @"
using System;
using System.Numerics;
using System.Security.Cryptography;

public static class SingularityEd25519Verifier
{
    private static readonly BigInteger P = (BigInteger.One << 255) - 19;
    private static readonly BigInteger L = (BigInteger.One << 252) + BigInteger.Parse("27742317777372353535851937790883648493");
    private static readonly BigInteger D = Mod(-121665 * ModInv(121666, P), P);
    private static readonly BigInteger I = BigInteger.ModPow(2, (P - 1) / 4, P);
    private static readonly BigInteger[] B = BuildBasePoint();

    private static BigInteger Mod(BigInteger a, BigInteger m)
    {
        BigInteger r = a % m;
        return r.Sign < 0 ? r + m : r;
    }

    private static BigInteger ModInv(BigInteger a, BigInteger m)
    {
        return BigInteger.ModPow(Mod(a, m), m - 2, m);
    }

    private static BigInteger FromUnsignedLE(byte[] bytes)
    {
        byte[] ext = new byte[bytes.Length + 1];
        Array.Copy(bytes, ext, bytes.Length);
        return new BigInteger(ext);
    }

    private static BigInteger RecoverX(BigInteger y)
    {
        BigInteger y2 = Mod(y * y, P);
        BigInteger xx = Mod((y2 - 1) * ModInv(Mod(D * y2 + 1, P), P), P);
        BigInteger x = BigInteger.ModPow(xx, (P + 3) / 8, P);
        if (Mod(x * x - xx, P) != 0)
        {
            x = Mod(x * I, P);
        }
        if (Mod(x * x - xx, P) != 0)
        {
            throw new CryptographicException("Encoded Ed25519 point does not lie on curve.");
        }
        if (!x.IsEven)
        {
            x = P - x;
        }
        return x;
    }

    private static BigInteger[] BuildBasePoint()
    {
        BigInteger by = Mod(4 * ModInv(5, P), P);
        BigInteger bx = RecoverX(by);
        return new BigInteger[] { bx, by, BigInteger.One, Mod(bx * by, P) };
    }

    private static BigInteger[] PointAdd(BigInteger[] p1, BigInteger[] p2)
    {
        BigInteger a = Mod((p1[1] - p1[0]) * (p2[1] - p2[0]), P);
        BigInteger b = Mod((p1[1] + p1[0]) * (p2[1] + p2[0]), P);
        BigInteger c = Mod(2 * D * p1[3] * p2[3], P);
        BigInteger d = Mod(2 * p1[2] * p2[2], P);
        BigInteger e = Mod(b - a, P);
        BigInteger f = Mod(d - c, P);
        BigInteger g = Mod(d + c, P);
        BigInteger h = Mod(b + a, P);
        return new BigInteger[] { Mod(e * f, P), Mod(g * h, P), Mod(f * g, P), Mod(e * h, P) };
    }

    private static BigInteger[] ScalarMul(BigInteger[] pt, BigInteger e)
    {
        BigInteger[] q = new BigInteger[] { BigInteger.Zero, BigInteger.One, BigInteger.One, BigInteger.Zero };
        BigInteger[] cur = pt;
        BigInteger k = e;
        while (k > 0)
        {
            if (!k.IsEven)
            {
                q = PointAdd(q, cur);
            }
            cur = PointAdd(cur, cur);
            k >>= 1;
        }
        return q;
    }

    private static byte[] EncodePoint(BigInteger[] pt)
    {
        BigInteger zi = ModInv(pt[2], P);
        BigInteger x = Mod(pt[0] * zi, P);
        BigInteger y = Mod(pt[1] * zi, P);
        byte[] yb = y.ToByteArray();
        byte[] enc = new byte[32];
        int copyLen = Math.Min(yb.Length, 32);
        Array.Copy(yb, enc, copyLen);
        if (!x.IsEven)
        {
            enc[31] |= 0x80;
        }
        return enc;
    }

    private static BigInteger[] DecodePoint(byte[] enc)
    {
        if (enc == null || enc.Length != 32)
        {
            throw new CryptographicException("Ed25519 encoded point must be 32 bytes.");
        }
        int sign = (enc[31] >> 7) & 1;
        byte[] yBytes = new byte[32];
        Array.Copy(enc, yBytes, 32);
        yBytes[31] &= 0x7F;
        BigInteger y = FromUnsignedLE(yBytes);
        if (y >= P)
        {
            throw new CryptographicException("Non-canonical Ed25519 coordinate y >= p.");
        }
        BigInteger x = RecoverX(y);
        if (x.IsZero && sign == 1)
        {
            throw new CryptographicException("Non-canonical Ed25519 zero coordinate with sign bit set.");
        }
        int xBit = x.IsEven ? 0 : 1;
        if (xBit != sign)
        {
            x = P - x;
        }
        return new BigInteger[] { x, y, BigInteger.One, Mod(x * y, P) };
    }

    private static bool ConstantTimeEquals(byte[] a, byte[] b)
    {
        if (a == null || b == null || a.Length != b.Length) return false;
        int diff = 0;
        for (int i = 0; i < a.Length; i++) diff |= (a[i] ^ b[i]);
        return diff == 0;
    }

    public static bool Verify(byte[] pubKey32, byte[] message, byte[] sig64)
    {
        if (pubKey32 == null || pubKey32.Length != 32 || sig64 == null || sig64.Length != 64 || message == null)
        {
            return false;
        }
        byte[] rBytes = new byte[32];
        byte[] sBytes = new byte[32];
        Array.Copy(sig64, 0, rBytes, 0, 32);
        Array.Copy(sig64, 32, sBytes, 0, 32);

        BigInteger s = FromUnsignedLE(sBytes);
        if (s >= L)
        {
            return false;
        }
        try
        {
            BigInteger[] aPt = DecodePoint(pubKey32);
            BigInteger[] rPt = DecodePoint(rBytes);
            byte[] hInput = new byte[64 + message.Length];
            Array.Copy(rBytes, 0, hInput, 0, 32);
            Array.Copy(pubKey32, 0, hInput, 32, 32);
            Array.Copy(message, 0, hInput, 64, message.Length);
            byte[] digest;
            using (var sha512 = SHA512.Create())
            {
                digest = sha512.ComputeHash(hInput);
            }
            BigInteger k = Mod(FromUnsignedLE(digest), L);
            byte[] lhs = EncodePoint(ScalarMul(B, s));
            byte[] rhs = EncodePoint(PointAdd(rPt, ScalarMul(aPt, k)));
            return ConstantTimeEquals(lhs, rhs);
        }
        catch
        {
            return false;
        }
    }
}
"@

function Verify-Sha256SumsEd25519 {
    param(
        [Parameter(Mandatory = $true)][byte[]]$SumsBytes,
        [Parameter(Mandatory = $true)][string]$SigBase64,
        [Parameter(Mandatory = $true)][string]$PubKeyHex
    )
    if (-not ("SingularityEd25519Verifier" -as [type])) {
        Add-Type -TypeDefinition $Ed25519VerifierCs -ReferencedAssemblies @("System.Numerics")
    }
    $pkBytes = New-Object byte[] 32
    for ($i = 0; $i -lt 32; $i++) {
        $pkBytes[$i] = [Convert]::ToByte($PubKeyHex.Substring($i * 2, 2), 16)
    }
    try {
        $sigBytes = [Convert]::FromBase64String($SigBase64.Trim())
    } catch {
        throw "Invalid base64 encoding in SHA256SUMS.txt.sig."
    }
    if ($sigBytes.Length -ne 64) {
        throw "Invalid Ed25519 signature length in SHA256SUMS.txt.sig (expected 64 bytes, got $($sigBytes.Length))."
    }
    if (-not [SingularityEd25519Verifier]::Verify($pkBytes, $SumsBytes, $sigBytes)) {
        throw "Ed25519 cryptographic signature verification FAILED for SHA256SUMS.txt. Update aborted."
    }
}

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  SINGULARITY BROWSER - VERIFIED AUTO-UPDATER (Ed25519 + SHA-256)" -ForegroundColor Yellow
Write-Host "=================================================================" -ForegroundColor Cyan

$SafeInstallDir = Resolve-SafeInstallDir -RawDir $InstallDir

$EffectivePubKeyHex = if (-not [string]::IsNullOrWhiteSpace($ReleasePubKeyHex)) {
    $ReleasePubKeyHex.Trim()
} else {
    $DefaultReleasePubKeyHex.Trim()
}

if ([string]::IsNullOrWhiteSpace($EffectivePubKeyHex)) {
    if (-not $AllowUnsigned) {
        throw "Ed25519 release signing public key is not configured (required by default in production). Set SINGULARITY_RELEASE_SIGNING_PUBKEY_HEX (64 hex chars) or pass -ReleasePubKeyHex to verify SHA256SUMS.txt.sig (or pass -AllowUnsigned only for non-production testing)."
    }
    Write-Host "[WARN] Running in -AllowUnsigned mode without Ed25519 signature verification (non-production only)." -ForegroundColor Yellow
} elseif (-not ($EffectivePubKeyHex -match '^[0-9a-fA-F]{64}$')) {
    throw "Invalid Ed25519 release signing public key (expected 64 hex characters)."
}

$pubHeaders = @{ "User-Agent" = $Ua }
$apiHeaders = @{
    "User-Agent" = $Ua
    "Accept"     = "application/vnd.github+json"
}
if ($Token -and $Token.Trim().Length -gt 0) {
    $apiHeaders["Authorization"] = "Bearer $($Token.Trim())"
}

Write-Host "[1/5] Checking latest public release at https://github.com/$Repo ..." -ForegroundColor Gray
try {
    $releaseJson = Invoke-AllowedHttpsRequest -Url $ApiUrl -Label "GitHub Releases API" -Headers $apiHeaders -TimeoutSec 15
    $release = $releaseJson | ConvertFrom-Json
} catch {
    if ($apiHeaders.ContainsKey("Authorization")) {
        $apiHeaders.Remove("Authorization")
        $releaseJson = Invoke-AllowedHttpsRequest -Url $ApiUrl -Label "GitHub Releases API" -Headers $apiHeaders -TimeoutSec 15
        $release = $releaseJson | ConvertFrom-Json
    } else {
        throw
    }
}

$tag = ([string]$release.tag_name).Trim()
$tagSem = Parse-StrictSemVer -VerText $tag
if ($null -eq $tagSem) {
    throw "Invalid GitHub release SemVer tag: $tag"
}
Write-Host "      Release found: $tag" -ForegroundColor Green

# Anti-downgrade check against currently installed singularity.exe (when present)
$installedSemVer = $null
$installedVerStr = $null
$existingExe = Join-Path $SafeInstallDir "singularity.exe"
if ((Test-Path -LiteralPath $existingExe) -and -not (Test-ReparsePoint -PathToCheck $existingExe)) {
    try {
        $fvi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($existingExe)
        $curStr = if ($fvi.ProductVersion) { $fvi.ProductVersion } else { $fvi.FileVersion }
        $curSem = Parse-SemVer -VerText ([string]$curStr)
        if ($null -ne $curSem) {
            $installedSemVer = $curSem
            $installedVerStr = [string]$curStr
            if ((Compare-SemVer $tagSem $curSem) -lt 0) {
                throw "Refusing downgrade from installed version $curStr to older release $tag."
            }
        }
    } catch {
        if ($_.Exception.Message -like "Refusing downgrade*") { throw }
    }
}

$setupAsset = $release.assets | Where-Object { $_.name -eq "Singularity-setup.exe" } | Select-Object -First 1
$sumAsset = $release.assets | Where-Object { $_.name -eq "SHA256SUMS.txt" } | Select-Object -First 1
$sigAsset = $release.assets | Where-Object { $_.name -eq "SHA256SUMS.txt.sig" } | Select-Object -First 1

if ($null -eq $setupAsset -or $null -eq $sumAsset) {
    throw "Required release assets (Singularity-setup.exe and SHA256SUMS.txt) are not attached to release $tag yet."
}
if (-not [string]::IsNullOrWhiteSpace($EffectivePubKeyHex) -and $null -eq $sigAsset) {
    throw "Required Ed25519 signature asset (SHA256SUMS.txt.sig) is missing from release $tag. Update aborted."
}

Assert-AllowedHttpsUrl -Url $setupAsset.browser_download_url -Label "Singularity-setup.exe"
Assert-AllowedHttpsUrl -Url $sumAsset.browser_download_url -Label "SHA256SUMS.txt"
if ($null -ne $sigAsset) {
    Assert-AllowedHttpsUrl -Url $sigAsset.browser_download_url -Label "SHA256SUMS.txt.sig"
}

$WorkDir = New-PrivateUpdateWorkDir
$SetupExe = Join-Path $WorkDir "Singularity-setup.exe"
$SumsFile = Join-Path $WorkDir "SHA256SUMS.txt"
$SigFile = Join-Path $WorkDir "SHA256SUMS.txt.sig"

try {
    Write-Host "[2/5] Downloading release artifacts into private per-user staging folder..." -ForegroundColor Gray
    Invoke-AllowedHttpsRequest -Url $setupAsset.browser_download_url -Label "Singularity-setup.exe" -Headers $pubHeaders -OutFile $SetupExe -TimeoutSec 180 | Out-Null
    Invoke-AllowedHttpsRequest -Url $sumAsset.browser_download_url -Label "SHA256SUMS.txt" -Headers $pubHeaders -OutFile $SumsFile -TimeoutSec 30 | Out-Null
    if (-not [string]::IsNullOrWhiteSpace($EffectivePubKeyHex)) {
        Invoke-AllowedHttpsRequest -Url $sigAsset.browser_download_url -Label "SHA256SUMS.txt.sig" -Headers $pubHeaders -OutFile $SigFile -TimeoutSec 30 | Out-Null
    }

    $sumsBytes = [System.IO.File]::ReadAllBytes($SumsFile)
    if (-not [string]::IsNullOrWhiteSpace($EffectivePubKeyHex)) {
        Write-Host "[3/5] Verifying Ed25519 cryptographic signature (SHA256SUMS.txt.sig)..." -ForegroundColor Gray
        $sigB64 = [System.IO.File]::ReadAllText($SigFile, [System.Text.Encoding]::ASCII)
        Verify-Sha256SumsEd25519 -SumsBytes $sumsBytes -SigBase64 $sigB64 -PubKeyHex $EffectivePubKeyHex
        Write-Host "      Ed25519 signature verified." -ForegroundColor Green
    } else {
        Write-Host "[3/5] Skipping Ed25519 check (-AllowUnsigned explicitly enabled)." -ForegroundColor Yellow
    }

    $sumsText = [System.Text.Encoding]::UTF8.GetString($sumsBytes)
    $signedHeader = Get-SignedReleaseHeaderVersion -SumsText $sumsText
    $signedHeaderCutoff = Parse-StrictSemVer -VerText "3.0.3"
    if ($null -ne $signedHeader) {
        if ((Compare-SemVer $signedHeader.SemVer $tagSem) -ne 0 -or $signedHeader.SemVer.Normalized -ne $tagSem.Normalized) {
            throw "Signed SHA256SUMS.txt release version '$($signedHeader.Raw)' does not match advertised GitHub release tag '$tag' (possible rollback attack). Update aborted."
        }
        if ($null -ne $installedSemVer -and (Compare-SemVer $signedHeader.SemVer $installedSemVer) -lt 0) {
            throw "Refusing downgrade from installed version $installedVerStr to signed release $($signedHeader.Raw)."
        }
        Write-Host "      Signed release version verified: $($signedHeader.Raw)" -ForegroundColor Green
    } elseif (-not [string]::IsNullOrWhiteSpace($EffectivePubKeyHex) -and (Compare-SemVer $tagSem $signedHeaderCutoff) -gt 0) {
        throw "Signed SHA256SUMS.txt is missing mandatory '# Singularity-Release:' version header for release $tag (possible rollback attack). Update aborted."
    }

    Write-Host "[4/5] Verifying SHA-256 cryptographic integrity..." -ForegroundColor Gray
    $expectedHash = $null
    foreach ($line in ($sumsText -split "`r?`n")) {
        if ($line -match '^\s*([A-Fa-f0-9]{64})\s+\*?Singularity-setup\.exe\s*$') {
            $expectedHash = $Matches[1].ToLowerInvariant()
            break
        }
    }
    if (-not $expectedHash) {
        throw "SHA-256 checksum for Singularity-setup.exe missing in SHA256SUMS.txt."
    }

    $actualHash = (Get-FileHash -LiteralPath $SetupExe -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -ne $expectedHash) {
        throw "SHA-256 mismatch! Expected=$expectedHash Actual=$actualHash. Update aborted."
    }
    Write-Host "      SHA-256 verified: $actualHash" -ForegroundColor Green

    Write-Host "[5/5] Installing Singularity $tag + Pure Chromium runtime into $SafeInstallDir ..." -ForegroundColor Gray
    $quotedInstallDir = ConvertTo-Win32QuotedArg -Value $SafeInstallDir
    $argLine = "--silent --dir $quotedInstallDir --launch"
    $proc = Start-Process -FilePath $SetupExe -ArgumentList $argLine -Wait -PassThru
    if ($proc.ExitCode -ne 0) {
        throw "Singularity-setup.exe exited with code $($proc.ExitCode)."
    }

    Write-Host ""
    Write-Host "[OK] Singularity $tag installed and verified." -ForegroundColor Green
} finally {
    Remove-Item -LiteralPath $WorkDir -Recurse -Force -ErrorAction SilentlyContinue
}
