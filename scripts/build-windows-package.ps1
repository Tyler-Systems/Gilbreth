<#
.SYNOPSIS
    Builds one source-bound Gilbreth Windows installer candidate.

.DESCRIPTION
    This is the public package builder. It requires a clean tagged tree, the
    pinned Rust/Inno toolchain, and an explicit version. It only copies files
    named by the tracked allowlist into an isolated dist tree; it never reads or
    mutates the live per-user install or data roots.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$')]
    [string]$Version,

    [Parameter(Mandatory)]
    [string]$SourceTag,

    [string]$OutputRoot,
    [string]$InnoCompiler,

    # The protected signing lane supplies a secretless approved wrapper command.
    # Credentials must come from the protected environment/certificate provider,
    # never this command line. It must contain Inno's literal $f placeholder.
    [string]$SignToolCommand,

    # Unsigned releases must opt in explicitly.
    [switch]$Unsigned
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-NativeText {
    param(
        [Parameter(Mandatory)] [string]$FilePath,
        [string[]]$ArgumentList = @(),
        [string[]]$RedactValues = @()
    )

    $output = & $FilePath @ArgumentList 2>&1
    $exitCode = $LASTEXITCODE
    $text = ($output | ForEach-Object { $_.ToString() }) -join "`n"
    $displayArguments = @($ArgumentList)
    foreach ($value in $RedactValues) {
        if ([string]::IsNullOrEmpty($value)) { continue }
        $text = $text.Replace($value, '[REDACTED]')
        $displayArguments = @($displayArguments | ForEach-Object { $_.Replace($value, '[REDACTED]') })
    }
    if ($exitCode -ne 0) {
        throw "Command failed ($exitCode): $FilePath $($displayArguments -join ' ')`n$text"
    }
    return $text.Trim()
}

function Get-Sha256Lower {
    param([Parameter(Mandatory)] [string]$LiteralPath)
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $LiteralPath).Hash.ToLowerInvariant()
}

function Add-GilbrethIconResourceApi {
    if ('GilbrethIconResource.NativeMethods' -as [type]) {
        return
    }

    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace GilbrethIconResource
{
    public static class NativeMethods
    {
        [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
        public static extern uint ExtractIconEx(
            string fileName,
            int iconIndex,
            IntPtr largeIcons,
            IntPtr smallIcons,
            uint iconCount);
    }
}
'@
}

function Assert-EmbeddedWindowsIcon {
    param([Parameter(Mandatory)] [string]$Path)

    Add-GilbrethIconResourceApi
    $count = [GilbrethIconResource.NativeMethods]::ExtractIconEx(
        $Path,
        -1,
        [IntPtr]::Zero,
        [IntPtr]::Zero,
        0
    )
    if ($count -lt 1) {
        throw "Gilbreth app has no embedded Windows icon group: $Path"
    }
}

function Get-DirectoryContentDigest {
    param([Parameter(Mandatory)] [System.Collections.IDictionary]$Roots)
    $rows = [System.Collections.Generic.List[string]]::new()
    foreach ($label in @($Roots.Keys | Sort-Object)) {
        $root = [System.IO.Path]::GetFullPath([string]$Roots[$label]).TrimEnd('\', '/')
        Assert-NoReparseAncestors -Path $root -Label "native toolchain $label root"
        $prefix = $root + [System.IO.Path]::DirectorySeparatorChar
        $items = @(Get-ChildItem -LiteralPath $root -Recurse -Force)
        $reparse = @($items | Where-Object {
            ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
        })
        if ($reparse.Count -ne 0) {
            throw "Native toolchain content may not contain reparse points: $($reparse[0].FullName)"
        }
        foreach ($file in @($items | Where-Object { -not $_.PSIsContainer } | Sort-Object FullName)) {
            $relative = $file.FullName.Substring($prefix.Length).Replace('\', '/')
            $rows.Add("$label/$relative|$($file.Length)|$(Get-Sha256Lower $file.FullName)")
        }
    }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes(($rows -join "`n") + "`n")
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally { $sha.Dispose() }
}

function Write-Utf8NoBom {
    param(
        [Parameter(Mandatory)] [string]$LiteralPath,
        [Parameter(Mandatory)] [string]$Content
    )
    $utf8 = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText($LiteralPath, $Content, $utf8)
}

function Assert-SafeRelativePath {
    param(
        [Parameter(Mandatory)] [string]$Value,
        [Parameter(Mandatory)] [string]$Label
    )

    if ([string]::IsNullOrWhiteSpace($Value) -or
        [System.IO.Path]::IsPathRooted($Value) -or
        $Value.Contains('*') -or $Value.Contains('?')) {
        throw "$Label must be a non-wildcard relative path: $Value"
    }
    $segments = $Value.Replace('\', '/').Split('/')
    if ($segments | Where-Object { $_ -in @('', '.', '..') }) {
        throw "$Label contains an empty, current-directory, or traversal segment: $Value"
    }
}

function Assert-NoReparseAncestors {
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string]$Label
    )
    $full = [System.IO.Path]::GetFullPath($Path)
    $root = [System.IO.Path]::GetPathRoot($full)
    $cursor = $full.TrimEnd('\', '/')
    while (-not [string]::IsNullOrWhiteSpace($cursor)) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -Force -LiteralPath $cursor
            if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "$Label contains a reparse-point ancestor: $cursor"
            }
        }
        if ($cursor.TrimEnd('\', '/').Equals(
                $root.TrimEnd('\', '/'), [System.StringComparison]::OrdinalIgnoreCase)) { break }
        $parent = [System.IO.Directory]::GetParent($cursor)
        if ($null -eq $parent) { break }
        $cursor = $parent.FullName
    }
}

function Get-VerifiedAuthenticodeFacts {
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string]$ExpectedSubject,
        [Parameter(Mandatory)] [string]$ExpectedSimpleSubject
    )
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    $actualCertificateSha256 = if ($null -eq $signature.SignerCertificate) { '' } else {
        (($signature.SignerCertificate.GetCertHash(
                    [System.Security.Cryptography.HashAlgorithmName]::SHA256) |
                ForEach-Object { $_.ToString('x2') }) -join '')
    }
    $timestampCertificateSha256 = if ($null -eq $signature.TimeStamperCertificate) { '' } else {
        (($signature.TimeStamperCertificate.GetCertHash(
                    [System.Security.Cryptography.HashAlgorithmName]::SHA256) |
                ForEach-Object { $_.ToString('x2') }) -join '')
    }
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
        $null -eq $signature.SignerCertificate -or
        $signature.SignerCertificate.Subject -ne $ExpectedSubject -or
        $signature.SignerCertificate.GetNameInfo(
            [System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName,
            $false) -ne $ExpectedSimpleSubject -or
        $null -eq $signature.TimeStamperCertificate) {
        throw "Authenticode verification failed for $([System.IO.Path]::GetFileName($Path))."
    }
    return [ordered]@{
        status = 'Valid'
        signerSubject = $signature.SignerCertificate.Subject
        signerSimpleSubject = $signature.SignerCertificate.GetNameInfo(
            [System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName,
            $false)
        signerIssuer = $signature.SignerCertificate.Issuer
        signerCertificateSha256 = $actualCertificateSha256
        signerNotBeforeUtc = $signature.SignerCertificate.NotBefore.ToUniversalTime().ToString('o')
        signerNotAfterUtc = $signature.SignerCertificate.NotAfter.ToUniversalTime().ToString('o')
        timestampStatus = 'present-and-signature-valid'
        timestampSubject = $signature.TimeStamperCertificate.Subject
        timestampCertificateSha256 = $timestampCertificateSha256
        timestampNotBeforeUtc = $signature.TimeStamperCertificate.NotBefore.ToUniversalTime().ToString('o')
        timestampNotAfterUtc = $signature.TimeStamperCertificate.NotAfter.ToUniversalTime().ToString('o')
    }
}

function Resolve-ContainedPath {
    param(
        [Parameter(Mandatory)] [string]$Root,
        [Parameter(Mandatory)] [string]$RelativePath,
        [Parameter(Mandatory)] [string]$Label
    )

    Assert-SafeRelativePath -Value $RelativePath -Label $Label
    $rootFull = [System.IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
    $relativeNative = $RelativePath.Replace('/', [System.IO.Path]::DirectorySeparatorChar)
    $candidate = [System.IO.Path]::GetFullPath((Join-Path $rootFull $relativeNative))
    $prefix = $rootFull + [System.IO.Path]::DirectorySeparatorChar
    if (-not $candidate.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label escapes its root: $RelativePath"
    }
    return $candidate
}

function Assert-GitTracked {
    param([Parameter(Mandatory)] [string]$RepoRelativePath)
    $null = Invoke-NativeText -FilePath 'git' -ArgumentList @(
        'ls-files', '--error-unmatch', '--', $RepoRelativePath.Replace('\', '/')
    )
}

function Get-CargoConfigFiles {
    param(
        [Parameter(Mandatory)] [string]$RepositoryRoot,
        [Parameter(Mandatory)] [string]$CargoHome
    )
    $directories = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    $repositoryFull = [System.IO.Path]::GetFullPath($RepositoryRoot)
    $repositoryDriveRoot = [System.IO.Path]::GetPathRoot($repositoryFull)
    $cursor = $repositoryFull.TrimEnd('\', '/')
    while (-not [string]::IsNullOrWhiteSpace($cursor)) {
        [void]$directories.Add((Join-Path $cursor '.cargo'))
        if ($cursor.TrimEnd('\', '/').Equals(
                $repositoryDriveRoot.TrimEnd('\', '/'),
                [System.StringComparison]::OrdinalIgnoreCase)) { break }
        $parent = [System.IO.Directory]::GetParent($cursor)
        if ($null -eq $parent) { break }
        $cursor = $parent.FullName
    }
    [void]$directories.Add([System.IO.Path]::GetFullPath($CargoHome))
    return @(
        foreach ($directory in $directories) {
            foreach ($name in @('config', 'config.toml')) {
                $candidate = Join-Path $directory $name
                if (Test-Path -LiteralPath $candidate) {
                    [System.IO.Path]::GetFullPath($candidate)
                }
            }
        }
    )
}

function Assert-FilesExcludeBuildMarkers {
    param(
        [Parameter(Mandatory)] [string[]]$LiteralPaths,
        [Parameter(Mandatory)] [System.Collections.IDictionary]$Markers,
        [Parameter(Mandatory)] [string]$Label
    )

    function Test-ContainsBuildMarker {
        param(
            [Parameter(Mandatory)] [string]$Text,
            [Parameter(Mandatory)] [string]$Needle,
            [Parameter(Mandatory)] [bool]$TokenBounded
        )

        $searchFrom = 0
        while ($searchFrom -lt $Text.Length) {
            $index = $Text.IndexOf(
                $Needle,
                $searchFrom,
                [System.StringComparison]::OrdinalIgnoreCase)
            if ($index -lt 0) {
                return $false
            }
            if (-not $TokenBounded) {
                return $true
            }

            $beforeIsIdentifier = $index -gt 0 -and (
                [char]::IsLetterOrDigit($Text[$index - 1]) -or
                $Text[$index - 1] -in @('_', '-'))
            $afterIndex = $index + $Needle.Length
            $afterIsIdentifier = $afterIndex -lt $Text.Length -and (
                [char]::IsLetterOrDigit($Text[$afterIndex]) -or
                $Text[$afterIndex] -in @('_', '-'))
            if (-not $beforeIsIdentifier -and -not $afterIsIdentifier) {
                return $true
            }
            $searchFrom = $index + 1
        }
        return $false
    }

    $latin1 = [System.Text.Encoding]::GetEncoding(28591)
    $utf8 = [System.Text.UTF8Encoding]::new($false)
    foreach ($path in $LiteralPaths) {
        $bytes = [System.IO.File]::ReadAllBytes($path)
        $byteText = $latin1.GetString($bytes)
        $utf8Text = $utf8.GetString($bytes)
        $utf16Text = [System.Text.Encoding]::Unicode.GetString($bytes)
        $utf16BigEndianText = [System.Text.Encoding]::BigEndianUnicode.GetString($bytes)
        $utf16OffsetOneText = ''
        $utf16BigEndianOffsetOneText = ''
        if ($bytes.Length -gt 1) {
            $utf16OffsetOneText = [System.Text.Encoding]::Unicode.GetString(
                $bytes, 1, $bytes.Length - 1)
            $utf16BigEndianOffsetOneText = [System.Text.Encoding]::BigEndianUnicode.GetString(
                $bytes, 1, $bytes.Length - 1)
        }
        foreach ($markerName in @($Markers.Keys | Sort-Object)) {
            $marker = [string]$Markers[$markerName]
            if ([string]::IsNullOrWhiteSpace($marker)) {
                continue
            }
            $variants = [System.Collections.Generic.HashSet[string]]::new(
                [System.StringComparer]::OrdinalIgnoreCase)
            [void]$variants.Add($marker)
            [void]$variants.Add($marker.Replace('\', '/'))
            [void]$variants.Add($marker.Replace('/', '\'))
            $tokenBounded = $markerName -in @('user-name', 'host-name')
            foreach ($variant in $variants) {
                $utf8AsBytes = $latin1.GetString($utf8.GetBytes($variant))
                if ((Test-ContainsBuildMarker $byteText $utf8AsBytes $tokenBounded) -or
                    (Test-ContainsBuildMarker $utf8Text $variant $tokenBounded) -or
                    (Test-ContainsBuildMarker $utf16Text $variant $tokenBounded) -or
                    (Test-ContainsBuildMarker $utf16BigEndianText $variant $tokenBounded) -or
                    (Test-ContainsBuildMarker $utf16OffsetOneText $variant $tokenBounded) -or
                    (Test-ContainsBuildMarker $utf16BigEndianOffsetOneText $variant $tokenBounded)) {
                    throw "$Label contains the forbidden $markerName build-machine marker: $([System.IO.Path]::GetFileName($path))"
                }
            }
        }
    }
}

if ($Unsigned -and -not [string]::IsNullOrWhiteSpace($SignToolCommand)) {
    throw 'Choose either -Unsigned or -SignToolCommand, not both.'
}
if (-not $Unsigned -and [string]::IsNullOrWhiteSpace($SignToolCommand)) {
    throw 'Pass -Unsigned or supply the protected -SignToolCommand.'
}
if (-not [string]::IsNullOrWhiteSpace($SignToolCommand) -and
    -not $SignToolCommand.Contains('$f')) {
    throw '-SignToolCommand must contain Inno Setup''s literal $f file placeholder.'
}
$repoRoot = (Invoke-NativeText -FilePath 'git' -ArgumentList @('rev-parse', '--show-toplevel')).Trim()
$repoRoot = [System.IO.Path]::GetFullPath($repoRoot)
$buildMarkers = [ordered]@{
    'checkout-root' = $repoRoot.TrimEnd('\', '/')
    'user-profile' = [System.IO.Path]::GetFullPath($env:USERPROFILE).TrimEnd('\', '/')
    'user-name' = [string]$env:USERNAME
    'host-name' = [string]$env:COMPUTERNAME
}
if (-not [System.IO.Path]::GetFullPath((Get-Location).Path).Equals(
        $repoRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'Run the package builder from the repository root so Cargo config discovery is deterministic.'
}
if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    $OutputRoot = Join-Path $repoRoot 'dist'
}
$OutputRoot = [System.IO.Path]::GetFullPath($OutputRoot)
Assert-NoReparseAncestors -Path $OutputRoot -Label 'package output root'

$forbiddenOutputRoots = @(
    (Join-Path $env:LOCALAPPDATA 'Gilbreth'),
    (Join-Path $env:LOCALAPPDATA 'Programs\Gilbreth')
) | ForEach-Object { [System.IO.Path]::GetFullPath($_).TrimEnd('\', '/') }
foreach ($forbidden in $forbiddenOutputRoots) {
    if ($OutputRoot.Equals($forbidden, [System.StringComparison]::OrdinalIgnoreCase) -or
        $OutputRoot.StartsWith($forbidden + [System.IO.Path]::DirectorySeparatorChar,
            [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Package output may not be the live program or data root: $forbidden"
    }
}
$repoPrefix = $repoRoot.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
if (-not $OutputRoot.StartsWith($repoPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw '-OutputRoot must remain inside the repository; live install/data paths are forbidden.'
}

if ($env:OS -ne 'Windows_NT') {
    throw 'The Windows package must be built on Windows.'
}

$dirty = Invoke-NativeText -FilePath 'git' -ArgumentList @(
    'status', '--porcelain=v1', '--untracked-files=all'
)
if (-not [string]::IsNullOrWhiteSpace($dirty)) {
    throw "Release builds require a clean tree:`n$dirty"
}

$configRelative = 'packaging/windows/release-config.json'
$allowlistRelative = 'packaging/windows/package-allowlist.json'
$innoRelative = 'packaging/windows/Gilbreth.iss'
$pePolicyRelative = 'packaging/windows/pe-dependencies.json'
$peVerifierRelative = 'scripts/windows-pe-dependencies.psm1'
$thirdPartyGeneratorRelative = 'scripts/windows-third-party-notices.ps1'
$thirdPartyPolicyRelative = 'packaging/windows/third-party-notices-policy.json'
$thirdPartyInventoryRelative = 'packaging/windows/third-party-inventory.json'
$thirdPartyNoticeRelative = 'docs/THIRD-PARTY-NOTICES.md'
Assert-GitTracked $configRelative
Assert-GitTracked $allowlistRelative
Assert-GitTracked $innoRelative
Assert-GitTracked $pePolicyRelative
Assert-GitTracked $peVerifierRelative
Assert-GitTracked $thirdPartyGeneratorRelative
Assert-GitTracked $thirdPartyPolicyRelative
Assert-GitTracked $thirdPartyInventoryRelative
Assert-GitTracked $thirdPartyNoticeRelative
Assert-GitTracked 'Cargo.lock'

$configPath = Resolve-ContainedPath $repoRoot $configRelative 'release config path'
$allowlistPath = Resolve-ContainedPath $repoRoot $allowlistRelative 'allowlist path'
$innoPath = Resolve-ContainedPath $repoRoot $innoRelative 'Inno script path'
$pePolicyPath = Resolve-ContainedPath $repoRoot $pePolicyRelative 'PE dependency policy path'
$peVerifierPath = Resolve-ContainedPath $repoRoot $peVerifierRelative 'PE dependency verifier path'
$thirdPartyGeneratorPath = Resolve-ContainedPath $repoRoot $thirdPartyGeneratorRelative 'third-party notice generator path'
$thirdPartyPolicyPath = Resolve-ContainedPath $repoRoot $thirdPartyPolicyRelative 'third-party notice policy path'
$thirdPartyInventoryPath = Resolve-ContainedPath $repoRoot $thirdPartyInventoryRelative 'third-party inventory path'
$thirdPartyNoticePath = Resolve-ContainedPath $repoRoot $thirdPartyNoticeRelative 'third-party notice path'
$cargoLockPath = Resolve-ContainedPath $repoRoot 'Cargo.lock' 'Cargo lock path'
foreach ($recipeInput in @(
        $configPath, $allowlistPath, $innoPath, $pePolicyPath,
        $peVerifierPath, $thirdPartyGeneratorPath, $thirdPartyPolicyPath,
        $thirdPartyInventoryPath, $thirdPartyNoticePath, $cargoLockPath
    )) {
    if (-not (Test-Path -LiteralPath $recipeInput -PathType Leaf) -or
        ((Get-Item -Force -LiteralPath $recipeInput).Attributes -band
            [System.IO.FileAttributes]::ReparsePoint)) {
        throw "Package recipe input must be a regular non-reparse file: $recipeInput"
    }
    Assert-NoReparseAncestors -Path $recipeInput -Label 'package recipe input'
}
$config = Get-Content -Raw -LiteralPath $configPath | ConvertFrom-Json
$allowlist = Get-Content -Raw -LiteralPath $allowlistPath | ConvertFrom-Json
$thirdPartyPolicy = Get-Content -Raw -LiteralPath $thirdPartyPolicyPath | ConvertFrom-Json
Import-Module $peVerifierPath -Force
$pePolicy = Import-WindowsPeDependencyPolicy -Path $pePolicyPath
if ($config.schemaVersion -ne 1 -or $allowlist.schemaVersion -ne 1 -or
    $thirdPartyPolicy.schemaVersion -ne 1) {
    throw 'Unsupported release config, allowlist, or third-party notice policy schema.'
}
$manualNoticeInputs = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase)
foreach ($component in @($thirdPartyPolicy.manualComponents)) {
    [void]$manualNoticeInputs.Add([string]$component.noticePath)
    $assetFilesProperty = $component.PSObject.Properties['assetFiles']
    if ($null -ne $assetFilesProperty) {
        foreach ($asset in @($assetFilesProperty.Value)) {
            [void]$manualNoticeInputs.Add([string]$asset.path)
        }
    }
}
foreach ($rule in @($thirdPartyPolicy.packageRules)) {
    $fallbackProperty = $rule.PSObject.Properties['fallback']
    if ($null -ne $fallbackProperty -and
        [string]$fallbackProperty.Value.kind -eq 'repo') {
        [void]$manualNoticeInputs.Add([string]$fallbackProperty.Value.path)
    }
    $extraProperty = $rule.PSObject.Properties['extraLicenseFiles']
    if ($null -ne $extraProperty) {
        foreach ($extra in @($extraProperty.Value)) {
            $repoPathProperty = $extra.PSObject.Properties['repoPath']
            if ($null -ne $repoPathProperty) {
                [void]$manualNoticeInputs.Add([string]$repoPathProperty.Value)
            }
        }
    }
}
foreach ($relative in $manualNoticeInputs) {
    Assert-GitTracked $relative
    $manualInputPath = Resolve-ContainedPath $repoRoot $relative 'manual third-party notice input'
    if (-not (Test-Path -LiteralPath $manualInputPath -PathType Leaf) -or
        ((Get-Item -Force -LiteralPath $manualInputPath).Attributes -band
            [System.IO.FileAttributes]::ReparsePoint)) {
        throw "Manual third-party notice input must be a regular non-reparse file: $relative"
    }
    Assert-NoReparseAncestors -Path $manualInputPath -Label 'manual third-party notice input'
}
if ([string]$config.target -cne 'windows-x64' -or
    [string]$config.rustHost -cne 'x86_64-pc-windows-msvc' -or
    [string]$config.msvcRuntimeLinkage -cne 'static') {
    throw 'Windows release config must require windows-x64 on x64 MSVC with static CRT linkage.'
}

if ($SourceTag -cnotmatch [string]$config.tagPattern) {
    throw "Source tag '$SourceTag' is not an accepted release tag."
}
if ($Matches.version -ne $Version) {
    throw "Source tag version '$($Matches.version)' does not match explicit version '$Version'."
}

$headCommit = Invoke-NativeText 'git' @('rev-parse', 'HEAD')
$tagRef = "refs/tags/$SourceTag"
$tagType = Invoke-NativeText 'git' @('cat-file', '-t', $tagRef)
if ($tagType -ne 'tag') {
    throw "Source tag '$SourceTag' must be an exact annotated tag ref."
}
$tagCommit = Invoke-NativeText 'git' @('rev-parse', "$tagRef^{commit}")
if ($tagCommit -ne $headCommit) {
    throw "Source tag '$SourceTag' does not resolve to HEAD $headCommit."
}
$shortCommit = Invoke-NativeText 'git' @('rev-parse', '--short=12', 'HEAD')
$commitEpoch = Invoke-NativeText 'git' @('show', '-s', '--format=%ct', 'HEAD')

$forbiddenBuildEnvironment = @(
    Get-ChildItem Env: | Where-Object {
        $_.Name -match '^(RUSTC($|_)|RUSTDOC($|_)|RUSTFLAGS$|CARGO_|DEP_|GILBRETH_PACKAGE_|GILBRETH_BUILD_|CC($|_)|CXX($|_)|CPP($|_)|CFLAGS($|_)|CPPFLAGS($|_)|CXXFLAGS($|_)|LDFLAGS($|_)|AR($|_)|RANLIB($|_)|RC($|_)|(HOST|TARGET)_(CC|CXX|CPP|CFLAGS|CPPFLAGS|CXXFLAGS|LDFLAGS|AR|RANLIB)$|CRATE_CC_|PKG_CONFIG|VCPKG|LIBSQLITE3_|SQLITE3_|SQLITE_MAX_|BINDGEN_|CL$|_CL_$|LINK$|_LINK_$|INCLUDE$|LIB$|LIBPATH$|VCTOOLS|WINDOWSSDK|VISUALSTUDIO|VSINSTALLDIR|VCINSTALLDIR)'
    }
)
if ($forbiddenBuildEnvironment.Count -ne 0) {
    throw ('Release build environment contains an unapproved Cargo/Rust override: ' +
        (($forbiddenBuildEnvironment.Name | Sort-Object) -join ', '))
}

$activeToolchain = Invoke-NativeText 'rustup' @('show', 'active-toolchain')
$rustcPath = [System.IO.Path]::GetFullPath((Invoke-NativeText 'rustup' @('which', 'rustc')))
$cargoPath = [System.IO.Path]::GetFullPath((Invoke-NativeText 'rustup' @('which', 'cargo')))
foreach ($tool in @($rustcPath, $cargoPath)) {
    if (-not (Test-Path -LiteralPath $tool -PathType Leaf)) {
        throw "Pinned Rust tool is missing: $tool"
    }
    Assert-NoReparseAncestors -Path $tool -Label 'Rust toolchain executable'
}
$rustcVersion = Invoke-NativeText $rustcPath @('-Vv')
$releasePattern = '(?m)^release: ' + [regex]::Escape([string]$config.rustRelease) + '$'
$commitPattern = '(?m)^commit-hash: ' + [regex]::Escape([string]$config.rustCommit) + '$'
$hostPattern = '(?m)^host: ' + [regex]::Escape([string]$config.rustHost) + '$'
if ($rustcVersion -notmatch $releasePattern -or
    $rustcVersion -notmatch $commitPattern -or
    $rustcVersion -notmatch $hostPattern) {
    throw "rustc is not the approved Windows release/commit/host:`n$rustcVersion"
}
if ((Get-Sha256Lower $rustcPath) -ne [string]$config.rustcSha256) {
    throw 'rustc.exe does not match the pinned Windows toolchain binary.'
}
$cargoVersion = Invoke-NativeText $cargoPath @('-Vv')
$cargoReleasePattern = '(?m)^release: ' + [regex]::Escape([string]$config.cargoRelease) + '$'
$cargoCommitPattern = '(?m)^commit-hash: ' + [regex]::Escape([string]$config.cargoCommit) + '$'
$cargoHostPattern = '(?m)^host: ' + [regex]::Escape([string]$config.cargoHost) + '$'
if ($cargoVersion -notmatch $cargoReleasePattern -or
    $cargoVersion -notmatch $cargoCommitPattern -or
    $cargoVersion -notmatch $cargoHostPattern -or
    (Get-Sha256Lower $cargoPath) -ne [string]$config.cargoSha256) {
    throw "cargo is not the approved Windows release/commit/host/binary:`n$cargoVersion"
}
$rustToolchainBin = Split-Path -Parent $rustcPath
$rustToolchainRoot = Split-Path -Parent $rustToolchainBin
$rustTargetLib = Join-Path $rustToolchainRoot (
    'lib\rustlib\' + [string]$config.rustHost + '\lib')
if (-not (Test-Path -LiteralPath $rustTargetLib -PathType Container)) {
    throw 'Pinned Rust target library directory is missing.'
}
$rustToolchainContentSha256 = Get-DirectoryContentDigest ([ordered]@{
    bin = $rustToolchainBin
    targetlib = $rustTargetLib
})
if ($rustToolchainContentSha256 -ne [string]$config.rustToolchainContentSha256) {
    throw 'Rust executable dependencies/target libraries do not match the approved content digest.'
}

$visualStudioBase = Join-Path ${env:ProgramFiles(x86)} (
    'Microsoft Visual Studio\' + [string]$config.visualStudioMajorVersion)
$toolsetRoots = @(
    Get-ChildItem -LiteralPath $visualStudioBase -Directory -ErrorAction SilentlyContinue |
        ForEach-Object {
            $candidate = Join-Path $_.FullName (
                'VC\Tools\MSVC\' + [string]$config.msvcToolsetVersion)
            if (Test-Path -LiteralPath (Join-Path $candidate 'bin\Hostx64\x64\cl.exe') -PathType Leaf) {
                [System.IO.Path]::GetFullPath($candidate)
            }
        }
)
if ($toolsetRoots.Count -ne 1) {
    throw 'Expected exactly one approved x64 MSVC toolset installation.'
}
$msvcRoot = $toolsetRoots[0]
$msvcBin = Join-Path $msvcRoot 'bin\Hostx64\x64'
$clPath = Join-Path $msvcBin 'cl.exe'
$linkPath = Join-Path $msvcBin 'link.exe'
$libToolPath = Join-Path $msvcBin 'lib.exe'
$windowsSdkRoot = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10'
$windowsSdkVersion = [string]$config.windowsSdkVersion
$windowsSdkBin = Join-Path $windowsSdkRoot "bin\$windowsSdkVersion\x64"
$rcPath = Join-Path $windowsSdkBin 'rc.exe'
$nativeTools = @(
    [ordered]@{ label = 'cl.exe'; path = $clPath; expected = [string]$config.clSha256 },
    [ordered]@{ label = 'link.exe'; path = $linkPath; expected = [string]$config.linkSha256 },
    [ordered]@{ label = 'lib.exe'; path = $libToolPath; expected = [string]$config.libSha256 },
    [ordered]@{ label = 'rc.exe'; path = $rcPath; expected = [string]$config.rcSha256 }
)
foreach ($tool in $nativeTools) {
    if (-not (Test-Path -LiteralPath $tool.path -PathType Leaf) -or
        ((Get-Item -Force -LiteralPath $tool.path).Attributes -band
            [System.IO.FileAttributes]::ReparsePoint)) {
        throw "Approved native tool is missing or not a regular file: $($tool.label)"
    }
    Assert-NoReparseAncestors -Path $tool.path -Label "approved $($tool.label)"
    if ((Get-Sha256Lower $tool.path) -ne $tool.expected) {
        throw "Approved native tool hash mismatch: $($tool.label)"
    }
}
$msvcInclude = Join-Path $msvcRoot 'include'
$msvcLib = Join-Path $msvcRoot 'lib\x64'
$sdkIncludeRoot = Join-Path $windowsSdkRoot "Include\$windowsSdkVersion"
$sdkUcrtLib = Join-Path $windowsSdkRoot "Lib\$windowsSdkVersion\ucrt\x64"
$sdkUmLib = Join-Path $windowsSdkRoot "Lib\$windowsSdkVersion\um\x64"
$includeDirectories = @(
    $msvcInclude,
    (Join-Path $sdkIncludeRoot 'ucrt'),
    (Join-Path $sdkIncludeRoot 'shared'),
    (Join-Path $sdkIncludeRoot 'um'),
    (Join-Path $sdkIncludeRoot 'winrt'),
    (Join-Path $sdkIncludeRoot 'cppwinrt')
)
$libraryDirectories = @($msvcLib, $sdkUcrtLib, $sdkUmLib)
foreach ($directory in @($includeDirectories + $libraryDirectories)) {
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
        throw "Approved native toolchain directory is missing: $directory"
    }
    Assert-NoReparseAncestors -Path $directory -Label 'approved native toolchain directory'
}
$msvcContentSha256 = Get-DirectoryContentDigest ([ordered]@{
    bin = $msvcBin
    include = $msvcInclude
    lib = $msvcLib
})
if ($msvcContentSha256 -ne [string]$config.msvcContentSha256) {
    throw 'MSVC headers/libraries do not match the approved content digest.'
}
$windowsSdkContentSha256 = Get-DirectoryContentDigest ([ordered]@{
    bin = $windowsSdkBin
    include = $sdkIncludeRoot
    ucrt = $sdkUcrtLib
    um = $sdkUmLib
})
if ($windowsSdkContentSha256 -ne [string]$config.windowsSdkContentSha256) {
    throw 'Windows SDK headers/libraries do not match the approved content digest.'
}
$nativeToolFacts = [ordered]@{
    visualStudioMajorVersion = [string]$config.visualStudioMajorVersion
    msvcToolsetVersion = [string]$config.msvcToolsetVersion
    msvcRuntimeLinkage = [string]$config.msvcRuntimeLinkage
    clSha256 = Get-Sha256Lower $clPath
    clVersion = (Get-Item -LiteralPath $clPath).VersionInfo.FileVersion
    linkSha256 = Get-Sha256Lower $linkPath
    linkVersion = (Get-Item -LiteralPath $linkPath).VersionInfo.FileVersion
    libSha256 = Get-Sha256Lower $libToolPath
    libVersion = (Get-Item -LiteralPath $libToolPath).VersionInfo.FileVersion
    msvcContentSha256 = $msvcContentSha256
    windowsSdkVersion = $windowsSdkVersion
    rcSha256 = Get-Sha256Lower $rcPath
    rcVersion = (Get-Item -LiteralPath $rcPath).VersionInfo.FileVersion
    windowsSdkContentSha256 = $windowsSdkContentSha256
}
$cargoHome = Join-Path $env:USERPROFILE '.cargo'
$cargoConfigs = @(Get-CargoConfigFiles -RepositoryRoot $repoRoot -CargoHome $cargoHome)
if ($cargoConfigs.Count -ne 0) {
    throw "Release builds refuse ambient Cargo config files:`n$($cargoConfigs -join "`n")"
}

$noticeVerification = & $thirdPartyGeneratorPath -Mode Verify `
    -RepositoryRoot $repoRoot -CargoPath $cargoPath -RustcPath $rustcPath `
    -PolicyPath $thirdPartyPolicyRelative
if (-not [string]::IsNullOrWhiteSpace(($noticeVerification -join "`n"))) {
    Write-Host ($noticeVerification -join "`n")
}

$metadataJson = Invoke-NativeText $cargoPath @('metadata', '--frozen', '--no-deps', '--format-version', '1')
$metadata = $metadataJson | ConvertFrom-Json
$appPackage = @($metadata.packages | Where-Object name -eq 'gilbreth-app')
if ($appPackage.Count -ne 1 -or [string]$appPackage[0].version -ne $Version) {
    throw "Cargo authoritative gilbreth-app version does not match '$Version'."
}

if ([string]::IsNullOrWhiteSpace($InnoCompiler)) {
    $knownInno = @(@(
            (Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe'),
            (Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 6\ISCC.exe')
        ) | Where-Object {
            -not [string]::IsNullOrWhiteSpace($_) -and
            (Test-Path -LiteralPath $_ -PathType Leaf)
        })
    if ($knownInno.Count -ne 1) {
        throw 'Pass -InnoCompiler with the absolute path to pinned ISCC.exe 6.7.3.'
    }
    $InnoCompiler = $knownInno[0]
}
$InnoCompiler = [System.IO.Path]::GetFullPath($InnoCompiler)
if (-not (Test-Path -LiteralPath $InnoCompiler -PathType Leaf)) {
    throw "Inno compiler not found: $InnoCompiler"
}
$isccSha256 = Get-Sha256Lower $InnoCompiler
if ($isccSha256 -ne [string]$config.isccSha256) {
    throw "ISCC.exe SHA-256 does not match pinned Inno Setup $($config.innoSetupVersion)."
}
$innoVersion = [string]$config.innoSetupVersion

$stageDir = Join-Path $OutputRoot "staging\$Version\windows-x64"
$publicDir = Join-Path $OutputRoot "public\$Version\windows-x64"
$workDir = Join-Path $OutputRoot "work\$Version\windows-x64"
foreach ($candidateDir in @($stageDir, $publicDir, $workDir)) {
    Assert-NoReparseAncestors -Path $candidateDir -Label 'candidate output path'
    if (Test-Path -LiteralPath $candidateDir) {
        throw "Candidate output already exists; refusing to overwrite it: $candidateDir"
    }
}
[System.IO.Directory]::CreateDirectory($stageDir) | Out-Null
[System.IO.Directory]::CreateDirectory($workDir) | Out-Null
Assert-NoReparseAncestors -Path $stageDir -Label 'staging directory'
Assert-NoReparseAncestors -Path $workDir -Label 'isolated Cargo target directory'
$publishWorkDir = Join-Path $workDir 'publish-complete'
$finalInnoDir = Join-Path $workDir 'inno-final'
$signingPassDir = Join-Path $workDir 'inno-signing-pass-1'
foreach ($internalDir in @($publishWorkDir, $finalInnoDir, $signingPassDir)) {
    [System.IO.Directory]::CreateDirectory($internalDir) | Out-Null
    Assert-NoReparseAncestors -Path $internalDir -Label 'internal package work directory'
}

$oldIncremental = $env:CARGO_INCREMENTAL
$oldEpoch = $env:SOURCE_DATE_EPOCH
$oldTargetDir = $env:CARGO_TARGET_DIR
$oldBuildTarget = $env:CARGO_BUILD_TARGET
$oldRustFlags = $env:RUSTFLAGS
$oldEncodedRustFlags = $env:CARGO_ENCODED_RUSTFLAGS
$oldRustc = $env:RUSTC
$oldRustcWrapper = $env:RUSTC_WRAPPER
$oldRustcWorkspaceWrapper = $env:RUSTC_WORKSPACE_WRAPPER
$oldPackageTrustMode = $env:GILBRETH_PACKAGE_TRUST_MODE
$oldPackageSignerSubject = $env:GILBRETH_PACKAGE_SIGNER_SUBJECT
$nativeBuildEnvironmentNames = @(
    'PATH', 'INCLUDE', 'LIB', 'LIBPATH',
    'CC_x86_64_pc_windows_msvc', 'AR_x86_64_pc_windows_msvc', 'RC',
    'CFLAGS_x86_64_pc_windows_msvc', 'CL', '_CL_', 'LINK', '_LINK_',
    'VCToolsInstallDir', 'VCToolsVersion', 'WindowsSdkDir',
    'WindowsSDKVersion', 'VisualStudioVersion', 'VSINSTALLDIR', 'VCINSTALLDIR',
    'GILBRETH_BUILD_GIT_SHA'
)
$nativeBuildEnvironmentBefore = @{}
foreach ($name in $nativeBuildEnvironmentNames) {
    $nativeBuildEnvironmentBefore[$name] =
        [Environment]::GetEnvironmentVariable($name, 'Process')
}
$targetTriple = [string]$config.rustHost
try {
    $env:CARGO_INCREMENTAL = '0'
    $env:SOURCE_DATE_EPOCH = $commitEpoch
    $env:CARGO_TARGET_DIR = $workDir
    $env:CARGO_BUILD_TARGET = $null
    $env:RUSTFLAGS = $null
    $env:CARGO_ENCODED_RUSTFLAGS = $null
    $env:RUSTC = $rustcPath
    $env:RUSTC_WRAPPER = $null
    $env:RUSTC_WORKSPACE_WRAPPER = $null
    $env:GILBRETH_PACKAGE_TRUST_MODE = 'release-package'
    $env:GILBRETH_PACKAGE_SIGNER_SUBJECT = [string]$config.signerSimpleSubject
    $nativePath = @(
        $rustToolchainBin,
        $msvcBin,
        $windowsSdkBin,
        (Join-Path $env:WINDIR 'System32'),
        $env:WINDIR
    ) -join ';'
    [Environment]::SetEnvironmentVariable('PATH', $nativePath, 'Process')
    [Environment]::SetEnvironmentVariable('INCLUDE', ($includeDirectories -join ';'), 'Process')
    [Environment]::SetEnvironmentVariable('LIB', ($libraryDirectories -join ';'), 'Process')
    [Environment]::SetEnvironmentVariable('LIBPATH', $msvcLib, 'Process')
    [Environment]::SetEnvironmentVariable('CC_x86_64_pc_windows_msvc', $clPath, 'Process')
    [Environment]::SetEnvironmentVariable('AR_x86_64_pc_windows_msvc', $libToolPath, 'Process')
    [Environment]::SetEnvironmentVariable('RC', $rcPath, 'Process')
    [Environment]::SetEnvironmentVariable('CFLAGS_x86_64_pc_windows_msvc', $null, 'Process')
    [Environment]::SetEnvironmentVariable('CL', $null, 'Process')
    [Environment]::SetEnvironmentVariable('_CL_', $null, 'Process')
    [Environment]::SetEnvironmentVariable('LINK', $null, 'Process')
    [Environment]::SetEnvironmentVariable('_LINK_', $null, 'Process')
    [Environment]::SetEnvironmentVariable('VCToolsInstallDir', $msvcRoot + '\', 'Process')
    [Environment]::SetEnvironmentVariable('VCToolsVersion', [string]$config.msvcToolsetVersion, 'Process')
    [Environment]::SetEnvironmentVariable('WindowsSdkDir', $windowsSdkRoot + '\', 'Process')
    [Environment]::SetEnvironmentVariable('WindowsSDKVersion', $windowsSdkVersion + '\', 'Process')
    [Environment]::SetEnvironmentVariable('VisualStudioVersion', '17.0', 'Process')
    [Environment]::SetEnvironmentVariable('GILBRETH_BUILD_GIT_SHA', $shortCommit, 'Process')
    $linkerConfigPath = $linkPath.Replace('\', '/')
    $targetRustFlags = @(
        '-C',
        'target-feature=+crt-static',
        "--remap-path-prefix=$($repoRoot.Replace('\', '/'))=.",
        "--remap-path-prefix=$(([string]$buildMarkers['user-profile']).Replace('\', '/'))=<user-profile>"
    )
    $targetRustFlagsJson = $targetRustFlags | ConvertTo-Json -Compress
    $targetRustFlagsConfig = "target.$targetTriple.rustflags=$targetRustFlagsJson"
    $null = Invoke-NativeText $cargoPath @(
        'build', '--release', '--frozen', '--target', $targetTriple,
        '--config', 'build.rustflags=[]',
        '--config', $targetRustFlagsConfig,
        '--config', "target.$targetTriple.linker='$linkerConfigPath'",
        '-p', 'gilbreth-app', '--bin', 'gilbreth-app'
    )
}
finally {
    $env:CARGO_INCREMENTAL = $oldIncremental
    $env:SOURCE_DATE_EPOCH = $oldEpoch
    $env:CARGO_TARGET_DIR = $oldTargetDir
    $env:CARGO_BUILD_TARGET = $oldBuildTarget
    $env:RUSTFLAGS = $oldRustFlags
    $env:CARGO_ENCODED_RUSTFLAGS = $oldEncodedRustFlags
    $env:RUSTC = $oldRustc
    $env:RUSTC_WRAPPER = $oldRustcWrapper
    $env:RUSTC_WORKSPACE_WRAPPER = $oldRustcWorkspaceWrapper
    $env:GILBRETH_PACKAGE_TRUST_MODE = $oldPackageTrustMode
    $env:GILBRETH_PACKAGE_SIGNER_SUBJECT = $oldPackageSignerSubject
    foreach ($name in $nativeBuildEnvironmentNames) {
        [Environment]::SetEnvironmentVariable(
            $name, $nativeBuildEnvironmentBefore[$name], 'Process')
    }
}
$builtExe = Join-Path $workDir "$targetTriple\release\gilbreth-app.exe"
if (-not (Test-Path -LiteralPath $builtExe -PathType Leaf)) {
    throw "The isolated Cargo build did not produce gilbreth-app.exe."
}
function Get-PolicyCheckedPeFacts {
    param([Parameter(Mandatory)] [string]$ImagePath)

    $facts = Get-WindowsPeDependencies -LinkPath $linkPath -ImagePath $ImagePath
    $null = Assert-WindowsPeDependencyPolicy -Facts $facts -Policy $pePolicy
    return $facts
}

function Assert-MatchingPeFacts {
    param(
        [Parameter(Mandatory)] [object]$Expected,
        [Parameter(Mandatory)] [object]$Actual,
        [Parameter(Mandatory)] [string]$Label
    )

    $expectedJson = $Expected | ConvertTo-Json -Compress
    $actualJson = $Actual | ConvertTo-Json -Compress
    if ($expectedJson -cne $actualJson) {
        throw "$Label changed the normalized PE import set."
    }
}

$builtPeFacts = Get-PolicyCheckedPeFacts -ImagePath $builtExe
Assert-EmbeddedWindowsIcon -Path $builtExe
$pePolicySha256 = Get-Sha256Lower $pePolicyPath
$peVerifierSha256 = Get-Sha256Lower $peVerifierPath
$null = Invoke-NativeText $builtExe @(
    '--package-self-check', '--expect-version', $Version,
    '--expect-git-sha', $headCommit
)

$dirtyAfterBuild = Invoke-NativeText 'git' @('status', '--porcelain=v1', '--untracked-files=all')
if (-not [string]::IsNullOrWhiteSpace($dirtyAfterBuild)) {
    throw "The locked build changed the source tree:`n$dirtyAfterBuild"
}
$cargoConfigsAfterBuild = @(Get-CargoConfigFiles -RepositoryRoot $repoRoot -CargoHome $cargoHome)
if ($cargoConfigsAfterBuild.Count -ne 0) {
    throw 'An ambient Cargo config file appeared during the release build.'
}

$seenDestinations = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$stagedRows = @()
foreach ($entry in @($allowlist.entries)) {
    $sourceRelative = [string]$entry.source
    $destinationRelative = [string]$entry.destination
    Assert-SafeRelativePath $sourceRelative 'allowlist source'
    Assert-SafeRelativePath $destinationRelative 'allowlist destination'
    if (-not $seenDestinations.Add($destinationRelative.Replace('\', '/'))) {
        throw "Duplicate allowlist destination: $destinationRelative"
    }
    if ([string]$entry.sourceKind -eq 'tracked') {
        Assert-GitTracked $sourceRelative
        $sourcePath = Resolve-ContainedPath $repoRoot $sourceRelative 'allowlist source'
    }
    elseif ([string]$entry.sourceKind -eq 'build-output') {
        if ($sourceRelative.Replace('\', '/') -ne 'build-output/gilbreth-app.exe') {
            throw "Unexpected build-output allowlist entry: $sourceRelative"
        }
        $sourcePath = $builtExe
    }
    else {
        throw "Unsupported sourceKind '$($entry.sourceKind)' for $sourceRelative."
    }

    if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
        throw "Allowlisted source file does not exist: $sourceRelative"
    }
    Assert-NoReparseAncestors -Path $sourcePath -Label 'allowlisted source path'
    if ((Get-Item -LiteralPath $sourcePath).Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        throw "Allowlisted source may not be a reparse point: $sourceRelative"
    }
    $destinationPath = Resolve-ContainedPath $stageDir $destinationRelative 'allowlist destination'
    [System.IO.Directory]::CreateDirectory((Split-Path -Parent $destinationPath)) | Out-Null
    Copy-Item -LiteralPath $sourcePath -Destination $destinationPath
    $file = Get-Item -LiteralPath $destinationPath
    $stagedRows += [ordered]@{
        role = [string]$entry.role
        path = $destinationRelative.Replace('\', '/')
        sizeBytes = [long]$file.Length
        sha256 = Get-Sha256Lower $destinationPath
    }
}

$stagePrefix = [System.IO.Path]::GetFullPath($stageDir).TrimEnd('\', '/') +
    [System.IO.Path]::DirectorySeparatorChar
$actualStageFiles = @(Get-ChildItem -LiteralPath $stageDir -File -Recurse | ForEach-Object {
    $_.FullName.Substring($stagePrefix.Length).Replace('\', '/')
})
$unexpectedStageFiles = @($actualStageFiles | Where-Object { -not $seenDestinations.Contains($_) })
if ($actualStageFiles.Count -ne $seenDestinations.Count -or $unexpectedStageFiles.Count -ne 0) {
    throw "Staging contains unexpected files: $($unexpectedStageFiles -join ', ')"
}
$appPath = Join-Path $stageDir 'gilbreth-app.exe'
$stagedPeFacts = Get-PolicyCheckedPeFacts -ImagePath $appPath
Assert-EmbeddedWindowsIcon -Path $appPath
Assert-MatchingPeFacts -Expected $builtPeFacts -Actual $stagedPeFacts `
    -Label 'The staged app copy'
$null = Invoke-NativeText $appPath @(
    '--package-self-check', '--expect-version', $Version,
    '--expect-git-sha', $headCommit
)

$identityRelative = 'gilbreth-install-identity.txt'
$identityPath = Resolve-ContainedPath $stageDir $identityRelative 'generated install identity'
function Write-InstallIdentity {
    param([Parameter(Mandatory)] [string]$AppSha256)
    if ($AppSha256 -notmatch '^[0-9a-f]{64}$') {
        throw 'Generated install identity requires a lowercase SHA-256 value.'
    }
    $identityText = @(
        'schema=1',
        "sha256=$AppSha256",
        "version=$Version",
        "git-sha=$shortCommit"
    ) -join "`n"
    Write-Utf8NoBom $identityPath ($identityText + "`n")
}
$initialAppHash = Get-Sha256Lower $appPath
Write-InstallIdentity $initialAppHash
if (-not $seenDestinations.Add($identityRelative)) {
    throw 'Generated install identity collides with the package allowlist.'
}
$identityFile = Get-Item -LiteralPath $identityPath
$stagedRows += [ordered]@{
    role = 'install-identity'
    path = $identityRelative
    sizeBytes = [long]$identityFile.Length
    sha256 = Get-Sha256Lower $identityPath
}
$finalStageFiles = @(Get-ChildItem -LiteralPath $stageDir -File -Recurse | ForEach-Object {
    $_.FullName.Substring($stagePrefix.Length).Replace('\', '/')
})
if ($finalStageFiles.Count -ne $seenDestinations.Count -or
    @($finalStageFiles | Where-Object { -not $seenDestinations.Contains($_) }).Count -ne 0) {
    throw 'Staging changed outside the allowlist plus generated install identity.'
}
$stagedPayloadPaths = @(
    Get-ChildItem -LiteralPath $stageDir -File -Recurse |
        Select-Object -ExpandProperty FullName
)
Assert-FilesExcludeBuildMarkers -LiteralPaths $stagedPayloadPaths `
    -Markers $buildMarkers -Label 'Staged package payload'

$installerBaseName = ([string]$config.installerNameTemplate).Replace('{version}', $Version)
function Invoke-InnoCompile {
    param(
        [Parameter(Mandatory)] [string]$ExpectedAppHash,
        [Parameter(Mandatory)] [string]$CompileOutputDirectory,
        [Parameter(Mandatory)] [string]$CompileBaseName
    )
    Write-InstallIdentity $ExpectedAppHash
    $arguments = @(
        '/Qp',
        "/DAppVersion=$Version",
        "/DSourceGitSha=$shortCommit",
        "/DExpectedAppSha256=$ExpectedAppHash",
        "/DStageDir=$stageDir",
        "/DOutputDir=$CompileOutputDirectory",
        "/DInstallerBaseName=$CompileBaseName"
    )
    if (-not $Unsigned) {
        $arguments += '/DSigningEnabled=1'
        $arguments += "/Sartifact_sign=$SignToolCommand"
    }
    $arguments += $innoPath
    $redactions = if ($Unsigned) { @() } else { @($SignToolCommand) }
    $null = Invoke-NativeText $InnoCompiler $arguments -RedactValues $redactions
}

$expectedAppHash = Get-Sha256Lower $appPath
if ($Unsigned) {
    Invoke-InnoCompile $expectedAppHash $finalInnoDir $installerBaseName
}
else {
    # First pass lets Inno's signonce hook mutate only the isolated staged app.
    # Its intentionally pre-sign-hash-bound Setup stays in internal work and is
    # deleted immediately; it is never given a release name or public path.
    $passOneBaseName = 'INTERNAL-DO-NOT-DISTRIBUTE-signing-pass-1'
    Invoke-InnoCompile $expectedAppHash $signingPassDir $passOneBaseName
    $passOneInstaller = Join-Path $signingPassDir ($passOneBaseName + '.exe')
    if (-not (Test-Path -LiteralPath $passOneInstaller -PathType Leaf)) {
        throw 'The internal signing pass did not produce its expected scratch Setup.'
    }
    Remove-Item -LiteralPath $passOneInstaller -Force
    $appSignatureFacts = Get-VerifiedAuthenticodeFacts -Path $appPath `
        -ExpectedSubject ([string]$config.signerSubject) `
        -ExpectedSimpleSubject ([string]$config.signerSimpleSubject)
    $signedPeFacts = Get-PolicyCheckedPeFacts -ImagePath $appPath
    Assert-MatchingPeFacts -Expected $builtPeFacts -Actual $signedPeFacts `
        -Label 'The signed staged app'
    $null = Invoke-NativeText $appPath @(
        '--package-self-check', '--expect-version', $Version,
        '--expect-git-sha', $headCommit
    )
    $expectedAppHash = Get-Sha256Lower $appPath
    Invoke-InnoCompile $expectedAppHash $finalInnoDir $installerBaseName
    if ((Get-Sha256Lower $appPath) -ne $expectedAppHash) {
        throw 'The signed staged app changed during the final Inno compile.'
    }
}
$finalPeFacts = Get-PolicyCheckedPeFacts -ImagePath $appPath
Assert-EmbeddedWindowsIcon -Path $appPath
Assert-MatchingPeFacts -Expected $builtPeFacts -Actual $finalPeFacts `
    -Label 'The final staged app'
$finalPeDependencyAudit = [ordered]@{
    method = 'pinned-link-dump-dependents-policy-v1'
    inspector = 'link.exe'
    inspectorSha256 = Get-Sha256Lower $linkPath
    policySha256 = $pePolicySha256
    verifierSha256 = $peVerifierSha256
    builtDirectImports = [string[]]@($builtPeFacts.directImports)
    builtDelayLoadImports = [string[]]@($builtPeFacts.delayLoadImports)
    directImports = [string[]]@($finalPeFacts.directImports)
    delayLoadImports = [string[]]@($finalPeFacts.delayLoadImports)
    exactBuiltFinalMatch = $true
    passed = $true
}
$null = Invoke-NativeText $appPath @(
    '--package-self-check', '--expect-version', $Version,
    '--expect-git-sha', $headCommit
)

$installerPath = Join-Path $finalInnoDir ($installerBaseName + '.exe')
if (-not (Test-Path -LiteralPath $installerPath -PathType Leaf)) {
    throw "ISCC did not produce the expected installer: $installerPath"
}

if ($Unsigned) {
    $appStatus = (Get-AuthenticodeSignature -LiteralPath $appPath).Status.ToString()
    $setupStatus = (Get-AuthenticodeSignature -LiteralPath $installerPath).Status.ToString()
    if ($appStatus -ne 'NotSigned' -or $setupStatus -ne 'NotSigned') {
        throw 'Unsigned package unexpectedly contains an Authenticode signature.'
    }
    $signatureFacts = [ordered]@{
        appStatus = $appStatus
        setupStatus = $setupStatus
        generatedUninstallerVerification = 'unsigned-vm-check-required'
    }
}
else {
    $appSignatureFacts = Get-VerifiedAuthenticodeFacts -Path $appPath `
        -ExpectedSubject ([string]$config.signerSubject) `
        -ExpectedSimpleSubject ([string]$config.signerSimpleSubject)
    $setupSignatureFacts = Get-VerifiedAuthenticodeFacts -Path $installerPath `
        -ExpectedSubject ([string]$config.signerSubject) `
        -ExpectedSimpleSubject ([string]$config.signerSimpleSubject)
    $signatureFacts = [ordered]@{
        app = $appSignatureFacts
        setup = $setupSignatureFacts
        generatedUninstallerVerification = 'signed-vm-check-required'
    }
}

Assert-FilesExcludeBuildMarkers -LiteralPaths @($stagedPayloadPaths + $installerPath) `
    -Markers $buildMarkers -Label 'Final Windows package'

$publishedInstallerPath = Join-Path $publishWorkDir ([System.IO.Path]::GetFileName($installerPath))
Copy-Item -LiteralPath $installerPath -Destination $publishedInstallerPath
if ((Get-Sha256Lower $publishedInstallerPath) -ne (Get-Sha256Lower $installerPath)) {
    throw 'The verified Setup changed while preparing atomic publication.'
}

# signonce may mutate only the copied staging app. The source target\release
# binary is never signed or changed. Public hashes are captured after ISCC.
$publicRows = @()
foreach ($row in $stagedRows) {
    $filePath = Resolve-ContainedPath $stageDir ([string]$row.path) 'staged public file'
    $file = Get-Item -LiteralPath $filePath
    $publicRows += [ordered]@{
        role = [string]$row.role
        path = 'program/' + [string]$row.path
        sizeBytes = [long]$file.Length
        sha256 = Get-Sha256Lower $filePath
    }
}
$stagedAppRow = @($publicRows | Where-Object { $_.role -eq 'installed-app' })
if ($stagedAppRow.Count -ne 1) {
    throw 'Expected one staged installed-app row before deriving the lifecycle guard.'
}
$publicRows += [ordered]@{
    role = 'lifecycle-guard'
    path = 'program/gilbreth-lifecycle-guard.exe'
    sizeBytes = [long]$stagedAppRow[0].sizeBytes
    sha256 = [string]$stagedAppRow[0].sha256
}
$installerFile = Get-Item -LiteralPath $publishedInstallerPath
$publicRows += [ordered]@{
    role = 'installer'
    path = $installerFile.Name
    sizeBytes = [long]$installerFile.Length
    sha256 = Get-Sha256Lower $publishedInstallerPath
}

$packageGeneratedUtc = [DateTime]::UtcNow.ToString('o')
$manifest = [ordered]@{
    schemaVersion = 2
    generatedUtc = $packageGeneratedUtc
    product = [string]$config.productName
    version = $Version
    target = [string]$config.target
    source = [ordered]@{ tag = $SourceTag; commit = $headCommit; embeddedGitSha = $shortCommit }
    build = [ordered]@{
        cleanTree = $true
        locked = $true
        frozen = $true
        rustToolchain = $activeToolchain
        rustToolchainContentSha256 = $rustToolchainContentSha256
        rustcSha256 = Get-Sha256Lower $rustcPath
        rustc = ($rustcVersion -replace "`n", '; ')
        cargoSha256 = Get-Sha256Lower $cargoPath
        cargo = $cargoVersion
        ambientCargoConfig = 'absent-before-and-after-build'
        targetTriple = $targetTriple
        targetFeatures = @('crt-static')
        msvcRuntimeLinkage = [string]$config.msvcRuntimeLinkage
        nativeToolchain = $nativeToolFacts
        peDependencyAudit = $finalPeDependencyAudit
        packageTrustMode = 'release-package'
        innoSetup = $innoVersion
        isccSha256 = $isccSha256
        sourceDateEpoch = [long]$commitEpoch
        pathRemapping = 'checkout-and-user-profile'
    }
    recipe = [ordered]@{
        releaseConfigSha256 = Get-Sha256Lower $configPath
        allowlistSha256 = Get-Sha256Lower $allowlistPath
        innoScriptSha256 = Get-Sha256Lower $innoPath
        peDependencyPolicySha256 = $pePolicySha256
        peDependencyVerifierSha256 = $peVerifierSha256
        thirdPartyNoticeGeneratorSha256 = Get-Sha256Lower $thirdPartyGeneratorPath
        thirdPartyNoticePolicySha256 = Get-Sha256Lower $thirdPartyPolicyPath
        thirdPartyInventorySha256 = Get-Sha256Lower $thirdPartyInventoryPath
        thirdPartyNoticeSha256 = Get-Sha256Lower $thirdPartyNoticePath
        cargoLockSha256 = Get-Sha256Lower $cargoLockPath
    }
    signing = [ordered]@{
        mode = $(if ($Unsigned) { 'unsigned' } else { 'artifact-signing' })
        expected = -not $Unsigned
        signerCertificateSha256 = $(if ($Unsigned) { '' } else { [string]$appSignatureFacts.signerCertificateSha256 })
        verification = $signatureFacts
    }
    files = $publicRows
}
$manifestFileName = "Gilbreth-$Version-windows-x64-release-manifest.json"
$manifestPath = Join-Path $publishWorkDir $manifestFileName
Write-Utf8NoBom $manifestPath (($manifest | ConvertTo-Json -Depth 8) + "`n")

$checksumFileName = "Gilbreth-$Version-windows-x64-SHA256SUMS.txt"
$checksumPath = Join-Path $publishWorkDir $checksumFileName
$checksumText = @(
    "$(Get-Sha256Lower $publishedInstallerPath)  $($installerFile.Name)",
    "$(Get-Sha256Lower $manifestPath)  $manifestFileName"
) -join "`n"
Write-Utf8NoBom $checksumPath ($checksumText + "`n")

$dirtyAfterPackage = Invoke-NativeText 'git' @('status', '--porcelain=v1', '--untracked-files=all')
if (-not [string]::IsNullOrWhiteSpace($dirtyAfterPackage)) {
    throw "Packaging changed the source tree:`n$dirtyAfterPackage"
}
$actualPublicFiles = @(Get-ChildItem -LiteralPath $publishWorkDir -File | Select-Object -ExpandProperty Name)
$expectedPublicFiles = @($installerFile.Name, $manifestFileName, $checksumFileName)
$unexpectedPublic = @($actualPublicFiles | Where-Object { $_ -notin $expectedPublicFiles })
if ($actualPublicFiles.Count -ne $expectedPublicFiles.Count -or $unexpectedPublic.Count -ne 0) {
    throw "Public output contains unexpected files: $($unexpectedPublic -join ', ')"
}
$publicParent = Split-Path -Parent $publicDir
[System.IO.Directory]::CreateDirectory($publicParent) | Out-Null
Assert-NoReparseAncestors -Path $publicParent -Label 'public output parent'
Move-Item -LiteralPath $publishWorkDir -Destination $publicDir
Assert-NoReparseAncestors -Path $publicDir -Label 'published candidate directory'

Write-Host "Package candidate built from $SourceTag ($headCommit)." -ForegroundColor Green
Write-Host "Public artifacts: $publicDir"
