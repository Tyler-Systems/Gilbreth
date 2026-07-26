#Requires -Version 5.1
<#
.SYNOPSIS
    Verify that the local Gilbreth release build and autostart registration
    match the current repository commit.

.DESCRIPTION
    Checks the current Git SHA, confirms target\release\gilbreth-app.exe exists
    and contains the 12-character Git SHA embedded by crates/gilbreth-app/build.rs,
    confirms target\release\gilbreth-elevated-record-helper.exe exists beside it,
    and confirms HKCU ...\Run\Gilbreth points at either that repository-local
    executable or the stable developer install under
    %LOCALAPPDATA%\Gilbreth\bin. The selected executable must contain the same
    embedded Git SHA. The script also reports whether a Gilbreth process is
    currently running and the
    elevated Record Routine helper config used by the future signed Program
    Files package lane, including the helper's embedded uiAccess manifest and
    Windows UAC/UIAccess secure-location policy when release-helper config is
    required.

.PARAMETER RequireRunning
    Treat "Gilbreth is not running" as a verification failure. By default the
    running state is reported but not required.

.PARAMETER RequireReleaseElevatedHelperConfig
    Treat missing/incomplete signed-helper release config as a verification
    failure. This also requires UAC and UIAccess secure-location policy to be
    enabled. This is intended for the packaged 2c-E release lane, not local
    unsigned development installs.
#>
[CmdletBinding()]
param(
    [switch]$RequireRunning,
    [switch]$RequireReleaseElevatedHelperConfig
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'install_helpers.ps1')

$repoRoot = Split-Path -Parent $PSScriptRoot
$releaseExe = Join-Path $repoRoot 'target\release\gilbreth-app.exe'
$releaseHelperExe = Join-Path $repoRoot 'target\release\gilbreth-elevated-record-helper.exe'
$stableExe = Join-Path $env:LOCALAPPDATA 'Gilbreth\bin\gilbreth-app.exe'
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$configPath = Join-Path $env:LOCALAPPDATA 'Gilbreth\config.toml'

function Invoke-Git {
    param([Parameter(Mandatory)] [string[]]$Arguments)
    Push-Location $repoRoot
    try {
        $output = & git @Arguments
        if ($LASTEXITCODE -ne 0) {
            throw "git $($Arguments -join ' ') failed with exit code $LASTEXITCODE"
        }
        ($output -join "`n").Trim()
    }
    finally {
        Pop-Location
    }
}

function Get-CommandPath {
    param([AllowNull()] [string]$Command)
    if ([string]::IsNullOrWhiteSpace($Command)) { return $null }

    $trimmed = $Command.Trim()
    if ($trimmed.StartsWith('"')) {
        $endQuote = $trimmed.IndexOf('"', 1)
        if ($endQuote -gt 1) {
            return $trimmed.Substring(1, $endQuote - 1)
        }
    }
    return ($trimmed -split '\s+', 2)[0]
}

function Test-BinaryContainsAscii {
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string]$Needle
    )
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $text = [System.Text.Encoding]::ASCII.GetString($bytes)
    $text.Contains($Needle)
}

function Get-NormalizedSha256 {
    param([AllowNull()] [string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    ($Value -replace '[:\-\s]', '').ToLowerInvariant()
}

$fullSha = Invoke-Git @('rev-parse', 'HEAD')
$shortSha = Invoke-Git @('rev-parse', '--short=12', 'HEAD')
$branch = Invoke-Git @('branch', '--show-current')
$status = Invoke-Git @('status', '--short')
$isDirty = -not [string]::IsNullOrWhiteSpace($status)

# Ensure the local CI gate (git pre-commit/pre-push hooks) is enabled for this
# clone so commits/pushes run the applicable Rust and operational-Python gates.
Invoke-Git @('config', 'core.hooksPath', '.githooks') | Out-Null

$failures = New-Object System.Collections.Generic.List[string]
$uacPolicy = Get-GilbrethUiAccessPolicyState

$releaseExists = Test-Path $releaseExe
$releaseContainsSha = $false
$releaseItem = $null
if ($releaseExists) {
    $releaseItem = Get-Item $releaseExe
    $releaseContainsSha = Test-BinaryContainsAscii -Path $releaseExe -Needle $shortSha
}
else {
    $failures.Add("release executable missing: $releaseExe")
}
if ($releaseExists -and -not $releaseContainsSha) {
    $failures.Add("release executable does not contain embedded Git SHA $shortSha")
}

$releaseHelperExists = Test-Path $releaseHelperExe
$releaseHelperItem = $null
if ($releaseHelperExists) {
    $releaseHelperItem = Get-Item $releaseHelperExe
}
else {
    $failures.Add("release elevated helper missing: $releaseHelperExe")
}

$runValue = $null
$runValueFound = $false
$runPath = $null
$runPathExists = $false
$installLane = $null
try {
    $runValue = (Get-ItemProperty -Path $runKey -ErrorAction Stop).Gilbreth
    $runValueFound = $true
    $runPath = Get-CommandPath $runValue
    if ($runPath) {
        $runPathExists = Test-Path -LiteralPath $runPath -PathType Leaf
        $installLane = Resolve-GilbrethDeveloperInstallLane `
            -RunPath $runPath `
            -ReleaseExe $releaseExe `
            -StableExe $stableExe
    }
}
catch {
    $failures.Add("HKCU Run value Gilbreth is missing")
}
if ($runValueFound -and [string]::IsNullOrWhiteSpace($runValue)) {
    $failures.Add("HKCU Run value Gilbreth is empty")
}
if ($runValueFound -and -not [string]::IsNullOrWhiteSpace($runValue) -and -not $installLane) {
    $failures.Add(
        "HKCU Run value does not point at a supported developer executable: $releaseExe or $stableExe"
    )
}
if ($runValueFound -and $runPath -and -not $runPathExists) {
    $failures.Add("HKCU Run target does not exist: $runPath")
}

$runTargetContainsSha = $false
if ($installLane -and $runPathExists) {
    $runTargetContainsSha = Test-BinaryContainsAscii -Path $runPath -Needle $shortSha
}
if ($installLane -and $runPathExists -and -not $runTargetContainsSha) {
    $failures.Add("HKCU Run target does not contain embedded Git SHA $shortSha")
}

$running = @(
    Get-Process -Name 'gilbreth-app' -ErrorAction SilentlyContinue |
        ForEach-Object {
            try {
                [pscustomobject]@{
                    Id = $_.Id
                    Path = $_.Path
                    StartTime = $_.StartTime
                }
            }
            catch {
                [pscustomobject]@{
                    Id = $_.Id
                    Path = $null
                    StartTime = $null
                }
            }
        }
)
if ($RequireRunning -and $running.Count -eq 0) {
    $failures.Add("Gilbreth is not running")
}

$configExists = Test-Path -LiteralPath $configPath -PathType Leaf
$configuredHelperPath = Get-GilbrethRecordConfigValue `
    -ConfigPath $configPath `
    -Key 'elevated_helper_path'
$configuredSignerSha256 = Get-GilbrethRecordConfigValue `
    -ConfigPath $configPath `
    -Key 'elevated_helper_required_signer_sha256'
$helperPathConfigured = -not [string]::IsNullOrWhiteSpace($configuredHelperPath)
$effectiveHelperPath = if ($helperPathConfigured) { $configuredHelperPath } else { $releaseHelperExe }
$effectiveHelperPathAbsolute = $false
$effectiveHelperPathExists = $false
$effectiveHelperFileNameOk = $false
$effectiveHelperPathSecure = $false
if (-not [string]::IsNullOrWhiteSpace($effectiveHelperPath)) {
    $effectiveHelperPathAbsolute = [System.IO.Path]::IsPathRooted($effectiveHelperPath)
    $effectiveHelperPathExists = Test-Path -LiteralPath $effectiveHelperPath -PathType Leaf
    $effectiveHelperFileNameOk = [string]::Equals(
        [System.IO.Path]::GetFileName($effectiveHelperPath),
        'gilbreth-elevated-record-helper.exe',
        [System.StringComparison]::OrdinalIgnoreCase
    )
    $effectiveHelperPathSecure = Test-GilbrethUiAccessSecureHelperPath -Path $effectiveHelperPath
}

$normalizedConfiguredSignerSha256 = Get-NormalizedSha256 $configuredSignerSha256
$signerSha256Configured = -not [string]::IsNullOrWhiteSpace($normalizedConfiguredSignerSha256)
$signerSha256FormatValid = $signerSha256Configured -and ($normalizedConfiguredSignerSha256 -match '^[0-9a-f]{64}$')
$authenticode = $null
$authenticodeStatus = 'not checked'
$authenticodeTimestamped = $false
$authenticodeSignerMatchesConfig = $null
$uiAccessManifestStatus = $null
$uiAccessManifestPresent = $false
$uiAccessManifestRequestedExecutionLevel = $null
$uiAccessManifestValue = $null
$uiAccessManifestTrue = $false
if ($effectiveHelperPathExists) {
    $authenticode = Get-GilbrethAuthenticodeSignerSha256 -Path $effectiveHelperPath
    $authenticodeStatus = $authenticode.Status
    $authenticodeTimestamped = [bool]$authenticode.Timestamped
    if ($signerSha256Configured) {
        $authenticodeSignerMatchesConfig = (
            $authenticode.SignerSha256 -and
            [string]::Equals(
                $authenticode.SignerSha256,
                $normalizedConfiguredSignerSha256,
                [System.StringComparison]::OrdinalIgnoreCase
            )
        )
    }
    $uiAccessManifestStatus = Get-GilbrethUiAccessManifestStatus -Path $effectiveHelperPath
    $uiAccessManifestPresent = $uiAccessManifestStatus.HasManifest
    $uiAccessManifestRequestedExecutionLevel = $uiAccessManifestStatus.RequestedExecutionLevel
    $uiAccessManifestValue = $uiAccessManifestStatus.UiAccess
    $uiAccessManifestTrue = $uiAccessManifestStatus.UiAccessTrue
}
$effectiveHelperDirectoryAcl = $null
$effectiveHelperDirectoryAdminWriteOnly = $false
if ($effectiveHelperPathExists) {
    $effectiveHelperDirectoryAcl = Test-GilbrethDirectoryAdminOnlyWrites -Path (Split-Path -Parent $effectiveHelperPath)
    $effectiveHelperDirectoryAdminWriteOnly = [bool]$effectiveHelperDirectoryAcl.admin_write_only
}

if ($RequireReleaseElevatedHelperConfig) {
    if (-not $uacPolicy.uac_enabled) {
        $failures.Add('Windows UAC EnableLUA policy is disabled')
    }
    if (-not $uacPolicy.secure_uia_paths_enabled) {
        $failures.Add('Windows UIAccess secure-location policy is disabled')
    }
    if (-not $configExists) {
        $failures.Add("Gilbreth config missing: $configPath")
    }
    if (-not $helperPathConfigured) {
        $failures.Add("record.elevated_helper_path is not configured")
    }
    if (-not $effectiveHelperPathAbsolute) {
        $failures.Add("record.elevated_helper_path is not absolute")
    }
    if (-not $effectiveHelperFileNameOk) {
        $failures.Add("record.elevated_helper_path must end with gilbreth-elevated-record-helper.exe")
    }
    if (-not $effectiveHelperPathExists) {
        $failures.Add("configured elevated helper does not exist: $effectiveHelperPath")
    }
    if (-not $effectiveHelperPathSecure) {
        $failures.Add("configured elevated helper is not under Program Files")
    }
    if (-not $signerSha256Configured) {
        $failures.Add("record.elevated_helper_required_signer_sha256 is not configured")
    }
    elseif (-not $signerSha256FormatValid) {
        $failures.Add("record.elevated_helper_required_signer_sha256 is not a 64-hex SHA-256")
    }
    if ($authenticodeStatus -ne 'Valid') {
        $failures.Add("configured elevated helper Authenticode status is $authenticodeStatus")
    }
    elseif (-not $authenticodeTimestamped) {
        $failures.Add('configured elevated helper Authenticode signature is not timestamped')
    }
    if ($signerSha256Configured -and -not $authenticodeSignerMatchesConfig) {
        $failures.Add("configured elevated helper signer SHA-256 does not match config")
    }
    if (-not $uiAccessManifestTrue) {
        $failures.Add('configured elevated helper manifest does not request uiAccess=true')
    }
    if (-not $effectiveHelperDirectoryAdminWriteOnly) {
        $failures.Add('configured elevated helper directory grants write access to non-admin principals')
    }
}

Write-Host "Gilbreth build/install verification" -ForegroundColor Cyan
Write-Host "Repo: $repoRoot"
Write-Host "Branch: $branch"
Write-Host "HEAD: $fullSha"
Write-Host "Embedded SHA expected: $shortSha"
Write-Host "Working tree dirty: $isDirty"
if ($isDirty) {
    Write-Host "Dirty files:" -ForegroundColor Yellow
    $status -split "`n" | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
}
Write-Host "Local CI gate: core.hooksPath = .githooks (git hooks enabled)"
Write-Host ""
Write-Host "Release exe: $releaseExe"
Write-Host "Release exists: $releaseExists"
if ($releaseItem) {
    Write-Host "Release last write: $($releaseItem.LastWriteTime)"
    Write-Host "Release size: $($releaseItem.Length)"
}
Write-Host "Release contains embedded SHA: $releaseContainsSha"
Write-Host ""
Write-Host "Release helper exe: $releaseHelperExe"
Write-Host "Release helper exists: $releaseHelperExists"
if ($releaseHelperItem) {
    Write-Host "Release helper last write: $($releaseHelperItem.LastWriteTime)"
    Write-Host "Release helper size: $($releaseHelperItem.Length)"
}
Write-Host ""
Write-Host "Elevated helper config path: $configPath"
Write-Host "Elevated helper config exists: $configExists"
Write-Host "Configured helper path: $(if ($helperPathConfigured) { $configuredHelperPath } else { '<empty; using release helper beside app>' })"
Write-Host "Effective helper path: $effectiveHelperPath"
Write-Host "Effective helper path absolute: $effectiveHelperPathAbsolute"
Write-Host "Effective helper path exists: $effectiveHelperPathExists"
Write-Host "Effective helper filename valid: $effectiveHelperFileNameOk"
Write-Host "Effective helper under Program Files: $effectiveHelperPathSecure"
Write-Host "Signer SHA-256 configured: $signerSha256Configured"
Write-Host "Signer SHA-256 format valid: $signerSha256FormatValid"
Write-Host "Effective helper Authenticode status: $authenticodeStatus"
Write-Host "Effective helper Authenticode timestamped: $authenticodeTimestamped"
Write-Host "Effective helper signer matches config: $(if ($null -eq $authenticodeSignerMatchesConfig) { '<not checked>' } else { $authenticodeSignerMatchesConfig })"
Write-Host "Effective helper manifest present: $uiAccessManifestPresent"
Write-Host "Effective helper requestedExecutionLevel: $(if ($uiAccessManifestRequestedExecutionLevel) { $uiAccessManifestRequestedExecutionLevel } else { '<not found>' })"
Write-Host "Effective helper uiAccess manifest value: $(if ($uiAccessManifestValue) { $uiAccessManifestValue } else { '<not found>' })"
Write-Host "Effective helper uiAccess=true: $uiAccessManifestTrue"
Write-Host "Effective helper directory admin-write-only: $effectiveHelperDirectoryAdminWriteOnly"
Write-Host "Windows UAC EnableLUA effective value: $($uacPolicy.enable_lua.effective_value)"
Write-Host "Windows UAC enabled: $($uacPolicy.uac_enabled)"
Write-Host "Windows UIAccess secure-location policy effective value: $($uacPolicy.enable_secure_uia_paths.effective_value)"
Write-Host "Windows UIAccess secure-location policy enabled: $($uacPolicy.secure_uia_paths_enabled)"
Write-Host "Release elevated-helper config required: $($RequireReleaseElevatedHelperConfig.IsPresent)"
Write-Host ""
Write-Host "HKCU Run value: $runValue"
Write-Host "HKCU Run path: $runPath"
Write-Host "HKCU Run path exists: $runPathExists"
Write-Host "Developer install lane: $(if ($installLane) { $installLane.name } else { '<unsupported>' })"
Write-Host "HKCU Run target contains embedded SHA: $runTargetContainsSha"
Write-Host ""
Write-Host "Gilbreth running: $($running.Count -gt 0)"
foreach ($process in $running) {
    Write-Host "  PID $($process.Id): $($process.Path) started $($process.StartTime)"
}

if ($failures.Count -gt 0) {
    Write-Host ""
    Write-Host "FAIL" -ForegroundColor Red
    foreach ($failure in $failures) {
        Write-Host "  - $failure" -ForegroundColor Red
    }
    throw "build/install verification failed"
}

Write-Host ""
Write-Host "PASS" -ForegroundColor Green
