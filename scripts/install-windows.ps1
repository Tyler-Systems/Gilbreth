#Requires -Version 5.1
<#
.SYNOPSIS
    Developer-only convenience install: build release binaries from this
    checkout, copy them to the legacy per-user development location, and create
    Start Menu + Desktop shortcuts.

.DESCRIPTION
    This is not the public installer and must not be used to construct or
    validate a release package. It requires Cargo plus a repository checkout,
    installs into the legacy %LOCALAPPDATA%\Gilbreth\bin development root, and
    may include the out-of-scope elevated helper. Public Windows releases are
    built by scripts\build-windows-package.ps1 and installed by the pinned Inno
    Setup package under %LOCALAPPDATA%\Programs\Gilbreth.

    Replaces `cargo run` for day-to-day use. After running this once, launch
    Gilbreth by double-clicking the "Gilbreth" shortcut (Desktop / Start Menu) or
    the installed exe -- no console window appears (unlike a debug build), and
    the tray icon comes up.

    The tray binary is installed to %LOCALAPPDATA%\Gilbreth\bin\gilbreth-app.exe
    and the elevated Record Routine helper is installed beside it as
    gilbreth-elevated-record-helper.exe. Keeping the helper beside the tray binary
    is required by the 2c-E helper launch path. Re-run this script after pulling
    changes to update the installed copies; quit Gilbreth from the tray first if
    it is running (Windows cannot overwrite a running exe).

.PARAMETER LaunchAtStartup
    Also register per-user autostart (HKCU ...\Run) pointing at the installed exe,
    so Gilbreth launches on logon. Equivalent to the tray "Launch at startup"
    toggle, but pre-pointed at the stable installed path.

.PARAMETER NoDesktopShortcut
    Skip the Desktop shortcut (the Start Menu shortcut is still created).

.PARAMETER ElevatedHelperSignerSha256
    Optional Authenticode signer certificate SHA-256 required for the elevated
    Record Routine helper. Omit for local unsigned debug/dev installs.

.PARAMETER ElevatedHelperPath
    Optional absolute path to the elevated Record Routine helper. Use this for
    signed helper installs under Program Files; omit to launch the helper beside
    the tray binary.

.EXAMPLE
    .\scripts\install-windows.ps1

.EXAMPLE
    .\scripts\install-windows.ps1 -LaunchAtStartup
#>
[CmdletBinding()]
param(
    [switch]$LaunchAtStartup,
    [switch]$NoDesktopShortcut,
    [string]$ElevatedHelperSignerSha256,
    [string]$ElevatedHelperPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'install_helpers.ps1')

$repoRoot = Split-Path -Parent $PSScriptRoot
Write-Host "Repo: $repoRoot"

# 1. Build the release binaries (console-less, optimized).
Write-Host "Building tray release binary (cargo build --release -p gilbreth-app)..." -ForegroundColor Cyan
Push-Location $repoRoot
try {
    & cargo build --release -p gilbreth-app
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed (exit $LASTEXITCODE)" }
    Write-Host "Building elevated helper release binary (cargo build --release -p gilbreth-capture-windows --bin gilbreth-elevated-record-helper)..." -ForegroundColor Cyan
    & cargo build --release -p gilbreth-capture-windows --bin gilbreth-elevated-record-helper
    if ($LASTEXITCODE -ne 0) { throw "helper cargo build failed (exit $LASTEXITCODE)" }
}
finally {
    Pop-Location
}

$builtExe = Join-Path $repoRoot 'target\release\gilbreth-app.exe'
$builtHelperExe = Join-Path $repoRoot 'target\release\gilbreth-elevated-record-helper.exe'
if (-not (Test-Path $builtExe)) { throw "build output not found: $builtExe" }
if (-not (Test-Path $builtHelperExe)) { throw "helper build output not found: $builtHelperExe" }

# 2. Refuse to overwrite a running instance (the file would be locked).
if (Get-Process -Name 'gilbreth-app' -ErrorAction SilentlyContinue) {
    throw "Gilbreth is running. Quit it from the tray (right-click -> Quit), then re-run this script."
}
if (Get-Process -Name 'gilbreth-elevated-record-helper' -ErrorAction SilentlyContinue) {
    throw "The elevated Record Routine helper is running. Stop the recording, then re-run this script."
}

# 3. Install to a stable per-user location.
$installDir = Join-Path $env:LOCALAPPDATA 'Gilbreth\bin'
$installedExe = Join-Path $installDir 'gilbreth-app.exe'
$installedHelperExe = Join-Path $installDir 'gilbreth-elevated-record-helper.exe'
New-Item -ItemType Directory -Force -Path $installDir | Out-Null
Copy-Item -Path $builtExe -Destination $installedExe -Force
Copy-Item -Path $builtHelperExe -Destination $installedHelperExe -Force
Write-Host "Installed: $installedExe" -ForegroundColor Green
Write-Host "Installed elevated helper: $installedHelperExe" -ForegroundColor Green

if (-not [string]::IsNullOrWhiteSpace($ElevatedHelperSignerSha256)) {
    $configPath = Set-GilbrethElevatedHelperSignerSha256 `
        -LocalDataDir (Join-Path $env:LOCALAPPDATA 'Gilbreth') `
        -SignerSha256 $ElevatedHelperSignerSha256
    Write-Host "Configured elevated helper signer SHA-256 in $configPath" -ForegroundColor Green
}
if (-not [string]::IsNullOrWhiteSpace($ElevatedHelperPath)) {
    $configPath = Set-GilbrethElevatedHelperPath `
        -LocalDataDir (Join-Path $env:LOCALAPPDATA 'Gilbreth') `
        -HelperPath $ElevatedHelperPath
    Write-Host "Configured elevated helper path in $configPath" -ForegroundColor Green
}

# 4. Create shortcuts. GetFolderPath('Desktop') resolves a OneDrive-redirected
#    Desktop correctly; CreateShortcut writes a standard .lnk.
function New-AppShortcut {
    param([Parameter(Mandatory)] [string]$LinkPath, [Parameter(Mandatory)] [string]$Target)
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($LinkPath)
    $shortcut.TargetPath = $Target
    $shortcut.WorkingDirectory = Split-Path -Parent $Target
    $shortcut.IconLocation = $Target
    $shortcut.Description = 'Gilbreth activity capture'
    $shortcut.Save()
}

$startMenuDir = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs'
New-Item -ItemType Directory -Force -Path $startMenuDir | Out-Null
New-AppShortcut -LinkPath (Join-Path $startMenuDir 'Gilbreth.lnk') -Target $installedExe
Write-Host "Start Menu shortcut created." -ForegroundColor Green

if (-not $NoDesktopShortcut) {
    $desktop = [Environment]::GetFolderPath('Desktop')
    New-AppShortcut -LinkPath (Join-Path $desktop 'Gilbreth.lnk') -Target $installedExe
    Write-Host "Desktop shortcut created." -ForegroundColor Green
}

# 5. Optional: per-user autostart, pointed at the stable installed exe.
if ($LaunchAtStartup) {
    $runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
    Set-ItemProperty -Path $runKey -Name 'Gilbreth' -Value ('"{0}"' -f $installedExe)
    Write-Host "Autostart registered (HKCU ...\Run\Gilbreth)." -ForegroundColor Green
}

Write-Host ""
Write-Host "Done. Double-click the 'Gilbreth' shortcut (Desktop / Start Menu) to launch -- " -ForegroundColor Cyan -NoNewline
Write-Host "no console window, tray icon appears." -ForegroundColor Cyan
if (-not $LaunchAtStartup) {
    Write-Host "Autostart: flip the tray's 'Launch at startup' toggle, or re-run with -LaunchAtStartup." -ForegroundColor DarkGray
}
