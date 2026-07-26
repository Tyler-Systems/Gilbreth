#Requires -Version 5.1

Set-StrictMode -Version Latest

function ConvertTo-GilbrethSha256Hex {
    param(
        [Parameter(Mandatory)]
        [string]$Value
    )

    $normalized = ($Value -replace '[:\-\s]', '').ToLowerInvariant()
    if ($normalized -notmatch '^[0-9a-f]{64}$') {
        throw 'Expected a 64-hex-character SHA-256 fingerprint.'
    }
    return $normalized
}

function Get-GilbrethFileSha256Hex {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $stream = [System.IO.File]::OpenRead($Path)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha256.ComputeHash($stream)
        return (($hash | ForEach-Object { $_.ToString('x2') }) -join '')
    }
    finally {
        $sha256.Dispose()
        $stream.Dispose()
    }
}

function Test-GilbrethPathEquals {
    param(
        [AllowNull()]
        [string]$Path,

        [AllowNull()]
        [string]$ExpectedPath
    )

    if ([string]::IsNullOrWhiteSpace($Path) -or [string]::IsNullOrWhiteSpace($ExpectedPath)) {
        return $false
    }

    try {
        $fullPath = [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
        $fullExpectedPath = [System.IO.Path]::GetFullPath($ExpectedPath).TrimEnd('\')
    }
    catch {
        return $false
    }

    return $fullPath.Equals(
        $fullExpectedPath,
        [System.StringComparison]::OrdinalIgnoreCase
    )
}

function Resolve-GilbrethDeveloperInstallLane {
    param(
        [AllowNull()]
        [string]$RunPath,

        [Parameter(Mandatory)]
        [string]$ReleaseExe,

        [Parameter(Mandatory)]
        [string]$StableExe
    )

    if ([string]::IsNullOrWhiteSpace($RunPath) -or -not [System.IO.Path]::IsPathRooted($RunPath)) {
        return $null
    }
    $runRoot = [System.IO.Path]::GetPathRoot($RunPath)
    if ([string]::IsNullOrWhiteSpace($runRoot) -or $runRoot -eq '\' -or $runRoot -match '^[A-Za-z]:$') {
        return $null
    }

    $candidates = @(
        [pscustomobject]@{
            name = 'repo-release'
            app_path = [System.IO.Path]::GetFullPath($ReleaseExe)
        },
        [pscustomobject]@{
            name = 'stable-install'
            app_path = [System.IO.Path]::GetFullPath($StableExe)
        }
    )

    foreach ($candidate in $candidates) {
        if (Test-GilbrethPathEquals -Path $RunPath -ExpectedPath $candidate.app_path) {
            return $candidate
        }
    }

    return $null
}

function ConvertTo-GilbrethElevatedHelperPath {
    param(
        [Parameter(Mandatory)]
        [string]$Value
    )

    if (-not [System.IO.Path]::IsPathRooted($Value)) {
        throw 'Expected an absolute elevated helper path.'
    }
    $root = [System.IO.Path]::GetPathRoot($Value)
    if ([string]::IsNullOrWhiteSpace($root) -or $root -eq '\' -or $root -match '^[A-Za-z]:$') {
        throw 'Expected a fully qualified elevated helper path.'
    }

    $fullPath = [System.IO.Path]::GetFullPath($Value)
    if ([System.IO.Path]::GetFileName($fullPath) -ne 'gilbreth-elevated-record-helper.exe') {
        throw 'Expected elevated helper path to end with gilbreth-elevated-record-helper.exe.'
    }
    if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
        throw "Elevated helper path does not exist: $fullPath"
    }
    return $fullPath
}

function ConvertFrom-GilbrethTomlString {
    param(
        [Parameter(Mandatory)]
        [string]$Value
    )

    $text = $Value.Trim()
    if ($text.StartsWith("'")) {
        $end = $text.IndexOf("'", 1)
        if ($end -gt 0) {
            return $text.Substring(1, $end - 1)
        }
    }

    if ($text.StartsWith('"')) {
        $builder = New-Object System.Text.StringBuilder
        $escaped = $false
        for ($i = 1; $i -lt $text.Length; $i++) {
            $ch = $text[$i]
            if ($escaped) {
                switch ($ch) {
                    '"' { [void]$builder.Append('"') }
                    '\' { [void]$builder.Append('\') }
                    'b' { [void]$builder.Append("`b") }
                    'f' { [void]$builder.Append("`f") }
                    'n' { [void]$builder.Append("`n") }
                    'r' { [void]$builder.Append("`r") }
                    't' { [void]$builder.Append("`t") }
                    default { [void]$builder.Append($ch) }
                }
                $escaped = $false
                continue
            }
            if ($ch -eq '\') {
                $escaped = $true
                continue
            }
            if ($ch -eq '"') {
                return $builder.ToString()
            }
            [void]$builder.Append($ch)
        }
    }

    return (($text -split '\s+#', 2)[0]).Trim()
}

function Get-GilbrethRecordConfigValue {
    param(
        [Parameter(Mandatory)]
        [string]$ConfigPath,

        [Parameter(Mandatory)]
        [string]$Key
    )

    if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
        return $null
    }

    $raw = Get-Content -LiteralPath $ConfigPath -Raw
    $normalizedRaw = ($raw -replace "`r`n", "`n") -replace "`r", "`n"
    $lines = @($normalizedRaw.Split("`n"))
    $inRecord = $false
    $keyPattern = '^\s*' + [regex]::Escape($Key) + '\s*=\s*(.+)$'

    foreach ($line in $lines) {
        if ($line -match '^\s*\[([^\]]+)\]\s*$') {
            $inRecord = ($Matches[1].Trim() -eq 'record')
            continue
        }
        if ($inRecord -and $line -match $keyPattern) {
            return ConvertFrom-GilbrethTomlString -Value $Matches[1]
        }
    }

    return $null
}

function Test-GilbrethPathUnderDirectory {
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$Directory
    )

    if ([string]::IsNullOrWhiteSpace($Path) -or [string]::IsNullOrWhiteSpace($Directory)) {
        return $false
    }

    try {
        $fullPath = [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
        $fullDirectory = [System.IO.Path]::GetFullPath($Directory).TrimEnd('\')
    }
    catch {
        return $false
    }

    return $fullPath.Equals($fullDirectory, [System.StringComparison]::OrdinalIgnoreCase) `
        -or $fullPath.StartsWith($fullDirectory + '\', [System.StringComparison]::OrdinalIgnoreCase)
}

function Test-GilbrethUiAccessSecureHelperPath {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $programFilesRoots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}) |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Select-Object -Unique
    foreach ($root in $programFilesRoots) {
        if (Test-GilbrethPathUnderDirectory -Path $Path -Directory $root) {
            return $true
        }
    }
    return $false
}

function Test-GilbrethAdminWriteSid {
    param(
        [Parameter(Mandatory)]
        [System.Security.Principal.SecurityIdentifier]$Sid
    )

    $trustedInstallerSid = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
    return $Sid.Value -eq 'S-1-5-18' `
        -or $Sid.Value -eq 'S-1-5-32-544' `
        -or $Sid.Value -eq $trustedInstallerSid
}

function Get-GilbrethDirectoryWriteRightsMask {
    $writeMask = 0
    @(
        [System.Security.AccessControl.FileSystemRights]::WriteData,
        [System.Security.AccessControl.FileSystemRights]::AppendData,
        [System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes,
        [System.Security.AccessControl.FileSystemRights]::WriteAttributes,
        [System.Security.AccessControl.FileSystemRights]::Delete,
        [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles,
        [System.Security.AccessControl.FileSystemRights]::ChangePermissions,
        [System.Security.AccessControl.FileSystemRights]::TakeOwnership
    ) | ForEach-Object { $writeMask = $writeMask -bor [int]$_ }
    return $writeMask
}

function Test-GilbrethFileSystemRightsIncludesWrite {
    param(
        [Parameter(Mandatory)]
        [System.Security.AccessControl.FileSystemRights]$Rights
    )

    return (([int]$Rights -band (Get-GilbrethDirectoryWriteRightsMask)) -ne 0)
}

function Test-GilbrethAccessRuleGrantsUntrustedWrite {
    param(
        [Parameter(Mandatory)]
        [System.Security.AccessControl.FileSystemAccessRule]$Rule
    )

    if ($Rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) {
        return $false
    }
    if (-not (Test-GilbrethFileSystemRightsIncludesWrite -Rights $Rule.FileSystemRights)) {
        return $false
    }

    $sid = $Rule.IdentityReference
    if (-not ($sid -is [System.Security.Principal.SecurityIdentifier])) {
        $sid = $sid.Translate([System.Security.Principal.SecurityIdentifier])
    }
    return -not (Test-GilbrethAdminWriteSid -Sid $sid)
}

function Test-GilbrethDirectoryAdminOnlyWrites {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $result = [ordered]@{
        path = $fullPath
        exists = Test-Path -LiteralPath $fullPath -PathType Container
        admin_write_only = $false
        write_violations = @()
    }
    if (-not $result.exists) {
        return [pscustomobject]$result
    }

    $acl = Get-Acl -LiteralPath $fullPath
    $violations = @(
        $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) |
            Where-Object { Test-GilbrethAccessRuleGrantsUntrustedWrite -Rule $_ } |
            ForEach-Object {
                [ordered]@{
                    sid = $_.IdentityReference.Value
                    rights = $_.FileSystemRights.ToString()
                    inherited = [bool]$_.IsInherited
                }
            }
    )

    $result.write_violations = @($violations)
    $result.admin_write_only = ($violations.Count -eq 0)
    return [pscustomobject]$result
}

function Test-GilbrethIsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-GilbrethPolicyDword {
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [int]$DefaultValue
    )

    $exists = $false
    $value = $null
    try {
        if (Test-Path -LiteralPath $Path) {
            $property = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction SilentlyContinue
            if ($null -ne $property -and $property.PSObject.Properties.Name -contains $Name) {
                $exists = $true
                $value = [int]$property.$Name
            }
        }
    }
    catch {
        $exists = $false
        $value = $null
    }

    [ordered]@{
        registry_path = $Path
        value_name = $Name
        exists = $exists
        value = $value
        default_value = $DefaultValue
        effective_value = if ($exists) { $value } else { $DefaultValue }
    }
}

function Get-GilbrethUiAccessPolicyState {
    $policyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $enableLua = Get-GilbrethPolicyDword `
        -Path $policyPath `
        -Name 'EnableLUA' `
        -DefaultValue 1
    $enableSecureUiaPaths = Get-GilbrethPolicyDword `
        -Path $policyPath `
        -Name 'EnableSecureUIAPaths' `
        -DefaultValue 1

    [ordered]@{
        registry_path = $policyPath
        enable_lua = $enableLua
        enable_secure_uia_paths = $enableSecureUiaPaths
        uac_enabled = ([int]$enableLua.effective_value -ne 0)
        secure_uia_paths_enabled = ([int]$enableSecureUiaPaths.effective_value -ne 0)
    }
}

function Get-GilbrethAuthenticodeSignerSha256 {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    try {
        $signature = Get-AuthenticodeSignature -LiteralPath $Path
        $signerSha256 = $null
        if ($signature.SignerCertificate) {
            $signerSha256 = $signature.SignerCertificate.GetCertHashString('SHA256').ToLowerInvariant()
        }
        [pscustomobject]@{
            Status = $signature.Status.ToString()
            SignerSha256 = $signerSha256
            Timestamped = ($null -ne $signature.TimeStamperCertificate)
            TimeStamperThumbprint = if ($signature.TimeStamperCertificate) {
                $signature.TimeStamperCertificate.Thumbprint
            }
            else {
                $null
            }
        }
    }
    catch {
        [pscustomobject]@{
            Status = "error: $($_.Exception.Message)"
            SignerSha256 = $null
            Timestamped = $false
            TimeStamperThumbprint = $null
        }
    }
}

function Add-GilbrethManifestResourceApi {
    if ('GilbrethManifestResource.NativeMethods' -as [type]) {
        return
    }

    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace GilbrethManifestResource
{
    public static class NativeMethods
    {
        public const uint LOAD_LIBRARY_AS_DATAFILE = 0x00000002;
        public const uint LOAD_LIBRARY_AS_IMAGE_RESOURCE = 0x00000020;

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr LoadLibraryEx(string lpFileName, IntPtr hFile, uint dwFlags);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool FreeLibrary(IntPtr hModule);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr FindResource(IntPtr hModule, IntPtr lpName, IntPtr lpType);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr LoadResource(IntPtr hModule, IntPtr hResInfo);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr LockResource(IntPtr hResData);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint SizeofResource(IntPtr hModule, IntPtr hResInfo);
    }
}
'@
}

function ConvertFrom-GilbrethManifestBytes {
    param(
        [Parameter(Mandatory)]
        [byte[]]$Bytes
    )

    if ($Bytes.Length -ge 2 -and $Bytes[0] -eq 0xff -and $Bytes[1] -eq 0xfe) {
        return [System.Text.Encoding]::Unicode.GetString($Bytes)
    }
    if ($Bytes.Length -ge 2 -and $Bytes[0] -eq 0xfe -and $Bytes[1] -eq 0xff) {
        return [System.Text.Encoding]::BigEndianUnicode.GetString($Bytes)
    }
    if ($Bytes.Length -ge 3 -and $Bytes[0] -eq 0xef -and $Bytes[1] -eq 0xbb -and $Bytes[2] -eq 0xbf) {
        return [System.Text.Encoding]::UTF8.GetString($Bytes, 3, $Bytes.Length - 3)
    }

    $utf8 = [System.Text.Encoding]::UTF8.GetString($Bytes)
    if ($utf8.Contains([char]0)) {
        $utf16 = [System.Text.Encoding]::Unicode.GetString($Bytes)
        if (-not $utf16.Contains([char]0)) {
            return $utf16
        }
    }
    return $utf8
}

function Get-GilbrethEmbeddedApplicationManifest {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Executable not found: $Path"
    }

    Add-GilbrethManifestResourceApi

    $flags = [GilbrethManifestResource.NativeMethods]::LOAD_LIBRARY_AS_DATAFILE -bor
        [GilbrethManifestResource.NativeMethods]::LOAD_LIBRARY_AS_IMAGE_RESOURCE
    $module = [GilbrethManifestResource.NativeMethods]::LoadLibraryEx($Path, [IntPtr]::Zero, $flags)
    if ($module -eq [IntPtr]::Zero) {
        $errorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "Unable to load executable resources for manifest check: $Path (Win32 error $errorCode)"
    }

    try {
        $resourceTypeManifest = [IntPtr]24
        foreach ($resourceId in 1, 2, 3) {
            $resourceInfo = [GilbrethManifestResource.NativeMethods]::FindResource(
                $module,
                [IntPtr]$resourceId,
                $resourceTypeManifest
            )
            if ($resourceInfo -eq [IntPtr]::Zero) {
                continue
            }

            $size = [GilbrethManifestResource.NativeMethods]::SizeofResource($module, $resourceInfo)
            if ($size -eq 0) {
                continue
            }

            $resourceHandle = [GilbrethManifestResource.NativeMethods]::LoadResource($module, $resourceInfo)
            if ($resourceHandle -eq [IntPtr]::Zero) {
                continue
            }
            $resourcePointer = [GilbrethManifestResource.NativeMethods]::LockResource($resourceHandle)
            if ($resourcePointer -eq [IntPtr]::Zero) {
                continue
            }

            $bytes = New-Object byte[] $size
            [System.Runtime.InteropServices.Marshal]::Copy($resourcePointer, $bytes, 0, [int]$size)
            return ConvertFrom-GilbrethManifestBytes -Bytes $bytes
        }
    }
    finally {
        [void][GilbrethManifestResource.NativeMethods]::FreeLibrary($module)
    }

    return $null
}

function Get-GilbrethUiAccessManifestStatus {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $manifest = Get-GilbrethEmbeddedApplicationManifest -Path $Path
    $requestedExecutionLevel = $null
    $uiAccess = $null

    if (-not [string]::IsNullOrWhiteSpace($manifest)) {
        try {
            [xml]$xml = $manifest
            $nodes = $xml.SelectNodes("//*[local-name()='requestedExecutionLevel']")
            foreach ($node in $nodes) {
                $requestedExecutionLevel = $node.GetAttribute('level')
                $uiAccess = $node.GetAttribute('uiAccess')
                break
            }
        }
        catch {
            if ($manifest -match '<\s*requestedExecutionLevel\b[^>]*\blevel\s*=\s*["'']([^"'']+)["'']') {
                $requestedExecutionLevel = $Matches[1]
            }
            if ($manifest -match '<\s*requestedExecutionLevel\b[^>]*\buiAccess\s*=\s*["'']([^"'']+)["'']') {
                $uiAccess = $Matches[1]
            }
        }
    }

    [pscustomobject]@{
        HasManifest = -not [string]::IsNullOrWhiteSpace($manifest)
        RequestedExecutionLevel = $requestedExecutionLevel
        UiAccess = $uiAccess
        UiAccessTrue = [string]::Equals($uiAccess, 'true', [System.StringComparison]::OrdinalIgnoreCase)
    }
}

function Set-GilbrethRecordConfigString {
    param(
        [Parameter(Mandatory)]
        [string]$ConfigPath,

        [Parameter(Mandatory)]
        [string]$Key,

        [Parameter(Mandatory)]
        [string]$Value
    )

    $parent = Split-Path -Parent $ConfigPath
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }

    $raw = ''
    $newline = "`r`n"
    if (Test-Path $ConfigPath) {
        $raw = Get-Content -LiteralPath $ConfigPath -Raw
        if ($raw -notmatch "`r`n") {
            $newline = "`n"
        }
    }

    $normalizedRaw = ($raw -replace "`r`n", "`n") -replace "`r", "`n"
    $trimmedRaw = $normalizedRaw.TrimEnd("`n")
    $lines = @()
    if ($trimmedRaw.Length -gt 0) {
        $lines = @($trimmedRaw.Split("`n"))
    }

    $escapedValue = $Value.Replace('\', '\\').Replace('"', '\"')
    $entryLine = ('{0} = "{1}"' -f $Key, $escapedValue)
    $recordStart = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i].Trim() -eq '[record]') {
            $recordStart = $i
            break
        }
    }

    if ($recordStart -lt 0) {
        if ($lines.Count -gt 0 -and $lines[-1].Trim().Length -gt 0) {
            $lines += ''
        }
        $lines += '[record]'
        $lines += $entryLine
    }
    else {
        $recordEnd = $lines.Count
        for ($i = $recordStart + 1; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -match '^\s*\[[^\]]+\]\s*$') {
                $recordEnd = $i
                break
            }
        }

        $keyIndex = -1
        $keyPattern = '^\s*' + [regex]::Escape($Key) + '\s*='
        for ($i = $recordStart + 1; $i -lt $recordEnd; $i++) {
            if ($lines[$i] -match $keyPattern) {
                $keyIndex = $i
                break
            }
        }

        if ($keyIndex -ge 0) {
            $lines[$keyIndex] = $entryLine
        }
        else {
            if ($recordEnd -ge $lines.Count) {
                $before = @($lines[0..$recordStart])
                $after = @()
                if (($recordStart + 1) -lt $lines.Count) {
                    $after = @($lines[($recordStart + 1)..($lines.Count - 1)])
                }
                $lines = $before + $entryLine + $after
            }
            else {
                $before = @($lines[0..($recordEnd - 1)])
                $after = @($lines[$recordEnd..($lines.Count - 1)])
                $lines = $before + $entryLine + $after
            }
        }
    }

    $updated = ($lines -join $newline) + $newline
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($ConfigPath, $updated, $utf8NoBom)
}

function Set-GilbrethElevatedHelperSignerSha256 {
    param(
        [Parameter(Mandatory)]
        [string]$LocalDataDir,

        [Parameter(Mandatory)]
        [string]$SignerSha256
    )

    $normalized = ConvertTo-GilbrethSha256Hex -Value $SignerSha256
    $configPath = Join-Path $LocalDataDir 'config.toml'
    Set-GilbrethRecordConfigString `
        -ConfigPath $configPath `
        -Key 'elevated_helper_required_signer_sha256' `
        -Value $normalized
    return $configPath
}

function Set-GilbrethElevatedHelperPath {
    param(
        [Parameter(Mandatory)]
        [string]$LocalDataDir,

        [Parameter(Mandatory)]
        [string]$HelperPath
    )

    $normalized = ConvertTo-GilbrethElevatedHelperPath -Value $HelperPath
    $configPath = Join-Path $LocalDataDir 'config.toml'
    Set-GilbrethRecordConfigString `
        -ConfigPath $configPath `
        -Key 'elevated_helper_path' `
        -Value $normalized
    return $configPath
}
