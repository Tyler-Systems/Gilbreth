<#
.SYNOPSIS
    Generates or verifies the checked-in Windows third-party inventory and notice.

.DESCRIPTION
    Resolves the exact non-development dependency closure of the gilbreth-app
    Windows x64 package from locked, package-scoped Cargo tree output mapped to
    target-filtered metadata. Normal and build dependencies are included; dev
    dependencies and dependencies for other targets are excluded. Upstream
    license files, explicitly pinned embedded assets, and non-Cargo runtime
    notices are rendered deterministically.

    This script is compatible with Windows PowerShell 5.1 and has no Python or
    third-party PowerShell-module dependency. The public package builder invokes
    Verify mode with its already validated, pinned Cargo executable.
#>
[CmdletBinding()]
param(
    [ValidateSet('Generate', 'Verify')]
    [string]$Mode = 'Verify',

    [string]$RepositoryRoot,

    [string]$CargoPath = 'cargo',

    [string]$RustcPath = 'rustc',

    [string]$PolicyPath = 'packaging/windows/third-party-notices-policy.json'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# PowerShell decodes a native command's stdout using [Console]::OutputEncoding.
# cargo and rustc emit UTF-8, so under a legacy console codepage every non-ASCII
# crate author name arrives mojibaked. The regenerated inventory then stops
# matching the checked-in one and Verify reports "stale or was edited by hand",
# which names the wrong cause and sends the reader hunting a dependency change
# that never happened. Pin the decode so the result cannot depend on which shell
# invoked this script. Guarded because a redirected host may have no console.
try { [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false) } catch { }

function Get-Sha256Lower {
    param([Parameter(Mandatory)] [string]$LiteralPath)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $stream = [System.IO.File]::OpenRead($LiteralPath)
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $stream.Dispose()
        $sha.Dispose()
    }
}

function Get-TextSha256Lower {
    param([Parameter(Mandatory)] [string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($Text)
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

function Get-NormalizedText {
    param([Parameter(Mandatory)] [string]$LiteralPath)
    $text = [System.IO.File]::ReadAllText($LiteralPath)
    $text = $text.Replace("`r`n", "`n").Replace("`r", "`n")
    $lines = [System.Collections.Generic.List[string]]::new()
    foreach ($line in $text.Split("`n")) {
        $lines.Add($line.TrimEnd([char[]]@(' ', "`t")))
    }
    return (($lines -join "`n").TrimEnd([char[]]@("`r", "`n"))) + "`n"
}

function Write-Utf8NoBom {
    param(
        [Parameter(Mandatory)] [string]$LiteralPath,
        [Parameter(Mandatory)] [string]$Content
    )
    $parent = Split-Path -Parent $LiteralPath
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        [System.IO.Directory]::CreateDirectory($parent) | Out-Null
    }
    [System.IO.File]::WriteAllText(
        $LiteralPath,
        $Content,
        [System.Text.UTF8Encoding]::new($false)
    )
}

function Assert-GeneratedFile {
    param(
        [Parameter(Mandatory)] [string]$LiteralPath,
        [Parameter(Mandatory)] [string]$Expected,
        [Parameter(Mandatory)] [string]$Label
    )
    if (-not (Test-Path -LiteralPath $LiteralPath -PathType Leaf)) {
        throw "$Label is missing: $LiteralPath. Run this script with -Mode Generate."
    }
    $bytes = [System.IO.File]::ReadAllBytes($LiteralPath)
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and
        $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        throw "$Label must be UTF-8 without a BOM: $LiteralPath"
    }
    if ($bytes -contains 13) {
        throw "$Label must use LF line endings: $LiteralPath"
    }
    try {
        $actual = [System.Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    }
    catch {
        throw "$Label is not valid UTF-8: $LiteralPath"
    }
    if ($actual -cne $Expected) {
        throw "$Label is stale or was edited by hand: $LiteralPath. Run this script with -Mode Generate and review the result."
    }
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
    if (@($segments | Where-Object { $_ -in @('', '.', '..') }).Count -ne 0) {
        throw "$Label contains an empty, current-directory, or traversal segment: $Value"
    }
}

function Resolve-ContainedPath {
    param(
        [Parameter(Mandatory)] [string]$Root,
        [Parameter(Mandatory)] [string]$RelativePath,
        [Parameter(Mandatory)] [string]$Label,
        [switch]$RequireFile
    )
    Assert-SafeRelativePath -Value $RelativePath -Label $Label
    $rootFull = [System.IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
    $relativeNative = $RelativePath.Replace('/', [System.IO.Path]::DirectorySeparatorChar)
    $candidate = [System.IO.Path]::GetFullPath((Join-Path $rootFull $relativeNative))
    $prefix = $rootFull + [System.IO.Path]::DirectorySeparatorChar
    if (-not $candidate.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label escapes its root: $RelativePath"
    }
    if ($RequireFile -and -not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        throw "$Label does not exist: $RelativePath"
    }
    return $candidate
}

function Get-JsonString {
    param([AllowNull()] [string]$Value)
    if ($null -eq $Value) { return 'null' }
    $builder = [System.Text.StringBuilder]::new()
    [void]$builder.Append('"')
    foreach ($character in $Value.ToCharArray()) {
        $number = [int]$character
        switch ($character) {
            '"' { [void]$builder.Append('\"'); continue }
            '\' { [void]$builder.Append('\\'); continue }
            "`b" { [void]$builder.Append('\b'); continue }
            "`f" { [void]$builder.Append('\f'); continue }
            "`n" { [void]$builder.Append('\n'); continue }
            "`r" { [void]$builder.Append('\r'); continue }
            "`t" { [void]$builder.Append('\t'); continue }
        }
        if ($number -lt 0x20) {
            [void]$builder.Append(('\u{0:x4}' -f $number))
        }
        else {
            [void]$builder.Append($character)
        }
    }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function ConvertTo-StableJsonValue {
    param(
        [AllowNull()]$Value,
        [int]$Indent = 0
    )
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [string] -or $Value -is [char]) {
        return Get-JsonString ([string]$Value)
    }
    if ($Value -is [bool]) {
        if ($Value) { return 'true' }
        return 'false'
    }
    if ($Value -is [byte] -or $Value -is [sbyte] -or
        $Value -is [int16] -or $Value -is [uint16] -or
        $Value -is [int32] -or $Value -is [uint32] -or
        $Value -is [int64] -or $Value -is [uint64] -or
        $Value -is [single] -or $Value -is [double] -or $Value -is [decimal]) {
        return [Convert]::ToString($Value, [Globalization.CultureInfo]::InvariantCulture)
    }
    $padding = ' ' * $Indent
    $childPadding = ' ' * ($Indent + 2)
    if ($Value -is [System.Collections.IDictionary]) {
        $keys = @($Value.Keys)
        if ($keys.Count -eq 0) { return '{}' }
        $rows = [System.Collections.Generic.List[string]]::new()
        foreach ($key in $keys) {
            $encoded = ConvertTo-StableJsonValue -Value $Value[$key] -Indent ($Indent + 2)
            $rows.Add($childPadding + (Get-JsonString ([string]$key)) + ': ' + $encoded)
        }
        return "{`n" + ($rows -join ",`n") + "`n$padding}"
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $items = @($Value)
        if ($items.Count -eq 0) { return '[]' }
        $rows = [System.Collections.Generic.List[string]]::new()
        foreach ($item in $items) {
            $encoded = ConvertTo-StableJsonValue -Value $item -Indent ($Indent + 2)
            $rows.Add($childPadding + $encoded)
        }
        return "[`n" + ($rows -join ",`n") + "`n$padding]"
    }
    $properties = @($Value.PSObject.Properties | Where-Object { $_.MemberType -match 'Property' })
    if ($properties.Count -eq 0) {
        return Get-JsonString ([string]$Value)
    }
    $rows = [System.Collections.Generic.List[string]]::new()
    foreach ($property in $properties) {
        $encoded = ConvertTo-StableJsonValue -Value $property.Value -Indent ($Indent + 2)
        $rows.Add($childPadding + (Get-JsonString $property.Name) + ': ' + $encoded)
    }
    return "{`n" + ($rows -join ",`n") + "`n$padding}"
}

function ConvertTo-StableJson {
    param([Parameter(Mandatory)]$Value)
    return (ConvertTo-StableJsonValue -Value $Value -Indent 0) + "`n"
}

function Escape-MarkdownCell {
    param([AllowNull()] [string]$Value)
    if ($null -eq $Value) { return '' }
    return $Value.Replace('|', '\|').Replace("`r", ' ').Replace("`n", ' ')
}

function Get-CargoTreePackageKeys {
    param(
        [Parameter(Mandatory)] [string]$Cargo,
        [Parameter(Mandatory)] [string]$RootPackageSpec,
        [Parameter(Mandatory)] [string]$TargetTriple,
        [Parameter(Mandatory)] [string]$EdgeKinds,
        [Parameter(Mandatory)] [hashtable]$PackagesByKey
    )
    $output = @(& $Cargo tree --frozen -p $RootPackageSpec --target $TargetTriple `
            -e $EdgeKinds --color never --prefix none --format '{p}')
    if ($LASTEXITCODE -ne 0) {
        throw "Cargo tree ($EdgeKinds) failed with exit code $LASTEXITCODE."
    }
    $lineRegex = [Text.RegularExpressions.Regex]::new(
        '^(?<name>[^ ]+) v(?<version>[^ ]+)(?: \(.*\))?$',
        [Text.RegularExpressions.RegexOptions]::CultureInvariant)
    $keys = @{}
    foreach ($rawLine in $output) {
        $line = [string]$rawLine
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $match = $lineRegex.Match($line)
        if (-not $match.Success) {
            throw "Unparseable Cargo tree ($EdgeKinds) output: $line"
        }
        $key = "$($match.Groups['name'].Value)@$($match.Groups['version'].Value)"
        if (-not $PackagesByKey.ContainsKey($key)) {
            throw "Cargo tree ($EdgeKinds) package is absent from target-filtered metadata: $key"
        }
        $keys[$key] = $true
    }
    if (-not $keys.ContainsKey($RootPackageSpec)) {
        throw "Cargo tree ($EdgeKinds) omitted the selected root package: $RootPackageSpec"
    }
    return $keys
}

function Get-PackageKey {
    param([Parameter(Mandatory)]$Package)
    return "$([string]$Package.name)@$([string]$Package.version)"
}

function Get-OptionalProperty {
    param(
        [AllowNull()]$Object,
        [Parameter(Mandatory)] [string]$Name
    )
    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Get-SortedStringsOrdinal {
    param([AllowEmptyCollection()] [object[]]$Values = @())
    $strings = [string[]]@($Values | ForEach-Object { [string]$_ })
    [Array]::Sort($strings, [StringComparer]::Ordinal)
    return $strings
}

function Get-VendoredSourceLabel {
    param(
        [Parameter(Mandatory)]$Entry,
        [Parameter(Mandatory)] [string]$RepoPath,
        [Parameter(Mandatory)] [string]$PackageKey,
        [switch]$RequireProvenance
    )
    $repository = [string](Get-OptionalProperty -Object $Entry -Name 'sourceRepository')
    $revision = [string](Get-OptionalProperty -Object $Entry -Name 'sourceRevision')
    $sourcePath = [string](Get-OptionalProperty -Object $Entry -Name 'sourcePath')
    $hasAll = -not [string]::IsNullOrWhiteSpace($repository) -and
        -not [string]::IsNullOrWhiteSpace($revision) -and
        -not [string]::IsNullOrWhiteSpace($sourcePath)
    if (-not $hasAll) {
        if ($RequireProvenance) {
            throw "Vendored fallback for $PackageKey must record sourceRepository, sourceRevision, and sourcePath."
        }
        return "repo:$RepoPath (for $PackageKey)"
    }
    if (-not $repository.StartsWith('https://', [StringComparison]::Ordinal)) {
        throw "Vendored source repository for $PackageKey must be an HTTPS URL: $repository"
    }
    return "$repository@$revision/$sourcePath (vendored as repo:$RepoPath for $PackageKey)"
}

function Assert-VendoredSourceMatchesPackage {
    param(
        [Parameter(Mandatory)]$Entry,
        [Parameter(Mandatory)]$PackageSource,
        [Parameter(Mandatory)] [string]$PackageKey
    )
    if ([string]$Entry.sourceRepository -cne [string]$PackageSource.primaryRepository -or
        [string]$Entry.sourceRevision -cne [string]$PackageSource.revision) {
        throw "Vendored source repository/revision does not match packageSource for $PackageKey"
    }
}

function Get-NormalizedGitRepositoryUrl {
    param([Parameter(Mandatory)] [string]$Value)
    $normalized = $Value.TrimEnd('/')
    if ($normalized.EndsWith('.git', [StringComparison]::OrdinalIgnoreCase)) {
        $normalized = $normalized.Substring(0, $normalized.Length - 4)
    }
    return $normalized
}

if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
    $RepositoryRoot = (& git rev-parse --show-toplevel).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($RepositoryRoot)) {
        throw 'Unable to resolve the repository root.'
    }
}
$RepositoryRoot = [System.IO.Path]::GetFullPath($RepositoryRoot).TrimEnd('\', '/')
$canonicalPolicyRelative = 'packaging/windows/third-party-notices-policy.json'
$canonicalPolicyAbsolute = Resolve-ContainedPath -Root $RepositoryRoot `
    -RelativePath $canonicalPolicyRelative -Label 'canonical third-party notice policy' -RequireFile
$requestedPolicyAbsolute = if ([System.IO.Path]::IsPathRooted($PolicyPath)) {
    [System.IO.Path]::GetFullPath($PolicyPath)
}
else {
    Resolve-ContainedPath -Root $RepositoryRoot -RelativePath $PolicyPath `
        -Label 'third-party notice policy' -RequireFile
}
if (-not [string]::Equals($requestedPolicyAbsolute, $canonicalPolicyAbsolute,
        [StringComparison]::OrdinalIgnoreCase)) {
    throw "PolicyPath must resolve to the canonical repository policy: $canonicalPolicyRelative"
}
$policyAbsolute = $canonicalPolicyAbsolute
$PolicyPath = $canonicalPolicyRelative
$policy = Get-Content -Raw -LiteralPath $policyAbsolute | ConvertFrom-Json
if ([int]$policy.schemaVersion -ne 1) {
    throw 'Unsupported third-party notice policy schema.'
}
if (@($policy.dependencyKinds).Count -ne 2 -or
    @($policy.dependencyKinds) -notcontains 'normal' -or
    @($policy.dependencyKinds) -notcontains 'build') {
    throw 'The notice policy must include exactly normal and build dependency kinds.'
}
$inventoryAbsolute = Resolve-ContainedPath -Root $RepositoryRoot `
    -RelativePath ([string]$policy.inventoryPath) -Label 'third-party inventory path'
$noticeAbsolute = Resolve-ContainedPath -Root $RepositoryRoot `
    -RelativePath ([string]$policy.noticePath) -Label 'third-party notice path'
$releaseConfigAbsolute = Resolve-ContainedPath -Root $RepositoryRoot `
    -RelativePath ([string]$policy.releaseConfigPath) -Label 'release config path' -RequireFile
$cargoLockAbsolute = Resolve-ContainedPath -Root $RepositoryRoot `
    -RelativePath 'Cargo.lock' -Label 'Cargo lock path' -RequireFile

$metadataOutput = @(& $CargoPath metadata --frozen --filter-platform `
        ([string]$policy.targetTriple) --format-version 1)
if ($LASTEXITCODE -ne 0) {
    throw "Cargo metadata failed with exit code $LASTEXITCODE."
}
$metadata = ($metadataOutput -join "`n") | ConvertFrom-Json
$packagesById = @{}
$packagesByKey = @{}
$externalByKey = @{}
foreach ($package in @($metadata.packages)) {
    $id = [string]$package.id
    if ($packagesById.ContainsKey($id)) { throw "Duplicate Cargo package id: $id" }
    $packagesById[$id] = $package
    $key = Get-PackageKey $package
    if ($packagesByKey.ContainsKey($key)) {
        throw "Ambiguous package name/version in target-filtered Cargo metadata: $key"
    }
    $packagesByKey[$key] = $package
    if ($null -ne $package.source) {
        $externalByKey[$key] = $package
    }
}
$rootCandidates = @($metadata.packages | Where-Object {
        [string]$_.name -eq [string]$policy.rootPackage -and
        $null -eq $_.source
    })
if ($rootCandidates.Count -ne 1) {
    throw "Expected one workspace root named $($policy.rootPackage); found $($rootCandidates.Count)."
}
$rootPackageVersion = [string]$rootCandidates[0].version
$rootPackageSpec = "$($policy.rootPackage)@$rootPackageVersion"
$normalKeys = Get-CargoTreePackageKeys -Cargo $CargoPath -RootPackageSpec $rootPackageSpec `
    -TargetTriple ([string]$policy.targetTriple) -EdgeKinds 'normal' -PackagesByKey $packagesByKey
$nonDevKeys = Get-CargoTreePackageKeys -Cargo $CargoPath -RootPackageSpec $rootPackageSpec `
    -TargetTriple ([string]$policy.targetTriple) -EdgeKinds 'normal,build' -PackagesByKey $packagesByKey
foreach ($key in $normalKeys.Keys) {
    if (-not $nonDevKeys.ContainsKey([string]$key)) {
        throw "Cargo normal closure is not a subset of the normal+build closure: $key"
    }
}
$normalIds = @{}
foreach ($key in $normalKeys.Keys) {
    $normalIds[[string]$packagesByKey[$key].id] = $true
}
$nonDevIds = @{}
foreach ($key in $nonDevKeys.Keys) {
    $nonDevIds[[string]$packagesByKey[$key].id] = $true
}

$workspaceMemberIds = @{}
foreach ($workspaceMember in @($metadata.workspace_members)) {
    $memberId = [string]$workspaceMember
    if ($workspaceMemberIds.ContainsKey($memberId)) {
        throw "Duplicate Cargo workspace member id: $memberId"
    }
    $workspaceMemberIds[$memberId] = $true
}
$repositoryPrefix = $RepositoryRoot + [System.IO.Path]::DirectorySeparatorChar
foreach ($id in $nonDevIds.Keys) {
    $package = $packagesById[$id]
    if ($null -ne $package.source) { continue }
    if (-not $workspaceMemberIds.ContainsKey([string]$id)) {
        throw "Reachable source-null package is not a workspace member (external path dependencies are forbidden): $id"
    }
    $manifestFull = [System.IO.Path]::GetFullPath([string]$package.manifest_path)
    if (-not $manifestFull.StartsWith($repositoryPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Reachable workspace manifest escapes RepositoryRoot: $manifestFull"
    }
    if (-not (Test-Path -LiteralPath $manifestFull -PathType Leaf)) {
        throw "Reachable workspace manifest is missing: $manifestFull"
    }
}

$workspaceByKey = @{}
$reachableExternalByKey = @{}
foreach ($id in $nonDevIds.Keys) {
    $package = $packagesById[$id]
    $key = Get-PackageKey $package
    if ($null -eq $package.source) { $workspaceByKey[$key] = $package }
    else { $reachableExternalByKey[$key] = $package }
}
$workspacePackages = @(foreach ($key in @(Get-SortedStringsOrdinal @($workspaceByKey.Keys))) {
        $workspaceByKey[$key]
    })
$externalPackages = @(foreach ($key in @(Get-SortedStringsOrdinal @($reachableExternalByKey.Keys))) {
        $reachableExternalByKey[$key]
    })
$externalNormalCount = @($externalPackages | Where-Object { $normalIds.ContainsKey([string]$_.id) }).Count
$externalBuildOnlyCount = $externalPackages.Count - $externalNormalCount
if ($workspacePackages.Count -ne [int]$policy.expectedCounts.workspacePackages -or
    $externalNormalCount -ne [int]$policy.expectedCounts.externalNormalPackages -or
    $externalBuildOnlyCount -ne [int]$policy.expectedCounts.externalBuildOnlyPackages -or
    $externalPackages.Count -ne [int]$policy.expectedCounts.externalNonDevPackages) {
    throw ('The Windows non-dev graph changed. Expected workspace/normal/build-only/external ' +
        "$($policy.expectedCounts.workspacePackages)/$($policy.expectedCounts.externalNormalPackages)/" +
        "$($policy.expectedCounts.externalBuildOnlyPackages)/$($policy.expectedCounts.externalNonDevPackages); " +
        "found $($workspacePackages.Count)/$externalNormalCount/$externalBuildOnlyCount/$($externalPackages.Count). " +
        'Review the graph and update the policy intentionally.')
}

$rulesByPackage = @{}
foreach ($rule in @($policy.packageRules)) {
    $key = [string]$rule.package
    if ($rulesByPackage.ContainsKey($key)) { throw "Duplicate package rule: $key" }
    if (-not $externalByKey.ContainsKey($key) -or
        -not $nonDevIds.ContainsKey([string]$externalByKey[$key].id)) {
        throw "Package rule does not name a package in the Windows non-dev graph: $key"
    }
    $rulesByPackage[$key] = $rule
}

$licenseTexts = @{}
$topLevelNoticeRegex = [Text.RegularExpressions.Regex]::new(
    '^(LICENSE|LICENCE|COPYING|COPYRIGHT|NOTICE|UNLICENSE)([._-].*)?$',
    [Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
        [Text.RegularExpressions.RegexOptions]::CultureInvariant)
function Add-LicenseReference {
    param(
        [Parameter(Mandatory)] [string]$PackageKey,
        [Parameter(Mandatory)] [string]$SourceLabel,
        [Parameter(Mandatory)] [string]$LiteralPath,
        [Parameter(Mandatory)] [string]$RawSha256,
        [Parameter(Mandatory)] [bool]$Fallback
    )
    $text = Get-NormalizedText $LiteralPath
    $contentSha = Get-TextSha256Lower $text
    if (-not $licenseTexts.ContainsKey($contentSha)) {
        $licenseTexts[$contentSha] = [ordered]@{
            sha256 = $contentSha
            text = $text
            packages = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
            sources = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        }
    }
    [void]$licenseTexts[$contentSha].packages.Add($PackageKey)
    [void]$licenseTexts[$contentSha].sources.Add($SourceLabel)
    return [ordered]@{
        source = $SourceLabel
        sha256 = $RawSha256
        contentSha256 = $contentSha
        fallback = $Fallback
    }
}

$cargoRows = [System.Collections.Generic.List[object]]::new()
foreach ($package in $externalPackages) {
    $key = Get-PackageKey $package
    if ([string]::IsNullOrWhiteSpace([string]$package.license)) {
        throw "Cargo package has no license expression: $key"
    }
    if ([string]$package.source -cne 'registry+https://github.com/rust-lang/crates.io-index') {
        throw "Unreviewed external Cargo source in Windows graph: $key ($($package.source))"
    }
    $packageRoot = Split-Path -Parent ([string]$package.manifest_path)
    $rule = if ($rulesByPackage.ContainsKey($key)) { $rulesByPackage[$key] } else { $null }
    $reviewedPackageSource = $null
    $reviewedFallback = Get-OptionalProperty -Object $rule -Name 'fallback'
    if ($null -ne $reviewedFallback -and [string]$reviewedFallback.kind -eq 'repo') {
        $packageSource = Get-OptionalProperty -Object $rule -Name 'packageSource'
        if ($null -eq $packageSource) {
            throw "Vendored fallback has no exact packageSource provenance: $key"
        }
        $sourceRepository = [string]$packageSource.repository
        $primaryRepository = [string]$packageSource.primaryRepository
        $sourceRevision = [string]$packageSource.revision
        $sourcePathInVcs = [string]$packageSource.pathInVcs
        if ([string]::IsNullOrWhiteSpace($sourceRepository) -or
            [string]::IsNullOrWhiteSpace($primaryRepository) -or
            $sourceRevision -cnotmatch '^[0-9a-f]{40}$' -or
            [string]$package.repository -cne $sourceRepository) {
            throw "Invalid packageSource repository or revision for $key"
        }
        $normalizedSourceRepository = Get-NormalizedGitRepositoryUrl $sourceRepository
        $normalizedPrimaryRepository = Get-NormalizedGitRepositoryUrl $primaryRepository
        if ($normalizedSourceRepository -cne $normalizedPrimaryRepository -and
            -not $normalizedSourceRepository.StartsWith(
                "$normalizedPrimaryRepository/tree/", [StringComparison]::Ordinal)) {
            throw "packageSource primaryRepository is unrelated to Cargo metadata for $key"
        }
        $vcsInfoPath = Join-Path $packageRoot '.cargo_vcs_info.json'
        if (-not (Test-Path -LiteralPath $vcsInfoPath -PathType Leaf)) {
            throw "Vendored fallback package has no .cargo_vcs_info.json: $key"
        }
        $vcsInfo = Get-Content -Raw -LiteralPath $vcsInfoPath | ConvertFrom-Json
        $actualRevision = [string]$vcsInfo.git.sha1
        $actualPathInVcs = [string](Get-OptionalProperty -Object $vcsInfo -Name 'path_in_vcs')
        if ($actualRevision -cne $sourceRevision -or $actualPathInVcs -cne $sourcePathInVcs) {
            throw "packageSource does not match .cargo_vcs_info.json for $key"
        }
        $reviewedPackageSource = [ordered]@{
            repository = $sourceRepository
            primaryRepository = $primaryRepository
            revision = $sourceRevision
            pathInVcs = $sourcePathInVcs
        }
    }
    $excluded = @{}
    $excludedValues = Get-OptionalProperty -Object $rule -Name 'excludeTopLevelFiles'
    if ($null -ne $excludedValues) {
        foreach ($name in @($excludedValues)) {
            $excluded[[string]$name] = $false
        }
    }
    $licenseFiles = [System.Collections.Generic.List[object]]::new()
    $topLevelByName = @{}
    foreach ($candidate in @(Get-ChildItem -LiteralPath $packageRoot -File |
            Where-Object { $topLevelNoticeRegex.IsMatch($_.Name) })) {
        $topLevelByName[$candidate.Name] = $candidate
    }
    $topLevelCandidates = @(foreach ($name in @(Get-SortedStringsOrdinal @($topLevelByName.Keys))) {
            $topLevelByName[$name]
        })
    $includedTopLevelCount = 0
    foreach ($file in $topLevelCandidates) {
        if ($excluded.ContainsKey($file.Name)) {
            $excluded[$file.Name] = $true
            continue
        }
        $includedTopLevelCount += 1
        $rawSha = Get-Sha256Lower $file.FullName
        $licenseFiles.Add((Add-LicenseReference -PackageKey $key `
                    -SourceLabel "$key/$($file.Name)" -LiteralPath $file.FullName `
                    -RawSha256 $rawSha -Fallback $false))
    }
    foreach ($excludedName in $excluded.Keys) {
        if (-not $excluded[$excludedName]) {
            throw "Excluded license file is stale or missing: $key/$excludedName"
        }
    }
    if ($includedTopLevelCount -eq 0) {
        $fallback = Get-OptionalProperty -Object $rule -Name 'fallback'
        if ($null -eq $fallback) {
            throw "Cargo package has no top-level license/notice file and no reviewed fallback: $key"
        }
        if ([string]$fallback.kind -eq 'cargo') {
            $sourceKey = [string]$fallback.package
            if (-not $externalByKey.ContainsKey($sourceKey) -or
                -not $nonDevIds.ContainsKey([string]$externalByKey[$sourceKey].id)) {
                throw "Fallback source package is not in the Windows non-dev graph: $sourceKey"
            }
            $sourceRoot = Split-Path -Parent ([string]$externalByKey[$sourceKey].manifest_path)
            $fallbackPath = Resolve-ContainedPath -Root $sourceRoot `
                -RelativePath ([string]$fallback.path) -Label "fallback license for $key" -RequireFile
            $sourceLabel = "$sourceKey/$([string]$fallback.path) (shared fallback for $key)"
        }
        elseif ([string]$fallback.kind -eq 'repo') {
            $fallbackPath = Resolve-ContainedPath -Root $RepositoryRoot `
                -RelativePath ([string]$fallback.path) -Label "fallback notice for $key" -RequireFile
            Assert-VendoredSourceMatchesPackage -Entry $fallback `
                -PackageSource $packageSource -PackageKey $key
            $sourceLabel = Get-VendoredSourceLabel -Entry $fallback `
                -RepoPath ([string]$fallback.path) -PackageKey $key -RequireProvenance
        }
        else {
            throw "Unsupported fallback kind for ${key}: $($fallback.kind)"
        }
        $actualFallbackSha = Get-Sha256Lower $fallbackPath
        if ($actualFallbackSha -cne [string]$fallback.sha256) {
            throw "Fallback license hash changed for ${key}: $sourceLabel"
        }
        $licenseFiles.Add((Add-LicenseReference -PackageKey $key -SourceLabel $sourceLabel `
                    -LiteralPath $fallbackPath -RawSha256 $actualFallbackSha -Fallback $true))
    }
    elseif ($null -ne (Get-OptionalProperty -Object $rule -Name 'fallback')) {
        throw "Reviewed fallback is stale because the package now contains a top-level license file: $key"
    }

    $extraLicenseFiles = Get-OptionalProperty -Object $rule -Name 'extraLicenseFiles'
    if ($null -ne $extraLicenseFiles) {
        foreach ($extra in @($extraLicenseFiles)) {
            $repoPath = Get-OptionalProperty -Object $extra -Name 'repoPath'
            if ($null -ne $repoPath) {
                $extraPath = Resolve-ContainedPath -Root $RepositoryRoot `
                    -RelativePath ([string]$repoPath) -Label "extra repo notice for $key" -RequireFile
                Assert-VendoredSourceMatchesPackage -Entry $extra `
                    -PackageSource $packageSource -PackageKey $key
                $sourceLabel = Get-VendoredSourceLabel -Entry $extra `
                    -RepoPath ([string]$repoPath) -PackageKey "$key/$([string]$extra.path)" `
                    -RequireProvenance
            }
            else {
                $extraPath = Resolve-ContainedPath -Root $packageRoot `
                    -RelativePath ([string]$extra.path) -Label "extra license for $key" -RequireFile
                $sourceLabel = "$key/$([string]$extra.path)"
            }
            $actualExtraSha = Get-Sha256Lower $extraPath
            if ($actualExtraSha -cne [string]$extra.sha256) {
                throw "Extra license hash changed for ${key}: $sourceLabel"
            }
            $licenseFiles.Add((Add-LicenseReference -PackageKey $key -SourceLabel $sourceLabel `
                        -LiteralPath $extraPath -RawSha256 $actualExtraSha -Fallback $false))
        }
    }
    $embeddedAssets = [System.Collections.Generic.List[object]]::new()
    $embeddedAssetValues = Get-OptionalProperty -Object $rule -Name 'embeddedAssets'
    if ($null -ne $embeddedAssetValues) {
        foreach ($asset in @($embeddedAssetValues)) {
            $assetPath = Resolve-ContainedPath -Root $packageRoot `
                -RelativePath ([string]$asset.path) -Label "embedded Cargo asset for $key" -RequireFile
            $actualAssetSha = Get-Sha256Lower $assetPath
            if ($actualAssetSha -cne [string]$asset.sha256) {
                throw "Embedded Cargo asset hash changed for ${key}: $($asset.path)"
            }
            $embeddedAssets.Add([ordered]@{
                    path = [string]$asset.path
                    sha256 = $actualAssetSha
                })
        }
    }
    $isProcMacro = @($package.targets | Where-Object {
            @($_.kind) -contains 'proc-macro'
        }).Count -ne 0
    $usage = if ($normalIds.ContainsKey([string]$package.id)) { 'normal' } else { 'build-only' }
    $cargoRows.Add([ordered]@{
            name = [string]$package.name
            version = [string]$package.version
            key = $key
            usage = $usage
            procMacro = $isProcMacro
            license = [string]$package.license
            repository = [string]$package.repository
            source = [string]$package.source
            authors = [string[]]@($package.authors)
            packageSource = $reviewedPackageSource
            licenseFiles = [object[]]@($licenseFiles)
            embeddedAssets = [object[]]@($embeddedAssets)
        })
}

$releaseConfig = Get-Content -Raw -LiteralPath $releaseConfigAbsolute | ConvertFrom-Json
if ([string]$releaseConfig.rustHost -cne [string]$policy.targetTriple -or
    [string]$releaseConfig.msvcRuntimeLinkage -cne 'static') {
    throw 'Release config no longer matches the Windows notice target/static-runtime disposition.'
}
$manualRows = [System.Collections.Generic.List[object]]::new()
$manualTexts = [System.Collections.Generic.List[object]]::new()
foreach ($component in @($policy.manualComponents)) {
    $noticePath = Resolve-ContainedPath -Root $RepositoryRoot `
        -RelativePath ([string]$component.noticePath) -Label "manual notice $($component.id)" -RequireFile
    $actualNoticeSha = Get-Sha256Lower $noticePath
    if ($actualNoticeSha -cne [string]$component.noticeSha256) {
        throw "Manual notice hash changed for $($component.id): $($component.noticePath)"
    }
    $assets = [System.Collections.Generic.List[object]]::new()
    $manualAssetValues = Get-OptionalProperty -Object $component -Name 'assetFiles'
    if ($null -ne $manualAssetValues) {
        foreach ($asset in @($manualAssetValues)) {
            $assetPath = Resolve-ContainedPath -Root $RepositoryRoot `
                -RelativePath ([string]$asset.path) -Label "manual component asset $($component.id)" -RequireFile
            $actualAssetSha = Get-Sha256Lower $assetPath
            if ($actualAssetSha -cne [string]$asset.sha256) {
                throw "Manual component asset hash changed for $($component.id): $($asset.path)"
            }
            $assets.Add([ordered]@{ path = [string]$asset.path; sha256 = $actualAssetSha })
        }
    }
    $manualRow = [ordered]@{
            id = [string]$component.id
            name = [string]$component.name
            version = [string]$component.version
            license = [string]$component.license
            relationship = [string]$component.relationship
            noticePath = [string]$component.noticePath
            noticeSha256 = $actualNoticeSha
            assets = [object[]]@($assets)
        }
    $componentProvenance = Get-OptionalProperty -Object $component -Name 'provenance'
    if ($null -ne $componentProvenance) {
        $manualRow['provenance'] = [ordered]@{
            repository = [string]$componentProvenance.repository
            revision = [string]$componentProvenance.revision
            toolchainPath = [string]$componentProvenance.toolchainPath
        }
    }
    $manualRows.Add($manualRow)
    $manualTexts.Add([ordered]@{
            id = [string]$component.id
            name = [string]$component.name
            path = [string]$component.noticePath
            text = Get-NormalizedText $noticePath
        })
}
$rust = @($manualRows | Where-Object { $_.id -eq 'rust-standard-library' })
if ($rust.Count -ne 1 -or [string]$rust[0].version -cne [string]$releaseConfig.rustRelease) {
    throw 'The Rust standard-library notice version does not match release-config.json.'
}
$rustProvenance = $rust[0].provenance
if ($null -eq $rustProvenance -or
    [string]$rustProvenance.repository -cne 'https://github.com/rust-lang/rust' -or
    [string]$rustProvenance.revision -cne [string]$releaseConfig.rustCommit -or
    [string]$rustProvenance.toolchainPath -cne 'share/doc/rust/COPYRIGHT-library.html') {
    throw 'The Rust standard-library notice provenance does not match the pinned Rust source/toolchain.'
}
$rustcVersionOutput = @(& $RustcPath -Vv)
if ($LASTEXITCODE -ne 0) {
    throw "rustc -Vv failed with exit code $LASTEXITCODE."
}
$rustcFacts = @{}
$rustcFactRegex = [Text.RegularExpressions.Regex]::new(
    '^(?<name>[^:]+): (?<value>.*)$',
    [Text.RegularExpressions.RegexOptions]::CultureInvariant)
foreach ($line in $rustcVersionOutput) {
    $match = $rustcFactRegex.Match([string]$line)
    if ($match.Success) {
        $rustcFacts[$match.Groups['name'].Value] = $match.Groups['value'].Value
    }
}
if ([string]$rustcFacts['release'] -cne [string]$releaseConfig.rustRelease -or
    [string]$rustcFacts['commit-hash'] -cne [string]$releaseConfig.rustCommit -or
    [string]$rustcFacts['host'] -cne [string]$releaseConfig.rustHost) {
    throw 'rustc identity does not match the pinned release configuration.'
}
$sysrootOutput = @(& $RustcPath --print sysroot)
if ($LASTEXITCODE -ne 0 -or $sysrootOutput.Count -ne 1 -or
    [string]::IsNullOrWhiteSpace([string]$sysrootOutput[0])) {
    throw 'Unable to resolve one pinned rustc sysroot.'
}
$rustToolchainNotice = Resolve-ContainedPath -Root ([string]$sysrootOutput[0]) `
    -RelativePath ([string]$rustProvenance.toolchainPath) `
    -Label 'pinned Rust standard-library copyright notice' -RequireFile
if ((Get-Sha256Lower $rustToolchainNotice) -cne [string]$rust[0].noticeSha256) {
    throw 'The vendored Rust standard-library notice differs from the pinned toolchain notice.'
}
$inno = @($manualRows | Where-Object { $_.id -eq 'inno-setup-runtime' })
if ($inno.Count -ne 1 -or [string]$inno[0].version -cne [string]$releaseConfig.innoSetupVersion) {
    throw 'The Inno manual notice version does not match release-config.json.'
}
$lzma = @($manualRows | Where-Object { $_.id -eq 'lzma-sdk' })
$expectedLzmaVersion = "Inno Setup $($releaseConfig.innoSetupVersion) component"
if ($lzma.Count -ne 1 -or [string]$lzma[0].version -cne $expectedLzmaVersion -or
    [string]$lzma[0].relationship -cne 'installer LZMA2 compression/decompression code') {
    throw 'The LZMA SDK disposition does not match the pinned Inno Setup release relationship.'
}
$sqlite = @($manualRows | Where-Object { $_.id -eq 'sqlite' })
$sqlitePackageKey = 'libsqlite3-sys@0.38.0'
if ($sqlite.Count -ne 1 -or -not $reachableExternalByKey.ContainsKey($sqlitePackageKey)) {
    throw 'The SQLite manual component or bundled libsqlite3-sys package is missing.'
}
$sqliteRoot = Split-Path -Parent ([string]$reachableExternalByKey[$sqlitePackageKey].manifest_path)
$sqliteHeader = Resolve-ContainedPath -Root $sqliteRoot -RelativePath 'sqlite3/sqlite3.h' `
    -Label 'bundled SQLite version header' -RequireFile
$sqliteVersionRegex = [Text.RegularExpressions.Regex]::new(
    '^\s*#define\s+SQLITE_VERSION\s+"([^"]+)"\s*$',
    [Text.RegularExpressions.RegexOptions]::Multiline -bor
        [Text.RegularExpressions.RegexOptions]::CultureInvariant)
$sqliteVersionMatches = $sqliteVersionRegex.Matches([IO.File]::ReadAllText($sqliteHeader))
if ($sqliteVersionMatches.Count -ne 1) {
    throw 'Unable to derive exactly one SQLITE_VERSION from the bundled sqlite3.h.'
}
$derivedSqliteVersion = [string]$sqliteVersionMatches[0].Groups[1].Value
$sqliteCargoRows = @($cargoRows | Where-Object { $_.key -eq $sqlitePackageKey })
$sqliteHeaderAssets = @(if ($sqliteCargoRows.Count -eq 1) {
        $sqliteCargoRows[0].embeddedAssets | Where-Object { $_.path -eq 'sqlite3/sqlite3.h' }
    })
if ([string]$sqlite[0].version -cne $derivedSqliteVersion -or $sqliteHeaderAssets.Count -ne 1) {
    throw 'The SQLite manual version does not match the hash-pinned bundled sqlite3.h.'
}
$microsoft = @($manualRows | Where-Object { $_.id -eq 'microsoft-runtime' })
$expectedMicrosoftVersion = "MSVC $($releaseConfig.msvcToolsetVersion) / Windows SDK $($releaseConfig.windowsSdkVersion)"
if ($microsoft.Count -ne 1 -or [string]$microsoft[0].version -cne $expectedMicrosoftVersion) {
    throw 'The Microsoft runtime disposition does not match release-config.json.'
}

$licenseInventory = [System.Collections.Generic.List[object]]::new()
foreach ($hash in @(Get-SortedStringsOrdinal @($licenseTexts.Keys))) {
    $entry = $licenseTexts[$hash]
    $licenseInventory.Add([ordered]@{
            sha256 = $hash
            packages = [string[]]@(Get-SortedStringsOrdinal @($entry.packages))
            sources = [string[]]@(Get-SortedStringsOrdinal @($entry.sources))
        })
}
$workspaceRows = [System.Collections.Generic.List[object]]::new()
foreach ($package in $workspacePackages) {
    $workspaceRows.Add([ordered]@{
            name = [string]$package.name
            version = [string]$package.version
            key = Get-PackageKey $package
        })
}
$generatorAbsolute = [System.IO.Path]::GetFullPath($PSCommandPath)
$inventory = [ordered]@{
    schemaVersion = 1
    generator = [ordered]@{
        path = 'scripts/windows-third-party-notices.ps1'
        sha256 = Get-Sha256Lower $generatorAbsolute
        policyPath = $PolicyPath.Replace('\', '/')
        policySha256 = Get-Sha256Lower $policyAbsolute
    }
    target = [string]$policy.targetTriple
    rootPackage = $rootPackageSpec
    dependencyKinds = [string[]]@('normal', 'build')
    dependencyGraph = [ordered]@{
        resolver = 'cargo-tree-package-scoped-v1'
        package = $rootPackageSpec
        normalEdges = 'normal'
        nonDevEdges = 'normal,build'
    }
    cargoLockSha256 = Get-Sha256Lower $cargoLockAbsolute
    counts = [ordered]@{
        workspacePackages = $workspaceRows.Count
        externalNormalPackages = $externalNormalCount
        externalBuildOnlyPackages = $externalBuildOnlyCount
        externalNonDevPackages = $cargoRows.Count
        uniqueCargoLicenseTexts = $licenseInventory.Count
        manualComponents = $manualRows.Count
    }
    workspacePackages = [object[]]@($workspaceRows)
    cargoPackages = [object[]]@($cargoRows)
    cargoLicenseTexts = [object[]]@($licenseInventory)
    manualComponents = [object[]]@($manualRows)
}
$inventoryText = ConvertTo-StableJson $inventory

$noticeLines = [System.Collections.Generic.List[string]]::new()
$noticeLines.Add('# Third-party notices')
$noticeLines.Add('')
$noticeLines.Add('> Generated by `scripts/windows-third-party-notices.ps1`; do not edit by hand.')
$noticeLines.Add('> The checked-in machine-readable companion is')
$noticeLines.Add('> `packaging/windows/third-party-inventory.json`.')
$noticeLines.Add('')
$noticeLines.Add('Gilbreth is licensed under AGPL-3.0-or-later. See `LICENSE.md` in the installed program directory.')
$noticeLines.Add('')
$noticeLines.Add('## Scope and method')
$noticeLines.Add('')
$noticeLines.Add('This notice covers the exact package-scoped Cargo.lock closure for `' +
    $rootPackageSpec + '` on')
$noticeLines.Add('`' + $policy.targetTriple + '`: ' + $externalNormalCount + ' external normal packages and')
$noticeLines.Add("$externalBuildOnlyCount build-only packages ($($cargoRows.Count) external non-development packages total), plus")
$noticeLines.Add("$($workspaceRows.Count) Gilbreth workspace packages. Dev dependencies and dependencies for other targets are excluded.")
$noticeLines.Add('Build-only crates are retained conservatively even though their code is not linked into the installed executable.')
$noticeLines.Add('')
$noticeLines.Add('For packages offering alternative licenses, upstream license files are retained for review. Gilbreth explicitly')
$noticeLines.Add('uses the Apache-2.0 option for `self_cell`; its alternative GPL-2.0-only text is intentionally excluded.')
$noticeLines.Add('Package identities, license expressions, source repositories, exact input hashes, and embedded-asset hashes')
$noticeLines.Add('are recorded in the companion inventory. Re-running verification fails closed on graph or byte changes.')
$noticeLines.Add('')
$noticeLines.Add('## Cargo package inventory')
$noticeLines.Add('')
$noticeLines.Add('| Package | Use | Proc macro | Declared license | Repository |')
$noticeLines.Add('| --- | --- | --- | --- | --- |')
foreach ($row in $cargoRows) {
    $noticeLines.Add('| `' + (Escape-MarkdownCell $row.key) + '` | ' +
        (Escape-MarkdownCell $row.usage) + ' | ' +
        $(if ($row.procMacro) { 'yes' } else { 'no' }) + ' | ' +
        (Escape-MarkdownCell $row.license) + ' | ' +
        (Escape-MarkdownCell $row.repository) + ' |')
}
$noticeLines.Add('')
$noticeLines.Add('## Embedded assets and non-Cargo runtime components')
$noticeLines.Add('')
$noticeLines.Add('The app embeds Inter and IBM Plex Mono. Because `FontDefinitions::default()` remains the glyph fallback,')
$noticeLines.Add('it also embeds egui/epaint default Hack, Noto Emoji, Ubuntu Light, and emoji-icon-font assets.')
$noticeLines.Add('The pinned Rust standard library and runtime are statically linked; their complete toolchain copyright')
$noticeLines.Add('bundle, including Rust in-tree and out-of-tree third-party notices, is retained below.')
$noticeLines.Add('The generated Setup and installed uninstaller contain Inno Setup and LZMA SDK code; bundled SQLite is')
$noticeLines.Add('statically compiled into the application. The Microsoft runtime/system-component disposition is included')
$noticeLines.Add('for completeness. Exact binary/source hashes are in the companion inventory.')
$noticeLines.Add('')
$noticeLines.Add('| Component | Version | Relationship | License/disposition |')
$noticeLines.Add('| --- | --- | --- | --- |')
foreach ($row in $manualRows) {
    $noticeLines.Add('| ' + (Escape-MarkdownCell $row.name) + ' | ' +
        (Escape-MarkdownCell $row.version) + ' | ' +
        (Escape-MarkdownCell $row.relationship) + ' | ' +
        (Escape-MarkdownCell $row.license) + ' |')
}
$noticeLines.Add('')
$noticeLines.Add('## Cargo license and notice texts')
$noticeLines.Add('')
$noticeLines.Add('Identical upstream texts are deduplicated by the SHA-256 of their LF-normalized UTF-8 content.')
foreach ($hash in @(Get-SortedStringsOrdinal @($licenseTexts.Keys))) {
    $entry = $licenseTexts[$hash]
    $noticeLines.Add('')
    $noticeLines.Add('### Text `' + $hash + '`')
    $noticeLines.Add('')
    $noticeLines.Add('Packages: ' + ((@(Get-SortedStringsOrdinal @($entry.packages)) | ForEach-Object {
                    '`' + [string]$_ + '`'
                }) -join ', '))
    $noticeLines.Add('')
    $noticeLines.Add('Sources: ' + ((@(Get-SortedStringsOrdinal @($entry.sources)) | ForEach-Object {
                    '`' + [string]$_ + '`'
                }) -join ', '))
    $noticeLines.Add('')
    $noticeLines.Add('~~~~text')
    foreach ($line in $entry.text.TrimEnd("`n").Split("`n")) { $noticeLines.Add($line) }
    $noticeLines.Add('~~~~')
}
$noticeLines.Add('')
$noticeLines.Add('## Manual component notices')
foreach ($entry in $manualTexts) {
    $noticeLines.Add('')
    $noticeLines.Add("### $($entry.name)")
    $noticeLines.Add('')
    $noticeLines.Add('Source input: `' + [string]$entry.path + '`')
    $noticeLines.Add('')
    $noticeLines.Add('~~~~text')
    foreach ($line in $entry.text.TrimEnd("`n").Split("`n")) { $noticeLines.Add($line) }
    $noticeLines.Add('~~~~')
}
$noticeLines.Add('')
$noticeLines.Add('The exact release source is identified by `source.tag` and `source.commit` in the release')
$noticeLines.Add('manifest shipped beside the installer, and is available from')
$noticeLines.Add('<https://github.com/Tyler-Systems/Gilbreth>.')
$noticeText = ($noticeLines -join "`n") + "`n"

if ($Mode -eq 'Generate') {
    Write-Utf8NoBom -LiteralPath $inventoryAbsolute -Content $inventoryText
    Write-Utf8NoBom -LiteralPath $noticeAbsolute -Content $noticeText
    Write-Host "Generated $($policy.inventoryPath) and $($policy.noticePath)."
}
else {
    Assert-GeneratedFile -LiteralPath $inventoryAbsolute -Expected $inventoryText `
        -Label 'Windows third-party inventory'
    Assert-GeneratedFile -LiteralPath $noticeAbsolute -Expected $noticeText `
        -Label 'Installed third-party notice'
    $summary = ("Verified Windows third-party notices: {0} normal, {1} build-only, " +
        "{2} unique Cargo texts, {3} manual components.") -f
        $externalNormalCount, $externalBuildOnlyCount, $licenseInventory.Count, $manualRows.Count
    Write-Host $summary
}
