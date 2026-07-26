Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-RegularNonReparseFilePath {
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string]$Label
    )

    $full = [System.IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
        throw "$Label must be a regular non-reparse file: $full"
    }

    $root = [System.IO.Path]::GetPathRoot($full).TrimEnd('\', '/')
    $cursor = $full.TrimEnd('\', '/')
    while (-not [string]::IsNullOrWhiteSpace($cursor)) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -Force -LiteralPath $cursor
            if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "$Label contains a reparse-point path component: $cursor"
            }
        }
        if ($cursor.Equals($root, [System.StringComparison]::OrdinalIgnoreCase)) {
            break
        }
        $parent = [System.IO.Directory]::GetParent($cursor)
        if ($null -eq $parent) { break }
        $cursor = $parent.FullName.TrimEnd('\', '/')
    }
    return $full
}

function Skip-StrictJsonWhitespace {
    param([Parameter(Mandatory)] [hashtable]$State)

    while ($State.Index -lt $State.Text.Length) {
        [char]$character = $State.Text[$State.Index]
        if ($character -ne ' ' -and $character -ne "`t" -and
            $character -ne "`r" -and $character -ne "`n") {
            break
        }
        $State.Index += 1
    }
}

function Read-StrictJsonString {
    param(
        [Parameter(Mandatory)] [hashtable]$State,
        [Parameter(Mandatory)] [string]$Label
    )

    Skip-StrictJsonWhitespace $State
    if ($State.Index -ge $State.Text.Length -or $State.Text[$State.Index] -ne '"') {
        throw "$Label must be a JSON string."
    }
    $State.Index += 1
    $builder = [System.Text.StringBuilder]::new()
    while ($State.Index -lt $State.Text.Length) {
        [char]$character = $State.Text[$State.Index]
        $State.Index += 1
        if ($character -eq '"') {
            return $builder.ToString()
        }
        if ([int]$character -lt 0x20) {
            throw "$Label contains an unescaped JSON control character."
        }
        if ($character -ne '\') {
            [void]$builder.Append($character)
            continue
        }
        if ($State.Index -ge $State.Text.Length) {
            throw "$Label contains an incomplete JSON escape."
        }
        [char]$escape = $State.Text[$State.Index]
        $State.Index += 1
        switch ($escape) {
            '"' { [void]$builder.Append('"'); break }
            '\' { [void]$builder.Append('\'); break }
            '/' { [void]$builder.Append('/'); break }
            'b' { [void]$builder.Append([char]8); break }
            'f' { [void]$builder.Append([char]12); break }
            'n' { [void]$builder.Append([char]10); break }
            'r' { [void]$builder.Append([char]13); break }
            't' { [void]$builder.Append([char]9); break }
            'u' {
                if ($State.Index + 4 -gt $State.Text.Length) {
                    throw "$Label contains an incomplete JSON Unicode escape."
                }
                $hex = $State.Text.Substring($State.Index, 4)
                if ($hex -cnotmatch '^[0-9a-fA-F]{4}$') {
                    throw "$Label contains an invalid JSON Unicode escape."
                }
                $State.Index += 4
                $code = [Convert]::ToInt32($hex, 16)
                if ($code -ge 0xD800 -and $code -le 0xDBFF) {
                    if ($State.Index + 6 -gt $State.Text.Length -or
                        $State.Text[$State.Index] -ne '\' -or
                        $State.Text[$State.Index + 1] -ne 'u') {
                        throw "$Label contains an unpaired JSON high surrogate."
                    }
                    $lowHex = $State.Text.Substring($State.Index + 2, 4)
                    if ($lowHex -cnotmatch '^[0-9a-fA-F]{4}$') {
                        throw "$Label contains an invalid JSON low-surrogate escape."
                    }
                    $lowCode = [Convert]::ToInt32($lowHex, 16)
                    if ($lowCode -lt 0xDC00 -or $lowCode -gt 0xDFFF) {
                        throw "$Label contains an unpaired JSON high surrogate."
                    }
                    $State.Index += 6
                    [void]$builder.Append([char]$code)
                    [void]$builder.Append([char]$lowCode)
                }
                elseif ($code -ge 0xDC00 -and $code -le 0xDFFF) {
                    throw "$Label contains an unpaired JSON low surrogate."
                }
                else {
                    [void]$builder.Append([char]$code)
                }
                break
            }
            default { throw "$Label contains an invalid JSON escape." }
        }
    }
    throw "$Label contains an unterminated JSON string."
}

function Read-StrictJsonStringArray {
    param(
        [Parameter(Mandatory)] [hashtable]$State,
        [Parameter(Mandatory)] [string]$Label
    )

    Skip-StrictJsonWhitespace $State
    if ($State.Index -ge $State.Text.Length -or $State.Text[$State.Index] -ne '[') {
        throw "$Label must be a JSON array."
    }
    $State.Index += 1
    Skip-StrictJsonWhitespace $State
    $items = [System.Collections.Generic.List[string]]::new()
    if ($State.Index -lt $State.Text.Length -and $State.Text[$State.Index] -eq ']') {
        $State.Index += 1
        return [string[]]$items.ToArray()
    }
    while ($true) {
        [void]$items.Add((Read-StrictJsonString -State $State -Label "$Label item"))
        Skip-StrictJsonWhitespace $State
        if ($State.Index -ge $State.Text.Length) {
            throw "$Label is unterminated."
        }
        [char]$delimiter = $State.Text[$State.Index]
        $State.Index += 1
        if ($delimiter -eq ']') { break }
        if ($delimiter -ne ',') {
            throw "$Label must use commas between string items."
        }
        Skip-StrictJsonWhitespace $State
        if ($State.Index -lt $State.Text.Length -and $State.Text[$State.Index] -eq ']') {
            throw "$Label may not contain a trailing comma."
        }
    }
    return [string[]]$items.ToArray()
}

function ConvertFrom-StrictPePolicyJson {
    param([Parameter(Mandatory)] [AllowEmptyString()] [string]$Text)

    $state = @{ Text = $Text; Index = 0 }
    Skip-StrictJsonWhitespace $state
    if ($state.Index -ge $state.Text.Length -or $state.Text[$state.Index] -ne '{') {
        throw 'PE dependency policy root must be a JSON object.'
    }
    $state.Index += 1
    Skip-StrictJsonWhitespace $state
    $seen = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal)
    $values = @{}
    if ($state.Index -lt $state.Text.Length -and $state.Text[$state.Index] -eq '}') {
        $state.Index += 1
    }
    else {
        while ($true) {
            $key = Read-StrictJsonString -State $state -Label 'PE dependency policy property name'
            if (-not $seen.Add($key)) {
                throw "PE dependency policy contains duplicate property '$key'."
            }
            if ($key -cnotin @('schemaVersion', 'directImports', 'delayLoadImports')) {
                throw "PE dependency policy contains unknown or mis-cased property '$key'."
            }
            Skip-StrictJsonWhitespace $state
            if ($state.Index -ge $state.Text.Length -or $state.Text[$state.Index] -ne ':') {
                throw "PE dependency policy property '$key' is missing its colon."
            }
            $state.Index += 1
            if ($key -ceq 'schemaVersion') {
                Skip-StrictJsonWhitespace $state
                if ($state.Index -ge $state.Text.Length -or $state.Text[$state.Index] -ne '1') {
                    throw 'PE dependency policy schemaVersion must be the JSON integer 1.'
                }
                $state.Index += 1
                $values[$key] = 1
            }
            else {
                [string[]]$array = @(Read-StrictJsonStringArray -State $state -Label "Policy $key")
                $values[$key] = $array
            }
            Skip-StrictJsonWhitespace $state
            if ($state.Index -ge $state.Text.Length) {
                throw 'PE dependency policy JSON object is unterminated.'
            }
            [char]$delimiter = $state.Text[$state.Index]
            $state.Index += 1
            if ($delimiter -eq '}') { break }
            if ($delimiter -ne ',') {
                throw 'PE dependency policy properties must be comma-separated.'
            }
            Skip-StrictJsonWhitespace $state
            if ($state.Index -lt $state.Text.Length -and $state.Text[$state.Index] -eq '}') {
                throw 'PE dependency policy may not contain a trailing comma.'
            }
        }
    }
    Skip-StrictJsonWhitespace $state
    if ($state.Index -ne $state.Text.Length) {
        throw 'PE dependency policy contains trailing JSON content.'
    }
    if ($seen.Count -ne 3 -or
        -not $seen.Contains('schemaVersion') -or
        -not $seen.Contains('directImports') -or
        -not $seen.Contains('delayLoadImports')) {
        throw 'PE dependency policy property set is invalid.'
    }
    return [pscustomobject]@{
        schemaVersion = 1
        directImports = [string[]]$values['directImports']
        delayLoadImports = [string[]]$values['delayLoadImports']
    }
}

function Test-SafeNormalizedDllName {
    param([AllowNull()] [object]$Value)
    return $Value -is [string] -and
        $Value -cmatch '^[a-z0-9][a-z0-9._-]*\.dll$'
}

function Test-ForbiddenDynamicCrtDllName {
    param([Parameter(Mandatory)] [string]$Value)

    return $Value -cmatch ('^(?:api-ms-win-crt-[a-z0-9._-]+|' +
        'concrt[0-9a-z_]*|msvcp[0-9a-z_]*|msvcrt|msvcr[0-9][0-9a-z_]*|' +
        'ucrtbase[0-9a-z_]*|vcruntime[0-9a-z_]*)\.dll$')
}

function Get-StrictStringArray {
    param(
        [AllowNull()] [object]$Value,
        [Parameter(Mandatory)] [string]$Label,
        [switch]$AllowEmpty,
        [switch]$RequireArray
    )

    if ($RequireArray -and -not ($Value -is [System.Array])) {
        throw "$Label must be an array."
    }
    $items = @($Value)
    if (-not $AllowEmpty -and $items.Count -eq 0) {
        throw "$Label may not be empty."
    }
    for ($index = 0; $index -lt $items.Count; $index += 1) {
        if (-not (Test-SafeNormalizedDllName $items[$index])) {
            throw "$Label contains an unsafe or non-normalized DLL name."
        }
        if (Test-ForbiddenDynamicCrtDllName ([string]$items[$index])) {
            throw "$Label contains forbidden dynamically linked CRT: $($items[$index])"
        }
        if ($index -gt 0 -and
            [string]::CompareOrdinal([string]$items[$index - 1], [string]$items[$index]) -ge 0) {
            throw "$Label must be strictly ordinal-sorted with no duplicates."
        }
    }
    return [string[]]$items
}

function Get-SectionDllNames {
    param(
        [Parameter(Mandatory)] [AllowEmptyString()] [string[]]$Lines,
        [Parameter(Mandatory)] [int]$Start,
        [Parameter(Mandatory)] [int]$End,
        [Parameter(Mandatory)] [string]$Label,
        [switch]$AllowEmpty
    )

    $names = [System.Collections.Generic.List[string]]::new()
    for ($index = $Start; $index -lt $End; $index += 1) {
        $line = [string]$Lines[$index]
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        if ($line -cnotmatch '^ {4}([A-Za-z0-9][A-Za-z0-9._-]*\.dll)$') {
            throw "$Label contains malformed pinned-link output: $line"
        }
        $name = $Matches[1].ToLowerInvariant()
        if (Test-ForbiddenDynamicCrtDllName $name) {
            throw "$Label contains forbidden dynamically linked CRT: $name"
        }
        $names.Add($name)
    }
    $unique = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal)
    foreach ($name in $names) { [void]$unique.Add($name) }
    $normalized = [string[]]@($unique)
    [Array]::Sort($normalized, [System.StringComparer]::Ordinal)
    if (-not $AllowEmpty -and $normalized.Count -eq 0) {
        throw "$Label contains no dependencies."
    }
    return $normalized
}

function ConvertFrom-LinkDependentsDump {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Text,
        [string]$ExpectedImagePath
    )

    $lines = [regex]::Split($Text, '\r?\n')
    $contentLines = [string[]]@($lines | Where-Object {
        -not [string]::IsNullOrWhiteSpace([string]$_)
    })
    if ($contentLines.Count -lt 6 -or
        $contentLines[0] -cnotmatch '^Dump of file (\S(?:.*\S)?)$' -or
        $contentLines[1] -cne 'File Type: EXECUTABLE IMAGE' -or
        $contentLines[2] -cne '  Image has the following dependencies:') {
        throw 'Pinned-link dependency output has an invalid preamble or direct section header.'
    }
    $dumpedImagePath = $Matches[1]
    if ($PSBoundParameters.ContainsKey('ExpectedImagePath')) {
        $dumpedFull = [System.IO.Path]::GetFullPath($dumpedImagePath)
        $expectedFull = [System.IO.Path]::GetFullPath($ExpectedImagePath)
        if (-not $dumpedFull.Equals(
                $expectedFull, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw 'Pinned-link dependency output identifies a different image.'
        }
    }
    $directHeaders = @(2)
    $delayHeaders = @(
        0..($contentLines.Count - 1) | Where-Object {
            [string]$contentLines[$_] -ceq '  Image has the following delay load dependencies:'
        }
    )
    $summaries = @(
        0..($contentLines.Count - 1) | Where-Object {
            [string]$contentLines[$_] -ceq '  Summary'
        }
    )
    if ($directHeaders.Count -ne 1 -or $delayHeaders.Count -gt 1 -or $summaries.Count -ne 1) {
        throw 'Pinned-link dependency output has missing or duplicate section headers.'
    }
    $directHeader = [int]$directHeaders[0]
    $summary = [int]$summaries[0]
    if ($summary -le $directHeader) {
        throw 'Pinned-link dependency output has invalid section ordering.'
    }
    $delayHeader = if ($delayHeaders.Count -eq 1) { [int]$delayHeaders[0] } else { -1 }
    if ($delayHeader -ne -1 -and ($delayHeader -le $directHeader -or $delayHeader -ge $summary)) {
        throw 'Pinned-link delay-load section has invalid ordering.'
    }
    if ($summary + 1 -ge $contentLines.Count) {
        throw 'Pinned-link dependency output has no summary rows.'
    }
    for ($index = $summary + 1; $index -lt $contentLines.Count; $index += 1) {
        if ($contentLines[$index] -cnotmatch '^ +[0-9A-Fa-f]+ +\.[A-Za-z0-9$._-]+$') {
            throw "Pinned-link dependency output contains a malformed summary row: $($contentLines[$index])"
        }
    }

    $directEnd = if ($delayHeader -eq -1) { $summary } else { $delayHeader }
    $direct = Get-SectionDllNames -Lines $contentLines -Start ($directHeader + 1) `
        -End $directEnd -Label 'Direct dependency section'
    [string[]]$delay = @()
    if ($delayHeader -ne -1) {
        $delay = [string[]]@(Get-SectionDllNames -Lines $contentLines `
            -Start ($delayHeader + 1) -End $summary `
            -Label 'Delay-load dependency section' -AllowEmpty)
    }
    return [pscustomobject]@{
        directImports = [string[]]$direct
        delayLoadImports = [string[]]$delay
    }
}

function Get-WindowsPeDependencies {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$LinkPath,
        [Parameter(Mandatory)] [string]$ImagePath
    )

    $LinkPath = Get-RegularNonReparseFilePath -Path $LinkPath -Label 'PE dependency linker input'
    $ImagePath = Get-RegularNonReparseFilePath -Path $ImagePath -Label 'PE dependency image input'
    $output = @(& $LinkPath '/dump' '/dependents' '/nologo' $ImagePath 2>&1)
    $exitCode = $LASTEXITCODE
    $text = ($output | ForEach-Object { $_.ToString() }) -join "`n"
    if ($exitCode -ne 0) {
        throw "Pinned link.exe dependency inspection failed with exit code $exitCode."
    }
    return ConvertFrom-LinkDependentsDump -Text $text -ExpectedImagePath $ImagePath
}

function Import-WindowsPeDependencyPolicy {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string]$Path)

    $Path = Get-RegularNonReparseFilePath -Path $Path -Label 'PE dependency policy'
    $document = ConvertFrom-StrictPePolicyJson (Get-Content -Raw -LiteralPath $Path)
    $direct = Get-StrictStringArray -Value $document.directImports `
        -Label 'Policy directImports' -RequireArray
    [string[]]$delay = @(Get-StrictStringArray `
        -Value $document.delayLoadImports `
        -Label 'Policy delayLoadImports' -AllowEmpty -RequireArray)
    return [pscustomobject]@{
        schemaVersion = 1
        directImports = [string[]]$direct
        delayLoadImports = [string[]]$delay
    }
}

function Assert-WindowsPeDependencyPolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object]$Facts,
        [Parameter(Mandatory)] [object]$Policy
    )

    foreach ($field in @('directImports', 'delayLoadImports')) {
        $allowEmpty = $field -ceq 'delayLoadImports'
        $actual = [string[]]@(Get-StrictStringArray -Value $Facts.$field `
            -Label "PE facts $field" -AllowEmpty:$allowEmpty -RequireArray)
        $expected = [string[]]@(Get-StrictStringArray -Value $Policy.$field `
            -Label "PE policy $field" -AllowEmpty:$allowEmpty -RequireArray)
        $missing = [string[]]@($expected | Where-Object { $_ -cnotin $actual })
        $unexpected = [string[]]@($actual | Where-Object { $_ -cnotin $expected })
        if ($actual.Count -ne $expected.Count -or $missing.Count -ne 0 -or $unexpected.Count -ne 0) {
            throw ("PE {0} do not match policy. missing=[{1}] unexpected=[{2}]" -f
                $field, ($missing -join ','), ($unexpected -join ','))
        }
        for ($index = 0; $index -lt $expected.Count; $index += 1) {
            if ($actual[$index] -cne $expected[$index]) {
                throw "PE $field order does not match policy."
            }
        }
    }
    return $true
}

Export-ModuleMember -Function @(
    'ConvertFrom-LinkDependentsDump',
    'Get-WindowsPeDependencies',
    'Import-WindowsPeDependencyPolicy',
    'Assert-WindowsPeDependencyPolicy'
)
