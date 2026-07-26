# Verify a Gilbreth Windows package

Verify all three files before running Setup. The ordinary schema-2 Windows set
uses platform-qualified names:

```text
Gilbreth-X.Y.Z-windows-x64-setup.exe
Gilbreth-X.Y.Z-windows-x64-release-manifest.json
Gilbreth-X.Y.Z-windows-x64-SHA256SUMS.txt
```

Older preview packages used a schema-1 set, which this guide still verifies:

```text
Gilbreth-X.Y.Z-preview-windows-x64-setup.exe
release-manifest.json
SHA256SUMS.txt
```

Every package published here uses the schema-2 set.

## Verify hashes and manifest identity

Put exactly one three-file set in an otherwise empty directory, set `$Version`,
and run this PowerShell from that directory:

```powershell
$Version = 'X.Y.Z'

$ordinary = @{
    Kind = 'schema2'
    Setup = "Gilbreth-$Version-windows-x64-setup.exe"
    Manifest = "Gilbreth-$Version-windows-x64-release-manifest.json"
    Checksums = "Gilbreth-$Version-windows-x64-SHA256SUMS.txt"
}
$legacy = @{
    Kind = 'schema1'
    Setup = "Gilbreth-$Version-preview-windows-x64-setup.exe"
    Manifest = 'release-manifest.json'
    Checksums = 'SHA256SUMS.txt'
}
$sets = @($ordinary, $legacy)
$matches = @($sets | Where-Object {
    (Test-Path -LiteralPath $_.Setup -PathType Leaf) -and
    (Test-Path -LiteralPath $_.Manifest -PathType Leaf) -and
    (Test-Path -LiteralPath $_.Checksums -PathType Leaf)
})
if ($matches.Count -ne 1) { throw 'Expected exactly one complete Gilbreth package set' }
$set = $matches[0]

$expectedNames = @($set.Setup, $set.Manifest, $set.Checksums)
$actualNames = @(Get-ChildItem -File | ForEach-Object Name)
$unexpected = @($actualNames | Where-Object { $_ -notin $expectedNames })
$missing = @($expectedNames | Where-Object { $_ -notin $actualNames })
if ($actualNames.Count -ne 3 -or $unexpected.Count -ne 0 -or $missing.Count -ne 0) {
    throw "Package directory is not the exact three-file set"
}

$expected = @{}
$lines = @(Get-Content -LiteralPath $set.Checksums |
    Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
if ($lines.Count -ne 2) { throw 'SHA256SUMS must contain exactly two entries' }
foreach ($line in $lines) {
    if ($line -notmatch '^([0-9a-f]{64})  ([^\\/]+)$') {
        throw "Malformed SHA256SUMS line: $line"
    }
    if ($expected.ContainsKey($Matches[2])) { throw 'Duplicate SHA256SUMS entry' }
    $expected[$Matches[2]] = $Matches[1]
}
if ($expected.Count -ne 2 -or
    -not $expected.ContainsKey($set.Setup) -or
    -not $expected.ContainsKey($set.Manifest)) {
    throw 'Checksums must cover exactly the installer and manifest'
}
foreach ($name in $expected.Keys) {
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $name).Hash.ToLowerInvariant()
    if ($actual -ne $expected[$name]) { throw "SHA-256 mismatch: $name" }
}

$manifest = Get-Content -Raw -LiteralPath $set.Manifest | ConvertFrom-Json
if ([string]$manifest.version -ne $Version) { throw 'Manifest version mismatch' }
if ($set.Kind -eq 'schema2') {
    if ([int]$manifest.schemaVersion -ne 2) { throw 'Expected manifest schema 2' }
    if ([string]$manifest.target -ne 'windows-x64') { throw 'Manifest target mismatch' }
    if ([string]$manifest.source.tag -ne "v$Version") { throw 'Manifest source tag mismatch' }
    if ([string]$manifest.signing.mode -notin @('unsigned', 'artifact-signing')) {
        throw 'Unexpected schema-2 signing mode'
    }
    if ($null -ne $manifest.channel) { throw 'Schema-2 manifest must not carry a preview channel' }
} else {
    if ([int]$manifest.schemaVersion -ne 1) { throw 'Expected legacy manifest schema 1' }
    if ([string]$manifest.channel -ne 'preview' -or
        [string]$manifest.architecture -ne 'windows-x64') {
        throw 'Legacy preview manifest identity mismatch'
    }
}
"PASS: $($set.Kind) Windows package hashes and identity match"
```

The release page identifies the expected source commit. Compare it with
`source.commit` in the manifest. Schema 2 also binds `source.tag` to `vX.Y.Z`;
the legacy schema records the preview tag a package was built from. The
manifest lists the expected SHA-256 of installed
`gilbreth-app.exe` and `gilbreth-lifecycle-guard.exe`, build inputs, and signing
posture. Matching hashes establish byte identity; they do not replace Windows
signature validation.

For a signed release, open each executable's **Properties > Digital
Signatures**, confirm the signer named in the draft or published release notes,
and confirm Windows reports a valid signature. An unsigned package has no Digital
Signatures entry and may trigger an unknown-publisher or SmartScreen warning.

## Tested platform and updates

The supported package target is **Windows 11 x64**. The recorded legacy R1
clean-machine lifecycle ran on Windows 11 Enterprise Evaluation 25H2, build
`26200.8655`, x64. Windows 10 and Windows on ARM64 are untested; the package and
manifest therefore say `windows-x64`, not a broader architecture claim.

Updates are manual. Gilbreth has no update checker, telemetry, or other network
updater. Download and verify the latest Windows set, stop every Gilbreth
process, and run Setup over the existing installation. The installer replaces
program files while preserving the database, archives, logs, configuration,
sidecars, and dashboard state. It refuses the update rather than partially
replacing files when it cannot establish exclusive access.

The latest published build **for a platform** is supported. Because Gilbreth
uses one version line while publishing only platforms that changed, that build
may be attached to an earlier project tag than another platform's latest
build.

## Install, archive, and uninstall boundaries

The per-user installer writes program files to
`%LOCALAPPDATA%\Programs\Gilbreth`; it needs neither a source checkout nor
administrator privileges. The default data root is `%LOCALAPPDATA%\Gilbreth`.
A deliberately configured SQLite database outside that root belongs to the
database class and is removed only by explicit destructive uninstall. If its
configuration cannot be resolved safely, purge fails closed and preserves the
config pointer. User-created exports outside the data root are retained.

Normal uninstall keeps user data. Interactive uninstall removes data only when
that option is explicitly selected. For automation,
`unins000.exe /SILENT /PURGEDATA` is destructive; silent uninstall without
`/PURGEDATA` keeps data. Content-free purge receipts are written outside the
removed root under `%LOCALAPPDATA%\Gilbreth-uninstall-receipts`.

Tray archive/reset creates a versioned AES-256-GCM `.gla`; DPAPI protects its
content key for the current Windows account. This is an account/profile
recovery boundary, not portability: loss of the Windows profile makes those
account-bound archives unrecoverable. The Privacy dashboard can explicitly
create a passphrase-protected portable `.gla`, or an acknowledged plaintext
`.db`. Legacy `gilbreth-archive-*.db` files remain plaintext and are never
silently converted.

Archive/reset, secure erase, portable export, and destructive uninstall use the
content-free outcomes `copied`, `removed`, `retained`, `deferred`, and
`needs retry`. Receipts contain bounded classes/counts/errors, not captured
content or identifying paths. Portable exports outside the data root are
reported as retained and are not deleted automatically.

Keep-data uninstall uses the independent lifecycle guard, so a quarantined main
app does not strand the Add/Remove Programs entry. Destructive purge also
requires the installed app to prove package authority. If install, update, or
uninstall refuses to continue, close all Gilbreth tray/dashboard processes in
every signed-in Windows session and retry; lifecycle operations intentionally
fail closed without exclusive access.

## macOS

There is no public macOS package or verification procedure yet. MAC-2 must
implement and test Developer ID signing, notarization, stapling, DMG packaging,
and the clean-machine Gatekeeper/TCC path before commands are added here.

### Removing Gilbreth by hand

macOS has no uninstaller. Dragging `Gilbreth.app` to the Trash removes the
application and nothing else: everything Gilbreth captured stays on disk. Tray
**Erase all my data** is the supported way to remove captured activity, and it
is the only path that also handles archives and sidecars; the list below is for
removing what remains after the app itself is gone, or for removing everything
without launching Gilbreth first.

Quit Gilbreth first, then remove the data root:

```sh
rm -rf ~/Library/"Application Support"/Gilbreth
```

That directory holds the live database and its WAL, the configuration, the
permission and pause-hotkey sidecars, the sphere-name map, operation receipts,
the single-instance and dashboard-UI lockfiles, and any archives copied in from
a Windows install. Diagnostic logs live under the same root unless
`logs.directory` in `config.toml` points elsewhere; check that value before
deleting if you ever changed it.

Two honest limits. macOS keeps its own copies Gilbreth cannot reach: APFS local
snapshots and Time Machine backups can retain blocks written before a removal
for up to about 24 hours, and FileVault is the control that protects them.
Login Items also survives a manual removal, so turn Gilbreth off under System
Settings > General > Login Items if you had launch-at-startup enabled.

Permission grants are separate from data. Accessibility and Input Monitoring
entries persist under System Settings > Privacy & Security until you remove
them there.
