# Release process

This is the sole recurring release procedure for Gilbreth. The
The roadmap decides *what* is ready; this document defines *how* a
release is cut. The one-time move to a public repository follows a separate runbook.

Gilbreth uses one monotonically increasing `vX.Y.Z` version line across all
platforms. A release includes only the platforms whose builds are ready; it
does not force an unchanged platform to rebuild. Support means the **latest
published build for each platform**, which may not be attached to the
numerically latest project tag.

## Release-host prerequisites

The Windows release maintainer needs a clean Windows 11 x64 clone, Git,
PowerShell 7, Python with `scripts/requirements-dev.txt`, rustup, and either the
GitHub CLI or equivalent GitHub web access. Enable the checked-in routing once
per clone and install the toolchain named by the release configuration:

```powershell
git config core.hooksPath .githooks
python -m pip install -r scripts/requirements-dev.txt
$ReleaseConfig = Get-Content -Raw packaging/windows/release-config.json | ConvertFrom-Json
$Toolchain = "$($ReleaseConfig.rustRelease)-$($ReleaseConfig.rustHost)"
rustup toolchain install $Toolchain --profile minimal --component rustfmt --component clippy
rustup override set $Toolchain
rustup show active-toolchain
```

The exact Rust release, Visual Studio toolset, Windows SDK, and Inno Setup
versions and hashes are authoritative in
[`packaging/windows/release-config.json`](../packaging/windows/release-config.json).
Provision the exact MSVC toolset and Windows SDK through Visual Studio Installer
and install the exact Inno Setup version for the current user or machine; pass
`-InnoCompiler` only when its approved `ISCC.exe` is outside the standard
locations. The builder requires one matching toolset installation and verifies
all tool versions, content digests, and binary hashes before compiling. Do not
weaken a pin to fit a workstation; update a pin deliberately in a reviewed
change. A signed release also requires the protected, secretless signing
wrapper described in the Windows lane below. Tyler Arnold is the default
release owner and publisher; any delegate and the signing-credential custodian
are named in the release notes or private operational record without recording
secret material.

## Shared lifecycle

1. **Select the release.** Choose `X.Y.Z`, the included platforms, and the
   user-visible changes. Never reuse a version or replace published bytes.
2. **Bind the source version.** Update `[workspace.package].version` in the
   root `Cargo.toml`, then refresh `Cargo.lock` with
   `cargo metadata --format-version 1 | Out-Null`. If Windows is selected,
   regenerate its version-bound notice inventory with
   `pwsh -File scripts/windows-third-party-notices.ps1 -Mode Generate`, review
   the diff, and verify it with `-Mode Verify`. Commit the version, lockfile,
   and generated notice files together. All selected platform packages use
   this same version.
3. **Reach clean, green `main`.** The ordinary fmt, clippy, workspace-test,
   Python-tooling, and platform CI gates pass. Review privacy-sensitive and
   destructive-path changes with the focused care described below.
4. **Create the source tag locally.** On that clean commit, create the annotated
   tag `vX.Y.Z`. Do not push it yet. Builders must reject a lightweight tag, a
   tag that does not resolve to `HEAD`, a dirty tree, or a Cargo version that
   differs from `X.Y.Z`.
5. **Build and smoke each selected platform.** Build from the exact tagged
   source and run the short product smoke for every platform in the release.
   A failed platform is either fixed before shipping or explicitly removed
   from this release's selected set.
6. **Push the same tag.** After all selected builds and smokes pass, push the
   already-tested annotated tag. Never recreate or move it.
7. **Assemble a draft GitHub Release.** Upload the complete three-file set for
   every selected platform. Keep the release in draft until all selected sets,
   notes, checksums, signing statements, and limitations are present; then
   publish it once.
8. **Verify as a stranger.** Without private-repository access, download every
   published set, follow [VERIFY.md](VERIFY.md), and exercise the applicable
   clean install/update/uninstall path.
9. **Dogfood and fix forward.** Normal use is the soak. Correct a defect in a
   new version; do not silently replace assets under an existing version. A
   truly unusable release may be marked pre-release or withdrawn with a plain
   explanation, but user data is never rolled back or deleted as a release
response.

The tag and publication operations are intentionally ordinary. Set the version
once, inspect the annotated tag, and push that same object only after every
selected platform build and smoke has passed:

```powershell
$Version = 'X.Y.Z'
git status --short
git tag -a "v$Version" -m "Gilbreth v$Version"
git cat-file -t "refs/tags/v$Version"       # must print: tag
git rev-list -n 1 "v$Version"              # must equal: git rev-parse HEAD

# Build and smoke every selected platform here. Do not push before it passes.
git push origin "v$Version"
```

For the currently executable Windows-only lane, the GitHub CLI equivalent of
creating the required draft is below; the GitHub web UI is also acceptable.
Review the draft, notes, limitations, and all assets before publishing it:

```powershell
$AssetDir = "dist/public/$Version/windows-x64"
gh release create "v$Version" --draft --verify-tag `
  --title "Gilbreth v$Version" --notes-file release-notes.md `
  "$AssetDir/Gilbreth-$Version-windows-x64-setup.exe" `
  "$AssetDir/Gilbreth-$Version-windows-x64-release-manifest.json" `
  "$AssetDir/Gilbreth-$Version-windows-x64-SHA256SUMS.txt"
```

Release when there is something worth shipping; there is no calendar cadence.
The intended human gate is under an hour once the platform builder exists. Do
not restore per-release review packets, candidate chains, duration-locked
soaks, evidence sealing, or other retired R1 ceremony.

## Windows x64 release lane

Windows 11 x64 is the only executable public-package lane today. From the
annotated `vX.Y.Z` commit, an unsigned build is:

```powershell
.\scripts\build-windows-package.ps1 `
  -Version X.Y.Z `
  -SourceTag vX.Y.Z `
  -Unsigned
```

A signed release supplies the existing protected `-SignToolCommand` instead of
`-Unsigned`. Never place signing credentials or the expanded signing command in
Git, a manifest, logs, or release notes.

The builder publishes exactly these files under
`dist/public/X.Y.Z/windows-x64/`:

```text
Gilbreth-X.Y.Z-windows-x64-setup.exe
Gilbreth-X.Y.Z-windows-x64-release-manifest.json
Gilbreth-X.Y.Z-windows-x64-SHA256SUMS.txt
```

The checksum file contains exactly two entries: the installer and manifest.
The schema-2 manifest identifies `target: "windows-x64"`, the exact source tag
and commit, Cargo version, pinned build inputs, package contents, and signing
mode (`unsigned` or `artifact-signing`). It has no preview channel. Publication
is atomic: no partial or extra public file set is acceptable.

The builder remains fail-closed on the established release properties:

- clean tree and exact annotated tag/commit/Cargo-version binding;
- pinned Rust, native, Inno Setup, and dependency inputs;
- allowlisted payload, third-party notices, package authority, PE dependencies,
  and static CRT policy;
- expected Authenticode state and signature verification;
- deterministic source/user-profile path remapping and scans of the staged
  payload and installer for checkout roots, user-profile paths, usernames, and
  host identifiers.

The compressed installer is also checked by the clean-machine smoke after
installation. Use a disposable data set and record these concrete results:

- Setup exits successfully over the previously supported Windows build, the
  installed payload contains only the expected package inventory, and a scan
  of those extracted files finds no checkout root, user-profile path,
  username, or host identifier.
- The existing data root and settings survive the update. The tray starts, a
  short known window/input sequence creates new activity, Today shows that
  activity, and Diagnostics reports the recorder and database as healthy.
- When installer or destructive-lifecycle code changed, keep-data uninstall
  preserves the disposable data root; after reinstall, explicit purge removes
  it. Neither path leaves an unexpected program file or autostart entry.

Follow [VERIFY.md](VERIFY.md) for the download, signature, and lifecycle checks.

## macOS arm64 release lane

There is no executable macOS public-package lane yet. Application dogfood is
complete, but **MAC-2**
must close before a macOS release. MAC-2 includes the remaining parity fixes,
Apple Developer enrollment, Developer ID signing, hardened runtime, DMG
packaging, timestamping, notarization, stapling, platform notices, and a
pristine-machine Gatekeeper/TCC smoke.

When that lane exists, its per-platform set will be:

```text
Gilbreth-X.Y.Z-macos-arm64.dmg
Gilbreth-X.Y.Z-macos-arm64-release-manifest.json
Gilbreth-X.Y.Z-macos-arm64-SHA256SUMS.txt
```

No macOS build, signing, or verification command is specified until MAC-2
implements and tests it. Linux remains library/CI hygiene only and is not a
product release target.

## Focused review and failure policy

Release ceremony stays lightweight, but changes to capture/privacy filtering,
destructive operations, database schemas/migrations, package authority, or the
no-network claim receive focused review before merge. Normal uninstall keeps
user data; explicit purge stays fail-closed. Migrations remain additive or
backward-tolerant. Release notes state signing posture and known limitations
honestly.

The rationale for the lightweight posture is preserved in the private
development archive.
