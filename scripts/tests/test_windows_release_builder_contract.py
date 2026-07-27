import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
BUILDER = ROOT / "scripts" / "build-windows-package.ps1"
CONFIG = ROOT / "packaging" / "windows" / "release-config.json"
INNO = ROOT / "packaging" / "windows" / "Gilbreth.iss"
RUNTIME = ROOT / "crates" / "gilbreth-app" / "src" / "uninstall.rs"
VERIFY = ROOT / "docs" / "VERIFY.md"
NOTICE_GENERATOR = ROOT / "scripts" / "windows-third-party-notices.ps1"
NOTICE = ROOT / "docs" / "THIRD-PARTY-NOTICES.md"


def _builder() -> str:
    return BUILDER.read_text(encoding="utf-8")


def test_release_build_never_mutates_the_callers_environment() -> None:
    """The build environment belongs to the child process, not to this shell.

    The builder used to set the toolchain variables on itself and restore them
    in a finally block. Two things went wrong with that. An interrupt skipped
    the restore, and the restore itself passed PowerShell's $null to
    SetEnvironmentVariable, which writes an empty string rather than removing
    the variable. Either way the caller's shell was left holding variables that
    the builder's own environment guard rejects, so a second run in the same
    shell failed with a list of twenty names and no hint that the fix was a new
    shell.
    """
    script = _builder()

    assert "function Invoke-NativeTextInEnvironment" in script
    assert "Invoke-NativeTextInEnvironment -FilePath $cargoPath" in script

    # The toolchain variables must be delivered as a hashtable to the child,
    # never assigned into this process.
    for name in (
        "GILBRETH_BUILD_GIT_SHA",
        "VCToolsInstallDir",
        "WindowsSDKVersion",
        "CC_x86_64_pc_windows_msvc",
    ):
        assert (
            f"[Environment]::SetEnvironmentVariable('{name}'" not in script
        ), f"{name} is still assigned into the builder's own process"

    # Nothing may reintroduce the save/restore pattern. Checked by its own
    # variables rather than by looking for "finally", which the script uses
    # legitimately elsewhere for disposing handles.
    for marker in (
        "$nativeBuildEnvironmentBefore",
        "$nativeBuildEnvironmentNames",
        "$oldIncremental",
        "$oldPackageTrustMode",
    ):
        assert marker not in script, f"{marker} reintroduces the save/restore pattern"

    # An ambient developer command prompt must not reach the build.
    assert "'VSINSTALLDIR'                    = $null" in script
    assert "'VCINSTALLDIR'                    = $null" in script


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="PowerShell 7 required")
def test_child_environment_removes_variables_rather_than_blanking_them() -> None:
    """$null must delete the variable in the child, not set it to "".

    This is the exact defect that made the builder single-shot per shell, and it
    is invisible to inspection: an empty variable still appears in `Get-ChildItem
    Env:` and still trips a guard that only checks for presence.
    """
    builder = _builder()
    function = "function Invoke-NativeTextInEnvironment" + builder.split(
        "function Invoke-NativeTextInEnvironment", 1
    )[1].split("\nfunction Get-Sha256Lower", 1)[0]

    script = f"""
$ErrorActionPreference = 'Stop'
{function}
# PROBE_KEEP is inherited, PROBE_DROP is removed, PROBE_SET is overridden.
$env:PROBE_KEEP = 'inherited'
$env:PROBE_DROP = 'should-disappear'
$out = Invoke-NativeTextInEnvironment -FilePath 'cmd.exe' `
    -ArgumentList @('/c', 'set PROBE_') `
    -Environment @{{ 'PROBE_DROP' = $null; 'PROBE_SET' = 'overridden' }}
"CHILD:$out"
"PARENT_DROP_STILL_SET:$([bool]$env:PROBE_DROP)"
"PARENT_SET_LEAKED:$([bool]$env:PROBE_SET)"
"""
    result = subprocess.run(
        [shutil.which("pwsh"), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    out = result.stdout

    assert "PROBE_KEEP=inherited" in out, "the child should inherit unlisted variables"
    assert "PROBE_SET=overridden" in out, "the child should receive overrides"
    assert "PROBE_DROP" not in out.split("PARENT_DROP_STILL_SET")[0], (
        "a $null value must remove the variable from the child, not blank it"
    )
    # And the caller is untouched either way.
    assert "PARENT_DROP_STILL_SET:True" in out
    assert "PARENT_SET_LEAKED:False" in out


def test_release_config_accepts_only_plain_semver_tags_and_stable_names() -> None:
    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    tag_pattern = re.compile(
        config["tagPattern"].replace("(?<version>", "(?P<version>")
    )

    assert tag_pattern.fullmatch("v1.2.3")
    assert not tag_pattern.fullmatch("v1.2.3-preview.1")
    assert not tag_pattern.fullmatch("1.2.3")
    assert not tag_pattern.fullmatch("V1.2.3")
    assert not tag_pattern.fullmatch("v01.2.3")
    assert not tag_pattern.fullmatch("v1.02.3")
    assert not tag_pattern.fullmatch("v1.2.03")
    assert config["target"] == "windows-x64"
    assert config["installerNameTemplate"] == ("Gilbreth-{version}-windows-x64-setup")
    assert "channel" not in config
    assert "architecture" not in config


def test_builder_requires_one_explicit_signing_mode() -> None:
    script = _builder()

    assert "[switch]$Unsigned" in script
    assert "Choose either -Unsigned or -SignToolCommand, not both." in script
    assert "Pass -Unsigned or supply the protected -SignToolCommand." in script
    assert "[string]$SignToolCommand" in script
    assert "[switch]$UnsignedPrototype" not in script
    assert "unsigned-prototype" not in script.lower()
    assert "-cnotmatch [string]$config.tagPattern" in script
    assert "(0|[1-9][0-9]*)" in script


def test_schema_two_manifest_is_platform_qualified_and_channel_free() -> None:
    script = _builder()
    manifest = script.split("$manifest = [ordered]@{", 1)[1].split(
        "$manifestFileName", 1
    )[0]

    assert "schemaVersion = 2" in manifest
    assert "target = [string]$config.target" in manifest
    assert "channel =" not in manifest
    assert (
        "mode = $(if ($Unsigned) { 'unsigned' } else { 'artifact-signing' })"
        in manifest
    )
    assert '"Gilbreth-$Version-windows-x64-release-manifest.json"' in script
    assert '"Gilbreth-$Version-windows-x64-SHA256SUMS.txt"' in script


def test_publication_is_atomic_and_contains_exactly_three_files() -> None:
    script = _builder()

    assert '"public\\$Version\\windows-x64"' in script
    assert (
        "$expectedPublicFiles = @($installerFile.Name, $manifestFileName, $checksumFileName)"
        in script
    )
    assert "$actualPublicFiles.Count -ne $expectedPublicFiles.Count" in script
    assert "Move-Item -LiteralPath $publishWorkDir -Destination $publicDir" in script
    assert "private-final-package" not in script
    assert "pre-sign-evidence.json" not in script
    assert "final-package-evidence.json" not in script


def test_build_paths_are_remapped_and_outputs_are_scanned_fail_closed() -> None:
    script = _builder()

    assert "--remap-path-prefix=$($repoRoot.Replace('\\', '/'))=." in script
    assert "--remap-path-prefix=$(([string]$buildMarkers['user-profile'])" in script
    assert "function Assert-FilesExcludeBuildMarkers" in script
    assert "'checkout-root'" in script
    assert "'user-profile'" in script
    assert "'user-name'" in script
    assert "'host-name'" in script
    assert "-Label 'Staged package payload'" in script
    assert "-Label 'Final Windows package'" in script
    assert (
        "$installerPath" in script.split("-Label 'Final Windows package'", 1)[0][-250:]
    )
    assert "$marker.Length -lt" not in script
    assert "function Test-ContainsBuildMarker" in script
    assert "$tokenBounded = $markerName -in @('user-name', 'host-name')" in script


# `IntegerRealTextBlob` is a real SQLite type-affinity string present in the
# linked binary, and a short account name can land inside it. That collision is
# why `user-name` matching is token-bounded: the first case must NOT reject.
# Keep any replacement marker a non-token-bounded substring of the content, or
# the case silently stops testing anything.
@pytest.mark.parametrize(
    ("content", "marker", "should_reject"),
    [
        (b"IntegerRealTextBlob", "eger", False),
        (b"C:\\Users\\eger\\AppData", "eger", True),
        (b"\x7f" + "eger\\".encode("utf-16-le"), "eger", True),
        ("ÉGER".encode(), "éger", True),
    ],
)
def test_build_marker_scan_handles_boundaries_and_encodings(
    tmp_path: Path, content: bytes, marker: str, should_reject: bool
) -> None:
    pwsh = shutil.which("pwsh")
    if pwsh is None:
        pytest.skip("PowerShell 7 is required to execute the build-marker scanner")

    builder = _builder()
    scanner = (
        "function Assert-FilesExcludeBuildMarkers"
        + builder.split("function Assert-FilesExcludeBuildMarkers", 1)[1].split(
            "if ($Unsigned -and", 1
        )[0]
    )
    fixture = tmp_path / "fixture.bin"
    fixture.write_bytes(content)
    fixture_literal = str(fixture).replace("'", "''")
    marker_literal = marker.replace("'", "''")
    script = f"""
$ErrorActionPreference = 'Stop'
{scanner}
$markers = [ordered]@{{ 'user-name' = '{marker_literal}' }}
Assert-FilesExcludeBuildMarkers -LiteralPaths @('{fixture_literal}') `
    -Markers $markers -Label 'Behavior fixture'
"""
    result = subprocess.run(
        [pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if should_reject:
        assert result.returncode != 0
        assert "forbidden user-name build-machine marker" in (
            result.stderr + result.stdout
        )
    else:
        assert result.returncode == 0, result.stderr or result.stdout


def test_provenance_toolchain_allowlist_and_pe_controls_remain_fail_closed() -> None:
    script = _builder()

    for required in (
        "Release builds require a clean tree",
        "must be an exact annotated tag ref",
        "does not resolve to HEAD",
        "Cargo authoritative gilbreth-app version does not match",
        "Rust executable dependencies/target libraries do not match",
        "Approved native tool hash mismatch",
        "Staging changed outside the allowlist",
        "Get-PolicyCheckedPeFacts",
        "target-feature=+crt-static",
        "Packaging changed the source tree",
    ):
        assert required in script


def test_inno_uses_stable_product_names_and_keeps_signed_and_unsigned_lanes() -> None:
    script = INNO.read_text(encoding="utf-8")

    assert "AppVerName={#ProductName} {#AppVersion}" in script
    assert "AppVerName={#ProductName} {#AppVersion} preview" not in script
    assert "OutputBaseFilename={#InstallerBaseName}" in script
    assert "#ifdef SigningEnabled" in script
    assert "SignTool=artifact_sign" in script
    assert "SignedUninstaller=yes" in script
    assert "SignedUninstaller=no" in script
    assert "Phase5" not in script
    assert "phase5" not in script


def test_release_lane_contains_no_prototype_authority_behavior() -> None:
    inno = INNO.read_text(encoding="utf-8")
    runtime = RUNTIME.read_text(encoding="utf-8")

    for source in (_builder(), inno, runtime):
        assert "allow-unsigned-prototype" not in source.lower()
        assert "unsignedprototype" not in source.lower()
    assert "--allow-unsigned-package" in inno
    assert "--allow-unsigned-package" in runtime


def _verification_block() -> str:
    section = VERIFY.read_text(encoding="utf-8").split(
        "## Verify hashes and manifest identity", 1
    )[1]
    blocks = re.findall(r"```powershell\n(.*?)```", section, re.DOTALL)
    assert blocks, "VERIFY.md must contain its executable PowerShell verifier"
    return blocks[0]


@pytest.mark.parametrize("kind", ["schema1", "schema2"])
def test_verify_procedure_accepts_legacy_and_current_sets(
    tmp_path: Path, kind: str
) -> None:
    pwsh = shutil.which("pwsh")
    if pwsh is None:
        pytest.skip("PowerShell 7 is required to execute the documented verifier")

    version = "0.1.0" if kind == "schema1" else "1.2.3"
    if kind == "schema1":
        setup_name = f"Gilbreth-{version}-preview-windows-x64-setup.exe"
        manifest_name = "release-manifest.json"
        checksum_name = "SHA256SUMS.txt"
        manifest = {
            "schemaVersion": 1,
            "version": version,
            "channel": "preview",
            "architecture": "windows-x64",
            "source": {"tag": "v0.1.0-preview.14", "commit": "a" * 40},
        }
    else:
        setup_name = f"Gilbreth-{version}-windows-x64-setup.exe"
        manifest_name = f"Gilbreth-{version}-windows-x64-release-manifest.json"
        checksum_name = f"Gilbreth-{version}-windows-x64-SHA256SUMS.txt"
        manifest = {
            "schemaVersion": 2,
            "version": version,
            "target": "windows-x64",
            "source": {"tag": f"v{version}", "commit": "b" * 40},
            "signing": {"mode": "unsigned"},
        }

    setup = tmp_path / setup_name
    manifest_path = tmp_path / manifest_name
    setup.write_bytes(b"synthetic installer fixture\n")
    manifest_path.write_text(json.dumps(manifest) + "\n", encoding="utf-8")
    checksums = tmp_path / checksum_name
    checksums.write_text(
        "\n".join(
            [
                f"{hashlib.sha256(setup.read_bytes()).hexdigest()}  {setup_name}",
                f"{hashlib.sha256(manifest_path.read_bytes()).hexdigest()}  {manifest_name}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    script = _verification_block().replace(
        "$Version = 'X.Y.Z'", f"$Version = '{version}'", 1
    )
    result = subprocess.run(
        [pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr or result.stdout
    assert f"PASS: {kind} Windows package hashes and identity match" in result.stdout


def test_installed_notice_uses_the_release_manifest_beside_the_installer() -> None:
    for path in (NOTICE_GENERATOR, NOTICE):
        text = path.read_text(encoding="utf-8")
        assert "manifest shipped beside the installer" in text
        assert "in `release-manifest.json`" not in text
