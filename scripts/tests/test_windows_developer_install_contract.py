import base64
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
HELPERS = ROOT / "scripts" / "install_helpers.ps1"
INSTALLER = ROOT / "scripts" / "install-windows.ps1"
VERIFIER = ROOT / "scripts" / "verify_build_install.ps1"

pytestmark = pytest.mark.skipif(
    os.name != "nt", reason="Windows developer install contract"
)


def _powershell(name: str) -> str:
    path = shutil.which(name)
    if not path:
        pytest.skip(f"{name} is unavailable")
    return path


def _run_ps(script: str, engine: str) -> subprocess.CompletedProcess[str]:
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    return subprocess.run(
        [
            _powershell(engine),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
            encoded,
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.parametrize("engine", ["pwsh", "powershell"])
def test_developer_install_lane_resolver_accepts_only_the_two_supported_paths(
    engine: str,
) -> None:
    script = f"""
    $ErrorActionPreference = 'Stop'
    . '{HELPERS}'
    $release = 'C:\\Repo With Space\\target\\release\\gilbreth-app.exe'
    $stable = 'C:\\Users\\Person\\AppData\\Local\\Gilbreth\\bin\\gilbreth-app.exe'
    $releaseLane = Resolve-GilbrethDeveloperInstallLane `
        -RunPath $release -ReleaseExe $release -StableExe $stable
    $stableLane = Resolve-GilbrethDeveloperInstallLane `
        -RunPath $stable.ToUpperInvariant() -ReleaseExe $release -StableExe $stable
    $unsupportedLane = Resolve-GilbrethDeveloperInstallLane `
        -RunPath 'C:\\Other\\gilbreth-app.exe' -ReleaseExe $release -StableExe $stable
    $relativeLane = Resolve-GilbrethDeveloperInstallLane `
        -RunPath 'target\\release\\gilbreth-app.exe' -ReleaseExe $release -StableExe $stable
    [ordered]@{{
        release_name = $releaseLane.name
        release_app = $releaseLane.app_path
        stable_name = $stableLane.name
        stable_app = $stableLane.app_path
        unsupported = ($null -eq $unsupportedLane)
        relative = ($null -eq $relativeLane)
    }} | ConvertTo-Json -Compress
    """

    result = _run_ps(script, engine)

    assert result.returncode == 0, result.stdout + result.stderr
    contract = json.loads(result.stdout)
    assert contract["release_name"] == "repo-release"
    assert contract["release_app"].lower().endswith(r"\target\release\gilbreth-app.exe")
    assert contract["stable_name"] == "stable-install"
    assert contract["stable_app"].lower().endswith(r"\gilbreth\bin\gilbreth-app.exe")
    assert contract["unsupported"] is True
    assert contract["relative"] is True


def test_verifier_checks_the_selected_supported_target_sha() -> None:
    installer = INSTALLER.read_text(encoding="utf-8")
    script = VERIFIER.read_text(encoding="utf-8")

    assert "$installDir = Join-Path $env:LOCALAPPDATA 'Gilbreth\\bin'" in installer
    assert "$installedExe = Join-Path $installDir 'gilbreth-app.exe'" in installer
    assert (
        "$stableExe = Join-Path $env:LOCALAPPDATA " "'Gilbreth\\bin\\gilbreth-app.exe'"
    ) in script
    assert "Resolve-GilbrethDeveloperInstallLane" in script
    assert "Test-BinaryContainsAscii -Path $runPath -Needle $shortSha" in script
    assert "HKCU Run target does not contain embedded Git SHA $shortSha" in script
    assert "HKCU Run value Gilbreth is empty" in script
