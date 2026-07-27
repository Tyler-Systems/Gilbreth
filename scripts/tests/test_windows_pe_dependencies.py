import base64
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "scripts" / "windows-pe-dependencies.psm1"
POLICY = ROOT / "packaging" / "windows" / "pe-dependencies.json"
BUILDER = ROOT / "scripts" / "build-windows-package.ps1"
CONFIG = ROOT / "packaging" / "windows" / "release-config.json"

FORBIDDEN_CRTS = [
    "VCRUNTIME140.dll",
    "VCRUNTIME140_1.dll",
    "VCRUNTIME140_1D.dll",
    "MSVCP140.dll",
    "MSVCP_WIN.dll",
    "MSVCR120.dll",
    "MSVCRT.dll",
    "CONCRT140.dll",
    "ucrtbase.dll",
    "ucrtbased.dll",
    "api-ms-win-crt-runtime-l1-1-0.dll",
]

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows PE policy")


def _powershell(name: str = "pwsh") -> str:
    path = shutil.which(name)
    if not path:
        pytest.skip(f"{name} is unavailable")
    return path


def _run_ps(script: str, name: str = "pwsh") -> subprocess.CompletedProcess[str]:
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    return subprocess.run(
        [
            _powershell(name),
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


def _dump(direct: list[str], delay: list[str] | None = None) -> str:
    rows = [
        "Dump of file fixture.exe",
        "",
        "File Type: EXECUTABLE IMAGE",
        "",
        "  Image has the following dependencies:",
        "",
        *[f"    {name}" for name in direct],
        "",
    ]
    if delay is not None:
        rows.extend(
            [
                "  Image has the following delay load dependencies:",
                "",
                *[f"    {name}" for name in delay],
                "",
            ]
        )
    rows.extend(["  Summary", "", "        1000 .text"])
    return "\r\n".join(rows)


def _convert_script(text: str) -> str:
    literal = text.replace("'", "''")
    return (
        f"Import-Module '{MODULE}' -Force; "
        f"ConvertFrom-LinkDependentsDump -Text '{literal}' | ConvertTo-Json -Compress"
    )


def test_parser_normalizes_case_and_duplicates() -> None:
    result = _run_ps(
        _convert_script(_dump(["KERNEL32.dll", "kernel32.dll", "USER32.dll"]))
    )
    assert result.returncode == 0, result.stderr
    facts = json.loads(result.stdout.strip())
    assert facts == {
        "directImports": ["kernel32.dll", "user32.dll"],
        "delayLoadImports": [],
    }


def test_parser_uses_ordinal_sorting_for_normalized_names() -> None:
    result = _run_ps(
        _convert_script(_dump(["a_b.dll", "A-B.dll", "a.b.dll", "a_b.dll"]))
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout.strip())["directImports"] == [
        "a-b.dll",
        "a.b.dll",
        "a_b.dll",
    ]


@pytest.mark.parametrize(
    "bad_name",
    FORBIDDEN_CRTS,
)
def test_exact_policy_rejects_dynamic_runtime_imports(bad_name: str) -> None:
    text = _dump([*json.loads(POLICY.read_text())["directImports"], bad_name])
    literal = text.replace("'", "''")
    script = (
        f"Import-Module '{MODULE}' -Force; "
        f"$p=Import-WindowsPeDependencyPolicy '{POLICY}'; "
        f"$f=ConvertFrom-LinkDependentsDump -Text '{literal}'; "
        "Assert-WindowsPeDependencyPolicy -Facts $f -Policy $p"
    )
    result = _run_ps(script)
    assert result.returncode != 0
    assert bad_name.lower() in (result.stdout + result.stderr).lower()


def test_exact_policy_rejects_delay_load_runtime() -> None:
    text = _dump(json.loads(POLICY.read_text())["directImports"], ["VCRUNTIME140.dll"])
    literal = text.replace("'", "''")
    script = (
        f"Import-Module '{MODULE}' -Force; "
        f"$p=Import-WindowsPeDependencyPolicy '{POLICY}'; "
        f"$f=ConvertFrom-LinkDependentsDump -Text '{literal}'; "
        "Assert-WindowsPeDependencyPolicy -Facts $f -Policy $p"
    )
    result = _run_ps(script)
    assert result.returncode != 0
    assert "vcruntime140.dll" in (result.stdout + result.stderr).lower()


@pytest.mark.parametrize("bad_name", FORBIDDEN_CRTS)
def test_policy_cannot_bless_forbidden_crt_family(
    tmp_path: Path, bad_name: str
) -> None:
    path = tmp_path / "policy.json"
    imports = sorted(["kernel32.dll", bad_name.lower()])
    path.write_text(
        json.dumps(
            {"schemaVersion": 1, "directImports": imports, "delayLoadImports": []}
        ),
        encoding="utf-8",
    )
    result = _run_ps(
        f"Import-Module '{MODULE}' -Force; Import-WindowsPeDependencyPolicy '{path}'"
    )
    assert result.returncode != 0
    assert bad_name.lower() in (result.stdout + result.stderr).lower()


def test_policy_assertion_intrinsically_rejects_forbidden_crt() -> None:
    script = (
        f"Import-Module '{MODULE}' -Force; "
        "$f=[pscustomobject]@{directImports=[string[]]@('kernel32.dll','msvcrt.dll');"
        "delayLoadImports=[string[]]@()}; "
        "$p=[pscustomobject]@{directImports=[string[]]@('kernel32.dll','msvcrt.dll');"
        "delayLoadImports=[string[]]@()}; "
        "Assert-WindowsPeDependencyPolicy -Facts $f -Policy $p"
    )
    result = _run_ps(script)
    assert result.returncode != 0
    assert "msvcrt.dll" in (result.stdout + result.stderr).lower()


def test_exact_policy_rejects_missing_expected_import() -> None:
    imports = json.loads(POLICY.read_text())["directImports"][:-1]
    literal = _dump(imports).replace("'", "''")
    script = (
        f"Import-Module '{MODULE}' -Force; "
        f"$p=Import-WindowsPeDependencyPolicy '{POLICY}'; "
        f"$f=ConvertFrom-LinkDependentsDump -Text '{literal}'; "
        "Assert-WindowsPeDependencyPolicy -Facts $f -Policy $p"
    )
    result = _run_ps(script)
    assert result.returncode != 0
    assert "missing=[wtsapi32.dll]" in (result.stdout + result.stderr).lower()


def test_link_inspector_nonzero_fails_closed(tmp_path: Path) -> None:
    fake_link = tmp_path / "fake-link.cmd"
    fake_image = tmp_path / "fixture.exe"
    fake_link.write_text("@exit /b 7\n", encoding="ascii")
    fake_image.write_bytes(b"not-a-real-pe")
    script = (
        f"Import-Module '{MODULE}' -Force; "
        f"Get-WindowsPeDependencies -LinkPath '{fake_link}' -ImagePath '{fake_image}'"
    )
    result = _run_ps(script)
    assert result.returncode != 0
    assert "exit code 7" in (result.stdout + result.stderr).lower()


@pytest.mark.parametrize(
    "text",
    [
        "not a PE dependency dump",
        _dump([]),
        _dump(["kernel32.dll"]).replace(
            "Image has the following dependencies:",
            "Image has the following dependencies:\r\n  Image has the following dependencies:",
        ),
        _dump(["..\\evil.dll"]),
        "unexpected prefix\r\n" + _dump(["kernel32.dll"]),
        _dump(["kernel32.dll"]).replace(
            "File Type: EXECUTABLE IMAGE",
            "File Type: EXECUTABLE IMAGE\r\nunexpected middle content",
        ),
        _dump(["kernel32.dll"]).replace("\r\n        1000 .text", ""),
        _dump(["kernel32.dll"]) + "\r\n    hidden.dll",
    ],
)
def test_parser_fails_closed_on_malformed_output(text: str) -> None:
    result = _run_ps(_convert_script(text))
    assert result.returncode != 0


@pytest.mark.parametrize(
    "direct",
    [
        ["KERNEL32.dll"],
        ["user32.dll", "kernel32.dll"],
        ["kernel32.dll", "kernel32.dll"],
        ["*.dll"],
        ["subdir/kernel32.dll"],
    ],
)
def test_policy_rejects_non_normalized_or_unsafe_entries(
    tmp_path: Path, direct: list[str]
) -> None:
    path = tmp_path / "policy.json"
    path.write_text(
        json.dumps(
            {"schemaVersion": 1, "directImports": direct, "delayLoadImports": []}
        ),
        encoding="utf-8",
    )
    result = _run_ps(
        f"Import-Module '{MODULE}' -Force; Import-WindowsPeDependencyPolicy '{path}'"
    )
    assert result.returncode != 0


@pytest.mark.parametrize(
    "text",
    [
        '[{"schemaVersion":1,"directImports":["kernel32.dll"],"delayLoadImports":[]}]',
        '{"schemaVersion":"1","directImports":["kernel32.dll"],"delayLoadImports":[]}',
        '{"schemaVersion":true,"directImports":["kernel32.dll"],"delayLoadImports":[]}',
        '{"schemaVersion":1.0,"directImports":["kernel32.dll"],"delayLoadImports":[]}',
        '{"schemaVersion":1,"directImports":"kernel32.dll","delayLoadImports":[]}',
        '{"schemaVersion":1,"directImports":["kernel32.dll"],"delayLoadImports":"user32.dll"}',
        '{"schemaVersion":1,"directImports":["kernel32.dll"],"delayLoadImports":null}',
        '{"SCHEMAVERSION":1,"directImports":["kernel32.dll"],"delayLoadImports":[]}',
        '{"schemaVersion":1,"directImports":["user32.dll"],'
        '"directImports":["kernel32.dll"],"delayLoadImports":[]}',
        '{"schemaVersion":1,"directImports":["kernel32.dll"],"delayLoadImports":[],"extra":[]}',
        '{"schemaVersion":1,"directImports":["kernel32.dll"]}',
        '{"schemaVersion":1,"directImports":[],"delayLoadImports":[]}',
    ],
)
def test_policy_rejects_wrong_json_shape_or_types(tmp_path: Path, text: str) -> None:
    path = tmp_path / "policy.json"
    path.write_text(text, encoding="utf-8")
    result = _run_ps(
        f"Import-Module '{MODULE}' -Force; Import-WindowsPeDependencyPolicy '{path}'"
    )
    assert result.returncode != 0


def test_policy_accepts_exact_schema_with_reordered_properties(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    path.write_text(
        '{"delayLoadImports":[],"directImports":["kernel32.dll"],"schemaVersion":1}',
        encoding="utf-8",
    )
    result = _run_ps(
        f"Import-Module '{MODULE}' -Force; "
        f"Import-WindowsPeDependencyPolicy '{path}' | ConvertTo-Json -Compress"
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout.strip()) == {
        "schemaVersion": 1,
        "directImports": ["kernel32.dll"],
        "delayLoadImports": [],
    }


def test_policy_rejects_directory_junction_ancestor(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    policy = real / "policy.json"
    policy.write_text(
        '{"schemaVersion":1,"directImports":["kernel32.dll"],"delayLoadImports":[]}',
        encoding="utf-8",
    )
    junction = tmp_path / "policy-junction"
    script = (
        f"Import-Module '{MODULE}' -Force; "
        f"$junction=New-Item -ItemType Junction -Path '{junction}' -Target '{real}'; "
        "try { "
        f"Import-WindowsPeDependencyPolicy (Join-Path $junction.FullName 'policy.json') "
        "} finally { Remove-Item -LiteralPath $junction.FullName -Force }"
    )
    result = _run_ps(script)
    assert result.returncode != 0
    assert "reparse-point" in (result.stdout + result.stderr).lower()


def test_pe_inputs_reject_directory_junction_ancestor(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    (real / "fake-link.cmd").write_text("@exit /b 0\n", encoding="ascii")
    (real / "fixture.exe").write_bytes(b"not-a-real-pe")
    junction = tmp_path / "input-junction"
    script = (
        f"Import-Module '{MODULE}' -Force; "
        f"$junction=New-Item -ItemType Junction -Path '{junction}' -Target '{real}'; "
        "try { "
        "Get-WindowsPeDependencies "
        "-LinkPath (Join-Path $junction.FullName 'fake-link.cmd') "
        "-ImagePath (Join-Path $junction.FullName 'fixture.exe') "
        "} finally { Remove-Item -LiteralPath $junction.FullName -Force }"
    )
    result = _run_ps(script)
    assert result.returncode != 0
    assert "reparse-point" in (result.stdout + result.stderr).lower()


def test_checked_in_policy_is_sorted_unique_and_static() -> None:
    policy = json.loads(POLICY.read_text(encoding="utf-8"))
    assert policy["schemaVersion"] == 1
    assert policy["directImports"] == sorted(set(policy["directImports"]))
    assert policy["delayLoadImports"] == []
    assert all(
        "vcruntime" not in name and "api-ms-win-crt-" not in name
        for name in policy["directImports"]
    )


def test_policy_includes_rustcrypto_system_randomness_dependency() -> None:
    policy = json.loads(POLICY.read_text(encoding="utf-8"))

    assert "bcrypt.dll" in policy["directImports"]


def test_builder_enforces_gate_before_execution_and_after_signing() -> None:
    source = BUILDER.read_text(encoding="utf-8")
    helper_facts = source.index("$facts = Get-WindowsPeDependencies")
    helper_assertion = source.index(
        "Assert-WindowsPeDependencyPolicy -Facts $facts", helper_facts
    )
    helper_return = source.index("return $facts", helper_assertion)
    assert helper_facts < helper_assertion < helper_return

    built_gate = source.index("$builtPeFacts = Get-PolicyCheckedPeFacts")
    built_icon_gate = source.index("Assert-EmbeddedWindowsIcon -Path $builtExe")
    built_execution = source.index("$null = Invoke-NativeText $builtExe", built_gate)
    staged_gate = source.index(
        "$stagedPeFacts = Get-PolicyCheckedPeFacts", built_execution
    )
    staged_icon_gate = source.index("Assert-EmbeddedWindowsIcon -Path $appPath")
    staged_execution = source.index("$null = Invoke-NativeText $appPath", staged_gate)
    signed_gate = source.index(
        "$signedPeFacts = Get-PolicyCheckedPeFacts", staged_execution
    )
    signed_execution = source.index("$null = Invoke-NativeText $appPath", signed_gate)
    final_gate = source.index(
        "$finalPeFacts = Get-PolicyCheckedPeFacts", signed_execution
    )
    final_icon_gate = source.index(
        "Assert-EmbeddedWindowsIcon -Path $appPath", staged_icon_gate + 1
    )
    final_execution = source.index("$null = Invoke-NativeText $appPath", final_gate)
    assert built_gate < built_icon_gate < built_execution
    assert built_execution < staged_gate < staged_icon_gate < staged_execution
    assert (
        staged_execution
        < signed_gate
        < signed_execution
        < final_gate
        < final_icon_gate
        < final_execution
    )
    assert "peDependencyPolicySha256" in source
    assert "peDependencyVerifierSha256" in source
    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    assert config["msvcRuntimeLinkage"] == "static"
    assert "target-feature=+crt-static" in source
    # The resource compiler must reach the build. It is delivered in the child
    # process environment rather than assigned into the builder's own process,
    # so this asserts the guarantee rather than the mechanism that carries it.
    assert re.search(r"^\s*'RC'\s*=\s*\$rcPath\s*$", source, re.MULTILINE), (
        "the builder must pass RC to the build environment"
    )
    assert "Invoke-NativeTextInEnvironment -FilePath $cargoPath" in source
    assert "RC($|_)" in source


def test_parser_works_in_windows_powershell_51() -> None:
    name = str(
        Path(os.environ["WINDIR"])
        / "System32"
        / "WindowsPowerShell"
        / "v1.0"
        / "powershell.exe"
    )
    if not Path(name).exists():
        pytest.skip("Windows PowerShell 5.1 is unavailable")
    result = _run_ps(_convert_script(_dump(["KERNEL32.dll", "USER32.dll"])), name=name)
    assert result.returncode == 0, result.stderr


def test_policy_parser_is_strict_in_windows_powershell_51(tmp_path: Path) -> None:
    name = str(
        Path(os.environ["WINDIR"])
        / "System32"
        / "WindowsPowerShell"
        / "v1.0"
        / "powershell.exe"
    )
    if not Path(name).exists():
        pytest.skip("Windows PowerShell 5.1 is unavailable")
    valid = _run_ps(
        f"Import-Module '{MODULE}' -Force; Import-WindowsPeDependencyPolicy '{POLICY}'",
        name=name,
    )
    assert valid.returncode == 0, valid.stderr

    duplicate = tmp_path / "duplicate-policy.json"
    duplicate.write_text(
        '{"schemaVersion":1,"directImports":["user32.dll"],'
        '"directImports":["kernel32.dll"],"delayLoadImports":[]}',
        encoding="utf-8",
    )
    rejected = _run_ps(
        f"Import-Module '{MODULE}' -Force; Import-WindowsPeDependencyPolicy '{duplicate}'",
        name=name,
    )
    assert rejected.returncode != 0
    assert "duplicate" in (rejected.stdout + rejected.stderr).lower()
