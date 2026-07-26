import hashlib
import json
import os
import re
import shutil
import subprocess
from functools import lru_cache
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
GENERATOR = ROOT / "scripts" / "windows-third-party-notices.ps1"
BUILDER = ROOT / "scripts" / "build-windows-package.ps1"
POLICY_PATH = ROOT / "packaging" / "windows" / "third-party-notices-policy.json"
INVENTORY_PATH = ROOT / "packaging" / "windows" / "third-party-inventory.json"
NOTICE_PATH = ROOT / "docs" / "THIRD-PARTY-NOTICES.md"
TARGET = "x86_64-pc-windows-msvc"


def _workspace_version() -> str:
    """The version every workspace crate inherits, read from the one place it is declared.

    Hardcoding it here means a release bump silently breaks three unrelated
    assertions, which is how it read before v0.1.1.
    """
    text = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    section = text.split("[workspace.package]", 1)[1]
    match = re.search(r'^version\s*=\s*"([^"]+)"', section, re.MULTILINE)
    assert match is not None, "workspace.package version not found in Cargo.toml"
    return match.group(1)


APP_PACKAGE_KEY = f"gilbreth-app@{_workspace_version()}"
EXPECTED_VENDOR_FALLBACKS = {
    "accesskit@0.24.1",
    "accesskit_consumer@0.35.0",
    "accesskit_windows@0.32.1",
    "accesskit_winit@0.32.2",
    "clipboard-win@5.4.1",
    "ecolor@0.35.0",
    "eframe@0.35.0",
    "egui@0.35.0",
    "egui-wgpu@0.35.0",
    "egui-winit@0.35.0",
    "emath@0.35.0",
    "epaint@0.35.0",
    "epaint_default_fonts@0.35.0",
    "gl_generator@0.14.0",
    "gpu-descriptor@0.3.2",
    "gpu-descriptor-types@0.2.0",
    "hexf-parse@0.2.1",
    "khronos_api@3.1.0",
    "profiling@1.0.18",
    "rusqlite_migration@2.6.0",
    "spirv@0.4.0+sdk-1.4.341.0",
}


def _json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _metadata() -> dict:
    result = subprocess.run(
        [
            "cargo",
            "metadata",
            "--locked",
            "--filter-platform",
            TARGET,
            "--format-version",
            "1",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


@lru_cache(maxsize=2)
def _cargo_tree_keys(edge_kinds: str) -> frozenset[str]:
    result = subprocess.run(
        [
            "cargo",
            "tree",
            "--frozen",
            "-p",
            APP_PACKAGE_KEY,
            "--target",
            TARGET,
            "-e",
            edge_kinds,
            "--color",
            "never",
            "--prefix",
            "none",
            "--format",
            "{p}",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    keys: set[str] = set()
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        match = re.fullmatch(r"([^ ]+) v([^ ]+)(?: \(.*\))?", line)
        assert match is not None, line
        keys.add(f"{match.group(1)}@{match.group(2)}")
    assert APP_PACKAGE_KEY in keys
    return frozenset(keys)


def _isolated_generator_root(
    tmp_path: Path,
    *,
    mutate_policy=None,
    mutate_metadata=None,
    tree_extra_line: str | None = None,
) -> tuple[Path, Path]:
    repository = tmp_path / "repository"
    policy = _json(POLICY_PATH)
    metadata = _metadata()

    inputs = {
        Path("Cargo.lock"),
        Path(policy["releaseConfigPath"]),
    }
    for component in policy["manualComponents"]:
        inputs.add(Path(component["noticePath"]))
        inputs.update(Path(row["path"]) for row in component.get("assetFiles", []))
    for rule in policy["packageRules"]:
        fallback = rule.get("fallback")
        if fallback and fallback["kind"] == "repo":
            inputs.add(Path(fallback["path"]))
        inputs.update(
            Path(row["repoPath"])
            for row in rule.get("extraLicenseFiles", [])
            if "repoPath" in row
        )
    for relative in inputs:
        destination = repository / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, destination)

    for package in metadata["packages"]:
        if package["source"] is not None:
            continue
        original = Path(package["manifest_path"])
        relative = original.relative_to(ROOT)
        destination = repository / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text("# metadata-only test manifest\n", encoding="utf-8")
        package["manifest_path"] = str(destination)

    if mutate_policy is not None:
        mutate_policy(policy)
    if mutate_metadata is not None:
        mutate_metadata(metadata, repository, tmp_path)

    isolated_policy = repository / "packaging/windows/third-party-notices-policy.json"
    isolated_policy.parent.mkdir(parents=True, exist_ok=True)
    isolated_policy.write_text(json.dumps(policy, indent=2) + "\n", encoding="utf-8")
    metadata_path = tmp_path / "metadata.json"
    metadata_path.write_text(json.dumps(metadata), encoding="ascii")
    normal_tree_path = tmp_path / "tree-normal.txt"
    nondev_tree_path = tmp_path / "tree-normal-build.txt"
    normal_lines = [
        f"{key.rsplit('@', 1)[0]} v{key.rsplit('@', 1)[1]}"
        for key in sorted(_cargo_tree_keys("normal"))
    ]
    nondev_lines = [
        f"{key.rsplit('@', 1)[0]} v{key.rsplit('@', 1)[1]}"
        for key in sorted(_cargo_tree_keys("normal,build"))
    ]
    if tree_extra_line is not None:
        normal_lines.append(tree_extra_line)
        nondev_lines.append(tree_extra_line)
    normal_tree_path.write_text("\n".join(normal_lines) + "\n", encoding="ascii")
    nondev_tree_path.write_text("\n".join(nondev_lines) + "\n", encoding="ascii")
    cargo_shim = tmp_path / "cargo.cmd"
    cargo_shim.write_text(
        "@echo off\r\n"
        'if /I "%1"=="metadata" (\r\n'
        f'  type "{metadata_path}"\r\n'
        "  exit /b 0\r\n"
        ")\r\n"
        'if /I "%1"=="tree" (\r\n'
        '  echo %* | %SystemRoot%\\System32\\findstr.exe /C:"normal,build" >nul\r\n'
        "  if errorlevel 1 (\r\n"
        f'    type "{normal_tree_path}"\r\n'
        "  ) else (\r\n"
        f'    type "{nondev_tree_path}"\r\n'
        "  )\r\n"
        "  exit /b 0\r\n"
        ")\r\n"
        "exit /b 2\r\n",
        encoding="ascii",
    )
    return repository, cargo_shim


def _run_isolated_generator(
    repository: Path, cargo_shim: Path
) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            shutil.which("pwsh") or "pwsh",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(GENERATOR),
            "-Mode",
            "Generate",
            "-RepositoryRoot",
            str(repository),
            "-CargoPath",
            str(cargo_shim),
        ],
        cwd=repository,
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.skipif(
    os.name != "nt",
    reason="Windows release graph includes host-resolved build dependencies",
)
def test_inventory_is_the_exact_windows_nondev_graph() -> None:
    inventory = _json(INVENTORY_PATH)
    metadata = _metadata()
    packages = {
        f"{package['name']}@{package['version']}": package
        for package in metadata["packages"]
    }
    assert len(packages) == len(metadata["packages"])

    normal = _cargo_tree_keys("normal")
    nondev = _cargo_tree_keys("normal,build")
    assert normal < nondev
    external = {
        key: "normal" if key in normal else "build-only"
        for key in nondev
        if packages[key]["source"] is not None
    }
    workspace = {key for key in nondev if packages[key]["source"] is None}
    recorded = {row["key"]: row["usage"] for row in inventory["cargoPackages"]}

    assert recorded == external
    assert {row["key"] for row in inventory["workspacePackages"]} == workspace


def test_inventory_declares_the_exact_windows_nondev_graph_contract() -> None:
    policy = _json(POLICY_PATH)
    inventory = _json(INVENTORY_PATH)
    recorded = {row["key"]: row["usage"] for row in inventory["cargoPackages"]}

    assert inventory["target"] == policy["targetTriple"] == TARGET
    assert inventory["dependencyGraph"] == {
        "resolver": "cargo-tree-package-scoped-v1",
        "package": APP_PACKAGE_KEY,
        "normalEdges": "normal",
        "nonDevEdges": "normal,build",
    }
    assert [row["key"] for row in inventory["cargoPackages"]] == sorted(
        recorded, key=lambda value: value.encode("utf-8")
    )
    assert inventory["counts"] == {
        "workspacePackages": 6,
        "externalNormalPackages": 263,
        "externalBuildOnlyPackages": 20,
        "externalNonDevPackages": 283,
        "uniqueCargoLicenseTexts": 188,
        "manualComponents": 7,
    }
    assert all(row["license"] for row in inventory["cargoPackages"])
    feature_union_only = {
        "egui_glow@0.35.0",
        "fax@0.2.7",
        "getrandom@0.3.4",
        "glifo@0.1.1",
        "glutin-winit@0.5.0",
        "glutin@0.32.3",
        "glutin_egl_sys@0.7.1",
        "jobserver@0.1.35",
        "memoffset@0.9.1",
        "quick-error@2.0.1",
        "termcolor@1.4.1",
        "tiff@0.11.3",
        "time-macros@0.2.27",
        "weezl@0.1.12",
        "winapi-util@0.1.11",
        "zune-core@0.5.1",
        "zune-jpeg@0.5.15",
    }
    assert feature_union_only.isdisjoint(recorded)


def test_generator_pins_utf8_decoding_before_reading_native_output() -> None:
    """A legacy console codepage must not be able to change what Generate produces.

    PowerShell decodes native stdout with [Console]::OutputEncoding. Without
    this pin, running the generator from an ibm437 console mojibakes non-ASCII
    crate author names, and Verify then reports the inventory as "stale or was
    edited by hand" -- an error that names the wrong cause entirely.
    """
    script = GENERATOR.read_text(encoding="utf-8")
    pin = "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)"
    assert pin in script, "generator must pin UTF-8 decoding of native output"

    first_native = min(
        script.index(marker) for marker in ("& $CargoPath", "& $Cargo ", "& $RustcPath")
    )
    assert (
        script.index(pin) < first_native
    ), "the UTF-8 pin must precede every cargo/rustc invocation it protects"


def test_inventory_pins_generator_policy_lock_and_manual_inputs() -> None:
    policy = _json(POLICY_PATH)
    inventory = _json(INVENTORY_PATH)

    assert "rootVersion" not in policy
    assert inventory["rootPackage"].startswith(f'{policy["rootPackage"]}@')
    assert inventory["generator"]["sha256"] == _sha256(GENERATOR)
    assert inventory["generator"]["policySha256"] == _sha256(POLICY_PATH)
    assert inventory["cargoLockSha256"] == _sha256(ROOT / "Cargo.lock")

    policy_components = {row["id"]: row for row in policy["manualComponents"]}
    for component in inventory["manualComponents"]:
        expected = policy_components[component["id"]]
        notice_path = ROOT / expected["noticePath"]
        assert component["noticeSha256"] == expected["noticeSha256"]
        assert component["noticeSha256"] == _sha256(notice_path)
        for asset in component["assets"]:
            assert asset["sha256"] == _sha256(ROOT / asset["path"])

    repo_inputs: list[tuple[str, str]] = []
    for rule in policy["packageRules"]:
        fallback = rule.get("fallback")
        if fallback and fallback["kind"] == "repo":
            repo_inputs.append((fallback["path"], fallback["sha256"]))
        for extra in rule.get("extraLicenseFiles", []):
            if "repoPath" in extra:
                repo_inputs.append((extra["repoPath"], extra["sha256"]))
    assert repo_inputs
    for relative, expected_hash in repo_inputs:
        assert _sha256(ROOT / relative) == expected_hash


def test_vendored_fallbacks_pin_the_exact_package_revision_and_upstream() -> None:
    policy = _json(POLICY_PATH)
    metadata = _metadata()
    packages = {f"{row['name']}@{row['version']}": row for row in metadata["packages"]}
    rules = {
        row["package"]: row
        for row in policy["packageRules"]
        if row.get("fallback") is not None
    }

    assert set(rules) == EXPECTED_VENDOR_FALLBACKS
    assert all(row["fallback"]["kind"] == "repo" for row in rules.values())
    for key, rule in rules.items():
        package = packages[key]
        package_source = rule["packageSource"]
        assert package_source["repository"] == package["repository"]
        vcs_info = _json(Path(package["manifest_path"]).parent / ".cargo_vcs_info.json")
        assert package_source["revision"] == vcs_info["git"]["sha1"]
        assert package_source["pathInVcs"] == vcs_info.get("path_in_vcs", "")

        vendored = [rule["fallback"]]
        vendored.extend(
            row for row in rule.get("extraLicenseFiles", []) if "repoPath" in row
        )
        for source in vendored:
            assert source["sourceRepository"] == package_source["primaryRepository"]
            assert source["sourceRevision"] == package_source["revision"]
            assert source["sourcePath"]

    accesskit_rules = [
        rules[key]
        for key in (
            "accesskit@0.24.1",
            "accesskit_consumer@0.35.0",
            "accesskit_windows@0.32.1",
        )
    ]
    assert all(
        any(
            row.get("sourcePath") == "LICENSE.chromium"
            for row in rule["extraLicenseFiles"]
        )
        for rule in accesskit_rules
    )
    assert "Copyright 2015 The Chromium Authors" in (
        ROOT / "packaging/windows/notices/AccessKit-LICENSE.chromium.txt"
    ).read_text(encoding="utf-8")
    assert "Copyright (c) 2018-2021 Emil Ernerfeldt" in (
        ROOT / "packaging/windows/notices/egui-LICENSE-MIT.txt"
    ).read_text(encoding="utf-8")


@pytest.mark.skipif(os.name != "nt", reason="Windows release notice gate")
@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ("revision", "packageSource does not match .cargo_vcs_info.json"),
        ("pathInVcs", "packageSource does not match .cargo_vcs_info.json"),
        ("repository", "Invalid packageSource repository or revision"),
        ("fallbackRepository", "does not match packageSource"),
        ("fallbackRevision", "does not match packageSource"),
    ],
)
def test_generator_rejects_vendored_source_provenance_mutation(
    tmp_path: Path, mutation: str, expected: str
) -> None:
    def mutate(policy: dict) -> None:
        rule = next(
            row
            for row in policy["packageRules"]
            if row["package"] == "accesskit@0.24.1"
        )
        if mutation == "revision":
            rule["packageSource"]["revision"] = "0" * 40
        elif mutation == "pathInVcs":
            rule["packageSource"]["pathInVcs"] = "wrong/path"
        elif mutation == "repository":
            rule["packageSource"]["repository"] = "https://example.invalid/repo"
        elif mutation == "fallbackRepository":
            rule["fallback"]["sourceRepository"] = "https://example.invalid/repo"
        else:
            rule["fallback"]["sourceRevision"] = "0" * 40

    repository, cargo_shim = _isolated_generator_root(tmp_path, mutate_policy=mutate)
    result = _run_isolated_generator(repository, cargo_shim)
    assert result.returncode != 0
    assert expected in result.stdout + result.stderr


@pytest.mark.skipif(os.name != "nt", reason="Windows release notice gate")
@pytest.mark.parametrize("mutation", ["nonmember", "outside-manifest"])
def test_generator_rejects_source_null_packages_outside_the_workspace(
    tmp_path: Path, mutation: str
) -> None:
    def mutate(metadata: dict, _repository: Path, outer: Path) -> None:
        package = next(
            row
            for row in metadata["packages"]
            if row["source"] is None and row["name"] == "gilbreth-app"
        )
        if mutation == "nonmember":
            metadata["workspace_members"].remove(package["id"])
        else:
            outside = outer / "outside" / "Cargo.toml"
            outside.parent.mkdir(parents=True, exist_ok=True)
            outside.write_text("# outside path dependency\n", encoding="utf-8")
            package["manifest_path"] = str(outside)

    repository, cargo_shim = _isolated_generator_root(tmp_path, mutate_metadata=mutate)
    result = _run_isolated_generator(repository, cargo_shim)
    assert result.returncode != 0
    combined = result.stdout + result.stderr
    if mutation == "nonmember":
        assert "external path dependencies are forbidden" in combined
    else:
        assert "manifest escapes RepositoryRoot" in combined


@pytest.mark.skipif(os.name != "nt", reason="Windows release notice gate")
def test_generator_rejects_unparseable_package_scoped_tree_output(
    tmp_path: Path,
) -> None:
    repository, cargo_shim = _isolated_generator_root(
        tmp_path, tree_extra_line="[unexpected cargo tree heading]"
    )
    result = _run_isolated_generator(repository, cargo_shim)
    assert result.returncode != 0
    assert "Unparseable Cargo tree (normal) output" in result.stdout + result.stderr


@pytest.mark.skipif(os.name != "nt", reason="Windows release notice gate")
@pytest.mark.parametrize(
    ("field", "expected"),
    [
        ("version", "notice version does not match release-config.json"),
        ("revision", "notice provenance does not match"),
    ],
)
def test_generator_rejects_rust_standard_library_policy_mutation(
    tmp_path: Path, field: str, expected: str
) -> None:
    def mutate(policy: dict) -> None:
        rust = next(
            row
            for row in policy["manualComponents"]
            if row["id"] == "rust-standard-library"
        )
        if field == "version":
            rust["version"] = "0.0.0"
        else:
            rust["provenance"]["revision"] = "0" * 40

    repository, cargo_shim = _isolated_generator_root(tmp_path, mutate_policy=mutate)
    result = _run_isolated_generator(repository, cargo_shim)
    assert result.returncode != 0
    assert expected in result.stdout + result.stderr


def test_all_hash_bound_text_inputs_are_lf_only() -> None:
    paths = {
        ROOT / "Cargo.lock",
        GENERATOR,
        POLICY_PATH,
        INVENTORY_PATH,
        NOTICE_PATH,
        ROOT / "crates/gilbreth-dashboard/assets/fonts/LICENSE-Inter.txt",
        ROOT / "crates/gilbreth-dashboard/assets/fonts/LICENSE-IBMPlexMono.txt",
    }
    paths.update((ROOT / "packaging/windows/notices").glob("*.txt"))
    for path in sorted(paths):
        relative = path.relative_to(ROOT).as_posix()
        attr = subprocess.run(
            ["git", "check-attr", "eol", "--", relative],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        assert attr.stdout.strip().endswith(": eol: lf"), attr.stdout
        assert b"\r" not in path.read_bytes(), relative


def test_notice_covers_embedded_font_sqlite_and_installer_edges() -> None:
    inventory = _json(INVENTORY_PATH)
    notice = NOTICE_PATH.read_text(encoding="utf-8")
    packages = {row["key"]: row for row in inventory["cargoPackages"]}
    components = {row["id"] for row in inventory["manualComponents"]}

    assert NOTICE_PATH.read_bytes().startswith(b"# Third-party notices\n")
    assert b"\r" not in NOTICE_PATH.read_bytes()
    assert all(
        line == line.rstrip(b" \t") for line in NOTICE_PATH.read_bytes().splitlines()
    )
    assert all(f"`{key}`" in notice for key in packages)
    assert len(packages["epaint_default_fonts@0.35.0"]["embeddedAssets"]) == 4
    assert "NotoEmoji-NOTICE.txt" in notice
    assert "Copyright 2015 The Chromium Authors" in notice
    assert "Copyright (c) 2018-2021 Emil Ernerfeldt" in notice
    assert "Ubuntu-Light.ttf` by [Dalton Maag]" in notice
    assert "shared fallback for" not in notice
    assert {
        "inter-fonts",
        "ibm-plex-mono-font",
        "rust-standard-library",
        "inno-setup-runtime",
        "lzma-sdk",
        "sqlite",
        "microsoft-runtime",
    } == components
    self_cell_sources = {
        item["source"] for item in packages["self_cell@1.2.2"]["licenseFiles"]
    }
    assert all("GPL" not in source for source in self_cell_sources)
    assert "uses the Apache-2.0 option for `self_cell`" in notice
    assert "Copyright notices for The Rust Standard Library" in notice


def test_sqlite_and_lzma_versions_are_derived_from_pinned_release_inputs() -> None:
    policy = _json(POLICY_PATH)
    release = _json(ROOT / "packaging/windows/release-config.json")
    components = {row["id"]: row for row in policy["manualComponents"]}
    rules = {row["package"]: row for row in policy["packageRules"]}
    metadata = _metadata()
    packages = {f"{row['name']}@{row['version']}": row for row in metadata["packages"]}

    sqlite_rule = rules["libsqlite3-sys@0.38.0"]
    header_asset = next(
        row
        for row in sqlite_rule["embeddedAssets"]
        if row["path"] == "sqlite3/sqlite3.h"
    )
    sqlite_root = Path(packages["libsqlite3-sys@0.38.0"]["manifest_path"]).parent
    sqlite_header = sqlite_root / header_asset["path"]
    assert _sha256(sqlite_header) == header_asset["sha256"]
    version_line = next(
        line
        for line in sqlite_header.read_text(encoding="utf-8").splitlines()
        if line.startswith("#define SQLITE_VERSION ")
    )
    derived_version = version_line.split('"', 2)[1]
    assert components["sqlite"]["version"] == derived_version

    expected_inno = release["innoSetupVersion"]
    assert components["inno-setup-runtime"]["version"] == expected_inno
    assert components["lzma-sdk"]["version"] == f"Inno Setup {expected_inno} component"
    assert components["lzma-sdk"]["relationship"] == (
        "installer LZMA2 compression/decompression code"
    )


@pytest.mark.skipif(os.name != "nt", reason="Windows release notice gate")
def test_rust_standard_library_notice_matches_the_pinned_toolchain() -> None:
    policy = _json(POLICY_PATH)
    release = _json(ROOT / "packaging/windows/release-config.json")
    component = next(
        row
        for row in policy["manualComponents"]
        if row["id"] == "rust-standard-library"
    )
    rustc_version = subprocess.run(
        ["rustc", "-Vv"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    facts = dict(
        line.split(": ", 1) for line in rustc_version.splitlines() if ": " in line
    )
    assert facts["release"] == component["version"] == release["rustRelease"]
    assert (
        facts["commit-hash"]
        == component["provenance"]["revision"]
        == release["rustCommit"]
    )
    assert facts["host"] == release["rustHost"] == TARGET
    sysroot = Path(
        subprocess.run(
            ["rustc", "--print", "sysroot"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    )
    toolchain_notice = sysroot / component["provenance"]["toolchainPath"]
    vendored_notice = ROOT / component["noticePath"]
    assert component["provenance"]["repository"] == (
        "https://github.com/rust-lang/rust"
    )
    assert component["noticeSha256"] == _sha256(toolchain_notice)
    assert component["noticeSha256"] == _sha256(vendored_notice)
    notice_text = vendored_notice.read_text(encoding="utf-8")
    assert "Copyright notices for The Rust Standard Library" in notice_text
    assert "Rust Standard Library is dual-licensed under Apache 2.0 and MIT" in (
        notice_text
    )


def test_public_package_builder_fails_closed_on_notice_drift() -> None:
    builder = BUILDER.read_text(encoding="utf-8")
    allowlist = _json(ROOT / "packaging" / "windows" / "package-allowlist.json")

    assert "Assert-GitTracked $thirdPartyGeneratorRelative" in builder
    assert "Assert-GitTracked $thirdPartyPolicyRelative" in builder
    assert "Assert-GitTracked $thirdPartyInventoryRelative" in builder
    assert "Assert-GitTracked $thirdPartyNoticeRelative" in builder
    assert "& $thirdPartyGeneratorPath -Mode Verify" in builder
    assert "-CargoPath $cargoPath -RustcPath $rustcPath" in builder
    assert "thirdPartyNoticeGeneratorSha256" in builder
    assert "thirdPartyNoticePolicySha256" in builder
    assert "thirdPartyInventorySha256" in builder
    assert "thirdPartyNoticeSha256" in builder
    assert (
        "$assetFilesProperty = $component.PSObject.Properties['assetFiles']" in builder
    )
    assert "[void]$manualNoticeInputs.Add([string]$asset.path)" in builder
    assert any(
        row["source"] == "docs/THIRD-PARTY-NOTICES.md"
        and row["destination"] == "THIRD-PARTY-NOTICES.md"
        for row in allowlist["entries"]
    )


@pytest.mark.skipif(os.name != "nt", reason="Windows release notice gate")
@pytest.mark.parametrize("engine", ["pwsh", "powershell"])
def test_checked_in_outputs_verify_in_both_powershell_engines(engine: str) -> None:
    shell = shutil.which(engine)
    if shell is None:
        pytest.skip(f"{engine} is unavailable")
    result = subprocess.run(
        [
            shell,
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(GENERATOR),
            "-Mode",
            "Verify",
            "-RepositoryRoot",
            str(ROOT),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "263 normal, 20 build-only, 188 unique Cargo texts" in result.stdout


@pytest.mark.skipif(os.name != "nt", reason="Windows release notice gate")
@pytest.mark.parametrize("engine", ["pwsh", "powershell"])
def test_checked_in_outputs_verify_under_turkish_culture(engine: str) -> None:
    shell = shutil.which(engine)
    if shell is None:
        pytest.skip(f"{engine} is unavailable")
    command = (
        "& { "
        "[Globalization.CultureInfo]::CurrentCulture = 'tr-TR'; "
        "[Globalization.CultureInfo]::CurrentUICulture = 'tr-TR'; "
        f"& '{GENERATOR}' -Mode Verify -RepositoryRoot '{ROOT}'; "
        "if (-not $?) { exit 1 } "
        "}"
    )
    result = subprocess.run(
        [shell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "263 normal, 20 build-only, 188 unique Cargo texts" in result.stdout


@pytest.mark.skipif(os.name != "nt", reason="Windows release notice gate")
def test_absolute_canonical_policy_path_is_accepted() -> None:
    result = subprocess.run(
        [
            shutil.which("pwsh") or "pwsh",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(GENERATOR),
            "-Mode",
            "Verify",
            "-RepositoryRoot",
            str(ROOT),
            "-PolicyPath",
            str(POLICY_PATH.resolve()),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.skipif(os.name != "nt", reason="Windows release notice gate")
@pytest.mark.parametrize("mode", ["Verify", "Generate"])
def test_external_policy_path_is_rejected_without_overwriting_outputs(
    tmp_path: Path, mode: str
) -> None:
    external = tmp_path / "third-party-notices-policy.json"
    external.write_bytes(POLICY_PATH.read_bytes())
    before = (_sha256(INVENTORY_PATH), _sha256(NOTICE_PATH))
    result = subprocess.run(
        [
            shutil.which("pwsh") or "pwsh",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(GENERATOR),
            "-Mode",
            mode,
            "-RepositoryRoot",
            str(ROOT),
            "-PolicyPath",
            str(external),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "must resolve to the canonical repository policy" in (
        result.stdout + result.stderr
    )
    assert before == (_sha256(INVENTORY_PATH), _sha256(NOTICE_PATH))
