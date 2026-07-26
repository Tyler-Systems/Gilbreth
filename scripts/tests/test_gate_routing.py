"""Regression coverage for the change-scoped local and hosted gates."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
PRE_PUSH = REPO_ROOT / ".githooks" / "pre-push"
PUBLIC_COPY_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "public-copy.yml"
NATIVE_CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"


def _git(*args: str, cwd: Path) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _sh() -> str:
    shell = shutil.which("sh")
    if shell:
        return shell

    git = shutil.which("git")
    assert git, "git is required to exercise the pre-push hook"
    # Git for Windows exposes git.exe through cmd/ and its POSIX shell
    # through bin/. It intentionally does not put sh.exe on PATH.
    candidate = Path(git).resolve().parent.parent / "bin" / "sh.exe"
    assert candidate.is_file(), f"could not find Git's sh.exe at {candidate}"
    return str(candidate)


def _classify(tmp_path: Path, changed_paths: list[str]) -> str:
    _git("init", "--quiet", cwd=tmp_path)
    _git("config", "user.name", "Gate Test", cwd=tmp_path)
    _git("config", "user.email", "gate-test@example.invalid", cwd=tmp_path)

    seed = tmp_path / "seed.txt"
    seed.write_text("base\n", encoding="utf-8")
    _git("add", "seed.txt", cwd=tmp_path)
    _git("commit", "--quiet", "-m", "base", cwd=tmp_path)
    base = _git("rev-parse", "HEAD", cwd=tmp_path)

    for relative in changed_paths:
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"changed: {relative}\n", encoding="utf-8")
    _git("add", "--all", cwd=tmp_path)
    _git("commit", "--quiet", "-m", "change", cwd=tmp_path)
    head = _git("rev-parse", "HEAD", cwd=tmp_path)

    env = os.environ.copy()
    env["GILBRETH_GATE_DRY_RUN"] = "1"
    result = subprocess.run(
        [_sh(), str(PRE_PUSH)],
        cwd=tmp_path,
        env=env,
        # Binary stdin preserves the LF protocol Git uses. Text-mode pipes
        # translate it to CRLF on Windows, leaving a stray CR in remote_sha.
        input=f"refs/heads/main {head} refs/heads/main {base}\n".encode(),
        check=True,
        capture_output=True,
    )
    return result.stdout.decode()


@pytest.mark.parametrize(
    ("paths", "expected"),
    [
        (["README.md"], "full=0 rust=0 operational_python=0 public_copy=1"),
        (
            ["docs/CAPABILITY_MATRIX.md"],
            "full=0 rust=0 operational_python=0 public_copy=1",
        ),
        (["SECURITY.md"], "full=0 rust=0 operational_python=0 public_copy=1"),
        (
            ["docs/MAINTAINING.md", "docs/VERIFY.md"],
            "full=0 rust=0 operational_python=0 public_copy=1",
        ),
        (
            ["docs/RELEASE_PROCESS.md", "docs/ARCHITECTURE.md"],
            "full=0 rust=0 operational_python=0 public_copy=1",
        ),
        (
            ["docs/VERIFY.md", "docs/ARCHITECTURE.md"],
            "full=0 rust=0 operational_python=0 public_copy=1",
        ),
        (
            ["crates/example/src/lib.rs"],
            "full=0 rust=1 operational_python=0 public_copy=0",
        ),
        (
            ["crates/gilbreth-core/src/copy_style.rs"],
            "full=0 rust=1 operational_python=0 public_copy=1",
        ),
        (
            ["scripts/example.py"],
            "full=0 rust=0 operational_python=1 public_copy=0",
        ),
        (
            ["README.md", "crates/example/src/lib.rs"],
            "full=0 rust=1 operational_python=0 public_copy=1",
        ),
    ],
)
def test_pre_push_routes_outgoing_changes(
    tmp_path: Path, paths: list[str], expected: str
) -> None:
    assert expected in _classify(tmp_path, paths)


def test_hosted_public_copy_lane_is_focused_and_complete() -> None:
    workflow = PUBLIC_COPY_WORKFLOW.read_text(encoding="utf-8")
    for path in [
        '"README.md"',
        '"SECURITY.md"',
        '"docs/MAINTAINING.md"',
        '"docs/RELEASE_PROCESS.md"',
        '"docs/VERIFY.md"',
        '"docs/ARCHITECTURE.md"',
        '"docs/CAPABILITY_MATRIX.md"',
        '"scripts/tests/test_copy_style_public_docs.py"',
        '"scripts/tests/test_living_document_links.py"',
        '"crates/gilbreth-core/src/copy_style.rs"',
    ]:
        # Push and PR routing both carry the same public-copy inputs.
        assert workflow.count(f"- {path}") == 2, path
    assert "python -m pytest" in workflow
    assert "scripts/tests/test_copy_style_public_docs.py" in workflow
    assert "scripts/tests/test_living_document_links.py" in workflow
    assert "cargo " not in workflow
    assert "\npermissions:\n  contents: read\n" in workflow

    push_route = workflow.split("\n  push:\n", 1)[1].split("\n  pull_request:\n", 1)[0]
    assert "branches:" not in push_route


def test_native_ci_ignores_prose_only_pushes_and_pull_requests() -> None:
    workflow = NATIVE_CI_WORKFLOW.read_text(encoding="utf-8")
    for path in ['"docs/**"', '"**.md"', '"LICENSE*"']:
        assert workflow.count(f"- {path}") == 2, path


def test_windows_ci_selects_release_toolchain_before_cache_and_gates() -> None:
    workflow = NATIVE_CI_WORKFLOW.read_text(encoding="utf-8")
    windows_job = workflow.split("\n  windows-gate:\n", 1)[1].split(
        "\n  linux-hygiene:\n", 1
    )[0]

    ordered_fragments = [
        "actions/checkout@",
        "packaging/windows/release-config.json",
        "$release.rustRelease",
        "$release.rustHost",
        "rustup toolchain install $toolchain --profile minimal --component rustfmt --component clippy",
        "rustup default $toolchain",
        "Swatinem/rust-cache@",
        "run: cargo fmt --all --check",
        "cargo clippy --locked --workspace",
        "cargo test --locked --workspace",
    ]
    positions = [windows_job.index(fragment) for fragment in ordered_fragments]

    assert positions == sorted(positions)


def test_macos_ci_is_hosted_arm64_and_runs_for_main_pushes_and_pull_requests() -> None:
    """The macOS lane is hosted arm64 and routed to main pushes and PRs only.

    Hosted macOS bills at 10x, which made this lane roughly 70% of a full run
    while being the least load-bearing: `.githooks/pre-push` already runs the
    identical native darwin gate before anything leaves the dev Mac, and the
    lane cannot compare visual baselines at all (hosted GPUs do not match a dev
    machine's rasterisation, so `CI` skips the comparison).

    The condition is pinned exactly, not merely tested for presence, because
    two properties must survive any edit: pull requests keep macOS coverage
    (the review gate), and main pushes keep it (the trunk-green record). Only
    topic-branch pushes are dropped. An `if:` that accidentally excluded PRs
    would silently remove the review gate.
    """
    workflow = NATIVE_CI_WORKFLOW.read_text(encoding="utf-8")
    event_header = workflow.split("\nenv:\n", 1)[0]
    macos_job = workflow.split("\n  macos-target:\n", 1)[1]

    assert "\n  push:\n" in event_header
    assert "\n  pull_request:\n" in event_header
    push_route = event_header.split("\n  push:\n", 1)[1].split(
        "\n  pull_request:\n", 1
    )[0]
    assert "branches:" not in push_route
    assert "runs-on: macos-15" in macos_job
    assert (
        "if: github.event_name != 'push' || github.ref == 'refs/heads/main'"
        in macos_job
    )

    ordered_fragments = [
        "actions/checkout@",
        "rustup toolchain install",
        "rustup default",
        "Swatinem/rust-cache@",
        "cargo clippy --locked --workspace --all-targets -- -D warnings",
        "cargo test --locked --workspace",
    ]
    positions = [macos_job.index(fragment) for fragment in ordered_fragments]
    assert positions == sorted(positions)


def test_workflows_cancel_superseded_runs_but_never_cancel_main() -> None:
    """Both workflows dedupe per ref, and main is never cancelled.

    Without a concurrency group two pushes in quick succession both run to
    completion even though the earlier result is discarded. Cancelling main is
    the one case that must not happen: those runs are the trunk-green record,
    so a following push must not destroy the evidence for the commit before it.
    """
    for workflow_path in (NATIVE_CI_WORKFLOW, PUBLIC_COPY_WORKFLOW):
        workflow = workflow_path.read_text(encoding="utf-8")
        assert "\nconcurrency:\n" in workflow, f"{workflow_path.name} needs a group"
        block = workflow.split("\nconcurrency:\n", 1)[1].split("\n\n", 1)[0]
        assert (
            "${{ github.ref }}" in block
        ), f"{workflow_path.name} must group per ref, not globally"
        assert (
            "cancel-in-progress: ${{ github.ref != 'refs/heads/main' }}" in block
        ), f"{workflow_path.name} must never cancel a main run"


# Workflows allowed to hold write permissions, and why. Everything absent from
# this mapping must be read-only, so adding a write-capable workflow is a
# deliberate edit here rather than something that slips in unnoticed.
WRITE_PERMITTED_WORKFLOWS = {
    "cla.yml": (
        "records contributor agreement acceptance, so it must commit the "
        "signatures file and comment on the pull request"
    ),
}


def test_public_workflows_are_read_only_sha_pinned_and_never_self_hosted() -> None:
    failures: list[str] = []
    workflow_root = REPO_ROOT / ".github" / "workflows"
    workflow_paths = sorted(
        [*workflow_root.glob("*.yml"), *workflow_root.glob("*.yaml")]
    )
    for path in workflow_paths:
        workflow = path.read_text(encoding="utf-8")
        write_allowed = path.name in WRITE_PERMITTED_WORKFLOWS
        if not write_allowed and "\npermissions:\n  contents: read\n" not in workflow:
            failures.append(f"{path.name}: missing top-level read-only permissions")
        if write_allowed:
            # A write-capable workflow still has to declare its permissions
            # explicitly. Inheriting the repository default is how a workflow
            # silently gains scope when that default is later changed.
            if not re.search(r"^permissions:$", workflow, re.MULTILINE):
                failures.append(
                    f"{path.name}: write-permitted workflow must declare "
                    "top-level permissions explicitly"
                )
            # pull_request_target plus a checkout of the pull request's own code
            # is the combination that leaks the token. Writing is tolerable;
            # writing while running contributor-supplied code is not.
            if "pull_request_target" in workflow and "actions/checkout@" in workflow:
                failures.append(
                    f"{path.name}: pull_request_target must not check out "
                    "pull request code while holding write permissions"
                )
        if re.search(r"^[ \t]+permissions:[ \t]*$", workflow, re.MULTILINE):
            failures.append(f"{path.name}: job-level permissions override is forbidden")
        for runner in re.findall(r"^[ \t]*runs-on:[ \t]*(.+)$", workflow, re.MULTILINE):
            if re.search(r"\bself-hosted\b", runner, re.IGNORECASE):
                failures.append(f"{path.name}: public workflow targets self-hosted")
        for action in re.findall(
            r"^[ \t]*-?[ \t]*uses:[ \t]*([^\s#]+)", workflow, re.MULTILINE
        ):
            revision = action.rsplit("@", 1)[-1]
            if not re.fullmatch(r"[0-9a-f]{40}", revision):
                failures.append(f"{path.name}: action is not SHA-pinned: {action}")

    assert not failures, "\n".join(failures)


def test_local_rust_gate_is_locked_and_no_php_lane_remains() -> None:
    hook = PRE_PUSH.read_text(encoding="utf-8")
    assert "cargo clippy --locked --workspace --all-targets -- -D warnings" in hook
    assert "cargo test --locked --workspace" in hook
    # site/ moved out of the repository on 2026-07-25, so the PHP lane is gone.
    assert "site/" not in hook
    assert "php -l" not in hook
