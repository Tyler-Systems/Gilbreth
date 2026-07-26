"""Keep the public maintainer and release path navigable from the README.

This is intentionally an offline link check. Remote URLs are allowed but are
not fetched; repository-local Markdown links must resolve in the checked-out
tree.
"""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import unquote, urlsplit

REPO_ROOT = Path(__file__).resolve().parents[2]

LIVING_DOCUMENTS = [
    REPO_ROOT / "README.md",
    REPO_ROOT / "SECURITY.md",
    REPO_ROOT / "docs" / "MAINTAINING.md",
    REPO_ROOT / "docs" / "RELEASE_PROCESS.md",
    REPO_ROOT / "docs" / "VERIFY.md",
    REPO_ROOT / "docs" / "ARCHITECTURE.md",
    REPO_ROOT / "docs" / "CAPABILITY_MATRIX.md",
]

README_DESTINATIONS = {
    "SECURITY.md",
    "docs/MAINTAINING.md",
    "docs/RELEASE_PROCESS.md",
    "docs/VERIFY.md",
    "docs/ARCHITECTURE.md",
    "docs/CAPABILITY_MATRIX.md",
}

INLINE_LINK = re.compile(
    r"!?\[[^\]]*\]\(\s*(?P<target><[^>]+>|[^\s)]+)"
    r"(?:\s+(?:\"[^\"]*\"|'[^']*'|\([^)]*\)))?\s*\)"
)
REFERENCE_LINK = re.compile(
    r"^\s{0,3}\[[^\]]+\]:\s*(?P<target><[^>]+>|\S+)", re.MULTILINE
)
HTML_LINK = re.compile(r"\b(?:href|src)=[\"'](?P<target>[^\"']+)[\"']")
HEADING = re.compile(r"^\s{0,3}#{1,6}\s+(?P<text>.+?)\s*#*\s*$", re.MULTILINE)
EXPLICIT_ID = re.compile(r"\b(?:id|name)=[\"'](?P<id>[^\"']+)[\"']", re.IGNORECASE)


def _targets(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    targets = [match.group("target") for match in INLINE_LINK.finditer(text)]
    targets.extend(match.group("target") for match in REFERENCE_LINK.finditer(text))
    targets.extend(match.group("target") for match in HTML_LINK.finditer(text))
    return [target[1:-1] if target.startswith("<") else target for target in targets]


def _local_path(source: Path, target: str) -> Path | None:
    parsed = urlsplit(target)
    if parsed.scheme or parsed.netloc or parsed.path.startswith("/"):
        return None
    if not parsed.path:
        return source.resolve() if parsed.fragment else None

    relative = Path(unquote(parsed.path.replace("\\", "/")))
    return (source.parent / relative).resolve()


def _github_anchors(path: Path) -> set[str]:
    text = path.read_text(encoding="utf-8")
    anchors = {unquote(match.group("id")) for match in EXPLICIT_ID.finditer(text)}
    seen: dict[str, int] = {}
    for match in HEADING.finditer(text):
        heading = re.sub(r"!?\[([^\]]+)\]\([^)]*\)", r"\1", match.group("text"))
        heading = re.sub(r"<[^>]+>", "", heading)
        heading = heading.replace("`", "").replace("*", "")
        base = "".join(
            char
            for char in heading.strip().lower()
            if char.isalnum() or char in {" ", "-", "_"}
        ).replace(" ", "-")
        duplicate = seen.get(base, 0)
        seen[base] = duplicate + 1
        anchors.add(base if duplicate == 0 else f"{base}-{duplicate}")
    return anchors


def test_living_documents_exist_and_local_links_resolve() -> None:
    failures: list[str] = []
    root = REPO_ROOT.resolve()

    for source in LIVING_DOCUMENTS:
        if not source.is_file():
            failures.append(f"missing living document: {source.relative_to(REPO_ROOT)}")
            continue

        for target in _targets(source):
            destination = _local_path(source, target)
            if destination is None:
                continue
            try:
                destination.relative_to(root)
            except ValueError:
                failures.append(
                    f"{source.relative_to(REPO_ROOT)}: local link escapes repository: "
                    f"{target}"
                )
                continue
            if not destination.exists():
                failures.append(
                    f"{source.relative_to(REPO_ROOT)}: broken local link: {target}"
                )
                continue
            fragment = unquote(urlsplit(target).fragment)
            if (
                fragment
                and destination.is_file()
                and destination.suffix.lower() == ".md"
            ):
                if fragment not in _github_anchors(destination):
                    failures.append(
                        f"{source.relative_to(REPO_ROOT)}: unknown local anchor: {target}"
                    )

    assert not failures, "\n".join(failures)


def test_readme_links_every_living_source_of_truth() -> None:
    linked = {
        Path(unquote(urlsplit(target).path)).as_posix()
        for target in _targets(REPO_ROOT / "README.md")
        if _local_path(REPO_ROOT / "README.md", target) is not None
    }
    missing = sorted(README_DESTINATIONS - linked)
    assert not missing, "README is missing canonical links: " + ", ".join(missing)


def test_newcomer_orientation_links_to_archive_index_only() -> None:
    failures: list[str] = []
    archive_root = (REPO_ROOT / "docs" / "archive").resolve()
    archive_index = (archive_root / "README.md").resolve()

    for source in [REPO_ROOT / "README.md", REPO_ROOT / "docs" / "MAINTAINING.md"]:
        for target in _targets(source):
            destination = _local_path(source, target)
            if destination is None:
                continue
            try:
                destination.relative_to(archive_root)
            except ValueError:
                continue
            if destination != archive_index:
                failures.append(
                    f"{source.relative_to(REPO_ROOT)} links directly to archived "
                    f"execution evidence: {target}"
                )

    assert not failures, "\n".join(failures)
