"""Lane B enforcement for the public docs (README + the
README-linked capability matrix): the same banned patterns the compiled
copy audits apply, greppable in CI (docs/MAINTAINING.md
Product-copy rules).

The needle lists are parsed out of ``crates/gilbreth-core/src/copy_style.rs``
so the two checkers cannot drift apart. The allowlist convention matches
the compiled one: a deliberate exception is either an in-file
``<!-- copy-allow: <rule-id> <reason> -->`` comment on the line above, or
(for table rows, where a comment would break the table) an exact-snippet
entry in ``RECORDED_SNIPPET_ALLOWS`` below citing the ruling. A recorded
snippet that disappears from its file fails the freshness test, so the
exception record cannot outlive the exception.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
COPY_STYLE_RS = REPO_ROOT / "crates" / "gilbreth-core" / "src" / "copy_style.rs"

PUBLIC_DOCS = [
    REPO_ROOT / "README.md",
    REPO_ROOT / "docs" / "CAPABILITY_MATRIX.md",
]

# Keep in sync with copy_style::rule_row (the needles themselves are
# parsed from the Rust source; these are stable document pointers).
RULE_ROWS = {
    "glow-vocabulary": "docs/MAINTAINING.md, Product-copy rules (glow and buzz vocabulary)",
    "importance-inflation": "docs/MAINTAINING.md, Product-copy rules (importance inflation)",
    "formula-phrase": "docs/MAINTAINING.md, Product-copy rules (formula phrases)",
    "negative-contrast": (
        "docs/MAINTAINING.md, Product-copy rules (rhetorical negative contrast; "
        "factual scope contrasts are the recorded exception)"
    ),
    "narrative-frame": "docs/MAINTAINING.md, Product-copy rules (tool-not-story)",
    "em-dash": (
        "docs/MAINTAINING.md, Product-copy rules (one em dash per string; "
        "per paragraph in prose docs)"
    ),
    "en-dash": "docs/MAINTAINING.md, Product-copy rules (en dash reserved for ranges)",
    "middot-separator": "docs/MAINTAINING.md, Product-copy rules (the bullet replaced the middot)",
    "arrow": (
        "docs/MAINTAINING.md, Product-copy rules (arrows; UI-path arrows in help text are the "
        "recorded exception)"
    ),
}

# Recorded rulings for whole pattern classes (Lane A execution record and
# the Lane B sweep), applied as strips before the char checks:
# - milestone-name dashes ("**M5a — Capture completeness**") are shared
#   identifiers, not prose (Lane A ruling);
# - bare "—" table cells are missing-value data notation (the UX-10
#   family, Lane B seeded exception);
# - en dashes joining alphanumeric range endpoints ("M0–M5", "§5–8") are
#   the range separator itself (TYPE_RAMP decision 4).
MILESTONE_IDENTIFIER = re.compile(r"\*\*M\d+[a-z]?(?:/[A-Za-z0-9]+)? — [^*]+\*\*")
# A cell-leading "—" is the missing-value marker whether the cell ends
# there ("| — |") or a parenthetical note follows ("| — (no analog; …)").
BARE_CELL = re.compile(r"\|\s*—\s*(?=[|(])")
RANGE_EN_DASH = re.compile(r"(?<=[A-Za-z0-9§])–(?=[A-Za-z0-9])")
STYLE_OR_SCRIPT = re.compile(r"<(style|script)\b.*?</\1>", re.DOTALL | re.IGNORECASE)

# Exact-snippet allows for table rows, where an HTML comment would break
# the table. Each entry: (file name, snippet, rule id, recorded reason).
RECORDED_SNIPPET_ALLOWS = [
    (
        "CAPABILITY_MATRIX.md",
        "fast-user-switch → `console` kind",
        "arrow",
        "schema-kind mapping notation in a matrix cell (Lane B ruling: data notation, not prose)",
    ),
    (
        "CAPABILITY_MATRIX.md",
        "`battery_saver` ← Low Power Mode",
        "arrow",
        "schema-kind mapping notation in a matrix cell (Lane B ruling: data notation, not prose)",
    ),
    (
        "CAPABILITY_MATRIX.md",
        "## Permission ↔ capability map (macOS)",
        "arrow",
        "bidirectional mapping notation in a heading (Lane B ruling: data notation, not prose)",
    ),
]

ALLOW_COMMENT = re.compile(
    r"<!--\s*copy-allow:\s*(?P<rule>[a-z-]+)\s+(?P<reason>[^>]+?)\s*-->"
)
ALLOW_MARKER = re.compile(r"<!--\s*copy-allow:")

HTML_ENTITIES = {
    "&mdash;": "—",
    "&#8212;": "—",
    "&ndash;": "–",
    "&#8211;": "–",
    "&middot;": "·",
    "&#183;": "·",
    "&bull;": "•",
    "&rarr;": "→",
    "&larr;": "←",
    "&rsquo;": "'",
    "&#8217;": "'",
}


def _rust_needle_list(name: str) -> list[str]:
    source = COPY_STYLE_RS.read_text(encoding="utf-8")
    match = re.search(
        rf"pub const {name}: &\[&str\] =\s*&\[(?P<body>.*?)\];", source, re.DOTALL
    )
    assert match, f"{name} not found in {COPY_STYLE_RS}"
    needles = re.findall(r'"([^"]+)"', match.group("body"))
    assert needles, f"{name} parsed empty — the shared law moved?"
    return needles


def _rust_arrow_chars() -> list[str]:
    source = COPY_STYLE_RS.read_text(encoding="utf-8")
    match = re.search(
        r"pub const ARROW_CHARS: &\[char\] =\s*&\[(?P<body>.*?)\];", source, re.DOTALL
    )
    assert match, f"ARROW_CHARS not found in {COPY_STYLE_RS}"
    return [
        chr(int(code, 16))
        for code in re.findall(r"'\\u\{([0-9A-Fa-f]+)\}'", match.group("body"))
    ]


def _normalized(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".html":
        # CSS and JS are code, not copy (`text-transform:`, `Promise`,
        # …); blank the blocks so line numbers stay stable.
        text = STYLE_OR_SCRIPT.sub(lambda m: "\n" * m.group(0).count("\n"), text)
    for entity, char in HTML_ENTITIES.items():
        text = text.replace(entity, char)
    return text.replace("’", "'")


def _line_allows(lines: list[str], index: int) -> set[str]:
    """Rule ids granted to line `index` by a copy-allow comment above it
    (or inline on the same line)."""
    granted: set[str] = set()
    for probe in (index - 1, index):
        if 0 <= probe < len(lines):
            for match in ALLOW_COMMENT.finditer(lines[probe]):
                granted.add(match.group("rule"))
    return granted


def _vocabulary_rules() -> dict[str, list[str]]:
    return {
        "glow-vocabulary": _rust_needle_list("GLOW_VOCABULARY"),
        "importance-inflation": _rust_needle_list("IMPORTANCE_INFLATION"),
        "formula-phrase": _rust_needle_list("FORMULA_PHRASES"),
        "negative-contrast": _rust_needle_list("NEGATIVE_CONTRAST_MARKERS"),
        "narrative-frame": _rust_needle_list("NARRATIVE_FRAME_MARKERS"),
    }


def _rule_fires_on_line(path: Path, line: str, rule: str) -> bool:
    """Whether a comment grant suppresses a real hit on its target line."""
    line = ALLOW_COMMENT.sub("", line)
    if rule in _vocabulary_rules():
        return any(
            re.search(
                rf"(?<![A-Za-z0-9]){re.escape(needle)}(?![A-Za-z0-9])",
                line,
                re.IGNORECASE,
            )
            for needle in _vocabulary_rules()[rule]
        )
    if rule == "em-dash":
        # Public-doc em-dash grants waive the per-item over-budget hit.
        return line.count("—") > 1
    if rule == "en-dash":
        return "–" in RANGE_EN_DASH.sub("-", line)
    if rule == "middot-separator":
        return "·" in line
    if rule == "arrow":
        return any(char in line for char in _rust_arrow_chars())
    raise AssertionError(f"unhandled public-copy rule: {rule} in {path}")


def _rule_fires_on_target(path: Path, lines: list[str], target: int, rule: str) -> bool:
    if rule != "em-dash":
        return _rule_fires_on_line(path, lines[target], rule)

    text = "\n".join(lines)
    text = MILESTONE_IDENTIFIER.sub("", text)
    text = BARE_CELL.sub("| ", text)
    for start, item in _items(text, is_html=path.suffix == ".html"):
        item_start = start - 1
        item_end = item_start + item.count("\n")
        if item_start <= target <= item_end:
            return item.count("—") > 1
    return False


def _allow_comment_failures(path: Path, text: str) -> list[str]:
    """Reject malformed, unknown, orphaned, and stale in-file grants."""
    lines = text.splitlines()
    failures: list[str] = []
    for index, line in enumerate(lines):
        if not ALLOW_MARKER.search(line):
            continue
        matches = list(ALLOW_COMMENT.finditer(line))
        if not matches:
            failures.append(
                f"{path.name}:{index + 1} malformed copy-allow; expected "
                "<!-- copy-allow: <rule-id> <reason> -->"
            )
            continue
        for match in matches:
            rule = match.group("rule")
            if rule not in RULE_ROWS:
                failures.append(
                    f"{path.name}:{index + 1} copy-allow names unknown rule {rule!r}"
                )
                continue
            if not match.group("reason").strip():
                failures.append(
                    f"{path.name}:{index + 1} copy-allow for {rule!r} needs a reason"
                )
                continue

            # Inline comments grant their own prose line. A comment-only
            # line grants the immediately following line, matching
            # _line_allows and keeping exceptions visibly beside the copy.
            own_copy = ALLOW_COMMENT.sub("", line).strip()
            target = index if own_copy else index + 1
            if target >= len(lines):
                failures.append(
                    f"{path.name}:{index + 1} orphaned copy-allow has no target line"
                )
            elif not _rule_fires_on_target(path, lines, target, rule):
                failures.append(
                    f"{path.name}:{index + 1} stale copy-allow for {rule!r}; "
                    "the granted rule does not fire on its target line"
                )
    return failures


def _strip_recorded_snippets(path: Path, line: str, rule: str) -> str:
    for file_name, snippet, snippet_rule, _reason in RECORDED_SNIPPET_ALLOWS:
        if snippet_rule == rule and path.name == file_name:
            line = line.replace(snippet, "")
    return line


def _recorded_allow_definition_failures(
    entries: list[tuple[str, str, str, str]],
) -> list[str]:
    failures = []
    for file_name, snippet, rule, reason in entries:
        if rule not in RULE_ROWS:
            failures.append(
                f"recorded allow for {file_name} names unknown rule {rule!r}"
            )
            continue
        if not reason.strip():
            failures.append(
                f"recorded allow for {snippet!r} in {file_name} needs a reason"
            )
        if not _rule_fires_on_line(Path(file_name), snippet, rule):
            failures.append(
                f"stale recorded allow: {snippet!r} no longer fires {rule!r}"
            )
    return failures


def _items(text: str, is_html: bool = False) -> list[tuple[int, str]]:
    """Prose items for the em-dash budget: a table row or list item is
    its own item; wrapped list items merge with their continuations;
    plain paragraphs split on blank lines. HTML has no markdown
    paragraphs, so each line is its own item there. Returns (1-based
    start line, item text)."""
    lines = text.splitlines()
    items: list[tuple[int, str]] = []
    current_start: int | None = None
    current: list[str] = []
    item_marker = re.compile(r"^\s*(?:[-*+]\s+|\d+\.\s+|\|)")

    if is_html:
        return [
            (number, line) for number, line in enumerate(lines, start=1) if line.strip()
        ]

    def flush() -> None:
        nonlocal current_start, current
        if current:
            items.append((current_start or 1, "\n".join(current)))
        current_start, current = None, []

    for number, line in enumerate(lines, start=1):
        if not line.strip():
            flush()
            continue
        if item_marker.match(line):
            flush()
            current_start, current = number, [line]
            continue
        if current:
            current.append(line)
        else:
            current_start, current = number, [line]
    flush()
    return items


def test_public_docs_avoid_the_banned_vocabulary() -> None:
    rules = _vocabulary_rules()
    failures = []
    for path in PUBLIC_DOCS:
        lines = _normalized(path).splitlines()
        for number, line in enumerate(lines, start=1):
            granted = _line_allows(lines, number - 1)
            for rule, needles in rules.items():
                if rule in granted:
                    continue
                for needle in needles:
                    if re.search(
                        rf"(?<![A-Za-z0-9]){re.escape(needle)}(?![A-Za-z0-9])",
                        line,
                        re.IGNORECASE,
                    ):
                        failures.append(
                            f"{path.name}:{number} banned term {needle!r} — {RULE_ROWS[rule]}"
                        )
    assert not failures, "\n".join(failures)


def test_public_docs_respect_the_em_dash_budget() -> None:
    failures = []
    for path in PUBLIC_DOCS:
        text = _normalized(path)
        text = MILESTONE_IDENTIFIER.sub("", text)
        text = BARE_CELL.sub("| ", text)
        lines = text.splitlines()
        for start, item in _items(text, is_html=path.suffix == ".html"):
            if "em-dash" in _line_allows(lines, start - 1):
                continue
            count = item.count("—")
            if count > 1:
                failures.append(
                    f"{path.name}:{start} {count} em dashes in one item/paragraph "
                    f"(budget is one) — {RULE_ROWS['em-dash']}"
                )
    assert not failures, "\n".join(failures)


def test_public_docs_use_the_bullet_separator_not_the_middot() -> None:
    failures = []
    for path in PUBLIC_DOCS:
        lines = _normalized(path).splitlines()
        for number, line in enumerate(lines, start=1):
            if "·" in line and "middot-separator" not in _line_allows(
                lines, number - 1
            ):
                failures.append(
                    f"{path.name}:{number} middot separator — {RULE_ROWS['middot-separator']}"
                )
    assert not failures, "\n".join(failures)


def test_public_docs_arrows_are_recorded_exceptions_only() -> None:
    arrows = _rust_arrow_chars()
    failures = []
    for path in PUBLIC_DOCS:
        lines = _normalized(path).splitlines()
        for number, line in enumerate(lines, start=1):
            if "arrow" in _line_allows(lines, number - 1):
                continue
            stripped = _strip_recorded_snippets(path, line, "arrow")
            found = [ch for ch in arrows if ch in stripped]
            if found:
                failures.append(
                    f"{path.name}:{number} arrow {found[0]!r} — {RULE_ROWS['arrow']}"
                )
    assert not failures, "\n".join(failures)


def test_public_docs_en_dashes_are_ranges_only() -> None:
    failures = []
    for path in PUBLIC_DOCS:
        text = RANGE_EN_DASH.sub("-", _normalized(path))
        lines = text.splitlines()
        for number, line in enumerate(lines, start=1):
            if "–" in line and "en-dash" not in _line_allows(lines, number - 1):
                failures.append(
                    f"{path.name}:{number} non-range en dash — {RULE_ROWS['en-dash']}"
                )
    assert not failures, "\n".join(failures)


def test_recorded_snippet_allows_stay_fresh() -> None:
    """The docs twin of the compiled stale-allow rule: an exact-snippet
    exception whose snippet no longer exists must leave the list."""
    failures = []
    for file_name, snippet, rule, reason in RECORDED_SNIPPET_ALLOWS:
        matches = [path for path in PUBLIC_DOCS if path.name == file_name]
        assert matches, f"allowlist names an unknown public doc: {file_name}"
        if not any(snippet in _normalized(path) for path in matches):
            failures.append(
                f"stale recorded allow: {snippet!r} ({rule}: {reason}) no longer "
                f"appears in {file_name}"
            )
    assert not failures, "\n".join(failures)


def test_public_doc_allow_comments_are_known_and_fresh() -> None:
    failures = _recorded_allow_definition_failures(RECORDED_SNIPPET_ALLOWS)
    for path in PUBLIC_DOCS:
        failures.extend(_allow_comment_failures(path, _normalized(path)))
    assert not failures, "\n".join(failures)


def test_recorded_allow_validation_rejects_unknown_stale_and_reasonless_entries() -> (
    None
):
    failures = _recorded_allow_definition_failures(
        [
            ("fixture.md", "→", "invented-rule", "recorded reason"),
            ("fixture.md", "ordinary copy", "arrow", "recorded reason"),
            ("fixture.md", "→", "arrow", ""),
        ]
    )
    assert any("unknown rule 'invented-rule'" in failure for failure in failures)
    assert any("no longer fires 'arrow'" in failure for failure in failures)
    assert any("needs a reason" in failure for failure in failures)


def test_allow_comment_validation_rejects_unknown_and_stale_grants() -> None:
    path = Path("fixture.md")
    failures = _allow_comment_failures(
        path,
        "\n".join(
            [
                "<!-- copy-allow: invented-rule recorded reason -->",
                "ordinary copy",
                "<!-- copy-allow: arrow recorded reason -->",
                "still ordinary copy",
                "<!-- copy-allow: arrow    -->",
                "path → target",
            ]
        ),
    )
    assert any("unknown rule 'invented-rule'" in failure for failure in failures)
    assert any("stale copy-allow for 'arrow'" in failure for failure in failures)
    assert any(
        "copy-allow for 'arrow' needs a reason" in failure for failure in failures
    )


def test_em_dash_allow_freshness_uses_the_whole_markdown_item() -> None:
    failures = _allow_comment_failures(
        Path("fixture.md"),
        "\n".join(
            [
                "<!-- copy-allow: em-dash recorded two-dash paragraph exception -->",
                "A paragraph with one — mark",
                "and a second — mark on its wrapped continuation.",
            ]
        ),
    )
    assert not failures
