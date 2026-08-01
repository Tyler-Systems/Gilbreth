# Maintaining Gilbreth

This is the two-minute orientation for someone taking over project work. It
describes the current repository state and points to the documents that own
each decision. Do not reconstruct current intent from closed review packets.

## Current state

| Area | State |
|---|---|
| Repository | Public, and starting from a single import commit. Development history before that import is kept in a private archive. |
| Windows x64 | Shipped. `v0.1.2` is published, signed through Azure Artifact Signing, and built from this source root. The builder, disposable-clone package proof, clean-machine marker smoke, and all four uninstall lanes are complete. |
| macOS arm64 | Application capture and dogfood are complete. Public packaging is blocked on the macOS distribution work. |
| Linux | LIN-1: ambient X11 capture (the dogfood tier) and the dashboard build and run from source, with the StatusNotifier tray, XGrabKey pause hotkey, and XDG autostart. Modal dialogs are the product's own egui shell in a child process, so confirm-gated privacy actions work; the key-content opt-in is absent rather than unprotected (no X11 password-field probe in this tier). Wayland is absent by design; there is no Linux application release lane. |

The immediate critical path is:

1. Complete the macOS distribution work before publishing a macOS package.

Packages and tags produced before the public import are historical development
artifacts. They are not republished here.

## Sources of truth

| Question | Authoritative document |
|---|---|
| What is Gilbreth, and what can someone use today? | [README](../README.md) |
| What should a maintainer read first? | This guide |
| How is a normal release prepared and published? | [Release process](RELEASE_PROCESS.md) |
| What are the current technical and privacy boundaries? | [Architecture](ARCHITECTURE.md) |
| What differs by platform? | [Capability matrix](CAPABILITY_MATRIX.md) |
| How are release artifacts verified? | [Verification guide](VERIFY.md) |
| How should a vulnerability be reported? | [Security policy](../SECURITY.md) |

These roles are deliberate: the release process owns recurring release work,
and this guide owns orientation. If two living documents disagree, fix the
disagreement in the document that owns the subject and replace stale
cross-document detail with a link.

Point-in-time evidence and closed execution records are kept in the private
development archive. They are not instructions and do not override the current
code or the living documents above.

## Common development and CI commands

Enable the repository's change-scoped local gates once per clone:

```powershell
git config core.hooksPath .githooks
```

The hooks resolve Python themselves: an activated virtualenv first, then the
repository `.venv`, then `python3`, then `python`. The interpreter no longer
has to be reachable under the bare name `python`; it only has to carry the gate
tooling (`pytest`, `black`, `ruff`), which the repo `.venv` provides. `cargo`
is still called by bare name, so the Rust toolchain must be on `PATH` for the
shell that runs `git push` or `git commit` — not merely installed. On macOS and
Linux that means `PATH="$HOME/.cargo/bin:$PATH"` with the repo `.venv` present
(or a venv activated). A shell missing the Rust toolchain fails the gate in a
way that reads like a broken hook rather than a missing tool. This applies to
`pre-commit` as well as `pre-push`.

Run the full Rust product gate:

```powershell
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo build --locked --release -p gilbreth-app --bin gilbreth-app
```

Run the verifier-host tooling gate whenever routing selects operational or
release checks. Python is required on those maintainer hosts but is never a
Gilbreth product/runtime dependency:

```powershell
python -m pip install -r scripts/requirements-dev.txt
python -m black --check scripts
python -m ruff check scripts
python -m pytest scripts/tests -q
```

For Windows development, use `cargo run -p gilbreth-app` for a console build or
`.\scripts\install-windows.ps1` for the normal installed development shape.
Launch the native dashboard directly with
`cargo run -p gilbreth-app -- --dashboard`.

For macOS TCC-sensitive dogfood, run the signed application bundle that
`scripts/make_macos_app_bundle.sh` produces, not the bare binary. A binary
launched directly from a terminal does not exercise the same TCC identity as
the app bundle, so its permission prompts and grants do not carry over.

## Product-copy rules

Enforced, not advisory: `crates/gilbreth-core/src/copy_style.rs` checks compiled
strings and `scripts/tests/test_copy_style_public_docs.py` checks the public
docs. Both name the rule they tripped, and the rule is described here.

Scope is product UI strings plus the public docs. Engineering records are
exempt — rewording a record risks drifting what it recorded.

Banned patterns:

- **Glow and buzz vocabulary** — seamless, robust, nuanced, delve, landscape,
  ecosystem, elevate, unlock, transform, leverage, game-changing,
  cutting-edge, empower. Use concrete nouns and plain verbs.
- **Importance inflation** — crucial, essential, pivotal, vital,
  comprehensive, only when actually ranking importance, which product copy
  almost never does.
- **Corporate register and nominalization stacks** — name the actor, the
  action, and the result.
- **Rhetorical negative contrast** — "not just X, it's Y".
- **Padded triples** — three items for rhythm rather than because there are
  three things.
- **Formula phrases** — "by doing X, you can Y", "at its core", "it is worth
  noting", "underscores", "let's dive in", "here's the thing", "in today's
  fast-paced world", "whether you're X or Y".
- **Hedge clouds** — state the posture; one qualifier tied to a specific
  claim is the ceiling.
- **Vague authority** — "studies show" without a citation.
- **Emoji bullets**, and arrows outside the exception below.
- **Reflexive bold-label bullets** in README and docs; keep structure only
  where it aids scanning.

Four exceptions are deliberate and allowed:

- **Factual scope contrasts.** The X-not-Y shape is fine when it states a real
  data boundary — "how much and when you type, never which keys". The
  rhetorical variant stays banned.
- **Factual enumerations of any length**, when every item names a real thing.
  The ban targets padded rhetorical triples.
- **One em dash per string**, and per paragraph in prose docs.
- **UI-path arrows in help text**, as in "tray → Privacy". Arrows stay out of
  primary captions, dialogs, and marketing copy.

Punctuation, which the same checks enforce:

- **`•` separates compound facts** in state summaries, merged gauge values,
  facts lines and chips. The middot is retired from product copy: a hyphen
  reads as minus next to numerals, and the bullet keeps dot semantics at
  legible weight.
- **The en dash is reserved for ranges.**
- **No narrative frames or anthropomorphism** — the product is a tool, not a
  storyteller.

These rules govern *style*. The tone rules govern *meaning* — value-free, no
productivity judgment, no fear copy, no causal language. A string must pass
both.

A deliberate exception gets a `// copy-allow:` comment beside the constant, or
an allowlist row in the docs test. Never a silent pass.

## Change discipline

- Preserve the no-network and local-data contract. Review capture, privacy,
  destructive paths, and database migrations with extra care.
- Keep cross-platform row meanings constant. A platform may omit an unsupported
  row kind; it must not reuse that kind with different semantics.
- **Attributes strand when you edit around them.** This codebase carries a lot
  of `#[cfg(...)]`, `#[cfg_attr(...)]`, `#[test]` and `// copy-allow:` lines,
  and each binds to whatever item follows it. Deleting an item leaves its
  attribute attached to the next one; inserting an item above another steals
  the attribute below. Both compile in many cases and surface only as a
  contradictory pair (`cfg(not(windows))` stacked on `cfg(windows)`, so the
  item exists on no platform), a duplicated `#[test]`, or a `copy-allow` that
  silently moved to a different string — a widened `cfg` predicate containing
  `"macos"` is itself a string literal and will take the allowance. Prefer
  anchoring insertions *below* an existing item, and after any deletion read
  the lines directly above and below what you removed.
- **A passing pin is not a pin.** Before claiming a test guards something,
  mutate the thing it guards and watch it fail. Tests that assert an
  after-state often pass against both the fixed and broken code because
  cleanup hides the difference; assert the step that only the fix can skip.
- Update the capability matrix whenever a platform's behavior or permission
  requirement changes.
- Use the release process for every release.
- Issues and code contributions are both open. Never merge a code pull request
  whose author has not accepted the agreement; the `contributor agreement` check
  enforces this, and overriding it is how the commercial licence gets foreclosed
  by accident. Decided 2026-07-26: a **Contributor
  Licence Agreement** based on Harmony HA-CLA v1.0 with outbound Option Five,
  individual and entity forms, so contributed work can ship under both
  AGPL-3.0-or-later and the commercial licence while contributors keep their
  copyright. Three alternatives were ruled out. A DCO only certifies the right
  to submit and grants the project nothing further. The Apache ICLA grants the
  right to *sublicense*, which is not the right to *relicense*, so it cannot
  support a commercial offering. A copyright **assignment** was chosen first and
  then reversed: 17 U.S.C. § 204(a) requires a signed writing to transfer
  ownership, and whether a pull-request comment satisfies that is settled only
  in the Fourth Circuit, so a defective signature would leave the project
  selling code it did not own. That risk does not exist for a non-exclusive
  licence, which § 204(a) does not reach. Policy is in
  [CONTRIBUTING.md](../CONTRIBUTING.md).
