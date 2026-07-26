# Local CI gate (git hooks)

These hooks run the same native-product, public-copy, and operational-tooling
checks used by hosted CI before code is committed or pushed.

- **pre-commit** (fast): always runs `cargo fmt --all --check`. When staged
  `scripts/**/*.py` files changed, it also runs Black and Ruff over `scripts/`.
- **pre-push** (change-scoped): diffs what the push actually sends and runs
  only the relevant gate:

  | Outgoing changes | Gates |
  |---|---|
  | `README.md`, `SECURITY.md`, and the living maintainer/release docs | focused public-copy and link audit |
  | other `docs/**`, `*.md`, `LICENSE*` only | none (prose exit) |
  | `scripts/**`, `pytest.ini` | Black, Ruff, `pytest scripts/tests` |
  | `crates/gilbreth-core/src/copy_style.rs` | focused public-copy audit plus Cargo gates |
  | `crates/**`, `Cargo.toml`, `Cargo.lock` | Cargo fmt, warning-denied Clippy, workspace tests |
  | anything else, new refs, or undiffable bases | both gates, fail-safe |

Rust-only changes no longer invoke a Python parity oracle. Python is required
on maintainer and release hosts when the routing table selects operational
checks; it is not a product or dashboard runtime dependency. The operational
suite includes one Windows cross-check against the development-only native
health-dump binary.

`GILBRETH_GATE_DRY_RUN=1` prints the pre-push classification and exits without
running gates.

## Enable (once per clone)

```
git config core.hooksPath .githooks
```

`scripts/verify_build_install.ps1` also sets this for you.

Install the routed gate tooling with:

```
python -m pip install -r scripts/requirements-dev.txt
```

## Bypass (emergencies only)

`git commit --no-verify` / `git push --no-verify`.

## Notes

- Windows runs these via git's bundled `sh` — no executable-bit setup needed.
- `cargo` must be on `PATH`; site PHP changes also require `php`. The hooks
  find Python themselves (an activated venv, then the repo `.venv`, then
  `python3`, then `python`), so it need not be on `PATH` under the bare name
  `python` — but the chosen interpreter must carry the scoped development
  requirements (the repo `.venv` does), needed when the focused public-copy
  audit or the operational-Python gate is selected.
