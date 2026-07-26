<!--
External code pull requests are not accepted until the Contributor Assignment
Agreement is published. See CONTRIBUTING.md. Issues are open and welcome.

That agreement assigns copyright in your contribution to Tyler Systems LLC and
licenses it back to you. Read it before writing code, not after.
-->

## What this changes

<!-- One or two sentences. Link the issue if there is one. -->

## Why

<!-- The problem being solved, not a restatement of the diff. -->

## Checklist

- [ ] I have read [CONTRIBUTING.md](../CONTRIBUTING.md) and I am covered by a
      signed Contributor Assignment Agreement, or I am a maintainer. I
      understand it assigns copyright in this contribution.
- [ ] `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
      and `cargo test --workspace` pass.
- [ ] `python -m pytest scripts/tests -q` passes.
- [ ] Capture, privacy, destructive-path or schema changes are called out above,
      so they get the closer review [docs/MAINTAINING.md](../docs/MAINTAINING.md)
      asks for.
- [ ] No captured data leaves the machine, and no telemetry is added.
