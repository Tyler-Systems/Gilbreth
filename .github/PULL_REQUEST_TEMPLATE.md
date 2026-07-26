<!--
External code pull requests are not accepted until the Contributor Licence
Agreement is published. See CONTRIBUTING.md. Issues are open and welcome.

You keep the copyright in what you write. The agreement licenses it to Tyler
Systems LLC broadly enough to support the commercial licence, and obliges the
project to keep licensing your work under the open licence too.
-->

## What this changes

<!-- One or two sentences. Link the issue if there is one. -->

## Why

<!-- The problem being solved, not a restatement of the diff. -->

## Checklist

- [ ] I have read [CONTRIBUTING.md](../CONTRIBUTING.md) and I am covered by a
      signed Contributor Licence Agreement, or I am a maintainer.
- [ ] `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
      and `cargo test --workspace` pass.
- [ ] `python -m pytest scripts/tests -q` passes.
- [ ] Capture, privacy, destructive-path or schema changes are called out above,
      so they get the closer review [docs/MAINTAINING.md](../docs/MAINTAINING.md)
      asks for.
- [ ] No captured data leaves the machine, and no telemetry is added.
