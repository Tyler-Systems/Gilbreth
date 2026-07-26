# Dashboard visual-snapshot baselines (per-platform)

The `visual_snapshot_*` tests in `../dashboard_ui.rs` render each dashboard
scene through `egui_kittest` + wgpu to a PNG and diff it against a checked-in
baseline. GPU rasterization differs by backend — **Metal on macOS renders
text and edges a hair differently from the Windows backend** — so a single
shared baseline cannot pass on both platforms. Baselines therefore live
under a **per-OS subdirectory**, and each platform compares against its own:

```
tests/snapshots/
  windows/<name>.png   # generated on the Windows dev box
  macos/<name>.png     # generated on the dev Mac (Metal)
```

The subdir is `std::env::consts::OS` (`"windows"` / `"macos"`), chosen at
runtime by the `platform_snapshot` helper.

## Running the suite

- **macOS:** scenes with checked-in Metal baselines are **un-ignored**, so the
  existing 9-scene suite runs under a normal `cargo test -p gilbreth-dashboard`
  on a dev Mac. A GPU/display is required. The two Recordings scenes are
  Windows-only: Record Routine has no macOS surface, so the tab is absent from
  `Tab::ALL` there and the scenes cannot be rendered. `today_first_run` is the
  temporary
  exception: it remains ignored until a genuine Metal render is generated and
  reviewed on macOS; the Windows bitmap must never be copied into `macos/`.

## Baselines are machine-specific, so CI does not compare them

Setting `CI` renders each scene but **skips the baseline comparison**
(`platform_snapshot` in `../dashboard_ui.rs`). This is not a convenience: the
baselines are specific to the machine that generated them, not merely to the
OS. When the mac lane moved from the self-hosted dev Mac to GitHub's hosted
`macos-15` image (`84b98aa`), all 11 mac scenes failed — eight of them on the
same 31 shared-chrome pixels, before any content differed — because hosted
arm64 runners render through a paravirtualized GPU rather than the dev Mac's
Metal. `egui_kittest`'s default colour `threshold` of 0.6 already absorbs the
routine backend variance; what fails is the default
`failed_pixel_count_threshold` of 0.

Consequences to keep in mind:

- **The pre-push hook on a dev machine is the only real visual gate.** A pull
  request from a fork or another machine is not visually gated at all. Review
  UI changes accordingly.
- Rendering still happens under CI, so wgpu initialization, layout panics and
  paint failures are still caught there. Only pixel equality is skipped.
- Do not "fix" a hosted-CI failure by raising
  `failed_pixel_count_threshold` to cover it. Absorbing `today_rich`'s 1802
  differing pixels needs a budget far larger than a genuine regression such as
  a changed label, and the budget would need retuning whenever the runner
  image changes.
- If a hosted visual gate is ever wanted, generate and commit a third
  `ci/` baseline set from the runner itself rather than loosening the
  comparison — and expect it to drift with runner image updates.
- **Windows:** the suite stays `#[ignore]`d (no GPU CI lane) and each scene
  must run in its own Cargo process. Use the PowerShell procedure below with
  `UPDATE_SNAPSHOTS` absent to compare the checked-in baselines.

`visual_snapshot_today_first_run` has a canonical 1180 × 960 Windows baseline
for Phase 7. Its macOS-specific ignore is removed only after the genuine Metal
baseline is reviewed and checked in; it then joins the normal macOS gate.

Do not combine the Windows scenes into one filtered test process. On the
Windows dev box, the shared wgpu harness terminates with `0xc0000005`
(`STATUS_ACCESS_VIOLATION`); the per-scene processes are intentional.

## (Re)generating baselines

Run on the target platform's dev machine (a real GPU is required — these do
not render headless without one):

```sh
# macOS (the checked-in Metal suite is un-ignored):
UPDATE_SNAPSHOTS=force cargo test -p gilbreth-dashboard --test dashboard_ui visual_snapshot

# Dev Mac only: generate, then compare the pending first-run Metal scene:
UPDATE_SNAPSHOTS=force cargo test -p gilbreth-dashboard --test dashboard_ui visual_snapshot_today_first_run -- --ignored --exact
cargo test -p gilbreth-dashboard --test dashboard_ui visual_snapshot_today_first_run -- --ignored --exact
```

On Windows, run the following in PowerShell. The first invocation regenerates
all 12 Windows baselines; the second compares them with updates disabled:

```powershell
$tests = @(
    "visual_snapshot_today_rich"
    "visual_snapshot_today_first_run"
    "visual_snapshot_no_database"
    "visual_snapshot_week_rich"
    "visual_snapshot_analytics_rich"
    "visual_snapshot_analytics_tables"
    "visual_snapshot_recordings_rich"
    "visual_snapshot_diagnostics_rich"
    "visual_snapshot_privacy_rich"
    "visual_snapshot_session_rich"
    "visual_snapshot_session_records"
    "visual_snapshot_recordings_empty"
)

function Invoke-WindowsVisualSnapshots {
    param([switch]$Update)

    if ($Update) {
        $env:UPDATE_SNAPSHOTS = "force"
    } else {
        Remove-Item Env:UPDATE_SNAPSHOTS -ErrorAction SilentlyContinue
    }

    try {
        foreach ($test in $tests) {
            cargo test -p gilbreth-dashboard --test dashboard_ui $test -- --ignored --exact
            if ($LASTEXITCODE -ne 0) {
                throw "$test failed with exit code $LASTEXITCODE"
            }
        }
    } finally {
        Remove-Item Env:UPDATE_SNAPSHOTS -ErrorAction SilentlyContinue
    }
}

Invoke-WindowsVisualSnapshots -Update # regenerate
Invoke-WindowsVisualSnapshots         # compare without rewriting
```

`UPDATE_SNAPSHOTS=force` rewrites every baseline; `=1` only rewrites the
ones that currently differ. After regenerating, **review the diff** before
committing — a baseline change should be an intended UI change, not GPU
noise. Regenerate only on the same OS whose subdir you are updating; never
cross-write (a Metal render must not land in `windows/`).

The 9 currently gated macOS baselines were generated on macOS 26.5 (Apple
Silicon, Metal) on 2026-07-19, when the Recordings tab was removed from the
non-Windows tab strip and every remaining scene's chrome shifted by one tab.
`today_first_run` remains pending a genuine Metal render.

The Windows baseline set, including the approved 1180 × 960
`today_first_run` scene, was visually reviewed on the Windows dev box on
2026-07-14.
