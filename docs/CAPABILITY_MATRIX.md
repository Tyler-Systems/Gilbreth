# Capability matrix: what Gilbreth captures per platform

> **Status: CURRENT LIVING CONTRACT, updated through 2026-07-19. MAC-1 is
> complete, and the README and maintainer guide link here as the public account
> of platform differences. Every platform change must update its row.** The
> schema is the single cross-platform contract
> ([schema/README.md](../schema/README.md)); rows below say what each
> platform actually writes into it and which permission gates it. Stream
> rules and degradation cells are recorded with the macOS platform notes.

Guiding principle (recorded at MAC-0): **meaning-constant rows, never
approximated ones.** Where macOS cannot capture what Windows captures, the
rows are absent and this document says so — a mac database is thinner,
never silently different. Readers feature-probe rather than require kinds.

## Stream-by-stream

| Capability | Windows | macOS | macOS permission |
|---|---|---|---|
| App focus segments (`focus_changed`, dwell) | ✅ WinEvent hooks | ✅ NSWorkspace poll, same rows | none |
| Focused-window titles on focus rows | ✅ whenever Foreground is on (see toggle asymmetry below) | ✅ when the `windows` toggle is on AND Accessibility granted; degrades to app granularity otherwise | Accessibility |
| All-window lifecycle (`window_opened`/`window_closed`) | ✅ WinEvent hooks | ❌ **absent by design** — the public all-windows-with-titles API is Screen Recording-gated (banned) | — |
| Keyboard rows (`key`, key-down only, positional names) | ✅ Raw Input | ✅ one listen-only CGEventTap, same name vocabulary (`Cmd`/`Option`/`Fn` additive) | Input Monitoring |
| Mouse rows (clicks, double-clicks, drags, moves, wheel) | ✅ Raw Input + state machines | ✅ same tap, same state machines ported; trackpad precise scroll flushes 250 ms aggregates (same delta sum, fewer rows); momentum coast dropped | Input Monitoring |
| Idle/active boundaries | ✅ | ✅ HID idle clock, same threshold | none |
| Session lock/unlock, console connect/disconnect | ✅ WTS notifications | ✅ session-dictionary poll, same rows; fast-user-switch → `console` kind; `remote` kind stays Windows-only | none |
| Power suspend/resume/status (`battery_saver` ← Low Power Mode) | ✅ broadcast messages | ✅ IOKit sleep/wake + divergence recovery; all wakes emit incl. dark wakes (higher row volume, recorded); `capped_dwell_ms` = 0 (uptime clock — sleep contributes no dwell) | none |
| Display shape (`virtual_screen`) | ✅ | ✅ | none |
| Process launch/exit + churn summaries | ✅ Toolhelp sweep, 5 s | ✅ libproc sweep, 5 s, same tracker/filter (hoisted to core); a process denying every unprivileged read is absent (Windows always has a name) | none |
| Clipboard rows (`clipboard_used`) | ✅ metadata incl. `text_char_count`/`byte_size` | ✅ **metadata-only, permanently**: kind/count from declared types; sizes always `None` (macOS 26 pasteboard privacy alert-gates data reads); additive `concealed` kind for password-manager copies (mac-only) | none |
| Notifications received (metadata) | ✅ WNS listener | ❌ **unsupported** — no public listener API; rows simply absent | — |
| Sensitive context: password fields | ✅ UIA probe (`password_field` reason) | ✅ AX secure-field probe, fail-closed, same reason — plus the stronger OS layer below. **Caveat:** apps that don't materialize an accessibility tree for passive readers (Chromium/Electron class) fail every probe; on sustained deterministic failure Gilbreth **announces itself to that app** (Electron's documented `AXManualAccessibility`; the one AX write in the product; the O3 pair, adopted 2026-07-14) and probes through its app element, after which typing clears; apps that still never answer stay **wholesale-redacted** (over-marking, never leaking) | Accessibility (probe only; keyboard never gates on it) |
| Sensitive context: OS-enforced secure input | — (no analog; `secure_desktop` reason is Windows-only) | ✅ `secure_input` reason (additive): macOS itself withholds keystrokes from taps during password entry — stronger than a probe | none |
| Input-relay/KVM hint (`input_origin`) | ✅ pinned-center heuristic | ✅ CGEvent source state (more direct) | Input Monitoring (same tap) |
| Record Routine (semantic action capture) | ✅ | ❌ **Windows-only** — tray items, Recordings tab, and the Analytics request button are absent from the macOS build, not merely disabled (reopen by decision record only) | — |
| Launch at startup | ✅ HKCU Run key | ✅ SMAppService login item (`/Applications` bundle) | user approval in Login Items (system UI) |
| Tray + dashboard + privacy actions (tray pause, erase, redaction) | ✅ | ✅ same working actions; NSAlert confirms; template menu-bar icon | none |
| Global pause/resume hotkey | ✅ configurable, default `Ctrl+Alt+Shift+P` | ✅ configurable, same default (Control-Option-Shift-P); registered through Carbon, so it needs no permission at all | Behaviour during macOS secure input is not characterised — see the note below |
| Encrypted Archive and reset | ✅ DPAPI-wrapped `.gla` | ❌ **absent** — the tray item and the dashboard portable-export section are not built on macOS, rather than shown and failing. Reading and removing a `.gla` or legacy `.db` copied from a Windows install still works: Diagnostics counts them and Erase all my data removes them | — |

## The one titles-toggle asymmetry (stated honestly)

On **macOS** the `windows` toggle gates title capture: windows off means no
titles captured, ever. On **Windows**, focus rows carry titles whenever
Foreground is on, regardless of that toggle (it gates only the lifecycle
rows). macOS as shipped is therefore **strictly more private on this
axis**. Owner decision 2026-07-12: the asymmetry stands for MAC-1 and is
documented here rather than papered over; Windows alignment to the stricter
behavior remains an open post-R1 roadmap item.

## What the macOS build does not provide

1. **No per-window open/close history** — window lifecycle rows don't
   exist on macOS; focus segments (with titles when granted) are the
   window story.
2. **No notification counts** — the `notifications_received` analytics
   stay empty on mac databases.
3. **No Record Routine** — semantic action capture is Windows-only.
4. **Thinner clipboard rows** — copies are visible (kind, format count,
   correlation id) but never sized; concealed copies are labeled, not
   classified.
5. **Two permission prompts to reach full capture** — Accessibility
   (titles + password-field probe) and Input Monitoring (keyboard/mouse;
   needs one relaunch after granting). Everything else works with zero
   grants.
6. **No archive/reset or portable export** — neither surface is built on
   macOS (owner decision 2026-07-19: no mac key wrap at MAC-2), so nothing
   offers an action that cannot succeed. Archives copied from a Windows
   install remain visible in Diagnostics and removable by Erase all my data.
   A Keychain-wrapped key reopens the lane by decision if demand appears.
7. **The pause hotkey's behaviour during secure input is not
   characterised.** The chord is registered through Carbon rather than read
   from the capture event tap, so the OS-enforced withholding described below
   does not obviously apply to it — but that has not been measured either way,
   and this document will not guess. What is measured (2026-07-19): the chord
   reaches Gilbreth under the pump's own event loop. The tray Pause item is
   unaffected and works regardless.

And one thing mac users get that Windows users don't: the OS-enforced
secure-input guarantee — during password entry in native fields, the
operating system itself withholds keystrokes from Gilbreth (labeled
`secure_input`), independent of any Gilbreth code being right.

## Permission ↔ capability map (macOS)

| Grant state | What runs |
|---|---|
| Zero grants | Foreground segments (app granularity), idle/active, session/lock, power, displays, process, clipboard metadata — the full no-permission tier |
| + Accessibility | window-granular focus rows with titles (when `windows` toggle on); AX password-field probe (defense in depth) |
| + Input Monitoring | keyboard + mouse rows (one grant covers both; post-grant relaunch required — TCC delivers the grant at process start) |
| Revoked mid-run | the affected stream transitions to OFF-declared within a pass; a re-grant is noticed on the 30 s re-probe cadence (Input Monitoring needs the relaunch again) |

Concise status:

> **Current through 2026-07-19:** every specified MAC-1 capture slice, the
> onboarding/Diagnostics permissions panel, and the per-platform dashboard
> baselines are implemented. The acceptance privacy-copy check passed against
> this matrix; the in-app cross-platform wording fixes landed with the Phase 6
> dashboard redesigns. MAC-1 closed 2026-07-14 (multi-day soak, acceptance,
> and the one-time redeploy) with this capability contract unchanged, and the
> installed-build dogfood since then matches it live, including the
> password-field caveat's announce arc: Electron apps activate and their
> typing clears, while apps that reject the attribute stay fail-closed
> redacted, now observed both in a Chromium browser and in a non-browser
> app. Public-package installation and path copy remain assigned to MAC-2.**
