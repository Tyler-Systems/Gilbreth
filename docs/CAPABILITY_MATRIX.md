# Capability matrix: what Gilbreth captures per platform

> **Status: CURRENT LIVING CONTRACT, updated through 2026-08-01. MAC-1 is
> complete, LIN-1 added the Linux column, and the README and maintainer guide
> link here as the public account
> of platform differences. Every platform change must update its row.** The
> schema is the single cross-platform contract
> ([schema/README.md](../schema/README.md)); rows below say what each
> platform actually writes into it and which permission gates it. Stream
> rules and degradation cells are recorded with the macOS platform notes.

Guiding principle (recorded at MAC-0): **meaning-constant rows, never
approximated ones.** Where macOS or Linux cannot capture what Windows
captures, the rows are absent and this document says so — those databases are
thinner, never silently different. Readers feature-probe rather than require
kinds. Linux is **X11 only, a dogfood tier with no packaged release**:
Wayland is absent by design (its compositors deliberately do not expose what
these streams read), and a Wayland session declines capture rather than
approximating. Streams marked LIN-2 are the roadmap's honest remainder, not
gaps discovered later. No stream below needs a permission grant on Linux, so
the platform has no permission column.

## Stream-by-stream

| Capability | Windows | macOS | macOS permission | Linux (X11, LIN-1) |
|---|---|---|---|---|
| App focus segments (`focus_changed`, dwell) | ✅ WinEvent hooks | ✅ NSWorkspace poll, same rows | none | ✅ EWMH `_NET_ACTIVE_WINDOW` events + 1 s recheck, same rows; `hwnd` carries the X window id |
| Focused-window titles on focus rows | ✅ whenever Foreground is on (see toggle asymmetry below) | ✅ when the `windows` toggle is on AND Accessibility granted; degrades to app granularity otherwise | Accessibility | ✅ whenever Foreground is on (the Windows posture — X11 gates nothing behind a permission) |
| All-window lifecycle (`window_opened`/`window_closed`) | ✅ WinEvent hooks | ❌ **absent by design** — the public all-windows-with-titles API is Screen Recording-gated (banned) | — | ❌ absent until LIN-2 (the client list) |
| Keyboard rows (`key`, key-down only, positional names) | ✅ Raw Input | ✅ one listen-only CGEventTap, same name vocabulary (`Cmd`/`Option`/`Fn` additive) | Input Monitoring | ✅ XInput2 raw events, same name vocabulary from the live keymap (Super maps to the `win` modifier); autorepeat filtered by flag plus timestamp pair |
| Mouse rows (clicks, double-clicks, drags, moves, wheel) | ✅ Raw Input + state machines | ✅ same tap, same state machines ported; trackpad precise scroll flushes 250 ms aggregates (same delta sum, fewer rows); momentum coast dropped | Input Monitoring | ✅ XI2 raw events, same state machines ported; wheel is discrete ±120 ticks (X wheel buttons, incl. touchpad-emulated notches); positions sampled per pass; fixed fallback click/drag metrics; absolute-device (touchscreen) motion absent |
| Idle/active boundaries | ✅ | ✅ HID idle clock, same threshold | none | ✅ X idle clock (MIT-SCREEN-SAVER), same threshold |
| Session lock/unlock, console connect/disconnect | ✅ WTS notifications | ✅ session-dictionary poll, same rows; fast-user-switch → `console` kind; `remote` kind stays Windows-only | none | ❌ absent until LIN-2 (elogind) |
| Power suspend/resume/status (`battery_saver` ← Low Power Mode) | ✅ broadcast messages | ✅ IOKit sleep/wake + divergence recovery; all wakes emit incl. dark wakes (higher row volume, recorded); `capped_dwell_ms` = 0 (uptime clock — sleep contributes no dwell) | none | ❌ absent until LIN-2 (elogind); sleep self-excludes from dwell (monotonic clock, the macOS behavior) |
| Display shape (`virtual_screen`) | ✅ | ✅ | none | ✅ root-window geometry, edge-detected on the 1 s cadence |
| Process launch/exit + churn summaries | ✅ Toolhelp sweep, 5 s | ✅ libproc sweep, 5 s, same tracker/filter (hoisted to core); a process denying every unprivileged read is absent (Windows always has a name) | none | ✅ procfs sweep, 5 s, same core tracker/filter; kernel threads excluded (Toolhelp/libproc parity); always has a name (`comm`) |
| Clipboard rows (`clipboard_used`) | ✅ metadata incl. `text_char_count`/`byte_size` | ✅ **metadata-only, permanently**: kind/count from declared types; sizes always `None` (macOS 26 pasteboard privacy alert-gates data reads); additive `concealed` kind for password-manager copies (mac-only) | none | ❌ absent until LIN-2 (XFixes selection events) |
| Notifications received (metadata) | ✅ WNS listener | ❌ **unsupported** — no public listener API; rows simply absent | — | ❌ **unsupported**: reading them means owning the notification-daemon role; rows simply absent |
| Sensitive context: password fields | ✅ UIA probe (`password_field` reason) | ✅ AX secure-field probe, fail-closed, same reason — plus the stronger OS layer below. **Caveat:** apps that don't materialize an accessibility tree for passive readers (Chromium/Electron class) fail every probe; on sustained deterministic failure Gilbreth **announces itself to that app** (Electron's documented `AXManualAccessibility`; the one AX write in the product; the O3 pair, adopted 2026-07-14) and probes through its app element, after which typing clears; apps that still never answer stay **wholesale-redacted** (over-marking, never leaking) | Accessibility (probe only; keyboard never gates on it) | ❌ **absent, a recorded LIN-1 gap rather than a design cell**: no probe exists on X11 in this tier, so the keyboard privacy posture rests on the lean-capture default (key names omitted at the writer) plus the redaction rules. LIN-2's sensitive-context decision record owns the next step |
| Sensitive context: OS-enforced secure input | — (no analog; `secure_desktop` reason is Windows-only) | ✅ `secure_input` reason (additive): macOS itself withholds keystrokes from taps during password entry — stronger than a probe | none | — (no analog; X11 delivers raw events regardless) |
| Input-relay/KVM hint (`input_origin`) | ✅ pinned-center heuristic | ✅ CGEvent source state (more direct) | Input Monitoring (same tap) | ❌ absent — no detector; the field is never set |
| Record Routine (semantic action capture) | ✅ | ❌ **Windows-only** — tray items, Recordings tab, and the Analytics request button are absent from the macOS build, not merely disabled (reopen by decision record only) | — | ❌ same absence as macOS, by the same decision record |
| Launch at startup | ✅ HKCU Run key | ✅ SMAppService login item (`/Applications` bundle) | user approval in Login Items (system UI) | ✅ XDG autostart desktop entry |
| Tray + dashboard + privacy actions (tray pause, erase, redaction) | ✅ | ✅ same working actions; NSAlert confirms; template menu-bar icon | none | ⚠️ tray (StatusNotifierItem), pause, stream toggles, key-content opt-in, and dashboard all work; **dialogs are fail-safe stubs**, so the confirm-gated tray actions (secure erase) decline rather than proceed unseen — a recorded LIN-1 gap; dashboard delete/prune still work |
| Global pause/resume hotkey | ✅ configurable, default `Ctrl+Alt+Shift+P` | ✅ configurable, same default (Control-Option-Shift-P); registered through Carbon, so it needs no permission at all | Behaviour during macOS secure input is not characterised — see the note below | ✅ configurable, same default; XGrabKey with CapsLock/NumLock variants, contended chords decline like the twins |
| Encrypted Archive and reset | ✅ DPAPI-wrapped `.gla` | ❌ **absent** — the tray item and the dashboard portable-export section are not built on macOS, rather than shown and failing. Reading and removing a `.gla` or legacy `.db` copied from a Windows install still works: Diagnostics counts them and Erase all my data removes them | — | ❌ **absent**: the same not-built-rather-than-failing shape as macOS, since DPAPI is Windows-only |

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

## What the Linux build does not provide

X11 only, and a dogfood tier: no package, no installer, no release lane.
Beyond that:

1. **No window lifecycle, session, power, or clipboard rows** — the four
   LIN-2 streams. Focus segments with titles are the window story until
   then, and a Linux database simply has no rows of those kinds.
2. **No notification counts** — reading them means registering as the
   session's notification daemon, which would displace the user's own.
3. **No Record Routine and no archive/reset** — absent by the same
   decision records that keep them off macOS, not by a Linux-specific
   limit. A `.gla` copied from a Windows install stays readable and
   removable.
4. **No password-field suppression** — a recorded gap, not a design
   cell. Key content is off by default (lean capture omits every key
   name at the writer), and the redaction rules still apply; enabling
   **Store typed key content** on Linux means passwords typed into
   ordinary fields can reach the database, which is not true on the
   other two platforms.
5. **Dialogs are logged, not shown** — the confirm-gated tray privacy
   actions decline rather than proceeding unseen. The dashboard's own
   delete and prune paths are unaffected.
6. **No input-relay hint and no absolute-device motion** — a KVM's
   forwarded input is indistinguishable here, and a touchscreen's
   position-reporting motion is excluded rather than reported as huge
   deltas. Clicks from either still record.
7. **Fixed click and drag metrics** — X11 exposes no system
   double-click interval or drag threshold, so the shared fallbacks
   (500 ms, 4 px, 8 px) stand in for the user's settings.

And one thing Linux gets that neither of the others does: capture needs
**no permission grant at all** — no TCC prompt, no consent dialog, every
stream live from first launch.

## Permission ↔ capability map (macOS)

| Grant state | What runs |
|---|---|
| Zero grants | Foreground segments (app granularity), idle/active, session/lock, power, displays, process, clipboard metadata — the full no-permission tier |
| + Accessibility | window-granular focus rows with titles (when `windows` toggle on); AX password-field probe (defense in depth) |
| + Input Monitoring | keyboard + mouse rows (one grant covers both; post-grant relaunch required — TCC delivers the grant at process start) |
| Revoked mid-run | the affected stream transitions to OFF-declared within a pass; a re-grant is noticed on the 30 s re-probe cadence (Input Monitoring needs the relaunch again) |

## The one titles-toggle asymmetry, restated for Linux

Linux matches **Windows** on this axis, not macOS: focus rows carry titles
whenever Foreground is on, and the `windows` toggle gates only the
lifecycle rows — which do not exist yet there. The reason is the same one
the Windows cell gives: X11 puts no permission in front of a title read,
so there is no grant for the toggle to compose with. macOS as shipped
remains strictly the most private of the three on this axis.

Concise status:

> **Current through 2026-08-01:** LIN-1 landed on 2026-08-01 and this
> column is its contract — every specified stream implemented and proven
> live on MX Linux/X11/Xfce (focus segments with titles and dwell,
> idle/active edges, key and mouse rows through the ported state machines,
> display shape, the procfs sweep with its churn summary, the tray pause
> toggle, the XGrabKey hotkey, and Today filling in the dashboard). The
> four LIN-2 streams, the password-field gap, and the dialog stubs are
> listed above as absences, not omissions. No packaged Linux release is
> planned.

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
