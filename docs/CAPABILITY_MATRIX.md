# Capability matrix: what Gilbreth captures per platform

> **Status: CURRENT LIVING CONTRACT, updated through 2026-08-01. MAC-1 is
> complete, LIN-1 added the Linux column, LIN-2 filled its remainder rows,
> and the README and maintainer guide link here as the public account
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
approximating. The LIN-2 remainder landed 2026-08-01, so the column now
carries every stream X11 can serve honestly. No stream below needs a
permission grant on Linux, so the platform has no permission column.

## Stream-by-stream

| Capability | Windows | macOS | macOS permission | Linux (X11, LIN-1 + LIN-2) |
|---|---|---|---|---|
| App focus segments (`focus_changed`, dwell) | ✅ WinEvent hooks | ✅ NSWorkspace poll, same rows | none | ✅ EWMH `_NET_ACTIVE_WINDOW` events + 1 s recheck, same rows; `hwnd` carries the X window id |
| Focused-window titles on focus rows | ✅ whenever Foreground is on (see toggle asymmetry below) | ✅ when the `windows` toggle is on AND Accessibility granted; degrades to app granularity otherwise | Accessibility | ✅ whenever Foreground is on (the Windows posture — X11 gates nothing behind a permission) |
| All-window lifecycle (`window_opened`/`window_closed`) | ✅ WinEvent hooks | ❌ **absent by design** — the public all-windows-with-titles API is Screen Recording-gated (banned) | — | ✅ client-list diff (`_NET_CLIENT_LIST` events + 1 s recheck), same origins: seeded silently at startup, observed opens/closes with the open-time identity kept for the close row, synthesized closes at shutdown; dock/desktop windows excluded (the taskbar-filter analog) |
| Keyboard rows (`key`, key-down only, positional names) | ✅ Raw Input | ✅ one listen-only CGEventTap, same name vocabulary (`Cmd`/`Option`/`Fn` additive) | Input Monitoring | ✅ XInput2 raw events, same name vocabulary from the live keymap (Super maps to the `win` modifier); autorepeat filtered by flag plus timestamp pair |
| Mouse rows (clicks, double-clicks, drags, moves, wheel) | ✅ Raw Input + state machines | ✅ same tap, same state machines ported; trackpad precise scroll flushes 250 ms aggregates (same delta sum, fewer rows); momentum coast dropped | Input Monitoring | ✅ XI2 raw events, same state machines ported; wheel is discrete ±120 ticks (X wheel buttons, incl. touchpad-emulated notches); positions sampled per pass; fixed fallback click/drag metrics; absolute-device (touchscreen) motion absent |
| Idle/active boundaries | ✅ | ✅ HID idle clock, same threshold | none | ✅ X idle clock (MIT-SCREEN-SAVER), same threshold |
| Session lock/unlock, console connect/disconnect | ✅ WTS notifications | ✅ session-dictionary poll, same rows; fast-user-switch → `console` kind; `remote` kind stays Windows-only | none | ✅ same rows from a 1 s poll of elogind's `LockedHint` OR'd with the session locker's own surface (the `org.xfce.ScreenSaver`/`org.freedesktop.ScreenSaver` bus names); measured 2026-08-01: xfce4-screensaver never reports to elogind, so the locker surface is load-bearing, and a saver that blanks without demanding a password writes the same rows (X11 exposes no lock-vs-blank distinction) • console kind from the `Active` property; `remote` stays Windows-only • a blocked session stops foreground dwell and raw keyboard/mouse input is discarded for the duration — X11 keeps delivering it while the lock surface is up, and what it spells is the unlock password |
| Power suspend/resume/status (`battery_saver` ← Low Power Mode) | ✅ broadcast messages | ✅ IOKit sleep/wake + divergence recovery; all wakes emit incl. dark wakes (higher row volume, recorded); `capped_dwell_ms` = 0 (uptime clock — sleep contributes no dwell) | none | ✅ elogind `PrepareForSleep` edges + the ported divergence recovery (CLOCK_BOOTTIME against CLOCK_MONOTONIC); `capped_dwell_ms` = 0 (sleep self-excludes from dwell: the monotonic clock stops, the macOS behavior); status from the sysfs power supplies with `battery_saver` honestly `None` (no Linux analog in this tier); a real suspend/resume cycle is not yet exercised live, per the status note |
| Display shape (`virtual_screen`) | ✅ | ✅ | none | ✅ root-window geometry, edge-detected on the 1 s cadence |
| Process launch/exit + churn summaries | ✅ Toolhelp sweep, 5 s | ✅ libproc sweep, 5 s, same tracker/filter (hoisted to core); a process denying every unprivileged read is absent (Windows always has a name) | none | ✅ procfs sweep, 5 s, same core tracker/filter; kernel threads excluded (Toolhelp/libproc parity); always has a name (`comm`) |
| Clipboard rows (`clipboard_used`) | ✅ metadata incl. `text_char_count`/`byte_size` | ✅ **metadata-only, permanently**: kind/count from declared types; sizes always `None` (macOS 26 pasteboard privacy alert-gates data reads); additive `concealed` kind for password-manager copies (mac and Linux) | none | ✅ **metadata-only, permanently**: XFixes owner-change events plus one `TARGETS` type-list round trip, never any content target (sizing X clipboard data means transferring it, so sizes stay `None` by construction); sub-second copies coalesce on the 1 s cadence; owner death writes `empty`, a refusing or silent owner writes `unavailable`; `concealed` from the KDE password-manager hint, presence-only (over-marking, never leaking) |
| Notifications received (metadata) | ✅ WNS listener | ❌ **unsupported** — no public listener API; rows simply absent | — | ❌ **unsupported**: reading them means owning the notification-daemon role; rows simply absent |
| Sensitive context: password fields | ✅ UIA probe (`password_field` reason) | ✅ AX secure-field probe, fail-closed, same reason — plus the stronger OS layer below. **Caveat:** apps that don't materialize an accessibility tree for passive readers (Chromium/Electron class) fail every probe; on sustained deterministic failure Gilbreth **announces itself to that app** (Electron's documented `AXManualAccessibility`; the one AX write in the product; the O3 pair, adopted 2026-07-14) and probes through its app element, after which typing clears; apps that still never answer stay **wholesale-redacted** (over-marking, never leaking) | Accessibility (probe only; keyboard never gates on it) | ❌ **no probe exists on X11 in this tier**, so the key-content opt-in it would protect is **absent from the UI too** (owner decision 2026-08-01, the Record Routine shape: not built, rather than shown without the protection behind it). Capture is lean-only from every surface: key names are omitted at the writer, and the redaction rules still apply. `privacy.store_key_content` in config.toml is still honoured for deliberate development use. **LIN-2 decision record (2026-08-01): the posture stays fail-closed and the opt-in stays absent.** LIN-2 added boundaries and metadata, not a probe; an AT-SPI probe would be a new capture surface carrying the Chromium-class blind spots the macOS caveat documents, and it is not built. What LIN-2 does add: raw input is discarded wholesale while the session lock surface is up, so unlock-password keystrokes never reach the channel even under the config-only development posture. Returning the opt-in to the Linux UI stays an owner decision, and it needs a real probe first |
| Sensitive context: OS-enforced secure input | — (no analog; `secure_desktop` reason is Windows-only) | ✅ `secure_input` reason (additive): macOS itself withholds keystrokes from taps during password entry — stronger than a probe | none | — (no analog; X11 delivers raw events regardless) |
| Input-relay/KVM hint (`input_origin`) | ✅ pinned-center heuristic | ✅ CGEvent source state (more direct) | Input Monitoring (same tap) | ❌ absent — no detector; the field is never set |
| Record Routine (semantic action capture) | ✅ | ❌ **Windows-only** — tray items, Recordings tab, and the Analytics request button are absent from the macOS build, not merely disabled (reopen by decision record only) | — | ❌ same absence as macOS, by the same decision record |
| Launch at startup | ✅ HKCU Run key | ✅ SMAppService login item (`/Applications` bundle) | user approval in Login Items (system UI) | ✅ XDG autostart desktop entry |
| Tray + dashboard + privacy actions (tray pause, erase, redaction) | ✅ | ✅ same working actions; NSAlert confirms; template menu-bar icon | none | ✅ same working actions, including confirm-gated secure erase; dialogs are the product's own egui shell hosted in a short-lived child process, since X11 has no `MessageBox`/`NSAlert` guaranteed present. A dialog that cannot be shown answers negative (a confirm) or defers (the three-way), so no destructive flow proceeds unseen. The key-content opt-in is the one absent item, per the password-field row |
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

1. **No notification counts** — reading them means registering as the
   session's notification daemon, which would displace the user's own.
2. **No Record Routine and no archive/reset** — absent by the same
   decision records that keep them off macOS, not by a Linux-specific
   limit. A `.gla` copied from a Windows install stays readable and
   removable.
3. **No password-field suppression, and therefore no key-content
   opt-in.** X11 has no probe in this tier, so rather than offer a
   setting whose protection does not exist here, the surface is absent:
   the tray item and the first-run posture dialog are not built on
   Linux (owner decision 2026-08-01, reaffirmed by the LIN-2 decision
   record in the password-field row). Capture is lean-only from every
   surface, with key names omitted at the writer, and
   `privacy.store_key_content` in config.toml is still honoured for
   deliberate development use — the one way to reach the unprotected
   posture. While the session lock surface is up, raw input is discarded
   wholesale, so that posture never sees unlock-password keystrokes.
4. **Lock evidence is a recorded composition.** elogind's `LockedHint`
   OR the session locker's own surface: a locker that reports to neither
   (or a lock flip shorter than the 1 s cadence) writes no rows, and a
   saver that blanks without demanding a password writes the same rows
   as a locking one, because X11 exposes no external distinction. The
   session-row meaning on every platform is "the lock surface engaged,"
   not "a password is required," so the rows stay meaning-constant.
5. **No input-relay hint and no absolute-device motion** — a KVM's
   forwarded input is indistinguishable here, and a touchscreen's
   position-reporting motion is excluded rather than reported as huge
   deltas. Clicks from either still record.
6. **Fixed click and drag metrics** — X11 exposes no system
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
lifecycle rows, exactly as on Windows now that LIN-2 carries them. The
reason is the same one
the Windows cell gives: X11 puts no permission in front of a title read,
so there is no grant for the toggle to compose with. macOS as shipped
remains strictly the most private of the three on this axis.

Concise status:

> **Current through 2026-08-01 (LIN-2):** the parity remainder landed the
> same day and was proven live on MX Linux/X11/Xfce: engaging and
> dismissing the session lock surface ends and reseeds the foreground
> segment with dwell capped at the boundary, keeps the unfocused
> correlations across the block, and writes `session_lock`/
> `session_unlock` rows (the locker-surface path and the elogind
> `LockedHint` path were each exercised separately, live against both
> buses); opening and closing a window writes lifecycle rows through the
> seeded/observed/synthesized origin arc; a copy writes one
> metadata-only clipboard row with kind and format count and no sizes.
> Not exercised live, recorded rather than implied: a real suspend/resume
> cycle (the `PrepareForSleep` subscription armed against the live system
> bus and the recovery paths are unit-covered, but no PrepareForSleep
> signal has been observed end to end), a console VT switch, and a
> password-demanding lock (this machine's saver has locking disabled, so
> the surface exercised was the same saver window without its password
> dialog). No packaged Linux release is planned.

> **Current through 2026-08-01 (LIN-1):** LIN-1 landed on 2026-08-01 and this
> column is its contract, with the same day's follow-up closing its two
> privacy holes: secure erase now confirms through a real dialog instead
> of declining unseen, and the key-content opt-in is absent rather than
> unprotected — every specified stream implemented and proven
> live on MX Linux/X11/Xfce (focus segments with titles and dwell,
> idle/active edges, key and mouse rows through the ported state machines,
> display shape, the procfs sweep with its churn summary, the tray pause
> toggle, the XGrabKey hotkey, and Today filling in the dashboard). The
> password-field gap and the remaining absences are listed above; the
> four streams this note once listed as absent are LIN-2's, carried
> since the note above. No packaged Linux release is planned.

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
