# Record Routine — threat model & EDR/AV posture

Posture note for Record Routine, the opt-in, bounded UI Automation action
recorder. This is an **honest disclosure**, not an evasion guide: Gilbreth does
**not** attempt to be undetectable, and this note exists so users and security
reviewers can reason about what the recorder does. Every behavioural claim below
is checkable against the source in this repository.

## The honest starting point

Record Routine subscribes to Windows **UI Automation (UIA)** events to capture
which UI element you act on and the kind of action. That is the **same OS API**
used by the publicly documented "UIA attack technique"
([Akamai](https://www.akamai.com/blog/security-research/windows-ui-automation-attack-technique-evades-edr)),
and per that research **there is no reliable technical signal** that separates a
benign accessibility/automation client from an abusive one — both perform
identical operations. So an EDR/AV product may flag Gilbreth's recorder on the
**API category**, not on any malicious behavior. We will not claim otherwise.

## What Gilbreth's recorder does NOT do

The behavioral distinctions that matter (and that a reviewer can verify against
the source and the value-free test harness):

- **Value-free.** It never reads element `Name`, `Value`, or text content — only a
  `has_name` boolean and structural selector identity. It **cannot** harvest typed
  text, field values, passwords, or 2FA codes. The cache request is the single
  chokepoint and never adds the Name/Value/Text property IDs. Check it yourself:
  `CACHE_PROPERTIES` in `crates/gilbreth-capture-windows/src/record_routine.rs`
  is the whole allowlist, and the test
  `cache_properties_are_limited_to_value_free_allowlist` in the same file fails if
  anything is added to it.
- **No input injection, no control actions.** It only **reads** cached control-
  pattern *availability* (is this a Toggle? a Scroll?). It never calls
  `Invoke()`, `SetValue()`, or any pattern method — it cannot click, type, or
  drive other apps.
- **No code/DLL injection** beyond the standard in-process `UIAutomationCore`
  provider that **every** UIA client loads. Nothing is injected into target apps.
- **Zero network.** No outbound calls, ever. Recordings are stored locally in the
  same SQLite DB as the rest of Gilbreth and never leave the machine unless the
  user exports a file themselves.
- **Opt-in and bounded.** Capture happens only inside a Record Routine session the
  user starts via a tray **two-confirmation** gate, with a visible recording
  indicator and a ~30-minute safety cap. It is never ambient; the always-on
  motion log contains no UIA selector/action data.
- **Baseline capture is suspended during Record Routine.** The normal
  baseline capture streams pause while a routine is active and reseed afterward,
  so apps that echo typed content into window titles do not defeat the value-free
  routine contract through the broader motion log.
- **Elevated apps require an explicit helper.** A normal non-elevated Gilbreth
  cannot read a higher-integrity (Run-as-administrator) app's UIA tree; such
  windows are skipped/annotated by the default path, never silently captured. The
  elevated-helper path is disabled by default and adds a per-recording consent before
  launching a short-lived elevated helper. That helper still reads only value-free
  UIA metadata, streams it back to the unelevated app, and does not capture
  Secure Desktop/UAC prompts. Release installs can also configure a required
  Authenticode signer certificate SHA-256 for the helper before `runas`; the
  stricter signed `uiAccess=true` package lane is deferred for public OSS release
  until an acceptable signing route exists.

## What an EDR/AV will observe (the IOCs)

During an active recording (and only then):

- a load of `UIAutomationCore.dll` and a connection over the UIA named pipe;
- a **system-wide focus-changed** subscription (`AddFocusChangedEventHandler` has
  no scope parameter), used purely to re-check window ownership; events from
  non-target / higher-integrity windows are dropped before any read;
- scoped element/property/structure event handlers on the target window.
- if `[record] elevated_helper_enabled = true` and the user opts in for that
  recording, a short-lived `gilbreth-elevated-record-helper.exe` child process
  launched through UAC/`runas`, plus local action/control named-pipe IPC back to
  the unelevated app. If configured, the app first verifies the helper with
  Windows Authenticode trust and a signer-certificate SHA-256 match. The
  unelevated app remains the sole SQLite writer. The public signed UIAccess
  package lane is retained as future tooling, not the current OSS release target.

All of these are **torn down when the recording stops**.

## Guidance

If your EDR/AV flags Gilbreth's recorder, it is reacting to the UIA
event-subscription **API category**, not to data exfiltration (there is none —
zero network, value-free, read-only). The appropriate response is a
**publisher/path allowlist** entry for the Gilbreth executable. Gilbreth will not
add detection-evasion behavior to avoid the flag.
