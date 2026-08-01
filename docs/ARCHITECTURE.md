# Gilbreth v2 — Architecture & Design

> Current technical contract for Gilbreth v2. For the project overview,
> mission, and roadmap, see the top-level [README](../README.md). Closed design
> and selected prototype records are kept in the private development archive.
> Historical tags remain only in the private repository archive. The Cargo manifests
> and lockfile, not this document, are dependency authority (§10).

## Contents
1. [Pipeline overview](#1-pipeline-overview)
2. [Workspace layout](#2-workspace-layout)
3. [Concurrency model](#3-concurrency-model)
4. [Event model](#4-event-model)
5. [Capture layer](#5-capture-layer)
6. [Privacy filter — "framed door, open by default"](#6-privacy-filter--framed-door-open-by-default)
7. [Storage layer](#7-storage-layer)
8. [Dashboard](#8-dashboard)
9. [App shell: lifecycle, config, single-instance, errors](#9-app-shell-lifecycle-config-single-instance-errors)
10. [Dependency authority and policy](#10-dependency-authority-and-policy)
11. [Build and verification order](#11-build-and-verification-order)

---

## 1. Pipeline overview

One long-running Rust process owns the whole capture-to-storage path; a second
process of the same Rust executable renders the native dashboard on demand.

```
 capture sources ─▶ bounded channel ─▶ [ single consumer thread ] ─▶ gilbreth.db ◀─ gilbreth-app --dashboard
  (platform             (crossbeam,       1. stamp envelope                           Rust/egui; WAL-safe reads,
   backend sends a       bounded,            (session_id + monotonic seq + ts)        rare explicit delete/prune
   typed Captured)       back-pressure)   2. privacy filter (redact / drop / flag)    and cooperative config IO
                                         3. batched SQLite write (flush 250ms / N)

 tray/UI thread ─ message pump ─ menu: stream toggles · open dashboard · privacy erase · quit
```

Two seams, both deliberately simple:
- **In-process:** capture sources send a typed `Captured { source, payload, captured_at }` over a **bounded** channel to a **single consumer thread**. That thread is the only place envelopes are stamped (session/seq/ts), filtered, and written. No JSON, no stringly-typed messages inside the app (that was a prototype artifact).
- **Cross-process:** the **SQLite file is the only contract**. The Rust app is the sole continuous *inserter*; the dashboard is a **reader** for all viewing and a **rare second writer** for explicit destructive operations only (delete-my-data). WAL serializes writers — "one writer at a time" means at any *instant*, not one forever. The writer, dashboard read-only views, and dashboard delete/prune write paths all set `busy_timeout = 5000` so rare checkpoint/VACUUM contention waits before surfacing an error. A privacy-grade *secure erase* is app-side (§7, §8).

**Egress boundary (architectural invariant).** There is **no outbound seam at
all.** Gilbreth makes zero outbound network calls, opens no dashboard listener,
and invokes no executor (not even a local agent or MCP server). Capture,
discovery, native rendering, and routine export all run locally, and
Gilbreth's responsibility ends at writing a local file. Acting on a discovered
routine — feeding it to an agent, an RPA tool, or any "efficiency platform" —
is something the user does outside Gilbreth. This keeps the privacy contract
absolute and keeps Gilbreth platform-agnostic.

---

## 2. Workspace layout

A Cargo workspace under `crates/`, plus a shared schema folder and optional
verifier-host operational tooling under `scripts/`:

| Crate | Role | Depends on |
|---|---|---|
| `gilbreth-core` | The `Captured`/`Event` envelope types, the `EventSource` trait, the **sequencer**, the privacy `Policy`/filter, pipeline glue. **Platform-agnostic, no Win32.** | — |
| `gilbreth-capture-windows` | Win32 implementations of `EventSource` (foreground, window, keyboard, mouse, system). | `gilbreth-core`, `windows` |
| `gilbreth-capture-macos` | Implemented macOS ambient-capture backend from MAC-1; its deliberate capability differences are recorded in the capability matrix. | `gilbreth-core` |
| `gilbreth-capture-linux` | Implemented Linux X11 ambient-capture backend from LIN-1 (the dogfood tier); its deliberate capability differences are recorded in the capability matrix. | `gilbreth-core`, `x11rb` |
| `gilbreth-store` | `rusqlite` connection, migrations, the batched single-writer. | `gilbreth-core`, `rusqlite` |
| `gilbreth-read` | Native read-time analytics and replay-export construction over the SQLite contract. Read-only; no store ownership or UI. | `rusqlite`, `chrono` |
| `gilbreth-dashboard` | Native egui shell, charts, seven product surfaces, and background read/action worker. | `gilbreth-read`, `eframe` |
| `gilbreth-app` | The one executable: capture single-instance guard, config, tray/message pump, pipeline wiring, and the `--dashboard` host boundary. | all of the above |

`schema/` carries canonical SQL/migration docs mirrored from `gilbreth-store`.
The historical Python implementation and its parity suite remain in the
private repository archive, not the fresh public tree. Keeping
`gilbreth-core` platform-free makes the pipeline testable and platform capture
backends replaceable.

---

## 3. Concurrency model

**Threads, not async. No tokio.** Capture is inherently message-loop/thread based and persistence is a single writer draining a channel — an executor buys nothing and costs binary size, `Send`/`Sync` friction, and complexity.

- **Channel:** `crossbeam-channel`, **bounded**. Bounded is the point — a burst of input must apply back-pressure (or drop, per policy) rather than grow memory unbounded in a process that runs all day. (Note: modern `std::sync::mpsc` is now built on crossbeam internals, so the old "2–10× faster" framing is dated; we pick crossbeam for the *ergonomics* — `select!` for drain-plus-shutdown, timeouts, bounded — not raw speed.)
- **Threads:**
  - **UI/message-pump thread** — owns the tray icon **and** the Win32 message loop. `tray-icon` requires its icon to live on a thread running a `GetMessageW`/`DispatchMessageW` loop; the same pump serves `SetWinEventHook` callbacks, `WM_INPUT` (raw input), and `WM_DISPLAYCHANGE`. Co-locating these is intentional and required (see §5).
  - **Consumer/writer thread — the single envelope authority.** Drains the event channel and a small command channel. For events, in order: (1) applies capture-time privacy exclusions that may drop a row entirely; (2) **stamps the retained envelope** — uses the DB-allocated `session_id`, assigns a **monotonic `seq`**, and derives `ts`; because this is the *one* sequencer, retained rows have no exclusion-created sequence holes and remain globally monotonic across all capture threads (§4); (3) applies the remaining writer privacy filter (§6); (4) buffers and commits **batched transactions** (§7). For maintenance commands, it owns app-side archive/reset, secure erase, and replacement-session creation. Owns the `rusqlite::Connection` (`!Sync`; never shared).
  - Additional capture threads only as needed (e.g. a separate raw-input pump if it can't share the UI pump).
- **Shutdown:** a shared `StopToken` wakes the message pump, capture exits the loop, pending mouse movement and live window-close events are flushed, the final sender is dropped, and the consumer drains until channel disconnect before flushing its pending batch and stamping `sessions.ended_at`. If the writer exits unexpectedly, it cancels the token and posts a wake message to the UI pump so `GetMessageW` does not block forever. The app join path has a timeout so a leaked sender cannot hang quit forever.

---

## 4. Event model

Sources emit a `Captured` (payload + the metadata only the source knows). The **sequencer** (the single consumer thread, §3) wraps it into an `EventEnvelope`, using the DB-allocated `session_id` and assigning the monotonic `seq` and `ts`. Durations are carried as `Duration`/`Instant` internally and only narrowed at the storage boundary — never the prototype's `i64 → u32` millisecond truncation.

```rust
// gilbreth-core

/// What a source emits. The envelope fields (session_id, seq, ts, is_sensitive)
/// are assigned downstream by the single sequencer (§3) — sources never stamp
/// seq themselves, so there is exactly one sequence authority.
pub struct Captured { pub source: Source, pub captured_at: Instant, pub payload: EventPayload }

pub struct EventEnvelope {
    pub schema_version: u16,
    pub session_id: i64,
    pub seq: u64,          // monotonic per session; assigned by the sequencer (§3), before the filter
    pub ts_unix_ms: i64,   // wall-clock UTC, for ordering/queries
    pub source: Source,    // Foreground | Window | Keyboard | Mouse | System
    pub is_sensitive: bool,// set by the privacy filter; default false
    pub payload: EventPayload,
}

pub enum EventPayload {
    FocusChanged { window: WindowRef, prev: Option<WindowRef>, previous_focused_for_ms: u64, window_unfocused_for_ms: u64 },
    WindowOpened { window: WindowRef, origin: WindowLifecycleOrigin },
    WindowClosed { window: WindowRef, open_for_ms: u64, origin: WindowLifecycleOrigin },
    Key         { key: String, mods: Modifiers, window: Option<WindowRef> },
    MouseClick  { button: MouseButton, x: Option<i32>, y: Option<i32>, window: Option<WindowRef>, input_origin: Option<InputOrigin> },
    MouseDoubleClick { button: MouseButton, interval_ms: u64, x: Option<i32>, y: Option<i32>, window: Option<WindowRef>, input_origin: Option<InputOrigin> },
    MouseDrag   { button: MouseButton, dx_total: i64, dy_total: i64, distance_px: u64, raw_event_count: u64, duration_ms: u64, start_x: Option<i32>, start_y: Option<i32>, end_x: Option<i32>, end_y: Option<i32>, window: Option<WindowRef>, selection_candidate: bool, input_origin: Option<InputOrigin> },
    MouseWheel  { axis: MouseWheelAxis, delta: i32, x: Option<i32>, y: Option<i32>, window: Option<WindowRef>, input_origin: Option<InputOrigin> },
    MouseMove   { dx_total: i64, dy_total: i64, distance_px: u64, raw_event_count: u64, duration_ms: u64, x: Option<i32>, y: Option<i32>, window: Option<WindowRef>, input_origin: Option<InputOrigin> },
    Idle        { idle_ms: u64 },     // entered idle
    Active      { idle_ms: u64 },     // returned from idle
    SystemInfo  { host: String, os_version: String, arch: String, processor_count: u32, memory_total_bytes: u64 },
    VirtualScreen { x0: i32, y0: i32, x1: i32, y1: i32, width: i32, height: i32 },
    ProcessStarted { pid: u32, exe: String, exe_source: ProcessExeSource },
    ProcessExited { pid: u32, exe: String, exe_source: ProcessExeSource },
    PowerSuspend { tick_ms: Option<u64> },
    PowerResume { tick_ms: Option<u64>, matched_suspend: bool },
    PowerBoundaryRecovered { gap_ms: u64, capped_dwell_ms: u64 },
    PowerStatusChanged { ac_online: Option<bool>, battery_percent: Option<u8>, battery_saver: Option<bool> },  // AC/battery, value-free
    SessionLock { session_id: u32 },
    SessionUnlock { session_id: u32 },
    SessionConnect { session_id: u32, connection: SessionConnectionKind },
    SessionDisconnect { session_id: u32, connection: SessionConnectionKind },
    ClipboardUsed { sequence_number: u32, format_kind: ClipboardFormatKind, format_count: u32, text_char_count: Option<u64>, byte_size: Option<u64> },
    NotificationsReceived { app: Option<String>, count: u32 },
    SensitiveContextEntered { reason: SensitiveContextReason },
    SensitiveContextExited { reason: SensitiveContextReason },
}

pub struct WindowRef { pub hwnd: u64, pub exe: String, pub title: String, pub pid: u32 }
pub struct Modifiers { pub shift: bool, pub ctrl: bool, pub alt: bool, pub win: bool }
pub enum ProcessExeSource { FullPath, SnapshotName }
pub enum InputOrigin { Local, RemoteRelaySuspected }
```

Decisions baked in here, each fixing a prototype gap:
- **`WindowRef` carries `hwnd + exe + title + pid`** — windows are tracked *per-HWND*, not collapsed per executable (the prototype keyed everything on the exe path, so two Notepad windows were one entity and same-exe focus changes were invisible).
- **One sequence authority.** `seq` / `ts` / `session_id` / `is_sensitive` live in the envelope (none existed in the prototype's `WinEvent`). `session_id` is allocated by SQLite when the session row is created; `seq` and `ts` are assigned by the **single sequencer stage** (the consumer thread, §3), *not* by the capture sources. So `seq` is globally monotonic across threads, and stamping happens *before* the filter, so redaction/drop never silently renumbers. A `UNIQUE(session_id, seq)` constraint enforces it (§7).
- **Within-session order is `seq`, not `ts`.** Each source carries its own `captured_at` `Instant`, and the single writer stamps events in receive order. That keeps one durable sequence, but it does not claim perfect causal ordering between independent sources such as a focus callback and the process polling worker when they race within the same few milliseconds. Coalesced `mouse_move` rows intentionally use the start of their sampling window as `ts`; the mouse state machine flushes pending movement before click/wheel rows, but independent-source review queries that need stored order should still sort by `(session_id, seq)`.
- **Session timebase (no channel-delay skew).** The sequencer records `(base_instant: Instant, base_utc_ms: i64)` at session start (`base_utc_ms` == `sessions.started_at`) and can resync that base when a power resume/recovery event or writer heartbeat observes wall-clock drift beyond the configured threshold. Each event's `ts_unix_ms` is derived from the source's monotonic `captured_at`, **not** the wall clock at dequeue — so queue latency never skews a timestamp. Resyncs affect future stamps only, log the old base/new base/measured drift/clamp, and use a never-go-backwards clamp against the last stamped timestamp; `seq` remains the durable in-session order.
- **Durations are `u64` ms** at this boundary, computed from monotonic `Instant`s upstream. For `FocusChanged`, `window` is the newly focused window, `prev` is the previously focused window, `previous_focused_for_ms` is the completed dwell that belongs to `prev`, and `window_unfocused_for_ms` is how long the newly focused window had been away.
- **Attribution is derived, not shared.** The prototype fanned the "current foreground app" into every capture thread via `Arc<RwLock<String>>` (a data race). Instead, the consumer tracks the current foreground from `FocusChanged` and joins it onto key/mouse events — or events carry the `hwnd` captured at input time. The shared mutable string is gone.

The envelope is serialized (serde) **only at the sink** — and only *after* the privacy filter has run — so the persisted typed columns **and** the `payload` JSON are both derived from the same already-redacted envelope (§6, §7). Capture stays format-agnostic.

---

## 5. Capture layer

All capture sits behind one trait, implemented per-platform in `gilbreth-capture-windows`:

```rust
/// Library crates use typed errors — no `anyhow` in public APIs (§9).
/// Platform crates convert Win32/platform details at the boundary so
/// `gilbreth-core` stays free of any `windows` dependency.
#[derive(thiserror::Error, Debug)]
pub enum CaptureError {
    #[error("capture is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("capture channel closed")]
    ChannelClosed,
    #[error("windows api error: {0}")]
    WindowsApi(String),
    #[error("source error: {0}")]
    Source(#[source] Box<dyn std::error::Error + Send + Sync>),
}

pub trait EventSource: Send {
    /// Emit `Captured` values until `stop` is signalled. The envelope/seq is
    /// assigned downstream by the sequencer (§3, §4) — sources never stamp it.
    fn run(self: Box<Self>, tx: Sender<Captured>, stop: StopToken) -> Result<(), CaptureError>;
}

pub enum WindowLifecycleOrigin { Observed, Seeded, Synthesized }
```

The public source wrappers (`ForegroundSource`, `WindowSource`, `KeyboardSource`, `MouseSource`, `SystemSource`, `IdleSource`) all route through one Windows `CapturePump`. That pump owns the co-located WinEvent hooks, raw-input window, hidden system window, shared message loop required by Win32, and the lightweight process-polling worker. **Event-driven wherever Windows allows it**; the deliberate exception is M5a process lifecycle capture, which uses coarse Toolhelp polling rather than ETW so always-on capture stays low-risk and privilege-free.

**Callbacks stay thin, non-blocking, and live on the pump thread.** `SetWinEventHook` requires a running message loop and delivers `WINEVENT_OUTOFCONTEXT` events **on the registering thread**; `RegisterRawInputDevices` allows only **one window per raw-input device class per process**. So the WinEvent callback and the `WM_INPUT` handler both live on the single message-pump thread, and each does the **minimum**: resolve the bare facts, update local state, and `try_send(Captured)` if the stream is enabled — no DB work, no blocking, no heavy parsing inside the callback. A full channel drops/counts the event rather than freezing the pump.

**Runtime toggles gate after state, before persistence.** M2 stream toggles do **not** unregister hooks or skip callback state updates. Foreground/window timing, keyboard modifiers, mouse cursor/delta state, system display state, and idle state keep advancing while a stream is disabled; only the final `Captured` value is dropped before it reaches the bounded channel. This keeps the first event after re-enable coherent and makes the privacy model explicit: disabled streams are still received in-process, but they are never buffered, sequenced, serialized, or written.

**Secure erase uses a separate suspension gate.** M3 adds a global capture suspension flag that is distinct from persisted stream toggles. Secure erase sets suspension, so callbacks and state machines may continue to receive activity in-process, but no stream enqueues or buffers captured events during the wipe. User toggle preferences are restored unchanged afterward unless replacement session creation fails, in which case capture stays suspended and the user is told to restart before recording resumes.

### Win32 surface

The official `windows` crate uses fine-grained features named after the module path. Required `features = [...]`:

| Capability | API (module path) | Feature flag |
|---|---|---|
| Focus changes (event-driven) | `SetWinEventHook`, `UnhookWinEvent` — `Win32::UI::Accessibility` | `Win32_UI_Accessibility` |
| Focus / open / close event constants | `EVENT_SYSTEM_FOREGROUND`, `EVENT_OBJECT_CREATE/DESTROY` — `Win32::UI::WindowsAndMessaging` | `Win32_UI_WindowsAndMessaging` |
| Message pump | `GetMessageW`/`PeekMessageW`/`TranslateMessage`/`DispatchMessageW`, `MSG`, `CreateWindowExW` (message-only `HWND_MESSAGE`) | `Win32_UI_WindowsAndMessaging` |
| Idle detection | `GetLastInputInfo`, `LASTINPUTINFO` — `Win32::UI::Input::KeyboardAndMouse` | `Win32_UI_Input_KeyboardAndMouse` |
| Raw input | `RegisterRawInputDevices`, `GetRawInputData`, `RAWINPUT`, `RAWINPUTDEVICE`, `WM_INPUT` — `Win32::UI::Input` (+ `WM_INPUT` in WindowsAndMessaging) | `Win32_UI_Input` |
| Foreground / window / title | `GetForegroundWindow`, `EnumWindows`, `GetWindowThreadProcessId`, `GetWindowTextW` | `Win32_UI_WindowsAndMessaging` |
| Process identity metadata | `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)`, `QueryFullProcessImageNameW`, `GetProcessTimes` — `Win32::System::Threading` | `Win32_System_Threading` |
| Process inventory polling | `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)`, `Process32FirstW`, `Process32NextW`, `PROCESSENTRY32W` — `Win32::System::Diagnostics::ToolHelp` | `Win32_System_Diagnostics_ToolHelp` |
| Single-instance | `CreateMutexW`, `GetLastError`, `ERROR_ALREADY_EXISTS` | `Win32_System_Threading`, `Win32_Foundation` |

(`Win32_Foundation` — `HWND`, `LPARAM`, `BOOL`, `HANDLE`, `CloseHandle` — is pulled in transitively but list it explicitly.)

### Per-stream design

- **`ForegroundSource`** — installs `SetWinEventHook(EVENT_SYSTEM_FOREGROUND)`. The callback (`unsafe extern "system" fn`, running on the pump thread) receives the new foreground `HWND` directly, normalizes it to the root top-level window, resolves it to a `WindowRef` (`GetWindowThreadProcessId` → `OpenProcess` → `QueryFullProcessImageNameW` for exe, `GetWindowTextW` for title), computes `previous_focused_for_ms` and `window_unfocused_for_ms` from per-HWND `Instant`s, and `try_send(Captured)`. Seed initial state once via `GetForegroundWindow`.
- **`WindowSource`** — `EVENT_OBJECT_CREATE`/`EVENT_OBJECT_SHOW`/`EVENT_OBJECT_DESTROY` (filtered to real top-level windows) drive `WindowOpened`/`WindowClosed`. `SHOW` is included because `CREATE` can arrive before visibility/title readiness; duplicate open attempts are deduped by HWND. A one-shot `EnumWindows` snapshot at startup seeds the `HashMap<HWND, WindowRecord>` so already-open windows are known. Window lifecycle payloads carry `origin = observed|seeded|synthesized`: observed means opened and closed during capture, seeded means already open at startup, synthesized means closed only because Gilbreth is shutting down. **No steady-state polling, no length-diff scheme.**
- **`KeyboardSource` / `MouseSource`** — raw input. Drive `RAWINPUT` directly via the `windows` crate (the prototype's `multiinput` is unmaintained since 2020). Register Keyboards first, then Mice, through **one** message-only window with `RIDEV_INPUTSINK` (so input is received in the background) — recall only one window per device class per process may register. Fan `WM_INPUT` out by device type. `GetRawInputData` is variable-length: call once with a null buffer to get the size, allocate, then read. Keyboard M1 emits **presses only** and updates modifier state on press/release so each emitted key carries a `shift/ctrl/alt/win` snapshot. Mouse M1 emits button-down clicks, wheel ticks, and sampled movement summaries; raw movement packets are coalesced into 250 ms windows before persistence so the channel and DB are not flooded. M5a adds value-free semantic annotations on top of existing rows: `mouse_double_click` after a completed click followed by a same-button click inside the user's OS double-click interval/rectangle (down-to-down timing, known same window required), and `mouse_drag` on button-up after movement leaves the OS drag rectangle or accumulated movement exceeds the drag threshold. The periodic timer resyncs active mouse buttons against physical button state and drops stale active-button tracking after missed button-up packets. `mouse_click` and `mouse_move` remain unchanged so existing input analytics do not double count derived semantics; left-button drags carry `selection_candidate = true` as a heuristic only, never selected content.
- **Input-sharing / software-KVM caveat.** Gilbreth records the local Windows session, not a cross-machine intent model. Tools such as Synergy, Deskflow, or Barrier can forward one machine's physical keyboard/mouse activity to another machine. When repeated relative raw mouse deltas arrive while `GetCursorPos` remains pinned at the virtual-screen center, mouse click/wheel/move payloads are tagged `input_origin = remote_relay_suspected`; local/default rows omit the field. The dashboard separates those counts and does not include them in clean local mouse totals. Gilbreth still does not infer the remote target machine or true remote coordinates; accurate per-machine context requires running Gilbreth on each machine or disabling Keyboard/Mouse capture on the host while controlling other machines.
- **Power boundaries.** The hidden top-level system window also receives `WM_POWERBROADCAST`. On `PBT_APMSUSPEND`, capture flushes pending mouse movement, closes the current foreground dwell, emits `power_suspend`, and resets pressed-key/modifier state. On `PBT_APMRESUMEAUTOMATIC` / `PBT_APMRESUMESUSPEND`, it debounces duplicate resume notifications, reseeds the current foreground window, and emits `power_resume { matched_suspend }`. If an unmatched resume itself shows a large `GetTickCount64` gap, or if a coarse timer later observes a large gap without a delivered suspend/resume pair, capture caps the foreground dwell, reseeds, emits `power_boundary_recovered { gap_ms, capped_dwell_ms }`, and increments the diagnostic counter. The recovery path arms the same resume debounce so a trailing OS resume broadcast is ignored. This prevents sleep/away time from being stored as one long foreground dwell, prevents a missed raw-input key release from suppressing future presses until restart, and makes standby handling auditable from the DB rather than inferred from logs or duration magic numbers.
- **Presence boundaries.** The same hidden top-level system window registers for `WM_WTSSESSION_CHANGE` with `WTSRegisterSessionNotification(NOTIFY_FOR_THIS_SESSION)`. It emits `session_lock` / `session_unlock` and console/remote `session_connect` / `session_disconnect` rows. Lock/disconnect flush pending mouse movement, close the current foreground dwell, reset pressed-key/modifier state, and emit `sensitive_context_entered`; unlock/connect emit `sensitive_context_exited` and reseed the current foreground window. Capture diagnostics log the Win32 value as `windows_session_id` so it is not confused with SQLite `sessions.session_id`; stored WTS payloads keep the backward-compatible `session_id` field. Registration failure is logged and non-fatal so the tray app can keep recording other streams. Sensitive-context reasons are tracked as an active set and emitted as balanced per-reason enter/exit rows, so an unlock/connect cannot clear suppression while another reason such as Secure Desktop remains active.

- **Secure Desktop boundary.** When System capture is enabled, Gilbreth installs a non-fatal `EVENT_SYSTEM_DESKTOPSWITCH` WinEvent hook and also arms the hidden system-window periodic timer at 1 second as a backstop. That 1-second System cadence also drives idle sampling and missed-power-boundary checks, which remain threshold/debounce gated. Each desktop sample reads the active input desktop with `OpenInputDesktop` plus `GetUserObjectInformationW(UOI_NAME)`. The ordinary `Default` input desktop is treated as normal; any non-`Default` desktop or an inaccessible input desktop is treated as protected and emits a value-free `sensitive_context_entered { reason = secure_desktop }` transition. Returning to `Default` emits the matching `sensitive_context_exited { reason = secure_desktop }` transition; the writer keeps suppression active until all active reasons have exited. Runtime System-stream toggles drop ordinary System telemetry but do not gate these sensitive-context policy rows once the System source has started. Gilbreth never stores the desktop name or any UAC/Winlogon prompt content. Idle-only capture keeps the older 5-second timer cadence.
- **Password-field boundary.** Keyboard or System capture starts a dedicated MTA UI Automation focus monitor. The monitor initializes COM off the Win32 message-pump thread, registers `AddFocusChangedEventHandler` with a cache request containing only `UIA_IsPasswordPropertyId`, seeds from the current focused element, and emits value-free `sensitive_context_entered/exited { reason = password_field }` rows only for confirmed `IsPassword` transitions. Focus transitions fail closed while UIA resolves the new element, and key capture synchronously asks the monitor thread for the current focused password state before building a key row; if that bounded probe cannot answer, or if the UIA focus generation changes while the probe is reading the focused element, the key is redacted. Recent same-window non-password answers are cached only while the focused HWND, UIA focus generation, and short TTL still match, and the cache is invalidated by navigation/Alt-style keyboard focus hints, mouse button focus hints, foreground changes, and UIA focus-generation changes before it can be trusted for a later key. Provisional gates from mouse/foreground uncertainty fall through to that probe so an in-field click can clear back to non-password instead of blindly redacting until the next focus event. It never reads UIA Name, Value, text, selector paths, document fields, or URL fields. UIA monitor startup/registration failure is logged and capture continues with password-field suppression active/fail-closed for keyboard rows.
- **Clipboard metadata.** The same system window registers with `AddClipboardFormatListener` and handles `WM_CLIPBOARDUPDATE`. It emits `clipboard_used` rows with the clipboard sequence number, coarse format family (`text|files|image|audio|custom|empty|unavailable`), format count, and size/count metadata when available. It never stores clipboard contents, previews, hashes, fingerprints, file paths, or custom format names. If another process has the clipboard open, Gilbreth records an `unavailable` metadata row instead of blocking the message pump.
- **Notification metadata.** System capture starts a best-effort WinRT `UserNotificationListener` worker when listener access is already `Allowed`. `Unspecified`, denied, or unavailable access logs and leaves the rest of capture running; the background capture worker deliberately does not call `RequestAccessAsync`, because the Windows consent flow is a UI/capability concern that needs an explicit product path. When allowed, the worker polls `GetNotificationsAsync(NotificationKinds::Toast)` on a bounded interval, retrying the seed poll until the first successful Action Center ID set can be remembered without emitting historical rows. Later polls diff against a bounded seen-ID cache; individual toast ID-read failures skip only that toast. The worker resolves source-app metadata through `UserNotification.AppInfo()`, bounds/rejects abnormal app labels, aggregates counts for new IDs per app for that polling pass, and emits `notifications_received { app, count }`. DisplayName/PFN/AUMID metadata is a label, not a verified exe identity, so any configured per-app exclusion disables notification rows globally at both capture and pre-sequencing privacy boundaries. The app label is metadata, not toast content, but it is projected into `events.title`, so configured title redaction and sensitive-context suppression redact it before storage when exclusions are empty. Gilbreth never calls `UserNotification.Notification()`, never reads toast XML/title/body/actions, and does not seed existing Action Center contents as new receipts.
- **Process lifecycle (M5a polling).** A dedicated lightweight worker polls `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)` every 5 seconds and diffs the live process set. The first successful snapshot seeds state only; Gilbreth does not synthesize `process_started` rows for processes already running before capture. Each live process stores a comparison key (`pid + lowercase PROCESSENTRY32W.szExeFile` plus `GetProcessTimes` creation time when available) and a separate persisted value (`QueryFullProcessImageNameW` full path when available, otherwise the Toolhelp base name with `exe_source = snapshot_name`). Diffing uses the comparison key, so full-path enrichment cannot create false start/exit churn. PID reuse with a different base name emits `process_exited(old)` + `process_started(new)`; same-name PID reuse also emits exit/start when both old and new creation times are available and differ. If creation time is unavailable, the tracker falls back to the basename behavior without persisting creation time or changing process event payloads. Snapshot failure, retry-exhausted `ERROR_BAD_LENGTH`, or an implausible empty snapshot skips the diff and preserves prior state rather than emitting a mass exit burst. Process rows are gated by the existing **System** capture toggle before enqueue, while the in-memory cache keeps updating so re-enable produces only the latest interval delta. Always-on process capture drops command line, arguments, parent PID, user SID, working directory, hashes, and file metadata. ETW process tracing is deferred to bounded Record Routine work because it is higher-fidelity but can carry privilege and privacy costs.
- **Windows shutdown/logoff boundaries.** The same hidden top-level system window answers `WM_QUERYENDSESSION` with "allow" and handles `WM_ENDSESSION` by posting `WM_QUIT` to the capture pump. `WM_CLOSE` routes to the same quit path (added 2026-07-28): every sender means "exit gracefully," and the unhandled default destroyed just the window, leaving a ghost tray over a still-running recorder. Observed live the same day: `taskkill`'s polite path delivers its WM_CLOSE to the tray host window, not this one — so the sanctioned scripted stop is `gilbreth-app --quit`, which finds the system window by class and posts WM_CLOSE to it directly (exit 0 when the request was posted to a found window — the flush completes asynchronously, so poll for process exit before touching the database; exit 1 when no window was found on this desktop); a stoppable posture beats resisting polite termination. That routes OS-initiated shutdown/logoff through the same post-loop flush path as tray Quit: pending mouse movement is flushed, the current foreground dwell is closed, live windows emit synthesized closes, the final sender drops, and the writer drains/stamps the session before process exit as far as Windows allows.
- **`SystemSource`** — one-shot at startup: `GetComputerNameExW`, `RtlGetVersion` (`GetVersionExW` fallback), `GlobalMemoryStatusEx`, and `GetNativeSystemInfo` → `SystemInfo`. Virtual-screen via `GetSystemMetrics(SM_*VIRTUALSCREEN)` emitted once, then updated on `WM_DISPLAYCHANGE` through the hidden top-level system window.
- **Idle** — `GetLastInputInfo` sampled on a coarse `WM_TIMER` (default 5 seconds); emit `Idle`/`Active` on threshold crossings. `LASTINPUTINFO.dwTime` is a 32-bit tick value, so capture computes idle duration in the 32-bit tick domain against `GetTickCount64` to survive the 49.7-day wrap. The threshold is startup-configured via `capture.idle_threshold_ms` (default 180000 ms / 3 min), with raw keyboard/mouse input also able to emit `Active` promptly after an idle period.

---

## 6. Privacy filter — "framed door, open by default"

A single pipeline stage in the consumer thread, **after stamping and before persistence** (§3):

```rust
pub struct Policy { /* denylist apps, redact rules, … — EMPTY by default */ }

impl Policy {
    /// Returns None to drop, Some(possibly-redacted) to keep.
    pub fn apply(&self, ev: EventEnvelope) -> Option<EventEnvelope> { /* default: Some(ev) */ }
}
```

- **The seam is built now; the policy is empty by default.** With no rules, `apply` is an identity pass-through (~zero behavior). This is the whole point: the *insertion point* exists from day one so privacy is never a retrofit, but the default honors the project's full-fidelity choice.
- **Two actions, different semantics.** *Redact* keeps the row, blanks content **in the typed payload** (e.g. `Key.key`, `WindowRef.title`), and sets `is_sensitive = true` → the *motion/timing* survives for analytics, the *content* doesn't. *Drop* removes the event entirely (reserved for hard-denylisted apps, e.g. a password manager). **Prefer redact-keep-row over drop.**
- **Redaction precedes serialization — for both copies.** The store serializes **both** the typed columns **and** the `payload` JSON from the *same post-filter envelope*, so a redacted key/title is absent from *both*. There is no pre-redaction copy anywhere downstream. **Tests must assert** that a redacted key/title appears in neither the typed column nor the JSON `payload`.
- **Sensitive-context suppression is stateful in the writer policy.** When enabled (`privacy.sensitive_context_suppression = true`, default), `sensitive_context_entered` adds a writer-local protected-context reason and `sensitive_context_exited` removes that reason. While any reason is active, policy keeps rows but redacts key values, window titles, notification app labels, and clipboard size/count metadata before the store sees them, marking changed rows `is_sensitive = true`. M5a drives this from lock/disconnect boundaries, Secure Desktop input-desktop sampling, and the dedicated MTA UIA password-field monitor. Sensitive-context boundary rows are treated as reliable control events by capture and bypass runtime stream gating so the writer policy and capture dedup state stay in sync. Capture-time and writer-side password/protected-context key redaction also zero non-essential modifier state on redacted key rows. After archive/reset or secure erase creates a replacement session, the writer snapshots any still-active sensitive reasons and re-emits value-free `sensitive_context_entered` rows into the new session; this preserves suppression without leaving the fresh DB with invisible redaction state. UIA work must not run on the Win32 message pump.
- **`seq` is assigned by the sequencer before the filter** (§3), so redaction/drop leaves sequence semantics intact (a gap = "something was dropped here", deliberately).
- The filter owns the `is_sensitive` envelope field.
- **Title retention (`privacy.title_retention_days`, default 0 = keep).** A startup scrub, not a capture-time filter: rows older than the window keep their timing/app/motion data while `title`/`prev_title` are blanked from both the typed columns and the payload JSON (`json_remove`), with `secure_delete` enabled for the duration so old pages do not retain title bytes. Like lean capture, scrubbed rows are **not** marked `is_sensitive` (policy aging-out is not a fired rule). Bounded batches keep a large backlog from stalling startup. Default 0 for existing installs; fresh installs move to 30 days at R1 packaging. Editable from the dashboard's Redaction rules (cooperative write, enforced at next app start).
- **Lean capture default (`privacy.store_key_content = false`).** A third action, distinct from redact and drop: policy *omits* the key name from every key row while keeping the row's timing, modifiers, and window context. It runs **after** the redaction rules (so title/key redaction and sensitive-context suppression still fire and still set `is_sensitive`), and unlike redaction it does **not** set `is_sensitive` — policy-omitted content is not a fired privacy rule, and stamping every key row would drown that flag's diagnostic value. The omitted key name is absent from both the typed `key` column (stored NULL) and the payload JSON (serde `skip_serializing_if`), exactly like a redacted value. Before discarding the name, policy records a coarse value-free `KeyClass` (printable / navigation / modifier / function / other) in the payload, so typing-speed analytics can later exclude navigation/editing/modifier keys from printable-character bursts (Rhythms). Keys a redaction rule already hit stay unclassified — classifying them would leak a shape trace of the protected content. Content capture is an explicit opt-in via the tray **Privacy > Store typed key content** toggle; because the policy is constructed once at startup, the change applies on the next run. Every dashboard keystroke metric counts `kind = 'key'` rows or reads modifiers, never the key value, so lean mode leaves input-volume and motion analytics unchanged.
- **Background-process churn filter (`capture.process_filter`, default on; LANDED 2026-07-04).** Capture-side, in the process monitor thread, before the channel (same pattern as stream gating). Modern Windows churns processes by design — service hosts starting on demand, UWP background task hosts, per-site browser renderers, spawn pipelines — and those rows were 27.5% of a live long-run DB with zero dashboard readers. The rule: a process transition is written **only if its exe basename has held foreground focus this session** (the foreground handler feeds a shared basename set on every focus event). This is the roadmap's crash-signature constraint made literal: an app the user actually works in keeps its start/exit evidence ("Excel crashed 3× this week" stays computable), while `svchost`/`conhost`/updater/pipeline churn does not reach the DB. **Demote, don't discard:** dropped transitions are counted per basename and flushed roughly hourly (and at monitor shutdown) as one value-free `process_churn_summary` row — window, dropped total, distinct exe count, top 3 basenames — so the churn *rate* stays queryable; a rate anomaly is a legitimate machine-health breadcrumb and Diagnostics renders it. A basename accumulating 30+ drops inside 10 minutes is flagged `sustained` in the summary (and noted in the log at debug level, so the basename never outlives retention in a warn stream): at the 5 s snapshot cadence, exit→restart gap widths quantize to ~0 s or ~5 s, so a gap-band test cannot distinguish a crash-looping service (~1-3 s restart backoff) from a busy spawn pipeline (~0 ms) — sustained volume in a window is the honest signal available, and this reasoning is recorded here deliberately as the rejected-alternative note. The 2026-07-28 observation day showed the flag chronic on developer machines (shells and build tools trip any rate a real restart loop would), so Diagnostics renders sustained names as a known category in the capture details rather than a verdict finding. Known limit: an app that launches and exits without ever holding focus leaves no process rows (first-launch rows for later-focused apps predate their first focus and can be dropped); no shipped lens reads them. `capture.process_filter = false` restores full process capture.
- **Mouse-move retention tier (`privacy.mouse_move_retention_days`, default 30; LANDED 2026-07-04).** A startup prune alongside retention and the title scrub: raw `mouse_move` rows older than the window are deleted in bounded batches. Movement rows are already coalesced into 250 ms windows at capture yet still dominate the DB (47% of a live long-run corpus; 60% of the 2026-07 dev DB) and feed only the mouse-speed / moves-per-hour lenses, so aging them out is housekeeping, not redaction — a plain delete with no `secure_delete` and no `is_sensitive` semantics, and keys/clicks/wheel keep the full `privacy.retention_days`. Consequence (stated in the Rhythms methodology expander): motion metrics see at most the tier window. Aggregate-before-delete (an hourly motion rollup) is deferred until a lens needs long-horizon velocity. 0 disables the tier. Note SQLite reuses freed pages rather than shrinking the file: the payoff is bounded growth, not a smaller file (compaction remains an explicit user action).

---

## 7. Storage layer

`gilbreth-store` owns a single `rusqlite::Connection` (bundled SQLite) on the consumer/writer thread.

**Connection setup (once, at open):**
```sql
PRAGMA journal_mode = WAL;      -- persistent; readers never block the single writer
PRAGMA synchronous  = NORMAL;   -- safe under WAL, far faster than FULL
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;     -- tolerate the dashboard's rare concurrent delete
```

**Write path:** buffer incoming events; flush as **one transaction with a `prepare_cached` INSERT reused across the batch**, committing **every ~250 ms or every 100–500 events** (whichever first). Never hold a long-lived transaction open — it blocks WAL checkpoints, starves the dashboard reader, and grows the `-wal` file unbounded. Batching amortizes the fsync cost so keystroke-rate input doesn't thrash the disk. If a batch commit returns `SQLITE_BUSY` / `SQLITE_LOCKED` despite the connection `busy_timeout`, the writer retries the whole batch with bounded backoff; shutdown cancellation is polled explicitly even while tray sender clones are still alive, interrupts in-flight SQLite waits, shortens the busy timeout, drains queued inputs until the writer input channel stays quiet briefly, and stamps the session closed. A shutdown-time `SQLITE_INTERRUPT` is retried so the one-shot interrupt does not drop the final legitimate flush. If the batch still cannot commit, it is counted in `events_skipped` / `actions_skipped` and the log includes the dropped first/last `seq` range for review. The rows written are serialized from the **post-redaction** envelope (§6).

**Migrations:** `rusqlite_migration` (tracks version in SQLite's `user_version` pragma — no metadata table). `Migrations::to_latest(&mut conn)` at startup. Migration `004` drops the initial `idx_events_session` index because `idx_events_session_kind_ts_id` covers the session-leading lookup shape used by dashboard analytics. Migration `005` adds the Record Routine schema spine (`record_requests`, `record_sessions`, `selector_paths`, `action_events`), and migration `006` adds the value-free action-level `framework_class` discriminator used by review/export-readiness logic without reading selector JSON. Production Record Routine capture now writes value-free `action_events` only during tray-confirmed recordings; Phase 2e diagnostics, D5 replay-readiness, and local value-free exports are implemented on top of that spine. Released migration files are protected by normalized SQL golden fixtures, and post-initial migrations are also tested to stay rollback-compatible: `ALTER TABLE ... ADD COLUMN`, `CREATE TABLE`, `CREATE INDEX`, `CREATE UNIQUE INDEX`, or `DROP INDEX` only. That second guard is load-bearing because `DatabaseTooFarAhead` lets an older binary continue against a newer DB only while migrations remain additive/index-shaped; any future table rewrite, column drop/rename/retype, or data rewrite needs an explicit version gate instead of leaning on that fallback.

### Record Routine elevated helper

The default app remains a normal-integrity tray process. For ordinary Record
Routine sessions it starts the in-process MTA UIA worker and sends value-free
`ActionCapture` rows straight to the writer channel. At the same boundary, the
tray suspends the broader baseline capture streams and resumes them with a
title-redacted reseed after the routine closes. That keeps the Record Routine
contract value-free even when a target app reflects typed content into its
window title. The 2c-E
elevated-window path adds a disabled-by-default helper gate, not an ambient
elevation model: `[record] elevated_helper_enabled = false` is the default, and
when an operator enables it the tray asks again per recording before launching
`gilbreth-elevated-record-helper.exe` with `ShellExecuteExW`/`runas`. By default
the helper is resolved beside the tray binary; `record.elevated_helper_path` can
point at an absolute signed helper path for the future `%ProgramFiles%` package
lane.

That helper runs the same value-free UIA capture worker in a separate process and
streams tagged JSON lines back over a local action pipe. A separate local control
pipe carries the single app-to-helper stop message, so shutdown cannot wedge
behind the action stream. `ActionCaptureWire` converts process-local `Instant`
values to unix milliseconds before IPC and maps them back to an `Instant` in the
app process. The app validates the IPC schema and `record_session_id`, matches
the Ready `helper_pid` to the exact process handle returned by
`ShellExecuteExW`, and checks the launched process image path against the
expected helper executable before accepting the helper run. After the action pipe
connects, it also reads the connected client process ID with
`GetNamedPipeClientProcessId` and rejects the stream unless that PID matches the
launched helper process. The release IPC decision is hardened named pipes: the
helper-specific DACL and one-instance pipe shape remain, and the elevated helper
opens its client handles with `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`
so the unelevated server can identify the peer without broader impersonation
authority. If
`record.elevated_helper_required_signer_sha256` is configured, the app also calls
`WinVerifyTrust` before launch and rejects the helper unless Windows trusts the
file's Authenticode signature and the signer certificate SHA-256 matches the
configured publisher fingerprint. In that configured signed lane, the app holds
a deny-write file handle across verification and `ShellExecuteExW` launch so the
verified helper bytes cannot be swapped before process creation. The default
remains empty so local unsigned debug builds keep working, with an explicit
runtime warning when that unsigned local/dev lane is used. The local
installer/update scripts can write that
config value with `-ElevatedHelperSignerSha256 <64-hex-fingerprint>`, preserving
existing config sections while leaving the field untouched when omitted. The same
scripts can write `record.elevated_helper_path` with `-ElevatedHelperPath`; the
app accepts only an absolute path whose filename is
`gilbreth-elevated-record-helper.exe` and still validates the launched process
image before trusting it. It rejects mismatched actions, then forwards accepted
actions into the same `WriterInput::Action` channel as the in-process worker. The
SQLite writer is still unelevated, single-threaded, and the only database writer.
The helper accepts only same-session `Stop` and `KeepAlive` control messages,
helper stop is bounded, and the helper receives a parent-liveness timeout derived
from the Record Routine safety cap plus a grace window. The tray sends
keepalives while its UI loop is healthy; if the parent stops pumping, the helper
self-stops, but cap-continued and paused recordings stay alive while keepalives
continue. The tray polls the helper bridge and closes the recording with the
helper's terminal reason if the helper exits after a successful launch. Gilbreth
still never runs automation, captures Secure Desktop/UAC prompt contents, or
makes network calls.

The `runas` helper lane is validated: visible high-integrity Notepad and
Calculator product smokes produced value-free native action rows with zero
sentinel/title leaks and no lingering helper process. Closed validation records
remain in the private development archive. The signed
`uiAccess=true` distribution lane remains deferred in the roadmap.
The main-app Azure Artifact Signing organization and local signing proofs pass, but even main-app
GO would not automatically reopen this helper lane: its rotating-leaf signer
pin, transactional install/restart, secure-location, revocation, and interactive
evidence requirements still need a separate decision. The lane's
build/sign/install/evidence tooling — the `uiaccess-helper-manifest` Cargo
feature, `build_uiaccess_elevated_helper.ps1`,
`sign_uiaccess_elevated_helper.ps1`, `install_signed_elevated_helper.ps1`,
`collect_2ce_token_measurement.ps1`, `collect_2ce_packaged_smoke_evidence.ps1`,
`collect_2ce_export_privacy_evidence.ps1`, `check_2ce_release_readiness.ps1`,
and the `gilbreth-token-diagnostics` binary — is retained. Reopening the lane
requires a new current decision and release procedure; the archived procedure
is historical evidence, not an active runbook. The IPC release decision keeps
the hardened named-pipe transport; COM local-server registration is revisited
only if a future service/enterprise package needs registered activation.

**DB location:** `%LOCALAPPDATA%\Gilbreth\gilbreth.db` (local filesystem only — WAL relies on shared memory and is unsupported on many network shares). The `-wal`/`-shm` sidecars must be accounted for by any backup/uninstall logic.

### Schema (v6)

```sql
CREATE TABLE sessions (
    session_id   INTEGER PRIMARY KEY,
    started_at   INTEGER NOT NULL,      -- unix ms UTC
    ended_at     INTEGER,
    host         TEXT,
    app_version  TEXT,
    git_sha      TEXT,
    run_label    TEXT
);

CREATE TABLE events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id   INTEGER NOT NULL REFERENCES sessions(session_id),
    seq          INTEGER NOT NULL,      -- monotonic per session
    ts           INTEGER NOT NULL,      -- unix ms UTC
    source       TEXT    NOT NULL,      -- foreground|window|keyboard|mouse|system
    kind         TEXT    NOT NULL,      -- focus_changed|window_opened|window_closed|key|
                                        -- mouse_move|mouse_click|mouse_double_click|mouse_drag|idle|active|system_info|virtual_screen|
                                        -- power_suspend|power_resume|power_boundary_recovered|power_status|
                                        -- session_lock|session_unlock|session_connect|session_disconnect|
                                        -- clipboard_used|notifications_received|
                                        -- sensitive_context_entered|sensitive_context_exited
    is_sensitive INTEGER NOT NULL DEFAULT 0,
    -- window identity (per-HWND)
    hwnd         TEXT, exe TEXT, title TEXT, pid INTEGER,   -- hwnd = hex string; see "Integer types".
                                              -- exe/prev_exe are stored basename-only for value-free window streams
                                              -- and Record Routine actions (A14). Deliberate process rows are the
                                              -- exception: their exe column and payload keep the full path when
                                              -- Windows exposes one (exe_source = full_path).
    prev_exe     TEXT, prev_title TEXT,        -- focus_changed
    -- keyboard
    key          TEXT, mod_shift INTEGER, mod_ctrl INTEGER, mod_alt INTEGER, mod_win INTEGER,
    -- mouse
    button       TEXT, pos_x INTEGER, pos_y INTEGER,
    -- previous_focused_for / open_for / idle, by kind
    duration_ms  INTEGER,
    -- post-redaction payload JSON; high-volume kinds may be storage-slimmed
    payload      TEXT NOT NULL,
    UNIQUE(session_id, seq)
);

CREATE INDEX idx_events_ts      ON events(ts);
CREATE INDEX idx_events_kind    ON events(kind);
CREATE INDEX idx_events_exe     ON events(exe);
CREATE INDEX idx_events_session_kind_ts_id ON events(session_id, kind, ts, id);

CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);   -- db uuid, created_at, etc.

-- Record Routine Phase 1 schema spine lives in schema/005_record_routine.sql:
-- record_requests, record_sessions, selector_paths, action_events.
-- schema/006_action_framework_class.sql adds action_events.framework_class.
-- Key action-log ordering contract:
-- action_events has UNIQUE(session_id, seq), and record_session_id/seq is only
-- a review index, not a second ordering universe.
```

Typed columns serve the common dashboard queries; `payload` is derived only after the privacy filter has run (§6). Most event kinds store the serialized post-redaction `EventPayload` for forward compatibility. High-volume rows may use a documented slim payload when the omitted data is duplicated elsewhere or not needed for analytics: new `mouse_move` rows keep `hwnd`, `exe`, `pid`, position, duration, and motion totals, but intentionally store `title = NULL` and omit the full `window` object from `payload`. For `focus_changed`, `duration_ms` is the completed dwell of `prev_*`, not the newly focused window.

`sessions` carries run identity for long-run review: `host`, `app_version`, `git_sha`, and an optional `run_label`. The app populates these at session creation, including replacement sessions after secure erase, so dashboard filters and external audits can isolate a run without cross-referencing startup logs by timestamp.

### Integer types

SQLite's `INTEGER` is **signed 64-bit (`i64`)**, and `rusqlite` errors when binding a `u64` that exceeds `i64::MAX`. So:

- **`hwnd` is persisted as hex `TEXT`** (e.g. `"0x1a2b3c"`). An `HWND` is an opaque 64-bit identity token that can use the full `u64` range and is only ever compared by equality (never summed), so hex text sidesteps signedness entirely and stays debuggable. (It stays `u64` in memory in `WindowRef` — the hex conversion happens only at the storage boundary.)
- **`seq`, `pid`, `duration_ms`, `memory_total_bytes`** are persisted as `INTEGER` (`i64`): each is within `i64::MAX` by range (a per-session counter, a PID, millisecond durations, a byte count), so the `u64`/`u32` → `i64` cast at the write boundary is lossless. Bind them as `i64`, never raw `u64`.

### Deletion & secure erase

Row deletion alone is **not** a privacy-grade erase. Under WAL, deleted bytes can linger in the `-wal` file and the freelist until a checkpoint + `VACUUM`, and SQLite may leave deleted content recoverable unless `PRAGMA secure_delete` is set. Two tiers, deliberately:

- **Delete-my-data (dashboard, M3).** Plain selected-row `DELETE` and manual retention prune, run by the dashboard as a rare second writer (§8). The dashboard opens a short-lived read-write connection per destructive action, sets `busy_timeout = 5000` and `foreign_keys = ON`, runs one delete transaction, then closes or compacts as appropriate. Fine for "remove this history", but not a forensic wipe. Selected-row delete does not compact the SQLite file. Manual prune commits the delete transaction, then attempts `PRAGMA wal_checkpoint(TRUNCATE)`, `VACUUM`, and a final checkpoint to reclaim disk space; if compaction is blocked by contention, the rows remain deleted and the dashboard reports compaction incomplete.
- **Configured retention (app startup, post-M4).** On startup, after migrations and before retention or new-session creation, the Rust app finalizes any stale open sessions left by an ungraceful prior exit by stamping `ended_at` to `max(started_at, last_event_ts_or_started_at)` and logging a warning with the repaired count. It then applies `privacy.retention_days` as a best-effort retention prune. It enables `PRAGMA secure_delete = ON` for the delete transaction, restores the prior setting, deletes old `events` and `action_events`, removes only ended sessions/recording sessions that become empty, expires stale unfulfilled `record_requests`, and garbage-collects unreferenced `selector_paths`; it never deletes the current live session. A verified `wal_checkpoint(TRUNCATE)` runs after the prune so secure-delete page rewrites are not left silently in WAL; if a live reader defers it, the deferral is logged with the deleted counts while the committed prune still reports success (a later checkpoint reclaims the WAL). Prune failures are logged and the app continues recording rather than blocking startup. Startup retention does **not** run `VACUUM`, so it is not privacy-grade erase and may not shrink the file; manual prune and secure erase remain the explicit compaction paths.
- **Archive and reset (app-side, post-M4 tray action).** Exposed as **Privacy > "Archive and reset..."** for clean long-run baselines. The app asks for two confirmations, refuses to run while Record Routine is active or starting/stopping (the writer independently refuses the command while a record session is open, so the guard does not rest on UI-thread state alone), sets capture suspension, waits for the capture-forwarder hop to become quiet, then the writer quiet-drains its own input channel and flushes batches before `VACUUM main INTO ?` creates a compact staging database. The app stamps copied open sessions with the archive timestamp, checkpoints the staging copy, then seals it as a versioned, chunk-authenticated `.gla` archive using AES-256-GCM and a per-archive key protected by the current Windows account through DPAPI. It reopens and verifies the sealed archive before deleting any live rows; provenance includes the source database UUID, schema, time span, host, and build. Explicit Privacy-dashboard export can rewrap an archive with an Argon2id-derived passphrase key or create a plaintext copy only after a specific acknowledgement. Legacy `.db` archives remain surfaced as plaintext-era files. Only after sealing and verification succeed does the writer run the same secure-delete/checkpoint/VACUUM/final-checkpoint reset sequence used by secure erase, mint fresh `meta`, create a fresh session, reset the sequencer, re-emit value-free `sensitive_context_entered` rows for any writer-policy reasons still active at reset time, lift capture suspension, and request a capture-pump reseed. The reseed emits fresh foreground, seeded window-open, system-info, virtual-screen, and power-status baseline rows for the replacement session and rebases in-memory window opened-at state so later synthesized closes cannot inherit pre-reset durations. If staging, sealing, verification, or closeout fails, incomplete artifacts are removed, no live rows are deleted, and capture returns to its prior user-selected pause state. If archive succeeds but replacement-session creation fails, capture remains suspended and the user is told to restart before recording resumes.
- **Secure erase / "wipe all" (app-side, M3 tray action).** Requires `PRAGMA secure_delete = ON`, the deletes, `PRAGMA wal_checkpoint(TRUNCATE)`, `VACUUM`, and a final `wal_checkpoint(TRUNCATE)` — operations that need near-exclusive access and rewrite the DB + sidecars. Only the app can do this correctly (it can suspend capture and owns the connection), so it is exposed as the tray menu item **Privacy > "Erase all my data…"**. The sequence is: two confirmations on a worker thread → refuse if Record Routine is active or starting/stopping (re-checked authoritatively by the writer, which refuses while a record session is open) → set capture suspension → wait for the capture-forwarder hop to become quiet → writer quiet-drains its own input channel and flushes → delete `action_events`, `record_sessions`, `record_requests`, `selector_paths`, `events`, `sessions`, and `meta` in a transaction → checkpoint/truncate → `VACUUM` → final checkpoint/truncate → mint fresh `meta` identity → create a fresh session and reset the sequencer → re-emit any active sensitive-context enter rows → resume capture and request the same capture-pump reseed used by archive/reset. The dashboard — having no IPC and no exclusive access — performs only row-level deletes/prunes and points the user to the tray for a full secure wipe. The docs/UI must not imply row deletion is forensically complete.
- **Secure-erase completion boundary.** Once secure erase creates its replacement session, the writer stamps an erase-completion boundary. For that replacement session's lifetime, a motion row that arrives with a capture timestamp strictly before the boundary is discarded, logged at warning level, and counted durably as `stale_pre_erase_rows_dropped` in Diagnostics; rows at or after the boundary are kept. Archive/reset deliberately clears and never creates this gate: a delayed row there missed the archive but remains legitimate live capture, so dropping it would lose data.
- **Physical-media caveat.** This is a logical SQLite scrub. SSD wear-leveling, filesystem snapshots, cloud backups, and copy-on-write storage can retain older physical blocks outside SQLite's control; forensic physical destruction requires whole-disk encryption/secure-device erase and backup management.
- **Scrub-incomplete outcome.** The writer connection already has `busy_timeout = 5000`, so checkpoint/VACUUM waits before failing under dashboard contention. If the delete commits but checkpoint/VACUUM cannot finish, the app still creates a fresh session and resumes capture. The user is told "data deleted, scrub incomplete; close dashboard and retry secure erase." Retrying is idempotent and re-runs the scrub on the now-empty DB. If replacement session creation fails after the delete commits, capture remains suspended and the user is told to restart before recording resumes.

---
## 8. Dashboard

The shipping dashboard is native Rust/egui and is hosted by the same
`gilbreth-app` executable as capture. The tray's **Open Dashboard** action
starts `gilbreth-app --dashboard`; no Python interpreter, web server, browser,
port, or address is part of the product path.

- **Crate boundary.** `gilbreth-read` owns WAL-safe SQLite reads, aggregation,
  filtering, and replay-export construction. `gilbreth-dashboard` owns the
  egui shell, navigation, charts, persisted UI state, and a background worker
  for reads and explicit actions. `gilbreth-app` owns process lifecycle and
  launches the dashboard role.
- **Seven product surfaces.** The native tabs are **Today**, **Week**,
  **Session**, **Analytics**, **Recordings**, **Privacy**, and **Diagnostics**.
  The Session surface includes selector/identity, story totals, foreground
  summary and opt-in titles, system context, an uncapped power timeline, event
  counts, a stable 500-row kind-filtered event snapshot, and confirm-gated
  multi-row selected delete.
- **Read and write discipline.** Viewing uses read-only, WAL-aware connections
  with a five-second busy timeout. The capture process remains the only
  continuous writer. Explicit selected-delete, prune, privacy-config, and
  Record Routine request actions use bounded, short-lived action paths; secure
  erase and archive/reset remain capture-process operations as defined in §7.
  A read-only snapshot may temporarily defer a truncate checkpoint, but must
  never block capture or lose committed rows.
- **Process and state ownership.** The capture mutex is capture-scoped, so more
  than one dashboard-only process can inspect the same database safely.
  Dashboard child processes are reaped by their owner. Only one viewer claims
  eframe persistence at a time; additional viewers remain fully usable without
  blocking on that ownership.
- **Refresh and privacy contract.** Reads are cached against a WAL-aware
  database signature and refresh asynchronously. Event selection is stable
  until explicit refresh or session change. Window titles remain opt-in,
  sensitive content is never introduced into evidence fixtures, and destructive
  actions retain confirmation and exact outcome copy.
- **Configuration boundary.** The native Advanced Privacy editor performs
  cooperative, document-preserving updates to the privacy keys it owns. Legacy
  `[dashboard]` keys in existing TOML are tolerated for rollback compatibility
  but are ignored at runtime and are not rewritten merely because they are
  obsolete.
- **Network boundary.** The dashboard opens no listener, makes no outbound
  request, and contains no telemetry path. SQLite remains the only
  capture/dashboard contract.
- **Verification.** Reader and action behavior is covered by Rust fixture,
  serialization, AccessKit, delete/scrub, WAL, and workspace tests. The retired
  Streamlit implementation and its parity/performance oracle remain private
  archive material and are not a public-tree build or gate.

---
## 9. App shell: lifecycle, config, single-instance, errors

- **Single-instance:** capture mode acquires `Local\GilbrethV2` first, then a
  machine-global mutex whose name is suffixed with the current Windows user
  SID; both handles remain live for the whole capture process. A local
  collision is a same-session double launch and keeps the explicit startup
  error. Acquiring local but colliding on global means the same user already
  has Gilbreth in another logon session, so the autostart-shaped second launch
  logs and exits quietly. The `--dashboard` role bypasses the capture guard,
  so multiple read-only viewers remain supported. On macOS and Linux the
  per-user data-root `flock` already spans that user's login sessions.
- **Config:** `%LOCALAPPDATA%\Gilbreth\config.toml` is deserialized into typed
  `serde` structs with defaults and no parse-path `unwrap`. Missing config
  creates typed defaults; malformed config is logged and left untouched.
  Existing-file edits are atomic and document-preserving. Runtime fields cover
  capture, storage, writer, Record Routine/helper, and privacy policy. Legacy
  `[dashboard]` `python`, `port`, `address`, and `auto_open_browser`
  keys remain tolerated text for rollback compatibility, but the native product
  ignores and never generates them.
- **Tray menu:** checked capture toggles use the single `CapturePump` control
  path; the tray also opens the native dashboard, owns archive/reset and secure
  erase, and performs clean shutdown. Explorer's taskbar-created broadcast
  re-adds the icon.
- **Dashboard launcher:** the tray starts the current `gilbreth-app` executable
  with `--dashboard`. No interpreter discovery, readiness polling, browser
  open, port selection, or Streamlit Job Object remains. An unretained worker
  waits and reaps each child when that dashboard exits; dashboard lifetime is
  independent of capture, and directly launched viewers do not claim the
  capture mutex.
- **Errors and diagnostics:** library crates expose typed errors; `anyhow` is
  limited to the app boundary. Malformed events and bounded insert failures are
  logged without silently killing capture, writer failure cancels and wakes the
  app, and file logs under `%LOCALAPPDATA%\Gilbreth\logs` include build
  identity, boundary transitions, and writer health without captured values.
- **Run review script:** `python scripts/review_run.py [path-to-db]` is an
  optional, read-only verifier-host health summary. It reports content-free DB,
  sequence, power, drop, and log findings and returns PASS only for the defined
  clean-health contract. It is not a product runtime or a substitute for deeper
  artifact review.
- **Local operational scripts:** `scripts/install-windows.ps1`,
  `scripts/install_current_release.ps1`, and
  `scripts/verify_build_install.ps1` remain development/install verification
  tooling. `scripts/review_run.py` and `scripts/tests` are optional
  verifier-host Python tooling. The native reader/WAL boundary is covered by
  `gilbreth-store` test
  `native_readonly_snapshot_defers_then_releases_wal_checkpoint`. Deferred
  signed-lane scripts remain inventoried in §7 and are outside the ordinary
  release process.

---

## 10. Dependency authority and policy

The root `Cargo.toml` owns shared direct requirements and version policy.
Individual crate manifests own feature selection and target-specific use.
`Cargo.lock` is the authoritative resolved graph for builds and releases. A
dependency change is complete only when the relevant manifests and lockfile
agree and the repository gate passes; this document does not carry a second
version list.

The notable architectural choices are:

| Dependency family | Policy |
|---|---|
| `windows` | Official Win32/WinRT bindings for the Windows backend; features stay scoped by crate. |
| `objc2-*` | Public Apple framework bindings for the macOS backend; no private APIs. |
| `x11rb` | Pure-Rust X protocol implementation for the Linux backend (no libX11/libxcb linkage); extension features stay scoped by crate. |
| `ksni` | StatusNotifierItem/dbusmenu tray for the Linux backend, consumed through its blocking API; keeps GTK/libappindicator out of the build and tokio out of the tree. |
| `rusqlite` + `rusqlite_migration` | Bundled SQLite and `user_version` migrations; the bundled feature requires a native C toolchain. |
| `crossbeam-channel` | Bounded channels and explicit shutdown for the synchronous single-writer design. |
| `eframe` / `egui` / `egui_kittest` | Exact-pinned UI stack; upgrades are deliberate work with snapshot coverage. |
| `tray-icon` | Native tray/menu-bar integration on the owning UI thread. |
| `serde`, `toml`, `toml_edit` | Event serialization plus typed, document-preserving configuration. |
| `tracing-*` | Structured diagnostics and release-safe rolling logs. |

Explicitly **not** used: `tokio`/`sqlx` (async is the wrong shape for a
single-writer embedded store), `multiinput` (unmaintained since about 2020;
the Windows backend drives `RAWINPUT` directly).

---

## 11. Build and verification order

The private repository archive preserves the original milestone tags. The
public tree is a Rust product workspace; build and verify it in dependency
order:

1. `gilbreth-core`: event envelope, sequencer, privacy policy, and shared
   platform-neutral contracts.
2. `gilbreth-capture-windows`, `gilbreth-capture-macos`, and
   `gilbreth-capture-linux`: platform capture backends against the core
   contract.
3. `gilbreth-store`: migrations, single-writer persistence, retention,
   delete/scrub, archive/reset, and WAL behavior.
4. `gilbreth-read`: read-only analytics, session/event-list queries, and
   replay-export construction.
5. `gilbreth-dashboard`: the seven-surface egui UI, accessibility tree,
   async reads, and explicit action plumbing.
6. `gilbreth-app`: capture lifecycle, tray, config, and the native
   `--dashboard` process host.

The repository-wide product gate is:

```powershell
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo build --locked --release -p gilbreth-app --bin gilbreth-app
```

A clean product clone needs Rust/MSVC to build but does not need Python.
Optional verifier-host development tooling is installed separately from
`scripts/requirements-dev.txt` and is checked with Black, Ruff, and
`pytest scripts/tests`. Those scripts validate operational evidence workflows;
they are not a product build step or runtime dependency.

Historical Streamlit behavior and differential archaeology belong to the
access-controlled private archive. The public build must never prebuild,
launch, or test that retired oracle.
