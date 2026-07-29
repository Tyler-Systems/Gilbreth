# Gilbreth Schema Contract

Current live schema version: 8 (`008_deletion_audit.sql`).

The SQLite schema is the local contract between the recorder and the native
dashboard. `gilbreth-store` owns migrations and writes, `gilbreth-read`
consumes the contract for read-time analytics, and `gilbreth-dashboard`
renders those results. The Python reader and parity harness they replaced are
retired and are not part of this repository. Migrations
are forward-only and additive unless a release explicitly adds a version
gate. The rollback compatibility guard in `gilbreth-store` currently allows
only:

- `ALTER TABLE ... ADD COLUMN`
- `CREATE TABLE`
- `CREATE INDEX`
- `DROP INDEX`

Released migration SQL is mirrored under
`crates/gilbreth-store/tests/fixtures/released_migrations/`; the test suite
compares normalized SQL text so shipped migrations are not edited in place.

Dashboard readers should feature-detect tables and columns instead of hard
failing on `user_version`. A newer app may create tables an older dashboard does
not know about; the dashboard should show less, not refuse to open the DB. An
older archive may lack newer tables; new panels should render "not available"
copy based on table/column probes.

Migration `007` adds `open_focus`: a single-row operational table (enforced by
`CHECK (id = 1)`) holding the writer's open foreground segment — session, exe
basename, segment start, and a high-water timestamp the writer re-stamps every
30 seconds while a segment is open. It is not an event log: a clean shutdown
deletes the row, so a row present at open means the previous run ended
ungracefully, and startup/archive repair converts it into one synthesized
`focus_changed` row flagged `recovered` in the payload before deleting it.
Readers treat the row as live only while its high-water mark is within two
beats of the read, and consume it for Today/Week active time and top apps
only. Privacy deletion covers the table explicitly; it carries no titles.

Migration `008` adds `deletion_audit`: value-free accounting for every
seq-bearing row Gilbreth deletes outside secure erase — dashboard prune,
recording delete, per-event delete, startup retention, and mouse-move
retention each write one row per affected session per operation, carrying
kind, operation timestamp, session, deleted-row count, and the deleted seq
span (plus the cutoff for prune kinds). No content and no event timestamps
are preserved. The seq-continuity health check (review_run.py and
`gilbreth-read`) uses the spans to classify a gap as a recorded deletion
rather than data loss; a gap not covered by audited spans still reads as
REVIEW; and a session's total missing seqs must fit inside its audited
rows_deleted sum, so a wide span cannot excuse a larger loss inside it.
Audit rows deliberately outlive their sessions and carry no FK; secure
erase deletes the table with everything else, and archives carry their
audit rows along. Rollback residue is stated, not hidden: a binary rolled
back before 008 erases without knowing this table, leaving value-free
audit rows behind while session ids restart — the checkers therefore
discard any span stamped before its session began, so pre-erase residue
can never explain a fresh session's gaps.

Record Routine tables (`record_requests`, `record_sessions`, `selector_paths`,
and `action_events`) are active for the dashboard/tray/writer lifecycle,
production UIA/MTA action capture, and dashboard review/delete/prune flows.
Migration `006` adds the action-level `framework_class` discriminator used by
the native export-readiness review without reading selector JSON. The dev-only
live UIA harness remains an opt-in development tool; native replay/export
construction and the dashboard export surfaces are active and value-free.
Privacy deletion and retention must explicitly cover all four tables; they must
not rely on SQLite FK cascade behavior.

## macOS vocabulary decisions (MAC-0, recorded 2026-07-11 — no migration)

The SQLite schema is the single cross-platform contract (macOS port decision
record). A database written on either platform must read
correctly on both. These decisions bind the MAC-1 capture implementation;
every one is additive or interpretive — none requires a migration, and none
changes what Windows writes.

- **`hwnd`** — carries a *synthetic per-run window id* on macOS, allocated by
  the AX observer registry that must track window identity anyway. Same
  reader semantics as Windows (an opaque within-session correlator for
  window lifecycle and focus rows); the column is not renamed. It is never a
  real OS handle on macOS and carries no meaning across sessions — exactly
  as an `HWND` carries none across boots.
- **`mod_win`** — carries the **Command** key on macOS. The column is
  documented, not renamed (a rename is a migration plus parity churn for
  zero data value). Full modifier-column mapping: `mod_ctrl` ← Control,
  `mod_alt` ← Option, `mod_win` ← Command, shift unchanged. Dashboards may
  label per platform at display time; stored values are position-equivalent.
- **Key-name table** — extended with the macOS names `Cmd`, `Option`, and
  `Fn` for those keys' own key events (additive vocabulary in the existing
  TitleCase convention beside `Win`/`Shift`; no Windows name is reused or
  repurposed; all three classify as `KeyClass::Modifier`). Shared keys
  (letters, digits, F-keys, arrows, `Space`, `Enter`, `Escape`…) keep their
  existing canonical names.
- **`SecureDesktop` sensitive-context reason** — stays Windows-truthful (the
  UAC secure desktop). macOS secure-input suppression gets a *sibling*
  reason (working name `secure_input`) added with MAC-1 — an additive enum
  string, not a migration. Readers must treat both as the same
  sensitive-suppression class; neither platform ever writes the other's
  reason.
- **Session connect/disconnect off-WTS** — macOS maps fast-user-switch
  resign/become-active to the existing `session_disconnect` /
  `session_connect` events with connection kind `console`; the `remote` kind
  stays Windows-only (no RDP analog is claimed on macOS).
- **`exe`** — carries the *bundle-executable path* on macOS
  (`/Applications/Name.app/Contents/MacOS/Name`), not the `.app` bundle
  directory. The shared display helper basenames both platforms' shapes
  (fixtures: `display_app_handles_macos_bundle_paths` in `gilbreth-read`);
  no reader may assume an `.exe` suffix or backslash separators.
- **`system_info` naming** (recorded 2026-07-11, Idle/System slice) — the
  `os_version` and `arch` payload fields are display strings with per-OS
  vocabularies: macOS writes `"macOS 26.5.2"` / `"aarch64"` where Windows
  writes bare build numbers / `"arm64"`-style names for the same silicon
  class. No reader may parse or compare these across platforms; they are
  labels, not enums.
- **`Windows` stream scope** (recorded 2026-07-11, Windows-titles slice) —
  on macOS the stream enriches `focus_changed` rows to focused-window
  granularity with titles (Accessibility-gated); `window_opened` /
  `window_closed` lifecycle rows are **not written on macOS** (their
  Windows source is all-window WinEvent hooks; the public macOS analog
  with titles is Screen Recording-gated, which MAC-1 bans). Readers
  feature-probe row kinds, never require them — the notifications pattern.
  In an enriched row `hwnd` is the *window's* synthetic id from the same
  per-run allocator as the app-granular ids (collisions impossible), and a
  macOS database may contain both granularities (grant/revoke/toggle
  transitions), each truthful at its observation granularity with
  unfocused-correlation continuity preserved per id.
- **Keyboard/Mouse stream vocabulary** (recorded 2026-07-12, Keyboard+Mouse
  slice) — macOS feeds the **same** `EventPayload` variants with the same
  meanings as Windows: `Key` rows on key-down only (no KeyUp/KeyPress
  variant exists), auto-repeat filtered; `key` names come from a
  **positional, layout-independent** `CGKeyCode → name` table matching the
  Windows `key_to_string` vocabulary byte-for-byte (letters uppercase,
  US-layout OEM punctuation, `F1..`, arrows, `Numpad*`, `Space/Enter/…`),
  so `key_class_for_name` classifies identically on both platforms. The
  three macOS modifier keys' own names are the additive `Cmd`/`Option`/`Fn`
  (already in the key-name-table bullet above); Command sets the `mod_win`
  column in `Modifiers`. Mouse rows (`MouseClick`/`MouseDoubleClick`/
  `MouseDrag`/`MouseWheel`/`MouseMove`) carry global display-point
  coordinates and the frontmost `window`; wheel `delta` is in Windows ±120
  units on both platforms; `input_origin` uses the same
  `{Local(None), RemoteRelaySuspected}` enum. The additive
  `secure_input` sensitive-context reason (`SensitiveContextReason`, serde
  `snake_case`) is macOS-only; `secure_desktop` stays Windows-only; readers
  treat both as the same sensitive-suppression class.
- **Clipboard vocabulary** (recorded 2026-07-12, Clipboard slice) — macOS
  writes the same `clipboard_used` rows with `sequence_number` = the
  truncating u32 cast of `NSPasteboard.changeCount` (an opaque correlation
  id on both platforms; Windows writes `GetClipboardSequenceNumber`), and
  `format_kind`/`format_count` classified from the declared-types list.
  **`text_char_count` and `byte_size` are permanently `None` on macOS**
  (metadata-only: macOS 26 pasteboard privacy alert-gates programmatic
  data reads; Windows keeps filling them). The additive kind
  **`concealed`** (`ClipboardFormatKind::Concealed`, serde `snake_case`)
  is macOS-only: a copy whose declared types include
  `org.nspasteboard.ConcealedType` (the password-manager convention),
  overriding content classification. Windows never writes it — it ignores
  its own equivalent exclusion marker today (a recorded Windows follow-up,
  the titles-toggle pattern); readers treat unknown-to-them kinds as
  opaque labels already, so no reader change is required.
- **Host locations** (not schema, kept here as the one cross-platform
  contract page): the data dir / default DB is `%LOCALAPPDATA%\Gilbreth` on
  Windows and `~/Library/Application Support/Gilbreth` on macOS
  (`gilbreth_store::default_db_path`).
- **Notifications stream** — unsupported on macOS (no public listener API;
  recorded scope decision). The `notifications_received` vocabulary is
  unchanged; macOS databases simply never contain those rows, and readers
  already feature-probe rather than require them.
