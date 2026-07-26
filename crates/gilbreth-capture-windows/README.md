# gilbreth-capture-windows

Windows-only capture sources for Gilbreth v2.

Current M1 coverage:

- Foreground focus via `SetWinEventHook(EVENT_SYSTEM_FOREGROUND)`.
- Window open/close via WinEvent create/show/destroy hooks.
- Keyboard presses via raw input on the shared message-only window.
- Mouse button-down clicks, wheel ticks, and sampled movement summaries via the same raw-input window.
- System info and virtual-screen snapshots through Win32 system metrics.
- Idle/active transitions via `GetLastInputInfo`.

Mouse movement is coalesced into 250 ms summary windows before persistence.
