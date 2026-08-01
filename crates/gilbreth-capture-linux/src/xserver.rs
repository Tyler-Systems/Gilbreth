//! The crate's X provider module (the `coregraphics.rs`/`appkit.rs`
//! analog): thin reads over the shared pump connection, kept out of the
//! monitors so the state machines stay provider-fed and unit-testable.
//! Every read here is best-effort — a window can vanish between the
//! `_NET_ACTIVE_WINDOW` read and its property reads, and a failed reply is
//! a blackout (`None`), never an error that stops the pump.

use std::sync::Arc;

use x11rb::{
    atom_manager,
    protocol::{
        screensaver::ConnectionExt as ScreenSaverConnectionExt,
        xproto::{AtomEnum, ChangeWindowAttributesAux, ConnectionExt, EventMask, Window},
    },
    rust_connection::RustConnection,
};

use crate::foreground::ActiveWindow;

atom_manager! {
    /// The interned EWMH atoms the pump reads. `WM_NAME`/`WM_CLASS` are
    /// predefined and need no interning.
    pub(crate) Atoms:
    AtomsCookie {
        _NET_ACTIVE_WINDOW,
        _NET_WM_NAME,
        _NET_WM_PID,
        UTF8_STRING,
    }
}

/// Select `PropertyNotify` on the root window so `_NET_ACTIVE_WINDOW`
/// changes arrive as events (the event-driven half of the foreground
/// stream; each client's root event mask is its own).
pub(crate) fn select_root_property_events(
    conn: &RustConnection,
    root: Window,
) -> Result<(), String> {
    conn.change_window_attributes(
        root,
        &ChangeWindowAttributesAux::new().event_mask(EventMask::PROPERTY_CHANGE),
    )
    .map_err(|error| format!("root event selection failed: {error}"))?
    .check()
    .map_err(|error| format!("root event selection refused: {error}"))
}

/// Reads over the shared connection, cloneable so each monitor's provider
/// closure owns one.
#[derive(Clone)]
pub(crate) struct XReader {
    conn: Arc<RustConnection>,
    root: Window,
    atoms: Atoms,
}

impl XReader {
    pub(crate) fn new(conn: Arc<RustConnection>, root: Window, atoms: Atoms) -> Self {
        Self { conn, root, atoms }
    }

    /// The EWMH active window with its attribution: identity from
    /// `_NET_ACTIVE_WINDOW`, pid from `_NET_WM_PID`, the focus-time title
    /// from `_NET_WM_NAME` (UTF-8) with the legacy `WM_NAME` fallback, and
    /// the executable path from procfs. `None` (no active window, or a
    /// read raced a closing window) is a blackout the monitor rides out.
    pub(crate) fn active_window(&self) -> Option<ActiveWindow> {
        let xid = self.window_u32(self.root, self.atoms._NET_ACTIVE_WINDOW, AtomEnum::WINDOW)?;
        if xid == 0 {
            return None;
        }
        let pid = self
            .window_u32(xid, self.atoms._NET_WM_PID, AtomEnum::CARDINAL)
            .unwrap_or(0);
        let title = self
            .utf8_text(xid, self.atoms._NET_WM_NAME, self.atoms.UTF8_STRING)
            .or_else(|| self.legacy_text(xid))
            .unwrap_or_default();
        let exe = exe_for_pid(pid).unwrap_or_default();
        Some(ActiveWindow {
            xid,
            pid,
            exe,
            title,
        })
    }

    /// The X idle clock: MIT-SCREEN-SAVER `ms_since_user_input`.
    pub(crate) fn idle_ms(&self) -> Option<u64> {
        let reply = self
            .conn
            .screensaver_query_info(self.root)
            .ok()?
            .reply()
            .ok()?;
        Some(u64::from(reply.ms_since_user_input))
    }

    fn window_u32(&self, window: Window, property: impl Into<u32>, type_: AtomEnum) -> Option<u32> {
        let reply = self
            .conn
            .get_property(false, window, property.into(), type_, 0, 1)
            .ok()?
            .reply()
            .ok()?;
        let value = reply.value32()?.next();
        value
    }

    fn utf8_text(
        &self,
        window: Window,
        property: impl Into<u32>,
        type_: impl Into<u32>,
    ) -> Option<String> {
        let reply = self
            .conn
            .get_property(
                false,
                window,
                property.into(),
                type_.into(),
                0,
                TITLE_READ_LIMIT_WORDS,
            )
            .ok()?
            .reply()
            .ok()?;
        if reply.value.is_empty() {
            return None;
        }
        Some(String::from_utf8_lossy(&reply.value).into_owned())
    }

    /// The pre-EWMH `WM_NAME` fallback. Decoded as Latin-1 (its STRING
    /// type's encoding); a COMPOUND_TEXT title degrades lossily rather
    /// than being dropped — the EWMH read above is the primary path.
    fn legacy_text(&self, window: Window) -> Option<String> {
        let reply = self
            .conn
            .get_property(
                false,
                window,
                AtomEnum::WM_NAME,
                AtomEnum::ANY,
                0,
                TITLE_READ_LIMIT_WORDS,
            )
            .ok()?
            .reply()
            .ok()?;
        if reply.value.is_empty() {
            return None;
        }
        Some(reply.value.iter().map(|&byte| byte as char).collect())
    }
}

/// Title reads are bounded (in 32-bit words) so a hostile title cannot
/// balloon a reply; 1024 words = 4 KiB, far past any real title.
const TITLE_READ_LIMIT_WORDS: u32 = 1024;

/// The executable path for a pid, the Windows `QueryFullProcessImageNameW`
/// analog: the `/proc/<pid>/exe` link (with the kernel's " (deleted)"
/// suffix stripped so an updated-on-disk binary keeps a stable identity),
/// falling back to the kernel's `comm` name when the link is unreadable.
pub(crate) fn exe_for_pid(pid: u32) -> Option<String> {
    if pid == 0 {
        return None;
    }
    if let Ok(link) = std::fs::read_link(format!("/proc/{pid}/exe")) {
        let mut path = link.to_string_lossy().into_owned();
        if let Some(stripped) = path.strip_suffix(" (deleted)") {
            path.truncate(stripped.len());
        }
        if !path.is_empty() {
            return Some(path);
        }
    }
    let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
    let comm = comm.trim();
    if comm.is_empty() {
        None
    } else {
        Some(comm.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exe_for_pid_reads_our_own_process() {
        let pid = std::process::id();
        let exe = exe_for_pid(pid).expect("own process path is readable");
        assert!(
            exe.contains("gilbreth"),
            "test binary path expected, got {exe}"
        );
        assert!(exe.starts_with('/'), "full path, not a comm fallback");
    }

    #[test]
    fn exe_for_pid_declines_pid_zero() {
        assert_eq!(exe_for_pid(0), None);
    }
}
