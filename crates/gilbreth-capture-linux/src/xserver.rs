//! The crate's X provider module (the `coregraphics.rs`/`appkit.rs`
//! analog): thin reads over the shared pump connection, kept out of the
//! monitors so the state machines stay provider-fed and unit-testable.
//! Every read here is best-effort — a window can vanish between the
//! `_NET_ACTIVE_WINDOW` read and its property reads, and a failed reply is
//! a blackout (`None`), never an error that stops the pump.

use std::{collections::HashSet, sync::Arc};

use x11rb::{
    atom_manager,
    connection::Connection,
    protocol::{
        screensaver::ConnectionExt as ScreenSaverConnectionExt,
        xinput::{
            ConnectionExt as XInputConnectionExt, DeviceId, EventMask as XIDeviceEventMask,
            ValuatorMode, XIEventMask,
        },
        xproto::{AtomEnum, ChangeWindowAttributesAux, ConnectionExt, EventMask, Window},
    },
    rust_connection::RustConnection,
};

use crate::{foreground::ActiveWindow, keyboard::Keymap};

/// XI2's device-id wildcards. Raw input selects on `XIAllMasterDevices`:
/// the server generates each raw event twice — once for the slave device
/// and once for its attached master — so the all-devices wildcard receives
/// every keystroke and click twice (observed live on this X server, 5
/// synthetic presses arriving as 10 rows). The master wildcard matches
/// exactly one copy per event; `sourceid` still names the generating slave
/// for the absolute-device filter. Device queries use `XIAllDevices`.
const XI_ALL_DEVICES: DeviceId = 0;
const XI_ALL_MASTER_DEVICES: DeviceId = 1;

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

/// Negotiate XI 2.2 and select the raw input streams on the root window:
/// key press/release, button press/release, and motion, for every device.
pub(crate) fn select_raw_input_events(conn: &RustConnection, root: Window) -> Result<(), String> {
    conn.xinput_xi_query_version(2, 2)
        .map_err(|error| format!("XI2 version request failed: {error}"))?
        .reply()
        .map_err(|error| format!("XI2 is unavailable on this server: {error}"))?;
    conn.xinput_xi_select_events(
        root,
        &[XIDeviceEventMask {
            deviceid: XI_ALL_MASTER_DEVICES,
            mask: vec![
                XIEventMask::RAW_KEY_PRESS
                    | XIEventMask::RAW_KEY_RELEASE
                    | XIEventMask::RAW_BUTTON_PRESS
                    | XIEventMask::RAW_BUTTON_RELEASE
                    | XIEventMask::RAW_MOTION,
            ],
        }],
    )
    .map_err(|error| format!("raw input selection failed: {error}"))?
    .check()
    .map_err(|error| format!("raw input selection refused: {error}"))
}

/// The slave devices whose x/y axes report absolute positions (touch
/// screens, tablets): their raw-motion valuators are positions, not
/// deltas, so the pump excludes them from motion accumulation rather than
/// fabricating huge movements. Best-effort — an unreadable device list
/// means an empty set, and the io refreshes it on hierarchy changes.
pub(crate) fn absolute_pointer_sources(conn: &RustConnection) -> HashSet<DeviceId> {
    let mut absolute = HashSet::new();
    let reply = match conn.xinput_xi_query_device(XI_ALL_DEVICES) {
        Ok(cookie) => match cookie.reply() {
            Ok(reply) => reply,
            Err(_) => return absolute,
        },
        Err(_) => return absolute,
    };
    for info in reply.infos {
        let axis0_absolute = info.classes.iter().any(|class| {
            class.data.as_valuator().is_some_and(|valuator| {
                valuator.number == 0 && valuator.mode == ValuatorMode::ABSOLUTE
            })
        });
        if axis0_absolute {
            absolute.insert(info.deviceid);
        }
    }
    absolute
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

    /// The pointer's root-space position, sampled once per pass that
    /// carries raw input (raw events carry no position of their own).
    pub(crate) fn pointer_position(&self) -> Option<(i32, i32)> {
        let reply = self.conn.query_pointer(self.root).ok()?.reply().ok()?;
        Some((i32::from(reply.root_x), i32::from(reply.root_y)))
    }

    /// The virtual-screen bounding box: the root window's geometry, which
    /// the server resizes across RandR changes.
    pub(crate) fn virtual_screen(&self) -> Option<crate::system::VirtualScreenRect> {
        let reply = self.conn.get_geometry(self.root).ok()?.reply().ok()?;
        Some(crate::system::VirtualScreenRect {
            width: i32::from(reply.width),
            height: i32::from(reply.height),
        })
    }

    /// The current keycode-to-keysym table, rebuilt on `MappingNotify`.
    pub(crate) fn keymap(&self) -> Option<Keymap> {
        let setup = self.conn.setup();
        let min = setup.min_keycode;
        let max = setup.max_keycode;
        let mapping = self
            .conn
            .get_keyboard_mapping(min, max - min + 1)
            .ok()?
            .reply()
            .ok()?;
        Some(Keymap::new(
            min,
            mapping.keysyms_per_keycode,
            mapping.keysyms,
        ))
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
