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
    /// The interned EWMH and selection atoms the pump reads. `WM_NAME`/
    /// `WM_CLASS`/`STRING` are predefined and need no interning. The
    /// MIME-named entries classify clipboard TARGETS replies; the
    /// `GILBRETH_CLIPBOARD` property is the transfer window's landing slot
    /// for those replies.
    pub(crate) Atoms:
    AtomsCookie {
        _NET_ACTIVE_WINDOW,
        _NET_CLIENT_LIST,
        _NET_WM_NAME,
        _NET_WM_PID,
        _NET_WM_WINDOW_TYPE,
        _NET_WM_WINDOW_TYPE_DESKTOP,
        _NET_WM_WINDOW_TYPE_DOCK,
        CLIPBOARD,
        COMPOUND_TEXT,
        DELETE,
        GILBRETH_CLIPBOARD,
        INSERT_PROPERTY,
        INSERT_SELECTION,
        MULTIPLE,
        SAVE_TARGETS,
        TARGETS,
        TEXT,
        TIMESTAMP,
        UTF8_STRING,
        AUDIO_WAV: b"audio/wav",
        AUDIO_X_WAV: b"audio/x-wav",
        GNOME_COPIED_FILES: b"x-special/gnome-copied-files",
        IMAGE_BMP: b"image/bmp",
        IMAGE_GIF: b"image/gif",
        IMAGE_JPEG: b"image/jpeg",
        IMAGE_PNG: b"image/png",
        IMAGE_TIFF: b"image/tiff",
        IMAGE_WEBP: b"image/webp",
        KDE_PASSWORD_HINT: b"x-kde-passwordManagerHint",
        TEXT_PLAIN: b"text/plain",
        TEXT_PLAIN_UTF8: b"text/plain;charset=utf-8",
        URI_LIST: b"text/uri-list",
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

/// Create the never-mapped InputOnly window that receives XFixes
/// selection events and hosts the `TARGETS` transfer property (a
/// requestor must be a window the requesting client owns).
pub(crate) fn create_transfer_window(
    conn: &RustConnection,
    root: Window,
) -> Result<Window, String> {
    let window = conn
        .generate_id()
        .map_err(|error| format!("transfer window id allocation failed: {error}"))?;
    conn.create_window(
        0, // depth: CopyFromParent (required for InputOnly)
        window,
        root,
        -1,
        -1,
        1,
        1,
        0,
        x11rb::protocol::xproto::WindowClass::INPUT_ONLY,
        0, // visual: CopyFromParent
        &x11rb::protocol::xproto::CreateWindowAux::new(),
    )
    .map_err(|error| format!("transfer window creation failed: {error}"))?
    .check()
    .map_err(|error| format!("transfer window creation refused: {error}"))?;
    Ok(window)
}

/// Negotiate XFixes and select CLIPBOARD selection events on the transfer
/// window: owner changes (a copy) plus the two owner-vanished subtypes.
pub(crate) fn select_clipboard_events(
    conn: &RustConnection,
    window: Window,
    atoms: &Atoms,
) -> Result<(), String> {
    use x11rb::protocol::xfixes::{ConnectionExt as XFixesConnectionExt, SelectionEventMask};
    conn.xfixes_query_version(5, 0)
        .map_err(|error| format!("XFixes version request failed: {error}"))?
        .reply()
        .map_err(|error| format!("XFixes is unavailable on this server: {error}"))?;
    conn.xfixes_select_selection_input(
        window,
        atoms.CLIPBOARD,
        SelectionEventMask::SET_SELECTION_OWNER
            | SelectionEventMask::SELECTION_WINDOW_DESTROY
            | SelectionEventMask::SELECTION_CLIENT_CLOSE,
    )
    .map_err(|error| format!("selection event selection failed: {error}"))?
    .check()
    .map_err(|error| format!("selection event selection refused: {error}"))
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

    /// The window manager's managed-window set: `_NET_CLIENT_LIST` on the
    /// root window, bounded like every property read. `None` (unreadable,
    /// or a WM that does not maintain the list) is a blackout the window
    /// monitor rides out.
    pub(crate) fn client_list(&self) -> Option<Vec<u32>> {
        let reply = self
            .conn
            .get_property(
                false,
                self.root,
                self.atoms._NET_CLIENT_LIST,
                AtomEnum::WINDOW,
                0,
                CLIENT_LIST_LIMIT_WORDS,
            )
            .ok()?
            .reply()
            .ok()?;
        let list: Vec<u32> = reply.value32()?.collect();
        Some(list)
    }

    /// One window's lifecycle identity, read at first sight: attribution
    /// (pid + procfs exe), the open-time title, and the dock/desktop
    /// exclusion from `_NET_WM_WINDOW_TYPE`. `None` when the window
    /// vanished before the reads landed.
    pub(crate) fn window_details(&self, xid: u32) -> Option<crate::window::WindowDetails> {
        // The type read doubles as the existence probe: a destroyed window
        // errors here and the monitor skips it rather than fabricating.
        let type_reply = self
            .conn
            .get_property(
                false,
                xid,
                self.atoms._NET_WM_WINDOW_TYPE,
                AtomEnum::ATOM,
                0,
                8,
            )
            .ok()?
            .reply()
            .ok()?;
        let excluded = type_reply.value32().is_some_and(|mut kinds| {
            kinds.any(|kind| {
                kind == self.atoms._NET_WM_WINDOW_TYPE_DOCK
                    || kind == self.atoms._NET_WM_WINDOW_TYPE_DESKTOP
            })
        });
        let pid = self
            .window_u32(xid, self.atoms._NET_WM_PID, AtomEnum::CARDINAL)
            .unwrap_or(0);
        let title = self
            .utf8_text(xid, self.atoms._NET_WM_NAME, self.atoms.UTF8_STRING)
            .or_else(|| self.legacy_text(xid))
            .unwrap_or_default();
        let exe = exe_for_pid(pid).unwrap_or_default();
        Some(crate::window::WindowDetails {
            pid,
            exe,
            title,
            excluded,
        })
    }

    /// Ask the CLIPBOARD owner for its declared-type list: a `TARGETS`
    /// conversion into the transfer window's property, stamped with the
    /// owner-change time per ICCCM. Flushed immediately so the reply is
    /// not deferred to the next pass's drain. The type list is metadata;
    /// no content target is ever requested.
    pub(crate) fn request_clipboard_targets(&self, window: Window, time: u32) -> bool {
        let sent = self
            .conn
            .convert_selection(
                window,
                self.atoms.CLIPBOARD,
                self.atoms.TARGETS,
                self.atoms.GILBRETH_CLIPBOARD,
                time,
            )
            .is_ok();
        sent && self.conn.flush().is_ok()
    }

    /// Read (and delete) the answered `TARGETS` property: a bounded atom
    /// array, each atom mapped to its classification so the monitor stays
    /// platform-pure. `None` when the property vanished or was not an
    /// atom list — the unavailable verdict.
    pub(crate) fn read_clipboard_targets(
        &self,
        window: Window,
    ) -> Option<Vec<crate::clipboard::TargetClass>> {
        let reply = self
            .conn
            .get_property(
                true,
                window,
                self.atoms.GILBRETH_CLIPBOARD,
                AtomEnum::ATOM,
                0,
                TARGETS_LIMIT_WORDS,
            )
            .ok()?
            .reply()
            .ok()?;
        let targets: Vec<u32> = reply.value32()?.collect();
        Some(
            targets
                .into_iter()
                .map(|atom| self.classify_target_atom(atom))
                .collect(),
        )
    }

    /// One TARGETS atom's class, the CF_*/UTI parity mapping: plain-text
    /// spellings, file references, raster images, sounds, the KDE
    /// password-manager hint, and the ICCCM protocol plumbing.
    fn classify_target_atom(&self, atom: u32) -> crate::clipboard::TargetClass {
        use crate::clipboard::TargetClass;
        let atoms = &self.atoms;
        if atom == atoms.KDE_PASSWORD_HINT {
            TargetClass::Concealed
        } else if atom == atoms.UTF8_STRING
            || atom == u32::from(AtomEnum::STRING)
            || atom == atoms.TEXT
            || atom == atoms.COMPOUND_TEXT
            || atom == atoms.TEXT_PLAIN
            || atom == atoms.TEXT_PLAIN_UTF8
        {
            TargetClass::Text
        } else if atom == atoms.URI_LIST || atom == atoms.GNOME_COPIED_FILES {
            TargetClass::Files
        } else if atom == atoms.IMAGE_PNG
            || atom == atoms.IMAGE_JPEG
            || atom == atoms.IMAGE_TIFF
            || atom == atoms.IMAGE_BMP
            || atom == atoms.IMAGE_GIF
            || atom == atoms.IMAGE_WEBP
        {
            TargetClass::Image
        } else if atom == atoms.AUDIO_WAV || atom == atoms.AUDIO_X_WAV {
            TargetClass::Audio
        } else if atom == atoms.TARGETS
            || atom == atoms.TIMESTAMP
            || atom == atoms.MULTIPLE
            || atom == atoms.SAVE_TARGETS
            || atom == atoms.DELETE
            || atom == atoms.INSERT_PROPERTY
            || atom == atoms.INSERT_SELECTION
        {
            TargetClass::Meta
        } else {
            TargetClass::Other
        }
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

/// Client-list reads are bounded the same way: 4096 windows is far past
/// any real session, and a list past the bound truncates rather than
/// ballooning the reply.
const CLIENT_LIST_LIMIT_WORDS: u32 = 4096;

/// TARGETS replies are bounded too: 1024 declared formats is far past any
/// real clipboard owner.
const TARGETS_LIMIT_WORDS: u32 = 1024;

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
