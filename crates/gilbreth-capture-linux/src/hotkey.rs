//! Global pause hotkey via `XGrabKey` (LIN-1 shell). The structural twin of
//! Windows `RegisterHotKey` and the macOS Carbon registration: the X server
//! delivers the grabbed chord to this client and withholds it from the
//! focused application, so the chord is consumed exactly as on the other
//! platforms. A contended grab answers `BadAccess`, the same "another app
//! owns it" meaning `registration_failure_alert` already carries.
//!
//! The grab lives on its own X connection with a dedicated reader thread:
//! grabbed key events are delivered to the grabbing connection, and the
//! pump's connection must never block behind another module's events. The
//! handler half is the Carbon/Win32 twin — set an atomic flag, wake the
//! pump, return — and the app's service pass consumes the edge.

use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::JoinHandle,
};

use tracing::{debug, warn};
use x11rb::{
    connection::Connection,
    protocol::{
        xproto::{
            AtomEnum, ChangeWindowAttributesAux, ConnectionExt, CreateWindowAux, EventMask,
            GrabMode, ModMask, PropMode, WindowClass,
        },
        Event,
    },
    rust_connection::RustConnection,
    wrapper::ConnectionExt as WrapperConnectionExt,
    COPY_DEPTH_FROM_PARENT,
};

/// Set by the reader thread, consumed once per pump service pass. Identical
/// edge semantics to the Windows `PAUSE_HOTKEY_PRESSED` and the Carbon twin.
static PAUSE_HOTKEY_PRESSED: AtomicBool = AtomicBool::new(false);

/// Consume the edge recorded by the grab reader. Called once per pump
/// service pass, immediately before tray/menu handling.
pub fn take_pause_hotkey_press() -> bool {
    PAUSE_HOTKEY_PRESSED.swap(false, Ordering::SeqCst)
}

/// The chord's modifier bools in schema vocabulary (`win` is Super on this
/// platform, the `mod_win ← Super` mapping the config parser already
/// documents).
#[derive(Clone, Copy, Debug)]
pub struct PauseChordModifiers {
    pub ctrl: bool,
    pub alt: bool,
    pub shift: bool,
    pub win: bool,
}

/// Lifetime guard for the X grab, mirroring the Windows/Carbon twins:
/// ungrabs the chord and joins the reader thread on drop.
pub struct PauseHotkeyGrab {
    conn: Arc<RustConnection>,
    root: u32,
    poke_window: u32,
    keycodes: Vec<u8>,
    masks: Vec<ModMask>,
    shutdown: Arc<AtomicBool>,
    reader: Option<JoinHandle<()>>,
}

impl Drop for PauseHotkeyGrab {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        for &keycode in &self.keycodes {
            for &mask in &self.masks {
                let _ = self.conn.ungrab_key(keycode, self.root, mask);
            }
        }
        // Wake the reader out of wait_for_event with a PropertyNotify on the
        // window only it watches, then join so shutdown is bounded.
        let _ = self.conn.change_property8(
            PropMode::REPLACE,
            self.poke_window,
            AtomEnum::WM_NAME,
            AtomEnum::STRING,
            b"quit",
        );
        let _ = self.conn.flush();
        if let Some(reader) = self.reader.take() {
            if reader.join().is_err() {
                warn!("pause hotkey reader thread panicked");
            }
        }
        let _ = self.conn.destroy_window(self.poke_window);
        let _ = self.conn.flush();
    }
}

/// Find the modifier mask NumLock is bound to (conventionally Mod2, but the
/// mapping is configuration): scan the modifier map for a keycode whose
/// keysym list contains `Num_Lock`.
fn num_lock_mask(conn: &RustConnection) -> Option<ModMask> {
    let modifier_map = conn.get_modifier_mapping().ok()?.reply().ok()?;
    let setup = conn.setup();
    let min = setup.min_keycode;
    let max = setup.max_keycode;
    let mapping = conn
        .get_keyboard_mapping(min, max - min + 1)
        .ok()?
        .reply()
        .ok()?;
    let per = usize::from(mapping.keysyms_per_keycode);
    let keysym_num_lock = u32::from(xkeysym::Keysym::Num_Lock);
    let is_num_lock = |keycode: u8| -> bool {
        if keycode < min {
            return false;
        }
        let start = usize::from(keycode - min) * per;
        mapping.keysyms[start..(start + per).min(mapping.keysyms.len())].contains(&keysym_num_lock)
    };
    let per_modifier = usize::from(modifier_map.keycodes_per_modifier());
    for modifier in 0..8usize {
        let start = modifier * per_modifier;
        let end = (start + per_modifier).min(modifier_map.keycodes.len());
        if modifier_map.keycodes[start..end]
            .iter()
            .any(|&keycode| keycode != 0 && is_num_lock(keycode))
        {
            return Some(ModMask::from(1u16 << modifier));
        }
    }
    None
}

/// Every keycode the current keymap binds to `keysym` at any shift level
/// (a letter chord matches its lowercase level-0 keysym; the level scan
/// also covers keypads and remapped layouts).
fn keycodes_for_keysym(conn: &RustConnection, keysym: u32) -> Result<Vec<u8>, String> {
    let setup = conn.setup();
    let min = setup.min_keycode;
    let max = setup.max_keycode;
    let mapping = conn
        .get_keyboard_mapping(min, max - min + 1)
        .map_err(|error| format!("keyboard mapping request failed: {error}"))?
        .reply()
        .map_err(|error| format!("keyboard mapping read failed: {error}"))?;
    let per = usize::from(mapping.keysyms_per_keycode);
    let mut keycodes = Vec::new();
    for keycode in min..=max {
        let start = usize::from(keycode - min) * per;
        let end = (start + per).min(mapping.keysyms.len());
        if mapping.keysyms[start..end].contains(&keysym) {
            keycodes.push(keycode);
        }
    }
    Ok(keycodes)
}

/// Register the pause chord: grab `keysym` + the chord modifiers on the root
/// window, in every lock-modifier variant (plain, CapsLock, NumLock, both)
/// so an engaged lock key cannot defeat the chord. Returns the guard whose
/// drop ungrabs, or an error whose contended-grab case means "another app
/// owns this chord" (the Windows/Carbon failure meaning).
pub fn register_pause_hotkey_grab(
    keysym: u32,
    modifiers: PauseChordModifiers,
) -> Result<PauseHotkeyGrab, String> {
    let (conn, screen_num) =
        x11rb::connect(None).map_err(|error| format!("cannot connect to the X server: {error}"))?;
    let conn = Arc::new(conn);
    let root = conn.setup().roots[screen_num].root;

    let keycodes = keycodes_for_keysym(&conn, keysym)?;
    if keycodes.is_empty() {
        return Err(format!(
            "the current keyboard map has no key for keysym {keysym:#x}; choose a different pause chord"
        ));
    }

    let mut base = ModMask::from(0u16);
    if modifiers.ctrl {
        base |= ModMask::CONTROL;
    }
    if modifiers.shift {
        base |= ModMask::SHIFT;
    }
    if modifiers.alt {
        base |= ModMask::M1;
    }
    if modifiers.win {
        base |= ModMask::M4;
    }

    let mut masks = vec![base, base | ModMask::LOCK];
    if let Some(num) = num_lock_mask(&conn) {
        masks.push(base | num);
        masks.push(base | ModMask::LOCK | num);
    }

    let mut granted: Vec<(u8, ModMask)> = Vec::new();
    for &keycode in &keycodes {
        for &mask in &masks {
            let grab = conn
                .grab_key(false, root, mask, keycode, GrabMode::ASYNC, GrabMode::ASYNC)
                .map_err(|error| format!("grab request failed: {error}"))?;
            match grab.check() {
                Ok(()) => granted.push((keycode, mask)),
                Err(error) => {
                    // Roll back everything granted so a partial claim never
                    // lingers, then report the same meaning as a failed
                    // RegisterHotKey: the chord is owned elsewhere.
                    for &(keycode, mask) in &granted {
                        let _ = conn.ungrab_key(keycode, root, mask);
                    }
                    let _ = conn.flush();
                    return Err(format!(
                        "the X server refused the pause chord grab (typically another app owns it): {error}"
                    ));
                }
            }
        }
    }

    // The reader's wake channel for shutdown: a hidden InputOnly window only
    // this connection watches; a property poke produces the event that
    // breaks wait_for_event.
    let poke_window = conn
        .generate_id()
        .map_err(|error| format!("window id allocation failed: {error}"))?;
    conn.create_window(
        COPY_DEPTH_FROM_PARENT,
        poke_window,
        root,
        -1,
        -1,
        1,
        1,
        0,
        WindowClass::INPUT_ONLY,
        0,
        &CreateWindowAux::new(),
    )
    .map_err(|error| format!("poke window creation failed: {error}"))?;
    conn.change_window_attributes(
        poke_window,
        &ChangeWindowAttributesAux::new().event_mask(EventMask::PROPERTY_CHANGE),
    )
    .map_err(|error| format!("poke window event selection failed: {error}"))?;
    conn.flush()
        .map_err(|error| format!("grab connection flush failed: {error}"))?;

    PAUSE_HOTKEY_PRESSED.store(false, Ordering::SeqCst);
    let shutdown = Arc::new(AtomicBool::new(false));
    let reader = {
        let conn = Arc::clone(&conn);
        let shutdown = Arc::clone(&shutdown);
        let keycodes = keycodes.clone();
        std::thread::Builder::new()
            .name("gilbreth-pause-hotkey".to_string())
            .spawn(move || loop {
                if shutdown.load(Ordering::SeqCst) {
                    return;
                }
                match conn.wait_for_event() {
                    Ok(Event::KeyPress(press)) if keycodes.contains(&press.detail) => {
                        // The lock-variant masks make lock bits legitimate;
                        // anything else delivered here was still our grab.
                        debug!(state = ?press.state, "pause hotkey chord received");
                        PAUSE_HOTKEY_PRESSED.store(true, Ordering::SeqCst);
                        crate::wake_pump();
                    }
                    Ok(_) => {}
                    Err(error) => {
                        if !shutdown.load(Ordering::SeqCst) {
                            warn!(%error, "pause hotkey connection failed; hotkey is off for this run");
                        }
                        return;
                    }
                }
            })
            .map_err(|error| format!("pause hotkey reader thread failed to start: {error}"))?
    };

    Ok(PauseHotkeyGrab {
        conn,
        root,
        poke_window,
        keycodes,
        masks,
        shutdown,
        reader: Some(reader),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn x_available() -> bool {
        std::env::var_os("DISPLAY").is_some()
    }

    #[test]
    fn grab_registers_and_releases_and_a_second_claim_contends() {
        if !x_available() {
            eprintln!("skipping: no DISPLAY (the grab needs a live X server)");
            return;
        }
        // An unlikely chord so the test never fights the user's real
        // binding: Ctrl+Alt+Shift+F19 (keysym 0xFFD0). A keymap without F19
        // legitimately declines; that path is also exercised honestly.
        let modifiers = PauseChordModifiers {
            ctrl: true,
            alt: true,
            shift: true,
            win: false,
        };
        let keysym = u32::from(xkeysym::Keysym::F19);
        let first = match register_pause_hotkey_grab(keysym, modifiers) {
            Ok(grab) => grab,
            Err(error) => {
                assert!(
                    error.contains("no key for keysym"),
                    "only a keymap without the key may decline: {error}"
                );
                return;
            }
        };
        // The same chord from a second connection must contend (BadAccess).
        let second = register_pause_hotkey_grab(keysym, modifiers);
        assert!(
            second.is_err(),
            "a second grab of the same chord must be refused"
        );
        drop(first);
        // After release the chord is grabbable again.
        let third = register_pause_hotkey_grab(keysym, modifiers)
            .expect("the chord is free again after drop");
        drop(third);
    }
}
