//! Dev-only probe: does a Carbon `RegisterEventHotKey` chord reach us under
//! the pump's *manual* event drain?
//!
//! P3 (MAC-2 parity punchlist) implements the panic/pause chord on macOS.
//! The owner-chosen mechanism is Carbon `RegisterEventHotKey` rather than
//! matching inside the listen-only `CGEventTap`, because the tap is torn down
//! whenever Input Monitoring is not granted (`capture-macos/src/lib.rs`
//! `wanted_mask` gated on `input_trusted`), and the zero-grant tier is a
//! supported configuration — a chord that dies there would be exactly the
//! silently-dead surface P3 exists to remove.
//!
//! The assumption that needs measuring before any of that is written: Carbon
//! hot-key events are dispatched by the Carbon event loop, but Gilbreth's pump
//! never calls `[NSApp run]`. It drives its own `CFRunLoopRunInMode` pass and
//! drains `NSEvent`s by hand (`platform/macos.rs` `init_app_shell` /
//! `pump_app_events`). Whether a Carbon hot key survives that arrangement is
//! not answerable from the code, and this port has been bitten by exactly this
//! class of assumption before (AppKit calling `CFRunLoopStop` for its own
//! reasons; Input Monitoring not delivering to an already-running process).
//!
//! Carbon hot keys need no TCC permission, so unlike the AX probe this one can
//! run straight from a terminal — no signing, no bundle, no `open`.
//!
//! Run: `cargo run -p gilbreth-app --features dev-hotkey-probe --bin gilbreth-hotkey-probe`
//! Then press Control-Option-Shift-P, with this terminal frontmost and again
//! with another app frontmost. Questions it answers, printed as a checklist on
//! exit:
//!   Q1 does the handler fire at all under the manual drain
//!   Q2 does it fire while another app is frontmost (it is a *global* chord)
//!   Q3 is the chord consumed (does the frontmost app also receive the P)
//!   Q4 does it fire while macOS secure input is active
//!
//! Q3 is answered by eye: the probe cannot see the other app's input. Type
//! into a text field with the chord and look for a stray character.

use std::ffi::c_void;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use objc2::MainThreadMarker;
use objc2_app_kit::{NSApplication, NSApplicationActivationPolicy, NSEventMask};
use objc2_foundation::{NSDate, NSDefaultRunLoopMode};

// ---------------------------------------------------------------------------
// Carbon FFI. Same linkage pattern as capture-macos `secure_input.rs`.
// ---------------------------------------------------------------------------

type OSStatus = i32;
/// `MacTypes.h:291` — `typedef unsigned long ItemCount;`, so 64-bit here.
/// Read from the SDK header rather than assumed; the obvious guess (`u32`)
/// would be an ABI mismatch.
type ItemCount = usize;

type EventTargetRef = *mut c_void;
type EventHandlerRef = *mut c_void;
type EventHandlerCallRef = *mut c_void;
type EventRef = *mut c_void;
type EventHotKeyRef = *mut c_void;

#[repr(C)]
#[derive(Clone, Copy)]
struct EventTypeSpec {
    event_class: u32,
    event_kind: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct EventHotKeyID {
    signature: u32,
    id: u32,
}

type EventHandlerProc = extern "C" fn(EventHandlerCallRef, EventRef, *mut c_void) -> OSStatus;

#[link(name = "Carbon", kind = "framework")]
extern "C" {
    fn GetApplicationEventTarget() -> EventTargetRef;
    fn InstallEventHandler(
        target: EventTargetRef,
        handler: EventHandlerProc,
        num_types: ItemCount,
        list: *const EventTypeSpec,
        user_data: *mut c_void,
        out_ref: *mut EventHandlerRef,
    ) -> OSStatus;
    fn RegisterEventHotKey(
        key_code: u32,
        modifiers: u32,
        id: EventHotKeyID,
        target: EventTargetRef,
        options: u32,
        out_ref: *mut EventHotKeyRef,
    ) -> OSStatus;
    fn UnregisterEventHotKey(hot_key: EventHotKeyRef) -> OSStatus;
    fn IsSecureEventInputEnabled() -> u8;
}

/// `'keyb'` — `kEventClassKeyboard`.
const K_EVENT_CLASS_KEYBOARD: u32 = 0x6B65_7962;
/// `kEventHotKeyPressed`.
const K_EVENT_HOT_KEY_PRESSED: u32 = 5;

// Carbon modifier bits (`Events.h`). These are NOT the CGEventFlags bits.
const CONTROL_KEY: u32 = 0x1000;
const OPTION_KEY: u32 = 0x0800;
const SHIFT_KEY: u32 = 0x0200;

/// `kVK_ANSI_P`. Positional and layout-independent, same basis as the
/// capture-macos keycode table.
const KVK_ANSI_P: u32 = 0x23;

/// Bumped by the Carbon callback. An atomic because the callback is plain C
/// with no way to carry Rust state safely, and this is the whole payload.
static FIRE_COUNT: AtomicU32 = AtomicU32::new(0);
/// Secure-input state sampled *inside* the callback, so a fire during secure
/// input is distinguishable after the fact.
static FIRED_DURING_SECURE_INPUT: AtomicU32 = AtomicU32::new(0);

extern "C" fn hot_key_handler(
    _call_ref: EventHandlerCallRef,
    _event: EventRef,
    _user_data: *mut c_void,
) -> OSStatus {
    FIRE_COUNT.fetch_add(1, Ordering::SeqCst);
    // SAFETY: no arguments, no preconditions — a global state read.
    if unsafe { IsSecureEventInputEnabled() } != 0 {
        FIRED_DURING_SECURE_INPUT.fetch_add(1, Ordering::SeqCst);
    }
    // noErr: claim the event. Returning eventNotHandledErr would pass it on.
    0
}

fn main() {
    let Some(mtm) = MainThreadMarker::new() else {
        eprintln!("probe must run on the main thread");
        std::process::exit(2);
    };

    // Mimic `platform::init_app_shell()` exactly: Accessory policy, then
    // `finishLaunching`, and never `[NSApp run]`.
    let app = NSApplication::sharedApplication(mtm);
    let _ = app.setActivationPolicy(NSApplicationActivationPolicy::Accessory);
    #[allow(deprecated)]
    app.finishLaunching();

    let mut handler_ref: EventHandlerRef = std::ptr::null_mut();
    let spec = EventTypeSpec {
        event_class: K_EVENT_CLASS_KEYBOARD,
        event_kind: K_EVENT_HOT_KEY_PRESSED,
    };
    // SAFETY: `spec` outlives the call (Carbon copies the list); the handler is
    // a plain `extern "C"` fn with the documented signature; out-param is a
    // valid local.
    let install = unsafe {
        InstallEventHandler(
            GetApplicationEventTarget(),
            hot_key_handler,
            1,
            &spec,
            std::ptr::null_mut(),
            &mut handler_ref,
        )
    };
    println!("InstallEventHandler -> {install} (0 = noErr)");

    let mut hot_key: EventHotKeyRef = std::ptr::null_mut();
    // SAFETY: documented signature; `id` is passed by value; out-param valid.
    let register = unsafe {
        RegisterEventHotKey(
            KVK_ANSI_P,
            CONTROL_KEY | OPTION_KEY | SHIFT_KEY,
            EventHotKeyID {
                signature: u32::from_be_bytes(*b"glbr"),
                id: 1,
            },
            GetApplicationEventTarget(),
            0,
            &mut hot_key,
        )
    };
    println!("RegisterEventHotKey -> {register} (0 = noErr; -9878 = eventHotKeyExistsErr)");
    if register != 0 {
        eprintln!("registration failed; nothing further to measure");
        std::process::exit(1);
    }

    println!();
    println!("Press Control-Option-Shift-P a few times over the next 60s:");
    println!("  - with THIS terminal frontmost");
    println!("  - with another app frontmost (Q2: it is a global chord)");
    println!("  - into a text field, and watch for a stray 'p' (Q3: consumed?)");
    println!("  - at a password prompt if you want Q4 (secure input)");
    println!();

    // Mimic the pump: our own bounded run-loop pass plus a hand drain of
    // NSEvents. Deliberately NOT `[NSApp run]` — that is the whole question.
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut last_report = 0;
    while Instant::now() < deadline {
        objc2::rc::autoreleasepool(|_| {
            // SAFETY: reading a framework-provided extern static; Foundation
            // initializes its run-loop mode constants before any code here runs.
            let mode = unsafe { NSDefaultRunLoopMode };
            let distant_past = NSDate::distantPast();
            while let Some(event) = app.nextEventMatchingMask_untilDate_inMode_dequeue(
                NSEventMask::Any,
                Some(&distant_past),
                mode,
                true,
            ) {
                app.sendEvent(&event);
            }
        });

        // The pump's own cadence.
        std::thread::sleep(Duration::from_millis(50));

        let fired = FIRE_COUNT.load(Ordering::SeqCst);
        if fired != last_report {
            let secure = FIRED_DURING_SECURE_INPUT.load(Ordering::SeqCst);
            println!("  chord fired: {fired} (of which during secure input: {secure})");
            last_report = fired;
        }
    }

    // SAFETY: `hot_key` is the live registration from above.
    let _ = unsafe { UnregisterEventHotKey(hot_key) };

    let fired = FIRE_COUNT.load(Ordering::SeqCst);
    let secure = FIRED_DURING_SECURE_INPUT.load(Ordering::SeqCst);
    println!();
    println!("== result ==");
    println!(
        "Q1 fires under the manual drain (no [NSApp run]): {}",
        if fired > 0 { "YES" } else { "NO" }
    );
    println!("   total fires: {fired}");
    println!("Q4 fired while secure input active: {secure}");
    println!("Q2/Q3 are answered by how you pressed it (see the notes above).");
    if fired == 0 {
        println!();
        println!("NO fires means Carbon hot keys need an event loop this pump does not run.");
        println!("That invalidates the mechanism choice; do not implement on top of it.");
    }
}
