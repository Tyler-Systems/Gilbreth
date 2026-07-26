//! `secure_input` sensitive context (the macOS TCC aND_STREAM_RULES...:
//! Keyboard+Mouse amendment). `IsSecureEventInputEnabled()` is a public
//! HIToolbox C function (Carbon framework, no permission): while secure
//! event input is active, macOS itself withholds key events from listen-only
//! taps system-wide, so capture receives NO keystrokes during password entry
//! (OS-enforced fail-closed). Gilbreth's only job is attribution — it emits
//! `SensitiveContextEntered/Exited { reason: SecureInput }` (the additive
//! core reason, serializing `"secure_input"`) so the quiet period reads as a
//! labeled sensitive context, not an unexplained capture gap.
//!
//! `SecureDesktop` stays Windows-only; neither platform writes the other's
//! reason. Web/other password fields that do not trigger secure input are
//! the AX `kAXSecureTextField` follow-up, not this slice.

use std::time::Instant;

use gilbreth_core::{Captured, EventPayload, SensitiveContextReason, Source};

#[link(name = "Carbon", kind = "framework")]
extern "C" {
    // Carbon/HIToolbox, public since 10.0. Returns a `Boolean`
    // (`unsigned char`); read as u8 and compare so a non-0/1 value can never
    // become an invalid Rust `bool`.
    fn IsSecureEventInputEnabled() -> u8;
}

/// Live secure-event-input state. No permission, no prompt.
pub(crate) fn secure_input_active() -> bool {
    // SAFETY: no arguments, no preconditions — a pure global state read.
    unsafe { IsSecureEventInputEnabled() != 0 }
}

/// Edge-detects the secure-input state and emits the labeled sensitive
/// context. Generic over the provider so tests drive the edges without the
/// real HIToolbox call. Polled on the pump cadence while the Keyboard stream
/// is enabled (that is when suppression is meaningful); disabling resets the
/// tracked state so a re-enable never fabricates an exit for a period the
/// stream did not observe.
pub(crate) struct SecureInputMonitor<P> {
    provider: P,
    active: bool,
    enabled: bool,
}

impl<P> SecureInputMonitor<P>
where
    P: FnMut() -> bool,
{
    pub(crate) fn new(provider: P) -> Self {
        Self {
            provider,
            active: false,
            enabled: false,
        }
    }

    pub(crate) fn poll(&mut self, now: Instant, enabled: bool, events: &mut Vec<Captured>) {
        if !enabled {
            if self.enabled && self.active {
                // Stream turned off while inside a secure-input span: close it
                // honestly so the context does not appear to hang open, then
                // reset. (No row if it was never open.)
                events.push(exit(now));
            }
            self.active = false;
            self.enabled = false;
            return;
        }
        self.enabled = true;

        let now_active = (self.provider)();
        if now_active == self.active {
            return;
        }
        self.active = now_active;
        events.push(if now_active { entered(now) } else { exit(now) });
    }
}

fn entered(now: Instant) -> Captured {
    Captured::new(
        Source::System,
        now,
        EventPayload::SensitiveContextEntered {
            reason: SensitiveContextReason::SecureInput,
        },
    )
}

fn exit(now: Instant) -> Captured {
    Captured::new(
        Source::System,
        now,
        EventPayload::SensitiveContextExited {
            reason: SensitiveContextReason::SecureInput,
        },
    )
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, rc::Rc, time::Instant};

    use super::*;

    fn reasons(events: &[Captured]) -> Vec<&'static str> {
        events.iter().map(|e| e.payload.kind()).collect()
    }

    fn monitor() -> (Rc<Cell<bool>>, SecureInputMonitor<impl FnMut() -> bool>) {
        let state = Rc::new(Cell::new(false));
        let view = state.clone();
        (state, SecureInputMonitor::new(move || view.get()))
    }

    #[test]
    fn enter_and_exit_edges_fire_once_each() {
        let (secure, mut monitor) = monitor();
        let base = Instant::now();
        let mut events = Vec::new();

        monitor.poll(base, true, &mut events);
        assert!(events.is_empty(), "inactive: no edge");

        secure.set(true);
        monitor.poll(base, true, &mut events);
        secure.set(true);
        monitor.poll(base, true, &mut events);
        assert_eq!(
            reasons(&events),
            vec!["sensitive_context_entered"],
            "one enter"
        );

        secure.set(false);
        monitor.poll(base, true, &mut events);
        assert_eq!(
            reasons(&events),
            vec!["sensitive_context_entered", "sensitive_context_exited"]
        );
    }

    #[test]
    fn disabling_the_stream_mid_span_closes_it() {
        let (secure, mut monitor) = monitor();
        let base = Instant::now();
        let mut events = Vec::new();

        secure.set(true);
        monitor.poll(base, true, &mut events);
        assert_eq!(reasons(&events), vec!["sensitive_context_entered"]);

        // Keyboard stream disabled while secure input is still active: the
        // span is closed so it does not hang open.
        monitor.poll(base, false, &mut events);
        assert_eq!(
            reasons(&events),
            vec!["sensitive_context_entered", "sensitive_context_exited"]
        );

        // Re-enable with secure input still active: a fresh enter (the reset
        // means the earlier span does not leak across the disabled gap).
        monitor.poll(base, true, &mut events);
        assert_eq!(
            events.last().unwrap().payload.kind(),
            "sensitive_context_entered"
        );
    }

    #[test]
    fn reason_serializes_as_secure_input() {
        // The additive core string the schema record commits to.
        assert_eq!(SensitiveContextReason::SecureInput.as_str(), "secure input");
        let json = serde_json::to_string(&SensitiveContextReason::SecureInput).unwrap();
        assert_eq!(json, "\"secure_input\"");
    }
}
