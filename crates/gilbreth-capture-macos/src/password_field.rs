//! AX password-field probe (the macOS TCC and stream rules,
//! "AX password-field probe" rules): the Windows sensitive-field semantics
//! ported against `kAXSecureTextField` on the system-wide focused element —
//! confirmed-active flags, an asymmetric probe cache TTL (see below),
//! fail-closed on any probe that cannot answer. Defense in depth: the
//! OS-enforced secure-input suppression (the keyboard slice) remains the
//! load-bearing guarantee; this probe covers password fields that do not
//! engage secure input.
//!
//! Trust interplay (owner-decided matrix cell): the probe needs
//! Accessibility, which is a different grant from the keyboard's Input
//! Monitoring. While Accessibility is missing the keyboard stream stays ON
//! and the probe is OFF-**declared** (edge-logged; the Diagnostics panel
//! surfaces it with the enable path) — the sensitive posture never
//! silently weakens, it is declared. While trusted, a probe that cannot
//! answer (timeout, AX-less app, no readable focused element) treats the
//! keystroke as sensitive — exactly the Windows fail-closed rule.
//!
//! Ported-with-adaptation, recorded honestly: Windows' monitor re-probes
//! from UIA focus-change *push* events, which lets its key path
//! short-circuit on the confirmed flag unconditionally. macOS has no push
//! here (the crate's no-observer architecture), so an unconditional
//! confirmed fast path would freeze the last answer forever. The poll
//! adaptation: the pump's observed window change (`note_focus`) is the
//! focus event — it probes and resolves the transition immediately, so
//! enter/exit rows land at the switch exactly as on Windows — and a cached
//! answer expires on a TTL so a within-window focus change onto (or off) a
//! password field is caught by the next emitting keystroke after expiry.
//! The TTL is **asymmetric** (owner decision 2026-07-12): a not-secure
//! answer — the one direction that fails *open* — expires in
//! [`NOT_SECURE_PROBE_CACHE_TTL`] (a sub-second cadence), so a
//! non-secure→secure within-window switch leaks only what fits in that
//! window — a keystroke or two at typical rates, a few more at burst
//! cadence (the bound is the time window, not a key count);
//! a secure answer keeps the full [`PROBE_CACHE_TTL`] because a stale one
//! only over-redacts. A `kAXFocusedUIElementChanged` observer would close
//! the residual entirely and stays the recorded follow-up.
//!
//! Honest-exit rule (over-redaction diagnosis O1, 2026-07-13): a
//! *window-change* probe that cannot answer closes an open confirmed
//! span — the span was confirmed in the previous window and must not
//! silently outlive it (the Day-2 soak found spans frozen open for hours
//! by apps whose probes never answer). Redaction itself is untouched: the
//! unresolved gate stays up and fails closed. Within one window a failing
//! probe still keeps the confirmed span — there the field may genuinely
//! still hold focus, and fail-closed keeps both the redaction and the
//! record.
//!
//! Assistive-activation announce (O3-pair adoption amendments in the TCC
//! record, 2026-07-14): apps whose probes deterministically fail — the
//! Chromium/Electron lazy-activation class — get announced to
//! (`AXManualAccessibility = true` through [`SecureFieldSource::announce`])
//! so their probes can start answering. The monitor owns the trigger: a
//! per-app count of unanswered probes that survives focus-away stints,
//! resets on that app's first definitive answer, and fires the announce on
//! the unresolved-WARN cadence (first at [`UNRESOLVED_STREAK_FIRST_WARN`],
//! then sparsely — the repeats are the retry ladder for a write that raced
//! an app hang). Behavior-triggered only, never app identity; redaction
//! stays fail-closed until the app actually answers, and liveness-off
//! edges retract every announcement (posture restore). The trigger needs
//! frontmost attribution (pids arrive from the foreground poller): with
//! the Foreground stream toggled off it is deliberately inert — Gilbreth
//! does not consult frontmost identity the user paused — and wholesale
//! fail-closed redaction stands, exactly the pre-adoption posture.

use std::time::{Duration, Instant};

use gilbreth_core::{CaptureControls, Captured, EventPayload, SensitiveContextReason, Source};
use tracing::{debug, info, warn};

use crate::ax::{SecureFieldProbe, SecureFieldSource};
use crate::foreground::TRUST_REPROBE_INTERVAL;

/// Cache TTL for a **confirmed-secure** answer: the ported Windows 2 s. A
/// stale secure answer only *over*-redacts (it keeps redacting a field that
/// stopped being secure) — the conservative, fail-closed direction — so it
/// keeps the full window.
pub(crate) const PROBE_CACHE_TTL: Duration = Duration::from_secs(2);

/// Unresolved-streak visibility (over-redaction diagnosis O1): a deterministically
/// unanswerable focus — Chromium-family apps never materialize their
/// accessibility tree for a passive reader — redacts every keystroke at
/// debug level, which cost two soak days of DB forensics to notice. The
/// streak counts consecutive unanswered probes since the last definitive
/// answer; warn once when it first sustains, then sparsely.
const UNRESOLVED_STREAK_FIRST_WARN: u64 = 25;
const UNRESOLVED_STREAK_WARN_EVERY: u64 = 1000;

fn unresolved_streak_warns(streak: u64) -> bool {
    streak == UNRESOLVED_STREAK_FIRST_WARN
        || (streak > UNRESOLVED_STREAK_FIRST_WARN
            && (streak - UNRESOLVED_STREAK_FIRST_WARN).is_multiple_of(UNRESOLVED_STREAK_WARN_EVERY))
}

/// Cache TTL for a **not-secure** answer: deliberately much shorter than
/// [`PROBE_CACHE_TTL`] (owner decision 2026-07-12, closing the review's
/// poll-vs-push residual). macOS has no within-window focus push, so a
/// non-secure→secure focus change *inside one window* is invisible to the
/// window-id poller; a stale not-secure answer is the one direction that
/// fails *open* — it would emit password keystrokes unredacted until it
/// expired. Bounding the not-secure TTL to one sub-second AX cadence caps
/// that leak to ~a keystroke or two instead of 2 s. The cost is only more
/// frequent probes while typing in a genuinely non-secure field, and each
/// is cheap on a responsive app — a hung app returns `CannotAnswer` →
/// fail-closed and never populates the cache, so this TTL never gates a
/// slow probe. (The proper fix, a `kAXFocusedUIElementChanged` observer
/// that eliminates the residual entirely, stays the recorded follow-up.)
pub(crate) const NOT_SECURE_PROBE_CACHE_TTL: Duration = Duration::from_millis(250);

/// Pump-side trust state for the probe (the WindowsStreamTrust policy with
/// probe-specific declarations): probe Accessibility on keyboard-enable
/// edges; while wanted-but-untrusted re-probe every
/// [`TRUST_REPROBE_INTERVAL`]; while trusted, revocation arrives as
/// `APIDisabled` from the probe reads themselves.
pub(crate) struct ProbeTrust {
    trusted: bool,
    wanted_last: bool,
    last_probe: Option<Instant>,
}

impl ProbeTrust {
    pub(crate) fn new() -> Self {
        Self {
            trusted: false,
            wanted_last: false,
            last_probe: None,
        }
    }

    pub(crate) fn refresh(
        &mut self,
        now: Instant,
        wanted: bool,
        probe: &mut impl FnMut() -> bool,
    ) -> bool {
        if !wanted {
            self.wanted_last = false;
            return false;
        }
        let enable_edge = !self.wanted_last;
        self.wanted_last = true;

        let reprobe_due = !self.trusted
            && self
                .last_probe
                .is_none_or(|last| now.saturating_duration_since(last) >= TRUST_REPROBE_INTERVAL);
        if enable_edge || reprobe_due {
            self.last_probe = Some(now);
            let trusted = probe();
            if trusted != self.trusted || enable_edge {
                log_probe_trust(trusted);
            }
            self.trusted = trusted;
        }
        self.trusted
    }

    pub(crate) fn on_api_disabled(&mut self, now: Instant) {
        if self.trusted {
            warn!(
                "password-field probe degraded to off-declared: Accessibility was revoked \
                 mid-run (keyboard capture continues; OS secure-input suppression still \
                 applies; re-probing for a re-grant every {}s)",
                TRUST_REPROBE_INTERVAL.as_secs()
            );
        }
        self.trusted = false;
        self.last_probe = Some(now);
    }
}

fn log_probe_trust(trusted: bool) {
    if trusted {
        info!("password-field probe active: Accessibility is granted");
    } else {
        info!(
            "password-field probe off (declared): Accessibility is not granted — keyboard \
             capture continues, protected by OS secure-input suppression; the AX probe \
             (defense in depth for fields that do not engage secure input) needs \
             System Settings > Privacy & Security > Accessibility; re-probing every {}s",
            TRUST_REPROBE_INTERVAL.as_secs()
        );
    }
}

#[derive(Clone, Copy)]
struct ProbeCache {
    window_id: u64,
    is_password: bool,
    focus_generation: u64,
    resolved_at: Instant,
}

/// The Windows sensitive-field logic, poll-adapted (module doc): window
/// changes probe immediately; keystrokes answer from the TTL-bounded cache
/// and probe on expiry; every unanswerable probe fails closed; confirmed
/// enter/exit rows emit once per transition through the shared core flags.
pub(crate) struct PasswordFieldMonitor {
    cache: Option<ProbeCache>,
    last_window_id: Option<u64>,
    probe_was_live: bool,
    /// The current focus has no definitive answer yet (fresh transition,
    /// fail-closed probe): keys redact and every key re-probes. Monitor-
    /// owned rather than read back from the shared gate flag, because the
    /// shared flag also means "confirmed in a password field" (Windows
    /// semantics, kept for cross-surface visibility) — a confirmed answer
    /// is resolved, not unresolved, and must serve from the cache.
    unresolved: bool,
    /// Consecutive probes without a definitive answer (module doc on the
    /// streak WARN); reset by any `Answered`, by liveness edges, and by
    /// revocation (which carries its own WARN).
    unresolved_streak: u64,
    /// Per-app unanswered-probe counts (the O3 announce trigger): unlike
    /// the global streak above, an entry survives focus-away stints and
    /// only ITS app's definitive answer clears it — a deterministically
    /// failing app accumulates to the announce threshold even when
    /// answerable apps interleave. Liveness edges and revocation clear
    /// all. An answer removes the entry; an app that exits mid-failure
    /// leaves its count until a liveness edge, so a reused pid can
    /// inherit it (accepted cell in the adoption amendments — the write
    /// is idempotent and benign). Same growth class as the reader's
    /// app-element cache.
    app_unanswered: Vec<(i32, u64)>,
}

pub(crate) struct RedactDecision {
    pub(crate) redact: bool,
    pub(crate) api_disabled: bool,
}

impl PasswordFieldMonitor {
    pub(crate) fn new() -> Self {
        Self {
            cache: None,
            last_window_id: None,
            probe_was_live: false,
            unresolved: false,
            unresolved_streak: 0,
            app_unanswered: Vec::new(),
        }
    }

    /// The pump calls this once per pass with "Accessibility trusted AND
    /// keyboard wanted". Both edges reset the probe's state so it never
    /// lingers across a liveness change: going live starts unresolved
    /// (gate up — the next emitting key probes); going off clears the gate
    /// AND the confirmed flag, emitting the exit row if a confirmed
    /// password context was open — the off-declared probe stops labeling,
    /// it does not freeze a stale sensitive period. The off edge also
    /// retracts every assistive-activation announcement (O3 posture
    /// restore: keyboard off, capture paused, or trust revoked — in the
    /// revoked case the clear write fails harmlessly downstream).
    pub(crate) fn on_probe_liveness(
        &mut self,
        live: bool,
        now: Instant,
        controls: &CaptureControls,
        source: &mut impl SecureFieldSource,
        events: &mut Vec<Captured>,
    ) {
        if live == self.probe_was_live {
            return;
        }
        self.probe_was_live = live;
        self.cache = None;
        self.unresolved_streak = 0;
        self.app_unanswered.clear();
        if live {
            self.unresolved = true;
            controls.set_password_field_gate(true);
        } else {
            source.retract_all();
            self.unresolved = false;
            controls.set_password_field_gate(false);
            let was_confirmed = controls
                .password_field_confirmed_active_flag()
                .swap(false, std::sync::atomic::Ordering::SeqCst);
            if was_confirmed {
                events.push(Captured::new(
                    Source::System,
                    now,
                    EventPayload::SensitiveContextExited {
                        reason: SensitiveContextReason::PasswordField,
                    },
                ));
            }
        }
    }

    /// The pump calls this once per pass with the currently-focused window
    /// id and its app's pid (the O3 announce scope). An observed focus
    /// change bumps the generation and — while the probe is live —
    /// resolves the new focus immediately (the Windows focus-event probe:
    /// enter/exit rows land at the transition, not at the next
    /// keystroke). Returns true when the probe reported Accessibility
    /// revocation.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn note_focus(
        &mut self,
        window_id: Option<u64>,
        app_pid: Option<i32>,
        probe_live: bool,
        now: Instant,
        controls: &CaptureControls,
        source: &mut impl SecureFieldSource,
        events: &mut Vec<Captured>,
    ) -> bool {
        if window_id == self.last_window_id {
            return false;
        }
        self.last_window_id = window_id;
        controls.mark_password_focus_changed();
        if !probe_live {
            return false;
        }
        self.cache = None;
        self.unresolved = true;
        controls.set_password_field_gate(true);
        debug!("password-field gate set while focused window is unresolved");
        let decision = self.resolve(window_id, app_pid, now, controls, source, events);
        if self.unresolved {
            // Over-redaction diagnosis O1: a confirmed span must not
            // silently outlive the window it was confirmed in. This
            // window change could not be resolved (the new focus answers
            // nothing — the Chromium lazy-accessibility shape), so the
            // span record closes honestly at the transition while
            // redaction continues under the unresolved gate. The flag
            // swap keeps the exit single: the liveness-off path and a
            // later answered probe both gate on the same flag.
            let was_confirmed = controls
                .password_field_confirmed_active_flag()
                .swap(false, std::sync::atomic::Ordering::SeqCst);
            if was_confirmed {
                events.push(Captured::new(
                    Source::System,
                    now,
                    EventPayload::SensitiveContextExited {
                        reason: SensitiveContextReason::PasswordField,
                    },
                ));
            }
        }
        decision.api_disabled
    }

    /// Decide whether this key-down's content must be redacted: cache
    /// answer while fresh, probe on gate/miss/expiry, fail closed on
    /// anything unanswerable — the Windows key-path ordering with the
    /// TTL bounding every answer (module doc).
    pub(crate) fn redact_key_at(
        &mut self,
        window_id: Option<u64>,
        app_pid: Option<i32>,
        now: Instant,
        controls: &CaptureControls,
        source: &mut impl SecureFieldSource,
        events: &mut Vec<Captured>,
    ) -> RedactDecision {
        if !self.unresolved {
            if let Some(cached) = window_id.and_then(|id| self.cached(id, now, controls)) {
                return RedactDecision {
                    redact: cached,
                    api_disabled: false,
                };
            }
        }
        self.resolve(window_id, app_pid, now, controls, source, events)
    }

    fn app_unanswered_bump(&mut self, pid: i32) -> u64 {
        if let Some((_, count)) = self
            .app_unanswered
            .iter_mut()
            .find(|(cached, _)| *cached == pid)
        {
            *count += 1;
            return *count;
        }
        self.app_unanswered.push((pid, 1));
        1
    }

    fn app_unanswered_clear(&mut self, pid: i32) {
        self.app_unanswered.retain(|(cached, _)| *cached != pid);
    }

    fn resolve(
        &mut self,
        window_id: Option<u64>,
        app_pid: Option<i32>,
        now: Instant,
        controls: &CaptureControls,
        source: &mut impl SecureFieldSource,
        events: &mut Vec<Captured>,
    ) -> RedactDecision {
        match source.probe(app_pid) {
            SecureFieldProbe::Answered { is_secure } => {
                self.unresolved = false;
                self.unresolved_streak = 0;
                if let Some(pid) = app_pid {
                    self.app_unanswered_clear(pid);
                }
                if let Some(window_id) = window_id {
                    self.cache = Some(ProbeCache {
                        window_id,
                        is_password: is_secure,
                        focus_generation: controls.password_focus_generation(),
                        resolved_at: now,
                    });
                }
                emit_confirmed_sample(is_secure, now, controls, events);
                RedactDecision {
                    redact: is_secure,
                    api_disabled: false,
                }
            }
            SecureFieldProbe::CannotAnswer => {
                // Fail closed: an unanswerable focus is treated as
                // sensitive, and the gate stays up so the next key
                // re-probes rather than trusting a stale cache.
                self.cache = None;
                self.unresolved = true;
                controls.set_password_field_gate(true);
                self.unresolved_streak += 1;
                if unresolved_streak_warns(self.unresolved_streak) {
                    warn!(
                        streak = self.unresolved_streak,
                        "password-field probe has not answered for a sustained streak: \
                         emitting keystrokes in this stretch are redacted fail-closed \
                         (defense in depth; OS secure-input suppression is unaffected). \
                         Known cause: apps that never materialize an accessibility tree \
                         for passive readers — on this signal Gilbreth announces itself \
                         to the focused app when frontmost attribution is available \
                         (O3 pair; inert while the Foreground stream is off); a streak \
                         sustained past an announce means the app did not activate — \
                         see the over-redaction diagnosis"
                    );
                }
                // The O3 announce trigger (module doc): the per-app count
                // — not the global streak — decides, so interleaved
                // answerable apps cannot mask a deterministically failing
                // one. Same first/sparse cadence as the WARN; the sparse
                // repeats retry a write that may have raced an app hang.
                // pid 0 is the poller's no-real-pid sentinel — never
                // account to or announce at it; and no pid at all (the
                // Foreground stream toggled off) leaves the trigger
                // deliberately inert (recorded cell in the adoption
                // amendments: no frontmost consultation the user paused).
                if let Some(pid) = app_pid.filter(|&pid| pid > 0) {
                    let app_count = self.app_unanswered_bump(pid);
                    if unresolved_streak_warns(app_count) {
                        info!(
                            pid,
                            unanswered = app_count,
                            "deterministic probe failure threshold reached for this app; \
                             requesting assistive-activation announce (O3 pair)"
                        );
                        source.announce(pid);
                    }
                }
                RedactDecision {
                    redact: true,
                    api_disabled: false,
                }
            }
            SecureFieldProbe::ApiDisabled => {
                // Revocation: redact this keystroke (the probe could not
                // answer) and tell the caller so trust degrades to
                // off-declared for subsequent keys. The revocation WARN
                // is the visibility here; the streak resets — and the
                // per-app counts with it (the liveness-off edge that
                // follows also retracts announcements).
                self.cache = None;
                self.unresolved = true;
                self.unresolved_streak = 0;
                self.app_unanswered.clear();
                controls.set_password_field_gate(true);
                RedactDecision {
                    redact: true,
                    api_disabled: true,
                }
            }
        }
    }

    fn cached(&self, window_id: u64, now: Instant, controls: &CaptureControls) -> Option<bool> {
        let cached = self.cache?;
        // Asymmetric TTL: a not-secure answer (the fail-open direction)
        // expires far sooner than a secure one, so a within-window switch
        // onto a password field is re-probed within a keystroke or two
        // rather than up to 2 s.
        let ttl = if cached.is_password {
            PROBE_CACHE_TTL
        } else {
            NOT_SECURE_PROBE_CACHE_TTL
        };
        if cached.window_id == window_id
            && cached.focus_generation == controls.password_focus_generation()
            && now.saturating_duration_since(cached.resolved_at) <= ttl
        {
            Some(cached.is_password)
        } else {
            None
        }
    }
}

/// Set the shared flags and emit the PasswordField enter/exit row once per
/// confirmed transition (the Windows `emit_confirmed_password_field_sample`
/// through the mac pump's pending-events path: rows gate at send, and row
/// loss under channel backpressure is counted like every stream's — the
/// flags themselves always update, so keystroke redaction never depends on
/// row delivery).
fn emit_confirmed_sample(
    is_password: bool,
    now: Instant,
    controls: &CaptureControls,
    events: &mut Vec<Captured>,
) {
    controls.set_password_field_gate(is_password);
    let previous = controls
        .password_field_confirmed_active_flag()
        .swap(is_password, std::sync::atomic::Ordering::SeqCst);
    if previous == is_password {
        return;
    }
    let payload = if is_password {
        EventPayload::SensitiveContextEntered {
            reason: SensitiveContextReason::PasswordField,
        }
    } else {
        EventPayload::SensitiveContextExited {
            reason: SensitiveContextReason::PasswordField,
        }
    };
    events.push(Captured::new(Source::System, now, payload));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn controls() -> CaptureControls {
        CaptureControls::all_enabled()
    }

    fn probe_of(outcome: SecureFieldProbe) -> impl FnMut() -> SecureFieldProbe {
        move || outcome
    }

    fn counted_probe(
        outcome: SecureFieldProbe,
    ) -> (
        std::rc::Rc<std::cell::Cell<u32>>,
        impl FnMut() -> SecureFieldProbe,
    ) {
        let count = std::rc::Rc::new(std::cell::Cell::new(0));
        let view = count.clone();
        (count, move || {
            view.set(view.get() + 1);
            outcome
        })
    }

    /// Records the O3-pair calls a monitor makes; probes always return the
    /// fixed outcome (swap `outcome` mid-test to script transitions).
    struct Scripted {
        outcome: SecureFieldProbe,
        announced: Vec<i32>,
        retract_alls: u32,
    }

    impl Scripted {
        fn new(outcome: SecureFieldProbe) -> Self {
            Self {
                outcome,
                announced: Vec::new(),
                retract_alls: 0,
            }
        }
    }

    impl SecureFieldSource for Scripted {
        fn probe(&mut self, _pid: Option<i32>) -> SecureFieldProbe {
            self.outcome
        }
        fn announce(&mut self, pid: i32) {
            self.announced.push(pid);
        }
        fn retract_all(&mut self) {
            self.retract_alls += 1;
        }
    }

    /// A live monitor focused on `window_id` whose focus transition has
    /// been resolved with `outcome` (no app pid: these tests exercise the
    /// cache/flag semantics, not the announce accounting).
    fn focused(
        controls: &CaptureControls,
        window_id: u64,
        outcome: SecureFieldProbe,
        now: Instant,
        events: &mut Vec<Captured>,
    ) -> PasswordFieldMonitor {
        let mut monitor = PasswordFieldMonitor::new();
        monitor.on_probe_liveness(true, now, controls, &mut probe_of(outcome), events);
        monitor.note_focus(
            Some(window_id),
            None,
            true,
            now,
            controls,
            &mut probe_of(outcome),
            events,
        );
        monitor
    }

    #[test]
    fn focus_transition_onto_a_secure_field_labels_and_redacts() {
        let controls = controls();
        let base = Instant::now();
        let mut events = Vec::new();

        // The window switch itself resolves the focus: the entered row
        // lands at the transition (Windows focus-event timing).
        let mut monitor = focused(
            &controls,
            7,
            SecureFieldProbe::Answered { is_secure: true },
            base,
            &mut events,
        );
        assert_eq!(events.len(), 1);
        assert!(matches!(
            events[0].payload,
            EventPayload::SensitiveContextEntered {
                reason: SensitiveContextReason::PasswordField
            }
        ));
        assert!(controls.password_field_confirmed_active());

        // Typing answers from the cache — redacted, no probe, no new rows.
        let (count, mut probe) = counted_probe(SecureFieldProbe::Answered { is_secure: true });
        let decision = monitor.redact_key_at(
            Some(7),
            None,
            base + Duration::from_millis(100),
            &controls,
            &mut probe,
            &mut events,
        );
        assert!(decision.redact);
        assert_eq!(count.get(), 0, "cache answers within the TTL");
        assert_eq!(events.len(), 1, "no repeat row while confirmed");
    }

    #[test]
    fn leaving_the_secure_field_exits_at_the_transition() {
        let controls = controls();
        let base = Instant::now();
        let mut events = Vec::new();

        let mut monitor = focused(
            &controls,
            7,
            SecureFieldProbe::Answered { is_secure: true },
            base,
            &mut events,
        );
        // Focus moves to a plain window: the exit row lands at the switch.
        monitor.note_focus(
            Some(8),
            None,
            true,
            base + Duration::from_millis(100),
            &controls,
            &mut probe_of(SecureFieldProbe::Answered { is_secure: false }),
            &mut events,
        );
        assert_eq!(events.len(), 2);
        assert!(matches!(
            events[1].payload,
            EventPayload::SensitiveContextExited {
                reason: SensitiveContextReason::PasswordField
            }
        ));
        assert!(!controls.password_field_confirmed_active());

        // Steady typing in the plain window: cached, clear, quiet.
        let (count, mut probe) = counted_probe(SecureFieldProbe::Answered { is_secure: false });
        let decision = monitor.redact_key_at(
            Some(8),
            None,
            base + Duration::from_millis(200),
            &controls,
            &mut probe,
            &mut events,
        );
        assert!(!decision.redact);
        assert_eq!(count.get(), 0);
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn a_not_secure_answer_expires_on_the_short_ttl_catching_within_window_secure_switches() {
        let controls = controls();
        let base = Instant::now();
        let mut events = Vec::new();

        // Not-secure window; then a password field gains focus WITHIN the
        // window (no window-id change — the poll cannot see it). The
        // not-secure answer expires on the SHORT TTL, so the switch is
        // caught within a keystroke or two, not up to 2 s.
        let mut monitor = focused(
            &controls,
            7,
            SecureFieldProbe::Answered { is_secure: false },
            base,
            &mut events,
        );
        let (count, mut probe) = counted_probe(SecureFieldProbe::Answered { is_secure: true });

        // Just inside the short TTL: the cached not-secure answer stands.
        let stale = monitor.redact_key_at(
            Some(7),
            None,
            base + NOT_SECURE_PROBE_CACHE_TTL - Duration::from_millis(1),
            &controls,
            &mut probe,
            &mut events,
        );
        assert!(
            !stale.redact,
            "within the short TTL the not-secure answer stands"
        );
        assert_eq!(count.get(), 0);

        // Just past the short TTL — and FAR before the 2 s secure TTL: the
        // now-secure field is re-probed and caught.
        let caught = monitor.redact_key_at(
            Some(7),
            None,
            base + NOT_SECURE_PROBE_CACHE_TTL + Duration::from_millis(1),
            &controls,
            &mut probe,
            &mut events,
        );
        assert_eq!(count.get(), 1, "an expired not-secure cache re-probes");
        assert!(
            caught.redact,
            "the secure field is caught at the short-TTL expiry"
        );
        assert!(
            NOT_SECURE_PROBE_CACHE_TTL * 4 < PROBE_CACHE_TTL,
            "the not-secure TTL is meaningfully tighter than the secure TTL"
        );
        assert!(matches!(
            events.last().expect("entered row").payload,
            EventPayload::SensitiveContextEntered {
                reason: SensitiveContextReason::PasswordField
            }
        ));
    }

    #[test]
    fn a_secure_answer_keeps_the_full_ttl_so_typing_a_password_does_not_re_probe_every_key() {
        // The asymmetry's safe side: a stale SECURE answer only
        // over-redacts, so it keeps the full 2 s window — steady typing in
        // a password field is not re-probed on every keystroke.
        let controls = controls();
        let base = Instant::now();
        let mut events = Vec::new();

        let mut monitor = focused(
            &controls,
            7,
            SecureFieldProbe::Answered { is_secure: true },
            base,
            &mut events,
        );
        let (count, mut probe) = counted_probe(SecureFieldProbe::Answered { is_secure: true });

        // Well past the short not-secure TTL but inside the 2 s secure TTL:
        // the secure answer still stands, no re-probe, still redacting.
        let still = monitor.redact_key_at(
            Some(7),
            None,
            base + NOT_SECURE_PROBE_CACHE_TTL * 4,
            &controls,
            &mut probe,
            &mut events,
        );
        assert!(still.redact, "the secure answer keeps redacting");
        assert_eq!(
            count.get(),
            0,
            "a secure answer is not re-probed on the short TTL"
        );
    }

    #[test]
    fn a_secure_answer_expires_on_the_full_ttl_lifting_redaction_with_an_exit_row() {
        // The secure arm is long, not infinite (tail-review pin): if the
        // Windows-style unconditional confirmed fast path ever came back —
        // the freeze-forever temptation the module doc warns about — a
        // within-window secure→plain move would redact all later typing
        // forever and never emit the exit row, and every other test would
        // still pass. Pin the expiry: just past [`PROBE_CACHE_TTL`] a
        // now-plain field is re-probed, redaction lifts, and the exit row
        // lands.
        let controls = controls();
        let base = Instant::now();
        let mut events = Vec::new();

        let mut monitor = focused(
            &controls,
            7,
            SecureFieldProbe::Answered { is_secure: true },
            base,
            &mut events,
        );
        let (count, mut probe) = counted_probe(SecureFieldProbe::Answered { is_secure: false });

        // Just inside the secure TTL: the cached answer stands, still
        // redacting, no re-probe.
        let still = monitor.redact_key_at(
            Some(7),
            None,
            base + PROBE_CACHE_TTL - Duration::from_millis(1),
            &controls,
            &mut probe,
            &mut events,
        );
        assert!(still.redact, "within the full TTL the secure answer stands");
        assert_eq!(count.get(), 0);

        // Just past it: the plain field is re-probed, redaction lifts, and
        // the PasswordField exit row is emitted.
        let lifted = monitor.redact_key_at(
            Some(7),
            None,
            base + PROBE_CACHE_TTL + Duration::from_millis(1),
            &controls,
            &mut probe,
            &mut events,
        );
        assert_eq!(count.get(), 1, "an expired secure cache re-probes");
        assert!(!lifted.redact, "redaction lifts once the field is plain");
        assert!(matches!(
            events.last().expect("exit row").payload,
            EventPayload::SensitiveContextExited {
                reason: SensitiveContextReason::PasswordField
            }
        ));
    }

    #[test]
    fn unanswerable_probe_fails_closed_and_keeps_probing() {
        let controls = controls();
        let base = Instant::now();
        let mut events = Vec::new();

        let mut monitor = focused(
            &controls,
            7,
            SecureFieldProbe::CannotAnswer,
            base,
            &mut events,
        );
        assert!(controls.password_field_active(), "gate stays up");
        assert!(events.is_empty(), "no confirmed row without an answer");

        // Keys while unresolved: redacted, and each one re-probes.
        let (count, mut probe) = counted_probe(SecureFieldProbe::CannotAnswer);
        let decision = monitor.redact_key_at(
            Some(7),
            None,
            base + Duration::from_millis(50),
            &controls,
            &mut probe,
            &mut events,
        );
        assert!(decision.redact, "cannot-answer is sensitive");
        assert!(!decision.api_disabled);
        assert_eq!(count.get(), 1);

        // The focus finally answers: the gate clears and typing flows.
        let resolved = monitor.redact_key_at(
            Some(7),
            None,
            base + Duration::from_millis(100),
            &controls,
            &mut probe_of(SecureFieldProbe::Answered { is_secure: false }),
            &mut events,
        );
        assert!(!resolved.redact);
        assert!(!controls.password_field_active(), "answer clears the gate");
    }

    #[test]
    fn focus_change_that_cannot_answer_closes_the_confirmed_span_honestly() {
        // O1 pin (over-redaction diagnosis): a real
        // password moment followed by focus moving into an app whose
        // probes never answer used to freeze the confirmed span open for
        // hours — the exit row only landed on a much-later successful
        // not-secure answer. The span closes at the transition; the
        // unresolved gate keeps redacting.
        let controls = controls();
        let base = Instant::now();
        let mut events = Vec::new();

        let mut monitor = focused(
            &controls,
            7,
            SecureFieldProbe::Answered { is_secure: true },
            base,
            &mut events,
        );
        assert_eq!(events.len(), 1);

        monitor.note_focus(
            Some(8),
            None,
            true,
            base + Duration::from_millis(100),
            &controls,
            &mut probe_of(SecureFieldProbe::CannotAnswer),
            &mut events,
        );
        assert_eq!(events.len(), 2, "the exit row lands at the transition");
        assert!(matches!(
            events[1].payload,
            EventPayload::SensitiveContextExited {
                reason: SensitiveContextReason::PasswordField
            }
        ));
        assert!(!controls.password_field_confirmed_active());
        assert!(
            controls.password_field_active(),
            "the unresolved gate stays up"
        );

        // Typing in the unanswerable window: still redacted, no new rows.
        let decision = monitor.redact_key_at(
            Some(8),
            None,
            base + Duration::from_millis(200),
            &controls,
            &mut probe_of(SecureFieldProbe::CannotAnswer),
            &mut events,
        );
        assert!(decision.redact, "fail-closed redaction is untouched");
        assert_eq!(events.len(), 2);

        // A later window that answers not-secure adds no duplicate exit.
        monitor.note_focus(
            Some(9),
            None,
            true,
            base + Duration::from_millis(300),
            &controls,
            &mut probe_of(SecureFieldProbe::Answered { is_secure: false }),
            &mut events,
        );
        assert_eq!(events.len(), 2, "the span already closed at the change");
    }

    #[test]
    fn within_window_cannot_answer_keeps_the_confirmed_span() {
        // The honest-exit rule is scoped to window CHANGES. Confirmed in
        // this window, a later in-window probe failure cannot prove the
        // field released — fail closed keeps the redaction AND the span.
        let controls = controls();
        let base = Instant::now();
        let mut events = Vec::new();

        let mut monitor = focused(
            &controls,
            7,
            SecureFieldProbe::Answered { is_secure: true },
            base,
            &mut events,
        );
        let decision = monitor.redact_key_at(
            Some(7),
            None,
            base + PROBE_CACHE_TTL + Duration::from_millis(1),
            &controls,
            &mut probe_of(SecureFieldProbe::CannotAnswer),
            &mut events,
        );
        assert!(decision.redact);
        assert!(
            controls.password_field_confirmed_active(),
            "the in-window span holds"
        );
        assert_eq!(events.len(), 1, "no exit row without a window change");
    }

    #[test]
    fn unresolved_streak_warns_first_then_sparsely_and_resets_on_answers() {
        assert!(!unresolved_streak_warns(0));
        assert!(!unresolved_streak_warns(1));
        assert!(!unresolved_streak_warns(UNRESOLVED_STREAK_FIRST_WARN - 1));
        assert!(unresolved_streak_warns(UNRESOLVED_STREAK_FIRST_WARN));
        assert!(!unresolved_streak_warns(UNRESOLVED_STREAK_FIRST_WARN + 1));
        assert!(unresolved_streak_warns(
            UNRESOLVED_STREAK_FIRST_WARN + UNRESOLVED_STREAK_WARN_EVERY
        ));
        assert!(unresolved_streak_warns(
            UNRESOLVED_STREAK_FIRST_WARN + 2 * UNRESOLVED_STREAK_WARN_EVERY
        ));

        // The counter accumulates across failing probes and resets on a
        // definitive answer (and on liveness edges, covered elsewhere).
        let controls = controls();
        let base = Instant::now();
        let mut events = Vec::new();
        let mut monitor = focused(
            &controls,
            7,
            SecureFieldProbe::CannotAnswer,
            base,
            &mut events,
        );
        assert_eq!(monitor.unresolved_streak, 1, "the focus probe counts");
        monitor.redact_key_at(
            Some(7),
            None,
            base + Duration::from_millis(50),
            &controls,
            &mut probe_of(SecureFieldProbe::CannotAnswer),
            &mut events,
        );
        assert_eq!(monitor.unresolved_streak, 2);
        monitor.redact_key_at(
            Some(7),
            None,
            base + Duration::from_millis(100),
            &controls,
            &mut probe_of(SecureFieldProbe::Answered { is_secure: false }),
            &mut events,
        );
        assert_eq!(monitor.unresolved_streak, 0, "an answer resets the streak");
    }

    /// A live monitor whose window-change probe onto (`window_id`,
    /// `app_pid`) already ran against `source` — the announce-accounting
    /// twin of [`focused`].
    fn focused_app(
        controls: &CaptureControls,
        window_id: u64,
        app_pid: i32,
        source: &mut Scripted,
        now: Instant,
        events: &mut Vec<Captured>,
    ) -> PasswordFieldMonitor {
        let mut monitor = PasswordFieldMonitor::new();
        monitor.on_probe_liveness(true, now, controls, source, events);
        monitor.note_focus(
            Some(window_id),
            Some(app_pid),
            true,
            now,
            controls,
            source,
            events,
        );
        monitor
    }

    /// One emitting-key probe `secs` after `base` (every step past both
    /// TTLs so a cached answer never masks a probe).
    #[allow(clippy::too_many_arguments)]
    fn key_probe(
        monitor: &mut PasswordFieldMonitor,
        window_id: u64,
        app_pid: i32,
        base: Instant,
        secs: u64,
        controls: &CaptureControls,
        source: &mut Scripted,
        events: &mut Vec<Captured>,
    ) {
        monitor.redact_key_at(
            Some(window_id),
            Some(app_pid),
            base + Duration::from_secs(secs),
            controls,
            source,
            events,
        );
    }

    #[test]
    fn deterministic_per_app_failures_announce_on_the_warn_cadence() {
        // O3-pair pin (TCC adoption amendments, 2026-07-14): the 25th
        // unanswered probe for one app announces exactly once, and the
        // sparse retry fires only at the next cadence point — not on
        // every failure past the threshold.
        let controls = controls();
        let base = Instant::now();
        let mut events = Vec::new();
        let mut source = Scripted::new(SecureFieldProbe::CannotAnswer);

        // The focus-change probe is failure #1; keys accumulate the rest.
        let mut monitor = focused_app(&controls, 7, 42, &mut source, base, &mut events);
        for step in 0..(UNRESOLVED_STREAK_FIRST_WARN - 2) {
            key_probe(
                &mut monitor,
                7,
                42,
                base,
                step + 1,
                &controls,
                &mut source,
                &mut events,
            );
        }
        assert!(
            source.announced.is_empty(),
            "one short of the threshold announces nothing"
        );
        key_probe(
            &mut monitor,
            7,
            42,
            base,
            100,
            &controls,
            &mut source,
            &mut events,
        );
        assert_eq!(
            source.announced,
            vec![42],
            "the threshold-crossing failure announces the failing app"
        );

        for step in 0..(UNRESOLVED_STREAK_WARN_EVERY - 1) {
            key_probe(
                &mut monitor,
                7,
                42,
                base,
                200 + step,
                &controls,
                &mut source,
                &mut events,
            );
        }
        assert_eq!(
            source.announced,
            vec![42],
            "no re-announce between cadence points"
        );
        key_probe(
            &mut monitor,
            7,
            42,
            base,
            5000,
            &controls,
            &mut source,
            &mut events,
        );
        assert_eq!(
            source.announced,
            vec![42, 42],
            "the sparse cadence retries the announce (a write may have raced an app hang)"
        );
    }

    #[test]
    fn an_answer_from_the_app_resets_its_announce_accounting() {
        // An app that answers is not deterministically failing: 24
        // failures, one answer, 24 more failures — never announced; the
        // next uninterrupted run to 25 announces.
        let controls = controls();
        let base = Instant::now();
        let mut events = Vec::new();
        let mut source = Scripted::new(SecureFieldProbe::CannotAnswer);

        let mut monitor = focused_app(&controls, 7, 42, &mut source, base, &mut events);
        for step in 0..(UNRESOLVED_STREAK_FIRST_WARN - 2) {
            key_probe(
                &mut monitor,
                7,
                42,
                base,
                step + 1,
                &controls,
                &mut source,
                &mut events,
            );
        }
        source.outcome = SecureFieldProbe::Answered { is_secure: false };
        key_probe(
            &mut monitor,
            7,
            42,
            base,
            100,
            &controls,
            &mut source,
            &mut events,
        );
        source.outcome = SecureFieldProbe::CannotAnswer;
        for step in 0..(UNRESOLVED_STREAK_FIRST_WARN - 1) {
            key_probe(
                &mut monitor,
                7,
                42,
                base,
                200 + step,
                &controls,
                &mut source,
                &mut events,
            );
        }
        assert!(
            source.announced.is_empty(),
            "the answer reset the count: 24+24 failures around it stay quiet"
        );
        key_probe(
            &mut monitor,
            7,
            42,
            base,
            400,
            &controls,
            &mut source,
            &mut events,
        );
        assert_eq!(
            source.announced,
            vec![42],
            "25 uninterrupted failures after the reset announce"
        );
    }

    #[test]
    fn announce_accounting_is_per_app_and_survives_focus_stints() {
        // The count is per-app and cumulative across stints: interleaved
        // answers from ANOTHER app must not mask the deterministically
        // failing one, and the announce names the failing pid only.
        let controls = controls();
        let base = Instant::now();
        let mut events = Vec::new();
        let mut source = Scripted::new(SecureFieldProbe::CannotAnswer);

        // Stint one on app 42: the focus probe + 19 keys = 20 failures.
        let mut monitor = focused_app(&controls, 7, 42, &mut source, base, &mut events);
        for step in 0..19 {
            key_probe(
                &mut monitor,
                7,
                42,
                base,
                step + 1,
                &controls,
                &mut source,
                &mut events,
            );
        }
        // Away-stint on app 9, which answers cleanly.
        source.outcome = SecureFieldProbe::Answered { is_secure: false };
        monitor.note_focus(
            Some(8),
            Some(9),
            true,
            base + Duration::from_secs(100),
            &controls,
            &mut source,
            &mut events,
        );
        // Back on app 42: the count resumes at 20, so the focus probe
        // (21) plus three keys stay quiet and the fifth failure of this
        // stint crosses 25.
        source.outcome = SecureFieldProbe::CannotAnswer;
        monitor.note_focus(
            Some(7),
            Some(42),
            true,
            base + Duration::from_secs(200),
            &controls,
            &mut source,
            &mut events,
        );
        for step in 0..3 {
            key_probe(
                &mut monitor,
                7,
                42,
                base,
                300 + step,
                &controls,
                &mut source,
                &mut events,
            );
        }
        assert!(
            source.announced.is_empty(),
            "24 cumulative failures for app 42 stay below the threshold"
        );
        key_probe(
            &mut monitor,
            7,
            42,
            base,
            400,
            &controls,
            &mut source,
            &mut events,
        );
        assert_eq!(
            source.announced,
            vec![42],
            "the failing app is announced; the answering app never is"
        );
    }

    #[test]
    fn liveness_off_retracts_announcements_and_resets_the_accounting() {
        // Posture restore (O3 adoption amendments): the off edge retracts
        // every announcement, and a fresh live period rebuilds the count
        // from zero before announcing again.
        let controls = controls();
        let base = Instant::now();
        let mut events = Vec::new();
        let mut source = Scripted::new(SecureFieldProbe::CannotAnswer);

        let mut monitor = focused_app(&controls, 7, 42, &mut source, base, &mut events);
        for step in 0..(UNRESOLVED_STREAK_FIRST_WARN - 1) {
            key_probe(
                &mut monitor,
                7,
                42,
                base,
                step + 1,
                &controls,
                &mut source,
                &mut events,
            );
        }
        assert_eq!(source.announced, vec![42]);
        assert_eq!(source.retract_alls, 0);

        monitor.on_probe_liveness(
            false,
            base + Duration::from_secs(100),
            &controls,
            &mut source,
            &mut events,
        );
        assert_eq!(
            source.retract_alls, 1,
            "the off edge restores the passive posture"
        );

        monitor.on_probe_liveness(
            true,
            base + Duration::from_secs(101),
            &controls,
            &mut source,
            &mut events,
        );
        for step in 0..(UNRESOLVED_STREAK_FIRST_WARN - 1) {
            key_probe(
                &mut monitor,
                7,
                42,
                base,
                200 + step,
                &controls,
                &mut source,
                &mut events,
            );
        }
        assert_eq!(
            source.announced,
            vec![42],
            "24 failures after the reset stay quiet — the count rebuilt from zero"
        );
        key_probe(
            &mut monitor,
            7,
            42,
            base,
            500,
            &controls,
            &mut source,
            &mut events,
        );
        assert_eq!(
            source.announced,
            vec![42, 42],
            "the 25th fresh failure announces again"
        );
    }

    #[test]
    fn the_pid_zero_sentinel_is_never_accounted_or_announced() {
        // pid 0 is the poller's no-real-pid fallback (review finding): a
        // parade of sentinel-attributed failures must neither accumulate
        // an announce count nor fire an announce at pid 0 — that would
        // install a dead probe route for every future sentinel window.
        let controls = controls();
        let base = Instant::now();
        let mut events = Vec::new();
        let mut source = Scripted::new(SecureFieldProbe::CannotAnswer);

        let mut monitor = focused_app(&controls, 7, 0, &mut source, base, &mut events);
        for step in 0..(2 * UNRESOLVED_STREAK_FIRST_WARN) {
            key_probe(
                &mut monitor,
                7,
                0,
                base,
                step + 1,
                &controls,
                &mut source,
                &mut events,
            );
        }
        assert!(
            source.announced.is_empty(),
            "sentinel-pid failures never announce"
        );
        assert!(
            monitor.app_unanswered.is_empty(),
            "sentinel-pid failures never accumulate accounting"
        );
    }

    #[test]
    fn revocation_clears_the_announce_accounting() {
        // ApiDisabled resets the per-app counts (trust is gone; the
        // liveness-off edge that follows in the pump retracts): failures
        // on either side of a revocation never sum to an announce.
        let controls = controls();
        let base = Instant::now();
        let mut events = Vec::new();
        let mut source = Scripted::new(SecureFieldProbe::CannotAnswer);

        let mut monitor = focused_app(&controls, 7, 42, &mut source, base, &mut events);
        for step in 0..(UNRESOLVED_STREAK_FIRST_WARN - 2) {
            key_probe(
                &mut monitor,
                7,
                42,
                base,
                step + 1,
                &controls,
                &mut source,
                &mut events,
            );
        }
        source.outcome = SecureFieldProbe::ApiDisabled;
        key_probe(
            &mut monitor,
            7,
            42,
            base,
            100,
            &controls,
            &mut source,
            &mut events,
        );
        source.outcome = SecureFieldProbe::CannotAnswer;
        for step in 0..(UNRESOLVED_STREAK_FIRST_WARN - 1) {
            key_probe(
                &mut monitor,
                7,
                42,
                base,
                200 + step,
                &controls,
                &mut source,
                &mut events,
            );
        }
        assert!(
            source.announced.is_empty(),
            "24 + 24 failures split by a revocation never announce"
        );
        key_probe(
            &mut monitor,
            7,
            42,
            base,
            400,
            &controls,
            &mut source,
            &mut events,
        );
        assert_eq!(source.announced, vec![42]);
    }

    #[test]
    fn api_disabled_redacts_and_reports_revocation() {
        let controls = controls();
        let base = Instant::now();
        let mut events = Vec::new();

        let mut monitor = PasswordFieldMonitor::new();
        monitor.on_probe_liveness(
            true,
            base,
            &controls,
            &mut probe_of(SecureFieldProbe::CannotAnswer),
            &mut events,
        );
        let api_disabled = monitor.note_focus(
            Some(7),
            None,
            true,
            base,
            &controls,
            &mut probe_of(SecureFieldProbe::ApiDisabled),
            &mut events,
        );
        assert!(api_disabled, "revocation surfaces from the focus probe");

        let decision = monitor.redact_key_at(
            Some(7),
            None,
            base + Duration::from_millis(10),
            &controls,
            &mut probe_of(SecureFieldProbe::ApiDisabled),
            &mut events,
        );
        assert!(decision.redact);
        assert!(decision.api_disabled, "revocation surfaces from keys too");
    }

    #[test]
    fn probe_going_off_clears_the_confirmed_state_and_exits_the_context() {
        let controls = controls();
        let base = Instant::now();
        let mut events = Vec::new();

        let mut monitor = focused(
            &controls,
            7,
            SecureFieldProbe::Answered { is_secure: true },
            base,
            &mut events,
        );
        assert!(controls.password_field_confirmed_active());
        assert_eq!(events.len(), 1);

        // Accessibility revoked: the probe goes off-declared. The stale
        // confirmed context must exit (the interplay cell keeps keyboard
        // flowing) and the gate must drop.
        monitor.on_probe_liveness(
            false,
            base + Duration::from_secs(1),
            &controls,
            &mut probe_of(SecureFieldProbe::CannotAnswer),
            &mut events,
        );
        assert!(!controls.password_field_confirmed_active());
        assert!(!controls.password_field_active());
        assert_eq!(events.len(), 2);
        assert!(matches!(
            events[1].payload,
            EventPayload::SensitiveContextExited {
                reason: SensitiveContextReason::PasswordField
            }
        ));

        // Re-granted: starts unresolved (gate up), so the next key
        // re-probes instead of trusting anything stale.
        monitor.on_probe_liveness(
            true,
            base + Duration::from_secs(2),
            &controls,
            &mut probe_of(SecureFieldProbe::CannotAnswer),
            &mut events,
        );
        assert!(controls.password_field_active());
        assert_eq!(events.len(), 2, "going live emits nothing by itself");
    }

    #[test]
    fn probe_trust_declares_untrusted_and_notices_regrant_on_cadence() {
        let mut trust = ProbeTrust::new();
        let base = Instant::now();

        assert!(!trust.refresh(base, true, &mut || false));
        // Within the re-probe interval: no new probe, still untrusted.
        let (count, mut probe) = {
            let count = std::rc::Rc::new(std::cell::Cell::new(0));
            let view = count.clone();
            (count, move || {
                view.set(view.get() + 1);
                true
            })
        };
        assert!(!trust.refresh(base + Duration::from_secs(1), true, &mut probe));
        assert_eq!(count.get(), 0);

        // On the cadence: the re-grant is noticed.
        assert!(trust.refresh(base + TRUST_REPROBE_INTERVAL, true, &mut probe));
        assert_eq!(count.get(), 1);

        // Revocation degrades immediately.
        trust.on_api_disabled(base + TRUST_REPROBE_INTERVAL + Duration::from_secs(1));
        assert!(!trust.refresh(
            base + TRUST_REPROBE_INTERVAL + Duration::from_secs(2),
            true,
            &mut || panic!("no probe before the cadence elapses"),
        ));
    }
}
