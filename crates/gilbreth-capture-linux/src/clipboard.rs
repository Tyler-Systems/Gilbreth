//! Clipboard metadata stream (LIN-2): `clipboard_used` rows from XFixes
//! selection events on the CLIPBOARD selection — **metadata only,
//! permanently**, the macOS posture for the X11 reason: the only way to
//! size X clipboard content is to transfer it, so `text_char_count` and
//! `byte_size` stay `None` by construction, never read and then redacted.
//!
//! The flow is event-driven where macOS polls a change counter, because
//! X11 gives the opposite primitives: XFixes announces every owner change
//! (`SetSelectionOwner`, plus the owner-vanished subtypes), and the
//! declared-type list must be ASKED FOR — a `TARGETS` conversion round
//! trip through the pump's own transfer window. `TARGETS` is the type
//! list, not the content; no other target is ever requested.
//!
//! Rules ported from the twins, adapted to that shape:
//!
//! - **Coalescing**: owner changes overwrite one pending slot and the
//!   `TARGETS` request fires on the 1 s cadence, so a sub-second copy
//!   burst (or a clipboard manager re-owning the selection right after
//!   every copy) yields one row carrying the latest server timestamp.
//! - **Off-period copies never replay**: while the System stream is off,
//!   owner-change signals are discarded at arrival, so nothing is pending
//!   to emit when the stream returns (the macOS baseline-advance
//!   invariant, event-shaped).
//! - **Launch emits nothing**: XFixes only reports changes, so there is
//!   no first-observation edge to suppress.
//! - **Unavailable is honest**: an owner that refuses `TARGETS`, answers
//!   with nothing, or never answers inside the timeout produces the
//!   `unavailable` row the Windows locked-clipboard path writes.
//! - **Owner vanished is empty**: X11 clipboards die with their owner
//!   (absent a manager), and Windows records an `empty` update when the
//!   clipboard is cleared — the same row here, no round trip needed.
//! - **Concealed**: the `x-kde-passwordManagerHint` target (KeePassXC and
//!   the KDE convention) classifies as the additive `concealed` kind,
//!   overriding content classification — presence alone decides, since
//!   reading the hint's value would itself be a content transfer
//!   (over-marking, never leaking).
//!
//! `sequence_number` is the X server timestamp of the owner change (a
//! truncating opaque correlation id on every platform: Windows uses its
//! clipboard sequence counter, macOS the pasteboard changeCount).

use std::time::{Duration, Instant};

use gilbreth_core::{Captured, ClipboardFormatKind, EventPayload, Source};
use tracing::debug;

use crate::idle::SAMPLE_INTERVAL;

/// How long a pending `TARGETS` request may wait for its `SelectionNotify`
/// before the owner is declared unavailable (a hung or vanished client).
const TARGETS_REPLY_TIMEOUT: Duration = Duration::from_secs(2);

/// One clipboard-relevant X event, translated by the pump's io seam.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ClipboardSignal {
    /// A client took ownership of CLIPBOARD (a copy happened).
    OwnerChanged { timestamp: u32 },
    /// The owner's window or client went away: the clipboard is empty.
    OwnerGone { timestamp: u32 },
    /// Our `TARGETS` conversion answered; `property_present` is false when
    /// the owner refused the conversion.
    TargetsReply { property_present: bool },
}

/// One declared target's classification, mapped from its atom by the X
/// seam so the monitor stays platform-pure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TargetClass {
    Text,
    Files,
    Image,
    Audio,
    Concealed,
    /// Protocol plumbing (TARGETS, TIMESTAMP, MULTIPLE, SAVE_TARGETS...):
    /// not a format, excluded from the count.
    Meta,
    Other,
}

/// Classify a declared-target list in the ported priority order (the
/// concealed override first, then Text > Files > Image > Audio > Custom),
/// with the format count excluding protocol plumbing.
pub(crate) fn classify_targets(classes: &[TargetClass]) -> (ClipboardFormatKind, u32) {
    let count = classes
        .iter()
        .filter(|class| !matches!(class, TargetClass::Meta))
        .count();
    let count = u32::try_from(count).unwrap_or(u32::MAX);
    let contains = |wanted: TargetClass| classes.contains(&wanted);
    let kind = if contains(TargetClass::Concealed) {
        ClipboardFormatKind::Concealed
    } else if count == 0 {
        ClipboardFormatKind::Empty
    } else if contains(TargetClass::Text) {
        ClipboardFormatKind::Text
    } else if contains(TargetClass::Files) {
        ClipboardFormatKind::Files
    } else if contains(TargetClass::Image) {
        ClipboardFormatKind::Image
    } else if contains(TargetClass::Audio) {
        ClipboardFormatKind::Audio
    } else {
        ClipboardFormatKind::Custom
    };
    (kind, count)
}

struct Pending {
    timestamp: u32,
    requested_at: Option<Instant>,
}

/// Drives the owner-change/TARGETS state machine. Generic over the
/// request and read providers so tests script the whole exchange without
/// an X server.
pub(crate) struct ClipboardMonitor<RQ, RD> {
    request_targets: RQ,
    read_targets: RD,
    pending: Option<Pending>,
    last_request_at: Option<Instant>,
}

impl<RQ, RD> ClipboardMonitor<RQ, RD>
where
    RQ: FnMut(u32) -> bool,
    RD: FnMut() -> Option<Vec<TargetClass>>,
{
    pub(crate) fn new(request_targets: RQ, read_targets: RD) -> Self {
        Self {
            request_targets,
            read_targets,
            pending: None,
            last_request_at: None,
        }
    }

    /// Post-erase reseed: a copy pending from before the wipe must not
    /// materialize as the replacement session's first row.
    pub(crate) fn reseed(&mut self) {
        self.pending = None;
    }

    /// One service-cadence pass: fold in this pass's translated signals,
    /// then issue or expire the pending `TARGETS` request. While the
    /// stream is off, signals are discarded at arrival and nothing stays
    /// pending — the off-period-copies-never-replay invariant.
    pub(crate) fn poll(
        &mut self,
        now: Instant,
        stream_enabled: bool,
        signals: impl IntoIterator<Item = ClipboardSignal>,
        events: &mut Vec<Captured>,
    ) {
        for signal in signals {
            match signal {
                ClipboardSignal::OwnerChanged { timestamp } => {
                    if stream_enabled {
                        // Overwrite: a burst coalesces to the latest copy,
                        // and a reply for an overwritten request reads as
                        // stale below.
                        self.pending = Some(Pending {
                            timestamp,
                            requested_at: None,
                        });
                    }
                }
                ClipboardSignal::OwnerGone { timestamp } => {
                    self.pending = None;
                    if stream_enabled {
                        events.push(row(now, timestamp, ClipboardFormatKind::Empty, 0));
                    }
                }
                ClipboardSignal::TargetsReply { property_present } => {
                    let answered = self
                        .pending
                        .as_ref()
                        .is_some_and(|pending| pending.requested_at.is_some());
                    if !answered {
                        debug!("stale TARGETS reply ignored");
                        continue;
                    }
                    let pending = self.pending.take().expect("checked above");
                    if !stream_enabled {
                        continue;
                    }
                    let answer = if property_present {
                        (self.read_targets)()
                    } else {
                        None
                    };
                    match answer {
                        Some(classes) => {
                            let (kind, count) = classify_targets(&classes);
                            events.push(row(now, pending.timestamp, kind, count));
                        }
                        // The owner refused the conversion or the property
                        // vanished: the Windows locked-clipboard analog.
                        None => events.push(row(
                            now,
                            pending.timestamp,
                            ClipboardFormatKind::Unavailable,
                            0,
                        )),
                    }
                }
            }
        }

        if !stream_enabled {
            self.pending = None;
            return;
        }
        match &mut self.pending {
            Some(pending) if pending.requested_at.is_none() => {
                let due = self
                    .last_request_at
                    .is_none_or(|last| now.saturating_duration_since(last) >= SAMPLE_INTERVAL);
                if due {
                    self.last_request_at = Some(now);
                    if (self.request_targets)(pending.timestamp) {
                        pending.requested_at = Some(now);
                    } else {
                        // A send that cannot leave the connection means the
                        // pump itself is failing; drop quietly rather than
                        // fabricate an owner verdict.
                        debug!("TARGETS request could not be sent; copy dropped");
                        self.pending = None;
                    }
                }
            }
            Some(pending)
                if pending.requested_at.is_some_and(|at| {
                    now.saturating_duration_since(at) >= TARGETS_REPLY_TIMEOUT
                }) =>
            {
                let timestamp = pending.timestamp;
                self.pending = None;
                events.push(row(now, timestamp, ClipboardFormatKind::Unavailable, 0));
            }
            _ => {}
        }
    }
}

fn row(now: Instant, sequence_number: u32, kind: ClipboardFormatKind, count: u32) -> Captured {
    Captured::new(
        Source::System,
        now,
        EventPayload::ClipboardUsed {
            sequence_number,
            format_kind: kind,
            format_count: count,
            // Metadata-only on X11, permanently: sizing means transferring
            // the content, so these are None by construction.
            text_char_count: None,
            byte_size: None,
        },
    )
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, rc::Rc};

    use super::*;

    struct Script {
        requests: Rc<RefCell<Vec<u32>>>,
        request_ok: Rc<RefCell<bool>>,
    }

    #[allow(clippy::type_complexity)]
    fn monitor() -> (
        Script,
        ClipboardMonitor<impl FnMut(u32) -> bool, impl FnMut() -> Option<Vec<TargetClass>>>,
    ) {
        let targets = Rc::new(RefCell::new(Some(vec![
            TargetClass::Meta,
            TargetClass::Meta,
            TargetClass::Text,
            TargetClass::Other,
        ])));
        let requests = Rc::new(RefCell::new(Vec::new()));
        let request_ok = Rc::new(RefCell::new(true));
        let targets_view = targets.clone();
        let requests_view = requests.clone();
        let ok_view = request_ok.clone();
        drop(targets);
        (
            Script {
                requests,
                request_ok,
            },
            ClipboardMonitor::new(
                move |timestamp| {
                    requests_view.borrow_mut().push(timestamp);
                    *ok_view.borrow()
                },
                move || targets_view.borrow().clone(),
            ),
        )
    }

    fn sole_clipboard_row(events: &[Captured]) -> (u32, ClipboardFormatKind, u32) {
        assert_eq!(events.len(), 1, "exactly one row expected");
        match &events[0].payload {
            EventPayload::ClipboardUsed {
                sequence_number,
                format_kind,
                format_count,
                text_char_count,
                byte_size,
            } => {
                assert_eq!(*text_char_count, None, "sizes are never read on X11");
                assert_eq!(*byte_size, None);
                (*sequence_number, *format_kind, *format_count)
            }
            other => panic!("expected ClipboardUsed, got {other:?}"),
        }
    }

    #[test]
    fn a_copy_requests_targets_once_and_emits_one_metadata_row() {
        let (script, mut monitor) = monitor();
        let base = Instant::now();
        let mut events = Vec::new();

        monitor.poll(
            base,
            true,
            [ClipboardSignal::OwnerChanged { timestamp: 5_000 }],
            &mut events,
        );
        assert_eq!(*script.requests.borrow(), vec![5_000], "one TARGETS ask");
        assert!(events.is_empty(), "no row until the owner answers");

        monitor.poll(
            base + Duration::from_millis(100),
            true,
            [ClipboardSignal::TargetsReply {
                property_present: true,
            }],
            &mut events,
        );
        let (seq, kind, count) = sole_clipboard_row(&events);
        assert_eq!(seq, 5_000, "the owner-change server timestamp");
        assert_eq!(kind, ClipboardFormatKind::Text);
        assert_eq!(count, 2, "meta targets are not formats");
        assert!(matches!(events[0].source, Source::System));

        // Quiet afterwards: nothing pending.
        events.clear();
        monitor.poll(base + Duration::from_secs(3), true, [], &mut events);
        assert!(events.is_empty());
    }

    #[test]
    fn a_copy_burst_coalesces_to_the_latest_timestamp() {
        let (script, mut monitor) = monitor();
        let base = Instant::now();
        let mut events = Vec::new();

        monitor.poll(
            base,
            true,
            [
                ClipboardSignal::OwnerChanged { timestamp: 5_000 },
                ClipboardSignal::OwnerChanged { timestamp: 5_010 },
                ClipboardSignal::OwnerChanged { timestamp: 5_020 },
            ],
            &mut events,
        );
        assert_eq!(
            *script.requests.borrow(),
            vec![5_020],
            "one request, the latest copy"
        );
        monitor.poll(
            base + Duration::from_millis(50),
            true,
            [ClipboardSignal::TargetsReply {
                property_present: true,
            }],
            &mut events,
        );
        let (seq, _, _) = sole_clipboard_row(&events);
        assert_eq!(seq, 5_020);
    }

    #[test]
    fn off_period_copies_never_replay() {
        let (script, mut monitor) = monitor();
        let base = Instant::now();
        let mut events = Vec::new();

        monitor.poll(
            base,
            false,
            [ClipboardSignal::OwnerChanged { timestamp: 5_000 }],
            &mut events,
        );
        monitor.poll(base + Duration::from_secs(2), true, [], &mut events);
        monitor.poll(base + Duration::from_secs(4), true, [], &mut events);
        assert!(events.is_empty(), "the off-period copy left nothing behind");
        assert!(script.requests.borrow().is_empty(), "and asked for nothing");
    }

    #[test]
    fn disabling_mid_flight_discards_the_pending_answer() {
        let (_script, mut monitor) = monitor();
        let base = Instant::now();
        let mut events = Vec::new();

        monitor.poll(
            base,
            true,
            [ClipboardSignal::OwnerChanged { timestamp: 5_000 }],
            &mut events,
        );
        // Stream turns off while the request is in flight; the late reply
        // must not become a row.
        monitor.poll(base + Duration::from_millis(100), false, [], &mut events);
        monitor.poll(
            base + Duration::from_millis(200),
            true,
            [ClipboardSignal::TargetsReply {
                property_present: true,
            }],
            &mut events,
        );
        assert!(events.is_empty(), "the reply became stale at disable");
    }

    #[test]
    fn owner_vanishing_is_the_empty_row_with_no_round_trip() {
        let (script, mut monitor) = monitor();
        let base = Instant::now();
        let mut events = Vec::new();

        monitor.poll(
            base,
            true,
            [ClipboardSignal::OwnerGone { timestamp: 6_000 }],
            &mut events,
        );
        let (seq, kind, count) = sole_clipboard_row(&events);
        assert_eq!(seq, 6_000);
        assert_eq!(kind, ClipboardFormatKind::Empty);
        assert_eq!(count, 0);
        assert!(script.requests.borrow().is_empty(), "nothing to ask");
    }

    #[test]
    fn a_refused_conversion_is_the_unavailable_row() {
        let (script, mut monitor) = monitor();
        let base = Instant::now();
        let mut events = Vec::new();

        monitor.poll(
            base,
            true,
            [ClipboardSignal::OwnerChanged { timestamp: 5_000 }],
            &mut events,
        );
        monitor.poll(
            base + Duration::from_millis(100),
            true,
            [ClipboardSignal::TargetsReply {
                property_present: false,
            }],
            &mut events,
        );
        let (_, kind, count) = sole_clipboard_row(&events);
        assert_eq!(kind, ClipboardFormatKind::Unavailable);
        assert_eq!(count, 0);
        drop(script);
    }

    #[test]
    fn a_silent_owner_times_out_to_the_unavailable_row() {
        let (_script, mut monitor) = monitor();
        let base = Instant::now();
        let mut events = Vec::new();

        monitor.poll(
            base,
            true,
            [ClipboardSignal::OwnerChanged { timestamp: 5_000 }],
            &mut events,
        );
        monitor.poll(base + Duration::from_secs(1), true, [], &mut events);
        assert!(events.is_empty(), "still inside the reply window");
        monitor.poll(base + Duration::from_secs(3), true, [], &mut events);
        let (seq, kind, _) = sole_clipboard_row(&events);
        assert_eq!(seq, 5_000);
        assert_eq!(kind, ClipboardFormatKind::Unavailable);
    }

    #[test]
    fn a_stale_reply_with_nothing_in_flight_is_ignored() {
        let (_script, mut monitor) = monitor();
        let base = Instant::now();
        let mut events = Vec::new();

        monitor.poll(
            base,
            true,
            [ClipboardSignal::TargetsReply {
                property_present: true,
            }],
            &mut events,
        );
        assert!(events.is_empty());
    }

    #[test]
    fn requests_throttle_to_the_cadence_so_bursts_stay_one_ask() {
        let (script, mut monitor) = monitor();
        let base = Instant::now();
        let mut events = Vec::new();

        monitor.poll(
            base,
            true,
            [ClipboardSignal::OwnerChanged { timestamp: 5_000 }],
            &mut events,
        );
        monitor.poll(
            base + Duration::from_millis(60),
            true,
            [
                ClipboardSignal::TargetsReply {
                    property_present: true,
                },
                // A new copy lands in the same pass as the old answer.
                ClipboardSignal::OwnerChanged { timestamp: 5_500 },
            ],
            &mut events,
        );
        assert_eq!(events.len(), 1, "the first copy's row");
        assert_eq!(
            *script.requests.borrow(),
            vec![5_000],
            "the second ask waits for the cadence"
        );
        events.clear();

        monitor.poll(base + Duration::from_millis(1_100), true, [], &mut events);
        assert_eq!(*script.requests.borrow(), vec![5_000, 5_500]);
        monitor.poll(
            base + Duration::from_millis(1_200),
            true,
            [ClipboardSignal::TargetsReply {
                property_present: true,
            }],
            &mut events,
        );
        let (seq, _, _) = sole_clipboard_row(&events);
        assert_eq!(seq, 5_500);
    }

    #[test]
    fn a_failed_request_send_drops_the_copy_quietly() {
        let (script, mut monitor) = monitor();
        let base = Instant::now();
        let mut events = Vec::new();

        *script.request_ok.borrow_mut() = false;
        monitor.poll(
            base,
            true,
            [ClipboardSignal::OwnerChanged { timestamp: 5_000 }],
            &mut events,
        );
        assert!(events.is_empty(), "no fabricated verdict");
        monitor.poll(base + Duration::from_secs(3), true, [], &mut events);
        assert!(events.is_empty(), "nothing left pending either");
    }

    #[test]
    fn reseed_drops_a_pending_copy_before_it_materializes() {
        let (script, mut monitor) = monitor();
        let base = Instant::now();
        let mut events = Vec::new();

        monitor.poll(
            base,
            true,
            [ClipboardSignal::OwnerChanged { timestamp: 5_000 }],
            &mut events,
        );
        assert_eq!(*script.requests.borrow(), vec![5_000], "request in flight");

        monitor.reseed();
        // The pre-erase answer arrives after the wipe: stale, no row.
        monitor.poll(
            base + Duration::from_millis(100),
            true,
            [ClipboardSignal::TargetsReply {
                property_present: true,
            }],
            &mut events,
        );
        monitor.poll(base + Duration::from_secs(3), true, [], &mut events);
        assert!(events.is_empty(), "nothing pending survives the reseed");
    }

    #[test]
    fn classifier_matches_the_ported_priority_order() {
        use TargetClass::*;
        assert_eq!(
            classify_targets(&[Meta, Text, Image]),
            (ClipboardFormatKind::Text, 2)
        );
        assert_eq!(
            classify_targets(&[Files, Text]),
            (ClipboardFormatKind::Text, 2),
            "file-manager copies declaring both classify Text, the ported rule"
        );
        assert_eq!(
            classify_targets(&[Meta, Files]),
            (ClipboardFormatKind::Files, 1)
        );
        assert_eq!(
            classify_targets(&[Image, Other]),
            (ClipboardFormatKind::Image, 2)
        );
        assert_eq!(classify_targets(&[Audio]), (ClipboardFormatKind::Audio, 1));
        assert_eq!(classify_targets(&[Other]), (ClipboardFormatKind::Custom, 1));
        assert_eq!(classify_targets(&[Meta]), (ClipboardFormatKind::Empty, 0));
        assert_eq!(classify_targets(&[]), (ClipboardFormatKind::Empty, 0));
        assert_eq!(
            classify_targets(&[Text, Concealed, Meta]),
            (ClipboardFormatKind::Concealed, 2),
            "the concealed hint overrides content classification"
        );
    }
}
