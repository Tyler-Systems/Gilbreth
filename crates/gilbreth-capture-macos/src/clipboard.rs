//! Clipboard metadata stream (the macOS TCC and stream rules,
//! clipboard rules 2026-07-12): `NSPasteboard.changeCount` polled on the
//! Windows 1 s system cadence (macOS has no push API), edge-detected, with
//! kind/count classified from the declared type list. **Metadata-only on
//! macOS, permanently**: `text_char_count` and `byte_size` stay `None` —
//! Windows fills them by opening the clipboard and sizing the data, but on
//! macOS 26 programmatic *data* reads can raise a pasteboard-privacy paste
//! alert, a trust hazard for a background app. `changeCount` and `types`
//! are metadata and not alert-gated (probe evidence in `appkit.rs`).
//!
//! Concealed copies (`org.nspasteboard.ConcealedType`, the password-manager
//! convention) classify as the additive `ClipboardFormatKind::Concealed`,
//! overriding content-type classification (owner decision 2026-07-12):
//! activity stays visible, the content class is deliberately not inspected.
//!
//! The mechanism polls whenever the pump runs — the baseline advances while
//! the System stream is off or capture is suspended, so copies made during
//! an off period are never replayed as rows on re-enable (the Windows
//! listener's gate-at-send parity), but the types list is only read when a
//! row will actually be emitted.

use std::time::Instant;

use gilbreth_core::{Captured, ClipboardFormatKind, EventPayload, Source};

use crate::idle::SAMPLE_INTERVAL;

/// The NSPasteboard convention marker for concealed content
/// (password managers). Classification-only; content is never requested.
pub(crate) const CONCEALED_TYPE: &str = "org.nspasteboard.ConcealedType";

/// Plain-text UTIs (and the legacy pboard name) — the CF_UNICODETEXT/
/// CF_TEXT/CF_OEMTEXT parity set. Rich-text-only pasteboards (RTF/HTML
/// without a plain-text representation) classify Custom, exactly as a
/// Windows clipboard without a plain-text format would.
const TEXT_TYPES: [&str; 5] = [
    "public.utf8-plain-text",
    "public.utf16-external-plain-text",
    "public.utf16-plain-text",
    "public.plain-text",
    "NSStringPboardType",
];

/// File-reference UTIs (and the legacy name) — the CF_HDROP parity set.
const FILE_TYPES: [&str; 2] = ["public.file-url", "NSFilenamesPboardType"];

/// Raster/vector image UTIs — the CF_BITMAP/CF_DIB*/CF_TIFF/metafile parity
/// set. PDF-on-pasteboard is included as the platform's vector-picture
/// clipboard format (what Preview and design tools put on copy), the twin
/// of Windows' enhanced-metafile clipboard entry.
const IMAGE_TYPES: [&str; 7] = [
    "public.tiff",
    "public.png",
    "public.jpeg",
    "com.compuserve.gif",
    "public.heic",
    "com.microsoft.bmp",
    "com.adobe.pdf",
];

/// Sound UTIs — the CF_WAVE/CF_RIFF parity set.
const AUDIO_TYPES: [&str; 2] = ["public.audio", "com.apple.cocoa.pasteboard.sound"];

/// Classify a declared-type list into the shared kind vocabulary, in the
/// ported Windows priority order (Text > Files > Image > Audio > Custom),
/// with two macOS-specific cells first: the concealed marker overrides
/// content classification (owner decision), and an empty list is a
/// genuinely empty pasteboard.
pub(crate) fn classify_pasteboard_types(types: &[String]) -> ClipboardFormatKind {
    if types.iter().any(|kind| kind == CONCEALED_TYPE) {
        return ClipboardFormatKind::Concealed;
    }
    if types.is_empty() {
        return ClipboardFormatKind::Empty;
    }
    let contains = |set: &[&str]| types.iter().any(|kind| set.contains(&kind.as_str()));
    if contains(&TEXT_TYPES) {
        return ClipboardFormatKind::Text;
    }
    if contains(&FILE_TYPES) {
        return ClipboardFormatKind::Files;
    }
    if contains(&IMAGE_TYPES) {
        return ClipboardFormatKind::Image;
    }
    if contains(&AUDIO_TYPES) {
        return ClipboardFormatKind::Audio;
    }
    ClipboardFormatKind::Custom
}

/// Edge-detects `changeCount` on the 1 s cadence and emits `ClipboardUsed`
/// rows. Generic over the providers so tests script pasteboard state
/// without AppKit. The count provider is a cheap scalar read every sample;
/// the types provider is only consulted when a change will emit.
pub(crate) struct ClipboardMonitor<C, T> {
    count_provider: C,
    types_provider: T,
    last_change_count: Option<i64>,
    last_sample: Option<Instant>,
}

impl<C, T> ClipboardMonitor<C, T>
where
    C: FnMut() -> Option<i64>,
    T: FnMut() -> Option<Vec<String>>,
{
    pub(crate) fn new(count_provider: C, types_provider: T) -> Self {
        Self {
            count_provider,
            types_provider,
            last_change_count: None,
            last_sample: None,
        }
    }

    /// One service-cadence pass.
    ///
    /// The `changeCount` scalar is read on EVERY pass (it is cheap and
    /// infallible in production). While the stream is OFF the baseline
    /// adopts it unconditionally each pass — that continuous advance is
    /// what keeps off-period copies from replaying; while ON, the baseline
    /// advances only at emission time on [`SAMPLE_INTERVAL`], which is what
    /// lets sub-second copies coalesce (do not make the enabled path adopt
    /// per-pass — that kills coalesced emission). Only EMISSION is
    /// throttled. This ordering is
    /// load-bearing for the privacy contract: a copy made while the stream
    /// is off (including a sub-cadence off→copy→on blip) MUST NOT replay as
    /// a row when the stream returns, so the baseline cannot be coupled to
    /// the 1 s emission cadence — an earlier version gated the count read
    /// behind the throttle and could replay an off-period copy inside a
    /// sub-1 s toggle window (review finding, fixed).
    ///
    /// The first observation is a baseline, not a copy — launch emits
    /// nothing (the power-status silent-baseline rule; Windows' listener
    /// only fires on real updates). While `stream_enabled` is false the
    /// baseline advances every pass and the types read is skipped — no
    /// pasteboard inspection happens for a row that cannot emit.
    pub(crate) fn poll(&mut self, now: Instant, stream_enabled: bool, events: &mut Vec<Captured>) {
        let Some(count) = (self.count_provider)() else {
            return;
        };
        if !stream_enabled {
            // Silent baseline advance (every pass): adopt the current count
            // without emitting, so off-period activity leaves no row to
            // replay when the stream re-enables.
            self.last_change_count = Some(count);
            return;
        }
        // Stream enabled: throttle emission. A change observed mid-window
        // stays pending (`last_change_count` is not advanced on a throttled
        // pass), so sub-second copy bursts coalesce into one row at the
        // cadence — the recorded coalescing nuance.
        if self
            .last_sample
            .is_some_and(|last| now.saturating_duration_since(last) < SAMPLE_INTERVAL)
        {
            return;
        }
        self.last_sample = Some(now);

        let changed = self.last_change_count.is_some_and(|prev| prev != count);
        self.last_change_count = Some(count);
        if !changed {
            return;
        }

        // The emitted sequence_number is the truncating u32 cast of the
        // NSInteger changeCount (recorded rule): readers treat it as an
        // opaque correlation id, so wrap is harmless.
        let sequence_number = count as u32;
        let (format_kind, format_count) = match (self.types_provider)() {
            Some(types) => (
                classify_pasteboard_types(&types),
                u32::try_from(types.len()).unwrap_or(u32::MAX),
            ),
            // No type array at all: the metadata-unavailable row, the
            // Windows locked-clipboard analog.
            None => (ClipboardFormatKind::Unavailable, 0),
        };
        events.push(Captured::new(
            Source::System,
            now,
            EventPayload::ClipboardUsed {
                sequence_number,
                format_kind,
                format_count,
                // Metadata-only on macOS, permanently (macOS 26 pasteboard
                // privacy): sizes are never read, so these are None by
                // construction, not by redaction.
                text_char_count: None,
                byte_size: None,
            },
        ));
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, rc::Rc, time::Duration};

    use super::*;

    struct Script {
        count: Rc<RefCell<Option<i64>>>,
        types: Rc<RefCell<Option<Vec<String>>>>,
        types_reads: Rc<RefCell<u32>>,
    }

    #[allow(clippy::type_complexity)]
    fn monitor() -> (
        Script,
        ClipboardMonitor<impl FnMut() -> Option<i64>, impl FnMut() -> Option<Vec<String>>>,
    ) {
        let count = Rc::new(RefCell::new(Some(100i64)));
        let types = Rc::new(RefCell::new(Some(vec![
            "public.utf8-plain-text".to_string()
        ])));
        let types_reads = Rc::new(RefCell::new(0u32));
        let count_view = count.clone();
        let types_view = types.clone();
        let reads_view = types_reads.clone();
        (
            Script {
                count,
                types,
                types_reads,
            },
            ClipboardMonitor::new(
                move || *count_view.borrow(),
                move || {
                    *reads_view.borrow_mut() += 1;
                    types_view.borrow().clone()
                },
            ),
        )
    }

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    #[test]
    fn first_observation_is_a_silent_baseline() {
        let (script, mut monitor) = monitor();
        let base = Instant::now();
        let mut events = Vec::new();

        monitor.poll(base, true, &mut events);
        assert!(events.is_empty(), "launch is not a copy");
        assert_eq!(*script.types_reads.borrow(), 0, "no types read at baseline");
    }

    #[test]
    fn change_count_edge_emits_one_metadata_row() {
        let (script, mut monitor) = monitor();
        let base = Instant::now();
        let mut events = Vec::new();

        monitor.poll(base, true, &mut events);
        *script.count.borrow_mut() = Some(101);
        monitor.poll(base + Duration::from_secs(2), true, &mut events);

        assert_eq!(events.len(), 1);
        match &events[0].payload {
            EventPayload::ClipboardUsed {
                sequence_number,
                format_kind,
                format_count,
                text_char_count,
                byte_size,
            } => {
                assert_eq!(*sequence_number, 101);
                assert_eq!(*format_kind, ClipboardFormatKind::Text);
                assert_eq!(*format_count, 1);
                assert_eq!(*text_char_count, None, "sizes are never read on macOS");
                assert_eq!(*byte_size, None);
            }
            other => panic!("expected ClipboardUsed, got {other:?}"),
        }
        assert!(matches!(events[0].source, Source::System));

        // Steady state: no repeats.
        monitor.poll(base + Duration::from_secs(4), true, &mut events);
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn off_period_copies_advance_the_baseline_without_replaying() {
        let (script, mut monitor) = monitor();
        let base = Instant::now();
        let mut events = Vec::new();

        monitor.poll(base, true, &mut events);
        // Stream off: two copies land; the baseline tracks them silently
        // and the pasteboard types are never inspected.
        *script.count.borrow_mut() = Some(101);
        monitor.poll(base + Duration::from_secs(2), false, &mut events);
        *script.count.borrow_mut() = Some(102);
        monitor.poll(base + Duration::from_secs(4), false, &mut events);
        assert!(events.is_empty());
        assert_eq!(*script.types_reads.borrow(), 0, "no types read while off");

        // Re-enable with no new copy: nothing to say.
        monitor.poll(base + Duration::from_secs(6), true, &mut events);
        assert!(events.is_empty(), "off-period copies never replay");

        // The next real copy emits normally.
        *script.count.borrow_mut() = Some(103);
        monitor.poll(base + Duration::from_secs(8), true, &mut events);
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn a_sub_cadence_off_copy_on_blip_does_not_replay() {
        // The regression the review caught: a copy made during a brief
        // off window (shorter than the 1 s emission cadence) must not
        // emit when the stream comes back on — because the baseline
        // advances on EVERY pass, including the ~50 ms passes that land
        // during the off window, not only on the throttled emission
        // samples.
        let (script, mut monitor) = monitor();
        let base = Instant::now();
        let mut events = Vec::new();

        monitor.poll(base, true, &mut events); // baseline at 100

        // Stream toggles off; a copy lands; a normal service pass (50 ms
        // cadence) runs while off and advances the baseline silently.
        monitor.poll(base + Duration::from_millis(200), false, &mut events);
        *script.count.borrow_mut() = Some(101);
        monitor.poll(base + Duration::from_millis(550), false, &mut events);
        assert_eq!(*script.types_reads.borrow(), 0, "no types read while off");

        // Stream comes back on, all within one second of launch. The next
        // emission-eligible pass must see NO change (baseline already 101).
        monitor.poll(base + Duration::from_millis(800), true, &mut events);
        monitor.poll(base + Duration::from_millis(1_050), true, &mut events);
        assert!(
            events.is_empty(),
            "an off-period copy must never replay as a row on re-enable"
        );
    }

    #[test]
    fn missing_type_array_emits_the_unavailable_row() {
        let (script, mut monitor) = monitor();
        let base = Instant::now();
        let mut events = Vec::new();

        monitor.poll(base, true, &mut events);
        *script.count.borrow_mut() = Some(101);
        *script.types.borrow_mut() = None;
        monitor.poll(base + Duration::from_secs(2), true, &mut events);

        match &events[0].payload {
            EventPayload::ClipboardUsed {
                format_kind,
                format_count,
                ..
            } => {
                assert_eq!(*format_kind, ClipboardFormatKind::Unavailable);
                assert_eq!(*format_count, 0);
            }
            other => panic!("expected ClipboardUsed, got {other:?}"),
        }
    }

    #[test]
    fn sequence_number_is_the_truncating_cast_of_the_nsinteger_count() {
        let (script, mut monitor) = monitor();
        let base = Instant::now();
        let mut events = Vec::new();

        monitor.poll(base, true, &mut events);
        // A count past u32::MAX wraps; readers treat it as opaque.
        *script.count.borrow_mut() = Some(0x1_0000_0005);
        monitor.poll(base + Duration::from_secs(2), true, &mut events);

        match &events[0].payload {
            EventPayload::ClipboardUsed {
                sequence_number, ..
            } => assert_eq!(*sequence_number, 5),
            other => panic!("expected ClipboardUsed, got {other:?}"),
        }
    }

    #[test]
    fn sampling_is_throttled_to_the_windows_cadence() {
        let (script, mut monitor) = monitor();
        let base = Instant::now();
        let mut events = Vec::new();

        monitor.poll(base, true, &mut events);
        *script.count.borrow_mut() = Some(101);
        monitor.poll(base + Duration::from_millis(50), true, &mut events);
        assert!(events.is_empty(), "throttled: no resample within 1s");

        monitor.poll(base + Duration::from_millis(1_050), true, &mut events);
        assert_eq!(events.len(), 1, "edge lands on the next sample");
    }

    #[test]
    fn unreadable_change_count_keeps_the_previous_baseline() {
        let (script, mut monitor) = monitor();
        let base = Instant::now();
        let mut events = Vec::new();

        monitor.poll(base, true, &mut events);
        *script.count.borrow_mut() = None;
        monitor.poll(base + Duration::from_secs(2), true, &mut events);
        assert!(events.is_empty());

        // The counter comes back one copy later: exactly one row, not a
        // phantom edge from the None gap.
        *script.count.borrow_mut() = Some(101);
        monitor.poll(base + Duration::from_secs(4), true, &mut events);
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn classifier_matches_the_windows_priority_order() {
        assert_eq!(
            classify_pasteboard_types(&strings(&["public.utf8-plain-text", "public.rtf"])),
            ClipboardFormatKind::Text
        );
        assert_eq!(
            // Finder file copies declare file-url AND a plain-text path;
            // Windows classifies the same combination Text (its classifier
            // checks text formats first) — parity means Text here too.
            classify_pasteboard_types(&strings(&["public.file-url", "public.utf8-plain-text"])),
            ClipboardFormatKind::Text
        );
        assert_eq!(
            classify_pasteboard_types(&strings(&["public.file-url"])),
            ClipboardFormatKind::Files
        );
        assert_eq!(
            classify_pasteboard_types(&strings(&["public.tiff", "public.png"])),
            ClipboardFormatKind::Image
        );
        assert_eq!(
            classify_pasteboard_types(&strings(&["com.adobe.pdf"])),
            ClipboardFormatKind::Image
        );
        assert_eq!(
            classify_pasteboard_types(&strings(&["public.audio"])),
            ClipboardFormatKind::Audio
        );
        assert_eq!(
            classify_pasteboard_types(&strings(&["com.example.custom-thing"])),
            ClipboardFormatKind::Custom
        );
        assert_eq!(
            // RTF without a plain-text sibling: Custom, exactly as a
            // Windows clipboard without a plain-text format.
            classify_pasteboard_types(&strings(&["public.rtf"])),
            ClipboardFormatKind::Custom
        );
        assert_eq!(classify_pasteboard_types(&[]), ClipboardFormatKind::Empty);
    }

    #[test]
    fn concealed_marker_overrides_content_classification() {
        assert_eq!(
            classify_pasteboard_types(&strings(&[
                "org.nspasteboard.ConcealedType",
                "public.utf8-plain-text",
            ])),
            ClipboardFormatKind::Concealed
        );
        // Transient copies classify by content (recorded decision: Windows
        // ignores its own exclusion markers; only the concealed kind is an
        // owner-decided override).
        assert_eq!(
            classify_pasteboard_types(&strings(&[
                "org.nspasteboard.TransientType",
                "public.utf8-plain-text",
            ])),
            ClipboardFormatKind::Text
        );
    }
}
