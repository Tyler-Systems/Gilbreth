//! The one real AppKit touchpoint of the Foreground slice: ask NSWorkspace
//! for the frontmost application. Kept alone in this module so everything
//! else in the crate stays provider-injected and unit-testable.
//!
//! Thread requirement: called from the pump, which runs on the process
//! main thread in production (the CFRunLoop pump's placement). NSWorkspace's
//! frontmost getters are safe in the vendored bindings and carry no
//! MainThreadMarker requirement.

use std::time::Duration;

use objc2::{
    rc::{autoreleasepool, Retained},
    runtime::{NSObjectProtocol, ProtocolObject},
};
use objc2_app_kit::{NSEvent, NSPasteboard, NSWorkspace};
use objc2_foundation::{NSActivityOptions, NSProcessInfo, NSString};
use tracing::info;

use crate::{foreground::FrontmostApp, mouse::PointerMetrics};

pub(crate) fn frontmost_app() -> Option<FrontmostApp> {
    // Independent-review blocker fix: the pump thread is a bare
    // CFRunLoopRunInMode loop with nothing draining an autorelease pool, so
    // the autoreleased returns here (NSRunningApplication, NSURL, CFString)
    // accumulated forever — measured at one triplet per 50ms poll,
    // ~1 GB/day. Every AppKit access on the pump thread must run inside its
    // own pool; the extracted values below are plain Rust data and safely
    // outlive it.
    autoreleasepool(|_pool| {
        let workspace = NSWorkspace::sharedWorkspace();
        let app = workspace.frontmostApplication()?;
        let pid = app.processIdentifier();
        // Full bundle-executable path per the schema vocabulary record — this
        // is the capture-side value. At rest it is deliberately reduced: the
        // store's priv-02/A14 rule basenames every WindowRef exe (typed
        // columns and payload JSON) at insert on both platforms, so paths
        // never reach the database. Empty when AppKit reports no executable
        // URL (the Windows twin's exe can be empty too, and the display
        // layer tolerates it).
        let exe = app
            .executableURL()
            .and_then(|url| url.path())
            .map(|path| path.to_string())
            .unwrap_or_default();
        Some(FrontmostApp { pid, exe })
    })
}

/// System pointer metrics for the mouse state machine. The double-click
/// interval is the live system setting (`NSEvent.doubleClickInterval`,
/// exactly as the Windows twin uses `GetDoubleClickTime`); macOS exposes no
/// public double-click/drag *box* metric, so those keep the Windows fallback
/// half-extents (4px / 8px) — a recorded parity note, not a defect.
pub(crate) fn pointer_metrics() -> PointerMetrics {
    // A class-method scalar read; wrapped in a pool for uniformity with the
    // pump-thread AppKit rule (nothing is autoreleased here, but the rule is
    // "every AppKit access on the pump thread runs inside a pool").
    let interval = autoreleasepool(|_pool| NSEvent::doubleClickInterval());
    let millis = if interval.is_finite() && interval > 0.0 {
        (interval * 1000.0) as u64
    } else {
        PointerMetrics::default().double_click_interval.as_millis() as u64
    };
    PointerMetrics {
        double_click_interval: Duration::from_millis(millis),
        ..PointerMetrics::default()
    }
}

/// Low Power Mode — the recorded `battery_saver` mapping for
/// `PowerStatusChanged` (TCC record, 2026-07-12 power rules). A scalar
/// read; pooled per the pump-thread AppKit rule.
pub(crate) fn low_power_mode_enabled() -> bool {
    autoreleasepool(|_pool| NSProcessInfo::processInfo().isLowPowerModeEnabled())
}

/// The general pasteboard's change counter (`NSPasteboard.changeCount`) —
/// the clipboard monitor's 1 s edge signal. A cheap scalar read; the types
/// list is only read after this moves. Metadata, never content: neither
/// this nor [`pasteboard_types`] is gated by macOS 26 pasteboard privacy
/// (`accessBehavior` alerts fire on programmatic *data* reads), evidenced
/// by the live probe below before the slice landed.
pub(crate) fn pasteboard_change_count() -> Option<i64> {
    autoreleasepool(|_pool| Some(NSPasteboard::generalPasteboard().changeCount() as i64))
}

/// The general pasteboard's declared type identifiers (UTIs), read once per
/// changeCount edge for kind/count classification. `None` means the
/// pasteboard reported no type array at all — the metadata-unavailable row,
/// the Windows locked-clipboard analog; an empty `Vec` is a genuinely empty
/// pasteboard. Content is never requested.
pub(crate) fn pasteboard_types() -> Option<Vec<String>> {
    autoreleasepool(|_pool| {
        NSPasteboard::generalPasteboard()
            .types()
            .map(|types| types.iter().map(|kind| kind.to_string()).collect())
    })
}

/// The App Nap stance (owner decision, recorded 2026-07-12): hold
/// `userInitiatedAllowingIdleSystemSleep` while any stream is enabled —
/// that option blocks App Nap and timer coalescing but never blocks system
/// or display sleep — and release it when capture is paused, so the app
/// naps like anything else when it isn't capturing. No stronger assertion
/// is ever taken.
pub(crate) struct PumpActivity {
    token: Option<Retained<ProtocolObject<dyn NSObjectProtocol>>>,
}

impl Drop for PumpActivity {
    fn drop(&mut self) {
        // Pump exit: the assertion must not outlive capture (endActivity is
        // required by the API contract; token deallocation alone is not
        // documented to end it).
        self.set(false);
    }
}

impl PumpActivity {
    pub(crate) fn new() -> Self {
        Self { token: None }
    }

    /// Idempotent reconcile: the pump calls this on desire edges, and the
    /// held-token check makes repeated calls harmless anyway.
    pub(crate) fn set(&mut self, wanted: bool) {
        if wanted == self.token.is_some() {
            return;
        }
        autoreleasepool(|_pool| {
            if wanted {
                // Value-free reason: it is user-visible in Activity
                // Monitor's "Prevent App Nap" column and `pmset -g assertions`.
                let reason = NSString::from_str("ambient capture is running");
                self.token = Some(
                    NSProcessInfo::processInfo().beginActivityWithOptions_reason(
                        NSActivityOptions::UserInitiatedAllowingIdleSystemSleep,
                        &reason,
                    ),
                );
                info!("app-nap activity assertion held (capture running)");
            } else if let Some(token) = self.token.take() {
                // SAFETY: the token is the one beginActivityWithOptions_reason
                // returned above.
                unsafe { NSProcessInfo::processInfo().endActivity(&token) };
                info!("app-nap activity assertion released (capture paused)");
            }
        });
    }
}

#[cfg(test)]
mod probe {
    /// Manual diagnostic, never run in CI (companion to
    /// `coregraphics::probe_session_snapshot`): prints the general
    /// pasteboard's changeCount and declared types so the clipboard rules'
    /// load-bearing assumption — metadata reads are NOT gated by macOS 26
    /// pasteboard privacy (no paste alert, no permission) — is evidenced
    /// live before/while the slice ships. Run with `--ignored --nocapture`,
    /// copy something (including from a password manager for the concealed
    /// marker), run again, compare. An `accessBehavior` alert would appear
    /// on screen if metadata reads were gated; none is expected.
    #[test]
    #[ignore = "manual probe: verify live pasteboard metadata access by hand"]
    fn probe_pasteboard_metadata() {
        println!("changeCount: {:?}", super::pasteboard_change_count());
        println!("types: {:?}", super::pasteboard_types());
    }
}
