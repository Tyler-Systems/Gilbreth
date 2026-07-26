//! Real providers for the AX-gated `Windows` stream (window titles):
//! trust probes and the focused-window reader, per the Windows-titles
//! amendment in the macOS TCC and stream rules.
//!
//! Everything here is the CF-style C Accessibility API: Create/Copy-rule
//! owned returns only, nothing autoreleased, so like `coregraphics.rs` (and
//! unlike `appkit.rs`) no autoreleasepool is required on the pump thread.
//! Keep it that way.
//!
//! One deliberate exception to the read-only posture lives here: the
//! O3-pair assistive-activation announce (`AXManualAccessibility = true`
//! on a deterministically failing app — the TCC record's O3-pair adoption
//! amendments, 2026-07-14). It is the only AX write in the product; do not
//! add another without a decision record.
//!
//! The binding crate (`objc2-application-services`) is the one objc2-family
//! member not already in the dependency tree via eframe/winit; it comes from
//! the same generator and org as the rest, so the vendor lineage is
//! unchanged (recorded in the workspace manifest).

use std::ptr::NonNull;

use objc2_application_services::{
    kAXTrustedCheckOptionPrompt, AXError, AXIsProcessTrusted, AXIsProcessTrustedWithOptions,
    AXUIElement,
};
use objc2_core_foundation::{CFBoolean, CFDictionary, CFRetained, CFString, CFType};
use tracing::{debug, info};

use crate::foreground::WindowProbe;

/// AX messaging timeout, set process-globally (via the system-wide
/// element at reader construction) AND directly on each element this
/// module reads. Both placements matter: the SDK header is explicit that
/// a timeout set on one element does not propagate to equal-but-distinct
/// refs — the review round caught the original app-element-only placement
/// leaving the window-title read unbounded at the process default.
/// Windows' `GetWindowTextW` reads a cached title and cannot block; the
/// closest public-API equivalent is bounding every synchronous AX
/// round-trip, so an unresponsive app stalls a probe by at most ~2× this
/// value (a probe is two sequential reads: focused window, then title).
/// Failures surface as `CannotComplete` and follow the blackout rule.
const MESSAGING_TIMEOUT_SECONDS: f32 = 0.25;

/// Is this process trusted for Accessibility right now? Never prompts.
pub(crate) fn process_trusted() -> bool {
    // SAFETY: no preconditions; a read-only trust check.
    unsafe { AXIsProcessTrusted() }
}

/// Ask macOS to show the Accessibility approval flow for this process (it
/// also registers the app, unchecked, in the System Settings list). Returns
/// the current trust state.
///
/// Fired ONLY behind an explicit user action, per the TCC record: the
/// Diagnostics panel's Request-access button routes here through the
/// permission-request sidecar (the app layer's
/// `perform_permission_action` — pump process only — is the one caller).
/// Never called autonomously. Live prompt→grant→reactivation arc
/// evidenced 2026-07-12 (soak log Day 1).
pub fn prompt_accessibility() -> bool {
    // SAFETY: reading a framework-provided extern static; HIServices
    // initializes its option keys before any code here can run.
    let prompt_key = unsafe { kAXTrustedCheckOptionPrompt };
    let options = CFDictionary::from_slices(&[prompt_key], &[CFBoolean::new(true)]);
    // SAFETY: the options dictionary is a valid CFDictionary of the
    // documented key/value shape and outlives the call.
    unsafe { AXIsProcessTrustedWithOptions(Some(options.as_opaque())) }
}

/// Focused-window identity token. Two probes that land on the same window
/// yield distinct `AXUIElement` refs that compare CFEqual-equal, which is
/// the documented identity contract this wrapper leans on; the poller only
/// ever compares keys (equality drives the synthetic-id map), so no other
/// property of the element escapes.
#[derive(Clone)]
pub(crate) struct AxWindowKey(CFRetained<AXUIElement>);

impl PartialEq for AxWindowKey {
    fn eq(&self, other: &Self) -> bool {
        let this: &CFType = (*self.0).as_ref();
        let that: &CFType = (*other.0).as_ref();
        this == that
    }
}

impl std::fmt::Debug for AxWindowKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Content-free on purpose: identity token, not window data.
        f.write_str("AxWindowKey")
    }
}

/// Reads the frontmost app's focused window and its title on the poller's
/// probe cadence. Caches one app element per pid (the element creation is
/// cheap but the messaging-timeout setup shouldn't repeat per probe); the
/// cache grows one entry per distinct frontmost app per run, the same
/// growth class as the poller's synthetic-id maps, and is covered by the
/// same recorded pruning follow-up (NSWorkspace termination observers).
pub(crate) struct FocusedWindowReader {
    focused_window_attr: CFRetained<CFString>,
    title_attr: CFRetained<CFString>,
    apps: Vec<(i32, CFRetained<AXUIElement>)>,
    /// Held for the reader's lifetime: the timeout set on the system-wide
    /// element is the process-global default that bounds every read this
    /// process ever makes (including future AX users), independent of the
    /// per-element settings below.
    _system_wide: CFRetained<AXUIElement>,
}

impl FocusedWindowReader {
    pub(crate) fn new() -> Self {
        // SAFETY: no preconditions; Create rule — the return is owned.
        let system_wide = unsafe { AXUIElement::new_system_wide() };
        // SAFETY: valid system-wide element; per the header, setting the
        // timeout here sets the process-global default. Failure (ignored)
        // still leaves the per-element settings as the bound.
        let _ = unsafe { system_wide.set_messaging_timeout(MESSAGING_TIMEOUT_SECONDS) };
        Self {
            // The binding exports no attribute-name constants; these
            // literals are the documented public header values
            // (AXAttributeConstants.h: kAXFocusedWindowAttribute,
            // kAXTitleAttribute — stable API since 10.2).
            focused_window_attr: CFString::from_static_str("AXFocusedWindow"),
            title_attr: CFString::from_static_str("AXTitle"),
            apps: Vec::new(),
            _system_wide: system_wide,
        }
    }

    /// One probe: focused window identity + title for the frontmost app —
    /// at most two bounded round-trips (~0.5 s worst case on a hung app).
    pub(crate) fn probe(&mut self, pid: i32) -> WindowProbe<AxWindowKey> {
        let app = self.app_element(pid);
        let window = match copy_element_attribute(&app, &self.focused_window_attr) {
            Ok(value) => match value.downcast::<AXUIElement>() {
                Ok(window) => window,
                // A non-element value would be an AX contract violation;
                // attribute at app granularity rather than guessing.
                Err(_) => return WindowProbe::NoFocusedWindow,
            },
            Err(err) => return self.classify_window_error(pid, err),
        };
        // Timeouts do NOT propagate between equal-but-distinct refs (SDK
        // header; review blocker): bound this fresh window element
        // explicitly before reading through it.
        // SAFETY: valid window element returned by the read above.
        let _ = unsafe { window.set_messaging_timeout(MESSAGING_TIMEOUT_SECONDS) };

        let title = match copy_element_attribute(&window, &self.title_attr) {
            Ok(value) => value
                .downcast::<CFString>()
                .map(|title| title.to_string())
                .unwrap_or_default(),
            Err(AXError::APIDisabled) => return WindowProbe::ApiDisabled,
            // A window with an unreadable title is still that window; an
            // empty title is the honest degraded shape (same as the
            // Foreground-only rows). This includes a window that died
            // between the two reads (`InvalidUIElement` here): one short
            // empty-title segment for a window that WAS focused this
            // instant ago, self-correcting on the next cadence probe; the
            // dead key stays in `window_ids` within the documented
            // growth class.
            Err(_) => String::new(),
        };

        WindowProbe::Window {
            key: AxWindowKey(window),
            title,
        }
    }

    fn app_element(&mut self, pid: i32) -> CFRetained<AXUIElement> {
        if let Some((_, element)) = self.apps.iter().find(|(cached, _)| *cached == pid) {
            return element.clone();
        }
        // SAFETY: no preconditions; Create rule — the return is owned.
        let element = unsafe { AXUIElement::new_application(pid) };
        // SAFETY: element is a valid application element. A failure here
        // (ignored) just means probes keep the system default timeout; the
        // probe error paths still apply.
        let _ = unsafe { element.set_messaging_timeout(MESSAGING_TIMEOUT_SECONDS) };
        self.apps.push((pid, element.clone()));
        element
    }

    fn classify_window_error(&mut self, pid: i32, err: AXError) -> WindowProbe<AxWindowKey> {
        match err {
            // Revocation mid-run: the caller degrades the stream and the
            // trust re-probe cadence notices a re-grant (TCC record).
            AXError::APIDisabled => WindowProbe::ApiDisabled,
            // Legitimately no focused window (or an app that doesn't
            // implement the AX API at all): app-granular attribution is
            // stable and honest — not a transient failure.
            AXError::NoValue | AXError::AttributeUnsupported | AXError::NotImplemented => {
                WindowProbe::NoFocusedWindow
            }
            // Stale cached element (the app died or its AX server was torn
            // down): drop it so the next probe recreates it fresh.
            AXError::InvalidUIElement => {
                self.drop_app_element(pid);
                WindowProbe::Failed
            }
            // CannotComplete (messaging timeout, unresponsive app) and
            // anything unclassified: transient — the blackout rule.
            _ => WindowProbe::Failed,
        }
    }

    fn drop_app_element(&mut self, pid: i32) {
        self.apps.retain(|(cached, _)| *cached != pid);
    }
}

/// One secure-field probe outcome (password-field slice). `Answered` is a
/// definitive yes/no; `CannotAnswer` is the fail-closed cell (no focused
/// element readable, timeout, AX-less app — the caller treats it as
/// sensitive); `ApiDisabled` is revocation (the caller degrades the probe
/// to off-declared, the matrix interplay cell).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SecureFieldProbe {
    Answered { is_secure: bool },
    CannotAnswer,
    ApiDisabled,
}

/// The secure-field probe seam (O3-pair adoption amendments, 2026-07-14):
/// the pump holds one implementation — [`SecureFieldReader`] in production,
/// scripted sources in tests. Beyond the probe itself it carries the two
/// O3-pair operations, so the monitor that decides *when* to announce never
/// touches AX types and stays unit-testable.
pub(crate) trait SecureFieldSource {
    /// One secure-field probe for the frontmost app. `pid` selects the
    /// route: announced apps probe through their own app element (the
    /// working Electron arm), everything else through the system-wide
    /// element (the shipped path).
    fn probe(&mut self, pid: Option<i32>) -> SecureFieldProbe;
    /// Announce Gilbreth as an assistive client to `pid`: write
    /// `AXManualAccessibility = true` on that app element and route its
    /// future probes through it. Safe to repeat (the caller bounds the
    /// cadence); success is judged behaviorally by probes answering —
    /// never by set/readback codes, which the probe round recorded as
    /// lying on Chromium.
    fn announce(&mut self, pid: i32);
    /// Restore the passive posture: clear every announced attribute
    /// (best-effort — fails harmlessly on dead apps or after revocation)
    /// and forget the routes.
    fn retract_all(&mut self);
}

/// Scripted-outcome convenience for tests that predate the O3 pair (and
/// any probe-only scripting): a bare `FnMut() -> SecureFieldProbe` is a
/// source with no announce bookkeeping. Test-only by construction (review
/// finding): the pre-O3 production wiring was exactly such a closure, so
/// without this gate a future edit could compile a silently announce-dead
/// pump — production must construct [`SecureFieldReader`].
#[cfg(test)]
impl<F: FnMut() -> SecureFieldProbe> SecureFieldSource for F {
    fn probe(&mut self, _pid: Option<i32>) -> SecureFieldProbe {
        self()
    }
    fn announce(&mut self, _pid: i32) {}
    fn retract_all(&mut self) {}
}

/// Reads whether the focused UI element is a secure text field
/// (password-field slice; TCC record "AX password-field probe" rules). The
/// check is the platform convention: role OR subrole equals
/// `AXSecureTextField` (AppKit exposes NSSecureTextField as role
/// AXTextField + subrole AXSecureTextField; the WebKit/Chromium bridges
/// follow the same convention for web password inputs). Content is never
/// read — role strings only.
///
/// Two probe routes (O3-pair adoption amendments, 2026-07-14): the default
/// is the system-wide element's `AXFocusedUIElement` (the shipped path);
/// an app announced to via [`SecureFieldSource::announce`] routes through
/// its own app element instead — the probe round showed the system-wide
/// path stays dead for activated Chromium in every cell, so the write and
/// the app-element route only work as a pair.
///
/// Every read is bounded by the established 0.25 s messaging timeout (set
/// on the system-wide element at construction — which also sets the
/// process-global default — and re-set on each focused element, per the
/// non-propagation rule): one probe is at most three sequential bounded
/// round-trips (focused element, role, subrole), ~0.75 s worst case on a
/// hung app. On a responsive app the caller's cache bounds recurrence
/// (asymmetric TTL: 2 s secure / 250 ms not-secure); a hung app answers
/// `CannotAnswer`, which never populates the cache, so there the bound is
/// the row-emitting key rate (the pump gate excludes autorepeats).
pub(crate) struct SecureFieldReader {
    system_wide: CFRetained<AXUIElement>,
    focused_attr: CFRetained<CFString>,
    role_attr: CFRetained<CFString>,
    subrole_attr: CFRetained<CFString>,
    /// `AXManualAccessibility` (Electron's documented public-header name
    /// for third-party assistive activation; no binding constant exists).
    manual_attr: CFRetained<CFString>,
    /// Apps announced to this run (O3 pair): pid → its app element, which
    /// becomes that pid's probe route from the announce attempt on —
    /// unconditionally on the write's return code, because verification
    /// is behavioral (the recorded Chromium code lies). One entry per
    /// pid; the same growth class as [`FocusedWindowReader::apps`], and
    /// self-pruning on element death (`InvalidUIElement` drops the
    /// route).
    announced: Vec<(i32, CFRetained<AXUIElement>)>,
}

impl SecureFieldReader {
    pub(crate) fn new() -> Self {
        // SAFETY: no preconditions; Create rule — the return is owned.
        let system_wide = unsafe { AXUIElement::new_system_wide() };
        // SAFETY: valid system-wide element (bounds the focused-element
        // read below; also the process-global default).
        let _ = unsafe { system_wide.set_messaging_timeout(MESSAGING_TIMEOUT_SECONDS) };
        Self {
            system_wide,
            // Documented public header values (AXAttributeConstants.h /
            // AXRoleConstants.h, stable API): kAXFocusedUIElementAttribute,
            // kAXRoleAttribute, kAXSubroleAttribute.
            focused_attr: CFString::from_static_str("AXFocusedUIElement"),
            role_attr: CFString::from_static_str("AXRole"),
            subrole_attr: CFString::from_static_str("AXSubrole"),
            manual_attr: CFString::from_static_str("AXManualAccessibility"),
            announced: Vec::new(),
        }
    }

    fn announced_element(&self, pid: i32) -> Option<CFRetained<AXUIElement>> {
        self.announced
            .iter()
            .find(|(cached, _)| *cached == pid)
            .map(|(_, element)| element.clone())
    }

    fn drop_announced(&mut self, pid: i32) {
        self.announced.retain(|(cached, _)| *cached != pid);
    }

    /// The role/subrole classification tail shared by both probe routes.
    fn classify_focused(&self, element: &AXUIElement) -> SecureFieldProbe {
        match self.role_matches_secure(element, &self.role_attr) {
            RoleCheck::Secure => return SecureFieldProbe::Answered { is_secure: true },
            RoleCheck::ApiDisabled => return SecureFieldProbe::ApiDisabled,
            RoleCheck::CannotAnswer => return SecureFieldProbe::CannotAnswer,
            RoleCheck::NotSecure => {}
        }
        match self.role_matches_secure(element, &self.subrole_attr) {
            RoleCheck::Secure => SecureFieldProbe::Answered { is_secure: true },
            RoleCheck::ApiDisabled => SecureFieldProbe::ApiDisabled,
            // A missing subrole (NoValue/AttributeUnsupported → NotSecure)
            // is normal — most elements declare none — and with the role
            // already read as not-secure this is the definitive "not a
            // password field". A subrole read that FAILS to communicate is
            // different: AppKit puts the secure marker in the subrole, so
            // the question is genuinely unanswered — fail closed.
            RoleCheck::NotSecure => SecureFieldProbe::Answered { is_secure: false },
            RoleCheck::CannotAnswer => SecureFieldProbe::CannotAnswer,
        }
    }

    /// One bounded `AXManualAccessibility` write. The return code is
    /// logged, never trusted (behavioral verification only).
    fn write_manual_accessibility(&self, element: &AXUIElement, on: bool) -> AXError {
        let value = CFBoolean::new(on);
        let flag: &CFType = (*value).as_ref();
        // SAFETY: valid app element; the attribute name and CFBoolean
        // value are the documented Electron affordance shape, and the
        // element's messaging timeout (set at creation) bounds the call.
        unsafe { element.set_attribute_value(&self.manual_attr, flag) }
    }

    fn role_matches_secure(&self, element: &AXUIElement, attribute: &CFString) -> RoleCheck {
        match copy_element_attribute(element, attribute) {
            Ok(value) => match value.downcast::<CFString>() {
                Ok(role) if role.to_string() == "AXSecureTextField" => RoleCheck::Secure,
                Ok(_) => RoleCheck::NotSecure,
                Err(_) => RoleCheck::CannotAnswer,
            },
            Err(AXError::APIDisabled) => RoleCheck::ApiDisabled,
            // NoValue/AttributeUnsupported: the attribute is absent, not a
            // failure to communicate — the element answered.
            Err(AXError::NoValue) | Err(AXError::AttributeUnsupported) => RoleCheck::NotSecure,
            Err(_) => RoleCheck::CannotAnswer,
        }
    }
}

impl SecureFieldSource for SecureFieldReader {
    fn probe(&mut self, pid: Option<i32>) -> SecureFieldProbe {
        let announced = pid.and_then(|pid| self.announced_element(pid));
        let via_announced = announced.is_some();
        let root = announced.unwrap_or_else(|| self.system_wide.clone());
        let element = match copy_element_attribute(&root, &self.focused_attr) {
            Ok(value) => match value.downcast::<AXUIElement>() {
                Ok(element) => element,
                Err(_) => return SecureFieldProbe::CannotAnswer,
            },
            Err(AXError::APIDisabled) => return SecureFieldProbe::ApiDisabled,
            // The announced element died (app exit, or pid reuse handing
            // the number to a different app): drop the route so a
            // successor at this pid starts on the virgin system-wide path
            // and earns its own announce. Nothing to clear — the
            // attribute was target-process state and died with it.
            Err(AXError::InvalidUIElement) if via_announced => {
                if let Some(pid) = pid {
                    debug!(pid, "announced app element died; dropping its probe route");
                    self.drop_announced(pid);
                }
                return SecureFieldProbe::CannotAnswer;
            }
            Err(_) => return SecureFieldProbe::CannotAnswer,
        };
        // SAFETY: valid element from the read above; timeouts do not
        // propagate between equal-but-distinct refs (the review-blocker
        // rule), so bound this fresh ref explicitly.
        let _ = unsafe { element.set_messaging_timeout(MESSAGING_TIMEOUT_SECONDS) };
        self.classify_focused(&element)
    }

    fn announce(&mut self, pid: i32) {
        // Belt-and-braces twin of the monitor's sentinel filter: pid 0 is
        // the poller's no-real-pid value and negatives are AX-invalid —
        // announcing there would install a dead probe route that
        // over-redacts every sentinel-attributed window from then on.
        if pid <= 0 {
            return;
        }
        let element = match self.announced_element(pid) {
            Some(element) => element,
            None => {
                // SAFETY: no preconditions; Create rule — the return is
                // owned.
                let element = unsafe { AXUIElement::new_application(pid) };
                // SAFETY: valid app element; a failed timeout set (ignored)
                // leaves the process-global default as the bound.
                let _ = unsafe { element.set_messaging_timeout(MESSAGING_TIMEOUT_SECONDS) };
                self.announced.push((pid, element.clone()));
                element
            }
        };
        let code = self.write_manual_accessibility(&element, true);
        info!(
            pid,
            code = ?code,
            "announced Gilbreth as an assistive client (AXManualAccessibility=true, O3 \
             pair): this app's secure-field probes now route through its app element; \
             the return code is recorded but not trusted — success is probes answering"
        );
    }

    fn retract_all(&mut self) {
        if self.announced.is_empty() {
            return;
        }
        info!(
            count = self.announced.len(),
            "clearing assistive-activation announcements (posture restore)"
        );
        for (pid, element) in std::mem::take(&mut self.announced) {
            let code = self.write_manual_accessibility(&element, false);
            debug!(pid, code = ?code, "assistive-activation announcement cleared");
        }
    }
}

enum RoleCheck {
    Secure,
    NotSecure,
    CannotAnswer,
    ApiDisabled,
}

/// `AXUIElementCopyAttributeValue` with the Copy rule made explicit: a
/// `Success` return transfers ownership of exactly one reference to us.
fn copy_element_attribute(
    element: &AXUIElement,
    attribute: &CFString,
) -> Result<CFRetained<CFType>, AXError> {
    let mut value: *const CFType = std::ptr::null();
    // SAFETY: the out-pointer references a live local for the duration of
    // the call.
    let err = unsafe { element.copy_attribute_value(attribute, NonNull::from(&mut value)) };
    if err != AXError::Success {
        return Err(err);
    }
    NonNull::new(value.cast_mut())
        // SAFETY: Success with a non-null out-value: we own one reference
        // (Copy rule), which CFRetained::from_raw takes over without
        // retaining again.
        .map(|value| unsafe { CFRetained::from_raw(value) })
        .ok_or(AXError::NoValue)
}

#[cfg(test)]
mod probe {
    /// Manual diagnostic, never run in CI (companion to
    /// `coregraphics::probe_session_snapshot`): prints the live
    /// Accessibility trust state so the granted/not-granted cells of the
    /// degradation matrix can be evidenced by hand — run before and after
    /// granting the bundle in System Settings > Privacy & Security >
    /// Accessibility. Never prompts.
    ///
    /// Run 2026-07-11 (unsigned dev test binary, no grant):
    /// `AXIsProcessTrusted: false` — the not-yet-asked matrix cell,
    /// evidenced live; the granted cell is evidenced after the bundle wrap
    /// + self-signed identity land (start-gate item 4).
    #[test]
    #[ignore = "manual probe: verify live Accessibility trust by hand"]
    fn probe_ax_trust() {
        println!("AXIsProcessTrusted: {}", super::process_trusted());
    }
}
