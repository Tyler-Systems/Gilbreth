//! DASH-06: fit the first-launch window inside the target monitor's usable
//! work area. eframe restores and clamps persisted geometry itself, so this
//! module acts only when the storage carries no window entry — a genuine
//! first launch (or a secondary window, which never persists). The fit runs
//! after window creation against the real HWND: every measurement is in
//! physical pixels on the monitor the OS actually chose, which makes the
//! math DPI- and multi-monitor-correct without touching process DPI
//! awareness (winit has already set it by then).
//!
//! Accepted residual: the gate is presence-based while eframe's restore is
//! parse-based, so a present-but-undeserializable window entry means one
//! launch at the unfitted default (eframe rewrites the entry on the next
//! graceful close). The exact eframe pin bounds the shape-drift risk.

/// The storage key eframe writes window geometry under
/// (`epi_integration::STORAGE_WINDOW_KEY` in eframe 0.35). When present,
/// eframe restores and monitor-clamps that geometry over the viewport
/// builder — persisted geometry stays authoritative and this module stays
/// out of the way.
const EFRAME_WINDOW_STORAGE_KEY: &str = "window";

pub(crate) fn window_geometry_is_persisted(storage: Option<&dyn eframe::Storage>) -> bool {
    storage.is_some_and(|storage| storage.get_string(EFRAME_WINDOW_STORAGE_KEY).is_some())
}

/// One rectangle in physical pixels, `(x, y, width, height)`.
type Rect = (i32, i32, i32, i32);

/// Where the first-launch window should move, if anywhere. `None` means the
/// outer rect already sits fully inside the work area — leave the OS
/// placement alone. A window larger than the work area shrinks to it and
/// centers; one that fits but hangs outside translates the shortest
/// distance back in. Degenerate work areas (zero or negative extent) fit
/// nothing.
fn fit_outer_rect(outer: Rect, work: Rect) -> Option<Rect> {
    let (x, y, width, height) = outer;
    let (work_x, work_y, work_width, work_height) = work;
    if work_width <= 0 || work_height <= 0 || width <= 0 || height <= 0 {
        return None;
    }
    let fitted_width = width.min(work_width);
    let fitted_height = height.min(work_height);
    let (fitted_x, fitted_y) = if fitted_width < width || fitted_height < height {
        // Shrunk: center in the work area so the first impression is a
        // deliberate placement, not a clipped cascade position.
        (
            work_x + (work_width - fitted_width) / 2,
            work_y + (work_height - fitted_height) / 2,
        )
    } else {
        // Fits: translate the shortest distance into the work area.
        (
            x.clamp(work_x, work_x + work_width - fitted_width),
            y.clamp(work_y, work_y + work_height - fitted_height),
        )
    };
    if (fitted_x, fitted_y, fitted_width, fitted_height) == outer {
        return None;
    }
    Some((fitted_x, fitted_y, fitted_width, fitted_height))
}

/// Best-effort: every failure leaves the OS placement in force. The window
/// is on screen but unpainted here (first paint happens strictly after the
/// creation closure), so the move can show as an unpainted-frame jump on a
/// slow surface init — content never renders at the wrong size. If that
/// jump proves visible in the first-run walk, the follow-up is
/// `with_visible(false)` plus a show after the first frame.
#[cfg(windows)]
pub(crate) fn fit_first_launch_window(cc: &eframe::CreationContext<'_>) {
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};
    use windows::Win32::Foundation::{HWND, RECT};
    use windows::Win32::Graphics::Gdi::{
        GetMonitorInfoW, MonitorFromWindow, MONITORINFO, MONITOR_DEFAULTTONEAREST,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        GetWindowRect, SetWindowPos, SWP_NOACTIVATE, SWP_NOZORDER,
    };

    let Ok(handle) = cc.window_handle() else {
        return;
    };
    let RawWindowHandle::Win32(win32) = handle.as_raw() else {
        return;
    };
    let hwnd = HWND(isize::from(win32.hwnd) as *mut core::ffi::c_void);

    // SAFETY: hwnd is the live window winit just created; the structs are
    // plain out-parameters sized by cbSize per the Win32 contract.
    unsafe {
        let monitor = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);
        let mut info = MONITORINFO {
            cbSize: std::mem::size_of::<MONITORINFO>() as u32,
            ..Default::default()
        };
        if !GetMonitorInfoW(monitor, &mut info).as_bool() {
            return;
        }
        let mut window = RECT::default();
        if GetWindowRect(hwnd, &mut window).is_err() {
            return;
        }
        let work = info.rcWork;
        let outer = (
            window.left,
            window.top,
            window.right - window.left,
            window.bottom - window.top,
        );
        let work_rect = (
            work.left,
            work.top,
            work.right - work.left,
            work.bottom - work.top,
        );
        let Some((x, y, width, height)) = fit_outer_rect(outer, work_rect) else {
            return;
        };
        if let Err(error) = SetWindowPos(
            hwnd,
            None,
            x,
            y,
            width,
            height,
            SWP_NOZORDER | SWP_NOACTIVATE,
        ) {
            tracing::warn!(%error, "first-launch window fit failed; keeping the OS placement");
        } else {
            tracing::info!(
                width,
                height,
                "fitted the first-launch window to the monitor work area"
            );
        }
    }
}

#[cfg(not(windows))]
pub(crate) fn fit_first_launch_window(_cc: &eframe::CreationContext<'_>) {
    // macOS constrains new windows to the visible frame itself; revisit
    // with the MAC-2 packaging pass if dogfood shows otherwise.
}

#[cfg(test)]
mod tests {
    use super::*;

    const WORK: Rect = (0, 0, 1920, 1040);

    #[test]
    fn a_window_inside_the_work_area_is_left_alone() {
        assert_eq!(fit_outer_rect((100, 100, 1180, 900), WORK), None);
        assert_eq!(fit_outer_rect((0, 0, 1920, 1040), WORK), None);
    }

    #[test]
    fn an_oversized_window_shrinks_to_the_work_area_and_centers() {
        // The DASH-06 case: 960 logical at 125% scaling = 1200 physical on
        // a 1080p panel with a 40px taskbar.
        assert_eq!(
            fit_outer_rect((60, 40, 1475, 1200), (0, 0, 1920, 1040)),
            Some((222, 0, 1475, 1040))
        );
        // Both axes oversized on a small panel.
        assert_eq!(
            fit_outer_rect((0, 0, 2000, 1200), (0, 0, 1366, 728)),
            Some((0, 0, 1366, 728))
        );
    }

    #[test]
    fn a_fitting_window_translates_the_shortest_distance_back_in() {
        // Hanging past the bottom-right: pulled up-left just enough.
        assert_eq!(
            fit_outer_rect((1000, 300, 1180, 960), WORK),
            Some((740, 80, 1180, 960))
        );
        // Off the top-left of a secondary monitor's work area.
        assert_eq!(
            fit_outer_rect((-50, -20, 800, 600), (0, 0, 1920, 1040)),
            Some((0, 0, 800, 600))
        );
    }

    #[test]
    fn a_secondary_monitor_work_area_keeps_its_origin() {
        // Work areas carry virtual-desktop origins; centering must land
        // inside the monitor, not at the primary's coordinates.
        assert_eq!(
            fit_outer_rect((100, 100, 3000, 2000), (1920, 200, 1280, 800)),
            Some((1920, 200, 1280, 800))
        );
        // A monitor left of primary has a negative origin; the clamp arms
        // must be sign-agnostic.
        assert_eq!(
            fit_outer_rect((-2000, -50, 800, 600), (-1920, 0, 1920, 1040)),
            Some((-1920, 0, 800, 600))
        );
    }

    #[test]
    fn degenerate_rects_fit_nothing() {
        assert_eq!(fit_outer_rect((0, 0, 1180, 960), (0, 0, 0, 1040)), None);
        assert_eq!(fit_outer_rect((0, 0, 0, 960), WORK), None);
    }

    struct KeyedStorage(bool);

    impl eframe::Storage for KeyedStorage {
        fn get_string(&self, key: &str) -> Option<String> {
            (self.0 && key == EFRAME_WINDOW_STORAGE_KEY).then(|| "geometry".to_string())
        }
        fn set_string(&mut self, _key: &str, _value: String) {}
        fn remove_string(&mut self, _key: &str) {}
        fn flush(&mut self) {}
    }

    #[test]
    fn persisted_geometry_is_detected_through_the_eframe_key() {
        assert!(!window_geometry_is_persisted(None));
        let empty = KeyedStorage(false);
        assert!(!window_geometry_is_persisted(Some(&empty)));
        let saved = KeyedStorage(true);
        assert!(window_geometry_is_persisted(Some(&saved)));
    }
}
