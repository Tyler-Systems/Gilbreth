//! System stream (LIN-1): the `SystemInfo` seed row and the
//! `virtual_screen` display shape — seeded once, then edge-detected on the
//! shared 1 s cadence, the macOS `SystemMonitor` emission rules minus its
//! session half (lock/unlock boundaries are LIN-2's elogind slice). The
//! display shape reads the root window's geometry: the X server resizes
//! the root across RandR changes, so its extent IS the virtual screen —
//! origin 0,0 by X's coordinate model, the meaning-constant bounding box.
//!
//! A stream disable re-baselines, so re-enable seeds fresh rows instead of
//! edge-detecting against stale state (the shared reseed rule).

use std::time::Instant;

use gilbreth_core::{Captured, EventPayload, Source};

use crate::idle::SAMPLE_INTERVAL;

/// The virtual-screen bounding box, root-window coordinates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct VirtualScreenRect {
    pub(crate) width: i32,
    pub(crate) height: i32,
}

/// Seeds once, then edge-detects display changes on the 1 s cadence.
/// Generic over the providers so tests inject scripted state without an X
/// server.
pub(crate) struct SystemMonitor<V, I> {
    screen_provider: V,
    info_provider: I,
    last_screen: Option<VirtualScreenRect>,
    last_sample: Option<Instant>,
    seeded: bool,
    enabled_last: bool,
}

impl<V, I> SystemMonitor<V, I>
where
    V: FnMut() -> Option<VirtualScreenRect>,
    I: FnMut() -> EventPayload,
{
    pub(crate) fn new(screen_provider: V, info_provider: I) -> Self {
        Self {
            screen_provider,
            info_provider,
            last_screen: None,
            last_sample: None,
            seeded: false,
            enabled_last: false,
        }
    }

    /// One service-cadence pass; internally throttled to [`SAMPLE_INTERVAL`].
    pub(crate) fn poll(&mut self, now: Instant, enabled: bool, events: &mut Vec<Captured>) {
        if !enabled {
            if self.enabled_last {
                // Re-baseline, exactly like the shared reseed rule: fresh
                // seeds and no phantom edges for state that changed while
                // the stream was off.
                self.seeded = false;
                self.last_screen = None;
                self.last_sample = None;
            }
            self.enabled_last = false;
            return;
        }
        self.enabled_last = true;

        if self
            .last_sample
            .is_some_and(|last| now.saturating_duration_since(last) < SAMPLE_INTERVAL)
        {
            return;
        }
        self.last_sample = Some(now);

        if !self.seeded {
            self.seeded = true;
            events.push(Captured::new(Source::System, now, (self.info_provider)()));
            if let Some(screen) = (self.screen_provider)() {
                self.last_screen = Some(screen);
                events.push(virtual_screen_event(screen, now));
            }
        } else if let Some(screen) = (self.screen_provider)() {
            if self.last_screen != Some(screen) {
                self.last_screen = Some(screen);
                events.push(virtual_screen_event(screen, now));
            }
        }
    }
}

fn virtual_screen_event(screen: VirtualScreenRect, now: Instant) -> Captured {
    Captured::new(
        Source::System,
        now,
        EventPayload::VirtualScreen {
            x0: 0,
            y0: 0,
            x1: screen.width,
            y1: screen.height,
            width: screen.width,
            height: screen.height,
        },
    )
}

/// The one-shot host identity payload: hostname, distribution + kernel,
/// architecture, logical CPU count, and physical memory.
pub(crate) fn system_info() -> EventPayload {
    EventPayload::SystemInfo {
        host: host_name().unwrap_or_default(),
        os_version: os_version(),
        arch: uname_field(|utsname| &utsname.machine).unwrap_or_default(),
        processor_count: std::thread::available_parallelism()
            .map(|count| u32::try_from(count.get()).unwrap_or(u32::MAX))
            .unwrap_or(0),
        memory_total_bytes: memory_total_bytes().unwrap_or(0),
    }
}

fn host_name() -> Option<String> {
    let mut buffer = [0u8; 256];
    // SAFETY: gethostname writes a NUL-terminated name into the provided
    // buffer, never past its length.
    let rc = unsafe { libc::gethostname(buffer.as_mut_ptr().cast(), buffer.len()) };
    if rc != 0 {
        return None;
    }
    let len = buffer.iter().position(|&byte| byte == 0)?;
    String::from_utf8(buffer[..len].to_vec()).ok()
}

fn uname_field(select: impl Fn(&libc::utsname) -> &[libc::c_char; 65]) -> Option<String> {
    // SAFETY: uname fills the zeroed struct; the buffers are NUL-terminated
    // fixed arrays read back below.
    let mut utsname: libc::utsname = unsafe { std::mem::zeroed() };
    // SAFETY: passing a valid pointer to the stack struct above.
    if unsafe { libc::uname(&mut utsname) } != 0 {
        return None;
    }
    let field = select(&utsname);
    let bytes: Vec<u8> = field
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8)
        .collect();
    String::from_utf8(bytes).ok()
}

/// "PRETTY_NAME (Linux <kernel release>)" — the distribution label plus the
/// kernel, the platform's two-part version identity.
fn os_version() -> String {
    let pretty = os_release_pretty_name().unwrap_or_else(|| "Linux".to_string());
    match uname_field(|utsname| &utsname.release) {
        Some(release) => format!("{pretty} (Linux {release})"),
        None => pretty,
    }
}

fn os_release_pretty_name() -> Option<String> {
    let contents = std::fs::read_to_string("/etc/os-release").ok()?;
    let line = contents
        .lines()
        .find_map(|line| line.strip_prefix("PRETTY_NAME="))?;
    Some(line.trim().trim_matches('"').to_string())
}

fn memory_total_bytes() -> Option<u64> {
    let contents = std::fs::read_to_string("/proc/meminfo").ok()?;
    let line = contents
        .lines()
        .find_map(|line| line.strip_prefix("MemTotal:"))?;
    let kib: u64 = line.trim().trim_end_matches("kB").trim().parse().ok()?;
    Some(kib * 1024)
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, rc::Rc, time::Duration};

    use super::*;

    fn kinds(events: &[Captured]) -> Vec<&'static str> {
        events.iter().map(|event| event.payload.kind()).collect()
    }

    #[test]
    fn seeds_info_and_screen_then_edges_only_on_change() {
        let screen = Rc::new(Cell::new(Some(VirtualScreenRect {
            width: 1920,
            height: 1080,
        })));
        let screen_view = screen.clone();
        let mut monitor = SystemMonitor::new(move || screen_view.get(), system_info);
        let base = Instant::now();
        let mut events = Vec::new();

        monitor.poll(base, true, &mut events);
        assert_eq!(kinds(&events), vec!["system_info", "virtual_screen"]);
        match &events[1].payload {
            EventPayload::VirtualScreen {
                x0,
                y0,
                x1,
                y1,
                width,
                height,
            } => {
                assert_eq!((*x0, *y0, *x1, *y1), (0, 0, 1920, 1080));
                assert_eq!((*width, *height), (1920, 1080));
            }
            other => panic!("expected virtual_screen, got {other:?}"),
        }

        // Unchanged shape on the next samples: no rows.
        monitor.poll(base + Duration::from_secs(1), true, &mut events);
        monitor.poll(base + Duration::from_secs(2), true, &mut events);
        assert_eq!(events.len(), 2);

        // A resolution change edges one row.
        screen.set(Some(VirtualScreenRect {
            width: 2560,
            height: 1440,
        }));
        monitor.poll(base + Duration::from_secs(3), true, &mut events);
        assert_eq!(
            kinds(&events),
            vec!["system_info", "virtual_screen", "virtual_screen"]
        );
    }

    #[test]
    fn sampling_throttles_below_the_cadence() {
        let calls = Rc::new(Cell::new(0u32));
        let calls_view = calls.clone();
        let mut monitor = SystemMonitor::new(
            move || {
                calls_view.set(calls_view.get() + 1);
                Some(VirtualScreenRect {
                    width: 1,
                    height: 1,
                })
            },
            system_info,
        );
        let base = Instant::now();
        let mut events = Vec::new();
        monitor.poll(base, true, &mut events);
        monitor.poll(base + Duration::from_millis(50), true, &mut events);
        assert_eq!(calls.get(), 1, "sub-cadence pass must not resample");
    }

    #[test]
    fn disable_rebaselines_so_reenable_seeds_fresh() {
        let mut monitor = SystemMonitor::new(
            || {
                Some(VirtualScreenRect {
                    width: 800,
                    height: 600,
                })
            },
            system_info,
        );
        let base = Instant::now();
        let mut events = Vec::new();
        monitor.poll(base, true, &mut events);
        monitor.poll(base + Duration::from_secs(1), false, &mut events);
        monitor.poll(base + Duration::from_secs(2), true, &mut events);
        assert_eq!(
            kinds(&events),
            vec![
                "system_info",
                "virtual_screen",
                "system_info",
                "virtual_screen"
            ],
            "re-enable re-seeds instead of edge-detecting stale state"
        );
    }

    #[test]
    fn live_system_info_reads_this_machine() {
        match system_info() {
            EventPayload::SystemInfo {
                host,
                os_version,
                arch,
                processor_count,
                memory_total_bytes,
            } => {
                assert!(!host.is_empty(), "hostname resolves");
                assert!(os_version.contains("Linux"), "kernel identity present");
                assert!(!arch.is_empty(), "arch resolves");
                assert!(processor_count > 0);
                assert!(memory_total_bytes > 1024 * 1024 * 128, "plausible memory");
            }
            other => panic!("expected system_info, got {other:?}"),
        }
    }
}
