//! The LIN-2 D-Bus seam: one watcher thread beside the X pump reads the
//! session boundaries the X server cannot see, publishing a shared
//! [`SessionSnapshot`] the pump's session provider samples on its own
//! cadence (the macOS session-dictionary-poll shape, with the dictionary
//! living behind D-Bus instead of CoreGraphics).
//!
//! Two half-independent sources compose the snapshot:
//!
//! - **elogind** (`org.freedesktop.login1`, the system bus): the session's
//!   `LockedHint` and `Active` properties. `Active` is the console edge
//!   (VT switch / fast-user-switch, the Windows `WTSSESSION` console
//!   analog). `LockedHint` is the lock state lockers REPORT to elogind.
//! - **The session locker's own surface** (`org.xfce.ScreenSaver`, with
//!   the `org.freedesktop.ScreenSaver` name as fallback, the session
//!   bus): whether the locker/saver window is covering the session.
//!   Measured live on the dogfood machine (MX Linux, Xfce 4.18,
//!   2026-08-01): xfce4-screensaver never calls `SetLockedHint`, and
//!   elogind does not latch it on `LockSession` either, so `LockedHint`
//!   alone is blind to every lock the desktop itself performs. The saver
//!   surface is the boundary the user actually experiences; a saver
//!   configured to blank without demanding a password reports the same
//!   engagement (X11 exposes no lock-vs-blank distinction; recorded in
//!   the capability matrix).
//!
//! `locked` is the OR of both sources. elogind's `Lock`/`Unlock` signals
//! are deliberately NOT latched into it: they are requests, not state — a
//! `Lock` no locker honors would latch a block no unlock ever clears.
//!
//! The same thread listens for elogind's `PrepareForSleep` signal (LIN-2's
//! power slice): `true` queues a WillSleep edge, `false` a DidWake edge,
//! each stamped with `CLOCK_BOOTTIME` at receipt, and the pump drains the
//! queue on its own cadence — the IOKit-callback-queue shape from the
//! macOS backend, carried by a signal instead of a callback.
//!
//! Reads are live (property cache off) on a one-second cadence, the
//! Windows/macOS session cadence; every read carries its own timeout so a
//! hung bus degrades to a stale-then-absent snapshot instead of a wedged
//! thread. Setup failure of either half is declared at info level and the
//! other half keeps working; with both halves absent the thread exits and
//! the snapshot stays `None` — session state honestly unknown, which
//! blocks nothing and edges nothing.

use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use async_io::Timer;
use tracing::{debug, info};
use zbus::proxy::{CacheProperties, MethodFlags};

use crate::power::{PowerEdge, PowerEdgeSample};
use crate::session::SessionSnapshot;

/// Snapshot refresh cadence — the shared 1 s session cadence.
const SAMPLE_INTERVAL: Duration = Duration::from_secs(1);
/// Stop-flag responsiveness: the loop wakes at least this often.
const TICK: Duration = Duration::from_millis(500);
/// Per-call guard so one hung bus peer cannot wedge the watcher.
const CALL_TIMEOUT: Duration = Duration::from_secs(2);
/// Bus connection setup guard.
const SETUP_TIMEOUT: Duration = Duration::from_secs(5);

/// The saver names probed for the lock surface, in order. Only the first
/// name that answers is consulted each tick, so a desktop exposing both
/// cannot double-report.
const SAVER_NAMES: [(&str, &str, &str); 2] = [
    (
        "org.xfce.ScreenSaver",
        "/org/xfce/ScreenSaver",
        "org.xfce.ScreenSaver",
    ),
    (
        "org.freedesktop.ScreenSaver",
        "/org/freedesktop/ScreenSaver",
        "org.freedesktop.ScreenSaver",
    ),
];

struct Shared {
    session: Mutex<Option<SessionSnapshot>>,
    power_edges: Mutex<Vec<PowerEdgeSample>>,
}

/// Handle to the watcher thread: the pump samples [`snapshot`], and
/// [`stop`] detaches the thread with its flag set (never joins — a hung
/// bus must not be able to wedge quit; the loop notices within [`TICK`]).
///
/// [`snapshot`]: SessionWatch::snapshot
/// [`stop`]: SessionWatch::stop
#[derive(Clone)]
pub(crate) struct SessionWatch {
    shared: Arc<Shared>,
    stop: Arc<AtomicBool>,
}

impl SessionWatch {
    pub(crate) fn snapshot(&self) -> Option<SessionSnapshot> {
        match self.shared.session.lock() {
            Ok(guard) => *guard,
            Err(poisoned) => *poisoned.into_inner(),
        }
    }

    /// Everything the PrepareForSleep listener queued since the last call.
    pub(crate) fn drain_power_edges(&self) -> Vec<PowerEdgeSample> {
        match self.shared.power_edges.lock() {
            Ok(mut guard) => std::mem::take(&mut *guard),
            Err(poisoned) => std::mem::take(&mut *poisoned.into_inner()),
        }
    }

    pub(crate) fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

/// Spawn the watcher thread. Infallible: setup failures are declared from
/// the thread and leave the snapshot `None`.
pub(crate) fn spawn_session_watch() -> SessionWatch {
    let shared = Arc::new(Shared {
        session: Mutex::new(None),
        power_edges: Mutex::new(Vec::new()),
    });
    let stop = Arc::new(AtomicBool::new(false));
    let thread_shared = Arc::clone(&shared);
    let thread_stop = Arc::clone(&stop);
    std::thread::Builder::new()
        .name("gilbreth-dbus-watch".to_string())
        .spawn(move || async_io::block_on(watch(thread_shared, thread_stop)))
        .map(drop)
        .unwrap_or_else(|error| {
            info!(%error, "D-Bus watcher thread failed to spawn; session boundaries absent");
        });
    SessionWatch { shared, stop }
}

/// Race a future against a timeout.
async fn timed<T>(future: impl std::future::Future<Output = T>, limit: Duration) -> Option<T> {
    futures_lite::future::or(async { Some(future.await) }, async {
        Timer::after(limit).await;
        None
    })
    .await
}

/// The elogind half: a live-read proxy on this user's session object, the
/// numeric session id the schema rows carry, and the manager's
/// `PrepareForSleep` signal stream for the power slice.
struct LoginSession {
    proxy: zbus::Proxy<'static>,
    session_id: u32,
    sleep_stream: Option<zbus::proxy::SignalStream<'static>>,
}

async fn connect_login_session() -> Result<LoginSession, String> {
    let conn = timed(zbus::Connection::system(), SETUP_TIMEOUT)
        .await
        .ok_or_else(|| "system bus connection timed out".to_string())?
        .map_err(|error| format!("system bus connection failed: {error}"))?;
    let manager: zbus::Proxy<'static> = zbus::Proxy::new(
        &conn,
        "org.freedesktop.login1",
        "/org/freedesktop/login1",
        "org.freedesktop.login1.Manager",
    )
    .await
    .map_err(|error| format!("login1 manager proxy failed: {error}"))?;
    // Subscribed before anything else so a suspend racing setup is not
    // lost; a failed subscription degrades to divergence-only recovery
    // (declared, not fatal).
    let sleep_stream = match timed(manager.receive_signal("PrepareForSleep"), CALL_TIMEOUT).await {
        Some(Ok(stream)) => Some(stream),
        Some(Err(error)) => {
            info!(%error, "PrepareForSleep subscription failed; power edges degrade to divergence recovery");
            None
        }
        None => {
            info!("PrepareForSleep subscription timed out; power edges degrade to divergence recovery");
            None
        }
    };

    // Our own session when the process runs inside one; otherwise this
    // user's seated session (a terminal launch outside the session scope,
    // the dogfood shape).
    let by_pid: Option<zbus::zvariant::OwnedObjectPath> = timed(
        manager.call("GetSessionByPID", &(std::process::id(),)),
        CALL_TIMEOUT,
    )
    .await
    .flatten_result();
    let path = match by_pid {
        Some(path) => path,
        None => {
            type SessionRow = (String, u32, String, String, zbus::zvariant::OwnedObjectPath);
            let rows: Vec<SessionRow> = timed(manager.call("ListSessions", &()), CALL_TIMEOUT)
                .await
                .flatten_result()
                .ok_or_else(|| "login1 ListSessions failed".to_string())?;
            // SAFETY: getuid is always safe to call.
            let uid = unsafe { libc::getuid() } as u32;
            let mine = rows.into_iter().filter(|row| row.1 == uid);
            let mut seated = None;
            let mut any = None;
            for row in mine {
                if any.is_none() {
                    any = Some(row.4.clone());
                }
                if !row.3.is_empty() {
                    seated = Some(row.4);
                    break;
                }
            }
            seated
                .or(any)
                .ok_or_else(|| "no login1 session for this user".to_string())?
        }
    };

    let proxy: zbus::Proxy<'static> = zbus::proxy::Builder::new(&conn)
        .destination("org.freedesktop.login1")
        .map_err(|error| format!("session proxy destination: {error}"))?
        .path(path)
        .map_err(|error| format!("session proxy path: {error}"))?
        .interface("org.freedesktop.login1.Session")
        .map_err(|error| format!("session proxy interface: {error}"))?
        .cache_properties(CacheProperties::No)
        .build()
        .await
        .map_err(|error| format!("session proxy build failed: {error}"))?;
    let id: Option<String> = timed(proxy.get_property("Id"), CALL_TIMEOUT)
        .await
        .flatten_result();
    let session_id = id.as_deref().and_then(parse_session_id).unwrap_or(0);
    Ok(LoginSession {
        proxy,
        session_id,
        sleep_stream,
    })
}

/// elogind session ids are numeric strings for user sessions ("1"); a
/// non-numeric id (greeter-style "c2") has no honest u32 form and reads 0.
pub(crate) fn parse_session_id(id: &str) -> Option<u32> {
    id.parse::<u32>().ok()
}

/// The saver half: proxies for each known lock-surface name; the first
/// that answers each tick wins.
struct SaverSurface {
    proxies: Vec<zbus::Proxy<'static>>,
}

async fn connect_saver_surface() -> Result<SaverSurface, String> {
    let conn = timed(zbus::Connection::session(), SETUP_TIMEOUT)
        .await
        .ok_or_else(|| "session bus connection timed out".to_string())?
        .map_err(|error| format!("session bus connection failed: {error}"))?;
    let mut proxies = Vec::new();
    for (destination, path, interface) in SAVER_NAMES {
        let proxy: zbus::Proxy<'static> = zbus::proxy::Builder::new(&conn)
            .destination(destination)
            .and_then(|builder| builder.path(path))
            .and_then(|builder| builder.interface(interface))
            .map_err(|error| format!("saver proxy setup failed: {error}"))?
            .cache_properties(CacheProperties::No)
            .build()
            .await
            .map_err(|error| format!("saver proxy build failed: {error}"))?;
        proxies.push(proxy);
    }
    Ok(SaverSurface { proxies })
}

impl SaverSurface {
    /// The first name that answers `GetActive` decides; auto-start is
    /// suppressed so polling can never launch a screensaver daemon that
    /// is not already running. No answer means no lock surface exists.
    async fn active(&self) -> bool {
        for proxy in &self.proxies {
            let reply: Option<Option<bool>> = timed(
                proxy.call_with_flags("GetActive", MethodFlags::NoAutoStart.into(), &()),
                CALL_TIMEOUT,
            )
            .await
            .flatten_result();
            if let Some(Some(active)) = reply {
                return active;
            }
        }
        false
    }
}

/// `Option<Result<T, E>>` to `Option<T>`, dropping the error silently —
/// per-tick read failures are transient by construction (the setup path
/// reports persistent ones).
trait FlattenResult<T> {
    fn flatten_result(self) -> Option<T>;
}

impl<T, E> FlattenResult<T> for Option<Result<T, E>> {
    fn flatten_result(self) -> Option<T> {
        self.and_then(|result| result.ok())
    }
}

/// What woke the loop: the pacing tick, one PrepareForSleep edge, or the
/// signal stream ending (bus loss; edges degrade to divergence recovery).
enum WakeReason {
    Tick,
    Sleep(bool),
    StreamEnded,
}

async fn watch(shared: Arc<Shared>, stop: Arc<AtomicBool>) {
    let mut login = match connect_login_session().await {
        Ok(login) => Some(login),
        Err(reason) => {
            info!(%reason, "elogind session boundaries absent for this run");
            None
        }
    };
    let saver = match connect_saver_surface().await {
        Ok(saver) => Some(saver),
        Err(reason) => {
            info!(%reason, "session lock-surface watch absent for this run");
            None
        }
    };
    if login.is_none() && saver.is_none() {
        info!("no D-Bus session source available; session and power streams stay absent");
        return;
    }
    let mut sleep_stream = login
        .as_mut()
        .and_then(|login| login.sleep_stream.take())
        .map(Box::pin);
    info!(
        elogind = login.is_some(),
        saver_surface = saver.is_some(),
        power_edges = sleep_stream.is_some(),
        "D-Bus session watch running on the 1 s cadence"
    );

    let mut last_published: Option<SessionSnapshot> = None;
    let mut last_sample_at: Option<std::time::Instant> = None;
    loop {
        if stop.load(Ordering::SeqCst) {
            return;
        }
        // Wait for the pacing tick or a sleep edge, whichever fires first.
        let reason = match sleep_stream.as_mut() {
            Some(stream) => {
                futures_lite::future::or(
                    async {
                        match futures_lite::StreamExt::next(stream).await {
                            Some(message) => message
                                .body()
                                .deserialize::<bool>()
                                .map(WakeReason::Sleep)
                                .unwrap_or(WakeReason::Tick),
                            None => WakeReason::StreamEnded,
                        }
                    },
                    async {
                        Timer::after(TICK).await;
                        WakeReason::Tick
                    },
                )
                .await
            }
            None => {
                Timer::after(TICK).await;
                WakeReason::Tick
            }
        };
        if stop.load(Ordering::SeqCst) {
            return;
        }
        match reason {
            WakeReason::Sleep(start) => {
                let edge = PowerEdgeSample {
                    at: std::time::Instant::now(),
                    continuous_ms: crate::power::boottime_ms(),
                    edge: if start {
                        PowerEdge::WillSleep
                    } else {
                        PowerEdge::DidWake
                    },
                };
                info!(start, "PrepareForSleep edge queued");
                match shared.power_edges.lock() {
                    Ok(mut guard) => guard.push(edge),
                    Err(poisoned) => poisoned.into_inner().push(edge),
                }
                crate::wake_pump();
            }
            WakeReason::StreamEnded => {
                info!("PrepareForSleep stream ended; power edges degrade to divergence recovery");
                sleep_stream = None;
            }
            WakeReason::Tick => {}
        }

        let due = last_sample_at
            .is_none_or(|last| std::time::Instant::now().duration_since(last) >= SAMPLE_INTERVAL);
        if due {
            last_sample_at = Some(std::time::Instant::now());
            let (locked_hint, on_console, session_id) = match &login {
                Some(login) => {
                    let locked: Option<bool> =
                        timed(login.proxy.get_property("LockedHint"), CALL_TIMEOUT)
                            .await
                            .flatten_result();
                    let active: Option<bool> =
                        timed(login.proxy.get_property("Active"), CALL_TIMEOUT)
                            .await
                            .flatten_result();
                    (
                        locked.unwrap_or(false),
                        // A failed read blocks nothing (the unknown-state
                        // rule): absent evidence is not an edge.
                        active.unwrap_or(true),
                        login.session_id,
                    )
                }
                None => (false, true, 0),
            };
            let saver_active = match &saver {
                Some(saver) => saver.active().await,
                None => false,
            };
            let snapshot = SessionSnapshot {
                session_id,
                on_console,
                locked: locked_hint || saver_active,
            };
            if last_published != Some(snapshot) {
                debug!(?snapshot, "session snapshot changed");
                last_published = Some(snapshot);
                if let Ok(mut guard) = shared.session.lock() {
                    *guard = Some(snapshot);
                }
                crate::wake_pump();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_ids_parse_numeric_and_decline_the_rest() {
        assert_eq!(parse_session_id("1"), Some(1));
        assert_eq!(parse_session_id("42"), Some(42));
        assert_eq!(parse_session_id("c2"), None);
        assert_eq!(parse_session_id(""), None);
    }

    #[test]
    fn stop_before_any_bus_answer_leaves_the_snapshot_unknown() {
        let watch = spawn_session_watch();
        watch.stop();
        assert_eq!(watch.snapshot(), None, "no fabricated session state");
    }
}
