#![cfg(target_os = "windows")]

pub mod notification_access;
pub mod record_routine;
pub mod record_routine_ipc;

use std::{
    cell::RefCell,
    collections::{HashMap, HashSet, VecDeque},
    ffi::c_void,
    mem::size_of,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, LazyLock,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use crossbeam_channel::{bounded, Receiver, SendTimeoutError, Sender, TrySendError};
use gilbreth_core::{
    exe_basename_lower, CaptureError, Captured, ClipboardFormatKind, DiagnosticsCounters,
    EventPayload, EventSource, ForegroundState, InputOrigin, Modifiers, MouseButton,
    MouseWheelAxis, ProcessExeSource, ProcessNoiseFilter, SensitiveContextReason,
    SensitiveFieldProbeRequest, SensitiveFieldProbeResult, SensitiveTransitionPending,
    SessionConnectionKind, Source, StopToken, WindowLifecycleOrigin, WindowRef,
};

// The portable control-surface vocabulary lives in gilbreth-core since MAC-0
// (shared with per-OS capture backends); re-exported so this crate's public
// API is unchanged.
pub use gilbreth_core::{
    CaptureControls, CaptureSettings, CaptureStream, DEFAULT_IDLE_THRESHOLD_MS,
};
use tracing::{debug, info, warn};
use windows::{
    core::{implement, w, Ref, BOOL, PWSTR},
    Win32::{
        Foundation::{
            CloseHandle, GetLastError, ERROR_BAD_LENGTH, ERROR_CLASS_ALREADY_EXISTS, FILETIME,
            HANDLE, HGLOBAL, HINSTANCE, HWND, LPARAM, LRESULT, POINT, WPARAM,
        },
        System::{
            Com::{
                CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER,
                COINIT_MULTITHREADED,
            },
            DataExchange::{
                AddClipboardFormatListener, CloseClipboard, EnumClipboardFormats, GetClipboardData,
                GetClipboardSequenceNumber, OpenClipboard, RemoveClipboardFormatListener,
            },
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
                TH32CS_SNAPPROCESS,
            },
            LibraryLoader::GetModuleHandleW,
            Memory::GlobalSize,
            Power::{GetSystemPowerStatus, SYSTEM_POWER_STATUS},
            RemoteDesktop::{
                WTSRegisterSessionNotification, WTSUnRegisterSessionNotification,
                NOTIFY_FOR_THIS_SESSION,
            },
            StationsAndDesktops::{
                CloseDesktop, GetUserObjectInformationW, OpenInputDesktop, DESKTOP_CONTROL_FLAGS,
                DESKTOP_READOBJECTS, HDESK, UOI_NAME,
            },
            SystemInformation::{
                ComputerNamePhysicalDnsHostname, GetComputerNameExW, GetNativeSystemInfo,
                GetTickCount64, GetVersionExW, GlobalMemoryStatusEx, MEMORYSTATUSEX,
                OSVERSIONINFOW, PROCESSOR_ARCHITECTURE, PROCESSOR_ARCHITECTURE_AMD64,
                PROCESSOR_ARCHITECTURE_ARM64, PROCESSOR_ARCHITECTURE_INTEL,
                PROCESSOR_ARCHITECTURE_UNKNOWN, SYSTEM_INFO,
            },
            Threading::{
                GetProcessTimes, OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_FORMAT,
                PROCESS_QUERY_LIMITED_INFORMATION,
            },
            WinRT::{RoInitialize, RoUninitialize, RO_INIT_MULTITHREADED},
        },
        UI::{
            Accessibility::{
                AutomationElementMode_None, CUIAutomation, CUIAutomation8, IUIAutomation,
                IUIAutomationElement, IUIAutomationFocusChangedEventHandler,
                IUIAutomationFocusChangedEventHandler_Impl, SetWinEventHook, TreeScope_Element,
                UIA_IsPasswordPropertyId, UnhookWinEvent, HWINEVENTHOOK,
            },
            Input::KeyboardAndMouse::{
                GetAsyncKeyState, GetDoubleClickTime, GetLastInputInfo, LASTINPUTINFO,
            },
            Input::{
                GetRawInputData, RegisterRawInputDevices, HRAWINPUT, MOUSE_MOVE_ABSOLUTE,
                RAWINPUTDEVICE, RAWINPUTHEADER, RAWKEYBOARD, RAWMOUSE, RIDEV_INPUTSINK, RID_INPUT,
                RIM_TYPEKEYBOARD, RIM_TYPEMOUSE,
            },
            WindowsAndMessaging::{
                CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, EnumWindows,
                GetAncestor, GetCursorPos, GetForegroundWindow, GetMessageW, GetSystemMetrics,
                GetWindow, GetWindowTextW, GetWindowThreadProcessId, IsWindow, IsWindowVisible,
                KillTimer, PostQuitMessage, RegisterClassW, SetTimer, TranslateMessage,
                CHILDID_SELF, EVENT_OBJECT_CREATE, EVENT_OBJECT_DESTROY, EVENT_OBJECT_SHOW,
                EVENT_SYSTEM_DESKTOPSWITCH, EVENT_SYSTEM_FOREGROUND, GA_ROOT, GW_OWNER,
                HWND_MESSAGE, MSG, OBJID_WINDOW, PBT_APMPOWERSTATUSCHANGE, PBT_APMRESUMEAUTOMATIC,
                PBT_APMRESUMESUSPEND, PBT_APMSUSPEND, RI_MOUSE_BUTTON_4_DOWN, RI_MOUSE_BUTTON_4_UP,
                RI_MOUSE_BUTTON_5_DOWN, RI_MOUSE_BUTTON_5_UP, RI_MOUSE_HWHEEL,
                RI_MOUSE_LEFT_BUTTON_DOWN, RI_MOUSE_LEFT_BUTTON_UP, RI_MOUSE_MIDDLE_BUTTON_DOWN,
                RI_MOUSE_MIDDLE_BUTTON_UP, RI_MOUSE_RIGHT_BUTTON_DOWN, RI_MOUSE_RIGHT_BUTTON_UP,
                RI_MOUSE_WHEEL, SM_CXDOUBLECLK, SM_CXDRAG, SM_CXVIRTUALSCREEN, SM_CYDOUBLECLK,
                SM_CYDRAG, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN,
                SYSTEM_METRICS_INDEX, WINDOW_EX_STYLE, WINDOW_STYLE, WINEVENT_OUTOFCONTEXT,
                WM_CLIPBOARDUPDATE, WM_CLOSE, WM_DISPLAYCHANGE, WM_ENDSESSION, WM_INPUT,
                WM_POWERBROADCAST, WM_QUERYENDSESSION, WM_TIMER, WM_WTSSESSION_CHANGE, WNDCLASSW,
                WTS_CONSOLE_CONNECT, WTS_CONSOLE_DISCONNECT, WTS_REMOTE_CONNECT,
                WTS_REMOTE_DISCONNECT, WTS_SESSION_LOCK, WTS_SESSION_UNLOCK,
            },
        },
    },
    UI::Notifications::{
        Management::{UserNotificationListener, UserNotificationListenerAccessStatus},
        NotificationKinds, UserNotification,
    },
};

type ReconcileReply = Sender<Option<u64>>;
type ReconcileRequests = (Sender<ReconcileReply>, Receiver<ReconcileReply>);

static SENSITIVE_RECONCILE_REQUESTS: LazyLock<ReconcileRequests> = LazyLock::new(|| bounded(16));

/// Request a value-free writer-policy reconciliation before capture resumes.
/// On the pump thread this completes synchronously; worker threads queue the
/// request for the next pump wake and receive an acknowledgement.
pub fn request_sensitive_context_reconcile() -> Receiver<Option<u64>> {
    let (reply_tx, reply_rx) = bounded(1);
    let direct = CAPTURE_STATE.with(|state| {
        let mut state = state.borrow_mut();
        state
            .as_mut()
            .map(CaptureState::reconcile_sensitive_context_for_resume)
    });
    if let Some(result) = direct {
        let _ = reply_tx.send(result);
    } else if SENSITIVE_RECONCILE_REQUESTS
        .0
        .try_send(reply_tx.clone())
        .is_err()
    {
        let _ = reply_tx.send(None);
    }
    reply_rx
}

const RI_KEY_BREAK: u16 = 0x0001;
const MOUSE_MOVE_FLUSH_INTERVAL: Duration = Duration::from_millis(250);
const FALLBACK_DOUBLE_CLICK_MS: u64 = 500;
const FALLBACK_DOUBLE_CLICK_BOX_PX: i32 = 4;
const FALLBACK_DRAG_BOX_PX: i32 = 8;
const REMOTE_RELAY_PINNED_CENTER_SAMPLES: u8 = 2;
const PROCESS_POLL_INTERVAL: Duration = Duration::from_secs(5);
/// Upper bound on how long a sensitive-context boundary send may block the
/// message pump when the writer channel is full (finding 6). Long enough to
/// ride out a transient burst, short enough that the UI never freezes.
const SENSITIVE_SEND_TIMEOUT: Duration = Duration::from_millis(250);
const PROCESS_SNAPSHOT_RETRIES: usize = 3;
const NOTIFICATION_APP_LABEL_MAX_CHARS: usize = 128;
const NOTIFICATION_POLL_INTERVAL: Duration = Duration::from_secs(15);
const NOTIFICATION_SEEN_IDS_MAX: usize = 512;
const IDLE_POLL_INTERVAL_MS: u32 = 5_000;
const SYSTEM_POLL_INTERVAL_MS: u32 = 1_000;
const MISSED_POWER_BOUNDARY_THRESHOLD_MS: u64 = 30_000;
const MISSED_POWER_BOUNDARY_MAX_DWELL: Duration =
    Duration::from_millis(MISSED_POWER_BOUNDARY_THRESHOLD_MS);
const POWER_RESUME_DEBOUNCE: Duration = Duration::from_secs(2);
const PASSWORD_FIELD_PROBE_TIMEOUT: Duration = Duration::from_millis(50);
const PASSWORD_FIELD_PROBE_CACHE_TTL: Duration = Duration::from_secs(2);
const IDLE_TIMER_ID: usize = 1;

const CF_TEXT: u32 = 1;
const CF_BITMAP: u32 = 2;
const CF_METAFILEPICT: u32 = 3;
const CF_SYLK: u32 = 4;
const CF_DIF: u32 = 5;
const CF_TIFF: u32 = 6;
const CF_OEMTEXT: u32 = 7;
const CF_DIB: u32 = 8;
const CF_PENDATA: u32 = 10;
const CF_RIFF: u32 = 11;
const CF_WAVE: u32 = 12;
const CF_UNICODETEXT: u32 = 13;
const CF_ENHMETAFILE: u32 = 14;
const CF_HDROP: u32 = 15;
const CF_LOCALE: u32 = 16;
const CF_DIBV5: u32 = 17;

#[link(name = "ntdll")]
extern "system" {
    fn RtlGetVersion(lpversioninformation: *mut OSVERSIONINFOW) -> i32;
}

thread_local! {
    static CAPTURE_STATE: RefCell<Option<CaptureState>> = const { RefCell::new(None) };
}

#[derive(Debug)]
pub struct CapturePump {
    foreground: bool,
    windows: bool,
    keyboard: bool,
    mouse: bool,
    system: bool,
    idle: bool,
}

impl Default for CapturePump {
    fn default() -> Self {
        Self::all()
    }
}

impl CapturePump {
    pub fn all() -> Self {
        Self {
            foreground: true,
            windows: true,
            keyboard: true,
            mouse: true,
            system: true,
            idle: true,
        }
    }

    pub fn foreground_only() -> Self {
        Self {
            foreground: true,
            windows: false,
            keyboard: false,
            mouse: false,
            system: false,
            idle: false,
        }
    }

    pub fn window_only() -> Self {
        Self {
            foreground: false,
            windows: true,
            keyboard: false,
            mouse: false,
            system: false,
            idle: false,
        }
    }

    pub fn keyboard_only() -> Self {
        Self {
            foreground: false,
            windows: false,
            keyboard: true,
            mouse: false,
            system: false,
            idle: false,
        }
    }

    pub fn mouse_only() -> Self {
        Self {
            foreground: false,
            windows: false,
            keyboard: false,
            mouse: true,
            system: false,
            idle: false,
        }
    }

    pub fn system_only() -> Self {
        Self {
            foreground: false,
            windows: false,
            keyboard: false,
            mouse: false,
            system: true,
            idle: false,
        }
    }

    pub fn idle_only() -> Self {
        Self {
            foreground: false,
            windows: false,
            keyboard: false,
            mouse: false,
            system: false,
            idle: true,
        }
    }

    pub fn run_with_message_pump<F>(
        self,
        tx: Sender<Captured>,
        stop: StopToken,
        after_message: F,
    ) -> Result<(), CaptureError>
    where
        F: FnMut(),
    {
        self.run_with_message_pump_and_controls(
            tx,
            stop,
            CaptureControls::all_enabled(),
            after_message,
        )
    }

    pub fn run_with_message_pump_and_controls<F>(
        self,
        tx: Sender<Captured>,
        stop: StopToken,
        controls: CaptureControls,
        mut after_message: F,
    ) -> Result<(), CaptureError>
    where
        F: FnMut(),
    {
        self.run_with_message_pump_controls_and_observer(tx, stop, controls, move |_, _, _| {
            after_message()
        })
    }

    /// Run the shared capture/message pump while exposing each dequeued
    /// Win32 message to the owning app after dispatch. This keeps app-shell
    /// controls such as a thread-registered `WM_HOTKEY` on the one existing
    /// pump thread: no polling thread and no second message loop.
    pub fn run_with_message_pump_controls_and_observer<F>(
        self,
        tx: Sender<Captured>,
        stop: StopToken,
        controls: CaptureControls,
        mut after_message: F,
    ) -> Result<(), CaptureError>
    where
        F: FnMut(u32, usize, isize),
    {
        let process_tx = tx.clone();
        let process_controls = controls.clone();
        let sensitive_field_tx = tx.clone();
        let sensitive_field_controls = controls.clone();
        let notification_tx = tx.clone();
        let notification_controls = controls.clone();
        // Keep a diagnostics handle after `controls` moves into the state, so
        // the shutdown path can report capture-side drops for this run.
        let diagnostics = controls.diagnostics();
        CAPTURE_STATE.with(|state| {
            *state.borrow_mut() = Some(CaptureState::new_with_system_capture(
                tx,
                controls,
                self.system,
            ));
        });
        let _state_guard = CaptureThreadStateGuard;

        if self.foreground {
            seed_initial_foreground();
        }
        if self.windows {
            seed_initial_windows();
        }
        if self.system {
            seed_system();
        }

        let _raw_input_window = if self.keyboard || self.mouse {
            Some(RawInputWindow::create(self.keyboard, self.mouse)?)
        } else {
            None
        };
        let needs_system_window =
            self.system || self.idle || self.foreground || self.keyboard || self.mouse;
        let periodic_timer_interval_ms = if self.system {
            Some(SYSTEM_POLL_INTERVAL_MS)
        } else if self.idle {
            Some(IDLE_POLL_INTERVAL_MS)
        } else {
            None
        };
        let _system_window = if needs_system_window {
            Some(SystemWindow::create(periodic_timer_interval_ms)?)
        } else {
            None
        };
        let _process_monitor = if self.system {
            Some(ProcessMonitor::start(
                process_tx,
                process_controls,
                stop.clone(),
            ))
        } else {
            None
        };
        let _sensitive_field_monitor =
            if sensitive_field_monitor_required(self.keyboard, self.system) {
                Some(SensitiveFieldMonitor::start(
                    sensitive_field_tx,
                    sensitive_field_controls,
                    stop.clone(),
                ))
            } else {
                None
            };
        let _notification_monitor = if self.system {
            Some(NotificationMonitor::start(
                notification_tx,
                notification_controls,
                stop.clone(),
            ))
        } else {
            None
        };

        let mut hooks = Vec::new();
        if self.foreground || self.keyboard {
            hooks.push(install_hook(
                EVENT_SYSTEM_FOREGROUND,
                EVENT_SYSTEM_FOREGROUND,
                Some(foreground_callback),
                "EVENT_SYSTEM_FOREGROUND",
            )?);
            debug!("foreground hook installed");
        }
        if self.windows {
            hooks.push(install_hook(
                EVENT_OBJECT_CREATE,
                EVENT_OBJECT_SHOW,
                Some(window_callback),
                "EVENT_OBJECT_CREATE/DESTROY/SHOW",
            )?);
            debug!("window lifecycle hook installed");
        }
        if self.system {
            if let Some(hook) = install_optional_hook(
                EVENT_SYSTEM_DESKTOPSWITCH,
                EVENT_SYSTEM_DESKTOPSWITCH,
                Some(desktop_switch_callback),
                "EVENT_SYSTEM_DESKTOPSWITCH",
            ) {
                hooks.push(hook);
                debug!("desktop switch hook installed");
            }
        }

        let mut msg = MSG::default();
        while !stop.is_cancelled() {
            let result = unsafe { GetMessageW(&mut msg, None, 0, 0) };
            if result.0 == -1 {
                break;
            }
            if !result.as_bool() {
                break;
            }

            // A worker-thread resume request is woken with WM_APP. Reconcile
            // before dispatching that (or any already-queued) message so no
            // raw input can overtake the writer-policy acknowledgement.
            check_requested_reseed();
            unsafe {
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
            check_requested_reseed();
            flush_due_mouse_movement();
            after_message(msg.message, msg.wParam.0, msg.lParam.0);
        }

        flush_shutdown_events();
        drop(hooks);
        let dropped = diagnostics.capture_events_dropped();
        if dropped > 0 {
            warn!(
                dropped,
                "capture dropped events under channel backpressure during this run; \
                 writer events_skipped does not include these"
            );
        }
        debug!("capture pump stopped");
        Ok(())
    }
}

impl EventSource for CapturePump {
    fn run(self: Box<Self>, tx: Sender<Captured>, stop: StopToken) -> Result<(), CaptureError> {
        self.run_with_message_pump(tx, stop, || {})
    }
}

#[derive(Debug, Default)]
pub struct ForegroundSource;

impl ForegroundSource {
    pub fn run_with_message_pump<F>(
        self,
        tx: Sender<Captured>,
        stop: StopToken,
        after_message: F,
    ) -> Result<(), CaptureError>
    where
        F: FnMut(),
    {
        CapturePump::foreground_only().run_with_message_pump(tx, stop, after_message)
    }
}

impl EventSource for ForegroundSource {
    fn run(self: Box<Self>, tx: Sender<Captured>, stop: StopToken) -> Result<(), CaptureError> {
        self.run_with_message_pump(tx, stop, || {})
    }
}

#[derive(Debug, Default)]
pub struct WindowSource;

impl EventSource for WindowSource {
    fn run(self: Box<Self>, tx: Sender<Captured>, stop: StopToken) -> Result<(), CaptureError> {
        CapturePump::window_only().run_with_message_pump(tx, stop, || {})
    }
}

#[derive(Debug, Default)]
pub struct KeyboardSource;

impl EventSource for KeyboardSource {
    fn run(self: Box<Self>, tx: Sender<Captured>, stop: StopToken) -> Result<(), CaptureError> {
        CapturePump::keyboard_only().run_with_message_pump(tx, stop, || {})
    }
}

#[derive(Debug, Default)]
pub struct MouseSource;

impl EventSource for MouseSource {
    fn run(self: Box<Self>, tx: Sender<Captured>, stop: StopToken) -> Result<(), CaptureError> {
        CapturePump::mouse_only().run_with_message_pump(tx, stop, || {})
    }
}

#[derive(Debug, Default)]
pub struct SystemSource;

impl EventSource for SystemSource {
    fn run(self: Box<Self>, tx: Sender<Captured>, stop: StopToken) -> Result<(), CaptureError> {
        CapturePump::system_only().run_with_message_pump(tx, stop, || {})
    }
}

#[derive(Debug, Default)]
pub struct IdleSource;

impl EventSource for IdleSource {
    fn run(self: Box<Self>, tx: Sender<Captured>, stop: StopToken) -> Result<(), CaptureError> {
        CapturePump::idle_only().run_with_message_pump(tx, stop, || {})
    }
}

struct WinEventHook(HWINEVENTHOOK);

impl Drop for WinEventHook {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = UnhookWinEvent(self.0);
            }
        }
    }
}

struct RawInputWindow {
    hwnd: HWND,
}

impl RawInputWindow {
    fn create(register_keyboard: bool, register_mouse: bool) -> Result<Self, CaptureError> {
        let hmodule = unsafe { GetModuleHandleW(None) }.map_err(|error| {
            CaptureError::WindowsApi(format!("GetModuleHandleW failed: {error}"))
        })?;
        let hinstance = HINSTANCE(hmodule.0);
        let class_name = w!("GilbrethRawInputWindow");

        let class = WNDCLASSW {
            lpfnWndProc: Some(raw_input_wnd_proc),
            hInstance: hinstance,
            lpszClassName: class_name,
            ..Default::default()
        };
        let atom = unsafe { RegisterClassW(&class) };
        if atom == 0 && unsafe { GetLastError() } != ERROR_CLASS_ALREADY_EXISTS {
            return Err(CaptureError::WindowsApi(
                "RegisterClassW(GilbrethRawInputWindow) failed".to_string(),
            ));
        }

        let hwnd = unsafe {
            CreateWindowExW(
                WINDOW_EX_STYLE(0),
                class_name,
                w!(""),
                WINDOW_STYLE(0),
                0,
                0,
                0,
                0,
                Some(HWND_MESSAGE),
                None,
                Some(hinstance),
                None,
            )
        }
        .map_err(|error| {
            CaptureError::WindowsApi(format!("CreateWindowExW(raw input) failed: {error}"))
        })?;
        let window = Self { hwnd };

        let mut devices = Vec::new();
        if register_keyboard {
            devices.push(RAWINPUTDEVICE {
                usUsagePage: 0x01,
                usUsage: 0x06,
                dwFlags: RIDEV_INPUTSINK,
                hwndTarget: window.hwnd,
            });
        }
        if register_mouse {
            devices.push(RAWINPUTDEVICE {
                usUsagePage: 0x01,
                usUsage: 0x02,
                dwFlags: RIDEV_INPUTSINK,
                hwndTarget: window.hwnd,
            });
        }

        unsafe {
            RegisterRawInputDevices(&devices, size_of::<RAWINPUTDEVICE>() as u32).map_err(
                |error| {
                    CaptureError::WindowsApi(format!(
                        "RegisterRawInputDevices(raw input) failed: {error}"
                    ))
                },
            )?;
        }

        debug!(
            keyboard = register_keyboard,
            mouse = register_mouse,
            "raw input window installed"
        );
        Ok(window)
    }
}

impl Drop for RawInputWindow {
    fn drop(&mut self) {
        if !self.hwnd.is_invalid() {
            if let Err(error) = unsafe { DestroyWindow(self.hwnd) } {
                warn!(%error, "failed to destroy raw input window");
            }
        }
    }
}

struct SystemWindow {
    hwnd: HWND,
    periodic_timer_id: Option<usize>,
    session_notifications_registered: bool,
    clipboard_listener_registered: bool,
}

impl SystemWindow {
    fn create(periodic_timer_interval_ms: Option<u32>) -> Result<Self, CaptureError> {
        let hmodule = unsafe { GetModuleHandleW(None) }.map_err(|error| {
            CaptureError::WindowsApi(format!("GetModuleHandleW failed: {error}"))
        })?;
        let hinstance = HINSTANCE(hmodule.0);
        let class_name = w!("GilbrethSystemWindow");

        let class = WNDCLASSW {
            lpfnWndProc: Some(system_wnd_proc),
            hInstance: hinstance,
            lpszClassName: class_name,
            ..Default::default()
        };
        let atom = unsafe { RegisterClassW(&class) };
        if atom == 0 && unsafe { GetLastError() } != ERROR_CLASS_ALREADY_EXISTS {
            return Err(CaptureError::WindowsApi(
                "RegisterClassW(GilbrethSystemWindow) failed".to_string(),
            ));
        }

        let hwnd = unsafe {
            CreateWindowExW(
                WINDOW_EX_STYLE(0),
                class_name,
                w!(""),
                WINDOW_STYLE(0),
                0,
                0,
                0,
                0,
                None,
                None,
                Some(hinstance),
                None,
            )
        }
        .map_err(|error| {
            CaptureError::WindowsApi(format!("CreateWindowExW(system) failed: {error}"))
        })?;

        let periodic_timer_id = if let Some(interval_ms) = periodic_timer_interval_ms {
            let timer_id = unsafe { SetTimer(Some(hwnd), IDLE_TIMER_ID, interval_ms, None) };
            if timer_id == 0 {
                unsafe {
                    let _ = DestroyWindow(hwnd);
                }
                return Err(CaptureError::WindowsApi(
                    "SetTimer(system) failed".to_string(),
                ));
            }
            Some(timer_id)
        } else {
            None
        };

        let session_notifications_registered =
            match unsafe { WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION) } {
                Ok(()) => true,
                Err(error) => {
                    warn!(%error, "failed to register session-change notifications");
                    false
                }
            };

        let clipboard_listener_registered = match unsafe { AddClipboardFormatListener(hwnd) } {
            Ok(()) => true,
            Err(error) => {
                warn!(%error, "failed to register clipboard listener");
                false
            }
        };

        debug!(
            periodic_timer_interval_ms,
            session_notifications_registered,
            clipboard_listener_registered,
            "system window installed"
        );
        Ok(Self {
            hwnd,
            periodic_timer_id,
            session_notifications_registered,
            clipboard_listener_registered,
        })
    }
}

impl Drop for SystemWindow {
    fn drop(&mut self) {
        if self.clipboard_listener_registered {
            if let Err(error) = unsafe { RemoveClipboardFormatListener(self.hwnd) } {
                warn!(%error, "failed to unregister clipboard listener");
            }
        }
        if self.session_notifications_registered {
            if let Err(error) = unsafe { WTSUnRegisterSessionNotification(self.hwnd) } {
                warn!(%error, "failed to unregister session-change notifications");
            }
        }
        if let Some(timer_id) = self.periodic_timer_id.take() {
            if let Err(error) = unsafe { KillTimer(Some(self.hwnd), timer_id) } {
                warn!(%error, "failed to kill system timer");
            }
        }
        if !self.hwnd.is_invalid() {
            if let Err(error) = unsafe { DestroyWindow(self.hwnd) } {
                warn!(%error, "failed to destroy system window");
            }
        }
    }
}

struct ProcessMonitor {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl ProcessMonitor {
    fn start(tx: Sender<Captured>, controls: CaptureControls, stop: StopToken) -> Self {
        let local_stop = Arc::new(AtomicBool::new(false));
        let thread_stop = local_stop.clone();
        let handle = thread::spawn(move || {
            run_process_monitor(tx, controls, stop, thread_stop);
        });
        Self {
            stop: local_stop,
            handle: Some(handle),
        }
    }
}

impl Drop for ProcessMonitor {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            handle.thread().unpark();
            if handle.join().is_err() {
                warn!("process monitor thread panicked during shutdown");
            }
        }
    }
}

fn run_process_monitor(
    tx: Sender<Captured>,
    controls: CaptureControls,
    stop: StopToken,
    local_stop: Arc<AtomicBool>,
) {
    let mut tracker = ProcessTracker::default();
    let mut noise_filter = ProcessNoiseFilter::new(Instant::now());
    while !stop.is_cancelled() && !local_stop.load(Ordering::SeqCst) {
        let now = Instant::now();
        match read_process_snapshot_with_retries() {
            Ok(snapshot) => {
                let transitions = tracker.apply_snapshot(snapshot, process_identity_exe);
                for transition in transitions {
                    if controls.app_excluded(&transition.basename()) {
                        continue;
                    }
                    let keep = !controls.process_filter_enabled() || {
                        let basename = transition.basename();
                        controls.foreground_exe_seen(&basename)
                            || noise_filter.keep_after_counting(&basename, now)
                    };
                    if keep {
                        send_process_transition(&tx, &controls, transition);
                    }
                }
            }
            Err(error) => {
                warn!(%error, "process snapshot failed; keeping previous process state");
            }
        }
        if let Some(payload) = noise_filter.summary_if_due(Instant::now()) {
            send_system_payload(&tx, &controls, payload, "process churn summary");
        }

        thread::park_timeout(PROCESS_POLL_INTERVAL);
    }
    if let Some(payload) = noise_filter.take_summary(Instant::now()) {
        send_system_payload(&tx, &controls, payload, "process churn summary");
    }
    debug!("process monitor stopped");
}

fn send_system_payload(
    tx: &Sender<Captured>,
    controls: &CaptureControls,
    payload: EventPayload,
    label: &str,
) {
    let captured = Captured::new(Source::System, Instant::now(), payload);
    if !controls.enabled_for(&captured) {
        debug!("capture stream disabled; dropping {label} before enqueue");
        return;
    }
    match tx.try_send(captured) {
        Ok(()) => {}
        Err(TrySendError::Full(_)) => {
            controls.diagnostics().increment_capture_events_dropped();
            warn!("event channel full; dropping {label}");
        }
        Err(TrySendError::Disconnected(_)) => warn!("event receiver closed"),
    }
}

// The background-process churn filter (ProcessNoiseFilter, demote-don't-
// discard) hoisted to gilbreth-core 2026-07-12 with its thresholds — the
// recorded MAC-1 core-hoist trigger; bodies moved unchanged, unit tests
// moved with them.

fn send_process_transition(
    tx: &Sender<Captured>,
    controls: &CaptureControls,
    transition: ProcessTransition,
) {
    let captured = transition.into_captured(Instant::now());
    if !controls.enabled_for(&captured) {
        debug!("capture stream disabled; dropping process event before enqueue");
        return;
    }

    match tx.try_send(captured) {
        Ok(()) => {}
        Err(TrySendError::Full(_)) => {
            controls.diagnostics().increment_capture_events_dropped();
            warn!("event channel full; dropping process event");
        }
        Err(TrySendError::Disconnected(_)) => warn!("event receiver closed"),
    }
}

fn sensitive_field_monitor_required(keyboard: bool, system: bool) -> bool {
    keyboard || system
}

/// The channel + flag bundle every sensitive-field participant shares: the
/// monitor thread, its COM focus handler, and shutdown reconciliation.
#[derive(Clone)]
struct SensitiveFieldShared {
    tx: Sender<Captured>,
    controls: CaptureControls,
    diagnostics: DiagnosticsCounters,
    active: Arc<AtomicBool>,
    confirmed_active: Arc<AtomicBool>,
    focus_generation: Arc<AtomicU64>,
}

impl SensitiveFieldShared {
    fn emit_confirmed_sample(&self, is_password: bool, now: Instant) {
        emit_confirmed_password_field_sample(
            &self.tx,
            &self.controls,
            &self.diagnostics,
            &self.active,
            &self.confirmed_active,
            is_password,
            now,
        );
    }
}

struct SensitiveFieldMonitor {
    stop: Arc<AtomicBool>,
    controls: CaptureControls,
    handle: Option<JoinHandle<()>>,
}

impl SensitiveFieldMonitor {
    fn start(tx: Sender<Captured>, controls: CaptureControls, stop: StopToken) -> Self {
        let local_stop = Arc::new(AtomicBool::new(false));
        let thread_stop = local_stop.clone();
        let shared = SensitiveFieldShared {
            tx,
            controls: controls.clone(),
            diagnostics: controls.diagnostics(),
            active: controls.password_field_active_flag(),
            confirmed_active: controls.password_field_confirmed_active_flag(),
            focus_generation: controls.password_focus_generation_counter(),
        };
        let (probe_tx, probe_rx) = bounded(8);
        controls.set_sensitive_field_probe(Some(probe_tx));
        let thread_controls = controls.clone();
        let handle = thread::spawn(move || {
            run_sensitive_field_monitor(shared, stop, thread_stop, probe_rx);
            thread_controls.set_sensitive_field_probe(None);
        });
        Self {
            stop: local_stop,
            controls,
            handle: Some(handle),
        }
    }
}

impl Drop for SensitiveFieldMonitor {
    fn drop(&mut self) {
        self.controls.set_sensitive_field_probe(None);
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            handle.thread().unpark();
            if handle.join().is_err() {
                warn!("sensitive-field monitor thread panicked during shutdown");
            }
        }
    }
}

#[derive(Clone)]
#[implement(IUIAutomationFocusChangedEventHandler)]
struct SensitiveFieldFocusHandler {
    shared: SensitiveFieldShared,
}

#[allow(non_snake_case)]
impl IUIAutomationFocusChangedEventHandler_Impl for SensitiveFieldFocusHandler_Impl {
    fn HandleFocusChangedEvent(
        &self,
        sender: Ref<IUIAutomationElement>,
    ) -> windows::core::Result<()> {
        self.shared.focus_generation.fetch_add(1, Ordering::SeqCst);
        self.shared.active.store(true, Ordering::SeqCst);
        let is_password = sender
            .as_ref()
            .and_then(uia_element_is_password)
            .unwrap_or(false);
        self.shared
            .emit_confirmed_sample(is_password, Instant::now());
        Ok(())
    }
}

fn run_sensitive_field_monitor(
    shared: SensitiveFieldShared,
    stop: StopToken,
    local_stop: Arc<AtomicBool>,
    probe_rx: Receiver<SensitiveFieldProbeRequest>,
) {
    if let Err(error) = run_sensitive_field_monitor_inner(&shared, &stop, &local_stop, &probe_rx) {
        warn!(%error, "sensitive-field UIA monitor unavailable");
        if !stop.is_cancelled() && !local_stop.load(Ordering::SeqCst) {
            shared.active.store(true, Ordering::SeqCst);
            return;
        }
    }
    shared.emit_confirmed_sample(false, Instant::now());
    debug!("sensitive-field monitor stopped");
}

fn run_sensitive_field_monitor_inner(
    shared: &SensitiveFieldShared,
    stop: &StopToken,
    local_stop: &Arc<AtomicBool>,
    probe_rx: &Receiver<SensitiveFieldProbeRequest>,
) -> Result<(), CaptureError> {
    let _com = UiaComApartment::initialize()?;
    let automation = create_uia_automation()?;
    let cache_request = unsafe {
        automation
            .CreateCacheRequest()
            .map_err(windows_context("IUIAutomation::CreateCacheRequest"))?
    };
    unsafe {
        cache_request
            .SetAutomationElementMode(AutomationElementMode_None)
            .map_err(windows_context(
                "IUIAutomationCacheRequest::SetAutomationElementMode",
            ))?;
        cache_request
            .SetTreeScope(windows::Win32::UI::Accessibility::TreeScope(
                TreeScope_Element.0,
            ))
            .map_err(windows_context("IUIAutomationCacheRequest::SetTreeScope"))?;
        cache_request
            .AddProperty(UIA_IsPasswordPropertyId)
            .map_err(windows_context("IUIAutomationCacheRequest::AddProperty"))?;
    }

    let handler = SensitiveFieldFocusHandler {
        shared: shared.clone(),
    };
    let handler: IUIAutomationFocusChangedEventHandler = handler.into();
    unsafe {
        automation
            .AddFocusChangedEventHandler(&cache_request, &handler)
            .map_err(windows_context(
                "IUIAutomation::AddFocusChangedEventHandler",
            ))?;
    }

    if let Some(is_password) = focused_element_is_password(&automation, &cache_request) {
        shared.emit_confirmed_sample(is_password, Instant::now());
    }

    while !stop.is_cancelled() && !local_stop.load(Ordering::SeqCst) {
        match probe_rx.recv_timeout(Duration::from_millis(50)) {
            Ok(request) => {
                let result = probe_focused_password_field(
                    &automation,
                    &cache_request,
                    &shared.focus_generation,
                );
                let _ = request.reply.send(result);
            }
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
        }
    }

    if let Err(error) = unsafe { automation.RemoveFocusChangedEventHandler(&handler) } {
        debug!(%error, "failed to remove sensitive-field focus handler");
    }
    Ok(())
}

fn probe_focused_password_field(
    automation: &IUIAutomation,
    cache_request: &windows::Win32::UI::Accessibility::IUIAutomationCacheRequest,
    focus_generation: &AtomicU64,
) -> Option<SensitiveFieldProbeResult> {
    probe_focused_password_field_with(focus_generation, || {
        focused_element_is_password(automation, cache_request)
    })
}

fn probe_focused_password_field_with(
    focus_generation: &AtomicU64,
    read_focused_is_password: impl FnOnce() -> Option<bool>,
) -> Option<SensitiveFieldProbeResult> {
    let generation_before = focus_generation.load(Ordering::SeqCst);
    let is_password = read_focused_is_password()?;
    if focus_generation.load(Ordering::SeqCst) != generation_before {
        return None;
    }
    Some(SensitiveFieldProbeResult {
        is_password,
        focus_generation: generation_before,
    })
}

fn focused_element_is_password(
    automation: &IUIAutomation,
    cache_request: &windows::Win32::UI::Accessibility::IUIAutomationCacheRequest,
) -> Option<bool> {
    unsafe { automation.GetFocusedElementBuildCache(cache_request) }
        .ok()
        .and_then(|element| uia_element_is_password(&element))
}

fn emit_confirmed_password_field_sample(
    tx: &Sender<Captured>,
    controls: &CaptureControls,
    diagnostics: &DiagnosticsCounters,
    active: &Arc<AtomicBool>,
    confirmed_active: &Arc<AtomicBool>,
    is_password: bool,
    now: Instant,
) {
    // Announce the transition before waiting on resume serialization. That
    // gates every ordinary stream until the state and writer-policy boundary
    // agree, including a transition that arrived during the final reopen.
    let _transition_pending = controls.begin_sensitive_transition();
    let _resume_guard = controls.sensitive_resume_guard();
    active.store(is_password, Ordering::SeqCst);
    let previous = confirmed_active.swap(is_password, Ordering::SeqCst);
    if previous == is_password {
        return;
    }
    if controls.sensitive_transition_should_defer() {
        // Panic pause stores no context timestamps. Keep the capture-side
        // state current; the resume reseed reconciles writer policy before
        // reopening ordinary traffic.
        controls.request_sensitive_context_reconcile();
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
    match send_sensitive_context_capture(
        tx,
        Captured::new(Source::System, now, payload),
        "sensitive-field",
    ) {
        SensitiveBoundarySend::Delivered => return,
        SensitiveBoundarySend::TimedOut(_) => {
            // This monitor runs off the pump thread and cannot reach the
            // pump-owned retry queue, so a timed-out confirmation really is
            // dropped -- count it (S2). Keystroke redaction itself is
            // capture-side and does not depend on this row.
            diagnostics.increment_capture_events_dropped();
        }
        SensitiveBoundarySend::Disconnected => {}
    }
    active.store(previous, Ordering::SeqCst);
    confirmed_active.store(previous, Ordering::SeqCst);
}

struct NotificationMonitor {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl NotificationMonitor {
    fn start(tx: Sender<Captured>, controls: CaptureControls, stop: StopToken) -> Self {
        let local_stop = Arc::new(AtomicBool::new(false));
        let thread_stop = local_stop.clone();
        let handle = thread::spawn(move || {
            run_notification_monitor(tx, controls, stop, thread_stop);
        });
        Self {
            stop: local_stop,
            handle: Some(handle),
        }
    }
}

impl Drop for NotificationMonitor {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            handle.thread().unpark();
            if handle.join().is_err() {
                warn!("notification monitor thread panicked during shutdown");
            }
        }
    }
}

fn run_notification_monitor(
    tx: Sender<Captured>,
    controls: CaptureControls,
    stop: StopToken,
    local_stop: Arc<AtomicBool>,
) {
    while !stop.is_cancelled() && !local_stop.load(Ordering::SeqCst) {
        match run_notification_monitor_inner(tx.clone(), controls.clone(), &stop, &local_stop) {
            Ok(()) => break,
            Err(error) => {
                warn!(%error, "notification monitor unavailable; will retry");
                thread::park_timeout(NOTIFICATION_POLL_INTERVAL);
            }
        }
    }
    debug!("notification monitor stopped");
}

fn run_notification_monitor_inner(
    tx: Sender<Captured>,
    controls: CaptureControls,
    stop: &StopToken,
    local_stop: &Arc<AtomicBool>,
) -> Result<(), CaptureError> {
    let _winrt = WinRtApartment::initialize()?;
    let listener = UserNotificationListener::Current()
        .map_err(windows_context("UserNotificationListener::Current"))?;
    let mut seen = NotificationSeenIds::default();
    let mut polling_active = false;
    let mut last_access = None;
    while !stop.is_cancelled() && !local_stop.load(Ordering::SeqCst) {
        let access = match notification_listener_access(&listener) {
            Ok(access) => access,
            Err(error) => {
                // GetAccessStatus can fail transiently while the shell or
                // notification service is restarting. Keep the monitor alive
                // so a later Allowed state really can activate capture.
                warn!(%error, "notification access status read failed; will retry");
                polling_active = false;
                seen = NotificationSeenIds::default();
                thread::park_timeout(NOTIFICATION_POLL_INTERVAL);
                continue;
            }
        };
        if last_access != Some(access) {
            info!(
                access = notification_access_status_name(access),
                "notification listener access observed; the background worker never requests consent"
            );
            last_access = Some(access);
        }
        if access != UserNotificationListenerAccessStatus::Allowed {
            polling_active = false;
            seen = NotificationSeenIds::default();
            thread::park_timeout(NOTIFICATION_POLL_INTERVAL);
            continue;
        }
        if !polling_active {
            match poll_notifications_once(&listener, &tx, &controls, &mut seen, true) {
                Ok(()) => {
                    polling_active = true;
                    debug!("notification polling fallback installed");
                }
                Err(error) => warn!(%error, "notification seed poll failed; will retry"),
            }
        } else if let Err(error) =
            poll_notifications_once(&listener, &tx, &controls, &mut seen, false)
        {
            warn!(%error, "notification polling pass failed");
        }
        thread::park_timeout(NOTIFICATION_POLL_INTERVAL);
    }

    Ok(())
}

#[derive(Default)]
struct NotificationSeenIds {
    ordered: VecDeque<u32>,
    set: HashSet<u32>,
}

impl NotificationSeenIds {
    fn remember(&mut self, notification_id: u32) -> bool {
        if !self.set.insert(notification_id) {
            return false;
        }
        self.ordered.push_back(notification_id);
        while self.ordered.len() > NOTIFICATION_SEEN_IDS_MAX {
            if let Some(old) = self.ordered.pop_front() {
                self.set.remove(&old);
            }
        }
        true
    }
}

fn poll_notifications_once(
    listener: &UserNotificationListener,
    tx: &Sender<Captured>,
    controls: &CaptureControls,
    seen: &mut NotificationSeenIds,
    seed_only: bool,
) -> Result<(), CaptureError> {
    let notifications = listener
        .GetNotificationsAsync(NotificationKinds::Toast)
        .map_err(windows_context(
            "UserNotificationListener::GetNotificationsAsync",
        ))?
        .join()
        .map_err(windows_context(
            "UserNotificationListener::GetNotificationsAsync::join",
        ))?;
    let mut by_app: HashMap<Option<String>, u32> = HashMap::new();
    for notification in &notifications {
        let notification_id = match notification
            .Id()
            .map_err(windows_context("UserNotification::Id"))
        {
            Ok(id) => id,
            Err(error) => {
                warn!(%error, "notification row skipped after ID read failed");
                continue;
            }
        };
        note_polled_notification(
            seen,
            seed_only,
            notification_id,
            notification_app_from(&notification),
            &mut by_app,
        );
    }
    for (app, count) in by_app {
        emit_notification_received(tx, controls, app, count, Instant::now());
    }
    Ok(())
}

fn note_polled_notification(
    seen: &mut NotificationSeenIds,
    seed_only: bool,
    notification_id: u32,
    app: Option<String>,
    by_app: &mut HashMap<Option<String>, u32>,
) {
    if !seen.remember(notification_id) || seed_only {
        return;
    }
    *by_app.entry(app).or_insert(0) += 1;
}

fn notification_listener_access(
    listener: &UserNotificationListener,
) -> Result<UserNotificationListenerAccessStatus, CaptureError> {
    listener
        .GetAccessStatus()
        .map_err(windows_context("UserNotificationListener::GetAccessStatus"))
}

fn notification_app_from(notification: &UserNotification) -> Option<String> {
    let app_info = notification.AppInfo().ok()?;
    app_info
        .DisplayInfo()
        .ok()
        .and_then(|display| display.DisplayName().ok())
        .and_then(|display_name| notification_app_label(&display_name.to_string_lossy()))
        .or_else(|| {
            app_info
                .PackageFamilyName()
                .ok()
                .and_then(|name| notification_app_label(&name.to_string_lossy()))
        })
        .or_else(|| {
            app_info
                .AppUserModelId()
                .ok()
                .and_then(|id| notification_app_label(&id.to_string_lossy()))
        })
}

fn notification_app_label(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.chars().count() > NOTIFICATION_APP_LABEL_MAX_CHARS
        || trimmed.chars().any(char::is_control)
    {
        return None;
    }
    Some(trimmed.to_string())
}

fn emit_notification_received(
    tx: &Sender<Captured>,
    controls: &CaptureControls,
    app: Option<String>,
    count: u32,
    now: Instant,
) {
    if count == 0 {
        return;
    }
    let current_focus = current_foreground_window();
    if notification_excluded_at_capture_boundary(controls, app.as_deref(), current_focus.as_ref()) {
        return;
    }
    send_system_capture(
        tx,
        controls,
        Captured::new(
            Source::System,
            now,
            EventPayload::NotificationsReceived { app, count },
        ),
        "notification",
    );
}

fn notification_excluded_at_capture_boundary(
    controls: &CaptureControls,
    app_label: Option<&str>,
    current_focus: Option<&WindowRef>,
) -> bool {
    // WinRT supplies DisplayName/PFN/AUMID metadata, not a trustworthy exe
    // identity. Any configured app exclusion therefore disables notification
    // rows globally; the narrower checks remain defense in depth if capture
    // controls ever grow a scoped exclusion mode.
    controls.has_app_exclusions()
        || current_focus.is_some_and(|window| controls.app_excluded(&window.exe))
        || app_label.is_some_and(|label| controls.notification_app_excluded(label))
}

fn notification_access_status_name(status: UserNotificationListenerAccessStatus) -> &'static str {
    match status {
        UserNotificationListenerAccessStatus::Unspecified => "unspecified",
        UserNotificationListenerAccessStatus::Allowed => "allowed",
        UserNotificationListenerAccessStatus::Denied => "denied",
        _ => "other",
    }
}

fn send_system_capture(
    tx: &Sender<Captured>,
    controls: &CaptureControls,
    captured: Captured,
    stream: &'static str,
) {
    if !controls.enabled_for(&captured) {
        debug!(
            stream,
            "capture stream disabled; dropping event before enqueue"
        );
        return;
    }

    match tx.try_send(captured) {
        Ok(()) => {}
        Err(TrySendError::Full(_)) => {
            controls.diagnostics().increment_capture_events_dropped();
            warn!(stream, "event channel full; dropping event");
        }
        Err(TrySendError::Disconnected(_)) => warn!(stream, "event receiver closed"),
    }
}

/// Outcome of the bounded boundary send: the pump-thread caller queues a
/// `TimedOut` row for retry ahead of later captures, while the aux-thread
/// password monitor (which has no access to the pump-owned retry queue)
/// rolls back and counts it.
enum SensitiveBoundarySend {
    Delivered,
    TimedOut(Captured),
    Disconnected,
}

/// Bounded send for a sensitive-context boundary row. Boundaries gate
/// redaction, so they strongly prefer delivery — but a blocking send on a
/// full channel would hang the Win32 message pump indefinitely, so the wait
/// is bounded to SENSITIVE_SEND_TIMEOUT. A timed-out row is handed back to
/// the caller (the enter direction must fail closed: an edge-triggered lock
/// boundary that is simply dropped would leave the whole locked span stored
/// unredacted). A disconnected receiver discards — the writer is gone for
/// the rest of the run.
fn send_sensitive_context_capture(
    tx: &Sender<Captured>,
    captured: Captured,
    stream: &'static str,
) -> SensitiveBoundarySend {
    match tx.send_timeout(captured, SENSITIVE_SEND_TIMEOUT) {
        Ok(()) => SensitiveBoundarySend::Delivered,
        Err(SendTimeoutError::Timeout(captured)) => {
            warn!(
                stream,
                "event channel full for {}ms; sensitive-context boundary not delivered yet",
                SENSITIVE_SEND_TIMEOUT.as_millis()
            );
            SensitiveBoundarySend::TimedOut(captured)
        }
        Err(SendTimeoutError::Disconnected(_)) => {
            warn!(
                stream,
                "event receiver closed; sensitive-context event not delivered"
            );
            SensitiveBoundarySend::Disconnected
        }
    }
}

fn uia_element_is_password(element: &IUIAutomationElement) -> Option<bool> {
    unsafe {
        element
            .CachedIsPassword()
            .or_else(|_| element.CurrentIsPassword())
            .ok()
            .map(|value| value.as_bool())
    }
}

struct UiaComApartment;

impl UiaComApartment {
    fn initialize() -> Result<Self, CaptureError> {
        unsafe {
            CoInitializeEx(None, COINIT_MULTITHREADED)
                .ok()
                .map_err(windows_error)?;
        }
        Ok(Self)
    }
}

impl Drop for UiaComApartment {
    fn drop(&mut self) {
        unsafe {
            CoUninitialize();
        }
    }
}

fn create_uia_automation() -> Result<IUIAutomation, CaptureError> {
    unsafe {
        CoCreateInstance(&CUIAutomation8, None, CLSCTX_INPROC_SERVER)
            .or_else(|_| CoCreateInstance(&CUIAutomation, None, CLSCTX_INPROC_SERVER))
            .map_err(windows_error)
    }
}

struct WinRtApartment;

impl WinRtApartment {
    fn initialize() -> Result<Self, CaptureError> {
        unsafe {
            RoInitialize(RO_INIT_MULTITHREADED).map_err(windows_error)?;
        }
        Ok(Self)
    }
}

impl Drop for WinRtApartment {
    fn drop(&mut self) {
        unsafe {
            RoUninitialize();
        }
    }
}

fn windows_error(error: windows::core::Error) -> CaptureError {
    CaptureError::WindowsApi(error.to_string())
}

fn windows_context(label: &'static str) -> impl FnOnce(windows::core::Error) -> CaptureError {
    move |error| CaptureError::WindowsApi(format!("{label}: {error}"))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProcessSnapshot {
    entries: HashMap<u32, String>,
}

impl ProcessSnapshot {
    fn from_entries(entries: impl IntoIterator<Item = ProcessSnapshotEntry>) -> Option<Self> {
        let entries: HashMap<u32, String> = entries
            .into_iter()
            .filter(|entry| !entry.snapshot_name.trim().is_empty())
            .map(|entry| (entry.pid, entry.snapshot_name))
            .collect();
        (!entries.is_empty()).then_some(Self { entries })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProcessSnapshotEntry {
    pid: u32,
    snapshot_name: String,
}

#[derive(Default)]
struct ProcessTracker {
    seeded: bool,
    live: HashMap<u32, ProcessIdentity>,
}

impl ProcessTracker {
    fn apply_snapshot<F>(
        &mut self,
        snapshot: Option<ProcessSnapshot>,
        mut resolve_exe: F,
    ) -> Vec<ProcessTransition>
    where
        F: FnMut(u32, &str) -> ProcessDetails,
    {
        let Some(snapshot) = snapshot else {
            return Vec::new();
        };

        if !self.seeded {
            self.live = enrich_process_snapshot(&snapshot, &mut resolve_exe);
            self.seeded = true;
            return Vec::new();
        }

        let mut transitions = Vec::new();
        let mut next_live = HashMap::with_capacity(snapshot.entries.len());
        let mut pids: Vec<u32> = snapshot
            .entries
            .keys()
            .chain(self.live.keys())
            .copied()
            .collect();
        pids.sort_unstable();
        pids.dedup();

        for pid in pids {
            match (self.live.get(&pid), snapshot.entries.get(&pid)) {
                (Some(previous), Some(snapshot_name)) => {
                    let next = ProcessIdentity::new(pid, snapshot_name, &mut resolve_exe);
                    if previous.is_same_process(&next) {
                        next_live.insert(pid, previous.refreshed_with(next));
                    } else {
                        transitions.push(ProcessTransition::Exited(previous.clone()));
                        transitions.push(ProcessTransition::Started(next.clone()));
                        next_live.insert(pid, next);
                    }
                }
                (Some(previous), None) => {
                    transitions.push(ProcessTransition::Exited(previous.clone()));
                }
                (None, Some(snapshot_name)) => {
                    let next = ProcessIdentity::new(pid, snapshot_name, &mut resolve_exe);
                    transitions.push(ProcessTransition::Started(next.clone()));
                    next_live.insert(pid, next);
                }
                (None, None) => {}
            }
        }

        self.live = next_live;
        transitions
    }
}

fn enrich_process_snapshot<F>(
    snapshot: &ProcessSnapshot,
    resolve_exe: &mut F,
) -> HashMap<u32, ProcessIdentity>
where
    F: FnMut(u32, &str) -> ProcessDetails,
{
    snapshot
        .entries
        .iter()
        .map(|(pid, snapshot_name)| (*pid, ProcessIdentity::new(*pid, snapshot_name, resolve_exe)))
        .collect()
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProcessIdentity {
    pid: u32,
    compare_name: String,
    exe: String,
    exe_source: ProcessExeSource,
    creation_time_100ns: Option<u64>,
}

impl ProcessIdentity {
    fn new<F>(pid: u32, snapshot_name: &str, resolve_exe: &mut F) -> Self
    where
        F: FnMut(u32, &str) -> ProcessDetails,
    {
        let details = resolve_exe(pid, snapshot_name);
        Self {
            pid,
            compare_name: compare_process_name(snapshot_name),
            exe: details.exe,
            exe_source: details.exe_source,
            creation_time_100ns: details.creation_time_100ns,
        }
    }

    fn is_same_process(&self, next: &Self) -> bool {
        self.compare_name == next.compare_name
            && match (self.creation_time_100ns, next.creation_time_100ns) {
                (Some(previous), Some(next)) => previous == next,
                _ => true,
            }
    }

    fn refreshed_with(&self, mut next: Self) -> Self {
        if next.creation_time_100ns.is_none() {
            next.creation_time_100ns = self.creation_time_100ns;
        }
        next
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProcessDetails {
    exe: String,
    exe_source: ProcessExeSource,
    creation_time_100ns: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ProcessTransition {
    Started(ProcessIdentity),
    Exited(ProcessIdentity),
}

impl ProcessTransition {
    /// Lowercased exe basename for churn filtering. Prefers the snapshot name
    /// (already a basename); falls back to the resolved path's basename.
    fn basename(&self) -> String {
        let identity = match self {
            ProcessTransition::Started(identity) | ProcessTransition::Exited(identity) => identity,
        };
        if identity.compare_name.is_empty() {
            exe_basename_lower(&identity.exe)
        } else {
            identity.compare_name.clone()
        }
    }

    fn into_captured(self, captured_at: Instant) -> Captured {
        let (pid, exe_source, payload) = match self {
            ProcessTransition::Started(identity) => {
                let payload = EventPayload::ProcessStarted {
                    pid: identity.pid,
                    exe: identity.exe.clone(),
                    exe_source: identity.exe_source,
                };
                (identity.pid, identity.exe_source, payload)
            }
            ProcessTransition::Exited(identity) => {
                let payload = EventPayload::ProcessExited {
                    pid: identity.pid,
                    exe: identity.exe.clone(),
                    exe_source: identity.exe_source,
                };
                (identity.pid, identity.exe_source, payload)
            }
        };
        debug!(
            pid,
            exe_source = exe_source.as_str(),
            "process transition observed"
        );
        Captured::new(Source::System, captured_at, payload)
    }
}

fn compare_process_name(snapshot_name: &str) -> String {
    snapshot_name.trim().to_lowercase()
}

fn process_identity_exe(pid: u32, snapshot_name: &str) -> ProcessDetails {
    let inspection = inspect_process(pid);
    let (exe, exe_source) = inspection
        .path
        .filter(|path| !path.trim().is_empty())
        .map(|path| (path, ProcessExeSource::FullPath))
        .unwrap_or_else(|| (snapshot_name.to_string(), ProcessExeSource::SnapshotName));
    ProcessDetails {
        exe,
        exe_source,
        creation_time_100ns: inspection.creation_time_100ns,
    }
}

fn read_process_snapshot_with_retries() -> Result<Option<ProcessSnapshot>, String> {
    for attempt in 0..PROCESS_SNAPSHOT_RETRIES {
        match read_process_snapshot_once() {
            Ok(snapshot) => return Ok(snapshot),
            Err(error) if unsafe { GetLastError() } == ERROR_BAD_LENGTH => {
                if attempt + 1 < PROCESS_SNAPSHOT_RETRIES {
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
                return Err(error);
            }
            Err(error) => return Err(error),
        }
    }
    Err("process snapshot failed".to_string())
}

fn read_process_snapshot_once() -> Result<Option<ProcessSnapshot>, String> {
    let handle = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
        .map_err(|error| format!("CreateToolhelp32Snapshot failed: {error}"))?;
    let _guard = HandleGuard(handle);

    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };

    unsafe { Process32FirstW(handle, &mut entry) }
        .map_err(|error| format!("Process32FirstW failed: {error}"))?;

    let mut entries = Vec::new();
    loop {
        if let Some(snapshot_name) = process_entry_name(&entry) {
            entries.push(ProcessSnapshotEntry {
                pid: entry.th32ProcessID,
                snapshot_name,
            });
        }

        entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
        if unsafe { Process32NextW(handle, &mut entry) }.is_err() {
            break;
        }
    }

    Ok(ProcessSnapshot::from_entries(entries))
}

fn process_entry_name(entry: &PROCESSENTRY32W) -> Option<String> {
    let len = entry
        .szExeFile
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(entry.szExeFile.len());
    if len == 0 {
        None
    } else {
        Some(String::from_utf16_lossy(&entry.szExeFile[..len]))
    }
}

struct CaptureState {
    tx: Sender<Captured>,
    controls: CaptureControls,
    system_capture_enabled: bool,
    password_focus_cache: Option<PasswordFocusCache>,
    foreground: ForegroundState,
    windows: WindowState,
    keyboard: KeyboardState,
    mouse: MouseState,
    system: SystemState,
    idle: IdleState,
    last_timer_tick_ms: Option<u64>,
    power_suspended: bool,
    last_power_resume_at: Option<Instant>,
    /// Debounce key for power-status events: `(ac_online, battery_saver,
    /// 10%-battery bucket)`, so battery-percent jitter does not spam the stream.
    last_power_status: Option<(Option<bool>, Option<bool>, Option<u8>)>,
    active_sensitive_reasons: HashSet<SensitiveContextReason>,
    /// Boundary rows that timed out on the bounded send, waiting for retry
    /// ahead of any later enqueue (RefCell: retried from `send`, which takes
    /// `&self`; the state lives on the pump thread only).
    pending_sensitive_boundaries: RefCell<VecDeque<PendingSensitiveBoundary>>,
    last_reseed_generation: u64,
}

struct PendingSensitiveBoundary {
    captured: Captured,
    _transition_pending: SensitiveTransitionPending,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PasswordFocusCache {
    hwnd: u64,
    is_password: bool,
    focus_generation: u64,
    resolved_at: Instant,
}

struct TimerSample {
    idle_ms: Option<u64>,
    tick_ms: Option<u64>,
    current_foreground: Option<WindowRef>,
    input_desktop: Option<InputDesktopSensitivity>,
    now: Instant,
}

#[derive(Clone, Copy, Debug, Default)]
struct ReseedAfterResetOptions {
    tick_ms: Option<u64>,
    redact_titles: bool,
}

/// Classify a `SYSTEM_POWER_STATUS` into value-free fields. `255` (unknown) maps to
/// `None` for AC line status and battery percent; battery-saver is bit 0 of the
/// system status flag (Windows 8+; `false` on older systems).
fn power_status_fields(status: &SYSTEM_POWER_STATUS) -> (Option<bool>, Option<u8>, Option<bool>) {
    let ac_online = match status.ACLineStatus {
        0 => Some(false),
        1 => Some(true),
        _ => None,
    };
    let battery_percent = if status.BatteryLifePercent <= 100 {
        Some(status.BatteryLifePercent)
    } else {
        None
    };
    let battery_saver = Some(status.SystemStatusFlag & 0x01 != 0);
    (ac_online, battery_percent, battery_saver)
}

fn reseed_windows_with_optional_title_redaction(
    mut current_foreground: Option<WindowRef>,
    mut windows: Vec<WindowRef>,
    redact_titles: bool,
) -> (Option<WindowRef>, Vec<WindowRef>) {
    if redact_titles {
        if let Some(window) = current_foreground.as_mut() {
            window.title = "<redacted>".to_string();
        }
        for window in &mut windows {
            window.title = "<redacted>".to_string();
        }
    }
    (current_foreground, windows)
}

impl CaptureState {
    #[cfg(test)]
    fn new(tx: Sender<Captured>, controls: CaptureControls) -> Self {
        Self::new_with_system_capture(tx, controls, true)
    }

    fn new_with_system_capture(
        tx: Sender<Captured>,
        controls: CaptureControls,
        system_capture_enabled: bool,
    ) -> Self {
        let idle_threshold = controls.idle_threshold();
        let last_reseed_generation = controls.reseed_generation();
        Self {
            tx,
            controls,
            system_capture_enabled,
            password_focus_cache: None,
            foreground: ForegroundState::default(),
            windows: WindowState::default(),
            keyboard: KeyboardState::default(),
            mouse: MouseState::default(),
            system: SystemState::default(),
            idle: IdleState::new(idle_threshold),
            last_timer_tick_ms: Some(current_tick_ms()),
            power_suspended: false,
            last_power_resume_at: None,
            last_power_status: None,
            active_sensitive_reasons: HashSet::new(),
            pending_sensitive_boundaries: RefCell::new(VecDeque::new()),
            last_reseed_generation,
        }
    }

    fn send(&self, captured: Captured, stream: &'static str) {
        if !self.controls.enabled_for(&captured) {
            debug!(
                stream,
                "capture stream disabled; dropping event before enqueue"
            );
            return;
        }

        // Sensitive-context boundaries that timed out earlier must enter the
        // channel before this newer row, or the writer would process the row
        // with stale suppression state.
        self.flush_pending_sensitive_boundaries();

        match self.tx.try_send(captured) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                // Durable accounting: a full channel means capture-produced
                // data never reached the writer, which the writer's own
                // events_skipped cannot see. Count it so the health story
                // stays honest even under sustained backpressure.
                self.controls
                    .diagnostics()
                    .increment_capture_events_dropped();
                warn!(stream, "event channel full; dropping event");
            }
            Err(TrySendError::Disconnected(_)) => {
                warn!(stream, "event receiver closed");
            }
        }
    }

    fn seed_foreground(&mut self, hwnd: HWND) {
        self.seed_foreground_at(hwnd, Instant::now());
    }

    fn seed_foreground_at(&mut self, hwnd: HWND, now: Instant) {
        if let Some(window) = normalize_window(hwnd).and_then(resolve_window) {
            self.seed_foreground_window_at(window, now);
        }
    }

    fn seed_foreground_window_at(&mut self, window: WindowRef, now: Instant) {
        self.note_focused_app(&window);
        if let Some(captured) = self.foreground.seed_window_at(window, now) {
            self.send(captured, "foreground");
        }
    }

    fn on_foreground(&mut self, hwnd: HWND) {
        let now = Instant::now();
        self.protect_unknown_password_focus();
        let Some(window) = normalize_window(hwnd).and_then(resolve_window) else {
            return;
        };

        self.note_focused_app(&window);
        if let Some(captured) = self.foreground.on_window_at(window, now) {
            self.send(captured, "foreground");
        }
    }

    /// Record the focused app for the process-churn filter's foreground
    /// rescue. `resolve_window` can leave `exe` empty when the window's path
    /// query fails (e.g. an elevated/protected window); without a fallback
    /// that app's later process start/exit rows would fail the rescue and be
    /// demoted as background churn (finding 7). Only when the window exe is
    /// empty, pay for a pid-based resolution so the rescue still works.
    fn note_focused_app(&self, window: &WindowRef) {
        if !window.exe.is_empty() {
            self.controls.note_foreground_exe(&window.exe);
            return;
        }
        let details = process_identity_exe(window.pid, "");
        if !details.exe.is_empty() {
            self.controls.note_foreground_exe(&details.exe);
        }
    }

    fn protect_unknown_password_focus(&mut self) {
        if self.controls.enabled(CaptureStream::Keyboard) {
            self.invalidate_password_focus_cache();
            self.controls.set_password_field_gate(true);
            debug!("password-field gate set while focused element is unresolved");
        }
    }

    fn invalidate_password_focus_cache(&mut self) {
        self.password_focus_cache = None;
    }

    fn redact_keyboard_for_password_field_at(
        &mut self,
        window: Option<&WindowRef>,
        now: Instant,
    ) -> bool {
        if self.controls.password_field_confirmed_active() {
            return true;
        }
        let hwnd = window.map(|window| window.hwnd);
        let provisional_gate = self.controls.password_field_active();
        if !provisional_gate {
            if let Some((hwnd, cached)) = hwnd.and_then(|hwnd| {
                self.cached_password_focus(hwnd, now)
                    .map(|cached| (hwnd, cached))
            }) {
                debug!(
                    hwnd = hwnd,
                    is_password = cached,
                    "using cached password-field probe"
                );
                return cached;
            }
        }

        match self
            .controls
            .probe_password_field_active(PASSWORD_FIELD_PROBE_TIMEOUT)
        {
            Some(result) => {
                if let Some(hwnd) = hwnd {
                    self.password_focus_cache = Some(PasswordFocusCache {
                        hwnd,
                        is_password: result.is_password,
                        focus_generation: result.focus_generation,
                        resolved_at: now,
                    });
                }
                emit_confirmed_password_field_sample(
                    &self.tx,
                    &self.controls,
                    &self.controls.diagnostics(),
                    &self.controls.password_field_active_flag(),
                    &self.controls.password_field_confirmed_active_flag(),
                    result.is_password,
                    now,
                );
                result.is_password
            }
            None => {
                self.invalidate_password_focus_cache();
                self.controls.set_password_field_gate(true);
                true
            }
        }
    }

    fn cached_password_focus(&self, hwnd: u64, now: Instant) -> Option<bool> {
        let cached = self.password_focus_cache?;
        if cached.hwnd == hwnd
            && cached.focus_generation == self.controls.password_focus_generation()
            && now.saturating_duration_since(cached.resolved_at) <= PASSWORD_FIELD_PROBE_CACHE_TTL
        {
            Some(cached.is_password)
        } else {
            None
        }
    }

    fn seed_windows(&mut self) {
        let now = Instant::now();
        for window in enum_top_level_windows() {
            self.windows.seed_window_at(window, now);
        }
    }

    fn seed_system(&mut self) {
        let now = Instant::now();
        for captured in self.system.seed_at(now) {
            self.send(captured, "system");
        }
    }

    fn check_requested_reseed(&mut self) {
        let generation = self.controls.reseed_generation();
        if generation == self.last_reseed_generation {
            return;
        }
        self.last_reseed_generation = generation;
        let redact_titles = self.controls.take_title_redaction_for_reseed();
        self.reseed_after_reset(redact_titles);
    }

    fn reseed_after_reset(&mut self, redact_titles: bool) {
        let now = Instant::now();
        self.reseed_after_reset_with_at(
            now,
            current_foreground_window(),
            enum_top_level_windows(),
            current_system_info(),
            current_virtual_screen(),
            ReseedAfterResetOptions {
                tick_ms: Some(current_tick_ms()),
                redact_titles,
            },
        );
        // Re-seed the current power status into the fresh DB (production path;
        // the _with_at variant used by tests stays deterministic without it).
        self.on_power_status_change();
    }

    fn reseed_after_reset_with_at(
        &mut self,
        now: Instant,
        current_foreground: Option<WindowRef>,
        windows: Vec<WindowRef>,
        system_info: EventPayload,
        screen: VirtualScreenSnapshot,
        options: ReseedAfterResetOptions,
    ) {
        let (current_foreground, windows) = reseed_windows_with_optional_title_redaction(
            current_foreground,
            windows,
            options.redact_titles,
        );
        self.foreground = ForegroundState::default();
        self.keyboard = KeyboardState::default();
        self.mouse = MouseState::default();
        self.idle = IdleState::new(self.controls.idle_threshold());
        self.last_timer_tick_ms = options.tick_ms.or(self.last_timer_tick_ms);
        self.power_suspended = false;
        self.last_power_resume_at = None;
        // Clear the power-status debounce so a same-bucket status after the reset
        // is not suppressed against the old DB's last value (the fresh DB has no
        // power_status row yet).
        self.last_power_status = None;

        // A manual panic pause suppresses sensitive-context timestamps along
        // with all other capture. Reconcile the writer's policy state before
        // any post-resume baseline row: exits clear whatever the writer knew
        // before the pause, then enters restore only reasons active now.
        if self.controls.take_sensitive_context_reconcile() {
            let _ = self.reconcile_sensitive_context_after_pause(now);
        }

        if let Some(window) = current_foreground {
            self.seed_foreground_window_at(window, now);
        }
        for captured in self.windows.reseed_with_events_at(windows, now) {
            self.send(captured, "window");
        }
        for captured in self.system.seed_with_at(system_info, screen, now) {
            self.send(captured, "system");
        }
        info!(
            redact_titles = options.redact_titles,
            "capture state reseeded after reset"
        );
    }

    fn on_display_change(&mut self) {
        if let Some(captured) = self.system.on_display_change_at(Instant::now()) {
            self.send(captured, "system");
        }
    }

    fn on_periodic_timer(&mut self) {
        let now = Instant::now();
        let tick_ms = Some(current_tick_ms());
        let missed_boundary_gap_ms = self.missed_power_boundary_gap_ms(tick_ms);
        let needs_current_foreground = self.power_suspended || missed_boundary_gap_ms.is_some();
        let current_foreground = needs_current_foreground
            .then(current_foreground_window)
            .flatten();
        let input_desktop = self
            .should_sample_input_desktop()
            .then(current_input_desktop_sensitivity);
        self.on_timer_sample_at(
            TimerSample {
                idle_ms: current_idle_ms(),
                tick_ms,
                current_foreground,
                input_desktop,
                now,
            },
            physical_key_down,
            physical_mouse_button_down,
        );
    }

    fn on_timer_sample_at<F, G>(
        &mut self,
        sample: TimerSample,
        is_key_down: F,
        is_mouse_button_down: G,
    ) where
        F: Fn(u16) -> bool,
        G: Fn(MouseButton) -> bool,
    {
        // Timer ticks are the retry heartbeat for boundary rows that timed
        // out while the channel was full: once the writer drains, the next
        // tick delivers them even if no new capture event fires.
        self.flush_pending_sensitive_boundaries();
        if let Some(input_desktop) = sample.input_desktop {
            self.on_input_desktop_sample_at(input_desktop, sample.now);
        }
        if self.power_suspended {
            self.on_power_resume_at(sample.now, sample.tick_ms, sample.current_foreground);
        } else if let Some(gap_ms) = self.missed_power_boundary_gap_ms(sample.tick_ms) {
            self.on_missed_power_boundary_at(sample.now, sample.current_foreground, gap_ms);
        }
        self.last_timer_tick_ms = sample.tick_ms.or(self.last_timer_tick_ms);
        self.keyboard.resync_pressed_keys_with(is_key_down);
        self.mouse.resync_active_buttons_with(is_mouse_button_down);

        let Some(idle_ms) = sample.idle_ms else {
            return;
        };
        if let Some(captured) = self.idle.on_sample_at(idle_ms, sample.now) {
            self.send(captured, "system");
        }
    }

    fn on_user_activity(&mut self, now: Instant) {
        let Some(idle_ms) = current_idle_ms() else {
            return;
        };
        if let Some(captured) = self.idle.on_activity_at(idle_ms, now) {
            self.send(captured, "system");
        }
    }

    fn on_window_visible(&mut self, hwnd: HWND) {
        let Some(hwnd) = normalize_window(hwnd) else {
            return;
        };

        if !is_real_top_level_window(hwnd) {
            return;
        }

        let Some(window) = resolve_window(hwnd) else {
            return;
        };

        if let Some(captured) = self.windows.on_opened_at(window, Instant::now()) {
            self.send(captured, "window");
        }
    }

    fn on_window_destroyed(&mut self, hwnd: HWND) {
        let hwnd = normalize_window(hwnd).unwrap_or(hwnd);
        let hwnd = hwnd_to_u64(hwnd);
        self.foreground.on_window_destroyed(hwnd);
        if let Some(captured) = self.windows.on_closed_at(hwnd, Instant::now()) {
            self.send(captured, "window");
        }
    }

    fn on_raw_input(&mut self, lparam: LPARAM) {
        let Some(raw) = raw_input_from_lparam(lparam) else {
            return;
        };

        let now = Instant::now();
        match raw {
            RawInputEvent::Keyboard(raw) => {
                self.on_raw_keyboard_at(raw, current_foreground_window(), now);
            }
            RawInputEvent::Mouse(raw) => {
                self.on_user_activity(now);
                if raw.may_change_focus() {
                    self.protect_unknown_password_focus();
                }
                let window = current_foreground_window();
                let position = current_cursor_position();
                for captured in self.mouse.on_raw_mouse(raw, window, position, now) {
                    self.send(captured, "mouse");
                }
            }
        }
    }

    fn on_raw_keyboard_at(
        &mut self,
        raw: RawKeyboardEvent,
        window: Option<WindowRef>,
        now: Instant,
    ) {
        self.on_user_activity(now);
        let alt_was_down = self.keyboard.mods.alt;
        let redact_key = if raw.is_key_down() {
            self.redact_keyboard_for_password_field_at(window.as_ref(), now)
        } else {
            false
        };
        if let Some(captured) = self
            .keyboard
            .on_raw_key_with_capture_redaction(raw, window, now, redact_key)
        {
            self.send(captured, "keyboard");
        }
        if raw.may_change_focus(alt_was_down) {
            self.invalidate_password_focus_cache();
        }
    }

    fn flush_due_mouse_movement(&mut self, now: Instant) {
        if let Some(captured) = self.mouse.flush_due(now) {
            self.send(captured, "mouse");
        }
    }

    fn flush_pending_mouse_movement(&mut self, now: Instant) {
        if let Some(captured) = self.mouse.flush_pending(now) {
            self.send(captured, "mouse");
        }
    }

    fn end_current_foreground_at(&mut self, now: Instant) {
        if let Some(captured) = self.foreground.end_current_at(now) {
            self.send(captured, "foreground");
        }
    }

    fn end_current_foreground_capped_at(&mut self, now: Instant) {
        if let Some(captured) = self
            .foreground
            .end_current_at_with_max_duration(now, MISSED_POWER_BOUNDARY_MAX_DWELL)
        {
            self.send(captured, "foreground");
        }
    }

    fn emit_power_suspend_at(&mut self, now: Instant, tick_ms: Option<u64>) {
        self.send(
            Captured::new(Source::System, now, EventPayload::PowerSuspend { tick_ms }),
            "system",
        );
    }

    /// Emit a value-free AC/battery power-status event on `PBT_APMPOWERSTATUSCHANGE`,
    /// debounced so only meaningful changes (plug/unplug, battery-saver toggle, or a
    /// ~10% battery step) are recorded rather than every percent tick.
    fn on_power_status_change(&mut self) {
        let mut status = SYSTEM_POWER_STATUS::default();
        if unsafe { GetSystemPowerStatus(&mut status) }.is_err() {
            return;
        }
        self.on_power_status_sample_at(&status, Instant::now());
    }

    fn on_power_status_sample_at(&mut self, status: &SYSTEM_POWER_STATUS, now: Instant) {
        let (ac_online, battery_percent, battery_saver) = power_status_fields(status);
        let key = (ac_online, battery_saver, battery_percent.map(|p| p / 10));
        if self.last_power_status == Some(key) {
            return;
        }
        self.last_power_status = Some(key);
        self.send(
            Captured::new(
                Source::System,
                now,
                EventPayload::PowerStatusChanged {
                    ac_online,
                    battery_percent,
                    battery_saver,
                },
            ),
            "system",
        );
    }

    fn emit_power_resume_at(&mut self, now: Instant, tick_ms: Option<u64>, matched_suspend: bool) {
        self.send(
            Captured::new(
                Source::System,
                now,
                EventPayload::PowerResume {
                    tick_ms,
                    matched_suspend,
                },
            ),
            "system",
        );
    }

    fn emit_power_boundary_recovered_at(&mut self, now: Instant, gap_ms: u64) {
        self.send(
            Captured::new(
                Source::System,
                now,
                EventPayload::PowerBoundaryRecovered {
                    gap_ms,
                    capped_dwell_ms: duration_ms(MISSED_POWER_BOUNDARY_MAX_DWELL),
                },
            ),
            "system",
        );
    }

    fn emit_session_lock_at(&mut self, now: Instant, session_id: u32) {
        self.send(
            Captured::new(
                Source::System,
                now,
                EventPayload::SessionLock { session_id },
            ),
            "system",
        );
    }

    fn emit_session_unlock_at(&mut self, now: Instant, session_id: u32) {
        self.send(
            Captured::new(
                Source::System,
                now,
                EventPayload::SessionUnlock { session_id },
            ),
            "system",
        );
    }

    fn emit_session_connect_at(
        &mut self,
        now: Instant,
        session_id: u32,
        connection: SessionConnectionKind,
    ) {
        self.send(
            Captured::new(
                Source::System,
                now,
                EventPayload::SessionConnect {
                    session_id,
                    connection,
                },
            ),
            "system",
        );
    }

    fn emit_session_disconnect_at(
        &mut self,
        now: Instant,
        session_id: u32,
        connection: SessionConnectionKind,
    ) {
        self.send(
            Captured::new(
                Source::System,
                now,
                EventPayload::SessionDisconnect {
                    session_id,
                    connection,
                },
            ),
            "system",
        );
    }

    fn enter_sensitive_context_at(&mut self, now: Instant, reason: SensitiveContextReason) {
        if self.active_sensitive_reasons.contains(&reason) {
            return;
        }
        let controls = self.controls.clone();
        let transition_pending = controls.begin_sensitive_transition();
        let _resume_guard = controls.sensitive_resume_guard();
        // Fail closed: track the context locally no matter what happens to
        // delivery. WTS lock/disconnect are edge-triggered — fired once,
        // never re-sampled — so gating the local set on a successful send
        // meant a timed-out enter was never retried and the whole span
        // failed open on the writer side (S1).
        self.active_sensitive_reasons.insert(reason);
        self.queue_or_send_sensitive_boundary(
            Captured::new(
                Source::System,
                now,
                EventPayload::SensitiveContextEntered { reason },
            ),
            transition_pending,
        );
    }

    fn exit_sensitive_context_at(&mut self, now: Instant, reason: SensitiveContextReason) {
        if !self.active_sensitive_reasons.contains(&reason) {
            return;
        }
        let controls = self.controls.clone();
        let transition_pending = controls.begin_sensitive_transition();
        let _resume_guard = controls.sensitive_resume_guard();
        self.active_sensitive_reasons.remove(&reason);
        // A queued (not yet delivered) exit keeps the writer suppressing
        // until it lands — the safe direction — and the queue preserves
        // enter/exit ordering.
        self.queue_or_send_sensitive_boundary(
            Captured::new(
                Source::System,
                now,
                EventPayload::SensitiveContextExited { reason },
            ),
            transition_pending,
        );
    }

    /// Deliver a sensitive-context boundary, queueing it on backpressure.
    /// Boundaries already waiting keep strict order (an enter queued behind a
    /// full channel must reach the writer before this exit, and vice versa).
    fn queue_or_send_sensitive_boundary(
        &mut self,
        captured: Captured,
        transition_pending: SensitiveTransitionPending,
    ) {
        if self.controls.sensitive_transition_should_defer() {
            self.controls.request_sensitive_context_reconcile();
            self.pending_sensitive_boundaries.borrow_mut().clear();
            return;
        }
        self.queue_or_send_sensitive_boundary_unchecked(captured, transition_pending);
    }

    fn queue_or_send_sensitive_boundary_unchecked(
        &mut self,
        captured: Captured,
        transition_pending: SensitiveTransitionPending,
    ) {
        self.flush_pending_sensitive_boundaries_unchecked();
        if !self.pending_sensitive_boundaries.borrow().is_empty() {
            self.pending_sensitive_boundaries
                .borrow_mut()
                .push_back(PendingSensitiveBoundary {
                    captured,
                    _transition_pending: transition_pending,
                });
            return;
        }
        match send_sensitive_context_capture(&self.tx, captured, "system") {
            SensitiveBoundarySend::Delivered | SensitiveBoundarySend::Disconnected => {}
            SensitiveBoundarySend::TimedOut(undelivered) => {
                self.pending_sensitive_boundaries.borrow_mut().push_back(
                    PendingSensitiveBoundary {
                        captured: undelivered,
                        _transition_pending: transition_pending,
                    },
                );
            }
        }
    }

    /// Retry queued boundary rows ahead of any newer capture. Called before
    /// every enqueue (and on timer ticks): channel FIFO then guarantees the
    /// writer flips suppression before it processes any row captured after
    /// the boundary, so a deferred boundary narrows redaction by at most the
    /// rows that were already in flight *before* the context changed.
    fn flush_pending_sensitive_boundaries(&self) {
        if self.controls.sensitive_transition_should_defer() {
            if !self.pending_sensitive_boundaries.borrow().is_empty() {
                self.controls.request_sensitive_context_reconcile();
            }
            self.pending_sensitive_boundaries.borrow_mut().clear();
            return;
        }
        self.flush_pending_sensitive_boundaries_unchecked();
    }

    fn flush_pending_sensitive_boundaries_unchecked(&self) {
        let mut pending = self.pending_sensitive_boundaries.borrow_mut();
        while let Some(boundary) = pending.pop_front() {
            let PendingSensitiveBoundary {
                captured,
                _transition_pending: transition_pending,
            } = boundary;
            match self.tx.try_send(captured) {
                Ok(()) => {}
                Err(TrySendError::Full(captured)) => {
                    pending.push_front(PendingSensitiveBoundary {
                        captured,
                        _transition_pending: transition_pending,
                    });
                    return;
                }
                Err(TrySendError::Disconnected(_)) => {
                    pending.clear();
                    return;
                }
            }
        }
    }

    fn reconcile_sensitive_context_after_pause(&mut self, now: Instant) -> bool {
        const REASONS: [SensitiveContextReason; 4] = [
            SensitiveContextReason::SessionLocked,
            SensitiveContextReason::SessionDisconnected,
            SensitiveContextReason::SecureDesktop,
            SensitiveContextReason::PasswordField,
        ];
        let mut active = self.active_sensitive_reasons.clone();
        if self.controls.password_field_confirmed_active() {
            active.insert(SensitiveContextReason::PasswordField);
        }
        self.pending_sensitive_boundaries.borrow_mut().clear();
        for reason in REASONS {
            if self
                .tx
                .send(Captured::new(
                    Source::System,
                    now,
                    EventPayload::SensitiveContextExited { reason },
                ))
                .is_err()
            {
                return false;
            }
        }
        for reason in REASONS {
            if active.contains(&reason)
                && self
                    .tx
                    .send(Captured::new(
                        Source::System,
                        now,
                        EventPayload::SensitiveContextEntered { reason },
                    ))
                    .is_err()
            {
                return false;
            }
        }
        true
    }

    fn reconcile_sensitive_context_for_resume(&mut self) -> Option<u64> {
        let controls = self.controls.clone();
        let _resume_guard = controls.sensitive_resume_guard();
        if controls.sensitive_transition_active() {
            return None;
        }
        let generation = controls.sensitive_transition_generation();
        controls.take_sensitive_context_reconcile();
        if !self.reconcile_sensitive_context_after_pause(Instant::now())
            || controls.sensitive_transition_active()
            || controls.sensitive_transition_generation() != generation
        {
            return None;
        }
        Some(generation)
    }

    fn on_input_desktop_sample_at(&mut self, input_desktop: InputDesktopSensitivity, now: Instant) {
        match input_desktop {
            InputDesktopSensitivity::Normal => {
                self.exit_sensitive_context_at(now, SensitiveContextReason::SecureDesktop);
            }
            InputDesktopSensitivity::Protected => {
                self.enter_sensitive_context_at(now, SensitiveContextReason::SecureDesktop);
            }
        }
    }

    fn should_sample_input_desktop(&self) -> bool {
        self.system_capture_enabled
    }

    fn on_clipboard_update(&mut self) {
        let now = Instant::now();
        self.on_clipboard_update_at(inspect_clipboard_metadata(), now);
    }

    fn on_clipboard_update_at(&mut self, metadata: ClipboardMetadata, now: Instant) {
        if let Some(captured) = self.system.on_clipboard_update_at(metadata, now) {
            self.send(captured, "system");
        }
    }

    fn on_power_suspend(&mut self) {
        let now = Instant::now();
        self.on_power_suspend_at(now, Some(current_tick_ms()));
    }

    fn on_power_suspend_at(&mut self, now: Instant, tick_ms: Option<u64>) {
        self.flush_pending_mouse_movement(now);
        self.mouse.reset_after_boundary();
        self.end_current_foreground_at(now);
        self.emit_power_suspend_at(now, tick_ms);
        self.keyboard.reset_after_boundary();
        self.power_suspended = true;
        self.last_power_resume_at = None;
        self.last_timer_tick_ms = tick_ms.or(self.last_timer_tick_ms);
        info!(tick_ms, "power suspend boundary");
    }

    fn on_power_resume(&mut self) {
        let now = Instant::now();
        if self.on_power_resume_at(now, Some(current_tick_ms()), current_foreground_window()) {
            self.on_power_status_change();
        }
    }

    #[cfg(test)]
    fn on_power_resume_with_status_sample_at(
        &mut self,
        now: Instant,
        tick_ms: Option<u64>,
        current_foreground: Option<WindowRef>,
        status: &SYSTEM_POWER_STATUS,
    ) {
        if self.on_power_resume_at(now, tick_ms, current_foreground) {
            self.on_power_status_sample_at(status, now);
        }
    }

    fn on_power_resume_at(
        &mut self,
        now: Instant,
        tick_ms: Option<u64>,
        current_foreground: Option<WindowRef>,
    ) -> bool {
        if self.is_duplicate_power_resume(now) {
            self.last_power_resume_at = Some(now);
            self.last_timer_tick_ms = tick_ms.or(self.last_timer_tick_ms);
            info!(tick_ms, "duplicate power resume boundary ignored");
            return false;
        }

        self.flush_pending_mouse_movement(now);
        let matched_suspend = self.power_suspended;
        let recovered_gap_ms = (!matched_suspend)
            .then(|| self.missed_power_boundary_gap_ms(tick_ms))
            .flatten();
        if let Some(gap_ms) = recovered_gap_ms {
            self.on_missed_power_boundary_at(now, current_foreground.clone(), gap_ms);
        } else {
            if !matched_suspend {
                self.end_current_foreground_capped_at(now);
            }
            self.mouse.reset_after_boundary();
            self.keyboard.reset_after_boundary();
            if let Some(window) = current_foreground {
                self.seed_foreground_window_at(window, now);
            }
        }
        self.emit_power_resume_at(now, tick_ms, matched_suspend);
        self.power_suspended = false;
        self.last_power_resume_at = Some(now);
        self.last_timer_tick_ms = tick_ms.or(self.last_timer_tick_ms);
        info!(tick_ms, matched_suspend, "power resume boundary");
        true
    }

    fn is_duplicate_power_resume(&self, now: Instant) -> bool {
        !self.power_suspended
            && self.last_power_resume_at.is_some_and(|previous| {
                now.saturating_duration_since(previous) <= POWER_RESUME_DEBOUNCE
            })
    }

    fn missed_power_boundary_gap_ms(&self, tick_ms: Option<u64>) -> Option<u64> {
        if self.power_suspended {
            return None;
        }

        match (self.last_timer_tick_ms, tick_ms) {
            (Some(previous), Some(current)) => {
                let gap_ms = current.saturating_sub(previous);
                (gap_ms > MISSED_POWER_BOUNDARY_THRESHOLD_MS).then_some(gap_ms)
            }
            _ => None,
        }
    }

    fn on_missed_power_boundary_at(
        &mut self,
        now: Instant,
        current_foreground: Option<WindowRef>,
        gap_ms: u64,
    ) {
        self.flush_pending_mouse_movement(now);
        self.mouse.reset_after_boundary();
        self.end_current_foreground_capped_at(now);
        self.keyboard.reset_after_boundary();
        if let Some(window) = current_foreground {
            self.seed_foreground_window_at(window, now);
        }
        self.on_power_status_change();
        self.emit_power_boundary_recovered_at(now, gap_ms);
        self.power_suspended = false;
        self.last_power_resume_at = Some(now);
        self.controls
            .diagnostics()
            .increment_power_boundary_catches();
        info!(
            gap_ms,
            capped_dwell_ms = duration_ms(MISSED_POWER_BOUNDARY_MAX_DWELL),
            "missed power boundary caught"
        );
    }

    fn on_session_change(&mut self, event: u32, session_id: u32) {
        let now = Instant::now();
        let current_foreground = matches!(
            event,
            WTS_CONSOLE_CONNECT | WTS_REMOTE_CONNECT | WTS_SESSION_UNLOCK
        )
        .then(current_foreground_window)
        .flatten();
        self.on_session_change_at(event, session_id, now, current_foreground);
    }

    fn on_session_change_at(
        &mut self,
        event: u32,
        session_id: u32,
        now: Instant,
        current_foreground: Option<WindowRef>,
    ) {
        match event {
            WTS_SESSION_LOCK => {
                self.flush_pending_mouse_movement(now);
                self.mouse.reset_after_boundary();
                self.end_current_foreground_at(now);
                self.keyboard.reset_after_boundary();
                self.emit_session_lock_at(now, session_id);
                self.enter_sensitive_context_at(now, SensitiveContextReason::SessionLocked);
                info!(windows_session_id = session_id, "windows session locked");
            }
            WTS_SESSION_UNLOCK => {
                self.exit_sensitive_context_at(now, SensitiveContextReason::SessionLocked);
                self.mouse.reset_after_boundary();
                self.keyboard.reset_after_boundary();
                if let Some(window) = current_foreground {
                    self.seed_foreground_window_at(window, now);
                }
                self.emit_session_unlock_at(now, session_id);
                info!(windows_session_id = session_id, "windows session unlocked");
            }
            WTS_CONSOLE_CONNECT => {
                self.exit_sensitive_context_at(now, SensitiveContextReason::SessionDisconnected);
                self.mouse.reset_after_boundary();
                self.keyboard.reset_after_boundary();
                if let Some(window) = current_foreground {
                    self.seed_foreground_window_at(window, now);
                }
                self.emit_session_connect_at(now, session_id, SessionConnectionKind::Console);
                info!(
                    windows_session_id = session_id,
                    connection = "console",
                    "windows session connected"
                );
            }
            WTS_REMOTE_CONNECT => {
                self.exit_sensitive_context_at(now, SensitiveContextReason::SessionDisconnected);
                self.mouse.reset_after_boundary();
                self.keyboard.reset_after_boundary();
                if let Some(window) = current_foreground {
                    self.seed_foreground_window_at(window, now);
                }
                self.emit_session_connect_at(now, session_id, SessionConnectionKind::Remote);
                info!(
                    windows_session_id = session_id,
                    connection = "remote",
                    "windows session connected"
                );
            }
            WTS_CONSOLE_DISCONNECT => {
                self.flush_pending_mouse_movement(now);
                self.mouse.reset_after_boundary();
                self.end_current_foreground_at(now);
                self.keyboard.reset_after_boundary();
                self.emit_session_disconnect_at(now, session_id, SessionConnectionKind::Console);
                self.enter_sensitive_context_at(now, SensitiveContextReason::SessionDisconnected);
                info!(
                    windows_session_id = session_id,
                    connection = "console",
                    "windows session disconnected"
                );
            }
            WTS_REMOTE_DISCONNECT => {
                self.flush_pending_mouse_movement(now);
                self.mouse.reset_after_boundary();
                self.end_current_foreground_at(now);
                self.keyboard.reset_after_boundary();
                self.emit_session_disconnect_at(now, session_id, SessionConnectionKind::Remote);
                self.enter_sensitive_context_at(now, SensitiveContextReason::SessionDisconnected);
                info!(
                    windows_session_id = session_id,
                    connection = "remote",
                    "windows session disconnected"
                );
            }
            _ => {
                debug!(
                    windows_session_id = session_id,
                    event, "ignored windows session-change notification"
                );
            }
        }
    }

    fn flush_shutdown_events(&mut self, now: Instant) {
        self.flush_pending_mouse_movement(now);
        self.end_current_foreground_at(now);
        for captured in self.windows.close_all_at(now) {
            self.send(captured, "window");
        }
    }
}

// ForegroundState (and its FocusedWindow/focus_changed helpers) hoisted to
// gilbreth-core 2026-07-12 — the recorded MAC-1 core-hoist trigger; bodies
// moved unchanged, unit tests moved with them.

#[derive(Default)]
struct WindowState {
    windows: HashMap<u64, OpenWindow>,
}

impl WindowState {
    fn seed_window_at(&mut self, window: WindowRef, opened_at: Instant) {
        self.windows.entry(window.hwnd).or_insert(OpenWindow {
            window,
            opened_at,
            origin: WindowLifecycleOrigin::Seeded,
        });
    }

    fn reseed_with_events_at(
        &mut self,
        windows: Vec<WindowRef>,
        opened_at: Instant,
    ) -> Vec<Captured> {
        self.windows.clear();
        windows
            .into_iter()
            .map(|window| {
                self.windows.insert(
                    window.hwnd,
                    OpenWindow {
                        window: window.clone(),
                        opened_at,
                        origin: WindowLifecycleOrigin::Seeded,
                    },
                );
                Captured::new(
                    Source::Window,
                    opened_at,
                    EventPayload::WindowOpened {
                        window,
                        origin: WindowLifecycleOrigin::Seeded,
                    },
                )
            })
            .collect()
    }

    fn on_opened_at(&mut self, window: WindowRef, opened_at: Instant) -> Option<Captured> {
        if self.windows.contains_key(&window.hwnd) {
            return None;
        }

        self.windows.insert(
            window.hwnd,
            OpenWindow {
                window: window.clone(),
                opened_at,
                origin: WindowLifecycleOrigin::Observed,
            },
        );

        Some(Captured::new(
            Source::Window,
            opened_at,
            EventPayload::WindowOpened {
                window,
                origin: WindowLifecycleOrigin::Observed,
            },
        ))
    }

    fn on_closed_at(&mut self, hwnd: u64, closed_at: Instant) -> Option<Captured> {
        let open = self.windows.remove(&hwnd)?;
        let open_for_ms = duration_ms(closed_at.saturating_duration_since(open.opened_at));

        Some(Captured::new(
            Source::Window,
            closed_at,
            EventPayload::WindowClosed {
                window: open.window,
                open_for_ms,
                origin: open.origin,
            },
        ))
    }

    fn close_all_at(&mut self, closed_at: Instant) -> Vec<Captured> {
        let windows = std::mem::take(&mut self.windows);
        windows
            .into_values()
            .map(|open| {
                let open_for_ms = duration_ms(closed_at.saturating_duration_since(open.opened_at));
                Captured::new(
                    Source::Window,
                    closed_at,
                    EventPayload::WindowClosed {
                        window: open.window,
                        open_for_ms,
                        origin: WindowLifecycleOrigin::Synthesized,
                    },
                )
            })
            .collect()
    }
}

struct OpenWindow {
    window: WindowRef,
    opened_at: Instant,
    origin: WindowLifecycleOrigin,
}

#[derive(Default)]
struct SystemState {
    last_virtual_screen: Option<VirtualScreenSnapshot>,
    last_clipboard_sequence: Option<u32>,
}

impl SystemState {
    fn seed_at(&mut self, captured_at: Instant) -> Vec<Captured> {
        self.seed_with_at(current_system_info(), current_virtual_screen(), captured_at)
    }

    fn seed_with_at(
        &mut self,
        system_info: EventPayload,
        screen: VirtualScreenSnapshot,
        captured_at: Instant,
    ) -> Vec<Captured> {
        let mut events = Vec::new();
        events.push(Captured::new(Source::System, captured_at, system_info));

        self.last_virtual_screen = Some(screen);
        events.push(Self::virtual_screen_event(screen, captured_at));
        events
    }

    fn on_display_change_at(&mut self, captured_at: Instant) -> Option<Captured> {
        self.on_virtual_screen_at(current_virtual_screen(), captured_at)
    }

    fn on_virtual_screen_at(
        &mut self,
        screen: VirtualScreenSnapshot,
        captured_at: Instant,
    ) -> Option<Captured> {
        if self.last_virtual_screen == Some(screen) {
            return None;
        }

        self.last_virtual_screen = Some(screen);
        Some(Self::virtual_screen_event(screen, captured_at))
    }

    fn virtual_screen_event(screen: VirtualScreenSnapshot, captured_at: Instant) -> Captured {
        Captured::new(
            Source::System,
            captured_at,
            EventPayload::VirtualScreen {
                x0: screen.x0,
                y0: screen.y0,
                x1: screen.x1(),
                y1: screen.y1(),
                width: screen.width,
                height: screen.height,
            },
        )
    }

    fn on_clipboard_update_at(
        &mut self,
        metadata: ClipboardMetadata,
        captured_at: Instant,
    ) -> Option<Captured> {
        if self.last_clipboard_sequence == Some(metadata.sequence_number) {
            return None;
        }

        self.last_clipboard_sequence = Some(metadata.sequence_number);
        Some(Self::clipboard_event(metadata, captured_at))
    }

    fn clipboard_event(metadata: ClipboardMetadata, captured_at: Instant) -> Captured {
        Captured::new(
            Source::System,
            captured_at,
            EventPayload::ClipboardUsed {
                sequence_number: metadata.sequence_number,
                format_kind: metadata.format_kind,
                format_count: metadata.format_count,
                text_char_count: metadata.text_char_count,
                byte_size: metadata.byte_size,
            },
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct VirtualScreenSnapshot {
    x0: i32,
    y0: i32,
    width: i32,
    height: i32,
}

impl VirtualScreenSnapshot {
    fn x1(self) -> i32 {
        self.x0.saturating_add(self.width)
    }

    fn y1(self) -> i32 {
        self.y0.saturating_add(self.height)
    }

    fn center(self) -> MousePosition {
        MousePosition {
            x: self.x0.saturating_add(self.width / 2),
            y: self.y0.saturating_add(self.height / 2),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ClipboardMetadata {
    sequence_number: u32,
    format_kind: ClipboardFormatKind,
    format_count: u32,
    text_char_count: Option<u64>,
    byte_size: Option<u64>,
}

impl ClipboardMetadata {
    fn unavailable(sequence_number: u32) -> Self {
        Self {
            sequence_number,
            format_kind: ClipboardFormatKind::Unavailable,
            format_count: 0,
            text_char_count: None,
            byte_size: None,
        }
    }

    fn from_formats(sequence_number: u32, formats: &[u32]) -> Self {
        let format_kind = classify_clipboard_formats(formats);
        let primary_format = primary_clipboard_format(format_kind, formats);
        let text_char_count = text_clipboard_format(formats).and_then(clipboard_text_char_count);
        let byte_size = primary_format.and_then(clipboard_global_size);

        Self {
            sequence_number,
            format_kind,
            format_count: u32::try_from(formats.len()).unwrap_or(u32::MAX),
            text_char_count,
            byte_size,
        }
    }
}

struct ClipboardOpenGuard;

impl ClipboardOpenGuard {
    fn open() -> windows::core::Result<Self> {
        unsafe { OpenClipboard(None) }?;
        Ok(Self)
    }
}

impl Drop for ClipboardOpenGuard {
    fn drop(&mut self) {
        if let Err(error) = unsafe { CloseClipboard() } {
            warn!(%error, "failed to close clipboard");
        }
    }
}

fn inspect_clipboard_metadata() -> ClipboardMetadata {
    let sequence_number = unsafe { GetClipboardSequenceNumber() };
    let Ok(_guard) = ClipboardOpenGuard::open() else {
        debug!("clipboard changed but metadata was unavailable; clipboard is locked");
        return ClipboardMetadata::unavailable(sequence_number);
    };

    ClipboardMetadata::from_formats(sequence_number, &enumerate_clipboard_formats())
}

fn enumerate_clipboard_formats() -> Vec<u32> {
    let mut formats = Vec::new();
    let mut current = 0;
    loop {
        let next = unsafe { EnumClipboardFormats(current) };
        if next == 0 {
            break;
        }
        formats.push(next);
        current = next;
        if formats.len() >= 256 {
            warn!("clipboard exposes more than 256 formats; metadata truncated");
            break;
        }
    }
    formats
}

fn classify_clipboard_formats(formats: &[u32]) -> ClipboardFormatKind {
    if formats.is_empty() {
        return ClipboardFormatKind::Empty;
    }
    if text_clipboard_format(formats).is_some() {
        return ClipboardFormatKind::Text;
    }
    if formats.contains(&CF_HDROP) {
        return ClipboardFormatKind::Files;
    }
    if formats.iter().any(|format| {
        matches!(
            *format,
            CF_BITMAP | CF_DIB | CF_DIBV5 | CF_TIFF | CF_ENHMETAFILE | CF_METAFILEPICT
        )
    }) {
        return ClipboardFormatKind::Image;
    }
    if formats
        .iter()
        .any(|format| matches!(*format, CF_WAVE | CF_RIFF))
    {
        return ClipboardFormatKind::Audio;
    }
    ClipboardFormatKind::Custom
}

fn primary_clipboard_format(kind: ClipboardFormatKind, formats: &[u32]) -> Option<u32> {
    match kind {
        ClipboardFormatKind::Text => text_clipboard_format(formats),
        ClipboardFormatKind::Files => formats.contains(&CF_HDROP).then_some(CF_HDROP),
        ClipboardFormatKind::Image => [
            CF_DIBV5,
            CF_DIB,
            CF_TIFF,
            CF_ENHMETAFILE,
            CF_BITMAP,
            CF_METAFILEPICT,
        ]
        .into_iter()
        .find(|format| formats.contains(format)),
        ClipboardFormatKind::Audio => [CF_WAVE, CF_RIFF]
            .into_iter()
            .find(|format| formats.contains(format)),
        // Concealed is macOS-only (the pasteboard concealed marker); the
        // Windows classifier never produces it, so no primary format exists.
        ClipboardFormatKind::Custom
        | ClipboardFormatKind::Empty
        | ClipboardFormatKind::Unavailable
        | ClipboardFormatKind::Concealed => None,
    }
}

fn text_clipboard_format(formats: &[u32]) -> Option<u32> {
    [CF_UNICODETEXT, CF_TEXT, CF_OEMTEXT]
        .into_iter()
        .find(|format| formats.contains(format))
}

fn clipboard_text_char_count(format: u32) -> Option<u64> {
    let byte_size = clipboard_global_size(format)?;
    match format {
        CF_UNICODETEXT => Some((byte_size / 2).saturating_sub(1)),
        CF_TEXT | CF_OEMTEXT => Some(byte_size.saturating_sub(1)),
        _ => None,
    }
}

fn clipboard_global_size(format: u32) -> Option<u64> {
    if !clipboard_format_is_global_memory(format) {
        return None;
    }
    let handle = unsafe { GetClipboardData(format).ok()? };
    let size = unsafe { GlobalSize(HGLOBAL(handle.0)) };
    (size > 0).then(|| u64::try_from(size).unwrap_or(u64::MAX))
}

fn clipboard_format_is_global_memory(format: u32) -> bool {
    matches!(
        format,
        CF_TEXT
            | CF_SYLK
            | CF_DIF
            | CF_TIFF
            | CF_OEMTEXT
            | CF_DIB
            | CF_PENDATA
            | CF_RIFF
            | CF_WAVE
            | CF_UNICODETEXT
            | CF_HDROP
            | CF_LOCALE
            | CF_DIBV5
    )
}

struct IdleState {
    threshold: Duration,
    is_idle: bool,
}

impl Default for IdleState {
    fn default() -> Self {
        Self::new(Duration::from_millis(DEFAULT_IDLE_THRESHOLD_MS))
    }
}

impl IdleState {
    fn new(threshold: Duration) -> Self {
        Self {
            threshold,
            is_idle: false,
        }
    }

    fn on_sample_at(&mut self, idle_ms: u64, captured_at: Instant) -> Option<Captured> {
        if !self.is_idle && idle_ms >= duration_ms(self.threshold) {
            self.is_idle = true;
            return Some(Self::idle_event(idle_ms, captured_at));
        }

        if self.is_idle && idle_ms < duration_ms(self.threshold) {
            self.is_idle = false;
            return Some(Self::active_event(idle_ms, captured_at));
        }

        None
    }

    fn on_activity_at(&mut self, idle_ms: u64, captured_at: Instant) -> Option<Captured> {
        if !self.is_idle {
            return None;
        }

        self.is_idle = false;
        Some(Self::active_event(idle_ms, captured_at))
    }

    fn idle_event(idle_ms: u64, captured_at: Instant) -> Captured {
        Captured::new(Source::System, captured_at, EventPayload::Idle { idle_ms })
    }

    fn active_event(idle_ms: u64, captured_at: Instant) -> Captured {
        Captured::new(
            Source::System,
            captured_at,
            EventPayload::Active { idle_ms },
        )
    }
}

#[derive(Default)]
struct KeyboardState {
    mods: Modifiers,
    pressed_keys: HashSet<u16>,
}

impl KeyboardState {
    #[cfg(test)]
    fn on_raw_key(
        &mut self,
        raw: RawKeyboardEvent,
        window: Option<WindowRef>,
        captured_at: Instant,
    ) -> Option<Captured> {
        self.on_raw_key_with_capture_redaction(raw, window, captured_at, false)
    }

    fn on_raw_key_with_capture_redaction(
        &mut self,
        raw: RawKeyboardEvent,
        mut window: Option<WindowRef>,
        captured_at: Instant,
        redact_key: bool,
    ) -> Option<Captured> {
        let is_release = raw.flags & RI_KEY_BREAK != 0;
        if let Some(modifier) = ModifierKey::from_vkey(raw.vkey) {
            self.set_modifier(modifier, !is_release);
        }

        if is_release {
            self.pressed_keys.remove(&raw.vkey);
            return None;
        }

        if !self.pressed_keys.insert(raw.vkey) {
            return None;
        }

        if redact_key {
            if let Some(window) = window.as_mut() {
                window.title = "<redacted>".to_string();
            }
        }

        Some(Captured::new(
            Source::Keyboard,
            captured_at,
            EventPayload::Key {
                key: if redact_key {
                    "<redacted>".to_string()
                } else {
                    key_to_string(raw.vkey)
                },
                mods: if redact_key {
                    Modifiers::default()
                } else {
                    self.mods.clone()
                },
                window,
                key_class: None,
            },
        ))
    }

    fn set_modifier(&mut self, modifier: ModifierKey, pressed: bool) {
        match modifier {
            ModifierKey::Shift => self.mods.shift = pressed,
            ModifierKey::Ctrl => self.mods.ctrl = pressed,
            ModifierKey::Alt => self.mods.alt = pressed,
            ModifierKey::Win => self.mods.win = pressed,
        }
    }

    fn reset_after_boundary(&mut self) {
        self.pressed_keys.clear();
        self.mods = Modifiers::default();
    }

    fn resync_pressed_keys_with<F>(&mut self, is_key_down: F)
    where
        F: Fn(u16) -> bool,
    {
        self.pressed_keys.retain(|vkey| is_key_down(*vkey));
        self.mods.shift = [0x10, 0xa0, 0xa1].into_iter().any(&is_key_down);
        self.mods.ctrl = [0x11, 0xa2, 0xa3].into_iter().any(&is_key_down);
        self.mods.alt = [0x12, 0xa4, 0xa5].into_iter().any(&is_key_down);
        self.mods.win = [0x5b, 0x5c].into_iter().any(is_key_down);
    }
}

#[derive(Clone, Copy)]
struct RawKeyboardEvent {
    vkey: u16,
    flags: u16,
}

impl RawKeyboardEvent {
    fn is_key_down(self) -> bool {
        self.flags & RI_KEY_BREAK == 0
    }

    fn may_change_focus(self, alt_was_down: bool) -> bool {
        self.is_key_down()
            && (alt_was_down
                || matches!(
                    self.vkey,
                    0x09 // Tab
                        | 0x0d // Enter
                        | 0x12 // Alt
                        | 0x1b // Esc
                        | 0x20 // Space
                        | 0x21
                        ..=0x28 // Page/Home/End/Arrow navigation
                        | 0x75 // F6 pane/address focus traversal
                        | 0xa4
                        | 0xa5 // Left/Right Alt
                ))
    }
}

struct MouseState {
    pending_move: Option<PendingMouseMove>,
    active_buttons: HashMap<MouseButton, ActiveMouseButton>,
    last_completed_click: Option<CompletedMouseClick>,
    last_cursor_position: Option<MousePosition>,
    move_flush_interval: Duration,
    double_click_interval: Duration,
    double_click_box: MouseBox,
    drag_box: MouseBox,
    pinned_center_raw_delta_count: u8,
    remote_relay_suspected: bool,
}

impl Default for MouseState {
    fn default() -> Self {
        Self {
            pending_move: None,
            active_buttons: HashMap::new(),
            last_completed_click: None,
            last_cursor_position: None,
            move_flush_interval: MOUSE_MOVE_FLUSH_INTERVAL,
            double_click_interval: system_double_click_interval(),
            double_click_box: system_double_click_box(),
            drag_box: system_drag_box(),
            pinned_center_raw_delta_count: 0,
            remote_relay_suspected: false,
        }
    }
}

impl MouseState {
    fn on_raw_mouse(
        &mut self,
        raw: RawMouseEvent,
        window: Option<WindowRef>,
        position: Option<MousePosition>,
        captured_at: Instant,
    ) -> Vec<Captured> {
        let mut events = Vec::new();
        let x = position.map(|position| position.x);
        let y = position.map(|position| position.y);
        let input_origin = self.update_input_origin(raw, position, current_virtual_screen());
        let down_buttons = raw.down_buttons().collect::<Vec<_>>();
        let up_buttons = raw.up_buttons().collect::<Vec<_>>();
        let has_vertical_wheel = raw.button_flags & RI_MOUSE_WHEEL as u16 != 0;
        let has_horizontal_wheel = raw.button_flags & RI_MOUSE_HWHEEL as u16 != 0;
        let has_discrete_input = !down_buttons.is_empty()
            || !up_buttons.is_empty()
            || has_vertical_wheel
            || has_horizontal_wheel;

        let movement = if raw.has_movement() {
            self.movement_delta(raw, position)
        } else {
            None
        };

        if let Some(position) = position {
            self.last_cursor_position = Some(position);
        }

        if let Some(movement) = movement {
            self.record_movement(
                movement,
                window.clone(),
                position,
                captured_at,
                input_origin,
            );
            self.record_active_button_movement(movement, window.clone(), position, input_origin);
        }
        if has_discrete_input {
            if let Some(captured) = self.flush_pending(captured_at) {
                events.push(captured);
            }
        } else if let Some(captured) = self.flush_due(captured_at) {
            events.push(captured);
        }

        for button in down_buttons {
            let double_click_interval_ms =
                self.double_click_interval_ms(button, position, window.as_ref(), captured_at);
            self.active_buttons.insert(
                button,
                ActiveMouseButton::new(
                    button,
                    position,
                    window.clone(),
                    captured_at,
                    input_origin,
                    double_click_interval_ms.is_none(),
                ),
            );
            events.push(Captured::new(
                Source::Mouse,
                captured_at,
                EventPayload::MouseClick {
                    button,
                    x,
                    y,
                    window: window.clone(),
                    input_origin,
                },
            ));
            if let Some(interval_ms) = double_click_interval_ms {
                events.push(Captured::new(
                    Source::Mouse,
                    captured_at,
                    EventPayload::MouseDoubleClick {
                        button,
                        interval_ms,
                        x,
                        y,
                        window: window.clone(),
                        input_origin,
                    },
                ));
                self.last_completed_click = None;
            }
        }

        if has_vertical_wheel {
            events.push(Captured::new(
                Source::Mouse,
                captured_at,
                EventPayload::MouseWheel {
                    axis: MouseWheelAxis::Vertical,
                    delta: raw.wheel_delta(),
                    x,
                    y,
                    window: window.clone(),
                    input_origin,
                },
            ));
        }

        if has_horizontal_wheel {
            events.push(Captured::new(
                Source::Mouse,
                captured_at,
                EventPayload::MouseWheel {
                    axis: MouseWheelAxis::Horizontal,
                    delta: raw.wheel_delta(),
                    x,
                    y,
                    window: window.clone(),
                    input_origin,
                },
            ));
        }

        for button in up_buttons {
            let Some(mut active) = self.active_buttons.remove(&button) else {
                continue;
            };
            active.finish(window.clone(), position, input_origin);
            if active.is_drag(&self.drag_box) {
                self.last_completed_click = None;
                events.push(active.into_drag(captured_at));
            } else if active.seed_completed_click {
                self.last_completed_click = Some(active.into_completed_click());
            } else {
                self.last_completed_click = None;
            }
        }

        events
    }

    fn record_movement(
        &mut self,
        movement: MouseMovement,
        window: Option<WindowRef>,
        position: Option<MousePosition>,
        captured_at: Instant,
        input_origin: Option<InputOrigin>,
    ) {
        if let Some(pending) = self.pending_move.as_mut() {
            pending.add(movement, window, position, captured_at, input_origin);
        } else {
            self.pending_move = Some(PendingMouseMove::new(
                movement,
                window,
                position,
                captured_at,
                input_origin,
            ));
        }
    }

    fn record_active_button_movement(
        &mut self,
        movement: MouseMovement,
        window: Option<WindowRef>,
        position: Option<MousePosition>,
        input_origin: Option<InputOrigin>,
    ) {
        for active in self.active_buttons.values_mut() {
            active.add_movement(movement, window.clone(), position, input_origin);
        }
    }

    fn double_click_interval_ms(
        &self,
        button: MouseButton,
        position: Option<MousePosition>,
        window: Option<&WindowRef>,
        captured_at: Instant,
    ) -> Option<u64> {
        let previous = self.last_completed_click.as_ref()?;
        if previous.button != button {
            return None;
        }
        let elapsed = captured_at.checked_duration_since(previous.started_at)?;
        if elapsed > self.double_click_interval {
            return None;
        }
        let previous_hwnd = previous.hwnd?;
        let window = window?;
        if previous_hwnd != window.hwnd {
            return None;
        }
        let position = position?;
        let (Some(previous_x), Some(previous_y)) = (previous.x, previous.y) else {
            return None;
        };
        if !self
            .double_click_box
            .contains(previous_x, previous_y, position.x, position.y)
        {
            return None;
        }
        Some(duration_ms(elapsed))
    }

    fn update_input_origin(
        &mut self,
        raw: RawMouseEvent,
        position: Option<MousePosition>,
        screen: VirtualScreenSnapshot,
    ) -> Option<InputOrigin> {
        if remote_relay_signature(raw, position, self.last_cursor_position, screen) {
            self.pinned_center_raw_delta_count = self
                .pinned_center_raw_delta_count
                .saturating_add(1)
                .min(REMOTE_RELAY_PINNED_CENTER_SAMPLES);
            if self.pinned_center_raw_delta_count >= REMOTE_RELAY_PINNED_CENTER_SAMPLES {
                self.remote_relay_suspected = true;
            }
        } else if raw.has_movement()
            || position.is_some_and(|position| !is_virtual_screen_center(position, screen))
        {
            self.pinned_center_raw_delta_count = 0;
            self.remote_relay_suspected = false;
        }

        self.remote_relay_suspected
            .then_some(InputOrigin::RemoteRelaySuspected)
    }

    fn movement_delta(
        &self,
        raw: RawMouseEvent,
        position: Option<MousePosition>,
    ) -> Option<MouseMovement> {
        if raw.is_absolute_movement() {
            let position = position?;
            let Some(previous) = self.last_cursor_position else {
                return Some(MouseMovement { dx: 0, dy: 0 });
            };

            return Some(MouseMovement {
                dx: i64::from(position.x) - i64::from(previous.x),
                dy: i64::from(position.y) - i64::from(previous.y),
            });
        }

        Some(MouseMovement {
            dx: i64::from(raw.last_x),
            dy: i64::from(raw.last_y),
        })
    }

    fn flush_due(&mut self, now: Instant) -> Option<Captured> {
        let pending = self.pending_move.as_ref()?;
        if now.saturating_duration_since(pending.started_at) < self.move_flush_interval {
            return None;
        }

        self.flush_pending(now)
    }

    fn flush_pending(&mut self, _now: Instant) -> Option<Captured> {
        self.pending_move
            .take()
            .map(PendingMouseMove::into_captured)
    }

    fn reset_after_boundary(&mut self) {
        self.active_buttons.clear();
        self.last_completed_click = None;
    }

    fn resync_active_buttons_with<F>(&mut self, is_button_down: F)
    where
        F: Fn(MouseButton) -> bool,
    {
        self.active_buttons
            .retain(|button, _| is_button_down(*button));
    }
}

#[derive(Clone, Copy)]
struct MouseBox {
    half_width: i32,
    half_height: i32,
}

impl MouseBox {
    fn contains(self, start_x: i32, start_y: i32, end_x: i32, end_y: i32) -> bool {
        !self.exceeded_by(start_x, start_y, end_x, end_y)
    }

    fn exceeded_by(self, start_x: i32, start_y: i32, end_x: i32, end_y: i32) -> bool {
        let half_width = i64::from(self.half_width.max(1));
        let half_height = i64::from(self.half_height.max(1));
        let dx = i64::from(end_x) - i64::from(start_x);
        let dy = i64::from(end_y) - i64::from(start_y);
        dx.abs() > half_width || dy.abs() > half_height
    }

    fn max_dimension(self) -> u64 {
        u64::try_from(self.half_width.max(self.half_height).max(1)).unwrap_or(1)
    }
}

fn system_double_click_interval() -> Duration {
    let ms = u64::from(unsafe { GetDoubleClickTime() });
    let ms = if ms == 0 {
        FALLBACK_DOUBLE_CLICK_MS
    } else {
        ms
    };
    Duration::from_millis(ms.min(5_000))
}

fn system_double_click_box() -> MouseBox {
    let width = positive_system_metric(SM_CXDOUBLECLK, FALLBACK_DOUBLE_CLICK_BOX_PX);
    let height = positive_system_metric(SM_CYDOUBLECLK, FALLBACK_DOUBLE_CLICK_BOX_PX);
    MouseBox {
        half_width: (width / 2).max(1),
        half_height: (height / 2).max(1),
    }
}

fn system_drag_box() -> MouseBox {
    let width = positive_system_metric(SM_CXDRAG, FALLBACK_DRAG_BOX_PX);
    let height = positive_system_metric(SM_CYDRAG, FALLBACK_DRAG_BOX_PX);
    MouseBox {
        half_width: (width / 2).max(1),
        half_height: (height / 2).max(1),
    }
}

fn positive_system_metric(metric: SYSTEM_METRICS_INDEX, fallback: i32) -> i32 {
    let value = unsafe { GetSystemMetrics(metric) };
    match value {
        0 => fallback,
        i32::MIN => fallback,
        value if value < 0 => -value,
        value => value,
    }
    .max(1)
}

struct CompletedMouseClick {
    button: MouseButton,
    started_at: Instant,
    x: Option<i32>,
    y: Option<i32>,
    hwnd: Option<u64>,
}

struct ActiveMouseButton {
    button: MouseButton,
    started_at: Instant,
    start_x: Option<i32>,
    start_y: Option<i32>,
    end_x: Option<i32>,
    end_y: Option<i32>,
    dx_total: i64,
    dy_total: i64,
    distance_px: u64,
    raw_event_count: u64,
    window: Option<WindowRef>,
    input_origin: Option<InputOrigin>,
    seed_completed_click: bool,
}

impl ActiveMouseButton {
    fn new(
        button: MouseButton,
        position: Option<MousePosition>,
        window: Option<WindowRef>,
        started_at: Instant,
        input_origin: Option<InputOrigin>,
        seed_completed_click: bool,
    ) -> Self {
        Self {
            button,
            started_at,
            start_x: position.map(|position| position.x),
            start_y: position.map(|position| position.y),
            end_x: position.map(|position| position.x),
            end_y: position.map(|position| position.y),
            dx_total: 0,
            dy_total: 0,
            distance_px: 0,
            raw_event_count: 0,
            window,
            input_origin,
            seed_completed_click,
        }
    }

    fn add_movement(
        &mut self,
        movement: MouseMovement,
        window: Option<WindowRef>,
        position: Option<MousePosition>,
        input_origin: Option<InputOrigin>,
    ) {
        self.dx_total = self.dx_total.saturating_add(movement.dx);
        self.dy_total = self.dy_total.saturating_add(movement.dy);
        self.distance_px = self.distance_px.saturating_add(movement.distance_px());
        self.raw_event_count = self.raw_event_count.saturating_add(1);
        self.finish(window, position, input_origin);
    }

    fn finish(
        &mut self,
        window: Option<WindowRef>,
        position: Option<MousePosition>,
        input_origin: Option<InputOrigin>,
    ) {
        if let Some(position) = position {
            self.end_x = Some(position.x);
            self.end_y = Some(position.y);
        }
        if window.is_some() {
            self.window = window;
        }
        if input_origin.is_some() {
            self.input_origin = input_origin;
        }
    }

    fn is_drag(&self, drag_box: &MouseBox) -> bool {
        if let (Some(start_x), Some(start_y), Some(end_x), Some(end_y)) =
            (self.start_x, self.start_y, self.end_x, self.end_y)
        {
            return drag_box.exceeded_by(start_x, start_y, end_x, end_y)
                || self.distance_px >= drag_box.max_dimension();
        }
        self.distance_px >= drag_box.max_dimension()
    }

    fn into_drag(self, ended_at: Instant) -> Captured {
        Captured::new(
            Source::Mouse,
            ended_at,
            EventPayload::MouseDrag {
                button: self.button,
                dx_total: self.dx_total,
                dy_total: self.dy_total,
                distance_px: self.distance_px,
                raw_event_count: self.raw_event_count,
                duration_ms: duration_ms(ended_at.saturating_duration_since(self.started_at)),
                start_x: self.start_x,
                start_y: self.start_y,
                end_x: self.end_x,
                end_y: self.end_y,
                window: self.window,
                selection_candidate: self.button == MouseButton::Left,
                input_origin: self.input_origin,
            },
        )
    }

    fn into_completed_click(self) -> CompletedMouseClick {
        CompletedMouseClick {
            button: self.button,
            started_at: self.started_at,
            x: self.start_x.or(self.end_x),
            y: self.start_y.or(self.end_y),
            hwnd: self.window.map(|window| window.hwnd),
        }
    }
}

struct PendingMouseMove {
    started_at: Instant,
    last_at: Instant,
    dx_total: i64,
    dy_total: i64,
    distance_px: u64,
    raw_event_count: u64,
    x: Option<i32>,
    y: Option<i32>,
    window: Option<WindowRef>,
    input_origin: Option<InputOrigin>,
}

impl PendingMouseMove {
    fn new(
        movement: MouseMovement,
        window: Option<WindowRef>,
        position: Option<MousePosition>,
        captured_at: Instant,
        input_origin: Option<InputOrigin>,
    ) -> Self {
        let mut pending = Self {
            started_at: captured_at,
            last_at: captured_at,
            dx_total: 0,
            dy_total: 0,
            distance_px: 0,
            raw_event_count: 0,
            x: None,
            y: None,
            window: None,
            input_origin: None,
        };
        pending.add(movement, window, position, captured_at, input_origin);
        pending
    }

    fn add(
        &mut self,
        movement: MouseMovement,
        window: Option<WindowRef>,
        position: Option<MousePosition>,
        captured_at: Instant,
        input_origin: Option<InputOrigin>,
    ) {
        self.last_at = captured_at;
        self.dx_total = self.dx_total.saturating_add(movement.dx);
        self.dy_total = self.dy_total.saturating_add(movement.dy);
        self.distance_px = self.distance_px.saturating_add(movement.distance_px());
        self.raw_event_count = self.raw_event_count.saturating_add(1);

        if let Some(position) = position {
            self.x = Some(position.x);
            self.y = Some(position.y);
        }
        if window.is_some() {
            self.window = window;
        }
        if input_origin.is_some() {
            self.input_origin = input_origin;
        }
    }

    fn into_captured(self) -> Captured {
        Captured::new(
            Source::Mouse,
            self.last_at,
            EventPayload::MouseMove {
                dx_total: self.dx_total,
                dy_total: self.dy_total,
                distance_px: self.distance_px,
                raw_event_count: self.raw_event_count,
                duration_ms: duration_ms(self.last_at.saturating_duration_since(self.started_at)),
                x: self.x,
                y: self.y,
                window: self.window,
                input_origin: self.input_origin,
            },
        )
    }
}

#[derive(Clone, Copy)]
struct RawMouseEvent {
    flags: u16,
    button_flags: u16,
    button_data: u16,
    last_x: i32,
    last_y: i32,
}

impl RawMouseEvent {
    fn may_change_focus(self) -> bool {
        self.down_buttons().next().is_some()
    }

    fn has_movement(self) -> bool {
        self.last_x != 0 || self.last_y != 0
    }

    fn is_absolute_movement(self) -> bool {
        self.flags & MOUSE_MOVE_ABSOLUTE.0 != 0
    }

    fn down_buttons(self) -> impl Iterator<Item = MouseButton> {
        [
            (RI_MOUSE_LEFT_BUTTON_DOWN as u16, MouseButton::Left),
            (RI_MOUSE_RIGHT_BUTTON_DOWN as u16, MouseButton::Right),
            (RI_MOUSE_MIDDLE_BUTTON_DOWN as u16, MouseButton::Middle),
            (RI_MOUSE_BUTTON_4_DOWN as u16, MouseButton::X1),
            (RI_MOUSE_BUTTON_5_DOWN as u16, MouseButton::X2),
        ]
        .into_iter()
        .filter_map(move |(flag, button)| {
            if self.button_flags & flag != 0 {
                Some(button)
            } else {
                None
            }
        })
    }

    fn up_buttons(self) -> impl Iterator<Item = MouseButton> {
        [
            (RI_MOUSE_LEFT_BUTTON_UP as u16, MouseButton::Left),
            (RI_MOUSE_RIGHT_BUTTON_UP as u16, MouseButton::Right),
            (RI_MOUSE_MIDDLE_BUTTON_UP as u16, MouseButton::Middle),
            (RI_MOUSE_BUTTON_4_UP as u16, MouseButton::X1),
            (RI_MOUSE_BUTTON_5_UP as u16, MouseButton::X2),
        ]
        .into_iter()
        .filter_map(move |(flag, button)| {
            if self.button_flags & flag != 0 {
                Some(button)
            } else {
                None
            }
        })
    }

    fn wheel_delta(self) -> i32 {
        i32::from(i16::from_ne_bytes(self.button_data.to_ne_bytes()))
    }
}

#[derive(Clone, Copy)]
struct MouseMovement {
    dx: i64,
    dy: i64,
}

impl MouseMovement {
    fn distance_px(self) -> u64 {
        (self.dx as f64).hypot(self.dy as f64).round() as u64
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MousePosition {
    x: i32,
    y: i32,
}

fn remote_relay_signature(
    raw: RawMouseEvent,
    position: Option<MousePosition>,
    previous_position: Option<MousePosition>,
    screen: VirtualScreenSnapshot,
) -> bool {
    if !raw.has_movement() || raw.is_absolute_movement() {
        return false;
    }

    match (position, previous_position) {
        (Some(position), Some(previous_position)) => {
            position == previous_position && is_virtual_screen_center(position, screen)
        }
        _ => false,
    }
}

fn is_virtual_screen_center(position: MousePosition, screen: VirtualScreenSnapshot) -> bool {
    position == screen.center()
}

#[derive(Clone, Copy)]
enum ModifierKey {
    Shift,
    Ctrl,
    Alt,
    Win,
}

impl ModifierKey {
    fn from_vkey(vkey: u16) -> Option<Self> {
        match vkey {
            0x10 | 0xa0 | 0xa1 => Some(Self::Shift),
            0x11 | 0xa2 | 0xa3 => Some(Self::Ctrl),
            0x12 | 0xa4 | 0xa5 => Some(Self::Alt),
            0x5b | 0x5c => Some(Self::Win),
            _ => None,
        }
    }
}

unsafe extern "system" fn raw_input_wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if msg == WM_INPUT {
        CAPTURE_STATE.with(|state| {
            if let Some(state) = state.borrow_mut().as_mut() {
                state.on_raw_input(lparam);
            }
        });
    }

    unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
}

unsafe extern "system" fn system_wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if msg == WM_DISPLAYCHANGE {
        CAPTURE_STATE.with(|state| {
            if let Some(state) = state.borrow_mut().as_mut() {
                state.on_display_change();
            }
        });
    } else if msg == WM_CLOSE {
        // Every realistic sender of WM_CLOSE to this hidden window —
        // taskkill without /F, Task Manager's polite path, installer and
        // updater close requests — means "exit gracefully", so it routes
        // to the same quit path as WM_ENDSESSION. Returning handled (not
        // DefWindowProc) keeps the window alive for the pump's post-loop
        // flush; the default would destroy just the window and leave a
        // half-dead app (the 2026-07-28 ghost-tray observation).
        info!("close requested on the capture window; stopping capture pump");
        unsafe {
            PostQuitMessage(0);
        }
        return LRESULT(0);
    } else if msg == WM_QUERYENDSESSION {
        info!("windows session end requested; allowing shutdown");
        return LRESULT(1);
    } else if msg == WM_ENDSESSION {
        if wparam.0 != 0 {
            info!("windows session ending; stopping capture pump");
            unsafe {
                PostQuitMessage(0);
            }
        } else {
            info!("windows session end canceled");
        }
        return LRESULT(0);
    } else if msg == WM_POWERBROADCAST {
        CAPTURE_STATE.with(|state| {
            if let Some(state) = state.borrow_mut().as_mut() {
                match wparam.0 as u32 {
                    PBT_APMSUSPEND => state.on_power_suspend(),
                    PBT_APMRESUMEAUTOMATIC | PBT_APMRESUMESUSPEND => state.on_power_resume(),
                    PBT_APMPOWERSTATUSCHANGE => state.on_power_status_change(),
                    _ => {}
                }
            }
        });
    } else if msg == WM_WTSSESSION_CHANGE {
        CAPTURE_STATE.with(|state| {
            if let Some(state) = state.borrow_mut().as_mut() {
                let Ok(event) = u32::try_from(wparam.0) else {
                    return;
                };
                let Ok(session_id) = u32::try_from(lparam.0) else {
                    return;
                };
                state.on_session_change(event, session_id);
            }
        });
    } else if msg == WM_CLIPBOARDUPDATE {
        CAPTURE_STATE.with(|state| {
            if let Some(state) = state.borrow_mut().as_mut() {
                state.on_clipboard_update();
            }
        });
    } else if msg == WM_TIMER && wparam.0 == IDLE_TIMER_ID {
        CAPTURE_STATE.with(|state| {
            if let Some(state) = state.borrow_mut().as_mut() {
                state.on_periodic_timer();
            }
        });
    }

    unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
}

unsafe extern "system" fn foreground_callback(
    _hook: HWINEVENTHOOK,
    event: u32,
    hwnd: HWND,
    _id_object: i32,
    _id_child: i32,
    _thread_id: u32,
    _event_time: u32,
) {
    if event != EVENT_SYSTEM_FOREGROUND || hwnd.is_invalid() {
        return;
    }

    CAPTURE_STATE.with(|state| {
        if let Some(state) = state.borrow_mut().as_mut() {
            state.on_foreground(hwnd);
        }
    });
}

unsafe extern "system" fn window_callback(
    _hook: HWINEVENTHOOK,
    event: u32,
    hwnd: HWND,
    id_object: i32,
    id_child: i32,
    _thread_id: u32,
    _event_time: u32,
) {
    if hwnd.is_invalid()
        || id_object != OBJID_WINDOW.0
        || id_child != i32::try_from(CHILDID_SELF).unwrap_or(0)
    {
        return;
    }

    CAPTURE_STATE.with(|state| {
        let mut state = state.borrow_mut();
        let Some(state) = state.as_mut() else {
            return;
        };

        match event {
            EVENT_OBJECT_CREATE | EVENT_OBJECT_SHOW => state.on_window_visible(hwnd),
            EVENT_OBJECT_DESTROY => state.on_window_destroyed(hwnd),
            _ => {}
        }
    });
}

unsafe extern "system" fn desktop_switch_callback(
    _hook: HWINEVENTHOOK,
    event: u32,
    _hwnd: HWND,
    _id_object: i32,
    _id_child: i32,
    _thread_id: u32,
    _event_time: u32,
) {
    if event != EVENT_SYSTEM_DESKTOPSWITCH {
        return;
    }

    CAPTURE_STATE.with(|state| {
        if let Some(state) = state.borrow_mut().as_mut() {
            if state.should_sample_input_desktop() {
                state.on_input_desktop_sample_at(
                    current_input_desktop_sensitivity(),
                    Instant::now(),
                );
            }
        }
    });
}

fn install_hook(
    event_min: u32,
    event_max: u32,
    callback: windows::Win32::UI::Accessibility::WINEVENTPROC,
    name: &'static str,
) -> Result<WinEventHook, CaptureError> {
    let hook = unsafe {
        SetWinEventHook(
            event_min,
            event_max,
            None,
            callback,
            0,
            0,
            WINEVENT_OUTOFCONTEXT,
        )
    };

    if hook.is_invalid() {
        clear_thread_state();
        return Err(CaptureError::WindowsApi(format!(
            "SetWinEventHook({name}) failed"
        )));
    }

    Ok(WinEventHook(hook))
}

fn install_optional_hook(
    event_min: u32,
    event_max: u32,
    callback: windows::Win32::UI::Accessibility::WINEVENTPROC,
    name: &'static str,
) -> Option<WinEventHook> {
    let hook = unsafe {
        SetWinEventHook(
            event_min,
            event_max,
            None,
            callback,
            0,
            0,
            WINEVENT_OUTOFCONTEXT,
        )
    };

    if hook.is_invalid() {
        warn!("optional {name} hook unavailable; using periodic fallback");
        None
    } else {
        Some(WinEventHook(hook))
    }
}

fn seed_initial_foreground() {
    let hwnd = unsafe { GetForegroundWindow() };
    if hwnd.is_invalid() {
        return;
    }

    CAPTURE_STATE.with(|state| {
        if let Some(state) = state.borrow_mut().as_mut() {
            state.seed_foreground(hwnd);
        }
    });
}

fn seed_initial_windows() {
    CAPTURE_STATE.with(|state| {
        if let Some(state) = state.borrow_mut().as_mut() {
            state.seed_windows();
        }
    });
}

fn seed_system() {
    CAPTURE_STATE.with(|state| {
        if let Some(state) = state.borrow_mut().as_mut() {
            state.seed_system();
            // Seed the current AC/battery status once at startup (power_status is
            // otherwise transition-only). Production path only; tests drive the
            // capture-state methods directly with injected data.
            state.on_power_status_change();
            state.on_input_desktop_sample_at(current_input_desktop_sensitivity(), Instant::now());
        }
    });
}

fn clear_thread_state() {
    CAPTURE_STATE.with(|state| {
        *state.borrow_mut() = None;
    });
}

struct CaptureThreadStateGuard;

impl Drop for CaptureThreadStateGuard {
    fn drop(&mut self) {
        clear_thread_state();
    }
}

fn flush_due_mouse_movement() {
    let now = Instant::now();
    CAPTURE_STATE.with(|state| {
        if let Some(state) = state.borrow_mut().as_mut() {
            state.flush_due_mouse_movement(now);
        }
    });
}

fn check_requested_reseed() {
    while let Ok(reply) = SENSITIVE_RECONCILE_REQUESTS.1.try_recv() {
        let result = CAPTURE_STATE.with(|state| {
            let mut state = state.borrow_mut();
            let state = state.as_mut()?;
            state.reconcile_sensitive_context_for_resume()
        });
        let _ = reply.send(result);
    }
    CAPTURE_STATE.with(|state| {
        if let Some(state) = state.borrow_mut().as_mut() {
            state.check_requested_reseed();
        }
    });
}

fn flush_shutdown_events() {
    let now = Instant::now();
    CAPTURE_STATE.with(|state| {
        if let Some(state) = state.borrow_mut().as_mut() {
            state.flush_shutdown_events(now);
        }
    });
}

fn current_foreground_window() -> Option<WindowRef> {
    let hwnd = unsafe { GetForegroundWindow() };
    normalize_window(hwnd).and_then(resolve_window)
}

enum RawInputEvent {
    Keyboard(RawKeyboardEvent),
    Mouse(RawMouseEvent),
}

fn raw_input_from_lparam(lparam: LPARAM) -> Option<RawInputEvent> {
    let hrawinput = HRAWINPUT(lparam.0 as *mut c_void);
    let header_size = size_of::<RAWINPUTHEADER>() as u32;
    let mut size = 0;

    let first = unsafe { GetRawInputData(hrawinput, RID_INPUT, None, &mut size, header_size) };
    if first == u32::MAX || size == 0 {
        return None;
    }

    let mut buffer = vec![0u8; size as usize];
    let read = unsafe {
        GetRawInputData(
            hrawinput,
            RID_INPUT,
            Some(buffer.as_mut_ptr().cast()),
            &mut size,
            header_size,
        )
    };
    if read == u32::MAX || read != size {
        return None;
    }

    raw_input_from_bytes(&buffer)
}

fn raw_input_from_bytes(buffer: &[u8]) -> Option<RawInputEvent> {
    let header = read_unaligned_from::<RAWINPUTHEADER>(buffer, 0)?;
    let data_offset = size_of::<RAWINPUTHEADER>();

    match header.dwType {
        value if value == RIM_TYPEKEYBOARD.0 => {
            let keyboard = read_unaligned_from::<RAWKEYBOARD>(buffer, data_offset)?;
            Some(RawInputEvent::Keyboard(RawKeyboardEvent {
                vkey: keyboard.VKey,
                flags: keyboard.Flags,
            }))
        }
        value if value == RIM_TYPEMOUSE.0 => {
            let mouse = read_unaligned_from::<RAWMOUSE>(buffer, data_offset)?;
            let buttons = unsafe { mouse.Anonymous.Anonymous };
            Some(RawInputEvent::Mouse(RawMouseEvent {
                flags: mouse.usFlags.0,
                button_flags: buttons.usButtonFlags,
                button_data: buttons.usButtonData,
                last_x: mouse.lLastX,
                last_y: mouse.lLastY,
            }))
        }
        _ => None,
    }
}

fn read_unaligned_from<T: Copy>(buffer: &[u8], offset: usize) -> Option<T> {
    let end = offset.checked_add(size_of::<T>())?;
    if end > buffer.len() {
        return None;
    }

    Some(unsafe { std::ptr::read_unaligned(buffer.as_ptr().add(offset).cast::<T>()) })
}

fn current_cursor_position() -> Option<MousePosition> {
    let mut point = POINT::default();
    unsafe { GetCursorPos(&mut point) }.ok()?;
    Some(MousePosition {
        x: point.x,
        y: point.y,
    })
}

fn current_idle_ms() -> Option<u64> {
    let mut info = LASTINPUTINFO {
        cbSize: size_of::<LASTINPUTINFO>() as u32,
        ..Default::default()
    };

    if !unsafe { GetLastInputInfo(&mut info) }.as_bool() {
        return None;
    }

    Some(idle_ms_from_ticks(current_tick_ms(), info.dwTime))
}

fn current_tick_ms() -> u64 {
    unsafe { GetTickCount64() }
}

fn idle_ms_from_ticks(now_tick_ms: u64, last_input_tick_ms: u32) -> u64 {
    u64::from((now_tick_ms as u32).wrapping_sub(last_input_tick_ms))
}

fn physical_key_down(vkey: u16) -> bool {
    unsafe { GetAsyncKeyState(i32::from(vkey)) }.is_negative()
}

fn physical_mouse_button_down(button: MouseButton) -> bool {
    let vkey = match button {
        MouseButton::Left => 0x01,
        MouseButton::Right => 0x02,
        MouseButton::Middle => 0x04,
        MouseButton::X1 => 0x05,
        MouseButton::X2 => 0x06,
    };
    unsafe { GetAsyncKeyState(vkey) }.is_negative()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InputDesktopSensitivity {
    Normal,
    Protected,
}

struct DesktopHandle(HDESK);

impl Drop for DesktopHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            if let Err(error) = unsafe { CloseDesktop(self.0) } {
                debug!(%error, "failed to close input desktop handle");
            }
        }
    }
}

fn current_input_desktop_sensitivity() -> InputDesktopSensitivity {
    current_input_desktop_name()
        .map(|name| input_desktop_sensitivity_from_name(Some(&name)))
        .unwrap_or(InputDesktopSensitivity::Protected)
}

fn input_desktop_sensitivity_from_name(name: Option<&str>) -> InputDesktopSensitivity {
    match name.map(str::trim).filter(|name| !name.is_empty()) {
        Some(name) if name.eq_ignore_ascii_case("Default") => InputDesktopSensitivity::Normal,
        _ => InputDesktopSensitivity::Protected,
    }
}

fn current_input_desktop_name() -> windows::core::Result<String> {
    let desktop = DesktopHandle(unsafe {
        OpenInputDesktop(DESKTOP_CONTROL_FLAGS(0), false, DESKTOP_READOBJECTS)
    }?);

    let mut needed_bytes = 0u32;
    let _ = unsafe {
        GetUserObjectInformationW(
            HANDLE(desktop.0 .0),
            UOI_NAME,
            None,
            0,
            Some(&mut needed_bytes),
        )
    };
    if needed_bytes == 0 {
        return Err(windows::core::Error::from_thread());
    }

    let wchar_len = usize::try_from(needed_bytes.div_ceil(2)).unwrap_or(0);
    if wchar_len == 0 {
        return Err(windows::core::Error::from_thread());
    }

    let mut buffer = vec![0u16; wchar_len];
    unsafe {
        GetUserObjectInformationW(
            HANDLE(desktop.0 .0),
            UOI_NAME,
            Some(buffer.as_mut_ptr().cast()),
            needed_bytes,
            Some(&mut needed_bytes),
        )
    }?;

    let len = buffer
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(buffer.len());
    Ok(String::from_utf16_lossy(&buffer[..len]))
}

fn current_system_info() -> EventPayload {
    EventPayload::SystemInfo {
        host: computer_name(),
        os_version: os_version(),
        arch: native_arch(),
        processor_count: processor_count(),
        memory_total_bytes: memory_total_bytes(),
    }
}

fn current_virtual_screen() -> VirtualScreenSnapshot {
    let x0 = unsafe { GetSystemMetrics(SM_XVIRTUALSCREEN) };
    let y0 = unsafe { GetSystemMetrics(SM_YVIRTUALSCREEN) };
    let width = unsafe { GetSystemMetrics(SM_CXVIRTUALSCREEN) };
    let height = unsafe { GetSystemMetrics(SM_CYVIRTUALSCREEN) };
    VirtualScreenSnapshot {
        x0,
        y0,
        width,
        height,
    }
}

fn computer_name() -> String {
    let mut size = 0;
    let _ = unsafe { GetComputerNameExW(ComputerNamePhysicalDnsHostname, None, &mut size) };
    if size == 0 {
        size = 256;
    }

    let mut buffer = vec![0u16; size as usize];
    if unsafe {
        GetComputerNameExW(
            ComputerNamePhysicalDnsHostname,
            Some(PWSTR(buffer.as_mut_ptr())),
            &mut size,
        )
    }
    .is_err()
    {
        return String::new();
    }

    String::from_utf16_lossy(&buffer[..size as usize])
}

fn os_version() -> String {
    let mut version = OSVERSIONINFOW {
        dwOSVersionInfoSize: size_of::<OSVERSIONINFOW>() as u32,
        ..Default::default()
    };

    let rtl_status = unsafe { RtlGetVersion(&mut version) };
    if rtl_status != 0 && unsafe { GetVersionExW(&mut version) }.is_err() {
        return "unknown".to_string();
    }

    format!(
        "{}.{}.{}",
        version.dwMajorVersion, version.dwMinorVersion, version.dwBuildNumber
    )
}

fn native_arch() -> String {
    let mut info = SYSTEM_INFO::default();
    unsafe {
        GetNativeSystemInfo(&mut info);
    }

    let arch = unsafe { info.Anonymous.Anonymous.wProcessorArchitecture };
    processor_architecture_name(arch).to_string()
}

fn processor_count() -> u32 {
    let mut info = SYSTEM_INFO::default();
    unsafe {
        GetNativeSystemInfo(&mut info);
    }
    info.dwNumberOfProcessors
}

fn processor_architecture_name(arch: PROCESSOR_ARCHITECTURE) -> &'static str {
    match arch {
        PROCESSOR_ARCHITECTURE_AMD64 => "x86_64",
        PROCESSOR_ARCHITECTURE_ARM64 => "arm64",
        PROCESSOR_ARCHITECTURE_INTEL => "x86",
        PROCESSOR_ARCHITECTURE_UNKNOWN => "unknown",
        _ => "other",
    }
}

fn memory_total_bytes() -> u64 {
    let mut status = MEMORYSTATUSEX {
        dwLength: size_of::<MEMORYSTATUSEX>() as u32,
        ..Default::default()
    };

    if unsafe { GlobalMemoryStatusEx(&mut status) }.is_err() {
        return 0;
    }

    status.ullTotalPhys
}

fn enum_top_level_windows() -> Vec<WindowRef> {
    let mut windows = Vec::new();
    let result = unsafe {
        EnumWindows(
            Some(enum_windows_callback),
            LPARAM((&mut windows as *mut Vec<WindowRef>) as isize),
        )
    };

    if let Err(error) = result {
        warn!(%error, "failed to enumerate startup windows");
    }

    windows
}

unsafe extern "system" fn enum_windows_callback(hwnd: HWND, lparam: LPARAM) -> BOOL {
    if is_real_top_level_window(hwnd) {
        let windows = unsafe { &mut *(lparam.0 as *mut Vec<WindowRef>) };
        if let Some(window) = resolve_window(hwnd) {
            windows.push(window);
        }
    }

    true.into()
}

fn is_real_top_level_window(hwnd: HWND) -> bool {
    if hwnd.is_invalid() {
        return false;
    }

    unsafe {
        if !IsWindow(Some(hwnd)).as_bool() || !IsWindowVisible(hwnd).as_bool() {
            return false;
        }

        if GetAncestor(hwnd, GA_ROOT).0 != hwnd.0 {
            return false;
        }

        GetWindow(hwnd, GW_OWNER).is_err()
    }
}

fn normalize_window(hwnd: HWND) -> Option<HWND> {
    if hwnd.is_invalid() {
        return None;
    }

    let root = unsafe { GetAncestor(hwnd, GA_ROOT) };
    if root.is_invalid() {
        Some(hwnd)
    } else {
        Some(root)
    }
}

fn resolve_window(hwnd: HWND) -> Option<WindowRef> {
    if hwnd.is_invalid() {
        return None;
    }

    let mut pid = 0;
    unsafe {
        GetWindowThreadProcessId(hwnd, Some(&mut pid));
    }
    if pid == 0 {
        return None;
    }
    if pid == std::process::id() {
        return None;
    }

    Some(WindowRef {
        hwnd: hwnd_to_u64(hwnd),
        exe: process_path(pid).unwrap_or_default(),
        title: window_title(hwnd),
        pid,
    })
}

fn hwnd_to_u64(hwnd: HWND) -> u64 {
    hwnd.0 as usize as u64
}

fn key_to_string(vkey: u16) -> String {
    match vkey {
        0x30..=0x39 | 0x41..=0x5a => char::from_u32(u32::from(vkey))
            .map(|value| value.to_string())
            .unwrap_or_else(|| format!("VK_0x{vkey:02x}")),
        0x08 => "Backspace".to_string(),
        0x09 => "Tab".to_string(),
        0x0d => "Enter".to_string(),
        0x10 | 0xa0 | 0xa1 => "Shift".to_string(),
        0x11 | 0xa2 | 0xa3 => "Ctrl".to_string(),
        0x12 | 0xa4 | 0xa5 => "Alt".to_string(),
        0x13 => "Pause".to_string(),
        0x14 => "CapsLock".to_string(),
        0x1b => "Escape".to_string(),
        0x20 => "Space".to_string(),
        0x21 => "PageUp".to_string(),
        0x22 => "PageDown".to_string(),
        0x23 => "End".to_string(),
        0x24 => "Home".to_string(),
        0x25 => "ArrowLeft".to_string(),
        0x26 => "ArrowUp".to_string(),
        0x27 => "ArrowRight".to_string(),
        0x28 => "ArrowDown".to_string(),
        0x2d => "Insert".to_string(),
        0x2e => "Delete".to_string(),
        0x5b | 0x5c => "Win".to_string(),
        0x5d => "Apps".to_string(),
        0x60..=0x69 => format!("Numpad{}", vkey - 0x60),
        0x6a => "NumpadMultiply".to_string(),
        0x6b => "NumpadAdd".to_string(),
        0x6c => "NumpadSeparator".to_string(),
        0x6d => "NumpadSubtract".to_string(),
        0x6e => "NumpadDecimal".to_string(),
        0x6f => "NumpadDivide".to_string(),
        0x70..=0x87 => format!("F{}", vkey - 0x6f),
        0x90 => "NumLock".to_string(),
        0x91 => "ScrollLock".to_string(),
        0xba => ";".to_string(),
        0xbb => "=".to_string(),
        0xbc => ",".to_string(),
        0xbd => "-".to_string(),
        0xbe => ".".to_string(),
        0xbf => "/".to_string(),
        0xc0 => "`".to_string(),
        0xdb => "[".to_string(),
        0xdc => "\\".to_string(),
        0xdd => "]".to_string(),
        0xde => "'".to_string(),
        _ => format!("VK_0x{vkey:02x}"),
    }
}

fn window_title(hwnd: HWND) -> String {
    let mut buffer = vec![0u16; 512];
    let len = unsafe { GetWindowTextW(hwnd, &mut buffer) };
    if len <= 0 {
        String::new()
    } else {
        String::from_utf16_lossy(&buffer[..len as usize])
    }
}

#[derive(Default)]
struct ProcessInspection {
    path: Option<String>,
    creation_time_100ns: Option<u64>,
}

fn inspect_process(pid: u32) -> ProcessInspection {
    let Ok(handle) = (unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }) else {
        return ProcessInspection::default();
    };
    let _guard = HandleGuard(handle);

    ProcessInspection {
        path: process_path_from_handle(handle),
        creation_time_100ns: process_creation_time_100ns_from_handle(handle),
    }
}

fn process_path(pid: u32) -> Option<String> {
    inspect_process(pid).path
}

fn process_path_from_handle(handle: HANDLE) -> Option<String> {
    let mut buffer = vec![0u16; 32_768];
    let mut size = buffer.len() as u32;
    unsafe {
        QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_FORMAT(0),
            PWSTR(buffer.as_mut_ptr()),
            &mut size,
        )
        .ok()?;
    }

    Some(String::from_utf16_lossy(&buffer[..size as usize]))
}

fn process_creation_time_100ns_from_handle(handle: HANDLE) -> Option<u64> {
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    unsafe {
        GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user).ok()?;
    }
    Some(filetime_to_100ns(creation))
}

fn filetime_to_100ns(filetime: FILETIME) -> u64 {
    (u64::from(filetime.dwHighDateTime) << 32) | u64::from(filetime.dwLowDateTime)
}

struct HandleGuard(HANDLE);

impl Drop for HandleGuard {
    fn drop(&mut self) {
        if let Err(error) = unsafe { CloseHandle(self.0) } {
            warn!(%error, "failed to close process handle");
        }
    }
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use gilbreth_core::EventPayload;

    /// WM_CLOSE routes to the same quit path as WM_ENDSESSION: the proc
    /// posts WM_QUIT to the calling thread's queue and reports the message
    /// handled, so the hidden window survives for the pump's post-loop
    /// flush instead of being destroyed under a half-alive app (the
    /// 2026-07-28 ghost-tray observation).
    #[test]
    fn wm_close_routes_to_the_quit_path_and_stays_handled() {
        use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
        use windows::Win32::UI::WindowsAndMessaging::{
            PeekMessageW, MSG, PM_REMOVE, WM_CLOSE, WM_QUIT,
        };

        let result = unsafe {
            super::system_wnd_proc(HWND(std::ptr::null_mut()), WM_CLOSE, WPARAM(0), LPARAM(0))
        };
        assert_eq!(result.0, 0, "WM_CLOSE reports handled");

        let mut message = MSG::default();
        let found = unsafe { PeekMessageW(&mut message, None, 0, 0, PM_REMOVE) };
        assert!(
            found.as_bool(),
            "the quit message waits in this thread's queue"
        );
        assert_eq!(message.message, WM_QUIT);
    }

    use super::*;

    fn window(hwnd: u64, title: &str) -> WindowRef {
        WindowRef {
            hwnd,
            exe: format!("C:\\Apps\\{title}.exe"),
            title: title.to_string(),
            pid: hwnd as u32,
        }
    }

    fn system_info_payload() -> EventPayload {
        EventPayload::SystemInfo {
            host: "workstation".to_string(),
            os_version: "10.0.26100".to_string(),
            arch: "x86_64".to_string(),
            processor_count: 16,
            memory_total_bytes: 64,
        }
    }

    fn screen(x0: i32, y0: i32, width: i32, height: i32) -> VirtualScreenSnapshot {
        VirtualScreenSnapshot {
            x0,
            y0,
            width,
            height,
        }
    }

    #[test]
    fn idle_ms_from_ticks_uses_32_bit_tick_domain_before_wrap() {
        assert_eq!(idle_ms_from_ticks(12_500, 10_000), 2_500);
    }

    #[test]
    fn idle_ms_from_ticks_uses_32_bit_tick_domain_after_wrap() {
        assert_eq!(idle_ms_from_ticks(0x1_0000_0010, 0xffff_ff00), 0x110);
    }

    fn raw_input_packet<T>(kind: u32, payload: &T) -> Vec<u8> {
        let mut bytes = Vec::new();
        let header = RAWINPUTHEADER {
            dwType: kind,
            dwSize: (size_of::<RAWINPUTHEADER>() + size_of::<T>()) as u32,
            ..Default::default()
        };

        push_bytes(&mut bytes, &header);
        push_bytes(&mut bytes, payload);
        bytes
    }

    fn push_bytes<T>(bytes: &mut Vec<u8>, value: &T) {
        let slice =
            unsafe { std::slice::from_raw_parts((value as *const T).cast::<u8>(), size_of::<T>()) };
        bytes.extend_from_slice(slice);
    }

    fn key_event(key: &str, captured_at: Instant) -> Captured {
        Captured::new(
            Source::Keyboard,
            captured_at,
            EventPayload::Key {
                key: key.to_string(),
                mods: Modifiers::default(),
                window: None,
                key_class: None,
            },
        )
    }

    fn process_snapshot(entries: &[(u32, &str)]) -> Option<ProcessSnapshot> {
        ProcessSnapshot::from_entries(entries.iter().map(|(pid, name)| ProcessSnapshotEntry {
            pid: *pid,
            snapshot_name: (*name).to_string(),
        }))
    }

    fn fake_process_details(
        pid: u32,
        snapshot_name: &str,
        creation_time_100ns: Option<u64>,
    ) -> ProcessDetails {
        let (exe, exe_source) = if snapshot_name == "fallback.exe" {
            (snapshot_name.to_string(), ProcessExeSource::SnapshotName)
        } else {
            (
                format!("C:\\Apps\\{pid}\\{snapshot_name}"),
                ProcessExeSource::FullPath,
            )
        };
        ProcessDetails {
            exe,
            exe_source,
            creation_time_100ns,
        }
    }

    fn fake_process_resolver(pid: u32, snapshot_name: &str) -> ProcessDetails {
        fake_process_details(pid, snapshot_name, Some(u64::from(pid) * 100))
    }

    fn process_started_pid(transition: &ProcessTransition) -> Option<u32> {
        match transition {
            ProcessTransition::Started(identity) => Some(identity.pid),
            ProcessTransition::Exited(_) => None,
        }
    }

    fn process_exited_pid(transition: &ProcessTransition) -> Option<u32> {
        match transition {
            ProcessTransition::Exited(identity) => Some(identity.pid),
            ProcessTransition::Started(_) => None,
        }
    }

    #[test]
    fn disabled_stream_drops_before_enqueue() {
        let controls = CaptureControls::all_enabled();
        controls.set_enabled(CaptureStream::Keyboard, false);
        let (tx, rx) = crossbeam_channel::bounded(4);
        let state = CaptureState::new(tx, controls);

        state.send(key_event("A", Instant::now()), "keyboard");

        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn process_tracker_first_snapshot_seeds_without_events() {
        let mut tracker = ProcessTracker::default();
        let transitions = tracker.apply_snapshot(
            process_snapshot(&[(10, "notepad.exe"), (20, "explorer.exe")]),
            fake_process_resolver,
        );

        assert!(transitions.is_empty());
        assert_eq!(tracker.live.len(), 2);
    }

    #[test]
    fn process_tracker_stable_processes_do_not_churn_across_intervals() {
        let mut tracker = ProcessTracker::default();
        assert!(tracker
            .apply_snapshot(
                process_snapshot(&[(10, "notepad.exe")]),
                fake_process_resolver
            )
            .is_empty());

        for _ in 0..5 {
            assert!(tracker
                .apply_snapshot(
                    process_snapshot(&[(10, "NOTEPAD.EXE")]),
                    fake_process_resolver
                )
                .is_empty());
        }

        let transitions = tracker.apply_snapshot(
            process_snapshot(&[(10, "notepad.exe"), (20, "calc.exe")]),
            fake_process_resolver,
        );
        assert_eq!(transitions.len(), 1);
        assert_eq!(process_started_pid(&transitions[0]), Some(20));

        for _ in 0..5 {
            assert!(tracker
                .apply_snapshot(
                    process_snapshot(&[(10, "notepad.exe"), (20, "calc.exe")]),
                    fake_process_resolver,
                )
                .is_empty());
        }
    }

    #[test]
    fn process_tracker_detects_exit_start_and_pid_reuse_by_base_name() {
        let mut tracker = ProcessTracker::default();
        assert!(tracker
            .apply_snapshot(
                process_snapshot(&[(10, "old.exe"), (20, "gone.exe")]),
                fake_process_resolver,
            )
            .is_empty());

        let transitions =
            tracker.apply_snapshot(process_snapshot(&[(10, "new.exe")]), fake_process_resolver);

        assert_eq!(transitions.len(), 3);
        assert_eq!(process_exited_pid(&transitions[0]), Some(10));
        assert_eq!(process_started_pid(&transitions[1]), Some(10));
        assert_eq!(process_exited_pid(&transitions[2]), Some(20));
        match &transitions[0] {
            ProcessTransition::Exited(identity) => {
                assert_eq!(identity.exe, "C:\\Apps\\10\\old.exe")
            }
            _ => panic!("expected old process exit"),
        }
        match &transitions[1] {
            ProcessTransition::Started(identity) => {
                assert_eq!(identity.exe, "C:\\Apps\\10\\new.exe")
            }
            _ => panic!("expected new process start"),
        }
    }

    #[test]
    fn process_tracker_same_pid_basename_and_creation_time_stays_stable() {
        let mut tracker = ProcessTracker::default();
        assert!(tracker
            .apply_snapshot(process_snapshot(&[(10, "same.exe")]), |pid, name| {
                fake_process_details(pid, name, Some(111))
            })
            .is_empty());

        let transitions = tracker
            .apply_snapshot(process_snapshot(&[(10, "same.exe")]), |pid, name| {
                fake_process_details(pid, name, Some(111))
            });

        assert!(transitions.is_empty());
        assert_eq!(
            tracker
                .live
                .get(&10)
                .expect("same process cached")
                .creation_time_100ns,
            Some(111)
        );
    }

    #[test]
    fn process_tracker_detects_same_name_pid_reuse_by_creation_time() {
        let mut tracker = ProcessTracker::default();
        assert!(tracker
            .apply_snapshot(process_snapshot(&[(10, "same.exe")]), |pid, name| {
                fake_process_details(pid, name, Some(111))
            })
            .is_empty());

        let transitions = tracker
            .apply_snapshot(process_snapshot(&[(10, "same.exe")]), |pid, name| {
                fake_process_details(pid, name, Some(222))
            });

        assert_eq!(transitions.len(), 2);
        assert_eq!(process_exited_pid(&transitions[0]), Some(10));
        assert_eq!(process_started_pid(&transitions[1]), Some(10));
        match (&transitions[0], &transitions[1]) {
            (ProcessTransition::Exited(previous), ProcessTransition::Started(next)) => {
                assert_eq!(previous.exe, "C:\\Apps\\10\\same.exe");
                assert_eq!(previous.creation_time_100ns, Some(111));
                assert_eq!(next.exe, "C:\\Apps\\10\\same.exe");
                assert_eq!(next.creation_time_100ns, Some(222));
            }
            _ => panic!("expected same-name pid reuse transition"),
        }
    }

    #[test]
    fn process_tracker_missing_creation_time_falls_back_to_basename() {
        let mut tracker = ProcessTracker::default();
        assert!(tracker
            .apply_snapshot(process_snapshot(&[(10, "same.exe")]), |pid, name| {
                fake_process_details(pid, name, Some(111))
            })
            .is_empty());

        let stable = tracker.apply_snapshot(process_snapshot(&[(10, "SAME.EXE")]), |pid, name| {
            fake_process_details(pid, name, None)
        });
        assert!(stable.is_empty());
        assert_eq!(
            tracker
                .live
                .get(&10)
                .expect("same process cached")
                .creation_time_100ns,
            Some(111)
        );

        let reused = tracker.apply_snapshot(process_snapshot(&[(10, "other.exe")]), |pid, name| {
            fake_process_details(pid, name, None)
        });
        assert_eq!(reused.len(), 2);
        assert_eq!(process_exited_pid(&reused[0]), Some(10));
        assert_eq!(process_started_pid(&reused[1]), Some(10));
    }

    #[test]
    fn exe_basename_lower_handles_paths_and_bare_names() {
        assert_eq!(
            exe_basename_lower("C:\\Windows\\System32\\SVCHOST.EXE"),
            "svchost.exe"
        );
        assert_eq!(
            exe_basename_lower("C:/Program Files/Git/git.exe"),
            "git.exe"
        );
        assert_eq!(exe_basename_lower("Notepad.exe"), "notepad.exe");
        assert_eq!(exe_basename_lower("  "), "");
    }

    #[test]
    fn capture_controls_foreground_rescue_tracks_basenames() {
        let controls = CaptureControls::all_enabled();
        assert!(!controls.foreground_exe_seen("excel.exe"));
        controls.note_foreground_exe("Excel.EXE");
        assert!(controls.foreground_exe_seen("excel.exe"));
        // Full paths normalize to the same basename key.
        controls.note_foreground_exe("C:\\Apps\\Tool.exe");
        assert!(controls.foreground_exe_seen("tool.exe"));
        // Empty exe never poisons the set.
        controls.note_foreground_exe("   ");
        assert!(!controls.foreground_exe_seen(""));
    }

    #[test]
    fn title_redacted_reseed_request_sets_one_shot_flag() {
        let controls = CaptureControls::all_enabled();

        assert!(!controls.take_title_redaction_for_reseed());
        assert_eq!(controls.request_title_redacted_reseed(), 1);
        assert_eq!(controls.reseed_generation(), 1);
        assert!(controls.take_title_redaction_for_reseed());
        assert!(!controls.take_title_redaction_for_reseed());
    }

    #[test]
    fn capture_settings_roundtrip_includes_process_filter() {
        let mut settings = CaptureSettings::all_enabled();
        settings.process_filter = false;
        let controls = CaptureControls::new(settings);
        assert!(!controls.process_filter_enabled());
        assert!(!controls.settings().process_filter);
        controls.set_process_filter_enabled(true);
        assert!(controls.settings().process_filter);
    }

    #[test]
    fn process_transition_basename_prefers_snapshot_name() {
        let mut tracker = ProcessTracker::default();
        assert!(tracker
            .apply_snapshot(process_snapshot(&[(10, "Notepad.exe")]), |pid, name| {
                fake_process_details(pid, name, Some(1))
            })
            .is_empty());
        // Empty snapshots read as None (mass-exit guard), so replace the
        // process with another pid to observe the exit transition.
        let transitions = tracker
            .apply_snapshot(process_snapshot(&[(99, "other.exe")]), |pid, name| {
                fake_process_details(pid, name, Some(1))
            });
        let exited = transitions
            .iter()
            .find(|transition| matches!(transition, ProcessTransition::Exited(_)))
            .expect("exit transition for the replaced process");
        assert_eq!(exited.basename(), "notepad.exe");
    }

    #[test]
    fn process_tracker_failed_snapshot_preserves_state_without_mass_exits() {
        let mut tracker = ProcessTracker::default();
        assert!(tracker
            .apply_snapshot(
                process_snapshot(&[(10, "notepad.exe")]),
                fake_process_resolver
            )
            .is_empty());

        let transitions = tracker.apply_snapshot(None, fake_process_resolver);

        assert!(transitions.is_empty());
        assert_eq!(tracker.live.len(), 1);
        assert!(tracker.live.contains_key(&10));
    }

    #[test]
    fn process_identity_caches_full_path_source_and_fallback() {
        let mut tracker = ProcessTracker::default();
        assert!(tracker
            .apply_snapshot(
                process_snapshot(&[(10, "notepad.exe"), (20, "fallback.exe")]),
                fake_process_resolver,
            )
            .is_empty());

        let notepad = tracker.live.get(&10).expect("notepad cached");
        assert_eq!(notepad.exe, "C:\\Apps\\10\\notepad.exe");
        assert_eq!(notepad.exe_source, ProcessExeSource::FullPath);
        let fallback = tracker.live.get(&20).expect("fallback cached");
        assert_eq!(fallback.exe, "fallback.exe");
        assert_eq!(fallback.exe_source, ProcessExeSource::SnapshotName);

        let transitions = tracker.apply_snapshot(
            process_snapshot(&[(10, "notepad.exe")]),
            fake_process_resolver,
        );

        assert_eq!(transitions.len(), 1);
        match &transitions[0] {
            ProcessTransition::Exited(identity) => {
                assert_eq!(identity.pid, 20);
                assert_eq!(identity.exe, "fallback.exe");
                assert_eq!(identity.exe_source, ProcessExeSource::SnapshotName);
            }
            _ => panic!("expected fallback exit"),
        }
    }

    #[test]
    fn process_toggle_off_on_drops_without_backlog_and_keeps_state_warm() {
        let controls = CaptureControls::all_enabled();
        let (tx, rx) = crossbeam_channel::bounded(8);
        let mut tracker = ProcessTracker::default();
        assert!(tracker
            .apply_snapshot(
                process_snapshot(&[(10, "notepad.exe")]),
                fake_process_resolver
            )
            .is_empty());

        controls.set_enabled(CaptureStream::System, false);
        for transition in tracker.apply_snapshot(
            process_snapshot(&[(10, "notepad.exe"), (20, "calc.exe")]),
            fake_process_resolver,
        ) {
            send_process_transition(&tx, &controls, transition);
        }
        assert!(rx.try_recv().is_err());

        controls.set_enabled(CaptureStream::System, true);
        for transition in tracker.apply_snapshot(
            process_snapshot(&[(10, "notepad.exe"), (20, "calc.exe"), (30, "mspaint.exe")]),
            fake_process_resolver,
        ) {
            send_process_transition(&tx, &controls, transition);
        }

        let captured = rx.try_recv().expect("latest delta enqueued");
        assert!(rx.try_recv().is_err());
        match captured.payload {
            EventPayload::ProcessStarted { pid, exe, .. } => {
                assert_eq!(pid, 30);
                assert_eq!(exe, "C:\\Apps\\30\\mspaint.exe");
            }
            _ => panic!("expected process start"),
        }
    }

    #[test]
    fn process_monitor_shutdown_wakes_poll_wait_promptly() {
        let controls = CaptureControls::all_enabled();
        let (tx, _rx) = crossbeam_channel::bounded(8);
        let stop = StopToken::new();
        let monitor = ProcessMonitor::start(tx, controls, stop);

        thread::sleep(Duration::from_millis(100));
        let started = Instant::now();
        drop(monitor);

        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn suspension_drops_before_enqueue_without_changing_stream_settings() {
        let controls = CaptureControls::all_enabled();
        let (tx, rx) = crossbeam_channel::bounded(4);
        let state = CaptureState::new(tx, controls.clone());

        controls.set_suspended(true);
        state.send(key_event("A", Instant::now()), "keyboard");

        assert!(controls.enabled(CaptureStream::Keyboard));
        assert!(controls.settings().keyboard);
        assert!(rx.try_recv().is_err());

        controls.set_suspended(false);
        state.send(key_event("B", Instant::now()), "keyboard");

        let captured = rx.try_recv().expect("resumed event enqueued");
        match captured.payload {
            EventPayload::Key { key, .. } => assert_eq!(key, "B"),
            _ => panic!("expected key event"),
        }
    }

    #[test]
    fn capture_thread_state_guard_drops_sender_on_early_exit() {
        let (tx, rx) = crossbeam_channel::bounded(1);
        CAPTURE_STATE.with(|state| {
            *state.borrow_mut() = Some(CaptureState::new(tx, CaptureControls::all_enabled()));
        });

        {
            let _guard = CaptureThreadStateGuard;
        }

        assert!(matches!(
            rx.recv_timeout(Duration::from_millis(1)),
            Err(crossbeam_channel::RecvTimeoutError::Disconnected)
        ));
    }

    #[test]
    fn sensitive_reconcile_request_is_acknowledged_on_pump_and_worker_paths() {
        let controls = CaptureControls::all_enabled();
        controls.set_suspended(true);
        let (tx, rx) = crossbeam_channel::bounded(32);
        let mut state = CaptureState::new(tx, controls.clone());
        state.on_input_desktop_sample_at(InputDesktopSensitivity::Protected, Instant::now());
        assert!(rx.try_recv().is_err());
        CAPTURE_STATE.with(|slot| *slot.borrow_mut() = Some(state));
        let _guard = CaptureThreadStateGuard;

        assert!(request_sensitive_context_reconcile()
            .recv_timeout(Duration::from_secs(1))
            .expect("same-thread reconciliation reply")
            .is_some());
        assert!(matches!(
            rx.recv().expect("first reconciliation row").payload,
            EventPayload::SensitiveContextExited {
                reason: SensitiveContextReason::SessionLocked
            }
        ));
        for _ in 0..4 {
            rx.recv().expect("remaining direct reconciliation row");
        }

        let worker = std::thread::spawn(|| {
            request_sensitive_context_reconcile()
                .recv_timeout(Duration::from_secs(1))
                .expect("worker reconciliation reply")
        });
        std::thread::sleep(Duration::from_millis(10));
        check_requested_reseed();
        assert!(worker.join().expect("worker joins").is_some());
    }

    #[test]
    fn foreground_state_continues_while_stream_is_disabled() {
        let controls = CaptureControls::all_enabled();
        let (tx, rx) = crossbeam_channel::bounded(4);
        let mut state = CaptureState::new(tx, controls.clone());
        let base = Instant::now();

        let first = state
            .foreground
            .seed_window_at(window(1, "A"), base)
            .expect("seed event");
        state.send(first, "foreground");

        controls.set_enabled(CaptureStream::Foreground, false);
        let disabled_switch = state
            .foreground
            .on_window_at(window(2, "B"), base + Duration::from_millis(1))
            .expect("disabled switch still updates state");
        state.send(disabled_switch, "foreground");

        controls.set_enabled(CaptureStream::Foreground, true);
        let reenabled_switch = state
            .foreground
            .on_window_at(window(1, "A"), base + Duration::from_millis(30))
            .expect("reenabled switch");
        state.send(reenabled_switch, "foreground");

        let _seed = rx.try_recv().expect("seed enqueued");
        let captured = rx.try_recv().expect("reenabled switch enqueued");
        assert!(rx.try_recv().is_err());
        match captured.payload {
            EventPayload::FocusChanged {
                prev,
                previous_focused_for_ms,
                window_unfocused_for_ms,
                ..
            } => {
                assert_eq!(prev.expect("previous window").title, "B");
                assert_eq!(previous_focused_for_ms, 29);
                assert_eq!(window_unfocused_for_ms, 29);
            }
            _ => panic!("expected focus event"),
        }
    }

    #[test]
    fn keyboard_modifiers_continue_while_stream_is_disabled() {
        let controls = CaptureControls::all_enabled();
        controls.set_enabled(CaptureStream::Keyboard, false);
        let (tx, rx) = crossbeam_channel::bounded(4);
        let mut state = CaptureState::new(tx, controls.clone());
        let base = Instant::now();

        if let Some(captured) = state.keyboard.on_raw_key(
            RawKeyboardEvent {
                vkey: 0x10,
                flags: 0,
            },
            None,
            base,
        ) {
            state.send(captured, "keyboard");
        }

        controls.set_enabled(CaptureStream::Keyboard, true);
        let captured = state
            .keyboard
            .on_raw_key(
                RawKeyboardEvent {
                    vkey: 0x41,
                    flags: 0,
                },
                None,
                base + Duration::from_millis(1),
            )
            .expect("A key event");
        state.send(captured, "keyboard");

        let captured = rx.try_recv().expect("reenabled key enqueued");
        assert!(rx.try_recv().is_err());
        match captured.payload {
            EventPayload::Key { key, mods, .. } => {
                assert_eq!(key, "A");
                assert!(mods.shift);
            }
            _ => panic!("expected key event"),
        }
    }

    #[test]
    fn mouse_position_continues_while_stream_is_disabled() {
        let controls = CaptureControls::all_enabled();
        controls.set_enabled(CaptureStream::Mouse, false);
        let (tx, rx) = crossbeam_channel::bounded(4);
        let mut state = CaptureState::new(tx, controls.clone());
        let base = Instant::now();

        for captured in state.mouse.on_raw_mouse(
            RawMouseEvent {
                flags: MOUSE_MOVE_ABSOLUTE.0,
                button_flags: 0,
                button_data: 0,
                last_x: 40_000,
                last_y: 40_000,
            },
            None,
            Some(MousePosition { x: 100, y: 100 }),
            base,
        ) {
            state.send(captured, "mouse");
        }

        controls.set_enabled(CaptureStream::Mouse, true);
        for captured in state.mouse.on_raw_mouse(
            RawMouseEvent {
                flags: MOUSE_MOVE_ABSOLUTE.0,
                button_flags: 0,
                button_data: 0,
                last_x: 60_000,
                last_y: 10_000,
            },
            None,
            Some(MousePosition { x: 110, y: 95 }),
            base + MOUSE_MOVE_FLUSH_INTERVAL,
        ) {
            state.send(captured, "mouse");
        }

        let captured = rx.try_recv().expect("reenabled mouse move enqueued");
        match captured.payload {
            EventPayload::MouseMove {
                dx_total,
                dy_total,
                distance_px,
                raw_event_count,
                ..
            } => {
                assert_eq!(dx_total, 10);
                assert_eq!(dy_total, -5);
                assert_eq!(distance_px, 11);
                assert_eq!(raw_event_count, 2);
            }
            _ => panic!("expected mouse move"),
        }
    }

    #[test]
    fn idle_stream_events_are_not_blocked_by_keyboard_toggle() {
        let controls = CaptureControls::all_enabled();
        controls.set_enabled(CaptureStream::Keyboard, false);
        let (tx, rx) = crossbeam_channel::bounded(4);
        let mut state = CaptureState::new(tx, controls);
        let base = Instant::now();

        let idle = state.idle.on_sample_at(300_000, base).expect("idle event");
        state.send(idle, "system");
        let active = state
            .idle
            .on_activity_at(10, base + Duration::from_millis(1))
            .expect("active event");
        state.send(active, "system");

        assert!(matches!(
            rx.try_recv().expect("idle enqueued").payload,
            EventPayload::Idle { .. }
        ));
        assert!(matches!(
            rx.try_recv().expect("active enqueued").payload,
            EventPayload::Active { .. }
        ));
    }

    #[test]
    fn capture_shutdown_flushes_current_foreground_dwell() {
        let (tx, rx) = crossbeam_channel::bounded(4);
        let mut state = CaptureState::new(tx, CaptureControls::all_enabled());
        let base = Instant::now();
        // Open the segment through the hoisted state's API (the seed row is
        // deliberately not sent — this test is about the shutdown flush).
        let _seed = state.foreground.seed_window_at(window(1, "A"), base);

        state.flush_shutdown_events(base + Duration::from_millis(55));

        let captured = rx.try_recv().expect("foreground dwell enqueued");
        assert!(rx.try_recv().is_err());
        match captured.payload {
            EventPayload::FocusChanged {
                window,
                prev,
                previous_focused_for_ms,
                ..
            } => {
                assert_eq!(window.title, "A");
                assert_eq!(prev.expect("previous window").title, "A");
                assert_eq!(previous_focused_for_ms, 55);
            }
            _ => panic!("expected focus event"),
        }
    }

    #[test]
    fn resume_without_suspend_caps_foreground_dwell_and_reseeds() {
        let controls = CaptureControls::all_enabled();
        let diagnostics = controls.diagnostics();
        let (tx, rx) = crossbeam_channel::bounded(8);
        let mut state = CaptureState::new(tx, controls);
        let base = Instant::now();
        let current = window(1, "A");

        state.seed_foreground_window_at(current.clone(), base);
        rx.try_recv().expect("seed event");

        state.on_power_resume_at(
            base + Duration::from_secs(9 * 60 * 60),
            Some(50_000),
            Some(current),
        );

        let boundary = rx.try_recv().expect("capped boundary event");
        let reseed = rx.try_recv().expect("resume reseed event");
        let resume = rx.try_recv().expect("resume power event");
        assert!(rx.try_recv().is_err());
        assert_eq!(diagnostics.power_boundary_catches(), 0);

        match &boundary.payload {
            EventPayload::FocusChanged {
                prev,
                previous_focused_for_ms,
                ..
            } => {
                assert!(prev.is_some());
                assert_eq!(
                    *previous_focused_for_ms,
                    duration_ms(MISSED_POWER_BOUNDARY_MAX_DWELL)
                );
            }
            _ => panic!("expected focus event"),
        }
        match &reseed.payload {
            EventPayload::FocusChanged {
                prev,
                previous_focused_for_ms,
                ..
            } => {
                assert!(prev.is_none());
                assert_eq!(*previous_focused_for_ms, 0);
            }
            _ => panic!("expected focus event"),
        }
        match &resume.payload {
            EventPayload::PowerResume {
                tick_ms,
                matched_suspend,
            } => {
                assert_eq!(*tick_ms, Some(50_000));
                assert!(!matched_suspend);
            }
            _ => panic!("expected power resume event"),
        }
    }

    #[test]
    fn power_resume_reseeds_power_status() {
        let controls = CaptureControls::all_enabled();
        let (tx, rx) = crossbeam_channel::bounded(8);
        let mut state = CaptureState::new(tx, controls);
        let base = Instant::now();
        state.last_power_status = Some((Some(true), Some(false), Some(8)));
        let on_battery = SYSTEM_POWER_STATUS {
            ACLineStatus: 0,
            BatteryLifePercent: 75,
            SystemStatusFlag: 0,
            ..Default::default()
        };

        state.on_power_resume_with_status_sample_at(
            base + Duration::from_secs(60),
            Some(50_000),
            None,
            &on_battery,
        );

        let resume = rx.try_recv().expect("resume power event");
        let status = rx.try_recv().expect("power status reseed event");
        assert!(rx.try_recv().is_err());

        assert!(matches!(
            resume.payload,
            EventPayload::PowerResume {
                tick_ms: Some(50_000),
                matched_suspend: false,
            }
        ));
        match &status.payload {
            EventPayload::PowerStatusChanged {
                ac_online,
                battery_percent,
                battery_saver,
            } => {
                assert_eq!(*ac_online, Some(false));
                assert_eq!(*battery_percent, Some(75));
                assert_eq!(*battery_saver, Some(false));
            }
            _ => panic!("expected power status event"),
        }
    }

    #[test]
    fn unmatched_resume_with_timer_gap_emits_recovered_boundary() {
        let controls = CaptureControls::all_enabled();
        let diagnostics = controls.diagnostics();
        let (tx, rx) = crossbeam_channel::bounded(8);
        let mut state = CaptureState::new(tx, controls);
        let base = Instant::now();
        let current = window(1, "A");
        let wake_tick = 1_000 + MISSED_POWER_BOUNDARY_THRESHOLD_MS + 1;

        state.seed_foreground_window_at(current.clone(), base);
        rx.try_recv().expect("seed event");
        state.last_timer_tick_ms = Some(1_000);

        state.on_power_resume_at(
            base + Duration::from_secs(9 * 60 * 60),
            Some(wake_tick),
            Some(current.clone()),
        );

        let boundary = rx.try_recv().expect("capped boundary event");
        let reseed = rx.try_recv().expect("resume reseed event");
        let status = rx.try_recv().expect("power status reseed event");
        let recovered = rx.try_recv().expect("power recovery event");
        let resume = rx.try_recv().expect("resume power event");
        assert!(rx.try_recv().is_err());
        assert_eq!(diagnostics.power_boundary_catches(), 1);

        match &boundary.payload {
            EventPayload::FocusChanged {
                prev,
                previous_focused_for_ms,
                ..
            } => {
                assert!(prev.is_some());
                assert_eq!(
                    *previous_focused_for_ms,
                    duration_ms(MISSED_POWER_BOUNDARY_MAX_DWELL)
                );
            }
            _ => panic!("expected focus event"),
        }
        assert!(matches!(
            reseed.payload,
            EventPayload::FocusChanged { prev: None, .. }
        ));
        assert!(matches!(
            status.payload,
            EventPayload::PowerStatusChanged { .. }
        ));
        match &recovered.payload {
            EventPayload::PowerBoundaryRecovered {
                gap_ms,
                capped_dwell_ms,
            } => {
                assert_eq!(*gap_ms, MISSED_POWER_BOUNDARY_THRESHOLD_MS + 1);
                assert_eq!(
                    *capped_dwell_ms,
                    duration_ms(MISSED_POWER_BOUNDARY_MAX_DWELL)
                );
            }
            _ => panic!("expected power recovery event"),
        }
        assert!(matches!(
            resume.payload,
            EventPayload::PowerResume {
                tick_ms: Some(value),
                matched_suspend: false,
            } if value == wake_tick
        ));

        state.on_power_resume_at(
            base + Duration::from_secs(9 * 60 * 60) + Duration::from_millis(100),
            Some(wake_tick + 100),
            Some(current),
        );
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn paired_suspend_resume_emits_real_dwell_then_reseeds_without_second_boundary() {
        let controls = CaptureControls::all_enabled();
        let (tx, rx) = crossbeam_channel::bounded(8);
        let mut state = CaptureState::new(tx, controls);
        let base = Instant::now();
        let current = window(1, "A");

        state.seed_foreground_window_at(current.clone(), base);
        rx.try_recv().expect("seed event");

        state.on_power_suspend_at(base + Duration::from_secs(90), Some(1_000));
        let suspend_boundary = rx.try_recv().expect("suspend boundary event");
        let suspend = rx.try_recv().expect("suspend power event");
        assert!(rx.try_recv().is_err());

        state.on_power_resume_at(
            base + Duration::from_secs(9 * 60 * 60),
            Some(1_000 + MISSED_POWER_BOUNDARY_THRESHOLD_MS + 1),
            Some(current),
        );
        let resume_seed = rx.try_recv().expect("resume seed event");
        let resume = rx.try_recv().expect("resume power event");
        assert!(rx.try_recv().is_err());

        match &suspend_boundary.payload {
            EventPayload::FocusChanged {
                prev,
                previous_focused_for_ms,
                ..
            } => {
                assert!(prev.is_some());
                assert_eq!(*previous_focused_for_ms, 90_000);
            }
            _ => panic!("expected focus event"),
        }
        match &suspend.payload {
            EventPayload::PowerSuspend { tick_ms } => assert_eq!(*tick_ms, Some(1_000)),
            _ => panic!("expected power suspend event"),
        }
        match &resume_seed.payload {
            EventPayload::FocusChanged {
                prev,
                previous_focused_for_ms,
                ..
            } => {
                assert!(prev.is_none());
                assert_eq!(*previous_focused_for_ms, 0);
            }
            _ => panic!("expected focus event"),
        }
        match &resume.payload {
            EventPayload::PowerResume {
                tick_ms,
                matched_suspend,
            } => {
                assert_eq!(
                    *tick_ms,
                    Some(1_000 + MISSED_POWER_BOUNDARY_THRESHOLD_MS + 1)
                );
                assert!(matched_suspend);
            }
            _ => panic!("expected power resume event"),
        }
    }

    #[test]
    fn duplicate_resume_after_suspend_is_debounced() {
        let controls = CaptureControls::all_enabled();
        let diagnostics = controls.diagnostics();
        let (tx, rx) = crossbeam_channel::bounded(8);
        let mut state = CaptureState::new(tx, controls);
        let base = Instant::now();
        let current = window(1, "A");

        state.seed_foreground_window_at(current.clone(), base);
        rx.try_recv().expect("seed event");

        state.on_power_suspend_at(base + Duration::from_secs(90), Some(1_000));
        rx.try_recv().expect("suspend boundary event");
        rx.try_recv().expect("suspend power event");
        assert!(rx.try_recv().is_err());

        state.on_power_resume_at(
            base + Duration::from_secs(9 * 60 * 60),
            Some(2_000),
            Some(current.clone()),
        );
        let resume_seed = rx.try_recv().expect("resume seed event");
        let resume = rx.try_recv().expect("resume power event");
        assert!(rx.try_recv().is_err());

        state.on_power_resume_at(
            base + Duration::from_secs(9 * 60 * 60) + Duration::from_millis(100),
            Some(2_100),
            Some(current),
        );
        assert!(rx.try_recv().is_err());
        assert_eq!(diagnostics.power_boundary_catches(), 0);
        assert!(!state.power_suspended);

        assert!(matches!(
            resume_seed.payload,
            EventPayload::FocusChanged { prev: None, .. }
        ));
        assert!(matches!(
            resume.payload,
            EventPayload::PowerResume {
                matched_suspend: true,
                ..
            }
        ));
    }

    #[test]
    fn session_lock_unlock_closes_and_reseeds_foreground() {
        let controls = CaptureControls::all_enabled();
        let (tx, rx) = crossbeam_channel::bounded(8);
        let mut state = CaptureState::new(tx, controls);
        let base = Instant::now();
        let current = window(1, "A");

        state.seed_foreground_window_at(current.clone(), base);
        rx.try_recv().expect("seed event");

        state.on_session_change_at(WTS_SESSION_LOCK, 42, base + Duration::from_secs(75), None);
        let lock_boundary = rx.try_recv().expect("lock boundary event");
        let lock = rx.try_recv().expect("session lock event");
        let sensitive_entered = rx.try_recv().expect("sensitive context entered");
        assert!(rx.try_recv().is_err());

        state.on_session_change_at(
            WTS_SESSION_UNLOCK,
            42,
            base + Duration::from_secs(90),
            Some(current),
        );
        let sensitive_exited = rx.try_recv().expect("sensitive context exited");
        let unlock_seed = rx.try_recv().expect("unlock seed event");
        let unlock = rx.try_recv().expect("session unlock event");
        assert!(rx.try_recv().is_err());

        match &lock_boundary.payload {
            EventPayload::FocusChanged {
                prev,
                previous_focused_for_ms,
                ..
            } => {
                assert!(prev.is_some());
                assert_eq!(*previous_focused_for_ms, 75_000);
            }
            _ => panic!("expected focus boundary"),
        }
        assert!(matches!(
            lock.payload,
            EventPayload::SessionLock { session_id: 42 }
        ));
        assert!(matches!(
            sensitive_entered.payload,
            EventPayload::SensitiveContextEntered {
                reason: SensitiveContextReason::SessionLocked
            }
        ));
        assert!(matches!(
            sensitive_exited.payload,
            EventPayload::SensitiveContextExited {
                reason: SensitiveContextReason::SessionLocked
            }
        ));
        assert!(matches!(
            unlock_seed.payload,
            EventPayload::FocusChanged { prev: None, .. }
        ));
        assert!(matches!(
            unlock.payload,
            EventPayload::SessionUnlock { session_id: 42 }
        ));
    }

    #[test]
    fn session_connect_disconnect_emits_connection_kind() {
        let controls = CaptureControls::all_enabled();
        let (tx, rx) = crossbeam_channel::bounded(8);
        let mut state = CaptureState::new(tx, controls);
        let base = Instant::now();
        let current = window(1, "A");

        state.seed_foreground_window_at(current.clone(), base);
        rx.try_recv().expect("seed event");

        state.on_session_change_at(
            WTS_REMOTE_DISCONNECT,
            7,
            base + Duration::from_secs(10),
            None,
        );
        let disconnect_boundary = rx.try_recv().expect("disconnect boundary event");
        let disconnect = rx.try_recv().expect("session disconnect event");
        let sensitive_entered = rx.try_recv().expect("sensitive context entered");
        assert!(rx.try_recv().is_err());

        state.on_session_change_at(
            WTS_REMOTE_CONNECT,
            7,
            base + Duration::from_secs(20),
            Some(current),
        );
        let sensitive_exited = rx.try_recv().expect("sensitive context exited");
        let connect_seed = rx.try_recv().expect("connect seed event");
        let connect = rx.try_recv().expect("session connect event");
        assert!(rx.try_recv().is_err());

        assert!(matches!(
            disconnect_boundary.payload,
            EventPayload::FocusChanged { prev: Some(_), .. }
        ));
        assert!(matches!(
            disconnect.payload,
            EventPayload::SessionDisconnect {
                session_id: 7,
                connection: SessionConnectionKind::Remote
            }
        ));
        assert!(matches!(
            sensitive_entered.payload,
            EventPayload::SensitiveContextEntered {
                reason: SensitiveContextReason::SessionDisconnected
            }
        ));
        assert!(matches!(
            sensitive_exited.payload,
            EventPayload::SensitiveContextExited {
                reason: SensitiveContextReason::SessionDisconnected
            }
        ));
        assert!(matches!(
            connect_seed.payload,
            EventPayload::FocusChanged { prev: None, .. }
        ));
        assert!(matches!(
            connect.payload,
            EventPayload::SessionConnect {
                session_id: 7,
                connection: SessionConnectionKind::Remote
            }
        ));
    }

    #[test]
    fn input_desktop_classifier_treats_only_default_as_normal() {
        assert_eq!(
            input_desktop_sensitivity_from_name(Some("Default")),
            InputDesktopSensitivity::Normal
        );
        assert_eq!(
            input_desktop_sensitivity_from_name(Some(" default ")),
            InputDesktopSensitivity::Normal
        );
        assert_eq!(
            input_desktop_sensitivity_from_name(Some("Winlogon")),
            InputDesktopSensitivity::Protected
        );
        assert_eq!(
            input_desktop_sensitivity_from_name(None),
            InputDesktopSensitivity::Protected
        );
    }

    #[test]
    fn input_desktop_sampling_ignores_runtime_system_toggle_for_policy_sync() {
        let controls = CaptureControls::all_enabled();
        let (tx, _rx) = crossbeam_channel::bounded(1);
        let state = CaptureState::new_with_system_capture(tx, controls.clone(), true);
        assert!(state.should_sample_input_desktop());

        controls.set_enabled(CaptureStream::System, false);
        assert!(state.should_sample_input_desktop());

        let (tx, _rx) = crossbeam_channel::bounded(1);
        let idle_only_state =
            CaptureState::new_with_system_capture(tx, CaptureControls::all_enabled(), false);
        assert!(!idle_only_state.should_sample_input_desktop());
    }

    #[test]
    fn secure_desktop_sample_emits_sensitive_context_boundaries() {
        let controls = CaptureControls::all_enabled();
        let (tx, rx) = crossbeam_channel::bounded(4);
        let mut state = CaptureState::new(tx, controls);
        let base = Instant::now();

        state.on_input_desktop_sample_at(InputDesktopSensitivity::Protected, base);
        let entered = rx.try_recv().expect("secure desktop entered");
        assert!(rx.try_recv().is_err());

        state.on_input_desktop_sample_at(
            InputDesktopSensitivity::Protected,
            base + Duration::from_secs(1),
        );
        assert!(rx.try_recv().is_err());

        state.on_input_desktop_sample_at(
            InputDesktopSensitivity::Normal,
            base + Duration::from_secs(2),
        );
        let exited = rx.try_recv().expect("secure desktop exited");
        assert!(rx.try_recv().is_err());

        assert!(matches!(
            entered.payload,
            EventPayload::SensitiveContextEntered {
                reason: SensitiveContextReason::SecureDesktop
            }
        ));
        assert!(matches!(
            exited.payload,
            EventPayload::SensitiveContextExited {
                reason: SensitiveContextReason::SecureDesktop
            }
        ));
    }

    #[test]
    fn sensitive_context_boundaries_bypass_runtime_system_toggle_for_policy_sync() {
        let controls = CaptureControls::all_enabled();
        controls.set_enabled(CaptureStream::System, false);
        let (tx, rx) = crossbeam_channel::bounded(4);
        let mut state = CaptureState::new(tx, controls);
        let base = Instant::now();

        state.on_input_desktop_sample_at(InputDesktopSensitivity::Protected, base);
        let entered = rx.try_recv().expect("secure desktop entered");
        state.on_input_desktop_sample_at(
            InputDesktopSensitivity::Normal,
            base + Duration::from_secs(1),
        );
        let exited = rx.try_recv().expect("secure desktop exited");
        assert!(rx.try_recv().is_err());

        assert!(matches!(
            entered.payload,
            EventPayload::SensitiveContextEntered {
                reason: SensitiveContextReason::SecureDesktop
            }
        ));
        assert!(matches!(
            exited.payload,
            EventPayload::SensitiveContextExited {
                reason: SensitiveContextReason::SecureDesktop
            }
        ));
    }

    #[test]
    fn panic_pause_suppresses_sensitive_boundaries_and_reconciles_before_reseed_rows() {
        let controls = CaptureControls::all_enabled();
        controls.set_suspended(true);
        let (tx, rx) = crossbeam_channel::bounded(16);
        let mut state = CaptureState::new(tx.clone(), controls.clone());
        let diagnostics = controls.diagnostics();
        let active = controls.password_field_active_flag();
        let confirmed_active = controls.password_field_confirmed_active_flag();
        let base = Instant::now();

        state.on_input_desktop_sample_at(InputDesktopSensitivity::Protected, base);
        emit_confirmed_password_field_sample(
            &tx,
            &controls,
            &diagnostics,
            &active,
            &confirmed_active,
            true,
            base + Duration::from_millis(1),
        );
        assert!(rx.try_recv().is_err(), "pause stores no context timestamps");

        controls.set_suspended(false);
        state.reseed_after_reset_with_at(
            base + Duration::from_secs(1),
            None,
            Vec::new(),
            system_info_payload(),
            screen(0, 0, 1920, 1080),
            ReseedAfterResetOptions::default(),
        );

        let boundaries = (0..6)
            .map(|_| rx.try_recv().expect("reconciliation boundary").payload)
            .collect::<Vec<_>>();
        assert!(matches!(
            boundaries[0],
            EventPayload::SensitiveContextExited {
                reason: SensitiveContextReason::SessionLocked
            }
        ));
        assert!(matches!(
            boundaries[2],
            EventPayload::SensitiveContextExited {
                reason: SensitiveContextReason::SecureDesktop
            }
        ));
        assert!(matches!(
            boundaries[4],
            EventPayload::SensitiveContextEntered {
                reason: SensitiveContextReason::SecureDesktop
            }
        ));
        assert!(matches!(
            boundaries[5],
            EventPayload::SensitiveContextEntered {
                reason: SensitiveContextReason::PasswordField
            }
        ));
        assert!(matches!(
            rx.try_recv().expect("system-info reseed").payload,
            EventPayload::SystemInfo { .. }
        ));
        assert!(matches!(
            rx.try_recv().expect("virtual-screen reseed").payload,
            EventPayload::VirtualScreen { .. }
        ));
    }

    #[test]
    fn password_field_sample_emits_sensitive_context_boundaries() {
        let (tx, rx) = crossbeam_channel::bounded(4);
        let controls = CaptureControls::all_enabled();
        let diagnostics = DiagnosticsCounters::new();
        let active = Arc::new(AtomicBool::new(false));
        let confirmed_active = Arc::new(AtomicBool::new(false));
        let base = Instant::now();

        emit_confirmed_password_field_sample(
            &tx,
            &controls,
            &diagnostics,
            &active,
            &confirmed_active,
            true,
            base,
        );
        let entered = rx.try_recv().expect("password context entered");
        assert!(rx.try_recv().is_err());

        emit_confirmed_password_field_sample(
            &tx,
            &controls,
            &diagnostics,
            &active,
            &confirmed_active,
            true,
            base + Duration::from_millis(1),
        );
        assert!(rx.try_recv().is_err());

        emit_confirmed_password_field_sample(
            &tx,
            &controls,
            &diagnostics,
            &active,
            &confirmed_active,
            false,
            base + Duration::from_millis(2),
        );
        let exited = rx.try_recv().expect("password context exited");
        assert!(rx.try_recv().is_err());

        assert!(matches!(
            entered.payload,
            EventPayload::SensitiveContextEntered {
                reason: SensitiveContextReason::PasswordField
            }
        ));
        assert!(matches!(
            exited.payload,
            EventPayload::SensitiveContextExited {
                reason: SensitiveContextReason::PasswordField
            }
        ));
    }

    #[test]
    fn password_field_sample_does_not_depend_on_stream_gate_for_policy_sync() {
        let (tx, rx) = crossbeam_channel::bounded(4);
        let controls = CaptureControls::all_enabled();
        let diagnostics = DiagnosticsCounters::new();
        let active = Arc::new(AtomicBool::new(false));
        let confirmed_active = Arc::new(AtomicBool::new(false));

        emit_confirmed_password_field_sample(
            &tx,
            &controls,
            &diagnostics,
            &active,
            &confirmed_active,
            true,
            Instant::now(),
        );

        assert!(matches!(
            rx.try_recv().expect("password context entered").payload,
            EventPayload::SensitiveContextEntered {
                reason: SensitiveContextReason::PasswordField
            }
        ));
    }

    #[test]
    fn password_field_sample_timeout_rolls_back_confirmed_state_for_retry() {
        let (blocked_tx, _blocked_rx) = crossbeam_channel::bounded(0);
        let controls = CaptureControls::all_enabled();
        let diagnostics = DiagnosticsCounters::new();
        let active = Arc::new(AtomicBool::new(false));
        let confirmed_active = Arc::new(AtomicBool::new(false));
        let base = Instant::now();

        emit_confirmed_password_field_sample(
            &blocked_tx,
            &controls,
            &diagnostics,
            &active,
            &confirmed_active,
            true,
            base,
        );

        assert!(!active.load(Ordering::SeqCst));
        assert!(!confirmed_active.load(Ordering::SeqCst));
        assert_eq!(diagnostics.capture_events_dropped(), 1);

        let (tx, rx) = crossbeam_channel::bounded(1);
        emit_confirmed_password_field_sample(
            &tx,
            &controls,
            &diagnostics,
            &active,
            &confirmed_active,
            true,
            base + Duration::from_millis(1),
        );

        assert!(active.load(Ordering::SeqCst));
        assert!(confirmed_active.load(Ordering::SeqCst));
        assert!(matches!(
            rx.try_recv().expect("password context entered").payload,
            EventPayload::SensitiveContextEntered {
                reason: SensitiveContextReason::PasswordField
            }
        ));
    }

    #[test]
    fn unresolved_password_focus_gate_does_not_emit_audit_rows_for_non_password_focus() {
        let controls = CaptureControls::new(CaptureSettings {
            foreground: false,
            windows: false,
            keyboard: true,
            mouse: false,
            system: false,
            idle: false,
            idle_threshold_ms: DEFAULT_IDLE_THRESHOLD_MS,
            process_filter: true,
        });
        let (tx, rx) = crossbeam_channel::bounded(4);
        let mut state = CaptureState::new_with_system_capture(tx, controls, false);

        state.protect_unknown_password_focus();
        assert!(state.controls.password_field_active());
        assert!(rx.try_recv().is_err());

        emit_confirmed_password_field_sample(
            &state.tx,
            &state.controls,
            &state.controls.diagnostics(),
            &state.controls.password_field_active_flag(),
            &state.controls.password_field_confirmed_active_flag(),
            false,
            Instant::now(),
        );

        assert!(!state.controls.password_field_active());
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn sensitive_field_monitor_runs_for_keyboard_without_system_stream() {
        assert!(sensitive_field_monitor_required(true, false));
        assert!(sensitive_field_monitor_required(false, true));
        assert!(!sensitive_field_monitor_required(false, false));
    }

    #[test]
    fn key_capture_fails_closed_when_password_probe_is_unavailable() {
        let (tx, rx) = crossbeam_channel::bounded(4);
        let controls = CaptureControls::new(CaptureSettings {
            foreground: false,
            windows: false,
            keyboard: true,
            mouse: false,
            system: false,
            idle: false,
            idle_threshold_ms: DEFAULT_IDLE_THRESHOLD_MS,
            process_filter: true,
        });
        let mut state = CaptureState::new_with_system_capture(tx, controls, false);
        let base = Instant::now();

        state.keyboard.mods.shift = true;
        let current_window = window(7, "Password Dialog");
        let redact_key = state.redact_keyboard_for_password_field_at(Some(&current_window), base);
        let captured = state
            .keyboard
            .on_raw_key_with_capture_redaction(
                RawKeyboardEvent {
                    vkey: 0x41,
                    flags: 0,
                },
                Some(current_window),
                base,
                redact_key,
            )
            .expect("key press emitted");
        state.send(captured, "keyboard");

        assert!(redact_key);
        match rx.try_recv().expect("redacted key").payload {
            EventPayload::Key {
                key, mods, window, ..
            } => {
                assert_eq!(key, "<redacted>");
                assert_eq!(window.expect("window").title, "<redacted>");
                assert_eq!(mods, Modifiers::default());
            }
            _ => panic!("expected key event"),
        }
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn key_capture_times_out_and_fails_closed_without_audit_boundary() {
        let (tx, rx) = crossbeam_channel::bounded(4);
        let controls = CaptureControls::new(CaptureSettings {
            foreground: false,
            windows: false,
            keyboard: true,
            mouse: false,
            system: false,
            idle: false,
            idle_threshold_ms: DEFAULT_IDLE_THRESHOLD_MS,
            process_filter: true,
        });
        let (probe_tx, _probe_rx) = crossbeam_channel::bounded(1);
        controls.set_sensitive_field_probe(Some(probe_tx));
        let mut state = CaptureState::new_with_system_capture(tx, controls, false);
        let base = Instant::now();
        let current_window = window(7, "Password Dialog");

        let started = Instant::now();
        let redact_key = state.redact_keyboard_for_password_field_at(Some(&current_window), base);
        assert!(
            started.elapsed()
                >= PASSWORD_FIELD_PROBE_TIMEOUT.saturating_sub(Duration::from_millis(10))
        );

        assert!(redact_key);
        assert!(state.controls.password_field_active());
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn provisional_password_gate_probes_and_clears_for_non_password_focus() {
        let (tx, rx) = crossbeam_channel::bounded(4);
        let controls = CaptureControls::new(CaptureSettings {
            foreground: false,
            windows: false,
            keyboard: true,
            mouse: false,
            system: false,
            idle: false,
            idle_threshold_ms: DEFAULT_IDLE_THRESHOLD_MS,
            process_filter: true,
        });
        let (probe_tx, probe_rx) = crossbeam_channel::bounded(1);
        controls.set_sensitive_field_probe(Some(probe_tx));
        let focus_generation = controls.password_focus_generation();
        let responder = thread::spawn(move || {
            let request = probe_rx.recv().expect("probe request");
            request
                .reply
                .send(Some(SensitiveFieldProbeResult {
                    is_password: false,
                    focus_generation,
                }))
                .expect("probe reply sent");
        });
        let mut state = CaptureState::new_with_system_capture(tx, controls, false);
        let base = Instant::now();
        let current_window = window(7, "Editor");

        state.protect_unknown_password_focus();
        assert!(state.controls.password_field_active());
        let redact_key = state.redact_keyboard_for_password_field_at(Some(&current_window), base);
        responder.join().expect("probe responder joins");

        assert!(!redact_key);
        assert!(!state.controls.password_field_active());
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn password_probe_fails_closed_if_focus_generation_changes_during_read() {
        let focus_generation = AtomicU64::new(17);

        let result = probe_focused_password_field_with(&focus_generation, || {
            focus_generation.fetch_add(1, Ordering::SeqCst);
            Some(false)
        });

        assert_eq!(result, None);
        assert_eq!(focus_generation.load(Ordering::SeqCst), 18);
    }

    #[test]
    fn password_probe_tags_answer_with_generation_before_read() {
        let focus_generation = AtomicU64::new(17);

        let result = probe_focused_password_field_with(&focus_generation, || Some(false));

        assert_eq!(
            result,
            Some(SensitiveFieldProbeResult {
                is_password: false,
                focus_generation: 17,
            })
        );
    }

    #[test]
    fn keyboard_path_redacts_when_focus_generation_changes_during_probe() {
        let (tx, rx) = crossbeam_channel::bounded(4);
        let controls = CaptureControls::new(CaptureSettings {
            foreground: false,
            windows: false,
            keyboard: true,
            mouse: false,
            system: false,
            idle: false,
            idle_threshold_ms: DEFAULT_IDLE_THRESHOLD_MS,
            process_filter: true,
        });
        let (probe_tx, probe_rx) = crossbeam_channel::bounded(1);
        controls.set_sensitive_field_probe(Some(probe_tx));
        let responder_controls = controls.clone();
        let responder = thread::spawn(move || {
            let request = probe_rx.recv().expect("keyboard path probe request");
            let result = probe_focused_password_field_with(
                &responder_controls.password_focus_generation_counter(),
                || {
                    responder_controls.mark_password_focus_changed();
                    Some(false)
                },
            );
            request.reply.send(result).expect("probe reply sent");
        });
        let mut state = CaptureState::new_with_system_capture(tx, controls, false);
        let current_window = window(7, "Login Form");

        state.on_raw_keyboard_at(
            RawKeyboardEvent {
                vkey: 0x41,
                flags: 0,
            },
            Some(current_window),
            Instant::now(),
        );
        responder.join().expect("probe responder joins");

        match rx.try_recv().expect("raced probe redacts key").payload {
            EventPayload::Key {
                key, mods, window, ..
            } => {
                assert_eq!(key, "<redacted>");
                assert_eq!(mods, Modifiers::default());
                assert_eq!(window.expect("window").title, "<redacted>");
            }
            _ => panic!("expected redacted key event"),
        }
        assert!(state.controls.password_field_active());
        assert!(state.password_focus_cache.is_none());
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn key_capture_uses_probe_result_before_building_key_row() {
        let (tx, rx) = crossbeam_channel::bounded(4);
        let controls = CaptureControls::new(CaptureSettings {
            foreground: false,
            windows: false,
            keyboard: true,
            mouse: false,
            system: false,
            idle: false,
            idle_threshold_ms: DEFAULT_IDLE_THRESHOLD_MS,
            process_filter: true,
        });
        let (probe_tx, probe_rx) = crossbeam_channel::bounded(1);
        controls.set_sensitive_field_probe(Some(probe_tx));
        let focus_generation = controls.password_focus_generation();
        let responder = thread::spawn(move || {
            let request = probe_rx.recv().expect("probe request");
            request
                .reply
                .send(Some(SensitiveFieldProbeResult {
                    is_password: true,
                    focus_generation,
                }))
                .expect("probe reply sent");
        });
        let mut state = CaptureState::new_with_system_capture(tx, controls, false);
        let base = Instant::now();
        let current_window = window(7, "Password Dialog");

        let redact_key = state.redact_keyboard_for_password_field_at(Some(&current_window), base);
        responder.join().expect("probe responder joins");
        let captured = state
            .keyboard
            .on_raw_key_with_capture_redaction(
                RawKeyboardEvent {
                    vkey: 0x41,
                    flags: 0,
                },
                Some(current_window),
                base,
                redact_key,
            )
            .expect("key press emitted");
        state.send(captured, "keyboard");

        assert!(redact_key);
        assert!(matches!(
            rx.try_recv().expect("password context entered").payload,
            EventPayload::SensitiveContextEntered {
                reason: SensitiveContextReason::PasswordField
            }
        ));
        match rx
            .try_recv()
            .expect("redacted key follows boundary")
            .payload
        {
            EventPayload::Key { key, .. } => assert_eq!(key, "<redacted>"),
            _ => panic!("expected key event"),
        }
    }

    #[test]
    fn key_capture_reuses_recent_non_password_probe_for_same_window() {
        let (tx, rx) = crossbeam_channel::bounded(4);
        let controls = CaptureControls::new(CaptureSettings {
            foreground: false,
            windows: false,
            keyboard: true,
            mouse: false,
            system: false,
            idle: false,
            idle_threshold_ms: DEFAULT_IDLE_THRESHOLD_MS,
            process_filter: true,
        });
        let (probe_tx, probe_rx) = crossbeam_channel::bounded(1);
        controls.set_sensitive_field_probe(Some(probe_tx));
        let focus_generation = controls.password_focus_generation();
        let responder = thread::spawn(move || {
            let request = probe_rx.recv().expect("first probe request");
            request
                .reply
                .send(Some(SensitiveFieldProbeResult {
                    is_password: false,
                    focus_generation,
                }))
                .expect("probe reply sent");
        });
        let mut state = CaptureState::new_with_system_capture(tx, controls, false);
        let base = Instant::now();
        let current_window = window(7, "Editor");

        let first = state.redact_keyboard_for_password_field_at(Some(&current_window), base);
        responder.join().expect("probe responder joins");
        let second = state.redact_keyboard_for_password_field_at(
            Some(&current_window),
            base + PASSWORD_FIELD_PROBE_CACHE_TTL / 2,
        );

        assert!(!first);
        assert!(!second);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn password_focus_generation_invalidates_same_window_non_password_cache() {
        let (tx, rx) = crossbeam_channel::bounded(4);
        let controls = CaptureControls::new(CaptureSettings {
            foreground: false,
            windows: false,
            keyboard: true,
            mouse: false,
            system: false,
            idle: false,
            idle_threshold_ms: DEFAULT_IDLE_THRESHOLD_MS,
            process_filter: true,
        });
        let current_window = window(7, "Login Form");
        let base = Instant::now();
        let mut state = CaptureState::new_with_system_capture(tx, controls.clone(), false);
        state.password_focus_cache = Some(PasswordFocusCache {
            hwnd: current_window.hwnd,
            is_password: false,
            focus_generation: controls.password_focus_generation(),
            resolved_at: base,
        });
        let new_generation = controls.mark_password_focus_changed();
        let (probe_tx, probe_rx) = crossbeam_channel::bounded(1);
        controls.set_sensitive_field_probe(Some(probe_tx));
        let responder = thread::spawn(move || {
            let request = probe_rx
                .recv()
                .expect("probe request after focus generation");
            request
                .reply
                .send(Some(SensitiveFieldProbeResult {
                    is_password: true,
                    focus_generation: new_generation,
                }))
                .expect("probe reply sent");
        });

        let redact_key = state.redact_keyboard_for_password_field_at(
            Some(&current_window),
            base + Duration::from_millis(1),
        );
        responder.join().expect("probe responder joins");

        assert!(redact_key);
        assert!(matches!(
            rx.try_recv().expect("password context entered").payload,
            EventPayload::SensitiveContextEntered {
                reason: SensitiveContextReason::PasswordField
            }
        ));
    }

    #[test]
    fn key_release_does_not_probe_password_focus() {
        let (tx, rx) = crossbeam_channel::bounded(4);
        let controls = CaptureControls::new(CaptureSettings {
            foreground: false,
            windows: false,
            keyboard: true,
            mouse: false,
            system: false,
            idle: false,
            idle_threshold_ms: DEFAULT_IDLE_THRESHOLD_MS,
            process_filter: true,
        });
        let (probe_tx, probe_rx) = crossbeam_channel::bounded(1);
        controls.set_sensitive_field_probe(Some(probe_tx));
        let mut state = CaptureState::new_with_system_capture(tx, controls, false);
        let current_window = window(7, "Editor");

        state.on_raw_keyboard_at(
            RawKeyboardEvent {
                vkey: 0x41,
                flags: RI_KEY_BREAK,
            },
            Some(current_window),
            Instant::now(),
        );

        assert!(probe_rx.try_recv().is_err());
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn ordinary_keydown_preserves_non_password_cache_for_steady_typing() {
        let (tx, _rx) = crossbeam_channel::bounded(4);
        let controls = CaptureControls::new(CaptureSettings {
            foreground: false,
            windows: false,
            keyboard: true,
            mouse: false,
            system: false,
            idle: false,
            idle_threshold_ms: DEFAULT_IDLE_THRESHOLD_MS,
            process_filter: true,
        });
        let current_window = window(7, "Login Form");
        let base = Instant::now();
        let mut state = CaptureState::new_with_system_capture(tx, controls.clone(), false);
        state.password_focus_cache = Some(PasswordFocusCache {
            hwnd: current_window.hwnd,
            is_password: false,
            focus_generation: controls.password_focus_generation(),
            resolved_at: base,
        });

        state.on_raw_keyboard_at(
            RawKeyboardEvent {
                vkey: 0x41,
                flags: 0,
            },
            Some(current_window),
            base + Duration::from_millis(1),
        );

        assert!(state.password_focus_cache.is_some());
    }

    #[test]
    fn focus_navigation_key_invalidates_cache_before_next_password_key() {
        let (tx, rx) = crossbeam_channel::bounded(4);
        let controls = CaptureControls::new(CaptureSettings {
            foreground: false,
            windows: false,
            keyboard: true,
            mouse: false,
            system: false,
            idle: false,
            idle_threshold_ms: DEFAULT_IDLE_THRESHOLD_MS,
            process_filter: true,
        });
        let current_window = window(7, "Login Form");
        let base = Instant::now();
        let mut state = CaptureState::new_with_system_capture(tx, controls.clone(), false);
        state.password_focus_cache = Some(PasswordFocusCache {
            hwnd: current_window.hwnd,
            is_password: false,
            focus_generation: controls.password_focus_generation(),
            resolved_at: base,
        });

        state.on_raw_keyboard_at(
            RawKeyboardEvent {
                vkey: 0x0d,
                flags: 0,
            },
            Some(current_window.clone()),
            base + Duration::from_millis(1),
        );
        assert!(state.password_focus_cache.is_none());
        match rx.try_recv().expect("navigation key emitted").payload {
            EventPayload::Key { key, .. } => assert_ne!(key, "<redacted>"),
            _ => panic!("expected key event"),
        }

        let (probe_tx, probe_rx) = crossbeam_channel::bounded(1);
        controls.set_sensitive_field_probe(Some(probe_tx));
        let focus_generation = controls.password_focus_generation();
        let responder = thread::spawn(move || {
            let request = probe_rx
                .recv()
                .expect("probe request after key invalidation");
            request
                .reply
                .send(Some(SensitiveFieldProbeResult {
                    is_password: true,
                    focus_generation,
                }))
                .expect("probe reply sent");
        });

        state.on_raw_keyboard_at(
            RawKeyboardEvent {
                vkey: 0x41,
                flags: 0,
            },
            Some(current_window),
            base + Duration::from_millis(1),
        );
        responder.join().expect("probe responder joins");

        assert!(matches!(
            rx.try_recv().expect("password context entered").payload,
            EventPayload::SensitiveContextEntered {
                reason: SensitiveContextReason::PasswordField
            }
        ));
        match rx
            .try_recv()
            .expect("redacted password key follows boundary")
            .payload
        {
            EventPayload::Key { key, .. } => assert_eq!(key, "<redacted>"),
            _ => panic!("expected key event"),
        }
    }

    #[test]
    fn raw_keyboard_focus_predicate_covers_navigation_and_alt_not_text() {
        assert!((RawKeyboardEvent {
            vkey: 0x0d,
            flags: 0
        })
        .may_change_focus(false));
        assert!(!(RawKeyboardEvent {
            vkey: 0x0d,
            flags: RI_KEY_BREAK
        })
        .may_change_focus(false));
        assert!(!(RawKeyboardEvent {
            vkey: 0x41,
            flags: 0
        })
        .may_change_focus(false));
        assert!((RawKeyboardEvent {
            vkey: 0x41,
            flags: 0
        })
        .may_change_focus(true));
    }

    #[test]
    fn notification_app_label_is_bounded_and_control_free() {
        assert_eq!(
            notification_app_label("  Calendar  "),
            Some("Calendar".to_string())
        );
        assert_eq!(notification_app_label(""), None);
        assert_eq!(notification_app_label("line\nbreak"), None);
        assert_eq!(
            notification_app_label(&"a".repeat(NOTIFICATION_APP_LABEL_MAX_CHARS + 1)),
            None
        );
    }

    #[test]
    fn any_app_exclusion_disables_notification_rows_globally() {
        let controls = CaptureControls::all_enabled().with_excluded_apps(["private.exe"]);
        let excluded_focus = window(1, "private");
        let allowed_focus = window(2, "allowed");

        assert!(notification_excluded_at_capture_boundary(
            &controls,
            Some("Friendly Product Name"),
            Some(&excluded_focus),
        ));
        assert!(notification_excluded_at_capture_boundary(
            &controls,
            Some("PRIVATE"),
            Some(&allowed_focus),
        ));
        assert!(notification_excluded_at_capture_boundary(
            &controls,
            Some("Friendly Product Name"),
            Some(&allowed_focus),
        ));
        assert!(notification_excluded_at_capture_boundary(
            &controls, None, None,
        ));

        let no_exclusions = CaptureControls::all_enabled();
        assert!(!notification_excluded_at_capture_boundary(
            &no_exclusions,
            Some("Friendly Product Name"),
            Some(&allowed_focus),
        ));
    }

    #[test]
    fn notification_received_sample_emits_value_free_event() {
        let controls = CaptureControls::all_enabled();
        let (tx, rx) = crossbeam_channel::bounded(4);
        let base = Instant::now();

        emit_notification_received(&tx, &controls, Some("Calendar".to_string()), 1, base);
        let event = rx.try_recv().expect("notification event");
        assert!(rx.try_recv().is_err());

        assert_eq!(event.source, Source::System);
        assert!(matches!(
            event.payload,
            EventPayload::NotificationsReceived {
                app: Some(ref app),
                count: 1
            } if app == "Calendar"
        ));
    }

    #[test]
    fn notification_received_sample_respects_system_toggle() {
        let controls = CaptureControls::all_enabled();
        controls.set_enabled(CaptureStream::System, false);
        let (tx, rx) = crossbeam_channel::bounded(4);

        emit_notification_received(
            &tx,
            &controls,
            Some("Calendar".to_string()),
            1,
            Instant::now(),
        );

        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn notification_poll_diff_seeds_dedupes_and_aggregates() {
        let mut seen = NotificationSeenIds::default();
        let mut by_app = HashMap::new();

        note_polled_notification(
            &mut seen,
            true,
            1,
            Some("Calendar".to_string()),
            &mut by_app,
        );
        assert!(by_app.is_empty());

        note_polled_notification(
            &mut seen,
            false,
            1,
            Some("Calendar".to_string()),
            &mut by_app,
        );
        assert!(by_app.is_empty());

        note_polled_notification(
            &mut seen,
            false,
            2,
            Some("Calendar".to_string()),
            &mut by_app,
        );
        note_polled_notification(
            &mut seen,
            false,
            3,
            Some("Calendar".to_string()),
            &mut by_app,
        );
        note_polled_notification(&mut seen, false, 4, None, &mut by_app);

        assert_eq!(by_app.get(&Some("Calendar".to_string())), Some(&2));
        assert_eq!(by_app.get(&None), Some(&1));
    }

    #[test]
    fn notification_seen_ids_are_bounded() {
        let mut seen = NotificationSeenIds::default();

        for id in 0..(NOTIFICATION_SEEN_IDS_MAX as u32 + 1) {
            assert!(seen.remember(id));
        }

        assert_eq!(seen.ordered.len(), NOTIFICATION_SEEN_IDS_MAX);
        assert_eq!(seen.set.len(), NOTIFICATION_SEEN_IDS_MAX);
        assert!(seen.remember(0));
        assert!(!seen.remember(NOTIFICATION_SEEN_IDS_MAX as u32));
    }

    #[test]
    fn sensitive_context_reasons_do_not_clear_each_other() {
        let controls = CaptureControls::all_enabled();
        let (tx, rx) = crossbeam_channel::bounded(4);
        let mut state = CaptureState::new(tx, controls);
        let base = Instant::now();

        state.enter_sensitive_context_at(base, SensitiveContextReason::SessionLocked);
        let lock_entered = rx.try_recv().expect("lock context entered");
        state.enter_sensitive_context_at(
            base + Duration::from_millis(1),
            SensitiveContextReason::SecureDesktop,
        );
        let secure_entered = rx.try_recv().expect("secure desktop context entered");

        state.exit_sensitive_context_at(
            base + Duration::from_millis(2),
            SensitiveContextReason::SessionLocked,
        );
        let lock_exited = rx.try_recv().expect("lock context exited");

        state.exit_sensitive_context_at(
            base + Duration::from_millis(3),
            SensitiveContextReason::SecureDesktop,
        );
        let secure_exited = rx.try_recv().expect("secure desktop context exited");
        assert!(rx.try_recv().is_err());

        assert!(matches!(
            lock_entered.payload,
            EventPayload::SensitiveContextEntered {
                reason: SensitiveContextReason::SessionLocked
            }
        ));
        assert!(matches!(
            secure_entered.payload,
            EventPayload::SensitiveContextEntered {
                reason: SensitiveContextReason::SecureDesktop
            }
        ));
        assert!(matches!(
            lock_exited.payload,
            EventPayload::SensitiveContextExited {
                reason: SensitiveContextReason::SessionLocked
            }
        ));
        assert!(matches!(
            secure_exited.payload,
            EventPayload::SensitiveContextExited {
                reason: SensitiveContextReason::SecureDesktop
            }
        ));
    }

    #[test]
    fn dropped_sensitive_enter_queues_and_delivers_before_later_captures() {
        let controls = CaptureControls::all_enabled();
        // Capacity 1: the SecureDesktop enter fills the only slot, so the
        // lock enter times out like a flood while the writer stalls.
        let (tx, rx) = crossbeam_channel::bounded(1);
        let mut state = CaptureState::new(tx, controls.clone());
        let base = Instant::now();

        state.enter_sensitive_context_at(base, SensitiveContextReason::SecureDesktop);
        state.enter_sensitive_context_at(
            base + Duration::from_millis(1),
            SensitiveContextReason::SessionLocked,
        );

        // Fail closed: the context is tracked locally even though the
        // boundary row has not been delivered yet.
        assert!(state
            .active_sensitive_reasons
            .contains(&SensitiveContextReason::SessionLocked));
        assert_eq!(state.pending_sensitive_boundaries.borrow().len(), 1);

        // Writer drains the first row; the channel now has room again.
        let first = rx.try_recv().expect("secure desktop boundary");
        assert!(matches!(
            first.payload,
            EventPayload::SensitiveContextEntered {
                reason: SensitiveContextReason::SecureDesktop
            }
        ));

        // A later pump or background-producer capture must NOT overtake the
        // queued lock boundary. The retained transition token globally gates
        // enabled_for until the timer retry places that boundary in the
        // shared channel.
        let background_row = Captured::new(
            Source::System,
            base + Duration::from_millis(2),
            EventPayload::SessionConnect {
                session_id: 7,
                connection: SessionConnectionKind::Console,
            },
        );
        assert!(!controls.enabled_for(&background_row));
        state.emit_session_connect_at(
            base + Duration::from_millis(2),
            7,
            SessionConnectionKind::Console,
        );
        assert!(rx.try_recv().is_err());
        assert_eq!(state.pending_sensitive_boundaries.borrow().len(), 1);

        // The timer heartbeat owns retries even while ordinary streams are
        // globally gated by the retained transition token.
        state.flush_pending_sensitive_boundaries();
        let second = rx.try_recv().expect("queued lock boundary");
        assert!(matches!(
            second.payload,
            EventPayload::SensitiveContextEntered {
                reason: SensitiveContextReason::SessionLocked
            }
        ));
        assert!(state.pending_sensitive_boundaries.borrow().is_empty());

        // With the queue empty the next capture flows normally.
        state.emit_session_connect_at(
            base + Duration::from_millis(3),
            7,
            SessionConnectionKind::Console,
        );
        let third = rx.try_recv().expect("session connect row");
        assert!(matches!(third.payload, EventPayload::SessionConnect { .. }));
    }

    #[test]
    fn queued_sensitive_boundaries_preserve_enter_exit_order() {
        let controls = CaptureControls::all_enabled();
        let (tx, rx) = crossbeam_channel::bounded(1);
        let mut state = CaptureState::new(tx, controls);
        let base = Instant::now();

        state.enter_sensitive_context_at(base, SensitiveContextReason::SecureDesktop);
        // Enter times out (queued); the matching exit queues behind it
        // without waiting on the send timeout again.
        state.enter_sensitive_context_at(
            base + Duration::from_millis(1),
            SensitiveContextReason::SessionLocked,
        );
        state.exit_sensitive_context_at(
            base + Duration::from_millis(2),
            SensitiveContextReason::SessionLocked,
        );
        assert_eq!(state.pending_sensitive_boundaries.borrow().len(), 2);
        assert!(!state
            .active_sensitive_reasons
            .contains(&SensitiveContextReason::SessionLocked));

        rx.try_recv().expect("secure desktop boundary drained");
        state.flush_pending_sensitive_boundaries();
        let queued_enter = rx.try_recv().expect("queued enter");
        assert!(matches!(
            queued_enter.payload,
            EventPayload::SensitiveContextEntered {
                reason: SensitiveContextReason::SessionLocked
            }
        ));
        state.flush_pending_sensitive_boundaries();
        let queued_exit = rx.try_recv().expect("queued exit");
        assert!(matches!(
            queued_exit.payload,
            EventPayload::SensitiveContextExited {
                reason: SensitiveContextReason::SessionLocked
            }
        ));
    }

    #[test]
    fn aux_stream_drop_paths_count_into_capture_events_dropped() {
        let controls = CaptureControls::all_enabled();
        let (tx, _rx) = crossbeam_channel::bounded(1);
        tx.try_send(Captured::new(
            Source::System,
            Instant::now(),
            EventPayload::SensitiveContextEntered {
                reason: SensitiveContextReason::SecureDesktop,
            },
        ))
        .expect("channel filled");
        assert_eq!(controls.diagnostics().capture_events_dropped(), 0);

        // Aux-thread send paths must count their drops like the pump path
        // does, or events_skipped=0 + capture_events_dropped=0 still would
        // not prove zero loss (S2).
        send_system_payload(
            &tx,
            &controls,
            EventPayload::SensitiveContextExited {
                reason: SensitiveContextReason::SecureDesktop,
            },
            "test payload",
        );
        assert_eq!(controls.diagnostics().capture_events_dropped(), 1);

        send_system_capture(
            &tx,
            &controls,
            Captured::new(
                Source::System,
                Instant::now(),
                EventPayload::SensitiveContextExited {
                    reason: SensitiveContextReason::SecureDesktop,
                },
            ),
            "notification",
        );
        assert_eq!(controls.diagnostics().capture_events_dropped(), 2);
    }

    #[test]
    fn clipboard_format_classification_is_coarse() {
        assert_eq!(
            classify_clipboard_formats(&[CF_UNICODETEXT, CF_LOCALE]),
            ClipboardFormatKind::Text
        );
        assert_eq!(
            classify_clipboard_formats(&[CF_HDROP]),
            ClipboardFormatKind::Files
        );
        assert_eq!(
            classify_clipboard_formats(&[CF_DIBV5]),
            ClipboardFormatKind::Image
        );
        assert_eq!(
            classify_clipboard_formats(&[CF_WAVE]),
            ClipboardFormatKind::Audio
        );
        assert_eq!(
            classify_clipboard_formats(&[42_000]),
            ClipboardFormatKind::Custom
        );
        assert_eq!(classify_clipboard_formats(&[]), ClipboardFormatKind::Empty);
    }

    #[test]
    fn clipboard_updates_dedupe_by_sequence_and_store_metadata_only() {
        let mut system = SystemState::default();
        let base = Instant::now();
        let metadata = ClipboardMetadata {
            sequence_number: 77,
            format_kind: ClipboardFormatKind::Text,
            format_count: 3,
            text_char_count: Some(12),
            byte_size: Some(26),
        };

        let captured = system
            .on_clipboard_update_at(metadata, base)
            .expect("first clipboard event");
        assert!(system.on_clipboard_update_at(metadata, base).is_none());

        match captured.payload {
            EventPayload::ClipboardUsed {
                sequence_number,
                format_kind,
                format_count,
                text_char_count,
                byte_size,
            } => {
                assert_eq!(sequence_number, 77);
                assert_eq!(format_kind, ClipboardFormatKind::Text);
                assert_eq!(format_count, 3);
                assert_eq!(text_char_count, Some(12));
                assert_eq!(byte_size, Some(26));
            }
            _ => panic!("expected clipboard event"),
        }
    }

    #[test]
    fn timer_gap_caps_foreground_dwell_and_resets_keyboard() {
        let controls = CaptureControls::all_enabled();
        let diagnostics = controls.diagnostics();
        let (tx, rx) = crossbeam_channel::bounded(8);
        let mut state = CaptureState::new(tx, controls);
        let base = Instant::now();
        let current = window(1, "A");

        state.seed_foreground_window_at(current.clone(), base);
        rx.try_recv().expect("seed event");
        state.last_timer_tick_ms = Some(1_000);
        state
            .keyboard
            .on_raw_key(
                RawKeyboardEvent {
                    vkey: 0x10,
                    flags: 0,
                },
                None,
                base + Duration::from_millis(1),
            )
            .expect("shift press emitted");
        state
            .keyboard
            .on_raw_key(
                RawKeyboardEvent {
                    vkey: 0x41,
                    flags: 0,
                },
                None,
                base + Duration::from_millis(2),
            )
            .expect("A press emitted");

        state.on_timer_sample_at(
            TimerSample {
                idle_ms: Some(0),
                tick_ms: Some(1_000 + MISSED_POWER_BOUNDARY_THRESHOLD_MS + 1),
                current_foreground: Some(current.clone()),
                input_desktop: None,
                now: base + Duration::from_secs(9 * 60 * 60),
            },
            |_| false,
            |_| false,
        );

        let boundary = rx.try_recv().expect("capped boundary event");
        let reseed = rx.try_recv().expect("timer reseed event");
        let status = rx.try_recv().expect("power status reseed event");
        let recovered = rx.try_recv().expect("power recovery event");
        assert!(rx.try_recv().is_err());
        assert_eq!(diagnostics.power_boundary_catches(), 1);

        match &boundary.payload {
            EventPayload::FocusChanged {
                previous_focused_for_ms,
                ..
            } => assert_eq!(
                *previous_focused_for_ms,
                duration_ms(MISSED_POWER_BOUNDARY_MAX_DWELL)
            ),
            _ => panic!("expected focus event"),
        }
        assert!(matches!(
            reseed.payload,
            EventPayload::FocusChanged { prev: None, .. }
        ));
        assert!(matches!(
            status.payload,
            EventPayload::PowerStatusChanged { .. }
        ));
        match &recovered.payload {
            EventPayload::PowerBoundaryRecovered {
                gap_ms,
                capped_dwell_ms,
            } => {
                assert_eq!(*gap_ms, MISSED_POWER_BOUNDARY_THRESHOLD_MS + 1);
                assert_eq!(
                    *capped_dwell_ms,
                    duration_ms(MISSED_POWER_BOUNDARY_MAX_DWELL)
                );
            }
            _ => panic!("expected power recovery event"),
        }

        state.on_power_resume_at(
            base + Duration::from_secs(9 * 60 * 60) + Duration::from_millis(100),
            Some(1_000 + MISSED_POWER_BOUNDARY_THRESHOLD_MS + 101),
            Some(current),
        );
        assert!(rx.try_recv().is_err());

        let press_after_resync = state
            .keyboard
            .on_raw_key(
                RawKeyboardEvent {
                    vkey: 0x41,
                    flags: 0,
                },
                None,
                base + Duration::from_secs(9 * 60 * 60) + Duration::from_millis(1),
            )
            .expect("resync should clear missed release");
        match press_after_resync.payload {
            EventPayload::Key { key, mods, .. } => {
                assert_eq!(key, "A");
                assert!(!mods.shift);
            }
            _ => panic!("expected key event"),
        }
    }

    #[test]
    fn timer_after_suspend_reseeds_if_resume_broadcast_is_missing() {
        let controls = CaptureControls::all_enabled();
        let (tx, rx) = crossbeam_channel::bounded(8);
        let mut state = CaptureState::new(tx, controls);
        let base = Instant::now();
        let current = window(1, "A");

        state.seed_foreground_window_at(current.clone(), base);
        rx.try_recv().expect("seed event");
        state.on_power_suspend_at(base + Duration::from_millis(10), Some(1_000));

        let suspend_boundary = rx.try_recv().expect("suspend boundary event");
        let suspend = rx.try_recv().expect("suspend power event");
        match &suspend_boundary.payload {
            EventPayload::FocusChanged {
                previous_focused_for_ms,
                ..
            } => assert_eq!(*previous_focused_for_ms, 10),
            _ => panic!("expected focus event"),
        }
        assert!(matches!(
            suspend.payload,
            EventPayload::PowerSuspend {
                tick_ms: Some(1_000)
            }
        ));

        state.on_timer_sample_at(
            TimerSample {
                idle_ms: Some(0),
                tick_ms: Some(1_000 + MISSED_POWER_BOUNDARY_THRESHOLD_MS + 1),
                current_foreground: Some(current),
                input_desktop: None,
                now: base + Duration::from_secs(60),
            },
            |_| false,
            |_| false,
        );

        let reseed = rx.try_recv().expect("timer should reseed after suspend");
        let resume = rx.try_recv().expect("timer resume power event");
        assert!(rx.try_recv().is_err());
        assert!(!state.power_suspended);
        assert!(matches!(
            reseed.payload,
            EventPayload::FocusChanged { prev: None, .. }
        ));
        assert!(matches!(
            resume.payload,
            EventPayload::PowerResume {
                matched_suspend: true,
                ..
            }
        ));
    }

    #[test]
    fn duplicate_foreground_window_does_not_emit_or_reset_timing() {
        let mut state = ForegroundState::default();
        let base = Instant::now();
        let first = window(1, "A");
        let second = window(2, "B");

        assert!(state.seed_window_at(first.clone(), base).is_some());
        assert!(state
            .on_window_at(first, base + Duration::from_millis(5))
            .is_none());
        let captured = state
            .on_window_at(second, base + Duration::from_millis(10))
            .expect("second window event");

        match &captured.payload {
            EventPayload::FocusChanged {
                previous_focused_for_ms,
                ..
            } => assert_eq!(*previous_focused_for_ms, 10),
            _ => panic!("expected focus event"),
        }
    }

    #[test]
    fn window_snapshot_seeds_without_emitting_open_events() {
        let mut state = WindowState::default();
        let base = Instant::now();

        state.seed_window_at(window(1, "A"), base);
        assert!(state
            .on_opened_at(window(1, "A"), base + Duration::from_millis(10))
            .is_none());
    }

    #[test]
    fn window_reseed_emits_seed_rows_and_rebases_synthesized_close_durations() {
        let mut state = WindowState::default();
        let base = Instant::now();
        let replacement_started = base + Duration::from_secs(60);

        state.seed_window_at(window(1, "A"), base);
        let seeded = state.reseed_with_events_at(vec![window(1, "A")], replacement_started);

        assert_eq!(seeded.len(), 1);
        match &seeded[0].payload {
            EventPayload::WindowOpened { window, origin } => {
                assert_eq!(window.title, "A");
                assert_eq!(*origin, WindowLifecycleOrigin::Seeded);
            }
            _ => panic!("expected seeded open event"),
        }

        let closed = state.close_all_at(replacement_started + Duration::from_millis(5_000));
        assert_eq!(closed.len(), 1);
        match &closed[0].payload {
            EventPayload::WindowClosed {
                open_for_ms,
                origin,
                ..
            } => {
                assert_eq!(*open_for_ms, 5_000);
                assert_eq!(*origin, WindowLifecycleOrigin::Synthesized);
            }
            _ => panic!("expected synthesized close event"),
        }
    }

    #[test]
    fn window_lifecycle_emits_open_and_close_events() {
        let mut state = WindowState::default();
        let base = Instant::now();
        let opened = state
            .on_opened_at(window(2, "B"), base)
            .expect("open event");
        let closed = state
            .on_closed_at(2, base + Duration::from_millis(25))
            .expect("close event");

        match &opened.payload {
            EventPayload::WindowOpened { window, origin } => {
                assert_eq!(window.title, "B");
                assert_eq!(*origin, WindowLifecycleOrigin::Observed);
            }
            _ => panic!("expected window open event"),
        }

        match &closed.payload {
            EventPayload::WindowClosed {
                window,
                open_for_ms,
                origin,
            } => {
                assert_eq!(window.title, "B");
                assert_eq!(*open_for_ms, 25);
                assert_eq!(*origin, WindowLifecycleOrigin::Observed);
            }
            _ => panic!("expected window close event"),
        }
    }

    #[test]
    fn capture_state_destroy_path_closes_tracked_window() {
        let (tx, rx) = crossbeam_channel::bounded(8);
        let mut state = CaptureState::new(tx, CaptureControls::all_enabled());
        let tracked = window(42, "Tracked");
        state
            .windows
            .seed_window_at(tracked.clone(), Instant::now());

        state.on_window_destroyed(HWND(tracked.hwnd as usize as *mut c_void));

        let closed = rx.try_recv().expect("close event");
        match closed.payload {
            EventPayload::WindowClosed { window, origin, .. } => {
                assert_eq!(window.hwnd, tracked.hwnd);
                assert_eq!(window.title, "Tracked");
                assert_eq!(origin, WindowLifecycleOrigin::Seeded);
            }
            _ => panic!("expected window close event"),
        }
    }

    #[test]
    fn window_state_synthesizes_live_closes_on_shutdown() {
        let mut state = WindowState::default();
        let base = Instant::now();

        state.seed_window_at(window(1, "A"), base);
        let opened = state
            .on_opened_at(window(2, "B"), base + Duration::from_millis(5))
            .expect("open event");
        assert!(matches!(
            opened.payload,
            EventPayload::WindowOpened {
                origin: WindowLifecycleOrigin::Observed,
                ..
            }
        ));

        let closed = state.close_all_at(base + Duration::from_millis(25));

        assert_eq!(closed.len(), 2);
        let mut titles_and_durations = closed
            .into_iter()
            .map(|captured| match captured.payload {
                EventPayload::WindowClosed {
                    window,
                    open_for_ms,
                    origin,
                } => (window.title, open_for_ms, origin),
                _ => panic!("expected close event"),
            })
            .collect::<Vec<_>>();
        titles_and_durations.sort();

        assert_eq!(
            titles_and_durations,
            vec![
                ("A".to_string(), 25, WindowLifecycleOrigin::Synthesized),
                ("B".to_string(), 20, WindowLifecycleOrigin::Synthesized)
            ]
        );
    }

    #[test]
    fn unknown_window_close_is_ignored() {
        let mut state = WindowState::default();
        assert!(state.on_closed_at(99, Instant::now()).is_none());
    }

    #[test]
    fn power_status_fields_classifies_ac_battery_and_saver() {
        let plugged = SYSTEM_POWER_STATUS {
            ACLineStatus: 1,
            BatteryLifePercent: 80,
            SystemStatusFlag: 1,
            ..Default::default()
        };
        assert_eq!(
            power_status_fields(&plugged),
            (Some(true), Some(80), Some(true))
        );

        let on_battery = SYSTEM_POWER_STATUS {
            ACLineStatus: 0,
            BatteryLifePercent: 55,
            SystemStatusFlag: 0,
            ..Default::default()
        };
        assert_eq!(
            power_status_fields(&on_battery),
            (Some(false), Some(55), Some(false))
        );

        // 255 == unknown / no battery.
        let unknown = SYSTEM_POWER_STATUS {
            ACLineStatus: 255,
            BatteryLifePercent: 255,
            ..Default::default()
        };
        let (ac, pct, _saver) = power_status_fields(&unknown);
        assert_eq!(ac, None);
        assert_eq!(pct, None);
    }

    #[test]
    fn reseed_clears_power_status_debounce() {
        // Review fix: after archive/reset the fresh DB has no power_status row, so
        // the debounce key must be cleared — otherwise a same-bucket status after
        // the reset would be suppressed against the old DB's last value.
        let controls = CaptureControls::all_enabled();
        let (tx, _rx) = crossbeam_channel::bounded(8);
        let mut state = CaptureState::new(tx, controls);
        state.last_power_status = Some((Some(true), Some(false), Some(5)));

        state.reseed_after_reset_with_at(
            Instant::now(),
            None,
            Vec::new(),
            system_info_payload(),
            screen(0, 0, 1920, 1080),
            ReseedAfterResetOptions {
                tick_ms: Some(1_000),
                redact_titles: false,
            },
        );

        assert!(state.last_power_status.is_none());
    }

    #[test]
    fn title_redacted_reseed_blanks_seeded_window_titles() {
        let controls = CaptureControls::all_enabled();
        let (tx, rx) = crossbeam_channel::bounded(8);
        let mut state = CaptureState::new(tx, controls);
        let base = Instant::now();

        state.reseed_after_reset_with_at(
            base,
            Some(window(1, "Recorded target title")),
            vec![
                window(1, "Recorded target title"),
                window(2, "Other open title"),
            ],
            system_info_payload(),
            screen(0, 0, 1920, 1080),
            ReseedAfterResetOptions {
                tick_ms: Some(1_000),
                redact_titles: true,
            },
        );

        let focus = rx.try_recv().expect("foreground seed event");
        match focus.payload {
            EventPayload::FocusChanged { window, prev, .. } => {
                assert_eq!(window.title, "<redacted>");
                assert!(prev.is_none());
            }
            _ => panic!("expected focus seed"),
        }

        for _ in 0..2 {
            let seeded = rx.try_recv().expect("window seed event");
            match seeded.payload {
                EventPayload::WindowOpened { window, origin } => {
                    assert_eq!(origin, WindowLifecycleOrigin::Seeded);
                    assert_eq!(window.title, "<redacted>");
                }
                _ => panic!("expected window seed"),
            }
        }
    }

    #[test]
    fn system_state_seeds_info_and_virtual_screen_and_dedupes_display_changes() {
        let mut state = SystemState::default();
        let base = Instant::now();
        let initial_screen = screen(-1920, 0, 4480, 1440);

        let seeded = state.seed_with_at(system_info_payload(), initial_screen, base);
        assert_eq!(seeded.len(), 2);

        match &seeded[0].payload {
            EventPayload::SystemInfo {
                host,
                processor_count,
                ..
            } => {
                assert_eq!(host, "workstation");
                assert_eq!(*processor_count, 16);
            }
            _ => panic!("expected system info"),
        }

        match &seeded[1].payload {
            EventPayload::VirtualScreen {
                x0,
                y0,
                x1,
                y1,
                width,
                height,
            } => {
                assert_eq!((*x0, *y0), (-1920, 0));
                assert_eq!((*x1, *y1), (2560, 1440));
                assert_eq!((*width, *height), (4480, 1440));
            }
            _ => panic!("expected virtual screen"),
        }

        assert!(state
            .on_virtual_screen_at(initial_screen, base + Duration::from_millis(1))
            .is_none());

        let changed = state
            .on_virtual_screen_at(screen(0, 0, 2560, 1440), base + Duration::from_millis(2))
            .expect("changed screen emits");
        match &changed.payload {
            EventPayload::VirtualScreen { x0, width, .. } => {
                assert_eq!(*x0, 0);
                assert_eq!(*width, 2560);
            }
            _ => panic!("expected virtual screen"),
        }
    }

    #[test]
    fn idle_state_emits_threshold_crossings_once() {
        let mut state = IdleState {
            threshold: Duration::from_millis(100),
            is_idle: false,
        };
        let base = Instant::now();

        assert!(state.on_sample_at(50, base).is_none());
        let idle = state
            .on_sample_at(100, base + Duration::from_millis(1))
            .expect("entered idle");
        assert!(state
            .on_sample_at(500, base + Duration::from_millis(2))
            .is_none());

        match &idle.payload {
            EventPayload::Idle { idle_ms } => assert_eq!(*idle_ms, 100),
            _ => panic!("expected idle"),
        }

        let active = state
            .on_activity_at(10, base + Duration::from_millis(3))
            .expect("activity exits idle");
        assert!(state
            .on_activity_at(1, base + Duration::from_millis(4))
            .is_none());

        match &active.payload {
            EventPayload::Active { idle_ms } => assert_eq!(*idle_ms, 10),
            _ => panic!("expected active"),
        }
    }

    #[test]
    fn processor_architecture_names_are_stable() {
        assert_eq!(
            processor_architecture_name(PROCESSOR_ARCHITECTURE_AMD64),
            "x86_64"
        );
        assert_eq!(
            processor_architecture_name(PROCESSOR_ARCHITECTURE_ARM64),
            "arm64"
        );
        assert_eq!(
            processor_architecture_name(PROCESSOR_ARCHITECTURE_INTEL),
            "x86"
        );
        assert_eq!(
            processor_architecture_name(PROCESSOR_ARCHITECTURE_UNKNOWN),
            "unknown"
        );
    }

    #[test]
    fn keyboard_state_emits_press_only_with_modifier_snapshot() {
        let mut state = KeyboardState::default();
        let base = Instant::now();

        let shift = state
            .on_raw_key(
                RawKeyboardEvent {
                    vkey: 0x10,
                    flags: 0,
                },
                None,
                base,
            )
            .expect("shift press emitted");
        let a = state
            .on_raw_key(
                RawKeyboardEvent {
                    vkey: 0x41,
                    flags: 0,
                },
                None,
                base + Duration::from_millis(1),
            )
            .expect("A press emitted");
        let shift_release = state.on_raw_key(
            RawKeyboardEvent {
                vkey: 0x10,
                flags: RI_KEY_BREAK,
            },
            None,
            base + Duration::from_millis(2),
        );
        let b = state
            .on_raw_key(
                RawKeyboardEvent {
                    vkey: 0x42,
                    flags: 0,
                },
                None,
                base + Duration::from_millis(3),
            )
            .expect("B press emitted");

        match &shift.payload {
            EventPayload::Key { key, mods, .. } => {
                assert_eq!(key, "Shift");
                assert!(mods.shift);
            }
            _ => panic!("expected key event"),
        }
        match &a.payload {
            EventPayload::Key { key, mods, .. } => {
                assert_eq!(key, "A");
                assert!(mods.shift);
            }
            _ => panic!("expected key event"),
        }
        assert!(shift_release.is_none());
        match &b.payload {
            EventPayload::Key { key, mods, .. } => {
                assert_eq!(key, "B");
                assert!(!mods.shift);
            }
            _ => panic!("expected key event"),
        }
    }

    #[test]
    fn keyboard_state_can_redact_password_field_key_before_enqueue() {
        let mut state = KeyboardState::default();
        let base = Instant::now();

        let captured = state
            .on_raw_key_with_capture_redaction(
                RawKeyboardEvent {
                    vkey: 0x41,
                    flags: 0,
                },
                Some(window(7, "Password Dialog")),
                base,
                true,
            )
            .expect("key press emitted");

        match captured.payload {
            EventPayload::Key { key, window, .. } => {
                assert_eq!(key, "<redacted>");
                assert_eq!(window.expect("window").title, "<redacted>");
            }
            _ => panic!("expected key event"),
        }
    }

    #[test]
    fn keyboard_state_suppresses_auto_repeat_until_release() {
        let mut state = KeyboardState::default();
        let base = Instant::now();

        let first = state.on_raw_key(
            RawKeyboardEvent {
                vkey: 0x41,
                flags: 0,
            },
            None,
            base,
        );
        let repeat = state.on_raw_key(
            RawKeyboardEvent {
                vkey: 0x41,
                flags: 0,
            },
            None,
            base + Duration::from_millis(1),
        );
        let release = state.on_raw_key(
            RawKeyboardEvent {
                vkey: 0x41,
                flags: RI_KEY_BREAK,
            },
            None,
            base + Duration::from_millis(2),
        );
        let second_press = state.on_raw_key(
            RawKeyboardEvent {
                vkey: 0x41,
                flags: 0,
            },
            None,
            base + Duration::from_millis(3),
        );

        assert!(first.is_some());
        assert!(repeat.is_none());
        assert!(release.is_none());
        assert!(second_press.is_some());
    }

    #[test]
    fn keyboard_state_reset_after_boundary_prevents_stuck_keys() {
        let mut state = KeyboardState::default();
        let base = Instant::now();

        let shift = state
            .on_raw_key(
                RawKeyboardEvent {
                    vkey: 0x10,
                    flags: 0,
                },
                None,
                base,
            )
            .expect("shift press emitted");
        let first_a = state.on_raw_key(
            RawKeyboardEvent {
                vkey: 0x41,
                flags: 0,
            },
            None,
            base + Duration::from_millis(1),
        );
        let repeated_a = state.on_raw_key(
            RawKeyboardEvent {
                vkey: 0x41,
                flags: 0,
            },
            None,
            base + Duration::from_millis(2),
        );

        state.reset_after_boundary();
        let press_after_boundary = state
            .on_raw_key(
                RawKeyboardEvent {
                    vkey: 0x41,
                    flags: 0,
                },
                None,
                base + Duration::from_millis(3),
            )
            .expect("missed release should not suppress future press");

        assert!(matches!(shift.payload, EventPayload::Key { .. }));
        assert!(first_a.is_some());
        assert!(repeated_a.is_none());
        match press_after_boundary.payload {
            EventPayload::Key { key, mods, .. } => {
                assert_eq!(key, "A");
                assert!(!mods.shift);
            }
            _ => panic!("expected key event"),
        }
    }

    #[test]
    fn keyboard_state_resync_clears_released_keys_and_phantom_modifiers() {
        let mut state = KeyboardState::default();
        let base = Instant::now();

        state
            .on_raw_key(
                RawKeyboardEvent {
                    vkey: 0x10,
                    flags: 0,
                },
                None,
                base,
            )
            .expect("shift press emitted");
        state
            .on_raw_key(
                RawKeyboardEvent {
                    vkey: 0x41,
                    flags: 0,
                },
                None,
                base + Duration::from_millis(1),
            )
            .expect("A press emitted");
        assert!(
            state
                .on_raw_key(
                    RawKeyboardEvent {
                        vkey: 0x41,
                        flags: 0,
                    },
                    None,
                    base + Duration::from_millis(2),
                )
                .is_none(),
            "repeat should be suppressed before resync"
        );

        state.resync_pressed_keys_with(|_| false);
        let press_after_resync = state
            .on_raw_key(
                RawKeyboardEvent {
                    vkey: 0x41,
                    flags: 0,
                },
                None,
                base + Duration::from_millis(3),
            )
            .expect("released key should not remain stuck after resync");

        match press_after_resync.payload {
            EventPayload::Key { key, mods, .. } => {
                assert_eq!(key, "A");
                assert!(!mods.shift);
                assert!(!mods.ctrl);
                assert!(!mods.alt);
                assert!(!mods.win);
            }
            _ => panic!("expected key event"),
        }
    }

    #[test]
    fn mouse_state_emits_button_downs_with_position_and_window() {
        let mut state = MouseState::default();
        let base = Instant::now();
        let events = state.on_raw_mouse(
            RawMouseEvent {
                flags: 0,
                button_flags: RI_MOUSE_LEFT_BUTTON_DOWN as u16,
                button_data: 0,
                last_x: 0,
                last_y: 0,
            },
            Some(window(10, "Editor")),
            Some(MousePosition { x: 100, y: 200 }),
            base,
        );

        assert_eq!(events.len(), 1);
        match &events[0].payload {
            EventPayload::MouseClick {
                button,
                x,
                y,
                window,
                ..
            } => {
                assert_eq!(*button, MouseButton::Left);
                assert_eq!(*x, Some(100));
                assert_eq!(*y, Some(200));
                assert_eq!(window.as_ref().expect("window").title, "Editor");
            }
            _ => panic!("expected mouse click"),
        }
    }

    #[test]
    fn mouse_state_flushes_pending_movement_before_wheel() {
        let mut state = MouseState::default();
        let base = Instant::now();

        let ignored = state.on_raw_mouse(
            RawMouseEvent {
                flags: 0,
                button_flags: 0,
                button_data: 0,
                last_x: 3,
                last_y: 4,
            },
            None,
            None,
            base,
        );
        assert!(ignored.is_empty());

        let wheel = state.on_raw_mouse(
            RawMouseEvent {
                flags: 0,
                button_flags: RI_MOUSE_WHEEL as u16,
                button_data: (-120i16) as u16,
                last_x: 0,
                last_y: 0,
            },
            None,
            Some(MousePosition { x: 300, y: 400 }),
            base + Duration::from_millis(1),
        );

        assert_eq!(wheel.len(), 2);
        match &wheel[0].payload {
            EventPayload::MouseMove {
                dx_total,
                dy_total,
                duration_ms,
                ..
            } => {
                assert_eq!(*dx_total, 3);
                assert_eq!(*dy_total, 4);
                assert_eq!(*duration_ms, 0);
            }
            _ => panic!("expected mouse move before wheel"),
        }
        match &wheel[1].payload {
            EventPayload::MouseWheel {
                axis, delta, x, y, ..
            } => {
                assert_eq!(*axis, MouseWheelAxis::Vertical);
                assert_eq!(*delta, -120);
                assert_eq!(*x, Some(300));
                assert_eq!(*y, Some(400));
            }
            _ => panic!("expected mouse wheel"),
        }
    }

    #[test]
    fn mouse_state_flushes_pending_movement_before_click() {
        let mut state = MouseState::default();
        let base = Instant::now();

        assert!(state
            .on_raw_mouse(
                RawMouseEvent {
                    flags: 0,
                    button_flags: 0,
                    button_data: 0,
                    last_x: 3,
                    last_y: 4,
                },
                None,
                None,
                base,
            )
            .is_empty());

        let click = state.on_raw_mouse(
            RawMouseEvent {
                flags: 0,
                button_flags: RI_MOUSE_LEFT_BUTTON_DOWN as u16,
                button_data: 0,
                last_x: 0,
                last_y: 0,
            },
            None,
            Some(MousePosition { x: 300, y: 400 }),
            base + Duration::from_millis(1),
        );

        assert_eq!(click.len(), 2);
        match &click[0].payload {
            EventPayload::MouseMove {
                dx_total,
                dy_total,
                duration_ms,
                ..
            } => {
                assert_eq!(*dx_total, 3);
                assert_eq!(*dy_total, 4);
                assert_eq!(*duration_ms, 0);
            }
            _ => panic!("expected mouse move before click"),
        }
        match &click[1].payload {
            EventPayload::MouseClick { button, x, y, .. } => {
                assert_eq!(*button, MouseButton::Left);
                assert_eq!(*x, Some(300));
                assert_eq!(*y, Some(400));
            }
            _ => panic!("expected mouse click"),
        }
    }

    #[test]
    fn mouse_state_emits_double_click_after_completed_click() {
        let mut state = MouseState {
            double_click_interval: Duration::from_millis(500),
            double_click_box: MouseBox {
                half_width: 3,
                half_height: 3,
            },
            ..MouseState::default()
        };
        let base = Instant::now();

        let first_down = state.on_raw_mouse(
            RawMouseEvent {
                flags: 0,
                button_flags: RI_MOUSE_LEFT_BUTTON_DOWN as u16,
                button_data: 0,
                last_x: 0,
                last_y: 0,
            },
            Some(window(10, "Editor")),
            Some(MousePosition { x: 100, y: 200 }),
            base,
        );
        assert_eq!(first_down.len(), 1);

        let first_up = state.on_raw_mouse(
            RawMouseEvent {
                flags: 0,
                button_flags: RI_MOUSE_LEFT_BUTTON_UP as u16,
                button_data: 0,
                last_x: 0,
                last_y: 0,
            },
            Some(window(10, "Editor")),
            Some(MousePosition { x: 100, y: 200 }),
            base + Duration::from_millis(25),
        );
        assert!(first_up.is_empty());

        let second_down = state.on_raw_mouse(
            RawMouseEvent {
                flags: 0,
                button_flags: RI_MOUSE_LEFT_BUTTON_DOWN as u16,
                button_data: 0,
                last_x: 0,
                last_y: 0,
            },
            Some(window(10, "Editor")),
            Some(MousePosition { x: 102, y: 201 }),
            base + Duration::from_millis(125),
        );

        assert_eq!(second_down.len(), 2);
        match &second_down[0].payload {
            EventPayload::MouseClick { button, x, y, .. } => {
                assert_eq!(*button, MouseButton::Left);
                assert_eq!(*x, Some(102));
                assert_eq!(*y, Some(201));
            }
            _ => panic!("expected ordinary second click"),
        }
        match &second_down[1].payload {
            EventPayload::MouseDoubleClick {
                button,
                interval_ms,
                x,
                y,
                ..
            } => {
                assert_eq!(*button, MouseButton::Left);
                assert_eq!(*interval_ms, 125);
                assert_eq!(*x, Some(102));
                assert_eq!(*y, Some(201));
            }
            _ => panic!("expected double-click annotation"),
        }
    }

    #[test]
    fn mouse_state_does_not_chain_overlapping_triple_click_annotations() {
        let mut state = MouseState {
            double_click_interval: Duration::from_millis(500),
            double_click_box: MouseBox {
                half_width: 3,
                half_height: 3,
            },
            ..MouseState::default()
        };
        let base = Instant::now();

        assert_eq!(
            state
                .on_raw_mouse(
                    RawMouseEvent {
                        flags: 0,
                        button_flags: RI_MOUSE_LEFT_BUTTON_DOWN as u16,
                        button_data: 0,
                        last_x: 0,
                        last_y: 0,
                    },
                    Some(window(10, "Editor")),
                    Some(MousePosition { x: 100, y: 200 }),
                    base,
                )
                .len(),
            1
        );
        assert!(state
            .on_raw_mouse(
                RawMouseEvent {
                    flags: 0,
                    button_flags: RI_MOUSE_LEFT_BUTTON_UP as u16,
                    button_data: 0,
                    last_x: 0,
                    last_y: 0,
                },
                Some(window(10, "Editor")),
                Some(MousePosition { x: 100, y: 200 }),
                base + Duration::from_millis(20),
            )
            .is_empty());

        let second_down = state.on_raw_mouse(
            RawMouseEvent {
                flags: 0,
                button_flags: RI_MOUSE_LEFT_BUTTON_DOWN as u16,
                button_data: 0,
                last_x: 0,
                last_y: 0,
            },
            Some(window(10, "Editor")),
            Some(MousePosition { x: 101, y: 201 }),
            base + Duration::from_millis(100),
        );
        assert_eq!(second_down.len(), 2);
        assert!(matches!(
            second_down[1].payload,
            EventPayload::MouseDoubleClick { .. }
        ));
        assert!(state
            .on_raw_mouse(
                RawMouseEvent {
                    flags: 0,
                    button_flags: RI_MOUSE_LEFT_BUTTON_UP as u16,
                    button_data: 0,
                    last_x: 0,
                    last_y: 0,
                },
                Some(window(10, "Editor")),
                Some(MousePosition { x: 101, y: 201 }),
                base + Duration::from_millis(120),
            )
            .is_empty());

        let third_down = state.on_raw_mouse(
            RawMouseEvent {
                flags: 0,
                button_flags: RI_MOUSE_LEFT_BUTTON_DOWN as u16,
                button_data: 0,
                last_x: 0,
                last_y: 0,
            },
            Some(window(10, "Editor")),
            Some(MousePosition { x: 102, y: 202 }),
            base + Duration::from_millis(200),
        );
        assert_eq!(third_down.len(), 1);
        assert!(matches!(
            third_down[0].payload,
            EventPayload::MouseClick { .. }
        ));
    }

    #[test]
    fn mouse_state_requires_known_same_window_for_double_click_annotation() {
        let mut state = MouseState {
            double_click_interval: Duration::from_millis(500),
            double_click_box: MouseBox {
                half_width: 3,
                half_height: 3,
            },
            ..MouseState::default()
        };
        let base = Instant::now();

        state.on_raw_mouse(
            RawMouseEvent {
                flags: 0,
                button_flags: RI_MOUSE_LEFT_BUTTON_DOWN as u16,
                button_data: 0,
                last_x: 0,
                last_y: 0,
            },
            None,
            Some(MousePosition { x: 100, y: 200 }),
            base,
        );
        state.on_raw_mouse(
            RawMouseEvent {
                flags: 0,
                button_flags: RI_MOUSE_LEFT_BUTTON_UP as u16,
                button_data: 0,
                last_x: 0,
                last_y: 0,
            },
            None,
            Some(MousePosition { x: 100, y: 200 }),
            base + Duration::from_millis(20),
        );

        let second_down = state.on_raw_mouse(
            RawMouseEvent {
                flags: 0,
                button_flags: RI_MOUSE_LEFT_BUTTON_DOWN as u16,
                button_data: 0,
                last_x: 0,
                last_y: 0,
            },
            Some(window(10, "Editor")),
            Some(MousePosition { x: 101, y: 201 }),
            base + Duration::from_millis(100),
        );
        assert_eq!(second_down.len(), 1);
        assert!(matches!(
            second_down[0].payload,
            EventPayload::MouseClick { .. }
        ));
    }

    #[test]
    fn mouse_state_emits_drag_on_button_up_after_threshold() {
        let mut state = MouseState {
            drag_box: MouseBox {
                half_width: 8,
                half_height: 8,
            },
            ..MouseState::default()
        };
        let base = Instant::now();

        let down = state.on_raw_mouse(
            RawMouseEvent {
                flags: 0,
                button_flags: RI_MOUSE_LEFT_BUTTON_DOWN as u16,
                button_data: 0,
                last_x: 0,
                last_y: 0,
            },
            Some(window(20, "Canvas")),
            Some(MousePosition { x: 100, y: 100 }),
            base,
        );
        assert_eq!(down.len(), 1);

        let moved = state.on_raw_mouse(
            RawMouseEvent {
                flags: 0,
                button_flags: 0,
                button_data: 0,
                last_x: 20,
                last_y: 10,
            },
            Some(window(20, "Canvas")),
            Some(MousePosition { x: 120, y: 110 }),
            base + Duration::from_millis(50),
        );
        assert!(moved.is_empty());

        let up = state.on_raw_mouse(
            RawMouseEvent {
                flags: 0,
                button_flags: RI_MOUSE_LEFT_BUTTON_UP as u16,
                button_data: 0,
                last_x: 0,
                last_y: 0,
            },
            Some(window(20, "Canvas")),
            Some(MousePosition { x: 120, y: 110 }),
            base + Duration::from_millis(100),
        );

        assert_eq!(up.len(), 2);
        assert!(matches!(up[0].payload, EventPayload::MouseMove { .. }));
        match &up[1].payload {
            EventPayload::MouseDrag {
                button,
                dx_total,
                dy_total,
                distance_px,
                raw_event_count,
                duration_ms,
                start_x,
                start_y,
                end_x,
                end_y,
                selection_candidate,
                window,
                ..
            } => {
                assert_eq!(*button, MouseButton::Left);
                assert_eq!(*dx_total, 20);
                assert_eq!(*dy_total, 10);
                assert_eq!(*distance_px, 22);
                assert_eq!(*raw_event_count, 1);
                assert_eq!(*duration_ms, 100);
                assert_eq!(*start_x, Some(100));
                assert_eq!(*start_y, Some(100));
                assert_eq!(*end_x, Some(120));
                assert_eq!(*end_y, Some(110));
                assert!(*selection_candidate);
                assert_eq!(window.as_ref().expect("window").title, "Canvas");
            }
            _ => panic!("expected drag annotation"),
        }
    }

    #[test]
    fn mouse_state_uses_accumulated_distance_for_return_to_origin_drag() {
        let mut state = MouseState {
            drag_box: MouseBox {
                half_width: 8,
                half_height: 8,
            },
            ..MouseState::default()
        };
        let base = Instant::now();

        state.on_raw_mouse(
            RawMouseEvent {
                flags: 0,
                button_flags: RI_MOUSE_LEFT_BUTTON_DOWN as u16,
                button_data: 0,
                last_x: 0,
                last_y: 0,
            },
            Some(window(20, "Canvas")),
            Some(MousePosition { x: 100, y: 100 }),
            base,
        );
        state.on_raw_mouse(
            RawMouseEvent {
                flags: 0,
                button_flags: 0,
                button_data: 0,
                last_x: 10,
                last_y: 0,
            },
            Some(window(20, "Canvas")),
            Some(MousePosition { x: 110, y: 100 }),
            base + Duration::from_millis(30),
        );
        state.on_raw_mouse(
            RawMouseEvent {
                flags: 0,
                button_flags: 0,
                button_data: 0,
                last_x: -10,
                last_y: 0,
            },
            Some(window(20, "Canvas")),
            Some(MousePosition { x: 100, y: 100 }),
            base + Duration::from_millis(60),
        );

        let up = state.on_raw_mouse(
            RawMouseEvent {
                flags: 0,
                button_flags: RI_MOUSE_LEFT_BUTTON_UP as u16,
                button_data: 0,
                last_x: 0,
                last_y: 0,
            },
            Some(window(20, "Canvas")),
            Some(MousePosition { x: 100, y: 100 }),
            base + Duration::from_millis(90),
        );
        assert_eq!(up.len(), 2);
        assert!(matches!(up[0].payload, EventPayload::MouseMove { .. }));
        assert!(matches!(up[1].payload, EventPayload::MouseDrag { .. }));
    }

    #[test]
    fn mouse_state_resync_drops_stale_active_button_after_missed_up() {
        let mut state = MouseState::default();
        let base = Instant::now();

        state.on_raw_mouse(
            RawMouseEvent {
                flags: 0,
                button_flags: RI_MOUSE_LEFT_BUTTON_DOWN as u16,
                button_data: 0,
                last_x: 0,
                last_y: 0,
            },
            Some(window(20, "Canvas")),
            Some(MousePosition { x: 100, y: 100 }),
            base,
        );
        assert!(state.active_buttons.contains_key(&MouseButton::Left));

        state.resync_active_buttons_with(|_| false);
        assert!(state.active_buttons.is_empty());

        let movement_after_resync = state.on_raw_mouse(
            RawMouseEvent {
                flags: 0,
                button_flags: 0,
                button_data: 0,
                last_x: 100,
                last_y: 100,
            },
            Some(window(20, "Canvas")),
            Some(MousePosition { x: 200, y: 200 }),
            base + Duration::from_secs(60),
        );
        assert!(movement_after_resync.is_empty());

        let up = state.on_raw_mouse(
            RawMouseEvent {
                flags: 0,
                button_flags: RI_MOUSE_LEFT_BUTTON_UP as u16,
                button_data: 0,
                last_x: 0,
                last_y: 0,
            },
            Some(window(20, "Canvas")),
            Some(MousePosition { x: 200, y: 200 }),
            base + Duration::from_secs(61),
        );
        assert_eq!(up.len(), 1);
        assert!(matches!(up[0].payload, EventPayload::MouseMove { .. }));
    }

    #[test]
    fn mouse_state_boundary_reset_drops_active_button_and_click_memory() {
        let mut state = MouseState::default();
        let base = Instant::now();
        state.active_buttons.insert(
            MouseButton::Left,
            ActiveMouseButton::new(
                MouseButton::Left,
                Some(MousePosition { x: 100, y: 100 }),
                Some(window(20, "Canvas")),
                base,
                None,
                true,
            ),
        );
        state.last_completed_click = Some(CompletedMouseClick {
            button: MouseButton::Left,
            started_at: base,
            x: Some(100),
            y: Some(100),
            hwnd: Some(20),
        });

        state.reset_after_boundary();

        assert!(state.active_buttons.is_empty());
        assert!(state.last_completed_click.is_none());
        let up = state.on_raw_mouse(
            RawMouseEvent {
                flags: 0,
                button_flags: RI_MOUSE_LEFT_BUTTON_UP as u16,
                button_data: 0,
                last_x: 0,
                last_y: 0,
            },
            Some(window(20, "Canvas")),
            Some(MousePosition { x: 130, y: 130 }),
            base + Duration::from_millis(100),
        );
        assert!(up.is_empty());
    }

    #[test]
    fn mouse_state_includes_same_packet_movement_before_click() {
        let mut state = MouseState::default();
        let base = Instant::now();

        assert!(state
            .on_raw_mouse(
                RawMouseEvent {
                    flags: 0,
                    button_flags: 0,
                    button_data: 0,
                    last_x: 3,
                    last_y: 4,
                },
                None,
                None,
                base,
            )
            .is_empty());

        let click = state.on_raw_mouse(
            RawMouseEvent {
                flags: 0,
                button_flags: RI_MOUSE_LEFT_BUTTON_DOWN as u16,
                button_data: 0,
                last_x: 5,
                last_y: -1,
            },
            None,
            Some(MousePosition { x: 305, y: 399 }),
            base + Duration::from_millis(10),
        );

        assert_eq!(click.len(), 2);
        match &click[0].payload {
            EventPayload::MouseMove {
                dx_total,
                dy_total,
                raw_event_count,
                duration_ms,
                x,
                y,
                ..
            } => {
                assert_eq!(*dx_total, 8);
                assert_eq!(*dy_total, 3);
                assert_eq!(*raw_event_count, 2);
                assert_eq!(*duration_ms, 10);
                assert_eq!(*x, Some(305));
                assert_eq!(*y, Some(399));
            }
            _ => panic!("expected mouse move before click"),
        }
        match &click[1].payload {
            EventPayload::MouseClick { button, .. } => assert_eq!(*button, MouseButton::Left),
            _ => panic!("expected mouse click"),
        }
    }

    #[test]
    fn mouse_state_coalesces_movement_until_interval_or_final_flush() {
        let mut state = MouseState::default();
        let base = Instant::now();

        assert!(state
            .on_raw_mouse(
                RawMouseEvent {
                    flags: 0,
                    button_flags: 0,
                    button_data: 0,
                    last_x: 3,
                    last_y: 4,
                },
                Some(window(10, "Editor")),
                Some(MousePosition { x: 100, y: 200 }),
                base,
            )
            .is_empty());

        let emitted = state.on_raw_mouse(
            RawMouseEvent {
                flags: 0,
                button_flags: 0,
                button_data: 0,
                last_x: -1,
                last_y: 2,
            },
            Some(window(11, "Browser")),
            Some(MousePosition { x: 101, y: 202 }),
            base + MOUSE_MOVE_FLUSH_INTERVAL,
        );

        assert_eq!(emitted.len(), 1);
        match &emitted[0].payload {
            EventPayload::MouseMove {
                dx_total,
                dy_total,
                distance_px,
                raw_event_count,
                duration_ms,
                x,
                y,
                window,
                ..
            } => {
                assert_eq!(*dx_total, 2);
                assert_eq!(*dy_total, 6);
                assert_eq!(*distance_px, 7);
                assert_eq!(*raw_event_count, 2);
                assert_eq!(*duration_ms, 250);
                assert_eq!(*x, Some(101));
                assert_eq!(*y, Some(202));
                assert_eq!(window.as_ref().expect("window").title, "Browser");
            }
            _ => panic!("expected mouse move"),
        }

        assert!(state
            .on_raw_mouse(
                RawMouseEvent {
                    flags: 0,
                    button_flags: 0,
                    button_data: 0,
                    last_x: 1,
                    last_y: 1,
                },
                None,
                None,
                base + Duration::from_millis(300),
            )
            .is_empty());

        let flushed = state
            .flush_pending(base + Duration::from_millis(1_000))
            .expect("pending move flushed");
        match &flushed.payload {
            EventPayload::MouseMove {
                dx_total,
                dy_total,
                duration_ms,
                ..
            } => {
                assert_eq!(*dx_total, 1);
                assert_eq!(*dy_total, 1);
                assert_eq!(*duration_ms, 0);
            }
            _ => panic!("expected mouse move"),
        }
    }

    #[test]
    fn pinned_center_raw_mouse_deltas_mark_remote_relay_suspected() {
        let mut state = MouseState::default();
        let base = Instant::now();
        let center = current_virtual_screen().center();
        state.last_cursor_position = Some(center);

        assert!(state
            .on_raw_mouse(
                RawMouseEvent {
                    flags: 0,
                    button_flags: 0,
                    button_data: 0,
                    last_x: 3,
                    last_y: 4,
                },
                None,
                Some(center),
                base,
            )
            .is_empty());
        let emitted = state.on_raw_mouse(
            RawMouseEvent {
                flags: 0,
                button_flags: 0,
                button_data: 0,
                last_x: -2,
                last_y: 1,
            },
            None,
            Some(center),
            base + MOUSE_MOVE_FLUSH_INTERVAL,
        );

        assert_eq!(emitted.len(), 1);
        match &emitted[0].payload {
            EventPayload::MouseMove { input_origin, .. } => {
                assert_eq!(*input_origin, Some(InputOrigin::RemoteRelaySuspected));
            }
            _ => panic!("expected mouse move"),
        }

        let click = state.on_raw_mouse(
            RawMouseEvent {
                flags: 0,
                button_flags: RI_MOUSE_LEFT_BUTTON_DOWN as u16,
                button_data: 0,
                last_x: 0,
                last_y: 0,
            },
            None,
            Some(center),
            base + MOUSE_MOVE_FLUSH_INTERVAL + Duration::from_millis(1),
        );
        match &click[0].payload {
            EventPayload::MouseClick { input_origin, .. } => {
                assert_eq!(*input_origin, Some(InputOrigin::RemoteRelaySuspected));
            }
            _ => panic!("expected mouse click"),
        }
    }

    #[test]
    fn normal_local_mouse_movement_does_not_mark_remote_relay() {
        let mut state = MouseState::default();
        let base = Instant::now();
        let center = current_virtual_screen().center();
        state.last_cursor_position = Some(center);

        let _ = state.on_raw_mouse(
            RawMouseEvent {
                flags: 0,
                button_flags: 0,
                button_data: 0,
                last_x: 3,
                last_y: 4,
            },
            None,
            Some(MousePosition {
                x: center.x.saturating_add(3),
                y: center.y.saturating_add(4),
            }),
            base,
        );
        let emitted = state.on_raw_mouse(
            RawMouseEvent {
                flags: 0,
                button_flags: 0,
                button_data: 0,
                last_x: 1,
                last_y: 1,
            },
            None,
            Some(MousePosition {
                x: center.x.saturating_add(4),
                y: center.y.saturating_add(5),
            }),
            base + MOUSE_MOVE_FLUSH_INTERVAL,
        );

        match &emitted[0].payload {
            EventPayload::MouseMove { input_origin, .. } => {
                assert_eq!(*input_origin, None);
            }
            _ => panic!("expected mouse move"),
        }
    }

    #[test]
    fn absolute_mouse_movement_does_not_mark_remote_relay() {
        let raw = RawMouseEvent {
            flags: MOUSE_MOVE_ABSOLUTE.0,
            button_flags: 0,
            button_data: 0,
            last_x: 40_000,
            last_y: 40_000,
        };
        let center = MousePosition { x: 500, y: 400 };

        assert!(!remote_relay_signature(
            raw,
            Some(center),
            Some(center),
            screen(0, 0, 1_000, 800)
        ));
    }

    #[test]
    fn stationary_center_cursor_does_not_mark_remote_relay() {
        let raw = RawMouseEvent {
            flags: 0,
            button_flags: RI_MOUSE_LEFT_BUTTON_DOWN as u16,
            button_data: 0,
            last_x: 0,
            last_y: 0,
        };
        let center = MousePosition { x: 500, y: 400 };

        assert!(!remote_relay_signature(
            raw,
            Some(center),
            Some(center),
            screen(0, 0, 1_000, 800)
        ));
    }

    #[test]
    fn absolute_mouse_movement_uses_cursor_deltas() {
        let mut state = MouseState::default();
        let base = Instant::now();

        assert!(state
            .on_raw_mouse(
                RawMouseEvent {
                    flags: MOUSE_MOVE_ABSOLUTE.0,
                    button_flags: 0,
                    button_data: 0,
                    last_x: 40_000,
                    last_y: 40_000,
                },
                None,
                Some(MousePosition { x: 100, y: 100 }),
                base,
            )
            .is_empty());

        let emitted = state.on_raw_mouse(
            RawMouseEvent {
                flags: MOUSE_MOVE_ABSOLUTE.0,
                button_flags: 0,
                button_data: 0,
                last_x: 60_000,
                last_y: 10_000,
            },
            None,
            Some(MousePosition { x: 105, y: 90 }),
            base + MOUSE_MOVE_FLUSH_INTERVAL,
        );

        assert_eq!(emitted.len(), 1);
        match &emitted[0].payload {
            EventPayload::MouseMove {
                dx_total,
                dy_total,
                distance_px,
                raw_event_count,
                ..
            } => {
                assert_eq!(*dx_total, 5);
                assert_eq!(*dy_total, -10);
                assert_eq!(*distance_px, 11);
                assert_eq!(*raw_event_count, 2);
            }
            _ => panic!("expected mouse move"),
        }
    }

    #[test]
    fn raw_input_parser_reads_keyboard_payload_without_mouse_tail() {
        let keyboard = RAWKEYBOARD {
            VKey: 0x41,
            Flags: RI_KEY_BREAK,
            ..Default::default()
        };
        let bytes = raw_input_packet(RIM_TYPEKEYBOARD.0, &keyboard);

        assert_eq!(
            bytes.len(),
            size_of::<RAWINPUTHEADER>() + size_of::<RAWKEYBOARD>()
        );
        match raw_input_from_bytes(&bytes).expect("keyboard packet parsed") {
            RawInputEvent::Keyboard(parsed) => {
                assert_eq!(parsed.vkey, 0x41);
                assert_eq!(parsed.flags, RI_KEY_BREAK);
            }
            RawInputEvent::Mouse(_) => panic!("expected keyboard packet"),
        }

        assert!(raw_input_from_bytes(&bytes[..bytes.len() - 1]).is_none());
    }

    #[test]
    fn key_to_string_names_common_keys() {
        assert_eq!(key_to_string(0x41), "A");
        assert_eq!(key_to_string(0x70), "F1");
        assert_eq!(key_to_string(0x25), "ArrowLeft");
        assert_eq!(key_to_string(0xff), "VK_0xff");
    }
}
