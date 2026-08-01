//! Linux tray shell (LIN-1): the StatusNotifierItem backend behind a
//! deliberately `tray-icon`-shaped facade, so the shared `Tray` in `main.rs`
//! builds its menu and drives checkmarks/labels/icon identically on all
//! three platforms while this module speaks SNI + dbusmenu through `ksni`
//! (the recorded LIN-1 tray decision: no GTK/libappindicator, the panel
//! renders the menu natively).
//!
//! Shape differences absorbed here, not in `main.rs`:
//! - `tray-icon` is immediate-mode (items are live handles); SNI is
//!   retained-mode (the panel pulls a menu layout). Items therefore share
//!   state cells with the ksni render, and every setter nudges the service
//!   to publish a new revision.
//! - `tray-icon` delivers menu activations through a global channel; the
//!   same channel exists here, fed by the ksni activation closures (which
//!   run on the service thread), and each activation wakes the capture pump
//!   so the service pass consumes the event immediately.
//! - muda auto-toggles a `CheckMenuItem` before the app handler runs; SNI
//!   checkmarks render only from our state. The shared handlers already
//!   derive state from config and force the checkmark afterwards, so both
//!   backends converge on the same final state.

use std::sync::{Arc, Mutex, OnceLock, RwLock};

use anyhow::{anyhow, Context, Result};
use crossbeam_channel::{unbounded, Receiver, Sender};
use ksni::blocking::TrayMethods;
use tracing::warn;

/// Menu item identity, matching `tray_icon::menu::MenuId`'s public `.0`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MenuId(pub String);

impl MenuId {
    pub fn new(id: &str) -> Self {
        Self(id.to_string())
    }
}

/// A menu activation, matching `tray_icon::menu::MenuEvent`'s `.id` field.
#[derive(Clone, Debug)]
pub struct MenuEvent {
    pub id: MenuId,
}

fn menu_channel() -> &'static (Sender<MenuEvent>, Receiver<MenuEvent>) {
    static CHANNEL: OnceLock<(Sender<MenuEvent>, Receiver<MenuEvent>)> = OnceLock::new();
    CHANNEL.get_or_init(unbounded)
}

impl MenuEvent {
    /// The global activation receiver, the `tray-icon` contract the shared
    /// tray handler polls each service pass.
    pub fn receiver() -> &'static Receiver<MenuEvent> {
        &menu_channel().1
    }
}

/// One SNI tray per process (the same singleton shape as the capture pump's
/// registration): setters on items reach the live service through here.
static TRAY_HANDLE: RwLock<Option<ksni::blocking::Handle<SniTray>>> = RwLock::new(None);

/// Publish a new menu/icon revision after a state change. Quiet before the
/// service spawns (Tray::new mutates items it has not yet attached) and
/// after it exits.
fn notify_tray() {
    let guard = match TRAY_HANDLE.read() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    if let Some(handle) = guard.as_ref() {
        // State lives in the shared cells; the closure only forces ksni to
        // re-read them and publish.
        handle.update(|_| {});
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ItemKind {
    Plain,
    Check { checked: bool },
}

// Same module-privacy note as `Entry`: named by the facade types only.
pub struct ItemState {
    id: String,
    label: String,
    enabled: bool,
    kind: ItemKind,
}

type SharedItem = Arc<Mutex<ItemState>>;

fn lock_item(item: &SharedItem) -> std::sync::MutexGuard<'_, ItemState> {
    match item.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

// `pub` only in the module-privacy sense: the module itself is private to
// the crate, and `main.rs` never names this type — it exists so the
// `IsMenuItem` facade trait can return it.
#[derive(Clone)]
pub enum Entry {
    Leaf(SharedItem),
    Separator,
    Sub(Submenu),
}

/// The `tray-icon` append contract: anything a menu can hold.
pub trait IsMenuItem {
    fn entry(&self) -> Entry;
}

#[derive(Clone)]
pub struct Menu {
    entries: Arc<Mutex<Vec<Entry>>>,
}

impl Menu {
    #[allow(clippy::new_without_default)] // mirrors tray_icon::menu::Menu::new
    pub fn new() -> Self {
        Self {
            entries: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn append(&self, item: &dyn IsMenuItem) -> Result<()> {
        self.entries
            .lock()
            .map_err(|_| anyhow!("menu state poisoned"))?
            .push(item.entry());
        Ok(())
    }
}

#[derive(Clone)]
pub struct Submenu {
    label: Arc<Mutex<String>>,
    enabled: bool,
    entries: Arc<Mutex<Vec<Entry>>>,
}

impl Submenu {
    pub fn new(label: &str, enabled: bool) -> Self {
        Self {
            label: Arc::new(Mutex::new(label.to_string())),
            enabled,
            entries: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn append(&self, item: &dyn IsMenuItem) -> Result<()> {
        self.entries
            .lock()
            .map_err(|_| anyhow!("submenu state poisoned"))?
            .push(item.entry());
        Ok(())
    }

    pub fn append_items(&self, items: &[&dyn IsMenuItem]) -> Result<()> {
        for item in items {
            self.append(*item)?;
        }
        Ok(())
    }
}

impl IsMenuItem for Submenu {
    fn entry(&self) -> Entry {
        Entry::Sub(self.clone())
    }
}

#[derive(Clone)]
pub struct MenuItem {
    state: SharedItem,
}

impl MenuItem {
    pub fn with_id(id: MenuId, label: &str, enabled: bool, _accelerator: Option<()>) -> Self {
        Self {
            state: Arc::new(Mutex::new(ItemState {
                id: id.0,
                label: label.to_string(),
                enabled,
                kind: ItemKind::Plain,
            })),
        }
    }

    pub fn set_enabled(&self, enabled: bool) {
        lock_item(&self.state).enabled = enabled;
        notify_tray();
    }

    pub fn set_text(&self, label: &str) {
        lock_item(&self.state).label = label.to_string();
        notify_tray();
    }
}

impl IsMenuItem for MenuItem {
    fn entry(&self) -> Entry {
        Entry::Leaf(Arc::clone(&self.state))
    }
}

#[derive(Clone)]
pub struct CheckMenuItem {
    state: SharedItem,
}

impl CheckMenuItem {
    pub fn with_id(
        id: MenuId,
        label: &str,
        enabled: bool,
        checked: bool,
        _accelerator: Option<()>,
    ) -> Self {
        Self {
            state: Arc::new(Mutex::new(ItemState {
                id: id.0,
                label: label.to_string(),
                enabled,
                kind: ItemKind::Check { checked },
            })),
        }
    }

    pub fn set_checked(&self, checked: bool) {
        lock_item(&self.state).kind = ItemKind::Check { checked };
        notify_tray();
    }

    #[allow(dead_code)] // facade parity with the tray-icon surface
    pub fn set_enabled(&self, enabled: bool) {
        lock_item(&self.state).enabled = enabled;
        notify_tray();
    }
}

impl IsMenuItem for CheckMenuItem {
    fn entry(&self) -> Entry {
        Entry::Leaf(Arc::clone(&self.state))
    }
}

pub struct PredefinedMenuItem;

impl PredefinedMenuItem {
    pub fn separator() -> Self {
        Self
    }
}

impl IsMenuItem for PredefinedMenuItem {
    fn entry(&self) -> Entry {
        Entry::Separator
    }
}

/// RGBA icon bytes, matching `tray_icon::Icon::from_rgba`'s validation.
#[derive(Clone)]
pub struct Icon {
    width: u32,
    height: u32,
    rgba: Vec<u8>,
}

impl Icon {
    pub fn from_rgba(rgba: Vec<u8>, width: u32, height: u32) -> Result<Self> {
        let expected = width as usize * height as usize * 4;
        if rgba.len() != expected {
            return Err(anyhow!(
                "icon byte length {} does not match {width}x{height} RGBA",
                rgba.len()
            ));
        }
        Ok(Self {
            width,
            height,
            rgba,
        })
    }

    /// SNI wants ARGB32 in network byte order: rotate each RGBA pixel right.
    fn to_sni(&self) -> ksni::Icon {
        let mut data = self.rgba.clone();
        for pixel in data.chunks_exact_mut(4) {
            pixel.rotate_right(1);
        }
        ksni::Icon {
            width: self.width as i32,
            height: self.height as i32,
            data,
        }
    }
}

/// Mutable tray-wide state shared between the app-side handles and the ksni
/// service render.
struct TrayShared {
    entries: Arc<Mutex<Vec<Entry>>>,
    icon: Mutex<ksni::Icon>,
    tooltip: Mutex<String>,
}

fn lock<'a, T>(mutex: &'a Mutex<T>, what: &str) -> std::sync::MutexGuard<'a, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            warn!(
                what,
                "tray state mutex poisoned; continuing with the inner value"
            );
            poisoned.into_inner()
        }
    }
}

struct SniTray {
    shared: Arc<TrayShared>,
}

fn render_entries(entries: &[Entry]) -> Vec<ksni::MenuItem<SniTray>> {
    entries
        .iter()
        .map(|entry| match entry {
            Entry::Separator => ksni::MenuItem::Separator,
            Entry::Leaf(item) => {
                let state = lock_item(item);
                let id = state.id.clone();
                match state.kind {
                    ItemKind::Plain => ksni::MenuItem::Standard(ksni::menu::StandardItem {
                        label: state.label.clone(),
                        enabled: state.enabled,
                        activate: Box::new(move |_tray: &mut SniTray| emit_menu_event(&id)),
                        ..Default::default()
                    }),
                    ItemKind::Check { checked } => {
                        ksni::MenuItem::Checkmark(ksni::menu::CheckmarkItem {
                            label: state.label.clone(),
                            enabled: state.enabled,
                            checked,
                            activate: Box::new(move |_tray: &mut SniTray| emit_menu_event(&id)),
                            ..Default::default()
                        })
                    }
                }
            }
            Entry::Sub(submenu) => ksni::MenuItem::SubMenu(ksni::menu::SubMenu {
                label: lock(&submenu.label, "submenu label").clone(),
                enabled: submenu.enabled,
                submenu: render_entries(&lock(&submenu.entries, "submenu entries")),
                ..Default::default()
            }),
        })
        .collect()
}

/// Runs on the ksni service thread: hand the activation to the pump-thread
/// handler through the global channel, then wake the pump so the handoff is
/// immediate rather than waiting out a service tick.
fn emit_menu_event(id: &str) {
    let _ = menu_channel().0.send(MenuEvent {
        id: MenuId(id.to_string()),
    });
    gilbreth_capture_linux::wake_pump();
}

impl ksni::Tray for SniTray {
    fn id(&self) -> String {
        "gilbreth".to_string()
    }

    fn title(&self) -> String {
        "Gilbreth".to_string()
    }

    fn category(&self) -> ksni::Category {
        ksni::Category::ApplicationStatus
    }

    fn icon_pixmap(&self) -> Vec<ksni::Icon> {
        vec![lock(&self.shared.icon, "icon").clone()]
    }

    fn tool_tip(&self) -> ksni::ToolTip {
        ksni::ToolTip {
            title: lock(&self.shared.tooltip, "tooltip").clone(),
            ..Default::default()
        }
    }

    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        render_entries(&lock(&self.shared.entries, "menu entries"))
    }
}

pub struct TrayIconBuilder {
    menu: Option<Box<Menu>>,
    tooltip: String,
    icon: Option<Icon>,
}

impl TrayIconBuilder {
    #[allow(clippy::new_without_default)] // mirrors tray_icon::TrayIconBuilder
    pub fn new() -> Self {
        Self {
            menu: None,
            tooltip: String::new(),
            icon: None,
        }
    }

    pub fn with_menu(mut self, menu: Box<Menu>) -> Self {
        self.menu = Some(menu);
        self
    }

    pub fn with_tooltip(mut self, tooltip: &str) -> Self {
        self.tooltip = tooltip.to_string();
        self
    }

    pub fn with_icon(mut self, icon: Icon) -> Self {
        self.icon = Some(icon);
        self
    }

    /// Template rendering is a macOS menu-bar concept; SNI panels tint by
    /// theme on their own. Accepted for call-site parity, ignored.
    pub fn with_icon_as_template(self, _template: bool) -> Self {
        self
    }

    pub fn build(self) -> Result<TrayIcon> {
        let menu = self
            .menu
            .ok_or_else(|| anyhow!("tray built without a menu"))?;
        let icon = self
            .icon
            .ok_or_else(|| anyhow!("tray built without an icon"))?;
        let shared = Arc::new(TrayShared {
            entries: Arc::clone(&menu.entries),
            icon: Mutex::new(icon.to_sni()),
            tooltip: Mutex::new(self.tooltip),
        });
        let handle = SniTray {
            shared: Arc::clone(&shared),
        }
        .spawn()
        .context("StatusNotifierItem registration failed (is a status-notifier host running?)")?;
        {
            let mut slot = match TRAY_HANDLE.write() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            *slot = Some(handle.clone());
        }
        Ok(TrayIcon { shared, handle })
    }
}

pub struct TrayIcon {
    shared: Arc<TrayShared>,
    handle: ksni::blocking::Handle<SniTray>,
}

/// The update-path error type. SNI updates cannot fail today (state lands
/// in shared cells; a gone service just ignores the nudge), but the shared
/// call sites map tray errors into `anyhow`, so this must be a std error
/// distinct from `anyhow::Error` — the same shape `tray_icon::Error` has.
#[derive(Debug)]
pub struct TrayUpdateError;

impl std::fmt::Display for TrayUpdateError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("tray update failed")
    }
}

impl std::error::Error for TrayUpdateError {}

impl TrayIcon {
    pub fn set_icon(&self, icon: Option<Icon>) -> Result<(), TrayUpdateError> {
        if let Some(icon) = icon {
            *lock(&self.shared.icon, "icon") = icon.to_sni();
            self.handle.update(|_| {});
        }
        Ok(())
    }

    pub fn set_tooltip(&self, tooltip: Option<&str>) -> Result<(), TrayUpdateError> {
        *lock(&self.shared.tooltip, "tooltip") = tooltip.unwrap_or_default().to_string();
        self.handle.update(|_| {});
        Ok(())
    }
}

impl Drop for TrayIcon {
    fn drop(&mut self) {
        {
            let mut slot = match TRAY_HANDLE.write() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            *slot = None;
        }
        // Bounded: ask the service to leave the bus so the panel drops the
        // icon with the process still alive to answer the final calls.
        self.handle.shutdown().wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn menu_model_renders_items_checks_separators_and_submenus() {
        let menu = Menu::new();
        let submenu = Submenu::new("Capture", true);
        let check = CheckMenuItem::with_id(MenuId::new("check"), "Foreground", true, true, None);
        let plain = MenuItem::with_id(MenuId::new("open"), "Open Dashboard", true, None);
        submenu
            .append_items(&[&check])
            .expect("submenu append works");
        menu.append(&submenu).expect("append submenu");
        menu.append(&plain).expect("append item");
        menu.append(&PredefinedMenuItem::separator())
            .expect("append separator");

        let rendered = render_entries(&menu.entries.lock().expect("entries"));
        assert_eq!(rendered.len(), 3);
        match &rendered[0] {
            ksni::MenuItem::SubMenu(sub) => {
                assert_eq!(sub.label, "Capture");
                assert_eq!(sub.submenu.len(), 1);
                match &sub.submenu[0] {
                    ksni::MenuItem::Checkmark(item) => {
                        assert_eq!(item.label, "Foreground");
                        assert!(item.checked);
                    }
                    _ => panic!("expected a checkmark inside the submenu"),
                }
            }
            _ => panic!("expected a submenu first"),
        }
        assert!(matches!(rendered[1], ksni::MenuItem::Standard(_)));
        assert!(matches!(rendered[2], ksni::MenuItem::Separator));
    }

    #[test]
    fn setters_change_what_the_next_render_reports() {
        let check = CheckMenuItem::with_id(MenuId::new("c"), "Keyboard", true, false, None);
        let plain = MenuItem::with_id(MenuId::new("p"), "Pause capture", true, None);
        let menu = Menu::new();
        menu.append(&check).expect("append");
        menu.append(&plain).expect("append");

        check.set_checked(true);
        plain.set_text("Resume capture");
        plain.set_enabled(false);

        let rendered = render_entries(&menu.entries.lock().expect("entries"));
        match &rendered[0] {
            ksni::MenuItem::Checkmark(item) => assert!(item.checked),
            _ => panic!("expected checkmark"),
        }
        match &rendered[1] {
            ksni::MenuItem::Standard(item) => {
                assert_eq!(item.label, "Resume capture");
                assert!(!item.enabled);
            }
            _ => panic!("expected standard item"),
        }
    }

    #[test]
    fn activation_closures_feed_the_global_menu_channel() {
        let item = MenuItem::with_id(MenuId::new("quit"), "Quit", true, None);
        let rendered = render_entries(&[item.entry()]);
        let mut tray = SniTray {
            shared: Arc::new(TrayShared {
                entries: Arc::new(Mutex::new(Vec::new())),
                icon: Mutex::new(ksni::Icon {
                    width: 1,
                    height: 1,
                    data: vec![0, 0, 0, 0],
                }),
                tooltip: Mutex::new(String::new()),
            }),
        };
        match rendered.into_iter().next().expect("one item") {
            ksni::MenuItem::Standard(standard) => (standard.activate)(&mut tray),
            _ => panic!("expected standard item"),
        }
        let event = MenuEvent::receiver()
            .try_recv()
            .expect("activation reached the channel");
        assert_eq!(event.id.0, "quit");
    }

    #[test]
    fn icon_validation_matches_the_tray_icon_contract_and_converts_to_argb() {
        assert!(Icon::from_rgba(vec![0; 5], 1, 1).is_err());
        let icon = Icon::from_rgba(vec![1, 2, 3, 4], 1, 1).expect("valid 1x1");
        let sni = icon.to_sni();
        assert_eq!(sni.data, vec![4, 1, 2, 3], "RGBA rotated to ARGB");
    }
}
