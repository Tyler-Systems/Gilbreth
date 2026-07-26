//! Canonical first-run consent copy used by the product dialog.

pub const CONSENT_DIALOG_TITLE: &str = "Before Gilbreth starts recording";

pub const CONSENT_DIALOG_BODY: &str = "Gilbreth records how this machine is used (apps, window titles, input timing) into a local database. Nothing leaves this machine, and Gilbreth sees this machine only.\n\nBy default, typing is recorded lean: how much and when you type, never which keys. You can instead store typed key content, which records what you type, key by key.\n\nWindow titles are kept 30 days by default. While the tray icon is visible, Gilbreth records whoever is using this session. Observing your own work changes it at first, so the first days can look unusual. Baselines settle over time.\n\nYou can change any of this later from the tray icon's Privacy menu or the dashboard's Privacy tab.\n\nYes: store typed key content\nNo: keep lean capture (the default)\nCancel: decide later. Gilbreth stays lean and asks again next launch.";
