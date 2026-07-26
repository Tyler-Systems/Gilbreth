#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! Windows-only binary: the UAC-elevated Record Routine helper has no macOS
//! analog and none is planned (macOS port scope decision, ROADMAP). The
//! Windows implementation lives in `windows_main.rs` unchanged; other targets
//! get a stub so workspace-wide builds succeed (MAC-0).

#[cfg(target_os = "windows")]
mod windows_main;

#[cfg(target_os = "windows")]
fn main() {
    windows_main::main()
}

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("gilbreth-elevated-record-helper is Windows-only.");
    std::process::exit(1);
}
