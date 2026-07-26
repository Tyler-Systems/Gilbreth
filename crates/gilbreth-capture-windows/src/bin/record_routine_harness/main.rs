//! Windows-only dev harness: Record Routine is Windows-only (macOS port
//! scope decision, ROADMAP). The implementation lives in `windows_main.rs`
//! unchanged; other targets get a stub so workspace-wide builds succeed
//! (MAC-0).

#[cfg(target_os = "windows")]
mod windows_main;

#[cfg(target_os = "windows")]
fn main() -> windows_main::HarnessResult<()> {
    windows_main::main()
}

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("record_routine_harness is Windows-only.");
    std::process::exit(1);
}
