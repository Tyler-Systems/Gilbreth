use std::{env, path::PathBuf};

const HELPER_BIN: &str = "gilbreth-elevated-record-helper";
const LOCAL_MANIFEST: &str = "manifests/gilbreth-elevated-record-helper.local.manifest";
const UIACCESS_MANIFEST: &str = "manifests/gilbreth-elevated-record-helper.uiaccess.manifest";

fn main() {
    println!("cargo:rerun-if-changed={LOCAL_MANIFEST}");
    println!("cargo:rerun-if-changed={UIACCESS_MANIFEST}");

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_os != "windows" || target_env != "msvc" {
        return;
    }

    let manifest = if env::var_os("CARGO_FEATURE_UIACCESS_HELPER_MANIFEST").is_some() {
        UIACCESS_MANIFEST
    } else {
        LOCAL_MANIFEST
    };
    let manifest_path =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string()))
            .join(manifest);
    if !manifest_path.is_file() {
        panic!("helper manifest should exist: {}", manifest_path.display());
    }
    let manifest_arg = format!("/MANIFESTINPUT:{}", manifest_path.display());

    println!("cargo:rustc-link-arg-bin={HELPER_BIN}=/MANIFEST:EMBED");
    println!("cargo:rustc-link-arg-bin={HELPER_BIN}=/MANIFESTUAC:NO");
    println!("cargo:rustc-link-arg-bin={HELPER_BIN}={manifest_arg}");
}
