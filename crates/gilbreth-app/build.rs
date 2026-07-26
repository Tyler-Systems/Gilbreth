use std::{env, process::Command};

const WINDOWS_ICON_RESOURCE: &str = "assets/windows/gilbreth.rc";
const WINDOWS_ICON: &str = "assets/windows/gilbreth.ico";

fn main() {
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/refs/heads");
    println!("cargo:rerun-if-changed=../../.git/packed-refs");
    println!("cargo:rerun-if-env-changed=GILBRETH_BUILD_GIT_SHA");
    println!("cargo:rerun-if-env-changed=GILBRETH_PACKAGE_TRUST_MODE");
    println!("cargo:rerun-if-env-changed=GILBRETH_PACKAGE_SIGNER_SUBJECT");
    println!("cargo:rerun-if-changed={WINDOWS_ICON_RESOURCE}");
    println!("cargo:rerun-if-changed={WINDOWS_ICON}");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        embed_resource::compile_for(
            WINDOWS_ICON_RESOURCE,
            ["gilbreth-app"],
            embed_resource::NONE,
        )
        .manifest_required()
        .expect("the Gilbreth Windows icon resource must compile");
    }

    let git_sha = match env::var("GILBRETH_BUILD_GIT_SHA") {
        Ok(value)
            if value.len() == 12
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()) =>
        {
            value
        }
        Ok(_) => panic!("GILBRETH_BUILD_GIT_SHA must be exactly 12 lowercase hex characters"),
        Err(_) => Command::new("git")
            .args(["rev-parse", "--short=12", "HEAD"])
            .output()
            .ok()
            .filter(|output| output.status.success())
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .map(|sha| sha.trim().to_string())
            .filter(|sha| !sha.is_empty())
            .unwrap_or_else(|| "unknown".to_string()),
    };

    println!("cargo:rustc-env=GILBRETH_GIT_SHA={git_sha}");

    let trust_mode =
        env::var("GILBRETH_PACKAGE_TRUST_MODE").unwrap_or_else(|_| "development".to_string());
    if !matches!(trust_mode.as_str(), "development" | "release-package") {
        panic!("unsupported GILBRETH_PACKAGE_TRUST_MODE");
    }
    let signer_subject = env::var("GILBRETH_PACKAGE_SIGNER_SUBJECT").unwrap_or_default();
    if trust_mode == "release-package"
        && (signer_subject.is_empty()
            || signer_subject.len() > 200
            || signer_subject.chars().any(char::is_control))
    {
        panic!("release-package builds require a bounded signer subject");
    }
    if trust_mode != "release-package" && !signer_subject.is_empty() {
        panic!("only release-package builds may embed a signer subject");
    }
    println!("cargo:rustc-env=GILBRETH_PACKAGE_TRUST_MODE={trust_mode}");
    println!("cargo:rustc-env=GILBRETH_PACKAGE_SIGNER_SUBJECT={signer_subject}");
}
