//! Lane B enforcement: the dashboard's copy-style audit
//! (docs/MAINTAINING.md, Product-copy rules).
//!
//! Walks the whole `src/` tree at test time and audits production
//! literals in const/static declarations, arrays, inline expressions,
//! and reconstructed `concat!`/`format!` copy against the shared law in
//! `gilbreth_core::copy_style`. Strict `// copy-allow:` annotations sit
//! beside deliberate exceptions. Copy whose words come from runtime
//! values is also audited as produced output in each module's own test
//! block, beside the tests that pin those strings.

use gilbreth_core::copy_style;

#[test]
fn production_copy_source_passes_the_copy_style_law() {
    let violations = copy_style::audit_crate_src("gilbreth-dashboard", env!("CARGO_MANIFEST_DIR"));
    copy_style::assert_no_violations(&violations);
}
