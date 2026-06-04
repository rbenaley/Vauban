//! VAU-002 -- Rust pin for the vault authorization lint script.
//!
//! `vauban-vault/scripts/check_vault_authz.sh` enforces the structural
//! invariants of the per-peer capability matrix (gate before crypto,
//! fail-closed catch-all, anomaly counter, no unguarded forwarding arm).
//! A developer running `cargo test --workspace` should trip the same
//! invariants without shelling out manually. Mirrors
//! `vauban-web/tests/web/rdp_cert_lints_test.rs`.

// Integration-test crate: unwrap/expect/panic are idiomatic here (the
// workspace denies them in production code).
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::path::PathBuf;
use std::process::Command;

fn script_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("scripts")
        .join("check_vault_authz.sh")
}

#[test]
fn check_vault_authz_passes() {
    let script = script_path();
    assert!(
        script.exists(),
        "lint script not found: {}",
        script.display()
    );

    let out = Command::new("bash")
        .arg(&script)
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn {}: {}", script.display(), e));

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "check_vault_authz.sh failed:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

/// The script must exist and be executable (catches a `git reset` dropping
/// the executable bit).
#[test]
fn vault_authz_lint_script_exists_and_executable() {
    use std::os::unix::fs::PermissionsExt;
    let path = script_path();
    assert!(path.exists(), "missing lint script: {}", path.display());
    let meta = std::fs::metadata(&path).expect("metadata");
    let mode = meta.permissions().mode();
    assert!(
        mode & 0o111 != 0,
        "lint script not executable: {} (mode={:o})",
        path.display(),
        mode
    );
}

/// The script body must keep guarding against the core VAU-002 regressions.
/// A future cleanup that loosens these greps must update this list
/// deliberately.
#[test]
fn vault_authz_lint_script_covers_core_invariants() {
    let body = std::fs::read_to_string(script_path()).expect("read script");
    for needle in [
        "fn is_authorized",
        "VaultPeer::Supervisor",
        "_ => false",
        "_ => true",
        "requests_denied",
        "fn deny_vault_request",
        "authz::is_authorized",
        "handle_vault_request",
    ] {
        assert!(
            body.contains(needle),
            "check_vault_authz.sh must still reference `{needle}` -- \
             removing the grep loosens a VAU-002 invariant."
        );
    }
}
