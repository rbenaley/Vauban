//! Rust pin for the audit WORM lint script.
//!
//! `vauban-audit/scripts/check_audit_worm.sh` enforces the structural
//! invariants of the tamper-evident audit log (hash chain + Ed25519 seal,
//! persist-before-ack, fail-closed `AuditNack`, no `TODO` stub). A developer
//! running `cargo test --workspace` should trip the same invariants without
//! shelling out manually. Mirrors `vauban-vault/tests/authz_lint_test.rs`.

// Integration-test crate: unwrap/expect/panic are idiomatic here (the
// workspace denies them in production code).
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::path::PathBuf;
use std::process::Command;

fn script_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("scripts")
        .join("check_audit_worm.sh")
}

#[test]
fn check_audit_worm_passes() {
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
        "check_audit_worm.sh failed:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

/// The script must exist and be executable (catches a `git reset` dropping
/// the executable bit).
#[test]
fn audit_worm_lint_script_exists_and_executable() {
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

/// The script body must keep guarding against the core WORM regressions.
#[test]
fn audit_worm_lint_script_covers_core_invariants() {
    let body = std::fs::read_to_string(script_path()).expect("read script");
    for needle in [
        "TODO: Write to WORM",
        "fn append_event",
        "fn seal",
        "fn verify_reader",
        "expected: &VerifyingKey",
        "PubkeyMismatch",
        "blake3::Hasher",
        "AuditNack",
        "events_failed",
        "sync_all",
    ] {
        assert!(
            body.contains(needle),
            "check_audit_worm.sh must still reference `{needle}` -- \
             removing the grep loosens a WORM invariant."
        );
    }
}
