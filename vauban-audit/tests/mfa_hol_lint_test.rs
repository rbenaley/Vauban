//! Rust pin for `scripts/check_audit_mfa_hol.sh`.
//!
//! Mirrors `worm_lint_test.rs`: `cargo test -p vauban-audit` must trip the
//! MFA / HOL structural invariants without a manual shell invocation.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::path::PathBuf;
use std::process::Command;

fn script_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("scripts")
        .join("check_audit_mfa_hol.sh")
}

#[test]
fn check_audit_mfa_hol_passes() {
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
        "check_audit_mfa_hol.sh failed:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

#[test]
fn mfa_hol_lint_script_exists_and_executable() {
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

#[test]
fn mfa_hol_lint_script_covers_core_invariants() {
    let body = std::fs::read_to_string(script_path()).expect("read script");
    for needle in [
        "SUPERVISOR_BROKER_TIMEOUT",
        "recv_from_supervisor_until",
        "drain_web_audit_channel",
        "AuditAck",
        "rotate_segment",
        "CRITICAL_ACK_TIMEOUT_SECS",
        "MfaChallengePassed",
        "emit_audit_critical",
        "audit ack timed out",
    ] {
        assert!(
            body.contains(needle),
            "check_audit_mfa_hol.sh must still reference `{needle}`"
        );
    }
}
