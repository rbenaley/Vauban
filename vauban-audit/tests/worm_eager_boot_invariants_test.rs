//! Source invariants for mandatory eager WORM + signing-key boot.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::path::PathBuf;
use std::process::Command;

fn main_rs() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/main.rs");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn script_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("scripts")
        .join("check_audit_worm_eager_boot.sh")
}

#[test]
fn inv_open_helper_exists() {
    let main = main_rs();
    assert!(main.contains("fn open_initial_worm_segment"));
    assert!(main.contains("Idempotent if"));
}

#[test]
fn inv_boot_fail_closed_no_toggle() {
    let main = main_rs();
    assert!(
        !main.contains("VAUBAN_AUDIT_REQUIRED"),
        "VAUBAN_AUDIT_REQUIRED toggle must stay removed"
    );
    assert!(
        !main.contains("audit_required"),
        "audit_required field must stay removed"
    );
    assert!(main.contains("refusing to start without Ed25519 WORM seals"));
    assert!(main.contains("refusing to start without durable audit log"));
}

#[test]
fn inv_boot_calls_open_before_main_loop() {
    let main = main_rs();
    let run = main.find("fn run_service").expect("run_service");
    let window = &main[run..run.saturating_add(12_000).min(main.len())];
    let open = window
        .find("open_initial_worm_segment(")
        .expect("boot open");
    let loop_call = window.find("main_loop(").expect("main_loop");
    assert!(open < loop_call, "eager WORM open must precede main_loop");
}

#[test]
fn inv_handle_audit_event_keeps_lazy_fallback() {
    let main = main_rs();
    let start = main
        .find("fn handle_audit_event")
        .expect("handle_audit_event");
    let after = &main[start + 1..];
    let end = after
        .find("\nfn ")
        .map(|i| start + 1 + i)
        .unwrap_or(main.len());
    let body = &main[start..end];
    assert!(
        body.contains("open_initial_worm_segment"),
        "defense-in-depth lazy open must remain"
    );
    assert!(!body.contains("request_audit_log_file_from_supervisor"));
    let ack = body.find("Message::AuditAck").expect("AuditAck");
    let rotate = body.find("rotate_segment(").expect("rotate_segment");
    assert!(ack < rotate, "MFA HOL: AuditAck before rotate_segment");
}

#[test]
fn check_audit_worm_eager_boot_lint_passes() {
    let script = script_path();
    assert!(script.exists(), "missing {}", script.display());
    let out = Command::new("bash")
        .arg(&script)
        .output()
        .unwrap_or_else(|e| panic!("spawn {}: {e}", script.display()));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "check_audit_worm_eager_boot.sh failed:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

#[test]
fn lint_script_covers_fail_closed_needles() {
    use std::os::unix::fs::PermissionsExt;
    let path = script_path();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert!(mode & 0o111 != 0, "script not executable");
    let body = std::fs::read_to_string(&path).unwrap();
    for needle in [
        "open_initial_worm_segment",
        "main_loop",
        "VAUBAN_AUDIT_REQUIRED",
        "refusing to start without durable audit log",
    ] {
        assert!(body.contains(needle), "lint must reference `{needle}`");
    }
}
