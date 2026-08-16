//! Pins for the class-level untrusted-input / trust-anchor / claims lints.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::path::PathBuf;
use std::process::Command;

fn script(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("scripts")
        .join(name)
}

fn assert_script_ok(name: &str) {
    let path = script(name);
    assert!(path.exists(), "missing {}", path.display());
    let out = Command::new("bash")
        .arg(&path)
        .output()
        .unwrap_or_else(|e| panic!("spawn {}: {e}", path.display()));
    assert!(
        out.status.success(),
        "{name} failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn check_untrusted_interpolation_passes() {
    assert_script_ok("check_untrusted_interpolation.sh");
}

#[test]
fn check_trust_anchor_passes() {
    assert_script_ok("check_trust_anchor.sh");
}

#[test]
fn check_security_claims_passes() {
    assert_script_ok("check_security_claims.sh");
}

#[test]
fn check_just_lint_wired_passes() {
    assert_script_ok("check_just_lint_wired.sh");
}

#[test]
fn class_lint_scripts_are_executable() {
    use std::os::unix::fs::PermissionsExt;
    for name in [
        "check_untrusted_interpolation.sh",
        "check_trust_anchor.sh",
        "check_security_claims.sh",
        "check_just_lint_wired.sh",
    ] {
        let path = script(name);
        let mode = std::fs::metadata(&path).expect(name).permissions().mode();
        assert!(mode & 0o111 != 0, "{name} not executable");
    }
}
