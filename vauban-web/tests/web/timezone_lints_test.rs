//! Pin tests for the timezone-localization lints.
//!
//! These tests run the two structural lint scripts shipped in
//! `vauban-web/scripts/`:
//!
//!  * `check_no_naked_datetime.sh` — refuses `.format(...)` chained
//!    on a known datetime accessor inside `templates/**.html`, plus
//!    `format!("...UTC...")` literals inside `src/handlers/**.rs`.
//!  * `check_template_carries_tz.sh` — refuses any template struct
//!    that exposes `DateTime<Utc>` without also carrying either
//!    `vauban: VaubanConfig` or `tz: chrono_tz::Tz`.
//!
//! The Rust pin guarantees the script is wired into `cargo test` so
//! a developer that bypasses CI's bash runner still sees the
//! regression locally. Each test spawns the script and asserts
//! `success()`.
//!
//! Why pin the script through Rust: the CI runner under
//! `.github/workflows/ci.yaml` shells out to `bash scripts/*.sh` but
//! a developer running `cargo test --workspace` should still trip
//! the lint on their own machine -- that's the production loop the
//! May 2026 audit revealed was missing.

use std::path::PathBuf;
use std::process::Command;

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn run_lint(script_name: &str) -> std::process::Output {
    let script = manifest_dir().join("scripts").join(script_name);
    assert!(
        script.exists(),
        "lint script not found: {}",
        script.display()
    );

    Command::new("bash")
        .arg(&script)
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn {}: {}", script.display(), e))
}

#[test]
fn check_no_naked_datetime_passes() {
    let out = run_lint("check_no_naked_datetime.sh");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "check_no_naked_datetime.sh failed:\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr
    );
}

#[test]
fn check_template_carries_tz_passes() {
    let out = run_lint("check_template_carries_tz.sh");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "check_template_carries_tz.sh failed:\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr
    );
}

/// The lint scripts must exist and be executable. Catches a
/// `git reset` that drops a script.
#[test]
fn lint_scripts_exist_and_executable() {
    use std::os::unix::fs::PermissionsExt;
    for name in ["check_no_naked_datetime.sh", "check_template_carries_tz.sh"] {
        let path = manifest_dir().join("scripts").join(name);
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
}

/// Regression: the script body MUST flag a `.format(...)` chain on
/// a datetime accessor. We synthesize a tmp template tree, inject a
/// regression line, and run the script against that copy via the
/// `TEMPLATE_DIR` override... actually, the script does not honor
/// an override; instead, we assert here via a static text check
/// that the script's regex covers the canonical accessors.
#[test]
fn check_no_naked_datetime_script_covers_canonical_fields() {
    let script = manifest_dir()
        .join("scripts")
        .join("check_no_naked_datetime.sh");
    let body = std::fs::read_to_string(&script).expect("read script");
    for field in [
        "created_at",
        "updated_at",
        "connected_at",
        "disconnected_at",
        "expires_at",
        "valid_from",
        "valid_until",
        "approved_at",
        "rejected_at",
        "deleted_at",
        "started_at",
        "ended_at",
        "last_login",
        "finalized_at",
        "computed_at",
        "timestamp",
    ] {
        assert!(
            body.contains(&format!("\"{}\"", field)),
            "lint script does not enumerate datetime accessor `{}`",
            field
        );
    }
}

/// Regression: the second script MUST recognize the two equivalent
/// satisfy-clauses: `vauban: VaubanConfig` and `tz: ... Tz`.
#[test]
fn check_template_carries_tz_script_recognizes_both_satisfy_clauses() {
    let script = manifest_dir()
        .join("scripts")
        .join("check_template_carries_tz.sh");
    let body = std::fs::read_to_string(&script).expect("read script");
    assert!(
        body.contains("VaubanConfig"),
        "lint script must recognize `vauban: VaubanConfig` as a tz carrier"
    );
    assert!(
        body.contains("Tz"),
        "lint script must recognize `tz: chrono_tz::Tz` as a tz carrier"
    );
}
