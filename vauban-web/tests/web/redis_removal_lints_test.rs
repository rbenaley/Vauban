//! Pin test for the no-Redis structural lint.
//!
//! `scripts/check_no_redis.sh` greps `vauban-web/Cargo.toml`, the production
//! portion of `src/**/*.rs`, and `config/**` for any Redis/Valkey reference
//! (the dependency, a `redis://` URL, the default port, a
//! `MultiplexedConnection`). Redis was fully removed (cache is in-memory
//! no-op, rate limiter is in-process), so a re-introduction must fail CI.
//!
//! The Rust pin guarantees the script is wired into `cargo test` so a
//! developer that bypasses CI's bash runner still trips the regression
//! locally (same rationale as `cdn_assets_lints_test.rs`).

use std::path::PathBuf;
use std::process::Command;

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn script_path() -> PathBuf {
    manifest_dir().join("scripts").join("check_no_redis.sh")
}

#[test]
fn check_no_redis_passes() {
    let script = script_path();
    assert!(script.exists(), "missing lint script: {}", script.display());

    let out = Command::new("bash")
        .arg(&script)
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn {}: {}", script.display(), e));

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "check_no_redis.sh failed:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

#[test]
fn check_no_redis_script_exists_and_executable() {
    use std::os::unix::fs::PermissionsExt;
    let path = script_path();
    assert!(path.exists(), "missing lint script: {}", path.display());
    let mode = std::fs::metadata(&path)
        .expect("metadata")
        .permissions()
        .mode();
    assert!(
        mode & 0o111 != 0,
        "lint script not executable: {} (mode={:o})",
        path.display(),
        mode
    );
}

/// The script must enumerate every forbidden token so a future Redis flavour
/// cannot creep back in undetected.
#[test]
fn check_no_redis_script_enumerates_all_tokens() {
    let body = std::fs::read_to_string(script_path()).expect("read script");
    for token in ["redis", "valkey", "6379", "MultiplexedConnection"] {
        assert!(
            body.contains(token),
            "lint script must enumerate forbidden token `{token}`"
        );
    }
}

/// The `redis` crate must not appear in any workspace `Cargo.toml`.
#[test]
fn redis_crate_absent_from_cargo_manifests() {
    let cargo_toml = manifest_dir().join("Cargo.toml");
    let body = std::fs::read_to_string(&cargo_toml).expect("read Cargo.toml");
    for line in body.lines() {
        let trimmed = line.trim_start();
        assert!(
            !trimmed.starts_with("redis "),
            "vauban-web/Cargo.toml must not declare a redis dependency: {line}"
        );
        assert!(
            !trimmed.starts_with("redis="),
            "vauban-web/Cargo.toml must not declare a redis dependency: {line}"
        );
    }
}
