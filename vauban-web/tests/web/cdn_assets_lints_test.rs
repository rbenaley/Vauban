//! Pin test for the no-runtime-CDN structural lint.
//!
//! `scripts/check_no_cdn_assets.sh` greps every template under
//! `templates/**.html` and the production portion of
//! `src/middleware/security.rs` for the CDN origins
//! (`cdn.tailwindcss.com`, `unpkg.com`, `cdn.jsdelivr.net`) that the
//! self-hosting effort removed. A non-zero exit blocks CI on the first
//! re-introduced reference.
//!
//! The Rust pin guarantees the script is wired into `cargo test` so a
//! developer that bypasses CI's bash runner still trips the regression
//! locally (same rationale as `timezone_lints_test.rs`).

use std::path::PathBuf;
use std::process::Command;

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn check_no_cdn_assets_passes() {
    let script = manifest_dir()
        .join("scripts")
        .join("check_no_cdn_assets.sh");
    assert!(script.exists(), "missing lint script: {}", script.display());

    let out = Command::new("bash")
        .arg(&script)
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn {}: {}", script.display(), e));

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "check_no_cdn_assets.sh failed:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

/// The lint script must exist and be executable. Catches a `git reset`
/// that drops it.
#[test]
fn check_no_cdn_assets_script_exists_and_executable() {
    use std::os::unix::fs::PermissionsExt;
    let path = manifest_dir()
        .join("scripts")
        .join("check_no_cdn_assets.sh");
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

/// The script must enumerate all three forbidden CDN origins, otherwise a
/// future CDN could be re-introduced undetected.
#[test]
fn check_no_cdn_assets_script_enumerates_all_origins() {
    let path = manifest_dir()
        .join("scripts")
        .join("check_no_cdn_assets.sh");
    let body = std::fs::read_to_string(&path).expect("read script");
    for origin in ["cdn.tailwindcss.com", "unpkg.com", "cdn.jsdelivr.net"] {
        assert!(
            body.contains(origin),
            "lint script must enumerate forbidden CDN origin `{origin}`"
        );
    }
}
