//! VAU-001 -- Rust pin for the RDP server-certificate lint script.
//!
//! `vauban-web/scripts/check_rdp_cert_paths.sh` is wired into CI under
//! `.github/workflows/ci.yaml`, but a developer running
//! `cargo test --workspace` on their own machine should trip the same
//! invariants without shelling out to the bash runner manually. This
//! test spawns the script and asserts `success()` -- the exact pattern
//! used by `timezone_lints_test.rs`. It also closes the historical gap
//! where the SSH host-key lint shipped without a `cargo test` wrapper.

use std::path::PathBuf;
use std::process::Command;

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn script_path() -> PathBuf {
    manifest_dir()
        .join("scripts")
        .join("check_rdp_cert_paths.sh")
}

#[test]
fn check_rdp_cert_paths_passes() {
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
        "check_rdp_cert_paths.sh failed:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

/// The script must exist and be executable. Catches a `git reset`
/// that drops the executable bit (CI invokes `bash scripts/*.sh` so an
/// inadvertent chmod is otherwise invisible until a contributor runs
/// it directly).
#[test]
fn rdp_cert_lint_script_exists_and_executable() {
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

/// The script body must keep guarding against the pre-fix accept-any
/// session verifier and the silent-green fallback. A future cleanup
/// that loosens these greps must update this list deliberately.
#[test]
fn rdp_cert_lint_script_covers_core_invariants() {
    let body = std::fs::read_to_string(script_path()).expect("read script");
    for needle in [
        "NoCertificateVerification",
        "PinningServerCertVerifier",
        "TofuAcceptAnyFetchVerifier",
        "_rdp_server_cert_unverified_fragment.html",
        "No RDP server certificate pinned for this asset",
        "RDP server certificate mismatch detected on previous connection",
        "issue_diagnostic_token",
        "caller_has_assets_manage",
    ] {
        assert!(
            body.contains(needle),
            "check_rdp_cert_paths.sh must still reference `{needle}` -- \
             removing the grep loosens a VAU-001 invariant."
        );
    }
}
