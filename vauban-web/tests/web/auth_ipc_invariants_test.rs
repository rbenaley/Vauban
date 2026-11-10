//! Auth IPC fail-closed source pins.
//!
//! `check_auth_ipc_mandatory.sh` is the contract: `init_auth_client`
//! returns `anyhow::Result`, `main` propagates it, and production code
//! under `vauban-web/src` does not call `auth_service.hash_password` or
//! `auth_service.verify_password`.

use std::path::PathBuf;
use std::process::Command;

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn check_auth_ipc_mandatory_passes() {
    let script = manifest_dir()
        .join("scripts")
        .join("check_auth_ipc_mandatory.sh");
    assert!(script.exists(), "missing lint script: {}", script.display());

    let out = Command::new("bash")
        .arg(&script)
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn {}: {}", script.display(), e));

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "check_auth_ipc_mandatory.sh failed:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

#[test]
fn check_auth_ipc_mandatory_script_exists_and_executable() {
    use std::os::unix::fs::PermissionsExt;
    let path = manifest_dir()
        .join("scripts")
        .join("check_auth_ipc_mandatory.sh");
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
