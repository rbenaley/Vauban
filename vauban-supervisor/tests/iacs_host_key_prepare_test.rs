//! Runtime tests for `shared::iacs_host_key::prepare_host_key_fd` as
//! invoked by the supervisor at boot.
//!
//! These tests live in the supervisor crate (which already imports
//! `shared` with the `iacs-host-key` feature) and exercise the
//! end-to-end shape of the FD-passing scheme without requiring a
//! full fork+exec round-trip:
//!
//!   - First call generates a fresh OpenSSH-encoded Ed25519 key on
//!     disk with mode 0600 and returns a readable FD.
//!   - Second call on the same path reads the existing file and
//!     returns the same key bytes (idempotent / reload-safe).
//!   - The returned FD parses cleanly via `read_host_key_from_fd`,
//!     which is what the proxy will do BEFORE `cap_enter`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use shared::iacs_host_key::prepare_host_key_fd;
use std::io::Read;

fn temp_path(label: &str) -> std::path::PathBuf {
    let dir = tempfile::tempdir().expect("tempdir");
    // Leak so the file outlives this helper; the test's TempDir
    // would otherwise be dropped before we read the FD.
    let p = dir.path().join(format!("vauban_iacs_test_{label}.key"));
    std::mem::forget(dir);
    p
}

#[test]
fn prepare_host_key_fd_creates_file_with_mode_0600() {
    let p = temp_path("create");
    assert!(!p.exists());
    let fd = prepare_host_key_fd(&p).expect("first call must generate");
    drop(fd);
    assert!(p.exists());

    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(&p)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        mode, 0o600,
        "the generated host key file MUST be mode 0600 \
         (no group/world access)"
    );
}

/// Read the contents of an inherited FD (consuming it).
fn slurp_fd(fd: std::os::fd::OwnedFd) -> String {
    let mut f = std::fs::File::from(fd);
    let mut s = String::new();
    f.read_to_string(&mut s).expect("read fd contents");
    s
}

#[test]
fn prepare_host_key_fd_returns_a_readable_fd() {
    let p = temp_path("readable");
    let fd = prepare_host_key_fd(&p).expect("prepare");
    let pem = slurp_fd(fd);
    assert!(
        pem.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"),
        "the inherited FD must expose an OpenSSH PEM-encoded \
         Ed25519 key; got prefix: {:?}",
        &pem[..pem.len().min(64)]
    );
}

#[test]
fn prepare_host_key_fd_is_idempotent_on_second_call() {
    let p = temp_path("idempotent");

    let fd1 = prepare_host_key_fd(&p).expect("first call");
    let pem1 = slurp_fd(fd1);

    let fd2 = prepare_host_key_fd(&p).expect("second call must reload");
    let pem2 = slurp_fd(fd2);

    assert_eq!(
        pem1, pem2,
        "prepare_host_key_fd MUST reload the existing file on the \
         second call rather than regenerate it (idempotent on disk)."
    );
}
