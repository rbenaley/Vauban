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

use shared::iacs_host_key::{prepare_host_key_fd, rewind_host_key_fd};
use std::io::Read;
use std::os::fd::IntoRawFd;

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

/// **Production regression test** -- "PEM preamble contains invalid
/// data (NUL byte)" boot loop on FreeBSD.
///
/// Reproduces the exact pathway the supervisor uses at runtime:
///
///   1. Boot: `prepare_host_key_fd(path)` -> RawFd (kept open in the
///      supervisor across the lifetime of the bastion, ready to be
///      inherited by every spawn of `vauban-proxy-iacs`).
///   2. First spawn: a child reads the FD to EOF -- emulated here
///      with a `dup(fd) -> read_to_string`. The kernel file table
///      entry's position cursor advances to EOF.
///   3. Crash & respawn: the supervisor inherits the SAME FD again
///      (the file table entry is shared). Without a rewind, the
///      respawn reads an empty string, hits `from_openssh("")` and
///      crash-loops.
///   4. With `rewind_host_key_fd(fd)` issued before each spawn, the
///      respawn reads the full PEM blob byte-for-byte identical to
///      the first read.
///
/// This pin is the runtime counterpart of the unit test
/// `rewind_host_key_fd_resets_position_after_full_read` in
/// `shared::iacs_host_key::tests`.
#[test]
fn supervisor_rewinds_host_key_fd_between_respawns() {
    use std::os::fd::FromRawFd;

    let p = temp_path("respawn");
    let supervisor_fd = prepare_host_key_fd(&p).expect("boot prepare");
    let raw = supervisor_fd.into_raw_fd();

    // Emulate the first child: dup() the FD across an `execv`-equivalent
    // boundary, drain to EOF -- this is what `vauban-proxy-iacs` does
    // in `read_host_key_from_fd`. Position cursor on the supervisor
    // FD advances along because both numerical FDs reference the same
    // file table entry (post-fork dup() / pre-execv inheritance).
    let pem_first = {
        let dup = unsafe { libc::dup(raw) };
        assert!(dup >= 0, "dup must succeed");
        let mut owned = unsafe { std::fs::File::from_raw_fd(dup) };
        let mut s = String::new();
        owned.read_to_string(&mut s).expect("first drain");
        s
    };
    assert!(
        pem_first.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"),
        "first read must yield the full PEM blob"
    );

    // Without a rewind, the supervisor's own FD is now at EOF
    // (shared cursor) -- this is the exact production bug.
    let pem_eof = {
        let dup = unsafe { libc::dup(raw) };
        let mut owned = unsafe { std::fs::File::from_raw_fd(dup) };
        let mut s = String::new();
        owned.read_to_string(&mut s).expect("eof drain");
        s
    };
    assert!(
        pem_eof.is_empty(),
        "without rewind the cursor is at EOF; this is the production-bug repro"
    );

    // The fix: rewind before every respawn.
    rewind_host_key_fd(raw).expect("rewind");
    let pem_respawn = {
        let dup = unsafe { libc::dup(raw) };
        let mut owned = unsafe { std::fs::File::from_raw_fd(dup) };
        let mut s = String::new();
        owned.read_to_string(&mut s).expect("respawn drain");
        s
    };
    assert_eq!(
        pem_respawn, pem_first,
        "after rewind_host_key_fd the respawn must see the FULL PEM blob \
         byte-for-byte identical to the first spawn (the fix for the \
         FreeBSD boot loop)."
    );

    // Tidy: close the supervisor FD.
    unsafe {
        libc::close(raw);
    }
}

/// Source-grep pin: every site in the supervisor that pushes
/// `("VAUBAN_IACS_HOST_KEY_FD", fd)` into `inheritable_fds` MUST be
/// paired with a `rewind_host_key_fd(fd)` call within a tight window
/// above. Three call sites today: boot startup, `respawn_service`,
/// and the `kill_and_respawn` watchdog path. Drift (a fourth spawn
/// site without the rewind) immediately fails this test.
#[test]
fn every_iacs_host_key_fd_push_is_preceded_by_a_rewind() {
    const SUPERVISOR_MAIN: &str = include_str!("../src/main.rs");
    let needle = "(\"VAUBAN_IACS_HOST_KEY_FD\", fd)";
    let push_sites: Vec<usize> = SUPERVISOR_MAIN
        .match_indices(needle)
        .map(|(i, _)| i)
        .collect();
    assert!(
        push_sites.len() >= 3,
        "expected at least 3 push sites for VAUBAN_IACS_HOST_KEY_FD \
         (boot + respawn_service + kill_and_respawn); found {}",
        push_sites.len()
    );
    for pos in push_sites {
        let win_start = pos.saturating_sub(800);
        let window = &SUPERVISOR_MAIN[win_start..pos];
        assert!(
            window.contains("rewind_host_key_fd"),
            "INVARIANT BROKEN: a push of VAUBAN_IACS_HOST_KEY_FD into \
             inheritable_fds at byte {} is NOT preceded by a \
             shared::iacs_host_key::rewind_host_key_fd call within \
             800 bytes. Without the rewind, the file position cursor \
             stays at EOF after the first spawn and every subsequent \
             respawn crash-loops on \"PEM preamble contains invalid \
             data (NUL byte)\". Add a rewind_host_key_fd(fd) call \
             before this push.",
            pos
        );
    }
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
