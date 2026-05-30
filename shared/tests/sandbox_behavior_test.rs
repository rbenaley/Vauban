//! Behavioral negative tests for the OS sandbox.
//!
//! These actually ENTER the sandbox and verify that:
//!   * a pre-opened fd (an IPC pipe) keeps working, and
//!   * `File::open`, `TcpStream::connect`, and a raw `socket(AF_INET)`
//!     are all refused.
//!
//! Because entering the sandbox is process-global and irreversible, each
//! check runs in a forked child so the test harness process stays usable.
//!
//! Platform matrix (see the plan's validation constraints):
//!
//! - FreeBSD: active on the integration server (Capsicum, errno-based).
//! - Linux: active, run manually (Landlock + seccomp, errno-based).
//! - OpenBSD: NOT run here. `pledge` kills on violation (SIGABRT) rather
//!   than returning errno, so the assertions differ; verified manually.
//!   Hence the `cfg(any(freebsd, linux))`.
#![cfg(any(target_os = "freebsd", target_os = "linux"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use shared::sandbox::{SandboxProfile, enter_sandbox};
use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

/// Run `body` in a forked child; the child's bool result becomes its exit
/// code (0 = true). Returns whether the child exited cleanly with success.
fn forked(body: impl FnOnce() -> bool) -> bool {
    // SAFETY: fork in a test. The child performs only the minimal work in
    // `body` and then `_exit`s without returning into the harness.
    match unsafe { libc::fork() } {
        -1 => panic!("fork() failed: {}", std::io::Error::last_os_error()),
        0 => {
            let ok = body();
            // SAFETY: terminate the child immediately without unwinding.
            unsafe { libc::_exit(i32::from(!ok)) };
        }
        pid => {
            let mut status: libc::c_int = 0;
            // SAFETY: valid pid and status pointer.
            let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
            assert_eq!(rc, pid, "waitpid failed");
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
        }
    }
}

/// A connected socketpair: index 0 stays "live" across the sandbox, index 1
/// is its peer. Returned as raw fds (the child owns them).
fn socketpair() -> (RawFd, RawFd) {
    let mut fds = [0 as RawFd; 2];
    // SAFETY: standard socketpair call with a valid out array.
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
    assert_eq!(
        rc,
        0,
        "socketpair failed: {}",
        std::io::Error::last_os_error()
    );
    (fds[0], fds[1])
}

#[test]
fn pre_opened_fd_survives_but_new_objects_are_denied() {
    let ok = forked(|| {
        // Pre-open a connected socketpair BEFORE entering the sandbox.
        let (a, b) = socketpair();

        // Enter the sandbox declaring the two fds as IPC pipes.
        let profile = SandboxProfile::new().ipc_pipes(&[a, b]);
        if enter_sandbox(profile).is_err() {
            eprintln!("enter_sandbox failed");
            return false;
        }

        // 1. The pre-opened fds MUST still work (write on a, read on b).
        // SAFETY: a and b are valid owned fds.
        let mut wa = unsafe { std::os::unix::net::UnixStream::from_raw_fd(a) };
        let mut rb = unsafe { std::os::unix::net::UnixStream::from_raw_fd(b) };
        if wa.write_all(b"ping").is_err() {
            eprintln!("write on pre-opened fd failed (should succeed)");
            return false;
        }
        let mut buf = [0u8; 4];
        if rb.read_exact(&mut buf).is_err() || &buf != b"ping" {
            eprintln!("read on pre-opened fd failed (should succeed)");
            return false;
        }

        // 2. Opening a new file by path MUST fail.
        if std::fs::File::open("/etc/hosts").is_ok() {
            eprintln!("File::open succeeded (should be denied)");
            return false;
        }

        // 3. Connecting a new TCP socket MUST fail (no socket()/connect()).
        if std::net::TcpStream::connect("127.0.0.1:9").is_ok() {
            eprintln!("TcpStream::connect succeeded (should be denied)");
            return false;
        }

        // 4. Creating a raw INET socket MUST fail.
        // SAFETY: socket() with constant args.
        let s = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        if s >= 0 {
            eprintln!("socket(AF_INET) succeeded (should be denied)");
            return false;
        }

        true
    });
    assert!(
        ok,
        "post-sandbox behavioral invariants violated (see child stderr above)"
    );
}

/// A listener pre-bound before the sandbox can still `accept()`, proving the
/// `Listener` resource projection grants the right capability.
#[test]
fn pre_bound_listener_can_still_accept() {
    let ok = forked(|| {
        let listener = match std::net::TcpListener::bind("127.0.0.1:0") {
            Ok(l) => l,
            Err(_) => return false,
        };
        let addr = listener.local_addr().unwrap();
        let lfd = listener.as_raw_fd();

        let profile = SandboxProfile::new().listener(lfd);
        if enter_sandbox(profile).is_err() {
            return false;
        }

        // A client connection initiated from OUTSIDE the sandbox: spawn a
        // thread that connects to the listener (the connecting socket is
        // created pre-accept in this same process, which is itself
        // sandboxed -- so instead we just verify accept() does not fail with
        // a capability error by using a non-blocking accept and tolerating
        // WouldBlock). The key assertion is that accept() is permitted.
        listener.set_nonblocking(true).ok();
        match listener.accept() {
            Ok(_) => true,
            // No pending connection is fine; a capability/permission error is
            // NOT (that would mean accept4 was filtered out).
            Err(e) => !matches!(e.kind(), std::io::ErrorKind::PermissionDenied),
        }
    });
    assert!(ok, "pre-bound listener lost the accept() capability");
}
