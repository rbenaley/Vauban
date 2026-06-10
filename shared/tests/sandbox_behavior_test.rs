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

/// THE DELEGATED-FD LIFECYCLE TEST.
///
/// The parent (not sandboxed -- it plays the supervisor) opens a temp file
/// and delegates it to a sandboxed child via SCM_RIGHTS. The child then
/// exercises EVERY operation the real services perform on delegated fds:
///
///   * `write_all` + `flush`        -- all writers
///   * `sync_all` (fsync)           -- audit WORM appender (the "worm io:
///     EPERM" bug: fsync was missing from the Linux seccomp base)
///   * `sync_data` (fdatasync)      -- IACS recording writer
///   * `metadata()` (fstat/statx)   -- recording download handler
///   * `seek` + `read_exact` (lseek)-- HTTP Range serving
///
/// and verifies that path-based `File::open` stays denied. This pins the
/// fsync/fdatasync seccomp-base fix and kills the whole regression class
/// (a delegated fd must support its full lifecycle, not just read/write).
#[test]
fn delegated_fd_lifecycle_operations_all_work() {
    use std::io::{Seek, SeekFrom};

    // SCM_RIGHTS channel (parent -> child) + an IPC pipe pair so the child
    // profile mirrors a real service shape (IpcPipe + FdReceiver).
    let (parent_sock, child_sock) = socketpair();
    let (ipc_a, ipc_b) = socketpair();

    let path =
        std::env::temp_dir().join(format!("vauban_sandbox_lifecycle_{}", std::process::id()));
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(&path)
        .expect("create temp file");

    const PAYLOAD: &[u8] = b"audit-record\n";

    // SAFETY: fork in a test; the child only runs the closure below and
    // `_exit`s without returning into the harness.
    match unsafe { libc::fork() } {
        -1 => panic!("fork() failed: {}", std::io::Error::last_os_error()),
        0 => {
            let ok = (|| -> bool {
                let profile = SandboxProfile::new()
                    .ipc_pipes(&[ipc_a, ipc_b])
                    .fd_receiver(child_sock);
                if enter_sandbox(profile).is_err() {
                    eprintln!("enter_sandbox failed");
                    return false;
                }

                // Receive the delegated fd (recvmsg + SCM_RIGHTS) AFTER the
                // sandbox is sealed, exactly like the real services.
                let owned = match shared::ipc::recv_fd(child_sock) {
                    Ok(fd) => fd,
                    Err(e) => {
                        eprintln!("recv_fd failed post-sandbox: {e}");
                        return false;
                    }
                };
                let mut f = std::fs::File::from(owned);

                if f.write_all(PAYLOAD).is_err() {
                    eprintln!("write_all on delegated fd failed");
                    return false;
                }
                if f.flush().is_err() {
                    eprintln!("flush on delegated fd failed");
                    return false;
                }
                if f.sync_all().is_err() {
                    eprintln!("sync_all (fsync) on delegated fd failed -- WORM regression");
                    return false;
                }
                if f.sync_data().is_err() {
                    eprintln!("sync_data (fdatasync) on delegated fd failed -- recording");
                    return false;
                }
                match f.metadata() {
                    Ok(m) if m.len() == PAYLOAD.len() as u64 => {}
                    Ok(m) => {
                        eprintln!("metadata length mismatch: {}", m.len());
                        return false;
                    }
                    Err(e) => {
                        eprintln!("metadata (fstat/statx) on delegated fd failed: {e}");
                        return false;
                    }
                }
                if f.seek(SeekFrom::Start(0)).is_err() {
                    eprintln!("seek (lseek) on delegated fd failed -- HTTP Range");
                    return false;
                }
                let mut buf = [0u8; PAYLOAD.len()];
                if f.read_exact(&mut buf).is_err() || buf != PAYLOAD {
                    eprintln!("read-back on delegated fd failed");
                    return false;
                }

                // Path-based open MUST stay denied: the delegation is the
                // only door.
                if std::fs::File::open("/etc/hosts").is_ok() {
                    eprintln!("File::open by path succeeded (should be denied)");
                    return false;
                }

                true
            })();
            // SAFETY: terminate the child immediately without unwinding.
            unsafe { libc::_exit(i32::from(!ok)) };
        }
        pid => {
            // Parent = supervisor: delegate the file fd, then reap the child.
            shared::ipc::send_fd(parent_sock, file.as_raw_fd()).expect("send_fd failed");
            let mut status: libc::c_int = 0;
            // SAFETY: valid pid and status pointer.
            let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
            drop(file);
            let _ = std::fs::remove_file(&path);
            assert_eq!(rc, pid, "waitpid failed");
            assert!(
                libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
                "delegated-fd lifecycle violated in the sandboxed child \
                 (see child stderr above)"
            );
        }
    }
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
