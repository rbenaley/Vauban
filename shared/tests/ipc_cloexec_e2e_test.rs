//! End-to-end proof of the VAU-005 IPC FD cloisonnement.
//!
//! `shared::ipc::IpcChannel::pair()` creates every pipe end with
//! `FD_CLOEXEC` (INV-1). The supervisor's `spawn_child` re-enables
//! inheritance for the minimal allowlist destined to a child via
//! `shared::ipc::clear_cloexec` (INV-2/INV-3). The security property
//! (INV-4) is that a child only keeps ITS pipe ends; every foreign
//! service's pipe end closes at `execv`.
//!
//! These tests prove INV-3 and INV-4 at the kernel level, through a REAL
//! `fork()` + `execve()` (FD_CLOEXEC only takes effect at exec, so a
//! source pin or an in-process flag read is not enough). The technique
//! is a portable self-re-exec (works on darwin / FreeBSD / Linux, no
//! `/proc` dependency):
//!
//! 1. Create pipes via `pair()` (all ends start FD_CLOEXEC).
//! 2. Mark "own" ends inheritable with `clear_cloexec`; leave "foreign"
//!    ends FD_CLOEXEC.
//! 3. `fork()`; the child `execve`s THIS test binary, selecting only the
//!    probe entrypoint, with the expected-open / expected-closed fd
//!    numbers passed through the environment (env survives exec).
//! 4. The re-exec'd probe inspects each fd with `fcntl(F_GETFD)`: "own"
//!    ends must be open (Ok), "foreign" ends must be `EBADF` (closed by
//!    exec). It exits 0 iff every expectation holds.
//! 5. The parent asserts the child exited 0.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr
)]

use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::{ForkResult, execve, fork};
use shared::ipc::{IpcChannel, clear_cloexec};
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::RawFd;

const PROBE_ENV: &str = "VAUBAN_FDPROBE";
const PROBE_OPEN_ENV: &str = "VAUBAN_FDPROBE_OPEN";
const PROBE_CLOSED_ENV: &str = "VAUBAN_FDPROBE_CLOSED";
const PROBE_TEST_NAME: &str = "fdprobe_child_entrypoint";

/// Re-exec'd probe entrypoint.
///
/// In a normal test run (no `VAUBAN_FDPROBE` in the environment) this is a
/// no-op that passes. When the parent re-execs this binary with the probe
/// env set, it inspects the listed fds and `process::exit`s with the
/// verdict (0 = every expectation held), bypassing the libtest reporter so
/// the parent reads our exit code directly via `waitpid`.
#[test]
fn fdprobe_child_entrypoint() {
    if std::env::var(PROBE_ENV).is_err() {
        // Not the probe child: nothing to do.
        return;
    }
    std::process::exit(run_probe());
}

fn parse_fd_list(var: &str) -> Vec<RawFd> {
    match std::env::var(var) {
        Ok(s) if !s.is_empty() => s
            .split(',')
            .map(|tok| tok.parse::<RawFd>().expect("fd token must be an integer"))
            .collect(),
        _ => Vec::new(),
    }
}

/// Returns true if `fd` is open in the current process.
fn fd_is_open(fd: RawFd) -> bool {
    use nix::fcntl::{FcntlArg, fcntl};
    use std::os::unix::io::BorrowedFd;
    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
    match fcntl(borrowed, FcntlArg::F_GETFD) {
        Ok(_) => true,
        Err(nix::errno::Errno::EBADF) => false,
        // Any other errno is unexpected for F_GETFD; treat as "not the
        // clean open/closed contract" and fail the probe.
        Err(_) => true,
    }
}

/// Probe body: 0 iff every OPEN fd is open AND every CLOSED fd is closed.
fn run_probe() -> i32 {
    let expect_open = parse_fd_list(PROBE_OPEN_ENV);
    let expect_closed = parse_fd_list(PROBE_CLOSED_ENV);

    for fd in &expect_open {
        if !fd_is_open(*fd) {
            eprintln!("probe: fd {fd} expected OPEN but is closed");
            return 1;
        }
    }
    for fd in &expect_closed {
        if fd_is_open(*fd) {
            eprintln!("probe: fd {fd} expected CLOSED but is open (FD leak!)");
            return 2;
        }
    }
    0
}

/// Fork + `execve` the probe child, asserting it exits 0.
///
/// `open_fds` must survive exec (caller has run `clear_cloexec` on them);
/// `closed_fds` must NOT survive exec (they keep FD_CLOEXEC).
fn assert_probe(open_fds: &[RawFd], closed_fds: &[RawFd]) {
    // Build argv + envp in the PARENT (allocation here is fine). The child
    // then only calls `execve` -- no allocation, no env mutation, async-
    // signal-safe.
    let exe = std::env::current_exe().expect("current_exe");
    let exe_c = CString::new(exe.as_os_str().as_bytes()).unwrap();
    let argv = [
        exe_c.clone(),
        CString::new(PROBE_TEST_NAME).unwrap(),
        CString::new("--exact").unwrap(),
        CString::new("--test-threads=1").unwrap(),
        CString::new("--nocapture").unwrap(),
    ];

    let join = |fds: &[RawFd]| {
        fds.iter()
            .map(|f| f.to_string())
            .collect::<Vec<_>>()
            .join(",")
    };

    // Preserve the existing environment (so libtest behaves), minus any
    // stale probe vars, plus our probe contract.
    let mut envp: Vec<CString> = std::env::vars()
        .filter(|(k, _)| !k.starts_with("VAUBAN_FDPROBE"))
        .map(|(k, v)| CString::new(format!("{k}={v}")).unwrap())
        .collect();
    envp.push(CString::new(format!("{PROBE_ENV}=1")).unwrap());
    envp.push(CString::new(format!("{PROBE_OPEN_ENV}={}", join(open_fds))).unwrap());
    envp.push(CString::new(format!("{PROBE_CLOSED_ENV}={}", join(closed_fds))).unwrap());

    // SAFETY: fork in a test. The child performs only `execve` (and, on the
    // unlikely error path, an `_exit`) -- no allocation, no Rust destructors.
    match unsafe { fork() }.expect("fork") {
        ForkResult::Child => {
            let _ = execve(&exe_c, &argv, &envp);
            // execve only returns on error; bail without running atexit
            // handlers in the forked child.
            unsafe { libc::_exit(127) };
        }
        ForkResult::Parent { child } => match waitpid(child, None).expect("waitpid") {
            WaitStatus::Exited(_, 0) => {}
            WaitStatus::Exited(_, code) => {
                panic!("probe child exited with code {code} (FD cloisonnement broken)")
            }
            other => panic!("probe child terminated abnormally: {other:?}"),
        },
    }
}

/// INV-4 (baseline): a foreign service's pipe ends are CLOSED after the
/// child execs, while the child's own pipe ends survive.
#[test]
fn foreign_pipe_ends_are_closed_after_execv() {
    let (own, _own_peer) = IpcChannel::pair().unwrap();
    let (foreign, _foreign_peer) = IpcChannel::pair().unwrap();

    // Own channel: supervisor would clear CLOEXEC on the destined child's
    // ends. Foreign channel: left FD_CLOEXEC, must vanish at exec.
    clear_cloexec(own.read_fd()).unwrap();
    clear_cloexec(own.write_fd()).unwrap();

    assert_probe(
        &[own.read_fd(), own.write_fd()],
        &[foreign.read_fd(), foreign.write_fd()],
    );
}

/// Several foreign pipes are ALL closed after exec (no FD survives the cut
/// just because there are many of them).
#[test]
fn multiple_foreign_pipes_all_closed() {
    let (own, _op) = IpcChannel::pair().unwrap();
    clear_cloexec(own.read_fd()).unwrap();
    clear_cloexec(own.write_fd()).unwrap();

    let (f1, _p1) = IpcChannel::pair().unwrap();
    let (f2, _p2) = IpcChannel::pair().unwrap();
    let (f3, _p3) = IpcChannel::pair().unwrap();

    assert_probe(
        &[own.read_fd(), own.write_fd()],
        &[
            f1.read_fd(),
            f1.write_fd(),
            f2.read_fd(),
            f2.write_fd(),
            f3.read_fd(),
            f3.write_fd(),
        ],
    );
}

/// Both ends (read AND write) of an own pipe survive exec when both are
/// de-CLOEXEC'd (a half-cleared channel would be a half-broken channel).
#[test]
fn both_ends_of_own_pipe_survive() {
    let (own, _peer) = IpcChannel::pair().unwrap();
    clear_cloexec(own.read_fd()).unwrap();
    clear_cloexec(own.write_fd()).unwrap();

    assert_probe(&[own.read_fd(), own.write_fd()], &[]);
}

/// A service wired with BOTH an outgoing and an incoming topology pipe
/// keeps exactly its two channels' ends, and nothing from a third
/// (foreign) service.
#[test]
fn service_with_outgoing_and_incoming_keeps_exactly_its_ends() {
    let (outgoing, _o_peer) = IpcChannel::pair().unwrap();
    let (incoming, _i_peer) = IpcChannel::pair().unwrap();
    let (foreign, _f_peer) = IpcChannel::pair().unwrap();

    for ch in [&outgoing, &incoming] {
        clear_cloexec(ch.read_fd()).unwrap();
        clear_cloexec(ch.write_fd()).unwrap();
    }

    assert_probe(
        &[
            outgoing.read_fd(),
            outgoing.write_fd(),
            incoming.read_fd(),
            incoming.write_fd(),
        ],
        &[foreign.read_fd(), foreign.write_fd()],
    );
}

/// Fail-closed: a pipe that the supervisor never explicitly hands to the
/// child (no `clear_cloexec`) stays closed -- a forgotten descriptor does
/// NOT leak.
#[test]
fn unlisted_foreign_fd_stays_closed_fail_closed() {
    let (forgotten, _peer) = IpcChannel::pair().unwrap();
    // Deliberately do NOT clear_cloexec: simulates an fd the supervisor
    // omitted from the allowlist. It must close at exec.
    assert_probe(&[], &[forgotten.read_fd(), forgotten.write_fd()]);
}
