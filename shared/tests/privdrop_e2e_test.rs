//! End-to-end proof of the VAU-009 privilege-drop group purge.
//!
//! `shared::privdrop::drop_privileges` purges the supplementary group list
//! (`setgroups([])`) BEFORE `setgid`/`setuid`, so a child the supervisor
//! forks never keeps root's secondary groups. A source pin proves the call
//! order; this test proves the KERNEL-level effect through a REAL
//! `fork()`/`execve()` (the only way to observe `getgroups()`/`geteuid()`
//! of a freshly deprivileged process).
//!
//! Technique (same portable self-re-exec as `ipc_cloexec_e2e_test.rs`):
//!
//! 1. Gate on root: dropping privileges and clearing supplementary groups
//!    requires `CAP_SETGID`/root. On an unprivileged CI runner the test
//!    skips cleanly (green); the integration server runs it for real.
//! 2. Resolve the `nobody`/`nogroup` target in the PARENT (NSS lookups +
//!    allocation are fine before the fork).
//! 3. `fork()`. The child calls `drop_privileges(Some(uid), Some(gid))` --
//!    the exact primitive the supervisor uses -- then `execve`s THIS test
//!    binary, selecting only the probe entrypoint, passing the expected
//!    uid/gid through the environment.
//! 4. The re-exec'd probe checks `getgroups()` is EMPTY (INV-1) and that
//!    `geteuid()`/`getegid()` equal the targets (the drop happened). It
//!    `process::exit`s the verdict (0 = all held), read by `waitpid`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr
)]

use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::{ForkResult, Uid, execve, fork};
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;

const PROBE_ENV: &str = "VAUBAN_PRIVDROP_PROBE";
const PROBE_UID_ENV: &str = "VAUBAN_PRIVDROP_UID";
const PROBE_GID_ENV: &str = "VAUBAN_PRIVDROP_GID";
const PROBE_TEST_NAME: &str = "privdrop_probe_child_entrypoint";

/// Last-resort target when `nobody`/`nogroup` cannot be resolved: the
/// conventional `nobody` id on most Unixes. Always non-zero so we never
/// "drop" to root by accident.
const FALLBACK_NOBODY: u32 = 65534;

/// Re-exec'd probe entrypoint.
///
/// A normal test run (no `VAUBAN_PRIVDROP_PROBE`) is a no-op pass. When the
/// parent re-execs this binary with the probe env set, it inspects the
/// deprivileged identity and `process::exit`s the verdict, bypassing the
/// libtest reporter so the parent reads our exit code via `waitpid`.
#[test]
fn privdrop_probe_child_entrypoint() {
    if std::env::var(PROBE_ENV).is_err() {
        return;
    }
    std::process::exit(run_probe());
}

fn run_probe() -> i32 {
    let want_uid: u32 = std::env::var(PROBE_UID_ENV)
        .ok()
        .and_then(|s| s.parse().ok())
        .expect("probe uid env");
    let want_gid: u32 = std::env::var(PROBE_GID_ENV)
        .ok()
        .and_then(|s| s.parse().ok())
        .expect("probe gid env");

    // INV-1: supplementary groups must be EMPTY after the drop. nix gates
    // getgroups out on Apple targets, so query the count via libc directly:
    // getgroups(0, NULL) returns the number of supplementary groups.
    let ngroups = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if ngroups < 0 {
        let e = std::io::Error::last_os_error();
        eprintln!("probe: getgroups() failed: {e}");
        return 1;
    }
    if ngroups != 0 {
        eprintln!("probe: getgroups() count={ngroups}, expected 0 (groups not purged!)");
        return 1;
    }

    // The drop actually happened (defensive: a no-op would leave us root).
    let euid = nix::unistd::geteuid().as_raw();
    if euid != want_uid {
        eprintln!("probe: geteuid()={euid}, expected {want_uid}");
        return 2;
    }
    let egid = nix::unistd::getegid().as_raw();
    if egid != want_gid {
        eprintln!("probe: getegid()={egid}, expected {want_gid}");
        return 3;
    }
    0
}

/// Resolve an unprivileged (uid, gid) target, preferring `nobody`/`nogroup`.
fn resolve_target() -> (u32, u32) {
    let uid = nix::unistd::User::from_name("nobody")
        .ok()
        .flatten()
        .map(|u| u.uid.as_raw())
        .filter(|&u| u != 0)
        .unwrap_or(FALLBACK_NOBODY);
    let gid = nix::unistd::Group::from_name("nogroup")
        .ok()
        .flatten()
        .map(|g| g.gid.as_raw())
        .or_else(|| {
            nix::unistd::Group::from_name("nobody")
                .ok()
                .flatten()
                .map(|g| g.gid.as_raw())
        })
        .filter(|&g| g != 0)
        .unwrap_or(FALLBACK_NOBODY);
    (uid, gid)
}

/// INV-1 (behavioral): a child deprivileged via `drop_privileges` has an
/// EMPTY supplementary group list and the target euid/egid.
#[test]
fn deprivileged_child_has_empty_supplementary_groups() {
    if !Uid::effective().is_root() {
        eprintln!("deprivileged_child_has_empty_supplementary_groups: skipped (requires root)");
        return;
    }

    let (uid, gid) = resolve_target();

    // Build argv/envp in the PARENT (allocation OK before fork).
    let exe = std::env::current_exe().expect("current_exe");
    let exe_c = CString::new(exe.as_os_str().as_bytes()).unwrap();
    let argv = [
        exe_c.clone(),
        CString::new(PROBE_TEST_NAME).unwrap(),
        CString::new("--exact").unwrap(),
        CString::new("--test-threads=1").unwrap(),
        CString::new("--nocapture").unwrap(),
    ];

    let mut envp: Vec<CString> = std::env::vars()
        .filter(|(k, _)| !k.starts_with("VAUBAN_PRIVDROP"))
        .map(|(k, v)| CString::new(format!("{k}={v}")).unwrap())
        .collect();
    envp.push(CString::new(format!("{PROBE_ENV}=1")).unwrap());
    envp.push(CString::new(format!("{PROBE_UID_ENV}={uid}")).unwrap());
    envp.push(CString::new(format!("{PROBE_GID_ENV}={gid}")).unwrap());

    // SAFETY: fork in a test. The child only calls the privdrop primitive
    // (raw syscalls) then `execve` (or `_exit` on the error path) -- no
    // allocation, no Rust destructors.
    match unsafe { fork() }.expect("fork") {
        ForkResult::Child => {
            if shared::privdrop::drop_privileges(Some(uid), Some(gid)).is_err() {
                unsafe { libc::_exit(126) };
            }
            let _ = execve(&exe_c, &argv, &envp);
            unsafe { libc::_exit(127) };
        }
        ForkResult::Parent { child } => match waitpid(child, None).expect("waitpid") {
            WaitStatus::Exited(_, 0) => {}
            WaitStatus::Exited(_, 126) => {
                panic!("child drop_privileges failed (target uid={uid}, gid={gid})")
            }
            WaitStatus::Exited(_, 127) => {
                panic!("child execve of the probe failed (binary not executable as uid={uid}?)")
            }
            WaitStatus::Exited(_, code) => panic!(
                "probe child exited {code}: supplementary groups NOT purged or wrong euid/egid \
                 (VAU-009 regression)"
            ),
            other => panic!("probe child terminated abnormally: {other:?}"),
        },
    }
}
