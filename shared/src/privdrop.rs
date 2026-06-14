//! Privilege-drop primitive for the Vauban supervisor (VAU-009).
//!
//! The supervisor stays root and deprivileges every child it `fork()`s, just
//! before `execv()`. Historically it called `setgid` then `setuid` but never
//! purged the supplementary group list, so a child inherited root's secondary
//! groups (`getgroups()` still contained e.g. group `0`). This weakened the
//! privilege separation: a "deprivileged" service could still reach resources
//! granted via root's secondary groups.
//!
//! [`drop_privileges`] is the single, canonical seam that performs the drop in
//! the correct order:
//!
//! 1. `setgroups(&[])` -- purge the supplementary groups WHILE still root
//!    (before `setuid` removes `CAP_SETGID`),
//! 2. `setgid(gid)`,
//! 3. `setuid(uid)`.
//!
//! ## Async-signal-safety
//!
//! This function is meant to be called in the child between `fork()` and
//! `execv()`. It performs ONLY raw syscalls (`setgroups`/`setgid`/`setuid`)
//! over a const, zero-length array; it never allocates, never takes a lock,
//! and never touches NSS. It is therefore async-signal-safe. (`initgroups`,
//! by contrast, performs NSS lookups and allocations and is deliberately NOT
//! used here -- see VAU-009 plan, "Hors perimetre".)

use nix::errno::Errno;
use nix::unistd::{Gid, Uid, setgid, setuid};

/// Drop the calling process' privileges to `gid`/`uid`, purging the
/// supplementary group list first.
///
/// Order (security-critical, VAU-009): `setgroups([])` -> `setgid` -> `setuid`.
/// The supplementary groups MUST be cleared before `setuid` drops the
/// `CAP_SETGID` capability, otherwise the purge would fail.
///
/// `setgroups([])` is only attempted when a privilege drop is actually
/// requested (`uid` or `gid` is `Some`). In dev/testing mode (both `None`)
/// this is a no-op: a non-root process must not (and cannot) call
/// `setgroups`.
///
/// Returns the first failing syscall's `Errno`. Callers in the post-fork
/// child MUST treat any error as fatal (abort before `execv`) so a child can
/// never run with a partially-dropped identity (fail-closed).
///
/// # Safety / context
///
/// Async-signal-safe; intended for the post-`fork()` child. See the module
/// docs.
pub fn drop_privileges(uid: Option<u32>, gid: Option<u32>) -> nix::Result<()> {
    // Purge supplementary groups FIRST, while still privileged. We call
    // libc::setgroups directly because nix gates `setgroups` out on Apple
    // targets (dev machines); the raw syscall with ngroups=0 / NULL is the
    // portable, allocation-free, async-signal-safe purge. Gated on an actual
    // drop so a non-root dev process does not hit EPERM.
    if uid.is_some() || gid.is_some() {
        // SAFETY: setgroups(0, NULL) clears the supplementary group list; it
        // reads no memory (count is 0) and only performs the syscall.
        let rc = unsafe { libc::setgroups(0, std::ptr::null()) };
        Errno::result(rc)?;
    }

    // GID before UID: once setuid drops privileges, setgid would fail.
    if let Some(g) = gid {
        setgid(Gid::from_raw(g))?;
    }
    if let Some(u) = uid {
        setuid(Uid::from_raw(u))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// In dev/testing mode (no uid/gid), the drop is a pure no-op: it does NOT
    /// call `setgroups` (which would EPERM for a non-root process). Safe to run
    /// everywhere, including as root, because it changes nothing.
    #[test]
    fn none_none_is_noop() {
        assert!(
            drop_privileges(None, None).is_ok(),
            "drop_privileges(None, None) must be a no-op Ok(())"
        );
    }

    /// As a non-root process, attempting a real drop surfaces EPERM from the
    /// very first syscall (`setgroups`). This proves `setgroups` is actually
    /// invoked, and the early `?` means `setgid`/`setuid` are NEVER reached --
    /// so the test runner's own identity is left intact.
    ///
    /// Skipped when running as root (a real drop there would irreversibly
    /// mutate the test process).
    #[test]
    fn nonroot_drop_attempt_surfaces_eperm() {
        if Uid::effective().is_root() {
            eprintln!("nonroot_drop_attempt_surfaces_eperm: skipped (running as root)");
            return;
        }
        let uid = nix::unistd::getuid().as_raw();
        let gid = nix::unistd::getgid().as_raw();
        let res = drop_privileges(Some(uid), Some(gid));
        assert_eq!(
            res,
            Err(nix::errno::Errno::EPERM),
            "a non-root setgroups([]) must fail with EPERM (and never reach setuid/setgid)"
        );
    }
}
