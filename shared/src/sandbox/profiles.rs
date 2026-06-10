//! Canonical sandbox profiles -- the single source of truth for what each
//! Vauban service is allowed to hold across the sandbox boundary.
//!
//! Two consumers:
//!
//! * The `web_server` constructor is called directly by `vauban-web`
//!   (the only service whose sandbox is not built from the raw-fd
//!   `setup_service_sandbox*` helpers, because its tokio/axum runtime needs
//!   `cap_enter`-only confinement on FreeBSD).
//! * The `*_KINDS` catalogues document the resource SHAPE every service
//!   declares, independent of the runtime fd numbers. They drive the
//!   profile-drift tests and the source-grep pins that verify each `main.rs`
//!   uses the matching `setup_service_sandbox*` helper.

use super::SandboxProfile;
use std::os::unix::io::RawFd;

/// Mechanism-agnostic classification of a [`super::Resource`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ResourceKind {
    /// Bidirectional IPC pipe.
    IpcPipe,
    /// SCM_RIGHTS fd receiver.
    FdReceiver,
    /// Already-connected socket (DB / cache).
    ConnectedSocket,
    /// Pre-bound listening socket.
    Listener,
    /// Writable directory.
    WritableDir,
    /// Read-only path.
    ReadablePath,
}

/// vauban-auth: supervisor + web IPC pipes, plus an SCM_RIGHTS fd receiver
/// for the LDAPS broker path (the supervisor connects to the directory and
/// passes the connected socket; auth terminates TLS + binds). Argon2 stays
/// CPU-bound; no DB or listener.
pub const AUTH_KINDS: &[ResourceKind] = &[ResourceKind::IpcPipe, ResourceKind::FdReceiver];

/// vauban-vault: supervisor + peer IPC pipes only (in-memory keyrings).
pub const VAULT_KINDS: &[ResourceKind] = &[ResourceKind::IpcPipe];

/// vauban-access: peer IPC pipes only. The PostgreSQL connections are
/// pre-opened by the service itself (r2d2 pool warm-up) before the sandbox
/// and intentionally not declared / rights-limited per fd: the wall is
/// `cap_enter` / seccomp itself, which makes any reconnection impossible.
/// `ConnectedSocket` stays in the [`ResourceKind`] vocabulary for backend
/// exhaustiveness but no service currently delegates such an fd.
pub const ACCESS_KINDS: &[ResourceKind] = &[ResourceKind::IpcPipe];

/// vauban-audit: peer IPC pipes, plus the SCM_RIGHTS fd-passing socket on
/// which the supervisor delegates WORM segment / recording file descriptors
/// (recvmsg only, hence a dedicated fd receiver).
pub const AUDIT_KINDS: &[ResourceKind] = &[ResourceKind::IpcPipe, ResourceKind::FdReceiver];

/// vauban-proxy-ssh: IPC pipes + an SCM_RIGHTS fd receiver.
pub const PROXY_SSH_KINDS: &[ResourceKind] = &[ResourceKind::IpcPipe, ResourceKind::FdReceiver];

/// vauban-proxy-iacs: IPC pipes + fd receiver + the inherited sshd listener.
pub const PROXY_IACS_KINDS: &[ResourceKind] = &[
    ResourceKind::IpcPipe,
    ResourceKind::FdReceiver,
    ResourceKind::Listener,
];

/// vauban-proxy-rdp: IPC pipes + an SCM_RIGHTS fd receiver.
pub const PROXY_RDP_KINDS: &[ResourceKind] = &[ResourceKind::IpcPipe, ResourceKind::FdReceiver];

/// vauban-web: a pre-bound HTTP listener, plus the supervisor SCM_RIGHTS
/// fd-passing socket (recording fds, brokered SMTP streams). The web runtime
/// keeps `cap_enter` as its only FreeBSD wall (no per-fd limiting).
pub const WEB_KINDS: &[ResourceKind] = &[ResourceKind::Listener, ResourceKind::FdReceiver];

/// Canonical profile for the vauban-web HTTP server.
///
/// On FreeBSD this enters `cap_enter()` without limiting per-fd rights (the
/// tokio/axum listener needs a hard-to-enumerate right set). On Linux the
/// listener drives the `accept4` allowance; on OpenBSD it drives `inet` and
/// the fd receiver drives `recvfd` (web receives recording / SMTP fds from
/// the supervisor via SCM_RIGHTS after the sandbox is sealed).
///
/// `fd_passing_fd` is `None` only in development without a supervisor (no
/// SCM_RIGHTS delegation happens in that mode).
#[must_use]
pub fn web_server(listener_fd: RawFd, fd_passing_fd: Option<RawFd>) -> SandboxProfile {
    let mut profile = SandboxProfile::new()
        .listener(listener_fd)
        .without_capsicum_fd_limiting();
    if let Some(fd) = fd_passing_fd {
        profile = profile.fd_receiver(fd);
    }
    profile
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn web_profile_matches_catalogue() {
        let mut expected = WEB_KINDS.to_vec();
        expected.sort_unstable();
        let p = web_server(3, Some(4));
        assert_eq!(p.kinds(), expected);
        // web relies on cap_enter only.
        assert!(!p.capsicum_limit_fds());
    }

    #[test]
    fn web_profile_without_supervisor_drops_fd_receiver() {
        // Development without a supervisor: no SCM_RIGHTS socket exists, so
        // the profile degrades to the listener alone.
        let p = web_server(3, None);
        assert_eq!(p.kinds(), vec![ResourceKind::Listener]);
    }

    #[test]
    fn catalogues_are_non_empty() {
        for kinds in [
            AUTH_KINDS,
            VAULT_KINDS,
            ACCESS_KINDS,
            AUDIT_KINDS,
            PROXY_SSH_KINDS,
            PROXY_IACS_KINDS,
            PROXY_RDP_KINDS,
            WEB_KINDS,
        ] {
            assert!(!kinds.is_empty());
        }
    }
}
