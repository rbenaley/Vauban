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

/// vauban-access: peer IPC pipes + an optional connected DB socket.
pub const ACCESS_KINDS: &[ResourceKind] = &[ResourceKind::IpcPipe, ResourceKind::ConnectedSocket];

/// vauban-audit: peer IPC pipes (incl. the SCM_RIGHTS fd-passing socket,
/// which the legacy code limits as a plain read/write pipe).
pub const AUDIT_KINDS: &[ResourceKind] = &[ResourceKind::IpcPipe];

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

/// vauban-web: a pre-bound HTTP listener. The web runtime keeps `cap_enter`
/// as its only FreeBSD wall (no per-fd limiting).
pub const WEB_KINDS: &[ResourceKind] = &[ResourceKind::Listener];

/// Canonical profile for the vauban-web HTTP server.
///
/// On FreeBSD this enters `cap_enter()` without limiting per-fd rights (the
/// tokio/axum listener needs a hard-to-enumerate right set). On Linux /
/// OpenBSD the listener drives the `accept4` / `inet` allowances.
#[must_use]
pub fn web_server(listener_fd: RawFd) -> SandboxProfile {
    SandboxProfile::new()
        .listener(listener_fd)
        .without_capsicum_fd_limiting()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn web_profile_matches_catalogue() {
        let p = web_server(3);
        assert_eq!(p.kinds(), WEB_KINDS.to_vec());
        // web relies on cap_enter only.
        assert!(!p.capsicum_limit_fds());
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
