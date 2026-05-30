//! FreeBSD Capsicum backend.
//!
//! Capsicum is a capability-based sandbox: the process enters an
//! irreversible "capability mode" (`cap_enter`) after which it can only act
//! on already-open file descriptors, and each fd can have its rights
//! narrowed (`cap_rights_limit`). This backend is a faithful port of the
//! historic `shared::capsicum` module -- the exact `Resource -> CapRights`
//! mapping is preserved so the FreeBSD production behavior is unchanged.

use super::{Entered, Resource, Result, SandboxBackend, SandboxError, SandboxProfile};
use std::os::unix::io::RawFd;

/// Capability rights flags (mirrors FreeBSD `cap_rights`). Crate-internal:
/// an implementation detail of the Capsicum backend.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct CapRights {
    pub read: bool,
    pub write: bool,
    pub seek: bool,
    pub mmap: bool,
    pub event: bool,
    pub fcntl: bool,
    pub fstat: bool,
    pub connect: bool,
    pub accept: bool,
    pub listen: bool,
    pub bind: bool,
    pub getpeername: bool,
    pub getsockname: bool,
    pub getsockopt: bool,
    pub setsockopt: bool,
    pub lookup: bool,
    pub create: bool,
    pub mkdirat: bool,
    pub fstatat: bool,
    pub unlinkat: bool,
    pub ftruncate: bool,
}

impl CapRights {
    /// Rights for a readable file descriptor.
    pub fn read_only() -> Self {
        Self {
            read: true,
            fstat: true,
            event: true,
            ..Default::default()
        }
    }

    /// Rights for a writable file descriptor.
    pub fn write_only() -> Self {
        Self {
            write: true,
            fstat: true,
            event: true,
            ..Default::default()
        }
    }

    /// Rights for a read-write file descriptor.
    pub fn read_write() -> Self {
        Self {
            read: true,
            write: true,
            fstat: true,
            event: true,
            ..Default::default()
        }
    }

    /// Rights for a connected socket.
    pub fn connected_socket() -> Self {
        Self {
            read: true,
            write: true,
            event: true,
            fstat: true,
            getpeername: true,
            getsockname: true,
            getsockopt: true,
            setsockopt: true,
            ..Default::default()
        }
    }

    /// Rights for a listening socket.
    ///
    /// SECURITY (FreeBSD/Capsicum): on FreeBSD, `accept()` returns a new fd
    /// that **inherits the cap rights of the listening socket** (the kernel
    /// intersects the listener's rights into the accepted fd -- the
    /// `cap_rights_inherit()` semantics in `accept(2)` under "CAPABILITIES").
    /// Therefore EVERY right the eventual connected socket needs MUST be set
    /// here, otherwise the first `read()` / `write()` on the accepted fd
    /// fails with errno 93 and the russh handshake stalls before the banner.
    pub fn listening_socket() -> Self {
        Self {
            accept: true,
            listen: true,
            // Inherited by accepted children (FreeBSD `cap_rights_inherit`):
            read: true,
            write: true,
            getpeername: true,
            // Listener-side rights:
            event: true,
            fcntl: true,
            fstat: true,
            getsockname: true,
            getsockopt: true,
            setsockopt: true,
            ..Default::default()
        }
    }

    /// Rights for a TCP connection (database, cache, etc.).
    pub fn tcp_connection() -> Self {
        Self {
            read: true,
            write: true,
            event: true,
            fstat: true,
            getsockopt: true,
            setsockopt: true,
            getpeername: true,
            getsockname: true,
            ..Default::default()
        }
    }

    /// Rights for a Unix socket that receives fds via SCM_RIGHTS (read-only).
    pub fn fd_receiver_socket() -> Self {
        Self {
            read: true,
            event: true,
            fstat: true,
            getsockopt: true,
            ..Default::default()
        }
    }

    /// Rights for a pre-opened storage directory (openat / mkdirat).
    pub fn directory() -> Self {
        Self {
            lookup: true,
            read: true,
            write: true,
            create: true,
            mkdirat: true,
            fstat: true,
            fstatat: true,
            ftruncate: true,
            seek: true,
            ..Default::default()
        }
    }
}

/// Enter capability mode (point of no return).
pub(crate) fn enter_capability_mode() -> Result<()> {
    capsicum::enter().map_err(SandboxError::EnterFailed)?;
    tracing::info!("Entered Capsicum capability mode");
    Ok(())
}

/// Check if the process is currently in capability mode.
#[allow(dead_code)] // retained for diagnostics / future self-tests
pub(crate) fn in_capability_mode() -> bool {
    capsicum::sandboxed()
}

/// Limit the rights on a file descriptor (must be called BEFORE
/// `enter_capability_mode`). Rights can only be narrowed, never widened.
pub(crate) fn limit_fd_rights(fd: RawFd, rights: &CapRights) -> Result<()> {
    use capsicum::CapRights as CapsicumCapRights; // Trait needed for .limit()
    use capsicum::{FileRights, Right};
    use std::os::unix::io::BorrowedFd;

    let mut file_rights = FileRights::new();

    if rights.read {
        file_rights.allow(Right::Read);
    }
    if rights.write {
        file_rights.allow(Right::Write);
    }
    if rights.seek {
        file_rights.allow(Right::Seek);
    }
    if rights.mmap {
        file_rights.allow(Right::Mmap);
    }
    if rights.event {
        file_rights.allow(Right::Event);
    }
    if rights.fcntl {
        file_rights.allow(Right::Fcntl);
    }
    if rights.fstat {
        file_rights.allow(Right::Fstat);
    }
    if rights.connect {
        file_rights.allow(Right::Connect);
    }
    if rights.accept {
        file_rights.allow(Right::Accept);
    }
    if rights.listen {
        file_rights.allow(Right::Listen);
    }
    if rights.bind {
        file_rights.allow(Right::Bind);
    }
    if rights.getpeername {
        file_rights.allow(Right::Getpeername);
    }
    if rights.getsockname {
        file_rights.allow(Right::Getsockname);
    }
    if rights.getsockopt {
        file_rights.allow(Right::Getsockopt);
    }
    if rights.setsockopt {
        file_rights.allow(Right::Setsockopt);
    }
    if rights.lookup {
        file_rights.allow(Right::Lookup);
    }
    if rights.create {
        file_rights.allow(Right::Create);
    }
    if rights.mkdirat {
        file_rights.allow(Right::Mkdirat);
    }
    if rights.fstatat {
        file_rights.allow(Right::Fstatat);
    }
    if rights.unlinkat {
        file_rights.allow(Right::Unlinkat);
    }
    if rights.ftruncate {
        file_rights.allow(Right::Ftruncate);
    }

    // SAFETY: The caller guarantees the fd is valid and open.
    let borrowed_fd = unsafe { BorrowedFd::borrow_raw(fd) };

    file_rights.limit(&borrowed_fd).map_err(|e| {
        SandboxError::LimitFailed(std::io::Error::from_raw_os_error(
            e.raw_os_error().unwrap_or(libc::EINVAL),
        ))
    })?;

    tracing::debug!("Limited rights on fd {}", fd);
    Ok(())
}

/// FreeBSD Capsicum sandbox backend.
///
/// `#[allow(clippy::upper_case_acronyms)]`: "FreeBSD" and "OpenBSD" are
/// proper nouns; rendering them `Freebsd` / `Openbsd` would be incorrect.
#[allow(clippy::upper_case_acronyms)]
struct FreeBSDBackend {
    limit_fds: bool,
}

impl SandboxBackend for FreeBSDBackend {
    fn restrict(&mut self, resource: &Resource) -> Result<()> {
        // vauban-web opts out of per-fd limiting (tokio/axum need a
        // hard-to-enumerate right set); cap_enter alone is its wall.
        if !self.limit_fds {
            return Ok(());
        }
        // EXHAUSTIVE match (no `_ =>`): a new Resource variant fails to
        // compile until handled here. Mapping preserved 1:1 from the
        // historic `setup_service_sandbox*` helpers.
        match resource {
            Resource::IpcPipe(fd) => limit_fd_rights(*fd, &CapRights::read_write()),
            Resource::FdReceiver(fd) => limit_fd_rights(*fd, &CapRights::fd_receiver_socket()),
            Resource::ConnectedSocket(fd) => limit_fd_rights(*fd, &CapRights::connected_socket()),
            Resource::Listener(fd) => limit_fd_rights(*fd, &CapRights::listening_socket()),
            Resource::WritableDir { fd, .. } => limit_fd_rights(*fd, &CapRights::directory()),
            // Capsicum is fd-based: a bare readable path has no fd to limit
            // here (the holder must pass the dir fd as WritableDir instead).
            Resource::ReadablePath(_) => Ok(()),
        }
    }

    fn commit(self, _required: bool) -> Result<Entered> {
        enter_capability_mode()?;
        Ok(Entered::witness())
    }
}

pub(crate) fn apply(profile: SandboxProfile) -> Result<Entered> {
    let backend = FreeBSDBackend {
        limit_fds: profile.capsicum_limit_fds(),
    };
    super::run_backend(backend, &profile)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sandbox_error_display_enter_failed() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "test error");
        let err = SandboxError::EnterFailed(io_err);
        assert!(format!("{}", err).contains("enter sandbox"));
    }

    #[test]
    fn sandbox_error_display_limit_failed() {
        let io_err = std::io::Error::new(std::io::ErrorKind::InvalidInput, "bad fd");
        let err = SandboxError::LimitFailed(io_err);
        assert!(format!("{}", err).contains("limit resource rights"));
    }

    #[test]
    fn test_cap_rights_default() {
        let rights = CapRights::default();
        assert!(!rights.read);
        assert!(!rights.write);
        assert!(!rights.accept);
        assert!(!rights.connect);
    }

    #[test]
    fn test_cap_rights_read_only() {
        let rights = CapRights::read_only();
        assert!(rights.read);
        assert!(!rights.write);
        assert!(rights.fstat);
        assert!(rights.event);
        assert!(!rights.connect);
    }

    #[test]
    fn test_cap_rights_write_only() {
        let rights = CapRights::write_only();
        assert!(!rights.read);
        assert!(rights.write);
        assert!(rights.fstat);
        assert!(rights.event);
    }

    #[test]
    fn test_cap_rights_read_write() {
        let rights = CapRights::read_write();
        assert!(rights.read);
        assert!(rights.write);
        assert!(rights.fstat);
        assert!(rights.event);
        assert!(!rights.connect);
        assert!(!rights.accept);
    }

    #[test]
    fn test_cap_rights_connected_socket() {
        let rights = CapRights::connected_socket();
        assert!(rights.read);
        assert!(rights.write);
        assert!(rights.event);
        assert!(rights.fstat);
        assert!(rights.getpeername);
        assert!(rights.getsockname);
        assert!(rights.getsockopt);
        assert!(rights.setsockopt);
        assert!(!rights.accept);
        assert!(!rights.listen);
        assert!(!rights.bind);
    }

    #[test]
    fn test_cap_rights_listening_socket() {
        let rights = CapRights::listening_socket();
        assert!(rights.accept);
        assert!(rights.listen);
        assert!(rights.event);
        assert!(rights.fcntl);
        assert!(rights.fstat);
        assert!(rights.getsockname);
        assert!(rights.getsockopt);
        assert!(rights.setsockopt);
        // SECURITY: inherited by accepted children via cap_rights_inherit().
        assert!(
            rights.read,
            "listening_socket MUST grant CAP_READ so accepted children inherit it"
        );
        assert!(
            rights.write,
            "listening_socket MUST grant CAP_WRITE so accepted children inherit it"
        );
        assert!(
            rights.getpeername,
            "listening_socket MUST grant CAP_GETPEERNAME for EWS peer IP logging"
        );
        assert!(!rights.connect);
    }

    #[test]
    fn test_cap_rights_directory() {
        let rights = CapRights::directory();
        assert!(rights.lookup);
        assert!(rights.read);
        assert!(rights.write);
        assert!(rights.create);
        assert!(rights.mkdirat);
        assert!(rights.fstat);
        assert!(rights.fstatat);
        assert!(rights.ftruncate);
        assert!(rights.seek);
        assert!(!rights.connect);
        assert!(!rights.accept);
        assert!(!rights.unlinkat);
    }

    #[test]
    fn test_cap_rights_tcp_connection() {
        let rights = CapRights::tcp_connection();
        assert!(rights.read);
        assert!(rights.write);
        assert!(rights.event);
        assert!(rights.fstat);
        assert!(rights.getsockopt);
        assert!(rights.setsockopt);
        assert!(rights.getpeername);
        assert!(rights.getsockname);
        assert!(!rights.accept);
        assert!(!rights.listen);
        assert!(!rights.bind);
        assert!(!rights.connect);
    }

    #[test]
    fn test_cap_rights_fd_receiver_socket() {
        let rights = CapRights::fd_receiver_socket();
        assert!(rights.read);
        assert!(rights.event);
        assert!(rights.fstat);
        assert!(rights.getsockopt);
        assert!(!rights.write);
        assert!(!rights.connect);
        assert!(!rights.accept);
        assert!(!rights.listen);
        assert!(!rights.bind);
    }

    #[test]
    fn test_cap_rights_custom_combination() {
        let rights = CapRights {
            read: true,
            write: true,
            seek: true,
            mmap: true,
            ..Default::default()
        };
        assert!(rights.read);
        assert!(rights.write);
        assert!(rights.seek);
        assert!(rights.mmap);
        assert!(!rights.event);
        assert!(!rights.fcntl);
    }
}
