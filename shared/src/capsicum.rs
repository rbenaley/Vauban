//! Capsicum sandboxing wrappers for FreeBSD.
//!
//! Capsicum is a capability-based security framework that allows processes
//! to enter a sandbox where they can only access pre-opened file descriptors.
//!
//! On FreeBSD, this module uses the `capsicum` crate to limit file descriptor
//! rights and enter capability mode. On other platforms, stub implementations
//! are provided for development.

use std::os::unix::io::RawFd;
use thiserror::Error;

/// Capsicum sandbox errors.
#[derive(Debug, Error)]
pub enum CapsicumError {
    #[error("Failed to enter capability mode: {0}")]
    EnterFailed(std::io::Error),

    #[error("Failed to limit fd rights: {0}")]
    LimitFailed(std::io::Error),

    #[error("Capsicum not available on this platform")]
    NotAvailable,
}

/// Result type for Capsicum operations.
pub type Result<T> = std::result::Result<T, CapsicumError>;

/// Capability rights flags (mirrors FreeBSD cap_rights).
#[derive(Debug, Clone, Copy)]
pub struct CapRights {
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
}

impl Default for CapRights {
    fn default() -> Self {
        Self {
            read: false,
            write: false,
            seek: false,
            mmap: false,
            event: false,
            fcntl: false,
            fstat: false,
            connect: false,
            accept: false,
            listen: false,
            bind: false,
            getpeername: false,
            getsockname: false,
            getsockopt: false,
            setsockopt: false,
        }
    }
}

impl CapRights {
    /// Create rights for a readable file descriptor.
    pub fn read_only() -> Self {
        Self {
            read: true,
            fstat: true,
            event: true,
            ..Default::default()
        }
    }

    /// Create rights for a writable file descriptor.
    pub fn write_only() -> Self {
        Self {
            write: true,
            fstat: true,
            event: true,
            ..Default::default()
        }
    }

    /// Create rights for a read-write file descriptor.
    pub fn read_write() -> Self {
        Self {
            read: true,
            write: true,
            fstat: true,
            event: true,
            ..Default::default()
        }
    }

    /// Create rights for a connected socket.
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

    /// Create rights for a listening socket.
    ///
    /// Includes rights needed for async I/O (tokio/mio):
    /// - CAP_FCNTL for non-blocking mode
    /// - CAP_EVENT for kqueue/poll
    pub fn listening_socket() -> Self {
        Self {
            accept: true,
            listen: true,
            event: true,
            fcntl: true, // Required for async I/O (non-blocking mode)
            fstat: true,
            getsockname: true,
            getsockopt: true,
            setsockopt: true,
            ..Default::default()
        }
    }

    /// Create rights for a TCP connection (database, cache, etc.).
    ///
    /// This is similar to `connected_socket()` but explicitly for
    /// established TCP connections used for database or cache access.
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
}

/// Enter capability mode (point of no return).
///
/// After calling this function:
/// - No new file descriptors can be opened from the global namespace
/// - The process can only access pre-opened file descriptors
/// - Fork/exec is still allowed (children inherit capability mode)
///
/// # Errors
/// Returns an error if entering capability mode fails.
#[cfg(target_os = "freebsd")]
pub fn enter_capability_mode() -> Result<()> {
    // SAFETY: cap_enter() is a FreeBSD system call
    let ret = unsafe { libc::cap_enter() };

    if ret != 0 {
        return Err(CapsicumError::EnterFailed(std::io::Error::last_os_error()));
    }

    tracing::info!("Entered Capsicum capability mode");
    Ok(())
}

/// Check if the process is currently in capability mode.
#[cfg(target_os = "freebsd")]
pub fn in_capability_mode() -> bool {
    let mut mode: libc::c_uint = 0;

    // SAFETY: cap_getmode() is a FreeBSD system call
    let ret = unsafe { libc::cap_getmode(&mut mode) };

    ret == 0 && mode != 0
}

/// Limit the rights on a file descriptor.
///
/// This must be called BEFORE entering capability mode.
/// Once rights are limited, they cannot be expanded.
///
/// # Safety
/// The file descriptor must be valid and open.
#[cfg(target_os = "freebsd")]
pub fn limit_fd_rights(fd: RawFd, rights: &CapRights) -> Result<()> {
    use capsicum::CapRights as CapsicumCapRights; // Trait needed for .limit()
    use capsicum::{FileRights, Right};
    use std::os::unix::io::BorrowedFd;

    // Build FileRights from our CapRights
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

    // SAFETY: The caller guarantees the fd is valid
    let borrowed_fd = unsafe { BorrowedFd::borrow_raw(fd) };

    file_rights
        .limit(&borrowed_fd)
        .map_err(|e| CapsicumError::LimitFailed(std::io::Error::from_raw_os_error(e.raw_os_error().unwrap_or(libc::EINVAL))))?;

    tracing::debug!("Limited rights on fd {}", fd);
    Ok(())
}

// ============================================================================
// Stub implementations for non-FreeBSD platforms (development)
// ============================================================================

#[cfg(not(target_os = "freebsd"))]
pub fn enter_capability_mode() -> Result<()> {
    tracing::warn!("Capsicum not available: running without sandbox");
    Ok(())
}

#[cfg(not(target_os = "freebsd"))]
pub fn in_capability_mode() -> bool {
    false
}

#[cfg(not(target_os = "freebsd"))]
pub fn limit_fd_rights(_fd: RawFd, _rights: &CapRights) -> Result<()> {
    tracing::debug!("Capsicum not available: fd rights not limited");
    Ok(())
}

/// Setup sandbox for a service with typical IPC pipes.
///
/// This is a helper function that:
/// 1. Limits rights on the provided file descriptors
/// 2. Enters capability mode
///
/// Call this after opening all required resources but before the main loop.
pub fn setup_service_sandbox(ipc_fds: &[RawFd], db_fd: Option<RawFd>) -> Result<()> {
    // Limit IPC pipe rights
    for &fd in ipc_fds {
        limit_fd_rights(fd, &CapRights::read_write())?;
    }

    // Limit database socket rights if present
    if let Some(fd) = db_fd {
        limit_fd_rights(fd, &CapRights::connected_socket())?;
    }

    // Enter capability mode
    enter_capability_mode()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== CapsicumError Tests ====================

    #[test]
    fn test_capsicum_error_display_enter_failed() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "test error");
        let err = CapsicumError::EnterFailed(io_err);
        let msg = format!("{}", err);
        assert!(msg.contains("enter capability mode"));
    }

    #[test]
    fn test_capsicum_error_display_limit_failed() {
        let io_err = std::io::Error::new(std::io::ErrorKind::InvalidInput, "bad fd");
        let err = CapsicumError::LimitFailed(io_err);
        let msg = format!("{}", err);
        assert!(msg.contains("limit fd rights"));
    }

    #[test]
    fn test_capsicum_error_display_not_available() {
        let err = CapsicumError::NotAvailable;
        let msg = format!("{}", err);
        assert!(msg.contains("not available"));
    }

    // ==================== CapRights Tests ====================

    #[test]
    fn test_cap_rights_default() {
        let rights = CapRights::default();
        assert!(!rights.read);
        assert!(!rights.write);
        assert!(!rights.seek);
        assert!(!rights.mmap);
        assert!(!rights.event);
        assert!(!rights.fcntl);
        assert!(!rights.fstat);
        assert!(!rights.connect);
        assert!(!rights.accept);
        assert!(!rights.listen);
        assert!(!rights.bind);
        assert!(!rights.getpeername);
        assert!(!rights.getsockname);
        assert!(!rights.getsockopt);
        assert!(!rights.setsockopt);
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
        assert!(rights.fstat);
        assert!(rights.getsockname);
        assert!(rights.getsockopt);
        assert!(rights.setsockopt);
        assert!(!rights.read);
        assert!(!rights.write);
        assert!(!rights.connect);
    }

    #[test]
    fn test_cap_rights_clone() {
        let rights = CapRights::read_write();
        let cloned = rights;
        assert_eq!(rights.read, cloned.read);
        assert_eq!(rights.write, cloned.write);
    }

    #[test]
    fn test_cap_rights_debug() {
        let rights = CapRights::read_only();
        let debug_str = format!("{:?}", rights);
        assert!(debug_str.contains("CapRights"));
        assert!(debug_str.contains("read: true"));
    }

    // ==================== Platform-specific Function Tests ====================

    #[test]
    fn test_enter_capability_mode_non_freebsd() {
        // On non-FreeBSD, this should return Ok and log a warning
        let result = enter_capability_mode();
        assert!(result.is_ok());
    }

    #[test]
    fn test_in_capability_mode_non_freebsd() {
        // On non-FreeBSD, we're never in capability mode
        assert!(!in_capability_mode());
    }

    #[test]
    fn test_limit_fd_rights_non_freebsd() {
        // On non-FreeBSD, this should return Ok
        let result = limit_fd_rights(0, &CapRights::read_only());
        assert!(result.is_ok());
    }

    // ==================== setup_service_sandbox Tests ====================

    #[test]
    fn test_setup_service_sandbox_empty() {
        let result = setup_service_sandbox(&[], None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_setup_service_sandbox_with_fds() {
        // Create a real fd pair for testing
        let (parent, child) = crate::ipc::IpcChannel::pair().unwrap();
        let fds = [parent.read_fd(), parent.write_fd()];
        
        let result = setup_service_sandbox(&fds, None);
        assert!(result.is_ok());
        
        // Prevent unused warnings
        drop(child);
    }

    #[test]
    fn test_setup_service_sandbox_with_db_fd() {
        // Use a real fd for testing
        let (parent, child) = crate::ipc::IpcChannel::pair().unwrap();
        let db_fd = Some(parent.read_fd());
        
        let result = setup_service_sandbox(&[], db_fd);
        assert!(result.is_ok());
        
        // Prevent unused warnings
        drop(parent);
        drop(child);
    }

    #[test]
    fn test_setup_service_sandbox_full() {
        let (ch1, _) = crate::ipc::IpcChannel::pair().unwrap();
        let (ch2, _) = crate::ipc::IpcChannel::pair().unwrap();
        
        let ipc_fds = [ch1.read_fd(), ch1.write_fd()];
        let db_fd = Some(ch2.read_fd());
        
        let result = setup_service_sandbox(&ipc_fds, db_fd);
        assert!(result.is_ok());
    }

    // ==================== Custom CapRights Tests ====================

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
}
