//! Async IPC clients for communication with other Vauban services.
//!
//! Note: the defense-in-depth RBAC re-check client used to live in this
//! module as `AccessRbacClient`. It now lives in `shared::access_guard`
//! so it can be shared across every protocol proxy (SSH, RDP, future
//! VNC / industrial protocols) without duplication. See
//! `docs/runbooks/ipc_topology_debugging.md` for the full rationale.

pub use crate::error::{IpcError, IpcResult};
use shared::ipc::IpcChannel;
use shared::messages::Message;
use std::io;
use std::os::unix::io::RawFd;
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;

/// Async wrapper for IPC channel using tokio's AsyncFd.
pub struct AsyncIpcChannel {
    /// The underlying blocking IPC channel.
    inner: IpcChannel,
    /// Async file descriptor for the read end.
    read_async_fd: AsyncFd<RawFd>,
}

impl AsyncIpcChannel {
    /// Create a new async IPC channel from a blocking one.
    pub fn new(channel: IpcChannel) -> io::Result<Self> {
        let read_fd = channel.read_fd();

        // Set the read fd to non-blocking
        set_nonblocking(read_fd)?;

        let read_async_fd = AsyncFd::new(read_fd)?;

        Ok(Self {
            inner: channel,
            read_async_fd,
        })
    }

    /// Send a message asynchronously.
    /// Note: Writes are typically small and complete immediately, so we don't
    /// need full async write support for this use case.
    pub fn send(&self, msg: &Message) -> IpcResult<()> {
        self.inner.send(msg).map_err(IpcError::from)
    }

    /// Receive a message asynchronously.
    pub async fn recv(&self) -> IpcResult<Message> {
        loop {
            // Wait for the fd to be readable
            let mut guard = self
                .read_async_fd
                .ready(Interest::READABLE)
                .await
                .map_err(|e| IpcError::ReceiveFailed(e.to_string()))?;

            // Try to receive
            match self.inner.try_recv() {
                Ok(msg) => return Ok(msg),
                Err(shared::ipc::IpcError::Io(ref e)) if e.kind() == io::ErrorKind::WouldBlock => {
                    // Clear readiness and wait again
                    guard.clear_ready();
                    continue;
                }
                Err(shared::ipc::IpcError::ConnectionClosed) => {
                    return Err(IpcError::ConnectionClosed);
                }
                Err(e) => {
                    return Err(IpcError::ReceiveFailed(e.to_string()));
                }
            }
        }
    }

    /// Get the underlying IPC channel for low-level access.
    #[allow(dead_code)] // Will be used for advanced IPC operations
    pub fn inner(&self) -> &IpcChannel {
        &self.inner
    }
}

/// Set a file descriptor to non-blocking mode.
fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    use libc::{F_GETFL, F_SETFL, O_NONBLOCK, fcntl};

    // SAFETY: We're calling fcntl with valid arguments on a valid fd.
    unsafe {
        let flags = fcntl(fd, F_GETFL);
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

// SECURITY: A `VaultClient` lived here that emitted a legacy "get credential
// by id" IPC verb and silently mapped the resulting `Ok(None)` to "no
// credential available". That verb has been removed from `shared::messages`
// because it could be (mis)interpreted as "no credential needed -> allow the
// connection". Credential retrieval will be reintroduced via the
// encrypted-transit verbs (`VaultEncrypt` / `VaultDecrypt`) once the Vault
// integration is wired through the supervisor.

/// Client for sending audit events.
/// Will be used when Audit integration is implemented.
#[allow(dead_code)]
pub struct AuditClient {
    channel: AsyncIpcChannel,
}

#[allow(dead_code)]
impl AuditClient {
    /// Create a new Audit client.
    pub fn new(channel: IpcChannel) -> io::Result<Self> {
        Ok(Self {
            channel: AsyncIpcChannel::new(channel)?,
        })
    }

    /// Send an audit event (fire and forget, no response expected).
    pub fn send_event(&self, event: Message) -> IpcResult<()> {
        self.channel.send(&event)
    }

    /// Send a session start event.
    pub fn session_start(
        &self,
        user_id: &str,
        session_id: &str,
        asset_id: &str,
        source_ip: Option<std::net::IpAddr>,
    ) -> IpcResult<()> {
        use shared::messages::AuditEventType;
        use std::time::{SystemTime, UNIX_EPOCH};

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let event = Message::AuditEvent {
            timestamp,
            event_type: AuditEventType::SessionStart,
            user_id: Some(user_id.to_string()),
            session_id: Some(session_id.to_string()),
            source_ip,
            details: format!("SSH session started for asset {}", asset_id),
        };

        self.channel.send(&event)
    }

    /// Send a session end event.
    pub fn session_end(&self, user_id: &str, session_id: &str, asset_id: &str) -> IpcResult<()> {
        use shared::messages::AuditEventType;
        use std::time::{SystemTime, UNIX_EPOCH};

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let event = Message::AuditEvent {
            timestamp,
            event_type: AuditEventType::SessionEnd,
            user_id: Some(user_id.to_string()),
            session_id: Some(session_id.to_string()),
            source_ip: None,
            details: format!("SSH session ended for asset {}", asset_id),
        };

        self.channel.send(&event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::SshCredential;
    use secrecy::{ExposeSecret, SecretString};

    #[test]
    fn test_set_nonblocking() {
        use std::os::unix::io::AsRawFd;

        // Create a pipe for testing
        let (read_fd, _write_fd) = nix::unistd::pipe().unwrap();

        // Set non-blocking
        let result = set_nonblocking(read_fd.as_raw_fd());
        assert!(result.is_ok());

        // Verify it's non-blocking
        use libc::{F_GETFL, O_NONBLOCK, fcntl};
        let flags = unsafe { fcntl(read_fd.as_raw_fd(), F_GETFL) };
        assert!(flags & O_NONBLOCK != 0);
    }

    #[test]
    fn test_set_nonblocking_preserves_other_flags() {
        use std::os::unix::io::AsRawFd;

        // Create a pipe for testing
        let (read_fd, _write_fd) = nix::unistd::pipe().unwrap();

        use libc::{F_GETFL, O_NONBLOCK, fcntl};
        let original_flags = unsafe { fcntl(read_fd.as_raw_fd(), F_GETFL) };

        // Set non-blocking
        set_nonblocking(read_fd.as_raw_fd()).unwrap();

        // Check that O_NONBLOCK is set and other flags are preserved
        let new_flags = unsafe { fcntl(read_fd.as_raw_fd(), F_GETFL) };
        assert_eq!(new_flags, original_flags | O_NONBLOCK);
    }

    #[test]
    fn test_ssh_credential_password_clone() {
        let cred = SshCredential::Password(SecretString::from("test123".to_string()));
        let cloned = cred.clone();
        match &cloned {
            SshCredential::Password(p) => assert_eq!(p.expose_secret(), "test123"),
            _ => panic!("Expected Password variant"),
        }
    }

    #[test]
    fn test_ssh_credential_private_key_clone() {
        let cred = SshCredential::PrivateKey {
            key_pem: SecretString::from("key-data".to_string()),
            passphrase: None,
        };
        let cloned = cred.clone();
        match &cloned {
            SshCredential::PrivateKey {
                key_pem,
                passphrase,
            } => {
                assert_eq!(key_pem.expose_secret(), "key-data");
                assert!(passphrase.is_none());
            }
            _ => panic!("Expected PrivateKey variant"),
        }
    }

    #[test]
    fn test_ssh_credential_debug() {
        let cred = SshCredential::Password(SecretString::from("secret".to_string()));
        let debug = format!("{:?}", cred);
        assert!(debug.contains("Password"));
        assert!(
            !debug.contains("secret"),
            "credential must be redacted in debug"
        );
    }
}
