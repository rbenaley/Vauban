//! Async IPC clients for communication with other Vauban services.

pub use crate::error::{IpcError, IpcResult};
use crate::session::SshCredential;
use secrecy::SecretString;
use shared::ipc::IpcChannel;
use shared::messages::Message;
use std::io;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use tracing::{debug, warn};

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
                Err(shared::ipc::IpcError::Io(ref e))
                    if e.kind() == io::ErrorKind::WouldBlock =>
                {
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
    use libc::{fcntl, F_GETFL, F_SETFL, O_NONBLOCK};
    
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

/// Client for RBAC authorization checks.
/// Will be used when RBAC integration is implemented.
#[allow(dead_code)]
pub struct RbacClient {
    channel: AsyncIpcChannel,
    next_request_id: AtomicU64,
}

#[allow(dead_code)]
impl RbacClient {
    /// Create a new RBAC client.
    pub fn new(channel: IpcChannel) -> io::Result<Self> {
        Ok(Self {
            channel: AsyncIpcChannel::new(channel)?,
            next_request_id: AtomicU64::new(1),
        })
    }

    /// Check if a subject is allowed to perform an action on an object.
    pub async fn check(&self, subject: &str, object: &str, action: &str) -> IpcResult<bool> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::SeqCst);

        debug!(
            request_id = request_id,
            subject = subject,
            object = object,
            action = action,
            "Sending RBAC check"
        );

        // Send request
        let request = Message::RbacCheck {
            request_id,
            subject: subject.to_string(),
            object: object.to_string(),
            action: action.to_string(),
        };
        self.channel.send(&request)?;

        // Wait for response
        loop {
            let response = self.channel.recv().await?;
            match response {
                Message::RbacResponse {
                    request_id: resp_id,
                    result,
                } if resp_id == request_id => {
                    debug!(
                        request_id = request_id,
                        allowed = result.allowed,
                        "RBAC response received"
                    );
                    return Ok(result.allowed);
                }
                _ => {
                    // Ignore messages with different request_id
                    warn!("Received unexpected message while waiting for RBAC response");
                }
            }
        }
    }
}

/// Client for Vault credential retrieval.
/// Will be used when Vault integration is implemented.
#[allow(dead_code)]
pub struct VaultClient {
    channel: AsyncIpcChannel,
    next_request_id: AtomicU64,
}

#[allow(dead_code)]
impl VaultClient {
    /// Create a new Vault client.
    pub fn new(channel: IpcChannel) -> io::Result<Self> {
        Ok(Self {
            channel: AsyncIpcChannel::new(channel)?,
            next_request_id: AtomicU64::new(1),
        })
    }

    /// Get SSH credential for an asset.
    pub async fn get_credential(&self, asset_id: &str) -> IpcResult<Option<SshCredential>> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::SeqCst);

        debug!(
            request_id = request_id,
            asset_id = asset_id,
            "Requesting SSH credential from Vault"
        );

        // Send request
        let request = Message::VaultGetCredential {
            request_id,
            asset_id: asset_id.to_string(),
            credential_type: "ssh".to_string(),
        };
        self.channel.send(&request)?;

        // Wait for response
        loop {
            let response = self.channel.recv().await?;
            match response {
                Message::VaultCredentialResponse {
                    request_id: resp_id,
                    credential,
                } if resp_id == request_id => {
                    debug!(
                        request_id = request_id,
                        found = credential.is_some(),
                        "Vault response received"
                    );

                    // Parse credential bytes into SshCredential
                    // For now, assume it's a password (TODO: implement proper credential parsing)
                    let ssh_cred = credential.map(|data| {
                        // Try to parse as UTF-8 password first
                        if let Ok(password) = String::from_utf8(data.clone()) {
                            SshCredential::Password(SecretString::from(password))
                        } else {
                            // Treat as binary key (PEM encoded)
                            SshCredential::PrivateKey {
                                key_pem: SecretString::from(String::from_utf8_lossy(&data).to_string()),
                                passphrase: None,
                            }
                        }
                    });

                    return Ok(ssh_cred);
                }
                _ => {
                    warn!("Received unexpected message while waiting for Vault response");
                }
            }
        }
    }
}

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
    pub fn session_end(
        &self,
        user_id: &str,
        session_id: &str,
        asset_id: &str,
    ) -> IpcResult<()> {
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
    use secrecy::ExposeSecret;

    #[test]
    fn test_set_nonblocking() {
        use std::os::unix::io::AsRawFd;

        // Create a pipe for testing
        let (read_fd, _write_fd) = nix::unistd::pipe().unwrap();

        // Set non-blocking
        let result = set_nonblocking(read_fd.as_raw_fd());
        assert!(result.is_ok());

        // Verify it's non-blocking
        use libc::{fcntl, F_GETFL, O_NONBLOCK};
        let flags = unsafe { fcntl(read_fd.as_raw_fd(), F_GETFL) };
        assert!(flags & O_NONBLOCK != 0);
    }

    #[test]
    fn test_set_nonblocking_preserves_other_flags() {
        use std::os::unix::io::AsRawFd;

        // Create a pipe for testing
        let (read_fd, _write_fd) = nix::unistd::pipe().unwrap();

        use libc::{fcntl, F_GETFL, O_NONBLOCK};
        let original_flags = unsafe { fcntl(read_fd.as_raw_fd(), F_GETFL) };

        // Set non-blocking
        set_nonblocking(read_fd.as_raw_fd()).unwrap();

        // Check that O_NONBLOCK is set and other flags are preserved
        let new_flags = unsafe { fcntl(read_fd.as_raw_fd(), F_GETFL) };
        assert_eq!(new_flags, original_flags | O_NONBLOCK);
    }

    #[test]
    fn test_rbac_client_request_id_increment() {
        // We can't fully test without a real channel, but we can test the atomic counter
        let counter = AtomicU64::new(1);
        let id1 = counter.fetch_add(1, Ordering::SeqCst);
        let id2 = counter.fetch_add(1, Ordering::SeqCst);
        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
    }

    #[test]
    fn test_request_id_counter_wrapping() {
        let counter = AtomicU64::new(u64::MAX - 1);
        let id1 = counter.fetch_add(1, Ordering::SeqCst);
        let id2 = counter.fetch_add(1, Ordering::SeqCst);
        assert_eq!(id1, u64::MAX - 1);
        assert_eq!(id2, u64::MAX);
        // Next wraps to 0 (fetch_add returns previous value before wrapping)
        let id3 = counter.fetch_add(1, Ordering::SeqCst);
        assert_eq!(id3, 0); // Wrapping occurred, returned 0
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
            SshCredential::PrivateKey { key_pem, passphrase } => {
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
        assert!(!debug.contains("secret"), "H-10: credential must be redacted in debug");
    }
}
