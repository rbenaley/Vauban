//! IPC client for communication with vauban-rbac.
//!
//! Provides async methods to check RBAC permissions via IPC pipes
//! to the RBAC service (Casbin enforcer).
//!
//! Follows the same pattern as `VaultCryptoClient`.

use crate::error::{AppError, AppResult};
use shared::ipc::IpcChannel;
use shared::messages::{Message, RbacResult};
use std::collections::HashMap;
use std::io;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use tokio::sync::{oneshot, Mutex};
use tracing::{debug, error, info, warn};

/// Async IPC client for vauban-rbac authorization checks.
pub struct RbacIpcClient {
    channel: IpcChannel,
    read_async_fd: AsyncFd<RawFd>,
    next_request_id: AtomicU64,
    pending_requests: Mutex<HashMap<u64, oneshot::Sender<RbacResult>>>,
}

impl RbacIpcClient {
    /// Create a new RBAC IPC client.
    ///
    /// The file descriptors are passed by the supervisor via topology pipes.
    pub fn new(read_fd: RawFd, write_fd: RawFd) -> io::Result<Arc<Self>> {
        let channel = unsafe { IpcChannel::from_raw_fds(read_fd, write_fd) };

        set_nonblocking(read_fd)?;

        let read_async_fd = AsyncFd::new(read_fd)?;

        Ok(Arc::new(Self {
            channel,
            read_async_fd,
            next_request_id: AtomicU64::new(1),
            pending_requests: Mutex::new(HashMap::new()),
        }))
    }

    /// Check if a subject has permission to perform an action on a resource.
    ///
    /// Fail-closed: returns false on IPC errors.
    pub async fn check_permission(
        &self,
        subject: &str,
        resource: &str,
        action: &str,
    ) -> AppResult<bool> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = oneshot::channel();

        self.pending_requests.lock().await.insert(request_id, tx);

        let msg = Message::RbacCheck {
            request_id,
            subject: subject.to_string(),
            object: resource.to_string(),
            action: action.to_string(),
        };
        self.channel
            .send(&msg)
            .map_err(|e| AppError::Ipc(format!("rbac send error: {}", e)))?;

        debug!(request_id, subject, resource, action, "RbacCheck request sent");

        let result = rx
            .await
            .map_err(|_| AppError::Ipc("rbac response channel dropped".to_string()))?;

        Ok(result.allowed)
    }

    /// Process incoming messages from the RBAC service.
    ///
    /// Should be spawned as a background task via `tokio::spawn`.
    pub async fn process_incoming(&self) -> AppResult<()> {
        loop {
            let mut guard = self
                .read_async_fd
                .ready(Interest::READABLE)
                .await
                .map_err(|e| AppError::Ipc(format!("AsyncFd ready failed: {}", e)))?;

            loop {
                match self.channel.try_recv() {
                    Ok(msg) => {
                        self.handle_message(msg).await;
                    }
                    Err(shared::ipc::IpcError::Io(ref e))
                        if e.kind() == io::ErrorKind::WouldBlock =>
                    {
                        guard.clear_ready();
                        break;
                    }
                    Err(shared::ipc::IpcError::ConnectionClosed) => {
                        info!("RBAC IPC connection closed");
                        return Err(AppError::Ipc("RBAC IPC connection closed".to_string()));
                    }
                    Err(e) => {
                        error!(error = %e, "RBAC IPC receive error");
                        guard.clear_ready();
                        break;
                    }
                }
            }
        }
    }

    async fn handle_message(&self, msg: Message) {
        let request_id = msg.request_id();

        let result = match msg {
            Message::RbacResponse { result, .. } => result,
            other => {
                warn!("Unexpected message from RBAC service: {:?}", other);
                return;
            }
        };

        if let Some(rid) = request_id {
            let mut pending = self.pending_requests.lock().await;
            if let Some(tx) = pending.remove(&rid) {
                let _ = tx.send(result);
            } else {
                warn!(request_id = rid, "No pending request for RBAC response");
            }
        }
    }
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    use libc::{fcntl, F_GETFL, F_SETFL, O_NONBLOCK};

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;
    use std::sync::atomic::Ordering;

    #[test]
    fn test_set_nonblocking() {
        let (read_fd, _write_fd) = nix::unistd::pipe().unwrap();
        let result = set_nonblocking(read_fd.as_raw_fd());
        assert!(result.is_ok());

        use libc::{fcntl, F_GETFL, O_NONBLOCK};
        let flags = unsafe { fcntl(read_fd.as_raw_fd(), F_GETFL) };
        assert!(flags & O_NONBLOCK != 0);
    }

    #[test]
    fn test_request_id_counter_increments() {
        let counter = AtomicU64::new(1);
        let id1 = counter.fetch_add(1, Ordering::SeqCst);
        let id2 = counter.fetch_add(1, Ordering::SeqCst);
        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
    }
}
