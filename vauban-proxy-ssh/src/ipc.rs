//! Async IPC clients for communication with other Vauban services.

pub use crate::error::{IpcError, IpcResult};
use shared::ipc::IpcChannel;
use shared::messages::{AccessRequest, AccessResponse, Message};
use std::collections::HashMap;
use std::io;
use std::os::unix::io::RawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::sync::{Mutex, oneshot};
use tracing::{debug, error, info, warn};

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

/// SECURITY: Async IPC client used to re-verify SSH session opens against
/// `vauban-access` from inside `vauban-proxy-ssh`'s Capsicum sandbox.
///
/// Defense-in-depth rationale: `vauban-web` already enforces RBAC before
/// emitting `Message::SshSessionOpen`, but the proxy cannot blindly trust
/// that gate -- a compromised or buggy web tier must not single-handedly
/// authorise an outbound SSH connection. Each session-open request is
/// re-checked here against the policy + access_rules tables via the
/// `AccessRequest::CheckAccessByUuid` verb (the proxy has no DB access
/// of its own).
///
/// Dispatch design follows `vauban-web::ipc::access::AccessIpcClient`:
/// concurrent in-flight requests are demultiplexed by `request_id` through a
/// shared `pending` map, so several SSH session opens can be authorised in
/// parallel without one stealing another's response. The IPC reader is run
/// as a dedicated tokio task (`process_incoming`) and feeds those oneshots.
pub struct AccessRbacClient {
    channel: IpcChannel,
    read_async_fd: AsyncFd<RawFd>,
    next_request_id: AtomicU64,
    pending: Mutex<HashMap<u64, oneshot::Sender<AccessResponse>>>,
}

impl AccessRbacClient {
    /// Create a new RBAC client over the access pipe pair handed down by the
    /// supervisor.
    pub fn new(read_fd: RawFd, write_fd: RawFd) -> io::Result<Arc<Self>> {
        // SAFETY: read_fd / write_fd are fresh pipe ends owned by this
        // process, passed in by the supervisor and not duplicated elsewhere.
        let channel = unsafe { IpcChannel::from_raw_fds(read_fd, write_fd) };
        set_nonblocking(read_fd)?;
        let read_async_fd = AsyncFd::new(read_fd)?;
        Ok(Arc::new(Self {
            channel,
            read_async_fd,
            next_request_id: AtomicU64::new(1),
            pending: Mutex::new(HashMap::new()),
        }))
    }

    /// Re-verify that `user_uuid` is allowed to open a `protocol` session
    /// against `asset_uuid`.
    ///
    /// Returns `Ok(true)` only when `vauban-access` explicitly grants the
    /// access. Returns `Ok(false)` for explicit policy denials AND for every
    /// other failure mode (unknown UUID, deleted asset, asset in no group,
    /// DB error). Returns `Err(_)` only on irrecoverable IPC errors (channel
    /// closed, send failure) so the caller can choose between "deny this
    /// request" and "tear the service down".
    pub async fn check_access_by_uuid(
        &self,
        user_uuid: &str,
        asset_uuid: &str,
        protocol: &str,
    ) -> IpcResult<bool> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(request_id, tx);

        let msg = Message::AccessRequest {
            request_id,
            request: AccessRequest::CheckAccessByUuid {
                user_uuid: user_uuid.to_string(),
                asset_uuid: asset_uuid.to_string(),
                protocol: protocol.to_string(),
            },
        };

        if let Err(e) = self.channel.send(&msg) {
            self.pending.lock().await.remove(&request_id);
            return Err(IpcError::SendFailed(e.to_string()));
        }

        debug!(
            request_id, user_uuid, asset_uuid, protocol,
            "AccessRbacClient: CheckAccessByUuid sent"
        );

        let response = rx.await.map_err(|_| {
            IpcError::ReceiveFailed("access response channel dropped".to_string())
        })?;

        match response {
            AccessResponse::AccessChecked(result) => {
                debug!(
                    request_id, user_uuid, asset_uuid, protocol,
                    allowed = result.allowed, "AccessRbacClient: response"
                );
                Ok(result.allowed)
            }
            AccessResponse::Error(e) => {
                // SECURITY: Treat backend-side errors as a policy denial,
                // not a transport error -- the access service already chose
                // to surface this through the response channel rather than
                // hanging up. Surfacing it as Ok(false) lets the caller
                // produce the same fail-closed behaviour as a denial.
                warn!(
                    request_id, user_uuid, asset_uuid, protocol, error = %e,
                    "AccessRbacClient: backend Error, denying fail-closed"
                );
                Ok(false)
            }
            other => {
                warn!(
                    request_id, user_uuid, asset_uuid, protocol,
                    response = ?other,
                    "AccessRbacClient: unexpected response variant, denying fail-closed"
                );
                Ok(false)
            }
        }
    }

    /// Background task that drains the access pipe and dispatches replies to
    /// the right `check_access_by_uuid` caller via the `pending` oneshots.
    ///
    /// MUST be spawned exactly once after `new()`. Returns when the channel
    /// is closed or hits an unrecoverable error -- the caller should treat
    /// that as a service-fatal condition and shut the proxy down (without
    /// this task running, every subsequent `check_access_by_uuid` would
    /// block forever).
    pub async fn process_incoming(self: Arc<Self>) -> IpcResult<()> {
        info!("AccessRbacClient: incoming dispatcher started");
        loop {
            let mut guard = self
                .read_async_fd
                .ready(Interest::READABLE)
                .await
                .map_err(|e| IpcError::ReceiveFailed(e.to_string()))?;

            match self.channel.try_recv() {
                Ok(Message::AccessResponse {
                    request_id,
                    response,
                }) => {
                    if let Some(tx) = self.pending.lock().await.remove(&request_id) {
                        if tx.send(response).is_err() {
                            debug!(
                                request_id,
                                "AccessRbacClient: caller dropped before response delivery"
                            );
                        }
                    } else {
                        warn!(
                            request_id,
                            "AccessRbacClient: response without pending request, dropping"
                        );
                    }
                }
                Ok(other) => {
                    warn!(
                        message = ?std::mem::discriminant(&other),
                        "AccessRbacClient: ignoring non-AccessResponse message on access pipe"
                    );
                }
                Err(shared::ipc::IpcError::Io(ref e)) if e.kind() == io::ErrorKind::WouldBlock => {
                    guard.clear_ready();
                    continue;
                }
                Err(shared::ipc::IpcError::ConnectionClosed) => {
                    error!("AccessRbacClient: access pipe closed, dispatcher exiting");
                    return Err(IpcError::ConnectionClosed);
                }
                Err(e) => {
                    error!(error = %e, "AccessRbacClient: fatal recv error, dispatcher exiting");
                    return Err(IpcError::ReceiveFailed(e.to_string()));
                }
            }
        }
    }
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

    // ==================== AccessRbacClient tests ====================

    use shared::messages::{AccessCheckResult, AccessResponse as AccessResp, RbacResult};

    /// Build a pair of pipes wired so that one end behaves as the proxy-ssh
    /// side (the AccessRbacClient) and the other as a stub vauban-access
    /// that we drive from the test.
    fn paired_channels() -> (IpcChannel, IpcChannel) {
        let (a_read, a_write) = nix::unistd::pipe().unwrap();
        let (b_read, b_write) = nix::unistd::pipe().unwrap();
        use std::os::unix::io::IntoRawFd;
        let proxy = unsafe {
            IpcChannel::from_raw_fds(a_read.into_raw_fd(), b_write.into_raw_fd())
        };
        let stub = unsafe {
            IpcChannel::from_raw_fds(b_read.into_raw_fd(), a_write.into_raw_fd())
        };
        (proxy, stub)
    }

    #[tokio::test]
    async fn test_access_rbac_client_check_allowed() {
        let (_proxy_for_drop, stub) = paired_channels();
        // Build the AccessRbacClient over a fresh pipe pair we own end-to-end.
        let (c_read, c_write) = nix::unistd::pipe().unwrap();
        let (d_read, d_write) = nix::unistd::pipe().unwrap();
        use std::os::unix::io::IntoRawFd;
        let client_read = c_read.into_raw_fd();
        let client_write = d_write.into_raw_fd();
        let stub2 = unsafe {
            IpcChannel::from_raw_fds(d_read.into_raw_fd(), c_write.into_raw_fd())
        };
        drop(stub);
        let _ = _proxy_for_drop;

        let client = AccessRbacClient::new(client_read, client_write).unwrap();
        let dispatcher = Arc::clone(&client);
        tokio::spawn(async move {
            let _ = dispatcher.process_incoming().await;
        });

        // Stub side: read the request, reply with allowed=true.
        let stub_join = tokio::task::spawn_blocking(move || {
            let req = stub2.recv().expect("stub recv");
            let request_id = match req {
                Message::AccessRequest {
                    request_id,
                    request: AccessRequest::CheckAccessByUuid { .. },
                } => request_id,
                other => panic!("unexpected request: {:?}", other),
            };
            stub2
                .send(&Message::AccessResponse {
                    request_id,
                    response: AccessResp::AccessChecked(AccessCheckResult {
                        allowed: true,
                        require_mfa: false,
                        require_approval: false,
                        max_session_duration: None,
                    }),
                })
                .expect("stub send");
        });

        let allowed = client
            .check_access_by_uuid("u-uuid", "a-uuid", "ssh")
            .await
            .expect("check_access_by_uuid");
        assert!(allowed, "stub returned allowed=true");
        stub_join.await.unwrap();
    }

    #[tokio::test]
    async fn test_access_rbac_client_check_denied() {
        let (c_read, c_write) = nix::unistd::pipe().unwrap();
        let (d_read, d_write) = nix::unistd::pipe().unwrap();
        use std::os::unix::io::IntoRawFd;
        let client_read = c_read.into_raw_fd();
        let client_write = d_write.into_raw_fd();
        let stub = unsafe {
            IpcChannel::from_raw_fds(d_read.into_raw_fd(), c_write.into_raw_fd())
        };

        let client = AccessRbacClient::new(client_read, client_write).unwrap();
        let dispatcher = Arc::clone(&client);
        tokio::spawn(async move {
            let _ = dispatcher.process_incoming().await;
        });

        let stub_join = tokio::task::spawn_blocking(move || {
            let req = stub.recv().expect("stub recv");
            let request_id = match req {
                Message::AccessRequest { request_id, .. } => request_id,
                other => panic!("unexpected request: {:?}", other),
            };
            stub.send(&Message::AccessResponse {
                request_id,
                response: AccessResp::AccessChecked(AccessCheckResult {
                    allowed: false,
                    require_mfa: false,
                    require_approval: false,
                    max_session_duration: None,
                }),
            })
            .expect("stub send");
        });

        let allowed = client
            .check_access_by_uuid("u-uuid", "a-uuid", "ssh")
            .await
            .expect("check_access_by_uuid");
        assert!(!allowed, "stub returned allowed=false -> client must deny");
        stub_join.await.unwrap();
    }

    #[tokio::test]
    async fn test_access_rbac_client_backend_error_treated_as_denial() {
        // SECURITY: A backend Error response must NOT bubble up as Err(_)
        // from check_access_by_uuid -- the caller in main.rs has separate
        // logging for the Err vs Ok(false) paths and we want the proxy to
        // treat backend complaints as policy denials (fail-closed) rather
        // than retry/timeout/panic.
        let (c_read, c_write) = nix::unistd::pipe().unwrap();
        let (d_read, d_write) = nix::unistd::pipe().unwrap();
        use std::os::unix::io::IntoRawFd;
        let client_read = c_read.into_raw_fd();
        let client_write = d_write.into_raw_fd();
        let stub = unsafe {
            IpcChannel::from_raw_fds(d_read.into_raw_fd(), c_write.into_raw_fd())
        };

        let client = AccessRbacClient::new(client_read, client_write).unwrap();
        let dispatcher = Arc::clone(&client);
        tokio::spawn(async move {
            let _ = dispatcher.process_incoming().await;
        });

        let stub_join = tokio::task::spawn_blocking(move || {
            let req = stub.recv().expect("stub recv");
            let request_id = match req {
                Message::AccessRequest { request_id, .. } => request_id,
                other => panic!("unexpected request: {:?}", other),
            };
            stub.send(&Message::AccessResponse {
                request_id,
                response: AccessResp::Error("simulated db meltdown".to_string()),
            })
            .expect("stub send");
        });

        let result = client
            .check_access_by_uuid("u-uuid", "a-uuid", "ssh")
            .await
            .expect("backend Error should NOT be surfaced as Err(_) here");
        assert!(
            !result,
            "backend Error must collapse to Ok(false) (fail-closed denial)"
        );
        stub_join.await.unwrap();
    }

    #[tokio::test]
    async fn test_access_rbac_client_demultiplexes_concurrent_requests() {
        // SECURITY: Two simultaneous SSH session opens must NOT see their
        // RBAC responses crossed -- i.e. caller A (asking about asset_a)
        // must never receive caller B's response. The pending-map dispatch
        // pattern enforces this; if anyone ever simplifies it back to a
        // single-receiver loop, this test will fail.
        let (c_read, c_write) = nix::unistd::pipe().unwrap();
        let (d_read, d_write) = nix::unistd::pipe().unwrap();
        use std::os::unix::io::IntoRawFd;
        let client_read = c_read.into_raw_fd();
        let client_write = d_write.into_raw_fd();
        let stub = unsafe {
            IpcChannel::from_raw_fds(d_read.into_raw_fd(), c_write.into_raw_fd())
        };

        let client = AccessRbacClient::new(client_read, client_write).unwrap();
        let dispatcher = Arc::clone(&client);
        tokio::spawn(async move {
            let _ = dispatcher.process_incoming().await;
        });

        let stub_join = tokio::task::spawn_blocking(move || {
            // Stub: read 2 requests, and reply OUT OF ORDER (second
            // response first) to confirm the dispatch handles it.
            let r1 = stub.recv().expect("stub recv 1");
            let id1 = match r1 {
                Message::AccessRequest { request_id, .. } => request_id,
                _ => panic!(),
            };
            let r2 = stub.recv().expect("stub recv 2");
            let (id2, asset2) = match r2 {
                Message::AccessRequest {
                    request_id,
                    request: AccessRequest::CheckAccessByUuid { asset_uuid, .. },
                } => (request_id, asset_uuid),
                _ => panic!(),
            };

            // Reply id2 first with allowed=true, then id1 with allowed=false.
            stub.send(&Message::AccessResponse {
                request_id: id2,
                response: AccessResp::AccessChecked(AccessCheckResult {
                    allowed: true,
                    require_mfa: false,
                    require_approval: false,
                    max_session_duration: None,
                }),
            })
            .unwrap();
            stub.send(&Message::AccessResponse {
                request_id: id1,
                response: AccessResp::AccessChecked(AccessCheckResult {
                    allowed: false,
                    require_mfa: false,
                    require_approval: false,
                    max_session_duration: None,
                }),
            })
            .unwrap();
            asset2
        });

        let client_a = Arc::clone(&client);
        let client_b = Arc::clone(&client);
        let h1 = tokio::spawn(async move {
            client_a
                .check_access_by_uuid("u", "asset-a", "ssh")
                .await
                .unwrap()
        });
        // Tiny stagger so the stub sees the requests in a deterministic order.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let h2 = tokio::spawn(async move {
            client_b
                .check_access_by_uuid("u", "asset-b", "ssh")
                .await
                .unwrap()
        });

        let asset2 = stub_join.await.unwrap();
        let r1 = h1.await.unwrap();
        let r2 = h2.await.unwrap();
        assert_eq!(asset2, "asset-b", "stub saw asset-b second");
        assert!(!r1, "first caller (asset-a) must observe allowed=false");
        assert!(r2, "second caller (asset-b) must observe allowed=true");
    }

    #[tokio::test]
    async fn test_access_rbac_client_caller_can_be_bounded_by_external_timeout() {
        // POST-INCIDENT REGRESSION GUARD: this is the exact failure mode
        // that tripped a supervisor unresponsive-restart in production --
        // vauban-access never replied to a CheckAccessByUuid request, the
        // proxy-ssh main loop blocked on the inline await, missed
        // heartbeats, and got killed.
        //
        // The IPC client itself does NOT impose a timeout (its job is
        // request/response demultiplexing); the call site MUST wrap it in
        // `tokio::time::timeout(...)`. This test pins down that contract:
        // the future returned by `check_access_by_uuid` is cancellable via
        // tokio::time::timeout WITHOUT poisoning the client for subsequent
        // requests.
        let (c_read, c_write) = nix::unistd::pipe().unwrap();
        let (d_read, d_write) = nix::unistd::pipe().unwrap();
        use std::os::unix::io::IntoRawFd;
        let client_read = c_read.into_raw_fd();
        let client_write = d_write.into_raw_fd();
        // Hold the stub end open but NEVER reply to the first request so
        // that the future would otherwise hang forever.
        let stub = unsafe {
            IpcChannel::from_raw_fds(d_read.into_raw_fd(), c_write.into_raw_fd())
        };

        let client = AccessRbacClient::new(client_read, client_write).unwrap();
        let dispatcher = Arc::clone(&client);
        tokio::spawn(async move {
            let _ = dispatcher.process_incoming().await;
        });

        // First call: stub will read the request but never respond. The
        // caller wraps it in a 200ms timeout and must observe Elapsed
        // (not a hang).
        let client1 = Arc::clone(&client);
        let timed = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            client1.check_access_by_uuid("u", "asset-silent", "ssh"),
        )
        .await;
        assert!(
            timed.is_err(),
            "external timeout MUST fire (Elapsed) when vauban-access is silent \
             -- if this assert ever flips, the production main loop is at risk \
             of being wedged again"
        );

        // Now drain the silent request so the stub can answer the next one,
        // proving the client survived the cancellation and still serves
        // subsequent callers (no internal poisoning).
        let stub_join = tokio::task::spawn_blocking(move || {
            // First request: read & discard (already sent before the timeout).
            let r1 = stub.recv().expect("stub recv 1 (silent)");
            let _ = match r1 {
                Message::AccessRequest { request_id, .. } => request_id,
                _ => panic!(),
            };
            // Second request: reply allowed=true.
            let r2 = stub.recv().expect("stub recv 2");
            let id2 = match r2 {
                Message::AccessRequest { request_id, .. } => request_id,
                _ => panic!(),
            };
            stub.send(&Message::AccessResponse {
                request_id: id2,
                response: AccessResp::AccessChecked(AccessCheckResult {
                    allowed: true,
                    require_mfa: false,
                    require_approval: false,
                    max_session_duration: None,
                }),
            })
            .unwrap();
        });

        let allowed = client
            .check_access_by_uuid("u", "asset-ok", "ssh")
            .await
            .expect("client must remain healthy after a cancelled call");
        assert!(allowed, "subsequent call must succeed normally");
        stub_join.await.unwrap();
    }

    #[test]
    fn test_rbac_result_construction() {
        // Sanity: RbacResult / AccessCheckResult constructors haven't drifted.
        let r = RbacResult {
            allowed: false,
            reason: Some("policy".to_string()),
        };
        assert!(!r.allowed);
        let a = AccessCheckResult {
            allowed: true,
            require_mfa: false,
            require_approval: false,
            max_session_duration: None,
        };
        assert!(a.allowed);
    }
}
