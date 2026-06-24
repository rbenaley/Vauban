//! IPC client for communication with vauban-proxy-ssh.
//!
//! Provides async methods to open SSH sessions, send terminal data,
//! and receive output from SSH sessions.

use crate::error::{AppError, AppResult};
use shared::ipc::IpcChannel;
use shared::messages::Message;
use std::collections::HashMap;
use std::io;
use std::os::unix::io::RawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::sync::{Mutex, mpsc, oneshot};
use tracing::{debug, error, info, warn};

/// Request to open an SSH session.
///
/// SECURITY (#4 - zero clear-text credentials on the web->proxy IPC):
/// the credential fields are NOT the secrets themselves but the **vault
/// ciphertexts** (`"v1:BASE64..."`) read verbatim from
/// `assets.connection_config`. vauban-web never decrypts; the proxy
/// materialises the plaintext via its decrypt-only `VaultDecryptClient`
/// just before building the russh credential. A ciphertext is useless
/// without the vault master key, so these are plain `String` and may be
/// shown in Debug -- hence the derive (no manual redaction needed).
#[derive(Clone, Debug)]
pub struct SshSessionOpenRequest {
    /// Unique session ID (UUID).
    pub session_id: String,
    /// Vauban user ID.
    pub user_id: String,
    /// Asset UUID.
    pub asset_id: String,
    /// Target hostname or IP.
    pub asset_host: String,
    /// SSH port.
    pub asset_port: u16,
    /// SSH username.
    pub username: String,
    /// Terminal width.
    pub terminal_cols: u16,
    /// Terminal height.
    pub terminal_rows: u16,
    /// Authentication type: "password" or "ssh_key".
    pub auth_type: String,
    /// Vault ciphertext of the password (password auth). Not a secret.
    pub password_ciphertext: Option<String>,
    /// Vault ciphertext of the PEM private key (key auth). Not a secret.
    pub private_key_ciphertext: Option<String>,
    /// Vault ciphertext of the private-key passphrase. Not a secret.
    pub passphrase_ciphertext: Option<String>,
    /// Expected SSH host key in OpenSSH format (e.g. "ssh-ed25519 AAAA...").
    /// If set, the proxy verifies the server key matches before continuing.
    pub expected_host_key: Option<String>,
    /// Cryptographic session token (BLAKE3-keyed MAC) issued by
    /// vauban-access, verified by vauban-proxy-ssh BEFORE
    /// `AccessGuard::authorize`. The token binds
    /// `(user_uuid, asset_uuid, "ssh", session_id)` so a compromised
    /// vauban-web cannot piggy-back another user's session here.
    /// See `docs/technical/Vauban_AccessGuard_Architecture_EN(1.0).md` §3.
    pub session_token: Vec<u8>,
}

/// Identity binding required to crypto-gate the host-key fetch path.
///
/// When `vauban-web` is running with a supervisor (Capsicum sandboxed
/// mode), the supervisor's TCP broker only accepts connect requests
/// that carry a fresh session token issued by `vauban-access`.
/// [`ProxySshClient::fetch_host_key`] derives a synthetic
/// `session_id` per request and asks `access_client` to mint the
/// token bound to `(user_uuid, asset_uuid, "ssh", host, port,
/// Service::ProxySsh, session_id)` -- the same policy as a real
/// session-open. Without this, a compromised vauban-web could use
/// the host-key fetch endpoint to enumerate the internal network.
pub struct HostKeyFetchIdentity<'a> {
    pub access_client: &'a super::AccessIpcClient,
    pub user_uuid: &'a str,
    pub asset_uuid: &'a str,
    /// Whether the original web caller holds Casbin `assets:manage`.
    /// Sourced from the request-scoped `PermissionContext` in the
    /// caller (`verify_ssh_host_key`, `fetch_ssh_host_key`). When
    /// `true`, the host-key fetch path uses
    /// [`super::AccessIpcClient::issue_diagnostic_token`] which
    /// bypasses the access-rule re-check (admins typically have no
    /// explicit rule on every asset). When `false`, the legacy
    /// session-token verb is used so non-admin callers stay gated by
    /// their access rule. Pre-issue #34 every caller used the legacy
    /// verb, which silently denied the admin path and made the verify
    /// endpoint fall back to a green "Verified" fragment.
    pub caller_has_assets_manage: bool,
}

/// Response from opening an SSH session.
#[derive(Debug, Clone)]
pub struct SshSessionOpened {
    /// Request ID for correlation.
    pub request_id: u64,
    /// Session ID.
    pub session_id: String,
    /// Whether the session was opened successfully.
    pub success: bool,
    /// Error message if failed.
    pub error: Option<String>,
}

/// Sender type for pending host key fetch responses.
///
/// Carries `(success, host_key, fingerprint, error)`.
type HostKeyResponseSender =
    oneshot::Sender<(bool, Option<String>, Option<String>, Option<String>)>;

/// Sender type for pending push-public-key / test-key-auth responses.
///
/// Carries `(success, error)`.
type SimpleResultSender = oneshot::Sender<(bool, Option<String>)>;

/// Async client for communicating with vauban-proxy-ssh.
pub struct ProxySshClient {
    /// Underlying IPC channel.
    channel: IpcChannel,
    /// Async file descriptor for reading.
    read_async_fd: AsyncFd<RawFd>,
    /// Next request ID.
    next_request_id: AtomicU64,
    /// Pending requests waiting for responses.
    pending_requests: Mutex<HashMap<u64, oneshot::Sender<SshSessionOpened>>>,
    /// Per-session data senders: session_id -> Sender.
    /// Each WebSocket subscribes to its session's channel.
    session_data_senders: Mutex<HashMap<String, mpsc::Sender<Vec<u8>>>>,
    /// Per-session data receivers waiting to be claimed by WebSocket.
    /// Created during open_session, taken by subscribe_session.
    session_data_receivers: Mutex<HashMap<String, mpsc::Receiver<Vec<u8>>>>,
    /// Pending host key fetch requests waiting for responses.
    pending_host_key_requests: Mutex<HashMap<u64, HostKeyResponseSender>>,
    /// Pending push-public-key requests. Carries `(success, error)`.
    pending_push_requests: Mutex<HashMap<u64, SimpleResultSender>>,
    /// Pending test-key-auth requests. Carries `(success, error)`.
    pending_test_requests: Mutex<HashMap<u64, SimpleResultSender>>,
}

impl ProxySshClient {
    /// Create a new SSH proxy client.
    ///
    /// The file descriptors should be passed by the supervisor.
    pub fn new(read_fd: RawFd, write_fd: RawFd) -> io::Result<Arc<Self>> {
        // Create IPC channel
        let channel = unsafe { IpcChannel::from_raw_fds(read_fd, write_fd) };

        // Set read fd to non-blocking
        set_nonblocking(read_fd)?;

        let read_async_fd = AsyncFd::new(read_fd)?;

        Ok(Arc::new(Self {
            channel,
            read_async_fd,
            next_request_id: AtomicU64::new(1),
            pending_requests: Mutex::new(HashMap::new()),
            session_data_senders: Mutex::new(HashMap::new()),
            session_data_receivers: Mutex::new(HashMap::new()),
            pending_host_key_requests: Mutex::new(HashMap::new()),
            pending_push_requests: Mutex::new(HashMap::new()),
            pending_test_requests: Mutex::new(HashMap::new()),
        }))
    }

    /// Subscribe to SSH data for a specific session.
    ///
    /// Returns a receiver that will receive data from the SSH session.
    /// If the session was opened (via `open_session`), the receiver was pre-created
    /// and buffered data will be available. Otherwise, a new channel is created.
    /// Call `unsubscribe_session` when the WebSocket disconnects.
    pub async fn subscribe_session(&self, session_id: &str) -> mpsc::Receiver<Vec<u8>> {
        // First, try to take the pre-created receiver (from open_session)
        let existing_rx = self.session_data_receivers.lock().await.remove(session_id);

        if let Some(rx) = existing_rx {
            debug!(session_id = %session_id, "WebSocket claimed pre-created SSH data channel");
            return rx;
        }

        // Fallback: create a new channel (shouldn't happen in normal flow)
        let (tx, rx) = mpsc::channel(256);
        self.session_data_senders
            .lock()
            .await
            .insert(session_id.to_string(), tx);
        debug!(session_id = %session_id, "WebSocket subscribed to SSH session (new channel)");
        rx
    }

    /// Unsubscribe from SSH data for a session.
    ///
    /// Should be called when the WebSocket disconnects.
    pub async fn unsubscribe_session(&self, session_id: &str) {
        self.session_data_senders.lock().await.remove(session_id);
        debug!(session_id = %session_id, "WebSocket unsubscribed from SSH session");
    }

    /// Request to open a new SSH session.
    pub async fn open_session(
        &self,
        request: SshSessionOpenRequest,
    ) -> AppResult<SshSessionOpened> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::SeqCst);
        let session_id = request.session_id.clone();

        debug!(
            request_id = request_id,
            session_id = %session_id,
            host = %request.asset_host,
            "Opening SSH session"
        );

        // Pre-create the data channel BEFORE sending the request.
        // This ensures SSH output is buffered even if WebSocket isn't connected yet.
        let (data_tx, data_rx) = mpsc::channel(256);
        {
            let mut senders = self.session_data_senders.lock().await;
            senders.insert(session_id.clone(), data_tx);
        }
        {
            let mut receivers = self.session_data_receivers.lock().await;
            receivers.insert(session_id.clone(), data_rx);
        }

        // Create response channel
        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self.pending_requests.lock().await;
            pending.insert(request_id, tx);
        }

        // Send request -- ship vault CIPHERTEXTS verbatim (no decryption
        // in vauban-web; the proxy decrypts via its VaultDecryptClient).
        let msg = Message::SshSessionOpen {
            request_id,
            session_id,
            user_id: request.user_id,
            asset_id: request.asset_id,
            asset_host: request.asset_host,
            asset_port: request.asset_port,
            username: request.username,
            terminal_cols: request.terminal_cols,
            terminal_rows: request.terminal_rows,
            auth_type: request.auth_type,
            password_ciphertext: request.password_ciphertext,
            private_key_ciphertext: request.private_key_ciphertext,
            passphrase_ciphertext: request.passphrase_ciphertext,
            expected_host_key: request.expected_host_key,
            session_token: request.session_token,
        };

        self.channel
            .send(&msg)
            .map_err(|e| AppError::Ipc(format!("IPC send failed: {}", e)))?;

        // Wait for response with timeout
        match tokio::time::timeout(std::time::Duration::from_secs(30), rx).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(_)) => {
                // Channel was dropped (shouldn't happen)
                Err(AppError::Ipc("Response channel dropped".to_string()))
            }
            Err(_) => {
                // Timeout
                let mut pending = self.pending_requests.lock().await;
                pending.remove(&request_id);
                Err(AppError::Ipc("SSH session open timeout".to_string()))
            }
        }
    }

    /// Send terminal input data to a session.
    pub fn send_data(&self, session_id: &str, data: &[u8]) -> AppResult<()> {
        let msg = Message::SshData {
            session_id: session_id.to_string(),
            data: data.to_vec(),
        };

        self.channel
            .send(&msg)
            .map_err(|e| AppError::Ipc(format!("IPC send failed: {}", e)))
    }

    /// Send terminal resize event.
    pub fn resize(&self, session_id: &str, cols: u16, rows: u16) -> AppResult<()> {
        let msg = Message::SshResize {
            session_id: session_id.to_string(),
            cols,
            rows,
        };

        self.channel
            .send(&msg)
            .map_err(|e| AppError::Ipc(format!("IPC send failed: {}", e)))
    }

    /// Close an SSH session.
    pub fn close_session(&self, session_id: &str) -> AppResult<()> {
        let msg = Message::SshSessionClose {
            session_id: session_id.to_string(),
        };

        self.channel
            .send(&msg)
            .map_err(|e| AppError::Ipc(format!("IPC send failed: {}", e)))
    }

    /// Fetch the SSH host key from a remote server.
    ///
    /// Sends a `SshFetchHostKey` request to the proxy, which performs a minimal
    /// SSH handshake and returns the server's public key.
    ///
    /// When a `supervisor` is provided (sandboxed / Capsicum mode), the method
    /// first asks the supervisor to establish a TCP connection to `host:port`
    /// and pass the resulting FD to the SSH proxy via `SCM_RIGHTS`.  The
    /// session ID used for the TCP connect follows the convention
    /// `"fetch-hostkey-{request_id}"` so the proxy can match the pre-connected
    /// FD to the incoming `SshFetchHostKey` message.
    ///
    /// Returns `(host_key_openssh, sha256_fingerprint)` on success.
    pub async fn fetch_host_key(
        &self,
        host: &str,
        port: u16,
        supervisor: Option<&super::SupervisorClient>,
        identity: Option<HostKeyFetchIdentity<'_>>,
    ) -> AppResult<(String, String)> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::SeqCst);

        debug!(
            request_id = request_id,
            host = %host,
            port = port,
            "Fetching SSH host key"
        );

        // If running under supervisor (Capsicum sandbox), request TCP
        // connection brokering BEFORE sending the fetch request to the
        // proxy.  The supervisor performs DNS resolution + TCP connect
        // and passes the socket FD to the SSH proxy via SCM_RIGHTS.
        if let Some(sv) = supervisor {
            let identity = identity.ok_or_else(|| {
                AppError::Ipc(
                    "fetch_host_key: identity is required when supervisor is set \
                     (the TCP broker is crypto-gated; a session token must be minted)"
                        .to_string(),
                )
            })?;
            let fetch_session_id = format!("fetch-hostkey-{}", request_id);
            // SECURITY: the supervisor's TCP broker is crypto-gated:
            // every connect requires a fresh token minted by
            // vauban-access. The host-key fetch path is no exception
            // -- without this gate a compromised vauban-web could use
            // SshFetchHostKey to enumerate the internal network.
            //
            // Issue #34: route admin callers (`assets:manage`) to the
            // diagnostic-token verb so the access-rule re-check is
            // skipped (admins typically have no explicit rule per
            // asset, and the legacy session-token verb silently denied
            // them; the verify endpoint then fell back to a green
            // "Verified" fragment that hid the missing live check).
            // Non-admin callers stay on the legacy verb so they remain
            // gated by their access rule.
            let token_params = shared::session_token::SessionTokenParams {
                session_id: fetch_session_id.clone(),
                user_uuid: identity.user_uuid.to_string(),
                asset_uuid: identity.asset_uuid.to_string(),
                protocol: "ssh".to_string(),
                host: host.to_string(),
                port,
                target_service: shared::messages::Service::ProxySsh,
            };
            let session_token = if identity.caller_has_assets_manage {
                identity
                    .access_client
                    .issue_diagnostic_token(token_params, true)
                    .await?
            } else {
                identity
                    .access_client
                    .issue_session_token(token_params)
                    .await?
            };
            debug!(
                request_id = request_id,
                fetch_session_id = %fetch_session_id,
                "Requesting TCP connection from supervisor for host key fetch"
            );
            match sv
                .request_tcp_connect(
                    &fetch_session_id,
                    host,
                    port,
                    shared::messages::Service::ProxySsh,
                    session_token,
                )
                .await
            {
                Ok(result) if result.success => {
                    debug!(
                        request_id = request_id,
                        "Supervisor established TCP connection for host key fetch"
                    );
                }
                Ok(result) => {
                    let err = result
                        .error
                        .unwrap_or_else(|| "TCP connect failed".to_string());
                    warn!(
                        request_id = request_id,
                        error = %err,
                        "Supervisor TCP connect failed for host key fetch"
                    );
                    return Err(AppError::Ipc(format!(
                        "Supervisor TCP connect failed: {}",
                        err
                    )));
                }
                Err(e) => {
                    warn!(
                        request_id = request_id,
                        error = %e,
                        "Supervisor TCP connect request failed for host key fetch"
                    );
                    return Err(AppError::Ipc(format!(
                        "Supervisor TCP connect request failed: {}",
                        e
                    )));
                }
            }
        }

        // Create a oneshot channel for the response
        let (tx, rx) = oneshot::channel::<(bool, Option<String>, Option<String>, Option<String>)>();

        // Store the pending request
        {
            let mut pending = self.pending_host_key_requests.lock().await;
            pending.insert(request_id, tx);
        }

        // Send the fetch request
        let msg = Message::SshFetchHostKey {
            request_id,
            asset_host: host.to_string(),
            asset_port: port,
        };

        self.channel
            .send(&msg)
            .map_err(|e| AppError::Ipc(format!("IPC send failed: {}", e)))?;

        // Wait for response with timeout
        match tokio::time::timeout(std::time::Duration::from_secs(30), rx).await {
            Ok(Ok((true, Some(key), Some(fp), _))) => Ok((key, fp)),
            Ok(Ok((false, _, _, Some(err)))) => {
                Err(AppError::Ipc(format!("Host key fetch failed: {}", err)))
            }
            Ok(Ok(_)) => Err(AppError::Ipc(
                "Host key fetch returned unexpected response".to_string(),
            )),
            Ok(Err(_)) => Err(AppError::Ipc(
                "Host key response channel dropped".to_string(),
            )),
            Err(_) => {
                let mut pending = self.pending_host_key_requests.lock().await;
                pending.remove(&request_id);
                Err(AppError::Ipc("Host key fetch timeout".to_string()))
            }
        }
    }

    /// Broker a supervisor TCP connection for a one-shot SSH operation
    /// (host-key fetch, push public key, test key auth). When a
    /// `supervisor` is set (Capsicum mode) the supervisor performs DNS +
    /// `connect()` and passes the socket FD to the proxy via SCM_RIGHTS,
    /// keyed by `session_id`. The TCP broker is crypto-gated, so an
    /// `identity` is required to mint the per-request session token.
    /// Without a supervisor (in-process dev / tests) this is a no-op and
    /// the proxy connects directly.
    async fn broker_connect(
        &self,
        session_id: &str,
        host: &str,
        port: u16,
        supervisor: Option<&super::SupervisorClient>,
        identity: Option<HostKeyFetchIdentity<'_>>,
    ) -> AppResult<()> {
        let Some(sv) = supervisor else {
            return Ok(());
        };
        let identity = identity.ok_or_else(|| {
            AppError::Ipc(
                "broker_connect: identity is required when supervisor is set \
                 (the TCP broker is crypto-gated; a session token must be minted)"
                    .to_string(),
            )
        })?;
        let token_params = shared::session_token::SessionTokenParams {
            session_id: session_id.to_string(),
            user_uuid: identity.user_uuid.to_string(),
            asset_uuid: identity.asset_uuid.to_string(),
            protocol: "ssh".to_string(),
            host: host.to_string(),
            port,
            target_service: shared::messages::Service::ProxySsh,
        };
        // Push / test are admin (`assets:manage`) operations, so the
        // caller normally has no per-asset access rule -- mint a
        // diagnostic token that bypasses the rule re-check (same
        // reasoning as the host-key fetch path, issue #34).
        let session_token = if identity.caller_has_assets_manage {
            identity
                .access_client
                .issue_diagnostic_token(token_params, true)
                .await?
        } else {
            identity
                .access_client
                .issue_session_token(token_params)
                .await?
        };
        match sv
            .request_tcp_connect(
                session_id,
                host,
                port,
                shared::messages::Service::ProxySsh,
                session_token,
            )
            .await
        {
            Ok(result) if result.success => Ok(()),
            Ok(result) => Err(AppError::Ipc(format!(
                "Supervisor TCP connect failed: {}",
                result
                    .error
                    .unwrap_or_else(|| "TCP connect failed".to_string())
            ))),
            Err(e) => Err(AppError::Ipc(format!(
                "Supervisor TCP connect request failed: {}",
                e
            ))),
        }
    }

    /// Push an OpenSSH public key onto the target's
    /// `~/.ssh/authorized_keys` via a one-shot password-authenticated
    /// session. `password_ciphertext` is the vault ciphertext of the
    /// one-shot password typed in the modal (decrypted proxy-side).
    /// `expected_host_key` MUST be present (host-key pinning is
    /// mandatory: we authenticate with a password, so we refuse to talk
    /// to an unpinned / mismatched server). Idempotent server-side.
    #[allow(clippy::too_many_arguments)]
    pub async fn push_public_key(
        &self,
        host: &str,
        port: u16,
        username: &str,
        public_key: &str,
        password_ciphertext: &str,
        expected_host_key: Option<String>,
        supervisor: Option<&super::SupervisorClient>,
        identity: Option<HostKeyFetchIdentity<'_>>,
    ) -> AppResult<()> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::SeqCst);
        // Proxy reconstructs the same synthetic id from request_id.
        let session_id = format!("push-pubkey-{}", request_id);
        self.broker_connect(&session_id, host, port, supervisor, identity)
            .await?;

        let (tx, rx) = oneshot::channel();
        self.pending_push_requests
            .lock()
            .await
            .insert(request_id, tx);

        let msg = Message::SshPushPublicKey {
            request_id,
            asset_host: host.to_string(),
            asset_port: port,
            username: username.to_string(),
            public_key: public_key.to_string(),
            password_ciphertext: password_ciphertext.to_string(),
            expected_host_key,
        };
        self.channel
            .send(&msg)
            .map_err(|e| AppError::Ipc(format!("IPC send failed: {}", e)))?;

        match tokio::time::timeout(std::time::Duration::from_secs(30), rx).await {
            Ok(Ok((true, _))) => Ok(()),
            Ok(Ok((false, err))) => Err(AppError::Ipc(format!(
                "Push public key failed: {}",
                err.unwrap_or_else(|| "unknown error".to_string())
            ))),
            Ok(Err(_)) => Err(AppError::Ipc("Push response channel dropped".to_string())),
            Err(_) => {
                self.pending_push_requests.lock().await.remove(&request_id);
                Err(AppError::Ipc("Push public key timeout".to_string()))
            }
        }
    }

    /// Dry-run key-based authentication against the target (connect +
    /// `authenticate_publickey` + disconnect) to validate that an
    /// imported key pair actually logs in. The private key / passphrase
    /// travel as vault ciphertexts (decrypted proxy-side).
    /// `expected_host_key` MUST be present (host-key pinning mandatory).
    #[allow(clippy::too_many_arguments)]
    pub async fn test_key_auth(
        &self,
        host: &str,
        port: u16,
        username: &str,
        private_key_ciphertext: &str,
        passphrase_ciphertext: Option<String>,
        expected_host_key: Option<String>,
        supervisor: Option<&super::SupervisorClient>,
        identity: Option<HostKeyFetchIdentity<'_>>,
    ) -> AppResult<()> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::SeqCst);
        let session_id = format!("test-keyauth-{}", request_id);
        self.broker_connect(&session_id, host, port, supervisor, identity)
            .await?;

        let (tx, rx) = oneshot::channel();
        self.pending_test_requests
            .lock()
            .await
            .insert(request_id, tx);

        let msg = Message::SshTestKeyAuth {
            request_id,
            asset_host: host.to_string(),
            asset_port: port,
            username: username.to_string(),
            private_key_ciphertext: private_key_ciphertext.to_string(),
            passphrase_ciphertext,
            expected_host_key,
        };
        self.channel
            .send(&msg)
            .map_err(|e| AppError::Ipc(format!("IPC send failed: {}", e)))?;

        match tokio::time::timeout(std::time::Duration::from_secs(30), rx).await {
            Ok(Ok((true, _))) => Ok(()),
            Ok(Ok((false, err))) => Err(AppError::Ipc(format!(
                "Key-based authentication failed: {}",
                err.unwrap_or_else(|| "unknown error".to_string())
            ))),
            Ok(Err(_)) => Err(AppError::Ipc("Test response channel dropped".to_string())),
            Err(_) => {
                self.pending_test_requests.lock().await.remove(&request_id);
                Err(AppError::Ipc("Test key auth timeout".to_string()))
            }
        }
    }

    /// Process incoming messages from the proxy.
    ///
    /// This should be called in a loop from a dedicated task.
    pub async fn process_incoming(&self) -> AppResult<()> {
        loop {
            // Wait for the fd to be readable
            let mut guard = self
                .read_async_fd
                .ready(Interest::READABLE)
                .await
                .map_err(|e| AppError::Ipc(format!("AsyncFd ready failed: {}", e)))?;

            // Try to receive messages
            loop {
                match self.channel.try_recv() {
                    Ok(msg) => {
                        self.handle_message(msg).await;
                    }
                    Err(shared::ipc::IpcError::Io(ref e))
                        if e.kind() == io::ErrorKind::WouldBlock =>
                    {
                        // No more messages available
                        guard.clear_ready();
                        break;
                    }
                    Err(shared::ipc::IpcError::ConnectionClosed) => {
                        info!("SSH proxy IPC connection closed");
                        return Err(AppError::Ipc("IPC connection closed".to_string()));
                    }
                    Err(e) => {
                        error!(error = %e, "IPC receive error");
                        guard.clear_ready();
                        break;
                    }
                }
            }
        }
    }

    /// Handle an incoming message from the proxy.
    async fn handle_message(&self, msg: Message) {
        match msg {
            Message::SshSessionOpened {
                request_id,
                session_id,
                success,
                error,
            } => {
                debug!(
                    request_id = request_id,
                    session_id = %session_id,
                    success = success,
                    "SSH session opened response"
                );

                let response = SshSessionOpened {
                    request_id,
                    session_id,
                    success,
                    error,
                };

                // Find and notify the waiting request
                let mut pending = self.pending_requests.lock().await;
                if let Some(tx) = pending.remove(&request_id) {
                    let _ = tx.send(response);
                }
            }

            Message::SshHostKeyResult {
                request_id,
                success,
                host_key,
                key_fingerprint,
                error,
            } => {
                debug!(
                    request_id = request_id,
                    success = success,
                    "SSH host key result received"
                );

                let mut pending = self.pending_host_key_requests.lock().await;
                if let Some(tx) = pending.remove(&request_id) {
                    let _ = tx.send((success, host_key, key_fingerprint, error));
                }
            }

            Message::SshPushPublicKeyResult {
                request_id,
                success,
                error,
            } => {
                debug!(request_id, success, "SSH push public key result received");
                if let Some(tx) = self.pending_push_requests.lock().await.remove(&request_id) {
                    let _ = tx.send((success, error));
                }
            }

            Message::SshTestKeyAuthResult {
                request_id,
                success,
                error,
            } => {
                debug!(request_id, success, "SSH test key auth result received");
                if let Some(tx) = self.pending_test_requests.lock().await.remove(&request_id) {
                    let _ = tx.send((success, error));
                }
            }

            Message::SshData { session_id, data } => {
                // Forward data to the session's subscribed WebSocket
                let senders = self.session_data_senders.lock().await;
                if let Some(tx) = senders.get(&session_id) {
                    if tx.send(data).await.is_err() {
                        warn!(session_id = %session_id, "Failed to forward SSH data, WebSocket dropped");
                    }
                } else {
                    debug!(session_id = %session_id, "SSH data received but no WebSocket subscribed");
                }
            }

            _ => {
                debug!(?msg, "Ignoring unexpected message from proxy");
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::io::AsRawFd;

    /// Create a test SSH session open request with default auth fields.
    fn make_test_request(session_id: &str, host: &str, port: u16) -> SshSessionOpenRequest {
        SshSessionOpenRequest {
            session_id: session_id.to_string(),
            user_id: "user".to_string(),
            asset_id: "asset".to_string(),
            asset_host: host.to_string(),
            asset_port: port,
            username: "admin".to_string(),
            terminal_cols: 80,
            terminal_rows: 24,
            auth_type: "password".to_string(),
            password_ciphertext: Some("v1:test-password-ct".to_string()),
            private_key_ciphertext: None,
            passphrase_ciphertext: None,
            expected_host_key: None,
            session_token: Vec::new(),
        }
    }

    // ==================== SshSessionOpenRequest Tests ====================

    #[test]
    fn test_ssh_session_open_request() {
        let request = make_test_request("sess-123", "192.168.1.100", 22);
        assert_eq!(request.session_id, "sess-123");
        assert_eq!(request.asset_port, 22);
        assert_eq!(request.auth_type, "password");
    }

    #[test]
    fn test_ssh_session_open_request_clone() {
        let mut request = make_test_request("clone-test", "10.0.0.1", 2222);
        request.username = "root".to_string();
        request.terminal_cols = 120;
        request.terminal_rows = 40;

        let cloned = request.clone();

        assert_eq!(request.session_id, cloned.session_id);
        assert_eq!(request.asset_host, cloned.asset_host);
        assert_eq!(request.asset_port, cloned.asset_port);
        assert_eq!(request.terminal_cols, cloned.terminal_cols);
    }

    #[test]
    fn test_ssh_session_open_request_carries_ciphertexts_not_secrets() {
        // #4: the request now holds vault ciphertexts, never clear-text
        // secrets. There is therefore nothing to redact -- and crucially
        // no plaintext credential can ever be constructed here.
        let mut request = make_test_request("ct-sess", "host.local", 22);
        request.password_ciphertext = Some("v1:CIPHER-PWD".to_string());
        request.private_key_ciphertext = Some("v1:CIPHER-KEY".to_string());
        request.passphrase_ciphertext = Some("v1:CIPHER-PASS".to_string());

        let debug_str = format!("{:?}", request);
        assert!(debug_str.contains("SshSessionOpenRequest"));
        assert!(debug_str.contains("ct-sess"));
        // Ciphertexts are not secrets: they may appear verbatim.
        assert!(debug_str.contains("v1:CIPHER-PWD"));
    }

    #[test]
    fn test_ssh_session_open_request_ipv6_host() {
        let request = make_test_request("ipv6-sess", "2001:db8::1", 22);
        assert_eq!(request.asset_host, "2001:db8::1");
    }

    #[test]
    fn test_ssh_session_open_request_alternate_port() {
        let request = make_test_request("alt-port", "server.local", 8022);
        assert_eq!(request.asset_port, 8022);
    }

    #[test]
    fn test_ssh_session_open_request_large_terminal() {
        let mut request = make_test_request("large", "host", 22);
        request.terminal_cols = 300;
        request.terminal_rows = 100;

        assert_eq!(request.terminal_cols, 300);
        assert_eq!(request.terminal_rows, 100);
    }

    #[test]
    fn test_ssh_session_open_request_ssh_key_auth() {
        let request = SshSessionOpenRequest {
            session_id: "key-auth".to_string(),
            user_id: "user".to_string(),
            asset_id: "asset".to_string(),
            asset_host: "host".to_string(),
            asset_port: 22,
            username: "admin".to_string(),
            terminal_cols: 80,
            terminal_rows: 24,
            auth_type: "ssh_key".to_string(),
            password_ciphertext: None,
            private_key_ciphertext: Some("v1:CIPHER-KEY".to_string()),
            passphrase_ciphertext: Some("v1:CIPHER-PASS".to_string()),
            expected_host_key: None,
            session_token: Vec::new(),
        };

        assert_eq!(request.auth_type, "ssh_key");
        assert!(request.private_key_ciphertext.is_some());
        assert!(request.passphrase_ciphertext.is_some());
    }

    // ==================== SshSessionOpened Tests ====================

    #[test]
    fn test_ssh_session_opened_success() {
        let response = SshSessionOpened {
            request_id: 1,
            session_id: "sess-123".to_string(),
            success: true,
            error: None,
        };
        assert!(response.success);
        assert!(response.error.is_none());
    }

    #[test]
    fn test_ssh_session_opened_failure() {
        let response = SshSessionOpened {
            request_id: 1,
            session_id: "sess-123".to_string(),
            success: false,
            error: Some("Connection refused".to_string()),
        };
        assert!(!response.success);
        assert_eq!(response.error.unwrap(), "Connection refused");
    }

    #[test]
    fn test_ssh_session_opened_clone() {
        let response = SshSessionOpened {
            request_id: 42,
            session_id: "clone-sess".to_string(),
            success: true,
            error: None,
        };

        let cloned = response.clone();

        assert_eq!(response.request_id, cloned.request_id);
        assert_eq!(response.session_id, cloned.session_id);
        assert_eq!(response.success, cloned.success);
    }

    #[test]
    fn test_ssh_session_opened_debug() {
        let response = SshSessionOpened {
            request_id: 999,
            session_id: "debug-resp".to_string(),
            success: false,
            error: Some("Auth failed".to_string()),
        };

        let debug_str = format!("{:?}", response);

        assert!(debug_str.contains("SshSessionOpened"));
        assert!(debug_str.contains("999"));
        assert!(debug_str.contains("Auth failed"));
    }

    #[test]
    fn test_ssh_session_opened_various_errors() {
        let errors = [
            "Connection refused",
            "Authentication failed",
            "Timeout",
            "Host key verification failed",
            "Permission denied",
        ];

        for error_msg in errors {
            let response = SshSessionOpened {
                request_id: 1,
                session_id: "test".to_string(),
                success: false,
                error: Some(error_msg.to_string()),
            };

            assert!(!response.success);
            assert_eq!(response.error.as_deref(), Some(error_msg));
        }
    }

    // ==================== set_nonblocking Tests ====================

    #[test]
    fn test_set_nonblocking() {
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
    fn test_set_nonblocking_preserves_flags() {
        // Create a pipe for testing
        let (read_fd, _write_fd) = nix::unistd::pipe().unwrap();

        use libc::{F_GETFL, O_NONBLOCK, fcntl};

        // Get original flags
        let original_flags = unsafe { fcntl(read_fd.as_raw_fd(), F_GETFL) };

        // Set non-blocking
        set_nonblocking(read_fd.as_raw_fd()).unwrap();

        // Check flags
        let new_flags = unsafe { fcntl(read_fd.as_raw_fd(), F_GETFL) };
        assert_eq!(new_flags, original_flags | O_NONBLOCK);
    }

    #[test]
    fn test_set_nonblocking_idempotent() {
        // Create a pipe for testing
        let (read_fd, _write_fd) = nix::unistd::pipe().unwrap();

        // Set non-blocking twice
        set_nonblocking(read_fd.as_raw_fd()).unwrap();
        set_nonblocking(read_fd.as_raw_fd()).unwrap();

        // Verify it's still non-blocking
        use libc::{F_GETFL, O_NONBLOCK, fcntl};
        let flags = unsafe { fcntl(read_fd.as_raw_fd(), F_GETFL) };
        assert!(flags & O_NONBLOCK != 0);
    }

    // ==================== AtomicU64 Request ID Tests ====================

    #[test]
    fn test_request_id_counter_increments() {
        let counter = AtomicU64::new(1);

        let id1 = counter.fetch_add(1, Ordering::SeqCst);
        let id2 = counter.fetch_add(1, Ordering::SeqCst);
        let id3 = counter.fetch_add(1, Ordering::SeqCst);

        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
        assert_eq!(id3, 3);
    }

    #[test]
    fn test_request_id_counter_wraps() {
        let counter = AtomicU64::new(u64::MAX);

        let id1 = counter.fetch_add(1, Ordering::SeqCst);
        let id2 = counter.fetch_add(1, Ordering::SeqCst);

        assert_eq!(id1, u64::MAX);
        assert_eq!(id2, 0); // Wrapped around
    }
}
