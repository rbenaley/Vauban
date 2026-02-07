//! SSH session management using russh.

use crate::error::{SessionError, SessionResult};
use russh::client::{self, Handle};
use russh::{Channel, ChannelId, ChannelMsg, Disconnect, Preferred};
use russh::keys::decode_secret_key;
use secrecy::{ExposeSecret, SecretString};
use std::borrow::Cow;
use std::os::unix::io::{FromRawFd, IntoRawFd, OwnedFd};
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpStream;
use tracing::{debug, error, info, warn};

/// Supported key exchange algorithms, ordered from most secure to legacy.
///
/// This list is shared by `SshSession::connect` and `fetch_host_key` to
/// guarantee identical algorithm negotiation for both session establishment
/// and host-key-only probes.  Legacy algorithms (DH group exchange, DH G1)
/// are included for compatibility with older SSH servers.
const PREFERRED_KEX: &[russh::kex::Name] = &[
    russh::kex::CURVE25519,
    russh::kex::CURVE25519_PRE_RFC_8731,
    russh::kex::ECDH_SHA2_NISTP256,
    russh::kex::ECDH_SHA2_NISTP384,
    russh::kex::ECDH_SHA2_NISTP521,
    russh::kex::DH_G16_SHA512,
    russh::kex::DH_G14_SHA256,
    russh::kex::DH_GEX_SHA256, // diffie-hellman-group-exchange-sha256
    russh::kex::DH_GEX_SHA1,   // diffie-hellman-group-exchange-sha1
    russh::kex::DH_G14_SHA1,
    russh::kex::DH_G1_SHA1,
];

/// Supported cipher algorithms, ordered from most secure to legacy.
///
/// See [`PREFERRED_KEX`] -- same rationale.  CBC ciphers are included for
/// compatibility with servers that do not advertise CTR/GCM modes.
const PREFERRED_CIPHER: &[russh::cipher::Name] = &[
    russh::cipher::CHACHA20_POLY1305,
    russh::cipher::AES_256_GCM,
    russh::cipher::AES_128_GCM,
    russh::cipher::AES_256_CTR,
    russh::cipher::AES_192_CTR,
    russh::cipher::AES_128_CTR,
    russh::cipher::AES_256_CBC,
    russh::cipher::AES_192_CBC,
    russh::cipher::AES_128_CBC,
];

/// Build an `Arc<client::Config>` with the project-wide algorithm preferences.
///
/// Called by `SshSession::connect` and `fetch_host_key` so that every SSH
/// handshake (session or host-key probe) uses the exact same configuration.
fn make_ssh_config() -> Arc<client::Config> {
    Arc::new(client::Config {
        preferred: Preferred {
            kex: Cow::Borrowed(PREFERRED_KEX),
            cipher: Cow::Borrowed(PREFERRED_CIPHER),
            ..Preferred::default()
        },
        ..client::Config::default()
    })
}

/// SSH credential types supported by the proxy.
///
/// Wraps credentials in `SecretString` (H-10) to ensure:
/// - Memory is zeroized when the credential is dropped
/// - `.expose_secret()` is required for access (compile-time enforcement)
/// - `Debug` output never contains the actual credential values
#[derive(Clone)]
pub enum SshCredential {
    /// Password-based authentication.
    Password(SecretString),
    /// Private key authentication with optional passphrase.
    PrivateKey {
        /// PEM-encoded private key.
        key_pem: SecretString,
        /// Optional passphrase for encrypted keys.
        passphrase: Option<SecretString>,
    },
}

impl std::fmt::Debug for SshCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SshCredential::Password(_) => {
                f.debug_tuple("Password").field(&"[REDACTED]").finish()
            }
            SshCredential::PrivateKey { .. } => {
                f.debug_struct("PrivateKey")
                    .field("key_pem", &"[REDACTED]")
                    .field("passphrase", &"[REDACTED]")
                    .finish()
            }
        }
    }
}

/// Configuration for creating a new SSH session.
#[derive(Debug)]
pub struct SessionConfig {
    /// Unique session identifier (UUID).
    pub session_id: String,
    /// Vauban user ID who initiated the session.
    pub user_id: String,
    /// Asset ID from database.
    pub asset_id: String,
    /// Target hostname or IP.
    pub host: String,
    /// Target SSH port.
    pub port: u16,
    /// SSH username on target.
    pub username: String,
    /// Terminal width in columns.
    pub terminal_cols: u16,
    /// Terminal height in rows.
    pub terminal_rows: u16,
    /// SSH credential for authentication.
    pub credential: SshCredential,
    /// Pre-established TCP connection from supervisor (for sandboxed operation).
    /// When running in Capsicum sandbox, the proxy cannot open network connections.
    /// The supervisor establishes the TCP connection and passes the FD via SCM_RIGHTS.
    pub preconnected_fd: Option<OwnedFd>,
    /// Expected SSH host key in OpenSSH format (e.g. "ssh-ed25519 AAAA...").
    /// If set, the server key MUST match during handshake or the connection is refused.
    /// If None, host key verification is skipped (logged as warning).
    pub expected_host_key: Option<String>,
}

/// Active SSH session with bidirectional channel.
pub struct SshSession {
    /// Unique session identifier.
    pub session_id: String,
    /// Vauban user ID (for session tracking and audit).
    #[allow(dead_code)]
    pub user_id: String,
    /// Asset ID (for session tracking and audit).
    #[allow(dead_code)]
    pub asset_id: String,
    /// SSH client handle.
    handle: Handle<SshHandler>,
    /// Channel ID for the PTY session (for channel operations).
    #[allow(dead_code)]
    channel_id: ChannelId,
    /// Channel for sending data to SSH.
    channel: Channel<client::Msg>,
    /// When the session was created (for metrics and session info).
    #[allow(dead_code)]
    pub created_at: Instant,
}

impl SshSession {
    /// Connect to an SSH server and open a PTY session.
    pub async fn connect(config: SessionConfig) -> SessionResult<Self> {
        info!(
            session_id = %config.session_id,
            host = %config.host,
            port = config.port,
            username = %config.username,
            "Connecting to SSH server"
        );

        let ssh_config = make_ssh_config();

        // Create handler for SSH events (with host key verification)
        let handler = SshHandler::new(
            config.session_id.clone(),
            config.expected_host_key.clone(),
        );

        // Connect to the SSH server - use pre-established FD if provided (sandboxed mode)
        // or open a new connection (non-sandboxed mode, e.g., development on macOS)
        let mut session = if let Some(fd) = config.preconnected_fd {
            // Sandboxed mode: use pre-established connection from supervisor
            debug!(session_id = %config.session_id, "Using pre-established connection from supervisor");
            
            // Convert OwnedFd to tokio TcpStream
            // SAFETY: The FD comes from the supervisor via SCM_RIGHTS and is a valid TCP socket
            let std_stream = unsafe { std::net::TcpStream::from_raw_fd(fd.into_raw_fd()) };
            std_stream.set_nonblocking(true)
                .map_err(|e| SessionError::ConnectionFailed(format!("Failed to set non-blocking: {}", e)))?;
            let stream = TcpStream::from_std(std_stream)
                .map_err(|e| SessionError::ConnectionFailed(format!("Failed to create tokio stream: {}", e)))?;
            
            client::connect_stream(ssh_config, stream, handler)
                .await
                .map_err(|e| SessionError::ConnectionFailed(e.to_string()))?
        } else {
            // Non-sandboxed mode: open connection directly (development/macOS)
            let addr = format!("{}:{}", config.host, config.port);
            client::connect(ssh_config, addr, handler)
                .await
                .map_err(|e| SessionError::ConnectionFailed(e.to_string()))?
        };

        debug!(session_id = %config.session_id, "TCP connection established");

        // Authenticate
        use russh::client::AuthResult;
        
        let auth_result = match &config.credential {
            SshCredential::Password(password) => {
                debug!(session_id = %config.session_id, "Authenticating with password");
                session
                    .authenticate_password(&config.username, password.expose_secret())
                    .await
                    .map_err(|e| SessionError::AuthenticationFailed(e.to_string()))?
            }
            SshCredential::PrivateKey { key_pem, passphrase } => {
                debug!(session_id = %config.session_id, "Authenticating with private key");
                let key = decode_secret_key(
                    key_pem.expose_secret(),
                    passphrase.as_ref().map(|p| p.expose_secret()),
                )
                .map_err(|e| SessionError::InvalidKey(e.to_string()))?;
                // russh 0.57+ requires PrivateKeyWithHashAlg for public key auth
                let key_with_alg = russh::keys::PrivateKeyWithHashAlg::new(
                    Arc::new(key),
                    None, // Use default hash algorithm
                );
                session
                    .authenticate_publickey(&config.username, key_with_alg)
                    .await
                    .map_err(|e| SessionError::AuthenticationFailed(e.to_string()))?
            }
        };

        match auth_result {
            AuthResult::Success => {}
            AuthResult::Failure { remaining_methods, partial_success: _ } => {
                return Err(SessionError::AuthenticationFailed(
                    format!("Authentication rejected. Remaining methods: {:?}", remaining_methods),
                ));
            }
        }

        debug!(session_id = %config.session_id, "Authentication successful");

        // Open a session channel
        let channel = session
            .channel_open_session()
            .await
            .map_err(|e| SessionError::ChannelOpenFailed(e.to_string()))?;

        let channel_id = channel.id();
        debug!(session_id = %config.session_id, channel_id = ?channel_id, "Channel opened");

        // Request PTY
        channel
            .request_pty(
                false,
                "xterm-256color",
                config.terminal_cols as u32,
                config.terminal_rows as u32,
                0, // pixel width
                0, // pixel height
                &[],
            )
            .await
            .map_err(|e| SessionError::PtyRequestFailed(e.to_string()))?;

        debug!(
            session_id = %config.session_id,
            cols = config.terminal_cols,
            rows = config.terminal_rows,
            "PTY allocated"
        );

        // Request shell
        channel
            .request_shell(false)
            .await
            .map_err(|e| SessionError::ShellStartFailed(e.to_string()))?;

        debug!(session_id = %config.session_id, "Shell started, session ready");

        Ok(Self {
            session_id: config.session_id,
            user_id: config.user_id,
            asset_id: config.asset_id,
            handle: session,
            channel_id,
            channel,
            created_at: Instant::now(),
        })
    }

    /// Send data to the SSH channel (terminal input from user).
    pub async fn write(&self, data: &[u8]) -> SessionResult<()> {
        self.channel
            .data(data)
            .await
            .map_err(|e| SessionError::IoError(std::io::Error::other(e.to_string())))?;
        Ok(())
    }

    /// Resize the PTY.
    pub async fn resize(&self, cols: u16, rows: u16) -> SessionResult<()> {
        debug!(
            session_id = %self.session_id,
            cols = cols,
            rows = rows,
            "Resizing PTY"
        );
        self.channel
            .window_change(cols as u32, rows as u32, 0, 0)
            .await
            .map_err(|e| SessionError::IoError(std::io::Error::other(e.to_string())))?;
        Ok(())
    }

    /// Wait for the next message from the SSH channel.
    /// Returns None if the channel is closed.
    pub async fn read(&mut self) -> Option<Vec<u8>> {
        loop {
            match self.channel.wait().await {
                Some(ChannelMsg::Data { data }) => {
                    return Some(data.to_vec());
                }
                Some(ChannelMsg::ExtendedData { data, ext }) => {
                    // Extended data (stderr) - treat as regular output
                    debug!(session_id = %self.session_id, ext = ext, "Received extended data");
                    return Some(data.to_vec());
                }
                Some(ChannelMsg::Eof) => {
                    debug!(session_id = %self.session_id, "Channel EOF received");
                    return None;
                }
                Some(ChannelMsg::Close) => {
                    debug!(session_id = %self.session_id, "Channel closed");
                    return None;
                }
                Some(ChannelMsg::ExitStatus { exit_status }) => {
                    info!(
                        session_id = %self.session_id,
                        exit_status = exit_status,
                        "Process exited"
                    );
                    // Continue reading until EOF/Close
                }
                Some(ChannelMsg::ExitSignal { signal_name, .. }) => {
                    info!(
                        session_id = %self.session_id,
                        signal = ?signal_name,
                        "Process killed by signal"
                    );
                }
                Some(msg) => {
                    debug!(session_id = %self.session_id, ?msg, "Other channel message");
                }
                None => {
                    debug!(session_id = %self.session_id, "Channel stream ended");
                    return None;
                }
            }
        }
    }

    /// Close the session gracefully.
    pub async fn close(self) -> SessionResult<()> {
        info!(session_id = %self.session_id, "Closing SSH session");

        // Send EOF to channel
        if let Err(e) = self.channel.eof().await {
            warn!(session_id = %self.session_id, error = %e, "Failed to send EOF");
        }

        // Disconnect the session
        if let Err(e) = self
            .handle
            .disconnect(Disconnect::ByApplication, "Session closed by user", "en")
            .await
        {
            warn!(session_id = %self.session_id, error = %e, "Failed to disconnect");
        }

        Ok(())
    }

    /// Get session uptime in seconds.
    #[allow(dead_code)] // Will be used for session metrics
    pub fn uptime_secs(&self) -> u64 {
        self.created_at.elapsed().as_secs()
    }
}

/// Handler for fetching host keys using shared state (Arc<Mutex<>>).
/// This is necessary because russh consumes the handler during `connect`.
struct HostKeyFetchHandler {
    captured: Arc<tokio::sync::Mutex<(Option<String>, Option<String>)>>,
}

impl client::Handler for HostKeyFetchHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        let key_str = server_public_key
            .to_openssh()
            .unwrap_or_else(|_| format!("{:?}", server_public_key.algorithm()));
        let fingerprint = server_public_key
            .fingerprint(russh::keys::HashAlg::Sha256)
            .to_string();

        debug!(
            key_type = ?server_public_key.algorithm(),
            fingerprint = %fingerprint,
            "Host key fetched from server"
        );

        let mut guard = self.captured.lock().await;
        *guard = (Some(key_str), Some(fingerprint));
        Ok(true)
    }
}

/// Fetch the SSH host key from a remote server by performing a minimal
/// SSH handshake (key exchange only, no authentication).
///
/// Returns `(host_key_openssh, sha256_fingerprint)` on success.
pub async fn fetch_host_key(
    host: &str,
    port: u16,
    preconnected_fd: Option<OwnedFd>,
) -> SessionResult<(String, String)> {
    info!(host = %host, port = port, "Fetching SSH host key");

    let captured = Arc::new(tokio::sync::Mutex::new((None, None)));

    // Reuse the project-wide SSH config builder (same algorithms as SshSession::connect)

    // Helper: direct TCP connect (used as primary path or fallback).
    let direct_connect =
        |cap: Arc<tokio::sync::Mutex<(Option<String>, Option<String>)>>,
         h: &str,
         p: u16| {
            let host_owned = h.to_string();
            async move {
                let handler = HostKeyFetchHandler {
                    captured: cap,
                };
                let addr = format!("{}:{}", host_owned, p);
                client::connect(make_ssh_config(), addr, handler).await
            }
        };

    // Attempt connection -- try pre-connected FD first, then fall back to direct.
    // The pre-connected FD is provided by the supervisor for sandboxed (Capsicum)
    // operation. If it fails (e.g. FD is stale due to race condition), we fall
    // back to direct TCP connect which works in non-sandboxed environments.
    let mut used_preconnected = false;
    let result = if let Some(fd) = preconnected_fd {
        used_preconnected = true;
        debug!(host = %host, port = port, "Using pre-connected FD for host key fetch");

        let handler = HostKeyFetchHandler {
            captured: Arc::clone(&captured),
        };

        // Try to use the pre-connected FD
        let preconn_result = async {
            let std_stream = unsafe { std::net::TcpStream::from_raw_fd(fd.into_raw_fd()) };
            std_stream
                .set_nonblocking(true)
                .map_err(|e| format!("set_nonblocking: {}", e))?;
            let stream = TcpStream::from_std(std_stream)
                .map_err(|e| format!("from_std: {}", e))?;
            client::connect_stream(make_ssh_config(), stream, handler)
                .await
                .map_err(|e| format!("connect_stream: {}", e))
        }
        .await;

        match preconn_result {
            Ok(session) => Ok(session),
            Err(e) => {
                warn!(
                    host = %host,
                    port = port,
                    error = %e,
                    "Pre-connected FD handshake failed, falling back to direct connect"
                );
                direct_connect(Arc::clone(&captured), host, port).await
            }
        }
    } else {
        debug!(host = %host, port = port, "Using direct connect for host key fetch");
        direct_connect(Arc::clone(&captured), host, port).await
    };

    // Disconnect gracefully (ignore errors - we have the key)
    match &result {
        Ok(session) => {
            let _ = session
                .disconnect(Disconnect::ByApplication, "Host key fetch complete", "en")
                .await;
        }
        Err(e) => {
            // Log the actual SSH error for diagnostics. Even if connect failed
            // *after* key exchange (e.g. no compatible auth), check_server_key
            // should have been called and `captured` will contain the key.
            warn!(
                host = %host,
                port = port,
                used_preconnected = used_preconnected,
                error = %e,
                "SSH handshake error during host key fetch (key may still have been captured)"
            );
        }
    }

    let guard = captured.lock().await;
    match &*guard {
        (Some(key), Some(fp)) => {
            info!(fingerprint = %fp, "SSH host key fetched successfully");
            Ok((key.clone(), fp.clone()))
        }
        _ => Err(SessionError::ConnectionFailed(
            format!(
                "Failed to retrieve host key during SSH handshake (pre-connected FD: {})",
                if used_preconnected { "yes" } else { "no" },
            ),
        )),
    }
}

/// Handler for SSH client events.
struct SshHandler {
    session_id: String,
    /// Expected host key for verification (OpenSSH format).
    expected_host_key: Option<String>,
}

impl SshHandler {
    fn new(session_id: String, expected_host_key: Option<String>) -> Self {
        Self {
            session_id,
            expected_host_key,
        }
    }
}

impl client::Handler for SshHandler {
    type Error = russh::Error;

    /// Verify the SSH server's host key against the expected key.
    ///
    /// Behavior:
    /// - If `expected_host_key` is set: compare and accept only if match
    /// - If `expected_host_key` is None: accept with a warning (insecure)
    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        let received_key = server_public_key
            .to_openssh()
            .unwrap_or_else(|_| format!("{:?}", server_public_key.algorithm()));

        match &self.expected_host_key {
            Some(expected) => {
                // Compare the key data (ignore trailing whitespace/comments)
                let received_trimmed = received_key.trim();
                let expected_trimmed = expected.trim();

                if received_trimmed == expected_trimmed {
                    info!(
                        session_id = %self.session_id,
                        key_type = ?server_public_key.algorithm(),
                        "SSH host key verified successfully"
                    );
                    Ok(true)
                } else {
                    // Compute fingerprints for readable error reporting
                    let received_fp = server_public_key
                        .fingerprint(russh::keys::HashAlg::Sha256);
                    error!(
                        session_id = %self.session_id,
                        received_fingerprint = %received_fp,
                        "SSH host key MISMATCH - possible MITM attack. \
                         Connection refused. Update the stored host key if \
                         the server key was intentionally changed."
                    );
                    Ok(false)
                }
            }
            None => {
                warn!(
                    session_id = %self.session_id,
                    key_type = ?server_public_key.algorithm(),
                    "No expected host key configured - accepting server key (INSECURE). \
                     Fetch the host key from the asset detail page to enable verification."
                );
                Ok(true)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== SshCredential Tests ====================

    #[test]
    fn test_ssh_credential_password() {
        let cred = SshCredential::Password(SecretString::from("secret123".to_string()));
        match &cred {
            SshCredential::Password(p) => assert_eq!(p.expose_secret(), "secret123"),
            _ => panic!("Expected password credential"),
        }
    }

    #[test]
    fn test_ssh_credential_private_key() {
        let cred = SshCredential::PrivateKey {
            key_pem: SecretString::from("-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----".to_string()),
            passphrase: Some(SecretString::from("secret".to_string())),
        };
        match &cred {
            SshCredential::PrivateKey { key_pem, passphrase } => {
                assert!(key_pem.expose_secret().contains("PRIVATE KEY"));
                assert_eq!(passphrase.as_ref().map(|p| p.expose_secret()), Some("secret"));
            }
            _ => panic!("Expected private key credential"),
        }
    }

    #[test]
    fn test_ssh_credential_private_key_no_passphrase() {
        let cred = SshCredential::PrivateKey {
            key_pem: SecretString::from("key-data".to_string()),
            passphrase: None,
        };
        match &cred {
            SshCredential::PrivateKey { passphrase, .. } => {
                assert!(passphrase.is_none());
            }
            _ => panic!("Expected private key credential"),
        }
    }

    #[test]
    fn test_ssh_credential_clone() {
        let cred = SshCredential::Password(SecretString::from("test".to_string()));
        let cloned = cred.clone();
        match (&cred, &cloned) {
            (SshCredential::Password(a), SshCredential::Password(b)) => {
                assert_eq!(a.expose_secret(), b.expose_secret());
            }
            _ => panic!("Clone should produce same variant"),
        }
    }

    #[test]
    fn test_ssh_credential_debug() {
        let cred = SshCredential::Password(SecretString::from("secret".to_string()));
        let debug = format!("{:?}", cred);
        assert!(debug.contains("Password"));
        // H-10: Debug must NOT contain actual secret
        assert!(!debug.contains("secret"), "H-10: credential debug must be redacted");
        assert!(debug.contains("REDACTED"), "H-10: credential debug must show [REDACTED]");
    }

    // ==================== SessionConfig Tests ====================

    #[test]
    fn test_session_config() {
        let config = SessionConfig {
            session_id: "sess-123".to_string(),
            user_id: "user-456".to_string(),
            asset_id: "asset-789".to_string(),
            host: "192.168.1.100".to_string(),
            port: 22,
            username: "admin".to_string(),
            terminal_cols: 80,
            terminal_rows: 24,
            credential: SshCredential::Password(SecretString::from("pass".to_string())),
            preconnected_fd: None,
            expected_host_key: None,
        };
        assert_eq!(config.session_id, "sess-123");
        assert_eq!(config.port, 22);
        assert_eq!(config.terminal_cols, 80);
    }

    #[test]
    fn test_session_config_debug() {
        let config = SessionConfig {
            session_id: "debug-sess".to_string(),
            user_id: "user".to_string(),
            asset_id: "asset".to_string(),
            host: "localhost".to_string(),
            port: 22,
            username: "test".to_string(),
            terminal_cols: 80,
            terminal_rows: 24,
            credential: SshCredential::Password(SecretString::from("pass".to_string())),
            preconnected_fd: None,
            expected_host_key: None,
        };
        let debug = format!("{:?}", config);
        assert!(debug.contains("SessionConfig"));
        assert!(debug.contains("debug-sess"));
    }

    #[test]
    fn test_session_config_different_ports() {
        for port in [22, 2222, 22222, 65535] {
            let config = SessionConfig {
                session_id: "sess".to_string(),
                user_id: "user".to_string(),
                asset_id: "asset".to_string(),
                host: "host".to_string(),
                port,
                username: "user".to_string(),
                terminal_cols: 80,
                terminal_rows: 24,
                credential: SshCredential::Password(SecretString::from("pass".to_string())),
                preconnected_fd: None,
                expected_host_key: None,
            };
            assert_eq!(config.port, port);
        }
    }

    #[test]
    fn test_session_config_terminal_dimensions() {
        let config = SessionConfig {
            session_id: "sess".to_string(),
            user_id: "user".to_string(),
            asset_id: "asset".to_string(),
            host: "host".to_string(),
            port: 22,
            username: "user".to_string(),
            terminal_cols: 200,
            terminal_rows: 50,
            credential: SshCredential::Password(SecretString::from("pass".to_string())),
            preconnected_fd: None,
            expected_host_key: None,
        };
        assert_eq!(config.terminal_cols, 200);
        assert_eq!(config.terminal_rows, 50);
    }

    #[test]
    fn test_session_config_with_expected_host_key() {
        let config = SessionConfig {
            session_id: "sess".to_string(),
            user_id: "user".to_string(),
            asset_id: "asset".to_string(),
            host: "host".to_string(),
            port: 22,
            username: "user".to_string(),
            terminal_cols: 80,
            terminal_rows: 24,
            credential: SshCredential::Password(SecretString::from("pass".to_string())),
            preconnected_fd: None,
            expected_host_key: Some("ssh-ed25519 AAAA...".to_string()),
        };
        assert_eq!(
            config.expected_host_key,
            Some("ssh-ed25519 AAAA...".to_string())
        );
    }

    // ==================== SshHandler Tests ====================

    #[test]
    fn test_ssh_handler_new() {
        let handler = SshHandler::new("test-session".to_string(), None);
        assert_eq!(handler.session_id, "test-session");
        assert!(handler.expected_host_key.is_none());
    }

    #[test]
    fn test_ssh_handler_with_expected_key() {
        let handler = SshHandler::new(
            "test-session".to_string(),
            Some("ssh-ed25519 AAAA...".to_string()),
        );
        assert_eq!(handler.session_id, "test-session");
        assert_eq!(
            handler.expected_host_key,
            Some("ssh-ed25519 AAAA...".to_string())
        );
    }

    // ==================== H-9 Regression: Host Key Verification ====================

    /// Structural test: verify that check_server_key contains host key
    /// verification logic (not just Ok(true)).
    #[test]
    fn test_check_server_key_has_verification_logic() {
        let source = include_str!("session.rs");

        // Must contain the comparison logic
        assert!(
            source.contains("expected_host_key"),
            "session.rs must reference expected_host_key for verification"
        );

        // Must NOT contain the old unconditional Ok(true) accepting all keys.
        // (We split the needle so this test itself does not produce a false match.)
        let old_todo = format!(
            "// {}: Verify against known_hosts database",
            "TODO"
        );
        assert!(
            // Count occurrences: the only match should be this test itself if any
            source.matches(&old_todo).count() == 0,
            "session.rs must not contain the old TODO placeholder for host key verification"
        );

        // Must contain MITM warning
        assert!(
            source.contains("MITM"),
            "session.rs must warn about MITM attacks on key mismatch"
        );
    }
}
