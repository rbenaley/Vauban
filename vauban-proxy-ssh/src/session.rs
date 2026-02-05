//! SSH session management using russh.

use crate::error::{SessionError, SessionResult};
use russh::client::{self, Handle};
use russh::{Channel, ChannelId, ChannelMsg, Disconnect, Preferred};
use russh::keys::decode_secret_key;
use std::borrow::Cow;
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, info, warn};

/// SSH credential types supported by the proxy.
#[derive(Debug, Clone)]
pub enum SshCredential {
    /// Password-based authentication.
    Password(String),
    /// Private key authentication with optional passphrase.
    /// Will be used when private key authentication is implemented.
    #[allow(dead_code)]
    PrivateKey {
        /// PEM-encoded private key.
        key_pem: String,
        /// Optional passphrase for encrypted keys.
        passphrase: Option<String>,
    },
}

/// Configuration for creating a new SSH session.
#[derive(Debug, Clone)]
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

        // Create SSH client configuration with broad algorithm support
        // This ensures compatibility with most SSH servers (including older ones)
        let ssh_config = client::Config {
            preferred: Preferred {
                // Key exchange algorithms (from most secure to legacy)
                kex: Cow::Borrowed(&[
                    russh::kex::CURVE25519,
                    russh::kex::CURVE25519_PRE_RFC_8731,
                    russh::kex::ECDH_SHA2_NISTP256,
                    russh::kex::ECDH_SHA2_NISTP384,
                    russh::kex::ECDH_SHA2_NISTP521,
                    russh::kex::DH_G16_SHA512,
                    russh::kex::DH_G14_SHA256,
                    russh::kex::DH_GEX_SHA256,  // diffie-hellman-group-exchange-sha256
                    russh::kex::DH_GEX_SHA1,    // diffie-hellman-group-exchange-sha1
                    russh::kex::DH_G14_SHA1,
                    russh::kex::DH_G1_SHA1,
                ]),
                // Ciphers (from most secure to legacy)
                cipher: Cow::Borrowed(&[
                    russh::cipher::CHACHA20_POLY1305,
                    russh::cipher::AES_256_GCM,
                    russh::cipher::AES_128_GCM,
                    russh::cipher::AES_256_CTR,
                    russh::cipher::AES_192_CTR,
                    russh::cipher::AES_128_CTR,
                    russh::cipher::AES_256_CBC,
                    russh::cipher::AES_192_CBC,
                    russh::cipher::AES_128_CBC,
                ]),
                ..Preferred::default()
            },
            ..client::Config::default()
        };
        let ssh_config = Arc::new(ssh_config);

        // Create handler for SSH events
        let handler = SshHandler::new(config.session_id.clone());

        // Connect to the SSH server
        let addr = format!("{}:{}", config.host, config.port);
        let mut session = client::connect(ssh_config, addr.clone(), handler)
            .await
            .map_err(|e| SessionError::ConnectionFailed(e.to_string()))?;

        info!(session_id = %config.session_id, "TCP connection established");

        // Authenticate
        use russh::client::AuthResult;
        
        let auth_result = match &config.credential {
            SshCredential::Password(password) => {
                debug!(session_id = %config.session_id, "Authenticating with password");
                session
                    .authenticate_password(&config.username, password)
                    .await
                    .map_err(|e| SessionError::AuthenticationFailed(e.to_string()))?
            }
            SshCredential::PrivateKey { key_pem, passphrase } => {
                debug!(session_id = %config.session_id, "Authenticating with private key");
                let key = decode_secret_key(key_pem, passphrase.as_deref())
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

        info!(session_id = %config.session_id, "Authentication successful");

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

        info!(session_id = %config.session_id, "Shell started, session ready");

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

/// Handler for SSH client events.
struct SshHandler {
    session_id: String,
}

impl SshHandler {
    fn new(session_id: String) -> Self {
        Self { session_id }
    }
}

impl client::Handler for SshHandler {
    type Error = russh::Error;

    /// Called when server sends its public key. For now, accept all keys.
    /// TODO: Implement proper host key verification using known_hosts.
    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        debug!(
            session_id = %self.session_id,
            key_type = ?server_public_key.algorithm(),
            "Server key received (accepting all keys for now)"
        );
        // TODO: Verify against known_hosts database
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== SshCredential Tests ====================

    #[test]
    fn test_ssh_credential_password() {
        let cred = SshCredential::Password("secret123".to_string());
        match cred {
            SshCredential::Password(p) => assert_eq!(p, "secret123"),
            _ => panic!("Expected password credential"),
        }
    }

    #[test]
    fn test_ssh_credential_private_key() {
        let cred = SshCredential::PrivateKey {
            key_pem: "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----".to_string(),
            passphrase: Some("secret".to_string()),
        };
        match cred {
            SshCredential::PrivateKey { key_pem, passphrase } => {
                assert!(key_pem.contains("PRIVATE KEY"));
                assert_eq!(passphrase, Some("secret".to_string()));
            }
            _ => panic!("Expected private key credential"),
        }
    }

    #[test]
    fn test_ssh_credential_private_key_no_passphrase() {
        let cred = SshCredential::PrivateKey {
            key_pem: "key-data".to_string(),
            passphrase: None,
        };
        match cred {
            SshCredential::PrivateKey { passphrase, .. } => {
                assert!(passphrase.is_none());
            }
            _ => panic!("Expected private key credential"),
        }
    }

    #[test]
    fn test_ssh_credential_clone() {
        let cred = SshCredential::Password("test".to_string());
        let cloned = cred.clone();
        match (cred, cloned) {
            (SshCredential::Password(a), SshCredential::Password(b)) => {
                assert_eq!(a, b);
            }
            _ => panic!("Clone should produce same variant"),
        }
    }

    #[test]
    fn test_ssh_credential_debug() {
        let cred = SshCredential::Password("secret".to_string());
        let debug = format!("{:?}", cred);
        // Debug should show Password variant (but ideally not the actual secret)
        assert!(debug.contains("Password"));
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
            credential: SshCredential::Password("pass".to_string()),
        };
        assert_eq!(config.session_id, "sess-123");
        assert_eq!(config.port, 22);
        assert_eq!(config.terminal_cols, 80);
    }

    #[test]
    fn test_session_config_clone() {
        let config = SessionConfig {
            session_id: "sess-abc".to_string(),
            user_id: "user-xyz".to_string(),
            asset_id: "asset-123".to_string(),
            host: "server.local".to_string(),
            port: 2222,
            username: "root".to_string(),
            terminal_cols: 120,
            terminal_rows: 40,
            credential: SshCredential::Password("secret".to_string()),
        };
        let cloned = config.clone();
        assert_eq!(config.session_id, cloned.session_id);
        assert_eq!(config.host, cloned.host);
        assert_eq!(config.port, cloned.port);
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
            credential: SshCredential::Password("pass".to_string()),
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
                credential: SshCredential::Password("pass".to_string()),
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
            credential: SshCredential::Password("pass".to_string()),
        };
        assert_eq!(config.terminal_cols, 200);
        assert_eq!(config.terminal_rows, 50);
    }

    // ==================== SshHandler Tests ====================

    #[test]
    fn test_ssh_handler_new() {
        let handler = SshHandler::new("test-session".to_string());
        assert_eq!(handler.session_id, "test-session");
    }
}
