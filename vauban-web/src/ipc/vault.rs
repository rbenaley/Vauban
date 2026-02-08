//! IPC client for communication with vauban-vault.
//!
//! Provides async methods to encrypt/decrypt secrets and manage TOTP MFA
//! via IPC pipes to the vault service (M-1, C-2).
//!
//! This client follows the same pattern as `ProxySshClient` but is simpler
//! since all vault operations are request/response (no streaming).

use crate::error::{AppError, AppResult};
use shared::ipc::IpcChannel;
use shared::messages::{Message, SensitiveString};
use std::collections::HashMap;
use std::io;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use tokio::sync::{oneshot, Mutex};
use tracing::{debug, error, info, warn};

/// Vault response variants, unified for the pending_requests map.
#[derive(Debug)]
enum VaultResponse {
    Encrypt {
        ciphertext: Option<String>,
        error: Option<String>,
    },
    Decrypt {
        plaintext: Option<SensitiveString>,
        error: Option<String>,
    },
    MfaGenerate {
        encrypted_secret: Option<String>,
        qr_code_base64: Option<String>,
        error: Option<String>,
    },
    MfaVerify {
        valid: bool,
        error: Option<String>,
    },
    MfaQrCode {
        qr_code_base64: Option<String>,
        error: Option<String>,
    },
}

/// Async IPC client for vauban-vault cryptographic operations.
pub struct VaultCryptoClient {
    /// Underlying IPC channel.
    channel: IpcChannel,
    /// Async file descriptor for reading.
    read_async_fd: AsyncFd<RawFd>,
    /// Next request ID.
    next_request_id: AtomicU64,
    /// Pending requests waiting for responses.
    pending_requests: Mutex<HashMap<u64, oneshot::Sender<VaultResponse>>>,
}

impl VaultCryptoClient {
    /// Create a new vault crypto client.
    ///
    /// The file descriptors should be passed by the supervisor via topology pipes.
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

    /// Encrypt plaintext with the specified domain keyring.
    ///
    /// Returns the versioned ciphertext string (e.g. "v1:BASE64...").
    pub async fn encrypt(&self, domain: &str, plaintext: &str) -> AppResult<String> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = oneshot::channel();

        self.pending_requests.lock().await.insert(request_id, tx);

        let msg = Message::VaultEncrypt {
            request_id,
            domain: domain.to_string(),
            plaintext: SensitiveString::new(plaintext.to_string()),
        };
        self.channel
            .send(&msg)
            .map_err(|e| AppError::Ipc(format!("vault send error: {}", e)))?;

        debug!(request_id, domain, "VaultEncrypt request sent");

        let resp = rx
            .await
            .map_err(|_| AppError::Ipc("vault response channel dropped".to_string()))?;

        match resp {
            VaultResponse::Encrypt {
                ciphertext: Some(ct),
                error: None,
            } => Ok(ct),
            VaultResponse::Encrypt {
                error: Some(e), ..
            } => Err(AppError::Ipc(format!("vault encrypt error: {}", e))),
            _ => Err(AppError::Ipc(
                "unexpected vault encrypt response".to_string(),
            )),
        }
    }

    /// Decrypt ciphertext with the specified domain keyring.
    ///
    /// Returns the decrypted plaintext as a `SensitiveString`.
    pub async fn decrypt(&self, domain: &str, ciphertext: &str) -> AppResult<SensitiveString> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = oneshot::channel();

        self.pending_requests.lock().await.insert(request_id, tx);

        let msg = Message::VaultDecrypt {
            request_id,
            domain: domain.to_string(),
            ciphertext: ciphertext.to_string(),
        };
        self.channel
            .send(&msg)
            .map_err(|e| AppError::Ipc(format!("vault send error: {}", e)))?;

        debug!(request_id, domain, "VaultDecrypt request sent");

        let resp = rx
            .await
            .map_err(|_| AppError::Ipc("vault response channel dropped".to_string()))?;

        match resp {
            VaultResponse::Decrypt {
                plaintext: Some(pt),
                error: None,
            } => Ok(pt),
            VaultResponse::Decrypt {
                error: Some(e), ..
            } => Err(AppError::Ipc(format!("vault decrypt error: {}", e))),
            _ => Err(AppError::Ipc(
                "unexpected vault decrypt response".to_string(),
            )),
        }
    }

    /// Generate a new MFA TOTP secret, encrypt it, and return the QR code.
    ///
    /// Returns `(encrypted_secret, qr_code_base64)`.
    /// The plaintext TOTP secret NEVER leaves the vault process.
    pub async fn mfa_generate(
        &self,
        username: &str,
        issuer: &str,
    ) -> AppResult<(String, String)> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = oneshot::channel();

        self.pending_requests.lock().await.insert(request_id, tx);

        let msg = Message::VaultMfaGenerate {
            request_id,
            username: username.to_string(),
            issuer: issuer.to_string(),
        };
        self.channel
            .send(&msg)
            .map_err(|e| AppError::Ipc(format!("vault send error: {}", e)))?;

        debug!(request_id, username, "VaultMfaGenerate request sent");

        let resp = rx
            .await
            .map_err(|_| AppError::Ipc("vault response channel dropped".to_string()))?;

        match resp {
            VaultResponse::MfaGenerate {
                encrypted_secret: Some(enc),
                qr_code_base64: Some(qr),
                error: None,
            } => Ok((enc, qr)),
            VaultResponse::MfaGenerate {
                error: Some(e), ..
            } => Err(AppError::Ipc(format!("vault mfa_generate error: {}", e))),
            _ => Err(AppError::Ipc(
                "unexpected vault mfa_generate response".to_string(),
            )),
        }
    }

    /// Verify a TOTP code against an encrypted secret.
    pub async fn mfa_verify(&self, encrypted_secret: &str, code: &str) -> AppResult<bool> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = oneshot::channel();

        self.pending_requests.lock().await.insert(request_id, tx);

        let msg = Message::VaultMfaVerify {
            request_id,
            encrypted_secret: encrypted_secret.to_string(),
            code: code.to_string(),
        };
        self.channel
            .send(&msg)
            .map_err(|e| AppError::Ipc(format!("vault send error: {}", e)))?;

        debug!(request_id, "VaultMfaVerify request sent");

        let resp = rx
            .await
            .map_err(|_| AppError::Ipc("vault response channel dropped".to_string()))?;

        match resp {
            VaultResponse::MfaVerify { valid, error: None } => Ok(valid),
            VaultResponse::MfaVerify {
                error: Some(e), ..
            } => Err(AppError::Ipc(format!("vault mfa_verify error: {}", e))),
            _ => Err(AppError::Ipc(
                "unexpected vault mfa_verify response".to_string(),
            )),
        }
    }

    /// Re-generate a QR code from an existing encrypted TOTP secret.
    pub async fn mfa_qr_code(
        &self,
        encrypted_secret: &str,
        username: &str,
        issuer: &str,
    ) -> AppResult<String> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = oneshot::channel();

        self.pending_requests.lock().await.insert(request_id, tx);

        let msg = Message::VaultMfaQrCode {
            request_id,
            encrypted_secret: encrypted_secret.to_string(),
            username: username.to_string(),
            issuer: issuer.to_string(),
        };
        self.channel
            .send(&msg)
            .map_err(|e| AppError::Ipc(format!("vault send error: {}", e)))?;

        debug!(request_id, username, "VaultMfaQrCode request sent");

        let resp = rx
            .await
            .map_err(|_| AppError::Ipc("vault response channel dropped".to_string()))?;

        match resp {
            VaultResponse::MfaQrCode {
                qr_code_base64: Some(qr),
                error: None,
            } => Ok(qr),
            VaultResponse::MfaQrCode {
                error: Some(e), ..
            } => Err(AppError::Ipc(format!("vault mfa_qr_code error: {}", e))),
            _ => Err(AppError::Ipc(
                "unexpected vault mfa_qr_code response".to_string(),
            )),
        }
    }

    /// Process incoming messages from the vault service.
    ///
    /// This should be called in a loop from a dedicated background task
    /// (via `tokio::spawn`).
    pub async fn process_incoming(&self) -> AppResult<()> {
        loop {
            // Wait for the fd to be readable
            let mut guard = self
                .read_async_fd
                .ready(Interest::READABLE)
                .await
                .map_err(|e| AppError::Ipc(format!("AsyncFd ready failed: {}", e)))?;

            // Try to receive all available messages
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
                        info!("Vault IPC connection closed");
                        return Err(AppError::Ipc("Vault IPC connection closed".to_string()));
                    }
                    Err(e) => {
                        error!(error = %e, "Vault IPC receive error");
                        guard.clear_ready();
                        break;
                    }
                }
            }
        }
    }

    /// Handle an incoming message from the vault.
    async fn handle_message(&self, msg: Message) {
        let request_id = msg.request_id();

        let response = match msg {
            Message::VaultEncryptResponse {
                ciphertext, error, ..
            } => VaultResponse::Encrypt { ciphertext, error },

            Message::VaultDecryptResponse {
                plaintext, error, ..
            } => VaultResponse::Decrypt { plaintext, error },

            Message::VaultMfaGenerateResponse {
                encrypted_secret,
                qr_code_base64,
                error,
                ..
            } => VaultResponse::MfaGenerate {
                encrypted_secret,
                qr_code_base64,
                error,
            },

            Message::VaultMfaVerifyResponse { valid, error, .. } => {
                VaultResponse::MfaVerify { valid, error }
            }

            Message::VaultMfaQrCodeResponse {
                qr_code_base64,
                error,
                ..
            } => VaultResponse::MfaQrCode {
                qr_code_base64,
                error,
            },

            other => {
                warn!("Unexpected message from vault: {:?}", other);
                return;
            }
        };

        if let Some(rid) = request_id {
            let mut pending = self.pending_requests.lock().await;
            if let Some(tx) = pending.remove(&rid) {
                let _ = tx.send(response);
            } else {
                warn!(request_id = rid, "No pending request for vault response");
            }
        }
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

    #[test]
    fn test_vault_response_encrypt() {
        let resp = VaultResponse::Encrypt {
            ciphertext: Some("v1:abc".to_string()),
            error: None,
        };
        let debug = format!("{:?}", resp);
        assert!(debug.contains("Encrypt"));
    }

    #[test]
    fn test_vault_response_decrypt() {
        let resp = VaultResponse::Decrypt {
            plaintext: Some(SensitiveString::new("secret".to_string())),
            error: None,
        };
        let debug = format!("{:?}", resp);
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("secret"));
    }

    #[test]
    fn test_vault_response_mfa_generate() {
        let resp = VaultResponse::MfaGenerate {
            encrypted_secret: Some("v1:enc".to_string()),
            qr_code_base64: Some("base64data".to_string()),
            error: None,
        };
        let debug = format!("{:?}", resp);
        assert!(debug.contains("MfaGenerate"));
    }

    #[test]
    fn test_vault_response_mfa_verify() {
        let resp = VaultResponse::MfaVerify {
            valid: true,
            error: None,
        };
        let debug = format!("{:?}", resp);
        assert!(debug.contains("true"));
    }
}
