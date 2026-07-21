//! IPC client for communication with vauban-vault.
//!
//! Provides async methods to encrypt/decrypt secrets and manage TOTP MFA
//! via IPC pipes to the vault service.
//!
//! Transport/correlation is owned by [`CorrelatedIpcCore`] (no timeout —
//! INV-CORR-5).

use crate::error::{AppError, AppResult};
use crate::ipc::correlated::{CorrelatedIpcCore, deliver_or_warn};
use shared::messages::{Message, SensitiveString};
use std::collections::HashMap;
use std::io;
use std::os::unix::io::RawFd;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use tokio::sync::oneshot;
use tracing::{debug, warn};

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
        plaintext_secret: Option<SensitiveString>,
        error: Option<String>,
    },
    MfaVerify {
        valid: bool,
        error: Option<String>,
    },
    MfaGetSecret {
        plaintext_secret: Option<SensitiveString>,
        error: Option<String>,
    },
}

/// Async IPC client for vauban-vault cryptographic operations.
pub struct VaultCryptoClient {
    core: CorrelatedIpcCore,
    pending_requests: StdMutex<HashMap<u64, oneshot::Sender<VaultResponse>>>,
}

impl VaultCryptoClient {
    /// Create a new vault crypto client.
    ///
    /// The file descriptors should be passed by the supervisor via topology pipes.
    pub fn new(read_fd: RawFd, write_fd: RawFd) -> io::Result<Arc<Self>> {
        Ok(Arc::new(Self {
            core: CorrelatedIpcCore::from_fds(read_fd, write_fd)?,
            pending_requests: StdMutex::new(HashMap::new()),
        }))
    }

    async fn call(&self, msg: Message, request_id: u64) -> AppResult<VaultResponse> {
        self.core
            .request(&self.pending_requests, request_id, &msg, None)
            .await
            .map_err(|e| e.into_app_ipc())
    }

    /// Encrypt plaintext with the specified domain keyring.
    ///
    /// Returns the versioned ciphertext string (e.g. "v1:BASE64...").
    pub async fn encrypt(&self, domain: &str, plaintext: &str) -> AppResult<String> {
        let request_id = self.core.alloc_id();
        let msg = Message::VaultEncrypt {
            request_id,
            domain: domain.to_string(),
            plaintext: SensitiveString::new(plaintext.to_string()),
        };
        debug!(request_id, domain, "VaultEncrypt request sent");
        match self.call(msg, request_id).await? {
            VaultResponse::Encrypt {
                ciphertext: Some(ct),
                error: None,
            } => Ok(ct),
            VaultResponse::Encrypt { error: Some(e), .. } => {
                Err(AppError::Ipc(format!("vault encrypt error: {}", e)))
            }
            _ => Err(AppError::Ipc(
                "unexpected vault encrypt response".to_string(),
            )),
        }
    }

    /// Decrypt ciphertext with the specified domain keyring.
    ///
    /// Returns the decrypted plaintext as a `SensitiveString`.
    pub async fn decrypt(&self, domain: &str, ciphertext: &str) -> AppResult<SensitiveString> {
        let request_id = self.core.alloc_id();
        let msg = Message::VaultDecrypt {
            request_id,
            domain: domain.to_string(),
            ciphertext: ciphertext.to_string(),
        };
        debug!(request_id, domain, "VaultDecrypt request sent");
        match self.call(msg, request_id).await? {
            VaultResponse::Decrypt {
                plaintext: Some(pt),
                error: None,
            } => Ok(pt),
            VaultResponse::Decrypt { error: Some(e), .. } => {
                Err(AppError::Ipc(format!("vault decrypt error: {}", e)))
            }
            _ => Err(AppError::Ipc(
                "unexpected vault decrypt response".to_string(),
            )),
        }
    }

    /// Generate a new MFA TOTP secret and encrypt it.
    ///
    /// Returns `(encrypted_secret, plaintext_secret)`.
    /// The vault generates and encrypts the secret; the plaintext is returned
    /// as a `SensitiveString` (zeroize-on-drop) for QR code generation by the
    /// web layer.
    pub async fn mfa_generate(
        &self,
        username: &str,
        issuer: &str,
    ) -> AppResult<(String, SensitiveString)> {
        let request_id = self.core.alloc_id();
        let msg = Message::VaultMfaGenerate {
            request_id,
            username: username.to_string(),
            issuer: issuer.to_string(),
        };
        debug!(request_id, username, "VaultMfaGenerate request sent");
        match self.call(msg, request_id).await? {
            VaultResponse::MfaGenerate {
                encrypted_secret: Some(enc),
                plaintext_secret: Some(pt),
                error: None,
            } => Ok((enc, pt)),
            VaultResponse::MfaGenerate { error: Some(e), .. } => {
                Err(AppError::Ipc(format!("vault mfa_generate error: {}", e)))
            }
            _ => Err(AppError::Ipc(
                "unexpected vault mfa_generate response".to_string(),
            )),
        }
    }

    /// Verify a TOTP code against an encrypted secret.
    pub async fn mfa_verify(&self, encrypted_secret: &str, code: &str) -> AppResult<bool> {
        let request_id = self.core.alloc_id();
        let msg = Message::VaultMfaVerify {
            request_id,
            encrypted_secret: encrypted_secret.to_string(),
            code: code.to_string(),
        };
        debug!(request_id, "VaultMfaVerify request sent");
        match self.call(msg, request_id).await? {
            VaultResponse::MfaVerify { valid, error: None } => Ok(valid),
            VaultResponse::MfaVerify { error: Some(e), .. } => {
                Err(AppError::Ipc(format!("vault mfa_verify error: {}", e)))
            }
            _ => Err(AppError::Ipc(
                "unexpected vault mfa_verify response".to_string(),
            )),
        }
    }

    /// Decrypt an encrypted TOTP secret and return the plaintext.
    ///
    /// Used to re-generate QR codes from existing encrypted secrets.
    /// Returns a `SensitiveString` (zeroize-on-drop).
    pub async fn mfa_get_secret(&self, encrypted_secret: &str) -> AppResult<SensitiveString> {
        let request_id = self.core.alloc_id();
        let msg = Message::VaultMfaGetSecret {
            request_id,
            encrypted_secret: encrypted_secret.to_string(),
        };
        debug!(request_id, "VaultMfaGetSecret request sent");
        match self.call(msg, request_id).await? {
            VaultResponse::MfaGetSecret {
                plaintext_secret: Some(pt),
                error: None,
            } => Ok(pt),
            VaultResponse::MfaGetSecret { error: Some(e), .. } => {
                Err(AppError::Ipc(format!("vault mfa_get_secret error: {}", e)))
            }
            _ => Err(AppError::Ipc(
                "unexpected vault mfa_get_secret response".to_string(),
            )),
        }
    }

    /// Process incoming messages from the vault service.
    ///
    /// This should be called in a loop from a dedicated background task
    /// (via `tokio::spawn`).
    pub async fn process_incoming(&self) -> AppResult<()> {
        self.core
            .process_loop(|msg| {
                self.handle_message(msg);
                async {}
            })
            .await
            .map_err(|e| e.into_app_ipc())
    }

    /// Handle an incoming message from the vault.
    fn handle_message(&self, msg: Message) {
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
                plaintext_secret,
                error,
                ..
            } => VaultResponse::MfaGenerate {
                encrypted_secret,
                plaintext_secret,
                error,
            },

            Message::VaultMfaVerifyResponse { valid, error, .. } => {
                VaultResponse::MfaVerify { valid, error }
            }

            Message::VaultMfaGetSecretResponse {
                plaintext_secret,
                error,
                ..
            } => VaultResponse::MfaGetSecret {
                plaintext_secret,
                error,
            },

            other => {
                warn!("Unexpected message from vault: {:?}", other);
                return;
            }
        };

        if let Some(rid) = request_id {
            deliver_or_warn(&self.pending_requests, rid, response, "vault");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn test_set_nonblocking() {
        let (read_fd, _write_fd) = nix::unistd::pipe().unwrap();
        let result = crate::ipc::correlated::set_nonblocking(read_fd.as_raw_fd());
        assert!(result.is_ok());

        use libc::{F_GETFL, O_NONBLOCK, fcntl};
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
            plaintext_secret: Some(SensitiveString::new("JBSWY3DPEHPK3PXP".to_string())),
            error: None,
        };
        let debug = format!("{:?}", resp);
        assert!(debug.contains("MfaGenerate"));
        assert!(debug.contains("REDACTED"));
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
