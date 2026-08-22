//! IPC client for communication with vauban-auth.
//!
//! Provides async methods for password hashing and verification
//! via IPC pipes to the auth service (Argon2id).
//!
//! Transport/correlation is owned by [`CorrelatedIpcCore`] (no timeout —
//! INV-CORR-5).

use crate::error::{AppError, AppResult};
use crate::ipc::correlated::{CorrelatedIpcCore, CorrelatedIpcErrorExt, deliver_or_warn};
use shared::messages::{LdapBindAndSearchOutcome, LdapBindOutcome, Message, SensitiveString};
use std::collections::HashMap;
use std::io;
use std::os::unix::io::RawFd;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use tokio::sync::oneshot;
use tracing::{debug, warn};

enum AuthResponse {
    Verify {
        valid: bool,
    },
    Hash {
        hash: Option<String>,
        error: Option<String>,
    },
    LdapBind {
        outcome: LdapBindOutcome,
    },
    LdapBindAndSearch {
        outcome: LdapBindAndSearchOutcome,
        group_keys: Vec<String>,
    },
}

/// Reply to [`AuthIpcClient::ldap_bind_and_search`].
#[derive(Debug, Clone)]
pub struct LdapBindAndSearchReply {
    /// Bind-then-search outcome (bind failures never increment aggregation).
    pub outcome: LdapBindAndSearchOutcome,
    /// Directory keys collected on [`LdapBindAndSearchOutcome::Complete`].
    pub group_keys: Vec<String>,
}

pub struct AuthIpcClient {
    core: CorrelatedIpcCore,
    pending_requests: StdMutex<HashMap<u64, oneshot::Sender<AuthResponse>>>,
}

impl AuthIpcClient {
    pub fn new(read_fd: RawFd, write_fd: RawFd) -> io::Result<Arc<Self>> {
        Ok(Arc::new(Self {
            core: CorrelatedIpcCore::from_fds(read_fd, write_fd)?,
            pending_requests: StdMutex::new(HashMap::new()),
        }))
    }

    async fn call(&self, msg: Message, request_id: u64) -> AppResult<AuthResponse> {
        self.core
            .request(&self.pending_requests, request_id, &msg, None)
            .await
            .map_err(|e| e.into_app_ipc())
    }

    /// Verify a password against an Argon2id hash.
    pub async fn verify_password(&self, password: &str, password_hash: &str) -> AppResult<bool> {
        let request_id = self.core.alloc_id();
        let msg = Message::AuthVerifyPassword {
            request_id,
            password_hash: password_hash.to_string(),
            password: SensitiveString::new(password.to_string()),
        };
        debug!(request_id, "AuthVerifyPassword request sent");
        match self.call(msg, request_id).await? {
            AuthResponse::Verify { valid } => Ok(valid),
            _ => Err(AppError::Ipc("unexpected auth response type".to_string())),
        }
    }

    /// Hash a plaintext password with Argon2id.
    pub async fn hash_password(&self, password: &str) -> AppResult<String> {
        let request_id = self.core.alloc_id();
        let msg = Message::AuthHashPassword {
            request_id,
            password: SensitiveString::new(password.to_string()),
        };
        debug!(request_id, "AuthHashPassword request sent");
        match self.call(msg, request_id).await? {
            AuthResponse::Hash { hash, error } => {
                if let Some(h) = hash {
                    Ok(h)
                } else {
                    Err(AppError::Ipc(
                        error.unwrap_or_else(|| "hash failed".to_string()),
                    ))
                }
            }
            _ => Err(AppError::Ipc("unexpected auth response type".to_string())),
        }
    }

    /// Bind then search (Phase 1 aggregation). Bind-level failures use the
    /// `Bind*` outcomes and must not increment the web fail-closed counter.
    pub async fn ldap_bind_and_search(
        &self,
        username: &str,
        password: &str,
    ) -> AppResult<LdapBindAndSearchReply> {
        let request_id = self.core.alloc_id();
        let msg = Message::AuthLdapBindAndSearch {
            request_id,
            username: username.to_string(),
            password: SensitiveString::new(password.to_string()),
        };
        debug!(request_id, "AuthLdapBindAndSearch request sent");
        match self.call(msg, request_id).await? {
            AuthResponse::LdapBindAndSearch {
                outcome,
                group_keys,
            } => Ok(LdapBindAndSearchReply {
                outcome,
                group_keys,
            }),
            _ => Err(AppError::Ipc("unexpected auth response type".to_string())),
        }
    }

    /// Perform an LDAPS simple bind against the configured directory.
    ///
    /// The auth service brokers a TCP socket through the supervisor, terminates
    /// TLS itself, and runs the bind; the plaintext password never transits the
    /// root TCB. The returned [`LdapBindOutcome`] is coarse on purpose: callers
    /// MUST collapse every non-`Success` variant into a single generic
    /// "invalid credentials" response to avoid directory enumeration.
    pub async fn ldap_bind(&self, username: &str, password: &str) -> AppResult<LdapBindOutcome> {
        let request_id = self.core.alloc_id();
        let msg = Message::AuthLdapBind {
            request_id,
            username: username.to_string(),
            password: SensitiveString::new(password.to_string()),
        };
        debug!(request_id, "AuthLdapBind request sent");
        match self.call(msg, request_id).await? {
            AuthResponse::LdapBind { outcome } => Ok(outcome),
            _ => Err(AppError::Ipc("unexpected auth response type".to_string())),
        }
    }

    /// Process incoming messages from the auth service.
    ///
    /// Should be spawned as a background task via `tokio::spawn`.
    pub async fn process_incoming(&self) -> AppResult<()> {
        self.core
            .process_loop(|msg| {
                self.handle_message(msg);
                async {}
            })
            .await
            .map_err(|e| e.into_app_ipc())
    }

    fn handle_message(&self, msg: Message) {
        let request_id = msg.request_id();

        let response = match msg {
            Message::AuthVerifyPasswordResponse { valid, .. } => AuthResponse::Verify { valid },
            Message::AuthHashPasswordResponse { hash, error, .. } => {
                AuthResponse::Hash { hash, error }
            }
            Message::AuthLdapBindResponse { outcome, .. } => AuthResponse::LdapBind { outcome },
            Message::AuthLdapBindAndSearchResponse {
                outcome,
                group_keys,
                ..
            } => AuthResponse::LdapBindAndSearch {
                outcome,
                group_keys,
            },
            other => {
                warn!("Unexpected message from Auth service: {:?}", other);
                return;
            }
        };

        if let Some(rid) = request_id {
            deliver_or_warn(&self.pending_requests, rid, response, "auth");
        }
    }
}

#[cfg(test)]
mod tests {
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
}
