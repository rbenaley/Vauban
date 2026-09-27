// Relax strict clippy lints in test code where unwrap/expect/panic are idiomatic.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::print_stdout,
        clippy::print_stderr
    )
)]

//! Decrypt-only IPC client for vauban-vault (MCP mirror of proxy-ssh).
//!
//! SECURITY (règle d'or / Phase 1): vauban-web ships only vault
//! ciphertext in `McpSessionOpen.credential_blob`. This client
//! materialises the upstream bearer inside the Capsicum-sealed proxy
//! address space. Authz: `VaultPeer::ProxyMcp` → `Decrypt{credentials}`
//! only (`vauban-vault/src/authz.rs`).

use crate::async_ipc::{AsyncIpcChannel, IpcError};
use secrecy::{ExposeSecret, SecretString};
use shared::ipc::IpcChannel;
use shared::messages::Message;
use shared::vault_envelope::is_vault_envelope;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::{Mutex, oneshot};
use tracing::{debug, error, info, warn};

/// Vault keyring domain for asset connection credentials.
pub const DOMAIN_CREDENTIALS: &str = "credentials";

#[derive(Debug)]
struct DecryptOutcome {
    plaintext: Option<shared::messages::SensitiveString>,
    error: Option<String>,
}

/// Async, decrypt-only IPC client for vauban-vault.
pub struct VaultDecryptClient {
    channel: AsyncIpcChannel,
    next_request_id: AtomicU64,
    pending_requests: Mutex<HashMap<u64, oneshot::Sender<DecryptOutcome>>>,
}

impl VaultDecryptClient {
    pub fn new(channel: IpcChannel) -> std::io::Result<Arc<Self>> {
        let channel = AsyncIpcChannel::new(channel)?;
        Ok(Arc::new(Self {
            channel,
            next_request_id: AtomicU64::new(1),
            pending_requests: Mutex::new(HashMap::new()),
        }))
    }

    pub async fn decrypt(&self, domain: &str, ciphertext: &str) -> Result<SecretString, String> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = oneshot::channel();
        self.pending_requests.lock().await.insert(request_id, tx);

        let msg = Message::VaultDecrypt {
            request_id,
            domain: domain.to_string(),
            ciphertext: ciphertext.to_string(),
        };
        if let Err(e) = self.channel.send(&msg) {
            self.pending_requests.lock().await.remove(&request_id);
            return Err(format!("vault send error: {e}"));
        }
        debug!(request_id, domain, "VaultDecrypt request sent");

        let outcome = rx
            .await
            .map_err(|_| "vault response channel dropped".to_string())?;

        match outcome {
            DecryptOutcome {
                plaintext: Some(pt),
                error: None,
            } => Ok(SecretString::from(pt.into_inner())),
            DecryptOutcome { error: Some(e), .. } => Err(format!("vault decrypt error: {e}")),
            _ => Err("unexpected vault decrypt response".to_string()),
        }
    }

    pub async fn process_incoming(self: Arc<Self>) {
        loop {
            match self.channel.recv().await {
                Ok(Message::VaultDecryptResponse {
                    request_id,
                    plaintext,
                    error,
                }) => {
                    let outcome = DecryptOutcome { plaintext, error };
                    if let Some(tx) = self.pending_requests.lock().await.remove(&request_id) {
                        let _ = tx.send(outcome);
                    } else {
                        warn!(request_id, "No pending vault request for decrypt response");
                    }
                }
                Ok(other) => {
                    debug!(?other, "Ignoring unexpected message from vault");
                }
                Err(IpcError::ConnectionClosed) => {
                    info!("Vault IPC connection closed; decrypt client stopping");
                    return;
                }
                Err(e) => {
                    error!(error = %e, "Vault IPC receive error");
                    return;
                }
            }
        }
    }
}

/// Materialise an upstream Bearer from `McpSessionOpen.credential_blob`.
///
/// - Empty blob → `Ok(None)` (auth_type none / no upstream secret).
/// - Non-empty → must be a vault envelope; decrypt via vault; refuse
///   plaintext passthrough (fail-closed).
pub async fn materialise_upstream_bearer(
    vault: Option<&Arc<VaultDecryptClient>>,
    credential_blob: Vec<u8>,
) -> Result<Option<String>, String> {
    if credential_blob.is_empty() {
        return Ok(None);
    }
    let ct = String::from_utf8(credential_blob)
        .map_err(|_| "credential_blob is not valid UTF-8 ciphertext".to_string())?;
    if !is_vault_envelope(&ct) {
        return Err("credential_blob is not a vault envelope (plaintext refused)".to_string());
    }
    let vault = vault.ok_or_else(|| "vault client not available".to_string())?;
    let secret = vault.decrypt(DOMAIN_CREDENTIALS, &ct).await?;
    Ok(Some(secret.expose_secret().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared::messages::SensitiveString;

    #[tokio::test]
    async fn empty_blob_is_none() {
        let got = materialise_upstream_bearer(None, Vec::new())
            .await
            .expect("ok");
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn plaintext_blob_refused() {
        let err = materialise_upstream_bearer(None, b"super-secret-token".to_vec())
            .await
            .expect_err("must refuse plaintext");
        assert!(err.contains("plaintext refused"), "got: {err}");
    }

    #[tokio::test]
    async fn envelope_without_vault_refused() {
        let err = materialise_upstream_bearer(None, b"v1:CIPHER".to_vec())
            .await
            .expect_err("must need vault");
        assert!(err.contains("vault client not available"), "got: {err}");
    }

    #[tokio::test]
    async fn decrypt_round_trip_returns_bearer() {
        let (client_ch, vault_ch) = IpcChannel::pair().unwrap();
        let client = VaultDecryptClient::new(client_ch).unwrap();
        tokio::spawn(Arc::clone(&client).process_incoming());

        let vault_handle = tokio::task::spawn_blocking(move || {
            let req: Message = vault_ch.recv().unwrap();
            let (request_id, domain, ciphertext) = match req {
                Message::VaultDecrypt {
                    request_id,
                    domain,
                    ciphertext,
                } => (request_id, domain, ciphertext),
                other => panic!("expected VaultDecrypt, got {other:?}"),
            };
            assert_eq!(domain, DOMAIN_CREDENTIALS);
            assert_eq!(ciphertext, "v1:CIPHER");
            vault_ch
                .send(&Message::VaultDecryptResponse {
                    request_id,
                    plaintext: Some(SensitiveString::new("upstream-bearer".to_string())),
                    error: None,
                })
                .unwrap();
        });

        let got = materialise_upstream_bearer(Some(&client), b"v1:CIPHER".to_vec())
            .await
            .expect("decrypt ok");
        assert_eq!(got.as_deref(), Some("upstream-bearer"));
        vault_handle.await.unwrap();
    }
}
