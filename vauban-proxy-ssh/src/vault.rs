//! Decrypt-only IPC client for vauban-vault.
//!
//! SECURITY (least privilege): vauban-proxy-ssh only ever needs to
//! *decrypt* asset credentials that vauban-web sealed at create/edit
//! time (the `credentials` keyring). It never encrypts and never reads
//! MFA secrets, so this client deliberately exposes a single
//! [`VaultDecryptClient::decrypt`] method. The matching authorization
//! rule already exists vault-side
//! (`vauban-vault/src/authz.rs`: `(VaultPeer::ProxySsh,
//! VaultDecrypt { domain }) => domain == DOMAIN_CREDENTIALS`) and the
//! `ProxySsh -> Vault` IPC edge is part of the supervisor topology, so
//! this module only had to grow the proxy-side half of the channel.
//!
//! This is the seam that removes weakness #4 (credentials in clear on
//! the web->proxy IPC): vauban-web now ships only vault ciphertexts in
//! `SshSessionOpen`, and the proxy materialises the plaintext here,
//! moments before it builds the russh credential, entirely inside its
//! own sandboxed address space.

use crate::ipc::AsyncIpcChannel;
use secrecy::SecretString;
use shared::ipc::IpcChannel;
use shared::messages::Message;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::{Mutex, oneshot};
use tracing::{debug, error, info, warn};

/// Vault keyring domain that holds asset connection credentials. MUST
/// match `vauban-vault`'s `DOMAIN_CREDENTIALS` and the authz allowlist.
pub const DOMAIN_CREDENTIALS: &str = "credentials";

/// Outcome of a single decrypt request, routed back to the awaiting
/// caller via the `pending_requests` map.
#[derive(Debug)]
struct DecryptOutcome {
    plaintext: Option<shared::messages::SensitiveString>,
    error: Option<String>,
}

/// Async, decrypt-only IPC client for vauban-vault.
///
/// One instance is created at proxy boot (when the supervisor wired the
/// `VAUBAN_VAULT_IPC_READ` / `VAUBAN_VAULT_IPC_WRITE` pipe). A single
/// background task drives [`VaultDecryptClient::process_incoming`];
/// every [`decrypt`](Self::decrypt) call registers a oneshot in
/// `pending_requests` keyed by `request_id` and awaits the reply.
pub struct VaultDecryptClient {
    channel: AsyncIpcChannel,
    next_request_id: AtomicU64,
    pending_requests: Mutex<HashMap<u64, oneshot::Sender<DecryptOutcome>>>,
}

impl VaultDecryptClient {
    /// Build a decrypt-only client from a raw vault IPC channel.
    ///
    /// The channel's read end is switched to non-blocking and wrapped in
    /// a tokio `AsyncFd` (inside [`AsyncIpcChannel::new`]); this MUST run
    /// in a tokio runtime context but BEFORE Capsicum so the reactor
    /// registration is not refused by the sandbox.
    pub fn new(channel: IpcChannel) -> std::io::Result<Arc<Self>> {
        let channel = AsyncIpcChannel::new(channel)?;
        Ok(Arc::new(Self {
            channel,
            next_request_id: AtomicU64::new(1),
            pending_requests: Mutex::new(HashMap::new()),
        }))
    }

    /// Decrypt a versioned ciphertext (e.g. `"v1:BASE64..."`) sealed in
    /// the `credentials` keyring, returning the plaintext as a
    /// `SecretString` (zeroize-on-drop) ready to feed a russh credential.
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
            // Drop the dangling pending entry so it cannot leak.
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

    /// Background reader loop. Spawn once via `tokio::spawn` after the
    /// sandbox is entered (mirrors the AccessGuard dispatcher). Routes
    /// every `VaultDecryptResponse` to the matching pending oneshot.
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
                Err(crate::error::IpcError::ConnectionClosed) => {
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

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;
    use shared::messages::SensitiveString;

    /// End-to-end round-trip over an in-process pipe: a fake vault peer
    /// answers a `VaultDecrypt` with a `VaultDecryptResponse`, and the
    /// client surfaces the plaintext as a `SecretString`.
    #[tokio::test]
    async fn decrypt_round_trip_returns_secret() {
        let (client_ch, vault_ch) = IpcChannel::pair().unwrap();
        let client = VaultDecryptClient::new(client_ch).unwrap();
        tokio::spawn(Arc::clone(&client).process_incoming());

        // Fake vault: read the request, reply with the "plaintext".
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
                    plaintext: Some(SensitiveString::new("super-secret".to_string())),
                    error: None,
                })
                .unwrap();
        });

        let secret = client
            .decrypt(DOMAIN_CREDENTIALS, "v1:CIPHER")
            .await
            .expect("decrypt ok");
        assert_eq!(secret.expose_secret(), "super-secret");
        vault_handle.await.unwrap();
    }

    #[tokio::test]
    async fn decrypt_propagates_vault_error() {
        let (client_ch, vault_ch) = IpcChannel::pair().unwrap();
        let client = VaultDecryptClient::new(client_ch).unwrap();
        tokio::spawn(Arc::clone(&client).process_incoming());

        let vault_handle = tokio::task::spawn_blocking(move || {
            let req: Message = vault_ch.recv().unwrap();
            let request_id = req.request_id().unwrap();
            vault_ch
                .send(&Message::VaultDecryptResponse {
                    request_id,
                    plaintext: None,
                    error: Some("key version unknown".to_string()),
                })
                .unwrap();
        });

        let err = client
            .decrypt(DOMAIN_CREDENTIALS, "v9:BAD")
            .await
            .expect_err("must surface vault error");
        assert!(err.contains("key version unknown"), "got: {err}");
        vault_handle.await.unwrap();
    }
}
