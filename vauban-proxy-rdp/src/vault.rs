//! Decrypt-only IPC client for RDP target passwords.
//!
//! The web process forwards the stored value (vault envelope or historical
//! plaintext). This module opens envelopes on the `credentials` domain and
//! leaves plaintext unchanged. A truncated envelope is refused.

use crate::error::IpcError;
use crate::ipc::AsyncIpcChannel;
use secrecy::SecretString;
use shared::ipc::IpcChannel;
use shared::messages::Message;
use shared::vault_envelope::is_vault_envelope;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::{Mutex, oneshot};
use tracing::{debug, error, info, warn};

pub const DOMAIN_CREDENTIALS: &str = "credentials";

#[derive(Debug)]
struct DecryptOutcome {
    plaintext: Option<shared::messages::SensitiveString>,
    error: Option<String>,
}

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

/// How a stored RDP password should be treated before the session starts.
#[derive(Debug, PartialEq, Eq)]
pub enum PasswordClass {
    Absent,
    Plaintext(String),
    Envelope(String),
    Rejected,
}

pub fn classify_password(raw: Option<&str>) -> PasswordClass {
    let Some(value) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return PasswordClass::Absent;
    };
    if is_vault_envelope(value) {
        return PasswordClass::Envelope(value.to_string());
    }
    // `v1:` and other digit-prefixed prefixes are truncated envelopes.
    if let Some(rest) = value.strip_prefix('v')
        && rest.contains(':')
        && rest.chars().next().is_some_and(|c| c.is_ascii_digit())
    {
        return PasswordClass::Rejected;
    }
    PasswordClass::Plaintext(value.to_string())
}

pub async fn materialise_rdp_password(
    vault: Option<&Arc<VaultDecryptClient>>,
    stored: Option<shared::messages::SensitiveString>,
) -> Result<Option<SecretString>, String> {
    let raw = stored.map(|s| s.into_inner());
    match classify_password(raw.as_deref()) {
        PasswordClass::Absent => Ok(None),
        PasswordClass::Plaintext(password) => Ok(Some(SecretString::from(password))),
        PasswordClass::Rejected => Err("truncated vault envelope".to_string()),
        PasswordClass::Envelope(ciphertext) => {
            let vault = vault.ok_or_else(|| "vault client not available".to_string())?;
            vault
                .decrypt(DOMAIN_CREDENTIALS, &ciphertext)
                .await
                .map(Some)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use secrecy::ExposeSecret;
    use shared::messages::SensitiveString;

    #[test]
    fn classify_plaintext_envelope_and_empty() {
        assert_eq!(classify_password(None), PasswordClass::Absent);
        assert_eq!(classify_password(Some("  ")), PasswordClass::Absent);
        assert_eq!(
            classify_password(Some("s3cret")),
            PasswordClass::Plaintext("s3cret".to_string())
        );
        assert_eq!(
            classify_password(Some("v1:QQ==")),
            PasswordClass::Envelope("v1:QQ==".to_string())
        );
        assert_eq!(classify_password(Some("v1:")), PasswordClass::Rejected);
    }

    proptest::proptest! {
        #[test]
        fn proptest_truncated_envelopes_are_rejected(n in 1u32..8) {
            let value = format!("v{n}:");
            prop_assert_eq!(classify_password(Some(&value)), PasswordClass::Rejected);
        }
    }

    #[tokio::test]
    async fn envelope_round_trip_returns_plaintext() {
        let (client_ch, vault_ch) = IpcChannel::pair().expect("pair");
        let client = VaultDecryptClient::new(client_ch).expect("client");
        tokio::spawn(Arc::clone(&client).process_incoming());
        let vault_handle = tokio::task::spawn_blocking(move || {
            let req: Message = vault_ch.recv().unwrap();
            let Message::VaultDecrypt {
                request_id,
                domain,
                ciphertext,
            } = req
            else {
                panic!("expected VaultDecrypt");
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
        let opened = materialise_rdp_password(
            Some(&client),
            Some(SensitiveString::new("v1:CIPHER".to_string())),
        )
        .await
        .expect("opened");
        assert_eq!(opened.expect("password").expose_secret(), "super-secret");
        vault_handle.await.unwrap();
    }

    #[tokio::test]
    async fn plaintext_does_not_call_the_vault() {
        let opened =
            materialise_rdp_password(None, Some(SensitiveString::new("historical".to_string())))
                .await
                .expect("plain");
        assert_eq!(opened.expect("password").expose_secret(), "historical");
    }

    #[tokio::test]
    async fn unreadable_envelope_is_rejected() {
        let err =
            materialise_rdp_password(None, Some(SensitiveString::new("v1:CIPHER".to_string())))
                .await
                .expect_err("no vault");
        assert!(err.contains("vault client"));
    }
}
