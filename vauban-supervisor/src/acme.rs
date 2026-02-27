//! ACME TLS-ALPN-01 certificate management worker.
//!
//! Handles the complete ACME workflow when the supervisor receives an
//! `AcmeRenewRequest` from `vauban-web`:
//!
//! 1. Create/reuse ACME account via `Account::builder()`
//! 2. Create certificate order
//! 3. For each authorization:
//!    a. Get TLS-ALPN-01 challenge
//!    b. Generate challenge certificate with `acmeIdentifier` extension (rcgen)
//!    c. Send `AcmeChallengeInstall` to vauban-web via IPC
//!    d. Mark challenge ready
//!    e. Wait for validation
//!    f. Send `AcmeChallengeRemove` to vauban-web
//! 4. Finalize order (generates CSR internally)
//! 5. Download certificate
//! 6. Write cert/key atomically to disk
//! 7. Send `AcmeCertActivate` to vauban-web for in-memory activation
//! 8. Send `AcmeRenewResponse` back to vauban-web

use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount,
    NewOrder, OrderStatus, RetryPolicy,
};
use rcgen::{CertificateParams, CustomExtension, DistinguishedName, KeyPair, PKCS_ECDSA_P256_SHA256};
use sha2::{Digest, Sha256};
use shared::ipc::IpcChannel;
use shared::messages::{Message, SensitiveString};
use std::io::Write;
use std::path::Path;
use tracing::{debug, error, info, warn};

/// OID for id-pe-acmeIdentifier (1.3.6.1.5.5.7.1.31)
/// RFC 8737, Section 3
const ACME_IDENTIFIER_OID: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 1, 31];

/// Parameters for an ACME renewal request.
pub struct AcmeRenewParams {
    pub request_id: u64,
    pub directory_url: String,
    pub domains: Vec<String>,
    pub email: String,
    pub account_key_path: String,
    pub cert_path: String,
    pub key_path: String,
    pub eab_kid: Option<String>,
    pub eab_hmac_key: Option<SensitiveString>,
}

/// Run the ACME renewal workflow in a dedicated tokio runtime.
///
/// This function is called from the synchronous supervisor main loop.
/// It creates a single-threaded tokio runtime, runs the async ACME
/// workflow, and blocks until completion.
pub fn handle_acme_renew(params: AcmeRenewParams, web_channel: &IpcChannel) {
    let AcmeRenewParams {
        request_id,
        directory_url,
        domains,
        email,
        account_key_path,
        cert_path,
        key_path,
        eab_kid,
        eab_hmac_key,
    } = params;
    info!(
        request_id = request_id,
        domains = ?domains,
        directory = %directory_url,
        "Starting ACME renewal workflow"
    );

    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            error!(error = %e, "Failed to create tokio runtime for ACME");
            send_renew_response(web_channel, request_id, false, Some(e.to_string()), None, None);
            return;
        }
    };

    rt.block_on(async {
        match acme_workflow(
            request_id,
            &directory_url,
            &domains,
            &email,
            &account_key_path,
            &cert_path,
            &key_path,
            eab_kid.as_deref(),
            eab_hmac_key.as_ref().map(|s| s.as_str()),
            web_channel,
        )
        .await
        {
            Ok((cert_pem, key_pem)) => {
                info!(request_id = request_id, "ACME renewal completed successfully");
                send_renew_response(
                    web_channel,
                    request_id,
                    true,
                    None,
                    Some(cert_pem),
                    Some(SensitiveString::new(key_pem)),
                );
            }
            Err(e) => {
                error!(request_id = request_id, error = %e, "ACME renewal failed");
                send_renew_response(
                    web_channel,
                    request_id,
                    false,
                    Some(e.to_string()),
                    None,
                    None,
                );
            }
        }
    });
}

/// Core async ACME workflow.
///
/// Returns (cert_pem, key_pem) on success.
#[allow(clippy::too_many_arguments)]
async fn acme_workflow(
    request_id: u64,
    directory_url: &str,
    domains: &[String],
    email: &str,
    account_key_path: &str,
    cert_path: &str,
    key_path: &str,
    eab_kid: Option<&str>,
    eab_hmac_key: Option<&str>,
    web_channel: &IpcChannel,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    // Step 1: Create or load ACME account
    let account = get_or_create_account(
        directory_url,
        email,
        account_key_path,
        eab_kid,
        eab_hmac_key,
    )
    .await?;

    info!(request_id = request_id, "ACME account ready");

    // Step 2: Create certificate order
    let identifiers: Vec<Identifier> = domains
        .iter()
        .map(|d| Identifier::Dns(d.clone()))
        .collect();

    let mut order = account
        .new_order(&NewOrder::new(&identifiers))
        .await
        .map_err(|e| format!("Failed to create ACME order: {}", e))?;

    info!(
        request_id = request_id,
        status = ?order.state().status,
        "ACME order created"
    );

    // Step 3: Handle authorizations
    let mut challenged_domains: Vec<String> = Vec::new();
    let mut authorizations = order.authorizations();
    while let Some(result) = authorizations.next().await {
        let mut authz = result.map_err(|e| format!("Failed to get authorization: {}", e))?;
        let domain = authz.identifier().to_string();
        debug!(request_id = request_id, domain = %domain, "Processing authorization");

        match authz.status {
            AuthorizationStatus::Valid => {
                info!(domain = %domain, "Authorization already valid, skipping");
                continue;
            }
            AuthorizationStatus::Pending => {}
            status => {
                return Err(format!(
                    "Authorization for {} has unexpected status: {:?}",
                    domain, status
                )
                .into());
            }
        }

        // Find TLS-ALPN-01 challenge
        let mut challenge = authz
            .challenge(ChallengeType::TlsAlpn01)
            .ok_or_else(|| {
                format!("No TLS-ALPN-01 challenge available for {}", domain)
            })?;

        // Step 3a: Compute the key authorization SHA-256 digest for acmeIdentifier
        let key_auth = challenge.key_authorization();
        let key_auth_digest = Sha256::digest(key_auth.as_str().as_bytes());

        // Step 3b: Generate challenge certificate
        let (challenge_cert_der, challenge_key_der) =
            generate_challenge_cert(&domain, key_auth_digest.as_slice())?;

        // Step 3c: Send challenge cert to vauban-web
        let install_msg = Message::AcmeChallengeInstall {
            request_id,
            domain: domain.clone(),
            challenge_cert_der,
            challenge_key_der,
        };
        web_channel
            .send(&install_msg)
            .map_err(|e| format!("Failed to send AcmeChallengeInstall: {}", e))?;

        challenged_domains.push(domain.clone());
        info!(domain = %domain, "Challenge certificate installed, notifying CA");

        // Step 3d: Tell the CA the challenge is ready
        challenge
            .set_ready()
            .await
            .map_err(|e| format!("Failed to set challenge ready for {}: {}", domain, e))?;
    }

    // Step 4: Wait for order to become ready (CA validates challenges here)
    let status = order
        .poll_ready(&RetryPolicy::default())
        .await
        .map_err(|e| format!("Order polling failed: {}", e))?;

    // Step 4b: Remove challenge certificates now that validation is complete
    for domain in &challenged_domains {
        let _ = web_channel.send(&Message::AcmeChallengeRemove {
            request_id,
            domain: domain.clone(),
        });
    }

    if status != OrderStatus::Ready {
        return Err(format!("Unexpected order status after polling: {:?}", status).into());
    }

    // Step 5: Finalize order (generates CSR + signs internally)
    let private_key_pem = order
        .finalize()
        .await
        .map_err(|e| format!("Failed to finalize order: {}", e))?;

    // Step 6: Download certificate
    let cert_chain_pem = order
        .poll_certificate(&RetryPolicy::default())
        .await
        .map_err(|e| format!("Failed to get certificate: {}", e))?;

    // Step 7: Write atomically to disk
    atomic_write_pem(cert_path, &cert_chain_pem)?;
    atomic_write_pem(key_path, &private_key_pem)?;

    info!(
        cert_path = %cert_path,
        key_path = %key_path,
        "Certificate and key written to disk"
    );

    // Step 8: Send cert activation to vauban-web
    let activate_msg = Message::AcmeCertActivate {
        request_id,
        cert_pem: cert_chain_pem.clone(),
        key_pem: SensitiveString::new(private_key_pem.clone()),
    };
    web_channel
        .send(&activate_msg)
        .map_err(|e| format!("Failed to send AcmeCertActivate: {}", e))?;

    Ok((cert_chain_pem, private_key_pem))
}

/// Get or create an ACME account.
///
/// If `account_key_path` exists, loads the persisted account credentials.
/// Otherwise, creates a new account and persists the credentials.
async fn get_or_create_account(
    directory_url: &str,
    email: &str,
    account_key_path: &str,
    eab_kid: Option<&str>,
    eab_hmac_key: Option<&str>,
) -> Result<Account, Box<dyn std::error::Error>> {
    let path = Path::new(account_key_path);

    if path.exists() {
        let json = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read account credentials: {}", e))?;

        let credentials: AccountCredentials = serde_json::from_str(&json)
            .map_err(|e| format!("Failed to parse account credentials: {}", e))?;

        let account = Account::builder()
            .map_err(|e| format!("Failed to create account builder: {}", e))?
            .from_credentials(credentials)
            .await
            .map_err(|e| format!("Failed to restore ACME account: {}", e))?;

        info!("Loaded existing ACME account from {}", account_key_path);
        Ok(account)
    } else {
        let new_account = NewAccount {
            contact: &[&format!("mailto:{}", email)],
            terms_of_service_agreed: true,
            only_return_existing: false,
        };

        let eab = match (eab_kid, eab_hmac_key) {
            (Some(kid), Some(hmac)) => {
                Some(instant_acme::ExternalAccountKey::new(kid.to_string(), hmac.as_bytes()))
            }
            _ => None,
        };

        let (account, credentials) = Account::builder()
            .map_err(|e| format!("Failed to create account builder: {}", e))?
            .create(
                &new_account,
                directory_url.to_owned(),
                eab.as_ref(),
            )
            .await
            .map_err(|e| format!("Failed to create ACME account: {}", e))?;

        // Persist account credentials
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create account key directory: {}", e))?;
        }

        let credentials_json = serde_json::to_string_pretty(&credentials)
            .map_err(|e| format!("Failed to serialize account credentials: {}", e))?;

        atomic_write_pem(account_key_path, &credentials_json)?;

        info!(
            "Created new ACME account, saved to {}",
            account_key_path
        );
        Ok(account)
    }
}

/// Generate a self-signed TLS-ALPN-01 challenge certificate.
///
/// The certificate contains the `acmeIdentifier` extension (OID 1.3.6.1.5.5.7.1.31)
/// with the SHA-256 digest of the key authorization as its value (RFC 8737).
///
/// Returns (cert_der, key_der).
fn generate_challenge_cert(
    domain: &str,
    key_auth_digest: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .map_err(|e| format!("Failed to generate challenge key: {}", e))?;

    let mut params = CertificateParams::new(vec![domain.to_string()])
        .map_err(|e| format!("Failed to create challenge cert params: {}", e))?;

    params.distinguished_name = DistinguishedName::new();

    // RFC 8737 Section 3: The acmeIdentifier extension value is an
    // ASN.1 OCTET STRING containing the SHA-256 digest of the key authorization.
    let mut ext_value = Vec::with_capacity(2 + key_auth_digest.len());
    ext_value.push(0x04); // OCTET STRING tag
    ext_value.push(key_auth_digest.len() as u8);
    ext_value.extend_from_slice(key_auth_digest);

    let mut ext = CustomExtension::from_oid_content(ACME_IDENTIFIER_OID, ext_value);
    ext.set_criticality(true);
    params.custom_extensions.push(ext);

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| format!("Failed to self-sign challenge cert: {}", e))?;

    Ok((cert.der().to_vec(), key_pair.serialize_der()))
}

/// Write data to a file atomically using write-to-temp + rename.
fn atomic_write_pem(path: &str, data: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(path);
    let parent = path
        .parent()
        .ok_or("Invalid file path: no parent directory")?;

    if !parent.exists() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create directory {}: {}", parent.display(), e))?;
    }

    let temp_path = path.with_extension("tmp");
    let mut file = std::fs::File::create(&temp_path)
        .map_err(|e| format!("Failed to create temp file: {}", e))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("Failed to set file permissions: {}", e))?;
    }

    file.write_all(data.as_bytes())
        .map_err(|e| format!("Failed to write data: {}", e))?;
    file.sync_all()
        .map_err(|e| format!("Failed to sync file: {}", e))?;

    std::fs::rename(&temp_path, path)
        .map_err(|e| format!("Failed to atomically rename: {}", e))?;

    Ok(())
}

/// Send an `AcmeRenewResponse` back to vauban-web.
fn send_renew_response(
    web_channel: &IpcChannel,
    request_id: u64,
    success: bool,
    error: Option<String>,
    cert_pem: Option<String>,
    key_pem: Option<SensitiveString>,
) {
    let msg = Message::AcmeRenewResponse {
        request_id,
        success,
        error,
        cert_pem,
        key_pem,
    };
    if let Err(e) = web_channel.send(&msg) {
        warn!(
            request_id = request_id,
            error = %e,
            "Failed to send AcmeRenewResponse"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_acme_identifier_oid() {
        assert_eq!(ACME_IDENTIFIER_OID, &[1, 3, 6, 1, 5, 5, 7, 1, 31]);
    }

    #[test]
    fn test_generate_challenge_cert() {
        let digest = Sha256::digest(b"test-key-authorization");
        let result = generate_challenge_cert("example.com", digest.as_slice());
        assert!(result.is_ok(), "Challenge cert generation should succeed");

        let (cert_der, key_der) = result.unwrap();
        assert!(!cert_der.is_empty(), "Certificate DER should not be empty");
        assert!(!key_der.is_empty(), "Key DER should not be empty");
        assert_eq!(cert_der[0], 0x30, "Certificate should start with SEQUENCE tag");
    }

    #[test]
    fn test_atomic_write_pem() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.pem");
        let path_str = path.to_str().unwrap();

        atomic_write_pem(path_str, "test content").unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content, "test content");
    }

    #[test]
    fn test_atomic_write_creates_parent_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("dir").join("test.pem");
        let path_str = path.to_str().unwrap();

        atomic_write_pem(path_str, "nested content").unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content, "nested content");
    }

    #[test]
    fn test_challenge_cert_contains_acme_extension() {
        let digest = [0xABu8; 32]; // dummy 32-byte digest
        let (cert_der, _) = generate_challenge_cert("test.example.com", &digest).unwrap();

        // Verify the OID bytes for acmeIdentifier appear in the DER
        // OID 1.3.6.1.5.5.7.1.31 encodes as: 06 0A 2B 06 01 05 05 07 01 1F
        let oid_encoded = [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x1F];
        let found = cert_der
            .windows(oid_encoded.len())
            .any(|w| w == oid_encoded);
        assert!(found, "Certificate must contain acmeIdentifier OID");
    }
}
