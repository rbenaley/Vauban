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
use rcgen::{
    CertificateParams, CustomExtension, DistinguishedName, KeyPair, PKCS_ECDSA_P256_SHA256,
};
use sha2::{Digest, Sha256};
use shared::ipc::IpcChannel;
use shared::messages::{Message, SensitiveString};
use std::io::Write;
use std::path::Path;
use tracing::{debug, error, info, warn};

/// OID for id-pe-acmeIdentifier (1.3.6.1.5.5.7.1.31)
/// RFC 8737, Section 3
const ACME_IDENTIFIER_OID: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 1, 31];

/// The only service allowed to ask for a renewal.
pub const RENEW_CALLER: &str = "web";

/// Why the supervisor refused a renewal request before any network or
/// disk access. `code()` is the text sent back to the caller: a closed
/// set, so nothing from the request is echoed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcmeRefusal {
    /// The request did not come from `vauban-web`.
    CallerNotAllowed,
    /// `[server.tls.acme] enabled` is false in the supervisor's config.
    Disabled,
    /// A path, the directory, the email or the domain list is missing
    /// from the supervisor's config.
    NotConfigured,
    /// The request names a directory other than the configured one.
    DirectoryMismatch,
    /// The request names a domain that is not in the configured list.
    DomainNotConfigured,
}

impl AcmeRefusal {
    #[cfg(test)]
    pub const ALL: [AcmeRefusal; 5] = [
        AcmeRefusal::CallerNotAllowed,
        AcmeRefusal::Disabled,
        AcmeRefusal::NotConfigured,
        AcmeRefusal::DirectoryMismatch,
        AcmeRefusal::DomainNotConfigured,
    ];

    pub fn code(self) -> &'static str {
        match self {
            AcmeRefusal::CallerNotAllowed => "acme_caller_not_allowed",
            AcmeRefusal::Disabled => "acme_disabled",
            AcmeRefusal::NotConfigured => "acme_not_configured",
            AcmeRefusal::DirectoryMismatch => "acme_directory_mismatch",
            AcmeRefusal::DomainNotConfigured => "acme_domain_not_configured",
        }
    }
}

/// Decide whether a renewal request runs, and with what.
///
/// The supervisor writes the certificate, the key and the account file
/// as root. Everything that decides what is written and where comes from
/// the supervisor's own configuration (`tls`), never from the request:
/// a service that can send this message must not be able to choose a
/// path, a certificate authority or a domain.
///
/// The request still carries a directory and a domain list. They are
/// compared with the configuration and a difference is a refusal, so a
/// tampered or stale request is seen instead of silently corrected. The
/// paths, the email and the EAB credentials of the request are not read.
pub fn authorize_renewal(
    requester_service_key: &str,
    tls: &crate::config::TlsCertPaths,
    request_id: u64,
    requested_directory_url: &str,
    requested_domains: &[String],
) -> Result<AcmeRenewParams, AcmeRefusal> {
    if requester_service_key != RENEW_CALLER {
        return Err(AcmeRefusal::CallerNotAllowed);
    }
    let acme = &tls.acme;
    if !acme.enabled {
        return Err(AcmeRefusal::Disabled);
    }
    let Some(directory_url) = acme.resolved_directory_url() else {
        return Err(AcmeRefusal::NotConfigured);
    };
    if acme.domains.is_empty()
        || acme.email.is_empty()
        || acme.account_key_path.is_empty()
        || tls.cert_path.is_empty()
        || tls.key_path.is_empty()
    {
        return Err(AcmeRefusal::NotConfigured);
    }
    if requested_directory_url != directory_url {
        return Err(AcmeRefusal::DirectoryMismatch);
    }
    if requested_domains.is_empty() || requested_domains.iter().any(|d| !acme.domains.contains(d)) {
        return Err(AcmeRefusal::DomainNotConfigured);
    }

    // An empty EAB key id in the file means "not set", as in vauban-web.
    let eab_kid = acme.eab_kid.clone().filter(|k| !k.is_empty());
    let eab_hmac_key = acme.eab_hmac_key.clone().filter(|k| !k.as_str().is_empty());

    Ok(AcmeRenewParams {
        request_id,
        directory_url: directory_url.to_string(),
        domains: acme.domains.clone(),
        email: acme.email.clone(),
        account_key_path: acme.account_key_path.clone(),
        cert_path: tls.cert_path.clone(),
        key_path: tls.key_path.clone(),
        eab_kid,
        eab_hmac_key,
    })
}

/// Answer a refused renewal request with its code only.
pub fn refuse_renewal(channel: &IpcChannel, request_id: u64, refusal: AcmeRefusal) {
    send_renew_response(
        channel,
        request_id,
        false,
        Some(refusal.code().to_string()),
        None,
        None,
    );
}

/// Parameters of an ACME renewal. Built only by [`authorize_renewal`],
/// from the supervisor's configuration. `Debug` does not print the EAB
/// key: `SensitiveString` redacts itself.
#[derive(Debug)]
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
            send_renew_response(
                web_channel,
                request_id,
                false,
                Some(e.to_string()),
                None,
                None,
            );
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
                info!(
                    request_id = request_id,
                    "ACME renewal completed successfully"
                );
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
    let identifiers: Vec<Identifier> = domains.iter().map(|d| Identifier::Dns(d.clone())).collect();

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
            .ok_or_else(|| format!("No TLS-ALPN-01 challenge available for {}", domain))?;

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
            (Some(kid), Some(hmac)) => Some(instant_acme::ExternalAccountKey::new(
                kid.to_string(),
                hmac.as_bytes(),
            )),
            _ => None,
        };

        let (account, credentials) = Account::builder()
            .map_err(|e| format!("Failed to create account builder: {}", e))?
            .create(&new_account, directory_url.to_owned(), eab.as_ref())
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

        info!("Created new ACME account, saved to {}", account_key_path);
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

    std::fs::rename(&temp_path, path).map_err(|e| format!("Failed to atomically rename: {}", e))?;

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
    use crate::config::{AcmeSettings, TlsCertPaths};

    const DIRECTORY: &str = "https://acme.example.test/directory";
    const STAGING: &str = "https://acme-staging.example.test/directory";

    /// A supervisor configuration with ACME enabled and complete.
    fn configured() -> TlsCertPaths {
        TlsCertPaths {
            cert_path: "/usr/local/etc/vauban/certs/server.crt".to_string(),
            key_path: "/usr/local/etc/vauban/certs/server.key".to_string(),
            acme: AcmeSettings {
                enabled: true,
                email: "ops@example.test".to_string(),
                domains: vec!["bastion.example.test".to_string()],
                account_key_path: "/usr/local/etc/vauban/acme/account.pem".to_string(),
                staging: false,
                directory_url: DIRECTORY.to_string(),
                staging_directory_url: STAGING.to_string(),
                eab_kid: None,
                eab_hmac_key: None,
            },
        }
    }

    fn domains(list: &[&str]) -> Vec<String> {
        list.iter().map(|d| d.to_string()).collect()
    }

    fn refusal(
        requester: &str,
        tls: &TlsCertPaths,
        directory: &str,
        requested: &[&str],
    ) -> Option<AcmeRefusal> {
        authorize_renewal(requester, tls, 1, directory, &domains(requested)).err()
    }

    #[test]
    fn test_renewal_from_web_uses_the_supervisor_configuration() {
        let tls = configured();
        let params = authorize_renewal(
            "web",
            &tls,
            42,
            DIRECTORY,
            &domains(&["bastion.example.test"]),
        )
        .expect("a matching request from web is authorized");

        assert_eq!(params.request_id, 42);
        assert_eq!(params.directory_url, DIRECTORY);
        assert_eq!(params.domains, tls.acme.domains);
        assert_eq!(params.email, tls.acme.email);
        assert_eq!(params.account_key_path, tls.acme.account_key_path);
        assert_eq!(params.cert_path, tls.cert_path);
        assert_eq!(params.key_path, tls.key_path);
        assert!(params.eab_kid.is_none());
        assert!(params.eab_hmac_key.is_none());
    }

    #[test]
    fn test_staging_flag_selects_the_staging_directory() {
        let mut tls = configured();
        tls.acme.staging = true;
        assert_eq!(tls.acme.resolved_directory_url(), Some(STAGING));
        assert!(refusal("web", &tls, STAGING, &["bastion.example.test"]).is_none());
        // The production directory is no longer the configured one.
        assert_eq!(
            refusal("web", &tls, DIRECTORY, &["bastion.example.test"]),
            Some(AcmeRefusal::DirectoryMismatch)
        );

        // Staging requested but no staging directory configured: the
        // production directory is used, as in vauban-web.
        tls.acme.staging_directory_url.clear();
        assert_eq!(tls.acme.resolved_directory_url(), Some(DIRECTORY));
    }

    #[test]
    fn test_eab_credentials_come_from_the_configuration() {
        let mut tls = configured();
        tls.acme.eab_kid = Some("kid-1".to_string());
        tls.acme.eab_hmac_key = Some(SensitiveString::new("hmac-1".to_string()));
        let params = authorize_renewal(
            "web",
            &tls,
            1,
            DIRECTORY,
            &domains(&["bastion.example.test"]),
        )
        .expect("authorized");
        assert_eq!(params.eab_kid.as_deref(), Some("kid-1"));
        assert_eq!(
            params.eab_hmac_key.as_ref().map(|k| k.as_str()),
            Some("hmac-1")
        );

        // Empty strings in the file mean "not set".
        tls.acme.eab_kid = Some(String::new());
        tls.acme.eab_hmac_key = Some(SensitiveString::new(String::new()));
        let params = authorize_renewal(
            "web",
            &tls,
            1,
            DIRECTORY,
            &domains(&["bastion.example.test"]),
        )
        .expect("authorized");
        assert!(params.eab_kid.is_none());
        assert!(params.eab_hmac_key.is_none());
    }

    #[test]
    fn test_a_subset_of_the_configured_domains_is_accepted_and_all_are_renewed() {
        let mut tls = configured();
        tls.acme.domains = domains(&["a.example.test", "b.example.test"]);
        let params = authorize_renewal("web", &tls, 1, DIRECTORY, &domains(&["b.example.test"]))
            .expect("authorized");
        assert_eq!(params.domains, tls.acme.domains);
    }

    #[test]
    fn attack_acme_renew_from_non_web_service_is_rejected() {
        let tls = configured();
        for service in [
            "proxy_ssh",
            "proxy_rdp",
            "proxy_iacs",
            "proxy_mcp",
            "audit",
            "auth",
            "access",
            "vault",
            "mailer",
            "supervisor",
            "",
            "WEB",
            "web ",
        ] {
            assert_eq!(
                refusal(service, &tls, DIRECTORY, &["bastion.example.test"]),
                Some(AcmeRefusal::CallerNotAllowed),
                "{service:?} must not trigger a renewal"
            );
        }
    }

    #[test]
    fn attack_acme_renew_when_disabled_is_rejected() {
        let mut tls = configured();
        tls.acme.enabled = false;
        assert_eq!(
            refusal("web", &tls, DIRECTORY, &["bastion.example.test"]),
            Some(AcmeRefusal::Disabled)
        );
        // The default configuration has ACME off.
        assert_eq!(
            refusal(
                "web",
                &TlsCertPaths::default(),
                DIRECTORY,
                &["bastion.example.test"]
            ),
            Some(AcmeRefusal::Disabled)
        );
    }

    #[test]
    fn attack_acme_unknown_directory_url_is_rejected() {
        let tls = configured();
        for directory in [
            "https://attacker.example.test/directory",
            "",
            "https://acme.example.test/directory/",
            "HTTPS://ACME.EXAMPLE.TEST/directory",
            STAGING,
        ] {
            assert_eq!(
                refusal("web", &tls, directory, &["bastion.example.test"]),
                Some(AcmeRefusal::DirectoryMismatch),
                "{directory:?}"
            );
        }
    }

    #[test]
    fn attack_acme_unconfigured_domain_is_rejected() {
        let tls = configured();
        for requested in [
            &["attacker.example.test"][..],
            &["bastion.example.test", "attacker.example.test"][..],
            &["BASTION.example.test"][..],
            &["*.example.test"][..],
            &[][..],
        ] {
            assert_eq!(
                refusal("web", &tls, DIRECTORY, requested),
                Some(AcmeRefusal::DomainNotConfigured),
                "{requested:?}"
            );
        }
    }

    #[test]
    fn attack_acme_incomplete_configuration_is_rejected() {
        let cases: [fn(&mut TlsCertPaths); 6] = [
            |t| t.acme.directory_url.clear(),
            |t| t.acme.domains.clear(),
            |t| t.acme.email.clear(),
            |t| t.acme.account_key_path.clear(),
            |t| t.cert_path.clear(),
            |t| t.key_path.clear(),
        ];
        for (i, break_it) in cases.iter().enumerate() {
            let mut tls = configured();
            break_it(&mut tls);
            assert_eq!(
                refusal("web", &tls, DIRECTORY, &["bastion.example.test"]),
                Some(AcmeRefusal::NotConfigured),
                "case {i}"
            );
        }
    }

    #[test]
    fn test_refusal_codes_are_distinct_and_carry_no_request_data() {
        let codes: std::collections::HashSet<_> =
            AcmeRefusal::ALL.iter().map(|r| r.code()).collect();
        assert_eq!(codes.len(), AcmeRefusal::ALL.len());
        for code in codes {
            assert!(code.starts_with("acme_"));
            assert!(code.chars().all(|c| c.is_ascii_lowercase() || c == '_'));
        }
    }

    /// The function that decides what is written cannot be handed a path:
    /// its signature has none. Pins the property the fix rests on.
    #[test]
    fn attack_acme_paths_from_message_are_ignored() {
        let src = include_str!("acme.rs");
        let signature = src
            .split("pub fn authorize_renewal(")
            .nth(1)
            .and_then(|rest| {
                rest.split(") -> Result<AcmeRenewParams, AcmeRefusal>")
                    .next()
            })
            .expect("authorize_renewal signature");
        for forbidden in ["account_key_path", "cert_path", "key_path", "email", "eab"] {
            assert!(
                !signature.contains(forbidden),
                "authorize_renewal must not take `{forbidden}` from the request"
            );
        }

        let main = include_str!("main.rs");
        let arm = main
            .split("Message::AcmeRenewRequest {")
            .nth(1)
            .and_then(|rest| rest.split("Message::RecordingFileRequest {").next())
            .expect("AcmeRenewRequest arm");
        for forbidden in ["account_key_path", "cert_path", "key_path", "eab_"] {
            assert!(
                !arm.contains(forbidden),
                "the dispatcher must not bind `{forbidden}` from the request"
            );
        }
        assert!(arm.contains("acme::authorize_renewal(service_key, tls,"));
        assert!(
            !main.contains("acme::AcmeRenewParams {"),
            "only authorize_renewal builds the renewal parameters"
        );
    }

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
        assert_eq!(
            cert_der[0], 0x30,
            "Certificate should start with SEQUENCE tag"
        );
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
