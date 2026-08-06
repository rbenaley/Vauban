//! In-process ACME TLS-ALPN-01 worker (ported from Vauban supervisor, no IPC).

use std::io::Write;
use std::path::Path;
use std::sync::Arc;

use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount,
    NewOrder, OrderStatus, RetryPolicy,
};
use rcgen::{
    CertificateParams, CustomExtension, DistinguishedName, KeyPair, PKCS_ECDSA_P256_SHA256,
};
use sha2::{Digest, Sha256};
use tracing::{debug, info};

use crate::acme::scheduler::CertExpiry;
use crate::config::AcmeConfig;
use crate::tls::{AcmeResolver, certified_key_from_der, certified_key_from_pem};

/// OID for id-pe-acmeIdentifier (1.3.6.1.5.5.7.1.31) — RFC 8737 §3.
const ACME_IDENTIFIER_OID: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 1, 31];

pub struct RenewRequest {
    pub acme: AcmeConfig,
    pub cert_path: String,
    pub key_path: String,
}

/// Run one ACME renewal and activate the certificate in the resolver.
pub async fn renew(
    request: RenewRequest,
    resolver: Arc<AcmeResolver>,
    cert_expiry: Arc<CertExpiry>,
) -> anyhow::Result<()> {
    let directory_url = request.acme.resolve_directory_url()?;
    let (cert_pem, key_pem) = acme_workflow(
        &directory_url,
        &request.acme.domains,
        &request.acme.email,
        &request.acme.account_key_path,
        &request.cert_path,
        &request.key_path,
        request.acme.eab_kid.as_deref(),
        request.acme.eab_hmac_key.as_deref(),
        &resolver,
    )
    .await?;

    let certified = certified_key_from_pem(&cert_pem, &key_pem)
        .map_err(|e| anyhow::anyhow!("activate cert parse failed: {e}"))?;
    resolver.activate_production_cert(Arc::new(certified));

    use rustls_pki_types::CertificateDer;
    use rustls_pki_types::pem::PemObject;
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .filter_map(|c| c.ok())
        .collect();
    if let Some(leaf) = certs.first() {
        cert_expiry.update_from_der(leaf.as_ref());
    }

    info!("ACME renewal completed and certificate activated");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn acme_workflow(
    directory_url: &str,
    domains: &[String],
    email: &str,
    account_key_path: &str,
    cert_path: &str,
    key_path: &str,
    eab_kid: Option<&str>,
    eab_hmac_key: Option<&str>,
    resolver: &AcmeResolver,
) -> anyhow::Result<(String, String)> {
    let account = get_or_create_account(
        directory_url,
        email,
        account_key_path,
        eab_kid,
        eab_hmac_key,
    )
    .await?;
    info!("ACME account ready");

    let identifiers: Vec<Identifier> = domains.iter().map(|d| Identifier::Dns(d.clone())).collect();
    let mut order = account
        .new_order(&NewOrder::new(&identifiers))
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create ACME order: {e}"))?;

    let mut challenged_domains: Vec<String> = Vec::new();
    let mut authorizations = order.authorizations();
    while let Some(result) = authorizations.next().await {
        let mut authz = result.map_err(|e| anyhow::anyhow!("Failed to get authorization: {e}"))?;
        let domain = authz.identifier().to_string();
        debug!(%domain, "Processing authorization");

        match authz.status {
            AuthorizationStatus::Valid => continue,
            AuthorizationStatus::Pending => {}
            status => {
                anyhow::bail!("Authorization for {domain} has unexpected status: {status:?}");
            }
        }

        let mut challenge = authz
            .challenge(ChallengeType::TlsAlpn01)
            .ok_or_else(|| anyhow::anyhow!("No TLS-ALPN-01 challenge for {domain}"))?;

        let key_auth = challenge.key_authorization();
        let key_auth_digest = Sha256::digest(key_auth.as_str().as_bytes());
        let (challenge_cert_der, challenge_key_der) =
            generate_challenge_cert(&domain, &key_auth_digest)?;

        let certified = certified_key_from_der(&challenge_cert_der, &challenge_key_der)
            .map_err(|e| anyhow::anyhow!("challenge cert: {e}"))?;
        resolver.install_challenge(&domain, Arc::new(certified));
        challenged_domains.push(domain.clone());

        challenge
            .set_ready()
            .await
            .map_err(|e| anyhow::anyhow!("set challenge ready for {domain}: {e}"))?;
    }

    let status = order
        .poll_ready(&RetryPolicy::default())
        .await
        .map_err(|e| anyhow::anyhow!("Order polling failed: {e}"))?;

    for domain in &challenged_domains {
        resolver.remove_challenge(domain);
    }

    if status != OrderStatus::Ready {
        anyhow::bail!("Unexpected order status after polling: {status:?}");
    }

    let private_key_pem = order
        .finalize()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to finalize order: {e}"))?;
    let cert_chain_pem = order
        .poll_certificate(&RetryPolicy::default())
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get certificate: {e}"))?;

    atomic_write_pem(cert_path, &cert_chain_pem)?;
    atomic_write_pem(key_path, &private_key_pem)?;
    info!(%cert_path, %key_path, "Certificate and key written to disk");

    Ok((cert_chain_pem, private_key_pem))
}

async fn get_or_create_account(
    directory_url: &str,
    email: &str,
    account_key_path: &str,
    eab_kid: Option<&str>,
    eab_hmac_key: Option<&str>,
) -> anyhow::Result<Account> {
    let path = Path::new(account_key_path);

    if path.exists() {
        let json = std::fs::read_to_string(path)?;
        let credentials: AccountCredentials = serde_json::from_str(&json)?;
        let account = Account::builder()
            .map_err(|e| anyhow::anyhow!("account builder: {e}"))?
            .from_credentials(credentials)
            .await
            .map_err(|e| anyhow::anyhow!("restore ACME account: {e}"))?;
        info!(%account_key_path, "Loaded existing ACME account");
        Ok(account)
    } else {
        let new_account = NewAccount {
            contact: &[&format!("mailto:{email}")],
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
            .map_err(|e| anyhow::anyhow!("account builder: {e}"))?
            .create(&new_account, directory_url.to_owned(), eab.as_ref())
            .await
            .map_err(|e| anyhow::anyhow!("create ACME account: {e}"))?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let credentials_json = serde_json::to_string_pretty(&credentials)?;
        atomic_write_pem(account_key_path, &credentials_json)?;
        info!(%account_key_path, "Created new ACME account");
        Ok(account)
    }
}

fn generate_challenge_cert(
    domain: &str,
    key_auth_digest: &[u8],
) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .map_err(|e| anyhow::anyhow!("challenge key: {e}"))?;
    let mut params = CertificateParams::new(vec![domain.to_string()])
        .map_err(|e| anyhow::anyhow!("challenge params: {e}"))?;
    params.distinguished_name = DistinguishedName::new();

    let mut ext_value = Vec::with_capacity(2 + key_auth_digest.len());
    ext_value.push(0x04);
    ext_value.push(key_auth_digest.len() as u8);
    ext_value.extend_from_slice(key_auth_digest);
    let mut ext = CustomExtension::from_oid_content(ACME_IDENTIFIER_OID, ext_value);
    ext.set_criticality(true);
    params.custom_extensions.push(ext);

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| anyhow::anyhow!("self-sign challenge: {e}"))?;
    Ok((cert.der().to_vec(), key_pair.serialize_der()))
}

pub(crate) fn atomic_write_pem(path: &str, data: &str) -> anyhow::Result<()> {
    let path = Path::new(path);
    if let Some(parent) = path.parent()
        && !parent.exists()
    {
        std::fs::create_dir_all(parent)?;
    }
    let temp_path = path.with_extension("tmp");
    let mut file = std::fs::File::create(&temp_path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(data.as_bytes())?;
    file.sync_all()?;
    std::fs::rename(&temp_path, path)?;
    Ok(())
}
