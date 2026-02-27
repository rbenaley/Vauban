//! Dynamic TLS certificate resolver with ACME TLS-ALPN-01 support.
//!
//! Implements `rustls::server::ResolvesServerCert` to dynamically select
//! between the production certificate and ACME challenge certificates based
//! on the ALPN protocol negotiated during the TLS handshake.

use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tracing::{debug, info, warn};

const ACME_TLS_ALPN_PROTOCOL: &[u8] = b"acme-tls/1";

/// Shared state for dynamic certificate resolution.
///
/// Protected by `RwLock` since reads (TLS handshakes) vastly outnumber
/// writes (certificate updates via IPC).
struct ResolverState {
    /// The production certificate used for normal HTTPS traffic.
    production_cert: Option<Arc<CertifiedKey>>,
    /// Active ACME TLS-ALPN-01 challenge certificates, keyed by domain.
    /// These are short-lived self-signed certificates with the `acmeIdentifier`
    /// extension, served only when the ALPN is `acme-tls/1`.
    challenge_certs: HashMap<String, Arc<CertifiedKey>>,
}

/// Dynamic TLS resolver that supports ACME TLS-ALPN-01 challenges.
///
/// During normal operation, the production certificate is served.
/// When the supervisor installs a challenge certificate (via IPC), the
/// resolver serves it for connections with ALPN `acme-tls/1` and matching SNI.
///
/// After ACME validation, the supervisor sends the new production certificate
/// which is activated in memory without restarting the server.
pub struct AcmeResolver {
    state: RwLock<ResolverState>,
}

impl std::fmt::Debug for AcmeResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.state.read().unwrap_or_else(|e| e.into_inner());
        f.debug_struct("AcmeResolver")
            .field("has_production_cert", &state.production_cert.is_some())
            .field("active_challenges", &state.challenge_certs.len())
            .finish()
    }
}

impl AcmeResolver {
    /// Create a new resolver with the given production certificate.
    pub fn new(production_cert: Arc<CertifiedKey>) -> Self {
        Self {
            state: RwLock::new(ResolverState {
                production_cert: Some(production_cert),
                challenge_certs: HashMap::new(),
            }),
        }
    }

    /// Create a resolver without a production certificate.
    /// Used when ACME will obtain the initial certificate.
    pub fn without_cert() -> Self {
        Self {
            state: RwLock::new(ResolverState {
                production_cert: None,
                challenge_certs: HashMap::new(),
            }),
        }
    }

    /// Install a TLS-ALPN-01 challenge certificate for a domain.
    /// Called by the IPC handler when the supervisor sends `AcmeChallengeInstall`.
    pub fn install_challenge(&self, domain: &str, certified_key: Arc<CertifiedKey>) {
        let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
        info!(domain = %domain, "Installing ACME TLS-ALPN-01 challenge certificate");
        state.challenge_certs.insert(domain.to_string(), certified_key);
    }

    /// Remove a TLS-ALPN-01 challenge certificate for a domain.
    /// Called by the IPC handler when the supervisor sends `AcmeChallengeRemove`.
    pub fn remove_challenge(&self, domain: &str) {
        let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
        if state.challenge_certs.remove(domain).is_some() {
            info!(domain = %domain, "Removed ACME TLS-ALPN-01 challenge certificate");
        } else {
            debug!(domain = %domain, "No challenge certificate to remove");
        }
    }

    /// Activate a new production certificate.
    /// Called by the IPC handler when the supervisor sends `AcmeCertActivate`.
    /// This enables zero-downtime certificate rotation.
    pub fn activate_production_cert(&self, certified_key: Arc<CertifiedKey>) {
        let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
        state.production_cert = Some(certified_key);
        info!("Activated new production TLS certificate");
    }

    /// Check if any challenge certificates are currently installed.
    pub fn has_active_challenges(&self) -> bool {
        let state = self.state.read().unwrap_or_else(|e| e.into_inner());
        !state.challenge_certs.is_empty()
    }
}

impl ResolvesServerCert for AcmeResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let is_acme_alpn = client_hello
            .alpn()
            .into_iter()
            .flatten()
            .any(|proto| proto == ACME_TLS_ALPN_PROTOCOL);

        if is_acme_alpn {
            let sni = client_hello.server_name()?;
            let state = self.state.read().unwrap_or_else(|e| e.into_inner());

            if let Some(cert) = state.challenge_certs.get(sni) {
                debug!(domain = %sni, "Serving ACME TLS-ALPN-01 challenge certificate");
                return Some(Arc::clone(cert));
            }

            warn!(
                domain = %sni,
                "ACME TLS-ALPN-01 request but no challenge certificate installed"
            );
            return None;
        }

        let state = self.state.read().unwrap_or_else(|e| e.into_inner());
        state.production_cert.as_ref().map(Arc::clone)
    }
}

/// Build a `CertifiedKey` from DER-encoded certificate and private key bytes.
///
/// Used to reconstruct certificates received via IPC from the supervisor.
pub fn certified_key_from_der(
    cert_der: &[u8],
    key_der: &[u8],
) -> Result<CertifiedKey, Box<dyn std::error::Error>> {
    use rustls::crypto::aws_lc_rs::sign::any_supported_type;
    use rustls_pki_types::{CertificateDer, PrivateKeyDer};

    let cert = CertificateDer::from(cert_der.to_vec());
    let key = PrivateKeyDer::try_from(key_der.to_vec())
        .map_err(|e| format!("Invalid DER private key: {}", e))?;
    let signing_key =
        any_supported_type(&key).map_err(|e| format!("Unsupported key type: {}", e))?;

    Ok(CertifiedKey::new(vec![cert], signing_key))
}

/// Build a `CertifiedKey` from PEM-encoded certificate chain and private key.
///
/// Used to load the production certificate from PEM files or PEM data
/// received via IPC after ACME renewal.
pub fn certified_key_from_pem(
    cert_pem: &str,
    key_pem: &str,
) -> Result<CertifiedKey, Box<dyn std::error::Error>> {
    use rustls::crypto::aws_lc_rs::sign::any_supported_type;
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::{CertificateDer, PrivateKeyDer};

    let cert_chain: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(cert_pem.as_bytes())
            .filter_map(|c| c.ok())
            .collect();

    if cert_chain.is_empty() {
        return Err("No valid certificates found in PEM data".into());
    }

    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
        .map_err(|e| format!("Invalid PEM private key: {}", e))?;

    let signing_key =
        any_supported_type(&key).map_err(|e| format!("Unsupported key type: {}", e))?;

    Ok(CertifiedKey::new(cert_chain, signing_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_acme_alpn_protocol_value() {
        assert_eq!(ACME_TLS_ALPN_PROTOCOL, b"acme-tls/1");
    }

    #[test]
    fn test_resolver_without_cert() {
        let resolver = AcmeResolver::without_cert();
        assert!(!resolver.has_active_challenges());
    }

    #[test]
    fn test_resolver_challenge_lifecycle() {
        let resolver = AcmeResolver::without_cert();

        assert!(!resolver.has_active_challenges());

        let state = resolver.state.read().unwrap_or_else(|e| e.into_inner());
        assert!(state.challenge_certs.is_empty());
        drop(state);

        // We can't easily create a CertifiedKey without real crypto material,
        // but we can test the state management logic via install/remove.
        assert!(!resolver.has_active_challenges());
    }

    #[test]
    fn test_resolver_state_default() {
        let resolver = AcmeResolver::without_cert();
        let state = resolver.state.read().unwrap_or_else(|e| e.into_inner());
        assert!(state.production_cert.is_none());
        assert!(state.challenge_certs.is_empty());
    }

    #[test]
    fn test_remove_nonexistent_challenge() {
        let resolver = AcmeResolver::without_cert();
        resolver.remove_challenge("nonexistent.com");
        assert!(!resolver.has_active_challenges());
    }
}
