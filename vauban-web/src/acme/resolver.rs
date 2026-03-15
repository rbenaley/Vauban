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
        state
            .challenge_certs
            .insert(domain.to_string(), certified_key);
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

/// Generate a self-signed certificate for the given domains and write it
/// to `cert_path` and `key_path`.
///
/// Used when ACME is enabled but no certificate files exist yet.
/// The scheduler will detect this as self-signed and trigger immediate
/// ACME renewal to replace it with a real certificate.
///
/// **Must be called before `cap_enter()`** since it performs file I/O.
pub fn generate_self_signed_cert(
    domains: &[String],
    cert_path: &str,
    key_path: &str,
) -> Result<CertifiedKey, Box<dyn std::error::Error>> {
    use rcgen::{CertificateParams, KeyPair};

    if domains.is_empty() {
        return Err("Cannot generate certificate: no domains configured".into());
    }

    let key_pair =
        KeyPair::generate().map_err(|e| format!("Failed to generate key pair: {}", e))?;
    let params = CertificateParams::new(domains.to_vec())
        .map_err(|e| format!("Failed to create certificate params: {}", e))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| format!("Failed to self-sign certificate: {}", e))?;

    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    // Write to disk atomically (temp + rename) with restrictive permissions
    atomic_write_pem(cert_path, &cert_pem)?;
    atomic_write_pem(key_path, &key_pem)?;

    info!(
        cert_path = %cert_path,
        key_path = %key_path,
        domains = ?domains,
        "Generated self-signed bootstrap certificate"
    );

    certified_key_from_pem(&cert_pem, &key_pem)
}

/// Write data to a file atomically using write-to-temp + rename.
fn atomic_write_pem(path: &str, data: &str) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;
    use std::path::Path;

    let path = Path::new(path);
    if let Some(parent) = path.parent()
        && !parent.exists()
    {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a CertifiedKey from a fresh self-signed certificate.
    fn make_certified_key(cn: &str) -> Arc<CertifiedKey> {
        use rcgen::{CertificateParams, DnType, KeyPair};
        use rustls::crypto::aws_lc_rs::sign::any_supported_type;
        use rustls_pki_types::{CertificateDer, PrivateKeyDer};

        let key_pair = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec![cn.to_string()]).unwrap();
        params.distinguished_name.push(DnType::CommonName, cn);
        let cert = params.self_signed(&key_pair).unwrap();

        let cert_der = CertificateDer::from(cert.der().to_vec());
        let key_der = PrivateKeyDer::try_from(key_pair.serialize_der()).unwrap();
        let signing_key = any_supported_type(&key_der).unwrap();

        Arc::new(CertifiedKey::new(vec![cert_der], signing_key))
    }

    // ==================== Protocol constant ====================

    #[test]
    fn test_acme_alpn_protocol_value() {
        assert_eq!(ACME_TLS_ALPN_PROTOCOL, b"acme-tls/1");
    }

    // ==================== Resolver construction ====================

    #[test]
    fn test_resolver_without_cert() {
        let resolver = AcmeResolver::without_cert();
        assert!(!resolver.has_active_challenges());
        let state = resolver.state.read().unwrap();
        assert!(state.production_cert.is_none());
    }

    #[test]
    fn test_resolver_with_production_cert() {
        let cert = make_certified_key("prod.example.com");
        let resolver = AcmeResolver::new(cert);
        assert!(!resolver.has_active_challenges());
        let state = resolver.state.read().unwrap();
        assert!(state.production_cert.is_some());
    }

    // ==================== Challenge lifecycle ====================

    #[test]
    fn test_challenge_install_and_has_active() {
        let resolver = AcmeResolver::without_cert();
        assert!(!resolver.has_active_challenges());

        let challenge_cert = make_certified_key("challenge.example.com");
        resolver.install_challenge("example.com", challenge_cert);

        assert!(resolver.has_active_challenges());
    }

    #[test]
    fn test_challenge_install_multiple_domains() {
        let resolver = AcmeResolver::without_cert();

        resolver.install_challenge("a.com", make_certified_key("a.com"));
        resolver.install_challenge("b.com", make_certified_key("b.com"));
        resolver.install_challenge("c.com", make_certified_key("c.com"));

        assert!(resolver.has_active_challenges());
        let state = resolver.state.read().unwrap();
        assert_eq!(state.challenge_certs.len(), 3);
    }

    #[test]
    fn test_challenge_remove() {
        let resolver = AcmeResolver::without_cert();
        resolver.install_challenge("example.com", make_certified_key("example.com"));
        assert!(resolver.has_active_challenges());

        resolver.remove_challenge("example.com");
        assert!(!resolver.has_active_challenges());
    }

    #[test]
    fn test_challenge_remove_nonexistent_is_noop() {
        let resolver = AcmeResolver::without_cert();
        resolver.remove_challenge("nonexistent.com");
        assert!(!resolver.has_active_challenges());
    }

    #[test]
    fn test_challenge_replace_same_domain() {
        let resolver = AcmeResolver::without_cert();

        let cert1 = make_certified_key("example.com");
        let cert2 = make_certified_key("example.com");
        let cert2_ptr = Arc::as_ptr(&cert2);

        resolver.install_challenge("example.com", cert1);
        resolver.install_challenge("example.com", cert2);

        let state = resolver.state.read().unwrap();
        assert_eq!(state.challenge_certs.len(), 1);
        assert!(std::ptr::eq(
            Arc::as_ptr(state.challenge_certs.get("example.com").unwrap()),
            cert2_ptr
        ));
    }

    #[test]
    fn test_challenge_remove_partial() {
        let resolver = AcmeResolver::without_cert();
        resolver.install_challenge("a.com", make_certified_key("a.com"));
        resolver.install_challenge("b.com", make_certified_key("b.com"));

        resolver.remove_challenge("a.com");
        assert!(resolver.has_active_challenges());

        let state = resolver.state.read().unwrap();
        assert_eq!(state.challenge_certs.len(), 1);
        assert!(state.challenge_certs.contains_key("b.com"));
    }

    // ==================== Production cert rotation ====================

    #[test]
    fn test_activate_production_cert() {
        let resolver = AcmeResolver::without_cert();
        let state = resolver.state.read().unwrap();
        assert!(state.production_cert.is_none());
        drop(state);

        let new_cert = make_certified_key("production.example.com");
        let new_cert_ptr = Arc::as_ptr(&new_cert);
        resolver.activate_production_cert(new_cert);

        let state = resolver.state.read().unwrap();
        assert!(state.production_cert.is_some());
        assert!(std::ptr::eq(
            Arc::as_ptr(state.production_cert.as_ref().unwrap()),
            new_cert_ptr
        ));
    }

    #[test]
    fn test_activate_production_cert_replaces_existing() {
        let initial = make_certified_key("old.example.com");
        let resolver = AcmeResolver::new(initial);

        let renewed = make_certified_key("new.example.com");
        let renewed_ptr = Arc::as_ptr(&renewed);
        resolver.activate_production_cert(renewed);

        let state = resolver.state.read().unwrap();
        assert!(std::ptr::eq(
            Arc::as_ptr(state.production_cert.as_ref().unwrap()),
            renewed_ptr
        ));
    }

    #[test]
    fn test_activate_production_cert_does_not_affect_challenges() {
        let resolver = AcmeResolver::without_cert();
        resolver.install_challenge("example.com", make_certified_key("challenge"));
        resolver.activate_production_cert(make_certified_key("production"));

        assert!(resolver.has_active_challenges());
        let state = resolver.state.read().unwrap();
        assert!(state.production_cert.is_some());
        assert_eq!(state.challenge_certs.len(), 1);
    }

    // ==================== Debug trait ====================

    #[test]
    fn test_debug_format() {
        let resolver = AcmeResolver::new(make_certified_key("debug.test"));
        resolver.install_challenge("a.com", make_certified_key("a.com"));
        resolver.install_challenge("b.com", make_certified_key("b.com"));

        let debug = format!("{:?}", resolver);
        assert!(debug.contains("has_production_cert: true"));
        assert!(debug.contains("active_challenges: 2"));
    }

    #[test]
    fn test_debug_format_empty() {
        let resolver = AcmeResolver::without_cert();
        let debug = format!("{:?}", resolver);
        assert!(debug.contains("has_production_cert: false"));
        assert!(debug.contains("active_challenges: 0"));
    }

    // ==================== certified_key_from_pem ====================

    #[test]
    fn test_certified_key_from_pem_valid() {
        use rcgen::{CertificateParams, DnType, KeyPair};

        let key_pair = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["test.com".to_string()]).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, "test.com");
        let cert = params.self_signed(&key_pair).unwrap();

        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        let result = certified_key_from_pem(&cert_pem, &key_pem);
        assert!(result.is_ok());
    }

    #[test]
    fn test_certified_key_from_pem_empty_cert() {
        let result = certified_key_from_pem(
            "",
            "-----BEGIN PRIVATE KEY-----\nfoo\n-----END PRIVATE KEY-----",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_certified_key_from_pem_garbage() {
        let result = certified_key_from_pem("not pem", "also not pem");
        assert!(result.is_err());
    }

    // ==================== certified_key_from_der ====================

    #[test]
    fn test_certified_key_from_der_valid() {
        use rcgen::{CertificateParams, DnType, KeyPair};

        let key_pair = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["der-test.com".to_string()]).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, "der-test.com");
        let cert = params.self_signed(&key_pair).unwrap();

        let cert_der = cert.der().as_ref();
        let key_der = key_pair.serialize_der();

        let result = certified_key_from_der(cert_der, &key_der);
        assert!(result.is_ok());
    }

    #[test]
    fn test_certified_key_from_der_invalid_key() {
        use rcgen::{CertificateParams, DnType, KeyPair};

        let key_pair = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["test.com".to_string()]).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, "test.com");
        let cert = params.self_signed(&key_pair).unwrap();

        let result = certified_key_from_der(cert.der().as_ref(), &[0xFF, 0xFF, 0xFF]);
        assert!(result.is_err());
    }

    // ==================== generate_self_signed_cert ====================

    #[test]
    fn test_generate_self_signed_cert_creates_files() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("server.crt");
        let key_path = dir.path().join("server.key");

        let result = generate_self_signed_cert(
            &["example.com".to_string(), "www.example.com".to_string()],
            cert_path.to_str().unwrap(),
            key_path.to_str().unwrap(),
        );

        assert!(result.is_ok());
        assert!(cert_path.exists());
        assert!(key_path.exists());

        let cert_pem = std::fs::read_to_string(&cert_path).unwrap();
        let key_pem = std::fs::read_to_string(&key_path).unwrap();
        assert!(cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(key_pem.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn test_generate_self_signed_cert_creates_parent_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("sub/dir/server.crt");
        let key_path = dir.path().join("sub/dir/server.key");

        let result = generate_self_signed_cert(
            &["nested.example.com".to_string()],
            cert_path.to_str().unwrap(),
            key_path.to_str().unwrap(),
        );

        assert!(result.is_ok());
        assert!(cert_path.exists());
        assert!(key_path.exists());
    }

    #[test]
    fn test_generate_self_signed_cert_empty_domains() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("server.crt");
        let key_path = dir.path().join("server.key");

        let result =
            generate_self_signed_cert(&[], cert_path.to_str().unwrap(), key_path.to_str().unwrap());

        assert!(result.is_err());
        assert!(!cert_path.exists());
    }

    #[test]
    fn test_generate_self_signed_cert_is_loadable() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("server.crt");
        let key_path = dir.path().join("server.key");

        let certified_key = generate_self_signed_cert(
            &["loadable.example.com".to_string()],
            cert_path.to_str().unwrap(),
            key_path.to_str().unwrap(),
        )
        .unwrap();

        assert!(!certified_key.cert.is_empty());

        let cert_pem = std::fs::read_to_string(&cert_path).unwrap();
        let key_pem = std::fs::read_to_string(&key_path).unwrap();
        let reloaded = certified_key_from_pem(&cert_pem, &key_pem);
        assert!(reloaded.is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn test_generate_self_signed_cert_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("server.crt");
        let key_path = dir.path().join("server.key");

        generate_self_signed_cert(
            &["perms.example.com".to_string()],
            cert_path.to_str().unwrap(),
            key_path.to_str().unwrap(),
        )
        .unwrap();

        let cert_mode = std::fs::metadata(&cert_path).unwrap().permissions().mode() & 0o777;
        let key_mode = std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(cert_mode, 0o600);
        assert_eq!(key_mode, 0o600);
    }
}
