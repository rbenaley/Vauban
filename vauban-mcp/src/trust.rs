//! Trust anchors for the bastion itself (hop 1, direct hop 2, tunnel
//! WebSocket): the public web roots, plus the CA certificates of
//! `--ca-file` for a bastion behind a private PKI. The inner pinned TLS
//! to the asset (see `inner`) never uses these.

use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use std::path::Path;
use std::sync::Arc;

pub fn load_ca_file(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let certs = CertificateDer::pem_file_iter(path)
        .map_err(|e| format!("ca file: {e}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("ca file: {e}"))?;
    if certs.is_empty() {
        return Err("ca file holds no certificate".into());
    }
    Ok(certs)
}

pub fn roots(extra: &[CertificateDer<'static>]) -> Result<rustls::RootCertStore, String> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for cert in extra {
        roots
            .add(cert.clone())
            .map_err(|e| format!("ca file: {e}"))?;
    }
    Ok(roots)
}

pub fn client_config(
    extra: &[CertificateDer<'static>],
) -> Result<Arc<rustls::ClientConfig>, String> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("tls: {e}"))?
        .with_root_certificates(roots(extra)?)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_file(name: &str, text: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("vauban-mcp-{}-{name}", std::process::id()));
        std::fs::write(&p, text).unwrap();
        p
    }

    #[test]
    fn ca_file_adds_one_anchor_to_the_web_roots() {
        let ca = rcgen::generate_simple_self_signed(vec!["ca.example".into()]).unwrap();
        let path = temp_file("ca.pem", &ca.cert.pem());
        let certs = load_ca_file(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(certs.len(), 1);
        assert_eq!(roots(&certs).unwrap().len(), roots(&[]).unwrap().len() + 1);
        assert!(client_config(&certs).is_ok());
    }

    #[test]
    fn empty_or_missing_ca_file_is_refused() {
        let path = temp_file("empty.pem", "not a certificate\n");
        assert!(load_ca_file(&path).is_err());
        let _ = std::fs::remove_file(&path);
        assert!(load_ca_file(Path::new("/nonexistent/vauban-ca.pem")).is_err());
    }
}
