//! Synchronous rustls glue for the LDAPS bind.
//!
//! `vauban-auth` receives a TCP socket already `connect()`-ed by the
//! supervisor (SCM_RIGHTS), then terminates TLS itself so the plaintext
//! password never transits the root TCB. We use rustls' blocking
//! [`rustls::Stream`] over the raw socket -- no tokio.

use std::io::{self, Read, Write};
use std::sync::Arc;

use rustls::{ClientConfig, ClientConnection, RootCertStore};
use rustls_pki_types::ServerName;

use crate::ldap;

/// Build a synchronous rustls [`ClientConfig`] that trusts ONLY the supplied
/// CA bundle (PEM). The directory's certificate chain is validated against
/// this anchor; the public webpki roots are intentionally NOT trusted (an
/// internal AD/LDAPS CA is the norm).
///
/// Uses the aws-lc-rs crypto provider (matching every other TLS user in the
/// workspace) and TLS 1.2 + 1.3, with no client authentication.
pub fn build_client_config(ca_pem: &str) -> anyhow::Result<Arc<ClientConfig>> {
    let mut reader = io::BufReader::new(ca_pem.as_bytes());
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("failed to parse LDAP CA PEM: {e}"))?;
    if certs.is_empty() {
        anyhow::bail!("LDAP CA PEM contained no certificates");
    }

    let mut roots = RootCertStore::empty();
    let (added, _ignored) = roots.add_parsable_certificates(certs);
    if added == 0 {
        anyhow::bail!("no usable certificates in LDAP CA PEM");
    }

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| anyhow::anyhow!("rustls provider lacks safe TLS versions: {e}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// Wrap `sock` in TLS (validating the chain against `config`, using
/// `server_name` for SNI and hostname verification), then perform an LDAP
/// simple bind. Returns the LDAP `resultCode`.
///
/// All TLS/handshake/IO failures surface as `io::Error` so the caller can map
/// them to a transport outcome (`TlsError` / `Unreachable`) distinct from a
/// credential rejection.
pub fn simple_bind_over_tls<S: Read + Write>(
    config: Arc<ClientConfig>,
    server_name: &str,
    sock: &mut S,
    dn: &str,
    password: &[u8],
) -> io::Result<i64> {
    let name = ServerName::try_from(server_name.to_string())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid TLS server name"))?;
    let mut conn = ClientConnection::new(config, name)
        .map_err(|e| io::Error::other(format!("rustls client init failed: {e}")))?;
    let mut tls = rustls::Stream::new(&mut conn, sock);
    ldap::simple_bind_on_stream(&mut tls, dn, password)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_client_config_rejects_empty_pem() {
        assert!(build_client_config("").is_err());
        assert!(build_client_config("not a certificate").is_err());
    }
}
