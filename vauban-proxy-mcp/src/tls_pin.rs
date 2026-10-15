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

//! TLS SPKI pinning for MCP upstream (same trust model as RDP VAU-001).
//!
//! Pin format: `SHA256:<standard-base64>` of the full SubjectPublicKeyInfo DER
//! (algorithm + public key). Fail-closed on mismatch / missing pin when TLS
//! is required.

use std::sync::Arc;

use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::pki_types;
use tracing::debug;

/// Build a rustls client config that pins the server SPKI fingerprint.
pub fn build_tls_config(expected_fingerprint: &str) -> Result<Arc<rustls::ClientConfig>, String> {
    let pin = expected_fingerprint.trim();
    if pin.is_empty() || !pin.starts_with("SHA256:") {
        return Err(
            "MCP TLS pin must be SHA256:<base64> (same format as RDP server cert fingerprint)"
                .into(),
        );
    }
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier = Arc::new(PinningServerCertVerifier {
        expected_fingerprint: pin.to_string(),
        provider: Arc::clone(&provider),
    });

    let mut config = rustls::client::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS provider init failed: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    config.resumption = rustls::client::Resumption::disabled();
    Ok(Arc::new(config))
}

/// Upgrade a brokered TCP FD to TLS with SPKI pin (10 s handshake timeout).
pub async fn connect_pinned(
    tcp: TcpStream,
    host: &str,
    expected_fingerprint: &str,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, String> {
    let server_name: pki_types::ServerName<'static> = host
        .trim()
        .to_string()
        .try_into()
        .map_err(|e| format!("invalid TLS server name {host}: {e}"))?;

    let tls_config = build_tls_config(expected_fingerprint)?;
    let connector = TlsConnector::from(tls_config);
    debug!(host = %host, "MCP upstream TLS handshake with SPKI pin");
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        connector.connect(server_name, tcp),
    )
    .await
    .map_err(|_| "MCP upstream TLS handshake timed out after 10s".to_string())?
    .map_err(|e| format!("MCP upstream TLS failed: {e}"))
}

/// SHA256:<base64> of full SPKI DER.
pub fn spki_sha256_fingerprint(cert: &pki_types::CertificateDer<'_>) -> Result<String, String> {
    shared::tls_pin::spki_sha256_fingerprint(cert.as_ref())
}

#[derive(Debug)]
struct PinningServerCertVerifier {
    expected_fingerprint: String,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for PinningServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &pki_types::CertificateDer<'_>,
        _intermediates: &[pki_types::CertificateDer<'_>],
        _server_name: &pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: pki_types::UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let live = spki_sha256_fingerprint(end_entity)
            .map_err(|e| rustls::Error::General(format!("SPKI extraction failed: {e}")))?;

        if shared::tls_pin::pins_match(&self.expected_fingerprint, &live) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "MCP upstream certificate mismatch - possible MITM. \
                 Expected pinned SPKI {expected}, server presented {live}. \
                 An admin must re-fetch and pin the new certificate.",
                expected = self.expected_fingerprint,
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    #[test]
    fn pin_format_rejected_when_empty() {
        assert!(build_tls_config("").is_err());
        assert!(build_tls_config("not-sha256").is_err());
    }

    #[test]
    fn pin_format_accepted_shape() {
        // Valid shape (will not handshake here — just ClientConfig build).
        let pin = format!(
            "SHA256:{}",
            base64::engine::general_purpose::STANDARD.encode([0u8; 32])
        );
        assert!(build_tls_config(&pin).is_ok());
    }

    #[tokio::test]
    async fn tls12_upstream_is_pinned_too() {
        use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .unwrap()
            .self_signed(&key_pair)
            .unwrap();
        let cert_der = pki_types::CertificateDer::from(cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
        let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS12])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let _ = acceptor.accept(tcp).await;
            }
        });

        let pin = spki_sha256_fingerprint(&cert_der).unwrap();
        let tls = connect_pinned(TcpStream::connect(addr).await.unwrap(), "localhost", &pin)
            .await
            .unwrap();
        assert_eq!(
            tls.get_ref().1.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_2)
        );

        let wrong = format!(
            "SHA256:{}",
            base64::engine::general_purpose::STANDARD.encode([0u8; 32])
        );
        let err = connect_pinned(TcpStream::connect(addr).await.unwrap(), "localhost", &wrong)
            .await
            .unwrap_err();
        assert!(err.contains("mismatch"), "{err}");
    }

    /// A certificate whose SPKI is not the asset pin is refused. The verifier
    /// compares that fingerprint only; expiry and the name are not a second PKI.
    #[tokio::test]
    async fn attack_wrong_spki_pin_is_rejected() {
        use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .unwrap()
            .self_signed(&key_pair)
            .unwrap();
        let cert_der = pki_types::CertificateDer::from(cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
        let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS12])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let _ = acceptor.accept(tcp).await;
            }
        });
        let wrong = format!(
            "SHA256:{}",
            base64::engine::general_purpose::STANDARD.encode([9u8; 32])
        );
        let err = connect_pinned(TcpStream::connect(addr).await.unwrap(), "localhost", &wrong)
            .await
            .unwrap_err();
        assert!(err.contains("mismatch"), "{err}");
    }
}
