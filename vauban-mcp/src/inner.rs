//! HTTP/1.1 inside the leaf-terminated TLS session.
//!
//! The presented certificate is not a trust anchor. Its SPKI is hashed
//! and compared to the pin from hop 1 / the TOFU store.

use crate::pin::spki_matches;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsConnector;

pub fn spki_pin_of_cert(cert: &[u8]) -> Result<String, String> {
    let full = shared::tls_pin::spki_sha256_fingerprint(cert)?;
    Ok(full.strip_prefix("SHA256:").unwrap_or(&full).to_string())
}

pub fn client_config(expected_pin: &str) -> Result<Arc<rustls::ClientConfig>, String> {
    if !expected_pin.starts_with("SHA256:") {
        return Err("pin must be SHA256:<base64>".into());
    }
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier = Arc::new(PinVerifier {
        expected: expected_pin.to_string(),
        provider: Arc::clone(&provider),
    });
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| format!("tls13: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

#[derive(Debug)]
struct PinVerifier {
    expected: String,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let live = spki_pin_of_cert(end_entity.as_ref()).map_err(TlsError::General)?;
        if spki_matches(&self.expected, &live) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(TlsError::General("SPKI pin mismatch".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
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
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub async fn mcp_post<S>(stream: S, bearer: &str, body: &[u8]) -> Result<String, String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, connection) = http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|e| format!("http1: {e}"))?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = hyper::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("authorization", format!("Bearer {bearer}"))
        .header("content-type", "application/json")
        .header("accept", "application/json")
        .body(Full::new(Bytes::from(body.to_vec())))
        .map_err(|e| format!("request: {e}"))?;
    let response = sender
        .send_request(request)
        .await
        .map_err(|e| format!("send: {e}"))?;
    let bytes = response
        .into_body()
        .collect()
        .await
        .map_err(|e| format!("body: {e}"))?
        .to_bytes();
    String::from_utf8(bytes.to_vec()).map_err(|e| format!("utf8: {e}"))
}

pub async fn mcp_post_pinned<S>(
    stream: S,
    server_name: &str,
    pin: &str,
    bearer: &str,
    body: &[u8],
) -> Result<String, String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let name: ServerName<'static> = server_name
        .to_string()
        .try_into()
        .map_err(|e| format!("server name: {e}"))?;
    let tls = TlsConnector::from(client_config(pin)?)
        .connect(name, stream)
        .await
        .map_err(|e| format!("tls: {e}"))?;
    mcp_post(tls, bearer, body).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use std::sync::Arc;
    use tokio::io::duplex;
    use tokio::sync::Barrier;
    use tokio_rustls::TlsAcceptor;

    fn identity() -> (Vec<u8>, String, String) {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["mcp.internal".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let der = cert.der().to_vec();
        let pin = format!("SHA256:{}", spki_pin_of_cert(&der).unwrap());
        (der, key.serialize_pem(), pin)
    }

    async fn serve(io: tokio::io::DuplexStream, der: Vec<u8>, key_pem: String) {
        let key = rustls::pki_types::PrivateKeyDer::try_from(pem_der(&key_pem)).unwrap();
        let cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![CertificateDer::from(der)], key)
            .unwrap();
        let tls = TlsAcceptor::from(Arc::new(cfg)).accept(io).await.unwrap();
        let service = hyper::service::service_fn(
            |req: hyper::Request<hyper::body::Incoming>| async move {
                let bytes = req.into_body().collect().await.unwrap().to_bytes();
                let v: serde_json::Value =
                    serde_json::from_slice(&bytes).unwrap_or(serde_json::json!({}));
                let id = v.get("id").cloned().unwrap_or(serde_json::Value::Null);
                let body = serde_json::json!({"jsonrpc":"2.0","id":id,"result":{"tools":[{"name":"echo"}]}}).to_string();
                Ok::<_, std::convert::Infallible>(hyper::Response::new(Full::new(Bytes::from(
                    body,
                ))))
            },
        );
        let _ = hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(tls), service)
            .await;
    }

    fn pem_der(pem: &str) -> Vec<u8> {
        let b64: String = pem
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with("-----"))
            .collect();
        base64::engine::general_purpose::STANDARD
            .decode(b64)
            .unwrap()
    }

    #[tokio::test]
    async fn tools_list_through_pinned_tunnel_returns_200_body() {
        let (der, key, pin) = identity();
        let (client, server) = duplex(16 * 1024);
        tokio::spawn(serve(server, der, key));
        let body = mcp_post_pinned(
            client,
            "mcp.internal",
            &pin,
            "vbw_test",
            br#"{"jsonrpc":"2.0","id":7,"method":"tools/list"}"#,
        )
        .await
        .unwrap();
        assert!(body.contains("echo"), "{body}");
        assert!(body.contains("\"id\":7"), "{body}");
    }

    #[tokio::test]
    async fn attack_tunnel_spki_mismatch_is_rejected() {
        let (der, key, pin) = identity();
        let (client, server) = duplex(16 * 1024);
        tokio::spawn(serve(server, der, key));
        let err = mcp_post_pinned(
            client,
            "mcp.internal",
            "SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=",
            "vbw_test",
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
        )
        .await;
        assert!(err.is_err(), "wrong pin must fail, live pin was {pin}");
    }

    #[tokio::test]
    async fn battle_thirty_two_posts_keep_their_ids() {
        let (der, key, pin) = identity();
        let barrier = Arc::new(Barrier::new(32));
        let mut joins = Vec::new();
        for i in 0..32 {
            let barrier = Arc::clone(&barrier);
            let der = der.clone();
            let key = key.clone();
            let pin = pin.clone();
            joins.push(tokio::spawn(async move {
                barrier.wait().await;
                let (client, server) = duplex(16 * 1024);
                tokio::spawn(serve(server, der, key));
                let raw = format!("{{\"jsonrpc\":\"2.0\",\"id\":{i},\"method\":\"tools/list\"}}");
                let body =
                    mcp_post_pinned(client, "mcp.internal", &pin, "vbw_test", raw.as_bytes())
                        .await
                        .unwrap();
                assert!(body.contains(&format!("\"id\":{i}")), "{body}");
            }));
        }
        for join in joins {
            join.await.unwrap();
        }
    }
}
