//! The shim against a fake bastion that answers hop 1 with a hop-2 URL
//! on another host. The shim refuses and the stored pin is unchanged.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use secrecy::SecretString;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use vauban_mcp::{hop, session, tofu};

const FAKE_SPKI: &str = "SHA256:attackerattackerattackerattackerattacker000=";

struct FakeBastion {
    url: String,
    root: reqwest::Certificate,
}

/// `hop2_url = None` answers with the bastion's own origin.
async fn fake_bastion(hop2_url: Option<&'static str>) -> FakeBastion {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let der = cert.der().to_vec();
    let key_der = rustls::pki_types::PrivateKeyDer::try_from(key.serialize_der()).unwrap();
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(der.clone())],
            key_der,
        )
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let hop2_url: Arc<str> = hop2_url
        .map(str::to_string)
        .unwrap_or_else(|| format!("https://LOCALHOST.:{port}/mcp"))
        .into();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let hop2_url = Arc::clone(&hop2_url);
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let service = hyper::service::service_fn(move |_req| {
                    let hop2_url = Arc::clone(&hop2_url);
                    async move {
                        let body = serde_json::json!({
                            "url": hop2_url.as_ref(),
                            "bearer": "vbw_fake",
                            "transport": "tunnel",
                            "tunnel_spki": FAKE_SPKI,
                        })
                        .to_string();
                        Ok::<_, std::convert::Infallible>(hyper::Response::new(Full::new(
                            Bytes::from(body),
                        )))
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), service)
                    .await;
            });
        }
    });
    FakeBastion {
        url: format!("https://localhost:{port}"),
        root: reqwest::Certificate::from_der(&der).unwrap(),
    }
}

fn client(root: reqwest::Certificate) -> reqwest::Client {
    reqwest::Client::builder()
        .use_rustls_tls()
        .add_root_certificate(root)
        .build()
        .unwrap()
}

#[tokio::test]
async fn attack_fake_bastion_host_substitution_is_refused_and_pin_kept() {
    let bastion = fake_bastion(Some("https://evil.example/mcp")).await;
    let dir = std::env::temp_dir().join(format!("vauban-mcp-e2e-{}", std::process::id()));
    let hosts = dir.join("known_mcp_hosts");
    let origin = tofu::origin_key(&bastion.url).unwrap();
    session::accept_pin(
        &origin,
        "SHA256:goodgoodgoodgoodgoodgoodgoodgoodgoodgood000=",
        &hosts,
    )
    .unwrap();
    let before = std::fs::read_to_string(&hosts).unwrap();

    let http = client(bastion.root);
    let key = SecretString::from("vbn_test".to_string());
    let err = hop::open_session(&http, &bastion.url, &key, "asset", "justification ok")
        .await
        .expect_err("a hop-2 url on another host must be refused");
    assert!(err.contains("not on --url origin"), "{err}");
    assert_eq!(std::fs::read_to_string(&hosts).unwrap(), before);
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn same_origin_hop1_in_another_case_is_accepted() {
    let bastion = fake_bastion(None).await;
    let http = client(bastion.root);
    let key = SecretString::from("vbn_test".to_string());
    let hop = hop::open_session(&http, &bastion.url, &key, "asset", "justification ok")
        .await
        .unwrap();
    assert_eq!(
        tofu::origin_key(&hop.url).unwrap(),
        tofu::origin_key(&bastion.url).unwrap()
    );
}

#[tokio::test]
async fn attack_fake_bastion_port_substitution_is_refused() {
    let bastion = fake_bastion(Some("https://localhost:1/mcp")).await;
    let http = client(bastion.root);
    let key = SecretString::from("vbn_test".to_string());
    assert!(
        hop::open_session(&http, &bastion.url, &key, "asset", "justification ok")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn attack_plain_http_cli_url_is_refused_before_any_request() {
    let http = reqwest::Client::new();
    let key = SecretString::from("vbn_test".to_string());
    let err = hop::open_session(
        &http,
        "http://127.0.0.1:9",
        &key,
        "asset",
        "justification ok",
    )
    .await
    .expect_err("http:// must be refused");
    assert!(err.contains("refused"), "{err}");
}

fn legacy_store(name: &str, line: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("vauban-mcp-e2e-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let hosts = dir.join("known_mcp_hosts");
    std::fs::write(&hosts, line).unwrap();
    (dir, hosts)
}

/// A 0.9.45 file keyed the pin by bare host. The same pin from the same
/// bastion moves to `localhost:<port>`; the old line is gone.
#[tokio::test]
async fn legacy_host_line_migrates_to_the_origin_on_the_same_pin() {
    let bastion = fake_bastion(None).await;
    let (dir, hosts) = legacy_store("migrate", &format!("localhost {FAKE_SPKI}\n"));
    let origin = tofu::origin_key(&bastion.url).unwrap();
    let http = client(bastion.root);
    let key = SecretString::from("vbn_test".to_string());
    let hop = hop::open_session(&http, &bastion.url, &key, "asset", "justification ok")
        .await
        .unwrap();
    let outcome = session::post_tunnel(&hop, &origin, "{}", &hosts).await;
    if let Err(e) = &outcome {
        assert!(!e.contains("refusing"), "the pin must be accepted: {e}");
    }
    assert_eq!(
        std::fs::read_to_string(&hosts).unwrap(),
        format!("{origin} {FAKE_SPKI}\n")
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn attack_legacy_host_line_refuses_a_different_pin_end_to_end() {
    let bastion = fake_bastion(None).await;
    let before = "localhost SHA256:goodgoodgoodgoodgoodgoodgoodgoodgoodgood000=\n";
    let (dir, hosts) = legacy_store("legacy-attack", before);
    let origin = tofu::origin_key(&bastion.url).unwrap();
    let http = client(bastion.root);
    let key = SecretString::from("vbn_test".to_string());
    let hop = hop::open_session(&http, &bastion.url, &key, "asset", "justification ok")
        .await
        .unwrap();
    let err = session::post_tunnel(&hop, &origin, "{}", &hosts)
        .await
        .expect_err("a pin that differs from the legacy line must be refused");
    assert!(err.contains("legacy line `localhost`"), "{err}");
    assert_eq!(std::fs::read_to_string(&hosts).unwrap(), before);
    let _ = std::fs::remove_dir_all(dir);
}
