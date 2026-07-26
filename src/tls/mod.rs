//! TLS 1.3 edge (rustls) and certificate bootstrap.

mod access_log;
mod resolver;
mod serve;

pub use access_log::{AccessLog, format_common_log};
pub use resolver::{
    AcmeResolver, certified_key_from_der, certified_key_from_pem, generate_self_signed_cert,
};
pub use serve::{
    HANDSHAKE_LOG_IDLE, HandshakeCapture, HandshakeFailureLog, note_handshake_failure, serve_https,
    shutdown_signal,
};

use std::sync::Arc;

use rustls::ServerConfig;
use rustls::sign::CertifiedKey;
use tracing::info;

use crate::config::Config;

const ALPN_H2: &[u8] = b"h2";
const ALPN_HTTP11: &[u8] = b"http/1.1";
const ALPN_ACME: &[u8] = b"acme-tls/1";

/// Install the aws-lc rustls crypto provider (once per process).
pub fn install_crypto_provider() -> anyhow::Result<()> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("failed to install aws-lc rustls crypto provider"))?;
    Ok(())
}

/// Load or bootstrap production certs and build a TLS 1.3-only `ServerConfig`.
pub fn build_server_config(cfg: &Config) -> anyhow::Result<(Arc<ServerConfig>, Arc<AcmeResolver>)> {
    let cert_path = &cfg.server.tls.cert_path;
    let key_path = &cfg.server.tls.key_path;
    let acme_enabled = cfg.server.tls.acme.as_ref().is_some_and(|a| a.enabled);

    let certified =
        if std::path::Path::new(cert_path).exists() && std::path::Path::new(key_path).exists() {
            load_pem_files(cert_path, key_path, cfg.server.tls.ca_chain_path.as_deref())?
        } else {
            let domains = cfg.bootstrap_domains();
            info!(
                ?domains,
                cert_path, key_path, "Bootstrapping self-signed TLS certificate"
            );
            generate_self_signed_cert(&domains, cert_path, key_path)
                .map_err(|e| anyhow::anyhow!("self-signed cert bootstrap failed: {e}"))?
        };

    let resolver = Arc::new(AcmeResolver::new(Arc::new(certified)));
    let mut server_config =
        ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_cert_resolver(resolver.clone());

    let mut alpn = vec![ALPN_H2.to_vec(), ALPN_HTTP11.to_vec()];
    if acme_enabled {
        alpn.push(ALPN_ACME.to_vec());
    }
    server_config.alpn_protocols = alpn;

    Ok((Arc::new(server_config), resolver))
}

fn load_pem_files(
    cert_path: &str,
    key_path: &str,
    ca_chain_path: Option<&str>,
) -> anyhow::Result<CertifiedKey> {
    let mut cert_pem = std::fs::read_to_string(cert_path)
        .map_err(|e| anyhow::anyhow!("read cert {cert_path}: {e}"))?;
    if let Some(chain_path) = ca_chain_path {
        let chain = std::fs::read_to_string(chain_path)
            .map_err(|e| anyhow::anyhow!("read ca chain {chain_path}: {e}"))?;
        cert_pem.push('\n');
        cert_pem.push_str(&chain);
    }
    let key_pem = std::fs::read_to_string(key_path)
        .map_err(|e| anyhow::anyhow!("read key {key_path}: {e}"))?;
    certified_key_from_pem(&cert_pem, &key_pem).map_err(|e| anyhow::anyhow!("parse TLS PEM: {e}"))
}
