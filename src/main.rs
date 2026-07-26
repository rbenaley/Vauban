#![recursion_limit = "256"]

mod acme;
mod app;
mod auth;
mod config;
mod db;
mod layout;
mod models;
mod perms;
mod tls;

use std::sync::Arc;

use tokio::net::TcpListener;
use tracing::info;

use crate::config::Config;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cfg = Config::load()?;
    tls::install_crypto_provider()?;

    let database = db::connect(&cfg.database.url).await?;
    db::seed_if_empty(&database).await?;

    let policy = Arc::new(perms::PolicyStore::load_from_csv(&cfg.access.policy_path)?);
    let (tls_config, resolver) = tls::build_server_config(&cfg)?;

    if let Some(acme) = cfg.server.tls.acme.clone().filter(|a| a.enabled) {
        let cert_info = acme::extract_cert_info(&cfg.server.tls.cert_path)
            .map_err(|e| anyhow::anyhow!("cert metadata: {e}"))?;
        let cert_expiry = Arc::new(acme::CertExpiry::new(cert_info));
        acme::start_acme_monitoring(
            acme,
            cfg.server.tls.cert_path.clone(),
            cfg.server.tls.key_path.clone(),
            resolver,
            cert_expiry,
        );
    }

    let addr = (cfg.server.host.as_str(), cfg.server.port);
    let listener = TcpListener::bind(addr).await?;
    info!(
        "vcp listening on https://{}:{} ({})",
        cfg.server.host,
        cfg.server.port,
        cfg.environment.as_str()
    );

    let router = app::router(database, policy, &cfg);
    tls::serve_https(listener, tls_config, router, tls::shutdown_signal()).await?;
    Ok(())
}
