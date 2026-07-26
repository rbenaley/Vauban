#![recursion_limit = "256"]

use std::sync::Arc;

use tokio::net::TcpListener;
use tracing::info;

use vcp::{acme, app, config, config::Config, db, perms, tls};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Config first so the default log filter can follow `environment`.
    let cfg = Config::load()?;

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                tracing_subscriber::EnvFilter::new(cfg.environment.default_log_filter())
            }),
        )
        .init();

    tls::install_crypto_provider()?;

    let database = db::connect(&cfg.database.url).await?;
    db::seed_if_empty(&database).await?;
    db::ensure_demo_catalog(&database).await?;

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
    let quiet_self_signed_rejections = cfg.environment == config::Environment::Development
        && !cfg.server.tls.acme.as_ref().is_some_and(|a| a.enabled);
    tls::serve_https(
        listener,
        tls_config,
        router,
        tls::shutdown_signal(),
        quiet_self_signed_rejections,
    )
    .await?;
    Ok(())
}
