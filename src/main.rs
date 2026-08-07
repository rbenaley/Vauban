#![recursion_limit = "256"]

use std::process::ExitCode;
use std::sync::Arc;

use tokio::net::TcpListener;
use tracing::info;

use vcp::cli::{cli_usage, first_command, wants_help};
use vcp::models::{DocArticle, Issue, Release};
use vcp::{acme, app, config::Config, db, perms, tls};

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if wants_help(&args) {
        print!("{}", cli_usage());
        return Ok(());
    }

    if let Some(cmd) = first_command(&args) {
        match cmd {
            "seed-data" => return run_seed_data().await,
            other => {
                anyhow::bail!("unknown command `{other}`\n\n{}", cli_usage());
            }
        }
    }

    run_server().await
}

async fn run_seed_data() -> anyhow::Result<()> {
    let cfg = Config::load()?;
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                tracing_subscriber::EnvFilter::new(cfg.environment.default_log_filter())
            }),
        )
        .init();

    let database = db::connect(&cfg.database.url).await?;
    db::seed_demo_catalog(&database).await?;

    let mut conn = database.clone();
    let docs = DocArticle::all().exec(&mut conn).await?.len();
    let releases = Release::all().exec(&mut conn).await?.len();
    let issues = Issue::all().exec(&mut conn).await?.len();
    info!(
        docs,
        releases, issues, "seed-data complete (full demo catalog)"
    );
    println!("seed-data: docs={docs} releases={releases} issues={issues}");
    Ok(())
}

async fn run_server() -> anyhow::Result<()> {
    // Config first so the default log filter can follow `environment`.
    let cfg = Config::load()?;

    // Fail closed on a second portal instance via PID file (not listen port:
    // another app may own the port). Stale PIDs / non-`vcp` reuse are cleared.
    let _pid_guard = vcp::process_guard::acquire(&cfg.server.pid_file)?;

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                tracing_subscriber::EnvFilter::new(cfg.environment.default_log_filter())
            }),
        )
        .init();

    tls::install_crypto_provider()?;

    let database = db::connect(&cfg.database.url).await?;
    db::seed_minimal_if_empty(&database).await?;

    vcp::magic_link::start_magic_link_purge(database.clone(), cfg.magiclinks.clone());

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

    let access_log = tls::AccessLog::open(&cfg.server.access_log_path).map_err(|e| {
        anyhow::anyhow!(
            "failed to open access log {}: {e}",
            cfg.server.access_log_path
        )
    })?;

    let addr = (cfg.server.host.as_str(), cfg.server.port);
    let listener = TcpListener::bind(addr).await?;
    info!(
        "vcp listening on https://{}:{} ({})",
        cfg.server.host,
        cfg.server.port,
        cfg.environment.as_str()
    );

    let router = app::router(database, policy, &cfg);
    tls::serve_https(
        listener,
        tls_config,
        router,
        access_log,
        tls::shutdown_signal(),
    )
    .await?;
    Ok(())
}
