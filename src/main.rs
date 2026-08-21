#![recursion_limit = "256"]

use std::env;
use std::process::ExitCode;
use std::sync::Arc;

use toasty_cli::ToastyCli;
use tokio::net::TcpListener;
use tracing::info;

use vcp::cli::{cli_usage, command_tail, first_command, version_line, wants_help, wants_version};
use vcp::config::Environment;
use vcp::docs_bundle::{export_articles_to_dir, import_articles_from_dir};
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
    let args: Vec<String> = env::args().skip(1).collect();

    // Dispatch subcommands before top-level --help/--version so
    // `vcp migration --help` reaches ToastyCli.
    if let Some(cmd) = first_command(&args) {
        match cmd {
            "seed-data" => return run_seed_data().await,
            "docs" => return run_docs(&args).await,
            "migration" => return run_migration(&args).await,
            "help" => {
                print!("{}", cli_usage());
                return Ok(());
            }
            other => {
                anyhow::bail!("unknown command `{other}`\n\n{}", cli_usage());
            }
        }
    }

    if wants_help(&args) {
        print!("{}", cli_usage());
        return Ok(());
    }
    if wants_version(&args) {
        println!("{}", version_line("vcp"));
        return Ok(());
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
    let docs = DocArticle::all().count().exec(&mut conn).await?;
    let releases = Release::all().count().exec(&mut conn).await?;
    let issues = Issue::all().count().exec(&mut conn).await?;
    info!(
        docs,
        releases, issues, "seed-data complete (full demo catalog)"
    );
    println!("seed-data: docs={docs} releases={releases} issues={issues}");
    Ok(())
}

async fn run_docs(args: &[String]) -> anyhow::Result<()> {
    let tail = command_tail(args);
    let Some(sub) = tail.first().copied() else {
        anyhow::bail!("docs requires `export` or `import`\n\n{}", cli_usage());
    };
    if wants_help(args) {
        print!("{}", cli_usage());
        return Ok(());
    }
    let Some(dir) = tail.get(1).copied() else {
        anyhow::bail!("docs {sub} requires <DIR>\n\n{}", cli_usage());
    };
    let cfg = Config::load()?;
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                tracing_subscriber::EnvFilter::new(cfg.environment.default_log_filter())
            }),
        )
        .init();
    let database = db::connect(&cfg.database.url).await?;
    let path = std::path::Path::new(dir);
    match sub {
        "export" => {
            let report = export_articles_to_dir(&database, path).await?;
            info!(exported = report.exported, dir = %path.display(), "docs export complete");
            println!(
                "docs export: exported={} dir={}",
                report.exported,
                path.display()
            );
        }
        "import" => {
            let report = import_articles_from_dir(&database, path).await?;
            info!(
                created = report.created,
                updated = report.updated,
                dir = %path.display(),
                "docs import complete"
            );
            println!(
                "docs import: created={} updated={} dir={}",
                report.created,
                report.updated,
                path.display()
            );
        }
        other => {
            anyhow::bail!("unknown docs subcommand `{other}`\n\n{}", cli_usage());
        }
    }
    Ok(())
}

/// Toasty migrations with development as the default env (same as the
/// former standalone migrations binary).
async fn run_migration(args: &[String]) -> anyhow::Result<()> {
    // Resolve Toasty.toml / toasty/ via Config::package_root (VCP_PACKAGE_ROOT,
    // parent of VCP_CONFIG_DIR, or /usr/local/share/vcp) — not CWD / compile paths.
    let root = Config::package_root()?;
    env::set_current_dir(&root)?;

    let toasty_cfg = toasty_cli::Config::load()?;
    let environment = env::var("VCP_ENVIRONMENT")
        .map(|v| Environment::parse(&v))
        .unwrap_or(Environment::Development);
    let app = Config::load_with_environment(Config::find_config_dir()?, environment)?;
    let database = db::open(&app.database.url).await?;

    let mut argv = Vec::with_capacity(args.len() + 1);
    argv.push("vcp".to_owned());
    argv.extend(args.iter().cloned());
    ToastyCli::with_config(database, toasty_cfg)
        .parse_from(argv)
        .await?;
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
    vcp::issue_notify::start_issue_notify_drain(database.clone(), cfg.issues.notify.clone());

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
    // newsyslog sends SIGHUP to process_guard pid (/var/run/vcp/vcp.pid).
    tls::spawn_reopen_on_hangup(access_log.clone());

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
