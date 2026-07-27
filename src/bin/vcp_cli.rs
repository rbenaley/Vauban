//! Toasty schema CLI for VCP (`migration generate|apply|…`).
//!
//! Usage (from package root):
//!   cargo run --bin vcp-cli -- migration generate --name describe_change
//!   cargo run --bin vcp-cli -- migration apply
//!
//! Database URL follows the same TOML layering as the portal. When
//! `VCP_ENVIRONMENT` is unset, defaults to **development** (unlike the
//! `vcp` server binary, which defaults to production).

use std::env;
use std::path::PathBuf;

use toasty_cli::{Config, ToastyCli};
use vcp::config::{Config as AppConfig, Environment};
use vcp::db;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Resolve Toasty.toml / toasty/ relative to the package, not the caller's CWD.
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    env::set_current_dir(&root)?;

    let config = Config::load()?;
    let environment = env::var("VCP_ENVIRONMENT")
        .map(|v| Environment::parse(&v))
        .unwrap_or(Environment::Development);
    let app = AppConfig::load_with_environment(AppConfig::find_config_dir()?, environment)?;
    let db = db::open(&app.database.url).await?;

    ToastyCli::with_config(db, config).parse_and_run().await?;
    Ok(())
}
