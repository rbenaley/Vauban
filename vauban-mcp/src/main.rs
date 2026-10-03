//! stdio MCP shim. JSON-RPC lines arrive on stdin and leave on stdout.
//! Logs stay on stderr.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use clap::Parser;
use std::process::ExitCode;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use vauban_mcp::cli::{self, Cli};
use vauban_mcp::hop;
use vauban_mcp::session::{self, known_hosts_path};

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("{e}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), String> {
    let cli = Cli::parse();
    if cli.transport != "tunnel" && cli.transport != "direct" {
        return Err("transport must be tunnel or direct".into());
    }
    let key = cli::load_api_key(cli.api_key_file.as_ref())?;
    let http = reqwest::Client::builder()
        .use_rustls_tls()
        .build()
        .map_err(|e| format!("http client: {e}"))?;
    let hop = hop::open_session(&http, &cli.url, &key, &cli.asset, &cli.justification).await?;
    let hosts = known_hosts_path();
    let stdin = tokio::io::stdin();
    let mut lines = BufReader::new(stdin).lines();
    let mut stdout = tokio::io::stdout();
    while let Some(line) = lines.next_line().await.map_err(|e| e.to_string())? {
        if line.trim().is_empty() {
            continue;
        }
        let body = vauban_mcp::parse_line(&line).map_err(|e| format!("stdio: {e}"))?;
        let raw = body.to_string();
        let response = if cli.transport == "direct" {
            session::post_direct(&http, &hop, &raw).await
        } else {
            match session::post_tunnel(&hop, &raw, &hosts).await {
                Ok(text) => Ok(text),
                Err(first) => {
                    tracing::warn!(error = %first, "tunnel dropped, reconnecting once");
                    session::post_tunnel(&hop, &raw, &hosts).await
                }
            }
        }?;
        stdout
            .write_all(response.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        stdout.write_all(b"\n").await.map_err(|e| e.to_string())?;
        stdout.flush().await.map_err(|e| e.to_string())?;
    }
    Ok(())
}
