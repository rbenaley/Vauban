//! Command line. The API key never appears here: it comes from
//! `VAUBAN_API_KEY` or `--api-key-file`.

use clap::Parser;
use secrecy::{ExposeSecret, SecretString};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "vauban-mcp")]
pub struct Cli {
    /// Bastion origin, `https://bastion.example`.
    #[arg(long)]
    pub url: String,
    /// Asset UUID.
    #[arg(long)]
    pub asset: String,
    /// Justification sent at hop 1 (10 to 1000 characters).
    #[arg(long)]
    pub justification: String,
    /// `tunnel` (default) or `direct`.
    #[arg(long, default_value = "tunnel")]
    pub transport: String,
    /// File containing the `vbn_` key. Otherwise `VAUBAN_API_KEY`.
    #[arg(long)]
    pub api_key_file: Option<PathBuf>,
}

pub fn load_api_key(file: Option<&PathBuf>) -> Result<SecretString, String> {
    if let Some(path) = file {
        let text = std::fs::read_to_string(path).map_err(|e| format!("api key file: {e}"))?;
        let key = text.trim().to_string();
        if key.is_empty() {
            return Err("api key file is empty".into());
        }
        return Ok(SecretString::from(key));
    }
    match std::env::var("VAUBAN_API_KEY") {
        Ok(key) if !key.trim().is_empty() => Ok(SecretString::from(key.trim().to_string())),
        _ => Err("set VAUBAN_API_KEY or pass --api-key-file".into()),
    }
}

pub fn key_is_secret(key: &SecretString) -> bool {
    !format!("{key:?}").contains(key.expose_secret())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attack_api_key_on_argv_is_rejected() {
        let err = Cli::try_parse_from([
            "vauban-mcp",
            "--url",
            "https://bastion.example",
            "--asset",
            "00000000-0000-0000-0000-000000000001",
            "--justification",
            "0123456789",
            "--api-key",
            "vbn_super-secret",
        ]);
        assert!(err.is_err(), "the key must not be an argv flag");
    }

    #[test]
    fn debug_does_not_print_the_key() {
        let key = SecretString::from("vbn_super-secret".to_string());
        assert!(key_is_secret(&key));
    }
}
