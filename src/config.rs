//! TOML configuration (Vauban-style layering).
//!
//! Lookup order for the config directory:
//! 1. `VCP_CONFIG_DIR` (must exist)
//! 2. `{CARGO_MANIFEST_DIR}/config` (development checkout)
//! 3. `/usr/local/etc/vcp` (production install)
//!
//! Loading:
//! - Production: `vcp.conf` only (self-contained)
//! - Development: `default.toml` + `development.toml` + optional `local.toml`
//! - Testing: `default.toml` + `testing.toml` (no `local.toml`)
//!
//! Environment selection: `VCP_ENVIRONMENT` (`development` / `testing` /
//! `production`). When unset, defaults to **production** (same as Vauban).

use std::path::{Path, PathBuf};

use config::{Config as ConfigBuilder, File};
use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Environment {
    Development,
    Testing,
    Production,
}

impl Environment {
    pub fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "development" | "dev" => Self::Development,
            "testing" | "test" => Self::Testing,
            _ => Self::Production,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Development => "development",
            Self::Testing => "testing",
            Self::Production => "production",
        }
    }

    pub const fn is_production(self) -> bool {
        matches!(self, Self::Production)
    }

    /// Default `RUST_LOG` filter when the env var is unset.
    pub const fn default_log_filter(self) -> &'static str {
        match self {
            Self::Development => "debug",
            Self::Testing | Self::Production => "info",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default = "default_environment")]
    pub environment: Environment,

    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub access: AccessConfig,

    pub mail: MailConfig,

    pub magiclinks: MagicLinksConfig,

    #[serde(default)]
    pub login: LoginConfig,

    #[serde(default)]
    pub org: OrgConfig,
}

/// SMTP submission settings (`[mail]`).
#[derive(Debug, Clone, Deserialize)]
pub struct MailConfig {
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_encryption: SmtpEncryption,
    #[serde(default)]
    pub smtp_username: String,
    #[serde(default)]
    pub smtp_password: String,
}

/// SMTP encryption mode for [`MailConfig::smtp_encryption`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SmtpEncryption {
    Plaintext,
    Starttls,
    Tls,
}

impl SmtpEncryption {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Plaintext => "plaintext",
            Self::Starttls => "starttls",
            Self::Tls => "tls",
        }
    }

    /// Parse a config / proptest corpus string.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "plaintext" => Some(Self::Plaintext),
            "starttls" => Some(Self::Starttls),
            "tls" => Some(Self::Tls),
            _ => None,
        }
    }
}

/// Magic-link identity and TTL (`[magiclinks]`).
#[derive(Debug, Clone, Deserialize)]
pub struct MagicLinksConfig {
    pub from_address: String,
    pub from_name: String,
    #[serde(default)]
    pub reply_to: String,
    /// Staff email: JIT `portal_role=admin`, Casbin `role:admin`.
    pub vcp_admin: String,
    #[serde(default = "default_token_ttl_secs")]
    pub token_ttl_secs: u64,
    /// Keep rows this many days after `expires_at` before purge (0 = purge when expired).
    #[serde(default = "default_token_retention_days")]
    pub token_retention_days: u64,
    /// Background purge tick interval.
    #[serde(default = "default_purge_interval_minutes")]
    pub purge_interval_minutes: u64,
}

fn default_token_ttl_secs() -> u64 {
    300
}

fn default_token_retention_days() -> u64 {
    1
}

fn default_purge_interval_minutes() -> u64 {
    60
}

impl MagicLinksConfig {
    /// Normalized admin email (trim + lowercase).
    pub fn vcp_admin_email(&self) -> String {
        self.vcp_admin.trim().to_ascii_lowercase()
    }

    /// Retention window in seconds (`token_retention_days * 86400`).
    pub fn retention_secs(&self) -> u64 {
        self.token_retention_days.saturating_mul(86_400)
    }

    /// Purge loop interval as a [`std::time::Duration`].
    pub fn purge_interval_duration(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.purge_interval_minutes.saturating_mul(60))
    }
}

fn default_environment() -> Environment {
    Environment::Production
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,

    /// Trusted browser origins for session CSRF / Origin checks (HTTPS only).
    ///
    /// The first entry is also the primary host for absolute customer URLs
    /// (ephemeral download links, etc.).
    #[serde(default)]
    pub public_origins: Vec<String>,

    /// Apache Common Log Format access log path.
    ///
    /// Production default: `/var/log/vcp-access.log`. Non-production: under
    /// the crate `logs/` directory (gitignored).
    pub access_log_path: String,

    pub tls: TlsConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
    #[serde(default)]
    pub ca_chain_path: Option<String>,
    #[serde(default)]
    pub acme: Option<AcmeConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AcmeConfig {
    pub enabled: bool,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default = "default_renew_before_hours")]
    pub renew_before_hours: u32,
    #[serde(default)]
    pub account_key_path: String,
    #[serde(default)]
    pub staging: bool,
    #[serde(default)]
    pub directory_url: String,
    #[serde(default)]
    pub staging_directory_url: String,
    #[serde(default)]
    pub eab_kid: Option<String>,
    #[serde(default)]
    pub eab_hmac_key: Option<String>,
}

fn default_renew_before_hours() -> u32 {
    24
}

impl AcmeConfig {
    pub fn resolve_directory_url(&self) -> anyhow::Result<String> {
        if self.staging && !self.staging_directory_url.is_empty() {
            return Ok(self.staging_directory_url.clone());
        }
        if self.directory_url.is_empty() {
            anyhow::bail!("ACME directory_url must be set when ACME is enabled");
        }
        Ok(self.directory_url.clone())
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if !self.enabled {
            return Ok(());
        }
        if self.email.is_empty() {
            anyhow::bail!("ACME email is required when ACME is enabled");
        }
        if self.domains.is_empty() {
            anyhow::bail!("ACME domains list cannot be empty when ACME is enabled");
        }
        if self.account_key_path.is_empty() {
            anyhow::bail!("ACME account_key_path is required when ACME is enabled");
        }
        self.resolve_directory_url()?;
        if self.eab_kid.is_some() != self.eab_hmac_key.is_some() {
            anyhow::bail!("eab_kid and eab_hmac_key must both be set or both be absent");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AccessConfig {
    pub model_path: String,
    pub policy_path: String,
}

/// Login anti-enumeration / brute-force controls.
#[derive(Debug, Clone, Deserialize)]
pub struct LoginConfig {
    #[serde(default = "default_login_max_attempts")]
    pub max_attempts: u32,
    #[serde(default = "default_login_window_secs")]
    pub window_secs: u64,
    #[serde(default = "default_login_lockout_secs")]
    pub lockout_secs: u64,
}

impl Default for LoginConfig {
    fn default() -> Self {
        Self {
            max_attempts: default_login_max_attempts(),
            window_secs: default_login_window_secs(),
            lockout_secs: default_login_lockout_secs(),
        }
    }
}

fn default_login_max_attempts() -> u32 {
    10
}

fn default_login_window_secs() -> u64 {
    300
}

fn default_login_lockout_secs() -> u64 {
    900
}

/// Organization / tenant provisioning limits.
#[derive(Debug, Clone, Deserialize)]
pub struct OrgConfig {
    /// Max portal user accounts (memberships) per client company.
    #[serde(default = "default_max_accounts_per_org")]
    pub max_accounts_per_org: usize,
    /// Max value for LTS / Industrial LTS subscription steppers (0..=N).
    #[serde(default = "default_max_lts_subscriptions")]
    pub max_lts_subscriptions: usize,
}

impl Default for OrgConfig {
    fn default() -> Self {
        Self {
            max_accounts_per_org: default_max_accounts_per_org(),
            max_lts_subscriptions: default_max_lts_subscriptions(),
        }
    }
}

fn default_max_accounts_per_org() -> usize {
    crate::models::MAX_USERS_PER_COMPANY
}

fn default_max_lts_subscriptions() -> usize {
    crate::models::MAX_LTS_SUBSCRIPTIONS_DEFAULT
}

impl Config {
    /// Load using auto-discovered config directory and `VCP_ENVIRONMENT`.
    pub fn load() -> anyhow::Result<Self> {
        let dir = Self::find_config_dir()?;
        let environment = std::env::var("VCP_ENVIRONMENT")
            .map(|e| Environment::parse(&e))
            .unwrap_or(Environment::Production);
        Self::load_with_environment(dir, environment)
    }

    pub fn load_with_environment(
        config_path: impl AsRef<Path>,
        environment: Environment,
    ) -> anyhow::Result<Self> {
        let config_path = config_path.as_ref();
        let mut builder = ConfigBuilder::builder();

        if environment.is_production() {
            let conf_path = config_path.join("vcp.conf");
            let contents = std::fs::read_to_string(&conf_path)
                .map_err(|e| anyhow::anyhow!("failed to read {}: {e}", conf_path.display()))?;
            builder =
                builder.add_source(config::File::from_str(&contents, config::FileFormat::Toml));
        } else {
            let default_path = config_path.join("default.toml");
            if default_path.exists() {
                builder = builder.add_source(File::from(default_path));
            }

            let env_path = config_path.join(format!("{}.toml", environment.as_str()));
            if env_path.exists() {
                builder = builder.add_source(File::from(env_path));
            }

            if environment != Environment::Testing {
                let local_path = config_path.join("local.toml");
                if local_path.exists() {
                    builder = builder.add_source(File::from(local_path));
                }
            }
        }

        let mut cfg: Config = builder
            .build()
            .map_err(|e| anyhow::anyhow!("config build failed: {e}"))?
            .try_deserialize()
            .map_err(|e| anyhow::anyhow!("config deserialize failed: {e}"))?;

        cfg.environment = environment;
        cfg.resolve_paths();
        cfg.validate()?;
        Ok(cfg)
    }

    /// Resolve the config directory (same search order as [`Config::load`]).
    pub fn find_config_dir() -> anyhow::Result<PathBuf> {
        if let Ok(path) = std::env::var("VCP_CONFIG_DIR") {
            let config_path = PathBuf::from(&path);
            if config_path.exists() {
                return Ok(config_path);
            }
            anyhow::bail!("VCP_CONFIG_DIR points to a missing directory: {path}");
        }

        let crate_config = Path::new(env!("CARGO_MANIFEST_DIR")).join("config");
        if crate_config.exists() {
            return Ok(crate_config);
        }

        let system_config = Path::new("/usr/local/etc/vcp");
        if system_config.exists() {
            return Ok(system_config.to_path_buf());
        }

        anyhow::bail!(
            "configuration directory not found. Searched:\n\
             - VCP_CONFIG_DIR\n\
             - {{CARGO_MANIFEST_DIR}}/config\n\
             - /usr/local/etc/vcp"
        );
    }

    fn resolve_paths(&mut self) {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        self.access.model_path = resolve_path(root, &self.access.model_path);
        self.access.policy_path = resolve_path(root, &self.access.policy_path);
        self.server.access_log_path = resolve_path(root, &self.server.access_log_path);
        self.server.tls.cert_path = resolve_path(root, &self.server.tls.cert_path);
        self.server.tls.key_path = resolve_path(root, &self.server.tls.key_path);
        if let Some(ref chain) = self.server.tls.ca_chain_path {
            self.server.tls.ca_chain_path = Some(resolve_path(root, chain));
        }
        if let Some(ref mut acme) = self.server.tls.acme
            && !acme.account_key_path.is_empty()
        {
            acme.account_key_path = resolve_path(root, &acme.account_key_path);
        }
    }

    fn validate(&self) -> anyhow::Result<()> {
        if self.server.host.trim().is_empty() {
            anyhow::bail!("server.host must not be empty");
        }
        if self.server.port == 0 {
            anyhow::bail!("server.port must be non-zero");
        }
        if self.database.url.trim().is_empty() {
            anyhow::bail!("database.url must not be empty");
        }
        if self.access.policy_path.trim().is_empty() {
            anyhow::bail!("access.policy_path must not be empty");
        }
        if self.server.access_log_path.trim().is_empty() {
            anyhow::bail!("server.access_log_path must not be empty");
        }
        if self.server.tls.cert_path.trim().is_empty() || self.server.tls.key_path.trim().is_empty()
        {
            anyhow::bail!("server.tls.cert_path and key_path are required");
        }
        if self.server.public_origins.is_empty() {
            anyhow::bail!("server.public_origins must contain at least one HTTPS origin");
        }
        for origin in &self.server.public_origins {
            if origin.starts_with("http://") {
                anyhow::bail!(
                    "public_origins must be HTTPS only (got {origin}); cleartext HTTP is forbidden"
                );
            }
            if !origin.starts_with("https://") {
                anyhow::bail!("public_origins entry must start with https:// (got {origin})");
            }
        }
        if let Some(acme) = &self.server.tls.acme {
            acme.validate()?;
        }
        self.validate_mail()?;
        self.validate_magiclinks()?;
        Ok(())
    }

    fn validate_mail(&self) -> anyhow::Result<()> {
        if self.mail.smtp_host.trim().is_empty() {
            anyhow::bail!("mail.smtp_host must not be empty");
        }
        if self.mail.smtp_port == 0 {
            anyhow::bail!("mail.smtp_port must be non-zero");
        }
        if self.environment.is_production()
            && self.mail.smtp_encryption == SmtpEncryption::Plaintext
        {
            anyhow::bail!("mail.smtp_encryption=plaintext is forbidden in production");
        }
        Ok(())
    }

    fn validate_magiclinks(&self) -> anyhow::Result<()> {
        if self.magiclinks.from_address.trim().is_empty() {
            anyhow::bail!("magiclinks.from_address must not be empty");
        }
        if self.magiclinks.vcp_admin.trim().is_empty() {
            anyhow::bail!("magiclinks.vcp_admin must not be empty");
        }
        if self.magiclinks.token_ttl_secs == 0 {
            anyhow::bail!("magiclinks.token_ttl_secs must be greater than zero");
        }
        if self.magiclinks.purge_interval_minutes == 0 {
            anyhow::bail!("magiclinks.purge_interval_minutes must be greater than zero");
        }
        Ok(())
    }

    /// Primary public origin (first `server.public_origins` entry).
    ///
    /// Used for customer-facing absolute URLs (ephemeral download links, etc.).
    pub fn primary_public_origin(&self) -> &str {
        self.server
            .public_origins
            .first()
            .map(String::as_str)
            .expect("server.public_origins validated non-empty")
    }

    /// Domains used for bootstrap self-signed certificates.
    pub fn bootstrap_domains(&self) -> Vec<String> {
        if let Some(acme) = &self.server.tls.acme
            && acme.enabled
            && !acme.domains.is_empty()
        {
            return acme.domains.clone();
        }
        vec!["localhost".to_owned(), "127.0.0.1".to_owned()]
    }
}

fn resolve_path(root: &Path, path: &str) -> String {
    if path.starts_with('/') {
        path.to_owned()
    } else {
        root.join(path).to_string_lossy().into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_development_layering() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("config");
        let cfg = Config::load_with_environment(&dir, Environment::Development).unwrap();
        assert_eq!(cfg.environment, Environment::Development);
        assert_eq!(cfg.server.port, 3000);
        assert!(cfg.database.url.contains("vcp"));
        assert!(Path::new(&cfg.access.policy_path).exists());
        assert!(
            cfg.server
                .public_origins
                .iter()
                .all(|o| o.starts_with("https://"))
        );
        assert!(
            cfg.server.access_log_path.ends_with("logs/vcp-access.log"),
            "{}",
            cfg.server.access_log_path
        );
        assert_eq!(cfg.login.max_attempts, 10);
        assert_eq!(cfg.login.window_secs, 300);
        assert_eq!(cfg.login.lockout_secs, 900);
        assert_eq!(cfg.org.max_accounts_per_org, 5);
        assert_eq!(cfg.org.max_lts_subscriptions, 99);
        assert_eq!(cfg.mail.smtp_host, "localhost");
        assert_eq!(cfg.mail.smtp_port, 1025);
        assert_eq!(cfg.mail.smtp_encryption, SmtpEncryption::Plaintext);
        assert_eq!(cfg.magiclinks.token_ttl_secs, 300);
        assert_eq!(cfg.magiclinks.token_retention_days, 7);
        assert_eq!(cfg.magiclinks.purge_interval_minutes, 60);
        assert_eq!(cfg.magiclinks.retention_secs(), 7 * 86_400);
        assert_eq!(
            cfg.magiclinks.purge_interval_duration(),
            std::time::Duration::from_secs(3600)
        );
        assert_eq!(cfg.magiclinks.vcp_admin_email(), "support@vauban.sh");
    }

    #[test]
    fn loads_production_vcp_conf() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("config");
        let cfg = Config::load_with_environment(&dir, Environment::Production).unwrap();
        assert_eq!(cfg.environment, Environment::Production);
        assert!(cfg.server.tls.acme.as_ref().is_some_and(|a| a.enabled));
        assert_eq!(cfg.server.port, 443);
        assert_eq!(cfg.server.access_log_path, "/var/log/vcp-access.log");
        assert_eq!(cfg.primary_public_origin(), "https://access.vauban.sh");
        assert_eq!(cfg.login.max_attempts, 10);
        assert_eq!(cfg.login.window_secs, 300);
        assert_eq!(cfg.login.lockout_secs, 900);
        assert_eq!(cfg.org.max_accounts_per_org, 5);
        assert_eq!(cfg.org.max_lts_subscriptions, 99);
        assert_eq!(cfg.mail.smtp_host, "smtp.tem.scaleway.com");
        assert_eq!(cfg.mail.smtp_port, 587);
        assert_eq!(cfg.mail.smtp_encryption, SmtpEncryption::Starttls);
        assert_eq!(cfg.magiclinks.token_ttl_secs, 300);
        assert_eq!(cfg.magiclinks.token_retention_days, 1);
        assert_eq!(cfg.magiclinks.purge_interval_minutes, 60);
    }

    #[test]
    fn loads_testing_layering_points_at_vcp_test() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("config");
        let cfg = Config::load_with_environment(&dir, Environment::Testing).unwrap();
        assert_eq!(cfg.environment, Environment::Testing);
        assert_eq!(cfg.server.port, 3001);
        assert!(cfg.database.url.contains("vcp_test"));
        assert!(!cfg.server.tls.acme.as_ref().is_some_and(|a| a.enabled));
        assert!(
            cfg.server.access_log_path.ends_with("logs/vcp-access.log"),
            "{}",
            cfg.server.access_log_path
        );
        // Elevated ceiling so suite login floods do not lock out.
        assert_eq!(cfg.login.max_attempts, 1000);
        assert_eq!(cfg.login.lockout_secs, 1);
        assert_eq!(cfg.org.max_accounts_per_org, 5);
        assert_eq!(cfg.org.max_lts_subscriptions, 99);
        assert_eq!(cfg.mail.smtp_encryption, SmtpEncryption::Plaintext);
        assert_eq!(cfg.magiclinks.token_ttl_secs, 300);
        assert_eq!(cfg.magiclinks.token_retention_days, 0);
        assert_eq!(cfg.magiclinks.purge_interval_minutes, 60);
    }

    #[test]
    fn rejects_http_public_origins() {
        let mut cfg = Config::load_with_environment(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("config"),
            Environment::Development,
        )
        .unwrap();
        cfg.server.public_origins = vec!["http://localhost:3000".to_owned()];
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("HTTPS only"));
    }

    #[test]
    fn production_rejects_plaintext_smtp() {
        let mut cfg = Config::load_with_environment(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("config"),
            Environment::Production,
        )
        .unwrap();
        cfg.mail.smtp_encryption = SmtpEncryption::Plaintext;
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("plaintext"));
    }

    #[test]
    fn rejects_zero_token_ttl() {
        let mut cfg = Config::load_with_environment(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("config"),
            Environment::Development,
        )
        .unwrap();
        cfg.magiclinks.token_ttl_secs = 0;
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("token_ttl_secs"));
    }

    #[test]
    fn rejects_zero_purge_interval_minutes() {
        let mut cfg = Config::load_with_environment(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("config"),
            Environment::Development,
        )
        .unwrap();
        cfg.magiclinks.purge_interval_minutes = 0;
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("purge_interval_minutes"));
    }

    #[test]
    fn smtp_encryption_parse_roundtrip() {
        assert_eq!(
            SmtpEncryption::parse("plaintext"),
            Some(SmtpEncryption::Plaintext)
        );
        assert_eq!(
            SmtpEncryption::parse("STARTTLS"),
            Some(SmtpEncryption::Starttls)
        );
        assert_eq!(SmtpEncryption::parse("tls"), Some(SmtpEncryption::Tls));
        assert_eq!(SmtpEncryption::parse("bogus"), None);
    }

    #[test]
    fn environment_aliases() {
        assert_eq!(Environment::parse("dev"), Environment::Development);
        assert_eq!(Environment::parse("test"), Environment::Testing);
        assert_eq!(Environment::parse("production"), Environment::Production);
    }

    #[test]
    fn development_default_log_filter_enables_global_debug() {
        assert_eq!(Environment::Development.default_log_filter(), "debug");
        assert_eq!(Environment::Testing.default_log_filter(), "info");
        assert_eq!(Environment::Production.default_log_filter(), "info");
    }
}

#[cfg(test)]
mod proptest_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(crate::proptest_util::default_config())]

        fn smtp_encryption_unknown_strings_reject(s in "[a-zA-Z0-9_]{0,32}") {
            let known = matches!(
                s.to_ascii_lowercase().as_str(),
                "plaintext" | "starttls" | "tls"
            );
            prop_assert_eq!(SmtpEncryption::parse(&s).is_some(), known);
        }
    }

    proptest! {
        #![proptest_config(crate::proptest_util::default_config())]

        fn token_ttl_positive_validates(ttl in 1u64..10_000) {
            let mut cfg = Config::load_with_environment(
                Path::new(env!("CARGO_MANIFEST_DIR")).join("config"),
                Environment::Development,
            )
            .unwrap();
            cfg.magiclinks.token_ttl_secs = ttl;
            prop_assert!(cfg.validate().is_ok());
        }
    }

    proptest! {
        #![proptest_config(crate::proptest_util::default_config())]

        fn retention_secs_is_days_times_86400(days in 0u64..=365) {
            let mut cfg = Config::load_with_environment(
                Path::new(env!("CARGO_MANIFEST_DIR")).join("config"),
                Environment::Development,
            )
            .unwrap();
            cfg.magiclinks.token_retention_days = days;
            prop_assert_eq!(cfg.magiclinks.retention_secs(), days.saturating_mul(86_400));
        }
    }

    proptest! {
        #![proptest_config(crate::proptest_util::default_config())]

        fn purge_interval_minutes_to_duration(mins in 1u64..=10_000) {
            let mut cfg = Config::load_with_environment(
                Path::new(env!("CARGO_MANIFEST_DIR")).join("config"),
                Environment::Development,
            )
            .unwrap();
            cfg.magiclinks.purge_interval_minutes = mins;
            prop_assert!(cfg.validate().is_ok());
            prop_assert_eq!(
                cfg.magiclinks.purge_interval_duration(),
                std::time::Duration::from_secs(mins.saturating_mul(60))
            );
        }
    }
}
