//! TOML configuration (Vauban-style layering).
//!
//! Lookup order for the config directory (release / runtime — no compile-time
//! paths):
//! 1. `VCP_CONFIG_DIR` (must exist)
//! 2. `/usr/local/etc/vcp` (production install)
//!
//! Local checkouts must export `VCP_CONFIG_DIR` (see `justfile`). Running the
//! release binary with neither env nor the system directory fails closed.
//!
//! Under `cfg(test)` or the `test-support` feature, a third fallback uses the
//! crate's `config/` directory and repo root (`Toasty.toml`) so tests work
//! without mutating the process environment.
//!
//! Loading:
//! - Production portal: `vcp.conf` only (self-contained). Storage helper
//!   loads sibling `vcp-store.conf` (blob root, listen, quotas, peer UID).
//! - Development: `default.toml` + `development.toml` + optional `local.toml`
//! - Testing: `default.toml` + `testing.toml` (no `local.toml`)
//!
//! Environment selection: `VCP_ENVIRONMENT` (`development` / `testing` /
//! `production`). When unset, defaults to **production** (same as Vauban).
//!
//! Relative paths in layered TOML are resolved against the **parent** of the
//! config directory (repo root when `VCP_CONFIG_DIR=…/config`). Production
//! `vcp.conf` uses absolute paths only.

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

    #[serde(default)]
    pub issues: IssuesConfig,

    #[serde(default)]
    pub storage: StorageConfig,
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
    /// When true, skip SMTP peer certificate verification (self-signed labs).
    /// Applies to `starttls` and `tls` only; default false.
    #[serde(default)]
    pub smtp_accept_invalid_certs: bool,
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

    /// Singleton PID file path.
    ///
    /// Production default: `/var/run/vcp/vcp.pid` (same runtime directory as
    /// the storage helper socket). Non-production: `/tmp/vcp.pid`.
    pub pid_file: String,

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
    /// Casbin-format `p, role:…, resource, action` CSV (see `PolicyStore`).
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

/// Issue tracker limits (`[issues]`).
#[derive(Debug, Clone, Deserialize)]
pub struct IssuesConfig {
    /// Max screenshots linked to one comment (or the opening description).
    #[serde(default = "default_max_attachments_per_comment")]
    pub max_attachments_per_comment: usize,
}

impl Default for IssuesConfig {
    fn default() -> Self {
        Self {
            max_attachments_per_comment: default_max_attachments_per_comment(),
        }
    }
}

fn default_max_attachments_per_comment() -> usize {
    crate::models::DEFAULT_MAX_ATTACHMENTS_PER_COMMENT
}

/// Blob helper IPC mode (`[storage].ipc`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StorageIpcMode {
    /// Dev: `vcp` spawns `vcp-store` and accepts a Unix stream.
    Spawn,
    /// Prod: connect to a named socket owned by `vcp-store`.
    Socket,
    /// Test-only: in-process [`crate::storage::StorageEngine`] (same API surface).
    Inline,
}

impl StorageIpcMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Spawn => "spawn",
            Self::Socket => "socket",
            Self::Inline => "inline",
        }
    }
}

/// Portal-side storage client settings (`[storage]` in `vcp.conf` / TOML).
///
/// Production socket mode needs only [`Self::ipc`] + [`Self::socket_path`].
/// Dev spawn / test inline also set [`Self::blob_path`] and abuse-limit
/// fields (passed into the helper or inline engine). Helper-owned prod
/// settings live in [`StoreHelperConfig`] / `vcp-store.conf`.
#[derive(Debug, Clone, Deserialize)]
pub struct StorageConfig {
    /// Blob root for spawn/inline only. Empty in production (`vcp.conf`).
    #[serde(default)]
    pub blob_path: String,
    #[serde(default = "default_storage_ipc")]
    pub ipc: StorageIpcMode,
    #[serde(default)]
    pub socket_path: String,
    #[serde(default)]
    pub helper_path: String,
    #[serde(default = "default_max_artifact_bytes")]
    pub max_artifact_bytes: u64,
    #[serde(default = "default_max_image_bytes")]
    pub max_image_bytes: u64,
    #[serde(default = "default_allowed_image_types")]
    pub allowed_image_types: Vec<String>,
    #[serde(default = "default_max_concurrent_uploads")]
    pub max_concurrent_uploads: u32,
    #[serde(default = "default_max_images_per_org")]
    pub max_images_per_org: u32,
    #[serde(default = "default_upload_ttl_secs")]
    pub upload_ttl_secs: u64,
    /// Unused by the portal process; peer UID is configured on the helper.
    #[serde(default)]
    pub expected_peer_uid: Option<u32>,
    /// When true, release finalize + deletes require helper-side WebAuthn.
    #[serde(default = "default_webauthn_required")]
    pub webauthn_required: bool,
    #[serde(default = "default_webauthn_uv")]
    pub webauthn_user_verification: String,
    #[serde(default)]
    pub webauthn_strict_sign_count: bool,
    /// Derived from [`Self::webauthn_origin`] at load time (not a TOML key).
    #[serde(skip)]
    pub webauthn_rp_id: String,
    #[serde(default = "default_webauthn_origin")]
    pub webauthn_origin: String,
    #[serde(default = "default_webauthn_challenge_ttl")]
    pub webauthn_challenge_ttl_secs: u64,
    /// Hours before an unapproved KEY PENDING enrolment becomes `expired`.
    /// `0` disables auto-expiry. Default 24.
    #[serde(default = "default_webauthn_pending_ttl_hours")]
    pub webauthn_pending_ttl_hours: u64,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            blob_path: "vcp-storage".into(),
            ipc: default_storage_ipc(),
            socket_path: String::new(),
            helper_path: String::new(),
            max_artifact_bytes: default_max_artifact_bytes(),
            max_image_bytes: default_max_image_bytes(),
            allowed_image_types: default_allowed_image_types(),
            max_concurrent_uploads: default_max_concurrent_uploads(),
            max_images_per_org: default_max_images_per_org(),
            upload_ttl_secs: default_upload_ttl_secs(),
            expected_peer_uid: None,
            webauthn_required: default_webauthn_required(),
            webauthn_user_verification: default_webauthn_uv(),
            webauthn_strict_sign_count: false,
            webauthn_origin: default_webauthn_origin(),
            webauthn_rp_id: default_webauthn_rp_id_from_origin(),
            webauthn_challenge_ttl_secs: default_webauthn_challenge_ttl(),
            webauthn_pending_ttl_hours: default_webauthn_pending_ttl_hours(),
        }
    }
}

impl StorageConfig {
    /// Set [`Self::webauthn_rp_id`] from [`Self::webauthn_origin`].
    pub fn derive_webauthn_rp_id(&mut self) -> anyhow::Result<()> {
        self.webauthn_rp_id = crate::storage::rp_id_from_webauthn_origin(&self.webauthn_origin)
            .map_err(anyhow::Error::msg)?;
        Ok(())
    }
}

/// Production helper settings (`vcp-store.conf`, loaded only by `vcp-store`).
#[derive(Debug, Clone, Deserialize)]
pub struct StoreHelperConfig {
    pub blob_path: String,
    pub listen: String,
    #[serde(default)]
    pub expected_peer_uid: Option<u32>,
    #[serde(default = "default_max_artifact_bytes")]
    pub max_artifact_bytes: u64,
    #[serde(default = "default_max_image_bytes")]
    pub max_image_bytes: u64,
    #[serde(default = "default_allowed_image_types")]
    pub allowed_image_types: Vec<String>,
    #[serde(default = "default_max_concurrent_uploads")]
    pub max_concurrent_uploads: u32,
    #[serde(default = "default_max_images_per_org")]
    pub max_images_per_org: u32,
    #[serde(default = "default_upload_ttl_secs")]
    pub upload_ttl_secs: u64,
    #[serde(default = "default_webauthn_required_prod")]
    pub webauthn_required: bool,
    #[serde(default = "default_webauthn_uv")]
    pub webauthn_user_verification: String,
    #[serde(default)]
    pub webauthn_strict_sign_count: bool,
    /// Derived from [`Self::webauthn_origin`] at load time (not a TOML key).
    #[serde(skip)]
    pub webauthn_rp_id: String,
    #[serde(default = "default_webauthn_origin")]
    pub webauthn_origin: String,
    #[serde(default = "default_webauthn_challenge_ttl")]
    pub webauthn_challenge_ttl_secs: u64,
    #[serde(default = "default_webauthn_pending_ttl_hours")]
    pub webauthn_pending_ttl_hours: u64,
}

impl StoreHelperConfig {
    /// Load a self-contained helper TOML (no layering).
    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        // `.conf` is not a config-rs format extension; force TOML like `vcp.conf`.
        let contents = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("failed to read {}: {e}", path.display()))?;
        let mut cfg: Self = ConfigBuilder::builder()
            .add_source(config::File::from_str(&contents, config::FileFormat::Toml))
            .build()
            .map_err(|e| anyhow::anyhow!("failed to build {}: {e}", path.display()))?
            .try_deserialize()
            .map_err(|e| anyhow::anyhow!("failed to parse {}: {e}", path.display()))?;
        cfg.webauthn_rp_id = crate::storage::rp_id_from_webauthn_origin(&cfg.webauthn_origin)
            .map_err(anyhow::Error::msg)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Default path beside portal config: `{config_dir}/vcp-store.conf`.
    pub fn default_path(config_dir: impl AsRef<Path>) -> PathBuf {
        config_dir.as_ref().join("vcp-store.conf")
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.blob_path.trim().is_empty() {
            anyhow::bail!("vcp-store blob_path must not be empty");
        }
        if !Path::new(&self.blob_path).is_absolute() {
            anyhow::bail!("vcp-store blob_path must be absolute");
        }
        if self.listen.trim().is_empty() {
            anyhow::bail!("vcp-store listen must not be empty");
        }
        if !Path::new(&self.listen).is_absolute() {
            anyhow::bail!("vcp-store listen must be absolute");
        }
        if self.max_artifact_bytes == 0 || self.max_image_bytes == 0 {
            anyhow::bail!("vcp-store max_*_bytes must be greater than zero");
        }
        if self.max_concurrent_uploads == 0 {
            anyhow::bail!("vcp-store max_concurrent_uploads must be greater than zero");
        }
        if self.webauthn_user_verification != "required" {
            anyhow::bail!("vcp-store webauthn_user_verification must be \"required\"");
        }
        if self.webauthn_origin.trim().is_empty() {
            anyhow::bail!("vcp-store webauthn_origin must not be empty");
        }
        if self.webauthn_rp_id.trim().is_empty() {
            anyhow::bail!("vcp-store webauthn_rp_id must be derived from webauthn_origin");
        }
        Ok(())
    }

    /// Convert into the engine [`StorageConfig`] shape.
    pub fn to_storage_config(&self) -> StorageConfig {
        StorageConfig {
            blob_path: self.blob_path.clone(),
            ipc: StorageIpcMode::Socket,
            socket_path: self.listen.clone(),
            helper_path: String::new(),
            max_artifact_bytes: self.max_artifact_bytes,
            max_image_bytes: self.max_image_bytes,
            allowed_image_types: self.allowed_image_types.clone(),
            max_concurrent_uploads: self.max_concurrent_uploads,
            max_images_per_org: self.max_images_per_org,
            upload_ttl_secs: self.upload_ttl_secs,
            expected_peer_uid: self.expected_peer_uid,
            webauthn_required: self.webauthn_required,
            webauthn_user_verification: self.webauthn_user_verification.clone(),
            webauthn_strict_sign_count: self.webauthn_strict_sign_count,
            webauthn_origin: self.webauthn_origin.clone(),
            webauthn_rp_id: self.webauthn_rp_id.clone(),
            webauthn_challenge_ttl_secs: self.webauthn_challenge_ttl_secs,
            webauthn_pending_ttl_hours: self.webauthn_pending_ttl_hours,
        }
    }
}

fn default_storage_ipc() -> StorageIpcMode {
    StorageIpcMode::Spawn
}

fn default_max_artifact_bytes() -> u64 {
    2 * 1024 * 1024 * 1024
}

fn default_max_image_bytes() -> u64 {
    10 * 1024 * 1024
}

fn default_allowed_image_types() -> Vec<String> {
    vec!["png".into(), "jpeg".into(), "webp".into()]
}

fn default_max_concurrent_uploads() -> u32 {
    4
}

fn default_max_images_per_org() -> u32 {
    1000
}

fn default_upload_ttl_secs() -> u64 {
    3600
}

/// Portal `StorageConfig` default (overridden per environment TOML).
fn default_webauthn_required() -> bool {
    true
}

fn default_webauthn_required_prod() -> bool {
    true
}

fn default_webauthn_uv() -> String {
    "required".into()
}

fn default_webauthn_origin() -> String {
    "https://access.vauban.sh".into()
}

fn default_webauthn_rp_id_from_origin() -> String {
    crate::storage::rp_id_from_webauthn_origin(&default_webauthn_origin())
        .expect("default webauthn_origin must yield a valid RP ID")
}

fn default_webauthn_challenge_ttl() -> u64 {
    300
}

fn default_webauthn_pending_ttl_hours() -> u64 {
    24
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
        cfg.resolve_paths(config_path);
        cfg.storage.derive_webauthn_rp_id()?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Resolve the config directory (same search order as [`Config::load`]).
    pub fn find_config_dir() -> anyhow::Result<PathBuf> {
        Self::find_config_dir_from(std::env::var_os("VCP_CONFIG_DIR").map(PathBuf::from))
    }

    /// Resolve the config directory from an optional `VCP_CONFIG_DIR` value.
    ///
    /// Prefer this in unit tests instead of mutating the process environment.
    pub fn find_config_dir_from(vcp_config_dir: Option<PathBuf>) -> anyhow::Result<PathBuf> {
        if let Some(config_path) = vcp_config_dir {
            if config_path.is_dir() {
                return Ok(config_path);
            }
            anyhow::bail!(
                "VCP_CONFIG_DIR points to a missing directory: {}",
                config_path.display()
            );
        }

        let system_config = Path::new("/usr/local/etc/vcp");
        if system_config.is_dir() {
            return Ok(system_config.to_path_buf());
        }

        #[cfg(any(test, feature = "test-support"))]
        {
            let checkout = Path::new(env!("CARGO_MANIFEST_DIR")).join("config");
            if checkout.is_dir() {
                return Ok(checkout);
            }
        }

        anyhow::bail!(
            "configuration directory not found. Searched:\n\
             - VCP_CONFIG_DIR\n\
             - /usr/local/etc/vcp\n\
             Set VCP_CONFIG_DIR (local: export VCP_CONFIG_DIR=$PWD/config) or install \
             the FreeBSD package under /usr/local/etc/vcp."
        );
    }

    /// Directory that contains `Toasty.toml` / `toasty/` migrations.
    ///
    /// Order: `VCP_PACKAGE_ROOT`, parent of [`Self::find_config_dir`] when it
    /// holds `Toasty.toml`, then `/usr/local/share/vcp`.
    pub fn package_root() -> anyhow::Result<PathBuf> {
        Self::package_root_from(
            std::env::var_os("VCP_PACKAGE_ROOT").map(PathBuf::from),
            None,
        )
    }

    /// Resolve the Toasty package root from optional overrides.
    ///
    /// `config_dir` short-circuits [`Self::find_config_dir`] when set (tests).
    pub fn package_root_from(
        vcp_package_root: Option<PathBuf>,
        config_dir: Option<PathBuf>,
    ) -> anyhow::Result<PathBuf> {
        if let Some(root) = vcp_package_root {
            if root.join("Toasty.toml").is_file() {
                return Ok(root);
            }
            anyhow::bail!("VCP_PACKAGE_ROOT has no Toasty.toml: {}", root.display());
        }

        let resolved_config = match config_dir {
            Some(dir) => Some(dir),
            None => Self::find_config_dir().ok(),
        };
        if let Some(config_dir) = resolved_config {
            let candidate = path_resolve_root(&config_dir);
            if candidate.join("Toasty.toml").is_file() {
                return Ok(candidate.to_path_buf());
            }
        }

        let share = Path::new("/usr/local/share/vcp");
        if share.join("Toasty.toml").is_file() {
            return Ok(share.to_path_buf());
        }

        #[cfg(any(test, feature = "test-support"))]
        {
            let checkout = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            if checkout.join("Toasty.toml").is_file() {
                return Ok(checkout);
            }
        }

        anyhow::bail!(
            "Toasty package root not found (VCP_PACKAGE_ROOT, parent of \
             VCP_CONFIG_DIR, or /usr/local/share/vcp with Toasty.toml)"
        );
    }

    fn resolve_paths(&mut self, config_dir: &Path) {
        let root = path_resolve_root(config_dir);
        self.access.policy_path = resolve_path(root, &self.access.policy_path);
        self.server.access_log_path = resolve_path(root, &self.server.access_log_path);
        self.server.pid_file = resolve_path(root, &self.server.pid_file);
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
        if !self.storage.blob_path.is_empty() {
            self.storage.blob_path = resolve_path(root, &self.storage.blob_path);
        }
        if !self.storage.socket_path.is_empty() {
            self.storage.socket_path = resolve_path(root, &self.storage.socket_path);
        }
        if !self.storage.helper_path.is_empty() {
            self.storage.helper_path = resolve_path(root, &self.storage.helper_path);
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
        if self.server.pid_file.trim().is_empty() {
            anyhow::bail!("server.pid_file must not be empty");
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
        self.validate_storage()?;
        Ok(())
    }

    fn validate_storage(&self) -> anyhow::Result<()> {
        if self.storage.ipc == StorageIpcMode::Inline && self.environment.is_production() {
            anyhow::bail!("storage.ipc=inline is not allowed in production");
        }
        if self.environment.is_production() {
            if self.storage.ipc != StorageIpcMode::Socket {
                anyhow::bail!("storage.ipc=socket is required in production");
            }
            if self.storage.socket_path.trim().is_empty() {
                anyhow::bail!("storage.socket_path is required when ipc=socket");
            }
            // Portal production config must not own the blob root (helper /
            // vcp-store.conf does). Empty blob_path is the jail-friendly shape.
            if !self.storage.blob_path.trim().is_empty() {
                anyhow::bail!(
                    "storage.blob_path must be empty in production (configure blob_path in vcp-store.conf)"
                );
            }
        } else {
            let path = Path::new(&self.storage.blob_path);
            if self.storage.blob_path.trim().is_empty() {
                anyhow::bail!("storage.blob_path must not be empty outside production");
            }
            if !path.is_absolute() {
                anyhow::bail!("storage.blob_path must be absolute after path resolution");
            }
            // Dev/test: ensure the directory exists so spawn/inline can open it.
            std::fs::create_dir_all(path).map_err(|e| {
                anyhow::anyhow!("failed to create storage.blob_path {}: {e}", path.display())
            })?;
        }
        if self.storage.max_artifact_bytes == 0 || self.storage.max_image_bytes == 0 {
            anyhow::bail!("storage max_*_bytes must be greater than zero");
        }
        if self.storage.max_concurrent_uploads == 0 {
            anyhow::bail!("storage.max_concurrent_uploads must be greater than zero");
        }
        if self.storage.webauthn_origin.trim().is_empty() {
            anyhow::bail!("storage.webauthn_origin must not be empty");
        }
        if self.storage.webauthn_rp_id.trim().is_empty() {
            anyhow::bail!(
                "storage.webauthn_rp_id must be derived from webauthn_origin before validate"
            );
        }
        if self.storage.webauthn_user_verification != "required" {
            anyhow::bail!("storage.webauthn_user_verification must be \"required\"");
        }
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
        if self.mail.smtp_accept_invalid_certs
            && self.mail.smtp_encryption == SmtpEncryption::Plaintext
        {
            anyhow::bail!(
                "mail.smtp_accept_invalid_certs requires smtp_encryption=starttls or tls"
            );
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

/// Repo / install root for relative TOML paths (`logs/`, `certs/`, …).
///
/// When `config_dir` is `…/config` or `/usr/local/etc/vcp`, relative paths are
/// resolved against its parent (checkout root or `/usr/local/etc`). Production
/// conf should use absolute paths only.
fn path_resolve_root(config_dir: &Path) -> &Path {
    config_dir
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(config_dir)
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
    fn find_config_dir_from_prefers_injected_path() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("config");
        let found = Config::find_config_dir_from(Some(dir.clone())).unwrap();
        assert_eq!(found, dir);
        let root =
            Config::package_root_from(Some(PathBuf::from(env!("CARGO_MANIFEST_DIR"))), Some(dir))
                .unwrap();
        assert!(root.join("Toasty.toml").is_file());
    }

    #[test]
    fn find_config_dir_test_fallback_reaches_checkout_config() {
        // No env mutation: cfg(test) fallback or a live system/env path.
        let found = Config::find_config_dir().unwrap();
        assert!(found.is_dir());
        assert!(found.join("default.toml").is_file() || found.join("vcp.conf").is_file());
        assert!(
            Config::package_root()
                .unwrap()
                .join("Toasty.toml")
                .is_file()
        );
    }

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
        assert_eq!(cfg.server.pid_file, "/tmp/vcp.pid");
        assert_eq!(cfg.login.max_attempts, 10);
        assert_eq!(cfg.login.window_secs, 300);
        assert_eq!(cfg.login.lockout_secs, 900);
        assert_eq!(cfg.org.max_accounts_per_org, 5);
        assert_eq!(cfg.org.max_lts_subscriptions, 99);
        assert_eq!(cfg.issues.max_attachments_per_comment, 5);
        assert_eq!(cfg.mail.smtp_host, "localhost");
        assert_eq!(cfg.mail.smtp_port, 1025);
        assert_eq!(cfg.mail.smtp_encryption, SmtpEncryption::Starttls);
        assert!(cfg.mail.smtp_accept_invalid_certs);
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
        assert_eq!(
            cfg.server.tls.acme.as_ref().map(|a| a.email.as_str()),
            Some("support@vauban.sh")
        );
        assert_eq!(cfg.server.port, 443);
        assert_eq!(cfg.server.access_log_path, "/var/log/vcp-access.log");
        assert_eq!(cfg.server.pid_file, "/var/run/vcp/vcp.pid");
        assert_eq!(cfg.primary_public_origin(), "https://access.vauban.sh");
        assert_eq!(cfg.login.max_attempts, 10);
        assert_eq!(cfg.login.window_secs, 300);
        assert_eq!(cfg.login.lockout_secs, 900);
        assert_eq!(cfg.org.max_accounts_per_org, 5);
        assert_eq!(cfg.org.max_lts_subscriptions, 99);
        assert_eq!(cfg.issues.max_attachments_per_comment, 5);
        assert_eq!(cfg.mail.smtp_host, "smtp.tem.scaleway.com");
        assert_eq!(cfg.mail.smtp_port, 587);
        assert_eq!(cfg.mail.smtp_encryption, SmtpEncryption::Starttls);
        assert!(!cfg.mail.smtp_accept_invalid_certs);
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
        assert_eq!(cfg.mail.smtp_encryption, SmtpEncryption::Starttls);
        assert!(cfg.mail.smtp_accept_invalid_certs);
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
    fn rejects_accept_invalid_certs_with_plaintext() {
        let mut cfg = Config::load_with_environment(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("config"),
            Environment::Development,
        )
        .unwrap();
        cfg.mail.smtp_encryption = SmtpEncryption::Plaintext;
        cfg.mail.smtp_accept_invalid_certs = true;
        let err = cfg.validate().unwrap_err().to_string();
        assert!(
            err.contains("smtp_accept_invalid_certs"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn production_allows_accept_invalid_certs_with_starttls() {
        let mut cfg = Config::load_with_environment(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("config"),
            Environment::Production,
        )
        .unwrap();
        cfg.mail.smtp_encryption = SmtpEncryption::Starttls;
        cfg.mail.smtp_accept_invalid_certs = true;
        cfg.validate()
            .expect("accept_invalid_certs allowed in prod");
    }

    #[test]
    fn smtp_accept_invalid_certs_defaults_false_when_key_absent() {
        let fragment = r#"
smtp_host = "localhost"
smtp_port = 587
smtp_encryption = "starttls"
"#;
        let loaded = config::Config::builder()
            .add_source(config::File::from_str(fragment, config::FileFormat::Toml))
            .build()
            .expect("fragment");
        let cfg: MailConfig = loaded.try_deserialize().expect("MailConfig");
        assert!(!cfg.smtp_accept_invalid_certs);
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

    #[test]
    fn production_rejects_storage_ipc_spawn() {
        let mut cfg = Config::load_with_environment(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("config"),
            Environment::Production,
        )
        .unwrap();
        cfg.storage.ipc = StorageIpcMode::Spawn;
        let err = cfg.validate().unwrap_err().to_string();
        assert!(
            err.contains("storage.ipc=socket is required in production"),
            "{err}"
        );
    }

    #[test]
    fn production_rejects_portal_blob_path() {
        let mut cfg = Config::load_with_environment(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("config"),
            Environment::Production,
        )
        .unwrap();
        cfg.storage.ipc = StorageIpcMode::Socket;
        cfg.storage.socket_path = "/var/run/vcp/store.sock".into();
        cfg.storage.blob_path = "/var/db/vcp/storage".into();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(
            err.contains("blob_path must be empty in production"),
            "{err}"
        );
    }

    #[test]
    fn production_conf_requires_socket_ipc() {
        let cfg = Config::load_with_environment(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("config"),
            Environment::Production,
        )
        .unwrap();
        assert_eq!(cfg.storage.ipc, StorageIpcMode::Socket);
        assert!(!cfg.storage.socket_path.is_empty());
        assert!(
            cfg.storage.blob_path.is_empty(),
            "portal vcp.conf must not set blob_path"
        );
    }

    #[test]
    fn store_helper_conf_loads_blob_and_listen() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("config/vcp-store.conf");
        let helper = StoreHelperConfig::load(&path).unwrap();
        assert_eq!(helper.blob_path, "/var/db/vcp/storage");
        assert_eq!(helper.listen, "/var/run/vcp/store.sock");
        assert_eq!(helper.expected_peer_uid, Some(800));
        assert!(helper.max_artifact_bytes > 0);
        assert_eq!(helper.webauthn_pending_ttl_hours, 24);
    }

    #[test]
    fn development_storage_pending_ttl_matches_helper_default() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("config");
        let cfg = Config::load_with_environment(&dir, Environment::Development).unwrap();
        assert_eq!(cfg.storage.webauthn_pending_ttl_hours, 24);
    }
}

#[cfg(test)]
mod proptest_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(crate::proptest_util::default_config())]

        #[test]
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

        #[test]
        fn smtp_accept_invalid_certs_bool_roundtrip(flag in proptest::bool::ANY) {
            let fragment = format!(
                "smtp_host = \"localhost\"\nsmtp_port = 587\nsmtp_encryption = \"starttls\"\nsmtp_accept_invalid_certs = {flag}\n"
            );
            let loaded = config::Config::builder()
                .add_source(config::File::from_str(&fragment, config::FileFormat::Toml))
                .build()
                .expect("fragment");
            let mail: MailConfig = loaded.try_deserialize().expect("MailConfig");
            prop_assert_eq!(mail.smtp_accept_invalid_certs, flag);

            let mut cfg = Config::load_with_environment(
                Path::new(env!("CARGO_MANIFEST_DIR")).join("config"),
                Environment::Development,
            )
            .unwrap();
            cfg.mail.smtp_encryption = SmtpEncryption::Starttls;
            cfg.mail.smtp_accept_invalid_certs = flag;
            prop_assert!(cfg.validate().is_ok());

            cfg.mail.smtp_encryption = SmtpEncryption::Plaintext;
            if flag {
                prop_assert!(cfg.validate().is_err());
            } else {
                prop_assert!(cfg.validate().is_ok());
            }
        }
    }

    proptest! {
        #![proptest_config(crate::proptest_util::default_config())]

        #[test]
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

        #[test]
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

        #[test]
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
