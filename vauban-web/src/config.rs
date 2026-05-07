/// VAUBAN Web - Configuration management.
///
/// Loads configuration from TOML files with multi-environment support.
/// Configuration is loaded from the workspace root `config/` directory.
///
/// Loading order:
/// 1. config/default.toml - default values
/// 2. config/{environment}.toml - environment-specific values
/// 3. config/local.toml - local overrides (not versioned)
/// 4. Environment variables prefixed with VAUBAN_ (for secrets only)
///
/// Configuration directory lookup order:
/// 1. VAUBAN_CONFIG_DIR environment variable (if set)
/// 2. Workspace root config/ directory (development)
/// 3. /usr/local/etc/vauban/ (production on FreeBSD)
use config::{Config as ConfigBuilder, ConfigError, File};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

// ==================== Optional Secret Wrapper ====================

/// Wrapper for optional secret values that properly implements Serialize/Deserialize.
/// This is needed because SecretString (SecretBox<str>) doesn't implement Serialize for Option.
///
/// The inner `String` is zeroized on `Drop` to prevent secret leakage in memory.
#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(transparent)]
pub struct OptionalSecret(Option<String>);

impl OptionalSecret {
    /// Create a new OptionalSecret from a string value.
    pub fn new(value: Option<String>) -> Self {
        Self(value)
    }

    /// Get the exposed secret value if present.
    pub fn as_ref(&self) -> Option<&str> {
        self.0.as_deref()
    }

    /// Get the wrapped secret as a SecretString if present.
    pub fn as_secret(&self) -> Option<secrecy::SecretString> {
        self.0
            .as_ref()
            .map(|s| secrecy::SecretString::from(s.clone()))
    }

    /// Get the exposed secret value as an Option<String>.
    pub fn to_string(&self) -> Option<String> {
        self.0.clone()
    }

    /// Check if the secret is present.
    pub fn is_some(&self) -> bool {
        self.0.is_some()
    }

    /// Check if the secret is absent.
    pub fn is_none(&self) -> bool {
        self.0.is_none()
    }

    /// Convert to a SecretString if present.
    ///
    /// Uses `take()` to move the inner value while leaving `None` behind,
    /// which is compatible with the `Drop` implementation.
    pub fn into_secret(mut self) -> Option<secrecy::SecretString> {
        self.0.take().map(secrecy::SecretString::from)
    }
}

impl std::fmt::Debug for OptionalSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_some() {
            write!(f, "[REDACTED]")
        } else {
            write!(f, "None")
        }
    }
}

impl From<Option<String>> for OptionalSecret {
    fn from(value: Option<String>) -> Self {
        Self::new(value)
    }
}

impl Drop for OptionalSecret {
    fn drop(&mut self) {
        if let Some(ref mut s) = self.0 {
            s.zeroize();
        }
    }
}

// ==================== Debug Helper Macro ====================

/// Macro to generate a Debug implementation that redacts sensitive fields.
///
/// # Example
///
/// ```rust
/// use vauban_web::debug_redacted_struct;
/// use secrecy::{SecretString, ExposeSecret};
///
/// struct MyConfig {
///     password: SecretString,
///     api_key: SecretString,
///     url: SecretString,
/// }
///
/// // Only redact password and api_key, expose url (calls expose_secret())
/// debug_redacted_struct!(
///     MyConfig,
///     redact: [password, api_key],
///     expose: [url]
/// );
///
/// let config = MyConfig {
///     password: SecretString::from("super_secret"),
///     api_key: SecretString::from("api_key_123"),
///     url: SecretString::from("https://example.com"),
/// };
///
/// let debug_str = format!("{:?}", config);
/// // Redacted fields show [REDACTED] (appears twice for 2 redacted fields)
/// assert!(debug_str.contains("[REDACTED]"));
/// // Exposed secret shows the actual value
/// assert!(debug_str.contains("https://example.com"));
/// // Secrets are NOT exposed in the debug output
/// assert!(!debug_str.contains("super_secret"));
/// assert!(!debug_str.contains("api_key_123"));
/// ```
#[macro_export]
macro_rules! debug_redacted_struct {
    (
        $name:ident,
        redact: [$($redact:ident),*],
        expose: [$($expose:ident),*]
    ) => {
        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct(stringify!($name))
                    $(.field(stringify!($redact), &"[REDACTED]"))*
                    $(.field(stringify!($expose), &self.$expose.expose_secret()))*
                    .finish()
            }
        }
    };
    (
        $name:ident,
        redact: [$($redact:ident),*]
    ) => {
        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct(stringify!($name))
                    $(.field(stringify!($redact), &"[REDACTED]"))*
                    .finish()
            }
        }
    };
}

/// Macro to generate a Debug implementation that redacts Option<Secret<String>> fields.
#[macro_export]
macro_rules! debug_redacted_optional {
    ($name:ident, redact: [$($redact:ident),*]) => {
        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct(stringify!($name))
                    .field("enabled", &self.enabled)
                    $(.field(stringify!($redact), &"[REDACTED]"))*
                    .finish()
            }
        }
    };
}

/// Application environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Environment {
    Development,
    Testing,
    #[default]
    Production,
}

impl Environment {
    pub fn parse(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "development" | "dev" => Self::Development,
            "testing" | "test" => Self::Testing,
            "production" | "prod" => Self::Production,
            _ => Self::Production,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Development => "development",
            Self::Testing => "testing",
            Self::Production => "production",
        }
    }

    pub fn is_development(&self) -> bool {
        matches!(self, Self::Development)
    }

    pub fn is_production(&self) -> bool {
        matches!(self, Self::Production)
    }
}

/// Application configuration.
/// All values must be defined in TOML files.
#[derive(Clone, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub environment: Environment,
    pub secret_key: secrecy::SecretString,
    pub database: DatabaseConfig,
    pub cache: CacheConfig,
    pub server: ServerConfig,
    pub jwt: JwtConfig,
    pub security: SecurityConfig,
    pub logging: LoggingConfig,
    /// API configuration for M2M endpoints.
    #[serde(default)]
    pub api: ApiConfig,
    /// WebSocket configuration.
    #[serde(default)]
    pub websocket: WebSocketConfig,
    /// Session recording configuration.
    #[serde(default)]
    pub recording: RecordingConfig,
    /// Asset / asset-group membership behavior.
    #[serde(default)]
    pub assets: AssetsConfig,
    /// Email notification (Issue #10) configuration.
    #[serde(default)]
    pub mailer: MailerConfig,
    /// Industrial / IACS module (preliminary scaffolding for future
    /// IACS asset support). Carries the global kill-switch for the
    /// EWS onboarding flow.
    #[serde(default)]
    pub industrial: IndustrialConfig,
    /// White-label / branding configuration. Currently only carries
    /// `[product.brand].name` -- the visible brand displayed in the
    /// top-left corner of every sidebar-bearing page. Defaults to
    /// `"VAUBAN"` (no white-label).
    #[serde(default)]
    pub product: ProductConfig,
}

debug_redacted_struct!(
    Config,
    redact: [secret_key]
);

/// Asset and asset-group configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AssetsConfig {
    /// When `true`, an asset may belong to several asset groups. When `false`, at most one
    /// group per asset is enforced by the application (see also startup warning if data
    /// already contains multi-group rows).
    #[serde(default = "AssetsConfig::default_allow_multiple_groups_per_asset")]
    pub allow_multiple_groups_per_asset: bool,
}

impl Default for AssetsConfig {
    fn default() -> Self {
        Self {
            allow_multiple_groups_per_asset: true,
        }
    }
}

impl AssetsConfig {
    const fn default_allow_multiple_groups_per_asset() -> bool {
        true
    }
}

/// Database configuration.
#[derive(Clone, Deserialize)]
pub struct DatabaseConfig {
    pub url: secrecy::SecretString,
    pub max_connections: u32,
    pub min_connections: u32,
    pub connect_timeout_secs: u64,
}

debug_redacted_struct!(
    DatabaseConfig,
    redact: [url]
);

/// Cache (Valkey/Redis) configuration.
#[derive(Clone, Deserialize)]
pub struct CacheConfig {
    pub enabled: bool,
    pub url: secrecy::SecretString,
    pub default_ttl_secs: u64,
}

debug_redacted_struct!(
    CacheConfig,
    redact: [url]
);

/// Server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub workers: Option<usize>,
    /// TLS configuration (required - HTTPS only).
    pub tls: TlsConfig,
}

/// TLS configuration for HTTPS.
/// VAUBAN Web runs exclusively over HTTPS with TLS 1.3.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Path to certificate file (PEM format).
    pub cert_path: String,
    /// Path to private key file (PEM format).
    pub key_path: String,
    /// Optional: Path to CA chain file for intermediate certificates.
    #[serde(default)]
    pub ca_chain_path: Option<String>,
    /// Optional ACME configuration for automatic certificate management.
    #[serde(default)]
    pub acme: Option<AcmeConfig>,
}

/// ACME automatic certificate management configuration.
///
/// Uses TLS-ALPN-01 (RFC 8737) challenge on port 443.
/// No HTTP port 80 required. Works with any RFC 8555-compliant CA
/// (Let's Encrypt, ZeroSSL, etc.) -- the CA is selected via `directory_url`.
#[derive(Clone, Serialize, Deserialize)]
pub struct AcmeConfig {
    /// Whether ACME is enabled.
    pub enabled: bool,
    /// Contact email for the ACME account.
    #[serde(default)]
    pub email: String,
    /// Domain names to obtain certificates for.
    #[serde(default)]
    pub domains: Vec<String>,
    /// Renew the certificate this many hours before expiration.
    #[serde(default = "AcmeConfig::default_renew_before_hours")]
    pub renew_before_hours: u32,
    /// Path to persist the ACME account private key.
    #[serde(default)]
    pub account_key_path: String,
    /// Use the ACME staging environment (for testing).
    #[serde(default)]
    pub staging: bool,
    /// External Account Binding key ID (required by some CAs, e.g. ZeroSSL).
    #[serde(default)]
    pub eab_kid: OptionalSecret,
    /// External Account Binding HMAC key (required by some CAs, e.g. ZeroSSL).
    #[serde(default)]
    pub eab_hmac_key: OptionalSecret,
    /// ACME directory URL (determines which CA is used).
    #[serde(default)]
    pub directory_url: String,
    /// ACME staging directory URL (used when `staging = true`).
    /// If empty and `staging = true`, falls back to `directory_url`.
    #[serde(default)]
    pub staging_directory_url: String,
}

impl AcmeConfig {
    fn default_renew_before_hours() -> u32 {
        24
    }

    /// Resolve the ACME directory URL based on staging flag and config.
    pub fn resolve_directory_url(&self) -> Result<String, String> {
        if self.staging && !self.staging_directory_url.is_empty() {
            return Ok(self.staging_directory_url.clone());
        }
        if self.directory_url.is_empty() {
            return Err("ACME directory_url must be set in configuration".to_string());
        }
        Ok(self.directory_url.clone())
    }

    /// Validate the ACME configuration.
    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }

        if self.email.is_empty() {
            return Err("ACME email is required when ACME is enabled".to_string());
        }
        if self.domains.is_empty() {
            return Err("ACME domains list cannot be empty when ACME is enabled".to_string());
        }
        if self.account_key_path.is_empty() {
            return Err("ACME account_key_path is required when ACME is enabled".to_string());
        }

        self.resolve_directory_url()?;

        if self.eab_kid.is_some() != self.eab_hmac_key.is_some() {
            return Err("eab_kid and eab_hmac_key must both be set or both be absent".to_string());
        }

        Ok(())
    }
}

impl std::fmt::Debug for AcmeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcmeConfig")
            .field("enabled", &self.enabled)
            .field("email", &self.email)
            .field("domains", &self.domains)
            .field("renew_before_hours", &self.renew_before_hours)
            .field("account_key_path", &self.account_key_path)
            .field("staging", &self.staging)
            .field("eab_kid", &self.eab_kid)
            .field("eab_hmac_key", &self.eab_hmac_key)
            .field("directory_url", &self.directory_url)
            .field("staging_directory_url", &self.staging_directory_url)
            .finish()
    }
}

/// JWT configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtConfig {
    pub access_token_lifetime_minutes: u64,
    pub refresh_token_lifetime_days: u64,
    pub algorithm: String,
}

/// Security configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub password_min_length: usize,
    pub max_failed_login_attempts: u32,
    pub session_max_duration_secs: u64,
    pub session_idle_timeout_secs: u64,
    pub rate_limit_per_minute: u32,
    pub argon2: Argon2Config,
    /// List of trusted reverse proxy IP addresses (e.g. `["127.0.0.1", "::1"]`).
    /// `X-Forwarded-For` and `X-Real-IP` headers are only trusted when the TCP
    /// connection originates from one of these addresses.  An empty list means
    /// proxy headers are **never** trusted and the TCP peer address is always used.
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    /// Require users to provide a justification before connecting to an asset.
    #[serde(default = "default_require_justification")]
    pub require_justification: bool,
}

impl SecurityConfig {
    /// Parse `trusted_proxies` into a `Vec<IpAddr>`, silently skipping
    /// entries that cannot be parsed.
    pub fn parsed_trusted_proxies(&self) -> Vec<std::net::IpAddr> {
        self.trusted_proxies
            .iter()
            .filter_map(|s| s.parse::<std::net::IpAddr>().ok())
            .collect()
    }
}

/// Argon2 configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Argon2Config {
    pub memory_size_kb: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

/// Log format options.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// JSON format for SIEM integration.
    Json,
    /// Human-readable text format (default).
    #[default]
    Text,
}

impl LogFormat {
    pub fn parse(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "json" => Self::Json,
            _ => Self::Text,
        }
    }

    pub fn is_json(&self) -> bool {
        matches!(self, Self::Json)
    }
}

/// Logging configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level: debug, info, warn, error.
    pub level: String,
    /// Log format: json or text.
    pub format: LogFormat,
}

/// API configuration.
/// Controls the M2M API endpoints (/api/v1/*).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    /// Enable or disable API endpoints.
    /// When false, only web routes are available.
    pub enabled: bool,
    /// API route prefix (e.g., "/api/v1").
    pub prefix: String,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            prefix: "/api/v1".to_string(),
        }
    }
}

/// WebSocket configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebSocketConfig {
    /// Maximum number of concurrent WebSocket connections per user.
    /// Prevents a single user from exhausting server resources.
    /// Each browser tab can open multiple WebSocket connections (dashboard,
    /// notifications, terminal, session, active-sessions), so this should be
    /// set high enough to support legitimate use (e.g. 10 SSH tabs ~ 30 WS).
    pub max_connections_per_user: usize,
}

impl Default for WebSocketConfig {
    fn default() -> Self {
        Self {
            max_connections_per_user: 30,
        }
    }
}

/// Session recording configuration.
#[derive(Clone, Deserialize)]
pub struct RecordingConfig {
    #[serde(default = "default_recording_enabled")]
    pub enabled: bool,
    #[serde(default = "default_recording_storage_path")]
    pub storage_path: String,
    #[serde(default = "default_recording_enabled")]
    pub rdp: bool,
    #[serde(default = "default_recording_enabled")]
    pub ssh: bool,
    /// Enable the recording integrity hydrator (bootstrap at boot +
    /// per-call-site enqueue + daily reconciliation cron). Default
    /// true. When false, the Recording Details page falls back to
    /// "Integrity metadata pending finalization" indefinitely.
    #[serde(default = "default_recording_enabled")]
    pub hydration_enabled: bool,
    /// Maximum sessions processed per bootstrap/cron batch. Default 50.
    /// The bootstrap loops until the candidate index is empty, so this
    /// only bounds the per-pass memory + transaction footprint, not
    /// the total amount of work.
    #[serde(default = "default_hydration_batch_size")]
    pub hydration_batch_size: i64,
    /// Grace period (seconds) after `disconnected_at` before a session
    /// with a missing `meta.json` is considered lost and marked
    /// finalized with NULL integrity columns. Below the grace period,
    /// missing meta is treated as a normal race with `vauban-audit`
    /// and silently retried by the next bootstrap or daily cron run.
    /// Default 300 (5 minutes). Sessions with a flat `.mp4` legacy
    /// `recording_path` (no directory, no `meta.json` ever produced)
    /// are finalized immediately regardless of this knob.
    #[serde(default = "default_hydration_missing_meta_grace_secs")]
    pub hydration_missing_meta_grace_secs: u64,
    /// Delay (seconds) between a session being marked `disconnected_at`
    /// by a call-site and the actual hydration call. Gives
    /// `vauban-audit` enough time to flush `meta.json` to disk after
    /// the WebSocket / proxy session ends. Default 5 s. This is the
    /// PRIMARY finalization latency in nominal operation: shorter
    /// values risk racing audit; longer values delay UI feedback.
    #[serde(default = "default_hydration_enqueue_delay_secs")]
    pub hydration_enqueue_delay_secs: u64,
    /// Hour of day (UTC, 0..=23) when the daily reconciliation cron
    /// runs. Default 4 (04:00 UTC = low traffic window). The cron is
    /// a SAFETY NET that re-runs the bootstrap, NOT the primary
    /// finalization path -- in nominal operation it logs
    /// `bootstrap_complete { hydrated=0, ... }` and exits in
    /// milliseconds. See `docs/technical/Vauban_Recording_Architecture_EN(1.3).md`.
    #[serde(default = "default_hydration_daily_cron_hour_utc")]
    pub hydration_daily_cron_hour_utc: u8,
}

fn default_require_justification() -> bool {
    true
}

fn default_recording_enabled() -> bool {
    true
}

fn default_recording_storage_path() -> String {
    "recordings".to_string()
}

fn default_hydration_batch_size() -> i64 {
    50
}

fn default_hydration_missing_meta_grace_secs() -> u64 {
    300
}

fn default_hydration_enqueue_delay_secs() -> u64 {
    5
}

fn default_hydration_daily_cron_hour_utc() -> u8 {
    4
}

impl RecordingConfig {
    /// Validate semantic invariants the serde defaults cannot enforce.
    /// Currently only: `hydration_daily_cron_hour_utc` must be a valid
    /// UTC hour (0..=23). Called from
    /// [`Config::load_with_environment`] so an out-of-range value
    /// fails the boot rather than silently misbehaving.
    pub fn validate(&self) -> Result<(), String> {
        if !self.hydration_enabled {
            return Ok(());
        }
        if self.hydration_daily_cron_hour_utc > 23 {
            return Err(format!(
                "recording.hydration_daily_cron_hour_utc must be in 0..=23, got {}",
                self.hydration_daily_cron_hour_utc
            ));
        }
        Ok(())
    }
}

impl Default for RecordingConfig {
    fn default() -> Self {
        Self {
            enabled: default_recording_enabled(),
            storage_path: default_recording_storage_path(),
            rdp: default_recording_enabled(),
            ssh: default_recording_enabled(),
            hydration_enabled: default_recording_enabled(),
            hydration_batch_size: default_hydration_batch_size(),
            hydration_missing_meta_grace_secs: default_hydration_missing_meta_grace_secs(),
            hydration_enqueue_delay_secs: default_hydration_enqueue_delay_secs(),
            hydration_daily_cron_hour_utc: default_hydration_daily_cron_hour_utc(),
        }
    }
}

/// Email notification configuration (Issue #10).
///
/// The mailer is embedded in `vauban-web`. The TCP socket to the MTA is
/// established by `vauban-supervisor` (which is not Capsicum-confined)
/// and passed back to `vauban-web` via SCM_RIGHTS. The supervisor also
/// owns its own copy of `[mailer]` (see
/// [`vauban-supervisor/src/config.rs`]) used as an SSRF-proof whitelist:
/// it accepts a `TcpConnectRequest { target_service: Web }` only if
/// `(host, port)` exactly matches its `smtp_host` / `smtp_port`.
///
/// Secrets (SMTP password) are loaded from the environment variable
/// `VAUBAN_SMTP_PASSWORD` and cleared from `/proc/PID/environ`
/// immediately after reading. Username can be loaded similarly via
/// `VAUBAN_SMTP_USERNAME` to avoid storing it in TOML.
#[derive(Clone, Deserialize)]
pub struct MailerConfig {
    /// Master switch. When false, `Mailer::queue` is a no-op and the
    /// dispatcher task does not start. Default false; enable explicitly
    /// in production with the SMTP credentials.
    #[serde(default)]
    pub enabled: bool,
    /// Sender address (RFC 5321 reverse-path / `MAIL FROM`).
    /// Mandatory when `enabled` is true.
    #[serde(default)]
    pub from_address: String,
    /// Display name rendered in the `From:` header (`"Name <addr>"`).
    /// Optional.
    #[serde(default)]
    pub from_name: String,
    /// Optional `Reply-To:` header. Empty string disables the header.
    #[serde(default)]
    pub reply_to: String,
    /// Public base URL injected into email templates (e.g.
    /// `https://vauban.example.com`). Used to build absolute links to
    /// the approval page, the reset-password page, etc. The dispatcher
    /// rejects values that are not `https://` in production.
    #[serde(default)]
    pub base_url: String,
    /// SMTP server host (DNS name). Resolved by the supervisor at each
    /// connect; the supervisor also enforces an exact `(host, port)`
    /// match against its own config (SSRF guard).
    #[serde(default)]
    pub smtp_host: String,
    /// SMTP server port (typically 587 with STARTTLS, or 465 with
    /// implicit TLS).
    #[serde(default = "MailerConfig::default_smtp_port")]
    pub smtp_port: u16,
    /// Transport encryption.
    #[serde(default = "MailerConfig::default_smtp_encryption")]
    pub smtp_encryption: SmtpEncryption,
    /// Optional SMTP username. Empty string == no AUTH.
    /// Override via `VAUBAN_SMTP_USERNAME`.
    #[serde(default)]
    pub smtp_username: String,
    /// SMTP password (`SecretString`). Override via
    /// `VAUBAN_SMTP_PASSWORD` (preferred). The env var is cleared from
    /// the process environment immediately after read.
    #[serde(default = "MailerConfig::default_secret_string")]
    pub smtp_password: secrecy::SecretString,
    /// Hostname advertised in the SMTP EHLO/HELO command. Defaults to
    /// "vauban" when empty. Many MTAs reject EHLOs containing a
    /// publicly-routable bare hostname mismatch, so override with the
    /// HELO-acceptable value for your relay (often the public DNS name
    /// of the deployment).
    #[serde(default)]
    pub helo_name: String,
    /// Dispatcher polling interval, in seconds. Notifications also wake
    /// the task instantly via `tokio::sync::Notify`, so this only
    /// matters for catching up after a restart or a missed notify.
    #[serde(default = "MailerConfig::default_poll_interval_secs")]
    pub poll_interval_secs: u64,
    /// Per-cycle batch size pulled from `email_outbox`. Bounds the
    /// memory and locking footprint of one cycle. Default 16.
    #[serde(default = "MailerConfig::default_batch_size")]
    pub batch_size: i64,
    /// Maximum delivery attempts per row. The dispatcher gives up and
    /// marks the row `failed` after this count. Default 5.
    #[serde(default = "MailerConfig::default_max_attempts")]
    pub max_attempts: i32,
    /// Per-attempt SMTP timeout, in seconds. Wraps the entire
    /// EHLO/STARTTLS/AUTH/MAIL/RCPT/DATA/QUIT exchange.
    #[serde(default = "MailerConfig::default_smtp_timeout_secs")]
    pub smtp_timeout_secs: u64,
    /// TCP-broker timeout, in seconds. The dispatcher waits at most
    /// this long for the supervisor to come back with the connected
    /// FD. The supervisor itself uses 30 s; we mirror that.
    #[serde(default = "MailerConfig::default_broker_timeout_secs")]
    pub broker_timeout_secs: u64,
}

/// SMTP transport encryption mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SmtpEncryption {
    /// Connect on the plain port (e.g. 587), then upgrade with
    /// `STARTTLS` before AUTH and DATA. Mandatory in production.
    Starttls,
    /// Connect with TLS from byte 0 (e.g. port 465).
    Tls,
    /// No transport encryption. ONLY allowed in development against a
    /// localhost test MTA. The dispatcher will refuse to send AUTH
    /// credentials in this mode.
    Plaintext,
}

impl MailerConfig {
    fn default_smtp_port() -> u16 {
        587
    }

    fn default_smtp_encryption() -> SmtpEncryption {
        SmtpEncryption::Starttls
    }

    fn default_secret_string() -> secrecy::SecretString {
        secrecy::SecretString::new(String::new().into())
    }

    fn default_poll_interval_secs() -> u64 {
        10
    }

    fn default_batch_size() -> i64 {
        16
    }

    fn default_max_attempts() -> i32 {
        5
    }

    fn default_smtp_timeout_secs() -> u64 {
        30
    }

    fn default_broker_timeout_secs() -> u64 {
        30
    }

    /// Effective HELO/EHLO domain. Falls back to `"vauban"` if not set.
    pub fn effective_helo(&self) -> &str {
        if self.helo_name.is_empty() {
            "vauban"
        } else {
            self.helo_name.as_str()
        }
    }

    /// Validate the mailer block. Called from `Config::load_with_environment`.
    /// All checks are no-ops when `enabled` is false (parking-lot mode).
    pub fn validate(&self, environment: Environment) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        if self.from_address.is_empty() {
            return Err("mailer.from_address is required when mailer is enabled".into());
        }
        if !self.from_address.contains('@') {
            return Err(format!(
                "mailer.from_address {:?} is not a valid email address",
                self.from_address
            ));
        }
        if self.smtp_host.is_empty() {
            return Err("mailer.smtp_host is required when mailer is enabled".into());
        }
        if self.smtp_port == 0 {
            return Err("mailer.smtp_port must be > 0".into());
        }
        if self.base_url.is_empty() {
            return Err("mailer.base_url is required when mailer is enabled".into());
        }
        if environment == Environment::Production && !self.base_url.starts_with("https://") {
            return Err(format!(
                "mailer.base_url must be https:// in production, got {:?}",
                self.base_url
            ));
        }
        if environment == Environment::Production
            && self.smtp_encryption == SmtpEncryption::Plaintext
        {
            return Err("mailer.smtp_encryption = \"plaintext\" is forbidden in production".into());
        }
        if self.batch_size <= 0 {
            return Err("mailer.batch_size must be > 0".into());
        }
        if self.max_attempts <= 0 {
            return Err("mailer.max_attempts must be > 0".into());
        }
        if self.poll_interval_secs == 0 {
            return Err("mailer.poll_interval_secs must be > 0".into());
        }
        if self.smtp_timeout_secs == 0 {
            return Err("mailer.smtp_timeout_secs must be > 0".into());
        }
        if self.broker_timeout_secs == 0 {
            return Err("mailer.broker_timeout_secs must be > 0".into());
        }
        Ok(())
    }
}

impl Default for MailerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            from_address: String::new(),
            from_name: String::new(),
            reply_to: String::new(),
            base_url: String::new(),
            smtp_host: String::new(),
            smtp_port: Self::default_smtp_port(),
            smtp_encryption: Self::default_smtp_encryption(),
            smtp_username: String::new(),
            smtp_password: Self::default_secret_string(),
            helo_name: String::new(),
            poll_interval_secs: Self::default_poll_interval_secs(),
            batch_size: Self::default_batch_size(),
            max_attempts: Self::default_max_attempts(),
            smtp_timeout_secs: Self::default_smtp_timeout_secs(),
            broker_timeout_secs: Self::default_broker_timeout_secs(),
        }
    }
}

impl std::fmt::Debug for MailerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MailerConfig")
            .field("enabled", &self.enabled)
            .field("from_address", &self.from_address)
            .field("from_name", &self.from_name)
            .field("reply_to", &self.reply_to)
            .field("base_url", &self.base_url)
            .field("smtp_host", &self.smtp_host)
            .field("smtp_port", &self.smtp_port)
            .field("smtp_encryption", &self.smtp_encryption)
            .field("smtp_username", &self.smtp_username)
            .field("smtp_password", &"[REDACTED]")
            .field("helo_name", &self.helo_name)
            .field("poll_interval_secs", &self.poll_interval_secs)
            .field("batch_size", &self.batch_size)
            .field("max_attempts", &self.max_attempts)
            .field("smtp_timeout_secs", &self.smtp_timeout_secs)
            .field("broker_timeout_secs", &self.broker_timeout_secs)
            .finish()
    }
}

/// IACS / industrial module configuration.
///
/// Carries the global kill-switch for the EWS onboarding flow introduced
/// as a preliminary scaffolding for future IACS asset support.
///
/// When `enabled` is false:
///   - the IACS sidebar entry is hidden,
///   - the "Onboard EWS" button on `/assets` is hidden,
///   - every `/iacs/*` route returns 404 (anti-enumeration),
///   - `PermissionContext::iacs_*` flags are forced to `false` regardless
///     of the Casbin policy (kill-switch precedence).
///
/// Existing rows in `ews_*` tables are preserved on disk (the kill-switch
/// only affects the UI / API surface). Re-enabling exposes them again.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IndustrialConfig {
    /// Master switch. Default `true` -- the IACS module is part of the
    /// shipped feature set.
    #[serde(default = "IndustrialConfig::default_enabled")]
    pub enabled: bool,

    /// Maximum number of EWS (active + pending) per user. `0` means
    /// no limit. Default `0`. The cap is enforced inside the
    /// `vauban-access` `SubmitEwsOnboarding` transaction.
    #[serde(default = "IndustrialConfig::default_max_ews_per_user")]
    pub max_ews_per_user: u32,

    /// IACS tunnel sub-module (russh server in-process within
    /// `vauban-web`). Optional `[industrial.iacs_tunnel]` TOML
    /// section; when omitted, defaults are used and the sub-module
    /// is enabled iff `industrial.enabled` is also true.
    #[serde(default)]
    pub iacs_tunnel: IacsTunnelConfig,
}

impl IndustrialConfig {
    fn default_enabled() -> bool {
        true
    }

    fn default_max_ews_per_user() -> u32 {
        0
    }
}

impl Default for IndustrialConfig {
    fn default() -> Self {
        Self {
            enabled: Self::default_enabled(),
            max_ews_per_user: Self::default_max_ews_per_user(),
            iacs_tunnel: IacsTunnelConfig::default(),
        }
    }
}

/// Configuration for the in-process IACS tunnel sshd, exposed under
/// `[industrial.iacs_tunnel]` in TOML. Lives in `vauban-web` (no new
/// service / no new IPC -- the sshd is a `tokio::spawn` task driven
/// by `russh`).
///
/// Two booleans gate the boot:
///
///   * `industrial.enabled` (parent) -- master kill-switch for the
///     IACS module. When `false` the tunnel server never binds,
///     regardless of this struct.
///   * `industrial.iacs_tunnel.enabled` (this struct) -- per-feature
///     opt-out so an operator can disable IACS tunnels while keeping
///     the rest of the IACS UI alive.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IacsTunnelConfig {
    /// Per-feature switch. Default `true`.
    #[serde(default = "IacsTunnelConfig::default_enabled")]
    pub enabled: bool,

    /// `host:port` the sshd listens on. Default `0.0.0.0:22322`. The
    /// canonical `22` is reserved for the regular VAUBAN proxy on
    /// the same host.
    #[serde(default = "IacsTunnelConfig::default_bind_addr")]
    pub bind_addr: String,

    /// Public hostname advertised to operators on the status page
    /// (`ssh -L ... user@<advertise_hostname> -p ...`). Defaults to
    /// `localhost`; production deployments should set this to the
    /// bastion FQDN reachable from EWS hosts.
    #[serde(default = "IacsTunnelConfig::default_advertise_hostname")]
    pub advertise_hostname: String,

    /// Target `host:port` the bastion will tunnel each accepted
    /// `direct-tcpip` channel to. Default `127.0.0.1:4321` (the MVP
    /// fixed target until L6 wires the per-asset hostname:port).
    #[serde(default = "IacsTunnelConfig::default_target_addr")]
    pub target_addr: String,

    /// Filesystem path of the ed25519 host key. Generated on first
    /// boot if absent; created with mode 0600.
    #[serde(default = "IacsTunnelConfig::default_host_key_path")]
    pub host_key_path: String,

    /// Maximum number of concurrent IACS tunnels per user. `0`
    /// disables the cap. Default `4`.
    #[serde(default = "IacsTunnelConfig::default_max_concurrent_per_user")]
    pub max_concurrent_per_user: u32,

    /// Maximum number of concurrent IACS tunnels per EWS. `0`
    /// disables the cap. Default `2`.
    #[serde(default = "IacsTunnelConfig::default_max_concurrent_per_ews")]
    pub max_concurrent_per_ews: u32,

    /// Time-to-live in seconds of a `waiting_client` row before the
    /// watchdog flips it to `expired`. Default `300` (5 min).
    #[serde(default = "IacsTunnelConfig::default_waiting_client_ttl_seconds")]
    pub waiting_client_ttl_seconds: u32,

    /// Polling interval in seconds for the revocation watchdog.
    /// Default `2`. The watchdog SELECTs IACS rows with disabled /
    /// offboarded EWS or deactivated users and force-closes them.
    #[serde(default = "IacsTunnelConfig::default_revocation_poll_interval_seconds")]
    pub revocation_poll_interval_seconds: u32,
}

impl IacsTunnelConfig {
    fn default_enabled() -> bool {
        true
    }
    fn default_bind_addr() -> String {
        "0.0.0.0:22322".to_string()
    }
    fn default_advertise_hostname() -> String {
        "localhost".to_string()
    }
    fn default_target_addr() -> String {
        "127.0.0.1:4321".to_string()
    }
    fn default_host_key_path() -> String {
        "/var/lib/vauban/iacs_tunnel_host_ed25519".to_string()
    }
    fn default_max_concurrent_per_user() -> u32 {
        4
    }
    fn default_max_concurrent_per_ews() -> u32 {
        2
    }
    fn default_waiting_client_ttl_seconds() -> u32 {
        300
    }
    fn default_revocation_poll_interval_seconds() -> u32 {
        2
    }

    /// Parse `bind_addr` into `(host, port)`, defaulting on parse
    /// errors so a malformed config still surfaces a *displayed*
    /// port on the status page (the boot-time validation happens
    /// in L3).
    pub fn bind_port(&self) -> u16 {
        self.bind_addr
            .rsplit_once(':')
            .and_then(|(_, p)| p.parse().ok())
            .unwrap_or(22322)
    }
}

impl Default for IacsTunnelConfig {
    fn default() -> Self {
        Self {
            enabled: Self::default_enabled(),
            bind_addr: Self::default_bind_addr(),
            advertise_hostname: Self::default_advertise_hostname(),
            target_addr: Self::default_target_addr(),
            host_key_path: Self::default_host_key_path(),
            max_concurrent_per_user: Self::default_max_concurrent_per_user(),
            max_concurrent_per_ews: Self::default_max_concurrent_per_ews(),
            waiting_client_ttl_seconds: Self::default_waiting_client_ttl_seconds(),
            revocation_poll_interval_seconds: Self::default_revocation_poll_interval_seconds(),
        }
    }
}

// =============================================================================
// PRODUCT / BRANDING (white-label)
// =============================================================================

/// White-label container. Currently only nests the brand block; future
/// product-level options (legal notice text, support email, ...) will
/// land here without breaking the existing `[product.brand]` namespace.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct ProductConfig {
    #[serde(default)]
    pub brand: BrandConfig,
}

/// Brand block. The single moving piece is `name`, which is rendered
/// in the top-left of every sidebar-bearing page via the Askama
/// template `partials/sidebar_content.html`.
///
/// # Special-cased values
///
/// - `"VAUBAN"` (default): the canonical wordmark is rendered.
/// - any other value: the wordmark is replaced by the visual
///   representation associated with that brand (currently only one
///   such mapping exists -- `"BAŞKESEN"` swaps in the Turkish flag
///   as an embedded SVG). A value that is neither `"VAUBAN"` nor a
///   known white-label key falls back to the default wordmark, so
///   the sidebar never breaks visually if an operator introduces a
///   typo or sets an unrecognised name.
///
/// The contract is intentionally string-based (rather than an enum)
/// so future white-label brands can be added by extending the
/// template's match arms without a config schema change.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BrandConfig {
    #[serde(default = "BrandConfig::default_name")]
    pub name: String,
}

impl BrandConfig {
    /// Canonical default brand name. Kept as a const so unit tests
    /// and the [`crate::templates::base::VaubanConfig`] fallback can
    /// reference the exact same literal.
    pub const DEFAULT_NAME: &'static str = "VAUBAN";

    fn default_name() -> String {
        Self::DEFAULT_NAME.to_string()
    }
}

impl Default for BrandConfig {
    fn default() -> Self {
        Self {
            name: Self::default_name(),
        }
    }
}

impl Config {
    /// Load configuration from TOML files.
    ///
    /// Automatically finds the configuration directory in this order:
    /// 1. VAUBAN_CONFIG_DIR environment variable (if set)
    /// 2. Workspace root config/ directory (development)
    /// 3. /usr/local/etc/vauban/ (production on FreeBSD)
    ///
    /// Then loads configuration:
    /// - Production (default): vauban.conf only
    /// - Development: default.toml + development.toml + local.toml
    /// - Testing: default.toml + testing.toml
    pub fn load() -> Result<Self, crate::error::AppError> {
        let config_path = Self::find_config_dir()?;
        Self::load_from_path(config_path)
    }

    /// Find the configuration directory.
    ///
    /// Searches in the following order:
    /// 1. VAUBAN_CONFIG_DIR environment variable (if set)
    /// 2. Workspace root config/ directory (based on CARGO_MANIFEST_DIR)
    /// 3. /usr/local/etc/vauban/ (production on FreeBSD)
    fn find_config_dir() -> Result<PathBuf, crate::error::AppError> {
        // 1. Check for explicit VAUBAN_CONFIG_DIR environment variable
        if let Ok(path) = std::env::var("VAUBAN_CONFIG_DIR") {
            let config_path = PathBuf::from(&path);
            if config_path.exists() {
                return Ok(config_path);
            }
            return Err(crate::error::AppError::Config(format!(
                "VAUBAN_CONFIG_DIR points to non-existent directory: {}",
                path
            )));
        }

        // 2. Check workspace root config/ directory (development)
        // CARGO_MANIFEST_DIR is set at compile time to the crate's directory (vauban-web/)
        // We go up one level to reach the workspace root
        let workspace_config = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .map(|p| p.join("config"));
        if let Some(ref config_path) = workspace_config
            && config_path.exists()
        {
            return Ok(config_path.clone());
        }

        // 3. Check system configuration directory (production on FreeBSD)
        let system_config = Path::new("/usr/local/etc/vauban");
        if system_config.exists() {
            return Ok(system_config.to_path_buf());
        }

        // No configuration directory found
        Err(crate::error::AppError::Config(
            "Configuration directory not found. Searched:\n\
             - VAUBAN_CONFIG_DIR environment variable\n\
             - Workspace root config/ directory\n\
             - /usr/local/etc/vauban/"
                .to_string(),
        ))
    }

    /// Get the workspace root directory.
    ///
    /// Uses CARGO_MANIFEST_DIR (set at compile time) to find the vauban-web crate,
    /// then goes up one level to get the workspace root.
    fn workspace_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf()
    }

    /// Resolve relative paths in configuration to absolute paths.
    ///
    /// This ensures paths work correctly regardless of the current working directory.
    /// Paths starting with "/" are considered absolute and left unchanged.
    /// Relative paths are resolved relative to the workspace root.
    fn resolve_paths(&mut self) {
        let workspace_root = Self::workspace_root();

        // Resolve TLS certificate paths
        self.server.tls.cert_path = Self::resolve_path(&workspace_root, &self.server.tls.cert_path);
        self.server.tls.key_path = Self::resolve_path(&workspace_root, &self.server.tls.key_path);
        if let Some(ref ca_path) = self.server.tls.ca_chain_path {
            self.server.tls.ca_chain_path = Some(Self::resolve_path(&workspace_root, ca_path));
        }

        // Resolve ACME account key path
        if let Some(ref mut acme) = self.server.tls.acme
            && !acme.account_key_path.is_empty()
        {
            acme.account_key_path = Self::resolve_path(&workspace_root, &acme.account_key_path);
        }
    }

    /// Resolve a single path relative to the workspace root.
    ///
    /// - Absolute paths (starting with "/") are returned unchanged.
    /// - Relative paths are joined with the workspace root.
    fn resolve_path(workspace_root: &Path, path: &str) -> String {
        if path.starts_with('/') {
            // Absolute path, leave unchanged
            path.to_string()
        } else {
            // Relative path, resolve from workspace root
            workspace_root.join(path).to_string_lossy().to_string()
        }
    }

    /// Load configuration from a specific directory path.
    pub fn load_from_path<P: AsRef<Path>>(config_path: P) -> Result<Self, crate::error::AppError> {
        let config_path = config_path.as_ref();

        let environment = std::env::var("VAUBAN_ENVIRONMENT")
            .map(|e| Environment::parse(&e))
            .unwrap_or(Environment::Production);

        Self::load_with_environment(config_path, environment)
    }

    /// Load configuration with a specific environment.
    pub fn load_with_environment<P: AsRef<Path>>(
        config_path: P,
        environment: Environment,
    ) -> Result<Self, crate::error::AppError> {
        let config_path = config_path.as_ref();

        let mut builder = ConfigBuilder::builder();

        if environment.is_production() {
            // Production: single self-contained config file
            let conf_path = config_path.join("vauban.conf");
            let contents = std::fs::read_to_string(&conf_path).map_err(|e| {
                crate::error::AppError::Config(format!(
                    "Failed to read config file {}: {}",
                    conf_path.display(),
                    e
                ))
            })?;
            builder =
                builder.add_source(config::File::from_str(&contents, config::FileFormat::Toml));
        } else {
            // Development / Testing: layered config files
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

        // 4. Override secret_key from VAUBAN_SECRET_KEY if set
        if let Ok(secret) = std::env::var("VAUBAN_SECRET_KEY") {
            // Clear the environment variable immediately after reading.
            // The secret is moved into the config builder; keeping it in the
            // environment would expose it to child processes and to readers
            // of /proc/PID/environ.
            //
            // SAFETY: This is called during single-threaded configuration loading
            // in main(), before the Tokio runtime is started.  No other thread
            // is reading the environment concurrently.
            unsafe {
                std::env::remove_var("VAUBAN_SECRET_KEY");
            }
            builder = builder.set_override("secret_key", secret).map_err(|e| {
                crate::error::AppError::Config(format!("Failed to set secret_key: {}", e))
            })?;
        }

        // 5. Override SMTP credentials (Issue #10) -- VAUBAN_SMTP_USERNAME
        //    and VAUBAN_SMTP_PASSWORD. Same env-var-erase pattern as
        //    VAUBAN_SECRET_KEY: read once, scrub from /proc/PID/environ.
        if let Ok(username) = std::env::var("VAUBAN_SMTP_USERNAME") {
            // SAFETY: same as VAUBAN_SECRET_KEY; called single-threaded
            // before the Tokio runtime is started.
            unsafe {
                std::env::remove_var("VAUBAN_SMTP_USERNAME");
            }
            builder = builder
                .set_override("mailer.smtp_username", username)
                .map_err(|e| {
                    crate::error::AppError::Config(format!(
                        "Failed to set mailer.smtp_username: {}",
                        e
                    ))
                })?;
        }
        if let Ok(password) = std::env::var("VAUBAN_SMTP_PASSWORD") {
            // SAFETY: same as VAUBAN_SECRET_KEY.
            unsafe {
                std::env::remove_var("VAUBAN_SMTP_PASSWORD");
            }
            builder = builder
                .set_override("mailer.smtp_password", password)
                .map_err(|e| {
                    crate::error::AppError::Config(format!(
                        "Failed to set mailer.smtp_password: {}",
                        e
                    ))
                })?;
        }

        // Build configuration
        let settings = builder.build().map_err(Self::config_error)?;

        // Deserialize into Config
        let mut config: Config = settings.try_deserialize().map_err(Self::config_error)?;

        // Force environment in case it's not in the file
        config.environment = environment;

        // Resolve relative paths to absolute paths based on workspace root
        config.resolve_paths();

        // Validate that secret_key is set
        if config.secret_key.expose_secret().is_empty() {
            return Err(crate::error::AppError::Config(
                "secret_key is required. Set it in config/{environment}.toml, config/local.toml, \
                 or via VAUBAN_SECRET_KEY environment variable."
                    .to_string(),
            ));
        }

        // Validate recording hydrator knobs (e.g. cron hour must be 0..=23).
        config
            .recording
            .validate()
            .map_err(crate::error::AppError::Config)?;

        // Validate mailer block (Issue #10). No-op when disabled; in
        // production it requires from_address, smtp_host, https base_url,
        // and rejects plaintext SMTP.
        config
            .mailer
            .validate(config.environment)
            .map_err(crate::error::AppError::Config)?;

        Ok(config)
    }

    /// Load configuration directly from a TOML string.
    /// Useful for testing.
    pub fn from_toml(toml_content: &str) -> Result<Self, crate::error::AppError> {
        let settings = ConfigBuilder::builder()
            .add_source(config::File::from_str(
                toml_content,
                config::FileFormat::Toml,
            ))
            .build()
            .map_err(Self::config_error)?;

        settings.try_deserialize().map_err(Self::config_error)
    }

    /// Load configuration from multiple TOML strings (base + overlay).
    /// Useful for testing with base configuration + test-specific overrides.
    pub fn from_toml_with_overlay(
        base_toml: &str,
        overlay_toml: &str,
    ) -> Result<Self, crate::error::AppError> {
        let settings = ConfigBuilder::builder()
            .add_source(config::File::from_str(base_toml, config::FileFormat::Toml))
            .add_source(config::File::from_str(
                overlay_toml,
                config::FileFormat::Toml,
            ))
            .build()
            .map_err(Self::config_error)?;

        settings.try_deserialize().map_err(Self::config_error)
    }

    fn config_error(e: ConfigError) -> crate::error::AppError {
        crate::error::AppError::Config(format!("Configuration error: {}", e))
    }

    /// Legacy method for backward compatibility.
    /// Prefer `Config::load()` for new uses.
    #[deprecated(since = "0.2.0", note = "Use Config::load() instead")]
    pub fn from_env() -> Result<Self, crate::error::AppError> {
        Self::load()
    }
}

/// Test configuration module.
/// Provides test fixtures loaded from config files.
#[cfg(test)]
pub mod test_fixtures {
    use std::path::PathBuf;

    /// Get the path to the workspace root config/ directory.
    /// Uses CARGO_MANIFEST_DIR to locate the workspace root.
    pub fn config_dir() -> PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("Failed to get workspace root")
            .join("config")
    }

    /// Base configuration TOML for tests (mirrors config/default.toml).
    /// This is loaded from the actual config file at test time.
    /// Path is relative to workspace root (../../config/ from vauban-web/src/).
    pub fn base_config() -> &'static str {
        include_str!("../../config/default.toml")
    }

    /// Testing environment configuration.
    pub fn testing_config() -> &'static str {
        include_str!("../../config/testing.toml")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== ProductConfig / BrandConfig (white-label) ====================

    /// Default contract: a TOML file that omits the `[product]` section
    /// MUST behave as if the operator had explicitly written
    /// `[product.brand] name = "VAUBAN"`. Without this, the sidebar
    /// would silently render an empty wordmark on every existing
    /// deployment that has not yet migrated its `vauban.conf`.
    #[test]
    fn brand_config_default_is_vauban() {
        let cfg = BrandConfig::default();
        assert_eq!(cfg.name, "VAUBAN");
        assert_eq!(cfg.name, BrandConfig::DEFAULT_NAME);
    }

    #[test]
    fn product_config_default_brand_is_vauban() {
        let cfg = ProductConfig::default();
        assert_eq!(cfg.brand.name, "VAUBAN");
    }

    /// Helper: parse `<toml_str>` through the SAME parser the
    /// production loader uses (`config::File::from_str` +
    /// `try_deserialize`). Goes through `config::Value` first so an
    /// unknown top-level field doesn't fail; the goal is to pin the
    /// `[product.brand]` deserialisation, not the full Config schema.
    fn parse_product_section(toml_str: &str) -> ProductConfig {
        #[derive(Deserialize)]
        struct Wrapper {
            #[serde(default)]
            product: ProductConfig,
        }
        let settings = config::Config::builder()
            .add_source(config::File::from_str(toml_str, config::FileFormat::Toml))
            .build()
            .expect("toml builds");
        let wrapped: Wrapper = settings.try_deserialize().expect("deserialize");
        wrapped.product
    }

    /// Round-trip: the canonical TOML shape `[product.brand]` with
    /// `name = "VAUBAN"` parses into the matching struct via the
    /// production parser.
    #[test]
    fn product_config_parses_canonical_toml() {
        let toml_str = r#"
            [product.brand]
            name = "VAUBAN"
        "#;
        let cfg = parse_product_section(toml_str);
        assert_eq!(cfg.brand.name, "VAUBAN");
    }

    /// White-label round-trip: an operator that writes the special
    /// value `"BAŞKESEN"` (the string the sidebar template uses to
    /// pivot to the Turkish-flag SVG) parses byte-for-byte without
    /// any normalisation. The dotted Turkish "Ş" (U+015E) MUST
    /// round-trip cleanly through TOML's UTF-8 layer.
    #[test]
    fn product_config_parses_baskesen_with_turkish_s() {
        let toml_str = r#"
            [product.brand]
            name = "BAŞKESEN"
        "#;
        let cfg = parse_product_section(toml_str);
        assert_eq!(cfg.brand.name, "BAŞKESEN");
        // Defensive byte-level pin: the Turkish "Ş" (U+015E) is
        // encoded as 0xC5 0x9E in UTF-8. A normalisation regression
        // (e.g. NFKC fold to "S") would break the template match.
        assert!(
            cfg.brand.name.contains('Ş'),
            "Turkish capital S with cedilla MUST round-trip; got {:?}",
            cfg.brand.name
        );
    }

    /// Missing `[product]` section -> default brand. This pins the
    /// "no white-label by default" contract.
    #[test]
    fn config_without_product_section_defaults_to_vauban() {
        let parsed = parse_product_section("# no [product] section\n");
        assert_eq!(parsed.brand.name, "VAUBAN");
    }

    /// Empty `[product]` section but missing `[product.brand]` ->
    /// `brand` falls back to its own default (`name = "VAUBAN"`).
    /// Pins that the inner `#[serde(default)]` works independently
    /// of the outer one.
    #[test]
    fn product_section_without_brand_block_defaults_to_vauban() {
        let cfg = parse_product_section("[product]\n");
        assert_eq!(cfg.brand.name, "VAUBAN");
    }

    // ==================== RecordingConfig::validate (issue #29 v1.4) ====================

    #[test]
    fn test_recording_config_validate_accepts_default() {
        let cfg = RecordingConfig::default();
        assert!(
            cfg.validate().is_ok(),
            "default RecordingConfig must validate"
        );
    }

    #[test]
    fn test_recording_config_validate_accepts_lower_bound() {
        let cfg = RecordingConfig {
            hydration_daily_cron_hour_utc: 0,
            ..RecordingConfig::default()
        };
        assert!(cfg.validate().is_ok(), "hour 0 (midnight UTC) is valid");
    }

    #[test]
    fn test_recording_config_validate_accepts_upper_bound() {
        let cfg = RecordingConfig {
            hydration_daily_cron_hour_utc: 23,
            ..RecordingConfig::default()
        };
        assert!(
            cfg.validate().is_ok(),
            "hour 23 is the upper inclusive bound"
        );
    }

    #[test]
    fn test_recording_config_validate_rejects_24() {
        let cfg = RecordingConfig {
            hydration_daily_cron_hour_utc: 24,
            ..RecordingConfig::default()
        };
        let err = cfg.validate().expect_err("hour 24 must be rejected");
        assert!(
            err.contains("0..=23"),
            "error message must mention the valid range, got: {}",
            err
        );
    }

    #[test]
    fn test_recording_config_validate_skipped_when_disabled() {
        // When the hydrator is disabled, an out-of-range cron hour is
        // not checked (the cron will not run anyway). This avoids
        // breaking deployments that don't use the hydrator.
        let cfg = RecordingConfig {
            hydration_enabled: false,
            hydration_daily_cron_hour_utc: 99,
            ..RecordingConfig::default()
        };
        assert!(
            cfg.validate().is_ok(),
            "validation skipped when hydration_enabled=false"
        );
    }

    #[test]
    fn test_recording_config_defaults_match_documentation() {
        // Pin the defaults documented in
        // docs/technical/Vauban_Recording_Architecture_EN(1.3).md.
        // Changing them is a deliberate operational decision -- the
        // doc + runbook MUST be updated in lock-step.
        let cfg = RecordingConfig::default();
        assert_eq!(
            cfg.hydration_enqueue_delay_secs, 5,
            "PRIMARY enqueue grace period documented as 5s"
        );
        assert_eq!(
            cfg.hydration_missing_meta_grace_secs, 300,
            "SAFETY-net missing-meta grace documented as 300s (5min)"
        );
        assert_eq!(
            cfg.hydration_daily_cron_hour_utc, 4,
            "daily reconciliation documented at 04:00 UTC"
        );
        assert_eq!(
            cfg.hydration_batch_size, 50,
            "bootstrap batch size documented as 50"
        );
    }

    // ==================== Environment Tests ====================

    #[test]
    fn test_environment_parse_development() {
        assert_eq!(Environment::parse("development"), Environment::Development);
        assert_eq!(Environment::parse("dev"), Environment::Development);
    }

    #[test]
    fn test_environment_parse_testing() {
        assert_eq!(Environment::parse("testing"), Environment::Testing);
        assert_eq!(Environment::parse("test"), Environment::Testing);
    }

    #[test]
    fn test_environment_parse_production() {
        assert_eq!(Environment::parse("production"), Environment::Production);
        assert_eq!(Environment::parse("prod"), Environment::Production);
    }

    #[test]
    fn test_environment_parse_unknown() {
        assert_eq!(Environment::parse("unknown"), Environment::Production);
        assert_eq!(Environment::parse(""), Environment::Production);
    }

    #[test]
    fn test_environment_parse_case_insensitive() {
        assert_eq!(Environment::parse("DEVELOPMENT"), Environment::Development);
        assert_eq!(Environment::parse("PRODUCTION"), Environment::Production);
        assert_eq!(Environment::parse("Testing"), Environment::Testing);
    }

    #[test]
    fn test_environment_as_str() {
        assert_eq!(Environment::Development.as_str(), "development");
        assert_eq!(Environment::Testing.as_str(), "testing");
        assert_eq!(Environment::Production.as_str(), "production");
    }

    #[test]
    fn test_environment_is_development() {
        assert!(Environment::Development.is_development());
        assert!(!Environment::Testing.is_development());
        assert!(!Environment::Production.is_development());
    }

    #[test]
    fn test_environment_is_production() {
        assert!(!Environment::Development.is_production());
        assert!(!Environment::Testing.is_production());
        assert!(Environment::Production.is_production());
    }

    #[test]
    fn test_environment_roundtrip() {
        for env in [
            Environment::Development,
            Environment::Testing,
            Environment::Production,
        ] {
            let str_val = env.as_str();
            let parsed = Environment::parse(str_val);
            assert_eq!(env, parsed);
        }
    }

    // ==================== LogFormat Tests ====================

    #[test]
    fn test_log_format_default() {
        let format = LogFormat::default();
        assert_eq!(format, LogFormat::Text);
    }

    #[test]
    fn test_log_format_parse_json() {
        assert_eq!(LogFormat::parse("json"), LogFormat::Json);
        assert_eq!(LogFormat::parse("JSON"), LogFormat::Json);
    }

    #[test]
    fn test_log_format_parse_text() {
        assert_eq!(LogFormat::parse("text"), LogFormat::Text);
        assert_eq!(LogFormat::parse("TEXT"), LogFormat::Text);
    }

    #[test]
    fn test_log_format_parse_unknown() {
        // Unknown values default to Text
        assert_eq!(LogFormat::parse("unknown"), LogFormat::Text);
        assert_eq!(LogFormat::parse(""), LogFormat::Text);
    }

    #[test]
    fn test_log_format_is_json() {
        assert!(LogFormat::Json.is_json());
        assert!(!LogFormat::Text.is_json());
    }

    // ==================== Config Loading Tests ====================

    #[test]
    fn test_config_load_from_config_dir() {
        // Load configuration from config/ directory
        let config = unwrap_ok!(Config::load_with_environment(
            test_fixtures::config_dir(),
            Environment::Testing
        ));

        assert_eq!(config.environment, Environment::Testing);
        assert!(!config.secret_key.expose_secret().is_empty());
    }

    #[test]
    fn test_config_from_toml_with_overlay() {
        let base = test_fixtures::base_config();
        let overlay = test_fixtures::testing_config();

        let config = unwrap_ok!(Config::from_toml_with_overlay(base, overlay));

        assert_eq!(config.environment, Environment::Testing);
    }

    #[test]
    fn test_config_from_toml_missing_required_fields() {
        let incomplete_toml = r#"
            environment = "testing"
            # Missing secret_key and other required fields
        "#;

        let result = Config::from_toml(incomplete_toml);
        assert!(result.is_err());
    }

    #[test]
    fn test_config_values_from_testing_toml() {
        let config = unwrap_ok!(Config::load_with_environment(
            test_fixtures::config_dir(),
            Environment::Testing
        ));

        // Values should come from config/testing.toml
        assert_eq!(config.logging.level, "warn");
        assert!(!config.cache.enabled);
    }

    #[test]
    fn test_config_values_from_default_toml() {
        let config = unwrap_ok!(Config::load_with_environment(
            test_fixtures::config_dir(),
            Environment::Development
        ));

        // Server values should come from config/default.toml (or development.toml)
        assert!(config.server.port > 0);
        assert!(!config.server.host.is_empty());
    }

    #[test]
    fn test_config_database_values() {
        let config = unwrap_ok!(Config::load_with_environment(
            test_fixtures::config_dir(),
            Environment::Testing
        ));

        // Database URL should be set
        assert!(!config.database.url.expose_secret().is_empty());
        assert!(config.database.max_connections > 0);
    }

    #[test]
    fn test_config_security_values() {
        let config = unwrap_ok!(Config::load_with_environment(
            test_fixtures::config_dir(),
            Environment::Testing
        ));

        // Security values should be reasonable
        assert!(config.security.password_min_length >= 8);
        assert!(config.security.max_failed_login_attempts > 0);
    }

    #[test]
    fn test_config_jwt_values() {
        let config = unwrap_ok!(Config::load_with_environment(
            test_fixtures::config_dir(),
            Environment::Testing
        ));

        // JWT values should be set
        assert!(config.jwt.access_token_lifetime_minutes > 0);
        assert!(!config.jwt.algorithm.is_empty());
    }

    // ==================== Environment Additional Tests ====================

    #[test]
    fn test_environment_debug() {
        let env = Environment::Development;
        let debug_str = format!("{:?}", env);
        assert!(debug_str.contains("Development"));
    }

    #[test]
    fn test_environment_clone() {
        let env = Environment::Production;
        let cloned = env;
        assert_eq!(env, cloned);
    }

    #[test]
    fn test_environment_default() {
        let env = Environment::default();
        assert_eq!(env, Environment::Production);
    }

    #[test]
    fn test_environment_serialize() {
        let env = Environment::Testing;
        let json = unwrap_ok!(serde_json::to_string(&env));
        assert!(json.contains("testing"));
    }

    #[test]
    fn test_environment_deserialize() {
        let json = r#""production""#;
        let env: Environment = unwrap_ok!(serde_json::from_str(json));
        assert_eq!(env, Environment::Production);
    }

    // ==================== LogFormat Additional Tests ====================

    #[test]
    fn test_log_format_debug() {
        let format = LogFormat::Json;
        let debug_str = format!("{:?}", format);
        assert!(debug_str.contains("Json"));
    }

    #[test]
    fn test_log_format_clone() {
        let format = LogFormat::Text;
        let cloned = format;
        assert_eq!(format, cloned);
    }

    #[test]
    fn test_log_format_is_json_text() {
        assert!(!LogFormat::Text.is_json());
    }

    #[test]
    fn test_log_format_is_json_json() {
        assert!(LogFormat::Json.is_json());
    }

    // ==================== Config Struct Tests ====================

    #[test]
    fn test_config_clone() {
        let config = unwrap_ok!(Config::load_with_environment(
            test_fixtures::config_dir(),
            Environment::Testing
        ));
        let cloned = config.clone();
        assert_eq!(config.environment, cloned.environment);
    }

    #[test]
    fn test_config_debug() {
        let config = unwrap_ok!(Config::load_with_environment(
            test_fixtures::config_dir(),
            Environment::Testing
        ));
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("Config"));
    }

    // ==================== Sub-Config Tests ====================

    #[test]
    fn test_database_config_debug() {
        let config = unwrap_ok!(Config::load_with_environment(
            test_fixtures::config_dir(),
            Environment::Testing
        ));
        let debug_str = format!("{:?}", config.database);
        assert!(debug_str.contains("DatabaseConfig"));
    }

    #[test]
    fn test_server_config_debug() {
        let config = unwrap_ok!(Config::load_with_environment(
            test_fixtures::config_dir(),
            Environment::Testing
        ));
        let debug_str = format!("{:?}", config.server);
        assert!(debug_str.contains("ServerConfig"));
    }

    #[test]
    fn test_cache_config_debug() {
        let config = unwrap_ok!(Config::load_with_environment(
            test_fixtures::config_dir(),
            Environment::Testing
        ));
        let debug_str = format!("{:?}", config.cache);
        assert!(debug_str.contains("CacheConfig"));
    }

    #[test]
    fn test_jwt_config_debug() {
        let config = unwrap_ok!(Config::load_with_environment(
            test_fixtures::config_dir(),
            Environment::Testing
        ));
        let debug_str = format!("{:?}", config.jwt);
        assert!(debug_str.contains("JwtConfig"));
    }

    #[test]
    fn test_security_config_debug() {
        let config = unwrap_ok!(Config::load_with_environment(
            test_fixtures::config_dir(),
            Environment::Testing
        ));
        let debug_str = format!("{:?}", config.security);
        assert!(debug_str.contains("SecurityConfig"));
    }

    #[test]
    fn test_logging_config_debug() {
        let config = unwrap_ok!(Config::load_with_environment(
            test_fixtures::config_dir(),
            Environment::Testing
        ));
        let debug_str = format!("{:?}", config.logging);
        assert!(debug_str.contains("LoggingConfig"));
    }

    #[test]
    fn test_tls_config_debug() {
        let config = unwrap_ok!(Config::load_with_environment(
            test_fixtures::config_dir(),
            Environment::Testing
        ));
        let debug_str = format!("{:?}", config.server.tls);
        assert!(debug_str.contains("TlsConfig"));
    }

    #[test]
    fn test_argon2_config_debug() {
        let config = unwrap_ok!(Config::load_with_environment(
            test_fixtures::config_dir(),
            Environment::Testing
        ));
        let debug_str = format!("{:?}", config.security.argon2);
        assert!(debug_str.contains("Argon2Config"));
    }

    // ==================== TLS Certificate Path Tests ====================
    // These tests prevent regressions where certificate paths become invalid
    // after configuration changes (e.g., moving config files).

    /// Get the workspace root directory.
    fn workspace_root() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("Failed to get workspace root")
            .to_path_buf()
    }

    #[test]
    fn test_tls_cert_paths_exist_in_development() {
        let config = unwrap_ok!(Config::load_with_environment(
            test_fixtures::config_dir(),
            Environment::Development
        ));

        let workspace = workspace_root();
        let cert_path = workspace.join(&config.server.tls.cert_path);
        let key_path = workspace.join(&config.server.tls.key_path);

        assert!(
            cert_path.exists(),
            "Development TLS certificate not found at: {}. \
             Run ./vauban-web/scripts/generate-dev-certs.sh to generate.",
            cert_path.display()
        );
        assert!(
            key_path.exists(),
            "Development TLS private key not found at: {}. \
             Run ./vauban-web/scripts/generate-dev-certs.sh to generate.",
            key_path.display()
        );
    }

    #[test]
    fn test_tls_cert_paths_exist_in_testing() {
        let config = unwrap_ok!(Config::load_with_environment(
            test_fixtures::config_dir(),
            Environment::Testing
        ));

        let workspace = workspace_root();
        let cert_path = workspace.join(&config.server.tls.cert_path);
        let key_path = workspace.join(&config.server.tls.key_path);

        assert!(
            cert_path.exists(),
            "Testing TLS certificate not found at: {}. \
             Run ./vauban-web/scripts/generate-dev-certs.sh to generate.",
            cert_path.display()
        );
        assert!(
            key_path.exists(),
            "Testing TLS private key not found at: {}. \
             Run ./vauban-web/scripts/generate-dev-certs.sh to generate.",
            key_path.display()
        );
    }

    #[test]
    fn test_tls_cert_paths_are_resolved_to_absolute() {
        // Verify that development/testing cert paths are resolved to absolute paths
        // This ensures they work regardless of the current working directory
        let dev_config = unwrap_ok!(Config::load_with_environment(
            test_fixtures::config_dir(),
            Environment::Development
        ));

        // Paths should be absolute (start with /)
        assert!(
            dev_config.server.tls.cert_path.starts_with('/'),
            "Development cert_path should be resolved to absolute path, got: {}",
            dev_config.server.tls.cert_path
        );
        assert!(
            dev_config.server.tls.key_path.starts_with('/'),
            "Development key_path should be resolved to absolute path, got: {}",
            dev_config.server.tls.key_path
        );

        // Paths should contain the workspace structure
        assert!(
            dev_config
                .server
                .tls
                .cert_path
                .contains("vauban-web/certs/"),
            "Development cert_path should be in vauban-web/certs/, got: {}",
            dev_config.server.tls.cert_path
        );
    }

    #[test]
    fn test_production_tls_paths_are_absolute() {
        let production_toml = include_str!("../../config/vauban.conf");

        // Verify production config uses absolute FreeBSD paths
        assert!(
            production_toml.contains("cert_path = \"/usr/local/"),
            "Production cert_path should use FreeBSD /usr/local/ path"
        );
        assert!(
            production_toml.contains("key_path = \"/usr/local/"),
            "Production key_path should use FreeBSD /usr/local/ path"
        );
    }

    // ==================== OptionalSecret Zeroize Tests ====================

    #[test]
    fn test_optional_secret_zeroize_on_drop() {
        // Verify that the Zeroize trait correctly zeros a String's buffer.
        // We test this directly on a String (which is what OptionalSecret::drop calls)
        // because inspecting freed memory after Drop is UB and unreliable.
        use zeroize::Zeroize;

        let mut secret = String::from("super_secret_value_12345");
        let ptr = secret.as_ptr();
        let len = secret.len();

        // Verify the String has non-zero content before zeroize
        let bytes_before = unsafe { std::slice::from_raw_parts(ptr, len) };
        assert!(
            bytes_before.iter().any(|&b| b != 0),
            "String should have non-zero content before zeroize"
        );

        // Call zeroize (this is what our Drop impl calls)
        secret.zeroize();

        // The String's heap buffer should now be all zeros
        // (String::zeroize overwrites the buffer, then truncates to len 0,
        //  but the capacity remains allocated so we can still read via the pointer)
        let bytes_after = unsafe { std::slice::from_raw_parts(ptr, len) };
        assert!(
            bytes_after.iter().all(|&b| b == 0),
            "String buffer should be zeroized after Zeroize::zeroize()"
        );
    }

    #[test]
    fn test_optional_secret_none_drop_is_safe() {
        // Dropping a None OptionalSecret should not panic
        let secret = OptionalSecret::new(None);
        drop(secret);
    }

    #[test]
    fn test_optional_secret_functional_after_zeroize_impl() {
        // Verify that adding Drop didn't break normal functionality
        let secret = OptionalSecret::new(Some("test_value".to_string()));
        assert!(secret.is_some());
        assert!(!secret.is_none());
        assert_eq!(secret.as_ref(), Some("test_value"));
        assert_eq!(secret.to_string(), Some("test_value".to_string()));

        let cloned = secret.clone();
        assert_eq!(cloned.as_ref(), Some("test_value"));

        let secret_string = secret.as_secret();
        assert!(secret_string.is_some());

        let into = cloned.into_secret();
        assert!(into.is_some());
    }

    #[test]
    fn test_optional_secret_debug_still_redacts() {
        let secret = OptionalSecret::new(Some("should_not_appear".to_string()));
        let debug = format!("{:?}", secret);
        assert_eq!(debug, "[REDACTED]");
        assert!(!debug.contains("should_not_appear"));

        let none_secret = OptionalSecret::new(None);
        let debug_none = format!("{:?}", none_secret);
        assert_eq!(debug_none, "None");
    }

    #[test]
    fn test_optional_secret_source_has_zeroize_drop() {
        // Structural regression test: verify that the source code contains
        // a Drop impl for OptionalSecret that calls zeroize()
        let source = include_str!("config.rs");
        assert!(
            source.contains("impl Drop for OptionalSecret"),
            "OptionalSecret must have a Drop implementation"
        );
        assert!(
            source.contains("s.zeroize()"),
            "OptionalSecret Drop must call zeroize()"
        );
        assert!(
            source.contains("use zeroize::Zeroize"),
            "config.rs must import zeroize::Zeroize"
        );
    }

    // ==================== VAUBAN_SECRET_KEY env-var clearing Tests ====================

    #[test]
    #[serial_test::serial]
    fn test_env_var_cleared_after_config_load() {
        // When VAUBAN_SECRET_KEY is set, loading configuration must
        // (a) use its value as secret_key, then (b) remove it from the environment.
        let env_secret = "env-secret-for-m4-clearing-test!";

        // Set the env var (single-threaded context, guarded by #[serial])
        unsafe {
            std::env::set_var("VAUBAN_SECRET_KEY", env_secret);
        }
        assert!(
            std::env::var("VAUBAN_SECRET_KEY").is_ok(),
            "pre-condition: VAUBAN_SECRET_KEY should be set"
        );

        let config =
            Config::load_with_environment(test_fixtures::config_dir(), Environment::Testing)
                .expect("Config loading should succeed with VAUBAN_SECRET_KEY set");

        // (a) The env var value must have been picked up
        assert_eq!(
            config.secret_key.expose_secret(),
            env_secret,
            "secret_key should come from VAUBAN_SECRET_KEY when set"
        );

        // (b) The env var must no longer be present
        assert!(
            std::env::var("VAUBAN_SECRET_KEY").is_err(),
            "VAUBAN_SECRET_KEY must be cleared from the environment after loading"
        );
    }

    #[test]
    #[serial_test::serial]
    fn test_toml_secret_key_still_works_without_env_var() {
        // Regression guard: when VAUBAN_SECRET_KEY is NOT set, the secret_key
        // must still be loaded from TOML files (current production path).
        //
        // This is the most important test: we must not break the
        // TOML-based secret_key loading that is the primary usage today.
        unsafe {
            std::env::remove_var("VAUBAN_SECRET_KEY");
        }
        assert!(
            std::env::var("VAUBAN_SECRET_KEY").is_err(),
            "pre-condition: VAUBAN_SECRET_KEY should not be set"
        );

        let config =
            Config::load_with_environment(test_fixtures::config_dir(), Environment::Testing)
                .expect("Config loading should succeed from TOML alone (no env var)");

        // The secret_key from testing.toml must be present
        assert_eq!(
            config.secret_key.expose_secret(),
            "test-secret-key-for-integration-tests!",
            "secret_key must come from testing.toml when VAUBAN_SECRET_KEY is absent"
        );
    }

    #[test]
    #[serial_test::serial]
    fn test_env_var_overrides_toml_secret_key() {
        // When both TOML and env var provide secret_key, the env var wins.
        let env_secret = "env-override-takes-priority-ok!!";

        unsafe {
            std::env::set_var("VAUBAN_SECRET_KEY", env_secret);
        }

        let config =
            Config::load_with_environment(test_fixtures::config_dir(), Environment::Testing)
                .expect("Config loading should succeed with env var override");

        assert_eq!(
            config.secret_key.expose_secret(),
            env_secret,
            "env var should override TOML secret_key"
        );

        // Clean-up: env var should already be cleared by the fix,
        // but verify it as a double-check.
        assert!(
            std::env::var("VAUBAN_SECRET_KEY").is_err(),
            "VAUBAN_SECRET_KEY must be cleared even when overriding TOML"
        );
    }

    #[test]
    fn test_source_has_remove_var() {
        // Structural regression test: the source code must contain
        // remove_var("VAUBAN_SECRET_KEY") to ensure the env var is cleared.
        let source = include_str!("config.rs");
        assert!(
            source.contains(r#"remove_var("VAUBAN_SECRET_KEY")"#),
            "config.rs must call remove_var(\"VAUBAN_SECRET_KEY\") after reading the env var"
        );
    }

    // ==================== SecurityConfig Tests (SEC-03) ====================

    #[test]
    fn test_sec03_require_justification_defaults_to_true() {
        assert!(
            default_require_justification(),
            "require_justification must default to true"
        );
    }

    #[test]
    fn test_sec03_require_justification_loaded_from_config() {
        let config =
            Config::load_with_environment(test_fixtures::config_dir(), Environment::Testing)
                .expect("Config loading should succeed");
        // testing.toml overrides to false so existing connect tests are not broken
        assert!(
            !config.security.require_justification,
            "require_justification should be false from testing.toml"
        );
    }
}
