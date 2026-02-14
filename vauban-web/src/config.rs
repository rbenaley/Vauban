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
    #[default]
    Development,
    Testing,
    Production,
}

impl Environment {
    pub fn parse(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "development" | "dev" => Self::Development,
            "testing" | "test" => Self::Testing,
            "production" | "prod" => Self::Production,
            _ => Self::Development,
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
}

debug_redacted_struct!(
    Config,
    redact: [secret_key]
);

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
    /// Maximum number of concurrent WebSocket connections per user (L-8).
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

impl Config {
    /// Load configuration from TOML files.
    ///
    /// Automatically finds the configuration directory in this order:
    /// 1. VAUBAN_CONFIG_DIR environment variable (if set)
    /// 2. Workspace root config/ directory (development)
    /// 3. /usr/local/etc/vauban/ (production on FreeBSD)
    ///
    /// Then loads configuration files in the following order:
    /// 1. config/default.toml
    /// 2. config/{environment}.toml (development, testing, production)
    /// 3. config/local.toml (optional, for local overrides)
    /// 4. VAUBAN_SECRET_KEY environment variable (for secrets only)
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

        // Determine environment from VAUBAN_ENVIRONMENT or default.toml
        let environment = std::env::var("VAUBAN_ENVIRONMENT")
            .map(|e| Environment::parse(&e))
            .unwrap_or(Environment::Development);

        Self::load_with_environment(config_path, environment)
    }

    /// Load configuration with a specific environment.
    pub fn load_with_environment<P: AsRef<Path>>(
        config_path: P,
        environment: Environment,
    ) -> Result<Self, crate::error::AppError> {
        let config_path = config_path.as_ref();

        let mut builder = ConfigBuilder::builder();

        // 1. Load default.toml (required)
        let default_path = config_path.join("default.toml");
        if !default_path.exists() {
            return Err(crate::error::AppError::Config(format!(
                "Configuration file not found: {}",
                default_path.display()
            )));
        }
        builder = builder.add_source(File::from(default_path));

        // 2. Load {environment}.toml
        let env_path = config_path.join(format!("{}.toml", environment.as_str()));
        if env_path.exists() {
            builder = builder.add_source(File::from(env_path));
        }

        // 3. Load local.toml (optional, not versioned)
        // Skip local.toml in testing environment to avoid overriding test database URL
        if environment != Environment::Testing {
            let local_path = config_path.join("local.toml");
            if local_path.exists() {
                builder = builder.add_source(File::from(local_path));
            }
        }

        // 4. Override secret_key from VAUBAN_SECRET_KEY if set
        if let Ok(secret) = std::env::var("VAUBAN_SECRET_KEY") {
            // M-4: Clear the environment variable immediately after reading.
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
        // Unknown values default to Development
        assert_eq!(Environment::parse("unknown"), Environment::Development);
        assert_eq!(Environment::parse(""), Environment::Development);
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
        let cloned = env.clone();
        assert_eq!(env, cloned);
    }

    #[test]
    fn test_environment_default() {
        let env = Environment::default();
        assert_eq!(env, Environment::Development);
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
        let cloned = format.clone();
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
        // Production paths should be absolute (FreeBSD standard paths)
        // We read the TOML directly because production.toml doesn't have secret_key
        // (it's set via environment variable in production)
        let production_toml = include_str!("../../config/production.toml");

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

    // ==================== M-3: OptionalSecret Zeroize Tests ====================

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

    // ==================== M-4: VAUBAN_SECRET_KEY env-var clearing Tests ====================

    #[test]
    #[serial_test::serial]
    fn test_m4_env_var_cleared_after_config_load() {
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

        let config = Config::load_with_environment(
            test_fixtures::config_dir(),
            Environment::Testing,
        )
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
    fn test_m4_toml_secret_key_still_works_without_env_var() {
        // Regression guard: when VAUBAN_SECRET_KEY is NOT set, the secret_key
        // must still be loaded from TOML files (current production path).
        //
        // This is the most important test for M-4: we must not break the
        // TOML-based secret_key loading that is the primary usage today.
        unsafe {
            std::env::remove_var("VAUBAN_SECRET_KEY");
        }
        assert!(
            std::env::var("VAUBAN_SECRET_KEY").is_err(),
            "pre-condition: VAUBAN_SECRET_KEY should not be set"
        );

        let config = Config::load_with_environment(
            test_fixtures::config_dir(),
            Environment::Testing,
        )
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
    fn test_m4_env_var_overrides_toml_secret_key() {
        // When both TOML and env var provide secret_key, the env var wins.
        let env_secret = "env-override-takes-priority-ok!!";

        unsafe {
            std::env::set_var("VAUBAN_SECRET_KEY", env_secret);
        }

        let config = Config::load_with_environment(
            test_fixtures::config_dir(),
            Environment::Testing,
        )
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
    fn test_m4_source_has_remove_var() {
        // Structural regression test: the source code must contain
        // remove_var("VAUBAN_SECRET_KEY") to ensure the env var is cleared.
        let source = include_str!("config.rs");
        assert!(
            source.contains(r#"remove_var("VAUBAN_SECRET_KEY")"#),
            "config.rs must call remove_var(\"VAUBAN_SECRET_KEY\") after reading the env var"
        );
    }
}
