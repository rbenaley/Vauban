/// VAUBAN Web - Configuration management.
///
/// Loads configuration from TOML files with multi-environment support.
/// Loading order:
/// 1. config/default.toml - default values
/// 2. config/{environment}.toml - environment-specific values
/// 3. config/local.toml - local overrides (not versioned)
/// 4. Environment variables prefixed with VAUBAN_ (for secrets only)
use config::{Config as ConfigBuilder, ConfigError, File};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use std::path::Path;

// ==================== Optional Secret Wrapper ====================

/// Wrapper for optional secret values that properly implements Serialize/Deserialize.
/// This is needed because SecretString (SecretBox<str>) doesn't implement Serialize for Option.
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
        self.0.as_ref().map(|s| secrecy::SecretString::from(s.clone()))
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
    pub fn into_secret(self) -> Option<secrecy::SecretString> {
        self.0.map(|s| secrecy::SecretString::from(s))
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
/// fn main() {
///     let config = MyConfig {
///         password: SecretString::from("super_secret"),
///         api_key: SecretString::from("api_key_123"),
///         url: SecretString::from("https://example.com"),
///     };
///
///     let debug_str = format!("{:?}", config);
///     // Redacted fields show [REDACTED] (appears twice for 2 redacted fields)
///     assert!(debug_str.contains("[REDACTED]"));
///     // Exposed secret shows the actual value
///     assert!(debug_str.contains("https://example.com"));
///     // Secrets are NOT exposed in the debug output
///     assert!(!debug_str.contains("super_secret"));
///     assert!(!debug_str.contains("api_key_123"));
/// }
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
    pub grpc: GrpcConfig,
    pub security: SecurityConfig,
    pub logging: LoggingConfig,
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

/// gRPC services configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrpcConfig {
    pub rbac_url: String,
    pub vault_url: String,
    pub auth_url: String,
    pub proxy_ssh_url: String,
    pub proxy_rdp_url: String,
    pub audit_url: String,
    pub mtls: MtlsConfig,
}

/// mTLS configuration.
#[derive(Clone, Serialize, Deserialize)]
pub struct MtlsConfig {
    pub enabled: bool,
    #[serde(default)]
    pub ca_cert: OptionalSecret,
    #[serde(default)]
    pub client_cert: OptionalSecret,
    #[serde(default)]
    pub client_key: OptionalSecret,
}

debug_redacted_optional!(
    MtlsConfig,
    redact: [ca_cert, client_cert, client_key]
);

/// Security configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub password_min_length: usize,
    pub max_failed_login_attempts: u32,
    pub session_max_duration_secs: u64,
    pub session_idle_timeout_secs: u64,
    pub rate_limit_per_minute: u32,
    pub argon2: Argon2Config,
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

impl Config {
    /// Load configuration from TOML files.
    ///
    /// Loads configuration in the following order:
    /// 1. config/default.toml
    /// 2. config/{environment}.toml (development, testing, production)
    /// 3. config/local.toml (optional, for local overrides)
    /// 4. VAUBAN_SECRET_KEY environment variable (for secrets only)
    pub fn load() -> Result<Self, crate::error::AppError> {
        Self::load_from_path("config")
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
    /// Base configuration TOML for tests (mirrors config/default.toml).
    /// This is loaded from the actual config file at test time.
    pub fn base_config() -> &'static str {
        include_str!("../config/default.toml")
    }

    /// Testing environment configuration.
    pub fn testing_config() -> &'static str {
        include_str!("../config/testing.toml")
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
        let config = Config::load_with_environment("config", Environment::Testing)
            .expect("Should load testing config");

        assert_eq!(config.environment, Environment::Testing);
        assert!(!config.secret_key.expose_secret().is_empty());
    }

    #[test]
    fn test_config_from_toml_with_overlay() {
        let base = test_fixtures::base_config();
        let overlay = test_fixtures::testing_config();

        let config =
            Config::from_toml_with_overlay(base, overlay).expect("Should load config with overlay");

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
        let config = Config::load_with_environment("config", Environment::Testing)
            .expect("Should load testing config");

        // Values should come from config/testing.toml
        assert_eq!(config.logging.level, "warn");
        assert!(!config.cache.enabled);
    }

    #[test]
    fn test_config_values_from_default_toml() {
        let config = Config::load_with_environment("config", Environment::Development)
            .expect("Should load development config");

        // Server values should come from config/default.toml (or development.toml)
        assert!(config.server.port > 0);
        assert!(!config.server.host.is_empty());
    }

    #[test]
    fn test_config_database_values() {
        let config = Config::load_with_environment("config", Environment::Testing)
            .expect("Should load testing config");

        // Database URL should be set
        assert!(!config.database.url.expose_secret().is_empty());
        assert!(config.database.max_connections > 0);
    }

    #[test]
    fn test_config_grpc_values() {
        let config = Config::load_with_environment("config", Environment::Testing)
            .expect("Should load testing config");

        // gRPC URLs should be set
        assert!(!config.grpc.rbac_url.is_empty());
        assert!(!config.grpc.vault_url.is_empty());
        assert!(!config.grpc.auth_url.is_empty());
    }

    #[test]
    fn test_config_security_values() {
        let config = Config::load_with_environment("config", Environment::Testing)
            .expect("Should load testing config");

        // Security values should be reasonable
        assert!(config.security.password_min_length >= 8);
        assert!(config.security.max_failed_login_attempts > 0);
    }

    #[test]
    fn test_config_jwt_values() {
        let config = Config::load_with_environment("config", Environment::Testing)
            .expect("Should load testing config");

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
        let json = serde_json::to_string(&env).unwrap();
        assert!(json.contains("testing"));
    }

    #[test]
    fn test_environment_deserialize() {
        let json = r#""production""#;
        let env: Environment = serde_json::from_str(json).unwrap();
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
        let config = Config::load_with_environment("config", Environment::Testing)
            .expect("Should load testing config");
        let cloned = config.clone();
        assert_eq!(config.environment, cloned.environment);
    }

    #[test]
    fn test_config_debug() {
        let config = Config::load_with_environment("config", Environment::Testing)
            .expect("Should load testing config");
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("Config"));
    }

    // ==================== Sub-Config Tests ====================

    #[test]
    fn test_database_config_debug() {
        let config = Config::load_with_environment("config", Environment::Testing)
            .expect("Should load testing config");
        let debug_str = format!("{:?}", config.database);
        assert!(debug_str.contains("DatabaseConfig"));
    }

    #[test]
    fn test_server_config_debug() {
        let config = Config::load_with_environment("config", Environment::Testing)
            .expect("Should load testing config");
        let debug_str = format!("{:?}", config.server);
        assert!(debug_str.contains("ServerConfig"));
    }

    #[test]
    fn test_cache_config_debug() {
        let config = Config::load_with_environment("config", Environment::Testing)
            .expect("Should load testing config");
        let debug_str = format!("{:?}", config.cache);
        assert!(debug_str.contains("CacheConfig"));
    }

    #[test]
    fn test_jwt_config_debug() {
        let config = Config::load_with_environment("config", Environment::Testing)
            .expect("Should load testing config");
        let debug_str = format!("{:?}", config.jwt);
        assert!(debug_str.contains("JwtConfig"));
    }

    #[test]
    fn test_security_config_debug() {
        let config = Config::load_with_environment("config", Environment::Testing)
            .expect("Should load testing config");
        let debug_str = format!("{:?}", config.security);
        assert!(debug_str.contains("SecurityConfig"));
    }

    #[test]
    fn test_logging_config_debug() {
        let config = Config::load_with_environment("config", Environment::Testing)
            .expect("Should load testing config");
        let debug_str = format!("{:?}", config.logging);
        assert!(debug_str.contains("LoggingConfig"));
    }

    #[test]
    fn test_grpc_config_debug() {
        let config = Config::load_with_environment("config", Environment::Testing)
            .expect("Should load testing config");
        let debug_str = format!("{:?}", config.grpc);
        assert!(debug_str.contains("GrpcConfig"));
    }

    #[test]
    fn test_tls_config_debug() {
        let config = Config::load_with_environment("config", Environment::Testing)
            .expect("Should load testing config");
        let debug_str = format!("{:?}", config.server.tls);
        assert!(debug_str.contains("TlsConfig"));
    }

    #[test]
    fn test_mtls_config_debug() {
        let config = Config::load_with_environment("config", Environment::Testing)
            .expect("Should load testing config");
        let debug_str = format!("{:?}", config.grpc.mtls);
        assert!(debug_str.contains("MtlsConfig"));
    }

    #[test]
    fn test_argon2_config_debug() {
        let config = Config::load_with_environment("config", Environment::Testing)
            .expect("Should load testing config");
        let debug_str = format!("{:?}", config.security.argon2);
        assert!(debug_str.contains("Argon2Config"));
    }
}
