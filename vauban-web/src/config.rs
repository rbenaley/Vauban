/// VAUBAN Web - Configuration management.
///
/// Charge la configuration depuis des fichiers TOML avec support multi-environnement.
/// Ordre de chargement :
/// 1. config/default.toml - valeurs par défaut
/// 2. config/{environment}.toml - valeurs spécifiques à l'environnement
/// 3. config/local.toml - surcharges locales (non versionné)
/// 4. Variables d'environnement préfixées VAUBAN_ (pour les secrets uniquement)
use config::{Config as ConfigBuilder, ConfigError, File};
use serde::{Deserialize, Serialize};
use std::path::Path;

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
    pub fn from_str(s: &str) -> Self {
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
/// Toutes les valeurs doivent être définies dans les fichiers TOML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub environment: Environment,
    pub secret_key: String,
    pub database: DatabaseConfig,
    pub cache: CacheConfig,
    pub server: ServerConfig,
    pub jwt: JwtConfig,
    pub grpc: GrpcConfig,
    pub security: SecurityConfig,
    pub logging: LoggingConfig,
}

/// Database configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub min_connections: u32,
    pub connect_timeout_secs: u64,
}

/// Cache (Valkey/Redis) configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    pub enabled: bool,
    pub url: String,
    pub default_ttl_secs: u64,
}

/// Server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub workers: Option<usize>,
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MtlsConfig {
    pub enabled: bool,
    #[serde(default)]
    pub ca_cert: Option<String>,
    #[serde(default)]
    pub client_cert: Option<String>,
    #[serde(default)]
    pub client_key: Option<String>,
}

/// Security configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub password_min_length: usize,
    pub max_failed_login_attempts: u32,
    pub session_max_duration_secs: u64,
    pub session_idle_timeout_secs: u64,
    pub rate_limit_per_minute: u32,
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
    pub fn from_str(s: &str) -> Self {
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
    /// Charge la configuration dans l'ordre suivant :
    /// 1. config/default.toml
    /// 2. config/{environment}.toml (development, testing, production)
    /// 3. config/local.toml (optionnel, pour les surcharges locales)
    /// 4. Variable d'environnement VAUBAN_SECRET_KEY (pour le secret uniquement)
    pub fn load() -> Result<Self, crate::error::AppError> {
        Self::load_from_path("config")
    }

    /// Load configuration from a specific directory path.
    pub fn load_from_path<P: AsRef<Path>>(config_path: P) -> Result<Self, crate::error::AppError> {
        let config_path = config_path.as_ref();

        // Détermine l'environnement depuis VAUBAN_ENVIRONMENT ou default.toml
        let environment = std::env::var("VAUBAN_ENVIRONMENT")
            .map(|e| Environment::from_str(&e))
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

        // 1. Charge default.toml (requis)
        let default_path = config_path.join("default.toml");
        if !default_path.exists() {
            return Err(crate::error::AppError::Config(format!(
                "Configuration file not found: {}",
                default_path.display()
            )));
        }
        builder = builder.add_source(File::from(default_path));

        // 2. Charge {environment}.toml
        let env_path = config_path.join(format!("{}.toml", environment.as_str()));
        if env_path.exists() {
            builder = builder.add_source(File::from(env_path));
        }

        // 3. Charge local.toml (optionnel, non versionné)
        let local_path = config_path.join("local.toml");
        if local_path.exists() {
            builder = builder.add_source(File::from(local_path));
        }

        // 4. Surcharge secret_key depuis VAUBAN_SECRET_KEY si défini
        if let Ok(secret) = std::env::var("VAUBAN_SECRET_KEY") {
            builder = builder.set_override("secret_key", secret).map_err(|e| {
                crate::error::AppError::Config(format!("Failed to set secret_key: {}", e))
            })?;
        }

        // Construit la configuration
        let settings = builder.build().map_err(|e| Self::config_error(e))?;

        // Désérialise en Config
        let mut config: Config = settings
            .try_deserialize()
            .map_err(|e| Self::config_error(e))?;

        // Force l'environnement au cas où il n'est pas dans le fichier
        config.environment = environment;

        // Valide que secret_key est défini
        if config.secret_key.is_empty() {
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
            .map_err(|e| Self::config_error(e))?;

        settings
            .try_deserialize()
            .map_err(|e| Self::config_error(e))
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
            .map_err(|e| Self::config_error(e))?;

        settings
            .try_deserialize()
            .map_err(|e| Self::config_error(e))
    }

    fn config_error(e: ConfigError) -> crate::error::AppError {
        crate::error::AppError::Config(format!("Configuration error: {}", e))
    }

    /// Legacy method for backward compatibility.
    /// Préfère `Config::load()` pour les nouvelles utilisations.
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
    fn test_environment_from_str_development() {
        assert_eq!(
            Environment::from_str("development"),
            Environment::Development
        );
        assert_eq!(Environment::from_str("dev"), Environment::Development);
    }

    #[test]
    fn test_environment_from_str_testing() {
        assert_eq!(Environment::from_str("testing"), Environment::Testing);
        assert_eq!(Environment::from_str("test"), Environment::Testing);
    }

    #[test]
    fn test_environment_from_str_production() {
        assert_eq!(Environment::from_str("production"), Environment::Production);
        assert_eq!(Environment::from_str("prod"), Environment::Production);
    }

    #[test]
    fn test_environment_from_str_unknown() {
        // Unknown values default to Development
        assert_eq!(Environment::from_str("unknown"), Environment::Development);
        assert_eq!(Environment::from_str(""), Environment::Development);
    }

    #[test]
    fn test_environment_from_str_case_insensitive() {
        assert_eq!(
            Environment::from_str("DEVELOPMENT"),
            Environment::Development
        );
        assert_eq!(Environment::from_str("PRODUCTION"), Environment::Production);
        assert_eq!(Environment::from_str("Testing"), Environment::Testing);
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
            let parsed = Environment::from_str(str_val);
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
    fn test_log_format_from_str_json() {
        assert_eq!(LogFormat::from_str("json"), LogFormat::Json);
        assert_eq!(LogFormat::from_str("JSON"), LogFormat::Json);
    }

    #[test]
    fn test_log_format_from_str_text() {
        assert_eq!(LogFormat::from_str("text"), LogFormat::Text);
        assert_eq!(LogFormat::from_str("TEXT"), LogFormat::Text);
    }

    #[test]
    fn test_log_format_from_str_unknown() {
        // Unknown values default to Text
        assert_eq!(LogFormat::from_str("unknown"), LogFormat::Text);
        assert_eq!(LogFormat::from_str(""), LogFormat::Text);
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
        assert!(!config.secret_key.is_empty());
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
        assert!(!config.database.url.is_empty());
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
}
