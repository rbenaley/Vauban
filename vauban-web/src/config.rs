/// VAUBAN Web - Configuration management.
///
/// Supports multiple environments: development, testing, production.

use serde::{Deserialize, Serialize};
use std::env;

/// Application environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Environment {
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
    pub ca_cert: Option<String>,
    pub client_cert: Option<String>,
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

impl Config {
    /// Load configuration from environment variables.
    pub fn from_env() -> Result<Self, crate::error::AppError> {
        dotenv::dotenv().ok(); // Ignore if .env doesn't exist

        let environment = Environment::from_str(
            &env::var("ENVIRONMENT").unwrap_or_else(|_| "development".to_string()),
        );

        let secret_key = env::var("SECRET_KEY")
            .map_err(|_| crate::error::AppError::Config("SECRET_KEY not set".to_string()))?;

        let database = DatabaseConfig {
            url: env::var("DATABASE_URL").unwrap_or_else(|_| {
                "postgresql://vauban:vauban@localhost/vauban".to_string()
            }),
            max_connections: env::var("DATABASE_MAX_CONNECTIONS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(10),
            min_connections: env::var("DATABASE_MIN_CONNECTIONS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(2),
            connect_timeout_secs: env::var("DATABASE_CONNECT_TIMEOUT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(10),
        };

        let cache = CacheConfig {
            enabled: env::var("CACHE_ENABLED")
                .map(|v| v == "true")
                .unwrap_or_else(|_| {
                    // Auto-detect: enable in production, disable in development/testing
                    environment.is_production()
                }),
            url: env::var("CACHE_URL")
                .unwrap_or_else(|_| "redis://localhost:6379".to_string()),
            default_ttl_secs: env::var("CACHE_TTL_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(3600),
        };

        let server = ServerConfig {
            host: env::var("SERVER_HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
            port: env::var("SERVER_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(8000),
            workers: env::var("SERVER_WORKERS")
                .ok()
                .and_then(|s| s.parse().ok()),
        };

        let jwt = JwtConfig {
            access_token_lifetime_minutes: env::var("JWT_ACCESS_LIFETIME_MINUTES")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(15),
            refresh_token_lifetime_days: env::var("JWT_REFRESH_LIFETIME_DAYS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(1),
            algorithm: env::var("JWT_ALGORITHM").unwrap_or_else(|_| "HS256".to_string()),
        };

        let grpc = GrpcConfig {
            rbac_url: env::var("GRPC_RBAC_URL")
                .unwrap_or_else(|_| "http://localhost:50052".to_string()),
            vault_url: env::var("GRPC_VAULT_URL")
                .unwrap_or_else(|_| "http://localhost:50053".to_string()),
            auth_url: env::var("GRPC_AUTH_URL")
                .unwrap_or_else(|_| "http://localhost:50051".to_string()),
            proxy_ssh_url: env::var("GRPC_PROXY_SSH_URL")
                .unwrap_or_else(|_| "http://localhost:50054".to_string()),
            proxy_rdp_url: env::var("GRPC_PROXY_RDP_URL")
                .unwrap_or_else(|_| "http://localhost:50055".to_string()),
            audit_url: env::var("GRPC_AUDIT_URL")
                .unwrap_or_else(|_| "http://localhost:50056".to_string()),
            mtls: MtlsConfig {
                enabled: environment.is_production()
                    && env::var("MTLS_ENABLED")
                        .map(|v| v == "true")
                        .unwrap_or(false),
                ca_cert: env::var("MTLS_CA_CERT").ok(),
                client_cert: env::var("MTLS_CLIENT_CERT").ok(),
                client_key: env::var("MTLS_CLIENT_KEY").ok(),
            },
        };

        let security = SecurityConfig {
            password_min_length: env::var("PASSWORD_MIN_LENGTH")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(12),
            max_failed_login_attempts: env::var("MAX_FAILED_LOGIN_ATTEMPTS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(5),
            session_max_duration_secs: env::var("SESSION_MAX_DURATION_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(28800), // 8 hours
            session_idle_timeout_secs: env::var("SESSION_IDLE_TIMEOUT_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(1800), // 30 minutes
            rate_limit_per_minute: env::var("RATE_LIMIT_PER_MINUTE")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(100),
        };

        Ok(Config {
            environment,
            secret_key,
            database,
            cache,
            server,
            jwt,
            grpc,
            security,
        })
    }
}

