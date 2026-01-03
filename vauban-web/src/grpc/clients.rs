/// VAUBAN Web - gRPC clients with mTLS support.
///
/// Clients for communicating with Rust microservices.

use std::time::Duration;
use tonic::transport::{Channel, Endpoint};
use tracing::warn;

use crate::config::{Config, MtlsConfig};
use crate::error::{AppError, AppResult};

/// Base gRPC client with mTLS support.
pub struct GrpcClient {
    channel: Channel,
}

impl GrpcClient {
    /// Create a new gRPC client with optional mTLS.
    pub async fn new(
        url: &str,
        mtls: &MtlsConfig,
    ) -> AppResult<Self> {
        let endpoint = Endpoint::from_shared(url.to_string())
            .map_err(|e| AppError::Config(format!("Invalid gRPC URL: {}", e)))?
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(5));

        // TODO: Implement mTLS configuration when tonic-tls API is finalized
        // For now, mTLS is disabled - all connections are insecure
        if mtls.enabled {
            warn!("mTLS is enabled but not yet fully implemented - using insecure connection");
        }

        let channel = endpoint
            .connect()
            .await
            .map_err(|e| AppError::Grpc(tonic::Status::internal(format!("Connection failed: {}", e))))?;

        Ok(Self { channel })
    }

    /// Get the underlying channel.
    pub fn channel(&self) -> &Channel {
        &self.channel
    }
}

/// RBAC service client (placeholder - will be generated from proto).
pub struct RbacClient {
    client: GrpcClient,
}

impl RbacClient {
    pub async fn new(config: &Config) -> AppResult<Self> {
        let client = GrpcClient::new(&config.grpc.rbac_url, &config.grpc.mtls).await?;
        Ok(Self { client })
    }

    /// Check permission (placeholder).
    pub async fn check_permission(
        &self,
        _user_id: &str,
        _resource: &str,
        _action: &str,
    ) -> AppResult<bool> {
        // TODO: Implement when proto is available
        warn!("RBAC check_permission called but not implemented");
        Ok(true) // Mock: allow all in development
    }
}

/// Vault service client (placeholder - will be generated from proto).
pub struct VaultClient {
    client: GrpcClient,
}

impl VaultClient {
    pub async fn new(config: &Config) -> AppResult<Self> {
        let client = GrpcClient::new(&config.grpc.vault_url, &config.grpc.mtls).await?;
        Ok(Self { client })
    }

    /// List credentials (placeholder).
    pub async fn list_credentials(&self, _asset_id: Option<&str>) -> AppResult<Vec<String>> {
        // TODO: Implement when proto is available
        warn!("Vault list_credentials called but not implemented");
        Ok(vec![])
    }
}

/// gRPC connection configuration helper.
#[derive(Debug, Clone)]
pub struct GrpcConnectionConfig {
    pub url: String,
    pub timeout_secs: u64,
    pub connect_timeout_secs: u64,
    pub mtls_enabled: bool,
}

impl GrpcConnectionConfig {
    /// Create a new gRPC connection config.
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
            timeout_secs: 10,
            connect_timeout_secs: 5,
            mtls_enabled: false,
        }
    }

    /// Set timeout.
    pub fn with_timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }

    /// Set connect timeout.
    pub fn with_connect_timeout(mut self, secs: u64) -> Self {
        self.connect_timeout_secs = secs;
        self
    }

    /// Enable mTLS.
    pub fn with_mtls(mut self) -> Self {
        self.mtls_enabled = true;
        self
    }

    /// Validate URL format.
    pub fn validate_url(&self) -> bool {
        self.url.starts_with("http://") || self.url.starts_with("https://")
    }

    /// Get timeout as Duration.
    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_secs)
    }

    /// Get connect timeout as Duration.
    pub fn connect_timeout(&self) -> Duration {
        Duration::from_secs(self.connect_timeout_secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== GrpcConnectionConfig Tests ====================

    #[test]
    fn test_grpc_connection_config_new() {
        let config = GrpcConnectionConfig::new("http://localhost:50051");

        assert_eq!(config.url, "http://localhost:50051");
        assert_eq!(config.timeout_secs, 10);
        assert_eq!(config.connect_timeout_secs, 5);
        assert!(!config.mtls_enabled);
    }

    #[test]
    fn test_grpc_connection_config_with_timeout() {
        let config = GrpcConnectionConfig::new("http://localhost:50051")
            .with_timeout(30);

        assert_eq!(config.timeout_secs, 30);
    }

    #[test]
    fn test_grpc_connection_config_with_connect_timeout() {
        let config = GrpcConnectionConfig::new("http://localhost:50051")
            .with_connect_timeout(15);

        assert_eq!(config.connect_timeout_secs, 15);
    }

    #[test]
    fn test_grpc_connection_config_with_mtls() {
        let config = GrpcConnectionConfig::new("https://secure.example.com:50051")
            .with_mtls();

        assert!(config.mtls_enabled);
    }

    #[test]
    fn test_grpc_connection_config_chain() {
        let config = GrpcConnectionConfig::new("https://api.example.com:443")
            .with_timeout(60)
            .with_connect_timeout(10)
            .with_mtls();

        assert_eq!(config.url, "https://api.example.com:443");
        assert_eq!(config.timeout_secs, 60);
        assert_eq!(config.connect_timeout_secs, 10);
        assert!(config.mtls_enabled);
    }

    #[test]
    fn test_grpc_connection_config_validate_url_http() {
        let config = GrpcConnectionConfig::new("http://localhost:50051");
        assert!(config.validate_url());
    }

    #[test]
    fn test_grpc_connection_config_validate_url_https() {
        let config = GrpcConnectionConfig::new("https://secure.example.com:443");
        assert!(config.validate_url());
    }

    #[test]
    fn test_grpc_connection_config_validate_url_invalid() {
        let config = GrpcConnectionConfig::new("localhost:50051");
        assert!(!config.validate_url());
    }

    #[test]
    fn test_grpc_connection_config_validate_url_grpc() {
        let config = GrpcConnectionConfig::new("grpc://localhost:50051");
        assert!(!config.validate_url());
    }

    #[test]
    fn test_grpc_connection_config_timeout_duration() {
        let config = GrpcConnectionConfig::new("http://localhost:50051")
            .with_timeout(30);

        assert_eq!(config.timeout(), Duration::from_secs(30));
    }

    #[test]
    fn test_grpc_connection_config_connect_timeout_duration() {
        let config = GrpcConnectionConfig::new("http://localhost:50051")
            .with_connect_timeout(15);

        assert_eq!(config.connect_timeout(), Duration::from_secs(15));
    }

    #[test]
    fn test_grpc_connection_config_clone() {
        let config = GrpcConnectionConfig::new("http://localhost:50051")
            .with_timeout(20)
            .with_mtls();
        let cloned = config.clone();

        assert_eq!(config.url, cloned.url);
        assert_eq!(config.timeout_secs, cloned.timeout_secs);
        assert_eq!(config.mtls_enabled, cloned.mtls_enabled);
    }

    #[test]
    fn test_grpc_connection_config_debug() {
        let config = GrpcConnectionConfig::new("http://localhost:50051");
        let debug_str = format!("{:?}", config);

        assert!(debug_str.contains("GrpcConnectionConfig"));
        assert!(debug_str.contains("localhost"));
    }
}

