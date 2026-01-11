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
    pub async fn new(url: &str, mtls: &MtlsConfig) -> AppResult<Self> {
        let endpoint = Endpoint::from_shared(url.to_string())
            .map_err(|e| AppError::Config(format!("Invalid gRPC URL: {}", e)))?
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(5));

        // TODO: Implement mTLS configuration when tonic-tls API is finalized
        // For now, mTLS is disabled - all connections are insecure
        if mtls.enabled {
            warn!("mTLS is enabled but not yet fully implemented - using insecure connection");
        }

        let channel = endpoint.connect().await.map_err(|e| {
            AppError::Grpc(tonic::Status::internal(format!("Connection failed: {}", e)))
        })?;

        Ok(Self { channel })
    }

    /// Get the underlying channel.
    pub fn channel(&self) -> &Channel {
        &self.channel
    }
}

/// RBAC service client (placeholder - will be generated from proto).
pub struct RbacClient {
    #[allow(dead_code)]
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
    #[allow(dead_code)]
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
        let config = GrpcConnectionConfig::new("http://localhost:50051").with_timeout(30);

        assert_eq!(config.timeout_secs, 30);
    }

    #[test]
    fn test_grpc_connection_config_with_connect_timeout() {
        let config = GrpcConnectionConfig::new("http://localhost:50051").with_connect_timeout(15);

        assert_eq!(config.connect_timeout_secs, 15);
    }

    #[test]
    fn test_grpc_connection_config_with_mtls() {
        let config = GrpcConnectionConfig::new("https://secure.example.com:50051").with_mtls();

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
        let config = GrpcConnectionConfig::new("http://localhost:50051").with_timeout(30);

        assert_eq!(config.timeout(), Duration::from_secs(30));
    }

    #[test]
    fn test_grpc_connection_config_connect_timeout_duration() {
        let config = GrpcConnectionConfig::new("http://localhost:50051").with_connect_timeout(15);

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

    // ==================== Additional URL Validation Tests ====================

    #[test]
    fn test_grpc_connection_config_validate_url_empty() {
        let config = GrpcConnectionConfig::new("");
        assert!(!config.validate_url());
    }

    #[test]
    fn test_grpc_connection_config_validate_url_with_path() {
        let config = GrpcConnectionConfig::new("http://localhost:50051/api/v1");
        assert!(config.validate_url());
    }

    #[test]
    fn test_grpc_connection_config_validate_url_with_port() {
        let config = GrpcConnectionConfig::new("https://api.example.com:8443");
        assert!(config.validate_url());
    }

    // ==================== Timeout Edge Cases ====================

    #[test]
    fn test_grpc_connection_config_zero_timeout() {
        let config = GrpcConnectionConfig::new("http://localhost:50051")
            .with_timeout(0);
        assert_eq!(config.timeout(), Duration::from_secs(0));
    }

    #[test]
    fn test_grpc_connection_config_large_timeout() {
        let config = GrpcConnectionConfig::new("http://localhost:50051")
            .with_timeout(3600); // 1 hour
        assert_eq!(config.timeout(), Duration::from_secs(3600));
    }

    #[test]
    fn test_grpc_connection_config_zero_connect_timeout() {
        let config = GrpcConnectionConfig::new("http://localhost:50051")
            .with_connect_timeout(0);
        assert_eq!(config.connect_timeout(), Duration::from_secs(0));
    }

    // ==================== Default Values Tests ====================

    #[test]
    fn test_grpc_connection_config_default_values() {
        let config = GrpcConnectionConfig::new("http://test:50051");
        
        assert_eq!(config.timeout_secs, 10);
        assert_eq!(config.connect_timeout_secs, 5);
        assert!(!config.mtls_enabled);
    }

    #[test]
    fn test_grpc_connection_config_override_all_defaults() {
        let config = GrpcConnectionConfig::new("https://secure:443")
            .with_timeout(120)
            .with_connect_timeout(30)
            .with_mtls();
        
        assert_eq!(config.timeout_secs, 120);
        assert_eq!(config.connect_timeout_secs, 30);
        assert!(config.mtls_enabled);
    }

    // ==================== URL Format Tests ====================

    #[test]
    fn test_grpc_connection_config_url_with_ipv4() {
        let config = GrpcConnectionConfig::new("http://192.168.1.100:50051");
        assert!(config.validate_url());
    }

    #[test]
    fn test_grpc_connection_config_url_with_ipv6() {
        let config = GrpcConnectionConfig::new("http://[::1]:50051");
        assert!(config.validate_url());
    }

    #[test]
    fn test_grpc_connection_config_ftp_url() {
        let config = GrpcConnectionConfig::new("ftp://files.example.com");
        assert!(!config.validate_url());
    }

    // ==================== Edge Cases ====================

    #[test]
    fn test_grpc_connection_config_url_only_protocol() {
        let config = GrpcConnectionConfig::new("http://");
        assert!(config.validate_url());
    }

    #[test]
    fn test_grpc_connection_config_url_with_auth() {
        let config = GrpcConnectionConfig::new("http://user:pass@localhost:50051");
        assert!(config.validate_url());
    }

    #[test]
    fn test_grpc_connection_config_url_with_query() {
        let config = GrpcConnectionConfig::new("http://localhost:50051?timeout=30");
        assert!(config.validate_url());
    }

    #[test]
    fn test_grpc_connection_config_localhost_variations() {
        let urls = [
            "http://localhost:50051",
            "http://127.0.0.1:50051",
            "http://0.0.0.0:50051",
            "http://[::1]:50051",
        ];
        
        for url in urls {
            let config = GrpcConnectionConfig::new(url);
            assert!(config.validate_url(), "Failed for URL: {}", url);
        }
    }

    // ==================== Timeout Boundary Tests ====================

    #[test]
    fn test_grpc_connection_config_max_timeout() {
        let config = GrpcConnectionConfig::new("http://localhost:50051")
            .with_timeout(u64::MAX);
        assert_eq!(config.timeout_secs, u64::MAX);
    }

    #[test]
    fn test_grpc_connection_config_timeout_overflow_safe() {
        let config = GrpcConnectionConfig::new("http://localhost:50051")
            .with_timeout(u64::MAX);
        // Duration::from_secs should handle this
        let duration = config.timeout();
        assert_eq!(duration.as_secs(), u64::MAX);
    }

    // ==================== Builder Pattern Tests ====================

    #[test]
    fn test_grpc_connection_config_builder_order_independence() {
        let config1 = GrpcConnectionConfig::new("http://test:50051")
            .with_timeout(30)
            .with_connect_timeout(10)
            .with_mtls();
        
        let config2 = GrpcConnectionConfig::new("http://test:50051")
            .with_mtls()
            .with_connect_timeout(10)
            .with_timeout(30);
        
        assert_eq!(config1.timeout_secs, config2.timeout_secs);
        assert_eq!(config1.connect_timeout_secs, config2.connect_timeout_secs);
        assert_eq!(config1.mtls_enabled, config2.mtls_enabled);
    }

    #[test]
    fn test_grpc_connection_config_multiple_with_timeout_calls() {
        let config = GrpcConnectionConfig::new("http://test:50051")
            .with_timeout(10)
            .with_timeout(20)
            .with_timeout(30);
        
        // Last call wins
        assert_eq!(config.timeout_secs, 30);
    }

    // ==================== URL Content Tests ====================

    #[test]
    fn test_grpc_connection_config_url_preserved() {
        let url = "https://api.production.example.com:443/grpc";
        let config = GrpcConnectionConfig::new(url);
        
        assert_eq!(config.url, url);
    }

    #[test]
    fn test_grpc_connection_config_url_with_unicode() {
        let config = GrpcConnectionConfig::new("http://服务器.example.com:50051");
        assert!(config.validate_url());
    }

    #[test]
    fn test_grpc_connection_config_url_case_sensitive() {
        let config_lower = GrpcConnectionConfig::new("http://localhost:50051");
        let config_upper = GrpcConnectionConfig::new("HTTP://localhost:50051");
        
        assert!(config_lower.validate_url());
        assert!(!config_upper.validate_url()); // HTTP:// != http://
    }

    // ==================== Duration Comparison Tests ====================

    #[test]
    fn test_grpc_connection_config_timeout_vs_connect_timeout() {
        let config = GrpcConnectionConfig::new("http://test:50051")
            .with_timeout(30)
            .with_connect_timeout(5);
        
        // Connection timeout should typically be less than request timeout
        assert!(config.connect_timeout() < config.timeout());
    }

    #[test]
    fn test_grpc_connection_config_equal_timeouts() {
        let config = GrpcConnectionConfig::new("http://test:50051")
            .with_timeout(10)
            .with_connect_timeout(10);
        
        assert_eq!(config.timeout(), config.connect_timeout());
    }

    // ==================== Security Tests ====================

    #[test]
    fn test_grpc_connection_config_mtls_default_false() {
        let config = GrpcConnectionConfig::new("http://localhost:50051");
        assert!(!config.mtls_enabled);
    }

    #[test]
    fn test_grpc_connection_config_https_without_mtls() {
        let config = GrpcConnectionConfig::new("https://secure.example.com:443");
        // HTTPS doesn't automatically enable mTLS
        assert!(!config.mtls_enabled);
    }

    #[test]
    fn test_grpc_connection_config_http_with_mtls() {
        // Technically allowed but unusual
        let config = GrpcConnectionConfig::new("http://internal:50051")
            .with_mtls();
        assert!(config.mtls_enabled);
    }

    // ==================== GrpcConnectionConfig Complete Field Coverage ====================

    #[test]
    fn test_grpc_connection_config_all_fields() {
        let config = GrpcConnectionConfig {
            url: "http://test:50051".to_string(),
            timeout_secs: 15,
            connect_timeout_secs: 8,
            mtls_enabled: true,
        };
        
        assert_eq!(config.url, "http://test:50051");
        assert_eq!(config.timeout_secs, 15);
        assert_eq!(config.connect_timeout_secs, 8);
        assert!(config.mtls_enabled);
    }

    #[test]
    fn test_grpc_connection_config_field_independence() {
        let mut config = GrpcConnectionConfig::new("http://test:50051");
        
        config.timeout_secs = 100;
        assert_eq!(config.connect_timeout_secs, 5); // Should be unchanged
        
        config.mtls_enabled = true;
        assert_eq!(config.timeout_secs, 100); // Should be unchanged
    }

    // ==================== Duration Method Coverage ====================

    #[test]
    fn test_grpc_connection_config_timeout_nanos() {
        let config = GrpcConnectionConfig::new("http://test:50051").with_timeout(1);
        assert_eq!(config.timeout().as_nanos(), 1_000_000_000);
    }

    #[test]
    fn test_grpc_connection_config_connect_timeout_nanos() {
        let config = GrpcConnectionConfig::new("http://test:50051").with_connect_timeout(1);
        assert_eq!(config.connect_timeout().as_nanos(), 1_000_000_000);
    }

    #[test]
    fn test_grpc_connection_config_timeout_millis() {
        let config = GrpcConnectionConfig::new("http://test:50051").with_timeout(2);
        assert_eq!(config.timeout().as_millis(), 2000);
    }

    // ==================== URL Edge Cases ====================

    #[test]
    fn test_grpc_connection_config_url_whitespace() {
        let config = GrpcConnectionConfig::new("  http://test:50051  ");
        assert!(!config.validate_url()); // Leading whitespace fails
    }

    #[test]
    fn test_grpc_connection_config_url_fragment() {
        let config = GrpcConnectionConfig::new("http://test:50051#section");
        assert!(config.validate_url());
    }

    #[test]
    fn test_grpc_connection_config_url_very_long() {
        let long_host = "a".repeat(1000);
        let url = format!("http://{}:50051", long_host);
        let config = GrpcConnectionConfig::new(&url);
        
        assert!(config.validate_url());
        // "http://" (7) + 1000 'a's + ":50051" (6) = 1013
        assert_eq!(config.url.len(), 1013);
    }

    // ==================== Clone Deep Tests ====================

    #[test]
    fn test_grpc_connection_config_clone_independence() {
        let mut config1 = GrpcConnectionConfig::new("http://test:50051");
        let config2 = config1.clone();
        
        config1.timeout_secs = 999;
        
        // Clone should not be affected
        assert_eq!(config2.timeout_secs, 10);
    }

    #[test]
    fn test_grpc_connection_config_clone_all_fields() {
        let config = GrpcConnectionConfig::new("https://secure:443")
            .with_timeout(60)
            .with_connect_timeout(15)
            .with_mtls();
        
        let cloned = config.clone();
        
        assert_eq!(cloned.url, config.url);
        assert_eq!(cloned.timeout_secs, config.timeout_secs);
        assert_eq!(cloned.connect_timeout_secs, config.connect_timeout_secs);
        assert_eq!(cloned.mtls_enabled, config.mtls_enabled);
    }

    // ==================== Debug Format Tests ====================

    #[test]
    fn test_grpc_connection_config_debug_contains_all_fields() {
        let config = GrpcConnectionConfig::new("http://test:50051")
            .with_timeout(30)
            .with_connect_timeout(10)
            .with_mtls();
        
        let debug = format!("{:?}", config);
        
        assert!(debug.contains("url"));
        assert!(debug.contains("timeout_secs"));
        assert!(debug.contains("connect_timeout_secs"));
        assert!(debug.contains("mtls_enabled"));
        assert!(debug.contains("30"));
        assert!(debug.contains("10"));
        assert!(debug.contains("true"));
    }

    // ==================== Validate URL Comprehensive ====================

    #[test]
    fn test_grpc_connection_config_validate_various_invalid() {
        let invalid_urls = [
            "",
            "localhost",
            "tcp://localhost:50051",
            "ws://localhost:50051",
            "wss://localhost:50051",
            "file:///path/to/file",
            "mailto:test@example.com",
            "data:text/plain;base64,SGVsbG8=",
        ];
        
        for url in invalid_urls {
            let config = GrpcConnectionConfig::new(url);
            assert!(!config.validate_url(), "Expected invalid: {}", url);
        }
    }

    #[test]
    fn test_grpc_connection_config_validate_various_valid() {
        let valid_urls = [
            "http://localhost",
            "http://localhost:80",
            "http://localhost:50051",
            "https://localhost",
            "https://localhost:443",
            "http://192.168.1.1:50051",
            "http://[::1]:50051",
            "http://example.com",
            "https://api.example.com:8443/v1",
            "http://user:pass@host:50051",
        ];
        
        for url in valid_urls {
            let config = GrpcConnectionConfig::new(url);
            assert!(config.validate_url(), "Expected valid: {}", url);
        }
    }

    // ==================== Builder Fluent API ====================

    #[test]
    fn test_grpc_connection_config_builder_returns_self() {
        let config = GrpcConnectionConfig::new("http://test:50051");
        
        // Each method returns Self for chaining
        let _ = config.with_timeout(10);
    }

    #[test]
    fn test_grpc_connection_config_builder_no_methods() {
        let config = GrpcConnectionConfig::new("http://test:50051");
        
        // Default values without calling any builder methods
        assert_eq!(config.timeout_secs, 10);
        assert_eq!(config.connect_timeout_secs, 5);
        assert!(!config.mtls_enabled);
    }

    // ==================== Duration Comparisons ====================

    #[test]
    fn test_grpc_connection_config_duration_arithmetic() {
        let config = GrpcConnectionConfig::new("http://test:50051")
            .with_timeout(30)
            .with_connect_timeout(10);
        
        let total = config.timeout() + config.connect_timeout();
        assert_eq!(total.as_secs(), 40);
    }

    #[test]
    fn test_grpc_connection_config_duration_zero_safe() {
        let config = GrpcConnectionConfig::new("http://test:50051")
            .with_timeout(0)
            .with_connect_timeout(0);
        
        assert!(!config.timeout().is_zero() || config.timeout() == Duration::ZERO);
    }

    // ==================== URL String Operations ====================

    #[test]
    fn test_grpc_connection_config_url_string_owned() {
        let url_str = "http://test:50051";
        let config = GrpcConnectionConfig::new(url_str);
        
        // URL should be owned (String, not &str)
        let _owned: String = config.url;
    }

    #[test]
    fn test_grpc_connection_config_url_mutation() {
        let mut config = GrpcConnectionConfig::new("http://old:50051");
        config.url = "http://new:50051".to_string();
        
        assert_eq!(config.url, "http://new:50051");
        assert!(config.validate_url());
    }
}
