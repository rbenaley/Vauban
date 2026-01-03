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

