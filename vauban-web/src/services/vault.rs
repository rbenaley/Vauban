/// VAUBAN Web - Vault service client wrapper.

use crate::config::Config;
use crate::error::{AppError, AppResult};
use crate::grpc::VaultClient;

/// Vault service wrapper.
pub struct VaultService {
    client: VaultClient,
}

impl VaultService {
    /// Create a new Vault service.
    pub async fn new(config: Config) -> AppResult<Self> {
        let client = VaultClient::new(&config).await?;
        Ok(Self { client })
    }

    /// List credentials for an asset.
    pub async fn list_credentials(&self, asset_id: Option<&str>) -> AppResult<Vec<String>> {
        self.client.list_credentials(asset_id).await
    }
}

