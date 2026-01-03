/// VAUBAN Web - RBAC service client wrapper.

use crate::config::Config;
use crate::error::{AppError, AppResult};
use crate::grpc::RbacClient;

/// RBAC service wrapper.
pub struct RbacService {
    client: RbacClient,
}

impl RbacService {
    /// Create a new RBAC service.
    pub async fn new(config: Config) -> AppResult<Self> {
        let client = RbacClient::new(&config).await?;
        Ok(Self { client })
    }

    /// Check if user has permission.
    pub async fn check_permission(
        &self,
        user_id: &str,
        resource: &str,
        action: &str,
    ) -> AppResult<bool> {
        self.client
            .check_permission(user_id, resource, action)
            .await
    }
}

