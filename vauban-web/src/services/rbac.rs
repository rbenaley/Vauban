/// VAUBAN Web - RBAC service client wrapper.
use crate::config::Config;
use crate::error::AppResult;
use crate::grpc::RbacClient;

/// RBAC permission check parameters.
#[derive(Debug, Clone)]
pub struct PermissionCheck {
    pub user_id: String,
    pub resource: String,
    pub action: String,
}

impl PermissionCheck {
    /// Create a new permission check.
    pub fn new(user_id: &str, resource: &str, action: &str) -> Self {
        Self {
            user_id: user_id.to_string(),
            resource: resource.to_string(),
            action: action.to_string(),
        }
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== PermissionCheck Tests ====================

    #[test]
    fn test_permission_check_new() {
        let check = PermissionCheck::new("user-123", "assets", "read");

        assert_eq!(check.user_id, "user-123");
        assert_eq!(check.resource, "assets");
        assert_eq!(check.action, "read");
    }

    #[test]
    fn test_permission_check_clone() {
        let check = PermissionCheck::new("user-456", "sessions", "create");
        let cloned = check.clone();

        assert_eq!(check.user_id, cloned.user_id);
        assert_eq!(check.resource, cloned.resource);
        assert_eq!(check.action, cloned.action);
    }

    #[test]
    fn test_permission_check_debug() {
        let check = PermissionCheck::new("admin", "users", "delete");
        let debug_str = format!("{:?}", check);

        assert!(debug_str.contains("PermissionCheck"));
        assert!(debug_str.contains("admin"));
        assert!(debug_str.contains("users"));
        assert!(debug_str.contains("delete"));
    }

    #[test]
    fn test_permission_check_common_actions() {
        let actions = ["read", "write", "create", "update", "delete", "execute"];

        for action in actions {
            let check = PermissionCheck::new("user", "resource", action);
            assert_eq!(check.action, action);
        }
    }

    #[test]
    fn test_permission_check_common_resources() {
        let resources = ["assets", "sessions", "users", "groups", "credentials"];

        for resource in resources {
            let check = PermissionCheck::new("user", resource, "read");
            assert_eq!(check.resource, resource);
        }
    }
}
