/// VAUBAN Web - RBAC service client wrapper.
use crate::config::Config;
use crate::error::AppResult;
use crate::ipc::RbacClient;

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

    // ==================== PermissionCheck Edge Cases ====================

    #[test]
    fn test_permission_check_empty_user_id() {
        let check = PermissionCheck::new("", "resource", "action");
        assert_eq!(check.user_id, "");
    }

    #[test]
    fn test_permission_check_empty_resource() {
        let check = PermissionCheck::new("user", "", "action");
        assert_eq!(check.resource, "");
    }

    #[test]
    fn test_permission_check_empty_action() {
        let check = PermissionCheck::new("user", "resource", "");
        assert_eq!(check.action, "");
    }

    #[test]
    fn test_permission_check_all_empty() {
        let check = PermissionCheck::new("", "", "");

        assert_eq!(check.user_id, "");
        assert_eq!(check.resource, "");
        assert_eq!(check.action, "");
    }

    #[test]
    fn test_permission_check_unicode_user_id() {
        let check = PermissionCheck::new("用户123", "assets", "read");
        assert_eq!(check.user_id, "用户123");
    }

    #[test]
    fn test_permission_check_unicode_resource() {
        let check = PermissionCheck::new("user", "资源", "read");
        assert_eq!(check.resource, "资源");
    }

    #[test]
    fn test_permission_check_unicode_action() {
        let check = PermissionCheck::new("user", "resource", "操作");
        assert_eq!(check.action, "操作");
    }

    #[test]
    fn test_permission_check_special_characters() {
        let check = PermissionCheck::new(
            "user@domain.com",
            "resource:with:colons",
            "action/with/slashes",
        );

        assert_eq!(check.user_id, "user@domain.com");
        assert_eq!(check.resource, "resource:with:colons");
        assert_eq!(check.action, "action/with/slashes");
    }

    #[test]
    fn test_permission_check_uuid_user_id() {
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        let check = PermissionCheck::new(uuid, "assets", "read");

        assert_eq!(check.user_id, uuid);
    }

    #[test]
    fn test_permission_check_long_values() {
        let long_user = "u".repeat(500);
        let long_resource = "r".repeat(500);
        let long_action = "a".repeat(500);

        let check = PermissionCheck::new(&long_user, &long_resource, &long_action);

        assert_eq!(check.user_id.len(), 500);
        assert_eq!(check.resource.len(), 500);
        assert_eq!(check.action.len(), 500);
    }

    #[test]
    fn test_permission_check_clone_independence() {
        let mut check1 = PermissionCheck::new("user1", "resource1", "action1");
        let check2 = check1.clone();

        check1.user_id = "modified".to_string();

        // Clone should not be affected
        assert_eq!(check2.user_id, "user1");
    }

    #[test]
    fn test_permission_check_debug_format() {
        let check = PermissionCheck::new("test-user", "test-resource", "test-action");
        let debug_str = format!("{:?}", check);

        assert!(debug_str.contains("PermissionCheck"));
        assert!(debug_str.contains("test-user"));
        assert!(debug_str.contains("test-resource"));
        assert!(debug_str.contains("test-action"));
    }

    // ==================== PermissionCheck Direct Construction ====================

    #[test]
    fn test_permission_check_direct_construction() {
        let check = PermissionCheck {
            user_id: "direct-user".to_string(),
            resource: "direct-resource".to_string(),
            action: "direct-action".to_string(),
        };

        assert_eq!(check.user_id, "direct-user");
        assert_eq!(check.resource, "direct-resource");
        assert_eq!(check.action, "direct-action");
    }

    #[test]
    fn test_permission_check_field_mutation() {
        let mut check = PermissionCheck::new("original", "resource", "action");

        check.user_id = "modified".to_string();
        check.resource = "new-resource".to_string();
        check.action = "new-action".to_string();

        assert_eq!(check.user_id, "modified");
        assert_eq!(check.resource, "new-resource");
        assert_eq!(check.action, "new-action");
    }

    // ==================== Common Permission Patterns ====================

    #[test]
    fn test_permission_check_crud_pattern() {
        let crud_actions = ["create", "read", "update", "delete"];
        let user = "user-123";
        let resource = "sessions";

        for action in crud_actions {
            let check = PermissionCheck::new(user, resource, action);
            assert_eq!(check.action, action);
        }
    }

    #[test]
    fn test_permission_check_admin_pattern() {
        let admin_actions = ["manage", "configure", "audit", "export"];

        for action in admin_actions {
            let check = PermissionCheck::new("admin", "system", action);
            assert_eq!(check.action, action);
        }
    }

    #[test]
    fn test_permission_check_wildcard_pattern() {
        let check = PermissionCheck::new("*", "*", "*");

        assert_eq!(check.user_id, "*");
        assert_eq!(check.resource, "*");
        assert_eq!(check.action, "*");
    }

    #[test]
    fn test_permission_check_hierarchical_resource() {
        let check = PermissionCheck::new("user", "org:team:project:asset", "read");
        assert_eq!(check.resource, "org:team:project:asset");
    }
}
