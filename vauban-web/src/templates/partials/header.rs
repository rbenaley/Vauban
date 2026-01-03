/// VAUBAN Web - Header data structure.

use crate::templates::base::UserContext;

/// Header data (not a template itself, used as data in includes).
#[derive(Debug, Clone)]
pub struct HeaderTemplate {
    pub user: UserContext,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_user_context() -> UserContext {
        UserContext {
            uuid: "user-uuid".to_string(),
            username: "testuser".to_string(),
            display_name: "Test User".to_string(),
            is_superuser: false,
            is_staff: false,
        }
    }

    #[test]
    fn test_header_template_creation() {
        let template = HeaderTemplate {
            user: create_test_user_context(),
        };
        assert_eq!(template.user.username, "testuser");
    }

    #[test]
    fn test_header_template_with_superuser() {
        let mut user = create_test_user_context();
        user.is_superuser = true;
        user.is_staff = true;
        
        let template = HeaderTemplate { user };
        assert!(template.user.is_superuser);
        assert!(template.user.is_staff);
    }

    #[test]
    fn test_header_template_clone() {
        let template = HeaderTemplate {
            user: create_test_user_context(),
        };
        let cloned = template.clone();
        assert_eq!(template.user.uuid, cloned.user.uuid);
    }
}
