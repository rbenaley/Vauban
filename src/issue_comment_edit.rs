//! Who may edit an issue comment (Support-authored comments only).

use crate::{
    models::{ISSUE_COMMENT_KIND_COMMENT, ISSUE_ROLE_SUPPORT},
    perms::PermissionContext,
};

pub use crate::models::COMMENT_NOT_EDITED;

/// True when the row is a human Support comment (not a reporter or FSM row).
pub fn is_support_authored_comment(kind: &str, author_role: &str) -> bool {
    kind == ISSUE_COMMENT_KIND_COMMENT && author_role == ISSUE_ROLE_SUPPORT
}

/// Admin zone + `issues_write` may edit Support comments only.
pub fn can_edit_support_comment(perms: &PermissionContext, kind: &str, author_role: &str) -> bool {
    perms.admin_view && perms.issues_write && is_support_authored_comment(kind, author_role)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn staff_write() -> PermissionContext {
        PermissionContext {
            admin_view: true,
            issues_write: true,
            issues_read: true,
            ..PermissionContext::default()
        }
    }

    #[test]
    fn staff_can_edit_support_comment_only() {
        let p = staff_write();
        assert!(can_edit_support_comment(
            &p,
            ISSUE_COMMENT_KIND_COMMENT,
            ISSUE_ROLE_SUPPORT
        ));
        assert!(!can_edit_support_comment(
            &p,
            ISSUE_COMMENT_KIND_COMMENT,
            crate::models::ISSUE_ROLE_REPORTER
        ));
        assert!(!can_edit_support_comment(
            &p,
            crate::models::ISSUE_COMMENT_KIND_STATUS,
            ISSUE_ROLE_SUPPORT
        ));
        assert!(!can_edit_support_comment(
            &p,
            crate::models::ISSUE_COMMENT_KIND_STATUS,
            crate::models::ISSUE_ROLE_SYSTEM
        ));
    }

    #[test]
    fn missing_capability_cannot_edit() {
        let read_only = PermissionContext {
            admin_view: true,
            issues_write: false,
            issues_read: true,
            ..PermissionContext::default()
        };
        assert!(!can_edit_support_comment(
            &read_only,
            ISSUE_COMMENT_KIND_COMMENT,
            ISSUE_ROLE_SUPPORT
        ));
        let company = PermissionContext {
            admin_view: false,
            issues_write: true,
            issues_read: true,
            ..PermissionContext::default()
        };
        assert!(!can_edit_support_comment(
            &company,
            ISSUE_COMMENT_KIND_COMMENT,
            ISSUE_ROLE_SUPPORT
        ));
    }
}
