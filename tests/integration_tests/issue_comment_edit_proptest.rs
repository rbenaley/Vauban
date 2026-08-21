//! Property tests for Support comment edit gates.

use proptest::prelude::*;
use vcp::issue_comment_edit::{can_edit_support_comment, is_support_authored_comment};
use vcp::models::{
    ISSUE_COMMENT_KIND_COMMENT, ISSUE_COMMENT_KIND_STATUS, ISSUE_ROLE_REPORTER, ISSUE_ROLE_SUPPORT,
    ISSUE_ROLE_SYSTEM,
};
use vcp::perms::PermissionContext;

fn any_kind() -> impl Strategy<Value = &'static str> {
    prop_oneof![
        Just(ISSUE_COMMENT_KIND_COMMENT),
        Just(ISSUE_COMMENT_KIND_STATUS),
    ]
}

fn any_role() -> impl Strategy<Value = &'static str> {
    prop_oneof![
        Just(ISSUE_ROLE_SUPPORT),
        Just(ISSUE_ROLE_REPORTER),
        Just(ISSUE_ROLE_SYSTEM),
    ]
}

proptest! {
    #![proptest_config(crate::common::prop_config(32))]

    #[test]
    fn prop_only_staff_write_edits_support_comments(
        admin_view in any::<bool>(),
        issues_write in any::<bool>(),
        kind in any_kind(),
        role in any_role(),
    ) {
        let perms = PermissionContext {
            admin_view,
            issues_write,
            issues_read: true,
            ..PermissionContext::default()
        };
        let allowed = can_edit_support_comment(&perms, kind, role);
        let expected = admin_view
            && issues_write
            && is_support_authored_comment(kind, role);
        prop_assert_eq!(allowed, expected);
        if role != ISSUE_ROLE_SUPPORT || kind != ISSUE_COMMENT_KIND_COMMENT {
            prop_assert!(!allowed);
        }
    }
}
