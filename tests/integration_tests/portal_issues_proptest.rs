//! Property tests for issue details bounds / key shaping / comment roles.

use proptest::prelude::*;
use vcp::issue_status::issue_is_closed;
use vcp::models::{
    ISSUE_COMMENT_KIND_COMMENT, ISSUE_COMMENT_KIND_STATUS, ISSUE_ROLE_REPORTER, ISSUE_ROLE_SUPPORT,
    ISSUE_ROLE_SYSTEM, ISSUE_STATUS_CLOSED, ISSUE_STATUS_IN_ANALYSIS, ISSUE_STATUS_OPEN,
    ISSUE_STATUS_RESOLVED,
};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn prop_details_trim_preserves_nonempty(raw in "[a-zA-Z0-9 .]{1,200}") {
        let details = raw.trim().to_owned();
        prop_assume!(!details.is_empty());
        prop_assert_eq!(details.len(), details.trim().len());
        prop_assert!(details.len() <= 200);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    #[test]
    fn prop_issue_key_shape(n in 200u32..500) {
        let key = format!("VBN-{n}");
        prop_assert!(key.starts_with("VBN-"));
        prop_assert!(key.len() >= 5);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    #[test]
    fn prop_comment_role_and_kind_are_catalogued(
        role in prop_oneof![
            Just(ISSUE_ROLE_REPORTER),
            Just(ISSUE_ROLE_SUPPORT),
            Just(ISSUE_ROLE_SYSTEM)
        ],
        kind in prop_oneof![
            Just(ISSUE_COMMENT_KIND_COMMENT),
            Just(ISSUE_COMMENT_KIND_STATUS)
        ]
    ) {
        prop_assert!(matches!(
            role,
            "reporter" | "support" | "system"
        ));
        prop_assert!(matches!(kind, "comment" | "status_change"));
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    #[test]
    fn prop_issue_closed_catalogue(
        status in prop_oneof![
            Just(ISSUE_STATUS_OPEN),
            Just(ISSUE_STATUS_IN_ANALYSIS),
            Just(ISSUE_STATUS_RESOLVED),
            Just(ISSUE_STATUS_CLOSED),
            Just("closed"),
            Just("RESOLVED"),
            Just("open")
        ]
    ) {
        let closed = issue_is_closed(status);
        let expect = status.eq_ignore_ascii_case(ISSUE_STATUS_CLOSED)
            || status.eq_ignore_ascii_case(ISSUE_STATUS_RESOLVED);
        prop_assert_eq!(closed, expect);
        if !closed {
            // Reopen target is always Open.
            prop_assert_eq!(ISSUE_STATUS_OPEN, "Open");
        }
    }
}
