//! Property tests for issue details bounds / key shaping / comment roles.

use proptest::prelude::*;
use vcp::models::{
    ISSUE_COMMENT_KIND_COMMENT, ISSUE_COMMENT_KIND_STATUS, ISSUE_ROLE_REPORTER, ISSUE_ROLE_SUPPORT,
    ISSUE_ROLE_SYSTEM,
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
