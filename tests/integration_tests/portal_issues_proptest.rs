//! Property tests for issue details bounds / key shaping / comment roles.

use proptest::prelude::*;
use vcp::issue_key::{next_issue_key_from_keys, parse_vbn_suffix};
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
        prop_assert_eq!(parse_vbn_suffix(&key), Some(n));
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn prop_next_issue_key_strictly_above_max_vbn(
        suffixes in prop::collection::vec(0u32..10_000, 0..40),
        noise in prop::collection::vec("[A-Z]{2,6}-[0-9]{1,5}", 0..10)
    ) {
        let mut keys: Vec<String> = suffixes.iter().map(|n| format!("VBN-{n}")).collect();
        keys.extend(noise);
        let key_refs: Vec<&str> = keys.iter().map(String::as_str).collect();
        let next = next_issue_key_from_keys(key_refs.iter().copied());
        let next_n = parse_vbn_suffix(&next).expect("allocator returns VBN-n");
        if let Some(max) = suffixes.iter().copied().max() {
            prop_assert!(next_n > max);
        } else {
            prop_assert_eq!(next_n, 200);
        }
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
