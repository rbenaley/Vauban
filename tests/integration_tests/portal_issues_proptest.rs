//! Property tests for issue details bounds / key shaping.

use proptest::prelude::*;

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
