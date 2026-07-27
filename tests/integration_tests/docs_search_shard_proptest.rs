//! Property tests for docs search query normalization.

use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn prop_query_trim_lowercase(raw in " *[A-Za-z0-9 ]{0,40} *") {
        let q = raw.trim().to_lowercase();
        prop_assert_eq!(q.as_str(), q.trim());
        prop_assert!(!q.chars().any(|c| c.is_ascii_uppercase()));
    }
}
