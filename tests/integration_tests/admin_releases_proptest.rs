//! Property tests for release metadata shaping.

use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn prop_release_version_trim(raw in " *test-[a-z0-9.]{1,24} *") {
        let version = raw.trim().to_owned();
        prop_assume!(!version.is_empty());
        prop_assert!(version.starts_with("test-"));
        prop_assert_eq!(version.as_str(), version.trim());
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    #[test]
    fn prop_channel_is_known(channel in prop_oneof!["LTS", "Stable", "EOL"]) {
        prop_assert!(matches!(channel.as_str(), "LTS" | "Stable" | "EOL"));
    }
}
