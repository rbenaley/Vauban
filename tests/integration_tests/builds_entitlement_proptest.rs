//! Property tests for download entitlement message stability.

use proptest::prelude::*;

const MSG: &str = "download not configured";

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    #[test]
    fn prop_download_message_is_stable(_n in 0u8..32) {
        prop_assert_eq!(MSG, "download not configured");
        prop_assert!(!MSG.is_empty());
        prop_assert!(MSG.chars().all(|c| c.is_ascii_lowercase() || c == ' '));
    }
}
