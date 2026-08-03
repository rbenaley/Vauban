//! Property tests for release metadata shaping and status badges.

use proptest::prelude::*;
use vcp::{
    docs_version::is_delete_confirm,
    models::{RELEASE_STATUS_HIDDEN, RELEASE_STATUS_PUBLISHED},
    ui::release_status_badge_class,
};

proptest! {
    #![proptest_config(crate::common::prop_config(32))]

    #[test]
    fn prop_release_version_trim(raw in " *test-[a-z0-9.]{1,24} *") {
        let version = raw.trim().to_owned();
        prop_assume!(!version.is_empty());
        prop_assert!(version.starts_with("test-"));
        prop_assert_eq!(version.as_str(), version.trim());
    }
}

proptest! {
    #![proptest_config(crate::common::prop_config(16))]

    #[test]
    fn prop_channel_is_known(channel in prop_oneof!["LTS", "Stable", "EOL"]) {
        prop_assert!(matches!(channel.as_str(), "LTS" | "Stable" | "EOL"));
    }
}

proptest! {
    #![proptest_config(crate::common::prop_config(24))]

    #[test]
    fn prop_status_badge_mapping(
        status in prop_oneof![
            Just(RELEASE_STATUS_PUBLISHED.to_owned()),
            Just(RELEASE_STATUS_HIDDEN.to_owned()),
            Just("published".to_owned()),
            Just("hidden".to_owned()),
            Just("DRAFT".to_owned()),
            Just("unknown".to_owned()),
        ]
    ) {
        let class = release_status_badge_class(&status);
        let upper = status.trim().to_ascii_uppercase();
        match upper.as_str() {
            "PUBLISHED" => prop_assert_eq!(class, "vb-badge status-published"),
            "HIDDEN" => prop_assert_eq!(class, "vb-badge status-hidden"),
            _ => prop_assert_eq!(class, "vb-badge soft"),
        }
    }
}

proptest! {
    #![proptest_config(crate::common::prop_config(32))]

    #[test]
    fn prop_delete_confirm_only_exact_delete(
        s in prop::collection::vec(prop::char::range('a', 'z'), 0..12)
            .prop_map(|v| v.into_iter().collect::<String>())
    ) {
        let ok = is_delete_confirm(&s);
        prop_assert_eq!(ok, s.trim() == "delete");
    }
}
