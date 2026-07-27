//! Property tests for admin docs slug / status helpers.

use proptest::prelude::*;
use vcp::{
    models::{DOC_STATUS_DRAFT, DOC_STATUS_PUBLISHED},
    slug::slugify,
};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn prop_slugify_is_url_safe(title in "[A-Za-z0-9 _-]{1,48}") {
        let s = slugify(&title);
        prop_assert!(!s.is_empty());
        prop_assert!(s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'));
        prop_assert!(!s.starts_with('-'));
        prop_assert!(!s.ends_with('-'));
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    #[test]
    fn prop_publish_flag_maps_status(publish in proptest::bool::ANY) {
        let status = if publish {
            DOC_STATUS_PUBLISHED
        } else {
            DOC_STATUS_DRAFT
        };
        prop_assert!(status == "PUBLISHED" || status == "DRAFT");
        prop_assert_ne!(DOC_STATUS_DRAFT, DOC_STATUS_PUBLISHED);
    }
}
