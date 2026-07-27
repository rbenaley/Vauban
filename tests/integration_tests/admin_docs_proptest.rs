//! Property tests for admin docs slug / status helpers + dialect escaping.

use proptest::prelude::*;
use vcp::{
    docs_body::{self, Block},
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

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    #[test]
    fn prop_bump_version_increments(n in 1u32..200) {
        let cur = format!("v{n}");
        let next = vcp::docs_version::bump_version(&cur);
        prop_assert_eq!(next, format!("v{}", n + 1));
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn prop_delete_confirm_only_exact_delete(
        s in "[A-Za-z0-9 _]{0,24}"
    ) {
        let ok = vcp::docs_version::is_delete_confirm(&s);
        prop_assert_eq!(ok, s.trim() == "delete");
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(40))]

    #[test]
    fn prop_docs_body_escape_neutralizes_angle_brackets(
        raw in "[A-Za-z0-9 <>\"'&]{0,80}"
    ) {
        let escaped = docs_body::escape_html(&raw);
        prop_assert!(!escaped.contains('<'));
        prop_assert!(!escaped.contains('>'));
        if raw.contains('<') {
            prop_assert!(escaped.contains("&lt;"));
        }
        let blocks = docs_body::parse(&raw);
        for block in blocks {
            match block {
                Block::Paragraph(t) | Block::Heading(t) | Block::Pre(t) | Block::Callout(t) => {
                    let again = docs_body::escape_html(&t);
                    prop_assert!(!again.contains('<'));
                }
                Block::List(items) => {
                    for item in items {
                        prop_assert!(!docs_body::escape_html(&item).contains('<'));
                    }
                }
            }
        }
    }
}
