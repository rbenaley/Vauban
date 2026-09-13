//! Property tests for docs search shard pure helpers (production code).

use proptest::prelude::*;
use vcp::docs_search::{
    normalize_category, normalize_org_slug, normalize_query, text_matches_query,
};

use crate::common::{docs_search_shard_body, shard_args_array};

proptest! {
    #![proptest_config(crate::common::prop_config(48))]

    #[test]
    fn prop_query_trim_lowercase_idempotent(raw in " *[A-Za-z0-9 ]{0,40} *") {
        let once = normalize_query(&raw);
        let twice = normalize_query(&once);
        prop_assert_eq!(&once, &twice);
        prop_assert_eq!(once.as_str(), once.trim());
        prop_assert!(!once.chars().any(|c| c.is_ascii_uppercase()));
    }

    #[test]
    fn prop_category_trim_preserves_inner_case(raw in " *[A-Za-z]{0,20} *") {
        let cat = normalize_category(&raw);
        prop_assert_eq!(cat.as_str(), cat.trim());
        if !raw.trim().is_empty() {
            prop_assert_eq!(cat, raw.trim());
        }
    }

    #[test]
    fn prop_blank_org_slug_rejected(spaces in " *") {
        prop_assert_eq!(normalize_org_slug(&spaces), None);
    }

    #[test]
    fn prop_nonempty_org_slug_trimmed(
        pad_l in " *",
        body in "[a-z0-9-]{1,20}",
        pad_r in " *"
    ) {
        let raw = format!("{pad_l}{body}{pad_r}");
        prop_assert_eq!(normalize_org_slug(&raw), Some(body.as_str()));
    }

    #[test]
    fn prop_text_match_case_insensitive(needle in "[A-Za-z]{3,10}") {
        let q = normalize_query(&needle);
        let title = needle.to_uppercase();
        prop_assert!(text_matches_query(&q, &title, "zzz"));
        prop_assert!(text_matches_query(&q, "zzz", &title));
        prop_assert!(!text_matches_query(&q, "nope", "still-nope"));
    }

    #[test]
    fn prop_shard_json_body_embeds_args(
        org in "[a-z0-9-]{1,16}",
        q in "[A-Za-z0-9 ]{0,24}",
        cat in "[A-Za-z ]{0,16}"
    ) {
        let body = docs_search_shard_body(&org, &q, &cat);
        prop_assert!(body.contains("\"args\":"));
        prop_assert!(body.contains("\"signals\":"));
        let args = shard_args_array(&body);
        prop_assert!(args.starts_with('['));
        prop_assert!(args.ends_with(']'));
        prop_assert!(args.contains(&org));
        // Empty q/cat still produce quoted empty strings.
        prop_assert_eq!(args.matches('"').count() % 2, 0);
        prop_assert_eq!(args.matches(',').count(), 3);
        prop_assert!(args.contains("\"1\""));
    }
}
