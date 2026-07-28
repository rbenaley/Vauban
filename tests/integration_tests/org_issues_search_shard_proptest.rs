//! Property tests for org issues search helpers (production code).

use proptest::prelude::*;
use vcp::issues_search::{
    issue_matches_query, issue_matches_status, normalize_query, normalize_status,
};

use crate::common::org_issues_search_shard_body;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn prop_query_trim_lowercase_idempotent(raw in " *[A-Za-z0-9 -]{0,40} *") {
        let once = normalize_query(&raw);
        let twice = normalize_query(&once);
        prop_assert_eq!(&once, &twice);
        prop_assert_eq!(once.as_str(), once.trim());
        prop_assert!(!once.chars().any(|c| c.is_ascii_uppercase()));
    }

    #[test]
    fn prop_status_trim(raw in " *[A-Za-z ]{0,20} *") {
        let status = normalize_status(&raw);
        prop_assert_eq!(status.as_str(), status.trim());
    }

    #[test]
    fn prop_issue_match_case_insensitive(needle in "[A-Za-z]{3,10}") {
        let q = normalize_query(&needle);
        let key = needle.to_uppercase();
        prop_assert!(issue_matches_query(&q, &key, "zzz"));
        prop_assert!(issue_matches_query(&q, "zzz", &key));
        prop_assert!(issue_matches_status("Open", "open"));
        prop_assert!(!issue_matches_status("Closed", "Open"));
    }

    #[test]
    fn prop_shard_json_body_embeds_args(
        org in "[a-z0-9-]{1,16}",
        q in "[A-Za-z0-9 -]{0,24}",
        status in "[A-Za-z ]{0,16}"
    ) {
        let body = org_issues_search_shard_body(&org, &q, &status);
        prop_assert!(body.starts_with('['));
        prop_assert!(body.ends_with(']'));
        prop_assert!(body.contains(&org));
        prop_assert_eq!(body.matches(',').count(), 2);
    }
}
