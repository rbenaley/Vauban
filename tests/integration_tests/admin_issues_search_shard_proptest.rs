//! Property tests for admin issues search helpers (production code).

use proptest::prelude::*;
use vcp::issues_search::{
    issue_matches_org, issue_matches_query, normalize_org_filter, normalize_query,
    resolve_org_filter,
};

use crate::common::admin_issues_search_shard_body;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn prop_org_filter_trim(raw in " *[A-Za-z0-9-]{0,20} *") {
        let once = normalize_org_filter(&raw);
        prop_assert_eq!(once.as_str(), once.trim());
    }

    #[test]
    fn prop_resolve_org_filter_by_slug_or_id(
        id in 1u64..50_000,
        slug in "[a-z][a-z0-9-]{1,12}"
    ) {
        let orgs = [(id, slug.as_str()), (id + 1, "other")];
        prop_assert_eq!(resolve_org_filter(orgs, &id.to_string()), Some(id));
        prop_assert_eq!(resolve_org_filter(orgs, &slug), Some(id));
        prop_assert_eq!(resolve_org_filter(orgs, "missing"), None);
        prop_assert!(issue_matches_org("", None, id));
        prop_assert!(issue_matches_org(&slug, Some(id), id));
        prop_assert!(!issue_matches_org(&slug, Some(id), id + 1));
    }

    #[test]
    fn prop_query_match_and_body(
        q in "[A-Za-z0-9 ]{0,20}",
        org in "[a-z0-9-]{0,16}",
        status in "[A-Za-z ]{0,12}"
    ) {
        let nq = normalize_query(&q);
        prop_assert_eq!(nq.as_str(), nq.trim());
        if !nq.is_empty() {
            prop_assert!(issue_matches_query(&nq, &nq.to_uppercase(), "x"));
        }
        let body = admin_issues_search_shard_body(&q, &org, &status);
        prop_assert!(body.starts_with('['));
        prop_assert_eq!(body.matches(',').count(), 2);
    }
}
