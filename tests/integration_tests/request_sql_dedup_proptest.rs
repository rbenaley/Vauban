//! Property tests: memoize keys stay stable under filter normalization.

use proptest::prelude::*;
use vcp::{
    docs_search::{normalize_category, normalize_query as normalize_docs_query},
    issues_search::{
        normalize_org_filter, normalize_query as normalize_issues_query, normalize_status,
    },
    list_page::page_offset,
};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn prop_docs_filter_key_idempotent_after_normalize(q in ".*", cat in ".*") {
        let q1 = normalize_docs_query(&q);
        let cat1 = normalize_category(&cat);
        let q2 = normalize_docs_query(&q1);
        let cat2 = normalize_category(&cat1);
        prop_assert_eq!(&q1, &q2);
        prop_assert_eq!(&cat1, &cat2);
    }

    #[test]
    fn prop_issues_filter_key_idempotent_after_normalize(
        q in ".*",
        status in ".*",
        org in ".*"
    ) {
        let q1 = normalize_issues_query(&q);
        let s1 = normalize_status(&status);
        let o1 = normalize_org_filter(&org);
        prop_assert_eq!(&q1, &normalize_issues_query(&q1));
        prop_assert_eq!(&s1, &normalize_status(&s1));
        prop_assert_eq!(&o1, &normalize_org_filter(&o1));
    }

    #[test]
    fn prop_page_offset_zero_based(page in 0usize..50, size in 1usize..20) {
        let off = page_offset(page, size);
        if page <= 1 {
            prop_assert_eq!(off, 0);
        } else {
            prop_assert_eq!(off, (page - 1) * size);
        }
    }
}
