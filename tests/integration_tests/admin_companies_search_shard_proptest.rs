//! Property tests for admin companies search helpers.

use proptest::prelude::*;
use vcp::companies_search::{CompanyMatchFields, company_matches_query, normalize_query};
use vcp::list_page::COMPANIES_PAGE_SIZE;

use crate::common::{admin_companies_search_shard_body_page, shard_args_array};

#[test]
fn prop_companies_page_size_is_three() {
    assert_eq!(COMPANIES_PAGE_SIZE, 3);
}

proptest! {
    #![proptest_config(crate::common::prop_config(48))]

    #[test]
    fn prop_query_match_and_body(q in "[A-Za-z0-9 ]{0,20}", page in "1|2|3") {
        let nq = normalize_query(&q);
        prop_assert_eq!(nq.as_str(), nq.trim());
        if !nq.is_empty() {
            let name = nq.to_uppercase();
            let matched = company_matches_query(
                &nq,
                &CompanyMatchFields {
                    name: &name,
                    slug: "x",
                    contact_name: "",
                    contact_email: "",
                    vat: "",
                    address: "",
                    emails: &[],
                },
            );
            prop_assert!(matched);
        }
        let body = admin_companies_search_shard_body_page(&q, &page);
        prop_assert!(body.contains("\"args\":"));
        prop_assert!(body.contains("\"signals\":"));
        let args = shard_args_array(&body);
        prop_assert!(args.starts_with('['));
        // q, page
        prop_assert_eq!(args.matches(',').count(), 1);
    }
}
