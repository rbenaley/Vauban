//! Property tests for seat boundary, email normalize, and company slugify.

use proptest::prelude::*;
use vcp::companies_accounts::normalize_emails;
use vcp::models::MAX_USERS_PER_COMPANY;
use vcp::seats::under_seat_cap;
use vcp::slug::slugify;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    #[test]
    fn prop_seat_boundary_respects_max(n in 0usize..=12, max in 1usize..=8) {
        prop_assert_eq!(under_seat_cap(n, max), n < max);
        // Default constant still documents product default.
        prop_assert_eq!(MAX_USERS_PER_COMPANY, 5);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn prop_company_slug_from_name(name in "Test [A-Za-z0-9 ]{2,32}") {
        let s = slugify(&name);
        prop_assert!(s.starts_with("test"));
        prop_assert!(s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'));
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    #[test]
    fn prop_normalize_emails_lowercases(
        local in "[a-zA-Z]{2,8}",
        domain in "[a-zA-Z]{2,8}"
    ) {
        let raw = format!("  {local}@{domain}.COM ");
        let out = normalize_emails(&[raw]);
        prop_assert_eq!(out.len(), 1);
        prop_assert!(out[0].chars().all(|c| !c.is_ascii_uppercase()));
        prop_assert!(out[0].contains('@'));
    }
}
