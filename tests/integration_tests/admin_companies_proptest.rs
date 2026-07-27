//! Property tests for seat boundary and company slugify.

use proptest::prelude::*;
use vcp::{models::MAX_USERS_PER_COMPANY, slug::slugify};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    #[test]
    fn prop_seat_boundary(n in 0usize..=8) {
        let can_add = n < MAX_USERS_PER_COMPANY;
        prop_assert_eq!(can_add, n < 5);
        if n >= MAX_USERS_PER_COMPANY {
            prop_assert!(!can_add);
        }
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
