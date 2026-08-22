//! Property tests for org account nav segment stability + session pill helper.

use proptest::prelude::*;
use vcp::{
    build_info::product_label,
    companies_accounts::{
        account_address_display, account_member_pill_class, format_company_address,
        is_signed_in_member,
    },
    models::RESERVED_ORG_SLUG,
    nav::{NavSection, nav_from_path},
};

proptest! {
    #![proptest_config(crate::common::prop_config(32))]

    #[test]
    fn prop_account_path_maps_to_account_section(
        slug in "[a-z][a-z0-9-]{1,24}"
    ) {
        let path = format!("/{slug}/account");
        let (section, crumb) = nav_from_path(&path);
        prop_assert_eq!(section, NavSection::Account);
        prop_assert_eq!(crumb, "account");
    }

    #[test]
    fn prop_signed_in_pill_marks_only_matching_email(
        local in "[a-z][a-z0-9._-]{1,16}",
        other in "[a-z][a-z0-9._-]{1,16}",
        domain in "[a-z]{2,8}\\.test",
    ) {
        prop_assume!(local != other);
        let signed_in = format!("{local}@{domain}");
        let peer = format!("{other}@{domain}");
        let upper = signed_in.to_ascii_uppercase();
        prop_assert!(is_signed_in_member(&signed_in, &signed_in));
        prop_assert!(is_signed_in_member(&upper, &signed_in));
        prop_assert!(!is_signed_in_member(&peer, &signed_in));
        prop_assert_eq!(
            account_member_pill_class(&signed_in, &signed_in),
            "vb-account-pill is-you"
        );
        prop_assert_eq!(
            account_member_pill_class(&peer, &signed_in),
            "vb-account-pill"
        );
    }

    #[test]
    fn prop_account_address_reserved_is_build_else_stored(
        slug in "[a-z][a-z0-9-]{1,24}",
        line_a in "[A-Za-z0-9 .,]{1,40}",
        line_b in "[A-Za-z0-9 .,]{0,40}",
    ) {
        let stored = if line_b.is_empty() {
            line_a.clone()
        } else {
            format!("{line_a}\n{line_b}")
        };
        let shown = account_address_display(&slug, &stored);
        if slug.eq_ignore_ascii_case(RESERVED_ORG_SLUG) {
            prop_assert_eq!(&shown, &product_label());
        } else {
            prop_assert_eq!(&shown, &format_company_address(&stored));
            prop_assert!(!shown.contains("VCP — v"));
        }
    }
}
