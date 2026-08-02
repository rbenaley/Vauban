//! Property tests for seat boundary, email normalize, and company slugify.

use proptest::prelude::*;
use vcp::companies_accounts::{
    format_technical_contact, normalize_contact_email, normalize_emails,
};
use vcp::list_page::{COMPANIES_PAGE_SIZE, LIST_PAGE_SIZE};
use vcp::models::MAX_USERS_PER_COMPANY;
use vcp::seats::under_seat_cap;
use vcp::slug::slugify;

#[test]
fn prop_list_page_size_is_ten() {
    assert_eq!(LIST_PAGE_SIZE, 10);
}

#[test]
fn prop_companies_page_size_is_three() {
    assert_eq!(COMPANIES_PAGE_SIZE, 3);
}

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
    fn prop_normalize_emails_lowercases_valid(
        local in "[a-zA-Z]{2,8}",
        domain in "[a-zA-Z]{2,8}"
    ) {
        let raw = format!("  {local}@{domain}.COM ");
        let out = normalize_emails(std::slice::from_ref(&raw)).expect("valid address");
        prop_assert_eq!(out.len(), 1);
        prop_assert!(out[0].chars().all(|c| !c.is_ascii_uppercase()));
        prop_assert!(out[0].contains('@'));
        let again = normalize_emails(&out).expect("idempotent");
        prop_assert_eq!(out, again);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn prop_normalize_emails_rejects_garbage_without_at(
        s in "[A-Za-z0-9 ._!-]{3,24}"
    ) {
        prop_assume!(!s.contains('@'));
        prop_assume!(!s.trim().is_empty());
        let err = normalize_emails(&[s]).expect_err("no @ must fail");
        prop_assert!(err.contains("Invalid email address"));
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    #[test]
    fn prop_normalize_contact_email_lowercases_valid(
        local in "[a-zA-Z]{2,8}",
        domain in "[a-zA-Z]{2,8}"
    ) {
        let raw = format!("  {local}@{domain}.COM ");
        let out = normalize_contact_email(&raw).expect("valid address");
        prop_assert!(out.chars().all(|c| !c.is_ascii_uppercase()));
        prop_assert!(out.contains('@'));
        let again = normalize_contact_email(&out).expect("idempotent");
        prop_assert_eq!(out, again);
    }

    #[test]
    fn prop_normalize_contact_email_empty_ok(ws in " *") {
        prop_assert_eq!(normalize_contact_email(&ws).expect("empty ok"), "");
    }

    #[test]
    fn prop_normalize_contact_email_rejects_garbage_without_at(
        s in "[A-Za-z0-9 ._!-]{3,24}"
    ) {
        prop_assume!(!s.contains('@'));
        prop_assume!(!s.trim().is_empty());
        let err = normalize_contact_email(&s).expect_err("no @ must fail");
        prop_assert!(err.contains("Invalid email address"));
    }

    #[test]
    fn prop_format_technical_contact_never_empty(
        name in ".*",
        email in ".*"
    ) {
        let line = format_technical_contact(&name, &email);
        prop_assert!(!line.is_empty());
        if name.trim().is_empty() && email.trim().is_empty() {
            prop_assert_eq!(line, "—");
        }
    }
}
