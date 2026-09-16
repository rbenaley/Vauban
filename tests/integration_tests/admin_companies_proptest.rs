//! Property tests for seat boundary, email normalize, and company slugify.

use proptest::prelude::*;
use vcp::companies_accounts::{
    COMPANY_DISPLAY_SEP, apply_lts_compose_action, clamp_lts_count, format_company_address,
    format_technical_contact, normalize_contact_email, normalize_emails, parse_lts_subscriptions,
    show_remove_account_row,
};
use vcp::list_page::{COMPANIES_PAGE_SIZE, LIST_PAGE_SIZE};
use vcp::models::{MAX_LTS_SUBSCRIPTIONS_DEFAULT, MAX_USERS_PER_COMPANY};
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
    #![proptest_config(crate::common::prop_config(24))]

    #[test]
    fn prop_seat_boundary_respects_max(n in 0usize..=12, max in 1usize..=8) {
        prop_assert_eq!(under_seat_cap(n, max), n < max);
        // Default constant still documents product default.
        prop_assert_eq!(MAX_USERS_PER_COMPANY, 5);
    }
}

proptest! {
    #![proptest_config(crate::common::prop_config(32))]

    #[test]
    fn prop_company_slug_from_name(name in "Test [A-Za-z0-9 ]{2,32}") {
        let s = slugify(&name);
        prop_assert!(s.starts_with("test"));
        prop_assert!(s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'));
    }
}

proptest! {
    #![proptest_config(crate::common::prop_config(24))]

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
    #![proptest_config(crate::common::prop_config(6))]

    /// `#[page(POST)]` contract: an invalid compose form always re-renders
    /// (200, form + error copy, admin chrome) and never 303s or 5xxs.
    #[test]
    fn prop_invalid_company_form_rerenders_never_redirects(
        name in prop_oneof![Just(String::new()), Just("   ".to_owned()), "Prop Co [a-z]{3,8}"],
        account in prop_oneof![Just("not-an-email".to_owned()), "[a-z]{3,8}", "[a-z]{3,6}@[a-z]{3,6}\\.test"],
    ) {
        // Keep at least one invalid dimension so the save always fails.
        prop_assume!(name.trim().is_empty() || !account.contains('@'));
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("rt");
        rt.block_on(async {
            let _guard = crate::common::db_lock().lock().await;
            let db = crate::common::test_db().await;
            crate::common::cleanup(&db).await;
            let email = crate::common::unique_email("prop-co-invalid");
            let slug = crate::common::unique_slug("prop-co-invalid");
            let (_user, _org) = crate::common::create_org_with_membership(
                &db, &email, "password", &slug, "admin",
            )
            .await;
            let router = crate::common::test_router().await;
            let cookie = crate::common::login_cookie(&router, &email).await;
            let body = format!(
                "name={}&contact_name=Ops&contact_email=ops%40example.com&account_rows=1&compose_action=save&email_0={}",
                crate::common::urlencoding_encode(&name),
                crate::common::urlencoding_encode(&account)
            );
            let resp = crate::common::post_form(
                &router, "/admin/companies/new", cookie.as_deref(), &body,
            )
            .await;
            let code = crate::common::status(&resp);
            assert_eq!(code, topcoat::router::StatusCode::OK, "invalid form must re-render, got {code}");
            let bytes = http_body_util::BodyExt::collect(resp.into_body()).await.expect("body").to_bytes();
            let html = String::from_utf8_lossy(&bytes);
            assert!(html.contains("vb-rail"), "re-render keeps admin chrome");
            assert!(
                html.contains("Company name is required") || html.contains("Invalid email address"),
                "re-render shows the validation error: {html}"
            );
            crate::common::cleanup(&db).await;
        });
    }
}

proptest! {
    #![proptest_config(crate::common::prop_config(32))]

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
    #![proptest_config(crate::common::prop_config(24))]

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

    #[test]
    fn prop_format_company_address_joins_nonempty_lines(
        a in "[A-Za-z0-9 .,-]{1,24}",
        b in "[A-Za-z0-9 .,-]{1,24}",
        c in "[A-Za-z0-9 .,-]{0,24}",
    ) {
        // Regex allows whitespace-only segments; the helper trims and drops them.
        let raw = format!("{a}\n  \n{b}\n{c}\n");
        let out = format_company_address(&raw);
        let expected = {
            let parts: Vec<&str> = [a.as_str(), b.as_str(), c.as_str()]
                .into_iter()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .collect();
            if parts.is_empty() {
                "—".to_owned()
            } else {
                parts.join(COMPANY_DISPLAY_SEP)
            }
        };
        prop_assert!(!out.is_empty());
        prop_assert!(!out.contains('\n'));
        for part in [a.as_str(), b.as_str(), c.as_str()]
            .into_iter()
            .map(str::trim)
            .filter(|line| !line.is_empty())
        {
            prop_assert!(out.contains(part));
        }
        prop_assert_eq!(out, expected);
        // Same glyph as technical contact name/email join.
        let contact = format_technical_contact("Name", "a@b.test");
        prop_assert!(contact.contains(COMPANY_DISPLAY_SEP));
    }
}

proptest! {
    #![proptest_config(crate::common::prop_config(48))]

    #[test]
    fn prop_clamp_lts_stays_in_range(value in -50i32..200, max in 0usize..=99) {
        let clamped = clamp_lts_count(value, max);
        prop_assert!(clamped >= 0);
        let max_i = i32::try_from(max).unwrap_or(i32::MAX);
        prop_assert!(clamped <= max_i);
        prop_assert_eq!(MAX_LTS_SUBSCRIPTIONS_DEFAULT, 99);
    }

    #[test]
    fn prop_parse_lts_accepts_in_range(value in 0i32..=99) {
        let raw = value.to_string();
        let parsed = parse_lts_subscriptions(&raw, 99, "Vauban LTS subscriptions")
            .expect("in-range");
        prop_assert_eq!(parsed, value);
    }

    #[test]
    fn prop_stepper_actions_stay_clamped(
        lts in 0i32..=99,
        industrial in 0i32..=99,
        action in prop_oneof![
            Just("lts_inc"),
            Just("lts_dec"),
            Just("ind_inc"),
            Just("ind_dec")
        ]
    ) {
        let (next_lts, next_ind) =
            apply_lts_compose_action(lts, industrial, action, 99).expect("step");
        prop_assert!((0..=99).contains(&next_lts));
        prop_assert!((0..=99).contains(&next_ind));
    }
}

proptest! {
    #![proptest_config(crate::common::prop_config(32))]

    #[test]
    fn prop_show_remove_account_row(
        extra_rows in 0usize..=6,
        email in ".*{0,48}"
    ) {
        let row_count = extra_rows + 1;
        let show = show_remove_account_row(row_count, &email);
        if row_count > 1 {
            prop_assert!(show);
        } else {
            prop_assert_eq!(show, !email.trim().is_empty());
        }
    }
}
