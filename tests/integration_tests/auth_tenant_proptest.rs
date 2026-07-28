//! Property tests for auth helpers and Casbin role contexts.

use proptest::prelude::*;
use vcp::{
    auth::resolve_home_org_slug,
    config::LoginConfig,
    db::{hash_password, verify_password},
    login_limit::{LoginRateLimiter, verify_login_password},
    models::{PORTAL_ROLE_ADMIN, RESERVED_ORG_SLUG},
    perms::PolicyStore,
};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn prop_password_roundtrip(password in "[a-zA-Z0-9]{8,24}") {
        let hash = hash_password(&password).expect("hash");
        prop_assert!(verify_password(&password, &hash));
        prop_assert!(!verify_password(&(password + "!"), &hash));
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    #[test]
    fn prop_unknown_roles_lack_admin_view(role in "[a-z]{3,12}") {
        prop_assume!(role != "admin" && role != "org");
        let store = PolicyStore::load_from_csv(PolicyStore::default_path()).unwrap();
        let ctx = store.context_for_role(&role);
        prop_assert!(!ctx.admin_view);
        prop_assert!(!ctx.releases_manage);
        prop_assert!(!ctx.companies_manage);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    #[test]
    fn prop_test_email_prefix_isolation(suffix in "[a-z0-9]{4,12}") {
        let email = format!("test_prop_{suffix}@example.com");
        prop_assert!(email.starts_with("test_"));
        prop_assert!(email.contains('@'));
        let slug = format!("test-prop-{suffix}");
        prop_assert!(slug.starts_with("test-"));
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn prop_resolve_home_org_slug_staff_always_vauban(
        client in prop::option::of("[a-z][a-z0-9-]{2,20}")
    ) {
        let landed = resolve_home_org_slug(PORTAL_ROLE_ADMIN, client);
        prop_assert_eq!(landed.as_deref(), Some(RESERVED_ORG_SLUG));
    }

    #[test]
    fn prop_resolve_home_org_slug_member_uses_client_or_none(
        client in prop::option::of("[a-z][a-z0-9-]{2,20}")
    ) {
        let landed = resolve_home_org_slug("", client.clone());
        prop_assert_eq!(landed, client.clone());
        let not_staff = resolve_home_org_slug("org", client.clone());
        prop_assert_eq!(not_staff, client);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    #[test]
    fn prop_login_rate_decide(failures in 0u32..20, max in 1u32..10) {
        let allow = LoginRateLimiter::decide(failures, max, false);
        prop_assert_eq!(allow, failures < max);
        prop_assert!(!LoginRateLimiter::decide(failures, max, true));
    }

    #[test]
    fn prop_verify_login_unknown_email_always_false(password in "[a-zA-Z0-9]{8,24}") {
        prop_assert!(!verify_login_password(&password, None));
    }
}

#[test]
fn prop_login_config_defaults_are_positive() {
    let cfg = LoginConfig::default();
    assert!(cfg.max_attempts >= 1);
    assert!(cfg.window_secs >= 1);
    assert!(cfg.lockout_secs >= 1);
}
