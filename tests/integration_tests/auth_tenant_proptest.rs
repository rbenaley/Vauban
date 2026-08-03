//! Property tests for auth helpers and Casbin role contexts.

use proptest::prelude::*;
use vcp::{
    auth::{PostAuthLanding, classify_post_auth_landing, resolve_home_org_slug},
    config::LoginConfig,
    login_limit::LoginRateLimiter,
    magic_link::{generate_raw_token, hash_token},
    models::{PORTAL_ROLE_ADMIN, PORTAL_ROLE_ORG, RESERVED_ORG_SLUG, is_allowed_portal_role},
    perms::PolicyStore,
};

proptest! {
    #![proptest_config(crate::common::prop_config(24))]

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
    #![proptest_config(crate::common::prop_config(24))]

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
    #![proptest_config(crate::common::prop_config(32))]

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
        let landed = resolve_home_org_slug(PORTAL_ROLE_ORG, client.clone());
        prop_assert_eq!(landed, client);
    }

    #[test]
    fn prop_classify_post_auth_landing_by_client_count(
        slugs in prop::collection::vec("[a-z][a-z0-9-]{2,12}", 0..6)
    ) {
        // Deduplicate so len matches distinct memberships.
        let mut unique = slugs;
        unique.sort();
        unique.dedup();
        let landed = classify_post_auth_landing(PORTAL_ROLE_ORG, &unique);
        match unique.len() {
            0 => prop_assert_eq!(landed, PostAuthLanding::None),
            1 => prop_assert_eq!(landed, PostAuthLanding::Org(unique[0].clone())),
            _ => prop_assert_eq!(landed, PostAuthLanding::ChooseOrg),
        }
        let staff = classify_post_auth_landing(PORTAL_ROLE_ADMIN, &unique);
        prop_assert_eq!(staff, PostAuthLanding::Org(RESERVED_ORG_SLUG.to_owned()));
    }

    #[test]
    fn prop_portal_role_catalogue_rejects_noise(role in "[a-z]{1,16}") {
        prop_assume!(role != PORTAL_ROLE_ADMIN && role != PORTAL_ROLE_ORG);
        prop_assert!(!is_allowed_portal_role(&role));
    }
}

proptest! {
    #![proptest_config(crate::common::prop_config(24))]

    #[test]
    fn prop_login_rate_decide(failures in 0u32..20, max in 1u32..10) {
        let allow = LoginRateLimiter::decide(failures, max, false);
        prop_assert_eq!(allow, failures < max);
        prop_assert!(!LoginRateLimiter::decide(failures, max, true));
    }

    #[test]
    fn prop_magic_token_hash_stable(raw in "[0-9a-f]{16,64}") {
        prop_assert_eq!(hash_token(&raw), hash_token(&raw));
        let (a, ha) = generate_raw_token();
        let (b, hb) = generate_raw_token();
        prop_assert_ne!(&a, &b);
        prop_assert_eq!(ha, hash_token(&a));
        prop_assert_eq!(hb, hash_token(&b));
    }
}

#[test]
fn prop_login_config_defaults_are_positive() {
    let cfg = LoginConfig::default();
    assert!(cfg.max_attempts >= 1);
    assert!(cfg.window_secs >= 1);
    assert!(cfg.lockout_secs >= 1);
}
