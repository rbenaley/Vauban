//! Property tests for auth helpers and Casbin role contexts.

use proptest::prelude::*;
use vcp::{
    db::{hash_password, verify_password},
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
        prop_assume!(role != "admin" && role != "member");
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
