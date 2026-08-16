//! Property tests: every RFC 4514 special (and any non-allowlisted
//! character) makes `substitute_bind_dn` fail closed.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use proptest::prelude::*;
use shared::ldap_dn::{BindDnError, substitute_bind_dn, username_allowed_in_bind_dn};

const DN_TEMPLATE: &str = "uid={username},ou=people,dc=example,dc=com";

/// Characters that must never appear in a bind-DN username.
fn rfc4514_specials() -> impl Strategy<Value = char> {
    prop_oneof![
        Just(','),
        Just('='),
        Just('+'),
        Just('"'),
        Just('\\'),
        Just('<'),
        Just('>'),
        Just('#'),
        Just(';'),
        Just(' '),
        Just('{'),
        Just('@'),
        Just('*'),
        Just('('),
        Just(')'),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Any username containing an RFC 4514 special (or `{` / `@`) is rejected.
    #[test]
    fn specials_are_always_rejected(
        prefix in "[A-Za-z0-9][A-Za-z0-9._-]{0,8}",
        special in rfc4514_specials(),
        suffix in "[A-Za-z0-9._-]{0,8}",
    ) {
        let username = format!("{prefix}{special}{suffix}");
        prop_assert!(!username_allowed_in_bind_dn(&username));
        prop_assert_eq!(
            substitute_bind_dn(DN_TEMPLATE, &username),
            Err(BindDnError::IllegalUsername)
        );
    }

    /// Allowlisted usernames produce exactly one substitution of `{username}`.
    #[test]
    fn allowlisted_usernames_substitute_once(
        username in "[A-Za-z0-9][A-Za-z0-9._-]{0,31}",
    ) {
        prop_assert!(username_allowed_in_bind_dn(&username));
        let dn = substitute_bind_dn(DN_TEMPLATE, &username).expect("allowlisted");
        let leftover = "{username}";
        prop_assert!(!dn.contains(leftover));
        prop_assert_eq!(dn, format!("uid={username},ou=people,dc=example,dc=com"));
    }

    /// A template without the placeholder never silently binds a constant DN.
    #[test]
    fn missing_placeholder_is_rejected(
        username in "[A-Za-z0-9][A-Za-z0-9._-]{0,15}",
        template in "[A-Za-z0-9,=]{3,40}",
    ) {
        prop_assume!(!template.contains("{username}"));
        prop_assert_eq!(
            substitute_bind_dn(&template, &username),
            Err(BindDnError::MissingPlaceholder)
        );
    }
}
