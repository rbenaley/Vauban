//! Property tests: `apply` is order-independent and `{name}` never
//! interpolates; random keys only grant what the AST allows.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use proptest::prelude::*;
use shared::ldap_mapping::{self, ParseError};

fn parse_ok(src: &str) -> ldap_mapping::MappingFile {
    ldap_mapping::parse(src.as_bytes()).expect("parse")
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Shuffling `static` / `match` / `resolve` lines does not change `apply`.
    #[test]
    fn apply_is_independent_of_line_order(
        name in "[A-Za-z][A-Za-z0-9_-]{0,15}",
        extra in "[A-Za-z][A-Za-z0-9_-]{0,15}",
    ) {
        prop_assume!(!name.eq_ignore_ascii_case("administrators"));
        prop_assume!(!extra.eq_ignore_ascii_case("administrators"));
        prop_assume!(!name.eq_ignore_ascii_case(&extra));

        let lines = [
            "resolve  user-attr  memberOf".to_string(),
            "static   CN=Domain Admins,CN=Users,DC=x  Administrators".to_string(),
            "match    CN={name},OU=g,DC=x  {name}".to_string(),
        ];
        let a = parse_ok(&lines.join("\n"));
        let b = parse_ok(&format!("{}\n{}\n{}", lines[2], lines[0], lines[1]));
        let keys = [
            "CN=Domain Admins,CN=Users,DC=x".to_string(),
            format!("CN={name},OU=g,DC=x"),
            format!("CN={extra},OU=g,DC=x"),
        ];
        prop_assert_eq!(ldap_mapping::apply(&keys, &a), ldap_mapping::apply(&keys, &b));
    }

    /// A capture that includes an RFC 4514 special is a miss, never a grant.
    #[test]
    fn specials_in_capture_are_misses(
        special in prop_oneof![
            Just(','), Just('='), Just('+'), Just('"'),
            Just('<'), Just('>'), Just('#'), Just(';'),
        ],
    ) {
        let ast = parse_ok(
            "resolve user-attr memberOf\nmatch CN={name},OU=g,DC=x {name}\n",
        );
        let key = format!("CN=ab{special}cd,OU=g,DC=x");
        prop_assert!(ldap_mapping::apply([&key], &ast).is_empty());
    }

    /// `{username}` on any executable line refuses parse.
    #[test]
    fn username_placeholder_always_refuses(
        prefix in "[A-Za-z]{1,8}",
    ) {
        let src = format!("static  uid={{username}},ou={prefix}  Admins\n");
        prop_assert_eq!(
            ldap_mapping::parse(src.as_bytes()),
            Err(ParseError::UsernamePlaceholderIllegal)
        );
    }

    /// Random allowlisted names captured from a well-formed key are granted
    /// unless they collide with a reserved static target.
    #[test]
    fn random_keys_only_grant_ast_targets(
        name in "[A-Za-z][A-Za-z0-9._-]{0,20}",
    ) {
        let ast = parse_ok(
            "\
resolve user-attr memberOf
static  CN=Domain Admins,DC=x  Administrators
match   CN={name},OU=g,DC=x  {name}
",
        );
        let key = format!("CN={name},OU=g,DC=x");
        let got = ldap_mapping::apply([&key], &ast);
        if name.eq_ignore_ascii_case("Administrators") {
            prop_assert!(got.is_empty());
        } else {
            prop_assert!(got.contains(&name));
            prop_assert_eq!(got.len(), 1);
        }
    }
}
