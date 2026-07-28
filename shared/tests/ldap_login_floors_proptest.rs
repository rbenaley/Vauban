//! Property tests for LDAPS login-form credential length floors.
//!
//! Pins the absolute floors and the pure helpers used by supervisor/web
//! config validation and the login handler gate.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use proptest::prelude::*;
use shared::validation::{
    LDAP_LOGIN_PASSWORD_MIN_FLOOR, LDAP_LOGIN_USERNAME_MIN_FLOOR, credentials_meet_login_mins,
    validate_ldap_login_length_config,
};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Any config mins at-or-above the absolute floors are accepted.
    #[test]
    fn config_accepts_mins_at_or_above_floors(
        user_extra in 0usize..64,
        pass_extra in 0usize..64,
    ) {
        let u = LDAP_LOGIN_USERNAME_MIN_FLOOR + user_extra;
        let p = LDAP_LOGIN_PASSWORD_MIN_FLOOR + pass_extra;
        prop_assert!(validate_ldap_login_length_config(u, p).is_ok());
    }

    /// Username min strictly below the floor always refuses boot.
    #[test]
    fn config_rejects_username_below_floor(
        user_min in 0usize..LDAP_LOGIN_USERNAME_MIN_FLOOR,
        pass_min in LDAP_LOGIN_PASSWORD_MIN_FLOOR..(LDAP_LOGIN_PASSWORD_MIN_FLOOR + 64),
    ) {
        let err = validate_ldap_login_length_config(user_min, pass_min)
            .expect_err("username below floor must fail");
        prop_assert!(err.contains("[auth.ldaps]"));
        prop_assert!(err.contains("login_username_min_length"));
    }

    /// Password min strictly below the floor always refuses boot.
    #[test]
    fn config_rejects_password_below_floor(
        user_min in LDAP_LOGIN_USERNAME_MIN_FLOOR..(LDAP_LOGIN_USERNAME_MIN_FLOOR + 64),
        pass_min in 0usize..LDAP_LOGIN_PASSWORD_MIN_FLOOR,
    ) {
        let err = validate_ldap_login_length_config(user_min, pass_min)
            .expect_err("password below floor must fail");
        prop_assert!(err.contains("[auth.ldaps]"));
        prop_assert!(err.contains("login_password_min_length"));
    }

    /// credentials_meet_login_mins is exactly char-count vs configured mins.
    #[test]
    fn credentials_meet_matches_char_counts(
        user_len in 0usize..48,
        pass_len in 0usize..64,
        user_min in 0usize..32,
        pass_min in 0usize..32,
    ) {
        let username = "u".repeat(user_len);
        let password = "p".repeat(pass_len);
        let expected = user_len >= user_min && pass_len >= pass_min;
        prop_assert_eq!(
            credentials_meet_login_mins(&username, &password, user_min, pass_min),
            expected
        );
    }

    /// Multi-byte Unicode codepoints still count as one char each.
    #[test]
    fn credentials_meet_counts_unicode_scalars(
        user_len in 0usize..24,
        pass_len in 0usize..24,
        user_min in 0usize..16,
        pass_min in 0usize..16,
    ) {
        let username = "é".repeat(user_len);
        let password = "字".repeat(pass_len);
        prop_assert_eq!(username.chars().count(), user_len);
        prop_assert_eq!(password.chars().count(), pass_len);
        let expected = user_len >= user_min && pass_len >= pass_min;
        prop_assert_eq!(
            credentials_meet_login_mins(&username, &password, user_min, pass_min),
            expected
        );
    }

    /// Below absolute password floor (with username OK) never meets default floors.
    #[test]
    fn short_password_never_meets_absolute_floors(pass_len in 0usize..LDAP_LOGIN_PASSWORD_MIN_FLOOR) {
        let username = "u".repeat(LDAP_LOGIN_USERNAME_MIN_FLOOR);
        let password = "p".repeat(pass_len);
        prop_assert!(!credentials_meet_login_mins(
            &username,
            &password,
            LDAP_LOGIN_USERNAME_MIN_FLOOR,
            LDAP_LOGIN_PASSWORD_MIN_FLOOR,
        ));
    }

    /// Below absolute username floor (with password OK) never meets default floors.
    #[test]
    fn short_username_never_meets_absolute_floors(user_len in 0usize..LDAP_LOGIN_USERNAME_MIN_FLOOR) {
        let username = "u".repeat(user_len);
        let password = "p".repeat(LDAP_LOGIN_PASSWORD_MIN_FLOOR);
        prop_assert!(!credentials_meet_login_mins(
            &username,
            &password,
            LDAP_LOGIN_USERNAME_MIN_FLOOR,
            LDAP_LOGIN_PASSWORD_MIN_FLOOR,
        ));
    }
}
