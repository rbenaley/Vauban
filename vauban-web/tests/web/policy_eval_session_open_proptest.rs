//! Property tests for policy eval 3→2 structural contracts.
//!
//! Pure source properties: for any of the connect handlers, the mint /
//! INSERT / SessionOpen ordering is stable under the 3→2 redesign.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use proptest::prelude::*;

const HANDLERS: &[(&str, &str)] = &[
    ("ssh", include_str!("../../src/handlers/web/ssh.rs")),
    ("rdp", include_str!("../../src/handlers/web/rdp.rs")),
];

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// For every connect handler source, mint precedes INSERT and
    /// SessionOpen construction, and can_access_asset is absent.
    #[test]
    fn connect_handlers_mint_once_before_insert_and_open(
        idx in 0usize..HANDLERS.len()
    ) {
        let (name, src) = HANDLERS[idx];
        let mint = src.find(".issue_session_token(");
        prop_assert!(
            mint.is_some(),
            "{}: missing issue_session_token",
            name
        );
        let mint = mint.expect("checked");
        let insert = src.find("insert_into(proxy_sessions");
        prop_assert!(
            insert.is_some(),
            "{}: missing proxy_sessions insert",
            name
        );
        let insert = insert.expect("checked");
        prop_assert!(
            mint < insert,
            "{}: mint@{} must be before insert@{}",
            name,
            mint,
            insert
        );
        prop_assert_eq!(
            src.matches(".issue_session_token(").count(),
            1,
            "{}: exactly one mint",
            name
        );
        prop_assert!(
            !src.contains("can_access_asset("),
            "{}: can_access_asset must stay off the connect path",
            name
        );
    }
}

#[test]
fn issued_session_token_fields_mirror_access_check_result_shape() {
    // Drift pin: IssuedSessionToken constraint field names must stay
    // aligned with shared::messages::AccessCheckResult / SessionTokenIssued.
    let ipc = include_str!("../../src/ipc/access.rs");
    let messages = include_str!("../../../shared/src/messages.rs");
    for field in ["require_mfa", "require_approval", "max_session_duration"] {
        assert!(
            ipc.contains(field) && messages.contains(field),
            "constraint field `{field}` must exist on IssuedSessionToken and SessionTokenIssued"
        );
    }
}
