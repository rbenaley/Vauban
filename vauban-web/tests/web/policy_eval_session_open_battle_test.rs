//! Battle-tested source pins for policy eval 3→2.
//!
//! Complements the access-side concurrent mint test in
//! `vauban-access::handlers::tests` and the AccessGuard battle suite
//! (proxy re-check remains mandatory).

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

const SSH: &str = include_str!("../../src/handlers/web/ssh.rs");
const RDP: &str = include_str!("../../src/handlers/web/rdp.rs");
const PROXY_SSH: &str = include_str!("../../../vauban-proxy-ssh/src/main.rs");
const PROXY_RDP: &str = include_str!("../../../vauban-proxy-rdp/src/main.rs");

/// JIT early-return after mint must discard the token without INSERT:
/// `show-access-request-modal` appears before the first proxy_sessions insert.
#[test]
fn battle_jit_modal_path_is_before_insert() {
    for (name, src) in [("ssh", SSH), ("rdp", RDP)] {
        let modal = src
            .find("show-access-request-modal")
            .unwrap_or_else(|| panic!("{name}: JIT modal trigger missing"));
        let insert = src
            .find("insert_into(proxy_sessions")
            .unwrap_or_else(|| panic!("{name}: INSERT missing"));
        assert!(
            modal < insert,
            "{name}: JIT modal (byte {modal}) must precede INSERT (byte {insert}) \
             so a discarded mint never leaves a connecting row"
        );
        let mint = src.find(".issue_session_token(").expect("mint");
        assert!(
            mint < modal,
            "{name}: mint must precede JIT modal so require_mfa comes from SessionTokenIssued"
        );
    }
}

/// Proxies must keep AccessGuard.authorize (eval #3) — 3→2 must not
/// collapse defense-in-depth.
#[test]
fn battle_proxies_keep_access_guard_authorize() {
    for (name, src) in [("proxy-ssh", PROXY_SSH), ("proxy-rdp", PROXY_RDP)] {
        assert!(
            src.contains("AccessGuard"),
            "{name} must reference AccessGuard"
        );
        assert!(
            src.contains(".authorize("),
            "{name} must call .authorize( on the session-open path"
        );
    }
}

/// Deny UX on early mint failure keeps the least-info-leak message
/// used before the 3→2 change (`No access rule…`).
#[test]
fn battle_mint_deny_keeps_no_access_rule_message() {
    for (name, src) in [("ssh", SSH), ("rdp", RDP)] {
        assert!(
            src.contains("No access rule grants you access to this asset"),
            "{name}: mint denial must surface the same user-facing string \
             as the former can_access_asset denial"
        );
    }
}
