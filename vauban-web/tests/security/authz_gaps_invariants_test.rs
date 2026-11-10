//! Source invariants for the three authorization fences closed by
//! `docs/remediation/authz_shadowing_and_api_gaps.md`.
//!
//! The shape of the code is the contract here: a refactor that drops
//! one of these call sites must fail CI even if no behavioral test
//! happens to exercise the exact path.
//!
//! Companion of `authz_gaps_e2e_test.rs`, `authz_gaps_proptest.rs`,
//! `authz_gaps_battle_test.rs` and
//! `docs/runbooks/authz_gaps_smoke_test.md`.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

const MAIN: &str = include_str!("../../src/main.rs");
const TEST_ROUTER: &str = include_str!("../common/mod.rs");
const WEBSOCKET: &str = include_str!("../../src/handlers/websocket.rs");
const API_ACCOUNTS: &str = include_str!("../../src/handlers/api/accounts.rs");
const API_SESSIONS: &str = include_str!("../../src/handlers/api/sessions.rs");
const WEB_SESSIONS: &str = include_str!("../../src/handlers/web/sessions.rs");
const ROLE_INVARIANTS: &str = include_str!("../../src/services/role_invariants.rs");
const RUNBOOK: &str = include_str!("../../../docs/runbooks/authz_gaps_smoke_test.md");

/// Body of the item starting at `signature`, up to the next top-level
/// `pub ` item or the test module.
fn item_body<'a>(source: &'a str, signature: &str) -> &'a str {
    let start = source
        .find(signature)
        .unwrap_or_else(|| panic!("`{signature}` must exist"));
    let after = &source[start..];
    let skip = signature.len();
    let next_item = after[skip..]
        .find("\npub ")
        .map(|o| skip + o)
        .unwrap_or(after.len());
    let cfg_test = after.find("#[cfg(test)]").unwrap_or(after.len());
    &after[..next_item.min(cfg_test)]
}

/// Strip `//` comment lines so a pin on forbidden text is not defeated
/// (or triggered) by prose.
fn code_only(body: &str) -> String {
    body.lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

// ---------------------------------------------------------------------
// 1. Interactive WebSocket data plane is owner-only
// ---------------------------------------------------------------------

#[test]
fn inv_terminal_and_rdp_routes_use_the_owner_guard() {
    for (name, src) in [("main.rs", MAIN), ("tests/common/mod.rs", TEST_ROUTER)] {
        for handler in ["terminal_ws", "rdp_ws"] {
            let needle = format!("get(handlers::websocket::{handler}).layer(");
            let at = src
                .find(&needle)
                .unwrap_or_else(|| panic!("{name}: route for {handler} must exist"));
            let layer = &src[at + needle.len()..];
            assert!(
                layer.starts_with("session_owner_guard"),
                "{name}: {handler} must be layered with session_owner_guard, got `{}`",
                &layer[..layer.len().min(40)]
            );
        }
        assert!(
            src.contains("handlers::websocket::ws_session_owner_guard"),
            "{name}: session_owner_guard must be built from ws_session_owner_guard"
        );
    }
}

#[test]
fn inv_owner_guard_uses_the_owner_only_audience() {
    let body = code_only(item_body(WEBSOCKET, "pub async fn ws_session_owner_guard("));
    assert!(
        body.contains("WsSessionAudience::OwnerOnly"),
        "ws_session_owner_guard must pass WsSessionAudience::OwnerOnly"
    );
    assert!(
        !body.contains("OwnerOrSupervisor"),
        "ws_session_owner_guard must not reference the supervisor audience"
    );
}

#[test]
fn inv_owner_only_audience_hardcodes_false() {
    let body = code_only(item_body(WEBSOCKET, "pub enum WsSessionAudience {"));
    assert!(
        body.contains("Self::OwnerOnly => false"),
        "WsSessionAudience::OwnerOnly must map to `false` unconditionally"
    );
}

#[test]
fn inv_shared_guard_goes_through_the_session_access_seam() {
    // `guard_session_ws` is private, so it sits inside the slice that
    // starts at the public `ws_session_guard`.
    let body = code_only(item_body(WEBSOCKET, "pub async fn ws_session_guard("));
    assert!(body.contains("async fn guard_session_ws("));
    assert!(
        body.contains("audience.honors_supervise(holds_supervise)"),
        "the supervise flag must be filtered by the audience"
    );
    assert!(
        body.contains("verify_session_ownership(&state, session_id, &user, can_supervise)"),
        "the guard must delegate to the session_access wrapper"
    );
    assert!(
        !body.contains("is_staff") && !body.contains("is_superuser"),
        "the guard must not gate on raw role flags"
    );
}

#[test]
fn inv_session_activation_is_one_shot() {
    let body = code_only(item_body(WEBSOCKET, "pub async fn activate_proxy_session("));
    assert!(
        body.contains(r#".filter(dsl::status.eq("connecting"))"#),
        "activate_proxy_session must only transition a `connecting` row"
    );
}

// ---------------------------------------------------------------------
// 2. API account update: superuser-target fence
// ---------------------------------------------------------------------

#[test]
fn inv_api_update_user_checks_superuser_target_twice() {
    let body = code_only(item_body(API_ACCOUNTS, "pub async fn update_user("));
    assert_eq!(
        body.matches("check_superuser_target_edit(").count(),
        2,
        "update_user must run the fence before AND inside the transaction"
    );
    assert!(
        body.contains("perms.users_manage_admins"),
        "the fence must be fed by the Casbin PermissionContext"
    );
    assert!(
        body.contains("check_superuser_target_edit(&in_tx_before, can_manage_admins)"),
        "the in-transaction re-check must use the in-tx snapshot"
    );
    assert!(
        !body.contains("auth_user.is_superuser") && !body.contains("auth_user.is_staff"),
        "update_user must not gate on raw role flags"
    );
}

#[test]
fn inv_api_update_user_ignores_soft_deleted_rows() {
    let body = code_only(item_body(API_ACCOUNTS, "pub async fn update_user("));
    assert_eq!(
        body.matches(".filter(is_deleted.eq(false))").count(),
        3,
        "pre-tx read, in-tx re-read and UPDATE must all filter is_deleted"
    );
}

#[test]
fn inv_superuser_target_fence_is_pure() {
    let body = code_only(item_body(
        ROLE_INVARIANTS,
        "pub fn check_superuser_target_edit(",
    ));
    assert!(body.contains("before.is_superuser && !can_manage_admins"));
    assert!(
        !body.contains(".await") && !body.contains("conn"),
        "check_superuser_target_edit must stay a pure, DB-free check"
    );
}

// ---------------------------------------------------------------------
// 3. API access request: same row as the web form
// ---------------------------------------------------------------------

#[test]
fn inv_api_create_session_builds_a_bounded_pending_request() {
    let body = code_only(item_body(API_SESSIONS, "pub async fn create_session("));
    for needle in [
        "max_session_duration: access_result.max_session_duration",
        "credential_id: PENDING_CREDENTIAL.to_string()",
        "credential_username: PENDING_CREDENTIAL.to_string()",
        "normalize_justification(request.justification.as_deref())",
        "crate::middleware::extract_client_ip(",
        "announce_access_request(",
    ] {
        assert!(
            body.contains(needle),
            "create_session must contain `{needle}`"
        );
    }
    for forbidden in [
        "request.credential_id",
        "max_session_duration: None",
        "127.0.0.1",
        "client_user_agent: None",
    ] {
        assert!(
            !body.contains(forbidden),
            "create_session must not contain `{forbidden}`"
        );
    }
}

#[test]
fn inv_api_create_session_evaluates_the_rule_before_the_bypass() {
    let body = code_only(item_body(API_SESSIONS, "pub async fn create_session("));
    let eval = body
        .find("can_access_asset(")
        .expect("create_session must call can_access_asset");
    let bypass = body
        .find("if !perms.sessions_bypass_access_rules")
        .expect("create_session must keep the bypass gate");
    assert!(
        eval < bypass,
        "the rule evaluation must run unconditionally (before the bypass \
         gate) so its max_session_duration always bounds the request"
    );
}

#[test]
fn inv_web_submit_shares_the_request_seam() {
    let body = code_only(item_body(
        WEB_SESSIONS,
        "pub async fn submit_access_request(",
    ));
    for needle in [
        "crate::services::access_request::normalize_justification(",
        "crate::services::access_request::PENDING_CREDENTIAL",
        "max_session_duration: access_result.max_session_duration",
        "announce_access_request(",
    ] {
        assert!(
            body.contains(needle),
            "submit_access_request must contain `{needle}`"
        );
    }
}

#[test]
fn inv_web_submit_checks_protocol_coherence_after_authorization() {
    let body = code_only(item_body(
        WEB_SESSIONS,
        "pub async fn submit_access_request(",
    ));
    let authz = body
        .find("can_access_asset(")
        .expect("submit_access_request must call can_access_asset");
    let guard = body
        .find("requested.matches_asset(asset.asset_type)")
        .expect("submit_access_request must check session_type against the asset type");
    let insert = body
        .find("insert_into(proxy_sessions::table)")
        .expect("submit_access_request must insert the pending row");
    assert!(
        authz < guard && guard < insert,
        "protocol guard must sit between authorization and the INSERT"
    );
    assert!(
        body.contains("SessionType::try_parse(&form.session_type)"),
        "an unknown session_type must be refused, not defaulted to ssh"
    );
}

#[test]
fn inv_api_create_session_checks_justification_after_authorization() {
    let body = code_only(item_body(API_SESSIONS, "pub async fn create_session("));
    let authz = body
        .find("if !perms.sessions_bypass_access_rules")
        .expect("bypass gate");
    let justification = body
        .find("normalize_justification(request.justification.as_deref())")
        .expect("justification check");
    let insert = body.find("insert_into(proxy_sessions)").expect("INSERT");
    assert!(
        authz < justification && justification < insert,
        "the justification refusal must not precede the access decision"
    );
}

#[test]
fn inv_announcer_emits_the_audit_event_once() {
    assert_eq!(
        WEB_SESSIONS
            .matches("AuditEventType::ApprovalRequested")
            .count(),
        1,
        "ApprovalRequested must be emitted from the single announcer seam"
    );
    let at = WEB_SESSIONS
        .find("pub(crate) async fn announce_access_request(")
        .expect("announce_access_request must exist");
    let body = &WEB_SESSIONS[at..];
    let end = body
        .find("\nasync fn queue_submitted_emails(")
        .unwrap_or(body.len());
    let body = &body[..end];
    for needle in [
        "AuditEventType::ApprovalRequested",
        "broadcast_approval_badge(state)",
        "queue_submitted_emails(",
    ] {
        assert!(body.contains(needle), "announcer must contain `{needle}`");
    }
}

// ---------------------------------------------------------------------
// Smoke runbook
// ---------------------------------------------------------------------

#[test]
fn inv_smoke_runbook_covers_the_three_fences() {
    for needle in [
        "/ws/terminal/",
        "/ws/rdp/",
        "/api/v1/accounts/",
        "/api/v1/sessions",
        "Pass criteria",
    ] {
        assert!(
            RUNBOOK.contains(needle),
            "authz_gaps_smoke_test.md must mention `{needle}`"
        );
    }
}
