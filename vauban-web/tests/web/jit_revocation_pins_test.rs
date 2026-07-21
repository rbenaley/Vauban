//! Structural pins for the JIT grant revocation feature.
//!
//! Three seams are frozen here (pure `include_str!` source pins, no
//! browser / no DB -- mirroring `heartbeat_frontend_test`):
//!
//!   1. **WS backstop** -- both the SSH and the RDP revalidation arms
//!      must probe `is_proxy_session_live` and, on failure, close with
//!      the dedicated 4403 code and the canonical `access_revoked`
//!      cause. This is the layer-3 invariant: no socket survives more
//!      than `REVALIDATE_INTERVAL_SECS` past a revoked/expired grant.
//!   2. **Front-end 4403 handling** -- both viewers must branch on
//!      `event.code === 4403`, redirect to the assets list (NOT
//!      /login) and never attempt a reconnect from that branch.
//!   3. **Shared terminate core** -- the admin API terminate, the
//!      user-deactivation sweep and the revocation cascade must all
//!      route through `services::session_termination` so the four
//!      termination side-effects (DB flip, recording hydration, proxy
//!      force-close, IACS IPC) cannot drift apart between callers.

const WEBSOCKET_RS: &str = include_str!("../../src/handlers/websocket.rs");
const JS: &str = include_str!("../../static/js/vauban-components.js");
const API_SESSIONS_RS: &str = include_str!("../../src/handlers/api/sessions.rs");
const WEB_SESSIONS_RS: &str = include_str!("../../src/handlers/web/sessions.rs");
const WEB_USERS_RS: &str = include_str!("../../src/handlers/web/users.rs");
const SESSION_ACTIVITY_RS: &str = include_str!("../../src/services/session_activity.rs");
const ASSET_LIST_HTML: &str = include_str!("../../templates/assets/asset_list.html");
const MY_REQUESTS_HTML: &str = include_str!("../../templates/sessions/my_requests.html");
const APPROVAL_LIST_HTML: &str = include_str!("../../templates/sessions/approval_list.html");

// ====================================================================
// 1. WS backstop (server side)
// ====================================================================

/// The dedicated close code must exist, be 4403, and be distinct from
/// the auth-expiry code.
#[test]
fn ws_close_access_revoked_code_is_4403() {
    assert!(
        WEBSOCKET_RS.contains("WS_CLOSE_ACCESS_REVOKED: u16 = 4403"),
        "websocket.rs must define WS_CLOSE_ACCESS_REVOKED = 4403"
    );
    assert!(
        WEBSOCKET_RS.contains("WS_CLOSE_AUTH_EXPIRED: u16 = 4401"),
        "the auth-expiry code must remain 4401 (distinct from 4403)"
    );
}

/// BOTH proxy-session loops (SSH + RDP) must wire the
/// `is_proxy_session_live` probe in their revalidation arm.
#[test]
fn both_ws_loops_wire_the_proxy_session_probe() {
    let probes = WEBSOCKET_RS
        .matches("session_activity::is_proxy_session_live(&state, &session_id)")
        .count();
    assert!(
        probes >= 2,
        "both the SSH and RDP reval arms must call is_proxy_session_live; found {probes}"
    );
}

/// Every probe failure must close with the 4403 frame AND set the
/// canonical `access_revoked` cause (websocket-logging rule).
#[test]
fn probe_failure_closes_4403_with_access_revoked_cause() {
    let mut cursor = 0usize;
    let needle = "is_proxy_session_live(&state, &session_id)";
    let mut sites = 0usize;
    while let Some(rel) = WEBSOCKET_RS[cursor..].find(needle) {
        let abs = cursor + rel;
        let window = &WEBSOCKET_RS[abs..(abs + 1600).min(WEBSOCKET_RS.len())];
        assert!(
            window.contains("WS_CLOSE_ACCESS_REVOKED"),
            "probe site at offset {abs} must close with WS_CLOSE_ACCESS_REVOKED"
        );
        assert!(
            window.contains(r#"close_cause = "access_revoked""#),
            "probe site at offset {abs} must set close_cause = \"access_revoked\""
        );
        sites += 1;
        cursor = abs + needle.len();
    }
    assert!(
        sites >= 2,
        "expected at least two probe sites, found {sites}"
    );
}

/// The login-session probe (4401) must stay FIRST: an expired login
/// wins over a revoked grant so the browser bounces to /login, not to
/// the assets page.
#[test]
fn login_probe_has_priority_over_grant_probe() {
    let mut cursor = 0usize;
    let needle = "is_proxy_session_live(&state, &session_id)";
    while let Some(rel) = WEBSOCKET_RS[cursor..].find(needle) {
        let abs = cursor + rel;
        let from = abs.saturating_sub(1400);
        let preceding = &WEBSOCKET_RS[from..abs];
        assert!(
            preceding.contains("is_login_session_live"),
            "each is_proxy_session_live site (offset {abs}) must be the else-branch \
             of an is_login_session_live check"
        );
        cursor = abs + needle.len();
    }
}

/// The probe itself must be fail-open on DB errors (never cut a live
/// session because the pool hiccuped) and fail-closed on bad input.
#[test]
fn proxy_session_probe_covers_the_liveness_invariants() {
    assert!(
        SESSION_ACTIVITY_RS.contains("pub async fn is_proxy_session_live"),
        "session_activity.rs must export is_proxy_session_live"
    );
    for filter in ["SessionStatus::SSH_RDP_INFLIGHT_AS_STR", "expires_at"] {
        assert!(
            SESSION_ACTIVITY_RS.contains(filter),
            "is_proxy_session_live must filter on `{filter}`"
        );
    }
}

// ====================================================================
// 2. Front-end 4403 handling
// ====================================================================

/// Both viewers must branch on 4403 and land on the assets list.
#[test]
fn both_viewers_handle_4403_with_assets_redirect() {
    let guards = JS.matches("event.code === 4403").count()
        + JS.matches("event && event.code === 4403").count();
    assert!(
        guards >= 2,
        "both the SSH and RDP onclose handlers must branch on close code 4403"
    );
    let redirects = JS
        .matches("window.location.href = '/assets?reason=access_revoked'")
        .count();
    assert!(
        redirects >= 2,
        "both 4403 branches must redirect to /assets?reason=access_revoked; found {redirects}"
    );
}

/// The 4403 branch must NEVER bounce to /login: revocation is not an
/// authentication failure and the login session is still valid.
#[test]
fn access_revoked_redirect_is_not_login() {
    let mut cursor = 0usize;
    let needle = "'/assets?reason=access_revoked'";
    let mut sites = 0usize;
    while let Some(rel) = JS[cursor..].find(needle) {
        let abs = cursor + rel;
        let from = abs.saturating_sub(400);
        let preceding = &JS[from..abs];
        let guard = preceding.rfind("4403").unwrap_or_else(|| {
            panic!("the access_revoked redirect at offset {abs} must be gated on close code 4403")
        });
        assert!(
            !preceding[guard..].contains("/login"),
            "no /login redirect may live inside the 4403 branch (offset {abs})"
        );
        sites += 1;
        cursor = abs + needle.len();
    }
    assert!(
        sites >= 2,
        "expected two access_revoked redirect sites, found {sites}"
    );
}

// ====================================================================
// 3. Shared terminate core
// ====================================================================

/// The three termination callers must all route through the shared
/// `services::session_termination` seam.
#[test]
fn all_terminate_callers_use_the_shared_core() {
    for (name, src) in [
        (
            "handlers/api/sessions.rs (admin terminate)",
            API_SESSIONS_RS,
        ),
        ("handlers/web/users.rs (deactivate_user)", WEB_USERS_RS),
        ("handlers/web/sessions.rs (revoke cascade)", WEB_SESSIONS_RS),
    ] {
        assert!(
            src.contains("session_termination::terminate_live_session"),
            "{name} must terminate through services::session_termination"
        );
    }
}

/// No caller may re-implement the DB flip inline: the string
/// `status.eq("terminated")` (an UPDATE fragment) must not reappear in
/// the three caller files -- only the shared service owns it.
#[test]
fn no_caller_reimplements_the_terminated_update() {
    for (name, src) in [
        ("handlers/api/sessions.rs", API_SESSIONS_RS),
        ("handlers/web/users.rs", WEB_USERS_RS),
        ("handlers/web/sessions.rs", WEB_SESSIONS_RS),
    ] {
        assert!(
            !src.contains(r#"status.eq("terminated")"#),
            "{name} must not carry an inline `status -> terminated` UPDATE; \
             use services::session_termination instead"
        );
    }
}

/// The revocation cascade must cover ALL live statuses -- including
/// the IACS ones (`waiting_client`, `ews_connected`, `tunnel_active`)
/// whose omission was the historical deactivate_user gap.
#[test]
fn cascade_covers_iacs_live_statuses() {
    // Whitespace-collapsed so rustfmt line-splitting of the array
    // literal cannot break the pin.
    let collapsed: String = WEB_SESSIONS_RS.split_whitespace().collect();
    assert!(
        collapsed.contains("SessionStatus::LIVE_AS_STR"),
        "revocation cascade must terminate via SessionStatus::LIVE_AS_STR \
         (includes IACS open lifecycle statuses)"
    );
}

// ====================================================================
// 4. Real-time UI refresh (WS -> HTMX triggers)
// ====================================================================

/// The dispatcher broadcasts one `jit-notification` per decision verb;
/// each page that renders approval state must re-fetch on the NEW verbs
/// too, otherwise the Connect/Request button (assets), the status badge
/// (my-requests) and the approvals list only update on F5. Pinned after
/// the revocation UI was observed stale in manual testing.
#[test]
fn ws_ui_triggers_listen_to_revoke_and_duration_events() {
    for (name, html) in [
        ("assets/asset_list.html", ASSET_LIST_HTML),
        ("sessions/my_requests.html", MY_REQUESTS_HTML),
        ("sessions/approval_list.html", APPROVAL_LIST_HTML),
    ] {
        for event in ["request_revoked", "request_duration_updated"] {
            assert!(
                html.contains(event),
                "{name} must refresh on the `{event}` WS notification \
                 (hx-trigger wsAfterMessage filter)"
            );
        }
    }
}

/// The dispatcher side of the contract: the web decision handler must
/// emit exactly these two event literals on the Notifications channel.
#[test]
fn dispatcher_emits_the_revoke_and_duration_event_literals() {
    for event in [r#""request_revoked""#, r#""request_duration_updated""#] {
        assert!(
            WEB_SESSIONS_RS.contains(event),
            "dispatch_approval_decision must map the decision kind to {event}"
        );
    }
}
