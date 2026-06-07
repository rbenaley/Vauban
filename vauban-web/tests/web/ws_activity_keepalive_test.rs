//! Part B (server-side defense-in-depth) tests for SSH/RDP keepalive.
//!
//! The front-end `/htmx/empty` heartbeat is covered E2E by
//! [`crate::web::heartbeat_session_keepalive_test`]. This module covers
//! the WebSocket-side `last_activity` refresh that keeps the idle reaper
//! from deleting a session whose user is actively typing/mousing, using
//! the layers that are achievable without a live-socket harness:
//!
//! 1. a DB integration test that the public bump helper advances
//!    `last_activity`;
//! 2. a structural pin that both WS handlers wire the throttled bump on
//!    their real-input arms (and keep the canonical lifecycle logs);
//! 3. a structural pin that `auth_middleware` exposes the session uuid
//!    via the `AuthSessionId` extension at every authentication site.

use chrono::{Duration, Utc};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use serial_test::serial;
use uuid::Uuid;

use crate::common::{TestApp, test_db};
use crate::fixtures::{create_test_user, unique_name};
use vauban_web::schema::auth_sessions;

const WEBSOCKET_SRC: &str = include_str!("../../src/handlers/websocket.rs");
const AUTH_MW_SRC: &str = include_str!("../../src/middleware/auth.rs");

/// The public bump helper used by the WS handlers must advance
/// `auth_sessions.last_activity` to "now".
#[tokio::test]
#[serial]
async fn touch_login_session_advances_last_activity() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("ws_keepalive");
    let test_user = create_test_user(&mut conn, &app.auth_service, &username).await;
    let claims = app
        .auth_service
        .verify_token(&test_user.token)
        .expect("valid fixture token");
    let session_uuid = Uuid::parse_str(claims.jti.as_ref().expect("fixture jti")).unwrap();

    let stale = Utc::now() - Duration::minutes(10);
    diesel::update(auth_sessions::table.filter(auth_sessions::uuid.eq(session_uuid)))
        .set(auth_sessions::last_activity.eq(stale))
        .execute(&mut conn)
        .await
        .expect("seed stale last_activity");

    vauban_web::services::session_activity::touch_login_session(&app.app_state, session_uuid).await;

    let updated: chrono::DateTime<Utc> = auth_sessions::table
        .filter(auth_sessions::uuid.eq(session_uuid))
        .select(auth_sessions::last_activity)
        .first(&mut conn)
        .await
        .expect("read last_activity");

    assert!(
        updated > stale,
        "touch_login_session must advance last_activity (was {stale}, now {updated})"
    );

    test_db::cleanup(&mut conn).await;
}

/// Both SSH and RDP handlers must wire the throttled keepalive bump.
#[test]
fn ws_handlers_wire_throttled_keepalive_bump() {
    assert!(
        WEBSOCKET_SRC.contains("ActivityThrottle::new(Duration::from_secs(60))"),
        "WS handlers must allocate a 60s ActivityThrottle for the keepalive bump"
    );
    let bumps = WEBSOCKET_SRC
        .matches("session_activity::touch_login_session(&state, auth_session.0)")
        .count();
    assert!(
        bumps >= 3,
        "expected the keepalive bump on the SSH text + binary arms and the RDP \
         input arm (>=3 call sites); found {bumps}"
    );
    // The bump must be gated by the throttle, never unconditional.
    assert!(
        WEBSOCKET_SRC.contains("activity_throttle.should_fire(Instant::now())"),
        "the keepalive bump must be gated behind activity_throttle.should_fire(...)"
    );
}

/// The keepalive additions must not have disturbed the canonical
/// WebSocket lifecycle log literals (also pinned by
/// `websocket_logging_test`, re-asserted here as a local guard).
#[test]
fn ws_lifecycle_logs_are_preserved() {
    for literal in [
        "WebSocket connection requested",
        "WebSocket connected",
        "WebSocket closed",
        "WebSocket disconnected",
    ] {
        assert!(
            WEBSOCKET_SRC.contains(literal),
            "lifecycle log literal `{literal}` must remain present in websocket.rs"
        );
    }
}

/// `auth_middleware` (and the require_* helpers) must expose the validated
/// session uuid via the `AuthSessionId` extension, which is what the WS
/// handlers consume. Pin every insertion site so a refactor cannot drop
/// the extension and silently disable the server-side keepalive.
#[test]
fn auth_middleware_inserts_auth_session_id_extension() {
    assert!(
        AUTH_MW_SRC.contains("pub struct AuthSessionId(pub Uuid)"),
        "AuthSessionId newtype must exist"
    );
    let inserts = AUTH_MW_SRC
        .matches("insert(AuthSessionId(session_uuid))")
        .count();
    assert!(
        inserts >= 3,
        "AuthSessionId(session_uuid) must be inserted at all 3 authentication \
         sites (auth_middleware, require_auth, require_mfa); found {inserts}"
    );
}
