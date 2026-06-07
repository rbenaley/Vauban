//! Tests for the SSH/RDP login-session re-validation that tears down a
//! live WebSocket once the auth token expires (idle timeout /
//! max-duration / reaped row).
//!
//! Layered, no live-socket harness (axum-test cannot drive a real WS, and
//! ssh_proxy/rdp_proxy are None in tests):
//! 1. DB integration of `is_login_session_live` under each expiry mode;
//! 2. structural pins that both WS loops wire the re-validation arm
//!    (close code 4401 + cause auth_expired) and keep the 4 lifecycle
//!    logs intact.

use chrono::{Duration, Utc};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use serial_test::serial;
use uuid::Uuid;

use crate::common::{TestApp, test_db};
use crate::fixtures::{create_test_user, unique_name};
use vauban_web::schema::auth_sessions;
use vauban_web::services::auth::AuthService;
use vauban_web::services::session_activity::is_login_session_live;

const WEBSOCKET_SRC: &str = include_str!("../../src/handlers/websocket.rs");

async fn fresh_session(
    auth_service: &AuthService,
    conn: &mut diesel_async::AsyncPgConnection,
    label: &str,
) -> Uuid {
    let username = unique_name(label);
    let test_user = create_test_user(conn, auth_service, &username).await;
    let claims = auth_service
        .verify_token(&test_user.token)
        .expect("valid fixture token");
    Uuid::parse_str(claims.jti.as_ref().expect("fixture jti")).unwrap()
}

/// A freshly-created session is live.
#[tokio::test]
#[serial]
async fn is_live_true_for_fresh_session() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let session_uuid = fresh_session(&app.auth_service, &mut conn, "reval_fresh").await;

    assert!(
        is_login_session_live(&app.app_state, session_uuid).await,
        "a fresh session must be considered live"
    );

    test_db::cleanup(&mut conn).await;
}

/// A session idle past `session_idle_timeout_secs` (30 min default) is dead.
#[tokio::test]
#[serial]
async fn is_live_false_when_idle_past_timeout() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let session_uuid = fresh_session(&app.auth_service, &mut conn, "reval_idle").await;

    // 2h ago >> 30 min default idle timeout; created_at stays recent so
    // only the idle predicate trips.
    diesel::update(auth_sessions::table.filter(auth_sessions::uuid.eq(session_uuid)))
        .set(auth_sessions::last_activity.eq(Utc::now() - Duration::hours(2)))
        .execute(&mut conn)
        .await
        .expect("seed idle last_activity");

    assert!(
        !is_login_session_live(&app.app_state, session_uuid).await,
        "an idle session must be considered dead"
    );

    test_db::cleanup(&mut conn).await;
}

/// A session older than `session_max_duration_secs` (8h default) is dead,
/// even with recent activity.
#[tokio::test]
#[serial]
async fn is_live_false_when_past_max_duration() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let session_uuid = fresh_session(&app.auth_service, &mut conn, "reval_maxdur").await;

    // created 9h ago (> 8h max-duration), but active right now so only the
    // max-duration predicate trips.
    diesel::update(auth_sessions::table.filter(auth_sessions::uuid.eq(session_uuid)))
        .set((
            auth_sessions::created_at.eq(Utc::now() - Duration::hours(9)),
            auth_sessions::last_activity.eq(Utc::now()),
        ))
        .execute(&mut conn)
        .await
        .expect("seed old created_at");

    assert!(
        !is_login_session_live(&app.app_state, session_uuid).await,
        "a session past max-duration must be considered dead"
    );

    test_db::cleanup(&mut conn).await;
}

/// A reaped (deleted) session row is dead.
#[tokio::test]
#[serial]
async fn is_live_false_when_row_reaped() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let session_uuid = fresh_session(&app.auth_service, &mut conn, "reval_reaped").await;

    diesel::delete(auth_sessions::table.filter(auth_sessions::uuid.eq(session_uuid)))
        .execute(&mut conn)
        .await
        .expect("delete session row");

    assert!(
        !is_login_session_live(&app.app_state, session_uuid).await,
        "a reaped session must be considered dead"
    );

    test_db::cleanup(&mut conn).await;
}

/// Both WS loops must wire the periodic re-validation arm: query liveness,
/// and on expiry close with code 4401 + cause auth_expired.
#[test]
fn ws_loops_wire_revalidation_arm() {
    assert!(
        WEBSOCKET_SRC.contains("const REVALIDATE_INTERVAL_SECS"),
        "websocket.rs must define REVALIDATE_INTERVAL_SECS"
    );
    let checks = WEBSOCKET_SRC
        .matches("is_login_session_live(&state, auth_session.0)")
        .count();
    assert!(
        checks >= 2,
        "both the SSH and RDP loops must re-validate via is_login_session_live; found {checks}"
    );
    let expiries = WEBSOCKET_SRC.matches("close_cause = \"auth_expired\"").count();
    assert!(
        expiries >= 2,
        "both loops must set close_cause = auth_expired on expiry; found {expiries}"
    );
    assert!(
        WEBSOCKET_SRC.contains("code: WS_CLOSE_AUTH_EXPIRED")
            && WEBSOCKET_SRC.contains("const WS_CLOSE_AUTH_EXPIRED: u16 = 4401"),
        "the expiry close must use the dedicated 4401 close code"
    );
}

/// The re-validation additions must not disturb the canonical lifecycle
/// log literals.
#[test]
fn ws_lifecycle_logs_preserved_after_revalidation() {
    for literal in [
        "WebSocket connection requested",
        "WebSocket connected",
        "WebSocket closed",
        "WebSocket disconnected",
    ] {
        assert!(
            WEBSOCKET_SRC.contains(literal),
            "lifecycle log literal `{literal}` must remain present"
        );
    }
}
