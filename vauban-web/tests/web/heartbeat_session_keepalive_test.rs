//! E2E tests for the SSH/RDP auth keepalive heartbeat.
//!
//! During a live SSH/RDP session every user interaction flows over the
//! WebSocket, so the browser issues no HTTP request and the 15-minute
//! access-token cookie is never renewed (and `auth_sessions.last_activity`
//! goes stale, letting the idle reaper delete the session). The front-end
//! mitigates this by pinging the existing no-op web route `/htmx/empty`
//! whenever the user is active.
//!
//! These tests pin the SERVER-SIDE contract the heartbeat relies on: a
//! plain authenticated GET on `/htmx/empty` must (a) rotate the cookie
//! JWT when it is close to expiry, and (b) bump `last_activity`. The
//! cookie rotation must NOT happen for Bearer-priority auth.
//!
//! Model: [`crate::web::jwt_cookie_renewal_test`] + the `last_activity`
//! update assertion in [`crate::middleware`].

use axum::http::header::{AUTHORIZATION, COOKIE, SET_COOKIE};
use chrono::{Duration, Utc};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use jsonwebtoken::{EncodingKey, Header, encode};
use secrecy::ExposeSecret;
use serial_test::serial;
use sha3::{Digest, Sha3_256};
use uuid::Uuid;

use crate::common::{TestApp, assertions::assert_status, test_db};
use crate::fixtures::{create_test_user, unique_name};
use vauban_web::schema::auth_sessions;
use vauban_web::services::auth::Claims;

/// The web-zone route reused as the heartbeat target. It must NOT live
/// under `/api/v1` (the API is independently disableable) and must
/// traverse `auth_middleware`.
const HEARTBEAT_ROUTE: &str = "/htmx/empty";

fn hash_token(token: &str) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(token.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn encode_jwt(app: &TestApp, claims: &Claims) -> String {
    let key = EncodingKey::from_secret(app.config.secret_key.expose_secret().as_bytes());
    encode(&Header::default(), claims, &key).expect("JWT encode for test")
}

fn access_token_set_cookie_values(response: &axum_test::TestResponse) -> Vec<String> {
    response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|h| h.to_str().ok())
        .filter(|line| {
            line.split(';')
                .next()
                .is_some_and(|first| first.trim_start().starts_with("access_token="))
        })
        .map(|s| s.to_string())
        .collect()
}

fn claims_with_exp(base: &Claims, exp: chrono::DateTime<Utc>, jti: Option<String>) -> Claims {
    Claims {
        sub: base.sub.clone(),
        username: base.username.clone(),
        exp: exp.timestamp(),
        iat: base.iat,
        mfa_verified: base.mfa_verified,
        is_superuser: base.is_superuser,
        is_staff: base.is_staff,
        jti,
    }
}

/// A near-expiry cookie hit on the heartbeat route must rotate the
/// access-token cookie (same `jti`, fresh `exp`). This is what keeps an
/// actively-typing SSH/RDP user logged in past the 15-minute window.
#[tokio::test]
#[serial]
async fn heartbeat_near_exp_cookie_rotates_access_token() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("hb_renew_cookie");
    let test_user = create_test_user(&mut conn, &app.auth_service, &username).await;
    let base_claims = app
        .auth_service
        .verify_token(&test_user.token)
        .expect("valid fixture token");
    let session_uuid = Uuid::parse_str(base_claims.jti.as_ref().expect("fixture token has jti"))
        .expect("jti is uuid");

    let renew_within = app
        .auth_service
        .access_token_renew_if_expires_within_seconds();
    assert!(
        renew_within >= 60,
        "test assumes renew window at least 60s (config drift)"
    );

    let exp = Utc::now() + Duration::seconds((renew_within - 30).max(10).min(renew_within));
    let near_token = encode_jwt(
        app,
        &claims_with_exp(&base_claims, exp, base_claims.jti.clone()),
    );

    diesel::update(auth_sessions::table.filter(auth_sessions::uuid.eq(session_uuid)))
        .set(auth_sessions::token_hash.eq(hash_token(&near_token)))
        .execute(&mut conn)
        .await
        .expect("update session token_hash");

    let response = app
        .server
        .get(HEARTBEAT_ROUTE)
        .add_header(COOKIE, format!("access_token={}", near_token))
        .await;

    assert_status(&response, 200);
    let set_cookies = access_token_set_cookie_values(&response);
    assert_eq!(
        set_cookies.len(),
        1,
        "heartbeat with near-exp cookie must rotate access_token, got {:?}",
        set_cookies
    );

    let raw = &set_cookies[0];
    let token_part = raw
        .split(';')
        .next()
        .expect("access_token cookie line")
        .strip_prefix("access_token=")
        .expect("access_token cookie prefix");

    let renewed = app
        .auth_service
        .verify_token(token_part)
        .expect("renewed JWT must verify");
    let sid = session_uuid.to_string();
    assert_eq!(renewed.jti.as_deref(), Some(sid.as_str()));
    let remaining = renewed.exp - Utc::now().timestamp();
    assert!(
        remaining > renew_within,
        "renewed token should have a full new lifetime window (remaining {}s, renew_within {}s)",
        remaining,
        renew_within
    );

    test_db::cleanup(&mut conn).await;
}

/// A heartbeat hit must bump `auth_sessions.last_activity`, which is what
/// keeps the idle-session reaper from deleting an active session.
#[tokio::test]
#[serial]
async fn heartbeat_bumps_last_activity() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("hb_last_activity");
    let test_user = create_test_user(&mut conn, &app.auth_service, &username).await;
    let base_claims = app
        .auth_service
        .verify_token(&test_user.token)
        .expect("valid fixture token");
    let session_uuid = Uuid::parse_str(base_claims.jti.as_ref().expect("fixture jti")).unwrap();

    // Push last_activity into the past (but well within the idle window,
    // 30 min by default) so the session stays valid and we can observe a
    // forward jump.
    let stale = Utc::now() - Duration::minutes(5);
    diesel::update(auth_sessions::table.filter(auth_sessions::uuid.eq(session_uuid)))
        .set(auth_sessions::last_activity.eq(stale))
        .execute(&mut conn)
        .await
        .expect("seed stale last_activity");

    let response = app
        .server
        .get(HEARTBEAT_ROUTE)
        .add_header(COOKIE, format!("access_token={}", test_user.token))
        .await;

    assert_status(&response, 200);

    let updated: chrono::DateTime<Utc> = auth_sessions::table
        .filter(auth_sessions::uuid.eq(session_uuid))
        .select(auth_sessions::last_activity)
        .first(&mut conn)
        .await
        .expect("read last_activity");

    assert!(
        updated > stale,
        "heartbeat must advance last_activity (was {stale}, now {updated})"
    );

    test_db::cleanup(&mut conn).await;
}

/// Bearer-priority auth must NOT rotate the cookie: API clients manage
/// their own tokens and never carry a renewable browser cookie.
#[tokio::test]
#[serial]
async fn heartbeat_bearer_does_not_rotate_cookie() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("hb_bearer");
    let test_user = create_test_user(&mut conn, &app.auth_service, &username).await;
    let base_claims = app
        .auth_service
        .verify_token(&test_user.token)
        .expect("valid fixture token");
    let session_uuid = Uuid::parse_str(base_claims.jti.as_ref().expect("fixture jti")).unwrap();

    let renew_within = app
        .auth_service
        .access_token_renew_if_expires_within_seconds();
    let exp = Utc::now() + Duration::seconds((renew_within - 30).max(10).min(renew_within));
    let near_token = encode_jwt(
        app,
        &claims_with_exp(&base_claims, exp, base_claims.jti.clone()),
    );

    diesel::update(auth_sessions::table.filter(auth_sessions::uuid.eq(session_uuid)))
        .set(auth_sessions::token_hash.eq(hash_token(&near_token)))
        .execute(&mut conn)
        .await
        .expect("update session token_hash");

    let response = app
        .server
        .get(HEARTBEAT_ROUTE)
        .add_header(AUTHORIZATION, format!("Bearer {}", near_token))
        .add_header(COOKIE, format!("access_token={}", near_token))
        .await;

    assert_status(&response, 200);
    let set_cookies = access_token_set_cookie_values(&response);
    assert!(
        set_cookies.is_empty(),
        "Bearer-priority auth must not rotate the cookie; got {:?}",
        set_cookies
    );

    test_db::cleanup(&mut conn).await;
}
