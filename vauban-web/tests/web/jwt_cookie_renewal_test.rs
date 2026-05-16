//! Battle tests for JWT access-token renewal on cookie-based web sessions.
//!
//! When the JWT `exp` is within [`AuthService::access_token_renew_if_expires_within_seconds`],
//! `auth_middleware` must re-issue the cookie (same `jti` / `auth_sessions.uuid`) and update
//! `token_hash` in the database. Bearer authentication must not trigger this path.

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

/// Build claims identical to `base` but with a custom `exp` and optional `jti`.
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

#[tokio::test]
#[serial]
async fn cookie_near_exp_triggers_access_token_set_cookie_and_fresh_exp() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("jwt_renew_cookie");
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

    // Fewer seconds remaining than the renewal threshold -> must rotate on next request.
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
        .get("/assets")
        .add_header(COOKIE, format!("access_token={}", near_token))
        .await;

    assert_status(&response, 200);
    let set_cookies = access_token_set_cookie_values(&response);
    assert_eq!(
        set_cookies.len(),
        1,
        "expected exactly one access_token Set-Cookie, got {:?}",
        set_cookies
    );

    let raw = &set_cookies[0];
    let cookie_val = raw.split(';').next().expect("access_token cookie line");
    let token_part = cookie_val
        .strip_prefix("access_token=")
        .expect("access_token cookie prefix");

    let renewed = app
        .auth_service
        .verify_token(token_part)
        .expect("renewed JWT must verify");
    let sid = session_uuid.to_string();
    assert_eq!(renewed.jti.as_deref(), Some(sid.as_str()));
    let now = Utc::now().timestamp();
    let remaining = renewed.exp - now;
    assert!(
        remaining > renew_within,
        "renewed token should have a full new lifetime window (remaining {}s, renew_within {}s)",
        remaining,
        renew_within
    );

    test_db::cleanup(&mut conn).await;
}

#[tokio::test]
#[serial]
async fn cookie_long_ttl_does_not_emit_access_token_set_cookie() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("jwt_no_renew");
    let test_user = create_test_user(&mut conn, &app.auth_service, &username).await;
    let base_claims = app
        .auth_service
        .verify_token(&test_user.token)
        .expect("valid fixture token");
    let session_uuid = Uuid::parse_str(base_claims.jti.as_ref().expect("fixture jti")).unwrap();

    let renew_within = app
        .auth_service
        .access_token_renew_if_expires_within_seconds();
    // Well outside the renewal window.
    let exp = Utc::now() + Duration::seconds(renew_within + 600);
    let long_token = encode_jwt(
        app,
        &claims_with_exp(&base_claims, exp, base_claims.jti.clone()),
    );

    diesel::update(auth_sessions::table.filter(auth_sessions::uuid.eq(session_uuid)))
        .set(auth_sessions::token_hash.eq(hash_token(&long_token)))
        .execute(&mut conn)
        .await
        .expect("update session token_hash");

    let response = app
        .server
        .get("/assets")
        .add_header(COOKIE, format!("access_token={}", long_token))
        .await;

    assert_status(&response, 200);
    let set_cookies = access_token_set_cookie_values(&response);
    assert!(
        set_cookies.is_empty(),
        "must not renew access_token cookie when exp is far; got {:?}",
        set_cookies
    );

    test_db::cleanup(&mut conn).await;
}

#[tokio::test]
#[serial]
async fn bearer_near_exp_does_not_emit_access_token_set_cookie() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("jwt_renew_bearer");
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
        .get("/assets")
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

#[tokio::test]
#[serial]
async fn legacy_jwt_without_jti_cookie_near_exp_still_renews() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("jwt_legacy_jti");
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
    let near_no_jti = encode_jwt(app, &claims_with_exp(&base_claims, exp, None));

    diesel::update(auth_sessions::table.filter(auth_sessions::uuid.eq(session_uuid)))
        .set(auth_sessions::token_hash.eq(hash_token(&near_no_jti)))
        .execute(&mut conn)
        .await
        .expect("update session token_hash");

    let response = app
        .server
        .get("/assets")
        .add_header(COOKIE, format!("access_token={}", near_no_jti))
        .await;

    assert_status(&response, 200);
    let set_cookies = access_token_set_cookie_values(&response);
    assert_eq!(
        set_cookies.len(),
        1,
        "legacy token (no jti) must still renew via cookie; got {:?}",
        set_cookies
    );

    let raw = &set_cookies[0];
    let token_part = raw
        .split(';')
        .next()
        .expect("cookie")
        .strip_prefix("access_token=")
        .expect("prefix");

    let renewed = app
        .auth_service
        .verify_token(token_part)
        .expect("renewed jwt");
    let sid = session_uuid.to_string();
    assert_eq!(renewed.jti.as_deref(), Some(sid.as_str()));

    test_db::cleanup(&mut conn).await;
}
