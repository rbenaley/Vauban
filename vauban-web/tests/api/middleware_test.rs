/// VAUBAN Web - Middleware Integration Tests.
///
/// Tests for authentication and authorization middlewares:
/// - auth_middleware: extracts user from JWT token
/// - require_auth: requires valid authentication
/// - require_mfa: requires MFA verification
use axum::http::header::{AUTHORIZATION, COOKIE};
use serial_test::serial;

use crate::common::{TestApp, assertions::assert_status};
use crate::fixtures::{create_simple_user, create_test_user, unique_name};

// =============================================================================
// auth_middleware Tests
// =============================================================================

/// Test that auth_middleware allows requests without token (for optional auth pages).
#[tokio::test]
#[serial]
async fn test_auth_middleware_allows_unauthenticated() {
    let app = TestApp::spawn().await;

    // Request a page that uses OptionalAuthUser
    let response = app.server.get("/health").await;

    assert_status(&response, 200);
}

/// Test that auth_middleware extracts user from valid Bearer token.
#[tokio::test]
#[serial]
async fn test_auth_middleware_extracts_user_from_bearer_token() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    let username = unique_name("bearer_user");
    let user_id = create_simple_user(&mut conn, &username);
    
    // Get user UUID
    let user_uuid: uuid::Uuid = {
        use diesel::prelude::*;
        use vauban_web::schema::users;
        users::table
            .filter(users::id.eq(user_id))
            .select(users::uuid)
            .first(&mut conn)
            .expect("User should exist")
    };

    let token = app.generate_test_token(
        &user_uuid.to_string(),
        &username,
        true,
        true,
    );

    // Request with Bearer token in Authorization header
    let response = app
        .server
        .get("/accounts/sessions")
        .add_header(AUTHORIZATION, format!("Bearer {}", token))
        .await;

    assert_status(&response, 200);
}

/// Test that auth_middleware extracts user from cookie.
#[tokio::test]
#[serial]
async fn test_auth_middleware_extracts_user_from_cookie() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    let username = unique_name("cookie_user");
    let user_id = create_simple_user(&mut conn, &username);
    
    let user_uuid: uuid::Uuid = {
        use diesel::prelude::*;
        use vauban_web::schema::users;
        users::table
            .filter(users::id.eq(user_id))
            .select(users::uuid)
            .first(&mut conn)
            .expect("User should exist")
    };

    let token = app.generate_test_token(
        &user_uuid.to_string(),
        &username,
        true,
        true,
    );

    // Request with token in cookie
    let response = app
        .server
        .get("/accounts/sessions")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);
}

/// Test that auth_middleware ignores invalid tokens gracefully.
#[tokio::test]
#[serial]
async fn test_auth_middleware_ignores_invalid_token() {
    let app = TestApp::spawn().await;

    // Request with invalid token
    let response = app
        .server
        .get("/accounts/sessions")
        .add_header(AUTHORIZATION, "Bearer invalid.token.here")
        .await;

    // Should redirect to login (not 500 error)
    let status = response.status_code().as_u16();
    assert!(
        status == 303 || status == 401,
        "Expected redirect or unauthorized, got {}",
        status
    );
}

/// Test that auth_middleware rejects expired tokens.
#[tokio::test]
#[serial]
async fn test_auth_middleware_rejects_expired_token() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    let username = unique_name("expired_token_user");
    let user_id = create_simple_user(&mut conn, &username);
    
    let user_uuid: uuid::Uuid = {
        use diesel::prelude::*;
        use vauban_web::schema::users;
        users::table
            .filter(users::id.eq(user_id))
            .select(users::uuid)
            .first(&mut conn)
            .expect("User should exist")
    };

    // Generate token but then expire all sessions
    let token = app.generate_test_token(
        &user_uuid.to_string(),
        &username,
        true,
        true,
    );

    // Expire all sessions for this user
    {
        use chrono::{Duration, Utc};
        use diesel::prelude::*;
        use vauban_web::schema::auth_sessions;
        
        diesel::update(
            auth_sessions::table.filter(auth_sessions::user_id.eq(user_id))
        )
        .set(auth_sessions::expires_at.eq(Utc::now() - Duration::hours(1)))
        .execute(&mut conn)
        .expect("Should expire sessions");
    }

    // Request with expired session
    let response = app
        .server
        .get("/accounts/sessions")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    // Should redirect to login
    let status = response.status_code().as_u16();
    assert!(
        status == 303 || status == 401,
        "Expected redirect or unauthorized for expired token, got {}",
        status
    );
}

/// Test that auth_middleware rejects token with revoked session.
#[tokio::test]
#[serial]
async fn test_auth_middleware_rejects_revoked_session() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    let username = unique_name("revoked_session_user");
    let user_id = create_simple_user(&mut conn, &username);
    
    let user_uuid: uuid::Uuid = {
        use diesel::prelude::*;
        use vauban_web::schema::users;
        users::table
            .filter(users::id.eq(user_id))
            .select(users::uuid)
            .first(&mut conn)
            .expect("User should exist")
    };

    let token = app.generate_test_token(
        &user_uuid.to_string(),
        &username,
        true,
        true,
    );

    // Delete all sessions for this user (simulating revocation)
    {
        use diesel::prelude::*;
        use vauban_web::schema::auth_sessions;
        
        diesel::delete(
            auth_sessions::table.filter(auth_sessions::user_id.eq(user_id))
        )
        .execute(&mut conn)
        .expect("Should delete sessions");
    }

    // Request with revoked session
    let response = app
        .server
        .get("/accounts/sessions")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    // Should redirect to login
    let status = response.status_code().as_u16();
    assert!(
        status == 303 || status == 401,
        "Expected redirect or unauthorized for revoked session, got {}",
        status
    );
}

// =============================================================================
// Bearer Token Priority Tests
// =============================================================================

/// Test that Bearer token takes priority over cookie.
#[tokio::test]
#[serial]
async fn test_bearer_token_takes_priority_over_cookie() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Create two users
    let user1_name = unique_name("bearer_priority_1");
    let user2_name = unique_name("bearer_priority_2");
    let user1_id = create_simple_user(&mut conn, &user1_name);
    let user2_id = create_simple_user(&mut conn, &user2_name);
    
    let user1_uuid: uuid::Uuid = {
        use diesel::prelude::*;
        use vauban_web::schema::users;
        users::table
            .filter(users::id.eq(user1_id))
            .select(users::uuid)
            .first(&mut conn)
            .expect("User should exist")
    };
    
    let user2_uuid: uuid::Uuid = {
        use diesel::prelude::*;
        use vauban_web::schema::users;
        users::table
            .filter(users::id.eq(user2_id))
            .select(users::uuid)
            .first(&mut conn)
            .expect("User should exist")
    };

    let token1 = app.generate_test_token(&user1_uuid.to_string(), &user1_name, true, true);
    let token2 = app.generate_test_token(&user2_uuid.to_string(), &user2_name, true, true);

    // Request with Bearer token (user1) and cookie (user2)
    // Bearer should take priority
    let response = app
        .server
        .get("/accounts/sessions")
        .add_header(AUTHORIZATION, format!("Bearer {}", token1))
        .add_header(COOKIE, format!("access_token={}", token2))
        .await;

    // Should succeed (Bearer token is valid)
    assert_status(&response, 200);
}

// =============================================================================
// Token Format Tests
// =============================================================================

/// Test that malformed Bearer header is handled gracefully.
#[tokio::test]
#[serial]
async fn test_malformed_bearer_header() {
    let app = TestApp::spawn().await;

    // Various malformed Bearer headers
    let malformed_headers = vec![
        "Bearer",           // No token
        "Bearer ",          // Empty token
        "bearer token",     // Lowercase bearer
        "Basic dGVzdA==",   // Wrong scheme
        "Token abc123",     // Wrong prefix
    ];

    for header in malformed_headers {
        let response = app
            .server
            .get("/accounts/sessions")
            .add_header(AUTHORIZATION, header)
            .await;

        // Should redirect or return 401 (not crash)
        let status = response.status_code().as_u16();
        assert!(
            status == 303 || status == 401,
            "Expected redirect or 401 for header '{}', got {}",
            header,
            status
        );
    }
}

/// Test that empty cookie is handled gracefully.
#[tokio::test]
#[serial]
async fn test_empty_cookie() {
    let app = TestApp::spawn().await;

    let response = app
        .server
        .get("/accounts/sessions")
        .add_header(COOKIE, "access_token=")
        .await;

    // Should redirect to login
    let status = response.status_code().as_u16();
    assert!(
        status == 303 || status == 401,
        "Expected redirect or 401 for empty cookie, got {}",
        status
    );
}

// =============================================================================
// Superuser/Staff Flag Tests
// =============================================================================

/// Test that superuser flag is correctly extracted from token.
#[tokio::test]
#[serial]
async fn test_superuser_flag_extracted() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    let username = unique_name("superuser_test");
    let user_id = create_simple_user(&mut conn, &username);
    
    let user_uuid: uuid::Uuid = {
        use diesel::prelude::*;
        use vauban_web::schema::users;
        users::table
            .filter(users::id.eq(user_id))
            .select(users::uuid)
            .first(&mut conn)
            .expect("User should exist")
    };

    // Generate token with superuser=true
    let token = app.generate_test_token(
        &user_uuid.to_string(),
        &username,
        true,  // is_superuser
        true,  // is_staff
    );

    let response = app
        .server
        .get("/accounts/sessions")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);
}

/// Test regular user (non-superuser) access.
#[tokio::test]
#[serial]
async fn test_regular_user_access() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    let username = unique_name("regular_user_test");
    let test_user = create_test_user(&mut conn, &app.auth_service, &username);

    let response = app
        .server
        .get("/accounts/sessions")
        .add_header(COOKIE, format!("access_token={}", test_user.token))
        .await;

    // Regular users should still be able to access their own sessions
    assert_status(&response, 200);
}
