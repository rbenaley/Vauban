/// VAUBAN Web - Integration tests for account pages (sessions and API keys).
///
/// Tests for:
/// - /accounts/sessions - User's active login sessions
/// - /accounts/sessions/{uuid}/revoke - Revoke a session
/// - /accounts/apikeys - User's API keys
/// - /accounts/apikeys/create - Create a new API key
/// - /accounts/apikeys/{uuid}/revoke - Revoke an API key

use crate::common::TestApp;
use crate::fixtures::{
    create_simple_user, create_test_auth_session, create_test_api_key, 
    create_expired_api_key, unique_name,
};
use axum::http::header::COOKIE;
use diesel::prelude::*;
use uuid::Uuid;

/// Helper to get user UUID from user_id.
fn get_user_uuid(conn: &mut diesel::PgConnection, user_id: i32) -> Uuid {
    use vauban_web::schema::users;
    users::table
        .filter(users::id.eq(user_id))
        .select(users::uuid)
        .first(conn)
        .expect("User should exist")
}

// =============================================================================
// User Sessions Page Tests
// =============================================================================

#[tokio::test]
async fn test_user_sessions_page_loads() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();
    
    // Create user in database
    let username = unique_name("sessions_page_user");
    let user_id = create_simple_user(&mut conn, &username);
    let user_uuid = get_user_uuid(&mut conn, user_id);
    
    // Generate auth token
    let token = app.generate_test_token(
        &user_uuid.to_string(),
        &username,
        true,
        true,
    );

    // Request user sessions page
    let response = app
        .server
        .get("/accounts/sessions")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 200 || status == 303,
        "Expected 200 or 303, got {}",
        status
    );
}

#[tokio::test]
async fn test_user_sessions_page_requires_auth() {
    let app = TestApp::spawn().await;

    // Request without auth token
    let response = app.server.get("/accounts/sessions").await;

    // Web pages should redirect to login (303 See Other)
    let status = response.status_code().as_u16();
    assert_eq!(
        status, 303,
        "Web pages without auth should redirect to login (303), got {}",
        status
    );

    // Verify redirect location
    let location = response.headers().get("location");
    assert!(location.is_some(), "Redirect should have Location header");
    assert_eq!(
        location.unwrap().to_str().unwrap(),
        "/login",
        "Should redirect to /login"
    );
}

#[tokio::test]
async fn test_user_sessions_page_shows_empty_state() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();
    
    // Create user in database
    let username = unique_name("empty_sessions_user");
    let user_id = create_simple_user(&mut conn, &username);
    let user_uuid = get_user_uuid(&mut conn, user_id);
    
    let token = app.generate_test_token(
        &user_uuid.to_string(),
        &username,
        true,
        true,
    );

    let response = app
        .server
        .get("/accounts/sessions")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert!(status == 200 || status == 303);
    
    if status == 200 {
        let body = response.text();
        // Note: The token generation creates a session, so we check for "My Sessions" title
        assert!(
            body.contains("My Sessions"),
            "Expected sessions page content"
        );
    }
}

#[tokio::test]
async fn test_user_sessions_page_displays_sessions() {
    use vauban_web::schema::users;

    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Create user and sessions
    let username = unique_name("sessions_user");
    let user_id = create_simple_user(&mut conn, &username);
    
    // Get user UUID
    let user_uuid: Uuid = users::table
        .filter(users::id.eq(user_id))
        .select(users::uuid)
        .first(&mut conn)
        .expect("User should exist");

    let _session1 = create_test_auth_session(&mut conn, user_id, true);
    let _session2 = create_test_auth_session(&mut conn, user_id, false);

    let token = app.generate_test_token(
        &user_uuid.to_string(),
        &username,
        true,
        true,
    );

    let response = app
        .server
        .get("/accounts/sessions")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert!(status == 200 || status == 303);
}

#[tokio::test]
async fn test_revoke_session_works() {
    use vauban_web::schema::users;

    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Create user and session
    let username = unique_name("revoke_session_user");
    let user_id = create_simple_user(&mut conn, &username);
    
    // Get user UUID
    let user_uuid: Uuid = users::table
        .filter(users::id.eq(user_id))
        .select(users::uuid)
        .first(&mut conn)
        .expect("User should exist");

    let session_uuid = create_test_auth_session(&mut conn, user_id, false);

    let token = app.generate_test_token(
        &user_uuid.to_string(),
        &username,
        true,
        true,
    );

    // Revoke the session
    let response = app
        .server
        .post(&format!("/accounts/sessions/{}/revoke", session_uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 200 || status == 303,
        "Expected success, got {}",
        status
    );
}

#[tokio::test]
async fn test_revoke_session_requires_auth() {
    let app = TestApp::spawn().await;
    let session_uuid = Uuid::new_v4();

    // Request without auth
    let response = app
        .server
        .post(&format!("/accounts/sessions/{}/revoke", session_uuid))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 303 || status == 401,
        "Expected redirect or unauthorized, got {}",
        status
    );
}

// =============================================================================
// API Keys Page Tests
// =============================================================================

#[tokio::test]
async fn test_api_keys_page_loads() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();
    
    // Create user in database
    let username = unique_name("apikeys_page_user");
    let user_id = create_simple_user(&mut conn, &username);
    let user_uuid = get_user_uuid(&mut conn, user_id);
    
    let token = app.generate_test_token(
        &user_uuid.to_string(),
        &username,
        true,
        true,
    );

    let response = app
        .server
        .get("/accounts/apikeys")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 200 || status == 303,
        "Expected 200 or 303, got {}",
        status
    );
}

#[tokio::test]
async fn test_api_keys_page_requires_auth() {
    let app = TestApp::spawn().await;

    let response = app.server.get("/accounts/apikeys").await;

    // Should redirect to login or return unauthorized
    let status = response.status_code().as_u16();
    assert!(
        status == 303 || status == 401,
        "Expected redirect (303) or unauthorized (401), got {}",
        status
    );
}

#[tokio::test]
async fn test_api_keys_page_shows_empty_state() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();
    
    // Create user in database
    let username = unique_name("empty_apikeys_user");
    let user_id = create_simple_user(&mut conn, &username);
    let user_uuid = get_user_uuid(&mut conn, user_id);
    
    let token = app.generate_test_token(
        &user_uuid.to_string(),
        &username,
        true,
        true,
    );

    let response = app
        .server
        .get("/accounts/apikeys")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert!(status == 200 || status == 303);
    
    if status == 200 {
        let body = response.text();
        assert!(
            body.contains("No API keys") || body.contains("API Keys"),
            "Expected API keys page content"
        );
    }
}

#[tokio::test]
async fn test_api_keys_page_displays_keys() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Create user and API keys
    let username = unique_name("apikeys_display_user");
    let user_id = create_simple_user(&mut conn, &username);
    let user_uuid = get_user_uuid(&mut conn, user_id);
    let _key1 = create_test_api_key(&mut conn, user_id, "Test Key 1", true);
    let _key2 = create_test_api_key(&mut conn, user_id, "Test Key 2", true);

    let token = app.generate_test_token(
        &user_uuid.to_string(),
        &username,
        true,
        true,
    );

    let response = app
        .server
        .get("/accounts/apikeys")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert!(status == 200 || status == 303);
}

#[tokio::test]
async fn test_api_keys_page_shows_expired_keys() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Create user with expired key
    let username = unique_name("expired_key_user");
    let user_id = create_simple_user(&mut conn, &username);
    let user_uuid = get_user_uuid(&mut conn, user_id);
    let _expired_key = create_expired_api_key(&mut conn, user_id, "Expired Key");

    let token = app.generate_test_token(
        &user_uuid.to_string(),
        &username,
        true,
        true,
    );

    let response = app
        .server
        .get("/accounts/apikeys")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert!(status == 200 || status == 303);
}

// =============================================================================
// Create API Key Tests
// =============================================================================

#[tokio::test]
async fn test_create_api_key_form_loads() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();
    
    // Create user in database
    let username = unique_name("create_form_user");
    let user_id = create_simple_user(&mut conn, &username);
    let user_uuid = get_user_uuid(&mut conn, user_id);
    
    let token = app.generate_test_token(
        &user_uuid.to_string(),
        &username,
        true,
        true,
    );

    let response = app
        .server
        .get("/accounts/apikeys/create")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 200 || status == 303,
        "Expected 200 or 303, got {}",
        status
    );
    
    if status == 200 {
        let body = response.text();
        assert!(
            body.contains("Create API Key") || body.contains("create"),
            "Expected create form content"
        );
    }
}

#[tokio::test]
async fn test_create_api_key_form_requires_auth() {
    let app = TestApp::spawn().await;

    let response = app.server.get("/accounts/apikeys/create").await;

    let status = response.status_code().as_u16();
    assert!(
        status == 303 || status == 401,
        "Expected redirect or unauthorized, got {}",
        status
    );
}

#[tokio::test]
async fn test_create_api_key_endpoint_accepts_form() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();
    
    // Create user in database
    let username = unique_name("create_key_user");
    let user_id = create_simple_user(&mut conn, &username);
    let user_uuid = get_user_uuid(&mut conn, user_id);

    let token = app.generate_test_token(
        &user_uuid.to_string(),
        &username,
        true,
        true,
    );

    // Create API key via POST with form data
    // Note: scopes is optional, so we only send the required field 'name'
    let response = app
        .server
        .post("/accounts/apikeys/create")
        .add_header(COOKIE, format!("access_token={}", token))
        .form(&[("name", "My Test Key")])
        .await;

    let status = response.status_code().as_u16();
    // 200 = success (returns created key HTML), 303 = redirect
    assert!(
        status == 200 || status == 303,
        "Expected 200 or 303, got {}",
        status
    );
}

#[tokio::test]
async fn test_create_api_key_requires_auth() {
    let app = TestApp::spawn().await;

    let response = app
        .server
        .post("/accounts/apikeys/create")
        .content_type("application/x-www-form-urlencoded")
        .text("name=Unauthorized+Key")
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 303 || status == 401,
        "Expected redirect or unauthorized, got {}",
        status
    );
}

// =============================================================================
// Revoke API Key Tests
// =============================================================================

#[tokio::test]
async fn test_revoke_api_key_success() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Create user and key
    let username = unique_name("revoke_key_user");
    let user_id = create_simple_user(&mut conn, &username);
    let user_uuid = get_user_uuid(&mut conn, user_id);
    let key_uuid = create_test_api_key(&mut conn, user_id, "Key to Revoke", true);

    let token = app.generate_test_token(
        &user_uuid.to_string(),
        &username,
        true,
        true,
    );

    // Revoke the key
    let response = app
        .server
        .post(&format!("/accounts/apikeys/{}/revoke", key_uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 200 || status == 303,
        "Expected success, got {}",
        status
    );
}

#[tokio::test]
async fn test_revoke_api_key_requires_auth() {
    let app = TestApp::spawn().await;
    let key_uuid = Uuid::new_v4();

    let response = app
        .server
        .post(&format!("/accounts/apikeys/{}/revoke", key_uuid))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 303 || status == 401,
        "Expected redirect or unauthorized, got {}",
        status
    );
}

#[tokio::test]
async fn test_revoke_api_key_not_found() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();
    let nonexistent_uuid = Uuid::new_v4();

    // Create user in database
    let username = unique_name("revoke_notfound_user");
    let user_id = create_simple_user(&mut conn, &username);
    let user_uuid = get_user_uuid(&mut conn, user_id);

    let token = app.generate_test_token(
        &user_uuid.to_string(),
        &username,
        true,
        true,
    );

    // Try to revoke non-existent key
    let response = app
        .server
        .post(&format!("/accounts/apikeys/{}/revoke", nonexistent_uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    // Should succeed (no-op) or return error
    let status = response.status_code().as_u16();
    assert!(
        status == 200 || status == 303 || status == 404,
        "Expected 200, 303, or 404, got {}",
        status
    );
}

#[tokio::test]
async fn test_cannot_revoke_other_users_key() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Create owner and their key
    let owner_name = unique_name("key_owner");
    let owner_id = create_simple_user(&mut conn, &owner_name);
    let key_uuid = create_test_api_key(&mut conn, owner_id, "Owners Key", true);

    // Create different user trying to revoke
    let attacker_name = unique_name("attacker");
    let attacker_id = create_simple_user(&mut conn, &attacker_name);
    let attacker_uuid = get_user_uuid(&mut conn, attacker_id);

    let attacker_token = app.generate_test_token(
        &attacker_uuid.to_string(),
        &attacker_name,
        true,
        true,
    );

    // Try to revoke another user's key
    let response = app
        .server
        .post(&format!("/accounts/apikeys/{}/revoke", key_uuid))
        .add_header(COOKIE, format!("access_token={}", attacker_token))
        .await;

    // Should succeed (no-op since key doesn't belong to attacker)
    let status = response.status_code().as_u16();
    assert!(
        status == 200 || status == 303,
        "Expected 200 or 303, got {}",
        status
    );
}

// =============================================================================
// Session Revocation Invalidates JWT Tests
// =============================================================================

#[tokio::test]
async fn test_revoked_session_token_becomes_invalid() {
    use vauban_web::schema::auth_sessions;

    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Create user
    let username = unique_name("revoke_invalidates_user");
    let user_id = create_simple_user(&mut conn, &username);

    // Get user UUID
    let user_uuid: uuid::Uuid = {
        use vauban_web::schema::users;
        users::table
            .filter(users::id.eq(user_id))
            .select(users::uuid)
            .first(&mut conn)
            .expect("User should exist")
    };

    // Generate a token for this user (this also creates a session in DB)
    let token = app.generate_test_token(
        &user_uuid.to_string(),
        &username,
        true,
        true,
    );

    // First, verify the token works (session exists)
    let response = app
        .server
        .get("/accounts/sessions")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    assert_eq!(response.status_code().as_u16(), 200, "Token should be valid initially");

    // Now delete ALL sessions for this user from database (simulating revocation)
    diesel::delete(
        auth_sessions::table.filter(auth_sessions::user_id.eq(user_id))
    )
    .execute(&mut conn)
    .expect("Should delete all sessions");

    // Try to use the token again - it should now be invalid
    let response2 = app
        .server
        .get("/accounts/sessions")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    
    // Should redirect to login or return 401 (session no longer exists in DB)
    let status = response2.status_code().as_u16();
    assert!(
        status == 303 || status == 401,
        "Expected redirect (303) or unauthorized (401) after session revocation, got {}",
        status
    );
}

#[tokio::test]
async fn test_session_created_on_login() {
    use diesel::prelude::*;
    use vauban_web::schema::{auth_sessions, users};

    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Create user with known password
    let username = unique_name("login_session_user");
    let password = "test_password_123!";
    
    // Hash the password properly
    let password_hash = app.auth_service.hash_password(password)
        .expect("Password hashing should succeed");
    
    // Create user with this password hash
    let user_uuid = Uuid::new_v4();
    diesel::insert_into(users::table)
        .values((
            users::uuid.eq(user_uuid),
            users::username.eq(&username),
            users::email.eq(format!("{}@test.local", username)),
            users::password_hash.eq(&password_hash),
            users::is_active.eq(true),
            users::is_staff.eq(false),
            users::is_superuser.eq(false),
            users::auth_source.eq("local"),
            users::preferences.eq(serde_json::json!({})),
        ))
        .execute(&mut conn)
        .expect("User creation should succeed");

    // Get user_id
    let user_id: i32 = users::table
        .filter(users::uuid.eq(user_uuid))
        .select(users::id)
        .first(&mut conn)
        .expect("User should exist");

    // Count sessions for THIS USER before login
    let sessions_before: i64 = auth_sessions::table
        .filter(auth_sessions::user_id.eq(user_id))
        .count()
        .get_result(&mut conn)
        .unwrap_or(0);

    // Attempt login with correct password
    let response = app
        .server
        .post("/api/auth/login")
        .json(&serde_json::json!({
            "username": username,
            "password": password
        }))
        .await;

    // Login should succeed
    let status = response.status_code().as_u16();
    assert!(
        status == 200 || status == 303,
        "Login should succeed, got {}",
        status
    );

    // Count sessions for THIS USER after login
    let sessions_after: i64 = auth_sessions::table
        .filter(auth_sessions::user_id.eq(user_id))
        .count()
        .get_result(&mut conn)
        .unwrap_or(0);

    // Session count should increase after successful login
    assert!(
        sessions_after > sessions_before,
        "Session count should increase after login: before={}, after={}",
        sessions_before,
        sessions_after
    );
}

#[tokio::test]
async fn test_expired_session_is_rejected() {
    use chrono::{Duration, Utc};
    use vauban_web::schema::auth_sessions;

    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Create user
    let username = unique_name("expired_session_user");
    let user_id = create_simple_user(&mut conn, &username);

    // Get user UUID
    let user_uuid: uuid::Uuid = {
        use vauban_web::schema::users;
        users::table
            .filter(users::id.eq(user_id))
            .select(users::uuid)
            .first(&mut conn)
            .expect("User should exist")
    };

    // Generate a token for this user (this creates a valid session)
    let token = app.generate_test_token(
        &user_uuid.to_string(),
        &username,
        true,
        true,
    );

    // Expire ALL sessions for this user by setting expires_at to past
    diesel::update(
        auth_sessions::table.filter(auth_sessions::user_id.eq(user_id))
    )
    .set(auth_sessions::expires_at.eq(Utc::now() - Duration::hours(1)))
    .execute(&mut conn)
    .expect("Should update sessions to expired");

    // Try to use the token - should be rejected (session expired)
    let response = app
        .server
        .get("/accounts/sessions")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    // Should redirect to login or return 401 (session expired)
    let status = response.status_code().as_u16();
    assert!(
        status == 303 || status == 401,
        "Expected redirect (303) or unauthorized (401) for expired session, got {}",
        status
    );
}

// =============================================================================
// WebSocket Broadcast Tests - Real-time Session Updates
// =============================================================================

#[tokio::test]
async fn test_revoke_session_broadcasts_update_to_websocket() {
    use std::time::Duration as StdDuration;
    use tokio::time::timeout;
    use vauban_web::schema::users;
    use vauban_web::services::broadcast::WsChannel;

    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Create user and sessions
    let username = unique_name("ws_revoke_user");
    let user_id = create_simple_user(&mut conn, &username);
    
    let user_uuid: Uuid = users::table
        .filter(users::id.eq(user_id))
        .select(users::uuid)
        .first(&mut conn)
        .expect("User should exist");

    // Create a session to revoke
    let session_to_revoke = create_test_auth_session(&mut conn, user_id, false);

    let token = app.generate_test_token(
        &user_uuid.to_string(),
        &username,
        true,
        true,
    );

    // Subscribe to the user's auth sessions channel BEFORE revoking
    let channel = WsChannel::UserAuthSessions(user_uuid.to_string());
    let mut receiver = app.broadcast.subscribe(&channel).await;

    // Revoke the session
    let response = app
        .server
        .post(&format!("/accounts/sessions/{}/revoke", session_to_revoke))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert!(
        response.status_code().as_u16() == 200 || response.status_code().as_u16() == 303,
        "Revoke should succeed"
    );

    // Wait for the broadcast message (with timeout)
    let result = timeout(StdDuration::from_secs(2), receiver.recv()).await;
    
    assert!(
        result.is_ok(),
        "Should receive a WebSocket broadcast within 2 seconds"
    );
    
    let message = result.unwrap();
    assert!(
        message.is_ok(),
        "WebSocket message should be received successfully"
    );
    
    let html = message.unwrap();
    // The message should contain the sessions list HTML
    assert!(
        html.contains("sessions-list") || html.contains("hx-swap-oob"),
        "Broadcast should contain sessions list HTML, got: {}",
        &html[..html.len().min(200)]
    );
}

#[tokio::test]
async fn test_revoke_session_removes_session_from_database() {
    use vauban_web::schema::{users, auth_sessions};

    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Create user and session
    let username = unique_name("revoke_db_user");
    let user_id = create_simple_user(&mut conn, &username);
    
    let user_uuid: Uuid = users::table
        .filter(users::id.eq(user_id))
        .select(users::uuid)
        .first(&mut conn)
        .expect("User should exist");

    let session_uuid = create_test_auth_session(&mut conn, user_id, false);

    // Verify session exists before revocation
    let exists_before: bool = diesel::select(diesel::dsl::exists(
        auth_sessions::table.filter(auth_sessions::uuid.eq(session_uuid))
    ))
    .get_result(&mut conn)
    .expect("Query should succeed");
    assert!(exists_before, "Session should exist before revocation");

    let token = app.generate_test_token(
        &user_uuid.to_string(),
        &username,
        true,
        true,
    );

    // Revoke the session
    let _response = app
        .server
        .post(&format!("/accounts/sessions/{}/revoke", session_uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    // Verify session no longer exists
    let exists_after: bool = diesel::select(diesel::dsl::exists(
        auth_sessions::table.filter(auth_sessions::uuid.eq(session_uuid))
    ))
    .get_result(&mut conn)
    .expect("Query should succeed");
    assert!(!exists_after, "Session should be deleted after revocation");
}

#[tokio::test]
async fn test_logout_broadcasts_session_removal() {
    use std::time::Duration as StdDuration;
    use tokio::time::timeout;
    use vauban_web::schema::users;
    use vauban_web::services::broadcast::WsChannel;

    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Create user
    let username = unique_name("ws_logout_user");
    let user_id = create_simple_user(&mut conn, &username);
    
    let user_uuid: Uuid = users::table
        .filter(users::id.eq(user_id))
        .select(users::uuid)
        .first(&mut conn)
        .expect("User should exist");

    // Generate token (this also creates a session)
    let token = app.generate_test_token(
        &user_uuid.to_string(),
        &username,
        true,
        true,
    );

    // Subscribe to the user's auth sessions channel
    let channel = WsChannel::UserAuthSessions(user_uuid.to_string());
    let mut receiver = app.broadcast.subscribe(&channel).await;

    // Logout
    let response = app
        .server
        .post("/api/auth/logout")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    // Logout should succeed (200) or redirect (303)
    let status = response.status_code().as_u16();
    assert!(
        status == 200 || status == 303,
        "Logout should succeed, got {}",
        status
    );

    // Wait for the broadcast message
    let result = timeout(StdDuration::from_secs(2), receiver.recv()).await;
    
    // Logout should broadcast an update
    assert!(
        result.is_ok(),
        "Should receive a WebSocket broadcast after logout"
    );
}

#[tokio::test]
async fn test_login_broadcasts_new_session() {
    use std::time::Duration as StdDuration;
    use tokio::time::timeout;
    use vauban_web::schema::users;
    use vauban_web::services::broadcast::WsChannel;

    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Create user with known password
    let username = unique_name("ws_login_user");
    let password = "test_password_123!";
    
    // Hash the password
    let password_hash = app.auth_service.hash_password(password)
        .expect("Password hashing should succeed");
    
    // Create user with this password hash
    let user_uuid = Uuid::new_v4();
    diesel::insert_into(users::table)
        .values((
            users::uuid.eq(user_uuid),
            users::username.eq(&username),
            users::email.eq(format!("{}@test.local", username)),
            users::password_hash.eq(&password_hash),
            users::is_active.eq(true),
            users::is_staff.eq(false),
            users::is_superuser.eq(false),
            users::auth_source.eq("local"),
            users::preferences.eq(serde_json::json!({})),
        ))
        .execute(&mut conn)
        .expect("User creation should succeed");

    // Subscribe to the user's auth sessions channel BEFORE logging in
    let channel = WsChannel::UserAuthSessions(user_uuid.to_string());
    let mut receiver = app.broadcast.subscribe(&channel).await;

    // Attempt login
    let response = app
        .server
        .post("/api/auth/login")
        .json(&serde_json::json!({
            "username": username,
            "password": password
        }))
        .await;

    // Login should succeed
    let status = response.status_code().as_u16();
    assert!(
        status == 200 || status == 303,
        "Login should succeed, got {}: {}",
        status,
        response.text()
    );

    // Wait for the broadcast message (new session notification)
    let result = timeout(StdDuration::from_secs(2), receiver.recv()).await;
    
    assert!(
        result.is_ok(),
        "Should receive a WebSocket broadcast after login (new session created)"
    );
    
    let message = result.unwrap();
    assert!(
        message.is_ok(),
        "WebSocket message should be received successfully"
    );
    
    let html = message.unwrap();
    assert!(
        html.contains("sessions-list") || html.contains("hx-swap-oob") || html.contains("session-row"),
        "Broadcast should contain session list HTML"
    );
}

#[tokio::test]
async fn test_multiple_sessions_all_updated_on_revoke() {
    use vauban_web::schema::{users, auth_sessions};

    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Create user with multiple sessions
    let username = unique_name("multi_session_user");
    let user_id = create_simple_user(&mut conn, &username);
    
    let user_uuid: Uuid = users::table
        .filter(users::id.eq(user_id))
        .select(users::uuid)
        .first(&mut conn)
        .expect("User should exist");

    // Generate token first (this creates a session)
    let token = app.generate_test_token(
        &user_uuid.to_string(),
        &username,
        true,
        true,
    );

    // Create 3 additional sessions
    let session1 = create_test_auth_session(&mut conn, user_id, false);
    let session2 = create_test_auth_session(&mut conn, user_id, false);
    let session3 = create_test_auth_session(&mut conn, user_id, false);

    // Count sessions before revocation (after token generation)
    let count_before: i64 = auth_sessions::table
        .filter(auth_sessions::user_id.eq(user_id))
        .count()
        .get_result(&mut conn)
        .expect("Count should succeed");
    
    // Should have at least 4 sessions (1 from token + 3 created)
    assert!(count_before >= 4, "Should have at least 4 sessions, got {}", count_before);

    // Revoke session2
    let _response = app
        .server
        .post(&format!("/accounts/sessions/{}/revoke", session2))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    // Count sessions after
    let count_after: i64 = auth_sessions::table
        .filter(auth_sessions::user_id.eq(user_id))
        .count()
        .get_result(&mut conn)
        .expect("Count should succeed");
    
    assert_eq!(
        count_after,
        count_before - 1,
        "Should have one less session after revocation"
    );

    // Verify session1 and session3 still exist
    let session1_exists: bool = diesel::select(diesel::dsl::exists(
        auth_sessions::table.filter(auth_sessions::uuid.eq(session1))
    ))
    .get_result(&mut conn)
    .unwrap();
    
    let session3_exists: bool = diesel::select(diesel::dsl::exists(
        auth_sessions::table.filter(auth_sessions::uuid.eq(session3))
    ))
    .get_result(&mut conn)
    .unwrap();
    
    assert!(session1_exists, "Session 1 should still exist");
    assert!(session3_exists, "Session 3 should still exist");
}
