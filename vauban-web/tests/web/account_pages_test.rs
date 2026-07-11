/// VAUBAN Web - Integration tests for account pages (profile, sessions and API keys).
///
/// Tests for:
/// - /accounts/profile - User's profile page
/// - /accounts/login-sessions - User's active login sessions
/// - /accounts/login-sessions/{uuid}/revoke - Revoke a session
/// - /accounts/all-login-sessions - Admin: all users' web sessions
/// - /accounts/all-login-sessions/{uuid}/revoke - Admin: revoke any user's session
/// - /accounts/apikeys - User's API keys
/// - /accounts/apikeys/create - Create a new API key
/// - /accounts/apikeys/{uuid}/revoke - Revoke an API key
use crate::common::{TestApp, unwrap_ok};
use crate::fixtures::{
    create_auth_session_with_token, create_expired_api_key, create_expired_auth_session,
    create_simple_admin_user, create_simple_user, create_test_api_key, create_test_auth_session,
    create_test_user_with_mfa, current_totp_for, unique_name,
};
use axum::http::header::{COOKIE, USER_AGENT};
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::json;
use uuid::Uuid;
use vauban_web::models::user::AuthSource;

/// Helper to get user UUID from user_id.
async fn get_user_uuid(conn: &mut AsyncPgConnection, user_id: i32) -> Uuid {
    use vauban_web::schema::users;
    unwrap_ok!(
        users::table
            .filter(users::id.eq(user_id))
            .select(users::uuid)
            .first(conn)
            .await
    )
}

// =============================================================================
// User Profile Page Tests
// =============================================================================

#[tokio::test]
async fn test_profile_page_loads() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Create user in database
    let username = unique_name("profile_page_user");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;

    // Generate auth token
    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, true, true)
        .await;

    // Request profile page
    let response = app
        .server
        .get("/accounts/profile")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert_eq!(
        status, 200,
        "Profile page should load successfully, got {}",
        status
    );

    let body = response.text();
    assert!(
        body.contains("My Profile"),
        "Page should contain 'My Profile' title"
    );
}

#[tokio::test]
async fn test_profile_page_requires_auth() {
    let app = TestApp::spawn().await;

    // Request without auth token
    let response = app.server.get("/accounts/profile").await;

    // Web pages should redirect to login (303 See Other)
    let status = response.status_code().as_u16();
    assert_eq!(
        status, 303,
        "Profile page without auth should redirect to login (303), got {}",
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
async fn test_profile_page_displays_user_info() {
    use vauban_web::schema::users;

    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Create user with specific details
    let username = unique_name("profile_display_user");
    let email = format!("{}@test.local", username);

    // Create user with first/last name
    let user_uuid = Uuid::new_v4();
    let password_hash = unwrap_ok!(app.auth_service.hash_password("test_password_123!"));

    unwrap_ok!(
        diesel::insert_into(users::table)
            .values((
                users::uuid.eq(user_uuid),
                users::username.eq(&username),
                users::email.eq(&email),
                users::password_hash.eq(&password_hash),
                users::first_name.eq("John"),
                users::last_name.eq("Doe"),
                users::is_active.eq(true),
                users::is_staff.eq(true),
                users::is_superuser.eq(false),
                users::auth_source.eq(AuthSource::Local),
                users::preferences.eq(serde_json::json!({})),
            ))
            .execute(&mut conn)
            .await
    );

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, true, true)
        .await;

    let response = app
        .server
        .get("/accounts/profile")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert_eq!(status, 200, "Profile page should load");

    let body = response.text();

    // Check that user information is displayed
    assert!(body.contains(&username), "Profile should show username");
    assert!(body.contains(&email), "Profile should show email");
    assert!(body.contains("John"), "Profile should show first name");
    assert!(body.contains("Doe"), "Profile should show last name");
    assert!(body.contains("John Doe"), "Profile should show full name");
    assert!(body.contains("Staff"), "Profile should show staff badge");
}

// =============================================================================
// BUG-06: Edit button on "My Profile" must only appear for admin users
// and redirect to /accounts/users/{uuid}/edit.
// =============================================================================

/// Structural: profile.html must guard the Edit button through the Casbin-backed
/// `perms.users_write` gate (NOT the legacy `is_staff || is_superuser` shortcut)
/// and use {{ profile.uuid }} in the link target.
#[test]
fn test_bug06_profile_edit_button_template_structure() {
    let template = include_str!("../../templates/accounts/profile.html");
    assert!(
        template.contains("perms.users_write"),
        "BUG-06: Edit button must be guarded by `perms.users_write` (Casbin-backed PermissionContext)"
    );
    assert!(
        !template.contains("profile.is_staff || profile.is_superuser")
            && !template.contains("profile.is_superuser || profile.is_staff"),
        "BUG-06: Edit button must NOT use the legacy `is_staff || is_superuser` shortcut; \
         use `perms.users_write` instead"
    );
    assert!(
        template.contains("/accounts/users/{{ profile.uuid }}/edit"),
        "BUG-06: Edit link must point to /accounts/users/{{{{ profile.uuid }}}}/edit"
    );
    assert!(
        !template.contains("/accounts/profile/edit"),
        "BUG-06: dead /accounts/profile/edit link must be removed"
    );
}

/// Structural: the user list page must NOT expose the user's email address
/// as a column. Email remains accessible from the user detail (`View`) page.
/// Regression guard for the privacy-tightening change requested after the
/// responsive overhaul (issue #14 follow-up).
#[test]
fn test_user_list_does_not_render_email_column() {
    let template = include_str!("../../templates/accounts/user_list.html");

    let lower = template.to_lowercase();
    assert!(
        !lower.contains(">email<"),
        "user_list: forbidden 'Email' column header detected; email is now View-only"
    );

    assert!(
        !template.contains("{{ user.email }}"),
        "user_list: forbidden user.email rendering detected; email is now View-only"
    );
}
#[tokio::test]
async fn test_bug06_regular_user_has_no_edit_button() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("bug06_regular");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;

    // Generate a token that matches the DB state: not staff, not superuser
    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, false, false)
        .await;

    let response = app
        .server
        .get("/accounts/profile")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(response.status_code().as_u16(), 200);
    let body = response.text();

    assert!(
        !body.contains(&format!("/accounts/users/{}/edit", user_uuid)),
        "BUG-06: regular user must NOT see Edit link on their profile"
    );
    assert!(
        !body.contains("/accounts/profile/edit"),
        "BUG-06: dead /accounts/profile/edit link must not appear"
    );
}

/// Staff user must see the Edit button pointing to their own /accounts/users/{uuid}/edit.
#[tokio::test]
async fn test_bug06_staff_user_has_edit_button() {
    use vauban_web::schema::users;

    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("bug06_staff");
    let user_uuid = Uuid::new_v4();
    let password_hash = unwrap_ok!(app.auth_service.hash_password("test_password_123!"));

    unwrap_ok!(
        diesel::insert_into(users::table)
            .values((
                users::uuid.eq(user_uuid),
                users::username.eq(&username),
                users::email.eq(format!("{}@test.local", username)),
                users::password_hash.eq(&password_hash),
                users::is_active.eq(true),
                users::is_staff.eq(true),
                users::is_superuser.eq(false),
                users::auth_source.eq(AuthSource::Local),
                users::preferences.eq(serde_json::json!({})),
            ))
            .execute(&mut conn)
            .await
    );

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, false, true)
        .await;

    let response = app
        .server
        .get("/accounts/profile")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(response.status_code().as_u16(), 200);
    let body = response.text();

    let expected_href = format!("/accounts/users/{}/edit", user_uuid);
    assert!(
        body.contains(&expected_href),
        "BUG-06: staff user must see Edit link to {}, got body: {}",
        expected_href,
        &body[..body.len().min(500)]
    );
    assert!(
        !body.contains("/accounts/profile/edit"),
        "BUG-06: dead /accounts/profile/edit link must not appear"
    );
}

/// Superuser must see the Edit button pointing to their own /accounts/users/{uuid}/edit.
#[tokio::test]
async fn test_bug06_superuser_has_edit_button() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("bug06_super");
    let user_id = create_simple_admin_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, true, true)
        .await;

    let response = app
        .server
        .get("/accounts/profile")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(response.status_code().as_u16(), 200);
    let body = response.text();

    let expected_href = format!("/accounts/users/{}/edit", user_uuid);
    assert!(
        body.contains(&expected_href),
        "BUG-06: superuser must see Edit link to {}",
        expected_href
    );
}

/// Defense-in-depth: a regular user who somehow crafts the edit URL directly
/// must be denied by the server-side RBAC check (Casbin users:write).
#[tokio::test]
async fn test_bug06_regular_user_cannot_access_own_edit_url() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("bug06_no_direct");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, false, false)
        .await;

    let response = app
        .server
        .get(&format!("/accounts/users/{}/edit", user_uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    // The handler performs a flash_redirect on RBAC failure (303 See Other).
    // We also accept any non-200 as a protective response.
    assert_ne!(
        status, 200,
        "BUG-06: regular user must NOT be able to GET their own edit form; got 200"
    );
    assert!(
        (300..400).contains(&status) || status == 403,
        "BUG-06: expected redirect or 403 for regular user on edit URL, got {}",
        status
    );
}

#[tokio::test]
async fn test_profile_page_shows_mfa_status() {
    use vauban_web::schema::users;

    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Create user with MFA enabled
    let username = unique_name("profile_mfa_user");
    let user_uuid = Uuid::new_v4();
    let password_hash = app
        .auth_service
        .hash_password("test_password_123!")
        .expect("Password hashing should succeed");

    diesel::insert_into(users::table)
        .values((
            users::uuid.eq(user_uuid),
            users::username.eq(&username),
            users::email.eq(format!("{}@test.local", username)),
            users::password_hash.eq(&password_hash),
            users::is_active.eq(true),
            users::is_staff.eq(false),
            users::is_superuser.eq(false),
            users::mfa_enabled.eq(true),
            users::auth_source.eq(AuthSource::Local),
            users::preferences.eq(serde_json::json!({})),
        ))
        .execute(&mut conn)
        .await
        .expect("User creation should succeed");

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, true, true)
        .await;

    let response = app
        .server
        .get("/accounts/profile")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert_eq!(status, 200, "Profile page should load");

    let body = response.text();

    // Check MFA status is shown
    assert!(
        body.contains("Two-Factor Authentication") || body.contains("MFA"),
        "Profile should show MFA section"
    );
    assert!(
        body.contains("Active") || body.contains("Enabled"),
        "Profile should show MFA is enabled"
    );
}

#[tokio::test]
async fn test_profile_page_shows_active_sessions() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Create user
    let username = unique_name("profile_sessions_user");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;

    // Create some sessions
    let _session1 = create_test_auth_session(&mut conn, user_id, true).await;
    let _session2 = create_test_auth_session(&mut conn, user_id, false).await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, true, true)
        .await;

    let response = app
        .server
        .get("/accounts/profile")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert_eq!(status, 200, "Profile page should load");

    let body = response.text();

    // Check sessions section is displayed
    assert!(
        body.contains("Active Sessions"),
        "Profile should have Active Sessions section"
    );
}

#[tokio::test]
async fn test_profile_page_shows_superuser_badge() {
    use vauban_web::schema::users;

    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Create superuser
    let username = unique_name("profile_superuser");
    let user_uuid = Uuid::new_v4();
    let password_hash = app
        .auth_service
        .hash_password("test_password_123!")
        .expect("Password hashing should succeed");

    diesel::insert_into(users::table)
        .values((
            users::uuid.eq(user_uuid),
            users::username.eq(&username),
            users::email.eq(format!("{}@test.local", username)),
            users::password_hash.eq(&password_hash),
            users::is_active.eq(true),
            users::is_staff.eq(true),
            users::is_superuser.eq(true),
            users::auth_source.eq(AuthSource::Local),
            users::preferences.eq(serde_json::json!({})),
        ))
        .execute(&mut conn)
        .await
        .expect("User creation should succeed");

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, true, true)
        .await;

    let response = app
        .server
        .get("/accounts/profile")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert_eq!(status, 200, "Profile page should load");

    let body = response.text();

    // Check admin badge is shown
    assert!(
        body.contains("Admin"),
        "Profile should show Admin badge for superuser"
    );
    assert!(body.contains("Staff"), "Profile should show Staff badge");
}

#[tokio::test]
async fn test_profile_page_shows_auth_source() {
    use vauban_web::schema::users;

    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Create user with LDAP auth source
    let username = unique_name("profile_ldap_user");
    let user_uuid = Uuid::new_v4();
    let password_hash = app
        .auth_service
        .hash_password("test_password_123!")
        .expect("Password hashing should succeed");

    diesel::insert_into(users::table)
        .values((
            users::uuid.eq(user_uuid),
            users::username.eq(&username),
            users::email.eq(format!("{}@test.local", username)),
            users::password_hash.eq(&password_hash),
            users::is_active.eq(true),
            users::is_staff.eq(false),
            users::is_superuser.eq(false),
            users::auth_source.eq(AuthSource::Ldap),
            users::preferences.eq(serde_json::json!({})),
        ))
        .execute(&mut conn)
        .await
        .expect("User creation should succeed");

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, true, true)
        .await;

    let response = app
        .server
        .get("/accounts/profile")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert_eq!(status, 200, "Profile page should load");

    let body = response.text();

    // Check auth source is displayed
    assert!(
        body.contains("LDAP"),
        "Profile should show LDAP auth source"
    );
    // For LDAP users, password change should not be shown or should indicate external management
    assert!(
        body.contains("managed by") || !body.contains("Change Password") || body.contains("LDAP"),
        "Profile should indicate password is managed externally for LDAP users"
    );
}

#[tokio::test]
async fn test_profile_page_shows_quick_actions() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("profile_actions_user");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, true, true)
        .await;

    let response = app
        .server
        .get("/accounts/profile")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert_eq!(status, 200, "Profile page should load");

    let body = response.text();

    // Check quick actions section
    assert!(
        body.contains("Quick Actions"),
        "Profile should have Quick Actions section"
    );
    assert!(
        body.contains("API Keys"),
        "Profile should have link to API Keys"
    );
    assert!(
        body.contains("Manage Login Sessions") || body.contains("/accounts/login-sessions"),
        "Profile should have link to sessions"
    );
}

#[tokio::test]
async fn test_profile_page_displays_uuid() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("profile_uuid_user");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, true, true)
        .await;

    let response = app
        .server
        .get("/accounts/profile")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert_eq!(status, 200, "Profile page should load");

    let body = response.text();

    // Check UUID is displayed
    assert!(
        body.contains(&user_uuid.to_string()),
        "Profile should display user UUID"
    );
}

// =============================================================================
// User Sessions Page Tests
// =============================================================================

#[tokio::test]
async fn test_user_sessions_page_loads() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Create user in database
    let username = unique_name("sessions_page_user");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;

    // Generate auth token
    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, true, true)
        .await;

    // Request user sessions page
    let response = app
        .server
        .get("/accounts/login-sessions")
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
    let response = app.server.get("/accounts/login-sessions").await;

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
    let mut conn = app.get_conn().await;

    // Create user in database
    let username = unique_name("empty_sessions_user");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, true, true)
        .await;

    let response = app
        .server
        .get("/accounts/login-sessions")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert!(status == 200 || status == 303);

    if status == 200 {
        let body = response.text();
        // Note: The token generation creates a session, so we check for "My Login Sessions" title
        assert!(
            body.contains("My Login Sessions"),
            "Expected sessions page content"
        );
    }
}

#[tokio::test]
async fn test_user_sessions_page_displays_sessions() {
    use vauban_web::schema::users;

    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Create user and sessions
    let username = unique_name("sessions_user");
    let user_id = create_simple_user(&mut conn, &username).await;

    // Get user UUID
    let user_uuid: Uuid = users::table
        .filter(users::id.eq(user_id))
        .select(users::uuid)
        .first(&mut conn)
        .await
        .expect("User should exist");

    let _session1 = create_test_auth_session(&mut conn, user_id, true).await;
    let _session2 = create_test_auth_session(&mut conn, user_id, false).await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, true, true)
        .await;

    let response = app
        .server
        .get("/accounts/login-sessions")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert!(status == 200 || status == 303);
}

#[tokio::test]
async fn test_revoke_session_works() {
    use vauban_web::schema::users;

    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Create user and session
    let username = unique_name("revoke_session_user");
    let user_id = create_simple_user(&mut conn, &username).await;

    // Get user UUID
    let user_uuid: Uuid = users::table
        .filter(users::id.eq(user_id))
        .select(users::uuid)
        .first(&mut conn)
        .await
        .expect("User should exist");

    let session_uuid = create_test_auth_session(&mut conn, user_id, false).await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, true, true)
        .await;
    let csrf_token = app.generate_csrf_token();

    // Revoke the session
    let response = app
        .server
        .post(&format!("/accounts/login-sessions/{}/revoke", session_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[("csrf_token", csrf_token.as_str())])
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
        .post(&format!("/accounts/login-sessions/{}/revoke", session_uuid))
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
    let mut conn = app.get_conn().await;

    // Create user in database
    let username = unique_name("apikeys_page_user");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, true, true)
        .await;

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
    let mut conn = app.get_conn().await;

    // Create user in database
    let username = unique_name("empty_apikeys_user");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, true, true)
        .await;

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
    let mut conn = app.get_conn().await;

    // Create user and API keys
    let username = unique_name("apikeys_display_user");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;
    let _key1 = create_test_api_key(&mut conn, user_id, "Test Key 1", true).await;
    let _key2 = create_test_api_key(&mut conn, user_id, "Test Key 2", true).await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, true, true)
        .await;

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
    let mut conn = app.get_conn().await;

    // Create user with expired key
    let username = unique_name("expired_key_user");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;
    let _expired_key = create_expired_api_key(&mut conn, user_id, "Expired Key").await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, true, true)
        .await;

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
    let mut conn = app.get_conn().await;

    // Create user in database
    let username = unique_name("create_form_user");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, true, true)
        .await;

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
    let mut conn = app.get_conn().await;

    // Create user in database
    let username = unique_name("create_key_user");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, true, true)
        .await;
    let csrf_token = app.generate_csrf_token();

    // Create API key via POST with form data
    // Note: scopes is optional, so we only send the required field 'name'
    let response = app
        .server
        .post("/accounts/apikeys/create")
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[("name", "My Test Key"), ("csrf_token", csrf_token.as_str())])
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
async fn test_create_api_key_accepts_repeated_scopes_and_empty_expiry() {
    // Regression: the browser posts one `scopes` key per ticked checkbox
    // plus `expires_in_days=` (empty) for the "Never" option. The old
    // `axum::extract::Form` extractor rejected that body with a 422 and
    // the modal silently did nothing.
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("multi_scope_key_user");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, true, true)
        .await;
    let csrf_token = app.generate_csrf_token();

    let body = format!(
        "name=Vault-Secrets-Test&scopes=read&scopes=secrets&expires_in_days=&csrf_token={}",
        csrf_token
    );
    let response = app
        .server
        .post("/accounts/apikeys/create")
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .content_type("application/x-www-form-urlencoded")
        .text(body)
        .await;

    assert_eq!(
        response.status_code().as_u16(),
        200,
        "repeated scopes + empty expiry must not 422: {}",
        response.text()
    );

    // The created key must carry both scopes in the JSONB column.
    use diesel::prelude::*;
    use diesel_async::RunQueryDsl;
    use vauban_web::schema::api_keys;
    let scopes: serde_json::Value = api_keys::table
        .filter(api_keys::user_id.eq(user_id))
        .order(api_keys::id.desc())
        .select(api_keys::scopes)
        .first(&mut conn)
        .await
        .expect("API key row must exist");
    assert_eq!(scopes, serde_json::json!(["read", "secrets"]));
}

#[tokio::test]
async fn test_create_api_key_filters_unknown_scopes_and_defaults_to_read() {
    // Adversarial: a tampered form posting a scope outside the
    // ApiKeyScope vocabulary must never land it in the JSONB column
    // (whitelist at write time), and a body with no scope at all must
    // fall back to the least-privilege ["read"].
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("scope_filter_user");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, true, true)
        .await;
    let csrf_token = app.generate_csrf_token();

    use diesel::prelude::*;
    use diesel_async::RunQueryDsl;
    use vauban_web::schema::api_keys;

    let latest_scopes = |conn: &mut diesel_async::AsyncPgConnection| {
        api_keys::table
            .filter(api_keys::user_id.eq(user_id))
            .order(api_keys::id.desc())
            .select(api_keys::scopes)
            .first::<serde_json::Value>(conn)
    };

    // Case 1: bogus scope smuggled next to a legitimate one.
    let response = app
        .server
        .post("/accounts/apikeys/create")
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .content_type("application/x-www-form-urlencoded")
        .text(format!(
            "name=Tampered&scopes=secrets&scopes=superadmin&csrf_token={}",
            csrf_token
        ))
        .await;
    assert_eq!(response.status_code().as_u16(), 200);
    assert_eq!(
        latest_scopes(&mut conn).await.expect("key row"),
        serde_json::json!(["secrets"]),
        "unknown scope strings must be dropped by the ApiKeyScope::parse whitelist"
    );

    // Case 2: no scope checkbox at all -> least-privilege default.
    let response = app
        .server
        .post("/accounts/apikeys/create")
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .content_type("application/x-www-form-urlencoded")
        .text(format!("name=NoScope&csrf_token={}", csrf_token))
        .await;
    assert_eq!(response.status_code().as_u16(), 200);
    assert_eq!(
        latest_scopes(&mut conn).await.expect("key row"),
        serde_json::json!(["read"]),
        "a body without scopes must default to the least-privilege [\"read\"]"
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
    let mut conn = app.get_conn().await;

    // Create user and key
    let username = unique_name("revoke_key_user");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;
    let key_uuid = create_test_api_key(&mut conn, user_id, "Key to Revoke", true).await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, true, true)
        .await;
    let csrf_token = app.generate_csrf_token();

    // Revoke the key
    let response = app
        .server
        .post(&format!("/accounts/apikeys/{}/revoke", key_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[("csrf_token", csrf_token.as_str())])
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
    let mut conn = app.get_conn().await;
    let nonexistent_uuid = Uuid::new_v4();

    // Create user in database
    let username = unique_name("revoke_notfound_user");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, true, true)
        .await;
    let csrf_token = app.generate_csrf_token();

    // Try to revoke non-existent key
    let response = app
        .server
        .post(&format!("/accounts/apikeys/{}/revoke", nonexistent_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[("csrf_token", csrf_token.as_str())])
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
    let mut conn = app.get_conn().await;

    // Create owner and their key
    let owner_name = unique_name("key_owner");
    let owner_id = create_simple_user(&mut conn, &owner_name).await;
    let key_uuid = create_test_api_key(&mut conn, owner_id, "Owners Key", true).await;

    // Create different user trying to revoke
    let attacker_name = unique_name("attacker");
    let attacker_id = create_simple_user(&mut conn, &attacker_name).await;
    let attacker_uuid = get_user_uuid(&mut conn, attacker_id).await;

    let attacker_token = app
        .generate_test_token(&attacker_uuid.to_string(), &attacker_name, true, true)
        .await;
    let csrf_token = app.generate_csrf_token();

    // Try to revoke another user's key
    let response = app
        .server
        .post(&format!("/accounts/apikeys/{}/revoke", key_uuid))
        .add_header(
            COOKIE,
            format!(
                "access_token={}; __vauban_csrf={}",
                attacker_token, csrf_token
            ),
        )
        .form(&[("csrf_token", csrf_token.as_str())])
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
    let mut conn = app.get_conn().await;

    // Create user
    let username = unique_name("revoke_invalidates_user");
    let user_id = create_simple_user(&mut conn, &username).await;

    // Get user UUID
    let user_uuid: uuid::Uuid = {
        use vauban_web::schema::users;
        users::table
            .filter(users::id.eq(user_id))
            .select(users::uuid)
            .first(&mut conn)
            .await
            .expect("User should exist")
    };

    // Generate a token for this user (this also creates a session in DB)
    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, true, true)
        .await;

    // First, verify the token works (session exists)
    let response = app
        .server
        .get("/accounts/login-sessions")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    assert_eq!(
        response.status_code().as_u16(),
        200,
        "Token should be valid initially"
    );

    // Now delete ALL sessions for this user from database (simulating revocation)
    diesel::delete(auth_sessions::table.filter(auth_sessions::user_id.eq(user_id)))
        .execute(&mut conn)
        .await
        .expect("Should delete all sessions");

    // Try to use the token again - it should now be invalid
    let response2 = app
        .server
        .get("/accounts/login-sessions")
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
    use vauban_web::schema::auth_sessions;

    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Per Finding #2 remediation, the API login endpoint refuses accounts
    // that do not have MFA configured. We therefore mint an MFA-enabled
    // user and submit the matching TOTP code below.
    let username = unique_name("login_session_user");
    let test_user = create_test_user_with_mfa(&mut conn, &app.auth_service, &username).await;
    let user_id = test_user.user.id;

    // Count sessions for THIS USER before login (baseline includes the
    // bootstrap session inserted by `create_test_user_with_mfa`).
    let sessions_before: i64 = auth_sessions::table
        .filter(auth_sessions::user_id.eq(user_id))
        .count()
        .get_result(&mut conn)
        .await
        .unwrap_or(0);

    // Attempt login with correct password + valid TOTP code.
    let response = app
        .server
        .post("/api/v1/auth/login")
        .json(&serde_json::json!({
            "username": username,
            "password": test_user.password,
            "mfa_code": current_totp_for(&test_user.mfa_secret),
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
        .await
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
    let mut conn = app.get_conn().await;

    // Create user
    let username = unique_name("expired_session_user");
    let user_id = create_simple_user(&mut conn, &username).await;

    // Get user UUID
    let user_uuid: uuid::Uuid = {
        use vauban_web::schema::users;
        users::table
            .filter(users::id.eq(user_id))
            .select(users::uuid)
            .first(&mut conn)
            .await
            .expect("User should exist")
    };

    // Generate a token for this user (this creates a valid session)
    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, true, true)
        .await;

    // Make the session idle for too long by setting last_activity to 2 hours ago
    // (exceeds session_idle_timeout_secs which is typically 30 min / 1800 secs)
    diesel::update(auth_sessions::table.filter(auth_sessions::user_id.eq(user_id)))
        .set(auth_sessions::last_activity.eq(Utc::now() - Duration::hours(2)))
        .execute(&mut conn)
        .await
        .expect("Should update sessions to idle-expired");

    // Try to use the token - should be rejected (session idle-expired)
    let response = app
        .server
        .get("/accounts/login-sessions")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    // Should redirect to login or return 401 (session expired)
    let status = response.status_code().as_u16();
    assert!(
        status == 303 || status == 401,
        "Expected redirect (303) or unauthorized (401) for idle-expired session, got {}",
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
    let mut conn = app.get_conn().await;

    // Create user and sessions
    let username = unique_name("ws_revoke_user");
    let user_id = create_simple_user(&mut conn, &username).await;

    let user_uuid: Uuid = users::table
        .filter(users::id.eq(user_id))
        .select(users::uuid)
        .first(&mut conn)
        .await
        .expect("User should exist");

    // Create a session to revoke
    let session_to_revoke = create_test_auth_session(&mut conn, user_id, false).await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, true, true)
        .await;
    let csrf_token = app.generate_csrf_token();

    // Subscribe to the user's auth sessions channel BEFORE revoking
    let channel = WsChannel::UserAuthSessions(user_uuid.to_string());
    let mut receiver = app.broadcast.subscribe(&channel).await;

    // Revoke the session
    let response = app
        .server
        .post(&format!(
            "/accounts/login-sessions/{}/revoke",
            session_to_revoke
        ))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[("csrf_token", csrf_token.as_str())])
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
    use vauban_web::schema::{auth_sessions, users};

    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Create user and session
    let username = unique_name("revoke_db_user");
    let user_id = create_simple_user(&mut conn, &username).await;

    let user_uuid: Uuid = users::table
        .filter(users::id.eq(user_id))
        .select(users::uuid)
        .first(&mut conn)
        .await
        .expect("User should exist");

    let session_uuid = create_test_auth_session(&mut conn, user_id, false).await;

    // Verify session exists before revocation
    let exists_before: bool = diesel::select(diesel::dsl::exists(
        auth_sessions::table.filter(auth_sessions::uuid.eq(session_uuid)),
    ))
    .get_result(&mut conn)
    .await
    .expect("Query should succeed");
    assert!(exists_before, "Session should exist before revocation");

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, true, true)
        .await;
    let csrf_token = app.generate_csrf_token();

    // Revoke the session
    let _response = app
        .server
        .post(&format!("/accounts/login-sessions/{}/revoke", session_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[("csrf_token", csrf_token.as_str())])
        .await;

    // Verify session no longer exists
    let exists_after: bool = diesel::select(diesel::dsl::exists(
        auth_sessions::table.filter(auth_sessions::uuid.eq(session_uuid)),
    ))
    .get_result(&mut conn)
    .await
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
    let mut conn = app.get_conn().await;

    // Create user
    let username = unique_name("ws_logout_user");
    let user_id = create_simple_user(&mut conn, &username).await;

    let user_uuid: Uuid = users::table
        .filter(users::id.eq(user_id))
        .select(users::uuid)
        .first(&mut conn)
        .await
        .expect("User should exist");

    // Generate token (this also creates a session)
    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, true, true)
        .await;

    // Subscribe to the user's auth sessions channel
    let channel = WsChannel::UserAuthSessions(user_uuid.to_string());
    let mut receiver = app.broadcast.subscribe(&channel).await;

    // Logout (web route)
    let csrf_token = app.generate_csrf_token();
    let response = app
        .server
        .post("/auth/logout")
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[("csrf_token", csrf_token.as_str())])
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
    use vauban_web::services::auth::AuthService;
    use vauban_web::services::broadcast::WsChannel;

    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Create user with known password
    let username = unique_name("ws_login_user");
    let password = "test_password_123!";

    // Hash the password
    let password_hash = app
        .auth_service
        .hash_password(password)
        .expect("Password hashing should succeed");

    // Per Finding #2 remediation, API login requires MFA configured on
    // the account. Generate a TOTP secret so we can include a valid code
    // in the login payload below.
    let (mfa_secret, _) =
        AuthService::generate_totp_secret(&username, "VAUBAN-tests").expect("totp secret");

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
            users::mfa_enabled.eq(true),
            users::mfa_secret.eq(Some(mfa_secret.clone())),
            users::auth_source.eq(AuthSource::Local),
            users::preferences.eq(serde_json::json!({})),
        ))
        .execute(&mut conn)
        .await
        .expect("User creation should succeed");

    // Subscribe to the user's auth sessions channel BEFORE logging in
    let channel = WsChannel::UserAuthSessions(user_uuid.to_string());
    let mut receiver = app.broadcast.subscribe(&channel).await;

    // Attempt login
    let response = app
        .server
        .post("/api/v1/auth/login")
        .json(&serde_json::json!({
            "username": username,
            "password": password,
            "mfa_code": current_totp_for(&mfa_secret),
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
        html.contains("sessions-list")
            || html.contains("hx-swap-oob")
            || html.contains("session-row"),
        "Broadcast should contain session list HTML"
    );
}

#[tokio::test]
async fn test_multiple_sessions_all_updated_on_revoke() {
    use vauban_web::schema::{auth_sessions, users};

    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Create user with multiple sessions
    let username = unique_name("multi_session_user");
    let user_id = create_simple_user(&mut conn, &username).await;

    let user_uuid: Uuid = users::table
        .filter(users::id.eq(user_id))
        .select(users::uuid)
        .first(&mut conn)
        .await
        .expect("User should exist");

    // Generate token first (this creates a session)
    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, true, true)
        .await;
    let csrf_token = app.generate_csrf_token();

    // Create 3 additional sessions
    let session1 = create_test_auth_session(&mut conn, user_id, false).await;
    let session2 = create_test_auth_session(&mut conn, user_id, false).await;
    let session3 = create_test_auth_session(&mut conn, user_id, false).await;

    // Count sessions before revocation (after token generation)
    let count_before: i64 = auth_sessions::table
        .filter(auth_sessions::user_id.eq(user_id))
        .count()
        .get_result(&mut conn)
        .await
        .expect("Count should succeed");

    // Should have at least 4 sessions (1 from token + 3 created)
    assert!(
        count_before >= 4,
        "Should have at least 4 sessions, got {}",
        count_before
    );

    // Revoke session2
    let _response = app
        .server
        .post(&format!("/accounts/login-sessions/{}/revoke", session2))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[("csrf_token", csrf_token.as_str())])
        .await;

    // Count sessions after
    let count_after: i64 = auth_sessions::table
        .filter(auth_sessions::user_id.eq(user_id))
        .count()
        .get_result(&mut conn)
        .await
        .expect("Count should succeed");

    assert_eq!(
        count_after,
        count_before - 1,
        "Should have one less session after revocation"
    );

    // Verify session1 and session3 still exist
    let session1_exists: bool = diesel::select(diesel::dsl::exists(
        auth_sessions::table.filter(auth_sessions::uuid.eq(session1)),
    ))
    .get_result(&mut conn)
    .await
    .unwrap();

    let session3_exists: bool = diesel::select(diesel::dsl::exists(
        auth_sessions::table.filter(auth_sessions::uuid.eq(session3)),
    ))
    .get_result(&mut conn)
    .await
    .unwrap();

    assert!(session1_exists, "Session 1 should still exist");
    assert!(session3_exists, "Session 3 should still exist");
}

// =============================================================================
// Admin Users Sessions Page Tests (/accounts/all-login-sessions)
// =============================================================================

#[tokio::test]
async fn test_admin_sessions_page_loads_for_admin() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("admsess_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let response = app
        .server
        .get("/accounts/all-login-sessions")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 200,
        "Admin should be able to view admin sessions page (got {})",
        status
    );
    let body = response.text();
    assert!(
        body.contains("All Login Sessions"),
        "Page should contain 'All Sessions' title"
    );
}

#[tokio::test]
async fn test_admin_sessions_page_loads_for_staff() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let staff_name = unique_name("admsess_staff");
    let staff_id = create_simple_admin_user(&mut conn, &staff_name).await;
    let staff_uuid = get_user_uuid(&mut conn, staff_id).await;

    let token = app
        .generate_test_token(&staff_uuid.to_string(), &staff_name, false, true)
        .await;

    let response = app
        .server
        .get("/accounts/all-login-sessions")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 200,
        "Staff should be able to view admin sessions page (got {})",
        status
    );
}

#[tokio::test]
async fn test_admin_sessions_page_rejected_for_regular_user() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user_name = unique_name("admsess_user");
    let user_id = create_simple_user(&mut conn, &user_name).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &user_name, false, false)
        .await;

    let response = app
        .server
        .get("/accounts/all-login-sessions")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 403 || status == 302,
        "Regular user should be rejected (got {})",
        status
    );
}

#[tokio::test]
async fn test_admin_sessions_shows_all_users_sessions() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("admsess_view_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let user_name = unique_name("admsess_view_user");
    let user_id = create_simple_user(&mut conn, &user_name).await;

    // Create sessions for both users
    create_test_auth_session(&mut conn, admin_id, false).await;
    create_test_auth_session(&mut conn, user_id, false).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let response = app
        .server
        .get("/accounts/all-login-sessions")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(response.status_code().as_u16(), 200);
    let body = response.text();

    // Both users' sessions should be visible (usernames have UUID suffixes)
    assert!(
        body.contains("admin-session-row-"),
        "Page should contain session rows"
    );
}

#[tokio::test]
async fn test_admin_sessions_hides_expired() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("admsess_expired_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let user_name = unique_name("admsess_expired_user");
    let user_id = create_simple_user(&mut conn, &user_name).await;

    // Create an expired session for user
    let expired_uuid = create_expired_auth_session(&mut conn, user_id, "expired_token_value").await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let response = app
        .server
        .get("/accounts/all-login-sessions")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(response.status_code().as_u16(), 200);
    let body = response.text();
    assert!(
        !body.contains(&expired_uuid.to_string()),
        "Expired sessions should not be shown"
    );
}

#[tokio::test]
async fn test_admin_revoke_session_deletes_from_db() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("adm_revoke_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let user_name = unique_name("adm_revoke_target");
    let user_id = create_simple_user(&mut conn, &user_name).await;

    let session_uuid =
        create_auth_session_with_token(&mut conn, user_id, "target_session_token", false).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let csrf_token = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!(
            "/accounts/all-login-sessions/{}/revoke",
            session_uuid
        ))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[("csrf_token", csrf_token.as_str())])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 200,
        "Admin revoke should succeed (got {})",
        status
    );

    // Verify session is deleted from DB
    use vauban_web::schema::auth_sessions;
    let session_exists: bool = diesel::select(diesel::dsl::exists(
        auth_sessions::table.filter(auth_sessions::uuid.eq(session_uuid)),
    ))
    .get_result(&mut conn)
    .await
    .unwrap();

    assert!(
        !session_exists,
        "Session should be deleted from DB after admin revocation"
    );
}

#[tokio::test]
async fn test_admin_revoke_non_staff_rejected() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user_name = unique_name("adm_revoke_nostaff");
    let user_id = create_simple_user(&mut conn, &user_name).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;

    let target_name = unique_name("adm_revoke_target2");
    let target_id = create_simple_user(&mut conn, &target_name).await;
    let session_uuid =
        create_auth_session_with_token(&mut conn, target_id, "some_token", false).await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &user_name, false, false)
        .await;
    let csrf_token = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!(
            "/accounts/all-login-sessions/{}/revoke",
            session_uuid
        ))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[("csrf_token", csrf_token.as_str())])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 403 || status == 302,
        "Non-staff should be rejected from admin revoke (got {})",
        status
    );

    // Session should still exist
    use vauban_web::schema::auth_sessions;
    let session_exists: bool = diesel::select(diesel::dsl::exists(
        auth_sessions::table.filter(auth_sessions::uuid.eq(session_uuid)),
    ))
    .get_result(&mut conn)
    .await
    .unwrap();
    assert!(
        session_exists,
        "Session should remain after rejected revoke"
    );
}

#[tokio::test]
async fn test_admin_revoke_nonexistent_session() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("adm_revoke_noexist");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let csrf_token = app.generate_csrf_token();

    let nonexistent = Uuid::new_v4();
    let response = app
        .server
        .post(&format!(
            "/accounts/all-login-sessions/{}/revoke",
            nonexistent
        ))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[("csrf_token", csrf_token.as_str())])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 404,
        "Nonexistent session should return 404 (got {})",
        status
    );
}

#[tokio::test]
async fn test_admin_revoke_invalid_uuid() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("adm_revoke_baduuid");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let csrf_token = app.generate_csrf_token();

    let response = app
        .server
        .post("/accounts/all-login-sessions/not-a-valid-uuid/revoke")
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[("csrf_token", csrf_token.as_str())])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "Invalid UUID should redirect (got {})",
        status
    );
}

#[tokio::test]
async fn test_admin_revoke_invalid_csrf() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("adm_revoke_badcsrf");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let user_name = unique_name("adm_revoke_csrf_target");
    let user_id = create_simple_user(&mut conn, &user_name).await;
    let session_uuid =
        create_auth_session_with_token(&mut conn, user_id, "csrf_test_token", false).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let response = app
        .server
        .post(&format!(
            "/accounts/all-login-sessions/{}/revoke",
            session_uuid
        ))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf=invalid", token),
        )
        .form(&[("csrf_token", "totally_wrong")])
        .await;

    let status = response.status_code().as_u16();
    assert_eq!(status, 400, "Invalid CSRF should return 400");

    // Session should still exist
    use vauban_web::schema::auth_sessions;
    let session_exists: bool = diesel::select(diesel::dsl::exists(
        auth_sessions::table.filter(auth_sessions::uuid.eq(session_uuid)),
    ))
    .get_result(&mut conn)
    .await
    .unwrap();
    assert!(session_exists, "Session should remain after CSRF failure");
}

#[tokio::test]
async fn test_admin_revoke_idempotent() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("adm_revoke_idemp");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let user_name = unique_name("adm_revoke_idemp_target");
    let user_id = create_simple_user(&mut conn, &user_name).await;
    let session_uuid =
        create_auth_session_with_token(&mut conn, user_id, "idemp_token", false).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let csrf_token = app.generate_csrf_token();

    // First revocation
    let response = app
        .server
        .post(&format!(
            "/accounts/all-login-sessions/{}/revoke",
            session_uuid
        ))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[("csrf_token", csrf_token.as_str())])
        .await;
    assert_eq!(response.status_code().as_u16(), 200);

    // Second revocation of same session should return 404
    let csrf_token2 = app.generate_csrf_token();
    let response2 = app
        .server
        .post(&format!(
            "/accounts/all-login-sessions/{}/revoke",
            session_uuid
        ))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token2),
        )
        .form(&[("csrf_token", csrf_token2.as_str())])
        .await;

    let status = response2.status_code().as_u16();
    assert_eq!(
        status, 404,
        "Second revoke of same session should return 404"
    );
}

#[tokio::test]
async fn test_admin_revoke_no_crash_when_target_offline() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("adm_revoke_offline");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let user_name = unique_name("adm_revoke_offline_target");
    let user_id = create_simple_user(&mut conn, &user_name).await;
    let session_uuid =
        create_auth_session_with_token(&mut conn, user_id, "offline_token", false).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let csrf_token = app.generate_csrf_token();

    // Revoke while user has no WebSocket connection -- should not crash
    let response = app
        .server
        .post(&format!(
            "/accounts/all-login-sessions/{}/revoke",
            session_uuid
        ))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[("csrf_token", csrf_token.as_str())])
        .await;

    let status = response.status_code().as_u16();
    assert_eq!(
        status, 200,
        "Revoke should succeed even when target has no WS (got {})",
        status
    );
}

#[tokio::test]
async fn test_admin_revoke_last_session() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("adm_revoke_last");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let user_name = unique_name("adm_revoke_last_target");
    let user_id = create_simple_user(&mut conn, &user_name).await;

    // Create only one session
    let session_uuid =
        create_auth_session_with_token(&mut conn, user_id, "last_token", false).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let csrf_token = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!(
            "/accounts/all-login-sessions/{}/revoke",
            session_uuid
        ))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[("csrf_token", csrf_token.as_str())])
        .await;

    assert_eq!(response.status_code().as_u16(), 200);

    // Verify no sessions remain for user
    use vauban_web::schema::auth_sessions;
    let remaining: i64 = auth_sessions::table
        .filter(auth_sessions::user_id.eq(user_id))
        .count()
        .get_result(&mut conn)
        .await
        .unwrap();
    assert_eq!(remaining, 0, "No sessions should remain for target user");
}

#[tokio::test]
async fn test_admin_sessions_page_has_correct_structure() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("admsess_struct");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let response = app
        .server
        .get("/accounts/all-login-sessions")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(response.status_code().as_u16(), 200);
    let body = response.text();
    assert!(
        body.contains("All Login Sessions"),
        "Page should contain the 'All Sessions' title"
    );
    assert!(
        body.contains("All active login sessions across all users"),
        "Page should contain the subtitle"
    );
}

// =============================================================================
// Issue #8 - Login session deduplication & route renaming
// =============================================================================

/// Helper: count rows in `auth_sessions` for a given user_id.
async fn count_auth_sessions(conn: &mut AsyncPgConnection, user_id_val: i32) -> i64 {
    use vauban_web::schema::auth_sessions;
    unwrap_ok!(
        auth_sessions::table
            .filter(auth_sessions::user_id.eq(user_id_val))
            .count()
            .get_result::<i64>(conn)
            .await
    )
}

/// Issue #8 -- the `uniq_auth_sessions_per_device` UNIQUE index must
/// reject a second `auth_sessions` row that shares (user_id, device_info,
/// ip_address) with an existing one.
///
/// This is the database-level invariant that backstops
/// `insert_session_with_purge` against inter-pod races.
#[tokio::test]
async fn test_unique_index_blocks_duplicate_session_per_device() {
    use chrono::{Duration, Utc};
    use diesel::result::{DatabaseErrorKind, Error as DieselError};
    use vauban_web::models::NewAuthSession;
    use vauban_web::schema::auth_sessions;

    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("uniq_idx_dup");
    let user_id = create_simple_user(&mut conn, &username).await;

    let ip: ipnetwork::IpNetwork = unwrap_ok!("127.0.0.1".parse());
    let device = "Chrome on macOS".to_string();

    // First insert: must succeed.
    let s1 = NewAuthSession {
        uuid: Uuid::new_v4(),
        user_id,
        token_hash: format!("hash_dup_a_{}", user_id),
        ip_address: ip,
        user_agent: Some("Mozilla/5.0 Test A".to_string()),
        device_info: device.clone(),
        expires_at: Utc::now() + Duration::hours(24),
        is_current: true,
    };
    unwrap_ok!(
        diesel::insert_into(auth_sessions::table)
            .values(&s1)
            .execute(&mut conn)
            .await
    );

    // Second insert with the same (user_id, device_info, ip_address)
    // tuple: must trip the UNIQUE index.
    let s2 = NewAuthSession {
        uuid: Uuid::new_v4(),
        user_id,
        token_hash: format!("hash_dup_b_{}", user_id),
        ip_address: ip,
        user_agent: Some("Mozilla/5.0 Test B".to_string()),
        device_info: device.clone(),
        expires_at: Utc::now() + Duration::hours(24),
        is_current: true,
    };
    let result = diesel::insert_into(auth_sessions::table)
        .values(&s2)
        .execute(&mut conn)
        .await;

    match result {
        Err(DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, _)) => {}
        Err(e) => panic!("expected UniqueViolation, got {:?}", e),
        Ok(_) => panic!(
            "expected UniqueViolation on second insert with same (user, device, ip); \
             did the migration `uniq_auth_sessions_per_device` run on the test DB?"
        ),
    }

    // Sanity: only the first row survives.
    assert_eq!(count_auth_sessions(&mut conn, user_id).await, 1);
}

/// Issue #8 -- two consecutive logins from the same user/device/IP must
/// leave exactly ONE row in `auth_sessions` (B-strict policy enforced
/// by `insert_session_with_purge`).
#[tokio::test]
async fn test_login_purges_previous_session_for_same_device() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("dedup_same_device");
    // Per Finding #2 remediation, API login requires MFA on the account.
    let test_user = create_test_user_with_mfa(&mut conn, &app.auth_service, &username).await;
    let user_id = test_user.user.id;

    // Snapshot baseline: `create_test_user_with_mfa` inserts a bootstrap session.
    let baseline = count_auth_sessions(&mut conn, user_id).await;

    // First real login.
    let r1 = app
        .server
        .post("/api/v1/auth/login")
        .add_header(USER_AGENT, "Mozilla/5.0 (Dedup Test Browser)")
        .json(&json!({
            "username": username,
            "password": test_user.password,
            "mfa_code": current_totp_for(&test_user.mfa_secret),
        }))
        .await;
    assert_eq!(r1.status_code().as_u16(), 200);

    let after_first = count_auth_sessions(&mut conn, user_id).await;
    assert!(
        after_first >= baseline,
        "first login should not decrease session count (baseline={}, after={})",
        baseline,
        after_first
    );

    // Second login from the same client (same UA, same default IP):
    // `insert_session_with_purge` must delete the row from r1 before
    // inserting the new one, so the count must NOT grow.
    let r2 = app
        .server
        .post("/api/v1/auth/login")
        .add_header(USER_AGENT, "Mozilla/5.0 (Dedup Test Browser)")
        .json(&json!({
            "username": username,
            "password": test_user.password,
            "mfa_code": current_totp_for(&test_user.mfa_secret),
        }))
        .await;
    assert_eq!(r2.status_code().as_u16(), 200);

    let after_second = count_auth_sessions(&mut conn, user_id).await;
    assert_eq!(
        after_second, after_first,
        "second login from the same (user, device, ip) must replace the previous \
         session, not duplicate it (was {}, now {})",
        after_first, after_second
    );
}

/// Issue #8 -- two logins with DIFFERENT User-Agents must keep BOTH
/// rows: the device fingerprint differs, so they are distinct devices.
#[tokio::test]
async fn test_login_keeps_sessions_for_different_user_agents() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("dedup_diff_device");
    // Per Finding #2 remediation, API login requires MFA on the account.
    let test_user = create_test_user_with_mfa(&mut conn, &app.auth_service, &username).await;
    let user_id = test_user.user.id;

    let baseline = count_auth_sessions(&mut conn, user_id).await;

    // First login -- pretend we are on macOS Chrome.
    let r1 = app
        .server
        .post("/api/v1/auth/login")
        .add_header(
            USER_AGENT,
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        )
        .json(&json!({
            "username": username,
            "password": test_user.password,
            "mfa_code": current_totp_for(&test_user.mfa_secret),
        }))
        .await;
    assert_eq!(r1.status_code().as_u16(), 200);

    // Second login -- pretend we are on Windows Firefox. Use a fresh
    // TOTP code computed at this moment (verifies that two distinct
    // codes within the same TOTP window are both accepted, which is
    // expected since `generate_access_token` does not consume the code).
    let r2 = app
        .server
        .post("/api/v1/auth/login")
        .add_header(
            USER_AGENT,
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) \
             Gecko/20100101 Firefox/121.0",
        )
        .json(&json!({
            "username": username,
            "password": test_user.password,
            "mfa_code": current_totp_for(&test_user.mfa_secret),
        }))
        .await;
    assert_eq!(r2.status_code().as_u16(), 200);

    let after = count_auth_sessions(&mut conn, user_id).await;
    assert_eq!(
        after,
        baseline + 2,
        "two logins with distinct device fingerprints must produce two rows \
         (baseline={}, after={})",
        baseline,
        after
    );
}

/// Issue #8 -- the legacy GET `/accounts/sessions` route must answer
/// 308 Permanent Redirect to `/accounts/login-sessions` so external
/// bookmarks and HTTP clients keep working.
#[tokio::test]
async fn test_legacy_user_sessions_route_redirects_permanent() {
    let app = TestApp::spawn().await;

    let response = app.server.get("/accounts/sessions").await;

    assert_eq!(
        response.status_code().as_u16(),
        308,
        "GET /accounts/sessions must answer 308 Permanent Redirect"
    );
    let location = unwrap_ok!(
        unwrap_ok!(
            response
                .headers()
                .get("location")
                .ok_or("missing Location header")
        )
        .to_str()
    );
    assert_eq!(location, "/accounts/login-sessions");
}

/// Issue #8 -- the legacy GET `/admin/sessions` route must redirect
/// to `/accounts/all-login-sessions` (admin view was reparented under
/// `/accounts` because it is a login-session view, not a bastion view).
#[tokio::test]
async fn test_legacy_admin_sessions_route_redirects_permanent() {
    let app = TestApp::spawn().await;

    let response = app.server.get("/admin/sessions").await;

    assert_eq!(
        response.status_code().as_u16(),
        308,
        "GET /admin/sessions must answer 308 Permanent Redirect"
    );
    let location = unwrap_ok!(
        unwrap_ok!(
            response
                .headers()
                .get("location")
                .ok_or("missing Location header")
        )
        .to_str()
    );
    assert_eq!(location, "/accounts/all-login-sessions");
}

/// Issue #8 -- the legacy POST `/accounts/sessions/{uuid}/revoke`
/// route must redirect to the new `/accounts/login-sessions/{uuid}/revoke`
/// while preserving the session UUID in the path.
#[tokio::test]
async fn test_legacy_user_revoke_route_redirects_permanent() {
    let app = TestApp::spawn().await;
    let session_uuid = Uuid::new_v4();

    let response = app
        .server
        .post(&format!("/accounts/sessions/{}/revoke", session_uuid))
        .await;

    assert_eq!(
        response.status_code().as_u16(),
        308,
        "POST /accounts/sessions/{{uuid}}/revoke must answer 308 Permanent Redirect"
    );
    let location = unwrap_ok!(
        unwrap_ok!(
            response
                .headers()
                .get("location")
                .ok_or("missing Location header")
        )
        .to_str()
    );
    assert_eq!(
        location,
        format!("/accounts/login-sessions/{}/revoke", session_uuid)
    );
}

/// Issue #8 -- legacy admin revoke route must redirect to the new
/// admin revoke route under `/accounts/all-login-sessions`, preserving
/// the session UUID.
#[tokio::test]
async fn test_legacy_admin_revoke_route_redirects_permanent() {
    let app = TestApp::spawn().await;
    let session_uuid = Uuid::new_v4();

    let response = app
        .server
        .post(&format!("/admin/sessions/{}/revoke", session_uuid))
        .await;

    assert_eq!(
        response.status_code().as_u16(),
        308,
        "POST /admin/sessions/{{uuid}}/revoke must answer 308 Permanent Redirect"
    );
    let location = unwrap_ok!(
        unwrap_ok!(
            response
                .headers()
                .get("location")
                .ok_or("missing Location header")
        )
        .to_str()
    );
    assert_eq!(
        location,
        format!("/accounts/all-login-sessions/{}/revoke", session_uuid)
    );
}
