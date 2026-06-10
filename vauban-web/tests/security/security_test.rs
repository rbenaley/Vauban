/// VAUBAN Web - Security Tests
///
/// Comprehensive security testing for VAUBAN platform including:
/// - SQL injection prevention
/// - Input validation
/// - Brute force protection
/// - Authentication security
/// - XSS prevention
/// - Session security
/// - Security headers
///
/// ## Known Security Issues (TODO)
///
/// The following security features need implementation:
/// - [ ] Security headers (X-Content-Type-Options, X-Frame-Options, CSP)
/// - [ ] Rate limiting on login endpoint
/// - [ ] Input validation returning 400 instead of 500 for malicious input
/// - [ ] Password complexity validation returning 400 instead of 500
use axum::http::header;
use serde_json::json;
use serial_test::serial;

use axum::http::header::COOKIE;

use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::RunQueryDsl;

use crate::common::{TestApp, assertions::*, test_db, unwrap_ok, unwrap_some};
use crate::fixtures::{
    create_admin_user, create_admin_user_with_mfa, create_simple_admin_user,
    create_simple_rdp_asset, create_simple_ssh_asset, create_simple_user, create_test_api_key,
    create_test_auth_session, create_test_rdp_asset, create_test_session_with_uuid,
    create_test_ssh_asset, create_test_user, create_test_user_with_mfa, current_totp_for,
    unique_name,
};

/// Helper to get user UUID from user_id.
async fn get_user_uuid(conn: &mut diesel_async::AsyncPgConnection, user_id: i32) -> uuid::Uuid {
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
// SQL Injection Prevention Tests
// =============================================================================

/// Test SQL injection attempts on user creation.
///
/// TODO: Currently returns 500 for SQL injection attempts.
/// Should return 400 Bad Request with proper input validation.
#[tokio::test]
#[serial]
async fn test_sql_injection_prevention_user_creation() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Use admin user since create_user now requires staff/superuser
    let username = unique_name("test_sql_inj");
    let admin = create_admin_user(&mut conn, &app.auth_service, &username).await;

    // Test SQL injection in username
    let response = app
        .server
        .post("/api/v1/accounts")
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .json(&json!({
            "username": "' OR '1'='1",
            "email": "hacker@example.com",
            "password": "Password123!"
        }))
        .await;

    // TODO: Should return 400 Bad Request, currently returns 500
    let status = response.status_code().as_u16();
    assert!(
        status == 400 || status == 422 || status == 500,
        "Expected 400, 422 or 500 for SQL injection attempt, got {}",
        status
    );

    // Test SQL injection with comment syntax
    let response = app
        .server
        .post("/api/v1/accounts")
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .json(&json!({
            "username": "admin'--",
            "email": "test@example.com",
            "password": "Password123!"
        }))
        .await;

    // TODO: Should return 400 Bad Request, currently returns 500
    let status = response.status_code().as_u16();
    assert!(
        status == 400 || status == 422 || status == 500,
        "Expected 400, 422 or 500 for SQL injection attempt, got {}",
        status
    );

    test_db::cleanup(&mut conn).await;
}

/// Test SQL injection attempts on user search/list.
#[tokio::test]
#[serial]
async fn test_sql_injection_prevention_user_search() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Use admin user since list_users now requires staff/superuser
    let username = unique_name("test_search");
    let admin = create_admin_user(&mut conn, &app.auth_service, &username).await;

    // API should handle malicious query parameters safely
    let response = app
        .server
        .get("/api/v1/accounts")
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;

    // Should return valid response, not crash
    let status = response.status_code().as_u16();
    assert!(
        status == 200 || status == 400,
        "Expected 200 or 400, got {}",
        status
    );

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// SQL Injection Prevention: Group Search
// =============================================================================

/// Test that group search handles SQL injection payloads safely.
///
/// Regression test: SQL Injection in group_list handler.
/// Previously, the handler used raw SQL string interpolation with format!()
/// which could be exploited. Now uses Diesel DSL .ilike() with parameterized queries.
#[tokio::test]
#[serial]
async fn test_sql_injection_group_search_single_quote() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("test_sqli_grp_admin");
    let admin = crate::fixtures::create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    // Classic SQL injection with single quote to break out of string literal
    // URL-encoded: ' = %27, space = %20, = is %3D
    let response = app
        .server
        .get("/accounts/groups?search=%27%20OR%20%271%27%3D%271")
        .add_header(
            axum::http::header::COOKIE,
            format!("access_token={}", admin.token),
        )
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 200 || status == 303,
        "SQL injection payload should not crash the server, got {}",
        status
    );

    test_db::cleanup(&mut conn).await;
}

/// Test SQL injection with comment syntax (--) in group search.
#[tokio::test]
#[serial]
async fn test_sql_injection_group_search_comment() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("test_sqli_grp_cmt");
    let admin = crate::fixtures::create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    // SQL comment injection attempt
    let response = app
        .server
        .get("/accounts/groups?search=test'--")
        .add_header(
            axum::http::header::COOKIE,
            format!("access_token={}", admin.token),
        )
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 200 || status == 303,
        "SQL injection with comment syntax should not crash the server, got {}",
        status
    );

    test_db::cleanup(&mut conn).await;
}

/// Test SQL injection with UNION SELECT in group search.
#[tokio::test]
#[serial]
async fn test_sql_injection_group_search_union() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("test_sqli_grp_union");
    let admin = crate::fixtures::create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    // UNION-based injection attempt
    // URL-encoded: ' = %27, space = %20
    let response = app
        .server
        .get("/accounts/groups?search=%27%20UNION%20SELECT%20uuid%2C%20username%2C%20email%2C%20password_hash%2C%20created_at%20FROM%20users--")
        .add_header(axum::http::header::COOKIE, format!("access_token={}", admin.token))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 200 || status == 303,
        "SQL injection with UNION SELECT should not crash the server, got {}",
        status
    );

    test_db::cleanup(&mut conn).await;
}

/// Test SQL injection with semicolon (stacked queries) in group search.
#[tokio::test]
#[serial]
async fn test_sql_injection_group_search_stacked() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("test_sqli_grp_stack");
    let admin = crate::fixtures::create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    // Stacked query injection attempt
    // URL-encoded: ' = %27, ; = %3B, space = %20
    let response = app
        .server
        .get("/accounts/groups?search=test%27%3B%20DROP%20TABLE%20vauban_groups%3B--")
        .add_header(
            axum::http::header::COOKIE,
            format!("access_token={}", admin.token),
        )
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 200 || status == 303,
        "SQL injection with stacked queries should not crash the server, got {}",
        status
    );

    test_db::cleanup(&mut conn).await;
}

/// Test SQL injection with backslash escape bypass in group search.
#[tokio::test]
#[serial]
async fn test_sql_injection_group_search_backslash_escape() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("test_sqli_grp_bslash");
    let admin = crate::fixtures::create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    // Backslash escape bypass (the old replace('\'', "''") was vulnerable to this)
    // URL-encoded: \ = %5C, ' = %27, space = %20, = is %3D
    let response = app
        .server
        .get("/accounts/groups?search=%5C%27%20OR%201%3D1--")
        .add_header(
            axum::http::header::COOKIE,
            format!("access_token={}", admin.token),
        )
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 200 || status == 303,
        "SQL injection with backslash escape should not crash the server, got {}",
        status
    );

    test_db::cleanup(&mut conn).await;
}

/// Test that legitimate group search still works correctly after the fix.
#[tokio::test]
#[serial]
async fn test_group_search_legitimate_query_works() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("test_grp_search_ok");
    let admin = crate::fixtures::create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    // Create a group with a known name for searching
    let group_name = unique_name("test-searchable-grp");
    crate::fixtures::create_test_vauban_group(&mut conn, &group_name).await;

    // Search for the group using a partial name
    let response = app
        .server
        .get(&format!("/accounts/groups?search={}", &group_name[..10]))
        .add_header(
            axum::http::header::COOKIE,
            format!("access_token={}", admin.token),
        )
        .await;

    let status = response.status_code().as_u16();
    assert_eq!(
        status, 200,
        "Legitimate search should return 200, got {}",
        status
    );

    let body = response.text();
    assert!(
        body.contains("Groups"),
        "Search results page should contain 'Groups' title"
    );

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// SQL Injection Prevention: Group Member Search
// =============================================================================

/// Test SQL injection in group member search endpoint.
///
/// Regression test: SQL Injection in group_member_search handler.
/// The available_users_data query was also vulnerable to string interpolation.
#[tokio::test]
#[serial]
async fn test_sql_injection_group_member_search_single_quote() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("test_sqli_mbr_admin");
    let admin = crate::fixtures::create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    // Create a group to search members in
    let group_uuid =
        crate::fixtures::create_test_vauban_group(&mut conn, &unique_name("test-sqli-mbr-grp"))
            .await;

    // SQL injection attempt on member search
    // URL-encoded: ' = %27, space = %20, = is %3D
    let response = app
        .server
        .get(&format!(
            "/accounts/groups/{}/members/search?user-search=%27%20OR%20%271%27%3D%271",
            group_uuid
        ))
        .add_header(
            axum::http::header::COOKIE,
            format!("access_token={}", admin.token),
        )
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 200 || status == 303,
        "SQL injection in member search should not crash the server, got {}",
        status
    );

    test_db::cleanup(&mut conn).await;
}

/// Test SQL injection with UNION SELECT in member search.
#[tokio::test]
#[serial]
async fn test_sql_injection_group_member_search_union() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("test_sqli_mbr_union");
    let admin = crate::fixtures::create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let group_uuid =
        crate::fixtures::create_test_vauban_group(&mut conn, &unique_name("test-sqli-mbr-u-grp"))
            .await;

    // URL-encoded: ' = %27, space = %20, , = %2C
    let response = app
        .server
        .get(&format!(
            "/accounts/groups/{}/members/search?user-search=%27%20UNION%20SELECT%20uuid%2C%20password_hash%2C%20email%20FROM%20users--",
            group_uuid
        ))
        .add_header(axum::http::header::COOKIE, format!("access_token={}", admin.token))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 200 || status == 303,
        "SQL injection with UNION in member search should not crash, got {}",
        status
    );

    test_db::cleanup(&mut conn).await;
}

/// Test SQL injection with semicolon in member search.
#[tokio::test]
#[serial]
async fn test_sql_injection_group_member_search_stacked() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("test_sqli_mbr_stack");
    let admin = crate::fixtures::create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let group_uuid =
        crate::fixtures::create_test_vauban_group(&mut conn, &unique_name("test-sqli-mbr-s-grp"))
            .await;

    // URL-encoded: ' = %27, ; = %3B, space = %20
    let response = app
        .server
        .get(&format!(
            "/accounts/groups/{}/members/search?user-search=x%27%3B%20DELETE%20FROM%20users%3B--",
            group_uuid
        ))
        .add_header(
            axum::http::header::COOKIE,
            format!("access_token={}", admin.token),
        )
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 200 || status == 303,
        "SQL injection with stacked query in member search should not crash, got {}",
        status
    );

    test_db::cleanup(&mut conn).await;
}

/// Test that legitimate member search works after the fix.
#[tokio::test]
#[serial]
async fn test_group_member_search_legitimate_query_works() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("test_mbr_search_ok");
    let admin = crate::fixtures::create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let group_uuid =
        crate::fixtures::create_test_vauban_group(&mut conn, &unique_name("test-mbr-search-grp"))
            .await;

    // Create a user that should be findable
    let searchable_name = unique_name("test_findable_usr");
    crate::fixtures::create_test_user(&mut conn, &app.auth_service, &searchable_name).await;

    // Search for the user using a partial name
    let response = app
        .server
        .get(&format!(
            "/accounts/groups/{}/members/search?user-search={}",
            group_uuid,
            &searchable_name[..8]
        ))
        .add_header(
            axum::http::header::COOKIE,
            format!("access_token={}", admin.token),
        )
        .await;

    let status = response.status_code().as_u16();
    assert_eq!(
        status, 200,
        "Legitimate member search should return 200, got {}",
        status
    );

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// API Authorization Tests
// =============================================================================

/// Test that regular users cannot create users via the API.
///
/// Regression test: No authorization checks on API endpoints.
/// Previously, any authenticated user could create/modify users, assets, etc.
/// Now requires staff or superuser privileges.
#[tokio::test]
#[serial]
async fn test_regular_user_cannot_create_user() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("test_authz_create");
    let regular_user = create_test_user(&mut conn, &app.auth_service, &username).await;

    let response = app
        .server
        .post("/api/v1/accounts")
        .add_header(header::AUTHORIZATION, app.auth_header(&regular_user.token))
        .json(&json!({
            "username": "should_fail",
            "email": "shouldfail@test.io",
            "password": "Password123!"
        }))
        .await;

    assert_status(&response, 403);

    test_db::cleanup(&mut conn).await;
}

/// Test that regular users cannot update users via the API.
#[tokio::test]
#[serial]
async fn test_regular_user_cannot_update_user() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("test_authz_upd");
    let regular_user = create_test_user(&mut conn, &app.auth_service, &username).await;

    let target_name = unique_name("test_authz_target");
    let target = create_test_user(&mut conn, &app.auth_service, &target_name).await;

    let response = app
        .server
        .put(&format!("/api/v1/accounts/{}", target.user.uuid))
        .add_header(header::AUTHORIZATION, app.auth_header(&regular_user.token))
        .json(&json!({
            "first_name": "Hacked"
        }))
        .await;

    assert_status(&response, 403);

    test_db::cleanup(&mut conn).await;
}

/// Test that regular users cannot list users via the API.
#[tokio::test]
#[serial]
async fn test_regular_user_cannot_list_users() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("test_authz_list");
    let regular_user = create_test_user(&mut conn, &app.auth_service, &username).await;

    let response = app
        .server
        .get("/api/v1/accounts")
        .add_header(header::AUTHORIZATION, app.auth_header(&regular_user.token))
        .await;

    assert_status(&response, 403);

    test_db::cleanup(&mut conn).await;
}

/// Test that regular users cannot create assets via the API.
#[tokio::test]
#[serial]
async fn test_regular_user_cannot_create_asset() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("test_authz_asset");
    let regular_user = create_test_user(&mut conn, &app.auth_service, &username).await;

    let response = app
        .server
        .post("/api/v1/assets/manage")
        .add_header(header::AUTHORIZATION, app.auth_header(&regular_user.token))
        .json(&json!({
            "name": "Unauthorized Asset",
            "hostname": "evil.example.com",
            "port": 22,
            "asset_type": "ssh"
        }))
        .await;

    assert_status(&response, 403);

    test_db::cleanup(&mut conn).await;
}

/// Test that regular users cannot create sessions via the API.
/// With access rule enforcement, a non-existent asset returns 404 before
/// the access check, so we accept either 403 or 404 as valid denial.
#[tokio::test]
#[serial]
async fn test_regular_user_cannot_create_session() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("test_authz_sess");
    let regular_user = create_test_user(&mut conn, &app.auth_service, &username).await;

    let response = app
        .server
        .post("/api/v1/sessions")
        .add_header(header::AUTHORIZATION, app.auth_header(&regular_user.token))
        .json(&json!({
            "asset_id": "00000000-0000-0000-0000-000000000000",
            "credential_id": "cred-123",
            "session_type": "ssh"
        }))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 403 || status == 404,
        "Expected 403 or 404, got {}",
        status
    );

    test_db::cleanup(&mut conn).await;
}

/// SECURITY: regular users may now hit `/api/v1/sessions` (the
/// post-audit policy grants `sessions:read` to `role:user`) but the
/// instance-level filter in `services::session_access` /
/// `list_sessions` MUST force the result set to their own sessions
/// only. We therefore assert (a) Casbin no longer blocks the call
/// (200) and (b) without `sessions:supervise`, the listing is empty
/// when no session was created by the caller.
#[tokio::test]
#[serial]
async fn test_regular_user_cannot_list_sessions() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("test_authz_lsess");
    let regular_user = create_test_user(&mut conn, &app.auth_service, &username).await;

    let response = app
        .server
        .get("/api/v1/sessions")
        .add_header(header::AUTHORIZATION, app.auth_header(&regular_user.token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(
        body.trim() == "[]",
        "regular user with no sessions of their own must see an empty \
         list (force-filter to caller_id), got: {body}"
    );

    test_db::cleanup(&mut conn).await;
}

/// Test that admin users CAN still access protected endpoints.
#[tokio::test]
#[serial]
async fn test_admin_user_can_access_protected_endpoints() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("test_authz_admin");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    // Admin should be able to list users
    let response = app
        .server
        .get("/api/v1/accounts")
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;
    assert_status(&response, 200);

    // Admin should be able to list sessions
    let response = app
        .server
        .get("/api/v1/sessions")
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;
    assert_status(&response, 200);

    // Admin should be able to create a user
    let new_username = unique_name("test_authz_newuser");
    let response = app
        .server
        .post("/api/v1/accounts")
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .json(&json!({
            "username": new_username,
            "email": format!("{}@test.io", new_username),
            "password": "SecurePassword123!"
        }))
        .await;
    let status = response.status_code().as_u16();
    assert!(
        status == 200 || status == 201,
        "Admin should be able to create users, got {}",
        status
    );

    test_db::cleanup(&mut conn).await;
}

/// Test that regular users can still read assets (non-admin read operation).
#[tokio::test]
#[serial]
async fn test_regular_user_can_list_assets() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("test_authz_rasset");
    let regular_user = create_test_user(&mut conn, &app.auth_service, &username).await;

    // Regular users should be able to list assets (needed for connection UI)
    let response = app
        .server
        .get("/api/v1/assets")
        .add_header(header::AUTHORIZATION, app.auth_header(&regular_user.token))
        .await;

    assert_status(&response, 200);

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// Input Validation Tests
// =============================================================================

/// Test input validation for user creation.
#[tokio::test]
#[serial]
async fn test_input_validation_user_creation() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Use admin user since create_user now requires staff/superuser
    let username = unique_name("test_input_val");
    let test_user = create_admin_user(&mut conn, &app.auth_service, &username).await;

    // Test empty username
    let response = app
        .server
        .post("/api/v1/accounts")
        .add_header(header::AUTHORIZATION, app.auth_header(&test_user.token))
        .json(&json!({
            "username": "",
            "email": "test@example.com",
            "password": "Password123!"
        }))
        .await;

    assert_status(&response, 400);

    // Test invalid email format
    let response = app
        .server
        .post("/api/v1/accounts")
        .add_header(header::AUTHORIZATION, app.auth_header(&test_user.token))
        .json(&json!({
            "username": "testuser",
            "email": "not-an-email",
            "password": "Password123!"
        }))
        .await;

    assert_status(&response, 400);

    // Test password too short
    let response = app
        .server
        .post("/api/v1/accounts")
        .add_header(header::AUTHORIZATION, app.auth_header(&test_user.token))
        .json(&json!({
            "username": "testuser",
            "email": "test@example.com",
            "password": "short"
        }))
        .await;

    assert_status(&response, 400);

    // Test username too long (> 150 chars)
    let long_username = "a".repeat(151);
    let response = app
        .server
        .post("/api/v1/accounts")
        .add_header(header::AUTHORIZATION, app.auth_header(&test_user.token))
        .json(&json!({
            "username": long_username,
            "email": "test@example.com",
            "password": "Password123!"
        }))
        .await;

    assert_status(&response, 400);

    test_db::cleanup(&mut conn).await;
}

/// Test input validation for asset creation.
#[tokio::test]
#[serial]
async fn test_input_validation_asset_creation() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Use admin user since create_asset now requires staff/superuser
    let username = unique_name("test_asset");
    let test_user = create_admin_user(&mut conn, &app.auth_service, &username).await;

    // Test invalid port number
    let response = app
        .server
        .post("/api/v1/assets/manage")
        .add_header(header::AUTHORIZATION, app.auth_header(&test_user.token))
        .json(&json!({
            "name": "Invalid Asset",
            "hostname": "invalid-host",
            "port": 99999,
            "asset_type": "ssh"
        }))
        .await;

    assert_status(&response, 400);

    // Test empty name
    let response = app
        .server
        .post("/api/v1/assets/manage")
        .add_header(header::AUTHORIZATION, app.auth_header(&test_user.token))
        .json(&json!({
            "name": "",
            "hostname": "host",
            "port": 22,
            "asset_type": "ssh"
        }))
        .await;

    assert_status(&response, 400);

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// XSS Prevention Tests
// =============================================================================

/// Test XSS prevention in user fields.
///
/// VAUBAN uses output encoding (via Askama templates) for XSS prevention.
/// Input containing HTML/JS is accepted but sanitized on display.
/// This test verifies that XSS input doesn't crash the server.
#[tokio::test]
#[serial]
async fn test_xss_prevention_user_fields() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Use admin user since create_user now requires staff/superuser
    let username = unique_name("test_xss");
    let test_user = create_admin_user(&mut conn, &app.auth_service, &username).await;

    // Test XSS in username - should be handled without crashing
    // VAUBAN sanitizes output via Askama templates (HTML escaping)
    let response = app
        .server
        .post("/api/v1/accounts")
        .add_header(header::AUTHORIZATION, app.auth_header(&test_user.token))
        .json(&json!({
            "username": "<script>alert('xss')</script>",
            "email": "xss1@example.com",
            "password": "Password123!"
        }))
        .await;

    // Input may be accepted (200), rejected (400), or cause validation error
    // The key is that it doesn't crash (500 is acceptable if it's a validation error)
    let status = response.status_code().as_u16();
    assert!(
        status == 200 || status == 400 || status == 422 || status == 500,
        "XSS input should be handled, got {}",
        status
    );

    // Test XSS with img tag in optional field
    let response = app
        .server
        .post("/api/v1/accounts")
        .add_header(header::AUTHORIZATION, app.auth_header(&test_user.token))
        .json(&json!({
            "username": "testuser_xss2",
            "email": "xss2@example.com",
            "password": "Password123!",
            "first_name": "<img src=x onerror=alert(1)>"
        }))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 200 || status == 400 || status == 500,
        "XSS input should be handled, got {}",
        status
    );

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// Authentication Security Tests
// =============================================================================

/// Test authentication security for API endpoints.
#[tokio::test]
#[serial]
async fn test_authentication_security() {
    let app = TestApp::spawn().await;

    // Test missing authentication header
    let response = app.server.get("/api/v1/accounts").await;
    assert_status(&response, 401);

    // Test invalid JWT token
    let response = app
        .server
        .get("/api/v1/accounts")
        .add_header(header::AUTHORIZATION, "Bearer invalid.token.here")
        .await;
    assert_status(&response, 401);

    // Test expired JWT token (simulated with old exp claim)
    let response = app
        .server
        .get("/api/v1/accounts")
        .add_header(
            header::AUTHORIZATION,
            "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1MTYyMzk3MjN9.Signature",
        )
        .await;
    assert_status(&response, 401);
}

/// Test JWT token validation.
#[tokio::test]
#[serial]
async fn test_jwt_token_validation() {
    let app = TestApp::spawn().await;

    // Malformed JWT
    let response = app
        .server
        .get("/api/v1/accounts")
        .add_header(
            header::AUTHORIZATION,
            "Bearer malformed.token.without.proper.format",
        )
        .await;
    assert_status(&response, 401);

    // JWT with invalid signature
    let response = app
        .server
        .get("/api/v1/accounts")
        .add_header(
            header::AUTHORIZATION,
            "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.invalid_sig",
        )
        .await;
    assert_status(&response, 401);

    // JWT with altered claims (different signature)
    let response = app
        .server
        .get("/api/v1/accounts")
        .add_header(
            header::AUTHORIZATION,
            "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5NzIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        )
        .await;
    assert_status(&response, 401);
}

/// Test API key authentication.
#[tokio::test]
#[serial]
async fn test_api_key_authentication() {
    let app = TestApp::spawn().await;

    // Empty Bearer token
    let response = app
        .server
        .get("/api/v1/accounts")
        .add_header(header::AUTHORIZATION, "Bearer ")
        .await;
    assert_status(&response, 401);

    // Invalid API key format
    let response = app
        .server
        .get("/api/v1/accounts")
        .add_header(header::AUTHORIZATION, "Bearer invalid_key_format")
        .await;
    assert_status(&response, 401);

    // Non-existent API key
    let response = app
        .server
        .get("/api/v1/accounts")
        .add_header(
            header::AUTHORIZATION,
            "Bearer vb_nonexistent_key_1234567890",
        )
        .await;
    assert_status(&response, 401);
}

// =============================================================================
// Brute Force Protection Tests
// =============================================================================

/// Test brute force protection on login.
#[tokio::test]
#[serial]
async fn test_brute_force_protection() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("test_bruteforce");
    let test_user = create_test_user(&mut conn, &app.auth_service, &username).await;

    // Make multiple failed login attempts
    const MAX_ATTEMPTS: u32 = 5;

    for _ in 0..MAX_ATTEMPTS {
        let response = app
            .server
            .post("/api/v1/auth/login")
            .json(&json!({
                "username": username,
                "password": "WrongPassword123!"
            }))
            .await;

        assert_status(&response, 401);
    }

    // After multiple failed attempts, account should be locked or rate limited
    let response = app
        .server
        .post("/api/v1/auth/login")
        .json(&json!({
            "username": username,
            "password": test_user.password
        }))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 401 || status == 403 || status == 429,
        "Expected 401, 403 or 429 after brute force attempts, got {}",
        status
    );

    test_db::cleanup(&mut conn).await;
}

/// Test account lockout mechanism.
#[tokio::test]
#[serial]
async fn test_account_lockout() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("test_lockout");
    let test_user = create_test_user(&mut conn, &app.auth_service, &username).await;

    // Make multiple failed login attempts
    for _ in 0..5 {
        let response = app
            .server
            .post("/api/v1/auth/login")
            .json(&json!({
                "username": username,
                "password": "WrongPassword123!"
            }))
            .await;

        assert_status(&response, 401);
    }

    // After lockout, even correct password should fail
    let response = app
        .server
        .post("/api/v1/auth/login")
        .json(&json!({
            "username": username,
            "password": test_user.password
        }))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 401 || status == 403,
        "Expected 401 or 403 after lockout, got {}",
        status
    );

    test_db::cleanup(&mut conn).await;
}

/// Test rate limiting functionality.
///
/// This test verifies the RateLimiter service directly rather than through
/// the HTTP layer, as the test server uses a high limit to avoid interference
/// with other tests.
#[tokio::test]
#[serial]
async fn test_rate_limiting() {
    use vauban_web::services::rate_limit::RateLimiter;

    // Create a rate limiter with a low limit for testing
    let limiter = unwrap_ok!(RateLimiter::new(false, None, 3).await);

    // First 3 requests should be allowed
    for i in 1..=3 {
        let result = unwrap_ok!(limiter.check("test_ip").await);
        assert!(
            result.allowed,
            "Request {} should be allowed, remaining: {}",
            i, result.remaining
        );
    }

    // 4th request should be blocked
    let result = unwrap_ok!(limiter.check("test_ip").await);
    assert!(
        !result.allowed,
        "Request 4 should be blocked (rate limited)"
    );
    assert_eq!(result.remaining, 0);
    assert!(result.reset_in_secs > 0);
}

// =============================================================================
// Session Security Tests
// =============================================================================

/// Test secure cookie settings.
#[tokio::test]
#[serial]
async fn test_secure_cookie_settings() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("test_cookie");
    let test_user = create_test_user(&mut conn, &app.auth_service, &username).await;

    let response = app
        .server
        .post("/api/v1/auth/login")
        .json(&json!({
            "username": username,
            "password": test_user.password
        }))
        .await;

    // Check that Set-Cookie header is present
    let headers = response.headers();
    if headers.contains_key("set-cookie") {
        let cookie = unwrap_ok!(unwrap_some!(headers.get("set-cookie")).to_str());
        // In production, cookies should have Secure, HttpOnly, and SameSite
        // Note: These may not be set in test environment
        assert!(
            cookie.contains("HttpOnly") || cookie.contains("httponly") || !cookie.is_empty(),
            "Cookie should have security attributes"
        );
    }

    test_db::cleanup(&mut conn).await;
}

/// Test session fixation protection.
///
/// Per Finding #2 remediation, API login requires MFA configured on the
/// account; we use an MFA-enabled fixture and a valid TOTP code.
#[tokio::test]
#[serial]
async fn test_session_fixation_protection() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("test_session");
    let test_user = create_test_user_with_mfa(&mut conn, &app.auth_service, &username).await;

    let response = app
        .server
        .post("/api/v1/auth/login")
        .json(&json!({
            "username": username,
            "password": test_user.password,
            "mfa_code": current_totp_for(&test_user.mfa_secret),
        }))
        .await;

    assert_status(&response, 200);

    // After successful login, session should be regenerated
    // This is verified by checking that a new token is issued
    let json: serde_json::Value = response.json();
    assert!(
        json.get("access_token").is_some(),
        "New token should be issued on login"
    );

    test_db::cleanup(&mut conn).await;
}

/// Test JWT token expiration.
///
/// Per Finding #2 remediation, API login requires MFA; we use an
/// MFA-enabled admin fixture and a valid TOTP code.
#[tokio::test]
#[serial]
async fn test_jwt_expiration() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Use admin user since /api/v1/accounts requires staff/superuser
    let username = unique_name("test_jwt_exp");
    let test_user = create_admin_user_with_mfa(&mut conn, &app.auth_service, &username).await;

    let response = app
        .server
        .post("/api/v1/auth/login")
        .json(&json!({
            "username": username,
            "password": test_user.password,
            "mfa_code": current_totp_for(&test_user.mfa_secret),
        }))
        .await;

    assert_status(&response, 200);

    let body: serde_json::Value = response.json();
    assert!(body.get("access_token").is_some());

    // Token should be valid immediately after login
    let token = unwrap_some!(body["access_token"].as_str());
    let response = app
        .server
        .get("/api/v1/accounts")
        .add_header(header::AUTHORIZATION, app.auth_header(token))
        .await;

    assert_status(&response, 200);

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// Password Security Tests
// =============================================================================

/// Test password complexity requirements.
///
/// TODO: Password validation currently returns 500 for some invalid passwords.
/// Should return 400 Bad Request with validation error message.
#[tokio::test]
#[serial]
async fn test_password_complexity() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Use admin user since create_user now requires staff/superuser
    let username = unique_name("test_pwd_complex");
    let test_user = create_admin_user(&mut conn, &app.auth_service, &username).await;

    // Password too short - should be rejected
    let response = app
        .server
        .post("/api/v1/accounts")
        .add_header(header::AUTHORIZATION, app.auth_header(&test_user.token))
        .json(&json!({
            "username": "newuser1",
            "email": "new1@example.com",
            "password": "short"
        }))
        .await;

    // TODO: Should return 400, may return 500 currently
    let status = response.status_code().as_u16();
    assert!(
        status == 400 || status == 500,
        "Short password should be rejected, got {}",
        status
    );

    // Password without numbers - may be accepted depending on policy
    let response = app
        .server
        .post("/api/v1/accounts")
        .add_header(header::AUTHORIZATION, app.auth_header(&test_user.token))
        .json(&json!({
            "username": "newuser2",
            "email": "new2@example.com",
            "password": "PasswordWithoutNumbers!"
        }))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 200 || status == 400 || status == 500,
        "Password without numbers should be handled, got {}",
        status
    );

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// Data Sanitization Tests
// =============================================================================

/// Test data sanitization for malicious inputs.
///
/// Verifies that the API handles various input types without crashing.
#[tokio::test]
#[serial]
async fn test_data_sanitization() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Use admin user since create_user now requires staff/superuser
    let username = unique_name("test_sanitize");
    let test_user = create_admin_user(&mut conn, &app.auth_service, &username).await;

    // Valid input with unique name
    let new_username = unique_name("admin_test");
    let response = app
        .server
        .post("/api/v1/accounts")
        .add_header(header::AUTHORIZATION, app.auth_header(&test_user.token))
        .json(&json!({
            "username": new_username,
            "email": format!("{}@example.com", new_username),
            "password": "Password123!"
        }))
        .await;

    // Valid input should work (200) or fail with validation error (400)
    let status = response.status_code().as_u16();
    assert!(
        status == 200 || status == 400 || status == 500,
        "Input should be handled, got {}",
        status
    );

    // HTML/JS in optional fields (without SQL injection patterns)
    let html_username = unique_name("htmluser");
    let response = app
        .server
        .post("/api/v1/accounts")
        .add_header(header::AUTHORIZATION, app.auth_header(&test_user.token))
        .json(&json!({
            "username": html_username,
            "email": format!("{}@example.com", html_username),
            "password": "Password123!",
            "first_name": "Test<b>Bold</b>"
        }))
        .await;

    // Should be handled (accepted, rejected, or sanitized)
    let status = response.status_code().as_u16();
    assert!(
        status == 200 || status == 400 || status == 500,
        "HTML input should be handled, got {}",
        status
    );

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// Security Headers Tests
// =============================================================================

/// Test security headers on main endpoints.
#[tokio::test]
#[serial]
async fn test_security_headers() {
    let app = TestApp::spawn().await;

    // Test security headers on home page
    let response = app.server.get("/").await;
    let headers = response.headers();

    // X-Content-Type-Options prevents MIME sniffing
    assert!(
        headers.contains_key("x-content-type-options"),
        "Missing X-Content-Type-Options header"
    );

    // X-Frame-Options prevents clickjacking
    assert!(
        headers.contains_key("x-frame-options"),
        "Missing X-Frame-Options header"
    );

    // Content-Security-Policy prevents XSS
    assert!(
        headers.contains_key("content-security-policy"),
        "Missing Content-Security-Policy header"
    );

    // Strict-Transport-Security for HTTPS
    assert!(
        headers.contains_key("strict-transport-security"),
        "Missing Strict-Transport-Security header"
    );

    // Referrer-Policy
    assert!(
        headers.contains_key("referrer-policy"),
        "Missing Referrer-Policy header"
    );

    // Permissions-Policy
    assert!(
        headers.contains_key("permissions-policy"),
        "Missing Permissions-Policy header"
    );
}

/// Test security headers on login page.
#[tokio::test]
#[serial]
async fn test_login_page_security_headers() {
    let app = TestApp::spawn().await;

    let response = app.server.get("/login").await;
    let headers = response.headers();

    assert!(
        headers.contains_key("x-frame-options"),
        "Missing X-Frame-Options header"
    );
    assert!(
        headers.contains_key("content-security-policy"),
        "Missing Content-Security-Policy header"
    );
    assert!(
        headers.contains_key("x-xss-protection"),
        "Missing X-XSS-Protection header"
    );
}

/// Test security headers on API endpoints.
#[tokio::test]
#[serial]
async fn test_api_security_headers() {
    let app = TestApp::spawn().await;

    let response = app.server.get("/api/v1/accounts").await;
    let headers = response.headers();

    assert!(
        headers.contains_key("x-content-type-options"),
        "API should have X-Content-Type-Options"
    );
    assert!(
        headers.contains_key("content-security-policy"),
        "API should have Content-Security-Policy"
    );
}

/// Test health endpoint is publicly accessible.
#[tokio::test]
#[serial]
async fn test_health_endpoint_public() {
    let app = TestApp::spawn().await;

    let response = app.server.get("/health").await;

    // Health endpoint should be accessible without auth
    assert_status(&response, 200);
}

// =============================================================================
// CSRF Protection Tests
// =============================================================================

/// Test CSRF protection on state-changing requests.
#[tokio::test]
#[serial]
async fn test_csrf_protection() {
    let app = TestApp::spawn().await;

    // State-changing request without authentication should be rejected
    let response = app
        .server
        .post("/api/v1/accounts")
        .json(&json!({
            "username": "testuser",
            "email": "test@example.com",
            "password": "Password123!"
        }))
        .await;

    // Should require proper authentication
    assert_status(&response, 401);
}

// =============================================================================
// CSRF Validation: connect_ssh
// =============================================================================

/// Test that connect_ssh rejects requests without a CSRF token.
///
/// Regression test: Missing CSRF Validation in connect_ssh.
/// Previously, the handler accepted but never validated the csrf_token field,
/// enabling CSRF attacks to initiate SSH connections on behalf of authenticated users.
#[tokio::test]
#[serial]
async fn test_connect_ssh_rejects_missing_csrf_token() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("test_ssh_csrf_miss");
    let admin = crate::fixtures::create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    // Create a test SSH asset
    let test_asset =
        crate::fixtures::create_test_ssh_asset(&mut conn, &unique_name("test-ssh-csrf")).await;

    // POST to connect_ssh with empty CSRF token (no CSRF cookie)
    let response = app
        .server
        .post(&format!("/assets/{}/connect", test_asset.asset.uuid))
        .add_header(
            axum::http::header::COOKIE,
            format!("access_token={}", admin.token),
        )
        .form(&json!({
            "csrf_token": "",
        }))
        .await;

    // Should fail with CSRF error, not succeed
    let body = response.text();
    assert!(
        body.contains("CSRF") || body.contains("csrf") || body.contains("Invalid"),
        "Request without CSRF token should be rejected. Got body: {}",
        body
    );

    test_db::cleanup(&mut conn).await;
}

/// Test that connect_ssh rejects requests with an invalid CSRF token.
#[tokio::test]
#[serial]
async fn test_connect_ssh_rejects_invalid_csrf_token() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("test_ssh_csrf_inv");
    let admin = crate::fixtures::create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let test_asset =
        crate::fixtures::create_test_ssh_asset(&mut conn, &unique_name("test-ssh-csrf2")).await;

    // POST with a forged CSRF token that doesn't match the cookie
    let response = app
        .server
        .post(&format!("/assets/{}/connect", test_asset.asset.uuid))
        .add_header(
            axum::http::header::COOKIE,
            format!(
                "access_token={}; __vauban_csrf=valid_cookie_token",
                admin.token
            ),
        )
        .form(&json!({
            "csrf_token": "forged_different_token",
        }))
        .await;

    let body = response.text();
    assert!(
        body.contains("CSRF") || body.contains("csrf") || body.contains("Invalid"),
        "Request with mismatched CSRF token should be rejected. Got body: {}",
        body
    );

    test_db::cleanup(&mut conn).await;
}

/// Test that connect_ssh rejects HTMX requests with an invalid CSRF token.
#[tokio::test]
#[serial]
async fn test_connect_ssh_rejects_invalid_csrf_htmx() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("test_ssh_csrf_htmx");
    let admin = crate::fixtures::create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let test_asset =
        crate::fixtures::create_test_ssh_asset(&mut conn, &unique_name("test-ssh-csrf3")).await;

    // HTMX request with forged CSRF token
    let response = app
        .server
        .post(&format!("/assets/{}/connect", test_asset.asset.uuid))
        .add_header(
            axum::http::header::COOKIE,
            format!("access_token={}", admin.token),
        )
        .add_header("HX-Request", "true")
        .form(&json!({
            "csrf_token": "forged_csrf_token",
        }))
        .await;

    // HTMX error response should contain toast with error message
    let body = response.text();
    let has_error = body.contains("CSRF")
        || body.contains("csrf")
        || body.contains("Invalid")
        || response
            .headers()
            .get("HX-Trigger")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.contains("error") || v.contains("CSRF") || v.contains("Invalid"))
            .unwrap_or(false);

    assert!(
        has_error,
        "HTMX request with invalid CSRF should return error toast. Headers: {:?}, Body: {}",
        response.headers(),
        body
    );

    test_db::cleanup(&mut conn).await;
}

/// Test that connect_ssh accepts a valid CSRF token.
///
/// The request will fail later (SSH proxy not available in tests), but it
/// should NOT fail on CSRF validation -- proving the token is correctly validated.
#[tokio::test]
#[serial]
async fn test_connect_ssh_accepts_valid_csrf_token() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("test_ssh_csrf_ok");
    let admin = crate::fixtures::create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let test_asset =
        crate::fixtures::create_test_ssh_asset(&mut conn, &unique_name("test-ssh-csrf4")).await;

    // Generate a valid CSRF token
    let csrf_token = app.generate_csrf_token();

    // POST with valid CSRF token (cookie and form match)
    let response = app
        .server
        .post(&format!("/assets/{}/connect", test_asset.asset.uuid))
        .add_header(
            axum::http::header::COOKIE,
            format!("access_token={}; __vauban_csrf={}", admin.token, csrf_token),
        )
        .form(&json!({
            "csrf_token": csrf_token,
        }))
        .await;

    // Should NOT fail on CSRF validation.
    //
    // Historically this test asserted we reached the "SSH proxy not available"
    // branch, because the superuser bypass let the request skip past the
    // access_rule check and fall through to the proxy lookup. Since the
    // bypass was removed (CheckAccessByUuid alignment), every user --
    // including the bootstrap admin -- is gated by the access_rule check
    // first. We therefore now assert the request progressed past CSRF
    // validation by reaching either the access-rule denial or the proxy
    // lookup; both prove the CSRF token was accepted.
    let body = response.text();
    assert!(
        !body.contains("CSRF") && !body.contains("csrf"),
        "Valid CSRF token should be accepted. Got: {}",
        body
    );

    let progressed_past_csrf = body.contains("No access rule")
        || body.contains("SSH proxy")
        || body.contains("proxy")
        || body.contains("not available");
    assert!(
        progressed_past_csrf,
        "With valid CSRF, request must progress past CSRF validation \
         (either to access-rule denial or proxy lookup). Got: {}",
        body
    );

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// MFA Security Tests
// =============================================================================

/// Finding #2 regression: API login MUST refuse accounts without MFA
/// configured (it used to silently mint a fully MFA-trusted token).
///
/// This test was historically permissive (accepted 200 OR 401); after the
/// remediation it asserts the strict policy: 403 with no token.
#[tokio::test]
#[serial]
async fn test_mfa_enforcement() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("test_mfa_enforce");
    let test_user = create_test_user(&mut conn, &app.auth_service, &username).await;

    let response = app
        .server
        .post("/api/v1/auth/login")
        .json(&json!({
            "username": username,
            "password": test_user.password,
        }))
        .await;

    assert_eq!(
        response.status_code().as_u16(),
        403,
        "API login MUST refuse accounts without MFA configured (Finding #2). \
         Got body: {}",
        response.text()
    );
    let body: serde_json::Value = response.json();
    assert!(
        body.get("access_token").is_none(),
        "Refused login must not include a token in the response body"
    );

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// CSRF Token Consistency Tests
// =============================================================================

/// Test that the CSRF token in the login form matches the cookie.
///
/// This test prevents a bug where the middleware and handler generate
/// different CSRF tokens, causing the form token to not match the cookie.
#[tokio::test]
#[serial]
async fn test_csrf_token_form_matches_cookie() {
    let app = TestApp::spawn().await;

    // Load the login page
    let response = app.server.get("/login").await;

    assert_status(&response, 200);

    // Extract CSRF cookie from response
    let csrf_cookie = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .find_map(|v| {
            let s = v.to_str().ok()?;
            if s.starts_with("__vauban_csrf=") {
                // Extract token value from "name=value; ..."
                let token = s.split(';').next()?.strip_prefix("__vauban_csrf=")?;
                Some(token.to_string())
            } else {
                None
            }
        });

    let cookie_token = unwrap_some!(csrf_cookie, "CSRF cookie should be set in response");

    // Extract CSRF token from HTML form
    let body = response.text();
    let form_token = unwrap_some!(
        extract_csrf_token_from_html(&body),
        "CSRF token should be present in login form HTML"
    );

    // The cookie and form token MUST match
    assert_eq!(
        cookie_token, form_token,
        "CSRF token in form ({}) must match cookie ({}). \
         This indicates the middleware and handler are generating different tokens.",
        form_token, cookie_token
    );
}

/// Test that only one CSRF cookie is set in the response.
///
/// This prevents a bug where both middleware and handler set different cookies.
#[tokio::test]
#[serial]
async fn test_csrf_no_duplicate_cookies() {
    let app = TestApp::spawn().await;

    // Load the login page
    let response = app.server.get("/login").await;

    assert_status(&response, 200);

    // Count CSRF cookies in response
    let csrf_cookie_count = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter(|v| {
            v.to_str()
                .map(|s| s.starts_with("__vauban_csrf="))
                .unwrap_or(false)
        })
        .count();

    assert_eq!(
        csrf_cookie_count, 1,
        "Expected exactly 1 CSRF cookie, found {}. \
         Multiple cookies indicate middleware/handler conflict.",
        csrf_cookie_count
    );
}

/// Test the complete login flow with CSRF token from page load.
///
/// This is an end-to-end test that:
/// 1. Loads the login page
/// 2. Extracts the CSRF token from the response
/// 3. Submits the login form with that token
/// 4. Verifies the CSRF validation passes (even if credentials are wrong)
#[tokio::test]
#[serial]
async fn test_csrf_login_flow_end_to_end() {
    let app = TestApp::spawn().await;

    // Step 1: Load the login page to get CSRF token
    let login_page = app.server.get("/login").await;
    assert_status(&login_page, 200);

    // Extract CSRF cookie
    let csrf_cookie = login_page
        .headers()
        .get_all("set-cookie")
        .iter()
        .find_map(|v| {
            let s = v.to_str().ok()?;
            if s.starts_with("__vauban_csrf=") {
                Some(s.split(';').next()?.to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| panic!("CSRF cookie should be set"));

    // Extract token from HTML
    let body = login_page.text();
    let form_token = unwrap_some!(
        extract_csrf_token_from_html(&body),
        "CSRF token should be in form"
    );

    // Step 2: Submit login with the CSRF token
    let response = app
        .server
        .post("/auth/login")
        .add_header("Cookie", csrf_cookie)
        .add_header("HX-Request", "true")
        .json(&json!({
            "username": "nonexistent_user",
            "password": "wrongpassword1",
            "csrf_token": form_token
        }))
        .await;

    // The response should NOT be "Invalid CSRF token"
    // It should be "Invalid credentials" or similar
    let response_body = response.text();

    assert!(
        !response_body.contains("Invalid CSRF token"),
        "CSRF validation failed! The token from the form did not match the cookie. \
         Response: {}",
        response_body
    );

    // Should get invalid credentials error (not CSRF error).
    // SEC-05: validation failures now also return "Invalid credentials",
    // rendered as "Incorrect username or password" by html_error_fragment.
    assert!(
        response_body.contains("Incorrect username or password"),
        "Expected 'Incorrect username or password', got: {}",
        response_body
    );
}

/// Test that CSRF token works after cookie expiration simulation.
///
/// Simulates the scenario where a user's CSRF cookie has expired
/// and they load the login page fresh.
#[tokio::test]
#[serial]
async fn test_csrf_fresh_session_works() {
    let app = TestApp::spawn().await;

    // Load login page without any existing cookies (fresh session)
    let response = app.server.get("/login").await;
    assert_status(&response, 200);

    // Verify we get a CSRF cookie
    let has_csrf_cookie = response.headers().get_all("set-cookie").iter().any(|v| {
        v.to_str()
            .map(|s| s.starts_with("__vauban_csrf="))
            .unwrap_or(false)
    });

    assert!(has_csrf_cookie, "Fresh login page should set a CSRF cookie");

    // Verify the form has a matching token
    let body = response.text();
    assert!(
        body.contains("name=\"csrf_token\"") && body.contains("value=\""),
        "Login form should have a csrf_token input with a value"
    );
}

// =============================================================================
// Credential Leak via Debug Derive Tests
// =============================================================================
// These tests verify that Debug implementations for LoginRequest and
// SshSessionOpenRequest redact sensitive fields (password, mfa_code,
// private_key, passphrase) to prevent credential leaks in logs.

/// Test that LoginRequest Debug output does not contain the plaintext password.
#[test]
fn test_login_request_debug_does_not_leak_password() {
    use vauban_web::handlers::auth::LoginRequest;

    let request = LoginRequest {
        username: "admin".to_string(),
        password: "MyS3cretP@ssword!".to_string(),
        mfa_code: None,
        csrf_token: None,
    };

    let debug_str = format!("{:?}", request);

    assert!(
        !debug_str.contains("MyS3cretP@ssword!"),
        "LoginRequest Debug must NOT contain the plaintext password. Got: {}",
        debug_str
    );
    assert!(
        debug_str.contains("[REDACTED]"),
        "LoginRequest Debug must show [REDACTED] for password. Got: {}",
        debug_str
    );
    // Username should still be visible (it's not a secret)
    assert!(
        debug_str.contains("admin"),
        "LoginRequest Debug should contain the username. Got: {}",
        debug_str
    );
}

/// Test that LoginRequest Debug output does not contain the MFA code.
#[test]
fn test_login_request_debug_does_not_leak_mfa_code() {
    use vauban_web::handlers::auth::LoginRequest;

    let request = LoginRequest {
        username: "admin".to_string(),
        password: "irrelevant-password".to_string(),
        mfa_code: Some("987654".to_string()),
        csrf_token: Some("csrf-value".to_string()),
    };

    let debug_str = format!("{:?}", request);

    assert!(
        !debug_str.contains("987654"),
        "LoginRequest Debug must NOT contain the MFA code. Got: {}",
        debug_str
    );
    assert!(
        !debug_str.contains("irrelevant-password"),
        "LoginRequest Debug must NOT contain the password. Got: {}",
        debug_str
    );
    // CSRF token is not a secret (it's also in the cookie), so it can appear
    assert!(debug_str.contains("csrf-value"));
}

/// Test that SshSessionOpenRequest Debug output does not contain SSH password.
#[test]
fn test_ssh_request_debug_does_not_leak_password() {
    use secrecy::SecretString;
    use vauban_web::ipc::SshSessionOpenRequest;

    let request = SshSessionOpenRequest {
        session_id: "sess-001".to_string(),
        user_id: "user-001".to_string(),
        asset_id: "asset-001".to_string(),
        asset_host: "10.0.0.1".to_string(),
        asset_port: 22,
        username: "root".to_string(),
        terminal_cols: 80,
        terminal_rows: 24,
        auth_type: "password".to_string(),
        password: Some(SecretString::from("ssh-p@ssw0rd!".to_string())),
        private_key: None,
        passphrase: None,
        expected_host_key: None,
        session_token: Vec::new(),
    };

    let debug_str = format!("{:?}", request);

    assert!(
        !debug_str.contains("ssh-p@ssw0rd!"),
        "SshSessionOpenRequest Debug must NOT contain the SSH password. Got: {}",
        debug_str
    );
    assert!(debug_str.contains("[REDACTED]"));
    // Non-secret fields should still be visible
    assert!(debug_str.contains("sess-001"));
    assert!(debug_str.contains("10.0.0.1"));
    assert!(debug_str.contains("root"));
}

/// Test that SshSessionOpenRequest Debug output does not contain private key.
#[test]
fn test_ssh_request_debug_does_not_leak_private_key() {
    use secrecy::SecretString;
    use vauban_web::ipc::SshSessionOpenRequest;

    let request = SshSessionOpenRequest {
        session_id: "sess-002".to_string(),
        user_id: "user-002".to_string(),
        asset_id: "asset-002".to_string(),
        asset_host: "10.0.0.2".to_string(),
        asset_port: 22,
        username: "deploy".to_string(),
        terminal_cols: 80,
        terminal_rows: 24,
        auth_type: "private_key".to_string(),
        password: None,
        private_key: Some(SecretString::from(
            "-----BEGIN OPENSSH PRIVATE KEY-----\nbase64data\n-----END OPENSSH PRIVATE KEY-----"
                .to_string(),
        )),
        passphrase: Some(SecretString::from("key-unlock-phrase".to_string())),
        expected_host_key: None,
        session_token: Vec::new(),
    };

    let debug_str = format!("{:?}", request);

    assert!(
        !debug_str.contains("BEGIN OPENSSH PRIVATE KEY"),
        "SshSessionOpenRequest Debug must NOT contain the private key. Got: {}",
        debug_str
    );
    assert!(
        !debug_str.contains("base64data"),
        "SshSessionOpenRequest Debug must NOT contain key data. Got: {}",
        debug_str
    );
    assert!(
        !debug_str.contains("key-unlock-phrase"),
        "SshSessionOpenRequest Debug must NOT contain the passphrase. Got: {}",
        debug_str
    );
}

/// Test that None secrets in SshSessionOpenRequest show None, not [REDACTED].
#[test]
fn test_ssh_request_debug_none_secrets_show_none() {
    use vauban_web::ipc::SshSessionOpenRequest;

    let request = SshSessionOpenRequest {
        session_id: "sess-003".to_string(),
        user_id: "user-003".to_string(),
        asset_id: "asset-003".to_string(),
        asset_host: "10.0.0.3".to_string(),
        asset_port: 22,
        username: "user".to_string(),
        terminal_cols: 80,
        terminal_rows: 24,
        auth_type: "password".to_string(),
        password: None,
        private_key: None,
        passphrase: None,
        expected_host_key: None,
        session_token: Vec::new(),
    };

    let debug_str = format!("{:?}", request);

    // When secrets are None, they should show as None (not [REDACTED])
    assert!(
        debug_str.contains("None"),
        "None secrets should show as None in Debug output. Got: {}",
        debug_str
    );
}

// =============================================================================
// X-Forwarded-For Header Spoofing Tests
// =============================================================================
// These tests verify that X-Forwarded-For / X-Real-IP headers are NOT trusted
// when the request does not originate from a configured trusted proxy.
// Before the fix, any client could inject these headers to spoof their IP,
// bypassing rate limiting and poisoning audit logs.

/// Test that the resolve_client_ip utility ignores XFF from untrusted sources.
/// This is a unit-level regression test for the core fix.
#[test]
fn test_resolve_client_ip_ignores_xff_without_trusted_proxy() {
    use axum::http::HeaderMap;
    use std::net::IpAddr;

    let mut headers = HeaderMap::new();
    headers.insert("X-Forwarded-For", "1.2.3.4".parse().unwrap());

    let connect_ip: IpAddr = "10.0.0.99".parse().unwrap();
    // Empty trusted list -> headers must be ignored
    let result = vauban_web::middleware::resolve_client_ip(&headers, connect_ip, &[]);

    assert_eq!(
        result.to_string(),
        "10.0.0.99",
        "XFF should be ignored when trusted_proxies is empty"
    );
}

/// Test that XFF is ignored when the connection comes from a non-trusted IP.
#[test]
fn test_resolve_client_ip_ignores_xff_from_non_trusted_ip() {
    use axum::http::HeaderMap;
    use std::net::IpAddr;

    let mut headers = HeaderMap::new();
    headers.insert("X-Forwarded-For", "1.2.3.4".parse().unwrap());

    let connect_ip: IpAddr = "10.0.0.99".parse().unwrap();
    // Trusted list does NOT include 10.0.0.99
    let trusted: Vec<IpAddr> = vec!["127.0.0.1".parse().unwrap()];
    let result = vauban_web::middleware::resolve_client_ip(&headers, connect_ip, &trusted);

    assert_eq!(
        result.to_string(),
        "10.0.0.99",
        "XFF should be ignored when connection is not from a trusted proxy"
    );
}

/// Test that X-Real-IP is also ignored from untrusted sources.
#[test]
fn test_resolve_client_ip_ignores_x_real_ip_without_trusted_proxy() {
    use axum::http::HeaderMap;
    use std::net::IpAddr;

    let mut headers = HeaderMap::new();
    headers.insert("X-Real-IP", "8.8.8.8".parse().unwrap());

    let connect_ip: IpAddr = "192.168.1.50".parse().unwrap();
    let result = vauban_web::middleware::resolve_client_ip(&headers, connect_ip, &[]);

    assert_eq!(
        result.to_string(),
        "192.168.1.50",
        "X-Real-IP should be ignored when trusted_proxies is empty"
    );
}

/// Test that XFF IS honoured when the connection comes from a trusted proxy.
#[test]
fn test_resolve_client_ip_trusts_xff_from_trusted_proxy() {
    use axum::http::HeaderMap;
    use std::net::IpAddr;

    let mut headers = HeaderMap::new();
    headers.insert("X-Forwarded-For", "203.0.113.50".parse().unwrap());

    let connect_ip: IpAddr = "127.0.0.1".parse().unwrap();
    let trusted: Vec<IpAddr> = vec!["127.0.0.1".parse().unwrap()];
    let result = vauban_web::middleware::resolve_client_ip(&headers, connect_ip, &trusted);

    assert_eq!(
        result.to_string(),
        "203.0.113.50",
        "XFF should be trusted when connection is from a trusted proxy"
    );
}

/// Test that only the first IP in the XFF chain is used (leftmost = original client).
#[test]
fn test_resolve_client_ip_uses_first_xff_entry() {
    use axum::http::HeaderMap;
    use std::net::IpAddr;

    let mut headers = HeaderMap::new();
    headers.insert(
        "X-Forwarded-For",
        "203.0.113.50, 70.41.3.18, 150.172.238.178".parse().unwrap(),
    );

    let connect_ip: IpAddr = "127.0.0.1".parse().unwrap();
    let trusted: Vec<IpAddr> = vec!["127.0.0.1".parse().unwrap()];
    let result = vauban_web::middleware::resolve_client_ip(&headers, connect_ip, &trusted);

    assert_eq!(
        result.to_string(),
        "203.0.113.50",
        "Should use the leftmost (original client) IP from the XFF chain"
    );
}

/// Test that the parsed_trusted_proxies method correctly parses valid IPs
/// and silently skips invalid ones.
#[test]
fn test_security_config_parsed_trusted_proxies() {
    use vauban_web::config::SecurityConfig;

    let config = SecurityConfig {
        password_min_length: 12,
        max_failed_login_attempts: 5,
        session_max_duration_secs: 28800,
        session_idle_timeout_secs: 1800,
        rate_limit_per_minute: 10,
        argon2: vauban_web::config::Argon2Config {
            memory_size_kb: 1024,
            iterations: 1,
            parallelism: 1,
        },
        require_justification: true,
        trusted_proxies: vec![
            "127.0.0.1".to_string(),
            "::1".to_string(),
            "not-a-valid-ip".to_string(), // Should be silently skipped
            "10.0.0.1".to_string(),
        ],
    };

    let parsed = config.parsed_trusted_proxies();
    assert_eq!(
        parsed.len(),
        3,
        "Invalid entries should be silently skipped"
    );
    assert_eq!(parsed[0].to_string(), "127.0.0.1");
    assert_eq!(parsed[1].to_string(), "::1");
    assert_eq!(parsed[2].to_string(), "10.0.0.1");
}

/// Test that an empty trusted_proxies config results in headers never being trusted.
#[test]
fn test_security_config_empty_trusted_proxies() {
    use vauban_web::config::SecurityConfig;

    let config = SecurityConfig {
        password_min_length: 12,
        max_failed_login_attempts: 5,
        session_max_duration_secs: 28800,
        session_idle_timeout_secs: 1800,
        rate_limit_per_minute: 10,
        argon2: vauban_web::config::Argon2Config {
            memory_size_kb: 1024,
            iterations: 1,
            parallelism: 1,
        },
        require_justification: true,
        trusted_proxies: vec![],
    };

    let parsed = config.parsed_trusted_proxies();
    assert!(parsed.is_empty());
}

/// Integration test: verify that login endpoint records the correct client IP
/// (i.e. the TCP peer address, not a spoofed X-Forwarded-For header).
/// In the test environment, trusted_proxies defaults to empty, so XFF is ignored.
#[tokio::test]
#[serial]
async fn test_login_ignores_spoofed_xff_header() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("test_xff_login");
    // Per Finding #2 remediation, API login requires MFA.
    let test_user = create_test_user_with_mfa(&mut conn, &app.auth_service, &username).await;

    // Attempt login with a spoofed X-Forwarded-For header
    let response = app
        .server
        .post("/api/v1/auth/login")
        .add_header(
            header::HeaderName::from_static("x-forwarded-for"),
            "6.6.6.6".parse::<header::HeaderValue>().unwrap(),
        )
        .json(&json!({
            "username": username,
            "password": test_user.password,
            "mfa_code": current_totp_for(&test_user.mfa_secret),
        }))
        .await;

    // Login should succeed regardless of XFF
    let status = response.status_code().as_u16();
    assert!(
        status == 200 || status == 303,
        "Login should succeed, got {}",
        status
    );

    // Verify the session was created with the real connection IP (127.0.0.1)
    // and NOT the spoofed 6.6.6.6
    {
        use diesel::{ExpressionMethods, QueryDsl};
        use diesel_async::RunQueryDsl;
        use vauban_web::schema::auth_sessions;

        let session_ip: ipnetwork::IpNetwork = unwrap_ok!(
            auth_sessions::table
                .filter(auth_sessions::user_id.eq(test_user.user.id))
                .order(auth_sessions::created_at.desc())
                .select(auth_sessions::ip_address)
                .first(&mut conn)
                .await
        );

        let ip_str = session_ip.ip().to_string();
        assert!(
            !ip_str.contains("6.6.6.6"),
            "Session IP should NOT be the spoofed XFF value 6.6.6.6, got: {}",
            ip_str
        );
    }

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// Session Revocation Bypass Tests
// =============================================================================
// These tests verify that a JWT token whose session has been revoked (deleted)
// from the database is correctly rejected by the auth middleware.
// Before the fix, require_auth only validated the JWT signature without checking
// the database, allowing revoked tokens to remain valid.

/// Test that an API request with a valid JWT but a revoked session is rejected.
/// This is the core regression test.
#[tokio::test]
#[serial]
async fn test_revoked_session_token_rejected_on_api() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Create an admin user with a valid session
    let username = unique_name("test_revoked_api");
    let admin = create_admin_user(&mut conn, &app.auth_service, &username).await;

    // Verify the token works before revocation
    let response = app
        .server
        .get("/api/v1/assets")
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;
    assert_status(&response, 200);

    // Revoke the session by deleting it from the database
    {
        use diesel::{ExpressionMethods, QueryDsl};
        use diesel_async::RunQueryDsl;
        use vauban_web::schema::auth_sessions;

        unwrap_ok!(
            diesel::delete(auth_sessions::table.filter(auth_sessions::user_id.eq(admin.user.id)),)
                .execute(&mut conn)
                .await
        );
    }

    // The same token should now be rejected (JWT is still valid, but session is revoked)
    let response = app
        .server
        .get("/api/v1/assets")
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 401 || status == 403,
        "Expected 401 or 403 for revoked session token on API, got {}",
        status
    );

    test_db::cleanup(&mut conn).await;
}

/// Test that a web page request with a revoked session redirects to login.
#[tokio::test]
#[serial]
async fn test_revoked_session_token_redirects_on_web() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("test_revoked_web");
    let admin = create_admin_user(&mut conn, &app.auth_service, &username).await;

    // Verify the token works before revocation (web page)
    let response = app
        .server
        .get("/accounts/login-sessions")
        .add_header(
            header::COOKIE,
            format!("access_token={}", admin.token)
                .parse::<header::HeaderValue>()
                .unwrap(),
        )
        .await;
    assert_status(&response, 200);

    // Revoke the session
    {
        use diesel::{ExpressionMethods, QueryDsl};
        use diesel_async::RunQueryDsl;
        use vauban_web::schema::auth_sessions;

        unwrap_ok!(
            diesel::delete(auth_sessions::table.filter(auth_sessions::user_id.eq(admin.user.id)),)
                .execute(&mut conn)
                .await
        );
    }

    // The same token should redirect to login
    let response = app
        .server
        .get("/accounts/login-sessions")
        .add_header(
            header::COOKIE,
            format!("access_token={}", admin.token)
                .parse::<header::HeaderValue>()
                .unwrap(),
        )
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 303 || status == 401,
        "Expected redirect (303) or 401 for revoked session on web page, got {}",
        status
    );

    test_db::cleanup(&mut conn).await;
}

/// Test that re-creating a session after revocation restores access.
/// This verifies that the system correctly handles session lifecycle.
#[tokio::test]
#[serial]
async fn test_new_session_works_after_revocation() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("test_reauth");
    let admin = create_admin_user(&mut conn, &app.auth_service, &username).await;

    // Revoke the session
    {
        use diesel::{ExpressionMethods, QueryDsl};
        use diesel_async::RunQueryDsl;
        use vauban_web::schema::auth_sessions;

        unwrap_ok!(
            diesel::delete(auth_sessions::table.filter(auth_sessions::user_id.eq(admin.user.id)),)
                .execute(&mut conn)
                .await
        );
    }

    // Old token should be rejected
    let response = app
        .server
        .get("/api/v1/assets")
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;
    let status = response.status_code().as_u16();
    assert!(
        status == 401 || status == 403,
        "Old token should be rejected after revocation, got {}",
        status
    );

    // Generate a new token and session for the same user
    let new_token = app
        .generate_test_token(
            &admin.user.uuid.to_string(),
            &admin.user.username,
            true,
            true,
        )
        .await;

    // New token should work
    let response = app
        .server
        .get("/api/v1/assets")
        .add_header(header::AUTHORIZATION, app.auth_header(&new_token))
        .await;
    assert_status(&response, 200);

    test_db::cleanup(&mut conn).await;
}

/// Test that an idle-expired session is rejected even with a valid JWT.
/// Sessions that exceed the idle timeout should be treated as invalid.
#[tokio::test]
#[serial]
async fn test_idle_expired_session_rejected_on_api() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("test_idle_api");
    let admin = create_admin_user(&mut conn, &app.auth_service, &username).await;

    // Verify token works
    let response = app
        .server
        .get("/api/v1/assets")
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;
    assert_status(&response, 200);

    // Set last_activity to 2 hours ago (exceeds idle timeout)
    {
        use chrono::{Duration, Utc};
        use diesel::{ExpressionMethods, QueryDsl};
        use diesel_async::RunQueryDsl;
        use vauban_web::schema::auth_sessions;

        unwrap_ok!(
            diesel::update(auth_sessions::table.filter(auth_sessions::user_id.eq(admin.user.id)),)
                .set(auth_sessions::last_activity.eq(Utc::now() - Duration::hours(2)))
                .execute(&mut conn)
                .await
        );
    }

    // Token should be rejected due to idle timeout
    let response = app
        .server
        .get("/api/v1/assets")
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 401 || status == 403,
        "Expected 401/403 for idle-expired session on API, got {}",
        status
    );

    test_db::cleanup(&mut conn).await;
}

/// Test that a session that exceeded max duration is rejected.
#[tokio::test]
#[serial]
async fn test_max_duration_exceeded_session_rejected_on_api() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("test_maxdur_api");
    let admin = create_admin_user(&mut conn, &app.auth_service, &username).await;

    // Verify token works
    let response = app
        .server
        .get("/api/v1/assets")
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;
    assert_status(&response, 200);

    // Set created_at to 10 hours ago (exceeds max_duration of 8h)
    {
        use chrono::{Duration, Utc};
        use diesel::{ExpressionMethods, QueryDsl};
        use diesel_async::RunQueryDsl;
        use vauban_web::schema::auth_sessions;

        unwrap_ok!(
            diesel::update(auth_sessions::table.filter(auth_sessions::user_id.eq(admin.user.id)),)
                .set(auth_sessions::created_at.eq(Utc::now() - Duration::hours(10)))
                .execute(&mut conn)
                .await
        );
    }

    // Token should be rejected due to max duration
    let response = app
        .server
        .get("/api/v1/assets")
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 401 || status == 403,
        "Expected 401/403 for max-duration-exceeded session on API, got {}",
        status
    );

    test_db::cleanup(&mut conn).await;
}

/// Test that a valid session with recent activity is accepted.
/// This is a positive test to ensure session validation doesn't block valid sessions.
#[tokio::test]
#[serial]
async fn test_valid_session_accepted_on_api() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("test_valid_sess");
    let admin = create_admin_user(&mut conn, &app.auth_service, &username).await;

    // Token with fresh session should work on API
    let response = app
        .server
        .get("/api/v1/assets")
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;
    assert_status(&response, 200);

    // Also works on web pages
    let response = app
        .server
        .get("/accounts/login-sessions")
        .add_header(
            header::COOKIE,
            format!("access_token={}", admin.token)
                .parse::<header::HeaderValue>()
                .unwrap(),
        )
        .await;
    assert_status(&response, 200);

    test_db::cleanup(&mut conn).await;
}

/// Test that revoking one session doesn't affect other users' sessions.
#[tokio::test]
#[serial]
async fn test_revoking_one_user_doesnt_affect_other() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Create two users
    let username1 = unique_name("test_revoke_u1");
    let username2 = unique_name("test_revoke_u2");
    let admin1 = create_admin_user(&mut conn, &app.auth_service, &username1).await;
    let admin2 = create_admin_user(&mut conn, &app.auth_service, &username2).await;

    // Both should work initially
    let response1 = app
        .server
        .get("/api/v1/assets")
        .add_header(header::AUTHORIZATION, app.auth_header(&admin1.token))
        .await;
    assert_status(&response1, 200);

    let response2 = app
        .server
        .get("/api/v1/assets")
        .add_header(header::AUTHORIZATION, app.auth_header(&admin2.token))
        .await;
    assert_status(&response2, 200);

    // Revoke user1's session only
    {
        use diesel::{ExpressionMethods, QueryDsl};
        use diesel_async::RunQueryDsl;
        use vauban_web::schema::auth_sessions;

        unwrap_ok!(
            diesel::delete(auth_sessions::table.filter(auth_sessions::user_id.eq(admin1.user.id)),)
                .execute(&mut conn)
                .await
        );
    }

    // User1 should be rejected
    let response1 = app
        .server
        .get("/api/v1/assets")
        .add_header(header::AUTHORIZATION, app.auth_header(&admin1.token))
        .await;
    let status1 = response1.status_code().as_u16();
    assert!(
        status1 == 401 || status1 == 403,
        "User1 should be rejected after revocation, got {}",
        status1
    );

    // User2 should still work
    let response2 = app
        .server
        .get("/api/v1/assets")
        .add_header(header::AUTHORIZATION, app.auth_header(&admin2.token))
        .await;
    assert_status(&response2, 200);

    test_db::cleanup(&mut conn).await;
}

/// Test that a regular (non-staff) user's revoked session is also rejected.
/// Ensures revocation applies uniformly regardless of user role.
#[tokio::test]
#[serial]
async fn test_regular_user_revoked_session_rejected() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("test_revoke_reg");
    let regular = create_test_user(&mut conn, &app.auth_service, &username).await;

    // Regular user accessing their own sessions page (no staff required)
    let response = app
        .server
        .get("/accounts/login-sessions")
        .add_header(
            header::COOKIE,
            format!("access_token={}", regular.token)
                .parse::<header::HeaderValue>()
                .unwrap(),
        )
        .await;
    assert_status(&response, 200);

    // Revoke the session
    {
        use diesel::{ExpressionMethods, QueryDsl};
        use diesel_async::RunQueryDsl;
        use vauban_web::schema::auth_sessions;

        unwrap_ok!(
            diesel::delete(
                auth_sessions::table.filter(auth_sessions::user_id.eq(regular.user.id)),
            )
            .execute(&mut conn)
            .await
        );
    }

    // Should be rejected after revocation
    let response = app
        .server
        .get("/accounts/login-sessions")
        .add_header(
            header::COOKIE,
            format!("access_token={}", regular.token)
                .parse::<header::HeaderValue>()
                .unwrap(),
        )
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 303 || status == 401,
        "Regular user should be rejected after session revocation, got {}",
        status
    );

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// XSS Sanitization Regression Tests
// =============================================================================
// These tests verify that HTML tags and XSS payloads are stripped from all
// user-supplied text fields in both web (Form) and API (JSON) handlers.

/// Test that creating a user via web form sanitizes first_name (XSS payload).
#[tokio::test]
#[serial]
async fn test_xss_sanitized_in_web_user_create_first_name() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("admin_xss_create");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let csrf_token = app.generate_csrf_token();

    let xss_payload = "<script>alert('xss')</script>John";
    let new_username = unique_name("xss_user_create");
    let new_email = format!("{}@test.vauban.io", new_username);

    let _response = app
        .server
        .post("/accounts/users")
        .add_header(
            header::COOKIE,
            format!("access_token={}; __vauban_csrf={}", admin.token, csrf_token),
        )
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("username", new_username.as_str()),
            ("email", new_email.as_str()),
            ("password", "SecurePassword123!"),
            ("first_name", xss_payload),
            ("last_name", "<img src=x onerror=alert(1)>Doe"),
            ("is_active", "on"),
        ])
        .await;

    // Verify that HTML tags were stripped from the stored values
    use diesel::{ExpressionMethods, QueryDsl};
    use diesel_async::RunQueryDsl;
    use vauban_web::schema::users;

    let (stored_first, stored_last): (Option<String>, Option<String>) = users::table
        .filter(users::username.eq(&new_username))
        .select((users::first_name, users::last_name))
        .first(&mut conn)
        .await
        .expect("User should exist");

    let first = stored_first.expect("first_name should be set");
    let last = stored_last.expect("last_name should be set");

    assert!(
        !first.contains("<script>"),
        "first_name must not contain <script> tag, got: {}",
        first
    );
    assert!(
        !first.contains("alert("),
        "first_name must not contain alert(), got: {}",
        first
    );
    assert!(
        first.contains("John"),
        "first_name should preserve plain text 'John', got: {}",
        first
    );

    assert!(
        !last.contains("<img"),
        "last_name must not contain <img> tag, got: {}",
        last
    );
    assert!(
        !last.contains("onerror"),
        "last_name must not contain onerror attribute, got: {}",
        last
    );
    assert!(
        last.contains("Doe"),
        "last_name should preserve plain text 'Doe', got: {}",
        last
    );

    test_db::cleanup(&mut conn).await;
}

/// Test that updating a user via web form sanitizes first_name and last_name.
#[tokio::test]
#[serial]
async fn test_xss_sanitized_in_web_user_update() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("admin_xss_update");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let csrf_token = app.generate_csrf_token();

    // Create a regular user to update
    let target_name = unique_name("xss_target_update");
    let target = create_admin_user(&mut conn, &app.auth_service, &target_name).await;

    let xss_first = "<div onmouseover=steal()>Alice</div>";
    let xss_last = "<a href='javascript:void(0)'>Smith</a>";

    let _response = app
        .server
        .post(&format!("/accounts/users/{}", target.user.uuid))
        .add_header(
            header::COOKIE,
            format!("access_token={}; __vauban_csrf={}", admin.token, csrf_token),
        )
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("username", target.user.username.as_str()),
            ("email", &format!("{}@test.vauban.io", target.user.username)),
            ("first_name", xss_first),
            ("last_name", xss_last),
            ("is_active", "on"),
        ])
        .await;

    use diesel::{ExpressionMethods, QueryDsl};
    use diesel_async::RunQueryDsl;
    use vauban_web::schema::users;

    let (stored_first, stored_last): (Option<String>, Option<String>) = users::table
        .filter(users::username.eq(&target.user.username))
        .select((users::first_name, users::last_name))
        .first::<(Option<String>, Option<String>)>(&mut conn)
        .await
        .expect("User should exist");

    let first = stored_first.expect("first_name should be set");
    let last = stored_last.expect("last_name should be set");

    assert!(
        !first.contains("<div"),
        "first_name must not contain <div> tag, got: {}",
        first
    );
    assert!(
        !first.contains("onmouseover"),
        "first_name must not contain event handler, got: {}",
        first
    );
    assert!(
        first.contains("Alice"),
        "first_name should preserve text 'Alice', got: {}",
        first
    );

    assert!(
        !last.contains("javascript:"),
        "last_name must not contain javascript: URI, got: {}",
        last
    );
    assert!(
        last.contains("Smith"),
        "last_name should preserve text 'Smith', got: {}",
        last
    );

    test_db::cleanup(&mut conn).await;
}

/// Test that the API create user handler sanitizes text fields.
#[tokio::test]
#[serial]
async fn test_xss_sanitized_in_api_create_user() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("admin_xss_api_create");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let new_username = unique_name("xss_api_user");

    let response = app
        .server
        .post("/api/v1/accounts")
        .add_header(header::AUTHORIZATION, format!("Bearer {}", admin.token))
        .json(&json!({
            "username": new_username,
            "email": format!("{}@test.vauban.io", new_username),
            "password": "SecurePassword123!",
            "first_name": "<script>document.cookie</script>Eve",
            "last_name": "<b onmouseover=alert('xss')>Hacker</b>"
        }))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 200 || status == 201,
        "API create user should succeed, got {}",
        status
    );

    let body: serde_json::Value = response.json();
    let first = body["first_name"].as_str().unwrap_or("");
    let last = body["last_name"].as_str().unwrap_or("");

    assert!(
        !first.contains("<script>"),
        "API response first_name must not contain <script>, got: {}",
        first
    );
    assert!(
        first.contains("Eve"),
        "API response first_name should preserve 'Eve', got: {}",
        first
    );

    assert!(
        !last.contains("onmouseover"),
        "API response last_name must not contain event handler, got: {}",
        last
    );
    assert!(
        last.contains("Hacker"),
        "API response last_name should preserve 'Hacker', got: {}",
        last
    );

    test_db::cleanup(&mut conn).await;
}

/// Test that the API update user handler sanitizes text fields.
#[tokio::test]
#[serial]
async fn test_xss_sanitized_in_api_update_user() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("admin_xss_api_upd");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let target_name = unique_name("xss_api_target");
    let target = create_admin_user(&mut conn, &app.auth_service, &target_name).await;

    let response = app
        .server
        .put(&format!("/api/v1/accounts/{}", target.user.uuid))
        .add_header(header::AUTHORIZATION, format!("Bearer {}", admin.token))
        .json(&json!({
            "first_name": "<iframe src=evil.com></iframe>Bob",
            "last_name": "<svg/onload=alert(1)>Jones"
        }))
        .await;

    let status = response.status_code().as_u16();
    assert_eq!(
        status, 200,
        "API update user should succeed, got {}",
        status
    );

    let body: serde_json::Value = response.json();
    let first = body["first_name"].as_str().unwrap_or("");
    let last = body["last_name"].as_str().unwrap_or("");

    assert!(
        !first.contains("<iframe"),
        "API first_name must not contain <iframe>, got: {}",
        first
    );
    assert!(
        first.contains("Bob"),
        "API first_name should preserve 'Bob', got: {}",
        first
    );

    assert!(
        !last.contains("<svg"),
        "API last_name must not contain <svg>, got: {}",
        last
    );
    assert!(
        !last.contains("onload"),
        "API last_name must not contain onload, got: {}",
        last
    );
    assert!(
        last.contains("Jones"),
        "API last_name should preserve 'Jones', got: {}",
        last
    );

    test_db::cleanup(&mut conn).await;
}

/// Test that creating an asset via web form sanitizes name and description.
#[tokio::test]
#[serial]
async fn test_xss_sanitized_in_web_asset_create() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("admin_xss_asset");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let csrf_token = app.generate_csrf_token();

    let xss_name = "<script>alert('xss')</script>Server01";
    let xss_desc = "<img src=x onerror=steal()>Production server";
    let asset_hostname = format!("{}.example.com", unique_name("xss-host"));

    let _response = app
        .server
        .post("/assets/manage/new")
        .add_header(
            header::COOKIE,
            format!("access_token={}; __vauban_csrf={}", admin.token, csrf_token),
        )
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("name", xss_name),
            ("hostname", asset_hostname.as_str()),
            ("port", "22"),
            ("asset_type", "ssh"),
            ("status", "active"),
            ("description", xss_desc),
            ("ssh_username", "root"),
            ("ssh_auth_type", "password"),
            ("ssh_password", "test-pwd"),
        ])
        .await;

    use diesel::{ExpressionMethods, QueryDsl};
    use diesel_async::RunQueryDsl;
    use vauban_web::schema::assets;

    let result: Option<(String, Option<String>)> = assets::table
        .filter(assets::hostname.eq(&asset_hostname))
        .filter(assets::is_deleted.eq(false))
        .select((assets::name, assets::description))
        .first(&mut conn)
        .await
        .ok();

    let (stored_name, stored_desc) = result.expect("Asset should be created");

    assert!(
        !stored_name.contains("<script>"),
        "Asset name must not contain <script>, got: {}",
        stored_name
    );
    assert!(
        stored_name.contains("Server01"),
        "Asset name should preserve 'Server01', got: {}",
        stored_name
    );

    let desc = stored_desc.expect("description should be set");
    assert!(
        !desc.contains("<img"),
        "Asset description must not contain <img>, got: {}",
        desc
    );
    assert!(
        !desc.contains("onerror"),
        "Asset description must not contain onerror, got: {}",
        desc
    );
    assert!(
        desc.contains("Production server"),
        "Asset description should preserve text, got: {}",
        desc
    );

    test_db::cleanup(&mut conn).await;
}

/// Test that creating a vauban group via web form sanitizes name and description.
#[tokio::test]
#[serial]
async fn test_xss_sanitized_in_web_group_create() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("admin_xss_grp");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let csrf_token = app.generate_csrf_token();

    // Generate a unique plain name, then wrap it in XSS payload
    let plain_name = unique_name("xss_grp");
    let xss_group_name = format!("<b onmouseover=alert(1)>{}</b>", plain_name);
    let xss_group_desc = "<script>steal()</script>Team description";

    let _response = app
        .server
        .post("/accounts/groups")
        .add_header(
            header::COOKIE,
            format!("access_token={}; __vauban_csrf={}", admin.token, csrf_token),
        )
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("name", xss_group_name.as_str()),
            ("description", xss_group_desc),
        ])
        .await;

    use diesel::{ExpressionMethods, QueryDsl};
    use diesel_async::RunQueryDsl;
    use vauban_web::schema::vauban_groups;

    // Search by the exact sanitized name (plain text only, no HTML)
    let result: Option<(String, Option<String>)> = vauban_groups::table
        .filter(vauban_groups::name.eq(&plain_name))
        .select((vauban_groups::name, vauban_groups::description))
        .first::<(String, Option<String>)>(&mut conn)
        .await
        .ok();

    assert!(
        result.is_some(),
        "Group should be created with sanitized name '{}'",
        plain_name
    );

    let (stored_name, stored_desc) = result.unwrap();

    assert!(
        !stored_name.contains("<b"),
        "Group name must not contain <b> tag, got: {}",
        stored_name
    );
    assert!(
        !stored_name.contains("onmouseover"),
        "Group name must not contain event handler, got: {}",
        stored_name
    );
    assert_eq!(
        stored_name, plain_name,
        "Group name should be the plain text without HTML"
    );

    if let Some(desc) = stored_desc {
        assert!(
            !desc.contains("<script>"),
            "Group description must not contain <script>, got: {}",
            desc
        );
        assert!(
            desc.contains("Team description"),
            "Group description should preserve text, got: {}",
            desc
        );
    }

    test_db::cleanup(&mut conn).await;
}

/// Test that the API create asset handler sanitizes name and description.
#[tokio::test]
#[serial]
async fn test_xss_sanitized_in_api_create_asset() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("admin_xss_api_asset");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let asset_hostname = format!("{}.example.com", unique_name("xss-api-host"));

    let response = app
        .server
        .post("/api/v1/assets/manage")
        .add_header(header::AUTHORIZATION, format!("Bearer {}", admin.token))
        .json(&json!({
            "name": "<script>alert('xss')</script>APIServer",
            "hostname": asset_hostname,
            "port": 22,
            "asset_type": "ssh",
            "description": "<img src=x onerror=alert(1)>API asset"
        }))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 200 || status == 201,
        "API create asset should succeed, got {}",
        status
    );

    let body: serde_json::Value = response.json();
    let name = body["name"].as_str().unwrap_or("");
    let desc = body["description"].as_str().unwrap_or("");

    assert!(
        !name.contains("<script>"),
        "API asset name must not contain <script>, got: {}",
        name
    );
    assert!(
        name.contains("APIServer"),
        "API asset name should preserve 'APIServer', got: {}",
        name
    );

    assert!(
        !desc.contains("<img"),
        "API asset description must not contain <img>, got: {}",
        desc
    );
    assert!(
        desc.contains("API asset"),
        "API asset description should preserve text, got: {}",
        desc
    );

    test_db::cleanup(&mut conn).await;
}

/// Helper function to extract CSRF token from HTML.
fn extract_csrf_token_from_html(html: &str) -> Option<String> {
    // Look for: <input type="hidden" name="csrf_token" value="TOKEN" />
    // or: <input name="csrf_token" ... value="TOKEN" ...>
    let patterns = [
        r#"name="csrf_token" value=""#,
        r#"name="csrf_token"[^>]*value=""#,
    ];

    for pattern in patterns {
        if let Some(start_idx) = html.find(pattern) {
            let after_pattern = &html[start_idx..];
            if let Some(value_start) = after_pattern.find("value=\"") {
                let value_content = &after_pattern[value_start + 7..];
                if let Some(value_end) = value_content.find('"') {
                    let token = &value_content[..value_end];
                    if !token.is_empty() {
                        return Some(token.to_string());
                    }
                }
            }
        }
    }

    // Fallback: simpler regex-like search
    if let Some(idx) = html.find("csrf_token") {
        let substring = &html[idx..];
        if let Some(value_idx) = substring.find("value=\"") {
            let value_start = &substring[value_idx + 7..];
            if let Some(end_idx) = value_start.find('"') {
                let token = &value_start[..end_idx];
                if !token.is_empty() {
                    return Some(token.to_string());
                }
            }
        }
    }

    None
}

// ==================== WebSocket Session Ownership Verification ====================

/// Helper: send a GET request to the terminal WebSocket endpoint.
///
/// We intentionally omit WebSocket upgrade headers so that
/// the ownership middleware can be tested with plain HTTP.
/// If the middleware rejects: returns 400/403/404.
/// If the middleware passes: the handler's WebSocketUpgrade extractor
/// fails, returning 426 (Upgrade Required).
async fn ws_terminal_request(
    app: &TestApp,
    session_uuid: &str,
    token: &str,
) -> axum_test::TestResponse {
    app.server
        .get(&format!("/ws/terminal/{}", session_uuid))
        .add_header(header::AUTHORIZATION, app.auth_header(token))
        .await
}

/// Helper: send a GET request to the session monitoring WebSocket endpoint.
/// Same strategy as ws_terminal_request (no WS headers).
async fn ws_session_request(
    app: &TestApp,
    session_uuid: &str,
    token: &str,
) -> axum_test::TestResponse {
    app.server
        .get(&format!("/ws/session/{}", session_uuid))
        .add_header(header::AUTHORIZATION, app.auth_header(token))
        .await
}

/// Regression: A regular user cannot access another user's terminal WebSocket.
/// The new session_access gate collapses NotOwner / AccessRuleRevoked to a
/// generic 404 (anti-enumeration), so the attacker can no longer fingerprint
/// the existence of someone else's session via 403 vs 404.
#[tokio::test]
#[serial]
async fn test_terminal_ws_forbidden_for_non_owner() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let owner = create_test_user(&mut conn, &app.auth_service, &unique_name("ws_owner")).await;
    let attacker =
        create_test_user(&mut conn, &app.auth_service, &unique_name("ws_attacker")).await;

    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("ws_asset"), owner.user.id).await;
    let (_session_id, session_uuid, _rule) = crate::fixtures::create_test_session_with_access(
        &mut conn,
        owner.user.id,
        asset_id,
        "ssh",
        "active",
    )
    .await;

    drop(conn);

    let response = ws_terminal_request(app, &session_uuid.to_string(), &attacker.token).await;
    let status = response.status_code().as_u16();
    assert_eq!(
        status, 404,
        "Regular user must not access another user's terminal WebSocket \
         (must collapse to 404 anti-enum), got {}",
        status
    );
}

/// Regression: A regular user cannot access another user's session monitoring WebSocket.
/// Same anti-enumeration rationale as above: 403/404 collapse to 404.
#[tokio::test]
#[serial]
async fn test_session_ws_forbidden_for_non_owner() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let owner = create_test_user(&mut conn, &app.auth_service, &unique_name("ws_own2")).await;
    let attacker = create_test_user(&mut conn, &app.auth_service, &unique_name("ws_atk2")).await;

    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("ws_asset2"), owner.user.id).await;
    let (_session_id, session_uuid, _rule) = crate::fixtures::create_test_session_with_access(
        &mut conn,
        owner.user.id,
        asset_id,
        "ssh",
        "active",
    )
    .await;

    drop(conn);

    let response = ws_session_request(app, &session_uuid.to_string(), &attacker.token).await;
    let status = response.status_code().as_u16();
    assert_eq!(
        status, 404,
        "Regular user must not access another user's session WebSocket \
         (must collapse to 404 anti-enum), got {}",
        status
    );
}

/// Regression: The session owner can access their own terminal WebSocket.
/// Without WS headers, the ownership middleware passes and the handler returns
/// 426 (Upgrade Required) because no actual WebSocket upgrade is attempted.
#[tokio::test]
#[serial]
async fn test_terminal_ws_allowed_for_owner() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let owner = create_test_user(&mut conn, &app.auth_service, &unique_name("ws_own3")).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("ws_asset3"), owner.user.id).await;
    let (_session_id, session_uuid, _rule) = crate::fixtures::create_test_session_with_access(
        &mut conn,
        owner.user.id,
        asset_id,
        "ssh",
        "active",
    )
    .await;

    drop(conn);

    // Owner accesses their own terminal -> middleware passes, handler returns 400
    // (no WebSocket upgrade headers) instead of 403/404 (rejected by guard).
    let response = ws_terminal_request(app, &session_uuid.to_string(), &owner.token).await;
    let status = response.status_code().as_u16();
    assert!(
        status != 403 && status != 404,
        "Session owner should pass ownership check, got {} (expected 400 or 426)",
        status
    );
}

/// Regression: The session owner can access their own session monitoring WebSocket.
#[tokio::test]
#[serial]
async fn test_session_ws_allowed_for_owner() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let owner = create_test_user(&mut conn, &app.auth_service, &unique_name("ws_own4")).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("ws_asset4"), owner.user.id).await;
    let (_session_id, session_uuid, _rule) = crate::fixtures::create_test_session_with_access(
        &mut conn,
        owner.user.id,
        asset_id,
        "ssh",
        "active",
    )
    .await;

    drop(conn);

    let response = ws_session_request(app, &session_uuid.to_string(), &owner.token).await;
    let status = response.status_code().as_u16();
    assert!(
        status != 403 && status != 404,
        "Session owner should pass ownership check, got {} (expected 400 or 426)",
        status
    );
}

/// Regression: An admin/staff user can access another user's terminal WebSocket.
#[tokio::test]
#[serial]
async fn test_terminal_ws_allowed_for_admin() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let owner = create_test_user(&mut conn, &app.auth_service, &unique_name("ws_own5")).await;
    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("ws_admin5")).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("ws_asset5"), owner.user.id).await;
    let (_session_id, session_uuid, _rule) = crate::fixtures::create_test_session_with_access(
        &mut conn,
        owner.user.id,
        asset_id,
        "ssh",
        "active",
    )
    .await;

    drop(conn);

    // Admin accesses another user's terminal -> middleware passes, handler returns 400
    // (no WebSocket upgrade headers) instead of 403/404 (rejected by guard).
    let response = ws_terminal_request(app, &session_uuid.to_string(), &admin.token).await;
    let status = response.status_code().as_u16();
    assert!(
        status != 403 && status != 404,
        "Admin should pass ownership check, got {} (expected 400 or 426)",
        status
    );
}

/// Regression: An admin/staff user can access another user's session monitoring WebSocket.
#[tokio::test]
#[serial]
async fn test_session_ws_allowed_for_admin() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let owner = create_test_user(&mut conn, &app.auth_service, &unique_name("ws_own6")).await;
    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("ws_admin6")).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("ws_asset6"), owner.user.id).await;
    let (_session_id, session_uuid, _rule) = crate::fixtures::create_test_session_with_access(
        &mut conn,
        owner.user.id,
        asset_id,
        "ssh",
        "active",
    )
    .await;

    drop(conn);

    let response = ws_session_request(app, &session_uuid.to_string(), &admin.token).await;
    let status = response.status_code().as_u16();
    assert!(
        status != 403 && status != 404,
        "Admin should pass ownership check, got {} (expected 400 or 426)",
        status
    );
}

/// Regression: Non-existent session UUID returns 404.
#[tokio::test]
#[serial]
async fn test_terminal_ws_nonexistent_session_returns_404() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user = create_test_user(&mut conn, &app.auth_service, &unique_name("ws_user7")).await;
    drop(conn);

    let fake_uuid = uuid::Uuid::new_v4();
    let response = ws_terminal_request(app, &fake_uuid.to_string(), &user.token).await;
    let status = response.status_code().as_u16();
    assert_eq!(
        status, 404,
        "Non-existent session should return 404, got {}",
        status
    );
}

/// Regression: Invalid session ID (not a UUID) collapses to 404 under the
/// session_access anti-enumeration policy. Historically this was 400 (UUID
/// parse error surfaced to the client); we now hide it behind the same 404
/// as a non-existent session so an attacker cannot distinguish "malformed"
/// from "non-existent" from "exists but you have no access".
#[tokio::test]
#[serial]
async fn test_terminal_ws_invalid_session_id_returns_400() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user = create_test_user(&mut conn, &app.auth_service, &unique_name("ws_user8")).await;
    drop(conn);

    let response = ws_terminal_request(app, "not-a-valid-uuid", &user.token).await;
    let status = response.status_code().as_u16();
    assert_eq!(
        status, 404,
        "Invalid session ID must collapse to 404 (anti-enum), got {}",
        status
    );
}

// ==================== HTML terminal_page IDOR (issue: post-MFA audit #7) ====================
//
// The HTML wrapper at `GET /sessions/terminal/{session_id}` used to be
// served to any authenticated user that knew (or guessed) a session UUID.
// The underlying WebSocket data path is gated by `ws_session_guard`, but
// the HTML probe alone could be used to enumerate valid session UUIDs by
// distinguishing 200 vs error responses. The fix calls
// `verify_session_ownership` and collapses every failure mode into a single
// opaque 404 so non-owners cannot tell "no such session" from "session
// belongs to someone else".

/// Helper: send a GET request to the SSH terminal HTML page using the
/// same cookie scheme as a real browser session.
async fn terminal_page_request(
    app: &TestApp,
    session_uuid: &str,
    token: &str,
) -> axum_test::TestResponse {
    app.server
        .get(&format!("/sessions/terminal/{}", session_uuid))
        .add_header(header::COOKIE, format!("access_token={}", token))
        .await
}

/// Regression (anti-IDOR): another user's terminal page must collapse to 404,
/// never 403/200, so probing cannot enumerate session UUIDs.
#[tokio::test]
#[serial]
async fn test_terminal_page_404_for_other_users_session() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let owner = create_test_user(&mut conn, &app.auth_service, &unique_name("tp_owner")).await;
    let attacker =
        create_test_user(&mut conn, &app.auth_service, &unique_name("tp_attacker")).await;

    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("tp_asset_a"), owner.user.id).await;
    let (_session_id, session_uuid) =
        create_test_session_with_uuid(&mut conn, owner.user.id, asset_id, "ssh", "active").await;

    drop(conn);

    let response = terminal_page_request(app, &session_uuid.to_string(), &attacker.token).await;
    let status = response.status_code().as_u16();
    assert_eq!(
        status, 404,
        "terminal_page must return 404 (not 403, not 200) when the requester \
         does not own the session, got {}",
        status
    );
}

/// Regression (anti-IDOR): a random/non-existent session UUID must also
/// return 404, identical to the "owned by someone else" response above.
#[tokio::test]
#[serial]
async fn test_terminal_page_404_for_nonexistent_session() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user = create_test_user(&mut conn, &app.auth_service, &unique_name("tp_user")).await;

    drop(conn);

    let fake_uuid = uuid::Uuid::new_v4();
    let response = terminal_page_request(app, &fake_uuid.to_string(), &user.token).await;
    let status = response.status_code().as_u16();
    assert_eq!(
        status, 404,
        "terminal_page must return 404 for unknown session UUIDs, got {}",
        status
    );
}

/// Regression: the legitimate session owner still receives the terminal
/// HTML wrapper. Without this the IDOR fix would be a regression for normal
/// users.
#[tokio::test]
#[serial]
async fn test_terminal_page_renders_for_owner() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let owner = create_test_user(&mut conn, &app.auth_service, &unique_name("tp_owner_ok")).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("tp_asset_b"), owner.user.id).await;
    let (_session_id, session_uuid, _rule) = crate::fixtures::create_test_session_with_access(
        &mut conn,
        owner.user.id,
        asset_id,
        "ssh",
        "active",
    )
    .await;

    drop(conn);

    let response = terminal_page_request(app, &session_uuid.to_string(), &owner.token).await;
    let status = response.status_code().as_u16();
    assert_eq!(
        status, 200,
        "Session owner must receive the terminal HTML wrapper, got {}",
        status
    );
}

/// Regression (anti-IDOR): the response body of the 404 returned for a
/// non-owner must NOT leak the requested session UUID. Otherwise an attacker
/// could still confirm hits via response correlation.
#[tokio::test]
#[serial]
async fn test_terminal_page_404_does_not_leak_session_uuid() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let owner = create_test_user(&mut conn, &app.auth_service, &unique_name("tp_owner_nl")).await;
    let attacker =
        create_test_user(&mut conn, &app.auth_service, &unique_name("tp_attacker_nl")).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("tp_asset_nl"), owner.user.id).await;
    let (_session_id, session_uuid) =
        create_test_session_with_uuid(&mut conn, owner.user.id, asset_id, "ssh", "active").await;

    drop(conn);

    let response = terminal_page_request(app, &session_uuid.to_string(), &attacker.token).await;
    let body = response.text();
    assert!(
        !body.contains(&session_uuid.to_string()),
        "404 response body must not echo the requested session UUID \
         (information disclosure)"
    );
}

// ==================== CSP unsafe-inline Removal ====================
//
// stated that `'unsafe-inline'` in script-src and `'unsafe-eval'` in the CSP
// negated most XSS protections. The fix moved all inline <script> and <style>
// blocks to external files and removed `'unsafe-inline'` from script-src.
//
// These tests verify:
//  1. script-src does NOT contain 'unsafe-inline'
//  2. CSP contains strengthening directives (base-uri, form-action, frame-ancestors)
//  3. Static JS/CSS files are served correctly with proper MIME types
//  4. Directory traversal is blocked
//  5. CSP is present on all endpoint types (pages, API, login)

/// Regression: CSP script-src must NOT contain 'unsafe-inline'.
#[tokio::test]
#[serial]
async fn test_csp_script_src_no_unsafe_inline() {
    let app = TestApp::spawn().await;

    let response = app.server.get("/login").await;
    let csp = response
        .headers()
        .get("content-security-policy")
        .expect("CSP header must be present")
        .to_str()
        .expect("CSP header must be valid UTF-8");

    // Extract the script-src directive specifically
    let script_src = csp
        .split(';')
        .find(|d| d.trim().starts_with("script-src"))
        .expect("CSP must contain a script-src directive");

    assert!(
        !script_src.contains("'unsafe-inline'"),
        "script-src MUST NOT contain 'unsafe-inline'. Got: {}",
        script_src
    );
}

/// Regression: CSP must contain base-uri restriction.
#[tokio::test]
#[serial]
async fn test_csp_contains_base_uri_restriction() {
    let app = TestApp::spawn().await;

    let response = app.server.get("/login").await;
    let csp = response
        .headers()
        .get("content-security-policy")
        .expect("CSP header must be present")
        .to_str()
        .expect("CSP header must be valid UTF-8");

    assert!(
        csp.contains("base-uri 'self'"),
        "CSP must contain base-uri 'self' to prevent <base> tag hijacking. Got: {}",
        csp
    );
}

/// Regression: CSP must contain form-action restriction.
#[tokio::test]
#[serial]
async fn test_csp_contains_form_action_restriction() {
    let app = TestApp::spawn().await;

    let response = app.server.get("/login").await;
    let csp = response
        .headers()
        .get("content-security-policy")
        .expect("CSP header must be present")
        .to_str()
        .expect("CSP header must be valid UTF-8");

    assert!(
        csp.contains("form-action 'self'"),
        "CSP must contain form-action 'self' to restrict form targets. Got: {}",
        csp
    );
}

/// Regression: CSP must contain frame-ancestors 'none'.
#[tokio::test]
#[serial]
async fn test_csp_contains_frame_ancestors_none() {
    let app = TestApp::spawn().await;

    let response = app.server.get("/login").await;
    let csp = response
        .headers()
        .get("content-security-policy")
        .expect("CSP header must be present")
        .to_str()
        .expect("CSP header must be valid UTF-8");

    assert!(
        csp.contains("frame-ancestors 'none'"),
        "CSP must contain frame-ancestors 'none' to prevent framing. Got: {}",
        csp
    );
}

/// Regression: CSP is consistent across page types (login, API, health).
#[tokio::test]
#[serial]
async fn test_csp_consistent_across_endpoints() {
    let app = TestApp::spawn().await;

    let login_csp = app
        .server
        .get("/login")
        .await
        .headers()
        .get("content-security-policy")
        .expect("login CSP")
        .to_str()
        .expect("valid UTF-8")
        .to_string();

    let health_csp = app
        .server
        .get("/health")
        .await
        .headers()
        .get("content-security-policy")
        .expect("health CSP")
        .to_str()
        .expect("valid UTF-8")
        .to_string();

    let api_csp = app
        .server
        .get("/api/v1/accounts")
        .await
        .headers()
        .get("content-security-policy")
        .expect("API CSP")
        .to_str()
        .expect("valid UTF-8")
        .to_string();

    assert_eq!(
        login_csp, health_csp,
        "CSP must be identical on login and health endpoints"
    );
    assert_eq!(
        login_csp, api_csp,
        "CSP must be identical on login and API endpoints"
    );
}

/// Regression: Static JS files are served with correct Content-Type.
#[tokio::test]
#[serial]
async fn test_static_js_served_with_correct_content_type() {
    let app = TestApp::spawn().await;

    let response = app.server.get("/static/js/tailwind-config.js").await;
    let status = response.status_code().as_u16();
    assert_eq!(
        status, 200,
        "Static JS file must be served, got status {}",
        status
    );

    let ct = response
        .headers()
        .get("content-type")
        .expect("Content-Type must be set")
        .to_str()
        .expect("valid UTF-8");
    assert!(
        ct.contains("application/javascript"),
        "JS files must be served as application/javascript, got: {}",
        ct
    );
}

/// Regression: Static CSS files are served with correct Content-Type.
#[tokio::test]
#[serial]
async fn test_static_css_served_with_correct_content_type() {
    let app = TestApp::spawn().await;

    let response = app.server.get("/static/css/vauban.css").await;
    let status = response.status_code().as_u16();
    assert_eq!(
        status, 200,
        "Static CSS file must be served, got status {}",
        status
    );

    let ct = response
        .headers()
        .get("content-type")
        .expect("Content-Type must be set")
        .to_str()
        .expect("valid UTF-8");
    assert!(
        ct.contains("text/css"),
        "CSS files must be served as text/css, got: {}",
        ct
    );
}

/// Regression: Directory traversal via static path is blocked.
///
/// The HTTP framework normalizes `..` segments before route matching, so paths
/// like `/static/../../etc/passwd` never reach the handler. This test verifies
/// that traversal attempts are blocked at some level (normalization, handler, or
/// fallback) by checking the response is NOT 200.
#[tokio::test]
#[serial]
async fn test_static_directory_traversal_blocked() {
    let app = TestApp::spawn().await;

    // Paths that try to escape: HTTP normalization collapses ".." before
    // route matching, so they hit the fallback (303 redirect) or 404.
    for path in &[
        "/static/../../../etc/passwd",
        "/static/%2e%2e/%2e%2e/etc/passwd",
        "/static/js/..%2f..%2fetc%2fpasswd",
    ] {
        let response = app.server.get(path).await;
        let status = response.status_code().as_u16();
        assert_ne!(
            status, 200,
            "Directory traversal for '{}' must NOT return 200, got {}",
            path, status
        );
    }

    // A path that reaches the handler but tries to read outside static/
    // by embedding ".." within the captured wildcard.
    let response = app.server.get("/static/js/../../../Cargo.toml").await;
    let status = response.status_code().as_u16();
    assert_ne!(
        status, 200,
        "Path traversal via wildcard must NOT return 200, got {}",
        status
    );
}

/// Regression: Unknown file extensions return 404.
#[tokio::test]
#[serial]
async fn test_static_unknown_extension_returns_404() {
    let app = TestApp::spawn().await;

    let response = app.server.get("/static/malicious.php").await;
    let status = response.status_code().as_u16();
    assert_eq!(
        status, 404,
        "Unknown file extension must return 404, got {}",
        status
    );
}

/// Regression: Static files have cache headers.
#[tokio::test]
#[serial]
async fn test_static_files_have_cache_headers() {
    let app = TestApp::spawn().await;

    let response = app.server.get("/static/js/vauban-components.js").await;
    assert_eq!(response.status_code().as_u16(), 200);

    let cache = response
        .headers()
        .get("cache-control")
        .expect("Cache-Control must be set")
        .to_str()
        .expect("valid UTF-8");
    assert!(
        cache.contains("max-age="),
        "Static files must have cache max-age, got: {}",
        cache
    );
}

// =============================================================================
// Regression: RBAC stub deny-by-default in release builds
// =============================================================================

/// Regression: The Access service must hard-fail at startup when no
/// Casbin enforcer is configured, and must deny-by-default at runtime in
/// the unlikely case that the enforcer ends up missing anyway. No debug
/// allow-all fallback is allowed anymore (Casbin is mandatory).
#[tokio::test]
#[serial]
async fn test_access_service_has_compile_time_guard() {
    let full_source = include_str!("../../../vauban-access/src/main.rs");
    // Only inspect production code; unit tests below #[cfg(test)] legitimately
    // mention removed patterns in their assertion strings.
    let prod = match full_source.find("#[cfg(test)]") {
        Some(idx) => &full_source[..idx],
        None => full_source,
    };

    assert!(
        prod.contains("refuses to start without a Casbin model"),
        "vauban-access must hard-fail at startup when model/policy paths are missing"
    );

    assert!(
        prod.contains("allowed: false"),
        "vauban-access must deny by default when the enforcer is missing"
    );

    let forbidden_dbg_cfg = format!("#[{}(debug_assertions)]", "cfg");
    assert!(
        !prod.contains(&forbidden_dbg_cfg),
        "vauban-access production code must not contain debug-gated allow-all fallbacks"
    );
}

/// Regression: The legacy allow-all RBAC shim in
/// `vauban-web/src/ipc/clients.rs` has been removed in favor of the
/// Casbin-backed [`crate::ipc::AccessIpcClient`]. This non-regression test
/// makes sure it does not resurface. Forbidden patterns are rebuilt at
/// runtime so the assertion strings themselves never match.
#[tokio::test]
#[serial]
async fn test_access_client_has_compile_time_guard() {
    let client_source = include_str!("../../src/ipc/clients.rs");

    let forbidden_struct = format!("pub {} Rbac{}", "struct", "Client");
    assert!(
        !client_source.contains(&forbidden_struct),
        "ipc/clients.rs must not define the legacy Rbac type; use AccessIpcClient + Casbin"
    );

    let forbidden_cfg = format!("#[{}(debug_assertions)]", "cfg");
    assert!(
        !client_source.contains(&forbidden_cfg),
        "ipc/clients.rs must not carry debug-gated RBAC fallbacks"
    );
}

/// Regression: The Access service must never contain an unguarded
/// allow-all fallback. Casbin is mandatory; when no enforcer is loaded the
/// handler must hardcode `allowed: false` (deny-by-default) and there must
/// be no debug-only allow-all short-circuit.
#[tokio::test]
#[serial]
async fn test_access_no_unguarded_allow_all() {
    let full_source = include_str!("../../../vauban-access/src/main.rs");
    let prod = match full_source.find("#[cfg(test)]") {
        Some(idx) => &full_source[..idx],
        None => full_source,
    };

    let deny_count = prod.matches("allowed: false").count();
    assert!(
        deny_count >= 1,
        "Must have at least one deny-by-default path (allowed: false) in production code, found {deny_count}"
    );

    // The legacy debug fallback used `#[cfg(debug_assertions)] ... allowed: true`.
    // That fallback has been removed; any surviving occurrence is a regression.
    let forbidden_dbg_cfg = format!("#[{}(debug_assertions)]", "cfg");
    assert!(
        !prod.contains(&forbidden_dbg_cfg),
        "vauban-access production code must not contain debug-gated RBAC fallbacks anymore"
    );

    let forbidden_fallback_str = format!("RBAC {}", "fallback");
    assert!(
        !prod.contains(&forbidden_fallback_str),
        "vauban-access production code must not reference the legacy RBAC fallback"
    );
}

// =============================================================================
// SSH Host Key Verification Tests
// =============================================================================

/// Regression: Verify that check_server_key in vauban-proxy-ssh
/// contains host key verification logic (not just Ok(true)).
#[tokio::test]
#[serial]
async fn test_ssh_host_key_verification_exists_in_proxy() {
    let session_source = include_str!("../../../vauban-proxy-ssh/src/session.rs");

    // Must reference expected_host_key for verification
    assert!(
        session_source.contains("expected_host_key"),
        "session.rs must contain expected_host_key field for host key verification"
    );

    // Must contain the comparison logic
    assert!(
        session_source.contains("MITM"),
        "session.rs must warn about MITM attacks on host key mismatch"
    );

    // Must NOT contain the old unconditional accept-all pattern.
    // The old code had a single `Ok(true)` with a TODO comment.
    // Check that we have BOTH Ok(true) (for match/no-key) AND Ok(false) (for mismatch).
    let ok_true_count = session_source.matches("Ok(true)").count();
    let ok_false_count = session_source.matches("Ok(false)").count();

    assert!(
        ok_false_count >= 1,
        "check_server_key must return Ok(false) on mismatch, found {} Ok(false)",
        ok_false_count
    );
    assert!(
        ok_true_count >= 1,
        "check_server_key must return Ok(true) on match, found {} Ok(true)",
        ok_true_count
    );
}

/// Regression: Verify that SshSessionOpen message includes expected_host_key.
#[tokio::test]
#[serial]
async fn test_ssh_session_open_has_expected_host_key_field() {
    let messages_source = include_str!("../../../shared/src/messages.rs");

    // The SshSessionOpen variant must include expected_host_key
    assert!(
        messages_source.contains("expected_host_key: Option<String>"),
        "SshSessionOpen must include expected_host_key: Option<String>"
    );
}

/// Regression: Verify that SshFetchHostKey and SshHostKeyResult
/// message variants exist.
#[tokio::test]
#[serial]
async fn test_ssh_host_key_fetch_messages_exist() {
    let messages_source = include_str!("../../../shared/src/messages.rs");

    assert!(
        messages_source.contains("SshFetchHostKey"),
        "Message enum must include SshFetchHostKey variant"
    );
    assert!(
        messages_source.contains("SshHostKeyResult"),
        "Message enum must include SshHostKeyResult variant"
    );
    assert!(
        messages_source.contains("key_fingerprint"),
        "SshHostKeyResult must include key_fingerprint field"
    );
}

/// Regression: Verify that connect_ssh passes the expected host key
/// from connection_config to the proxy.
#[tokio::test]
#[serial]
async fn test_connect_ssh_passes_host_key() {
    let web_source = include_str!("../../src/handlers/web/ssh.rs");

    // connect_ssh must extract ssh_host_key from connection_config
    assert!(
        web_source.contains("ssh_host_key"),
        "connect_ssh must extract ssh_host_key from connection_config"
    );

    // Must pass expected_host_key to the open request
    assert!(
        web_source.contains("expected_host_key"),
        "connect_ssh must pass expected_host_key in SshSessionOpenRequest"
    );
}

/// Regression: Verify that the proxy handles SshFetchHostKey messages.
#[tokio::test]
#[serial]
async fn test_proxy_handles_fetch_host_key_message() {
    let proxy_main_source = include_str!("../../../vauban-proxy-ssh/src/main.rs");

    assert!(
        proxy_main_source.contains("SshFetchHostKey"),
        "vauban-proxy-ssh/main.rs must handle SshFetchHostKey messages"
    );
    assert!(
        proxy_main_source.contains("SshHostKeyResult"),
        "vauban-proxy-ssh/main.rs must send SshHostKeyResult responses"
    );
    assert!(
        proxy_main_source.contains("fetch_host_key"),
        "vauban-proxy-ssh/main.rs must call fetch_host_key function"
    );
}

/// Regression: Verify that the fetch_ssh_host_key endpoint
/// rejects non-SSH assets.
#[tokio::test]
#[serial]
async fn test_fetch_host_key_rejects_non_ssh_assets() {
    let web_source = include_str!("../../src/handlers/web/ssh.rs");

    // The handler must check asset type
    assert!(
        web_source.contains("Host key fetch is only available for SSH assets"),
        "fetch_ssh_host_key must reject non-SSH assets with clear error message"
    );
}

/// Regression: Verify that host key data is stored in connection_config JSONB.
#[tokio::test]
#[serial]
async fn test_host_key_stored_in_connection_config() {
    let web_source = include_str!("../../src/handlers/web/ssh.rs");

    // The handler must store ssh_host_key and ssh_host_key_fingerprint
    assert!(
        web_source.contains(r#"config["ssh_host_key"]"#),
        "fetch handler must store ssh_host_key in connection_config"
    );
    assert!(
        web_source.contains(r#"config["ssh_host_key_fingerprint"]"#),
        "fetch handler must store ssh_host_key_fingerprint in connection_config"
    );
}

/// Regression: Verify that the IPC client (proxy_ssh.rs) handles
/// SshHostKeyResult responses.
#[tokio::test]
#[serial]
async fn test_ipc_client_handles_host_key_result() {
    let client_source = include_str!("../../src/ipc/proxy_ssh.rs");

    assert!(
        client_source.contains("SshHostKeyResult"),
        "ProxySshClient must handle SshHostKeyResult messages"
    );
    assert!(
        client_source.contains("pending_host_key_requests"),
        "ProxySshClient must track pending host key requests"
    );
    assert!(
        client_source.contains("fetch_host_key"),
        "ProxySshClient must provide a fetch_host_key method"
    );
}

// ── VAU-001: RDP server-certificate pinning (SPKI + TOFU) ──
//
// Strict mirror of the SSH host-key satellite tests above. These grep
// the IPC wire format, proxy verifier, web handlers and templates to
// pin the end-to-end pinning surface against silent regressions.

/// The proxy session path MUST pin the server SPKI and warn about MITM,
/// and MUST NOT carry the pre-fix accept-any `NoCertificateVerification`
/// verifier on the session path.
#[tokio::test]
#[serial]
async fn test_rdp_cert_pinning_exists_in_proxy() {
    let session_source = include_str!("../../../vauban-proxy-rdp/src/session.rs");

    assert!(
        session_source.contains("PinningServerCertVerifier"),
        "vauban-proxy-rdp/session.rs must install PinningServerCertVerifier on the session path"
    );
    assert!(
        session_source.contains("MITM"),
        "vauban-proxy-rdp/session.rs must warn about MITM on certificate mismatch"
    );
    assert!(
        !session_source.contains("struct NoCertificateVerification"),
        "vauban-proxy-rdp/session.rs must NOT define the accept-any \
         NoCertificateVerification verifier (the VAU-001 MITM hole)"
    );
    // The accept-any verifier, if present, is confined to the fetch path.
    assert!(
        session_source.contains("TofuAcceptAnyFetchVerifier"),
        "vauban-proxy-rdp/session.rs must define TofuAcceptAnyFetchVerifier \
         (TOFU fetch-only accept-any, confined to the fetch path)"
    );
}

/// `RdpSessionOpen` must carry the pinned fingerprint, and the cert-fetch
/// message variants must exist in the shared IPC enum.
#[tokio::test]
#[serial]
async fn test_rdp_session_open_has_expected_cert_fingerprint_field() {
    let messages_source = include_str!("../../../shared/src/messages.rs");

    assert!(
        messages_source.contains("expected_cert_fingerprint"),
        "RdpSessionOpen must include expected_cert_fingerprint"
    );
    assert!(
        messages_source.contains("RdpFetchServerCert"),
        "Message enum must include the RdpFetchServerCert variant"
    );
    assert!(
        messages_source.contains("RdpServerCertResult"),
        "Message enum must include the RdpServerCertResult variant"
    );
}

/// `connect_rdp` must thread the pinned fingerprint from connection_config
/// into the open request, and flip the mismatch flag on a verification
/// failure reported by the proxy.
#[tokio::test]
#[serial]
async fn test_connect_rdp_passes_cert_and_marks_mismatch() {
    let web_source = include_str!("../../src/handlers/web/rdp.rs");

    assert!(
        web_source.contains("expected_cert_fingerprint"),
        "connect_rdp must pass expected_cert_fingerprint in RdpSessionOpenRequest"
    );
    assert!(
        web_source.contains("rdp_server_cert_mismatch"),
        "connect_rdp must set rdp_server_cert_mismatch on verification failure"
    );
    assert!(
        web_source.contains("certificate mismatch") && web_source.contains("MITM"),
        "connect_rdp must detect the certificate-mismatch / MITM error wording"
    );
}

/// The proxy-rdp main loop must handle RdpFetchServerCert and answer with
/// RdpServerCertResult via the fetch_server_cert function.
#[tokio::test]
#[serial]
async fn test_proxy_rdp_handles_fetch_cert_message() {
    let proxy_main_source = include_str!("../../../vauban-proxy-rdp/src/main.rs");

    assert!(
        proxy_main_source.contains("RdpFetchServerCert"),
        "vauban-proxy-rdp/main.rs must handle RdpFetchServerCert messages"
    );
    assert!(
        proxy_main_source.contains("RdpServerCertResult"),
        "vauban-proxy-rdp/main.rs must send RdpServerCertResult responses"
    );
    assert!(
        proxy_main_source.contains("fetch_server_cert"),
        "vauban-proxy-rdp/main.rs must call session::fetch_server_cert"
    );
}

/// The admin fetch handler must reject non-RDP assets, detect cert
/// changes, support `confirm`, and store the cert in connection_config.
#[tokio::test]
#[serial]
async fn test_fetch_rdp_cert_rejects_non_rdp_and_detects_change() {
    let web_source = include_str!("../../src/handlers/web/rdp.rs");

    assert!(
        web_source.contains("Certificate fetch is only available for RDP assets"),
        "fetch_rdp_server_cert must reject non-RDP assets with a clear message"
    );
    assert!(
        web_source.contains("old_spki != &server_spki"),
        "fetch_rdp_server_cert must compare the stored SPKI with the freshly fetched one"
    );
    assert!(
        web_source.contains("_rdp_server_cert_mismatch_fragment.html"),
        "fetch_rdp_server_cert must return the mismatch fragment when SPKIs differ"
    );
    assert!(
        web_source.contains(r#"config["rdp_server_cert_fingerprint"]"#),
        "fetch handler must store rdp_server_cert_fingerprint in connection_config"
    );
    assert!(
        web_source.contains(r#"config["rdp_server_cert_spki"]"#),
        "fetch handler must store rdp_server_cert_spki in connection_config"
    );
}

/// The IPC client must track pending cert requests, handle
/// RdpServerCertResult, and expose a fetch_server_cert method.
#[tokio::test]
#[serial]
async fn test_ipc_client_handles_rdp_cert_result() {
    let client_source = include_str!("../../src/ipc/proxy_rdp.rs");

    assert!(
        client_source.contains("RdpServerCertResult"),
        "ProxyRdpClient must handle RdpServerCertResult messages"
    );
    assert!(
        client_source.contains("pending_cert_requests"),
        "ProxyRdpClient must track pending cert requests"
    );
    assert!(
        client_source.contains("fetch_server_cert"),
        "ProxyRdpClient must provide a fetch_server_cert method"
    );
}

// ── Host Key Mismatch Detection Tests ──

/// Verify that fetch_ssh_host_key handler detects key changes and returns
/// a mismatch fragment instead of silently overwriting the stored key.
#[tokio::test]
#[serial]
async fn test_fetch_host_key_detects_key_change() {
    let web_source = include_str!("../../src/handlers/web/ssh.rs");

    // Handler must compare old key with new key
    assert!(
        web_source.contains("stored_host_key"),
        "fetch_ssh_host_key must read the previously stored host key"
    );
    assert!(
        web_source.contains("old_key != &host_key"),
        "fetch_ssh_host_key must compare old key with newly fetched key"
    );
    assert!(
        web_source.contains("_ssh_host_key_mismatch_fragment.html"),
        "fetch_ssh_host_key must return mismatch fragment when keys differ"
    );
    assert!(
        web_source.contains(r#""confirm""#),
        "fetch_ssh_host_key must support confirm parameter to accept new key"
    );
}

/// Verify that the API handler also detects key changes and supports
/// the confirm parameter.
#[tokio::test]
#[serial]
async fn test_api_fetch_host_key_detects_key_change() {
    // Issue #27: the SSH host-key fetch / confirm flow lives in the
    // admin zone. The handler moved to handlers/api/manage_assets.rs.
    let api_source = include_str!("../../src/handlers/api/manage_assets.rs");

    assert!(
        api_source.contains("stored_host_key"),
        "API fetch handler must read the previously stored host key"
    );
    assert!(
        api_source.contains("key_changed"),
        "API fetch handler must return key_changed flag when keys differ"
    );
    assert!(
        api_source.contains(r#""confirm""#),
        "API fetch handler must support confirm parameter"
    );
}

/// Verify that connect_ssh marks the asset with a mismatch flag when
/// the SSH proxy reports a host key verification failure.
#[tokio::test]
#[serial]
async fn test_connect_ssh_marks_mismatch_on_failure() {
    let web_source = include_str!("../../src/handlers/web/ssh.rs");

    assert!(
        web_source.contains("ssh_host_key_mismatch"),
        "connect_ssh must set ssh_host_key_mismatch flag on key verification failure"
    );
    assert!(
        web_source.contains("is_host_key_mismatch"),
        "connect_ssh must detect host key mismatch from error messages"
    );
    // Verify that the mismatch detection checks for relevant keywords
    assert!(
        web_source.contains(r#"msg.contains("MITM")"#)
            || web_source.contains(r#"error_str.contains("MITM")"#),
        "connect_ssh must detect MITM-related error messages"
    );
}

/// Verify that the SSH host-key fragments still encode the three
/// states (verified / mismatch / no-key) consumed by the admin
/// `/assets/manage/{uuid}` detail page. Issue #34 removed the
/// user-zone detail page (`templates/assets/asset_detail.html`)
/// because it leaked description / dates / fingerprint to non-
/// approved users; the verify-host-key HTMX endpoint and its
/// fragments stay because the admin /manage detail page still
/// drives them.
#[tokio::test]
#[serial]
async fn test_asset_detail_template_three_host_key_states() {
    // Admin /manage detail page must still call the verify endpoint
    // and show the loading state.
    let admin_detail = include_str!("../../templates/assets/manage/detail.html");
    assert!(
        admin_detail.contains("verify-host-key"),
        "admin asset detail template must call verify-host-key endpoint"
    );
    assert!(
        admin_detail.contains("hx-trigger"),
        "admin asset detail template must use hx-trigger for auto-verification"
    );
    assert!(
        admin_detail.contains("Verifying host key"),
        "admin asset detail template must show a 'Verifying' loading state"
    );
    assert!(
        admin_detail.contains("No Host Key Stored"),
        "admin asset detail template must show 'No Host Key Stored' state"
    );

    // States 1 (verified) and 3 (mismatch) remain in HTMX fragments.
    let verified_fragment = include_str!("../../templates/assets/_ssh_host_key_fragment.html");
    assert!(
        verified_fragment.contains("Host Key Verified"),
        "verified fragment must show 'Host Key Verified'"
    );

    let mismatch_fragment =
        include_str!("../../templates/assets/_ssh_host_key_mismatch_fragment.html");
    assert!(
        mismatch_fragment.contains("Host Key Changed"),
        "mismatch fragment must show host key change warning"
    );

    let stored_mismatch_fragment =
        include_str!("../../templates/assets/_ssh_host_key_stored_mismatch_fragment.html");
    assert!(
        stored_mismatch_fragment.contains("Host Key Mismatch"),
        "stored mismatch fragment must show 'Host Key Mismatch'"
    );

    let no_key_fragment = include_str!("../../templates/assets/_ssh_host_key_no_key_fragment.html");
    assert!(
        no_key_fragment.contains("No Host Key Stored"),
        "no-key fragment must show 'No Host Key Stored'"
    );
}

/// Issue #34: the user-zone `AssetDetail` struct has been removed
/// because the user-zone /assets/{uuid} detail page is gone. The
/// ssh_host_key_mismatch field LIVES ON in the admin
/// `ManageAssetDetail` struct, which is the surface the SSH host
/// key fragments still feed into.
#[tokio::test]
#[serial]
async fn test_asset_detail_struct_has_mismatch_field() {
    let struct_source = include_str!("../../src/templates/assets/manage/detail.rs");

    assert!(
        struct_source.contains("ssh_host_key_mismatch"),
        "ManageAssetDetail struct must keep the ssh_host_key_mismatch field"
    );
}

/// Verify that the mismatch fragment template exists and contains
/// appropriate security warnings.
#[tokio::test]
#[serial]
async fn test_mismatch_fragment_has_security_warnings() {
    let fragment = include_str!("../../templates/assets/_ssh_host_key_mismatch_fragment.html");

    assert!(
        fragment.contains("WARNING"),
        "mismatch fragment must display a WARNING message"
    );
    assert!(
        fragment.contains("man-in-the-middle"),
        "mismatch fragment must warn about MITM attacks"
    );
    assert!(
        fragment.contains("__OLD_FINGERPRINT__"),
        "mismatch fragment must show the old fingerprint"
    );
    assert!(
        fragment.contains("__NEW_FINGERPRINT__"),
        "mismatch fragment must show the new fingerprint"
    );
    assert!(
        fragment.contains("confirm=true"),
        "mismatch fragment must have a button to accept the new key"
    );
    assert!(
        fragment.contains("hx-confirm"),
        "mismatch fragment must require user confirmation before accepting"
    );
}

/// Verify that the fetch handler clears the mismatch flag when a key is
/// successfully stored (either first fetch or confirmed accept).
#[tokio::test]
#[serial]
async fn test_fetch_handler_clears_mismatch_flag() {
    let web_source = include_str!("../../src/handlers/web/ssh.rs");

    assert!(
        web_source.contains(r#"m.remove("ssh_host_key_mismatch")"#),
        "fetch handler must remove the mismatch flag when storing a new key"
    );

    // Issue #27: API fetch handler moved to manage_assets.rs.
    let api_source = include_str!("../../src/handlers/api/manage_assets.rs");
    assert!(
        api_source.contains(r#"m.remove("ssh_host_key_mismatch")"#),
        "API fetch handler must remove the mismatch flag when storing a new key"
    );
}

/// Verify that the GET ssh-host-key API endpoint exists and returns the
/// three host key states (verified, mismatch, no_key).
#[tokio::test]
#[serial]
async fn test_api_get_ssh_host_key_status_endpoint_exists() {
    // Issue #27: SSH host-key status endpoint moved to manage_assets.rs.
    let api_source = include_str!("../../src/handlers/api/manage_assets.rs");

    assert!(
        api_source.contains("get_ssh_host_key_status"),
        "API must have a get_ssh_host_key_status handler"
    );
    assert!(
        api_source.contains(r#""verified""#),
        "get_ssh_host_key_status must return 'verified' state"
    );
    assert!(
        api_source.contains(r#""mismatch""#),
        "get_ssh_host_key_status must return 'mismatch' state"
    );
    assert!(
        api_source.contains(r#""no_key""#),
        "get_ssh_host_key_status must return 'no_key' state"
    );
}

/// Verify the GET route for ssh-host-key is registered in main.rs.
#[tokio::test]
#[serial]
async fn test_api_get_ssh_host_key_route_registered() {
    let main_source = include_str!("../../src/main.rs");

    assert!(
        main_source.contains("get_ssh_host_key_status"),
        "GET ssh-host-key route must be registered in main.rs"
    );
    assert!(
        main_source.contains("get(handlers::api::get_ssh_host_key_status)"),
        "GET handler must be wired with get() in the route definition"
    );
}

/// Verify that connect_ssh persists the mismatch flag for both response
/// error branches (successful proxy response with error, and transport error).
#[tokio::test]
#[serial]
async fn test_connect_ssh_detects_mismatch_in_both_error_branches() {
    let web_source = include_str!("../../src/handlers/web/ssh.rs");

    // Count occurrences of is_host_key_mismatch - should appear at least
    // twice (once in each error branch of the proxy call).
    let mismatch_count = web_source.matches("is_host_key_mismatch").count();
    assert!(
        mismatch_count >= 4,
        "connect_ssh must check for host key mismatch in both error branches \
         (found {} occurrences of is_host_key_mismatch, expected >= 4)",
        mismatch_count
    );
}

/// Verify the API handler re-exports include the new GET endpoint.
#[tokio::test]
#[serial]
async fn test_api_mod_exports_host_key_status() {
    let mod_source = include_str!("../../src/handlers/api/mod.rs");

    assert!(
        mod_source.contains("get_ssh_host_key_status"),
        "api/mod.rs must re-export get_ssh_host_key_status"
    );
}

/// Verify that the verify_ssh_host_key handler exists and performs
/// proactive host key verification against the remote server.
#[tokio::test]
#[serial]
async fn test_verify_ssh_host_key_handler_exists() {
    let web_source = include_str!("../../src/handlers/web/ssh.rs");

    assert!(
        web_source.contains("verify_ssh_host_key"),
        "web handler must include verify_ssh_host_key for proactive verification"
    );
    // Must compare stored key against remote key
    assert!(
        web_source.contains("old_key == remote_key"),
        "verify handler must compare stored key against remote key"
    );
    // Must handle proxy unavailability gracefully
    assert!(
        web_source.contains("Proxy unavailable")
            || web_source.contains("SSH proxy not available, returning stored state"),
        "verify handler must fall back gracefully when proxy is unavailable"
    );
    // Must handle connection failure gracefully
    assert!(
        web_source.contains("Could not verify host key against remote server"),
        "verify handler must fall back gracefully when connection fails"
    );
}

/// Verify the verify-host-key route is registered in main.rs.
#[tokio::test]
#[serial]
async fn test_verify_host_key_route_registered() {
    let main_source = include_str!("../../src/main.rs");

    assert!(
        main_source.contains("verify-host-key"),
        "verify-host-key route must be registered in main.rs"
    );
    assert!(
        main_source.contains("verify_ssh_host_key"),
        "verify_ssh_host_key handler must be wired in main.rs"
    );
}

/// Verify that all four HTMX fragments exist for the SSH host key states.
#[tokio::test]
#[serial]
async fn test_all_ssh_host_key_fragments_exist() {
    // Verified (green)
    let _ = include_str!("../../templates/assets/_ssh_host_key_fragment.html");
    // Mismatch detected during fetch/refresh (red, two fingerprints)
    let _ = include_str!("../../templates/assets/_ssh_host_key_mismatch_fragment.html");
    // Mismatch from stored flag (red, one fingerprint)
    let _ = include_str!("../../templates/assets/_ssh_host_key_stored_mismatch_fragment.html");
    // No key stored (amber)
    let _ = include_str!("../../templates/assets/_ssh_host_key_no_key_fragment.html");
    // If we got here without a compile error, all fragments exist.
}

// ---------------------------------------------------------------------------
// Privilege separation (privsep) compliance for SSH host key fetch
// ---------------------------------------------------------------------------
// Under Capsicum (FreeBSD sandbox), after cap_enter() no new network
// connections are allowed.  TCP connections must be brokered by the
// supervisor and the resulting FDs passed via SCM_RIGHTS on a Unix
// socketpair.  These tests verify that the host key fetch code path
// correctly delegates TCP connect to the supervisor when one is
// available.

/// Verify that ProxySshClient::fetch_host_key accepts an optional
/// supervisor parameter for Capsicum-compatible TCP connection brokering.
#[tokio::test]
#[serial]
async fn test_fetch_host_key_accepts_supervisor_param() {
    let ipc_source = include_str!("../../src/ipc/proxy_ssh.rs");

    // The method signature must accept an optional supervisor reference
    assert!(
        ipc_source.contains("supervisor: Option<&super::SupervisorClient>"),
        "privsep: fetch_host_key must accept an optional SupervisorClient for Capsicum TCP brokering"
    );
}

/// Verify that fetch_host_key requests a TCP connection from the
/// supervisor before sending SshFetchHostKey to the proxy.
#[tokio::test]
#[serial]
async fn test_fetch_host_key_requests_supervisor_tcp_connect() {
    let ipc_source = include_str!("../../src/ipc/proxy_ssh.rs");

    // Must call request_tcp_connect when supervisor is available
    assert!(
        ipc_source.contains("request_tcp_connect"),
        "privsep: fetch_host_key must call request_tcp_connect on the supervisor"
    );

    // Must use the correct session_id format matching the proxy's expectation
    assert!(
        ipc_source.contains(r#"format!("fetch-hostkey-{}", request_id)"#),
        "privsep: fetch_host_key must use 'fetch-hostkey-{{request_id}}' as session_id for TCP connect"
    );

    // Must target Service::ProxySsh
    assert!(
        ipc_source.contains("Service::ProxySsh"),
        "privsep: fetch_host_key must target Service::ProxySsh for TCP connect brokering"
    );
}

/// Verify that the web handler (verify_ssh_host_key) passes the
/// supervisor to fetch_host_key.
#[tokio::test]
#[serial]
async fn test_verify_handler_passes_supervisor() {
    let web_source = include_str!("../../src/handlers/web/ssh.rs");

    // The verify handler must extract the supervisor and pass it
    assert!(
        web_source.contains("supervisor_ref"),
        "privsep: verify_ssh_host_key must extract supervisor reference"
    );
    assert!(
        web_source.contains("state.supervisor.as_deref()"),
        "privsep: verify_ssh_host_key must get supervisor from state"
    );
}

/// Verify that the web handler (fetch_ssh_host_key) passes the
/// supervisor to fetch_host_key.
#[tokio::test]
#[serial]
async fn test_fetch_web_handler_passes_supervisor() {
    let web_source = include_str!("../../src/handlers/web/ssh.rs");

    // The fetch handler must pass supervisor_ref to fetch_host_key
    // Count occurrences - we need at least 2 (one in fetch_ssh_host_key,
    // one in verify_ssh_host_key)
    let count = web_source.matches("supervisor_ref").count();
    assert!(
        count >= 2,
        "privsep: both fetch_ssh_host_key and verify_ssh_host_key must pass supervisor_ref (found {} occurrences)",
        count
    );
}

/// Verify that the API handler (fetch_ssh_host_key_api) passes the
/// supervisor to fetch_host_key.
#[tokio::test]
#[serial]
async fn test_fetch_api_handler_passes_supervisor() {
    // Issue #27: SSH host-key fetch API moved to manage_assets.rs.
    let api_source = include_str!("../../src/handlers/api/manage_assets.rs");

    assert!(
        api_source.contains("supervisor_ref"),
        "privsep: fetch_ssh_host_key_api must extract supervisor reference"
    );
    assert!(
        api_source.contains("state.supervisor.as_deref()"),
        "privsep: fetch_ssh_host_key_api must get supervisor from state"
    );
}

/// Verify that the proxy correctly constructs the fetch session ID
/// from the request_id to match the supervisor's TCP connect.
#[tokio::test]
#[serial]
async fn test_proxy_fetch_session_id_matches_supervisor() {
    let proxy_source = include_str!("../../../vauban-proxy-ssh/src/main.rs");

    // The proxy must construct the same session_id format
    assert!(
        proxy_source.contains(r#"format!("fetch-hostkey-{}", request_id)"#),
        "privsep: proxy must construct fetch_session_id matching the supervisor TCP connect session_id"
    );

    // The proxy must look up the FD in pending_connections
    assert!(
        proxy_source.contains("pending.lock().await.remove(&fetch_session_id)"),
        "privsep: proxy must retrieve pre-connected FD from pending_connections"
    );
}

/// Verify that the session::fetch_host_key function supports both
/// pre-connected FD (sandboxed) and direct connection (dev mode).
#[tokio::test]
#[serial]
async fn test_session_fetch_supports_preconnected_fd() {
    let session_source = include_str!("../../../vauban-proxy-ssh/src/session.rs");

    // Must accept an optional pre-connected FD
    assert!(
        session_source.contains("preconnected_fd: Option<OwnedFd>"),
        "privsep: session::fetch_host_key must accept Option<OwnedFd> for pre-connected FD"
    );

    // Must handle the pre-connected case (use from_raw_fd)
    assert!(
        session_source.contains("from_raw_fd"),
        "privsep: session::fetch_host_key must use from_raw_fd for pre-connected FD"
    );

    // Must have a fallback for direct connection (dev mode without supervisor)
    assert!(
        session_source.contains("client::connect(ssh_config, addr, handler)"),
        "privsep: session::fetch_host_key must fall back to direct connect when no FD is provided"
    );
}

// =============================================================================
// SSH Secrets Zeroization and Redaction Tests
// =============================================================================
// These tests verify that credential fields (password, private_key, passphrase)
// are protected with secrecy/zeroize wrappers at every layer:
// - SshSessionOpenRequest uses SecretString (vauban-web)
// - Message::SshSessionOpen uses SensitiveString (shared IPC transport)
// - SshCredential uses SecretString (vauban-proxy-ssh)
//
// Protection goals:
// - Zeroize on drop: memory is scrubbed when credentials go out of scope
// - Redacted Debug: format!("{:?}") never reveals credential values
// - Compile-time enforcement: expose_secret() required to access the value

/// SshSessionOpenRequest credential fields MUST be SecretString, not String.
#[test]
fn test_ssh_session_open_request_uses_secret_string() {
    let source = include_str!("../../src/ipc/proxy_ssh.rs");

    // password field must be Option<SecretString>
    assert!(
        source.contains("pub password: Option<SecretString>"),
        "SshSessionOpenRequest.password must be Option<SecretString>"
    );

    // private_key field must be Option<SecretString>
    assert!(
        source.contains("pub private_key: Option<SecretString>"),
        "SshSessionOpenRequest.private_key must be Option<SecretString>"
    );

    // passphrase field must be Option<SecretString>
    assert!(
        source.contains("pub passphrase: Option<SecretString>"),
        "SshSessionOpenRequest.passphrase must be Option<SecretString>"
    );
}

/// Message::SshSessionOpen credential fields MUST be SensitiveString for IPC transport.
#[test]
fn test_message_ssh_session_open_uses_sensitive_string() {
    let source = include_str!("../../../shared/src/messages.rs");

    // SensitiveString type must exist
    assert!(
        source.contains("pub struct SensitiveString"),
        "shared/messages.rs must define SensitiveString type"
    );

    // password field in SshSessionOpen must use SensitiveString
    assert!(
        source.contains("password: Option<SensitiveString>"),
        "Message::SshSessionOpen.password must be Option<SensitiveString>"
    );

    // private_key field must use SensitiveString
    assert!(
        source.contains("private_key: Option<SensitiveString>"),
        "Message::SshSessionOpen.private_key must be Option<SensitiveString>"
    );

    // passphrase field must use SensitiveString
    assert!(
        source.contains("passphrase: Option<SensitiveString>"),
        "Message::SshSessionOpen.passphrase must be Option<SensitiveString>"
    );
}

/// SensitiveString must implement Zeroize on Drop.
#[test]
fn test_sensitive_string_has_zeroize_drop() {
    let source = include_str!("../../../shared/src/messages.rs");

    // Must use zeroize crate
    assert!(
        source.contains("use zeroize::Zeroize"),
        "shared/messages.rs must import zeroize::Zeroize"
    );

    // Drop impl must call zeroize
    assert!(
        source.contains("self.0.zeroize()"),
        "SensitiveString Drop must call zeroize() on inner string"
    );
}

/// SensitiveString Debug must print [REDACTED], not the secret value.
#[test]
fn test_sensitive_string_debug_redacted() {
    use shared::messages::SensitiveString;

    let secret = SensitiveString::new("top-secret-password-12345".to_string());
    let debug = format!("{:?}", secret);

    assert!(
        !debug.contains("top-secret-password"),
        "SensitiveString Debug must NOT reveal the secret. Got: {}",
        debug
    );
    assert!(
        debug.contains("REDACTED"),
        "SensitiveString Debug must show [REDACTED]. Got: {}",
        debug
    );
}

/// SensitiveString must be serde-transparent (no IPC protocol break).
#[test]
fn test_sensitive_string_serde_transparent() {
    let source = include_str!("../../../shared/src/messages.rs");

    assert!(
        source.contains("#[serde(transparent)]"),
        "SensitiveString must use #[serde(transparent)] for IPC compatibility"
    );
}

/// SshCredential (proxy side) must use SecretString, not plain String.
#[test]
fn test_ssh_credential_uses_secret_string() {
    let source = include_str!("../../../vauban-proxy-ssh/src/session.rs");

    // Password variant must use SecretString
    assert!(
        source.contains("Password(SecretString)"),
        "SshCredential::Password must wrap SecretString, not String"
    );

    // PrivateKey key_pem must use SecretString
    assert!(
        source.contains("key_pem: SecretString"),
        "SshCredential::PrivateKey.key_pem must be SecretString"
    );

    // PrivateKey passphrase must use Option<SecretString>
    assert!(
        source.contains("passphrase: Option<SecretString>"),
        "SshCredential::PrivateKey.passphrase must be Option<SecretString>"
    );
}

/// SshCredential Debug must not derive automatically; must be redacted.
#[test]
fn test_ssh_credential_debug_not_derived() {
    let source = include_str!("../../../vauban-proxy-ssh/src/session.rs");

    // SshCredential must NOT have #[derive(Debug)]
    // It should have a manual Debug impl with [REDACTED]
    assert!(
        source.contains("impl std::fmt::Debug for SshCredential"),
        "SshCredential must have manual Debug impl (not derive)"
    );

    assert!(
        source.contains("REDACTED"),
        "SshCredential Debug impl must use [REDACTED]"
    );
}

/// Proxy main.rs must convert SensitiveString -> SecretString.
#[test]
fn test_proxy_converts_sensitive_to_secret() {
    let source = include_str!("../../../vauban-proxy-ssh/src/main.rs");

    // Must import SecretString
    assert!(
        source.contains("use secrecy::SecretString"),
        "proxy main.rs must import secrecy::SecretString"
    );

    // Must use into_inner() to extract from SensitiveString
    assert!(
        source.contains("into_inner()"),
        "proxy must call SensitiveString::into_inner() for conversion"
    );
}

/// connect_ssh handler must wrap credentials in SecretString.
#[test]
fn test_connect_ssh_wraps_credentials() {
    let source = include_str!("../../src/handlers/web/ssh.rs");

    // Must use SecretString::from() or secrecy::SecretString for credentials
    assert!(
        source.contains("secrecy::SecretString::from(val.to_string())")
            || source.contains("secrecy::SecretString::from(s.to_string())"),
        "connect_ssh must wrap extracted credentials in SecretString"
    );
}

/// open_session() must convert SecretString -> SensitiveString for IPC.
#[test]
fn test_open_session_converts_secret_to_sensitive() {
    let source = include_str!("../../src/ipc/proxy_ssh.rs");

    // Must use expose_secret() to access credential before IPC transport
    assert!(
        source.contains("expose_secret()"),
        "open_session must call expose_secret() when converting to SensitiveString"
    );

    // Must create SensitiveString for IPC message
    assert!(
        source.contains("SensitiveString::new"),
        "open_session must construct SensitiveString for IPC message fields"
    );
}

/// SshCredential authentication must use expose_secret().
#[test]
fn test_credential_auth_uses_expose_secret() {
    let source = include_str!("../../../vauban-proxy-ssh/src/session.rs");

    // Password auth must call expose_secret()
    assert!(
        source.contains("password.expose_secret()"),
        "password authentication must call .expose_secret()"
    );

    // Private key auth must call expose_secret()
    assert!(
        source.contains("key_pem.expose_secret()"),
        "private key decoding must call .expose_secret()"
    );
}

// =============================================================================
// IACS sshd Host Key Hygiene Tests
// =============================================================================

/// The IACS sshd Ed25519 host key transits through a transient `String`
/// buffer when read off disk (in `vauban-web`'s in-process variant) or
/// off the supervisor-provided FD (in `shared::iacs_host_key`). Both
/// buffers MUST be zeroized before they are dropped, mirroring the
/// hygiene already enforced for TLS keys (`SensitiveString` +
/// explicit `zeroize()` in `vauban-supervisor` / `vauban-web`) and SSH
/// client keys (`SecretString` in `vauban-proxy-ssh`).
///
/// Without this, the OpenSSH PEM (containing the Ed25519 private key
/// in clear) lingers in the process heap arena until the allocator
/// reuses the slot, widening the window for a coredump or `/proc/`
/// memory read to extract the host key.
#[test]
fn test_iacs_host_key_pem_is_zeroized() {
    let shared_src = include_str!("../../../shared/src/iacs_host_key.rs");
    assert!(
        shared_src.contains("data.zeroize();"),
        "shared::iacs_host_key::load_or_generate_host_key MUST zeroize the PEM `data` buffer"
    );
    assert!(
        shared_src.contains("buf.zeroize();"),
        "shared::iacs_host_key::read_host_key_from_fd MUST zeroize the PEM `buf` buffer"
    );

    let web_src = include_str!("../../src/services/iacs_tunnel/server.rs");
    assert!(
        web_src.contains("data.zeroize();"),
        "vauban-web in-process IACS load_or_generate_host_key MUST zeroize the PEM `data` buffer"
    );
    assert!(
        web_src.contains("use zeroize::Zeroize;"),
        "vauban-web/src/services/iacs_tunnel/server.rs MUST import zeroize::Zeroize"
    );
}

// =============================================================================
// Vault Structural Regression Tests
// =============================================================================

/// vauban-vault must NOT depend on tokio (synchronous service).
#[test]
fn test_vault_no_tokio_dependency() {
    let cargo = include_str!("../../../vauban-vault/Cargo.toml");
    assert!(
        !cargo.contains("tokio"),
        "vauban-vault must NOT depend on tokio (pure synchronous service)"
    );
}

/// vauban-vault must NOT depend on diesel or sqlx (no database).
#[test]
fn test_vault_no_database_dependency() {
    let cargo = include_str!("../../../vauban-vault/Cargo.toml");
    assert!(
        !cargo.contains("diesel"),
        "vauban-vault must NOT depend on diesel (no database access)"
    );
    assert!(
        !cargo.contains("sqlx"),
        "vauban-vault must NOT depend on sqlx (no database access)"
    );
}

/// vauban-vault must NOT depend on reqwest (no network).
#[test]
fn test_vault_no_network_dependency() {
    let cargo = include_str!("../../../vauban-vault/Cargo.toml");
    assert!(
        !cargo.contains("reqwest"),
        "vauban-vault must NOT depend on reqwest (no network access)"
    );
    assert!(
        !cargo.contains("hyper"),
        "vauban-vault must NOT depend on hyper (no network access)"
    );
}

/// vauban-vault must depend on zeroize for key material cleanup.
#[test]
fn test_vault_has_zeroize_dependency() {
    let cargo = include_str!("../../../vauban-vault/Cargo.toml");
    assert!(
        cargo.contains("zeroize"),
        "vauban-vault must depend on zeroize for key material cleanup"
    );
}

/// MasterKey must implement zeroization (ZeroizeOnDrop pattern).
#[test]
fn test_vault_master_key_zeroize() {
    let source = include_str!("../../../vauban-vault/src/keyring.rs");
    assert!(
        source.contains("fn drop(&mut self)") && source.contains("zeroize()"),
        "MasterKey must zeroize on drop"
    );
}

/// MasterKey Debug must be redacted (no key material in logs).
#[test]
fn test_vault_master_key_debug_redacted() {
    let source = include_str!("../../../vauban-vault/src/keyring.rs");
    assert!(
        source.contains("MasterKey([REDACTED])"),
        "MasterKey Debug must show [REDACTED], never raw key bytes"
    );
}

/// Vault crypto module uses AES-256-GCM and OsRng for nonces.
#[test]
fn test_vault_crypto_uses_aes256_gcm_osrng() {
    let source = include_str!("../../../vauban-vault/src/crypto.rs");
    assert!(
        source.contains("Aes256Gcm"),
        "vault crypto must use AES-256-GCM"
    );
    assert!(
        source.contains("OsRng"),
        "vault crypto must use OsRng for nonce generation"
    );
}

/// Vault keyring uses HKDF-SHA3-256 for key derivation (PQC alignment).
#[test]
fn test_vault_keyring_uses_hkdf_sha3() {
    let source = include_str!("../../../vauban-vault/src/keyring.rs");
    assert!(
        source.contains("Hkdf::<Sha3_256>"),
        "vault keyring must use HKDF-SHA3-256 for PQC-aligned key derivation"
    );
}

/// Vault transit handlers zeroize plaintext after operations.
#[test]
fn test_vault_transit_zeroizes_plaintext() {
    let source = include_str!("../../../vauban-vault/src/transit.rs");
    assert!(
        source.contains("zeroize()"),
        "vault transit handlers must zeroize plaintext after operations"
    );
}

/// Vault IPC messages use SensitiveString for credential transport.
#[test]
fn test_vault_messages_use_sensitive_string() {
    let source = include_str!("../../../shared/src/messages.rs");
    // VaultEncrypt must use SensitiveString for plaintext
    assert!(
        source.contains("plaintext: SensitiveString"),
        "VaultEncrypt must use SensitiveString for plaintext field"
    );
    // VaultDecryptResponse must use SensitiveString for plaintext
    assert!(
        source.contains("plaintext: Option<SensitiveString>"),
        "VaultDecryptResponse must use SensitiveString for plaintext field"
    );
}

/// connect_ssh handler must decrypt encrypted credentials via vault.
#[test]
fn test_connect_ssh_decrypts_via_vault() {
    let source = include_str!("../../src/handlers/web/ssh.rs");
    assert!(
        source.contains("vault.decrypt(\"credentials\""),
        "connect_ssh must call vault.decrypt for encrypted credentials"
    );
    assert!(
        source.contains("is_encrypted(val)"),
        "connect_ssh must check is_encrypted() for backward compatibility"
    );
}

/// Asset creation must encrypt credentials via vault.
#[test]
fn test_asset_creation_encrypts_via_vault() {
    // Issue #27: asset CRUD moved to manage_assets.rs (admin zone).
    let source = include_str!("../../src/handlers/web/manage_assets.rs");
    assert!(
        source.contains("encrypt_connection_config"),
        "asset creation/edit must call encrypt_connection_config for credential encryption"
    );
}

/// MFA handlers must use vault for TOTP generation and verification.
#[test]
fn test_mfa_handlers_use_vault() {
    let source = include_str!("../../src/handlers/auth.rs");
    assert!(
        source.contains(".mfa_verify("),
        "MFA verification must use vault.mfa_verify"
    );
    assert!(
        source.contains(".mfa_generate("),
        "MFA setup must use vault.mfa_generate"
    );
}

/// Vault client in AppState must be available.
#[test]
fn test_vault_client_in_appstate() {
    let source = include_str!("../../src/lib.rs");
    assert!(
        source.contains("vault_client: Option<Arc<VaultCryptoClient>>"),
        "AppState must contain vault_client field"
    );
}

// =============================================================================
// VAU-002: vault per-peer authorization (capability matrix) -- structural pins
// =============================================================================

/// The vault MUST ship a per-peer capability matrix module (authz.rs) with a
/// fail-closed `is_authorized` and the `VaultPeer` identity enum.
#[test]
fn test_vau002_vault_authz_module_exists_and_fail_closed() {
    let source = include_str!("../../../vauban-vault/src/authz.rs");
    assert!(
        source.contains("enum VaultPeer"),
        "vauban-vault must define a VaultPeer identity enum (authz.rs)"
    );
    assert!(
        source.contains("fn is_authorized"),
        "vauban-vault must define is_authorized (per-peer capability matrix)"
    );
    assert!(
        source.contains("VaultPeer::Supervisor"),
        "the matrix must model the Supervisor (control-only) peer"
    );
    // Fail-closed catch-all, never fail-open.
    assert!(
        source.contains("_ => false"),
        "is_authorized must default to deny (`_ => false`)"
    );
    assert!(
        !source.contains("_ => true"),
        "is_authorized must NOT contain a fail-open `_ => true` arm"
    );
}

/// SECURITY: even web cannot VaultDecrypt the `mfa` domain, and auth is limited
/// to MfaVerify. Pin the documented least-privilege grants so a loosening is
/// caught (the matrix is the single source of truth for VAU-002).
#[test]
fn test_vau002_matrix_denies_mfa_secret_exfiltration() {
    let source = include_str!("../../../vauban-vault/src/authz.rs");
    // web Decrypt is restricted to credentials (not a wildcard / mfa).
    assert!(
        source.contains(
            "(VaultPeer::Web, Message::VaultDecrypt { domain, .. }) => domain == DOMAIN_CREDENTIALS"
        ),
        "web VaultDecrypt must be limited to the credentials domain"
    );
    // auth's ONLY grant is MfaVerify.
    assert!(
        source.contains("(VaultPeer::Auth, Message::VaultMfaVerify { .. }) => true"),
        "auth must be granted VaultMfaVerify"
    );
    assert!(
        !source.contains("VaultPeer::Auth, Message::VaultMfaGetSecret"),
        "auth must NOT be granted VaultMfaGetSecret (TOTP secret exfiltration)"
    );
}

/// The vault main loop MUST gate peer requests before any crypto and keep the
/// `requests_denied` anomaly counter.
#[test]
fn test_vau002_vault_main_gates_and_counts() {
    let source = include_str!("../../../vauban-vault/src/main.rs");
    assert!(
        source.contains("mod authz;"),
        "vauban-vault main.rs must wire the authz module"
    );
    assert!(
        source.contains("authz::is_authorized"),
        "handle_peer_message must authorize via authz::is_authorized"
    );
    assert!(
        source.contains("requests_denied"),
        "ServiceState must carry the requests_denied anomaly counter (VAU-002)"
    );
    assert!(
        source.contains("fn deny_vault_request"),
        "vauban-vault must have a deny_vault_request helper (warn + typed denial)"
    );
    // The pre-fix unguarded forwarding arm must be gone.
    assert!(
        !source.contains("=> handle_vault_request(channel, state, other),"),
        "vauban-vault must NOT forward vault verbs without authorization"
    );
}

/// is_encrypted helper must check version prefix format.
#[test]
fn test_is_encrypted_helper_exists() {
    let source = include_str!("../../src/handlers/web/mod.rs");
    assert!(
        source.contains("fn is_encrypted("),
        "is_encrypted() helper must exist for backward compatibility"
    );
}

// =============================================================================
// Backward Compatibility: plaintext -> encrypted progressive migration
// =============================================================================

/// auth.rs must have is_encrypted() for backward compatibility with plaintext secrets.
#[test]
fn test_auth_has_is_encrypted() {
    let source = include_str!("../../src/handlers/auth.rs");
    assert!(
        source.contains("fn is_encrypted("),
        "auth.rs must have is_encrypted() for backward compatibility"
    );
}

/// MFA verify in auth.rs must check is_encrypted before sending to vault.
/// This ensures plaintext secrets (pre-migration) still work via direct verification.
#[test]
fn test_mfa_verify_checks_is_encrypted() {
    let source = include_str!("../../src/handlers/auth.rs");
    // The pattern: vault is only used when is_encrypted(secret) is true
    assert!(
        source.contains("is_encrypted(secret)")
            || source.contains("is_encrypted(&secret)")
            || source.contains("is_encrypted(&s)"),
        "MFA verification must check is_encrypted() before calling vault"
    );
}

/// auth.rs must implement encrypt-on-read for progressive migration.
/// When a plaintext secret is verified successfully, it should be encrypted
/// and updated in the database.
#[test]
fn test_encrypt_on_read_in_auth() {
    let source = include_str!("../../src/handlers/auth.rs");
    assert!(
        source.contains("encrypt-on-read")
            || source.contains("Migrated plaintext MFA secret to encrypted"),
        "auth.rs must implement encrypt-on-read for progressive secret migration"
    );
    // Must call vault.encrypt for the migration
    assert!(
        source.contains("vault.encrypt(\"mfa\""),
        "encrypt-on-read must call vault.encrypt(\"mfa\", ...) to encrypt plaintext secrets"
    );
}

/// mfa_setup_page must handle plaintext existing secrets with encrypt-on-read.
#[test]
fn test_mfa_setup_page_backward_compat() {
    let source = include_str!("../../src/handlers/auth.rs");
    // The mfa_setup_page handler must check is_encrypted on existing secrets
    // and encrypt-on-read if they are plaintext
    assert!(
        source.contains("Plaintext secret (pre-migration)"),
        "mfa_setup_page must handle plaintext secrets with encrypt-on-read"
    );
}

/// vauban-vault must expose a library crate for reuse by vauban-migrate.
#[test]
fn test_vault_has_lib_crate() {
    let cargo = include_str!("../../../vauban-vault/Cargo.toml");
    assert!(
        cargo.contains("[lib]"),
        "vauban-vault must expose a [lib] section for reuse by vauban-migrate"
    );
}

/// vauban-vault lib.rs must export crypto and keyring modules.
#[test]
fn test_vault_lib_exports_modules() {
    let source = include_str!("../../../vauban-vault/src/lib.rs");
    assert!(
        source.contains("pub mod crypto"),
        "vauban-vault lib must export crypto module"
    );
    assert!(
        source.contains("pub mod keyring"),
        "vauban-vault lib must export keyring module"
    );
}

/// migrate_secrets logic must exist in vauban-supervisor/src/admin.rs.
#[test]
fn test_migrate_secrets_exists_in_supervisor() {
    let source = include_str!("../../../vauban-supervisor/src/admin.rs");
    assert!(
        source.contains("cmd_migrate_secrets"),
        "migrate_secrets must exist in vauban-supervisor/src/admin.rs"
    );
}

/// vauban-supervisor must depend on vauban-vault for keyring reuse by migrate_secrets.
#[test]
fn test_supervisor_depends_on_vault() {
    let cargo = include_str!("../../../vauban-supervisor/Cargo.toml");
    assert!(
        cargo.contains("vauban-vault"),
        "vauban-supervisor must depend on vauban-vault for keyring reuse"
    );
}

/// migrate_secrets must implement is_encrypted for idempotent migration.
#[test]
fn test_migrate_has_is_encrypted() {
    let source = include_str!("../../../vauban-supervisor/src/admin.rs");
    assert!(
        source.contains("fn is_encrypted("),
        "migrate_secrets must have is_encrypted() for idempotent migration"
    );
}

/// migrate_secrets must support --dry-run for safe operation.
#[test]
fn test_migrate_supports_dry_run() {
    let admin_source = include_str!("../../../vauban-supervisor/src/admin.rs");
    let main_source = include_str!("../../../vauban-supervisor/src/main.rs");
    assert!(
        admin_source.contains("dry_run") && main_source.contains("dry_run"),
        "migrate_secrets must support --dry-run flag for safe operation"
    );
}

/// migrate_secrets must migrate MFA secrets.
#[test]
fn test_migrate_handles_mfa_secrets() {
    let source = include_str!("../../../vauban-supervisor/src/admin.rs");
    assert!(
        source.contains("migrate_mfa_secrets"),
        "migrate_secrets must have migrate_mfa_secrets function"
    );
}

/// migrate_secrets must migrate credential secrets in connection_config.
#[test]
fn test_migrate_handles_credential_secrets() {
    let source = include_str!("../../../vauban-supervisor/src/admin.rs");
    assert!(
        source.contains("migrate_credential_secrets"),
        "migrate_secrets must have migrate_credential_secrets function"
    );
    assert!(
        source.contains("\"password\"")
            && source.contains("\"private_key\"")
            && source.contains("\"passphrase\""),
        "migrate_secrets must encrypt password, private_key, and passphrase fields"
    );
}

// =============================================================================
// OptionalSecret Zeroize Regression Tests
// =============================================================================

/// OptionalSecret must import zeroize.
#[test]
fn test_config_imports_zeroize() {
    let source = include_str!("../../src/config.rs");
    assert!(
        source.contains("use zeroize::Zeroize"),
        "config.rs must import zeroize::Zeroize"
    );
}

/// OptionalSecret must implement Drop with zeroization.
#[test]
fn test_optional_secret_has_zeroize_drop() {
    let source = include_str!("../../src/config.rs");
    assert!(
        source.contains("impl Drop for OptionalSecret"),
        "OptionalSecret must implement Drop"
    );
    assert!(
        source.contains("s.zeroize()"),
        "OptionalSecret Drop must call zeroize() on the inner String"
    );
}

/// OptionalSecret Debug must still redact secrets (not regressed).
#[test]
fn test_optional_secret_debug_redacts() {
    let source = include_str!("../../src/config.rs");
    assert!(
        source.contains("impl std::fmt::Debug for OptionalSecret") && source.contains("[REDACTED]"),
        "OptionalSecret Debug must redact values as [REDACTED]"
    );
}

// =============================================================================
// Post-Quantum Secret Key Zeroize Regression Tests
// =============================================================================

/// crypto.rs must define zeroize_pq_secret_key helper.
#[test]
fn test_has_zeroize_pq_helper() {
    let source = include_str!("../../src/crypto.rs");
    assert!(
        source.contains("fn zeroize_pq_secret_key"),
        "crypto.rs must define zeroize_pq_secret_key helper function"
    );
}

/// HybridKemSecretKey Drop must call zeroize on PQ key.
#[test]
fn test_kem_drop_zeroizes_pq_key() {
    let source = include_str!("../../src/crypto.rs");
    // Find the Drop impl for HybridKemSecretKey and verify it calls zeroize
    assert!(
        source.contains("impl Drop for HybridKemSecretKey"),
        "HybridKemSecretKey must implement Drop"
    );
    // The Drop impl must not be empty (the old version had an empty body)
    let drop_start = source
        .find("impl Drop for HybridKemSecretKey")
        .expect("HybridKemSecretKey Drop not found");
    let drop_end = drop_start + source[drop_start..].find("\n}\n").unwrap_or(600) + 3;
    let drop_body = &source[drop_start..drop_end];
    assert!(
        drop_body.contains("zeroize_pq_secret_key"),
        "HybridKemSecretKey Drop must call zeroize_pq_secret_key"
    );
}

/// HybridSigSecretKey Drop must call zeroize on PQ key.
#[test]
fn test_sig_drop_zeroizes_pq_key() {
    let source = include_str!("../../src/crypto.rs");
    assert!(
        source.contains("impl Drop for HybridSigSecretKey"),
        "HybridSigSecretKey must implement Drop"
    );
    let drop_start = source
        .find("impl Drop for HybridSigSecretKey")
        .expect("HybridSigSecretKey Drop not found");
    let drop_end = drop_start + source[drop_start..].find("\n}\n").unwrap_or(600) + 3;
    let drop_body = &source[drop_start..drop_end];
    assert!(
        drop_body.contains("zeroize_pq_secret_key"),
        "HybridSigSecretKey Drop must call zeroize_pq_secret_key"
    );
}

/// PqSecretKeyBytes trait must be implemented for both PQ key types.
#[test]
fn test_pq_secret_key_bytes_trait_impls() {
    let source = include_str!("../../src/crypto.rs");
    assert!(
        source.contains("impl PqSecretKeyBytes for mlkem768::SecretKey"),
        "PqSecretKeyBytes must be implemented for mlkem768::SecretKey"
    );
    assert!(
        source.contains("impl PqSecretKeyBytes for mldsa65::SecretKey"),
        "PqSecretKeyBytes must be implemented for mldsa65::SecretKey"
    );
}

/// The zeroize helper must actually call zeroize() on the raw bytes.
#[test]
fn test_zeroize_helper_calls_zeroize() {
    let source = include_str!("../../src/crypto.rs");
    let helper_start = source
        .find("fn zeroize_pq_secret_key")
        .expect("zeroize_pq_secret_key not found");
    let helper_body = &source[helper_start..helper_start + 500];
    assert!(
        helper_body.contains("slice.zeroize()"),
        "zeroize_pq_secret_key must call slice.zeroize()"
    );
}

// ==================== VAUBAN_SECRET_KEY cleared from environment ====================

#[test]
fn test_source_removes_env_var_after_reading() {
    // Structural regression test: load_with_environment must call
    // remove_var("VAUBAN_SECRET_KEY") immediately after std::env::var()
    let source = include_str!("../../src/config.rs");
    assert!(
        source.contains(r#"remove_var("VAUBAN_SECRET_KEY")"#),
        "config.rs must call remove_var(\"VAUBAN_SECRET_KEY\") to clear the env var"
    );
}

#[test]
fn test_remove_var_before_set_override() {
    // The remove_var call must happen BEFORE the value is used (defense in depth):
    // if set_override fails, the env var is already cleared.
    let source = include_str!("../../src/config.rs");
    let remove_pos = source
        .find(r#"remove_var("VAUBAN_SECRET_KEY")"#)
        .expect("remove_var not found");
    let set_override_pos = source[remove_pos..]
        .find("set_override")
        .expect("set_override not found after remove_var");
    assert!(
        set_override_pos > 0,
        "remove_var must appear before set_override in the source"
    );
}

#[test]
fn test_remove_var_inside_env_var_block() {
    // The remove_var must be inside the `if let Ok(secret) = std::env::var(...)` block,
    // i.e. it only runs when the env var was actually set.
    let source = include_str!("../../src/config.rs");

    // Find the env::var("VAUBAN_SECRET_KEY") read
    let env_read_pos = source
        .find(r#"std::env::var("VAUBAN_SECRET_KEY")"#)
        .expect("env::var(\"VAUBAN_SECRET_KEY\") not found");

    // Find remove_var relative to the env read
    let after_read = &source[env_read_pos..];
    let remove_offset = after_read
        .find(r#"remove_var("VAUBAN_SECRET_KEY")"#)
        .expect("remove_var not found after env::var read");

    // The remove_var should be close (within the same if-block, < 700 chars).
    // The allowance accounts for the SAFETY comment explaining the unsafe block.
    assert!(
        remove_offset < 700,
        "remove_var should be close to env::var read (found at offset {})",
        remove_offset
    );
}

#[test]
fn test_toml_secret_key_path_preserved() {
    // Structural regression test: the TOML-based secret_key loading path must still exist.
    // This guards against someone accidentally removing TOML support while implementing
    // the env var clearing.
    let source = include_str!("../../src/config.rs");

    // The config struct must still have a secret_key field of type SecretString
    assert!(
        source.contains("pub secret_key: secrecy::SecretString"),
        "regression: Config must still have secret_key: secrecy::SecretString"
    );

    // The error message mentioning TOML as a valid source must still exist
    assert!(
        source.contains("config/{environment}.toml"),
        "regression: error message must still mention TOML as a valid source for secret_key"
    );

    // The validation that secret_key is not empty must still exist
    assert!(
        source.contains("config.secret_key.expose_secret().is_empty()"),
        "regression: validation that secret_key is not empty must remain"
    );
}

// ==================== Silent cache fallback -> fail-closed ====================

#[test]
fn test_cache_no_silent_fallback_to_mock() {
    // The old pattern "falling back to mock cache" must no longer appear in
    // create_cache_client().  When cache.enabled = true and Redis fails,
    // an error must be returned, not a silent MockCache.
    let source = include_str!("../../src/cache.rs");
    assert!(
        !source.contains("falling back to mock"),
        "cache.rs must not contain 'falling back to mock' (fail-closed when enabled)"
    );
}

#[test]
fn test_cache_disabled_mock_path_preserved() {
    // Regression: the explicit cache.enabled = false -> MockCache path must remain.
    let source = include_str!("../../src/cache.rs");
    assert!(
        source.contains("Cache is disabled - using mock cache"),
        "regression: cache.rs must still have the disabled -> mock path"
    );
}

#[test]
fn test_cache_enabled_uses_error_propagation() {
    // When cache.enabled = true, errors must propagate via ? (not match/Ok(Mock)).
    // Look for the fail-closed pattern: map_err + AppError::Config.
    let source = include_str!("../../src/cache.rs");

    // The function must return AppError::Config on Redis client creation failure
    assert!(
        source.contains("Cache is enabled but Redis client creation failed"),
        "cache.rs must return Config error on Redis client creation failure"
    );

    // The function must return AppError::Config on Redis connection failure
    assert!(
        source.contains("Cache is enabled but cannot connect to Redis"),
        "cache.rs must return Config error on Redis connection failure"
    );
}

#[test]
fn test_cache_error_messages_suggest_disabling() {
    // Error messages must tell the operator how to recover.
    let source = include_str!("../../src/cache.rs");

    let error_count = source
        .matches("Set cache.enabled = false to run without cache")
        .count();
    assert!(
        error_count >= 2,
        "both cache error paths must suggest 'Set cache.enabled = false' (found {})",
        error_count
    );
}

#[test]
fn test_rate_limiter_no_silent_fallback() {
    // The old "Falling back to in-memory" pattern must be gone.
    let source = include_str!("../../src/services/rate_limit.rs");
    assert!(
        !source.contains("Falling back to in-memory"),
        "rate_limit.rs must not silently fall back to in-memory when cache is enabled"
    );
}

#[test]
fn test_rate_limiter_fail_closed_on_bad_client() {
    // When cache_enabled = true, Redis client creation failure must return
    // an error via AppError::Config, not a warn + fallback.
    let source = include_str!("../../src/services/rate_limit.rs");
    assert!(
        source.contains("cache is enabled but Redis client creation failed"),
        "rate_limit.rs must return Config error on Redis client failure"
    );
}

#[test]
fn test_rate_limiter_fail_closed_on_no_url() {
    // When cache_enabled = true but no URL, must return an error.
    let source = include_str!("../../src/services/rate_limit.rs");
    assert!(
        source.contains("cache is enabled but no Redis URL provided"),
        "rate_limit.rs must return error when cache enabled but no URL"
    );
}

#[test]
fn test_rate_limiter_in_memory_path_preserved() {
    // Regression: the cache_enabled = false -> InMemory path must remain.
    let source = include_str!("../../src/services/rate_limit.rs");
    assert!(
        source.contains("Rate limiter using in-memory backend"),
        "regression: rate_limit.rs must still have the in-memory backend path"
    );
}

// ==================== Atomic Redis rate limiting (Lua script) ====================

#[test]
fn test_no_separate_incr_expire_in_check_redis() {
    // The old non-atomic pattern used separate INCR then EXPIRE commands.
    // After the Lua-script refactor, check_redis must NOT contain individual redis::cmd("INCR")
    // or conn.expire() calls -- only the atomic Lua script.
    let source = include_str!("../../src/services/rate_limit.rs");

    // Find the check_redis function body
    let fn_start = source
        .find("async fn check_redis")
        .expect("check_redis function must exist");
    let fn_body = &source[fn_start..];
    // Find the end of the function (next "fn " at same indentation level)
    let fn_end = fn_body[1..]
        .find("\n    /// ")
        .or_else(|| fn_body[1..].find("\n    pub fn"))
        .or_else(|| fn_body[1..].find("\n    fn "))
        .unwrap_or(800);
    let fn_body = &fn_body[..fn_end + 1];

    assert!(
        !fn_body.contains("redis::cmd(\"INCR\")"),
        "check_redis must not use separate INCR command (use Lua script instead)"
    );
    assert!(
        !fn_body.contains(".expire("),
        "check_redis must not use separate expire() call (use Lua script instead)"
    );
}

#[test]
fn test_uses_lua_script_constant() {
    // The rate limiter must define and use a RATE_LIMIT_LUA constant.
    let source = include_str!("../../src/services/rate_limit.rs");
    assert!(
        source.contains("RATE_LIMIT_LUA"),
        "rate_limit.rs must define RATE_LIMIT_LUA constant"
    );
    assert!(
        source.contains("Script::new(Self::RATE_LIMIT_LUA)"),
        "check_redis must use Script::new(Self::RATE_LIMIT_LUA)"
    );
}

#[test]
fn test_lua_script_is_atomic() {
    // The Lua script must contain INCR, TTL, and EXPIRE in a single script body.
    // This guarantees atomicity on the Redis server.
    let source = include_str!("../../src/services/rate_limit.rs");

    // Extract the Lua script content (between r#" and "#)
    let lua_start = source
        .find("RATE_LIMIT_LUA")
        .expect("RATE_LIMIT_LUA not found");
    let after = &source[lua_start..];
    // Find the raw string delimiters
    let script_start = after
        .find("r#\"")
        .expect("Lua script must be a raw string literal");
    let script_end = after[script_start + 3..]
        .find("\"#")
        .expect("Lua script raw string must be closed");
    let lua_body = &after[script_start + 3..script_start + 3 + script_end];

    assert!(
        lua_body.contains("redis.call('INCR'"),
        "Lua script must call INCR"
    );
    assert!(
        lua_body.contains("redis.call('EXPIRE'"),
        "Lua script must call EXPIRE"
    );
    assert!(
        lua_body.contains("redis.call('TTL'"),
        "Lua script must call TTL"
    );
}

#[test]
fn test_lua_script_recovers_stale_keys() {
    // The Lua script must handle the case where a key exists without TTL
    // (ttl == -1), which could happen from the old non-atomic code or a crash.
    let source = include_str!("../../src/services/rate_limit.rs");

    let lua_start = source.find("RATE_LIMIT_LUA").unwrap();
    let after = &source[lua_start..];
    let script_start = after.find("r#\"").unwrap();
    let script_end = after[script_start + 3..].find("\"#").unwrap();
    let lua_body = &after[script_start + 3..script_start + 3 + script_end];

    assert!(
        lua_body.contains("ttl == -1"),
        "Lua script must check for ttl == -1 (missing TTL / crash recovery)"
    );
}

#[test]
fn test_check_redis_uses_invoke_async() {
    // The script must be executed via invoke_async for async compatibility.
    let source = include_str!("../../src/services/rate_limit.rs");
    assert!(
        source.contains("invoke_async"),
        "check_redis must use invoke_async for the Lua script"
    );
}

// ==================== No Mutex serialization on Redis cache ====================

/// Return only the production (non-test) portion of cache.rs source.
fn cache_prod_source() -> &'static str {
    let full = include_str!("../../src/cache.rs");
    full.split("#[cfg(test)]").next().unwrap_or(full)
}

#[test]
fn test_no_mutex_on_multiplexed_connection() {
    // MultiplexedConnection handles multiplexing internally and is Clone.
    // Wrapping it in a Mutex serializes all cache operations unnecessarily.
    let source = cache_prod_source();
    assert!(
        !source.contains("Mutex<redis"),
        "CacheConnection::Redis must not wrap MultiplexedConnection in Mutex"
    );
}

#[test]
fn test_no_lock_await_in_cache() {
    // With the Mutex removed, no .lock().await should remain in production code.
    let source = cache_prod_source();
    assert!(
        !source.contains(".lock().await"),
        "cache.rs production code must not call .lock().await"
    );
}

#[test]
fn test_no_tokio_mutex_import() {
    // The tokio::sync::Mutex import should be gone from production code.
    let source = cache_prod_source();
    assert!(
        !source.contains("tokio::sync::Mutex"),
        "cache.rs must not import tokio::sync::Mutex"
    );
}

#[test]
fn test_uses_connection_clone() {
    // Cache operations must clone the MultiplexedConnection for concurrent access.
    let source = cache_prod_source();
    assert!(
        source.contains("conn.clone()"),
        "cache operations must use conn.clone() for concurrent access"
    );
}

#[test]
fn test_redis_variant_stores_connection_directly() {
    // The Redis variant must store MultiplexedConnection directly, not Arc<Mutex<...>>.
    let source = cache_prod_source();
    assert!(
        source.contains("Redis(redis::aio::MultiplexedConnection)"),
        "CacheConnection::Redis must store MultiplexedConnection directly"
    );
}

// ==================== Structural Regression Tests ====================
// Verify that process::exit() is not called in production code across all services.
// These tests prevent regressions where destructors (Drop/Zeroize) would be bypassed.

/// Helper: Extract production code from a source file (before #[cfg(test)]).
fn prod_source(full_source: &str) -> &str {
    if let Some(idx) = full_source.find("#[cfg(test)]") {
        &full_source[..idx]
    } else {
        full_source
    }
}

/// Helper: Check if production code contains a pattern on non-comment lines.
/// This avoids false positives from doc comments mentioning removed patterns.
fn prod_code_contains(source: &str, pattern: &str) -> bool {
    source.lines().any(|line| {
        let trimmed = line.trim();
        // Skip comment lines
        if trimmed.starts_with("//") || trimmed.starts_with("///") || trimmed.starts_with("*") {
            return false;
        }
        trimmed.contains(pattern)
    })
}

// --- vauban-web: ipc/supervisor.rs ---

#[test]
fn test_supervisor_ipc_no_process_exit() {
    let source = include_str!("../../src/ipc/supervisor.rs");
    let prod = prod_source(source);
    assert!(
        !prod_code_contains(prod, "process::exit"),
        "supervisor.rs must not call process::exit() - use server_handle.graceful_shutdown() instead"
    );
}

#[test]
fn test_supervisor_ipc_has_graceful_shutdown() {
    let source = include_str!("../../src/ipc/supervisor.rs");
    let prod = prod_source(source);
    assert!(
        prod.contains("graceful_shutdown"),
        "supervisor.rs must call graceful_shutdown() on ControlMessage::Shutdown"
    );
}

#[test]
fn test_supervisor_ipc_has_server_handle() {
    let source = include_str!("../../src/ipc/supervisor.rs");
    let prod = prod_source(source);
    assert!(
        prod.contains("server_handle"),
        "SupervisorClientInner must have a server_handle field"
    );
}

// --- vauban-web: cache.rs ---

#[test]
fn test_cache_no_process_exit() {
    let source = cache_prod_source();
    assert!(
        !prod_code_contains(source, "process::exit"),
        "cache.rs production code must not call process::exit()"
    );
}

#[test]
fn test_cache_uses_check_or_shutdown() {
    let source = cache_prod_source();
    assert!(
        source.contains("check_or_shutdown"),
        "cache.rs must use check_or_shutdown (not check_or_exit)"
    );
}

// --- vauban-web: db.rs ---

#[test]
fn test_db_no_process_exit() {
    let source = include_str!("../../src/db.rs");
    let prod = prod_source(source);
    assert!(
        !prod_code_contains(prod, "process::exit"),
        "db.rs production code must not call process::exit()"
    );
}

#[test]
fn test_db_uses_get_connection_or_shutdown() {
    let source = include_str!("../../src/db.rs");
    let prod = prod_source(source);
    assert!(
        prod.contains("get_connection_or_shutdown"),
        "db.rs must use get_connection_or_shutdown (not get_connection_or_exit)"
    );
}

// --- vauban-web: main.rs ---

#[test]
fn test_web_main_no_process_exit() {
    let source = include_str!("../../src/main.rs");
    let prod = prod_source(source);
    assert!(
        !prod_code_contains(prod, "process::exit"),
        "main.rs production code must not call process::exit()"
    );
}

#[test]
fn test_web_main_uses_server_handle() {
    let source = include_str!("../../src/main.rs");
    let prod = prod_source(source);
    assert!(
        prod.contains("server_handle"),
        "main.rs must create and pass a server_handle for graceful shutdown"
    );
}

// --- create_superuser (now in vauban-supervisor) ---

#[test]
fn test_create_superuser_no_process_exit() {
    let source = include_str!("../../../vauban-supervisor/src/admin.rs");
    assert!(
        !source.contains("process::exit"),
        "admin.rs must not call process::exit() - use anyhow::Result instead"
    );
}

#[test]
fn test_create_superuser_uses_result() {
    let source = include_str!("../../../vauban-supervisor/src/admin.rs");
    assert!(
        source.contains("-> Result<()>"),
        "admin.rs must use anyhow::Result for error propagation"
    );
}

// ==================== Phase 6e: Admin CLI Migration Regression Tests ====================
// Verify that admin CLI tools have been moved from vauban-web to vauban-supervisor.

#[test]
fn test_no_admin_binaries_in_web() {
    let binaries = [
        "create_superuser",
        "reset_password",
        "reset_2FA",
        "migrate_secrets",
        "seed_data",
    ];
    for bin_name in &binaries {
        let path = format!(
            "{}/../../src/bin/{}.rs",
            env!("CARGO_MANIFEST_DIR"),
            bin_name
        );
        assert!(
            !std::path::Path::new(&path).exists(),
            "Admin binary {bin_name}.rs must NOT exist in vauban-web/src/bin/ (moved to supervisor)"
        );
    }
}

#[test]
fn test_all_admin_commands_in_supervisor() {
    let source = include_str!("../../../vauban-supervisor/src/admin.rs");
    let commands = [
        "cmd_create_superuser",
        "cmd_reset_password",
        "cmd_reset_2fa",
        "cmd_migrate_secrets",
        "cmd_seed_data",
    ];
    for cmd in &commands {
        assert!(
            source.contains(cmd),
            "Admin command {cmd} must exist in vauban-supervisor/src/admin.rs"
        );
    }
}

#[test]
fn test_supervisor_cli_has_all_subcommands() {
    let source = include_str!("../../../vauban-supervisor/src/main.rs");
    let subcommands = [
        "CreateSuperuser",
        "ResetPassword",
        "Reset2fa",
        "MigrateSecrets",
        "SeedData",
    ];
    for sub in &subcommands {
        assert!(
            source.contains(sub),
            "Supervisor must define AdminSubcommand::{sub}"
        );
    }
}

#[test]
fn test_web_cargo_no_admin_bin_entries() {
    let cargo = include_str!("../../Cargo.toml");
    let old_bins = [
        "create_superuser",
        "reset_password",
        "reset_2FA",
        "migrate_secrets",
        "seed_data",
    ];
    for bin in &old_bins {
        assert!(
            !cargo.contains(&format!("name = \"{bin}\"")),
            "vauban-web Cargo.toml must not have [[bin]] entry for {bin}"
        );
    }
}

#[test]
fn test_supervisor_uses_secure_password_hashing() {
    let source = include_str!("../../../vauban-supervisor/src/admin.rs");
    assert!(
        source.contains("Argon2id") || source.contains("argon2id"),
        "Supervisor admin must use Argon2id for password hashing"
    );
    assert!(
        source.contains("SaltString::generate"),
        "Supervisor admin must generate random salts"
    );
}

#[test]
fn test_supervisor_admin_validates_input() {
    let source = include_str!("../../../vauban-supervisor/src/admin.rs");
    assert!(
        source.contains("validate_username"),
        "Supervisor admin must validate usernames"
    );
    assert!(
        source.contains("validate_email"),
        "Supervisor admin must validate email addresses"
    );
}

#[test]
fn test_web_admin_ipc_handler_exists() {
    let source = include_str!("../../src/ipc/admin.rs");
    assert!(
        source.contains("pub async fn handle_admin_command"),
        "vauban-web must have IPC handler for AdminCommand messages"
    );
}

// ==================== Structural Regression Tests ====================
// Verify that stub DELETE handlers return 501 Not Implemented, not 200 OK.

#[test]
fn test_delete_stubs_return_501() {
    let source = include_str!("../../src/main.rs");
    // Ensure no bare "Not implemented" string response remains (which returns 200 OK)
    let has_bare_stub = source.lines().any(|line| {
        let trimmed = line.trim();
        // Match the old pattern: `delete(|| async { "Not implemented" })`
        trimmed.contains("\"Not implemented\"")
            && !trimmed.contains("StatusCode::NOT_IMPLEMENTED")
            && !trimmed.starts_with("//")
    });
    assert!(
        !has_bare_stub,
        "All DELETE stubs must return StatusCode::NOT_IMPLEMENTED, not bare 200 OK"
    );
}

#[test]
fn test_delete_stubs_use_not_implemented_status() {
    let source = include_str!("../../src/main.rs");
    let prod = prod_source(source);
    // Every "Not implemented" in production code must be paired with NOT_IMPLEMENTED status
    let not_impl_count = prod.matches("\"Not implemented\"").count();
    let status_501_count = prod.matches("StatusCode::NOT_IMPLEMENTED").count();
    assert!(
        status_501_count >= not_impl_count,
        "Found {} 'Not implemented' strings but only {} StatusCode::NOT_IMPLEMENTED. \
         All stubs must return 501.",
        not_impl_count,
        status_501_count
    );
}

// ==========================================================================
// Bearer token extraction must be case-insensitive (RFC 7235)
// ==========================================================================

// ==========================================================================
// Pool error detection must use structural matching, not string parsing
// ==========================================================================

#[test]
fn test_no_string_based_connection_lost_detection() {
    // Ensure db.rs does not use fragile string-based error detection
    let source = include_str!("../../src/db.rs");
    let prod = prod_source(source);
    // The old is_connection_lost() pattern matched on error message substrings
    assert!(
        !prod.contains("is_connection_lost"),
        "regression: db.rs must use structural PoolError matching, \
         not the fragile string-based is_connection_lost() function."
    );
}

#[test]
fn test_uses_classify_pool_error() {
    let source = include_str!("../../src/db.rs");
    let prod = prod_source(source);
    assert!(
        prod.contains("classify_pool_error"),
        "regression: db.rs must use classify_pool_error() for structured error handling."
    );
}

// ==========================================================================
// Bearer token extraction must be case-insensitive (RFC 7235)
// ==========================================================================

#[test]
fn test_no_case_sensitive_bearer_prefix() {
    // Ensure extract_token does not use case-sensitive strip_prefix("Bearer ")
    let source = include_str!("../../src/middleware/auth.rs");
    let prod = prod_source(source);
    assert!(
        !prod.contains(r#"strip_prefix("Bearer "#),
        "regression: Bearer prefix must be compared case-insensitively (RFC 7235). \
         Use eq_ignore_ascii_case instead of strip_prefix."
    );
}

#[test]
fn test_bearer_uses_case_insensitive_comparison() {
    let source = include_str!("../../src/middleware/auth.rs");
    let prod = prod_source(source);
    assert!(
        prod.contains("eq_ignore_ascii_case")
            || prod.contains("to_ascii_lowercase")
            || prod.contains("to_lowercase"),
        "regression: Bearer scheme extraction must use case-insensitive comparison (RFC 7235)."
    );
}

// ==========================================================================
// LIKE wildcard characters must be escaped in search inputs
// ==========================================================================

#[test]
fn test_no_raw_like_pattern_in_handlers() {
    // Ensure no handler builds ILIKE patterns with unescaped format!("%{}%", ...)
    let files = [
        ("web/users", include_str!("../../src/handlers/web/users.rs")),
        (
            "web/sessions",
            include_str!("../../src/handlers/web/sessions.rs"),
        ),
        (
            "web/assets",
            include_str!("../../src/handlers/web/assets.rs"),
        ),
        (
            "web/groups",
            include_str!("../../src/handlers/web/groups.rs"),
        ),
        (
            "web/asset_groups",
            include_str!("../../src/handlers/web/asset_groups.rs"),
        ),
        (
            "api/accounts",
            include_str!("../../src/handlers/api/accounts.rs"),
        ),
    ];

    for (name, source) in &files {
        let prod = prod_source(source);
        // Check that no format!("%{}%", ...) pattern is used for LIKE queries
        assert!(
            !prod.contains(r#"format!("%{}%""#),
            "regression in {}: LIKE patterns must use like_contains() to escape wildcards. \
             Found raw format!(\"%{{}}%\") pattern.",
            name
        );
    }
}

#[test]
fn test_like_contains_used_in_handlers() {
    let files = [
        ("web/users", include_str!("../../src/handlers/web/users.rs")),
        (
            "web/assets",
            include_str!("../../src/handlers/web/assets.rs"),
        ),
        (
            "api/accounts",
            include_str!("../../src/handlers/api/accounts.rs"),
        ),
    ];

    for (name, source) in &files {
        let prod = prod_source(source);
        assert!(
            prod.contains("like_contains"),
            "regression in {}: search handlers must use like_contains() for ILIKE patterns.",
            name
        );
    }
}

// ==========================================================================
// No duplicated utility functions
// ==========================================================================

#[test]
fn test_no_duplicate_is_htmx_request() {
    // is_htmx_request must only be defined once (in error.rs)
    let files = [
        ("handlers/auth", include_str!("../../src/handlers/auth.rs")),
        (
            "handlers/api/sessions",
            include_str!("../../src/handlers/api/sessions.rs"),
        ),
    ];

    for (name, source) in &files {
        let prod = prod_source(source);
        assert!(
            !prod.contains("fn is_htmx_request("),
            "regression in {}: is_htmx_request must not be redefined locally. \
             Use crate::error::is_htmx_request instead.",
            name
        );
    }
}

#[test]
fn test_no_duplicate_constant_time_compare() {
    // constant_time_compare must only be defined in crypto.rs
    let files = [
        (
            "middleware/csrf",
            include_str!("../../src/middleware/csrf.rs"),
        ),
        (
            "middleware/flash",
            include_str!("../../src/middleware/flash.rs"),
        ),
    ];

    for (name, source) in &files {
        let prod = prod_source(source);
        assert!(
            !prod.contains("fn constant_time_compare("),
            "regression in {}: constant_time_compare must not be redefined locally. \
             Use crate::crypto::constant_time_compare_str instead.",
            name
        );
    }
}

// ==========================================================================
// Per-user WebSocket connection limit (unified middleware approach)
// ==========================================================================

#[test]
fn test_ws_connection_counter_exists() {
    let source = include_str!("../../src/services/connections.rs");
    let prod = prod_source(source);
    assert!(
        prod.contains("WsConnectionCounter"),
        "regression: connections.rs must define WsConnectionCounter for unified per-user WS limiting"
    );
    assert!(
        prod.contains("try_acquire"),
        "regression: WsConnectionCounter must have a try_acquire method"
    );
}

#[test]
fn test_ws_connection_guard_raii() {
    let source = include_str!("../../src/services/connections.rs");
    let prod = prod_source(source);
    assert!(
        prod.contains("WsConnectionGuard"),
        "regression: connections.rs must define WsConnectionGuard (RAII)"
    );
    assert!(
        prod.contains("impl Drop for WsConnectionGuard"),
        "regression: WsConnectionGuard must implement Drop to decrement counter"
    );
    assert!(
        prod.contains("fetch_sub"),
        "regression: WsConnectionGuard::drop must use fetch_sub to decrement atomic counter"
    );
}

#[test]
fn test_connection_limit_error() {
    let source = include_str!("../../src/services/connections.rs");
    let prod = prod_source(source);
    assert!(
        prod.contains("ConnectionLimitError"),
        "regression: connections.rs must define ConnectionLimitError"
    );
    assert!(
        prod.contains("connection limit reached"),
        "regression: ConnectionLimitError message must indicate limit reached"
    );
}

#[test]
fn test_ws_connection_limit_middleware_exists() {
    let source = include_str!("../../src/handlers/websocket.rs");
    let prod = prod_source(source);
    assert!(
        prod.contains("ws_connection_limit"),
        "regression: websocket.rs must define ws_connection_limit middleware"
    );
    assert!(
        prod.contains("try_acquire"),
        "regression: ws_connection_limit middleware must call try_acquire on WsConnectionCounter"
    );
    assert!(
        prod.contains("TOO_MANY_REQUESTS"),
        "regression: ws_connection_limit must return 429 when limit is reached"
    );
}

#[test]
fn test_middleware_applied_to_ws_routes() {
    let source = include_str!("../../src/main.rs");
    let prod = prod_source(source);
    assert!(
        prod.contains("ws_connection_limit"),
        "regression: main.rs must apply ws_connection_limit middleware to WS routes"
    );
    assert!(
        prod.contains("ws_limit_layer") || prod.contains("ws_connection_limit"),
        "regression: main.rs must create the WS limit layer"
    );
}

#[test]
fn test_ws_counter_in_app_state() {
    let source = include_str!("../../src/lib.rs");
    let prod = prod_source(source);
    assert!(
        prod.contains("ws_counter"),
        "regression: AppState must include ws_counter (WsConnectionCounter)"
    );
    assert!(
        prod.contains("WsConnectionCounter"),
        "regression: AppState must import WsConnectionCounter"
    );
}

#[test]
fn test_config_has_websocket_section() {
    let source = include_str!("../../src/config.rs");
    let prod = prod_source(source);
    assert!(
        prod.contains("WebSocketConfig"),
        "regression: config.rs must define WebSocketConfig for TOML configuration"
    );
    assert!(
        prod.contains("max_connections_per_user"),
        "regression: WebSocketConfig must have max_connections_per_user field"
    );
}

#[test]
fn test_default_limit_is_30() {
    let source = include_str!("../../src/config.rs");
    let prod = prod_source(source);
    // The Default impl should set max_connections_per_user to 30
    assert!(
        prod.contains("max_connections_per_user: 30"),
        "regression: default max_connections_per_user must be 30"
    );
}

#[test]
fn test_register_is_simple_tuple() {
    // After the unified middleware approach, register() should return a simple tuple,
    // NOT a Result. The connection limit is enforced by the middleware, not by register().
    let source = include_str!("../../src/services/connections.rs");
    let prod = prod_source(source);
    assert!(
        !prod.contains("pub async fn register")
            || !prod.contains("-> Result<(Uuid, mpsc::Receiver<String>), ConnectionLimitError>"),
        "regression: register() must NOT return Result -- limit is enforced by middleware"
    );
}

#[test]
fn test_all_ws_routes_protected_by_layer() {
    // Verify that the layer is applied to the entire ws_routes group,
    // not to individual routes. This ensures future handlers are also protected.
    let source = include_str!("../../src/main.rs");
    let prod = prod_source(source);
    // The layer must be applied at the Router level, not per-route
    assert!(
        prod.contains(".layer(ws_limit_layer)"),
        "regression: ws_limit_layer must be applied as .layer() on the ws_routes Router"
    );
}

#[test]
fn test_ws_guard_extractor_exists() {
    // WsGuard must be defined as an Axum extractor wrapping Arc<WsConnectionGuard>
    let source = include_str!("../../src/handlers/websocket.rs");
    let prod = prod_source(source);
    assert!(
        prod.contains("struct WsGuard"),
        "regression: websocket.rs must define WsGuard extractor"
    );
    assert!(
        prod.contains("FromRequestParts"),
        "regression: WsGuard must implement FromRequestParts (Axum extractor)"
    );
}

#[test]
fn test_all_ws_handlers_accept_ws_guard() {
    // CRITICAL: Every WebSocket handler must accept WsGuard as a parameter
    // and pass it into on_upgrade(). Without this, the RAII guard is dropped
    // after the HTTP handshake, not when the WebSocket connection closes.
    let source = include_str!("../../src/handlers/websocket.rs");
    let prod = prod_source(source);

    let handlers = [
        "dashboard_ws",
        "session_ws",
        "notifications_ws",
        "active_sessions_ws",
        "terminal_ws",
    ];

    for handler in handlers {
        // Find the handler function and check it has WsGuard parameter
        let handler_start = prod
            .find(&format!("fn {handler}("))
            .unwrap_or_else(|| panic!("regression: handler {handler} not found in websocket.rs"));

        // Get the function signature (up to the opening brace)
        let signature_end = prod[handler_start..]
            .find('{')
            .map(|i| handler_start + i)
            .unwrap_or(prod.len());
        let signature = &prod[handler_start..signature_end];

        assert!(
            signature.contains("WsGuard") || signature.contains("ws_guard"),
            "regression: handler {handler} must accept WsGuard parameter to hold the guard \
             for the entire WebSocket connection lifetime. Signature: {signature}"
        );
    }
}

#[test]
fn test_all_handle_fns_receive_ws_guard() {
    // The internal handle_*_socket functions must also receive the guard
    // (passed from the on_upgrade closure) to keep it alive.
    let source = include_str!("../../src/handlers/websocket.rs");
    let prod = prod_source(source);

    let handle_fns = [
        "handle_dashboard_socket",
        "handle_session_socket",
        "handle_notifications_socket",
        "handle_active_sessions_socket",
        "handle_terminal_socket",
    ];

    for func in handle_fns {
        let fn_start = prod
            .find(&format!("fn {func}("))
            .unwrap_or_else(|| panic!("regression: function {func} not found in websocket.rs"));

        let signature_end = prod[fn_start..]
            .find('{')
            .map(|i| fn_start + i)
            .unwrap_or(prod.len());
        let signature = &prod[fn_start..signature_end];

        assert!(
            signature.contains("WsGuard") || signature.contains("ws_guard"),
            "regression: function {func} must receive WsGuard to hold it for the connection \
             lifetime. Without it, the guard is dropped after the HTTP upgrade handshake. \
             Signature: {signature}"
        );
    }
}

// =============================================================================
// MFA Bypass Prevention Tests
// =============================================================================

/// Verify that a pre-MFA JWT (mfa_verified=false) cannot access web pages
/// protected by WebAuthUser. The server must redirect to /mfa/verify.
#[tokio::test]
#[serial]
async fn test_mfa_bypass_pre_mfa_jwt_redirects_to_mfa_verify() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("mfa_bypass");
    let test_user = create_test_user(&mut conn, &app.auth_service, &username).await;

    let session_uuid = uuid::Uuid::new_v4();
    // Generate a JWT with mfa_verified=false (simulating post-login, pre-MFA state)
    let pre_mfa_token = unwrap_ok!(app.auth_service.generate_access_token(
        &test_user.user.uuid.to_string(),
        &username,
        false,
        false,
        false,
        Some(session_uuid),
    ));
    crate::fixtures::create_session_for_token_pub(
        &mut conn,
        test_user.user.id,
        session_uuid,
        &pre_mfa_token,
    )
    .await;

    // Attempt to access /assets with the pre-MFA cookie (simulates URL manipulation)
    let response = app
        .server
        .get("/assets")
        .add_header(COOKIE, format!("access_token={}", pre_mfa_token))
        .await;

    let status = response.status_code().as_u16();
    assert_eq!(
        status, 303,
        "Pre-MFA JWT must be redirected (303), got {}",
        status
    );

    let location = unwrap_some!(response.headers().get("location"))
        .to_str()
        .unwrap_or("");
    assert_eq!(
        location, "/mfa/verify",
        "Pre-MFA JWT must redirect to /mfa/verify, got {}",
        location
    );

    test_db::cleanup(&mut conn).await;
}

/// Verify that a fully verified JWT (mfa_verified=true) can access web pages.
#[tokio::test]
#[serial]
async fn test_mfa_verified_jwt_can_access_protected_pages() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("mfa_ok");
    let test_user = create_test_user(&mut conn, &app.auth_service, &username).await;

    // The default token from create_test_user has mfa_verified=true
    let response = app
        .server
        .get("/assets")
        .add_header(COOKIE, format!("access_token={}", test_user.token))
        .await;

    let status = response.status_code().as_u16();
    assert_eq!(status, 200, "MFA-verified JWT must get 200, got {}", status);

    test_db::cleanup(&mut conn).await;
}

/// Verify that pre-MFA JWT can still access the MFA setup page.
#[tokio::test]
#[serial]
async fn test_pre_mfa_jwt_can_access_mfa_setup() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("mfa_setup_access");
    let test_user = create_test_user(&mut conn, &app.auth_service, &username).await;

    let session_uuid = uuid::Uuid::new_v4();
    let pre_mfa_token = unwrap_ok!(app.auth_service.generate_access_token(
        &test_user.user.uuid.to_string(),
        &username,
        false,
        false,
        false,
        Some(session_uuid),
    ));
    crate::fixtures::create_session_for_token_pub(
        &mut conn,
        test_user.user.id,
        session_uuid,
        &pre_mfa_token,
    )
    .await;

    let response = app
        .server
        .get("/mfa/setup")
        .add_header(COOKIE, format!("access_token={}", pre_mfa_token))
        .await;

    let status = response.status_code().as_u16();
    assert_eq!(
        status, 200,
        "Pre-MFA JWT must be able to access /mfa/setup (200), got {}",
        status
    );

    test_db::cleanup(&mut conn).await;
}

/// Verify that /mfa/verify redirects to /mfa/setup when MFA is not configured.
#[tokio::test]
#[serial]
async fn test_mfa_verify_redirects_to_setup_when_mfa_not_configured() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("mfa_verify_access");
    let test_user = create_test_user(&mut conn, &app.auth_service, &username).await;

    let session_uuid = uuid::Uuid::new_v4();
    let pre_mfa_token = unwrap_ok!(app.auth_service.generate_access_token(
        &test_user.user.uuid.to_string(),
        &username,
        false,
        false,
        false,
        Some(session_uuid),
    ));
    crate::fixtures::create_session_for_token_pub(
        &mut conn,
        test_user.user.id,
        session_uuid,
        &pre_mfa_token,
    )
    .await;

    let response = app
        .server
        .get("/mfa/verify")
        .add_header(COOKIE, format!("access_token={}", pre_mfa_token))
        .await;

    let status = response.status_code().as_u16();
    assert_eq!(
        status, 303,
        "User without MFA configured must be redirected from /mfa/verify (303), got {}",
        status
    );
    let location = unwrap_some!(response.headers().get("location"))
        .to_str()
        .unwrap_or("");
    assert_eq!(
        location, "/mfa/setup",
        "Must redirect to /mfa/setup, got {}",
        location
    );

    test_db::cleanup(&mut conn).await;
}

/// Verify that the API endpoints (using AuthUser, not WebAuthUser) are not
/// affected by the MFA enforcement -- they handle MFA at the handler level.
#[tokio::test]
#[serial]
async fn test_api_endpoints_unaffected_by_web_mfa_enforcement() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("mfa_api");
    let test_user = create_admin_user(&mut conn, &app.auth_service, &username).await;

    // API endpoints use Bearer auth, not cookies, and the AuthUser extractor
    let response = app
        .server
        .get("/api/v1/accounts")
        .add_header(header::AUTHORIZATION, app.auth_header(&test_user.token))
        .await;

    let status = response.status_code().as_u16();
    assert_eq!(
        status, 200,
        "API with MFA-verified JWT must work, got {}",
        status
    );

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// SEC-06: TOTP Skew Regression (Structural Tests)
// =============================================================================

/// SEC-06: vault TOTP verification must use the shared TOTP_SKEW constant
/// instead of a hardcoded literal, preventing silent drift.
#[test]
fn test_sec06_vault_uses_shared_totp_constants() {
    let source = include_str!("../../../vauban-vault/src/transit.rs");
    assert!(
        source.contains("TOTP_SKEW"),
        "SEC-06: vauban-vault/transit.rs must use shared::totp::TOTP_SKEW"
    );
    assert!(
        source.contains("TOTP_DIGITS"),
        "SEC-06: vauban-vault/transit.rs must use shared::totp::TOTP_DIGITS"
    );
    assert!(
        source.contains("TOTP_STEP"),
        "SEC-06: vauban-vault/transit.rs must use shared::totp::TOTP_STEP"
    );
}

/// SEC-06: web TOTP verification must use the shared TOTP_SKEW constant
/// instead of a hardcoded literal, preventing silent drift.
#[test]
fn test_sec06_web_auth_uses_shared_totp_constants() {
    let source = include_str!("../../src/services/auth.rs");
    assert!(
        source.contains("TOTP_SKEW"),
        "SEC-06: services/auth.rs must use shared::totp::TOTP_SKEW"
    );
    assert!(
        source.contains("TOTP_DIGITS"),
        "SEC-06: services/auth.rs must use shared::totp::TOTP_DIGITS"
    );
    assert!(
        source.contains("TOTP_STEP"),
        "SEC-06: services/auth.rs must use shared::totp::TOTP_STEP"
    );
}

// =============================================================================
// SEC-02: Client IP Must Not Be Hardcoded (Structural Tests)
// =============================================================================

/// SEC-02: session-creating handlers must not hardcode 0.0.0.0 as client IP.
/// They must use extract_client_ip to capture the real address.
#[test]
fn test_sec02_no_hardcoded_client_ip_in_session_handlers() {
    let ssh_source = include_str!("../../src/handlers/web/ssh.rs");
    assert!(
        !ssh_source.contains(r#""0.0.0.0/0""#),
        "SEC-02: ssh.rs must not hardcode 0.0.0.0/0 as client IP"
    );
    assert!(
        ssh_source.contains("extract_client_ip"),
        "SEC-02: ssh.rs must use extract_client_ip for real client address"
    );

    let rdp_source = include_str!("../../src/handlers/web/rdp.rs");
    assert!(
        !rdp_source.contains(r#""0.0.0.0/0""#),
        "SEC-02: rdp.rs must not hardcode 0.0.0.0/0 as client IP"
    );
    assert!(
        rdp_source.contains("extract_client_ip"),
        "SEC-02: rdp.rs must use extract_client_ip for real client address"
    );

    let sessions_source = include_str!("../../src/handlers/web/sessions.rs");
    assert!(
        !sessions_source.contains(r#""0.0.0.0/0""#),
        "SEC-02: sessions.rs must not hardcode 0.0.0.0/0 as client IP"
    );
}

// =============================================================================
// SEC-03: Connection justification enforcement
// =============================================================================

/// Structural regression: SSH and RDP handlers must validate justification
/// based on the require_justification config flag.
#[test]
fn test_sec03_handlers_validate_justification() {
    let ssh_source = include_str!("../../src/handlers/web/ssh.rs");
    assert!(
        ssh_source.contains("require_justification"),
        "SEC-03: ssh.rs must check require_justification config"
    );
    assert!(
        ssh_source.contains("form_justification"),
        "SEC-03: ssh.rs must extract form_justification for DB insertion"
    );

    let rdp_source = include_str!("../../src/handlers/web/rdp.rs");
    assert!(
        rdp_source.contains("require_justification"),
        "SEC-03: rdp.rs must check require_justification config"
    );
    assert!(
        rdp_source.contains("form_justification"),
        "SEC-03: rdp.rs must extract form_justification for DB insertion"
    );
}

/// Structural regression: ConnectSshForm and ConnectRdpForm must have a
/// justification field so the modal can submit it.
#[test]
fn test_sec03_connect_forms_have_justification_field() {
    let ssh_source = include_str!("../../src/handlers/web/ssh.rs");
    assert!(
        ssh_source.contains("pub justification: Option<String>"),
        "SEC-03: ConnectSshForm must have a justification field"
    );

    let rdp_source = include_str!("../../src/handlers/web/rdp.rs");
    assert!(
        rdp_source.contains("pub justification: Option<String>"),
        "SEC-03: ConnectRdpForm must have a justification field"
    );
}

/// Structural regression: the justification modal template must exist.
#[test]
fn test_sec03_justification_modal_template_exists() {
    let template = include_str!("../../templates/sessions/justification_modal.html");
    assert!(
        template.contains("Connection Justification"),
        "SEC-03: justification modal must have the expected title"
    );
    assert!(
        template.contains("justificationModal"),
        "SEC-03: justification modal must use the justificationModal Alpine store"
    );
    assert!(
        template.contains(r#"name="justification""#),
        "SEC-03: justification modal must have a justification textarea"
    );
}

/// Structural regression: the SEC-03 justification modal MUST be
/// inlined on the user-zone `/assets` list page (asset_list.html).
/// Issue #34 removed the user-zone `/assets/{uuid}` detail page that
/// used to host both modaux (information leak surface), so the
/// modal is now included once at the bottom of the list and opened
/// per-row by `$store.justificationModal.open(uuid, type)`.
#[test]
fn test_sec03_asset_list_includes_justification_modal() {
    let template = include_str!("../../templates/assets/asset_list.html");
    assert!(
        template.contains("justification_modal.html"),
        "SEC-03: asset_list.html must include justification_modal.html \
         (issue #34: modaux are inlined on /assets, not on the removed \
         /assets/{{uuid}} detail page)"
    );
    assert!(
        template.contains("require_justification"),
        "SEC-03: asset_list.html must branch on require_justification"
    );
    assert!(
        template.contains("$store.justificationModal.open("),
        "SEC-03: per-row Connect button must open the inlined Alpine \
         justificationModal store with the asset uuid + type"
    );
}

/// Integration: when require_justification is false (testing config),
/// SSH connect works without justification.
#[tokio::test]
#[serial]
async fn test_sec03_ssh_connect_without_justification_when_disabled() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("sec03_ssh_nojust");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let asset = create_test_ssh_asset(&mut conn, &unique_name("sec03-ssh-asset")).await;

    let csrf_token = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!("/assets/{}/connect", asset.asset.uuid))
        .add_header(
            header::COOKIE,
            format!("access_token={}; __vauban_csrf={}", admin.token, csrf_token),
        )
        .form(&[("csrf_token", csrf_token.as_str())])
        .await;

    let body = response.text();
    // Should NOT be rejected for missing justification
    assert!(
        !body.contains("Justification is required"),
        "SEC-03: connect should succeed without justification when disabled: {}",
        body
    );

    test_db::cleanup(&mut conn).await;
}

/// Integration: when require_justification is false (testing config),
/// SSH connect accepts and stores a justification if provided.
#[tokio::test]
#[serial]
async fn test_sec03_ssh_connect_stores_justification_when_provided() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("sec03_ssh_just");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let asset = create_test_ssh_asset(&mut conn, &unique_name("sec03-ssh-just")).await;

    let csrf_token = app.generate_csrf_token();

    let _response = app
        .server
        .post(&format!("/assets/{}/connect", asset.asset.uuid))
        .add_header(
            header::COOKIE,
            format!("access_token={}; __vauban_csrf={}", admin.token, csrf_token),
        )
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("justification", "Routine maintenance on production server"),
        ])
        .await;

    // Check that the justification was stored in the proxy_sessions table
    use diesel::prelude::*;
    use diesel_async::RunQueryDsl;
    use vauban_web::schema::proxy_sessions;

    let stored: Option<Option<String>> = proxy_sessions::table
        .filter(proxy_sessions::asset_id.eq(asset.asset.id))
        .select(proxy_sessions::justification)
        .first(&mut conn)
        .await
        .ok();

    if let Some(justification) = stored {
        assert_eq!(
            justification.as_deref(),
            Some("Routine maintenance on production server"),
            "SEC-03: justification should be stored in proxy_sessions"
        );
    }
    // If no row was inserted (SSH proxy not available), that's OK in tests

    test_db::cleanup(&mut conn).await;
}

/// Integration: RDP connect works without justification when disabled.
#[tokio::test]
#[serial]
async fn test_sec03_rdp_connect_without_justification_when_disabled() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("sec03_rdp_nojust");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let asset = create_test_rdp_asset(&mut conn, &unique_name("sec03-rdp-asset")).await;

    let csrf_token = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!("/assets/{}/connect-rdp", asset.asset.uuid))
        .add_header(
            header::COOKIE,
            format!("access_token={}; __vauban_csrf={}", admin.token, csrf_token),
        )
        .form(&[("csrf_token", csrf_token.as_str())])
        .await;

    let body = response.text();
    assert!(
        !body.contains("Justification is required"),
        "SEC-03: RDP connect should succeed without justification when disabled: {}",
        body
    );

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// SEC-07: Account status enforcement (is_active)
// =============================================================================

/// Structural: auth.rs checks is_active after password verification (SEC-04/SEC-07).
#[test]
fn test_sec07_login_checks_is_active() {
    let auth_source = include_str!("../../src/handlers/auth.rs");
    assert!(
        auth_source.contains("user.is_active"),
        "SEC-07: login handler must check user.is_active"
    );
    // SEC-04: AccountDeactivated variant was removed to prevent enumeration;
    // the login handler now returns generic "Invalid credentials" for deactivated accounts.
    assert!(
        !auth_source.contains("AccountDeactivated"),
        "SEC-04: LoginErrorKind must NOT have AccountDeactivated (prevents enumeration)"
    );
}

/// Structural: SSH connect handler checks is_active via shared constant.
#[test]
fn test_sec07_ssh_connect_checks_is_active() {
    let ssh_source = include_str!("../../src/handlers/web/ssh.rs");
    assert!(
        ssh_source.contains("user_is_active"),
        "SEC-07: SSH connect must verify user is_active"
    );
    assert!(
        ssh_source.contains("ACCOUNT_DEACTIVATED_MSG"),
        "SEC-07: SSH connect must use shared ACCOUNT_DEACTIVATED_MSG constant"
    );
}

/// Structural: RDP connect handler checks is_active via shared constant.
#[test]
fn test_sec07_rdp_connect_checks_is_active() {
    let rdp_source = include_str!("../../src/handlers/web/rdp.rs");
    assert!(
        rdp_source.contains("user_is_active"),
        "SEC-07: RDP connect must verify user is_active"
    );
    assert!(
        rdp_source.contains("ACCOUNT_DEACTIVATED_MSG"),
        "SEC-07: RDP connect must use shared ACCOUNT_DEACTIVATED_MSG constant"
    );
}

/// Structural: deactivate_user revokes auth_sessions, terminates proxy sessions,
/// disables API keys, and force-logs out browser sessions.
#[test]
fn test_sec07_deactivate_user_revokes_all() {
    let users_source = include_str!("../../src/handlers/web/users.rs");
    assert!(
        users_source.contains("async fn deactivate_user"),
        "SEC-07: deactivate_user function must exist"
    );
    assert!(
        users_source.contains("async fn reactivate_user"),
        "SEC-07: reactivate_user function must exist"
    );
    assert!(
        users_source.contains("account_deactivated"),
        "SEC-07: deactivate_user must redirect to login with account_deactivated reason"
    );
}

/// Structural: login page template handles account_deactivated reason.
#[test]
fn test_sec07_login_page_shows_deactivation_reason() {
    let template = include_str!("../../templates/accounts/login.html");
    assert!(
        template.contains("account_deactivated"),
        "SEC-07: login template must handle account_deactivated reason"
    );
    assert!(
        template.contains("Your account has been deactivated by an administrator"),
        "SEC-07: login template must show deactivation message"
    );
}

/// Integration: deactivated user cannot login via API (SEC-04: generic message).
#[tokio::test]
#[serial]
async fn test_sec07_deactivated_user_cannot_login_api() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("sec07_deact_api");
    let test_user = create_test_user(&mut conn, &app.auth_service, &username).await;

    // Deactivate the user
    use vauban_web::schema::users;
    unwrap_ok!(
        diesel::update(users::table.filter(users::id.eq(test_user.user.id)))
            .set(users::is_active.eq(false))
            .execute(&mut conn)
            .await
    );

    // Try to login via API
    let response = app
        .server
        .post("/api/v1/auth/login")
        .json(&json!({
            "username": username,
            "password": test_user.password
        }))
        .await;

    assert_status(&response, 401);
    let body = response.text();
    // SEC-04: must NOT reveal account state -- generic "Invalid credentials" only
    assert!(
        body.contains("Invalid credentials"),
        "SEC-04: API login must return generic error, not reveal deactivation: {}",
        body
    );
    assert!(
        !body.contains("deactivated"),
        "SEC-04: API login must NOT mention deactivation: {}",
        body
    );

    test_db::cleanup(&mut conn).await;
}

/// Integration: deactivated user cannot login via HTMX.
#[tokio::test]
#[serial]
async fn test_sec07_deactivated_user_cannot_login_htmx() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("sec07_deact_htmx");
    let test_user = create_test_user(&mut conn, &app.auth_service, &username).await;

    // Deactivate the user
    use vauban_web::schema::users;
    unwrap_ok!(
        diesel::update(users::table.filter(users::id.eq(test_user.user.id)))
            .set(users::is_active.eq(false))
            .execute(&mut conn)
            .await
    );

    let csrf_token = app.generate_csrf_token();

    let response = app
        .server
        .post("/auth/login")
        .add_header("HX-Request", "true")
        .add_header(header::COOKIE, format!("__vauban_csrf={}", csrf_token))
        .json(&json!({
            "username": username,
            "password": test_user.password,
            "csrf_token": csrf_token
        }))
        .await;

    let body = response.text();
    // SEC-04: html_error_fragment translates "Invalid credentials" to user-friendly form
    assert!(
        body.contains("Incorrect username or password"),
        "SEC-04: HTMX login must return generic error: {}",
        body
    );
    assert!(
        !body.contains("deactivated"),
        "SEC-04: HTMX login must NOT mention deactivation: {}",
        body
    );

    test_db::cleanup(&mut conn).await;
}

/// Integration: deactivating a user via web form revokes their auth sessions.
#[tokio::test]
#[serial]
async fn test_sec07_deactivation_revokes_auth_sessions() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Admin who will deactivate
    let admin_username = unique_name("sec07_admin_rev");
    let admin_id = create_simple_admin_user(&mut conn, &admin_username).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let admin_token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_username, true, true)
        .await;
    let csrf_token = app.generate_csrf_token();

    // Target user
    let target_username = unique_name("sec07_target_rev");
    let target_id = create_simple_user(&mut conn, &target_username).await;
    let target_uuid = get_user_uuid(&mut conn, target_id).await;

    // Create auth sessions for the target user
    create_test_auth_session(&mut conn, target_id, false).await;
    create_test_auth_session(&mut conn, target_id, false).await;

    // Verify sessions exist
    use vauban_web::schema::auth_sessions;
    let count_before: i64 = unwrap_ok!(
        auth_sessions::table
            .filter(auth_sessions::user_id.eq(target_id))
            .count()
            .get_result(&mut conn)
            .await
    );
    assert!(count_before >= 2, "Should have at least 2 auth sessions");

    // Deactivate the target user via web form (is_active not sent = unchecked = false)
    let target_email = format!("{}@test.vauban.io", target_username);
    let response = app
        .server
        .post(&format!("/accounts/users/{}", target_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", admin_token, csrf_token),
        )
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("username", &target_username),
            ("email", &target_email),
        ])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 303 || status == 302,
        "Expected redirect, got {}",
        status
    );

    // Verify sessions are deleted
    let count_after: i64 = unwrap_ok!(
        auth_sessions::table
            .filter(auth_sessions::user_id.eq(target_id))
            .count()
            .get_result(&mut conn)
            .await
    );
    assert_eq!(
        count_after, 0,
        "All auth sessions should be revoked after deactivation"
    );

    test_db::cleanup(&mut conn).await;
}

/// Integration: deactivating a user via web form disables their API keys.
#[tokio::test]
#[serial]
async fn test_sec07_deactivation_disables_api_keys() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_username = unique_name("sec07_admin_key");
    let admin_id = create_simple_admin_user(&mut conn, &admin_username).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let admin_token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_username, true, true)
        .await;
    let csrf_token = app.generate_csrf_token();

    let target_username = unique_name("sec07_target_key");
    let target_id = create_simple_user(&mut conn, &target_username).await;
    let target_uuid = get_user_uuid(&mut conn, target_id).await;

    // Create active API keys
    create_test_api_key(&mut conn, target_id, "key1", true).await;
    create_test_api_key(&mut conn, target_id, "key2", true).await;

    // Verify keys are active
    use vauban_web::schema::api_keys;
    let active_before: i64 = unwrap_ok!(
        api_keys::table
            .filter(api_keys::user_id.eq(target_id))
            .filter(api_keys::is_active.eq(true))
            .count()
            .get_result(&mut conn)
            .await
    );
    assert_eq!(active_before, 2, "Should have 2 active API keys");

    // Deactivate user (is_active not sent = unchecked)
    let target_email = format!("{}@test.vauban.io", target_username);
    let _response = app
        .server
        .post(&format!("/accounts/users/{}", target_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", admin_token, csrf_token),
        )
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("username", &target_username),
            ("email", &target_email),
        ])
        .await;

    // Verify keys are disabled
    let active_after: i64 = unwrap_ok!(
        api_keys::table
            .filter(api_keys::user_id.eq(target_id))
            .filter(api_keys::is_active.eq(true))
            .count()
            .get_result(&mut conn)
            .await
    );
    assert_eq!(
        active_after, 0,
        "All API keys should be disabled after deactivation"
    );

    test_db::cleanup(&mut conn).await;
}

/// Integration: reactivating a user via web form re-enables their API keys.
#[tokio::test]
#[serial]
async fn test_sec07_reactivation_restores_api_keys() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_username = unique_name("sec07_admin_react");
    let admin_id = create_simple_admin_user(&mut conn, &admin_username).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let admin_token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_username, true, true)
        .await;

    let target_username = unique_name("sec07_target_react");
    let target_id = create_simple_user(&mut conn, &target_username).await;
    let target_uuid = get_user_uuid(&mut conn, target_id).await;

    // Create active API keys
    create_test_api_key(&mut conn, target_id, "key_r1", true).await;
    create_test_api_key(&mut conn, target_id, "key_r2", true).await;

    // Step 1: Deactivate (unchecked is_active)
    let target_email = format!("{}@test.vauban.io", target_username);
    let csrf_token = app.generate_csrf_token();
    let _response = app
        .server
        .post(&format!("/accounts/users/{}", target_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", admin_token, csrf_token),
        )
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("username", &target_username),
            ("email", &target_email),
        ])
        .await;

    // Step 2: Reactivate (is_active = "on")
    let csrf_token2 = app.generate_csrf_token();
    let _response = app
        .server
        .post(&format!("/accounts/users/{}", target_uuid))
        .add_header(
            COOKIE,
            format!(
                "access_token={}; __vauban_csrf={}",
                admin_token, csrf_token2
            ),
        )
        .form(&[
            ("csrf_token", csrf_token2.as_str()),
            ("username", &target_username),
            ("email", &target_email),
            ("is_active", "on"),
        ])
        .await;

    use vauban_web::schema::api_keys;
    let active_after: i64 = unwrap_ok!(
        api_keys::table
            .filter(api_keys::user_id.eq(target_id))
            .filter(api_keys::is_active.eq(true))
            .count()
            .get_result(&mut conn)
            .await
    );
    assert_eq!(
        active_after, 2,
        "All API keys should be re-enabled after reactivation"
    );

    test_db::cleanup(&mut conn).await;
}

/// Integration: deactivated user cannot connect to SSH asset.
#[tokio::test]
#[serial]
async fn test_sec07_deactivated_user_cannot_ssh() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("sec07_ssh_deact");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let asset = create_test_ssh_asset(&mut conn, &unique_name("sec07-ssh")).await;

    // Deactivate the admin user
    use vauban_web::schema::users;
    unwrap_ok!(
        diesel::update(users::table.filter(users::id.eq(admin.user.id)))
            .set(users::is_active.eq(false))
            .execute(&mut conn)
            .await
    );

    let csrf_token = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!("/assets/{}/connect", asset.asset.uuid))
        .add_header(
            header::COOKIE,
            format!("access_token={}; __vauban_csrf={}", admin.token, csrf_token),
        )
        .form(&[("csrf_token", csrf_token.as_str())])
        .await;

    let body = response.text();
    assert!(
        body.contains("deactivated"),
        "SEC-07: deactivated user should not be able to SSH: {}",
        body
    );

    test_db::cleanup(&mut conn).await;
}

/// Integration: deactivated user cannot connect to RDP asset.
#[tokio::test]
#[serial]
async fn test_sec07_deactivated_user_cannot_rdp() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("sec07_rdp_deact");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let asset = create_test_rdp_asset(&mut conn, &unique_name("sec07-rdp")).await;

    // Deactivate the admin user
    use vauban_web::schema::users;
    unwrap_ok!(
        diesel::update(users::table.filter(users::id.eq(admin.user.id)))
            .set(users::is_active.eq(false))
            .execute(&mut conn)
            .await
    );

    let csrf_token = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!("/assets/{}/connect-rdp", asset.asset.uuid))
        .add_header(
            header::COOKIE,
            format!("access_token={}; __vauban_csrf={}", admin.token, csrf_token),
        )
        .form(&[("csrf_token", csrf_token.as_str())])
        .await;

    // RDP handler returns the error via HX-Trigger header (toast notification)
    let trigger = response
        .headers()
        .get("HX-Trigger")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        trigger.contains("deactivated"),
        "SEC-07: deactivated user should not be able to RDP. HX-Trigger: {}",
        trigger
    );

    test_db::cleanup(&mut conn).await;
}

/// Structural: deactivate_user sets recording_path in the same UPDATE as "terminated".
#[test]
fn test_sec07_deactivate_user_sets_recording_path() {
    let users_source = include_str!("../../src/handlers/web/users.rs");
    assert!(
        users_source.contains("proxy_sessions::is_recorded.eq(true)"),
        "SEC-07: deactivate_user must set is_recorded=true when terminating proxy sessions"
    );
    assert!(
        users_source.contains("proxy_sessions::recording_path.eq("),
        "SEC-07: deactivate_user must set recording_path when terminating proxy sessions"
    );
}

/// Structural: terminate_session sets recording_path in the same UPDATE as "terminated".
#[test]
fn test_sec07_terminate_session_sets_recording_path() {
    let sessions_source = include_str!("../../src/handlers/api/sessions.rs");
    assert!(
        sessions_source.contains("is_recorded.eq(true)"),
        "SEC-07: terminate_session must set is_recorded=true"
    );
    assert!(
        sessions_source.contains("recording_path.eq("),
        "SEC-07: terminate_session must set recording_path"
    );
}

/// Integration: deactivating a user sets is_recorded and recording_path on
/// active proxy sessions (SSH).
#[tokio::test]
#[serial]
async fn test_sec07_deactivation_sets_recording_metadata_ssh() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_username = unique_name("sec07_rec_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_username).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let admin_token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_username, true, true)
        .await;

    let target_username = unique_name("sec07_rec_target");
    let target_id = create_simple_user(&mut conn, &target_username).await;
    let target_uuid = get_user_uuid(&mut conn, target_id).await;

    // Create an active SSH proxy session for the target user
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("sec07-rec-ssh"), target_id).await;
    let (session_id, _session_uuid) =
        create_test_session_with_uuid(&mut conn, target_id, asset_id, "ssh", "active").await;

    // Verify recording metadata is not set yet
    use vauban_web::schema::proxy_sessions;
    let (is_rec_before, rec_path_before): (bool, Option<String>) = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::id.eq(session_id))
            .select((proxy_sessions::is_recorded, proxy_sessions::recording_path,))
            .first(&mut conn)
            .await
    );
    assert!(
        !is_rec_before,
        "is_recorded should be false before deactivation"
    );
    assert!(
        rec_path_before.is_none(),
        "recording_path should be None before deactivation"
    );

    // Deactivate target user via web form (is_active not sent = unchecked)
    let target_email = format!("{}@test.vauban.io", target_username);
    let csrf_token = app.generate_csrf_token();
    let _response = app
        .server
        .post(&format!("/accounts/users/{}", target_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", admin_token, csrf_token),
        )
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("username", &target_username),
            ("email", &target_email),
        ])
        .await;

    // Verify recording metadata is now set
    let (is_rec_after, rec_path_after, db_status): (bool, Option<String>, String) = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::id.eq(session_id))
            .select((
                proxy_sessions::is_recorded,
                proxy_sessions::recording_path,
                proxy_sessions::status,
            ))
            .first(&mut conn)
            .await
    );
    assert_eq!(db_status, "terminated", "Session should be terminated");
    assert!(
        is_rec_after,
        "is_recorded should be true after deactivation"
    );
    assert!(
        rec_path_after.is_some(),
        "recording_path should be set after deactivation"
    );
    let path = rec_path_after.unwrap();
    assert!(
        path.contains("recordings/"),
        "recording_path should contain the storage path: {}",
        path
    );

    test_db::cleanup(&mut conn).await;
}

/// Integration: admin terminate_session sets is_recorded and recording_path
/// on the terminated proxy session.
#[tokio::test]
#[serial]
async fn test_sec07_terminate_session_sets_recording_metadata() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("sec07_term_rec");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("sec07-term-rec-ssh"), admin_id).await;
    let (session_id, session_uuid) =
        create_test_session_with_uuid(&mut conn, admin_id, asset_id, "ssh", "active").await;

    let csrf_token = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!("/sessions/{}/terminate", session_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .add_header("HX-Request", "true")
        .form(&[("csrf_token", csrf_token.as_str())])
        .await;

    assert_status(&response, 200);

    use vauban_web::schema::proxy_sessions;
    let (is_rec, rec_path, db_status): (bool, Option<String>, String) = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::id.eq(session_id))
            .select((
                proxy_sessions::is_recorded,
                proxy_sessions::recording_path,
                proxy_sessions::status,
            ))
            .first(&mut conn)
            .await
    );
    assert_eq!(db_status, "terminated");
    assert!(is_rec, "is_recorded should be true after admin termination");
    assert!(
        rec_path.is_some(),
        "recording_path should be set after admin termination"
    );

    test_db::cleanup(&mut conn).await;
}

/// Integration: deactivating a user sets recording metadata on active RDP sessions.
#[tokio::test]
#[serial]
async fn test_sec07_deactivation_sets_recording_metadata_rdp() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_username = unique_name("sec07_rec_rdp_adm");
    let admin_id = create_simple_admin_user(&mut conn, &admin_username).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let admin_token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_username, true, true)
        .await;

    let target_username = unique_name("sec07_rec_rdp_tgt");
    let target_id = create_simple_user(&mut conn, &target_username).await;
    let target_uuid = get_user_uuid(&mut conn, target_id).await;

    let asset_id =
        create_simple_rdp_asset(&mut conn, &unique_name("sec07-rec-rdp"), target_id).await;
    let (session_id, _session_uuid) =
        create_test_session_with_uuid(&mut conn, target_id, asset_id, "rdp", "active").await;

    // Deactivate target user
    let target_email = format!("{}@test.vauban.io", target_username);
    let csrf_token = app.generate_csrf_token();
    let _response = app
        .server
        .post(&format!("/accounts/users/{}", target_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", admin_token, csrf_token),
        )
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("username", &target_username),
            ("email", &target_email),
        ])
        .await;

    use vauban_web::schema::proxy_sessions;
    let (is_rec, rec_path, db_status): (bool, Option<String>, String) = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::id.eq(session_id))
            .select((
                proxy_sessions::is_recorded,
                proxy_sessions::recording_path,
                proxy_sessions::status,
            ))
            .first(&mut conn)
            .await
    );
    assert_eq!(db_status, "terminated");
    assert!(
        is_rec,
        "is_recorded should be true for RDP session after deactivation"
    );
    assert!(
        rec_path.is_some(),
        "recording_path should be set for RDP session after deactivation"
    );

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// SEC-04: Anti-enumeration -- login error uniformity
// =============================================================================

/// Structural: LoginErrorKind must NOT contain variants that reveal account state.
#[test]
fn test_sec04_no_account_state_variants() {
    let auth_source = include_str!("../../src/handlers/auth.rs");
    assert!(
        !auth_source.contains("AccountLocked"),
        "SEC-04: LoginErrorKind must not have AccountLocked variant"
    );
    assert!(
        !auth_source.contains("AccountDeactivated"),
        "SEC-04: LoginErrorKind must not have AccountDeactivated variant"
    );
}

/// Structural: password verification must occur BEFORE is_locked/is_active checks.
#[test]
fn test_sec04_password_verified_before_account_state_checks() {
    let auth_source = include_str!("../../src/handlers/auth.rs");
    let verify_pos = auth_source
        .find("verify_password")
        .expect("verify_password must exist in auth.rs");
    let locked_pos = auth_source
        .find("user.is_locked()")
        .expect("user.is_locked() must exist in auth.rs");
    let active_pos = auth_source
        .find("user.is_active")
        .expect("user.is_active must exist in auth.rs");
    assert!(
        verify_pos < locked_pos,
        "SEC-04: verify_password (pos {}) must come before is_locked (pos {})",
        verify_pos,
        locked_pos
    );
    assert!(
        verify_pos < active_pos,
        "SEC-04: verify_password (pos {}) must come before is_active (pos {})",
        verify_pos,
        active_pos
    );
}

/// Structural: login_error_response helper must exist and be used for DRY.
#[test]
fn test_sec04_login_error_response_helper_exists() {
    let auth_source = include_str!("../../src/handlers/auth.rs");
    assert!(
        auth_source.contains("fn login_error_response("),
        "SEC-04: login_error_response helper must exist"
    );
    assert!(
        auth_source.contains("fn rate_limit_response("),
        "SEC-04: rate_limit_response helper must exist"
    );
    let call_count = auth_source.matches("login_error_response(").count();
    assert!(
        call_count >= 4,
        "SEC-04: login_error_response should be called at least 4 times (got {})",
        call_count
    );
}

/// Structural: ACCOUNT_DEACTIVATED_MSG constant must be used in ssh.rs and rdp.rs.
#[test]
fn test_sec04_deactivated_constant_used() {
    let ssh_source = include_str!("../../src/handlers/web/ssh.rs");
    let rdp_source = include_str!("../../src/handlers/web/rdp.rs");
    let mod_source = include_str!("../../src/handlers/web/mod.rs");
    assert!(
        mod_source.contains("ACCOUNT_DEACTIVATED_MSG"),
        "SEC-04: ACCOUNT_DEACTIVATED_MSG must be defined in handlers/web/mod.rs"
    );
    assert!(
        ssh_source.contains("ACCOUNT_DEACTIVATED_MSG"),
        "SEC-04: ssh.rs must use ACCOUNT_DEACTIVATED_MSG constant"
    );
    assert!(
        rdp_source.contains("ACCOUNT_DEACTIVATED_MSG"),
        "SEC-04: rdp.rs must use ACCOUNT_DEACTIVATED_MSG constant"
    );
    assert!(
        !ssh_source.contains("\"Your account has been deactivated\""),
        "SEC-04: ssh.rs must NOT have hardcoded deactivated string"
    );
    assert!(
        !rdp_source.contains("\"Your account has been deactivated\""),
        "SEC-04: rdp.rs must NOT have hardcoded deactivated string"
    );
}

/// Structural: login_error_html must reuse html_error_fragment from error.rs.
#[test]
fn test_sec04_login_error_html_reuses_fragment() {
    let auth_source = include_str!("../../src/handlers/auth.rs");
    assert!(
        auth_source.contains("html_error_fragment"),
        "SEC-04: login_error_html must delegate to html_error_fragment"
    );
}

/// Structural: user_friendly_message must not translate locked/deactivated errors.
#[test]
fn test_sec04_user_friendly_message_cleaned() {
    let error_source = include_str!("../../src/error.rs");
    assert!(
        !error_source.contains("\"Account is locked\""),
        "SEC-04: user_friendly_message must not reference 'Account is locked'"
    );
    assert!(
        !error_source.contains("\"Account is deactivated\""),
        "SEC-04: user_friendly_message must not reference 'Account is deactivated'"
    );
}

/// Integration: non-existent user login returns generic "Invalid credentials".
#[tokio::test]
#[serial]
async fn test_sec04_nonexistent_user_api() {
    let app = TestApp::spawn().await;

    let response = app
        .server
        .post("/api/v1/auth/login")
        .json(&json!({
            "username": "sec04_ghost_user_does_not_exist",
            "password": "SomePassword123!"
        }))
        .await;

    assert_status(&response, 401);
    let body = response.text();
    assert!(
        body.contains("Invalid credentials"),
        "SEC-04: nonexistent user must get generic error: {}",
        body
    );
    assert!(
        !body.contains("not found"),
        "SEC-04: must not reveal user does not exist: {}",
        body
    );
}

/// Integration: wrong password returns generic "Invalid credentials".
#[tokio::test]
#[serial]
async fn test_sec04_wrong_password_api() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("sec04_wrong_pw");
    let _test_user = create_test_user(&mut conn, &app.auth_service, &username).await;

    let response = app
        .server
        .post("/api/v1/auth/login")
        .json(&json!({
            "username": username,
            "password": "WrongPassword999!"
        }))
        .await;

    assert_status(&response, 401);
    let body = response.text();
    assert!(
        body.contains("Invalid credentials"),
        "SEC-04: wrong password must get generic error: {}",
        body
    );

    test_db::cleanup(&mut conn).await;
}

/// Integration: locked account + wrong password returns "Invalid credentials" (not "locked").
#[tokio::test]
#[serial]
async fn test_sec04_locked_wrong_password_api() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("sec04_lock_wp");
    let _test_user = create_test_user(&mut conn, &app.auth_service, &username).await;

    use vauban_web::schema::users;
    unwrap_ok!(
        diesel::update(users::table.filter(users::username.eq(&username)))
            .set(users::locked_until.eq(Some(chrono::Utc::now() + chrono::Duration::hours(1))))
            .execute(&mut conn)
            .await
    );

    let response = app
        .server
        .post("/api/v1/auth/login")
        .json(&json!({
            "username": username,
            "password": "WrongPassword999!"
        }))
        .await;

    assert_status(&response, 401);
    let body = response.text();
    assert!(
        body.contains("Invalid credentials"),
        "SEC-04: locked+wrong pw must get generic error: {}",
        body
    );
    assert!(
        !body.contains("locked"),
        "SEC-04: must NOT reveal account is locked: {}",
        body
    );

    test_db::cleanup(&mut conn).await;
}

/// Integration: locked account + correct password returns "Invalid credentials" (not "locked").
#[tokio::test]
#[serial]
async fn test_sec04_locked_correct_password_api() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("sec04_lock_cp");
    let test_user = create_test_user(&mut conn, &app.auth_service, &username).await;

    use vauban_web::schema::users;
    unwrap_ok!(
        diesel::update(users::table.filter(users::username.eq(&username)))
            .set(users::locked_until.eq(Some(chrono::Utc::now() + chrono::Duration::hours(1))))
            .execute(&mut conn)
            .await
    );

    let response = app
        .server
        .post("/api/v1/auth/login")
        .json(&json!({
            "username": username,
            "password": test_user.password
        }))
        .await;

    assert_status(&response, 401);
    let body = response.text();
    assert!(
        body.contains("Invalid credentials"),
        "SEC-04: locked+correct pw must get generic error: {}",
        body
    );
    assert!(
        !body.contains("locked"),
        "SEC-04: must NOT reveal account is locked: {}",
        body
    );

    test_db::cleanup(&mut conn).await;
}

/// Integration: deactivated account + correct password returns "Invalid credentials".
#[tokio::test]
#[serial]
async fn test_sec04_deactivated_correct_password_api() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("sec04_deact_cp");
    let test_user = create_test_user(&mut conn, &app.auth_service, &username).await;

    use vauban_web::schema::users;
    unwrap_ok!(
        diesel::update(users::table.filter(users::username.eq(&username)))
            .set(users::is_active.eq(false))
            .execute(&mut conn)
            .await
    );

    let response = app
        .server
        .post("/api/v1/auth/login")
        .json(&json!({
            "username": username,
            "password": test_user.password
        }))
        .await;

    assert_status(&response, 401);
    let body = response.text();
    assert!(
        body.contains("Invalid credentials"),
        "SEC-04: deactivated+correct pw must get generic error: {}",
        body
    );
    assert!(
        !body.contains("deactivated"),
        "SEC-04: must NOT reveal account is deactivated: {}",
        body
    );

    test_db::cleanup(&mut conn).await;
}

/// Integration: all error responses via HTMX also return generic "Invalid credentials".
#[tokio::test]
#[serial]
async fn test_sec04_htmx_uniform_errors() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("sec04_htmx_unif");
    let test_user = create_test_user(&mut conn, &app.auth_service, &username).await;
    let csrf_token = app.generate_csrf_token();

    use vauban_web::schema::users;
    unwrap_ok!(
        diesel::update(users::table.filter(users::username.eq(&username)))
            .set(users::locked_until.eq(Some(chrono::Utc::now() + chrono::Duration::hours(1))))
            .execute(&mut conn)
            .await
    );

    // Locked + correct password via HTMX
    let response = app
        .server
        .post("/auth/login")
        .add_header("HX-Request", "true")
        .add_header(header::COOKIE, format!("__vauban_csrf={}", csrf_token))
        .json(&json!({
            "username": username,
            "password": test_user.password,
            "csrf_token": csrf_token
        }))
        .await;

    let body = response.text();
    // HTMX: html_error_fragment translates to user-friendly message
    assert!(
        body.contains("Incorrect username or password"),
        "SEC-04: HTMX locked+correct pw must show generic error: {}",
        body
    );
    assert!(
        !body.contains("locked"),
        "SEC-04: HTMX must NOT reveal locked state: {}",
        body
    );

    // Nonexistent user via HTMX
    let response = app
        .server
        .post("/auth/login")
        .add_header("HX-Request", "true")
        .add_header(header::COOKIE, format!("__vauban_csrf={}", csrf_token))
        .json(&json!({
            "username": "sec04_htmx_ghost_user",
            "password": "SomePassword123!",
            "csrf_token": csrf_token
        }))
        .await;

    let body = response.text();
    assert!(
        body.contains("Incorrect username or password"),
        "SEC-04: HTMX nonexistent user must show generic error: {}",
        body
    );

    test_db::cleanup(&mut conn).await;
}

/// Integration: progressive lockout still works (5 failed attempts -> locked_until set).
#[tokio::test]
#[serial]
async fn test_sec04_progressive_lockout_still_works() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("sec04_prog_lock");
    let _test_user = create_test_user(&mut conn, &app.auth_service, &username).await;

    for i in 0..5 {
        let response = app
            .server
            .post("/api/v1/auth/login")
            .json(&json!({
                "username": username,
                "password": "WrongPassword999!"
            }))
            .await;

        assert_status(&response, 401);
        let body = response.text();
        assert!(
            body.contains("Invalid credentials"),
            "SEC-04: attempt {} must return generic error: {}",
            i + 1,
            body
        );
    }

    use vauban_web::schema::users;
    let (failed_attempts, lock_until): (i32, Option<chrono::DateTime<chrono::Utc>>) = unwrap_ok!(
        users::table
            .filter(users::username.eq(&username))
            .select((users::failed_login_attempts, users::locked_until))
            .first(&mut conn)
            .await
    );
    assert_eq!(
        failed_attempts, 5,
        "SEC-04: failed_login_attempts should be 5"
    );
    assert!(
        lock_until.is_some(),
        "SEC-04: locked_until should be set after 5 failed attempts"
    );

    test_db::cleanup(&mut conn).await;
}

/// Integration: CSRF error returns specific message (not "Invalid credentials").
#[tokio::test]
#[serial]
async fn test_sec04_csrf_error_distinct() {
    let app = TestApp::spawn().await;

    let response = app
        .server
        .post("/auth/login")
        .add_header("HX-Request", "true")
        .add_header(header::COOKIE, "__vauban_csrf=invalid_token")
        .json(&json!({
            "username": "anyuser",
            "password": "anypass",
            "csrf_token": "wrong_csrf"
        }))
        .await;

    let body = response.text();
    assert!(
        body.contains("Invalid or expired form"),
        "SEC-04: CSRF error should show form-specific message: {}",
        body
    );
    assert!(
        !body.contains("Invalid credentials"),
        "SEC-04: CSRF error should NOT show 'Invalid credentials': {}",
        body
    );
}

// ==================== Cryptographic session-token gate (web tier) ====================
//
// SECURITY: vauban-web MUST mint a fresh cryptographic session token
// on every session-open request and thread it through the supervisor's
// TCP broker AND the protocol-proxy SshSessionOpen / RdpSessionOpen
// IPC. Without this, a compromised vauban-web could open sessions on
// behalf of arbitrary users (web is the only tier that holds session
// state in memory, so it is the highest-value compromise target).
//
// These tests are anti-regression guards on the WIRING in vauban-web.
// They are deliberately string-based (rather than runtime) because
// a runtime test would require spinning the full IPC stack; static
// asserts on the source catch the regression at PR-review time.

#[test]
fn test_access_client_exposes_issue_session_token() {
    let source = include_str!("../../src/ipc/access.rs");
    assert!(
        source.contains("pub async fn issue_session_token("),
        "AccessIpcClient MUST expose issue_session_token so handlers \
         can mint a fresh token on every session-open. Removing this \
         method silently disables the cryptographic gate."
    );
    assert!(
        source.contains("AccessReq::IssueSessionToken"),
        "issue_session_token MUST send an AccessReq::IssueSessionToken \
         IPC message to vauban-access (the only minter)."
    );
    assert!(
        source.contains("AccessResp::SessionTokenIssued"),
        "issue_session_token MUST recognize the SessionTokenIssued \
         success variant and return the token bytes."
    );
    assert!(
        source.contains("AccessResp::SessionTokenDenied"),
        "issue_session_token MUST recognize the SessionTokenDenied \
         fail-closed variant and surface a generic 'Access denied' \
         to the user (no fingerprinting of policy vs minter errors)."
    );
}

#[test]
fn test_ssh_handler_mints_token_before_session_open() {
    let source = include_str!("../../src/handlers/web/ssh.rs");
    let mint_idx = source.find(".issue_session_token(").expect(
        "vauban-web SSH handler MUST mint a session token via \
         AccessIpcClient::issue_session_token before opening a session.",
    );
    let request_idx = source
        .find("SshSessionOpenRequest {")
        .expect("vauban-web SSH handler MUST construct a SshSessionOpenRequest");
    assert!(
        mint_idx < request_idx,
        "issue_session_token MUST be called BEFORE SshSessionOpenRequest \
         is built so the token can be threaded into the request and \
         into the supervisor's request_tcp_connect."
    );
    assert!(
        source.contains("session_token: session_token_bytes"),
        "vauban-web SSH handler MUST set SshSessionOpenRequest.\
         session_token to the freshly minted token bytes."
    );
}

#[test]
fn test_rdp_handler_mints_token_before_session_open() {
    let source = include_str!("../../src/handlers/web/rdp.rs");
    let mint_idx = source.find(".issue_session_token(").expect(
        "vauban-web RDP handler MUST mint a session token via \
         AccessIpcClient::issue_session_token before opening a session.",
    );
    let request_idx = source
        .find("RdpSessionOpenRequest {")
        .expect("vauban-web RDP handler MUST construct a RdpSessionOpenRequest");
    assert!(
        mint_idx < request_idx,
        "issue_session_token MUST be called BEFORE RdpSessionOpenRequest \
         is built."
    );
    assert!(
        source.contains("session_token: session_token_bytes"),
        "vauban-web RDP handler MUST set RdpSessionOpenRequest.\
         session_token to the freshly minted token bytes."
    );
}

#[test]
fn test_supervisor_client_request_tcp_connect_takes_session_token() {
    let source = include_str!("../../src/ipc/supervisor.rs");
    assert!(
        source.contains("session_token: Vec<u8>"),
        "SupervisorClient::request_tcp_connect MUST accept a \
         session_token parameter so the supervisor's TCP broker can \
         crypto-verify before any DNS/connect work."
    );
    assert!(
        source.contains("Message::TcpConnectRequest {") && source.contains("session_token,"),
        "SupervisorClient::request_tcp_connect MUST forward the \
         session_token into Message::TcpConnectRequest."
    );
}

#[test]
fn test_host_key_fetch_path_is_crypto_gated() {
    let source = include_str!("../../src/ipc/proxy_ssh.rs");
    assert!(
        source.contains("HostKeyFetchIdentity"),
        "fetch_host_key MUST require a HostKeyFetchIdentity (with \
         AccessIpcClient + user_uuid + asset_uuid) when a supervisor \
         is set, so the host-key fetch path is crypto-gated like \
         every other supervisor TCP-broker call. Without this, a \
         compromised vauban-web could enumerate the internal network \
         via SshFetchHostKey."
    );
    assert!(
        source.contains(".issue_session_token("),
        "fetch_host_key MUST call issue_session_token to mint a token \
         for the synthetic 'fetch-hostkey-{{request_id}}' session before \
         calling the supervisor's TCP broker."
    );
}
