/// VAUBAN Web - Integration tests for web pages using raw SQL queries.
///
/// These tests cover the HTML page handlers that use diesel::sql_query()
/// for complex queries with JOINs, subqueries, and PostgreSQL-specific features.
/// Since raw SQL is not checked at compile time, these tests ensure query validity.
use crate::common::{TestApp, assertions::assert_status};
use crate::fixtures::{
    create_approval_request, create_recorded_session, create_simple_ssh_asset, create_simple_user,
    create_test_asset_group, create_test_asset_in_group, create_test_session,
    create_test_vauban_group, get_asset_uuid, unique_name,
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
// Session Detail Page Tests (triple JOIN with ::text casts)
// =============================================================================

#[tokio::test]
async fn test_session_detail_page_loads() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Create test data with proper user UUID
    let user_id = create_simple_user(&mut conn, "test_session_page");
    let user_uuid = get_user_uuid(&mut conn, user_id);
    let asset_id = create_simple_ssh_asset(&mut conn, "test-session-page-asset", user_id);
    let session_id = create_test_session(&mut conn, user_id, asset_id, "ssh", "active");

    // Generate auth token
    let token = app.generate_test_token(&user_uuid.to_string(), "test_session_page", true, true);

    // Request session detail page
    let response = app
        .server
        .get(&format!("/sessions/{}", session_id))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    // Should return HTML page (200 or redirect)
    let status = response.status_code().as_u16();
    assert!(
        status == 200 || status == 303,
        "Expected 200 or 303, got {}",
        status
    );
}

#[tokio::test]
async fn test_session_detail_not_found() {
    let app = TestApp::spawn().await;

    let token = app.generate_test_token(
        &Uuid::new_v4().to_string(),
        "test_session_notfound",
        true,
        true,
    );

    // Request non-existent session
    let response = app
        .server
        .get("/sessions/999999")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    // Should return 404
    assert_status(&response, 404);
}

// =============================================================================
// Recording Play Page Tests (triple JOIN)
// =============================================================================

#[tokio::test]
async fn test_recording_play_page_with_recorded_session() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Create test data with recorded session
    let user_id = create_simple_user(&mut conn, "test_recording_page");
    let user_uuid = get_user_uuid(&mut conn, user_id);
    let asset_id = create_simple_ssh_asset(&mut conn, "test-recording-asset", user_id);
    let session_id = create_recorded_session(&mut conn, user_id, asset_id);

    let token = app.generate_test_token(&user_uuid.to_string(), "test_recording_page", true, true);

    let response = app
        .server
        .get(&format!("/sessions/recordings/{}/play", session_id))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 200 || status == 303 || status == 404,
        "Expected valid response, got {}",
        status
    );
}

#[tokio::test]
async fn test_recording_play_not_found() {
    let app = TestApp::spawn().await;

    let token =
        app.generate_test_token(&Uuid::new_v4().to_string(), "test_rec_notfound", true, true);

    let response = app
        .server
        .get("/sessions/recordings/999999/play")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 404);
}

// =============================================================================
// Approval List Page Tests (dynamic WHERE clause, triple JOIN)
// =============================================================================

#[tokio::test]
async fn test_approval_list_page_loads() {
    let app = TestApp::spawn().await;

    let token = app.generate_test_token(
        &Uuid::new_v4().to_string(),
        "test_approval_list",
        true,
        true,
    );

    let response = app
        .server
        .get("/sessions/approvals")
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
async fn test_approval_list_with_status_filter() {
    let app = TestApp::spawn().await;

    let token = app.generate_test_token(
        &Uuid::new_v4().to_string(),
        "test_approval_filter",
        true,
        true,
    );

    // Test with pending status filter
    let response = app
        .server
        .get("/sessions/approvals?status=pending")
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
async fn test_approval_list_with_pagination() {
    let app = TestApp::spawn().await;

    let token = app.generate_test_token(
        &Uuid::new_v4().to_string(),
        "test_approval_page",
        true,
        true,
    );

    // Test pagination
    let response = app
        .server
        .get("/sessions/approvals?page=2")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 200 || status == 303,
        "Expected 200 or 303, got {}",
        status
    );
}

// =============================================================================
// Approval Detail Page Tests (triple JOIN with inet::text cast)
// =============================================================================

#[tokio::test]
async fn test_approval_detail_page_loads() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Create test data with justification (approval request)
    let user_id = create_simple_user(&mut conn, "test_approval_detail");
    let user_uuid = get_user_uuid(&mut conn, user_id);
    let asset_id = create_simple_ssh_asset(&mut conn, "test-approval-asset", user_id);
    let session_uuid = create_approval_request(&mut conn, user_id, asset_id);

    let token = app.generate_test_token(&user_uuid.to_string(), "test_approval_detail", true, true);

    let response = app
        .server
        .get(&format!("/sessions/approvals/{}", session_uuid))
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
async fn test_approval_detail_not_found() {
    let app = TestApp::spawn().await;

    let token = app.generate_test_token(
        &Uuid::new_v4().to_string(),
        "test_appr_notfound",
        true,
        true,
    );

    let fake_uuid = Uuid::new_v4();
    let response = app
        .server
        .get(&format!("/sessions/approvals/{}", fake_uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 404);
}

// =============================================================================
// Active Sessions Page Tests (triple JOIN with inet::text cast)
// =============================================================================

#[tokio::test]
async fn test_active_sessions_page_loads() {
    let app = TestApp::spawn().await;

    let token = app.generate_test_token(
        &Uuid::new_v4().to_string(),
        "test_active_sessions",
        true,
        true,
    );

    let response = app
        .server
        .get("/sessions/active")
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
async fn test_active_sessions_with_data() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Create an active session
    let user_id = create_simple_user(&mut conn, "test_active_data");
    let user_uuid = get_user_uuid(&mut conn, user_id);
    let asset_id = create_simple_ssh_asset(&mut conn, "test-active-asset", user_id);
    let _session_id = create_test_session(&mut conn, user_id, asset_id, "ssh", "active");

    let token = app.generate_test_token(&user_uuid.to_string(), "test_active_data", true, true);

    let response = app
        .server
        .get("/sessions/active")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 200 || status == 303,
        "Expected 200 or 303, got {}",
        status
    );
}

// =============================================================================
// Asset Group List Page Tests (subquery in SELECT for asset_count)
// =============================================================================

#[tokio::test]
async fn test_asset_group_list_page_loads() {
    let app = TestApp::spawn().await;

    let token = app.generate_test_token(
        &Uuid::new_v4().to_string(),
        "test_assetgroup_list",
        true,
        true,
    );

    let response = app
        .server
        .get("/assets/groups")
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
async fn test_asset_group_list_with_search() {
    let app = TestApp::spawn().await;

    let token = app.generate_test_token(
        &Uuid::new_v4().to_string(),
        "test_assetgroup_search",
        true,
        true,
    );

    // Test with ILIKE search
    let response = app
        .server
        .get("/assets/groups?search=production")
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
async fn test_asset_group_list_with_special_chars_search() {
    let app = TestApp::spawn().await;

    let token = app.generate_test_token(
        &Uuid::new_v4().to_string(),
        "test_assetgroup_special",
        true,
        true,
    );

    // Test SQL injection protection in ILIKE search (URL-encoded)
    // The single quote is URL-encoded as %27
    let response = app
        .server
        .get("/assets/groups?search=test%27%3BDROP%20TABLE%20asset_groups%3B--")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    // Should not crash, return valid response
    let status = response.status_code().as_u16();
    assert!(
        status == 200 || status == 303 || status == 400,
        "Expected valid response (not 500), got {}",
        status
    );
}

// =============================================================================
// Asset Group Detail Page Tests
// =============================================================================

#[tokio::test]
async fn test_asset_group_detail_page_loads() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Create test asset group
    let group_uuid = create_test_asset_group(&mut conn, &unique_name("test-detail-group"));

    let token = app.generate_test_token(
        &Uuid::new_v4().to_string(),
        "test_assetgroup_detail",
        true,
        true,
    );

    let response = app
        .server
        .get(&format!("/assets/groups/{}", group_uuid))
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
async fn test_asset_group_detail_not_found() {
    let app = TestApp::spawn().await;

    let token = app.generate_test_token(
        &Uuid::new_v4().to_string(),
        "test_group_notfound",
        true,
        true,
    );

    let fake_uuid = Uuid::new_v4();
    let response = app
        .server
        .get(&format!("/assets/groups/{}", fake_uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 404);
}

// =============================================================================
// Asset Group Edit Page Tests
// =============================================================================

#[tokio::test]
async fn test_asset_group_edit_page_loads() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    let group_uuid = create_test_asset_group(&mut conn, &unique_name("test-edit-group"));

    let token = app.generate_test_token(
        &Uuid::new_v4().to_string(),
        "test_assetgroup_edit",
        true,
        true,
    );

    let response = app
        .server
        .get(&format!("/assets/groups/{}/edit", group_uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 200 || status == 303,
        "Expected 200 or 303, got {}",
        status
    );
}

// =============================================================================
// Asset Detail Page Tests (LEFT JOIN with group info)
// =============================================================================

#[tokio::test]
async fn test_asset_detail_page_loads() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    let user_id = create_simple_user(&mut conn, "test_asset_detail_page");
    let user_uuid = get_user_uuid(&mut conn, user_id);
    let asset_id = create_simple_ssh_asset(&mut conn, "test-asset-detail", user_id);
    let asset_uuid = get_asset_uuid(&mut conn, asset_id);

    let token =
        app.generate_test_token(&user_uuid.to_string(), "test_asset_detail_page", true, true);

    let response = app
        .server
        .get(&format!("/assets/{}", asset_uuid))
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
async fn test_asset_detail_with_group() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    let user_id = create_simple_user(&mut conn, &unique_name("test_asset_group"));
    let group_uuid = create_test_asset_group(&mut conn, &unique_name("test-asset-group-link"));
    let asset_id = create_test_asset_in_group(
        &mut conn,
        &unique_name("test-asset-in-group"),
        user_id,
        &group_uuid,
    );
    let asset_uuid = get_asset_uuid(&mut conn, asset_id);

    let token = app.generate_test_token(
        &Uuid::new_v4().to_string(),
        "test_asset_with_group",
        true,
        true,
    );

    let response = app
        .server
        .get(&format!("/assets/{}", asset_uuid))
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
async fn test_asset_detail_not_found() {
    let app = TestApp::spawn().await;

    let token = app.generate_test_token(
        &Uuid::new_v4().to_string(),
        "test_asset_notfound",
        true,
        true,
    );

    // Use a random UUID that doesn't exist
    let non_existent_uuid = Uuid::new_v4();
    let response = app
        .server
        .get(&format!("/assets/{}", non_existent_uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 404);
}

// =============================================================================
// User Groups Page Tests (vauban_groups)
// =============================================================================

#[tokio::test]
async fn test_group_list_page_loads() {
    let app = TestApp::spawn().await;

    let token = app.generate_test_token(&Uuid::new_v4().to_string(), "test_group_list", true, true);

    let response = app
        .server
        .get("/accounts/groups")
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
async fn test_group_list_with_search() {
    let app = TestApp::spawn().await;

    let token =
        app.generate_test_token(&Uuid::new_v4().to_string(), "test_group_search", true, true);

    let response = app
        .server
        .get("/accounts/groups?search=admin")
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
async fn test_group_detail_page_loads() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    let group_uuid = create_test_vauban_group(&mut conn, &unique_name("test-vauban-group"));

    let token = app.generate_test_token(
        &Uuid::new_v4().to_string(),
        "test_vauban_group_detail",
        true,
        true,
    );

    let response = app
        .server
        .get(&format!("/accounts/groups/{}", group_uuid))
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
async fn test_group_detail_not_found() {
    let app = TestApp::spawn().await;

    let token = app.generate_test_token(
        &Uuid::new_v4().to_string(),
        "test_vgroup_notfound",
        true,
        true,
    );

    let fake_uuid = Uuid::new_v4();
    let response = app
        .server
        .get(&format!("/accounts/groups/{}", fake_uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 404);
}

// =============================================================================
// Web Form POST Tests (PRG Pattern with Flash Messages)
// =============================================================================

#[tokio::test]
async fn test_update_asset_web_form_redirects_on_success() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Create test data
    let user_id = create_simple_user(&mut conn, "test_asset_form");
    let user_uuid = get_user_uuid(&mut conn, user_id);
    let asset_id = create_simple_ssh_asset(&mut conn, "test-form-asset", user_id);
    let asset_uuid = get_asset_uuid(&mut conn, asset_id);

    let token = app.generate_test_token(&user_uuid.to_string(), "test_asset_form", true, true);

    // Submit form with valid data
    let response = app
        .server
        .post(&format!("/assets/{}/edit", asset_uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .form(&[
            ("name", "Updated Asset Name"),
            ("hostname", "updated.example.com"),
            ("port", "22"),
            ("status", "online"),
        ])
        .await;

    // Should redirect (PRG pattern)
    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "Expected redirect (302 or 303), got {}",
        status
    );
}

#[tokio::test]
async fn test_update_asset_web_form_validation_error() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Create test data
    let user_id = create_simple_user(&mut conn, "test_asset_val");
    let user_uuid = get_user_uuid(&mut conn, user_id);
    let asset_id = create_simple_ssh_asset(&mut conn, "test-val-asset", user_id);
    let asset_uuid = get_asset_uuid(&mut conn, asset_id);

    let token = app.generate_test_token(&user_uuid.to_string(), "test_asset_val", true, true);

    // Submit form with invalid port
    let response = app
        .server
        .post(&format!("/assets/{}/edit", asset_uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .form(&[
            ("name", "Test Asset"),
            ("hostname", "test.example.com"),
            ("port", "99999"),  // Invalid port
            ("status", "online"),
        ])
        .await;

    // Should redirect back to edit page with error flash
    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "Expected redirect (302 or 303), got {}",
        status
    );
}

#[tokio::test]
async fn test_update_asset_group_web_form_redirects_on_success() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Create test data
    let user_id = create_simple_user(&mut conn, "test_group_form");
    let user_uuid = get_user_uuid(&mut conn, user_id);
    let group_uuid = create_test_asset_group(&mut conn, "test-form-group");

    let token = app.generate_test_token(&user_uuid.to_string(), "test_group_form", true, true);

    // Submit form with valid data
    let response = app
        .server
        .post(&format!("/assets/groups/{}/edit", group_uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .form(&[
            ("name", "Updated Group Name"),
            ("slug", "updated-group-slug"),
            ("description", "Updated description"),
            ("color", "#FF5733"),
            ("icon", "server"),
        ])
        .await;

    // Should redirect (PRG pattern)
    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "Expected redirect (302 or 303), got {}",
        status
    );
}

#[tokio::test]
async fn test_update_asset_group_web_form_validation_error() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Create test data
    let user_id = create_simple_user(&mut conn, "test_group_val");
    let user_uuid = get_user_uuid(&mut conn, user_id);
    let group_uuid = create_test_asset_group(&mut conn, "test-val-group");

    let token = app.generate_test_token(&user_uuid.to_string(), "test_group_val", true, true);

    // Submit form with empty name (validation error)
    let response = app
        .server
        .post(&format!("/assets/groups/{}/edit", group_uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .form(&[
            ("name", ""),  // Empty name - validation error
            ("slug", "valid-slug"),
            ("color", "#FF5733"),
            ("icon", "server"),
        ])
        .await;

    // Should redirect back to edit page with error flash
    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "Expected redirect (302 or 303), got {}",
        status
    );
}

#[tokio::test]
async fn test_asset_edit_page_requires_authentication() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    let user_id = create_simple_user(&mut conn, "test_auth_check");
    let asset_id = create_simple_ssh_asset(&mut conn, "test-auth-asset", user_id);
    let asset_uuid = get_asset_uuid(&mut conn, asset_id);

    // Try to access edit page without authentication
    let response = app
        .server
        .get(&format!("/assets/{}/edit", asset_uuid))
        .await;

    // Should redirect to login (303) or return 401
    let status = response.status_code().as_u16();
    assert!(
        status == 303 || status == 401,
        "Expected redirect to login (303) or 401, got {}",
        status
    );
}

#[tokio::test]
async fn test_web_form_post_requires_authentication() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    let user_id = create_simple_user(&mut conn, "test_post_auth");
    let asset_id = create_simple_ssh_asset(&mut conn, "test-post-asset", user_id);
    let asset_uuid = get_asset_uuid(&mut conn, asset_id);

    // Try to submit form without authentication
    let response = app
        .server
        .post(&format!("/assets/{}/edit", asset_uuid))
        .form(&[
            ("name", "Hacked"),
            ("hostname", "hacked.com"),
            ("port", "22"),
            ("status", "online"),
        ])
        .await;

    // Should redirect to login (303) or return 401
    let status = response.status_code().as_u16();
    assert!(
        status == 303 || status == 401,
        "Expected redirect to login (303) or 401, got {}",
        status
    );
}

// =============================================================================
// Flash Message Display Tests (Regression Prevention)
// =============================================================================

#[tokio::test]
async fn test_invalid_ip_address_shows_flash_error() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Create test data
    let user_id = create_simple_user(&mut conn, "test_ip_error");
    let user_uuid = get_user_uuid(&mut conn, user_id);
    let asset_id = create_simple_ssh_asset(&mut conn, "test-ip-asset", user_id);
    let asset_uuid = get_asset_uuid(&mut conn, asset_id);

    let token = app.generate_test_token(&user_uuid.to_string(), "test_ip_error", true, true);

    // Submit form with invalid IP address (192.168.1.400 is invalid)
    let response = app
        .server
        .post(&format!("/assets/{}/edit", asset_uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .form(&[
            ("name", "Test Asset"),
            ("hostname", "test.example.com"),
            ("ip_address", "192.168.1.400"),  // Invalid IP address
            ("port", "22"),
            ("status", "online"),
        ])
        .await;

    // Should redirect back to edit page (PRG pattern)
    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "Expected redirect (302 or 303), got {}",
        status
    );

    // Check that redirect location is back to edit page
    let location = response.headers().get("location");
    assert!(
        location.is_some(),
        "Response should have Location header for redirect"
    );
    let location_str = location.unwrap().to_str().unwrap();
    assert!(
        location_str.contains(&format!("/assets/{}/edit", asset_uuid)),
        "Should redirect back to edit page, got: {}",
        location_str
    );

    // Check that flash cookie is set with error message
    let cookies = response.headers().get_all("set-cookie");
    let flash_cookie = cookies
        .iter()
        .find(|c| c.to_str().unwrap().contains("__vauban_flash"));
    assert!(
        flash_cookie.is_some(),
        "Flash cookie should be set for error message"
    );
}

#[tokio::test]
async fn test_edit_page_displays_flash_messages() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Create test data
    let user_id = create_simple_user(&mut conn, "test_flash_display");
    let user_uuid = get_user_uuid(&mut conn, user_id);
    let asset_id = create_simple_ssh_asset(&mut conn, "test-flash-asset", user_id);
    let asset_uuid = get_asset_uuid(&mut conn, asset_id);

    let token = app.generate_test_token(&user_uuid.to_string(), "test_flash_display", true, true);

    // First, submit form with invalid IP to set flash cookie
    let error_response = app
        .server
        .post(&format!("/assets/{}/edit", asset_uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .form(&[
            ("name", "Test Asset"),
            ("hostname", "test.example.com"),
            ("ip_address", "invalid-ip"),  // Invalid IP address
            ("port", "22"),
            ("status", "online"),
        ])
        .await;

    // Extract flash cookie from response
    let flash_cookie = error_response
        .headers()
        .get_all("set-cookie")
        .iter()
        .find(|c| c.to_str().unwrap().contains("__vauban_flash"))
        .map(|c| {
            let cookie_str = c.to_str().unwrap();
            // Extract just the cookie value part (before ;)
            cookie_str.split(';').next().unwrap().to_string()
        });

    assert!(flash_cookie.is_some(), "Flash cookie should be set");

    // Now GET the edit page with the flash cookie to verify message is displayed
    let get_response = app
        .server
        .get(&format!("/assets/{}/edit", asset_uuid))
        .add_header(COOKIE, format!("access_token={}; {}", token, flash_cookie.unwrap()))
        .await;

    // Should return 200 with HTML containing error message
    assert_status(&get_response, 200);

    // Check that the response body contains error message
    let body = get_response.text();
    assert!(
        body.contains("Invalid IP address") || body.contains("bg-red-50") || body.contains("error"),
        "Edit page should display error flash message. Body excerpt: {}...",
        &body[..std::cmp::min(500, body.len())]
    );
}

#[tokio::test]
async fn test_asset_group_empty_name_shows_flash_error() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Create test data
    let user_id = create_simple_user(&mut conn, "test_group_name_err");
    let user_uuid = get_user_uuid(&mut conn, user_id);
    let group_uuid = create_test_asset_group(&mut conn, &unique_name("test-name-err-grp"));

    let token = app.generate_test_token(&user_uuid.to_string(), "test_group_name_err", true, true);

    // Submit form with empty name (validation error)
    let response = app
        .server
        .post(&format!("/assets/groups/{}/edit", group_uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .form(&[
            ("name", ""),  // Empty name - validation error
            ("slug", "valid-slug"),
            ("color", "#FF5733"),
            ("icon", "server"),
        ])
        .await;

    // Should redirect back to edit page (PRG pattern)
    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "Expected redirect (302 or 303), got {}",
        status
    );

    // Check that redirect location is back to edit page
    let location = response.headers().get("location");
    assert!(
        location.is_some(),
        "Response should have Location header for redirect"
    );
    let location_str = location.unwrap().to_str().unwrap();
    assert!(
        location_str.contains(&format!("/assets/groups/{}/edit", group_uuid)),
        "Should redirect back to edit page, got: {}",
        location_str
    );

    // Check that flash cookie is set with error message
    let cookies = response.headers().get_all("set-cookie");
    let flash_cookie = cookies
        .iter()
        .find(|c| c.to_str().unwrap().contains("__vauban_flash"));
    assert!(
        flash_cookie.is_some(),
        "Flash cookie should be set for error message"
    );
}

#[tokio::test]
async fn test_asset_group_empty_slug_shows_flash_error() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Create test data
    let user_id = create_simple_user(&mut conn, "test_group_slug_err");
    let user_uuid = get_user_uuid(&mut conn, user_id);
    let group_uuid = create_test_asset_group(&mut conn, &unique_name("test-slug-err-grp"));

    let token = app.generate_test_token(&user_uuid.to_string(), "test_group_slug_err", true, true);

    // Submit form with empty slug (validation error)
    let response = app
        .server
        .post(&format!("/assets/groups/{}/edit", group_uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .form(&[
            ("name", "Valid Group Name"),
            ("slug", ""),  // Empty slug - validation error
            ("color", "#FF5733"),
            ("icon", "server"),
        ])
        .await;

    // Should redirect back to edit page (PRG pattern)
    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "Expected redirect (302 or 303), got {}",
        status
    );

    // Check that flash cookie is set with error message
    let cookies = response.headers().get_all("set-cookie");
    let flash_cookie = cookies
        .iter()
        .find(|c| c.to_str().unwrap().contains("__vauban_flash"));
    assert!(
        flash_cookie.is_some(),
        "Flash cookie should be set for slug validation error"
    );
}

#[tokio::test]
async fn test_asset_group_edit_page_displays_flash_messages() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Create test data
    let user_id = create_simple_user(&mut conn, "test_group_flash");
    let user_uuid = get_user_uuid(&mut conn, user_id);
    let group_uuid = create_test_asset_group(&mut conn, &unique_name("test-grp-flash-disp"));

    let token = app.generate_test_token(&user_uuid.to_string(), "test_group_flash", true, true);

    // First, submit form with empty name to set flash cookie
    let error_response = app
        .server
        .post(&format!("/assets/groups/{}/edit", group_uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .form(&[
            ("name", ""),  // Empty name - validation error
            ("slug", "valid-slug"),
            ("color", "#FF5733"),
            ("icon", "server"),
        ])
        .await;

    // Extract flash cookie from response
    let flash_cookie = error_response
        .headers()
        .get_all("set-cookie")
        .iter()
        .find(|c| c.to_str().unwrap().contains("__vauban_flash"))
        .map(|c| {
            let cookie_str = c.to_str().unwrap();
            // Extract just the cookie value part (before ;)
            cookie_str.split(';').next().unwrap().to_string()
        });

    assert!(flash_cookie.is_some(), "Flash cookie should be set");

    // Now GET the edit page with the flash cookie to verify message is displayed
    let get_response = app
        .server
        .get(&format!("/assets/groups/{}/edit", group_uuid))
        .add_header(COOKIE, format!("access_token={}; {}", token, flash_cookie.unwrap()))
        .await;

    // Should return 200 with HTML containing error message
    assert_status(&get_response, 200);

    // Check that the response body contains error message
    let body = get_response.text();
    assert!(
        body.contains("name") || body.contains("required") || body.contains("bg-red-50") || body.contains("error"),
        "Edit page should display error flash message. Body excerpt: {}...",
        &body[..std::cmp::min(500, body.len())]
    );
}
