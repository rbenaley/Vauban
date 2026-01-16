/// VAUBAN Web - Integration tests for web pages using raw SQL queries.
///
/// These tests cover the HTML page handlers that use diesel::sql_query()
/// for complex queries with JOINs, subqueries, and PostgreSQL-specific features.
/// Since raw SQL is not checked at compile time, these tests ensure query validity.
use crate::common::{TestApp, assertions::assert_status};
use crate::fixtures::{
    create_approval_request, create_recorded_session, create_simple_admin_user,
    create_simple_ssh_asset, create_simple_user, create_test_asset_group,
    create_test_asset_in_group, create_test_session, create_test_vauban_group, get_asset_uuid,
    unique_name,
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
async fn test_approval_list_with_orphaned_status_filter() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    let username = unique_name("orphaned_approval_user");
    let user_id = create_simple_user(&mut conn, &username);
    let asset_id = create_simple_ssh_asset(&mut conn, "orphaned-approval-asset", user_id);
    let approval_uuid = create_approval_request(&mut conn, user_id, asset_id);

    use vauban_web::schema::proxy_sessions::dsl as ps;
    diesel::update(ps::proxy_sessions.filter(ps::uuid.eq(approval_uuid)))
        .set(ps::status.eq("orphaned"))
        .execute(&mut conn)
        .expect("Failed to update approval status");

    let token = app.generate_test_token(
        &Uuid::new_v4().to_string(),
        "test_approval_orphaned",
        true,
        true,
    );

    let response = app
        .server
        .get("/sessions/approvals?status=orphaned")
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
// Asset Delete Tests (soft delete + approval/session updates)
// =============================================================================

#[tokio::test]
async fn test_asset_delete_soft_deletes_and_updates_related_data() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Create a regular user who owns the asset and sessions
    let username = unique_name("delete_asset_user");
    let user_id = create_simple_user(&mut conn, &username);
    let asset_name = unique_name("delete-asset");
    let asset_id = create_simple_ssh_asset(&mut conn, &asset_name, user_id);
    let approval_uuid = create_approval_request(&mut conn, user_id, asset_id);
    let active_session_id = create_test_session(&mut conn, user_id, asset_id, "ssh", "active");
    let asset_uuid = get_asset_uuid(&mut conn, asset_id);

    // Create an admin user in the database to perform the deletion
    let admin_username = unique_name("admin_delete");
    let admin_id = create_simple_admin_user(&mut conn, &admin_username);
    let admin_uuid = get_user_uuid(&mut conn, admin_id);

    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_username, true, true);
    let csrf_token = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!("/assets/{}/delete", asset_uuid))
        .add_header(axum::http::header::AUTHORIZATION, app.auth_header(&token))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[("csrf_token", csrf_token.as_str())])
        .await;

    let status = response.status_code().as_u16();

    // For redirects, check the Location header to distinguish success from error
    if status == 302 || status == 303 {
        if let Some(location) = response.headers().get("location") {
            let location_str = location.to_str().unwrap_or("");
            // Success should redirect to /assets, error redirects back to /assets/{uuid}
            assert!(
                location_str == "/assets" || location_str.starts_with("/assets?"),
                "Expected redirect to /assets (success), got redirect to '{}' (likely an error)",
                location_str
            );
        }
    } else {
        assert!(
            status == 200 || status == 303,
            "Expected 200 or 303, got {}",
            status
        );
    }

    let mut conn = app.get_conn();

    use vauban_web::schema::assets::dsl as a;
    let (is_deleted, deleted_at): (bool, Option<chrono::DateTime<chrono::Utc>>) = a::assets
        .filter(a::id.eq(asset_id))
        .select((a::is_deleted, a::deleted_at))
        .first(&mut conn)
        .expect("Asset should exist");
    assert!(is_deleted, "Asset should be soft deleted (asset_id={})", asset_id);
    assert!(deleted_at.is_some(), "deleted_at should be set");

    use vauban_web::schema::proxy_sessions::dsl as ps;
    let approval_status: String = ps::proxy_sessions
        .filter(ps::uuid.eq(approval_uuid))
        .select(ps::status)
        .first(&mut conn)
        .expect("Approval session should exist");
    assert_eq!(
        approval_status, "orphaned",
        "Approval status should be 'orphaned', got '{}'",
        approval_status
    );

    let (session_status, disconnected_at): (String, Option<chrono::DateTime<chrono::Utc>>) =
        ps::proxy_sessions
            .filter(ps::id.eq(active_session_id))
            .select((ps::status, ps::disconnected_at))
            .first(&mut conn)
            .expect("Active session should exist");
    assert_eq!(session_status, "terminated");
    assert!(disconnected_at.is_some(), "disconnected_at should be set");
}

#[tokio::test]
async fn test_asset_delete_rejects_missing_csrf() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    let username = unique_name("delete_asset_csrf_missing");
    let user_id = create_simple_user(&mut conn, &username);
    let asset_id = create_simple_ssh_asset(&mut conn, "delete-asset-csrf", user_id);
    let asset_uuid = get_asset_uuid(&mut conn, asset_id);

    // Create an admin user in the database
    let admin_username = unique_name("admin_csrf_test");
    let admin_id = create_simple_admin_user(&mut conn, &admin_username);
    let admin_uuid = get_user_uuid(&mut conn, admin_id);
    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_username, true, true);

    let invalid_csrf = "invalid-token";
    let response = app
        .server
        .post(&format!("/assets/{}/delete", asset_uuid))
        .add_header(axum::http::header::AUTHORIZATION, app.auth_header(&token))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, invalid_csrf),
        )
        .form(&[("csrf_token", invalid_csrf)])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "Expected redirect (302 or 303), got {}",
        status
    );

    let flash_cookie = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .find(|c| c.to_str().unwrap().contains("__vauban_flash"));
    if flash_cookie.is_none() {
        let location = response
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            location.contains(&format!("/assets/{}", asset_uuid)) || location.contains("/login"),
            "Expected flash cookie or redirect back to asset detail/login"
        );
    }
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
    let csrf_token = app.generate_csrf_token();

    // Submit form with valid data
    let response = app
        .server
        .post(&format!("/assets/{}/edit", asset_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[
            ("name", "Updated Asset Name"),
            ("hostname", "updated.example.com"),
            ("port", "22"),
            ("status", "online"),
            ("csrf_token", csrf_token.as_str()),
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
    let csrf_token = app.generate_csrf_token();

    // Submit form with invalid port
    let response = app
        .server
        .post(&format!("/assets/{}/edit", asset_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[
            ("name", "Test Asset"),
            ("hostname", "test.example.com"),
            ("port", "99999"),  // Invalid port
            ("status", "online"),
            ("csrf_token", csrf_token.as_str()),
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
    let csrf_token = app.generate_csrf_token();

    // Submit form with valid data
    let response = app
        .server
        .post(&format!("/assets/groups/{}/edit", group_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[
            ("name", "Updated Group Name"),
            ("slug", "updated-group-slug"),
            ("description", "Updated description"),
            ("color", "#FF5733"),
            ("icon", "server"),
            ("csrf_token", csrf_token.as_str()),
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
    let csrf_token = app.generate_csrf_token();

    // Submit form with empty name (validation error)
    let response = app
        .server
        .post(&format!("/assets/groups/{}/edit", group_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[
            ("name", ""),  // Empty name - validation error
            ("slug", "valid-slug"),
            ("color", "#FF5733"),
            ("icon", "server"),
            ("csrf_token", csrf_token.as_str()),
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
    let csrf_token = app.generate_csrf_token();

    // Submit form with invalid IP address (192.168.1.400 is invalid)
    let response = app
        .server
        .post(&format!("/assets/{}/edit", asset_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[
            ("name", "Test Asset"),
            ("hostname", "test.example.com"),
            ("ip_address", "192.168.1.400"),  // Invalid IP address
            ("port", "22"),
            ("status", "online"),
            ("csrf_token", csrf_token.as_str()),
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
    let csrf_token = app.generate_csrf_token();

    // First, submit form with invalid IP to set flash cookie
    let error_response = app
        .server
        .post(&format!("/assets/{}/edit", asset_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[
            ("name", "Test Asset"),
            ("hostname", "test.example.com"),
            ("ip_address", "invalid-ip"),  // Invalid IP address
            ("port", "22"),
            ("status", "online"),
            ("csrf_token", csrf_token.as_str()),
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
    let csrf_token = app.generate_csrf_token();

    // Submit form with empty name (validation error)
    let response = app
        .server
        .post(&format!("/assets/groups/{}/edit", group_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[
            ("name", ""),  // Empty name - validation error
            ("slug", "valid-slug"),
            ("color", "#FF5733"),
            ("icon", "server"),
            ("csrf_token", csrf_token.as_str()),
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
    let csrf_token = app.generate_csrf_token();

    // Submit form with empty slug (validation error)
    let response = app
        .server
        .post(&format!("/assets/groups/{}/edit", group_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[
            ("name", "Valid Group Name"),
            ("slug", ""),  // Empty slug - validation error
            ("color", "#FF5733"),
            ("icon", "server"),
            ("csrf_token", csrf_token.as_str()),
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
    let csrf_token = app.generate_csrf_token();

    // First, submit form with empty name to set flash cookie
    let error_response = app
        .server
        .post(&format!("/assets/groups/{}/edit", group_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[
            ("name", ""),  // Empty name - validation error
            ("slug", "valid-slug"),
            ("color", "#FF5733"),
            ("icon", "server"),
            ("csrf_token", csrf_token.as_str()),
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

// =============================================================================
// User Management Tests (Create, Edit, Delete)
// =============================================================================

#[tokio::test]
async fn test_user_create_form_requires_admin() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Create a regular user (not staff, not superuser)
    let username = unique_name("regular_user");
    let user_id = create_simple_user(&mut conn, &username);
    let user_uuid = get_user_uuid(&mut conn, user_id);
    let token = app.generate_test_token(&user_uuid.to_string(), &username, false, false);

    let response = app
        .server
        .get("/accounts/users/new")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    // Should return 403 Forbidden (Authorization error)
    let status = response.status_code().as_u16();
    assert!(
        status == 403 || status == 401,
        "Regular user should not access create form, got {}",
        status
    );
}

#[tokio::test]
async fn test_user_create_form_loads_for_admin() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    let admin_username = unique_name("admin_create_form");
    let admin_id = create_simple_admin_user(&mut conn, &admin_username);
    let admin_uuid = get_user_uuid(&mut conn, admin_id);
    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_username, true, true);

    let response = app
        .server
        .get("/accounts/users/new")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(body.contains("Create New User") || body.contains("New User"));
}

#[tokio::test]
async fn test_user_create_success() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    let admin_username = unique_name("admin_create_user");
    let admin_id = create_simple_admin_user(&mut conn, &admin_username);
    let admin_uuid = get_user_uuid(&mut conn, admin_id);
    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_username, true, true);
    let csrf_token = app.generate_csrf_token();

    let new_username = unique_name("newuser");
    let new_email = format!("{}@test.vauban.io", new_username);

    let response = app
        .server
        .post("/accounts/users")
        .add_header(COOKIE, format!("access_token={}; __vauban_csrf={}", token, csrf_token))
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("username", &new_username),
            ("email", &new_email),
            ("password", "SecurePassword123!"),
            ("is_active", "on"),
        ])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 303 || status == 302,
        "Expected redirect after creation, got {}",
        status
    );

    // Verify user was created
    use vauban_web::schema::users;
    let created: Option<i32> = users::table
        .filter(users::username.eq(&new_username))
        .filter(users::is_deleted.eq(false))
        .select(users::id)
        .first(&mut conn)
        .optional()
        .unwrap();

    assert!(created.is_some(), "User should be created in database");
}

#[tokio::test]
async fn test_user_create_validates_password_length() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    let admin_username = unique_name("admin_pw_val");
    let admin_id = create_simple_admin_user(&mut conn, &admin_username);
    let admin_uuid = get_user_uuid(&mut conn, admin_id);
    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_username, true, true);
    let csrf_token = app.generate_csrf_token();

    let new_username = unique_name("shortpw");
    let new_email = format!("{}@test.vauban.io", new_username);

    // Password too short (less than 12 characters based on config)
    let response = app
        .server
        .post("/accounts/users")
        .add_header(COOKIE, format!("access_token={}; __vauban_csrf={}", token, csrf_token))
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("username", &new_username),
            ("email", &new_email),
            ("password", "short"),
            ("is_active", "on"),
        ])
        .await;

    // Should redirect back to form with error
    let status = response.status_code().as_u16();
    assert!(
        status == 303 || status == 302,
        "Expected redirect, got {}",
        status
    );

    // Verify redirect is back to the create form (error case)
    if let Some(location) = response.headers().get("location") {
        let loc = location.to_str().unwrap();
        assert!(
            loc.contains("/accounts/users/new"),
            "Should redirect back to create form on error, got {}",
            loc
        );
    }
}

#[tokio::test]
async fn test_user_create_staff_cannot_create_superuser() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Create a staff user (not superuser)
    let staff_username = unique_name("staff_no_super");
    let staff_id = {
        use vauban_web::schema::users;
        let user_uuid = uuid::Uuid::new_v4();
        diesel::insert_into(users::table)
            .values((
                users::uuid.eq(user_uuid),
                users::username.eq(&staff_username),
                users::email.eq(format!("{}@test.vauban.io", staff_username)),
                users::password_hash.eq("hash"),
                users::is_active.eq(true),
                users::is_staff.eq(true),
                users::is_superuser.eq(false),
                users::auth_source.eq("local"),
                users::preferences.eq(serde_json::json!({})),
            ))
            .returning(users::id)
            .get_result::<i32>(&mut conn)
            .unwrap()
    };
    let staff_uuid = get_user_uuid(&mut conn, staff_id);
    let token = app.generate_test_token(&staff_uuid.to_string(), &staff_username, false, true);
    let csrf_token = app.generate_csrf_token();

    let new_username = unique_name("wannabe_super");
    let new_email = format!("{}@test.vauban.io", new_username);

    // Try to create a superuser
    let response = app
        .server
        .post("/accounts/users")
        .add_header(COOKIE, format!("access_token={}; __vauban_csrf={}", token, csrf_token))
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("username", &new_username),
            ("email", &new_email),
            ("password", "SecurePassword123!"),
            ("is_active", "on"),
            ("is_superuser", "on"),
        ])
        .await;

    // Should redirect back with error
    let status = response.status_code().as_u16();
    assert!(status == 303 || status == 302);

    // Verify superuser was NOT created
    use vauban_web::schema::users;
    let created: Option<bool> = users::table
        .filter(users::username.eq(&new_username))
        .filter(users::is_deleted.eq(false))
        .select(users::is_superuser)
        .first(&mut conn)
        .optional()
        .unwrap();

    assert!(created.is_none(), "Superuser should NOT be created by staff");
}

#[tokio::test]
async fn test_user_edit_form_loads() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    let admin_username = unique_name("admin_edit_form");
    let admin_id = create_simple_admin_user(&mut conn, &admin_username);
    let admin_uuid = get_user_uuid(&mut conn, admin_id);
    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_username, true, true);

    // Create a user to edit
    let target_username = unique_name("edit_target");
    let target_id = create_simple_user(&mut conn, &target_username);
    let target_uuid = get_user_uuid(&mut conn, target_id);

    let response = app
        .server
        .get(&format!("/accounts/users/{}/edit", target_uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(body.contains("Edit User") || body.contains("edit"));
}

#[tokio::test]
async fn test_user_update_success() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    let admin_username = unique_name("admin_update");
    let admin_id = create_simple_admin_user(&mut conn, &admin_username);
    let admin_uuid = get_user_uuid(&mut conn, admin_id);
    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_username, true, true);
    let csrf_token = app.generate_csrf_token();

    // Create a user to update
    let target_username = unique_name("update_target");
    let target_id = create_simple_user(&mut conn, &target_username);
    let target_uuid = get_user_uuid(&mut conn, target_id);

    let new_email = format!("updated_{}@test.vauban.io", target_username);

    let response = app
        .server
        .post(&format!("/accounts/users/{}", target_uuid))
        .add_header(COOKIE, format!("access_token={}; __vauban_csrf={}", token, csrf_token))
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("username", &target_username),
            ("email", &new_email),
            ("is_active", "on"),
        ])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 303 || status == 302,
        "Expected redirect, got {}",
        status
    );

    // Verify email was updated
    use vauban_web::schema::users;
    let updated_email: String = users::table
        .filter(users::id.eq(target_id))
        .select(users::email)
        .first(&mut conn)
        .unwrap();

    assert_eq!(updated_email, new_email, "Email should be updated");
}

#[tokio::test]
async fn test_user_update_staff_cannot_edit_superuser() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Create a staff user
    let staff_username = unique_name("staff_cant_edit");
    let staff_id = {
        use vauban_web::schema::users;
        let user_uuid = uuid::Uuid::new_v4();
        diesel::insert_into(users::table)
            .values((
                users::uuid.eq(user_uuid),
                users::username.eq(&staff_username),
                users::email.eq(format!("{}@test.vauban.io", staff_username)),
                users::password_hash.eq("hash"),
                users::is_active.eq(true),
                users::is_staff.eq(true),
                users::is_superuser.eq(false),
                users::auth_source.eq("local"),
                users::preferences.eq(serde_json::json!({})),
            ))
            .returning(users::id)
            .get_result::<i32>(&mut conn)
            .unwrap()
    };
    let staff_uuid = get_user_uuid(&mut conn, staff_id);
    let token = app.generate_test_token(&staff_uuid.to_string(), &staff_username, false, true);

    // Create a superuser to try to edit
    let super_username = unique_name("super_target");
    let super_id = create_simple_admin_user(&mut conn, &super_username);
    let super_uuid = get_user_uuid(&mut conn, super_id);

    // Try to access edit form
    let response = app
        .server
        .get(&format!("/accounts/users/{}/edit", super_uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    // Should redirect with error (staff cannot edit superuser)
    let status = response.status_code().as_u16();
    assert!(
        status == 303 || status == 302,
        "Staff should not be able to edit superuser, got {}",
        status
    );
}

#[tokio::test]
async fn test_user_delete_soft_deletes() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    let admin_username = unique_name("admin_delete");
    let admin_id = create_simple_admin_user(&mut conn, &admin_username);
    let admin_uuid = get_user_uuid(&mut conn, admin_id);
    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_username, true, true);
    let csrf_token = app.generate_csrf_token();

    // Create a user to delete
    let target_username = unique_name("delete_target");
    let target_id = create_simple_user(&mut conn, &target_username);
    let target_uuid = get_user_uuid(&mut conn, target_id);

    let response = app
        .server
        .post(&format!("/accounts/users/{}/delete", target_uuid))
        .add_header(COOKIE, format!("access_token={}; __vauban_csrf={}", token, csrf_token))
        .form(&[("csrf_token", csrf_token.as_str())])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 303 || status == 302,
        "Expected redirect, got {}",
        status
    );

    // Verify user is soft-deleted
    use vauban_web::schema::users;
    let (is_deleted, deleted_at): (bool, Option<chrono::DateTime<chrono::Utc>>) = users::table
        .filter(users::id.eq(target_id))
        .select((users::is_deleted, users::deleted_at))
        .first(&mut conn)
        .unwrap();

    assert!(is_deleted, "User should be soft-deleted");
    assert!(deleted_at.is_some(), "deleted_at should be set");
}

#[tokio::test]
#[ignore] // This test requires isolation - run with `cargo test -- --ignored` for full validation
async fn test_user_delete_protects_last_superuser() {
    // This test verifies that when there is only 1 active superuser,
    // deleting them should fail. Due to test parallelism, this test
    // is marked as ignored and should be run separately.
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();
    use vauban_web::schema::users;
    use chrono::Utc;

    // Create a unique superuser for this test
    let last_super_username = unique_name("last_super");
    let last_super_id = create_simple_admin_user(&mut conn, &last_super_username);
    let last_super_uuid = get_user_uuid(&mut conn, last_super_id);

    // Deactivate ALL OTHER superusers
    let now = Utc::now();
    diesel::update(
        users::table
            .filter(users::is_superuser.eq(true))
            .filter(users::is_active.eq(true))
            .filter(users::id.ne(last_super_id)),
    )
    .set((users::is_active.eq(false), users::updated_at.eq(now)))
    .execute(&mut conn)
    .ok();

    // Verify we have exactly 1 active superuser now
    let superuser_count: i64 = users::table
        .filter(users::is_superuser.eq(true))
        .filter(users::is_active.eq(true))
        .filter(users::is_deleted.eq(false))
        .count()
        .get_result(&mut conn)
        .unwrap();
    assert_eq!(superuser_count, 1, "Should have exactly 1 active superuser for this test");

    let token = app.generate_test_token(&last_super_uuid.to_string(), &last_super_username, true, true);
    let csrf_token = app.generate_csrf_token();

    // Try to delete self (the last active superuser)
    let response = app
        .server
        .post(&format!("/accounts/users/{}/delete", last_super_uuid))
        .add_header(COOKIE, format!("access_token={}; __vauban_csrf={}", token, csrf_token))
        .form(&[("csrf_token", csrf_token.as_str())])
        .await;

    let status = response.status_code().as_u16();
    assert!(status == 303 || status == 302, "Expected redirect, got {}", status);

    // Verify user is NOT deleted (protection worked)
    let is_deleted: bool = users::table
        .filter(users::id.eq(last_super_id))
        .select(users::is_deleted)
        .first(&mut conn)
        .unwrap();

    assert!(!is_deleted, "Last superuser should NOT be deleted");

    // Cleanup: reactivate the other superusers
    diesel::update(
        users::table
            .filter(users::is_superuser.eq(true))
            .filter(users::is_active.eq(false)),
    )
    .set((users::is_active.eq(true), users::updated_at.eq(now)))
    .execute(&mut conn)
    .ok();
}

#[tokio::test]
async fn test_user_delete_staff_cannot_delete_superuser() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Create a staff user
    let staff_username = unique_name("staff_del");
    let staff_id = {
        use vauban_web::schema::users;
        let user_uuid = uuid::Uuid::new_v4();
        diesel::insert_into(users::table)
            .values((
                users::uuid.eq(user_uuid),
                users::username.eq(&staff_username),
                users::email.eq(format!("{}@test.vauban.io", staff_username)),
                users::password_hash.eq("hash"),
                users::is_active.eq(true),
                users::is_staff.eq(true),
                users::is_superuser.eq(false),
                users::auth_source.eq("local"),
                users::preferences.eq(serde_json::json!({})),
            ))
            .returning(users::id)
            .get_result::<i32>(&mut conn)
            .unwrap()
    };
    let staff_uuid = get_user_uuid(&mut conn, staff_id);
    let token = app.generate_test_token(&staff_uuid.to_string(), &staff_username, false, true);
    let csrf_token = app.generate_csrf_token();

    // Create a superuser to try to delete
    let super_username = unique_name("super_nodelete");
    let super_id = create_simple_admin_user(&mut conn, &super_username);
    let super_uuid = get_user_uuid(&mut conn, super_id);

    // Try to delete the superuser
    let response = app
        .server
        .post(&format!("/accounts/users/{}/delete", super_uuid))
        .add_header(COOKIE, format!("access_token={}; __vauban_csrf={}", token, csrf_token))
        .form(&[("csrf_token", csrf_token.as_str())])
        .await;

    let status = response.status_code().as_u16();
    assert!(status == 303 || status == 302);

    // Verify superuser is NOT deleted
    use vauban_web::schema::users;
    let is_deleted: bool = users::table
        .filter(users::id.eq(super_id))
        .select(users::is_deleted)
        .first(&mut conn)
        .unwrap();

    assert!(!is_deleted, "Staff should NOT be able to delete superuser");
}

#[tokio::test]
async fn test_user_delete_rejects_csrf_invalid() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    let admin_username = unique_name("admin_csrf_del");
    let admin_id = create_simple_admin_user(&mut conn, &admin_username);
    let admin_uuid = get_user_uuid(&mut conn, admin_id);
    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_username, true, true);

    let target_username = unique_name("csrf_del_target");
    let target_id = create_simple_user(&mut conn, &target_username);
    let target_uuid = get_user_uuid(&mut conn, target_id);

    let invalid_csrf = "invalid-token";
    let response = app
        .server
        .post(&format!("/accounts/users/{}/delete", target_uuid))
        .add_header(COOKIE, format!("access_token={}; __vauban_csrf={}", token, invalid_csrf))
        .form(&[("csrf_token", invalid_csrf)])
        .await;

    let status = response.status_code().as_u16();
    assert!(status == 303 || status == 302);

    // Verify user is NOT deleted (CSRF should have failed)
    use vauban_web::schema::users;
    let is_deleted: bool = users::table
        .filter(users::id.eq(target_id))
        .select(users::is_deleted)
        .first(&mut conn)
        .unwrap();

    assert!(!is_deleted, "User should NOT be deleted with invalid CSRF");
}
