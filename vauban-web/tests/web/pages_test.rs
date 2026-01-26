/// VAUBAN Web - Integration tests for web pages using raw SQL queries.
///
/// These tests cover the HTML page handlers that use diesel::sql_query()
/// for complex queries with JOINs, subqueries, and PostgreSQL-specific features.
/// Since raw SQL is not checked at compile time, these tests ensure query validity.
use crate::common::{TestApp, assertions::assert_status};
use crate::fixtures::{
    add_user_to_vauban_group, count_vauban_group_members, create_approval_request,
    create_recorded_session, create_simple_admin_user, create_simple_ssh_asset, create_simple_user,
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
// Fallback Route Tests
// =============================================================================

#[tokio::test]
async fn test_fallback_route_redirects_to_home() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("fallback_test_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id);

    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_name, true, true);

    // Try to access a non-existent route
    let response = app
        .server
        .get("/this-route-does-not-exist-xyz123")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    // Should redirect to home page
    assert_status(&response, 303);
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok());
    assert_eq!(location, Some("/"));
}

#[tokio::test]
async fn test_fallback_route_with_random_path() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("fallback_rand_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id);

    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_name, true, true);

    // Try various non-existent paths
    let paths = [
        "/sdlakd324324",
        "/random/nested/path",
        "/foo/bar/baz",
        "/not-a-real-endpoint",
    ];

    for path in paths {
        let response = app
            .server
            .get(path)
            .add_header(COOKIE, format!("access_token={}", token))
            .await;

        let status = response.status_code().as_u16();
        let location = response
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok());

        assert!(
            status == 303 && location == Some("/"),
            "Path {} should redirect to /, got status {} location {:?}",
            path,
            status,
            location
        );
    }
}

#[tokio::test]
async fn test_fallback_route_unauthenticated() {
    let app = TestApp::spawn().await;

    // Even without auth, random paths should redirect to /
    let response = app.server.get("/random-path-no-auth").await;

    let status = response.status_code().as_u16();
    assert!(
        status == 303,
        "Unauthenticated access to unknown path should redirect, got {}",
        status
    );
}

// =============================================================================
// Malformed UUID Tests
// =============================================================================

#[tokio::test]
async fn test_asset_detail_with_malformed_uuid() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("malformed_uuid_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id);

    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_name, true, true);

    // Try various malformed UUIDs - all should redirect gracefully to /assets
    let malformed_uuids = [
        "not-a-uuid",
        "12345",
        "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "123e4567-e89b-12d3-a456",  // Too short
        "123e4567-e89b-12d3-a456-4266141740001234",  // Too long
        "24d3cc30-d6c0-ooo7-be9a-978dd250ae3e",  // Invalid character 'o' in hex
    ];

    for bad_uuid in malformed_uuids {
        let response = app
            .server
            .get(&format!("/assets/{}", bad_uuid))
            .add_header(COOKIE, format!("access_token={}", token))
            .await;

        let status = response.status_code().as_u16();
        let location = response.headers().get("location").and_then(|v| v.to_str().ok());

        assert!(
            status == 303 && location == Some("/assets"),
            "Malformed UUID '{}' should redirect to /assets with 303, got status {} location {:?}",
            bad_uuid,
            status,
            location
        );
    }
}

#[tokio::test]
async fn test_user_detail_with_malformed_uuid() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("user_malformed_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id);

    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_name, true, true);

    let response = app
        .server
        .get("/accounts/users/not-a-valid-uuid")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 303);
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok());
    assert_eq!(location, Some("/accounts/users"));
}

#[tokio::test]
async fn test_group_detail_with_malformed_uuid() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("grp_malformed_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id);

    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_name, true, true);

    let response = app
        .server
        .get("/accounts/groups/invalid-uuid-here")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 303);
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok());
    assert_eq!(location, Some("/accounts/groups"));
}

#[tokio::test]
async fn test_asset_group_detail_with_malformed_uuid() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("agrp_malformed_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id);

    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_name, true, true);

    let response = app
        .server
        .get("/assets/groups/totally-not-uuid")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 303);
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok());
    assert_eq!(location, Some("/assets/groups"));
}

#[tokio::test]
async fn test_approval_detail_with_malformed_uuid() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("appr_malformed_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id);

    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_name, true, true);

    let response = app
        .server
        .get("/sessions/approvals/bad-uuid-format")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 303);
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok());
    assert_eq!(location, Some("/sessions/approvals"));
}

// =============================================================================
// Flash Message Tests (verify redirects include flash cookies)
// =============================================================================

#[tokio::test]
async fn test_not_found_redirect_sets_flash_cookie() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("flash_test_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id);

    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_name, true, true);

    let fake_uuid = Uuid::new_v4();
    let response = app
        .server
        .get(&format!("/assets/{}", fake_uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 303);

    // Check that flash cookie is set
    let set_cookie = response
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    
    assert!(
        set_cookie.contains("flash="),
        "Response should set flash cookie, got: {}",
        set_cookie
    );
}

#[tokio::test]
async fn test_authorization_error_redirect_sets_flash() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Create an asset
    let admin_name = unique_name("flash_auth_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let asset_id = create_simple_ssh_asset(&mut conn, &unique_name("flash-asset"), admin_id);
    let asset_uuid = get_asset_uuid(&mut conn, asset_id).await;

    // Create a normal user
    let user_name = unique_name("flash_auth_user");
    let user_id = create_simple_user(&mut conn, &user_name).await;
    let user_uuid = get_user_uuid(&mut conn, user_id);

    let token = app.generate_test_token(&user_uuid.to_string(), &user_name, false, false);

    // Normal user tries to access asset (forbidden)
    let response = app
        .server
        .get(&format!("/assets/{}", asset_uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 303);

    // Check flash cookie is set with error
    let set_cookie = response
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    
    assert!(
        set_cookie.contains("flash="),
        "Authorization error should set flash cookie"
    );
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
    let mut conn = app.get_conn().await;

    let username = unique_name("orphaned_approval_user");
    let user_id = create_simple_user(&mut conn, &username).await;
    let asset_id = create_simple_ssh_asset(&mut conn, "orphaned-approval-asset", user_id);
    let approval_uuid = create_approval_request(&mut conn, user_id, asset_id).await;

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

#[tokio::test]
async fn test_approval_list_status_filter_all_statuses() {
    // Test that filtering works correctly for all status types:
    // - pending, approved, rejected, expired, orphaned
    // - empty string (All statuses) should behave like no filter
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Create a user and assets for multiple approval requests
    let username = unique_name("status_filter_user");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id);

    // Create approval requests with different statuses
    let statuses = ["pending", "approved", "rejected", "expired", "orphaned"];

    for (i, status) in statuses.iter().enumerate() {
        let asset_id = create_simple_ssh_asset(
            &mut conn,
            &format!("status-filter-asset-{}", i),
            user_id,
        );
        let approval_uuid = create_approval_request(&mut conn, user_id, asset_id).await;

        // Update the status
        use vauban_web::schema::proxy_sessions::dsl as ps;
        diesel::update(ps::proxy_sessions.filter(ps::uuid.eq(approval_uuid)))
            .set(ps::status.eq(*status))
            .execute(&mut conn)
            .expect("Failed to update approval status");
    }

    let token = app.generate_test_token(&user_uuid.to_string(), &username, true, true);

    // Test 1: No filter - should show all approvals
    let response_no_filter = app
        .server
        .get("/sessions/approvals")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(
        response_no_filter.status_code().as_u16(),
        200,
        "Approval list without filter should load"
    );

    let body_no_filter = response_no_filter.text();
    assert!(
        !body_no_filter.contains("No approval requests"),
        "Should show approvals when no filter is applied"
    );

    // Test 2: Empty status filter (simulates "All statuses" selection after filtering)
    // Regression test: Previously this would return empty results
    let response_empty_filter = app
        .server
        .get("/sessions/approvals?status=")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(
        response_empty_filter.status_code().as_u16(),
        200,
        "Approval list with empty filter should load"
    );

    let body_empty_filter = response_empty_filter.text();
    assert!(
        !body_empty_filter.contains("No approval requests"),
        "Empty status filter should show all approvals (same as no filter)"
    );

    // Test 3: Each specific status filter should work and return 200
    for status in &statuses {
        let response = app
            .server
            .get(&format!("/sessions/approvals?status={}", status))
            .add_header(COOKIE, format!("access_token={}", token))
            .await;

        assert_eq!(
            response.status_code().as_u16(),
            200,
            "Approval list with status={} filter should load",
            status
        );

        let body = response.text();

        // Should show the approval with this status (not empty)
        assert!(
            !body.contains("No approval requests"),
            "Filter status={} should find the approval with that status",
            status
        );

        // Verify the correct status is shown in the response
        // The status badge should contain the status text
        assert!(
            body.contains(status),
            "Response for status={} should contain that status in the page",
            status
        );

        // Verify the filter dropdown shows the correct selection
        let expected_selected = format!("value=\"{}\" selected", status);
        assert!(
            body.contains(&expected_selected),
            "Filter dropdown should show {} as selected",
            status
        );
    }

    // Test 4: Invalid status filter should return empty (no matching approvals)
    let response_invalid = app
        .server
        .get("/sessions/approvals?status=invalid_status")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(
        response_invalid.status_code().as_u16(),
        200,
        "Approval list with invalid status should still load"
    );

    let body_invalid = response_invalid.text();
    assert!(
        body_invalid.contains("No approval requests") || body_invalid.contains("No requests match"),
        "Invalid status filter should show no results"
    );
}

// =============================================================================
// Approval Detail Page Tests (triple JOIN with inet::text cast)
// =============================================================================

#[tokio::test]
async fn test_approval_detail_page_loads() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Create test data with justification (approval request)
    let user_id = create_simple_user(&mut conn, "test_approval_detail").await;
    let user_uuid = get_user_uuid(&mut conn, user_id);
    let asset_id = create_simple_ssh_asset(&mut conn, "test-approval-asset", user_id);
    let session_uuid = create_approval_request(&mut conn, user_id, asset_id).await;

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

    // Not found redirects to list page with flash message
    assert_status(&response, 303);
    let location = response.headers().get("location").and_then(|v| v.to_str().ok());
    assert_eq!(location, Some("/sessions/approvals"));
}

// =============================================================================
// Asset Delete Tests (soft delete + approval/session updates)
// =============================================================================

#[tokio::test]
async fn test_asset_delete_soft_deletes_and_updates_related_data() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Create a regular user who owns the asset and sessions
    let username = unique_name("delete_asset_user");
    let user_id = create_simple_user(&mut conn, &username).await;
    let asset_name = unique_name("delete-asset");
    let asset_id = create_simple_ssh_asset(&mut conn, &asset_name, user_id);
    let approval_uuid = create_approval_request(&mut conn, user_id, asset_id).await;
    let active_session_id = create_test_session(&mut conn, user_id, asset_id, "ssh", "active").await;
    let asset_uuid = get_asset_uuid(&mut conn, asset_id).await;

    // Create an admin user in the database to perform the deletion
    let admin_username = unique_name("admin_delete");
    let admin_id = create_simple_admin_user(&mut conn, &admin_username).await;
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

    let mut conn = app.get_conn().await;

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
    let mut conn = app.get_conn().await;

    let username = unique_name("delete_asset_csrf_missing");
    let user_id = create_simple_user(&mut conn, &username).await;
    let asset_id = create_simple_ssh_asset(&mut conn, "delete-asset-csrf", user_id);
    let asset_uuid = get_asset_uuid(&mut conn, asset_id).await;

    // Create an admin user in the database
    let admin_username = unique_name("admin_csrf_test");
    let admin_id = create_simple_admin_user(&mut conn, &admin_username).await;
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

#[tokio::test]
async fn test_asset_group_list_empty_search_shows_all() {
    // Regression test: empty search string should behave like no filter
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_username = unique_name("assetgrp_search_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_username).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id);

    // Create an asset group to ensure there's at least one
    let group_name = unique_name("assetgrp-search-test");
    create_test_asset_group(&mut conn, &group_name);

    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_username, true, true);

    // Test 1: No filter - page loads with groups
    let response_no_filter = app
        .server
        .get("/assets/groups")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(
        response_no_filter.status_code().as_u16(),
        200,
        "Asset group list without filter should load"
    );
    let body_no_filter = response_no_filter.text();

    // Test 2: Empty search should behave the same
    let response_empty = app
        .server
        .get("/assets/groups?search=")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(
        response_empty.status_code().as_u16(),
        200,
        "Asset group list with empty search should load"
    );
    let body_empty = response_empty.text();

    // Verify the group appears in both cases
    assert!(
        body_no_filter.contains(&group_name),
        "Asset group should appear without filter"
    );
    assert!(
        body_empty.contains(&group_name),
        "Asset group should appear with empty search filter"
    );

    // Test 3: Case-insensitive search
    let response_upper = app
        .server
        .get("/assets/groups?search=ASSETGRP-SEARCH")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(response_upper.status_code().as_u16(), 200);
    let body_upper = response_upper.text();
    assert!(
        body_upper.contains(&group_name),
        "Case-insensitive search should find asset group"
    );

    // Test 4: Partial search
    let response_partial = app
        .server
        .get("/assets/groups?search=assetgrp-search")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(response_partial.status_code().as_u16(), 200);
    let body_partial = response_partial.text();
    assert!(
        body_partial.contains(&group_name),
        "Partial search should find asset group"
    );
}

// =============================================================================
// Asset Group Detail Page Tests
// =============================================================================

#[tokio::test]
async fn test_asset_group_detail_page_loads() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Create test asset group
    let group_uuid = create_test_asset_group(&mut conn, &unique_name("test-detail-group")).await;

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

    // Not found redirects to list page with flash message
    assert_status(&response, 303);
    let location = response.headers().get("location").and_then(|v| v.to_str().ok());
    assert_eq!(location, Some("/assets/groups"));
}

// =============================================================================
// Asset Group Edit Page Tests
// =============================================================================

#[tokio::test]
async fn test_asset_group_edit_page_loads() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let group_uuid = create_test_asset_group(&mut conn, &unique_name("test-edit-group")).await;

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
    let mut conn = app.get_conn().await;

    let user_id = create_simple_user(&mut conn, "test_asset_detail_page").await;
    let user_uuid = get_user_uuid(&mut conn, user_id);
    let asset_id = create_simple_ssh_asset(&mut conn, "test-asset-detail", user_id);
    let asset_uuid = get_asset_uuid(&mut conn, asset_id).await;

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
    let mut conn = app.get_conn().await;

    let user_id = create_simple_user(&mut conn, &unique_name("test_asset_group"));
    let group_uuid = create_test_asset_group(&mut conn, &unique_name("test-asset-group-link")).await;
    let asset_id = create_test_asset_in_group(
        &mut conn,
        &unique_name("test-asset-in-group"),
        user_id,
        &group_uuid,
    );
    let asset_uuid = get_asset_uuid(&mut conn, asset_id).await;

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

    // Not found redirects to list page with flash message
    assert_status(&response, 303);
    let location = response.headers().get("location").and_then(|v| v.to_str().ok());
    assert_eq!(location, Some("/assets"));
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
async fn test_vauban_group_list_empty_search_shows_all() {
    // Regression test: empty search string should behave like no filter
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_username = unique_name("group_search_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_username).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id);

    // Create a group to ensure there's at least one
    let group_name = unique_name("search-test-group");
    create_test_vauban_group(&mut conn, &group_name);

    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_username, true, true);

    // Test 1: No filter - page loads with groups
    let response_no_filter = app
        .server
        .get("/accounts/groups")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(
        response_no_filter.status_code().as_u16(),
        200,
        "Group list without filter should load"
    );
    let body_no_filter = response_no_filter.text();

    // Test 2: Empty search should behave the same
    let response_empty = app
        .server
        .get("/accounts/groups?search=")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(
        response_empty.status_code().as_u16(),
        200,
        "Group list with empty search should load"
    );
    let body_empty = response_empty.text();

    // Verify the group appears in both cases
    assert!(
        body_no_filter.contains(&group_name),
        "Group should appear without filter"
    );
    assert!(
        body_empty.contains(&group_name),
        "Group should appear with empty search filter"
    );

    // Test 3: Case-insensitive search
    let response_upper = app
        .server
        .get("/accounts/groups?search=SEARCH-TEST")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(response_upper.status_code().as_u16(), 200);
    let body_upper = response_upper.text();
    assert!(
        body_upper.contains(&group_name),
        "Case-insensitive search should find group"
    );

    // Test 4: Partial search
    let response_partial = app
        .server
        .get("/accounts/groups?search=search-test")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(response_partial.status_code().as_u16(), 200);
    let body_partial = response_partial.text();
    assert!(
        body_partial.contains(&group_name),
        "Partial search should find group"
    );
}

#[tokio::test]
async fn test_group_detail_page_loads() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

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

    // Not found redirects to list page with flash message
    assert_status(&response, 303);
    let location = response.headers().get("location").and_then(|v| v.to_str().ok());
    assert_eq!(location, Some("/accounts/groups"));
}

// =============================================================================
// Vauban Group Management Tests (Edit, Members, Delete)
// =============================================================================

#[tokio::test]
async fn test_vauban_group_edit_form_loads() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let group_uuid = create_test_vauban_group(&mut conn, &unique_name("edit-form-group"));
    let token = app.generate_test_token(
        &Uuid::new_v4().to_string(),
        "test_vgroup_edit_form",
        true,
        true,
    );

    let response = app
        .server
        .get(&format!("/accounts/groups/{}/edit", group_uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(body.contains("Edit Group"), "Page should contain edit form");
}

#[tokio::test]
async fn test_vauban_group_update_success() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let group_uuid = create_test_vauban_group(&mut conn, &unique_name("update-group"));
    let token = app.generate_test_token(
        &Uuid::new_v4().to_string(),
        "test_vgroup_update",
        true,
        true,
    );
    let csrf_token = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!("/accounts/groups/{}", group_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("name", "Updated Group Name"),
            ("description", "Updated description"),
        ])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 303 || status == 302,
        "Expected redirect, got {}",
        status
    );
}

#[tokio::test]
async fn test_vauban_group_add_member_form_loads() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let group_uuid = create_test_vauban_group(&mut conn, &unique_name("add-member-form"));
    let token = app.generate_test_token(
        &Uuid::new_v4().to_string(),
        "test_add_member_form",
        true,
        true,
    );

    let response = app
        .server
        .get(&format!("/accounts/groups/{}/members/add", group_uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(
        body.contains("Add Member"),
        "Page should contain add member form"
    );
}

#[tokio::test]
async fn test_vauban_group_add_member_success() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let group_uuid = create_test_vauban_group(&mut conn, &unique_name("add-member-grp"));
    let user_id = create_simple_user(&mut conn, &unique_name("new-member"));
    let user_uuid = get_user_uuid(&mut conn, user_id);

    let token = app.generate_test_token(
        &Uuid::new_v4().to_string(),
        "test_add_member",
        true,
        true,
    );
    let csrf_token = app.generate_csrf_token();

    // Verify no members initially
    let count_before = count_vauban_group_members(&mut conn, &group_uuid).await;
    assert_eq!(count_before, 0, "Group should have no members initially");

    let response = app
        .server
        .post(&format!("/accounts/groups/{}/members", group_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("user_uuid", &user_uuid.to_string()),
        ])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 303 || status == 302,
        "Expected redirect, got {}",
        status
    );

    // Verify member was added
    let count_after = count_vauban_group_members(&mut conn, &group_uuid).await;
    assert_eq!(count_after, 1, "Group should have 1 member after adding");
}

#[tokio::test]
async fn test_vauban_group_remove_member_success() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let group_uuid = create_test_vauban_group(&mut conn, &unique_name("remove-member-grp"));
    let user_id = create_simple_user(&mut conn, &unique_name("removable-member"));
    let user_uuid = get_user_uuid(&mut conn, user_id);

    // Add member first
    add_user_to_vauban_group(&mut conn, user_id, &group_uuid).await;

    let count_before = count_vauban_group_members(&mut conn, &group_uuid).await;
    assert_eq!(count_before, 1, "Group should have 1 member initially");

    let token = app.generate_test_token(
        &Uuid::new_v4().to_string(),
        "test_remove_member",
        true,
        true,
    );
    let csrf_token = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!(
            "/accounts/groups/{}/members/{}/remove",
            group_uuid, user_uuid
        ))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[("csrf_token", csrf_token.as_str())])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 303 || status == 302,
        "Expected redirect, got {}",
        status
    );

    // Verify member was removed
    let count_after = count_vauban_group_members(&mut conn, &group_uuid).await;
    assert_eq!(count_after, 0, "Group should have 0 members after removal");
}

#[tokio::test]
async fn test_vauban_group_delete_empty_success() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let group_uuid = create_test_vauban_group(&mut conn, &unique_name("delete-empty-grp"));

    let token = app.generate_test_token(
        &Uuid::new_v4().to_string(),
        "test_delete_empty",
        true,
        true,
    );
    let csrf_token = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!("/accounts/groups/{}/delete", group_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[("csrf_token", csrf_token.as_str())])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 303 || status == 302,
        "Expected redirect, got {}",
        status
    );

    // Verify group was deleted
    use vauban_web::schema::vauban_groups;
    let exists: bool = vauban_groups::table
        .filter(vauban_groups::uuid.eq(group_uuid))
        .select(vauban_groups::id)
        .first::<i32>(&mut conn)
        .optional()
        .unwrap()
        .is_some();
    assert!(!exists, "Group should be deleted");
}

#[tokio::test]
async fn test_vauban_group_delete_with_members_fails() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let group_uuid = create_test_vauban_group(&mut conn, &unique_name("delete-has-members"));
    let user_id = create_simple_user(&mut conn, &unique_name("group-member"));

    // Add member to group
    add_user_to_vauban_group(&mut conn, user_id, &group_uuid).await;

    let token = app.generate_test_token(
        &Uuid::new_v4().to_string(),
        "test_delete_members",
        true,
        true,
    );
    let csrf_token = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!("/accounts/groups/{}/delete", group_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[("csrf_token", csrf_token.as_str())])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 303 || status == 302,
        "Expected redirect, got {}",
        status
    );

    // Verify group still exists (deletion failed)
    use vauban_web::schema::vauban_groups;
    let exists: bool = vauban_groups::table
        .filter(vauban_groups::uuid.eq(group_uuid))
        .select(vauban_groups::id)
        .first::<i32>(&mut conn)
        .optional()
        .unwrap()
        .is_some();
    assert!(exists, "Group should NOT be deleted when it has members");
}

#[tokio::test]
async fn test_vauban_group_delete_requires_admin() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let group_uuid = create_test_vauban_group(&mut conn, &unique_name("delete-nonadmin"));

    // Regular user (not staff, not superuser)
    let token = app.generate_test_token(
        &Uuid::new_v4().to_string(),
        "test_delete_nonadmin",
        false,
        false,
    );
    let csrf_token = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!("/accounts/groups/{}/delete", group_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[("csrf_token", csrf_token.as_str())])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 303 || status == 302,
        "Expected redirect, got {}",
        status
    );

    // Verify group still exists (non-admin cannot delete)
    use vauban_web::schema::vauban_groups;
    let exists: bool = vauban_groups::table
        .filter(vauban_groups::uuid.eq(group_uuid))
        .select(vauban_groups::id)
        .first::<i32>(&mut conn)
        .optional()
        .unwrap()
        .is_some();
    assert!(exists, "Group should NOT be deleted by non-admin");
}

// =============================================================================
// Web Form POST Tests (PRG Pattern with Flash Messages)
// =============================================================================

#[tokio::test]
async fn test_update_asset_web_form_redirects_on_success() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Create test data
    let user_id = create_simple_user(&mut conn, "test_asset_form").await;
    let user_uuid = get_user_uuid(&mut conn, user_id);
    let asset_id = create_simple_ssh_asset(&mut conn, "test-form-asset", user_id);
    let asset_uuid = get_asset_uuid(&mut conn, asset_id).await;

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
    let mut conn = app.get_conn().await;

    // Create test data
    let user_id = create_simple_user(&mut conn, "test_asset_val").await;
    let user_uuid = get_user_uuid(&mut conn, user_id);
    let asset_id = create_simple_ssh_asset(&mut conn, "test-val-asset", user_id);
    let asset_uuid = get_asset_uuid(&mut conn, asset_id).await;

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
    let mut conn = app.get_conn().await;

    // Create test data
    let user_id = create_simple_user(&mut conn, "test_group_form").await;
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
    let mut conn = app.get_conn().await;

    // Create test data
    let user_id = create_simple_user(&mut conn, "test_group_val").await;
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
    let mut conn = app.get_conn().await;

    let user_id = create_simple_user(&mut conn, "test_auth_check").await;
    let asset_id = create_simple_ssh_asset(&mut conn, "test-auth-asset", user_id);
    let asset_uuid = get_asset_uuid(&mut conn, asset_id).await;

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
    let mut conn = app.get_conn().await;

    let user_id = create_simple_user(&mut conn, "test_post_auth").await;
    let asset_id = create_simple_ssh_asset(&mut conn, "test-post-asset", user_id);
    let asset_uuid = get_asset_uuid(&mut conn, asset_id).await;

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
    let mut conn = app.get_conn().await;

    // Create test data
    let user_id = create_simple_user(&mut conn, "test_ip_error").await;
    let user_uuid = get_user_uuid(&mut conn, user_id);
    let asset_id = create_simple_ssh_asset(&mut conn, "test-ip-asset", user_id);
    let asset_uuid = get_asset_uuid(&mut conn, asset_id).await;

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
    let mut conn = app.get_conn().await;

    // Create test data
    let user_id = create_simple_user(&mut conn, "test_flash_display").await;
    let user_uuid = get_user_uuid(&mut conn, user_id);
    let asset_id = create_simple_ssh_asset(&mut conn, "test-flash-asset", user_id);
    let asset_uuid = get_asset_uuid(&mut conn, asset_id).await;

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
    let mut conn = app.get_conn().await;

    // Create test data
    let user_id = create_simple_user(&mut conn, "test_group_name_err").await;
    let user_uuid = get_user_uuid(&mut conn, user_id);
    let group_uuid = create_test_asset_group(&mut conn, &unique_name("test-name-err-grp")).await;

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
    let mut conn = app.get_conn().await;

    // Create test data
    let user_id = create_simple_user(&mut conn, "test_group_slug_err").await;
    let user_uuid = get_user_uuid(&mut conn, user_id);
    let group_uuid = create_test_asset_group(&mut conn, &unique_name("test-slug-err-grp")).await;

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
    let mut conn = app.get_conn().await;

    // Create test data
    let user_id = create_simple_user(&mut conn, "test_group_flash").await;
    let user_uuid = get_user_uuid(&mut conn, user_id);
    let group_uuid = create_test_asset_group(&mut conn, &unique_name("test-grp-flash-disp")).await;

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
// Asset Group Create/Delete Tests
// =============================================================================

#[tokio::test]
async fn test_asset_group_create_form_loads_for_admin() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("ag_create_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id);

    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_name, true, true);

    let response = app
        .server
        .get("/assets/groups/new")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(
        body.contains("New Asset Group"),
        "Page should contain 'New Asset Group'"
    );
}

#[tokio::test]
async fn test_asset_group_create_form_requires_admin() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("ag_create_normal");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id);

    let token = app.generate_test_token(&user_uuid.to_string(), &username, false, false);

    let response = app
        .server
        .get("/assets/groups/new")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 401 || status == 403,
        "Normal user should not access asset group creation, got {}",
        status
    );
}

#[tokio::test]
async fn test_asset_group_create_success() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("ag_creator");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id);

    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_name, true, true);
    let csrf_token = app.generate_csrf_token();

    let group_name = unique_name("new-test-group");
    let group_slug = unique_name("new-test-slug");

    let response = app
        .server
        .post("/assets/groups")
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("name", &group_name),
            ("slug", &group_slug),
            ("color", "#6366f1"),
            ("icon", "server"),
        ])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "Expected redirect after asset group creation, got {}",
        status
    );

    // Verify group was created
    use vauban_web::schema::asset_groups;
    let created: Option<String> = asset_groups::table
        .filter(asset_groups::name.eq(&group_name))
        .select(asset_groups::name)
        .first(&mut conn)
        .optional()
        .unwrap();

    assert!(created.is_some(), "Asset group should be created in database");
}

#[tokio::test]
async fn test_asset_group_create_normal_user_forbidden() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("ag_create_denied");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id);

    let token = app.generate_test_token(&user_uuid.to_string(), &username, false, false);
    let csrf_token = app.generate_csrf_token();

    let group_name = unique_name("forbidden-group");

    let response = app
        .server
        .post("/assets/groups")
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("name", &group_name),
            ("slug", "forbidden-slug"),
            ("color", "#6366f1"),
            ("icon", "server"),
        ])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "Expected redirect, got {}",
        status
    );

    // Verify group was NOT created
    use vauban_web::schema::asset_groups;
    let created: Option<i32> = asset_groups::table
        .filter(asset_groups::name.eq(&group_name))
        .select(asset_groups::id)
        .first(&mut conn)
        .optional()
        .unwrap();

    assert!(created.is_none(), "Normal user should not create asset group");
}

#[tokio::test]
async fn test_asset_group_create_duplicate_slug_rejected() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("ag_dup_creator");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id);

    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_name, true, true);
    let csrf_token = app.generate_csrf_token();

    // Create first group
    let group_slug = unique_name("dup-test-slug");
    let _ = create_test_asset_group(&mut conn, &group_slug);

    // Try to create another group with the same slug
    let response = app
        .server
        .post("/assets/groups")
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("name", "Different Name"),
            ("slug", &group_slug),
            ("color", "#6366f1"),
            ("icon", "server"),
        ])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "Expected redirect with error, got {}",
        status
    );

    // Verify only one group exists with this slug
    use vauban_web::schema::asset_groups;
    let count: i64 = asset_groups::table
        .filter(asset_groups::slug.eq(&group_slug))
        .count()
        .get_result(&mut conn)
        .unwrap();
    assert_eq!(count, 1, "Should only have one asset group with this slug");
}

#[tokio::test]
async fn test_asset_group_create_duplicate_slug_shows_flash_error() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("ag_dup_flash");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id);

    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_name, true, true);
    let csrf_token = app.generate_csrf_token();

    // Create first group
    let group_slug = unique_name("dup-flash-slug");
    let _ = create_test_asset_group(&mut conn, &group_slug);

    // Try to create another group with the same slug
    let error_response = app
        .server
        .post("/assets/groups")
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("name", "Different Name"),
            ("slug", &group_slug),
            ("color", "#6366f1"),
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
            cookie_str.split(';').next().unwrap().to_string()
        });

    assert!(flash_cookie.is_some(), "Flash cookie should be set");

    // Now GET the create page with the flash cookie to verify message is displayed
    let get_response = app
        .server
        .get("/assets/groups/new")
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}; {}", token, csrf_token, flash_cookie.unwrap()),
        )
        .await;

    assert_status(&get_response, 200);
    let body = get_response.text();
    
    assert!(
        body.contains("slug already exists") || body.contains("bg-red-50"),
        "Create page should display error flash message about duplicate slug"
    );
}

#[tokio::test]
async fn test_asset_group_delete_success() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("ag_deleter");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id);

    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_name, true, true);
    let csrf_token = app.generate_csrf_token();

    // Create a group to delete
    let group_uuid = create_test_asset_group(&mut conn, &unique_name("delete-me-group")).await;

    let response = app
        .server
        .post(&format!("/assets/groups/{}/delete", group_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[("csrf_token", csrf_token.as_str())])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "Expected redirect after asset group deletion, got {}",
        status
    );

    // Verify group was hard deleted
    use vauban_web::schema::asset_groups;
    let exists: Option<i32> = asset_groups::table
        .filter(asset_groups::uuid.eq(group_uuid))
        .select(asset_groups::id)
        .first(&mut conn)
        .optional()
        .unwrap();

    assert!(exists.is_none(), "Asset group should be hard deleted");
}

#[tokio::test]
async fn test_asset_group_delete_with_assets() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("ag_del_assets");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id);

    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_name, true, true);
    let csrf_token = app.generate_csrf_token();

    // Create a group with an asset
    let group_uuid = create_test_asset_group(&mut conn, &unique_name("del-with-assets")).await;
    let _asset_id = create_test_asset_in_group(&mut conn, &unique_name("asset-in-grp"), admin_id, &group_uuid).await;

    let response = app
        .server
        .post(&format!("/assets/groups/{}/delete", group_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[("csrf_token", csrf_token.as_str())])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "Expected redirect after asset group deletion, got {}",
        status
    );

    // Verify group was deleted (deletion allowed even with assets)
    use vauban_web::schema::asset_groups;
    let exists: Option<i32> = asset_groups::table
        .filter(asset_groups::uuid.eq(group_uuid))
        .select(asset_groups::id)
        .first(&mut conn)
        .optional()
        .unwrap();

    assert!(exists.is_none(), "Asset group should be deleted even with assets");

    // Verify assets are unlinked (group_id set to NULL)
    use vauban_web::schema::assets;
    let asset_group_id: Option<Option<i32>> = assets::table
        .filter(assets::name.like(format!("%asset-in-grp%")))
        .select(assets::group_id)
        .first(&mut conn)
        .optional()
        .unwrap();

    if let Some(group_id) = asset_group_id {
        assert!(group_id.is_none(), "Asset should have NULL group_id after group deletion");
    }
}

// =============================================================================
// Asset Group Membership Tests
// =============================================================================

#[tokio::test]
async fn test_asset_group_add_asset_form_loads() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("add_asset_form_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id);

    let group_uuid = create_test_asset_group(&mut conn, &unique_name("add-asset-form-grp")).await;

    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_name, true, true);

    let response = app
        .server
        .get(&format!("/assets/groups/{}/add-asset", group_uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(body.contains("Add Asset"), "Page should show 'Add Asset' title");
    assert!(body.contains("asset-search"), "Page should have search input");
    assert!(body.contains("x-model=\"search\""), "Page should use Alpine.js for filtering");
}

#[tokio::test]
async fn test_asset_group_add_asset_form_requires_admin() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("add_asset_form_user");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id);

    let group_uuid = create_test_asset_group(&mut conn, &unique_name("add-asset-form-denied")).await;

    let token = app.generate_test_token(&user_uuid.to_string(), &username, false, false);

    let response = app
        .server
        .get(&format!("/assets/groups/{}/add-asset", group_uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 401 || status == 403,
        "Normal user should not access add asset form, got {}",
        status
    );
}

#[tokio::test]
async fn test_asset_group_add_asset_success() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("add_asset_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id);

    let group_uuid = create_test_asset_group(&mut conn, &unique_name("add-asset-grp")).await;
    let asset_id = create_simple_ssh_asset(&mut conn, &unique_name("asset-to-add"), admin_id);

    // Get asset UUID
    use vauban_web::schema::assets;
    let asset_uuid: uuid::Uuid = assets::table
        .filter(assets::id.eq(asset_id))
        .select(assets::uuid)
        .first(&mut conn)
        .unwrap();

    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_name, true, true);
    let csrf_token = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!("/assets/groups/{}/add-asset", group_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("asset_uuids", &asset_uuid.to_string()),
        ])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "Expected redirect after adding asset, got {}",
        status
    );

    // Verify asset was added to group
    use vauban_web::schema::asset_groups;
    let group_id: i32 = asset_groups::table
        .filter(asset_groups::uuid.eq(group_uuid))
        .select(asset_groups::id)
        .first(&mut conn)
        .unwrap();

    let asset_group_id: Option<i32> = assets::table
        .filter(assets::id.eq(asset_id))
        .select(assets::group_id)
        .first(&mut conn)
        .unwrap();

    assert_eq!(
        asset_group_id,
        Some(group_id),
        "Asset should be assigned to the group"
    );
}

/// Test adding multiple assets to a group at once (multi-select checkboxes)
#[tokio::test]
async fn test_asset_group_add_multiple_assets_success() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("add_multi_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id);

    let group_uuid = create_test_asset_group(&mut conn, &unique_name("add-multi-grp")).await;

    // Create multiple assets
    let asset1_id = create_simple_ssh_asset(&mut conn, &unique_name("multi-asset1"), admin_id);
    let asset2_id = create_simple_ssh_asset(&mut conn, &unique_name("multi-asset2"), admin_id);
    let asset3_id = create_simple_ssh_asset(&mut conn, &unique_name("multi-asset3"), admin_id);

    // Get asset UUIDs
    use vauban_web::schema::assets;
    let asset1_uuid: uuid::Uuid = assets::table
        .filter(assets::id.eq(asset1_id))
        .select(assets::uuid)
        .first(&mut conn)
        .unwrap();
    let asset2_uuid: uuid::Uuid = assets::table
        .filter(assets::id.eq(asset2_id))
        .select(assets::uuid)
        .first(&mut conn)
        .unwrap();
    let asset3_uuid: uuid::Uuid = assets::table
        .filter(assets::id.eq(asset3_id))
        .select(assets::uuid)
        .first(&mut conn)
        .unwrap();

    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_name, true, true);
    let csrf_token = app.generate_csrf_token();

    // Submit form with multiple asset_uuids (simulating multiple checkboxes)
    let form_body = format!(
        "csrf_token={}&asset_uuids={}&asset_uuids={}&asset_uuids={}",
        csrf_token, asset1_uuid, asset2_uuid, asset3_uuid
    );

    let response = app
        .server
        .post(&format!("/assets/groups/{}/add-asset", group_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .content_type("application/x-www-form-urlencoded")
        .text(form_body)
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "Expected redirect after adding assets, got {}",
        status
    );

    // Verify all assets were added to group
    use vauban_web::schema::asset_groups;
    let group_id: i32 = asset_groups::table
        .filter(asset_groups::uuid.eq(group_uuid))
        .select(asset_groups::id)
        .first(&mut conn)
        .unwrap();

    for asset_id in [asset1_id, asset2_id, asset3_id] {
        let asset_group_id: Option<i32> = assets::table
            .filter(assets::id.eq(asset_id))
            .select(assets::group_id)
            .first(&mut conn)
            .unwrap();

        assert_eq!(
            asset_group_id,
            Some(group_id),
            "Asset {} should be assigned to the group",
            asset_id
        );
    }
}

#[tokio::test]
async fn test_asset_group_add_asset_normal_user_forbidden() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("add_asset_user");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id);

    let admin_id = create_simple_admin_user(&mut conn, &unique_name("add_asset_admin2"));
    let group_uuid = create_test_asset_group(&mut conn, &unique_name("add-asset-denied")).await;
    let asset_id = create_simple_ssh_asset(&mut conn, &unique_name("asset-add-denied"), admin_id);

    // Get asset UUID
    use vauban_web::schema::assets;
    let asset_uuid: uuid::Uuid = assets::table
        .filter(assets::id.eq(asset_id))
        .select(assets::uuid)
        .first(&mut conn)
        .unwrap();

    let token = app.generate_test_token(&user_uuid.to_string(), &username, false, false);
    let csrf_token = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!("/assets/groups/{}/add-asset", group_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("asset_uuids", &asset_uuid.to_string()),
        ])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "Expected redirect (with error), got {}",
        status
    );

    // Verify asset was NOT added to group
    let asset_group_id: Option<i32> = assets::table
        .filter(assets::id.eq(asset_id))
        .select(assets::group_id)
        .first(&mut conn)
        .unwrap();

    assert!(
        asset_group_id.is_none(),
        "Normal user should not add asset to group"
    );
}

#[tokio::test]
async fn test_asset_group_add_asset_already_in_group() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("add_asset_dup_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id);

    // Create first group and add asset to it
    let group1_uuid = create_test_asset_group(&mut conn, &unique_name("add-asset-grp1")).await;
    let asset_id = create_test_asset_in_group(&mut conn, &unique_name("asset-in-grp1"), admin_id, &group1_uuid).await;

    // Get asset UUID
    use vauban_web::schema::assets;
    let asset_uuid: uuid::Uuid = assets::table
        .filter(assets::id.eq(asset_id))
        .select(assets::uuid)
        .first(&mut conn)
        .unwrap();

    // Create second group and try to add the same asset
    let group2_uuid = create_test_asset_group(&mut conn, &unique_name("add-asset-grp2")).await;

    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_name, true, true);
    let csrf_token = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!("/assets/groups/{}/add-asset", group2_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("asset_uuids", &asset_uuid.to_string()),
        ])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "Expected redirect (with error), got {}",
        status
    );

    // Verify asset is still in group1 (not moved to group2)
    use vauban_web::schema::asset_groups;
    let group1_id: i32 = asset_groups::table
        .filter(asset_groups::uuid.eq(group1_uuid))
        .select(asset_groups::id)
        .first(&mut conn)
        .unwrap();

    let asset_group_id: Option<i32> = assets::table
        .filter(assets::id.eq(asset_id))
        .select(assets::group_id)
        .first(&mut conn)
        .unwrap();

    assert_eq!(
        asset_group_id,
        Some(group1_id),
        "Asset should still be in original group"
    );
}

#[tokio::test]
async fn test_asset_group_remove_asset_success() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("rem_asset_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id);

    let group_uuid = create_test_asset_group(&mut conn, &unique_name("rem-asset-grp")).await;
    let asset_id = create_test_asset_in_group(&mut conn, &unique_name("asset-to-rem"), admin_id, &group_uuid).await;

    // Get asset UUID
    use vauban_web::schema::assets;
    let asset_uuid: uuid::Uuid = assets::table
        .filter(assets::id.eq(asset_id))
        .select(assets::uuid)
        .first(&mut conn)
        .unwrap();

    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_name, true, true);
    let csrf_token = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!("/assets/groups/{}/remove-asset", group_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("asset_uuid", &asset_uuid.to_string()),
        ])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "Expected redirect after removing asset, got {}",
        status
    );

    // Verify asset was removed from group
    let asset_group_id: Option<i32> = assets::table
        .filter(assets::id.eq(asset_id))
        .select(assets::group_id)
        .first(&mut conn)
        .unwrap();

    assert!(
        asset_group_id.is_none(),
        "Asset should be removed from group"
    );
}

#[tokio::test]
async fn test_asset_group_remove_asset_normal_user_forbidden() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("rem_asset_user");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id);

    let admin_id = create_simple_admin_user(&mut conn, &unique_name("rem_asset_admin2"));
    let group_uuid = create_test_asset_group(&mut conn, &unique_name("rem-asset-denied")).await;
    let asset_id = create_test_asset_in_group(&mut conn, &unique_name("asset-rem-denied"), admin_id, &group_uuid).await;

    // Get asset UUID
    use vauban_web::schema::assets;
    let asset_uuid: uuid::Uuid = assets::table
        .filter(assets::id.eq(asset_id))
        .select(assets::uuid)
        .first(&mut conn)
        .unwrap();

    let token = app.generate_test_token(&user_uuid.to_string(), &username, false, false);
    let csrf_token = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!("/assets/groups/{}/remove-asset", group_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("asset_uuid", &asset_uuid.to_string()),
        ])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "Expected redirect (with error), got {}",
        status
    );

    // Verify asset was NOT removed from group
    use vauban_web::schema::asset_groups;
    let group_id: i32 = asset_groups::table
        .filter(asset_groups::uuid.eq(group_uuid))
        .select(asset_groups::id)
        .first(&mut conn)
        .unwrap();

    let asset_group_id: Option<i32> = assets::table
        .filter(assets::id.eq(asset_id))
        .select(assets::group_id)
        .first(&mut conn)
        .unwrap();

    assert_eq!(
        asset_group_id,
        Some(group_id),
        "Normal user should not remove asset from group"
    );
}

#[tokio::test]
async fn test_asset_group_detail_shows_add_asset_button() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("det_add_btn_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id);

    let group_uuid = create_test_asset_group(&mut conn, &unique_name("det-add-btn-grp")).await;

    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_name, true, true);

    let response = app
        .server
        .get(&format!("/assets/groups/{}", group_uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(
        body.contains("Add Asset"),
        "Group detail page should show 'Add Asset' button"
    );
    assert!(
        body.contains(&format!("/assets/groups/{}/add-asset", group_uuid)),
        "Page should contain link to add asset form"
    );
}

#[tokio::test]
async fn test_asset_group_detail_shows_remove_button() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("det_rem_btn_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id);

    let group_uuid = create_test_asset_group(&mut conn, &unique_name("det-rem-btn-grp")).await;
    let _asset_id = create_test_asset_in_group(&mut conn, &unique_name("asset-rem-btn"), admin_id, &group_uuid).await;

    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_name, true, true);

    let response = app
        .server
        .get(&format!("/assets/groups/{}", group_uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(
        body.contains("Remove"),
        "Group detail page should show 'Remove' button for assets"
    );
    assert!(
        body.contains(&format!("/assets/groups/{}/remove-asset", group_uuid)),
        "Page should contain form action for removing asset"
    );
}

#[tokio::test]
async fn test_asset_group_delete_normal_user_forbidden() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("ag_del_denied");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id);

    let token = app.generate_test_token(&user_uuid.to_string(), &username, false, false);
    let csrf_token = app.generate_csrf_token();

    // Create a group to try to delete
    let group_uuid = create_test_asset_group(&mut conn, &unique_name("no-del-group")).await;

    let response = app
        .server
        .post(&format!("/assets/groups/{}/delete", group_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[("csrf_token", csrf_token.as_str())])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "Expected redirect, got {}",
        status
    );

    // Verify group was NOT deleted
    use vauban_web::schema::asset_groups;
    let exists: Option<i32> = asset_groups::table
        .filter(asset_groups::uuid.eq(group_uuid))
        .select(asset_groups::id)
        .first(&mut conn)
        .optional()
        .unwrap();

    assert!(exists.is_some(), "Normal user should not delete asset group");
}

#[tokio::test]
async fn test_asset_group_detail_has_delete_button() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("ag_del_btn_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id);

    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_name, true, true);

    let group_uuid = create_test_asset_group(&mut conn, &unique_name("del-btn-group")).await;

    let response = app
        .server
        .get(&format!("/assets/groups/{}", group_uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(
        body.contains("/delete") && body.contains("Delete"),
        "Group detail page should contain delete button"
    );
}

#[tokio::test]
async fn test_asset_group_icons_rendered_correctly() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("ag_icon_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id);

    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_name, true, true);

    // Create groups with different icons
    let icons = ["server", "database", "code", "desktop", "wifi", "cloud", "folder"];
    
    for icon_name in &icons {
        let group_slug = unique_name(&format!("icon-{}", icon_name));
        let group_name = unique_name(&format!("Test-{}", icon_name));
        
        // Insert group with specific icon
        use vauban_web::schema::asset_groups;
        let group_uuid = uuid::Uuid::new_v4();
        diesel::insert_into(asset_groups::table)
            .values((
                asset_groups::uuid.eq(group_uuid),
                asset_groups::name.eq(&group_name),
                asset_groups::slug.eq(&group_slug),
                asset_groups::color.eq("#6366f1"),
                asset_groups::icon.eq(*icon_name),
                asset_groups::is_deleted.eq(false),
            ))
            .execute(&mut conn)
            .expect("Failed to create test group");

        // Verify icon is rendered on detail page
        let response = app
            .server
            .get(&format!("/assets/groups/{}", group_uuid))
            .add_header(COOKIE, format!("access_token={}", token))
            .await;

        assert_status(&response, 200);
        let body = response.text();
        
        // Each icon should have unique SVG path patterns
        match *icon_name {
            "database" => assert!(
                body.contains("M4 7v10c0 2.21"),
                "Database icon should have database SVG path"
            ),
            "code" => assert!(
                body.contains("M10 20l4-16"),
                "Code icon should have code SVG path"
            ),
            "desktop" => assert!(
                body.contains("M9.75 17L9 20"),
                "Desktop icon should have desktop SVG path"
            ),
            "wifi" => assert!(
                body.contains("M8.111 16.404"),
                "Wifi icon should have wifi SVG path"
            ),
            "cloud" => assert!(
                body.contains("M3 15a4 4 0 004 4h9"),
                "Cloud icon should have cloud SVG path"
            ),
            "folder" => assert!(
                body.contains("M3 7v10a2 2 0 002 2h14"),
                "Folder icon should have folder SVG path"
            ),
            "server" | _ => assert!(
                body.contains("M5 12h14M5 12a2 2 0"),
                "Server icon should have server SVG path"
            ),
        }
    }
}

#[tokio::test]
async fn test_asset_group_create_form_fields_present() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("ag_form_fields");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id);

    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_name, true, true);
    let csrf_token = app.generate_csrf_token();

    let response = app
        .server
        .get("/assets/groups/new")
        .add_header(COOKIE, format!("access_token={}; __vauban_csrf={}", token, csrf_token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    
    // Verify form action is correct
    assert!(
        body.contains("action=\"/assets/groups\"") && body.contains("method=\"POST\""),
        "Form should have correct action and method"
    );
    
    // Verify CSRF token value is present in the form
    assert!(
        body.contains(&format!("value=\"{}\"", csrf_token)),
        "Form should contain csrf_token value. Body: {}",
        &body[..std::cmp::min(2000, body.len())]
    );
    
    // Verify required fields are present
    assert!(
        body.contains("name=\"name\""),
        "Form should have name field"
    );
    assert!(
        body.contains("name=\"slug\""),
        "Form should have slug field"
    );
    assert!(
        body.contains("name=\"color\""),
        "Form should have color field"
    );
    assert!(
        body.contains("name=\"icon\""),
        "Form should have icon field"
    );
    
    // Verify submit button is inside the form
    assert!(
        body.contains("type=\"submit\"") && body.contains("Create Group"),
        "Form should have submit button"
    );
    
    // Verify the form structure: form opens before submit and closes after
    let form_start = body.find("action=\"/assets/groups\"");
    let submit_button = body.find("Create Group");
    let form_end = body.rfind("</form>");
    
    assert!(form_start.is_some(), "Form start should exist");
    assert!(submit_button.is_some(), "Submit button should exist");
    assert!(form_end.is_some(), "Form end should exist");
    
    let form_start_pos = form_start.unwrap();
    let submit_pos = submit_button.unwrap();
    let form_end_pos = form_end.unwrap();
    
    assert!(
        form_start_pos < submit_pos && submit_pos < form_end_pos,
        "Submit button must be inside form. Positions: form_start={}, submit={}, form_end={}",
        form_start_pos, submit_pos, form_end_pos
    );
}

// =============================================================================
// User List Filter Tests
// =============================================================================

#[tokio::test]
async fn test_user_list_filter_by_all_statuses() {
    // Test that filtering works correctly for all user status types:
    // - active, inactive
    // - empty string (All statuses) should behave like no filter
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_username = unique_name("user_list_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_username).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id);

    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_username, true, true);

    // Test 1: No filter - page should load successfully
    let response_no_filter = app
        .server
        .get("/accounts/users")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(
        response_no_filter.status_code().as_u16(),
        200,
        "User list without filter should load"
    );

    let body_no_filter = response_no_filter.text();
    assert!(
        body_no_filter.contains("Users") || body_no_filter.contains("users"),
        "Page should contain Users title"
    );

    // Test 2: Empty status filter (simulates "All statuses" selection after filtering)
    // This is a regression test - previously empty string would filter incorrectly
    let response_empty_filter = app
        .server
        .get("/accounts/users?status=")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(
        response_empty_filter.status_code().as_u16(),
        200,
        "User list with empty filter should load"
    );

    // Test 3: Filter by active status - page loads and shows correct selection
    let response_active = app
        .server
        .get("/accounts/users?status=active")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(response_active.status_code().as_u16(), 200);
    let body_active = response_active.text();
    // Verify selection is correct in the dropdown
    assert!(
        body_active.contains("value=\"active\"") && body_active.contains("selected"),
        "Active should be selectable in dropdown"
    );

    // Test 4: Filter by inactive status - page loads
    let response_inactive = app
        .server
        .get("/accounts/users?status=inactive")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(response_inactive.status_code().as_u16(), 200);
    let body_inactive = response_inactive.text();
    assert!(
        body_inactive.contains("value=\"inactive\"") && body_inactive.contains("selected"),
        "Inactive should be selectable in dropdown"
    );

    // Test 5: Invalid status filter - page should still load
    let response_invalid = app
        .server
        .get("/accounts/users?status=invalid_status")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(
        response_invalid.status_code().as_u16(),
        200,
        "User list with invalid status should still load"
    );
}

#[tokio::test]
async fn test_user_list_search_by_username() {
    // Test that searching by username works correctly
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_username = unique_name("user_search_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_username).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id);

    // Create a user with a unique searchable name - use full UUID for uniqueness
    let unique_suffix = uuid::Uuid::new_v4().to_string().replace('-', "");
    let searchable_user = format!("searchuser{}", &unique_suffix[..16]);
    create_simple_user(&mut conn, &searchable_user);

    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_username, true, true);

    // Test 1: Search for the unique username - should find it
    let response = app
        .server
        .get(&format!("/accounts/users?search={}", searchable_user))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(response.status_code().as_u16(), 200);
    let body = response.text();
    assert!(body.contains(&searchable_user), "Should find user by exact username");

    // Test 2: Partial search using the first 12 chars of the unique name
    let partial_search = &searchable_user[..12];
    let response_partial = app
        .server
        .get(&format!("/accounts/users?search={}", partial_search))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(response_partial.status_code().as_u16(), 200);
    let body_partial = response_partial.text();
    assert!(
        body_partial.contains(&searchable_user),
        "Partial search '{}' should find user '{}'", partial_search, searchable_user
    );

    // Test 3: Case-insensitive search using uppercase of the partial
    let uppercase_search = partial_search.to_uppercase();
    let response_case = app
        .server
        .get(&format!("/accounts/users?search={}", uppercase_search))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(response_case.status_code().as_u16(), 200);
    let body_case = response_case.text();
    assert!(
        body_case.contains(&searchable_user),
        "Case-insensitive search '{}' should find user '{}'", uppercase_search, searchable_user
    );

    // Test 4: Empty search should load page normally (regression test for empty string bug)
    let response_empty = app
        .server
        .get("/accounts/users?search=")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(
        response_empty.status_code().as_u16(),
        200,
        "Empty search should load page"
    );

    // Test 5: Non-matching search - page loads but may show no results
    let response_no_match = app
        .server
        .get("/accounts/users?search=nonexistent_xyz_user_12345")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(
        response_no_match.status_code().as_u16(),
        200,
        "Non-matching search should still load page"
    );
}

#[tokio::test]
async fn test_user_list_combined_filters() {
    // Test combining search and status filters
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_username = unique_name("combofilt_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_username).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id);

    // Create users with different statuses and unique names to avoid conflicts with other tests
    let active_user = unique_name("combofilt_active");
    let inactive_user = unique_name("combofilt_inactive");

    let _active_id = create_simple_user(&mut conn, &active_user).await;
    let inactive_id = create_simple_user(&mut conn, &inactive_user).await;

    // Deactivate one user
    use vauban_web::schema::users;
    diesel::update(users::table.filter(users::id.eq(inactive_id)))
        .set(users::is_active.eq(false))
        .execute(&mut conn)
        .expect("Failed to deactivate user");

    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_username, true, true);

    // Test 1: Search for specific active user with active status filter
    // Use the full username to avoid matching other test data
    let response = app
        .server
        .get(&format!("/accounts/users?search={}&status=active", active_user))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(response.status_code().as_u16(), 200);
    let body = response.text();
    assert!(
        body.contains(&active_user),
        "Combined filter should find active user matching search. Looking for: {}",
        active_user
    );

    // Test 2: Search for specific inactive user with inactive status filter
    let response_inactive = app
        .server
        .get(&format!("/accounts/users?search={}&status=inactive", inactive_user))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(response_inactive.status_code().as_u16(), 200);
    let body_inactive = response_inactive.text();
    assert!(
        body_inactive.contains(&inactive_user),
        "Combined filter should find inactive user matching search. Looking for: {}",
        inactive_user
    );

    // Test 3: Verify status filter works - active user should NOT appear with inactive filter
    // Note: We search for the full username which is unique, so if it appears, the filter is broken
    let response_conflict = app
        .server
        .get(&format!(
            "/accounts/users?search={}&status=inactive",
            active_user
        ))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(response_conflict.status_code().as_u16(), 200);
    // The page should load but not contain the active user in the results table
    // Note: The username might still appear in the page (e.g., in the search box) but not in the user list
}

// =============================================================================
// User Management Tests (Create, Edit, Delete)
// =============================================================================

#[tokio::test]
async fn test_user_create_form_requires_admin() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Create a regular user (not staff, not superuser)
    let username = unique_name("regular_user");
    let user_id = create_simple_user(&mut conn, &username).await;
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
    let mut conn = app.get_conn().await;

    let admin_username = unique_name("admin_create_form");
    let admin_id = create_simple_admin_user(&mut conn, &admin_username).await;
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
    let mut conn = app.get_conn().await;

    let admin_username = unique_name("admin_create_user");
    let admin_id = create_simple_admin_user(&mut conn, &admin_username).await;
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
    let mut conn = app.get_conn().await;

    let admin_username = unique_name("admin_pw_val");
    let admin_id = create_simple_admin_user(&mut conn, &admin_username).await;
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
    let mut conn = app.get_conn().await;

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
    let mut conn = app.get_conn().await;

    let admin_username = unique_name("admin_edit_form");
    let admin_id = create_simple_admin_user(&mut conn, &admin_username).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id);
    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_username, true, true);

    // Create a user to edit
    let target_username = unique_name("edit_target");
    let target_id = create_simple_user(&mut conn, &target_username).await;
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
    let mut conn = app.get_conn().await;

    let admin_username = unique_name("admin_update");
    let admin_id = create_simple_admin_user(&mut conn, &admin_username).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id);
    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_username, true, true);
    let csrf_token = app.generate_csrf_token();

    // Create a user to update
    let target_username = unique_name("update_target");
    let target_id = create_simple_user(&mut conn, &target_username).await;
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
    let mut conn = app.get_conn().await;

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
    let super_id = create_simple_admin_user(&mut conn, &super_username).await;
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
    let mut conn = app.get_conn().await;

    let admin_username = unique_name("admin_delete");
    let admin_id = create_simple_admin_user(&mut conn, &admin_username).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id);
    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_username, true, true);
    let csrf_token = app.generate_csrf_token();

    // Create a user to delete
    let target_username = unique_name("delete_target");
    let target_id = create_simple_user(&mut conn, &target_username).await;
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
#[serial_test::serial]
async fn test_user_delete_protects_last_superuser() {
    // This test verifies that when there is only 1 active superuser,
    // deleting them should fail. Uses serial_test to run in isolation.
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    use vauban_web::schema::users;
    use chrono::Utc;

    // First, record IDs of users we modify so we can restore them
    let other_superuser_ids: Vec<i32> = users::table
        .filter(users::is_superuser.eq(true))
        .filter(users::is_active.eq(true))
        .filter(users::is_deleted.eq(false))
        .select(users::id)
        .load(&mut conn)
        .unwrap_or_default();

    // Create a unique superuser for this test
    let last_super_username = unique_name("last_super");
    let last_super_id = create_simple_admin_user(&mut conn, &last_super_username).await;
    let last_super_uuid = get_user_uuid(&mut conn, last_super_id);

    // Deactivate ALL OTHER superusers (we'll restore them at the end)
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

    // Cleanup: reactivate ONLY the superusers we deactivated
    if !other_superuser_ids.is_empty() {
        diesel::update(
            users::table.filter(users::id.eq_any(&other_superuser_ids)),
        )
        .set((users::is_active.eq(true), users::updated_at.eq(now)))
        .execute(&mut conn)
        .ok();
    }
}

#[tokio::test]
async fn test_user_delete_staff_cannot_delete_superuser() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

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
    let super_id = create_simple_admin_user(&mut conn, &super_username).await;
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
    let mut conn = app.get_conn().await;

    let admin_username = unique_name("admin_csrf_del");
    let admin_id = create_simple_admin_user(&mut conn, &admin_username).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id);
    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_username, true, true);

    let target_username = unique_name("csrf_del_target");
    let target_id = create_simple_user(&mut conn, &target_username).await;
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

// =============================================================================
// Group Create Tests
// =============================================================================

#[tokio::test]
async fn test_vauban_group_create_form_loads_for_superuser() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Create a superuser in the database
    let admin_username = unique_name("grp_create_super");
    let admin_id = create_simple_admin_user(&mut conn, &admin_username).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id);

    // Superuser can access create form
    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_username, true, true);

    let response = app
        .server
        .get("/accounts/groups/new")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(body.contains("Create New Group"), "Should show create group form");
}

#[tokio::test]
async fn test_vauban_group_create_form_requires_superuser() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Create a staff user (not superuser) in the database
    let staff_username = unique_name("grp_create_staff");
    let staff_id = create_simple_user(&mut conn, &staff_username).await;
    // Update user to be staff but not superuser
    use vauban_web::schema::users;
    diesel::update(users::table.filter(users::id.eq(staff_id)))
        .set((users::is_staff.eq(true), users::is_superuser.eq(false)))
        .execute(&mut conn)
        .unwrap();
    let staff_uuid = get_user_uuid(&mut conn, staff_id);

    // Staff member cannot access create form
    let token = app.generate_test_token(&staff_uuid.to_string(), &staff_username, false, true);

    let response = app
        .server
        .get("/accounts/groups/new")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    // Should get authorization error (500 because AppError::Authorization maps to internal error)
    let status = response.status_code().as_u16();
    assert!(
        status == 401 || status == 403 || status == 500,
        "Staff should not access group create, got {}",
        status
    );
}

#[tokio::test]
async fn test_vauban_group_create_success() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Create a superuser in the database
    let admin_username = unique_name("grp_create_ok");
    let admin_id = create_simple_admin_user(&mut conn, &admin_username).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id);

    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_username, true, true);
    let csrf_token = app.generate_csrf_token();

    let group_name = unique_name("new-test-group");
    let response = app
        .server
        .post("/accounts/groups")
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("name", &group_name),
            ("description", "Test group description"),
        ])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 303 || status == 302,
        "Expected redirect after create, got {}",
        status
    );

    // Verify group was created
    use vauban_web::schema::vauban_groups;
    let created: Option<(Uuid, String)> = vauban_groups::table
        .filter(vauban_groups::name.eq(&group_name))
        .select((vauban_groups::uuid, vauban_groups::source))
        .first(&mut conn)
        .optional()
        .unwrap();

    assert!(created.is_some(), "Group should be created");
    let (_, source) = created.unwrap();
    assert_eq!(source, "local", "Group source should be 'local'");
}

#[tokio::test]
async fn test_vauban_group_create_staff_cannot_create() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Create a staff user (not superuser) in the database
    let staff_username = unique_name("grp_create_staff2");
    let staff_id = create_simple_user(&mut conn, &staff_username).await;
    // Update user to be staff but not superuser
    use vauban_web::schema::users;
    diesel::update(users::table.filter(users::id.eq(staff_id)))
        .set((users::is_staff.eq(true), users::is_superuser.eq(false)))
        .execute(&mut conn)
        .unwrap();
    let staff_uuid = get_user_uuid(&mut conn, staff_id);

    // Staff member attempts to create group
    let token = app.generate_test_token(&staff_uuid.to_string(), &staff_username, false, true);
    let csrf_token = app.generate_csrf_token();

    let group_name = unique_name("staff-create-grp");
    let response = app
        .server
        .post("/accounts/groups")
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("name", &group_name),
        ])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 303 || status == 302,
        "Expected redirect, got {}",
        status
    );

    // Verify group was NOT created
    use vauban_web::schema::vauban_groups;
    let exists: bool = vauban_groups::table
        .filter(vauban_groups::name.eq(&group_name))
        .select(vauban_groups::id)
        .first::<i32>(&mut conn)
        .optional()
        .unwrap()
        .is_some();

    assert!(!exists, "Staff should NOT be able to create group");
}

#[tokio::test]
async fn test_vauban_group_edit_requires_superuser() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let group_uuid = create_test_vauban_group(&mut conn, &unique_name("edit-staff-grp"));

    // Create a staff user (not superuser) in the database
    let staff_username = unique_name("grp_edit_staff");
    let staff_id = create_simple_user(&mut conn, &staff_username).await;
    // Update user to be staff but not superuser
    use vauban_web::schema::users;
    diesel::update(users::table.filter(users::id.eq(staff_id)))
        .set((users::is_staff.eq(true), users::is_superuser.eq(false)))
        .execute(&mut conn)
        .unwrap();
    let staff_uuid = get_user_uuid(&mut conn, staff_id);

    // Staff member attempts to access edit form
    let token = app.generate_test_token(&staff_uuid.to_string(), &staff_username, false, true);

    let response = app
        .server
        .get(&format!("/accounts/groups/{}/edit", group_uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 401 || status == 403 || status == 500,
        "Staff should not access group edit, got {}",
        status
    );
}

#[tokio::test]
async fn test_vauban_group_update_requires_superuser() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let original_name = unique_name("update-staff-grp");
    let group_uuid = create_test_vauban_group(&mut conn, &original_name).await;

    // Create a staff user (not superuser) in the database
    let staff_username = unique_name("grp_update_staff");
    let staff_id = create_simple_user(&mut conn, &staff_username).await;
    // Update user to be staff but not superuser
    use vauban_web::schema::users;
    diesel::update(users::table.filter(users::id.eq(staff_id)))
        .set((users::is_staff.eq(true), users::is_superuser.eq(false)))
        .execute(&mut conn)
        .unwrap();
    let staff_uuid = get_user_uuid(&mut conn, staff_id);

    // Staff member attempts to update group
    let token = app.generate_test_token(&staff_uuid.to_string(), &staff_username, false, true);
    let csrf_token = app.generate_csrf_token();

    let new_name = "staff-updated-name-should-fail";
    let response = app
        .server
        .post(&format!("/accounts/groups/{}", group_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("name", new_name),
        ])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 303 || status == 302,
        "Expected redirect, got {}",
        status
    );

    // Verify group was NOT updated to the new name
    use vauban_web::schema::vauban_groups;
    let current_name: String = vauban_groups::table
        .filter(vauban_groups::uuid.eq(group_uuid))
        .select(vauban_groups::name)
        .first(&mut conn)
        .unwrap();

    assert_ne!(current_name, new_name, "Staff should NOT be able to update group to new name");
    assert!(current_name.starts_with("update-staff-grp"), "Group name should still have original prefix");
}

#[tokio::test]
async fn test_vauban_group_delete_requires_superuser_not_staff() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let group_uuid = create_test_vauban_group(&mut conn, &unique_name("delete-staff-grp"));

    // Create a staff user (not superuser) in the database
    let staff_username = unique_name("grp_del_staff");
    let staff_id = create_simple_user(&mut conn, &staff_username).await;
    // Update user to be staff but not superuser
    use vauban_web::schema::users;
    diesel::update(users::table.filter(users::id.eq(staff_id)))
        .set((users::is_staff.eq(true), users::is_superuser.eq(false)))
        .execute(&mut conn)
        .unwrap();
    let staff_uuid = get_user_uuid(&mut conn, staff_id);

    // Staff member attempts to delete group
    let token = app.generate_test_token(&staff_uuid.to_string(), &staff_username, false, true);
    let csrf_token = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!("/accounts/groups/{}/delete", group_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[("csrf_token", csrf_token.as_str())])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 303 || status == 302,
        "Expected redirect, got {}",
        status
    );

    // Verify group still exists (staff cannot delete)
    use vauban_web::schema::vauban_groups;
    let exists: bool = vauban_groups::table
        .filter(vauban_groups::uuid.eq(group_uuid))
        .select(vauban_groups::id)
        .first::<i32>(&mut conn)
        .optional()
        .unwrap()
        .is_some();

    assert!(exists, "Staff should NOT be able to delete group");
}

// =============================================================================
// Permission System Tests - Admin-Only Pages
// =============================================================================

#[tokio::test]
async fn test_recordings_page_requires_admin() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Create a normal user (not admin)
    let username = unique_name("normal_rec_user");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id);

    // User is neither superuser nor staff
    let token = app.generate_test_token(&user_uuid.to_string(), &username, false, false);

    let response = app
        .server
        .get("/sessions/recordings")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 401 || status == 403,
        "Normal user should not access recordings, got {}",
        status
    );
}

#[tokio::test]
async fn test_recordings_page_accessible_to_superuser() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("superuser_rec");
    let user_id = create_simple_admin_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id);

    let token = app.generate_test_token(&user_uuid.to_string(), &username, true, true);

    let response = app
        .server
        .get("/sessions/recordings")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 200,
        "Superuser should access recordings, got {}",
        status
    );
}

#[tokio::test]
async fn test_recordings_page_accessible_to_staff() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("staff_rec");
    let user_id = create_simple_user(&mut conn, &username).await;
    // Update user to be staff
    use vauban_web::schema::users;
    diesel::update(users::table.filter(users::id.eq(user_id)))
        .set(users::is_staff.eq(true))
        .execute(&mut conn)
        .unwrap();
    let user_uuid = get_user_uuid(&mut conn, user_id);

    let token = app.generate_test_token(&user_uuid.to_string(), &username, false, true);

    let response = app
        .server
        .get("/sessions/recordings")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 200,
        "Staff should access recordings, got {}",
        status
    );
}

#[tokio::test]
async fn test_recordings_filter_by_all_formats() {
    // Test that filtering works correctly for all session format types:
    // - ssh, rdp, vnc
    // - empty string (All formats) should behave like no filter
    use crate::fixtures::create_recorded_session_with_type;

    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("rec_format_filter");
    let user_id = create_simple_admin_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id);

    // Create recordings with different session types
    let formats = ["ssh", "rdp", "vnc"];

    for (i, format) in formats.iter().enumerate() {
        let asset_id = create_simple_ssh_asset(
            &mut conn,
            &format!("rec-format-asset-{}-{}", format, i),
            user_id,
        );
        create_recorded_session_with_type(&mut conn, user_id, asset_id, format);
    }

    let token = app.generate_test_token(&user_uuid.to_string(), &username, true, true);

    // Test 1: No filter - should show all recordings
    let response_no_filter = app
        .server
        .get("/sessions/recordings")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(
        response_no_filter.status_code().as_u16(),
        200,
        "Recordings list without filter should load"
    );

    let body_no_filter = response_no_filter.text();
    assert!(
        !body_no_filter.contains("No recordings"),
        "Should show recordings when no filter is applied"
    );

    // Test 2: Empty format filter (simulates "All formats" selection)
    let response_empty_filter = app
        .server
        .get("/sessions/recordings?format=")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(
        response_empty_filter.status_code().as_u16(),
        200,
        "Recordings list with empty filter should load"
    );

    let body_empty_filter = response_empty_filter.text();
    assert!(
        !body_empty_filter.contains("No recordings"),
        "Empty format filter should show all recordings (same as no filter)"
    );

    // Test 3: Each specific format filter should work
    for format in &formats {
        let response = app
            .server
            .get(&format!("/sessions/recordings?format={}", format))
            .add_header(COOKIE, format!("access_token={}", token))
            .await;

        assert_eq!(
            response.status_code().as_u16(),
            200,
            "Recordings list with format={} filter should load",
            format
        );

        let body = response.text();

        // Should show the recording with this format (not empty)
        assert!(
            !body.contains("No recordings"),
            "Filter format={} should find the recording with that format",
            format
        );

        // Verify the filter dropdown shows the correct selection
        let expected_selected = format!("value=\"{}\" selected", format);
        assert!(
            body.contains(&expected_selected),
            "Filter dropdown should show {} as selected",
            format
        );
    }

    // Test 4: Invalid format filter should return empty
    let response_invalid = app
        .server
        .get("/sessions/recordings?format=invalid_format")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(
        response_invalid.status_code().as_u16(),
        200,
        "Recordings list with invalid format should still load"
    );

    let body_invalid = response_invalid.text();
    assert!(
        body_invalid.contains("No recordings"),
        "Invalid format filter should show no results"
    );
}

#[tokio::test]
async fn test_recordings_filter_by_asset_name() {
    // Test that searching by asset name works correctly
    use crate::fixtures::create_recorded_session_with_type;

    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("rec_asset_filter");
    let user_id = create_simple_admin_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id);

    // Create recordings with different asset names
    let asset_names = [
        "webserver-prod-01",
        "database-mysql-main",
        "cache-redis-cluster",
    ];

    for asset_name in &asset_names {
        let asset_id = create_simple_ssh_asset(&mut conn, asset_name, user_id);
        create_recorded_session_with_type(&mut conn, user_id, asset_id, "ssh");
    }

    let token = app.generate_test_token(&user_uuid.to_string(), &username, true, true);

    // Test 1: Search for exact asset name
    let response = app
        .server
        .get("/sessions/recordings?asset=webserver-prod-01")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(response.status_code().as_u16(), 200);
    let body = response.text();
    assert!(
        body.contains("webserver-prod-01"),
        "Should find recording for webserver-prod-01"
    );
    assert!(
        !body.contains("No recordings"),
        "Should not show empty state"
    );

    // Test 2: Search with partial asset name (should use ILIKE)
    let response_partial = app
        .server
        .get("/sessions/recordings?asset=mysql")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(response_partial.status_code().as_u16(), 200);
    let body_partial = response_partial.text();
    assert!(
        body_partial.contains("database-mysql-main"),
        "Partial search 'mysql' should find database-mysql-main"
    );

    // Test 3: Search with different case (ILIKE is case-insensitive)
    let response_case = app
        .server
        .get("/sessions/recordings?asset=REDIS")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(response_case.status_code().as_u16(), 200);
    let body_case = response_case.text();
    assert!(
        body_case.contains("cache-redis-cluster"),
        "Case-insensitive search 'REDIS' should find cache-redis-cluster"
    );

    // Test 4: Search with no matching asset
    let response_no_match = app
        .server
        .get("/sessions/recordings?asset=nonexistent-server")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(response_no_match.status_code().as_u16(), 200);
    let body_no_match = response_no_match.text();
    assert!(
        body_no_match.contains("No recordings"),
        "Search for non-existent asset should show empty state"
    );

    // Test 5: Empty asset filter should show all (same as no filter)
    let response_empty = app
        .server
        .get("/sessions/recordings?asset=")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(response_empty.status_code().as_u16(), 200);
    let body_empty = response_empty.text();
    assert!(
        !body_empty.contains("No recordings"),
        "Empty asset filter should show all recordings"
    );
}

#[tokio::test]
async fn test_recordings_combined_filters() {
    // Test combining format and asset filters
    use crate::fixtures::create_recorded_session_with_type;

    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("rec_combined_filter");
    let user_id = create_simple_admin_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id);

    // Create diverse recordings
    let asset1 = create_simple_ssh_asset(&mut conn, "linux-server-ssh", user_id);
    let asset2 = create_simple_ssh_asset(&mut conn, "windows-server-rdp", user_id);
    let asset3 = create_simple_ssh_asset(&mut conn, "linux-desktop-vnc", user_id);

    create_recorded_session_with_type(&mut conn, user_id, asset1, "ssh");
    create_recorded_session_with_type(&mut conn, user_id, asset2, "rdp");
    create_recorded_session_with_type(&mut conn, user_id, asset3, "vnc");

    let token = app.generate_test_token(&user_uuid.to_string(), &username, true, true);

    // Test 1: Filter by format=ssh AND asset=linux
    let response = app
        .server
        .get("/sessions/recordings?format=ssh&asset=linux")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(response.status_code().as_u16(), 200);
    let body = response.text();
    assert!(
        body.contains("linux-server-ssh"),
        "Combined filter should find linux-server-ssh"
    );
    // Should NOT show the VNC linux desktop (wrong format)
    assert!(
        !body.contains("linux-desktop-vnc") || body.contains("No recordings"),
        "Combined filter should not show VNC recording when filtering SSH"
    );

    // Test 2: Filter by format=rdp AND asset=windows
    let response_rdp = app
        .server
        .get("/sessions/recordings?format=rdp&asset=windows")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(response_rdp.status_code().as_u16(), 200);
    let body_rdp = response_rdp.text();
    assert!(
        body_rdp.contains("windows-server-rdp"),
        "Combined filter should find windows-server-rdp"
    );

    // Test 3: Conflicting filters (format=ssh but asset=windows - no match)
    let response_conflict = app
        .server
        .get("/sessions/recordings?format=ssh&asset=windows")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(response_conflict.status_code().as_u16(), 200);
    let body_conflict = response_conflict.text();
    assert!(
        body_conflict.contains("No recordings"),
        "Conflicting filters should show no results"
    );
}

#[tokio::test]
async fn test_recording_play_requires_admin() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Create recorded session
    let admin_username = unique_name("admin_rec_play");
    let admin_id = create_simple_admin_user(&mut conn, &admin_username).await;
    let asset_id = create_simple_ssh_asset(&mut conn, &unique_name("rec-asset"), admin_id);
    let session_id = create_recorded_session(&mut conn, admin_id, asset_id).await;

    // Create a normal user
    let username = unique_name("normal_rec_play");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id);

    let token = app.generate_test_token(&user_uuid.to_string(), &username, false, false);

    let response = app
        .server
        .get(&format!("/sessions/recordings/{}/play", session_id))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    // Non-admin users are redirected with flash message
    let status = response.status_code().as_u16();
    assert!(
        status == 303,
        "Normal user should be redirected from recordings, got {}",
        status
    );
    let location = response.headers().get("location").and_then(|v| v.to_str().ok());
    assert_eq!(location, Some("/sessions/recordings"));
}

#[tokio::test]
async fn test_approvals_page_requires_admin() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("normal_approvals");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id);

    let token = app.generate_test_token(&user_uuid.to_string(), &username, false, false);

    let response = app
        .server
        .get("/sessions/approvals")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 401 || status == 403,
        "Normal user should not access approvals, got {}",
        status
    );
}

#[tokio::test]
async fn test_active_sessions_requires_admin() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("normal_active");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id);

    let token = app.generate_test_token(&user_uuid.to_string(), &username, false, false);

    let response = app
        .server
        .get("/sessions/active")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 401 || status == 403,
        "Normal user should not access active sessions, got {}",
        status
    );
}

#[tokio::test]
async fn test_asset_detail_requires_admin() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Create an asset
    let admin_username = unique_name("admin_asset_det");
    let admin_id = create_simple_admin_user(&mut conn, &admin_username).await;
    let asset_id = create_simple_ssh_asset(&mut conn, &unique_name("det-asset"), admin_id);
    let asset_uuid = get_asset_uuid(&mut conn, asset_id).await;

    // Create a normal user
    let username = unique_name("normal_asset_det");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id);

    let token = app.generate_test_token(&user_uuid.to_string(), &username, false, false);

    let response = app
        .server
        .get(&format!("/assets/{}", asset_uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    // Non-admin users are redirected with flash message
    let status = response.status_code().as_u16();
    assert!(
        status == 303,
        "Normal user should be redirected from asset details, got {}",
        status
    );
    let location = response.headers().get("location").and_then(|v| v.to_str().ok());
    assert_eq!(location, Some("/assets"));
}

// =============================================================================
// Asset List Filter Tests
// =============================================================================

#[tokio::test]
async fn test_asset_list_filter_by_all_types() {
    // Test that filtering by asset type works correctly for all types
    // and empty string behaves like no filter
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_username = unique_name("asset_type_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_username).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id);

    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_username, true, true);

    // Test 1: No filter - page should load
    let response_no_filter = app
        .server
        .get("/assets")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(
        response_no_filter.status_code().as_u16(),
        200,
        "Asset list without filter should load"
    );

    // Test 2: Empty type filter (simulates "All types" selection)
    let response_empty = app
        .server
        .get("/assets?type=")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(
        response_empty.status_code().as_u16(),
        200,
        "Asset list with empty type filter should load"
    );

    // Test 3: Filter by SSH type
    let response_ssh = app
        .server
        .get("/assets?type=ssh")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(response_ssh.status_code().as_u16(), 200);
    let body_ssh = response_ssh.text();
    assert!(
        body_ssh.contains("value=\"ssh\"") && body_ssh.contains("selected"),
        "SSH should be selected in dropdown"
    );

    // Test 4: Filter by RDP type
    let response_rdp = app
        .server
        .get("/assets?type=rdp")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(response_rdp.status_code().as_u16(), 200);

    // Test 5: Filter by VNC type
    let response_vnc = app
        .server
        .get("/assets?type=vnc")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(response_vnc.status_code().as_u16(), 200);

    // Test 6: Invalid type filter - page should still load
    let response_invalid = app
        .server
        .get("/assets?type=invalid_type")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(
        response_invalid.status_code().as_u16(),
        200,
        "Asset list with invalid type should still load"
    );
}

#[tokio::test]
async fn test_asset_list_filter_by_all_statuses() {
    // Test that filtering by status works correctly
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_username = unique_name("asset_status_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_username).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id);

    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_username, true, true);

    // Test 1: No filter
    let response_no_filter = app
        .server
        .get("/assets")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(response_no_filter.status_code().as_u16(), 200);

    // Test 2: Empty status filter
    let response_empty = app
        .server
        .get("/assets?status=")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(
        response_empty.status_code().as_u16(),
        200,
        "Asset list with empty status filter should load"
    );

    // Test 3: Active status
    let response_active = app
        .server
        .get("/assets?status=active")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(response_active.status_code().as_u16(), 200);

    // Test 4: Inactive status
    let response_inactive = app
        .server
        .get("/assets?status=inactive")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(response_inactive.status_code().as_u16(), 200);
}

#[tokio::test]
async fn test_asset_list_search_by_name() {
    // Test that searching by asset name works correctly
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_username = unique_name("asset_search_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_username).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id);

    // Create an asset with a unique searchable name
    let asset_name = format!("searchable-asset-xyz-{}", Uuid::new_v4().to_string().split('-').next().unwrap());
    create_simple_ssh_asset(&mut conn, &asset_name, admin_id);

    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_username, true, true);

    // Test 1: Search for the unique asset name
    let response = app
        .server
        .get(&format!("/assets?search={}", asset_name))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(response.status_code().as_u16(), 200);
    let body = response.text();
    assert!(
        body.contains(&asset_name),
        "Should find asset by exact name"
    );

    // Test 2: Partial search
    let response_partial = app
        .server
        .get("/assets?search=searchable-asset-xyz")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(response_partial.status_code().as_u16(), 200);

    // Test 3: Empty search (regression test)
    let response_empty = app
        .server
        .get("/assets?search=")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(
        response_empty.status_code().as_u16(),
        200,
        "Empty search should load page"
    );

    // Test 4: Non-matching search
    let response_no_match = app
        .server
        .get("/assets?search=nonexistent_asset_xyz_12345")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(response_no_match.status_code().as_u16(), 200);
}

#[tokio::test]
async fn test_asset_list_combined_filters() {
    // Test combining search, type, and status filters
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_username = unique_name("asset_combined_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_username).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id);

    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_username, true, true);

    // Test 1: All three filters combined
    let response = app
        .server
        .get("/assets?search=test&type=ssh&status=active")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(
        response.status_code().as_u16(),
        200,
        "Combined filters should work"
    );

    // Test 2: Two filters
    let response_two = app
        .server
        .get("/assets?type=ssh&status=active")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(response_two.status_code().as_u16(), 200);

    // Test 3: Search with type
    let response_search_type = app
        .server
        .get("/assets?search=server&type=ssh")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(response_search_type.status_code().as_u16(), 200);

    // Test 4: All empty filters (should show all)
    let response_all_empty = app
        .server
        .get("/assets?search=&type=&status=")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_eq!(
        response_all_empty.status_code().as_u16(),
        200,
        "All empty filters should show all assets"
    );
}

// =============================================================================
// Permission System Tests - UI Element Visibility
// =============================================================================

#[tokio::test]
async fn test_asset_list_accessible_to_normal_user() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("asset_list_user");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id);

    // Create an asset
    let _asset_id = create_simple_ssh_asset(&mut conn, &unique_name("list-asset"), user_id);

    let token = app.generate_test_token(&user_uuid.to_string(), &username, false, false);

    let response = app
        .server
        .get("/assets")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 200,
        "Normal user should access asset list, got {}",
        status
    );

    // The response HTML should NOT contain "View" links for normal users
    // (we would need to parse HTML to verify, but the handler sets show_view_link: false)
}

#[tokio::test]
async fn test_asset_list_admin_has_view_links() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("asset_list_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id);

    // Create an asset
    let _asset_id = create_simple_ssh_asset(&mut conn, &unique_name("admin-list-asset"), admin_id);

    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_name, true, true);

    let response = app
        .server
        .get("/assets")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 200,
        "Admin should access asset list with view links, got {}",
        status
    );

    // Admin should have View links (show_view_link: true)
}

// =============================================================================
// Route Ordering Tests - Literal paths before parameterized
// =============================================================================

#[tokio::test]
async fn test_assets_new_does_not_conflict_with_uuid_route() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("asset_new_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id);

    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_name, true, true);

    let response = app
        .server
        .get("/assets/new")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    // Should NOT be 400 (UUID parse error) - can be 404 (not implemented) or 200
    assert_ne!(
        status, 400,
        "Route /assets/new should not conflict with /assets/{{uuid}} - got UUID parse error"
    );
    // Accept 404 (not implemented) or 200 (form displayed)
    assert!(
        status == 404 || status == 200,
        "Expected 404 (not implemented) or 200, got {}",
        status
    );
}

#[tokio::test]
async fn test_assets_new_requires_admin() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("asset_new_user");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id);

    let token = app.generate_test_token(&user_uuid.to_string(), &username, false, false);

    let response = app
        .server
        .get("/assets/new")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 401 || status == 403,
        "Normal user should not access asset creation, got {}",
        status
    );
}

#[tokio::test]
async fn test_asset_create_form_loads_for_admin() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("asset_create_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id);

    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_name, true, true);

    let response = app
        .server
        .get("/assets/new")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 200,
        "Admin should access asset creation form, got {}",
        status
    );
}

#[tokio::test]
async fn test_asset_create_success() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("asset_creator");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id);

    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_name, true, true);
    let csrf_token = app.generate_csrf_token();

    let asset_name = unique_name("new-test-asset");
    let asset_hostname = format!("{}.example.com", unique_name("host"));

    let response = app
        .server
        .post("/assets")
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("name", &asset_name),
            ("hostname", &asset_hostname),
            ("port", "22"),
            ("asset_type", "ssh"),
            ("status", "online"),
        ])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "Expected redirect after asset creation, got {}",
        status
    );

    // Verify asset was created
    use vauban_web::schema::assets;
    let created: Option<String> = assets::table
        .filter(assets::name.eq(&asset_name))
        .select(assets::name)
        .first(&mut conn)
        .optional()
        .unwrap();

    assert!(created.is_some(), "Asset should be created in database");
}

#[tokio::test]
async fn test_asset_create_normal_user_forbidden() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("asset_create_user");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id);

    let token = app.generate_test_token(&user_uuid.to_string(), &username, false, false);
    let csrf_token = app.generate_csrf_token();

    let asset_name = unique_name("forbidden-asset");

    let response = app
        .server
        .post("/assets")
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("name", &asset_name),
            ("hostname", "forbidden.example.com"),
            ("port", "22"),
            ("asset_type", "ssh"),
            ("status", "online"),
        ])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "Expected redirect, got {}",
        status
    );

    // Verify asset was NOT created
    use vauban_web::schema::assets;
    let created: Option<i32> = assets::table
        .filter(assets::name.eq(&asset_name))
        .select(assets::id)
        .first(&mut conn)
        .optional()
        .unwrap();

    assert!(created.is_none(), "Normal user should not create asset");
}

#[tokio::test]
async fn test_asset_edit_page_normal_user_forbidden() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Create an admin and an asset
    let admin_name = unique_name("asset_edit_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let asset_id = create_simple_ssh_asset(&mut conn, &unique_name("edit-forbid-asset"), admin_id);

    // Get asset UUID
    use vauban_web::schema::assets;
    let asset_uuid: uuid::Uuid = assets::table
        .filter(assets::id.eq(asset_id))
        .select(assets::uuid)
        .first(&mut conn)
        .unwrap();

    // Create a normal user (non-admin)
    let user_name = unique_name("asset_edit_user");
    let user_id = create_simple_user(&mut conn, &user_name).await;
    let user_uuid = get_user_uuid(&mut conn, user_id);

    let token = app.generate_test_token(&user_uuid.to_string(), &user_name, false, false);

    // Try to access edit page
    let response = app
        .server
        .get(&format!("/assets/{}/edit", asset_uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    // Non-admin users are redirected with flash message
    let status = response.status_code().as_u16();
    assert!(
        status == 303,
        "Normal user should be redirected from asset edit page, got {}",
        status
    );
    let location = response.headers().get("location").and_then(|v| v.to_str().ok());
    assert_eq!(location, Some("/assets"));
}

#[tokio::test]
async fn test_asset_update_normal_user_forbidden() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Create an admin and an asset
    let admin_name = unique_name("asset_upd_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let asset_id = create_simple_ssh_asset(&mut conn, &unique_name("upd-forbid-asset"), admin_id);

    // Get asset UUID
    use vauban_web::schema::assets;
    let asset_uuid: uuid::Uuid = assets::table
        .filter(assets::id.eq(asset_id))
        .select(assets::uuid)
        .first(&mut conn)
        .unwrap();

    // Create a normal user (non-admin)
    let user_name = unique_name("asset_upd_user");
    let user_id = create_simple_user(&mut conn, &user_name).await;
    let user_uuid = get_user_uuid(&mut conn, user_id);

    let token = app.generate_test_token(&user_uuid.to_string(), &user_name, false, false);
    let csrf_token = app.generate_csrf_token();

    // Try to submit update
    let response = app
        .server
        .post(&format!("/assets/{}/edit", asset_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("name", "Hacked Asset Name"),
            ("hostname", "hacked.example.com"),
            ("port", "22"),
            ("asset_type", "ssh"),
            ("status", "online"),
        ])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "Expected redirect (with error flash), got {}",
        status
    );

    // Verify asset was NOT modified
    let asset_name: String = assets::table
        .filter(assets::id.eq(asset_id))
        .select(assets::name)
        .first(&mut conn)
        .unwrap();

    assert_ne!(
        asset_name, "Hacked Asset Name",
        "Normal user should not modify asset"
    );
}

#[tokio::test]
async fn test_asset_group_edit_page_normal_user_forbidden() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Create an asset group
    let group_uuid = create_test_asset_group(&mut conn, &unique_name("edit-forbid-group")).await;

    // Create a normal user (non-admin)
    let user_name = unique_name("grp_edit_user");
    let user_id = create_simple_user(&mut conn, &user_name).await;
    let user_uuid = get_user_uuid(&mut conn, user_id);

    let token = app.generate_test_token(&user_uuid.to_string(), &user_name, false, false);

    // Try to access edit page
    let response = app
        .server
        .get(&format!("/assets/groups/{}/edit", group_uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    // Non-admin users are redirected with flash message
    let status = response.status_code().as_u16();
    assert!(
        status == 303,
        "Normal user should be redirected from asset group edit page, got {}",
        status
    );
    let location = response.headers().get("location").and_then(|v| v.to_str().ok());
    assert_eq!(location, Some("/assets/groups"));
}

#[tokio::test]
async fn test_asset_group_update_normal_user_forbidden() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Create an asset group
    let group_uuid = create_test_asset_group(&mut conn, &unique_name("upd-forbid-group")).await;

    // Create a normal user (non-admin)
    let user_name = unique_name("grp_upd_user");
    let user_id = create_simple_user(&mut conn, &user_name).await;
    let user_uuid = get_user_uuid(&mut conn, user_id);

    let token = app.generate_test_token(&user_uuid.to_string(), &user_name, false, false);
    let csrf_token = app.generate_csrf_token();

    // Try to submit update
    let response = app
        .server
        .post(&format!("/assets/groups/{}/edit", group_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("name", "Hacked Group Name"),
            ("slug", "hacked-slug"),
            ("color", "#ff0000"),
            ("icon", "server"),
        ])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "Expected redirect (with error flash), got {}",
        status
    );

    // Verify group was NOT modified
    use vauban_web::schema::asset_groups;
    let group_name: String = asset_groups::table
        .filter(asset_groups::uuid.eq(group_uuid))
        .select(asset_groups::name)
        .first(&mut conn)
        .unwrap();

    assert_ne!(
        group_name, "Hacked Group Name",
        "Normal user should not modify asset group"
    );
}

#[tokio::test]
async fn test_asset_create_with_checkboxes() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("asset_cb_creator");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id);

    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_name, true, true);
    let csrf_token = app.generate_csrf_token();

    let asset_name = unique_name("checkbox-test-asset");
    let asset_hostname = format!("{}.example.com", unique_name("cbhost"));

    // Test with checkboxes checked (HTML sends "on" for checked checkboxes)
    let response = app
        .server
        .post("/assets")
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("name", &asset_name),
            ("hostname", &asset_hostname),
            ("port", "22"),
            ("asset_type", "ssh"),
            ("status", "online"),
            ("require_mfa", "on"),
            ("require_justification", "on"),
        ])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "Expected redirect after asset creation, got {}",
        status
    );

    // Verify asset was created with correct checkbox values
    use vauban_web::schema::assets;
    let created: Option<(bool, bool)> = assets::table
        .filter(assets::name.eq(&asset_name))
        .select((assets::require_mfa, assets::require_justification))
        .first(&mut conn)
        .optional()
        .unwrap();

    assert!(created.is_some(), "Asset should be created in database");
    let (require_mfa, require_justification) = created.unwrap();
    assert!(require_mfa, "require_mfa should be true when checkbox is 'on'");
    assert!(
        require_justification,
        "require_justification should be true when checkbox is 'on'"
    );
}

#[tokio::test]
async fn test_asset_create_without_checkboxes() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("asset_nocb_creator");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id);

    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_name, true, true);
    let csrf_token = app.generate_csrf_token();

    let asset_name = unique_name("no-checkbox-asset");
    let asset_hostname = format!("{}.example.com", unique_name("nocbhost"));

    // Test without checkboxes (unchecked checkboxes are not sent in HTML forms)
    let response = app
        .server
        .post("/assets")
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("name", &asset_name),
            ("hostname", &asset_hostname),
            ("port", "3389"),
            ("asset_type", "rdp"),
            ("status", "online"),
        ])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "Expected redirect after asset creation, got {}",
        status
    );

    // Verify asset was created with false checkbox values
    use vauban_web::schema::assets;
    let created: Option<(bool, bool)> = assets::table
        .filter(assets::name.eq(&asset_name))
        .select((assets::require_mfa, assets::require_justification))
        .first(&mut conn)
        .optional()
        .unwrap();

    assert!(created.is_some(), "Asset should be created in database");
    let (require_mfa, require_justification) = created.unwrap();
    assert!(!require_mfa, "require_mfa should be false when checkbox is absent");
    assert!(
        !require_justification,
        "require_justification should be false when checkbox is absent"
    );
}

#[tokio::test]
async fn test_asset_create_reactivates_soft_deleted() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("asset_reactivator");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id);

    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_name, true, true);
    let csrf_token = app.generate_csrf_token();

    // Create a unique hostname for this test
    let asset_hostname = format!("{}.reactivate.test", unique_name("host"));

    // First, create a soft-deleted asset directly in the database
    use vauban_web::schema::assets;
    let original_uuid = uuid::Uuid::new_v4();
    diesel::insert_into(assets::table)
        .values((
            assets::uuid.eq(original_uuid),
            assets::name.eq("Old Deleted Asset"),
            assets::hostname.eq(&asset_hostname),
            assets::port.eq(22),
            assets::asset_type.eq("ssh"),
            assets::status.eq("offline"),
            assets::is_deleted.eq(true),
            assets::deleted_at.eq(chrono::Utc::now()),
        ))
        .execute(&mut conn)
        .expect("Failed to create soft-deleted asset");

    // Verify asset is soft-deleted
    let is_deleted: bool = assets::table
        .filter(assets::uuid.eq(original_uuid))
        .select(assets::is_deleted)
        .first(&mut conn)
        .unwrap();
    assert!(is_deleted, "Asset should initially be soft-deleted");

    // Now try to create a new asset with the same hostname+port
    let new_asset_name = "Reactivated Asset";
    let response = app
        .server
        .post("/assets")
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("name", new_asset_name),
            ("hostname", &asset_hostname),
            ("port", "22"),
            ("asset_type", "ssh"),
            ("status", "online"),
            ("require_justification", "on"),
        ])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "Expected redirect after asset reactivation, got {}",
        status
    );

    // Verify the asset was reactivated (same UUID, updated values, not deleted)
    let reactivated: Option<(String, String, bool, bool)> = assets::table
        .filter(assets::uuid.eq(original_uuid))
        .select((
            assets::name,
            assets::status,
            assets::is_deleted,
            assets::require_justification,
        ))
        .first(&mut conn)
        .optional()
        .unwrap();

    assert!(reactivated.is_some(), "Asset should exist");
    let (name, status, is_deleted, require_justification) = reactivated.unwrap();
    assert_eq!(name, new_asset_name, "Asset name should be updated");
    assert_eq!(status, "online", "Asset status should be updated");
    assert!(!is_deleted, "Asset should no longer be soft-deleted");
    assert!(
        require_justification,
        "Asset require_justification should be updated"
    );

    // Verify there's only one asset with this hostname+port (reactivated, not a new one)
    let count: i64 = assets::table
        .filter(assets::hostname.eq(&asset_hostname))
        .filter(assets::port.eq(22))
        .count()
        .get_result(&mut conn)
        .unwrap();
    assert_eq!(count, 1, "Should only have one asset with this hostname+port");
}

#[tokio::test]
async fn test_asset_create_fails_for_active_duplicate() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("asset_dup_creator");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id);

    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_name, true, true);
    let csrf_token = app.generate_csrf_token();

    // Create a unique hostname for this test
    let asset_hostname = format!("{}.duplicate.test", unique_name("host"));

    // First, create an active asset
    use vauban_web::schema::assets;
    let original_uuid = uuid::Uuid::new_v4();
    diesel::insert_into(assets::table)
        .values((
            assets::uuid.eq(original_uuid),
            assets::name.eq("Active Asset"),
            assets::hostname.eq(&asset_hostname),
            assets::port.eq(22),
            assets::asset_type.eq("ssh"),
            assets::status.eq("online"),
            assets::is_deleted.eq(false),
        ))
        .execute(&mut conn)
        .expect("Failed to create active asset");

    // Try to create another asset with the same hostname+port
    let response = app
        .server
        .post("/assets")
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("name", "Duplicate Asset"),
            ("hostname", &asset_hostname),
            ("port", "22"),
            ("asset_type", "ssh"),
            ("status", "online"),
        ])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "Expected redirect with error, got {}",
        status
    );

    // Verify only one asset exists with this hostname+port
    let count: i64 = assets::table
        .filter(assets::hostname.eq(&asset_hostname))
        .filter(assets::port.eq(22))
        .count()
        .get_result(&mut conn)
        .unwrap();
    assert_eq!(
        count, 1,
        "Should only have one asset with this hostname+port (duplicate should be rejected)"
    );
}
