/// VAUBAN Web - Asset Pages Tests.
///
/// Tests for asset-related HTML pages:
/// - Asset edit page
/// - Asset detail page
/// - Navigation flows
/// - Asset list pagination
use axum::http::header;
use axum::http::header::COOKIE;
use serial_test::serial;
use uuid::Uuid;

use crate::common::{TestApp, assertions::*, test_db};
use crate::fixtures::{
    add_user_to_vauban_group, create_admin_user, create_approved_session,
    create_simple_admin_user, create_simple_ssh_asset, create_simple_user,
    create_test_access_rule_with_constraints, create_test_asset_group, create_test_asset_in_group,
    create_test_rdp_asset, create_test_ssh_asset, create_test_vauban_group, unique_name,
};

// =============================================================================
// Asset Edit Page Tests
// =============================================================================

/// Test asset edit page loads with authentication.
#[tokio::test]
#[serial]
async fn test_asset_edit_page_authenticated() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Setup: create admin and asset
    let admin_name = unique_name("test_admin_edit_page");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let asset = create_test_ssh_asset(&mut conn, &unique_name("test-edit-page-asset")).await;

    // Execute: GET /assets/{uuid}/edit
    let response = app
        .server
        .get(&format!("/assets/{}/edit", asset.asset.uuid))
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;

    // Assert: 200 OK
    assert_status(&response, 200);

    // Verify it contains edit form elements
    let body = response.text();
    assert!(
        body.contains("Edit Asset") || body.contains("Save Changes"),
        "Edit page should contain form elements"
    );
    assert!(
        body.contains(&asset.asset.name),
        "Edit page should contain asset name"
    );

    // Cleanup
    test_db::cleanup(&mut conn).await;
}

/// Test asset edit page requires authentication.
#[tokio::test]
#[serial]
async fn test_asset_edit_page_unauthenticated() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Setup: create asset
    let asset = create_test_ssh_asset(&mut conn, &unique_name("test-edit-unauth-asset")).await;

    // Execute: GET /assets/{uuid}/edit without auth
    let response = app
        .server
        .get(&format!("/assets/{}/edit", asset.asset.uuid))
        .await;

    // Assert: 401 Unauthorized or 302 Redirect to login
    let status = response.status_code();
    assert!(
        status == 401 || status == 302 || status == 303,
        "Unauthenticated request should return 401 or redirect, got {}",
        status
    );

    // Cleanup
    test_db::cleanup(&mut conn).await;
}

/// Test asset edit page with non-existent asset redirects to list.
#[tokio::test]
#[serial]
async fn test_asset_edit_page_not_found() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Setup: create admin
    let admin_name = unique_name("test_admin_edit_404");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let fake_uuid = Uuid::new_v4();

    // Execute: GET /assets/{fake_uuid}/edit
    let response = app
        .server
        .get(&format!("/assets/{}/edit", fake_uuid))
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;

    // Assert: redirects to asset list with flash message
    assert_status(&response, 303);
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok());
    assert_eq!(location, Some("/assets"));

    // Cleanup
    test_db::cleanup(&mut conn).await;
}

/// Test asset edit page with RDP asset.
#[tokio::test]
#[serial]
async fn test_asset_edit_page_rdp_asset() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Setup: create admin and RDP asset
    let admin_name = unique_name("test_admin_edit_rdp");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let asset = create_test_rdp_asset(&mut conn, &unique_name("test-edit-rdp-asset")).await;

    // Execute: GET /assets/{uuid}/edit
    let response = app
        .server
        .get(&format!("/assets/{}/edit", asset.asset.uuid))
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;

    // Assert: 200 OK
    assert_status(&response, 200);

    // Verify it shows RDP type
    let body = response.text();
    assert!(
        body.contains("RDP") || body.contains("rdp"),
        "Edit page should show RDP asset type"
    );

    // Cleanup
    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// Asset Navigation Flow Tests
// =============================================================================

/// Test the complete edit -> save -> redirect to detail flow.
/// This test ensures the HX-Redirect URL matches a valid route.
#[tokio::test]
#[serial]
async fn test_asset_edit_to_detail_navigation_flow() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Setup
    let admin_name = unique_name("test_admin_nav_flow");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let asset = create_test_ssh_asset(&mut conn, &unique_name("test-nav-flow-asset")).await;

    // Step 1: Verify edit page loads correctly
    let edit_response = app
        .server
        .get(&format!("/assets/{}/edit", asset.asset.uuid))
        .add_header(header::COOKIE, format!("access_token={}", admin.token))
        .await;
    assert_status(&edit_response, 200);

    // Step 2: Submit update via HTMX (with HX-Request header)
    let update_response = app
        .server
        .put(&format!("/api/v1/assets/{}", asset.asset.uuid))
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .add_header("HX-Request", "true")
        .json(&serde_json::json!({
            "name": unique_name("updated-nav-test")
        }))
        .await;

    // Verify 200 OK and HX-Redirect header is set
    assert_status(&update_response, 200);
    let redirect_header = update_response
        .headers()
        .get("HX-Redirect")
        .expect("HX-Redirect header should be present for HTMX requests");
    let redirect_url = redirect_header.to_str().expect("Valid header value");
    assert!(
        redirect_url.starts_with("/assets/"),
        "Redirect URL should point to asset detail page, got: {}",
        redirect_url
    );

    // Step 3: Follow the redirect URL - this must succeed (not 400/404)
    let detail_response = app
        .server
        .get(redirect_url)
        .add_header(header::COOKIE, format!("access_token={}", admin.token))
        .await;

    let status = detail_response.status_code().as_u16();
    assert!(
        status == 200 || status == 303,
        "Asset detail page at '{}' should load successfully, got status {}",
        redirect_url,
        status
    );

    // Cleanup
    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// Asset Detail Page Tests
// =============================================================================

/// Test that asset detail page accepts UUID in URL (not integer ID).
/// This ensures URL format consistency across the application.
#[tokio::test]
#[serial]
async fn test_asset_detail_accepts_uuid_not_integer_id() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Setup
    let admin_name = unique_name("test_admin_uuid_route");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let asset = create_test_ssh_asset(&mut conn, &unique_name("test-uuid-route-asset")).await;

    // UUID-based URL should work
    let uuid_response = app
        .server
        .get(&format!("/assets/{}", asset.asset.uuid))
        .add_header(header::COOKIE, format!("access_token={}", admin.token))
        .await;

    let status = uuid_response.status_code().as_u16();
    assert!(
        status == 200 || status == 303,
        "Asset detail page should accept UUID in URL, got status {}",
        status
    );

    // Integer ID should NOT work - redirects to /assets with error message
    let id_response = app
        .server
        .get("/assets/123")
        .add_header(header::COOKIE, format!("access_token={}", admin.token))
        .await;

    // Should redirect gracefully instead of returning raw error
    assert_status(&id_response, 303);
    let location = id_response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok());
    assert_eq!(
        location,
        Some("/assets"),
        "Invalid UUID should redirect to /assets"
    );

    // Cleanup
    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// SSH Connection Tests
// =============================================================================

/// Test SSH connect endpoint returns error when SSH proxy is not available.
/// This is the expected behavior in test environment without vauban-proxy-ssh.
#[tokio::test]
#[serial]
async fn test_ssh_connect_without_proxy() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Setup: create admin and SSH asset
    let admin_name = unique_name("test_admin_ssh_connect");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let asset = create_test_ssh_asset(&mut conn, &unique_name("test-ssh-connect-asset")).await;

    // Generate valid CSRF token for double-submit
    let csrf_token = app.generate_csrf_token();

    // Execute: POST /assets/{uuid}/connect
    let response = app
        .server
        .post(&format!("/assets/{}/connect", asset.asset.uuid))
        .add_header(
            header::COOKIE,
            format!("access_token={}; __vauban_csrf={}", admin.token, csrf_token),
        )
        .form(&[("csrf_token", &csrf_token)])
        .await;

    // Assert: Should return JSON with error (SSH proxy not available in tests)
    let status = response.status_code().as_u16();
    assert_eq!(status, 200, "Connect endpoint should return 200 with JSON");

    let body = response.text();
    assert!(
        body.contains("\"success\":false") || body.contains("SSH proxy not available"),
        "Response should indicate SSH proxy unavailable: {}",
        body
    );

    // Cleanup
    test_db::cleanup(&mut conn).await;
}

/// Test SSH connect endpoint requires authentication.
#[tokio::test]
#[serial]
async fn test_ssh_connect_requires_auth() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Setup: create SSH asset
    let asset = create_test_ssh_asset(&mut conn, &unique_name("test-ssh-unauth-asset")).await;

    // Execute: POST /assets/{uuid}/connect without auth
    let response = app
        .server
        .post(&format!("/assets/{}/connect", asset.asset.uuid))
        .form(&[("csrf_token", "test-csrf")])
        .await;

    // Assert: 401 Unauthorized or redirect to login
    let status = response.status_code().as_u16();
    assert!(
        status == 401 || status == 302 || status == 303,
        "Unauthenticated connect should return 401 or redirect, got {}",
        status
    );

    // Cleanup
    test_db::cleanup(&mut conn).await;
}

/// Test SSH connect endpoint with invalid UUID returns error.
#[tokio::test]
#[serial]
async fn test_ssh_connect_invalid_uuid() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Setup: create admin
    let admin_name = unique_name("test_admin_ssh_invalid");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    // Generate valid CSRF token for double-submit
    let csrf_token = app.generate_csrf_token();

    // Execute: POST /assets/invalid-uuid/connect
    let response = app
        .server
        .post("/assets/not-a-valid-uuid/connect")
        .add_header(
            header::COOKIE,
            format!("access_token={}; __vauban_csrf={}", admin.token, csrf_token),
        )
        .form(&[("csrf_token", &csrf_token)])
        .await;

    // Assert: Should return JSON with error
    let status = response.status_code().as_u16();
    assert_eq!(status, 200, "Connect endpoint should return 200 with JSON");

    let body = response.text();
    assert!(
        body.contains("\"success\":false") && body.contains("Invalid asset identifier"),
        "Response should indicate invalid UUID: {}",
        body
    );

    // Cleanup
    test_db::cleanup(&mut conn).await;
}

/// Test SSH connect endpoint with non-existent asset returns error.
#[tokio::test]
#[serial]
async fn test_ssh_connect_asset_not_found() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Setup: create admin
    let admin_name = unique_name("test_admin_ssh_404");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let fake_uuid = Uuid::new_v4();

    // Generate valid CSRF token for double-submit
    let csrf_token = app.generate_csrf_token();

    // Execute: POST /assets/{fake_uuid}/connect
    let response = app
        .server
        .post(&format!("/assets/{}/connect", fake_uuid))
        .add_header(
            header::COOKIE,
            format!("access_token={}; __vauban_csrf={}", admin.token, csrf_token),
        )
        .form(&[("csrf_token", &csrf_token)])
        .await;

    // Assert: Should return JSON with "not found" error
    let status = response.status_code().as_u16();
    assert_eq!(status, 200, "Connect endpoint should return 200 with JSON");

    let body = response.text();
    // May return "SSH proxy not available" or "Asset not found" depending on check order
    assert!(
        body.contains("\"success\":false"),
        "Response should indicate failure: {}",
        body
    );

    // Cleanup
    test_db::cleanup(&mut conn).await;
}

/// Test SSH connect endpoint with RDP asset type returns error.
#[tokio::test]
#[serial]
async fn test_ssh_connect_wrong_asset_type() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Setup: create admin and RDP asset (not SSH)
    let admin_name = unique_name("test_admin_ssh_rdp");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let rdp_asset = create_test_rdp_asset(&mut conn, &unique_name("test-rdp-asset")).await;

    // Generate valid CSRF token for double-submit
    let csrf_token = app.generate_csrf_token();

    // Execute: POST /assets/{rdp_uuid}/connect (trying SSH on RDP asset)
    let response = app
        .server
        .post(&format!("/assets/{}/connect", rdp_asset.asset.uuid))
        .add_header(
            header::COOKIE,
            format!("access_token={}; __vauban_csrf={}", admin.token, csrf_token),
        )
        .form(&[("csrf_token", &csrf_token)])
        .await;

    // Assert: Should return JSON with error (depends on SSH proxy availability)
    let status = response.status_code().as_u16();
    assert_eq!(status, 200, "Connect endpoint should return 200 with JSON");

    let body = response.text();
    assert!(
        body.contains("\"success\":false"),
        "Response should indicate failure for RDP asset on SSH endpoint: {}",
        body
    );

    // Cleanup
    test_db::cleanup(&mut conn).await;
}

/// Test SSH connect endpoint with username override.
#[tokio::test]
#[serial]
async fn test_ssh_connect_with_username_override() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Setup: create admin and SSH asset
    let admin_name = unique_name("test_admin_ssh_user");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let asset = create_test_ssh_asset(&mut conn, &unique_name("test-ssh-user-asset")).await;

    // Generate valid CSRF token for double-submit
    let csrf_token = app.generate_csrf_token();

    // Execute: POST /assets/{uuid}/connect with username
    let response = app
        .server
        .post(&format!("/assets/{}/connect", asset.asset.uuid))
        .add_header(
            header::COOKIE,
            format!("access_token={}; __vauban_csrf={}", admin.token, csrf_token),
        )
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("username", "custom_admin"),
        ])
        .await;

    // Assert: Should return JSON response (success depends on SSH proxy)
    let status = response.status_code().as_u16();
    assert_eq!(status, 200, "Connect endpoint should return 200 with JSON");

    // Cleanup
    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// RDP Connect Endpoint Tests
// =============================================================================

/// Test RDP connect endpoint with RDP asset (proxy unavailable in test env).
#[tokio::test]
#[serial]
async fn test_rdp_connect_endpoint_without_proxy() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("test_admin_rdp_connect");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let rdp_asset = create_test_rdp_asset(&mut conn, &unique_name("test-rdp-connect")).await;
    let csrf_token = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!("/assets/{}/connect-rdp", rdp_asset.asset.uuid))
        .add_header(
            header::COOKIE,
            format!("access_token={}; __vauban_csrf={}", admin.token, csrf_token),
        )
        .form(&[("csrf_token", csrf_token.as_str())])
        .await;

    // Without RDP proxy, expect either:
    // - 200 with HX-Trigger error (HTMX pattern)
    // - 303 redirect (CSRF/auth middleware redirect)
    // - 408 timeout
    let status = response.status_code().as_u16();
    assert!(
        status == 200 || status == 303 || status == 408,
        "RDP connect should return 200/303/408, got {}",
        status
    );

    test_db::cleanup(&mut conn).await;
}

/// Test RDP connect endpoint with SSH asset returns error.
#[tokio::test]
#[serial]
async fn test_rdp_connect_wrong_asset_type() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("test_admin_rdp_ssh");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let ssh_asset = create_test_ssh_asset(&mut conn, &unique_name("test-ssh-for-rdp")).await;
    let csrf_token = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!("/assets/{}/connect-rdp", ssh_asset.asset.uuid))
        .add_header(
            header::COOKIE,
            format!("access_token={}; __vauban_csrf={}", admin.token, csrf_token),
        )
        .form(&[("csrf_token", csrf_token.as_str())])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 200 || status == 303 || status == 408,
        "RDP connect on SSH asset should return 200/303/408, got {}",
        status
    );

    test_db::cleanup(&mut conn).await;
}

/// Test RDP connect endpoint with nonexistent asset.
#[tokio::test]
#[serial]
async fn test_rdp_connect_nonexistent_asset() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("test_admin_rdp_404");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let csrf_token = app.generate_csrf_token();
    let fake_uuid = Uuid::new_v4();

    let response = app
        .server
        .post(&format!("/assets/{}/connect-rdp", fake_uuid))
        .add_header(
            header::COOKIE,
            format!("access_token={}; __vauban_csrf={}", admin.token, csrf_token),
        )
        .form(&[("csrf_token", csrf_token.as_str())])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 200 || status == 303 || status == 404,
        "RDP connect on nonexistent asset should return 200/303/404, got {}",
        status
    );

    test_db::cleanup(&mut conn).await;
}

/// Test RDP connect endpoint requires authentication.
#[tokio::test]
#[serial]
async fn test_rdp_connect_requires_auth() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let rdp_asset = create_test_rdp_asset(&mut conn, &unique_name("test-rdp-noauth")).await;

    let response = app
        .server
        .post(&format!("/assets/{}/connect-rdp", rdp_asset.asset.uuid))
        .form(&[("csrf_token", "invalid")])
        .await;

    // Without valid auth, expect a redirect (302/303) to login
    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303 || status == 401 || status == 403,
        "RDP connect without auth should redirect or return 4xx, got {}",
        status
    );

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// Asset List Pagination Tests
// =============================================================================

async fn get_admin_uuid(conn: &mut diesel_async::AsyncPgConnection, admin_id: i32) -> Uuid {
    use diesel::ExpressionMethods;
    use diesel::QueryDsl;
    use diesel_async::RunQueryDsl;
    use vauban_web::schema::users;
    users::table
        .filter(users::id.eq(admin_id))
        .select(users::uuid)
        .first(conn)
        .await
        .expect("admin uuid")
}

#[tokio::test]
async fn test_asset_list_page_1_default() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("pg_admin_default");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_admin_uuid(&mut conn, admin_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let response = app
        .server
        .get("/assets")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);
}

#[tokio::test]
async fn test_asset_list_pagination_with_many_assets() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("pg_admin_many");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_admin_uuid(&mut conn, admin_id).await;

    for i in 0..35 {
        let name = unique_name(&format!("pg_asset_{:03}", i));
        create_simple_ssh_asset(&mut conn, &name, admin_id).await;
    }

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let response = app
        .server
        .get("/assets")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(body.contains("Showing"), "page 1 should show pagination counter");
    assert!(body.contains("title=\"Next page\""), "page 1 should have Next button");
    assert!(body.contains("title=\"Last page\""), "page 1 should have Last button");
    assert!(!body.contains("title=\"First page\""), "page 1 should not have First button");
}

#[tokio::test]
async fn test_asset_list_page_2() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("pg_admin_p2");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_admin_uuid(&mut conn, admin_id).await;

    for i in 0..35 {
        let name = unique_name(&format!("pg2_asset_{:03}", i));
        create_simple_ssh_asset(&mut conn, &name, admin_id).await;
    }

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let response = app
        .server
        .get("/assets?page=2")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(body.contains("title=\"First page\""), "page 2 should have First button");
    assert!(body.contains("title=\"Previous page\""), "page 2 should have Previous button");
}

#[tokio::test]
async fn test_asset_list_page_999_clamps_to_last() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("pg_admin_999");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_admin_uuid(&mut conn, admin_id).await;

    for i in 0..5 {
        let name = unique_name(&format!("pg999_asset_{}", i));
        create_simple_ssh_asset(&mut conn, &name, admin_id).await;
    }

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let response = app
        .server
        .get("/assets?page=999")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);
}

#[tokio::test]
async fn test_asset_list_page_negative_defaults_to_1() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("pg_admin_neg");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_admin_uuid(&mut conn, admin_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let response = app
        .server
        .get("/assets?page=-1")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);
}

#[tokio::test]
async fn test_asset_list_page_abc_defaults_to_1() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("pg_admin_abc");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_admin_uuid(&mut conn, admin_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let response = app
        .server
        .get("/assets?page=abc")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);
}

#[tokio::test]
async fn test_asset_list_pagination_preserves_filters() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("pg_admin_filt");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_admin_uuid(&mut conn, admin_id).await;

    for i in 0..35 {
        let name = unique_name(&format!("pgf_asset_{:03}", i));
        create_simple_ssh_asset(&mut conn, &name, admin_id).await;
    }

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let response = app
        .server
        .get("/assets?search=pgf&type=ssh&status=online")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    if body.contains("Showing") {
        assert!(
            body.contains("search=pgf"),
            "pagination links should preserve search filter"
        );
        assert!(
            body.contains("type=ssh"),
            "pagination links should preserve type filter"
        );
        assert!(
            body.contains("status=online"),
            "pagination links should preserve status filter"
        );
    }
}

#[tokio::test]
async fn test_asset_list_showing_counter_accurate() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("pg_admin_cnt");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_admin_uuid(&mut conn, admin_id).await;

    let search_tag = unique_name("pgcnt");
    for i in 0..35 {
        let name = format!("{}_asset_{:03}", search_tag, i);
        create_simple_ssh_asset(&mut conn, &name, admin_id).await;
    }

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let response = app
        .server
        .get(&format!("/assets?search={}", search_tag))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(
        body.contains(">35</span>"),
        "counter should show total of 35 items"
    );
    assert!(
        body.contains(">1</span>") && body.contains(">30</span>"),
        "first page should show 1 to 30"
    );
}

// =============================================================================
// Request / Connect Button Tests
// =============================================================================

/// Helper: get the internal user ID from UUID.
async fn get_user_id(conn: &mut diesel_async::AsyncPgConnection, user_uuid: &Uuid) -> i32 {
    use diesel::ExpressionMethods;
    use diesel::QueryDsl;
    use diesel_async::RunQueryDsl;
    use vauban_web::schema::users;
    users::table
        .filter(users::uuid.eq(user_uuid))
        .select(users::id)
        .first(conn)
        .await
        .expect("user id")
}

/// Non-admin user with an approval-required rule should see "Request".
#[tokio::test]
#[serial]
async fn test_asset_button_shows_request_when_approval_required() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("btn_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;

    let user_name = unique_name("btn_user");
    let user_id = create_simple_user(&mut conn, &user_name).await;
    let user_uuid = get_admin_uuid(&mut conn, user_id).await;

    let ug_uuid = create_test_vauban_group(&mut conn, "btn_ug").await;
    add_user_to_vauban_group(&mut conn, user_id, &ug_uuid).await;

    let ag_uuid = create_test_asset_group(&mut conn, &unique_name("btn_ag")).await;
    let _asset_id = create_test_asset_in_group(&mut conn, &unique_name("btn_asset"), admin_id, &ag_uuid).await;

    create_test_access_rule_with_constraints(
        &mut conn,
        &ug_uuid,
        &ag_uuid,
        &["ssh"],
        false,
        true, // require_approval = true
        Some(900),
    )
    .await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &user_name, false, false)
        .await;

    let response = app
        .server
        .get("/assets")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(
        body.contains("Request"),
        "non-admin user with approval rule should see Request button"
    );
    assert!(
        body.contains("#request-access"),
        "Request button should link to #request-access"
    );

    test_db::cleanup(&mut conn).await;
}

/// Non-admin user WITHOUT approval-required rule should see "Connect".
#[tokio::test]
#[serial]
async fn test_asset_button_shows_connect_when_no_approval() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("btn_admin_na");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;

    let user_name = unique_name("btn_user_na");
    let user_id = create_simple_user(&mut conn, &user_name).await;
    let user_uuid = get_admin_uuid(&mut conn, user_id).await;

    let ug_uuid = create_test_vauban_group(&mut conn, "btn_ug_na").await;
    add_user_to_vauban_group(&mut conn, user_id, &ug_uuid).await;

    let ag_uuid = create_test_asset_group(&mut conn, &unique_name("btn_ag_na")).await;
    let _asset_id = create_test_asset_in_group(&mut conn, &unique_name("btn_asset_na"), admin_id, &ag_uuid).await;

    create_test_access_rule_with_constraints(
        &mut conn,
        &ug_uuid,
        &ag_uuid,
        &["ssh"],
        false,
        false, // require_approval = false
        None,
    )
    .await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &user_name, false, false)
        .await;

    let response = app
        .server
        .get("/assets")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(
        body.contains("Connect"),
        "non-admin user without approval rule should see Connect button"
    );

    test_db::cleanup(&mut conn).await;
}

/// Non-admin user with an approved session should see "Connect" even if approval is required.
#[tokio::test]
#[serial]
async fn test_asset_button_shows_connect_after_approval() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("btn_admin_ap");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;

    let user_name = unique_name("btn_user_ap");
    let user_id = create_simple_user(&mut conn, &user_name).await;
    let user_uuid = get_admin_uuid(&mut conn, user_id).await;

    let ug_uuid = create_test_vauban_group(&mut conn, "btn_ug_ap").await;
    add_user_to_vauban_group(&mut conn, user_id, &ug_uuid).await;

    let ag_uuid = create_test_asset_group(&mut conn, &unique_name("btn_ag_ap")).await;
    let asset_id = create_test_asset_in_group(&mut conn, &unique_name("btn_asset_ap"), admin_id, &ag_uuid).await;

    create_test_access_rule_with_constraints(
        &mut conn,
        &ug_uuid,
        &ag_uuid,
        &["ssh"],
        false,
        true,
        Some(3600),
    )
    .await;

    create_approved_session(&mut conn, user_id, asset_id, Some(3600)).await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &user_name, false, false)
        .await;

    let response = app
        .server
        .get("/assets")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(
        body.contains("Connect"),
        "user with approved session should see Connect, not Request"
    );

    test_db::cleanup(&mut conn).await;
}

/// Admin user should always see "Connect" even if approval rules exist.
#[tokio::test]
#[serial]
async fn test_asset_button_shows_connect_for_admin() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("btn_admin_adm");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_admin_uuid(&mut conn, admin_id).await;

    let ug_uuid = create_test_vauban_group(&mut conn, "btn_ug_adm").await;
    let ag_uuid = create_test_asset_group(&mut conn, &unique_name("btn_ag_adm")).await;
    let _asset_id = create_test_asset_in_group(&mut conn, &unique_name("btn_asset_adm"), admin_id, &ag_uuid).await;

    create_test_access_rule_with_constraints(
        &mut conn,
        &ug_uuid,
        &ag_uuid,
        &["ssh"],
        false,
        true,
        Some(900),
    )
    .await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let response = app
        .server
        .get("/assets")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(
        body.contains("Connect"),
        "admin should always see Connect button"
    );
    assert!(
        !body.contains("#request-access"),
        "admin should not see Request link"
    );

    test_db::cleanup(&mut conn).await;
}

/// The "Request" button should link to the asset detail page with #request-access.
#[tokio::test]
#[serial]
async fn test_asset_button_request_links_to_detail() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("btn_admin_lnk");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;

    let user_name = unique_name("btn_user_lnk");
    let user_id = create_simple_user(&mut conn, &user_name).await;
    let user_uuid = get_admin_uuid(&mut conn, user_id).await;

    let ug_uuid = create_test_vauban_group(&mut conn, "btn_ug_lnk").await;
    add_user_to_vauban_group(&mut conn, user_id, &ug_uuid).await;

    let ag_uuid = create_test_asset_group(&mut conn, &unique_name("btn_ag_lnk")).await;
    let _asset_id = create_test_asset_in_group(&mut conn, &unique_name("btn_asset_lnk"), admin_id, &ag_uuid).await;

    create_test_access_rule_with_constraints(
        &mut conn,
        &ug_uuid,
        &ag_uuid,
        &["ssh"],
        false,
        true,
        Some(900),
    )
    .await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &user_name, false, false)
        .await;

    let response = app
        .server
        .get("/assets")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(
        body.contains("/assets/") && body.contains("#request-access"),
        "Request button should have href to /assets/{{uuid}}#request-access"
    );

    test_db::cleanup(&mut conn).await;
}

/// The asset list page should contain the WS trigger element.
#[tokio::test]
#[serial]
async fn test_asset_list_ws_trigger_present() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("btn_admin_ws");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_admin_uuid(&mut conn, admin_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let response = app
        .server
        .get("/assets")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(
        body.contains("asset-ws-trigger"),
        "asset list should contain #asset-ws-trigger element"
    );
    assert!(
        body.contains("request_approved"),
        "WS trigger should listen for request_approved event"
    );

    test_db::cleanup(&mut conn).await;
}
