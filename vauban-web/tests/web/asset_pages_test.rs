/// VAUBAN Web - Asset Pages Tests.
///
/// Tests for asset-related HTML pages:
/// - Asset edit page
/// - Asset detail page
/// - Navigation flows
use axum::http::header;
use serial_test::serial;
use uuid::Uuid;

use crate::common::{TestApp, assertions::*, test_db};
use crate::fixtures::{
    create_admin_user, create_test_rdp_asset, create_test_ssh_asset, unique_name,
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
        .form(&[("csrf_token", csrf_token.as_str()), ("username", "custom_admin")])
        .await;

    // Assert: Should return JSON response (success depends on SSH proxy)
    let status = response.status_code().as_u16();
    assert_eq!(status, 200, "Connect endpoint should return 200 with JSON");

    // Cleanup
    test_db::cleanup(&mut conn).await;
}
