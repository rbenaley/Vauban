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
use crate::fixtures::{create_admin_user, create_test_rdp_asset, create_test_ssh_asset, unique_name};

// =============================================================================
// Asset Edit Page Tests
// =============================================================================

/// Test asset edit page loads with authentication.
#[tokio::test]
#[serial]
async fn test_asset_edit_page_authenticated() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Setup: create admin and asset
    let admin_name = unique_name("test_admin_edit_page");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name);

    let asset = create_test_ssh_asset(&mut conn, &unique_name("test-edit-page-asset"));

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
    test_db::cleanup(&mut conn);
}

/// Test asset edit page requires authentication.
#[tokio::test]
#[serial]
async fn test_asset_edit_page_unauthenticated() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Setup: create asset
    let asset = create_test_ssh_asset(&mut conn, &unique_name("test-edit-unauth-asset"));

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
    test_db::cleanup(&mut conn);
}

/// Test asset edit page with non-existent asset returns 404.
#[tokio::test]
#[serial]
async fn test_asset_edit_page_not_found() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Setup: create admin
    let admin_name = unique_name("test_admin_edit_404");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name);

    let fake_uuid = Uuid::new_v4();

    // Execute: GET /assets/{fake_uuid}/edit
    let response = app
        .server
        .get(&format!("/assets/{}/edit", fake_uuid))
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;

    // Assert: 404 Not Found
    assert_status(&response, 404);

    // Cleanup
    test_db::cleanup(&mut conn);
}

/// Test asset edit page with RDP asset.
#[tokio::test]
#[serial]
async fn test_asset_edit_page_rdp_asset() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Setup: create admin and RDP asset
    let admin_name = unique_name("test_admin_edit_rdp");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name);

    let asset = create_test_rdp_asset(&mut conn, &unique_name("test-edit-rdp-asset"));

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
    test_db::cleanup(&mut conn);
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
    let mut conn = app.get_conn();

    // Setup
    let admin_name = unique_name("test_admin_nav_flow");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name);
    let asset = create_test_ssh_asset(&mut conn, &unique_name("test-nav-flow-asset"));

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
    test_db::cleanup(&mut conn);
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
    let mut conn = app.get_conn();

    // Setup
    let admin_name = unique_name("test_admin_uuid_route");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name);
    let asset = create_test_ssh_asset(&mut conn, &unique_name("test-uuid-route-asset"));

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

    // Integer ID should NOT work (returns 400 Bad Request for invalid UUID)
    let id_response = app
        .server
        .get("/assets/123")
        .add_header(header::COOKIE, format!("access_token={}", admin.token))
        .await;

    assert_status(&id_response, 400);

    // Cleanup
    test_db::cleanup(&mut conn);
}
