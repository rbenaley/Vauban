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
    add_user_to_vauban_group, create_admin_user, create_approved_session, create_simple_admin_user,
    create_simple_ssh_asset, create_simple_user, create_test_access_rule_with_constraints,
    create_test_asset_group, create_test_asset_in_group, create_test_rdp_asset,
    create_test_ssh_asset, create_test_vauban_group, grant_user_full_access_to_new_group,
    unique_name,
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

    // The previous "is_superuser / is_staff" listing-bypass is gone; admins
    // now require an access_rule to see an asset, like every other user.
    let ag =
        grant_user_full_access_to_new_group(&mut conn, admin_id, &unique_name("pg_many"), &["ssh"])
            .await;

    for i in 0..35 {
        let name = unique_name(&format!("pg_asset_{:03}", i));
        create_test_asset_in_group(&mut conn, &name, admin_id, &ag).await;
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
    assert!(
        body.contains("Showing"),
        "page 1 should show pagination counter"
    );
    assert!(
        body.contains("title=\"Next page\""),
        "page 1 should have Next button"
    );
    assert!(
        body.contains("title=\"Last page\""),
        "page 1 should have Last button"
    );
    assert!(
        !body.contains("title=\"First page\""),
        "page 1 should not have First button"
    );
}

#[tokio::test]
async fn test_asset_list_page_2() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("pg_admin_p2");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_admin_uuid(&mut conn, admin_id).await;

    let ag =
        grant_user_full_access_to_new_group(&mut conn, admin_id, &unique_name("pg_p2"), &["ssh"])
            .await;

    for i in 0..35 {
        let name = unique_name(&format!("pg2_asset_{:03}", i));
        create_test_asset_in_group(&mut conn, &name, admin_id, &ag).await;
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
    assert!(
        body.contains("title=\"First page\""),
        "page 2 should have First button"
    );
    assert!(
        body.contains("title=\"Previous page\""),
        "page 2 should have Previous button"
    );
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

    let ag =
        grant_user_full_access_to_new_group(&mut conn, admin_id, &unique_name("pg_cnt"), &["ssh"])
            .await;

    let search_tag = unique_name("pgcnt");
    for i in 0..35 {
        let name = format!("{}_asset_{:03}", search_tag, i);
        create_test_asset_in_group(&mut conn, &name, admin_id, &ag).await;
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
    let _asset_id =
        create_test_asset_in_group(&mut conn, &unique_name("btn_asset"), admin_id, &ag_uuid).await;

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
    let _asset_id =
        create_test_asset_in_group(&mut conn, &unique_name("btn_asset_na"), admin_id, &ag_uuid)
            .await;

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
    let asset_id =
        create_test_asset_in_group(&mut conn, &unique_name("btn_asset_ap"), admin_id, &ag_uuid)
            .await;

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

/// Admin user is now subject to the same access rules as any other user
/// (the historical "always Connect for admins" bypass was removed).
/// When the matching rule has `require_approval = true`, an admin must
/// see the orange "Request" button — exactly like a regular user — so
/// the UI does not lie about what `connect_ssh` / `connect_rdp` will
/// enforce.
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
    add_user_to_vauban_group(&mut conn, admin_id, &ug_uuid).await;
    let _asset_id =
        create_test_asset_in_group(&mut conn, &unique_name("btn_asset_adm"), admin_id, &ag_uuid)
            .await;

    create_test_access_rule_with_constraints(
        &mut conn,
        &ug_uuid,
        &ag_uuid,
        &["ssh"],
        false,
        true, // require_approval
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
        body.contains("#request-access"),
        "admin must see the Request link when the matching rule requires \
         approval — no more privileged-user shortcut to a blue Connect \
         button on an approval-protected asset."
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
    let _asset_id =
        create_test_asset_in_group(&mut conn, &unique_name("btn_asset_lnk"), admin_id, &ag_uuid)
            .await;

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

// =============================================================================
// Asset secret-input contract — browser credential prompt suppression
// =============================================================================
//
// Asset credentials (account name, secret, key passphrase) are credentials
// for the TARGET system, not for the operator. We must therefore prevent
// browsers (especially Safari + Chrome) from offering to save / generate
// a password in the operator's keychain — that would leak asset secrets
// outside Vauban's RBAC + audit perimeter.
//
// The defense, applied to /assets/new and /assets/{uuid}/edit:
//   1. Visible labels are credential-neutral ("Account Name" / "Secret"
//      / "Key Passphrase"), never "Username" / "Password".
//   2. <input type="text"> instead of <input type="password"> — this
//      removes the strongest single autofill signal.
//   3. name= and id= attributes are opaque (vbn_account / vbn_secret /
//      vbn_secret_phrase) so name-based heuristics fail.
//   4. Each field carries data-real-name="ssh_*" so the form's @submit
//      Alpine handler restores the real server-side name synchronously
//      before the browser serialises the form (per HTML spec, listeners
//      run before the default action — the POST payload is unchanged).
//   5. The Secret field is visually masked with the OFL-1.1 web font
//      `text-security-disc.woff2` via a CSS attribute selector
//      (`input[data-real-name="ssh_password"]`) — no dedicated class on
//      the input, no `-webkit-text-security` (works on Firefox too).
//      Account Name and Key Passphrase remain in clear text.
//
// Anti-regression marker: ASSET-CREDS-NO-SAVE-PROMPT-20260420.

/// Window size around a tag location used for attribute scanning. Inputs
/// in our templates rarely span more than a few hundred bytes when fully
/// inlined; 800 leaves comfortable slack for placeholder text.
const SECRET_INPUT_WINDOW: usize = 800;

/// Assert the secret-input contract for a single field on `body`.
///
/// - `dom_name`: the opaque HTML name/id used to hide the field from
///   browser heuristics (e.g. `vbn_secret`).
/// - `real_name`: the server-side name carried by `data-real-name=` and
///   restored at submit time (e.g. `ssh_password`).
/// - `expected_label`: the visible label text (e.g. `Secret`).
fn assert_secret_input_contract(
    body: &str,
    dom_name: &str,
    real_name: &str,
    expected_label: &str,
    context: &str,
) {
    // 1. The static HTML must NOT carry name="ssh_*" anywhere as a
    //    real attribute. Note: data-real-name="ssh_*" contains the
    //    substring `name="ssh_*"` — the leading space prefix in the
    //    needle excludes that case (data-real-name is preceded by `-`,
    //    real `name=` attributes are always preceded by whitespace on
    //    an HTML input tag).
    let raw_name_needle = format!(" name=\"{}\"", real_name);
    assert!(
        !body.contains(&raw_name_needle),
        "{}: rendered HTML must NOT carry `name=\"{}\"` as a real \
         attribute — browsers (Safari/Chrome) trigger Save Password / \
         Generate Password prompts when they recognise credential-shaped \
         names. The real name MUST live only in `data-real-name=\"{}\"` \
         (ASSET-CREDS-NO-SAVE-PROMPT-20260420).",
        context,
        real_name,
        real_name
    );
    let raw_id_needle = format!(" id=\"{}\"", real_name);
    assert!(
        !body.contains(&raw_id_needle),
        "{}: rendered HTML must NOT carry `id=\"{}\"` — same heuristic \
         risk as name=. Use the opaque `vbn_*` id and aria/label \
         relations instead (ASSET-CREDS-NO-SAVE-PROMPT-20260420).",
        context,
        real_name
    );

    // 2. The opaque DOM input must exist with the right name + id +
    //    data-real-name attribute, all in the same input tag.
    let dom_needle = format!("name=\"{}\"", dom_name);
    let pos = body.find(&dom_needle).unwrap_or_else(|| {
        panic!(
            "{}: missing input with `name=\"{}\"` — secret fields must \
             carry the opaque DOM name; the @submit handler restores the \
             real server-side name at submit time \
             (ASSET-CREDS-NO-SAVE-PROMPT-20260420).",
            context, dom_name
        )
    });
    let win_start = pos.saturating_sub(200);
    let win_end = (pos + SECRET_INPUT_WINDOW).min(body.len());
    let window = &body[win_start..win_end];

    // 3. type="text" — never type="password" (the strongest single
    //    autofill signal). The typed value is intentionally visible.
    assert!(
        window.contains("type=\"text\""),
        "{}: input `name=\"{}\"` must use `type=\"text\"` to avoid \
         browser credential autofill \
         (ASSET-CREDS-NO-SAVE-PROMPT-20260420). Window:\n{}",
        context,
        dom_name,
        window
    );
    assert!(
        !window.contains("type=\"password\""),
        "{}: input `name=\"{}\"` must NOT be `type=\"password\"` \
         (ASSET-CREDS-NO-SAVE-PROMPT-20260420). Window:\n{}",
        context,
        dom_name,
        window
    );

    // 4. data-real-name carries the server-side name.
    let dra_needle = format!("data-real-name=\"{}\"", real_name);
    assert!(
        window.contains(&dra_needle),
        "{}: input `name=\"{}\"` must carry `data-real-name=\"{}\"` so \
         the form's @submit handler can restore the server-side name \
         (ASSET-CREDS-NO-SAVE-PROMPT-20260420). Window:\n{}",
        context,
        dom_name,
        real_name,
        window
    );

    // 5. id= matches dom_name and the visible <label for=...> binds to
    //    that opaque id (a11y must not regress).
    let id_needle = format!("id=\"{}\"", dom_name);
    assert!(
        window.contains(&id_needle),
        "{}: input `name=\"{}\"` must also carry the matching opaque \
         `id=\"{}\"` so the visible <label for=...> can bind to it \
         (ASSET-CREDS-NO-SAVE-PROMPT-20260420). Window:\n{}",
        context,
        dom_name,
        dom_name,
        window
    );
    let label_needle = format!("for=\"{}\"", dom_name);
    assert!(
        body.contains(&label_needle),
        "{}: missing <label for=\"{}\">. Without a label binding the \
         field is invisible to screen readers \
         (ASSET-CREDS-NO-SAVE-PROMPT-20260420).",
        context,
        dom_name
    );

    // 6. Visible label text matches the expected credential-neutral
    //    wording. We anchor on `for="vbn_*"` so there is no ambiguity
    //    with other labels on the page.
    let label_marker = format!("for=\"{}\"", dom_name);
    let lbl_pos = body
        .find(&label_marker)
        .expect("label needle checked above");
    let lbl_end = (lbl_pos + 400).min(body.len());
    let lbl_window = &body[lbl_pos..lbl_end];
    assert!(
        lbl_window.contains(expected_label),
        "{}: <label for=\"{}\"> must contain visible text `{}` (got \
         window:\n{}).",
        context,
        dom_name,
        expected_label,
        lbl_window
    );
}

/// Assert the form-level @submit handler that swaps `data-real-name`
/// back to `name` synchronously inside the submit event. Without it,
/// the server would receive opaque names and reject the form.
fn assert_form_submit_swap(body: &str, form_action_substr: &str, context: &str) {
    let pos = body.find(form_action_substr).unwrap_or_else(|| {
        panic!(
            "{}: form action `{}` not found in rendered HTML",
            context, form_action_substr
        )
    });
    let win_end = (pos + 1000).min(body.len());
    let form_tag = &body[pos..win_end];
    assert!(
        form_tag.contains("data-real-name") && form_tag.contains("@submit"),
        "{}: <form> must declare an @submit handler that rewrites \
         `data-real-name` -> `name` before the browser serialises the \
         form. Without the swap, the server would receive opaque names \
         (vbn_*) and the form would fail validation \
         (ASSET-CREDS-NO-SAVE-PROMPT-20260420). Window:\n{}",
        context,
        form_tag
    );
}

/// /assets/new — every secret field carries the opaque-name + swap
/// contract; visible labels are credential-neutral.
#[tokio::test]
#[serial]
async fn test_asset_create_form_uses_credential_neutral_inputs() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("asset_create_neutral");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let response = app
        .server
        .get("/assets/new")
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;

    assert_status(&response, 200);
    let body = response.text();

    assert_form_submit_swap(&body, "action=\"/assets\"", "asset create form");

    // All three fields share the same opaque-name + swap contract.
    for (dom_name, real_name, expected_label) in [
        ("vbn_account", "ssh_username", "Account Name"),
        ("vbn_secret", "ssh_password", "Secret"),
        ("vbn_secret_phrase", "ssh_passphrase", "Key Passphrase"),
    ] {
        assert_secret_input_contract(
            &body,
            dom_name,
            real_name,
            expected_label,
            &format!("asset create form ({})", expected_label),
        );
    }

    test_db::cleanup(&mut conn).await;
}

/// /assets/{uuid}/edit — same contract as the create form. Edit is the
/// path most likely to trigger Save Password prompts because operators
/// rotate secrets there.
#[tokio::test]
#[serial]
async fn test_asset_edit_form_uses_credential_neutral_inputs() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("asset_edit_neutral");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let asset = create_test_ssh_asset(&mut conn, &unique_name("edit-neutral-asset")).await;

    let response = app
        .server
        .get(&format!("/assets/{}/edit", asset.asset.uuid))
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;

    assert_status(&response, 200);
    let body = response.text();

    let action = format!("action=\"/assets/{}/edit\"", asset.asset.uuid);
    assert_form_submit_swap(&body, &action, "asset edit form");

    for (dom_name, real_name, expected_label) in [
        ("vbn_account", "ssh_username", "Account Name"),
        ("vbn_secret", "ssh_password", "Secret"),
        ("vbn_secret_phrase", "ssh_passphrase", "Key Passphrase"),
    ] {
        assert_secret_input_contract(
            &body,
            dom_name,
            real_name,
            expected_label,
            &format!("asset edit form ({})", expected_label),
        );
    }

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// Asset Secret — visual masking via OFL-1.1 web font
// =============================================================================
//
// The Secret field is `<input type="text">`, which means the typed value
// would otherwise be rendered in clear. We layer a glyph-substitution font
// (text-security-disc.woff2 — every glyph maps to "•") via a pure CSS
// attribute selector on `data-real-name="ssh_password"`.  No class on the
// input, no `-webkit-text-security`: the HTML stays untouched and Firefox
// gets the same masking as Safari/Chrome.
//
// Three regression-guard invariants:
//
//   A. The font is registered in `static_assets.rs` (otherwise the binary
//      can't serve it and the @font-face URL 404s in production).
//   B. `vauban.css` declares both the @font-face block AND the attribute
//      selector that applies it.  A revert that drops either side leaves
//      the secret visible in clear.
//   C. The masking is scoped to the secret field only — Account Name and
//      Key Passphrase MUST remain unmasked (we do not want a user to
//      mistake "Account Name" for a secret-grade field).
//
// Anti-regression marker: ASSET-SECRET-VISUAL-MASK-20260420.

/// A. + B. — font is registered and CSS wires it to the right selector.
#[test]
fn test_secret_input_visual_mask_is_wired() {
    use vauban_web::static_assets::lookup;

    // A. The font asset is compiled into the binary and served as woff2.
    let font = lookup("fonts/text-security-disc.woff2").expect(
        "text-security-disc.woff2 must be registered in static_assets::STATIC_FILES \
         — without it the @font-face URL returns 404 and the Secret field renders \
         in clear (ASSET-SECRET-VISUAL-MASK-20260420).",
    );
    assert_eq!(
        font.content_type, "font/woff2",
        "text-security-disc.woff2 must be served with `font/woff2` content-type \
         (ASSET-SECRET-VISUAL-MASK-20260420)."
    );
    assert!(
        font.content.len() > 1000,
        "text-security-disc.woff2 looks truncated ({} bytes); expected ~2 KB \
         (ASSET-SECRET-VISUAL-MASK-20260420).",
        font.content.len()
    );
    // woff2 magic bytes: "wOF2" (0x77 0x4F 0x46 0x32).
    assert_eq!(
        &font.content[..4],
        b"wOF2",
        "text-security-disc.woff2 magic bytes mismatch — file is corrupted \
         or replaced with the wrong format (ASSET-SECRET-VISUAL-MASK-20260420)."
    );

    // B. The CSS declares the @font-face AND the attribute selector that
    //    applies it. Both must be present for the masking to work.
    let css = include_str!("../../static/css/vauban.css");
    assert!(
        css.contains("@font-face") && css.contains("text-security-disc"),
        "vauban.css must declare @font-face for `text-security-disc` \
         (ASSET-SECRET-VISUAL-MASK-20260420)."
    );
    assert!(
        css.contains("/static/fonts/text-security-disc.woff2"),
        "vauban.css @font-face must point at /static/fonts/text-security-disc.woff2 \
         (ASSET-SECRET-VISUAL-MASK-20260420)."
    );
    assert!(
        css.contains("input[data-real-name=\"ssh_password\"]"),
        "vauban.css must apply `text-security-disc` to \
         `input[data-real-name=\"ssh_password\"]` — without this selector \
         the font is loaded but never used (ASSET-SECRET-VISUAL-MASK-20260420)."
    );
}

/// C. — masking is scoped to the secret field only.
#[test]
fn test_secret_input_visual_mask_is_scoped_to_password() {
    let css = include_str!("../../static/css/vauban.css");

    // The masking must NOT leak onto username (Account Name) or passphrase.
    // If a future refactor broadens the selector, the secret would visually
    // collide with adjacent fields and confuse operators.
    assert!(
        !css.contains("input[data-real-name=\"ssh_username\"]"),
        "vauban.css must NOT apply masking to ssh_username (Account Name is \
         intentionally readable) (ASSET-SECRET-VISUAL-MASK-20260420)."
    );
    assert!(
        !css.contains("input[data-real-name=\"ssh_passphrase\"]"),
        "vauban.css must NOT apply masking to ssh_passphrase (Key Passphrase \
         is intentionally readable in this iteration) \
         (ASSET-SECRET-VISUAL-MASK-20260420)."
    );
}
