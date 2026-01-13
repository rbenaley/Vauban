/// VAUBAN Web - Assets API Integration Tests.
///
/// Tests for /api/v1/assets/* endpoints.
use axum::http::header;
use diesel::prelude::*;
use serde_json::json;
use serial_test::serial;
use uuid::Uuid;

use crate::common::{TestApp, assertions::*, test_db};
use crate::fixtures::{
    create_admin_user, create_test_rdp_asset, create_test_ssh_asset, create_test_user, unique_name,
};

/// Test list assets with authentication.
#[tokio::test]
#[serial]
async fn test_list_assets_authenticated() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Setup: create user and assets
    let username = unique_name("test_user_assets");
    let user = create_test_user(&mut conn, &app.auth_service, &username);

    create_test_ssh_asset(&mut conn, &unique_name("test-ssh"));
    create_test_rdp_asset(&mut conn, &unique_name("test-rdp"));

    // Execute: GET /api/v1/assets
    let response = app
        .server
        .get("/api/v1/assets")
        .add_header(header::AUTHORIZATION, app.auth_header(&user.token))
        .await;

    // Assert: 200 OK with array
    assert_status(&response, 200);

    // Cleanup
    test_db::cleanup(&mut conn);
}

/// Test list assets without authentication.
#[tokio::test]
#[serial]
async fn test_list_assets_unauthenticated() {
    let app = TestApp::spawn().await;

    // Execute: GET /api/v1/assets without token
    let response = app.server.get("/api/v1/assets").await;

    // Assert: 401 Unauthorized
    assert_status(&response, 401);
}

/// Test list assets with type filter.
#[tokio::test]
#[serial]
async fn test_list_assets_filter_by_type() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Setup: create user and assets of different types
    let username = unique_name("test_user_filter");
    let user = create_test_user(&mut conn, &app.auth_service, &username);

    create_test_ssh_asset(&mut conn, &unique_name("test-ssh"));
    create_test_rdp_asset(&mut conn, &unique_name("test-rdp"));

    // Execute: GET /api/v1/assets?type=ssh
    let response = app
        .server
        .get("/api/v1/assets?type=ssh")
        .add_header(header::AUTHORIZATION, app.auth_header(&user.token))
        .await;

    // Assert: 200 OK
    assert_status(&response, 200);

    // Cleanup
    test_db::cleanup(&mut conn);
}

/// Test list assets with status filter.
#[tokio::test]
#[serial]
async fn test_list_assets_filter_by_status() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Setup: create user and online asset
    let username = unique_name("test_user_status");
    let user = create_test_user(&mut conn, &app.auth_service, &username);

    create_test_ssh_asset(&mut conn, &unique_name("test-online"));

    // Execute: GET /api/v1/assets?status=online
    let response = app
        .server
        .get("/api/v1/assets?status=online")
        .add_header(header::AUTHORIZATION, app.auth_header(&user.token))
        .await;

    // Assert: 200 OK
    assert_status(&response, 200);

    // Cleanup
    test_db::cleanup(&mut conn);
}

/// Test create asset.
#[tokio::test]
#[serial]
async fn test_create_asset_success() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Setup: create admin
    let admin_name = unique_name("test_admin_asset");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name);

    let asset_name = unique_name("test-new-asset");

    // Execute: POST /api/v1/assets
    let response = app
        .server
        .post("/api/v1/assets")
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .json(&json!({
            "name": asset_name,
            "hostname": format!("{}.test.vauban.io", asset_name),
            "ip_address": "192.168.100.1",
            "port": 22,
            "asset_type": "ssh",
            "status": "online"
        }))
        .await;

    // Assert: 200 OK or 201 Created (both acceptable)
    let status = response.status_code().as_u16();
    assert!(
        status == 200 || status == 201,
        "Expected 200 or 201, got {}",
        status
    );

    // Cleanup
    test_db::cleanup(&mut conn);
}

/// Test create asset with invalid IP.
#[tokio::test]
#[serial]
async fn test_create_asset_invalid_ip() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Setup: create admin
    let admin_name = unique_name("test_admin_ip");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name);

    // Execute: POST /api/v1/assets with invalid IP
    let response = app
        .server
        .post("/api/v1/assets")
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .json(&json!({
            "name": "test-invalid-ip",
            "hostname": "invalid.test.vauban.io",
            "ip_address": "not-an-ip",
            "port": 22,
            "asset_type": "ssh",
            "status": "online"
        }))
        .await;

    // Assert: 400 Bad Request
    assert_status(&response, 400);

    // Cleanup
    test_db::cleanup(&mut conn);
}

/// Test create asset with invalid port.
#[tokio::test]
#[serial]
async fn test_create_asset_invalid_port() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Setup: create admin
    let admin_name = unique_name("test_admin_port");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name);

    // Execute: POST /api/v1/assets with invalid port
    let response = app
        .server
        .post("/api/v1/assets")
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .json(&json!({
            "name": "test-invalid-port",
            "hostname": "port.test.vauban.io",
            "ip_address": "192.168.1.1",
            "port": 99999,  // Invalid port
            "asset_type": "ssh",
            "status": "online"
        }))
        .await;

    // Assert: 400 Bad Request
    assert_status(&response, 400);

    // Cleanup
    test_db::cleanup(&mut conn);
}

/// Test get asset by UUID.
#[tokio::test]
#[serial]
async fn test_get_asset_exists() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Setup: create user and asset
    let username = unique_name("test_user_get_asset");
    let user = create_test_user(&mut conn, &app.auth_service, &username);

    let asset = create_test_ssh_asset(&mut conn, &unique_name("test-get-asset"));

    // Execute: GET /api/v1/assets/{uuid}
    let response = app
        .server
        .get(&format!("/api/v1/assets/{}", asset.asset.uuid))
        .add_header(header::AUTHORIZATION, app.auth_header(&user.token))
        .await;

    // Assert: 200 OK
    assert_status(&response, 200);
    assert_json_has_field(&response, "uuid");

    // Cleanup
    test_db::cleanup(&mut conn);
}

/// Test get non-existent asset.
#[tokio::test]
#[serial]
async fn test_get_asset_not_found() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Setup: create user
    let username = unique_name("test_user_asset_404");
    let user = create_test_user(&mut conn, &app.auth_service, &username);

    let fake_uuid = Uuid::new_v4();

    // Execute: GET /api/v1/assets/{fake_uuid}
    let response = app
        .server
        .get(&format!("/api/v1/assets/{}", fake_uuid))
        .add_header(header::AUTHORIZATION, app.auth_header(&user.token))
        .await;

    // Assert: 404 Not Found
    assert_status(&response, 404);

    // Cleanup
    test_db::cleanup(&mut conn);
}

/// Test update asset.
#[tokio::test]
#[serial]
async fn test_update_asset_success() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Setup: create admin and asset
    let admin_name = unique_name("test_admin_upd_asset");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name);

    let asset = create_test_ssh_asset(&mut conn, &unique_name("test-update-asset"));

    // Execute: PUT /api/v1/assets/{uuid}
    let response = app
        .server
        .put(&format!("/api/v1/assets/{}", asset.asset.uuid))
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .json(&json!({
            "name": "updated-asset-name",
            "status": "maintenance"
        }))
        .await;

    // Assert: 200 OK
    assert_status(&response, 200);

    // Cleanup
    test_db::cleanup(&mut conn);
}

/// Test update asset with IPv4 address persists to database.
#[tokio::test]
#[serial]
async fn test_update_asset_with_ipv4_persists_to_database() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Setup: create admin and asset
    let admin_name = unique_name("test_admin_ip_asset");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name);

    let asset = create_test_ssh_asset(&mut conn, &unique_name("test-ip-asset"));

    // Execute: PUT /api/v1/assets/{uuid} with new IP
    let response = app
        .server
        .put(&format!("/api/v1/assets/{}", asset.asset.uuid))
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .json(&json!({
            "ip_address": "192.168.1.200"
        }))
        .await;

    // Assert: 200 OK
    assert_status(&response, 200);

    // Verify IP was persisted in database
    use vauban_web::schema::assets::dsl::{assets, ip_address, uuid};
    let db_ip: Option<ipnetwork::IpNetwork> = assets
        .filter(uuid.eq(asset.asset.uuid))
        .select(ip_address)
        .first(&mut conn)
        .expect("Asset should exist in database");

    assert_eq!(
        db_ip.map(|ip| ip.to_string()),
        Some("192.168.1.200/32".to_string()),
        "Database should contain the updated IPv4 address"
    );

    // Cleanup
    test_db::cleanup(&mut conn);
}

/// Test update asset with IPv6 address persists to database.
#[tokio::test]
#[serial]
async fn test_update_asset_with_ipv6_persists_to_database() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Setup: create admin and asset
    let admin_name = unique_name("test_admin_ipv6_asset");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name);

    let asset = create_test_ssh_asset(&mut conn, &unique_name("test-ipv6-asset"));

    // Execute: PUT /api/v1/assets/{uuid} with IPv6
    let response = app
        .server
        .put(&format!("/api/v1/assets/{}", asset.asset.uuid))
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .json(&json!({
            "ip_address": "2001:db8::1"
        }))
        .await;

    // Assert: 200 OK
    assert_status(&response, 200);

    // Verify IPv6 was persisted in database
    use vauban_web::schema::assets::dsl::{assets, ip_address, uuid};
    let db_ip: Option<ipnetwork::IpNetwork> = assets
        .filter(uuid.eq(asset.asset.uuid))
        .select(ip_address)
        .first(&mut conn)
        .expect("Asset should exist in database");

    assert_eq!(
        db_ip.map(|ip| ip.to_string()),
        Some("2001:db8::1/128".to_string()),
        "Database should contain the updated IPv6 address"
    );

    // Cleanup
    test_db::cleanup(&mut conn);
}

/// Test update asset with multiple fields persists all to database.
#[tokio::test]
#[serial]
async fn test_update_asset_with_multiple_fields_persists_to_database() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Setup: create admin and asset
    let admin_name = unique_name("test_admin_multi_asset");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name);

    let asset = create_test_ssh_asset(&mut conn, &unique_name("test-multi-asset"));

    // Execute: PUT /api/v1/assets/{uuid} with multiple fields
    let response = app
        .server
        .put(&format!("/api/v1/assets/{}", asset.asset.uuid))
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .json(&json!({
            "name": "multi-updated-asset",
            "ip_address": "10.0.0.100",
            "port": 2222,
            "status": "maintenance"
        }))
        .await;

    // Assert: 200 OK with updated fields in response (except ip_address which is skip_serializing)
    assert_status(&response, 200);
    let json: serde_json::Value = response.json();
    assert_eq!(
        json.get("name").and_then(|v| v.as_str()),
        Some("multi-updated-asset"),
        "Response should contain the updated name"
    );
    assert_eq!(
        json.get("port").and_then(|v| v.as_i64()),
        Some(2222),
        "Response should contain the updated port"
    );
    assert_eq!(
        json.get("status").and_then(|v| v.as_str()),
        Some("maintenance"),
        "Response should contain the updated status"
    );

    // Verify IP was persisted in database (ip_address is not serialized in response for security)
    use vauban_web::schema::assets::dsl::{assets, ip_address, uuid};
    let db_ip: Option<ipnetwork::IpNetwork> = assets
        .filter(uuid.eq(asset.asset.uuid))
        .select(ip_address)
        .first(&mut conn)
        .expect("Asset should exist in database");

    assert_eq!(
        db_ip.map(|ip| ip.to_string()),
        Some("10.0.0.100/32".to_string()),
        "Database should contain the updated IP address"
    );

    // Cleanup
    test_db::cleanup(&mut conn);
}

/// Test update asset with invalid IP address returns error.
#[tokio::test]
#[serial]
async fn test_update_asset_with_invalid_ip_returns_error() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Setup: create admin and asset
    let admin_name = unique_name("test_admin_invalid_ip");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name);

    let asset = create_test_ssh_asset(&mut conn, &unique_name("test-invalid-ip-asset"));

    // Execute: PUT /api/v1/assets/{uuid} with invalid IP
    let response = app
        .server
        .put(&format!("/api/v1/assets/{}", asset.asset.uuid))
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .json(&json!({
            "ip_address": "not-a-valid-ip"
        }))
        .await;

    // Assert: 400 Bad Request or 422 Unprocessable Entity
    let status = response.status_code();
    assert!(
        status == 400 || status == 422,
        "Invalid IP should return 400 or 422, got {}",
        status
    );

    // Cleanup
    test_db::cleanup(&mut conn);
}

// ==================== Asset Edit Page Tests ====================

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

// ==================== Form Submission Tests ====================

/// Test update asset with form-like JSON (strings for numbers).
/// This simulates what HTMX json-enc extension sends.
#[tokio::test]
#[serial]
async fn test_update_asset_with_string_port() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Setup: create admin and asset
    let admin_name = unique_name("test_admin_string_port");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name);

    let asset = create_test_ssh_asset(&mut conn, &unique_name("test-string-port-asset"));

    // Execute: PUT with port as string (like HTML forms send)
    let response = app
        .server
        .put(&format!("/api/v1/assets/{}", asset.asset.uuid))
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .json(&serde_json::json!({
            "port": "2222"
        }))
        .await;

    // Assert: 200 OK
    assert_status(&response, 200);

    // Verify port was updated in database
    use vauban_web::schema::assets::dsl::{assets, port, uuid};
    let db_port: i32 = assets
        .filter(uuid.eq(asset.asset.uuid))
        .select(port)
        .first(&mut conn)
        .expect("Asset should exist in database");

    assert_eq!(db_port, 2222, "Database should contain the updated port");

    // Cleanup
    test_db::cleanup(&mut conn);
}

/// Test update asset with boolean as string "on" (checkbox behavior).
#[tokio::test]
#[serial]
async fn test_update_asset_with_checkbox_on() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Setup: create admin and asset
    let admin_name = unique_name("test_admin_checkbox");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name);

    let asset = create_test_ssh_asset(&mut conn, &unique_name("test-checkbox-asset"));

    // Execute: PUT with require_mfa as "on" (like HTML checkboxes)
    let response = app
        .server
        .put(&format!("/api/v1/assets/{}", asset.asset.uuid))
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .json(&serde_json::json!({
            "require_mfa": "on"
        }))
        .await;

    // Assert: 200 OK
    assert_status(&response, 200);

    // Verify require_mfa was updated in database
    use vauban_web::schema::assets::dsl::{assets, require_mfa, uuid};
    let db_mfa: bool = assets
        .filter(uuid.eq(asset.asset.uuid))
        .select(require_mfa)
        .first(&mut conn)
        .expect("Asset should exist in database");

    assert!(db_mfa, "Database should have require_mfa set to true");

    // Cleanup
    test_db::cleanup(&mut conn);
}

/// Test update asset with full form-like submission.
#[tokio::test]
#[serial]
async fn test_update_asset_full_form_submission() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Setup: create admin and asset
    let admin_name = unique_name("test_admin_full_form");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name);

    let asset = create_test_ssh_asset(&mut conn, &unique_name("test-full-form-asset"));

    // Use unique names to avoid conflicts
    let updated_name = unique_name("updated-server");
    let updated_hostname = format!("{}.example.com", unique_name("updated"));

    // Execute: PUT with all fields as strings (like HTMX json-enc sends)
    let response = app
        .server
        .put(&format!("/api/v1/assets/{}", asset.asset.uuid))
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .json(&serde_json::json!({
            "name": updated_name,
            "hostname": updated_hostname,
            "ip_address": "10.0.0.50",
            "port": "8022",
            "status": "maintenance",
            "description": "Updated via form",
            "require_mfa": "on",
            "require_justification": "on"
        }))
        .await;

    // Assert: 200 OK
    assert_status(&response, 200);

    // Verify all fields were updated in database
    use vauban_web::schema::assets::dsl::*;
    let (db_name, db_hostname, db_port, db_status, db_mfa, db_justification): (
        String,
        String,
        i32,
        String,
        bool,
        bool,
    ) = assets
        .filter(uuid.eq(asset.asset.uuid))
        .select((name, hostname, port, status, require_mfa, require_justification))
        .first(&mut conn)
        .expect("Asset should exist in database");

    assert!(db_name.starts_with("updated-server"), "Name should start with 'updated-server'");
    assert!(db_hostname.contains("updated"), "Hostname should contain 'updated'");
    assert_eq!(db_port, 8022);
    assert_eq!(db_status, "maintenance");
    assert!(db_mfa);
    assert!(db_justification);

    // Cleanup
    test_db::cleanup(&mut conn);
}

// =============================================================================
// End-to-End Navigation Tests
// =============================================================================
// These tests verify complete user flows to catch routing inconsistencies.

/// Test the complete edit flow: edit page -> submit -> redirect -> detail page.
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
