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
