/// VAUBAN Web - Assets API Integration Tests.
///
/// Tests for /api/v1/assets/* endpoints.
use axum::http::header;
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::RunQueryDsl;
use serde_json::json;
use serial_test::serial;
use uuid::Uuid;

use crate::common::{TestApp, assertions::*, test_db, unwrap_ok};
use crate::fixtures::{
    create_admin_user, create_test_rdp_asset, create_test_ssh_asset, create_test_user, unique_name,
};

/// Test list assets with authentication.
#[tokio::test]
#[serial]
async fn test_list_assets_authenticated() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Setup: create user and assets
    let username = unique_name("test_user_assets");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;

    create_test_ssh_asset(&mut conn, &unique_name("test-ssh")).await;
    create_test_rdp_asset(&mut conn, &unique_name("test-rdp")).await;

    // Execute: GET /api/v1/assets
    let response = app
        .server
        .get("/api/v1/assets")
        .add_header(header::AUTHORIZATION, app.auth_header(&user.token))
        .await;

    // Assert: 200 OK with array
    assert_status(&response, 200);

    // Cleanup
    test_db::cleanup(&mut conn).await;
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
    let mut conn = app.get_conn().await;

    // Setup: create user and assets of different types
    let username = unique_name("test_user_filter");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;

    create_test_ssh_asset(&mut conn, &unique_name("test-ssh")).await;
    create_test_rdp_asset(&mut conn, &unique_name("test-rdp")).await;

    // Execute: GET /api/v1/assets?type=ssh
    let response = app
        .server
        .get("/api/v1/assets?type=ssh")
        .add_header(header::AUTHORIZATION, app.auth_header(&user.token))
        .await;

    // Assert: 200 OK
    assert_status(&response, 200);

    // Cleanup
    test_db::cleanup(&mut conn).await;
}

/// Test list assets with status filter.
#[tokio::test]
#[serial]
async fn test_list_assets_filter_by_status() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Setup: create user and online asset
    let username = unique_name("test_user_status");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;

    create_test_ssh_asset(&mut conn, &unique_name("test-online")).await;

    // Execute: GET /api/v1/assets?status=online
    let response = app
        .server
        .get("/api/v1/assets?status=online")
        .add_header(header::AUTHORIZATION, app.auth_header(&user.token))
        .await;

    // Assert: 200 OK
    assert_status(&response, 200);

    // Cleanup
    test_db::cleanup(&mut conn).await;
}

/// Test create asset.
#[tokio::test]
#[serial]
async fn test_create_asset_success() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Setup: create admin
    let admin_name = unique_name("test_admin_asset");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

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
    test_db::cleanup(&mut conn).await;
}

/// Test create asset with invalid IP.
#[tokio::test]
#[serial]
async fn test_create_asset_invalid_ip() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Setup: create admin
    let admin_name = unique_name("test_admin_ip");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

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
    test_db::cleanup(&mut conn).await;
}

/// Test create asset with invalid port.
#[tokio::test]
#[serial]
async fn test_create_asset_invalid_port() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Setup: create admin
    let admin_name = unique_name("test_admin_port");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

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
    test_db::cleanup(&mut conn).await;
}

/// Test get asset by UUID.
#[tokio::test]
#[serial]
async fn test_get_asset_exists() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Setup: create user and asset
    let username = unique_name("test_user_get_asset");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;

    let asset = create_test_ssh_asset(&mut conn, &unique_name("test-get-asset")).await;

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
    test_db::cleanup(&mut conn).await;
}

/// Test get non-existent asset.
#[tokio::test]
#[serial]
async fn test_get_asset_not_found() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Setup: create user
    let username = unique_name("test_user_asset_404");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;

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
    test_db::cleanup(&mut conn).await;
}

/// Test update asset.
#[tokio::test]
#[serial]
async fn test_update_asset_success() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Setup: create admin and asset
    let admin_name = unique_name("test_admin_upd_asset");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let asset = create_test_ssh_asset(&mut conn, &unique_name("test-update-asset")).await;

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
    test_db::cleanup(&mut conn).await;
}

/// Test update asset with IPv4 address persists to database.
#[tokio::test]
#[serial]
async fn test_update_asset_with_ipv4_persists_to_database() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Setup: create admin and asset
    let admin_name = unique_name("test_admin_ip_asset");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let asset = create_test_ssh_asset(&mut conn, &unique_name("test-ip-asset")).await;

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
    let db_ip: Option<ipnetwork::IpNetwork> = unwrap_ok!(
        assets
            .filter(uuid.eq(asset.asset.uuid))
            .select(ip_address)
            .first(&mut conn)
            .await
    );

    assert_eq!(
        db_ip.map(|ip| ip.to_string()),
        Some("192.168.1.200/32".to_string()),
        "Database should contain the updated IPv4 address"
    );

    // Cleanup
    test_db::cleanup(&mut conn).await;
}

/// Test update asset with IPv6 address persists to database.
#[tokio::test]
#[serial]
async fn test_update_asset_with_ipv6_persists_to_database() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Setup: create admin and asset
    let admin_name = unique_name("test_admin_ipv6_asset");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let asset = create_test_ssh_asset(&mut conn, &unique_name("test-ipv6-asset")).await;

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
    let db_ip: Option<ipnetwork::IpNetwork> = unwrap_ok!(
        assets
            .filter(uuid.eq(asset.asset.uuid))
            .select(ip_address)
            .first(&mut conn)
            .await
    );

    assert_eq!(
        db_ip.map(|ip| ip.to_string()),
        Some("2001:db8::1/128".to_string()),
        "Database should contain the updated IPv6 address"
    );

    // Cleanup
    test_db::cleanup(&mut conn).await;
}

/// Test update asset with multiple fields persists all to database.
#[tokio::test]
#[serial]
async fn test_update_asset_with_multiple_fields_persists_to_database() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Setup: create admin and asset
    let admin_name = unique_name("test_admin_multi_asset");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let asset = create_test_ssh_asset(&mut conn, &unique_name("test-multi-asset")).await;

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
    let db_ip: Option<ipnetwork::IpNetwork> = unwrap_ok!(
        assets
            .filter(uuid.eq(asset.asset.uuid))
            .select(ip_address)
            .first(&mut conn)
            .await
    );

    assert_eq!(
        db_ip.map(|ip| ip.to_string()),
        Some("10.0.0.100/32".to_string()),
        "Database should contain the updated IP address"
    );

    // Cleanup
    test_db::cleanup(&mut conn).await;
}

/// Test update asset with invalid IP address returns error.
#[tokio::test]
#[serial]
async fn test_update_asset_with_invalid_ip_returns_error() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Setup: create admin and asset
    let admin_name = unique_name("test_admin_invalid_ip");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let asset = create_test_ssh_asset(&mut conn, &unique_name("test-invalid-ip-asset")).await;

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
    test_db::cleanup(&mut conn).await;
}
// ==================== Form Submission Tests ====================

/// Test update asset with form-like JSON (strings for numbers).
/// This simulates what HTMX json-enc extension sends.
#[tokio::test]
#[serial]
async fn test_update_asset_with_string_port() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Setup: create admin and asset
    let admin_name = unique_name("test_admin_string_port");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let asset = create_test_ssh_asset(&mut conn, &unique_name("test-string-port-asset")).await;

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
    let db_port: i32 = unwrap_ok!(
        assets
            .filter(uuid.eq(asset.asset.uuid))
            .select(port)
            .first(&mut conn)
            .await
    );

    assert_eq!(db_port, 2222, "Database should contain the updated port");

    // Cleanup
    test_db::cleanup(&mut conn).await;
}

/// Test update asset with boolean as string "on" (checkbox behavior).
#[tokio::test]
#[serial]
async fn test_update_asset_with_checkbox_on() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Setup: create admin and asset
    let admin_name = unique_name("test_admin_checkbox");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let asset = create_test_ssh_asset(&mut conn, &unique_name("test-checkbox-asset")).await;

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
    let db_mfa: bool = unwrap_ok!(
        assets
            .filter(uuid.eq(asset.asset.uuid))
            .select(require_mfa)
            .first(&mut conn)
            .await
    );

    assert!(db_mfa, "Database should have require_mfa set to true");

    // Cleanup
    test_db::cleanup(&mut conn).await;
}

/// Test update asset with full form-like submission.
#[tokio::test]
#[serial]
async fn test_update_asset_full_form_submission() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Setup: create admin and asset
    let admin_name = unique_name("test_admin_full_form");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let asset = create_test_ssh_asset(&mut conn, &unique_name("test-full-form-asset")).await;

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
    ) = unwrap_ok!(
        assets
            .filter(uuid.eq(asset.asset.uuid))
            .select((
                name,
                hostname,
                port,
                status,
                require_mfa,
                require_justification
            ))
            .first(&mut conn)
            .await
    );

    assert!(
        db_name.starts_with("updated-server"),
        "Name should start with 'updated-server'"
    );
    assert!(
        db_hostname.contains("updated"),
        "Hostname should contain 'updated'"
    );
    assert_eq!(db_port, 8022);
    assert_eq!(db_status, "maintenance");
    assert!(db_mfa);
    assert!(db_justification);

    // Cleanup
    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// Malformed UUID Tests
// =============================================================================

/// Test get asset with malformed UUID returns validation error.
#[tokio::test]
#[serial]
async fn test_get_asset_malformed_uuid_returns_validation_error() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin = create_admin_user(
        &mut conn,
        &app.auth_service,
        &unique_name("asset_malformed"),
    )
    .await;

    // Try various malformed UUIDs
    let malformed_uuids = [
        "not-a-uuid",
        "12345",
        "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "24d3cc30-d6c0-ooo7-be9a-978dd250ae3e", // Invalid character 'o'
    ];

    for bad_uuid in malformed_uuids {
        let response = app
            .server
            .get(&format!("/api/v1/assets/{}", bad_uuid))
            .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
            .await;

        let status = response.status_code().as_u16();
        assert!(
            status == 400 || status == 422,
            "Malformed UUID '{}' should return 400 or 422, got {}",
            bad_uuid,
            status
        );
    }

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// SSH Host Key Status API Tests (H-9 Three States)
// =============================================================================

/// Helper: update an asset's connection_config directly in the DB.
async fn set_connection_config(
    conn: &mut diesel_async::AsyncPgConnection,
    asset_uuid: uuid::Uuid,
    config: serde_json::Value,
) {
    use diesel::prelude::*;
    use diesel_async::RunQueryDsl;
    use vauban_web::schema::assets::dsl;

    unwrap_ok!(
        diesel::update(dsl::assets.filter(dsl::uuid.eq(asset_uuid)))
            .set(dsl::connection_config.eq(config))
            .execute(conn)
            .await
    );
}

/// GET /api/v1/assets/{uuid}/ssh-host-key returns "no_key" when no host key
/// has ever been stored for the asset.
#[tokio::test]
#[serial]
async fn test_ssh_host_key_status_no_key() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("admin_hk_nokey");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let asset = create_test_ssh_asset(&mut conn, &unique_name("hk-nokey")).await;

    let response = app
        .server
        .get(&format!(
            "/api/v1/assets/{}/ssh-host-key",
            asset.asset.uuid
        ))
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;

    assert_status(&response, 200);
    let json: serde_json::Value = response.json();
    assert_eq!(
        json.get("status").and_then(|v| v.as_str()),
        Some("no_key"),
        "Should return 'no_key' when no host key is stored"
    );
    assert!(
        json.get("fingerprint").is_none(),
        "Should NOT include fingerprint when status is no_key"
    );

    test_db::cleanup(&mut conn).await;
}

/// GET /api/v1/assets/{uuid}/ssh-host-key returns "verified" when a host key
/// is stored without any mismatch flag.
#[tokio::test]
#[serial]
async fn test_ssh_host_key_status_verified() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("admin_hk_verified");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let asset = create_test_ssh_asset(&mut conn, &unique_name("hk-verified")).await;

    // Store a host key in connection_config
    set_connection_config(
        &mut conn,
        asset.asset.uuid,
        serde_json::json!({
            "ssh_host_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAATEST",
            "ssh_host_key_fingerprint": "SHA256:TestFingerprint123"
        }),
    )
    .await;

    let response = app
        .server
        .get(&format!(
            "/api/v1/assets/{}/ssh-host-key",
            asset.asset.uuid
        ))
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;

    assert_status(&response, 200);
    let json: serde_json::Value = response.json();
    assert_eq!(
        json.get("status").and_then(|v| v.as_str()),
        Some("verified"),
        "Should return 'verified' when host key is stored without mismatch"
    );
    assert_eq!(
        json.get("fingerprint").and_then(|v| v.as_str()),
        Some("SHA256:TestFingerprint123"),
        "Should include the stored fingerprint"
    );
    assert_eq!(
        json.get("host_key").and_then(|v| v.as_str()),
        Some("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAATEST"),
        "Should include the stored host key"
    );

    test_db::cleanup(&mut conn).await;
}

/// GET /api/v1/assets/{uuid}/ssh-host-key returns "mismatch" when a host key
/// is stored AND the mismatch flag has been set by a failed connection.
#[tokio::test]
#[serial]
async fn test_ssh_host_key_status_mismatch() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("admin_hk_mismatch");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let asset = create_test_ssh_asset(&mut conn, &unique_name("hk-mismatch")).await;

    // Store a host key with mismatch flag
    set_connection_config(
        &mut conn,
        asset.asset.uuid,
        serde_json::json!({
            "ssh_host_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAOLD",
            "ssh_host_key_fingerprint": "SHA256:OldFingerprint",
            "ssh_host_key_mismatch": true
        }),
    )
    .await;

    let response = app
        .server
        .get(&format!(
            "/api/v1/assets/{}/ssh-host-key",
            asset.asset.uuid
        ))
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;

    assert_status(&response, 200);
    let json: serde_json::Value = response.json();
    assert_eq!(
        json.get("status").and_then(|v| v.as_str()),
        Some("mismatch"),
        "Should return 'mismatch' when ssh_host_key_mismatch flag is true"
    );
    assert_eq!(
        json.get("fingerprint").and_then(|v| v.as_str()),
        Some("SHA256:OldFingerprint"),
        "Should include the stored (old) fingerprint"
    );

    test_db::cleanup(&mut conn).await;
}

/// GET /api/v1/assets/{uuid}/ssh-host-key returns 400 for non-SSH asset types.
#[tokio::test]
#[serial]
async fn test_ssh_host_key_status_rejects_non_ssh() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("admin_hk_rdp");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let rdp_asset = create_test_rdp_asset(&mut conn, &unique_name("hk-rdp")).await;

    let response = app
        .server
        .get(&format!(
            "/api/v1/assets/{}/ssh-host-key",
            rdp_asset.asset.uuid
        ))
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 400 || status == 422,
        "Non-SSH asset should return 400 or 422, got {}",
        status
    );

    test_db::cleanup(&mut conn).await;
}

/// GET /api/v1/assets/{uuid}/ssh-host-key returns 401 without authentication.
#[tokio::test]
#[serial]
async fn test_ssh_host_key_status_requires_auth() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let asset = create_test_ssh_asset(&mut conn, &unique_name("hk-noauth")).await;

    let response = app
        .server
        .get(&format!(
            "/api/v1/assets/{}/ssh-host-key",
            asset.asset.uuid
        ))
        .await;

    assert_status(&response, 401);

    test_db::cleanup(&mut conn).await;
}

/// GET /api/v1/assets/{uuid}/ssh-host-key returns 404 for non-existent asset.
#[tokio::test]
#[serial]
async fn test_ssh_host_key_status_not_found() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("admin_hk_notfound");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let fake_uuid = Uuid::new_v4();

    let response = app
        .server
        .get(&format!("/api/v1/assets/{}/ssh-host-key", fake_uuid))
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;

    assert_status(&response, 404);

    test_db::cleanup(&mut conn).await;
}

/// After storing a host key with mismatch=true, verify that reading the full
/// asset via GET /api/v1/assets/{uuid} also exposes the mismatch in
/// connection_config so consumers can detect it.
#[tokio::test]
#[serial]
async fn test_get_asset_exposes_mismatch_in_connection_config() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("admin_hk_full");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let asset = create_test_ssh_asset(&mut conn, &unique_name("hk-full")).await;

    set_connection_config(
        &mut conn,
        asset.asset.uuid,
        serde_json::json!({
            "ssh_host_key": "ssh-ed25519 AAAATESKEY",
            "ssh_host_key_fingerprint": "SHA256:FP",
            "ssh_host_key_mismatch": true
        }),
    )
    .await;

    let response = app
        .server
        .get(&format!("/api/v1/assets/{}", asset.asset.uuid))
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;

    assert_status(&response, 200);
    let json: serde_json::Value = response.json();
    let config = json.get("connection_config");
    assert!(config.is_some(), "Response should include connection_config");
    let config = config.unwrap();
    assert_eq!(
        config.get("ssh_host_key_mismatch").and_then(|v| v.as_bool()),
        Some(true),
        "connection_config should contain ssh_host_key_mismatch = true"
    );
    assert_eq!(
        config
            .get("ssh_host_key_fingerprint")
            .and_then(|v| v.as_str()),
        Some("SHA256:FP"),
        "connection_config should contain the fingerprint"
    );

    test_db::cleanup(&mut conn).await;
}

/// Verify that the mismatch flag is cleared (via connection_config) when a
/// host key is successfully stored. We simulate this by setting the mismatch
/// flag, then using the update_asset endpoint to clear it.
#[tokio::test]
#[serial]
async fn test_mismatch_flag_cleared_after_update() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("admin_hk_clear");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let asset = create_test_ssh_asset(&mut conn, &unique_name("hk-clear")).await;

    // Set mismatch flag
    set_connection_config(
        &mut conn,
        asset.asset.uuid,
        serde_json::json!({
            "ssh_host_key": "ssh-ed25519 OLD",
            "ssh_host_key_fingerprint": "SHA256:OLD",
            "ssh_host_key_mismatch": true
        }),
    )
    .await;

    // Verify mismatch state via API
    let response = app
        .server
        .get(&format!(
            "/api/v1/assets/{}/ssh-host-key",
            asset.asset.uuid
        ))
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;
    assert_status(&response, 200);
    let json: serde_json::Value = response.json();
    assert_eq!(
        json.get("status").and_then(|v| v.as_str()),
        Some("mismatch")
    );

    // Simulate clearing mismatch by updating connection_config
    // (this is what the fetch handler does when confirm=true)
    set_connection_config(
        &mut conn,
        asset.asset.uuid,
        serde_json::json!({
            "ssh_host_key": "ssh-ed25519 NEW",
            "ssh_host_key_fingerprint": "SHA256:NEW"
        }),
    )
    .await;

    // Verify it's now "verified"
    let response = app
        .server
        .get(&format!(
            "/api/v1/assets/{}/ssh-host-key",
            asset.asset.uuid
        ))
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;
    assert_status(&response, 200);
    let json: serde_json::Value = response.json();
    assert_eq!(
        json.get("status").and_then(|v| v.as_str()),
        Some("verified"),
        "After clearing mismatch flag, status should be 'verified'"
    );
    assert_eq!(
        json.get("fingerprint").and_then(|v| v.as_str()),
        Some("SHA256:NEW"),
        "Fingerprint should be the new one"
    );

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// Malformed UUID Tests
// =============================================================================

/// Test update asset with malformed UUID returns validation error.
#[tokio::test]
#[serial]
async fn test_update_asset_malformed_uuid_returns_validation_error() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin = create_admin_user(
        &mut conn,
        &app.auth_service,
        &unique_name("asset_upd_malformed"),
    )
    .await;

    let response = app
        .server
        .put("/api/v1/assets/invalid-uuid-here")
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .json(&serde_json::json!({
            "name": "Test Asset"
        }))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 400 || status == 422,
        "Malformed UUID should return 400 or 422, got {}",
        status
    );

    test_db::cleanup(&mut conn).await;
}

/// L-2: DELETE /api/v1/assets/{uuid} must return 501 Not Implemented (not 200 OK).
#[tokio::test]
#[serial]
async fn test_delete_asset_returns_501_not_implemented() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("admin_del_asset");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let response = app
        .server
        .delete(&format!("/api/v1/assets/{}", Uuid::new_v4()))
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;

    assert_status(&response, 501);

    test_db::cleanup(&mut conn).await;
}
