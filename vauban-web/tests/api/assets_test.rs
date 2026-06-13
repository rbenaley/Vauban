/// VAUBAN Web - Assets API Integration Tests.
///
/// Tests for /api/v1/assets/* endpoints.
use axum::http::header::{self, COOKIE};
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
        .add_header(header::AUTHORIZATION, app.api_key_header(&user.api_key))
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
        .add_header(header::AUTHORIZATION, app.api_key_header(&user.api_key))
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
        .add_header(header::AUTHORIZATION, app.api_key_header(&user.api_key))
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
        .post("/api/v1/assets/manage")
        .add_header(header::AUTHORIZATION, app.api_key_header(&admin.api_key))
        .json(&json!({
            "name": asset_name,
            "hostname": format!("{}.test.vauban.io", asset_name),
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
        .post("/api/v1/assets/manage")
        .add_header(header::AUTHORIZATION, app.api_key_header(&admin.api_key))
        .json(&json!({
            "name": "test-invalid-port",
            "hostname": "port.test.vauban.io",
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

    // Issue #27: GET single asset by UUID is an admin-zone operation
    // (the user zone only exposes the list filtered by access rules
    // and the connect/request flows). Auth as admin and target the
    // /api/v1/assets/manage/{uuid} sub-tree.
    let admin_name = unique_name("test_admin_get_asset");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let asset = create_test_ssh_asset(&mut conn, &unique_name("test-get-asset")).await;

    let response = app
        .server
        .get(&format!("/api/v1/assets/manage/{}", asset.asset.uuid))
        .add_header(header::AUTHORIZATION, app.api_key_header(&admin.api_key))
        .await;

    assert_status(&response, 200);
    assert_json_has_field(&response, "uuid");

    test_db::cleanup(&mut conn).await;
}

/// Test get non-existent asset.
#[tokio::test]
#[serial]
async fn test_get_asset_not_found() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Issue #27: GET single asset by UUID is admin-only. We test
    // the 404 path for an admin caller (a regular user would get a
    // 403 from the routing-layer gate -- pinned by
    // `manage_assets_anti_enumeration_test`).
    let admin_name = unique_name("test_admin_asset_404");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let fake_uuid = Uuid::new_v4();

    let response = app
        .server
        .get(&format!("/api/v1/assets/manage/{}", fake_uuid))
        .add_header(header::AUTHORIZATION, app.api_key_header(&admin.api_key))
        .await;

    assert_status(&response, 404);

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
        .put(&format!("/api/v1/assets/manage/{}", asset.asset.uuid))
        .add_header(header::AUTHORIZATION, app.api_key_header(&admin.api_key))
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
        .put(&format!("/api/v1/assets/manage/{}", asset.asset.uuid))
        .add_header(header::AUTHORIZATION, app.api_key_header(&admin.api_key))
        .json(&json!({
            "name": "multi-updated-asset",
            "port": 2222,
            "status": "maintenance"
        }))
        .await;

    // Assert: 200 OK with updated fields in response
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
        .put(&format!("/api/v1/assets/manage/{}", asset.asset.uuid))
        .add_header(header::AUTHORIZATION, app.api_key_header(&admin.api_key))
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

/// Test update asset with simple field change.
#[tokio::test]
#[serial]
async fn test_update_asset_simple_field() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("test_admin_checkbox");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let asset = create_test_ssh_asset(&mut conn, &unique_name("test-checkbox-asset")).await;

    let response = app
        .server
        .put(&format!("/api/v1/assets/manage/{}", asset.asset.uuid))
        .add_header(header::AUTHORIZATION, app.api_key_header(&admin.api_key))
        .json(&serde_json::json!({
            "status": "maintenance"
        }))
        .await;

    assert_status(&response, 200);

    use vauban_web::schema::assets::dsl::{assets, status, uuid};
    let db_status: String = unwrap_ok!(
        assets
            .filter(uuid.eq(asset.asset.uuid))
            .select(status)
            .first(&mut conn)
            .await
    );

    assert_eq!(db_status, "maintenance");

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
        .put(&format!("/api/v1/assets/manage/{}", asset.asset.uuid))
        .add_header(header::AUTHORIZATION, app.api_key_header(&admin.api_key))
        .json(&serde_json::json!({
            "name": updated_name,
            "hostname": updated_hostname,
            "port": "8022",
            "status": "maintenance",
            "description": "Updated via form"
        }))
        .await;

    assert_status(&response, 200);

    use vauban_web::schema::assets::dsl::*;
    let (db_name, db_hostname, db_port, db_status): (String, String, i32, String) = unwrap_ok!(
        assets
            .filter(uuid.eq(asset.asset.uuid))
            .select((name, hostname, port, status))
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
            .get(&format!("/api/v1/assets/manage/{}", bad_uuid))
            .add_header(header::AUTHORIZATION, app.api_key_header(&admin.api_key))
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
// SSH Host Key Status API Tests (Three States)
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
            "/api/v1/assets/manage/{}/ssh-host-key",
            asset.asset.uuid
        ))
        .add_header(header::AUTHORIZATION, app.api_key_header(&admin.api_key))
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
            "/api/v1/assets/manage/{}/ssh-host-key",
            asset.asset.uuid
        ))
        .add_header(header::AUTHORIZATION, app.api_key_header(&admin.api_key))
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
            "/api/v1/assets/manage/{}/ssh-host-key",
            asset.asset.uuid
        ))
        .add_header(header::AUTHORIZATION, app.api_key_header(&admin.api_key))
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
            "/api/v1/assets/manage/{}/ssh-host-key",
            rdp_asset.asset.uuid
        ))
        .add_header(header::AUTHORIZATION, app.api_key_header(&admin.api_key))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 400 || status == 422,
        "Non-SSH asset should return 400 or 422, got {}",
        status
    );

    test_db::cleanup(&mut conn).await;
}

/// GET /api/v1/assets/manage/{uuid}/ssh-host-key without auth must
/// be denied. Issue #27 mounted this route under the admin nest, so
/// the `require_assets_manage` route_layer rejects with 403 before
/// the AuthUser extractor would have rejected with 401. We accept
/// either: both are valid "you cannot reach this" answers and
/// 403-first is intentional anti-enumeration.
#[tokio::test]
#[serial]
async fn test_ssh_host_key_status_requires_auth() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let asset = create_test_ssh_asset(&mut conn, &unique_name("hk-noauth")).await;

    let response = app
        .server
        .get(&format!(
            "/api/v1/assets/manage/{}/ssh-host-key",
            asset.asset.uuid
        ))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 401 || status == 403,
        "Expected 401 or 403 without auth, got {}",
        status
    );

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
        .get(&format!("/api/v1/assets/manage/{}/ssh-host-key", fake_uuid))
        .add_header(header::AUTHORIZATION, app.api_key_header(&admin.api_key))
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
        .get(&format!("/api/v1/assets/manage/{}", asset.asset.uuid))
        .add_header(header::AUTHORIZATION, app.api_key_header(&admin.api_key))
        .await;

    assert_status(&response, 200);
    let json: serde_json::Value = response.json();
    let config = json.get("connection_config");
    assert!(
        config.is_some(),
        "Response should include connection_config"
    );
    let config = config.unwrap();
    assert_eq!(
        config
            .get("ssh_host_key_mismatch")
            .and_then(|v| v.as_bool()),
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
            "/api/v1/assets/manage/{}/ssh-host-key",
            asset.asset.uuid
        ))
        .add_header(header::AUTHORIZATION, app.api_key_header(&admin.api_key))
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
            "/api/v1/assets/manage/{}/ssh-host-key",
            asset.asset.uuid
        ))
        .add_header(header::AUTHORIZATION, app.api_key_header(&admin.api_key))
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
        .put("/api/v1/assets/manage/invalid-uuid-here")
        .add_header(header::AUTHORIZATION, app.api_key_header(&admin.api_key))
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

/// DELETE /api/v1/assets/{uuid} must return 501 Not Implemented (not 200 OK).
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
        .add_header(header::AUTHORIZATION, app.api_key_header(&admin.api_key))
        .await;

    assert_status(&response, 501);

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// Issue #22 - Audit actor stamping (created_by_id / updated_by_id)
// =============================================================================
//
// These tests close the loop on the IPC + DB-write wiring added for
// issue #22: a `POST /api/v1/assets/manage` MUST stamp both audit
// columns with the caller's numeric `users.id`, a subsequent `PUT`
// MUST re-stamp `updated_by_id` only (preserving the original
// creator), and the rendered HTML detail page MUST surface the
// resolved `username` for the operator. Without this end-to-end
// coverage we can ship a backend that silently leaves the columns
// `NULL`, which is exactly what regressed during the IPC migration.

/// `POST /api/v1/assets/manage` MUST stamp `created_by_id` and
/// `updated_by_id` with the caller's `users.id`, resolved from the
/// JWT `sub` claim through `services::audit_authors::resolve_actor_id`.
#[tokio::test]
#[serial]
async fn test_create_asset_api_stamps_audit_actor_pair() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin = create_admin_user(
        &mut conn,
        &app.auth_service,
        &unique_name("audit_create_admin"),
    )
    .await;

    let asset_name = unique_name("audit-asset-create");
    let response = app
        .server
        .post("/api/v1/assets/manage")
        .add_header(header::AUTHORIZATION, app.api_key_header(&admin.api_key))
        .json(&json!({
            "name": asset_name,
            "hostname": format!("{}.audit.test", asset_name),
            "port": 22,
            "asset_type": "ssh",
            "status": "online"
        }))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 200 || status == 201,
        "Expected 2xx, got {}",
        status
    );
    let body: serde_json::Value = response.json();
    let asset_uuid = Uuid::parse_str(body["uuid"].as_str().expect("response carries uuid"))
        .expect("uuid is valid");

    use vauban_web::schema::assets::dsl as a;
    let (created_by, updated_by): (Option<i32>, Option<i32>) = unwrap_ok!(
        a::assets
            .filter(a::uuid.eq(asset_uuid))
            .select((a::created_by_id, a::updated_by_id))
            .first(&mut conn)
            .await
    );
    assert_eq!(
        created_by,
        Some(admin.user.id),
        "created_by_id MUST equal the calling admin's users.id"
    );
    assert_eq!(
        updated_by,
        Some(admin.user.id),
        "updated_by_id MUST equal the calling admin's users.id on creation"
    );

    test_db::cleanup(&mut conn).await;
}

/// `PUT /api/v1/assets/manage/{uuid}` MUST re-stamp `updated_by_id`
/// with the caller while leaving `created_by_id` untouched, so a
/// later admin "fixing a typo" never erases the original creator
/// from the audit trail.
#[tokio::test]
#[serial]
async fn test_update_asset_api_restamps_only_updated_by() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let creator =
        create_admin_user(&mut conn, &app.auth_service, &unique_name("audit_creator")).await;
    let editor =
        create_admin_user(&mut conn, &app.auth_service, &unique_name("audit_editor")).await;

    let asset_name = unique_name("audit-asset-update");
    let create_resp = app
        .server
        .post("/api/v1/assets/manage")
        .add_header(header::AUTHORIZATION, app.api_key_header(&creator.api_key))
        .json(&json!({
            "name": asset_name,
            "hostname": format!("{}.audit.test", asset_name),
            "port": 22,
            "asset_type": "ssh",
            "status": "online"
        }))
        .await;
    let create_status = create_resp.status_code().as_u16();
    assert!(create_status == 200 || create_status == 201);
    let asset_uuid = Uuid::parse_str(
        create_resp.json::<serde_json::Value>()["uuid"]
            .as_str()
            .expect("uuid"),
    )
    .expect("uuid");

    let update_resp = app
        .server
        .put(&format!("/api/v1/assets/manage/{}", asset_uuid))
        .add_header(header::AUTHORIZATION, app.api_key_header(&editor.api_key))
        .json(&json!({
            "status": "maintenance"
        }))
        .await;
    assert_status(&update_resp, 200);

    use vauban_web::schema::assets::dsl as a;
    let (created_by, updated_by): (Option<i32>, Option<i32>) = unwrap_ok!(
        a::assets
            .filter(a::uuid.eq(asset_uuid))
            .select((a::created_by_id, a::updated_by_id))
            .first(&mut conn)
            .await
    );
    assert_eq!(
        created_by,
        Some(creator.user.id),
        "PUT MUST NOT rewrite created_by_id"
    );
    assert_eq!(
        updated_by,
        Some(editor.user.id),
        "PUT MUST re-stamp updated_by_id with the editor"
    );

    test_db::cleanup(&mut conn).await;
}

/// `GET /assets/manage/{uuid}` (HTML) MUST render the resolved
/// `username` for both audit actors. This is the user-visible
/// proof that the full chain works: write-side stamping (this
/// test creates by API), join in `manage_assets::asset_detail`
/// against `users`, and Askama rendering of `AuthorRef.username`.
///
/// Aligned with the approval-decision UI which also surfaces the
/// stable login handle (not `first_name + last_name`).
#[tokio::test]
#[serial]
async fn test_asset_detail_html_renders_audit_usernames() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let creator_name = unique_name("audit_render_creator");
    let editor_name = unique_name("audit_render_editor");
    let creator = create_admin_user(&mut conn, &app.auth_service, &creator_name).await;
    let editor = create_admin_user(&mut conn, &app.auth_service, &editor_name).await;

    let asset_name = unique_name("audit-render-asset");
    let create_resp = app
        .server
        .post("/api/v1/assets/manage")
        .add_header(header::AUTHORIZATION, app.api_key_header(&creator.api_key))
        .json(&json!({
            "name": asset_name,
            "hostname": format!("{}.audit.test", asset_name),
            "port": 22,
            "asset_type": "ssh",
            "status": "online"
        }))
        .await;
    let asset_uuid = Uuid::parse_str(
        create_resp.json::<serde_json::Value>()["uuid"]
            .as_str()
            .expect("uuid"),
    )
    .expect("uuid");

    let _ = app
        .server
        .put(&format!("/api/v1/assets/manage/{}", asset_uuid))
        .add_header(header::AUTHORIZATION, app.api_key_header(&editor.api_key))
        .json(&json!({ "status": "maintenance" }))
        .await;

    let html_resp = app
        .server
        .get(&format!("/assets/manage/{}", asset_uuid))
        .add_header(COOKIE, format!("access_token={}", editor.token))
        .await;
    assert_status(&html_resp, 200);
    let body = html_resp.text();

    assert!(
        body.contains("Created by"),
        "detail page must label the created_by row"
    );
    assert!(
        body.contains("Updated by"),
        "detail page must label the updated_by row"
    );
    assert!(
        body.contains(&creator_name),
        "detail page must surface the creator username `{}` in the audit metadata; \
         got HTML excerpt around metadata: <missing>",
        creator_name
    );
    assert!(
        body.contains(&editor_name),
        "detail page must surface the editor username `{}` in the audit metadata",
        editor_name
    );
    assert!(
        !body.contains("AuthorRef {"),
        "detail page must never leak the AuthorRef Debug repr"
    );

    test_db::cleanup(&mut conn).await;
}

/// `GET /assets/manage/deleted` MUST surface the operator that
/// soft-deleted each tombstone. The chain under test:
///   1. admin A creates the asset (POST API),
///   2. admin B soft-deletes the asset (DELETE web form),
///   3. soft-delete re-stamps `updated_by_id = B.id`,
///   4. the deleted-list page joins on `users` and renders B's
///      `username` next to the row.
///
/// Without this surfacing, audit reviewers cannot answer the basic
/// "who deleted this?" question — the whole point of issue #22 on
/// the tombstone view.
#[tokio::test]
#[serial]
async fn test_deleted_list_surfaces_deleting_operator_username() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let creator_name = unique_name("audit_del_creator");
    let deleter_name = unique_name("audit_del_deleter");
    let creator = create_admin_user(&mut conn, &app.auth_service, &creator_name).await;
    let deleter = create_admin_user(&mut conn, &app.auth_service, &deleter_name).await;

    let asset_name = unique_name("audit-del-asset");
    let create_resp = app
        .server
        .post("/api/v1/assets/manage")
        .add_header(header::AUTHORIZATION, app.api_key_header(&creator.api_key))
        .json(&json!({
            "name": asset_name,
            "hostname": format!("{}.audit.test", asset_name),
            "port": 22,
            "asset_type": "ssh",
            "status": "online"
        }))
        .await;
    let asset_uuid = Uuid::parse_str(
        create_resp.json::<serde_json::Value>()["uuid"]
            .as_str()
            .expect("uuid"),
    )
    .expect("uuid");

    // Soft-delete via the web form so the operator UUID flows
    // through `WebAuthUser` exactly the way the IDE-driven flow
    // does. The admin zone has no API DELETE endpoint by design
    // (audit-friendly: every soft-delete carries a CSRF receipt
    // and a flash redirect target).
    let csrf = app.generate_csrf_token();
    let cookie = format!("access_token={}; __vauban_csrf={}", deleter.token, csrf);
    let delete_resp = app
        .server
        .post(&format!("/assets/manage/{}/delete", asset_uuid))
        .add_header(COOKIE, cookie)
        .form(&[("csrf_token", csrf.as_str())])
        .await;
    let del_status = delete_resp.status_code().as_u16();
    assert!(
        (200..400).contains(&del_status),
        "POST /assets/manage/{{uuid}}/delete expected 2xx/3xx, got {}",
        del_status
    );

    use vauban_web::schema::assets::dsl as a;
    let (is_deleted, updated_by): (bool, Option<i32>) = unwrap_ok!(
        a::assets
            .filter(a::uuid.eq(asset_uuid))
            .select((a::is_deleted, a::updated_by_id))
            .first(&mut conn)
            .await
    );
    assert!(is_deleted, "asset must be tombstoned");
    assert_eq!(
        updated_by,
        Some(deleter.user.id),
        "soft-delete MUST re-stamp updated_by_id with the deleting operator"
    );

    let html_resp = app
        .server
        .get("/assets/manage/deleted")
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", deleter.token, csrf),
        )
        .await;
    assert_status(&html_resp, 200);
    let body = html_resp.text();

    assert!(
        body.contains(&asset_name),
        "tombstone row must reference the deleted asset name"
    );
    assert!(
        body.contains(&deleter_name),
        "deleted-list page MUST surface the deleter username `{}`; without it the \
         auditor cannot answer 'who deleted this asset?'",
        deleter_name
    );
    assert!(
        !body.contains("AuthorRef {"),
        "deleted-list MUST NEVER leak the AuthorRef Debug repr"
    );

    test_db::cleanup(&mut conn).await;
}
