/// VAUBAN Web - Access Control Integration Tests.
///
/// Tests for access rule enforcement on asset visibility and session authorization.
use axum::http::header;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use serde_json::json;
use serial_test::serial;
use uuid::Uuid;

use crate::common::{TestApp, assertions::*, test_db};
use vauban_web::models::asset::AssetType;

use crate::fixtures::{
    add_user_to_vauban_group, create_admin_user, create_expired_access_rule,
    create_future_access_rule, create_inactive_access_rule, create_simple_ssh_asset,
    create_test_access_rule, create_test_access_rule_with_constraints, create_test_asset_group,
    create_test_asset_in_group, create_test_asset_in_group_with_type, create_test_user,
    create_test_vauban_group, get_asset_uuid, unique_name,
};

/// Helper to create a staff-only user (is_staff=true, is_superuser=false).
async fn create_staff_user(
    conn: &mut diesel_async::AsyncPgConnection,
    auth_service: &vauban_web::services::auth::AuthService,
    username: &str,
) -> crate::fixtures::TestUser {
    use vauban_web::models::user::{AuthSource, NewUser, User};
    use vauban_web::schema::users;

    let password = "StaffPassword123!";
    let password_hash = auth_service.hash_password(password).unwrap();
    let user_uuid = Uuid::new_v4();

    let new_user = NewUser {
        uuid: user_uuid,
        username: username.to_string(),
        email: format!("{}@test.vauban.io", username),
        password_hash,
        first_name: Some("Staff".to_string()),
        last_name: Some("User".to_string()),
        phone: None,
        is_active: true,
        is_staff: true,
        is_superuser: false,
        is_service_account: false,
        mfa_enabled: false,
        mfa_enforced: false,
        mfa_secret: None,
        preferences: serde_json::json!({}),
        auth_source: AuthSource::Local,
        external_id: None,
    };

    let user: User = diesel::insert_into(users::table)
        .values(&new_user)
        .get_result(conn)
        .await
        .expect("Failed to create staff user");

    use sha3::{Digest, Sha3_256};
    let session_uuid = Uuid::new_v4();
    let token = auth_service
        .generate_access_token(
            &user.uuid.to_string(),
            &user.username,
            true,
            false,
            true,
            Some(session_uuid),
        )
        .expect("Failed to generate token");

    let mut hasher = Sha3_256::new();
    hasher.update(token.as_bytes());
    let token_hash = format!("{:x}", hasher.finalize());

    let ip: ipnetwork::IpNetwork = "127.0.0.1".parse().unwrap();
    use vauban_web::models::auth_session::NewAuthSession;
    use vauban_web::schema::auth_sessions;
    let new_session = NewAuthSession {
        uuid: session_uuid,
        user_id: user.id,
        token_hash: token_hash.clone(),
        ip_address: ip,
        user_agent: Some("Test Client".to_string()),
        device_info: format!("Test/{}", &token_hash[..8]),
        expires_at: chrono::Utc::now() + chrono::Duration::hours(24),
        is_current: true,
    };
    diesel::insert_into(auth_sessions::table)
        .values(&new_session)
        .execute(conn)
        .await
        .ok();

    crate::fixtures::TestUser {
        user,
        password: password.to_string(),
        token,
    }
}

/// Helper to create a superuser-only user (is_superuser=true, is_staff=false).
async fn create_superuser_only(
    conn: &mut diesel_async::AsyncPgConnection,
    auth_service: &vauban_web::services::auth::AuthService,
    username: &str,
) -> crate::fixtures::TestUser {
    use vauban_web::models::user::{AuthSource, NewUser, User};
    use vauban_web::schema::users;

    let password = "SuperPassword123!";
    let password_hash = auth_service.hash_password(password).unwrap();
    let user_uuid = Uuid::new_v4();

    let new_user = NewUser {
        uuid: user_uuid,
        username: username.to_string(),
        email: format!("{}@test.vauban.io", username),
        password_hash,
        first_name: Some("Super".to_string()),
        last_name: Some("User".to_string()),
        phone: None,
        is_active: true,
        is_staff: false,
        is_superuser: true,
        is_service_account: false,
        mfa_enabled: false,
        mfa_enforced: false,
        mfa_secret: None,
        preferences: serde_json::json!({}),
        auth_source: AuthSource::Local,
        external_id: None,
    };

    let user: User = diesel::insert_into(users::table)
        .values(&new_user)
        .get_result(conn)
        .await
        .expect("Failed to create superuser");

    use sha3::{Digest, Sha3_256};
    let session_uuid = Uuid::new_v4();
    let token = auth_service
        .generate_access_token(
            &user.uuid.to_string(),
            &user.username,
            true,
            true,
            false,
            Some(session_uuid),
        )
        .expect("Failed to generate token");

    let mut hasher = Sha3_256::new();
    hasher.update(token.as_bytes());
    let token_hash = format!("{:x}", hasher.finalize());

    let ip: ipnetwork::IpNetwork = "127.0.0.1".parse().unwrap();
    use vauban_web::models::auth_session::NewAuthSession;
    use vauban_web::schema::auth_sessions;
    let new_session = NewAuthSession {
        uuid: session_uuid,
        user_id: user.id,
        token_hash: token_hash.clone(),
        ip_address: ip,
        user_agent: Some("Test Client".to_string()),
        device_info: format!("Test/{}", &token_hash[..8]),
        expires_at: chrono::Utc::now() + chrono::Duration::hours(24),
        is_current: true,
    };
    diesel::insert_into(auth_sessions::table)
        .values(&new_session)
        .execute(conn)
        .await
        .ok();

    crate::fixtures::TestUser {
        user,
        password: password.to_string(),
        token,
    }
}

// =============================================================================
// Asset Visibility Tests
// =============================================================================

/// Regular user with a valid access rule should see assets in the linked group.
#[tokio::test]
#[serial]
async fn test_user_with_access_rule_sees_assets() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("test_ac_sees");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;

    let ug = create_test_vauban_group(&mut conn, "test-ug-sees").await;
    let ag = create_test_asset_group(&mut conn, "test-ag-sees").await;

    add_user_to_vauban_group(&mut conn, user.user.id, &ug).await;
    let _asset_id = create_test_asset_in_group(&mut conn, "test-visible", user.user.id, &ag).await;
    create_test_access_rule(&mut conn, &ug, &ag, &["ssh"]).await;

    let response = app
        .server
        .get("/api/v1/assets")
        .add_header(header::AUTHORIZATION, app.auth_header(&user.token))
        .await;

    assert_status(&response, 200);
    let json: Vec<serde_json::Value> = response.json();
    assert!(
        !json.is_empty(),
        "User with access rule should see at least one asset"
    );

    test_db::cleanup(&mut conn).await;
}

/// Regular user without any access rule should see no assets.
#[tokio::test]
#[serial]
async fn test_user_without_access_rule_sees_no_assets() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("test_ac_nosee");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;

    // Create an asset in a group, but do NOT create an access rule for this user
    let ag = create_test_asset_group(&mut conn, "test-ag-nosee").await;
    let admin_name = unique_name("test_ac_nosee_adm");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    create_test_asset_in_group(&mut conn, "test-invisible", admin.user.id, &ag).await;

    let response = app
        .server
        .get("/api/v1/assets")
        .add_header(header::AUTHORIZATION, app.auth_header(&user.token))
        .await;

    assert_status(&response, 200);
    let json: Vec<serde_json::Value> = response.json();
    assert!(
        json.is_empty(),
        "User without access rule should see no assets, got {}",
        json.len()
    );

    test_db::cleanup(&mut conn).await;
}

/// User in multiple groups sees the union of assets from all access rules.
#[tokio::test]
#[serial]
async fn test_user_in_multiple_groups_sees_union() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("test_ac_union");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;

    // Group 1
    let ug1 = create_test_vauban_group(&mut conn, "test-ug-union1").await;
    let ag1 = create_test_asset_group(&mut conn, "test-ag-union1").await;
    add_user_to_vauban_group(&mut conn, user.user.id, &ug1).await;
    create_test_asset_in_group(&mut conn, "test-union-a1", user.user.id, &ag1).await;
    create_test_access_rule(&mut conn, &ug1, &ag1, &["ssh"]).await;

    // Group 2
    let ug2 = create_test_vauban_group(&mut conn, "test-ug-union2").await;
    let ag2 = create_test_asset_group(&mut conn, "test-ag-union2").await;
    add_user_to_vauban_group(&mut conn, user.user.id, &ug2).await;
    create_test_asset_in_group(&mut conn, "test-union-a2", user.user.id, &ag2).await;
    create_test_access_rule(&mut conn, &ug2, &ag2, &["ssh"]).await;

    let response = app
        .server
        .get("/api/v1/assets")
        .add_header(header::AUTHORIZATION, app.auth_header(&user.token))
        .await;

    assert_status(&response, 200);
    let json: Vec<serde_json::Value> = response.json();
    assert!(
        json.len() >= 2,
        "User in 2 groups should see at least 2 assets, got {}",
        json.len()
    );

    test_db::cleanup(&mut conn).await;
}

/// Superuser should see all assets regardless of access rules.
#[tokio::test]
#[serial]
async fn test_superuser_sees_all_assets() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("test_ac_su_all");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    // Create an asset that has no access rule linking to anyone
    let ag = create_test_asset_group(&mut conn, "test-ag-suall").await;
    create_test_asset_in_group(&mut conn, "test-su-visible", admin.user.id, &ag).await;

    let su_name = unique_name("test_ac_su_user");
    let su = create_superuser_only(&mut conn, &app.auth_service, &su_name).await;

    let response = app
        .server
        .get("/api/v1/assets")
        .add_header(header::AUTHORIZATION, app.auth_header(&su.token))
        .await;

    assert_status(&response, 200);
    let json: Vec<serde_json::Value> = response.json();
    assert!(!json.is_empty(), "Superuser should see all assets");

    test_db::cleanup(&mut conn).await;
}

/// Staff user should see all assets regardless of access rules.
#[tokio::test]
#[serial]
async fn test_staff_sees_all_assets() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("test_ac_staff_setup");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let ag = create_test_asset_group(&mut conn, "test-ag-staffall").await;
    create_test_asset_in_group(&mut conn, "test-staff-visible", admin.user.id, &ag).await;

    let staff_name = unique_name("test_ac_staff_user");
    let staff = create_staff_user(&mut conn, &app.auth_service, &staff_name).await;

    let response = app
        .server
        .get("/api/v1/assets")
        .add_header(header::AUTHORIZATION, app.auth_header(&staff.token))
        .await;

    assert_status(&response, 200);
    let json: Vec<serde_json::Value> = response.json();
    assert!(!json.is_empty(), "Staff user should see all assets");

    test_db::cleanup(&mut conn).await;
}

/// An asset with no asset group membership is not reachable via access rules but superusers can see it.
#[tokio::test]
#[serial]
async fn test_asset_without_group_not_visible_via_access_rules() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("test_ac_nogrp_u");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;

    // Create asset with no group membership (no row in asset_asset_groups)
    let nogrp_name = unique_name("test-nogrp-asset");
    create_simple_ssh_asset(&mut conn, &nogrp_name, user.user.id).await;

    // Give user some access rule to a different group
    let ug = create_test_vauban_group(&mut conn, "test-ug-nogrp").await;
    let ag = create_test_asset_group(&mut conn, "test-ag-nogrp").await;
    add_user_to_vauban_group(&mut conn, user.user.id, &ug).await;
    create_test_access_rule(&mut conn, &ug, &ag, &["ssh"]).await;

    // Regular user should NOT see ungrouped asset
    let response = app
        .server
        .get("/api/v1/assets")
        .add_header(header::AUTHORIZATION, app.auth_header(&user.token))
        .await;

    assert_status(&response, 200);
    let user_assets: Vec<serde_json::Value> = response.json();
    let sees_ungrouped_by_name = user_assets.iter().any(|a| {
        a.get("name")
            .and_then(|v| v.as_str())
            .is_some_and(|n| n == nogrp_name.as_str())
    });
    assert!(
        !sees_ungrouped_by_name,
        "Regular user should NOT see assets without any asset group"
    );

    // Superuser SHOULD see the ungrouped asset
    let su_name = unique_name("test_ac_nogrp_su");
    let su = create_superuser_only(&mut conn, &app.auth_service, &su_name).await;

    let response = app
        .server
        .get("/api/v1/assets")
        .add_header(header::AUTHORIZATION, app.auth_header(&su.token))
        .await;

    assert_status(&response, 200);
    let su_assets: Vec<serde_json::Value> = response.json();
    assert!(
        !su_assets.is_empty(),
        "Superuser should see all assets including ungrouped ones"
    );

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// Protocol-Based Visibility Tests
// =============================================================================

/// SSH-only access rule should hide RDP assets in the same group.
/// This is the exact bug reported by users: an RDP asset appeared in the list
/// even though only SSH was allowed by the access rule.
#[tokio::test]
#[serial]
async fn test_ssh_only_rule_hides_rdp_assets() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("test_proto_flt_adm");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let username = unique_name("test_proto_flt_usr");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;

    let ug = create_test_vauban_group(&mut conn, "test-ug-proto-flt").await;
    let ag = create_test_asset_group(&mut conn, &unique_name("test-ag-proto-flt")).await;
    add_user_to_vauban_group(&mut conn, user.user.id, &ug).await;

    let ssh_id = create_test_asset_in_group_with_type(
        &mut conn,
        "proto-flt-ssh",
        admin.user.id,
        &ag,
        AssetType::Ssh,
    )
    .await;
    let rdp_id = create_test_asset_in_group_with_type(
        &mut conn,
        "proto-flt-rdp",
        admin.user.id,
        &ag,
        AssetType::Rdp,
    )
    .await;

    create_test_access_rule(&mut conn, &ug, &ag, &["ssh"]).await;

    let response = app
        .server
        .get("/api/v1/assets")
        .add_header(header::AUTHORIZATION, app.auth_header(&user.token))
        .await;

    assert_status(&response, 200);
    let json: Vec<serde_json::Value> = response.json();

    let ssh_uuid = get_asset_uuid(&mut conn, ssh_id).await.to_string();
    let rdp_uuid = get_asset_uuid(&mut conn, rdp_id).await.to_string();

    let has_ssh = json
        .iter()
        .any(|a| a.get("uuid").and_then(|v| v.as_str()) == Some(&ssh_uuid));
    let has_rdp = json
        .iter()
        .any(|a| a.get("uuid").and_then(|v| v.as_str()) == Some(&rdp_uuid));

    assert!(has_ssh, "SSH asset should be visible with SSH-only rule");
    assert!(
        !has_rdp,
        "RDP asset should NOT be visible with SSH-only rule"
    );

    test_db::cleanup(&mut conn).await;
}

/// RDP-only access rule should hide SSH assets in the same group.
#[tokio::test]
#[serial]
async fn test_rdp_only_rule_hides_ssh_assets() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("test_rdp_flt_adm");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let username = unique_name("test_rdp_flt_usr");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;

    let ug = create_test_vauban_group(&mut conn, "test-ug-rdp-flt").await;
    let ag = create_test_asset_group(&mut conn, &unique_name("test-ag-rdp-flt")).await;
    add_user_to_vauban_group(&mut conn, user.user.id, &ug).await;

    let ssh_id = create_test_asset_in_group_with_type(
        &mut conn,
        "rdp-flt-ssh",
        admin.user.id,
        &ag,
        AssetType::Ssh,
    )
    .await;
    let rdp_id = create_test_asset_in_group_with_type(
        &mut conn,
        "rdp-flt-rdp",
        admin.user.id,
        &ag,
        AssetType::Rdp,
    )
    .await;

    create_test_access_rule(&mut conn, &ug, &ag, &["rdp"]).await;

    let response = app
        .server
        .get("/api/v1/assets")
        .add_header(header::AUTHORIZATION, app.auth_header(&user.token))
        .await;

    assert_status(&response, 200);
    let json: Vec<serde_json::Value> = response.json();

    let ssh_uuid = get_asset_uuid(&mut conn, ssh_id).await.to_string();
    let rdp_uuid = get_asset_uuid(&mut conn, rdp_id).await.to_string();

    let has_ssh = json
        .iter()
        .any(|a| a.get("uuid").and_then(|v| v.as_str()) == Some(&ssh_uuid));
    let has_rdp = json
        .iter()
        .any(|a| a.get("uuid").and_then(|v| v.as_str()) == Some(&rdp_uuid));

    assert!(
        !has_ssh,
        "SSH asset should NOT be visible with RDP-only rule"
    );
    assert!(has_rdp, "RDP asset should be visible with RDP-only rule");

    test_db::cleanup(&mut conn).await;
}

/// Rule with both SSH and RDP should show both asset types.
#[tokio::test]
#[serial]
async fn test_dual_protocol_rule_shows_both_types() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("test_dual_flt_adm");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let username = unique_name("test_dual_flt_usr");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;

    let ug = create_test_vauban_group(&mut conn, "test-ug-dual-flt").await;
    let ag = create_test_asset_group(&mut conn, &unique_name("test-ag-dual-flt")).await;
    add_user_to_vauban_group(&mut conn, user.user.id, &ug).await;

    let ssh_id = create_test_asset_in_group_with_type(
        &mut conn,
        "dual-flt-ssh",
        admin.user.id,
        &ag,
        AssetType::Ssh,
    )
    .await;
    let rdp_id = create_test_asset_in_group_with_type(
        &mut conn,
        "dual-flt-rdp",
        admin.user.id,
        &ag,
        AssetType::Rdp,
    )
    .await;

    create_test_access_rule(&mut conn, &ug, &ag, &["ssh", "rdp"]).await;

    let response = app
        .server
        .get("/api/v1/assets")
        .add_header(header::AUTHORIZATION, app.auth_header(&user.token))
        .await;

    assert_status(&response, 200);
    let json: Vec<serde_json::Value> = response.json();

    let ssh_uuid = get_asset_uuid(&mut conn, ssh_id).await.to_string();
    let rdp_uuid = get_asset_uuid(&mut conn, rdp_id).await.to_string();

    let has_ssh = json
        .iter()
        .any(|a| a.get("uuid").and_then(|v| v.as_str()) == Some(&ssh_uuid));
    let has_rdp = json
        .iter()
        .any(|a| a.get("uuid").and_then(|v| v.as_str()) == Some(&rdp_uuid));

    assert!(
        has_ssh,
        "SSH asset should be visible with dual-protocol rule"
    );
    assert!(
        has_rdp,
        "RDP asset should be visible with dual-protocol rule"
    );

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// Temporal Validity Tests
// =============================================================================

/// Expired access rule should not grant visibility to assets.
#[tokio::test]
#[serial]
async fn test_expired_access_rule_hides_assets() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("test_ac_expired");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;

    let ug = create_test_vauban_group(&mut conn, "test-ug-expired").await;
    let ag = create_test_asset_group(&mut conn, "test-ag-expired").await;
    add_user_to_vauban_group(&mut conn, user.user.id, &ug).await;
    create_test_asset_in_group(&mut conn, "test-expired-asset", user.user.id, &ag).await;
    create_expired_access_rule(&mut conn, &ug, &ag).await;

    let response = app
        .server
        .get("/api/v1/assets")
        .add_header(header::AUTHORIZATION, app.auth_header(&user.token))
        .await;

    assert_status(&response, 200);
    let json: Vec<serde_json::Value> = response.json();
    assert!(
        json.is_empty(),
        "Expired access rule should not grant asset visibility, got {} assets",
        json.len()
    );

    test_db::cleanup(&mut conn).await;
}

/// Future access rule (valid_from in the future) should not grant visibility.
#[tokio::test]
#[serial]
async fn test_future_access_rule_hides_assets() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("test_ac_future");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;

    let ug = create_test_vauban_group(&mut conn, "test-ug-future").await;
    let ag = create_test_asset_group(&mut conn, "test-ag-future").await;
    add_user_to_vauban_group(&mut conn, user.user.id, &ug).await;
    create_test_asset_in_group(&mut conn, "test-future-asset", user.user.id, &ag).await;
    create_future_access_rule(&mut conn, &ug, &ag).await;

    let response = app
        .server
        .get("/api/v1/assets")
        .add_header(header::AUTHORIZATION, app.auth_header(&user.token))
        .await;

    assert_status(&response, 200);
    let json: Vec<serde_json::Value> = response.json();
    assert!(
        json.is_empty(),
        "Future access rule should not grant asset visibility, got {} assets",
        json.len()
    );

    test_db::cleanup(&mut conn).await;
}

/// Inactive access rule (is_active=false) should not grant visibility.
#[tokio::test]
#[serial]
async fn test_inactive_access_rule_hides_assets() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("test_ac_inactive");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;

    let ug = create_test_vauban_group(&mut conn, "test-ug-inactive").await;
    let ag = create_test_asset_group(&mut conn, "test-ag-inactive").await;
    add_user_to_vauban_group(&mut conn, user.user.id, &ug).await;
    create_test_asset_in_group(&mut conn, "test-inactive-asset", user.user.id, &ag).await;
    create_inactive_access_rule(&mut conn, &ug, &ag).await;

    let response = app
        .server
        .get("/api/v1/assets")
        .add_header(header::AUTHORIZATION, app.auth_header(&user.token))
        .await;

    assert_status(&response, 200);
    let json: Vec<serde_json::Value> = response.json();
    assert!(
        json.is_empty(),
        "Inactive access rule should not grant asset visibility, got {} assets",
        json.len()
    );

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// Session Authorization Tests
// =============================================================================

/// User with a valid SSH access rule can create an SSH session.
#[tokio::test]
#[serial]
async fn test_session_creation_with_valid_access_rule() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("test_ac_sess_ok");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;

    let ug = create_test_vauban_group(&mut conn, "test-ug-sess-ok").await;
    let ag = create_test_asset_group(&mut conn, "test-ag-sess-ok").await;
    add_user_to_vauban_group(&mut conn, user.user.id, &ug).await;
    let asset_id =
        create_test_asset_in_group(&mut conn, "test-sess-ok-asset", user.user.id, &ag).await;
    let asset_uuid = get_asset_uuid(&mut conn, asset_id).await;
    create_test_access_rule(&mut conn, &ug, &ag, &["ssh"]).await;

    let response = app
        .server
        .post("/api/v1/sessions")
        .add_header(header::AUTHORIZATION, app.auth_header(&user.token))
        .json(&json!({
            "asset_id": asset_uuid.to_string(),
            "credential_id": "cred-test",
            "session_type": "ssh"
        }))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 200 || status == 201,
        "Session creation with valid access rule should succeed, got {}",
        status
    );

    test_db::cleanup(&mut conn).await;
}

/// User with SSH-only access rule cannot create an RDP session (403).
#[tokio::test]
#[serial]
async fn test_session_creation_wrong_protocol_denied() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("test_ac_proto");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;

    let ug = create_test_vauban_group(&mut conn, "test-ug-proto").await;
    let ag = create_test_asset_group(&mut conn, "test-ag-proto").await;
    add_user_to_vauban_group(&mut conn, user.user.id, &ug).await;
    let asset_id =
        create_test_asset_in_group(&mut conn, "test-proto-asset", user.user.id, &ag).await;
    let asset_uuid = get_asset_uuid(&mut conn, asset_id).await;
    // Only SSH is allowed
    create_test_access_rule(&mut conn, &ug, &ag, &["ssh"]).await;

    let response = app
        .server
        .post("/api/v1/sessions")
        .add_header(header::AUTHORIZATION, app.auth_header(&user.token))
        .json(&json!({
            "asset_id": asset_uuid.to_string(),
            "credential_id": "cred-test",
            "session_type": "rdp"
        }))
        .await;

    assert_status(&response, 403);

    test_db::cleanup(&mut conn).await;
}

/// User without any access rule cannot create a session (403).
#[tokio::test]
#[serial]
async fn test_session_creation_without_access_rule_denied() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("test_ac_norule");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;

    // Create an asset in a group but no access rule for this user
    let admin_name = unique_name("test_ac_norule_adm");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let ag = create_test_asset_group(&mut conn, "test-ag-norule").await;
    let asset_id =
        create_test_asset_in_group(&mut conn, "test-norule-asset", admin.user.id, &ag).await;
    let asset_uuid = get_asset_uuid(&mut conn, asset_id).await;

    let response = app
        .server
        .post("/api/v1/sessions")
        .add_header(header::AUTHORIZATION, app.auth_header(&user.token))
        .json(&json!({
            "asset_id": asset_uuid.to_string(),
            "credential_id": "cred-test",
            "session_type": "ssh"
        }))
        .await;

    assert_status(&response, 403);

    test_db::cleanup(&mut conn).await;
}

/// Superuser can create a session without any access rule.
#[tokio::test]
#[serial]
async fn test_session_creation_superuser_bypass() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("test_ac_su_bypass_adm");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let ag = create_test_asset_group(&mut conn, "test-ag-su-bypass").await;
    let asset_id =
        create_test_asset_in_group(&mut conn, "test-su-bypass-asset", admin.user.id, &ag).await;
    let asset_uuid = get_asset_uuid(&mut conn, asset_id).await;

    let su_name = unique_name("test_ac_su_bypass");
    let su = create_superuser_only(&mut conn, &app.auth_service, &su_name).await;

    let response = app
        .server
        .post("/api/v1/sessions")
        .add_header(header::AUTHORIZATION, app.auth_header(&su.token))
        .json(&json!({
            "asset_id": asset_uuid.to_string(),
            "credential_id": "cred-test",
            "session_type": "ssh"
        }))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 200 || status == 201,
        "Superuser should bypass access rules, got {}",
        status
    );

    test_db::cleanup(&mut conn).await;
}

/// Access rule requiring justification: session without justification is rejected,
/// session with justification succeeds.
#[tokio::test]
#[serial]
async fn test_session_creation_justification_required() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("test_ac_just");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;

    let ug = create_test_vauban_group(&mut conn, "test-ug-just").await;
    let ag = create_test_asset_group(&mut conn, "test-ag-just").await;
    add_user_to_vauban_group(&mut conn, user.user.id, &ug).await;
    let asset_id =
        create_test_asset_in_group(&mut conn, "test-just-asset", user.user.id, &ag).await;
    let asset_uuid = get_asset_uuid(&mut conn, asset_id).await;
    create_test_access_rule_with_constraints(&mut conn, &ug, &ag, &["ssh"], false, true, None)
        .await;

    // Without justification -> should fail (400 validation error)
    let response = app
        .server
        .post("/api/v1/sessions")
        .add_header(header::AUTHORIZATION, app.auth_header(&user.token))
        .json(&json!({
            "asset_id": asset_uuid.to_string(),
            "credential_id": "cred-test",
            "session_type": "ssh"
        }))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 400 || status == 403 || status == 422,
        "Missing justification should be rejected, got {}",
        status
    );

    // With justification -> should succeed
    let response = app
        .server
        .post("/api/v1/sessions")
        .add_header(header::AUTHORIZATION, app.auth_header(&user.token))
        .json(&json!({
            "asset_id": asset_uuid.to_string(),
            "credential_id": "cred-test",
            "session_type": "ssh",
            "justification": "Emergency maintenance required"
        }))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 200 || status == 201,
        "Session with justification should succeed, got {}",
        status
    );

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// Edge Cases
// =============================================================================

/// Soft-deleted asset (is_deleted=true) should not appear even with a valid access rule.
#[tokio::test]
#[serial]
async fn test_deleted_asset_not_visible_with_access_rule() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("test_ac_deleted");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;

    let ug = create_test_vauban_group(&mut conn, "test-ug-deleted").await;
    let ag = create_test_asset_group(&mut conn, "test-ag-deleted").await;
    add_user_to_vauban_group(&mut conn, user.user.id, &ug).await;
    let asset_id = create_test_asset_in_group(&mut conn, "test-del-asset", user.user.id, &ag).await;
    create_test_access_rule(&mut conn, &ug, &ag, &["ssh"]).await;

    // Soft-delete the asset
    diesel::update(
        vauban_web::schema::assets::table.filter(vauban_web::schema::assets::id.eq(asset_id)),
    )
    .set(vauban_web::schema::assets::is_deleted.eq(true))
    .execute(&mut conn)
    .await
    .expect("Failed to soft-delete asset");

    let response = app
        .server
        .get("/api/v1/assets")
        .add_header(header::AUTHORIZATION, app.auth_header(&user.token))
        .await;

    assert_status(&response, 200);
    let json: Vec<serde_json::Value> = response.json();
    let asset_uuid = get_asset_uuid(&mut conn, asset_id).await;
    let has_deleted = json
        .iter()
        .any(|a| a.get("uuid").and_then(|v| v.as_str()) == Some(&asset_uuid.to_string()));
    assert!(
        !has_deleted,
        "Soft-deleted asset should not appear in listing"
    );

    test_db::cleanup(&mut conn).await;
}
