/// VAUBAN Web - Battle-test integration suite for the fine-grained
/// Casbin migration of the Axum handlers.
///
/// Each test below is the canonical proof-of-regression for ONE of the
/// privilege-boundary changes introduced by the migration. They keep the
/// system honest end-to-end: not only are the Casbin grants right
/// ([`super::super::middleware::permissions_test`] takes care of that
/// matrix), but the handlers actually consume `PermissionContext` and
/// reject privileged callers when the new fine-grained scope is missing.
use axum::http::header;
use serde_json::json;
use serial_test::serial;

use crate::common::{TestApp, assertions::*, test_db};
use crate::fixtures::{
    add_user_to_vauban_group, create_admin_user, create_staff_only_user, create_test_access_rule,
    create_test_asset_group, create_test_asset_in_group, create_test_ssh_asset, create_test_user,
    create_test_vauban_group, unique_name,
};

// ---------------------------------------------------------------------------
// 1. assets:read_all -- regular users see only access-rule assets, staff
//    sees everything.
// ---------------------------------------------------------------------------

/// `GET /api/v1/assets` returns ONLY the assets reachable through an
/// access rule for a regular user; the unrelated asset created by an
/// admin is invisible. This is the scope of `assets:read` (without
/// `assets:read_all`).
#[tokio::test]
#[serial]
async fn assets_read_all_filters_for_regular_user() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("read_all_user");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;

    // User has access rule -> sees this asset.
    let ug_name = unique_name("casbin-read-all-ug");
    let ag_vis_name = unique_name("casbin-read-all-ag-vis");
    let ag_hid_name = unique_name("casbin-read-all-ag-hid");
    let visible_asset = unique_name("read-all-visible");
    let hidden_asset = unique_name("read-all-hidden");

    let ug = create_test_vauban_group(&mut conn, &ug_name).await;
    let ag_visible = create_test_asset_group(&mut conn, &ag_vis_name).await;
    add_user_to_vauban_group(&mut conn, user.user.id, &ug).await;
    create_test_asset_in_group(&mut conn, &visible_asset, user.user.id, &ag_visible).await;
    create_test_access_rule(&mut conn, &ug, &ag_visible, &["ssh"]).await;

    // Hidden asset in a group the user cannot reach.
    let admin_name = unique_name("read_all_admin");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let ag_hidden = create_test_asset_group(&mut conn, &ag_hid_name).await;
    create_test_asset_in_group(&mut conn, &hidden_asset, admin.user.id, &ag_hidden).await;

    let response = app
        .server
        .get("/api/v1/assets")
        .add_header(header::AUTHORIZATION, app.auth_header(&user.token))
        .await;
    assert_status(&response, 200);

    let json: Vec<serde_json::Value> = response.json();
    let names: Vec<String> = json
        .iter()
        .filter_map(|a| a.get("name").and_then(|v| v.as_str()).map(String::from))
        .collect();
    assert!(
        names.iter().any(|n| n == &visible_asset),
        "user should see asset reachable via access rule, got: {:?}",
        names
    );
    assert!(
        names.iter().all(|n| n != &hidden_asset),
        "regular user (no assets:read_all) MUST NOT see assets outside their \
         access rules; got: {:?}",
        names
    );

    test_db::cleanup(&mut conn).await;
}

/// Same listing as a staff user: `assets:read_all` makes both assets
/// visible.
#[tokio::test]
#[serial]
async fn assets_read_all_returns_everything_for_staff() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let staff_name = unique_name("read_all_staff");
    let staff = create_staff_only_user(&mut conn, &app.auth_service, &staff_name).await;

    let admin_name = unique_name("read_all_admin2");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let ag_name = unique_name("casbin-read-all-staff-ag");
    let ag = create_test_asset_group(&mut conn, &ag_name).await;
    let asset_name = unique_name("read-all-staff-asset");
    create_test_asset_in_group(&mut conn, &asset_name, admin.user.id, &ag).await;

    let response = app
        .server
        .get("/api/v1/assets")
        .add_header(header::AUTHORIZATION, app.auth_header(&staff.token))
        .await;
    assert_status(&response, 200);

    let json: Vec<serde_json::Value> = response.json();
    assert!(
        !json.is_empty(),
        "staff (assets:read_all) MUST see every asset"
    );

    test_db::cleanup(&mut conn).await;
}

// ---------------------------------------------------------------------------
// 2. sessions:bypass_access_rules -- staff is now subject to access rules
//    when opening a session; only superusers bypass.
// ---------------------------------------------------------------------------

/// Staff posts to `/api/v1/sessions` for an asset that has no access
/// rule reaching them. Before the migration this was waved through; now
/// it must be denied because `sessions:bypass_access_rules` is reserved
/// to superusers (via the `*, *` wildcard).
#[tokio::test]
#[serial]
async fn sessions_bypass_access_rules_staff_denied_without_rule() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let staff_name = unique_name("bypass_staff");
    let staff = create_staff_only_user(&mut conn, &app.auth_service, &staff_name).await;

    // Asset with no group / no rule reaching the staff user.
    let asset = create_test_ssh_asset(&mut conn, &unique_name("bypass-asset")).await;

    let response = app
        .server
        .post("/api/v1/sessions")
        .add_header(header::AUTHORIZATION, app.auth_header(&staff.token))
        .json(&json!({
            "asset_id": asset.asset.uuid.to_string(),
            "credential_id": "battle-test-cred",
            "session_type": "ssh",
            "justification": "battle-test"
        }))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 403 || status == 404,
        "staff opening a session without a matching access rule MUST be \
         refused (only superusers may bypass); got {}",
        status
    );

    test_db::cleanup(&mut conn).await;
}

// ---------------------------------------------------------------------------
// 3. ssh_fetch_host_key -- now requires assets:manage (was `require_staff`,
//    renamed from the legacy "write" action in issue #27 / asset zone split).
// ---------------------------------------------------------------------------

/// Regular user POSTs to `/api/v1/assets/{uuid}/ssh-host-key` and is
/// rejected with 403 because they lack `assets:manage`. The asset is
/// otherwise fully accessible (this is a pure permission test, not a
/// not-found test).
#[tokio::test]
#[serial]
async fn ssh_fetch_host_key_requires_assets_manage() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("hostkey_user");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;
    let asset = create_test_ssh_asset(&mut conn, &unique_name("hostkey-asset")).await;

    let response = app
        .server
        .post(&format!("/api/v1/assets/manage/{}/ssh-host-key", asset.asset.uuid))
        .add_header(header::AUTHORIZATION, app.auth_header(&user.token))
        .await;

    assert_status(&response, 403);

    test_db::cleanup(&mut conn).await;
}

/// Same endpoint with a staff caller: the permission gate must pass
/// (we accept any non-403 status because the SSH proxy may not be
/// available in the test environment, which surfaces as 500/502; the
/// contract here is "the gate did not refuse", not "the proxy
/// succeeded").
#[tokio::test]
#[serial]
async fn ssh_fetch_host_key_passes_gate_for_staff() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let staff_name = unique_name("hostkey_staff");
    let staff = create_staff_only_user(&mut conn, &app.auth_service, &staff_name).await;
    let asset = create_test_ssh_asset(&mut conn, &unique_name("hostkey-staff-asset")).await;

    let response = app
        .server
        .post(&format!("/api/v1/assets/manage/{}/ssh-host-key", asset.asset.uuid))
        .add_header(header::AUTHORIZATION, app.auth_header(&staff.token))
        .await;

    assert_ne!(
        response.status_code().as_u16(),
        403,
        "staff (assets:manage) MUST clear the permission gate; the proxy \
         layer may then return another non-403 status"
    );

    test_db::cleanup(&mut conn).await;
}

// ---------------------------------------------------------------------------
// 4. users:manage_admins -- only superusers may promote/demote a superuser.
// ---------------------------------------------------------------------------

/// Staff calls `POST /api/v1/accounts` with `is_superuser=true` in the
/// payload. Even though staff has `users:write` for plain CRUD, granting
/// the superuser flag now requires the dedicated `users:manage_admins`
/// scope -- which is reserved to superusers via the wildcard.
#[tokio::test]
#[serial]
async fn users_promote_superuser_requires_manage_admins() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let staff_name = unique_name("promote_staff");
    let staff = create_staff_only_user(&mut conn, &app.auth_service, &staff_name).await;

    let target_username = unique_name("promote_target");
    let response = app
        .server
        .post("/api/v1/accounts")
        .add_header(header::AUTHORIZATION, app.auth_header(&staff.token))
        .json(&json!({
            "username": target_username,
            "email": format!("{}@test.vauban.io", target_username),
            "password": "BattleTest1234!",
            "is_active": true,
            "is_staff": false,
            "is_superuser": true,
        }))
        .await;

    assert_status(&response, 403);

    // Sanity: the same call without the superuser bit must succeed for
    // staff (it has users:write). This proves the previous 403 was
    // really about manage_admins, not about users:write.
    let plain_username = unique_name("promote_target_plain");
    let response = app
        .server
        .post("/api/v1/accounts")
        .add_header(header::AUTHORIZATION, app.auth_header(&staff.token))
        .json(&json!({
            "username": plain_username,
            "email": format!("{}@test.vauban.io", plain_username),
            "password": "BattleTest1234!",
            "is_active": true,
            "is_staff": false,
            "is_superuser": false,
        }))
        .await;
    let status = response.status_code().as_u16();
    assert!(
        status == 200 || status == 201,
        "staff with users:write must be able to create a non-admin user; \
         got {}",
        status
    );

    test_db::cleanup(&mut conn).await;
}

/// Mirror test: a superuser CAN promote at creation time.
#[tokio::test]
#[serial]
async fn users_promote_superuser_allowed_for_superuser() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("promote_admin");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let target_username = unique_name("promote_target_su");
    let response = app
        .server
        .post("/api/v1/accounts")
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .json(&json!({
            "username": target_username,
            "email": format!("{}@test.vauban.io", target_username),
            "password": "BattleTest1234!",
            "is_active": true,
            "is_staff": true,
            "is_superuser": true,
        }))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 200 || status == 201,
        "superuser with users:manage_admins must be able to mint another \
         superuser; got {}",
        status
    );

    test_db::cleanup(&mut conn).await;
}
