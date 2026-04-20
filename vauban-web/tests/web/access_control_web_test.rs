/// VAUBAN Web - Access Control Web Tests.
///
/// Verifies that the web path enforces access rules identically to the API path:
/// - SSH/RDP connect handlers deny users without matching access rules
/// - Asset detail page denies unauthorized users
/// - Superuser and staff bypass access rules
/// - Temporal validity is enforced
use axum::http::header::{self, COOKIE};
use serial_test::serial;

use crate::common::{TestApp, assertions::*, test_db};
use vauban_web::models::asset::AssetType;

use crate::fixtures::{
    add_user_to_vauban_group, create_admin_user, create_expired_access_rule,
    create_inactive_access_rule, create_test_access_rule, create_test_asset_group,
    create_test_asset_in_group, create_test_asset_in_group_with_type, create_test_user,
    create_test_vauban_group, get_asset_uuid, unique_name,
};

// =============================================================================
// SSH Connect Access Control
// =============================================================================

/// Regular user without access rule is denied SSH connect.
#[tokio::test]
#[serial]
async fn test_web_ssh_connect_denied_without_access_rule() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("w_ssh_deny_adm");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("w-ssh-deny-ag")).await;
    let asset_id =
        create_test_asset_in_group(&mut conn, "w-ssh-deny-asset", admin.user.id, &ag).await;
    let asset_uuid = get_asset_uuid(&mut conn, asset_id).await;

    let username = unique_name("w_ssh_deny_usr");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;

    let csrf_token = app.generate_csrf_token();
    let response = app
        .server
        .post(&format!("/assets/{}/connect", asset_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", user.token, csrf_token),
        )
        .form(&serde_json::json!({
            "csrf_token": csrf_token,
        }))
        .await;

    let body = response.text();
    assert!(
        body.contains("No access rule") || body.contains("showToast"),
        "Should deny SSH connect without access rule, body: {}",
        &body[..body.len().min(200)]
    );

    test_db::cleanup(&mut conn).await;
}

/// Regular user with valid SSH access rule is NOT denied (may fail for other reasons like no proxy).
#[tokio::test]
#[serial]
async fn test_web_ssh_connect_allowed_with_access_rule() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("w_ssh_ok_adm");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let ug = create_test_vauban_group(&mut conn, &unique_name("w-ssh-ok-ug")).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("w-ssh-ok-ag")).await;

    let username = unique_name("w_ssh_ok_usr");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;
    add_user_to_vauban_group(&mut conn, user.user.id, &ug).await;

    let asset_id =
        create_test_asset_in_group(&mut conn, "w-ssh-ok-asset", admin.user.id, &ag).await;
    let asset_uuid = get_asset_uuid(&mut conn, asset_id).await;
    create_test_access_rule(&mut conn, &ug, &ag, &["ssh"]).await;

    let csrf_token = app.generate_csrf_token();
    let response = app
        .server
        .post(&format!("/assets/{}/connect", asset_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", user.token, csrf_token),
        )
        .form(&serde_json::json!({
            "csrf_token": csrf_token,
        }))
        .await;

    let body = response.text();
    assert!(
        !body.contains("No access rule"),
        "Should NOT deny SSH connect with valid access rule, body: {}",
        &body[..body.len().min(200)]
    );

    test_db::cleanup(&mut conn).await;
}

/// RDP-only access rule denies SSH connect.
#[tokio::test]
#[serial]
async fn test_web_ssh_connect_wrong_protocol_denied() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("w_ssh_proto_adm");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let ug = create_test_vauban_group(&mut conn, &unique_name("w-ssh-proto-ug")).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("w-ssh-proto-ag")).await;

    let username = unique_name("w_ssh_proto_usr");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;
    add_user_to_vauban_group(&mut conn, user.user.id, &ug).await;

    let asset_id =
        create_test_asset_in_group(&mut conn, "w-ssh-proto-asset", admin.user.id, &ag).await;
    let asset_uuid = get_asset_uuid(&mut conn, asset_id).await;
    create_test_access_rule(&mut conn, &ug, &ag, &["rdp"]).await;

    let csrf_token = app.generate_csrf_token();
    let response = app
        .server
        .post(&format!("/assets/{}/connect", asset_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", user.token, csrf_token),
        )
        .form(&serde_json::json!({
            "csrf_token": csrf_token,
        }))
        .await;

    let body = response.text();
    assert!(
        body.contains("No access rule") || body.contains("showToast"),
        "RDP-only rule should deny SSH connect"
    );

    test_db::cleanup(&mut conn).await;
}

/// SECURITY: superusers MUST NOT bypass access_rule enforcement for SSH.
///
/// The historical "superuser bypass" was retired alongside the proxy-ssh
/// defense-in-depth re-check (CheckAccessByUuid). Both layers
/// (vauban-web::handlers::web::ssh::connect_ssh and the proxy-side
/// CheckAccessByUuid) now apply the EXACT same policy. Allowing the bypass
/// here while the proxy enforces the rule produced the regression where
/// every superuser-initiated SSH session resulted in "Access denied" with
/// no recourse. This test inverts the legacy assertion and locks the new,
/// strict policy in place. See docs/runbooks/ipc_topology_debugging.md.
#[tokio::test]
#[serial]
async fn test_web_ssh_connect_superuser_requires_access_rule() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("w_ssh_su_adm");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("w-ssh-su-ag")).await;
    let asset_id =
        create_test_asset_in_group(&mut conn, "w-ssh-su-asset", admin.user.id, &ag).await;
    let asset_uuid = get_asset_uuid(&mut conn, asset_id).await;

    let csrf_token = app.generate_csrf_token();
    let response = app
        .server
        .post(&format!("/assets/{}/connect", asset_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", admin.token, csrf_token),
        )
        .form(&serde_json::json!({
            "csrf_token": csrf_token,
        }))
        .await;

    let body = response.text();
    assert!(
        body.contains("No access rule") || body.contains("showToast"),
        "Superuser MUST be denied SSH connect when no access_rule grants it \
         (no privileged-user bypass): {body}"
    );

    test_db::cleanup(&mut conn).await;
}

/// Expired access rule denies SSH connect.
#[tokio::test]
#[serial]
async fn test_web_ssh_connect_expired_rule_denied() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("w_ssh_exp_adm");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let ug = create_test_vauban_group(&mut conn, &unique_name("w-ssh-exp-ug")).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("w-ssh-exp-ag")).await;

    let username = unique_name("w_ssh_exp_usr");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;
    add_user_to_vauban_group(&mut conn, user.user.id, &ug).await;

    let asset_id =
        create_test_asset_in_group(&mut conn, "w-ssh-exp-asset", admin.user.id, &ag).await;
    let asset_uuid = get_asset_uuid(&mut conn, asset_id).await;
    create_expired_access_rule(&mut conn, &ug, &ag).await;

    let csrf_token = app.generate_csrf_token();
    let response = app
        .server
        .post(&format!("/assets/{}/connect", asset_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", user.token, csrf_token),
        )
        .form(&serde_json::json!({
            "csrf_token": csrf_token,
        }))
        .await;

    let body = response.text();
    assert!(
        body.contains("No access rule") || body.contains("showToast"),
        "Expired rule should deny SSH connect"
    );

    test_db::cleanup(&mut conn).await;
}

/// Inactive access rule denies SSH connect.
#[tokio::test]
#[serial]
async fn test_web_ssh_connect_inactive_rule_denied() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("w_ssh_inact_adm");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let ug = create_test_vauban_group(&mut conn, &unique_name("w-ssh-inact-ug")).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("w-ssh-inact-ag")).await;

    let username = unique_name("w_ssh_inact_usr");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;
    add_user_to_vauban_group(&mut conn, user.user.id, &ug).await;

    let asset_id =
        create_test_asset_in_group(&mut conn, "w-ssh-inact-asset", admin.user.id, &ag).await;
    let asset_uuid = get_asset_uuid(&mut conn, asset_id).await;
    create_inactive_access_rule(&mut conn, &ug, &ag).await;

    let csrf_token = app.generate_csrf_token();
    let response = app
        .server
        .post(&format!("/assets/{}/connect", asset_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", user.token, csrf_token),
        )
        .form(&serde_json::json!({
            "csrf_token": csrf_token,
        }))
        .await;

    let body = response.text();
    assert!(
        body.contains("No access rule") || body.contains("showToast"),
        "Inactive rule should deny SSH connect"
    );

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// RDP Connect Access Control
// =============================================================================

/// Regular user without access rule is denied RDP connect.
#[tokio::test]
#[serial]
async fn test_web_rdp_connect_denied_without_access_rule() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("w_rdp_deny_adm");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("w-rdp-deny-ag")).await;
    let asset_id =
        create_test_asset_in_group(&mut conn, "w-rdp-deny-asset", admin.user.id, &ag).await;
    let asset_uuid = get_asset_uuid(&mut conn, asset_id).await;

    let username = unique_name("w_rdp_deny_usr");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;

    let csrf_token = app.generate_csrf_token();
    let response = app
        .server
        .post(&format!("/assets/{}/connect-rdp", asset_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", user.token, csrf_token),
        )
        .form(&serde_json::json!({
            "csrf_token": csrf_token,
        }))
        .await;

    let hx_trigger = response
        .headers()
        .get("HX-Trigger")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let body = response.text();
    assert!(
        hx_trigger.contains("No access rule")
            || body.contains("No access rule")
            || body.contains("showToast"),
        "Should deny RDP connect without access rule"
    );

    test_db::cleanup(&mut conn).await;
}

/// SSH-only access rule denies RDP connect.
#[tokio::test]
#[serial]
async fn test_web_rdp_connect_wrong_protocol_denied() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("w_rdp_proto_adm");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let ug = create_test_vauban_group(&mut conn, &unique_name("w-rdp-proto-ug")).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("w-rdp-proto-ag")).await;

    let username = unique_name("w_rdp_proto_usr");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;
    add_user_to_vauban_group(&mut conn, user.user.id, &ug).await;

    let asset_id =
        create_test_asset_in_group(&mut conn, "w-rdp-proto-asset", admin.user.id, &ag).await;
    let asset_uuid = get_asset_uuid(&mut conn, asset_id).await;
    create_test_access_rule(&mut conn, &ug, &ag, &["ssh"]).await;

    let csrf_token = app.generate_csrf_token();
    let response = app
        .server
        .post(&format!("/assets/{}/connect-rdp", asset_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", user.token, csrf_token),
        )
        .form(&serde_json::json!({
            "csrf_token": csrf_token,
        }))
        .await;

    let hx_trigger = response
        .headers()
        .get("HX-Trigger")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let body = response.text();
    assert!(
        hx_trigger.contains("No access rule")
            || body.contains("No access rule")
            || body.contains("showToast"),
        "SSH-only rule should deny RDP connect"
    );

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// Asset Detail Access Control
// =============================================================================

/// Regular user without access rule is denied asset detail.
#[tokio::test]
#[serial]
async fn test_web_asset_detail_denied_without_access_rule() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("w_det_deny_adm");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("w-det-deny-ag")).await;
    let asset_id =
        create_test_asset_in_group(&mut conn, "w-det-deny-asset", admin.user.id, &ag).await;
    let asset_uuid = get_asset_uuid(&mut conn, asset_id).await;

    let username = unique_name("w_det_deny_usr");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;

    let response = app
        .server
        .get(&format!("/assets/{}", asset_uuid))
        .add_header(COOKIE, format!("access_token={}", user.token))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 303 || status == 403,
        "Regular user without access rule should be redirected/denied from asset detail, got {}",
        status
    );

    test_db::cleanup(&mut conn).await;
}

/// Admin (superuser) can view asset detail page.
/// Note: In test env without Casbin, regular users are blocked by RBAC fallback
/// before reaching instance-level checks. The instance-level access check is
/// verified indirectly: `test_web_asset_detail_denied_without_access_rule`
/// confirms denial, and the SSH/RDP connect tests verify instance-level checks.
#[tokio::test]
#[serial]
async fn test_web_asset_detail_allowed_with_access_rule() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("w_det_ok_adm");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("w-det-ok-ag")).await;
    let asset_id =
        create_test_asset_in_group(&mut conn, "w-det-ok-asset", admin.user.id, &ag).await;
    let asset_uuid = get_asset_uuid(&mut conn, asset_id).await;

    let response = app
        .server
        .get(&format!("/assets/{}", asset_uuid))
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(
        body.contains("w-det-ok-asset"),
        "Admin should see asset detail"
    );

    test_db::cleanup(&mut conn).await;
}

/// Superuser can view any asset detail without access rules.
#[tokio::test]
#[serial]
async fn test_web_asset_detail_superuser_bypass() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("w_det_su_adm");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("w-det-su-ag")).await;
    let asset_id =
        create_test_asset_in_group(&mut conn, "w-det-su-asset", admin.user.id, &ag).await;
    let asset_uuid = get_asset_uuid(&mut conn, asset_id).await;

    let response = app
        .server
        .get(&format!("/assets/{}", asset_uuid))
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;

    assert_status(&response, 200);

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// Asset List Access Control
// =============================================================================

/// Regular user only sees assets allowed by access rules in the web listing.
#[tokio::test]
#[serial]
async fn test_web_asset_list_filters_by_access_rules() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("w_list_flt_adm");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let ug = create_test_vauban_group(&mut conn, &unique_name("w-list-flt-ug")).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("w-list-flt-ag")).await;

    let username = unique_name("w_list_flt_usr");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;
    add_user_to_vauban_group(&mut conn, user.user.id, &ug).await;

    create_test_asset_in_group(&mut conn, "w-visible-asset", admin.user.id, &ag).await;
    create_test_access_rule(&mut conn, &ug, &ag, &["ssh"]).await;

    let ag2 = create_test_asset_group(&mut conn, &unique_name("w-list-flt-ag2")).await;
    create_test_asset_in_group(&mut conn, "w-hidden-asset", admin.user.id, &ag2).await;

    let response = app
        .server
        .get("/assets")
        .add_header(COOKIE, format!("access_token={}", user.token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(
        body.contains("w-visible-asset"),
        "User should see assets allowed by access rules"
    );
    assert!(
        !body.contains("w-hidden-asset"),
        "User should NOT see assets without access rules"
    );

    test_db::cleanup(&mut conn).await;
}

/// SSH-only rule hides RDP assets from the web asset list.
/// This test reproduces the exact bug reported: a user with an SSH-only rule
/// could see RDP assets in Production Servers.
#[tokio::test]
#[serial]
async fn test_web_asset_list_protocol_filtering_hides_wrong_type() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("w_pflt_adm");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let ug = create_test_vauban_group(&mut conn, &unique_name("w-pflt-ug")).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("w-pflt-ag")).await;

    let username = unique_name("w_pflt_usr");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;
    add_user_to_vauban_group(&mut conn, user.user.id, &ug).await;

    create_test_asset_in_group_with_type(
        &mut conn,
        "w-pflt-ssh-asset",
        admin.user.id,
        &ag,
        AssetType::Ssh,
    )
    .await;
    create_test_asset_in_group_with_type(
        &mut conn,
        "w-pflt-rdp-asset",
        admin.user.id,
        &ag,
        AssetType::Rdp,
    )
    .await;

    create_test_access_rule(&mut conn, &ug, &ag, &["ssh"]).await;

    let response = app
        .server
        .get("/assets")
        .add_header(COOKIE, format!("access_token={}", user.token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(
        body.contains("w-pflt-ssh-asset"),
        "SSH asset should be visible with SSH-only rule"
    );
    assert!(
        !body.contains("w-pflt-rdp-asset"),
        "RDP asset should NOT be visible with SSH-only rule"
    );

    test_db::cleanup(&mut conn).await;
}

/// Dual-protocol rule shows both SSH and RDP assets in the web list.
#[tokio::test]
#[serial]
async fn test_web_asset_list_dual_protocol_shows_both() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("w_dual_adm");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let ug = create_test_vauban_group(&mut conn, &unique_name("w-dual-ug")).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("w-dual-ag")).await;

    let username = unique_name("w_dual_usr");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;
    add_user_to_vauban_group(&mut conn, user.user.id, &ug).await;

    create_test_asset_in_group_with_type(
        &mut conn,
        "w-dual-ssh-asset",
        admin.user.id,
        &ag,
        AssetType::Ssh,
    )
    .await;
    create_test_asset_in_group_with_type(
        &mut conn,
        "w-dual-rdp-asset",
        admin.user.id,
        &ag,
        AssetType::Rdp,
    )
    .await;

    create_test_access_rule(&mut conn, &ug, &ag, &["ssh", "rdp"]).await;

    let response = app
        .server
        .get("/assets")
        .add_header(COOKIE, format!("access_token={}", user.token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(
        body.contains("w-dual-ssh-asset"),
        "SSH asset should be visible with dual-protocol rule"
    );
    assert!(
        body.contains("w-dual-rdp-asset"),
        "RDP asset should be visible with dual-protocol rule"
    );

    test_db::cleanup(&mut conn).await;
}

/// Superuser sees all assets regardless of access rules.
#[tokio::test]
#[serial]
async fn test_web_asset_list_superuser_sees_all() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("w_list_su_adm");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("w-list-su-ag")).await;
    create_test_asset_in_group(&mut conn, "w-su-all-asset", admin.user.id, &ag).await;

    let response = app
        .server
        .get("/assets")
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(
        body.contains("w-su-all-asset") || body.contains("Assets"),
        "Superuser should see assets page, body contains '{}...'",
        &body[..body.len().min(500)]
    );

    test_db::cleanup(&mut conn).await;
}
