/// VAUBAN Web - Access Rules CRUD Web Tests.
///
/// Tests for the web-based access rules management pages:
/// - List page (empty state / with rules)
/// - Create form and submission
/// - Detail page
/// - Edit form and submission
/// - Delete
/// - Authorization checks
/// - CSRF validation
use axum::http::header::{self, COOKIE};
use serial_test::serial;

use crate::common::{TestApp, assertions::*, test_db};
use crate::fixtures::{
    create_admin_user, create_test_access_rule, create_test_asset_group, create_test_user,
    create_test_vauban_group, unique_name,
};

// =============================================================================
// List Page
// =============================================================================

/// Structural: the access rules list must NOT expose a "Protocols" column.
/// Protocols remain accessible from the access rule detail/edit pages.
/// Regression guard for the privacy/UX-tightening change requested after the
/// responsive overhaul (issue #14 follow-up).
#[test]
fn test_access_list_does_not_render_protocols_column() {
    let template = include_str!("../../templates/assets/access_list.html");

    let lower = template.to_lowercase();
    assert!(
        !lower.contains(">protocols<"),
        "access_list: forbidden 'Protocols' column header detected; protocols are now Edit-only"
    );

    assert!(
        !template.contains("rule.protocols_display()"),
        "access_list: forbidden rule.protocols_display() rendering detected; protocols are now Edit-only"
    );
}

/// Access rules list page loads with empty state when no rules exist.
#[tokio::test]
#[serial]
async fn test_web_access_rules_list_page_loads_empty() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("w_ar_list_empty_adm");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let response = app
        .server
        .get("/assets/access")
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(
        body.contains("No access rules") || body.contains("Access Rules"),
        "List page should show empty state or header"
    );

    test_db::cleanup(&mut conn).await;
}

/// Access rules list page shows existing rules.
#[tokio::test]
#[serial]
async fn test_web_access_rules_list_shows_rules() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("w_ar_list_show_adm");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let ug = create_test_vauban_group(&mut conn, &unique_name("w-ar-list-ug")).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("w-ar-list-ag")).await;
    create_test_access_rule(&mut conn, &ug, &ag, &["ssh"]).await;

    let response = app
        .server
        .get("/assets/access")
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(
        body.contains("test-rule"),
        "List page should show the created rule name"
    );
    // NOTE: Protocols are intentionally NOT exposed on the list page anymore
    // (issue #14 follow-up). They remain available on the detail/edit pages.
    // See test_access_list_does_not_render_protocols_column for the
    // structural guard.

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// Create Form
// =============================================================================

/// Create form page loads for admin.
#[tokio::test]
#[serial]
async fn test_web_access_rule_create_form_loads() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("w_ar_form_adm");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let response = app
        .server
        .get("/assets/access/new")
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(
        body.contains("New Access Rule") || body.contains("Create Rule"),
        "Create form should contain form title"
    );
    assert!(
        body.contains("csrf_token"),
        "Create form should contain CSRF token"
    );

    test_db::cleanup(&mut conn).await;
}

/// Successfully create an access rule via web form.
#[tokio::test]
#[serial]
async fn test_web_create_access_rule_success() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("w_ar_create_adm");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let ug = create_test_vauban_group(&mut conn, &unique_name("w-ar-create-ug")).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("w-ar-create-ag")).await;

    use diesel::prelude::*;
    use diesel_async::RunQueryDsl;
    let ug_id: i32 = vauban_web::schema::vauban_groups::table
        .filter(vauban_web::schema::vauban_groups::uuid.eq(ug))
        .select(vauban_web::schema::vauban_groups::id)
        .first(&mut conn)
        .await
        .unwrap();
    let ag_id: i32 = vauban_web::schema::asset_groups::table
        .filter(vauban_web::schema::asset_groups::uuid.eq(ag))
        .select(vauban_web::schema::asset_groups::id)
        .first(&mut conn)
        .await
        .unwrap();

    let csrf_token = app.generate_csrf_token();
    let response = app
        .server
        .post("/assets/access")
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", admin.token, csrf_token),
        )
        .form(&serde_json::json!({
            "csrf_token": csrf_token,
            "name": "Web Created Rule",
            "description": "Created via web form",
            "user_group_id": ug_id,
            "asset_group_id": ag_id,
            "allowed_ssh": "true",
            "is_active": "true",
            "priority": "5",
        }))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 303 || status == 302,
        "Successful creation should redirect (PRG), got {}",
        status
    );

    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        location.starts_with("/assets/access/"),
        "Should redirect to the new rule detail, got: {}",
        location
    );

    test_db::cleanup(&mut conn).await;
}

/// Create with missing name returns validation error.
#[tokio::test]
#[serial]
async fn test_web_create_access_rule_validation_error() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("w_ar_val_adm");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let csrf_token = app.generate_csrf_token();
    let response = app
        .server
        .post("/assets/access")
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", admin.token, csrf_token),
        )
        .form(&serde_json::json!({
            "csrf_token": csrf_token,
            "name": "",
            "user_group_id": 1,
            "asset_group_id": 1,
        }))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 303 || status == 302,
        "Validation error should redirect, got {}",
        status
    );

    test_db::cleanup(&mut conn).await;
}

/// Create an access rule with duration_value + duration_unit (2 hours).
#[tokio::test]
#[serial]
async fn test_web_create_access_rule_with_duration() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("w_ar_dur_adm");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let ug = create_test_vauban_group(&mut conn, &unique_name("w-ar-dur-ug")).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("w-ar-dur-ag")).await;

    use diesel::prelude::*;
    use diesel_async::RunQueryDsl;
    let ug_id: i32 = vauban_web::schema::vauban_groups::table
        .filter(vauban_web::schema::vauban_groups::uuid.eq(ug))
        .select(vauban_web::schema::vauban_groups::id)
        .first(&mut conn)
        .await
        .unwrap();
    let ag_id: i32 = vauban_web::schema::asset_groups::table
        .filter(vauban_web::schema::asset_groups::uuid.eq(ag))
        .select(vauban_web::schema::asset_groups::id)
        .first(&mut conn)
        .await
        .unwrap();

    let csrf_token = app.generate_csrf_token();
    let response = app
        .server
        .post("/assets/access")
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", admin.token, csrf_token),
        )
        .form(&serde_json::json!({
            "csrf_token": csrf_token,
            "name": "Duration Rule 2h",
            "user_group_id": ug_id,
            "asset_group_id": ag_id,
            "allowed_ssh": "true",
            "is_active": "true",
            "duration_value": 2,
            "duration_unit": "hours",
        }))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 303 || status == 302,
        "Successful creation should redirect (PRG), got {}",
        status
    );

    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        location.starts_with("/assets/access/"),
        "Should redirect to the new rule detail, got: {}",
        location
    );

    let detail = app
        .server
        .get(location)
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;
    assert_status(&detail, 200);
    let body = detail.text();
    assert!(body.contains("2h"), "Detail page should display duration as '2h'");

    test_db::cleanup(&mut conn).await;
}

/// Create an access rule with 30 minutes duration.
#[tokio::test]
#[serial]
async fn test_web_create_access_rule_with_minutes_duration() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("w_ar_min_adm");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let ug = create_test_vauban_group(&mut conn, &unique_name("w-ar-min-ug")).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("w-ar-min-ag")).await;

    use diesel::prelude::*;
    use diesel_async::RunQueryDsl;
    let ug_id: i32 = vauban_web::schema::vauban_groups::table
        .filter(vauban_web::schema::vauban_groups::uuid.eq(ug))
        .select(vauban_web::schema::vauban_groups::id)
        .first(&mut conn)
        .await
        .unwrap();
    let ag_id: i32 = vauban_web::schema::asset_groups::table
        .filter(vauban_web::schema::asset_groups::uuid.eq(ag))
        .select(vauban_web::schema::asset_groups::id)
        .first(&mut conn)
        .await
        .unwrap();

    let csrf_token = app.generate_csrf_token();
    let response = app
        .server
        .post("/assets/access")
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", admin.token, csrf_token),
        )
        .form(&serde_json::json!({
            "csrf_token": csrf_token,
            "name": "Duration Rule 30min",
            "user_group_id": ug_id,
            "asset_group_id": ag_id,
            "allowed_ssh": "true",
            "is_active": "true",
            "duration_value": 30,
            "duration_unit": "minutes",
        }))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 303 || status == 302,
        "Successful creation should redirect (PRG), got {}",
        status
    );

    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let detail = app
        .server
        .get(location)
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;
    assert_status(&detail, 200);
    let body = detail.text();
    assert!(body.contains("30min"), "Detail page should display duration as '30min'");

    test_db::cleanup(&mut conn).await;
}

/// Create form defaults to 2 hours duration.
#[tokio::test]
#[serial]
async fn test_web_access_rule_create_form_defaults_to_2h() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("w_ar_def_adm");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let response = app
        .server
        .get("/assets/access/new")
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(
        body.contains("duration_value"),
        "Create form should have duration_value field"
    );
    assert!(
        body.contains("duration_unit"),
        "Create form should have duration_unit select"
    );
    assert!(
        body.contains("value=\"2\""),
        "Default duration_value should be 2"
    );

    test_db::cleanup(&mut conn).await;
}

/// Detail page shows 'Unlimited' when no duration set.
#[tokio::test]
#[serial]
async fn test_web_access_rule_detail_shows_unlimited() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("w_ar_unlim_adm");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let ug = create_test_vauban_group(&mut conn, &unique_name("w-ar-unlim-ug")).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("w-ar-unlim-ag")).await;
    let rule_uuid = create_test_access_rule(&mut conn, &ug, &ag, &["ssh"]).await;

    let response = app
        .server
        .get(&format!("/assets/access/{}", rule_uuid))
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(
        body.contains("Unlimited"),
        "Detail page should show 'Unlimited' when no duration set"
    );

    test_db::cleanup(&mut conn).await;
}

/// Edit form shows duration_value/duration_unit fields.
#[tokio::test]
#[serial]
async fn test_web_access_rule_edit_form_shows_duration_fields() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("w_ar_edit_dur_adm");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let ug = create_test_vauban_group(&mut conn, &unique_name("w-ar-edit-dur-ug")).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("w-ar-edit-dur-ag")).await;

    use crate::fixtures::create_test_access_rule_with_constraints;
    let rule_uuid =
        create_test_access_rule_with_constraints(&mut conn, &ug, &ag, &["ssh"], false, false, Some(7200))
            .await;

    let response = app
        .server
        .get(&format!("/assets/access/{}/edit", rule_uuid))
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(
        body.contains("duration_value"),
        "Edit form should have duration_value field"
    );
    assert!(
        body.contains("value=\"2\""),
        "Edit form should pre-fill 2 for 7200s"
    );

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// Detail Page
// =============================================================================

/// Detail page loads for an existing access rule.
#[tokio::test]
#[serial]
async fn test_web_access_rule_detail_loads() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("w_ar_detail_adm");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let ug = create_test_vauban_group(&mut conn, &unique_name("w-ar-detail-ug")).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("w-ar-detail-ag")).await;
    let rule_uuid = create_test_access_rule(&mut conn, &ug, &ag, &["ssh", "rdp"]).await;

    let response = app
        .server
        .get(&format!("/assets/access/{}", rule_uuid))
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(
        body.contains("Rule Configuration") || body.contains("test-rule"),
        "Detail page should show rule configuration"
    );
    assert!(
        body.contains("SSH") && body.contains("RDP"),
        "Detail page should show allowed protocols"
    );

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// Edit Form
// =============================================================================

/// Edit form loads with pre-populated data.
#[tokio::test]
#[serial]
async fn test_web_access_rule_edit_form_loads() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("w_ar_edit_adm");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let ug = create_test_vauban_group(&mut conn, &unique_name("w-ar-edit-ug")).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("w-ar-edit-ag")).await;
    let rule_uuid = create_test_access_rule(&mut conn, &ug, &ag, &["ssh"]).await;

    let response = app
        .server
        .get(&format!("/assets/access/{}/edit", rule_uuid))
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(
        body.contains("Edit Access Rule") || body.contains("Save Changes"),
        "Edit form should contain form elements"
    );
    assert!(
        body.contains("test-rule"),
        "Edit form should contain pre-populated rule name"
    );

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// Delete
// =============================================================================

/// Successfully delete an access rule.
#[tokio::test]
#[serial]
async fn test_web_delete_access_rule_success() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("w_ar_del_adm");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let ug = create_test_vauban_group(&mut conn, &unique_name("w-ar-del-ug")).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("w-ar-del-ag")).await;
    let rule_uuid = create_test_access_rule(&mut conn, &ug, &ag, &["ssh"]).await;

    let csrf_token = app.generate_csrf_token();
    let response = app
        .server
        .post(&format!("/assets/access/{}/delete", rule_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", admin.token, csrf_token),
        )
        .form(&serde_json::json!({
            "csrf_token": csrf_token,
        }))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 303 || status == 302,
        "Delete should redirect, got {}",
        status
    );

    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(
        location, "/assets/access",
        "Should redirect to access rules list"
    );

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// Authorization
// =============================================================================

/// Regular user cannot access CRUD operations for access rules.
#[tokio::test]
#[serial]
async fn test_web_access_rules_crud_requires_admin() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("w_ar_noauth_usr");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;

    // GET create form
    let response = app
        .server
        .get("/assets/access/new")
        .add_header(COOKIE, format!("access_token={}", user.token))
        .await;
    let status = response.status_code().as_u16();
    assert!(
        status == 303 || status == 403,
        "Regular user should be denied create form, got {}",
        status
    );

    // POST create
    let csrf_token = app.generate_csrf_token();
    let response = app
        .server
        .post("/assets/access")
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", user.token, csrf_token),
        )
        .form(&serde_json::json!({
            "csrf_token": csrf_token,
            "name": "Unauthorized",
            "user_group_id": 1,
            "asset_group_id": 1,
            "allowed_ssh": "true",
        }))
        .await;
    let status = response.status_code().as_u16();
    assert!(
        status == 303 || status == 403,
        "Regular user should be denied create, got {}",
        status
    );

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// CSRF Validation
// =============================================================================

/// Create access rule without CSRF token is rejected.
#[tokio::test]
#[serial]
async fn test_web_access_rules_csrf_validation() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("w_ar_csrf_adm");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let response = app
        .server
        .post("/assets/access")
        .add_header(COOKIE, format!("access_token={}", admin.token))
        .form(&serde_json::json!({
            "csrf_token": "invalid-token",
            "name": "CSRF Test",
            "user_group_id": 1,
            "asset_group_id": 1,
            "allowed_ssh": "true",
        }))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 303 || status == 403,
        "Invalid CSRF should be rejected, got {}",
        status
    );

    test_db::cleanup(&mut conn).await;
}
