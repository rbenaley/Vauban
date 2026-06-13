/// VAUBAN Web - Access Rules API Integration Tests.
///
/// Tests for /api/v1/access-rules/* endpoints.
use axum::http::header;
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::json;
use uuid::Uuid;
use vauban_web::models::api_key::ApiKeyScope;

use crate::common::TestApp;
use crate::common::assertions::assert_status;
use crate::fixtures::{
    create_real_api_key, create_simple_admin_user, create_simple_user, create_test_asset_group,
    create_test_vauban_group, unique_name,
};

async fn get_user_uuid(conn: &mut AsyncPgConnection, user_id: i32) -> Uuid {
    use vauban_web::schema::users;
    users::table
        .filter(users::id.eq(user_id))
        .select(users::uuid)
        .first(conn)
        .await
        .expect("User should exist")
}

// =============================================================================
// Helper: create admin + token pair
// =============================================================================

async fn setup_admin(app: &TestApp, prefix: &str) -> (String, Uuid) {
    let mut conn = app.get_conn().await;
    let admin_name = unique_name(prefix);
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let (_key_uuid, token) =
        create_real_api_key(&mut conn, admin_id, &[ApiKeyScope::Admin], None).await;
    (token, admin_uuid)
}

async fn setup_groups(app: &TestApp) -> (Uuid, Uuid) {
    let mut conn = app.get_conn().await;
    let ug = create_test_vauban_group(&mut conn, &unique_name("ar_ug")).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("ar-ag")).await;
    (ug, ag)
}

// =============================================================================
// CRUD Tests
// =============================================================================

#[tokio::test]
async fn test_api_create_access_rule_success() {
    let app = TestApp::spawn().await;
    let (token, _) = setup_admin(app, "ar_create_admin").await;
    let (ug, ag) = setup_groups(app).await;

    let response = app
        .server
        .post("/api/v1/access-rules")
        .add_header(header::AUTHORIZATION, app.api_key_header(&token))
        .json(&json!({
            "name": "test-rule-create",
            "user_group_uuid": ug.to_string(),
            "asset_group_uuid": ag.to_string(),
            "allowed_protocols": ["ssh", "rdp"]
        }))
        .await;

    assert_status(&response, 200);

    let body: serde_json::Value = response.json();
    assert!(body.get("uuid").is_some(), "Response should contain uuid");
    assert_eq!(body["name"], "test-rule-create");
    assert!(
        body.get("user_group_name").is_some(),
        "Response should contain user_group_name"
    );
    assert!(
        body.get("asset_group_name").is_some(),
        "Response should contain asset_group_name"
    );
    assert_eq!(body["is_active"], true);

    let protos = body["allowed_protocols"]
        .as_array()
        .expect("protocols array");
    assert!(protos.contains(&json!("ssh")));
    assert!(protos.contains(&json!("rdp")));
}

#[tokio::test]
async fn test_api_create_access_rule_validation_error_empty_name() {
    let app = TestApp::spawn().await;
    let (token, _) = setup_admin(app, "ar_empty_admin").await;
    let (ug, ag) = setup_groups(app).await;

    let response = app
        .server
        .post("/api/v1/access-rules")
        .add_header(header::AUTHORIZATION, app.api_key_header(&token))
        .json(&json!({
            "name": "",
            "user_group_uuid": ug.to_string(),
            "asset_group_uuid": ag.to_string()
        }))
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 400 || status == 422,
        "Expected 400 or 422 for empty name, got {}",
        status
    );
}

#[tokio::test]
async fn test_api_create_access_rule_invalid_user_group_uuid() {
    let app = TestApp::spawn().await;
    let (token, _) = setup_admin(app, "ar_inv_ug_admin").await;
    let mut conn = app.get_conn().await;
    let ag = create_test_asset_group(&mut conn, &unique_name("ar-ag-inv-ug")).await;

    let response = app
        .server
        .post("/api/v1/access-rules")
        .add_header(header::AUTHORIZATION, app.api_key_header(&token))
        .json(&json!({
            "name": "rule-bad-ug",
            "user_group_uuid": Uuid::new_v4().to_string(),
            "asset_group_uuid": ag.to_string()
        }))
        .await;

    assert_status(&response, 404);
}

#[tokio::test]
async fn test_api_create_access_rule_invalid_asset_group_uuid() {
    let app = TestApp::spawn().await;
    let (token, _) = setup_admin(app, "ar_inv_ag_admin").await;
    let mut conn = app.get_conn().await;
    let ug = create_test_vauban_group(&mut conn, &unique_name("ar_ug_inv_ag")).await;

    let response = app
        .server
        .post("/api/v1/access-rules")
        .add_header(header::AUTHORIZATION, app.api_key_header(&token))
        .json(&json!({
            "name": "rule-bad-ag",
            "user_group_uuid": ug.to_string(),
            "asset_group_uuid": Uuid::new_v4().to_string()
        }))
        .await;

    assert_status(&response, 404);
}

#[tokio::test]
async fn test_api_create_access_rule_duplicate() {
    let app = TestApp::spawn().await;
    let (token, _) = setup_admin(app, "ar_dup_admin").await;
    let (ug, ag) = setup_groups(app).await;

    let payload = json!({
        "name": "rule-dup-first",
        "user_group_uuid": ug.to_string(),
        "asset_group_uuid": ag.to_string(),
        "allowed_protocols": ["ssh"]
    });

    let first = app
        .server
        .post("/api/v1/access-rules")
        .add_header(header::AUTHORIZATION, app.api_key_header(&token))
        .json(&payload)
        .await;
    assert_status(&first, 200);

    let second = app
        .server
        .post("/api/v1/access-rules")
        .add_header(header::AUTHORIZATION, app.api_key_header(&token))
        .json(&json!({
            "name": "rule-dup-second",
            "user_group_uuid": ug.to_string(),
            "asset_group_uuid": ag.to_string(),
            "allowed_protocols": ["rdp"]
        }))
        .await;

    let status = second.status_code().as_u16();
    assert!(
        status == 400 || status == 422,
        "Expected 400 or 422 for duplicate rule, got {}",
        status
    );
}

#[tokio::test]
async fn test_api_list_access_rules_success() {
    let app = TestApp::spawn().await;
    let (token, _) = setup_admin(app, "ar_list_admin").await;
    let (ug, ag) = setup_groups(app).await;

    let create_resp = app
        .server
        .post("/api/v1/access-rules")
        .add_header(header::AUTHORIZATION, app.api_key_header(&token))
        .json(&json!({
            "name": "rule-for-listing",
            "user_group_uuid": ug.to_string(),
            "asset_group_uuid": ag.to_string(),
            "allowed_protocols": ["ssh"]
        }))
        .await;
    assert_status(&create_resp, 200);

    let response = app
        .server
        .get("/api/v1/access-rules")
        .add_header(header::AUTHORIZATION, app.api_key_header(&token))
        .await;

    assert_status(&response, 200);

    let body: serde_json::Value = response.json();
    let arr = body.as_array().expect("Response should be a JSON array");
    assert!(
        arr.iter().any(|r| r["name"] == "rule-for-listing"),
        "List should contain the created rule"
    );
}

#[tokio::test]
async fn test_api_get_access_rule_success() {
    let app = TestApp::spawn().await;
    let (token, _) = setup_admin(app, "ar_get_admin").await;
    let (ug, ag) = setup_groups(app).await;

    let create_resp = app
        .server
        .post("/api/v1/access-rules")
        .add_header(header::AUTHORIZATION, app.api_key_header(&token))
        .json(&json!({
            "name": "rule-for-get",
            "user_group_uuid": ug.to_string(),
            "asset_group_uuid": ag.to_string(),
            "allowed_protocols": ["ssh", "rdp"]
        }))
        .await;
    assert_status(&create_resp, 200);

    let created: serde_json::Value = create_resp.json();
    let rule_uuid = created["uuid"].as_str().expect("uuid in create response");

    let response = app
        .server
        .get(&format!("/api/v1/access-rules/{}", rule_uuid))
        .add_header(header::AUTHORIZATION, app.api_key_header(&token))
        .await;

    assert_status(&response, 200);

    let body: serde_json::Value = response.json();
    assert_eq!(body["uuid"], rule_uuid);
    assert_eq!(body["name"], "rule-for-get");
}

#[tokio::test]
async fn test_api_get_access_rule_not_found() {
    let app = TestApp::spawn().await;
    let (token, _) = setup_admin(app, "ar_get404_admin").await;

    let response = app
        .server
        .get(&format!("/api/v1/access-rules/{}", Uuid::new_v4()))
        .add_header(header::AUTHORIZATION, app.api_key_header(&token))
        .await;

    assert_status(&response, 404);
}

#[tokio::test]
async fn test_api_update_access_rule_success() {
    let app = TestApp::spawn().await;
    let (token, _) = setup_admin(app, "ar_upd_admin").await;
    let (ug, ag) = setup_groups(app).await;

    let create_resp = app
        .server
        .post("/api/v1/access-rules")
        .add_header(header::AUTHORIZATION, app.api_key_header(&token))
        .json(&json!({
            "name": "rule-before-update",
            "user_group_uuid": ug.to_string(),
            "asset_group_uuid": ag.to_string()
        }))
        .await;
    assert_status(&create_resp, 200);

    let created: serde_json::Value = create_resp.json();
    let rule_uuid = created["uuid"].as_str().expect("uuid");

    let response = app
        .server
        .put(&format!("/api/v1/access-rules/{}", rule_uuid))
        .add_header(header::AUTHORIZATION, app.api_key_header(&token))
        .json(&json!({
            "name": "rule-after-update"
        }))
        .await;

    assert_status(&response, 200);

    let body: serde_json::Value = response.json();
    assert_eq!(body["name"], "rule-after-update");
}

#[tokio::test]
async fn test_api_update_access_rule_toggle_active() {
    let app = TestApp::spawn().await;
    let (token, _) = setup_admin(app, "ar_toggle_admin").await;
    let (ug, ag) = setup_groups(app).await;

    let create_resp = app
        .server
        .post("/api/v1/access-rules")
        .add_header(header::AUTHORIZATION, app.api_key_header(&token))
        .json(&json!({
            "name": "rule-toggle-active",
            "user_group_uuid": ug.to_string(),
            "asset_group_uuid": ag.to_string()
        }))
        .await;
    assert_status(&create_resp, 200);

    let created: serde_json::Value = create_resp.json();
    let rule_uuid = created["uuid"].as_str().expect("uuid");
    assert_eq!(created["is_active"], true);

    let response = app
        .server
        .put(&format!("/api/v1/access-rules/{}", rule_uuid))
        .add_header(header::AUTHORIZATION, app.api_key_header(&token))
        .json(&json!({ "is_active": false }))
        .await;

    assert_status(&response, 200);

    let body: serde_json::Value = response.json();
    assert_eq!(body["is_active"], false, "Rule should be deactivated");
}

#[tokio::test]
async fn test_api_delete_access_rule_success() {
    let app = TestApp::spawn().await;
    let (token, _) = setup_admin(app, "ar_del_admin").await;
    let (ug, ag) = setup_groups(app).await;

    let create_resp = app
        .server
        .post("/api/v1/access-rules")
        .add_header(header::AUTHORIZATION, app.api_key_header(&token))
        .json(&json!({
            "name": "rule-to-delete",
            "user_group_uuid": ug.to_string(),
            "asset_group_uuid": ag.to_string()
        }))
        .await;
    assert_status(&create_resp, 200);

    let created: serde_json::Value = create_resp.json();
    let rule_uuid = created["uuid"].as_str().expect("uuid");

    let response = app
        .server
        .delete(&format!("/api/v1/access-rules/{}", rule_uuid))
        .add_header(header::AUTHORIZATION, app.api_key_header(&token))
        .await;

    assert_status(&response, 200);

    let get_resp = app
        .server
        .get(&format!("/api/v1/access-rules/{}", rule_uuid))
        .add_header(header::AUTHORIZATION, app.api_key_header(&token))
        .await;
    assert_status(&get_resp, 404);
}

#[tokio::test]
async fn test_api_delete_access_rule_not_found() {
    let app = TestApp::spawn().await;
    let (token, _) = setup_admin(app, "ar_del404_admin").await;

    let response = app
        .server
        .delete(&format!("/api/v1/access-rules/{}", Uuid::new_v4()))
        .add_header(header::AUTHORIZATION, app.api_key_header(&token))
        .await;

    assert_status(&response, 404);
}

// =============================================================================
// Authorization Tests
// =============================================================================

#[tokio::test]
async fn test_api_access_rules_requires_staff() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user_name = unique_name("ar_nostaff");
    let user_id = create_simple_user(&mut conn, &user_name).await;
    let _user_uuid = get_user_uuid(&mut conn, user_id).await;
    let (_key_uuid, token) =
        create_real_api_key(&mut conn, user_id, &[ApiKeyScope::Admin], None).await;

    let fake_uuid = Uuid::new_v4();

    // POST (create)
    let resp = app
        .server
        .post("/api/v1/access-rules")
        .add_header(header::AUTHORIZATION, app.api_key_header(&token))
        .json(&json!({
            "name": "forbidden-rule",
            "user_group_uuid": Uuid::new_v4().to_string(),
            "asset_group_uuid": Uuid::new_v4().to_string()
        }))
        .await;
    assert_status(&resp, 403);

    // GET (list)
    let resp = app
        .server
        .get("/api/v1/access-rules")
        .add_header(header::AUTHORIZATION, app.api_key_header(&token))
        .await;
    assert_status(&resp, 403);

    // GET (single)
    let resp = app
        .server
        .get(&format!("/api/v1/access-rules/{}", fake_uuid))
        .add_header(header::AUTHORIZATION, app.api_key_header(&token))
        .await;
    assert_status(&resp, 403);

    // PUT (update)
    let resp = app
        .server
        .put(&format!("/api/v1/access-rules/{}", fake_uuid))
        .add_header(header::AUTHORIZATION, app.api_key_header(&token))
        .json(&json!({ "name": "updated" }))
        .await;
    assert_status(&resp, 403);

    // DELETE
    let resp = app
        .server
        .delete(&format!("/api/v1/access-rules/{}", fake_uuid))
        .add_header(header::AUTHORIZATION, app.api_key_header(&token))
        .await;
    assert_status(&resp, 403);
}
