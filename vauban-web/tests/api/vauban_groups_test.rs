/// VAUBAN Web - Vauban Groups API Tests.
///
/// Tests for /api/v1/groups/* endpoints (user groups, not asset groups).
use axum::http::header;
use uuid::Uuid;
use vauban_web::models::api_key::ApiKeyScope;

use crate::common::{TestApp, assertions::assert_status};
use crate::fixtures::{
    add_user_to_vauban_group, create_real_api_key, create_simple_admin_user, create_simple_user,
    create_test_vauban_group, unique_name,
};

// =============================================================================
// Group Members API Tests
// =============================================================================

#[tokio::test]
async fn test_api_list_group_members_success() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let group_uuid = create_test_vauban_group(&mut conn, &unique_name("api-list-members")).await;
    let user_id = create_simple_user(&mut conn, &unique_name("api-member")).await;

    // Add member to group
    add_user_to_vauban_group(&mut conn, user_id, &group_uuid).await;

    // Create admin user for authentication
    let admin_name = unique_name("api_members_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let (_key_uuid, token) =
        create_real_api_key(&mut conn, admin_id, &[ApiKeyScope::Admin], None).await;

    let response = app
        .server
        .get(&format!("/api/v1/groups/{}/members", group_uuid))
        .add_header(header::AUTHORIZATION, app.api_key_header(&token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(
        body.contains("members"),
        "Response should contain members array"
    );
    assert!(
        body.contains("total"),
        "Response should contain total count"
    );
}

#[tokio::test]
async fn test_api_list_group_members_not_found() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Create admin user for authentication
    let admin_name = unique_name("api_members_404_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let (_key_uuid, token) =
        create_real_api_key(&mut conn, admin_id, &[ApiKeyScope::Admin], None).await;

    let fake_uuid = Uuid::new_v4();
    let response = app
        .server
        .get(&format!("/api/v1/groups/{}/members", fake_uuid))
        .add_header(header::AUTHORIZATION, app.api_key_header(&token))
        .await;

    assert_status(&response, 404);
}

#[tokio::test]
async fn test_api_list_group_members_empty() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let group_uuid = create_test_vauban_group(&mut conn, &unique_name("api-empty-group")).await;

    // Create admin user for authentication
    let admin_name = unique_name("api_empty_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let (_key_uuid, token) =
        create_real_api_key(&mut conn, admin_id, &[ApiKeyScope::Admin], None).await;

    let response = app
        .server
        .get(&format!("/api/v1/groups/{}/members", group_uuid))
        .add_header(header::AUTHORIZATION, app.api_key_header(&token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(
        body.contains("\"total\":0"),
        "Empty group should have 0 members"
    );
}
