/// VAUBAN Web - Vauban Groups API Tests.
///
/// Tests for /api/v1/groups/* endpoints (user groups, not asset groups).
use axum::http::header::COOKIE;
use diesel::prelude::*;
use uuid::Uuid;

use crate::common::{TestApp, assertions::assert_status};
use crate::fixtures::{add_user_to_vauban_group, create_simple_admin_user, create_simple_user, create_test_vauban_group, unique_name};

/// Helper to get user UUID from user_id.
fn get_user_uuid(conn: &mut diesel::PgConnection, user_id: i32) -> Uuid {
    use vauban_web::schema::users;
    users::table
        .filter(users::id.eq(user_id))
        .select(users::uuid)
        .first(conn)
        .expect("User should exist")
}

// =============================================================================
// Group Members API Tests
// =============================================================================

#[tokio::test]
async fn test_api_list_group_members_success() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    let group_uuid = create_test_vauban_group(&mut conn, &unique_name("api-list-members"));
    let user_id = create_simple_user(&mut conn, &unique_name("api-member"));

    // Add member to group
    add_user_to_vauban_group(&mut conn, user_id, &group_uuid);

    // Create admin user for authentication
    let admin_name = unique_name("api_members_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name);
    let admin_uuid = get_user_uuid(&mut conn, admin_id);

    let token = app.generate_test_token(
        &admin_uuid.to_string(),
        &admin_name,
        true,
        true,
    );

    let response = app
        .server
        .get(&format!("/api/v1/groups/{}/members", group_uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(body.contains("members"), "Response should contain members array");
    assert!(body.contains("total"), "Response should contain total count");
}

#[tokio::test]
async fn test_api_list_group_members_not_found() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    // Create admin user for authentication
    let admin_name = unique_name("api_members_404_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name);
    let admin_uuid = get_user_uuid(&mut conn, admin_id);

    let token = app.generate_test_token(
        &admin_uuid.to_string(),
        &admin_name,
        true,
        true,
    );

    let fake_uuid = Uuid::new_v4();
    let response = app
        .server
        .get(&format!("/api/v1/groups/{}/members", fake_uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 404);
}

#[tokio::test]
async fn test_api_list_group_members_empty() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    let group_uuid = create_test_vauban_group(&mut conn, &unique_name("api-empty-group"));

    // Create admin user for authentication
    let admin_name = unique_name("api_empty_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name);
    let admin_uuid = get_user_uuid(&mut conn, admin_id);

    let token = app.generate_test_token(
        &admin_uuid.to_string(),
        &admin_name,
        true,
        true,
    );

    let response = app
        .server
        .get(&format!("/api/v1/groups/{}/members", group_uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(body.contains("\"total\":0"), "Empty group should have 0 members");
}
