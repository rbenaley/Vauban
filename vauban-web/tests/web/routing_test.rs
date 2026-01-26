/// VAUBAN Web - Routing Tests.
///
/// Tests for fallback routes, malformed UUID handling, and route ordering.
use crate::common::{TestApp, assertions::assert_status, unwrap_ok};
use crate::fixtures::{create_simple_admin_user, unique_name};
use axum::http::header::COOKIE;
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use uuid::Uuid;

/// Helper to get user UUID from user_id.
async fn get_user_uuid(conn: &mut AsyncPgConnection, user_id: i32) -> Uuid {
    use vauban_web::schema::users;
    unwrap_ok!(users::table
        .filter(users::id.eq(user_id))
        .select(users::uuid)
        .first(conn)
        .await)
}

// =============================================================================
// Fallback Route Tests
// =============================================================================

#[tokio::test]
async fn test_fallback_route_redirects_to_home() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("fallback_test_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_name, true, true).await;

    // Try to access a non-existent route
    let response = app
        .server
        .get("/this-route-does-not-exist-xyz123")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    // Should redirect to home page
    assert_status(&response, 303);
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok());
    assert_eq!(location, Some("/"));
}

#[tokio::test]
async fn test_fallback_route_with_random_path() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("fallback_rand_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_name, true, true).await;

    // Try various non-existent paths
    let paths = [
        "/sdlakd324324",
        "/random/nested/path",
        "/foo/bar/baz",
        "/not-a-real-endpoint",
    ];

    for path in paths {
        let response = app
            .server
            .get(path)
            .add_header(COOKIE, format!("access_token={}", token))
            .await;

        let status = response.status_code().as_u16();
        let location = response
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok());

        assert!(
            status == 303 && location == Some("/"),
            "Path {} should redirect to /, got status {} location {:?}",
            path,
            status,
            location
        );
    }
}

#[tokio::test]
async fn test_fallback_route_unauthenticated() {
    let app = TestApp::spawn().await;

    // Even without auth, random paths should redirect to /
    let response = app.server.get("/random-path-no-auth").await;

    let status = response.status_code().as_u16();
    assert!(
        status == 303,
        "Unauthenticated access to unknown path should redirect, got {}",
        status
    );
}

// =============================================================================
// Malformed UUID Tests
// =============================================================================

#[tokio::test]
async fn test_asset_detail_with_malformed_uuid() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("malformed_uuid_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_name, true, true).await;

    // Try various malformed UUIDs - all should redirect gracefully to /assets
    let malformed_uuids = [
        "not-a-uuid",
        "12345",
        "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "123e4567-e89b-12d3-a456",  // Too short
        "123e4567-e89b-12d3-a456-4266141740001234",  // Too long
        "24d3cc30-d6c0-ooo7-be9a-978dd250ae3e",  // Invalid character 'o' in hex
    ];

    for bad_uuid in malformed_uuids {
        let response = app
            .server
            .get(&format!("/assets/{}", bad_uuid))
            .add_header(COOKIE, format!("access_token={}", token))
            .await;

        let status = response.status_code().as_u16();
        let location = response.headers().get("location").and_then(|v| v.to_str().ok());

        assert!(
            status == 303 && location == Some("/assets"),
            "Malformed UUID '{}' should redirect to /assets with 303, got status {} location {:?}",
            bad_uuid,
            status,
            location
        );
    }
}

#[tokio::test]
async fn test_user_detail_with_malformed_uuid() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("user_malformed_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_name, true, true).await;

    let response = app
        .server
        .get("/accounts/users/not-a-valid-uuid")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 303);
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok());
    assert_eq!(location, Some("/accounts/users"));
}

#[tokio::test]
async fn test_group_detail_with_malformed_uuid() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("grp_malformed_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_name, true, true).await;

    let response = app
        .server
        .get("/accounts/groups/invalid-uuid-here")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 303);
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok());
    assert_eq!(location, Some("/accounts/groups"));
}

#[tokio::test]
async fn test_asset_group_detail_with_malformed_uuid() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("agrp_malformed_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_name, true, true).await;

    let response = app
        .server
        .get("/assets/groups/totally-not-uuid")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 303);
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok());
    assert_eq!(location, Some("/assets/groups"));
}

#[tokio::test]
async fn test_approval_detail_with_malformed_uuid() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("appr_malformed_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let token = app.generate_test_token(&admin_uuid.to_string(), &admin_name, true, true).await;

    let response = app
        .server
        .get("/sessions/approvals/bad-uuid-format")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 303);
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok());
    assert_eq!(location, Some("/sessions/approvals"));
}
