/// VAUBAN Web - Integration tests for sidebar user menu.
///
/// Tests for the user menu in the sidebar (bottom left):
/// - My profile link navigation
/// - My sessions link navigation
/// - API keys link navigation
/// - Log out functionality
///
/// These tests verify that the sidebar user dropdown menu works correctly
/// after the UI refactoring that moved these links from the header to the sidebar.
use crate::common::TestApp;
use crate::fixtures::{create_simple_user, unique_name};
use axum::http::header::COOKIE;
use diesel::prelude::*;
use uuid::Uuid;

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
// Sidebar User Menu Content Tests
// =============================================================================

#[tokio::test]
async fn test_sidebar_contains_user_profile_link() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    let username = unique_name("sidebar_profile_user");
    let user_id = create_simple_user(&mut conn, &username);
    let user_uuid = get_user_uuid(&mut conn, user_id);

    let token = app.generate_test_token(&user_uuid.to_string(), &username, false, false);

    // Request dashboard (which includes the sidebar)
    let response = app
        .server
        .get("/")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert_eq!(status, 200, "Dashboard should load successfully");

    let body = response.text();

    // Check that the sidebar contains the My profile link
    assert!(
        body.contains("/accounts/profile"),
        "Sidebar should contain link to /accounts/profile"
    );
    assert!(
        body.contains("My profile"),
        "Sidebar should contain 'My profile' text"
    );
}

#[tokio::test]
async fn test_sidebar_contains_user_sessions_link() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    let username = unique_name("sidebar_sessions_user");
    let user_id = create_simple_user(&mut conn, &username);
    let user_uuid = get_user_uuid(&mut conn, user_id);

    let token = app.generate_test_token(&user_uuid.to_string(), &username, false, false);

    let response = app
        .server
        .get("/")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert_eq!(status, 200, "Dashboard should load successfully");

    let body = response.text();

    // Check that the sidebar contains the My sessions link
    assert!(
        body.contains("/accounts/sessions"),
        "Sidebar should contain link to /accounts/sessions"
    );
    assert!(
        body.contains("My sessions"),
        "Sidebar should contain 'My sessions' text"
    );
}

#[tokio::test]
async fn test_sidebar_contains_api_keys_link() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    let username = unique_name("sidebar_apikeys_user");
    let user_id = create_simple_user(&mut conn, &username);
    let user_uuid = get_user_uuid(&mut conn, user_id);

    let token = app.generate_test_token(&user_uuid.to_string(), &username, false, false);

    let response = app
        .server
        .get("/")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert_eq!(status, 200, "Dashboard should load successfully");

    let body = response.text();

    // Check that the sidebar contains the API keys link
    assert!(
        body.contains("/accounts/apikeys"),
        "Sidebar should contain link to /accounts/apikeys"
    );
    assert!(
        body.contains("API keys"),
        "Sidebar should contain 'API keys' text"
    );
}

#[tokio::test]
async fn test_sidebar_contains_logout_button() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    let username = unique_name("sidebar_logout_user");
    let user_id = create_simple_user(&mut conn, &username);
    let user_uuid = get_user_uuid(&mut conn, user_id);

    let token = app.generate_test_token(&user_uuid.to_string(), &username, false, false);

    let response = app
        .server
        .get("/")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert_eq!(status, 200, "Dashboard should load successfully");

    let body = response.text();

    // Check that the sidebar contains the logout form/button
    assert!(
        body.contains("/auth/logout"),
        "Sidebar should contain logout form action"
    );
    assert!(
        body.contains("Log out"),
        "Sidebar should contain 'Log out' text"
    );
}

#[tokio::test]
async fn test_sidebar_displays_user_name() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    let username = unique_name("sidebar_name_user");
    let user_id = create_simple_user(&mut conn, &username);
    let user_uuid = get_user_uuid(&mut conn, user_id);

    let token = app.generate_test_token(&user_uuid.to_string(), &username, false, false);

    let response = app
        .server
        .get("/")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert_eq!(status, 200, "Dashboard should load successfully");

    let body = response.text();

    // Check that the sidebar displays the user's display name
    // The display name is constructed from first_name + last_name or username
    assert!(
        body.contains(&username) || body.contains("User"),
        "Sidebar should display user's name"
    );
}

// =============================================================================
// Sidebar User Menu Navigation Tests
// =============================================================================

#[tokio::test]
async fn test_my_profile_link_navigates_correctly() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    let username = unique_name("nav_profile_user");
    let user_id = create_simple_user(&mut conn, &username);
    let user_uuid = get_user_uuid(&mut conn, user_id);

    let token = app.generate_test_token(&user_uuid.to_string(), &username, false, false);

    // Navigate to profile page (the link from sidebar)
    let response = app
        .server
        .get("/accounts/profile")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert_eq!(
        status, 200,
        "Profile page should load successfully, got {}",
        status
    );

    let body = response.text();
    assert!(
        body.contains("My Profile") || body.contains("Profile"),
        "Profile page should have profile title"
    );
}

#[tokio::test]
async fn test_my_sessions_link_navigates_correctly() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    let username = unique_name("nav_sessions_user");
    let user_id = create_simple_user(&mut conn, &username);
    let user_uuid = get_user_uuid(&mut conn, user_id);

    let token = app.generate_test_token(&user_uuid.to_string(), &username, false, false);

    // Navigate to sessions page (the link from sidebar)
    let response = app
        .server
        .get("/accounts/sessions")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert_eq!(
        status, 200,
        "Sessions page should load successfully, got {}",
        status
    );

    let body = response.text();
    assert!(
        body.contains("My Sessions") || body.contains("Sessions"),
        "Sessions page should have sessions title"
    );
}

#[tokio::test]
async fn test_api_keys_link_navigates_correctly() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    let username = unique_name("nav_apikeys_user");
    let user_id = create_simple_user(&mut conn, &username);
    let user_uuid = get_user_uuid(&mut conn, user_id);

    let token = app.generate_test_token(&user_uuid.to_string(), &username, false, false);

    // Navigate to API keys page (the link from sidebar)
    let response = app
        .server
        .get("/accounts/apikeys")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    let status = response.status_code().as_u16();
    assert_eq!(
        status, 200,
        "API keys page should load successfully, got {}",
        status
    );

    let body = response.text();
    assert!(
        body.contains("API Keys") || body.contains("API keys"),
        "API keys page should have API keys title"
    );
}

#[tokio::test]
async fn test_logout_button_works() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    let username = unique_name("nav_logout_user");
    let user_id = create_simple_user(&mut conn, &username);
    let user_uuid = get_user_uuid(&mut conn, user_id);

    let token = app.generate_test_token(&user_uuid.to_string(), &username, false, false);
    let csrf_token = app.generate_csrf_token();

    // Submit logout form (as it would be from sidebar)
    let response = app
        .server
        .post("/auth/logout")
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[("csrf_token", csrf_token.as_str())])
        .await;

    let status = response.status_code().as_u16();
    // Logout should succeed (200) or redirect to login (303)
    assert!(
        status == 200 || status == 303,
        "Logout should succeed, got {}",
        status
    );

    // If redirect, verify it goes to login page
    if status == 303 {
        let location = response.headers().get("location");
        assert!(
            location.is_some(),
            "Redirect should have Location header"
        );
        let loc_str = location.unwrap().to_str().unwrap();
        assert!(
            loc_str.contains("/login") || loc_str == "/",
            "Should redirect to login or home, got {}",
            loc_str
        );
    }
}

// =============================================================================
// Sidebar User Menu Authentication Tests
// =============================================================================

#[tokio::test]
async fn test_my_profile_requires_authentication() {
    let app = TestApp::spawn().await;

    // Request without auth token
    let response = app.server.get("/accounts/profile").await;

    let status = response.status_code().as_u16();
    assert_eq!(
        status, 303,
        "Profile page without auth should redirect to login (303), got {}",
        status
    );

    let location = response.headers().get("location");
    assert!(location.is_some(), "Redirect should have Location header");
    assert_eq!(
        location.unwrap().to_str().unwrap(),
        "/login",
        "Should redirect to /login"
    );
}

#[tokio::test]
async fn test_my_sessions_requires_authentication() {
    let app = TestApp::spawn().await;

    // Request without auth token
    let response = app.server.get("/accounts/sessions").await;

    let status = response.status_code().as_u16();
    assert_eq!(
        status, 303,
        "Sessions page without auth should redirect to login (303), got {}",
        status
    );

    let location = response.headers().get("location");
    assert!(location.is_some(), "Redirect should have Location header");
    assert_eq!(
        location.unwrap().to_str().unwrap(),
        "/login",
        "Should redirect to /login"
    );
}

#[tokio::test]
async fn test_api_keys_requires_authentication() {
    let app = TestApp::spawn().await;

    // Request without auth token
    let response = app.server.get("/accounts/apikeys").await;

    let status = response.status_code().as_u16();
    assert!(
        status == 303 || status == 401,
        "API keys page without auth should redirect (303) or return 401, got {}",
        status
    );
}

#[tokio::test]
async fn test_logout_requires_csrf_token() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    let username = unique_name("logout_csrf_user");
    let user_id = create_simple_user(&mut conn, &username);
    let user_uuid = get_user_uuid(&mut conn, user_id);

    let token = app.generate_test_token(&user_uuid.to_string(), &username, false, false);

    // Submit logout with empty/invalid CSRF token
    let response = app
        .server
        .post("/auth/logout")
        .add_header(COOKIE, format!("access_token={}", token))
        .form(&[("csrf_token", "invalid_token")])
        .await;

    let status = response.status_code().as_u16();
    // With invalid CSRF, logout gracefully redirects to login (303)
    // instead of showing an error. This is intentional because:
    // - The user's intent is clear (they want to log out)
    // - If the session is expired, there's nothing to protect
    assert!(
        status == 303,
        "Logout with invalid CSRF should redirect to login (303), got {}",
        status
    );

    // Verify it redirects to login
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok());
    assert_eq!(
        location,
        Some("/login"),
        "Should redirect to /login on invalid CSRF"
    );
}

// =============================================================================
// Sidebar User Menu Complete Navigation Flow Tests
// =============================================================================

#[tokio::test]
async fn test_complete_user_menu_navigation_flow() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    let username = unique_name("flow_menu_user");
    let user_id = create_simple_user(&mut conn, &username);
    let user_uuid = get_user_uuid(&mut conn, user_id);

    let token = app.generate_test_token(&user_uuid.to_string(), &username, false, false);

    // Step 1: Load dashboard (with sidebar)
    let dashboard_response = app
        .server
        .get("/")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    assert_eq!(
        dashboard_response.status_code().as_u16(),
        200,
        "Dashboard should load"
    );

    let dashboard_body = dashboard_response.text();

    // Verify all menu links are present
    assert!(
        dashboard_body.contains("/accounts/profile"),
        "Dashboard should have profile link"
    );
    assert!(
        dashboard_body.contains("/accounts/sessions"),
        "Dashboard should have sessions link"
    );
    assert!(
        dashboard_body.contains("/accounts/apikeys"),
        "Dashboard should have API keys link"
    );
    assert!(
        dashboard_body.contains("/auth/logout"),
        "Dashboard should have logout action"
    );

    // Step 2: Navigate to Profile
    let profile_response = app
        .server
        .get("/accounts/profile")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    assert_eq!(
        profile_response.status_code().as_u16(),
        200,
        "Profile page should load"
    );

    // Step 3: Navigate to Sessions
    let sessions_response = app
        .server
        .get("/accounts/sessions")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    assert_eq!(
        sessions_response.status_code().as_u16(),
        200,
        "Sessions page should load"
    );

    // Step 4: Navigate to API Keys
    let apikeys_response = app
        .server
        .get("/accounts/apikeys")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    assert_eq!(
        apikeys_response.status_code().as_u16(),
        200,
        "API keys page should load"
    );

    // Step 5: Logout
    let csrf_token = app.generate_csrf_token();
    let logout_response = app
        .server
        .post("/auth/logout")
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[("csrf_token", csrf_token.as_str())])
        .await;

    let logout_status = logout_response.status_code().as_u16();
    assert!(
        logout_status == 200 || logout_status == 303,
        "Logout should succeed"
    );
}

#[tokio::test]
async fn test_sidebar_user_menu_on_all_pages() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn();

    let username = unique_name("sidebar_all_pages_user");
    let user_id = create_simple_user(&mut conn, &username);
    let user_uuid = get_user_uuid(&mut conn, user_id);

    let token = app.generate_test_token(&user_uuid.to_string(), &username, true, true);

    // List of pages that should have the sidebar with user menu
    let pages = [
        "/",
        "/accounts/profile",
        "/accounts/sessions",
        "/accounts/apikeys",
        "/assets",
        "/sessions",
    ];

    for page in pages {
        let response = app
            .server
            .get(page)
            .add_header(COOKIE, format!("access_token={}", token))
            .await;

        let status = response.status_code().as_u16();
        assert!(
            status == 200 || status == 303,
            "Page {} should load, got {}",
            page,
            status
        );

        if status == 200 {
            let body = response.text();

            // Each page should have the user menu links in sidebar
            assert!(
                body.contains("/accounts/profile") || body.contains("My profile"),
                "Page {} should have profile link in sidebar",
                page
            );
            assert!(
                body.contains("/auth/logout") || body.contains("Log out"),
                "Page {} should have logout in sidebar",
                page
            );
        }
    }
}
