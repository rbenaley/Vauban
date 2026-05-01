//! Issue #27 — sidebar visibility contract for the asset zone split.
//!
//! Render the dashboard for four user contexts and assert that:
//!
//! 1. Regular user — sidebar shows "Assets" but NEVER "Manage Assets"
//!    or "Deleted assets" (the latter live under `/assets/manage/*`).
//! 2. Staff      — sidebar shows BOTH "Assets" and "Manage Assets".
//! 3. Superuser  — sidebar shows BOTH.
//! 4. Unauthenticated — no asset link at all (no sidebar rendered).

use axum::http::header::COOKIE;
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::RunQueryDsl;
use serial_test::serial;
use uuid::Uuid;

use crate::common::{TestApp, unwrap_ok};
use crate::fixtures::{create_simple_user, unique_name};

async fn user_uuid_for(app: &TestApp, user_id: i32) -> Uuid {
    use vauban_web::schema::users;
    let mut conn = app.get_conn().await;
    unwrap_ok!(
        users::table
            .filter(users::id.eq(user_id))
            .select(users::uuid)
            .first(&mut conn)
            .await
    )
}

async fn dashboard_body(app: &TestApp, token: Option<&str>) -> String {
    let req = app.server.get("/");
    let req = match token {
        Some(t) => req.add_header(COOKIE, format!("access_token={}", t)),
        None => req,
    };
    let response = req.await;
    response.text()
}

/// Regular user: sees "Assets" but NOT "Manage Assets" / "Deleted assets".
#[tokio::test]
#[serial]
async fn sidebar_regular_user_hides_manage_assets_entry() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("sidebar_split_user");
    let user_id = create_simple_user(&mut conn, &username).await;
    let uuid = user_uuid_for(app, user_id).await;
    let token = app
        .generate_test_token(&uuid.to_string(), &username, false, false)
        .await;

    let body = dashboard_body(app, Some(&token)).await;

    // The user-zone entry MUST be visible.
    assert!(
        body.contains("href=\"/assets\""),
        "regular user must see the user-zone Assets sidebar entry"
    );

    // The admin-zone entries MUST NOT be visible.
    assert!(
        !body.contains("/assets/manage"),
        "regular user MUST NOT see ANY /assets/manage/* link in the \
         sidebar (issue #27 zone split). Body contained the admin URL."
    );
    assert!(
        !body.contains(">Manage Assets<"),
        "regular user MUST NOT see the 'Manage Assets' label in the sidebar"
    );
}

/// Staff: sees BOTH the user-zone Assets and the admin Manage Assets
/// entries. Mirrors the production Casbin policy (`role:staff` is
/// granted both `assets:read` and `assets:manage`).
#[tokio::test]
#[serial]
async fn sidebar_staff_shows_both_zones() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("sidebar_split_staff");
    let user_id = create_simple_user(&mut conn, &username).await;

    {
        use vauban_web::schema::users;
        unwrap_ok!(
            diesel::update(users::table.filter(users::id.eq(user_id)))
                .set(users::is_staff.eq(true))
                .execute(&mut conn)
                .await
        );
    }

    let uuid = user_uuid_for(app, user_id).await;
    let token = app
        .generate_test_token(&uuid.to_string(), &username, false, true)
        .await;

    let body = dashboard_body(app, Some(&token)).await;

    assert!(
        body.contains("href=\"/assets\""),
        "staff must see the user-zone Assets entry"
    );
    assert!(
        body.contains("/assets/manage"),
        "staff must see at least one /assets/manage/* link in the sidebar"
    );
}

/// Superuser: identical contract to staff (the wildcard policy
/// matches every permission, including `assets:manage`).
#[tokio::test]
#[serial]
async fn sidebar_superuser_shows_both_zones() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("sidebar_split_super");
    let user_id = create_simple_user(&mut conn, &username).await;

    {
        use vauban_web::schema::users;
        unwrap_ok!(
            diesel::update(users::table.filter(users::id.eq(user_id)))
                .set((users::is_staff.eq(true), users::is_superuser.eq(true),))
                .execute(&mut conn)
                .await
        );
    }

    let uuid = user_uuid_for(app, user_id).await;
    let token = app
        .generate_test_token(&uuid.to_string(), &username, true, true)
        .await;

    let body = dashboard_body(app, Some(&token)).await;
    assert!(
        body.contains("/assets/manage"),
        "superuser must see /assets/manage/* in the sidebar"
    );
}
