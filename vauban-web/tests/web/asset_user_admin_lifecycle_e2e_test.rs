//! Issue #27 — end-to-end lifecycle test exercising both the user
//! and admin asset zones in a single flow.
//!
//! Steps (single TestApp, two roles, one asset):
//!
//! 1. **Admin** GETs `/assets/manage/` → 200 OK (admin list).
//! 2. **Admin** GETs `/assets/manage/new` → 200 OK (create form).
//! 3. (Skip POST create: it requires the full CSRF + form pipeline
//!    which is exercised by `asset_pages_test.rs`.) Instead seed the
//!    asset directly via `create_test_ssh_asset`.
//! 4. **Admin** GETs `/assets/manage/{uuid}` → 200 OK (admin detail).
//! 5. **Admin** GETs `/assets/manage/{uuid}/edit` → 200 OK.
//! 6. **Regular user** GETs `/assets` → 200 OK and the response body
//!    DOES NOT advertise the admin sub-tree.
//! 7. **Regular user** GETs `/assets/manage/{uuid}` → 403 Forbidden
//!    (the admin gate refuses).
//! 8. **Regular user** GETs `/assets/manage/{uuid}/edit` → 403.
//! 9. **Regular user** POSTs `/assets/manage/{uuid}/delete` → 403.
//!
//! Each assertion below is the canonical proof-of-regression for
//! one of the eight invariants the issue cares about.

use axum::http::header::COOKIE;
use serial_test::serial;

use crate::common::{TestApp, assertions::assert_status};
use crate::fixtures::{create_admin_user, create_test_ssh_asset, create_test_user, unique_name};

#[tokio::test]
#[serial]
async fn admin_and_user_asset_lifecycle_end_to_end() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Two users on the same TestApp so the JWT session pool stays
    // consistent and the policy is loaded once.
    let admin_name = unique_name("e2e_admin");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let user_name = unique_name("e2e_user");
    let user = create_test_user(&mut conn, &app.auth_service, &user_name).await;

    // Seed an asset directly so we do not have to roundtrip the full
    // create form (covered by asset_pages_test.rs).
    let asset = create_test_ssh_asset(&mut conn, &unique_name("e2e_asset")).await;
    let asset_uuid = asset.asset.uuid;

    // ----- Admin (role:superuser) walk-through. -----

    // Use /assets/manage/new as the canonical entry point; the bare
    // root /assets/manage[/] is intercepted by the user-zone
    // /assets/{uuid} route in the test router (uuid="manage") and
    // its handling is pinned separately by
    // `manage_assets_gate_matrix_test`.
    let resp = app
        .server
        .get("/assets/manage/new")
        .add_header(COOKIE, format!("access_token={}", admin.token))
        .await;
    assert_status(&resp, 200);
    assert!(
        resp.text().contains("New Asset")
            || resp.text().contains("New asset")
            || resp.text().contains("Save"),
        "admin GET /assets/manage/new must render the create form"
    );

    let resp = app
        .server
        .get(&format!("/assets/manage/{}", asset_uuid))
        .add_header(COOKIE, format!("access_token={}", admin.token))
        .await;
    assert_status(&resp, 200);
    let admin_detail_body = resp.text();
    // Admin detail MUST NOT advertise end-user actions (issue #27).
    assert!(
        !admin_detail_body.contains("submit_access_request"),
        "admin detail page must not carry end-user `submit_access_request` references"
    );

    let resp = app
        .server
        .get(&format!("/assets/manage/{}/edit", asset_uuid))
        .add_header(COOKIE, format!("access_token={}", admin.token))
        .await;
    assert_status(&resp, 200);

    // ----- Regular user (role:user) walk-through. -----

    let resp = app
        .server
        .get("/assets")
        .add_header(COOKIE, format!("access_token={}", user.token))
        .await;
    assert_status(&resp, 200);
    let user_list_body = resp.text();
    // The user-zone list MUST NOT leak the admin sub-tree URLs.
    assert!(
        !user_list_body.contains("/assets/manage"),
        "GET /assets (user zone) MUST NOT advertise /assets/manage/* URLs in the rendered HTML"
    );

    // Admin sub-tree: every action MUST refuse with 403.
    for url in [
        format!("/assets/manage/{}", asset_uuid),
        format!("/assets/manage/{}/edit", asset_uuid),
    ] {
        let resp = app
            .server
            .get(&url)
            .add_header(COOKIE, format!("access_token={}", user.token))
            .await;
        assert_status(&resp, 403);
    }

    let resp = app
        .server
        .post(&format!("/assets/manage/{}/delete", asset_uuid))
        .add_header(COOKIE, format!("access_token={}", user.token))
        .await;
    assert_status(&resp, 403);

    // Final assertion: the admin can still operate on the asset
    // (i.e. the user's denied probes did not leave the admin gate
    // in a bad state).
    let resp = app
        .server
        .get(&format!("/assets/manage/{}", asset_uuid))
        .add_header(COOKIE, format!("access_token={}", admin.token))
        .await;
    assert_status(&resp, 200);
}
