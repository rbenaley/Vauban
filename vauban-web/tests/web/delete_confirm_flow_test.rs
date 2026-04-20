//! BUG-12 / GitHub issue #19 — anti-regression suite for the
//! styled-modal delete-confirmation flow.
//!
//! Background. Five destructive forms used `hx-confirm` without any
//! HTMX verb on the form/ancestor, so HTMX never attached and the
//! attribute was decorative — a single click destroyed data with no
//! confirmation. This module locks in the fix on three axes:
//!
//! * **HTML contract** (5 tests, tag `BUG-12-HTML-CONTRACT-20260420`)
//!   — for each affected page, the rendered HTML must carry the new
//!   `hx-post` verb, the `data-confirm-*` attributes the modal reads
//!   from, an `@htmx:confirm.prevent` listener, the `hx-confirm`
//!   fallback, and must NOT carry the legacy
//!   `method="post" action="..."` native-submit attributes for the
//!   destructive endpoint.
//!
//! * **HTMX handler dialect** (5 tests, tag
//!   `BUG-12-HTMX-REDIRECT-20260420`) — POST with `HX-Request: true`
//!   must answer with `200 OK` + `HX-Redirect: <parent>` (an empty
//!   body) AND mutate the underlying entity. Returning `303 + Location`
//!   to an HTMX request is a regression: HTMX silently follows the
//!   redirect via fetch and swaps the result into the form's default
//!   target, breaking the UX.
//!
//! * **Non-HTMX fallback** (5 tests, tag
//!   `BUG-12-NATIVE-FALLBACK-20260420`) — POST without `HX-Request`
//!   (JS-off browser, scripts, curl) must keep the historical PRG
//!   contract: `303 + Location` to the parent page AND mutate the
//!   entity. This guards against the inverse regression of always
//!   emitting `HX-Redirect` and breaking native form clients.
//!
//! Plus one JS smoke test
//! (`test_alpine_delete_confirm_store_is_registered`,
//! tag `BUG-12-DELETE-CONFIRM-COMPONENT-20260420`) that pins the
//! Alpine store registration so a future refactor of
//! `vauban-components.js` cannot silently break the modal contract.

use crate::common::{TestApp, assertions::*, test_db};
use crate::fixtures::{
    add_user_to_vauban_group, create_simple_user, create_test_asset_group,
    create_test_asset_in_group, create_test_ssh_asset, create_test_vauban_group, unique_name,
};
use axum::http::header::{COOKIE, LOCATION};
use diesel::{ExpressionMethods, OptionalExtension, QueryDsl};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serial_test::serial;
use uuid::Uuid;

// =============================================================================
// Local helpers (kept local on purpose — these tests are tightly coupled to
// the BUG-12 contract and we do not want them to drift with the shared
// fixtures over time)
// =============================================================================

/// Cookie header carrying both auth and CSRF, as the destructive web
/// handlers require (double-submit cookie pattern).
fn auth_csrf_cookie(token: &str, csrf: &str) -> String {
    format!("access_token={}; __vauban_csrf={}", token, csrf)
}

/// Build a token for an admin user. Admin (is_staff + is_superuser) is the
/// only role that can drive every one of the 5 destructive endpoints, so
/// it is the lowest common denominator across the suite.
///
/// Important: we materialize a real user row first and feed its real UUID
/// to `generate_test_token`. Passing a freshly-minted random UUID would
/// race the helper's "find-or-create" path against the auth middleware,
/// which then redirects to `/login` because the FK from `auth_sessions`
/// to `users` resolves to `id=1` (the helper's fallback). We hit exactly
/// that trap on the first iteration of this suite — keeping the user
/// creation explicit makes the failure mode local and obvious.
async fn admin_token(app: &TestApp, label: &str) -> String {
    use crate::fixtures::create_simple_admin_user;
    let mut conn = app.get_conn().await;
    let user_id = create_simple_admin_user(&mut conn, label).await;
    let user_uuid = lookup_user_uuid(&mut conn, user_id).await;
    app.generate_test_token(&user_uuid.to_string(), label, true, true)
        .await
}

/// Lookup a user UUID by id (mirrors the inline helper used elsewhere in
/// the test tree — kept local so this file stays self-contained).
async fn lookup_user_uuid(conn: &mut AsyncPgConnection, user_id: i32) -> Uuid {
    use vauban_web::schema::users;
    users::table
        .filter(users::id.eq(user_id))
        .select(users::uuid)
        .first(conn)
        .await
        .expect("user must exist")
}

// =============================================================================
// Section A. HTML contract — the destructive forms must be HTMX-driven.
//                            tag: BUG-12-HTML-CONTRACT-20260420
// =============================================================================

/// Form #1 — Delete asset, on `/assets/{uuid}`.
#[tokio::test]
#[serial]
async fn test_asset_detail_delete_form_is_htmx_driven() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let token = admin_token(app, "bug12_html_asset_delete").await;

    let asset = create_test_ssh_asset(&mut conn, &unique_name("bug12-asset-detail")).await;

    let response = app
        .server
        .get(&format!("/assets/{}", asset.asset.uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    assert_status(&response, 200);

    let body = response.text();
    let endpoint = format!("/assets/{}/delete", asset.asset.uuid);

    assert!(
        body.contains(&format!("hx-post=\"{}\"", endpoint)),
        "delete asset form must be HTMX-driven (hx-post present): {}",
        endpoint
    );
    // Anti-regression marker: the prior form had `method="post"` together
    // with `action="..."` for this endpoint. If we ever see that pattern
    // re-emerge on this endpoint, we are back to the silent-confirm bug.
    assert!(
        !body.contains(&format!("action=\"{}\"", endpoint)),
        "BUG-12-NO-NATIVE-POST-20260420: native action= MUST NOT target {} anymore",
        endpoint
    );
    assert!(
        body.contains("data-confirm-title=\"Delete asset\""),
        "form must carry data-confirm-title for the styled modal"
    );
    assert!(
        body.contains(&asset.asset.name),
        "modal copy must name the resource (asset name '{}')",
        asset.asset.name
    );
    assert!(
        body.contains("@htmx:confirm.prevent"),
        "form must intercept htmx:confirm to dispatch the modal"
    );
    assert!(
        body.contains("hx-confirm="),
        "hx-confirm fallback must remain (defense-in-depth if Alpine is unavailable)"
    );

    test_db::cleanup(&mut conn).await;
}

/// Form #2 — Delete account group, on `/accounts/groups/{uuid}`.
#[tokio::test]
#[serial]
async fn test_account_group_detail_delete_form_is_htmx_driven() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let token = admin_token(app, "bug12_html_acct_grp_delete").await;

    let group_uuid = create_test_vauban_group(&mut conn, &unique_name("bug12-acct-grp")).await;

    let response = app
        .server
        .get(&format!("/accounts/groups/{}", group_uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    assert_status(&response, 200);

    let body = response.text();
    let endpoint = format!("/accounts/groups/{}/delete", group_uuid);

    assert!(
        body.contains(&format!("hx-post=\"{}\"", endpoint)),
        "delete account-group form must be HTMX-driven: {}",
        endpoint
    );
    assert!(
        !body.contains(&format!("action=\"{}\"", endpoint)),
        "BUG-12-NO-NATIVE-POST-20260420: native action= MUST NOT target {} anymore",
        endpoint
    );
    assert!(
        body.contains("data-confirm-title=\"Delete account group\""),
        "form must carry data-confirm-title for the styled modal"
    );
    assert!(
        body.contains("@htmx:confirm.prevent"),
        "form must intercept htmx:confirm to dispatch the modal"
    );
    assert!(
        body.contains("hx-confirm="),
        "hx-confirm fallback must remain"
    );

    test_db::cleanup(&mut conn).await;
}

/// Form #3 — Remove member from account group, on `/accounts/groups/{uuid}`.
#[tokio::test]
#[serial]
async fn test_account_group_remove_member_form_is_htmx_driven() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let token = admin_token(app, "bug12_html_remove_member").await;

    // The remove-member form only renders when the group has members,
    // so we seed exactly one member.
    let group_uuid = create_test_vauban_group(&mut conn, &unique_name("bug12-rm-mem-grp")).await;
    let user_id = create_simple_user(&mut conn, &unique_name("bug12-rm-mem-user")).await;
    add_user_to_vauban_group(&mut conn, user_id, &group_uuid).await;
    let user_uuid = lookup_user_uuid(&mut conn, user_id).await;

    let response = app
        .server
        .get(&format!("/accounts/groups/{}", group_uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    assert_status(&response, 200);

    let body = response.text();
    let endpoint = format!(
        "/accounts/groups/{}/members/{}/remove",
        group_uuid, user_uuid
    );

    assert!(
        body.contains(&format!("hx-post=\"{}\"", endpoint)),
        "remove-member form must be HTMX-driven: {}",
        endpoint
    );
    assert!(
        !body.contains(&format!("action=\"{}\"", endpoint)),
        "BUG-12-NO-NATIVE-POST-20260420: native action= MUST NOT target {} anymore",
        endpoint
    );
    assert!(
        body.contains("data-confirm-title=\"Remove member\""),
        "form must carry data-confirm-title for the styled modal"
    );
    assert!(
        body.contains("@htmx:confirm.prevent"),
        "form must intercept htmx:confirm to dispatch the modal"
    );

    test_db::cleanup(&mut conn).await;
}

/// Form #4 — Delete asset group, on `/assets/groups/{uuid}`.
#[tokio::test]
#[serial]
async fn test_asset_group_detail_delete_form_is_htmx_driven() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let token = admin_token(app, "bug12_html_asset_grp_delete").await;

    let group_uuid = create_test_asset_group(&mut conn, &unique_name("bug12-asset-grp")).await;

    let response = app
        .server
        .get(&format!("/assets/groups/{}", group_uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    assert_status(&response, 200);

    let body = response.text();
    let endpoint = format!("/assets/groups/{}/delete", group_uuid);

    assert!(
        body.contains(&format!("hx-post=\"{}\"", endpoint)),
        "delete asset-group form must be HTMX-driven: {}",
        endpoint
    );
    assert!(
        !body.contains(&format!("action=\"{}\"", endpoint)),
        "BUG-12-NO-NATIVE-POST-20260420: native action= MUST NOT target {} anymore",
        endpoint
    );
    assert!(
        body.contains("data-confirm-title=\"Delete asset group\""),
        "form must carry data-confirm-title for the styled modal"
    );
    assert!(
        body.contains("@htmx:confirm.prevent"),
        "form must intercept htmx:confirm to dispatch the modal"
    );

    test_db::cleanup(&mut conn).await;
}

/// Form #5 — Remove asset from asset group, on `/assets/groups/{uuid}`.
#[tokio::test]
#[serial]
async fn test_asset_group_remove_asset_form_is_htmx_driven() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let token = admin_token(app, "bug12_html_remove_asset").await;
    let admin_id = create_simple_user(&mut conn, &unique_name("bug12-rm-asset-admin")).await;

    let group_uuid = create_test_asset_group(&mut conn, &unique_name("bug12-rm-asset-grp")).await;
    // The remove-asset form only renders for assets that are members of
    // the group, so we seed one.
    let _asset_id =
        create_test_asset_in_group(&mut conn, &unique_name("bug12-grp-asset"), admin_id, &group_uuid)
            .await;

    let response = app
        .server
        .get(&format!("/assets/groups/{}", group_uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    assert_status(&response, 200);

    let body = response.text();
    let endpoint = format!("/assets/groups/{}/remove-asset", group_uuid);

    assert!(
        body.contains(&format!("hx-post=\"{}\"", endpoint)),
        "remove-asset form must be HTMX-driven: {}",
        endpoint
    );
    assert!(
        !body.contains(&format!("action=\"{}\"", endpoint)),
        "BUG-12-NO-NATIVE-POST-20260420: native action= MUST NOT target {} anymore",
        endpoint
    );
    assert!(
        body.contains("data-confirm-title=\"Remove asset from group\""),
        "form must carry data-confirm-title for the styled modal"
    );
    assert!(
        body.contains("@htmx:confirm.prevent"),
        "form must intercept htmx:confirm to dispatch the modal"
    );

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// Section B. HTMX handler dialect — POST with HX-Request → 200 + HX-Redirect.
//                                   tag: BUG-12-HTMX-REDIRECT-20260420
// =============================================================================

/// Helper: assert the response speaks the HTMX-redirect dialect.
fn assert_hx_redirect(response: &axum_test::TestResponse, expected_location: &str) {
    let status = response.status_code().as_u16();
    assert_eq!(
        status, 200,
        "HTMX delete must return 200 (not 303), got {} — see htmx_or_flash_redirect",
        status
    );
    let hx_redirect = response
        .headers()
        .get("HX-Redirect")
        .and_then(|v| v.to_str().ok());
    assert_eq!(
        hx_redirect,
        Some(expected_location),
        "HX-Redirect header MUST point at {}",
        expected_location
    );
    // HX-Redirect is the entire payload — body should be empty.
    assert!(
        response.text().is_empty(),
        "HTMX-redirect responses should ship an empty body"
    );
}

#[tokio::test]
#[serial]
async fn test_htmx_delete_asset_returns_hx_redirect() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let token = admin_token(app, "bug12_htmx_delete_asset").await;
    let csrf = app.generate_csrf_token();

    let asset = create_test_ssh_asset(&mut conn, &unique_name("bug12-htmx-asset")).await;

    let response = app
        .server
        .post(&format!("/assets/{}/delete", asset.asset.uuid))
        .add_header(COOKIE, auth_csrf_cookie(&token, &csrf))
        .add_header("HX-Request", "true")
        .form(&[("csrf_token", csrf.as_str())])
        .await;

    assert_hx_redirect(&response, "/assets");

    use vauban_web::schema::assets;
    let is_deleted: bool = assets::table
        .filter(assets::uuid.eq(asset.asset.uuid))
        .select(assets::is_deleted)
        .first(&mut conn)
        .await
        .expect("asset row must still exist (soft-delete keeps the tombstone)");
    assert!(
        is_deleted,
        "HTMX path must still actually soft-delete the asset, not just emit the header"
    );

    test_db::cleanup(&mut conn).await;
}

#[tokio::test]
#[serial]
async fn test_htmx_delete_account_group_returns_hx_redirect() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let token = admin_token(app, "bug12_htmx_delete_acct_grp").await;
    let csrf = app.generate_csrf_token();

    let group_uuid =
        create_test_vauban_group(&mut conn, &unique_name("bug12-htmx-acct-grp")).await;

    let response = app
        .server
        .post(&format!("/accounts/groups/{}/delete", group_uuid))
        .add_header(COOKIE, auth_csrf_cookie(&token, &csrf))
        .add_header("HX-Request", "true")
        .form(&[("csrf_token", csrf.as_str())])
        .await;

    assert_hx_redirect(&response, "/accounts/groups");

    use vauban_web::schema::vauban_groups;
    let exists: bool = vauban_groups::table
        .filter(vauban_groups::uuid.eq(group_uuid))
        .select(vauban_groups::id)
        .first::<i32>(&mut conn)
        .await
        .optional()
        .expect("query must succeed")
        .is_some();
    assert!(!exists, "account group must be hard-deleted on the HTMX path");

    test_db::cleanup(&mut conn).await;
}

#[tokio::test]
#[serial]
async fn test_htmx_remove_member_returns_hx_redirect() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let token = admin_token(app, "bug12_htmx_remove_member").await;
    let csrf = app.generate_csrf_token();

    let group_uuid =
        create_test_vauban_group(&mut conn, &unique_name("bug12-htmx-rm-grp")).await;
    let user_id = create_simple_user(&mut conn, &unique_name("bug12-htmx-rm-user")).await;
    add_user_to_vauban_group(&mut conn, user_id, &group_uuid).await;
    let user_uuid = lookup_user_uuid(&mut conn, user_id).await;

    let response = app
        .server
        .post(&format!(
            "/accounts/groups/{}/members/{}/remove",
            group_uuid, user_uuid
        ))
        .add_header(COOKIE, auth_csrf_cookie(&token, &csrf))
        .add_header("HX-Request", "true")
        .form(&[("csrf_token", csrf.as_str())])
        .await;

    assert_hx_redirect(&response, &format!("/accounts/groups/{}", group_uuid));

    use crate::fixtures::count_vauban_group_members;
    let count = count_vauban_group_members(&mut conn, &group_uuid).await;
    assert_eq!(count, 0, "member removal must persist on the HTMX path");

    test_db::cleanup(&mut conn).await;
}

#[tokio::test]
#[serial]
async fn test_htmx_delete_asset_group_returns_hx_redirect() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let token = admin_token(app, "bug12_htmx_delete_asset_grp").await;
    let csrf = app.generate_csrf_token();

    let group_uuid =
        create_test_asset_group(&mut conn, &unique_name("bug12-htmx-asset-grp")).await;

    let response = app
        .server
        .post(&format!("/assets/groups/{}/delete", group_uuid))
        .add_header(COOKIE, auth_csrf_cookie(&token, &csrf))
        .add_header("HX-Request", "true")
        .form(&[("csrf_token", csrf.as_str())])
        .await;

    assert_hx_redirect(&response, "/assets/groups");

    use vauban_web::schema::asset_groups;
    let exists: bool = asset_groups::table
        .filter(asset_groups::uuid.eq(group_uuid))
        .filter(asset_groups::is_deleted.eq(false))
        .select(asset_groups::id)
        .first::<i32>(&mut conn)
        .await
        .optional()
        .expect("query must succeed")
        .is_some();
    assert!(
        !exists,
        "asset group must be deleted (or soft-deleted) on the HTMX path"
    );

    test_db::cleanup(&mut conn).await;
}

#[tokio::test]
#[serial]
async fn test_htmx_remove_asset_from_group_returns_hx_redirect() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let token = admin_token(app, "bug12_htmx_remove_asset_grp").await;
    let csrf = app.generate_csrf_token();
    let admin_id = create_simple_user(&mut conn, &unique_name("bug12-htmx-rm-asset-admin")).await;

    let group_uuid =
        create_test_asset_group(&mut conn, &unique_name("bug12-htmx-rm-asset-grp")).await;
    let asset_id = create_test_asset_in_group(
        &mut conn,
        &unique_name("bug12-htmx-grp-asset"),
        admin_id,
        &group_uuid,
    )
    .await;
    let asset_uuid: Uuid = vauban_web::schema::assets::table
        .filter(vauban_web::schema::assets::id.eq(asset_id))
        .select(vauban_web::schema::assets::uuid)
        .first(&mut conn)
        .await
        .expect("asset row must exist");

    let response = app
        .server
        .post(&format!("/assets/groups/{}/remove-asset", group_uuid))
        .add_header(COOKIE, auth_csrf_cookie(&token, &csrf))
        .add_header("HX-Request", "true")
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("asset_uuid", &asset_uuid.to_string()),
        ])
        .await;

    assert_hx_redirect(&response, &format!("/assets/groups/{}", group_uuid));

    use vauban_web::schema::asset_asset_groups;
    let still_linked: i64 = asset_asset_groups::table
        .filter(asset_asset_groups::asset_id.eq(asset_id))
        .count()
        .get_result(&mut conn)
        .await
        .expect("count must succeed");
    assert_eq!(
        still_linked, 0,
        "asset must be unlinked from the group on the HTMX path"
    );

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// Section C. Non-HTMX fallback — POST without HX-Request → 303 + Location.
//                                tag: BUG-12-NATIVE-FALLBACK-20260420
//
// Guards against the inverse regression: always emitting HX-Redirect would
// silently break native HTML form clients (JS off, scripts, curl).
// =============================================================================

fn assert_native_redirect(response: &axum_test::TestResponse, expected_location: &str) {
    let status = response.status_code().as_u16();
    assert!(
        status == 303 || status == 302,
        "non-HTMX delete must keep PRG (303), got {}",
        status
    );
    let location = response
        .headers()
        .get(LOCATION)
        .and_then(|v| v.to_str().ok());
    assert_eq!(
        location,
        Some(expected_location),
        "Location header MUST point at {}",
        expected_location
    );
}

#[tokio::test]
#[serial]
async fn test_native_delete_asset_keeps_303_redirect() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let token = admin_token(app, "bug12_native_delete_asset").await;
    let csrf = app.generate_csrf_token();

    let asset = create_test_ssh_asset(&mut conn, &unique_name("bug12-native-asset")).await;

    let response = app
        .server
        .post(&format!("/assets/{}/delete", asset.asset.uuid))
        .add_header(COOKIE, auth_csrf_cookie(&token, &csrf))
        // explicitly DO NOT set HX-Request
        .form(&[("csrf_token", csrf.as_str())])
        .await;

    assert_native_redirect(&response, "/assets");

    use vauban_web::schema::assets;
    let is_deleted: bool = assets::table
        .filter(assets::uuid.eq(asset.asset.uuid))
        .select(assets::is_deleted)
        .first(&mut conn)
        .await
        .expect("asset row must still exist");
    assert!(
        is_deleted,
        "non-HTMX path must still soft-delete the asset"
    );

    test_db::cleanup(&mut conn).await;
}

#[tokio::test]
#[serial]
async fn test_native_delete_account_group_keeps_303_redirect() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let token = admin_token(app, "bug12_native_delete_acct_grp").await;
    let csrf = app.generate_csrf_token();

    let group_uuid =
        create_test_vauban_group(&mut conn, &unique_name("bug12-native-acct-grp")).await;

    let response = app
        .server
        .post(&format!("/accounts/groups/{}/delete", group_uuid))
        .add_header(COOKIE, auth_csrf_cookie(&token, &csrf))
        .form(&[("csrf_token", csrf.as_str())])
        .await;

    assert_native_redirect(&response, "/accounts/groups");

    use vauban_web::schema::vauban_groups;
    let exists: bool = vauban_groups::table
        .filter(vauban_groups::uuid.eq(group_uuid))
        .select(vauban_groups::id)
        .first::<i32>(&mut conn)
        .await
        .optional()
        .expect("query must succeed")
        .is_some();
    assert!(!exists, "account group must be deleted on the non-HTMX path");

    test_db::cleanup(&mut conn).await;
}

#[tokio::test]
#[serial]
async fn test_native_remove_member_keeps_303_redirect() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let token = admin_token(app, "bug12_native_remove_member").await;
    let csrf = app.generate_csrf_token();

    let group_uuid =
        create_test_vauban_group(&mut conn, &unique_name("bug12-native-rm-grp")).await;
    let user_id = create_simple_user(&mut conn, &unique_name("bug12-native-rm-user")).await;
    add_user_to_vauban_group(&mut conn, user_id, &group_uuid).await;
    let user_uuid = lookup_user_uuid(&mut conn, user_id).await;

    let response = app
        .server
        .post(&format!(
            "/accounts/groups/{}/members/{}/remove",
            group_uuid, user_uuid
        ))
        .add_header(COOKIE, auth_csrf_cookie(&token, &csrf))
        .form(&[("csrf_token", csrf.as_str())])
        .await;

    assert_native_redirect(&response, &format!("/accounts/groups/{}", group_uuid));

    use crate::fixtures::count_vauban_group_members;
    let count = count_vauban_group_members(&mut conn, &group_uuid).await;
    assert_eq!(count, 0, "member must be removed on the non-HTMX path");

    test_db::cleanup(&mut conn).await;
}

#[tokio::test]
#[serial]
async fn test_native_delete_asset_group_keeps_303_redirect() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let token = admin_token(app, "bug12_native_delete_asset_grp").await;
    let csrf = app.generate_csrf_token();

    let group_uuid =
        create_test_asset_group(&mut conn, &unique_name("bug12-native-asset-grp")).await;

    let response = app
        .server
        .post(&format!("/assets/groups/{}/delete", group_uuid))
        .add_header(COOKIE, auth_csrf_cookie(&token, &csrf))
        .form(&[("csrf_token", csrf.as_str())])
        .await;

    assert_native_redirect(&response, "/assets/groups");

    use vauban_web::schema::asset_groups;
    let exists: bool = asset_groups::table
        .filter(asset_groups::uuid.eq(group_uuid))
        .filter(asset_groups::is_deleted.eq(false))
        .select(asset_groups::id)
        .first::<i32>(&mut conn)
        .await
        .optional()
        .expect("query must succeed")
        .is_some();
    assert!(!exists, "asset group must be deleted on the non-HTMX path");

    test_db::cleanup(&mut conn).await;
}

#[tokio::test]
#[serial]
async fn test_native_remove_asset_from_group_keeps_303_redirect() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let token = admin_token(app, "bug12_native_remove_asset_grp").await;
    let csrf = app.generate_csrf_token();
    let admin_id =
        create_simple_user(&mut conn, &unique_name("bug12-native-rm-asset-admin")).await;

    let group_uuid =
        create_test_asset_group(&mut conn, &unique_name("bug12-native-rm-asset-grp")).await;
    let asset_id = create_test_asset_in_group(
        &mut conn,
        &unique_name("bug12-native-grp-asset"),
        admin_id,
        &group_uuid,
    )
    .await;
    let asset_uuid: Uuid = vauban_web::schema::assets::table
        .filter(vauban_web::schema::assets::id.eq(asset_id))
        .select(vauban_web::schema::assets::uuid)
        .first(&mut conn)
        .await
        .expect("asset row must exist");

    let response = app
        .server
        .post(&format!("/assets/groups/{}/remove-asset", group_uuid))
        .add_header(COOKIE, auth_csrf_cookie(&token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("asset_uuid", &asset_uuid.to_string()),
        ])
        .await;

    assert_native_redirect(&response, &format!("/assets/groups/{}", group_uuid));

    use vauban_web::schema::asset_asset_groups;
    let still_linked: i64 = asset_asset_groups::table
        .filter(asset_asset_groups::asset_id.eq(asset_id))
        .count()
        .get_result(&mut conn)
        .await
        .expect("count must succeed");
    assert_eq!(
        still_linked, 0,
        "asset must be unlinked on the non-HTMX path"
    );

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// Section D. JS smoke test — pin the Alpine store registration.
//                            tag: BUG-12-DELETE-CONFIRM-COMPONENT-20260420
//
// We do NOT spin up a headless browser here; this is a static `grep`-style
// assertion that the contract surface in vauban-components.js is stable.
// If a future refactor renames the store key or drops it, the modal stops
// opening and every destructive form quietly degrades to the
// `window.confirm()` fallback — this test fires before that happens.
// =============================================================================

#[test]
fn test_alpine_delete_confirm_store_is_registered() {
    let js = include_str!("../../static/js/vauban-components.js");

    assert!(
        js.contains("Alpine.store('deleteConfirm'"),
        "vauban-components.js must register Alpine.store('deleteConfirm', ...) — \
         BUG-12-DELETE-CONFIRM-COMPONENT-20260420. \
         Renaming or removing the store silently breaks every BUG-12 form."
    );
    // The contract methods the templates rely on. A renamed callback would
    // also break the modal silently, so we lock the names in here.
    for needle in [
        "openWith:",
        "confirm:",
        "cancel:",
        "issueRequest",
    ] {
        assert!(
            js.contains(needle),
            "vauban-components.js must define `{}` on the deleteConfirm store \
             (BUG-12-DELETE-CONFIRM-COMPONENT-20260420)",
            needle
        );
    }

    // Regression guard for BUG-12 follow-up: the styled Alpine modal must
    // call `issueRequest(true)` (skipConfirmation=true), otherwise HTMX
    // re-prompts via window.confirm() because the form still carries
    // `hx-confirm` as the JS-off fallback. Symptom: user sees BOTH the
    // styled modal AND a native browser dialog before the request fires.
    // The literal must stay byte-for-byte stable; if you refactor the
    // callsite, update this assertion deliberately.
    assert!(
        js.contains("issueRequest(true)"),
        "vauban-components.js must call `issueRequest(true)` from the \
         deleteConfirm store to skip HTMX's redundant native confirm prompt \
         (BUG-12-DELETE-CONFIRM-COMPONENT-20260420). Calling \
         `issueRequest()` without arguments causes a double-confirm UX bug."
    );
}
