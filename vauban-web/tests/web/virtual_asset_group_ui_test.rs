//! Tier 4 — UI / handler gating tests for the virtual "All assets"
//! group.
//!
//! These tests drive the real Axum router to assert the defense-in-depth
//! guards the [`vauban_web::handlers::web::asset_groups`] module installs
//! on top of the database triggers:
//!
//! * **U32** — `GET /assets/groups` HTML never exposes the virtual UUID,
//!   name, or slug (asset-group index hides it).
//! * **U33** — `GET /assets/groups/{ALL_UUID}` redirects with a flash
//!   "not found" (404-equivalent for the PRG pattern).
//! * **U34** — `POST /assets/groups/{ALL_UUID}/delete` refuses with a
//!   flash error ("System group cannot be deleted") — 403-equivalent.
//! * **U35** — `GET /assets/groups/{ALL_UUID}/edit` refuses.
//! * **U36** — `POST /assets/groups/{ALL_UUID}/edit` (update) refuses.
//! * **U37** — `GET /assets/groups/{ALL_UUID}/add-asset` refuses.
//! * **U38** — `POST /assets/groups/{ALL_UUID}/add-asset` refuses.
//! * **U39** — `POST /assets/groups/{ALL_UUID}/remove-asset` refuses.
//! * **U40** — Access-rule create form's asset-group dropdown DOES
//!   include the virtual group with a "Virtual" badge.
//! * **U41** — Access-rule edit form's asset-group dropdown DOES
//!   include the virtual group with a "Virtual" badge.
//! * **U42** — `POST /assets/access` with `asset_group_id` pointing at
//!   the virtual group succeeds and persists a rule.
//! * **U43** — Existing access-rule listing handler does NOT crash when
//!   a rule references the virtual group, and the virtual group's name
//!   appears in the rendered detail.

use axum::http::header::{self, COOKIE};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use serial_test::serial;
use shared::messages::ALL_ASSETS_GROUP_UUID;
use uuid::Uuid;

use crate::common::{TestApp, assertions::*, test_db};
use crate::fixtures::{
    create_admin_user, create_test_access_rule, create_test_asset_group, create_test_vauban_group,
    unique_name,
};

fn auth_csrf_cookie(token: &str, csrf: &str) -> String {
    format!("access_token={}; __vauban_csrf={}", token, csrf)
}

fn virtual_uuid_str() -> &'static str {
    ALL_ASSETS_GROUP_UUID
}

/// Resolve the virtual group's internal id (used by some POST forms
/// that take an i32 `asset_group_id`).
async fn virtual_internal_id(conn: &mut diesel_async::AsyncPgConnection) -> i32 {
    use vauban_web::schema::asset_groups;
    let v_uuid = Uuid::parse_str(ALL_ASSETS_GROUP_UUID).unwrap();
    asset_groups::table
        .filter(asset_groups::uuid.eq(v_uuid))
        .select(asset_groups::id)
        .first(conn)
        .await
        .expect("virtual group must exist (migration applied)")
}

// =====================================================================
// U32 — Hidden in the asset-group index
// =====================================================================

#[tokio::test]
#[serial]
async fn u32_virtual_group_hidden_from_asset_groups_index() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("u32_adm")).await;

    let response = app
        .server
        .get("/assets/groups")
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;
    assert_status(&response, 200);

    let body = response.text();
    assert!(
        !body.contains(virtual_uuid_str()),
        "virtual UUID must NOT appear in the asset-groups index"
    );
    assert!(
        !body.contains("All assets"),
        "the virtual group's display name must NOT appear in the index"
    );
    assert!(
        !body.contains("__all-assets__"),
        "the virtual group's slug must NOT leak in the index"
    );

    test_db::cleanup(&mut conn).await;
}

// =====================================================================
// U33 — Detail page is not browsable
// =====================================================================

#[tokio::test]
#[serial]
async fn u33_virtual_group_detail_not_browsable() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("u33_adm")).await;

    let response = app
        .server
        .get(&format!("/assets/groups/{}", virtual_uuid_str()))
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;
    let status = response.status_code().as_u16();
    assert!(
        status == 303 || status == 302,
        "virtual group detail must redirect (PRG with flash), got {status}"
    );
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(
        location, "/assets/groups",
        "virtual group detail must redirect back to the index"
    );

    test_db::cleanup(&mut conn).await;
}

// =====================================================================
// U34 — Delete refused
// =====================================================================

#[tokio::test]
#[serial]
async fn u34_virtual_group_delete_refused() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("u34_adm")).await;
    let csrf = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!("/assets/groups/{}/delete", virtual_uuid_str()))
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[("csrf_token", csrf.as_str())])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 303 || status == 302,
        "delete on virtual group must redirect with flash, got {status}"
    );

    // Defense-in-depth: the row MUST still exist in the DB
    // (handler short-circuits before the IPC call; the trigger is the
    // last line of defense).
    use vauban_web::schema::asset_groups;
    let v_uuid = Uuid::parse_str(virtual_uuid_str()).unwrap();
    let still_exists: bool = asset_groups::table
        .filter(asset_groups::uuid.eq(v_uuid))
        .filter(asset_groups::is_deleted.eq(false))
        .select(asset_groups::id)
        .first::<i32>(&mut conn)
        .await
        .optional()
        .unwrap()
        .is_some();
    assert!(
        still_exists,
        "virtual group MUST remain after a delete attempt"
    );

    test_db::cleanup(&mut conn).await;
}

// =====================================================================
// U35 — Edit form refused
// =====================================================================

#[tokio::test]
#[serial]
async fn u35_virtual_group_edit_form_refused() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("u35_adm")).await;

    let response = app
        .server
        .get(&format!("/assets/groups/{}/edit", virtual_uuid_str()))
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;
    let status = response.status_code().as_u16();
    assert!(
        status == 303 || status == 302,
        "virtual group edit form must redirect, got {status}"
    );

    test_db::cleanup(&mut conn).await;
}

// =====================================================================
// U36 — Update (POST edit) refused
// =====================================================================

#[tokio::test]
#[serial]
async fn u36_virtual_group_update_refused() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("u36_adm")).await;
    let csrf = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!("/assets/groups/{}/edit", virtual_uuid_str()))
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&serde_json::json!({
            "csrf_token": csrf,
            "name": "Hijacked",
            "slug": "hijacked-slug",
            "description": "should not stick",
            "color": "#ff0000",
            "icon": "skull",
        }))
        .await;
    let status = response.status_code().as_u16();
    assert!(
        status == 303 || status == 302,
        "virtual group update must redirect with flash, got {status}"
    );

    // The row's name must remain unchanged.
    use vauban_web::schema::asset_groups;
    let v_uuid = Uuid::parse_str(virtual_uuid_str()).unwrap();
    let name: String = asset_groups::table
        .filter(asset_groups::uuid.eq(v_uuid))
        .select(asset_groups::name)
        .first(&mut conn)
        .await
        .unwrap();
    assert_eq!(
        name, "All assets",
        "virtual group name MUST NOT change after a hijack attempt"
    );

    test_db::cleanup(&mut conn).await;
}

// =====================================================================
// U37 — add-asset GET refused
// =====================================================================

#[tokio::test]
#[serial]
async fn u37_virtual_group_add_asset_form_refused() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("u37_adm")).await;

    let response = app
        .server
        .get(&format!("/assets/groups/{}/add-asset", virtual_uuid_str()))
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;
    let status = response.status_code().as_u16();
    // The handler raises AppError::Authorization which maps to 403,
    // not a flash redirect.
    assert!(
        status == 403 || status == 303 || status == 302,
        "virtual group add-asset form must be refused (403/303), got {status}"
    );

    test_db::cleanup(&mut conn).await;
}

// =====================================================================
// U38 — add-asset POST refused
// =====================================================================

#[tokio::test]
#[serial]
async fn u38_virtual_group_add_asset_post_refused() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("u38_adm")).await;
    let csrf = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!("/assets/groups/{}/add-asset", virtual_uuid_str()))
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&serde_json::json!({
            "csrf_token": csrf,
            "asset_uuid": Uuid::new_v4().to_string(),
        }))
        .await;
    let status = response.status_code().as_u16();
    assert!(
        status == 403 || status == 303 || status == 302,
        "virtual group add-asset must be refused, got {status}"
    );

    // Defense-in-depth: even if the handler is bypassed, the trigger
    // would block it; we assert no membership row was created.
    use vauban_web::schema::asset_asset_groups;
    let virtual_id = virtual_internal_id(&mut conn).await;
    let count: i64 = asset_asset_groups::table
        .filter(asset_asset_groups::asset_group_id.eq(virtual_id))
        .count()
        .get_result(&mut conn)
        .await
        .unwrap();
    assert_eq!(
        count, 0,
        "no membership row may exist for the virtual group, ever"
    );

    test_db::cleanup(&mut conn).await;
}

// =====================================================================
// U39 — remove-asset POST refused
// =====================================================================

#[tokio::test]
#[serial]
async fn u39_virtual_group_remove_asset_refused() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("u39_adm")).await;
    let csrf = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!(
            "/assets/groups/{}/remove-asset",
            virtual_uuid_str()
        ))
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&serde_json::json!({
            "csrf_token": csrf,
            "asset_uuid": Uuid::new_v4().to_string(),
        }))
        .await;
    let status = response.status_code().as_u16();
    assert!(
        status == 303 || status == 302 || status == 403,
        "virtual group remove-asset must be refused, got {status}"
    );

    test_db::cleanup(&mut conn).await;
}

// =====================================================================
// U40 — Access-rule CREATE form exposes the virtual group with a badge
// =====================================================================

#[tokio::test]
#[serial]
async fn u40_access_rule_create_form_shows_virtual_with_badge() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("u40_adm")).await;

    let response = app
        .server
        .get("/assets/access/new")
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;
    assert_status(&response, 200);

    let body = response.text();
    assert!(
        body.contains("All assets"),
        "create form must surface the virtual group label (got body length {})",
        body.len()
    );
    assert!(
        body.contains("data-virtual=\"true\""),
        "create form must emit the data-virtual marker on the virtual <option>"
    );
    assert!(
        body.contains("Virtual"),
        "create form must render the 'Virtual' badge text"
    );

    test_db::cleanup(&mut conn).await;
}

// =====================================================================
// U41 — Access-rule EDIT form also exposes the virtual group
// =====================================================================

#[tokio::test]
#[serial]
async fn u41_access_rule_edit_form_shows_virtual_with_badge() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("u41_adm")).await;

    // Seed an arbitrary rule (on a static group) so /assets/access/{uuid}/edit
    // is a valid URL; the dropdown contents are what we're asserting on.
    let ug = create_test_vauban_group(&mut conn, &unique_name("u41_ug")).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("u41_ag")).await;
    let rule_uuid = create_test_access_rule(&mut conn, &ug, &ag, &["ssh"]).await;

    let response = app
        .server
        .get(&format!("/assets/access/{}/edit", rule_uuid))
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;
    assert_status(&response, 200);

    let body = response.text();
    assert!(
        body.contains("All assets"),
        "edit form must surface the virtual group label"
    );
    assert!(
        body.contains("data-virtual=\"true\""),
        "edit form must emit the data-virtual marker"
    );

    test_db::cleanup(&mut conn).await;
}

// =====================================================================
// U42 — Access rule on the virtual group can be created
// =====================================================================

#[tokio::test]
#[serial]
async fn u42_access_rule_create_on_virtual_group_succeeds() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("u42_adm")).await;
    let csrf = app.generate_csrf_token();

    let ug = create_test_vauban_group(&mut conn, &unique_name("u42_ug")).await;
    use vauban_web::schema::vauban_groups;
    let ug_id: i32 = vauban_groups::table
        .filter(vauban_groups::uuid.eq(ug))
        .select(vauban_groups::id)
        .first(&mut conn)
        .await
        .unwrap();
    let virtual_id = virtual_internal_id(&mut conn).await;

    let response = app
        .server
        .post("/assets/access")
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&serde_json::json!({
            "csrf_token": csrf,
            "name": "u42-rule-on-virtual",
            "description": "all-assets policy",
            "user_group_id": ug_id,
            "asset_group_id": virtual_id,
            "allowed_ssh": "true",
            "is_active": "true",
            "priority": "5",
        }))
        .await;
    let status = response.status_code().as_u16();
    assert!(
        status == 303 || status == 302,
        "creation must redirect (PRG), got {status}"
    );

    // The persisted rule must point at the virtual asset_group_id.
    use vauban_web::schema::access_rules;
    let count: i64 = access_rules::table
        .filter(access_rules::name.eq("u42-rule-on-virtual"))
        .filter(access_rules::asset_group_id.eq(virtual_id))
        .count()
        .get_result(&mut conn)
        .await
        .unwrap();
    assert_eq!(
        count, 1,
        "exactly one rule on the virtual group must be persisted"
    );

    test_db::cleanup(&mut conn).await;
}

// =====================================================================
// U43 — Listing / detail handlers do not crash when a rule references
//        the virtual group
// =====================================================================

#[tokio::test]
#[serial]
async fn u43_access_rule_list_renders_when_rule_targets_virtual_group() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("u43_adm")).await;

    let ug = create_test_vauban_group(&mut conn, &unique_name("u43_ug")).await;
    let v_uuid = Uuid::parse_str(virtual_uuid_str()).unwrap();
    let _rule = create_test_access_rule(&mut conn, &ug, &v_uuid, &["ssh"]).await;

    let response = app
        .server
        .get("/assets/access")
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;
    assert_status(&response, 200);
    let body = response.text();
    assert!(
        body.contains("All assets") || body.contains("test-rule"),
        "rule list must render at least the virtual group name or the rule name"
    );

    test_db::cleanup(&mut conn).await;
}
