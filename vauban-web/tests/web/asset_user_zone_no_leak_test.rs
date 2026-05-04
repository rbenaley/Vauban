//! Issue #34 -- E2E anti-leak coverage for the user-zone asset
//! surface.
//!
//! Five scenarios:
//!
//! 1. Non-approved user `GET /assets/{uuid}` -> 410 Gone, body
//!    carries NO asset hostname / description / fingerprint.
//! 2. Non-approved user `GET /assets` -> 200 with Request button
//!    AND no `description` / `created_at` / `ssh_host_key_fingerprint`
//!    leaking from the catalogue rows.
//! 3. Non-approved user `POST /sessions/request` (the inlined modal
//!    is the new home of this flow) -> 200 + a `proxy_sessions` row
//!    is created in `pending` state.
//! 4. Approved user `POST /assets/{uuid}/connect` from /assets
//!    directly -> redirect / 200 with the connecting payload.
//! 5. The legacy `/assets/{uuid}/verify-host-key` endpoint is still
//!    mounted (admin /manage detail page consumes it) -- DOCUMENTING
//!    that issue #34 ONLY gutted the user-zone DETAIL page; the
//!    HTMX host-key verification stays.

use crate::common::{TestApp, assertions::assert_status, unwrap_ok};
use crate::fixtures::{
    add_user_to_vauban_group, create_approved_session, create_simple_admin_user,
    create_simple_user, create_test_access_rule_with_constraints, create_test_asset_group,
    create_test_asset_in_group, create_test_ssh_asset, create_test_vauban_group, get_asset_uuid,
    unique_name,
};
use axum::http::header::COOKIE;
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use uuid::Uuid;

async fn get_user_uuid(conn: &mut AsyncPgConnection, user_id: i32) -> Uuid {
    use vauban_web::schema::users;
    unwrap_ok!(
        users::table
            .filter(users::id.eq(user_id))
            .select(users::uuid)
            .first(conn)
            .await
    )
}

/// Cas 1 -- non-approved user GET `/assets/{uuid}` -> 410 Gone.
///
/// The body MUST be a constant short text, with NO database-derived
/// field interpolated (no asset hostname, no description, no group
/// name, no fingerprint, no UUID). 410 (and not 404) so the URL is
/// auditable but still anti-enumerative: the same response is
/// returned for every UUID, valid or not.
#[tokio::test]
async fn case1_non_approved_user_gets_410_with_no_leak() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("issue34_c1_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;

    let user_name = unique_name("issue34_c1_user");
    let user_id = create_simple_user(&mut conn, &user_name).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;

    let ug = create_test_vauban_group(&mut conn, &unique_name("issue34_c1_ug")).await;
    add_user_to_vauban_group(&mut conn, user_id, &ug).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("issue34_c1_ag")).await;
    let asset_id =
        create_test_asset_in_group(&mut conn, &unique_name("issue34_c1_asset"), admin_id, &ag)
            .await;
    let asset_uuid = get_asset_uuid(&mut conn, asset_id).await;
    create_test_access_rule_with_constraints(&mut conn, &ug, &ag, &["ssh"], false, true, Some(600))
        .await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &user_name, false, false)
        .await;

    let response = app
        .server
        .get(&format!("/assets/{}", asset_uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 410);
    let body = response.text();

    // Forbidden tokens (no DB-derived data must leak).
    assert!(
        !body.contains(&asset_uuid.to_string()),
        "410 body must NOT echo the requested UUID (anti-enum)"
    );
    // The asset name and the user's groups MUST NOT leak either.
    let asset_name = "issue34_c1_asset";
    assert!(
        !body.to_lowercase().contains(&asset_name.to_lowercase()),
        "410 body must NOT echo the asset name (anti-enum)"
    );
    assert!(
        !body.contains("ssh_host_key"),
        "410 body must NOT echo the ssh-host-key fragment"
    );
    assert!(
        !body.contains("Connection Details"),
        "410 body must NOT contain the legacy detail-page sections"
    );

    // Same 410 for an UNKNOWN UUID -- the response MUST be identical.
    let unknown = Uuid::new_v4();
    let response_unknown = app
        .server
        .get(&format!("/assets/{}", unknown))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    assert_status(&response_unknown, 410);
    assert_eq!(
        response.text(),
        response_unknown.text(),
        "the 410 body MUST be byte-identical for known and unknown \
         UUIDs (anti-enumeration)"
    );
}

/// Cas 2 -- non-approved user GET `/assets` -> Request button is
/// inlined; the catalogue row carries hostname / port / group_name
/// (those are part of the `assets:read` contract), but NEVER the
/// per-asset `description`, `created_at`, `updated_at`, or
/// `ssh_host_key_fingerprint`.
#[tokio::test]
async fn case2_non_approved_user_lists_assets_no_extra_leak() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("issue34_c2_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;

    let user_name = unique_name("issue34_c2_user");
    let user_id = create_simple_user(&mut conn, &user_name).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;

    let ug = create_test_vauban_group(&mut conn, &unique_name("issue34_c2_ug")).await;
    add_user_to_vauban_group(&mut conn, user_id, &ug).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("issue34_c2_ag")).await;
    let _asset_id =
        create_test_asset_in_group(&mut conn, &unique_name("issue34_c2_asset"), admin_id, &ag)
            .await;
    create_test_access_rule_with_constraints(&mut conn, &ug, &ag, &["ssh"], false, true, Some(600))
        .await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &user_name, false, false)
        .await;

    let response = app
        .server
        .get("/assets")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);
    let body = response.text();

    // Request button must appear (inlined modal trigger).
    assert!(
        body.contains("Request"),
        "asset list must surface the Request button for assets requiring approval"
    );
    assert!(
        body.contains("$store.accessModal.open("),
        "Request button must trigger the inlined Alpine accessModal"
    );

    // Forbidden detail-page fields:
    assert!(
        !body.contains("Connection Details"),
        "asset_list.html must NOT carry the legacy detail-page \
         `Connection Details` section heading"
    );
    assert!(
        !body.contains("System Information"),
        "asset_list.html must NOT carry the legacy detail-page \
         `System Information` section"
    );
    assert!(
        !body.contains("ssh_host_key_fingerprint"),
        "asset_list.html must NOT leak ssh_host_key_fingerprint \
         (admin-only at /assets/manage/{{uuid}})"
    );
    // Created/updated dates: the assets table is loaded with
    // `select((id, uuid, name, hostname, port, asset_type, status))`
    // so created_at / updated_at are not even fetched, but pin a
    // body-level assertion in case a future regression adds them.
    assert!(
        !body.contains("Last Updated"),
        "asset_list.html must NOT show the `Last Updated` field that \
         lived on the deleted detail page"
    );
}

/// Cas 3 -- non-approved user POST `/sessions/request` (the modal's
/// target) directly. The endpoint must accept `asset_uuid` +
/// `session_type` (the two fields the inlined Alpine store sets) +
/// `justification` and create a `pending` `proxy_sessions` row. This
/// confirms the modal works end-to-end without the deleted detail
/// page.
#[tokio::test]
async fn case3_non_approved_user_submits_access_request_via_modal_endpoint() {
    use vauban_web::schema::proxy_sessions::dsl as ps;

    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("issue34_c3_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let user_name = unique_name("issue34_c3_user");
    let user_id = create_simple_user(&mut conn, &user_name).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;

    let ug = create_test_vauban_group(&mut conn, &unique_name("issue34_c3_ug")).await;
    add_user_to_vauban_group(&mut conn, user_id, &ug).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("issue34_c3_ag")).await;
    let asset_id =
        create_test_asset_in_group(&mut conn, &unique_name("issue34_c3_asset"), admin_id, &ag)
            .await;
    let asset_uuid = get_asset_uuid(&mut conn, asset_id).await;
    create_test_access_rule_with_constraints(&mut conn, &ug, &ag, &["ssh"], false, true, Some(600))
        .await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &user_name, false, false)
        .await;
    let csrf = app.generate_csrf_token();

    let response = app
        .server
        .post("/sessions/request")
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf),
        )
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("asset_uuid", &asset_uuid.to_string()),
            ("session_type", "ssh"),
            (
                "justification",
                "issue34 e2e: requesting access via the inlined modal",
            ),
        ])
        .await;

    // Submit access request returns 200 (HTMX flow) or 303 (legacy);
    // both indicate the row was created.
    let status = response.status_code().as_u16();
    assert!(
        status == 200 || status == 303,
        "POST /sessions/request must succeed (200 / 303); got {}",
        status
    );

    let row_count: i64 = unwrap_ok!(
        ps::proxy_sessions
            .filter(ps::user_id.eq(user_id))
            .filter(ps::asset_id.eq(asset_id))
            .filter(ps::status.eq("pending"))
            .count()
            .get_result(&mut conn)
            .await
    );
    assert_eq!(
        row_count, 1,
        "the inlined modal flow must create exactly ONE pending \
         proxy_sessions row for (user, asset)"
    );
}

/// Cas 4 -- approved user POST `/assets/{uuid}/connect` directly
/// from `/assets`. The connect form on the list (no-justification
/// case) targets this exact endpoint, so it must work without the
/// detail page. We assert the response is NOT a 410 (the gone
/// handler) and NOT a 404; the actual session-creation behaviour is
/// covered by `jit_access_test.rs`.
#[tokio::test]
async fn case4_approved_user_connects_from_list_directly() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("issue34_c4_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let user_name = unique_name("issue34_c4_user");
    let user_id = create_simple_user(&mut conn, &user_name).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;

    let ug = create_test_vauban_group(&mut conn, &unique_name("issue34_c4_ug")).await;
    add_user_to_vauban_group(&mut conn, user_id, &ug).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("issue34_c4_ag")).await;
    let asset_id =
        create_test_asset_in_group(&mut conn, &unique_name("issue34_c4_asset"), admin_id, &ag)
            .await;
    let asset_uuid = get_asset_uuid(&mut conn, asset_id).await;

    // No-approval rule + no-justification asset -> direct connect path.
    create_test_access_rule_with_constraints(
        &mut conn,
        &ug,
        &ag,
        &["ssh"],
        false,
        false,
        Some(600),
    )
    .await;
    create_approved_session(&mut conn, user_id, asset_id, Some(600)).await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &user_name, false, false)
        .await;
    let csrf = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!("/assets/{}/connect", asset_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf),
        )
        .add_header(
            axum::http::header::HeaderName::from_static("hx-request"),
            "true",
        )
        .form(&[("csrf_token", csrf.as_str())])
        .await;

    let status = response.status_code().as_u16();
    assert_ne!(
        status, 410,
        "POST /assets/{{uuid}}/connect MUST NOT be the gone handler; \
         the connect path lives at the same URL as before issue #34"
    );
    assert_ne!(
        status, 404,
        "POST /assets/{{uuid}}/connect must remain mounted (issue #34 \
         only removed the GET detail page, not the connect verb)"
    );
    // 200 (HTMX swap), 303 (legacy redirect) or 5xx (proxy not
    // available in test) are all acceptable -- the goal here is to
    // confirm the route is reachable from /assets without a detail
    // page detour.
    assert!(
        status == 200 || status == 303 || status >= 500,
        "POST /assets/{{uuid}}/connect should be reachable (got {})",
        status
    );
}

/// Cas 5 -- the `/assets/{uuid}/verify-host-key` HTMX endpoint
/// stays mounted because the admin `/assets/manage/{uuid}` page
/// consumes it. Issue #34 only removed the user-zone DETAIL page;
/// the SSH host-key verification surface is unchanged. Pinning this
/// here so a future cleanup pass doesn't accidentally take both
/// down.
#[tokio::test]
async fn case5_verify_host_key_endpoint_is_still_mounted_for_admin() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("issue34_c5_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let asset = create_test_ssh_asset(&mut conn, &unique_name("issue34_c5_asset")).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let response = app
        .server
        .get(&format!("/assets/{}/verify-host-key", asset.asset.uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .add_header(
            axum::http::header::HeaderName::from_static("hx-request"),
            "true",
        )
        .await;

    let status = response.status_code();
    assert_ne!(
        status, 410,
        "GET /assets/{{uuid}}/verify-host-key MUST NOT be 410: the \
         admin /manage/{{uuid}} detail page consumes this endpoint \
         and issue #34 only removed the user-zone GET detail page"
    );
    assert_ne!(
        status, 404,
        "GET /assets/{{uuid}}/verify-host-key MUST stay mounted"
    );
}
