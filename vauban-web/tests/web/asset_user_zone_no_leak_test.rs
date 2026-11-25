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

/// A validation failure of `POST /sessions/request` without HTMX sends
/// the browser back to the asset list. It used to redirect to
/// `/assets/{uuid}`, the removed detail page (constant 410).
#[tokio::test]
async fn access_request_validation_failure_redirects_to_the_asset_list() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user_name = unique_name("issue45_user");
    let user_id = create_simple_user(&mut conn, &user_name).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;
    let asset = create_test_ssh_asset(&mut conn, &unique_name("issue45_asset")).await;
    let asset_uuid = asset.asset.uuid;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &user_name, false, false)
        .await;
    let csrf = app.generate_csrf_token();

    // No `HX-Request` header and no justification.
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
        ])
        .await;

    assert_status(&response, 303);
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(location, "/assets", "must not redirect to /assets/{{uuid}}");
}

fn collect_files(dir: &std::path::Path, ext: &str, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_files(&path, ext, out);
        } else if path.extension().is_some_and(|e| e == ext) {
            out.push(path);
        }
    }
}

/// Source pin: nothing links or redirects to the bare `/assets/{uuid}`
/// URL. In the user zone that path is a constant 410; sub-routes
/// (`/assets/{uuid}/connect`, ...) and `/assets/manage/{uuid}` remain.
#[test]
fn no_template_or_handler_targets_the_removed_asset_detail_page() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();

    // Templates: `/assets/{{ expr }}` must be followed by `/`.
    let mut templates = Vec::new();
    collect_files(&root.join("templates"), "html", &mut templates);
    assert!(!templates.is_empty(), "templates directory not found");
    for path in templates {
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        let mut rest = text.as_str();
        while let Some(pos) = rest.find("/assets/{{") {
            let after = &rest[pos + "/assets/{{".len()..];
            let Some(close) = after.find("}}") else { break };
            if !after[close + 2..].starts_with('/') {
                offenders.push(path.display().to_string());
            }
            rest = &after[close + 2..];
        }
    }

    // Handlers: a format string that is exactly `/assets/{}`.
    let mut handlers = Vec::new();
    collect_files(&root.join("src/handlers"), "rs", &mut handlers);
    assert!(!handlers.is_empty(), "handlers directory not found");
    for path in handlers {
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        if text.contains("\"/assets/{}\"") {
            offenders.push(path.display().to_string());
        }
    }

    assert!(
        offenders.is_empty(),
        "link or redirect to the removed /assets/{{uuid}} page in: {offenders:?}"
    );
}

/// Issue #45: from My Requests, Connect on an approved request opens
/// the session the way the asset list does. Both pages carry the same
/// form, posting to `/assets/{asset uuid}/connect`, and that endpoint
/// answers. The button used to be a link to `/assets/{request uuid}`,
/// the removed detail page (constant 410).
#[tokio::test]
async fn my_requests_connect_is_the_asset_list_connect() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_id = create_simple_admin_user(&mut conn, &unique_name("issue45_c_admin")).await;
    let user_name = unique_name("issue45_c_user");
    let user_id = create_simple_user(&mut conn, &user_name).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;

    let ug = create_test_vauban_group(&mut conn, &unique_name("issue45_c_ug")).await;
    add_user_to_vauban_group(&mut conn, user_id, &ug).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("issue45_c_ag")).await;
    let asset_id =
        create_test_asset_in_group(&mut conn, &unique_name("issue45_c_asset"), admin_id, &ag).await;
    let asset_uuid = get_asset_uuid(&mut conn, asset_id).await;
    // Approval required, no MFA; the request below is approved.
    create_test_access_rule_with_constraints(&mut conn, &ug, &ag, &["ssh"], false, true, Some(600))
        .await;
    let grant_uuid = create_approved_session(&mut conn, user_id, asset_id, Some(600)).await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &user_name, false, false)
        .await;
    let csrf = app.generate_csrf_token();
    let cookie = format!("access_token={}; __vauban_csrf={}", token, csrf);

    let connect_form = format!("hx-post=\"/assets/{}/connect\"", asset_uuid);

    let list = app
        .server
        .get("/assets")
        .add_header(COOKIE, cookie.clone())
        .await;
    assert_status(&list, 200);
    let list_body = list.text();
    let list_uses_modal =
        list_body.contains(&format!("$store.justificationModal.open('{}'", asset_uuid));
    assert!(
        list_body.contains(&connect_form) || list_uses_modal,
        "the asset list must offer Connect for the approved asset"
    );

    let mine = app
        .server
        .get("/sessions/my-requests")
        .add_header(COOKIE, cookie.clone())
        .await;
    assert_status(&mine, 200);
    let mine_body = mine.text();
    assert!(
        mine_body.contains(&format!("data-testid=\"connect-{}\"", grant_uuid)),
        "the approved request must carry a Connect control"
    );
    // Same control on both pages: the direct form, or the modal button.
    assert_eq!(
        mine_body.contains(&connect_form),
        list_body.contains(&connect_form),
        "My Requests and the asset list must offer the same direct Connect form"
    );
    assert_eq!(
        mine_body.contains(&format!("$store.justificationModal.open('{}'", asset_uuid)),
        list_body.contains(&format!("$store.justificationModal.open('{}'", asset_uuid)),
        "My Requests and the asset list must open the same modal"
    );
    assert!(
        !mine_body.contains(&format!("/assets/{}", grant_uuid)),
        "the request UUID must not appear in an asset path"
    );
    assert!(
        mine_body.contains("id=\"justification-modal-text\"")
            || mine_body.contains("justificationModal.show"),
        "My Requests must include the modals the Connect control drives"
    );

    // The endpoint the control posts to answers; it is not the tombstone.
    let response = app
        .server
        .post(&format!("/assets/{}/connect", asset_uuid))
        .add_header(COOKIE, cookie)
        .add_header(
            axum::http::header::HeaderName::from_static("hx-request"),
            "true",
        )
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("justification", "issue45 e2e: connect from My Requests"),
        ])
        .await;
    let status = response.status_code().as_u16();
    assert_ne!(status, 410, "Connect must not reach the 410 tombstone");
    assert_ne!(status, 404, "the connect endpoint must be mounted");
    assert!(
        !response.text().contains("Asset detail page has moved"),
        "Connect must not answer with the tombstone body"
    );
}

/// Source pin: the Connect control of My Requests stays in step with
/// the one of the asset list. Same endpoints, same modal call, same two
/// modal includes. A change on one side alone fails here.
#[test]
fn my_requests_connect_control_matches_the_asset_list() {
    let list = include_str!("../../templates/assets/asset_list.html");
    let mine = include_str!("../../templates/sessions/my_requests.html")
        .replace("req.asset_uuid", "asset.uuid")
        .replace("req.", "asset.");

    for snippet in [
        // direct form: endpoint switch on the asset type
        r#"<form hx-post="/assets/{{ asset.uuid }}/{%- if asset.asset_type == "rdp" -%}connect-rdp{%- else if asset.asset_type == "mcp" -%}connect-mcp{%- else -%}connect{%- endif -%}""#,
        // branch that sends Connect through the modal
        r#"{% else if require_justification || asset.require_mfa || asset.asset_type == "mcp" %}"#,
        r#"@click="$store.justificationModal.open('{{ asset.uuid }}', '{{ asset.asset_type }}', {{ asset.require_mfa }}, {{ require_justification || asset.asset_type == "mcp" }})""#,
        // IACS tunnel form and its gates
        r#"<form hx-post="/assets/{{ asset.uuid }}/connect-iacs""#,
        "{% if iacs_connect_allowed %}",
        r#"<a href="/iacs/onboard""#,
        // the two modals
        r#"{% include "sessions/access_request_modal.html" %}"#,
        r#"{% include "sessions/justification_modal.html" %}"#,
    ] {
        assert!(list.contains(snippet), "asset_list.html lost: {snippet}");
        assert!(mine.contains(snippet), "my_requests.html lost: {snippet}");
    }
}
