//! IACS / EWS onboarding -- end-to-end web tests.
//!
//! Exercises the full user-zone + admin-zone surface introduced by
//! paliers 6-8: form rendering, request submission via the HTML
//! handler, admin approve / reject through the `/iacs/admin/*` nest
//! gated by `require_iacs_manage`, and the EWS lifecycle (disable /
//! enable / offboard).
//!
//! These tests intentionally drive the public HTTP surface (CSRF
//! cookie + JWT cookie + form-encoded bodies) so that any future
//! refactor of the route or middleware layout is caught by the
//! routing layer, not just by the service-level units.
//!
//! Anti-enumeration is verified separately
//! (`iacs_kill_switch_test::iacs_admin_404_for_regular_user`).

use crate::common::{TestApp, assertions::assert_status, unwrap_ok};
use crate::fixtures::{create_simple_admin_user, create_simple_user, unique_name};
use axum::http::header::COOKIE;
use base64::Engine;
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use sha2::{Digest, Sha256};
use uuid::Uuid;

// ===================================================================
// Helpers
// ===================================================================

/// Build a syntactically-valid `ssh-ed25519` public key line whose
/// 32-byte payload is derived from `tag` via SHA-256 so every
/// distinct tag yields a distinct fingerprint (`KeyAlreadyUsed` never
/// trips spuriously when the global TestApp shares one PostgreSQL
/// catalog across hundreds of tests -- a bare `u8` seed only had 256
/// colours and collisions were inevitable).
///
/// Mirrors `services::iacs::tests::make_ed25519_line` (which lives in
/// a `mod tests` and is therefore not reachable from this crate).
fn make_ed25519_line_for_tag(tag: &str) -> String {
    let key_bytes = Sha256::digest(tag.as_bytes());
    let mut blob = Vec::new();
    blob.extend_from_slice(&11u32.to_be_bytes());
    blob.extend_from_slice(b"ssh-ed25519");
    blob.extend_from_slice(&32u32.to_be_bytes());
    blob.extend_from_slice(&key_bytes);
    let payload = base64::engine::general_purpose::STANDARD.encode(&blob);
    format!("ssh-ed25519 {} VAUBAN", payload)
}

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

// ===================================================================
// User zone
// ===================================================================

/// `GET /iacs/onboard` renders the form for a user holding
/// `iacs:request`.
#[tokio::test]
async fn iacs_onboard_form_renders_for_user() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("iacs_form");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, false, false)
        .await;

    let response = app
        .server
        .get("/iacs/onboard")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(
        body.contains("Onboard") || body.contains("EWS") || body.contains("public_key"),
        "onboarding form should mention EWS / public_key; body len {}",
        body.len()
    );
}

/// Submitting a well-formed request creates a `pending` row and
/// redirects to `/sessions/my-requests`.
#[tokio::test]
async fn iacs_submit_request_creates_pending_row() {
    use vauban_web::schema::ews_onboarding_requests as r;

    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("iacs_submit");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, false, false)
        .await;
    let csrf_token = app.generate_csrf_token();

    let ews_name = unique_name("ews_submit");
    let key_line = make_ed25519_line_for_tag(ews_name.as_str());

    let response = app
        .server
        .post("/iacs/onboard")
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("name", ews_name.as_str()),
            ("public_key", key_line.as_str()),
            ("justification", "I need to manage the IACS PLC bench"),
        ])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "submit should redirect, got {}",
        status
    );
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(
        location, "/sessions/my-requests",
        "submit should land on /sessions/my-requests"
    );

    let pending: i64 = unwrap_ok!(
        r::table
            .filter(r::user_id.eq(user_id))
            .filter(r::name.eq(&ews_name))
            .filter(r::status.eq("pending"))
            .count()
            .get_result(&mut conn)
            .await
    );
    assert_eq!(pending, 1, "exactly one pending row was created");
}

/// A user without `iacs:request` (i.e. holding no role above
/// `role:user` AND with `[industrial].enabled = true` -- which is the
/// default) sees the onboarding form because the policy grants
/// `role:user` the permission. The negative case is exercised by the
/// kill-switch test suite. Here we instead verify the *form rejection
/// path*: an empty justification round-trips with a flash error
/// (PRG redirect to `/iacs/onboard`) and does NOT create a row.
#[tokio::test]
async fn iacs_submit_rejects_empty_justification() {
    use vauban_web::schema::ews_onboarding_requests as r;

    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("iacs_no_just");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, false, false)
        .await;
    let csrf_token = app.generate_csrf_token();

    let ews_name = unique_name("ews_nojust");
    let key_line = make_ed25519_line_for_tag(ews_name.as_str());

    let response = app
        .server
        .post("/iacs/onboard")
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("name", ews_name.as_str()),
            ("public_key", key_line.as_str()),
            ("justification", "   "),
        ])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "validation failure should redirect with flash, got {}",
        status
    );

    let count: i64 = unwrap_ok!(
        r::table
            .filter(r::user_id.eq(user_id))
            .filter(r::name.eq(&ews_name))
            .count()
            .get_result(&mut conn)
            .await
    );
    assert_eq!(
        count, 0,
        "no row should be persisted when validation rejects the form"
    );
}

/// `POST /iacs/onboard` rejects a non-ed25519 algorithm with a flash
/// redirect. Defence in depth on top of the parser unit tests.
#[tokio::test]
async fn iacs_submit_rejects_non_ed25519_algo() {
    use vauban_web::schema::ews_onboarding_requests as r;

    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("iacs_rsa");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, false, false)
        .await;
    let csrf_token = app.generate_csrf_token();

    let ews_name = unique_name("ews_rsa");
    let response = app
        .server
        .post("/iacs/onboard")
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("name", ews_name.as_str()),
            ("public_key", "ssh-rsa AAAAB3NzaC1yc2E= VAUBAN"),
            ("justification", "RSA should be refused"),
        ])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "non-ed25519 should redirect with flash, got {}",
        status
    );

    let count: i64 = unwrap_ok!(
        r::table
            .filter(r::user_id.eq(user_id))
            .filter(r::name.eq(&ews_name))
            .count()
            .get_result(&mut conn)
            .await
    );
    assert_eq!(count, 0, "no row should be persisted for ssh-rsa");
}

/// `POST /iacs/onboard/{uuid}/cancel` flips a pending request to
/// `cancelled`. The user must own the request.
#[tokio::test]
async fn iacs_user_can_cancel_own_pending_request() {
    use vauban_web::schema::ews_onboarding_requests as r;

    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("iacs_cancel");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, false, false)
        .await;
    let csrf_token = app.generate_csrf_token();

    let ews_name = unique_name("ews_cancel");
    let key_line = make_ed25519_line_for_tag(ews_name.as_str());

    let submit = app
        .server
        .post("/iacs/onboard")
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("name", ews_name.as_str()),
            ("public_key", key_line.as_str()),
            ("justification", "Cancel-me"),
        ])
        .await;
    assert!(matches!(submit.status_code().as_u16(), 302 | 303));

    let request_uuid: Uuid = unwrap_ok!(
        r::table
            .filter(r::user_id.eq(user_id))
            .filter(r::name.eq(&ews_name))
            .select(r::uuid)
            .first(&mut conn)
            .await
    );

    let cancel = app
        .server
        .post(&format!("/iacs/onboard/{}/cancel", request_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf_token),
        )
        .form(&[("csrf_token", csrf_token.as_str())])
        .await;
    assert!(
        matches!(cancel.status_code().as_u16(), 302 | 303),
        "cancel should redirect"
    );

    let new_status: String = unwrap_ok!(
        r::table
            .filter(r::uuid.eq(request_uuid))
            .select(r::status)
            .first(&mut conn)
            .await
    );
    assert_eq!(new_status, "cancelled");
}

// ===================================================================
// Admin zone -- approve / reject / lifecycle
// ===================================================================

/// `GET /iacs/admin` renders the admin landing page for a superuser
/// and forbids a regular user via the `require_iacs_manage` route
/// layer (anti-enumeration: the layer fires BEFORE the handler).
#[tokio::test]
async fn iacs_admin_landing_page_renders_for_superuser() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("iacs_admin_landing");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let response = app
        .server
        .get("/iacs/admin")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(
        body.contains("IACS") || body.contains("EWS") || body.contains("Onboarding"),
        "admin landing should mention IACS / EWS / Onboarding"
    );
}

/// Anti-enumeration: a regular user trying any route under
/// `/iacs/admin/*` (even with a random / never-existed UUID) is
/// blocked by the route layer with 403. The handler is never reached
/// so a non-admin cannot oracle the existence of a request UUID.
#[tokio::test]
async fn iacs_admin_routes_block_regular_user_with_403() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("iacs_user_403");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, false, false)
        .await;

    let response = app
        .server
        .get("/iacs/admin")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    let status = response.status_code().as_u16();
    assert!(
        status == 403 || status == 303,
        "regular user must NOT access /iacs/admin (got {})",
        status
    );

    // Random UUID under /iacs/admin/request: the layer collapses the
    // response BEFORE any DB lookup -- no enumeration leak.
    let random = Uuid::new_v4();
    let response = app
        .server
        .get(&format!("/iacs/admin/request/{}", random))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    let status = response.status_code().as_u16();
    assert!(
        status == 403 || status == 303,
        "regular user must NOT access /iacs/admin/request/{{uuid}} (got {})",
        status
    );
}

/// End-to-end: user submits, admin approves, an `ews` row is created
/// with the same fingerprint as the request. The request status moves
/// to `approved`.
#[tokio::test]
async fn iacs_admin_can_approve_request_and_creates_ews_row() {
    use vauban_web::schema::{ews, ews_onboarding_requests as r};

    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("iacs_approve_user");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;

    let admin_name = unique_name("iacs_approve_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    // 1. user submits.
    let user_token = app
        .generate_test_token(&user_uuid.to_string(), &username, false, false)
        .await;
    let csrf_token = app.generate_csrf_token();

    let ews_name = unique_name("ews_approve");
    let key_line = make_ed25519_line_for_tag(ews_name.as_str());

    let submit = app
        .server
        .post("/iacs/onboard")
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", user_token, csrf_token),
        )
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("name", ews_name.as_str()),
            ("public_key", key_line.as_str()),
            ("justification", "Approve me end-to-end"),
        ])
        .await;
    assert!(matches!(submit.status_code().as_u16(), 302 | 303));

    let (request_uuid, fingerprint): (Uuid, String) = unwrap_ok!(
        r::table
            .filter(r::user_id.eq(user_id))
            .filter(r::name.eq(&ews_name))
            .select((r::uuid, r::public_key_fingerprint))
            .first(&mut conn)
            .await
    );

    // 2. admin approves.
    let admin_token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let approve = app
        .server
        .post(&format!("/iacs/admin/request/{}/approve", request_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", admin_token, csrf_token),
        )
        .form(&[("csrf_token", csrf_token.as_str())])
        .await;
    let status = approve.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "approve should redirect, got {}",
        status
    );

    // 3. request is approved, ews row is created with same fingerprint.
    let new_status: String = unwrap_ok!(
        r::table
            .filter(r::uuid.eq(request_uuid))
            .select(r::status)
            .first(&mut conn)
            .await
    );
    assert_eq!(new_status, "approved");

    let ews_count: i64 = unwrap_ok!(
        ews::table
            .filter(ews::user_id.eq(user_id))
            .filter(ews::public_key_fingerprint.eq(&fingerprint))
            .filter(ews::offboarded_at.is_null())
            .count()
            .get_result(&mut conn)
            .await
    );
    assert_eq!(ews_count, 1, "approval must produce exactly one ews row");
}

/// End-to-end: user submits, admin rejects with a reason. The request
/// flips to `rejected`, the reason is persisted, no `ews` row is
/// created.
#[tokio::test]
async fn iacs_admin_can_reject_request_with_reason() {
    use vauban_web::schema::{ews, ews_onboarding_requests as r};

    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("iacs_reject_user");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;

    let admin_name = unique_name("iacs_reject_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let user_token = app
        .generate_test_token(&user_uuid.to_string(), &username, false, false)
        .await;
    let csrf_token = app.generate_csrf_token();

    let ews_name = unique_name("ews_reject");
    let key_line = make_ed25519_line_for_tag(ews_name.as_str());

    let submit = app
        .server
        .post("/iacs/onboard")
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", user_token, csrf_token),
        )
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("name", ews_name.as_str()),
            ("public_key", key_line.as_str()),
            ("justification", "Reject me end-to-end"),
        ])
        .await;
    assert!(matches!(submit.status_code().as_u16(), 302 | 303));

    let (request_uuid, fingerprint): (Uuid, String) = unwrap_ok!(
        r::table
            .filter(r::user_id.eq(user_id))
            .filter(r::name.eq(&ews_name))
            .select((r::uuid, r::public_key_fingerprint))
            .first(&mut conn)
            .await
    );

    let admin_token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let reject = app
        .server
        .post(&format!("/iacs/admin/request/{}/reject", request_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", admin_token, csrf_token),
        )
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            (
                "reason",
                "Asset not whitelisted in the IACS perimeter for this requester",
            ),
        ])
        .await;
    let status = reject.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "reject should redirect, got {}",
        status
    );

    let (new_status, persisted_reason): (String, Option<String>) = unwrap_ok!(
        r::table
            .filter(r::uuid.eq(request_uuid))
            .select((r::status, r::decision_reason))
            .first(&mut conn)
            .await
    );
    assert_eq!(new_status, "rejected");
    assert!(
        persisted_reason
            .as_deref()
            .map(|s| s.contains("not whitelisted"))
            .unwrap_or(false),
        "rejection reason should be persisted, got {:?}",
        persisted_reason
    );

    let ews_count: i64 = unwrap_ok!(
        ews::table
            .filter(ews::public_key_fingerprint.eq(&fingerprint))
            .count()
            .get_result(&mut conn)
            .await
    );
    assert_eq!(ews_count, 0, "rejection must NOT create any ews row");
}

/// `POST /iacs/admin/request/{uuid}/reject` with an empty / too-short
/// reason flashes an error and does NOT update the row.
#[tokio::test]
async fn iacs_admin_reject_requires_a_reason() {
    use vauban_web::schema::ews_onboarding_requests as r;

    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("iacs_rejnoreason_user");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;

    let admin_name = unique_name("iacs_rejnoreason_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let user_token = app
        .generate_test_token(&user_uuid.to_string(), &username, false, false)
        .await;
    let csrf_token = app.generate_csrf_token();

    let ews_name = unique_name("ews_rejnoreason");
    let key_line = make_ed25519_line_for_tag(ews_name.as_str());

    let submit = app
        .server
        .post("/iacs/onboard")
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", user_token, csrf_token),
        )
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("name", ews_name.as_str()),
            ("public_key", key_line.as_str()),
            ("justification", "Short-reason reject"),
        ])
        .await;
    assert!(matches!(submit.status_code().as_u16(), 302 | 303));

    let request_uuid: Uuid = unwrap_ok!(
        r::table
            .filter(r::user_id.eq(user_id))
            .filter(r::name.eq(&ews_name))
            .select(r::uuid)
            .first(&mut conn)
            .await
    );

    let admin_token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let response = app
        .server
        .post(&format!("/iacs/admin/request/{}/reject", request_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", admin_token, csrf_token),
        )
        .form(&[("csrf_token", csrf_token.as_str()), ("reason", "x")])
        .await;
    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "missing-reason reject should redirect with flash, got {}",
        status
    );

    let new_status: String = unwrap_ok!(
        r::table
            .filter(r::uuid.eq(request_uuid))
            .select(r::status)
            .first(&mut conn)
            .await
    );
    assert_eq!(
        new_status, "pending",
        "row must stay pending when reject is missing a reason"
    );
}

/// Lifecycle: approve -> disable -> enable -> offboard.
/// Each transition flips the corresponding column on the `ews` row.
#[tokio::test]
async fn iacs_admin_ews_lifecycle_disable_enable_offboard() {
    use vauban_web::schema::{ews, ews_onboarding_requests as r};

    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("iacs_lc_user");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;

    let admin_name = unique_name("iacs_lc_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let user_token = app
        .generate_test_token(&user_uuid.to_string(), &username, false, false)
        .await;
    let admin_token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let csrf_token = app.generate_csrf_token();

    // 1. submit + approve.
    let ews_name = unique_name("ews_lc");
    let key_line = make_ed25519_line_for_tag(ews_name.as_str());
    let submit = app
        .server
        .post("/iacs/onboard")
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", user_token, csrf_token),
        )
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("name", ews_name.as_str()),
            ("public_key", key_line.as_str()),
            ("justification", "Lifecycle me"),
        ])
        .await;
    assert!(matches!(submit.status_code().as_u16(), 302 | 303));

    let request_uuid: Uuid = unwrap_ok!(
        r::table
            .filter(r::user_id.eq(user_id))
            .filter(r::name.eq(&ews_name))
            .select(r::uuid)
            .first(&mut conn)
            .await
    );

    let approve = app
        .server
        .post(&format!("/iacs/admin/request/{}/approve", request_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", admin_token, csrf_token),
        )
        .form(&[("csrf_token", csrf_token.as_str())])
        .await;
    assert!(matches!(approve.status_code().as_u16(), 302 | 303));

    let ews_uuid: Uuid = unwrap_ok!(
        ews::table
            .filter(ews::user_id.eq(user_id))
            .filter(ews::name.eq(&ews_name))
            .select(ews::uuid)
            .first(&mut conn)
            .await
    );

    // 2. disable.
    let disable = app
        .server
        .post(&format!("/iacs/admin/ews/{}/disable", ews_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", admin_token, csrf_token),
        )
        .form(&[("csrf_token", csrf_token.as_str())])
        .await;
    assert!(matches!(disable.status_code().as_u16(), 302 | 303));

    let disabled_at: Option<chrono::DateTime<chrono::Utc>> = unwrap_ok!(
        ews::table
            .filter(ews::uuid.eq(ews_uuid))
            .select(ews::disabled_at)
            .first(&mut conn)
            .await
    );
    assert!(disabled_at.is_some(), "disable must set disabled_at");

    // 3. enable.
    let enable = app
        .server
        .post(&format!("/iacs/admin/ews/{}/enable", ews_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", admin_token, csrf_token),
        )
        .form(&[("csrf_token", csrf_token.as_str())])
        .await;
    assert!(matches!(enable.status_code().as_u16(), 302 | 303));

    let disabled_at: Option<chrono::DateTime<chrono::Utc>> = unwrap_ok!(
        ews::table
            .filter(ews::uuid.eq(ews_uuid))
            .select(ews::disabled_at)
            .first(&mut conn)
            .await
    );
    assert!(
        disabled_at.is_none(),
        "enable must clear disabled_at, got {:?}",
        disabled_at
    );

    // 4. offboard.
    let offboard = app
        .server
        .post(&format!("/iacs/admin/ews/{}/offboard", ews_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", admin_token, csrf_token),
        )
        .form(&[("csrf_token", csrf_token.as_str())])
        .await;
    assert!(matches!(offboard.status_code().as_u16(), 302 | 303));

    let offboarded_at: Option<chrono::DateTime<chrono::Utc>> = unwrap_ok!(
        ews::table
            .filter(ews::uuid.eq(ews_uuid))
            .select(ews::offboarded_at)
            .first(&mut conn)
            .await
    );
    assert!(offboarded_at.is_some(), "offboard must set offboarded_at");
}

// ===================================================================
// /sessions/my-requests integration
// ===================================================================
//
// Strict per-state rendering tests live in
// `iacs_my_requests_render_test.rs`. The tests in this file are
// limited to the lifecycle / DB invariants exercised through
// /iacs/* and /iacs/admin/* endpoints.
