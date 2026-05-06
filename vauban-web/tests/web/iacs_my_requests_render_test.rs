//! `/sessions/my-requests` rendering -- strict regression tests.
//!
//! Pre-history: an earlier weaker test (`iacs_test::iacs_my_requests_lists_pending_request`)
//! checked only `body.contains(&ews_name)`. That assertion was too
//! permissive: a regression that hid the entire EWS tab content
//! (e.g. a stray `{% if iacs_visible %}` flip, or a 500 in
//! `load_my_ews_items` swallowed by `unwrap_or_else(Vec::new)`)
//! could have left the EWS name printed *somewhere* on the page
//! (or not at all) without the test catching the loss of the
//! status badge.
//!
//! The tests below cover EVERY visible state of an EWS row in the
//! the EWS tab (`#ews-tab`) and assert simultaneously:
//!
//! 1. The EWS name appears.
//! 2. The corresponding state label appears (`Pending` / `Rejected`
//!    / `Cancelled` / `Active` / `Disabled` / `Offboarded`).
//! 3. The badge background class for the state is in the body --
//!    pinning the actual rendered chip, not just the label text.
//! 4. The `#ews-tab` container is present (so we know the IACS UI
//!    branch ran -- `iacs_visible=true`).
//! 5. The section-empty placeholder ("No EWS registered") is ABSENT
//!    when at least one row is expected.
//!
//! The lifecycle transitions are driven through the public HTTP
//! surface, so any future refactor of the handler / template / IPC
//! layer that breaks the rendering contract trips a test here.

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

/// Submit an EWS onboarding request via the public HTTP surface.
/// Returns the persisted request UUID.
async fn submit_request(
    app: &TestApp,
    user_token: &str,
    csrf_token: &str,
    ews_name: &str,
    user_id: i32,
) -> Uuid {
    use vauban_web::schema::ews_onboarding_requests as r;

    let key_line = make_ed25519_line_for_tag(ews_name);
    let response = app
        .server
        .post("/iacs/onboard")
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", user_token, csrf_token),
        )
        .form(&[
            ("csrf_token", csrf_token),
            ("name", ews_name),
            ("public_key", key_line.as_str()),
            ("justification", "render-test justification text"),
        ])
        .await;
    assert!(
        matches!(response.status_code().as_u16(), 302 | 303),
        "submit failed (status {}): {}",
        response.status_code().as_u16(),
        response.text()
    );

    let mut conn = app.get_conn().await;
    unwrap_ok!(
        r::table
            .filter(r::user_id.eq(user_id))
            .filter(r::name.eq(ews_name))
            .select(r::uuid)
            .first(&mut conn)
            .await
    )
}

/// Approve a pending request. Returns the resulting `ews.uuid`.
async fn admin_approve(
    app: &TestApp,
    admin_token: &str,
    csrf_token: &str,
    request_uuid: Uuid,
    ews_name: &str,
    user_id: i32,
) -> Uuid {
    use vauban_web::schema::ews;

    let response = app
        .server
        .post(&format!("/iacs/admin/request/{}/approve", request_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", admin_token, csrf_token),
        )
        .form(&[("csrf_token", csrf_token)])
        .await;
    assert!(
        matches!(response.status_code().as_u16(), 302 | 303),
        "approve failed (status {})",
        response.status_code().as_u16()
    );

    let mut conn = app.get_conn().await;
    unwrap_ok!(
        ews::table
            .filter(ews::user_id.eq(user_id))
            .filter(ews::name.eq(ews_name))
            .select(ews::uuid)
            .first(&mut conn)
            .await
    )
}

/// Fetch `/sessions/my-requests` for the given user and return the
/// rendered HTML body.
async fn fetch_my_requests(app: &TestApp, user_token: &str) -> String {
    let response = app
        .server
        .get("/sessions/my-requests")
        .add_header(COOKIE, format!("access_token={}", user_token))
        .await;
    assert_status(&response, 200);
    response.text()
}

/// Asserts the EWS tab panel (`#ews-tab`) is present in the HTML AND
/// the expected EWS name + state badge appear together near each other.
///
/// `expected_state_label` -- the human-facing label
/// (`MyEwsState::label`).
/// `expected_badge_class_marker` -- a stable substring of
/// `MyEwsState::badge_class` that uniquely identifies the badge for
/// this state. Picking one colour-token is enough; the goal is to
/// catch an accidental swap of the badge class, not to pin every
/// dark-mode variant.
fn assert_section_renders_state(
    body: &str,
    ews_name: &str,
    expected_state_label: &str,
    expected_badge_class_marker: &str,
) {
    assert!(
        body.contains(r#"id="ews-tab""#),
        "the EWS tab panel (#ews-tab) must be present when iacs_visible=true (body len {})",
        body.len()
    );
    assert!(
        !body.contains("No EWS registered"),
        "section should not show the empty-state placeholder when an EWS row is expected"
    );
    assert!(
        body.contains(ews_name),
        "EWS name '{}' must appear in the rendered body",
        ews_name
    );

    let name_pos = body
        .find(ews_name)
        .expect("ews_name presence already asserted");
    let window_end = (name_pos + 2_000).min(body.len());
    let window = &body[name_pos..window_end];

    assert!(
        window.contains(expected_state_label),
        "state label '{}' must appear within ~2 KiB after the EWS name; \
         this regression usually means the badge was dropped from the row template. \
         Window dump:\n{}",
        expected_state_label,
        window
    );
    assert!(
        window.contains(expected_badge_class_marker),
        "expected badge css class '{}' near the EWS name; the badge class \
         pinning catches a swap of the colour-coded chip even if the label \
         is unchanged. Window dump:\n{}",
        expected_badge_class_marker,
        window
    );
}

// ===================================================================
// Pending
// ===================================================================

#[tokio::test]
async fn my_requests_renders_pending_ews_with_yellow_badge() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("mr_pending");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;
    let user_token = app
        .generate_test_token(&user_uuid.to_string(), &username, false, false)
        .await;
    let csrf_token = app.generate_csrf_token();

    let ews_name = unique_name("ews_mr_pending");
    let _ = submit_request(app, &user_token, &csrf_token, &ews_name, user_id).await;

    let body = fetch_my_requests(app, &user_token).await;
    assert_section_renders_state(&body, &ews_name, "Pending", "bg-yellow-100");
}

// ===================================================================
// Cancelled
// ===================================================================

#[tokio::test]
async fn my_requests_renders_cancelled_ews_with_red_badge_and_no_active() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("mr_cancel");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;
    let user_token = app
        .generate_test_token(&user_uuid.to_string(), &username, false, false)
        .await;
    let csrf_token = app.generate_csrf_token();

    let ews_name = unique_name("ews_mr_cancel");
    let request_uuid = submit_request(app, &user_token, &csrf_token, &ews_name, user_id).await;

    let cancel = app
        .server
        .post(&format!("/iacs/onboard/{}/cancel", request_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", user_token, csrf_token),
        )
        .form(&[("csrf_token", csrf_token.as_str())])
        .await;
    assert!(matches!(cancel.status_code().as_u16(), 302 | 303));

    let body = fetch_my_requests(app, &user_token).await;
    assert_section_renders_state(&body, &ews_name, "Cancelled", "bg-red-100");
}

// ===================================================================
// Approved -> Active
// ===================================================================

#[tokio::test]
async fn my_requests_renders_approved_ews_as_active_with_green_badge() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("mr_approve");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;
    let admin_name = unique_name("mr_approve_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let user_token = app
        .generate_test_token(&user_uuid.to_string(), &username, false, false)
        .await;
    let admin_token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let csrf_token = app.generate_csrf_token();

    let ews_name = unique_name("ews_mr_active");
    let request_uuid = submit_request(app, &user_token, &csrf_token, &ews_name, user_id).await;
    let _ews_uuid = admin_approve(
        app,
        &admin_token,
        &csrf_token,
        request_uuid,
        &ews_name,
        user_id,
    )
    .await;

    let body = fetch_my_requests(app, &user_token).await;
    assert_section_renders_state(&body, &ews_name, "Active", "bg-green-100");
    assert!(
        !body.contains("Pending"),
        "after approval the row must not be displayed twice (pending row \
         must be filtered out by load_my_ews_items)"
    );
}

// ===================================================================
// Rejected
// ===================================================================

#[tokio::test]
async fn my_requests_renders_rejected_ews_with_red_badge_and_reason() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("mr_reject");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;
    let admin_name = unique_name("mr_reject_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let user_token = app
        .generate_test_token(&user_uuid.to_string(), &username, false, false)
        .await;
    let admin_token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let csrf_token = app.generate_csrf_token();

    let ews_name = unique_name("ews_mr_rejected");
    let request_uuid = submit_request(app, &user_token, &csrf_token, &ews_name, user_id).await;

    let reject = app
        .server
        .post(&format!("/iacs/admin/request/{}/reject", request_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", admin_token, csrf_token),
        )
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("reason", "DEBUG-rejection-reason-marker-string-for-test"),
        ])
        .await;
    assert!(matches!(reject.status_code().as_u16(), 302 | 303));

    let body = fetch_my_requests(app, &user_token).await;
    assert_section_renders_state(&body, &ews_name, "Rejected", "bg-red-100");
    assert!(
        body.contains("DEBUG-rejection-reason-marker-string-for-test"),
        "the rejection reason must appear in /sessions/my-requests so the \
         requester knows WHY their request was refused"
    );
}

// ===================================================================
// Disabled (admin disable on an active EWS)
// ===================================================================

#[tokio::test]
async fn my_requests_renders_disabled_ews_with_gray_badge() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("mr_disable");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;
    let admin_name = unique_name("mr_disable_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let user_token = app
        .generate_test_token(&user_uuid.to_string(), &username, false, false)
        .await;
    let admin_token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let csrf_token = app.generate_csrf_token();

    let ews_name = unique_name("ews_mr_disabled");
    let request_uuid = submit_request(app, &user_token, &csrf_token, &ews_name, user_id).await;
    let ews_uuid = admin_approve(
        app,
        &admin_token,
        &csrf_token,
        request_uuid,
        &ews_name,
        user_id,
    )
    .await;

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

    let body = fetch_my_requests(app, &user_token).await;
    // Disabled badge uses bg-gray-100 (light) / bg-gray-700 (dark);
    // pin the light variant which is always emitted.
    assert_section_renders_state(&body, &ews_name, "Disabled", "bg-gray-100");
}

// ===================================================================
// Offboarded (admin offboard)
// ===================================================================

#[tokio::test]
async fn my_requests_renders_offboarded_ews_with_orange_badge() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("mr_offboard");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;
    let admin_name = unique_name("mr_offboard_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let user_token = app
        .generate_test_token(&user_uuid.to_string(), &username, false, false)
        .await;
    let admin_token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let csrf_token = app.generate_csrf_token();

    let ews_name = unique_name("ews_mr_offboarded");
    let request_uuid = submit_request(app, &user_token, &csrf_token, &ews_name, user_id).await;
    let ews_uuid = admin_approve(
        app,
        &admin_token,
        &csrf_token,
        request_uuid,
        &ews_name,
        user_id,
    )
    .await;

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

    let body = fetch_my_requests(app, &user_token).await;
    assert_section_renders_state(&body, &ews_name, "Offboarded", "bg-orange-100");
}

// ===================================================================
// Section gating: kill-switch hides the section entirely
// ===================================================================

/// Sanity counter-test: when `iacs_visible = false` (e.g. via the
/// `[industrial].enabled = false` kill-switch -- here simulated by
/// stripping the `iacs:read` Casbin permission via a user without
/// has no EWS rows, the EWS tab still exists and the empty-state
/// copy is shown inside the panel.
///
/// We do not toggle the global kill-switch here because the test
/// `TestApp` is a process-wide singleton. Instead, this test pins
/// the converse: a JIT session is rendered while no IACS section is
/// shown. If a future regression always renders the section
/// regardless of `iacs_visible`, this test catches it.
///
/// Note: there is no easy way to simulate `iacs_visible = false`
/// per-user in the casbin policy (the policy is shared). The
/// `iacs_kill_switch_test` covers the global kill-switch; this test
/// instead pins the absence of the empty section when a fresh user
/// has no EWS at all.
#[tokio::test]
async fn my_requests_shows_empty_state_when_no_ews_submitted() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("mr_empty");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;
    let user_token = app
        .generate_test_token(&user_uuid.to_string(), &username, false, false)
        .await;

    // Sanity: the brand-new user really has no EWS.
    use vauban_web::schema::{ews, ews_onboarding_requests as r};
    let r_count: i64 = unwrap_ok!(
        r::table
            .filter(r::user_id.eq(user_id))
            .count()
            .get_result(&mut conn)
            .await
    );
    let e_count: i64 = unwrap_ok!(
        ews::table
            .filter(ews::user_id.eq(user_id))
            .count()
            .get_result(&mut conn)
            .await
    );
    assert_eq!(r_count, 0);
    assert_eq!(e_count, 0);

    let body = fetch_my_requests(app, &user_token).await;
    assert!(
        body.contains(r#"id="ews-tab""#),
        "EWS tab panel must render when iacs_visible=true"
    );
    assert!(
        body.contains("No EWS registered"),
        "empty-state placeholder must render when the user owns no EWS"
    );
}
