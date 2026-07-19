//! IACS admin-zone UX -- end-to-end tests for paliers introduced in
//! May 2026:
//!
//! 1. Confirmation dialogs on every `Offboard` action -- both
//!    user-zone (`/sessions/my-requests`) and admin-zone
//!    (`/iacs/admin` + `/iacs/admin/ews/{uuid}`). Since the CSP
//!    hardening (July 2026) the confirms are HTMX-driven
//!    (`hx-confirm` + styled deleteConfirm modal); inline
//!    `onsubmit="return confirm(...)"` is dead code under
//!    `script-src 'self'` and is forbidden by
//!    `scripts/check_no_inline_event_handlers.sh`.
//! 2. Copy-to-clipboard buttons on the SSH-keygen command
//!    (`/iacs/onboard`) and on the full public key
//!    (`/iacs/admin/ews/{uuid}`).
//! 3. Session-expired admin browsing `/iacs/admin` -> 303 to /login,
//!    NOT 403 "Insufficient privileges".
//! 4. Pending-onboarding pagination at 3 rows per page on
//!    `/iacs/admin?pending_page=N`.
//! 5. EWS Active/Offboarded tabs with 5-rows-per-page pagination and
//!    HTMX-driven `?search=` filtering on `username | ews.name`.
//!
//! These tests drive the public HTTP surface (CSRF cookie + JWT
//! cookie + form bodies) so any regression in the route layer or
//! template shape is caught here, not just by lower-level units.
//! They share helper code with `iacs_test.rs` (no module-level reuse
//! to keep test crates light: a few helpers are duplicated below).

use crate::common::{TestApp, assertions::assert_status, unwrap_ok};
use crate::fixtures::{create_simple_admin_user, create_simple_user, unique_name};
use axum::http::header::COOKIE;
use base64::Engine;
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use sha2::{Digest, Sha256};
use uuid::Uuid;

// ===================================================================
// Helpers (duplicated from iacs_test.rs / iacs_my_requests_render_test.rs:
// integration-test files cannot import from each other in a single
// `tests/web/` integration crate, so a tiny copy is the cleanest path).
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
            ("justification", "ux-test"),
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

async fn admin_offboard(app: &TestApp, admin_token: &str, csrf_token: &str, ews_uuid: Uuid) {
    let response = app
        .server
        .post(&format!("/iacs/admin/ews/{}/offboard", ews_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", admin_token, csrf_token),
        )
        .form(&[("csrf_token", csrf_token)])
        .await;
    assert!(
        matches!(response.status_code().as_u16(), 302 | 303),
        "offboard failed (status {})",
        response.status_code().as_u16()
    );
}

/// Spawn an admin and return `(admin_id, admin_token, csrf_token)`.
async fn spawn_admin(app: &TestApp, suffix: &str) -> (i32, String, String) {
    let mut conn = app.get_conn().await;
    let admin_name = unique_name(suffix);
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let csrf = app.generate_csrf_token();
    (admin_id, token, csrf)
}

/// Spawn a regular user and return `(user_id, user_token, csrf_token)`.
async fn spawn_user(app: &TestApp, suffix: &str) -> (i32, String, String) {
    let mut conn = app.get_conn().await;
    let username = unique_name(suffix);
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;
    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, false, false)
        .await;
    let csrf = app.generate_csrf_token();
    (user_id, token, csrf)
}

// ===================================================================
// Confirmation dialogs (P1 + P2)
// ===================================================================

/// Self-offboard from the user's "My Requests" page MUST present a
/// confirmation dialog so an accidental click does not destroy
/// the EWS irreversibly. Pinned by grepping the rendered HTML for
/// `hx-confirm=` (CSP-compliant; inline `onsubmit=` is dead code).
/// The action target proves it is the `offboard-self` form (and not
/// e.g. the `cancel` form).
#[tokio::test]
async fn my_requests_self_offboard_form_has_confirm_dialog() {
    let app = TestApp::spawn().await;

    let (user_id, user_token, csrf_token) = spawn_user(app, "iacs_ux_so_user").await;
    let (_admin_id, admin_token, _) = spawn_admin(app, "iacs_ux_so_admin").await;

    let ews_name = unique_name("ews_ux_so");
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

    let response = app
        .server
        .get("/sessions/my-requests")
        .add_header(COOKIE, format!("access_token={}", user_token))
        .await;
    assert_status(&response, 200);
    let body = response.text();

    // Locate the EWS-tab panel; the confirm() must guard the
    // `offboard-self` action specifically.
    assert!(
        body.contains(r#"id="ews-tab""#),
        "EWS tab panel must be present"
    );
    assert!(
        body.contains("/offboard-self"),
        "self-offboard form must be rendered when EWS is active"
    );
    // CSP hardening: ONLY the HTMX `hx-confirm` attribute counts.
    // Inline `onsubmit=` is silently disabled by `script-src 'self'`
    // (the guard would be dead code) and is forbidden by the
    // `check_no_inline_event_handlers.sh` lint.
    assert!(
        body.contains("hx-confirm="),
        "self-offboard form must present an HTMX confirm dialog; \
         `hx-confirm=` does not appear in body"
    );
    assert!(
        !body.contains("onsubmit="),
        "inline onsubmit= is dead code under the CSP and must not reappear"
    );
}

/// Admin offboard from the IACS landing page must also present a
/// `confirm()` dialog. Pinned by parsing the rendered HTML for the
/// admin landing.
#[tokio::test]
async fn admin_landing_offboard_form_has_confirm_dialog() {
    let app = TestApp::spawn().await;

    let (user_id, user_token, csrf_token) = spawn_user(app, "iacs_ux_ao_user").await;
    let (_admin_id, admin_token, _) = spawn_admin(app, "iacs_ux_ao_admin").await;

    let ews_name = unique_name("ews_ux_ao");
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

    let response = app
        .server
        .get("/iacs/admin")
        .add_header(COOKIE, format!("access_token={}", admin_token))
        .await;
    assert_status(&response, 200);
    let body = response.text();

    assert!(
        body.contains("/offboard"),
        "admin offboard action must be rendered"
    );
    assert!(
        body.contains("Offboarding is irreversible"),
        "the confirm() dialog text must be present (Tailwind / HTMX confirm message)"
    );
    // CSP hardening: only `hx-confirm=` counts (see the self-offboard
    // test above for the rationale).
    assert!(
        body.contains("hx-confirm="),
        "admin offboard form must present an HTMX confirm dialog"
    );
    assert!(
        !body.contains("onsubmit="),
        "inline onsubmit= is dead code under the CSP and must not reappear"
    );
}

/// Admin offboard from the per-EWS detail page must also present a
/// `confirm()` dialog -- the detail page is reached after clicking
/// `Details` from the landing list.
#[tokio::test]
async fn admin_detail_offboard_form_has_confirm_dialog() {
    let app = TestApp::spawn().await;

    let (user_id, user_token, csrf_token) = spawn_user(app, "iacs_ux_ad_user").await;
    let (_admin_id, admin_token, _) = spawn_admin(app, "iacs_ux_ad_admin").await;

    let ews_name = unique_name("ews_ux_ad");
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

    let response = app
        .server
        .get(&format!("/iacs/admin/ews/{}", ews_uuid))
        .add_header(COOKIE, format!("access_token={}", admin_token))
        .await;
    assert_status(&response, 200);
    let body = response.text();

    assert!(
        body.contains(&format!("/iacs/admin/ews/{}/offboard", ews_uuid)),
        "EWS detail must render the offboard form action"
    );
    // CSP hardening: only `hx-confirm=` counts (inline onsubmit= is
    // dead code under `script-src 'self'`).
    assert!(
        body.contains("hx-confirm="),
        "EWS detail offboard form must guard the action with an HTMX confirm"
    );
    assert!(
        !body.contains("onsubmit="),
        "inline onsubmit= is dead code under the CSP and must not reappear"
    );
}

// ===================================================================
// Copy buttons (P3 + P4)
// ===================================================================

/// `/iacs/onboard` must render TWO copy buttons (one per OS tab) for
/// the `ssh-keygen` command. Pinned by `data-testid` so the page
/// shape is observable in CI.
#[tokio::test]
async fn iacs_onboard_renders_copy_button_for_ssh_keygen_command() {
    let app = TestApp::spawn().await;
    let (_user_id, user_token, _csrf) = spawn_user(app, "iacs_ux_copykg").await;

    let response = app
        .server
        .get("/iacs/onboard")
        .add_header(COOKIE, format!("access_token={}", user_token))
        .await;
    assert_status(&response, 200);
    let body = response.text();

    assert!(
        body.contains(r#"data-testid="ssh-keygen-unix-copy""#),
        "Mac/Linux tab must include a copy button (data-testid='ssh-keygen-unix-copy')"
    );
    assert!(
        body.contains(r#"data-testid="ssh-keygen-windows-copy""#),
        "Windows tab must include a copy button (data-testid='ssh-keygen-windows-copy')"
    );
    // The pre+code block carrying the command stays in place under
    // the same testid -- so the button has something to copy.
    assert!(
        body.contains(r#"data-testid="ssh-keygen-unix""#),
        "Mac/Linux command code block must remain identifiable"
    );
}

/// `/iacs/admin/ews/{uuid}` must include a copy button next to the
/// "Show full public key" modal, so the admin can `<click>` the
/// public key into the clipboard for redistribution.
#[tokio::test]
async fn iacs_admin_ews_detail_renders_copy_button_for_public_key() {
    let app = TestApp::spawn().await;

    let (user_id, user_token, csrf_token) = spawn_user(app, "iacs_ux_pkcopy_user").await;
    let (_admin_id, admin_token, _) = spawn_admin(app, "iacs_ux_pkcopy_admin").await;

    let ews_name = unique_name("ews_pkcopy");
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

    let response = app
        .server
        .get(&format!("/iacs/admin/ews/{}", ews_uuid))
        .add_header(COOKIE, format!("access_token={}", admin_token))
        .await;
    assert_status(&response, 200);
    let body = response.text();

    assert!(
        body.contains(r#"data-testid="iacs-ews-pubkey-copy""#),
        "EWS detail must include a copy button next to the full public key"
    );
    assert!(
        body.contains(r#"data-testid="iacs-ews-pubkey""#),
        "EWS detail must keep the pubkey block identifiable for the copy button to copy from"
    );
}

// ===================================================================
// Session-expired redirect to /login (P5)
// ===================================================================

/// An admin whose session has expired (no JWT cookie at all) browsing
/// `/iacs/admin` MUST be redirected to `/login`, NOT served a JSON
/// 403 "Insufficient privileges". This is the bug fix in
/// `middleware/require_iacs_manage.rs`.
#[tokio::test]
async fn iacs_admin_redirects_to_login_when_session_missing() {
    let app = TestApp::spawn().await;
    // Deliberately NO `access_token=` cookie.
    let response = app.server.get("/iacs/admin").await;
    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "session-missing admin must be redirected (got {})",
        status
    );
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert_eq!(
        location, "/login",
        "Location must be /login (was {location:?})"
    );

    let body = response.text();
    assert!(
        !body.contains("Insufficient privileges"),
        "must NOT show the 403 Insufficient privileges body when the session is missing; \
         got: {}",
        body.chars().take(400).collect::<String>()
    );
}

/// A request carrying a syntactically invalid JWT cookie (the shape
/// most commonly observed when a session expires after the cookie
/// hits the browser cache) MUST also redirect to /login.
#[tokio::test]
async fn iacs_admin_redirects_to_login_when_jwt_invalid() {
    let app = TestApp::spawn().await;
    let response = app
        .server
        .get("/iacs/admin")
        .add_header(COOKIE, "access_token=this-is-not-a-real-jwt")
        .await;
    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "expired JWT must be redirected (got {})",
        status
    );
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert_eq!(location, "/login");
}

// ===================================================================
// Pending-onboarding pagination (P6, 3 / page)
// ===================================================================

/// 4 pending requests, `pending_page=1` (default) shows the 3
/// most-recent rows; `pending_page=2` shows the 4th. The pagination
/// nav element (`data-testid="iacs-pending-pagination"`) is rendered
/// only when `total_pages > 1`.
#[tokio::test]
async fn iacs_admin_paginates_pending_requests_at_3_per_page() {
    let app = TestApp::spawn().await;

    let (user_id, user_token, csrf_token) = spawn_user(app, "iacs_pending_pg").await;
    let (_admin_id, admin_token, _) = spawn_admin(app, "iacs_pending_pg_a").await;

    // Submit 4 requests under the same user. `submit_request` uses
    // ed25519 keys derived from the EWS name so each request has a
    // distinct fingerprint (no `KeyAlreadyUsed` collision).
    let mut names: Vec<String> = Vec::with_capacity(4);
    for i in 0..4 {
        let name = format!("{}-{}", unique_name("pg_p"), i);
        let _ = submit_request(app, &user_token, &csrf_token, &name, user_id).await;
        names.push(name);
    }

    // Page 1 (default) = 3 most-recent rows. The admin landing also
    // emits a pagination block because total_pages = 2 > 1.
    let resp_p1 = app
        .server
        .get("/iacs/admin")
        .add_header(COOKIE, format!("access_token={}", admin_token))
        .await;
    assert_status(&resp_p1, 200);
    let body_p1 = resp_p1.text();
    assert!(
        body_p1.contains(r#"data-testid="iacs-pending-pagination""#),
        "page 1 must render the pending pagination block when there are 4 requests \
         (3 per page -> 2 pages); body sample: {}",
        body_p1.chars().take(400).collect::<String>()
    );

    // Count how many of our names appear on page 1 vs page 2. With
    // `created_at DESC` ordering, the latest-submitted (index 3 in
    // `names`) appears first.
    let count_in = |body: &str, names: &[String]| -> usize {
        names.iter().filter(|n| body.contains(n.as_str())).count()
    };
    let on_p1 = count_in(&body_p1, &names);
    assert_eq!(
        on_p1, 3,
        "page 1 must render exactly 3 EWS names (got {on_p1})"
    );

    let resp_p2 = app
        .server
        .get("/iacs/admin?pending_page=2")
        .add_header(COOKIE, format!("access_token={}", admin_token))
        .await;
    assert_status(&resp_p2, 200);
    let body_p2 = resp_p2.text();
    let on_p2 = count_in(&body_p2, &names);
    assert_eq!(
        on_p2, 1,
        "page 2 must render the remaining 1 row (got {on_p2})"
    );

    // The 4th-submitted name (latest, ordered DESC -> page 1) must
    // not appear on page 2; conversely the oldest (index 0) must be
    // there.
    assert!(
        body_p1.contains(&names[3]),
        "the latest submission (index 3) must be on page 1"
    );
    assert!(
        body_p2.contains(&names[0]),
        "the oldest submission (index 0) must be on page 2"
    );
}

// ===================================================================
// EWS Active / Offboarded tabs (P7)
// ===================================================================

/// The Active tab is the default. Switching to `?tab=offboarded` flips
/// which rows are visible: the offboarded EWS must appear in the
/// offboarded tab AND vanish from the active tab.
#[tokio::test]
async fn iacs_admin_tabs_filter_active_vs_offboarded() {
    let app = TestApp::spawn().await;

    let (user_id, user_token, csrf_token) = spawn_user(app, "iacs_tab_user").await;
    let (_admin_id, admin_token, _) = spawn_admin(app, "iacs_tab_admin").await;

    let active_name = unique_name("ews_tab_active");
    let off_name = unique_name("ews_tab_off");

    let req_active = submit_request(app, &user_token, &csrf_token, &active_name, user_id).await;
    let _ews_active = admin_approve(
        app,
        &admin_token,
        &csrf_token,
        req_active,
        &active_name,
        user_id,
    )
    .await;

    let req_off = submit_request(app, &user_token, &csrf_token, &off_name, user_id).await;
    let ews_off = admin_approve(app, &admin_token, &csrf_token, req_off, &off_name, user_id).await;
    admin_offboard(app, &admin_token, &csrf_token, ews_off).await;

    // Default tab (Active): the active row appears, the offboarded
    // one does not.
    let resp_active = app
        .server
        .get("/iacs/admin")
        .add_header(COOKIE, format!("access_token={}", admin_token))
        .await;
    assert_status(&resp_active, 200);
    let body_active = resp_active.text();
    assert!(
        body_active.contains(&active_name),
        "active EWS must be listed in the default (Active) tab"
    );
    assert!(
        !body_active.contains(&off_name),
        "offboarded EWS must NOT appear in the Active tab"
    );

    // Offboarded tab: the inverse.
    let resp_off = app
        .server
        .get("/iacs/admin?tab=offboarded")
        .add_header(COOKIE, format!("access_token={}", admin_token))
        .await;
    assert_status(&resp_off, 200);
    let body_off = resp_off.text();
    assert!(
        body_off.contains(&off_name),
        "offboarded EWS must be listed in the Offboarded tab"
    );
    assert!(
        !body_off.contains(&active_name),
        "active EWS must NOT appear in the Offboarded tab"
    );
}

/// 6 active EWS, `EWS_PAGE_SIZE = 5` -> 2 pages. Page 1 has 5 rows,
/// page 2 has 1.
#[tokio::test]
async fn iacs_admin_paginates_ews_at_5_per_page() {
    let app = TestApp::spawn().await;

    let (user_id, user_token, csrf_token) = spawn_user(app, "iacs_ews_pg_user").await;
    let (_admin_id, admin_token, _) = spawn_admin(app, "iacs_ews_pg_admin").await;

    let mut names: Vec<String> = Vec::with_capacity(6);
    for i in 0..6 {
        let name = format!("{}-{}", unique_name("pg_e"), i);
        let req = submit_request(app, &user_token, &csrf_token, &name, user_id).await;
        let _ = admin_approve(app, &admin_token, &csrf_token, req, &name, user_id).await;
        names.push(name);
    }

    let resp_p1 = app
        .server
        .get("/iacs/admin")
        .add_header(COOKIE, format!("access_token={}", admin_token))
        .await;
    assert_status(&resp_p1, 200);
    let body_p1 = resp_p1.text();
    assert!(
        body_p1.contains(r#"data-testid="iacs-ews-pagination""#),
        "EWS pagination block must render with 6 active rows (5 per page)"
    );
    let on_p1 = names
        .iter()
        .filter(|n| body_p1.contains(n.as_str()))
        .count();
    assert_eq!(on_p1, 5, "page 1 must show 5 EWS names (got {on_p1})");

    let resp_p2 = app
        .server
        .get("/iacs/admin?ews_page=2")
        .add_header(COOKIE, format!("access_token={}", admin_token))
        .await;
    assert_status(&resp_p2, 200);
    let body_p2 = resp_p2.text();
    let on_p2 = names
        .iter()
        .filter(|n| body_p2.contains(n.as_str()))
        .count();
    assert_eq!(on_p2, 1, "page 2 must show 1 EWS name (got {on_p2})");
}

/// HTMX-driven search filters the EWS list by `username` OR `ews.name`.
/// Two EWS owned by two distinct users; a search for one of the
/// usernames returns ONLY that EWS, the other is hidden.
#[tokio::test]
async fn iacs_admin_search_filters_by_username_or_ews_name() {
    let app = TestApp::spawn().await;

    let (alice_id, alice_token, csrf_token) = spawn_user(app, "iacs_search_alice").await;
    let (bob_id, bob_token, _) = spawn_user(app, "iacs_search_bob").await;
    let (_admin_id, admin_token, _) = spawn_admin(app, "iacs_search_admin").await;

    let alice_ews = unique_name("alice_ews");
    let bob_ews = unique_name("bob_ews");

    let req_alice = submit_request(app, &alice_token, &csrf_token, &alice_ews, alice_id).await;
    let _ = admin_approve(
        app,
        &admin_token,
        &csrf_token,
        req_alice,
        &alice_ews,
        alice_id,
    )
    .await;

    let req_bob = submit_request(app, &bob_token, &csrf_token, &bob_ews, bob_id).await;
    let _ = admin_approve(app, &admin_token, &csrf_token, req_bob, &bob_ews, bob_id).await;

    // Lookup alice's username from the DB so the search query is
    // exactly the one the handler stores. `unique_name()` returns
    // a stable, sluggified value but resolves to the same column
    // value as Alice's row.
    let alice_username: String = {
        use vauban_web::schema::users;
        let mut conn = app.get_conn().await;
        unwrap_ok!(
            users::table
                .filter(users::id.eq(alice_id))
                .select(users::username)
                .first::<String>(&mut conn)
                .await
        )
    };

    // Search by username -> only alice's EWS shows up.
    let resp = app
        .server
        .get(&format!("/iacs/admin?search={}", alice_username))
        .add_header(COOKIE, format!("access_token={}", admin_token))
        .await;
    assert_status(&resp, 200);
    let body = resp.text();
    assert!(
        body.contains(&alice_ews),
        "search by alice's username must return alice's EWS"
    );
    assert!(
        !body.contains(&bob_ews),
        "search by alice's username must NOT return bob's EWS"
    );

    // Search by ews name -> only bob's EWS.
    let resp = app
        .server
        .get(&format!("/iacs/admin?search={}", bob_ews))
        .add_header(COOKIE, format!("access_token={}", admin_token))
        .await;
    assert_status(&resp, 200);
    let body = resp.text();
    assert!(
        body.contains(&bob_ews),
        "search by bob's EWS name must return bob's EWS"
    );
    assert!(
        !body.contains(&alice_ews),
        "search by bob's EWS name must NOT return alice's EWS"
    );
}

/// The HTMX search input must be wired with the `hx-get` /
/// `hx-target` / `hx-select` triple targeting the EWS section,
/// and must include the hidden `tab` field so a search inside
/// the Offboarded tab does not silently fall back to the Active
/// tab on the next round-trip.
#[tokio::test]
async fn iacs_admin_search_input_carries_htmx_attributes() {
    let app = TestApp::spawn().await;
    let (_admin_id, admin_token, _) = spawn_admin(app, "iacs_htmx_attrs").await;

    let response = app
        .server
        .get("/iacs/admin")
        .add_header(COOKIE, format!("access_token={}", admin_token))
        .await;
    assert_status(&response, 200);
    let body = response.text();

    assert!(
        body.contains(r#"data-testid="iacs-ews-search""#),
        "search input must carry data-testid='iacs-ews-search'"
    );
    assert!(
        body.contains(r#"hx-get="/iacs/admin""#),
        "search input must `hx-get='/iacs/admin'`"
    );
    assert!(
        body.contains(r##"hx-target="#iacs-ews-section""##),
        "search input must `hx-target='#iacs-ews-section'`"
    );
    assert!(
        body.contains(r##"hx-select="#iacs-ews-section""##),
        "search input must `hx-select='#iacs-ews-section'`"
    );
    // The hidden `tab` field is what carries tab state through the
    // HTMX round-trip via `hx-include="[name='search'], [name='tab']"`.
    assert!(
        body.contains(r#"name="tab""#),
        "search input must include a hidden `name='tab'` companion field so \
         tab state is preserved across HTMX swaps"
    );
}

/// Tab nav anchors carry the `data-testid` pins so a future template
/// refactor cannot silently drop them. Pinning `aria-current="page"`
/// on the active tab pins the WAI-ARIA contract too.
#[tokio::test]
async fn iacs_admin_tab_nav_renders_with_testid_pins() {
    let app = TestApp::spawn().await;
    let (_admin_id, admin_token, _) = spawn_admin(app, "iacs_tab_pins").await;

    let resp = app
        .server
        .get("/iacs/admin")
        .add_header(COOKIE, format!("access_token={}", admin_token))
        .await;
    let body = resp.text();
    assert!(body.contains(r#"data-testid="iacs-tab-active""#));
    assert!(body.contains(r#"data-testid="iacs-tab-offboarded""#));

    // On the default (`?tab=active`) page the Active tab carries
    // `aria-current="page"` (it is rendered as `<span>`, not `<a>`).
    let active_anchor = body
        .lines()
        .find(|l| l.contains(r#"data-testid="iacs-tab-active""#))
        .unwrap_or_default();
    assert!(
        active_anchor.contains(r#"aria-current="page""#),
        "default tab Active must carry aria-current; line: {active_anchor}"
    );
}
