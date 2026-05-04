//! Issue #34 -- end-to-end coverage for the SSH host-key verification
//! and connect-time pre-flight gates.
//!
//! These tests are the run-time counterpart of the source-grep pin
//! tests in `ssh_host_key_no_silent_green_test.rs`: they bring up a
//! real `TestApp` (Axum router, DB, JWT auth) and exercise the actual
//! HTTP surface. The five regressions they cover, all introduced when
//! the asset surface was split into user vs admin zones (issue #27)
//! and aggravated by the legacy host-key flow:
//!
//! 1. **Silent green fragment when the proxy is unavailable** --
//!    `verify_ssh_host_key` previously returned the GREEN
//!    "SSH Host Key Verified" fragment whenever the SSH proxy could
//!    not be reached. Operators reading the admin detail page
//!    therefore saw a successful verification when in fact NOTHING
//!    had been live-checked. Test A pins the new amber "Could not
//!    verify" fragment.
//!
//! 2. **Mismatch flag must persist across reloads** -- Test B asserts
//!    that once `connection_config.ssh_host_key_mismatch = true` is
//!    set in DB, the verify endpoint stays RED (no silent recovery
//!    on page reload).
//!
//! 3. **No-key path** -- Test C confirms that an SSH asset without a
//!    pinned `ssh_host_key` returns the dedicated no-key fragment
//!    (and not the green one).
//!
//! 4. **`connect_ssh` must refuse when no key is pinned** -- the
//!    pre-flight Lot 3 gate. Pre-#34 the proxy logged "INSECURE -
//!    accepting server key" and opened the session against whatever
//!    key the server presented. Test D asserts the user gets a clear
//!    refusal message and no `proxy_sessions` row is created.
//!
//! 5. **`connect_ssh` must refuse when mismatch flag is set** -- the
//!    other half of the Lot 3 pre-flight gate. Test E asserts the
//!    user gets the explicit MITM-warning refusal and no row is
//!    created.

use crate::common::{TestApp, assertions::assert_status, unwrap_ok};
use crate::fixtures::{
    add_user_to_vauban_group, create_simple_admin_user, create_simple_user,
    create_test_access_rule_with_constraints, create_test_asset_group, create_test_asset_in_group,
    create_test_ssh_asset, create_test_vauban_group, get_asset_uuid, unique_name,
};
use axum::http::header::COOKIE;
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::json;
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

/// Update `assets.connection_config` for a given asset id. Centralised
/// so each test can dictate the exact host-key state without
/// re-implementing the diesel DSL boilerplate.
async fn set_connection_config(
    conn: &mut AsyncPgConnection,
    asset_id: i32,
    config: serde_json::Value,
) {
    use vauban_web::schema::assets::dsl as a;
    let _: usize = unwrap_ok!(
        diesel::update(a::assets.filter(a::id.eq(asset_id)))
            .set(a::connection_config.eq(config))
            .execute(conn)
            .await
    );
}

const PINNED_KEY_OPENSSH: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPinnedKeyForIssue34Test";
const PINNED_KEY_FP: &str = "SHA256:pinned-fingerprint-issue34-test";

/// Test A -- proxy unavailable -> amber "Could not verify" fragment.
///
/// The default `TestApp` builds an `AppState` whose `ssh_proxy` is
/// `None` (no real SSH proxy at the other end of the IPC). The verify
/// handler must then render the amber fragment, NEVER the green one.
/// This is the load-bearing regression test for issue #34: pre-fix
/// the handler returned the green fragment in this exact situation,
/// silently telling operators "Verified" when nothing had been
/// live-checked.
#[tokio::test]
async fn case_a_verify_returns_amber_when_proxy_unavailable() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("issue34_kk_a_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let asset = create_test_ssh_asset(&mut conn, &unique_name("issue34_kk_a_asset")).await;
    let asset_id = asset.asset.id;
    let asset_uuid = asset.asset.uuid;
    set_connection_config(
        &mut conn,
        asset_id,
        json!({
            "ssh_host_key": PINNED_KEY_OPENSSH,
            "ssh_host_key_fingerprint": PINNED_KEY_FP,
            "ssh_host_key_mismatch": false,
        }),
    )
    .await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let response = app
        .server
        .get(&format!("/assets/{}/verify-host-key", asset_uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .add_header(
            axum::http::header::HeaderName::from_static("hx-request"),
            "true",
        )
        .await;

    assert_status(&response, 200);
    let body = response.text();

    assert!(
        body.contains("Could not verify"),
        "verify endpoint with proxy=None must render the amber \"Could \
         not verify\" fragment. Body did not contain that string. \
         This is the issue #34 silent-green regression. Body: {body}"
    );
    assert!(
        !body.contains("SSH Host Key Verified"),
        "verify endpoint with proxy=None must NOT render the green \
         \"SSH Host Key Verified\" fragment. Pre-issue-#34 it did, \
         and that misled operators into thinking nothing was wrong. \
         Body: {body}"
    );
}

/// Test B -- mismatch flag in DB -> RED mismatch fragment, even on
/// reload.
///
/// Once `connection_config.ssh_host_key_mismatch` is set to `true`
/// (typically by `connect_ssh` after a failed handshake), the verify
/// endpoint MUST surface the red mismatch fragment regardless of
/// whether the proxy is reachable. Operators cannot silently
/// "refresh away" a previously-detected MITM.
#[tokio::test]
async fn case_b_verify_returns_red_when_mismatch_flag_set() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("issue34_kk_b_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let asset = create_test_ssh_asset(&mut conn, &unique_name("issue34_kk_b_asset")).await;
    let asset_id = asset.asset.id;
    let asset_uuid = asset.asset.uuid;
    set_connection_config(
        &mut conn,
        asset_id,
        json!({
            "ssh_host_key": PINNED_KEY_OPENSSH,
            "ssh_host_key_fingerprint": PINNED_KEY_FP,
            "ssh_host_key_mismatch": true,
        }),
    )
    .await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let response = app
        .server
        .get(&format!("/assets/{}/verify-host-key", asset_uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .add_header(
            axum::http::header::HeaderName::from_static("hx-request"),
            "true",
        )
        .await;

    assert_status(&response, 200);
    let body = response.text();

    assert!(
        !body.contains("SSH Host Key Verified"),
        "verify endpoint with mismatch flag must NOT render the green \
         \"SSH Host Key Verified\" fragment. Body: {body}"
    );
    // The stored-mismatch fragment carries either "MISMATCH" or
    // "Mismatch" in its label/title; both are acceptable. We assert on
    // the case-insensitive substring so the test does not break on
    // benign template polish.
    let body_lower = body.to_lowercase();
    assert!(
        body_lower.contains("mismatch") || body_lower.contains("changed"),
        "verify endpoint with mismatch flag must surface a clear \
         mismatch / changed warning. Body: {body}"
    );
}

/// Test C -- no key stored -> dedicated no-key fragment.
///
/// An SSH asset whose `connection_config.ssh_host_key` is absent
/// MUST surface the no-key fragment, not the green one and not the
/// amber unverified fallback. The no-key fragment carries the
/// "Fetch Host Key" CTA pointing to `/assets/manage/{uuid}/fetch-host-key`.
#[tokio::test]
async fn case_c_verify_returns_no_key_when_no_key_stored() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("issue34_kk_c_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let asset = create_test_ssh_asset(&mut conn, &unique_name("issue34_kk_c_asset")).await;
    let asset_uuid = asset.asset.uuid;
    // create_test_ssh_asset already inserts an empty connection_config
    // (`{}`), so no extra setup is needed: ssh_host_key is absent.

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let response = app
        .server
        .get(&format!("/assets/{}/verify-host-key", asset_uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .add_header(
            axum::http::header::HeaderName::from_static("hx-request"),
            "true",
        )
        .await;

    assert_status(&response, 200);
    let body = response.text();

    assert!(
        body.contains("No Host Key Stored"),
        "verify endpoint with no stored key must render the no-key \
         fragment (\"No Host Key Stored\"). Body: {body}"
    );
    assert!(
        !body.contains("SSH Host Key Verified"),
        "verify endpoint with no stored key must NOT render the green \
         fragment. Body: {body}"
    );
    assert!(
        !body.contains("Could not verify"),
        "verify endpoint with no stored key must NOT render the amber \
         unverified fallback (the no-key fragment is the right \
         answer). Body: {body}"
    );
}

/// Test D -- connect_ssh refuses when no host key is pinned.
///
/// Pre-issue #34, `connect_ssh` passed `expected_host_key = None` to
/// the proxy when the asset had no pinned key, opening a TOFU window
/// indefinitely. The Lot 3 pre-flight gate now refuses categorically.
/// We assert the refusal is HTMX-friendly (200 + error in body) AND
/// that no `proxy_sessions` row is created.
#[tokio::test]
async fn case_d_connect_refuses_when_no_pinned_key() {
    use vauban_web::schema::proxy_sessions::dsl as ps;

    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("issue34_kk_d_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let user_name = unique_name("issue34_kk_d_user");
    let user_id = create_simple_user(&mut conn, &user_name).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;

    // Grant the user explicit SSH access on the asset so the pre-
    // flight gate is the ONLY remaining refusal reason. The pre-
    // flight runs AFTER the access-rule check (least-info-leak: a
    // user without access hears "No access rule" first), so the test
    // must establish access before it can observe the pre-flight.
    let ug = create_test_vauban_group(&mut conn, &unique_name("issue34_kk_d_ug")).await;
    add_user_to_vauban_group(&mut conn, user_id, &ug).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("issue34_kk_d_ag")).await;
    let asset_id =
        create_test_asset_in_group(&mut conn, &unique_name("issue34_kk_d_asset"), admin_id, &ag)
            .await;
    let asset_uuid = get_asset_uuid(&mut conn, asset_id).await;
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
    // No host key configured -- this is the regression scenario.

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
    // The HTMX-flavoured refusal returns 200 + an `HX-Trigger` header
    // carrying a `showToast` payload (see `htmx_error_response` in
    // `vauban-web/src/handlers/web/ssh.rs`). The user-visible message
    // therefore lives in the header, not the body.
    let trigger = response
        .headers()
        .get("HX-Trigger")
        .map(|v| v.to_str().unwrap_or("").to_string())
        .unwrap_or_default();
    let body = response.text();
    assert!(
        status < 500,
        "connect with no pinned key must NOT 5xx: the pre-flight gate \
         is supposed to refuse with a clear HTMX-friendly response. \
         Status: {status}, body: {body}, trigger: {trigger}"
    );
    assert!(
        trigger.contains("No SSH host key pinned"),
        "connect with no pinned key must surface the explicit \
         refusal \"No SSH host key pinned\" via the HX-Trigger \
         showToast payload. This is the issue #34 strict-pin gate. \
         Status: {status}, trigger: {trigger}, body: {body}"
    );

    let row_count: i64 = unwrap_ok!(
        ps::proxy_sessions
            .filter(ps::user_id.eq(user_id))
            .filter(ps::asset_id.eq(asset_id))
            .count()
            .get_result(&mut conn)
            .await
    );
    assert_eq!(
        row_count, 0,
        "connect with no pinned key must NOT create any proxy_sessions \
         row. Found {row_count} row(s). The pre-flight gate must \
         refuse BEFORE any DB insert."
    );
}

/// Test E -- connect_ssh refuses when the mismatch flag is set.
///
/// Same goal as Test D but the trigger is `ssh_host_key_mismatch =
/// true` rather than missing key. The user-visible message
/// explicitly mentions the previous mismatch so operators understand
/// why their connection is blocked and what to fix
/// (`/assets/manage/{uuid}/fetch-host-key`).
#[tokio::test]
async fn case_e_connect_refuses_when_mismatch_flag_set() {
    use vauban_web::schema::proxy_sessions::dsl as ps;

    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("issue34_kk_e_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let user_name = unique_name("issue34_kk_e_user");
    let user_id = create_simple_user(&mut conn, &user_name).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;

    // Grant access (see case_d for the rationale).
    let ug = create_test_vauban_group(&mut conn, &unique_name("issue34_kk_e_ug")).await;
    add_user_to_vauban_group(&mut conn, user_id, &ug).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("issue34_kk_e_ag")).await;
    let asset_id =
        create_test_asset_in_group(&mut conn, &unique_name("issue34_kk_e_asset"), admin_id, &ag)
            .await;
    let asset_uuid = get_asset_uuid(&mut conn, asset_id).await;
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
    set_connection_config(
        &mut conn,
        asset_id,
        json!({
            "ssh_host_key": PINNED_KEY_OPENSSH,
            "ssh_host_key_fingerprint": PINNED_KEY_FP,
            "ssh_host_key_mismatch": true,
        }),
    )
    .await;

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
    let trigger = response
        .headers()
        .get("HX-Trigger")
        .map(|v| v.to_str().unwrap_or("").to_string())
        .unwrap_or_default();
    let body = response.text();
    assert!(
        status < 500,
        "connect with mismatch flag must NOT 5xx; the pre-flight gate \
         is HTMX-friendly. Status: {status}, body: {body}, trigger: \
         {trigger}"
    );
    assert!(
        trigger.contains("SSH host key mismatch detected on previous connection"),
        "connect with mismatch flag must surface the explicit MITM \
         warning via HX-Trigger showToast. This is the issue #34 \
         strict-pin gate. Status: {status}, trigger: {trigger}, body: \
         {body}"
    );

    let row_count: i64 = unwrap_ok!(
        ps::proxy_sessions
            .filter(ps::user_id.eq(user_id))
            .filter(ps::asset_id.eq(asset_id))
            .count()
            .get_result(&mut conn)
            .await
    );
    assert_eq!(
        row_count, 0,
        "connect with mismatch flag must NOT create any proxy_sessions \
         row. Found {row_count} row(s)."
    );
}
