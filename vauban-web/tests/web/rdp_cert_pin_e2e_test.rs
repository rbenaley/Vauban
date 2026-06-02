//! VAU-001 -- end-to-end coverage for the RDP server-certificate
//! verification and connect-time pre-flight gates. Strict mirror of
//! `ssh_host_key_e2e_test.rs`.
//!
//! These tests bring up a real `TestApp` (Axum router, DB, JWT auth)
//! and exercise the actual HTTP surface with `rdp_proxy = None` (no
//! real proxy at the other end of the IPC). The five regressions they
//! pin:
//!
//! 1. **Silent green when the proxy is unavailable** -- `verify_rdp_
//!    server_cert` must render the amber "Could not verify" fragment,
//!    NEVER the green one, when the proxy cannot be reached (Test A).
//! 2. **Mismatch flag must persist across reloads** -- once
//!    `rdp_server_cert_mismatch = true`, the verify endpoint stays RED
//!    (Test B).
//! 3. **No-cert path** -- an RDP asset without a pinned SPKI surfaces
//!    the dedicated no-key fragment (Test C).
//! 4. **`connect_rdp` must refuse when no cert is pinned** (Test D).
//! 5. **`connect_rdp` must refuse when the mismatch flag is set**
//!    (Test E).

use crate::common::{TestApp, assertions::assert_status, unwrap_ok};
use crate::fixtures::{
    add_user_to_vauban_group, create_simple_admin_user, create_simple_user,
    create_test_access_rule_with_constraints, create_test_asset_group,
    create_test_asset_in_group_with_type, create_test_rdp_asset, create_test_vauban_group,
    get_asset_uuid, unique_name,
};
use axum::http::header::COOKIE;
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::json;
use uuid::Uuid;
use vauban_web::models::asset::AssetType;

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

const PINNED_SPKI_B64: &str = "TUlJQklqQU5CZ2txaGtpRzl3MEJ-VkFVLTAwMS10ZXN0LXNwa2k=";
const PINNED_CERT_FP: &str = "SHA256:vauban-vau001-pinned-cert-fingerprint";

/// Test A -- proxy unavailable -> amber "Could not verify" fragment.
#[tokio::test]
async fn case_a_verify_returns_amber_when_proxy_unavailable() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("vau001_a_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let asset = create_test_rdp_asset(&mut conn, &unique_name("vau001_a_asset")).await;
    let asset_id = asset.asset.id;
    let asset_uuid = asset.asset.uuid;
    set_connection_config(
        &mut conn,
        asset_id,
        json!({
            "rdp_server_cert_spki": PINNED_SPKI_B64,
            "rdp_server_cert_fingerprint": PINNED_CERT_FP,
            "rdp_server_cert_mismatch": false,
        }),
    )
    .await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let response = app
        .server
        .get(&format!("/assets/{}/verify-rdp-cert", asset_uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .add_header(
            axum::http::header::HeaderName::from_static("hx-request"),
            "true",
        )
        .await;

    assert_status(&response, 200);
    let body = response.text();

    assert!(
        body.contains("Could not verify server certificate"),
        "verify endpoint with proxy=None must render the amber \"Could \
         not verify\" fragment. This is the VAU-001 silent-green \
         regression. Body: {body}"
    );
    assert!(
        !body.contains("RDP Server Certificate Verified"),
        "verify endpoint with proxy=None must NOT render the green \
         \"RDP Server Certificate Verified\" fragment. Body: {body}"
    );
}

/// Test B -- mismatch flag in DB -> RED stored-mismatch fragment.
#[tokio::test]
async fn case_b_verify_returns_red_when_mismatch_flag_set() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("vau001_b_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let asset = create_test_rdp_asset(&mut conn, &unique_name("vau001_b_asset")).await;
    let asset_id = asset.asset.id;
    let asset_uuid = asset.asset.uuid;
    set_connection_config(
        &mut conn,
        asset_id,
        json!({
            "rdp_server_cert_spki": PINNED_SPKI_B64,
            "rdp_server_cert_fingerprint": PINNED_CERT_FP,
            "rdp_server_cert_mismatch": true,
        }),
    )
    .await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let response = app
        .server
        .get(&format!("/assets/{}/verify-rdp-cert", asset_uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .add_header(
            axum::http::header::HeaderName::from_static("hx-request"),
            "true",
        )
        .await;

    assert_status(&response, 200);
    let body = response.text();

    assert!(
        !body.contains("RDP Server Certificate Verified"),
        "verify endpoint with mismatch flag must NOT render the green \
         fragment. Body: {body}"
    );
    let body_lower = body.to_lowercase();
    assert!(
        body_lower.contains("mismatch") || body_lower.contains("changed"),
        "verify endpoint with mismatch flag must surface a clear \
         mismatch / changed warning. Body: {body}"
    );
}

/// Test C -- no cert stored -> dedicated no-key fragment.
#[tokio::test]
async fn case_c_verify_returns_no_key_when_no_cert_stored() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("vau001_c_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;

    let asset = create_test_rdp_asset(&mut conn, &unique_name("vau001_c_asset")).await;
    let asset_uuid = asset.asset.uuid;
    // create_test_rdp_asset inserts an empty connection_config, so the
    // SPKI is absent.

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let response = app
        .server
        .get(&format!("/assets/{}/verify-rdp-cert", asset_uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .add_header(
            axum::http::header::HeaderName::from_static("hx-request"),
            "true",
        )
        .await;

    assert_status(&response, 200);
    let body = response.text();

    assert!(
        body.contains("No Server Certificate Pinned"),
        "verify endpoint with no stored cert must render the no-key \
         fragment (\"No Server Certificate Pinned\"). Body: {body}"
    );
    assert!(
        !body.contains("RDP Server Certificate Verified"),
        "verify endpoint with no stored cert must NOT render the green \
         fragment. Body: {body}"
    );
    assert!(
        !body.contains("Could not verify server certificate"),
        "verify endpoint with no stored cert must NOT render the amber \
         fallback (the no-key fragment is the right answer). Body: {body}"
    );
}

/// Test D -- connect_rdp refuses when no server certificate is pinned.
#[tokio::test]
async fn case_d_connect_refuses_when_no_pinned_cert() {
    use vauban_web::schema::proxy_sessions::dsl as ps;

    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("vau001_d_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let user_name = unique_name("vau001_d_user");
    let user_id = create_simple_user(&mut conn, &user_name).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;

    let ug = create_test_vauban_group(&mut conn, &unique_name("vau001_d_ug")).await;
    add_user_to_vauban_group(&mut conn, user_id, &ug).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("vau001_d_ag")).await;
    let asset_id = create_test_asset_in_group_with_type(
        &mut conn,
        &unique_name("vau001_d_asset"),
        admin_id,
        &ag,
        AssetType::Rdp,
    )
    .await;
    let asset_uuid = get_asset_uuid(&mut conn, asset_id).await;
    create_test_access_rule_with_constraints(
        &mut conn,
        &ug,
        &ag,
        &["rdp"],
        false,
        false,
        Some(600),
    )
    .await;
    // No server certificate configured -- this is the regression scenario.

    let token = app
        .generate_test_token(&user_uuid.to_string(), &user_name, false, false)
        .await;
    let csrf = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!("/assets/{}/connect-rdp", asset_uuid))
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
        "connect with no pinned cert must NOT 5xx. Status: {status}, \
         body: {body}, trigger: {trigger}"
    );
    assert!(
        trigger.contains("No RDP server certificate pinned for this asset"),
        "connect with no pinned cert must surface the explicit refusal \
         via the HX-Trigger showToast payload. Status: {status}, \
         trigger: {trigger}, body: {body}"
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
        "connect with no pinned cert must NOT create any proxy_sessions \
         row. Found {row_count} row(s)."
    );
}

/// Test E -- connect_rdp refuses when the mismatch flag is set.
#[tokio::test]
async fn case_e_connect_refuses_when_mismatch_flag_set() {
    use vauban_web::schema::proxy_sessions::dsl as ps;

    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("vau001_e_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let user_name = unique_name("vau001_e_user");
    let user_id = create_simple_user(&mut conn, &user_name).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;

    let ug = create_test_vauban_group(&mut conn, &unique_name("vau001_e_ug")).await;
    add_user_to_vauban_group(&mut conn, user_id, &ug).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("vau001_e_ag")).await;
    let asset_id = create_test_asset_in_group_with_type(
        &mut conn,
        &unique_name("vau001_e_asset"),
        admin_id,
        &ag,
        AssetType::Rdp,
    )
    .await;
    let asset_uuid = get_asset_uuid(&mut conn, asset_id).await;
    create_test_access_rule_with_constraints(
        &mut conn,
        &ug,
        &ag,
        &["rdp"],
        false,
        false,
        Some(600),
    )
    .await;
    set_connection_config(
        &mut conn,
        asset_id,
        json!({
            "rdp_server_cert_spki": PINNED_SPKI_B64,
            "rdp_server_cert_fingerprint": PINNED_CERT_FP,
            "rdp_server_cert_mismatch": true,
        }),
    )
    .await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &user_name, false, false)
        .await;
    let csrf = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!("/assets/{}/connect-rdp", asset_uuid))
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
        "connect with mismatch flag must NOT 5xx. Status: {status}, \
         body: {body}, trigger: {trigger}"
    );
    assert!(
        trigger.contains("RDP server certificate mismatch detected on previous connection"),
        "connect with mismatch flag must surface the explicit MITM \
         warning via HX-Trigger showToast. Status: {status}, trigger: \
         {trigger}, body: {body}"
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
