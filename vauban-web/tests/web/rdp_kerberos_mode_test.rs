//! RDP Kerberos / Restricted Admin (phase A) -- web E2E coverage for the
//! per-asset NLA auth mode.
//!
//! The asset create/edit forms expose a `rdp_auth_mode` dropdown
//! (`ntlm` | `kerberos_restricted_admin`) persisted in
//! `connection_config.rdp_auth_mode` and carried by `connect_rdp` into
//! `RdpSessionOpenRequest.rdp_auth_mode` (the RDP proxy then drives its
//! CredSSP leg accordingly, fail-closed, no NTLM fallback in Kerberos
//! mode).
//!
//! Test matrix:
//!
//! **UI rendering**
//! - create form renders the dropdown, guarded by `assetType === 'rdp'`
//! - edit form renders the dropdown with the stored mode pre-selected
//!
//! **Server-side enforcement (create)**
//! - `kerberos_restricted_admin` + FQDN hostname persists the mode
//! - `kerberos_restricted_admin` + IP-literal hostname is REFUSED
//!   (Kerberos needs an SPN `TERMSRV/<fqdn>`; fail-closed, no row)
//! - absent `rdp_auth_mode` defaults to `ntlm`
//! - tampered garbage `rdp_auth_mode` normalises to `ntlm` (closed set)
//!
//! **Server-side enforcement (edit)**
//! - switching `ntlm` -> `kerberos_restricted_admin` persists
//! - blank `rdp_auth_mode` on edit keeps the stored mode (option A)
//! - `kerberos_restricted_admin` + IP-literal hostname is REFUSED on
//!   edit too (no partial persist)
//!
//! **connect_rdp source pins**
//! - the handler reads `connection_config.rdp_auth_mode` through the
//!   closed-set parser and carries it into `RdpSessionOpenRequest`.

use crate::common::{TestApp, assertions::*, test_db, unwrap_ok};
use crate::fixtures::{create_admin_user, unique_name};
use axum::http::header::COOKIE;
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::Value as Json;
use serial_test::serial;
use uuid::Uuid;
use vauban_web::models::asset::{Asset, AssetType, NewAsset};
use vauban_web::schema::assets;

// =============================================================================
// Helpers
// =============================================================================

/// Cookie header expected by the create/edit handlers: `access_token`
/// for auth AND `__vauban_csrf` for the double-submit CSRF check.
fn auth_csrf_cookie(token: &str, csrf: &str) -> String {
    format!("access_token={}; __vauban_csrf={}", token, csrf)
}

async fn read_asset_by_hostname(conn: &mut AsyncPgConnection, hostname: &str) -> Option<Asset> {
    assets::table
        .filter(assets::hostname.eq(hostname))
        .first(conn)
        .await
        .ok()
}

async fn read_asset_by_uuid(conn: &mut AsyncPgConnection, asset_uuid: Uuid) -> Option<Asset> {
    assets::table
        .filter(assets::uuid.eq(asset_uuid))
        .first(conn)
        .await
        .ok()
}

/// Insert an RDP asset directly with a custom `connection_config`.
async fn insert_rdp_asset_with_config(
    conn: &mut AsyncPgConnection,
    name: &str,
    hostname: &str,
    connection_config: Json,
) -> Asset {
    let new_asset = NewAsset {
        uuid: Uuid::new_v4(),
        name: name.to_string(),
        hostname: hostname.to_string(),
        port: 3389,
        asset_type: AssetType::Rdp,
        status: "online".to_string(),
        description: None,
        connection_config,
        created_by_id: None,
        updated_by_id: None,
        connection_username: "Administrator".to_string(),
    };
    unwrap_ok!(
        diesel::insert_into(assets::table)
            .values(&new_asset)
            .get_result(conn)
            .await
    )
}

fn stored_auth_mode(asset: &Asset) -> Option<&str> {
    asset
        .connection_config
        .get("rdp_auth_mode")
        .and_then(|v| v.as_str())
}

// =============================================================================
// UI rendering
// =============================================================================

/// The create form must render the `rdp_auth_mode` dropdown with both
/// canonical options, wrapped in the `assetType === 'rdp'` Alpine guard.
#[tokio::test]
#[serial]
async fn test_create_form_renders_rdp_auth_mode_dropdown() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("krb_ui_create");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let response = app
        .server
        .get("/assets/manage/new")
        .add_header(COOKIE, format!("access_token={}", admin.token))
        .await;

    assert_status(&response, 200);
    let body = response.text();

    assert!(
        body.contains("name=\"rdp_auth_mode\""),
        "rdp_auth_mode dropdown must be present in the create form"
    );
    assert!(
        body.contains("value=\"ntlm\"") && body.contains("value=\"kerberos_restricted_admin\""),
        "both canonical auth modes must be offered"
    );

    let select_index = body
        .find("name=\"rdp_auth_mode\"")
        .expect("dropdown must be in the markup");
    let preceding = &body[..select_index];
    let nearest_div = preceding
        .rfind("<div ")
        .expect("dropdown must live inside a <div>");
    let guard_window = &body[nearest_div..select_index];
    assert!(
        guard_window.contains("x-show=\"assetType === 'rdp'\""),
        "the dropdown's enclosing div must carry the assetType === 'rdp' \
         guard so SSH/IACS never show it; got window:\n{}",
        guard_window
    );

    test_db::cleanup(&mut conn).await;
}

/// The edit form must render the dropdown and expose the stored mode to
/// the Alpine `x-model` binding.
#[tokio::test]
#[serial]
async fn test_edit_form_renders_stored_auth_mode() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("krb_ui_edit");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let hostname = format!("{}.krb-ui.test", unique_name("host"));
    let asset = insert_rdp_asset_with_config(
        &mut conn,
        &unique_name("krb-ui-edit"),
        &hostname,
        serde_json::json!({
            "username": "Administrator",
            "rdp_auth_mode": "kerberos_restricted_admin",
        }),
    )
    .await;

    let response = app
        .server
        .get(&format!("/assets/manage/{}/edit", asset.uuid))
        .add_header(COOKIE, format!("access_token={}", admin.token))
        .await;

    assert_status(&response, 200);
    let body = response.text();

    assert!(
        body.contains("name=\"rdp_auth_mode\""),
        "rdp_auth_mode dropdown must be present in the edit form"
    );
    assert!(
        body.contains("rdpAuthMode: 'kerberos_restricted_admin'"),
        "the stored Kerberos mode must seed the Alpine x-model binding"
    );

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// Server-side enforcement -- create
// =============================================================================

/// Kerberos mode + FQDN hostname: the mode is persisted verbatim.
#[tokio::test]
#[serial]
async fn test_create_rdp_kerberos_with_fqdn_persists_mode() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("krb_create_ok");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let csrf = app.generate_csrf_token();

    let asset_name = unique_name("krb-asset-ok");
    let hostname = format!("{}.corp.example.com", unique_name("host"));

    let response = app
        .server
        .post("/assets/manage/new")
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", &asset_name),
            ("hostname", &hostname),
            ("port", "3389"),
            ("asset_type", "rdp"),
            ("status", "online"),
            ("ssh_username", "Administrator"),
            ("ssh_password", "Win-Pwd-2026!"),
            ("rdp_domain", "CORP"),
            ("rdp_auth_mode", "kerberos_restricted_admin"),
        ])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "Kerberos + FQDN create must succeed, got {}",
        status
    );

    let asset = read_asset_by_hostname(&mut conn, &hostname)
        .await
        .expect("Kerberos RDP asset must be persisted");
    assert_eq!(
        stored_auth_mode(&asset),
        Some("kerberos_restricted_admin"),
        "the Kerberos mode must be persisted, got config: {}",
        asset.connection_config
    );

    test_db::cleanup(&mut conn).await;
}

/// Kerberos mode + IP-literal hostname: refused fail-closed (no SPN
/// without a DNS name), and NO row is persisted.
#[tokio::test]
#[serial]
async fn test_create_rdp_kerberos_with_ip_hostname_is_refused() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("krb_create_ip");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let csrf = app.generate_csrf_token();

    let asset_name = unique_name("krb-asset-ip");
    let hostname = "192.0.2.10";

    let response = app
        .server
        .post("/assets/manage/new")
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", &asset_name),
            ("hostname", hostname),
            ("port", "3389"),
            ("asset_type", "rdp"),
            ("status", "online"),
            ("ssh_username", "Administrator"),
            ("ssh_password", "Win-Pwd-2026!"),
            ("rdp_auth_mode", "kerberos_restricted_admin"),
        ])
        .await;

    // The handler flashes an error and redirects back to the create form.
    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "refusal is a flash-redirect, got {}",
        status
    );

    let count: i64 = unwrap_ok!(
        assets::table
            .filter(assets::name.eq(&asset_name))
            .count()
            .get_result(&mut conn)
            .await
    );
    assert_eq!(
        count, 0,
        "Kerberos + IP-literal hostname must NOT persist any asset row"
    );

    test_db::cleanup(&mut conn).await;
}

/// Absent `rdp_auth_mode` defaults to `ntlm` (historic behavior).
#[tokio::test]
#[serial]
async fn test_create_rdp_without_auth_mode_defaults_to_ntlm() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("krb_create_dflt");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let csrf = app.generate_csrf_token();

    let asset_name = unique_name("krb-asset-dflt");
    let hostname = format!("{}.dflt.test", unique_name("host"));

    let response = app
        .server
        .post("/assets/manage/new")
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", &asset_name),
            ("hostname", &hostname),
            ("port", "3389"),
            ("asset_type", "rdp"),
            ("status", "online"),
            ("ssh_username", "Administrator"),
            ("ssh_password", "Win-Pwd-2026!"),
        ])
        .await;

    let status = response.status_code().as_u16();
    assert!(status == 302 || status == 303, "create failed: {}", status);

    let asset = read_asset_by_hostname(&mut conn, &hostname)
        .await
        .expect("asset must be persisted");
    assert_eq!(
        stored_auth_mode(&asset),
        Some("ntlm"),
        "absent rdp_auth_mode must default to ntlm, got config: {}",
        asset.connection_config
    );

    test_db::cleanup(&mut conn).await;
}

/// A tampered request smuggling an arbitrary `rdp_auth_mode` string is
/// normalised to `ntlm` (closed set -- never an attacker-chosen value).
#[tokio::test]
#[serial]
async fn test_create_rdp_with_garbage_auth_mode_normalises_to_ntlm() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("krb_create_junk");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let csrf = app.generate_csrf_token();

    let asset_name = unique_name("krb-asset-junk");
    let hostname = format!("{}.junk.test", unique_name("host"));

    let response = app
        .server
        .post("/assets/manage/new")
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", &asset_name),
            ("hostname", &hostname),
            ("port", "3389"),
            ("asset_type", "rdp"),
            ("status", "online"),
            ("ssh_username", "Administrator"),
            ("ssh_password", "Win-Pwd-2026!"),
            ("rdp_auth_mode", "kerberos'; DROP TABLE assets; --"),
        ])
        .await;

    let status = response.status_code().as_u16();
    assert!(status == 302 || status == 303, "create failed: {}", status);

    let asset = read_asset_by_hostname(&mut conn, &hostname)
        .await
        .expect("asset must be persisted");
    assert_eq!(
        stored_auth_mode(&asset),
        Some("ntlm"),
        "a tampered rdp_auth_mode must collapse to ntlm, got config: {}",
        asset.connection_config
    );

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// Server-side enforcement -- edit
// =============================================================================

/// Switching a stored `ntlm` row to Kerberos (with an FQDN) persists.
#[tokio::test]
#[serial]
async fn test_edit_rdp_switch_to_kerberos_persists() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("krb_edit_sw");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let csrf = app.generate_csrf_token();

    let hostname = format!("{}.krb-edit.example.com", unique_name("host"));
    let asset = insert_rdp_asset_with_config(
        &mut conn,
        &unique_name("krb-edit-sw"),
        &hostname,
        serde_json::json!({
            "username": "Administrator",
            "password": "stored-pwd",
            "rdp_auth_mode": "ntlm",
        }),
    )
    .await;

    let response = app
        .server
        .post(&format!("/assets/manage/{}/edit", asset.uuid))
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", &asset.name),
            ("hostname", &hostname),
            ("port", "3389"),
            ("status", "online"),
            ("ssh_username", "Administrator"),
            ("ssh_password", ""),
            ("rdp_auth_mode", "kerberos_restricted_admin"),
        ])
        .await;

    let status = response.status_code().as_u16();
    assert!(status == 302 || status == 303, "edit failed: {}", status);

    let after = read_asset_by_uuid(&mut conn, asset.uuid).await.unwrap();
    assert_eq!(
        stored_auth_mode(&after),
        Some("kerberos_restricted_admin"),
        "edit must persist the Kerberos mode, got config: {}",
        after.connection_config
    );

    test_db::cleanup(&mut conn).await;
}

/// A blank `rdp_auth_mode` on edit keeps the stored mode (option A --
/// same semantics as the other credential fields).
#[tokio::test]
#[serial]
async fn test_edit_rdp_blank_auth_mode_keeps_stored_mode() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("krb_edit_keep");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let csrf = app.generate_csrf_token();

    let hostname = format!("{}.krb-keep.example.com", unique_name("host"));
    let asset = insert_rdp_asset_with_config(
        &mut conn,
        &unique_name("krb-edit-keep"),
        &hostname,
        serde_json::json!({
            "username": "Administrator",
            "rdp_auth_mode": "kerberos_restricted_admin",
        }),
    )
    .await;

    let response = app
        .server
        .post(&format!("/assets/manage/{}/edit", asset.uuid))
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", &asset.name),
            ("hostname", &hostname),
            ("port", "3389"),
            ("status", "maintenance"),
            ("ssh_username", "Administrator"),
            ("ssh_password", ""),
            ("rdp_auth_mode", ""),
        ])
        .await;

    let status = response.status_code().as_u16();
    assert!(status == 302 || status == 303, "edit failed: {}", status);

    let after = read_asset_by_uuid(&mut conn, asset.uuid).await.unwrap();
    assert_eq!(
        stored_auth_mode(&after),
        Some("kerberos_restricted_admin"),
        "blank rdp_auth_mode must keep the stored mode, got config: {}",
        after.connection_config
    );

    test_db::cleanup(&mut conn).await;
}

/// Kerberos mode + IP-literal hostname is refused on EDIT too: neither
/// the hostname nor the mode may land (no partial persist).
#[tokio::test]
#[serial]
async fn test_edit_rdp_kerberos_with_ip_hostname_is_refused() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("krb_edit_ip");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let csrf = app.generate_csrf_token();

    let hostname = format!("{}.krb-ip.example.com", unique_name("host"));
    let asset = insert_rdp_asset_with_config(
        &mut conn,
        &unique_name("krb-edit-ip"),
        &hostname,
        serde_json::json!({
            "username": "Administrator",
            "rdp_auth_mode": "ntlm",
        }),
    )
    .await;

    let response = app
        .server
        .post(&format!("/assets/manage/{}/edit", asset.uuid))
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", &asset.name),
            ("hostname", "198.51.100.7"),
            ("port", "3389"),
            ("status", "online"),
            ("ssh_username", "Administrator"),
            ("ssh_password", ""),
            ("rdp_auth_mode", "kerberos_restricted_admin"),
        ])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "refusal is a flash-redirect, got {}",
        status
    );

    let after = read_asset_by_uuid(&mut conn, asset.uuid).await.unwrap();
    assert_eq!(
        after.hostname, hostname,
        "the IP-literal hostname must NOT be persisted"
    );
    assert_eq!(
        stored_auth_mode(&after),
        Some("ntlm"),
        "the Kerberos mode must NOT be persisted alongside a refused \
         hostname, got config: {}",
        after.connection_config
    );

    test_db::cleanup(&mut conn).await;
}

// =============================================================================
// connect_rdp source pins
// =============================================================================

/// `connect_rdp` must read the stored mode through the closed-set parser
/// and carry it into `RdpSessionOpenRequest` (the proxy enforces the
/// fail-closed no-NTLM-fallback posture on its side).
#[test]
fn test_connect_rdp_threads_auth_mode_into_open_request() {
    let source = include_str!("../../src/handlers/web/rdp.rs");

    assert!(
        source.contains("shared::messages::RdpAuthMode::parse("),
        "connect_rdp must parse connection_config.rdp_auth_mode through \
         the closed-set RdpAuthMode parser"
    );
    let request_idx = source
        .find("RdpSessionOpenRequest {")
        .expect("connect_rdp must build a RdpSessionOpenRequest");
    let request_body = &source[request_idx..request_idx + 700];
    assert!(
        request_body.contains("rdp_auth_mode"),
        "RdpSessionOpenRequest must carry rdp_auth_mode"
    );
}

/// The IPC client must forward the mode verbatim into the
/// `Message::RdpSessionOpen` wire message.
#[test]
fn test_ipc_client_forwards_auth_mode_on_the_wire() {
    let source = include_str!("../../src/ipc/proxy_rdp.rs");
    assert!(
        source.contains("rdp_auth_mode: request.rdp_auth_mode"),
        "RdpProxyClient::open_session must forward rdp_auth_mode into \
         Message::RdpSessionOpen"
    );
}
