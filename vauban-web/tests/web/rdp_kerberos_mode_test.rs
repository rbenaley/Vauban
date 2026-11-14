//! RDP Kerberos / Restricted Admin (phase A) -- web E2E coverage for the
//! per-asset NLA auth mode.
//!
//! The asset create/edit forms expose a `rdp_auth_mode` dropdown
//! (`ntlm` | `kerberos` | `kerberos_restricted_admin`) persisted in
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
//! - an unknown `rdp_auth_mode` is REFUSED, never stored as `ntlm`
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

/// The create form must render the `rdp_auth_mode` dropdown with the three
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
        body.contains("value=\"ntlm\"")
            && body.contains("value=\"kerberos_restricted_admin\"")
            && body.contains("value=\"kerberos\""),
        "the three canonical auth modes must be offered"
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
            ("rdp_domain", "corp.example.com"),
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

/// An unknown `rdp_auth_mode` is refused and NO row is persisted. It is
/// not folded into `ntlm`: a typo in `kerberos` must not silently yield
/// an NTLM asset.
#[tokio::test]
#[serial]
async fn attack_create_rdp_with_unknown_auth_mode_is_rejected() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("krb_create_junk");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    for mode in [
        "kerberos'; DROP TABLE assets; --",
        "Kerberos",
        "kerbeross",
        "kerberos-restricted-admin",
    ] {
        let csrf = app.generate_csrf_token();
        let asset_name = unique_name("krb-asset-junk");
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
                ("rdp_domain", "corp.example.com"),
                ("rdp_auth_mode", mode),
            ])
            .await;

        let status = response.status_code().as_u16();
        assert!(
            status == 302 || status == 303,
            "refusal is a flash-redirect, got {status}"
        );
        assert!(
            read_asset_by_hostname(&mut conn, &hostname).await.is_none(),
            "mode {mode:?} must NOT create an asset"
        );
    }

    test_db::cleanup(&mut conn).await;
}

/// Same refusal on edit: the stored mode is kept.
#[tokio::test]
#[serial]
async fn attack_edit_rdp_with_unknown_auth_mode_is_rejected() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin =
        create_admin_user(&mut conn, &app.auth_service, &unique_name("krb_edit_junk")).await;

    let hostname = format!("{}.corp.example.com", unique_name("host"));
    let name = unique_name("krb-edit-junk");
    let asset = insert_rdp_asset_with_config(
        &mut conn,
        &name,
        &hostname,
        serde_json::json!({
            "username": "Administrator",
            "domain": "corp.example.com",
            "rdp_auth_mode": "kerberos",
        }),
    )
    .await;

    let csrf = app.generate_csrf_token();
    let response = app
        .server
        .post(&format!("/assets/manage/{}/edit", asset.uuid))
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", name.as_str()),
            ("hostname", hostname.as_str()),
            ("port", "3389"),
            ("status", "online"),
            ("rdp_auth_mode", "ntlmv2"),
        ])
        .await;
    let status = response.status_code().as_u16();
    assert!(status == 302 || status == 303, "got {status}");

    let after = read_asset_by_uuid(&mut conn, asset.uuid)
        .await
        .expect("row");
    assert_eq!(stored_auth_mode(&after), Some("kerberos"));

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
            ("rdp_domain", "corp.example.com"),
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
            "domain": "corp.example.com",
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
// Server-side enforcement -- Kerberos domain (realm)
// =============================================================================
//
// `sspi` upper-cases the asset domain into the Kerberos realm, unchecked:
// no domain means an EMPTY realm, and a NetBIOS short name is sent as-is.
// A Kerberos asset must therefore carry the DNS name of its domain.

fn stored_domain(asset: &Asset) -> Option<&str> {
    asset
        .connection_config
        .get("domain")
        .and_then(|v| v.as_str())
}

/// POST the create form for a Kerberos RDP asset with the given domain
/// field (`None` = field absent). Returns the hostname used.
async fn post_kerberos_create(
    app: &TestApp,
    token: &str,
    label: &str,
    domain: Option<&str>,
) -> (String, u16) {
    let csrf = app.generate_csrf_token();
    let asset_name = unique_name(label);
    let hostname = format!("{}.corp.example.com", unique_name("host"));
    let mut form: Vec<(&str, &str)> = vec![
        ("csrf_token", csrf.as_str()),
        ("name", &asset_name),
        ("hostname", &hostname),
        ("port", "3389"),
        ("asset_type", "rdp"),
        ("status", "online"),
        ("ssh_username", "Administrator"),
        ("ssh_password", "Win-Pwd-2026!"),
        ("rdp_auth_mode", "kerberos_restricted_admin"),
    ];
    if let Some(d) = domain {
        form.push(("rdp_domain", d));
    }
    let status = app
        .server
        .post("/assets/manage/new")
        .add_header(COOKIE, auth_csrf_cookie(token, &csrf))
        .form(&form)
        .await
        .status_code()
        .as_u16();
    (hostname, status)
}

/// Kerberos mode without any domain: refused, and NO row is persisted.
#[tokio::test]
#[serial]
async fn attack_create_rdp_kerberos_without_domain_is_rejected() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("krb_nodom")).await;

    for domain in [None, Some(""), Some("   ")] {
        let (hostname, status) = post_kerberos_create(app, &admin.token, "krb-nodom", domain).await;
        assert!(
            status == 302 || status == 303,
            "refusal is a flash-redirect, got {status} for {domain:?}"
        );
        assert!(
            read_asset_by_hostname(&mut conn, &hostname).await.is_none(),
            "a Kerberos asset without a domain must NOT be persisted ({domain:?})"
        );
    }

    test_db::cleanup(&mut conn).await;
}

/// Kerberos mode with a NetBIOS short name, or with a value carrying a
/// principal separator: refused, and NO row is persisted.
#[tokio::test]
#[serial]
async fn attack_create_rdp_kerberos_with_non_dns_domain_is_rejected() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("krb_netb")).await;

    for domain in [
        "CORP",
        "corp",
        "corp.example.com@evil.test",
        "corp.example.com/admin",
        "corp..example.com",
        "-corp.example.com",
    ] {
        let (hostname, status) =
            post_kerberos_create(app, &admin.token, "krb-netb", Some(domain)).await;
        assert!(
            status == 302 || status == 303,
            "refusal is a flash-redirect, got {status} for {domain:?}"
        );
        assert!(
            read_asset_by_hostname(&mut conn, &hostname).await.is_none(),
            "domain {domain:?} must NOT yield a Kerberos asset"
        );
    }

    test_db::cleanup(&mut conn).await;
}

/// Non-regression: the NTLM mode keeps accepting a NetBIOS domain, or
/// none at all. The realm rule is Kerberos-only.
#[tokio::test]
#[serial]
async fn test_create_rdp_ntlm_keeps_accepting_netbios_or_no_domain() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("ntlm_dom")).await;

    for domain in [Some("CORP"), None] {
        let csrf = app.generate_csrf_token();
        let asset_name = unique_name("ntlm-dom");
        let hostname = format!("{}.corp.example.com", unique_name("host"));
        let mut form: Vec<(&str, &str)> = vec![
            ("csrf_token", csrf.as_str()),
            ("name", &asset_name),
            ("hostname", &hostname),
            ("port", "3389"),
            ("asset_type", "rdp"),
            ("status", "online"),
            ("ssh_username", "Administrator"),
            ("ssh_password", "Win-Pwd-2026!"),
            ("rdp_auth_mode", "ntlm"),
        ];
        if let Some(d) = domain {
            form.push(("rdp_domain", d));
        }
        let status = app
            .server
            .post("/assets/manage/new")
            .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
            .form(&form)
            .await
            .status_code()
            .as_u16();
        assert!(status == 302 || status == 303, "got {status}");
        let asset = read_asset_by_hostname(&mut conn, &hostname)
            .await
            .expect("NTLM asset must be persisted");
        assert_eq!(stored_auth_mode(&asset), Some("ntlm"));
        assert_eq!(stored_domain(&asset), domain);
    }

    test_db::cleanup(&mut conn).await;
}

/// Clearing the domain of a stored Kerberos asset is refused: the mode
/// and the domain both stay as they were (no partial persist).
#[tokio::test]
#[serial]
async fn attack_edit_rdp_kerberos_clearing_domain_is_rejected() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("krb_clr")).await;
    let csrf = app.generate_csrf_token();

    let hostname = format!("{}.krb-clr.example.com", unique_name("host"));
    let asset = insert_rdp_asset_with_config(
        &mut conn,
        &unique_name("krb-edit-clr"),
        &hostname,
        serde_json::json!({
            "username": "Administrator",
            "domain": "corp.example.com",
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
            ("rdp_domain", ""),
            ("rdp_auth_mode", ""),
        ])
        .await;
    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "refusal is a flash-redirect, got {status}"
    );

    let after = read_asset_by_uuid(&mut conn, asset.uuid).await.unwrap();
    assert_eq!(stored_domain(&after), Some("corp.example.com"));
    assert_eq!(stored_auth_mode(&after), Some("kerberos_restricted_admin"));
    assert_eq!(after.status, "online", "nothing else may be persisted");

    test_db::cleanup(&mut conn).await;
}

/// Switching an NTLM asset to Kerberos while its stored domain is a
/// NetBIOS short name (form field absent = keep stored) is refused.
#[tokio::test]
#[serial]
async fn attack_edit_switch_to_kerberos_with_stored_netbios_domain_is_rejected() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("krb_swn")).await;
    let csrf = app.generate_csrf_token();

    let hostname = format!("{}.krb-swn.example.com", unique_name("host"));
    let asset = insert_rdp_asset_with_config(
        &mut conn,
        &unique_name("krb-edit-swn"),
        &hostname,
        serde_json::json!({
            "username": "Administrator",
            "domain": "CORP",
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
    assert!(
        status == 302 || status == 303,
        "refusal is a flash-redirect, got {status}"
    );

    let after = read_asset_by_uuid(&mut conn, asset.uuid).await.unwrap();
    assert_eq!(
        stored_auth_mode(&after),
        Some("ntlm"),
        "the Kerberos mode must NOT be persisted over a NetBIOS domain"
    );
    assert_eq!(stored_domain(&after), Some("CORP"));

    test_db::cleanup(&mut conn).await;
}

/// Source pin: create and update both go through the single RDP auth
/// settings service, which chains the FQDN and the realm checks.
#[test]
fn test_kerberos_asset_validation_is_a_single_seam() {
    let handlers = include_str!("../../src/handlers/web/manage_assets.rs");
    assert_eq!(
        handlers
            .matches("crate::services::rdp_auth_mode::resolve(")
            .count(),
        2,
        "create and update must each resolve the RDP auth settings once"
    );
    assert!(
        !handlers.contains("RdpAuthMode::KerberosRestrictedAdmin.as_str()"),
        "handlers must ask `uses_kerberos()`, not compare against one mode"
    );

    let service = include_str!("../../src/services/rdp_auth_mode.rs");
    let start = service
        .find("pub fn validate(\n")
        .expect("services::rdp_auth_mode::validate must exist");
    let body = &service[start..];
    let end = body.find("\n}\n").expect("function end");
    let body = &body[..end];
    assert!(body.contains("mode.uses_kerberos()"));
    assert!(body.contains("validate_kerberos_fqdn(hostname)"));
    assert!(body.contains("validate_kerberos_domain(domain)"));
    assert!(
        service.contains("shared::kerberos::normalize_realm("),
        "the domain check must delegate to shared::kerberos::normalize_realm"
    );
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

// =============================================================================
// Standard Kerberos mode (`kerberos`)
// =============================================================================
//
// Same Kerberos-only leg as Restricted Admin, with regular TSCredentials:
// for accounts that are not local administrators of the target. It is a
// Kerberos mode, so it carries the same asset constraints (FQDN, DNS
// domain), through the same validation seam.

/// POST the create form in the standard `kerberos` mode. Returns the
/// hostname used and the HTTP status.
async fn post_standard_kerberos_create(
    app: &TestApp,
    token: &str,
    hostname: Option<&str>,
    domain: Option<&str>,
) -> (String, u16) {
    let csrf = app.generate_csrf_token();
    let asset_name = unique_name("krb-std");
    let hostname = hostname
        .map(str::to_string)
        .unwrap_or_else(|| format!("{}.corp.example.com", unique_name("host")));
    let mut form: Vec<(&str, &str)> = vec![
        ("csrf_token", csrf.as_str()),
        ("name", &asset_name),
        ("hostname", &hostname),
        ("port", "3389"),
        ("asset_type", "rdp"),
        ("status", "online"),
        ("ssh_username", "jdoe"),
        ("ssh_password", "Win-Pwd-2026!"),
        ("rdp_auth_mode", "kerberos"),
    ];
    if let Some(d) = domain {
        form.push(("rdp_domain", d));
    }
    let status = app
        .server
        .post("/assets/manage/new")
        .add_header(COOKIE, auth_csrf_cookie(token, &csrf))
        .form(&form)
        .await
        .status_code()
        .as_u16();
    (hostname, status)
}

/// `kerberos` + FQDN + DNS domain: persisted verbatim, NOT folded into
/// `ntlm` or into Restricted Admin.
#[tokio::test]
#[serial]
async fn test_create_rdp_standard_kerberos_persists_mode() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("krb_std_ok")).await;

    let (hostname, status) =
        post_standard_kerberos_create(app, &admin.token, None, Some("corp.example.com")).await;
    assert!(status == 302 || status == 303, "got {status}");

    let asset = read_asset_by_hostname(&mut conn, &hostname)
        .await
        .expect("standard Kerberos RDP asset must be persisted");
    assert_eq!(stored_auth_mode(&asset), Some("kerberos"));
    assert_eq!(stored_domain(&asset), Some("corp.example.com"));

    test_db::cleanup(&mut conn).await;
}

/// The standard mode is a Kerberos mode: an IP literal has no SPN, a
/// missing or NetBIOS domain has no realm. Each is refused, with NO row.
#[tokio::test]
#[serial]
async fn attack_create_rdp_standard_kerberos_without_fqdn_or_realm_is_rejected() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("krb_std_bad")).await;

    // TEST-NET-3 literal, distinct from the Restricted Admin IP test.
    let cases: [(Option<&str>, Option<&str>); 5] = [
        (Some("203.0.113.77"), Some("corp.example.com")),
        (None, None),
        (None, Some("")),
        (None, Some("CORP")),
        (None, Some("corp.example.com@evil.test")),
    ];
    for (hostname, domain) in cases {
        let (used, status) =
            post_standard_kerberos_create(app, &admin.token, hostname, domain).await;
        assert!(
            status == 302 || status == 303,
            "refusal is a flash-redirect, got {status} for {hostname:?} / {domain:?}"
        );
        assert!(
            read_asset_by_hostname(&mut conn, &used).await.is_none(),
            "{hostname:?} / {domain:?} must NOT yield a Kerberos asset"
        );
    }

    test_db::cleanup(&mut conn).await;
}

/// The edit form seeds the Alpine binding with the stored standard mode,
/// so saving the form unchanged does not silently change the mode.
#[tokio::test]
#[serial]
async fn test_edit_form_renders_stored_standard_kerberos_mode() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("krb_std_ui")).await;

    let hostname = format!("{}.corp.example.com", unique_name("host"));
    let asset = insert_rdp_asset_with_config(
        &mut conn,
        &unique_name("krb-std-edit"),
        &hostname,
        serde_json::json!({
            "username": "jdoe",
            "domain": "corp.example.com",
            "rdp_auth_mode": "kerberos",
        }),
    )
    .await;

    let response = app
        .server
        .get(&format!("/assets/manage/{}/edit", asset.uuid))
        .add_header(COOKIE, format!("access_token={}", admin.token))
        .await;
    assert_status(&response, 200);
    assert!(
        response.text().contains("rdpAuthMode: 'kerberos'"),
        "the stored standard Kerberos mode must seed the x-model binding"
    );

    test_db::cleanup(&mut conn).await;
}

/// Both forms state what the standard mode does with the password: it is
/// delegated to the target, unlike Restricted Admin.
#[test]
fn test_forms_warn_that_standard_kerberos_delegates_the_password() {
    for (name, template) in [
        (
            "asset_create.html",
            include_str!("../../templates/assets/asset_create.html"),
        ),
        (
            "asset_edit.html",
            include_str!("../../templates/assets/asset_edit.html"),
        ),
    ] {
        let start = template
            .find("x-show=\"rdpAuthMode === 'kerberos'\"")
            .unwrap_or_else(|| panic!("{name}: no help text for the standard mode"));
        let help = &template[start..start + 600];
        assert!(
            help.contains("The password is delegated to the target"),
            "{name}: the standard mode must say the password is delegated"
        );
        assert!(help.contains("No NTLM fallback"), "{name}");
    }
}

// =============================================================================
// Classified NLA failure (`RdpAuthFailure`)
// =============================================================================
//
// Behavioral coverage: `services::rdp_auth_failure` (messages, audit
// details) and `ipc::proxy_rdp` (delivery) unit tests, and the proxy's
// `auth_failure` module. No RDP proxy runs in this suite, so the handler
// branch is pinned at source level.

/// On a classified failure, `connect_rdp` hands the reason and the mode
/// to `refuse_rdp_auth`, which audits them and answers with a constant
/// message chosen by `assets:manage`. That branch returns before the
/// code that forwards the proxy's error text.
#[test]
fn test_connect_rdp_answers_a_classified_failure_with_a_constant_message() {
    let source = include_str!("../../src/handlers/web/rdp.rs");
    let start = source
        .find("if let Some((reason, attempted_mode)) = response.auth_failure {")
        .expect("classified-failure branch in connect_rdp");
    let block = &source[start..];
    let end = block.find("\n            }\n").expect("end of the branch");
    let block = &block[..end];
    assert!(block.contains("return refuse_rdp_auth("));
    assert!(block.contains("attempted_mode,"));
    for forbidden in ["response.error", "format!(", "is_staff", "is_superuser"] {
        assert!(!block.contains(forbidden), "branch uses `{forbidden}`");
    }

    let helper_start = source
        .find("fn refuse_rdp_auth(")
        .expect("refuse_rdp_auth helper");
    let helper = &source[helper_start..];
    let helper = &helper[..helper.find("\n}\n").expect("end of the helper")];
    assert!(helper.contains("shared::messages::AuditEventType::RdpAuthFailed"));
    assert!(
        helper
            .contains("crate::services::rdp_auth_failure::audit_details(asset_uuid, reason, mode)")
    );
    assert!(helper.contains("crate::services::rdp_auth_failure::message_for("));
    assert!(
        helper.contains("perms.assets_manage,"),
        "the wording is selected by the Casbin-derived assets:manage flag"
    );
    for forbidden in ["format!(", "is_staff", "is_superuser", ".error"] {
        assert!(!helper.contains(forbidden), "helper uses `{forbidden}`");
    }

    // The branch precedes the legacy path that shows the proxy's text.
    let legacy = source
        .find(".unwrap_or_else(|| \"RDP connection failed\".to_string());")
        .expect("legacy text path");
    assert!(start < legacy);
}

/// The reason reaches the browser only through `message_for`: no other
/// handler or template formats an `RdpAuthFailure`.
#[test]
fn test_rdp_auth_failure_wording_is_a_single_seam() {
    let service = include_str!("../../src/services/rdp_auth_failure.rs");
    assert!(
        service.contains("pub const fn operator_message(reason: RdpAuthFailure) -> &'static str")
    );
    let table = &service[service
        .find("pub const fn operator_message")
        .expect("table")
        ..service
            .find("pub const fn message_for")
            .expect("message_for")];
    assert!(
        !table.contains("_ =>"),
        "no wildcard arm: every reason is worded"
    );

    let handler = include_str!("../../src/handlers/web/rdp.rs");
    assert_eq!(
        handler.matches("rdp_auth_failure::message_for(").count(),
        1,
        "one wording call site"
    );
    assert!(
        !handler.contains("rdp_auth_failure::operator_message("),
        "handlers never bypass the assets:manage selection"
    );
}
