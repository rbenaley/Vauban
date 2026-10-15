//! MCP asset create — same "Create Asset does nothing" class as IACS.
//!
//! Root cause (2026-07-27): Authentication card is `x-show="!isIacs && !isMcp"`
//! but the Secret input inside keeps Alpine `:required` when
//! `authType === 'password'` (the default). For MCP, `isIacs` is false and
//! `authType` stays `'password'`, so the *hidden* field is required → the
//! browser blocks submit with no visible error.
//!
//! Fix: strip `data-iacs-strip` fields when `isIacs || isMcp`, and exclude
//! MCP from the Secret `:required` expression.
use crate::common::{TestApp, assertions::*};
use crate::fixtures::{create_admin_user, unique_name};
use axum::http::header::{COOKIE, LOCATION, SET_COOKIE};
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serial_test::serial;
use uuid::Uuid;
use vauban_web::models::asset::{Asset, AssetType};
use vauban_web::schema::assets;

fn auth_csrf_cookie(token: &str, csrf: &str) -> String {
    format!("access_token={}; __vauban_csrf={}", token, csrf)
}

async fn read_asset_by_hostname(conn: &mut AsyncPgConnection, hostname: &str) -> Option<Asset> {
    assets::table
        .filter(assets::hostname.eq(hostname))
        .filter(assets::is_deleted.eq(false))
        .first::<Asset>(conn)
        .await
        .ok()
}

#[tokio::test]
#[serial]
async fn mcp_asset_creates_via_web_form_without_ssh_fields() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin =
        create_admin_user(&mut conn, &app.auth_service, &unique_name("mcp_create_ok")).await;
    let csrf = app.generate_csrf_token();

    let asset_name = unique_name("mcp-asset");
    let asset_hostname = format!("{}.mcp.test", unique_name("upstream"));

    // Payload after the JS strip: no ssh_* / rdp_* fields. Upstream
    // bearer is optional; omit it so the path does not depend on vault
    // encrypt (test DBs may lack secret_groups).
    let response = app
        .server
        .post("/assets/manage/new")
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", &asset_name),
            ("hostname", &asset_hostname),
            ("port", "19001"),
            ("asset_type", "mcp"),
            ("status", "online"),
            ("description", "local mcp"),
        ])
        .await;

    let status = response.status_code().as_u16();
    let location = response
        .headers()
        .get(LOCATION)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    let set_cookies: Vec<_> = response
        .headers()
        .get_all(axum::http::header::SET_COOKIE)
        .iter()
        .filter_map(|h| h.to_str().ok())
        .collect();
    assert!(
        status == 302 || status == 303,
        "MCP create must succeed (302/303), got {}; Location={:?}; cookies={:?}",
        status,
        location,
        set_cookies,
    );

    assert!(
        location.starts_with("/assets/manage/")
            && Uuid::parse_str(location.trim_start_matches("/assets/manage/")).is_ok(),
        "Expected redirect to /assets/manage/<uuid>, got {:?}; cookies={:?}",
        location,
        set_cookies,
    );

    let asset = read_asset_by_hostname(&mut conn, &asset_hostname)
        .await
        .expect("MCP asset must be persisted");
    assert_eq!(asset.asset_type, AssetType::Mcp);
    assert_eq!(asset.port, 19001);

    let cfg = &asset.connection_config;
    assert_eq!(
        cfg.get("auth_type").and_then(|v| v.as_str()),
        Some("none"),
        "MCP without upstream bearer must set auth_type=none, got {}",
        cfg
    );
    assert!(
        cfg.get("allowed_tools").is_some(),
        "MCP create must seed allowed_tools catalogue, got {}",
        cfg
    );
}

#[tokio::test]
#[serial]
async fn create_form_mcp_excludes_secret_required_and_strips_with_iacs() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin = create_admin_user(
        &mut conn,
        &app.auth_service,
        &unique_name("mcp_create_markup"),
    )
    .await;

    let response = app
        .server
        .get("/assets/manage/new")
        .add_header(COOKIE, format!("access_token={}", admin.token))
        .await;
    assert_status(&response, 200);
    let body = response.text();

    assert!(
        body.contains("!isIacs && !isMcp && (assetType === 'rdp' || authType === 'password')"),
        "Secret :required must exclude MCP (hidden auth field must not block submit)"
    );
    assert!(
        body.contains("isIacs || isMcp"),
        "create @submit must strip credential fields for MCP as well as IACS"
    );
    assert!(
        body.contains("get isMcp()"),
        "create form must expose isMcp Alpine helper"
    );
    assert!(
        body.contains("submitError"),
        "create form must surface a visible client-side error when HTML5 validation blocks submit"
    );
    assert!(
        body.contains("el.required = false"),
        "MCP/IACS strip must clear required on hidden Secret so the browser cannot silently block submit"
    );
}

fn extract_flash_cookie(response: &axum_test::TestResponse) -> Option<String> {
    response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|c| c.to_str().ok())
        .find(|c| c.contains("__vauban_flash"))
        .and_then(|c| c.split(';').next())
        .map(|s| s.to_string())
}

/// Failed MCP create used to 303 back to `/assets/manage/new` with a
/// flash cookie the GET handler never consumed — the operator saw a
/// blank form. Pin the PRG: the error must be visible in the HTML.
#[tokio::test]
#[serial]
async fn mcp_create_name_collision_flash_is_visible_on_the_form() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("mcp_flash")).await;
    let csrf = app.generate_csrf_token();
    let name = unique_name("mcp-taken");
    let host_a = format!("{}.mcp-a.test", unique_name("up"));
    let host_b = format!("{}.mcp-b.test", unique_name("up"));

    let first = app
        .server
        .post("/assets/manage/new")
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", &name),
            ("hostname", &host_a),
            ("port", "19002"),
            ("asset_type", "mcp"),
            ("status", "online"),
        ])
        .await;
    let status = first.status_code().as_u16();
    let first_loc = first
        .headers()
        .get(LOCATION)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    assert!(
        (status == 302 || status == 303)
            && first_loc.starts_with("/assets/manage/")
            && first_loc != "/assets/manage/new",
        "first MCP create must land on the new asset, got {status} {first_loc}"
    );

    let collision = app
        .server
        .post("/assets/manage/new")
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", &name),
            ("hostname", &host_b),
            ("port", "19002"),
            ("asset_type", "mcp"),
            ("status", "online"),
        ])
        .await;
    let status = collision.status_code().as_u16();
    assert!(status == 302 || status == 303);
    let location = collision
        .headers()
        .get(LOCATION)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    assert!(
        location == "/assets/manage/new" || location.starts_with("/assets/manage/new?"),
        "duplicate name must bounce to the create form, got {location}"
    );

    let flash = extract_flash_cookie(&collision).expect("collision must set __vauban_flash");
    let form = app
        .server
        .get(location)
        .add_header(COOKIE, format!("access_token={}; {}", admin.token, flash))
        .await;
    assert_status(&form, 200);
    let body = form.text();
    assert!(
        body.contains("already exists") && body.contains("Choose a different name"),
        "create form must render the name-collision flash (not a blank page); got: {}",
        &body[..body.len().min(1200)]
    );
    assert!(
        !body.contains("cannot be restored"),
        "active-name collision must not be worded as a restore refusal"
    );
    assert!(
        body.contains("bg-red-50") || body.contains("text-red-"),
        "collision flash must use the error banner style"
    );
}

/// A validation error used to PRG back to an empty form. The operator
/// lost name / type / host and thought Create "did nothing".
#[tokio::test]
#[serial]
async fn mcp_create_validation_error_repopulates_non_secret_fields() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("mcp_draft")).await;
    let csrf = app.generate_csrf_token();

    let response = app
        .server
        .post("/assets/manage/new")
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", "local mcp ops"),
            ("hostname", "not a valid host"),
            ("port", "19002"),
            ("asset_type", "mcp"),
            ("status", "online"),
            ("description", "lab ops"),
            ("ssh_password", "must-not-echo"),
        ])
        .await;
    let status = response.status_code().as_u16();
    assert!(status == 302 || status == 303);
    let location = response
        .headers()
        .get(LOCATION)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    assert!(
        location.starts_with("/assets/manage/new?"),
        "failed create must keep a draft query, got {location}"
    );
    assert!(
        location.contains("asset_type=mcp") && location.contains("19002"),
        "draft must keep type and port, got {location}"
    );
    assert!(
        !location.contains("must-not-echo") && !location.contains("ssh_password"),
        "draft must omit secrets, got {location}"
    );

    let flash = extract_flash_cookie(&response).expect("validation must set a flash");
    let form = app
        .server
        .get(location)
        .add_header(COOKIE, format!("access_token={}; {}", admin.token, flash))
        .await;
    assert_status(&form, 200);
    let body = form.text();
    assert!(
        body.contains("local mcp ops") && body.contains("not a valid host"),
        "create form must re-show the submitted name and hostname; got: {}",
        &body[..body.len().min(1500)]
    );
    assert!(
        body.contains("value=\"mcp\"") && body.contains("selected"),
        "create form must keep Type=MCP selected"
    );
    assert!(
        !body.contains("must-not-echo"),
        "create form must not echo the submitted secret"
    );
}

/// ADR 010: the MCP create form stores the upstream SPKI pin and refuses a
/// malformed one with a visible error.
#[tokio::test]
#[serial]
async fn mcp_create_stores_tls_pin_and_rejects_malformed() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("mcp_pin")).await;
    let csrf = app.generate_csrf_token();
    let pin = format!("SHA256:{}=", "A".repeat(43));

    let host_ok = format!("{}.mcp-pin.test", unique_name("up"));
    let name_ok = unique_name("mcp-pin-ok");
    let ok = app
        .server
        .post("/assets/manage/new")
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", name_ok.as_str()),
            ("hostname", host_ok.as_str()),
            ("port", "19001"),
            ("asset_type", "mcp"),
            ("status", "online"),
            ("mcp_tls_spki", pin.as_str()),
        ])
        .await;
    let ok_loc = ok
        .headers()
        .get(LOCATION)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(matches!(ok.status_code().as_u16(), 302 | 303));
    let ok_flash = extract_flash_cookie(&ok).unwrap_or_default();
    let asset = read_asset_by_hostname(&mut conn, &host_ok)
        .await
        .unwrap_or_else(|| panic!("MCP asset with pin must be persisted: {ok_loc} {ok_flash}"));
    assert_eq!(
        asset.connection_config["mcp_upstream_tls_spki"].as_str(),
        Some(pin.as_str())
    );

    let edit_url = format!("/assets/manage/{}/edit", asset.uuid);
    let edit = app
        .server
        .post(&edit_url)
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", name_ok.as_str()),
            ("hostname", host_ok.as_str()),
            ("port", "19001"),
            ("status", "online"),
            ("mcp_tls_spki", "SHA256:short"),
        ])
        .await;
    let edit_loc = edit
        .headers()
        .get(LOCATION)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert_eq!(edit_loc, edit_url, "malformed pin on edit must bounce back");
    let edit_flash = extract_flash_cookie(&edit).expect("edit must flash the pin error");
    let edit_page = app
        .server
        .get(&edit_url)
        .add_header(
            COOKIE,
            format!("access_token={}; {}", admin.token, edit_flash),
        )
        .await
        .text();
    assert!(
        edit_page.contains("MCP upstream TLS pin must be SHA256:"),
        "edit flash must explain the pin format"
    );
    let unchanged = read_asset_by_hostname(&mut conn, &host_ok)
        .await
        .expect("asset");
    assert_eq!(
        unchanged.connection_config["mcp_upstream_tls_spki"].as_str(),
        Some(pin.as_str()),
        "rejected edit must keep the stored pin"
    );

    let new_pin = format!("SHA256:{}A=", "B".repeat(42));
    let rotated = app
        .server
        .post(&edit_url)
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", name_ok.as_str()),
            ("hostname", host_ok.as_str()),
            ("port", "19001"),
            ("status", "online"),
            ("mcp_tls_spki", new_pin.as_str()),
        ])
        .await;
    assert!(matches!(rotated.status_code().as_u16(), 302 | 303));
    let rotated_asset = read_asset_by_hostname(&mut conn, &host_ok)
        .await
        .expect("asset");
    assert_eq!(
        rotated_asset.connection_config["mcp_upstream_tls_spki"].as_str(),
        Some(new_pin.as_str()),
        "valid pin on edit must replace the stored one"
    );

    let host_bad = format!("{}.mcp-pin-bad.test", unique_name("up"));
    let name_bad = unique_name("mcp-pin-bad");
    let bad = app
        .server
        .post("/assets/manage/new")
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", name_bad.as_str()),
            ("hostname", host_bad.as_str()),
            ("port", "19001"),
            ("asset_type", "mcp"),
            ("status", "online"),
            ("mcp_tls_spki", "SHA256:short"),
        ])
        .await;
    let location = bad
        .headers()
        .get(LOCATION)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(location.starts_with("/assets/manage/new?"), "{location}");
    assert!(read_asset_by_hostname(&mut conn, &host_bad).await.is_none());
    let flash = extract_flash_cookie(&bad).expect("malformed pin must set a flash");
    let form = app
        .server
        .get(&location)
        .add_header(COOKIE, format!("access_token={}; {}", admin.token, flash))
        .await;
    let body = form.text();
    assert!(
        body.contains("MCP upstream TLS pin must be SHA256:"),
        "malformed pin flash must be visible; got: {}",
        &body[..body.len().min(1500)]
    );
}

#[tokio::test]
#[serial]
async fn create_form_mcp_has_tls_pin_field() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("mcp_pin_ui")).await;
    let response = app
        .server
        .get("/assets/manage/new")
        .add_header(COOKIE, format!("access_token={}", admin.token))
        .await;
    assert_status(&response, 200);
    let body = response.text();
    assert!(
        body.contains("name=\"mcp_tls_spki\""),
        "MCP create form must expose the SPKI pin input"
    );
}

/// The edit page preselects the stored MCP transport: saving the form
/// unchanged must not turn a tunnel asset back into a direct one.
#[tokio::test]
#[serial]
async fn mcp_edit_page_preselects_the_stored_transport() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("mcp_tr_edit")).await;
    for (transport, other) in [("tunnel", "direct"), ("direct", "tunnel")] {
        let asset: Asset = diesel::insert_into(assets::table)
            .values(&vauban_web::models::asset::NewAsset {
                uuid: Uuid::new_v4(),
                name: unique_name("mcp-tr-edit"),
                hostname: format!("{}.mcp.test", unique_name("up")),
                port: 19001,
                asset_type: AssetType::Mcp,
                status: "online".into(),
                description: None,
                connection_config: serde_json::json!({ "transport": transport }),
                created_by_id: None,
                updated_by_id: None,
                connection_username: String::new(),
            })
            .get_result(&mut conn)
            .await
            .unwrap();
        let page = app
            .server
            .get(&format!("/assets/manage/{}/edit", asset.uuid))
            .add_header(COOKIE, format!("access_token={}", admin.token))
            .await
            .text();
        assert!(
            page.contains(&format!(r#"<option value="{transport}" selected>"#)),
            "{transport} must be preselected"
        );
        assert!(
            !page.contains(&format!(r#"<option value="{other}" selected>"#)),
            "{other} must not be preselected"
        );
    }
    crate::common::test_db::cleanup(&mut conn).await;
}
