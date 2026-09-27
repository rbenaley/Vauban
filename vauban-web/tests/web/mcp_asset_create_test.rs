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
