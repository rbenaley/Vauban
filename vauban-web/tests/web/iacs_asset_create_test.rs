/// VAUBAN Web - E2E tests for IACS asset creation (admin zone).
///
/// **Background -- Operator-reported regression (2026-05-08).** The
/// "Create Asset" button on `/assets/manage/new` appeared to do nothing
/// when the operator selected an IACS variant (Modbus / OPC-UA /
/// PROFINET / IEC-104 / TCP). Root cause was a UI/server contract
/// mismatch:
///
/// 1. The Authentication card was hidden via Alpine `x-show="!isIacs"`,
///    but `x-show` only toggles `display:none` -- the inputs and the
///    `<select name="ssh_auth_type">` stay in the DOM. The browser
///    therefore submitted `ssh_auth_type=password` (the Alpine
///    `authType` default), `ssh_username=root` (renamed from the
///    opaque `vbn_account` by the form's `@submit` handler), and
///    empty `ssh_password` / `ssh_passphrase` fields.
/// 2. `validate_auth_inputs` correctly refuses any auth-related field
///    on an IACS asset (it would silently re-introduce the SEC-11
///    credential-carryover risk if it accepted them), so the create
///    handler returned a flash-error redirect to `/assets/manage/new`.
/// 3. The redirect landed back on the same form, the operator saw no
///    new asset and no obvious error -- "rien ne se passe".
///
/// Additional defect on the `iacs_tcp` branch: the `x-on:change`
/// helper set `port = 0` to force the operator to enter a port, but
/// the input has `min="1"`, so the browser refused the submit
/// silently when the operator clicked Create Asset without first
/// editing the port -- same "nothing happens" symptom for a different
/// underlying cause.
///
/// The fix: every credential-related input/select in the create AND
/// edit forms now carries `data-iacs-strip`, and the form's `@submit`
/// handler sets `disabled = true` on each tagged element when the
/// asset type starts with `iacs_`. Disabled fields are not part of
/// the form submission per the HTML spec, so the IACS POST never
/// carries `ssh_auth_type` / `ssh_username` / `ssh_password` /
/// `ssh_passphrase` / `rdp_domain`.
///
/// This file has FOUR layers of E2E coverage:
///
/// 1. **Happy path (5 tests)** -- one per IACS variant. Submits the
///    payload that the browser sends after the JS strip runs (no
///    `ssh_*` fields, no `rdp_domain`) and asserts the create handler
///    persists the row and redirects to its detail page.
/// 2. **Tampered-submit guard (1 test)** -- pins the server-side
///    refusal: a raw POST that smuggles `ssh_auth_type=password` on
///    an IACS asset MUST be rejected. This is the canary that fails
///    if a future maintainer "softens" `validate_auth_inputs` to
///    silently ignore IACS credential fields and accidentally
///    re-opens the SEC-11 carryover surface.
/// 3. **Form markup pin (3 tests)** -- assert the Alpine wiring that
///    makes the JS strip work (every credential input carries
///    `data-iacs-strip`, the `@submit` handler disables them when
///    `isIacs`, the `iacs_tcp` branch clears the port to `null`
///    instead of `0`). These are server-rendered HTML grep tests:
///    they survive even if the JS engine isn't available in the
///    test runner.
/// 4. **Edit form parity (1 test)** -- exact same strip wiring on
///    `asset_edit.html`, since the `update_asset_web` handler also
///    pipes through `validate_auth_inputs` (against the existing
///    asset_type) and would refuse an IACS edit that smuggles
///    `ssh_auth_type=password`.
use crate::common::{TestApp, assertions::*};
use crate::fixtures::{create_admin_user, unique_name};
use axum::http::header::{COOKIE, LOCATION};
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serial_test::serial;
use uuid::Uuid;
use vauban_web::models::asset::{Asset, AssetType};
use vauban_web::schema::assets;

fn auth_csrf_cookie(token: &str, csrf: &str) -> String {
    format!("access_token={}; __vauban_csrf={}", token, csrf)
}

async fn read_asset_by_triplet(
    conn: &mut AsyncPgConnection,
    hostname: &str,
    port: i32,
) -> Option<Asset> {
    assets::table
        .filter(assets::hostname.eq(hostname))
        .filter(assets::port.eq(port))
        .filter(assets::is_deleted.eq(false))
        .first(conn)
        .await
        .ok()
}

// =============================================================================
// 1. Happy path -- one test per IACS variant.
// =============================================================================

async fn create_iacs_asset_happy_path(asset_type_str: &str, port: i32, expected: AssetType) {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name(&format!("iacs_create_ok_{}", asset_type_str));
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let csrf = app.generate_csrf_token();

    let asset_name = unique_name(&format!("iacs-{}-asset", asset_type_str));
    let asset_hostname = format!("{}.iacs.test", unique_name("plc"));
    let port_str = port.to_string();

    let response = app
        .server
        .post("/assets/manage/new")
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", &asset_name),
            ("hostname", &asset_hostname),
            ("port", &port_str),
            ("asset_type", asset_type_str),
            ("status", "online"),
        ])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "IACS {} create must succeed (302/303), got {}; Location={:?}",
        asset_type_str,
        status,
        response.headers().get(LOCATION),
    );

    let location = response
        .headers()
        .get(LOCATION)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    assert!(
        location.starts_with("/assets/manage/")
            && Uuid::parse_str(location.trim_start_matches("/assets/manage/")).is_ok(),
        "Expected redirect to /assets/manage/<uuid> for new IACS asset, got {:?}",
        location
    );

    let asset = read_asset_by_triplet(&mut conn, &asset_hostname, port)
        .await
        .unwrap_or_else(|| {
            panic!(
                "IACS {} asset must be persisted at ({}, {})",
                asset_type_str, asset_hostname, port
            )
        });
    assert_eq!(asset.asset_type, expected);

    let cfg = &asset.connection_config;
    assert!(
        cfg.get("password").is_none(),
        "IACS connection_config must NOT carry a password, got {}",
        cfg
    );
    assert!(
        cfg.get("private_key").is_none(),
        "IACS connection_config must NOT carry a private_key, got {}",
        cfg
    );
    assert!(
        cfg.get("auth_type").is_none(),
        "IACS connection_config must NOT carry auth_type, got {}",
        cfg
    );
    assert!(
        cfg.get("domain").is_none(),
        "IACS connection_config must NOT carry domain, got {}",
        cfg
    );
}

#[tokio::test]
#[serial]
async fn iacs_modbus_asset_creates_via_web_form() {
    create_iacs_asset_happy_path("iacs_modbus", 502, AssetType::IacsModbus).await;
}

#[tokio::test]
#[serial]
async fn iacs_opcua_asset_creates_via_web_form() {
    create_iacs_asset_happy_path("iacs_opcua", 4840, AssetType::IacsOpcua).await;
}

#[tokio::test]
#[serial]
async fn iacs_profinet_asset_creates_via_web_form() {
    create_iacs_asset_happy_path("iacs_profinet", 34962, AssetType::IacsProfinet).await;
}

#[tokio::test]
#[serial]
async fn iacs_iec104_asset_creates_via_web_form() {
    create_iacs_asset_happy_path("iacs_iec104", 2404, AssetType::IacsIec104).await;
}

#[tokio::test]
#[serial]
async fn iacs_tcp_asset_creates_via_web_form() {
    // iacs_tcp has no IANA-assigned default port; the operator must
    // type one. Pick a representative non-default to assert the
    // handler does not silently force a port and that the form does
    // not need a fallback.
    create_iacs_asset_happy_path("iacs_tcp", 1502, AssetType::IacsTcp).await;
}

// =============================================================================
// 2. Tampered-submit guard.
// =============================================================================

/// CANARY-IACS-AUTHFIELD-20260508. A raw POST that smuggles
/// `ssh_auth_type=password` for an IACS asset MUST be rejected.
/// `validate_auth_inputs` enforces this server-side so a tampered
/// client cannot use the IACS path to seed credentials on an asset
/// that should not carry any (SEC-11 carryover lineage).
#[tokio::test]
#[serial]
async fn iacs_create_with_smuggled_ssh_auth_type_is_refused() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin = create_admin_user(
        &mut conn,
        &app.auth_service,
        &unique_name("iacs_create_tamper"),
    )
    .await;
    let csrf = app.generate_csrf_token();

    let asset_name = unique_name("iacs-tampered-asset");
    let asset_hostname = format!("{}.iacs.test", unique_name("plc"));

    let response = app
        .server
        .post("/assets/manage/new")
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", &asset_name),
            ("hostname", &asset_hostname),
            ("port", "502"),
            ("asset_type", "iacs_modbus"),
            ("status", "online"),
            // Tampered: the form's @submit handler strips these on
            // IACS, so a real browser never sends them. A raw POST
            // that does send them MUST land in the rejection arm.
            ("ssh_auth_type", "password"),
            ("ssh_username", "root"),
        ])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "Tampered IACS create must redirect (with flash error), got {}",
        status,
    );
    let location = response
        .headers()
        .get(LOCATION)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    assert_eq!(
        location, "/assets/manage/new",
        "Tampered IACS create must bounce back to /assets/manage/new, got {:?}",
        location
    );

    // And critically: NO row was created.
    let row = read_asset_by_triplet(&mut conn, &asset_hostname, 502).await;
    assert!(
        row.is_none(),
        "Tampered IACS POST must NOT create an asset row, got {:?}",
        row.map(|a| a.uuid)
    );
}

// =============================================================================
// 3. Form markup pins.
// =============================================================================

/// Pin: every credential-related input/select on the CREATE form
/// carries `data-iacs-strip` so the `@submit` handler can disable
/// them when `isIacs`. If a future maintainer adds a new credential
/// field without the marker, this test fails BEFORE the operator
/// hits the silent rejection path.
#[tokio::test]
#[serial]
async fn create_form_tags_every_credential_field_with_iacs_strip() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin = create_admin_user(
        &mut conn,
        &app.auth_service,
        &unique_name("iacs_create_markup"),
    )
    .await;

    let response = app
        .server
        .get("/assets/manage/new")
        .add_header(COOKIE, format!("access_token={}", admin.token))
        .await;
    assert_status(&response, 200);
    let body = response.text();

    // Every input/select that resolves to an `ssh_*` or `rdp_*`
    // server-side field name MUST be tagged.
    for needle in [
        // The opaque DOM names that get renamed at submit:
        "name=\"vbn_account\"",
        "name=\"vbn_secret\"",
        "name=\"vbn_secret_phrase\"",
        // The fields whose name is already the server-side name:
        "name=\"ssh_auth_type\"",
        "name=\"ssh_private_key\"",
        "name=\"rdp_domain\"",
    ] {
        assert!(
            body.contains(needle),
            "create form must still render {} (otherwise the strip pin is meaningless)",
            needle
        );
    }
    // And `data-iacs-strip` must appear at least 6 times (one per
    // credential-related field). We don't pin a tighter coupling to
    // avoid brittle test breakage if a field is renamed.
    let strip_count = body.matches("data-iacs-strip").count();
    assert!(
        strip_count >= 6,
        "create form must tag at least 6 credential fields with data-iacs-strip, got {}",
        strip_count
    );
}

/// Pin: the `@submit` handler MUST disable every `data-iacs-strip`
/// element when `isIacs` is true, BEFORE the `data-real-name` swap.
/// Otherwise the renamed-and-disabled field would still slip into
/// the form data. The exact wording is grepped to keep the contract
/// machine-readable.
#[tokio::test]
#[serial]
async fn create_form_submit_handler_disables_iacs_fields_before_rename() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin = create_admin_user(
        &mut conn,
        &app.auth_service,
        &unique_name("iacs_create_submit"),
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
        body.contains("data-iacs-strip"),
        "create form @submit handler must reference data-iacs-strip"
    );
    assert!(
        body.contains("el.disabled = true"),
        "create form @submit handler must disable the tagged fields (so they are not submitted)"
    );
    assert!(
        body.contains("if (!el.disabled) { el.name = el.dataset.realName; }"),
        "create form @submit handler must skip the rename for already-disabled fields"
    );
}

/// Pin: switching to `iacs_tcp` MUST clear the port to `null`
/// (browser-rendered as empty) instead of `0`, which would fail the
/// `min=\"1\"` constraint and silently block the submit.
#[tokio::test]
#[serial]
async fn create_form_iacs_tcp_branch_clears_port_to_null_not_zero() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin = create_admin_user(
        &mut conn,
        &app.auth_service,
        &unique_name("iacs_create_tcp_port"),
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
        body.contains("'iacs_tcp' && Object.values(defaults).includes(port)) { port = null }"),
        "iacs_tcp branch must set port = null (empty input) -- setting it to 0 collides with min=\"1\" and silently blocks submit"
    );
    // And reciprocally: a previously-cleared port (`null`) must be
    // re-filled when the operator picks a protocol with a default.
    assert!(
        body.contains("port === null"),
        "the change handler must treat port === null as 'no port set' so the next protocol can apply its default"
    );
}

// =============================================================================
// 4. Edit form parity.
// =============================================================================

/// CANARY-IACS-BADGE-OVERFLOW-20260508. Pin the visual fix on the
/// admin detail page: the fixed-size `h-10 w-10` square next to the
/// asset name MUST render the compact `badge_label` (3 chars max)
/// and not the raw upper-cased `asset_type` (which is up to 11 chars
/// for IACS variants and overflows the tile, crashing into the
/// title `<h2>`). Operator-reported regression on 2026-05-08.
#[tokio::test]
#[serial]
async fn iacs_detail_page_renders_compact_badge_label_not_overflowing_tile() {
    use vauban_web::models::asset::NewAsset;

    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin = create_admin_user(
        &mut conn,
        &app.auth_service,
        &unique_name("iacs_badge_render"),
    )
    .await;

    let asset_uuid = Uuid::new_v4();
    let asset_name = unique_name("Modbus-PLC");
    let new_asset = NewAsset {
        uuid: asset_uuid,
        name: asset_name.clone(),
        hostname: format!("plc-{}.test", &asset_uuid.to_string()[..8]),
        port: 502,
        asset_type: AssetType::IacsModbus,
        status: "online".to_string(),
        description: None,
        connection_config: serde_json::json!({}),
        created_by_id: None,
        updated_by_id: None,
        connection_username: "root".to_string(),
    };
    let _: Asset = diesel::insert_into(assets::table)
        .values(&new_asset)
        .get_result(&mut conn)
        .await
        .expect("seed IACS modbus asset");

    let response = app
        .server
        .get(&format!("/assets/manage/{}", asset_uuid))
        .add_header(COOKIE, format!("access_token={}", admin.token))
        .await;
    assert_status(&response, 200);
    let body = response.text();

    // The short label MUST be there.
    assert!(
        body.contains(">MB<") || body.contains("MB\n"),
        "detail page must render the compact badge label 'MB' for an IACS Modbus asset"
    );
    // The long upper-cased token MUST NOT be there: that is what
    // overflowed the square tile in the operator screenshot.
    assert!(
        !body.contains("IACS_MODBUS"),
        "detail page must NOT render the long upper-cased 'IACS_MODBUS' (overflows the h-10 w-10 tile)"
    );
    // The friendly type label IS allowed (it goes into the
    // flexible-width Type pill below the header).
    assert!(
        body.contains("IACS - Modbus"),
        "detail page must render the readable 'IACS - Modbus' in the Type pill"
    );
    // The header tile MUST keep its flex-shrink-0 guard so it does
    // not collapse on narrow viewports while the title wraps.
    assert!(
        body.contains("flex-shrink-0"),
        "header badge tile must carry flex-shrink-0 to survive narrow viewports"
    );
}

/// Pin: the EDIT form carries the same strip wiring. The
/// `update_asset_web` handler also pipes through
/// `validate_auth_inputs(existing.asset_type, ...)` and would refuse
/// an IACS edit that smuggled `ssh_auth_type=password`.
#[tokio::test]
#[serial]
async fn edit_form_tags_credential_fields_with_iacs_strip() {
    use vauban_web::models::asset::NewAsset;

    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin = create_admin_user(
        &mut conn,
        &app.auth_service,
        &unique_name("iacs_edit_markup"),
    )
    .await;

    // Seed an SSH asset so the edit form renders the auth section
    // (otherwise the IACS branch hides it server-side and there is
    // nothing to grep). The strip wiring is what matters.
    let asset_uuid = Uuid::new_v4();
    let new_asset = NewAsset {
        uuid: asset_uuid,
        name: unique_name("ssh-edit-strip"),
        hostname: format!("edit-strip-{}.test.local", &asset_uuid.to_string()[..8]),
        port: 22,
        asset_type: AssetType::Ssh,
        status: "online".to_string(),
        description: None,
        connection_config: serde_json::json!({}),
        created_by_id: None,
        updated_by_id: None,
        connection_username: "root".to_string(),
    };
    let _: Asset = diesel::insert_into(assets::table)
        .values(&new_asset)
        .get_result(&mut conn)
        .await
        .expect("seed SSH asset");

    let response = app
        .server
        .get(&format!("/assets/manage/{}/edit", asset_uuid))
        .add_header(COOKIE, format!("access_token={}", admin.token))
        .await;
    assert_status(&response, 200);
    let body = response.text();

    let strip_count = body.matches("data-iacs-strip").count();
    assert!(
        strip_count >= 6,
        "edit form must tag at least 6 credential fields with data-iacs-strip, got {}",
        strip_count
    );
    assert!(
        body.contains(".startsWith('iacs_')"),
        "edit form @submit handler must guard the strip on asset_type starting with iacs_"
    );
}

// =============================================================================
// Type-filter dropdown carries the synthetic 'iacs' option AND filters rows
// =============================================================================

/// Operator request 2026-05-08: every page that exposes a Type
/// filter must surface a single "IACS - All Industrial Protocols"
/// option that matches every `iacs_*` asset_type at once. This
/// test pins the user-zone /assets and the admin /assets/manage
/// dropdowns and asserts the `?type=iacs` filter narrows the
/// result set to IACS rows only.
#[tokio::test]
#[serial]
async fn iacs_all_filter_appears_in_dropdowns_and_narrows_results() {
    use vauban_web::models::asset::{IACS_ALL_FILTER_TOKEN, NewAsset};

    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin = create_admin_user(
        &mut conn,
        &app.auth_service,
        &unique_name("iacs_all_filter_adm"),
    )
    .await;

    // Seed an SSH asset and an IACS Modbus asset so the filter
    // path can actually narrow.
    let ssh_uuid = Uuid::new_v4();
    let iacs_uuid = Uuid::new_v4();
    let prefix = unique_name("iacs_all_filter");
    for (uuid, name, hostname, port, asset_type) in [
        (
            ssh_uuid,
            format!("{prefix}-ssh"),
            format!("ssh-{}.test.local", &ssh_uuid.to_string()[..8]),
            22,
            AssetType::Ssh,
        ),
        (
            iacs_uuid,
            format!("{prefix}-mb"),
            format!("mb-{}.test.local", &iacs_uuid.to_string()[..8]),
            502,
            AssetType::IacsModbus,
        ),
    ] {
        let new_asset = NewAsset {
            uuid,
            name,
            hostname,
            port,
            asset_type,
            status: "online".to_string(),
            description: None,
            connection_config: serde_json::json!({}),
            created_by_id: None,
            updated_by_id: None,
            connection_username: "root".to_string(),
        };
        let _: Asset = diesel::insert_into(assets::table)
            .values(&new_asset)
            .get_result(&mut conn)
            .await
            .expect("seed asset");
    }

    // Admin /assets/manage list: dropdown carries the synthetic row
    // AND ?type=iacs returns the IACS asset only.
    let response = app
        .server
        .get("/assets/manage")
        .add_header(COOKIE, format!("access_token={}", admin.token))
        .await;
    assert_status(&response, 200);
    let body = response.text();
    assert!(
        body.contains(&format!("value=\"{}\"", IACS_ALL_FILTER_TOKEN)),
        "admin /assets/manage Type dropdown must expose the synthetic 'iacs' value"
    );
    assert!(
        body.contains("IACS - All Industrial Protocols"),
        "admin /assets/manage Type dropdown must label the synthetic row \
         'IACS - All Industrial Protocols'"
    );

    let filtered = app
        .server
        .get("/assets/manage?type=iacs")
        .add_header(COOKIE, format!("access_token={}", admin.token))
        .await;
    assert_status(&filtered, 200);
    let filtered_body = filtered.text();
    assert!(
        filtered_body.contains(&format!("{prefix}-mb")),
        "?type=iacs must keep the IACS Modbus asset in the rendered list"
    );
    assert!(
        !filtered_body.contains(&format!("{prefix}-ssh")),
        "?type=iacs must filter the SSH asset OUT of the rendered list"
    );

    // The label rename "generic TCP" -> "Generic TCP" (capital G).
    assert!(
        body.contains("IACS - Generic TCP"),
        "the IACS-TCP label must render with a capital G ('Generic TCP')"
    );
    assert!(
        !body.contains("IACS - generic TCP"),
        "the lowercase 'generic TCP' label must no longer appear"
    );
}

/// Sister test of the admin-zone E2E above: pin the SAME synthetic
/// 'iacs' row on the user-zone /assets dropdown. Both handlers
/// share `AssetType::filter_options()` but a future refactor could
/// silently drop one of the two call sites; this test catches it.
///
/// We hit /assets as the admin without any access rule; the
/// rendered list is allowed to be empty but the filter dropdown
/// MUST still carry the synthetic row.
#[tokio::test]
#[serial]
async fn user_zone_assets_dropdown_carries_iacs_all_filter_option() {
    use vauban_web::models::asset::IACS_ALL_FILTER_TOKEN;

    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin = create_admin_user(
        &mut conn,
        &app.auth_service,
        &unique_name("uzone_iacs_filter_adm"),
    )
    .await;

    let response = app
        .server
        .get("/assets")
        .add_header(COOKIE, format!("access_token={}", admin.token))
        .await;
    assert_status(&response, 200);
    let body = response.text();

    assert!(
        body.contains(&format!("value=\"{}\"", IACS_ALL_FILTER_TOKEN)),
        "user-zone /assets Type dropdown must expose the synthetic 'iacs' value"
    );
    assert!(
        body.contains("IACS - All Industrial Protocols"),
        "user-zone /assets Type dropdown must label the synthetic row \
         'IACS - All Industrial Protocols'"
    );
    assert!(
        body.contains("IACS - Generic TCP"),
        "user-zone /assets Type dropdown must use capital G ('Generic TCP')"
    );
}
