/// VAUBAN Web - Integration tests for asset-protocol coupling and the
/// credential-handling contract of the create/edit/delete flow.
///
/// **Background — Issue #15.** The asset create/edit form historically
/// surfaced the SSH-shaped Authentication block (`Password` /
/// `Private Key` selector + private-key textarea + passphrase field)
/// regardless of the chosen `asset_type`. RDP only consumes username +
/// password (+ optional Windows AD `domain`), so an operator could
/// store an SSH key on an RDP row that the proxy would never use --
/// dormant credential, no UI feedback. The audit also surfaced a
/// related defect: `build_connection_config` branched on `auth_type`
/// without consulting `asset_type`, so a tampered request that
/// bypassed the UI persisted the private key encrypted-at-rest.
///
/// **Background — Issue #17 (SEC-11 follow-up).** Soft-delete + recreate
/// on the same `(hostname, port, username)` triplet historically
/// reactivated the prior row. Even after the credential-carryover patch
/// (#15), recreating an asset still landed at the previous UUID, which
/// violates the audit invariant that "delete is final" (RG-ASS-04).
/// Issue #17 made deletion structurally irreversible: a fresh INSERT is
/// always issued, the active triplet is enforced by the partial unique
/// index `idx_assets_hostname_port_username_active` (originally
/// introduced in 20260330000000_add_connection_username and
/// re-documented from 20260420000000_assets_irreversible_delete), and a
/// DB trigger `assets_no_resurrection_trg` rejects any attempt to flip
/// `is_deleted` back to `false`. The reactivation branch and its
/// associated `force_soft_delete_keeping_config` test helper are gone:
/// the latter is no longer expressible because the
/// `assets_tombstone_no_secrets` CHECK constraint forbids a tombstone
/// from carrying a populated `connection_config`.
///
/// Tests covering the irreversible-delete semantics live in
/// `asset_irreversible_delete_test.rs` (handler + integration) and
/// `assets_db_invariants_test.rs` (raw-SQL guarantees).
///
/// Test matrix in this file:
///
/// **UI rendering (4 tests)** — verify the server-rendered HTML carries
/// the right Alpine `x-show` wiring so the client toggle would correctly
/// hide protocol-incompatible fields. We can't run JS in this layer, so
/// we assert on the directives themselves.
///
/// - `test_create_form_ssh_renders_auth_type_selector`
/// - `test_create_form_rdp_hides_auth_type_selector_and_private_key`
/// - `test_create_form_rdp_renders_domain_field`
/// - `test_create_form_ssh_hides_domain_field`
///
/// **Server-side enforcement (4 tests)** — these are the canary tests:
/// even a request that bypasses the UI must be rejected.
///
/// - `test_create_rdp_with_private_key_rejects_400_and_drops_field`
///   (CANARY-RDP-PK-20260418)
/// - `test_create_rdp_with_password_succeeds`
/// - `test_create_ssh_with_private_key_succeeds` (non-regression)
/// - `test_create_rdp_with_domain_persists_in_connection_config`
///
/// **Soft-delete scrub (1 test)** — `delete_asset_web` must purge
/// `connection_config` to `{}`. This is now also enforced by the DB
/// CHECK constraint, but we keep the integration test as
/// defence-in-depth: it pins the handler contract independently of
/// the DB invariant.
///
/// - `test_soft_delete_purges_connection_config`
///
/// **Edit flow (1 test)**
///
/// - `test_edit_rdp_cannot_set_private_key_via_form`
use crate::common::{TestApp, assertions::*, test_db, unwrap_ok};
use crate::fixtures::{create_admin_user, unique_name};
use axum::http::header::{COOKIE, LOCATION, SET_COOKIE};
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

/// Build the cookie header that the create/edit handlers expect:
/// `access_token` for the auth middleware AND `__vauban_csrf` for the
/// double-submit CSRF check.
fn auth_csrf_cookie(token: &str, csrf: &str) -> String {
    format!("access_token={}; __vauban_csrf={}", token, csrf)
}

/// Read an asset's full row from the DB by UUID, including its
/// `connection_config` JSON. Used to assert on what was actually
/// persisted.
async fn read_asset_by_uuid(conn: &mut AsyncPgConnection, asset_uuid: Uuid) -> Option<Asset> {
    assets::table
        .filter(assets::uuid.eq(asset_uuid))
        .first(conn)
        .await
        .ok()
}

/// Read an asset row by `(hostname, port, connection_username)` -- the
/// reactivation lookup key used by `create_asset_web`. Returns the
/// matching row (active OR soft-deleted) or None.
async fn read_asset_by_triplet(
    conn: &mut AsyncPgConnection,
    hostname: &str,
    port: i32,
    username: &str,
) -> Option<Asset> {
    assets::table
        .filter(assets::hostname.eq(hostname))
        .filter(assets::port.eq(port))
        .filter(assets::connection_username.eq(username))
        .first(conn)
        .await
        .ok()
}

/// Insert an asset directly with a custom `connection_config` JSON.
/// Bypasses the web layer so SEC-11 tests can simulate a row created
/// before the carryover fix landed.
async fn insert_asset_with_config(
    conn: &mut AsyncPgConnection,
    name: &str,
    hostname: &str,
    port: i32,
    asset_type: AssetType,
    connection_username: &str,
    connection_config: Json,
) -> Asset {
    let new_asset = NewAsset {
        uuid: Uuid::new_v4(),
        name: name.to_string(),
        hostname: hostname.to_string(),
        port,
        asset_type,
        status: "online".to_string(),
        description: None,
        connection_config,
        created_by_id: None,
        connection_username: connection_username.to_string(),
    };
    unwrap_ok!(
        diesel::insert_into(assets::table)
            .values(&new_asset)
            .get_result(conn)
            .await
    )
}

// Issue #17: the `force_soft_delete_keeping_config` helper that used
// to live here is intentionally gone. Its purpose was to construct a
// tombstone with a populated `connection_config` to reproduce the
// pre-fix carryover bug surface. After issue #17, that state is
// structurally impossible: `assets_tombstone_no_secrets` rejects any
// UPDATE that sets `is_deleted = true` without scrubbing the column,
// so the helper would only ever produce a CHECK violation. The
// equivalent "DB rejects this" assertion lives in
// `assets_db_invariants_test.rs::test_i3_purge_must_be_concurrent_with_soft_delete`.

// =============================================================================
// UI rendering -- 4 tests
// =============================================================================

/// SSH is the default `asset_type` on a fresh `/assets/new`. The server
/// MUST render the `ssh_auth_type` `<select>` and the Alpine guard that
/// scopes it to `assetType === 'ssh'` so the toggle survives a switch
/// to RDP without losing its DOM presence.
#[tokio::test]
#[serial]
async fn test_create_form_ssh_renders_auth_type_selector() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("asset_proto_ui_ssh_sel");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let response = app
        .server
        .get("/assets/manage/new")
        .add_header(COOKIE, format!("access_token={}", admin.token))
        .await;

    assert_status(&response, 200);
    let body = response.text();

    assert!(
        body.contains("name=\"ssh_auth_type\""),
        "auth_type selector must be present in the markup"
    );
    assert!(
        body.contains("x-show=\"assetType === 'ssh'\""),
        "auth_type selector must be guarded by assetType === 'ssh' so it disappears when the operator picks RDP"
    );

    test_db::cleanup(&mut conn).await;
}

/// The private-key textarea + passphrase block MUST be guarded by
/// `assetType === 'ssh' && authType === 'private_key'` so an operator
/// switching the protocol selector to RDP cannot even *see* the field
/// (defence in depth behind the server-side rejection).
#[tokio::test]
#[serial]
async fn test_create_form_rdp_hides_auth_type_selector_and_private_key() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("asset_proto_ui_rdp_hide");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let response = app
        .server
        .get("/assets/manage/new")
        .add_header(COOKIE, format!("access_token={}", admin.token))
        .await;

    assert_status(&response, 200);
    let body = response.text();

    assert!(
        body.contains("x-show=\"assetType === 'ssh' && authType === 'private_key'\""),
        "private-key block must be hidden whenever assetType is RDP"
    );
    assert!(
        body.contains("name=\"ssh_private_key\""),
        "private-key textarea must still exist in the DOM (just hidden) so SSH operators can fill it"
    );
}

/// The RDP `domain` field is brand new (issue #15). It MUST be present
/// in the markup with an `assetType === 'rdp'` guard.
#[tokio::test]
#[serial]
async fn test_create_form_rdp_renders_domain_field() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("asset_proto_ui_rdp_dom");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let response = app
        .server
        .get("/assets/manage/new")
        .add_header(COOKIE, format!("access_token={}", admin.token))
        .await;

    assert_status(&response, 200);
    let body = response.text();

    assert!(
        body.contains("name=\"rdp_domain\""),
        "RDP domain input must be present"
    );
    assert!(
        body.contains("x-show=\"assetType === 'rdp'\""),
        "RDP domain input must be wrapped in an assetType === 'rdp' guard"
    );
}

/// Inverse of the previous test: when SSH is selected, the domain block
/// is hidden by the same guard. We assert on the directive's existence
/// (it's the same string) -- the point is that the server NEVER renders
/// a domain input *without* the guard, which would make it visible
/// unconditionally.
#[tokio::test]
#[serial]
async fn test_create_form_ssh_hides_domain_field() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("asset_proto_ui_ssh_dom");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let response = app
        .server
        .get("/assets/manage/new")
        .add_header(COOKIE, format!("access_token={}", admin.token))
        .await;

    assert_status(&response, 200);
    let body = response.text();

    let domain_index = body
        .find("name=\"rdp_domain\"")
        .expect("domain input must be in the markup");
    let preceding = &body[..domain_index];
    let nearest_div = preceding
        .rfind("<div ")
        .expect("domain input must live inside a <div>");
    let guard_window = &body[nearest_div..domain_index];
    assert!(
        guard_window.contains("x-show=\"assetType === 'rdp'\""),
        "domain input's enclosing div must carry the assetType === 'rdp' guard so SSH never shows it; got window:\n{}",
        guard_window
    );
}

// =============================================================================
// Server-side enforcement -- 4 tests
// =============================================================================

/// **CANARY-RDP-PK-20260418** -- the regression we never want to ship
/// again. POST a brand-new RDP asset with `ssh_auth_type=private_key`
/// and a recognisable canary blob. The handler MUST reject the request
/// (303 redirect to `/assets/new` with an error flash), and the canary
/// MUST NOT appear anywhere in the persisted row's `connection_config`.
#[tokio::test]
#[serial]
async fn test_create_rdp_with_private_key_rejects_400_and_drops_field() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("asset_proto_canary");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let csrf = app.generate_csrf_token();

    let asset_name = unique_name("canary-rdp-asset");
    let asset_hostname = format!("{}.canary.test", unique_name("host"));
    const CANARY: &str = "CANARY-RDP-PK-20260418-MUST-NOT-PERSIST";

    let response = app
        .server
        .post("/assets/manage/new")
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", &asset_name),
            ("hostname", &asset_hostname),
            ("port", "3389"),
            ("asset_type", "rdp"),
            ("status", "online"),
            ("ssh_username", "Administrator"),
            ("ssh_auth_type", "private_key"),
            ("ssh_private_key", CANARY),
        ])
        .await;

    assert_status(&response, 303);
    let location = response
        .headers()
        .get(LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(
        location, "/assets/manage/new",
        "rejected RDP+private_key submissions must bounce back to /assets/manage/new"
    );

    let persisted = read_asset_by_triplet(&mut conn, &asset_hostname, 3389, "Administrator").await;
    if let Some(asset) = persisted {
        let cfg = asset.connection_config.to_string();
        assert!(
            !cfg.contains(CANARY),
            "Canary leaked into persisted connection_config: {}",
            cfg
        );
        assert!(
            !cfg.contains("private_key"),
            "private_key key must never appear on an RDP row, got: {}",
            cfg
        );
    }
}

/// Happy path for RDP: username + password + (no domain) succeeds, the
/// row is persisted with `asset_type=rdp` and a clean
/// `connection_config` containing `password` only -- no SSH leftovers.
#[tokio::test]
#[serial]
async fn test_create_rdp_with_password_succeeds() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("asset_proto_rdp_ok");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let csrf = app.generate_csrf_token();

    let asset_name = unique_name("rdp-ok-asset");
    let asset_hostname = format!("{}.rdp.test", unique_name("host"));

    let response = app
        .server
        .post("/assets/manage/new")
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", &asset_name),
            ("hostname", &asset_hostname),
            ("port", "3389"),
            ("asset_type", "rdp"),
            ("status", "online"),
            ("ssh_username", "Administrator"),
            ("ssh_password", "Win-Pwd-2026!"),
        ])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "Expected redirect after RDP create, got {}",
        status
    );

    let asset = read_asset_by_triplet(&mut conn, &asset_hostname, 3389, "Administrator")
        .await
        .expect("RDP asset must be persisted");
    assert_eq!(asset.asset_type, AssetType::Rdp);
    let cfg = asset.connection_config;
    assert!(
        cfg.get("password").is_some(),
        "RDP connection_config must contain password, got {}",
        cfg
    );
    assert!(
        cfg.get("auth_type").is_none(),
        "RDP connection_config must NOT carry an auth_type key, got {}",
        cfg
    );
    assert!(
        cfg.get("private_key").is_none(),
        "RDP connection_config must NOT carry a private_key, got {}",
        cfg
    );
}

/// Non-regression: the SSH + private-key path still works after the
/// asset_type-aware refactor. We deliberately use a clearly-non-secret
/// placeholder string -- the test only cares that the field round-trips,
/// not its content.
#[tokio::test]
#[serial]
async fn test_create_ssh_with_private_key_succeeds() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("asset_proto_ssh_pk");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let csrf = app.generate_csrf_token();

    let asset_name = unique_name("ssh-pk-asset");
    let asset_hostname = format!("{}.ssh.test", unique_name("host"));
    const FAKE_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\nNON-SECRET-TEST-PLACEHOLDER\n-----END OPENSSH PRIVATE KEY-----";

    let response = app
        .server
        .post("/assets/manage/new")
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", &asset_name),
            ("hostname", &asset_hostname),
            ("port", "22"),
            ("asset_type", "ssh"),
            ("status", "online"),
            ("ssh_username", "root"),
            ("ssh_auth_type", "private_key"),
            ("ssh_private_key", FAKE_KEY),
        ])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "Expected redirect after SSH create, got {}",
        status
    );

    let asset = read_asset_by_triplet(&mut conn, &asset_hostname, 22, "root")
        .await
        .expect("SSH asset must be persisted");
    assert_eq!(asset.asset_type, AssetType::Ssh);
    let cfg = asset.connection_config;
    assert_eq!(
        cfg.get("auth_type").and_then(|v| v.as_str()),
        Some("private_key"),
        "SSH connection_config must round-trip auth_type"
    );
    assert!(
        cfg.get("private_key").is_some(),
        "SSH private_key must be persisted (encrypted in prod, plaintext here -- vault is None in tests)"
    );
}

/// RDP + domain: the `domain` form field MUST land inside
/// `connection_config.domain`. This is the field the proxy's
/// `SessionConfig` already consumes -- this test closes the wiring gap.
#[tokio::test]
#[serial]
async fn test_create_rdp_with_domain_persists_in_connection_config() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("asset_proto_rdp_dom");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let csrf = app.generate_csrf_token();

    let asset_name = unique_name("rdp-dom-asset");
    let asset_hostname = format!("{}.dom.test", unique_name("host"));

    let response = app
        .server
        .post("/assets/manage/new")
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", &asset_name),
            ("hostname", &asset_hostname),
            ("port", "3389"),
            ("asset_type", "rdp"),
            ("status", "online"),
            ("ssh_username", "Administrator"),
            ("ssh_password", "Win-Pwd-2026!"),
            ("rdp_domain", "CORP"),
        ])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "Expected redirect after RDP+domain create, got {}",
        status
    );

    let asset = read_asset_by_triplet(&mut conn, &asset_hostname, 3389, "Administrator")
        .await
        .expect("RDP asset must be persisted");
    assert_eq!(
        asset
            .connection_config
            .get("domain")
            .and_then(|v| v.as_str()),
        Some("CORP"),
        "RDP domain must be persisted in connection_config.domain, got {}",
        asset.connection_config
    );
}

// =============================================================================
// Soft-delete scrub -- 1 test (defence-in-depth alongside DB CHECK)
// =============================================================================

/// Soft-delete via the web handler MUST scrub `connection_config` to
/// `{}` so the row cannot leak credentials even if an operator
/// inspects the table directly. The DB-level CHECK constraint
/// `assets_tombstone_no_secrets` enforces the same invariant
/// independently; this test pins the handler contract so a future
/// refactor that accidentally removes the scrub is caught at the
/// integration boundary as well.
#[tokio::test]
#[serial]
async fn test_soft_delete_purges_connection_config() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("sec11_purge");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let csrf = app.generate_csrf_token();

    let hostname = format!("{}.purge.test", unique_name("host"));
    let asset = insert_asset_with_config(
        &mut conn,
        &unique_name("sec11-purge-orig"),
        &hostname,
        22,
        AssetType::Ssh,
        "root",
        serde_json::json!({
            "username": "root",
            "auth_type": "password",
            "password": "MUST-BE-SCRUBBED",
        }),
    )
    .await;

    let response = app
        .server
        .post(&format!("/assets/manage/{}/delete", asset.uuid))
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[("csrf_token", csrf.as_str())])
        .await;
    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "delete must redirect, got {}",
        status
    );

    let after = read_asset_by_uuid(&mut conn, asset.uuid)
        .await
        .expect("soft-deleted row still exists in the table");
    assert!(after.is_deleted, "row must be soft-deleted");
    assert_eq!(
        after.connection_config,
        serde_json::json!({}),
        "connection_config must be scrubbed to {{}} on soft-delete, got {}",
        after.connection_config
    );
}

// =============================================================================
// Edit flow -- 1 test
// =============================================================================

/// Editing an existing RDP asset MUST also reject any attempt to inject
/// SSH key material via the form. This closes the symmetric attack
/// surface to `test_create_rdp_with_private_key_rejects_400_and_drops_field`.
#[tokio::test]
#[serial]
async fn test_edit_rdp_cannot_set_private_key_via_form() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("asset_proto_edit_rdp");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let csrf = app.generate_csrf_token();

    let hostname = format!("{}.edit.test", unique_name("host"));
    let asset = insert_asset_with_config(
        &mut conn,
        &unique_name("rdp-edit-target"),
        &hostname,
        3389,
        AssetType::Rdp,
        "Administrator",
        serde_json::json!({"username": "Administrator", "password": "initial"}),
    )
    .await;

    const CANARY: &str = "EDIT-CANARY-RDP-PK-MUST-BE-REJECTED";
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
            ("ssh_auth_type", "private_key"),
            ("ssh_private_key", CANARY),
        ])
        .await;
    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "edit must redirect (success OR error), got {}",
        status
    );
    let location = response
        .headers()
        .get(LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        location.ends_with("/edit"),
        "rejected edit must bounce back to /edit, got {}",
        location
    );

    let after = read_asset_by_uuid(&mut conn, asset.uuid)
        .await
        .expect("row must still exist");
    let cfg = after.connection_config.to_string();
    assert!(
        !cfg.contains(CANARY),
        "canary MUST NOT be persisted on RDP edit, got: {}",
        cfg
    );
    assert!(
        !cfg.contains("private_key"),
        "private_key key MUST NOT exist on the RDP row after edit, got: {}",
        cfg
    );
}

// =============================================================================
// ASS-02 / ASS-03 required-credential enforcement (issue #16) -- 6 tests
//
// Background: `build_connection_config` silently dropped empty
// credential inputs, so an RDP asset could be persisted with no
// password (CANARY-RDP-EMPTY-20260418). These tests pin the
// post-fix contract:
//
// - On CREATE: empty password / private_key MUST 4xx with a flash
//   error and persist NOTHING.
// - On EDIT: an empty input means "keep existing" (option A semantic),
//   never "wipe to empty". A non-empty input replaces the stored
//   value.
// - On EDIT render: the stored ciphertext MUST NEVER be sent back to
//   the browser (defence in depth + UX).
// =============================================================================

/// **CANARY-RDP-EMPTY-20260418** -- the BUG-10 / issue #16 regression.
/// POST a brand-new RDP asset with `ssh_password=""` and verify the
/// handler bounces the operator back to `/assets/new` with an explicit
/// ASS-03 error, and that NO row is persisted on the
/// (hostname, port, username) triplet.
#[tokio::test]
#[serial]
async fn test_create_rdp_with_empty_password_rejects_400_canary_empty_20260418() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("ass03_canary");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let csrf = app.generate_csrf_token();

    let asset_name = unique_name("CANARY-RDP-EMPTY-20260418");
    let asset_hostname = format!("{}.canary-empty.test", unique_name("host"));

    let response = app
        .server
        .post("/assets/manage/new")
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", &asset_name),
            ("hostname", &asset_hostname),
            ("port", "3389"),
            ("asset_type", "rdp"),
            ("status", "online"),
            ("ssh_username", "Administrator"),
            ("ssh_password", ""),
        ])
        .await;

    assert_status(&response, 303);
    let location = response
        .headers()
        .get(LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(
        location, "/assets/manage/new",
        "RDP+empty-password create must bounce to /assets/manage/new, got {}",
        location
    );

    let flash_cookie = response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|c| c.to_str().ok())
        .find(|c| c.contains("__vauban_flash"))
        .expect("rejection must set a flash cookie");
    assert!(
        flash_cookie.contains("__vauban_flash"),
        "expected a flash cookie carrying the ASS-03 rejection"
    );

    let persisted = read_asset_by_triplet(&mut conn, &asset_hostname, 3389, "Administrator").await;
    assert!(
        persisted.is_none(),
        "no row must be persisted when RDP password is empty, got: {:?}",
        persisted.map(|a| a.connection_config)
    );
}

/// SSH password-mode counterpart to the RDP canary above. Symmetric
/// rejection so we don't quietly create a useless SSH row either.
#[tokio::test]
#[serial]
async fn test_create_ssh_password_mode_with_empty_password_rejects_400() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("ass02_pwd_canary");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let csrf = app.generate_csrf_token();

    let asset_hostname = format!("{}.ass02-pwd.test", unique_name("host"));
    let response = app
        .server
        .post("/assets/manage/new")
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", &unique_name("ssh-empty-pwd")),
            ("hostname", &asset_hostname),
            ("port", "22"),
            ("asset_type", "ssh"),
            ("status", "online"),
            ("ssh_username", "root"),
            ("ssh_auth_type", "password"),
            ("ssh_password", ""),
        ])
        .await;

    assert_status(&response, 303);
    let location = response
        .headers()
        .get(LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(location, "/assets/manage/new");

    let persisted = read_asset_by_triplet(&mut conn, &asset_hostname, 22, "root").await;
    assert!(
        persisted.is_none(),
        "no row must be persisted when SSH password mode has empty password"
    );
}

/// SSH private-key-mode counterpart. An empty key submit must be
/// rejected with the matching ASS-02 error; nothing persisted.
#[tokio::test]
#[serial]
async fn test_create_ssh_key_mode_with_empty_private_key_rejects_400() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("ass02_key_canary");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let csrf = app.generate_csrf_token();

    let asset_hostname = format!("{}.ass02-key.test", unique_name("host"));
    let response = app
        .server
        .post("/assets/manage/new")
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", &unique_name("ssh-empty-key")),
            ("hostname", &asset_hostname),
            ("port", "22"),
            ("asset_type", "ssh"),
            ("status", "online"),
            ("ssh_username", "root"),
            ("ssh_auth_type", "private_key"),
            ("ssh_private_key", ""),
        ])
        .await;

    assert_status(&response, 303);
    let location = response
        .headers()
        .get(LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(location, "/assets/manage/new");

    let persisted = read_asset_by_triplet(&mut conn, &asset_hostname, 22, "root").await;
    assert!(
        persisted.is_none(),
        "no row must be persisted when SSH key mode has empty private_key"
    );
}

/// Option A semantic: editing an RDP asset with `ssh_password=""`
/// MUST preserve the previously stored password instead of wiping it.
/// We simulate the stored row carrying a recognisable plaintext sentinel
/// so we can assert it round-tripped untouched.
#[tokio::test]
#[serial]
async fn test_edit_rdp_with_blank_password_preserves_existing() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("ass03_keep_pwd");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let csrf = app.generate_csrf_token();

    let hostname = format!("{}.keep-pwd.test", unique_name("host"));
    const SENTINEL: &str = "KEEP-ME-ACROSS-EDIT-20260419";
    let asset = insert_asset_with_config(
        &mut conn,
        &unique_name("rdp-keep-target"),
        &hostname,
        3389,
        AssetType::Rdp,
        "Administrator",
        serde_json::json!({"username": "Administrator", "password": SENTINEL}),
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
            ("description", "operator only changed the description"),
        ])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "blank-password edit on a row with stored password must succeed, got {}",
        status
    );

    let after = read_asset_by_uuid(&mut conn, asset.uuid)
        .await
        .expect("row must still exist after edit");
    let cfg_str = after.connection_config.to_string();
    assert!(
        cfg_str.contains(SENTINEL),
        "blank password edit MUST preserve the stored password sentinel, got: {}",
        cfg_str
    );
    assert_eq!(
        after.status, "maintenance",
        "the non-credential field the operator actually changed must be persisted"
    );
}

/// Non-regression mirror of the previous test: a non-blank password on
/// the edit form must replace the stored value. Without this we'd be
/// unable to rotate credentials at all.
#[tokio::test]
#[serial]
async fn test_edit_rdp_with_new_password_replaces_existing() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("ass03_replace_pwd");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let csrf = app.generate_csrf_token();

    let hostname = format!("{}.replace-pwd.test", unique_name("host"));
    const OLD: &str = "OLD-PWD-MUST-BE-GONE-20260419";
    const NEW: &str = "NEW-PWD-MUST-BE-PRESENT-20260419";
    let asset = insert_asset_with_config(
        &mut conn,
        &unique_name("rdp-replace-target"),
        &hostname,
        3389,
        AssetType::Rdp,
        "Administrator",
        serde_json::json!({"username": "Administrator", "password": OLD}),
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
            ("ssh_password", NEW),
        ])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "credential rotation on edit must succeed, got {}",
        status
    );

    let after = read_asset_by_uuid(&mut conn, asset.uuid)
        .await
        .expect("row must still exist");
    let cfg_str = after.connection_config.to_string();
    // The new value either lands plaintext (no vault wired in tests) or
    // wrapped in a `v1:` ciphertext envelope; either way the OLD
    // plaintext sentinel must NOT remain visible.
    assert!(
        !cfg_str.contains(OLD),
        "old password sentinel must be evicted, got: {}",
        cfg_str
    );
    // Plaintext path (vault disabled) -- the most common test config.
    // If vault is wired, encryption hides the sentinel and we just
    // assert eviction of OLD above.
    if !cfg_str.contains("\"v1:") {
        assert!(
            cfg_str.contains(NEW),
            "new password sentinel must be persisted (plaintext path), got: {}",
            cfg_str
        );
    }
}

/// Defence-in-depth: the GET `/assets/{uuid}/edit` page MUST NOT echo
/// the stored credential ciphertext (or plaintext) back into the
/// `<input type="password">` `value=` attribute. Doing so would leak
/// secrets into browser DOM, autofill and history, and confuse
/// operators with a 200+ dot field unrelated to the original password.
#[tokio::test]
#[serial]
async fn test_edit_form_does_not_leak_stored_credential_into_html() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("ass03_no_leak");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let hostname = format!("{}.no-leak.test", unique_name("host"));
    const SENTINEL: &str = "NEVER-RENDER-IN-HTML-20260419";
    let asset = insert_asset_with_config(
        &mut conn,
        &unique_name("rdp-no-leak-target"),
        &hostname,
        3389,
        AssetType::Rdp,
        "Administrator",
        serde_json::json!({"username": "Administrator", "password": SENTINEL}),
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
        !body.contains(SENTINEL),
        "stored credential MUST NOT appear in the edit-form HTML, got body fragment:\n{}",
        body.chars()
            .skip_while(|c| *c != '<')
            .take(2000)
            .collect::<String>()
    );
    assert!(
        body.contains("Leave blank to keep current secret"),
        "edit form must surface the option-A hint when a credential is on \
         file. Wording was updated alongside the credential-neutral \
         input rebrand (Password -> Secret) — see \
         ASSET-CREDS-NO-SAVE-PROMPT-20260420."
    );
}

// =============================================================================
// SEC-12 / GitHub issue #20 — host-key state survives edit
//
// These tests exercise the structural invariant that POST /assets/{uuid}/edit
// MUST NOT silently drop fields the form does not expose. Before the fix,
// `update_asset_web` rebuilt `connection_config` from scratch via
// `build_connection_config` and only patched back password/private_key/
// passphrase via `merge_preserved_credentials`, which destroyed:
//
//   1. `ssh_host_key` (the pinned public key) — host-key pinning gone,
//      next connection silently re-pins whatever the server offers (TOFU bypass).
//   2. `ssh_host_key_fingerprint` (the SHA256 cache) — operator UI shows
//      "No Host Key Stored" after an unrelated edit.
//   3. `ssh_host_key_mismatch` (the MITM block flag) — set by
//      verify_ssh_host_key on a suspected attack; cleared by an unrelated
//      edit, which silently re-enables connections to the suspect host.
//
// The fix uses `compute_updated_connection_config` (overlay on existing).
// Anti-regression marker: SEC-12-EDIT-PRESERVE-20260420.
// =============================================================================

/// CARDINAL: a description-only edit MUST preserve `ssh_host_key`,
/// `ssh_host_key_fingerprint` AND the `ssh_host_key_mismatch` block flag.
/// A regression here means an unrelated UI tweak silently destroys
/// host-key pinning AND clears any pending MITM block.
#[tokio::test]
#[serial]
async fn test_edit_ssh_description_only_preserves_full_host_key_state() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("sec12_desc_edit");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let csrf = app.generate_csrf_token();

    let hostname = format!("{}.host-key-keep.test", unique_name("host"));
    const HOST_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINSEC12KEEPMEACROSSEDIT20260420";
    const FINGERPRINT: &str = "SHA256:SEC12KEEPMEACROSSEDIT20260420aaaaaaaaaaaaaaaaaaaaaa";
    const STORED_PWD: &str = "STORED-PWD-SEC12-20260420";

    let asset = insert_asset_with_config(
        &mut conn,
        &unique_name("ssh-host-key-keep"),
        &hostname,
        22,
        AssetType::Ssh,
        "alice",
        serde_json::json!({
            "username": "alice",
            "auth_type": "password",
            "password": STORED_PWD,
            "ssh_host_key": HOST_KEY,
            "ssh_host_key_fingerprint": FINGERPRINT,
            "ssh_host_key_mismatch": true,
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
            ("port", "22"),
            ("status", "online"),
            ("ssh_username", "alice"),
            ("ssh_auth_type", "password"),
            ("ssh_password", ""), // option A: keep stored password
            (
                "description",
                "operator only changed the description -- SEC-12",
            ),
        ])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "description-only edit must succeed, got {}",
        status
    );

    let after = read_asset_by_uuid(&mut conn, asset.uuid)
        .await
        .expect("row must still exist after edit");

    assert_eq!(
        after
            .connection_config
            .get("ssh_host_key")
            .and_then(|v| v.as_str()),
        Some(HOST_KEY),
        "SEC-12 regression: ssh_host_key was wiped by an unrelated edit. \
         Full config after edit: {}",
        after.connection_config
    );
    assert_eq!(
        after
            .connection_config
            .get("ssh_host_key_fingerprint")
            .and_then(|v| v.as_str()),
        Some(FINGERPRINT),
        "SEC-12 regression: ssh_host_key_fingerprint was wiped by an unrelated edit"
    );
    assert_eq!(
        after
            .connection_config
            .get("ssh_host_key_mismatch")
            .and_then(|v| v.as_bool()),
        Some(true),
        "SEC-12 regression: ssh_host_key_mismatch flag was cleared by an unrelated edit \
         (this would silently re-allow connections to a suspected MITM target)"
    );
    // And the stored password survived too (option A, defended by
    // test_edit_rdp_with_blank_password_preserves_existing for RDP).
    let cfg_str = after.connection_config.to_string();
    assert!(
        cfg_str.contains(STORED_PWD),
        "blank-password edit must preserve stored ciphertext, got: {}",
        cfg_str
    );
}

/// Rotating a credential (non-empty password input) MUST still preserve
/// the host-key pinning. The two operations are orthogonal and the edit
/// form has no input for host-key state.
#[tokio::test]
#[serial]
async fn test_edit_ssh_password_rotation_preserves_host_key_pinning() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("sec12_rotate_pwd");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let csrf = app.generate_csrf_token();

    let hostname = format!("{}.rotate-keep-key.test", unique_name("host"));
    const HOST_KEY: &str = "ssh-rsa AAAAB3SEC12ROTATE20260420";
    const FINGERPRINT: &str = "SHA256:SEC12ROTATEPWDKEEPHOSTKEY20260420bbbbbbbbbbb";
    const NEW_PWD: &str = "ROTATED-PWD-SEC12-20260420";

    let asset = insert_asset_with_config(
        &mut conn,
        &unique_name("ssh-rotate-keep-key"),
        &hostname,
        22,
        AssetType::Ssh,
        "alice",
        serde_json::json!({
            "username": "alice",
            "auth_type": "password",
            "password": "OLD-PWD-MUST-BE-GONE",
            "ssh_host_key": HOST_KEY,
            "ssh_host_key_fingerprint": FINGERPRINT,
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
            ("port", "22"),
            ("status", "online"),
            ("ssh_username", "alice"),
            ("ssh_auth_type", "password"),
            ("ssh_password", NEW_PWD),
        ])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "edit must succeed, got {}",
        status
    );

    let after = read_asset_by_uuid(&mut conn, asset.uuid).await.unwrap();

    assert_eq!(
        after
            .connection_config
            .get("ssh_host_key")
            .and_then(|v| v.as_str()),
        Some(HOST_KEY),
        "SEC-12 regression: ssh_host_key was wiped by a credential rotation"
    );
    assert_eq!(
        after
            .connection_config
            .get("ssh_host_key_fingerprint")
            .and_then(|v| v.as_str()),
        Some(FINGERPRINT),
        "SEC-12 regression: ssh_host_key_fingerprint was wiped by a credential rotation"
    );
    let cfg_str = after.connection_config.to_string();
    assert!(
        !cfg_str.contains("OLD-PWD-MUST-BE-GONE"),
        "old password sentinel must be evicted, got: {}",
        cfg_str
    );
    if !cfg_str.contains("\"v1:") {
        assert!(
            cfg_str.contains(NEW_PWD),
            "new password must be persisted (plaintext path), got: {}",
            cfg_str
        );
    }
}

/// Switching `auth_type` from password to private_key persists the new
/// credential AND preserves the host-key pinning. Mirrors the unit test
/// `test_compute_updated_ssh_switch_to_private_key` at the HTTP layer.
#[tokio::test]
#[serial]
async fn test_edit_ssh_switch_auth_type_preserves_host_key_pinning() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("sec12_switch_auth");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let csrf = app.generate_csrf_token();

    let hostname = format!("{}.switch-keep-key.test", unique_name("host"));
    const HOST_KEY: &str = "ecdsa-sha2-nistp256 AAAAESEC12SWITCH20260420";
    const FINGERPRINT: &str = "SHA256:SEC12SWITCHAUTHTYPE20260420ccccccccccccccccccc";
    const NEW_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\nSEC12-NEW-KEY-20260420\n-----END OPENSSH PRIVATE KEY-----";

    let asset = insert_asset_with_config(
        &mut conn,
        &unique_name("ssh-switch-keep-key"),
        &hostname,
        22,
        AssetType::Ssh,
        "alice",
        serde_json::json!({
            "username": "alice",
            "auth_type": "password",
            "password": "WAS-USING-PASSWORD",
            "ssh_host_key": HOST_KEY,
            "ssh_host_key_fingerprint": FINGERPRINT,
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
            ("port", "22"),
            ("status", "online"),
            ("ssh_username", "alice"),
            ("ssh_auth_type", "private_key"),
            ("ssh_private_key", NEW_KEY),
        ])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "edit must succeed, got {}",
        status
    );

    let after = read_asset_by_uuid(&mut conn, asset.uuid).await.unwrap();

    assert_eq!(
        after
            .connection_config
            .get("ssh_host_key")
            .and_then(|v| v.as_str()),
        Some(HOST_KEY),
        "SEC-12 regression: ssh_host_key was wiped by an auth_type switch"
    );
    assert_eq!(
        after
            .connection_config
            .get("ssh_host_key_fingerprint")
            .and_then(|v| v.as_str()),
        Some(FINGERPRINT),
        "SEC-12 regression: ssh_host_key_fingerprint was wiped by an auth_type switch"
    );
    assert_eq!(
        after
            .connection_config
            .get("auth_type")
            .and_then(|v| v.as_str()),
        Some("private_key"),
    );
}

/// Companion to the SEC-12 SSH tests: an edit that doesn't touch RDP-only
/// fields must preserve the stored Windows AD `domain`. Before the fix,
/// `build_connection_config` only emitted `domain` when the form re-sent
/// it (which it does in the browser, but a non-browser client or a JS-off
/// session could omit it), so editing such a row from a stripped-down
/// client silently wiped the domain. The new "absent ⇒ keep" semantic
/// closes that hole.
#[tokio::test]
#[serial]
async fn test_edit_rdp_absent_domain_preserves_stored_domain() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("sec12_rdp_keep_dom");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let csrf = app.generate_csrf_token();

    let hostname = format!("{}.rdp-keep-domain.test", unique_name("host"));
    const DOMAIN: &str = "CORP-SEC12-20260420";
    const STORED_PWD: &str = "RDP-PWD-KEEP-DOMAIN-20260420";

    let asset = insert_asset_with_config(
        &mut conn,
        &unique_name("rdp-keep-domain"),
        &hostname,
        3389,
        AssetType::Rdp,
        "Administrator",
        serde_json::json!({
            "username": "Administrator",
            "password": STORED_PWD,
            "domain": DOMAIN,
        }),
    )
    .await;

    // Submit an edit that omits `rdp_domain` entirely (simulates a
    // non-browser client or a future stripped-down quick-edit form).
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
            (
                "description",
                "domain field intentionally absent from the request body",
            ),
        ])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "edit must succeed, got {}",
        status
    );

    let after = read_asset_by_uuid(&mut conn, asset.uuid).await.unwrap();
    assert_eq!(
        after
            .connection_config
            .get("domain")
            .and_then(|v| v.as_str()),
        Some(DOMAIN),
        "absent rdp_domain field MUST preserve stored domain, got config: {}",
        after.connection_config
    );
    let cfg_str = after.connection_config.to_string();
    assert!(
        cfg_str.contains(STORED_PWD),
        "stored RDP password must round-trip on a domain-preserving edit, got: {}",
        cfg_str
    );
}

/// Companion: an explicit blank `rdp_domain` (operator deliberately
/// emptied the visible input) DOES clear the stored domain. This is the
/// only legitimate way to remove a domain via the UI.
#[tokio::test]
#[serial]
async fn test_edit_rdp_explicit_blank_domain_clears_stored_domain() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("sec12_rdp_clr_dom");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let csrf = app.generate_csrf_token();

    let hostname = format!("{}.rdp-clear-domain.test", unique_name("host"));
    let asset = insert_asset_with_config(
        &mut conn,
        &unique_name("rdp-clear-domain"),
        &hostname,
        3389,
        AssetType::Rdp,
        "Administrator",
        serde_json::json!({
            "username": "Administrator",
            "password": "ANY-PWD",
            "domain": "CORP",
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
            ("rdp_domain", ""), // explicit clear
        ])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "edit must succeed, got {}",
        status
    );

    let after = read_asset_by_uuid(&mut conn, asset.uuid).await.unwrap();
    assert!(
        after.connection_config.get("domain").is_none(),
        "explicit blank rdp_domain MUST clear stored domain, got config: {}",
        after.connection_config
    );
}
