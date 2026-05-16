//! Lot A -- battle-tested suite for the privileged-port unprivilegisation
//! contract.
//!
//! Pin tests across the full handler -> template -> rendered HTML
//! pipeline that the local-forward port (LHS of `ssh -L`) is shifted
//! out of the kernel-restricted privileged range whenever the asset
//! port is `< 1024`. Without this contract, an operator on Linux /
//! macOS / Windows would need root to run the rendered SSH command
//! against a Modbus PLC (port 502).
//!
//! These tests exercise the WHOLE production path:
//!
//!   * [`vauban-web/src/services/iacs_tunnel/port_mapping.rs`] (the
//!     pure helper -- already covered by unit tests in the module),
//!   * [`vauban-web/src/handlers/web/iacs_tunnel.rs`] (where the
//!     helper is wired into the status handler),
//!   * [`vauban-web/src/templates/sessions/iacs_tunnel_status.rs`]
//!     (the rendered `ssh -L <local>:<host>:<port>` line),
//!   * [`vauban-web/templates/sessions/iacs_tunnel_status.html`]
//!     (the operator-visible HTML, including the privileged-port
//!     hint shown ONLY when `local_forward_port != target_port`).
//!
//! Each scenario opens a real `proxy_sessions` row via
//! `POST /assets/{uuid}/connect-iacs`, GETs the status page, and
//! greps the rendered HTML for the expected `-L <local>:<host>:<port>`
//! triplet. This is the closest we can get to an E2E test without
//! actually wiring up the proxy-iacs sshd against a fake EWS.

use crate::common::{TestApp, assertions::assert_status, unwrap_ok};
use crate::fixtures::{
    add_user_to_vauban_group, create_simple_admin_user, create_simple_user,
    create_test_access_rule, create_test_asset_group, create_test_asset_in_group_with_type,
    create_test_vauban_group, unique_name,
};
use axum::http::header::COOKIE;
use chrono::Utc;
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use vauban_web::models::asset::AssetType;
use vauban_web::services::iacs_tunnel::derive_local_forward_port;

// ===================================================================
// Helpers (same shape as iacs_connect_button_test.rs but allow a
// custom asset hostname / port so we can vary the upstream side).
// ===================================================================

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

async fn seed_active_ews(conn: &mut AsyncPgConnection, user_id: i32, label: &str) -> Uuid {
    let key_seed = Sha256::digest(format!("{}-{}", label, Uuid::new_v4()).as_bytes());
    let fp_hex = hex::encode(key_seed);
    let request_uuid = Uuid::new_v4();
    let ews_uuid = Uuid::new_v4();
    let now = Utc::now();

    diesel::sql_query(
        "INSERT INTO ews_onboarding_requests \
         (uuid, user_id, name, public_key, public_key_fingerprint, key_algo, \
          status, justification, decided_by_id, decided_at, created_at, updated_at) \
         VALUES ($1, $2, $3, 'ssh-ed25519 placeholder', $4, 'ed25519', \
                 'approved', 'seed-justification', $2, $5, $5, $5)",
    )
    .bind::<diesel::sql_types::Uuid, _>(request_uuid)
    .bind::<diesel::sql_types::Integer, _>(user_id)
    .bind::<diesel::sql_types::Text, _>(format!("ews_{}", &request_uuid.to_string()[..8]))
    .bind::<diesel::sql_types::Text, _>(&fp_hex)
    .bind::<diesel::sql_types::Timestamptz, _>(now)
    .execute(conn)
    .await
    .expect("insert seed ews_onboarding_requests");

    diesel::sql_query(
        "INSERT INTO ews \
         (uuid, request_uuid, user_id, name, public_key, public_key_fingerprint, \
          key_algo, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, 'ssh-ed25519 placeholder', $5, 'ed25519', $6, $6)",
    )
    .bind::<diesel::sql_types::Uuid, _>(ews_uuid)
    .bind::<diesel::sql_types::Uuid, _>(request_uuid)
    .bind::<diesel::sql_types::Integer, _>(user_id)
    .bind::<diesel::sql_types::Text, _>(format!("ews_{}", &ews_uuid.to_string()[..8]))
    .bind::<diesel::sql_types::Text, _>(&fp_hex)
    .bind::<diesel::sql_types::Timestamptz, _>(now)
    .execute(conn)
    .await
    .expect("insert seed ews");

    ews_uuid
}

/// Like the helper in `iacs_connect_button_test.rs` but lets the test
/// pin an EXACT `(hostname, port)` couple on the asset row -- needed
/// to exercise the LHS / RHS contract for non-default-port and
/// non-loopback hostnames.
///
/// Implementation: leverage the production fixture
/// `create_test_asset_in_group_with_type` (which inserts the asset
/// AND wires the `asset_asset_groups` link table correctly) then
/// UPDATE the row to override `hostname` and `port`.
///
/// The `asset_hostname_template` is interpolated with the asset's
/// UUID prefix so concurrent tests do not collide on the
/// `(hostname, port, username)` partial unique index. The template
/// can carry the literal `{u}` placeholder for the UUID prefix
/// (e.g. `"plc-{u}.factory.example"`); if the template has no
/// placeholder, the prefix is appended.
async fn seed_iacs_asset_with_explicit_target(
    conn: &mut AsyncPgConnection,
    admin_id: i32,
    user_id: i32,
    label: &str,
    asset_type: AssetType,
    asset_hostname_template: &str,
    asset_port: i32,
) -> (Uuid, String) {
    use vauban_web::schema::assets;

    let suffix = unique_name(label);
    let asset_group_uuid = create_test_asset_group(conn, &format!("{}-ag", suffix)).await;
    let user_group_uuid = create_test_vauban_group(conn, &format!("{}-ug", suffix)).await;
    add_user_to_vauban_group(conn, user_id, &user_group_uuid).await;

    let asset_id = create_test_asset_in_group_with_type(
        conn,
        &format!("{}-asset", suffix),
        admin_id,
        &asset_group_uuid,
        asset_type,
    )
    .await;

    // Read the auto-generated UUID and craft a unique hostname.
    let asset_uuid: Uuid = unwrap_ok!(
        assets::table
            .filter(assets::id.eq(asset_id))
            .select(assets::uuid)
            .first(conn)
            .await
    );
    let uuid_prefix = &asset_uuid.to_string()[..8];
    let asset_hostname = if asset_hostname_template.contains("{u}") {
        asset_hostname_template.replace("{u}", uuid_prefix)
    } else {
        format!("{}-{}", asset_hostname_template, uuid_prefix)
    };

    // Override hostname + port to whatever the scenario needs.
    diesel::update(assets::table.filter(assets::id.eq(asset_id)))
        .set((
            assets::hostname.eq(asset_hostname.clone()),
            assets::port.eq(asset_port),
        ))
        .execute(conn)
        .await
        .expect("UPDATE assets SET hostname, port");

    let proto = asset_type.as_str();
    let _ = create_test_access_rule(conn, &user_group_uuid, &asset_group_uuid, &[proto]).await;

    (asset_uuid, asset_hostname)
}

/// Open a tunnel session via the public endpoint and return the
/// rendered status page body (HTML).
async fn open_tunnel_and_fetch_status(
    app: &TestApp,
    asset_uuid: Uuid,
    user_uuid: &str,
    username: &str,
) -> (String, String) {
    let token = app
        .generate_test_token(user_uuid, username, false, false)
        .await;
    let csrf = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!("/assets/{}/connect-iacs", asset_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf),
        )
        .form(&[("csrf_token", csrf.as_str())])
        .await;
    let location = response
        .headers()
        .get("location")
        .map(|v| v.to_str().unwrap_or("").to_string())
        .expect("connect-iacs must set Location");
    let session_uuid_str = location
        .strip_prefix("/sessions/")
        .and_then(|tail| tail.split('/').next())
        .map(|s| s.to_string())
        .expect("Location format /sessions/{uuid}/iacs/status");

    let resp = app
        .server
        .get(&format!("/sessions/{}/iacs/status", session_uuid_str))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    assert_status(&resp, 200);
    let body = resp.text();
    (session_uuid_str, body)
}

// ===================================================================
// Battle-tested scenarios
// ===================================================================

/// Headline case: Modbus on the canonical IANA port 502. The local
/// bind MUST land on `50502` so the EWS does not need root.
#[tokio::test]
async fn lot_a_modbus_502_renders_local_50502() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_id = create_simple_admin_user(&mut conn, &unique_name("a_modbus_admin")).await;
    let username = unique_name("a_modbus_user");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await.to_string();

    let (asset_uuid, asset_hostname) = seed_iacs_asset_with_explicit_target(
        &mut conn,
        admin_id,
        user_id,
        "a_modbus",
        AssetType::IacsModbus,
        "plc-prod-{u}.factory.example",
        502,
    )
    .await;
    let _ews = seed_active_ews(&mut conn, user_id, "a_modbus").await;

    let (_session_uuid, body) =
        open_tunnel_and_fetch_status(app, asset_uuid, &user_uuid, &username).await;

    let needle = format!("ssh -i ~/.ssh/id_VAUBAN -L 50502:{asset_hostname}:502 ");
    assert!(
        body.contains(&needle),
        "Modbus 502 must render as `{needle}`. Body: {}",
        &body[..body.len().min(2500)]
    );
    // The privileged-port hint MUST appear (50502 != 502).
    assert!(
        body.contains("data-testid=\"iacs-tunnel-port-rewrite-hint\""),
        "the privileged-port hint must surface when the local port \
         differs from the upstream port (Modbus 502 -> 50502)"
    );
    // The hint MUST mention both ports for the operator's IACS
    // client configuration.
    assert!(
        body.contains("mbpoll -p 50502"),
        "the hint must include the canonical mbpoll example with \
         the rewritten port so the operator can copy-paste"
    );
}

/// MMS / IEC-61850: the other privileged IACS protocol Vauban
/// recognises. 102 -> 50102.
#[tokio::test]
async fn lot_a_mms_102_renders_local_50102() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_id = create_simple_admin_user(&mut conn, &unique_name("a_mms_admin")).await;
    let username = unique_name("a_mms_user");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await.to_string();

    // We use IacsTcp (the generic catch-all) and pin port 102 manually
    // to model an MMS deployment without a dedicated AssetType.
    let (asset_uuid, asset_hostname) = seed_iacs_asset_with_explicit_target(
        &mut conn,
        admin_id,
        user_id,
        "a_mms",
        AssetType::IacsTcp,
        "rtu-{u}.substation.example",
        102,
    )
    .await;
    let _ews = seed_active_ews(&mut conn, user_id, "a_mms").await;

    let (_session_uuid, body) =
        open_tunnel_and_fetch_status(app, asset_uuid, &user_uuid, &username).await;

    let needle = format!("-L 50102:{asset_hostname}:102 ");
    assert!(
        body.contains(&needle),
        "MMS 102 must render as `{needle}`. Body: {}",
        &body[..body.len().min(2500)]
    );
}

/// Non-privileged IACS protocol (OPC-UA 4840): the LHS MUST equal
/// the upstream port. No rewrite when no privilege is required.
#[tokio::test]
async fn lot_a_opcua_4840_no_rewrite() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_id = create_simple_admin_user(&mut conn, &unique_name("a_opcua_admin")).await;
    let username = unique_name("a_opcua_user");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await.to_string();

    let (asset_uuid, asset_hostname) = seed_iacs_asset_with_explicit_target(
        &mut conn,
        admin_id,
        user_id,
        "a_opcua",
        AssetType::IacsOpcua,
        "scada-{u}.example",
        4_840,
    )
    .await;
    let _ews = seed_active_ews(&mut conn, user_id, "a_opcua").await;

    let (_session_uuid, body) =
        open_tunnel_and_fetch_status(app, asset_uuid, &user_uuid, &username).await;

    let needle = format!("-L 4840:{asset_hostname}:4840 ");
    assert!(
        body.contains(&needle),
        "OPC-UA 4840 must render as `{needle}` (no rewrite). \
         Body: {}",
        &body[..body.len().min(2500)]
    );
    // The privileged-port hint MUST NOT appear (LP == TP).
    assert!(
        !body.contains("data-testid=\"iacs-tunnel-port-rewrite-hint\""),
        "the privileged-port hint MUST NOT appear when LP == TP \
         (here 4840 == 4840). It would only confuse the operator."
    );
}

/// Boundary at 1024: 1024 itself MUST NOT be rewritten (it is the
/// first user port), 1023 MUST be rewritten to 51023.
#[tokio::test]
async fn lot_a_boundary_1024_not_rewritten_1023_rewritten() {
    // 1024
    {
        let app = TestApp::spawn().await;
        let mut conn = app.get_conn().await;
        let admin_id = create_simple_admin_user(&mut conn, &unique_name("a_b1024_admin")).await;
        let username = unique_name("a_b1024_user");
        let user_id = create_simple_user(&mut conn, &username).await;
        let user_uuid = get_user_uuid(&mut conn, user_id).await.to_string();
        let (asset_uuid, asset_hostname) = seed_iacs_asset_with_explicit_target(
            &mut conn,
            admin_id,
            user_id,
            "a_b1024",
            AssetType::IacsTcp,
            "boundary-1024-{u}.example",
            1_024,
        )
        .await;
        let _ews = seed_active_ews(&mut conn, user_id, "a_b1024").await;
        let (_session_uuid, body) =
            open_tunnel_and_fetch_status(app, asset_uuid, &user_uuid, &username).await;
        let needle = format!("-L 1024:{asset_hostname}:1024 ");
        assert!(
            body.contains(&needle),
            "port 1024 (first user port) MUST NOT be rewritten -- \
             expected `{needle}`. Body excerpt: {}",
            &body[..body.len().min(1500)]
        );
    }

    // 1023 (last privileged port)
    {
        let app = TestApp::spawn().await;
        let mut conn = app.get_conn().await;
        let admin_id = create_simple_admin_user(&mut conn, &unique_name("a_b1023_admin")).await;
        let username = unique_name("a_b1023_user");
        let user_id = create_simple_user(&mut conn, &username).await;
        let user_uuid = get_user_uuid(&mut conn, user_id).await.to_string();
        let (asset_uuid, asset_hostname) = seed_iacs_asset_with_explicit_target(
            &mut conn,
            admin_id,
            user_id,
            "a_b1023",
            AssetType::IacsTcp,
            "boundary-1023-{u}.example",
            1_023,
        )
        .await;
        let _ews = seed_active_ews(&mut conn, user_id, "a_b1023").await;
        let (_session_uuid, body) =
            open_tunnel_and_fetch_status(app, asset_uuid, &user_uuid, &username).await;
        let needle = format!("-L 51023:{asset_hostname}:1023 ");
        assert!(
            body.contains(&needle),
            "port 1023 (last privileged port) MUST be rewritten to \
             51023 -- expected `{needle}`. Body excerpt: {}",
            &body[..body.len().min(1500)]
        );
    }
}

/// IPv6 literal hostname: the rendered command must NOT split on the
/// first colon (a regression that did would treat `2001:db8::1`
/// followed by `502` as `2001` host and `db8::1:502` port). The
/// handler uses `rsplit_once(':')` so the LAST colon is the
/// separator; the IPv6 literal is preserved verbatim.
///
/// Note: a square-bracketed literal is the canonical OpenSSH form
/// for IPv6 in `-L`. Vauban currently stores the asset hostname as
/// a bare literal -- the operator may need to bracket it manually
/// when copy-pasting. This test pins the current behavior so a
/// future change to add automatic bracketing is conscious.
#[tokio::test]
async fn lot_a_ipv6_asset_host_preserved_verbatim() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_id = create_simple_admin_user(&mut conn, &unique_name("a_ipv6_admin")).await;
    let username = unique_name("a_ipv6_user");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await.to_string();

    let (asset_uuid, asset_hostname) = seed_iacs_asset_with_explicit_target(
        &mut conn,
        admin_id,
        user_id,
        "a_ipv6",
        AssetType::IacsModbus,
        // IPv6 literal carrying internal colons -- the rsplit_once
        // parser must keep it intact. We do not append a UUID
        // suffix because the literal is unique enough across runs.
        "fd00::cafe:beef",
        502,
    )
    .await;
    let _ews = seed_active_ews(&mut conn, user_id, "a_ipv6").await;

    let (_session_uuid, body) =
        open_tunnel_and_fetch_status(app, asset_uuid, &user_uuid, &username).await;

    // The full triplet must appear with the IPv6 literal preserved.
    // Note: the helper appends a UUID suffix when no `{u}` placeholder
    // is present, so the actual asset hostname is
    // `fd00::cafe:beef-<uuid_prefix>`. The prefix has no internal
    // colons so the rsplit_once on `:` still cleanly separates the
    // port. The IPv6 portion (including its internal colons) is
    // preserved verbatim.
    let needle = format!("-L 50502:{asset_hostname}:502 ");
    assert!(
        body.contains(&needle),
        "IPv6 asset host must be preserved verbatim (no truncation \
         on internal `:` separators). Expected `{needle}`. Body: {}",
        &body[..body.len().min(2500)]
    );
    assert!(
        asset_hostname.starts_with("fd00::cafe:beef"),
        "the IPv6 literal must survive the UPDATE intact"
    );
}

/// The handler MUST NOT crash on a row whose `tunnel_target_addr`
/// is malformed (missing `:`). Defensive fallback to `127.0.0.1:4321`
/// keeps the page from 500-ing during a manual DB tweak. The shifted
/// port for 4321 (already user-range) stays 4321.
#[tokio::test]
async fn lot_a_malformed_target_addr_falls_back_safely() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_id = create_simple_admin_user(&mut conn, &unique_name("a_mal_admin")).await;
    let username = unique_name("a_mal_user");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await.to_string();
    let user_uuid_parsed: Uuid = user_uuid.parse().expect("user_uuid parse");

    let (asset_uuid, _asset_hostname) = seed_iacs_asset_with_explicit_target(
        &mut conn,
        admin_id,
        user_id,
        "a_mal",
        AssetType::IacsModbus,
        // The hostname is irrelevant -- we corrupt
        // `tunnel_target_addr` after session creation.
        "loopback-{u}.local",
        502,
    )
    .await;
    let _ews = seed_active_ews(&mut conn, user_id, "a_mal").await;

    let token = app
        .generate_test_token(&user_uuid, &username, false, false)
        .await;
    let csrf = app.generate_csrf_token();
    let response = app
        .server
        .post(&format!("/assets/{}/connect-iacs", asset_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf),
        )
        .form(&[("csrf_token", csrf.as_str())])
        .await;
    let location = response
        .headers()
        .get("location")
        .map(|v| v.to_str().unwrap_or("").to_string())
        .expect("connect-iacs must set Location");
    let session_uuid_str = location
        .strip_prefix("/sessions/")
        .and_then(|tail| tail.split('/').next())
        .map(|s| s.to_string())
        .expect("Location format /sessions/{uuid}/iacs/status");

    // Manually corrupt the row's tunnel_target_addr to simulate
    // a botched manual UPDATE.
    diesel::sql_query(
        "UPDATE proxy_sessions SET tunnel_target_addr = 'not-a-host-port' \
         WHERE uuid = $1",
    )
    .bind::<diesel::sql_types::Uuid, _>(Uuid::parse_str(&session_uuid_str).expect("uuid parse"))
    .execute(&mut conn)
    .await
    .expect("update tunnel_target_addr");

    let _ = user_uuid_parsed; // silence unused warning if compiler complains
    let resp = app
        .server
        .get(&format!("/sessions/{}/iacs/status", session_uuid_str))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    assert_status(&resp, 200);
    let body = resp.text();
    assert!(
        body.contains("ssh -i ~/.ssh/id_VAUBAN -L "),
        "the page must still render the ssh -L block on a malformed \
         tunnel_target_addr (defensive fallback)"
    );
}

/// Pin tests on the pure helper across the call graph: the value
/// rendered in the HTML matches `derive_local_forward_port(asset.port)`
/// for every IACS asset_type. This catches a refactor that wires the
/// LHS of `-L` to a different source than the helper.
#[tokio::test]
async fn lot_a_handler_uses_helper_for_every_iacs_asset_type() {
    for asset_type in [
        AssetType::IacsModbus,
        AssetType::IacsOpcua,
        AssetType::IacsProfinet,
        AssetType::IacsIec104,
    ] {
        let asset_port: i32 = asset_type
            .default_port()
            .expect("every IACS asset_type EXCEPT IacsTcp has a default_port");
        let expected_local = derive_local_forward_port(asset_port as u16);

        let app = TestApp::spawn().await;
        let mut conn = app.get_conn().await;
        let admin_id = create_simple_admin_user(
            &mut conn,
            &unique_name(&format!("a_{}_admin", asset_type.as_str())),
        )
        .await;
        let username = unique_name(&format!("a_{}_user", asset_type.as_str()));
        let user_id = create_simple_user(&mut conn, &username).await;
        let user_uuid = get_user_uuid(&mut conn, user_id).await.to_string();

        let (asset_uuid, asset_hostname) = seed_iacs_asset_with_explicit_target(
            &mut conn,
            admin_id,
            user_id,
            &format!("a_helper_{}", asset_type.as_str()),
            asset_type,
            "host-{u}.factory.example",
            asset_port,
        )
        .await;
        let _ews = seed_active_ews(
            &mut conn,
            user_id,
            &format!("a_helper_{}", asset_type.as_str()),
        )
        .await;

        let (_session_uuid, body) =
            open_tunnel_and_fetch_status(app, asset_uuid, &user_uuid, &username).await;

        let needle = format!("-L {expected_local}:{asset_hostname}:{asset_port} ");
        assert!(
            body.contains(&needle),
            "for {:?} (port {asset_port}) the rendered command must \
             contain `{}` (helper output {expected_local}). Body: {}",
            asset_type,
            needle,
            &body[..body.len().min(2500)]
        );
    }
}

/// Regression pin: the rendered command MUST NOT carry the legacy
/// `127.0.0.1` hardcoded RHS for an asset whose hostname is NOT
/// loopback. Without the Lot 3 + Lot A wiring fix, the bastion's
/// `validate_target` would reject every EWS request in production
/// (the bastion expects the per-session pinned asset host on the
/// `direct-tcpip` open).
#[tokio::test]
async fn lot_a_no_hardcoded_loopback_rhs_for_non_loopback_assets() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_id = create_simple_admin_user(&mut conn, &unique_name("a_noloop_admin")).await;
    let username = unique_name("a_noloop_user");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await.to_string();

    let (asset_uuid, asset_hostname) = seed_iacs_asset_with_explicit_target(
        &mut conn,
        admin_id,
        user_id,
        "a_noloop",
        AssetType::IacsModbus,
        // 10.42.0.7 is not a valid hostname for the unique index
        // ALONE across concurrent test runs; the helper appends a
        // UUID-derived suffix. The non-loopback property is
        // preserved (the IP literal stays in the prefix).
        "10.42.0.7",
        502,
    )
    .await;
    let _ews = seed_active_ews(&mut conn, user_id, "a_noloop").await;

    let (_session_uuid, body) =
        open_tunnel_and_fetch_status(app, asset_uuid, &user_uuid, &username).await;

    let needle = format!("-L 50502:{asset_hostname}:502 ");
    assert!(
        body.contains(&needle),
        "the rendered command must carry the asset's real (host, port) \
         pair on the RHS of `-L` -- expected `{needle}`. Body: {}",
        &body[..body.len().min(2500)]
    );
    // Defence in depth: explicitly assert that the rendered ssh -L
    // block (between the `-L ` and the next space) does NOT contain
    // `127.0.0.1` for this non-loopback asset.
    let cmd_block = body
        .split("ssh -i ~/.ssh/id_VAUBAN -L ")
        .nth(1)
        .and_then(|tail| tail.split(' ').next())
        .map(|s| s.to_string())
        .unwrap_or_default();
    assert!(
        !cmd_block.contains("127.0.0.1"),
        "the `-L <triplet>` portion must NOT mention 127.0.0.1 for a \
         non-loopback asset (regression guard for the pre-Lot-A \
         hardcoded RHS). got: {cmd_block}"
    );
}

/// Operator UX pin: the page renders the local-bind hint `127.0.0.1:<lp>`
/// in the prose so the operator immediately knows where to point
/// their IACS client without parsing the `ssh -L` triplet.
#[tokio::test]
async fn lot_a_status_page_advertises_local_bind_address() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_id = create_simple_admin_user(&mut conn, &unique_name("a_uxbind_admin")).await;
    let username = unique_name("a_uxbind_user");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await.to_string();

    let (asset_uuid, _asset_hostname) = seed_iacs_asset_with_explicit_target(
        &mut conn,
        admin_id,
        user_id,
        "a_uxbind",
        AssetType::IacsModbus,
        "plc-{u}.example",
        502,
    )
    .await;
    let _ews = seed_active_ews(&mut conn, user_id, "a_uxbind").await;

    let (_session_uuid, body) =
        open_tunnel_and_fetch_status(app, asset_uuid, &user_uuid, &username).await;

    assert!(
        body.contains("data-testid=\"iacs-tunnel-local-bind\""),
        "the status page must surface the local-bind hint via a \
         dedicated data-testid so the operator (and our tests) can \
         find it without grepping the ssh command"
    );
    assert!(
        body.contains(">127.0.0.1:50502<"),
        "the local-bind hint must render as `127.0.0.1:<lp>` so the \
         operator copies the right address into their IACS client"
    );
}
