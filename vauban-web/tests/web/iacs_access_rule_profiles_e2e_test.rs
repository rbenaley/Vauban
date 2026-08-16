//! Access-rule coverage for ADR 006 IACS profiles.
//!
//! The web form's "IACS (all industrial protocols)" checkbox expands
//! at save time. Rules persisted before ADR 006 still hold the
//! five-token snapshot (`iacs_modbus` … `iacs_tcp`). User-zone
//! `/assets` filters `asset_type IN allowed_protocols`, so EtherNet/IP
//! (and BACnet/SC, DNP3, IEC 61850) vanished until the listing path
//! unions that snapshot with the current catalogue.
//!
//! Layers:
//! * Unit / proptest -- `rule_grants_asset_type` / prefix helper
//! * Invariants -- listing uses `starts_with` + `is_legacy_all_iacs_rule`
//! * E2E -- GET `/assets` as `role:user` + `list_accessible_asset_ids`
//! * Battle -- concurrent listing under a legacy-all rule
//! * Attack -- a Modbus-only rule must not reveal an ENIP asset

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use axum::http::header::COOKIE;
use serial_test::serial;
use shared::messages::ALL_ASSETS_GROUP_UUID;
use uuid::Uuid;
use vauban_web::models::asset::AssetType;
use vauban_web::services::access;

use crate::common::{TestApp, assertions::*, test_db};
use crate::fixtures::{
    add_user_to_vauban_group, create_admin_user, create_test_access_rule, create_test_asset_group,
    create_test_asset_in_group_with_type, create_test_user, create_test_vauban_group, unique_name,
};

const LEGACY_ALL_IACS: &[&str] = &[
    "iacs_modbus",
    "iacs_opcua",
    "iacs_profinet",
    "iacs_iec104",
    "iacs_tcp",
];

fn virtual_uuid() -> Uuid {
    Uuid::parse_str(ALL_ASSETS_GROUP_UUID).expect("virtual UUID parses")
}

fn listing_src() -> &'static str {
    include_str!("../../src/services/access.rs")
}

#[test]
fn list_accessible_asset_ids_uses_prefix_for_all_iacs_rules() {
    let src = listing_src();
    assert!(
        src.contains("is_legacy_all_iacs_rule"),
        "list_accessible_asset_ids MUST detect the durable all-IACS snapshot"
    );
    assert!(
        src.contains("starts_with(assets.asset_type, 'iacs_')"),
        "all-IACS listing MUST use starts_with so a future iacs_* \
         profile is visible without a catalogue edit"
    );
    assert!(
        src.contains("is_iacs_applicative_protocol"),
        "IT tokens (ssh/rdp) on an all-IACS rule must stay exact-match"
    );
    assert!(
        !src.contains("expand_legacy_all_iacs_protocols"),
        "listing must not union a closed IACS_APPLICATIVE_PROTOCOLS slice"
    );
}

#[test]
fn migration_upgrades_legacy_all_snapshot_only() {
    let up = include_str!(
        "../../../vauban-db/migrations/20260817160000_iacs_access_rule_profiles/up.sql"
    );
    for token in [
        "iacs_enip",
        "iacs_bacnet_sc",
        "iacs_dnp3",
        "iacs_iec61850",
        "iacs_modbus",
        "iacs_opcua",
        "iacs_profinet",
        "iacs_iec104",
        "iacs_tcp",
    ] {
        assert!(
            up.contains(token),
            "access-rule profile migration must mention {token}"
        );
    }
    assert!(
        up.contains("AND NOT"),
        "upgrade must skip rows that already carry the ADR 006 tokens"
    );
}

#[tokio::test]
#[serial]
async fn e2e_legacy_all_iacs_rule_shows_enip_on_user_zone_assets() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user = create_test_user(&mut conn, &app.auth_service, &unique_name("enip_vis_u")).await;
    let ug = create_test_vauban_group(&mut conn, &unique_name("enip_vis_ug")).await;
    add_user_to_vauban_group(&mut conn, user.user.id, &ug).await;
    create_test_access_rule(&mut conn, &ug, &virtual_uuid(), LEGACY_ALL_IACS).await;

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("enip_vis_a")).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("enip_vis_ag")).await;
    let enip_name = unique_name("enip-visible");
    let enip_id = create_test_asset_in_group_with_type(
        &mut conn,
        &enip_name,
        admin.user.id,
        &ag,
        AssetType::IacsEnip,
    )
    .await;

    let visible = access::list_accessible_asset_ids(
        &app._access_service.access_client,
        &mut conn,
        user.user.id,
    )
    .await
    .expect("list");
    assert!(
        visible.contains(&enip_id),
        "legacy-all IACS rule must include an EtherNet/IP asset in list_accessible_asset_ids"
    );

    let resp = app
        .server
        .get("/assets")
        .add_header(COOKIE, format!("access_token={}", user.token))
        .await;
    assert_status(&resp, 200);
    let body = resp.text();
    assert!(
        body.contains(&enip_name),
        "GET /assets must render the EtherNet/IP asset when the rule \
         is the pre-ADR-006 IACS master snapshot; body follows:\n{body}"
    );

    test_db::cleanup(&mut conn).await;
}

#[tokio::test]
#[serial]
async fn e2e_current_all_iacs_rule_shows_every_adr006_profile() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user = create_test_user(&mut conn, &app.auth_service, &unique_name("adr6_vis_u")).await;
    let ug = create_test_vauban_group(&mut conn, &unique_name("adr6_vis_ug")).await;
    add_user_to_vauban_group(&mut conn, user.user.id, &ug).await;
    create_test_access_rule(
        &mut conn,
        &ug,
        &virtual_uuid(),
        shared::access_guard::IACS_APPLICATIVE_PROTOCOLS,
    )
    .await;

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("adr6_vis_a")).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("adr6_vis_ag")).await;

    let mut ids = Vec::new();
    for (label, ty) in [
        ("enip", AssetType::IacsEnip),
        ("bsc", AssetType::IacsBacnetSc),
        ("dnp3", AssetType::IacsDnp3),
        ("61850", AssetType::IacsIec61850),
    ] {
        let name = unique_name(&format!("adr6-{label}"));
        let id =
            create_test_asset_in_group_with_type(&mut conn, &name, admin.user.id, &ag, ty).await;
        ids.push((name, id));
    }

    let visible = access::list_accessible_asset_ids(
        &app._access_service.access_client,
        &mut conn,
        user.user.id,
    )
    .await
    .expect("list");
    for (name, id) in &ids {
        assert!(
            visible.contains(id),
            "current all-IACS rule must include {name}"
        );
    }

    test_db::cleanup(&mut conn).await;
}

/// A Modbus-only grant must not enumerate EtherNet/IP assets on
/// `/assets`. Expanding "any iacs_*" to every current profile would
/// let a narrow IPC rule leak the new catalogue.
#[tokio::test]
#[serial]
async fn attack_modbus_only_rule_does_not_reveal_enip_on_assets() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user = create_test_user(&mut conn, &app.auth_service, &unique_name("enip_hid_u")).await;
    let ug = create_test_vauban_group(&mut conn, &unique_name("enip_hid_ug")).await;
    add_user_to_vauban_group(&mut conn, user.user.id, &ug).await;
    create_test_access_rule(&mut conn, &ug, &virtual_uuid(), &["iacs_modbus"]).await;

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("enip_hid_a")).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("enip_hid_ag")).await;
    let enip_name = unique_name("enip-hidden");
    let enip_id = create_test_asset_in_group_with_type(
        &mut conn,
        &enip_name,
        admin.user.id,
        &ag,
        AssetType::IacsEnip,
    )
    .await;
    let modbus_name = unique_name("modbus-shown");
    let modbus_id = create_test_asset_in_group_with_type(
        &mut conn,
        &modbus_name,
        admin.user.id,
        &ag,
        AssetType::IacsModbus,
    )
    .await;

    let visible = access::list_accessible_asset_ids(
        &app._access_service.access_client,
        &mut conn,
        user.user.id,
    )
    .await
    .expect("list");
    assert!(
        visible.contains(&modbus_id),
        "Modbus asset must stay visible"
    );
    assert!(
        !visible.contains(&enip_id),
        "Modbus-only rule must not reveal an EtherNet/IP asset"
    );

    let resp = app
        .server
        .get("/assets")
        .add_header(COOKIE, format!("access_token={}", user.token))
        .await;
    assert_status(&resp, 200);
    let body = resp.text();
    assert!(body.contains(&modbus_name), "Modbus row must render");
    assert!(
        !body.contains(&enip_name),
        "GET /assets must not render the EtherNet/IP asset under a \
         Modbus-only rule; body follows:\n{body}"
    );

    test_db::cleanup(&mut conn).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn battle_legacy_all_iacs_listing_under_contention() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user = create_test_user(&mut conn, &app.auth_service, &unique_name("enip_bat_u")).await;
    let ug = create_test_vauban_group(&mut conn, &unique_name("enip_bat_ug")).await;
    add_user_to_vauban_group(&mut conn, user.user.id, &ug).await;
    create_test_access_rule(&mut conn, &ug, &virtual_uuid(), LEGACY_ALL_IACS).await;

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("enip_bat_a")).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("enip_bat_ag")).await;
    let enip_id = create_test_asset_in_group_with_type(
        &mut conn,
        &unique_name("enip-battle"),
        admin.user.id,
        &ag,
        AssetType::IacsEnip,
    )
    .await;

    let user_id = user.user.id;
    let access_client = app._access_service.access_client.clone();
    let pool = app.db_pool.clone();
    let barrier = Arc::new(tokio::sync::Barrier::new(8));
    let mut joins = Vec::new();
    for _ in 0..8 {
        let barrier = Arc::clone(&barrier);
        let access_client = access_client.clone();
        let pool = pool.clone();
        joins.push(tokio::spawn(async move {
            let mut c = pool.get().await.expect("conn");
            barrier.wait().await;
            access::list_accessible_asset_ids(&access_client, &mut c, user_id).await
        }));
    }

    for join in joins {
        let visible = join.await.expect("task").expect("list");
        assert!(
            visible.contains(&enip_id),
            "every concurrent listing must keep the EtherNet/IP asset"
        );
    }

    test_db::cleanup(&mut conn).await;
}
