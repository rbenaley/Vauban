//! Tier 3 — Policy resolution tests for the virtual "All assets"
//! group.
//!
//! These tests drive the real `vauban_web::services::access` API
//! against a real Postgres + an in-process `vauban-access` service, so
//! the AccessGuard re-check on the proxy side and the web-side decision
//! both flow through the exact same code path that production uses.
//!
//! Properties under test (one test per property unless noted):
//!
//! * **P20** — Dynamic property: a user with only a virtual SSH rule
//!   sees a brand-new asset on the very next call.
//! * **P21** — Soft-delete eviction: same setup, asset soft-deleted
//!   → next call excludes it.
//! * **P22** — Protocol filter honoured: virtual rule with
//!   `allowed_protocols = ['ssh']` excludes RDP assets.
//! * **P23** — `is_active = false` virtual rule → no assets returned.
//! * **P24** — Time-bounded validity: `valid_until < now()` virtual
//!   rule → no assets returned.
//! * **P25** — OR-aggregation safety: virtual rule (no MFA) + static
//!   rule on group Foo (MFA required) on asset X (in Foo)
//!   → `can_access_asset` returns `require_mfa = true`. Same for
//!   `require_approval`.
//! * **P26** — `min` aggregation on session duration: virtual rule
//!   (max = 3600s) + static rule (max = 900s) → result is 900s.
//! * **P27** — Inactive overlap: virtual rule (allowed) + static rule
//!   on Foo with `is_active = false` → access still granted via
//!   virtual.
//! * **P28** — Orphan asset coverage: `can_access_asset(user,
//!   asset_in_no_static_group, 'ssh')` → granted.
//! * **P29** — User-group isolation: two users in different
//!   user_groups don't share virtual rules.
//! * **P30** — AccessGuard parity: `CheckAccessByUuid` (proxy-side
//!   re-check) MUST agree with the web-side `can_access_asset`
//!   verdict when access flows through a virtual rule. Tested for
//!   both SSH and RDP.
//! * **P31** — Cross-protocol denial: a virtual rule narrowed to SSH
//!   denies RDP via the same proxy-side path.

use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::RunQueryDsl;
use serial_test::serial;
use shared::messages::ALL_ASSETS_GROUP_UUID;
use uuid::Uuid;
use vauban_web::models::asset::AssetType;
use vauban_web::services::access;

use crate::common::{TestApp, test_db};
use crate::fixtures::{
    add_user_to_vauban_group, create_admin_user, create_test_access_rule,
    create_test_access_rule_with_constraints, create_test_asset_group, create_test_asset_in_group,
    create_test_asset_in_group_with_type, create_test_user, create_test_vauban_group,
    get_asset_uuid, unique_name,
};

/// Lazily fetch the virtual asset_group's UUID.
fn virtual_uuid() -> Uuid {
    Uuid::parse_str(ALL_ASSETS_GROUP_UUID).expect("virtual UUID parses")
}

/// Insert an asset that belongs to NO static group ("orphan" from the
/// regular RBAC perspective). Returns the asset's database id.
async fn insert_orphan_asset(conn: &mut diesel_async::AsyncPgConnection, name: &str) -> i32 {
    use vauban_web::models::asset::NewAsset;
    use vauban_web::schema::assets;

    let new_asset = NewAsset {
        uuid: Uuid::new_v4(),
        name: name.to_string(),
        hostname: format!("{name}.local"),
        port: 22,
        asset_type: AssetType::Ssh,
        status: "online".to_string(),
        description: None,
        connection_config: serde_json::json!({}),
        created_by_id: None,
        connection_username: "root".to_string(),
    };
    diesel::insert_into(assets::table)
        .values(&new_asset)
        .returning(assets::id)
        .get_result(conn)
        .await
        .expect("orphan asset insert")
}

// =====================================================================
// P20 — Dynamic property
// =====================================================================

#[tokio::test]
#[serial]
async fn p20_dynamic_property_new_asset_visible_via_virtual_rule() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("p20_user");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;
    let ug = create_test_vauban_group(&mut conn, &unique_name("p20_ug")).await;
    add_user_to_vauban_group(&mut conn, user.user.id, &ug).await;

    let v = virtual_uuid();
    create_test_access_rule(&mut conn, &ug, &v, &["ssh"]).await;

    let before = access::list_accessible_asset_ids(
        &app._access_service.access_client,
        &mut conn,
        user.user.id,
    )
    .await
    .expect("list before");

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("p20_admin")).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("p20_ag")).await;
    let new_asset_id =
        create_test_asset_in_group(&mut conn, "p20-new-asset", admin.user.id, &ag).await;

    let after = access::list_accessible_asset_ids(
        &app._access_service.access_client,
        &mut conn,
        user.user.id,
    )
    .await
    .expect("list after");

    assert!(
        !before.contains(&new_asset_id),
        "new asset must not exist before insert"
    );
    assert!(
        after.contains(&new_asset_id),
        "virtual SSH rule must include the brand-new asset on the very next call"
    );

    test_db::cleanup(&mut conn).await;
}

// =====================================================================
// P21 — Soft-delete eviction
// =====================================================================

#[tokio::test]
#[serial]
async fn p21_soft_delete_evicts_asset_from_virtual_rule() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("p21_user");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;
    let ug = create_test_vauban_group(&mut conn, &unique_name("p21_ug")).await;
    add_user_to_vauban_group(&mut conn, user.user.id, &ug).await;
    create_test_access_rule(&mut conn, &ug, &virtual_uuid(), &["ssh"]).await;

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("p21_adm")).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("p21_ag")).await;
    let asset_id = create_test_asset_in_group(&mut conn, "p21-asset", admin.user.id, &ag).await;

    let visible_before = access::list_accessible_asset_ids(
        &app._access_service.access_client,
        &mut conn,
        user.user.id,
    )
    .await
    .expect("list");
    assert!(visible_before.contains(&asset_id));

    // Soft-delete the asset (mirror the production scrubbed payload).
    use vauban_web::schema::assets;
    diesel::update(assets::table.filter(assets::id.eq(asset_id)))
        .set((
            assets::is_deleted.eq(true),
            assets::deleted_at.eq(chrono::Utc::now()),
            assets::connection_config.eq(serde_json::json!({})),
        ))
        .execute(&mut conn)
        .await
        .expect("soft delete");

    let visible_after = access::list_accessible_asset_ids(
        &app._access_service.access_client,
        &mut conn,
        user.user.id,
    )
    .await
    .expect("list after");
    assert!(
        !visible_after.contains(&asset_id),
        "soft-deleted asset must be evicted from the virtual rule's set"
    );

    test_db::cleanup(&mut conn).await;
}

// =====================================================================
// P22 — Protocol filter honoured
// =====================================================================

#[tokio::test]
#[serial]
async fn p22_protocol_filter_excludes_rdp_assets() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("p22_user");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;
    let ug = create_test_vauban_group(&mut conn, &unique_name("p22_ug")).await;
    add_user_to_vauban_group(&mut conn, user.user.id, &ug).await;
    create_test_access_rule(&mut conn, &ug, &virtual_uuid(), &["ssh"]).await;

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("p22_adm")).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("p22_ag")).await;
    let ssh_id = create_test_asset_in_group_with_type(
        &mut conn,
        "p22-ssh",
        admin.user.id,
        &ag,
        AssetType::Ssh,
    )
    .await;
    let rdp_id = create_test_asset_in_group_with_type(
        &mut conn,
        "p22-rdp",
        admin.user.id,
        &ag,
        AssetType::Rdp,
    )
    .await;

    let visible = access::list_accessible_asset_ids(
        &app._access_service.access_client,
        &mut conn,
        user.user.id,
    )
    .await
    .expect("list");
    assert!(visible.contains(&ssh_id), "SSH asset must be visible");
    assert!(
        !visible.contains(&rdp_id),
        "RDP asset must be filtered out by SSH-only virtual rule"
    );

    test_db::cleanup(&mut conn).await;
}

// =====================================================================
// P23 — Inactive virtual rule yields nothing
// =====================================================================

#[tokio::test]
#[serial]
async fn p23_inactive_virtual_rule_returns_empty() {
    use vauban_web::schema::access_rules;

    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("p23_user");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;
    let ug = create_test_vauban_group(&mut conn, &unique_name("p23_ug")).await;
    add_user_to_vauban_group(&mut conn, user.user.id, &ug).await;

    let rule_uuid = create_test_access_rule(&mut conn, &ug, &virtual_uuid(), &["ssh"]).await;

    diesel::update(access_rules::table.filter(access_rules::uuid.eq(rule_uuid)))
        .set(access_rules::is_active.eq(false))
        .execute(&mut conn)
        .await
        .expect("deactivate");

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("p23_adm")).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("p23_ag")).await;
    let asset_id = create_test_asset_in_group(&mut conn, "p23-asset", admin.user.id, &ag).await;

    let visible = access::list_accessible_asset_ids(
        &app._access_service.access_client,
        &mut conn,
        user.user.id,
    )
    .await
    .expect("list");
    assert!(
        !visible.contains(&asset_id),
        "inactive virtual rule must not surface assets"
    );

    test_db::cleanup(&mut conn).await;
}

// =====================================================================
// P24 — Expired virtual rule yields nothing
// =====================================================================

#[tokio::test]
#[serial]
async fn p24_expired_virtual_rule_returns_empty() {
    use vauban_web::schema::access_rules;

    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("p24_user");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;
    let ug = create_test_vauban_group(&mut conn, &unique_name("p24_ug")).await;
    add_user_to_vauban_group(&mut conn, user.user.id, &ug).await;
    let rule_uuid = create_test_access_rule(&mut conn, &ug, &virtual_uuid(), &["ssh"]).await;

    let past = chrono::Utc::now() - chrono::Duration::days(7);
    diesel::update(access_rules::table.filter(access_rules::uuid.eq(rule_uuid)))
        .set(access_rules::valid_until.eq(past))
        .execute(&mut conn)
        .await
        .expect("expire");

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("p24_adm")).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("p24_ag")).await;
    let asset_id = create_test_asset_in_group(&mut conn, "p24-asset", admin.user.id, &ag).await;

    let visible = access::list_accessible_asset_ids(
        &app._access_service.access_client,
        &mut conn,
        user.user.id,
    )
    .await
    .expect("list");
    assert!(
        !visible.contains(&asset_id),
        "expired virtual rule must not surface assets"
    );

    test_db::cleanup(&mut conn).await;
}

// =====================================================================
// P25 — OR-aggregation safety on require_mfa / require_approval
// =====================================================================

#[tokio::test]
#[serial]
async fn p25_or_aggregation_mfa_and_approval() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("p25_user");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;
    let ug = create_test_vauban_group(&mut conn, &unique_name("p25_ug")).await;
    add_user_to_vauban_group(&mut conn, user.user.id, &ug).await;

    // Virtual rule: no MFA, no approval.
    create_test_access_rule(&mut conn, &ug, &virtual_uuid(), &["ssh"]).await;

    // Static rule on group Foo: MFA + approval required.
    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("p25_adm")).await;
    let foo = create_test_asset_group(&mut conn, &unique_name("p25_foo")).await;
    create_test_access_rule_with_constraints(&mut conn, &ug, &foo, &["ssh"], true, true, None)
        .await;

    let asset_id = create_test_asset_in_group(&mut conn, "p25-asset", admin.user.id, &foo).await;

    let result = access::can_access_asset(
        &app._access_service.access_client,
        &mut conn,
        user.user.id,
        asset_id,
        "ssh",
    )
    .await
    .expect("can_access_asset");

    assert!(result.allowed, "access must be allowed");
    assert!(
        result.require_mfa,
        "MFA must be required (OR-aggregation across virtual + static)"
    );
    assert!(
        result.require_approval,
        "approval must be required (OR-aggregation across virtual + static)"
    );

    test_db::cleanup(&mut conn).await;
}

// =====================================================================
// P26 — `min` aggregation on session duration
// =====================================================================

#[tokio::test]
#[serial]
async fn p26_min_aggregation_on_session_duration() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("p26_user");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;
    let ug = create_test_vauban_group(&mut conn, &unique_name("p26_ug")).await;
    add_user_to_vauban_group(&mut conn, user.user.id, &ug).await;

    // Virtual rule: max 3600s.
    create_test_access_rule_with_constraints(
        &mut conn,
        &ug,
        &virtual_uuid(),
        &["ssh"],
        false,
        false,
        Some(3600),
    )
    .await;

    // Static rule: max 900s.
    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("p26_adm")).await;
    let foo = create_test_asset_group(&mut conn, &unique_name("p26_foo")).await;
    create_test_access_rule_with_constraints(
        &mut conn,
        &ug,
        &foo,
        &["ssh"],
        false,
        false,
        Some(900),
    )
    .await;

    let asset_id = create_test_asset_in_group(&mut conn, "p26-asset", admin.user.id, &foo).await;

    let result = access::can_access_asset(
        &app._access_service.access_client,
        &mut conn,
        user.user.id,
        asset_id,
        "ssh",
    )
    .await
    .expect("can_access_asset");
    assert!(result.allowed);
    assert_eq!(
        result.max_session_duration,
        Some(900),
        "min aggregation must pick the shorter duration"
    );

    test_db::cleanup(&mut conn).await;
}

// =====================================================================
// P27 — Inactive overlap: access still granted via virtual
// =====================================================================

#[tokio::test]
#[serial]
async fn p27_inactive_static_overlap_does_not_block_virtual() {
    use vauban_web::schema::access_rules;

    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("p27_user");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;
    let ug = create_test_vauban_group(&mut conn, &unique_name("p27_ug")).await;
    add_user_to_vauban_group(&mut conn, user.user.id, &ug).await;
    create_test_access_rule(&mut conn, &ug, &virtual_uuid(), &["ssh"]).await;

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("p27_adm")).await;
    let foo = create_test_asset_group(&mut conn, &unique_name("p27_foo")).await;
    let static_rule_uuid = create_test_access_rule(&mut conn, &ug, &foo, &["ssh"]).await;
    diesel::update(access_rules::table.filter(access_rules::uuid.eq(static_rule_uuid)))
        .set(access_rules::is_active.eq(false))
        .execute(&mut conn)
        .await
        .expect("deactivate static");

    let asset_id = create_test_asset_in_group(&mut conn, "p27-asset", admin.user.id, &foo).await;

    let result = access::can_access_asset(
        &app._access_service.access_client,
        &mut conn,
        user.user.id,
        asset_id,
        "ssh",
    )
    .await
    .expect("can_access_asset");
    assert!(
        result.allowed,
        "virtual rule must grant access even when the static overlap is inactive"
    );

    test_db::cleanup(&mut conn).await;
}

// =====================================================================
// P28 — Orphan asset coverage
// =====================================================================

#[tokio::test]
#[serial]
async fn p28_orphan_asset_covered_by_virtual_rule() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("p28_user");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;
    let ug = create_test_vauban_group(&mut conn, &unique_name("p28_ug")).await;
    add_user_to_vauban_group(&mut conn, user.user.id, &ug).await;
    create_test_access_rule(&mut conn, &ug, &virtual_uuid(), &["ssh"]).await;

    let orphan_id = insert_orphan_asset(&mut conn, &unique_name("p28_orphan")).await;

    // List path
    let visible = access::list_accessible_asset_ids(
        &app._access_service.access_client,
        &mut conn,
        user.user.id,
    )
    .await
    .expect("list");
    assert!(
        visible.contains(&orphan_id),
        "orphan asset must be visible through virtual rule (list path)"
    );

    // Per-asset path
    let result = access::can_access_asset(
        &app._access_service.access_client,
        &mut conn,
        user.user.id,
        orphan_id,
        "ssh",
    )
    .await
    .expect("can_access_asset");
    assert!(
        result.allowed,
        "orphan asset must be reachable through virtual rule (per-asset path)"
    );

    test_db::cleanup(&mut conn).await;
}

// =====================================================================
// P29 — User-group isolation
// =====================================================================

#[tokio::test]
#[serial]
async fn p29_user_group_isolation_for_virtual_rules() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user_a = create_test_user(&mut conn, &app.auth_service, &unique_name("p29_a")).await;
    let user_b = create_test_user(&mut conn, &app.auth_service, &unique_name("p29_b")).await;
    let ug_a = create_test_vauban_group(&mut conn, &unique_name("p29_uga")).await;
    let ug_b = create_test_vauban_group(&mut conn, &unique_name("p29_ugb")).await;
    add_user_to_vauban_group(&mut conn, user_a.user.id, &ug_a).await;
    add_user_to_vauban_group(&mut conn, user_b.user.id, &ug_b).await;

    // Only ug_a has the virtual rule.
    create_test_access_rule(&mut conn, &ug_a, &virtual_uuid(), &["ssh"]).await;

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("p29_adm")).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("p29_ag")).await;
    let asset_id = create_test_asset_in_group(&mut conn, "p29-asset", admin.user.id, &ag).await;

    let visible_a = access::list_accessible_asset_ids(
        &app._access_service.access_client,
        &mut conn,
        user_a.user.id,
    )
    .await
    .expect("list a");
    let visible_b = access::list_accessible_asset_ids(
        &app._access_service.access_client,
        &mut conn,
        user_b.user.id,
    )
    .await
    .expect("list b");

    assert!(
        visible_a.contains(&asset_id),
        "user_a sees the asset via virtual rule"
    );
    assert!(
        !visible_b.contains(&asset_id),
        "user_b in a different group MUST NOT inherit user_a's virtual rule"
    );

    test_db::cleanup(&mut conn).await;
}

// =====================================================================
// P30 — AccessGuard parity (proxy-side re-check)
// =====================================================================

#[tokio::test]
#[serial]
async fn p30_accessguard_parity_for_virtual_rule() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("p30_user");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;
    let ug = create_test_vauban_group(&mut conn, &unique_name("p30_ug")).await;
    add_user_to_vauban_group(&mut conn, user.user.id, &ug).await;
    create_test_access_rule(&mut conn, &ug, &virtual_uuid(), &["ssh", "rdp"]).await;

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("p30_adm")).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("p30_ag")).await;
    let ssh_id = create_test_asset_in_group_with_type(
        &mut conn,
        "p30-ssh",
        admin.user.id,
        &ag,
        AssetType::Ssh,
    )
    .await;
    let rdp_id = create_test_asset_in_group_with_type(
        &mut conn,
        "p30-rdp",
        admin.user.id,
        &ag,
        AssetType::Rdp,
    )
    .await;
    let ssh_uuid = get_asset_uuid(&mut conn, ssh_id).await;
    let rdp_uuid = get_asset_uuid(&mut conn, rdp_id).await;

    let client = &app._access_service.access_client;

    for (asset_id, asset_uuid, protocol) in [(ssh_id, ssh_uuid, "ssh"), (rdp_id, rdp_uuid, "rdp")] {
        let web_decision =
            access::can_access_asset(client, &mut conn, user.user.id, asset_id, protocol)
                .await
                .expect("web can_access_asset");

        let guard_decision = client
            .check_access_by_uuid(
                &user.user.uuid.to_string(),
                &asset_uuid.to_string(),
                protocol,
            )
            .await
            .expect("proxy CheckAccessByUuid");

        assert_eq!(
            web_decision.allowed, guard_decision.allowed,
            "AccessGuard MUST agree with web-side decision for {protocol}"
        );
        assert!(
            guard_decision.allowed,
            "{protocol} access via virtual rule MUST be allowed"
        );
    }

    test_db::cleanup(&mut conn).await;
}

// =====================================================================
// P31 — Cross-protocol denial via AccessGuard
// =====================================================================

#[tokio::test]
#[serial]
async fn p31_accessguard_denies_wrong_protocol_on_virtual_rule() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("p31_user");
    let user = create_test_user(&mut conn, &app.auth_service, &username).await;
    let ug = create_test_vauban_group(&mut conn, &unique_name("p31_ug")).await;
    add_user_to_vauban_group(&mut conn, user.user.id, &ug).await;
    // SSH-only virtual rule.
    create_test_access_rule(&mut conn, &ug, &virtual_uuid(), &["ssh"]).await;

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("p31_adm")).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("p31_ag")).await;
    let rdp_id = create_test_asset_in_group_with_type(
        &mut conn,
        "p31-rdp",
        admin.user.id,
        &ag,
        AssetType::Rdp,
    )
    .await;
    let rdp_uuid = get_asset_uuid(&mut conn, rdp_id).await;

    let guard_decision = app
        ._access_service
        .access_client
        .check_access_by_uuid(&user.user.uuid.to_string(), &rdp_uuid.to_string(), "rdp")
        .await
        .expect("CheckAccessByUuid");
    assert!(
        !guard_decision.allowed,
        "RDP access via SSH-only virtual rule MUST be denied at the proxy gate"
    );

    test_db::cleanup(&mut conn).await;
}
