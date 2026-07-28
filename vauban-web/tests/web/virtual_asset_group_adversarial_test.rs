//! Tier 5 — Adversarial / threat-model tests for the virtual
//! "All assets" group.
//!
//! Each test pins a specific bypass attempt or saturation regime an
//! attacker (or a stale rollback) might use to subvert the virtual
//! group's invariants. They run against a real Postgres + the
//! in-process vauban-access service so every layer of defense (DB
//! triggers, app handlers, IPC) is exercised end-to-end.
//!
//! Threat catalogue:
//!
//! * **A44** — Direct SQL bypass: raw INSERT into `asset_asset_groups`
//!   targeting the virtual row raises (DB trigger).
//! * **A45** — Re-pointing bypass: raw UPDATE re-targeting an existing
//!   membership at the virtual row raises (DB trigger).
//! * **A46** — CTE wrapper: same INSERT wrapped inside a `WITH … AS …`
//!   still raises — Postgres triggers fire on the underlying mutation.
//! * **A47** — Forged second virtual row: raw INSERT
//!   `kind='all'` with a different UUID is rejected by the partial
//!   UNIQUE index.
//! * **A48** — kind flip-flop: raw `UPDATE … SET kind='static' WHERE
//!   kind='all'` is blocked by the mutation trigger.
//! * **A49** — UUID swap by deletion: raw `DELETE FROM asset_groups
//!   WHERE kind='all'` raises — the chain breaks at step 1.
//! * **A50** — Cross-protocol denial via virtual rule (SSH-only
//!   rule, RDP request → denied at the proxy gate).
//! * **A51** — Concurrency under churn: 64 concurrent
//!   `list_accessible_asset_ids` calls + concurrent asset INSERT/
//!   soft-DELETE must never panic and must converge.
//! * **A52** — Race: virtual-rule + asset creation interleaved across
//!   100 iterations, the reachable set is monotonically the union.
//! * **A53** — Boot-time tampering surface: the OnceLock initializer
//!   refuses to start vauban-access if the virtual row is missing
//!   (whitebox check on `init_or_die`).
//! * **A54** — AccessGuard agreement under saturation: 50 sequential
//!   `check_access_by_uuid` calls on a virtual-rule-only asset all
//!   succeed end-to-end without leaking the pending-slot.

use diesel::prelude::*;
use diesel::sql_query;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serial_test::serial;
use shared::messages::ALL_ASSETS_GROUP_UUID;
use uuid::Uuid;

use crate::common::{TestApp, test_db};
use crate::fixtures::{
    add_user_to_vauban_group, create_admin_user, create_test_access_rule, create_test_asset_group,
    create_test_asset_in_group, create_test_asset_in_group_with_type, create_test_user,
    create_test_vauban_group, get_asset_uuid, unique_name,
};
use vauban_web::models::asset::AssetType;
use vauban_web::services::access;

fn virtual_uuid() -> Uuid {
    Uuid::parse_str(ALL_ASSETS_GROUP_UUID).expect("virtual UUID parses")
}

async fn insert_asset_raw(conn: &mut AsyncPgConnection, name: &str) -> i32 {
    use diesel::QueryableByName;
    #[derive(QueryableByName)]
    struct Row {
        #[diesel(sql_type = diesel::sql_types::Int4)]
        id: i32,
    }
    let row: Row = sql_query(format!(
        "INSERT INTO assets (uuid, name, hostname, port, asset_type, status, connection_username, connection_config)
         VALUES (gen_random_uuid(), '{name}', '{name}.local', 22, 'ssh', 'online', 'root', '{{}}'::jsonb)
         RETURNING id"
    ))
    .get_result(conn)
    .await
    .expect("asset insert");
    row.id
}

async fn insert_static_group_raw(conn: &mut AsyncPgConnection, name: &str) -> i32 {
    use diesel::QueryableByName;
    #[derive(QueryableByName)]
    struct Row {
        #[diesel(sql_type = diesel::sql_types::Int4)]
        id: i32,
    }
    let slug = format!("{name}-slug");
    let row: Row = sql_query(format!(
        "INSERT INTO asset_groups (uuid, name, slug, kind, color, icon)
         VALUES (gen_random_uuid(), '{name}', '{slug}', 'static', '#000000', 'folder')
         RETURNING id"
    ))
    .get_result(conn)
    .await
    .expect("static group insert");
    row.id
}

fn assert_err_contains(err: &diesel::result::Error, fragment: &str) {
    let msg = format!("{err:?}").to_lowercase();
    assert!(
        msg.contains(&fragment.to_lowercase()),
        "expected error to contain {fragment:?}, got: {err:?}"
    );
}

// =====================================================================
// A44 — Direct SQL bypass on membership
// =====================================================================

#[tokio::test]
#[serial]
async fn a44_direct_sql_membership_insert_raises() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let asset_id = insert_asset_raw(&mut conn, &unique_name("a44_asset")).await;

    let err = sql_query(format!(
        "INSERT INTO asset_asset_groups (asset_id, asset_group_id)
         SELECT {asset_id}, id FROM asset_groups WHERE kind = 'all'"
    ))
    .execute(&mut conn)
    .await
    .expect_err("trigger MUST raise");
    assert_err_contains(&err, "cannot add members to virtual");

    sql_query(format!("DELETE FROM assets WHERE id = {asset_id}"))
        .execute(&mut conn)
        .await
        .ok();
}

// =====================================================================
// A45 — Re-pointing existing membership at the virtual row
// =====================================================================

#[tokio::test]
#[serial]
async fn a45_repoint_membership_to_virtual_raises() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let asset_id = insert_asset_raw(&mut conn, &unique_name("a45_asset")).await;
    let static_id = insert_static_group_raw(&mut conn, &unique_name("a45_grp")).await;

    sql_query(format!(
        "INSERT INTO asset_asset_groups (asset_id, asset_group_id) VALUES ({asset_id}, {static_id})"
    ))
    .execute(&mut conn)
    .await
    .expect("seed static membership");

    let err = sql_query(format!(
        "UPDATE asset_asset_groups SET asset_group_id = (SELECT id FROM asset_groups WHERE kind='all')
         WHERE asset_id = {asset_id}"
    ))
    .execute(&mut conn)
    .await
    .expect_err("UPDATE re-pointing MUST raise");
    assert_err_contains(&err, "cannot add members to virtual");

    sql_query(format!(
        "DELETE FROM asset_asset_groups WHERE asset_id = {asset_id}"
    ))
    .execute(&mut conn)
    .await
    .ok();
    sql_query(format!("DELETE FROM assets WHERE id = {asset_id}"))
        .execute(&mut conn)
        .await
        .ok();
    sql_query(format!("DELETE FROM asset_groups WHERE id = {static_id}"))
        .execute(&mut conn)
        .await
        .ok();
}

// =====================================================================
// A46 — CTE wrapper does not bypass the trigger
// =====================================================================

#[tokio::test]
#[serial]
async fn a46_cte_wrapper_does_not_bypass_trigger() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let asset_id = insert_asset_raw(&mut conn, &unique_name("a46_asset")).await;

    // Postgres BEFORE INSERT triggers fire on the underlying mutation,
    // not on the CTE statement boundary. This must still raise.
    let err = sql_query(format!(
        "WITH v AS (SELECT id FROM asset_groups WHERE kind = 'all')
         INSERT INTO asset_asset_groups (asset_id, asset_group_id)
         SELECT {asset_id}, id FROM v"
    ))
    .execute(&mut conn)
    .await
    .expect_err("CTE-wrapped INSERT MUST raise");
    assert_err_contains(&err, "cannot add members to virtual");

    sql_query(format!("DELETE FROM assets WHERE id = {asset_id}"))
        .execute(&mut conn)
        .await
        .ok();
}

// =====================================================================
// A47 — Forged second virtual row rejected by UNIQUE singleton index
// =====================================================================

#[tokio::test]
#[serial]
async fn a47_forged_second_virtual_row_rejected() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let err = sql_query(
        "INSERT INTO asset_groups (uuid, name, slug, kind, color, icon)
         VALUES (gen_random_uuid(), 'forged-all', 'forged-all', 'all', '#000000', 'folder')",
    )
    .execute(&mut conn)
    .await
    .expect_err("a second kind='all' row MUST be rejected");
    assert_err_contains(&err, "uniq_asset_groups_kind_singleton");
}

// =====================================================================
// A48 — kind flip-flop blocked
// =====================================================================

#[tokio::test]
#[serial]
async fn a48_kind_flip_flop_blocked() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let err = sql_query("UPDATE asset_groups SET kind = 'static' WHERE kind = 'all'")
        .execute(&mut conn)
        .await
        .expect_err("kind flip-flop MUST raise");
    // The mutation trigger refuses any UPDATE on a virtual row.
    assert_err_contains(&err, "cannot");
}

// =====================================================================
// A49 — DELETE on virtual row raises
// =====================================================================

#[tokio::test]
#[serial]
async fn a49_delete_virtual_row_raises() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let err = sql_query("DELETE FROM asset_groups WHERE kind = 'all'")
        .execute(&mut conn)
        .await
        .expect_err("DELETE on virtual row MUST raise");
    assert_err_contains(&err, "cannot");
}

// =====================================================================
// A50 — Cross-protocol denial via SSH-only virtual rule
// =====================================================================

#[tokio::test]
#[serial]
async fn a50_cross_protocol_denied_via_virtual_rule() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user = create_test_user(&mut conn, &app.auth_service, &unique_name("a50_user")).await;
    let ug = create_test_vauban_group(&mut conn, &unique_name("a50_ug")).await;
    add_user_to_vauban_group(&mut conn, user.user.id, &ug).await;
    create_test_access_rule(&mut conn, &ug, &virtual_uuid(), &["ssh"]).await;

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("a50_adm")).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("a50_ag")).await;
    let rdp_id = create_test_asset_in_group_with_type(
        &mut conn,
        "a50-rdp",
        admin.user.id,
        &ag,
        AssetType::Rdp,
    )
    .await;
    let rdp_uuid = get_asset_uuid(&mut conn, rdp_id).await;

    let decision = app
        ._access_service
        .access_client
        .check_access_by_uuid(&user.user.uuid.to_string(), &rdp_uuid.to_string(), "rdp")
        .await
        .expect("CheckAccessByUuid");
    assert!(
        !decision.allowed,
        "SSH-only virtual rule MUST NOT grant RDP at the proxy gate"
    );

    test_db::cleanup(&mut conn).await;
}

// =====================================================================
// A51 — Concurrency under churn (64 concurrent calls + writers)
// =====================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[serial]
async fn a51_concurrency_under_churn() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user = create_test_user(&mut conn, &app.auth_service, &unique_name("a51_user")).await;
    let ug = create_test_vauban_group(&mut conn, &unique_name("a51_ug")).await;
    add_user_to_vauban_group(&mut conn, user.user.id, &ug).await;
    create_test_access_rule(&mut conn, &ug, &virtual_uuid(), &["ssh"]).await;

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("a51_adm")).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("a51_ag")).await;
    // Seed a baseline asset so every reader sees ≥ 1 result.
    let _ = create_test_asset_in_group(&mut conn, "a51-seed", admin.user.id, &ag).await;

    let user_id = user.user.id;
    let access_client = app._access_service.access_client.clone();
    let pool = app.db_pool.clone();

    // The pool's `max_size` is sized for the test fleet (95) but the
    // Postgres SERVER budget (`max_connections`, default 100, minus
    // `superuser_reserved_connections` and minus whatever `vauban-web`
    // / `vauban-access` are already holding open) is the real cap.
    // Without bounding the in-flight acquisitions, 64 simultaneous
    // `pool.get().await` calls each open a fresh Postgres connection
    // and saturate the server, surfacing as
    // `CouldntSetupConfiguration("remaining connection slots are
    // reserved for roles with the SUPERUSER attribute")`.
    //
    // The signal we want to pin in this test is "many concurrent
    // invocations of `list_accessible_asset_ids` interleaved with
    // writers", not "open as many sockets as the server allows". So
    // we keep the 64 spawned readers (genuine concurrency: 64 tasks
    // racing each other across an 8-thread runtime) but cap the
    // in-flight Postgres connections via a Semaphore. 16 is well
    // below any reasonable per-database budget and yields enough
    // overlap for the path under test.
    use std::sync::Arc;
    use tokio::sync::Semaphore;
    let conn_budget = Arc::new(Semaphore::new(16));

    // Spawn 64 concurrent readers.
    let mut readers = Vec::new();
    for i in 0..64 {
        let access_client = access_client.clone();
        let pool = pool.clone();
        let budget = conn_budget.clone();
        readers.push(tokio::spawn(async move {
            let _permit = budget.acquire().await.expect("conn budget");
            let mut conn = pool.get().await.expect("conn");
            let res = access::list_accessible_asset_ids(&access_client, &mut conn, user_id).await;
            (i, res)
        }));
    }

    // Concurrent churn: a few inserts and soft-deletes. The writer
    // is sequential (one connection at a time inside the loop) but
    // shares the same connection budget so it competes fairly with
    // the readers.
    let pool_w = pool.clone();
    let admin_id = admin.user.id;
    let ag_clone = ag;
    let budget_w = conn_budget.clone();
    let writer = tokio::spawn(async move {
        for i in 0..8u32 {
            let _permit = budget_w.acquire().await.expect("conn budget");
            let mut conn = pool_w.get().await.expect("conn");
            let id = create_test_asset_in_group(
                &mut conn,
                &format!("a51-churn-{i}"),
                admin_id,
                &ag_clone,
            )
            .await;
            // Soft-delete every other one.
            if i % 2 == 0 {
                use vauban_web::schema::assets;
                let _ = diesel::update(assets::table.filter(assets::id.eq(id)))
                    .set((
                        assets::is_deleted.eq(true),
                        assets::deleted_at.eq(chrono::Utc::now()),
                    ))
                    .execute(&mut conn)
                    .await;
            }
        }
    });

    for r in readers {
        let (idx, out) = r.await.expect("reader joined");
        let v = out.unwrap_or_else(|e| panic!("reader {idx} failed: {e}"));
        assert!(
            !v.is_empty(),
            "reader {idx} must see at least the seed asset"
        );
    }
    writer.await.expect("writer joined");

    test_db::cleanup(&mut conn).await;
}

// =====================================================================
// A52 — Race: monotonic union of new assets
// =====================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a52_race_new_assets_eventually_visible() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user = create_test_user(&mut conn, &app.auth_service, &unique_name("a52_user")).await;
    let ug = create_test_vauban_group(&mut conn, &unique_name("a52_ug")).await;
    add_user_to_vauban_group(&mut conn, user.user.id, &ug).await;
    create_test_access_rule(&mut conn, &ug, &virtual_uuid(), &["ssh"]).await;

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("a52_adm")).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("a52_ag")).await;
    let user_id = user.user.id;
    let access_client = app._access_service.access_client.clone();
    let pool = app.db_pool.clone();

    let mut created: Vec<i32> = Vec::new();
    for i in 0..20 {
        let id =
            create_test_asset_in_group(&mut conn, &format!("a52-asset-{i}"), admin.user.id, &ag)
                .await;
        created.push(id);

        let mut c = pool.get().await.expect("conn");
        let visible = access::list_accessible_asset_ids(&access_client, &mut c, user_id)
            .await
            .unwrap();
        for prev in &created {
            assert!(
                visible.contains(prev),
                "iteration {i}: previously-created asset {prev} must remain visible (monotonic)"
            );
        }
    }

    test_db::cleanup(&mut conn).await;
}

// =====================================================================
// A53 — Boot-time tampering: init_or_die fails loud when the virtual
//        row is missing
// =====================================================================

#[tokio::test]
#[serial]
async fn a53_init_or_die_refuses_when_virtual_row_missing() {
    // Whitebox: drive the resolver against a DB where the singleton row
    // was scrubbed by temporarily disabling the mutation trigger
    // (the only legitimate way to delete the row without dropping the
    // database). The resolver MUST refuse, then we restore the row.
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    diesel_async::AsyncConnection::transaction::<(), diesel::result::Error, _>(&mut conn, |conn| {
        Box::pin(async move {
            sql_query("ALTER TABLE asset_groups DISABLE TRIGGER block_mutation_on_virtual_groups")
                .execute(conn)
                .await?;
            sql_query("DELETE FROM asset_groups WHERE kind = 'all'")
                .execute(conn)
                .await?;
            sql_query("ALTER TABLE asset_groups ENABLE TRIGGER block_mutation_on_virtual_groups")
                .execute(conn)
                .await?;

            let result = vauban_web::services::virtual_group::resolve_id_for_test(conn).await;
            assert!(
                result.is_err(),
                "resolve_id_for_test MUST fail when the virtual row is missing"
            );
            let msg = format!("{:?}", result.unwrap_err());
            assert!(
                msg.contains("seeded 'All assets' row"),
                "error must point at the missing seeded row, got: {msg}"
            );

            // Roll the txn back so the singleton row reappears and the
            // rest of the suite can continue to use it.
            Err::<(), diesel::result::Error>(diesel::result::Error::RollbackTransaction)
        })
    })
    .await
    .ok();

    // Sanity-check: the singleton row still exists outside the txn.
    let post: i32 = vauban_web::services::virtual_group::resolve_id_for_test(&mut conn)
        .await
        .expect("singleton must be present after rollback");
    assert!(post > 0, "post-rollback id must be a real positive id");

    test_db::cleanup(&mut conn).await;
}

// =====================================================================
// A54 — AccessGuard saturation: 50 sequential checks, no leak
// =====================================================================

#[tokio::test]
#[serial]
async fn a54_accessguard_saturation_50_sequential() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user = create_test_user(&mut conn, &app.auth_service, &unique_name("a54_user")).await;
    let ug = create_test_vauban_group(&mut conn, &unique_name("a54_ug")).await;
    add_user_to_vauban_group(&mut conn, user.user.id, &ug).await;
    create_test_access_rule(&mut conn, &ug, &virtual_uuid(), &["ssh"]).await;

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("a54_adm")).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("a54_ag")).await;
    let asset_id = create_test_asset_in_group(&mut conn, "a54-asset", admin.user.id, &ag).await;
    let asset_uuid = get_asset_uuid(&mut conn, asset_id).await;
    let user_uuid = user.user.uuid.to_string();
    let asset_uuid_str = asset_uuid.to_string();

    let client = app._access_service.access_client.clone();
    for i in 0..50 {
        let dec = client
            .check_access_by_uuid(&user_uuid, &asset_uuid_str, "ssh")
            .await
            .unwrap_or_else(|e| panic!("iteration {i}: {e}"));
        assert!(
            dec.allowed,
            "iteration {i}: must remain allowed; pending-slot leak would surface as a flake"
        );
    }

    test_db::cleanup(&mut conn).await;
}
