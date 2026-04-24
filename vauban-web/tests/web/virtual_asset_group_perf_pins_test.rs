//! Tier 6 (perf budgets) + Tier 7 (structural source pins) tests for
//! the virtual "All assets" group.
//!
//! **Tier 6** asserts soft performance budgets so a future regression
//! in the virtual-rule resolver, the count badge query, or the
//! check_access path surfaces as a test failure rather than a silent
//! production slowdown.
//!
//! **Tier 7** ("structural pins") inlines source files with
//! `include_str!` and asserts they contain — by literal substring —
//! the defense-in-depth markers we rely on. A future refactor that
//! accidentally drops one of these guards (e.g. removes the OR-branch
//! in `handle_check_access_multi`, or stops setting `kind = 'static'`
//! in the asset-group create handler) will fail with a precise
//! diagnostic naming the missing marker.
//!
//! Tests:
//!
//! * **P55** — 1,000 active assets: `list_accessible_asset_ids` for a
//!   user with a single virtual SSH rule completes under 2s in dev.
//! * **P56** — 200 access_rules (mixed static + 1 virtual):
//!   `can_access_asset` is deterministic and remains under 1s.
//! * **S58** — `list_accessible_asset_ids` source contains the virtual
//!   special-case (`virtual_asset_group_id` reference).
//! * **S59** — `can_access_asset` source contains the same special-case.
//! * **S60** — `handle_check_access_multi` source contains the
//!   OR-branch on the virtual id.
//! * **S61** — `handle_list_asset_groups` filters by `kind = 'static'`
//!   by default and the path that surfaces virtual groups names
//!   `include_virtual` explicitly.
//! * **S62** — Asset-group mutation web handlers
//!   (`update_asset_group`, `delete_asset_group_web`,
//!   `asset_group_add_asset`, `asset_group_remove_asset`) reference
//!   the `is_virtual_asset_group_uuid` guard.
//! * **S63** — `ALL_ASSETS_GROUP_UUID` constant pinned to its exact
//!   reserved value `00000000-0000-0000-0000-000000000a11`.
//! * **S64** — Migration filename pinned: a deliberate rename forces
//!   an explicit test update.
//! * **S65** — `AssetGroupInfo` carries the `kind` field (used by the
//!   web layer to render the "Virtual" badge) and `ListAssetGroups`
//!   carries `include_virtual` (used by the access-rule editor).

use serial_test::serial;
use std::time::Instant;

use crate::common::{TestApp, test_db};
use crate::fixtures::{
    add_user_to_vauban_group, create_admin_user, create_test_access_rule, create_test_asset_group,
    create_test_asset_in_group, create_test_user, create_test_vauban_group, unique_name,
};
use shared::messages::ALL_ASSETS_GROUP_UUID;
use uuid::Uuid;
use vauban_web::services::access;

fn virtual_uuid() -> Uuid {
    Uuid::parse_str(ALL_ASSETS_GROUP_UUID).expect("virtual UUID parses")
}

// =====================================================================
// P55 — perf budget: list_accessible_asset_ids over 1,000 assets
// =====================================================================

#[tokio::test]
#[serial]
async fn p55_perf_list_accessible_asset_ids_under_budget() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user = create_test_user(&mut conn, &app.auth_service, &unique_name("p55_user")).await;
    let ug = create_test_vauban_group(&mut conn, &unique_name("p55_ug")).await;
    add_user_to_vauban_group(&mut conn, user.user.id, &ug).await;
    create_test_access_rule(&mut conn, &ug, &virtual_uuid(), &["ssh"]).await;

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("p55_adm")).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("p55_ag")).await;
    // Bulk-seed 1,000 assets via a single SQL statement so setup time
    // doesn't dominate the test's wall-clock.
    use diesel::sql_query;
    use diesel_async::RunQueryDsl;
    use vauban_web::schema::asset_groups;
    use diesel::prelude::*;
    let ag_id: i32 = asset_groups::table
        .filter(asset_groups::uuid.eq(ag))
        .select(asset_groups::id)
        .first(&mut conn)
        .await
        .expect("ag id");

    sql_query(format!(
        "INSERT INTO assets (uuid, name, hostname, port, asset_type, status, connection_username, connection_config, created_by_id)
         SELECT gen_random_uuid(), 'p55-asset-' || gs::text, 'p55-host-' || gs::text || '-' || (extract(epoch from now())*1000)::bigint::text, 22, 'ssh', 'online', 'root', '{{}}'::jsonb, {admin}
         FROM generate_series(1, 1000) gs",
        admin = admin.user.id
    ))
    .execute(&mut conn)
    .await
    .expect("bulk insert");
    sql_query(format!(
        "INSERT INTO asset_asset_groups (asset_id, asset_group_id)
         SELECT a.id, {ag_id} FROM assets a WHERE a.name LIKE 'p55-asset-%'"
    ))
    .execute(&mut conn)
    .await
    .expect("bulk membership");
    // Insert one orphan to verify the virtual rule covers it too.
    let _ = create_test_asset_in_group(&mut conn, "p55-seed-extra", admin.user.id, &ag).await;

    let started = Instant::now();
    let visible = access::list_accessible_asset_ids(
        &app._access_service.access_client,
        &mut conn,
        user.user.id,
    )
    .await
    .expect("list");
    let elapsed = started.elapsed();

    assert!(
        visible.len() >= 1001,
        "must cover the 1,000 bulk-seeded SSH assets + the extra one (got {})",
        visible.len()
    );
    // Soft budget: the list path on dev workstations should be well
    // under 2s for 1,000 assets. CI machines are slower but still safe.
    assert!(
        elapsed.as_millis() < 2_000,
        "list_accessible_asset_ids exceeded 2s budget: {:?}",
        elapsed
    );

    test_db::cleanup(&mut conn).await;
}

// =====================================================================
// P56 — perf budget: can_access_asset over many rules
// =====================================================================

#[tokio::test]
#[serial]
async fn p56_perf_can_access_asset_under_budget() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user = create_test_user(&mut conn, &app.auth_service, &unique_name("p56_user")).await;
    let ug = create_test_vauban_group(&mut conn, &unique_name("p56_ug")).await;
    add_user_to_vauban_group(&mut conn, user.user.id, &ug).await;
    create_test_access_rule(&mut conn, &ug, &virtual_uuid(), &["ssh"]).await;

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("p56_adm")).await;
    let ag = create_test_asset_group(&mut conn, &unique_name("p56_ag")).await;
    let asset_id = create_test_asset_in_group(&mut conn, "p56-asset", admin.user.id, &ag).await;

    // Seed ~200 unrelated rules in bulk so the matching path actually
    // has work to do. Each rule needs a unique (user_group_id,
    // asset_group_id) pair, so we bulk-create 200 noise UGs and 200
    // noise AGs first, then pair them 1:1.
    use diesel::sql_query;
    use diesel_async::RunQueryDsl;
    let stamp = chrono::Utc::now().timestamp_millis();
    sql_query(format!(
        "INSERT INTO vauban_groups (uuid, name, source)
         SELECT gen_random_uuid(), 'p56-noise-ug-{stamp}-' || gs::text, 'local'
         FROM generate_series(1, 200) gs"
    ))
    .execute(&mut conn)
    .await
    .expect("bulk noise UGs");
    sql_query(format!(
        "INSERT INTO asset_groups (uuid, name, slug, kind, color, icon)
         SELECT gen_random_uuid(), 'p56-noise-ag-{stamp}-' || gs::text, 'p56-noise-ag-{stamp}-' || gs::text, 'static', '#000', 'folder'
         FROM generate_series(1, 200) gs"
    ))
    .execute(&mut conn)
    .await
    .expect("bulk noise AGs");
    sql_query(format!(
        "INSERT INTO access_rules (uuid, name, user_group_id, asset_group_id, allowed_protocols, is_active, priority)
         SELECT gen_random_uuid(), 'p56-noise-rule-{stamp}-' || gs::text,
                u.id,
                a.id,
                ARRAY['ssh']::varchar[],
                true,
                0
         FROM generate_series(1, 200) gs
         JOIN vauban_groups u ON u.name = 'p56-noise-ug-{stamp}-' || gs::text
         JOIN asset_groups a ON a.name = 'p56-noise-ag-{stamp}-' || gs::text"
    ))
    .execute(&mut conn)
    .await
    .expect("bulk noise rules");

    let started = Instant::now();
    let result = access::can_access_asset(
        &app._access_service.access_client,
        &mut conn,
        user.user.id,
        asset_id,
        "ssh",
    )
    .await
    .expect("can_access");
    let elapsed = started.elapsed();

    assert!(result.allowed);
    assert!(
        elapsed.as_millis() < 1_000,
        "can_access_asset exceeded 1s budget: {:?}",
        elapsed
    );

    test_db::cleanup(&mut conn).await;
}

// =====================================================================
// S58 — Source pin: list_accessible_asset_ids special-cases the virtual id
// =====================================================================

#[test]
fn s58_list_accessible_asset_ids_references_virtual() {
    let src = include_str!("../../src/services/access.rs");
    assert!(
        src.contains("list_accessible_asset_ids"),
        "function name must be present in the source"
    );
    assert!(
        src.contains("virtual_asset_group_id"),
        "list_accessible_asset_ids MUST reference virtual_asset_group_id() to special-case the singleton row"
    );
}

// =====================================================================
// S59 — Source pin: can_access_asset references virtual id
// =====================================================================

#[test]
fn s59_can_access_asset_references_virtual() {
    let src = include_str!("../../src/services/access.rs");
    assert!(src.contains("pub async fn can_access_asset"));
    // Per-asset path must also see the virtual id (defense-in-depth).
    let count = src.matches("virtual_asset_group_id").count();
    assert!(
        count >= 2,
        "virtual_asset_group_id MUST be referenced from BOTH list_accessible_asset_ids AND can_access_asset (defense-in-depth), found {count}"
    );
}

// =====================================================================
// S60 — Source pin: handle_check_access_multi has the OR-branch
// =====================================================================

#[test]
fn s60_handle_check_access_multi_or_branch_on_virtual() {
    let src = include_str!("../../../vauban-access/src/handlers.rs");
    assert!(
        src.contains("handle_check_access_multi"),
        "handler name must be present in the source"
    );
    assert!(
        src.contains("virtual_asset_group_id"),
        "handle_check_access_multi MUST OR-aggregate on virtual_asset_group_id()"
    );
}

// =====================================================================
// S61 — Source pin: handle_list_asset_groups filters static by default
// =====================================================================

#[test]
fn s61_handle_list_asset_groups_default_filters_static() {
    let src = include_str!("../../../vauban-access/src/handlers.rs");
    assert!(
        src.contains("ASSET_GROUP_KIND_STATIC"),
        "handle_list_asset_groups MUST filter on ASSET_GROUP_KIND_STATIC by default"
    );
    assert!(
        src.contains("include_virtual"),
        "the path that surfaces virtual groups MUST name include_virtual explicitly"
    );
}

// =====================================================================
// S62 — Source pin: web mutation handlers carry the virtual guard
// =====================================================================

#[test]
fn s62_web_mutation_handlers_have_virtual_guard() {
    let src = include_str!("../../src/handlers/web/asset_groups.rs");
    let guard = "is_virtual_asset_group_uuid";
    assert!(src.contains(guard), "asset_groups handlers MUST define {guard}");

    // Each destructive endpoint MUST consult it.
    for (handler, expected) in [
        ("pub async fn update_asset_group", true),
        ("pub async fn delete_asset_group_web", true),
        ("pub async fn asset_group_add_asset_form", true),
        ("pub async fn asset_group_add_asset", true),
        ("pub async fn asset_group_remove_asset", true),
        ("pub async fn asset_group_edit", true),
        ("pub async fn asset_group_detail", true),
    ] {
        if !expected {
            continue;
        }
        let idx = src.find(handler).unwrap_or_else(|| {
            panic!("handler {handler} not found in asset_groups.rs source")
        });
        // Look at the next ~3KB of source after the function signature
        // for the guard.
        let window = &src[idx..usize::min(idx + 3072, src.len())];
        assert!(
            window.contains(guard),
            "{handler} MUST consult {guard} (defense-in-depth on top of the trigger)"
        );
    }
}

// =====================================================================
// S63 — Pinned UUID value
// =====================================================================

#[test]
fn s63_all_assets_group_uuid_is_pinned() {
    assert_eq!(
        ALL_ASSETS_GROUP_UUID, "00000000-0000-0000-0000-000000000a11",
        "ALL_ASSETS_GROUP_UUID is part of the public IPC contract; \
         changing it requires a coordinated migration + rollout"
    );
    // Also assert the constant is what the seed migration uses.
    let migration = include_str!(
        "../../../vauban-db/migrations/20260424000000_virtual_asset_group_all/up.sql"
    );
    assert!(
        migration.contains("00000000-0000-0000-0000-000000000a11"),
        "migration's seed INSERT must use the pinned UUID"
    );
}

// =====================================================================
// S64 — Pinned migration filename
// =====================================================================

#[test]
fn s64_migration_filename_pinned() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .join("vauban-db/migrations/20260424000000_virtual_asset_group_all/up.sql");
    assert!(
        path.exists(),
        "migration file MUST exist at the pinned path: {}",
        path.display()
    );
    let down = path.with_file_name("down.sql");
    assert!(
        down.exists(),
        "migration MUST ship a down.sql at: {}",
        down.display()
    );
}

// =====================================================================
// S65 — IPC contract pin: kind + include_virtual
// =====================================================================

#[test]
fn s65_ipc_contract_carries_kind_and_include_virtual() {
    let messages = include_str!("../../../shared/src/messages.rs");
    assert!(
        messages.contains("ALL_ASSETS_GROUP_UUID"),
        "shared::messages MUST export ALL_ASSETS_GROUP_UUID"
    );
    assert!(
        messages.contains("ASSET_GROUP_KIND_ALL") && messages.contains("ASSET_GROUP_KIND_STATIC"),
        "shared::messages MUST export both kind constants"
    );
    assert!(
        messages.contains("pub kind: String"),
        "AssetGroupInfo / GroupOption MUST carry a `kind: String` field"
    );
    assert!(
        messages.contains("include_virtual"),
        "ListAssetGroups / ListAssetGroupOptions MUST carry an `include_virtual` flag"
    );
}
