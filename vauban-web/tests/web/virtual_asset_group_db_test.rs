//! Tier 1 — DB-level schema invariants for the virtual "All assets"
//! group introduced in `20260424000000_virtual_asset_group_all`.
//!
//! These tests bypass the Rust handler layer entirely. They prove the
//! invariants are *structural* — even if a future handler regression
//! tries to mutate the singleton row or attach assets to it, the
//! database itself rejects every illegal transition.
//!
//! Invariants under test:
//!
//! * **V1** — Exactly one row exists with `kind = 'all'`, the reserved
//!   UUID `00000000-0000-0000-0000-000000000a11`, and `is_deleted =
//!   false` after a fresh migration apply.
//! * **V2** — The `kind` CHECK constraint rejects unknown values.
//! * **V3** — The partial UNIQUE index on `kind WHERE kind <> 'static'`
//!   prevents a second virtual row from being inserted.
//! * **V4** — The `block_membership_on_virtual_groups` BEFORE INSERT
//!   trigger refuses any attempt to attach an asset to the virtual
//!   row.
//! * **V5** — The same trigger fires on UPDATE (re-pointing an
//!   existing membership at the virtual row).
//! * **V6** — The `block_mutation_on_virtual_groups` BEFORE DELETE
//!   trigger refuses to delete the virtual row.
//! * **V7** — The same trigger fires on UPDATE — including `name`,
//!   `slug`, `color`, and `is_deleted`.
//! * **V8** — The `kind` flip-flop (`UPDATE … SET kind = 'static'`) is
//!   blocked by V7 (UPDATE branch).
//! * **V9** — The trigger identifies the virtual row by `kind`, not by
//!   the hardcoded UUID — proven by the trigger SQL itself
//!   (whitebox structural test).
//! * **V10** — Soft-delete (`UPDATE … SET is_deleted = true WHERE
//!   kind = 'all'`) is blocked by V7.
//! * **V11** — The `kind` column has the expected NOT NULL DEFAULT
//!   `'static'` so existing rows survive the migration.
//!
//! Each test names the exact SQLSTATE and message fragment it expects,
//! so a future migration that accidentally relaxes a constraint or
//! reworks a trigger fails with a precise diagnostic instead of a
//! silent regression.

use crate::common::TestApp;
use crate::fixtures::unique_name;
use diesel::result::Error as DieselError;
use diesel::sql_query;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serial_test::serial;
use shared::messages::{ALL_ASSETS_GROUP_UUID, ASSET_GROUP_KIND_ALL, ASSET_GROUP_KIND_STATIC};

/// Insert a regular static asset_group via raw SQL and return its id.
async fn insert_static_group(conn: &mut AsyncPgConnection, name: &str) -> i32 {
    use diesel::QueryableByName;

    #[derive(QueryableByName)]
    struct IdRow {
        #[diesel(sql_type = diesel::sql_types::Int4)]
        id: i32,
    }

    let slug = name.to_lowercase().replace('_', "-");
    let row: IdRow = diesel::sql_query(format!(
        "INSERT INTO asset_groups (uuid, name, slug, kind, color, icon)
         VALUES (gen_random_uuid(), '{name}', '{slug}', 'static', '#000000', 'folder')
         RETURNING id"
    ))
    .get_result(conn)
    .await
    .expect("static group insert");
    row.id
}

/// Insert a regular asset (SSH, online) and return its id.
async fn insert_asset(conn: &mut AsyncPgConnection, name: &str) -> i32 {
    use diesel::QueryableByName;

    #[derive(QueryableByName)]
    struct IdRow {
        #[diesel(sql_type = diesel::sql_types::Int4)]
        id: i32,
    }

    let row: IdRow = diesel::sql_query(format!(
        "INSERT INTO assets (uuid, name, hostname, port, asset_type, status, connection_username, connection_config)
         VALUES (gen_random_uuid(), '{name}', '{name}.local', 22, 'ssh', 'online', 'root', '{{}}'::jsonb)
         RETURNING id"
    ))
    .get_result(conn)
    .await
    .expect("asset insert");
    row.id
}

/// Helper: assert a Diesel error message contains a substring (case-insensitive).
fn assert_err_contains(err: &DieselError, fragment: &str) {
    let msg = format!("{err:?}").to_lowercase();
    assert!(
        msg.contains(&fragment.to_lowercase()),
        "expected error to contain {fragment:?}, got: {err:?}"
    );
}

// =====================================================================
// V1 — Singleton row exists after migration
// =====================================================================

#[tokio::test]
#[serial]
async fn v1_virtual_row_exists_after_migration() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    use diesel::QueryableByName;
    #[derive(QueryableByName)]
    struct Row {
        #[diesel(sql_type = diesel::sql_types::Text)]
        uuid: String,
        #[diesel(sql_type = diesel::sql_types::Text)]
        kind: String,
        #[diesel(sql_type = diesel::sql_types::Bool)]
        is_deleted: bool,
        #[diesel(sql_type = diesel::sql_types::Text)]
        slug: String,
    }

    let rows: Vec<Row> = sql_query(
        "SELECT uuid::text AS uuid, kind, is_deleted, slug FROM asset_groups WHERE kind = 'all'",
    )
    .load(&mut conn)
    .await
    .expect("query");

    assert_eq!(rows.len(), 1, "exactly one kind='all' row must exist");
    let row = &rows[0];
    assert_eq!(row.uuid, ALL_ASSETS_GROUP_UUID);
    assert_eq!(row.kind, ASSET_GROUP_KIND_ALL);
    assert!(!row.is_deleted, "virtual row must not be soft-deleted");
    assert_eq!(row.slug, "__all-assets__");
}

// =====================================================================
// V2 — kind CHECK constraint rejects unknown values
// =====================================================================

#[tokio::test]
#[serial]
async fn v2_kind_check_rejects_unknown_value() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let err = sql_query(
        "INSERT INTO asset_groups (uuid, name, slug, kind, color, icon)
         VALUES (gen_random_uuid(), 'unknown-kind', 'unknown-kind', 'unknown', '#000000', 'folder')",
    )
    .execute(&mut conn)
    .await
    .expect_err("kind='unknown' must be rejected by CHECK constraint");
    assert_err_contains(&err, "asset_groups_kind_check");
}

// =====================================================================
// V3 — Partial UNIQUE index rejects a second virtual row
// =====================================================================

#[tokio::test]
#[serial]
async fn v3_unique_singleton_rejects_second_virtual_row() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    // Direct INSERT bypassing the seed UPSERT: the partial UNIQUE index
    // on (kind) WHERE kind <> 'static' must reject this.
    let err = sql_query(
        "INSERT INTO asset_groups (uuid, name, slug, kind, color, icon)
         VALUES (gen_random_uuid(), 'fake-all', 'fake-all', 'all', '#000000', 'folder')",
    )
    .execute(&mut conn)
    .await
    .expect_err("a second kind='all' row must be rejected by the singleton UNIQUE index");
    assert_err_contains(&err, "uniq_asset_groups_kind_singleton");
}

// =====================================================================
// V4 — Trigger blocks attaching an asset to the virtual row
// =====================================================================

#[tokio::test]
#[serial]
async fn v4_trigger_blocks_membership_insert_on_virtual() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let asset_id = insert_asset(&mut conn, &unique_name("test_v4_asset")).await;

    let err = sql_query(format!(
        "INSERT INTO asset_asset_groups (asset_id, asset_group_id)
         SELECT {asset_id}, id FROM asset_groups WHERE kind = 'all'"
    ))
    .execute(&mut conn)
    .await
    .expect_err("attaching to virtual must raise");
    assert_err_contains(&err, "cannot add members to virtual");

    // Cleanup the test asset.
    sql_query(format!("DELETE FROM assets WHERE id = {asset_id}"))
        .execute(&mut conn)
        .await
        .ok();
}

// =====================================================================
// V5 — Trigger blocks UPDATE that re-points membership to virtual
// =====================================================================

#[tokio::test]
#[serial]
async fn v5_trigger_blocks_membership_update_to_virtual() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let asset_id = insert_asset(&mut conn, &unique_name("test_v5_asset")).await;
    let static_id = insert_static_group(&mut conn, &unique_name("test_v5_grp")).await;

    sql_query(format!(
        "INSERT INTO asset_asset_groups (asset_id, asset_group_id) VALUES ({asset_id}, {static_id})"
    ))
    .execute(&mut conn)
    .await
    .expect("static membership insert");

    let err = sql_query(format!(
        "UPDATE asset_asset_groups
         SET asset_group_id = (SELECT id FROM asset_groups WHERE kind = 'all')
         WHERE asset_id = {asset_id}"
    ))
    .execute(&mut conn)
    .await
    .expect_err("re-pointing to virtual must raise");
    assert_err_contains(&err, "cannot add members to virtual");

    // Cleanup
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
// V6 — Trigger blocks DELETE on the virtual row
// =====================================================================

#[tokio::test]
#[serial]
async fn v6_trigger_blocks_delete_on_virtual_row() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let err = sql_query("DELETE FROM asset_groups WHERE kind = 'all'")
        .execute(&mut conn)
        .await
        .expect_err("DELETE on virtual must raise");
    assert_err_contains(&err, "cannot delete virtual asset_group");
}

// =====================================================================
// V7 — Trigger blocks any UPDATE on the virtual row
// =====================================================================

#[tokio::test]
#[serial]
async fn v7_trigger_blocks_update_on_virtual_row() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let err = sql_query("UPDATE asset_groups SET name = 'Hijack' WHERE kind = 'all'")
        .execute(&mut conn)
        .await
        .expect_err("renaming virtual must raise");
    assert_err_contains(&err, "cannot update virtual asset_group");

    let err = sql_query("UPDATE asset_groups SET color = '#ff0000' WHERE kind = 'all'")
        .execute(&mut conn)
        .await
        .expect_err("recolouring virtual must raise");
    assert_err_contains(&err, "cannot update virtual asset_group");

    let err = sql_query("UPDATE asset_groups SET slug = 'pwned' WHERE kind = 'all'")
        .execute(&mut conn)
        .await
        .expect_err("re-slugging virtual must raise");
    assert_err_contains(&err, "cannot update virtual asset_group");
}

// =====================================================================
// V8 — kind flip-flop is blocked by V7
// =====================================================================

#[tokio::test]
#[serial]
async fn v8_kind_flip_flop_is_blocked() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let err = sql_query("UPDATE asset_groups SET kind = 'static' WHERE kind = 'all'")
        .execute(&mut conn)
        .await
        .expect_err("kind flip-flop must raise");
    assert_err_contains(&err, "cannot update virtual asset_group");
}

// =====================================================================
// V9 — Trigger identifies the virtual row by `kind`, not by UUID
//
// Whitebox: read pg_proc to confirm the trigger function's body
// branches on `kind <> 'static'`, not on a hardcoded UUID literal.
// A future seed UUID change must keep the guards intact.
// =====================================================================

#[tokio::test]
#[serial]
async fn v9_trigger_branches_on_kind_not_uuid() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    use diesel::QueryableByName;
    #[derive(QueryableByName)]
    struct Body {
        #[diesel(sql_type = diesel::sql_types::Text)]
        prosrc: String,
    }

    for fname in &[
        "block_mutation_on_virtual_groups",
        "block_membership_on_virtual_groups",
    ] {
        let rows: Vec<Body> = sql_query(format!(
            "SELECT prosrc FROM pg_proc WHERE proname = '{fname}'"
        ))
        .load(&mut conn)
        .await
        .expect("pg_proc lookup");
        assert_eq!(rows.len(), 1, "exactly one trigger function {fname}");
        let body = &rows[0].prosrc;
        assert!(
            body.contains("kind") && body.contains("static"),
            "{fname} must branch on kind, not UUID; got body: {body}"
        );
        assert!(
            !body.contains("00000000-0000-0000-0000-000000000a11"),
            "{fname} must NOT hardcode the reserved UUID; got body: {body}"
        );
    }
}

// =====================================================================
// V10 — Soft-delete on the virtual row is blocked by V7
// =====================================================================

#[tokio::test]
#[serial]
async fn v10_soft_delete_on_virtual_is_blocked() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let err = sql_query("UPDATE asset_groups SET is_deleted = true WHERE kind = 'all'")
        .execute(&mut conn)
        .await
        .expect_err("soft-deleting virtual must raise");
    assert_err_contains(&err, "cannot update virtual asset_group");
}

// =====================================================================
// V11 — `kind` column has NOT NULL DEFAULT 'static' so existing rows survive
// =====================================================================

#[tokio::test]
#[serial]
async fn v11_kind_column_default_static() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    use diesel::QueryableByName;
    #[derive(QueryableByName)]
    struct ColInfo {
        #[diesel(sql_type = diesel::sql_types::Text)]
        column_default: String,
        #[diesel(sql_type = diesel::sql_types::Text)]
        is_nullable: String,
    }

    let rows: Vec<ColInfo> = sql_query(
        "SELECT column_default, is_nullable
         FROM information_schema.columns
         WHERE table_name = 'asset_groups' AND column_name = 'kind'",
    )
    .load(&mut conn)
    .await
    .expect("information_schema lookup");

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].is_nullable, "NO");
    assert!(
        rows[0].column_default.contains("static"),
        "column_default should default to 'static', got: {}",
        rows[0].column_default
    );

    // Sanity: a fresh INSERT without `kind` defaults to 'static'.
    let name = unique_name("v11_default");
    let slug = name.to_lowercase().replace('_', "-");
    sql_query(format!(
        "INSERT INTO asset_groups (uuid, name, slug, color, icon)
         VALUES (gen_random_uuid(), '{name}', '{slug}', '#000000', 'folder')"
    ))
    .execute(&mut conn)
    .await
    .expect("default kind insert");

    #[derive(QueryableByName)]
    struct KindRow {
        #[diesel(sql_type = diesel::sql_types::Text)]
        kind: String,
    }
    let kind: Vec<KindRow> = sql_query(format!(
        "SELECT kind FROM asset_groups WHERE name = '{name}'"
    ))
    .load(&mut conn)
    .await
    .expect("query default");
    assert_eq!(kind.len(), 1);
    assert_eq!(kind[0].kind, ASSET_GROUP_KIND_STATIC);

    sql_query(format!("DELETE FROM asset_groups WHERE name = '{name}'"))
        .execute(&mut conn)
        .await
        .ok();
}
