//! Issue #17 — DB-level invariant tests for the irreversible-delete
//! semantics on `assets`.
//!
//! These tests bypass the Rust handler layer entirely and exercise the
//! contract directly against PostgreSQL. The point is to prove the
//! guarantees are *structural*: even if a future handler regression
//! reintroduces a reactivation branch, a stray `UPDATE`, or a
//! superuser console session, the database still rejects every
//! illegal state transition.
//!
//! Invariants under test:
//!
//! * **I1** — At most one ACTIVE row per `(hostname, port,
//!   connection_username)` triplet
//!   (`idx_assets_hostname_port_username_active` partial unique index,
//!   originally introduced in
//!   `20260330000000_add_connection_username` and re-documented from
//!   `20260420000000_assets_irreversible_delete`).
//! * **I2** — Arbitrarily many *tombstones* (`is_deleted = true`) may
//!   coexist on the same triplet -- audit history is unbounded.
//! * **I3** — A tombstone MUST NOT carry credentials
//!   (`assets_tombstone_no_secrets` CHECK constraint).
//! * **I4** — `is_deleted` MUST NOT transition from `true` back to
//!   `false` (`assets_no_resurrection_trg` BEFORE UPDATE trigger).
//!
//! Each test names the PostgreSQL SQLSTATE it expects, so a future
//! migration that accidentally relaxes the wrong constraint will fail
//! with a precise diagnostic instead of a generic "row was inserted".

use crate::common::TestApp;
use crate::fixtures::unique_name;
use diesel::ExpressionMethods;
use diesel::QueryDsl;
use diesel::result::{DatabaseErrorKind, Error as DieselError};
use diesel::sql_query;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::json;
use serial_test::serial;
use uuid::Uuid;
use vauban_web::models::asset::{AssetType, NewAsset};
use vauban_web::schema::assets;

/// Insert an ACTIVE asset directly via Diesel and return its row id.
/// We bypass the handler so the test is concerned only with what the
/// database accepts, not with form validation.
async fn insert_active_asset(
    conn: &mut AsyncPgConnection,
    name: &str,
    hostname: &str,
    port: i32,
    username: &str,
) -> i32 {
    let new_asset = NewAsset {
        uuid: Uuid::new_v4(),
        name: name.to_string(),
        hostname: hostname.to_string(),
        port,
        asset_type: AssetType::Ssh,
        status: "online".to_string(),
        description: None,
        connection_config: json!({}),
        created_by_id: None,
        connection_username: username.to_string(),
    };
    diesel::insert_into(assets::table)
        .values(&new_asset)
        .returning(assets::id)
        .get_result(conn)
        .await
        .expect("active insert must succeed on a fresh triplet")
}

/// Soft-delete a row at the DB level following the production
/// contract: scrub `connection_config` to `{}` in the same UPDATE so
/// the CHECK constraint is satisfied. The trigger only fires on the
/// `false -> true` transition (allowed), so this is the canonical
/// "what the handler does" minus the audit columns.
async fn soft_delete_at_db(conn: &mut AsyncPgConnection, asset_id: i32) {
    let now = chrono::Utc::now();
    diesel::update(assets::table.filter(assets::id.eq(asset_id)))
        .set((
            assets::is_deleted.eq(true),
            assets::deleted_at.eq(now),
            assets::updated_at.eq(now),
            assets::connection_config.eq(json!({})),
        ))
        .execute(conn)
        .await
        .expect("soft-delete with config scrub must succeed");
}

// =============================================================================
// I1 — partial unique index on (hostname, port, connection_username)
// =============================================================================

/// Two ACTIVE rows on the same triplet must be rejected by the
/// `idx_assets_hostname_port_username_active` partial unique index.
/// SQLSTATE 23505 is the canonical "unique_violation". The index was
/// originally introduced by
/// `20260330000000_add_connection_username`; the
/// `20260420000000_assets_irreversible_delete` migration only adds an
/// explanatory `COMMENT ON INDEX` linking it to issue #17.
#[tokio::test]
#[serial]
async fn test_i1_two_active_rows_same_triplet_rejected() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let hostname = format!("{}.i1.test", unique_name("host"));
    let username = "shared";
    let _first = insert_active_asset(&mut conn, &unique_name("i1-a"), &hostname, 22, username).await;

    let new_asset = NewAsset {
        uuid: Uuid::new_v4(),
        name: unique_name("i1-b"),
        hostname: hostname.clone(),
        port: 22,
        asset_type: AssetType::Ssh,
        status: "online".to_string(),
        description: None,
        connection_config: json!({}),
        created_by_id: None,
        connection_username: username.to_string(),
    };
    let result = diesel::insert_into(assets::table)
        .values(&new_asset)
        .execute(&mut conn)
        .await;

    match result {
        Err(DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, info)) => {
            let constraint = info.constraint_name().unwrap_or("");
            let message = info.message();
            assert!(
                constraint.contains("idx_assets_hostname_port_username_active")
                    || message.contains("idx_assets_hostname_port_username_active"),
                "expected the partial unique index 'idx_assets_hostname_port_username_active' \
                 to fire, got constraint='{}' message='{}'",
                constraint,
                message
            );
        }
        other => panic!(
            "expected UniqueViolation on idx_assets_hostname_port_username_active, got {:?}",
            other
        ),
    }
}

// =============================================================================
// I2 — tombstones may freely share a triplet
// =============================================================================

/// Soft-delete and recreate the same triplet N times: every iteration
/// must succeed and leave exactly one ACTIVE row plus N tombstones,
/// each on a distinct UUID. This is the audit invariant.
#[tokio::test]
#[serial]
async fn test_i2_two_tombstones_same_triplet_allowed() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let hostname = format!("{}.i2.test", unique_name("host"));
    let username = "shared_i2";

    let mut tombstone_uuids: Vec<Uuid> = Vec::new();

    for i in 0..3 {
        let id = insert_active_asset(&mut conn, &format!("i2-{}", i), &hostname, 22, username).await;
        let uuid: Uuid = assets::table
            .filter(assets::id.eq(id))
            .select(assets::uuid)
            .first(&mut conn)
            .await
            .expect("read uuid back");
        soft_delete_at_db(&mut conn, id).await;
        tombstone_uuids.push(uuid);
    }
    let _final_active = insert_active_asset(&mut conn, "i2-final", &hostname, 22, username).await;

    let active_count: i64 = assets::table
        .filter(assets::hostname.eq(&hostname))
        .filter(assets::port.eq(22))
        .filter(assets::connection_username.eq(username))
        .filter(assets::is_deleted.eq(false))
        .count()
        .get_result(&mut conn)
        .await
        .expect("count active");
    let tombstone_count: i64 = assets::table
        .filter(assets::hostname.eq(&hostname))
        .filter(assets::port.eq(22))
        .filter(assets::connection_username.eq(username))
        .filter(assets::is_deleted.eq(true))
        .count()
        .get_result(&mut conn)
        .await
        .expect("count tombstones");

    assert_eq!(active_count, 1, "exactly one active row must remain");
    assert_eq!(tombstone_count, 3, "three tombstones must coexist");

    let unique_uuids: std::collections::HashSet<_> = tombstone_uuids.into_iter().collect();
    assert_eq!(
        unique_uuids.len(),
        3,
        "every tombstone must carry a distinct UUID (no row reuse)"
    );
}

// =============================================================================
// I3 — CHECK constraint blocks secrets in tombstones
// =============================================================================

/// A direct UPDATE that flips `is_deleted` to true while leaving a
/// non-empty `connection_config` must be rejected by the CHECK
/// constraint `assets_tombstone_no_secrets` (SQLSTATE 23514).
#[tokio::test]
#[serial]
async fn test_i3_purge_must_be_concurrent_with_soft_delete() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let hostname = format!("{}.i3a.test", unique_name("host"));
    let asset_id = insert_active_asset(&mut conn, &unique_name("i3a"), &hostname, 22, "u").await;
    diesel::update(assets::table.filter(assets::id.eq(asset_id)))
        .set(assets::connection_config.eq(json!({"password": "still-here"})))
        .execute(&mut conn)
        .await
        .expect("populate config on the active row");

    let now = chrono::Utc::now();
    let result = diesel::update(assets::table.filter(assets::id.eq(asset_id)))
        .set((
            assets::is_deleted.eq(true),
            assets::deleted_at.eq(now),
            assets::updated_at.eq(now),
        ))
        .execute(&mut conn)
        .await;

    match result {
        Err(DieselError::DatabaseError(DatabaseErrorKind::CheckViolation, info)) => {
            let constraint = info.constraint_name().unwrap_or("");
            assert!(
                constraint.contains("assets_tombstone_no_secrets")
                    || info.message().contains("assets_tombstone_no_secrets"),
                "expected the tombstone CHECK to fire, got constraint='{}' message='{}'",
                constraint,
                info.message()
            );
        }
        other => panic!(
            "expected CheckViolation on assets_tombstone_no_secrets, got {:?}",
            other
        ),
    }

    soft_delete_at_db(&mut conn, asset_id).await;
}

/// Trying to *write* a secret onto an already-tombstoned row must
/// also fail the CHECK -- the constraint applies to the row state
/// after the UPDATE regardless of which column transitions.
#[tokio::test]
#[serial]
async fn test_i3_check_constraint_blocks_secret_in_tombstone() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let hostname = format!("{}.i3b.test", unique_name("host"));
    let asset_id = insert_active_asset(&mut conn, &unique_name("i3b"), &hostname, 22, "u").await;
    soft_delete_at_db(&mut conn, asset_id).await;

    let result = diesel::update(assets::table.filter(assets::id.eq(asset_id)))
        .set(assets::connection_config.eq(json!({"private_key": "leaked-back-in"})))
        .execute(&mut conn)
        .await;

    match result {
        Err(DieselError::DatabaseError(DatabaseErrorKind::CheckViolation, info)) => {
            let msg = info.message();
            assert!(
                msg.contains("assets_tombstone_no_secrets")
                    || info.constraint_name() == Some("assets_tombstone_no_secrets"),
                "expected the tombstone CHECK to fire, got message='{}'",
                msg
            );
        }
        other => panic!(
            "expected CheckViolation on assets_tombstone_no_secrets, got {:?}",
            other
        ),
    }
}

// =============================================================================
// I4 — anti-resurrection trigger
// =============================================================================

/// The headline guarantee: a direct `UPDATE assets SET is_deleted =
/// false WHERE id = ?` on a tombstone must be rejected by the
/// `assets_no_resurrection_trg` trigger. This is the test that proves
/// the contract is enforced by Postgres rather than by the
/// application: it bypasses every Rust call path.
#[tokio::test]
#[serial]
async fn test_i4_resurrection_blocked_by_trigger() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let hostname = format!("{}.i4a.test", unique_name("host"));
    let asset_id = insert_active_asset(&mut conn, &unique_name("i4a"), &hostname, 22, "u").await;
    soft_delete_at_db(&mut conn, asset_id).await;

    let result = diesel::update(assets::table.filter(assets::id.eq(asset_id)))
        .set(assets::is_deleted.eq(false))
        .execute(&mut conn)
        .await;

    match result {
        Err(DieselError::DatabaseError(_, info)) => {
            let msg = info.message();
            assert!(
                msg.contains("assets_no_resurrection")
                    || msg.contains("cannot be restored")
                    || msg.contains("issue #17"),
                "expected the resurrection trigger to fire, got message='{}'",
                msg
            );
        }
        Ok(rows) => panic!(
            "expected the resurrection trigger to reject the UPDATE, got {} affected rows",
            rows
        ),
        other => panic!("unexpected error type: {:?}", other),
    }

    let still_deleted: bool = assets::table
        .filter(assets::id.eq(asset_id))
        .select(assets::is_deleted)
        .first(&mut conn)
        .await
        .expect("read back the tombstone");
    assert!(still_deleted, "the row must remain a tombstone after the failed resurrection");
}

/// Variant: the trigger must fire even when other columns are also
/// being updated in the same statement. We pin this because it would
/// be tempting (and wrong) for a future trigger refactor to gate on
/// "only is_deleted changed".
#[tokio::test]
#[serial]
async fn test_i4_resurrection_blocked_even_with_other_columns_changing() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let hostname = format!("{}.i4b.test", unique_name("host"));
    let asset_id = insert_active_asset(&mut conn, &unique_name("i4b"), &hostname, 22, "u").await;
    soft_delete_at_db(&mut conn, asset_id).await;

    let result = diesel::update(assets::table.filter(assets::id.eq(asset_id)))
        .set((
            assets::is_deleted.eq(false),
            assets::name.eq("trying-to-revive"),
            assets::description.eq(Some("noise to mask the resurrection".to_string())),
        ))
        .execute(&mut conn)
        .await;

    assert!(
        matches!(result, Err(DieselError::DatabaseError(..))),
        "trigger must fire regardless of co-updated columns, got {:?}",
        result
    );

    let row: (bool, String) = assets::table
        .filter(assets::id.eq(asset_id))
        .select((assets::is_deleted, assets::name))
        .first(&mut conn)
        .await
        .expect("read back");
    assert!(row.0, "tombstone flag must remain true");
    assert_ne!(
        row.1, "trying-to-revive",
        "the rejected UPDATE must roll back the co-updated columns too"
    );
}

/// **Defense test** — prove that the resurrection guarantee is
/// enforced by PostgreSQL itself, not by Diesel's typed UPDATE
/// builder. We bypass the typed query layer entirely and ship a
/// hand-rolled `UPDATE` over the raw SQL connection, the way a
/// compromised handler, an `psql` console session, or any future
/// non-Diesel data path (Python script, ad-hoc migration, ETL) would.
/// The trigger MUST still fire.
///
/// This is the canonical "battle-tested" test for issue #17: it is
/// the one that would still catch a regression if someone, in the
/// next refactor, replaced Diesel with sqlx, with a stored procedure,
/// or with raw `pg_query` calls.
#[tokio::test]
#[serial]
async fn test_i4_resurrection_blocked_via_raw_sql_bypassing_orm() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let hostname = format!("{}.i4-raw.test", unique_name("host"));
    let asset_id = insert_active_asset(&mut conn, &unique_name("i4-raw"), &hostname, 22, "u").await;
    soft_delete_at_db(&mut conn, asset_id).await;

    let stmt = format!("UPDATE assets SET is_deleted = false WHERE id = {}", asset_id);
    let result = sql_query(&stmt).execute(&mut conn).await;

    match result {
        Err(DieselError::DatabaseError(_, info)) => {
            let msg = info.message();
            assert!(
                msg.contains("assets_no_resurrection")
                    || msg.contains("cannot be restored")
                    || msg.contains("issue #17"),
                "raw-SQL resurrection must fire the trigger; got message='{}'",
                msg
            );
        }
        Ok(rows) => panic!(
            "raw-SQL resurrection succeeded with {} affected rows -- the DB-level guarantee is broken!",
            rows
        ),
        other => panic!("unexpected error type from raw-SQL resurrection: {:?}", other),
    }

    let stmt2 = format!(
        "UPDATE assets SET is_deleted = false, name = 'raw-revive', \
         updated_at = NOW() WHERE id = {}",
        asset_id
    );
    let result2 = sql_query(&stmt2).execute(&mut conn).await;
    assert!(
        matches!(result2, Err(DieselError::DatabaseError(..))),
        "even a multi-column raw UPDATE must be rejected, got {:?}",
        result2
    );

    let stmt3 = format!(
        "WITH revive AS (UPDATE assets SET is_deleted = false WHERE id = {} \
         RETURNING id) SELECT id FROM revive",
        asset_id
    );
    let result3 = sql_query(&stmt3).execute(&mut conn).await;
    assert!(
        matches!(result3, Err(DieselError::DatabaseError(..))),
        "CTE-wrapped resurrection must also be rejected, got {:?}",
        result3
    );

    let still_deleted: bool = assets::table
        .filter(assets::id.eq(asset_id))
        .select(assets::is_deleted)
        .first(&mut conn)
        .await
        .expect("read back the tombstone");
    assert!(
        still_deleted,
        "after three rejected resurrection attempts, the row MUST still be a tombstone"
    );

    let cfg: serde_json::Value = assets::table
        .filter(assets::id.eq(asset_id))
        .select(assets::connection_config)
        .first(&mut conn)
        .await
        .expect("read back the config");
    assert_eq!(
        cfg,
        json!({}),
        "no rejected attempt may have leaked secrets back into the tombstone"
    );
}

/// A tombstone cannot be reactivated even via an UPDATE that
/// "re-deletes" it: the trigger only fires on the false ← true
/// transition, so updating a tombstone with `is_deleted = true` is a
/// no-op (idempotent) and must succeed. This is the negative
/// counterpart of the previous test -- it pins that the trigger is
/// directional.
#[tokio::test]
#[serial]
async fn test_i4_re_setting_is_deleted_true_on_tombstone_is_noop() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let hostname = format!("{}.i4c.test", unique_name("host"));
    let asset_id = insert_active_asset(&mut conn, &unique_name("i4c"), &hostname, 22, "u").await;
    soft_delete_at_db(&mut conn, asset_id).await;

    let now = chrono::Utc::now();
    let result = diesel::update(assets::table.filter(assets::id.eq(asset_id)))
        .set((assets::is_deleted.eq(true), assets::updated_at.eq(now)))
        .execute(&mut conn)
        .await;
    assert!(
        result.is_ok(),
        "redundant soft-delete on a tombstone must be accepted as a no-op, got {:?}",
        result
    );
}
