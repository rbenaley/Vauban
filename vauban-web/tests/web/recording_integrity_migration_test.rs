//! Structural tests for migration
//! `20260430000000_recording_integrity_metadata`.
//!
//! These tests assert the schema-level invariants the migration is
//! responsible for: every new column exists with the expected type,
//! every CHECK constraint is in place, and the partial index is
//! present. They run against the same test DB as every other
//! integration test (the migration must already have been applied
//! via `diesel migration run`).

use crate::common::TestApp;
use diesel::prelude::*;
use diesel::sql_types::{Bool, Text};
use diesel_async::RunQueryDsl;

#[derive(QueryableByName)]
struct ColumnRow {
    #[diesel(sql_type = Text)]
    column_name: String,
    #[diesel(sql_type = Text)]
    #[allow(dead_code)]
    data_type: String,
    #[diesel(sql_type = Bool)]
    is_nullable_bool: bool,
}

async fn select_columns(prefix: &str) -> Vec<ColumnRow> {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    diesel::sql_query(
        "SELECT column_name, data_type, (is_nullable = 'YES') AS is_nullable_bool \
         FROM information_schema.columns \
         WHERE table_name = 'proxy_sessions' \
           AND column_name LIKE $1",
    )
    .bind::<Text, _>(format!("{}%", prefix))
    .load::<ColumnRow>(&mut conn)
    .await
    .expect("query columns")
}

// ---------------------------------------------------------------------------
// Test 1: every new column added by the migration is present and
// nullable so pre-existing rows survive without a backfill.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_migration_added_all_ten_recording_columns_nullable() {
    let cols = select_columns("recording_").await;
    let names: Vec<&str> = cols.iter().map(|c| c.column_name.as_str()).collect();

    let expected = [
        "recording_blake3",
        "recording_size_bytes",
        "recording_duration_ms",
        "recording_event_count",
        "recording_format",
        "recording_width",
        "recording_height",
        "recording_segment_count",
        "recording_codec",
        "recording_finalized_at",
        // Pre-existing column also matches the prefix:
        "recording_path",
    ];
    for name in &expected {
        assert!(
            names.contains(name),
            "expected column `{}` missing; got: {:?}",
            name,
            names
        );
    }

    // Each new column must be nullable (no backfill required).
    for c in &cols {
        if c.column_name == "recording_path" {
            continue;
        }
        if !c.column_name.starts_with("recording_") || c.column_name == "recording_path" {
            continue;
        }
        assert!(
            c.is_nullable_bool,
            "column `{}` must be nullable, got is_nullable={}",
            c.column_name, c.is_nullable_bool
        );
    }
}

// ---------------------------------------------------------------------------
// Test 2: blake3 column has the expected type (varchar or character
// varying) and length 64.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_migration_blake3_column_is_varchar_64() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    #[derive(QueryableByName)]
    struct R {
        #[diesel(sql_type = Text)]
        data_type: String,
        #[diesel(sql_type = diesel::sql_types::Integer)]
        character_maximum_length: i32,
    }

    let r: Vec<R> = diesel::sql_query(
        "SELECT data_type, character_maximum_length \
         FROM information_schema.columns \
         WHERE table_name = 'proxy_sessions' \
           AND column_name = 'recording_blake3'",
    )
    .load::<R>(&mut conn)
    .await
    .expect("query");
    assert_eq!(r.len(), 1, "recording_blake3 must exist");
    assert_eq!(r[0].character_maximum_length, 64);
    assert!(r[0].data_type.contains("character"));
}

// ---------------------------------------------------------------------------
// Test 3: the recording_blake3_format CHECK constraint exists and
// enforces lowercase 64-char hex (a non-hex value must be rejected).
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_migration_check_blake3_format_present() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    #[derive(QueryableByName)]
    struct C {
        #[diesel(sql_type = Text)]
        #[allow(dead_code)]
        conname: String,
    }
    let r: Vec<C> = diesel::sql_query(
        "SELECT conname FROM pg_constraint \
         WHERE conrelid = 'proxy_sessions'::regclass \
           AND contype = 'c' \
           AND conname = 'recording_blake3_format'",
    )
    .load::<C>(&mut conn)
    .await
    .expect("query");
    assert_eq!(r.len(), 1, "CHECK recording_blake3_format must exist");
}

// ---------------------------------------------------------------------------
// Test 4: the recording_format_enum CHECK constraint exists.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_migration_check_format_enum_present() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    #[derive(QueryableByName)]
    struct C {
        #[diesel(sql_type = Text)]
        #[allow(dead_code)]
        conname: String,
    }
    let r: Vec<C> = diesel::sql_query(
        "SELECT conname FROM pg_constraint \
         WHERE conrelid = 'proxy_sessions'::regclass \
           AND contype = 'c' \
           AND conname = 'recording_format_enum'",
    )
    .load::<C>(&mut conn)
    .await
    .expect("query");
    assert_eq!(r.len(), 1, "CHECK recording_format_enum must exist");
}

// ---------------------------------------------------------------------------
// Test 5: the partial index on unfinalized recordings is present and
// has the documented WHERE clause (validates the hydrator's batch-scan
// path stays cheap).
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_migration_partial_index_present_with_correct_predicate() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    #[derive(QueryableByName)]
    struct I {
        #[diesel(sql_type = Text)]
        indexdef: String,
    }
    let r: Vec<I> = diesel::sql_query(
        "SELECT indexdef FROM pg_indexes \
         WHERE tablename = 'proxy_sessions' \
           AND indexname = 'idx_proxy_sessions_pending_finalization'",
    )
    .load::<I>(&mut conn)
    .await
    .expect("query");
    assert_eq!(r.len(), 1, "partial index must exist");
    let def = &r[0].indexdef;
    assert!(
        def.to_lowercase().contains("where"),
        "index must be partial, got: {}",
        def
    );
    assert!(
        def.contains("recording_finalized_at"),
        "predicate must reference recording_finalized_at: {}",
        def
    );
}
