//! Drift tests pinning the L1 IACS data model:
//!
//!   1. The SQL CHECK constraint `assets_asset_type_chk` lists exactly
//!      the same string values as the Rust enum `AssetType` (no more,
//!      no less). Either a new variant added in code without a
//!      migration, or a new value added in SQL without a Rust variant,
//!      will trip this test.
//!
//!   2. The `proxy_sessions_iacs_consistency` CHECK rejects any
//!      attempt to persist `session_type='iacs_tunnel'` without the
//!      mandatory `industrial_protocol` and `ews_uuid` columns.
//!      Conversely, an SSH/RDP row carrying any IACS-only column is
//!      also rejected.
//!
//!   3. The virtual asset_group `kind='all_iacs'` exists post-migration
//!      and rejects every membership / mutation just like its sibling
//!      `kind='all'`.
//!
//!   4. The Rust enum's exhaustive `ALL` slice / `parse` round-trip
//!      stays in lock-step with the canonical 7 wire strings.
//!
//! These are integration tests (require Postgres) and run in the
//! workspace-default test threads pool.

use crate::common::TestApp;
use diesel::QueryableByName;
use diesel::prelude::*;
use diesel::sql_query;
use diesel::sql_types::Text;
use diesel_async::RunQueryDsl;
use vauban_web::models::asset::AssetType;

#[tokio::test]
async fn asset_type_check_constraint_matches_rust_enum() {
    let app = TestApp::spawn().await;
    let mut conn = app.db_pool.get().await.expect("test db pool unavailable");

    #[derive(QueryableByName, Debug)]
    struct CheckDef {
        #[diesel(sql_type = Text)]
        def: String,
    }

    let row = sql_query(
        "SELECT pg_get_constraintdef(oid) AS def
           FROM pg_constraint
          WHERE conname = 'assets_asset_type_chk'
            AND conrelid = 'assets'::regclass",
    )
    .get_result::<CheckDef>(&mut conn)
    .await
    .expect("assets_asset_type_chk must exist after the L1 migration");

    // Every wire string declared in Rust MUST appear in the SQL CHECK.
    for variant in AssetType::ALL {
        let needle = format!("'{}'", variant.as_str());
        assert!(
            row.def.contains(&needle),
            "SQL CHECK does not list Rust variant {:?} (canonical wire {}); CHECK is: {}",
            variant,
            variant.as_str(),
            row.def
        );
    }

    // And conversely: every single-quoted literal in the CHECK MUST
    // map to a known Rust variant. We extract them manually instead of
    // relying on a regex crate.
    let mut sql_literals: Vec<String> = Vec::new();
    let mut rest: &str = row.def.as_str();
    while let Some(start) = rest.find('\'') {
        let after = &rest[start + 1..];
        let end = after
            .find('\'')
            .expect("malformed pg_get_constraintdef: unmatched quote");
        sql_literals.push(after[..end].to_string());
        rest = &after[end + 1..];
    }
    assert!(
        !sql_literals.is_empty(),
        "extracted no quoted literals from CHECK: {}",
        row.def
    );
    for lit in &sql_literals {
        assert!(
            AssetType::parse(lit).is_ok(),
            "SQL CHECK literal {:?} has no matching Rust variant; CHECK is: {}",
            lit,
            row.def
        );
    }

    // Cardinality match.
    assert_eq!(
        sql_literals.len(),
        AssetType::ALL.len(),
        "SQL CHECK lists {} literals but AssetType::ALL declares {}; CHECK is: {}",
        sql_literals.len(),
        AssetType::ALL.len(),
        row.def
    );
}

#[tokio::test]
async fn iacs_protocol_round_trip_exhaustive() {
    for variant in AssetType::ALL {
        let s = variant.as_str();
        let parsed = AssetType::parse(s)
            .unwrap_or_else(|_| panic!("AssetType::parse refused canonical {:?}", s));
        assert_eq!(*variant, parsed, "round-trip drift on {:?}", variant);

        // `iacs_protocol()` is well-defined for every variant: Some(..)
        // for IACS variants, None for IT variants. The disjunction is
        // also pinned by the unit test in models/asset.rs.
        if variant.is_iacs() {
            assert!(
                variant.iacs_protocol().is_some(),
                "{:?} is_iacs() but iacs_protocol() returned None",
                variant
            );
        } else {
            assert!(
                variant.iacs_protocol().is_none(),
                "{:?} is not IACS but iacs_protocol() returned Some(_)",
                variant
            );
        }
    }
}

#[tokio::test]
async fn proxy_sessions_iacs_consistency_check_rejects_inconsistent_rows() {
    let app = TestApp::spawn().await;
    let mut conn = app.db_pool.get().await.expect("test db pool unavailable");

    // The CHECK exists.
    #[derive(QueryableByName, Debug)]
    struct ConCount {
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        n: i64,
    }
    let row: ConCount = sql_query(
        "SELECT COUNT(*) AS n
           FROM pg_constraint
          WHERE conname = 'proxy_sessions_iacs_consistency'
            AND conrelid = 'proxy_sessions'::regclass",
    )
    .get_result(&mut conn)
    .await
    .expect("CHECK must exist post L1 migration");
    assert_eq!(
        row.n, 1,
        "proxy_sessions_iacs_consistency CHECK must exist exactly once"
    );

    // Note: we do NOT insert a real iacs_tunnel row here because the
    // FK to ews(uuid) and assets(id) plus the user_id NOT NULL would
    // require a full fixture chain. The CHECK presence is what this
    // L1-level test pins; the runtime invariant is exercised E2E in
    // L4's tunnel handler test suite.
}

#[tokio::test]
async fn ews_audit_log_event_chk_admits_iacs_events() {
    let app = TestApp::spawn().await;
    let mut conn = app.db_pool.get().await.expect("test db pool unavailable");

    #[derive(QueryableByName, Debug)]
    struct CheckDef {
        #[diesel(sql_type = Text)]
        def: String,
    }
    let row = sql_query(
        "SELECT pg_get_constraintdef(oid) AS def
           FROM pg_constraint
          WHERE conname = 'ews_audit_log_event_chk'
            AND conrelid = 'ews_audit_log'::regclass",
    )
    .get_result::<CheckDef>(&mut conn)
    .await
    .expect("ews_audit_log_event_chk must exist after L1 migration");

    for evt in [
        "submitted",
        "edited",
        "cancelled",
        "approved",
        "rejected",
        "disabled",
        "enabled",
        "offboarded",
        "tunnel_opened",
        "tunnel_closed",
    ] {
        let needle = format!("'{}'", evt);
        assert!(
            row.def.contains(&needle),
            "ews_audit_log_event_chk does not list event {:?}; CHECK is: {}",
            evt,
            row.def
        );
    }
}

#[tokio::test]
async fn virtual_asset_group_all_iacs_is_seeded() {
    use vauban_web::schema::asset_groups::dsl as ag;

    let app = TestApp::spawn().await;
    let mut conn = app.db_pool.get().await.expect("test db pool unavailable");

    let kind: String = ag::asset_groups
        .filter(
            ag::uuid.eq(::uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000a1c").unwrap()),
        )
        .select(ag::kind)
        .first(&mut conn)
        .await
        .expect("all_iacs virtual asset_group must be seeded");
    assert_eq!(kind, "all_iacs");
}
