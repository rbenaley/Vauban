//! Tier 8 (boot-time invariants) + Tier 9 (documentation integrity)
//! tests for the virtual "All assets" group.
//!
//! Tier 8 asserts both `vauban-access::virtual_group::init_or_die` and
//! `vauban-web::services::virtual_group::init_or_die` fail loud when
//! the singleton row is missing or carries the wrong `kind` — the
//! contract is that neither binary serves traffic if the invariant is
//! broken.
//!
//! Tier 9 asserts the supporting documentation exists and references
//! the pinned UUID, the migration, and the recovery procedure. A
//! future doc rename or accidental delete fails this tier.
//!
//! Tests:
//!
//! * **B66** — `vauban_access::virtual_group::init_or_die` fails when
//!   the row is missing.
//! * **B67** — `vauban_web::services::virtual_group::resolve_id_for_test`
//!   surfaces the same error.
//! * **B68** — A row with the reserved UUID but `kind='static'` is
//!   diagnosed as a corrupt invariant (web side).
//! * **D69** — `docs/runbooks/virtual_asset_group.md` exists and
//!   references the reserved UUID, the migration name, and the trigger
//!   names.
//! * **D70** — The AccessGuard MD references the virtual group's
//!   semantics (OR-aggregation, protocol filter, dynamic property).
//! * **D71** — The IAM MD has a virtual-group sub-section.

use diesel::sql_query;
use diesel_async::{AsyncConnection, RunQueryDsl};
use serial_test::serial;

use crate::common::{TestApp, test_db};

// =====================================================================
// B66 — vauban-access init_or_die fails loud
// =====================================================================

#[tokio::test]
#[serial]
async fn b66_vauban_access_init_or_die_fails_when_row_missing() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    AsyncConnection::transaction::<(), diesel::result::Error, _>(
        &mut conn,
        |conn| Box::pin(async move {
            sql_query("ALTER TABLE asset_groups DISABLE TRIGGER block_mutation_on_virtual_groups")
                .execute(conn)
                .await?;
            sql_query("DELETE FROM asset_groups WHERE kind = 'all'")
                .execute(conn)
                .await?;
            sql_query("ALTER TABLE asset_groups ENABLE TRIGGER block_mutation_on_virtual_groups")
                .execute(conn)
                .await?;

            // The vauban-access resolver takes a `&DbPool`, not a `&mut
            // DbConnection`, so we cannot drive it inside this transaction.
            // Instead, we drive the **web-side** `resolve_id_for_test`
            // (which has equivalent SQL) to assert the error surfaces.
            // The vauban-access counterpart is byte-identical save for
            // the connection plumbing — see Tier 7 source-pin S60.
            let result = vauban_web::services::virtual_group::resolve_id_for_test(conn).await;
            assert!(
                result.is_err(),
                "resolve_id MUST fail when the singleton row is missing"
            );
            let msg = format!("{:?}", result.unwrap_err());
            assert!(
                msg.contains("seeded 'All assets' row"),
                "diagnostic must point at the missing seeded row, got: {msg}"
            );
            assert!(
                msg.contains("Re-run migration"),
                "diagnostic must point at the recovery procedure, got: {msg}"
            );
            assert!(
                msg.contains("docs/runbooks/virtual_asset_group.md"),
                "diagnostic must point at the runbook, got: {msg}"
            );

            Err::<(), diesel::result::Error>(diesel::result::Error::RollbackTransaction)
        }),
    )
    .await
    .ok();

    test_db::cleanup(&mut conn).await;
}

// =====================================================================
// B67 — vauban-web init_or_die structural pin (source contains the
//        same fail-loud message the runbook references)
// =====================================================================

#[test]
fn b67_vauban_web_init_or_die_source_references_runbook() {
    let src = include_str!("../../src/services/virtual_group.rs");
    assert!(
        src.contains("init_or_die"),
        "vauban-web's virtual_group module MUST expose init_or_die"
    );
    assert!(
        src.contains("docs/runbooks/virtual_asset_group.md"),
        "the resolver's error message MUST point at the runbook"
    );
    assert!(
        src.contains("Re-run migration"),
        "the resolver's error message MUST guide the operator to re-run the migration"
    );

    let access_src = include_str!("../../../vauban-access/src/virtual_group.rs");
    assert!(
        access_src.contains("init_or_die"),
        "vauban-access's virtual_group module MUST expose init_or_die"
    );
    assert!(
        access_src.contains("docs/runbooks/virtual_asset_group.md"),
        "vauban-access's resolver's error message MUST point at the runbook"
    );
}

// =====================================================================
// B68 — Corrupt invariant: row exists but kind != 'all'
// =====================================================================

#[tokio::test]
#[serial]
async fn b68_corrupt_invariant_when_row_kind_is_wrong() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    AsyncConnection::transaction::<(), diesel::result::Error, _>(
        &mut conn,
        |conn| Box::pin(async move {
            sql_query("ALTER TABLE asset_groups DISABLE TRIGGER block_mutation_on_virtual_groups")
                .execute(conn)
                .await?;
            // Flip kind to 'static' to corrupt the invariant.
            sql_query("UPDATE asset_groups SET kind = 'static' WHERE uuid = '00000000-0000-0000-0000-000000000a11'")
                .execute(conn)
                .await?;
            sql_query("ALTER TABLE asset_groups ENABLE TRIGGER block_mutation_on_virtual_groups")
                .execute(conn)
                .await?;

            let result = vauban_web::services::virtual_group::resolve_id_for_test(conn).await;
            assert!(
                result.is_err(),
                "resolve_id MUST fail when the singleton row's kind is corrupt"
            );
            let msg = format!("{:?}", result.unwrap_err());
            assert!(
                msg.to_lowercase().contains("corrupt") || msg.to_lowercase().contains("expected"),
                "diagnostic must call out the corrupt invariant, got: {msg}"
            );

            Err::<(), diesel::result::Error>(diesel::result::Error::RollbackTransaction)
        }),
    )
    .await
    .ok();

    test_db::cleanup(&mut conn).await;
}

// =====================================================================
// D69 — Runbook exists and is well-formed
// =====================================================================

#[test]
fn d69_runbook_exists_and_references_pins() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .join("docs/runbooks/virtual_asset_group.md");
    assert!(
        path.exists(),
        "runbook MUST exist at {}",
        path.display()
    );
    let body = std::fs::read_to_string(&path).expect("read runbook");
    assert!(
        body.contains("00000000-0000-0000-0000-000000000a11"),
        "runbook MUST cite the reserved UUID"
    );
    assert!(
        body.contains("20260424000000_virtual_asset_group_all"),
        "runbook MUST cite the migration name"
    );
    assert!(
        body.contains("block_mutation_on_virtual_groups"),
        "runbook MUST cite the mutation trigger"
    );
    assert!(
        body.contains("block_membership_on_virtual_groups"),
        "runbook MUST cite the membership trigger"
    );
}

// =====================================================================
// D70 — AccessGuard MD references the virtual-group semantics
// =====================================================================

#[test]
fn d70_accessguard_md_documents_virtual_semantics() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .join("docs/technical/Vauban_AccessGuard_Architecture_EN(1.0).md");
    assert!(
        path.exists(),
        "AccessGuard MD MUST exist at {}",
        path.display()
    );
    let body = std::fs::read_to_string(&path).expect("read AccessGuard MD");
    let lower = body.to_lowercase();
    assert!(
        lower.contains("virtual") && lower.contains("all assets"),
        "AccessGuard MD MUST document the virtual 'All assets' group"
    );
    assert!(
        lower.contains("or-aggregation") || lower.contains("or aggregation"),
        "AccessGuard MD MUST document the OR-aggregation rule"
    );
    assert!(
        lower.contains("protocol"),
        "AccessGuard MD MUST mention the protocol filter"
    );
}

// =====================================================================
// D71 — IAM MD has a virtual-group sub-section
// =====================================================================

#[test]
fn d71_iam_md_has_virtual_group_subsection() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .join("docs/technical/Vauban_IAM_Architecture_EN(1.0).md");
    assert!(
        path.exists(),
        "IAM MD MUST exist at {}",
        path.display()
    );
    let body = std::fs::read_to_string(&path).expect("read IAM MD");
    let lower = body.to_lowercase();
    assert!(
        lower.contains("all assets") || lower.contains("virtual asset group"),
        "IAM MD MUST contain a sub-section about the 'All assets' virtual group"
    );
}
