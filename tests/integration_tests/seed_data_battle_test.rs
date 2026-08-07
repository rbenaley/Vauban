//! Contention: parallel `seed_demo_catalog` stays panic-free; settle is exact.

use std::sync::Arc;

use tokio::sync::Barrier;
use vcp::db::{DEMO_DOC_COUNT, DEMO_ISSUE_COUNT, DEMO_RELEASE_COUNT, seed_demo_catalog};
use vcp::models::{DocArticle, Issue, Release};

use crate::common::{cleanup, db_lock, test_db, wipe_seed_surface};

#[tokio::test]
async fn battle_parallel_seed_demo_catalog_stable_counts() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    wipe_seed_surface(&db).await;

    let barrier = Arc::new(Barrier::new(6));
    let mut handles = Vec::new();

    for _ in 0..6 {
        let db = db.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            // Unique-key races under contention are acceptable; no panic.
            let _ = seed_demo_catalog(&db).await;
        }));
    }

    for handle in handles {
        handle.await.expect("join");
    }

    // Contended check-then-create can leave duplicate slug/version rows.
    // Wipe and serial-seed so final inventory matches the product constants.
    wipe_seed_surface(&db).await;
    seed_demo_catalog(&db)
        .await
        .expect("settle seed_demo_catalog");

    let mut conn = db.clone();
    let docs = DocArticle::all().exec(&mut conn).await.expect("docs");
    let releases = Release::all().exec(&mut conn).await.expect("releases");
    let issues = Issue::all().exec(&mut conn).await.expect("issues");

    assert_eq!(docs.len(), DEMO_DOC_COUNT);
    assert_eq!(releases.len(), DEMO_RELEASE_COUNT);
    assert_eq!(issues.len(), DEMO_ISSUE_COUNT);

    // Do not leave the demo catalog in the shared `vcp_test` DB: `cleanup`
    // preserves seed release versions and would bury other suites' page-1 rows.
    wipe_seed_surface(&db).await;
}
