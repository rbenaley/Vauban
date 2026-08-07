//! E2E: minimal boot seed vs full `seed_demo_catalog` against `vcp_test`.

use vcp::db::{
    DEMO_DOC_COUNT, DEMO_ISSUE_COUNT, DEMO_RELEASE_COUNT, MINIMAL_DOC_SLUG, seed_demo_catalog,
    seed_minimal_if_empty,
};
use vcp::models::{DocArticle, Issue, Release, User};

use crate::common::{cleanup, db_lock, test_db, wipe_seed_surface};

#[tokio::test]
async fn e2e_minimal_then_demo_catalog_counts() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    wipe_seed_surface(&db).await;

    seed_minimal_if_empty(&db).await.expect("minimal seed");

    let mut conn = db.clone();
    let docs = DocArticle::all().exec(&mut conn).await.expect("docs");
    let releases = Release::all().exec(&mut conn).await.expect("releases");
    let issues = Issue::all().exec(&mut conn).await.expect("issues");
    let users = User::all().exec(&mut conn).await.expect("users");

    assert_eq!(docs.len(), 1, "minimal seed: one Quick start doc");
    assert_eq!(docs[0].slug, MINIMAL_DOC_SLUG);
    assert!(releases.is_empty(), "minimal seed: no releases");
    assert!(issues.is_empty(), "minimal seed: no issues");
    assert_eq!(users.len(), 1, "minimal seed: l.martin only");

    // Second call is a no-op when users exist.
    seed_minimal_if_empty(&db)
        .await
        .expect("minimal seed idempotent");
    let docs_again = DocArticle::all().exec(&mut conn).await.expect("docs");
    assert_eq!(docs_again.len(), 1);

    seed_demo_catalog(&db).await.expect("demo catalog");

    let docs = DocArticle::all().exec(&mut conn).await.expect("docs");
    let releases = Release::all().exec(&mut conn).await.expect("releases");
    let issues = Issue::all().exec(&mut conn).await.expect("issues");

    assert_eq!(docs.len(), DEMO_DOC_COUNT);
    assert_eq!(releases.len(), DEMO_RELEASE_COUNT);
    assert_eq!(issues.len(), DEMO_ISSUE_COUNT);

    // Idempotent full seed keeps stable counts.
    seed_demo_catalog(&db).await.expect("demo catalog again");
    let docs = DocArticle::all().exec(&mut conn).await.expect("docs");
    let releases = Release::all().exec(&mut conn).await.expect("releases");
    let issues = Issue::all().exec(&mut conn).await.expect("issues");
    assert_eq!(docs.len(), DEMO_DOC_COUNT);
    assert_eq!(releases.len(), DEMO_RELEASE_COUNT);
    assert_eq!(issues.len(), DEMO_ISSUE_COUNT);

    // Leave `vcp_test` without the demo catalog: ordinary `cleanup` preserves
    // seed release versions and would push other suites' fixtures off page 1.
    wipe_seed_surface(&db).await;
}
