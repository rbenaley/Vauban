//! E2E: export and resync walk more than one cursor page.

use vcp::db::{self, now_unix};
use vcp::docs_bundle::export_articles_to_dir;
use vcp::models::{DocArticle, Release};

use crate::common::{cleanup, db_lock, test_db, unique_slug, wipe_seed_surface};

#[tokio::test]
async fn e2e_export_covers_more_than_one_page() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    wipe_seed_surface(&db).await;

    let mut conn = db.clone();
    for i in 0..11 {
        toasty::create!(DocArticle {
            title: format!("Scan {i}"),
            summary: "s".to_owned(),
            category: "API".to_owned(),
            slug: unique_slug(&format!("scan-{i}")),
            version: "v1".to_owned(),
            status: "PUBLISHED".to_owned(),
            body: format!("body {i}"),
            updated_at: now_unix(),
        })
        .exec(&mut conn)
        .await
        .expect("create");
    }

    let dir = tempfile::tempdir().expect("export dir");
    let report = export_articles_to_dir(&db, dir.path())
        .await
        .expect("export");
    assert_eq!(report.exported, 11);
    let files = std::fs::read_dir(dir.path())
        .expect("read")
        .filter(|e| {
            e.as_ref()
                .ok()
                .and_then(|e| e.path().extension().map(|x| x == "md"))
                .unwrap_or(false)
        })
        .count();
    assert_eq!(files, 11);
}

#[tokio::test]
async fn e2e_resync_is_idempotent_across_pages() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    wipe_seed_surface(&db).await;

    let mut conn = db.clone();
    for i in 0..11 {
        toasty::create!(Release {
            version: format!("v0.0.{i}-paginate"),
            channel: "Stable".to_owned(),
            released_on: "2026-01-01".to_owned(),
            status: "HIDDEN".to_owned(),
            notes: String::new(),
            organization_id: 0,
            v_major: 0,
            v_minor: 0,
            v_patch: 0,
            is_industrial: 0,
            has_client_suffix: 0,
            client_suffix: String::new(),
            product_track: "Stable".to_owned(),
        })
        .exec(&mut conn)
        .await
        .expect("release");
    }

    db::resync_release_sort_keys(&db).await.expect("resync 1");
    db::resync_release_sort_keys(&db).await.expect("resync 2");

    let rows = Release::all()
        .filter(Release::fields().version().starts_with("v0.0."))
        .exec(&mut conn)
        .await
        .expect("list");
    assert!(rows.len() >= 11);
    for row in rows {
        if !row.version.contains("-paginate") {
            continue;
        }
        assert_eq!(row.v_major, 0);
        assert_eq!(row.product_track, "Stable");
    }
}
