//! Contention: parallel resync + export do not panic or drop rows.

use std::sync::Arc;

use tokio::sync::Barrier;
use vcp::db::{self, now_unix};
use vcp::docs_bundle::export_articles_to_dir;
use vcp::models::DocArticle;

use crate::common::{cleanup, db_lock, test_db, unique_slug, wipe_seed_surface};

#[tokio::test]
async fn battle_parallel_resync_and_export() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    wipe_seed_surface(&db).await;

    {
        let mut conn = db.clone();
        for i in 0..11 {
            let _ = toasty::create!(DocArticle {
                title: format!("Battle {i}"),
                summary: "s".to_owned(),
                category: "API".to_owned(),
                slug: unique_slug(&format!("btl-{i}")),
                version: "v1".to_owned(),
                status: "DRAFT".to_owned(),
                body: "body".to_owned(),
                updated_at: now_unix(),
            })
            .exec(&mut conn)
            .await
            .expect("doc");
        }
    }

    let barrier = Arc::new(Barrier::new(4));
    let mut handles = Vec::new();
    for i in 0..4 {
        let url = crate::common::database_url();
        let barrier = Arc::clone(&barrier);
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let db = db::connect(&url).await.expect("connect");
            if i % 2 == 0 {
                db::resync_release_sort_keys(&db).await.expect("resync");
            } else {
                let dir = tempfile::tempdir().expect("dir");
                let _ = export_articles_to_dir(&db, dir.path())
                    .await
                    .expect("export");
            }
        }));
    }

    for handle in handles {
        handle.await.expect("join");
    }

    let mut conn = db.clone();
    let n = DocArticle::all()
        .count()
        .exec(&mut conn)
        .await
        .expect("count");
    assert_eq!(n, 11u64);
}
