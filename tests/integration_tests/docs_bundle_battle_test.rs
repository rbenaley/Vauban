//! Contention: parallel import of disjoint slug sets; concurrent export dirs.

use std::sync::Arc;

use tokio::sync::Barrier;
use vcp::docs_bundle::{
    BundledArticle, export_articles_to_dir, import_articles_from_dir, serialize_markdown,
};
use vcp::models::{DOC_STATUS_PUBLISHED, DocArticle};

use crate::common::{db_lock, test_db, wipe_seed_surface};

#[tokio::test]
async fn battle_parallel_import_disjoint_slugs() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    wipe_seed_surface(&db).await;

    let n = 4usize;
    let barrier = Arc::new(Barrier::new(n));
    let url = crate::common::database_url();
    let mut handles = Vec::with_capacity(n);
    for i in 0..n {
        let barrier = Arc::clone(&barrier);
        let url = url.clone();
        handles.push(tokio::spawn(async move {
            let dir = tempfile::tempdir().expect("tmpdir");
            let slug = format!("battle-doc-{i}");
            let article = BundledArticle {
                title: format!("Battle {i}"),
                slug: slug.clone(),
                summary: "s".to_owned(),
                category: "API".to_owned(),
                status: DOC_STATUS_PUBLISHED.to_owned(),
                version: "v1".to_owned(),
                body: format!("Body `{i}`"),
            };
            std::fs::write(
                dir.path().join(format!("{slug}__v1.md")),
                serialize_markdown(&article),
            )
            .expect("write");
            barrier.wait().await;
            // Fresh connect per task — Toasty Db handles are not multi-task safe.
            let db = vcp::db::connect(&url).await.expect("connect");
            let report = import_articles_from_dir(&db, dir.path())
                .await
                .expect("import");
            assert_eq!(report.created, 1);
            slug
        }));
    }
    let mut slugs = Vec::new();
    for h in handles {
        slugs.push(h.await.expect("join"));
    }

    let mut conn = db.clone();
    for slug in &slugs {
        let rows = DocArticle::all()
            .filter(DocArticle::fields().slug().eq(slug.clone()))
            .exec(&mut conn)
            .await
            .expect("query");
        assert_eq!(rows.len(), 1, "slug {slug} must be unique");
        assert_eq!(rows[0].status, DOC_STATUS_PUBLISHED);
    }

    wipe_seed_surface(&db).await;
}

#[tokio::test]
async fn battle_parallel_export_to_temp_dirs() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    wipe_seed_surface(&db).await;

    {
        let mut conn = db.clone();
        for i in 0..3u32 {
            let _ = toasty::create!(DocArticle {
                title: format!("Export {i}"),
                summary: "s".to_owned(),
                category: "API".to_owned(),
                slug: format!("export-par-{i}"),
                version: "v1".to_owned(),
                status: DOC_STATUS_PUBLISHED.to_owned(),
                body: "x".to_owned(),
                updated_at: vcp::db::now_unix(),
            })
            .exec(&mut conn)
            .await
            .expect("create");
        }
    }

    let barrier = Arc::new(Barrier::new(2));
    let url = crate::common::database_url();
    let mut handles = Vec::with_capacity(2);
    for _ in 0..2 {
        let barrier = Arc::clone(&barrier);
        let url = url.clone();
        handles.push(tokio::spawn(async move {
            let dir = tempfile::tempdir().expect("tmpdir");
            barrier.wait().await;
            let db = vcp::db::connect(&url).await.expect("connect");
            let report = export_articles_to_dir(&db, dir.path())
                .await
                .expect("export");
            assert!(report.exported >= 3);
            report.exported
        }));
    }
    let a = handles.pop().expect("h").await.expect("join");
    let b = handles.pop().expect("h").await.expect("join");
    assert_eq!(a, b);

    wipe_seed_surface(&db).await;
}
