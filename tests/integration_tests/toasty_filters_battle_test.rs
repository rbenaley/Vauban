//! Contention: parallel published/channel filtered reads.

use std::sync::Arc;

use tokio::sync::Barrier;
use vcp::{
    db::now_unix,
    models::{DocArticle, Release},
};

use crate::common::{cleanup, db_lock, test_db, unique_slug};

#[tokio::test]
async fn battle_parallel_published_doc_filters() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let pub_slug = unique_slug("tf-pub");
    let draft_slug = unique_slug("tf-draft");
    {
        let mut conn = db.clone();
        let _ = toasty::create!(DocArticle {
            title: "Published filter".to_owned(),
            summary: "s".to_owned(),
            category: "API".to_owned(),
            slug: pub_slug.clone(),
            version: "v1".to_owned(),
            status: "PUBLISHED".to_owned(),
            body: "body".to_owned(),
            updated_at: now_unix(),
        })
        .exec(&mut conn)
        .await
        .expect("pub");
        let _ = toasty::create!(DocArticle {
            title: "Draft filter".to_owned(),
            summary: "s".to_owned(),
            category: "API".to_owned(),
            slug: draft_slug.clone(),
            version: "v1".to_owned(),
            status: "DRAFT".to_owned(),
            body: "body".to_owned(),
            updated_at: now_unix(),
        })
        .exec(&mut conn)
        .await
        .expect("draft");
    }

    let n = 10usize;
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::with_capacity(n);
    let url = crate::common::database_url();

    for _ in 0..n {
        let url = url.clone();
        let barrier = barrier.clone();
        let pub_slug = pub_slug.clone();
        let draft_slug = draft_slug.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let db = vcp::db::connect(&url).await.expect("connect");
            let mut conn = db.clone();
            let published = DocArticle::all()
                .filter(DocArticle::fields().status().eq("PUBLISHED"))
                .exec(&mut conn)
                .await
                .expect("filter");
            assert!(published.iter().any(|d| d.slug == pub_slug));
            assert!(!published.iter().any(|d| d.slug == draft_slug));
        }));
    }

    for h in handles {
        h.await.expect("join");
    }

    cleanup(&db).await;
}

#[tokio::test]
async fn battle_parallel_channel_release_filters() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let lts = unique_slug("tf-lts");
    let eol = unique_slug("tf-eol");
    {
        let mut conn = db.clone();
        for (ver, ch) in [(&lts, "LTS"), (&eol, "EOL")] {
            let _ = toasty::create!(Release {
                version: ver.clone(),
                channel: ch.to_owned(),
                released_on: "2026-07-01".to_owned(),
                size_mb: "1.0".to_owned(),
                sha256: "x".to_owned(),
                status: "PUBLISHED".to_owned(),
                notes: "n".to_owned(),
                organization_id: 0,
            })
            .exec(&mut conn)
            .await
            .expect("rel");
        }
    }

    let n = 8usize;
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::with_capacity(n);
    let url = crate::common::database_url();

    for _ in 0..n {
        let url = url.clone();
        let barrier = barrier.clone();
        let lts = lts.clone();
        let eol = eol.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let db = vcp::db::connect(&url).await.expect("connect");
            let mut conn = db.clone();
            let rows = Release::all()
                .filter(Release::fields().channel().eq("LTS"))
                .exec(&mut conn)
                .await
                .expect("channel");
            assert!(rows.iter().any(|r| r.version == lts));
            assert!(!rows.iter().any(|r| r.version == eol));
        }));
    }

    for h in handles {
        h.await.expect("join");
    }

    cleanup(&db).await;
}
