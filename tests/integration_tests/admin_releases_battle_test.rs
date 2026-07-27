//! Contention tests for concurrent Release creates.

use std::sync::Arc;

use tokio::sync::Barrier;
use vcp::models::Release;

use crate::common::{cleanup, db_lock, test_db, unique_slug};

#[tokio::test]
async fn battle_concurrent_release_creates() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let n = 8usize;
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::with_capacity(n);
    let url = crate::common::database_url();
    let base = unique_slug("rel");

    for i in 0..n {
        let url = url.clone();
        let barrier = barrier.clone();
        let version = format!("{base}-{i}");
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let db = vcp::db::connect(&url).await.expect("connect");
            let mut conn = db.clone();
            let created = toasty::create!(Release {
                version: version.clone(),
                channel: "LTS".to_owned(),
                released_on: "2026-07-01".to_owned(),
                size_mb: "1.0".to_owned(),
                signature_prefix: "pending".to_owned(),
                status: "PUBLISHED".to_owned(),
                notes: "FIX: battle".to_owned(),
            })
            .exec(&mut conn)
            .await
            .expect("create release");
            assert_eq!(created.version, version);
        }));
    }

    for h in handles {
        h.await.expect("join");
    }

    {
        let mut conn = db.clone();
        let rows = Release::all().exec(&mut conn).await.expect("all");
        let ours = rows.iter().filter(|r| r.version.starts_with(&base)).count();
        assert_eq!(ours, n);
    }

    cleanup(&db).await;
}
