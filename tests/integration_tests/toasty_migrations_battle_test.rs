//! Contention: parallel connect / apply_pending_migrations stays idempotent.

use std::sync::Arc;

use tokio::sync::Barrier;
use vcp::db;

use crate::common::{database_url, db_lock};

#[tokio::test]
async fn battle_parallel_connect_applies_migrations_once() {
    let _guard = db_lock().lock().await;
    let url = database_url();
    let barrier = Arc::new(Barrier::new(8));
    let mut handles = Vec::new();

    for _ in 0..8 {
        let url = url.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            db::connect(&url).await.expect("connect+migrate")
        }));
    }

    for handle in handles {
        let _db = handle.await.expect("join");
    }

    // Second wave: already-applied migrations must be a no-op.
    let db = db::connect(&url).await.expect("reconnect");
    db::apply_pending_migrations(&db)
        .await
        .expect("idempotent apply");
}
