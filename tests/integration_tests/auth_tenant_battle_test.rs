//! Contention tests for sessions and membership lookups.

use std::sync::Arc;

use tokio::sync::Barrier;
use vcp::{
    auth::{load_user_for_token_hex, persist_session_record},
    db::now_unix,
    models::Membership,
};

use crate::common::{
    cleanup, create_org_with_membership, create_test_user, db_lock, test_db, unique_email,
    unique_slug,
};

#[tokio::test]
async fn battle_concurrent_session_writes() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let email = unique_email("battle-sess");
    let user = create_test_user(&db, &email, "password").await;
    let user_id = user.id;
    let url = crate::common::database_url();
    let n = 8usize;
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::with_capacity(n);

    for i in 0..n {
        let url = url.clone();
        let barrier = barrier.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            // Fresh connect per task — Toasty Db handles are not multi-task safe.
            let db = vcp::db::connect(&url).await.expect("connect");
            let mut conn = db.clone();
            let hex = format!("{i:064x}");
            persist_session_record(&mut conn, hex.clone(), user_id, now_unix() + 3600)
                .await
                .expect("persist");
            let loaded = load_user_for_token_hex(&mut conn, &hex).await;
            assert_eq!(loaded.expect("user").id, user_id);
            let _ = vcp::models::AuthSession::delete_by_token_hash(&mut conn, &hex).await;
        }));
    }

    for h in handles {
        h.await.expect("join");
    }

    cleanup(&db).await;
}

#[tokio::test]
async fn battle_parallel_membership_reads() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let email = unique_email("battle-mem");
    let slug = unique_slug("battle-org");
    let (user, org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;

    // Sanity: membership visible before contention.
    {
        let mut conn = db.clone();
        let rows = Membership::all().exec(&mut conn).await.expect("all");
        assert!(
            rows.iter()
                .any(|m| m.user_id == user.id && m.organization_id == org.id),
            "fixture membership missing"
        );
    }

    let n = 12usize;
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::with_capacity(n);

    let url = crate::common::database_url();
    for _ in 0..n {
        let url = url.clone();
        let barrier = barrier.clone();
        let user_id = user.id;
        let org_id = org.id;
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let db = vcp::db::connect(&url).await.expect("connect");
            let mut conn = db.clone();
            let rows = Membership::all()
                .exec(&mut conn)
                .await
                .expect("memberships");
            let hit = rows
                .into_iter()
                .filter(|m| m.user_id == user_id && m.organization_id == org_id)
                .collect::<Vec<_>>();
            assert_eq!(hit.len(), 1);
            assert_eq!(hit[0].role, "member");
        }));
    }

    for h in handles {
        h.await.expect("join");
    }

    cleanup(&db).await;
}
