//! Contention tests for parallel membership_count / can_add_member.

use std::sync::Arc;

use tokio::sync::Barrier;
use vcp::seats::{can_add_member, membership_count};

use crate::common::{
    cleanup, create_membership, create_org_with_membership, create_test_user, db_lock, test_db,
    unique_email, unique_slug,
};

#[tokio::test]
async fn battle_parallel_seat_helper_reads() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let email = unique_email("battle-co");
    let slug = unique_slug("battle-co-org");
    let (_user, org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;

    // Fill to 3 seats (1 already from create_org_with_membership).
    for i in 0..2 {
        let u = create_test_user(&db, &unique_email(&format!("battle-seat-{i}")), "password").await;
        create_membership(&db, u.id, org.id, "member").await;
    }

    let n = 10usize;
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::with_capacity(n);
    let url = crate::common::database_url();
    let org_id = org.id;

    for _ in 0..n {
        let url = url.clone();
        let barrier = barrier.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let db = vcp::db::connect(&url).await.expect("connect");
            let mut conn = db.clone();
            let count = membership_count(&mut conn, org_id).await.expect("count");
            assert_eq!(count, 3);
            let can = can_add_member(&mut conn, org_id).await.expect("can");
            assert!(can);
        }));
    }

    for h in handles {
        h.await.expect("join");
    }

    cleanup(&db).await;
}
