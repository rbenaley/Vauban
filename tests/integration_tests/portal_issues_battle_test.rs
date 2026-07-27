//! Contention tests for concurrent issue creates under one org.

use std::sync::Arc;

use tokio::sync::Barrier;
use vcp::models::Issue;

use crate::common::{
    cleanup, create_org_with_membership, db_lock, test_db, unique_email, unique_slug,
};

#[tokio::test]
async fn battle_concurrent_issue_creates() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let email = unique_email("battle-iss");
    let slug = unique_slug("battle-iss-org");
    let (_user, org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;

    let n = 8usize;
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::with_capacity(n);
    let url = crate::common::database_url();
    let org_id = org.id;
    let base = unique_slug("iss");

    for i in 0..n {
        let url = url.clone();
        let barrier = barrier.clone();
        let key = format!("TEST-{base}-{i}");
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let db = vcp::db::connect(&url).await.expect("connect");
            let mut conn = db.clone();
            let created = toasty::create!(Issue {
                key: key.clone(),
                title: format!("Battle issue {i}"),
                component: "Portal".to_owned(),
                severity: "Minor".to_owned(),
                status: "Open".to_owned(),
                organization_id: org_id,
                details: format!("details-{i}"),
            })
            .exec(&mut conn)
            .await
            .expect("create issue");
            assert_eq!(created.key, key);
            assert_eq!(created.details, format!("details-{i}"));
        }));
    }

    for h in handles {
        h.await.expect("join");
    }

    {
        let mut conn = db.clone();
        let rows = Issue::all()
            .filter(Issue::fields().organization_id().eq(org_id))
            .exec(&mut conn)
            .await
            .expect("list");
        let ours: Vec<_> = rows
            .into_iter()
            .filter(|i| i.key.starts_with(&format!("TEST-{base}-")))
            .collect();
        assert_eq!(ours.len(), n);
    }

    cleanup(&db).await;
}
