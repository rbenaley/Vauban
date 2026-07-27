//! Contention tests for concurrent issue creates under one org.

use std::sync::Arc;

use tokio::sync::Barrier;
use vcp::models::{ISSUE_COMMENT_KIND_COMMENT, ISSUE_ROLE_REPORTER, Issue, IssueComment};

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
            let now = vcp::db::now_unix();
            let created = toasty::create!(Issue {
                key: key.clone(),
                title: format!("Battle issue {i}"),
                component: "Portal".to_owned(),
                severity: "Minor".to_owned(),
                status: "Open".to_owned(),
                organization_id: org_id,
                details: format!("details-{i}"),
                opened_by_user_id: 1,
                created_at: now,
                updated_at: now,
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

#[tokio::test]
async fn battle_concurrent_issue_comment_creates() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let email = unique_email("battle-cmt");
    let slug = unique_slug("battle-cmt-org");
    let (user, org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;

    let now = vcp::db::now_unix();
    let issue = {
        let mut conn = db.clone();
        toasty::create!(Issue {
            key: format!("TEST-{}", unique_slug("cmt")),
            title: "Comment battle".to_owned(),
            component: "Portal".to_owned(),
            severity: "Minor".to_owned(),
            status: "Open".to_owned(),
            organization_id: org.id,
            details: "opener".to_owned(),
            opened_by_user_id: user.id,
            created_at: now,
            updated_at: now,
        })
        .exec(&mut conn)
        .await
        .expect("issue")
    };

    let n = 8usize;
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::with_capacity(n);
    let url = crate::common::database_url();
    let issue_id = issue.id;
    let user_id = user.id;

    for i in 0..n {
        let url = url.clone();
        let barrier = barrier.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let db = vcp::db::connect(&url).await.expect("connect");
            let mut conn = db.clone();
            let created = toasty::create!(IssueComment {
                issue_id,
                author_user_id: user_id,
                author_role: ISSUE_ROLE_REPORTER.to_owned(),
                body: format!("reply-{i}"),
                kind: ISSUE_COMMENT_KIND_COMMENT.to_owned(),
                created_at: vcp::db::now_unix(),
            })
            .exec(&mut conn)
            .await
            .expect("comment");
            assert_eq!(created.issue_id, issue_id);
        }));
    }

    for h in handles {
        h.await.expect("join");
    }

    {
        let mut conn = db.clone();
        let rows = IssueComment::all()
            .filter(IssueComment::fields().issue_id().eq(issue_id))
            .exec(&mut conn)
            .await
            .expect("list");
        assert_eq!(rows.len(), n);
    }

    cleanup(&db).await;
}
