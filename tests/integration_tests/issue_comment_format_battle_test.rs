//! Contention: parallel issue-page renders keep dialect HTML.

use std::sync::Arc;

use http_body_util::BodyExt;
use tokio::sync::Barrier;
use topcoat::router::StatusCode;
use vcp::models::{ISSUE_COMMENT_KIND_COMMENT, ISSUE_ROLE_SUPPORT, IssueComment};

use crate::common::{
    cleanup, create_org_with_membership, create_test_issue, db_lock, get, login_cookie, status,
    test_db, test_router, unique_email, unique_slug,
};

#[tokio::test]
async fn battle_parallel_issue_pages_emit_vb_pre() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = Arc::new(test_router().await);

    let member = unique_email("icf-bt-mem");
    let slug = unique_slug("icf-bt");
    let (user, org) = create_org_with_membership(&db, &member, "password", &slug, "member").await;
    let issue =
        create_test_issue(&db, org.id, user.id, "TEST-icf-bt", "Battle format", "Open").await;
    let now = vcp::db::now_unix();
    let mut conn = db.clone();
    let _ = toasty::create!(IssueComment {
        issue_id: issue.id,
        author_user_id: user.id,
        author_role: ISSUE_ROLE_SUPPORT.to_owned(),
        body: "```\nparallel-fence\n```".to_owned(),
        kind: ISSUE_COMMENT_KIND_COMMENT.to_owned(),
        created_at: now,
        edited_at: 0,
    })
    .exec(&mut conn)
    .await
    .expect("comment");

    let cookie = login_cookie(&router, &member).await.expect("login");
    let n = 8usize;
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::new();
    for _ in 0..n {
        let router = router.clone();
        let barrier = barrier.clone();
        let cookie = cookie.clone();
        let path = format!("/{slug}/issues/{}", issue.key);
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let resp = get(&router, &path, Some(&cookie)).await;
            let st = status(&resp);
            let html = {
                let bytes = resp.into_body().collect().await.expect("body").to_bytes();
                String::from_utf8_lossy(&bytes).into_owned()
            };
            (st, html)
        }));
    }

    for h in handles {
        let (st, html) = h.await.expect("join");
        assert_eq!(st, StatusCode::OK);
        assert!(
            html.contains("vb-pre") && html.contains("parallel-fence"),
            "every concurrent render must emit the fence: {html}"
        );
    }

    cleanup(&db).await;
}
