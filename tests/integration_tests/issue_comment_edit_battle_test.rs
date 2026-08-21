//! Contention: parallel Support edits last-write-wins.

use std::sync::Arc;

use tokio::sync::Barrier;
use vcp::models::{ISSUE_COMMENT_KIND_COMMENT, ISSUE_ROLE_SUPPORT, IssueComment};

use crate::common::{
    cleanup, create_org_with_membership, create_test_issue, db_lock, login_cookie, post_form,
    status, test_db, test_router, unique_email, unique_slug, urlencoding_encode,
};

#[tokio::test]
async fn battle_parallel_support_comment_edits() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = Arc::new(test_router().await);

    let admin = unique_email("ced-bt-adm");
    let member = unique_email("ced-bt-mem");
    let slug = unique_slug("ced-bt");
    let _ =
        create_org_with_membership(&db, &admin, "password", &unique_slug("ced-bt-adm"), "admin")
            .await;
    let (user, org) = create_org_with_membership(&db, &member, "password", &slug, "member").await;
    let issue = create_test_issue(&db, org.id, user.id, "TEST-ced-bt", "Battle edit", "Open").await;
    let now = vcp::db::now_unix();
    let mut conn = db.clone();
    let comment = toasty::create!(IssueComment {
        issue_id: issue.id,
        author_user_id: user.id,
        author_role: ISSUE_ROLE_SUPPORT.to_owned(),
        body: "seed".to_owned(),
        kind: ISSUE_COMMENT_KIND_COMMENT.to_owned(),
        created_at: now,
        edited_at: 0,
    })
    .exec(&mut conn)
    .await
    .expect("comment");

    let cookie = login_cookie(&router, &admin).await.expect("admin");
    let n = 6usize;
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::new();
    for i in 0..n {
        let router = router.clone();
        let barrier = barrier.clone();
        let cookie = cookie.clone();
        let slug = slug.clone();
        let key = issue.key.clone();
        let id = comment.id;
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            post_form(
                &router,
                &format!("/admin/issues/{key}/edit-comment?org={slug}"),
                Some(&cookie),
                &format!(
                    "comment_id={id}&body={}",
                    urlencoding_encode(&format!("edit-{i}"))
                ),
            )
            .await
        }));
    }
    let mut ok = 0usize;
    for h in handles {
        if status(&h.await.expect("join")).is_redirection() {
            ok += 1;
        }
    }
    assert_eq!(ok, n, "all edits must PRG");

    let rows = IssueComment::all()
        .filter(IssueComment::fields().id().eq(comment.id))
        .limit(1)
        .exec(&mut conn)
        .await
        .expect("reload");
    let body = &rows[0].body;
    assert!(
        body.starts_with("edit-"),
        "last write must be one of the parallel bodies, got {body}"
    );
    assert!(rows[0].edited_at > 0);

    cleanup(&db).await;
}
