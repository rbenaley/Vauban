//! E2E: issue comments render docs dialect; titles and mail stay raw.

use http_body_util::BodyExt;
use topcoat::mail::{MemoryTransport, TextBody};
use topcoat::router::StatusCode;
use vcp::models::{ISSUE_COMMENT_KIND_COMMENT, ISSUE_ROLE_SUPPORT, IssueComment};

use crate::common::{
    cleanup, create_org_with_membership, create_test_issue, db_lock, get, login_cookie,
    post_multipart_with_files, status, test_db, test_router, test_router_with_memory_mail,
    unique_email, unique_slug,
};

async fn body_text(resp: topcoat::router::response::Response) -> String {
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

const FENCE_BODY: &str =
    "See the snippet:\n\n```\nssh allow-from 10.0.0.1\n```\n\nUse `PermitRootLogin`.";

#[tokio::test]
async fn e2e_issue_comment_renders_dialect_title_stays_raw() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let member = unique_email("icf-mem");
    let slug = unique_slug("icf-org");
    let (user, org) = create_org_with_membership(&db, &member, "password", &slug, "member").await;
    let title = "## not a heading `code`";
    let issue = create_test_issue(&db, org.id, user.id, "TEST-icf-1", title, "In analysis").await;
    let cookie = login_cookie(&router, &member).await.expect("login");
    let posted = post_multipart_with_files(
        &router,
        &format!("/{slug}/issues/{}/reply", issue.key),
        Some(&cookie),
        &[("body", FENCE_BODY)],
        &[],
    )
    .await;
    assert!(status(&posted).is_redirection());

    let page = get(
        &router,
        &format!("/{slug}/issues/{}", issue.key),
        Some(&cookie),
    )
    .await;
    assert_eq!(status(&page), StatusCode::OK);
    let html = body_text(page).await;
    assert!(
        html.contains("vb-pre") && html.contains("ssh allow-from 10.0.0.1"),
        "comment fence must render as vb-pre: {html}"
    );
    assert!(
        html.contains("vb-inline-code") && html.contains("PermitRootLogin"),
        "inline code must chip: {html}"
    );
    assert!(html.contains(title), "title must stay raw text: {html}");
    let title_idx = html.find(title).expect("title");
    let before = &html[title_idx.saturating_sub(80)..title_idx];
    assert!(
        before.contains("vb-title"),
        "raw title must sit in vb-title, not a dialect h3: {before}"
    );

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_issue_comment_mail_excerpt_stays_raw() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let memory = MemoryTransport::new();
    let router = test_router_with_memory_mail(memory.clone()).await;

    let admin = unique_email("icf-adm");
    let member = unique_email("icf-mail-mem");
    let slug = unique_slug("icf-mail");
    let _ =
        create_org_with_membership(&db, &admin, "password", &unique_slug("icf-adm"), "admin").await;
    let (_user, _org) = create_org_with_membership(&db, &member, "password", &slug, "member").await;
    let cookie = login_cookie(&router, &member).await.expect("member");
    let report = post_multipart_with_files(
        &router,
        &format!("/{slug}/issues"),
        Some(&cookie),
        &[
            ("title", "Mail raw excerpt"),
            ("component", "Portal"),
            ("severity", "Major"),
            ("details", "opener"),
        ],
        &[],
    )
    .await;
    assert!(status(&report).is_redirection());
    let loc = report
        .headers()
        .get(topcoat::router::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .expect("loc")
        .to_owned();
    let key = loc.rsplit('/').next().unwrap().split('?').next().unwrap();

    memory.clear();
    let posted = post_multipart_with_files(
        &router,
        &format!("/{slug}/issues/{key}/reply"),
        Some(&cookie),
        &[("body", FENCE_BODY)],
        &[],
    )
    .await;
    assert!(status(&posted).is_redirection());

    let sent = memory.sent();
    assert!(
        sent.iter().any(|m| {
            let t = match m.text() {
                TextBody::Text(s) => s.clone(),
                _ => String::new(),
            };
            t.contains("```") && t.contains("ssh allow-from")
        }),
        "mail must keep raw fences, got {sent:?}"
    );

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_admin_issue_comment_uses_same_renderer() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let admin = unique_email("icf-adm2");
    let member = unique_email("icf-mem2");
    let slug = unique_slug("icf-adm-org");
    let _ = create_org_with_membership(&db, &admin, "password", &unique_slug("icf-adm2"), "admin")
        .await;
    let (user, org) = create_org_with_membership(&db, &member, "password", &slug, "member").await;
    let now = vcp::db::now_unix();
    let issue = create_test_issue(&db, org.id, user.id, "TEST-icf-adm", "Admin view", "Open").await;
    let mut conn = db.clone();
    let _ = toasty::create!(IssueComment {
        issue_id: issue.id,
        author_user_id: user.id,
        author_role: ISSUE_ROLE_SUPPORT.to_owned(),
        body: FENCE_BODY.to_owned(),
        kind: ISSUE_COMMENT_KIND_COMMENT.to_owned(),
        created_at: now,
        edited_at: 0,
    })
    .exec(&mut conn)
    .await
    .expect("comment");

    let cookie = login_cookie(&router, &admin).await.expect("admin");
    let page = get(
        &router,
        &format!("/admin/issues/{}?org={slug}", issue.key),
        Some(&cookie),
    )
    .await;
    assert_eq!(status(&page), StatusCode::OK);
    let html = body_text(page).await;
    assert!(html.contains("vb-pre") && html.contains("ssh allow-from 10.0.0.1"));
    assert!(html.contains("DIALECT_HINT") || html.contains("fence a code block"));

    cleanup(&db).await;
}
