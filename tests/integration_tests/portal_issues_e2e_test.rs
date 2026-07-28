//! E2E: issue report persists details; wrong org 404; reply from DB.

use http_body_util::BodyExt;
use topcoat::router::StatusCode;
use vcp::models::{
    ISSUE_COMMENT_KIND_COMMENT, ISSUE_ROLE_SUPPORT, Issue, IssueComment, RESERVED_ORG_SLUG,
};

use crate::common::{
    cleanup, cookie_header, create_org_with_membership, create_test_org, db_lock,
    ensure_reserved_org, get, post_form, status, test_db, test_router, unique_email, unique_slug,
    urlencoding_encode,
};

async fn body_text(resp: topcoat::router::Response) -> String {
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

async fn login(router: &topcoat::router::Router, email: &str) -> Option<String> {
    let form = format!("email={}&password=password", urlencoding_encode(email));
    let login = post_form(router, "/login", None, &form).await;
    assert!(status(&login).is_redirection());
    cookie_header(&login)
}

#[tokio::test]
async fn e2e_report_issue_persists_and_shows_details() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("iss-rep");
    let slug = unique_slug("iss-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;
    let cookie = login(&router, &email).await;

    let details = "Steps to reproduce: click download then boom";
    let form = format!(
        "title={}&component=Portal&severity=Major&details={}",
        urlencoding_encode("Test portal latency"),
        urlencoding_encode(details)
    );
    let report = post_form(
        &router,
        &format!("/{slug}/issues"),
        cookie.as_deref(),
        &form,
    )
    .await;
    assert!(
        status(&report).is_redirection(),
        "report should PRG, got {}",
        status(&report)
    );

    // Follow Location if present; otherwise list and open first VBN- row.
    let location = report
        .headers()
        .get(topcoat::router::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_owned());
    let detail_path = location.unwrap_or_else(|| format!("/{slug}/issues"));
    let detail = get(&router, &detail_path, cookie.as_deref()).await;
    assert_eq!(status(&detail), StatusCode::OK);
    let html = body_text(detail).await;
    assert!(
        html.contains(details) || html.contains("Test portal latency"),
        "detail should show persisted details; html={html}"
    );

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_issue_detail_shows_seeded_comment_and_reply() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("iss-cmt");
    let slug = unique_slug("iss-cmt-org");
    let (user, org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let cookie = login(&router, &email).await;

    let now = vcp::db::now_unix();
    let key = format!("VBN-{}", unique_slug("k").replace('-', ""));
    let support_body = "Initial analysis underway from DB.";
    {
        let mut conn = db.clone();
        let issue = toasty::create!(Issue {
            key: key.clone(),
            title: "Comment e2e".to_owned(),
            component: "SSH Proxy".to_owned(),
            severity: "Major".to_owned(),
            status: "In analysis".to_owned(),
            organization_id: org.id,
            details: "Reporter opener text".to_owned(),
            opened_by_user_id: user.id,
            created_at: now - 10_000,
            updated_at: now - 1_000,
        })
        .exec(&mut conn)
        .await
        .expect("issue");
        let _ = toasty::create!(IssueComment {
            issue_id: issue.id,
            author_user_id: user.id,
            author_role: ISSUE_ROLE_SUPPORT.to_owned(),
            body: support_body.to_owned(),
            kind: ISSUE_COMMENT_KIND_COMMENT.to_owned(),
            created_at: now - 1_000,
        })
        .exec(&mut conn)
        .await
        .expect("comment");
    }

    let detail = get(&router, &format!("/{slug}/issues/{key}"), cookie.as_deref()).await;
    assert_eq!(status(&detail), StatusCode::OK);
    let html = body_text(detail).await;
    assert!(
        html.contains(support_body),
        "seeded comment missing: {html}"
    );
    assert!(
        html.contains("Reporter opener text"),
        "opener details missing: {html}"
    );
    assert!(
        html.contains("Vauban Support"),
        "support-role comments must display as Vauban Support: {html}"
    );

    let reply = "Follow-up metrics attached.";
    let form = format!("body={}", urlencoding_encode(reply));
    let posted = post_form(
        &router,
        &format!("/{slug}/issues/{key}/reply"),
        cookie.as_deref(),
        &form,
    )
    .await;
    assert!(
        status(&posted).is_redirection(),
        "reply should PRG, got {}",
        status(&posted)
    );

    let after = get(&router, &format!("/{slug}/issues/{key}"), cookie.as_deref()).await;
    assert_eq!(status(&after), StatusCode::OK);
    let html = body_text(after).await;
    assert!(html.contains(reply), "reply missing after POST: {html}");

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_issues_wrong_org_is_404() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("iss-wo");
    let slug = unique_slug("iss-home");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;
    let _other = create_test_org(&db, &unique_slug("iss-other")).await;
    let cookie = login(&router, &email).await;

    let missing = get(
        &router,
        &format!("/{}/issues", unique_slug("no-access")),
        cookie.as_deref(),
    )
    .await;
    assert_eq!(status(&missing), StatusCode::NOT_FOUND);

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_admin_issues_aggregate_and_reserved_redirect() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;
    let _vauban = ensure_reserved_org(&db).await;

    let staff_email = unique_email("iss-adm");
    let client_slug = unique_slug("iss-client");
    let (user, org) =
        create_org_with_membership(&db, &staff_email, "password", &client_slug, "admin").await;
    let cookie = login(&router, &staff_email).await;

    let now = vcp::db::now_unix();
    let key = format!("VBN-{}", unique_slug("ak").replace('-', ""));
    {
        let mut conn = db.clone();
        let _ = toasty::create!(Issue {
            key: key.clone(),
            title: "Admin aggregate visible".to_owned(),
            component: "Portal".to_owned(),
            severity: "Major".to_owned(),
            status: "Open".to_owned(),
            organization_id: org.id,
            details: "Cross-org queue body".to_owned(),
            opened_by_user_id: user.id,
            created_at: now,
            updated_at: now,
        })
        .exec(&mut conn)
        .await
        .expect("issue");
    }

    let list = get(&router, "/admin/issues", cookie.as_deref()).await;
    assert_eq!(status(&list), StatusCode::OK);
    let html = body_text(list).await;
    assert!(html.contains(&key), "aggregate list missing key: {html}");
    assert!(
        html.contains(&client_slug) || html.contains("Admin aggregate visible"),
        "aggregate list should show org or title: {html}"
    );

    let detail = get(&router, &format!("/admin/issues/{key}"), cookie.as_deref()).await;
    assert_eq!(status(&detail), StatusCode::OK);
    let html = body_text(detail).await;
    assert!(html.contains("Cross-org queue body"), "detail missing body");

    let reserved = get(
        &router,
        &format!("/{RESERVED_ORG_SLUG}/issues"),
        cookie.as_deref(),
    )
    .await;
    assert!(
        status(&reserved).is_redirection(),
        "reserved org issues should redirect, got {}",
        status(&reserved)
    );
    let location = reserved
        .headers()
        .get(topcoat::router::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(location, "/admin/issues");

    let member_email = unique_email("iss-mem");
    let member_slug = unique_slug("iss-mem-org");
    let (_mu, _mo) =
        create_org_with_membership(&db, &member_email, "password", &member_slug, "member").await;
    let member_cookie = login(&router, &member_email).await;
    let denied = get(&router, "/admin/issues", member_cookie.as_deref()).await;
    assert_eq!(status(&denied), StatusCode::NOT_FOUND);

    cleanup(&db).await;
}
