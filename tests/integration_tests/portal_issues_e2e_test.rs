//! E2E: issue report persists details; wrong org 404; reply from DB.

use http_body_util::BodyExt;
use topcoat::router::StatusCode;
use vcp::models::{
    ISSUE_COMMENT_KIND_COMMENT, ISSUE_COMMENT_KIND_STATUS, ISSUE_ROLE_SUPPORT, ISSUE_STATUS_CLOSED,
    ISSUE_STATUS_OPEN, Issue, IssueComment, RESERVED_ORG_SLUG,
};

use crate::common::{
    cleanup, create_org_with_membership, create_test_org, db_lock, ensure_reserved_org, get,
    login_cookie, post_form, status, test_db, test_router, unique_email, unique_slug,
    urlencoding_encode,
};

async fn body_text(resp: topcoat::router::Response) -> String {
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

async fn login(router: &topcoat::router::Router, email: &str) -> Option<String> {
    login_cookie(router, email).await
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

    let location = report
        .headers()
        .get(topcoat::router::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_owned())
        .expect("Location after report");
    assert!(
        location.starts_with(&format!("/{slug}/issues/VBN-")),
        "happy create must land on detail URL, got {location}"
    );
    assert!(
        !location.contains("err=create"),
        "successful create must not use err=create"
    );
    let detail = get(&router, &location, cookie.as_deref()).await;
    assert_eq!(status(&detail), StatusCode::OK);
    let html = body_text(detail).await;
    assert!(
        html.contains(details) || html.contains("Test portal latency"),
        "detail should show persisted details; html={html}"
    );

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_report_issue_empty_title_skips_create() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("iss-empty");
    let slug = unique_slug("iss-empty-org");
    let (_user, org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;
    let cookie = login(&router, &email).await;

    let form = "title=&component=Portal&severity=Minor&details=ignored";
    let report = post_form(&router, &format!("/{slug}/issues"), cookie.as_deref(), form).await;
    assert!(status(&report).is_redirection());
    let location = report
        .headers()
        .get(topcoat::router::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert_eq!(location, format!("/{slug}/issues"));
    assert!(!location.contains("VBN-"));

    {
        let mut conn = db.clone();
        let rows = Issue::all()
            .filter(Issue::fields().organization_id().eq(org.id))
            .exec(&mut conn)
            .await
            .expect("list");
        assert!(rows.is_empty(), "empty title must not insert");
    }

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

    assert!(
        html.contains(&format!("/admin/issues/{key}?org={client_slug}")),
        "aggregate list must link with ?org=; {html}"
    );

    let detail = get(
        &router,
        &format!("/admin/issues/{key}?org={client_slug}"),
        cookie.as_deref(),
    )
    .await;
    assert_eq!(status(&detail), StatusCode::OK);
    let html = body_text(detail).await;
    assert!(html.contains("Cross-org queue body"), "detail missing body");

    let reserved = get(
        &router,
        &format!("/{RESERVED_ORG_SLUG}/issues"),
        cookie.as_deref(),
    )
    .await;
    assert_eq!(
        status(&reserved),
        StatusCode::TEMPORARY_REDIRECT,
        "GET /vauban/issues must use redirect (307), got {}",
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

#[tokio::test]
async fn e2e_member_close_blocks_reply_and_reopen_restores() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("iss-close");
    let slug = unique_slug("iss-close-org");
    let (user, org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;
    let cookie = login(&router, &email).await;

    let now = vcp::db::now_unix();
    let key = format!("VBN-{}", unique_slug("cl").replace('-', ""));
    let issue_id = {
        let mut conn = db.clone();
        let issue = toasty::create!(Issue {
            key: key.clone(),
            title: "Close e2e".to_owned(),
            component: "Portal".to_owned(),
            severity: "Major".to_owned(),
            status: ISSUE_STATUS_OPEN.to_owned(),
            organization_id: org.id,
            details: "Please close me".to_owned(),
            opened_by_user_id: user.id,
            created_at: now,
            updated_at: now,
        })
        .exec(&mut conn)
        .await
        .expect("issue");
        issue.id
    };

    let closed = post_form(
        &router,
        &format!("/{slug}/issues/{key}/close"),
        cookie.as_deref(),
        "",
    )
    .await;
    assert!(
        status(&closed).is_redirection(),
        "close should PRG, got {}",
        status(&closed)
    );

    {
        let mut conn = db.clone();
        let rows = Issue::all()
            .filter(Issue::fields().id().eq(issue_id))
            .exec(&mut conn)
            .await
            .expect("issue");
        assert_eq!(rows[0].status, ISSUE_STATUS_CLOSED);
        let comments = IssueComment::all()
            .filter(IssueComment::fields().issue_id().eq(issue_id))
            .exec(&mut conn)
            .await
            .expect("comments");
        assert!(
            comments.iter().any(|c| {
                c.kind == ISSUE_COMMENT_KIND_STATUS && c.body.eq_ignore_ascii_case("Closed")
            }),
            "timeline must include Closed status_change"
        );
    }

    let detail = get(&router, &format!("/{slug}/issues/{key}"), cookie.as_deref()).await;
    assert_eq!(status(&detail), StatusCode::OK);
    let html = body_text(detail).await;
    assert!(
        html.contains("This issue is closed"),
        "closed panel missing: {html}"
    );
    assert!(
        html.contains("Reopen issue"),
        "reopen control missing: {html}"
    );
    assert!(!html.contains("Add a reply"), "reply form must be hidden");

    let blocked = post_form(
        &router,
        &format!("/{slug}/issues/{key}/reply"),
        cookie.as_deref(),
        &format!("body={}", urlencoding_encode("should not persist")),
    )
    .await;
    assert!(status(&blocked).is_redirection());
    {
        let mut conn = db.clone();
        let comments = IssueComment::all()
            .filter(IssueComment::fields().issue_id().eq(issue_id))
            .exec(&mut conn)
            .await
            .expect("comments");
        assert!(
            !comments
                .iter()
                .any(|c| c.kind == ISSUE_COMMENT_KIND_COMMENT && c.body.contains("should not")),
            "reply must not insert while closed"
        );
    }

    let reopened = post_form(
        &router,
        &format!("/{slug}/issues/{key}/reopen"),
        cookie.as_deref(),
        "",
    )
    .await;
    assert!(status(&reopened).is_redirection());
    {
        let mut conn = db.clone();
        let rows = Issue::all()
            .filter(Issue::fields().id().eq(issue_id))
            .exec(&mut conn)
            .await
            .expect("issue");
        assert_eq!(rows[0].status, ISSUE_STATUS_OPEN);
    }

    let reply = "Back in business.";
    let posted = post_form(
        &router,
        &format!("/{slug}/issues/{key}/reply"),
        cookie.as_deref(),
        &format!("body={}", urlencoding_encode(reply)),
    )
    .await;
    assert!(status(&posted).is_redirection());
    let after = get(&router, &format!("/{slug}/issues/{key}"), cookie.as_deref()).await;
    assert_eq!(status(&after), StatusCode::OK);
    let html = body_text(after).await;
    assert!(html.contains(reply), "reply after reopen missing: {html}");

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_admin_close_reopen_and_member_denied_admin_close() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;
    let _vauban = ensure_reserved_org(&db).await;

    let staff_email = unique_email("iss-adm-cl");
    let client_slug = unique_slug("iss-adm-cl-org");
    let (user, org) =
        create_org_with_membership(&db, &staff_email, "password", &client_slug, "admin").await;
    let staff_cookie = login(&router, &staff_email).await;

    let now = vcp::db::now_unix();
    let key = format!("VBN-{}", unique_slug("acl").replace('-', ""));
    let issue_id = {
        let mut conn = db.clone();
        let issue = toasty::create!(Issue {
            key: key.clone(),
            title: "Admin close e2e".to_owned(),
            component: "Portal".to_owned(),
            severity: "Minor".to_owned(),
            status: ISSUE_STATUS_OPEN.to_owned(),
            organization_id: org.id,
            details: "staff closes".to_owned(),
            opened_by_user_id: user.id,
            created_at: now,
            updated_at: now,
        })
        .exec(&mut conn)
        .await
        .expect("issue");
        issue.id
    };

    let closed = post_form(
        &router,
        &format!("/admin/issues/{key}/close?org={client_slug}"),
        staff_cookie.as_deref(),
        "",
    )
    .await;
    assert!(status(&closed).is_redirection());
    {
        let mut conn = db.clone();
        let rows = Issue::all()
            .filter(Issue::fields().id().eq(issue_id))
            .exec(&mut conn)
            .await
            .expect("issue");
        assert_eq!(rows[0].status, ISSUE_STATUS_CLOSED);
    }

    let reopened = post_form(
        &router,
        &format!("/admin/issues/{key}/reopen?org={client_slug}"),
        staff_cookie.as_deref(),
        "",
    )
    .await;
    assert!(status(&reopened).is_redirection());
    {
        let mut conn = db.clone();
        let rows = Issue::all()
            .filter(Issue::fields().id().eq(issue_id))
            .exec(&mut conn)
            .await
            .expect("issue");
        assert_eq!(rows[0].status, ISSUE_STATUS_OPEN);
    }

    let member_email = unique_email("iss-mem-cl");
    let member_slug = unique_slug("iss-mem-cl-org");
    let (_mu, _mo) =
        create_org_with_membership(&db, &member_email, "password", &member_slug, "member").await;
    let member_cookie = login(&router, &member_email).await;
    let denied = post_form(
        &router,
        &format!("/admin/issues/{key}/close"),
        member_cookie.as_deref(),
        "",
    )
    .await;
    assert_eq!(status(&denied), StatusCode::NOT_FOUND);

    // Wrong-org close must not mutate another tenant's issue.
    let other_email = unique_email("iss-wo-cl");
    let other_slug = unique_slug("iss-wo-cl-org");
    let (_ou, _oo) =
        create_org_with_membership(&db, &other_email, "password", &other_slug, "member").await;
    let other_cookie = login(&router, &other_email).await;
    let wrong = post_form(
        &router,
        &format!("/{other_slug}/issues/{key}/close"),
        other_cookie.as_deref(),
        "",
    )
    .await;
    assert!(
        status(&wrong) == StatusCode::NOT_FOUND
            || status(&wrong) == StatusCode::FORBIDDEN
            || status(&wrong).is_redirection(),
        "wrong-org close must fail closed, got {}",
        status(&wrong)
    );
    {
        let mut conn = db.clone();
        let rows = Issue::all()
            .filter(Issue::fields().id().eq(issue_id))
            .exec(&mut conn)
            .await
            .expect("issue");
        assert_eq!(
            rows[0].status, ISSUE_STATUS_OPEN,
            "wrong-org close must not change status"
        );
    }

    cleanup(&db).await;
}
