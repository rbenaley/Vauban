//! E2E: issue report persists details; wrong org 404; reply from DB.

use http_body_util::BodyExt;
use topcoat::router::StatusCode;
use vcp::issue_anchor::ISSUE_REPLY_ANCHOR;
use vcp::models::{
    ISSUE_COMMENT_KIND_COMMENT, ISSUE_COMMENT_KIND_STATUS, ISSUE_ROLE_SUPPORT, ISSUE_STATUS_CLOSED,
    ISSUE_STATUS_IN_ANALYSIS, ISSUE_STATUS_OPEN, ISSUE_STATUS_RESOLVED, Issue, IssueComment,
    MAX_ISSUE_ATTACHMENTS, RESERVED_ORG_SLUG,
};

use crate::common::{
    MultipartFile, TINY_PNG, cleanup, create_org_with_membership, create_test_org,
    data_topcoat_on_event_values, db_lock, ensure_reserved_org, get, is_topcoat_function_handler,
    login_cookie, post_form, post_multipart_with_files, status, test_db, test_router, unique_email,
    unique_slug,
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
    let report = post_multipart_with_files(
        &router,
        &format!("/{slug}/issues"),
        cookie.as_deref(),
        &[
            ("title", "Test portal latency"),
            ("component", "Portal"),
            ("severity", "Major"),
            ("details", details),
        ],
        &[],
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
async fn e2e_report_form_lists_vauban_components() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("iss-comp-form");
    let slug = unique_slug("iss-comp-form-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;
    let cookie = login(&router, &email).await;

    let page = get(&router, &format!("/{slug}/issues/new"), cookie.as_deref()).await;
    assert_eq!(status(&page), StatusCode::OK);
    let html = body_text(page).await;
    for label in [
        "SSH",
        "RDP",
        "IACS",
        "Web UI",
        "Authentication",
        "Access control",
        "Vault",
        "Recording &amp; audit",
        "Recording & audit",
        "Notifications",
        "Infrastructure",
        "Portal",
        "Other",
    ] {
        // HTML may escape `&` in "Recording & audit".
        if label == "Recording & audit" || label == "Recording &amp; audit" {
            assert!(
                html.contains("Recording & audit") || html.contains("Recording &amp; audit"),
                "form missing Recording & audit: {html}"
            );
            continue;
        }
        assert!(
            html.contains(label),
            "report form missing component {label}: {html}"
        );
    }
    assert!(!html.contains("SSH Proxy"));
    assert!(!html.contains("RDP Gateway"));
    assert!(!html.contains("Control plane"));

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_report_issue_unknown_component_skips_create() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("iss-bad-comp");
    let slug = unique_slug("iss-bad-comp-org");
    let (_user, org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;
    let cookie = login(&router, &email).await;

    let report = post_multipart_with_files(
        &router,
        &format!("/{slug}/issues"),
        cookie.as_deref(),
        &[
            ("title", "Should not persist"),
            ("component", "NotAVaubanSurface"),
            ("severity", "Major"),
            ("details", "forged component"),
        ],
        &[],
    )
    .await;
    assert!(status(&report).is_redirection());
    let location = report
        .headers()
        .get(topcoat::router::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert_eq!(location, format!("/{slug}/issues/new"));

    {
        let mut conn = db.clone();
        let rows = Issue::all()
            .filter(Issue::fields().organization_id().eq(org.id))
            .exec(&mut conn)
            .await
            .expect("list");
        assert!(rows.is_empty(), "unknown component must not insert");
    }

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

    let report = post_multipart_with_files(
        &router,
        &format!("/{slug}/issues"),
        cookie.as_deref(),
        &[
            ("title", ""),
            ("component", "Portal"),
            ("severity", "Minor"),
            ("details", "ignored"),
        ],
        &[],
    )
    .await;
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
            component: "SSH".to_owned(),
            severity: "Major".to_owned(),
            status: "In analysis".to_owned(),
            organization_id: org.id,
            details: "Reporter opener text".to_owned(),
            opened_by_user_id: user.id,
            created_at: now - 10_000,
            updated_at: now - 1_000,
            version: 1,
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
            edited_at: 0,
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
    let posted = post_multipart_with_files(
        &router,
        &format!("/{slug}/issues/{key}/reply"),
        cookie.as_deref(),
        &[("body", reply)],
        &[],
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

/// After a reply / close / reopen the browser must land on the reply box, not
/// on the page header. The portal scrolls inside `.vb-scroll`, so the only
/// no-JS lever is the fragment on the `303` — and the anchor has to exist in
/// the closed rendering too, where the reply form is replaced by a panel.
#[tokio::test]
async fn e2e_issue_post_actions_redirect_to_the_reply_anchor() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("iss-anchor");
    let slug = unique_slug("iss-anchor-org");
    let (user, org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;
    let cookie = login(&router, &email).await;

    let now = vcp::db::now_unix();
    let key = format!("VBN-{}", unique_slug("an").replace('-', ""));
    {
        let mut conn = db.clone();
        toasty::create!(Issue {
            key: key.clone(),
            title: "Anchor e2e".to_owned(),
            component: "Portal".to_owned(),
            severity: "Minor".to_owned(),
            status: ISSUE_STATUS_OPEN.to_owned(),
            organization_id: org.id,
            details: "Scroll me to the bottom".to_owned(),
            opened_by_user_id: user.id,
            created_at: now,
            updated_at: now,
            version: 1,
        })
        .exec(&mut conn)
        .await
        .expect("issue");
    }

    let expected = format!("/{slug}/issues/{key}#{ISSUE_REPLY_ANCHOR}");

    let posted = post_multipart_with_files(
        &router,
        &format!("/{slug}/issues/{key}/reply"),
        cookie.as_deref(),
        &[("body", "Landing at the bottom, please.")],
        &[],
    )
    .await;
    assert!(status(&posted).is_redirection());
    let reply_loc = posted
        .headers()
        .get(topcoat::router::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    assert_eq!(reply_loc, expected, "reply must anchor on the reply box");

    // The fragment only works if the target id is actually rendered.
    let open_html = body_text(get(&router, &reply_loc, cookie.as_deref()).await).await;
    assert!(
        open_html.contains(&format!("id=\"{ISSUE_REPLY_ANCHOR}\"")),
        "open pane must render the reply anchor: {open_html}"
    );

    // Close is only legal from Resolved (FSM); seed that before the close POST.
    {
        let mut conn = db.clone();
        let rows = Issue::all()
            .filter(Issue::fields().organization_id().eq(org.id))
            .exec(&mut conn)
            .await
            .expect("list");
        let mut issue = rows
            .into_iter()
            .find(|i| i.key == key)
            .expect("seeded issue");
        issue
            .update()
            .status(ISSUE_STATUS_RESOLVED.to_owned())
            .exec(&mut conn)
            .await
            .expect("seed Resolved");
    }

    let closed = post_form(
        &router,
        &format!("/{slug}/issues/{key}/close"),
        cookie.as_deref(),
        "",
    )
    .await;
    let close_loc = closed
        .headers()
        .get(topcoat::router::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    assert_eq!(close_loc, expected, "close must anchor on the reply box");

    let closed_html = body_text(get(&router, &close_loc, cookie.as_deref()).await).await;
    assert!(
        closed_html.contains("This issue is closed"),
        "expected the closed panel: {closed_html}"
    );
    assert!(
        closed_html.contains(&format!("id=\"{ISSUE_REPLY_ANCHOR}\"")),
        "closed panel must keep the anchor alive: {closed_html}"
    );

    let reopened = post_form(
        &router,
        &format!("/{slug}/issues/{key}/reopen"),
        cookie.as_deref(),
        "",
    )
    .await;
    let reopen_loc = reopened
        .headers()
        .get(topcoat::router::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    assert_eq!(reopen_loc, expected, "reopen must anchor on the reply box");

    // An empty body is a no-op redirect: it must still land at the bottom.
    let empty = post_multipart_with_files(
        &router,
        &format!("/{slug}/issues/{key}/reply"),
        cookie.as_deref(),
        &[("body", "   ")],
        &[],
    )
    .await;
    let empty_loc = empty
        .headers()
        .get(topcoat::router::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    assert_eq!(empty_loc, expected, "empty reply must still anchor");

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
            version: 1,
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
            status: ISSUE_STATUS_RESOLVED.to_owned(),
            organization_id: org.id,
            details: "Please close me".to_owned(),
            opened_by_user_id: user.id,
            created_at: now,
            updated_at: now,
            version: 1,
        })
        .exec(&mut conn)
        .await
        .expect("issue");
        issue.id
    };

    let detail_resolved = get(&router, &format!("/{slug}/issues/{key}"), cookie.as_deref()).await;
    assert_eq!(status(&detail_resolved), StatusCode::OK);
    let html_resolved = body_text(detail_resolved).await;
    assert!(
        html_resolved.contains("This issue is resolved"),
        "resolved panel missing: {html_resolved}"
    );
    assert!(
        html_resolved.contains("Close issue"),
        "close control missing on Resolved: {html_resolved}"
    );

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

    let blocked = post_multipart_with_files(
        &router,
        &format!("/{slug}/issues/{key}/reply"),
        cookie.as_deref(),
        &[("body", "should not persist")],
        &[],
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
    let posted = post_multipart_with_files(
        &router,
        &format!("/{slug}/issues/{key}/reply"),
        cookie.as_deref(),
        &[("body", reply)],
        &[],
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
async fn e2e_close_from_open_is_noop_and_reopen_resolved_to_analysis() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("iss-fsm");
    let slug = unique_slug("iss-fsm-org");
    let (user, org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;
    let cookie = login(&router, &email).await;

    let now = vcp::db::now_unix();
    let open_key = format!("VBN-{}", unique_slug("op").replace('-', ""));
    let open_id = {
        let mut conn = db.clone();
        toasty::create!(Issue {
            key: open_key.clone(),
            title: "Open close noop".to_owned(),
            component: "Portal".to_owned(),
            severity: "Minor".to_owned(),
            status: ISSUE_STATUS_OPEN.to_owned(),
            organization_id: org.id,
            details: "open".to_owned(),
            opened_by_user_id: user.id,
            created_at: now,
            updated_at: now,
            version: 1,
        })
        .exec(&mut conn)
        .await
        .expect("issue")
        .id
    };

    let close_open = post_form(
        &router,
        &format!("/{slug}/issues/{open_key}/close"),
        cookie.as_deref(),
        "",
    )
    .await;
    assert!(status(&close_open).is_redirection());
    {
        let mut conn = db.clone();
        let rows = Issue::all()
            .filter(Issue::fields().id().eq(open_id))
            .exec(&mut conn)
            .await
            .expect("issue");
        assert_eq!(rows[0].status, ISSUE_STATUS_OPEN);
    }

    let resolved_key = format!("VBN-{}", unique_slug("rs").replace('-', ""));
    let resolved_id = {
        let mut conn = db.clone();
        toasty::create!(Issue {
            key: resolved_key.clone(),
            title: "Reopen to analysis".to_owned(),
            component: "Portal".to_owned(),
            severity: "Minor".to_owned(),
            status: ISSUE_STATUS_RESOLVED.to_owned(),
            organization_id: org.id,
            details: "resolved".to_owned(),
            opened_by_user_id: user.id,
            created_at: now,
            updated_at: now,
            version: 1,
        })
        .exec(&mut conn)
        .await
        .expect("issue")
        .id
    };

    let reopened = post_form(
        &router,
        &format!("/{slug}/issues/{resolved_key}/reopen"),
        cookie.as_deref(),
        "",
    )
    .await;
    assert!(status(&reopened).is_redirection());
    {
        let mut conn = db.clone();
        let rows = Issue::all()
            .filter(Issue::fields().id().eq(resolved_id))
            .exec(&mut conn)
            .await
            .expect("issue");
        assert_eq!(rows[0].status, ISSUE_STATUS_IN_ANALYSIS);
    }

    let forbidden = post_form(
        &router,
        &format!("/{slug}/issues/{open_key}/start-analysis"),
        cookie.as_deref(),
        "",
    )
    .await;
    assert!(
        status(&forbidden) == StatusCode::NOT_FOUND || status(&forbidden).is_client_error(),
        "org must not have start-analysis route, got {}",
        status(&forbidden)
    );

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
            version: 1,
        })
        .exec(&mut conn)
        .await
        .expect("issue");
        issue.id
    };

    let started = post_form(
        &router,
        &format!("/admin/issues/{key}/start-analysis?org={client_slug}"),
        staff_cookie.as_deref(),
        "",
    )
    .await;
    assert!(status(&started).is_redirection());
    {
        let mut conn = db.clone();
        let rows = Issue::all()
            .filter(Issue::fields().id().eq(issue_id))
            .exec(&mut conn)
            .await
            .expect("issue");
        assert_eq!(rows[0].status, ISSUE_STATUS_IN_ANALYSIS);
    }

    let resolved = post_form(
        &router,
        &format!("/admin/issues/{key}/resolve?org={client_slug}"),
        staff_cookie.as_deref(),
        "",
    )
    .await;
    assert!(status(&resolved).is_redirection());
    {
        let mut conn = db.clone();
        let rows = Issue::all()
            .filter(Issue::fields().id().eq(issue_id))
            .exec(&mut conn)
            .await
            .expect("issue");
        assert_eq!(rows[0].status, ISSUE_STATUS_RESOLVED);
    }

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

#[tokio::test]
async fn e2e_issue_create_with_image_attachment_gallery() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("iss-img");
    let slug = unique_slug("iss-img-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;
    let cookie = login(&router, &email).await;

    let report = post_multipart_with_files(
        &router,
        &format!("/{slug}/issues"),
        cookie.as_deref(),
        &[
            ("title", "Screenshot issue"),
            ("component", "Portal"),
            ("severity", "Major"),
            ("details", "See attached"),
        ],
        &[MultipartFile {
            field: "screenshots",
            filename: "shot.png",
            content_type: "image/png",
            bytes: TINY_PNG,
        }],
    )
    .await;
    assert!(status(&report).is_redirection());
    let location = report
        .headers()
        .get(topcoat::router::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_owned())
        .expect("Location");
    assert!(
        location.starts_with(&format!("/{slug}/issues/VBN-")),
        "{location}"
    );
    assert!(!location.contains("err="), "{location}");

    let detail = get(&router, &location, cookie.as_deref()).await;
    assert_eq!(status(&detail), StatusCode::OK);
    let html = body_text(detail).await;
    let needle = format!("/{slug}/images/");
    assert!(
        html.contains(&needle) && html.contains(".png"),
        "detail gallery must include /{slug}/images/…png; html={html}"
    );

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_issue_reply_attaches_screenshot_to_gallery() {
    use vcp::issue_attachments::list_for_issue;

    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("iss-reply-img");
    let slug = unique_slug("iss-reply-img");
    let (_user, org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;
    let cookie = login(&router, &email).await;

    let created = post_multipart_with_files(
        &router,
        &format!("/{slug}/issues"),
        cookie.as_deref(),
        &[
            ("title", "Reply attach"),
            ("component", "Portal"),
            ("severity", "Minor"),
            ("details", "no image yet"),
        ],
        &[],
    )
    .await;
    assert!(status(&created).is_redirection());
    let location = created
        .headers()
        .get(topcoat::router::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_owned())
        .expect("Location");
    let key = location.rsplit('/').next().expect("issue key").to_owned();

    let before = get(&router, &location, cookie.as_deref()).await;
    let before_html = body_text(before).await;
    assert!(
        !before_html.contains(&format!("/{slug}/images/")),
        "fresh issue must not show a gallery yet"
    );

    let reply = post_multipart_with_files(
        &router,
        &format!("/{slug}/issues/{key}/reply"),
        cookie.as_deref(),
        &[("body", "Here is a screenshot")],
        &[MultipartFile {
            field: "screenshots",
            filename: "reply-shot.png",
            content_type: "image/png",
            bytes: TINY_PNG,
        }],
    )
    .await;
    assert!(
        status(&reply).is_redirection(),
        "reply+screenshot must PRG, got {}",
        status(&reply)
    );
    let reply_loc = reply
        .headers()
        .get(topcoat::router::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        !reply_loc.contains("err=attach"),
        "reply attach must not fail: {reply_loc}"
    );

    let detail = get(&router, &location, cookie.as_deref()).await;
    assert_eq!(status(&detail), StatusCode::OK);
    let html = body_text(detail).await;
    assert!(
        html.contains("Here is a screenshot"),
        "reply body missing: {html}"
    );
    assert!(
        html.contains(&format!("/{slug}/images/")) && html.contains(".png"),
        "gallery must show attached image after reply: {html}"
    );
    let reply_at = html
        .find("Here is a screenshot")
        .expect("reply body in html");
    // Image must sit in the same comment bubble as the reply body (not a
    // separate end-of-thread gallery / opener-only strip).
    let after_reply = &html[reply_at..];
    let next_bubble_end = after_reply.find("vb-bubble").unwrap_or(after_reply.len());
    let in_same_region = after_reply[..next_bubble_end].contains(&format!("/{slug}/images/"))
        || after_reply[..800.min(after_reply.len())].contains(&format!("/{slug}/images/"));
    assert!(
        in_same_region || html.contains("vb-issue-thumb"),
        "reply screenshot must render as a thumb near the reply body: {html}"
    );
    assert!(
        html.contains("vb-issue-lightbox") && html.contains("data-topcoat"),
        "detail must ship Topcoat lightbox wiring"
    );
    // Lightbox is a native <dialog>: closable without JS (method="dialog"),
    // and the close button is anchored to the image, not to the backdrop.
    assert!(
        html.contains("<dialog") && html.contains("method=\"dialog\""),
        "lightbox must render as a dialog with a JS-free dismiss: {html}"
    );
    // Anchor on the element, not on the `img.closest('.vb-issue-lightbox-figure')`
    // lookup that thumb handlers also carry.
    let figure_at = html
        .find("class=\"vb-issue-lightbox-figure\"")
        .expect("lightbox figure in rendered html");
    let figure_end = html[figure_at..]
        .find("</form>")
        .expect("figure form closes");
    let figure = &html[figure_at..figure_at + figure_end];
    assert!(
        figure.contains("issue-lb-img") && figure.contains("vb-issue-lightbox-close"),
        "close button must render inside the image figure: {figure}"
    );

    {
        let mut conn = db.clone();
        let rows = Issue::all()
            .filter(Issue::fields().organization_id().eq(org.id))
            .filter(Issue::fields().key().eq(key.clone()))
            .limit(1)
            .exec(&mut conn)
            .await
            .expect("issue");
        let atts = list_for_issue(
            &mut conn,
            org.id,
            rows[0].id,
            vcp::issue_attachments::issue_attachment_list_limit(MAX_ISSUE_ATTACHMENTS),
        )
        .await
        .expect("atts");
        assert_eq!(atts.len(), 1, "exactly one liaison after reply attach");
        assert_eq!(atts[0].ext, "png");
    }

    cleanup(&db).await;
}

/// Several screenshots on one reply: the picker accumulates picks client-side,
/// so the reply seam must carry (and render) more than one file per comment.
#[tokio::test]
async fn e2e_issue_reply_attaches_several_screenshots() {
    use vcp::issue_attachments::list_for_issue;

    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("iss-multi-img");
    let slug = unique_slug("iss-multi-img");
    let (_user, org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;
    let cookie = login(&router, &email).await;

    let created = post_multipart_with_files(
        &router,
        &format!("/{slug}/issues"),
        cookie.as_deref(),
        &[
            ("title", "Multi attach"),
            ("component", "Portal"),
            ("severity", "Minor"),
            ("details", "several shots incoming"),
        ],
        &[],
    )
    .await;
    let location = created
        .headers()
        .get(topcoat::router::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_owned())
        .expect("Location");
    let key = location.rsplit('/').next().expect("issue key").to_owned();

    let shots: Vec<MultipartFile<'_>> = ["one.png", "two.png", "three.png"]
        .into_iter()
        .map(|filename| MultipartFile {
            field: "screenshots",
            filename,
            content_type: "image/png",
            bytes: TINY_PNG,
        })
        .collect();
    let reply = post_multipart_with_files(
        &router,
        &format!("/{slug}/issues/{key}/reply"),
        cookie.as_deref(),
        &[("body", "Three screenshots")],
        &shots,
    )
    .await;
    let reply_loc = reply
        .headers()
        .get(topcoat::router::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        status(&reply).is_redirection() && !reply_loc.contains("err=attach"),
        "reply with 3 screenshots must succeed: {reply_loc}"
    );

    let detail = get(&router, &location, cookie.as_deref()).await;
    assert_eq!(status(&detail), StatusCode::OK);
    let html = body_text(detail).await;
    assert_eq!(
        html.matches("vb-issue-thumb\"").count(),
        3,
        "every attached screenshot must render its own thumb: {html}"
    );
    assert!(
        html.contains("issue-lb-prev")
            && html.contains("issue-lb-next")
            && html.contains("data-step=\"-1\"")
            && html.contains("data-step=\"1\""),
        "multi-thumb detail must ship looping prev/next lightbox controls: {html}"
    );
    let clicks = data_topcoat_on_event_values(&html, "click");
    assert!(
        clicks
            .iter()
            .any(|js| js.contains("vcpGallery") && js.contains("closest('.vb-issue-thumbs')")),
        "thumb open handler must scope the gallery to one comment strip: {clicks:?}"
    );
    assert!(
        clicks
            .iter()
            .any(|js| js.contains("data-step") && js.contains("((i % n) + n) % n")),
        "nav handler must wrap the gallery index: {clicks:?}"
    );
    let keys = data_topcoat_on_event_values(&html, "keydown");
    assert!(
        keys.iter()
            .any(|js| js.contains("ArrowLeft") && js.contains("ArrowRight")),
        "lightbox must bind arrow keys for gallery navigation: {keys:?}"
    );

    // Picker affordances: cap wiring, add trigger state, live count.
    assert!(
        html.contains(&format!("data-max=\"{MAX_ISSUE_ATTACHMENTS}\"")),
        "picker must publish the configured cap"
    );
    assert!(
        html.contains("data-shot-add") && html.contains("data-shot-status"),
        "picker must ship the cap-state and live-count hooks: {html}"
    );
    assert!(
        html.contains("data-shot-dropzone"),
        "picker must expose the drag-and-drop dropzone: {html}"
    );
    assert!(
        html.contains("screenshots per message") && html.contains("drag"),
        "picker must state the cap and invite drag & drop"
    );
    for handler in data_topcoat_on_event_values(&html, "change")
        .into_iter()
        .chain(data_topcoat_on_event_values(&html, "load"))
        .chain(data_topcoat_on_event_values(&html, "drop"))
        .chain(data_topcoat_on_event_values(&html, "dragover"))
        .chain(data_topcoat_on_event_values(&html, "dragleave"))
    {
        assert!(
            is_topcoat_function_handler(&handler),
            "Topcoat binds handlers with `return <js>`: {handler}"
        );
    }
    assert!(
        data_topcoat_on_event_values(&html, "drop")
            .iter()
            .any(|js| js.contains("dataTransfer") && js.contains("dispatchEvent")),
        "drop must feed files into the change accumulator"
    );
    let fit = data_topcoat_on_event_values(&html, "load");
    assert!(
        fit.iter()
            .any(|js| js.contains("getBoundingClientRect") && js.contains("style.width")),
        "lightbox must pin the figure to the measured image box: {fit:?}"
    );
    assert!(
        data_topcoat_on_event_values(&html, "change")
            .iter()
            .any(|js| js.contains("vcpShots") && js.contains("DataTransfer")),
        "picker must accumulate picks instead of replacing the FileList"
    );

    {
        let mut conn = db.clone();
        let rows = Issue::all()
            .filter(Issue::fields().organization_id().eq(org.id))
            .filter(Issue::fields().key().eq(key.clone()))
            .limit(1)
            .exec(&mut conn)
            .await
            .expect("issue");
        let atts = list_for_issue(
            &mut conn,
            org.id,
            rows[0].id,
            vcp::issue_attachments::issue_attachment_list_limit(MAX_ISSUE_ATTACHMENTS),
        )
        .await
        .expect("atts");
        assert_eq!(atts.len(), 3, "one liaison per screenshot");
        let mut ids: Vec<&str> = atts.iter().map(|a| a.image_id.as_str()).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), 3, "liaisons must point at distinct blobs");
    }

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_issue_attachment_over_cap_rejected() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("iss-att-cap");
    let slug = unique_slug("iss-att-cap");
    let (_u, org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;
    let cookie = login(&router, &email).await;

    let files: Vec<MultipartFile<'_>> = (0..(MAX_ISSUE_ATTACHMENTS + 1))
        .map(|_| MultipartFile {
            field: "screenshots",
            filename: "shot.png",
            content_type: "image/png",
            bytes: TINY_PNG,
        })
        .collect();
    let over = post_multipart_with_files(
        &router,
        &format!("/{slug}/issues"),
        cookie.as_deref(),
        &[
            ("title", "Over cap"),
            ("component", "Portal"),
            ("severity", "Minor"),
            ("details", "cap"),
        ],
        &files,
    )
    .await;
    assert!(status(&over).is_redirection());
    let loc = over
        .headers()
        .get(topcoat::router::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        loc.contains("err=attach"),
        "over-cap must fail closed: {loc}"
    );
    {
        let mut conn = db.clone();
        let rows = Issue::all()
            .filter(Issue::fields().organization_id().eq(org.id))
            .exec(&mut conn)
            .await
            .expect("list");
        assert!(rows.is_empty(), "over-cap must not create an issue");
    }

    cleanup(&db).await;
}
