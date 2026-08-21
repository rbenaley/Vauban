//! E2E: Support can edit Support comments; company and reporter rows cannot.

use http_body_util::BodyExt;
use topcoat::router::StatusCode;
use vcp::models::{
    COMMENT_NOT_EDITED, ISSUE_COMMENT_KIND_COMMENT, ISSUE_ROLE_REPORTER, IssueComment,
};

use crate::common::{
    cleanup, create_org_with_membership, db_lock, get, login_cookie, post_form,
    post_multipart_with_files, status, test_db, test_router, unique_email, unique_slug,
    urlencoding_encode,
};

async fn body_text(resp: topcoat::router::Response) -> String {
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

#[tokio::test]
async fn e2e_staff_edits_support_comment_company_cannot() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let admin = unique_email("ced-adm");
    let member = unique_email("ced-mem");
    let slug = unique_slug("ced-org");
    let _ =
        create_org_with_membership(&db, &admin, "password", &unique_slug("ced-adm"), "admin").await;
    let (_user, _org) = create_org_with_membership(&db, &member, "password", &slug, "member").await;
    let member_cookie = login_cookie(&router, &member).await.expect("member");
    let report = post_multipart_with_files(
        &router,
        &format!("/{slug}/issues"),
        Some(&member_cookie),
        &[
            ("title", "Edit comment ticket"),
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

    let admin_cookie = login_cookie(&router, &admin).await.expect("admin");
    let reply = post_multipart_with_files(
        &router,
        &format!("/admin/issues/{key}/reply?org={slug}"),
        Some(&admin_cookie),
        &[("body", "Original support note")],
        &[],
    )
    .await;
    assert!(status(&reply).is_redirection());

    let mut conn = db.clone();
    let comments = IssueComment::all()
        .filter(
            IssueComment::fields()
                .kind()
                .eq(ISSUE_COMMENT_KIND_COMMENT.to_owned()),
        )
        .exec(&mut conn)
        .await
        .expect("comments");
    let support = comments
        .iter()
        .find(|c| c.body.contains("Original support note"))
        .expect("support comment");
    assert_eq!(support.edited_at, COMMENT_NOT_EDITED);

    let admin_page = get(
        &router,
        &format!("/admin/issues/{key}?org={slug}"),
        Some(&admin_cookie),
    )
    .await;
    assert_eq!(status(&admin_page), StatusCode::OK);
    let admin_html = body_text(admin_page).await;
    assert!(
        admin_html.contains(&format!("edit={}", support.id)),
        "admin must see Edit: {admin_html}"
    );

    let org_page = get(
        &router,
        &format!("/{slug}/issues/{key}"),
        Some(&member_cookie),
    )
    .await;
    let org_html = body_text(org_page).await;
    assert!(
        !org_html.contains(&format!("edit={}", support.id)),
        "company page must not offer Edit"
    );
    assert!(!org_html.contains("edit-comment"));

    let edit_page = get(
        &router,
        &format!("/admin/issues/{key}?org={slug}&edit={}", support.id),
        Some(&admin_cookie),
    )
    .await;
    assert_eq!(status(&edit_page), StatusCode::OK);
    let edit_html = body_text(edit_page).await;
    assert!(
        edit_html.contains("Original support note") && edit_html.contains("Save"),
        "edit form missing: {edit_html}"
    );

    let saved = post_form(
        &router,
        &format!("/admin/issues/{key}/edit-comment?org={slug}"),
        Some(&admin_cookie),
        &format!(
            "comment_id={}&body={}",
            support.id,
            urlencoding_encode("Corrected support note")
        ),
    )
    .await;
    assert!(status(&saved).is_redirection());

    let after = get(
        &router,
        &format!("/admin/issues/{key}?org={slug}"),
        Some(&admin_cookie),
    )
    .await;
    let after_html = body_text(after).await;
    assert!(after_html.contains("Corrected support note"));
    assert!(!after_html.contains("Original support note"));
    assert!(after_html.contains("Edited"));

    let denied = post_form(
        &router,
        &format!("/admin/issues/{key}/edit-comment?org={slug}"),
        Some(&member_cookie),
        &format!(
            "comment_id={}&body={}",
            support.id,
            urlencoding_encode("hijack")
        ),
    )
    .await;
    assert_eq!(status(&denied), StatusCode::NOT_FOUND);

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_staff_cannot_edit_reporter_comment() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let admin = unique_email("ced-rep-adm");
    let member = unique_email("ced-rep-mem");
    let slug = unique_slug("ced-rep");
    let _ = create_org_with_membership(
        &db,
        &admin,
        "password",
        &unique_slug("ced-rep-adm"),
        "admin",
    )
    .await;
    let (user, org) = create_org_with_membership(&db, &member, "password", &slug, "member").await;
    let now = vcp::db::now_unix();
    let mut conn = db.clone();
    let issue = vcp::models::Issue::all()
        .filter(vcp::models::Issue::fields().organization_id().eq(org.id))
        .limit(1)
        .exec(&mut conn)
        .await
        .ok()
        .and_then(|v| v.into_iter().next());
    let issue = if let Some(i) = issue {
        i
    } else {
        crate::common::create_test_issue(
            &db,
            org.id,
            user.id,
            "TEST-ced-rep",
            "Reporter edit",
            "Open",
        )
        .await
    };
    let reporter = toasty::create!(IssueComment {
        issue_id: issue.id,
        author_user_id: user.id,
        author_role: ISSUE_ROLE_REPORTER.to_owned(),
        body: "Company said this".to_owned(),
        kind: ISSUE_COMMENT_KIND_COMMENT.to_owned(),
        created_at: now,
        edited_at: 0,
    })
    .exec(&mut conn)
    .await
    .expect("reporter comment");

    let admin_cookie = login_cookie(&router, &admin).await.expect("admin");
    let denied = post_form(
        &router,
        &format!("/admin/issues/{}/edit-comment?org={slug}", issue.key),
        Some(&admin_cookie),
        &format!(
            "comment_id={}&body={}",
            reporter.id,
            urlencoding_encode("rewrite company")
        ),
    )
    .await;
    assert_eq!(status(&denied), StatusCode::NOT_FOUND);

    let rows = IssueComment::all()
        .filter(IssueComment::fields().id().eq(reporter.id))
        .limit(1)
        .exec(&mut conn)
        .await
        .expect("reload");
    assert_eq!(rows[0].body, "Company said this");
    assert_eq!(rows[0].edited_at, COMMENT_NOT_EDITED);

    cleanup(&db).await;
}
