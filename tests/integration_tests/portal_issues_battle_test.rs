//! Contention tests for concurrent issue creates under one org.

use std::sync::Arc;

use tokio::sync::Barrier;
use topcoat::router::StatusCode;
use vcp::models::{
    ISSUE_COMMENT_KIND_COMMENT, ISSUE_COMMENT_KIND_STATUS, ISSUE_ROLE_REPORTER,
    ISSUE_STATUS_CLOSED, ISSUE_STATUS_OPEN, Issue, IssueComment,
};

use crate::common::{
    MultipartFile, TINY_PNG, cleanup, create_org_with_membership, db_lock, get, login_cookie,
    post_form, post_multipart_with_files, status, test_db, test_router, unique_email, unique_slug,
};

#[tokio::test]
async fn battle_concurrent_report_issue_http_posts() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let email = unique_email("battle-http-iss");
    let slug = unique_slug("battle-http-iss");
    let (_user, org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;

    let router = test_router().await;
    let cookie = login_cookie(&router, &email).await.expect("login cookie");

    let n = 8usize;
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::with_capacity(n);
    let marker = unique_slug("http-iss");

    for i in 0..n {
        let barrier = barrier.clone();
        let cookie = cookie.clone();
        let slug = slug.clone();
        let marker = marker.clone();
        let router = test_router().await;
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let title = format!("HTTP battle {marker} {i}");
            let details = format!("battle-{i}");
            let resp = post_multipart_with_files(
                &router,
                &format!("/{slug}/issues"),
                Some(&cookie),
                &[
                    ("title", title.as_str()),
                    ("component", "Portal"),
                    ("severity", "Minor"),
                    ("details", details.as_str()),
                ],
                &[],
            )
            .await;
            assert!(
                status(&resp).is_redirection(),
                "expected redirect, got {}",
                status(&resp)
            );
            let location = resp
                .headers()
                .get(topcoat::router::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_owned())
                .expect("Location");
            assert!(
                !location.contains("err=create"),
                "create must succeed under contention: {location}"
            );
            assert!(
                location.contains(&format!("/{slug}/issues/VBN-")),
                "expected detail redirect, got {location}"
            );
            let detail = get(&router, &location, Some(&cookie)).await;
            assert_eq!(
                status(&detail),
                StatusCode::OK,
                "must not redirect to missing detail ({location})"
            );
            location
        }));
    }

    let mut locations = Vec::with_capacity(n);
    for h in handles {
        locations.push(h.await.expect("join"));
    }
    locations.sort();
    locations.dedup();
    assert_eq!(
        locations.len(),
        n,
        "concurrent reports must allocate distinct keys"
    );

    {
        let mut conn = db.clone();
        let rows = Issue::all()
            .filter(Issue::fields().organization_id().eq(org.id))
            .exec(&mut conn)
            .await
            .expect("list");
        let ours: Vec<_> = rows
            .into_iter()
            .filter(|i| i.title.contains(&marker))
            .collect();
        assert_eq!(ours.len(), n);
        let mut keys: Vec<_> = ours.into_iter().map(|i| i.key).collect();
        keys.sort();
        keys.dedup();
        assert_eq!(keys.len(), n);
    }

    cleanup(&db).await;
}

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

#[tokio::test]
async fn battle_parallel_close_reopen_under_detail_reads() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = Arc::new(test_router().await);

    let email = unique_email("battle-close");
    let slug = unique_slug("battle-close-org");
    let (user, org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;

    let now = vcp::db::now_unix();
    let key = format!("TEST-{}", unique_slug("clr"));
    {
        let mut conn = db.clone();
        let _ = toasty::create!(Issue {
            key: key.clone(),
            title: "Close battle".to_owned(),
            component: "Portal".to_owned(),
            severity: "Minor".to_owned(),
            status: ISSUE_STATUS_OPEN.to_owned(),
            organization_id: org.id,
            details: "opener".to_owned(),
            opened_by_user_id: user.id,
            created_at: now,
            updated_at: now,
        })
        .exec(&mut conn)
        .await
        .expect("issue");
    }

    let cookie = login_cookie(router.as_ref(), &email).await.expect("cookie");

    let barrier = Arc::new(Barrier::new(3));
    let close_path = format!("/{slug}/issues/{key}/close");
    let reopen_path = format!("/{slug}/issues/{key}/reopen");
    let detail_path = format!("/{slug}/issues/{key}");

    let cookie_a = cookie.clone();
    let cookie_b = cookie.clone();
    let cookie_c = cookie;
    let router_a = router.clone();
    let router_b = router.clone();
    let router_c = router;
    let barrier_a = barrier.clone();
    let barrier_b = barrier.clone();
    let barrier_c = barrier;
    let close_path_a = close_path;
    let reopen_path_b = reopen_path;
    let detail_path_c = detail_path;

    let h1 = tokio::spawn(async move {
        barrier_a.wait().await;
        let resp = post_form(router_a.as_ref(), &close_path_a, Some(&cookie_a), "").await;
        assert!(
            status(&resp).is_redirection() || status(&resp) == StatusCode::OK,
            "close got {}",
            status(&resp)
        );
    });
    let h2 = tokio::spawn(async move {
        barrier_b.wait().await;
        let resp = post_form(router_b.as_ref(), &reopen_path_b, Some(&cookie_b), "").await;
        assert!(
            status(&resp).is_redirection() || status(&resp) == StatusCode::OK,
            "reopen got {}",
            status(&resp)
        );
    });
    let h3 = tokio::spawn(async move {
        barrier_c.wait().await;
        let resp = get(router_c.as_ref(), &detail_path_c, Some(&cookie_c)).await;
        assert_eq!(status(&resp), StatusCode::OK);
    });

    h1.await.expect("close join");
    h2.await.expect("reopen join");
    h3.await.expect("detail join");

    {
        let mut conn = db.clone();
        let rows = Issue::all()
            .filter(Issue::fields().organization_id().eq(org.id))
            .exec(&mut conn)
            .await
            .expect("list");
        let ours: Vec<_> = rows.into_iter().filter(|i| i.key == key).collect();
        assert_eq!(ours.len(), 1, "exactly one issue row");
        assert!(
            ours[0].status == ISSUE_STATUS_OPEN || ours[0].status == ISSUE_STATUS_CLOSED,
            "final status must be Open or Closed, got {}",
            ours[0].status
        );
        let comments = IssueComment::all()
            .filter(IssueComment::fields().issue_id().eq(ours[0].id))
            .exec(&mut conn)
            .await
            .expect("comments");
        let status_rows = comments
            .iter()
            .filter(|c| c.kind == ISSUE_COMMENT_KIND_STATUS)
            .count();
        assert!(
            status_rows <= 2,
            "at most one close + one reopen status_change under race, got {status_rows}"
        );
    }

    cleanup(&db).await;
}

#[tokio::test]
async fn battle_parallel_attach_respects_cap() {
    use vcp::issue_attachments::{attach_many, issue_attachment_list_limit, list_for_issue};
    use vcp::models::MAX_ISSUE_ATTACHMENTS;
    use vcp::storage::upsert_image_object;

    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let email = unique_email("battle-att");
    let slug = unique_slug("battle-att-org");
    let (user, org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;

    let mut conn = db.clone();
    let now = vcp::db::now_unix();
    let issue = toasty::create!(Issue {
        key: format!("TEST-{}", unique_slug("batt")),
        title: "Attach race".to_owned(),
        component: "Portal".to_owned(),
        severity: "Minor".to_owned(),
        status: ISSUE_STATUS_OPEN.to_owned(),
        organization_id: org.id,
        details: "race".to_owned(),
        opened_by_user_id: user.id,
        created_at: now,
        updated_at: now,
    })
    .exec(&mut conn)
    .await
    .expect("issue");

    let cap = MAX_ISSUE_ATTACHMENTS;
    let list_limit = issue_attachment_list_limit(cap);
    let sha = "ab".repeat(32);
    let mut tokens = Vec::new();
    for _ in 0..(cap + 3) {
        let id = uuid::Uuid::new_v4().to_string();
        upsert_image_object(&mut conn, org.id, &id, "png", &sha, 12)
            .await
            .expect("upsert image");
        tokens.push(format!("{id}.png"));
    }

    let wave1: Vec<String> = tokens.iter().take(cap).cloned().collect();
    let n = wave1.len();
    let barrier = Arc::new(Barrier::new(n));
    let url = crate::common::database_url();
    let org_id = org.id;
    let issue_id = issue.id;
    let user_id = user.id;
    let mut handles = Vec::with_capacity(n);
    for token in wave1 {
        let barrier = barrier.clone();
        let url = url.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let db = vcp::db::connect(&url).await.expect("connect");
            let mut conn = db.clone();
            attach_many(&mut conn, org_id, issue_id, 0, user_id, &[token], cap)
                .await
                .expect("wave1 attach");
        }));
    }
    for h in handles {
        h.await.expect("join");
    }

    let rows = list_for_issue(&mut conn, org.id, issue.id, list_limit)
        .await
        .expect("list");
    assert_eq!(
        rows.len(),
        cap,
        "exactly cap attachments after parallel wave on opener"
    );

    for token in tokens.iter().skip(cap) {
        let err = attach_many(
            &mut conn,
            org.id,
            issue.id,
            0,
            user.id,
            std::slice::from_ref(token),
            cap,
        )
        .await
        .expect_err("over-cap");
        assert_eq!(err, vcp::issue_attachments::AttachError::CapExceeded);
    }
    let rows = list_for_issue(&mut conn, org.id, issue.id, list_limit)
        .await
        .expect("list");
    assert_eq!(rows.len(), cap);

    cleanup(&db).await;
}

#[tokio::test]
async fn battle_concurrent_create_with_attachments() {
    use vcp::issue_attachments::list_for_issue;

    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let email = unique_email("battle-cr-att");
    let slug = unique_slug("battle-cr-att");
    let (_user, org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;

    let mut conn = db.clone();
    let router = test_router().await;
    let cookie = login_cookie(&router, &email).await.expect("login");
    let n = 6usize;
    let barrier = Arc::new(Barrier::new(n));
    let marker = unique_slug("cr-att");
    let mut handles = Vec::with_capacity(n);
    for i in 0..n {
        let barrier = barrier.clone();
        let cookie = cookie.clone();
        let slug = slug.clone();
        let marker = marker.clone();
        let router = test_router().await;
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let title = format!("Attach create {marker} {i}");
            let details = format!("att-{i}");
            let resp = post_multipart_with_files(
                &router,
                &format!("/{slug}/issues"),
                Some(&cookie),
                &[
                    ("title", title.as_str()),
                    ("component", "Portal"),
                    ("severity", "Minor"),
                    ("details", details.as_str()),
                ],
                &[MultipartFile {
                    field: "screenshots",
                    filename: "shot.png",
                    content_type: "image/png",
                    bytes: TINY_PNG,
                }],
            )
            .await;
            assert!(status(&resp).is_redirection(), "{}", status(&resp));
            let location = resp
                .headers()
                .get(topcoat::router::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_owned())
                .expect("Location");
            assert!(
                !location.contains("err="),
                "create+attach must succeed: {location}"
            );
            location
        }));
    }
    let mut locations = Vec::with_capacity(n);
    for h in handles {
        locations.push(h.await.expect("join"));
    }
    locations.sort();
    locations.dedup();
    assert_eq!(locations.len(), n);

    let rows = Issue::all()
        .filter(Issue::fields().organization_id().eq(org.id))
        .exec(&mut conn)
        .await
        .expect("issues");
    let ours: Vec<_> = rows
        .into_iter()
        .filter(|i| i.title.contains(&marker))
        .collect();
    assert_eq!(ours.len(), n);
    for issue in &ours {
        let atts = list_for_issue(
            &mut conn,
            org.id,
            issue.id,
            vcp::issue_attachments::issue_attachment_list_limit(vcp::models::MAX_ISSUE_ATTACHMENTS),
        )
        .await
        .expect("atts");
        assert_eq!(atts.len(), 1, "each create should carry one attachment");
    }

    cleanup(&db).await;
}

/// The picker and the lightbox are rendered per request. Under parallel
/// detail loads every response must still carry its own complete wiring —
/// no half-rendered figure, no picker that lost its cap.
#[tokio::test]
async fn battle_concurrent_detail_renders_keep_picker_and_lightbox() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let email = unique_email("battle-shot-ui");
    let slug = unique_slug("battle-shot-ui");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;

    let router = test_router().await;
    let cookie = login_cookie(&router, &email).await.expect("login");
    let created = post_multipart_with_files(
        &router,
        &format!("/{slug}/issues"),
        Some(&cookie),
        &[
            ("title", "Picker under load"),
            ("component", "Portal"),
            ("severity", "Minor"),
            ("details", "with a screenshot"),
        ],
        &[MultipartFile {
            field: "screenshots",
            filename: "shot.png",
            content_type: "image/png",
            bytes: TINY_PNG,
        }],
    )
    .await;
    let location = created
        .headers()
        .get(topcoat::router::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_owned())
        .expect("Location");

    let n = 8usize;
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::with_capacity(n);
    for _ in 0..n {
        let barrier = barrier.clone();
        let cookie = cookie.clone();
        let location = location.clone();
        let router = test_router().await;
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let resp = get(&router, &location, Some(&cookie)).await;
            assert_eq!(status(&resp), StatusCode::OK);
            let bytes = http_body_util::BodyExt::collect(resp.into_body())
                .await
                .expect("body")
                .to_bytes();
            String::from_utf8_lossy(&bytes).into_owned()
        }));
    }
    for h in handles {
        let html = h.await.expect("join");
        assert!(
            html.contains(&format!(
                "data-max=\"{}\"",
                vcp::models::MAX_ISSUE_ATTACHMENTS
            )),
            "every concurrent render must publish the cap"
        );
        assert!(
            html.contains("data-shot-add") && html.contains("data-shot-status"),
            "every concurrent render must ship the picker hooks"
        );
        assert!(
            html.contains("vb-issue-lightbox-figure") && html.contains("vb-issue-lightbox-close"),
            "every concurrent render must ship a complete lightbox figure"
        );
    }

    cleanup(&db).await;
}
