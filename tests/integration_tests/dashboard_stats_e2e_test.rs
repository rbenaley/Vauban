//! E2E: org dashboard issue tiles derive from one org-scoped load.

use http_body_util::BodyExt;
use toasty::Db;
use topcoat::router::StatusCode;
use vcp::{
    db::now_unix,
    models::{
        ISSUE_STATUS_CLOSED, ISSUE_STATUS_IN_ANALYSIS, ISSUE_STATUS_OPEN, ISSUE_STATUS_RESOLVED,
        Issue,
    },
};

use crate::common::{
    cleanup, create_org_with_membership, create_test_issue, db_lock, get, login_cookie, status,
    test_db, test_router, unique_email, unique_slug,
};

async fn body_text(resp: topcoat::router::Response) -> String {
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

async fn create_issue_at(
    db: &Db,
    organization_id: u64,
    opened_by_user_id: u64,
    key: &str,
    title: &str,
    status: &str,
    updated_at: i64,
) -> Issue {
    let mut conn = db.clone();
    toasty::create!(Issue {
        key: key.to_owned(),
        title: title.to_owned(),
        component: "SSH Proxy".to_owned(),
        severity: "Major".to_owned(),
        status: status.to_owned(),
        organization_id,
        details: "fixture".to_owned(),
        opened_by_user_id,
        created_at: updated_at,
        updated_at,
    })
    .exec(&mut conn)
    .await
    .expect("create timed issue")
}

#[tokio::test]
async fn e2e_dashboard_issue_stats_from_org_rows() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;
    let email = unique_email("dash-e2e-stats");
    let slug = unique_slug("dash-e2e-stats");
    let (user, org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;
    let now = now_unix();

    create_issue_at(
        &db,
        org.id,
        user.id,
        "VBN-DASH-OLD",
        "Older open",
        ISSUE_STATUS_OPEN,
        now - 5_000,
    )
    .await;
    create_issue_at(
        &db,
        org.id,
        user.id,
        "VBN-DASH-RES",
        "Resolved row",
        ISSUE_STATUS_RESOLVED,
        now - 4_000,
    )
    .await;
    create_issue_at(
        &db,
        org.id,
        user.id,
        "VBN-DASH-CL",
        "Closed row",
        ISSUE_STATUS_CLOSED,
        now - 3_000,
    )
    .await;
    create_issue_at(
        &db,
        org.id,
        user.id,
        "VBN-DASH-LATEST",
        "Newest analysis",
        ISSUE_STATUS_IN_ANALYSIS,
        now - 10,
    )
    .await;

    let cookie = login_cookie(&router, &email).await.expect("cookie");
    let page = get(&router, &format!("/{slug}"), Some(&cookie)).await;
    assert_eq!(status(&page), StatusCode::OK);
    let html = body_text(page).await;

    assert!(html.contains("OPEN ISSUES"), "{html}");
    assert!(html.contains("IN ANALYSIS"), "{html}");
    assert!(
        html.contains("VBN-DASH-LATEST"),
        "latest activity must prefer newest updated_at: {html}"
    );
    assert!(
        html.contains("moved to analysis"),
        "latest in-analysis activity copy: {html}"
    );

    let open_idx = html.find("OPEN ISSUES").expect("OPEN ISSUES");
    let open_window = &html[open_idx..open_idx.saturating_add(180).min(html.len())];
    assert!(
        open_window.contains(">2<") || open_window.contains("2"),
        "open_count=2 expected near OPEN ISSUES: {open_window}"
    );
    let anal_idx = html.find("IN ANALYSIS").expect("IN ANALYSIS");
    let anal_window = &html[anal_idx..anal_idx.saturating_add(180).min(html.len())];
    assert!(
        anal_window.contains(">1<") || anal_window.contains("1"),
        "in_analysis=1 expected near IN ANALYSIS: {anal_window}"
    );

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_dashboard_issue_stats_are_tenant_scoped() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email_a = unique_email("dash-e2e-a");
    let slug_a = unique_slug("dash-e2e-a");
    let (user_a, org_a) =
        create_org_with_membership(&db, &email_a, "password", &slug_a, "member").await;

    let email_b = unique_email("dash-e2e-b");
    let slug_b = unique_slug("dash-e2e-b");
    let (user_b, org_b) =
        create_org_with_membership(&db, &email_b, "password", &slug_b, "member").await;

    create_test_issue(
        &db,
        org_a.id,
        user_a.id,
        "VBN-TENANT-A",
        "Home org open",
        ISSUE_STATUS_OPEN,
    )
    .await;
    create_test_issue(
        &db,
        org_b.id,
        user_b.id,
        "VBN-TENANT-B",
        "Foreign flood",
        ISSUE_STATUS_IN_ANALYSIS,
    )
    .await;
    create_test_issue(
        &db,
        org_b.id,
        user_b.id,
        "VBN-TENANT-B2",
        "Foreign flood 2",
        ISSUE_STATUS_IN_ANALYSIS,
    )
    .await;

    let cookie = login_cookie(&router, &email_a).await.expect("cookie");
    let page = get(&router, &format!("/{slug_a}"), Some(&cookie)).await;
    assert_eq!(status(&page), StatusCode::OK);
    let html = body_text(page).await;

    assert!(
        !html.contains("VBN-TENANT-B"),
        "must not surface foreign issue keys: {html}"
    );
    let open_idx = html.find("OPEN ISSUES").expect("OPEN ISSUES");
    let open_window = &html[open_idx..open_idx.saturating_add(180).min(html.len())];
    assert!(
        open_window.contains(">1<") || open_window.contains("1"),
        "tenant A open_count must ignore foreign issues: {open_window}"
    );
    let anal_idx = html.find("IN ANALYSIS").expect("IN ANALYSIS");
    let anal_window = &html[anal_idx..anal_idx.saturating_add(180).min(html.len())];
    assert!(
        anal_window.contains(">0<") || anal_window.contains("0"),
        "tenant A in_analysis must be 0: {anal_window}"
    );

    cleanup(&db).await;
}
