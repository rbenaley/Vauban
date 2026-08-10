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

/// Exact `vb-stat-value` text after a dashboard tile label (avoids `contains("1")`
/// matching `19` / `16` / …).
fn tile_value_after(html: &str, label: &str) -> String {
    let idx = html
        .find(label)
        .unwrap_or_else(|| panic!("missing tile label {label}: {html}"));
    let after = &html[idx + label.len()..];
    let marker = "vb-stat-value";
    let v = after
        .find(marker)
        .unwrap_or_else(|| panic!("missing {marker} after {label}: {after}"));
    let rest = &after[v + marker.len()..];
    let start = rest
        .find('>')
        .unwrap_or_else(|| panic!("missing value open tag after {label}"))
        + 1;
    let end = rest[start..]
        .find('<')
        .unwrap_or_else(|| panic!("missing value close tag after {label}"))
        + start;
    rest[start..end].trim().to_owned()
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
        version: 1,
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

    assert_eq!(
        tile_value_after(&html, "OPEN ISSUES"),
        "1",
        "OPEN ISSUES must be FSM Open only"
    );
    assert_eq!(
        tile_value_after(&html, "IN ANALYSIS"),
        "1",
        "IN ANALYSIS must be FSM In analysis only"
    );

    cleanup(&db).await;
}

/// Regression: a mixed status corpus must not inflate OPEN ISSUES with In analysis
/// (the bug that showed 19 instead of 16 for a 16/3/1/1 tenant).
#[tokio::test]
async fn e2e_dashboard_open_tile_excludes_in_analysis() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;
    let email = unique_email("dash-e2e-mix");
    let slug = unique_slug("dash-e2e-mix");
    let (user, org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;
    let now = now_unix();

    for i in 0..5 {
        create_issue_at(
            &db,
            org.id,
            user.id,
            &format!("VBN-MIX-O{i}"),
            "Open row",
            ISSUE_STATUS_OPEN,
            now - 1_000 - i,
        )
        .await;
    }
    for i in 0..2 {
        create_issue_at(
            &db,
            org.id,
            user.id,
            &format!("VBN-MIX-A{i}"),
            "Analysis row",
            ISSUE_STATUS_IN_ANALYSIS,
            now - 100 - i,
        )
        .await;
    }
    create_issue_at(
        &db,
        org.id,
        user.id,
        "VBN-MIX-R",
        "Resolved row",
        ISSUE_STATUS_RESOLVED,
        now - 50,
    )
    .await;
    create_issue_at(
        &db,
        org.id,
        user.id,
        "VBN-MIX-C",
        "Closed row",
        ISSUE_STATUS_CLOSED,
        now - 40,
    )
    .await;

    let cookie = login_cookie(&router, &email).await.expect("cookie");
    let page = get(&router, &format!("/{slug}"), Some(&cookie)).await;
    assert_eq!(status(&page), StatusCode::OK);
    let html = body_text(page).await;

    assert_eq!(
        tile_value_after(&html, "OPEN ISSUES"),
        "5",
        "must not report 7 (Open+In analysis): {html}"
    );
    assert_eq!(
        tile_value_after(&html, "IN ANALYSIS"),
        "2",
        "analysis tile: {html}"
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
    assert_eq!(
        tile_value_after(&html, "OPEN ISSUES"),
        "1",
        "tenant A open_count must ignore foreign issues"
    );
    assert_eq!(
        tile_value_after(&html, "IN ANALYSIS"),
        "0",
        "tenant A in_analysis must be 0"
    );

    cleanup(&db).await;
}
