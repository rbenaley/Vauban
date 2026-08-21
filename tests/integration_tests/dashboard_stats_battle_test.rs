//! Contention: parallel org dashboard GETs stay healthy under load.

use std::sync::Arc;

use http_body_util::BodyExt;
use tokio::sync::Barrier;
use topcoat::router::StatusCode;
use vcp::models::{ISSUE_STATUS_IN_ANALYSIS, ISSUE_STATUS_OPEN, ISSUE_STATUS_RESOLVED};

use crate::common::{
    cleanup, create_org_with_membership, create_test_issue, db_lock, get, login_cookie, status,
    test_db, test_router, unique_email, unique_slug,
};

async fn body_text(resp: topcoat::router::Response) -> String {
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

fn tile_value_after(html: &str, label: &str) -> String {
    let idx = html
        .find(label)
        .unwrap_or_else(|| panic!("missing tile label {label}"));
    let after = &html[idx + label.len()..];
    let marker = "vb-stat-value";
    let v = after
        .find(marker)
        .unwrap_or_else(|| panic!("missing {marker} after {label}"));
    let rest = &after[v + marker.len()..];
    let start = rest.find('>').expect("value open") + 1;
    let end = rest[start..].find('<').expect("value close") + start;
    rest[start..end].trim().to_owned()
}

#[tokio::test]
async fn battle_parallel_dashboard_gets_with_issue_stats() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let email = unique_email("dash-battle");
    let slug = unique_slug("dash-battle");
    let (user, org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;
    create_test_issue(
        &db,
        org.id,
        user.id,
        "VBN-BATTLE-1",
        "Open fixture",
        ISSUE_STATUS_OPEN,
    )
    .await;
    create_test_issue(
        &db,
        org.id,
        user.id,
        "VBN-BATTLE-2",
        "Analysis fixture",
        ISSUE_STATUS_IN_ANALYSIS,
    )
    .await;
    create_test_issue(
        &db,
        org.id,
        user.id,
        "VBN-BATTLE-3",
        "Resolved fixture",
        ISSUE_STATUS_RESOLVED,
    )
    .await;

    let router = test_router().await;
    let cookie = login_cookie(&router, &email).await.expect("cookie");
    let path = format!("/{slug}");

    let n = 8usize;
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::with_capacity(n);
    for _ in 0..n {
        let cookie = cookie.clone();
        let path = path.clone();
        let barrier = barrier.clone();
        let router = test_router().await;
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let resp = get(&router, &path, Some(&cookie)).await;
            assert_eq!(status(&resp), StatusCode::OK);
            let html = body_text(resp).await;
            assert!(html.contains("OPEN ISSUES"), "{html}");
            assert!(html.contains("IN ANALYSIS"), "{html}");
            assert_eq!(tile_value_after(&html, "OPEN ISSUES"), "1", "{html}");
            assert_eq!(tile_value_after(&html, "IN ANALYSIS"), "1", "{html}");
            assert!(html.contains("vb-grid-2"), "{html}");
            assert!(
                !html.contains("just now") && !html.contains(" ago"),
                "activity must stay dateless under contention: {html}"
            );
        }));
    }
    for h in handles {
        h.await.expect("join");
    }
    cleanup(&db).await;
}
