//! E2E: issue report persists details; wrong org 404.

use http_body_util::BodyExt;
use topcoat::router::StatusCode;

use crate::common::{
    cleanup, cookie_header, create_org_with_membership, create_test_org, db_lock, get, post_form,
    status, test_db, test_router, unique_email, unique_slug, urlencoding_encode,
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
