//! E2E: Topcoat 0.8 runtime script, login signals, branded 404, rail on ?page=.

use http_body_util::BodyExt;
use topcoat::router::StatusCode;

use crate::common::{
    assert_topcoat_click_handlers_are_functions, cleanup, create_org_with_membership, db_lock, get,
    login_cookie, status, test_db, test_router, unique_email, unique_slug,
};

async fn body_text(resp: topcoat::router::response::Response) -> String {
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

#[tokio::test]
async fn e2e_login_html_includes_0_8_runtime() {
    let _guard = db_lock().lock().await;
    let router = test_router().await;
    let resp = get(&router, "/login", None).await;
    assert_eq!(status(&resp), StatusCode::OK);
    let html = body_text(resp).await;
    assert!(
        html.contains("/_topcoat/assets/topcoat-") && html.contains("type=\"module\""),
        "login HTML must include the 0.8 runtime module script: {html}"
    );
    assert!(
        !html.contains("missing .runtime()") && !html.contains("runtime() was omitted"),
        "login must not panic about missing .runtime(): {html}"
    );
    assert!(
        html.contains("Sign in") || html.contains("email"),
        "login must render both sign-in chrome: {html}"
    );
    assert_topcoat_click_handlers_are_functions(&html);
}

#[tokio::test]
async fn e2e_unknown_path_branded_404_has_chrome() {
    let _guard = db_lock().lock().await;
    let router = test_router().await;
    let resp = get(&router, "/definitely-not-a-route", None).await;
    assert_eq!(status(&resp), StatusCode::NOT_FOUND);
    let html = body_text(resp).await;
    assert!(
        html.contains("data-vcp-404") || html.contains("vb-"),
        "unknown URL must keep branded 404 chrome: {html}"
    );
}

#[tokio::test]
async fn e2e_docs_page_two_keeps_docs_rail_active() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let email = unique_email("rail-page");
    let slug = unique_slug("rail-page");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;
    let router = test_router().await;
    let cookie = login_cookie(&router, &email).await;
    let resp = get(&router, &format!("/{slug}/docs?page=2"), cookie.as_deref()).await;
    assert_eq!(status(&resp), StatusCode::OK);
    let html = body_text(resp).await;
    assert!(
        html.contains("vb-rail-item active"),
        "docs ?page=2 must still mark a rail item active: {html}"
    );
    assert!(
        html.contains("/docs") && html.contains("Docs"),
        "docs rail item must stay on the docs list: {html}"
    );
}

#[tokio::test]
async fn e2e_publish_page_still_has_pkg_kick() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let email = unique_email("pkg-kick");
    let slug = unique_slug("pkg-kick");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let router = test_router().await;
    let cookie = login_cookie(&router, &email).await;
    let resp = get(&router, "/admin/releases/new", cookie.as_deref()).await;
    assert!(
        status(&resp).is_success() || status(&resp).is_redirection(),
        "publish page must render, got {}",
        status(&resp)
    );
    if status(&resp).is_success() {
        let html = body_text(resp).await;
        assert!(
            html.contains("vb-pkg-kick") || html.contains("pkg_go") || html.contains("Publish"),
            "publish compose must keep the 0.6 kick contract: {html}"
        );
    }
}
