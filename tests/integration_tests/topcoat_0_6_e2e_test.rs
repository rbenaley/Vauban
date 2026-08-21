//! E2E: Topcoat 0.6 body limit and asset-backed HTML still work.

use http_body_util::BodyExt;
use vcp::config::MIB;

use crate::common::{
    MultipartFile, cleanup, create_org_with_membership, db_lock, get, login_cookie,
    post_multipart_with_files, status, test_config, test_db, test_router, test_router_with_config,
    unique_email, unique_slug,
};

#[tokio::test]
async fn e2e_unmatched_url_has_root_chrome() {
    let _guard = db_lock().lock().await;
    let router = test_router().await;
    let resp = get(&router, "/definitely-not-a-route", None).await;
    assert_eq!(status(&resp), topcoat::router::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn e2e_login_html_renders_with_assets() {
    let _guard = db_lock().lock().await;
    let router = test_router().await;
    let resp = get(&router, "/login", None).await;
    assert!(
        status(&resp).is_success(),
        "login must render, got {}",
        status(&resp)
    );
}

#[tokio::test]
async fn e2e_oversized_body_returns_413() {
    let _guard = db_lock().lock().await;
    let mut cfg = test_config().await;
    cfg.storage.max_artifact_bytes = 512 * 1024;
    cfg.storage.max_image_bytes = 256 * 1024;
    cfg.server.max_request_body_mib = 1;
    cfg.validate()
        .expect("1 MiB HTTP covers the lowered object quotas");
    assert_eq!(cfg.server.max_request_body_bytes(), MIB as usize);

    let db = test_db().await;
    cleanup(&db).await;
    let email = unique_email("body-413");
    let slug = unique_slug("body-413");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let router = test_router_with_config(cfg).await;
    let cookie = login_cookie(&router, &email).await;
    let oversized = vec![0u8; (MIB as usize) + 64 * 1024];
    let resp = post_multipart_with_files(
        &router,
        "/admin/releases/new",
        cookie.as_deref(),
        &[("date", "2026-08-01"), ("notes", "too big")],
        &[MultipartFile {
            field: "package",
            filename: "too-big.pkg",
            content_type: "application/octet-stream",
            bytes: &oversized,
        }],
    )
    .await;
    assert_eq!(
        status(&resp),
        topcoat::router::StatusCode::PAYLOAD_TOO_LARGE,
        "body over max_request_body_mib must 413"
    );
}

fn location(resp: &topcoat::router::response::Response) -> Option<&str> {
    resp.headers().get("location").and_then(|v| v.to_str().ok())
}

#[tokio::test]
async fn e2e_href_root_and_logout_match_markers() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let email = unique_email("href-nav");
    let slug = unique_slug("href-nav");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let router = test_router().await;

    let anon = get(&router, "/", None).await;
    assert_eq!(
        location(&anon),
        Some("/login"),
        "anonymous / must href! login_page"
    );

    let cookie = login_cookie(&router, &email).await;
    let dash = get(&router, &format!("/{slug}"), cookie.as_deref()).await;
    assert!(status(&dash).is_success());
    let html = {
        let bytes = dash.into_body().collect().await.expect("body").to_bytes();
        String::from_utf8_lossy(&bytes).into_owned()
    };
    assert!(
        html.contains(&format!("href=\"/{slug}/docs\"")),
        "dashboard docs card must use href!(docs_page)"
    );
    assert!(
        html.contains("href=\"/admin/releases\""),
        "admin rail must use href!(admin_releases_page)"
    );

    let logout = crate::common::post_form(&router, "/logout", cookie.as_deref(), "").await;
    assert_eq!(
        location(&logout),
        Some("/login"),
        "logout PRG must href! login_page"
    );
}
