//! Battle: parallel 413 floods under a tiny BodyLimit.

use std::sync::Arc;

use tokio::sync::Barrier;
use vcp::config::MIB;

use crate::common::{
    MultipartFile, cleanup, create_org_with_membership, db_lock, get, login_cookie,
    post_multipart_with_files, status, test_config, test_db, test_router, test_router_with_config,
    unique_email, unique_slug,
};

#[tokio::test]
async fn battle_parallel_413_tiny_body_cap() {
    let _guard = db_lock().lock().await;
    let mut cfg = test_config().await;
    cfg.storage.max_artifact_bytes = 512 * 1024;
    cfg.storage.max_image_bytes = 256 * 1024;
    cfg.server.max_request_body_mib = 1;
    cfg.validate()
        .expect("tiny cap is valid with lowered quotas");

    let db = test_db().await;
    cleanup(&db).await;
    let email = unique_email("body-413-b");
    let slug = unique_slug("body-413-b");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let router = Arc::new(test_router_with_config(cfg).await);
    let cookie = login_cookie(&router, &email).await;
    let cookie = Arc::new(cookie);
    let oversized = Arc::new(vec![0u8; (MIB as usize) + 8 * 1024]);
    let n = 8usize;
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::with_capacity(n);
    for _ in 0..n {
        let router = router.clone();
        let oversized = oversized.clone();
        let cookie = cookie.clone();
        let barrier = barrier.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let resp = post_multipart_with_files(
                &router,
                "/admin/releases/new",
                cookie.as_deref(),
                &[("date", "2026-08-01"), ("notes", "flood")],
                &[MultipartFile {
                    field: "package",
                    filename: "too-big.pkg",
                    content_type: "application/octet-stream",
                    bytes: &oversized,
                }],
            )
            .await;
            status(&resp)
        }));
    }
    for handle in handles {
        let code = handle.await.expect("join");
        assert_eq!(code, topcoat::router::StatusCode::PAYLOAD_TOO_LARGE);
    }
}

#[tokio::test]
async fn battle_parallel_unknown_url_404() {
    let _guard = db_lock().lock().await;
    let router = Arc::new(test_router().await);
    let n = 8usize;
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::with_capacity(n);
    for i in 0..n {
        let router = router.clone();
        let barrier = barrier.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let resp = get(&router, &format!("/no-such-battle-{i}"), None).await;
            status(&resp)
        }));
    }
    for handle in handles {
        let code = handle.await.expect("join");
        assert_eq!(code, topcoat::router::StatusCode::NOT_FOUND);
    }
}

#[tokio::test]
async fn battle_parallel_href_list_pages() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let email = unique_email("href-battle");
    let slug = unique_slug("href-battle");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let router = Arc::new(test_router().await);
    let cookie = Arc::new(login_cookie(&router, &email).await);
    let paths = [
        format!("/{slug}/docs?page=2"),
        format!("/{slug}/issues?page=2"),
        "/admin/releases?page=2".to_owned(),
        "/admin/companies?page=2".to_owned(),
    ];
    let n = paths.len();
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::with_capacity(n);
    for path in paths {
        let router = router.clone();
        let cookie = cookie.clone();
        let barrier = barrier.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let resp = get(&router, &path, cookie.as_deref()).await;
            (path, status(&resp))
        }));
    }
    for handle in handles {
        let (path, code) = handle.await.expect("join");
        assert!(
            code.is_success() || code.is_redirection(),
            "href-built {path} must be served, got {code}"
        );
    }
}
