//! Battle: parallel GETs must not 5xx from a missing `.runtime()`.

use std::sync::Arc;

use tokio::sync::Barrier;
use topcoat::router::StatusCode;

use crate::common::{
    cleanup, create_org_with_membership, db_lock, get, login_cookie, status, test_db, test_router,
    unique_email, unique_slug,
};

#[tokio::test]
async fn battle_parallel_login_runtime_present() {
    let _guard = db_lock().lock().await;
    let router = Arc::new(test_router().await);
    let n = 8usize;
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::with_capacity(n);
    for _ in 0..n {
        let router = router.clone();
        let barrier = barrier.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let resp = get(&router, "/login", None).await;
            status(&resp)
        }));
    }
    for handle in handles {
        let code = handle.await.expect("join");
        assert_eq!(
            code,
            StatusCode::OK,
            "GET /login flood must not miss runtime"
        );
    }
}

#[tokio::test]
async fn battle_parallel_list_and_publish_pages() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let email = unique_email("rt-flood");
    let slug = unique_slug("rt-flood");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let router = Arc::new(test_router().await);
    let cookie = Arc::new(login_cookie(&router, &email).await);
    let paths = [
        "/login".to_owned(),
        format!("/{slug}/docs?q=ssh"),
        "/admin/companies?q=".to_owned(),
        "/admin/releases/new".to_owned(),
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
            let cookie = if path == "/login" {
                None
            } else {
                cookie.as_deref()
            };
            let resp = get(&router, &path, cookie).await;
            (path, status(&resp))
        }));
    }
    for handle in handles {
        let (path, code) = handle.await.expect("join");
        assert!(
            code.is_success() || code.is_redirection(),
            "{path} must not 5xx from missing .runtime(), got {code}"
        );
    }
}
