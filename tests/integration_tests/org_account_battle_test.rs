//! Contention: parallel /{org}/account GETs stay healthy.

use std::sync::Arc;

use http_body_util::BodyExt;
use tokio::sync::Barrier;
use topcoat::router::StatusCode;

use crate::common::{
    cleanup, create_org_with_membership, db_lock, get, login_cookie, status, test_db, test_router,
    unique_email, unique_slug,
};

async fn body_text(resp: topcoat::router::Response) -> String {
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

#[tokio::test]
async fn battle_parallel_org_account_gets() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let email = unique_email("acct-battle");
    let slug = unique_slug("acct-battle");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;
    let router = test_router().await;
    let cookie = login_cookie(&router, &email).await.expect("cookie");
    let path = format!("/{slug}/account");

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
            assert!(
                html.contains("Account &amp; subscription")
                    || html.contains("Account & subscription"),
                "{html}"
            );
            assert!(html.contains("USER ACCOUNTS"), "{html}");
            assert!(html.contains("Vauban LTS subscriptions"), "{html}");
            assert!(!html.contains("SIGNED-IN USER"), "{html}");
        }));
    }
    for h in handles {
        h.await.expect("join");
    }
    cleanup(&db).await;
}
