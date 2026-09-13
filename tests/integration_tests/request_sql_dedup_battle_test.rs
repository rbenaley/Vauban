//! Contention: parallel list GETs that embed search shards stay healthy.

use std::sync::Arc;

use http_body_util::BodyExt;
use tokio::sync::Barrier;
use topcoat::router::StatusCode;

use crate::common::{
    cleanup, create_org_with_membership, db_lock, get, html_embeds_topcoat_shard, login_cookie,
    status, test_db, test_router, unique_email, unique_slug,
};

async fn body_text(resp: topcoat::router::response::Response) -> String {
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

#[tokio::test]
async fn battle_parallel_docs_list_gets_with_embedded_shard() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let email = unique_email("dedup-battle-docs");
    let slug = unique_slug("dedup-docs");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;
    let router = test_router().await;
    let cookie = login_cookie(&router, &email).await.expect("cookie");

    let n = 8usize;
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::with_capacity(n);
    let path = format!("/{slug}/docs");
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
                html.contains("data-docs-search-shard") || html_embeds_topcoat_shard(&html),
                "docs list must embed search shard"
            );
        }));
    }
    for h in handles {
        h.await.expect("join");
    }
    cleanup(&db).await;
}

#[tokio::test]
async fn battle_parallel_admin_companies_list_gets() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let email = unique_email("dedup-battle-co");
    let slug = unique_slug("dedup-co");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let router = test_router().await;
    let cookie = login_cookie(&router, &email).await.expect("cookie");

    let n = 8usize;
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::with_capacity(n);
    for _ in 0..n {
        let cookie = cookie.clone();
        let barrier = barrier.clone();
        let router = test_router().await;
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let resp = get(&router, "/admin/companies", Some(&cookie)).await;
            assert_eq!(status(&resp), StatusCode::OK);
            let html = body_text(resp).await;
            assert!(
                html.contains("data-admin-companies-search-shard")
                    || html_embeds_topcoat_shard(&html),
                "companies list must embed search shard"
            );
        }));
    }
    for h in handles {
        h.await.expect("join");
    }
    cleanup(&db).await;
}
