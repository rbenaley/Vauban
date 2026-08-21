//! Contention: parallel admin companies search shard POSTs.

use std::sync::Arc;

use http_body_util::BodyExt;
use tokio::sync::Barrier;
use topcoat::router::StatusCode;

use crate::common::{
    admin_companies_search_shard_body, cleanup, create_org_with_membership, create_test_org,
    db_lock, get, login_cookie, post_json, shard_path_from_html, status, test_db, test_router,
    unique_email, unique_slug,
};

async fn body_text(resp: topcoat::router::response::Response) -> String {
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

#[tokio::test]
async fn battle_parallel_admin_companies_search_shard_posts_return_200() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let email = unique_email("battle-co-shard");
    let slug = unique_slug("battle-co-shard");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;

    let marker = unique_slug("bcoshards");
    create_test_org(&db, &unique_slug(&format!("{marker}-hit"))).await;

    let router = test_router().await;
    let cookie = login_cookie(&router, &email).await.expect("cookie");
    let page = get(&router, "/admin/companies", Some(&cookie)).await;
    assert_eq!(status(&page), StatusCode::OK);
    let shard_path = shard_path_from_html(&body_text(page).await).expect("shard path");

    let n = 10usize;
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::with_capacity(n);

    for i in 0..n {
        let barrier = barrier.clone();
        let cookie = cookie.clone();
        let shard_path = shard_path.clone();
        let marker = marker.clone();
        let router = test_router().await;
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let q = if i % 2 == 0 {
                marker.as_str()
            } else {
                "zzz-no-hit-co"
            };
            let body = admin_companies_search_shard_body(q);
            let resp = post_json(&router, &shard_path, Some(&cookie), &body).await;
            assert_eq!(status(&resp), StatusCode::OK);
            let html = body_text(resp).await;
            assert!(html.contains("data-admin-companies-search-shard"), "{html}");
            if q == marker.as_str() {
                assert!(html.contains(&marker), "{html}");
            }
        }));
    }

    for h in handles {
        h.await.expect("join");
    }

    cleanup(&db).await;
}
