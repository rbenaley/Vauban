//! Contention: parallel GET /docs with search query.

use std::sync::Arc;

use tokio::sync::Barrier;
use topcoat::router::StatusCode;

use crate::common::{
    cleanup, cookie_header, create_org_with_membership, db_lock, get, post_form, status, test_db,
    test_router, unique_email, unique_slug, urlencoding_encode,
};

#[tokio::test]
async fn battle_parallel_docs_search_gets() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let email = unique_email("battle-shard");
    let slug = unique_slug("battle-shard-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;

    let router = test_router().await;
    let form = format!("email={}&password=password", urlencoding_encode(&email));
    let login = post_form(&router, "/login", None, &form).await;
    let cookie = cookie_header(&login).expect("cookie");

    let n = 8usize;
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::with_capacity(n);

    for i in 0..n {
        let barrier = barrier.clone();
        let cookie = cookie.clone();
        let slug = slug.clone();
        let router = test_router().await;
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let path = format!("/{slug}/docs?q=api{i}");
            let resp = get(&router, &path, Some(&cookie)).await;
            assert_eq!(status(&resp), StatusCode::OK);
        }));
    }

    for h in handles {
        h.await.expect("join");
    }

    cleanup(&db).await;
}
