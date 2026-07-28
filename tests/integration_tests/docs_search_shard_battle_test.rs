//! Contention: parallel docs search shard POSTs (the live-search path).

use std::sync::Arc;

use http_body_util::BodyExt;
use tokio::sync::Barrier;
use topcoat::router::StatusCode;

use crate::common::{
    cleanup, create_org_with_membership, create_published_doc, db_lock, docs_search_shard_body,
    get, login_cookie, post_json, shard_path_from_html, status, test_db, test_router, unique_email,
    unique_slug,
};

async fn body_text(resp: topcoat::router::Response) -> String {
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

#[tokio::test]
async fn battle_parallel_docs_search_gets() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let email = unique_email("battle-shard");
    let slug = unique_slug("battle-shard-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;

    let router = test_router().await;
    let cookie = login_cookie(&router, &email).await.expect("cookie");

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

#[tokio::test]
async fn battle_parallel_docs_search_shard_posts_return_200() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let email = unique_email("battle-shard-post");
    let slug = unique_slug("battle-shard-post-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;

    let pub_slug = unique_slug("battle-ssh-doc");
    create_published_doc(
        &db,
        "SSH Bastion Access",
        "tunnel howto",
        "Security",
        &pub_slug,
    )
    .await;

    let router = test_router().await;
    let cookie = login_cookie(&router, &email).await.expect("cookie");
    let page = get(&router, &format!("/{slug}/docs"), Some(&cookie)).await;
    assert_eq!(status(&page), StatusCode::OK);
    let html = body_text(page).await;
    let shard_path = shard_path_from_html(&html).expect("shard path");

    let n = 10usize;
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::with_capacity(n);

    for i in 0..n {
        let barrier = barrier.clone();
        let cookie = cookie.clone();
        let slug = slug.clone();
        let shard_path = shard_path.clone();
        let pub_slug = pub_slug.clone();
        let router = test_router().await;
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            // Alternate empty / matching queries under contention.
            let q = if i % 2 == 0 { "ssh" } else { "zzz-no-hit" };
            let body = docs_search_shard_body(&slug, q, "");
            let resp = post_json(&router, &shard_path, Some(&cookie), &body).await;
            assert_eq!(status(&resp), StatusCode::OK, "shard POST must not panic");
            let html = body_text(resp).await;
            assert!(
                html.contains("data-docs-search-shard"),
                "missing shard marker: {html}"
            );
            if q == "ssh" {
                assert!(
                    html.contains(&pub_slug) || html.contains("SSH Bastion"),
                    "expected match under contention: {html}"
                );
            }
        }));
    }

    for h in handles {
        h.await.expect("join");
    }

    cleanup(&db).await;
}
