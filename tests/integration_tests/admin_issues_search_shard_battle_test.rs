//! Contention: parallel admin issues search shard POSTs.

use std::sync::Arc;

use http_body_util::BodyExt;
use tokio::sync::Barrier;
use topcoat::router::StatusCode;

use crate::common::{
    admin_issues_search_shard_body, cleanup, create_org_with_membership, create_test_issue,
    db_lock, get, login_cookie, post_json, shard_path_from_html, status, test_db, test_router,
    unique_email, unique_slug,
};

async fn body_text(resp: topcoat::router::Response) -> String {
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

#[tokio::test]
async fn battle_parallel_admin_issues_search_shard_posts_return_200() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let email = unique_email("battle-adm-iss");
    let slug = unique_slug("battle-adm-iss");
    let (user, org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let key = format!("VBN-{}", unique_slug("abk").replace('-', ""));
    create_test_issue(&db, org.id, user.id, &key, "Admin SSH queue", "Open").await;

    let router = test_router().await;
    let cookie = login_cookie(&router, &email).await.expect("cookie");
    let page = get(&router, "/admin/issues", Some(&cookie)).await;
    assert_eq!(status(&page), StatusCode::OK);
    let shard_path = shard_path_from_html(&body_text(page).await).expect("shard path");

    let n = 10usize;
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::with_capacity(n);

    for i in 0..n {
        let barrier = barrier.clone();
        let cookie = cookie.clone();
        let shard_path = shard_path.clone();
        let slug = slug.clone();
        let key = key.clone();
        let router = test_router().await;
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let q = if i % 2 == 0 { "ssh" } else { "zzz-no-hit" };
            let org_f = if i % 3 == 0 { slug.as_str() } else { "" };
            let body = admin_issues_search_shard_body(q, org_f, "");
            let resp = post_json(&router, &shard_path, Some(&cookie), &body).await;
            assert_eq!(status(&resp), StatusCode::OK);
            let html = body_text(resp).await;
            assert!(html.contains("data-admin-issues-search-shard"), "{html}");
            if q == "ssh" {
                assert!(html.contains(&key) || html.contains("Admin SSH"), "{html}");
            }
        }));
    }

    for h in handles {
        h.await.expect("join");
    }

    cleanup(&db).await;
}
