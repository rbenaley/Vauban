//! Contention: parallel authorized download POSTs stay 501.

use std::sync::Arc;

use http_body_util::BodyExt;
use tokio::sync::Barrier;
use topcoat::router::StatusCode;
use vcp::models::{RELEASE_GA_ORG_ID, Release};

use crate::common::{
    cleanup, cookie_header, create_org_with_membership, db_lock, post_form, status, test_db,
    test_router, unique_email, unique_slug, urlencoding_encode,
};

#[tokio::test]
async fn battle_parallel_download_posts() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let email = unique_email("battle-dl");
    let slug = unique_slug("battle-dl-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;

    let version = unique_slug("dl-ver");
    {
        let mut conn = db.clone();
        let _ = toasty::create!(Release {
            version: version.clone(),
            channel: "LTS".to_owned(),
            released_on: "2026-07-01".to_owned(),
            size_mb: "1.0".to_owned(),
            signature_prefix: "abc".to_owned(),
            status: "PUBLISHED".to_owned(),
            notes: "FIX: x".to_owned(),
            organization_id: RELEASE_GA_ORG_ID,
        })
        .exec(&mut conn)
        .await
        .expect("release");
    }

    let router = test_router().await;
    let form = format!("email={}&password=password", urlencoding_encode(&email));
    let login = post_form(&router, "/login", None, &form).await;
    let cookie = cookie_header(&login).expect("cookie");

    let n = 8usize;
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::with_capacity(n);
    let path = format!("/{slug}/builds/{version}/download");

    for _ in 0..n {
        let barrier = barrier.clone();
        let cookie = cookie.clone();
        let path = path.clone();
        let router = test_router().await;
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let resp = post_form(&router, &path, Some(&cookie), "").await;
            assert_eq!(status(&resp), StatusCode::NOT_IMPLEMENTED);
            let body = resp.into_body().collect().await.expect("body").to_bytes();
            let text = String::from_utf8_lossy(&body);
            assert!(text.contains("download not configured"), "{text}");
        }));
    }

    for h in handles {
        h.await.expect("join");
    }

    cleanup(&db).await;
}
