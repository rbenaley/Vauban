//! Contention tests for concurrent Release creates.

use std::sync::Arc;

use http_body_util::BodyExt;
use tokio::sync::Barrier;
use topcoat::router::StatusCode;
use vcp::models::{RELEASE_GA_ORG_ID, Release};

use crate::common::{
    cleanup, cookie_header, create_org_with_membership, db_lock, get, post_form, status, test_db,
    test_router, unique_email, unique_slug, urlencoding_encode,
};

fn count_channel_badges(html: &str) -> usize {
    html.matches("vb-badge chan-lts").count()
        + html.matches("vb-badge chan-stable").count()
        + html.matches("vb-badge chan-eol").count()
}

#[tokio::test]
async fn battle_concurrent_release_creates() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let n = 8usize;
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::with_capacity(n);
    let url = crate::common::database_url();
    let base = unique_slug("rel");

    for i in 0..n {
        let url = url.clone();
        let barrier = barrier.clone();
        let version = format!("{base}-{i}");
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let db = vcp::db::connect(&url).await.expect("connect");
            let mut conn = db.clone();
            let created = toasty::create!(Release {
                version: version.clone(),
                channel: "LTS".to_owned(),
                released_on: "2026-07-01".to_owned(),
                size_mb: "1.0".to_owned(),
                sha256: "pending".to_owned(),
                status: "PUBLISHED".to_owned(),
                notes: "FIX: battle".to_owned(),
                organization_id: RELEASE_GA_ORG_ID,
            })
            .exec(&mut conn)
            .await
            .expect("create release");
            assert_eq!(created.version, version);
        }));
    }

    for h in handles {
        h.await.expect("join");
    }

    {
        let mut conn = db.clone();
        let rows = Release::all().exec(&mut conn).await.expect("all");
        let ours = rows.iter().filter(|r| r.version.starts_with(&base)).count();
        assert_eq!(ours, n);
    }

    cleanup(&db).await;
}

#[tokio::test]
async fn battle_parallel_admin_releases_page_pagination() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let email = unique_email("battle-rel-page");
    let slug = unique_slug("battle-rel-page");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;

    {
        let mut conn = db.clone();
        for i in 0..11u32 {
            let version = format!("v99.battle.{i}");
            let _ = toasty::create!(Release {
                version,
                channel: "LTS".to_owned(),
                released_on: "2026-07-01".to_owned(),
                size_mb: "1.0".to_owned(),
                sha256: "eee".to_owned(),
                status: "PUBLISHED".to_owned(),
                notes: "FIX: battle page".to_owned(),
                organization_id: RELEASE_GA_ORG_ID,
            })
            .exec(&mut conn)
            .await
            .expect("release");
        }
    }

    let router = Arc::new(test_router().await);
    let form = format!("email={}&password=password", urlencoding_encode(&email));
    let login = post_form(router.as_ref(), "/login", None, &form).await;
    let cookie = cookie_header(&login).expect("cookie");

    let barrier = Arc::new(Barrier::new(2));
    let cookie_a = cookie.clone();
    let cookie_b = cookie;
    let router_a = router.clone();
    let router_b = router;
    let barrier_a = barrier.clone();
    let barrier_b = barrier;

    let h1 = tokio::spawn(async move {
        barrier_a.wait().await;
        let resp = get(router_a.as_ref(), "/admin/releases?page=1", Some(&cookie_a)).await;
        assert_eq!(status(&resp), StatusCode::OK);
        let body = resp.into_body().collect().await.expect("body").to_bytes();
        String::from_utf8_lossy(&body).into_owned()
    });
    let h2 = tokio::spawn(async move {
        barrier_b.wait().await;
        let resp = get(router_b.as_ref(), "/admin/releases?page=2", Some(&cookie_b)).await;
        assert_eq!(status(&resp), StatusCode::OK);
        let body = resp.into_body().collect().await.expect("body").to_bytes();
        String::from_utf8_lossy(&body).into_owned()
    });

    let page1 = h1.await.expect("join page1");
    let page2 = h2.await.expect("join page2");
    assert!(page1.contains("vb-pager"), "page1 pager: {page1}");
    assert!(
        page1.contains("vb-list-toolbar"),
        "toolbar under contention: {page1}"
    );
    assert_eq!(count_channel_badges(&page1), 10, "page1 rows: {page1}");
    assert!(
        (1..=10).contains(&count_channel_badges(&page2)),
        "page2 rows under contention: {page2}"
    );

    cleanup(&db).await;
}
