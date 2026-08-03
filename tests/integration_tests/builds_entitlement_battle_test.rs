//! Contention: parallel authorized download POSTs stay 501.

use std::sync::Arc;

use http_body_util::BodyExt;
use tokio::sync::Barrier;
use topcoat::router::StatusCode;
use vcp::models::{RELEASE_GA_ORG_ID, Release};

use crate::common::{
    cleanup, create_org_with_membership, db_lock, get, login_cookie, post_form, status, test_db,
    test_router, unique_email, unique_slug,
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
            sha256: "abc".to_owned(),
            status: "PUBLISHED".to_owned(),
            notes: "FIX: x".to_owned(),
            organization_id: RELEASE_GA_ORG_ID,
            v_major: vcp::release_pkg::version_sort_fields(&version).v_major,
            v_minor: vcp::release_pkg::version_sort_fields(&version).v_minor,
            v_patch: vcp::release_pkg::version_sort_fields(&version).v_patch,
            has_client_suffix: vcp::release_pkg::version_sort_fields(&version).has_client_suffix,
            client_suffix: vcp::release_pkg::version_sort_fields(&version).client_suffix,
        })
        .exec(&mut conn)
        .await
        .expect("release");
    }

    let router = test_router().await;
    let cookie = login_cookie(&router, &email).await.expect("cookie");

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

#[tokio::test]
async fn battle_parallel_ephemeral_generate() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let email = unique_email("battle-eph");
    let slug = unique_slug("battle-eph-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;

    let version = unique_slug("eph-ver");
    {
        let mut conn = db.clone();
        let _ = toasty::create!(Release {
            version: version.clone(),
            channel: "LTS".to_owned(),
            released_on: "2026-07-01".to_owned(),
            size_mb: "1.0".to_owned(),
            sha256: "abc".to_owned(),
            status: "PUBLISHED".to_owned(),
            notes: "FIX: x".to_owned(),
            organization_id: RELEASE_GA_ORG_ID,
            v_major: vcp::release_pkg::version_sort_fields(&version).v_major,
            v_minor: vcp::release_pkg::version_sort_fields(&version).v_minor,
            v_patch: vcp::release_pkg::version_sort_fields(&version).v_patch,
            has_client_suffix: vcp::release_pkg::version_sort_fields(&version).has_client_suffix,
            client_suffix: vcp::release_pkg::version_sort_fields(&version).client_suffix,
        })
        .exec(&mut conn)
        .await
        .expect("release");
    }

    let router = test_router().await;
    let cookie = login_cookie(&router, &email).await.expect("cookie");

    let n = 8usize;
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::with_capacity(n);
    let path = format!("/{slug}/builds/{version}/ephemeral");

    for _ in 0..n {
        let barrier = barrier.clone();
        let cookie = cookie.clone();
        let path = path.clone();
        let router = test_router().await;
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let resp = post_form(&router, &path, Some(&cookie), "").await;
            assert!(status(&resp).is_redirection(), "{:?}", status(&resp));
        }));
    }

    for h in handles {
        h.await.expect("join");
    }

    cleanup(&db).await;
}

#[tokio::test]
async fn battle_parallel_builds_page_keeps_verify_hooks() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let email = unique_email("battle-verify");
    let slug = unique_slug("battle-verify-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;

    let version = unique_slug("verify-ver");
    let digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    {
        let mut conn = db.clone();
        let _ = toasty::create!(Release {
            version: version.clone(),
            channel: "LTS".to_owned(),
            released_on: "2026-07-01".to_owned(),
            size_mb: "1.0".to_owned(),
            sha256: digest.to_owned(),
            status: "PUBLISHED".to_owned(),
            notes: "FIX: verify battle".to_owned(),
            organization_id: RELEASE_GA_ORG_ID,
            v_major: vcp::release_pkg::version_sort_fields(&version).v_major,
            v_minor: vcp::release_pkg::version_sort_fields(&version).v_minor,
            v_patch: vcp::release_pkg::version_sort_fields(&version).v_patch,
            has_client_suffix: vcp::release_pkg::version_sort_fields(&version).has_client_suffix,
            client_suffix: vcp::release_pkg::version_sort_fields(&version).client_suffix,
        })
        .exec(&mut conn)
        .await
        .expect("release");
    }

    let router = Arc::new(test_router().await);
    let cookie = login_cookie(router.as_ref(), &email).await.expect("cookie");

    let n = 8usize;
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::with_capacity(n);

    for i in 0..n {
        let barrier = barrier.clone();
        let cookie = cookie.clone();
        let slug = slug.clone();
        let version = version.clone();
        let router = router.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let path = if i % 2 == 0 {
                format!("/{slug}/builds")
            } else {
                format!("/{slug}/builds/{version}")
            };
            let resp = get(router.as_ref(), &path, Some(&cookie)).await;
            assert!(status(&resp).is_success(), "{path}");
            let body = resp.into_body().collect().await.expect("body").to_bytes();
            let html = String::from_utf8_lossy(&body);
            assert!(html.contains("Verify signature"), "{html}");
            assert!(
                html.contains("vb-verify") || html.contains("data-verify-signature-panel"),
                "{html}"
            );
        }));
    }

    for h in handles {
        h.await.expect("join");
    }

    cleanup(&db).await;
}

#[tokio::test]
async fn battle_parallel_builds_page_pagination() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let email = unique_email("battle-page");
    let slug = unique_slug("battle-page-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;

    {
        let mut conn = db.clone();
        for i in 0..11u32 {
            let version = format!("v99.0.{i}");
            let _ = toasty::create!(Release {
                version: version.clone(),
                channel: "LTS".to_owned(),
                released_on: "2026-07-01".to_owned(),
                size_mb: "1.0".to_owned(),
                sha256: "abc".to_owned(),
                status: "PUBLISHED".to_owned(),
                notes: "FIX: page battle".to_owned(),
                organization_id: RELEASE_GA_ORG_ID,
                v_major: vcp::release_pkg::version_sort_fields(&version).v_major,
                v_minor: vcp::release_pkg::version_sort_fields(&version).v_minor,
                v_patch: vcp::release_pkg::version_sort_fields(&version).v_patch,
                has_client_suffix: vcp::release_pkg::version_sort_fields(&version)
                    .has_client_suffix,
                client_suffix: vcp::release_pkg::version_sort_fields(&version).client_suffix,
            })
            .exec(&mut conn)
            .await
            .expect("release");
        }
    }

    let router = Arc::new(test_router().await);
    let cookie = login_cookie(router.as_ref(), &email).await.expect("cookie");

    let barrier = Arc::new(Barrier::new(2));
    let slug_a = slug.clone();
    let slug_b = slug.clone();
    let cookie_a = cookie.clone();
    let cookie_b = cookie.clone();
    let router_a = router.clone();
    let router_b = router.clone();
    let barrier_a = barrier.clone();
    let barrier_b = barrier;

    let h1 = tokio::spawn(async move {
        barrier_a.wait().await;
        let resp = get(
            router_a.as_ref(),
            &format!("/{slug_a}/builds?page=1"),
            Some(&cookie_a),
        )
        .await;
        assert!(status(&resp).is_success());
        let body = resp.into_body().collect().await.expect("body").to_bytes();
        String::from_utf8_lossy(&body).into_owned()
    });
    let h2 = tokio::spawn(async move {
        barrier_b.wait().await;
        let resp = get(
            router_b.as_ref(),
            &format!("/{slug_b}/builds?page=2"),
            Some(&cookie_b),
        )
        .await;
        assert!(status(&resp).is_success());
        let body = resp.into_body().collect().await.expect("body").to_bytes();
        String::from_utf8_lossy(&body).into_owned()
    });

    let page1 = h1.await.expect("join page1");
    let page2 = h2.await.expect("join page2");
    assert!(page1.contains("v99.0.10"), "page1 highest: {page1}");
    assert!(page1.contains("vb-pager"), "page1 pager: {page1}");
    assert!(
        page1.contains("vb-chip-row") && page1.contains("vb-chip-group"),
        "pager layout row present under contention: {page1}"
    );
    assert!(page2.contains("v99.0.0"), "page2 remainder: {page2}");
    assert!(
        !page2.contains(">v99.0.10<"),
        "page2 must not list highest: {page2}"
    );

    cleanup(&db).await;
}
