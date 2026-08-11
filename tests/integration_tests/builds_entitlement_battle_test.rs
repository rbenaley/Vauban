//! Contention: parallel authorized download POSTs return 200 with seeded blobs.

use std::sync::Arc;

use http_body_util::BodyExt;
use tokio::sync::Barrier;
use topcoat::router::StatusCode;
use vcp::models::{RELEASE_GA_ORG_ID, Release};

use crate::common::{
    cleanup, create_org_with_membership, db_lock, get, login_cookie, post_form,
    seed_release_artifact, seed_release_digest, status, test_db, test_router, unique_email,
    unique_slug,
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
    let payload = b"vcp-battle-download-fixture";
    {
        let mut conn = db.clone();
        let id = toasty::create!(Release {
            version: version.clone(),
            channel: "LTS".to_owned(),
            released_on: "2026-07-01".to_owned(),
            status: "PUBLISHED".to_owned(),
            notes: "FIX: x".to_owned(),
            organization_id: RELEASE_GA_ORG_ID,
            v_major: vcp::release_pkg::version_sort_fields(&version).v_major,
            v_minor: vcp::release_pkg::version_sort_fields(&version).v_minor,
            v_patch: vcp::release_pkg::version_sort_fields(&version).v_patch,
            is_industrial: 0,
            has_client_suffix: vcp::release_pkg::version_sort_fields(&version).has_client_suffix,
            client_suffix: vcp::release_pkg::version_sort_fields(&version).client_suffix,
            product_track: "LTS".to_owned(),
        })
        .exec(&mut conn)
        .await
        .expect("release")
        .id;
        let _sha = seed_release_artifact(&db, id, payload).await;
    }

    let cookie = {
        let router = test_router().await;
        login_cookie(&router, &email).await.expect("cookie")
    };

    let n = 8usize;
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::with_capacity(n);
    let path = format!("/{slug}/builds/{version}/download");
    let expected = payload.to_vec();

    for _ in 0..n {
        let barrier = barrier.clone();
        let cookie = cookie.clone();
        let path = path.clone();
        let expected = expected.clone();
        let router = test_router().await;
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let resp = post_form(&router, &path, Some(&cookie), "").await;
            assert_eq!(status(&resp), StatusCode::OK);
            let body = resp.into_body().collect().await.expect("body").to_bytes();
            assert_eq!(body.as_ref(), expected.as_slice());
        }));
    }

    for h in handles {
        h.await.expect("join");
    }

    cleanup(&db).await;
}

/// A wave of downloads on an artifact-less build must all PRG identically:
/// same 303, same Location, empty bodies, no partial stream, no panic.
#[tokio::test]
async fn battle_parallel_download_posts_without_blob_redirect() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let email = unique_email("battle-dl-miss");
    let slug = unique_slug("battle-dl-miss");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;

    let version = unique_slug("dl-miss-ver");
    {
        let mut conn = db.clone();
        let _ = toasty::create!(Release {
            version: version.clone(),
            channel: "LTS".to_owned(),
            released_on: "2026-07-01".to_owned(),
            status: "PUBLISHED".to_owned(),
            notes: "FIX: no blob".to_owned(),
            organization_id: RELEASE_GA_ORG_ID,
            v_major: vcp::release_pkg::version_sort_fields(&version).v_major,
            v_minor: vcp::release_pkg::version_sort_fields(&version).v_minor,
            v_patch: vcp::release_pkg::version_sort_fields(&version).v_patch,
            is_industrial: 0,
            has_client_suffix: vcp::release_pkg::version_sort_fields(&version).has_client_suffix,
            client_suffix: vcp::release_pkg::version_sort_fields(&version).client_suffix,
            product_track: "LTS".to_owned(),
        })
        .exec(&mut conn)
        .await
        .expect("release");
    }

    let cookie = {
        let router = test_router().await;
        login_cookie(&router, &email).await.expect("cookie")
    };

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
            let resp = post_form(&router, &path, Some(&cookie), "channel=LTS").await;
            assert_eq!(status(&resp), StatusCode::SEE_OTHER);
            let location = resp
                .headers()
                .get(topcoat::router::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
                .expect("Location");
            let body = resp.into_body().collect().await.expect("body").to_bytes();
            assert!(body.is_empty(), "redirect must not stream partial bytes");
            location
        }));
    }

    let expected = format!("/{slug}/builds/{version}?channel=LTS&dl_error=missing");
    for h in handles {
        let location = h.await.expect("join");
        assert_eq!(
            location, expected,
            "every failure must PRG to the same view"
        );
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
        let id = toasty::create!(Release {
            version: version.clone(),
            channel: "LTS".to_owned(),
            released_on: "2026-07-01".to_owned(),
            status: "PUBLISHED".to_owned(),
            notes: "FIX: x".to_owned(),
            organization_id: RELEASE_GA_ORG_ID,
            v_major: vcp::release_pkg::version_sort_fields(&version).v_major,
            v_minor: vcp::release_pkg::version_sort_fields(&version).v_minor,
            v_patch: vcp::release_pkg::version_sort_fields(&version).v_patch,
            is_industrial: 0,
            has_client_suffix: vcp::release_pkg::version_sort_fields(&version).has_client_suffix,
            client_suffix: vcp::release_pkg::version_sort_fields(&version).client_suffix,
            product_track: "LTS".to_owned(),
        })
        .exec(&mut conn)
        .await
        .expect("release")
        .id;
        // Ephemeral mint requires a storage_objects row (digest SoT).
        seed_release_digest(
            &db,
            id,
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            1_048_576,
        )
        .await;
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
    {
        let mut conn = db.clone();
        let _ = toasty::create!(Release {
            version: version.clone(),
            channel: "LTS".to_owned(),
            released_on: "2026-07-01".to_owned(),
            status: "PUBLISHED".to_owned(),
            notes: "FIX: verify battle".to_owned(),
            organization_id: RELEASE_GA_ORG_ID,
            v_major: vcp::release_pkg::version_sort_fields(&version).v_major,
            v_minor: vcp::release_pkg::version_sort_fields(&version).v_minor,
            v_patch: vcp::release_pkg::version_sort_fields(&version).v_patch,
            is_industrial: 0,
            has_client_suffix: vcp::release_pkg::version_sort_fields(&version).has_client_suffix,
            client_suffix: vcp::release_pkg::version_sort_fields(&version).client_suffix,
            product_track: "LTS".to_owned(),
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
                status: "PUBLISHED".to_owned(),
                notes: "FIX: page battle".to_owned(),
                organization_id: RELEASE_GA_ORG_ID,
                v_major: vcp::release_pkg::version_sort_fields(&version).v_major,
                v_minor: vcp::release_pkg::version_sort_fields(&version).v_minor,
                v_patch: vcp::release_pkg::version_sort_fields(&version).v_patch,
                is_industrial: 0,
                has_client_suffix: vcp::release_pkg::version_sort_fields(&version)
                    .has_client_suffix,
                client_suffix: vcp::release_pkg::version_sort_fields(&version).client_suffix,
                product_track: "LTS".to_owned(),
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

#[tokio::test]
async fn battle_parallel_lts_only_vs_industrial_only_no_cross_leak() {
    use crate::common::create_org_with_membership_subs;
    use vcp::release_pkg::release_write_keys;

    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let core = format!("v93.1.{}", unique_slug("bt").len());
    let lts_ver = format!("{core}+LTS");
    let ind_ver = format!("{core}+LTS.industrial");
    let payload = b"battle-track";
    for (version, channel, track) in [
        (lts_ver.as_str(), "LTS", "LTS"),
        (ind_ver.as_str(), "LTS.industrial", "LTS.industrial"),
    ] {
        let (sort, _) = release_write_keys(version, channel);
        let mut conn = db.clone();
        let id = toasty::create!(Release {
            version: version.to_owned(),
            channel: channel.to_owned(),
            released_on: "2026-07-01".to_owned(),
            status: "PUBLISHED".to_owned(),
            notes: "FIX: battle track".to_owned(),
            organization_id: RELEASE_GA_ORG_ID,
            v_major: sort.v_major,
            v_minor: sort.v_minor,
            v_patch: sort.v_patch,
            is_industrial: sort.is_industrial,
            has_client_suffix: sort.has_client_suffix,
            client_suffix: sort.client_suffix,
            product_track: track.to_owned(),
        })
        .exec(&mut conn)
        .await
        .expect("release")
        .id;
        let _ = seed_release_artifact(&db, id, payload).await;
        let _ = track;
    }

    let email_lts = unique_email("battle-lts");
    let slug_lts = unique_slug("battle-lts");
    let _ = create_org_with_membership_subs(&db, &email_lts, "password", &slug_lts, "member", 1, 0)
        .await;
    let email_ind = unique_email("battle-ind");
    let slug_ind = unique_slug("battle-ind");
    let _ = create_org_with_membership_subs(&db, &email_ind, "password", &slug_ind, "member", 0, 1)
        .await;

    let router = Arc::new(test_router().await);
    let cookie_lts = login_cookie(router.as_ref(), &email_lts)
        .await
        .expect("cookie");
    let cookie_ind = login_cookie(router.as_ref(), &email_ind)
        .await
        .expect("cookie");
    let barrier = Arc::new(Barrier::new(4));

    let mut handles = Vec::new();
    for (slug, cookie, allow_ver, deny_ver) in [
        (
            slug_lts.clone(),
            cookie_lts.clone(),
            lts_ver.clone(),
            ind_ver.clone(),
        ),
        (
            slug_ind.clone(),
            cookie_ind.clone(),
            ind_ver.clone(),
            lts_ver.clone(),
        ),
    ] {
        for is_allow in [true, false] {
            let router = router.clone();
            let barrier = barrier.clone();
            let slug = slug.clone();
            let cookie = cookie.clone();
            let ver = if is_allow {
                allow_ver.clone()
            } else {
                deny_ver.clone()
            };
            handles.push(tokio::spawn(async move {
                barrier.wait().await;
                let resp = post_form(
                    router.as_ref(),
                    &format!("/{slug}/builds/{ver}/download"),
                    Some(&cookie),
                    "",
                )
                .await;
                (is_allow, status(&resp))
            }));
        }
    }

    let mut allow_ok = 0;
    let mut deny_ok = 0;
    for h in handles {
        let (is_allow, st) = h.await.expect("join");
        if is_allow {
            assert_eq!(st, StatusCode::OK);
            allow_ok += 1;
        } else {
            assert_eq!(st, StatusCode::NOT_FOUND);
            deny_ok += 1;
        }
    }
    assert_eq!(allow_ok, 2);
    assert_eq!(deny_ok, 2);

    cleanup(&db).await;
}
