//! Contention tests for concurrent Release creates.

use std::sync::Arc;

use http_body_util::BodyExt;
use tokio::sync::Barrier;
use topcoat::router::StatusCode;
use vcp::models::{RELEASE_GA_ORG_ID, Release};

use crate::common::{
    cleanup, create_org_with_membership, db_lock, get, login_cookie, post_form, status, test_db,
    test_router, unique_email, unique_slug,
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
                status: "PUBLISHED".to_owned(),
                notes: "FIX: battle".to_owned(),
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
                version: version.clone(),
                channel: "LTS".to_owned(),
                released_on: "2026-07-01".to_owned(),
                status: "PUBLISHED".to_owned(),
                notes: "FIX: battle page".to_owned(),
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
        page1.contains("vb-chip-row") && page1.contains("vb-rel-head"),
        "chip row + catalog grid under contention: {page1}"
    );
    assert_eq!(count_channel_badges(&page1), 10, "page1 rows: {page1}");
    assert!(
        (1..=10).contains(&count_channel_badges(&page2)),
        "page2 rows under contention: {page2}"
    );

    cleanup(&db).await;
}

#[tokio::test]
async fn battle_parallel_publish_unpublish_under_list_reads() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let email = unique_email("battle-rel-status");
    let slug = unique_slug("battle-rel-status");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;

    let release_id = {
        let mut conn = db.clone();
        let id = toasty::create!(Release {
            version: "v95.battle.status".to_owned(),
            channel: "LTS".to_owned(),
            released_on: "2026-07-01".to_owned(),
            status: "PUBLISHED".to_owned(),
            notes: "FIX: battle status".to_owned(),
            organization_id: RELEASE_GA_ORG_ID,
            v_major: vcp::release_pkg::version_sort_fields("v95.battle.status").v_major,
            v_minor: vcp::release_pkg::version_sort_fields("v95.battle.status").v_minor,
            v_patch: vcp::release_pkg::version_sort_fields("v95.battle.status").v_patch,
            has_client_suffix: vcp::release_pkg::version_sort_fields("v95.battle.status")
                .has_client_suffix,
            client_suffix: vcp::release_pkg::version_sort_fields("v95.battle.status").client_suffix,
        })
        .exec(&mut conn)
        .await
        .expect("release")
        .id;
        vcp::storage::upsert_release_object(
            &mut conn,
            id,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            1_048_576,
        )
        .await
        .expect("storage object");
        id
    };

    let router = Arc::new(test_router().await);
    let cookie = login_cookie(router.as_ref(), &email).await.expect("cookie");

    let barrier = Arc::new(Barrier::new(3));
    let cookie_a = cookie.clone();
    let cookie_b = cookie.clone();
    let cookie_c = cookie;
    let router_a = router.clone();
    let router_b = router.clone();
    let router_c = router;
    let barrier_a = barrier.clone();
    let barrier_b = barrier.clone();
    let barrier_c = barrier;

    let h_list = tokio::spawn(async move {
        barrier_a.wait().await;
        let resp = get(router_a.as_ref(), "/admin/releases", Some(&cookie_a)).await;
        assert_eq!(status(&resp), StatusCode::OK);
    });
    let h_unpub = tokio::spawn(async move {
        barrier_b.wait().await;
        let resp = post_form(
            router_b.as_ref(),
            &format!("/admin/releases/{release_id}/unpublish"),
            Some(&cookie_b),
            "",
        )
        .await;
        assert!(status(&resp).is_redirection() || status(&resp) == StatusCode::OK);
    });
    let h_pub = tokio::spawn(async move {
        barrier_c.wait().await;
        let resp = post_form(
            router_c.as_ref(),
            &format!("/admin/releases/{release_id}/publish"),
            Some(&cookie_c),
            "",
        )
        .await;
        assert!(status(&resp).is_redirection() || status(&resp) == StatusCode::OK);
    });

    h_list.await.expect("list join");
    h_unpub.await.expect("unpub join");
    h_pub.await.expect("pub join");

    {
        let mut conn = db.clone();
        let rows = Release::all()
            .filter(Release::fields().id().eq(release_id))
            .exec(&mut conn)
            .await
            .expect("lookup");
        assert_eq!(rows.len(), 1);
        assert!(
            rows[0].status == "PUBLISHED" || rows[0].status == "HIDDEN",
            "status must remain a known value: {}",
            rows[0].status
        );
    }

    cleanup(&db).await;
}

#[tokio::test]
async fn battle_parallel_semver_list_order_under_concurrent_creates() {
    use std::sync::Arc;
    use tokio::sync::Barrier;

    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let email = unique_email("battle-semver");
    let slug = unique_slug("battle-semver");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;

    // High majors stay on page 1 even if a leftover demo catalog is present.
    let barrier = Arc::new(Barrier::new(4));
    let mut handles = Vec::new();
    for (i, suffix) in ["acme", "beta", "zenith"].into_iter().enumerate() {
        let db = db.clone();
        let barrier = barrier.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let version = format!("v99.7.1-{suffix}");
            let mut conn = db.clone();
            let _ = toasty::create!(Release {
                version: version.clone(),
                channel: "LTS".to_owned(),
                released_on: "2026-07-01".to_owned(),
                status: "PUBLISHED".to_owned(),
                notes: format!("FIX: battle {i}"),
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
        }));
    }
    {
        let db = db.clone();
        let barrier = barrier.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let version = "v99.7.1".to_owned();
            let mut conn = db.clone();
            let _ = toasty::create!(Release {
                version: version.clone(),
                channel: "LTS".to_owned(),
                released_on: "2026-07-01".to_owned(),
                status: "PUBLISHED".to_owned(),
                notes: "FIX: plain".to_owned(),
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
        }));
    }
    for h in handles {
        h.await.expect("join create");
    }

    let router = Arc::new(test_router().await);
    let cookie = login_cookie(&router, &email).await.expect("cookie");
    let barrier = Arc::new(Barrier::new(3));
    let mut readers = Vec::new();
    for _ in 0..3 {
        let router = router.clone();
        let cookie = cookie.clone();
        let barrier = barrier.clone();
        readers.push(tokio::spawn(async move {
            barrier.wait().await;
            let resp = get(&router, "/admin/releases", Some(&cookie)).await;
            assert_eq!(status(&resp), StatusCode::OK);
            let bytes = resp.into_body().collect().await.expect("body").to_bytes();
            String::from_utf8_lossy(&bytes).into_owned()
        }));
    }
    for h in readers {
        let html = h.await.expect("join read");
        let i_acme = html.find("v99.7.1-acme").expect("acme");
        let i_beta = html.find("v99.7.1-beta").expect("beta");
        let i_zen = html.find("v99.7.1-zenith").expect("zenith");
        let i_plain = html
            .find(">v99.7.1<")
            .or_else(|| html.find("v99.7.1"))
            .expect("plain");
        assert!(
            i_acme < i_beta && i_beta < i_zen && i_zen < i_plain,
            "stable SQL order under contention: {html}"
        );
    }

    cleanup(&db).await;
}

/// Sweeping abandoned ceremonies must never touch a publish that is still in
/// flight: parallel uploads and Release manager reads keep every staged row
/// alive and hidden, and cancels remove exactly those rows.
#[tokio::test]
async fn battle_staged_publishes_survive_concurrent_list_sweeps() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let mut cfg = crate::common::test_config().await;
    cfg.storage.webauthn_required = true;
    // Every staged publish holds an in-flight upload slot until it commits or
    // is rolled back; keep the helper cap above the storm size.
    cfg.storage.max_concurrent_uploads = 16;
    let router = Arc::new(crate::common::test_router_with_config(cfg).await);

    let email = unique_email("battle-staged");
    let slug = unique_slug("battle-staged");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let cookie = login_cookie(router.as_ref(), &email).await.expect("cookie");

    let n = 6usize;
    let base = unique_slug("v-staged");
    let barrier = Arc::new(Barrier::new(n * 2));
    let mut uploads = Vec::with_capacity(n);
    let mut readers = Vec::with_capacity(n);

    for i in 0..n {
        let upload_router = router.clone();
        let upload_cookie = cookie.clone();
        let upload_barrier = barrier.clone();
        let version = format!("{base}-{i}");
        uploads.push(tokio::spawn(async move {
            upload_barrier.wait().await;
            let bytes = vcp::freebsd_pkg::craft_test_vauban_pkg(&version);
            let resp = crate::common::post_multipart_with_files(
                upload_router.as_ref(),
                "/admin/releases/new",
                Some(&upload_cookie),
                &[("date", "2026-08-01"), ("notes", "FIX: battle staged")],
                &[crate::common::MultipartFile {
                    field: "package",
                    filename: "vauban.pkg",
                    content_type: "application/octet-stream",
                    bytes: &bytes,
                }],
            )
            .await;
            assert!(status(&resp).is_redirection());
            resp.headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .and_then(|l| l.strip_prefix("/admin/releases/confirm?token="))
                .expect("confirm redirect")
                .to_owned()
        }));

        let read_router = router.clone();
        let read_cookie = cookie.clone();
        let read_barrier = barrier.clone();
        readers.push(tokio::spawn(async move {
            read_barrier.wait().await;
            let resp = get(read_router.as_ref(), "/admin/releases", Some(&read_cookie)).await;
            assert_eq!(status(&resp), StatusCode::OK);
            let body = resp.into_body().collect().await.expect("body").to_bytes();
            String::from_utf8_lossy(&body).into_owned()
        }));
    }

    let mut tokens = Vec::with_capacity(n);
    for h in uploads {
        tokens.push(h.await.expect("join upload"));
    }
    for h in readers {
        let html = h.await.expect("join reader");
        assert!(
            !html.contains(&base),
            "in-flight publish must stay out of the release manager: {html}"
        );
    }

    {
        let mut conn = db.clone();
        let rows = Release::all().exec(&mut conn).await.expect("all");
        let staged: Vec<_> = rows.iter().filter(|r| r.version.contains(&base)).collect();
        assert_eq!(staged.len(), n, "no live ceremony may be swept");
        assert!(staged.iter().all(|r| r.status == "STAGING"));
    }

    for token in tokens {
        let resp = crate::common::post_form(
            router.as_ref(),
            "/admin/releases/confirm/cancel",
            Some(&cookie),
            &format!("token={token}"),
        )
        .await;
        assert!(status(&resp).is_redirection());
    }

    {
        let mut conn = db.clone();
        let rows = Release::all().exec(&mut conn).await.expect("all");
        assert!(
            !rows.iter().any(|r| r.version.contains(&base)),
            "cancelled publishes must leave nothing behind"
        );
    }

    cleanup(&db).await;
}

/// Parallel validate-pkg preflights: garbage stays 422 with no rows; crafted
/// packages return 204 under contention.
#[tokio::test]
async fn battle_parallel_validate_pkg_preflight() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let router = Arc::new(test_router().await);
    let email = unique_email("battle-valpkg");
    let slug = unique_slug("battle-valpkg");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let cookie = login_cookie(router.as_ref(), &email).await.expect("cookie");

    let before = {
        let mut conn = db.clone();
        Release::all()
            .exec(&mut conn)
            .await
            .expect("releases")
            .len()
    };

    let n = 4usize;
    let barrier = Arc::new(Barrier::new(n * 2));
    let mut bad = Vec::with_capacity(n);
    let mut ok = Vec::with_capacity(n);

    for i in 0..n {
        let upload_router = router.clone();
        let upload_cookie = cookie.clone();
        let upload_barrier = barrier.clone();
        bad.push(tokio::spawn(async move {
            upload_barrier.wait().await;
            let garbage = format!("not-a-pkg-preflight-{i}").into_bytes();
            let resp = crate::common::post_multipart_with_files(
                upload_router.as_ref(),
                "/admin/releases/new/validate-pkg",
                Some(&upload_cookie),
                &[],
                &[crate::common::MultipartFile {
                    field: "package",
                    filename: "vauban.pkg",
                    content_type: "application/octet-stream",
                    bytes: &garbage,
                }],
            )
            .await;
            status(&resp)
        }));

        let upload_router = router.clone();
        let upload_cookie = cookie.clone();
        let upload_barrier = barrier.clone();
        ok.push(tokio::spawn(async move {
            upload_barrier.wait().await;
            let bytes = vcp::freebsd_pkg::craft_test_vauban_pkg(&format!("1.0.{i}"));
            let resp = crate::common::post_multipart_with_files(
                upload_router.as_ref(),
                "/admin/releases/new/validate-pkg",
                Some(&upload_cookie),
                &[],
                &[crate::common::MultipartFile {
                    field: "package",
                    filename: "vauban.pkg",
                    content_type: "application/octet-stream",
                    bytes: &bytes,
                }],
            )
            .await;
            status(&resp)
        }));
    }

    for h in bad {
        assert_eq!(h.await.expect("join bad"), StatusCode::UNPROCESSABLE_ENTITY);
    }
    for h in ok {
        assert_eq!(h.await.expect("join ok"), StatusCode::NO_CONTENT);
    }

    {
        let mut conn = db.clone();
        let after = Release::all()
            .exec(&mut conn)
            .await
            .expect("releases")
            .len();
        assert_eq!(after, before, "validate-pkg must never create rows");
    }

    cleanup(&db).await;
}

/// Concurrent garbage uploads must never leave STAGING rows; interleaved
/// valid packages must still reach the confirm ceremony.
#[tokio::test]
async fn battle_parallel_invalid_packages_never_stage() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let mut cfg = crate::common::test_config().await;
    cfg.storage.webauthn_required = true;
    cfg.storage.max_concurrent_uploads = 16;
    let router = Arc::new(crate::common::test_router_with_config(cfg).await);

    let email = unique_email("battle-notpkg");
    let slug = unique_slug("battle-notpkg");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let cookie = login_cookie(router.as_ref(), &email).await.expect("cookie");

    let n = 4usize;
    let base_bad = unique_slug("v-bad");
    let base_ok = unique_slug("v-ok");
    let barrier = Arc::new(Barrier::new(n * 2));
    let mut bad = Vec::with_capacity(n);
    let mut ok = Vec::with_capacity(n);

    for i in 0..n {
        let upload_router = router.clone();
        let upload_cookie = cookie.clone();
        let upload_barrier = barrier.clone();
        bad.push(tokio::spawn(async move {
            upload_barrier.wait().await;
            let garbage = format!("not-a-pkg-{i}").into_bytes();
            let resp = crate::common::post_multipart_with_files(
                upload_router.as_ref(),
                "/admin/releases/new",
                Some(&upload_cookie),
                &[("date", "2026-08-01"), ("notes", "FIX: battle not pkg")],
                &[crate::common::MultipartFile {
                    field: "package",
                    filename: "vauban.pkg",
                    content_type: "application/octet-stream",
                    bytes: &garbage,
                }],
            )
            .await;
            assert!(status(&resp).is_redirection());
            resp.headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_owned()
        }));

        let upload_router = router.clone();
        let upload_cookie = cookie.clone();
        let upload_barrier = barrier.clone();
        let version = format!("{base_ok}-{i}");
        ok.push(tokio::spawn(async move {
            upload_barrier.wait().await;
            let bytes = vcp::freebsd_pkg::craft_test_vauban_pkg(&version);
            let resp = crate::common::post_multipart_with_files(
                upload_router.as_ref(),
                "/admin/releases/new",
                Some(&upload_cookie),
                &[("date", "2026-08-01"), ("notes", "FIX: battle ok pkg")],
                &[crate::common::MultipartFile {
                    field: "package",
                    filename: "vauban.pkg",
                    content_type: "application/octet-stream",
                    bytes: &bytes,
                }],
            )
            .await;
            assert!(status(&resp).is_redirection());
            resp.headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_owned()
        }));
    }

    for h in bad {
        let loc = h.await.expect("join bad");
        assert_eq!(loc, "/admin/releases/new?err=not_pkg");
    }
    let mut tokens = Vec::with_capacity(n);
    for h in ok {
        let loc = h.await.expect("join ok");
        let token = loc
            .strip_prefix("/admin/releases/confirm?token=")
            .expect("confirm redirect");
        tokens.push(token.to_owned());
    }

    {
        let mut conn = db.clone();
        let rows = Release::all().exec(&mut conn).await.expect("all");
        assert!(
            !rows.iter().any(|r| r.version.contains(&base_bad)),
            "invalid packages must never stage"
        );
        let staged: Vec<_> = rows
            .iter()
            .filter(|r| r.version.contains(&base_ok))
            .collect();
        assert_eq!(staged.len(), n);
        assert!(staged.iter().all(|r| r.status == "STAGING"));
    }

    for token in tokens {
        let resp = crate::common::post_form(
            router.as_ref(),
            "/admin/releases/confirm/cancel",
            Some(&cookie),
            &format!("token={token}"),
        )
        .await;
        assert!(status(&resp).is_redirection());
    }

    cleanup(&db).await;
}

/// Parallel All / LTS list reads under a mixed catalog must never leak the
/// wrong channel into a filtered page, and both responses keep the chip row
/// plus the fixed colgroup.
#[tokio::test]
async fn battle_parallel_channel_filter_under_list_reads() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let email = unique_email("battle-rel-chan");
    let slug = unique_slug("battle-rel-chan");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;

    {
        let mut conn = db.clone();
        for i in 0..6u32 {
            for channel in ["LTS", "Stable"] {
                let version = format!("v99.battle.chan.{channel}.{i}");
                let sort = vcp::release_pkg::version_sort_fields(&version);
                let _ = toasty::create!(Release {
                    version,
                    channel: channel.to_owned(),
                    released_on: "2026-08-01".to_owned(),
                    status: "PUBLISHED".to_owned(),
                    notes: "FIX: battle channel".to_owned(),
                    organization_id: RELEASE_GA_ORG_ID,
                    v_major: sort.v_major,
                    v_minor: sort.v_minor,
                    v_patch: sort.v_patch,
                    has_client_suffix: sort.has_client_suffix,
                    client_suffix: sort.client_suffix,
                })
                .exec(&mut conn)
                .await
                .expect("release");
            }
        }
    }

    let router = Arc::new(test_router().await);
    let cookie = login_cookie(router.as_ref(), &email).await.expect("cookie");
    let barrier = Arc::new(Barrier::new(2));

    let cookie_a = cookie.clone();
    let cookie_b = cookie;
    let router_a = router.clone();
    let router_b = router;
    let barrier_a = barrier.clone();
    let barrier_b = barrier;

    let h_all = tokio::spawn(async move {
        barrier_a.wait().await;
        let resp = get(router_a.as_ref(), "/admin/releases", Some(&cookie_a)).await;
        assert_eq!(status(&resp), StatusCode::OK);
        let body = resp.into_body().collect().await.expect("body").to_bytes();
        String::from_utf8_lossy(&body).into_owned()
    });
    let h_lts = tokio::spawn(async move {
        barrier_b.wait().await;
        let resp = get(
            router_b.as_ref(),
            "/admin/releases?channel=LTS",
            Some(&cookie_b),
        )
        .await;
        assert_eq!(status(&resp), StatusCode::OK);
        let body = resp.into_body().collect().await.expect("body").to_bytes();
        String::from_utf8_lossy(&body).into_owned()
    });

    let all_html = h_all.await.expect("join all");
    let lts_html = h_lts.await.expect("join lts");
    assert!(
        all_html.contains("vb-chip-row") && all_html.contains("vb-rel-head"),
        "all view chrome: {all_html}"
    );
    assert!(
        lts_html.contains("vb-chip-row") && lts_html.contains("vb-rel-head"),
        "lts view chrome: {lts_html}"
    );
    assert!(
        all_html.contains("v99.battle.chan.Stable.") && all_html.contains("v99.battle.chan.LTS."),
        "all must show both channels: {all_html}"
    );
    assert!(
        lts_html.contains("v99.battle.chan.LTS.") && !lts_html.contains("v99.battle.chan.Stable."),
        "LTS filter must hide Stable under contention: {lts_html}"
    );

    cleanup(&db).await;
}
