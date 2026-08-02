//! Contention tests for parallel membership_count / can_add_member / email normalize.

use std::sync::Arc;
use std::thread;

use http_body_util::BodyExt;
use tokio::sync::Barrier;
use topcoat::router::StatusCode;
use vcp::companies_accounts::{
    apply_lts_compose_action, clamp_lts_count, normalize_contact_email, normalize_emails,
};
use vcp::seats::{can_add_member, membership_count};

use crate::common::{
    cleanup, cookie_header, create_membership, create_org_with_membership, create_test_org,
    create_test_user, db_lock, get, post_form, status, test_db, test_router, unique_email,
    unique_slug, urlencoding_encode,
};

#[tokio::test]
async fn battle_parallel_seat_helper_reads() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let email = unique_email("battle-co");
    let slug = unique_slug("battle-co-org");
    let (_user, org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;

    // Fill to 3 seats (1 already from create_org_with_membership).
    for i in 0..2 {
        let u = create_test_user(&db, &unique_email(&format!("battle-seat-{i}")), "password").await;
        create_membership(&db, u.id, org.id, "member").await;
    }

    let n = 10usize;
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::with_capacity(n);
    let url = crate::common::database_url();
    let org_id = org.id;

    for _ in 0..n {
        let url = url.clone();
        let barrier = barrier.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let db = vcp::db::connect(&url).await.expect("connect");
            let mut conn = db.clone();
            let count = membership_count(&mut conn, org_id).await.expect("count");
            assert_eq!(count, 3);
            let can = can_add_member(&mut conn, org_id, 5).await.expect("can");
            assert!(can);
        }));
    }

    for h in handles {
        h.await.expect("join");
    }

    cleanup(&db).await;
}

#[test]
fn battle_parallel_normalize_emails_mixed_corpus() {
    let valid = [
        "a@example.com".to_owned(),
        "B@X.TEST".to_owned(),
        "".to_owned(),
    ];
    let invalid = ["not-an-email".to_owned(), "a@".to_owned()];
    let n = 8usize;
    let mut handles = Vec::with_capacity(n);
    for i in 0..n {
        let valid = valid.clone();
        let invalid = invalid.clone();
        handles.push(thread::spawn(move || {
            if i % 2 == 0 {
                let out = normalize_emails(&valid).expect("valid corpus");
                assert_eq!(out.len(), 2);
                assert_eq!(out[0], "a@example.com");
                assert_eq!(out[1], "b@x.test");
            } else {
                let err = normalize_emails(&invalid).expect_err("invalid corpus");
                assert!(err.contains("Invalid email address"));
            }
        }));
    }
    for h in handles {
        h.join().expect("join");
    }
}

#[test]
fn battle_parallel_normalize_contact_email_mixed_corpus() {
    let n = 8usize;
    let mut handles = Vec::with_capacity(n);
    for i in 0..n {
        handles.push(thread::spawn(move || {
            if i % 2 == 0 {
                assert_eq!(
                    normalize_contact_email("  Ops@Example.COM ").expect("valid"),
                    "ops@example.com"
                );
                assert_eq!(normalize_contact_email("").expect("empty"), "");
            } else {
                let err = normalize_contact_email("not-an-email").expect_err("invalid");
                assert!(err.contains("Invalid email address"));
            }
        }));
    }
    for h in handles {
        h.join().expect("join");
    }
}

#[tokio::test]
async fn battle_parallel_admin_companies_page_pagination() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let email = unique_email("battle-co-page");
    let slug = unique_slug("battle-co-page");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;

    let marker = unique_slug("bacopage");
    for i in 0..4u32 {
        let org_slug = unique_slug(&format!("{marker}-{i}"));
        create_test_org(&db, &org_slug).await;
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
    let marker_a = marker.clone();
    let marker_b = marker;

    let path1 = format!("/admin/companies?q={marker_a}&page=1");
    let path2 = format!("/admin/companies?q={marker_b}&page=2");
    let h1 = tokio::spawn(async move {
        barrier_a.wait().await;
        let resp = get(router_a.as_ref(), &path1, Some(&cookie_a)).await;
        assert_eq!(status(&resp), StatusCode::OK);
        let body = resp.into_body().collect().await.expect("body").to_bytes();
        let html = String::from_utf8_lossy(&body).into_owned();
        assert!(html.contains(&marker_a), "page1 marker: {html}");
        html
    });
    let h2 = tokio::spawn(async move {
        barrier_b.wait().await;
        let resp = get(router_b.as_ref(), &path2, Some(&cookie_b)).await;
        assert_eq!(status(&resp), StatusCode::OK);
        let body = resp.into_body().collect().await.expect("body").to_bytes();
        let html = String::from_utf8_lossy(&body).into_owned();
        assert!(html.contains(&marker_b), "page2 marker: {html}");
        html
    });

    let page1 = h1.await.expect("join page1");
    let page2 = h2.await.expect("join page2");
    assert!(page1.contains("vb-pager"), "page1 pager: {page1}");
    assert!(
        page1.contains("vb-list-toolbar"),
        "toolbar under contention: {page1}"
    );
    assert!(
        (1..=3).contains(&page2.matches("class=\"vb-company-card\"").count()),
        "page2 cards under contention: {page2}"
    );

    cleanup(&db).await;
}

#[test]
fn battle_parallel_lts_clamp_and_steppers() {
    let n = 8usize;
    let mut handles = Vec::with_capacity(n);
    for i in 0..n {
        handles.push(thread::spawn(move || {
            let max = 99usize;
            let base = (i as i32) * 10;
            let clamped = clamp_lts_count(base, max);
            assert!((0..=99).contains(&clamped));
            let (lts, ind) = apply_lts_compose_action(clamped, 0, "lts_inc", max).expect("step");
            assert!((0..=99).contains(&lts));
            assert_eq!(ind, 0);
        }));
    }
    for h in handles {
        h.join().expect("join");
    }
}

#[tokio::test]
async fn battle_parallel_company_create_with_lts_counters() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let email = unique_email("battle-lts-create");
    let slug = unique_slug("battle-lts-create");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let router = test_router().await;
    let form = format!("email={}&password=password", urlencoding_encode(&email));
    let login = post_form(&router, "/login", None, &form).await;
    let cookie = cookie_header(&login).expect("cookie");

    let n = 4usize;
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::with_capacity(n);
    for i in 0..n {
        let cookie = cookie.clone();
        let barrier = barrier.clone();
        let router = test_router().await;
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let name = format!("Battle LTS {i} {}", unique_slug("blts"));
            let member = unique_email(&format!("blts-m-{i}"));
            let body = format!(
                "name={}&contact_name=Ops&contact_email=ops%40example.com&vat=FR1&address=1+St&lts_subscriptions=2&industrial_lts_subscriptions=1&account_rows=1&compose_action=save&email_0={}",
                urlencoding_encode(&name),
                urlencoding_encode(&member)
            );
            let resp = post_form(&router, "/admin/companies/new", Some(&cookie), &body).await;
            assert_eq!(status(&resp), StatusCode::SEE_OTHER);
        }));
    }
    for h in handles {
        h.await.expect("join");
    }

    cleanup(&db).await;
}
