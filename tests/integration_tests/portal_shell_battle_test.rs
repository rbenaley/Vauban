//! Contention: parallel GETs of login + org shell chrome.

use std::sync::Arc;

use http_body_util::BodyExt;
use tokio::sync::Barrier;
use topcoat::router::StatusCode;
use vcp::models::{RELEASE_GA_ORG_ID, Release};

use crate::common::{
    cleanup, cookie_header, create_org_with_membership, db_lock, get, post_form, status, test_db,
    test_router, unique_email, unique_slug,
};

fn urlencoding_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[tokio::test]
async fn battle_parallel_login_and_shell_reads() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = Arc::new(test_router().await);

    let email = unique_email("shell-battle");
    let slug = unique_slug("shell-battle");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let version = unique_slug("shell-battle-rel");
    {
        let mut conn = db.clone();
        let _ = toasty::create!(Release {
            version: version.clone(),
            channel: "LTS".to_owned(),
            released_on: "2026-07-15".to_owned(),
            size_mb: "2.0".to_owned(),
            sha256: "abc".to_owned(),
            status: "PUBLISHED".to_owned(),
            notes: "FIX: battle polish".to_owned(),
            organization_id: RELEASE_GA_ORG_ID,
        })
        .exec(&mut conn)
        .await
        .expect("release");
    }

    let form = format!("email={}&password=password", urlencoding_encode(&email));
    let login = post_form(router.as_ref(), "/login", None, &form).await;
    let cookie = cookie_header(&login).expect("session cookie");

    let n = 10usize;
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::with_capacity(n);

    for i in 0..n {
        let router = router.clone();
        let barrier = barrier.clone();
        let cookie = cookie.clone();
        let slug = slug.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            match i % 3 {
                0 => {
                    let resp = get(router.as_ref(), "/login", None).await;
                    assert_eq!(status(&resp), StatusCode::OK);
                    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
                    let html = String::from_utf8_lossy(&bytes);
                    assert!(html.contains("vb-login-body"), "{html}");
                }
                1 => {
                    let resp = get(router.as_ref(), &format!("/{slug}"), Some(&cookie)).await;
                    assert_eq!(status(&resp), StatusCode::OK);
                    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
                    let html = String::from_utf8_lossy(&bytes);
                    assert!(html.contains("vb-shell"), "{html}");
                    assert!(html.contains("vb-screen"), "{html}");
                }
                _ => {
                    let resp =
                        get(router.as_ref(), &format!("/{slug}/builds"), Some(&cookie)).await;
                    assert_eq!(status(&resp), StatusCode::OK);
                    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
                    let html = String::from_utf8_lossy(&bytes);
                    assert!(html.contains("vb-screen"), "{html}");
                    assert!(html.contains("vb-btn"), "{html}");
                }
            }
        }));
    }

    for h in handles {
        h.await.expect("join");
    }

    cleanup(&db).await;
}
