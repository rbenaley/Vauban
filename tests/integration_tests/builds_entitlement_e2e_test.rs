//! E2E: authorized download 501; wrong org 404; anonymous denied.

use http_body_util::BodyExt;
use topcoat::router::StatusCode;
use vcp::models::Release;

use crate::common::{
    cleanup, cookie_header, create_org_with_membership, create_test_org, db_lock, post_form,
    status, test_db, test_router, unique_email, unique_slug, urlencoding_encode,
};

async fn body_text(resp: topcoat::router::Response) -> String {
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

async fn login(router: &topcoat::router::Router, email: &str) -> Option<String> {
    let form = format!("email={}&password=password", urlencoding_encode(email));
    let login = post_form(router, "/login", None, &form).await;
    assert!(status(&login).is_redirection());
    cookie_header(&login)
}

#[tokio::test]
async fn e2e_authorized_download_returns_501() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("dl-ok");
    let slug = unique_slug("dl-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;
    let version = unique_slug("dlv");
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
        })
        .exec(&mut conn)
        .await
        .expect("release");
    }

    let cookie = login(&router, &email).await;
    let resp = post_form(
        &router,
        &format!("/{slug}/builds/{version}/download"),
        cookie.as_deref(),
        "",
    )
    .await;
    assert_eq!(status(&resp), StatusCode::NOT_IMPLEMENTED);
    let body = body_text(resp).await;
    assert!(body.contains("download not configured"), "{body}");

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_download_wrong_org_is_404() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("dl-wo");
    let slug = unique_slug("dl-home");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;
    let _other = create_test_org(&db, &unique_slug("dl-other")).await;
    let version = unique_slug("dlv2");
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
        })
        .exec(&mut conn)
        .await
        .expect("release");
    }

    let cookie = login(&router, &email).await;
    let resp = post_form(
        &router,
        &format!("/{}/builds/{version}/download", unique_slug("no-access")),
        cookie.as_deref(),
        "",
    )
    .await;
    assert_eq!(status(&resp), StatusCode::NOT_FOUND);

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_download_anonymous_denied() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let version = unique_slug("dl-anon");
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
        })
        .exec(&mut conn)
        .await
        .expect("release");
    }

    // No session cookie: require_org maps to 404 (anti-enumeration); also accept 401 / redirect.
    let resp = post_form(
        &router,
        &format!("/{}/builds/{version}/download", unique_slug("anon-org")),
        None,
        "",
    )
    .await;
    let st = status(&resp);
    assert!(
        st == StatusCode::NOT_FOUND
            || st == StatusCode::UNAUTHORIZED
            || st.is_redirection()
            || st == StatusCode::FORBIDDEN,
        "anonymous must not get 501, got {st}"
    );
    assert_ne!(st, StatusCode::NOT_IMPLEMENTED);

    cleanup(&db).await;
}
