//! E2E: authorized download 501; wrong org 404; anonymous denied; GA vs private.

use http_body_util::BodyExt;
use topcoat::router::StatusCode;
use vcp::models::{RELEASE_GA_ORG_ID, Release};

use crate::common::{
    cleanup, cookie_header, create_org_with_membership, create_test_org, db_lock, get, post_form,
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
            organization_id: RELEASE_GA_ORG_ID,
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
            organization_id: RELEASE_GA_ORG_ID,
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
            organization_id: RELEASE_GA_ORG_ID,
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

#[tokio::test]
async fn e2e_org_private_release_hidden_from_other_org() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email_a = unique_email("priv-a");
    let slug_a = unique_slug("priv-a");
    let (_user_a, org_a) =
        create_org_with_membership(&db, &email_a, "password", &slug_a, "org").await;

    let email_b = unique_email("priv-b");
    let slug_b = unique_slug("priv-b");
    let (_user_b, _org_b) =
        create_org_with_membership(&db, &email_b, "password", &slug_b, "org").await;

    let private_ver = unique_slug("priv-rel");
    let ga_ver = unique_slug("ga-rel");
    {
        let mut conn = db.clone();
        let _ = toasty::create!(Release {
            version: private_ver.clone(),
            channel: "LTS".to_owned(),
            released_on: "2026-07-01".to_owned(),
            size_mb: "1.0".to_owned(),
            signature_prefix: "abc".to_owned(),
            status: "PUBLISHED".to_owned(),
            notes: "HOTFIX: private".to_owned(),
            organization_id: org_a.id,
        })
        .exec(&mut conn)
        .await
        .expect("private release");
        let _ = toasty::create!(Release {
            version: ga_ver.clone(),
            channel: "LTS".to_owned(),
            released_on: "2026-07-02".to_owned(),
            size_mb: "1.0".to_owned(),
            signature_prefix: "def".to_owned(),
            status: "PUBLISHED".to_owned(),
            notes: "GA".to_owned(),
            organization_id: RELEASE_GA_ORG_ID,
        })
        .exec(&mut conn)
        .await
        .expect("ga release");
    }

    let cookie_a = login(&router, &email_a).await;
    let list_a = get(&router, &format!("/{slug_a}/builds"), cookie_a.as_deref()).await;
    assert!(status(&list_a).is_success());
    let body_a = body_text(list_a).await;
    assert!(
        body_a.contains(&private_ver),
        "owner must see private build"
    );
    assert!(body_a.contains(&ga_ver), "owner must see GA build");

    let cookie_b = login(&router, &email_b).await;
    let list_b = get(&router, &format!("/{slug_b}/builds"), cookie_b.as_deref()).await;
    assert!(status(&list_b).is_success());
    let body_b = body_text(list_b).await;
    assert!(
        !body_b.contains(&private_ver),
        "other org must not see private build"
    );
    assert!(body_b.contains(&ga_ver), "other org must see GA build");

    let detail_b = get(
        &router,
        &format!("/{slug_b}/builds/{private_ver}"),
        cookie_b.as_deref(),
    )
    .await;
    assert_eq!(status(&detail_b), StatusCode::NOT_FOUND);

    let dl_b = post_form(
        &router,
        &format!("/{slug_b}/builds/{private_ver}/download"),
        cookie_b.as_deref(),
        "",
    )
    .await;
    assert_eq!(status(&dl_b), StatusCode::NOT_FOUND);

    cleanup(&db).await;
}
