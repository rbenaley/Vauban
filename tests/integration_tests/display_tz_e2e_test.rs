//! E2E: vcp_tz cookie changes visible admin docs timestamps.

use chrono::{TimeZone, Utc};
use http_body_util::BodyExt;
use topcoat::router::StatusCode;
use vcp::models::DocArticle;

use crate::common::{
    cleanup, create_org_with_membership, db_lock, get, login_cookie, status, test_db, test_router,
    unique_email, unique_slug,
};

async fn body_text(resp: topcoat::router::response::Response) -> String {
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

#[tokio::test]
async fn e2e_vcp_tz_cookie_changes_admin_docs_time() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("tz-admin");
    let slug = unique_slug("tz-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;

    // Fixed instant: 2026-06-23 12:00:00 UTC → Paris CEST 14:00.
    let fixed = Utc
        .with_ymd_and_hms(2026, 6, 23, 12, 0, 0)
        .unwrap()
        .timestamp();
    let article_slug = unique_slug("tz-doc");
    let article_id = {
        let mut conn = db.clone();
        toasty::create!(DocArticle {
            title: "TZ Article".to_owned(),
            summary: "s".to_owned(),
            category: "API".to_owned(),
            slug: article_slug.clone(),
            version: "v1".to_owned(),
            status: "DRAFT".to_owned(),
            body: "body".to_owned(),
            updated_at: fixed,
        })
        .exec(&mut conn)
        .await
        .expect("doc")
        .id
    };

    let session = login_cookie(&router, &email).await.expect("session cookie");

    let utc_cookie = format!("{session}; vcp_tz=UTC");
    let paris_cookie = format!("{session}; vcp_tz=Europe/Paris");

    let utc_page = get(
        &router,
        &format!("/admin/docs/{article_id}"),
        Some(&utc_cookie),
    )
    .await;
    assert_eq!(status(&utc_page), StatusCode::OK);
    let utc_html = body_text(utc_page).await;

    let paris_page = get(
        &router,
        &format!("/admin/docs/{article_id}"),
        Some(&paris_cookie),
    )
    .await;
    assert_eq!(status(&paris_page), StatusCode::OK);
    let paris_html = body_text(paris_page).await;

    assert!(
        utc_html.contains("12:00") || utc_html.contains("2026-06-23"),
        "UTC page should show noon UTC: {utc_html}"
    );
    assert!(
        paris_html.contains("14:00") || paris_html.contains("13:00"),
        "Paris page should show localized hour: {paris_html}"
    );
    // Visible strings should differ when both render the fixture row.
    assert_ne!(
        utc_html, paris_html,
        "timezone cookie must change rendered HTML"
    );

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_root_layout_serves_vcp_tz_script() {
    let router = test_router().await;
    let login_page = get(&router, "/login", None).await;
    assert_eq!(status(&login_page), StatusCode::OK);
    let html = body_text(login_page).await;
    assert!(
        html.contains("vcp_tz") || html.contains("vcp_tz.js"),
        "login HTML must reference vcp_tz script: {html}"
    );
}
