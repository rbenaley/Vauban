//! E2E: list pages with embedded shards still render after request-scoped dedup.

use http_body_util::BodyExt;
use topcoat::router::StatusCode;

use crate::common::{
    cleanup, create_org_with_membership, create_published_doc, db_lock, get, login_cookie, status,
    test_db, test_router, unique_email, unique_slug,
};

async fn body_text(resp: topcoat::router::Response) -> String {
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

#[tokio::test]
async fn e2e_docs_list_get_embeds_shard_and_pages() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;
    let email = unique_email("dedup-e2e-docs");
    let slug = unique_slug("dedup-e2e-docs");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;
    let art = unique_slug("dedup-art");
    create_published_doc(&db, "Dedup Doc", "summary", "API", &art).await;
    let cookie = login_cookie(&router, &email).await.expect("cookie");

    let page = get(&router, &format!("/{slug}/docs"), Some(&cookie)).await;
    assert_eq!(status(&page), StatusCode::OK);
    let html = body_text(page).await;
    assert!(
        html.contains("Dedup Doc") || html.contains("vb-list"),
        "{html}"
    );
    assert!(
        html.contains("/_topcoat/shards/"),
        "docs list GET must embed live search shard"
    );

    let paged = get(&router, &format!("/{slug}/docs?page=1"), Some(&cookie)).await;
    assert_eq!(status(&paged), StatusCode::OK);

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_admin_companies_list_get_embeds_shard() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;
    let email = unique_email("dedup-e2e-co");
    let slug = unique_slug("dedup-e2e-co");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let cookie = login_cookie(&router, &email).await.expect("cookie");

    let page = get(&router, "/admin/companies", Some(&cookie)).await;
    assert_eq!(status(&page), StatusCode::OK);
    let html = body_text(page).await;
    assert!(
        html.contains("/_topcoat/shards/") || html.contains("data-admin-companies-search-shard"),
        "companies list GET must embed search shard: {html}"
    );

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_admin_issues_list_get_embeds_shard() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;
    let email = unique_email("dedup-e2e-iss");
    let slug = unique_slug("dedup-e2e-iss");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let cookie = login_cookie(&router, &email).await.expect("cookie");

    let page = get(&router, "/admin/issues", Some(&cookie)).await;
    assert_eq!(status(&page), StatusCode::OK);
    let html = body_text(page).await;
    assert!(
        html.contains("/_topcoat/shards/") || html.contains("data-admin-issues-search-shard"),
        "admin issues list GET must embed search shard"
    );

    cleanup(&db).await;
}
