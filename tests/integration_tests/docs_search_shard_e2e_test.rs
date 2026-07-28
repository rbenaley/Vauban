//! E2E: docs search shard happy path + denial paths (tenant / auth / Casbin).

use http_body_util::BodyExt;
use topcoat::router::StatusCode;

use crate::common::{
    cleanup, create_membership, create_org_with_membership, create_published_doc, create_test_org,
    create_test_user, db_lock, docs_search_shard_body, get, login_cookie, post_json,
    shard_path_from_html, status, test_db, test_router, unique_email, unique_slug,
};

async fn body_text(resp: topcoat::router::Response) -> String {
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

struct ShardFixture {
    db: toasty::Db,
    router: topcoat::router::Router,
    cookie: String,
    slug: String,
    shard_path: String,
}

async fn member_docs_shard(email_prefix: &str, org_prefix: &str) -> ShardFixture {
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;
    let email = unique_email(email_prefix);
    let slug = unique_slug(org_prefix);
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;
    let cookie = login_cookie(&router, &email).await.expect("cookie");
    let page = get(&router, &format!("/{slug}/docs"), Some(&cookie)).await;
    assert_eq!(status(&page), StatusCode::OK);
    let html = body_text(page).await;
    let shard_path = shard_path_from_html(&html).expect("docs page embeds shard path");
    assert!(
        shard_path.starts_with("/_topcoat/shards/"),
        "unexpected shard path: {shard_path}"
    );
    ShardFixture {
        db,
        router,
        cookie,
        slug,
        shard_path,
    }
}

#[tokio::test]
async fn e2e_docs_page_renders_with_search() {
    let _guard = db_lock().lock().await;
    let fx = member_docs_shard("shard-e2e", "shard-org").await;

    let q = get(
        &fx.router,
        &format!("/{}/docs?q=start", fx.slug),
        Some(&fx.cookie),
    )
    .await;
    assert_eq!(status(&q), StatusCode::OK);

    let body = docs_search_shard_body(&fx.slug, "ssh", "");
    let shard = post_json(&fx.router, &fx.shard_path, Some(&fx.cookie), &body).await;
    assert_eq!(
        status(&shard),
        StatusCode::OK,
        "shard POST must succeed without org path param"
    );
    let shard_html = body_text(shard).await;
    assert!(
        shard_html.contains("data-docs-search-shard") || shard_html.contains("vb-list"),
        "{shard_html}"
    );

    cleanup(&fx.db).await;
}

#[tokio::test]
async fn e2e_docs_search_shard_returns_matching_published_articles() {
    let _guard = db_lock().lock().await;
    let fx = member_docs_shard("shard-match", "shard-match-org").await;

    let hit = unique_slug("shard-hit");
    let miss = unique_slug("shard-miss");
    create_published_doc(&fx.db, "Unique SSH Guide", "bastion keys", "Security", &hit).await;
    create_published_doc(&fx.db, "Billing FAQ", "invoices", "Operations", &miss).await;

    let body = docs_search_shard_body(&fx.slug, "ssh", "");
    let shard = post_json(&fx.router, &fx.shard_path, Some(&fx.cookie), &body).await;
    assert_eq!(status(&shard), StatusCode::OK);
    let html = body_text(shard).await;
    assert!(html.contains("Unique SSH Guide"), "{html}");
    assert!(html.contains(&format!("/{}/docs/{hit}", fx.slug)), "{html}");
    assert!(!html.contains("Billing FAQ"), "{html}");
    assert!(!html.contains(&miss), "{html}");

    cleanup(&fx.db).await;
}

#[tokio::test]
async fn e2e_docs_search_shard_rejects_empty_org_slug() {
    let _guard = db_lock().lock().await;
    let fx = member_docs_shard("shard-empty", "shard-empty-org").await;

    let body = docs_search_shard_body("   ", "ssh", "");
    let shard = post_json(&fx.router, &fx.shard_path, Some(&fx.cookie), &body).await;
    assert_eq!(status(&shard), StatusCode::NOT_FOUND);
    let html = body_text(shard).await;
    assert!(!html.contains("data-docs-search-shard"), "{html}");

    cleanup(&fx.db).await;
}

#[tokio::test]
async fn e2e_docs_search_shard_rejects_forged_org_slug() {
    let _guard = db_lock().lock().await;
    let fx = member_docs_shard("shard-forge", "shard-forge-org").await;

    let body = docs_search_shard_body(&unique_slug("no-such-org"), "ssh", "");
    let shard = post_json(&fx.router, &fx.shard_path, Some(&fx.cookie), &body).await;
    assert_eq!(status(&shard), StatusCode::NOT_FOUND);

    cleanup(&fx.db).await;
}

#[tokio::test]
async fn e2e_docs_search_shard_wrong_tenant_membership_is_404() {
    let _guard = db_lock().lock().await;
    let fx = member_docs_shard("shard-tenant", "shard-home-org").await;

    let foreign = create_test_org(&fx.db, &unique_slug("shard-foreign-org")).await;
    let hit = unique_slug("shard-foreign-doc");
    create_published_doc(&fx.db, "Foreign Only Doc", "secret", "API", &hit).await;

    let body = docs_search_shard_body(&foreign.slug, "foreign", "");
    let shard = post_json(&fx.router, &fx.shard_path, Some(&fx.cookie), &body).await;
    assert_eq!(status(&shard), StatusCode::NOT_FOUND);
    let html = body_text(shard).await;
    assert!(!html.contains("Foreign Only Doc"), "{html}");
    assert!(!html.contains(&hit), "{html}");

    cleanup(&fx.db).await;
}

#[tokio::test]
async fn e2e_docs_search_shard_anonymous_is_404() {
    let _guard = db_lock().lock().await;
    let fx = member_docs_shard("shard-anon", "shard-anon-org").await;

    let body = docs_search_shard_body(&fx.slug, "ssh", "");
    let shard = post_json(&fx.router, &fx.shard_path, None, &body).await;
    assert_eq!(status(&shard), StatusCode::NOT_FOUND);

    cleanup(&fx.db).await;
}

#[tokio::test]
async fn e2e_docs_search_shard_missing_docs_read_is_404() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    // Unknown membership role: require_org succeeds, Casbin docs_read fails closed.
    let email = unique_email("shard-nodocs");
    let slug = unique_slug("shard-nodocs-org");
    let user = create_test_user(&db, &email, "password").await;
    let org = create_test_org(&db, &slug).await;
    create_membership(&db, user.id, org.id, "no_docs").await;

    let cookie = login_cookie(&router, &email).await.expect("cookie");
    // Page itself is also forbidden; borrow a shard path from a normal member session.
    let helper_email = unique_email("shard-path-helper");
    let helper_slug = unique_slug("shard-path-helper-org");
    let (_hu, _ho) =
        create_org_with_membership(&db, &helper_email, "password", &helper_slug, "member").await;
    let helper_cookie = login_cookie(&router, &helper_email)
        .await
        .expect("helper cookie");
    let page = get(
        &router,
        &format!("/{helper_slug}/docs"),
        Some(&helper_cookie),
    )
    .await;
    assert_eq!(status(&page), StatusCode::OK);
    let shard_path = shard_path_from_html(&body_text(page).await).expect("shard path");

    let body = docs_search_shard_body(&slug, "ssh", "");
    let shard = post_json(&router, &shard_path, Some(&cookie), &body).await;
    assert_eq!(status(&shard), StatusCode::NOT_FOUND);

    cleanup(&db).await;
}
