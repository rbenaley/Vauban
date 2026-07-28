//! E2E: org issues search shard happy path + denial paths.

use http_body_util::BodyExt;
use topcoat::router::StatusCode;

use crate::common::{
    cleanup, create_membership, create_org_with_membership, create_test_issue, create_test_org,
    create_test_user, db_lock, get, login_cookie, org_issues_search_shard_body, post_json,
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
    user_id: u64,
    org_id: u64,
}

async fn member_issues_shard(email_prefix: &str, org_prefix: &str) -> ShardFixture {
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;
    let email = unique_email(email_prefix);
    let slug = unique_slug(org_prefix);
    let (user, org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;
    let cookie = login_cookie(&router, &email).await.expect("cookie");
    let page = get(&router, &format!("/{slug}/issues"), Some(&cookie)).await;
    assert_eq!(status(&page), StatusCode::OK);
    let shard_path = shard_path_from_html(&body_text(page).await).expect("shard path");
    assert!(shard_path.starts_with("/_topcoat/shards/"));
    ShardFixture {
        db,
        router,
        cookie,
        slug,
        shard_path,
        user_id: user.id,
        org_id: org.id,
    }
}

#[tokio::test]
async fn e2e_org_issues_search_shard_returns_matching_issues() {
    let _guard = db_lock().lock().await;
    let fx = member_issues_shard("org-iss-match", "org-iss-match").await;

    let hit = format!("VBN-{}", unique_slug("hit").replace('-', ""));
    let miss = format!("VBN-{}", unique_slug("miss").replace('-', ""));
    create_test_issue(
        &fx.db,
        fx.org_id,
        fx.user_id,
        &hit,
        "Unique SSH Guide Issue",
        "Open",
    )
    .await;
    create_test_issue(
        &fx.db,
        fx.org_id,
        fx.user_id,
        &miss,
        "Billing FAQ Issue",
        "Open",
    )
    .await;

    let body = org_issues_search_shard_body(&fx.slug, "ssh", "");
    let shard = post_json(&fx.router, &fx.shard_path, Some(&fx.cookie), &body).await;
    assert_eq!(status(&shard), StatusCode::OK);
    let html = body_text(shard).await;
    assert!(html.contains("Unique SSH Guide Issue"), "{html}");
    assert!(
        html.contains(&format!("/{}/issues/{hit}", fx.slug)),
        "{html}"
    );
    assert!(!html.contains("Billing FAQ Issue"), "{html}");
    assert!(!html.contains(&miss), "{html}");

    cleanup(&fx.db).await;
}

#[tokio::test]
async fn e2e_org_issues_search_shard_rejects_empty_org_slug() {
    let _guard = db_lock().lock().await;
    let fx = member_issues_shard("org-iss-empty", "org-iss-empty").await;

    let body = org_issues_search_shard_body("   ", "ssh", "");
    let shard = post_json(&fx.router, &fx.shard_path, Some(&fx.cookie), &body).await;
    assert_eq!(status(&shard), StatusCode::NOT_FOUND);

    cleanup(&fx.db).await;
}

#[tokio::test]
async fn e2e_org_issues_search_shard_rejects_forged_org_slug() {
    let _guard = db_lock().lock().await;
    let fx = member_issues_shard("org-iss-forge", "org-iss-forge").await;

    let body = org_issues_search_shard_body(&unique_slug("no-such-org"), "ssh", "");
    let shard = post_json(&fx.router, &fx.shard_path, Some(&fx.cookie), &body).await;
    assert_eq!(status(&shard), StatusCode::NOT_FOUND);

    cleanup(&fx.db).await;
}

#[tokio::test]
async fn e2e_org_issues_search_shard_wrong_tenant_membership_is_404() {
    let _guard = db_lock().lock().await;
    let fx = member_issues_shard("org-iss-tenant", "org-iss-home").await;

    let foreign = create_test_org(&fx.db, &unique_slug("org-iss-foreign")).await;
    let foreign_user =
        create_test_user(&fx.db, &unique_email("org-iss-foreign-u"), "password").await;
    let key = format!("VBN-{}", unique_slug("foreign").replace('-', ""));
    create_test_issue(
        &fx.db,
        foreign.id,
        foreign_user.id,
        &key,
        "Foreign Only Issue",
        "Open",
    )
    .await;

    let body = org_issues_search_shard_body(&foreign.slug, "foreign", "");
    let shard = post_json(&fx.router, &fx.shard_path, Some(&fx.cookie), &body).await;
    assert_eq!(status(&shard), StatusCode::NOT_FOUND);
    let html = body_text(shard).await;
    assert!(!html.contains("Foreign Only Issue"), "{html}");
    assert!(!html.contains(&key), "{html}");

    cleanup(&fx.db).await;
}

#[tokio::test]
async fn e2e_org_issues_search_shard_anonymous_is_404() {
    let _guard = db_lock().lock().await;
    let fx = member_issues_shard("org-iss-anon", "org-iss-anon").await;

    let body = org_issues_search_shard_body(&fx.slug, "ssh", "");
    let shard = post_json(&fx.router, &fx.shard_path, None, &body).await;
    assert_eq!(status(&shard), StatusCode::NOT_FOUND);

    cleanup(&fx.db).await;
}

#[tokio::test]
async fn e2e_org_issues_search_shard_missing_issues_read_is_404() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("org-iss-noread");
    let slug = unique_slug("org-iss-noread");
    let user = create_test_user(&db, &email, "password").await;
    let org = create_test_org(&db, &slug).await;
    create_membership(&db, user.id, org.id, "no_issues").await;

    let cookie = login_cookie(&router, &email).await.expect("cookie");

    let helper_email = unique_email("org-iss-path");
    let helper_slug = unique_slug("org-iss-path");
    let (_hu, _ho) =
        create_org_with_membership(&db, &helper_email, "password", &helper_slug, "member").await;
    let helper_cookie = login_cookie(&router, &helper_email)
        .await
        .expect("helper cookie");
    let page = get(
        &router,
        &format!("/{helper_slug}/issues"),
        Some(&helper_cookie),
    )
    .await;
    assert_eq!(status(&page), StatusCode::OK);
    let shard_path = shard_path_from_html(&body_text(page).await).expect("shard path");

    let body = org_issues_search_shard_body(&slug, "ssh", "");
    let shard = post_json(&router, &shard_path, Some(&cookie), &body).await;
    assert_eq!(status(&shard), StatusCode::NOT_FOUND);

    cleanup(&db).await;
}
