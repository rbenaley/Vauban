//! E2E: admin companies search shard happy path + denial paths.

use http_body_util::BodyExt;
use topcoat::router::StatusCode;

use crate::common::{
    admin_companies_search_shard_body, cleanup, create_membership, create_org_with_membership,
    create_test_org, create_test_user, db_lock, get, is_topcoat_shard_path, login_cookie,
    post_json, shard_path_from_html, status, test_db, test_router, unique_email, unique_slug,
};

async fn body_text(resp: topcoat::router::response::Response) -> String {
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

struct AdminCompaniesShardFixture {
    db: toasty::Db,
    router: topcoat::router::Router,
    cookie: String,
    shard_path: String,
}

async fn staff_admin_companies_shard() -> AdminCompaniesShardFixture {
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;
    let email = unique_email("adm-co-staff");
    let slug = unique_slug("adm-co-home");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let cookie = login_cookie(&router, &email).await.expect("cookie");
    let page = get(&router, "/admin/companies", Some(&cookie)).await;
    assert_eq!(status(&page), StatusCode::OK);
    let shard_path = shard_path_from_html(&body_text(page).await).expect("shard path");
    assert!(is_topcoat_shard_path(&shard_path));
    AdminCompaniesShardFixture {
        db,
        router,
        cookie,
        shard_path,
    }
}

#[tokio::test]
async fn e2e_admin_companies_search_shard_matches_name_and_email() {
    let _guard = db_lock().lock().await;
    let fx = staff_admin_companies_shard().await;

    let marker = unique_slug("coshardsrch");
    let hit_slug = unique_slug(&format!("{marker}-hit"));
    let miss_slug = unique_slug("co-miss-other");
    let hit = create_test_org(&fx.db, &hit_slug).await;
    create_test_org(&fx.db, &miss_slug).await;

    let account = unique_email("co-shard-acct");
    let user = create_test_user(&fx.db, &account, "password").await;
    create_membership(&fx.db, user.id, hit.id, "org").await;

    let all = post_json(
        &fx.router,
        &fx.shard_path,
        Some(&fx.cookie),
        &admin_companies_search_shard_body(""),
    )
    .await;
    assert_eq!(status(&all), StatusCode::OK);
    let all_html = body_text(all).await;
    assert!(
        all_html.contains("data-admin-companies-search-shard"),
        "{all_html}"
    );
    // Empty q may only show leftover alphabetically-first cards on page 1.

    let by_name = post_json(
        &fx.router,
        &fx.shard_path,
        Some(&fx.cookie),
        &admin_companies_search_shard_body(&marker),
    )
    .await;
    assert_eq!(status(&by_name), StatusCode::OK);
    let name_html = body_text(by_name).await;
    assert!(name_html.contains(&marker), "{name_html}");
    assert!(!name_html.contains(&miss_slug), "{name_html}");
    // Lot F: stable per-card id so the 0.8 morph follows a reordered card.
    assert!(
        name_html.contains(&format!("id=\"company-{}\"", hit.id)),
        "company cards must carry a stable id: {name_html}"
    );

    let by_email = post_json(
        &fx.router,
        &fx.shard_path,
        Some(&fx.cookie),
        &admin_companies_search_shard_body(&account),
    )
    .await;
    assert_eq!(status(&by_email), StatusCode::OK);
    let email_html = body_text(by_email).await;
    assert!(email_html.contains(&account), "{email_html}");
    assert!(email_html.contains(&marker), "{email_html}");

    cleanup(&fx.db).await;
}

#[tokio::test]
async fn e2e_admin_companies_search_shard_anonymous_is_404() {
    let _guard = db_lock().lock().await;
    let fx = staff_admin_companies_shard().await;

    let shard = post_json(
        &fx.router,
        &fx.shard_path,
        None,
        &admin_companies_search_shard_body("acme"),
    )
    .await;
    assert_eq!(status(&shard), StatusCode::NOT_FOUND);

    cleanup(&fx.db).await;
}

#[tokio::test]
async fn e2e_admin_companies_search_shard_member_is_404() {
    let _guard = db_lock().lock().await;
    let fx = staff_admin_companies_shard().await;

    let marker = unique_slug("co-deny-secret");
    create_test_org(&fx.db, &unique_slug(&format!("{marker}-org"))).await;

    let member_email = unique_email("adm-co-member");
    let member_slug = unique_slug("adm-co-member");
    let (_mu, _mo) =
        create_org_with_membership(&fx.db, &member_email, "password", &member_slug, "member").await;
    let member_cookie = login_cookie(&fx.router, &member_email)
        .await
        .expect("member cookie");

    let shard = post_json(
        &fx.router,
        &fx.shard_path,
        Some(&member_cookie),
        &admin_companies_search_shard_body(&marker),
    )
    .await;
    assert_eq!(status(&shard), StatusCode::NOT_FOUND);
    let deny = body_text(shard).await;
    assert!(
        !deny.contains(&marker),
        "denial must not leak company marker: {deny}"
    );

    cleanup(&fx.db).await;
}
