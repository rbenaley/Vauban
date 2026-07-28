//! E2E: admin issues search shard happy path + denial paths.

use http_body_util::BodyExt;
use topcoat::router::StatusCode;

use crate::common::{
    admin_issues_search_shard_body, cleanup, create_org_with_membership, create_test_issue,
    create_test_org, create_test_user, db_lock, get, login_cookie, post_json, shard_path_from_html,
    status, test_db, test_router, unique_email, unique_slug,
};

async fn body_text(resp: topcoat::router::Response) -> String {
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

struct AdminShardFixture {
    db: toasty::Db,
    router: topcoat::router::Router,
    cookie: String,
    shard_path: String,
    staff_user_id: u64,
    home_org_id: u64,
    home_slug: String,
}

async fn staff_admin_issues_shard() -> AdminShardFixture {
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;
    let email = unique_email("adm-iss-staff");
    let slug = unique_slug("adm-iss-home");
    let (user, org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let cookie = login_cookie(&router, &email).await.expect("cookie");
    let page = get(&router, "/admin/issues", Some(&cookie)).await;
    assert_eq!(status(&page), StatusCode::OK);
    let shard_path = shard_path_from_html(&body_text(page).await).expect("shard path");
    assert!(shard_path.starts_with("/_topcoat/shards/"));
    AdminShardFixture {
        db,
        router,
        cookie,
        shard_path,
        staff_user_id: user.id,
        home_org_id: org.id,
        home_slug: slug,
    }
}

#[tokio::test]
async fn e2e_admin_issues_search_shard_matches_and_filters_org() {
    let _guard = db_lock().lock().await;
    let fx = staff_admin_issues_shard().await;

    let other = create_test_org(&fx.db, &unique_slug("adm-iss-other")).await;
    let other_user = create_test_user(&fx.db, &unique_email("adm-iss-other-u"), "password").await;

    let home_key = format!("VBN-{}", unique_slug("ahome").replace('-', ""));
    let other_key = format!("VBN-{}", unique_slug("aother").replace('-', ""));
    create_test_issue(
        &fx.db,
        fx.home_org_id,
        fx.staff_user_id,
        &home_key,
        "Home SSH Ticket",
        "Open",
    )
    .await;
    create_test_issue(
        &fx.db,
        other.id,
        other_user.id,
        &other_key,
        "Other SSH Ticket",
        "Open",
    )
    .await;

    let all = post_json(
        &fx.router,
        &fx.shard_path,
        Some(&fx.cookie),
        &admin_issues_search_shard_body("ssh", "", ""),
    )
    .await;
    assert_eq!(status(&all), StatusCode::OK);
    let all_html = body_text(all).await;
    assert!(all_html.contains("Home SSH Ticket"), "{all_html}");
    assert!(all_html.contains("Other SSH Ticket"), "{all_html}");

    let filtered = post_json(
        &fx.router,
        &fx.shard_path,
        Some(&fx.cookie),
        &admin_issues_search_shard_body("ssh", &fx.home_slug, ""),
    )
    .await;
    assert_eq!(status(&filtered), StatusCode::OK);
    let html = body_text(filtered).await;
    assert!(html.contains("Home SSH Ticket"), "{html}");
    assert!(!html.contains("Other SSH Ticket"), "{html}");
    assert!(
        html.contains(&format!("/admin/issues/{home_key}")),
        "{html}"
    );

    cleanup(&fx.db).await;
}

#[tokio::test]
async fn e2e_admin_issues_search_shard_anonymous_is_404() {
    let _guard = db_lock().lock().await;
    let fx = staff_admin_issues_shard().await;

    let shard = post_json(
        &fx.router,
        &fx.shard_path,
        None,
        &admin_issues_search_shard_body("ssh", "", ""),
    )
    .await;
    assert_eq!(status(&shard), StatusCode::NOT_FOUND);

    cleanup(&fx.db).await;
}

#[tokio::test]
async fn e2e_admin_issues_search_shard_member_is_404() {
    let _guard = db_lock().lock().await;
    let fx = staff_admin_issues_shard().await;

    let member_email = unique_email("adm-iss-member");
    let member_slug = unique_slug("adm-iss-member");
    let (_mu, _mo) =
        create_org_with_membership(&fx.db, &member_email, "password", &member_slug, "member").await;
    let member_cookie = login_cookie(&fx.router, &member_email)
        .await
        .expect("member cookie");

    let shard = post_json(
        &fx.router,
        &fx.shard_path,
        Some(&member_cookie),
        &admin_issues_search_shard_body("ssh", "", ""),
    )
    .await;
    assert_eq!(status(&shard), StatusCode::NOT_FOUND);

    cleanup(&fx.db).await;
}
