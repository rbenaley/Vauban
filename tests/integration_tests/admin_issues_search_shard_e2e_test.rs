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
        html.contains(&format!("/admin/issues/{home_key}?org={}", fx.home_slug)),
        "list row must disambiguate with ?org=; html={html}"
    );

    cleanup(&fx.db).await;
}

/// Same public key in two orgs: list hrefs + detail with ?org= open the right ticket.
#[tokio::test]
async fn e2e_admin_issues_same_key_list_opens_correct_org() {
    let _guard = db_lock().lock().await;
    let fx = staff_admin_issues_shard().await;

    let other = create_test_org(&fx.db, &unique_slug("adm-dup-org")).await;
    let other_user = create_test_user(&fx.db, &unique_email("adm-dup-u"), "password").await;
    let shared_key = "VBN-200";
    create_test_issue(
        &fx.db,
        fx.home_org_id,
        fx.staff_user_id,
        shared_key,
        "Home Dup Title",
        "Open",
    )
    .await;
    create_test_issue(
        &fx.db,
        other.id,
        other_user.id,
        shared_key,
        "Other Dup Title",
        "Open",
    )
    .await;

    let list = post_json(
        &fx.router,
        &fx.shard_path,
        Some(&fx.cookie),
        &admin_issues_search_shard_body("Dup Title", "", ""),
    )
    .await;
    assert_eq!(status(&list), StatusCode::OK);
    let list_html = body_text(list).await;
    assert!(
        list_html.contains(&format!("/admin/issues/{shared_key}?org={}", fx.home_slug)),
        "home row href missing; {list_html}"
    );
    assert!(
        list_html.contains(&format!("/admin/issues/{shared_key}?org={}", other.slug)),
        "other row href missing; {list_html}"
    );

    let home_detail = get(
        &fx.router,
        &format!("/admin/issues/{shared_key}?org={}", fx.home_slug),
        Some(&fx.cookie),
    )
    .await;
    assert_eq!(status(&home_detail), StatusCode::OK);
    let home_html = body_text(home_detail).await;
    assert!(home_html.contains("Home Dup Title"), "{home_html}");
    assert!(!home_html.contains("Other Dup Title"), "{home_html}");

    let other_detail = get(
        &fx.router,
        &format!("/admin/issues/{shared_key}?org={}", other.slug),
        Some(&fx.cookie),
    )
    .await;
    assert_eq!(status(&other_detail), StatusCode::OK);
    let other_html = body_text(other_detail).await;
    assert!(other_html.contains("Other Dup Title"), "{other_html}");
    assert!(!other_html.contains("Home Dup Title"), "{other_html}");

    let ambiguous = get(
        &fx.router,
        &format!("/admin/issues/{shared_key}"),
        Some(&fx.cookie),
    )
    .await;
    assert_eq!(
        status(&ambiguous),
        StatusCode::NOT_FOUND,
        "ambiguous key without ?org= must 404"
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

#[tokio::test]
async fn e2e_admin_issues_list_pagination() {
    let _guard = db_lock().lock().await;
    let fx = staff_admin_issues_shard().await;

    let marker = unique_slug("adm-iss-page");
    for i in 0..11u32 {
        let key = format!("TEST-{}", unique_slug(&format!("aip{i}")).replace('-', ""));
        create_test_issue(
            &fx.db,
            fx.home_org_id,
            fx.staff_user_id,
            &key,
            &format!("{marker} ticket {i}"),
            "Open",
        )
        .await;
    }

    let page1 = get(
        &fx.router,
        &format!("/admin/issues?q={marker}&page=1"),
        Some(&fx.cookie),
    )
    .await;
    assert_eq!(status(&page1), StatusCode::OK);
    let p1 = body_text(page1).await;
    let rows_p1 = p1.matches("vb-row").count();
    assert_eq!(rows_p1, 10, "page 1 must show 10 rows: {p1}");
    assert!(p1.contains("vb-pager"), "pager when >10: {p1}");
    assert!(
        p1.contains(&format!("/admin/issues?q={marker}&page=2"))
            || p1.contains(&format!("q={marker}&amp;page=2")),
        "next page link: {p1}"
    );

    let page2 = get(
        &fx.router,
        &format!("/admin/issues?q={marker}&page=2"),
        Some(&fx.cookie),
    )
    .await;
    assert_eq!(status(&page2), StatusCode::OK);
    let p2 = body_text(page2).await;
    let rows_p2 = p2.matches("vb-row").count();
    assert_eq!(rows_p2, 1, "page 2 remainder: {rows_p2} in {p2}");
    assert!(p2.contains(&marker), "page 2 keeps marker: {p2}");

    assert!(
        p2.contains(&format!("href=\"/admin/issues?q={marker}&status=Open\""))
            || p2.contains(&format!("/admin/issues?q={marker}&amp;status=Open\""))
            || p2.contains("status=Open\""),
        "Open chip must omit page: {p2}"
    );
    assert!(
        !p2.contains("status=Open&page=") && !p2.contains("status=Open&amp;page="),
        "status chips must not sticky page=: {p2}"
    );

    cleanup(&fx.db).await;
}
