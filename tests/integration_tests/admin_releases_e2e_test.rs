//! E2E: admin release create + member 404.

use http_body_util::BodyExt;
use topcoat::router::StatusCode;
use vcp::models::{RELEASE_GA_ORG_ID, Release};

use crate::common::{
    cleanup, cookie_header, create_org_with_membership, db_lock, get, post_form, status, test_db,
    test_router, unique_email, unique_slug, urlencoding_encode,
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
async fn e2e_admin_creates_release() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("rel-admin");
    let slug = unique_slug("rel-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let cookie = login(&router, &email).await;

    let version = unique_slug("v");
    let form = format!(
        "version={}&channel=LTS&date=2026-07-01&notes={}",
        urlencoding_encode(&version),
        urlencoding_encode("FIX: test release")
    );
    let create = post_form(&router, "/admin/releases/new", cookie.as_deref(), &form).await;
    assert!(
        status(&create).is_redirection(),
        "create should PRG, got {}",
        status(&create)
    );

    let list = get(&router, "/admin/releases", cookie.as_deref()).await;
    assert_eq!(status(&list), StatusCode::OK);

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_member_denied_admin_releases() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("rel-mem");
    let slug = unique_slug("rel-mem-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;
    let cookie = login(&router, &email).await;

    let page = get(&router, "/admin/releases/new", cookie.as_deref()).await;
    assert_eq!(status(&page), StatusCode::NOT_FOUND);

    let form = "version=test-1.0.0&channel=LTS&date=2026-07-01&notes=x";
    let create = post_form(&router, "/admin/releases/new", cookie.as_deref(), form).await;
    assert_eq!(status(&create), StatusCode::NOT_FOUND);

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_admin_creates_org_targeted_release() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("rel-target");
    let slug = unique_slug("rel-target-org");
    let (_user, org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let cookie = login(&router, &email).await;

    let version = unique_slug("v-priv");
    let form = format!(
        "version={}&channel=LTS&date=2026-07-01&notes={}&organization_id={}",
        urlencoding_encode(&version),
        urlencoding_encode("FIX: private hotfix"),
        org.id
    );
    let create = post_form(&router, "/admin/releases/new", cookie.as_deref(), &form).await;
    assert!(status(&create).is_redirection());

    {
        let mut conn = db.clone();
        let rows = Release::all().exec(&mut conn).await.expect("releases");
        let found = rows.iter().find(|r| r.version == version).expect("created");
        assert_eq!(found.organization_id, org.id);
    }

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_admin_releases_list_pagination() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("rel-page");
    let slug = unique_slug("rel-page-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let cookie = login(&router, &email).await;

    {
        let mut conn = db.clone();
        for i in 0..11u32 {
            let version = format!("v99.page.{i}");
            let _ = toasty::create!(Release {
                version,
                channel: "LTS".to_owned(),
                released_on: "2026-07-01".to_owned(),
                size_mb: "1.0".to_owned(),
                sha256: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                    .to_owned(),
                status: "PUBLISHED".to_owned(),
                notes: "FIX: admin pagination".to_owned(),
                organization_id: RELEASE_GA_ORG_ID,
            })
            .exec(&mut conn)
            .await
            .expect("release");
        }
    }

    let page1 = get(&router, "/admin/releases?page=1", cookie.as_deref()).await;
    assert_eq!(status(&page1), StatusCode::OK);
    let p1 = body_text(page1).await;
    // Channel badge marks each data row (thead has none).
    let rows_p1 = p1.matches("vb-badge soft").count();
    assert_eq!(rows_p1, 10, "page 1 must show 10 rows: {p1}");
    assert!(p1.contains("vb-pager"), "pager when >10: {p1}");
    assert!(
        p1.contains("vb-list-toolbar"),
        "toolbar pager (no chips): {p1}"
    );
    assert!(
        p1.contains("/admin/releases?page=2") || p1.contains("href=\"/admin/releases?page=2\""),
        "next page link: {p1}"
    );

    let page2 = get(&router, "/admin/releases?page=2", cookie.as_deref()).await;
    assert_eq!(status(&page2), StatusCode::OK);
    let p2 = body_text(page2).await;
    let rows_p2 = p2.matches("vb-badge soft").count();
    assert!(
        (1..=10).contains(&rows_p2),
        "page 2 row count: {rows_p2} in {p2}"
    );
    assert!(
        p2.contains("v99.page.") || p1.contains("v99.page."),
        "pagination fixtures appear across pages: p1={p1} p2={p2}"
    );

    cleanup(&db).await;
}
