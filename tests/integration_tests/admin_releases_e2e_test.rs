//! E2E: admin release create + member 404.

use topcoat::router::StatusCode;
use vcp::models::Release;

use crate::common::{
    cleanup, cookie_header, create_org_with_membership, db_lock, get, post_form, status, test_db,
    test_router, unique_email, unique_slug, urlencoding_encode,
};

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
