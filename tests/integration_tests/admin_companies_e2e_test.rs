//! E2E: admin company create + seat helper + member 403.

use topcoat::router::StatusCode;
use vcp::models::MAX_USERS_PER_COMPANY;
use vcp::seats::{can_add_member, membership_count};

use crate::common::{
    cleanup, cookie_header, create_membership, create_org_with_membership, create_test_user,
    db_lock, get, post_form, status, test_db, test_router, unique_email, unique_slug,
    urlencoding_encode,
};

async fn login(router: &topcoat::router::Router, email: &str) -> Option<String> {
    let form = format!("email={}&password=password", urlencoding_encode(email));
    let login = post_form(router, "/login", None, &form).await;
    assert!(status(&login).is_redirection());
    cookie_header(&login)
}

#[tokio::test]
async fn e2e_admin_creates_company() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("co-admin");
    let slug = unique_slug("co-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let cookie = login(&router, &email).await;

    let name = format!("Test Co {}", unique_slug("name"));
    let form = format!(
        "name={}&contact=ops%40example.com&vat=FR123&address=1+Test",
        urlencoding_encode(&name)
    );
    let create = post_form(
        &router,
        &format!("/{slug}/admin/companies/new"),
        cookie.as_deref(),
        &form,
    )
    .await;
    assert!(
        status(&create).is_redirection(),
        "create should PRG, got {}",
        status(&create)
    );

    let list = get(
        &router,
        &format!("/{slug}/admin/companies"),
        cookie.as_deref(),
    )
    .await;
    assert_eq!(status(&list), StatusCode::OK);

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_seat_helper_respects_max_users() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let email = unique_email("co-seats");
    let slug = unique_slug("co-seats-org");
    let (_user, org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;

    {
        let mut conn = db.clone();
        assert!(can_add_member(&mut conn, org.id).await.unwrap());
    }

    // Fill to MAX_USERS_PER_COMPANY.
    let mut conn = db.clone();
    let mut count = membership_count(&mut conn, org.id).await.unwrap();
    while count < MAX_USERS_PER_COMPANY {
        let u = create_test_user(&db, &unique_email("fill"), "password").await;
        create_membership(&db, u.id, org.id, "member").await;
        count = membership_count(&mut conn, org.id).await.unwrap();
    }
    assert_eq!(count, MAX_USERS_PER_COMPANY);
    assert!(!can_add_member(&mut conn, org.id).await.unwrap());

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_member_denied_admin_companies() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("co-mem");
    let slug = unique_slug("co-mem-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;
    let cookie = login(&router, &email).await;

    let page = get(
        &router,
        &format!("/{slug}/admin/companies/new"),
        cookie.as_deref(),
    )
    .await;
    assert_eq!(status(&page), StatusCode::FORBIDDEN);

    let form = "name=Test+Denied&contact=&vat=&address=";
    let create = post_form(
        &router,
        &format!("/{slug}/admin/companies/new"),
        cookie.as_deref(),
        form,
    )
    .await;
    assert_eq!(status(&create), StatusCode::FORBIDDEN);

    cleanup(&db).await;
}
