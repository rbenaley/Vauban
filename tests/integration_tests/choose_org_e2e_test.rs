//! E2E: multi-org picker after magic-link / session entry.

use http_body_util::BodyExt;
use topcoat::router::StatusCode;
use vcp::magic_link::issue_token;
use vcp::models::MEMBERSHIP_ROLE_ORG;

use crate::common::{
    cleanup, cookie_header, create_membership, create_org_with_membership, create_test_org,
    db_lock, get, login_cookie, status, test_db, test_router, unique_email, unique_slug,
};

async fn body_text(resp: topcoat::router::response::Response) -> String {
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

fn location(resp: &topcoat::router::response::Response) -> Option<&str> {
    resp.headers().get("location").and_then(|v| v.to_str().ok())
}

#[tokio::test]
async fn e2e_dual_membership_magic_lands_on_choose_org() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("choose-dual");
    let slug_a = unique_slug("choose-a");
    let slug_b = unique_slug("choose-b");
    // Ensure stable slug order for assertions (sorted ascending in picker).
    let (slug_lo, slug_hi) = if slug_a < slug_b {
        (slug_a, slug_b)
    } else {
        (slug_b, slug_a)
    };

    let (user, org_lo) =
        create_org_with_membership(&db, &email, "password", &slug_lo, "member").await;
    let org_hi = create_test_org(&db, &slug_hi).await;
    create_membership(&db, user.id, org_hi.id, MEMBERSHIP_ROLE_ORG).await;

    let mut conn = db.clone();
    let raw = issue_token(&mut conn, user.id, 300).await.expect("issue");
    let consume = get(&router, &format!("/login/magic?token={raw}"), None).await;
    assert_eq!(location(&consume), Some("/choose-org"));
    let cookie = cookie_header(&consume).expect("session cookie");

    let picker = get(&router, "/choose-org", Some(&cookie)).await;
    assert_eq!(status(&picker), StatusCode::OK);
    let html = body_text(picker).await;
    assert!(
        html.contains("<!DOCTYPE html>") && html.contains("stylesheet"),
        "choose-org #[route] must wrap root_layout (CSS/fonts)"
    );
    assert!(
        html.contains("vb-login-body") && html.contains("vb-login-panel"),
        "choose-org must use the VCP login splash chrome"
    );
    assert!(html.contains("VAUBAN"));
    assert!(html.contains("Choose an organization"));
    assert!(html.contains("vb-login-org-link"));
    assert!(html.contains(&slug_lo));
    assert!(html.contains(&slug_hi));
    assert!(html.contains(&org_lo.name) || html.contains("Org "));
    assert!(html.contains(&format!("/{slug_lo}")));
    assert!(html.contains(&format!("/{slug_hi}")));

    let open_a = get(&router, &format!("/{slug_lo}"), Some(&cookie)).await;
    assert_eq!(status(&open_a), StatusCode::OK);
    let foreign = unique_slug("choose-x");
    let _ = create_test_org(&db, &foreign).await;
    let denied = get(&router, &format!("/{foreign}"), Some(&cookie)).await;
    assert_eq!(status(&denied), StatusCode::NOT_FOUND);

    let root = get(&router, "/", Some(&cookie)).await;
    assert_eq!(status(&root), StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(location(&root), Some("/choose-org"));

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_single_org_skips_choose_org() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("choose-one");
    let slug = unique_slug("choose-one");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;
    let cookie = login_cookie(&router, &email).await.expect("cookie");

    let picker = get(&router, "/choose-org", Some(&cookie)).await;
    assert_eq!(status(&picker), StatusCode::TEMPORARY_REDIRECT);
    let expected = format!("/{slug}");
    assert_eq!(location(&picker), Some(expected.as_str()));

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_anonymous_choose_org_redirects_to_login() {
    let _guard = db_lock().lock().await;
    let router = test_router().await;
    let resp = get(&router, "/choose-org", None).await;
    assert_eq!(status(&resp), StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(location(&resp), Some("/login"));
}

#[tokio::test]
async fn e2e_staff_choose_org_redirects_to_vauban() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("choose-staff");
    let slug = unique_slug("choose-staff-client");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let cookie = login_cookie(&router, &email).await.expect("cookie");

    let picker = get(&router, "/choose-org", Some(&cookie)).await;
    assert_eq!(status(&picker), StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(location(&picker), Some("/vauban"));

    cleanup(&db).await;
}
