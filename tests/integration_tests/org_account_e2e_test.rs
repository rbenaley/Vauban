//! E2E: /{org}/account shows company fiche fields; denials stay 404.

use http_body_util::BodyExt;
use topcoat::router::StatusCode;
use vcp::build_info::product_label;
use vcp::models::{MEMBERSHIP_ROLE_ORG, Organization, RESERVED_ORG_SLUG};

use crate::common::{
    cleanup, create_membership, create_org_with_membership, create_test_org, create_test_user,
    db_lock, get, login_cookie, status, test_db, test_router, unique_email, unique_slug,
};

async fn body_text(resp: topcoat::router::response::Response) -> String {
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

async fn patch_org_profile(db: &toasty::Db, org_id: u64) {
    let mut conn = db.clone();
    let mut org = Organization::all()
        .filter(Organization::fields().id().eq(org_id))
        .exec(&mut conn)
        .await
        .expect("orgs")
        .into_iter()
        .next()
        .expect("org");
    org.update()
        .address("42 Account Street".to_owned())
        .vat("FR424242424".to_owned())
        .lts_subscriptions(3)
        .industrial_lts_subscriptions(2)
        .technical_contact_name("Account Ops".to_owned())
        .technical_contact_email("ops@account.test".to_owned())
        .exec(&mut conn)
        .await
        .expect("update org");
}

#[tokio::test]
async fn e2e_org_account_shows_company_fiche_fields() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("acct-e2e");
    let slug = unique_slug("acct-e2e");
    let (_user, org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;
    patch_org_profile(&db, org.id).await;

    let cookie = login_cookie(&router, &email).await.expect("cookie");
    let page = get(&router, &format!("/{slug}/account"), Some(&cookie)).await;
    assert_eq!(status(&page), StatusCode::OK);
    let html = body_text(page).await;

    assert!(html.contains("42 Account Street"), "{html}");
    assert!(
        !html.contains("data-vcp-build"),
        "client account must not swap Address for the portal build: {html}"
    );
    assert!(html.contains("FR424242424"), "{html}");
    assert!(
        html.contains("data-account-lts=\"3\"") || html.contains(">3<"),
        "LTS=3: {html}"
    );
    assert!(
        html.contains("data-account-industrial-lts=\"2\"") || html.contains(">2<"),
        "Industrial=2: {html}"
    );
    assert!(
        html.contains("Account Ops") || html.contains("ops@account.test"),
        "{html}"
    );
    assert!(html.contains(&email), "member pill: {html}");
    assert!(html.contains("USER ACCOUNTS"), "{html}");
    assert!(
        html.contains("vb-account-pill is-you"),
        "session member pill highlight: {html}"
    );
    assert!(
        !html.contains("Signed in as") && !html.contains("data-account-signed-in"),
        "no SESSION Signed in as block: {html}"
    );
    assert!(
        !html.contains("SIGNED-IN USER"),
        "must not use Concept SIGNED-IN USER mockup label: {html}"
    );
    assert!(
        !html.contains("Supported builds"),
        "SUBSCRIPTION omits supported builds: {html}"
    );
    assert!(
        html.contains("Sign out") || html.contains("logout"),
        "{html}"
    );

    cleanup(&db).await;
}

/// Reserved `/vauban/account` shows the live crate + git SHA, not the seed placeholder.
#[tokio::test]
async fn e2e_reserved_account_shows_vcp_build_label() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("acct-build");
    let slug = unique_slug("acct-build");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;

    let cookie = login_cookie(&router, &email).await.expect("cookie");
    let page = get(
        &router,
        &format!("/{RESERVED_ORG_SLUG}/account"),
        Some(&cookie),
    )
    .await;
    assert_eq!(status(&page), StatusCode::OK);
    let html = body_text(page).await;
    let label = product_label();

    assert!(
        html.contains(&label) && html.contains("data-vcp-build"),
        "reserved account must render {label}: {html}"
    );
    assert!(
        !html.contains("reserved preview tenant"),
        "must not show the seed placeholder: {html}"
    );

    cleanup(&db).await;
}

/// With two members, only the session user's pill is marked `is-you`.
#[tokio::test]
async fn e2e_org_account_highlights_only_signed_in_member() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email_a = unique_email("acct-you-a");
    let email_b = unique_email("acct-you-b");
    let slug = unique_slug("acct-you");
    let (_user_a, org) =
        create_org_with_membership(&db, &email_a, "password", &slug, "member").await;
    let user_b = create_test_user(&db, &email_b, "password").await;
    create_membership(&db, user_b.id, org.id, MEMBERSHIP_ROLE_ORG).await;

    let cookie = login_cookie(&router, &email_b).await.expect("cookie");
    let page = get(&router, &format!("/{slug}/account"), Some(&cookie)).await;
    assert_eq!(status(&page), StatusCode::OK);
    let html = body_text(page).await;

    assert!(html.contains(&email_a) && html.contains(&email_b), "{html}");
    assert!(
        !html.contains("Signed in as") && !html.contains("data-account-signed-in"),
        "no SESSION Signed in as block: {html}"
    );
    assert_eq!(
        html.matches("vb-account-pill is-you").count(),
        1,
        "exactly one session pill: {html}"
    );
    let you_at = html.find("vb-account-pill is-you").expect("is-you pill");
    let you_window = &html[you_at..(you_at + 200).min(html.len())];
    assert!(
        you_window.contains(&email_b),
        "is-you pill must be B: {you_window}"
    );
    assert!(
        !you_window.contains(&email_a),
        "is-you pill must not be A: {you_window}"
    );

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_org_account_wrong_org_and_anon_are_404() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("acct-deny");
    let slug = unique_slug("acct-deny");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;
    let other = create_test_org(&db, &unique_slug("acct-other")).await;

    let anon = get(&router, &format!("/{slug}/account"), None).await;
    assert_eq!(status(&anon), StatusCode::NOT_FOUND);

    let cookie = login_cookie(&router, &email).await.expect("cookie");
    let cross = get(&router, &format!("/{}/account", other.slug), Some(&cookie)).await;
    assert_eq!(status(&cross), StatusCode::NOT_FOUND);

    cleanup(&db).await;
}
