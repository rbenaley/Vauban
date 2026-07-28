//! E2E: production `app::router` + `vcp_test` (HTTP in-process, no TLS).

use http_body_util::BodyExt;
use topcoat::router::StatusCode;
use vcp::db::now_unix;
use vcp::models::{AuthSession, RESERVED_ORG_SLUG};

use crate::common::{
    cleanup, cookie_header, create_org_with_membership, create_test_org, db_lock,
    expire_all_sessions_for_user, get, login_cookie, post_form, status, test_config, test_db,
    test_router, test_router_with_config, unique_email, unique_slug,
};

fn location(resp: &topcoat::router::Response) -> Option<&str> {
    resp.headers().get("location").and_then(|v| v.to_str().ok())
}

async fn body_text(resp: topcoat::router::Response) -> String {
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

#[tokio::test]
async fn e2e_login_reaches_member_dashboard() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("e2e-admin");
    let slug = unique_slug("e2e-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;

    let form = format!("email={}&password=password", urlencoding_encode(&email));
    let login = post_form(&router, "/login", None, &form).await;
    assert!(
        status(&login).is_redirection(),
        "login should redirect, got {}",
        status(&login)
    );
    let cookie = cookie_header(&login);
    assert!(
        cookie.is_some(),
        "login must set session cookie: {cookie:?}"
    );

    let dash = get(&router, &format!("/{slug}"), cookie.as_deref()).await;
    assert_eq!(
        status(&dash),
        StatusCode::OK,
        "dashboard status; cookie={cookie:?}"
    );
    let html = body_text(dash).await;
    assert!(
        html.contains(&slug) || html.contains("Administration") || html.len() > 100,
        "dashboard HTML should render"
    );

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_wrong_org_slug_is_404() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("e2e-member");
    let slug = unique_slug("e2e-home");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;
    let _other = create_test_org(&db, &unique_slug("e2e-other")).await;

    let form = format!("email={}&password=password", urlencoding_encode(&email));
    let login = post_form(&router, "/login", None, &form).await;
    let cookie = cookie_header(&login);

    let missing = get(
        &router,
        &format!("/{}", unique_slug("no-access")),
        cookie.as_deref(),
    )
    .await;
    assert_eq!(status(&missing), StatusCode::NOT_FOUND);

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_member_denied_admin_nest() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("e2e-noadmin");
    let slug = unique_slug("e2e-memorg");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;

    let form = format!("email={}&password=password", urlencoding_encode(&email));
    let login = post_form(&router, "/login", None, &form).await;
    let cookie = cookie_header(&login);
    assert!(cookie.is_some(), "login cookie required");

    // Same 404 as anonymous — no existence oracle for `/admin/*`.
    let admin = get(&router, "/admin/docs", cookie.as_deref()).await;
    assert_eq!(
        status(&admin),
        StatusCode::NOT_FOUND,
        "member must not learn that /admin/docs exists"
    );
    let anonymous = get(&router, "/admin/docs", None).await;
    assert_eq!(status(&anonymous), StatusCode::NOT_FOUND);
    let unknown = get(&router, "/admin", cookie.as_deref()).await;
    assert_eq!(status(&unknown), StatusCode::NOT_FOUND);

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_member_denied_reserved_org_is_404() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("e2e-vauban-deny");
    let slug = unique_slug("e2e-vauban-deny");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;
    let cookie = login_cookie(&router, &email).await;

    let reserved = get(&router, &format!("/{RESERVED_ORG_SLUG}"), cookie.as_deref()).await;
    assert_eq!(status(&reserved), StatusCode::NOT_FOUND);

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_existing_org_without_membership_same_as_missing_slug() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("e2e-eq-mem");
    let slug = unique_slug("e2e-eq-home");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;
    let foreign = unique_slug("e2e-eq-foreign");
    let _other = create_test_org(&db, &foreign).await;
    let cookie = login_cookie(&router, &email).await;

    let real = get(&router, &format!("/{foreign}"), cookie.as_deref()).await;
    let invented = get(
        &router,
        &format!("/{}", unique_slug("e2e-eq-missing")),
        cookie.as_deref(),
    )
    .await;
    assert_eq!(status(&real), StatusCode::NOT_FOUND);
    assert_eq!(status(&invented), StatusCode::NOT_FOUND);

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_login_unknown_email_and_bad_password_same_redirect() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("e2e-login-oracle");
    let slug = unique_slug("e2e-login-oracle");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;

    let unknown = post_form(
        &router,
        "/login",
        None,
        &format!(
            "email={}&password=password",
            urlencoding_encode(&unique_email("e2e-login-missing"))
        ),
    )
    .await;
    let bad = post_form(
        &router,
        "/login",
        None,
        &format!(
            "email={}&password=wrong-password",
            urlencoding_encode(&email)
        ),
    )
    .await;
    assert!(status(&unknown).is_redirection());
    assert!(status(&bad).is_redirection());
    assert_eq!(location(&unknown), Some("/login"));
    assert_eq!(location(&bad), Some("/login"));

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_login_rate_limit_still_redirects_to_login() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let mut cfg = test_config().await;
    cfg.login.max_attempts = 2;
    cfg.login.window_secs = 300;
    cfg.login.lockout_secs = 60;
    let router = test_router_with_config(cfg).await;

    let email = unique_email("e2e-rate");
    let slug = unique_slug("e2e-rate");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;
    let form = format!("email={}&password=wrong", urlencoding_encode(&email));

    let first = post_form(&router, "/login", None, &form).await;
    let second = post_form(&router, "/login", None, &form).await;
    let third = post_form(&router, "/login", None, &form).await;
    for resp in [&first, &second, &third] {
        assert!(status(resp).is_redirection());
        assert_eq!(location(resp), Some("/login"));
    }

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_anonymous_root_redirects_to_login() {
    let _guard = db_lock().lock().await;
    let router = test_router().await;
    let resp = get(&router, "/", None).await;
    assert!(status(&resp).is_redirection());
    assert_eq!(location(&resp), Some("/login"));
}

#[tokio::test]
async fn e2e_member_session_root_and_login_redirect_to_org() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("e2e-home-mem");
    let slug = unique_slug("e2e-home-mem");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;
    let cookie = login_cookie(&router, &email).await;
    assert!(cookie.is_some());

    let expected = format!("/{slug}");
    let root = get(&router, "/", cookie.as_deref()).await;
    assert!(status(&root).is_redirection());
    assert_eq!(location(&root), Some(expected.as_str()));

    let login = get(&router, "/login", cookie.as_deref()).await;
    assert!(status(&login).is_redirection());
    assert_eq!(location(&login), Some(expected.as_str()));
    let html = body_text(login).await;
    assert!(
        !html.contains("Continue to portal"),
        "authenticated /login must redirect, not show Continue chrome"
    );

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_staff_session_root_and_login_redirect_to_vauban() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("e2e-home-staff");
    let slug = unique_slug("e2e-staff-client");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let cookie = login_cookie(&router, &email).await;
    assert!(cookie.is_some());

    let expected = format!("/{RESERVED_ORG_SLUG}");
    let root = get(&router, "/", cookie.as_deref()).await;
    assert!(status(&root).is_redirection());
    assert_eq!(location(&root), Some(expected.as_str()));

    let login = get(&router, "/login", cookie.as_deref()).await;
    assert!(status(&login).is_redirection());
    assert_eq!(location(&login), Some(expected.as_str()));

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_expired_session_root_falls_back_to_login() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("e2e-home-exp");
    let slug = unique_slug("e2e-home-exp");
    let (user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;
    let cookie = login_cookie(&router, &email).await;
    assert!(cookie.is_some());
    expire_all_sessions_for_user(&db, user.id).await;

    let root = get(&router, "/", cookie.as_deref()).await;
    assert!(status(&root).is_redirection());
    assert_eq!(location(&root), Some("/login"));

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_expired_session_cannot_open_org() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("e2e-exp");
    let slug = unique_slug("e2e-exp-org");
    let (user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;

    let form = format!("email={}&password=password", urlencoding_encode(&email));
    let login = post_form(&router, "/login", None, &form).await;
    let cookie = cookie_header(&login);
    assert!(cookie.is_some());

    // Force every persisted session for this user into the past.
    expire_all_sessions_for_user(&db, user.id).await;
    assert!(now_unix() > 0);

    let mut conn = db.clone();
    let sessions = AuthSession::all().exec(&mut conn).await.unwrap_or_default();
    assert!(
        sessions
            .iter()
            .filter(|s| s.user_id == user.id)
            .all(|s| s.expires_at < now_unix()),
        "sessions should be expired"
    );

    let dash = get(&router, &format!("/{slug}"), cookie.as_deref()).await;
    // require_org maps unauthenticated to 404 (anti-enumeration).
    assert_eq!(status(&dash), StatusCode::NOT_FOUND);

    cleanup(&db).await;
}

fn urlencoding_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
