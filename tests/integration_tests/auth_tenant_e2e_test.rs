//! E2E: production `app::router` + `vcp_test` (HTTP in-process, no TLS).

use http_body_util::BodyExt;
use topcoat::router::StatusCode;
use vcp::db::now_unix;
use vcp::models::AuthSession;

use crate::common::{
    cleanup, cookie_header, create_org_with_membership, create_test_org, db_lock,
    expire_all_sessions_for_user, get, post_form, status, test_db, test_router, unique_email,
    unique_slug,
};

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

    // Module page path for admin docs editor (Casbin admin_view + docs_write).
    let admin = get(&router, &format!("/{slug}/admin/docs"), cookie.as_deref()).await;
    assert_eq!(
        status(&admin),
        StatusCode::FORBIDDEN,
        "member must not access admin docs"
    );

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
