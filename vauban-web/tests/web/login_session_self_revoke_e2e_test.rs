//! End-to-end coverage for the self-revocation guard on login
//! sessions (profile bug): a user must never be able to revoke the
//! session that authenticates the request, and the plain-form flow
//! must never land on a blank page.

use axum::http::header::{COOKIE, REFERER};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use sha3::{Digest, Sha3_256};
use uuid::Uuid;
use vauban_web::schema::auth_sessions;

use crate::common::{TestApp, assertions::assert_status, unwrap_ok};
use crate::fixtures::{
    create_simple_admin_user, create_simple_user, create_test_auth_session, unique_name,
};

/// `(uuid, username)` of a persisted user (the fixtures suffix the
/// requested username, so assertions must read the stored value).
async fn user_identity(conn: &mut diesel_async::AsyncPgConnection, user_id: i32) -> (Uuid, String) {
    use vauban_web::schema::users;
    unwrap_ok!(
        users::table
            .filter(users::id.eq(user_id))
            .select((users::uuid, users::username))
            .first(conn)
            .await
    )
}

/// Resolve the `auth_sessions.uuid` of the session created by
/// `generate_test_token` (the caller's CURRENT session) via the SHA3
/// hash of the access token.
async fn current_session_uuid(app: &TestApp, token: &str) -> Uuid {
    let mut conn = app.get_conn().await;
    let mut hasher = Sha3_256::new();
    hasher.update(token.as_bytes());
    let token_hash = format!("{:x}", hasher.finalize());
    unwrap_ok!(
        auth_sessions::table
            .filter(auth_sessions::token_hash.eq(token_hash))
            .select(auth_sessions::uuid)
            .first(&mut conn)
            .await
    )
}

async fn session_exists(app: &TestApp, session_uuid: Uuid) -> bool {
    let mut conn = app.get_conn().await;
    let count: i64 = unwrap_ok!(
        auth_sessions::table
            .filter(auth_sessions::uuid.eq(session_uuid))
            .count()
            .get_result(&mut conn)
            .await
    );
    count > 0
}

struct SelfRevokeSetup {
    app: &'static TestApp,
    token: String,
    csrf: String,
    own_session: Uuid,
    other_session: Uuid,
}

async fn spawn_user_with_two_sessions(prefix: &str) -> SelfRevokeSetup {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let user_id = create_simple_user(&mut conn, &unique_name(prefix)).await;
    let (user_uuid, username) = user_identity(&mut conn, user_id).await;
    let other_session = create_test_auth_session(&mut conn, user_id, false).await;
    drop(conn);

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, false, false)
        .await;
    let own_session = current_session_uuid(app, &token).await;
    let csrf = app.generate_csrf_token();

    SelfRevokeSetup {
        app,
        token,
        csrf,
        own_session,
        other_session,
    }
}

/// Plain-form self-revocation (the profile page flow) is refused:
/// the row survives, the caller stays authenticated, and the browser
/// is PRG-redirected (no blank page).
#[tokio::test]
async fn self_revocation_via_plain_form_is_refused_with_redirect() {
    let setup = spawn_user_with_two_sessions("selfrev_form").await;

    let response = setup
        .app
        .server
        .post(&format!(
            "/accounts/login-sessions/{}/revoke",
            setup.own_session
        ))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", setup.token, setup.csrf),
        )
        .add_header(REFERER, "https://vauban.test/accounts/profile")
        .form(&[("csrf_token", setup.csrf.as_str())])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        (300..400).contains(&status),
        "plain-form refusal must PRG-redirect (no blank page), got {status}"
    );
    let location = response
        .headers()
        .get("location")
        .expect("refusal must carry a Location header")
        .to_str()
        .expect("ascii location");
    assert_eq!(
        location, "/accounts/profile",
        "the profile Referer must redirect back to the profile page"
    );

    assert!(
        session_exists(setup.app, setup.own_session).await,
        "the current session row must survive the refused self-revocation"
    );

    // Still authenticated: the profile page loads.
    let profile = setup
        .app
        .server
        .get("/accounts/profile")
        .add_header(COOKIE, format!("access_token={}", setup.token))
        .await;
    assert_status(&profile, 200);
}

/// HTMX self-revocation (forged or UI regression) is refused with a
/// 403 and the row survives.
#[tokio::test]
async fn self_revocation_via_htmx_is_refused_with_403() {
    let setup = spawn_user_with_two_sessions("selfrev_htmx").await;

    let response = setup
        .app
        .server
        .post(&format!(
            "/accounts/login-sessions/{}/revoke",
            setup.own_session
        ))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", setup.token, setup.csrf),
        )
        .add_header("HX-Request", "true")
        .form(&[("csrf_token", setup.csrf.as_str())])
        .await;

    assert_status(&response, 403);
    assert!(
        response.text().contains("use logout"),
        "the refusal must tell the user to use logout"
    );
    assert!(session_exists(setup.app, setup.own_session).await);
}

/// Revoking ANOTHER session through the plain profile form succeeds
/// with a PRG redirect (not the pre-fix blank `Html("")` page) and
/// deletes the row.
#[tokio::test]
async fn other_session_revocation_via_plain_form_redirects_and_deletes() {
    let setup = spawn_user_with_two_sessions("otherrev_form").await;

    let response = setup
        .app
        .server
        .post(&format!(
            "/accounts/login-sessions/{}/revoke",
            setup.other_session
        ))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", setup.token, setup.csrf),
        )
        .add_header(REFERER, "https://vauban.test/accounts/profile")
        .form(&[("csrf_token", setup.csrf.as_str())])
        .await;

    let status = response.status_code().as_u16();
    assert!(
        (300..400).contains(&status),
        "plain-form success must PRG-redirect, got {status}"
    );
    assert!(
        !session_exists(setup.app, setup.other_session).await,
        "the other session row must be deleted"
    );
    assert!(
        session_exists(setup.app, setup.own_session).await,
        "the current session must be untouched"
    );
}

/// The HTMX flow of the login-sessions page keeps its contract: 200
/// with an empty body (the row is swapped out client-side).
#[tokio::test]
async fn other_session_revocation_via_htmx_keeps_empty_200() {
    let setup = spawn_user_with_two_sessions("otherrev_htmx").await;

    let response = setup
        .app
        .server
        .post(&format!(
            "/accounts/login-sessions/{}/revoke",
            setup.other_session
        ))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", setup.token, setup.csrf),
        )
        .add_header("HX-Request", "true")
        .form(&[("csrf_token", setup.csrf.as_str())])
        .await;

    assert_status(&response, 200);
    assert_eq!(response.text(), "", "HTMX success must keep the empty body");
    assert!(!session_exists(setup.app, setup.other_session).await);
}

/// Both self-service pages detect the current session via the JWT
/// `jti`: badge present, no revoke form on the current session, revoke
/// form present on the other one. (Pre-fix, the profile page hashed a
/// non-existent `auth_token` cookie and offered to revoke the current
/// session.)
#[tokio::test]
async fn profile_and_sessions_pages_mark_current_session_unrevokable() {
    let setup = spawn_user_with_two_sessions("currentmark").await;
    let own_revoke = format!("/accounts/login-sessions/{}/revoke", setup.own_session);
    let other_revoke = format!("/accounts/login-sessions/{}/revoke", setup.other_session);

    for path in ["/accounts/profile", "/accounts/login-sessions"] {
        let response = setup
            .app
            .server
            .get(path)
            .add_header(COOKIE, format!("access_token={}", setup.token))
            .await;
        assert_status(&response, 200);
        let html = response.text();
        assert!(
            html.contains("Current"),
            "{path} must badge the current session"
        );
        assert!(
            !html.contains(&own_revoke),
            "{path} must not offer to revoke the current session"
        );
        assert!(
            html.contains(&other_revoke),
            "{path} must keep the revoke form on the other session"
        );
    }
}

/// Admin surface: an admin cannot revoke their own current session
/// from /accounts/all-login-sessions either (defence in depth; the WS
/// force-logout must never target the caller).
#[tokio::test]
async fn admin_self_revocation_is_refused_with_403() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin_id = create_simple_admin_user(&mut conn, &unique_name("selfrev_admin")).await;
    let (admin_uuid, admin_name) = user_identity(&mut conn, admin_id).await;
    drop(conn);

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let own_session = current_session_uuid(app, &token).await;
    let csrf = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!(
            "/accounts/all-login-sessions/{}/revoke",
            own_session
        ))
        .add_header(
            COOKIE,
            format!("access_token={token}; __vauban_csrf={csrf}"),
        )
        .add_header("HX-Request", "true")
        .form(&[("csrf_token", csrf.as_str())])
        .await;

    assert_status(&response, 403);
    assert!(
        session_exists(app, own_session).await,
        "the admin's current session must survive"
    );

    // The admin sessions page marks the caller's session as current.
    let page = app
        .server
        .get("/accounts/all-login-sessions")
        .add_header(COOKIE, format!("access_token={token}"))
        .await;
    assert_status(&page, 200);
    let html = page.text();
    assert!(html.contains("Current session"));
    assert!(
        !html.contains(&format!(
            "/accounts/all-login-sessions/{}/revoke",
            own_session
        )),
        "the admin page must not offer to revoke the caller's own session"
    );
}
