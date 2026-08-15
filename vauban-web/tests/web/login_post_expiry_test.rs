//! E2E tests for the post-expiry login recovery (CSRF self-heal + rotation).
//!
//! Reproduces the production bug where, after a session-expiry redirect to
//! `/login?reason=session_expired`, the web login form stayed stuck on
//! "Invalid or expired form. Please reload and try again." until a FULL
//! manual page reload, because the double-submit CSRF pair (cookie
//! `__vauban_csrf` + hidden field) was desynchronized and never resynced by
//! the error response.
//!
//! Two complementary fixes are pinned here:
//!  1. PRIMARY -- `login_web` self-heals on a CSRF failure: it mints a fresh
//!     token, ships the new cookie AND an out-of-band swap of the hidden
//!     field, so the very next submit succeeds without a reload.
//!  2. PREVENTIVE -- `login_page` forces a fresh CSRF token when reached via
//!     a canonical `?reason=` redirect, so the new sign-in starts aligned.
//!
//! SEC-04 non-regression: the user-facing CSRF message is unchanged and the
//! generic "Invalid credentials" wording never leaks here.

use axum::http::header::{self, SET_COOKIE};
use serial_test::serial;

use crate::common::{TestApp, assertions::assert_status, test_db};
use crate::fixtures::{create_test_user, unique_name};

/// Extract the value of the `__vauban_csrf` cookie from a response's
/// `Set-Cookie` headers, if present.
fn csrf_set_cookie(response: &axum_test::TestResponse) -> Option<String> {
    response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|h| h.to_str().ok())
        .find_map(|line| {
            let first = line.split(';').next()?.trim();
            let value = first.strip_prefix("__vauban_csrf=")?;
            Some(value.to_string())
        })
}

/// Extract the CSRF token carried by the `id="login-csrf-token"` input, used
/// both by the GET login page hidden field and by the OOB swap fragment that
/// the CSRF error response returns.
fn extract_login_csrf_token(html: &str) -> Option<String> {
    let anchor = html.find(r#"id="login-csrf-token""#)?;
    let tail = &html[anchor..];
    let value_idx = tail.find(r#"value=""#)?;
    let after = &tail[value_idx + r#"value=""#.len()..];
    let end = after.find('"')?;
    let token = &after[..end];
    if token.is_empty() {
        None
    } else {
        Some(token.to_string())
    }
}

/// PRIMARY: a CSRF failure on the HTMX login returns the red banner AND a
/// fresh, synchronized cookie + hidden-field swap, so the immediate retry
/// (no GET in between) succeeds.
#[tokio::test]
#[serial]
async fn login_csrf_error_htmx_refreshes_token_for_retry() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("post_expiry_selfheal");
    let test_user = create_test_user(&mut conn, &app.auth_service, &username).await;

    // Step 1: POST with a desynchronized double-submit pair (valid cookie,
    // mismatched form token) -- exactly the post-expiry stale-token case.
    let stale_cookie = app.generate_csrf_token();
    let first = app
        .server
        .post("/auth/login")
        .add_header(header::COOKIE, format!("__vauban_csrf={}", stale_cookie))
        .add_header("HX-Request", "true")
        .json(&serde_json::json!({
            "username": username,
            "password": test_user.password,
            "csrf_token": "totally-wrong-token",
        }))
        .await;

    let first_body = first.text();
    assert!(
        first_body.contains("Invalid or expired form"),
        "CSRF failure must keep the form-specific banner; got: {first_body}"
    );
    assert!(
        !first_body.contains("Incorrect username or password")
            && !first_body.contains("Invalid credentials"),
        "SEC-04: CSRF failure must not leak credential wording; got: {first_body}"
    );

    // The self-heal: new cookie + OOB hidden field, both carrying the SAME
    // fresh token.
    let healed_cookie =
        csrf_set_cookie(&first).expect("CSRF error response must Set-Cookie a fresh token");
    let healed_hidden = extract_login_csrf_token(&first_body)
        .expect("CSRF error response must carry an OOB hidden csrf_token swap");
    assert_eq!(
        healed_cookie, healed_hidden,
        "the refreshed cookie and hidden field must be identical for the retry"
    );
    assert_ne!(
        healed_cookie, stale_cookie,
        "the refreshed token must differ from the stale one"
    );

    // Step 2: retry with the healed pair and valid credentials -- NO GET in
    // between. Must succeed (HX-Redirect to MFA setup for a non-MFA user).
    let retry = app
        .server
        .post("/auth/login")
        .add_header(header::COOKIE, format!("__vauban_csrf={}", healed_cookie))
        .add_header("HX-Request", "true")
        .json(&serde_json::json!({
            "username": username,
            "password": test_user.password,
            "csrf_token": healed_hidden,
        }))
        .await;

    let retry_body = retry.text();
    assert!(
        !retry_body.contains("Invalid or expired form"),
        "retry with healed token must NOT fail CSRF; got: {retry_body}"
    );
    let redirect = retry
        .headers()
        .get("HX-Redirect")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert_eq!(
        redirect, "/mfa/setup",
        "successful retry must redirect to MFA setup; body: {retry_body}"
    );

    test_db::cleanup(&mut conn).await;
}

/// The full post-expiry flow: land on `/login?reason=session_expired`, read
/// the synchronized token straight from that page, then sign in once -- no
/// manual reload required.
#[tokio::test]
#[serial]
async fn login_after_session_expired_redirect_succeeds_without_manual_reload() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("post_expiry_flow");
    let test_user = create_test_user(&mut conn, &app.auth_service, &username).await;

    // Arrive on the login page via the canonical expiry redirect, carrying a
    // (now meaningless) stale CSRF cookie from the dead session.
    let stale_cookie = app.generate_csrf_token();
    let page = app
        .server
        .get("/login?reason=session_expired")
        .add_header(header::COOKIE, format!("__vauban_csrf={}", stale_cookie))
        .await;
    assert_status(&page, 200);

    let cookie = csrf_set_cookie(&page).expect("expiry redirect must mint a fresh CSRF cookie");
    let hidden =
        extract_login_csrf_token(&page.text()).expect("login page must carry a hidden csrf_token");
    assert_eq!(
        cookie, hidden,
        "page-issued cookie and hidden field must be aligned"
    );

    // Single sign-in attempt with the page-issued pair.
    let login = app
        .server
        .post("/auth/login")
        .add_header(header::COOKIE, format!("__vauban_csrf={}", cookie))
        .add_header("HX-Request", "true")
        .json(&serde_json::json!({
            "username": username,
            "password": test_user.password,
            "csrf_token": hidden,
        }))
        .await;

    let body = login.text();
    assert!(
        !body.contains("Invalid or expired form"),
        "post-expiry sign-in must not fail CSRF; got: {body}"
    );
    let redirect = login
        .headers()
        .get("HX-Redirect")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert_eq!(
        redirect, "/mfa/setup",
        "post-expiry sign-in must proceed to MFA setup; body: {body}"
    );

    test_db::cleanup(&mut conn).await;
}

/// PREVENTIVE: a canonical `?reason=` redirect forces a fresh CSRF token even
/// when the incoming cookie is still cryptographically valid.
#[tokio::test]
#[serial]
async fn login_page_with_reason_rotates_csrf() {
    let app = TestApp::spawn().await;

    for reason in [
        "session_expired",
        "session_revoked",
        "account_deactivated",
        "account_deleted",
    ] {
        let old = app.generate_csrf_token();
        let page = app
            .server
            .get(&format!("/login?reason={reason}"))
            .add_header(header::COOKIE, format!("__vauban_csrf={}", old))
            .await;
        assert_status(&page, 200);

        let new_cookie = csrf_set_cookie(&page)
            .unwrap_or_else(|| panic!("reason={reason} must rotate the CSRF cookie"));
        let new_hidden = extract_login_csrf_token(&page.text())
            .unwrap_or_else(|| panic!("reason={reason} page must carry a hidden csrf_token"));

        assert_ne!(
            new_cookie, old,
            "reason={reason}: a fresh token must be minted, not the stale one"
        );
        assert_eq!(
            new_cookie, new_hidden,
            "reason={reason}: rotated cookie and hidden field must match"
        );
    }
}

/// Count the `__vauban_csrf` Set-Cookie headers in a response.
fn csrf_set_cookie_count(response: &axum_test::TestResponse) -> usize {
    response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter(|h| {
            h.to_str()
                .map(|s| s.starts_with("__vauban_csrf="))
                .unwrap_or(false)
        })
        .count()
}

/// ROOT-CAUSE regression: a cold request (no CSRF cookie) for a NON-HTML
/// response -- a static asset, a favicon, JSON, ... -- must NEVER mint a
/// CSRF cookie. This is the fix for the recurring "Invalid or expired
/// form" login bug: on a cold page load the browser fires the document
/// plus several subresources concurrently, and an early cookie-less
/// favicon/asset response used to mint its own token and clobber the one
/// the login HTML embedded, desynchronising the double-submit pair.
#[tokio::test]
#[serial]
async fn cold_static_asset_request_does_not_mint_csrf_cookie() {
    let app = TestApp::spawn().await;

    // A real, compiled-in static asset (text/css), requested with NO
    // incoming CSRF cookie -- exactly what a browser does in parallel with
    // the login document on a cold load.
    let css = app.server.get("/static/css/vauban.css").await;
    assert_status(&css, 200);
    assert_eq!(
        csrf_set_cookie_count(&css),
        0,
        "a non-HTML (text/css) response must never mint a CSRF cookie, \
         otherwise it races the login document and clobbers its token"
    );

    // A plain text/plain endpoint must likewise not mint.
    let health = app.server.get("/health").await;
    assert_eq!(
        csrf_set_cookie_count(&health),
        0,
        "a text/plain response must not mint a CSRF cookie either"
    );
}

/// Companion invariant: a cold `/login` (HTML document) request MUST still
/// mint exactly one CSRF cookie, and the hidden field must match it. This
/// pins that restricting minting to HTML responses did not regress the
/// page that actually needs the cookie.
#[tokio::test]
#[serial]
async fn cold_login_page_mints_exactly_one_aligned_csrf_cookie() {
    let app = TestApp::spawn().await;

    let page = app.server.get("/login").await;
    assert_status(&page, 200);
    assert_eq!(
        csrf_set_cookie_count(&page),
        1,
        "a cold /login must mint exactly one CSRF cookie"
    );

    let cookie = csrf_set_cookie(&page).expect("cold /login must Set-Cookie a CSRF token");
    let hidden =
        extract_login_csrf_token(&page.text()).expect("login page must carry a hidden csrf_token");
    assert_eq!(
        cookie, hidden,
        "the minted cookie and the rendered hidden field must be identical"
    );
}

/// Non-regression: a plain `/login` GET with a still-valid CSRF cookie must
/// REUSE it (no needless rotation), preserving `get_or_create_csrf_token`.
#[tokio::test]
#[serial]
async fn login_page_without_reason_reuses_valid_csrf() {
    let app = TestApp::spawn().await;

    let existing = app.generate_csrf_token();
    let page = app
        .server
        .get("/login")
        .add_header(header::COOKIE, format!("__vauban_csrf={}", existing))
        .await;
    assert_status(&page, 200);

    // The handler reuses the valid cookie, so it does not set a new one; the
    // middleware also leaves it untouched.
    assert!(
        csrf_set_cookie(&page).is_none(),
        "a valid CSRF cookie must not be rotated on a plain /login"
    );
    let hidden =
        extract_login_csrf_token(&page.text()).expect("login page must carry a hidden csrf_token");
    assert_eq!(
        hidden, existing,
        "the hidden field must reflect the reused, still-valid cookie"
    );
}
