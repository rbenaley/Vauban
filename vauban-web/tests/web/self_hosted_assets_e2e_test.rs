//! End-to-end tests for the self-hosted front-end assets.
//!
//! Every front-end dependency (Tailwind JIT compiler, htmx, Alpine.js,
//! the xterm stack) used to be loaded from public CDNs
//! (`cdn.tailwindcss.com`, `unpkg.com`, `cdn.jsdelivr.net`). They are now
//! vendored verbatim under `static/js/vendor` / `static/css/vendor` and
//! served same-origin from `/static/`.
//!
//! These tests drive the full Axum router (`TestApp`) and assert:
//!  * `GET /login` renders the self-hosted `<script>` references and
//!    carries NO CDN origin in either the body or the CSP header.
//!  * every vendored asset is actually served (`200` + correct
//!    `Content-Type` + non-empty body) -- a regression guard against the
//!    "referenced-but-not-registered in STATIC_FILES" 404 class of bug.
//!  * the authenticated SSH terminal page references the self-hosted
//!    xterm CSS + JS (anti-regression: the xterm stylesheet + the
//!    `style-src 'unsafe-inline'` kept in the CSP are what guarantee a
//!    correct font/format rendering of the terminal).

use axum::http::header;

use crate::common::TestApp;
use crate::fixtures::{
    create_simple_ssh_asset, create_test_session_with_uuid, create_test_user,
    grant_user_access_to_asset, unique_name,
};

const CDN_ORIGINS: [&str; 3] = ["cdn.tailwindcss.com", "unpkg.com", "cdn.jsdelivr.net"];

const VENDOR_JS: [&str; 8] = [
    "/static/js/vendor/tailwindcss.js",
    "/static/js/vendor/htmx.min.js",
    "/static/js/vendor/htmx-ext-ws.js",
    "/static/js/vendor/htmx-ext-json-enc.js",
    "/static/js/vendor/alpine.min.js",
    "/static/js/vendor/xterm.min.js",
    "/static/js/vendor/xterm-addon-fit.min.js",
    "/static/js/vendor/xterm-addon-web-links.min.js",
];

const VENDOR_CSS: [&str; 1] = ["/static/css/vendor/xterm.min.css"];

/// `GET /login` must reference the self-hosted Tailwind/htmx/Alpine scripts
/// and must NOT leak any CDN origin in the rendered HTML.
#[tokio::test]
async fn login_page_references_self_hosted_scripts_and_no_cdn() {
    let app = TestApp::spawn().await;

    let response = app.server.get("/login").await;
    assert_eq!(response.status_code().as_u16(), 200, "login must render");

    let body = response.text();

    for asset in [
        "/static/js/vendor/tailwindcss.js",
        "/static/js/vendor/htmx.min.js",
        "/static/js/vendor/htmx-ext-ws.js",
        "/static/js/vendor/htmx-ext-json-enc.js",
        "/static/js/vendor/alpine.min.js",
    ] {
        assert!(
            body.contains(asset),
            "login body must reference self-hosted asset {asset}"
        );
    }

    for origin in CDN_ORIGINS {
        assert!(
            !body.contains(origin),
            "login body must NOT reference CDN origin {origin}"
        );
    }
}

/// The CSP served on `/login` must carry no CDN origin (every dependency is
/// same-origin) yet keep `'unsafe-eval'` / `'unsafe-inline'` (Tailwind JIT +
/// Alpine standard build + xterm injected <style> still need them).
#[tokio::test]
async fn login_csp_drops_cdn_but_keeps_unsafe_directives() {
    let app = TestApp::spawn().await;

    let response = app.server.get("/login").await;
    let csp = response
        .headers()
        .get("content-security-policy")
        .expect("CSP header must be present")
        .to_str()
        .expect("CSP header must be valid UTF-8")
        .to_string();

    for origin in CDN_ORIGINS {
        assert!(
            !csp.contains(origin),
            "CSP must NOT whitelist CDN origin {origin}; got: {csp}"
        );
    }
    assert!(
        !csp.contains("https://"),
        "CSP must not carry any remote https origin; got: {csp}"
    );

    let script_src = csp
        .split(';')
        .find(|d| d.trim().starts_with("script-src"))
        .expect("CSP must contain script-src");
    assert!(
        script_src.contains("'unsafe-eval'"),
        "script-src must keep 'unsafe-eval' (Tailwind JIT + Alpine); got: {script_src}"
    );

    let style_src = csp
        .split(';')
        .find(|d| d.trim().starts_with("style-src"))
        .expect("CSP must contain style-src");
    assert!(
        style_src.contains("'unsafe-inline'"),
        "style-src must keep 'unsafe-inline' (Tailwind JIT + xterm); got: {style_src}"
    );
}

/// The CSP served on `/login` must scope `connect-src` to exactly `'self'`
/// (no blanket `wss:` source) and lock `object-src` to `'none'`. Same-origin
/// WebSockets (SSH/RDP terminals, htmx notifications) are covered by `'self'`.
#[tokio::test]
async fn login_csp_locks_connect_src_self_and_object_src_none() {
    let app = TestApp::spawn().await;

    let response = app.server.get("/login").await;
    let csp = response
        .headers()
        .get("content-security-policy")
        .expect("CSP header must be present")
        .to_str()
        .expect("CSP header must be valid UTF-8")
        .to_string();

    let connect_src = csp
        .split(';')
        .find(|d| d.trim().starts_with("connect-src"))
        .expect("CSP must contain connect-src")
        .trim();
    assert_eq!(
        connect_src, "connect-src 'self'",
        "connect-src must be exactly 'self' (no blanket wss:); got: {connect_src}"
    );

    let object_src = csp
        .split(';')
        .find(|d| d.trim().starts_with("object-src"))
        .expect("CSP must contain object-src")
        .trim();
    assert_eq!(
        object_src, "object-src 'none'",
        "object-src must be exactly 'none'; got: {object_src}"
    );
}

/// Every vendored JS asset must be served (200 + JS content-type + body).
#[tokio::test]
async fn vendored_js_assets_are_served() {
    let app = TestApp::spawn().await;

    for path in VENDOR_JS {
        let response = app.server.get(path).await;
        assert_eq!(
            response.status_code().as_u16(),
            200,
            "vendored asset {path} must be served (registered in STATIC_FILES)"
        );
        let ct = response
            .headers()
            .get("content-type")
            .unwrap_or_else(|| panic!("Content-Type must be set for {path}"))
            .to_str()
            .expect("valid UTF-8");
        assert!(
            ct.contains("application/javascript"),
            "{path} must be served as JavaScript, got: {ct}"
        );
        assert!(
            !response.text().is_empty(),
            "vendored asset {path} must have a non-empty body"
        );
    }
}

/// Every vendored CSS asset must be served (200 + CSS content-type + body).
#[tokio::test]
async fn vendored_css_assets_are_served() {
    let app = TestApp::spawn().await;

    for path in VENDOR_CSS {
        let response = app.server.get(path).await;
        assert_eq!(
            response.status_code().as_u16(),
            200,
            "vendored asset {path} must be served (registered in STATIC_FILES)"
        );
        let ct = response
            .headers()
            .get("content-type")
            .unwrap_or_else(|| panic!("Content-Type must be set for {path}"))
            .to_str()
            .expect("valid UTF-8");
        assert!(
            ct.contains("text/css"),
            "{path} must be served as text/css, got: {ct}"
        );
        assert!(
            !response.text().is_empty(),
            "vendored asset {path} must have a non-empty body"
        );
    }
}

/// The authenticated SSH terminal page must reference the self-hosted xterm
/// CSS + the three self-hosted xterm scripts (no jsdelivr). This is the
/// anti-regression guard for the terminal rendering: the xterm stylesheet
/// loaded same-origin + `style-src 'unsafe-inline'` kept in the CSP are what
/// make the terminal font/format render correctly.
#[tokio::test]
async fn terminal_page_references_self_hosted_xterm() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user = create_test_user(&mut conn, &app.auth_service, &unique_name("xterm_e2e")).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("xterm_e2e_asset"), user.user.id).await;
    let _ = grant_user_access_to_asset(
        &mut conn,
        user.user.id,
        asset_id,
        &unique_name("xterm_e2e_grant"),
        &["ssh"],
    )
    .await;
    let (_sid, session_uuid) =
        create_test_session_with_uuid(&mut conn, user.user.id, asset_id, "ssh", "active").await;
    drop(conn);

    let response = app
        .server
        .get(&format!("/sessions/terminal/{}", session_uuid))
        .add_header(header::COOKIE, format!("access_token={}", user.token))
        .await;

    assert_eq!(
        response.status_code().as_u16(),
        200,
        "owner with an active rule must get the terminal HTML"
    );

    let body = response.text();
    for asset in [
        "/static/css/vendor/xterm.min.css",
        "/static/js/vendor/xterm.min.js",
        "/static/js/vendor/xterm-addon-fit.min.js",
        "/static/js/vendor/xterm-addon-web-links.min.js",
    ] {
        assert!(
            body.contains(asset),
            "terminal page must reference self-hosted xterm asset {asset}"
        );
    }

    for origin in CDN_ORIGINS {
        assert!(
            !body.contains(origin),
            "terminal page must NOT reference CDN origin {origin}"
        );
    }
}
