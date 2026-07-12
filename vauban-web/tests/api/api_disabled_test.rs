//! VAUBAN Web - `api.enabled = false` E2E tests (INV-API-1).
//!
//! When the M2M API is disabled by configuration, the WHOLE `/api/v1`
//! tree must answer `501 Not Implemented` with the canonical JSON body
//! — every method included (GET/POST/PUT/DELETE/PATCH/HEAD), root path
//! included — and the web zone must stay untouched.
//!
//! The suite mounts the exact production seam
//! ([`vauban_web::handlers::api::api_disabled_router`], the same
//! function `create_app` swaps in when `config.api.enabled` is false)
//! next to a real web route, so the routing shape under test is the
//! production one.

use axum::http::Method;
use axum_test::TestServer;
use serde_json::Value;
use serial_test::serial;

use crate::common::TestApp;

/// Build a server with the production disabled-API catch-all merged
/// with a representative web route + the production fallback, wrapped
/// by the production security-headers middleware (so the INV-HDR
/// per-surface matrix is asserted on 501 responses too).
async fn disabled_api_server() -> TestServer {
    let app = TestApp::spawn().await;
    let router = axum::Router::new()
        .route(
            "/login",
            axum::routing::get(vauban_web::handlers::web::login_page),
        )
        .merge(vauban_web::handlers::api::api_disabled_router())
        .fallback(vauban_web::handlers::web::fallback_handler)
        .layer(axum::middleware::from_fn(
            vauban_web::middleware::security::security_headers_middleware,
        ))
        .with_state(app.app_state.clone());
    TestServer::new(router).expect("disabled-API test server")
}

/// Assert the canonical INV-API-1 response: 501 + JSON body
/// `{"error": "API is disabled", "status": 501}`.
fn assert_501_json(response: &axum_test::TestResponse, context: &str) {
    assert_eq!(
        response.status_code().as_u16(),
        501,
        "{context}: disabled API must answer 501 Not Implemented"
    );
    let body: Value = response.json();
    assert_eq!(
        body["error"], "API is disabled",
        "{context}: canonical error message"
    );
    assert_eq!(body["status"], 501, "{context}: status echoed in body");
}

/// Every HTTP method on a representative `/api/v1` sub-path answers
/// the canonical 501 JSON — including PATCH and HEAD, which used to
/// fall through to the web fallback (a misleading 404).
#[tokio::test]
#[serial]
async fn all_methods_on_api_subpaths_return_501_json() {
    let server = disabled_api_server().await;

    let paths = [
        "/api/v1/vault/secrets",
        "/api/v1/sessions",
        "/api/v1/accounts",
        "/api/v1/assets/manage/groups",
        "/api/v1/sessions/00000000-0000-0000-0000-000000000000/terminate",
    ];
    for path in paths {
        for method in [
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::PATCH,
        ] {
            let response = server.method(method.clone(), path).await;
            assert_501_json(&response, &format!("{method} {path}"));
        }
        // HEAD carries no body by HTTP semantics: status only.
        let response = server.method(Method::HEAD, path).await;
        assert_eq!(
            response.status_code().as_u16(),
            501,
            "HEAD {path}: disabled API must answer 501"
        );
    }
}

/// The `/api/v1` root itself (no trailing sub-path) answers 501 too.
#[tokio::test]
#[serial]
async fn api_root_returns_501_json() {
    let server = disabled_api_server().await;
    let response = server.get("/api/v1").await;
    assert_501_json(&response, "GET /api/v1");
    let response = server.post("/api/v1").await;
    assert_501_json(&response, "POST /api/v1");
}

/// INV-HDR-2/3/4 on the disabled branch: the 501 responses are API
/// surface responses and must carry `Cache-Control: no-store`, no CSP,
/// and no deprecated x-xss-protection.
#[tokio::test]
#[serial]
async fn disabled_api_501_carries_api_surface_headers() {
    let server = disabled_api_server().await;
    let response = server.get("/api/v1/sessions").await;
    assert_501_json(&response, "GET /api/v1/sessions");

    let headers = response.headers();
    assert_eq!(
        headers
            .get("cache-control")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default(),
        "no-store",
        "501 API responses must carry Cache-Control: no-store (INV-HDR-4)"
    );
    assert!(
        headers.get("content-security-policy").is_none(),
        "501 API responses must NOT carry the browser-only CSP (INV-HDR-2)"
    );
    assert!(
        headers.get("x-xss-protection").is_none(),
        "the deprecated x-xss-protection header must never be emitted (INV-HDR-3)"
    );
    assert!(
        headers.get("x-content-type-options").is_some()
            && headers.get("x-frame-options").is_some()
            && headers.get("strict-transport-security").is_some(),
        "501 API responses must keep the transport base set (INV-HDR-1)"
    );
}

/// Disabling the API must not affect the web zone: a real web route
/// still renders, and a non-API unknown path still gets the web
/// fallback (404), NOT a 501.
#[tokio::test]
#[serial]
async fn web_zone_is_untouched_when_api_disabled() {
    let server = disabled_api_server().await;

    let response = server.get("/login").await;
    assert_eq!(
        response.status_code().as_u16(),
        200,
        "web route must keep working with the API disabled"
    );

    // The web fallback applies to non-API unknown paths: anonymous
    // callers get its login redirect (303), never the API's 501.
    let response = server.get("/definitely/not/a/route").await;
    let status = response.status_code().as_u16();
    assert!(
        status == 303 || status == 404,
        "non-API unknown paths must keep the web fallback behaviour \
         (303 redirect or 404), got {status}"
    );
}
