//! VAUBAN Web - Per-surface response headers E2E matrix (INV-HDR).
//!
//! Pins the invariants of
//! [`vauban_web::middleware::security`] and
//! [`vauban_web::middleware::cors`] end-to-end over the real test
//! router (which mirrors production: API sub-router merged CORS-free
//! into a CORS-wrapped web branch):
//!
//! - INV-HDR-1: base set (`x-content-type-options`, `x-frame-options`,
//!   `strict-transport-security`) on every response, both surfaces.
//! - INV-HDR-2: `content-security-policy`, `referrer-policy`,
//!   `permissions-policy` on the web surface ONLY.
//! - INV-HDR-3: the deprecated XSS-auditor header is never emitted
//!   anywhere (forbidden token, pinned on source below).
//! - INV-HDR-4: `Cache-Control: no-store` on every `/api/*` response
//!   (unless the handler set its own directive), never injected on web.
//! - INV-HDR-5: CORS headers only ever appear on the web/WS surface;
//!   `/api/*` never carries `access-control-*` nor a CORS `Vary`.
//!
//! The disabled-API 501 headers live in `api_disabled_test.rs`; the
//! vault `/value` `no-store` pin lives in `vault_secrets_test.rs`.

use std::fs;
use std::path::{Path, PathBuf};

use axum::http::{Method, header};
use serial_test::serial;
use uuid::Uuid;

use vauban_web::models::api_key::ApiKeyScope;

use crate::common::{TestApp, test_db};
use crate::fixtures::{create_admin_user, create_real_api_key, create_test_user, unique_name};

/// The origin allowlisted by `config/testing.toml` (`server.public_origins`).
const ALLOWED_ORIGIN: &str = "https://localhost:8443";

/// INV-HDR-1 helper: the transport base set must be on every response.
fn assert_base_set(headers: &axum::http::HeaderMap, context: &str) {
    assert_eq!(
        headers
            .get("x-content-type-options")
            .and_then(|v| v.to_str().ok()),
        Some("nosniff"),
        "{context}: x-content-type-options must be nosniff (INV-HDR-1)"
    );
    assert_eq!(
        headers.get("x-frame-options").and_then(|v| v.to_str().ok()),
        Some("DENY"),
        "{context}: x-frame-options must be DENY (INV-HDR-1)"
    );
    let hsts = headers
        .get("strict-transport-security")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        hsts.contains("max-age=") && hsts.contains("includeSubDomains"),
        "{context}: strict-transport-security must be present (INV-HDR-1), got: {hsts:?}"
    );
}

/// INV-HDR-3 helper: the deprecated XSS-auditor header is never emitted.
/// The needle is built from fragments so source pins scanning for the
/// forbidden token do not match this test file.
fn assert_no_legacy_xss_header(headers: &axum::http::HeaderMap, context: &str) {
    let forbidden = format!("x-xss-{}", "protection");
    assert!(
        headers.get(forbidden.as_str()).is_none(),
        "{context}: the deprecated {forbidden} header must never be emitted (INV-HDR-3)"
    );
}

/// INV-HDR-2 + INV-HDR-4 helper for the API surface: no browser-only
/// directive, `Cache-Control: no-store` injected.
fn assert_api_surface(headers: &axum::http::HeaderMap, context: &str) {
    assert_base_set(headers, context);
    assert_no_legacy_xss_header(headers, context);
    for name in [
        "content-security-policy",
        "referrer-policy",
        "permissions-policy",
    ] {
        assert!(
            headers.get(name).is_none(),
            "{context}: browser-only header '{name}' must NOT be on the API surface (INV-HDR-2)"
        );
    }
    assert_eq!(
        headers
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("no-store"),
        "{context}: API responses must carry Cache-Control: no-store (INV-HDR-4)"
    );
}

/// INV-HDR-5 helper: no CORS header on the response.
fn assert_no_cors_headers(headers: &axum::http::HeaderMap, context: &str) {
    assert!(
        headers.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none(),
        "{context}: access-control-allow-origin must NOT appear on the API surface (INV-HDR-5)"
    );
    let vary = headers
        .get(header::VARY)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    assert!(
        !vary.contains("origin"),
        "{context}: the API surface must not carry a CORS Vary (INV-HDR-5), got: {vary:?}"
    );
}

// =============================================================================
// Web surface (/login)
// =============================================================================

/// The web surface carries the full browser hardening set and no
/// injected `no-store` (INV-HDR-1/2/3/4).
#[tokio::test]
#[serial]
async fn login_page_carries_full_web_header_set() {
    let app = TestApp::spawn().await;

    let response = app.server.get("/login").await;
    assert_eq!(response.status_code().as_u16(), 200);
    let headers = response.headers();

    assert_base_set(headers, "GET /login");
    assert_no_legacy_xss_header(headers, "GET /login");
    for name in [
        "content-security-policy",
        "referrer-policy",
        "permissions-policy",
    ] {
        assert!(
            headers.get(name).is_some(),
            "GET /login: web surface must carry '{name}' (INV-HDR-2)"
        );
    }
    assert!(
        headers.get(header::CACHE_CONTROL).is_none(),
        "GET /login: the web surface must not receive the API no-store injection (INV-HDR-4)"
    );
}

// =============================================================================
// API surface across the status matrix (401 / 403 / 404 / 400 / 200)
// =============================================================================

/// 401 (no key): API headers hold even for unauthenticated callers.
#[tokio::test]
#[serial]
async fn api_headers_on_401_without_key() {
    let app = TestApp::spawn().await;

    for path in [
        "/api/v1/sessions",
        "/api/v1/accounts",
        "/api/v1/vault/secrets",
    ] {
        let response = app.server.get(path).await;
        assert_eq!(response.status_code().as_u16(), 401, "GET {path}");
        assert_api_surface(response.headers(), &format!("GET {path} (401)"));
        assert_no_cors_headers(response.headers(), &format!("GET {path} (401)"));
    }
}

/// 403 (valid key, wrong scope): API headers hold on authorization
/// denials.
#[tokio::test]
#[serial]
async fn api_headers_on_403_wrong_scope() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("hdr_scope")).await;
    let (_uuid, read_key) =
        create_real_api_key(&mut conn, admin.user.id, &[ApiKeyScope::Read], None).await;

    let response = app
        .server
        .get("/api/v1/vault/secrets")
        .add_header(header::AUTHORIZATION, app.api_key_header(&read_key))
        .await;
    assert_eq!(response.status_code().as_u16(), 403);
    assert_api_surface(response.headers(), "GET /api/v1/vault/secrets (403)");

    test_db::cleanup(&mut conn).await;
}

/// 404 (authorized, non-existent resource) and 400 (malformed UUID):
/// API headers hold on the honest-status error paths.
#[tokio::test]
#[serial]
async fn api_headers_on_404_and_400() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user = create_test_user(&mut conn, &app.auth_service, &unique_name("hdr_404")).await;
    drop(conn);

    let ghost = Uuid::new_v4();
    let response = app
        .server
        .get(&format!("/api/v1/sessions/{ghost}"))
        .add_header(header::AUTHORIZATION, app.api_key_header(&user.api_key))
        .await;
    assert_eq!(response.status_code().as_u16(), 404);
    assert_api_surface(response.headers(), "GET /api/v1/sessions/{ghost} (404)");

    let response = app
        .server
        .get("/api/v1/sessions/not-a-uuid")
        .add_header(header::AUTHORIZATION, app.api_key_header(&user.api_key))
        .await;
    assert_eq!(response.status_code().as_u16(), 400);
    assert_api_surface(response.headers(), "GET /api/v1/sessions/not-a-uuid (400)");
}

/// 200 (authorized happy path): API headers hold on success too.
#[tokio::test]
#[serial]
async fn api_headers_on_200_success() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user = create_test_user(&mut conn, &app.auth_service, &unique_name("hdr_200")).await;
    drop(conn);

    let response = app
        .server
        .get("/api/v1/sessions")
        .add_header(header::AUTHORIZATION, app.api_key_header(&user.api_key))
        .await;
    assert_eq!(response.status_code().as_u16(), 200);
    assert_api_surface(response.headers(), "GET /api/v1/sessions (200)");
    assert_no_cors_headers(response.headers(), "GET /api/v1/sessions (200)");
}

// =============================================================================
// CORS scoping (INV-HDR-5)
// =============================================================================

/// An allowlisted `Origin` gets ACAO on a web route, and NEVER on the
/// API surface — same request, different branch.
#[tokio::test]
#[serial]
async fn cors_acao_on_web_never_on_api() {
    let app = TestApp::spawn().await;

    let response = app
        .server
        .get("/login")
        .add_header(header::ORIGIN, ALLOWED_ORIGIN)
        .await;
    assert_eq!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .and_then(|v| v.to_str().ok()),
        Some(ALLOWED_ORIGIN),
        "the allowlisted origin must be reflected on the web branch (VAU-010)"
    );

    for path in ["/api/v1/sessions", "/api/v1/vault/secrets"] {
        let response = app
            .server
            .get(path)
            .add_header(header::ORIGIN, ALLOWED_ORIGIN)
            .await;
        assert_no_cors_headers(
            response.headers(),
            &format!("GET {path} with allowlisted Origin"),
        );
    }
}

/// A CORS preflight on the API surface is NOT honoured: no ACAO, no
/// preflight short-circuit (the allowlisted origin gets nothing either).
#[tokio::test]
#[serial]
async fn cors_preflight_on_api_is_not_honoured() {
    let app = TestApp::spawn().await;

    let response = app
        .server
        .method(Method::OPTIONS, "/api/v1/sessions")
        .add_header(header::ORIGIN, ALLOWED_ORIGIN)
        .add_header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
        .await;
    assert!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none(),
        "a preflight on /api/v1/* must NOT be honoured (INV-HDR-5), got status {}",
        response.status_code()
    );
    assert_ne!(
        response.status_code().as_u16(),
        200,
        "no CORS layer must short-circuit the API preflight with a 200 (INV-HDR-5)"
    );
}

// =============================================================================
// Structural pins (source drift guards)
// =============================================================================

fn read_src(rel: &str) -> String {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// INV-HDR-5 pin: in production `main.rs`, the CORS layer is scoped to
/// the web and WS branches and absent from `common_layers` (which also
/// wraps the API zone). Whitespace-stripped so the pin survives rustfmt.
#[test]
fn pin_cors_is_scoped_to_web_and_ws_in_main() {
    let src: String = read_src("src/main.rs")
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();

    let web_needle = ["web_routes", ".layer(cors)", ".merge(api_routes)"].concat();
    assert!(
        src.contains(&web_needle),
        "main.rs: web_routes must carry the CORS layer BEFORE merging api_routes (INV-HDR-5)"
    );
    let ws_needle = ["ws_routes", ".layer(cors.clone())"].concat();
    assert!(
        src.contains(&ws_needle),
        "main.rs: ws_routes must carry the CORS layer (INV-HDR-5)"
    );

    // CORS inside the common ServiceBuilder stack would wrap the API
    // zone too: scan the block between the builder and `let ws_app`.
    let builder_marker = ["ServiceBuilder", "::new()"].concat();
    let end_marker = ["let", "ws_app"].concat();
    let banned = ["layer", "(cors"].concat();
    let common_block = src
        .split(&builder_marker)
        .nth(1)
        .and_then(|rest| rest.split(&end_marker).next())
        .unwrap_or_default();
    assert!(
        !common_block.contains(&banned),
        "main.rs: common_layers must NOT contain the CORS layer (INV-HDR-5)"
    );
}

/// INV-HDR-5 pin: the CORS seam lives in the lib
/// (`middleware/cors.rs`), shared by production and the test router;
/// `main.rs` must consume it instead of re-defining its own.
#[test]
fn pin_cors_seam_is_the_shared_lib_module() {
    let cors_src = read_src("src/middleware/cors.rs");
    assert!(
        cors_src.contains("pub fn build_cors_layer(") && cors_src.contains("AllowOrigin::list"),
        "middleware/cors.rs must expose build_cors_layer over AllowOrigin::list (VAU-010)"
    );

    let main_src = read_src("src/main.rs");
    assert!(
        main_src.contains(
            "middleware::cors::build_cors_layer(&state.config.server.parsed_public_origins())"
        ),
        "main.rs must consume the shared CORS seam fed by server.parsed_public_origins()"
    );
    let redefined = ["fn ", "build_cors_layer"].concat();
    assert!(
        !main_src.contains(&redefined),
        "main.rs must not re-define its own CORS layer builder"
    );
}

/// INV-HDR-3 pin: the deprecated XSS-auditor header token must not
/// appear anywhere in `vauban-web/src/` (the needle is built via
/// `format!` so this test's own source never matches).
#[test]
fn pin_legacy_xss_header_token_is_banned_from_src() {
    let forbidden = format!("x-xss-{}", "protection");
    let mut src_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    src_dir.push("src");

    fn walk(dir: &Path, forbidden: &str, hits: &mut Vec<String>) {
        for entry in fs::read_dir(dir).expect("read src dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                walk(&path, forbidden, hits);
            } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                let body = fs::read_to_string(&path).expect("read source file");
                if body.to_ascii_lowercase().contains(forbidden) {
                    hits.push(path.display().to_string());
                }
            }
        }
    }

    let mut hits = Vec::new();
    walk(&src_dir, &forbidden, &mut hits);
    assert!(
        hits.is_empty(),
        "the deprecated {forbidden} header token is banned from vauban-web/src (INV-HDR-3), \
         found in: {hits:?}"
    );
}
