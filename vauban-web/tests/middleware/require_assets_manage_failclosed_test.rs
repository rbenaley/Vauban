//! Issue #27 — fail-closed contract for the `require_assets_manage`
//! middleware.
//!
//! These tests build a minimal `axum::Router` layered with the
//! middleware and drive real HTTP requests through it. They cover
//! the four scenarios that `tests/middleware/permissions_test.rs`
//! and `manage_assets_gate_matrix_test.rs` cannot reach because
//! they exercise the FULL production stack (auth + perm_context):
//!
//! 1. **Default `PermissionContext`** with `AuthUser` present: every
//!    flag is `false`, the middleware MUST refuse with 403.
//! 2. **Missing `PermissionContext` extension** with `AuthUser`
//!    present: a misordered middleware stack would yield no
//!    extension at all; the middleware MUST still refuse with 403
//!    (fail-closed).
//! 3. **Other flags set, `assets_manage = false`** with `AuthUser`
//!    present: a custom Casbin policy that grants `assets:read` to
//!    staff but withholds `assets:manage` MUST still produce 403;
//!    the middleware reads ONE flag and ignores everything else.
//! 4. **No `AuthUser` AND no `PermissionContext`**: the caller is
//!    UN-authenticated (cookie missing, JWT expired). The
//!    middleware MUST split this case off from the perm-denied
//!    path: HTML routes redirect to `/login` (303), API routes
//!    yield 401 JSON. Pinned by the gate-matrix E2E suite; we
//!    keep a unit pin here so a regression is caught at the
//!    middleware level too.
//!
//! The first three cases inject a synthetic `AuthUser` upstream of
//! the middleware -- mirroring what `auth_middleware` does in
//! production -- so the gate stays in the perm-denied path
//! (legitimate 403) instead of falling into the unauthenticated
//! redirect path. Without the `AuthUser` injection, every test
//! collapses to the redirect / 401 branch and we lose coverage of
//! the perm-fail-closed contract.

use axum::Router;
use axum::body::Body;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::{Next, from_fn};
use axum::routing::get;
use tower::ServiceExt;

use vauban_web::auth::PermissionContext;
use vauban_web::middleware::AuthUser;
use vauban_web::middleware::require_assets_manage::require_assets_manage;

fn dummy_auth_user() -> AuthUser {
    AuthUser {
        uuid: "00000000-0000-0000-0000-00000000abcd".into(),
        username: "test-user".into(),
        mfa_verified: true,
        is_superuser: false,
        is_staff: false,
    }
}

/// Build a router that injects an `AuthUser` (production analogue
/// of a successful `auth_middleware` pass) but NO
/// `PermissionContext`. Used to exercise the perm-denied
/// fail-closed path without falling into the unauthenticated
/// redirect path.
fn probe_router_with_auth_only() -> Router {
    Router::new()
        .route("/probe", get(|| async { (StatusCode::OK, "downstream") }))
        .layer(from_fn(require_assets_manage))
        .layer(from_fn(|mut req: Request, next: Next| async move {
            req.extensions_mut().insert(dummy_auth_user());
            next.run(req).await
        }))
}

/// Build a router with NO `AuthUser` and NO `PermissionContext`
/// (the production "session expired" stack). Drives the
/// unauthenticated branch of the middleware.
fn probe_router_unauthenticated() -> Router {
    Router::new()
        .route("/probe", get(|| async { (StatusCode::OK, "downstream") }))
        .layer(from_fn(require_assets_manage))
}

fn probe_router_with_perms(perms: PermissionContext) -> Router {
    Router::new()
        .route("/probe", get(|| async { (StatusCode::OK, "downstream") }))
        .layer(from_fn(require_assets_manage))
        .layer(from_fn(move |mut req: Request, next: Next| {
            let perms = perms.clone();
            async move {
                req.extensions_mut().insert(dummy_auth_user());
                req.extensions_mut().insert(perms);
                next.run(req).await
            }
        }))
}

/// Fail-closed #1: missing `PermissionContext` extension WITH
/// `AuthUser` present yields 403 (perm-denied path).
#[tokio::test]
async fn missing_extension_yields_403() {
    let response = probe_router_with_auth_only()
        .oneshot(
            axum::http::Request::builder()
                .uri("/probe")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("router service");

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "fail-closed: an authenticated caller missing PermissionContext \
         MUST be treated as a denial (every flag defaults to false). A \
         regression here would mean a misordered middleware stack could \
         expose admin endpoints."
    );
}

/// Fail-closed #2: explicit `PermissionContext::default()` with
/// `AuthUser` present yields 403.
#[tokio::test]
async fn default_context_yields_403() {
    let response = probe_router_with_perms(PermissionContext::default())
        .oneshot(
            axum::http::Request::builder()
                .uri("/probe")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("router service");

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "fail-closed: PermissionContext::default() has every flag false; the \
         middleware MUST refuse with 403 for an authenticated caller."
    );
}

/// Fail-closed #3: other flags set, `assets_manage = false`, with
/// `AuthUser` present. The middleware reads exactly ONE flag and
/// ignores everything else. A custom Casbin policy that grants
/// `assets:read` and `admin:view` but withholds `assets:manage`
/// MUST still see a 403.
#[tokio::test]
async fn other_flags_do_not_leak_through() {
    let response = probe_router_with_perms(PermissionContext {
        users_read: true,
        assets_read: true,
        assets_read_all: true,
        admin_view: true,
        sessions_read: true,
        sessions_supervise: true,
        // Critical: assets_manage stays false.
        assets_manage: false,
        ..Default::default()
    })
    .oneshot(
        axum::http::Request::builder()
            .uri("/probe")
            .body(Body::empty())
            .expect("request"),
    )
    .await
    .expect("router service");

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "the gate MUST refuse `assets_manage = false` even when other \
         flags are true. Otherwise a custom policy granting any nearby \
         permission would silently unlock the admin sub-tree."
    );
}

/// Fail-closed #4: NO `AuthUser` AND NO `PermissionContext`. The
/// caller is un-authenticated; the middleware MUST split this off
/// from the perm-denied path. For the HTML probe path, that means
/// 303 to `/login` (matches `WebAuthUser` rejection shape) -- NEVER
/// 200 OK and NEVER a JSON 403 body. This test pins the
/// user-reported regression on `/assets/manage`.
#[tokio::test]
async fn unauthenticated_html_request_redirects_to_login() {
    let response = probe_router_unauthenticated()
        .oneshot(
            axum::http::Request::builder()
                .uri("/probe")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("router service");

    assert_eq!(
        response.status(),
        StatusCode::SEE_OTHER,
        "session-expired HTML caller MUST be redirected to /login, NOT \
         served a 403 'Insufficient privileges' JSON. Regression of the \
         user-reported bug on /assets/manage."
    );
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert_eq!(location, "/login");
}

/// Sanity counterpart: `assets_manage = true` MUST allow the request
/// through. Without this we would not actually be testing a gate, just
/// a "deny everything" middleware.
#[tokio::test]
async fn assets_manage_true_allows_through() {
    let response = probe_router_with_perms(PermissionContext {
        assets_manage: true,
        ..Default::default()
    })
    .oneshot(
        axum::http::Request::builder()
            .uri("/probe")
            .body(Body::empty())
            .expect("request"),
    )
    .await
    .expect("router service");

    assert_eq!(response.status(), StatusCode::OK);
}
