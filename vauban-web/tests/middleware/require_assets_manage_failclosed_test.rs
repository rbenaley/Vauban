//! Issue #27 — fail-closed contract for the `require_assets_manage`
//! middleware.
//!
//! These tests build a minimal `axum::Router` layered with the
//! middleware and drive real HTTP requests through it. They cover
//! the three scenarios that `tests/middleware/permissions_test.rs`
//! and `manage_assets_gate_matrix_test.rs` cannot reach because
//! they exercise the FULL production stack (auth + perm_context):
//!
//! 1. **Default `PermissionContext`**: every flag is `false`, the
//!    middleware MUST refuse with 403.
//! 2. **Missing `PermissionContext` extension**: a public route or
//!    a misordered middleware stack would yield no extension at
//!    all; the middleware MUST still refuse with 403 (fail-closed).
//! 3. **Other flags set, `assets_manage = false`**: a custom Casbin
//!    policy that grants `assets:read` to staff but withholds
//!    `assets:manage` MUST still produce 403; the middleware reads
//!    ONE flag and ignores everything else.

use axum::Router;
use axum::body::Body;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::{Next, from_fn};
use axum::routing::get;
use tower::ServiceExt;

use vauban_web::auth::PermissionContext;
use vauban_web::middleware::require_assets_manage::require_assets_manage;

fn probe_router() -> Router {
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
                req.extensions_mut().insert(perms);
                next.run(req).await
            }
        }))
}

/// Fail-closed #1: missing `PermissionContext` extension yields 403.
#[tokio::test]
async fn missing_extension_yields_403() {
    let response = probe_router()
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
        "fail-closed: a missing PermissionContext extension MUST be treated \
         as a denial (every flag defaults to false). A regression here would \
         mean a public route or a middleware reorder could expose admin \
         endpoints."
    );
}

/// Fail-closed #2: explicit `PermissionContext::default()` yields 403.
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
         middleware MUST refuse."
    );
}

/// Fail-closed #3: other flags set, `assets_manage = false`. The
/// middleware reads exactly ONE flag and ignores everything else.
/// A custom Casbin policy that grants `assets:read` and `admin:view`
/// but withholds `assets:manage` MUST still see a 403.
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
