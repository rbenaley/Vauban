//! `/assets/manage/*` admin gate (issue #27 asset zone split).
//!
//! Layered on the `/assets/manage` `Router::nest` to deny every request
//! whose [`PermissionContext::assets_manage`] is `false`. Defence-in-
//! depth: each handler in [`crate::handlers::web::manage_assets`] also
//! re-checks the permission. The two checks are intentional and pin
//! two independent invariants:
//!
//! - the **routing** check (this middleware) blocks access to the
//!   sub-tree as a whole, including any future route added without the
//!   handler-level gate (regression-proof);
//! - the **handler** check blocks access when a handler is mistakenly
//!   moved out of the nest, when a misconfiguration replaces the nest
//!   with a flat `route()` declaration, or when the middleware is ever
//!   bypassed by a `tower::ServiceBuilder` reorder.
//!
//! Both checks share the same source of truth -- the request-scoped
//! `PermissionContext` populated by
//! [`crate::middleware::permissions::permission_context_middleware`] -- so
//! they cannot drift.
//!
//! # Fail-closed
//!
//! When the [`PermissionContext`] extension is missing (public route,
//! middleware reordered, expired token), the
//! [`PermissionContext::from_request_parts`] impl returns
//! [`PermissionContext::default`]; every field is `false` so the
//! middleware refuses with 403.
//!
//! # Anti-enumeration
//!
//! The 403 is returned **before** any DB lookup, so a `role:user`
//! cannot use `/assets/manage/{random-uuid}` as an oracle for asset
//! existence. See `tests/web/manage_assets_anti_enumeration_test.rs`.

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::auth::PermissionContext;
use crate::error::AppError;

/// Reject requests whose `PermissionContext.assets_manage` is `false`.
///
/// Implementation note: we read the [`PermissionContext`] from request
/// extensions directly rather than via the extractor so the middleware
/// stays loader-agnostic (extractor uses `from_request_parts`, but
/// middleware is upstream of extractor consumption). The fail-closed
/// path is the same: a missing extension yields the default context,
/// which has `assets_manage = false`.
pub async fn require_assets_manage(request: Request, next: Next) -> Response {
    let perms = request
        .extensions()
        .get::<PermissionContext>()
        .cloned()
        .unwrap_or_default();

    if perms.assets_manage {
        next.run(request).await
    } else {
        AppError::forbidden("assets:manage").into_response()
    }
}

#[cfg(test)]
mod tests {
    //! These tests build a minimal axum [`Router`] that is layered with
    //! the `require_assets_manage` middleware and asserts the gate
    //! behaviour by driving real HTTP requests through it. We
    //! intentionally avoid hand-constructing [`axum::middleware::Next`]
    //! because its constructor is not part of the public API in axum
    //! 0.7+; the router-driven approach is also closer to the way the
    //! middleware is used in production (`Router::nest` +
    //! `route_layer(from_fn(...))`).
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::http::StatusCode;
    use axum::middleware::from_fn;
    use axum::routing::get;
    use tower::ServiceExt;

    /// Build a router that returns `200 OK` from `/probe` IFF the
    /// middleware allows the request through.
    fn router_without_perms() -> Router {
        Router::new()
            .route("/probe", get(|| async { (StatusCode::OK, "downstream") }))
            .layer(from_fn(require_assets_manage))
    }

    /// Variant that injects a synthetic [`PermissionContext`] before
    /// the gate runs. Mirrors what the production
    /// `permission_context_middleware` does in front of every request.
    fn router_with_perms(perms: PermissionContext) -> Router {
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

    /// Fail-closed contract: a missing `PermissionContext` extension
    /// (loader failure, middleware reordered, expired token) yields
    /// the default context (every flag `false`) and the gate refuses.
    #[tokio::test]
    async fn middleware_denies_when_perms_missing() {
        let response = router_without_perms()
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
            "fail-closed: missing PermissionContext extension must yield 403"
        );
    }

    #[tokio::test]
    async fn middleware_denies_when_assets_manage_false() {
        let response = router_with_perms(PermissionContext {
            assets_read: true,
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
            "the gate must reject `assets_manage = false` even when other flags are true"
        );
    }

    #[tokio::test]
    async fn middleware_allows_when_assets_manage_true() {
        let response = router_with_perms(PermissionContext {
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
}
