//! `/iacs/admin/*` admin gate (palier 7 of the IACS roll-out).
//!
//! Layered on the `Router::nest("/iacs/admin", ...)` carrying the
//! admin-zone routes. Mirrors [`crate::middleware::require_assets_manage`]
//! line-for-line, including the fail-closed contract on a missing
//! `PermissionContext` extension and the anti-enumeration guarantee
//! (the 403 happens BEFORE the handler / DB lookup, so a non-admin
//! cannot use `/iacs/admin/{random-uuid}` as an oracle for EWS or
//! request existence).
//!
//! The matching defence-in-depth is in
//! [`crate::handlers::web::iacs`]: every admin-zone handler also
//! re-checks `perms.iacs_manage` at the top of its body so a routing
//! misconfiguration that hoists a handler outside of the nest still
//! fails closed.
//!
//! # Kill-switch interaction
//!
//! `[industrial].enabled = false` forces every `iacs_*` flag of
//! `PermissionContext` to `false` (see `PermissionContext::load`).
//! That means a disabled industrial config also makes this middleware
//! refuse with 403 -- exactly what we want: the admin sub-tree is
//! invisible when the kill-switch is off, and any attempt to reach
//! it returns the same shape as a non-admin caller.

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::auth::PermissionContext;
use crate::error::AppError;

/// Reject requests whose `PermissionContext.iacs_manage` is `false`.
pub async fn require_iacs_manage(request: Request, next: Next) -> Response {
    let perms = request
        .extensions()
        .get::<PermissionContext>()
        .cloned()
        .unwrap_or_default();

    if perms.iacs_manage {
        next.run(request).await
    } else {
        AppError::forbidden("iacs:manage").into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::http::StatusCode;
    use axum::middleware::from_fn;
    use axum::routing::get;
    use tower::ServiceExt;

    fn router_without_perms() -> Router {
        Router::new()
            .route("/probe", get(|| async { (StatusCode::OK, "downstream") }))
            .layer(from_fn(require_iacs_manage))
    }

    fn router_with_perms(perms: PermissionContext) -> Router {
        Router::new()
            .route("/probe", get(|| async { (StatusCode::OK, "downstream") }))
            .layer(from_fn(require_iacs_manage))
            .layer(from_fn(move |mut req: Request, next: Next| {
                let perms = perms.clone();
                async move {
                    req.extensions_mut().insert(perms);
                    next.run(req).await
                }
            }))
    }

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
    async fn middleware_denies_when_iacs_manage_false() {
        let response = router_with_perms(PermissionContext {
            iacs_read: true,
            iacs_request: true,
            iacs_manage: false,
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
            "the gate must reject `iacs_manage = false` even when other flags are true"
        );
    }

    #[tokio::test]
    async fn middleware_allows_when_iacs_manage_true() {
        let response = router_with_perms(PermissionContext {
            iacs_manage: true,
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
