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
use crate::middleware::{AuthUser, unauthenticated_response_for};

/// Reject requests whose `PermissionContext.iacs_manage` is `false`.
///
/// Three outcomes:
///
/// 1. The caller has `iacs:manage` -> the request flows through.
/// 2. The caller is authenticated but lacks the permission -> 403
///    (legitimate authorization denial, surfaces as
///    "Insufficient privileges").
/// 3. The caller is NOT authenticated (cookie missing, JWT expired,
///    session revoked, ...) -> response is content-negotiated by URL
///    family via [`crate::middleware::unauthenticated_response_for`]:
///    `/api/...` yields 401 JSON (matches the `AuthUser` extractor)
///    and everything else yields 303 to `/login` (matches the
///    `WebAuthUser` extractor). Without this branch a session-
///    expired admin clicking "IACS" in the sidebar saw a JSON 403
///    error page instead of the login prompt every other admin
///    page renders.
pub async fn require_iacs_manage(request: Request, next: Next) -> Response {
    let has_auth_user = request.extensions().get::<AuthUser>().is_some();
    let perms = request
        .extensions()
        .get::<PermissionContext>()
        .cloned()
        .unwrap_or_default();

    if perms.iacs_manage {
        next.run(request).await
    } else if !has_auth_user {
        unauthenticated_response_for(&request)
    } else {
        AppError::forbidden("iacs:manage").into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::middleware::AuthUser;
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
        // Mirror the production middleware order: auth_middleware
        // inserts AuthUser before permission_context_middleware
        // computes the PermissionContext, so a router that
        // exercises require_iacs_manage with a real `iacs_manage =
        // false` decision MUST also expose an AuthUser (otherwise
        // the gate collapses to AuthRedirect, not 403). Tests that
        // explicitly want the unauthenticated path use
        // `router_without_perms`.
        let auth_user = AuthUser {
            uuid: "00000000-0000-0000-0000-00000000abcd".into(),
            username: "test-user".into(),
            mfa_verified: true,
            is_superuser: false,
            is_staff: false,
        };
        Router::new()
            .route("/probe", get(|| async { (StatusCode::OK, "downstream") }))
            .layer(from_fn(require_iacs_manage))
            .layer(from_fn(move |mut req: Request, next: Next| {
                let perms = perms.clone();
                let auth_user = auth_user.clone();
                async move {
                    req.extensions_mut().insert(auth_user);
                    req.extensions_mut().insert(perms);
                    next.run(req).await
                }
            }))
    }

    #[tokio::test]
    async fn middleware_redirects_to_login_when_no_auth_user() {
        // No AuthUser AND no PermissionContext: this is the
        // session-expired path. The gate must collapse to a redirect
        // to /login, not a 403 "Insufficient privileges" -- otherwise
        // an admin whose JWT just expired and clicks "IACS" in the
        // sidebar gets a confusing JSON error instead of the login
        // prompt every other admin page renders.
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
            StatusCode::SEE_OTHER,
            "missing AuthUser extension must redirect to /login (303), not 403"
        );
        let location = response
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert_eq!(
            location, "/login",
            "AuthRedirect must point at /login, got {location:?}"
        );
    }

    /// AuthUser present (authenticated) but `iacs_manage` collapsed to
    /// false because no PermissionContext was loaded -> 403
    /// (defensive: this should never happen in production because
    /// permission_context_middleware always inserts a context, but
    /// the gate must still distinguish "not authenticated" from
    /// "authenticated but unauthorized").
    #[tokio::test]
    async fn middleware_denies_with_403_when_auth_user_present_but_perms_missing() {
        let auth_user = AuthUser {
            uuid: "00000000-0000-0000-0000-000000000001".into(),
            username: "alice".into(),
            mfa_verified: true,
            is_superuser: false,
            is_staff: false,
        };
        let router = Router::new()
            .route("/probe", get(|| async { (StatusCode::OK, "downstream") }))
            .layer(from_fn(require_iacs_manage))
            .layer(from_fn(move |mut req: Request, next: Next| {
                let auth_user = auth_user.clone();
                async move {
                    req.extensions_mut().insert(auth_user);
                    next.run(req).await
                }
            }));

        let response = router
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
            "AuthUser present but iacs_manage=false must yield 403, not a redirect"
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
