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
//! # Fail-closed and content-negotiated unauthenticated path
//!
//! Three outcomes:
//!
//! 1. The caller has `assets:manage` -> the request flows through.
//! 2. The caller is authenticated but lacks the permission -> 403
//!    (legitimate authorization denial, surfaces as
//!    "Insufficient privileges").
//! 3. The caller is **not authenticated** (cookie missing, JWT
//!    expired, session revoked, ...). Because this middleware is
//!    mounted on BOTH the `/assets/manage` HTML nest AND the
//!    `/api/v1/assets/manage` JSON nest, the response is
//!    content-negotiated by URL family via
//!    [`crate::middleware::unauthenticated_response`]:
//!    - `/api/...` -> 401 JSON `Authentication required` (matches
//!      `AuthUser::from_request_parts`),
//!    - everything else -> 303 redirect to `/login` (matches
//!      `WebAuthUser::from_request_parts`).
//!
//! Without that branching, an admin whose JWT had just expired and
//! who clicked a link to `/assets/manage` saw the JSON body
//! `{"error":"Insufficient privileges: assets:manage required"}` --
//! confusing because the caller WAS NOT unauthorized, they were
//! UN-authenticated. The same applies to the IACS admin gate
//! (`require_iacs_manage`).
//!
//! # Anti-enumeration
//!
//! The 403 / 401 / 303 is returned **before** any DB lookup, so a
//! `role:user` cannot use `/assets/manage/{random-uuid}` as an oracle
//! for asset existence. See `tests/web/manage_assets_anti_enumeration_test.rs`.

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::auth::PermissionContext;
use crate::error::AppError;
use crate::middleware::{AuthUser, unauthenticated_response_for};

/// Reject requests whose `PermissionContext.assets_manage` is `false`.
///
/// Implementation note: we read the [`PermissionContext`] from request
/// extensions directly rather than via the extractor so the middleware
/// stays loader-agnostic (extractor uses `from_request_parts`, but
/// middleware is upstream of extractor consumption). The fail-closed
/// path is the same: a missing extension yields the default context,
/// which has `assets_manage = false`.
pub async fn require_assets_manage(request: Request, next: Next) -> Response {
    let has_auth_user = request.extensions().get::<AuthUser>().is_some();
    let perms = request
        .extensions()
        .get::<PermissionContext>()
        .cloned()
        .unwrap_or_default();

    if perms.assets_manage {
        next.run(request).await
    } else if !has_auth_user {
        unauthenticated_response_for(&request)
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
    /// middleware allows the request through. NOTE: no `AuthUser`
    /// is injected, so the gate falls into the unauthenticated
    /// branch -- the URL family then drives the response shape.
    fn router_without_auth() -> Router {
        Router::new()
            .route("/probe", get(|| async { (StatusCode::OK, "downstream") }))
            .layer(from_fn(require_assets_manage))
    }

    /// Variant that injects a synthetic [`PermissionContext`] AND a
    /// dummy [`AuthUser`] before the gate runs. Mirrors what the
    /// production middleware stack does:
    /// `auth_middleware` injects `AuthUser`, then
    /// `permission_context_middleware` computes and injects the
    /// `PermissionContext`. The presence of `AuthUser` is what
    /// distinguishes "session expired" (no AuthUser, redirect /
    /// 401) from "authenticated but unauthorized" (AuthUser
    /// present, 403).
    fn router_with_perms(perms: PermissionContext) -> Router {
        let auth_user = AuthUser {
            uuid: "00000000-0000-0000-0000-00000000abcd".into(),
            username: "test-user".into(),
            mfa_verified: true,
            is_superuser: false,
            is_staff: false,
        };
        Router::new()
            .route("/probe", get(|| async { (StatusCode::OK, "downstream") }))
            .layer(from_fn(require_assets_manage))
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

    /// Session-expired path on an HTML route: missing `AuthUser`
    /// (and missing `PermissionContext`) must redirect to /login,
    /// NOT serve a 403 JSON. This pins the exact symptom the user
    /// reported on `/assets/manage`.
    #[tokio::test]
    async fn missing_auth_user_redirects_to_login_on_html_route() {
        let response = router_without_auth()
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
            "session-expired HTML route must redirect to /login, not return 403"
        );
        let location = response
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert_eq!(
            location, "/login",
            "Location must be /login, was {location:?}"
        );
    }

    /// Session-expired path on an API route: missing `AuthUser`
    /// must yield 401 JSON, matching the `AuthUser` extractor used
    /// by every other API handler. M2M / curl callers cannot
    /// follow an HTML redirect and need a deterministic 401.
    #[tokio::test]
    async fn missing_auth_user_returns_401_json_on_api_route() {
        let response = router_without_auth()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/v1/assets/manage/probe")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("router service");

        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "session-expired API route must yield 401, not redirect"
        );
        assert!(
            response.headers().get("location").is_none(),
            "API 401 must NOT carry a Location header"
        );
    }

    /// AuthUser present (authenticated) but `assets_manage =
    /// false`: legitimate authorization denial -> 403 with the
    /// "Insufficient privileges" body that audit logs / E2E tests
    /// pin on.
    #[tokio::test]
    async fn middleware_denies_with_403_when_assets_manage_false() {
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

    /// Defensive path: `AuthUser` present but `PermissionContext`
    /// missing (would happen only if the loader is bypassed). The
    /// caller IS authenticated, so the gate must yield 403, NOT a
    /// redirect, to make the misconfiguration visible.
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
            .layer(from_fn(require_assets_manage))
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
            "AuthUser present but assets_manage=false must yield 403, not a redirect"
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
