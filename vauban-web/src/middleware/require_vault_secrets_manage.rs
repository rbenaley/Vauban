//! `/vault/secrets/*` admin gate (organisational vault secrets).
//!
//! Layered on the `/vault/secrets` `Router::nest` to deny every request
//! whose [`PermissionContext::vault_secrets_manage`] is `false`. Exact
//! mirror of [`crate::middleware::require_assets_manage`]; see that
//! module for the full rationale (routing check + handler re-check,
//! content-negotiated unauthenticated path, anti-enumeration before any
//! DB lookup).

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::auth::PermissionContext;
use crate::error::AppError;
use crate::middleware::{AuthUser, unauthenticated_response_for};

/// Reject requests whose `PermissionContext.vault_secrets_manage` is
/// `false`.
///
/// Fail-closed: a missing `PermissionContext` extension yields the
/// default context, which has `vault_secrets_manage = false`. The
/// 403 / 401 / 303 is returned **before** any DB lookup, so a
/// `role:user` cannot use `/vault/secrets/{random-uuid}` as an oracle
/// for secret existence.
pub async fn require_vault_secrets_manage(request: Request, next: Next) -> Response {
    let has_auth_user = request.extensions().get::<AuthUser>().is_some();
    let perms = request
        .extensions()
        .get::<PermissionContext>()
        .cloned()
        .unwrap_or_default();

    if perms.vault_secrets_manage {
        next.run(request).await
    } else if !has_auth_user {
        unauthenticated_response_for(&request)
    } else {
        AppError::forbidden("vault_secrets:manage").into_response()
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

    fn router_without_auth() -> Router {
        Router::new()
            .route("/probe", get(|| async { (StatusCode::OK, "downstream") }))
            .layer(from_fn(require_vault_secrets_manage))
    }

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
            .layer(from_fn(require_vault_secrets_manage))
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

    /// Session-expired path on an HTML route: missing `AuthUser` must
    /// redirect to /login, NOT serve a 403 JSON.
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

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert_eq!(location, "/login");
    }

    /// AuthUser present but `vault_secrets_manage = false`: 403, even
    /// when every other flag is true (no substitution by read or by
    /// assets_manage).
    #[tokio::test]
    async fn middleware_denies_with_403_when_vault_secrets_manage_false() {
        let response = router_with_perms(PermissionContext {
            vault_secrets_read: true,
            assets_manage: true,
            admin_view: true,
            vault_secrets_manage: false,
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
            "the gate must reject `vault_secrets_manage = false` even when other flags are true"
        );
    }

    #[tokio::test]
    async fn middleware_allows_when_vault_secrets_manage_true() {
        let response = router_with_perms(PermissionContext {
            vault_secrets_manage: true,
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
