//! Middleware that pre-computes the per-request [`PermissionContext`].
//!
//! This middleware MUST be installed **after** [`crate::middleware::auth::auth_middleware`]
//! in the layer stack so that an [`AuthUser`] is already present in the
//! request extensions. For unauthenticated requests (no `AuthUser`) the
//! middleware is a pure no-op.
//!
//! Cost analysis: roughly 13 Casbin checks per authenticated request,
//! emitted in parallel via `tokio::join!` inside [`PermissionContext::load`].
//! With the supervisor active the dominant cost is a single IPC round-trip;
//! in dev fallback mode the checks resolve in microseconds.

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;

use crate::AppState;
use crate::auth::PermissionContext;
use crate::middleware::auth::AuthUser;

/// Inject a [`PermissionContext`] into the request extensions.
///
/// - If no [`AuthUser`] is present (public route, expired token), the
///   middleware is a pure pass-through.
/// - If [`AuthUser`] is present, all tracked permissions are loaded in
///   parallel and inserted into the extensions for downstream extraction.
pub async fn permission_context_middleware(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    if let Some(user) = request.extensions().get::<AuthUser>().cloned() {
        let perms = PermissionContext::load(&state, &user).await;
        request.extensions_mut().insert(perms);
    }
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::PermissionContext;

    #[test]
    fn test_middleware_signature_compiles() {
        // Compile-time check that the middleware function has the expected
        // signature for `axum::middleware::from_fn_with_state`.
        fn _check<F, Fut>(_: F)
        where
            F: Fn(State<AppState>, Request, Next) -> Fut,
            Fut: std::future::Future<Output = Response>,
        {
        }
        _check(permission_context_middleware);
    }

    #[test]
    fn test_permission_context_default_used_when_extension_missing() {
        // Documented invariant: when the middleware never ran (e.g. the route
        // is public), the FromRequestParts impl on PermissionContext returns
        // the default fail-closed context. This sanity-check verifies the
        // contract at the type level: Default is wired and denies everything.
        let ctx = PermissionContext::default();
        assert!(!ctx.users_write);
        assert!(!ctx.admin_view);
    }
}
