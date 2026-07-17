//! Generic route-layer Casbin permission gate (BAC hardening).
//!
//! Factorizes the `require_assets_manage` pattern so every admin
//! sub-tree can be fenced by a `route_layer` without duplicating the
//! fail-closed logic. The named wrappers below are mounted on
//! `Router::nest` sub-trees in `main.rs`:
//!
//! - [`require_users_read`]        -> `/accounts/users`
//! - [`require_groups_read`]       -> `/accounts/groups`
//! - [`require_access_rules_read`] -> `/assets/access`
//!
//! Layering contract (same as `require_assets_manage`):
//!
//! - the **routing** check (this middleware) blocks access to the
//!   sub-tree as a whole, including any future route added without the
//!   handler-level gate (regression-proof);
//! - the **handler** check (`if !perms.<flag> { ... }`) blocks access
//!   when a handler is mistakenly moved out of the nest or the nest is
//!   replaced by a flat `route()` declaration.
//!
//! Both checks read the same request-scoped [`PermissionContext`]
//! populated by
//! [`crate::middleware::permissions::permission_context_middleware`],
//! so they cannot drift.
//!
//! # Fail-closed
//!
//! A missing `PermissionContext` extension yields
//! [`PermissionContext::default()`], which denies everything. A
//! missing `AuthUser` extension routes through
//! [`crate::middleware::unauthenticated_response_for`] (303 `/login`
//! for HTML, 401 JSON for `/api/...`).
//!
//! # Anti-enumeration
//!
//! The 403 / 401 / 303 is returned **before** any DB lookup, so a
//! `role:user` cannot use `/accounts/groups/{random-uuid}` (or any
//! other fenced sub-tree) as an existence oracle.
//!
//! # Note on the gate granularity
//!
//! Each nest is fenced by the *minimum* permission of its sub-tree
//! (the `read` action): mutation handlers inside the nest re-assert
//! their stronger flag (`users_write`, `groups_write`,
//! `groups_manage_members`, `access_rules_write`) in their body, per
//! the casbin-permissions rule.

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::auth::PermissionContext;
use crate::error::AppError;
use crate::middleware::{AuthUser, unauthenticated_response_for};

/// Shared fail-closed gate body. `flag` extracts the boolean to
/// enforce from the request-scoped [`PermissionContext`]; `label` is
/// the canonical `resource:action` couple surfaced in the 403 body
/// (kept identical across the route_layer and the in-handler
/// re-check so anti-enumeration probes observe one single shape).
async fn require_flag(
    request: Request,
    next: Next,
    flag: fn(&PermissionContext) -> bool,
    label: &'static str,
) -> Response {
    let has_auth_user = request.extensions().get::<AuthUser>().is_some();
    let perms = request
        .extensions()
        .get::<PermissionContext>()
        .cloned()
        .unwrap_or_default();

    if flag(&perms) {
        next.run(request).await
    } else if !has_auth_user {
        unauthenticated_response_for(&request)
    } else {
        AppError::forbidden(label).into_response()
    }
}

/// Reject requests whose `PermissionContext.users_read` is `false`.
/// Mounted on the `/accounts/users` nest.
pub async fn require_users_read(request: Request, next: Next) -> Response {
    require_flag(request, next, |p| p.users_read, "users:read").await
}

/// Reject requests whose `PermissionContext.groups_read` is `false`.
/// Mounted on the `/accounts/groups` nest.
pub async fn require_groups_read(request: Request, next: Next) -> Response {
    require_flag(request, next, |p| p.groups_read, "groups:read").await
}

/// Reject requests whose `PermissionContext.access_rules_read` is
/// `false`. Mounted on the `/assets/access` nest.
pub async fn require_access_rules_read(request: Request, next: Next) -> Response {
    require_flag(request, next, |p| p.access_rules_read, "access_rules:read").await
}

#[cfg(test)]
mod tests {
    //! Router-driven gate tests, mirroring
    //! `require_assets_manage::tests`. The proptest counterpart in
    //! `tests/middleware/bac_proptest.rs` fuzzes the whole
    //! `PermissionContext` space; here we pin the deterministic
    //! outcomes.
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::http::StatusCode;
    use axum::middleware::from_fn;
    use axum::routing::get;
    use tower::ServiceExt;

    type GateFuture = std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send>>;
    type Gate = fn(Request, Next) -> GateFuture;
    type GrantFn = fn(&mut PermissionContext);
    type GateCase = (&'static str, Gate, GrantFn);

    /// The three named wrappers, with the flag setter used to grant
    /// them and the expected 403 label.
    fn gates() -> Vec<GateCase> {
        fn users(req: Request, next: Next) -> GateFuture {
            Box::pin(require_users_read(req, next))
        }
        fn groups(req: Request, next: Next) -> GateFuture {
            Box::pin(require_groups_read(req, next))
        }
        fn access(req: Request, next: Next) -> GateFuture {
            Box::pin(require_access_rules_read(req, next))
        }
        vec![
            ("users:read", users as Gate, |p| p.users_read = true),
            ("groups:read", groups as Gate, |p| p.groups_read = true),
            ("access_rules:read", access as Gate, |p| {
                p.access_rules_read = true
            }),
        ]
    }

    fn router_with(gate: Gate, auth: Option<PermissionContext>) -> Router {
        let router = Router::new()
            .route("/probe", get(|| async { (StatusCode::OK, "downstream") }))
            .layer(from_fn(gate));
        match auth {
            None => router,
            Some(perms) => {
                let auth_user = AuthUser {
                    uuid: "00000000-0000-0000-0000-00000000abcd".into(),
                    username: "test-user".into(),
                    mfa_verified: true,
                    is_superuser: false,
                    is_staff: false,
                };
                router.layer(from_fn(move |mut req: Request, next: Next| {
                    let perms = perms.clone();
                    let auth_user = auth_user.clone();
                    async move {
                        req.extensions_mut().insert(auth_user);
                        req.extensions_mut().insert(perms);
                        next.run(req).await
                    }
                }))
            }
        }
    }

    async fn probe(router: Router, path: &str) -> (StatusCode, Option<String>) {
        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .uri(path)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("router service");
        let status = response.status();
        let location = response
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        (status, location)
    }

    /// Unauthenticated on an HTML path -> 303 `/login` for every gate.
    #[tokio::test]
    async fn missing_auth_user_redirects_to_login_on_html_route() {
        for (label, gate, _) in gates() {
            let (status, location) = probe(router_with(gate, None), "/probe").await;
            assert_eq!(
                status,
                StatusCode::SEE_OTHER,
                "{label}: unauthenticated HTML must redirect"
            );
            assert_eq!(location.as_deref(), Some("/login"), "{label}");
        }
    }

    /// Authenticated but flag=false -> 403, even when EVERY other
    /// permission is granted (the gate must depend only on its flag).
    #[tokio::test]
    async fn denies_with_403_when_flag_false_even_with_all_other_flags() {
        for (label, gate, grant) in gates() {
            // Grant everything...
            let mut all = PermissionContext {
                users_read: true,
                users_write: true,
                users_manage_admins: true,
                assets_read: true,
                assets_read_all: true,
                assets_manage: true,
                groups_read: true,
                groups_write: true,
                groups_manage_members: true,
                access_rules_read: true,
                access_rules_write: true,
                auth_sessions_read: true,
                auth_sessions_write: true,
                sessions_read: true,
                sessions_write: true,
                sessions_supervise: true,
                sessions_bypass_access_rules: true,
                admin_view: true,
                profile_read: true,
                profile_write: true,
                iacs_request: true,
                iacs_read: true,
                iacs_manage: true,
                assets_connect_iacs: true,
                vault_secrets_read: true,
                vault_secrets_manage: true,
            };
            // ...except the gate's own flag. We locate it by granting
            // it on a default context and diffing.
            let mut only = PermissionContext::default();
            grant(&mut only);
            if only.users_read {
                all.users_read = false;
            }
            if only.groups_read {
                all.groups_read = false;
            }
            if only.access_rules_read {
                all.access_rules_read = false;
            }

            let (status, _) = probe(router_with(gate, Some(all)), "/probe").await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "{label}: gate must reject flag=false regardless of other flags"
            );
        }
    }

    /// Authenticated with ONLY the gate's flag -> pass-through.
    #[tokio::test]
    async fn allows_when_flag_true() {
        for (label, gate, grant) in gates() {
            let mut perms = PermissionContext::default();
            grant(&mut perms);
            let (status, _) = probe(router_with(gate, Some(perms)), "/probe").await;
            assert_eq!(status, StatusCode::OK, "{label}: flag=true must pass");
        }
    }

    /// Fail-closed: authenticated but the `PermissionContext`
    /// extension is missing entirely -> 403.
    #[tokio::test]
    async fn denies_with_403_when_perms_extension_missing() {
        for (label, gate, _) in gates() {
            let auth_user = AuthUser {
                uuid: "00000000-0000-0000-0000-000000000001".into(),
                username: "alice".into(),
                mfa_verified: true,
                is_superuser: false,
                is_staff: false,
            };
            let router = Router::new()
                .route("/probe", get(|| async { (StatusCode::OK, "downstream") }))
                .layer(from_fn(gate))
                .layer(from_fn(move |mut req: Request, next: Next| {
                    let auth_user = auth_user.clone();
                    async move {
                        req.extensions_mut().insert(auth_user);
                        next.run(req).await
                    }
                }));
            let (status, _) = probe(router, "/probe").await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "{label}: missing PermissionContext must fail closed"
            );
        }
    }
}
