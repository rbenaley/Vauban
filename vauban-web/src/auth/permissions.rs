//! Casbin-backed authorization context, pre-computed once per authenticated
//! request by [`crate::middleware::permissions`] and consumed by handlers and
//! templates as a [`PermissionContext`] extractor / template field.
//!
//! Design goals:
//!
//! - **DRY**: every (resource, action) pair the web layer ever asks Casbin for
//!   has exactly one boolean here. Handlers no longer pre-compute one-off
//!   `has_user_write` / `user_is_admin` flags; templates no longer take the
//!   `is_staff || is_superuser` shortcut for UI gating.
//! - **Fail-closed**: [`PermissionContext::default`] denies everything. If the
//!   middleware never ran (route not authenticated) or the IPC client is
//!   unavailable, downstream callers see a fully-restrictive context.
//! - **Single source of truth**: [`check_rbac`] still lives here (and is
//!   re-exported by [`crate::handlers::web`] for the migration period); the
//!   loader simply runs the canonical helper for every tracked permission in
//!   parallel via `tokio::join!`.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use crate::AppState;
use crate::error::AppError;
use crate::middleware::auth::AuthUser;

/// Pre-computed Casbin permissions for a single authenticated request.
///
/// One boolean per `(resource, action)` couple referenced anywhere in the web
/// layer. The middleware loads all of them in parallel; handlers and templates
/// consume them without ever calling Casbin themselves again, so behaviour is
/// uniform between the server-side gate and the UI gate.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PermissionContext {
    pub users_read: bool,
    pub users_write: bool,
    /// Promote / edit / delete a user holding the superuser flag. Only the
    /// `role:superuser` (wildcard) grants this; staff cannot escalate
    /// another account to administrator.
    pub users_manage_admins: bool,
    pub assets_read: bool,
    /// Bypass per-asset access-rule filtering when listing assets. Holders see
    /// every active asset regardless of access rules; non-holders see the
    /// subset granted by access rules. Staff and superuser have it; regular
    /// users do not.
    pub assets_read_all: bool,
    pub assets_write: bool,
    pub groups_read: bool,
    /// CRUD on the group itself (create, edit, delete). Resserre par rapport
    /// au comportement legacy: seul le superuser (wildcard) le possede.
    pub groups_write: bool,
    /// Add or remove members of an existing group. Granted to staff and
    /// superuser.
    pub groups_manage_members: bool,
    pub access_rules_read: bool,
    pub access_rules_write: bool,
    pub auth_sessions_read: bool,
    pub auth_sessions_write: bool,
    pub sessions_read: bool,
    pub sessions_write: bool,
    /// Observe / interact with proxy sessions owned by other users (e.g. live
    /// WebSocket viewer for audit or shadowing). Staff and superuser.
    pub sessions_supervise: bool,
    /// Open a proxy session on an asset *without* a matching access rule.
    /// Reserved to the superuser via the wildcard policy entry.
    pub sessions_bypass_access_rules: bool,
    pub admin_view: bool,
    pub profile_read: bool,
    pub profile_write: bool,
}

impl PermissionContext {
    /// Load all tracked permissions for `user` in parallel.
    ///
    /// All checks are emitted concurrently with `tokio::join!`; the cost is
    /// dominated by a single IPC round-trip when the supervisor is up, or by a
    /// pure in-memory match when running in dev fallback mode.
    pub async fn load(state: &AppState, user: &AuthUser) -> Self {
        let (
            users_read,
            users_write,
            users_manage_admins,
            assets_read,
            assets_read_all,
            assets_write,
            groups_read,
            groups_write,
            groups_manage_members,
            access_rules_read,
            access_rules_write,
            auth_sessions_read,
            auth_sessions_write,
            sessions_read,
            sessions_write,
            sessions_supervise,
            sessions_bypass_access_rules,
            admin_view,
            profile_read,
            profile_write,
        ) = tokio::join!(
            check_rbac(state, user, "users", "read"),
            check_rbac(state, user, "users", "write"),
            check_rbac(state, user, "users", "manage_admins"),
            check_rbac(state, user, "assets", "read"),
            check_rbac(state, user, "assets", "read_all"),
            check_rbac(state, user, "assets", "write"),
            check_rbac(state, user, "groups", "read"),
            check_rbac(state, user, "groups", "write"),
            check_rbac(state, user, "groups", "manage_members"),
            check_rbac(state, user, "access_rules", "read"),
            check_rbac(state, user, "access_rules", "write"),
            check_rbac(state, user, "auth_sessions", "read"),
            check_rbac(state, user, "auth_sessions", "write"),
            check_rbac(state, user, "sessions", "read"),
            check_rbac(state, user, "sessions", "write"),
            check_rbac(state, user, "sessions", "supervise"),
            check_rbac(state, user, "sessions", "bypass_access_rules"),
            check_rbac(state, user, "admin", "view"),
            check_rbac(state, user, "profile", "read"),
            check_rbac(state, user, "profile", "write"),
        );

        Self {
            users_read,
            users_write,
            users_manage_admins,
            assets_read,
            assets_read_all,
            assets_write,
            groups_read,
            groups_write,
            groups_manage_members,
            access_rules_read,
            access_rules_write,
            auth_sessions_read,
            auth_sessions_write,
            sessions_read,
            sessions_write,
            sessions_supervise,
            sessions_bypass_access_rules,
            admin_view,
            profile_read,
            profile_write,
        }
    }
}

/// Extractor that pulls the [`PermissionContext`] populated by
/// [`crate::middleware::permissions::permission_context_middleware`].
///
/// On unauthenticated routes (where the middleware did not run) the extractor
/// returns a fail-closed [`PermissionContext::default`] so that handlers
/// accidentally placed outside the auth-protected stack still observe a
/// deny-everything context instead of panicking.
impl<S> FromRequestParts<S> for PermissionContext
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(parts
            .extensions
            .get::<PermissionContext>()
            .cloned()
            .unwrap_or_default())
    }
}

/// Check RBAC permission via the Casbin IPC client.
///
/// Maps `AuthUser` flags to a Casbin role subject and delegates to
/// vauban-access. Fail-closed: returns `false` on any IPC error.
///
/// **No fallback path**: Casbin is the single source of truth for
/// authorization. vauban-web refuses to start without an IPC connection to
/// vauban-access, so `state.access_client` is always populated in production.
/// This function therefore never short-circuits on `is_superuser` /
/// `is_staff` attributes - those flags are passed to Casbin as role subjects
/// and the policy file decides.
///
/// This is the canonical implementation. Handlers must read the
/// pre-computed [`PermissionContext`] (one parallel batch per request)
/// rather than calling `check_rbac` directly; the function is exposed so
/// that the middleware and the test suite can populate the context.
pub async fn check_rbac(
    state: &AppState,
    auth_user: &AuthUser,
    resource: &str,
    action: &str,
) -> bool {
    let subject = if auth_user.is_superuser {
        "role:superuser"
    } else if auth_user.is_staff {
        "role:staff"
    } else {
        "role:user"
    };
    state
        .access_client
        .check_permission(subject, resource, action)
        .await
        .unwrap_or_else(|e| {
            tracing::error!(
                subject, resource, action, error = %e,
                "Casbin IPC error while evaluating RBAC; denying by default"
            );
            false
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_permission_context_default_denies_everything() {
        let ctx = PermissionContext::default();
        assert!(!ctx.users_read);
        assert!(!ctx.users_write);
        assert!(!ctx.users_manage_admins);
        assert!(!ctx.assets_read);
        assert!(!ctx.assets_read_all);
        assert!(!ctx.assets_write);
        assert!(!ctx.groups_read);
        assert!(!ctx.groups_write);
        assert!(!ctx.groups_manage_members);
        assert!(!ctx.access_rules_read);
        assert!(!ctx.access_rules_write);
        assert!(!ctx.auth_sessions_read);
        assert!(!ctx.auth_sessions_write);
        assert!(!ctx.sessions_read);
        assert!(!ctx.sessions_write);
        assert!(!ctx.sessions_supervise);
        assert!(!ctx.sessions_bypass_access_rules);
        assert!(!ctx.admin_view);
        assert!(!ctx.profile_read);
        assert!(!ctx.profile_write);
    }

    #[test]
    fn test_permission_context_clone_eq() {
        let ctx = PermissionContext {
            users_read: true,
            admin_view: true,
            ..Default::default()
        };
        let cloned = ctx.clone();
        assert_eq!(ctx, cloned);
    }

    #[test]
    fn test_permission_context_debug_lists_fields() {
        let ctx = PermissionContext::default();
        let s = format!("{:?}", ctx);
        assert!(s.contains("PermissionContext"));
        assert!(s.contains("users_write"));
        assert!(s.contains("admin_view"));
    }
}
