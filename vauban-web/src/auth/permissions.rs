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
    /// Manage the asset catalogue: full CRUD (create, edit, delete, view-detail
    /// in the admin zone) on the `proxy_assets` table, plus admin-only side
    /// operations such as fetching SSH host keys. This is the SOLE permission
    /// gating the `/assets/manage/*` admin sub-tree (issue #27, asset zone
    /// split). Holders are staff and superuser; regular users do NOT have it.
    /// **No session can ever be opened from the admin zone**: source-level CI
    /// tests (see `tests/web/manage_assets_no_session_test.rs`) pin that
    /// invariant. Renamed from the legacy "write" action in v0.6.x; the
    /// rename is intentional - the old name suggested only mutation, but
    /// the gate is now also used for admin-side reads (asset detail,
    /// deleted audit) so a "manage" semantic is more accurate.
    pub assets_manage: bool,
    pub groups_read: bool,
    /// CRUD on the group itself (create, edit, delete). Granted to staff and
    /// superuser.
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
    /// Submit a new EWS onboarding request (`POST /iacs/onboard`),
    /// edit a pending request, cancel a pending request, or
    /// auto-offboard one of the caller's own approved EWS. Granted to
    /// every `role:user` and `role:staff` by default; the per-deployment
    /// Casbin policy can narrow the scope further.
    ///
    /// Subject to the global kill-switch: when
    /// `config.industrial.enabled == false`, this flag is forced to
    /// `false` regardless of the policy decision (the IACS surface is
    /// fully hidden / 404'd in that mode).
    pub iacs_request: bool,
    /// Read the caller's own EWS catalogue (in `/sessions/my-requests`
    /// and equivalent self-service pages). Granted to every
    /// `role:user` and `role:staff`. Subject to the same kill-switch as
    /// `iacs_request`.
    pub iacs_read: bool,
    /// Admin CRUD on the IACS / EWS surface (admin list, approve,
    /// reject with reason, disable, enable, offboard). Granted to
    /// `role:staff` and `role:superuser` (via wildcard). Subject to
    /// the same kill-switch as `iacs_request`.
    pub iacs_manage: bool,
    /// Open an IACS tunnel session against an asset (`POST
    /// /assets/{uuid}/connect-iacs`). Granted to `role:user` and
    /// `role:staff` by default; gated by the in-process `services::iacs_tunnel`
    /// pipeline AND the `assets:read` + access-rule chain just like
    /// SSH/RDP `Connect`. Subject to the global kill-switch:
    /// `[industrial].enabled = false` forces the flag to `false`,
    /// regardless of the policy decision.
    pub assets_connect_iacs: bool,
    /// Consume the organisational vault-secrets M2M API
    /// (`GET /api/v1/vault/secrets*`). This is the FUNCTIONAL capability
    /// only; the instance-level decision (which secrets) is governed by
    /// `secret_access_rules` evaluated in vauban-access, with NO
    /// superuser/read_all bypass. Granted to `role:user` and
    /// `role:staff` by default.
    pub vault_secrets_read: bool,
    /// Admin CRUD on the "Vault Secrets" section (`/vault/secrets/*`):
    /// secrets (write-only values), secret groups + membership, and
    /// secret access rules. Granted to `role:staff` and
    /// `role:superuser` (via wildcard). Holding `manage` does NOT
    /// imply the right to read a secret VALUE through the API -- that
    /// path stays behind a covering secret_access_rule.
    pub vault_secrets_manage: bool,
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
            assets_manage,
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
            iacs_request,
            iacs_read,
            iacs_manage,
            assets_connect_iacs,
            vault_secrets_read,
            vault_secrets_manage,
        ) = tokio::join!(
            check_rbac(state, user, "users", "read"),
            check_rbac(state, user, "users", "write"),
            check_rbac(state, user, "users", "manage_admins"),
            check_rbac(state, user, "assets", "read"),
            check_rbac(state, user, "assets", "read_all"),
            check_rbac(state, user, "assets", "manage"),
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
            check_rbac(state, user, "iacs", "request"),
            check_rbac(state, user, "iacs", "read"),
            check_rbac(state, user, "iacs", "manage"),
            check_rbac(state, user, "assets", "connect_iacs"),
            check_rbac(state, user, "vault_secrets", "read"),
            check_rbac(state, user, "vault_secrets", "manage"),
        );

        // Kill-switch precedence: `[industrial].enabled = false` forces
        // every `iacs_*` permission to `false` regardless of the policy
        // decision. The flag is meant to fully hide the IACS surface
        // (sidebar, routes, button); a partial gate would leak the
        // module's existence via 403 responses or partial UI elements.
        let industrial_enabled = state.config.industrial.enabled;

        Self {
            users_read,
            users_write,
            users_manage_admins,
            assets_read,
            assets_read_all,
            assets_manage,
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
            iacs_request: iacs_request && industrial_enabled,
            iacs_read: iacs_read && industrial_enabled,
            iacs_manage: iacs_manage && industrial_enabled,
            // The IACS tunnel pipeline (handler + sshd) refuses to
            // operate when the kill-switch is off, so collapsing the
            // permission to `false` mirrors the fail-closed posture
            // of the other `iacs_*` flags. The user-zone Connect
            // button is hidden in that mode (see asset_list.html).
            assets_connect_iacs: assets_connect_iacs && industrial_enabled,
            vault_secrets_read,
            vault_secrets_manage,
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
        assert!(!ctx.assets_manage);
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
        assert!(!ctx.iacs_request);
        assert!(!ctx.iacs_read);
        assert!(!ctx.iacs_manage);
        assert!(!ctx.assets_connect_iacs);
        assert!(!ctx.vault_secrets_read);
        assert!(!ctx.vault_secrets_manage);
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
