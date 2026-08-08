//! Casbin-format policy loader (`PolicyStore`) and request-scoped
//! `PermissionContext`.
//!
//! VCP does not depend on the `casbin` crate and does not read a Casbin
//! `model.conf`. Grants live in `config/access/vcp_policy.csv`
//! (`p, role:…, resource, action`); exact-match lookups feed
//! `PermissionContext` flags used by pages, shards, and `view!`.

use std::{collections::HashSet, fs, path::Path, sync::Arc};

use topcoat::{
    context::{Cx, app_context, memoize},
    router::error::{ForbiddenError, RouterErrorExt},
};

use crate::auth::AuthUser;

/// Tracked (resource, action) couples — keep in lock-step with
/// `config/access/vcp_policy.csv` (see drift test).
#[cfg_attr(not(test), allow(dead_code))]
pub const TRACKED_PERMS: &[(&str, &str)] = &[
    ("docs", "read"),
    ("docs", "write"),
    ("builds", "read"),
    ("builds", "download"),
    ("releases", "manage"),
    ("issues", "read"),
    ("issues", "write"),
    ("companies", "manage"),
    ("key", "manage"),
    ("account", "read"),
    ("admin", "view"),
];

#[derive(Debug, Clone, Default)]
pub struct PermissionContext {
    pub docs_read: bool,
    pub docs_write: bool,
    pub builds_read: bool,
    pub builds_download: bool,
    pub releases_manage: bool,
    pub issues_read: bool,
    pub issues_write: bool,
    pub companies_manage: bool,
    pub key_manage: bool,
    pub account_read: bool,
    pub admin_view: bool,
}

#[derive(Debug, Clone)]
pub struct PolicyStore {
    /// Grants: (`role:name`, resource, action)
    grants: HashSet<(String, String, String)>,
}

impl PolicyStore {
    pub fn load_from_csv(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let text = fs::read_to_string(path.as_ref())?;
        let mut grants = HashSet::new();
        for (line_no, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<_> = line.split(',').map(str::trim).collect();
            if parts.len() != 4 || parts[0] != "p" {
                anyhow::bail!(
                    "invalid policy line {}: expected `p, sub, obj, act`",
                    line_no + 1
                );
            }
            grants.insert((
                parts[1].to_owned(),
                parts[2].to_owned(),
                parts[3].to_owned(),
            ));
        }
        Ok(Self { grants })
    }

    pub fn default_path() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config/access/vcp_policy.csv")
    }

    pub fn allows(&self, role: &str, resource: &str, action: &str) -> bool {
        let sub = if role.starts_with("role:") {
            role.to_owned()
        } else {
            format!("role:{role}")
        };
        self.grants
            .contains(&(sub, resource.to_owned(), action.to_owned()))
    }

    pub fn context_for_role(&self, role: &str) -> PermissionContext {
        PermissionContext {
            docs_read: self.allows(role, "docs", "read"),
            docs_write: self.allows(role, "docs", "write"),
            builds_read: self.allows(role, "builds", "read"),
            builds_download: self.allows(role, "builds", "download"),
            releases_manage: self.allows(role, "releases", "manage"),
            issues_read: self.allows(role, "issues", "read"),
            issues_write: self.allows(role, "issues", "write"),
            companies_manage: self.allows(role, "companies", "manage"),
            key_manage: self.allows(role, "key", "manage"),
            account_read: self.allows(role, "account", "read"),
            admin_view: self.allows(role, "admin", "view"),
        }
    }
}

pub fn policy(cx: &Cx) -> Arc<PolicyStore> {
    app_context::<Arc<PolicyStore>>(cx).clone()
}

#[memoize]
pub async fn require_perms(cx: &Cx, role: &str) -> PermissionContext {
    policy(cx).context_for_role(role)
}

pub async fn perms_for_user(cx: &Cx, user: &AuthUser) -> PermissionContext {
    require_perms(cx, user.role.as_str()).await.clone()
}

#[allow(dead_code)]
pub async fn require_admin_view(cx: &Cx, user: &AuthUser) -> Result<(), ForbiddenError> {
    let perms = perms_for_user(cx, user).await;
    perms.admin_view.then_some(()).ok_or_forbidden()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vcp_policy_grants_every_tracked_permission() {
        let store = PolicyStore::load_from_csv(PolicyStore::default_path()).unwrap();
        for &(resource, action) in TRACKED_PERMS {
            let granted = store
                .grants
                .iter()
                .any(|(_, r, a)| r == resource && a == action);
            assert!(
                granted,
                "tracked permission {resource}:{action} missing from vcp_policy.csv"
            );
        }
    }

    #[test]
    fn org_role_cannot_manage_releases() {
        let store = PolicyStore::load_from_csv(PolicyStore::default_path()).unwrap();
        let ctx = store.context_for_role("org");
        assert!(ctx.docs_read);
        assert!(!ctx.docs_write);
        assert!(!ctx.releases_manage);
        assert!(!ctx.key_manage);
        assert!(!ctx.admin_view);
        assert!(ctx.issues_write);
    }

    #[test]
    fn admin_can_view_admin_nest() {
        let store = PolicyStore::load_from_csv(PolicyStore::default_path()).unwrap();
        let ctx = store.context_for_role("admin");
        assert!(ctx.admin_view);
        assert!(ctx.releases_manage);
        assert!(ctx.companies_manage);
        assert!(ctx.key_manage);
        assert!(ctx.docs_write);
    }
}
