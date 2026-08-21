//! Session helpers: current user, org membership, require_* gates.
//!
//! Anti-enumeration deny matrix:
//! - Missing session / wrong org / unknown slug / reserved `vauban` for
//!   non-staff / `/admin/*` for non-staff → **404**
//! - Capability **entry** after membership (`*_read`, compose `*_write`,
//!   admin secondary perms) → **404** via [`capability_denied`]
//! - Action on a **visible** resource (e.g. `builds_download`) → **403**
//! - Invisible / other-tenant object → **404**

use std::time::{SystemTime, UNIX_EPOCH};

use toasty::Db;
use topcoat::{
    Result,
    context::{Cx, app_context, memoize},
    router::error::{NotFoundError, RouterErrorExt, UnauthorizedError, not_found},
    session::{self, TokenHash},
};

use crate::{
    config::Config,
    db::{now_unix, token_hash_hex},
    models::{
        AuthSession, MEMBERSHIP_ROLE_ORG, Membership, Organization, PORTAL_ROLE_ADMIN,
        RESERVED_ORG_SLUG, User,
    },
};

#[derive(Debug, Clone)]
pub struct AuthUser {
    pub id: u64,
    pub email: String,
    pub display_name: String,
    /// Casbin role for this request (`org` or `admin`).
    pub role: String,
    /// Persisted `User.portal_role` (`admin` or `org`).
    pub portal_role: String,
}

pub fn db(cx: &Cx) -> Db {
    app_context::<Db>(cx).clone()
}

/// Application config from router `app_context`.
pub fn config(cx: &Cx) -> std::sync::Arc<Config> {
    app_context::<std::sync::Arc<Config>>(cx).clone()
}

/// Connected storage helper client from router `app_context`.
pub fn storage(cx: &Cx) -> std::sync::Arc<crate::storage::StorageClient> {
    app_context::<std::sync::Arc<crate::storage::StorageClient>>(cx).clone()
}

/// True when the persisted session expiry is at or before "now".
pub fn session_is_expired(expires_at: i64) -> bool {
    expires_at <= now_unix()
}

/// Capability entry denied: same **404** as an unknown path (anti-enumeration).
///
/// Use for module/shard Casbin gates after tenant/staff auth succeeds.
/// Do **not** use for visible-resource action denials (e.g. download).
pub fn capability_denied() -> NotFoundError {
    not_found()
}

/// Load a user for a persisted session token hash (hex). Returns `None` when
/// the session is missing, expired, the user row is gone, or soft-deleted.
pub async fn load_user_for_token_hex(db: &mut Db, hex: &str) -> Option<User> {
    let Ok(record) = AuthSession::get_by_token_hash(db, hex).await else {
        return None;
    };
    if session_is_expired(record.expires_at) {
        return None;
    }
    let user = User::get_by_id(db, record.user_id).await.ok()?;
    if !user.is_active() {
        let _ = AuthSession::delete_by_token_hash(db, hex).await;
        return None;
    }
    Some(user)
}

/// Delete every persisted session for a user (soft-delete / revoke).
pub async fn invalidate_sessions_for_user(db: &mut Db, user_id: u64) -> anyhow::Result<()> {
    let sessions = AuthSession::all()
        .filter(AuthSession::fields().user_id().eq(user_id))
        .exec(db)
        .await?;
    for session in sessions {
        let _ = AuthSession::delete_by_token_hash(db, &session.token_hash).await;
    }
    Ok(())
}

/// Persist or replace an `AuthSession` row (production path used by login and
/// test fixtures — no parallel store).
pub async fn persist_session_record(
    db: &mut Db,
    token_hash: String,
    user_id: u64,
    expires_at: i64,
) -> anyhow::Result<()> {
    let _ = AuthSession::delete_by_token_hash(db, &token_hash).await;
    toasty::create!(AuthSession {
        token_hash,
        user_id,
        expires_at,
    })
    .exec(db)
    .await?;
    Ok(())
}

#[memoize]
async fn session_user(cx: &Cx) -> Option<User> {
    let Ok(Some(token_hash)) = session::token_hash(cx).await else {
        return None;
    };
    load_user_by_token_hash(cx, &token_hash).await
}

async fn load_user_by_token_hash(cx: &Cx, token_hash: &TokenHash) -> Option<User> {
    let mut db = db(cx);
    let hex = token_hash_hex(token_hash);
    load_user_for_token_hex(&mut db, &hex).await
}

pub async fn current_user(cx: &Cx) -> Option<&User> {
    session_user(cx).await
}

pub async fn require_auth(cx: &Cx) -> Result<&User, UnauthorizedError> {
    current_user(cx).await.ok_or_unauthorized()
}

#[derive(Debug, Clone)]
pub struct OrgContext {
    pub org: Organization,
    pub user: AuthUser,
}

#[derive(Debug, Clone)]
pub struct StaffContext {
    pub user: AuthUser,
}

fn auth_user_from(user: &User, casbin_role: String) -> AuthUser {
    AuthUser {
        id: user.id,
        email: user.email.clone(),
        display_name: user.display_name.clone(),
        role: casbin_role,
        portal_role: user.portal_role.clone(),
    }
}

/// Resolve `{org}` slug + membership (memoized). `None` means missing auth,
/// org, or membership — callers map that to **404** (anti-enumeration).
///
/// Staff Casbin context uses `portal_role` (`admin`) even on `/vauban` preview.
/// Reserved org `vauban` is staff-only.
#[memoize]
async fn org_context(cx: &Cx, slug: &str) -> Option<OrgContext> {
    let user = require_auth(cx).await.ok()?;
    let mut db = db(cx);

    let org = Organization::get_by_slug(&mut db, slug).await.ok()?;

    let is_reserved = org.slug.eq_ignore_ascii_case(RESERVED_ORG_SLUG);
    if is_reserved && user.portal_role != PORTAL_ROLE_ADMIN {
        return None;
    }

    let membership = Membership::all()
        .filter(Membership::fields().user_id().eq(user.id))
        .filter(Membership::fields().organization_id().eq(org.id))
        .limit(1)
        .exec(&mut db)
        .await
        .ok()
        .and_then(|mut rows| rows.pop())?;

    // Memberships are always `org`; staff preview uses portal_role for Casbin.
    let casbin_role = if user.portal_role == PORTAL_ROLE_ADMIN {
        PORTAL_ROLE_ADMIN.to_owned()
    } else if membership.role == MEMBERSHIP_ROLE_ORG {
        MEMBERSHIP_ROLE_ORG.to_owned()
    } else {
        membership.role
    };

    Some(OrgContext {
        org,
        user: auth_user_from(user, casbin_role),
    })
}

/// Resolve `{org}` slug + membership. Fail with **404** when the org is
/// missing or the user is not a member (anti-enumeration).
///
/// Backed by memoized [`org_context`] so layout + page share one lookup.
pub async fn require_org(cx: &Cx, slug: &str) -> Result<OrgContext, NotFoundError> {
    org_context(cx, slug).await.cloned().ok_or_else(not_found)
}

/// Vauban Support gate for `/admin/*`. Missing session, client, or missing
/// `admin_view` → **404** (anti-enumeration: same answer as an unknown path).
pub async fn require_staff(cx: &Cx) -> Result<StaffContext> {
    let Some(user) = current_user(cx).await else {
        return Err(not_found().into());
    };
    if user.portal_role != PORTAL_ROLE_ADMIN {
        return Err(not_found().into());
    }
    let auth = auth_user_from(user, PORTAL_ROLE_ADMIN.to_owned());
    // Map Casbin denial to 404 so `/admin/*` never leaks via 403.
    if crate::perms::require_admin_view(cx, &auth).await.is_err() {
        return Err(not_found().into());
    }
    Ok(StaffContext { user: auth })
}

/// Fail-closed admin-on-org gate. Missing org/membership/`admin_view` → **404**.
#[allow(dead_code)]
pub async fn require_org_admin(cx: &Cx, slug: &str) -> Result<OrgContext, NotFoundError> {
    let ctx = require_org(cx, slug).await?;
    if crate::perms::require_admin_view(cx, &ctx.user)
        .await
        .is_err()
    {
        return Err(capability_denied());
    }
    Ok(ctx)
}

pub async fn persist_session(cx: &Cx, session: session::Session, user_id: u64) -> Result<()> {
    let mut db = db(cx);
    let token_hash = token_hash_hex(&session.token_hash);
    let expires_at = system_expires_unix(session.expires_at);
    persist_session_record(&mut db, token_hash, user_id, expires_at).await?;
    Ok(())
}

pub async fn delete_session_hash(cx: &Cx, token_hash: &TokenHash) -> Result<()> {
    let mut db = db(cx);
    let hex = token_hash_hex(token_hash);
    let _ = AuthSession::delete_by_token_hash(&mut db, &hex).await;
    Ok(())
}

/// Client organization visible in the post-auth picker (excludes reserved `vauban`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientOrg {
    pub slug: String,
    pub name: String,
}

/// Where an authenticated user should land after login / magic-link / `GET /`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PostAuthLanding {
    /// Direct navigate to `/{slug}` (staff → `vauban`, or single client org).
    Org(String),
    /// Multiple client memberships — show `/choose-org`.
    ChooseOrg,
    /// No usable client membership (org user with zero orgs).
    None,
}

/// Pure landing classification (unit / proptest).
///
/// `client_slugs` must already exclude the reserved tenant and be sorted if
/// callers care about which single slug is chosen when `len == 1`.
pub fn classify_post_auth_landing(portal_role: &str, client_slugs: &[String]) -> PostAuthLanding {
    if portal_role == PORTAL_ROLE_ADMIN {
        return PostAuthLanding::Org(RESERVED_ORG_SLUG.to_owned());
    }
    match client_slugs.len() {
        0 => PostAuthLanding::None,
        1 => PostAuthLanding::Org(client_slugs[0].clone()),
        _ => PostAuthLanding::ChooseOrg,
    }
}

/// Client orgs for `user_id`, excluding reserved `vauban`, sorted by slug.
pub async fn client_orgs_for_user(cx: &Cx, user_id: u64) -> Result<Vec<ClientOrg>> {
    let mut database = db(cx);
    let memberships = Membership::all()
        .filter(Membership::fields().user_id().eq(user_id))
        .exec(&mut database)
        .await
        .unwrap_or_default();
    if memberships.is_empty() {
        return Ok(Vec::new());
    }
    let org_ids: Vec<u64> = memberships.iter().map(|m| m.organization_id).collect();
    let orgs = crate::id_lookups::orgs_by_ids(&mut database, &org_ids)
        .await
        .unwrap_or_default();
    let mut clients: Vec<ClientOrg> = orgs
        .into_iter()
        .filter(|o| !o.slug.eq_ignore_ascii_case(RESERVED_ORG_SLUG))
        .map(|o| ClientOrg {
            slug: o.slug,
            name: o.name,
        })
        .collect();
    clients.sort_by(|a, b| a.slug.cmp(&b.slug));
    Ok(clients)
}

/// Resolve post-auth landing for an authenticated user.
pub async fn post_auth_landing(cx: &Cx, user: &User) -> Result<PostAuthLanding> {
    let clients = client_orgs_for_user(cx, user.id).await?;
    let slugs: Vec<String> = clients.into_iter().map(|o| o.slug).collect();
    Ok(classify_post_auth_landing(&user.portal_role, &slugs))
}

/// Landing org slug when a direct org is available; `None` for ChooseOrg / no orgs.
///
/// Prefer [`post_auth_landing`] at session entry points so multi-org users are
/// sent to `/choose-org` instead of an arbitrary first membership.
pub async fn home_org_slug(cx: &Cx, user: &User) -> Result<Option<String>> {
    Ok(match post_auth_landing(cx, user).await? {
        PostAuthLanding::Org(slug) => Some(slug),
        PostAuthLanding::ChooseOrg | PostAuthLanding::None => None,
    })
}

/// Pure landing-slug decision for the single-org / staff case (unit / proptest).
pub fn resolve_home_org_slug(
    portal_role: &str,
    first_client_slug: Option<String>,
) -> Option<String> {
    let slugs: Vec<String> = first_client_slug.into_iter().collect();
    match classify_post_auth_landing(portal_role, &slugs) {
        PostAuthLanding::Org(slug) => Some(slug),
        PostAuthLanding::ChooseOrg | PostAuthLanding::None => None,
    }
}

/// First client org slug (sorted); `None` if zero client memberships.
pub async fn first_client_org_slug(cx: &Cx, user_id: u64) -> Result<Option<String>> {
    let clients = client_orgs_for_user(cx, user_id).await?;
    Ok(clients.into_iter().next().map(|o| o.slug))
}

fn system_expires_unix(expires_at: SystemTime) -> i64 {
    expires_at
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::token_hash_hex;
    use topcoat::session::TokenHash;

    #[test]
    fn session_expiry_boundary() {
        let now = now_unix();
        assert!(session_is_expired(now));
        assert!(session_is_expired(now - 1));
        assert!(!session_is_expired(now + 3600));
    }

    #[test]
    fn token_hash_hex_encodes_32_bytes() {
        let raw = [0xabu8; 32];
        let hash = TokenHash::new(raw);
        let encoded = token_hash_hex(&hash);
        assert_eq!(encoded, hex::encode(raw));
        assert_eq!(encoded.len(), 64);
    }

    #[test]
    fn auth_tenant_resolve_home_org_slug_staff_uses_vauban() {
        assert_eq!(
            resolve_home_org_slug(PORTAL_ROLE_ADMIN, Some("acme".to_owned())).as_deref(),
            Some(RESERVED_ORG_SLUG)
        );
        assert_eq!(
            resolve_home_org_slug(PORTAL_ROLE_ADMIN, None).as_deref(),
            Some(RESERVED_ORG_SLUG)
        );
    }

    #[test]
    fn auth_tenant_resolve_home_org_slug_member_uses_client() {
        assert_eq!(
            resolve_home_org_slug(
                crate::models::PORTAL_ROLE_ORG,
                Some("acme-infrastructure".to_owned())
            )
            .as_deref(),
            Some("acme-infrastructure")
        );
        assert_eq!(
            resolve_home_org_slug(crate::models::PORTAL_ROLE_ORG, None),
            None
        );
    }

    #[test]
    fn classify_post_auth_landing_staff_zero_one_many() {
        assert_eq!(
            classify_post_auth_landing(PORTAL_ROLE_ADMIN, &[]),
            PostAuthLanding::Org(RESERVED_ORG_SLUG.to_owned())
        );
        assert_eq!(
            classify_post_auth_landing(PORTAL_ROLE_ADMIN, &["a".into(), "b".into()]),
            PostAuthLanding::Org(RESERVED_ORG_SLUG.to_owned())
        );
        assert_eq!(
            classify_post_auth_landing(crate::models::PORTAL_ROLE_ORG, &[]),
            PostAuthLanding::None
        );
        assert_eq!(
            classify_post_auth_landing(crate::models::PORTAL_ROLE_ORG, &["acme".into()]),
            PostAuthLanding::Org("acme".into())
        );
        assert_eq!(
            classify_post_auth_landing(
                crate::models::PORTAL_ROLE_ORG,
                &["acme".into(), "beta".into()]
            ),
            PostAuthLanding::ChooseOrg
        );
    }

    #[test]
    fn auth_tenant_capability_denied_is_not_found() {
        let err = capability_denied();
        let msg = format!("{err:?}");
        assert!(
            msg.to_ascii_lowercase().contains("not") || msg.contains("404") || !msg.is_empty(),
            "capability_denied must be a NotFoundError ({msg})"
        );
    }
}
