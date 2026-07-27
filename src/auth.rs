//! Session helpers: current user, org membership, require_* gates.

use std::time::{SystemTime, UNIX_EPOCH};

use toasty::Db;
use topcoat::{
    Result,
    context::{Cx, app_context, memoize},
    router::{
        ForbiddenError, NotFoundError, RouterErrorExt, UnauthorizedError, forbidden, not_found,
    },
    session::{self, TokenHash},
};

use crate::{
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
    /// Persisted `User.portal_role` (`admin` for Vauban Support, else empty).
    pub portal_role: String,
}

pub fn db(cx: &Cx) -> Db {
    app_context::<Db>(cx).clone()
}

/// True when the persisted session expiry is at or before "now".
pub fn session_is_expired(expires_at: i64) -> bool {
    expires_at <= now_unix()
}

/// Load a user for a persisted session token hash (hex). Returns `None` when
/// the session is missing, expired, or the user row is gone.
pub async fn load_user_for_token_hex(db: &mut Db, hex: &str) -> Option<User> {
    let Ok(record) = AuthSession::get_by_token_hash(db, hex).await else {
        return None;
    };
    if session_is_expired(record.expires_at) {
        return None;
    }
    User::get_by_id(db, record.user_id).await.ok()
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

    let org = Organization::all()
        .filter(Organization::fields().slug().eq(slug))
        .exec(&mut db)
        .await
        .ok()
        .and_then(|mut rows| rows.pop())?;

    let is_reserved = org.slug.eq_ignore_ascii_case(RESERVED_ORG_SLUG);
    if is_reserved && user.portal_role != PORTAL_ROLE_ADMIN {
        return None;
    }

    let membership = Membership::all()
        .filter(Membership::fields().user_id().eq(user.id))
        .filter(Membership::fields().organization_id().eq(org.id))
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

/// Vauban Support gate for `/admin/*`. Anonymous → **404**; authenticated
/// non-staff → **403**.
pub async fn require_staff(cx: &Cx) -> Result<StaffContext> {
    let Some(user) = current_user(cx).await else {
        return Err(not_found().into());
    };
    if user.portal_role != PORTAL_ROLE_ADMIN {
        return Err(forbidden().into());
    }
    let auth = auth_user_from(user, PORTAL_ROLE_ADMIN.to_owned());
    crate::perms::require_admin_view(cx, &auth).await?;
    Ok(StaffContext { user: auth })
}

/// Fail-closed admin gate (scaffold helper).
#[allow(dead_code)]
pub async fn require_org_admin(cx: &Cx, slug: &str) -> Result<OrgContext, ForbiddenError> {
    let ctx = match require_org(cx, slug).await {
        Ok(c) => c,
        Err(_) => return Err(forbidden()),
    };
    crate::perms::require_admin_view(cx, &ctx.user).await?;
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

fn system_expires_unix(expires_at: SystemTime) -> i64 {
    expires_at
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{hash_password, token_hash_hex, verify_password};
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
    fn password_helpers_reject_wrong_secret() {
        let hash = hash_password("correct-horse").unwrap();
        assert!(verify_password("correct-horse", &hash));
        assert!(!verify_password("wrong", &hash));
    }
}
