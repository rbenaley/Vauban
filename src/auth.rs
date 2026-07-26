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
    models::{AuthSession, Membership, Organization, User},
};

#[derive(Debug, Clone)]
pub struct AuthUser {
    #[allow(dead_code)]
    pub id: u64,
    #[allow(dead_code)]
    pub email: String,
    pub display_name: String,
    /// Active membership role for the current org request (empty if none).
    pub role: String,
}

pub fn db(cx: &Cx) -> Db {
    app_context::<Db>(cx).clone()
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
    let Ok(record) = AuthSession::get_by_token_hash(&mut db, &hex).await else {
        return None;
    };
    if record.expires_at <= now_unix() {
        return None;
    }
    User::get_by_id(&mut db, record.user_id).await.ok()
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

/// Resolve `{org}` slug + membership. Fail with **404** when the org is
/// missing or the user is not a member (anti-enumeration).
pub async fn require_org(cx: &Cx, slug: &str) -> Result<OrgContext, NotFoundError> {
    let user = match require_auth(cx).await {
        Ok(u) => u,
        Err(_) => return Err(not_found()),
    };
    let mut db = db(cx);

    let org = Organization::all()
        .filter(Organization::fields().slug().eq(slug))
        .exec(&mut db)
        .await
        .ok()
        .and_then(|mut rows| rows.pop())
        .ok_or_else(not_found)?;

    let membership = Membership::all()
        .filter(Membership::fields().user_id().eq(user.id))
        .filter(Membership::fields().organization_id().eq(org.id))
        .exec(&mut db)
        .await
        .ok()
        .and_then(|mut rows| rows.pop())
        .ok_or_else(not_found)?;

    Ok(OrgContext {
        org,
        user: AuthUser {
            id: user.id,
            email: user.email.clone(),
            display_name: user.display_name.clone(),
            role: membership.role,
        },
    })
}

/// Fail-closed admin gate (scaffold helper for upcoming admin mutations).
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
    let _ = AuthSession::delete_by_token_hash(&mut db, &token_hash).await;
    toasty::create!(AuthSession {
        token_hash,
        user_id,
        expires_at,
    })
    .exec(&mut db)
    .await?;
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
