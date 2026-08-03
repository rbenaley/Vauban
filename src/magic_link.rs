//! One-shot magic-link tokens (hash-at-rest).

use std::time::{SystemTime, UNIX_EPOCH};

use argon2::password_hash::rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use toasty::Db;

use crate::models::{MAGIC_LINK_NOT_CONSUMED, MagicLinkToken, USER_NOT_DELETED, User};

/// Generate a raw URL-safe token and its SHA-256 hex digest.
pub fn generate_raw_token() -> (String, String) {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let raw = hex::encode(bytes);
    let hash = hash_token(&raw);
    (raw, hash)
}

/// SHA-256 hex of a raw magic-link token.
pub fn hash_token(raw: &str) -> String {
    let digest = Sha256::digest(raw.as_bytes());
    hex::encode(digest)
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Persist a new magic-link token for `user_id`. Returns the raw token for emailing.
///
/// Any previously unused tokens for this user are invalidated first so only the
/// latest link remains valid (single active magic link per account).
pub async fn issue_token(db: &mut Db, user_id: u64, ttl_secs: u64) -> anyhow::Result<String> {
    invalidate_tokens_for_user(db, user_id).await?;
    let (raw, token_hash) = generate_raw_token();
    let now = now_unix();
    let expires_at = now + ttl_secs as i64;
    toasty::create!(MagicLinkToken {
        token_hash,
        user_id,
        expires_at,
        consumed_at: MAGIC_LINK_NOT_CONSUMED,
        created_at: now,
    })
    .exec(db)
    .await?;
    Ok(raw)
}

/// Consume a raw token: returns the active user on success.
pub async fn consume_token(db: &mut Db, raw_token: &str) -> anyhow::Result<Option<User>> {
    let token_hash = hash_token(raw_token);
    let Ok(mut record) = MagicLinkToken::get_by_token_hash(db, &token_hash).await else {
        return Ok(None);
    };
    let now = now_unix();
    if record.consumed_at != MAGIC_LINK_NOT_CONSUMED {
        return Ok(None);
    }
    if record.expires_at < now {
        return Ok(None);
    }

    let Ok(user) = User::get_by_id(db, record.user_id).await else {
        return Ok(None);
    };
    if user.deleted_at != USER_NOT_DELETED {
        return Ok(None);
    }

    // Mark consumed before returning (one-shot).
    record.update().consumed_at(now).exec(db).await?;
    Ok(Some(user))
}

/// Invalidate all unused tokens for a user (re-issue, soft-delete / revoke).
pub async fn invalidate_tokens_for_user(db: &mut Db, user_id: u64) -> anyhow::Result<()> {
    let now = now_unix();
    let tokens = MagicLinkToken::all()
        .filter(MagicLinkToken::fields().user_id().eq(user_id))
        .filter(
            MagicLinkToken::fields()
                .consumed_at()
                .eq(MAGIC_LINK_NOT_CONSUMED),
        )
        .exec(db)
        .await?;
    for mut token in tokens {
        token.update().consumed_at(now).exec(db).await?;
    }
    Ok(())
}

/// Look up an active (not soft-deleted) user by email.
pub async fn active_user_by_email(db: &mut Db, email: &str) -> anyhow::Result<Option<User>> {
    let users = User::all()
        .filter(User::fields().email().eq(email))
        .exec(db)
        .await?;
    Ok(users.into_iter().find(|u| u.is_active()))
}

/// Look up any user row by email (including soft-deleted), for revive paths.
pub async fn user_by_email_any(db: &mut Db, email: &str) -> anyhow::Result<Option<User>> {
    let users = User::all()
        .filter(User::fields().email().eq(email))
        .exec(db)
        .await?;
    Ok(users.into_iter().next())
}

/// Ensure the configured `vcp_admin` user exists as active staff with `/vauban` membership.
pub async fn ensure_vcp_admin_user(db: &mut Db, email: &str) -> anyhow::Result<User> {
    use crate::models::{
        MEMBERSHIP_ROLE_ORG, Membership, Organization, PORTAL_ROLE_ADMIN, RESERVED_ORG_SLUG,
    };

    let email = email.trim().to_ascii_lowercase();
    let user = if let Some(mut existing) = user_by_email_any(db, &email).await? {
        existing
            .update()
            .display_name("Vauban Support".to_owned())
            .portal_role(PORTAL_ROLE_ADMIN.to_owned())
            .deleted_at(USER_NOT_DELETED)
            .exec(db)
            .await?;
        User::get_by_id(db, existing.id).await?
    } else {
        toasty::create!(User {
            email: email.clone(),
            display_name: "Vauban Support".to_owned(),
            portal_role: PORTAL_ROLE_ADMIN.to_owned(),
            deleted_at: USER_NOT_DELETED,
        })
        .exec(db)
        .await?
    };

    let vauban = {
        let rows = Organization::all()
            .filter(Organization::fields().slug().eq(RESERVED_ORG_SLUG))
            .exec(db)
            .await?;
        if let Some(org) = rows.into_iter().next() {
            org
        } else {
            toasty::create!(Organization {
                slug: RESERVED_ORG_SLUG.to_owned(),
                name: "Vauban".to_owned(),
                address: "Vauban — reserved preview tenant".to_owned(),
                vat: String::new(),
                plan_label: "Internal · Vauban Support".to_owned(),
                supported_builds: "LTS".to_owned(),
                lts_subscriptions: 0,
                industrial_lts_subscriptions: 0,
                technical_contact_name: "Vauban Support".to_owned(),
                technical_contact_email: email.clone(),
                status: "INTERNAL".to_owned(),
            })
            .exec(db)
            .await?
        }
    };

    let memberships = Membership::all()
        .filter(Membership::fields().user_id().eq(user.id))
        .filter(Membership::fields().organization_id().eq(vauban.id))
        .exec(db)
        .await?;
    if memberships.is_empty() {
        toasty::create!(Membership {
            user_id: user.id,
            organization_id: vauban.id,
            role: MEMBERSHIP_ROLE_ORG.to_owned(),
        })
        .exec(db)
        .await?;
    }

    Ok(user)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_raw_token_is_hex_and_hashes_stably() {
        let (raw, hash) = generate_raw_token();
        assert_eq!(raw.len(), 64);
        assert_eq!(hash, hash_token(&raw));
        assert_ne!(hash, raw);
    }

    #[test]
    fn hash_token_is_deterministic() {
        assert_eq!(hash_token("abc"), hash_token("abc"));
        assert_ne!(hash_token("abc"), hash_token("abd"));
    }
}

#[cfg(test)]
mod proptest_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        fn hash_token_unique_for_distinct_inputs(a in "[0-9a-f]{8,64}", b in "[0-9a-f]{8,64}") {
            prop_assume!(a != b);
            prop_assert_ne!(hash_token(&a), hash_token(&b));
        }
    }

    proptest! {
        fn generate_raw_token_always_64_hex(_ in 0u8..32) {
            let (raw, hash) = generate_raw_token();
            prop_assert_eq!(raw.len(), 64);
            prop_assert!(raw.chars().all(|c| c.is_ascii_hexdigit()));
            prop_assert_eq!(hash.len(), 64);
        }
    }
}
