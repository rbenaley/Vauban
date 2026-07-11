//! Boot-time resolver for the singleton "All secrets" virtual secret group.
//!
//! Mirror of [`crate::virtual_group`] for the organisational vault-secrets
//! machinery. The virtual group's UUID is pinned by the migration
//! (`20260711000000_vault_secrets`) to
//! [`shared::messages::ALL_SECRETS_GROUP_UUID`]; its DB-internal `id` is
//! environment-specific, so we resolve the UUID -> id mapping ONCE at boot
//! and cache it in a `OnceLock`.
//!
//! Fail-loud at boot: if the row is absent, [`init_or_die`] aborts the
//! process with a structured error. Re-run the migration to recover (the
//! seed INSERT is ON CONFLICT-safe and acts as a self-heal). See
//! `docs/runbooks/virtual_asset_group.md` for the equivalent asset-side
//! recovery procedure -- the same steps apply with the secrets migration.

use crate::db::{DbConnection, DbPool};
use anyhow::{Context, Result};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use std::sync::OnceLock;
use vauban_db::schema::secret_groups;

/// Sentinel value returned by [`virtual_secret_group_id`] before
/// [`init_or_die`] has populated the cache. Negative so it can never
/// collide with a real `SERIAL` id and so a stray reference fails closed
/// (no row will ever match `id = i32::MIN`).
pub const UNINITIALIZED_VIRTUAL_ID: i32 = i32::MIN;

static VIRTUAL_SECRET_GROUP_ID: OnceLock<i32> = OnceLock::new();

/// Read-only accessor.
///
/// Returns [`UNINITIALIZED_VIRTUAL_ID`] before [`init_or_die`] runs --
/// that value cannot match any real row, so callers degrade to
/// "no virtual rule applies" rather than incorrectly granting access.
pub fn virtual_secret_group_id() -> i32 {
    *VIRTUAL_SECRET_GROUP_ID
        .get()
        .unwrap_or(&UNINITIALIZED_VIRTUAL_ID)
}

/// Boot-time initializer. Resolve the virtual group's internal id from
/// the seeded UUID and stash it in the process-global `OnceLock`.
///
/// Hard-fails if the row is missing or carries the wrong `kind` -- the
/// supervisor will respawn us; the operator must re-run the migration.
pub async fn init_or_die(pool: &DbPool) -> Result<i32> {
    use shared::messages::{ALL_SECRETS_GROUP_UUID, SECRET_GROUP_KIND_ALL};

    let mut conn = pool
        .get()
        .await
        .context("virtual_secret_group::init_or_die: db pool acquire failed")?;
    let id = lookup(&mut conn).await?;
    // Idempotent: re-initialization with the same id is a no-op.
    let _ = VIRTUAL_SECRET_GROUP_ID.set(id);
    let cached = virtual_secret_group_id();
    if cached != id {
        anyhow::bail!(
            "virtual_secret_group: OnceLock raced and was set to {}, expected {} \
             (re-init attempt with conflicting id?)",
            cached,
            id,
        );
    }
    tracing::info!(
        virtual_secret_group_id = id,
        uuid = ALL_SECRETS_GROUP_UUID,
        kind = SECRET_GROUP_KIND_ALL,
        "Virtual 'All secrets' group resolved at boot"
    );
    Ok(id)
}

async fn lookup(conn: &mut DbConnection) -> Result<i32> {
    use shared::messages::{ALL_SECRETS_GROUP_UUID, SECRET_GROUP_KIND_ALL};

    let target_uuid = uuid::Uuid::parse_str(ALL_SECRETS_GROUP_UUID)
        .context("ALL_SECRETS_GROUP_UUID is malformed")?;
    let row: Option<(i32, String)> = secret_groups::table
        .filter(secret_groups::uuid.eq(target_uuid))
        .select((secret_groups::id, secret_groups::kind))
        .first::<(i32, String)>(conn)
        .await
        .optional()
        .context("virtual_secret_group: DB query for the seeded row failed")?;

    let (id, kind) = row.ok_or_else(|| {
        anyhow::anyhow!(
            "virtual_secret_group: the seeded 'All secrets' row (uuid={}) is missing. \
             Re-run migration 20260711000000_vault_secrets to recover \
             (the seed INSERT is ON CONFLICT-safe and acts as a self-heal).",
            ALL_SECRETS_GROUP_UUID
        )
    })?;
    if kind != SECRET_GROUP_KIND_ALL {
        anyhow::bail!(
            "virtual_secret_group: row uuid={} exists but kind={:?}, expected {:?}. \
             The singleton invariant is corrupt; refusing to serve traffic.",
            ALL_SECRETS_GROUP_UUID,
            kind,
            SECRET_GROUP_KIND_ALL
        );
    }
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uninitialized_sentinel_cannot_match_real_id() {
        // SERIAL columns in Postgres are 1-based; i32::MIN is structurally
        // disjoint from any real id, so a stray reference to
        // virtual_secret_group_id() before init fails closed.
        const _: () = assert!(UNINITIALIZED_VIRTUAL_ID < 0);
        const _: () = assert!(UNINITIALIZED_VIRTUAL_ID != 0);
    }
}
