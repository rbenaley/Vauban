//! Boot-time resolver for the singleton "All assets" virtual asset group.
//!
//! See `docs/runbooks/virtual_asset_group.md` for the recovery procedure.
//!
//! Why a `OnceLock`?
//! ---------------
//! The virtual group's UUID is pinned by the migration
//! (`20260424000000_virtual_asset_group_all`) to
//! [`shared::messages::ALL_ASSETS_GROUP_UUID`]. Its DB-internal `id`,
//! however, depends on insertion order and is therefore environment-
//! specific. We resolve the UUID -> id mapping ONCE at boot, before the
//! Capsicum sandbox closes, and cache the answer in this `OnceLock` so the
//! hot path (`handle_check_access_by_uuid`, `handle_check_access_multi`)
//! never reaches the DB just to look up a constant.
//!
//! The cached id is the contract surface: every code path that wants to
//! know "is this row the virtual group" must compare against
//! [`virtual_asset_group_id`] -- never grep the schema, never rebind to a
//! random id at request time. That keeps the membership/mutation
//! invariants single-sourced (the trigger plus the partial unique index
//! are the DB-side guards; this constant is the application-side guard).
//!
//! Fail-loud at boot
//! -----------------
//! If the row is absent at boot, [`init_or_die`] aborts the process with a
//! structured error. The migration is the recovery procedure -- re-running
//! it is `ON CONFLICT DO NOTHING` and self-heals.

use crate::db::{DbConnection, DbPool};
use anyhow::{Context, Result};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use std::sync::OnceLock;
use vauban_db::schema::asset_groups;

/// Sentinel value returned by [`virtual_asset_group_id`] before
/// [`init_or_die`] has populated the cache. Negative so it can never
/// collide with a real `SERIAL` id and so a stray reference fails closed
/// (no row will ever match `id = i32::MIN`).
pub const UNINITIALIZED_VIRTUAL_ID: i32 = i32::MIN;

static VIRTUAL_GROUP_ID: OnceLock<i32> = OnceLock::new();

/// Read-only accessor.
///
/// Returns [`UNINITIALIZED_VIRTUAL_ID`] before [`init_or_die`] runs --
/// that value cannot match any real row, so callers degrade to
/// "no virtual rule applies" rather than incorrectly granting access.
pub fn virtual_asset_group_id() -> i32 {
    *VIRTUAL_GROUP_ID.get().unwrap_or(&UNINITIALIZED_VIRTUAL_ID)
}

/// Boot-time initializer. Resolve the virtual group's internal id from
/// the seeded UUID and stash it in the process-global `OnceLock`.
///
/// Hard-fails if the row is missing or carries the wrong `kind` -- the
/// supervisor will respawn us; the operator must re-run the migration.
pub async fn init_or_die(pool: &DbPool) -> Result<i32> {
    use shared::messages::{ALL_ASSETS_GROUP_UUID, ASSET_GROUP_KIND_ALL};

    let mut conn = pool
        .get()
        .await
        .context("virtual_group::init_or_die: db pool acquire failed")?;
    let id = lookup(&mut conn).await?;
    // Idempotent: re-initialization with the same id is a no-op.
    let _ = VIRTUAL_GROUP_ID.set(id);
    let cached = virtual_asset_group_id();
    if cached != id {
        anyhow::bail!(
            "virtual_group: OnceLock raced and was set to {}, expected {} \
             (re-init attempt with conflicting id?)",
            cached,
            id,
        );
    }
    tracing::info!(
        virtual_group_id = id,
        uuid = ALL_ASSETS_GROUP_UUID,
        kind = ASSET_GROUP_KIND_ALL,
        "Virtual 'All assets' group resolved at boot"
    );
    Ok(id)
}

async fn lookup(conn: &mut DbConnection) -> Result<i32> {
    use shared::messages::{ALL_ASSETS_GROUP_UUID, ASSET_GROUP_KIND_ALL};

    let target_uuid = uuid::Uuid::parse_str(ALL_ASSETS_GROUP_UUID)
        .context("ALL_ASSETS_GROUP_UUID is malformed")?;
    let row: Option<(i32, String)> = asset_groups::table
        .filter(asset_groups::uuid.eq(target_uuid))
        .select((asset_groups::id, asset_groups::kind))
        .first::<(i32, String)>(conn)
        .await
        .optional()
        .context("virtual_group: DB query for the seeded row failed")?;

    let (id, kind) = row.ok_or_else(|| {
        anyhow::anyhow!(
            "virtual_group: the seeded 'All assets' row (uuid={}) is missing. \
             Re-run migration 20260424000000_virtual_asset_group_all to recover \
             (the seed INSERT is ON CONFLICT-safe and acts as a self-heal). \
             See docs/runbooks/virtual_asset_group.md.",
            ALL_ASSETS_GROUP_UUID
        )
    })?;
    if kind != ASSET_GROUP_KIND_ALL {
        anyhow::bail!(
            "virtual_group: row uuid={} exists but kind={:?}, expected {:?}. \
             The singleton invariant is corrupt; refusing to serve traffic.",
            ALL_ASSETS_GROUP_UUID,
            kind,
            ASSET_GROUP_KIND_ALL
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
        // virtual_asset_group_id() before init fails closed.
        assert!(UNINITIALIZED_VIRTUAL_ID < 0);
        assert_ne!(UNINITIALIZED_VIRTUAL_ID, 0);
    }
}
