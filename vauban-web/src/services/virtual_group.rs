//! Boot-time resolver for the singleton "All assets" virtual asset group,
//! mirrored on the web side.
//!
//! See [`vauban_access::virtual_group`] for the access-side counterpart.
//! This module exists because vauban-web also needs the internal `id` of
//! the virtual row to special-case it in
//! [`crate::services::access::list_accessible_asset_ids`] and
//! [`crate::services::access::can_access_asset`] (the per-user asset
//! reachability and per-asset access checks). Both layers must agree, or
//! the proxy-side AccessGuard re-check would silently disagree with the
//! UI-side decision.
//!
//! Loaded once at boot via `OnceLock` from
//! [`shared::messages::ALL_ASSETS_GROUP_UUID`]. Fail-loud if missing.

use anyhow::{Context, Result};
use diesel::prelude::*;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use std::sync::OnceLock;

/// Sentinel returned by [`virtual_asset_group_id`] before
/// [`init_or_die`] runs. Negative on purpose so it can never collide
/// with a real `SERIAL` id and any stray reference fails closed.
pub const UNINITIALIZED_VIRTUAL_ID: i32 = i32::MIN;

static VIRTUAL_GROUP_ID: OnceLock<i32> = OnceLock::new();

/// Read-only accessor.
pub fn virtual_asset_group_id() -> i32 {
    *VIRTUAL_GROUP_ID.get().unwrap_or(&UNINITIALIZED_VIRTUAL_ID)
}

/// Stateless query: resolve the virtual group's internal id from the
/// DB without touching the [`OnceLock`].
///
/// Exposed so adversarial / boot-time tests can drive the same lookup
/// path as [`init_or_die`] against a tampered DB without mutating the
/// process-wide cache.
pub async fn resolve_id_for_test(conn: &mut AsyncPgConnection) -> Result<i32> {
    resolve_id(conn).await
}

async fn resolve_id(conn: &mut AsyncPgConnection) -> Result<i32> {
    use crate::schema::asset_groups;
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
             Re-run migration 20260424000000_virtual_asset_group_all to recover. \
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

/// Boot-time initializer. Resolve the virtual group's internal id.
///
/// Hard-fails on missing row or wrong `kind` -- the recovery procedure
/// is documented in `docs/runbooks/virtual_asset_group.md`.
pub async fn init_or_die(conn: &mut AsyncPgConnection) -> Result<i32> {
    use shared::messages::ALL_ASSETS_GROUP_UUID;

    let id = resolve_id(conn).await?;
    let _ = VIRTUAL_GROUP_ID.set(id);
    let cached = virtual_asset_group_id();
    if cached != id {
        anyhow::bail!(
            "virtual_group: OnceLock raced and was set to {}, expected {}",
            cached,
            id
        );
    }
    tracing::info!(
        virtual_group_id = id,
        uuid = ALL_ASSETS_GROUP_UUID,
        "Virtual 'All assets' group resolved at boot (vauban-web)"
    );
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uninitialized_sentinel_cannot_match_real_id() {
        assert!(UNINITIALIZED_VIRTUAL_ID < 0);
    }
}
