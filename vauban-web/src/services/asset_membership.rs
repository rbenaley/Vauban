//! Asset–asset_group membership (many-to-many) helpers.

use diesel::dsl::count_star;
use diesel::ExpressionMethods;
use diesel::OptionalExtension;
use diesel::QueryDsl;
use diesel_async::{AsyncPgConnection, RunQueryDsl};

use crate::db::DbPool;
use crate::schema::asset_asset_groups::dsl as aag;

/// Returns true if at least one asset is linked to more than one asset group.
pub async fn any_asset_has_multiple_groups(
    conn: &mut AsyncPgConnection,
) -> Result<bool, diesel::result::Error> {
    let found: Option<i32> = aag::asset_asset_groups
        .group_by(aag::asset_id)
        .having(count_star().gt(1_i64))
        .select(aag::asset_id)
        .first(conn)
        .await
        .optional()?;

    Ok(found.is_some())
}

/// If `allow_multiple_groups_per_asset` is false but multi-group rows exist, log a warning.
pub async fn warn_if_single_group_mode_inconsistent_with_data(pool: &DbPool, allow_multiple: bool) {
    if allow_multiple {
        return;
    }
    let mut conn = match pool.get().await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "Could not verify asset group membership; skipping single-group mode consistency check"
            );
            return;
        }
    };
    match any_asset_has_multiple_groups(&mut conn).await {
        Ok(true) => {
            tracing::warn!(
                "allow_multiple_groups_per_asset is false but some assets belong to more than one asset group; \
                 single-group enforcement is not fully effective until memberships are corrected (remove extra group links)"
            );
        }
        Ok(false) => {}
        Err(e) => {
            tracing::warn!(
                error = %e,
                "Failed to query asset_asset_groups for single-group mode consistency check"
            );
        }
    }
}
