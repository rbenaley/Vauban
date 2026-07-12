/// VAUBAN Web - Organisational vault secret access service.
///
/// Determines which vault secrets a user can read, based on
/// `secret_access_rules` linking user groups (`vauban_groups`) to secret
/// groups (`secret_groups`). Mirror of [`crate::services::access`] for
/// the PAM asset surface, but deliberately independent from it: no
/// protocols, no MFA, no JIT — a rule either covers a secret group in
/// its validity window or it does not.
///
/// All decisions are delegated to vauban-access via IPC (single oracle);
/// only the `secret_secret_groups` junction is resolved locally, exactly
/// like `asset_asset_groups` on the asset side.
///
/// SECURITY: there is NO `read_all`-style bypass. Even a superuser must
/// be covered by an explicit rule to read a secret value.
use diesel::prelude::*;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use std::sync::Arc;

use crate::error::AppError;
use crate::ipc::AccessIpcClient;

/// Return the IDs of all vault secrets accessible to a given user via
/// active, temporally valid secret access rules, for a call originating
/// from the identity-verified `source_asset_id` (provenance dimension:
/// only rules whose asset group contains that asset — directly or via
/// the virtual "All assets" group — participate).
///
/// The IPC service computes the set of accessible secret groups (with a
/// flag for the virtual "All secrets" singleton); local DB is only used
/// to resolve those groups to secret IDs and filter inactive rows.
///
/// Fail-closed: returns an empty Vec on IPC error.
pub async fn list_accessible_secret_ids(
    access_client: &Arc<AccessIpcClient>,
    conn: &mut AsyncPgConnection,
    user_id: i32,
    source_asset_id: i32,
) -> Result<Vec<i32>, AppError> {
    use crate::schema::{secret_secret_groups, vault_secrets};

    let entries = match access_client
        .list_accessible_secret_groups(user_id, source_asset_id)
        .await
    {
        Ok(e) => e,
        Err(err) => {
            tracing::error!(
                user_id, source_asset_id, error = %err,
                "list_accessible_secret_groups IPC call failed; returning empty set (fail-closed)"
            );
            return Ok(Vec::new());
        }
    };

    let mut all_ids = Vec::new();
    for entry in entries {
        // The virtual "All secrets" group has zero junction rows by
        // trigger invariant: resolve it to every active secret instead
        // of joining `secret_secret_groups`.
        if entry.is_virtual_all {
            let ids: Vec<i32> = vault_secrets::table
                .filter(vault_secrets::is_active.eq(true))
                .select(vault_secrets::id)
                .load(conn)
                .await
                .map_err(AppError::Database)?;
            all_ids.extend(ids);
            continue;
        }
        let ids: Vec<i32> = vault_secrets::table
            .inner_join(
                secret_secret_groups::table
                    .on(vault_secrets::id.eq(secret_secret_groups::secret_id)),
            )
            .filter(secret_secret_groups::secret_group_id.eq(entry.secret_group_id))
            .filter(vault_secrets::is_active.eq(true))
            .select(vault_secrets::id)
            .load(conn)
            .await
            .map_err(AppError::Database)?;
        all_ids.extend(ids);
    }
    all_ids.sort_unstable();
    all_ids.dedup();
    Ok(all_ids)
}

/// Check whether a user can read a specific vault secret when calling
/// from the identity-verified `source_asset_id`.
///
/// Fully delegated to vauban-access (`CheckSecretAccessByUuid`), which
/// evaluates active rules in their validity window, injects the virtual
/// "All secrets" group, filters on the provenance asset group and
/// requires the secret row to be active.
///
/// Fail-closed: `false` on any IPC error or unexpected response shape.
pub async fn can_access_secret(
    access_client: &Arc<AccessIpcClient>,
    user_uuid: &str,
    secret_uuid: &str,
    source_asset_id: i32,
) -> bool {
    access_client
        .check_secret_access_by_uuid(user_uuid, secret_uuid, source_asset_id)
        .await
}
