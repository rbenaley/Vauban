//! User-zone Assets JSON API — issue #27 asset zone split.
//!
//! This module exposes ONLY `GET /api/v1/assets` (gated by
//! `assets_read`), the read-only catalogue mirroring the user-facing
//! HTML list at `/assets`. Admin CRUD (`POST` / `PUT` / `GET /{uuid}`)
//! lives in [`crate::handlers::api::manage_assets`] under the gated
//! `/api/v1/assets/manage/*` sub-tree.
//!
//! v1.0 has not shipped, so the pre-split admin URLs (`POST
//! /api/v1/assets`, `PUT /api/v1/assets/{uuid}`, `GET
//! /api/v1/assets/{uuid}`, `/api/v1/assets/groups*`) are NOT mounted
//! as 308 redirects: there are no external clients to preserve
//! compatibility for. Every consumer (UI, CLI, IaC, tests) targets
//! `/api/v1/assets/manage/*` directly. The absence of the legacy
//! redirects is pinned by
//! `tests/web/boot_smoke_test::main_rs_does_not_carry_legacy_asset_redirects`.
//! `DELETE /api/v1/assets/{uuid}` keeps a 501 stub so an unsupported
//! verb returns a canonical "not implemented" answer instead of
//! falling through to a generic 404.
use axum::{
    Json,
    extract::{Query, State},
};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use serde::Deserialize;

use crate::AppState;
use crate::auth::PermissionContext;
use crate::error::{AppError, AppResult};
use crate::middleware::auth::AuthUser;
use crate::models::asset::{Asset, AssetType};
use crate::schema::asset_asset_groups::dsl as aag;
use crate::schema::assets::dsl::*;

/// Query parameters for the user-zone asset listing.
#[derive(Debug, Deserialize)]
pub struct ListAssetsParams {
    pub asset_type: Option<String>,
    pub group_id: Option<i32>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// List assets handler (user zone).
///
/// Holders of `assets:read_all` (staff and superuser) see every asset.
/// Regular users only see assets exposed via an active access rule
/// matching one of their groups.
///
/// Mutations have moved to the admin zone:
/// [`crate::handlers::api::manage_assets::create_asset`],
/// [`crate::handlers::api::manage_assets::update_asset`],
/// [`crate::handlers::api::manage_assets::get_asset`].
pub async fn list_assets(
    State(state): State<AppState>,
    user: AuthUser,
    perms: PermissionContext,
    Query(params): Query<ListAssetsParams>,
) -> AppResult<Json<Vec<Asset>>> {
    if !perms.assets_read {
        return Err(AppError::forbidden("assets:read"));
    }

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;
    let mut query = assets.filter(is_deleted.eq(false)).into_boxed();

    // Industrial kill-switch (layer 2 of 4): mirrors the web list
    // filters in `handlers::web::assets::asset_list` /
    // `handlers::web::manage_assets::manage_asset_list`. The JSON
    // API MUST surface the same set of rows as the HTML page or a
    // CLI / IaC client could enumerate IACS UUIDs that the user
    // cannot see in the browser.
    if !state.config.industrial.enabled {
        query = query.filter(asset_type.ne_all(AssetType::iacs_variants()));
    }

    if !perms.assets_read_all {
        let user_internal_id: i32 = crate::schema::users::table
            .filter(
                crate::schema::users::uuid
                    .eq(::uuid::Uuid::parse_str(&user.uuid).unwrap_or_default()),
            )
            .select(crate::schema::users::id)
            .first(&mut conn)
            .await
            .map_err(|_| AppError::Authorization("User not found".to_string()))?;

        let accessible_ids = crate::services::access::list_accessible_asset_ids(
            &state.access_client,
            &mut conn,
            user_internal_id,
        )
        .await?;
        query = query.filter(crate::schema::assets::id.eq_any(accessible_ids));
    }

    if let Some(ref asset_type_val) = params.asset_type {
        if let Some(parsed) = AssetType::try_parse(asset_type_val) {
            query = query.filter(asset_type.eq(parsed));
        } else {
            query = query.filter(crate::schema::assets::id.eq(-1));
        }
    }

    if let Some(group_id_val) = params.group_id {
        let sub = aag::asset_asset_groups
            .filter(aag::asset_group_id.eq(group_id_val))
            .select(aag::asset_id);
        query = query.filter(crate::schema::assets::id.eq_any(sub));
    }

    let assets_list = query
        .limit(params.limit.unwrap_or(50))
        .offset(params.offset.unwrap_or(0))
        .load::<Asset>(&mut conn)
        .await?;

    Ok(Json(assets_list))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_assets_params_defaults() {
        let params = ListAssetsParams {
            asset_type: None,
            group_id: None,
            limit: None,
            offset: None,
        };

        assert_eq!(params.limit.unwrap_or(50), 50);
        assert_eq!(params.offset.unwrap_or(0), 0);
    }

    /// User-zone assertion: this module must never carry a CRUD
    /// mutation. Mutations live in `api/manage_assets.rs`. Forbidden
    /// patterns are built from `format!` to avoid self-matching.
    #[test]
    fn user_zone_api_module_has_no_mutation() {
        let source = include_str!("assets.rs");
        let body = source
            .split("#[cfg(test)]")
            .next()
            .expect("module always has a non-test prefix");

        let forbidden = [
            format!("diesel::insert_into({}assets)", "::"),
            format!("diesel::insert_into({}assets::table)", ""),
            format!("diesel::update({}assets)", "::"),
            format!("diesel::update({}assets::table)", ""),
            format!("diesel::delete({}assets)", "::"),
            format!("diesel::delete({}assets::table)", ""),
            format!("perms.assets_{}", "manage"),
        ];

        for pat in &forbidden {
            assert!(
                !body.contains(pat.as_str()),
                "user-zone api/assets.rs must never contain '{}'; mutations and \
                 admin operations belong in api/manage_assets.rs",
                pat
            );
        }
    }
}
