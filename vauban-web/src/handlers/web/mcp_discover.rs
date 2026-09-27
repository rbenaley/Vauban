//! Admin MCP tool discovery — web handlers.
//!
//! `POST /assets/manage/{uuid}/discover-mcp-tools` talks to the
//! upstream MCP server, persists the catalogue on the asset, then
//! redirects back to the edit page.

use super::*;
use crate::error::AppResult;
use crate::models::asset::{Asset, AssetType};
use crate::schema::{asset_asset_groups, asset_groups, assets};
use crate::services::mcp_discover::{
    DiscoveredTool, GroupCatalogTool, ToolCatalogStatus, apply_discovered_catalog,
    approve_pending_catalog, approve_tool_in_catalog, catalog_from_asset,
    discover_tools_from_upstream, merge_approved_group_catalog,
};
use diesel::{ExpressionMethods, OptionalExtension, QueryDsl};
use diesel_async::RunQueryDsl;

const VIRTUAL_ALL_ASSETS_UUID: &str = "00000000-0000-0000-0000-000000000a11";

#[derive(Debug, serde::Deserialize)]
pub struct DiscoverMcpToolsForm {
    pub csrf_token: String,
}

/// POST `/assets/manage/{uuid}/discover-mcp-tools`
pub async fn discover_mcp_tools_web(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
    Form(form): Form<DiscoverMcpToolsForm>,
) -> Response {
    let flash = incoming_flash.flash();
    let edit_url = format!("/assets/manage/{uuid_str}/edit");

    let csrf_cookie = jar.get(crate::middleware::csrf::CSRF_COOKIE_NAME);
    if !crate::middleware::csrf::validate_double_submit(
        state.config.secret_key.expose_secret().as_bytes(),
        csrf_cookie.map(|c| c.value()),
        &form.csrf_token,
    ) {
        return flash_redirect(flash.error("Invalid CSRF token"), &edit_url);
    }

    if !perms.assets_manage {
        return flash_redirect(
            flash.error("Only administrators can discover MCP tools"),
            "/assets/manage",
        );
    }

    let asset_uuid = match ::uuid::Uuid::parse_str(&uuid_str) {
        Ok(u) => u,
        Err(_) => return flash_redirect(flash.error("Invalid asset identifier"), "/assets/manage"),
    };

    let mut conn = match state.db_pool.get().await {
        Ok(c) => c,
        Err(_) => {
            return flash_redirect(flash.error("Database connection error"), &edit_url);
        }
    };

    let asset: Asset = match assets::table
        .filter(assets::uuid.eq(asset_uuid))
        .filter(assets::is_deleted.eq(false))
        .first(&mut conn)
        .await
    {
        Ok(a) => a,
        Err(diesel::result::Error::NotFound) => {
            return flash_redirect(flash.error("Asset not found"), "/assets/manage");
        }
        Err(e) => {
            tracing::error!(error = %e, "load asset for MCP discover failed");
            return flash_redirect(flash.error("Database error"), &edit_url);
        }
    };

    if asset.asset_type != AssetType::Mcp {
        return flash_redirect(
            flash.error("Tool discovery is only available for MCP assets"),
            &edit_url,
        );
    }

    let tools =
        match discover_tools_from_upstream(&state, &asset, &auth_user.uuid.to_string()).await {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(asset = %uuid_str, error = %e, "MCP tool discovery failed");
                return flash_redirect(flash.error(format!("Discovery failed: {e}")), &edit_url);
            }
        };

    if tools.is_empty() {
        return flash_redirect(
            flash.error("Upstream MCP server returned no tools"),
            &edit_url,
        );
    }

    let new_config = apply_discovered_catalog(asset.connection_config.clone(), &tools);
    if let Err(e) = diesel::update(assets::table.filter(assets::id.eq(asset.id)))
        .set(assets::connection_config.eq(new_config))
        .execute(&mut conn)
        .await
    {
        tracing::error!(error = %e, "persist MCP catalogue failed");
        return flash_redirect(flash.error("Failed to save discovered tools"), &edit_url);
    }

    crate::services::emit_audit(
        &state,
        crate::ipc::AuditEvent::new(
            shared::messages::AuditEventType::AssetUpdated,
            format!(
                r#"{{"asset":"{}","action":"mcp_discover","tools":{}}}"#,
                uuid_str,
                tools.len()
            ),
        )
        .user(auth_user.uuid.clone()),
    );

    let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
    let pending = tools.len();
    flash_redirect(
        flash.success(format!(
            "Discovered {pending} tool(s) as pending (TOFU): {}. Approve them before sessions can use them.",
            names.join(", ")
        )),
        &edit_url,
    )
}

#[derive(Debug, serde::Deserialize)]
pub struct ApproveMcpToolsForm {
    pub csrf_token: String,
    /// When set, approve only this tool; otherwise approve all pending.
    pub tool_name: Option<String>,
}

/// POST `/assets/manage/{uuid}/approve-mcp-tools`
pub async fn approve_mcp_tools_web(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
    Form(form): Form<ApproveMcpToolsForm>,
) -> Response {
    let flash = incoming_flash.flash();
    let edit_url = format!("/assets/manage/{uuid_str}/edit");

    let csrf_cookie = jar.get(crate::middleware::csrf::CSRF_COOKIE_NAME);
    if !crate::middleware::csrf::validate_double_submit(
        state.config.secret_key.expose_secret().as_bytes(),
        csrf_cookie.map(|c| c.value()),
        &form.csrf_token,
    ) {
        return flash_redirect(flash.error("Invalid CSRF token"), &edit_url);
    }

    if !perms.assets_manage {
        return flash_redirect(
            flash.error("Only administrators can approve MCP tools"),
            "/assets/manage",
        );
    }

    let asset_uuid = match ::uuid::Uuid::parse_str(&uuid_str) {
        Ok(u) => u,
        Err(_) => return flash_redirect(flash.error("Invalid asset identifier"), "/assets/manage"),
    };

    let mut conn = match state.db_pool.get().await {
        Ok(c) => c,
        Err(_) => {
            return flash_redirect(flash.error("Database connection error"), &edit_url);
        }
    };

    let asset: Asset = match assets::table
        .filter(assets::uuid.eq(asset_uuid))
        .filter(assets::is_deleted.eq(false))
        .first(&mut conn)
        .await
    {
        Ok(a) => a,
        Err(diesel::result::Error::NotFound) => {
            return flash_redirect(flash.error("Asset not found"), "/assets/manage");
        }
        Err(e) => {
            tracing::error!(error = %e, "load asset for MCP approve failed");
            return flash_redirect(flash.error("Database error"), &edit_url);
        }
    };

    if asset.asset_type != AssetType::Mcp {
        return flash_redirect(
            flash.error("Tool approval is only available for MCP assets"),
            &edit_url,
        );
    }

    let new_config = match form
        .tool_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(name) => approve_tool_in_catalog(asset.connection_config.clone(), name),
        None => approve_pending_catalog(asset.connection_config.clone()),
    };

    if let Err(e) = diesel::update(assets::table.filter(assets::id.eq(asset.id)))
        .set(assets::connection_config.eq(new_config))
        .execute(&mut conn)
        .await
    {
        tracing::error!(error = %e, "persist MCP tool approval failed");
        return flash_redirect(flash.error("Failed to save approvals"), &edit_url);
    }

    crate::services::emit_audit(
        &state,
        crate::ipc::AuditEvent::new(
            shared::messages::AuditEventType::AssetUpdated,
            format!(
                r#"{{"asset":"{}","action":"mcp_approve_tools","tool":{}}}"#,
                uuid_str,
                form.tool_name
                    .as_deref()
                    .map(|s| format!("\"{s}\""))
                    .unwrap_or_else(|| "\"*\"".to_string())
            ),
        )
        .user(auth_user.uuid.clone()),
    );

    flash_redirect(
        flash.success("MCP tool catalogue updated (approved tools available for sessions)"),
        &edit_url,
    )
}

async fn mcp_assets_in_group(
    conn: &mut crate::db::DbConnection,
    asset_group_id: i32,
) -> AppResult<Vec<Asset>> {
    let virtual_uuid = ::uuid::Uuid::parse_str(VIRTUAL_ALL_ASSETS_UUID)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("virtual uuid: {e}")))?;

    let is_virtual: bool = asset_groups::table
        .filter(asset_groups::id.eq(asset_group_id))
        .filter(asset_groups::uuid.eq(virtual_uuid))
        .select(asset_groups::id)
        .first::<i32>(conn)
        .await
        .optional()?
        .is_some();

    if is_virtual {
        Ok(assets::table
            .filter(assets::is_deleted.eq(false))
            .filter(assets::asset_type.eq(AssetType::Mcp))
            .load(conn)
            .await?)
    } else {
        Ok(assets::table
            .inner_join(asset_asset_groups::table.on(asset_asset_groups::asset_id.eq(assets::id)))
            .filter(asset_asset_groups::asset_group_id.eq(asset_group_id))
            .filter(assets::is_deleted.eq(false))
            .filter(assets::asset_type.eq(AssetType::Mcp))
            .select(assets::all_columns)
            .load(conn)
            .await?)
    }
}

/// Union of **approved** MCP tools for every MCP asset in an
/// asset group, with the asset names that expose each tool.
// allow-ungated: catalogue helper; callers already gate assets:manage or access_rules:read
pub async fn load_mcp_group_catalog(
    conn: &mut crate::db::DbConnection,
    asset_group_id: i32,
) -> AppResult<Vec<GroupCatalogTool>> {
    let mcp_assets = mcp_assets_in_group(conn, asset_group_id).await?;
    let pairs: Vec<(String, Vec<DiscoveredTool>)> = mcp_assets
        .iter()
        .map(|a| (a.name.clone(), catalog_from_asset(a)))
        .collect();
    Ok(merge_approved_group_catalog(&pairs))
}

/// Tool names still present on a **non-deleted** MCP asset in the group
/// (any catalogue status). Used to drop rule leftovers after an asset
/// is tombstoned — those names are not "pending Approve".
// allow-ungated: catalogue helper; callers already gate assets:manage or access_rules:read
pub async fn load_mcp_live_tool_names(
    conn: &mut crate::db::DbConnection,
    asset_group_id: i32,
) -> AppResult<std::collections::HashSet<String>> {
    let mcp_assets = mcp_assets_in_group(conn, asset_group_id).await?;
    let mut names = std::collections::HashSet::new();
    for asset in mcp_assets {
        for tool in catalog_from_asset(&asset) {
            let n = tool.name.trim();
            if !n.is_empty() {
                names.insert(n.to_string());
            }
        }
    }
    Ok(names)
}

/// Union of **approved** MCP tools for every MCP asset in an
/// asset group (virtual "All assets" → every non-deleted MCP asset).
// allow-ungated: catalogue helper; callers already gate assets:manage or access_rules:read
pub async fn load_mcp_tools_for_asset_group(
    conn: &mut crate::db::DbConnection,
    asset_group_id: i32,
) -> AppResult<Vec<DiscoveredTool>> {
    Ok(load_mcp_group_catalog(conn, asset_group_id)
        .await?
        .into_iter()
        .map(|t| DiscoveredTool {
            name: t.name,
            description: t.description,
            status: Some(ToolCatalogStatus::Approved),
            ..Default::default()
        })
        .collect())
}
