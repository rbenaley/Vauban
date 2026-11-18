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
    apply_discovered_instructions_at, approval_is_current, approve_pending_catalog,
    approve_tool_in_catalog, catalog_from_asset, discover_tools_from_upstream,
    merge_approved_group_catalog,
};
use crate::services::mcp_rule_prune::prune_after_asset_change;
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

    let discovered =
        match discover_tools_from_upstream(&state, &asset, &auth_user.uuid.to_string()).await {
            Ok(t) => t,
            Err(e) => {
                // The cause can be text chosen by the upstream server
                // (a JSON-RPC error message) or by another service: it
                // goes to the log, the browser gets a constant sentence.
                tracing::warn!(asset = %uuid_str, error = %e, "MCP tool discovery failed");
                return flash_redirect(flash.error(DISCOVERY_FAILED_MESSAGE), &edit_url);
            }
        };

    let tools = discovered.tools;
    if tools.is_empty() {
        return flash_redirect(
            flash.error("Upstream MCP server returned no tools"),
            &edit_url,
        );
    }

    // The catalogue is merged into the document as it is NOW, not into
    // the copy read before the round trip to the upstream server: a
    // change stored meanwhile (an approval, a drift notice) is kept.
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let merge = |current: &serde_json::Value| {
        Some(apply_discovered_instructions_at(
            apply_discovered_catalog(current.clone(), &tools),
            discovered.instructions.as_deref(),
            &now,
        ))
    };
    match crate::models::asset::update_connection_config_with(&mut conn, asset.id, merge).await {
        Ok(crate::models::asset::ConfigUpdate::Conflict) => {
            tracing::warn!(asset = %uuid_str, "MCP catalogue changed concurrently; not saved");
            return flash_redirect(
                flash.error("The asset changed while tools were being discovered. Try again."),
                &edit_url,
            );
        }
        Ok(_) => {}
        Err(e) => {
            tracing::error!(error = %e, "persist MCP catalogue failed");
            return flash_redirect(flash.error("Failed to save discovered tools"), &edit_url);
        }
    }
    prune_after_asset_change(&state, &mut conn, asset.id, "mcp_discover").await;

    crate::services::emit_audit(
        &state,
        crate::ipc::AuditEvent::new(
            shared::messages::AuditEventType::AssetUpdated,
            serde_json::json!({
                "asset": uuid_str,
                "action": "mcp_discover",
                "tools": tools.len(),
            })
            .to_string(),
        )
        .user(auth_user.uuid.clone()),
    );

    // The names are upstream text and there can be hundreds: the flash
    // is a cookie. The panel below lists them.
    let found = tools.len();
    flash_redirect(
        flash.success(format!(
            "Discovery found {found} tool(s). New or changed tools are pending: review and approve them before sessions can use them."
        )),
        &edit_url,
    )
}

#[derive(Debug, serde::Deserialize)]
pub struct ApproveMcpToolsForm {
    pub csrf_token: String,
    /// When set, approve only this tool; otherwise approve all pending.
    pub tool_name: Option<String>,
    /// What the page showed for this approval: the fingerprint of the
    /// tool (or of the instructions), or the pending digest for
    /// "Approve pending" (`mcp_discover::approval_is_current`).
    pub shown: Option<String>,
}

/// Shown when a discovery fails, whatever the cause.
pub const DISCOVERY_FAILED_MESSAGE: &str =
    "Tool discovery failed. The cause is in the vauban-web log.";

/// Shown when an approval no longer matches the catalogue.
pub const APPROVAL_STALE_MESSAGE: &str = "The catalogue changed since this page was shown. Nothing was approved: review it and approve again.";

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

    // Approve in the document as it is now, not in the copy read above.
    let tool_name = form
        .tool_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let shown = form.shown.as_deref().unwrap_or_default();
    let approve = |current: &serde_json::Value| {
        // An approval counts only for what the page showed.
        if !approval_is_current(current, tool_name, shown) {
            return None;
        }
        Some(match tool_name {
            Some(name) => approve_tool_in_catalog(current.clone(), name),
            None => approve_pending_catalog(current.clone()),
        })
    };
    match crate::models::asset::update_connection_config_with(&mut conn, asset.id, approve).await {
        Ok(crate::models::asset::ConfigUpdate::Conflict) => {
            tracing::warn!(asset = %uuid_str, "MCP catalogue changed concurrently; approval not saved");
            return flash_redirect(
                flash.error("The asset changed while the approval was being saved. Try again."),
                &edit_url,
            );
        }
        Ok(crate::models::asset::ConfigUpdate::Unchanged) => {
            tracing::warn!(asset = %uuid_str, "MCP approval does not match the catalogue; not saved");
            return flash_redirect(flash.error(APPROVAL_STALE_MESSAGE), &edit_url);
        }
        Ok(_) => {}
        Err(e) => {
            tracing::error!(error = %e, "persist MCP tool approval failed");
            return flash_redirect(flash.error("Failed to save approvals"), &edit_url);
        }
    }
    prune_after_asset_change(&state, &mut conn, asset.id, "mcp_approve").await;

    crate::services::emit_audit(
        &state,
        crate::ipc::AuditEvent::new(
            shared::messages::AuditEventType::AssetUpdated,
            // Built as JSON, not by format: the tool name is form input.
            serde_json::json!({
                "asset": uuid_str,
                "action": "mcp_approve_tools",
                "tool": tool_name.unwrap_or("*"),
            })
            .to_string(),
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
