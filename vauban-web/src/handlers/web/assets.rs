//! User-zone "Assets" handlers — issue #27 asset zone split.
//!
//! These handlers serve the user-facing `/assets` catalogue. Every row
//! is filtered by the caller's access rules and exposes ONLY two
//! actions: `Connect` (SSH/RDP, via `handlers::web::ssh::connect_ssh`
//! and `handlers::web::rdp::connect_rdp`) or `Request access` (via
//! `handlers::web::sessions::submit_access_request`).
//!
//! There is no detail page, no create / edit / delete affordance and no
//! View link in the user zone. All CRUD lives in
//! [`crate::handlers::web::manage_assets`] under the gated
//! `/assets/manage/*` sub-tree (`assets:manage` Casbin permission).
//!
//! Source-level invariants are enforced by
//! `vauban-web/tests/web/asset_user_zone_no_crud_test.rs`, which scans
//! both this module and `templates/assets/asset_list.html` for any
//! `assets/new`, `assets/manage`, `/edit`, `/delete`, `assets_manage`,
//! `New asset`, `Edit`, `Delete`, `View` action labels and any
//! `diesel::insert_into(assets::table)` / `diesel::update(assets::table)`
//! / `diesel::delete(assets::table)` mutation. Mutation in this file is
//! a regression by definition.
use super::*;
use crate::models::asset::AssetType;

const ASSETS_PER_PAGE: i64 = 30;

/// User-facing asset catalogue (filtered by access rules).
///
/// Renders the `templates/assets/asset_list.html` template with
/// per-row Connect / Request affordances. The gated admin list
/// (`/assets/manage`) lives in
/// [`crate::handlers::web::manage_assets::manage_asset_list`].
pub async fn asset_list(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    _perms: crate::auth::PermissionContext,
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse, AppError> {
    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new("Assets".to_string(), user.clone()).with_current_path("/assets");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;

    let search_filter = params.get("search").filter(|s| !s.is_empty()).cloned();
    let type_filter = params.get("type").filter(|s| !s.is_empty()).cloned();
    let status_filter = params.get("status").filter(|s| !s.is_empty()).cloned();
    let page: i32 = params
        .get("page")
        .and_then(|s| s.parse::<i32>().ok())
        .unwrap_or(1)
        .max(1);

    // Resolve user internal ID for ALL users (incl. superuser/staff) so that
    // the listing, the per-row "Request Access" badge, and the connect
    // handler all consult the same access policy. The historical
    // privileged-user bypass produced a UI that pretended access rules
    // didn't apply to admins, while the connect handler (since febd388)
    // and `submit_access_request` enforced them anyway.
    let user_internal_id: i32 = crate::schema::users::table
        .filter(
            crate::schema::users::uuid
                .eq(::uuid::Uuid::parse_str(&auth_user.uuid).unwrap_or_default()),
        )
        .select(crate::schema::users::id)
        .first(&mut conn)
        .await
        .map_err(|_| AppError::Authorization("User not found".to_string()))?;

    // Resolve accessible asset IDs once for everyone, including superusers.
    // The bootstrap superuser MUST own at least one access_rule for itself
    // (the Vauban admin runbook covers this); otherwise its asset list will
    // legitimately be empty, mirroring what the proxy would enforce.
    let accessible_ids: Vec<i32> = crate::services::access::list_accessible_asset_ids(
        &state.access_client,
        &mut conn,
        user_internal_id,
    )
    .await?;

    let mut count_query = schema_assets::table
        .filter(schema_assets::is_deleted.eq(false))
        .into_boxed();

    count_query = count_query.filter(schema_assets::id.eq_any(accessible_ids.clone()));
    if let Some(ref search) = search_filter
        && !search.is_empty()
    {
        let pattern = crate::db::like_contains(search);
        count_query = count_query.filter(
            schema_assets::name
                .ilike(pattern.clone())
                .or(schema_assets::hostname.ilike(pattern)),
        );
    }
    if let Some(ref asset_type) = type_filter
        && !asset_type.is_empty()
    {
        if let Some(parsed) = AssetType::try_parse(asset_type) {
            count_query = count_query.filter(schema_assets::asset_type.eq(parsed));
        } else {
            count_query = count_query.filter(schema_assets::id.eq(-1));
        }
    }
    if let Some(ref status_val) = status_filter
        && !status_val.is_empty()
    {
        count_query = count_query.filter(schema_assets::status.eq(status_val));
    }

    let total_items: i64 = count_query.count().get_result(&mut conn).await.unwrap_or(0);
    let total_pages = ((total_items as f64) / (ASSETS_PER_PAGE as f64))
        .ceil()
        .max(1.0) as i32;
    let page = page.min(total_pages);
    let offset = ((page - 1) as i64) * ASSETS_PER_PAGE;

    let mut query = schema_assets::table
        .filter(schema_assets::is_deleted.eq(false))
        .into_boxed();

    query = query.filter(schema_assets::id.eq_any(accessible_ids.clone()));
    if let Some(ref search) = search_filter
        && !search.is_empty()
    {
        let pattern = crate::db::like_contains(search);
        query = query.filter(
            schema_assets::name
                .ilike(pattern.clone())
                .or(schema_assets::hostname.ilike(pattern)),
        );
    }
    if let Some(ref asset_type) = type_filter
        && !asset_type.is_empty()
    {
        if let Some(parsed) = AssetType::try_parse(asset_type) {
            query = query.filter(schema_assets::asset_type.eq(parsed));
        } else {
            query = query.filter(schema_assets::id.eq(-1));
        }
    }
    if let Some(ref status_val) = status_filter
        && !status_val.is_empty()
    {
        query = query.filter(schema_assets::status.eq(status_val));
    }

    let db_assets: Vec<(i32, ::uuid::Uuid, String, String, i32, AssetType, String)> = query
        .select((
            schema_assets::id,
            schema_assets::uuid,
            schema_assets::name,
            schema_assets::hostname,
            schema_assets::port,
            schema_assets::asset_type,
            schema_assets::status,
        ))
        .order(schema_assets::name.asc())
        .limit(ASSETS_PER_PAGE)
        .offset(offset)
        .load(&mut conn)
        .await?;

    let displayed_asset_ids: Vec<i32> = db_assets.iter().map(|(id, ..)| *id).collect();

    // Compute the approval / approved sets for ALL users (incl. superusers).
    // Skipping this step for admins is what made the row render the blue
    // "Connect" button on assets that actually require approval — see the
    // top-of-handler comment in the legacy revision.
    //
    // NOTE: the virtual "All assets" group has no rows in `asset_asset_groups`
    // (enforced by a DB trigger). An INNER JOIN through that table silently
    // misses any access rule whose `asset_group_id` is the virtual id, causing
    // `requires_request` to be false even though approval is required. We
    // handle this with a separate query that detects such rules and, when
    // found, marks every asset on the current page as requiring approval.
    let (approval_set, approved_set) = {
        use crate::schema::{access_rules, asset_asset_groups, user_groups};

        let mut approval_ids: Vec<i32> = access_rules::table
            .inner_join(
                asset_asset_groups::table
                    .on(asset_asset_groups::asset_group_id.eq(access_rules::asset_group_id)),
            )
            .inner_join(
                user_groups::table.on(user_groups::group_id.eq(access_rules::user_group_id)),
            )
            .filter(user_groups::user_id.eq(user_internal_id))
            .filter(access_rules::is_active.eq(true))
            .filter(access_rules::require_approval.eq(true))
            .filter(asset_asset_groups::asset_id.eq_any(&displayed_asset_ids))
            .select(asset_asset_groups::asset_id)
            .distinct()
            .load(&mut conn)
            .await
            .unwrap_or_default();

        let virtual_id = crate::services::virtual_group::virtual_asset_group_id();
        let virtual_approval_count: i64 = access_rules::table
            .inner_join(
                user_groups::table.on(user_groups::group_id.eq(access_rules::user_group_id)),
            )
            .filter(user_groups::user_id.eq(user_internal_id))
            .filter(access_rules::is_active.eq(true))
            .filter(access_rules::require_approval.eq(true))
            .filter(access_rules::asset_group_id.eq(virtual_id))
            .select(diesel::dsl::count_star())
            .first(&mut conn)
            .await
            .unwrap_or(0);
        if virtual_approval_count > 0 {
            approval_ids.extend_from_slice(&displayed_asset_ids);
            approval_ids.sort_unstable();
            approval_ids.dedup();
        }

        let approved_ids: Vec<i32> = proxy_sessions::table
            .filter(proxy_sessions::user_id.eq(user_internal_id))
            .filter(proxy_sessions::status.eq("approved"))
            .filter(
                proxy_sessions::expires_at
                    .is_null()
                    .or(proxy_sessions::expires_at.gt(diesel::dsl::now)),
            )
            .filter(proxy_sessions::asset_id.eq_any(&displayed_asset_ids))
            .select(proxy_sessions::asset_id)
            .distinct()
            .load(&mut conn)
            .await
            .unwrap_or_default();

        let a_set: std::collections::HashSet<i32> = approval_ids.into_iter().collect();
        let p_set: std::collections::HashSet<i32> = approved_ids.into_iter().collect();
        (a_set, p_set)
    };

    let asset_items: Vec<AssetListItem> = db_assets
        .into_iter()
        .map(
            |(id, uuid, name, hostname, port, asset_type, status)| AssetListItem {
                requires_request: approval_set.contains(&id) && !approved_set.contains(&id),
                id,
                uuid,
                name,
                hostname,
                port,
                asset_type: asset_type.to_string(),
                status,
                group_name: None,
            },
        )
        .collect();

    use crate::templates::accounts::user_list::Pagination;

    let start_index = if total_items > 0 { offset + 1 } else { 0 };
    let end_index = (offset + ASSETS_PER_PAGE).min(total_items);

    let pagination = if total_items > 0 {
        Some(Pagination {
            current_page: page,
            total_pages,
            total_items: total_items as i32,
            items_per_page: ASSETS_PER_PAGE as i32,
            has_previous: page > 1,
            has_next: page < total_pages,
            start_index: start_index as i32,
            end_index: end_index as i32,
        })
    } else {
        None
    };

    let template = AssetListTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        assets: asset_items,
        pagination,
        search: search_filter,
        type_filter,
        status_filter,
        asset_types: vec![
            ("ssh".to_string(), "SSH".to_string()),
            ("rdp".to_string(), "RDP".to_string()),
        ],
        statuses: vec![
            ("online".to_string(), "Online".to_string()),
            ("offline".to_string(), "Offline".to_string()),
            ("maintenance".to_string(), "Maintenance".to_string()),
        ],
        require_justification: state.config.security.require_justification,
    };

    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;
    Ok(Html(html))
}

/// User-facing asset connect page (`GET /assets/{uuid}`).
///
/// Issue #27: this page replaces the legacy mixed admin+user
/// `asset_detail` handler with a strict "connect / request access"
/// view that NEVER renders Edit, Delete, Fetch-Host-Key or any other
/// CRUD affordance. Those live exclusively at `/assets/manage/{uuid}`
/// behind the `assets:manage` Casbin gate.
///
/// # Authorization layers
///
/// 1. Casbin `assets:read` (loaded by `permission_context_middleware`)
///    must be true; otherwise the request is rejected with 403 BEFORE
///    any DB lookup so the route cannot be probed by an unprivileged
///    caller as an asset-existence oracle.
/// 2. The asset must belong to the caller's
///    `services::access::list_accessible_asset_ids` set; an admin who
///    has `assets:read_all` (and therefore sees every asset on the
///    list) is still gated here on the per-user access rule (the same
///    invariant `connect_ssh` / `connect_rdp` enforce a few lines
///    later, so the page truthfully reflects what the proxy will
///    accept).
/// 3. Anti-enumeration: every denial path collapses to the same
///    `flash_redirect` / 404 template so the URL is not a probing
///    oracle for asset UUIDs.
pub async fn asset_user_view(
    State(state): State<AppState>,
    incoming_flash: IncomingFlash,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    axum::extract::Path(asset_uuid_str): axum::extract::Path<String>,
) -> Response {
    use crate::models::asset::Asset;
    use crate::templates::assets::asset_detail::{AssetDetail, AssetDetailTemplate};

    let flash = incoming_flash.flash();

    if !perms.assets_read {
        return flash_redirect(
            flash.error("Insufficient privileges to view this asset"),
            "/assets",
        );
    }

    let asset_uuid = match ::uuid::Uuid::parse_str(&asset_uuid_str) {
        Ok(uuid) => uuid,
        Err(_) => {
            return flash_redirect(flash.error("Asset not found"), "/assets");
        }
    };

    let user = Some(user_context_from_auth(&auth_user));

    let mut conn = match state.db_pool.get().await {
        Ok(conn) => conn,
        Err(_) => {
            return flash_redirect(
                flash.error("Database connection error. Please try again."),
                "/assets",
            );
        }
    };

    let user_internal_id: i32 = match crate::schema::users::table
        .filter(
            crate::schema::users::uuid
                .eq(::uuid::Uuid::parse_str(&auth_user.uuid).unwrap_or_default()),
        )
        .select(crate::schema::users::id)
        .first(&mut conn)
        .await
    {
        Ok(id) => id,
        Err(_) => {
            return flash_redirect(flash.error("User not found"), "/assets");
        }
    };

    let accessible_ids: Vec<i32> = match crate::services::access::list_accessible_asset_ids(
        &state.access_client,
        &mut conn,
        user_internal_id,
    )
    .await
    {
        Ok(ids) => ids,
        Err(_) => {
            return flash_redirect(
                flash.error("Database error. Please try again."),
                "/assets",
            );
        }
    };

    let asset_model: Asset = match schema_assets::table
        .filter(schema_assets::uuid.eq(asset_uuid))
        .filter(schema_assets::is_deleted.eq(false))
        .filter(schema_assets::id.eq_any(&accessible_ids))
        .select(Asset::as_select())
        .first(&mut conn)
        .await
    {
        Ok(row) => row,
        Err(diesel::result::Error::NotFound) => {
            // Anti-enumeration: collapse "asset does not exist" and
            // "asset exists but the caller lacks an access rule" to
            // the same generic message so the URL is not an oracle.
            return flash_redirect(flash.error("Asset not found"), "/assets");
        }
        Err(_) => {
            return flash_redirect(
                flash.error("Database error. Please try again."),
                "/assets",
            );
        }
    };

    let asset_name = asset_model.name.clone();
    let asset_id = asset_model.id;

    let asset_connection_config = &asset_model.connection_config;
    let ssh_host_key_fingerprint = asset_connection_config
        .get("ssh_host_key_fingerprint")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let ssh_host_key_mismatch = asset_connection_config
        .get("ssh_host_key_mismatch")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let group_rows: Vec<(String, ::uuid::Uuid)> = {
        use crate::schema::asset_asset_groups::dsl as aag;
        use crate::schema::asset_groups::dsl as ag;
        aag::asset_asset_groups
            .inner_join(ag::asset_groups.on(aag::asset_group_id.eq(ag::id)))
            .filter(aag::asset_id.eq(asset_id))
            .filter(ag::is_deleted.eq(false))
            .select((ag::name, ag::uuid))
            .load(&mut conn)
            .await
            .unwrap_or_default()
    };

    let (group_name, group_uuid): (Option<String>, Option<String>) = if group_rows.is_empty() {
        (None, None)
    } else {
        let names = group_rows
            .iter()
            .map(|(n, _)| n.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        (
            Some(names),
            group_rows.as_slice().first().map(|(_, u)| u.to_string()),
        )
    };

    let (require_approval, require_mfa, has_approved_session) = {
        use crate::schema::{access_rules, asset_asset_groups, user_groups};

        let virtual_id = crate::services::virtual_group::virtual_asset_group_id();

        let approval_count: i64 = access_rules::table
            .inner_join(
                asset_asset_groups::table
                    .on(asset_asset_groups::asset_group_id.eq(access_rules::asset_group_id)),
            )
            .inner_join(
                user_groups::table.on(user_groups::group_id.eq(access_rules::user_group_id)),
            )
            .filter(user_groups::user_id.eq(user_internal_id))
            .filter(access_rules::is_active.eq(true))
            .filter(access_rules::require_approval.eq(true))
            .filter(asset_asset_groups::asset_id.eq(asset_id))
            .select(diesel::dsl::count_star())
            .first(&mut conn)
            .await
            .unwrap_or(0);

        let virtual_approval_count: i64 = access_rules::table
            .inner_join(
                user_groups::table.on(user_groups::group_id.eq(access_rules::user_group_id)),
            )
            .filter(user_groups::user_id.eq(user_internal_id))
            .filter(access_rules::is_active.eq(true))
            .filter(access_rules::require_approval.eq(true))
            .filter(access_rules::asset_group_id.eq(virtual_id))
            .select(diesel::dsl::count_star())
            .first(&mut conn)
            .await
            .unwrap_or(0);

        let mfa_count: i64 = access_rules::table
            .inner_join(
                asset_asset_groups::table
                    .on(asset_asset_groups::asset_group_id.eq(access_rules::asset_group_id)),
            )
            .inner_join(
                user_groups::table.on(user_groups::group_id.eq(access_rules::user_group_id)),
            )
            .filter(user_groups::user_id.eq(user_internal_id))
            .filter(access_rules::is_active.eq(true))
            .filter(access_rules::require_mfa.eq(true))
            .filter(asset_asset_groups::asset_id.eq(asset_id))
            .select(diesel::dsl::count_star())
            .first(&mut conn)
            .await
            .unwrap_or(0);

        let virtual_mfa_count: i64 = access_rules::table
            .inner_join(
                user_groups::table.on(user_groups::group_id.eq(access_rules::user_group_id)),
            )
            .filter(user_groups::user_id.eq(user_internal_id))
            .filter(access_rules::is_active.eq(true))
            .filter(access_rules::require_mfa.eq(true))
            .filter(access_rules::asset_group_id.eq(virtual_id))
            .select(diesel::dsl::count_star())
            .first(&mut conn)
            .await
            .unwrap_or(0);

        let approved_count: i64 = proxy_sessions::table
            .filter(proxy_sessions::user_id.eq(user_internal_id))
            .filter(proxy_sessions::asset_id.eq(asset_id))
            .filter(proxy_sessions::status.eq("approved"))
            .filter(
                proxy_sessions::expires_at
                    .is_null()
                    .or(proxy_sessions::expires_at.gt(diesel::dsl::now)),
            )
            .select(diesel::dsl::count_star())
            .first(&mut conn)
            .await
            .unwrap_or(0);

        (
            approval_count + virtual_approval_count > 0,
            mfa_count + virtual_mfa_count > 0,
            approved_count > 0,
        )
    };

    let asset = AssetDetail {
        uuid: asset_model.uuid.to_string(),
        name: asset_name.clone(),
        hostname: asset_model.hostname.clone(),
        port: asset_model.port,
        asset_type: asset_model.asset_type.to_string(),
        status: asset_model.status.clone(),
        group_name,
        group_uuid,
        description: asset_model.description.clone(),
        require_approval,
        require_mfa,
        created_at: asset_model.created_at.format("%b %d, %Y %H:%M").to_string(),
        updated_at: asset_model.updated_at.format("%b %d, %Y %H:%M").to_string(),
        ssh_host_key_fingerprint,
        ssh_host_key_mismatch,
        has_approved_session,
        require_justification: state.config.security.require_justification,
    };

    let flash_messages: Vec<crate::templates::base::FlashMessage> = incoming_flash
        .messages()
        .iter()
        .map(|m| crate::templates::base::FlashMessage {
            level: m.level.clone(),
            message: m.message.clone(),
        })
        .collect();

    let base = BaseTemplate::new(format!("{} - Assets", asset_name), user.clone())
        .with_current_path("/assets")
        .with_messages(flash_messages);
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

    let template = AssetDetailTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        asset,
    };

    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(_) => flash_redirect(flash.error("Failed to render page"), "/assets"),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_assets_per_page_is_30() {
        assert_eq!(super::ASSETS_PER_PAGE, 30);
    }

    #[test]
    fn test_asset_list_handler_uses_pagination() {
        let source = include_str!("assets.rs");
        let fn_start = source
            .find("fn asset_list")
            .expect("asset_list handler must exist");
        let fn_end = source[fn_start..]
            .find("\npub async fn ")
            .map(|p| fn_start + p)
            .unwrap_or(source.len());
        let body = &source[fn_start..fn_end];

        assert!(
            body.contains("ASSETS_PER_PAGE"),
            "asset_list must use ASSETS_PER_PAGE constant"
        );
        assert!(
            body.contains(".count()"),
            "asset_list must execute a COUNT query"
        );
        assert!(
            body.contains(".offset("),
            "asset_list must use .offset() for pagination"
        );
        assert!(
            body.contains("Pagination {"),
            "asset_list must construct a Pagination struct"
        );
        assert!(
            !body.contains(".limit(50)"),
            "asset_list must not hardcode .limit(50)"
        );
    }

    #[test]
    fn test_asset_list_handler_parses_page_param() {
        let source = include_str!("assets.rs");
        let fn_start = source
            .find("fn asset_list")
            .expect("asset_list handler must exist");
        let fn_end = source[fn_start..]
            .find("\npub async fn ")
            .map(|p| fn_start + p)
            .unwrap_or(source.len());
        let body = &source[fn_start..fn_end];

        assert!(
            body.contains("\"page\""),
            "asset_list must read the 'page' query parameter"
        );
        assert!(
            body.contains(".max(1)"),
            "asset_list must clamp page to minimum 1"
        );
    }

    #[test]
    fn test_asset_list_handler_clamps_page_to_total() {
        let source = include_str!("assets.rs");
        let fn_start = source
            .find("fn asset_list")
            .expect("asset_list handler must exist");
        let fn_end = source[fn_start..]
            .find("\npub async fn ")
            .map(|p| fn_start + p)
            .unwrap_or(source.len());
        let body = &source[fn_start..fn_end];

        assert!(
            body.contains(".min(total_pages)"),
            "asset_list must clamp page to total_pages so ?page=999 stays valid"
        );
    }

    #[test]
    fn test_asset_list_queries_approval_rules() {
        let source = include_str!("assets.rs");
        let fn_start = source
            .find("fn asset_list")
            .expect("asset_list handler must exist");
        let fn_end = source[fn_start..]
            .find("\npub async fn ")
            .map(|p| fn_start + p)
            .unwrap_or(source.len());
        let body = &source[fn_start..fn_end];

        assert!(
            body.contains("require_approval"),
            "asset_list must query access_rules.require_approval"
        );
        assert!(
            body.contains("asset_asset_groups"),
            "asset_list must join asset_asset_groups for approval check"
        );
    }

    #[test]
    fn test_asset_list_queries_approved_sessions() {
        let source = include_str!("assets.rs");
        let fn_start = source
            .find("fn asset_list")
            .expect("asset_list handler must exist");
        let fn_end = source[fn_start..]
            .find("\npub async fn ")
            .map(|p| fn_start + p)
            .unwrap_or(source.len());
        let body = &source[fn_start..fn_end];

        assert!(
            body.contains("status.eq(\"approved\")"),
            "asset_list must query approved sessions"
        );
        assert!(
            body.contains("expires_at"),
            "asset_list must check expires_at for approved sessions"
        );
    }

    #[test]
    fn test_asset_list_uses_hashset_for_lookup() {
        let source = include_str!("assets.rs");
        let fn_start = source
            .find("fn asset_list")
            .expect("asset_list handler must exist");
        let fn_end = source[fn_start..]
            .find("\npub async fn ")
            .map(|p| fn_start + p)
            .unwrap_or(source.len());
        let body = &source[fn_start..fn_end];

        assert!(
            body.contains("HashSet"),
            "asset_list must use HashSet for O(1) lookup"
        );
        assert!(
            body.contains("approval_set.contains"),
            "asset_list must use approval_set.contains for lookup"
        );
    }
}
