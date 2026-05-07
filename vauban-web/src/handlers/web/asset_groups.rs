/// Asset group management page handlers.
///
/// Asset group table operations delegate to AccessIpcClient when available,
/// with fallback to direct SQL when IPC is not configured.
use super::*;

/// Format RFC3339 date string to display format.
fn format_rfc3339_date(s: &str, fmt: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|d| d.format(fmt).to_string())
        .unwrap_or_else(|| s.to_string())
}

/// Returns `true` if the given UUID string matches the singleton virtual
/// "All assets" group. Comparison is done in canonical lowercase hyphenated
/// form via `Uuid::parse_str`, so input case / whitespace cannot bypass it.
///
/// Defense-in-depth: every asset-group mutation handler MUST short-circuit
/// when this returns true. The DB triggers (`block_membership_on_virtual_groups`
/// and `block_mutation_on_virtual_groups`) catch what slips through, but
/// surfacing a clear 403 + flash message is much friendlier than a generic
/// "trigger raised" error bubbling up from Diesel.
fn is_virtual_asset_group_uuid(uuid_str: &str) -> bool {
    use shared::messages::ALL_ASSETS_GROUP_UUID;
    match (
        ::uuid::Uuid::parse_str(uuid_str),
        ::uuid::Uuid::parse_str(ALL_ASSETS_GROUP_UUID),
    ) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

/// Asset group list page.
pub async fn asset_group_list(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse, AppError> {
    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new("Asset Groups".to_string(), user.clone())
        .with_current_path("/assets/groups");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

    // Filter out empty strings - form sends empty string when search is cleared
    let search_filter = params.get("search").filter(|s| !s.is_empty()).cloned();

    let client = &state.access_client;
    let groups: Vec<crate::templates::assets::group_list::AssetGroupItem> = {
        // IPC path: list groups via Access, counts via local SQL
        let ipc_groups = client.list_asset_groups().await?;
        let mut conn = state
            .db_pool
            .get()
            .await
            .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;
        let count_rows: Vec<GroupCountRow> = diesel::sql_query(
            "SELECT aag.asset_group_id AS group_id, COUNT(*)::bigint AS cnt \
                 FROM asset_asset_groups aag \
                 INNER JOIN assets a ON a.id = aag.asset_id AND a.is_deleted = false \
                 GROUP BY aag.asset_group_id",
        )
        .load(&mut conn)
        .await
        .map_err(AppError::Database)?;
        let counts: std::collections::HashMap<i32, i64> = count_rows
            .into_iter()
            .map(|r| (r.group_id, r.cnt))
            .collect();

        let search_lower = search_filter.as_ref().map(|s| s.to_lowercase());
        let mut groups: Vec<_> = ipc_groups
            .into_iter()
            .filter(|g| {
                search_lower.as_ref().is_none_or(|s| {
                    g.name.to_lowercase().contains(s) || g.slug.to_lowercase().contains(s)
                })
            })
            .map(|g| crate::templates::assets::group_list::AssetGroupItem {
                uuid: g.uuid,
                name: g.name,
                slug: g.slug,
                description: g.description,
                color: g.color,
                icon: g.icon,
                asset_count: counts.get(&g.id).copied().unwrap_or(0),
                created_at: format_rfc3339_date(&g.created_at, "%b %d, %Y"),
            })
            .collect();
        groups.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
        groups
    };

    let template = AssetGroupListTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        groups,
        search: search_filter,
    };

    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;
    Ok(Html(html))
}

/// Helper for asset count by group_id query (IPC path).
#[derive(diesel::QueryableByName)]
struct GroupCountRow {
    #[diesel(sql_type = diesel::sql_types::Integer)]
    group_id: i32,
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    cnt: i64,
}

/// Asset group detail page.
pub async fn asset_group_detail(
    State(state): State<AppState>,
    incoming_flash: IncomingFlash,
    auth_user: WebAuthUser,
    jar: CookieJar,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
) -> Response {
    let flash = incoming_flash.flash();
    let user = Some(user_context_from_auth(&auth_user));

    let csrf_token = jar
        .get(crate::middleware::csrf::CSRF_COOKIE_NAME)
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    if ::uuid::Uuid::parse_str(&uuid_str).is_err() {
        return flash_redirect(flash.error("Invalid group identifier"), "/assets/groups");
    }

    // Virtual "All assets" group is system-managed and never directly
    // browsable: present it as not found so it stays invisible in the
    // asset-groups index.
    if is_virtual_asset_group_uuid(&uuid_str) {
        return flash_redirect(flash.error("Asset group not found"), "/assets/groups");
    }

    let client = &state.access_client;
    let (group, group_name): (
        crate::templates::assets::group_detail::AssetGroupDetail,
        String,
    ) = {
        // IPC path: get group via Access, assets via local SQL
        let group_info = match client.get_asset_group(&uuid_str).await {
            Ok(info) => info,
            Err(_) => {
                return flash_redirect(flash.error("Asset group not found"), "/assets/groups");
            }
        };
        let mut conn = match state.db_pool.get().await {
            Ok(conn) => conn,
            Err(_) => {
                return flash_redirect(
                    flash.error("Database connection error. Please try again."),
                    "/assets/groups",
                );
            }
        };
        let assets_data: Vec<GroupAssetResult> = match diesel::sql_query(
            "SELECT a.uuid, a.name, a.hostname, a.asset_type, a.status FROM assets a \
             INNER JOIN asset_asset_groups aag ON aag.asset_id = a.id \
             WHERE aag.asset_group_id = $1 AND a.is_deleted = false ORDER BY a.name ASC",
        )
        .bind::<diesel::sql_types::Integer, _>(group_info.id)
        .load(&mut conn)
        .await
        {
            Ok(data) => data,
            Err(_) => {
                return flash_redirect(
                    flash.error("Database error. Please try again."),
                    "/assets/groups",
                );
            }
        };

        let assets: Vec<crate::templates::assets::group_detail::GroupAssetItem> = assets_data
            .into_iter()
            .map(|a| {
                let badge_label = crate::models::asset::AssetType::parse_or_ssh(&a.asset_type)
                    .badge_label()
                    .to_string();
                crate::templates::assets::group_detail::GroupAssetItem {
                    uuid: a.uuid.to_string(),
                    name: a.name,
                    hostname: a.hostname,
                    asset_type: a.asset_type,
                    badge_label,
                    status: a.status,
                }
            })
            .collect();

        // Audit pair (issue #22). The IPC `AssetGroupInfo` does not
        // carry `created_by_id` / `updated_by_id` (those are pure
        // presentation, not a policy decision) so we fetch them
        // directly. `id` came back from the IPC response so this
        // is a primary-key lookup, no extra UUID parsing needed.
        let audit_ids: Option<(Option<i32>, Option<i32>)> = {
            use crate::schema::asset_groups::dsl as ag_dsl;
            ag_dsl::asset_groups
                .filter(ag_dsl::id.eq(group_info.id))
                .select((ag_dsl::created_by_id, ag_dsl::updated_by_id))
                .first(&mut conn)
                .await
                .ok()
        };
        let (created_by, updated_by) = match audit_ids {
            Some((created_by_id, updated_by_id)) => {
                crate::services::audit_authors::resolve_audit_pair(
                    &mut conn,
                    created_by_id,
                    updated_by_id,
                )
                .await
            }
            None => (None, None),
        };

        let group = crate::templates::assets::group_detail::AssetGroupDetail {
            uuid: group_info.uuid,
            name: group_info.name.clone(),
            slug: group_info.slug,
            description: group_info.description,
            color: group_info.color,
            icon: group_info.icon,
            created_at: format_rfc3339_date(&group_info.created_at, "%b %d, %Y %H:%M"),
            updated_at: format_rfc3339_date(&group_info.updated_at, "%b %d, %Y %H:%M"),
            created_by,
            updated_by,
            assets,
        };
        (group, group_info.name)
    };

    let base = BaseTemplate::new(format!("{} - Asset Group", group_name), user.clone())
        .with_current_path("/assets/groups");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

    let template = AssetGroupDetailTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        group,
        csrf_token,
    };

    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(_) => flash_redirect(flash.error("Failed to render page"), "/assets/groups"),
    }
}

/// Helper struct for group asset query results.
#[derive(diesel::QueryableByName)]
struct GroupAssetResult {
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    uuid: ::uuid::Uuid,
    #[diesel(sql_type = diesel::sql_types::Varchar)]
    name: String,
    #[diesel(sql_type = diesel::sql_types::Varchar)]
    hostname: String,
    #[diesel(sql_type = diesel::sql_types::Varchar)]
    asset_type: String,
    #[diesel(sql_type = diesel::sql_types::Varchar)]
    status: String,
}

/// Asset group add asset form page.
pub async fn asset_group_add_asset_form(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
) -> Result<impl IntoResponse, AppError> {
    use crate::templates::assets::group_add_asset::{
        AssetGroupAddAssetTemplate, AvailableAsset, GroupSummary,
    };

    if !perms.groups_write {
        return Err(AppError::Authorization(
            "Only administrators can manage asset group membership".to_string(),
        ));
    }

    // Virtual "All assets" group is system-managed: membership cannot be
    // mutated, the form has no purpose. The DB trigger
    // `block_membership_on_virtual_groups` would also reject the underlying
    // INSERT, but failing here is friendlier and avoids a useless render.
    if is_virtual_asset_group_uuid(&uuid_str) {
        return Err(AppError::Authorization(
            "The 'All assets' virtual group is system-managed and cannot be modified".to_string(),
        ));
    }

    let user = Some(user_context_from_auth(&auth_user));

    let flash_messages: Vec<crate::templates::base::FlashMessage> = incoming_flash
        .messages()
        .iter()
        .map(|m| crate::templates::base::FlashMessage {
            level: m.level.clone(),
            message: m.message.clone(),
        })
        .collect();

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;

    let client = &state.access_client;
    let (group, target_group_id): (GroupSummary, i32) = {
        let group_info = client
            .get_asset_group(&uuid_str)
            .await
            .map_err(|_| AppError::NotFound("Asset group not found".to_string()))?;
        let group = GroupSummary {
            uuid: group_info.uuid,
            name: group_info.name,
        };
        (group, group_info.id)
    };

    let allow_multiple = state.config.assets.allow_multiple_groups_per_asset;

    // Get ALL assets (not deleted) with ids for membership lookup
    use crate::models::asset::AssetType as DbAssetType;
    use crate::schema::asset_asset_groups::dsl as aag;
    use crate::schema::asset_groups::dsl as ag;
    use crate::schema::assets::dsl as a;

    let available_asset_rows: Vec<(i32, ::uuid::Uuid, String, String, DbAssetType, String)> =
        a::assets
            .filter(a::is_deleted.eq(false))
            .select((
                a::id,
                a::uuid,
                a::name,
                a::hostname,
                a::asset_type,
                a::status,
            ))
            .order(a::name.asc())
            .load(&mut conn)
            .await
            .map_err(AppError::Database)?;

    let asset_ids: Vec<i32> = available_asset_rows.iter().map(|r| r.0).collect();

    let membership_rows: Vec<(i32, i32, String)> = if asset_ids.is_empty() {
        Vec::new()
    } else {
        aag::asset_asset_groups
            .inner_join(ag::asset_groups.on(aag::asset_group_id.eq(ag::id)))
            .filter(aag::asset_id.eq_any(asset_ids))
            .filter(ag::is_deleted.eq(false))
            .select((aag::asset_id, ag::id, ag::name))
            .load(&mut conn)
            .await
            .map_err(AppError::Database)?
    };

    let mut by_asset: std::collections::HashMap<i32, Vec<(i32, String)>> =
        std::collections::HashMap::new();
    for (aid, gid, gname) in membership_rows {
        by_asset.entry(aid).or_default().push((gid, gname));
    }

    let available_assets: Vec<AvailableAsset> = available_asset_rows
        .into_iter()
        .map(|(asset_pk, uuid, name, hostname, asset_type, status)| {
            let mems = by_asset.get(&asset_pk).cloned().unwrap_or_default();
            let in_target_group = mems.iter().any(|(id, _)| *id == target_group_id);
            let other_group_names: Vec<String> = mems
                .into_iter()
                .filter(|(id, _)| *id != target_group_id)
                .map(|(_, n)| n)
                .collect();
            AvailableAsset {
                uuid: uuid.to_string(),
                name,
                hostname,
                asset_type: asset_type.to_string(),
                status,
                in_target_group,
                other_group_names,
                allow_multiple_groups_per_asset: allow_multiple,
            }
        })
        .collect();

    // Count selectable assets for this form
    let available_count = available_assets.iter().filter(|a| a.is_available()).count();

    let csrf_token = jar
        .get(crate::middleware::csrf::CSRF_COOKIE_NAME)
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    let base = BaseTemplate::new(
        format!("Add Asset to {} - Asset Group", group.name),
        user.clone(),
    )
    .with_current_path("/assets/groups")
    .with_messages(flash_messages);
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

    let template = AssetGroupAddAssetTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        group,
        available_assets,
        available_count,
        allow_multiple_groups_per_asset: allow_multiple,
        csrf_token,
    };

    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;
    Ok(Html(html).into_response())
}

/// Parsed form data for adding assets to a group.
/// This struct is populated by manual parsing to support multiple checkbox values.
#[derive(Debug)]
pub struct AddAssetToGroupForm {
    pub asset_uuids: Vec<String>,
    pub csrf_token: String,
}

impl AddAssetToGroupForm {
    /// Parse form data from raw bytes, supporting multiple values for asset_uuids.
    /// HTML forms with multiple checkboxes send: asset_uuids=uuid1&asset_uuids=uuid2
    fn from_bytes(bytes: &[u8]) -> Self {
        let mut asset_uuids = Vec::new();
        let mut csrf_token = String::new();

        for (key, value) in url::form_urlencoded::parse(bytes) {
            match key.as_ref() {
                "asset_uuids" => asset_uuids.push(value.to_string()),
                "csrf_token" => csrf_token = value.to_string(),
                _ => {}
            }
        }

        Self {
            asset_uuids,
            csrf_token,
        }
    }
}

/// Handle adding assets to a group (supports multiple selection).
pub async fn asset_group_add_asset(
    State(state): State<AppState>,
    _auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let flash = incoming_flash.flash();

    // Parse form data manually to support multiple checkbox values
    let form = AddAssetToGroupForm::from_bytes(&body);

    // CSRF validation
    let csrf_cookie = jar.get(crate::middleware::csrf::CSRF_COOKIE_NAME);
    if !crate::middleware::csrf::validate_double_submit(
        state.config.secret_key.expose_secret().as_bytes(),
        csrf_cookie.map(|c| c.value()),
        &form.csrf_token,
    ) {
        return flash_redirect(
            flash.error("Invalid CSRF token. Please refresh the page and try again."),
            &format!("/assets/groups/{}/add-asset", uuid_str),
        );
    }

    if !perms.groups_write {
        return flash_redirect(
            flash.error("Only administrators can manage asset group membership"),
            &format!("/assets/groups/{}", uuid_str),
        );
    }

    // Parse group UUID
    if ::uuid::Uuid::parse_str(&uuid_str).is_err() {
        return flash_redirect(flash.error("Invalid group identifier"), "/assets/groups");
    }

    // Defense-in-depth on top of the DB trigger: refuse to even attempt
    // attaching assets to the virtual "All assets" group.
    if is_virtual_asset_group_uuid(&uuid_str) {
        return flash_redirect(
            flash.error("Cannot add assets to the 'All assets' virtual group (system-managed)"),
            "/assets/groups",
        );
    }

    // Check if any assets were selected
    if form.asset_uuids.is_empty() {
        return flash_redirect(
            flash.error("Please select at least one asset to add"),
            &format!("/assets/groups/{}/add-asset", uuid_str),
        );
    }

    // Parse all asset UUIDs
    let mut asset_uuids: Vec<::uuid::Uuid> = Vec::new();
    for uuid_str_item in &form.asset_uuids {
        match ::uuid::Uuid::parse_str(uuid_str_item) {
            Ok(uuid) => asset_uuids.push(uuid),
            Err(_) => {
                return flash_redirect(
                    flash.error("Invalid asset identifier"),
                    &format!("/assets/groups/{}/add-asset", uuid_str),
                );
            }
        }
    }

    let client = &state.access_client;
    let group_id: i32 = {
        // IPC path: get group id
        let group_info = match client.get_asset_group(&uuid_str).await {
            Ok(info) => info,
            Err(_) => {
                return flash_redirect(flash.error("Asset group not found"), "/assets/groups");
            }
        };
        group_info.id
    };

    let mut conn = match state.db_pool.get().await {
        Ok(conn) => conn,
        Err(_) => {
            return flash_redirect(
                flash.error("Database connection error. Please try again."),
                &format!("/assets/groups/{}/add-asset", uuid_str),
            );
        }
    };

    use crate::models::asset::NewAssetAssetGroup;
    use crate::schema::asset_asset_groups::dsl as aag;
    use crate::schema::assets::dsl as a;

    let allow_multiple = state.config.assets.allow_multiple_groups_per_asset;

    let asset_ids: Vec<i32> = match a::assets
        .filter(a::uuid.eq_any(&asset_uuids))
        .filter(a::is_deleted.eq(false))
        .select(a::id)
        .load(&mut conn)
        .await
    {
        Ok(ids) => ids,
        Err(_) => {
            return flash_redirect(
                flash.error("Database error. Please try again."),
                &format!("/assets/groups/{}/add-asset", uuid_str),
            );
        }
    };

    let now = chrono::Utc::now();
    let mut added: usize = 0;

    for aid in asset_ids {
        if !allow_multiple {
            let has_any = match aag::asset_asset_groups
                .filter(aag::asset_id.eq(aid))
                .select(aag::asset_id)
                .first::<i32>(&mut conn)
                .await
                .optional()
            {
                Ok(o) => o.is_some(),
                Err(_) => {
                    return flash_redirect(
                        flash.error("Database error. Please try again."),
                        &format!("/assets/groups/{}/add-asset", uuid_str),
                    );
                }
            };
            if has_any {
                continue;
            }
        } else {
            let in_target = match aag::asset_asset_groups
                .filter(aag::asset_id.eq(aid))
                .filter(aag::asset_group_id.eq(group_id))
                .select(aag::asset_id)
                .first::<i32>(&mut conn)
                .await
                .optional()
            {
                Ok(o) => o.is_some(),
                Err(_) => {
                    return flash_redirect(
                        flash.error("Database error. Please try again."),
                        &format!("/assets/groups/{}/add-asset", uuid_str),
                    );
                }
            };
            if in_target {
                continue;
            }
        }

        match diesel::insert_into(aag::asset_asset_groups)
            .values(NewAssetAssetGroup {
                asset_id: aid,
                asset_group_id: group_id,
            })
            .execute(&mut conn)
            .await
        {
            Ok(1) => {
                let _ = diesel::update(a::assets.filter(a::id.eq(aid)))
                    .set(a::updated_at.eq(now))
                    .execute(&mut conn)
                    .await;
                added += 1;
            }
            Ok(_) => {}
            Err(_) => {
                return flash_redirect(
                    flash.error("Failed to add assets to group. Please try again."),
                    &format!("/assets/groups/{}/add-asset", uuid_str),
                );
            }
        }
    }

    match added {
        0 => flash_redirect(
            flash.error("No assets were added. They may already be assigned to groups."),
            &format!("/assets/groups/{}/add-asset", uuid_str),
        ),
        1 => flash_redirect(
            flash.success("1 asset added to group successfully"),
            &format!("/assets/groups/{}", uuid_str),
        ),
        n => flash_redirect(
            flash.success(format!("{} assets added to group successfully", n)),
            &format!("/assets/groups/{}", uuid_str),
        ),
    }
}

/// Form data for removing an asset from a group.
#[derive(Debug, serde::Deserialize)]
pub struct RemoveAssetFromGroupForm {
    pub asset_uuid: String,
    pub csrf_token: String,
}

/// Handle removing an asset from a group.
//
// Axum extractors are positional and `headers` was added to gate the
// HX-Redirect dialect (BUG-12 / issue #19). Splitting purely for the arg
// count would obscure the linear remove flow.
#[allow(clippy::too_many_arguments)]
pub async fn asset_group_remove_asset(
    State(state): State<AppState>,
    _auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    headers: axum::http::HeaderMap,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
    Form(form): Form<RemoveAssetFromGroupForm>,
) -> Response {
    let flash = incoming_flash.flash();

    // BUG-12 / issue #19: HTMX-driven flow uses HX-Redirect — see
    // `htmx_or_flash_redirect` for the rationale.

    // CSRF validation
    let csrf_cookie = jar.get(crate::middleware::csrf::CSRF_COOKIE_NAME);
    if !crate::middleware::csrf::validate_double_submit(
        state.config.secret_key.expose_secret().as_bytes(),
        csrf_cookie.map(|c| c.value()),
        &form.csrf_token,
    ) {
        return htmx_or_flash_redirect(
            &headers,
            flash.error("Invalid CSRF token. Please refresh the page and try again."),
            &format!("/assets/groups/{}", uuid_str),
        );
    }

    if !perms.groups_write {
        return htmx_or_flash_redirect(
            &headers,
            flash.error("Only administrators can manage asset group membership"),
            &format!("/assets/groups/{}", uuid_str),
        );
    }

    // Defense-in-depth on top of the DB trigger: the virtual "All assets"
    // group has no membership rows by invariant, so a remove is nonsense.
    if is_virtual_asset_group_uuid(&uuid_str) {
        return htmx_or_flash_redirect(
            &headers,
            flash
                .error("Cannot remove assets from the 'All assets' virtual group (system-managed)"),
            "/assets/groups",
        );
    }

    // Parse group UUID (for redirect)
    let group_uuid = match ::uuid::Uuid::parse_str(&uuid_str) {
        Ok(uuid) => uuid,
        Err(_) => {
            return htmx_or_flash_redirect(
                &headers,
                flash.error("Invalid group identifier"),
                "/assets/groups",
            );
        }
    };

    // Parse asset UUID
    let asset_uuid = match ::uuid::Uuid::parse_str(&form.asset_uuid) {
        Ok(uuid) => uuid,
        Err(_) => {
            return htmx_or_flash_redirect(
                &headers,
                flash.error("Invalid asset identifier"),
                &format!("/assets/groups/{}", group_uuid),
            );
        }
    };

    let mut conn = match state.db_pool.get().await {
        Ok(conn) => conn,
        Err(_) => {
            return htmx_or_flash_redirect(
                &headers,
                flash.error("Database connection error. Please try again."),
                &format!("/assets/groups/{}", group_uuid),
            );
        }
    };

    use crate::schema::asset_asset_groups::dsl as aag;
    use crate::schema::asset_groups::dsl as ag;
    use crate::schema::assets::dsl as a;

    let group_pk: i32 = match ag::asset_groups
        .filter(ag::uuid.eq(group_uuid))
        .filter(ag::is_deleted.eq(false))
        .select(ag::id)
        .first(&mut conn)
        .await
    {
        Ok(id) => id,
        Err(diesel::result::Error::NotFound) => {
            return htmx_or_flash_redirect(
                &headers,
                flash.error("Asset group not found"),
                "/assets/groups",
            );
        }
        Err(_) => {
            return htmx_or_flash_redirect(
                &headers,
                flash.error("Database error. Please try again."),
                &format!("/assets/groups/{}", group_uuid),
            );
        }
    };

    let asset_pk: i32 = match a::assets
        .filter(a::uuid.eq(asset_uuid))
        .filter(a::is_deleted.eq(false))
        .select(a::id)
        .first(&mut conn)
        .await
    {
        Ok(id) => id,
        Err(diesel::result::Error::NotFound) => {
            return htmx_or_flash_redirect(
                &headers,
                flash.error("Asset not found"),
                &format!("/assets/groups/{}", group_uuid),
            );
        }
        Err(_) => {
            return htmx_or_flash_redirect(
                &headers,
                flash.error("Database error. Please try again."),
                &format!("/assets/groups/{}", group_uuid),
            );
        }
    };

    let deleted = diesel::delete(
        aag::asset_asset_groups
            .filter(aag::asset_id.eq(asset_pk))
            .filter(aag::asset_group_id.eq(group_pk)),
    )
    .execute(&mut conn)
    .await;

    match deleted {
        Ok(0) => htmx_or_flash_redirect(
            &headers,
            flash.error("Asset was not a member of this group"),
            &format!("/assets/groups/{}", group_uuid),
        ),
        Ok(_) => {
            let _ = diesel::update(a::assets.filter(a::id.eq(asset_pk)))
                .set(a::updated_at.eq(chrono::Utc::now()))
                .execute(&mut conn)
                .await;
            htmx_or_flash_redirect(
                &headers,
                flash.success("Asset removed from group successfully"),
                &format!("/assets/groups/{}", group_uuid),
            )
        }
        Err(_) => htmx_or_flash_redirect(
            &headers,
            flash.error("Failed to remove asset from group. Please try again."),
            &format!("/assets/groups/{}", group_uuid),
        ),
    }
}

/// Asset group edit page.
pub async fn asset_group_edit(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
) -> Response {
    let flash = incoming_flash.flash();

    if !perms.groups_write {
        return flash_redirect(
            flash.error("Only administrators can edit asset groups"),
            "/assets/groups",
        );
    }

    // Virtual "All assets" group is system-managed: present it as not found
    // so it cannot be edited. The DB trigger
    // `block_mutation_on_virtual_groups` would also reject the underlying
    // UPDATE, but failing here is friendlier.
    if is_virtual_asset_group_uuid(&uuid_str) {
        return flash_redirect(flash.error("Asset group not found"), "/assets/groups");
    }

    let user = Some(user_context_from_auth(&auth_user));

    // Convert incoming flash messages to template FlashMessages
    let flash_messages: Vec<crate::templates::base::FlashMessage> = incoming_flash
        .messages()
        .iter()
        .map(|m| crate::templates::base::FlashMessage {
            level: m.level.clone(),
            message: m.message.clone(),
        })
        .collect();

    let client = &state.access_client;
    let group = {
        let group_info = match client.get_asset_group(&uuid_str).await {
            Ok(info) => info,
            Err(_) => {
                return flash_redirect(flash.error("Asset group not found"), "/assets/groups");
            }
        };
        crate::templates::assets::group_edit::AssetGroupEdit {
            uuid: group_info.uuid,
            name: group_info.name,
            slug: group_info.slug,
            description: group_info.description,
            color: group_info.color,
            icon: group_info.icon,
        }
    };

    let base = BaseTemplate::new(format!("Edit {} - Asset Group", group.name), user.clone())
        .with_current_path("/assets/groups")
        .with_messages(flash_messages);
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

    let template = AssetGroupEditTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        group,
    };

    // Flash cookie cleanup is handled centrally by `flash_middleware`
    // (see `vauban-web/src/middleware/flash.rs`).
    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(_) => flash_redirect(flash.error("Failed to render page"), "/assets/groups"),
    }
}

/// Form data for updating asset group.
#[derive(Debug, serde::Deserialize)]
pub struct UpdateAssetGroupForm {
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub color: String,
    pub icon: String,
    pub csrf_token: String,
}

/// Update asset group handler (Web form with PRG pattern).
///
/// Handles POST /assets/groups/{uuid}/edit with flash messages.
pub async fn update_asset_group(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
    axum::extract::Form(form): axum::extract::Form<UpdateAssetGroupForm>,
) -> Response {
    let flash = incoming_flash.flash();
    let secret = state.config.secret_key.expose_secret().as_bytes();
    let csrf_cookie = jar.get(crate::middleware::csrf::CSRF_COOKIE_NAME);
    if !crate::middleware::csrf::validate_double_submit(
        secret,
        csrf_cookie.map(|c| c.value()),
        &form.csrf_token,
    ) {
        return flash_redirect(
            flash.error("Invalid CSRF token. Please refresh the page and try again."),
            &format!("/assets/groups/{}/edit", uuid_str),
        );
    }

    if !perms.groups_write {
        return flash_redirect(
            flash.error("Only administrators can modify asset groups"),
            &format!("/assets/groups/{}", uuid_str),
        );
    }

    // Defense-in-depth on top of the DB trigger
    // `block_mutation_on_virtual_groups`: refuse to even attempt updating
    // the singleton virtual "All assets" group.
    if is_virtual_asset_group_uuid(&uuid_str) {
        return flash_redirect(
            flash.error("Cannot modify the 'All assets' virtual group (system-managed)"),
            "/assets/groups",
        );
    }

    // Validate UUID
    let group_uuid = match ::uuid::Uuid::parse_str(&uuid_str) {
        Ok(uuid) => uuid,
        Err(_) => {
            return flash_redirect(
                flash.error("Invalid group identifier"),
                &format!("/assets/groups/{}/edit", uuid_str),
            );
        }
    };

    // Validate form fields
    if form.name.trim().is_empty() {
        return flash_redirect(
            flash.error("Group name is required"),
            &format!("/assets/groups/{}/edit", group_uuid),
        );
    }

    if form.slug.trim().is_empty() {
        return flash_redirect(
            flash.error("Group slug is required"),
            &format!("/assets/groups/{}/edit", group_uuid),
        );
    }

    // Sanitize text fields to prevent stored XSS
    let sanitized_name = sanitize(&form.name);
    let sanitized_description = sanitize_opt(form.description.clone());

    let client = &state.access_client;
    // Issue #22 — forward the operator UUID so vauban-access
    // re-stamps `updated_by_id` on the row.
    let result: Result<(), AppError> = client
        .update_asset_group(
            &uuid_str,
            &sanitized_name,
            &form.slug,
            sanitized_description,
            &form.color,
            &form.icon,
            Some(auth_user.uuid.clone()),
        )
        .await
        .map(|_| ());

    match result {
        Ok(_) => flash_redirect(
            flash.success("Asset group updated successfully"),
            &format!("/assets/groups/{}", group_uuid),
        ),
        Err(_) => flash_redirect(
            flash.error("Failed to update asset group. Please try again."),
            &format!("/assets/groups/{}/edit", group_uuid),
        ),
    }
}

/// Asset group create form page.
pub async fn asset_group_create_form(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
) -> Result<impl IntoResponse, AppError> {
    use crate::templates::assets::group_create::{AssetGroupCreateForm, AssetGroupCreateTemplate};

    if !perms.groups_write {
        return Err(AppError::Authorization(
            "Only administrators can create asset groups".to_string(),
        ));
    }

    // Convert incoming flash messages to template FlashMessages
    let flash_messages: Vec<crate::templates::base::FlashMessage> = incoming_flash
        .messages()
        .iter()
        .map(|m| crate::templates::base::FlashMessage {
            level: m.level.clone(),
            message: m.message.clone(),
        })
        .collect();

    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new("New Asset Group".to_string(), user.clone())
        .with_current_path("/assets/groups")
        .with_messages(flash_messages);
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

    let csrf_token = jar
        .get(crate::middleware::csrf::CSRF_COOKIE_NAME)
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    let form = AssetGroupCreateForm {
        color: "#6366f1".to_string(), // Default color (indigo)
        icon: "server".to_string(),
        ..Default::default()
    };

    let template = AssetGroupCreateTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        form,
        csrf_token,
    };

    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;

    // Flash cookie cleanup is handled centrally by `flash_middleware`
    // (see `vauban-web/src/middleware/flash.rs`).
    Ok(Html(html))
}

/// Form data for creating an asset group via web form.
#[derive(Debug, serde::Deserialize)]
pub struct CreateAssetGroupWebForm {
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub color: String,
    pub icon: String,
    pub csrf_token: String,
}

/// Handle asset group creation form submission.
pub async fn create_asset_group_web(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    Form(form): Form<CreateAssetGroupWebForm>,
) -> Response {
    let flash = incoming_flash.flash();

    // CSRF validation
    let csrf_cookie = jar.get(crate::middleware::csrf::CSRF_COOKIE_NAME);
    if !crate::middleware::csrf::validate_double_submit(
        state.config.secret_key.expose_secret().as_bytes(),
        csrf_cookie.map(|c| c.value()),
        &form.csrf_token,
    ) {
        return flash_redirect(flash.error("Invalid CSRF token"), "/assets/groups/new");
    }

    if !perms.groups_write {
        return flash_redirect(
            flash.error("Only administrators can create asset groups"),
            "/assets/groups",
        );
    }

    // Validate form data
    if form.name.trim().is_empty() {
        return flash_redirect(flash.error("Group name is required"), "/assets/groups/new");
    }
    if form.slug.trim().is_empty() {
        return flash_redirect(flash.error("Group slug is required"), "/assets/groups/new");
    }

    // Sanitize text fields to prevent stored XSS
    let sanitized_name = sanitize(form.name.trim());
    let sanitized_description =
        sanitize_opt(form.description.as_ref().filter(|s| !s.is_empty()).cloned());

    let client = &state.access_client;
    // Issue #22 — forward the operator UUID so vauban-access
    // stamps `created_by_id` / `updated_by_id` on the new row.
    let result = client
        .create_asset_group(
            &sanitized_name,
            form.slug.trim(),
            sanitized_description,
            &form.color,
            &form.icon,
            Some(auth_user.uuid.clone()),
        )
        .await;

    match result {
        Ok(info) => flash_redirect(
            flash.success(format!("Asset group '{}' created successfully", info.name)),
            &format!("/assets/groups/{}", info.uuid),
        ),
        Err(e) => {
            let msg = e.to_string();
            if msg.to_lowercase().contains("slug") || msg.to_lowercase().contains("unique") {
                flash_redirect(
                    flash.error("An asset group with this slug already exists"),
                    "/assets/groups/new",
                )
            } else {
                tracing::error!("Failed to create asset group: {}", e);
                flash_redirect(
                    flash.error("Failed to create asset group"),
                    "/assets/groups/new",
                )
            }
        }
    }
}

/// Form data for deleting an asset group.
#[derive(Debug, serde::Deserialize)]
pub struct DeleteAssetGroupForm {
    pub csrf_token: String,
}

/// Delete asset group handler (Web form with PRG pattern).
///
/// Hard-deletes the asset group and its asset associations.
//
// Axum extractors are positional and `headers` was added to gate the
// HX-Redirect dialect (BUG-12 / issue #19). Splitting purely for the arg
// count would obscure the linear delete flow.
#[allow(clippy::too_many_arguments)]
pub async fn delete_asset_group_web(
    State(state): State<AppState>,
    _auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    headers: axum::http::HeaderMap,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
    Form(form): Form<DeleteAssetGroupForm>,
) -> Response {
    let flash = incoming_flash.flash();

    // BUG-12 / issue #19: HTMX-driven flow uses HX-Redirect — see
    // `htmx_or_flash_redirect` for the rationale.

    // CSRF validation
    let csrf_cookie = jar.get(crate::middleware::csrf::CSRF_COOKIE_NAME);
    if !crate::middleware::csrf::validate_double_submit(
        state.config.secret_key.expose_secret().as_bytes(),
        csrf_cookie.map(|c| c.value()),
        &form.csrf_token,
    ) {
        return htmx_or_flash_redirect(
            &headers,
            flash.error("Invalid CSRF token"),
            &format!("/assets/groups/{}", uuid_str),
        );
    }

    if !perms.groups_write {
        return htmx_or_flash_redirect(
            &headers,
            flash.error("Only administrators can delete asset groups"),
            "/assets/groups",
        );
    }

    // Defense-in-depth on top of the DB trigger
    // `block_mutation_on_virtual_groups`: refuse to even attempt deleting
    // the singleton virtual "All assets" group.
    if is_virtual_asset_group_uuid(&uuid_str) {
        return htmx_or_flash_redirect(
            &headers,
            flash.error("Cannot delete the 'All assets' virtual group (system-managed)"),
            "/assets/groups",
        );
    }

    // Validate UUID
    if ::uuid::Uuid::parse_str(&uuid_str).is_err() {
        return htmx_or_flash_redirect(
            &headers,
            flash.error("Invalid group identifier"),
            "/assets/groups",
        );
    }

    let client = &state.access_client;
    let result = {
        // IPC path: get group to know id, clear local assets, then delete via IPC
        let group_info = match client.get_asset_group(&uuid_str).await {
            Ok(info) => info,
            Err(_) => {
                return htmx_or_flash_redirect(
                    &headers,
                    flash.error("Asset group not found"),
                    "/assets/groups",
                );
            }
        };
        let mut conn = match state.db_pool.get().await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Database connection error: {}", e);
                return htmx_or_flash_redirect(
                    &headers,
                    flash.error("Database connection error"),
                    &format!("/assets/groups/{}", uuid_str),
                );
            }
        };
        use crate::schema::asset_asset_groups::dsl as aag;
        let _ =
            diesel::delete(aag::asset_asset_groups.filter(aag::asset_group_id.eq(group_info.id)))
                .execute(&mut conn)
                .await;
        client
            .delete_asset_group(&uuid_str)
            .await
            .map(|_| group_info.name)
    };

    match result {
        Ok(group_name) => htmx_or_flash_redirect(
            &headers,
            flash.success(format!("Asset group '{}' deleted successfully", group_name)),
            "/assets/groups",
        ),
        Err(e) => {
            tracing::error!("Failed to delete asset group: {}", e);
            htmx_or_flash_redirect(
                &headers,
                flash.error("Failed to delete asset group"),
                &format!("/assets/groups/{}", uuid_str),
            )
        }
    }
}
