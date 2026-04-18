/// Asset management page handlers.
use super::*;
use crate::models::asset::{Asset, AssetType};

const ASSETS_PER_PAGE: i64 = 30;

/// Asset create form page.
pub async fn asset_create_form(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    jar: CookieJar,
) -> Result<impl IntoResponse, AppError> {
    use crate::templates::assets::asset_create::{AssetCreateForm, AssetCreateTemplate};

    if !perms.assets_write {
        return Err(AppError::Authorization(
            "Only administrators can create assets".to_string(),
        ));
    }

    let user = Some(user_context_from_auth(&auth_user));
    let base =
        BaseTemplate::new("New Asset".to_string(), user.clone()).with_current_path("/assets");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

    let csrf_token = jar
        .get(crate::middleware::csrf::CSRF_COOKIE_NAME)
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    let form = AssetCreateForm {
        port: 22, // Default SSH port
        asset_type: "ssh".to_string(),
        status: "online".to_string(),
        ..Default::default()
    };

    let template = AssetCreateTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        form,
        csrf_token,
        asset_types: vec![
            ("ssh".to_string(), "SSH".to_string()),
            ("rdp".to_string(), "RDP".to_string()),
        ],
    };

    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;
    Ok(Html(html))
}

/// Form data for creating an asset via web form.
#[derive(Debug, serde::Deserialize)]
pub struct CreateAssetWebForm {
    pub name: String,
    pub hostname: String,
    pub port: i32,
    pub asset_type: String,
    pub status: String,
    pub description: Option<String>,
    pub csrf_token: String,
    /// SSH username for authentication
    pub ssh_username: Option<String>,
    /// Authentication type: "password" or "private_key"
    pub ssh_auth_type: Option<String>,
    /// Password for password-based authentication
    pub ssh_password: Option<String>,
    /// Private key content for key-based authentication
    pub ssh_private_key: Option<String>,
    /// Passphrase for encrypted private keys
    pub ssh_passphrase: Option<String>,
}

/// Handle asset creation form submission.
pub async fn create_asset_web(
    State(state): State<AppState>,
    _auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    Form(form): Form<CreateAssetWebForm>,
) -> Response {
    let flash = incoming_flash.flash();

    // CSRF validation
    let csrf_cookie = jar.get(crate::middleware::csrf::CSRF_COOKIE_NAME);
    if !crate::middleware::csrf::validate_double_submit(
        state.config.secret_key.expose_secret().as_bytes(),
        csrf_cookie.map(|c| c.value()),
        &form.csrf_token,
    ) {
        return flash_redirect(flash.error("Invalid CSRF token"), "/assets/new");
    }

    if !perms.assets_write {
        return flash_redirect(
            flash.error("Only administrators can create assets"),
            "/assets",
        );
    }

    // Validate form data
    if form.name.trim().is_empty() {
        return flash_redirect(flash.error("Asset name is required"), "/assets/new");
    }
    if form.hostname.trim().is_empty() {
        return flash_redirect(flash.error("Hostname is required"), "/assets/new");
    }
    if form.port < 1 || form.port > 65535 {
        return flash_redirect(
            flash.error("Port must be between 1 and 65535"),
            "/assets/new",
        );
    }

    let mut conn = match state.db_pool.get().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Database connection error: {}", e);
            return flash_redirect(flash.error("Database connection error"), "/assets/new");
        }
    };

    // Determine connection username (default to "root" if not provided)
    let connection_username = form
        .ssh_username
        .as_deref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or("root");

    // Check if asset with same hostname+port+username already exists (active)
    use crate::schema::assets::dsl as a;
    let existing_active: Option<i32> = a::assets
        .filter(a::hostname.eq(form.hostname.trim()))
        .filter(a::port.eq(form.port))
        .filter(a::connection_username.eq(connection_username))
        .filter(a::is_deleted.eq(false))
        .select(a::id)
        .first(&mut conn)
        .await
        .optional()
        .unwrap_or(None);

    if existing_active.is_some() {
        return flash_redirect(
            flash.error("An asset with this hostname, port and username already exists"),
            "/assets/new",
        );
    }

    // Check if a soft-deleted asset with same hostname+port+username exists - reactivate it
    let existing_deleted: Option<(i32, ::uuid::Uuid)> = a::assets
        .filter(a::hostname.eq(form.hostname.trim()))
        .filter(a::port.eq(form.port))
        .filter(a::connection_username.eq(connection_username))
        .filter(a::is_deleted.eq(true))
        .select((a::id, a::uuid))
        .first(&mut conn)
        .await
        .optional()
        .unwrap_or(None);

    let now = chrono::Utc::now();

    // Sanitize text fields to prevent stored XSS
    let sanitized_name = sanitize(form.name.trim());
    let sanitized_description =
        sanitize_opt(form.description.as_ref().filter(|s| !s.is_empty()).cloned());
    let parsed_asset_type = AssetType::parse(&form.asset_type);

    if let Some((deleted_id, deleted_uuid)) = existing_deleted {
        // Reactivate the soft-deleted asset with new data
        let result = diesel::update(a::assets.filter(a::id.eq(deleted_id)))
            .set((
                a::name.eq(&sanitized_name),
                a::asset_type.eq(parsed_asset_type),
                a::status.eq(&form.status),
                a::description.eq(&sanitized_description),
                a::connection_username.eq(connection_username),
                a::is_deleted.eq(false),
                a::deleted_at.eq(None::<chrono::DateTime<chrono::Utc>>),
                a::updated_at.eq(now),
            ))
            .execute(&mut conn)
            .await;

        return match result {
            Ok(_) => flash_redirect(
                flash.success(format!(
                    "Asset '{}' reactivated successfully",
                    sanitized_name
                )),
                &format!("/assets/{}", deleted_uuid),
            ),
            Err(e) => {
                tracing::error!("Failed to reactivate asset: {}", e);
                flash_redirect(flash.error("Failed to reactivate asset"), "/assets/new")
            }
        };
    }

    // Create new asset
    let new_uuid = ::uuid::Uuid::new_v4();

    // Build connection_config JSON with SSH credentials
    let mut connection_config = build_connection_config(
        form.ssh_username.as_deref(),
        form.ssh_auth_type.as_deref(),
        form.ssh_password.as_deref(),
        form.ssh_private_key.as_deref(),
        form.ssh_passphrase.as_deref(),
    );

    // Encrypt credential fields via vault when available
    if let Some(ref vault) = state.vault_client
        && let Err(e) = encrypt_connection_config(vault, &mut connection_config).await
    {
        tracing::error!("Failed to encrypt connection config: {}", e);
        return flash_redirect(
            flash.error("Failed to encrypt credentials"),
            "/assets/create",
        );
    }

    let result = diesel::insert_into(a::assets)
        .values((
            a::uuid.eq(new_uuid),
            a::name.eq(&sanitized_name),
            a::hostname.eq(form.hostname.trim()),
            a::port.eq(form.port),
            a::asset_type.eq(parsed_asset_type),
            a::status.eq(&form.status),
            a::description.eq(&sanitized_description),
            a::connection_config.eq(connection_config),
            a::connection_username.eq(connection_username),
            a::is_deleted.eq(false),
            a::created_at.eq(now),
            a::updated_at.eq(now),
        ))
        .execute(&mut conn)
        .await;

    match result {
        Ok(_) => flash_redirect(
            flash.success(format!("Asset '{}' created successfully", sanitized_name)),
            &format!("/assets/{}", new_uuid),
        ),
        Err(e) => {
            tracing::error!("Failed to create asset: {}", e);
            flash_redirect(flash.error("Failed to create asset"), "/assets/new")
        }
    }
}

/// Asset list page.
pub async fn asset_list(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse, AppError> {
    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new("Assets".to_string(), user.clone()).with_current_path("/assets");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

    // Sourced from the request-scoped PermissionContext (Casbin via middleware).
    let user_is_admin = perms.assets_read;

    // Load assets from database
    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;

    // Filter out empty strings - form sends empty string when "All" is selected
    let search_filter = params.get("search").filter(|s| !s.is_empty()).cloned();
    let type_filter = params.get("type").filter(|s| !s.is_empty()).cloned();
    let status_filter = params.get("status").filter(|s| !s.is_empty()).cloned();
    let page: i32 = params
        .get("page")
        .and_then(|s| s.parse::<i32>().ok())
        .unwrap_or(1)
        .max(1);

    // Resolve user internal ID for non-admin users (used for access filtering + approval queries)
    let user_internal_id: Option<i32> = if !auth_user.is_superuser && !auth_user.is_staff {
        let uid: i32 = crate::schema::users::table
            .filter(
                crate::schema::users::uuid
                    .eq(::uuid::Uuid::parse_str(&auth_user.uuid).unwrap_or_default()),
            )
            .select(crate::schema::users::id)
            .first(&mut conn)
            .await
            .map_err(|_| AppError::Authorization("User not found".to_string()))?;
        Some(uid)
    } else {
        None
    };

    // Resolve accessible asset IDs once for non-admin users
    let accessible_ids: Option<Vec<i32>> = if let Some(uid) = user_internal_id {
        let ids = crate::services::access::list_accessible_asset_ids(
            &state.access_client,
            &mut conn,
            uid,
        )
        .await?;
        Some(ids)
    } else {
        None
    };

    // Build count query with the same filters
    let mut count_query = schema_assets::table
        .filter(schema_assets::is_deleted.eq(false))
        .into_boxed();

    if let Some(ref ids) = accessible_ids {
        count_query = count_query.filter(schema_assets::id.eq_any(ids.clone()));
    }
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

    // Build data query with the same filters
    let mut query = schema_assets::table
        .filter(schema_assets::is_deleted.eq(false))
        .into_boxed();

    if let Some(ref ids) = accessible_ids {
        query = query.filter(schema_assets::id.eq_any(ids.clone()));
    }
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

    let (approval_set, approved_set) = if let Some(uid) = user_internal_id {
        use crate::schema::{access_rules, asset_asset_groups, user_groups};

        let approval_ids: Vec<i32> = access_rules::table
            .inner_join(
                asset_asset_groups::table
                    .on(asset_asset_groups::asset_group_id.eq(access_rules::asset_group_id)),
            )
            .inner_join(
                user_groups::table.on(user_groups::group_id.eq(access_rules::user_group_id)),
            )
            .filter(user_groups::user_id.eq(uid))
            .filter(access_rules::is_active.eq(true))
            .filter(access_rules::require_approval.eq(true))
            .filter(asset_asset_groups::asset_id.eq_any(&displayed_asset_ids))
            .select(asset_asset_groups::asset_id)
            .distinct()
            .load(&mut conn)
            .await
            .unwrap_or_default();

        let approved_ids: Vec<i32> = proxy_sessions::table
            .filter(proxy_sessions::user_id.eq(uid))
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
    } else {
        (
            std::collections::HashSet::new(),
            std::collections::HashSet::new(),
        )
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
        show_view_link: user_is_admin,
        require_justification: state.config.security.require_justification,
    };

    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;
    Ok(Html(html))
}

/// Asset search (header quick search).
pub async fn asset_search(
    State(state): State<AppState>,
    _auth_user: WebAuthUser,
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse, AppError> {
    use crate::schema::assets::dsl as a;

    let query = params.get("search").map(|s| s.trim()).unwrap_or("");
    if query.is_empty() {
        return Ok(Html(String::new()));
    }

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;
    let pattern = crate::db::like_contains(query);

    let rows: Vec<(uuid::Uuid, String, String, AssetType, String)> = a::assets
        .filter(a::is_deleted.eq(false))
        .filter(a::name.ilike(&pattern).or(a::hostname.ilike(&pattern)))
        .select((a::uuid, a::name, a::hostname, a::asset_type, a::status))
        .order(a::name.asc())
        .limit(8)
        .load(&mut conn)
        .await?;

    if rows.is_empty() {
        return Ok(Html(String::new()));
    }

    let mut html = String::from(
        r#"<div class="rounded-md bg-white dark:bg-gray-800 shadow ring-1 ring-gray-200 dark:ring-gray-700">
<ul class="divide-y divide-gray-200 dark:divide-gray-700">"#,
    );

    for (asset_uuid, name, hostname, asset_type, status) in rows {
        // SAFETY: askama HTML escape infallible for valid UTF-8 strings
        #[allow(clippy::unwrap_used)]
        let name = askama::filters::escape(&name, askama::filters::Html)
            .unwrap()
            .to_string();
        #[allow(clippy::unwrap_used)]
        let hostname = askama::filters::escape(&hostname, askama::filters::Html)
            .unwrap()
            .to_string();
        let asset_type = asset_type.to_string();
        #[allow(clippy::unwrap_used)]
        let status = askama::filters::escape(&status, askama::filters::Html)
            .unwrap()
            .to_string();
        html.push_str(&format!(
            r#"<li class="p-3 hover:bg-gray-50 dark:hover:bg-gray-700">
<a class="block text-sm" href="/assets/{asset_uuid}">
<div class="font-medium text-gray-900 dark:text-white">{name}</div>
<div class="text-xs text-gray-500 dark:text-gray-400">{hostname} · {asset_type} · {status}</div>
</a>
</li>"#
        ));
    }

    html.push_str("</ul></div>");
    Ok(Html(html))
}

/// Asset detail page.
pub async fn asset_detail(
    State(state): State<AppState>,
    incoming_flash: IncomingFlash,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    axum::extract::Path(asset_uuid_str): axum::extract::Path<String>,
) -> Response {
    let flash = incoming_flash.flash();

    // Parse UUID manually to provide graceful redirect on malformed input
    let asset_uuid = match ::uuid::Uuid::parse_str(&asset_uuid_str) {
        Ok(uuid) => uuid,
        Err(_) => {
            return flash_redirect(flash.error("Invalid asset identifier"), "/assets");
        }
    };

    if !perms.assets_read {
        return flash_redirect(
            flash.error("Only administrators can view asset details"),
            "/assets",
        );
    }

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

    use crate::schema::asset_asset_groups::dsl as aag;
    use crate::schema::asset_groups::dsl as ag;
    use crate::schema::assets::dsl as a;

    let asset_model: Asset = match a::assets
        .filter(a::uuid.eq(asset_uuid))
        .filter(a::is_deleted.eq(false))
        .select(Asset::as_select())
        .first(&mut conn)
        .await
    {
        Ok(row) => row,
        Err(diesel::result::Error::NotFound) => {
            return flash_redirect(flash.error("Asset not found"), "/assets");
        }
        Err(_) => {
            return flash_redirect(flash.error("Database error. Please try again."), "/assets");
        }
    };

    let asset_name = asset_model.name.clone();

    // Instance-level access control: non-admin users must have an access rule
    if !auth_user.is_superuser && !auth_user.is_staff {
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
            Err(_) => return flash_redirect(flash.error("Access denied"), "/assets"),
        };

        let asset_internal_id = asset_model.id;

        let accessible_ids = crate::services::access::list_accessible_asset_ids(
            &state.access_client,
            &mut conn,
            user_internal_id,
        )
        .await
        .unwrap_or_default();

        if !accessible_ids.contains(&asset_internal_id) {
            return flash_redirect(flash.error("Access denied"), "/assets");
        }
    }

    // Determine JIT flags from access rules for the current user
    let (require_approval, require_mfa_from_rule, has_approved_session) =
        if !auth_user.is_superuser && !auth_user.is_staff {
            let user_internal_id: i32 = crate::schema::users::table
                .filter(
                    crate::schema::users::uuid
                        .eq(::uuid::Uuid::parse_str(&auth_user.uuid).unwrap_or_default()),
                )
                .select(crate::schema::users::id)
                .first(&mut conn)
                .await
                .unwrap_or(0);

            let access_result = crate::services::access::can_access_asset(
                &state.access_client,
                &mut conn,
                user_internal_id,
                asset_model.id,
                asset_model.asset_type.as_str(),
            )
            .await
            .unwrap_or_else(|_| crate::services::access::AccessCheckResult::denied());

            let approved = if access_result.require_approval {
                use crate::schema::proxy_sessions;
                proxy_sessions::table
                    .filter(proxy_sessions::user_id.eq(user_internal_id))
                    .filter(proxy_sessions::asset_id.eq(asset_model.id))
                    .filter(proxy_sessions::status.eq("approved"))
                    .filter(
                        proxy_sessions::expires_at
                            .is_null()
                            .or(proxy_sessions::expires_at.gt(diesel::dsl::now)),
                    )
                    .select(proxy_sessions::uuid)
                    .first::<::uuid::Uuid>(&mut conn)
                    .await
                    .is_ok()
            } else {
                false
            };

            (
                access_result.require_approval,
                access_result.require_mfa,
                approved,
            )
        } else {
            (false, false, false)
        };

    // Extract SSH host key fingerprint and mismatch status from connection_config
    let asset_connection_config = &asset_model.connection_config;
    let ssh_host_key_fingerprint = asset_connection_config
        .get("ssh_host_key_fingerprint")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let ssh_host_key_mismatch = asset_connection_config
        .get("ssh_host_key_mismatch")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let group_rows: Vec<(String, ::uuid::Uuid)> = aag::asset_asset_groups
        .inner_join(ag::asset_groups.on(aag::asset_group_id.eq(ag::id)))
        .filter(aag::asset_id.eq(asset_model.id))
        .filter(ag::is_deleted.eq(false))
        .select((ag::name, ag::uuid))
        .load(&mut conn)
        .await
        .unwrap_or_default();

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

    let asset = crate::templates::assets::asset_detail::AssetDetail {
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
        require_mfa: require_mfa_from_rule,
        created_at: asset_model.created_at.format("%b %d, %Y %H:%M").to_string(),
        updated_at: asset_model.updated_at.format("%b %d, %Y %H:%M").to_string(),
        ssh_host_key_fingerprint,
        ssh_host_key_mismatch,
        has_approved_session,
        require_justification: state.config.security.require_justification,
    };

    let base = BaseTemplate::new(format!("{} - Asset", asset_name), user.clone())
        .with_current_path("/assets");
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

// NOTE: AssetQueryDetailResult removed - migrated to Diesel DSL tuple query

/// Asset edit page.
pub async fn asset_edit(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
) -> Response {
    let flash = incoming_flash.flash();

    if !perms.assets_write {
        return flash_redirect(
            flash.error("Only administrators can edit assets"),
            "/assets",
        );
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

    let mut conn = match state.db_pool.get().await {
        Ok(conn) => conn,
        Err(_) => {
            return flash_redirect(
                flash.error("Database connection error. Please try again."),
                "/assets",
            );
        }
    };

    let asset_uuid = match ::uuid::Uuid::parse_str(&uuid_str) {
        Ok(uuid) => uuid,
        Err(_) => {
            return flash_redirect(flash.error("Invalid asset identifier"), "/assets");
        }
    };

    use crate::schema::assets::dsl as a;

    // Query asset for editing
    #[allow(clippy::type_complexity)]
    let asset_row: (
        ::uuid::Uuid,
        String,
        String,
        i32,
        AssetType,
        String,
        Option<String>,
        serde_json::Value,
        String,
    ) = match a::assets
        .filter(a::uuid.eq(asset_uuid))
        .filter(a::is_deleted.eq(false))
        .select((
            a::uuid,
            a::name,
            a::hostname,
            a::port,
            a::asset_type,
            a::status,
            a::description,
            a::connection_config,
            a::connection_username,
        ))
        .first(&mut conn)
        .await
    {
        Ok(row) => row,
        Err(diesel::result::Error::NotFound) => {
            return flash_redirect(flash.error("Asset not found"), "/assets");
        }
        Err(_) => {
            return flash_redirect(flash.error("Database error. Please try again."), "/assets");
        }
    };

    let (
        asset_uuid_val,
        asset_name,
        asset_hostname,
        asset_port,
        asset_type_val,
        asset_status,
        asset_description,
        asset_connection_config,
        ssh_username,
    ) = asset_row;
    let ssh_auth_type = asset_connection_config
        .get("auth_type")
        .and_then(|v| v.as_str())
        .unwrap_or("password")
        .to_string();
    let ssh_password = asset_connection_config
        .get("password")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let ssh_private_key = asset_connection_config
        .get("private_key")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let ssh_passphrase = asset_connection_config
        .get("passphrase")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let ssh_host_key_fingerprint = asset_connection_config
        .get("ssh_host_key_fingerprint")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let asset = crate::templates::assets::asset_edit::AssetEdit {
        uuid: asset_uuid_val.to_string(),
        name: asset_name.clone(),
        hostname: asset_hostname,
        port: asset_port,
        asset_type: asset_type_val.to_string(),
        status: asset_status,
        description: asset_description,
        ssh_username,
        ssh_auth_type,
        ssh_password,
        ssh_private_key,
        ssh_passphrase,
        ssh_host_key_fingerprint,
    };

    let base = BaseTemplate::new(format!("Edit {} - Asset", asset_name), user.clone())
        .with_current_path("/assets")
        .with_messages(flash_messages);
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

    let template = AssetEditTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        asset,
    };

    // Flash cookie cleanup is handled centrally by `flash_middleware`
    // (see `vauban-web/src/middleware/flash.rs`): any request that
    // arrived with a `__vauban_flash` cookie exits with a clearing
    // Set-Cookie unless the handler itself just installed a fresh one.
    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(_) => flash_redirect(flash.error("Failed to render page"), "/assets"),
    }
}

/// Delete asset handler (Web form with PRG pattern).
///
/// Soft-deletes the asset and updates related approvals/sessions.
pub async fn delete_asset_web(
    State(state): State<AppState>,
    _auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
    Form(form): Form<DeleteAssetForm>,
) -> Response {
    let flash = incoming_flash.flash();

    let csrf_cookie = jar.get(crate::middleware::csrf::CSRF_COOKIE_NAME);
    let secret = state.config.secret_key.expose_secret().as_bytes();
    if !crate::middleware::csrf::validate_double_submit(
        secret,
        csrf_cookie.map(|c| c.value()),
        &form.csrf_token,
    ) {
        return flash_redirect(
            flash.error("Invalid CSRF token. Please refresh the page and try again."),
            &format!("/assets/{}", uuid_str),
        );
    }

    if !perms.assets_write {
        return flash_redirect(
            flash.error("You do not have permission to delete assets"),
            &format!("/assets/{}", uuid_str),
        );
    }

    let asset_uuid = match ::uuid::Uuid::parse_str(&uuid_str) {
        Ok(uuid) => uuid,
        Err(_) => {
            return flash_redirect(flash.error("Invalid asset identifier"), "/assets");
        }
    };

    let mut conn = match state.db_pool.get().await {
        Ok(conn) => conn,
        Err(_) => {
            return flash_redirect(
                flash.error("Database connection error. Please try again."),
                &format!("/assets/{}", asset_uuid),
            );
        }
    };

    use crate::schema::assets::dsl as a;
    use crate::schema::proxy_sessions::dsl as ps;
    use chrono::Utc;

    let asset_id: i32 = match a::assets
        .filter(a::uuid.eq(asset_uuid))
        .filter(a::is_deleted.eq(false))
        .select(a::id)
        .first(&mut conn)
        .await
    {
        Ok(id) => id,
        Err(diesel::result::Error::NotFound) => {
            return flash_redirect(flash.error("Asset not found or already deleted"), "/assets");
        }
        Err(_) => {
            return flash_redirect(
                flash.error("Failed to delete asset. Please try again."),
                &format!("/assets/{}", asset_uuid),
            );
        }
    };

    let now = Utc::now();
    let result = conn
        .transaction::<_, diesel::result::Error, _>(|conn| {
            Box::pin(async move {
                diesel::update(a::assets.filter(a::id.eq(asset_id)))
                    .set((
                        a::is_deleted.eq(true),
                        a::deleted_at.eq(now),
                        a::updated_at.eq(now),
                    ))
                    .execute(conn)
                    .await?;

                diesel::update(
                    ps::proxy_sessions
                        .filter(ps::asset_id.eq(asset_id))
                        .filter(ps::status.eq("active")),
                )
                .set((
                    ps::status.eq("terminated"),
                    ps::disconnected_at.eq(now),
                    ps::updated_at.eq(now),
                ))
                .execute(conn)
                .await?;

                Ok(())
            })
        })
        .await;

    match result {
        Ok(_) => {
            if let Err(err) = diesel::update(
                ps::proxy_sessions
                    .filter(ps::asset_id.eq(asset_id))
                    .filter(ps::status.eq_any(vec!["pending", "connecting"])),
            )
            .set((ps::status.eq("orphaned"), ps::updated_at.eq(now)))
            .execute(&mut conn)
            .await
            {
                tracing::error!("Failed to orphan approvals after delete: {}", err);
            }

            flash_redirect(flash.success("Asset deleted successfully"), "/assets")
        }
        Err(_) => flash_redirect(
            flash.error("Failed to delete asset. Please try again."),
            &format!("/assets/{}", asset_uuid),
        ),
    }
}

/// Form data for updating an asset (Web form).
#[derive(Debug, serde::Deserialize)]
pub struct UpdateAssetForm {
    pub name: String,
    pub hostname: String,
    pub port: i32,
    pub status: String,
    pub description: Option<String>,
    pub csrf_token: String,
    /// SSH username for authentication
    pub ssh_username: Option<String>,
    /// Authentication type: "password" or "private_key"
    pub ssh_auth_type: Option<String>,
    /// Password for password-based authentication
    pub ssh_password: Option<String>,
    /// Private key content for key-based authentication
    pub ssh_private_key: Option<String>,
    /// Passphrase for encrypted private keys
    pub ssh_passphrase: Option<String>,
}

/// Form data for deleting an asset.
#[derive(Debug, serde::Deserialize)]
pub struct DeleteAssetForm {
    pub csrf_token: String,
}

/// CSRF-only form payload for HTMX actions.
#[derive(Debug, serde::Deserialize)]
pub struct CsrfOnlyForm {
    pub csrf_token: String,
}

/// Update asset handler (Web form with PRG pattern).
///
/// Handles POST /assets/{uuid}/edit with flash messages.
pub async fn update_asset_web(
    State(state): State<AppState>,
    _auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
    axum::extract::Form(form): axum::extract::Form<UpdateAssetForm>,
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
            &format!("/assets/{}/edit", uuid_str),
        );
    }

    if !perms.assets_write {
        return flash_redirect(
            flash.error("Only administrators can modify assets"),
            &format!("/assets/{}", uuid_str),
        );
    }

    // Validate UUID
    let asset_uuid = match ::uuid::Uuid::parse_str(&uuid_str) {
        Ok(uuid) => uuid,
        Err(_) => {
            return flash_redirect(
                flash.error("Invalid asset identifier"),
                &format!("/assets/{}/edit", uuid_str),
            );
        }
    };

    // Validate form fields
    if form.name.trim().is_empty() {
        return flash_redirect(
            flash.error("Asset name is required"),
            &format!("/assets/{}/edit", asset_uuid),
        );
    }

    if form.hostname.trim().is_empty() {
        return flash_redirect(
            flash.error("Hostname is required"),
            &format!("/assets/{}/edit", asset_uuid),
        );
    }

    if form.port < 1 || form.port > 65535 {
        return flash_redirect(
            flash.error("Port must be between 1 and 65535"),
            &format!("/assets/{}/edit", asset_uuid),
        );
    }

    // Get database connection
    let mut conn = match state.db_pool.get().await {
        Ok(conn) => conn,
        Err(_) => {
            return flash_redirect(
                flash.error("Database connection error. Please try again."),
                &format!("/assets/{}/edit", asset_uuid),
            );
        }
    };

    use crate::schema::assets::dsl as a;
    use chrono::Utc;

    // First, get the existing asset to preserve unchanged values
    let existing: Result<crate::models::asset::Asset, _> = a::assets
        .filter(a::uuid.eq(asset_uuid))
        .filter(a::is_deleted.eq(false))
        .first(&mut conn)
        .await;

    let existing = match existing {
        Ok(asset) => asset,
        Err(_) => {
            return flash_redirect(flash.error("Asset not found"), "/assets");
        }
    };

    // Build connection_config JSON with SSH credentials
    let mut connection_config = build_connection_config(
        form.ssh_username.as_deref(),
        form.ssh_auth_type.as_deref(),
        form.ssh_password.as_deref(),
        form.ssh_private_key.as_deref(),
        form.ssh_passphrase.as_deref(),
    );

    // Encrypt credential fields via vault when available
    if let Some(ref vault) = state.vault_client
        && let Err(e) = encrypt_connection_config(vault, &mut connection_config).await
    {
        tracing::error!("Failed to encrypt connection config: {}", e);
        return flash_redirect(
            flash.error("Failed to encrypt credentials"),
            &format!("/assets/{}/edit", asset_uuid),
        );
    }

    // Sanitize text fields to prevent stored XSS
    let sanitized_name = sanitize(&form.name);
    let sanitized_description = sanitize_opt(form.description.clone());

    // Determine connection username
    let updated_username = form
        .ssh_username
        .as_deref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or(&existing.connection_username);

    // Update the asset
    let result = diesel::update(a::assets.filter(a::uuid.eq(asset_uuid)))
        .set((
            a::name.eq(&sanitized_name),
            a::hostname.eq(&form.hostname),
            a::port.eq(form.port),
            a::status.eq(&form.status),
            a::description.eq(sanitized_description.as_deref()),
            a::connection_config.eq(connection_config),
            a::connection_username.eq(updated_username),
            a::updated_at.eq(Utc::now()),
        ))
        .execute(&mut conn)
        .await;

    match result {
        Ok(_) => {
            // Success: redirect to detail page with success message
            flash_redirect(
                flash.success("Asset updated successfully"),
                &format!("/assets/{}", asset_uuid),
            )
        }
        Err(e) => {
            tracing::error!("Failed to update asset: {}", e);
            // Error: redirect back to edit page with error message
            flash_redirect(
                flash.error("Failed to update asset. Please try again."),
                &format!("/assets/{}/edit", asset_uuid),
            )
        }
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
