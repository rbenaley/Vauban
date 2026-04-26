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
    /// Optional Windows AD domain for RDP authentication.
    ///
    /// Stored as `connection_config.domain` and consumed by
    /// `vauban-proxy-rdp` (see `SessionConfig.domain`). Ignored for
    /// non-RDP `asset_type` values to keep the JSONB blob protocol-clean.
    pub rdp_domain: Option<String>,
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

    // Reject illegal protocol+auth combinations BEFORE we touch the DB so
    // a tampered request (UI bypass, scripted POST, ...) cannot persist
    // SSH credentials on an RDP row. Mirrors the carryover defence below.
    let parsed_asset_type = AssetType::parse(&form.asset_type);
    if let Err(msg) = validate_auth_inputs(
        parsed_asset_type,
        form.ssh_auth_type.as_deref(),
        form.ssh_private_key.as_deref(),
        form.ssh_passphrase.as_deref(),
    ) {
        return flash_redirect(flash.error(msg), "/assets/new");
    }

    // Enforce the FA ASS-02 / ASS-03 required-credential contract.
    // Without this, `build_connection_config` would silently drop empty
    // credential inputs and persist a row with no usable secret -- the
    // BUG-10 / CANARY-RDP-EMPTY-20260418 scenario.
    if let Err(msg) = validate_required_credentials(
        parsed_asset_type,
        form.ssh_auth_type.as_deref(),
        form.ssh_password.as_deref(),
        form.ssh_private_key.as_deref(),
    ) {
        return flash_redirect(flash.error(msg), "/assets/new");
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

    use crate::schema::assets::dsl as a;

    let now = chrono::Utc::now();

    // Sanitize text fields to prevent stored XSS
    let sanitized_name = sanitize(form.name.trim());
    let sanitized_description =
        sanitize_opt(form.description.as_ref().filter(|s| !s.is_empty()).cloned());

    let mut connection_config = build_connection_config(
        parsed_asset_type,
        form.ssh_username.as_deref(),
        form.ssh_auth_type.as_deref(),
        form.ssh_password.as_deref(),
        form.ssh_private_key.as_deref(),
        form.ssh_passphrase.as_deref(),
        form.rdp_domain.as_deref(),
    );

    if let Some(ref vault) = state.vault_client
        && let Err(e) = encrypt_connection_config(vault, &mut connection_config).await
    {
        tracing::error!("Failed to encrypt connection config: {}", e);
        return flash_redirect(flash.error("Failed to encrypt credentials"), "/assets/new");
    }

    // Issue #17: every create produces a fresh UUID. Soft-deleted rows
    // sharing the same (hostname, port, username) triplet are tombstones
    // (audit-only) and must NEVER be reactivated -- the
    // `assets_no_resurrection_trg` trigger and the irreversible-delete
    // policy (RG-ASS-04) make any other path a security regression.
    //
    // Uniqueness on the active triplet is enforced by the partial unique
    // index `idx_assets_hostname_port_username_active` (introduced in
    // 20260330000000_add_connection_username, re-documented from
    // 20260420000000_assets_irreversible_delete). We let the DB be the
    // source of truth: a UniqueViolation here means another active row
    // already exists, which we surface as a friendly flash. Any other
    // Diesel error is logged and reported generically.
    let new_uuid = ::uuid::Uuid::new_v4();

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
        Err(diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::UniqueViolation,
            _,
        )) => flash_redirect(
            flash.error("An asset with this hostname, port and username already exists"),
            "/assets/new",
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

    // Resolve user internal ID for ALL users (incl. superuser/staff) so that
    // the listing, the per-row "Request Access" badge, and the connect
    // handler all consult the same access policy. The historical
    // privileged-user bypass produced a UI that pretended access rules
    // didn't apply to admins, while the connect handler (since febd388)
    // and `submit_access_request` enforced them anyway — manifesting as
    // a blue "Connect" button that, on submit, was rejected with a
    // bogus "MFA code is required" prompt.
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

    // Build count query with the same filters
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

    // Build data query with the same filters
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
    // top-of-handler comment.
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

        // Supplementary check for the virtual "All assets" group.
        // If any active rule ties this user (via their groups) to the virtual
        // asset group AND requires approval, every asset on the page is covered.
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
        show_view_link: user_is_admin,
        require_justification: state.config.security.require_justification,
    };

    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;
    Ok(Html(html))
}

/// Issue #17 — read-only audit page listing soft-deleted assets.
///
/// Gated on `perms.assets_read` (admin / staff). The page exposes
/// strictly the audit-relevant columns -- no `connection_config`,
/// no edit / restore / connect affordances -- because deletion is
/// irreversible (RG-ASS-04) and tombstones carry `{}` as their
/// `connection_config` by contract (`assets_tombstone_no_secrets`
/// CHECK constraint, enforced at COMMIT time).
pub async fn asset_deleted_list(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse, AppError> {
    use crate::templates::accounts::user_list::Pagination;
    use crate::templates::assets::{AssetDeletedListTemplate, DeletedAssetItem};

    if !perms.assets_read {
        return Err(AppError::Authorization(
            "Only administrators can view the deleted assets audit page".to_string(),
        ));
    }

    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new("Deleted Assets".to_string(), user.clone())
        .with_current_path("/assets/deleted");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;

    let page: i32 = params
        .get("page")
        .and_then(|s| s.parse::<i32>().ok())
        .unwrap_or(1)
        .max(1);

    let total_items: i64 = schema_assets::table
        .filter(schema_assets::is_deleted.eq(true))
        .count()
        .get_result(&mut conn)
        .await
        .unwrap_or(0);
    let total_pages = ((total_items as f64) / (ASSETS_PER_PAGE as f64))
        .ceil()
        .max(1.0) as i32;
    let page = page.min(total_pages);
    let offset = ((page - 1) as i64) * ASSETS_PER_PAGE;

    #[allow(clippy::type_complexity)]
    let rows: Vec<(
        ::uuid::Uuid,
        String,
        String,
        i32,
        String,
        AssetType,
        Option<chrono::DateTime<chrono::Utc>>,
        chrono::DateTime<chrono::Utc>,
    )> = schema_assets::table
        .filter(schema_assets::is_deleted.eq(true))
        .select((
            schema_assets::uuid,
            schema_assets::name,
            schema_assets::hostname,
            schema_assets::port,
            schema_assets::connection_username,
            schema_assets::asset_type,
            schema_assets::deleted_at,
            schema_assets::created_at,
        ))
        // Most recent deletion first -- the audit reader almost
        // always wants "what just disappeared".
        .order(schema_assets::deleted_at.desc().nulls_last())
        .then_order_by(schema_assets::name.asc())
        .limit(ASSETS_PER_PAGE)
        .offset(offset)
        .load(&mut conn)
        .await?;

    let assets: Vec<DeletedAssetItem> = rows
        .into_iter()
        .map(
            |(
                uuid,
                name,
                hostname,
                port,
                connection_username,
                asset_type,
                deleted_at,
                created_at,
            )| {
                DeletedAssetItem {
                    uuid,
                    name,
                    hostname,
                    port,
                    connection_username,
                    asset_type: asset_type.to_string(),
                    deleted_at,
                    created_at,
                }
            },
        )
        .collect();

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

    let template = AssetDeletedListTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        assets,
        pagination,
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

    // Instance-level access control: EVERY user must have a matching access
    // rule, including superusers and staff. Removing the historical
    // privileged-user bypass aligns this view with the policy that
    // `connect_ssh`/`connect_rdp` actually enforce (commit febd388):
    // otherwise the UI would dangle a "Connect" button at admins for an
    // asset that the proxy will refuse on the same access-rule check,
    // surfacing as the inconsistent flow that produced the spurious
    // "MFA code is required" prompt for superusers. The bootstrap
    // superuser MUST own at least one access_rule for itself.
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

    {
        let accessible_ids = crate::services::access::list_accessible_asset_ids(
            &state.access_client,
            &mut conn,
            user_internal_id,
        )
        .await
        .unwrap_or_default();

        if !accessible_ids.contains(&asset_model.id) {
            return flash_redirect(flash.error("Access denied"), "/assets");
        }
    }

    // Determine JIT flags from access rules using the SAME policy the
    // connect handler will re-apply. No superuser bypass: see the
    // comment above for the rationale.
    let (require_approval, require_mfa_from_rule, has_approved_session) = {
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

    // Forward incoming flash messages so post-redirect-get flows
    // (notably the SEC-11 reactivation success warning produced by
    // `create_asset_web`) actually reach the operator on the detail
    // page they land on.
    let flash_messages: Vec<crate::templates::base::FlashMessage> = incoming_flash
        .messages()
        .iter()
        .map(|m| crate::templates::base::FlashMessage {
            level: m.level.clone(),
            message: m.message.clone(),
        })
        .collect();

    let base = BaseTemplate::new(format!("{} - Asset", asset_name), user.clone())
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
    // Only expose the *presence* of each secret to the template, never
    // the value itself (encrypted or plaintext). The edit form renders
    // empty inputs with "Leave blank to keep current" hints; the
    // handler then preserves the stored value when the operator
    // submits a blank field (option A, see `compute_updated_connection_config`).
    let has_secret = |key: &str| {
        asset_connection_config
            .get(key)
            .and_then(|v| v.as_str())
            .is_some_and(|s| !s.is_empty())
    };
    let has_password = has_secret("password");
    let has_private_key = has_secret("private_key");
    let has_passphrase = has_secret("passphrase");
    let ssh_host_key_fingerprint = asset_connection_config
        .get("ssh_host_key_fingerprint")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let rdp_domain = asset_connection_config
        .get("domain")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

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
        has_password,
        has_private_key,
        has_passphrase,
        ssh_host_key_fingerprint,
        rdp_domain,
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
//
// Axum extractors are positional and we just added `headers` to gate the
// HX-Redirect dialect (BUG-12 / issue #19). Splitting the handler purely
// for the arg count would obscure the linear delete flow; `allow` is the
// right trade-off here.
#[allow(clippy::too_many_arguments)]
pub async fn delete_asset_web(
    State(state): State<AppState>,
    _auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    headers: axum::http::HeaderMap,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
    Form(form): Form<DeleteAssetForm>,
) -> Response {
    let flash = incoming_flash.flash();

    // BUG-12 / issue #19: HTMX-driven delete flows need `HX-Redirect` rather than
    // the native 303 — see `htmx_or_flash_redirect` for the why. Both code paths
    // still set the same flash cookie so the destination page surfaces the message.

    let csrf_cookie = jar.get(crate::middleware::csrf::CSRF_COOKIE_NAME);
    let secret = state.config.secret_key.expose_secret().as_bytes();
    if !crate::middleware::csrf::validate_double_submit(
        secret,
        csrf_cookie.map(|c| c.value()),
        &form.csrf_token,
    ) {
        return htmx_or_flash_redirect(
            &headers,
            flash.error("Invalid CSRF token. Please refresh the page and try again."),
            &format!("/assets/{}", uuid_str),
        );
    }

    if !perms.assets_write {
        return htmx_or_flash_redirect(
            &headers,
            flash.error("You do not have permission to delete assets"),
            &format!("/assets/{}", uuid_str),
        );
    }

    let asset_uuid = match ::uuid::Uuid::parse_str(&uuid_str) {
        Ok(uuid) => uuid,
        Err(_) => {
            return htmx_or_flash_redirect(
                &headers,
                flash.error("Invalid asset identifier"),
                "/assets",
            );
        }
    };

    let mut conn = match state.db_pool.get().await {
        Ok(conn) => conn,
        Err(_) => {
            return htmx_or_flash_redirect(
                &headers,
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
            return htmx_or_flash_redirect(
                &headers,
                flash.error("Asset not found or already deleted"),
                "/assets",
            );
        }
        Err(_) => {
            return htmx_or_flash_redirect(
                &headers,
                flash.error("Failed to delete asset. Please try again."),
                &format!("/assets/{}", asset_uuid),
            );
        }
    };

    let now = Utc::now();
    let result = conn
        .transaction::<_, diesel::result::Error, _>(|conn| {
            Box::pin(async move {
                // Issue #17: scrub `connection_config` on soft-delete so
                // a tombstone never carries credentials, even briefly.
                // The DB enforces the same invariant via the
                // `assets_tombstone_no_secrets` CHECK constraint -- this
                // explicit write is now defence-in-depth, kept so the
                // intent is local-readable and so any future code path
                // that bypasses this handler is still rejected at COMMIT
                // time. Resurrection of the tombstone is separately
                // blocked by the `assets_no_resurrection_trg` trigger
                // (RG-ASS-04: delete is irreversible).
                diesel::update(a::assets.filter(a::id.eq(asset_id)))
                    .set((
                        a::is_deleted.eq(true),
                        a::deleted_at.eq(now),
                        a::updated_at.eq(now),
                        a::connection_config.eq(serde_json::json!({})),
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

            htmx_or_flash_redirect(
                &headers,
                flash.success("Asset deleted successfully"),
                "/assets",
            )
        }
        Err(_) => htmx_or_flash_redirect(
            &headers,
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
    /// Optional Windows AD domain for RDP authentication.
    pub rdp_domain: Option<String>,
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

    // First, get the existing asset to preserve unchanged values.
    //
    // Issue #17: filtering on `is_deleted = false` here makes the
    // edit page report 404 on a tombstone, which is the correct UX
    // signal (the asset is gone, RG-ASS-04 says delete is
    // irreversible). The DB-level `assets_no_resurrection_trg`
    // trigger is the actual security guarantee -- this filter is the
    // friendly UX closing the door earlier.
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

    // Reject illegal protocol+auth combinations using the asset's
    // immutable type. We deliberately read `existing.asset_type`
    // (rather than a form field) because the edit form does NOT expose
    // an `asset_type` selector -- a tampered request that smuggled one
    // in must not flip the protocol to bypass validation.
    if let Err(msg) = validate_auth_inputs(
        existing.asset_type,
        form.ssh_auth_type.as_deref(),
        form.ssh_private_key.as_deref(),
        form.ssh_passphrase.as_deref(),
    ) {
        return flash_redirect(flash.error(msg), &format!("/assets/{}/edit", asset_uuid));
    }

    // Enforce ASS-02 / ASS-03 required credentials, taking into
    // account the option-A "blank field means keep existing" semantic:
    // we accept a blank submit ONLY when the existing connection_config
    // already carries the field. If neither side has it, we reject.
    let blank = |o: Option<&str>| o.map(str::trim).is_none_or(str::is_empty);
    let existing_field = |k: &str| {
        existing
            .connection_config
            .get(k)
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
    };
    let effective_password = if blank(form.ssh_password.as_deref()) {
        existing_field("password")
    } else {
        form.ssh_password.as_deref()
    };
    let effective_private_key = if blank(form.ssh_private_key.as_deref()) {
        existing_field("private_key")
    } else {
        form.ssh_private_key.as_deref()
    };
    // Likewise for auth_type: the form may omit it (e.g. RDP) or send
    // an empty string; fall back to whatever the row already records.
    let effective_auth_type = form
        .ssh_auth_type
        .as_deref()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            existing
                .connection_config
                .get("auth_type")
                .and_then(|v| v.as_str())
        });
    if let Err(msg) = validate_required_credentials(
        existing.asset_type,
        effective_auth_type,
        effective_password,
        effective_private_key,
    ) {
        return flash_redirect(flash.error(msg), &format!("/assets/{}/edit", asset_uuid));
    }

    // Compute the new connection_config by overlaying the form fields
    // on the existing row. This preserves by construction every field
    // the edit form does NOT expose — most importantly the SSH
    // host-key state (`ssh_host_key`, `ssh_host_key_fingerprint`,
    // `ssh_host_key_mismatch`), whose silent erasure on every edit
    // was the root cause of GitHub issue #20.
    //
    // The function also implements the "blank input ⇒ keep existing"
    // semantic for credentials (option A), so a description-only
    // edit does not wipe the stored password / private key / passphrase.
    let mut connection_config = compute_updated_connection_config(
        &existing.connection_config,
        existing.asset_type,
        form.ssh_username.as_deref(),
        form.ssh_auth_type.as_deref(),
        form.ssh_password.as_deref(),
        form.ssh_private_key.as_deref(),
        form.ssh_passphrase.as_deref(),
        form.rdp_domain.as_deref(),
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
