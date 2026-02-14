/// Asset management page handlers.
use super::*;

/// Asset create form page.
pub async fn asset_create_form(
    State(_state): State<AppState>,
    auth_user: WebAuthUser,
    jar: CookieJar,
) -> Result<impl IntoResponse, AppError> {
    use crate::templates::assets::asset_create::{AssetCreateForm, AssetCreateTemplate};

    // Only admin users can create assets
    if !is_admin(&auth_user) {
        return Err(AppError::Authorization(
            "Only administrators can create assets".to_string(),
        ));
    }

    let user = Some(user_context_from_auth(&auth_user));
    let base =
        BaseTemplate::new("New Asset".to_string(), user.clone()).with_current_path("/assets");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        base.into_fields();

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
            ("vnc".to_string(), "VNC".to_string()),
        ],
    };

    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;
    Ok(Html(html))
}

/// Deserialize HTML checkbox value ("on" or absent) to bool.
fn deserialize_checkbox<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;
    let opt: Option<String> = Option::deserialize(deserializer)?;
    match opt.as_deref() {
        Some("on") | Some("true") | Some("1") => Ok(true),
        _ => Ok(false),
    }
}

/// Form data for creating an asset via web form.
#[derive(Debug, serde::Deserialize)]
pub struct CreateAssetWebForm {
    pub name: String,
    pub hostname: String,
    pub ip_address: Option<String>,
    pub port: i32,
    pub asset_type: String,
    pub status: String,
    pub description: Option<String>,
    #[serde(default, deserialize_with = "deserialize_checkbox")]
    pub require_mfa: bool,
    #[serde(default, deserialize_with = "deserialize_checkbox")]
    pub require_justification: bool,
    pub csrf_token: String,
    // SSH credentials (stored in connection_config)
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
    auth_user: WebAuthUser,
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

    // Permission check - only admin can create assets
    if !is_admin(&auth_user) {
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

    // Check if asset with same hostname+port already exists (active)
    use crate::schema::assets::dsl as a;
    let existing_active: Option<i32> = a::assets
        .filter(a::hostname.eq(form.hostname.trim()))
        .filter(a::port.eq(form.port))
        .filter(a::is_deleted.eq(false))
        .select(a::id)
        .first(&mut conn)
        .await
        .optional()
        .unwrap_or(None);

    if existing_active.is_some() {
        return flash_redirect(
            flash.error("An asset with this hostname and port already exists"),
            "/assets/new",
        );
    }

    // Check if a soft-deleted asset with same hostname+port exists - reactivate it
    let existing_deleted: Option<(i32, ::uuid::Uuid)> = a::assets
        .filter(a::hostname.eq(form.hostname.trim()))
        .filter(a::port.eq(form.port))
        .filter(a::is_deleted.eq(true))
        .select((a::id, a::uuid))
        .first(&mut conn)
        .await
        .optional()
        .unwrap_or(None);

    let now = chrono::Utc::now();

    // Sanitize text fields to prevent stored XSS
    let sanitized_name = sanitize(form.name.trim());
    let sanitized_description = sanitize_opt(
        form.description.as_ref().filter(|s| !s.is_empty()).cloned(),
    );

    if let Some((deleted_id, deleted_uuid)) = existing_deleted {
        // Reactivate the soft-deleted asset with new data
        let result = diesel::update(a::assets.filter(a::id.eq(deleted_id)))
            .set((
                a::name.eq(&sanitized_name),
                a::asset_type.eq(&form.asset_type),
                a::status.eq(&form.status),
                a::description.eq(&sanitized_description),
                a::require_mfa.eq(form.require_mfa),
                a::require_justification.eq(form.require_justification),
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

    // C-2: Encrypt credential fields via vault when available
    if let Some(ref vault) = state.vault_client
        && let Err(e) = encrypt_connection_config(vault, &mut connection_config).await
    {
        tracing::error!("Failed to encrypt connection config: {}", e);
        return flash_redirect(flash.error("Failed to encrypt credentials"), "/assets/create");
    }

    // Parse IP address if provided
    let ip_address: Option<ipnetwork::IpNetwork> = form
        .ip_address
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .and_then(|s| s.trim().parse().ok());

    let result = diesel::insert_into(a::assets)
        .values((
            a::uuid.eq(new_uuid),
            a::name.eq(&sanitized_name),
            a::hostname.eq(form.hostname.trim()),
            a::ip_address.eq(ip_address),
            a::port.eq(form.port),
            a::asset_type.eq(&form.asset_type),
            a::status.eq(&form.status),
            a::description.eq(&sanitized_description),
            a::connection_config.eq(connection_config),
            a::require_mfa.eq(form.require_mfa),
            a::require_justification.eq(form.require_justification),
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
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse, AppError> {
    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new("Assets".to_string(), user.clone()).with_current_path("/assets");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        base.into_fields();

    // Determine if user is admin (can view asset details)
    let user_is_admin = is_admin(&auth_user);

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

    let mut query = schema_assets::table
        .filter(schema_assets::is_deleted.eq(false))
        .into_boxed();

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
        query = query.filter(schema_assets::asset_type.eq(asset_type));
    }

    if let Some(ref status) = status_filter
        && !status.is_empty()
    {
        query = query.filter(schema_assets::status.eq(status));
    }

    let db_assets: Vec<(i32, ::uuid::Uuid, String, String, i32, String, String)> = query
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
        .limit(50)
        .load(&mut conn)
        .await?;

    let asset_items: Vec<AssetListItem> = db_assets
        .into_iter()
        .map(
            |(id, uuid, name, hostname, port, asset_type, status)| AssetListItem {
                id,
                uuid,
                name,
                hostname,
                port,
                asset_type,
                status,
                group_name: None,
            },
        )
        .collect();

    let template = AssetListTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        assets: asset_items,
        pagination: None,
        search: search_filter,
        type_filter,
        status_filter,
        asset_types: vec![
            ("ssh".to_string(), "SSH".to_string()),
            ("rdp".to_string(), "RDP".to_string()),
            ("vnc".to_string(), "VNC".to_string()),
        ],
        statuses: vec![
            ("online".to_string(), "Online".to_string()),
            ("offline".to_string(), "Offline".to_string()),
            ("maintenance".to_string(), "Maintenance".to_string()),
        ],
        show_view_link: user_is_admin,
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

    let rows: Vec<(uuid::Uuid, String, String, String, String)> = a::assets
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
        #[allow(clippy::unwrap_used)]
        let asset_type = askama::filters::escape(&asset_type, askama::filters::Html)
            .unwrap()
            .to_string();
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

    // Only admin users (superuser or staff) can view asset details
    if !is_admin(&auth_user) {
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

    // Query asset details with optional group info - migrated to Diesel DSL
    use crate::schema::asset_groups::dsl as ag;
    use crate::schema::assets::dsl as a;

    // First get the asset
    #[allow(clippy::type_complexity)]
    let asset_row: (
        ::uuid::Uuid,
        String,
        String,
        Option<ipnetwork::IpNetwork>,
        i32,
        String,
        String,
        Option<i32>,
        Option<String>,
        Option<String>,
        Option<String>,
        bool,
        bool,
        i32,
        Option<chrono::DateTime<chrono::Utc>>,
        chrono::DateTime<chrono::Utc>,
        chrono::DateTime<chrono::Utc>,
        serde_json::Value,
    ) = match a::assets
        .filter(a::uuid.eq(asset_uuid))
        .filter(a::is_deleted.eq(false))
        .select((
            a::uuid,
            a::name,
            a::hostname,
            a::ip_address,
            a::port,
            a::asset_type,
            a::status,
            a::group_id,
            a::description,
            a::os_type,
            a::os_version,
            a::require_mfa,
            a::require_justification,
            a::max_session_duration,
            a::last_seen,
            a::created_at,
            a::updated_at,
            a::connection_config,
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
        asset_uuid,
        asset_name,
        asset_hostname,
        asset_ip,
        asset_port,
        asset_type_val,
        asset_status,
        asset_group_id,
        asset_description,
        asset_os_type,
        asset_os_version,
        asset_require_mfa,
        asset_require_justification,
        asset_max_session_duration,
        asset_last_seen,
        asset_created_at,
        asset_updated_at,
        asset_connection_config,
    ) = asset_row;

    // Extract SSH host key fingerprint and mismatch status from connection_config (H-9)
    let ssh_host_key_fingerprint = asset_connection_config
        .get("ssh_host_key_fingerprint")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let ssh_host_key_mismatch = asset_connection_config
        .get("ssh_host_key_mismatch")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // Get group info if group_id is set
    let (group_name, group_uuid): (Option<String>, Option<String>) =
        if let Some(gid) = asset_group_id {
            match ag::asset_groups
                .filter(ag::id.eq(gid))
                .select((ag::name, ag::uuid))
                .first::<(String, ::uuid::Uuid)>(&mut conn)
                .await
                .optional()
            {
                Ok(Some((n, u))) => (Some(n), Some(u.to_string())),
                _ => (None, None),
            }
        } else {
            (None, None)
        };

    let asset = crate::templates::assets::asset_detail::AssetDetail {
        uuid: asset_uuid.to_string(),
        name: asset_name.clone(),
        hostname: asset_hostname,
        ip_address: asset_ip.map(|ip| ip.to_string()),
        port: asset_port,
        asset_type: asset_type_val,
        status: asset_status,
        group_name,
        group_uuid,
        description: asset_description,
        os_type: asset_os_type,
        os_version: asset_os_version,
        require_mfa: asset_require_mfa,
        require_justification: asset_require_justification,
        max_session_duration: asset_max_session_duration,
        last_seen: asset_last_seen.map(|dt| dt.format("%b %d, %Y %H:%M").to_string()),
        created_at: asset_created_at.format("%b %d, %Y %H:%M").to_string(),
        updated_at: asset_updated_at.format("%b %d, %Y %H:%M").to_string(),
        ssh_host_key_fingerprint,
        ssh_host_key_mismatch,
    };

    let base = BaseTemplate::new(format!("{} - Asset", asset_name), user.clone())
        .with_current_path("/assets");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        base.into_fields();

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
    incoming_flash: IncomingFlash,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
) -> Response {
    let flash = incoming_flash.flash();

    // Only admin users can edit assets
    if !is_admin(&auth_user) {
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
        Option<ipnetwork::IpNetwork>,
        i32,
        String,
        String,
        Option<String>,
        serde_json::Value,
        bool,
        bool,
    ) = match a::assets
        .filter(a::uuid.eq(asset_uuid))
        .filter(a::is_deleted.eq(false))
        .select((
            a::uuid,
            a::name,
            a::hostname,
            a::ip_address,
            a::port,
            a::asset_type,
            a::status,
            a::description,
            a::connection_config,
            a::require_mfa,
            a::require_justification,
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
        asset_ip,
        asset_port,
        asset_type_val,
        asset_status,
        asset_description,
        asset_connection_config,
        asset_require_mfa,
        asset_require_justification,
    ) = asset_row;

    // Extract SSH credentials from connection_config
    let ssh_username = asset_connection_config
        .get("username")
        .and_then(|v| v.as_str())
        .unwrap_or("root")
        .to_string();
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
        ip_address: asset_ip.map(|ip| ip.ip().to_string()),
        port: asset_port,
        asset_type: asset_type_val,
        status: asset_status,
        description: asset_description,
        require_mfa: asset_require_mfa,
        require_justification: asset_require_justification,
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
        base.into_fields();

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

    // Clear flash cookie after reading and return HTML
    use crate::middleware::flash::ClearFlashCookie;
    match template.render() {
        Ok(html) => (ClearFlashCookie, Html(html)).into_response(),
        Err(_) => flash_redirect(flash.error("Failed to render page"), "/assets"),
    }
}

/// Delete asset handler (Web form with PRG pattern).
///
/// Soft-deletes the asset and updates related approvals/sessions.
pub async fn delete_asset_web(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
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

    if !auth_user.is_superuser && !auth_user.is_staff {
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
    pub ip_address: Option<String>,
    pub port: i32,
    pub status: String,
    pub description: Option<String>,
    #[serde(default)]
    pub require_mfa: Option<String>,
    #[serde(default)]
    pub require_justification: Option<String>,
    pub csrf_token: String,
    // SSH credentials (stored in connection_config)
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
    auth_user: WebAuthUser,
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

    // Permission check - only admin can update assets
    if !is_admin(&auth_user) {
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

    // Parse and validate IP address if provided
    let new_ip_address: Option<ipnetwork::IpNetwork> = if let Some(ref ip_str) = form.ip_address {
        if ip_str.trim().is_empty() {
            None
        } else {
            match ip_str.parse::<std::net::IpAddr>() {
                Ok(ip) => Some(ipnetwork::IpNetwork::from(ip)),
                Err(_) => {
                    return flash_redirect(
                        flash.error(
                            "Invalid IP address format. Use format like 192.168.1.1 or 2001:db8::1",
                        ),
                        &format!("/assets/{}/edit", asset_uuid),
                    );
                }
            }
        }
    } else {
        None
    };

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

    // Parse boolean fields from checkbox values
    let require_mfa = form
        .require_mfa
        .as_ref()
        .map(|v| v == "on" || v == "true")
        .unwrap_or(false);
    let require_justification = form
        .require_justification
        .as_ref()
        .map(|v| v == "on" || v == "true")
        .unwrap_or(false);

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

    // C-2: Encrypt credential fields via vault when available
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

    // Update the asset
    let result = diesel::update(a::assets.filter(a::uuid.eq(asset_uuid)))
        .set((
            a::name.eq(&sanitized_name),
            a::hostname.eq(&form.hostname),
            a::ip_address.eq(new_ip_address.or(existing.ip_address)),
            a::port.eq(form.port),
            a::status.eq(&form.status),
            a::description.eq(sanitized_description.as_deref()),
            a::connection_config.eq(connection_config),
            a::require_mfa.eq(require_mfa),
            a::require_justification.eq(require_justification),
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
