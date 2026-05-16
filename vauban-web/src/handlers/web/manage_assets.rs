//! Admin-only "Manage Assets" handlers — issue #27 asset zone split.
//!
//! These handlers serve the `/assets/manage/*` admin sub-tree and are
//! gated by [`crate::auth::PermissionContext::assets_manage`]. The user
//! zone (connect, request access) lives in
//! [`crate::handlers::web::assets`] and never invokes any code path
//! defined here.
//!
//! # Defence-in-depth
//!
//! Every public handler in this module asserts `perms.assets_manage` at
//! the top of its body, BEFORE any DB lookup, regardless of the routing
//! middleware that already gates the entire `/assets/manage` nest. This
//! double-check guarantees that:
//!
//! - if a future route registration leaks one of these handlers outside
//!   the nest, the gate still holds;
//! - the per-route 403 happens **before** any oracle (the asset
//!   existence check, the connection_config decryption) — anti-
//!   enumeration by construction.
//!
//! # No session can ever be opened from this module
//!
//! Source-level CI tests in `tests/web/manage_assets_no_session_test.rs`
//! enforce that this file (and every `templates/assets/manage/*.html`
//! template) never references `connect-rdp`, `connect_ssh`, `/connect"`,
//! `submit_access_request`, `request-access`, `/sessions/request`,
//! `wss://` or `WebSocket`. The admin zone is structurally session-free.
use super::*;
use crate::models::asset::{Asset, AssetType};

const ASSETS_PER_PAGE: i64 = 30;

/// Asset create form page (admin zone).
pub async fn asset_create_form(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    jar: CookieJar,
    browser_tz: BrowserTz,
) -> Result<impl IntoResponse, AppError> {
    use crate::templates::assets::asset_create::{AssetCreateForm, AssetCreateTemplate};

    if !perms.assets_manage {
        return Err(AppError::Authorization(
            "Only administrators can create assets".to_string(),
        ));
    }

    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new("New Asset".to_string(), user.clone(), browser_tz.0)
        .with_current_path("/assets/manage");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

    let csrf_token = jar
        .get(crate::middleware::csrf::CSRF_COOKIE_NAME)
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    let form = AssetCreateForm {
        port: 22,
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
        asset_types: AssetType::select_options(),
    };

    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;
    Ok(Html(html))
}

/// Form data for creating an asset via web form (admin zone).
#[derive(Debug, serde::Deserialize)]
pub struct CreateAssetWebForm {
    pub name: String,
    pub hostname: String,
    pub port: i32,
    pub asset_type: String,
    pub status: String,
    pub description: Option<String>,
    pub csrf_token: String,
    pub ssh_username: Option<String>,
    pub ssh_auth_type: Option<String>,
    pub ssh_password: Option<String>,
    pub ssh_private_key: Option<String>,
    pub ssh_passphrase: Option<String>,
    /// Optional Windows AD domain for RDP authentication.
    ///
    /// Stored as `connection_config.domain` and consumed by
    /// `vauban-proxy-rdp` (see `SessionConfig.domain`). Ignored for
    /// non-RDP `asset_type` values to keep the JSONB blob protocol-clean.
    pub rdp_domain: Option<String>,
}

/// Handle asset creation form submission (admin zone).
pub async fn create_asset_web(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    Form(form): Form<CreateAssetWebForm>,
) -> Response {
    let flash = incoming_flash.flash();

    let csrf_cookie = jar.get(crate::middleware::csrf::CSRF_COOKIE_NAME);
    if !crate::middleware::csrf::validate_double_submit(
        state.config.secret_key.expose_secret().as_bytes(),
        csrf_cookie.map(|c| c.value()),
        &form.csrf_token,
    ) {
        return flash_redirect(flash.error("Invalid CSRF token"), "/assets/manage/new");
    }

    if !perms.assets_manage {
        return flash_redirect(
            flash.error("Only administrators can create assets"),
            "/assets/manage",
        );
    }

    if form.name.trim().is_empty() {
        return flash_redirect(flash.error("Asset name is required"), "/assets/manage/new");
    }
    if form.hostname.trim().is_empty() {
        return flash_redirect(flash.error("Hostname is required"), "/assets/manage/new");
    }
    if form.port < 1 || form.port > 65535 {
        return flash_redirect(
            flash.error("Port must be between 1 and 65535"),
            "/assets/manage/new",
        );
    }

    let parsed_asset_type = match AssetType::parse(&form.asset_type) {
        Ok(t) => t,
        Err(_) => {
            return flash_redirect(
                flash.error(format!(
                    "Unknown asset type: {:?}. Must be one of {:?}",
                    form.asset_type,
                    AssetType::ALL
                        .iter()
                        .map(|a| a.as_str())
                        .collect::<Vec<_>>()
                )),
                "/assets/manage/new",
            );
        }
    };
    if let Err(msg) = validate_auth_inputs(
        parsed_asset_type,
        form.ssh_auth_type.as_deref(),
        form.ssh_private_key.as_deref(),
        form.ssh_passphrase.as_deref(),
    ) {
        return flash_redirect(flash.error(msg), "/assets/manage/new");
    }

    if let Err(msg) = validate_required_credentials(
        parsed_asset_type,
        form.ssh_auth_type.as_deref(),
        form.ssh_password.as_deref(),
        form.ssh_private_key.as_deref(),
    ) {
        return flash_redirect(flash.error(msg), "/assets/manage/new");
    }

    let mut conn = match state.db_pool.get().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Database connection error: {}", e);
            return flash_redirect(
                flash.error("Database connection error"),
                "/assets/manage/new",
            );
        }
    };

    let connection_username = form
        .ssh_username
        .as_deref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or("root");

    use crate::schema::assets::dsl as a;

    let now = chrono::Utc::now();

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
        return flash_redirect(
            flash.error("Failed to encrypt credentials"),
            "/assets/manage/new",
        );
    }

    // Issue #17: every create produces a fresh UUID. Soft-deleted rows
    // sharing the same (hostname, port, username) triplet are tombstones
    // (audit-only) and must NEVER be reactivated -- the
    // `assets_no_resurrection_trg` trigger and the irreversible-delete
    // policy (RG-ASS-04) make any other path a security regression.
    let new_uuid = ::uuid::Uuid::new_v4();

    // Issue #22 — stamp the audit pair on creation so the
    // Metadata UI surfaces "Created by" / "Updated by" without
    // ever needing to fall back to the muted em-dash for assets
    // born after this change. A `None` here only happens if the
    // session JWT no longer maps to a live user row; we let the
    // INSERT proceed (audit columns are `Nullable<Int4>`) so a
    // transient lookup miss never blocks a legitimate create.
    let actor_id =
        crate::services::audit_authors::resolve_actor_id(&mut conn, &auth_user.uuid).await;

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
            a::created_by_id.eq(actor_id),
            a::updated_by_id.eq(actor_id),
            a::created_at.eq(now),
            a::updated_at.eq(now),
        ))
        .execute(&mut conn)
        .await;

    match result {
        Ok(_) => flash_redirect(
            flash.success(format!("Asset '{}' created successfully", sanitized_name)),
            &format!("/assets/manage/{}", new_uuid),
        ),
        Err(diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::UniqueViolation,
            _,
        )) => flash_redirect(
            flash.error("An asset with this hostname, port and username already exists"),
            "/assets/manage/new",
        ),
        Err(e) => {
            tracing::error!("Failed to create asset: {}", e);
            flash_redirect(flash.error("Failed to create asset"), "/assets/manage/new")
        }
    }
}

/// Manage Assets list page (admin zone).
///
/// Shows every asset (including those the caller has no access rule for)
/// with full CRUD action affordances per row. The user-facing list at
/// `/assets` is at [`crate::handlers::web::assets::asset_list`] and is
/// filtered by access rules and shows Connect/Request — NOT
/// View/Edit/Delete.
pub async fn manage_asset_list(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    browser_tz: BrowserTz,
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse, AppError> {
    use crate::templates::accounts::user_list::Pagination;
    use crate::templates::assets::manage::{ManageAssetItem, ManageAssetListTemplate};

    if !perms.assets_manage {
        return Err(AppError::Authorization(
            "Only administrators can manage assets".to_string(),
        ));
    }

    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new("Manage Assets".to_string(), user.clone(), browser_tz.0)
        .with_current_path("/assets/manage");
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

    let mut count_query = schema_assets::table
        .filter(schema_assets::is_deleted.eq(false))
        .into_boxed();

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
        match AssetType::parse_filter(asset_type) {
            crate::models::asset::AssetTypeFilter::One(parsed) => {
                count_query = count_query.filter(schema_assets::asset_type.eq(parsed));
            }
            crate::models::asset::AssetTypeFilter::IacsAll => {
                count_query = count_query
                    .filter(schema_assets::asset_type.eq_any(AssetType::iacs_variants()));
            }
            crate::models::asset::AssetTypeFilter::Unknown => {
                count_query = count_query.filter(schema_assets::id.eq(-1));
            }
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
        match AssetType::parse_filter(asset_type) {
            crate::models::asset::AssetTypeFilter::One(parsed) => {
                query = query.filter(schema_assets::asset_type.eq(parsed));
            }
            crate::models::asset::AssetTypeFilter::IacsAll => {
                query = query.filter(schema_assets::asset_type.eq_any(AssetType::iacs_variants()));
            }
            crate::models::asset::AssetTypeFilter::Unknown => {
                query = query.filter(schema_assets::id.eq(-1));
            }
        }
    }
    if let Some(ref status_val) = status_filter
        && !status_val.is_empty()
    {
        query = query.filter(schema_assets::status.eq(status_val));
    }

    #[allow(clippy::type_complexity)]
    let db_assets: Vec<(::uuid::Uuid, String, String, i32, AssetType, String)> = query
        .select((
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

    let assets: Vec<ManageAssetItem> = db_assets
        .into_iter()
        .map(|(uuid, name, hostname, port, asset_type, status)| {
            let iacs_protocol_label = asset_type
                .iacs_protocol()
                .map(|p| p.as_str().to_string())
                .unwrap_or_default();
            ManageAssetItem {
                uuid,
                name,
                hostname,
                port,
                is_iacs: asset_type.is_iacs(),
                iacs_protocol_label,
                asset_type: asset_type.to_string(),
                status,
                group_name: None,
            }
        })
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

    let template = ManageAssetListTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        assets,
        pagination,
        search: search_filter,
        type_filter,
        status_filter,
        asset_types: AssetType::filter_options(),
        statuses: vec![
            ("online".to_string(), "Online".to_string()),
            ("offline".to_string(), "Offline".to_string()),
            ("maintenance".to_string(), "Maintenance".to_string()),
        ],
    };

    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;
    Ok(Html(html))
}

/// Issue #17 — read-only audit page listing soft-deleted assets.
///
/// Now lives under `/assets/manage/deleted` and is gated by the
/// `assets_manage` permission (was `assets_read` pre-issue #27).
/// Tightening the gate is intentional: the deleted-assets page reveals
/// historical hostnames, which a read-only catalogue user has no
/// legitimate need to see.
pub async fn asset_deleted_list(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    browser_tz: BrowserTz,
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse, AppError> {
    use crate::templates::accounts::user_list::Pagination;
    use crate::templates::assets::{AssetDeletedListTemplate, DeletedAssetItem};

    if !perms.assets_manage {
        return Err(AppError::Authorization(
            "Only administrators can view the deleted assets audit page".to_string(),
        ));
    }

    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new("Deleted Assets".to_string(), user.clone(), browser_tz.0)
        .with_current_path("/assets/manage/deleted");
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
        Option<i32>,
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
            schema_assets::updated_by_id,
        ))
        .order(schema_assets::deleted_at.desc().nulls_last())
        .then_order_by(schema_assets::name.asc())
        .limit(ASSETS_PER_PAGE)
        .offset(offset)
        .load(&mut conn)
        .await?;

    // Issue #22 — bulk-resolve the operator that soft-deleted each
    // tombstone. We reuse `updated_by_id` (re-stamped by
    // `delete_asset_web`) instead of introducing a dedicated
    // `deleted_by_id` column: by contract a tombstone's last write
    // IS the deletion. One round-trip for the whole page, even
    // when many rows share the same admin.
    let actor_ids: Vec<Option<i32>> = rows.iter().map(|r| r.8).collect();
    let authors = crate::services::audit_authors::resolve_authors(&mut conn, &actor_ids).await;

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
                updated_by_id,
            )| {
                let deleted_by = updated_by_id.and_then(|id| authors.get(&id).cloned());
                DeletedAssetItem {
                    uuid,
                    name,
                    hostname,
                    port,
                    connection_username,
                    is_iacs: asset_type.is_iacs(),
                    type_label: asset_type.label().to_string(),
                    asset_type: asset_type.to_string(),
                    deleted_at,
                    created_at,
                    deleted_by,
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

/// Admin asset search (HTMX) — gated by `assets_manage`.
///
/// Returns search-suggestion HTML linking to `/assets/manage/{uuid}`.
/// The user-zone catalogue does not expose a search-suggestion endpoint
/// because its only meaningful action ("Connect") is already on every
/// row of the user list itself.
pub async fn asset_search(
    State(state): State<AppState>,
    _auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse, AppError> {
    use crate::schema::assets::dsl as a;

    if !perms.assets_manage {
        return Err(AppError::Authorization(
            "Only administrators can search the asset catalogue".to_string(),
        ));
    }

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
<a class="block text-sm" href="/assets/manage/{asset_uuid}">
<div class="font-medium text-gray-900 dark:text-white">{name}</div>
<div class="text-xs text-gray-500 dark:text-gray-400">{hostname} . {asset_type} . {status}</div>
</a>
</li>"#
        ));
    }

    html.push_str("</ul></div>");
    Ok(Html(html))
}

/// Asset detail page (admin zone).
///
/// Renders the full administrative detail of an asset. Replaces the
/// pre-issue-#27 `/assets/{uuid}` page that used to show Connect /
/// Request affordances. Connect / Request live exclusively on the user
/// zone list at `/assets`; this page is read-and-CRUD only.
pub async fn asset_detail(
    State(state): State<AppState>,
    incoming_flash: IncomingFlash,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    browser_tz: BrowserTz,
    axum::extract::Path(asset_uuid_str): axum::extract::Path<String>,
) -> Response {
    let flash = incoming_flash.flash();

    if !perms.assets_manage {
        return flash_redirect(
            flash.error("Only administrators can view asset details"),
            "/assets",
        );
    }

    // Parse UUID after the gate so a `role:user` cannot probe the route
    // with a malformed UUID and learn the "Invalid identifier" oracle:
    // the gate already rejected them with 403.
    let asset_uuid = match ::uuid::Uuid::parse_str(&asset_uuid_str) {
        Ok(uuid) => uuid,
        Err(_) => {
            return flash_redirect(flash.error("Invalid asset identifier"), "/assets/manage");
        }
    };

    let user = Some(user_context_from_auth(&auth_user));

    let mut conn = match state.db_pool.get().await {
        Ok(conn) => conn,
        Err(_) => {
            return flash_redirect(
                flash.error("Database connection error. Please try again."),
                "/assets/manage",
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
            return flash_redirect(flash.error("Asset not found"), "/assets/manage");
        }
        Err(_) => {
            return flash_redirect(
                flash.error("Database error. Please try again."),
                "/assets/manage",
            );
        }
    };

    let asset_name = asset_model.name.clone();

    // Extract SSH host key fingerprint and mismatch status from
    // connection_config so the admin sees the current pinning state
    // and can fix a mismatch via "Fetch host key" without ever
    // reaching the Connect path (admin zone is session-free).
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

    // Resolve the audit-author pair (issue #22). One DB round-trip
    // covers both ids; on failure, render falls back to "—" so a
    // transient DB blip on the lookup never fails the detail page.
    let (created_by, updated_by) = crate::services::audit_authors::resolve_audit_pair(
        &mut conn,
        asset_model.created_by_id,
        asset_model.updated_by_id,
    )
    .await;

    let iacs_protocol_label = asset_model
        .asset_type
        .iacs_protocol()
        .map(|p| p.as_str().to_string())
        .unwrap_or_default();

    let asset = crate::templates::assets::manage::ManageAssetDetail {
        uuid: asset_model.uuid.to_string(),
        name: asset_name.clone(),
        hostname: asset_model.hostname.clone(),
        port: asset_model.port,
        asset_type: asset_model.asset_type.to_string(),
        badge_label: asset_model.asset_type.badge_label().to_string(),
        type_label: asset_model.asset_type.label().to_string(),
        is_iacs: asset_model.asset_type.is_iacs(),
        iacs_protocol_label,
        status: asset_model.status.clone(),
        group_name,
        group_uuid,
        description: asset_model.description.clone(),
        created_at: crate::utils::format_local(asset_model.created_at, browser_tz.0),
        updated_at: crate::utils::format_local(asset_model.updated_at, browser_tz.0),
        created_by,
        updated_by,
        ssh_host_key_fingerprint,
        ssh_host_key_mismatch,
    };

    let flash_messages: Vec<crate::templates::base::FlashMessage> = incoming_flash
        .messages()
        .iter()
        .map(|m| crate::templates::base::FlashMessage {
            level: m.level.clone(),
            message: m.message.clone(),
        })
        .collect();

    let base = BaseTemplate::new(
        format!("{} - Manage Asset", asset_name),
        user.clone(),
        browser_tz.0,
    )
    .with_current_path("/assets/manage")
    .with_messages(flash_messages);
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

    let template = crate::templates::assets::manage::ManageAssetDetailTemplate {
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
        Err(_) => flash_redirect(flash.error("Failed to render page"), "/assets/manage"),
    }
}

/// Asset edit page (admin zone).
pub async fn asset_edit(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    browser_tz: BrowserTz,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
) -> Response {
    let flash = incoming_flash.flash();

    if !perms.assets_manage {
        return flash_redirect(
            flash.error("Only administrators can edit assets"),
            "/assets",
        );
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

    let mut conn = match state.db_pool.get().await {
        Ok(conn) => conn,
        Err(_) => {
            return flash_redirect(
                flash.error("Database connection error. Please try again."),
                "/assets/manage",
            );
        }
    };

    let asset_uuid = match ::uuid::Uuid::parse_str(&uuid_str) {
        Ok(uuid) => uuid,
        Err(_) => {
            return flash_redirect(flash.error("Invalid asset identifier"), "/assets/manage");
        }
    };

    use crate::schema::assets::dsl as a;

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
            return flash_redirect(flash.error("Asset not found"), "/assets/manage");
        }
        Err(_) => {
            return flash_redirect(
                flash.error("Database error. Please try again."),
                "/assets/manage",
            );
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
        badge_label: asset_type_val.badge_label().to_string(),
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

    let base = BaseTemplate::new(
        format!("Edit {} - Asset", asset_name),
        user.clone(),
        browser_tz.0,
    )
    .with_current_path("/assets/manage")
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

    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(_) => flash_redirect(flash.error("Failed to render page"), "/assets/manage"),
    }
}

/// Form data for updating an asset (admin web form).
#[derive(Debug, serde::Deserialize)]
pub struct UpdateAssetForm {
    pub name: String,
    pub hostname: String,
    pub port: i32,
    pub status: String,
    pub description: Option<String>,
    pub csrf_token: String,
    pub ssh_username: Option<String>,
    pub ssh_auth_type: Option<String>,
    pub ssh_password: Option<String>,
    pub ssh_private_key: Option<String>,
    pub ssh_passphrase: Option<String>,
    pub rdp_domain: Option<String>,
}

/// Form data for deleting an asset (admin web form).
#[derive(Debug, serde::Deserialize)]
pub struct DeleteAssetForm {
    pub csrf_token: String,
}

/// CSRF-only form payload for HTMX actions (admin web).
#[derive(Debug, serde::Deserialize)]
pub struct CsrfOnlyForm {
    pub csrf_token: String,
}

/// Update asset handler (admin zone).
pub async fn update_asset_web(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
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
            &format!("/assets/manage/{}/edit", uuid_str),
        );
    }

    if !perms.assets_manage {
        return flash_redirect(
            flash.error("Only administrators can modify assets"),
            &format!("/assets/manage/{}", uuid_str),
        );
    }

    let asset_uuid = match ::uuid::Uuid::parse_str(&uuid_str) {
        Ok(uuid) => uuid,
        Err(_) => {
            return flash_redirect(
                flash.error("Invalid asset identifier"),
                &format!("/assets/manage/{}/edit", uuid_str),
            );
        }
    };

    if form.name.trim().is_empty() {
        return flash_redirect(
            flash.error("Asset name is required"),
            &format!("/assets/manage/{}/edit", asset_uuid),
        );
    }
    if form.hostname.trim().is_empty() {
        return flash_redirect(
            flash.error("Hostname is required"),
            &format!("/assets/manage/{}/edit", asset_uuid),
        );
    }
    if form.port < 1 || form.port > 65535 {
        return flash_redirect(
            flash.error("Port must be between 1 and 65535"),
            &format!("/assets/manage/{}/edit", asset_uuid),
        );
    }

    let mut conn = match state.db_pool.get().await {
        Ok(conn) => conn,
        Err(_) => {
            return flash_redirect(
                flash.error("Database connection error. Please try again."),
                &format!("/assets/manage/{}/edit", asset_uuid),
            );
        }
    };

    use crate::schema::assets::dsl as a;
    use chrono::Utc;

    let existing: Result<crate::models::asset::Asset, _> = a::assets
        .filter(a::uuid.eq(asset_uuid))
        .filter(a::is_deleted.eq(false))
        .first(&mut conn)
        .await;

    let existing = match existing {
        Ok(asset) => asset,
        Err(_) => {
            return flash_redirect(flash.error("Asset not found"), "/assets/manage");
        }
    };

    if let Err(msg) = validate_auth_inputs(
        existing.asset_type,
        form.ssh_auth_type.as_deref(),
        form.ssh_private_key.as_deref(),
        form.ssh_passphrase.as_deref(),
    ) {
        return flash_redirect(
            flash.error(msg),
            &format!("/assets/manage/{}/edit", asset_uuid),
        );
    }

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
        return flash_redirect(
            flash.error(msg),
            &format!("/assets/manage/{}/edit", asset_uuid),
        );
    }

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

    if let Some(ref vault) = state.vault_client
        && let Err(e) = encrypt_connection_config(vault, &mut connection_config).await
    {
        tracing::error!("Failed to encrypt connection config: {}", e);
        return flash_redirect(
            flash.error("Failed to encrypt credentials"),
            &format!("/assets/manage/{}/edit", asset_uuid),
        );
    }

    let sanitized_name = sanitize(&form.name);
    let sanitized_description = sanitize_opt(form.description.clone());

    let updated_username = form
        .ssh_username
        .as_deref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or(&existing.connection_username);

    // Issue #22 — re-stamp the audit actor so the "Updated by"
    // cell on `/assets/manage/{uuid}` reflects the operator that
    // performed the most recent edit, not just the original
    // creator. Best-effort: a `None` collapses to the muted
    // em-dash on render.
    let actor_id =
        crate::services::audit_authors::resolve_actor_id(&mut conn, &auth_user.uuid).await;

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
            a::updated_by_id.eq(actor_id),
        ))
        .execute(&mut conn)
        .await;

    match result {
        Ok(_) => flash_redirect(
            flash.success("Asset updated successfully"),
            &format!("/assets/manage/{}", asset_uuid),
        ),
        Err(e) => {
            tracing::error!("Failed to update asset: {}", e);
            flash_redirect(
                flash.error("Failed to update asset. Please try again."),
                &format!("/assets/manage/{}/edit", asset_uuid),
            )
        }
    }
}

/// Delete asset handler (admin zone).
///
/// Soft-deletes the asset and updates related approvals/sessions.
/// Returns to `/assets/manage` after a successful deletion.
//
// Axum extractors are positional and we have many of them (state, user,
// perms, flash, jar, headers, path, form). Splitting the handler purely
// for the arg count would obscure the linear delete flow; `allow` is
// the right trade-off here.
#[allow(clippy::too_many_arguments)]
pub async fn delete_asset_web(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    headers: axum::http::HeaderMap,
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
        return htmx_or_flash_redirect(
            &headers,
            flash.error("Invalid CSRF token. Please refresh the page and try again."),
            &format!("/assets/manage/{}", uuid_str),
        );
    }

    if !perms.assets_manage {
        return htmx_or_flash_redirect(
            &headers,
            flash.error("You do not have permission to delete assets"),
            &format!("/assets/manage/{}", uuid_str),
        );
    }

    let asset_uuid = match ::uuid::Uuid::parse_str(&uuid_str) {
        Ok(uuid) => uuid,
        Err(_) => {
            return htmx_or_flash_redirect(
                &headers,
                flash.error("Invalid asset identifier"),
                "/assets/manage",
            );
        }
    };

    let mut conn = match state.db_pool.get().await {
        Ok(conn) => conn,
        Err(_) => {
            return htmx_or_flash_redirect(
                &headers,
                flash.error("Database connection error. Please try again."),
                &format!("/assets/manage/{}", asset_uuid),
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
                "/assets/manage",
            );
        }
        Err(_) => {
            return htmx_or_flash_redirect(
                &headers,
                flash.error("Failed to delete asset. Please try again."),
                &format!("/assets/manage/{}", asset_uuid),
            );
        }
    };

    let now = Utc::now();
    // Issue #22 — re-stamp `updated_by_id` on soft-delete: the
    // tombstone's audit pair must reflect the operator that
    // performed the deletion, not the original creator. Resolved
    // outside the transaction so we never block the row write on
    // a `users` lookup latency. Best-effort: a `None` collapses
    // to the muted em-dash on the `/assets/manage/deleted` page.
    let actor_id =
        crate::services::audit_authors::resolve_actor_id(&mut conn, &auth_user.uuid).await;
    let result = conn
        .transaction::<Vec<i32>, diesel::result::Error, _>(|conn| {
            Box::pin(async move {
                diesel::update(a::assets.filter(a::id.eq(asset_id)))
                    .set((
                        a::is_deleted.eq(true),
                        a::deleted_at.eq(now),
                        a::updated_at.eq(now),
                        a::updated_by_id.eq(actor_id),
                        a::connection_config.eq(serde_json::json!({})),
                    ))
                    .execute(conn)
                    .await?;

                // Returning ids lets us schedule per-session
                // hydration AFTER the transaction commits (issue
                // #29 v1.4 PRIMARY path).
                let terminated_ids: Vec<i32> = diesel::update(
                    ps::proxy_sessions
                        .filter(ps::asset_id.eq(asset_id))
                        .filter(ps::status.eq("active")),
                )
                .set((
                    ps::status.eq("terminated"),
                    ps::disconnected_at.eq(now),
                    ps::updated_at.eq(now),
                ))
                .returning(ps::id)
                .get_results(conn)
                .await?;

                Ok(terminated_ids)
            })
        })
        .await;

    match result {
        Ok(terminated_ids) => {
            for sid in terminated_ids {
                std::mem::drop(crate::services::recording_hydrator::enqueue_hydration(
                    &state,
                    sid,
                    std::time::Duration::from_secs(
                        state.config.recording.hydration_enqueue_delay_secs,
                    ),
                ));
            }

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
                "/assets/manage",
            )
        }
        Err(_) => htmx_or_flash_redirect(
            &headers,
            flash.error("Failed to delete asset. Please try again."),
            &format!("/assets/manage/{}", asset_uuid),
        ),
    }
}

#[cfg(test)]
mod tests {
    //! Source-level invariants on this admin-only module.
    //!
    //! Forbidden patterns are built from `format!` so the test cannot
    //! match its own assertion strings (lesson learned from the
    //! recording hydrator test suite, issue #29).

    /// The admin "Manage Assets" zone must NEVER expose a code path
    /// that can open a session. This source-level test enforces the
    /// invariant by string scan; it is complemented by render-snapshot
    /// tests in `tests/web/manage_assets_render_snapshot_test.rs` that
    /// parse the rendered HTML and assert no `<a href>` or `<form>`
    /// targets a connect / request endpoint.
    #[test]
    fn module_source_has_no_session_opening_path() {
        let source = include_str!("manage_assets.rs");

        // Strip the `#[cfg(test)]` block from the body before scanning,
        // so the assertion strings themselves are not matched.
        let body = source
            .split("#[cfg(test)]")
            .next()
            .expect("module always has a non-test prefix");
        let stripped: String = body
            .lines()
            .map(|l| {
                let t = l.trim_start();
                if t.starts_with("//") { "" } else { l }
            })
            .collect::<Vec<_>>()
            .join("\n");

        let forbidden = [
            format!("connect{}rdp", "-"),
            format!("connect{}ssh", "_"),
            format!("/conn{}ect{}", "ect", "\""),
            format!("submit{}access{}request", "_", "_"),
            format!("request{}access", "-"),
            format!("/sessions{}request", "/"),
            format!("request{}session", "_"),
            format!("ws{}://", "s"),
            format!("Web{}Socket", ""),
        ];

        for pat in &forbidden {
            assert!(
                !stripped.contains(pat.as_str()),
                "manage_assets.rs (admin zone) must never reference '{}' \
                 (a session-opening or access-request code path); found \
                 it in the module body. The admin zone is structurally \
                 session-free; move any such code back to the user zone \
                 (handlers/web/assets.rs / handlers/web/ssh.rs / \
                 handlers/web/rdp.rs)",
                pat
            );
        }
    }

    /// Every public handler exported by this module MUST gate on
    /// `perms.assets_manage` in its first 10 lines, regardless of any
    /// router-level middleware. Defence-in-depth.
    #[test]
    fn every_public_handler_gates_on_assets_manage() {
        let source = include_str!("manage_assets.rs");
        let body = source
            .split("#[cfg(test)]")
            .next()
            .expect("module always has a non-test prefix");

        let gate_pattern = format!("perms.assets_{}", "manage");

        let mut cursor = 0usize;
        let needle = "pub async fn ";
        while let Some(pos) = body[cursor..].find(needle) {
            let absolute = cursor + pos;
            // Slice the next ~30 lines (handler signature + first body
            // statements) and look for the gate pattern.
            let slice_end = body[absolute..]
                .lines()
                .take(30)
                .map(|l| l.len() + 1)
                .sum::<usize>();
            let slice = &body[absolute..(absolute + slice_end).min(body.len())];

            // Extract handler name for nicer assertion message.
            let after_needle = &body[absolute + needle.len()..];
            let name: String = after_needle
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();

            assert!(
                slice.contains(gate_pattern.as_str()),
                "admin handler `{name}` must gate on `{gate_pattern}` in its \
                 first ~30 lines (defence-in-depth even if the routing layer \
                 fails); not found in `manage_assets.rs`",
            );

            cursor = absolute + needle.len();
        }
    }
}
