/// Asset group management page handlers.
use super::*;

pub async fn access_rules_list(
    State(_state): State<AppState>,
    auth_user: WebAuthUser,
) -> Result<impl IntoResponse, AppError> {
    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new("Access Rules".to_string(), user.clone())
        .with_current_path("/assets/access");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        base.into_fields();

    let template = AccessListTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
    };

    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;
    Ok(Html(html))
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
        base.into_fields();

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;
    // Filter out empty strings - form sends empty string when search is cleared
    let search_filter = params.get("search").filter(|s| !s.is_empty()).cloned();

    // L-5: Replaced raw SQL with Diesel DSL (left_join + group_by) for type safety
    // and proper LIKE wildcard escaping via like_contains().
    use crate::db::like_contains;
    use crate::schema::asset_groups;
    use diesel::dsl::count;

    let mut query = asset_groups::table
        .left_join(
            schema_assets::table.on(
                schema_assets::group_id
                    .eq(asset_groups::id.nullable())
                    .and(schema_assets::is_deleted.eq(false)),
            ),
        )
        .filter(asset_groups::is_deleted.eq(false))
        .group_by((
            asset_groups::id,
            asset_groups::uuid,
            asset_groups::name,
            asset_groups::slug,
            asset_groups::description,
            asset_groups::color,
            asset_groups::icon,
            asset_groups::created_at,
        ))
        .select((
            asset_groups::uuid,
            asset_groups::name,
            asset_groups::slug,
            asset_groups::description,
            asset_groups::color,
            asset_groups::icon,
            asset_groups::created_at,
            count(schema_assets::id.nullable()),
        ))
        .order(asset_groups::name.asc())
        .into_boxed();

    if let Some(ref s) = search_filter {
        let pattern = like_contains(s);
        query = query.filter(
            asset_groups::name
                .ilike(pattern.clone())
                .or(asset_groups::slug.ilike(pattern)),
        );
    }

    let groups_data: Vec<AssetGroupRow> =
        query.load(&mut conn).await.map_err(AppError::Database)?;

    let groups: Vec<crate::templates::assets::group_list::AssetGroupItem> = groups_data
        .into_iter()
        .map(
            |(uuid, name, slug, description, color, icon, created_at, asset_count)| {
                crate::templates::assets::group_list::AssetGroupItem {
                    uuid: uuid.to_string(),
                    name,
                    slug,
                    description,
                    color,
                    icon,
                    asset_count,
                    created_at: created_at.format("%b %d, %Y").to_string(),
                }
            },
        )
        .collect();

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

/// Query result type for asset group list (L-5: Diesel DSL replaces raw SQL).
type AssetGroupRow = (
    ::uuid::Uuid,
    String,
    String,
    Option<String>,
    String,
    String,
    chrono::DateTime<chrono::Utc>,
    i64,
);

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

    let mut conn = match state.db_pool.get().await {
        Ok(conn) => conn,
        Err(_) => {
            return flash_redirect(
                flash.error("Database connection error. Please try again."),
                "/assets/groups",
            );
        }
    };

    let group_uuid = match ::uuid::Uuid::parse_str(&uuid_str) {
        Ok(uuid) => uuid,
        Err(_) => {
            return flash_redirect(flash.error("Invalid group identifier"), "/assets/groups");
        }
    };

    // NOTE: Raw SQL - simple query but kept for consistency with related code
    let group_data: AssetGroupDetailResult = match diesel::sql_query(
        "SELECT uuid, name, slug, description, color, icon, created_at, updated_at
         FROM asset_groups WHERE uuid = $1 AND is_deleted = false",
    )
    .bind::<DieselUuid, _>(group_uuid)
    .get_result(&mut conn)
    .await
    {
        Ok(data) => data,
        Err(diesel::result::Error::NotFound) => {
            return flash_redirect(flash.error("Asset group not found"), "/assets/groups");
        }
        Err(_) => {
            return flash_redirect(
                flash.error("Database error. Please try again."),
                "/assets/groups",
            );
        }
    };

    // NOTE: Raw SQL - kept for consistency with asset_group_detail page
    let assets_data: Vec<GroupAssetResult> = match diesel::sql_query(
        "SELECT a.uuid, a.name, a.hostname, a.asset_type, a.status
         FROM assets a
         INNER JOIN asset_groups g ON g.id = a.group_id
         WHERE g.uuid = $1 AND a.is_deleted = false
         ORDER BY a.name ASC",
    )
    .bind::<DieselUuid, _>(group_uuid)
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
        .map(|a| crate::templates::assets::group_detail::GroupAssetItem {
            uuid: a.uuid.to_string(),
            name: a.name,
            hostname: a.hostname,
            asset_type: a.asset_type,
            status: a.status,
        })
        .collect();

    let group = crate::templates::assets::group_detail::AssetGroupDetail {
        uuid: group_data.uuid.to_string(),
        name: group_data.name.clone(),
        slug: group_data.slug,
        description: group_data.description,
        color: group_data.color,
        icon: group_data.icon,
        created_at: group_data.created_at.format("%b %d, %Y %H:%M").to_string(),
        updated_at: group_data.updated_at.format("%b %d, %Y %H:%M").to_string(),
        assets,
    };

    let base = BaseTemplate::new(format!("{} - Asset Group", group_data.name), user.clone())
        .with_current_path("/assets/groups");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        base.into_fields();

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

/// Helper struct for asset group detail query results.
#[derive(diesel::QueryableByName)]
struct AssetGroupDetailResult {
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    uuid: ::uuid::Uuid,
    #[diesel(sql_type = diesel::sql_types::Varchar)]
    name: String,
    #[diesel(sql_type = diesel::sql_types::Varchar)]
    slug: String,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    description: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Varchar)]
    color: String,
    #[diesel(sql_type = diesel::sql_types::Varchar)]
    icon: String,
    #[diesel(sql_type = diesel::sql_types::Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = diesel::sql_types::Timestamptz)]
    updated_at: chrono::DateTime<chrono::Utc>,
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
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
) -> Result<impl IntoResponse, AppError> {
    use crate::templates::assets::group_add_asset::{
        AssetGroupAddAssetTemplate, AvailableAsset, GroupSummary,
    };

    // Only admin users can add assets to groups
    if !is_admin(&auth_user) {
        return Err(AppError::Authorization(
            "Only administrators can manage asset group membership".to_string(),
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
    let group_uuid = ::uuid::Uuid::parse_str(&uuid_str)
        .map_err(|e| AppError::Validation(format!("Invalid UUID: {}", e)))?;

    // Get the group details
    use crate::schema::asset_groups::dsl as ag;
    let group_row: (::uuid::Uuid, String) = ag::asset_groups
        .filter(ag::uuid.eq(group_uuid))
        .filter(ag::is_deleted.eq(false))
        .select((ag::uuid, ag::name))
        .first(&mut conn)
        .await
        .map_err(|e| match e {
            diesel::result::Error::NotFound => {
                AppError::NotFound("Asset group not found".to_string())
            }
            _ => AppError::Database(e),
        })?;

    let group = GroupSummary {
        uuid: group_row.0.to_string(),
        name: group_row.1,
    };

    // Get ALL assets (not deleted) with their current group name if assigned
    // Assets already in a group will be displayed as grayed out and non-selectable
    use crate::schema::assets::dsl as a;
    let available_asset_rows: Vec<(::uuid::Uuid, String, String, String, String, Option<i32>)> =
        a::assets
            .filter(a::is_deleted.eq(false))
            .select((
                a::uuid,
                a::name,
                a::hostname,
                a::asset_type,
                a::status,
                a::group_id,
            ))
            .order(a::name.asc())
            .load(&mut conn)
            .await
            .map_err(AppError::Database)?;

    // Get all group names for lookup
    let group_names: std::collections::HashMap<i32, String> = ag::asset_groups
        .filter(ag::is_deleted.eq(false))
        .select((ag::id, ag::name))
        .load::<(i32, String)>(&mut conn)
        .await
        .map_err(AppError::Database)?
        .into_iter()
        .collect();

    let available_assets: Vec<AvailableAsset> = available_asset_rows
        .into_iter()
        .map(|(uuid, name, hostname, asset_type, status, group_id)| {
            let current_group_name = group_id.and_then(|gid| group_names.get(&gid).cloned());
            AvailableAsset {
                uuid: uuid.to_string(),
                name,
                hostname,
                asset_type,
                status,
                current_group_name,
            }
        })
        .collect();

    // Count assets that are available (not assigned to any group)
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
        base.into_fields();

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
    auth_user: WebAuthUser,
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

    // Permission check
    if !is_admin(&auth_user) {
        return flash_redirect(
            flash.error("Only administrators can manage asset group membership"),
            &format!("/assets/groups/{}", uuid_str),
        );
    }

    // Parse group UUID
    let group_uuid = match ::uuid::Uuid::parse_str(&uuid_str) {
        Ok(uuid) => uuid,
        Err(_) => {
            return flash_redirect(flash.error("Invalid group identifier"), "/assets/groups");
        }
    };

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

    let mut conn = match state.db_pool.get().await {
        Ok(conn) => conn,
        Err(_) => {
            return flash_redirect(
                flash.error("Database connection error. Please try again."),
                &format!("/assets/groups/{}/add-asset", uuid_str),
            );
        }
    };

    // Get the group's internal ID
    use crate::schema::asset_groups::dsl as ag;
    let group_id: i32 = match ag::asset_groups
        .filter(ag::uuid.eq(group_uuid))
        .filter(ag::is_deleted.eq(false))
        .select(ag::id)
        .first(&mut conn)
        .await
    {
        Ok(id) => id,
        Err(diesel::result::Error::NotFound) => {
            return flash_redirect(flash.error("Asset group not found"), "/assets/groups");
        }
        Err(_) => {
            return flash_redirect(
                flash.error("Database error. Please try again."),
                &format!("/assets/groups/{}/add-asset", uuid_str),
            );
        }
    };

    // Update all selected assets to set their group_id
    use crate::schema::assets::dsl as a;
    let updated = diesel::update(a::assets)
        .filter(a::uuid.eq_any(&asset_uuids))
        .filter(a::is_deleted.eq(false))
        .filter(a::group_id.is_null()) // Only update if not already in a group
        .set((
            a::group_id.eq(Some(group_id)),
            a::updated_at.eq(chrono::Utc::now()),
        ))
        .execute(&mut conn)
        .await;

    match updated {
        Ok(0) => {
            // No rows updated - either assets not found or already in groups
            flash_redirect(
                flash.error("No assets were added. They may already be assigned to groups."),
                &format!("/assets/groups/{}/add-asset", uuid_str),
            )
        }
        Ok(count) => {
            let message = if count == 1 {
                "1 asset added to group successfully".to_string()
            } else {
                format!("{} assets added to group successfully", count)
            };
            flash_redirect(
                flash.success(&message),
                &format!("/assets/groups/{}", uuid_str),
            )
        }
        Err(_) => flash_redirect(
            flash.error("Failed to add assets to group. Please try again."),
            &format!("/assets/groups/{}/add-asset", uuid_str),
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
pub async fn asset_group_remove_asset(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
    Form(form): Form<RemoveAssetFromGroupForm>,
) -> Response {
    let flash = incoming_flash.flash();

    // CSRF validation
    let csrf_cookie = jar.get(crate::middleware::csrf::CSRF_COOKIE_NAME);
    if !crate::middleware::csrf::validate_double_submit(
        state.config.secret_key.expose_secret().as_bytes(),
        csrf_cookie.map(|c| c.value()),
        &form.csrf_token,
    ) {
        return flash_redirect(
            flash.error("Invalid CSRF token. Please refresh the page and try again."),
            &format!("/assets/groups/{}", uuid_str),
        );
    }

    // Permission check
    if !is_admin(&auth_user) {
        return flash_redirect(
            flash.error("Only administrators can manage asset group membership"),
            &format!("/assets/groups/{}", uuid_str),
        );
    }

    // Parse group UUID (for redirect)
    let group_uuid = match ::uuid::Uuid::parse_str(&uuid_str) {
        Ok(uuid) => uuid,
        Err(_) => {
            return flash_redirect(flash.error("Invalid group identifier"), "/assets/groups");
        }
    };

    // Parse asset UUID
    let asset_uuid = match ::uuid::Uuid::parse_str(&form.asset_uuid) {
        Ok(uuid) => uuid,
        Err(_) => {
            return flash_redirect(
                flash.error("Invalid asset identifier"),
                &format!("/assets/groups/{}", group_uuid),
            );
        }
    };

    let mut conn = match state.db_pool.get().await {
        Ok(conn) => conn,
        Err(_) => {
            return flash_redirect(
                flash.error("Database connection error. Please try again."),
                &format!("/assets/groups/{}", group_uuid),
            );
        }
    };

    // Update the asset to remove its group_id
    use crate::schema::assets::dsl as a;
    let updated = diesel::update(a::assets)
        .filter(a::uuid.eq(asset_uuid))
        .filter(a::is_deleted.eq(false))
        .set((
            a::group_id.eq(None::<i32>),
            a::updated_at.eq(chrono::Utc::now()),
        ))
        .execute(&mut conn)
        .await;

    match updated {
        Ok(0) => flash_redirect(
            flash.error("Asset not found"),
            &format!("/assets/groups/{}", group_uuid),
        ),
        Ok(_) => flash_redirect(
            flash.success("Asset removed from group successfully"),
            &format!("/assets/groups/{}", group_uuid),
        ),
        Err(_) => flash_redirect(
            flash.error("Failed to remove asset from group. Please try again."),
            &format!("/assets/groups/{}", group_uuid),
        ),
    }
}

/// Asset group edit page.
pub async fn asset_group_edit(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    incoming_flash: IncomingFlash,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
) -> Response {
    let flash = incoming_flash.flash();

    // Only admin users can edit asset groups
    if !is_admin(&auth_user) {
        return flash_redirect(
            flash.error("Only administrators can edit asset groups"),
            "/assets/groups",
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
                "/assets/groups",
            );
        }
    };

    let group_uuid = match ::uuid::Uuid::parse_str(&uuid_str) {
        Ok(uuid) => uuid,
        Err(_) => {
            return flash_redirect(flash.error("Invalid group identifier"), "/assets/groups");
        }
    };

    // NOTE: Raw SQL - kept for consistency with asset_group pages
    let group_data: AssetGroupEditResult = match diesel::sql_query(
        "SELECT uuid, name, slug, description, color, icon
         FROM asset_groups WHERE uuid = $1 AND is_deleted = false",
    )
    .bind::<DieselUuid, _>(group_uuid)
    .get_result(&mut conn)
    .await
    {
        Ok(data) => data,
        Err(diesel::result::Error::NotFound) => {
            return flash_redirect(flash.error("Asset group not found"), "/assets/groups");
        }
        Err(_) => {
            return flash_redirect(
                flash.error("Database error. Please try again."),
                "/assets/groups",
            );
        }
    };

    let group = crate::templates::assets::group_edit::AssetGroupEdit {
        uuid: group_data.uuid.to_string(),
        name: group_data.name.clone(),
        slug: group_data.slug,
        description: group_data.description,
        color: group_data.color,
        icon: group_data.icon,
    };

    let base = BaseTemplate::new(
        format!("Edit {} - Asset Group", group_data.name),
        user.clone(),
    )
    .with_current_path("/assets/groups")
    .with_messages(flash_messages);
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        base.into_fields();

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

    // Clear flash cookie after reading and return HTML
    use crate::middleware::flash::ClearFlashCookie;
    match template.render() {
        Ok(html) => (ClearFlashCookie, Html(html)).into_response(),
        Err(_) => flash_redirect(flash.error("Failed to render page"), "/assets/groups"),
    }
}

/// Helper struct for asset group edit query results.
#[derive(diesel::QueryableByName)]
struct AssetGroupEditResult {
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    uuid: ::uuid::Uuid,
    #[diesel(sql_type = diesel::sql_types::Varchar)]
    name: String,
    #[diesel(sql_type = diesel::sql_types::Varchar)]
    slug: String,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    description: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Varchar)]
    color: String,
    #[diesel(sql_type = diesel::sql_types::Varchar)]
    icon: String,
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

    // Permission check - only admin can update asset groups
    if !is_admin(&auth_user) {
        return flash_redirect(
            flash.error("Only administrators can modify asset groups"),
            &format!("/assets/groups/{}", uuid_str),
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

    // Get database connection
    let mut conn = match state.db_pool.get().await {
        Ok(conn) => conn,
        Err(_) => {
            return flash_redirect(
                flash.error("Database connection error. Please try again."),
                &format!("/assets/groups/{}/edit", group_uuid),
            );
        }
    };

    // Sanitize text fields to prevent stored XSS
    let sanitized_name = sanitize(&form.name);
    let sanitized_description = sanitize_opt(form.description.clone());

    // NOTE: Raw SQL - UPDATE with NOW() PostgreSQL function, using parameterized queries
    let result = diesel::sql_query(
        "UPDATE asset_groups SET name = $1, slug = $2, description = $3, color = $4, icon = $5, updated_at = NOW()
         WHERE uuid = $6 AND is_deleted = false"
    )
    .bind::<Text, _>(&sanitized_name)
    .bind::<Text, _>(&form.slug)
    .bind::<Nullable<Text>, _>(sanitized_description.as_deref())
    .bind::<Text, _>(&form.color)
    .bind::<Text, _>(&form.icon)
    .bind::<DieselUuid, _>(group_uuid)
    .execute(&mut conn).await;

    match result {
        Ok(_) => {
            // Success: redirect to detail page with success message
            flash_redirect(
                flash.success("Asset group updated successfully"),
                &format!("/assets/groups/{}", group_uuid),
            )
        }
        Err(_) => {
            // Error: redirect back to edit page with error message
            flash_redirect(
                flash.error("Failed to update asset group. Please try again."),
                &format!("/assets/groups/{}/edit", group_uuid),
            )
        }
    }
}

/// Asset group create form page.
pub async fn asset_group_create_form(
    State(_state): State<AppState>,
    auth_user: WebAuthUser,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
) -> Result<impl IntoResponse, AppError> {
    use crate::templates::assets::group_create::{AssetGroupCreateForm, AssetGroupCreateTemplate};

    // Only admin users can create asset groups
    if !is_admin(&auth_user) {
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
        base.into_fields();

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

    // Clear flash cookie after reading and return HTML
    use crate::middleware::flash::ClearFlashCookie;
    Ok((ClearFlashCookie, Html(html)))
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

    // Permission check - only admin can create asset groups
    if !is_admin(&auth_user) {
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

    let mut conn = match state.db_pool.get().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Database connection error: {}", e);
            return flash_redirect(
                flash.error("Database connection error"),
                "/assets/groups/new",
            );
        }
    };

    // Check if asset group with same slug already exists
    use crate::schema::asset_groups::dsl as ag;
    let existing: Option<i32> = ag::asset_groups
        .filter(ag::slug.eq(form.slug.trim()))
        .filter(ag::is_deleted.eq(false))
        .select(ag::id)
        .first(&mut conn)
        .await
        .optional()
        .unwrap_or(None);

    if existing.is_some() {
        return flash_redirect(
            flash.error("An asset group with this slug already exists"),
            "/assets/groups/new",
        );
    }

    // Create the asset group
    let new_uuid = ::uuid::Uuid::new_v4();
    let now = chrono::Utc::now();

    // Sanitize text fields to prevent stored XSS
    let sanitized_name = sanitize(form.name.trim());
    let sanitized_description = sanitize_opt(
        form.description.as_ref().filter(|s| !s.is_empty()).cloned(),
    );

    let result = diesel::insert_into(ag::asset_groups)
        .values((
            ag::uuid.eq(new_uuid),
            ag::name.eq(&sanitized_name),
            ag::slug.eq(form.slug.trim()),
            ag::description.eq(&sanitized_description),
            ag::color.eq(&form.color),
            ag::icon.eq(&form.icon),
            ag::is_deleted.eq(false),
            ag::created_at.eq(now),
            ag::updated_at.eq(now),
        ))
        .execute(&mut conn)
        .await;

    match result {
        Ok(_) => flash_redirect(
            flash.success(format!(
                "Asset group '{}' created successfully",
                sanitized_name
            )),
            &format!("/assets/groups/{}", new_uuid),
        ),
        Err(e) => {
            tracing::error!("Failed to create asset group: {}", e);
            flash_redirect(
                flash.error("Failed to create asset group"),
                "/assets/groups/new",
            )
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
pub async fn delete_asset_group_web(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
    Form(form): Form<DeleteAssetGroupForm>,
) -> Response {
    let flash = incoming_flash.flash();

    // CSRF validation
    let csrf_cookie = jar.get(crate::middleware::csrf::CSRF_COOKIE_NAME);
    if !crate::middleware::csrf::validate_double_submit(
        state.config.secret_key.expose_secret().as_bytes(),
        csrf_cookie.map(|c| c.value()),
        &form.csrf_token,
    ) {
        return flash_redirect(
            flash.error("Invalid CSRF token"),
            &format!("/assets/groups/{}", uuid_str),
        );
    }

    // Permission check - only admin can delete asset groups
    if !is_admin(&auth_user) {
        return flash_redirect(
            flash.error("Only administrators can delete asset groups"),
            "/assets/groups",
        );
    }

    // Validate UUID
    let group_uuid = match ::uuid::Uuid::parse_str(&uuid_str) {
        Ok(uuid) => uuid,
        Err(_) => {
            return flash_redirect(flash.error("Invalid group identifier"), "/assets/groups");
        }
    };

    let mut conn = match state.db_pool.get().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Database connection error: {}", e);
            return flash_redirect(
                flash.error("Database connection error"),
                &format!("/assets/groups/{}", uuid_str),
            );
        }
    };

    // Get the group id and name for logging
    use crate::schema::asset_groups::dsl as ag;
    let group_data: Option<(i32, String)> = ag::asset_groups
        .filter(ag::uuid.eq(group_uuid))
        .filter(ag::is_deleted.eq(false))
        .select((ag::id, ag::name))
        .first(&mut conn)
        .await
        .optional()
        .unwrap_or(None);

    let (group_id, group_name) = match group_data {
        Some(data) => data,
        None => {
            return flash_redirect(flash.error("Asset group not found"), "/assets/groups");
        }
    };

    // Remove group association from assets first (set group_id to NULL)
    use crate::schema::assets::dsl as a;
    let _ = diesel::update(a::assets.filter(a::group_id.eq(group_id)))
        .set(a::group_id.eq(None::<i32>))
        .execute(&mut conn)
        .await;

    // Hard delete the asset group
    let result = diesel::delete(ag::asset_groups.filter(ag::id.eq(group_id)))
        .execute(&mut conn)
        .await;

    match result {
        Ok(_) => flash_redirect(
            flash.success(format!("Asset group '{}' deleted successfully", group_name)),
            "/assets/groups",
        ),
        Err(e) => {
            tracing::error!("Failed to delete asset group: {}", e);
            flash_redirect(
                flash.error("Failed to delete asset group"),
                &format!("/assets/groups/{}", uuid_str),
            )
        }
    }
}
