/// Vauban group management page handlers.
use super::*;

pub async fn group_list(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse, AppError> {
    let user = Some(user_context_from_auth(&auth_user));
    let base =
        BaseTemplate::new("Groups".to_string(), user.clone()).with_current_path("/accounts/groups");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        base.into_fields();

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;
    // Filter out empty strings - form sends empty string when search is cleared
    let search_filter = params.get("search").filter(|s| !s.is_empty()).cloned();

    // Query groups with member count
    // Groups list query - migrated to Diesel DSL
    use crate::schema::vauban_groups::dsl::*;

    #[allow(clippy::type_complexity)]
    let groups_data: Vec<(
        ::uuid::Uuid,
        String,
        Option<String>,
        String,
        chrono::DateTime<chrono::Utc>,
    )> = if let Some(ref s) = search_filter {
        let pattern = format!("%{}%", s);
        vauban_groups
            .filter(name.ilike(&pattern).or(description.ilike(&pattern)))
            .order(name.asc())
            .select((uuid, name, description, source, created_at))
            .load::<(
                ::uuid::Uuid,
                String,
                Option<String>,
                String,
                chrono::DateTime<chrono::Utc>,
            )>(&mut conn)
            .await
            .map_err(AppError::Database)?
    } else {
        vauban_groups
            .order(name.asc())
            .select((uuid, name, description, source, created_at))
            .load::<(
                ::uuid::Uuid,
                String,
                Option<String>,
                String,
                chrono::DateTime<chrono::Utc>,
            )>(&mut conn)
            .await
            .map_err(AppError::Database)?
    };

    // Get member counts - migrated to Diesel DSL
    use crate::schema::user_groups::dsl::{group_id as ug_group_id, user_groups};
    let mut group_items: Vec<crate::templates::accounts::group_list::GroupListItem> =
        Vec::with_capacity(groups_data.len());
    for (group_uuid, group_name, group_description, group_source, group_created_at) in groups_data {
        // Get member count for this group using JOIN
        let member_count: i64 = user_groups
            .inner_join(vauban_groups.on(id.eq(ug_group_id)))
            .filter(uuid.eq(group_uuid))
            .count()
            .get_result(&mut conn)
            .await
            .unwrap_or(0);

        group_items.push(crate::templates::accounts::group_list::GroupListItem {
            uuid: group_uuid.to_string(),
            name: group_name,
            description: group_description,
            source: group_source,
            member_count,
            created_at: group_created_at.format("%b %d, %Y").to_string(),
        });
    }

    let template = GroupListTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        groups: group_items,
        search: search_filter,
    };

    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;
    Ok(Html(html))
}

// NOTE: GroupQueryResult and CountResult removed - migrated to Diesel DSL

/// Group detail page.
pub async fn group_detail(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
) -> Response {
    let flash = incoming_flash.flash();
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

    // Get CSRF token from cookie
    let csrf_token = jar
        .get(crate::middleware::csrf::CSRF_COOKIE_NAME)
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    let mut conn = match state.db_pool.get().await {
        Ok(conn) => conn,
        Err(_) => {
            return flash_redirect(
                flash.error("Database connection error. Please try again."),
                "/accounts/groups",
            );
        }
    };

    let group_uuid = match ::uuid::Uuid::parse_str(&uuid_str) {
        Ok(uuid) => uuid,
        Err(_) => {
            return flash_redirect(flash.error("Invalid group identifier"), "/accounts/groups");
        }
    };

    // Query group details - migrated to Diesel DSL (combined into single query)
    use crate::schema::vauban_groups::dsl as vg;
    #[allow(clippy::type_complexity)]
    let group_row: (
        ::uuid::Uuid,
        String,
        Option<String>,
        String,
        chrono::DateTime<chrono::Utc>,
        Option<String>,
        chrono::DateTime<chrono::Utc>,
        Option<chrono::DateTime<chrono::Utc>>,
    ) = match vg::vauban_groups
        .filter(vg::uuid.eq(group_uuid))
        .select((
            vg::uuid,
            vg::name,
            vg::description,
            vg::source,
            vg::created_at,
            vg::external_id,
            vg::updated_at,
            vg::last_synced,
        ))
        .first(&mut conn)
        .await
    {
        Ok(row) => row,
        Err(diesel::result::Error::NotFound) => {
            return flash_redirect(flash.error("Group not found"), "/accounts/groups");
        }
        Err(_) => {
            return flash_redirect(
                flash.error("Database error. Please try again."),
                "/accounts/groups",
            );
        }
    };

    // Unpack the combined result
    let (
        g_uuid,
        g_name,
        g_description,
        g_source,
        g_created_at,
        g_external_id,
        g_updated_at,
        g_last_synced,
    ) = group_row;

    // Query group members - migrated to Diesel DSL with JOINs
    use crate::schema::user_groups::dsl as ug;
    use crate::schema::users::dsl as u;
    #[allow(clippy::type_complexity)]
    let members_data: Vec<(
        ::uuid::Uuid,
        String,
        String,
        Option<String>,
        Option<String>,
        bool,
    )> = match u::users
        .inner_join(ug::user_groups.on(ug::user_id.eq(u::id)))
        .inner_join(vg::vauban_groups.on(vg::id.eq(ug::group_id)))
        .filter(vg::uuid.eq(group_uuid))
        .filter(u::is_deleted.eq(false))
        .order(u::username.asc())
        .select((
            u::uuid,
            u::username,
            u::email,
            u::first_name,
            u::last_name,
            u::is_active,
        ))
        .load(&mut conn)
        .await
    {
        Ok(data) => data,
        Err(_) => {
            return flash_redirect(
                flash.error("Database error. Please try again."),
                "/accounts/groups",
            );
        }
    };

    let members: Vec<crate::templates::accounts::group_detail::GroupMember> = members_data
        .into_iter()
        .map(
            |(m_uuid, m_username, m_email, m_first_name, m_last_name, m_is_active)| {
                let full_name = match (m_first_name, m_last_name) {
                    (Some(f), Some(l)) => Some(format!("{} {}", f, l)),
                    (Some(f), None) => Some(f),
                    (None, Some(l)) => Some(l),
                    (None, None) => None,
                };
                crate::templates::accounts::group_detail::GroupMember {
                    uuid: m_uuid.to_string(),
                    username: m_username,
                    email: m_email,
                    full_name,
                    is_active: m_is_active,
                }
            },
        )
        .collect();

    let group = crate::templates::accounts::group_detail::GroupDetail {
        uuid: g_uuid.to_string(),
        name: g_name.clone(),
        description: g_description,
        source: g_source,
        external_id: g_external_id,
        created_at: g_created_at.format("%b %d, %Y %H:%M").to_string(),
        updated_at: g_updated_at.format("%b %d, %Y %H:%M").to_string(),
        last_synced: g_last_synced.map(|dt| dt.format("%b %d, %Y %H:%M").to_string()),
        members,
    };

    let base = BaseTemplate::new(format!("{} - Group", g_name), user.clone())
        .with_current_path("/accounts/groups")
        .with_messages(flash_messages);
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        base.into_fields();

    let template = GroupDetailTemplate {
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

    // Clear flash cookie after reading and return HTML
    use crate::middleware::flash::ClearFlashCookie;
    match template.render() {
        Ok(html) => (ClearFlashCookie, Html(html)).into_response(),
        Err(_) => flash_redirect(flash.error("Failed to render page"), "/accounts/groups"),
    }
}

// NOTE: GroupExtraResult and GroupMemberResult removed - migrated to Diesel DSL

// =============================================================================
// Vauban Group Management (Edit, Members)
// =============================================================================

/// Form data for updating a group.
#[derive(Debug, serde::Deserialize)]
pub struct UpdateGroupWebForm {
    pub csrf_token: String,
    pub name: String,
    pub description: Option<String>,
}

/// Form data for adding a member to a group.
#[derive(Debug, serde::Deserialize)]
pub struct AddGroupMemberForm {
    pub csrf_token: String,
    pub user_uuid: String,
}

/// Form data for creating a new group.
#[derive(Debug, serde::Deserialize)]
pub struct CreateGroupWebForm {
    pub csrf_token: String,
    pub name: String,
    pub description: Option<String>,
}

/// Vauban group create form page (GET /accounts/groups/new).
pub async fn vauban_group_create_form(
    State(_state): State<AppState>,
    auth_user: WebAuthUser,
    jar: CookieJar,
) -> Result<impl IntoResponse, AppError> {
    use crate::templates::accounts::GroupCreateTemplate;

    // Only superuser can create groups
    if !auth_user.is_superuser {
        return Err(AppError::Authorization(
            "Only superusers can create groups".to_string(),
        ));
    }

    // Get CSRF token from cookie
    let csrf_token = jar
        .get(crate::middleware::csrf::CSRF_COOKIE_NAME)
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    let user = Some(user_context_from_auth(&auth_user));
    let base =
        BaseTemplate::new("Create Group".to_string(), user).with_current_path("/accounts/groups");

    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        base.into_fields();

    let template = GroupCreateTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        csrf_token,
    };

    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;
    Ok(Html(html))
}

/// Create vauban group handler (POST /accounts/groups).
pub async fn create_vauban_group_web(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    Form(form): Form<CreateGroupWebForm>,
) -> Response {
    use crate::schema::vauban_groups::dsl as vg;
    use chrono::Utc;

    let flash = incoming_flash.flash();

    // CSRF validation
    let csrf_cookie = jar.get(crate::middleware::csrf::CSRF_COOKIE_NAME);
    let secret = state.config.secret_key.expose_secret().as_bytes();
    if !crate::middleware::csrf::validate_double_submit(
        secret,
        csrf_cookie.map(|c| c.value()),
        &form.csrf_token,
    ) {
        return flash_redirect(
            flash.error("Invalid CSRF token. Please refresh the page and try again."),
            "/accounts/groups/new",
        );
    }

    // Only superuser can create groups
    if !auth_user.is_superuser {
        return flash_redirect(
            flash.error("Only superusers can create groups"),
            "/accounts/groups",
        );
    }

    // Validate name
    if form.name.trim().is_empty() || form.name.len() > 100 {
        return flash_redirect(
            flash.error("Group name must be between 1 and 100 characters"),
            "/accounts/groups/new",
        );
    }

    let mut conn = match state.db_pool.get().await {
        Ok(conn) => conn,
        Err(_) => {
            return flash_redirect(
                flash.error("Database connection error. Please try again."),
                "/accounts/groups/new",
            );
        }
    };

    // Check if group name already exists
    let existing: Option<i32> = vg::vauban_groups
        .filter(vg::name.eq(&form.name))
        .select(vg::id)
        .first(&mut conn)
        .await
        .optional()
        .unwrap_or(None);

    if existing.is_some() {
        return flash_redirect(
            flash.error("A group with this name already exists"),
            "/accounts/groups/new",
        );
    }

    // Create the group
    let new_uuid = ::uuid::Uuid::new_v4();
    let now = Utc::now();

    // Sanitize text fields to prevent stored XSS
    let sanitized_name = sanitize(&form.name);
    let sanitized_description = sanitize_opt(form.description.filter(|d| !d.trim().is_empty()));

    let insert_result = diesel::insert_into(vg::vauban_groups)
        .values((
            vg::uuid.eq(new_uuid),
            vg::name.eq(&sanitized_name),
            vg::description.eq(&sanitized_description),
            vg::source.eq("local"),
            vg::created_at.eq(now),
            vg::updated_at.eq(now),
        ))
        .execute(&mut conn)
        .await;

    match insert_result {
        Ok(_) => flash_redirect(
            flash.success(format!("Group '{}' created successfully", sanitized_name)),
            &format!("/accounts/groups/{}", new_uuid),
        ),
        Err(e) => {
            tracing::error!("Failed to create group: {:?}", e);
            flash_redirect(
                flash.error("Failed to create group. Please try again."),
                "/accounts/groups/new",
            )
        }
    }
}

/// Vauban group edit form page (GET /accounts/groups/{uuid}/edit).
pub async fn vauban_group_edit_form(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    jar: CookieJar,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
) -> Result<impl IntoResponse, AppError> {
    use crate::schema::vauban_groups::dsl as vg;
    use crate::templates::accounts::{GroupEditData, GroupEditTemplate};

    // Only superuser can edit groups
    if !auth_user.is_superuser {
        return Err(AppError::Authorization(
            "Only superusers can edit groups".to_string(),
        ));
    }

    // Get CSRF token from cookie
    let csrf_token = jar
        .get(crate::middleware::csrf::CSRF_COOKIE_NAME)
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;
    let group_uuid = ::uuid::Uuid::parse_str(&uuid_str)
        .map_err(|e| AppError::Validation(format!("Invalid UUID: {}", e)))?;

    let group_row: (::uuid::Uuid, String, Option<String>, String) = vg::vauban_groups
        .filter(vg::uuid.eq(group_uuid))
        .select((vg::uuid, vg::name, vg::description, vg::source))
        .first(&mut conn)
        .await
        .map_err(|e| match e {
            diesel::result::Error::NotFound => AppError::NotFound("Group not found".to_string()),
            _ => AppError::Database(e),
        })?;

    let (g_uuid, g_name, g_description, g_source) = group_row;

    let group = GroupEditData {
        uuid: g_uuid.to_string(),
        name: g_name.clone(),
        description: g_description,
        source: g_source,
    };

    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new(format!("Edit {} - Group", g_name), user)
        .with_current_path("/accounts/groups");

    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        base.into_fields();

    let template = GroupEditTemplate {
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

    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;
    Ok(Html(html))
}

/// Update vauban group handler (POST /accounts/groups/{uuid}).
pub async fn update_vauban_group_web(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
    Form(form): Form<UpdateGroupWebForm>,
) -> Response {
    use crate::schema::vauban_groups::dsl as vg;
    use chrono::Utc;

    let flash = incoming_flash.flash();

    // CSRF validation
    let csrf_cookie = jar.get(crate::middleware::csrf::CSRF_COOKIE_NAME);
    let secret = state.config.secret_key.expose_secret().as_bytes();
    if !crate::middleware::csrf::validate_double_submit(
        secret,
        csrf_cookie.map(|c| c.value()),
        &form.csrf_token,
    ) {
        return flash_redirect(
            flash.error("Invalid CSRF token. Please refresh the page and try again."),
            &format!("/accounts/groups/{}/edit", uuid_str),
        );
    }

    // Only superuser can edit groups
    if !auth_user.is_superuser {
        return flash_redirect(
            flash.error("Only superusers can edit groups"),
            "/accounts/groups",
        );
    }

    let group_uuid = match ::uuid::Uuid::parse_str(&uuid_str) {
        Ok(uuid) => uuid,
        Err(_) => {
            return flash_redirect(flash.error("Invalid group identifier"), "/accounts/groups");
        }
    };

    // Validate name
    if form.name.trim().is_empty() || form.name.len() > 100 {
        return flash_redirect(
            flash.error("Group name must be between 1 and 100 characters"),
            &format!("/accounts/groups/{}/edit", uuid_str),
        );
    }

    let mut conn = match state.db_pool.get().await {
        Ok(conn) => conn,
        Err(_) => {
            return flash_redirect(
                flash.error("Database connection error. Please try again."),
                &format!("/accounts/groups/{}/edit", uuid_str),
            );
        }
    };

    let now = Utc::now();

    // Sanitize text fields to prevent stored XSS
    let sanitized_name = sanitize(form.name.trim());
    let sanitized_description = sanitize_opt_ref(form.description.as_ref().filter(|s| !s.is_empty()));

    let result = diesel::update(vg::vauban_groups.filter(vg::uuid.eq(group_uuid)))
        .set((
            vg::name.eq(&sanitized_name),
            vg::description.eq(&sanitized_description),
            vg::updated_at.eq(now),
        ))
        .execute(&mut conn)
        .await;

    match result {
        Ok(0) => flash_redirect(flash.error("Group not found"), "/accounts/groups"),
        Ok(_) => flash_redirect(
            flash.success("Group updated successfully"),
            &format!("/accounts/groups/{}", uuid_str),
        ),
        Err(_) => flash_redirect(
            flash.error("Failed to update group. Please try again."),
            &format!("/accounts/groups/{}/edit", uuid_str),
        ),
    }
}

/// Add member form page (GET /accounts/groups/{uuid}/members/add).
pub async fn group_add_member_form(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
) -> Result<impl IntoResponse, AppError> {
    use crate::schema::user_groups::dsl as ug;
    use crate::schema::users::dsl as u;
    use crate::schema::vauban_groups::dsl as vg;
    use crate::templates::accounts::{AvailableUser, GroupAddMemberTemplate, GroupInfo};

    // Only staff or superuser can manage members
    if !auth_user.is_superuser && !auth_user.is_staff {
        return Err(AppError::Authorization(
            "You do not have permission to manage group members".to_string(),
        ));
    }

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;
    let group_uuid = ::uuid::Uuid::parse_str(&uuid_str)
        .map_err(|e| AppError::Validation(format!("Invalid UUID: {}", e)))?;

    // Get group info
    let group_row: (::uuid::Uuid, String, i32) = vg::vauban_groups
        .filter(vg::uuid.eq(group_uuid))
        .select((vg::uuid, vg::name, vg::id))
        .first(&mut conn)
        .await
        .map_err(|e| match e {
            diesel::result::Error::NotFound => AppError::NotFound("Group not found".to_string()),
            _ => AppError::Database(e),
        })?;

    let (g_uuid, g_name, group_id) = group_row;

    // Get users NOT in this group
    let existing_member_ids: Vec<i32> = ug::user_groups
        .filter(ug::group_id.eq(group_id))
        .select(ug::user_id)
        .load(&mut conn)
        .await
        .map_err(AppError::Database)?;

    let available_users_data: Vec<(::uuid::Uuid, String, String)> = u::users
        .filter(u::is_deleted.eq(false))
        .filter(u::is_active.eq(true))
        .filter(u::id.ne_all(&existing_member_ids))
        .order(u::username.asc())
        .select((u::uuid, u::username, u::email))
        .limit(50)
        .load(&mut conn)
        .await
        .map_err(AppError::Database)?;

    let available_users: Vec<AvailableUser> = available_users_data
        .into_iter()
        .map(|(uuid, username, email)| AvailableUser {
            uuid: uuid.to_string(),
            username,
            email,
        })
        .collect();

    let group = GroupInfo {
        uuid: g_uuid.to_string(),
        name: g_name.clone(),
    };

    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new(format!("Add Member - {}", g_name), user)
        .with_current_path("/accounts/groups");

    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        base.into_fields();

    let template = GroupAddMemberTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        group,
        available_users,
    };

    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;
    Ok(Html(html))
}

/// Search users for adding to group (HTMX endpoint).
pub async fn group_member_search(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse, AppError> {
    use crate::schema::user_groups::dsl as ug;
    use crate::schema::users::dsl as u;
    use crate::schema::vauban_groups::dsl as vg;

    // Only staff or superuser can manage members
    if !auth_user.is_superuser && !auth_user.is_staff {
        return Err(AppError::Authorization(
            "You do not have permission to manage group members".to_string(),
        ));
    }

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;
    let group_uuid = ::uuid::Uuid::parse_str(&uuid_str)
        .map_err(|e| AppError::Validation(format!("Invalid UUID: {}", e)))?;

    let search_term = params.get("user-search").cloned().unwrap_or_default();

    // Get group ID
    let group_id: i32 = vg::vauban_groups
        .filter(vg::uuid.eq(group_uuid))
        .select(vg::id)
        .first(&mut conn)
        .await
        .map_err(|e| match e {
            diesel::result::Error::NotFound => AppError::NotFound("Group not found".to_string()),
            _ => AppError::Database(e),
        })?;

    // Get users NOT in this group, optionally filtered by search
    let existing_member_ids: Vec<i32> = ug::user_groups
        .filter(ug::group_id.eq(group_id))
        .select(ug::user_id)
        .load(&mut conn)
        .await
        .map_err(AppError::Database)?;

    let available_users_data: Vec<(::uuid::Uuid, String, String)> = if search_term.is_empty() {
        u::users
            .filter(u::is_deleted.eq(false))
            .filter(u::is_active.eq(true))
            .filter(u::id.ne_all(&existing_member_ids))
            .order(u::username.asc())
            .select((u::uuid, u::username, u::email))
            .limit(50)
            .load(&mut conn)
            .await
            .map_err(AppError::Database)?
    } else {
        let pattern = format!("%{}%", search_term);
        u::users
            .filter(u::is_deleted.eq(false))
            .filter(u::is_active.eq(true))
            .filter(u::id.ne_all(&existing_member_ids))
            .filter(u::username.ilike(&pattern).or(u::email.ilike(&pattern)))
            .order(u::username.asc())
            .select((u::uuid, u::username, u::email))
            .limit(50)
            .load(&mut conn)
            .await
            .map_err(AppError::Database)?
    };

    // Build HTML response for HTMX
    let mut html = String::new();
    if available_users_data.is_empty() {
        html.push_str(r#"<div class="px-4 py-8 text-center text-gray-500 dark:text-gray-400">"#);
        html.push_str(r#"<svg class="mx-auto h-12 w-12 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">"#);
        html.push_str(r#"<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z"/>"#);
        html.push_str("</svg>");
        html.push_str(r#"<p class="mt-2 text-sm">No matching users found.</p>"#);
        html.push_str("</div>");
    } else {
        for (user_uuid, username, email) in available_users_data {
            let initial = username.chars().next().unwrap_or('U').to_uppercase();
            html.push_str(&format!(
                r#"<div class="px-4 py-3 hover:bg-gray-50 dark:hover:bg-gray-700">
                    <form method="post" action="/accounts/groups/{}/members" class="flex items-center justify-between">
                        <input type="hidden" name="csrf_token" />
                        <input type="hidden" name="user_uuid" value="{}" />
                        <div class="flex items-center space-x-3">
                            <div class="flex-shrink-0">
                                <span class="inline-flex h-8 w-8 items-center justify-center rounded-full bg-gray-500">
                                    <span class="text-xs font-medium leading-none text-white">{}</span>
                                </span>
                            </div>
                            <div>
                                <p class="text-sm font-medium text-gray-900 dark:text-white">{}</p>
                                <p class="text-xs text-gray-500 dark:text-gray-400">{}</p>
                            </div>
                        </div>
                        <button type="submit" class="inline-flex items-center rounded-md bg-vauban-600 px-2.5 py-1.5 text-xs font-semibold text-white shadow-sm hover:bg-vauban-500">
                            <svg class="-ml-0.5 mr-1 h-4 w-4" viewBox="0 0 20 20" fill="currentColor">
                                <path d="M10.75 4.75a.75.75 0 00-1.5 0v4.5h-4.5a.75.75 0 000 1.5h4.5v4.5a.75.75 0 001.5 0v-4.5h4.5a.75.75 0 000-1.5h-4.5v-4.5z"/>
                            </svg>
                            Add
                        </button>
                    </form>
                </div>"#,
                uuid_str, user_uuid, initial, username, email
            ));
        }
    }

    Ok(Html(html))
}

/// Add member to group handler (POST /accounts/groups/{uuid}/members).
pub async fn add_group_member_web(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
    Form(form): Form<AddGroupMemberForm>,
) -> Response {
    use crate::schema::user_groups::dsl as ug;
    use crate::schema::users::dsl as u;
    use crate::schema::vauban_groups::dsl as vg;

    let flash = incoming_flash.flash();

    // CSRF validation
    let csrf_cookie = jar.get(crate::middleware::csrf::CSRF_COOKIE_NAME);
    let secret = state.config.secret_key.expose_secret().as_bytes();
    if !crate::middleware::csrf::validate_double_submit(
        secret,
        csrf_cookie.map(|c| c.value()),
        &form.csrf_token,
    ) {
        return flash_redirect(
            flash.error("Invalid CSRF token. Please refresh the page and try again."),
            &format!("/accounts/groups/{}/members/add", uuid_str),
        );
    }

    // Permission check
    if !auth_user.is_superuser && !auth_user.is_staff {
        return flash_redirect(
            flash.error("You do not have permission to manage group members"),
            "/accounts/groups",
        );
    }

    let group_uuid = match ::uuid::Uuid::parse_str(&uuid_str) {
        Ok(uuid) => uuid,
        Err(_) => {
            return flash_redirect(flash.error("Invalid group identifier"), "/accounts/groups");
        }
    };

    let user_uuid = match ::uuid::Uuid::parse_str(&form.user_uuid) {
        Ok(uuid) => uuid,
        Err(_) => {
            return flash_redirect(
                flash.error("Invalid user identifier"),
                &format!("/accounts/groups/{}/members/add", uuid_str),
            );
        }
    };

    let mut conn = match state.db_pool.get().await {
        Ok(conn) => conn,
        Err(_) => {
            return flash_redirect(
                flash.error("Database connection error. Please try again."),
                &format!("/accounts/groups/{}/members/add", uuid_str),
            );
        }
    };

    // Get group ID
    let group_id: Option<i32> = vg::vauban_groups
        .filter(vg::uuid.eq(group_uuid))
        .select(vg::id)
        .first(&mut conn)
        .await
        .optional()
        .unwrap_or(None);

    let group_id = match group_id {
        Some(id) => id,
        None => {
            return flash_redirect(flash.error("Group not found"), "/accounts/groups");
        }
    };

    // Get user ID
    let user_id: Option<i32> = u::users
        .filter(u::uuid.eq(user_uuid))
        .filter(u::is_deleted.eq(false))
        .select(u::id)
        .first(&mut conn)
        .await
        .optional()
        .unwrap_or(None);

    let user_id = match user_id {
        Some(id) => id,
        None => {
            return flash_redirect(
                flash.error("User not found"),
                &format!("/accounts/groups/{}/members/add", uuid_str),
            );
        }
    };

    // Insert membership
    let result = diesel::insert_into(ug::user_groups)
        .values((ug::user_id.eq(user_id), ug::group_id.eq(group_id)))
        .execute(&mut conn)
        .await;

    match result {
        Ok(_) => flash_redirect(
            flash.success("Member added successfully"),
            &format!("/accounts/groups/{}", uuid_str),
        ),
        Err(diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::UniqueViolation,
            _,
        )) => flash_redirect(
            flash.error("User is already a member of this group"),
            &format!("/accounts/groups/{}/members/add", uuid_str),
        ),
        Err(_) => flash_redirect(
            flash.error("Failed to add member. Please try again."),
            &format!("/accounts/groups/{}/members/add", uuid_str),
        ),
    }
}

/// Remove member from group parameters.
#[derive(Debug, serde::Deserialize)]
pub struct RemoveMemberParams {
    pub group_uuid: String,
    pub user_uuid: String,
}

/// Remove member from group handler (POST /accounts/groups/{uuid}/members/{user_uuid}/remove).
pub async fn remove_group_member_web(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    axum::extract::Path((group_uuid_str, user_uuid_str)): axum::extract::Path<(String, String)>,
    Form(form): Form<DeleteAssetForm>,
) -> Response {
    use crate::schema::user_groups::dsl as ug;
    use crate::schema::users::dsl as u;
    use crate::schema::vauban_groups::dsl as vg;

    let flash = incoming_flash.flash();

    // CSRF validation
    let csrf_cookie = jar.get(crate::middleware::csrf::CSRF_COOKIE_NAME);
    let secret = state.config.secret_key.expose_secret().as_bytes();
    if !crate::middleware::csrf::validate_double_submit(
        secret,
        csrf_cookie.map(|c| c.value()),
        &form.csrf_token,
    ) {
        return flash_redirect(
            flash.error("Invalid CSRF token. Please refresh the page and try again."),
            &format!("/accounts/groups/{}", group_uuid_str),
        );
    }

    // Permission check
    if !auth_user.is_superuser && !auth_user.is_staff {
        return flash_redirect(
            flash.error("You do not have permission to manage group members"),
            "/accounts/groups",
        );
    }

    let group_uuid = match ::uuid::Uuid::parse_str(&group_uuid_str) {
        Ok(uuid) => uuid,
        Err(_) => {
            return flash_redirect(flash.error("Invalid group identifier"), "/accounts/groups");
        }
    };

    let user_uuid = match ::uuid::Uuid::parse_str(&user_uuid_str) {
        Ok(uuid) => uuid,
        Err(_) => {
            return flash_redirect(
                flash.error("Invalid user identifier"),
                &format!("/accounts/groups/{}", group_uuid_str),
            );
        }
    };

    let mut conn = match state.db_pool.get().await {
        Ok(conn) => conn,
        Err(_) => {
            return flash_redirect(
                flash.error("Database connection error. Please try again."),
                &format!("/accounts/groups/{}", group_uuid_str),
            );
        }
    };

    // Get group ID
    let group_id: Option<i32> = vg::vauban_groups
        .filter(vg::uuid.eq(group_uuid))
        .select(vg::id)
        .first(&mut conn)
        .await
        .optional()
        .unwrap_or(None);

    let group_id = match group_id {
        Some(id) => id,
        None => {
            return flash_redirect(flash.error("Group not found"), "/accounts/groups");
        }
    };

    // Get user ID
    let user_id: Option<i32> = u::users
        .filter(u::uuid.eq(user_uuid))
        .select(u::id)
        .first(&mut conn)
        .await
        .optional()
        .unwrap_or(None);

    let user_id = match user_id {
        Some(id) => id,
        None => {
            return flash_redirect(
                flash.error("User not found"),
                &format!("/accounts/groups/{}", group_uuid_str),
            );
        }
    };

    // Delete membership
    let result = diesel::delete(
        ug::user_groups
            .filter(ug::user_id.eq(user_id))
            .filter(ug::group_id.eq(group_id)),
    )
    .execute(&mut conn)
    .await;

    match result {
        Ok(0) => flash_redirect(
            flash.error("User is not a member of this group"),
            &format!("/accounts/groups/{}", group_uuid_str),
        ),
        Ok(_) => flash_redirect(
            flash.success("Member removed successfully"),
            &format!("/accounts/groups/{}", group_uuid_str),
        ),
        Err(_) => flash_redirect(
            flash.error("Failed to remove member. Please try again."),
            &format!("/accounts/groups/{}", group_uuid_str),
        ),
    }
}

/// Delete vauban group handler (POST /accounts/groups/{uuid}/delete).
///
/// A group can only be deleted if it has no members.
pub async fn delete_vauban_group_web(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
    Form(form): Form<DeleteAssetForm>,
) -> Response {
    use crate::schema::user_groups::dsl as ug;
    use crate::schema::vauban_groups::dsl as vg;

    let flash = incoming_flash.flash();

    // CSRF validation
    let csrf_cookie = jar.get(crate::middleware::csrf::CSRF_COOKIE_NAME);
    let secret = state.config.secret_key.expose_secret().as_bytes();
    if !crate::middleware::csrf::validate_double_submit(
        secret,
        csrf_cookie.map(|c| c.value()),
        &form.csrf_token,
    ) {
        return flash_redirect(
            flash.error("Invalid CSRF token. Please refresh the page and try again."),
            &format!("/accounts/groups/{}", uuid_str),
        );
    }

    // Only superuser can delete groups
    if !auth_user.is_superuser {
        return flash_redirect(
            flash.error("Only superusers can delete groups"),
            "/accounts/groups",
        );
    }

    let group_uuid = match ::uuid::Uuid::parse_str(&uuid_str) {
        Ok(uuid) => uuid,
        Err(_) => {
            return flash_redirect(flash.error("Invalid group identifier"), "/accounts/groups");
        }
    };

    let mut conn = match state.db_pool.get().await {
        Ok(conn) => conn,
        Err(_) => {
            return flash_redirect(
                flash.error("Database connection error. Please try again."),
                &format!("/accounts/groups/{}", uuid_str),
            );
        }
    };

    // Get group ID
    let group_id: Option<i32> = vg::vauban_groups
        .filter(vg::uuid.eq(group_uuid))
        .select(vg::id)
        .first(&mut conn)
        .await
        .optional()
        .unwrap_or(None);

    let group_id = match group_id {
        Some(id) => id,
        None => {
            return flash_redirect(flash.error("Group not found"), "/accounts/groups");
        }
    };

    // Check if group has members
    let member_count: i64 = ug::user_groups
        .filter(ug::group_id.eq(group_id))
        .count()
        .get_result(&mut conn)
        .await
        .unwrap_or(0);

    if member_count > 0 {
        return flash_redirect(
            flash.error(format!(
                "Cannot delete group: it still has {} member{}. Remove all members first.",
                member_count,
                if member_count == 1 { "" } else { "s" }
            )),
            &format!("/accounts/groups/{}", uuid_str),
        );
    }

    // Delete the group
    let result = diesel::delete(vg::vauban_groups.filter(vg::id.eq(group_id)))
        .execute(&mut conn)
        .await;

    match result {
        Ok(0) => flash_redirect(flash.error("Group not found"), "/accounts/groups"),
        Ok(_) => flash_redirect(
            flash.success("Group deleted successfully"),
            "/accounts/groups",
        ),
        Err(_) => flash_redirect(
            flash.error("Failed to delete group. Please try again."),
            &format!("/accounts/groups/{}", uuid_str),
        ),
    }
}

