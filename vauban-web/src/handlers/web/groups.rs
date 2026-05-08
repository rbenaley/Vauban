/// Vauban group management page handlers.
use super::*;
use shared::messages::VaubanGroupInfo as IpcVaubanGroupInfo;

/// Format RFC3339 date string to display format in the caller's timezone.
fn format_rfc3339_date(s: &str, tz: chrono_tz::Tz) -> String {
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|d| crate::utils::format_local(d.with_timezone(&chrono::Utc), tz))
        .unwrap_or_else(|| s.to_string())
}

/// Format RFC3339 date string to display format with time in the caller's timezone.
fn format_rfc3339_datetime(s: &str, tz: chrono_tz::Tz) -> String {
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|d| crate::utils::format_local(d.with_timezone(&chrono::Utc), tz))
        .unwrap_or_else(|| s.to_string())
}

pub async fn group_list(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    browser_tz: BrowserTz,
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse, AppError> {
    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new("Groups".to_string(), user.clone(), browser_tz.0)
        .with_current_path("/accounts/groups");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

    // Filter out empty strings - form sends empty string when search is cleared
    let search_filter = params.get("search").filter(|s| !s.is_empty()).cloned();

    let client = &state.access_client;
    let group_items: Vec<crate::templates::accounts::group_list::GroupListItem> = {
        let groups = client
            .list_vauban_groups()
            .await
            .map_err(|e| AppError::Internal(anyhow::anyhow!("IPC error: {}", e)))?;
        let mut items: Vec<_> = groups
            .into_iter()
            .map(
                |g: IpcVaubanGroupInfo| crate::templates::accounts::group_list::GroupListItem {
                    uuid: g.uuid,
                    name: g.name,
                    description: g.description,
                    source: g.source,
                    member_count: g.member_count,
                    created_at: format_rfc3339_date(&g.created_at, browser_tz.0),
                },
            )
            .collect();
        if let Some(ref s) = search_filter {
            let search_lower = s.to_lowercase();
            items.retain(|item| {
                item.name.to_lowercase().contains(&search_lower)
                    || item
                        .description
                        .as_ref()
                        .is_some_and(|d| d.to_lowercase().contains(&search_lower))
            });
        }
        items
    };

    const GROUPS_PER_PAGE: usize = 30;

    let page: usize = params
        .get("page")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(1)
        .max(1);

    let total_items = group_items.len();
    let total_pages = ((total_items as f64) / (GROUPS_PER_PAGE as f64))
        .ceil()
        .max(1.0) as usize;
    let page = page.min(total_pages);
    let offset = (page - 1) * GROUPS_PER_PAGE;
    let paged_items: Vec<_> = group_items
        .into_iter()
        .skip(offset)
        .take(GROUPS_PER_PAGE)
        .collect();

    use crate::templates::accounts::user_list::Pagination;

    let start_index = if total_items > 0 { offset + 1 } else { 0 };
    let end_index = (offset + GROUPS_PER_PAGE).min(total_items);

    let pagination = if total_items > 0 {
        Some(Pagination {
            current_page: page as i32,
            total_pages: total_pages as i32,
            total_items: total_items as i32,
            items_per_page: GROUPS_PER_PAGE as i32,
            has_previous: page > 1,
            has_next: page < total_pages,
            start_index: start_index as i32,
            end_index: end_index as i32,
        })
    } else {
        None
    };

    let template = GroupListTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        groups: paged_items,
        search: search_filter,
        pagination,
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
    browser_tz: BrowserTz,
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

    if ::uuid::Uuid::parse_str(&uuid_str).is_err() {
        return flash_redirect(flash.error("Invalid group identifier"), "/accounts/groups");
    }

    let client = &state.access_client;
    let group = {
        let group_info = match client.get_vauban_group(&uuid_str).await {
            Ok(g) => g,
            Err(_) => {
                return flash_redirect(flash.error("Group not found"), "/accounts/groups");
            }
        };
        let member_ids = client
            .list_group_members(group_info.id)
            .await
            .unwrap_or_default();

        let members: Vec<crate::templates::accounts::group_detail::GroupMember> =
            if member_ids.is_empty() {
                vec![]
            } else {
                let mut conn = match state.db_pool.get().await {
                    Ok(conn) => conn,
                    Err(_) => {
                        return flash_redirect(
                            flash.error("Database connection error. Please try again."),
                            "/accounts/groups",
                        );
                    }
                };
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
                    .filter(u::id.eq_any(&member_ids))
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
                members_data
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
                    .collect()
            };

        crate::templates::accounts::group_detail::GroupDetail {
            uuid: group_info.uuid,
            name: group_info.name.clone(),
            description: group_info.description,
            source: group_info.source,
            external_id: group_info.external_id,
            created_at: format_rfc3339_datetime(&group_info.created_at, browser_tz.0),
            updated_at: format_rfc3339_datetime(&group_info.updated_at, browser_tz.0),
            last_synced: group_info
                .last_synced
                .as_ref()
                .map(|s| format_rfc3339_datetime(s, browser_tz.0)),
            members,
        }
    };

    let base = BaseTemplate::new(format!("{} - Group", group.name), user.clone(), browser_tz.0)
        .with_current_path("/accounts/groups")
        .with_messages(flash_messages);
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

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

    // Flash cookie cleanup is handled centrally by `flash_middleware`
    // (see `vauban-web/src/middleware/flash.rs`).
    match template.render() {
        Ok(html) => Html(html).into_response(),
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
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    jar: CookieJar,
    browser_tz: BrowserTz,
) -> Result<impl IntoResponse, AppError> {
    use crate::templates::accounts::GroupCreateTemplate;

    if !perms.groups_write {
        return Err(AppError::forbidden("groups:write"));
    }

    // Get CSRF token from cookie
    let csrf_token = jar
        .get(crate::middleware::csrf::CSRF_COOKIE_NAME)
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    let user = Some(user_context_from_auth(&auth_user));
    let base =
        BaseTemplate::new("Create Group".to_string(), user, browser_tz.0)
            .with_current_path("/accounts/groups");

    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

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
    _auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    Form(form): Form<CreateGroupWebForm>,
) -> Response {
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

    if !perms.groups_write {
        return flash_redirect(
            flash.error("Insufficient privileges: groups:write required"),
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

    // Sanitize text fields to prevent stored XSS
    let sanitized_name = sanitize(&form.name);
    let sanitized_description = sanitize_opt(form.description.filter(|d| !d.trim().is_empty()));

    let client = &state.access_client;
    match client
        .create_vauban_group(&sanitized_name, sanitized_description.clone())
        .await
    {
        Ok(info) => flash_redirect(
            flash.success(format!("Group '{}' created successfully", sanitized_name)),
            &format!("/accounts/groups/{}", info.uuid),
        ),
        Err(e) => {
            let err_msg = e.to_string();
            let is_already_exists = err_msg.to_lowercase().contains("already exists")
                || err_msg.to_lowercase().contains("duplicate");
            flash_redirect(
                flash.error(if is_already_exists {
                    "A group with this name already exists"
                } else {
                    "Failed to create group. Please try again."
                }),
                "/accounts/groups/new",
            )
        }
    }
}

/// Vauban group edit form page (GET /accounts/groups/{uuid}/edit).
pub async fn vauban_group_edit_form(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    jar: CookieJar,
    browser_tz: BrowserTz,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
) -> Result<impl IntoResponse, AppError> {
    use crate::templates::accounts::{GroupEditData, GroupEditTemplate};

    if !perms.groups_write {
        return Err(AppError::forbidden("groups:write"));
    }

    // Get CSRF token from cookie
    let csrf_token = jar
        .get(crate::middleware::csrf::CSRF_COOKIE_NAME)
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    let client = &state.access_client;
    let info = client
        .get_vauban_group(&uuid_str)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("IPC error: {}", e)))?;
    let group = GroupEditData {
        uuid: info.uuid,
        name: info.name,
        description: info.description,
        source: info.source,
    };

    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new(format!("Edit {} - Group", group.name), user, browser_tz.0)
        .with_current_path("/accounts/groups");

    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

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
    _auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
    Form(form): Form<UpdateGroupWebForm>,
) -> Response {
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

    if !perms.groups_write {
        return flash_redirect(
            flash.error("Insufficient privileges: groups:write required"),
            "/accounts/groups",
        );
    }

    // Validate name
    if form.name.trim().is_empty() || form.name.len() > 100 {
        return flash_redirect(
            flash.error("Group name must be between 1 and 100 characters"),
            &format!("/accounts/groups/{}/edit", uuid_str),
        );
    }

    // Sanitize text fields to prevent stored XSS
    let sanitized_name = sanitize(form.name.trim());
    let sanitized_description =
        sanitize_opt_ref(form.description.as_ref().filter(|s| !s.is_empty()));

    let client = &state.access_client;
    match client
        .update_vauban_group(&uuid_str, &sanitized_name, sanitized_description)
        .await
    {
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
    perms: crate::auth::PermissionContext,
    browser_tz: BrowserTz,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
) -> Result<impl IntoResponse, AppError> {
    use crate::templates::accounts::{AvailableUser, GroupAddMemberTemplate, GroupInfo};

    if !perms.groups_manage_members {
        return Err(AppError::forbidden("groups:manage_members"));
    }

    let client = &state.access_client;
    let (group, available_users) = {
        let group_info = client
            .get_vauban_group(&uuid_str)
            .await
            .map_err(|e| AppError::Internal(anyhow::anyhow!("IPC error: {}", e)))?;
        let existing_member_ids = client
            .list_group_members(group_info.id)
            .await
            .unwrap_or_default();

        let mut conn = state
            .db_pool
            .get()
            .await
            .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;
        use crate::schema::users::dsl as u;
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
            uuid: group_info.uuid,
            name: group_info.name,
        };
        (group, available_users)
    };

    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new(format!("Add Member - {}", group.name), user, browser_tz.0)
        .with_current_path("/accounts/groups");

    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

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
        is_search: false,
    };

    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;
    Ok(Html(html))
}

/// Search users for adding to group (HTMX endpoint).
///
/// The HTMX response is rendered through the same Askama partial as the
/// initial page (`accounts/_group_add_member_list.html`), which:
///   - auto-escapes username/email (defense-in-depth XSS),
///   - opts each form into Alpine's `csrf` component so the
///     double-submit token is populated on submit (otherwise the empty
///     `csrf_token` would be rejected by `add_group_member_web`).
pub async fn group_member_search(
    State(state): State<AppState>,
    _auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse, AppError> {
    use crate::templates::accounts::{AvailableUser, GroupAddMemberListPartial, GroupInfo};

    if !perms.groups_manage_members {
        return Err(AppError::forbidden("groups:manage_members"));
    }

    let search_term = params.get("user-search").cloned().unwrap_or_default();

    let client = &state.access_client;
    let group_info = client
        .get_vauban_group(&uuid_str)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("IPC error: {}", e)))?;
    let existing_member_ids: Vec<i32> = client
        .list_group_members(group_info.id)
        .await
        .unwrap_or_default();

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;
    use crate::schema::users::dsl as u;
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
        let pattern = crate::db::like_contains(&search_term);
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

    let partial = GroupAddMemberListPartial {
        group: GroupInfo {
            uuid: group_info.uuid,
            name: group_info.name,
        },
        available_users: available_users_data
            .into_iter()
            .map(|(uuid, username, email)| AvailableUser {
                uuid: uuid.to_string(),
                username,
                email,
            })
            .collect(),
        is_search: true,
    };

    let html = partial
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;
    Ok(Html(html))
}

/// Add member to group handler (POST /accounts/groups/{uuid}/members).
pub async fn add_group_member_web(
    State(state): State<AppState>,
    _auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
    Form(form): Form<AddGroupMemberForm>,
) -> Response {
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

    if !perms.groups_manage_members {
        return flash_redirect(
            flash.error("Insufficient privileges: groups:manage_members required"),
            "/accounts/groups",
        );
    }

    if ::uuid::Uuid::parse_str(&uuid_str).is_err() {
        return flash_redirect(flash.error("Invalid group identifier"), "/accounts/groups");
    }

    let user_uuid = match ::uuid::Uuid::parse_str(&form.user_uuid) {
        Ok(uuid) => uuid,
        Err(_) => {
            return flash_redirect(
                flash.error("Invalid user identifier"),
                &format!("/accounts/groups/{}/members/add", uuid_str),
            );
        }
    };

    let client = &state.access_client;
    let group_info = match client.get_vauban_group(&uuid_str).await {
        Ok(g) => g,
        Err(_) => {
            return flash_redirect(flash.error("Group not found"), "/accounts/groups");
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
    use crate::schema::users::dsl as u;
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

    match client.add_group_member(group_info.id, user_id).await {
        Ok(_) => flash_redirect(
            flash.success("Member added successfully"),
            &format!("/accounts/groups/{}", uuid_str),
        ),
        Err(e) => {
            let err_msg = e.to_string();
            let is_already_member = err_msg.to_lowercase().contains("already")
                || err_msg.to_lowercase().contains("duplicate");
            flash_redirect(
                flash.error(if is_already_member {
                    "User is already a member of this group"
                } else {
                    "Failed to add member. Please try again."
                }),
                &format!("/accounts/groups/{}/members/add", uuid_str),
            )
        }
    }
}

/// Remove member from group parameters.
#[derive(Debug, serde::Deserialize)]
pub struct RemoveMemberParams {
    pub group_uuid: String,
    pub user_uuid: String,
}

/// Remove member from group handler (POST /accounts/groups/{uuid}/members/{user_uuid}/remove).
// Axum extractors compose the argument list; the new `perms` extractor
// pushes us one over the default clippy threshold.
#[allow(clippy::too_many_arguments)]
pub async fn remove_group_member_web(
    State(state): State<AppState>,
    _auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    headers: axum::http::HeaderMap,
    axum::extract::Path((group_uuid_str, user_uuid_str)): axum::extract::Path<(String, String)>,
    Form(form): Form<DeleteAssetForm>,
) -> Response {
    let flash = incoming_flash.flash();

    // BUG-12 / issue #19: HTMX-driven flow uses HX-Redirect — see
    // `htmx_or_flash_redirect` for the rationale.

    // CSRF validation
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
            &format!("/accounts/groups/{}", group_uuid_str),
        );
    }

    if !perms.groups_manage_members {
        return htmx_or_flash_redirect(
            &headers,
            flash.error("Insufficient privileges: groups:manage_members required"),
            "/accounts/groups",
        );
    }

    let user_uuid = match ::uuid::Uuid::parse_str(&user_uuid_str) {
        Ok(uuid) => uuid,
        Err(_) => {
            return htmx_or_flash_redirect(
                &headers,
                flash.error("Invalid user identifier"),
                &format!("/accounts/groups/{}", group_uuid_str),
            );
        }
    };

    let client = &state.access_client;
    let group_info = match client.get_vauban_group(&group_uuid_str).await {
        Ok(g) => g,
        Err(_) => {
            return htmx_or_flash_redirect(
                &headers,
                flash.error("Group not found"),
                "/accounts/groups",
            );
        }
    };

    let mut conn = match state.db_pool.get().await {
        Ok(conn) => conn,
        Err(_) => {
            return htmx_or_flash_redirect(
                &headers,
                flash.error("Database connection error. Please try again."),
                &format!("/accounts/groups/{}", group_uuid_str),
            );
        }
    };
    use crate::schema::users::dsl as u;
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
            return htmx_or_flash_redirect(
                &headers,
                flash.error("User not found"),
                &format!("/accounts/groups/{}", group_uuid_str),
            );
        }
    };

    match client.remove_group_member(group_info.id, user_id).await {
        Ok(_) => htmx_or_flash_redirect(
            &headers,
            flash.success("Member removed successfully"),
            &format!("/accounts/groups/{}", group_uuid_str),
        ),
        Err(_) => htmx_or_flash_redirect(
            &headers,
            flash.error("Failed to remove member. Please try again."),
            &format!("/accounts/groups/{}", group_uuid_str),
        ),
    }
}

/// Delete vauban group handler (POST /accounts/groups/{uuid}/delete).
///
/// A group can only be deleted if it has no members.
// Axum extractors compose the argument list; the new `perms` extractor
// pushes us one over the default clippy threshold.
#[allow(clippy::too_many_arguments)]
pub async fn delete_vauban_group_web(
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

    // BUG-12 / issue #19: HTMX-driven flow uses HX-Redirect — see
    // `htmx_or_flash_redirect` for the rationale.

    // CSRF validation
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
            &format!("/accounts/groups/{}", uuid_str),
        );
    }

    if !perms.groups_write {
        return htmx_or_flash_redirect(
            &headers,
            flash.error("Insufficient privileges: groups:write required"),
            "/accounts/groups",
        );
    }

    let client = &state.access_client;
    match client.delete_vauban_group(&uuid_str).await {
        Ok(_) => htmx_or_flash_redirect(
            &headers,
            flash.success("Group deleted successfully"),
            "/accounts/groups",
        ),
        Err(e) => {
            let err_msg = e.to_string();
            let has_members = err_msg.to_lowercase().contains("member")
                || err_msg.to_lowercase().contains("has ");
            let msg = if has_members {
                "Cannot delete group: it still has members. Remove all members first."
            } else {
                "Failed to delete group. Please try again."
            };
            htmx_or_flash_redirect(
                &headers,
                flash.error(msg),
                &format!("/accounts/groups/{}", uuid_str),
            )
        }
    }
}
