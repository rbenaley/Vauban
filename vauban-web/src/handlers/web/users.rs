/// User management page handlers.
use super::*;
use crate::models::user::AuthSource;

/// Validate a candidate password against the configured minimum length.
///
/// Centralises both the length check and the user-facing error wording so
/// the create-user, edit-user and self-rotation paths stay in lock-step
/// with whatever `security.password_min_length` a deployment configures
/// (the config file remains the single source of truth -- this helper
/// only avoids re-typing the same `if … { format!(…) }` in every
/// handler). The length policy itself is validated at boot in
/// `config.rs` (must be `>= 8`).
pub(crate) fn validate_password_length(pwd: &str, min_len: usize) -> Result<(), String> {
    if pwd.len() < min_len {
        Err(format!("Password must be at least {} characters", min_len))
    } else {
        Ok(())
    }
}

pub async fn user_list(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    browser_tz: BrowserTz,
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse, AppError> {
    use crate::schema::users;
    use crate::templates::accounts::user_list::UserListItem;

    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new("Users".to_string(), user.clone(), browser_tz.0)
        .with_current_path("/accounts/users");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

    // Load users from database
    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;

    // Filter out empty strings - form sends empty string when "All" is selected
    let search_filter = params.get("search").filter(|s| !s.is_empty()).cloned();
    let status_filter = params.get("status").filter(|s| !s.is_empty()).cloned();

    let mut query = users::table
        .filter(users::is_deleted.eq(false))
        .into_boxed();

    if let Some(ref search) = search_filter
        && !search.is_empty()
    {
        let pattern = crate::db::like_contains(search);
        query = query.filter(
            users::username
                .ilike(pattern.clone())
                .or(users::email.ilike(pattern.clone()))
                .or(users::first_name.ilike(pattern.clone()))
                .or(users::last_name.ilike(pattern)),
        );
    }

    if let Some(ref status) = status_filter {
        match status.as_str() {
            "active" => query = query.filter(users::is_active.eq(true)),
            "inactive" => query = query.filter(users::is_active.eq(false)),
            _ => {}
        }
    }

    const USERS_PER_PAGE: i64 = 30;

    let page: i32 = params
        .get("page")
        .and_then(|s| s.parse::<i32>().ok())
        .unwrap_or(1)
        .max(1);

    let mut count_query = users::table
        .filter(users::is_deleted.eq(false))
        .into_boxed();

    if let Some(ref search) = search_filter
        && !search.is_empty()
    {
        let pattern = crate::db::like_contains(search);
        count_query = count_query.filter(
            users::username
                .ilike(pattern.clone())
                .or(users::email.ilike(pattern.clone()))
                .or(users::first_name.ilike(pattern.clone()))
                .or(users::last_name.ilike(pattern)),
        );
    }

    if let Some(ref status) = status_filter {
        match status.as_str() {
            "active" => count_query = count_query.filter(users::is_active.eq(true)),
            "inactive" => count_query = count_query.filter(users::is_active.eq(false)),
            _ => {}
        }
    }

    let total_items: i64 = count_query.count().get_result(&mut conn).await.unwrap_or(0);

    let total_pages = ((total_items as f64) / (USERS_PER_PAGE as f64))
        .ceil()
        .max(1.0) as i32;
    let page = page.min(total_pages);
    let offset = ((page - 1) as i64) * USERS_PER_PAGE;

    #[allow(clippy::type_complexity)]
    let db_users: Vec<(
        uuid::Uuid,
        String,
        String,
        Option<String>,
        Option<String>,
        AuthSource,
        bool,
        bool,
        bool,
        bool,
        Option<chrono::DateTime<chrono::Utc>>,
    )> = query
        .select((
            users::uuid,
            users::username,
            users::email,
            users::first_name,
            users::last_name,
            users::auth_source,
            users::mfa_enabled,
            users::is_active,
            users::is_staff,
            users::is_superuser,
            users::last_login,
        ))
        .order(users::username.asc())
        .limit(USERS_PER_PAGE)
        .offset(offset)
        .load(&mut conn)
        .await?;

    let user_items: Vec<UserListItem> = db_users
        .into_iter()
        .map(
            |(
                user_uuid,
                username,
                email,
                first_name,
                last_name,
                auth_source,
                mfa_enabled,
                is_active,
                is_staff,
                is_superuser,
                last_login,
            )| {
                let full_name = match (first_name, last_name) {
                    (Some(f), Some(l)) => Some(format!("{} {}", f, l)),
                    (Some(f), None) => Some(f),
                    (None, Some(l)) => Some(l),
                    (None, None) => None,
                };
                UserListItem {
                    uuid: user_uuid.to_string(),
                    username,
                    email,
                    full_name,
                    auth_source: auth_source.to_string(),
                    mfa_enabled,
                    is_active,
                    is_staff,
                    is_superuser,
                    last_login: last_login.map(|dt| crate::utils::format_local(dt, browser_tz.0)),
                }
            },
        )
        .collect();

    use crate::templates::accounts::user_list::Pagination;

    let start_index = if total_items > 0 { offset + 1 } else { 0 };
    let end_index = (offset + USERS_PER_PAGE).min(total_items);

    let pagination = if total_items > 0 {
        Some(Pagination {
            current_page: page,
            total_pages,
            total_items: total_items as i32,
            items_per_page: USERS_PER_PAGE as i32,
            has_previous: page > 1,
            has_next: page < total_pages,
            start_index: start_index as i32,
            end_index: end_index as i32,
        })
    } else {
        None
    };

    let template = UserListTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        users: user_items,
        pagination,
        search: search_filter,
        status_filter,
    };

    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;
    Ok(Html(html))
}

/// User detail page.
pub async fn user_detail(
    State(state): State<AppState>,
    incoming_flash: IncomingFlash,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    browser_tz: BrowserTz,
    axum::extract::Path(user_uuid): axum::extract::Path<String>,
) -> Response {
    use crate::schema::users;
    use crate::templates::accounts::user_detail::UserDetail;

    let flash = incoming_flash.flash();

    let user = Some(user_context_from_auth(&auth_user));

    // UX-22: forward incoming flash messages to the BaseTemplate so the
    // PRG redirect target (this page) actually renders the success/error
    // banner emitted by `update_user_web`. Without this, the cookie is
    // present but the message is invisible to the administrator.
    let flash_messages: Vec<crate::templates::base::FlashMessage> = incoming_flash
        .messages()
        .iter()
        .map(|m| crate::templates::base::FlashMessage {
            level: m.level.clone(),
            message: m.message.clone(),
        })
        .collect();

    let base = BaseTemplate::new("User Details".to_string(), user, browser_tz.0)
        .with_current_path("/accounts/users")
        .with_messages(flash_messages);

    // Load user from database
    let mut conn = match state.db_pool.get().await {
        Ok(conn) => conn,
        Err(_) => {
            return flash_redirect(
                flash.error("Database connection error. Please try again."),
                "/accounts/users",
            );
        }
    };

    let parsed_uuid = match uuid::Uuid::parse_str(&user_uuid) {
        Ok(uuid) => uuid,
        Err(_) => {
            return flash_redirect(flash.error("Invalid user identifier"), "/accounts/users");
        }
    };

    #[allow(clippy::type_complexity)]
    let db_user: Option<(
        uuid::Uuid,
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        AuthSource,
        bool,
        bool,
        bool,
        bool,
        Option<chrono::DateTime<chrono::Utc>>,
        chrono::DateTime<chrono::Utc>,
    )> = match users::table
        .filter(users::uuid.eq(parsed_uuid))
        .filter(users::is_deleted.eq(false))
        .select((
            users::uuid,
            users::username,
            users::email,
            users::first_name,
            users::last_name,
            users::phone,
            users::auth_source,
            users::mfa_enabled,
            users::is_active,
            users::is_staff,
            users::is_superuser,
            users::last_login,
            users::created_at,
        ))
        .first(&mut conn)
        .await
        .optional()
    {
        Ok(user) => user,
        Err(_) => {
            return flash_redirect(
                flash.error("Database error. Please try again."),
                "/accounts/users",
            );
        }
    };

    let db_user = match db_user {
        Some(u) => u,
        None => {
            return flash_redirect(flash.error("User not found"), "/accounts/users");
        }
    };

    let (
        uuid,
        username,
        email,
        first_name,
        last_name,
        phone,
        auth_source,
        mfa_enabled,
        is_active,
        is_staff,
        is_superuser,
        last_login,
        created_at,
    ) = db_user;

    let full_name = match (&first_name, &last_name) {
        (Some(f), Some(l)) => Some(format!("{} {}", f, l)),
        (Some(f), None) => Some(f.clone()),
        (None, Some(l)) => Some(l.clone()),
        (None, None) => None,
    };

    let user_detail = UserDetail {
        uuid: uuid.to_string(),
        username,
        email,
        first_name,
        last_name,
        phone,
        full_name,
        is_active,
        is_staff,
        is_superuser,
        mfa_enabled,
        auth_source: auth_source.to_string(),
        last_login: last_login.map(|dt| crate::utils::format_local(dt, browser_tz.0)),
        created_at: crate::utils::format_local(created_at, browser_tz.0),
    };

    // Sourced from the request-scoped PermissionContext (Casbin via middleware)
    // instead of an ad-hoc `check_rbac` round-trip per request. Promotions /
    // edits of an existing superuser require `users:manage_admins`.
    let can_edit = perms.users_write && (!is_superuser || perms.users_manage_admins);

    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();
    let template = UserDetailTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        user_detail,
        can_edit,
    };

    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(_) => flash_redirect(flash.error("Failed to render page"), "/accounts/users"),
    }
}

// =============================================================================
// User Management (Create, Edit, Delete)
// =============================================================================

/// Form data for creating a user.
#[derive(Debug, serde::Deserialize)]
pub struct CreateUserWebForm {
    pub csrf_token: String,
    pub username: String,
    pub email: String,
    pub password: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub is_active: Option<String>,
    pub is_staff: Option<String>,
    pub is_superuser: Option<String>,
}

/// Form data for updating a user.
#[derive(Debug, serde::Deserialize)]
pub struct UpdateUserWebForm {
    pub csrf_token: String,
    pub username: String,
    pub email: String,
    pub password: Option<String>,
    /// Step-up MFA proof: the *operator's own* current TOTP code, required
    /// when (and only when) `password` is provided as a non-empty rotation
    /// request. The operator MUST have an enrolled TOTP factor; there is
    /// no password fallback. The code is verified against `auth_user.uuid`'s
    /// `mfa_secret`, NOT against the target's, and is single-use within its
    /// 30-second window (RFC 6238 §5.2 replay protection persisted via
    /// `users.last_totp_used_window`). See [`crate::auth::step_up`].
    pub totp_code: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub is_active: Option<String>,
    pub is_staff: Option<String>,
    pub is_superuser: Option<String>,
}

/// User create form page (GET /accounts/users/new).
pub async fn user_create_form(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    browser_tz: BrowserTz,
) -> Result<impl IntoResponse, AppError> {
    use crate::templates::accounts::UserCreateTemplate;

    if !perms.users_write {
        return Err(AppError::Authorization(
            "You do not have permission to create users".to_string(),
        ));
    }

    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new("New User".to_string(), user, browser_tz.0)
        .with_current_path("/accounts/users");

    let password_min_length = state.config.security.password_min_length;
    let can_manage_superusers = perms.users_manage_admins;

    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();
    let template = UserCreateTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        password_min_length,
        can_manage_superusers,
    };

    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;
    Ok(Html(html))
}

/// Create user handler (POST /accounts/users).
pub async fn create_user_web(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    Form(form): Form<CreateUserWebForm>,
) -> Response {
    use crate::schema::users;

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
            "/accounts/users/new",
        );
    }

    if !perms.users_write {
        return flash_redirect(
            flash.error("You do not have permission to create users"),
            "/accounts/users",
        );
    }

    let wants_superuser = form.is_superuser.as_deref() == Some("on");
    if wants_superuser && !perms.users_manage_admins {
        return flash_redirect(
            flash.error("Only a superuser can create superuser accounts"),
            "/accounts/users/new",
        );
    }

    // Validate username
    if form.username.len() < 3 || form.username.len() > 50 {
        return flash_redirect(
            flash.error("Username must be between 3 and 50 characters"),
            "/accounts/users/new",
        );
    }

    // Validate password length
    if let Err(msg) =
        validate_password_length(&form.password, state.config.security.password_min_length)
    {
        return flash_redirect(flash.error(msg), "/accounts/users/new");
    }

    let mut conn = match state.db_pool.get().await {
        Ok(conn) => conn,
        Err(_) => {
            return flash_redirect(
                flash.error("Database connection error. Please try again."),
                "/accounts/users/new",
            );
        }
    };

    // Check for duplicate username or email among active users
    let active_duplicate: Option<i32> = users::table
        .filter(
            users::username
                .eq(&form.username)
                .or(users::email.eq(&form.email)),
        )
        .filter(users::is_deleted.eq(false))
        .select(users::id)
        .first(&mut conn)
        .await
        .optional()
        .unwrap_or(None);

    if active_duplicate.is_some() {
        return flash_redirect(
            flash.error("Username or email already exists"),
            "/accounts/users/new",
        );
    }

    let password_hash = if let Some(ref client) = state.auth_ipc_client {
        match client.hash_password(&form.password).await {
            Ok(hash) => hash,
            Err(_) => {
                return flash_redirect(
                    flash.error("Failed to process password. Please try again."),
                    "/accounts/users/new",
                );
            }
        }
    } else {
        match state.auth_service.hash_password(&form.password) {
            Ok(hash) => hash,
            Err(_) => {
                return flash_redirect(
                    flash.error("Failed to process password. Please try again."),
                    "/accounts/users/new",
                );
            }
        }
    };

    let user_uuid = uuid::Uuid::new_v4();
    let is_active = form.is_active.as_deref() == Some("on");
    let is_staff = form.is_staff.as_deref() == Some("on");

    // Sanitize text fields to prevent stored XSS
    let sanitized_first_name = sanitize_opt(form.first_name.filter(|s| !s.is_empty()));
    let sanitized_last_name = sanitize_opt(form.last_name.filter(|s| !s.is_empty()));

    let result = diesel::insert_into(users::table)
        .values((
            users::uuid.eq(user_uuid),
            users::username.eq(&form.username),
            users::email.eq(&form.email),
            users::password_hash.eq(&password_hash),
            users::first_name.eq(&sanitized_first_name),
            users::last_name.eq(&sanitized_last_name),
            users::is_active.eq(is_active),
            users::is_staff.eq(is_staff),
            users::is_superuser.eq(wants_superuser),
            users::auth_source.eq(AuthSource::Local),
            users::preferences.eq(serde_json::json!({})),
        ))
        .execute(&mut conn)
        .await;

    match result {
        Ok(_) => {
            crate::services::emit_audit(
                &state,
                crate::ipc::AuditEvent::new(
                    shared::messages::AuditEventType::UserCreated,
                    format!(
                        r#"{{"target":"{}","is_staff":{},"is_superuser":{}}}"#,
                        user_uuid, is_staff, wants_superuser
                    ),
                )
                .user(auth_user.uuid.to_string()),
            );
            flash_redirect(
                flash.success(format!("User '{}' created successfully", form.username)),
                &format!("/accounts/users/{}", user_uuid),
            )
        }
        Err(e) => {
            tracing::error!(
                username = %form.username,
                error = %e,
                "Failed to insert user into database"
            );
            flash_redirect(
                flash.error("Failed to create user. Please try again."),
                "/accounts/users/new",
            )
        }
    }
}

/// User edit form page (GET /accounts/users/{uuid}/edit).
pub async fn user_edit_form(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    browser_tz: BrowserTz,
    axum::extract::Path(user_uuid): axum::extract::Path<String>,
) -> Response {
    use crate::schema::users;
    use crate::templates::accounts::{UserEditData, UserEditTemplate};

    let flash = incoming_flash.flash();

    if !perms.users_write {
        return flash_redirect(
            flash.error("You do not have permission to edit users"),
            "/accounts/users",
        );
    }

    let parsed_uuid = match uuid::Uuid::parse_str(&user_uuid) {
        Ok(uuid) => uuid,
        Err(_) => {
            return flash_redirect(flash.error("Invalid user identifier"), "/accounts/users");
        }
    };

    let mut conn = match state.db_pool.get().await {
        Ok(conn) => conn,
        Err(_) => {
            return flash_redirect(
                flash.error("Database connection error. Please try again."),
                "/accounts/users",
            );
        }
    };

    #[allow(clippy::type_complexity)]
    let db_user: Option<(
        uuid::Uuid,
        String,
        String,
        Option<String>,
        Option<String>,
        bool,
        bool,
        bool,
    )> = match users::table
        .filter(users::uuid.eq(parsed_uuid))
        .filter(users::is_deleted.eq(false))
        .select((
            users::uuid,
            users::username,
            users::email,
            users::first_name,
            users::last_name,
            users::is_active,
            users::is_staff,
            users::is_superuser,
        ))
        .first(&mut conn)
        .await
        .optional()
    {
        Ok(user) => user,
        Err(_) => {
            return flash_redirect(
                flash.error("Database error. Please try again."),
                "/accounts/users",
            );
        }
    };

    let db_user = match db_user {
        Some(u) => u,
        None => {
            return flash_redirect(flash.error("User not found"), "/accounts/users");
        }
    };

    let (uuid, username, email, first_name, last_name, is_active, is_staff, is_superuser) = db_user;

    // Editing or viewing the edit form for an existing superuser requires
    // `users:manage_admins`; staff with mere `users:write` cannot escalate
    // through this entry point.
    if is_superuser && !perms.users_manage_admins {
        return flash_redirect(
            flash.error("Only a superuser can edit superuser accounts"),
            &format!("/accounts/users/{}", user_uuid),
        );
    }

    let user_data = UserEditData {
        uuid: uuid.to_string(),
        username,
        email,
        first_name,
        last_name,
        is_active,
        is_staff,
        is_superuser,
    };

    let password_min_length = state.config.security.password_min_length;
    let can_manage_superusers = perms.users_manage_admins;
    // Sourced from the request-scoped PermissionContext (Casbin via middleware).
    let can_delete = perms.users_write && (!is_superuser || perms.users_manage_admins);

    // Whether the OPERATOR (not the target) has a usable TOTP factor enrolled.
    // Drives the enrollment banner in the template; a `false` value disables
    // the password input and the delete button. The handlers enforce the same
    // gate server-side via `crate::auth::step_up`.
    let auth_user_has_mfa: bool = match uuid::Uuid::parse_str(&auth_user.uuid) {
        Ok(op_uuid) => users::table
            .filter(users::uuid.eq(op_uuid))
            .filter(users::is_deleted.eq(false))
            .select((users::mfa_enabled, users::mfa_secret))
            .first::<(bool, Option<String>)>(&mut conn)
            .await
            .map(|(enabled, secret)| enabled && secret.is_some_and(|s| !s.is_empty()))
            .unwrap_or(false),
        Err(_) => false,
    };

    let user = Some(user_context_from_auth(&auth_user));

    // UX-22: forward incoming flash messages so password validation errors
    // (e.g. "Password must be at least N characters") and CSRF / DB errors
    // raised by `update_user_web` are actually displayed when the user is
    // bounced back to the edit form.
    let flash_messages: Vec<crate::templates::base::FlashMessage> = incoming_flash
        .messages()
        .iter()
        .map(|m| crate::templates::base::FlashMessage {
            level: m.level.clone(),
            message: m.message.clone(),
        })
        .collect();

    let base = BaseTemplate::new("Edit User".to_string(), user, browser_tz.0)
        .with_current_path("/accounts/users")
        .with_messages(flash_messages);

    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();
    let template = UserEditTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        user_data,
        password_min_length,
        can_manage_superusers,
        can_delete,
        auth_user_has_mfa,
    };

    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(_) => flash_redirect(flash.error("Failed to render page"), "/accounts/users"),
    }
}

/// Update user handler (POST /accounts/users/{uuid}).
///
/// Role-invariant fence (see [`crate::services::role_invariants`]):
///
/// * **Self-demotion** is refused up-front by [`check_self_change`]: an
///   operator cannot remove their own `is_superuser`/`is_staff` flag or
///   deactivate their own row through this handler. Casbin already
///   refuses some of these (staff cannot edit a superuser at all), but
///   nothing in Casbin stops a superuser from deleting their own
///   privileges and locking the platform out.
/// * **Last-active-superuser** is enforced inside a SERIALIZABLE
///   transaction that wraps the in-tx snapshot read,
///   [`check_last_active_superuser`] and the actual `UPDATE`. Two
///   operators racing to demote the last two superusers cannot both
///   succeed: at most one commits, the second sees the post-commit
///   snapshot and is rejected (or retried, then rejected). Without
///   SERIALIZABLE this would be a TOCTOU window between the count and
///   the update.
pub async fn update_user_web(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    axum::extract::Path(user_uuid): axum::extract::Path<String>,
    Form(form): Form<UpdateUserWebForm>,
) -> Response {
    use crate::schema::users;
    use crate::services::role_invariants::{
        ChangeIntent, CheckError, RoleSnapshot, check_last_active_superuser, check_self_change,
        run_serializable,
    };
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
            &format!("/accounts/users/{}/edit", user_uuid),
        );
    }

    if !perms.users_write {
        return flash_redirect(
            flash.error("You do not have permission to edit users"),
            "/accounts/users",
        );
    }

    let parsed_uuid = match uuid::Uuid::parse_str(&user_uuid) {
        Ok(uuid) => uuid,
        Err(_) => {
            return flash_redirect(flash.error("Invalid user identifier"), "/accounts/users");
        }
    };

    // Operator UUID is parsed once for the self-change pure check below.
    // The middleware guarantees `auth_user.uuid` is always a valid UUID
    // string (it loads it from the same DB column we will compare to);
    // a parse failure here would mean the auth state is corrupted and
    // we treat that as a hard refusal rather than silently letting the
    // self-check pass.
    let operator_uuid = match uuid::Uuid::parse_str(&auth_user.uuid) {
        Ok(u) => u,
        Err(_) => {
            return flash_redirect(
                flash.error("Invalid session"),
                &format!("/accounts/users/{}/edit", user_uuid),
            );
        }
    };

    let mut conn = match state.db_pool.get().await {
        Ok(conn) => conn,
        Err(_) => {
            return flash_redirect(
                flash.error("Database connection error. Please try again."),
                &format!("/accounts/users/{}/edit", user_uuid),
            );
        }
    };

    // Get current user data to check permissions and detect is_active changes
    let current_user: Option<(i32, bool, bool, bool)> = users::table
        .filter(users::uuid.eq(parsed_uuid))
        .filter(users::is_deleted.eq(false))
        .select((
            users::id,
            users::is_superuser,
            users::is_staff,
            users::is_active,
        ))
        .first(&mut conn)
        .await
        .optional()
        .unwrap_or(None);

    let (user_id, target_is_superuser, target_is_staff, old_is_active) = match current_user {
        Some(u) => u,
        None => {
            return flash_redirect(flash.error("User not found"), "/accounts/users");
        }
    };

    if target_is_superuser && !perms.users_manage_admins {
        return flash_redirect(
            flash.error("Only a superuser can edit superuser accounts"),
            &format!("/accounts/users/{}", user_uuid),
        );
    }

    let wants_superuser = form.is_superuser.as_deref() == Some("on");
    if wants_superuser && !perms.users_manage_admins {
        return flash_redirect(
            flash.error("Only a superuser can grant superuser privileges"),
            &format!("/accounts/users/{}/edit", user_uuid),
        );
    }

    let is_active = form.is_active.as_deref() == Some("on");
    let is_staff = form.is_staff.as_deref() == Some("on");

    // Self-change check (role-invariants). Pure, no DB. Fences out
    // self-demote / self-deactivate before any expensive validation or
    // side effect runs. Self-delete is unreachable from this edit
    // handler (see `delete_user_web` for that case) so we pass
    // `intent_delete = false` here.
    let before = RoleSnapshot {
        is_superuser: target_is_superuser,
        is_staff: target_is_staff,
        is_active: old_is_active,
        is_deleted: false,
    };
    let after = RoleSnapshot {
        is_superuser: wants_superuser,
        is_staff,
        is_active,
        is_deleted: false,
    };
    if let Err(violation) = check_self_change(operator_uuid, parsed_uuid, &before, &after, false) {
        tracing::info!(
            operator = %auth_user.uuid,
            target = %user_uuid,
            violation = ?violation,
            "update_user_web: refused self-demotion"
        );
        return flash_redirect(
            flash.error(violation.flash_message()),
            &format!("/accounts/users/{}/edit", user_uuid),
        );
    }

    // Validate username
    if form.username.len() < 3 || form.username.len() > 50 {
        return flash_redirect(
            flash.error("Username must be between 3 and 50 characters"),
            &format!("/accounts/users/{}/edit", user_uuid),
        );
    }

    // Check for duplicate username or email (excluding current user, active only)
    let active_duplicate: Option<i32> = users::table
        .filter(
            users::username
                .eq(&form.username)
                .or(users::email.eq(&form.email)),
        )
        .filter(users::id.ne(user_id))
        .filter(users::is_deleted.eq(false))
        .select(users::id)
        .first(&mut conn)
        .await
        .optional()
        .unwrap_or(None);

    if active_duplicate.is_some() {
        return flash_redirect(
            flash.error("Username or email already exists"),
            &format!("/accounts/users/{}/edit", user_uuid),
        );
    }

    // Validate and hash new password if provided
    let password_hash = if let Some(ref password) = form.password {
        if !password.is_empty() {
            if let Err(msg) =
                validate_password_length(password, state.config.security.password_min_length)
            {
                return flash_redirect(
                    flash.error(msg),
                    &format!("/accounts/users/{}/edit", user_uuid),
                );
            }

            // Step-up MFA: the OPERATOR (auth_user) MUST prove possession
            // of their second factor before any password is rotated --
            // their own or someone else's. This protects against hijacked
            // browser sessions silently flipping credentials and, unlike a
            // password re-prompt, works uniformly for federated accounts
            // and is forward-compatible with Passkeys/itsme/eID. The code
            // is single-use within its 30-second window so an intercepted
            // code cannot be replayed on another sensitive op. See
            // [`crate::auth::step_up`] for the full contract.
            let totp_code = form.totp_code.as_deref().unwrap_or("");
            let edit_url = format!("/accounts/users/{}/edit", user_uuid);
            if let Err(err) =
                crate::auth::enforce_totp_step_up(&state, &mut conn, &auth_user.uuid, totp_code)
                    .await
            {
                tracing::info!(
                    operator = %auth_user.uuid,
                    target = %user_uuid,
                    error = ?err,
                    "update_user_web: step-up MFA rejected, refusing password rotation"
                );
                return flash_redirect(flash.error(err.flash_message()), &edit_url);
            }

            let h = if let Some(ref client) = state.auth_ipc_client {
                client.hash_password(password).await
            } else {
                state.auth_service.hash_password(password)
            };
            match h {
                Ok(hash) => Some(hash),
                Err(_) => {
                    return flash_redirect(
                        flash.error("Failed to process password. Please try again."),
                        &format!("/accounts/users/{}/edit", user_uuid),
                    );
                }
            }
        } else {
            None
        }
    } else {
        None
    };

    let now = Utc::now();

    // Sanitize text fields to prevent stored XSS
    let sanitized_first_name = sanitize_opt_ref(form.first_name.as_ref().filter(|s| !s.is_empty()));
    let sanitized_last_name = sanitize_opt_ref(form.last_name.as_ref().filter(|s| !s.is_empty()));

    // Drop the pre-tx connection: `run_serializable` checks one out of
    // its own (potentially different to allow proper isolation) and
    // holding two simultaneously would deadlock under sustained load
    // when the pool is at its `max_connections` cap.
    drop(conn);

    // Run the UPDATE inside a SERIALIZABLE transaction so the in-tx
    // count(other active superusers) and the UPDATE form one atomic
    // unit. Two concurrent demotions of two different last superusers
    // cannot both succeed: SERIALIZABLE detects the rw-dependency cycle
    // and the loser is either retried (and re-checked against the new
    // post-commit state) or returned with `LastActiveSuperuserDemote`.
    let pool_ref = &state.db_pool;
    let form_ref = &form;
    let pwd_ref = &password_hash;
    let sf_ref = &sanitized_first_name;
    let sl_ref = &sanitized_last_name;
    let tx_outcome = run_serializable::<bool, _>(pool_ref, move |c| {
        let username = form_ref.username.clone();
        let email = form_ref.email.clone();
        let first_name = sf_ref.clone();
        let last_name = sl_ref.clone();
        let password_hash_owned = pwd_ref.clone();
        Box::pin(async move {
            // Re-read the target inside the SERIALIZABLE snapshot so the
            // count we are about to take and the row we are about to
            // update agree on what "before" was. A concurrent committed
            // demote between the pre-tx read and now is invisible until
            // the next snapshot, but that is exactly what SERIALIZABLE
            // will detect at commit time.
            let row: Option<(i32, bool, bool, bool, bool)> = users::table
                .filter(users::uuid.eq(parsed_uuid))
                .filter(users::is_deleted.eq(false))
                .select((
                    users::id,
                    users::is_superuser,
                    users::is_staff,
                    users::is_active,
                    users::is_deleted,
                ))
                .first(c)
                .await
                .optional()
                .map_err(CheckError::Db)?;
            let (in_tx_id, b_super, b_staff, b_active, b_deleted) = match row {
                Some(t) => t,
                None => {
                    // Target disappeared between the pre-tx read and
                    // the SERIALIZABLE snapshot: bail out cleanly. The
                    // UPDATE would have been a no-op anyway.
                    return Ok(false);
                }
            };
            let in_tx_before = RoleSnapshot {
                is_superuser: b_super,
                is_staff: b_staff,
                is_active: b_active,
                is_deleted: b_deleted,
            };

            // Determine intent purely from in-tx state vs form. The
            // outside-tx `before` cannot be trusted here: it might be
            // stale by one committed write.
            let intent = if in_tx_before.is_superuser && in_tx_before.is_active {
                if !wants_superuser {
                    Some(ChangeIntent::Demote)
                } else if !is_active {
                    Some(ChangeIntent::Deactivate)
                } else {
                    None
                }
            } else {
                None
            };
            if let Some(intent) = intent {
                check_last_active_superuser(c, in_tx_id, &in_tx_before, intent).await?;
            }

            if let Some(ref hash) = password_hash_owned {
                diesel::update(users::table.filter(users::id.eq(in_tx_id)))
                    .set((
                        users::username.eq(&username),
                        users::email.eq(&email),
                        users::password_hash.eq(hash),
                        users::first_name.eq(&first_name),
                        users::last_name.eq(&last_name),
                        users::is_active.eq(is_active),
                        users::is_staff.eq(is_staff),
                        users::is_superuser.eq(wants_superuser),
                        users::updated_at.eq(now),
                    ))
                    .execute(c)
                    .await
                    .map_err(CheckError::Db)?;
            } else {
                diesel::update(users::table.filter(users::id.eq(in_tx_id)))
                    .set((
                        users::username.eq(&username),
                        users::email.eq(&email),
                        users::first_name.eq(&first_name),
                        users::last_name.eq(&last_name),
                        users::is_active.eq(is_active),
                        users::is_staff.eq(is_staff),
                        users::is_superuser.eq(wants_superuser),
                        users::updated_at.eq(now),
                    ))
                    .execute(c)
                    .await
                    .map_err(CheckError::Db)?;
            }
            Ok(true)
        })
    })
    .await;

    match tx_outcome {
        Ok(true) => {
            // Audit: role/privilege change is a privileged escalation -> emit
            // critical (durable ack) so it is never lost; fail the request
            // closed if the audit log cannot record it.
            let role_changed =
                target_is_superuser != wants_superuser || target_is_staff != is_staff;
            if role_changed
                && let Err(e) = crate::services::emit_audit_critical(
                    &state,
                    crate::ipc::AuditEvent::new(
                        shared::messages::AuditEventType::RoleChanged,
                        format!(
                            r#"{{"target":"{}","is_staff":{},"is_superuser":{}}}"#,
                            user_uuid, is_staff, wants_superuser
                        ),
                    )
                    .user(auth_user.uuid.to_string()),
                )
                .await
            {
                tracing::error!(error = %e, "update_user_web: critical audit emit failed");
                return flash_redirect(
                    flash.error("Audit log unavailable; change not recorded. Please retry."),
                    &format!("/accounts/users/{}/edit", user_uuid),
                );
            }
            // Activation transitions + a general update record (fire-and-forget).
            if old_is_active != is_active {
                let ev = if is_active {
                    shared::messages::AuditEventType::UserActivated
                } else {
                    shared::messages::AuditEventType::UserDeactivated
                };
                crate::services::emit_audit(
                    &state,
                    crate::ipc::AuditEvent::new(ev, format!(r#"{{"target":"{}"}}"#, user_uuid))
                        .user(auth_user.uuid.to_string()),
                );
            }
            if password_hash.is_some() {
                crate::services::emit_audit(
                    &state,
                    crate::ipc::AuditEvent::new(
                        shared::messages::AuditEventType::PasswordChanged,
                        format!(r#"{{"target":"{}","by":"admin"}}"#, user_uuid),
                    )
                    .user(auth_user.uuid.to_string()),
                );
            }
            crate::services::emit_audit(
                &state,
                crate::ipc::AuditEvent::new(
                    shared::messages::AuditEventType::UserUpdated,
                    format!(r#"{{"target":"{}"}}"#, user_uuid),
                )
                .user(auth_user.uuid.to_string()),
            );
            // Trigger side effects on is_active change (SEC-07).
            // These are best-effort, fire-and-forget side channels
            // (revoke active sessions, broadcast deactivation) and
            // therefore intentionally outside the SERIALIZABLE tx --
            // running them inside would extend the lock window for no
            // correctness benefit (the tx already committed when we
            // get here).
            if old_is_active && !is_active {
                deactivate_user(&state, user_id, &user_uuid).await;
            } else if !old_is_active && is_active {
                reactivate_user(&state, user_id).await;
            }
            // UX-22: emit a transactional confirmation that explicitly mentions
            // the password when it was rotated, so administrators get an
            // unambiguous signal that the credential change took effect.
            let success_msg = if password_hash.is_some() {
                "User and password updated successfully"
            } else {
                "User updated successfully"
            };
            flash_redirect(
                flash.success(success_msg),
                &format!("/accounts/users/{}", user_uuid),
            )
        }
        Ok(false) => flash_redirect(flash.error("User not found"), "/accounts/users"),
        Err(CheckError::Violation(violation)) => {
            tracing::info!(
                operator = %auth_user.uuid,
                target = %user_uuid,
                violation = ?violation,
                "update_user_web: refused last-active-superuser mutation"
            );
            flash_redirect(
                flash.error(violation.flash_message()),
                &format!("/accounts/users/{}/edit", user_uuid),
            )
        }
        Err(CheckError::Db(_)) => flash_redirect(
            flash.error("Failed to update user. Please try again."),
            &format!("/accounts/users/{}/edit", user_uuid),
        ),
    }
}

/// Form payload for deleting a user.
///
/// Like password rotation, deletion is a sensitive operation gated by a
/// fresh step-up TOTP proof from the operator (issue #11). The same
/// single-use replay protection applies (`users.last_totp_used_window`).
#[derive(Debug, serde::Deserialize)]
pub struct DeleteUserForm {
    pub csrf_token: String,
    /// Step-up MFA proof, required. The operator MUST have an enrolled
    /// TOTP factor; there is no fallback.
    pub totp_code: Option<String>,
}

/// Delete user handler (POST /accounts/users/{uuid}/delete).
/// Web only - not available via API.
///
/// Role-invariant fence (see [`crate::services::role_invariants`]):
///
/// * **Self-delete** is always refused, even for a superuser. There is
///   no legitimate use case for it (the operator can be deleted by a
///   peer superuser) and allowing it would be a one-click way to lose
///   the operator's own session, audit context, and -- if the operator
///   was the last active superuser -- the entire admin floor.
/// * **Last-active-superuser** deletion is refused. The previous
///   `count() then update()` pair was a TOCTOU window; both are now
///   inside a SERIALIZABLE transaction so two concurrent deletes of
///   the last two superusers cannot both succeed.
pub async fn delete_user_web(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    axum::extract::Path(user_uuid): axum::extract::Path<String>,
    Form(form): Form<DeleteUserForm>,
) -> Response {
    use crate::schema::users;
    use crate::services::role_invariants::{
        ChangeIntent, CheckError, RoleSnapshot, check_last_active_superuser, check_self_change,
        run_serializable,
    };
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
            &format!("/accounts/users/{}", user_uuid),
        );
    }

    if !perms.users_write {
        return flash_redirect(
            flash.error("You do not have permission to delete users"),
            "/accounts/users",
        );
    }

    let parsed_uuid = match uuid::Uuid::parse_str(&user_uuid) {
        Ok(uuid) => uuid,
        Err(_) => {
            return flash_redirect(flash.error("Invalid user identifier"), "/accounts/users");
        }
    };

    // Operator UUID for the self-change pure check below. Same
    // hardening as in `update_user_web`: a corrupted auth state means
    // hard refusal.
    let operator_uuid = match uuid::Uuid::parse_str(&auth_user.uuid) {
        Ok(u) => u,
        Err(_) => {
            return flash_redirect(
                flash.error("Invalid session"),
                &format!("/accounts/users/{}", user_uuid),
            );
        }
    };

    let mut conn = match state.db_pool.get().await {
        Ok(conn) => conn,
        Err(_) => {
            return flash_redirect(
                flash.error("Database connection error. Please try again."),
                &format!("/accounts/users/{}", user_uuid),
            );
        }
    };

    // Get target user data
    let target_user: Option<(i32, bool, bool, bool)> = users::table
        .filter(users::uuid.eq(parsed_uuid))
        .filter(users::is_deleted.eq(false))
        .select((
            users::id,
            users::is_superuser,
            users::is_staff,
            users::is_active,
        ))
        .first(&mut conn)
        .await
        .optional()
        .unwrap_or(None);

    let (user_id, target_is_superuser, target_is_staff, target_is_active) = match target_user {
        Some(u) => u,
        None => {
            return flash_redirect(
                flash.error("User not found or already deleted"),
                "/accounts/users",
            );
        }
    };

    if target_is_superuser && !perms.users_manage_admins {
        return flash_redirect(
            flash.error("Only a superuser can delete another superuser"),
            &format!("/accounts/users/{}", user_uuid),
        );
    }

    // Self-delete is always refused, regardless of permissions. The
    // operator can never delete their own account through this
    // handler. Casbin already has the role to do it, but the role
    // invariants forbid it irrespective of role.
    let snap = RoleSnapshot {
        is_superuser: target_is_superuser,
        is_staff: target_is_staff,
        is_active: target_is_active,
        is_deleted: false,
    };
    if let Err(violation) = check_self_change(operator_uuid, parsed_uuid, &snap, &snap, true) {
        tracing::info!(
            operator = %auth_user.uuid,
            target = %user_uuid,
            violation = ?violation,
            "delete_user_web: refused self-delete"
        );
        return flash_redirect(
            flash.error(violation.flash_message()),
            &format!("/accounts/users/{}", user_uuid),
        );
    }

    // Step-up MFA: deletion is irreversible (modulo the soft-delete fence
    // below) and therefore gated on a fresh TOTP proof from the OPERATOR,
    // not the target. Same contract as password rotation in
    // `update_user_web`. The proof is single-use across concurrent
    // requests within its 30-second window.
    let totp_code = form.totp_code.as_deref().unwrap_or("");
    let detail_url = format!("/accounts/users/{}", user_uuid);
    if let Err(err) =
        crate::auth::enforce_totp_step_up(&state, &mut conn, &auth_user.uuid, totp_code).await
    {
        tracing::info!(
            operator = %auth_user.uuid,
            target = %user_uuid,
            error = ?err,
            "delete_user_web: step-up MFA rejected, refusing deletion"
        );
        return flash_redirect(flash.error(err.flash_message()), &detail_url);
    }

    // Drop the pre-tx connection before entering `run_serializable`:
    // holding two simultaneously would deadlock under sustained load
    // when the pool is at its `max_connections` cap.
    drop(conn);

    // Soft-delete inside a SERIALIZABLE transaction. The previous
    // implementation did `count(active superusers) then UPDATE` outside
    // any transaction, which was a TOCTOU window: two operators each
    // counting "2 active superusers" then each soft-deleting one of
    // them ended up with zero superusers. The SERIALIZABLE wrap
    // collapses that race.
    let pool_ref = &state.db_pool;
    let tx_outcome = run_serializable::<bool, _>(pool_ref, move |c| {
        Box::pin(async move {
            // Re-read inside the snapshot so the count and the update
            // agree on what "before" was.
            let row: Option<(i32, String, String, bool, bool, bool)> = users::table
                .filter(users::uuid.eq(parsed_uuid))
                .filter(users::is_deleted.eq(false))
                .select((
                    users::id,
                    users::username,
                    users::email,
                    users::is_superuser,
                    users::is_staff,
                    users::is_active,
                ))
                .first(c)
                .await
                .optional()
                .map_err(CheckError::Db)?;
            let (in_tx_id, current_username, current_email, b_super, b_staff, b_active) = match row
            {
                Some(t) => t,
                None => return Ok(false),
            };
            let in_tx_before = RoleSnapshot {
                is_superuser: b_super,
                is_staff: b_staff,
                is_active: b_active,
                is_deleted: false,
            };

            // Last-active-superuser fence. Only relevant when the
            // target is currently a usable superuser (non-superusers
            // and inactive ones don't count toward the minimum).
            check_last_active_superuser(c, in_tx_id, &in_tx_before, ChangeIntent::Delete).await?;

            // Soft-delete: mark as deleted and retire username/email
            // so the UNIQUE constraints are freed for future reuse
            // while preserving audit history.
            let now = Utc::now();
            let suffix = format!("_deleted_{}", now.timestamp_millis());
            diesel::update(users::table.filter(users::id.eq(in_tx_id)))
                .set((
                    users::is_deleted.eq(true),
                    users::deleted_at.eq(now),
                    users::updated_at.eq(now),
                    users::username.eq(format!("{}{}", current_username, suffix)),
                    users::email.eq(format!("{}{}", current_email, suffix)),
                ))
                .execute(c)
                .await
                .map_err(CheckError::Db)?;
            Ok(true)
        })
    })
    .await;

    let _ = user_id; // user_id was only needed for permission gating above

    match tx_outcome {
        Ok(true) => {
            // Audit: user deletion is destructive -> critical (durable ack).
            if let Err(e) = crate::services::emit_audit_critical(
                &state,
                crate::ipc::AuditEvent::new(
                    shared::messages::AuditEventType::UserDeleted,
                    format!(r#"{{"target":"{}"}}"#, user_uuid),
                )
                .user(auth_user.uuid.to_string()),
            )
            .await
            {
                tracing::error!(error = %e, "delete_user_web: critical audit emit failed");
            }
            flash_redirect(
                flash.success("User deleted successfully"),
                "/accounts/users",
            )
        }
        Ok(false) => flash_redirect(
            flash.error("User not found or already deleted"),
            "/accounts/users",
        ),
        Err(CheckError::Violation(violation)) => {
            tracing::info!(
                operator = %auth_user.uuid,
                target = %user_uuid,
                violation = ?violation,
                "delete_user_web: refused last-active-superuser delete"
            );
            flash_redirect(
                flash.error(violation.flash_message()),
                &format!("/accounts/users/{}", user_uuid),
            )
        }
        Err(CheckError::Db(_)) => flash_redirect(
            flash.error("Failed to delete user. Please try again."),
            &format!("/accounts/users/{}", user_uuid),
        ),
    }
}

/// Form data for the "Change Password" modal opened from `/accounts/profile`.
///
/// Unlike [`UpdateUserWebForm`], this is the *self-service* path: the user is
/// rotating *their own* password without going through the Edit User screen
/// (which is admin-oriented, gated on `users:write`, and asks for a lot of
/// other fields). The flow stays on `/accounts/profile` thanks to a Post/
/// Redirect/Get round-trip back to the same page with a flash banner; no
/// separate `/accounts/password/change` page is rendered, the operator never
/// loses their place.
///
/// Security model (mirrors issue #11 step-up applied to update_user_web):
/// - The current password is **not** required. The proof of identity is the
///   operator's own fresh TOTP code, which is single-use within its 30-second
///   window (RFC 6238 §5.2 replay protection persisted via
///   `users.last_totp_used_window`). This matches the same trade-off chosen
///   for cross-user password rotation in `update_user_web`: a per-action
///   second factor is strictly stronger than re-prompting a possibly-already-
///   compromised password, and is forward-compatible with Passkeys/WebAuthn.
/// - Operators without an enrolled TOTP factor are refused outright with an
///   actionable link to `/accounts/mfa/setup`. There is no password fallback.
/// - Federated accounts (LDAP/SAML/OIDC) refuse the rotation: their password
///   lives in the upstream IdP, not in our `users.password_hash` column.
#[derive(Debug, serde::Deserialize)]
pub struct ChangeOwnPasswordForm {
    pub csrf_token: String,
    pub new_password: String,
    pub confirm_password: String,
    /// Step-up MFA proof: the operator's own current TOTP code, mandatory.
    /// Verified against `auth_user.uuid`'s `mfa_secret`. Single-use within
    /// its 30-second window. See [`crate::auth::step_up`].
    pub totp_code: String,
}

/// Self-service password rotation handler (POST /accounts/profile/password).
///
/// Web-only: there is no API equivalent because callers that already hold an
/// API key have a strictly weaker authentication context than a freshly-
/// proven TOTP step-up; routing them through the same modal would be a
/// downgrade. API password changes go through the admin path.
///
/// On success the response is always a 303 redirect back to
/// `/accounts/profile` with a green flash, so refreshing the page after the
/// rotation does not re-submit the form (defence against accidental
/// double-rotation).
pub async fn change_own_password_web(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    Form(form): Form<ChangeOwnPasswordForm>,
) -> Response {
    use crate::schema::users;
    use chrono::Utc;

    let flash = incoming_flash.flash();
    let profile_url = "/accounts/profile";

    // CSRF (double-submit). Same shape as every other state-mutating handler
    // in this module so the CSRF middleware contract stays uniform.
    let csrf_cookie = jar.get(crate::middleware::csrf::CSRF_COOKIE_NAME);
    let secret = state.config.secret_key.expose_secret().as_bytes();
    if !crate::middleware::csrf::validate_double_submit(
        secret,
        csrf_cookie.map(|c| c.value()),
        &form.csrf_token,
    ) {
        return flash_redirect(
            flash.error("Invalid CSRF token. Please refresh the page and try again."),
            profile_url,
        );
    }

    // Confirmation match runs FIRST: it is a pure user-input mistake, no
    // need to bother the database or the vault for it.
    if form.new_password != form.confirm_password {
        return flash_redirect(
            flash.error("New password and confirmation do not match"),
            profile_url,
        );
    }

    // Length policy is loaded from config so deployments that tighten
    // `security.password_min_length` get a single source of truth across the
    // create-user, edit-user and self-rotation paths. The wording lives in
    // `validate_password_length` so the three sites stay aligned.
    if let Err(msg) = validate_password_length(
        &form.new_password,
        state.config.security.password_min_length,
    ) {
        return flash_redirect(flash.error(msg), profile_url);
    }

    let mut conn = match state.db_pool.get().await {
        Ok(conn) => conn,
        Err(_) => {
            return flash_redirect(
                flash.error("Database connection error. Please try again."),
                profile_url,
            );
        }
    };

    // Refuse federated accounts: their password is owned by the upstream IdP
    // and rotating only the local hash would silently desynchronise the two
    // and lock the user out the next time they log in via SSO. We look up
    // the user by UUID from the JWT, not by the form, so a tampered request
    // body cannot point us at someone else's row.
    let parsed_uuid = match uuid::Uuid::parse_str(&auth_user.uuid) {
        Ok(u) => u,
        Err(_) => {
            return flash_redirect(
                flash.error("Could not verify your identity. Please log out and log back in."),
                profile_url,
            );
        }
    };
    let me: Option<(i32, AuthSource)> = users::table
        .filter(users::uuid.eq(parsed_uuid))
        .filter(users::is_deleted.eq(false))
        .select((users::id, users::auth_source))
        .first(&mut conn)
        .await
        .optional()
        .unwrap_or(None);
    let (user_id, auth_source) = match me {
        Some(t) => t,
        None => {
            return flash_redirect(
                flash.error("Could not verify your identity. Please log out and log back in."),
                profile_url,
            );
        }
    };
    if !matches!(auth_source, AuthSource::Local) {
        return flash_redirect(
            flash.error(
                "Your password is managed by your identity provider and cannot be changed here.",
            ),
            profile_url,
        );
    }

    // Step-up MFA -- exact same contract as update_user_web (issue #11).
    // The proof is single-use; rejecting here returns to /accounts/profile
    // with a precise flash so the user knows what to fix (no enrolment vs
    // wrong code vs replayed code vs vault unavailable).
    if let Err(err) =
        crate::auth::enforce_totp_step_up(&state, &mut conn, &auth_user.uuid, &form.totp_code).await
    {
        tracing::info!(
            operator = %auth_user.uuid,
            error = ?err,
            "change_own_password_web: step-up MFA rejected, refusing self password rotation"
        );
        return flash_redirect(flash.error(err.flash_message()), profile_url);
    }

    // Hash through the auth-IPC client when configured (production path:
    // Argon2 work happens out-of-process so the web tier stays responsive),
    // otherwise fall back to the in-process AuthService used in tests.
    let new_hash = if let Some(ref client) = state.auth_ipc_client {
        client.hash_password(&form.new_password).await
    } else {
        state.auth_service.hash_password(&form.new_password)
    };
    let new_hash = match new_hash {
        Ok(h) => h,
        Err(_) => {
            return flash_redirect(
                flash.error("Failed to process password. Please try again."),
                profile_url,
            );
        }
    };

    let now = Utc::now();
    match diesel::update(users::table.filter(users::id.eq(user_id)))
        .set((
            users::password_hash.eq(&new_hash),
            users::updated_at.eq(now),
        ))
        .execute(&mut conn)
        .await
    {
        Ok(_) => {
            tracing::info!(
                operator = %auth_user.uuid,
                "change_own_password_web: password rotated via self-service modal"
            );
            crate::services::emit_audit(
                &state,
                crate::ipc::AuditEvent::new(
                    shared::messages::AuditEventType::PasswordChanged,
                    r#"{"by":"self"}"#,
                )
                .user(auth_user.uuid.to_string()),
            );
            // Best-effort: zeroize the plaintext we still hold on the stack
            // before returning. The Form<T> deserializer already moved the
            // String out of the wire bytes, so this is the only copy we
            // can reach.
            let mut np = form.new_password;
            np.zeroize();
            let mut cp = form.confirm_password;
            cp.zeroize();
            flash_redirect(flash.success("Password updated successfully"), profile_url)
        }
        Err(_) => flash_redirect(
            flash.error("Failed to update password. Please try again."),
            profile_url,
        ),
    }
}

/// User profile page.
pub async fn profile(
    State(state): State<AppState>,
    jar: axum_extra::extract::CookieJar,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    browser_tz: BrowserTz,
) -> Result<impl IntoResponse, AppError> {
    use crate::models::auth_session::AuthSession;
    use crate::models::user::User;
    use crate::schema::users;
    use sha3::{Digest, Sha3_256};

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;

    // Parse the UUID from the auth user
    let user_uuid = uuid::Uuid::parse_str(&auth_user.uuid)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Invalid UUID: {}", e)))?;

    // Fetch the full user data from the database
    let db_user: User = users::table
        .filter(users::uuid.eq(user_uuid))
        .filter(users::is_deleted.eq(false))
        .first(&mut conn)
        .await
        .map_err(|e| match e {
            diesel::result::Error::NotFound => AppError::NotFound("User not found".to_string()),
            _ => AppError::Database(e),
        })?;

    // Build full name
    let full_name = match (&db_user.first_name, &db_user.last_name) {
        (Some(first), Some(last)) => Some(format!("{} {}", first, last)),
        (Some(first), None) => Some(first.clone()),
        (None, Some(last)) => Some(last.clone()),
        (None, None) => None,
    };

    // Build profile detail
    let profile = ProfileDetail {
        uuid: db_user.uuid.to_string(),
        username: db_user.username.clone(),
        email: db_user.email.clone(),
        first_name: db_user.first_name.clone(),
        last_name: db_user.last_name.clone(),
        phone: db_user.phone.clone(),
        full_name,
        is_active: db_user.is_active,
        is_staff: db_user.is_staff,
        is_superuser: db_user.is_superuser,
        mfa_enabled: db_user.mfa_enabled,
        mfa_enforced: db_user.mfa_enforced,
        auth_source: db_user.auth_source.to_string(),
        last_login: db_user
            .last_login
            .map(|dt| crate::utils::format_local_with_seconds(dt, browser_tz.0)),
        created_at: crate::utils::format_local_with_seconds(db_user.created_at, browser_tz.0),
        updated_at: crate::utils::format_local_with_seconds(db_user.updated_at, browser_tz.0),
    };

    // Get the current token hash from cookie for session detection
    let current_token_hash = jar
        .get("auth_token")
        .map(|c| c.value().to_string())
        .map(|token| {
            let mut hasher = Sha3_256::new();
            hasher.update(token.as_bytes());
            hex::encode(hasher.finalize())
        });

    // Fetch active sessions for the user
    let db_sessions: Vec<AuthSession> = auth_sessions::table
        .filter(auth_sessions::user_id.eq(db_user.id))
        .filter(auth_sessions::expires_at.gt(chrono::Utc::now()))
        .order(auth_sessions::created_at.desc())
        .load(&mut conn)
        .await
        .unwrap_or_default();

    let sessions: Vec<ProfileSession> = db_sessions
        .into_iter()
        .map(|s| {
            let device_info = s.device_info.clone();
            let is_current = current_token_hash
                .as_ref()
                .map(|hash| hash == &s.token_hash)
                .unwrap_or(false);
            ProfileSession {
                uuid: s.uuid.to_string(),
                ip_address: s.ip_address.ip().to_string(),
                device_info,
                last_activity: s.last_activity,
                created_at: s.created_at,
                is_current,
            }
        })
        .collect();

    let user = Some(user_context_from_auth(&auth_user));

    // Forward incoming flash messages so the change-password modal's
    // PRG round-trip back to /accounts/profile actually renders the
    // success/error banner. Without this, the signed cookie is set on
    // the redirect response but the message never reaches the template
    // and the user sees no feedback at all.
    let flash_messages: Vec<crate::templates::base::FlashMessage> = incoming_flash
        .messages()
        .iter()
        .map(|m| crate::templates::base::FlashMessage {
            level: m.level.clone(),
            message: m.message.clone(),
        })
        .collect();

    let base = BaseTemplate::new("My Profile".to_string(), user.clone(), browser_tz.0)
        .with_current_path("/accounts/profile")
        .with_messages(flash_messages);
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

    let template = ProfileTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        profile,
        sessions,
        current_session_token: current_token_hash,
        perms,
        password_min_length: state.config.security.password_min_length,
    };

    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;
    Ok(Html(html))
}

/// MFA setup page (for authenticated users viewing their MFA status).
///
/// VAU-008 (ephemeral): entry point for the ROTATION flow (the user is already
/// enrolled). Strictly READ-ONLY -- no secret production and no DB write. The
/// candidate secret is created exclusively by `POST /mfa/setup/init` (CSRF
/// gated, current-TOTP step-up for rotation) and lives ONLY in the per-session
/// in-memory store. Renders the same three states as `mfa_setup_page`.
pub async fn mfa_setup(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    session_id: crate::middleware::auth::AuthSessionId,
    browser_tz: BrowserTz,
) -> Result<impl IntoResponse, AppError> {
    use ::uuid::Uuid as UuidType;

    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new("MFA Setup".to_string(), user.clone(), browser_tz.0)
        .with_current_path("/accounts/mfa");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;
    let user_uuid = UuidType::parse_str(&auth_user.uuid)
        .map_err(|_| AppError::Validation("Invalid user UUID".to_string()))?;

    let (user_username, mfa_already_enabled): (String, bool) = crate::schema::users::table
        .filter(crate::schema::users::uuid.eq(user_uuid))
        .filter(crate::schema::users::is_deleted.eq(false))
        .select((
            crate::schema::users::username,
            crate::schema::users::mfa_enabled,
        ))
        .first(&mut conn)
        .await
        .map_err(AppError::Database)?;

    // The candidate is keyed by the login session (= auth_sessions.uuid, which
    // is the JWT `jti`). On a web flow this is always present.
    let session_jti = session_id.0.to_string();
    let candidate = state.pending_mfa.get(&auth_user.uuid, &session_jti);

    let (show_qr, needs_totp_stepup, secret, mut qr_code_base64) = match candidate {
        Some(ref s) => {
            let (plaintext_secret, qr) =
                crate::handlers::auth::mfa_qr_from_secret(&state, s, &user_username).await?;
            (true, false, plaintext_secret, qr)
        }
        None => (false, mfa_already_enabled, String::new(), String::new()),
    };

    let template = MfaSetupTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        show_qr,
        needs_totp_stepup,
        secret,
        qr_code_base64: qr_code_base64.clone(),
    };

    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;
    // Zeroize QR code data after template rendering (contains TOTP secret in image)
    qr_code_base64.zeroize();
    Ok(Html(html))
}

/// User sessions list page (web sessions, not proxy sessions).
pub async fn user_sessions(
    State(state): State<AppState>,
    jar: axum_extra::extract::CookieJar,
    auth_user: WebAuthUser,
    browser_tz: BrowserTz,
) -> Result<impl IntoResponse, AppError> {
    use crate::models::AuthSession;
    use sha3::{Digest, Sha3_256};

    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new("My Login Sessions".to_string(), user.clone(), browser_tz.0)
        .with_current_path("/accounts/login-sessions");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

    // Load user sessions from database
    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;

    // Get current token hash to identify the real current session
    let current_token_hash = jar.get("access_token").map(|cookie| {
        let mut hasher = Sha3_256::new();
        hasher.update(cookie.value().as_bytes());
        format!("{:x}", hasher.finalize())
    });

    // Debug: log auth_user UUID
    tracing::debug!(auth_uuid = %auth_user.uuid, "Loading sessions for user");

    let parsed_uuid = auth_user.uuid.parse::<uuid::Uuid>().ok();
    let user_id: i32 = if let Some(uuid_val) = parsed_uuid {
        use crate::schema::users;
        users::table
            .filter(users::uuid.eq(uuid_val))
            .select(users::id)
            .first::<i32>(&mut conn)
            .await
            .unwrap_or(0)
    } else {
        0
    };

    // Debug: log found user_id
    tracing::debug!(user_id = user_id, auth_uuid = %auth_user.uuid, "Found user_id for auth UUID");

    let db_sessions: Vec<AuthSession> = auth_sessions::table
        .filter(auth_sessions::user_id.eq(user_id))
        .filter(auth_sessions::expires_at.gt(chrono::Utc::now()))
        .order(auth_sessions::created_at.desc())
        .load(&mut conn)
        .await
        .unwrap_or_default();

    // Debug: log number of sessions found
    tracing::debug!(
        session_count = db_sessions.len(),
        user_id = user_id,
        "Sessions loaded from DB"
    );

    let sessions: Vec<AuthSessionItem> = db_sessions
        .into_iter()
        .map(|s| {
            let device_info = s.device_info.clone();
            let is_current = current_token_hash
                .as_ref()
                .map(|hash| hash == &s.token_hash)
                .unwrap_or(false);
            AuthSessionItem {
                uuid: s.uuid,
                ip_address: s.ip_address.ip().to_string(),
                device_info,
                last_activity: s.last_activity,
                created_at: s.created_at,
                is_current,
                is_expired: s.is_expired(),
            }
        })
        .collect();

    let template = AccountSessionListTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        sessions,
    };

    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;
    Ok(Html(html))
}

/// API keys list page.
pub async fn api_keys(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    browser_tz: BrowserTz,
) -> Result<impl IntoResponse, AppError> {
    use crate::models::ApiKey;

    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new("API Keys".to_string(), user.clone(), browser_tz.0)
        .with_current_path("/accounts/apikeys");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

    // Load user API keys from database
    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;
    let parsed_uuid = auth_user.uuid.parse::<uuid::Uuid>().ok();
    let user_id: i32 = if let Some(uuid_val) = parsed_uuid {
        use crate::schema::users;
        users::table
            .filter(users::uuid.eq(uuid_val))
            .select(users::id)
            .first::<i32>(&mut conn)
            .await
            .unwrap_or(0)
    } else {
        0
    };

    let db_keys: Vec<ApiKey> = api_keys::table
        .filter(api_keys::user_id.eq(user_id))
        .order(api_keys::created_at.desc())
        .load(&mut conn)
        .await
        .unwrap_or_default();

    let api_keys_list: Vec<ApiKeyItem> = db_keys
        .into_iter()
        .map(|k| {
            let scopes = k.scopes_vec();
            ApiKeyItem {
                uuid: k.uuid,
                name: k.name,
                key_prefix: k.key_prefix,
                scopes,
                last_used_at: k.last_used_at,
                expires_at: k.expires_at,
                is_active: k.is_active,
                created_at: k.created_at,
            }
        })
        .collect();

    let template = ApikeyListTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        api_keys: api_keys_list,
    };

    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;
    Ok(Html(html))
}

/// Revoke an auth session.
pub async fn revoke_session(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    jar: CookieJar,
    axum::extract::Path(session_uuid_str): axum::extract::Path<String>,
    Form(form): Form<CsrfOnlyForm>,
) -> AppResult<Response> {
    let secret = state.config.secret_key.expose_secret().as_bytes();
    let csrf_cookie = jar.get(crate::middleware::csrf::CSRF_COOKIE_NAME);
    if !crate::middleware::csrf::validate_double_submit(
        secret,
        csrf_cookie.map(|c| c.value()),
        &form.csrf_token,
    ) {
        return Ok((axum::http::StatusCode::BAD_REQUEST, "Invalid CSRF token").into_response());
    }

    // Parse UUID manually for graceful error handling
    let session_uuid = match uuid::Uuid::parse_str(&session_uuid_str) {
        Ok(uuid) => uuid,
        Err(_) => {
            return Ok(Redirect::to("/accounts/login-sessions").into_response());
        }
    };

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;

    // Get user ID
    let parsed_uuid = auth_user.uuid.parse::<uuid::Uuid>().ok();
    let user_id: i32 = if let Some(uuid_val) = parsed_uuid {
        use crate::schema::users;
        users::table
            .filter(users::uuid.eq(uuid_val))
            .select(users::id)
            .first::<i32>(&mut conn)
            .await
            .unwrap_or(0)
    } else {
        0
    };

    // Delete the session (only if it belongs to the user)
    let deleted = diesel::delete(
        auth_sessions::table
            .filter(auth_sessions::uuid.eq(session_uuid))
            .filter(auth_sessions::user_id.eq(user_id)),
    )
    .execute(&mut conn)
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("Failed to revoke session: {}", e)))?;

    // Send WebSocket notification if session was deleted
    if deleted > 0 {
        // Broadcast notification to all connected clients for this user
        // The WebSocket handler will forward this to update the UI
        broadcast_sessions_update(&state, &auth_user.uuid, user_id).await;
    }

    // Return empty response (HTMX will remove the element via hx-target)
    Ok(Html("").into_response())
}

/// Broadcast updated sessions list to WebSocket clients.
/// Called when a session is created or revoked.
/// Uses UserConnectionRegistry to send personalized HTML to each client,
/// ensuring each client sees the correct "Current session" indicator.
/// Also sends via the standard broadcast channel for backwards compatibility.
pub async fn broadcast_sessions_update(state: &AppState, user_uuid: &str, user_id: i32) {
    use crate::models::AuthSession;
    use crate::services::broadcast::{WsChannel, WsMessage};

    // Load current sessions from database
    let db_sessions: Vec<AuthSession> = match state.db_pool.get().await {
        Ok(mut conn) => auth_sessions::table
            .filter(auth_sessions::user_id.eq(user_id))
            .filter(auth_sessions::expires_at.gt(chrono::Utc::now()))
            .order(auth_sessions::created_at.desc())
            .load(&mut conn)
            .await
            .unwrap_or_default(),
        Err(_) => return,
    };

    // Send personalized HTML to each connected client via UserConnectionRegistry
    state
        .user_connections
        .send_personalized(user_uuid, |client_token_hash| {
            let sessions_html = build_sessions_html(&db_sessions, client_token_hash);
            let message = WsMessage::new("sessions-list", sessions_html);
            message.to_htmx_html()
        })
        .await;

    // Also send via standard broadcast channel (for backwards compatibility and tests)
    // This uses an empty token_hash, so no session will be marked as "current"
    let generic_html = build_sessions_html(&db_sessions, "");
    let channel = WsChannel::UserAuthSessions(user_uuid.to_string());
    let message = WsMessage::new("sessions-list", generic_html);
    state.broadcast.send(&channel, message).await.ok();
}

/// Build HTML for the sessions list, personalized for the client's token_hash.
pub(crate) fn build_sessions_html(
    sessions: &[crate::models::AuthSession],
    client_token_hash: &str,
) -> String {
    if sessions.is_empty() {
        return r#"<li class="px-6 py-8 text-center text-gray-500 dark:text-gray-400">No active sessions</li>"#.to_string();
    }

    let mut html = String::new();
    for s in sessions {
        let device_info = s.device_info.clone();
        let is_current = !client_token_hash.is_empty() && client_token_hash == s.token_hash;
        let ip = s.ip_address.ip().to_string();
        let uuid = s.uuid;

        let icon_class = if is_current {
            "bg-green-100 dark:bg-green-900"
        } else {
            "bg-gray-100 dark:bg-gray-700"
        };
        let icon_color = if is_current {
            "text-green-600 dark:text-green-400"
        } else {
            "text-gray-600 dark:text-gray-400"
        };

        let current_badge = if is_current {
            r#"<span class="ml-2 inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200">Current session</span>"#
        } else {
            ""
        };

        let action_html = if is_current {
            r#"<span class="text-xs text-gray-400 dark:text-gray-500">This device</span>"#
                .to_string()
        } else {
            format!(
                r#"<form hx-post="/accounts/login-sessions/{}/revoke" hx-confirm="Are you sure you want to revoke this session?" hx-target="closest li" hx-swap="outerHTML">
                    <button type="submit" class="inline-flex items-center px-3 py-1.5 border border-transparent text-xs font-medium rounded text-red-700 bg-red-100 hover:bg-red-200 dark:text-red-200 dark:bg-red-900 dark:hover:bg-red-800 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500">Revoke</button>
                </form>"#,
                uuid
            )
        };

        html.push_str(&format!(
            r#"<li id="session-row-{}" class="px-6 py-4">
                <div class="flex items-center justify-between">
                    <div class="flex items-center min-w-0 gap-x-4">
                        <div class="flex-shrink-0">
                            <span class="inline-flex items-center justify-center h-10 w-10 rounded-full {}">
                                <svg class="h-5 w-5 {}" fill="currentColor" viewBox="0 0 20 20">
                                    <path fill-rule="evenodd" d="M3 5a2 2 0 012-2h10a2 2 0 012 2v8a2 2 0 01-2 2h-2.22l.123.489.804.804A1 1 0 0113 18H7a1 1 0 01-.707-1.707l.804-.804L7.22 15H5a2 2 0 01-2-2V5zm5.771 7H5V5h10v7H8.771z" clip-rule="evenodd" />
                                </svg>
                            </span>
                        </div>
                        <div class="min-w-0 flex-1">
                            <p class="text-sm font-medium text-gray-900 dark:text-white truncate">{}{}</p>
                            <p class="text-sm text-gray-500 dark:text-gray-400">IP: {}</p>
                        </div>
                    </div>
                    <div class="flex-shrink-0">{}</div>
                </div>
            </li>"#,
            uuid, icon_class, icon_color, device_info, current_badge, ip, action_html
        ));
    }

    html
}

/// Revoke an API key.
pub async fn revoke_api_key(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    jar: CookieJar,
    axum::extract::Path(key_uuid_str): axum::extract::Path<String>,
    Form(form): Form<CsrfOnlyForm>,
) -> AppResult<Response> {
    use crate::services::broadcast::WsChannel;

    let secret = state.config.secret_key.expose_secret().as_bytes();
    let csrf_cookie = jar.get(crate::middleware::csrf::CSRF_COOKIE_NAME);
    if !crate::middleware::csrf::validate_double_submit(
        secret,
        csrf_cookie.map(|c| c.value()),
        &form.csrf_token,
    ) {
        return Ok((axum::http::StatusCode::BAD_REQUEST, "Invalid CSRF token").into_response());
    }

    // Parse UUID manually for graceful error handling
    let key_uuid = match uuid::Uuid::parse_str(&key_uuid_str) {
        Ok(uuid) => uuid,
        Err(_) => {
            return Ok(Redirect::to("/accounts/apikeys").into_response());
        }
    };

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;

    // Get user ID
    let parsed_uuid = auth_user.uuid.parse::<uuid::Uuid>().ok();
    let user_id: i32 = if let Some(uuid_val) = parsed_uuid {
        use crate::schema::users;
        users::table
            .filter(users::uuid.eq(uuid_val))
            .select(users::id)
            .first::<i32>(&mut conn)
            .await
            .unwrap_or(0)
    } else {
        0
    };

    // Mark the key as inactive (soft delete)
    let updated = diesel::update(
        api_keys::table
            .filter(api_keys::uuid.eq(key_uuid))
            .filter(api_keys::user_id.eq(user_id)),
    )
    .set(api_keys::is_active.eq(false))
    .execute(&mut conn)
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("Failed to revoke API key: {}", e)))?;

    let revoked_html = format!(
        r#"<tr id="api-key-{}" class="opacity-50"><td colspan="6" class="px-6 py-4 text-center text-sm text-gray-500 dark:text-gray-400">API key revoked</td></tr>"#,
        key_uuid
    );

    // Send WebSocket notification if key was updated
    if updated > 0 {
        let channel = WsChannel::UserApiKeys(auth_user.uuid.clone());
        // Send raw HTML with hx-swap-oob attribute for HTMX WebSocket extension
        let ws_html = format!(
            r#"<tr id="api-key-{}" hx-swap-oob="outerHTML" class="opacity-50"><td colspan="6" class="px-6 py-4 text-center text-sm text-gray-500 dark:text-gray-400">API key revoked</td></tr>"#,
            key_uuid
        );
        state
            .broadcast
            .send_raw(&channel.as_str(), ws_html)
            .await
            .ok();
    }

    // Return updated row HTML for direct HTMX swap
    Ok(Html(revoked_html).into_response())
}

/// Create API key form (returns modal HTML).
pub async fn create_api_key_form(
    State(_state): State<AppState>,
    _auth_user: WebAuthUser,
) -> Result<impl IntoResponse, AppError> {
    use crate::templates::accounts::ApikeyCreateFormTemplate;

    let template = ApikeyCreateFormTemplate {};
    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;
    Ok(Html(html))
}

/// Create a new API key.
pub async fn create_api_key(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    jar: CookieJar,
    axum::extract::Form(form): axum::extract::Form<CreateApiKeyForm>,
) -> Result<impl IntoResponse, AppError> {
    use crate::models::{ApiKey, NewApiKey};
    use crate::templates::accounts::ApikeyCreatedTemplate;

    let secret = state.config.secret_key.expose_secret().as_bytes();
    let csrf_cookie = jar.get(crate::middleware::csrf::CSRF_COOKIE_NAME);
    if !crate::middleware::csrf::validate_double_submit(
        secret,
        csrf_cookie.map(|c| c.value()),
        &form.csrf_token,
    ) {
        return Err(AppError::Validation("Invalid CSRF token".to_string()));
    }

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;

    // Get user ID
    let parsed_uuid = auth_user
        .uuid
        .parse::<uuid::Uuid>()
        .ok()
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("Invalid user UUID")))?;
    use crate::schema::users;
    let user_id: i32 = users::table
        .filter(users::uuid.eq(parsed_uuid))
        .select(users::id)
        .first::<i32>(&mut conn)
        .await
        .map_err(|_| AppError::Internal(anyhow::anyhow!("User not found")))?;

    // Generate the API key
    let (_prefix, full_key, hash) = ApiKey::generate_key();

    // Parse scopes
    let scopes: Vec<String> = form
        .scopes
        .clone()
        .unwrap_or_else(|| vec!["read".to_string()]);
    let scopes_json = serde_json::to_value(&scopes)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Failed to serialize scopes: {}", e)))?;

    // Calculate expiration
    let expires_at = form.expires_in_days.and_then(|days| {
        if days > 0 {
            Some(chrono::Utc::now() + chrono::Duration::days(days))
        } else {
            None
        }
    });

    // Get prefix from full key
    let key_prefix = full_key.chars().take(8).collect::<String>();

    // Insert the key
    let new_key = NewApiKey {
        uuid: uuid::Uuid::new_v4(),
        user_id,
        name: form.name.clone(),
        key_prefix,
        key_hash: hash,
        scopes: scopes_json,
        expires_at,
    };

    diesel::insert_into(api_keys::table)
        .values(&new_key)
        .execute(&mut conn)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Failed to create API key: {}", e)))?;

    // Return success message with the key (only shown once)
    let template = ApikeyCreatedTemplate {
        name: form.name.clone(),
        key: full_key,
    };
    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;

    Ok(Html(html))
}

/// Admin: list all users' auth sessions.
pub async fn admin_user_sessions(
    State(state): State<AppState>,
    jar: CookieJar,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    browser_tz: BrowserTz,
) -> Result<impl IntoResponse, AppError> {
    if !perms.auth_sessions_read {
        return Err(AppError::Authorization(
            "Only administrators can view user sessions".to_string(),
        ));
    }

    use crate::models::AuthSession;
    use crate::templates::accounts::session_list::AdminAuthSessionItem;
    use sha3::{Digest, Sha3_256};

    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new("All Login Sessions".to_string(), user.clone(), browser_tz.0)
        .with_current_path("/accounts/all-login-sessions");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

    let current_token_hash = jar.get("access_token").map(|cookie| {
        let mut hasher = Sha3_256::new();
        hasher.update(cookie.value().as_bytes());
        format!("{:x}", hasher.finalize())
    });

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;

    use crate::schema::users;

    let db_sessions: Vec<(AuthSession, String, uuid::Uuid)> = auth_sessions::table
        .inner_join(users::table.on(users::id.eq(auth_sessions::user_id)))
        .filter(auth_sessions::expires_at.gt(chrono::Utc::now()))
        .order(auth_sessions::created_at.desc())
        .select((AuthSession::as_select(), users::username, users::uuid))
        .load(&mut conn)
        .await
        .unwrap_or_default();

    let sessions: Vec<AdminAuthSessionItem> = db_sessions
        .into_iter()
        .map(|(s, username, user_uuid)| {
            let device_info = s.device_info.clone();
            let is_current = current_token_hash
                .as_deref()
                .is_some_and(|h| h == s.token_hash);
            AdminAuthSessionItem {
                uuid: s.uuid,
                username,
                user_uuid: user_uuid.to_string(),
                ip_address: s.ip_address.ip().to_string(),
                device_info,
                last_activity: s.last_activity,
                created_at: s.created_at,
                is_expired: s.is_expired(),
                is_current,
            }
        })
        .collect();

    use crate::templates::accounts::AdminSessionListTemplate;

    let template = AdminSessionListTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        sessions,
    };

    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;
    Ok(Html(html))
}

/// Deactivate a user account (SEC-07).
///
/// Revokes all auth sessions, terminates active proxy sessions (SSH/RDP),
/// disables API keys, force-logs out all browser sessions via WebSocket,
/// and broadcasts updates to session pages.
pub async fn deactivate_user(state: &AppState, user_id: i32, user_uuid: &str) {
    use crate::models::session::{ProxySession, SessionType};

    let mut conn = match state.db_pool.get().await {
        Ok(conn) => conn,
        Err(_) => return,
    };

    // 1. Delete all auth sessions
    let _ = diesel::delete(auth_sessions::table.filter(auth_sessions::user_id.eq(user_id)))
        .execute(&mut conn)
        .await;

    // 2. Terminate all active proxy sessions (SSH/RDP)
    let active_sessions: Vec<ProxySession> = proxy_sessions::table
        .filter(proxy_sessions::user_id.eq(user_id))
        .filter(
            proxy_sessions::status
                .eq("connecting")
                .or(proxy_sessions::status.eq("active")),
        )
        .load(&mut conn)
        .await
        .unwrap_or_default();

    let now = chrono::Utc::now();
    for session in &active_sessions {
        let session_uuid_str = session.uuid.to_string();

        // Check if recording is enabled for this session type
        let is_recording = match session.session_type {
            SessionType::Ssh => state.config.recording.ssh_recording_enabled(),
            SessionType::Rdp => state.config.recording.rdp_recording_enabled(),
            SessionType::IacsTunnel => state.config.recording.iacs_recording_enabled(),
        };

        // Set recording_path + is_recorded in the same UPDATE that sets "terminated",
        // because the WebSocket cleanup handler filters on status IN ('active','connecting')
        // and would skip sessions already marked "terminated".
        if is_recording {
            let path_anchor = session.connected_at.unwrap_or(now);
            let recording_path = crate::services::recording_hydrator::recording_dir_for_session(
                &state.config.recording.storage_path,
                &session_uuid_str,
                path_anchor,
            );
            let _ = diesel::update(proxy_sessions::table.filter(proxy_sessions::id.eq(session.id)))
                .set((
                    proxy_sessions::status.eq("terminated"),
                    proxy_sessions::disconnected_at.eq(now),
                    proxy_sessions::is_recorded.eq(true),
                    proxy_sessions::recording_path.eq(&recording_path),
                ))
                .execute(&mut conn)
                .await;
        } else {
            let _ = diesel::update(proxy_sessions::table.filter(proxy_sessions::id.eq(session.id)))
                .set((
                    proxy_sessions::status.eq("terminated"),
                    proxy_sessions::disconnected_at.eq(now),
                ))
                .execute(&mut conn)
                .await;
        }

        // PRIMARY hydration path (issue #29 v1.4): schedule the
        // integrity bundle population for this session. Idempotent +
        // no-op for non-recorded rows.
        std::mem::drop(crate::services::recording_hydrator::enqueue_hydration(
            state,
            session.id,
            std::time::Duration::from_secs(state.config.recording.hydration_enqueue_delay_secs),
        ));

        match session.session_type {
            SessionType::Ssh => {
                if let Some(ref proxy) = state.ssh_proxy {
                    let _ = proxy.close_session(&session_uuid_str);
                    proxy.unsubscribe_session(&session_uuid_str).await;
                }
            }
            SessionType::Rdp => {
                if let Some(ref proxy) = state.rdp_proxy {
                    let _ = proxy.close_session(&session_uuid_str);
                    proxy.unsubscribe_session(&session_uuid_str).await;
                }
            }
            // IACS tunnels are closed via the in-process registry once
            // L3 lands (`services::iacs_tunnel::Registry::close`). The
            // L1 stub just relies on the status update above; the
            // watchdog (L4) and the running tunnel task will then
            // observe the row transition.
            SessionType::IacsTunnel => {}
        }
    }

    // 3. Disable all active API keys
    let _ = diesel::update(
        api_keys::table
            .filter(api_keys::user_id.eq(user_id))
            .filter(api_keys::is_active.eq(true)),
    )
    .set(api_keys::is_active.eq(false))
    .execute(&mut conn)
    .await;

    // 4. Force-logout all browser sessions via WebSocket
    let force_logout_html =
        crate::services::session_activity::force_logout_oob("account_deactivated");
    state
        .user_connections
        .send_personalized(user_uuid, |_token_hash| force_logout_html.clone())
        .await;

    // 5. Broadcast session updates
    if !active_sessions.is_empty() {
        crate::tasks::dashboard::push_session_list_update(&state.broadcast, &state.db_pool).await;
        crate::tasks::dashboard::push_active_sessions_update(&state.broadcast, &state.db_pool)
            .await;
    }
    broadcast_sessions_update(state, user_uuid, user_id).await;
    broadcast_admin_sessions_update(state).await;

    tracing::info!(
        user_id = user_id,
        user_uuid = user_uuid,
        "User account deactivated: revoked all sessions and disabled API keys"
    );
}

/// Reactivate a user account (SEC-07).
///
/// Re-enables all API keys that were disabled during deactivation.
pub async fn reactivate_user(state: &AppState, user_id: i32) {
    let mut conn = match state.db_pool.get().await {
        Ok(conn) => conn,
        Err(_) => return,
    };

    let _ = diesel::update(
        api_keys::table
            .filter(api_keys::user_id.eq(user_id))
            .filter(api_keys::is_active.eq(false)),
    )
    .set(api_keys::is_active.eq(true))
    .execute(&mut conn)
    .await;

    tracing::info!(
        user_id = user_id,
        "User account reactivated: re-enabled API keys"
    );
}

/// Admin: revoke any user's auth session and force-logout their browser.
pub async fn admin_revoke_session(
    State(state): State<AppState>,
    _auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    jar: CookieJar,
    axum::extract::Path(session_uuid_str): axum::extract::Path<String>,
    Form(form): Form<CsrfOnlyForm>,
) -> AppResult<Response> {
    if !perms.auth_sessions_write {
        return Err(AppError::Authorization(
            "Only administrators can revoke user sessions".to_string(),
        ));
    }

    let secret = state.config.secret_key.expose_secret().as_bytes();
    let csrf_cookie = jar.get(crate::middleware::csrf::CSRF_COOKIE_NAME);
    if !crate::middleware::csrf::validate_double_submit(
        secret,
        csrf_cookie.map(|c| c.value()),
        &form.csrf_token,
    ) {
        return Ok((axum::http::StatusCode::BAD_REQUEST, "Invalid CSRF token").into_response());
    }

    let session_uuid = match uuid::Uuid::parse_str(&session_uuid_str) {
        Ok(uuid) => uuid,
        Err(_) => {
            return Ok(Redirect::to("/accounts/all-login-sessions").into_response());
        }
    };

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;

    // Fetch the session BEFORE deleting to get user_id, user_uuid, and token_hash
    use crate::models::AuthSession;
    use crate::schema::users;

    let session_info: Option<(AuthSession, uuid::Uuid)> = auth_sessions::table
        .inner_join(users::table.on(users::id.eq(auth_sessions::user_id)))
        .filter(auth_sessions::uuid.eq(session_uuid))
        .select((AuthSession::as_select(), users::uuid))
        .first(&mut conn)
        .await
        .ok();

    let Some((target_session, target_user_uuid)) = session_info else {
        return Ok((axum::http::StatusCode::NOT_FOUND, "Session not found").into_response());
    };

    let target_user_id = target_session.user_id;
    let target_token_hash = target_session.token_hash.clone();

    // Delete the session
    diesel::delete(auth_sessions::table.filter(auth_sessions::uuid.eq(session_uuid)))
        .execute(&mut conn)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Failed to revoke session: {}", e)))?;

    let target_user_uuid_str = target_user_uuid.to_string();

    // Update the target user's "My sessions" page
    broadcast_sessions_update(&state, &target_user_uuid_str, target_user_id).await;

    // Update all admins' "Users sessions" page
    broadcast_admin_sessions_update(&state).await;

    // Force-logout the target browser via WebSocket (OOB swap into
    // #force-logout -> Alpine x-init window.location.replace).
    let force_logout_html = crate::services::session_activity::force_logout_oob("session_revoked");
    state
        .user_connections
        .send_to_matching(
            &target_user_uuid_str,
            &target_token_hash,
            &force_logout_html,
        )
        .await;

    Ok(Html("").into_response())
}

/// Broadcast updated admin sessions list to all admin WebSocket clients.
///
/// Uses `send_personalized` (same pattern as My Sessions) so each admin sees
/// their own session marked as "Current session".
pub(crate) async fn broadcast_admin_sessions_update(state: &AppState) {
    use crate::models::AuthSession;

    let (db_sessions, admin_uuids) = match state.db_pool.get().await {
        Ok(mut conn) => {
            use crate::schema::users;

            let db_sessions: Vec<(AuthSession, String, uuid::Uuid)> = auth_sessions::table
                .inner_join(users::table.on(users::id.eq(auth_sessions::user_id)))
                .filter(auth_sessions::expires_at.gt(chrono::Utc::now()))
                .order(auth_sessions::created_at.desc())
                .select((AuthSession::as_select(), users::username, users::uuid))
                .load(&mut conn)
                .await
                .unwrap_or_default();

            let admin_uuids: Vec<String> = users::table
                .filter(users::is_staff.eq(true).or(users::is_superuser.eq(true)))
                .filter(users::is_deleted.eq(false))
                .select(users::uuid)
                .load::<uuid::Uuid>(&mut conn)
                .await
                .unwrap_or_default()
                .into_iter()
                .map(|u| u.to_string())
                .collect();

            (db_sessions, admin_uuids)
        }
        Err(_) => return,
    };

    for admin_uuid in &admin_uuids {
        state
            .user_connections
            .send_personalized(admin_uuid, |viewer_token_hash| {
                let sessions_html =
                    build_admin_sessions_html(&db_sessions, viewer_token_hash);
                format!(
                    r#"<ul id="admin-sessions-list" hx-swap-oob="innerHTML" role="list" class="divide-y divide-gray-200 dark:divide-gray-700">{}</ul>"#,
                    sessions_html
                )
            })
            .await;
    }
}

/// Build HTML for the admin sessions list, personalized for the viewer.
///
/// When `viewer_token_hash` matches a session's token_hash, that session is
/// marked as "Current session" with a green badge (same UX as My Sessions).
fn build_admin_sessions_html(
    sessions: &[(crate::models::AuthSession, String, uuid::Uuid)],
    viewer_token_hash: &str,
) -> String {
    if sessions.is_empty() {
        return r#"<li class="px-6 py-8 text-center text-gray-500 dark:text-gray-400">No active sessions</li>"#.to_string();
    }

    let mut html = String::new();
    for (s, username, _user_uuid) in sessions {
        let is_current = !viewer_token_hash.is_empty() && s.token_hash == viewer_token_hash;
        let device_info = s.device_info.clone();
        let ip = s.ip_address.ip().to_string();
        let uuid = s.uuid;

        let age = {
            let duration = chrono::Utc::now().signed_duration_since(s.created_at);
            if duration.num_days() > 0 {
                format!("{} days ago", duration.num_days())
            } else if duration.num_hours() > 0 {
                format!("{} hours ago", duration.num_hours())
            } else if duration.num_minutes() > 0 {
                format!("{} minutes ago", duration.num_minutes())
            } else {
                "Just now".to_string()
            }
        };

        let last_active = {
            let duration = chrono::Utc::now().signed_duration_since(s.last_activity);
            if duration.num_days() > 0 {
                format!("{} days ago", duration.num_days())
            } else if duration.num_hours() > 0 {
                format!("{} hours ago", duration.num_hours())
            } else if duration.num_minutes() > 0 {
                format!("{} minutes ago", duration.num_minutes())
            } else {
                "Just now".to_string()
            }
        };

        let (icon_bg, icon_color) = if is_current {
            (
                "bg-green-100 dark:bg-green-900",
                "text-green-600 dark:text-green-400",
            )
        } else {
            (
                "bg-gray-100 dark:bg-gray-700",
                "text-gray-600 dark:text-gray-400",
            )
        };

        let current_badge = if is_current {
            r#"<span class="ml-2 inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200">Current session</span>"#
        } else {
            ""
        };

        let action_html = if is_current {
            r#"<span class="text-xs text-gray-400 dark:text-gray-500">This session</span>"#
                .to_string()
        } else {
            format!(
                r#"<form hx-post="/accounts/all-login-sessions/{uuid}/revoke" hx-confirm="Are you sure you want to revoke this session for {username}? They will be logged out immediately." hx-target="closest li" hx-swap="outerHTML" x-data="csrf">
                            <input type="hidden" name="csrf_token" x-model="token" />
                            <button type="submit" class="inline-flex items-center px-3 py-1.5 border border-transparent text-xs font-medium rounded text-red-700 bg-red-100 hover:bg-red-200 dark:text-red-200 dark:bg-red-900 dark:hover:bg-red-800 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500">Revoke</button>
                        </form>"#,
                uuid = uuid,
                username = username,
            )
        };

        html.push_str(&format!(
            r#"<li id="admin-session-row-{uuid}" class="px-6 py-4">
                <div class="flex items-center justify-between">
                    <div class="flex items-center min-w-0 gap-x-4">
                        <div class="flex-shrink-0">
                            <span class="inline-flex items-center justify-center h-10 w-10 rounded-full {icon_bg}">
                                <svg class="h-5 w-5 {icon_color}" fill="currentColor" viewBox="0 0 20 20">
                                    <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-6-3a2 2 0 11-4 0 2 2 0 014 0zm-2 4a5 5 0 00-4.546 2.916A5.986 5.986 0 0010 16a5.986 5.986 0 004.546-2.084A5 5 0 0010 11z" clip-rule="evenodd" />
                                </svg>
                            </span>
                        </div>
                        <div class="min-w-0 flex-1">
                            <p class="text-sm font-medium text-gray-900 dark:text-white truncate">
                                {username}{current_badge}
                                <span class="ml-2 text-xs text-gray-500 dark:text-gray-400 font-normal">{device_info}</span>
                            </p>
                            <p class="text-sm text-gray-500 dark:text-gray-400">IP: {ip}</p>
                            <p class="text-xs text-gray-400 dark:text-gray-500">Started {age} &middot; Last active {last_active}</p>
                        </div>
                    </div>
                    <div class="flex-shrink-0">
                        {action_html}
                    </div>
                </div>
            </li>"#,
            uuid = uuid,
            username = username,
            device_info = device_info,
            ip = ip,
            age = age,
            last_active = last_active,
            icon_bg = icon_bg,
            icon_color = icon_color,
            current_badge = current_badge,
            action_html = action_html,
        ));
    }

    html
}

/// Form data for creating an API key.
#[derive(Debug, serde::Deserialize)]
pub struct CreateApiKeyForm {
    pub name: String,
    pub scopes: Option<Vec<String>>,
    pub expires_in_days: Option<i64>,
    pub csrf_token: String,
}
