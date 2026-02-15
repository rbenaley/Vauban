/// User management page handlers.
use super::*;
use crate::models::user::AuthSource;

pub async fn user_list(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse, AppError> {
    use crate::schema::users;
    use crate::templates::accounts::user_list::UserListItem;

    let user = Some(user_context_from_auth(&auth_user));
    let base =
        BaseTemplate::new("Users".to_string(), user.clone()).with_current_path("/accounts/users");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        base.into_fields();

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
        .limit(50)
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
                    last_login: last_login.map(|dt| dt.format("%b %d, %Y %H:%M").to_string()),
                }
            },
        )
        .collect();

    let template = UserListTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        users: user_items,
        pagination: None,
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
    axum::extract::Path(user_uuid): axum::extract::Path<String>,
) -> Response {
    use crate::schema::users;
    use crate::templates::accounts::user_detail::UserDetail;

    let flash = incoming_flash.flash();

    let user = Some(user_context_from_auth(&auth_user));
    let base =
        BaseTemplate::new("User Details".to_string(), user).with_current_path("/accounts/users");

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
        last_login: last_login.map(|dt| dt.format("%b %d, %Y %H:%M").to_string()),
        created_at: created_at.format("%b %d, %Y").to_string(),
    };

    // Determine if current user can edit this user
    // Staff can edit non-superusers, superusers can edit anyone
    let can_edit = auth_user.is_superuser || (auth_user.is_staff && !is_superuser);

    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        base.into_fields();
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
) -> Result<impl IntoResponse, AppError> {
    use crate::templates::accounts::UserCreateTemplate;

    // Only staff or superuser can access
    if !auth_user.is_superuser && !auth_user.is_staff {
        return Err(AppError::Authorization(
            "You do not have permission to create users".to_string(),
        ));
    }

    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new("New User".to_string(), user).with_current_path("/accounts/users");

    let password_min_length = state.config.security.password_min_length;
    let can_manage_superusers = auth_user.is_superuser;

    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        base.into_fields();
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

    // Permission check
    if !auth_user.is_superuser && !auth_user.is_staff {
        return flash_redirect(
            flash.error("You do not have permission to create users"),
            "/accounts/users",
        );
    }

    // Check if trying to create a superuser without being a superuser
    let wants_superuser = form.is_superuser.as_deref() == Some("on");
    if wants_superuser && !auth_user.is_superuser {
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
    let min_len = state.config.security.password_min_length;
    if form.password.len() < min_len {
        return flash_redirect(
            flash.error(format!("Password must be at least {} characters", min_len)),
            "/accounts/users/new",
        );
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

    // Check for duplicate username or email
    let existing: Option<i32> = users::table
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

    if existing.is_some() {
        return flash_redirect(
            flash.error("Username or email already exists"),
            "/accounts/users/new",
        );
    }

    // Hash password
    let password_hash = match state.auth_service.hash_password(&form.password) {
        Ok(hash) => hash,
        Err(_) => {
            return flash_redirect(
                flash.error("Failed to process password. Please try again."),
                "/accounts/users/new",
            );
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
        Ok(_) => flash_redirect(
            flash.success(format!("User '{}' created successfully", form.username)),
            &format!("/accounts/users/{}", user_uuid),
        ),
        Err(_) => flash_redirect(
            flash.error("Failed to create user. Please try again."),
            "/accounts/users/new",
        ),
    }
}

/// User edit form page (GET /accounts/users/{uuid}/edit).
pub async fn user_edit_form(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    incoming_flash: IncomingFlash,
    axum::extract::Path(user_uuid): axum::extract::Path<String>,
) -> Response {
    use crate::schema::users;
    use crate::templates::accounts::{UserEditData, UserEditTemplate};

    let flash = incoming_flash.flash();

    // Only staff or superuser can access
    if !auth_user.is_superuser && !auth_user.is_staff {
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

    // Staff cannot edit superusers
    if is_superuser && !auth_user.is_superuser {
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
    let can_manage_superusers = auth_user.is_superuser;
    // Can delete if: superuser can delete anyone (except last superuser), staff can delete non-superusers
    let can_delete = auth_user.is_superuser || (auth_user.is_staff && !is_superuser);

    let user = Some(user_context_from_auth(&auth_user));
    let base =
        BaseTemplate::new("Edit User".to_string(), user).with_current_path("/accounts/users");

    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        base.into_fields();
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
    };

    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(_) => flash_redirect(flash.error("Failed to render page"), "/accounts/users"),
    }
}

/// Update user handler (POST /accounts/users/{uuid}).
pub async fn update_user_web(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    axum::extract::Path(user_uuid): axum::extract::Path<String>,
    Form(form): Form<UpdateUserWebForm>,
) -> Response {
    use crate::schema::users;
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

    // Permission check
    if !auth_user.is_superuser && !auth_user.is_staff {
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
                &format!("/accounts/users/{}/edit", user_uuid),
            );
        }
    };

    // Get current user data to check permissions
    let current_user: Option<(i32, bool)> = users::table
        .filter(users::uuid.eq(parsed_uuid))
        .filter(users::is_deleted.eq(false))
        .select((users::id, users::is_superuser))
        .first(&mut conn)
        .await
        .optional()
        .unwrap_or(None);

    let (user_id, target_is_superuser) = match current_user {
        Some(u) => u,
        None => {
            return flash_redirect(flash.error("User not found"), "/accounts/users");
        }
    };

    // Staff cannot edit superusers
    if target_is_superuser && !auth_user.is_superuser {
        return flash_redirect(
            flash.error("Only a superuser can edit superuser accounts"),
            &format!("/accounts/users/{}", user_uuid),
        );
    }

    // Staff cannot promote to superuser
    let wants_superuser = form.is_superuser.as_deref() == Some("on");
    if wants_superuser && !auth_user.is_superuser {
        return flash_redirect(
            flash.error("Only a superuser can grant superuser privileges"),
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

    // Check for duplicate username or email (excluding current user)
    let existing: Option<i32> = users::table
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

    if existing.is_some() {
        return flash_redirect(
            flash.error("Username or email already exists"),
            &format!("/accounts/users/{}/edit", user_uuid),
        );
    }

    // Validate and hash new password if provided
    let password_hash = if let Some(ref password) = form.password {
        if !password.is_empty() {
            let min_len = state.config.security.password_min_length;
            if password.len() < min_len {
                return flash_redirect(
                    flash.error(format!("Password must be at least {} characters", min_len)),
                    &format!("/accounts/users/{}/edit", user_uuid),
                );
            }
            match state.auth_service.hash_password(password) {
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

    let is_active = form.is_active.as_deref() == Some("on");
    let is_staff = form.is_staff.as_deref() == Some("on");
    let now = Utc::now();

    // Sanitize text fields to prevent stored XSS
    let sanitized_first_name = sanitize_opt_ref(form.first_name.as_ref().filter(|s| !s.is_empty()));
    let sanitized_last_name = sanitize_opt_ref(form.last_name.as_ref().filter(|s| !s.is_empty()));

    // Update with or without password
    let result = if let Some(ref hash) = password_hash {
        diesel::update(users::table.filter(users::id.eq(user_id)))
            .set((
                users::username.eq(&form.username),
                users::email.eq(&form.email),
                users::password_hash.eq(hash),
                users::first_name.eq(&sanitized_first_name),
                users::last_name.eq(&sanitized_last_name),
                users::is_active.eq(is_active),
                users::is_staff.eq(is_staff),
                users::is_superuser.eq(wants_superuser),
                users::updated_at.eq(now),
            ))
            .execute(&mut conn)
            .await
    } else {
        diesel::update(users::table.filter(users::id.eq(user_id)))
            .set((
                users::username.eq(&form.username),
                users::email.eq(&form.email),
                users::first_name.eq(&sanitized_first_name),
                users::last_name.eq(&sanitized_last_name),
                users::is_active.eq(is_active),
                users::is_staff.eq(is_staff),
                users::is_superuser.eq(wants_superuser),
                users::updated_at.eq(now),
            ))
            .execute(&mut conn)
            .await
    };

    match result {
        Ok(_) => flash_redirect(
            flash.success("User updated successfully"),
            &format!("/accounts/users/{}", user_uuid),
        ),
        Err(_) => flash_redirect(
            flash.error("Failed to update user. Please try again."),
            &format!("/accounts/users/{}/edit", user_uuid),
        ),
    }
}

/// Delete user handler (POST /accounts/users/{uuid}/delete).
/// Web only - not available via API.
pub async fn delete_user_web(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    axum::extract::Path(user_uuid): axum::extract::Path<String>,
    Form(form): Form<DeleteAssetForm>,
) -> Response {
    use crate::schema::users;
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

    // Permission check - must be staff or superuser
    if !auth_user.is_superuser && !auth_user.is_staff {
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
    let target_user: Option<(i32, bool, bool)> = users::table
        .filter(users::uuid.eq(parsed_uuid))
        .filter(users::is_deleted.eq(false))
        .select((users::id, users::is_superuser, users::is_active))
        .first(&mut conn)
        .await
        .optional()
        .unwrap_or(None);

    let (user_id, target_is_superuser, target_is_active) = match target_user {
        Some(u) => u,
        None => {
            return flash_redirect(
                flash.error("User not found or already deleted"),
                "/accounts/users",
            );
        }
    };

    // Staff cannot delete superusers
    if target_is_superuser && !auth_user.is_superuser {
        return flash_redirect(
            flash.error("Only a superuser can delete another superuser"),
            &format!("/accounts/users/{}", user_uuid),
        );
    }

    // Prevent deleting the last active superuser
    if target_is_superuser && target_is_active {
        let superuser_count: i64 = users::table
            .filter(users::is_superuser.eq(true))
            .filter(users::is_active.eq(true))
            .filter(users::is_deleted.eq(false))
            .count()
            .get_result(&mut conn)
            .await
            .unwrap_or(0);

        if superuser_count <= 1 {
            return flash_redirect(
                flash.error("Cannot delete the last active superuser"),
                &format!("/accounts/users/{}", user_uuid),
            );
        }
    }

    // Soft delete the user
    let now = Utc::now();
    let result = diesel::update(users::table.filter(users::id.eq(user_id)))
        .set((
            users::is_deleted.eq(true),
            users::deleted_at.eq(now),
            users::updated_at.eq(now),
        ))
        .execute(&mut conn)
        .await;

    match result {
        Ok(_) => flash_redirect(
            flash.success("User deleted successfully"),
            "/accounts/users",
        ),
        Err(_) => flash_redirect(
            flash.error("Failed to delete user. Please try again."),
            &format!("/accounts/users/{}", user_uuid),
        ),
    }
}

/// User profile page.
pub async fn profile(
    State(state): State<AppState>,
    jar: axum_extra::extract::CookieJar,
    auth_user: WebAuthUser,
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
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string()),
        created_at: db_user
            .created_at
            .format("%Y-%m-%d %H:%M:%S UTC")
            .to_string(),
        updated_at: db_user
            .updated_at
            .format("%Y-%m-%d %H:%M:%S UTC")
            .to_string(),
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
            let device_info = s.device_info.clone().unwrap_or_else(|| {
                AuthSession::parse_device_info(s.user_agent.as_deref().unwrap_or(""))
            });
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
    let base = BaseTemplate::new("My Profile".to_string(), user.clone())
        .with_current_path("/accounts/profile");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        base.into_fields();

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
    };

    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;
    Ok(Html(html))
}

/// MFA setup page (for authenticated users viewing their MFA status).
pub async fn mfa_setup(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
) -> Result<impl IntoResponse, AppError> {
    use crate::services::auth::AuthService;
    use ::uuid::Uuid as UuidType;

    let user = Some(user_context_from_auth(&auth_user));
    let base =
        BaseTemplate::new("MFA Setup".to_string(), user.clone()).with_current_path("/accounts/mfa");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        base.into_fields();

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;
    let user_uuid = UuidType::parse_str(&auth_user.uuid)
        .map_err(|_| AppError::Validation("Invalid user UUID".to_string()))?;

    // Get user's MFA secret or generate a new one
    let user_data: (i32, String, Option<String>) = crate::schema::users::table
        .filter(crate::schema::users::uuid.eq(user_uuid))
        .filter(crate::schema::users::is_deleted.eq(false))
        .select((
            crate::schema::users::id,
            crate::schema::users::username,
            crate::schema::users::mfa_secret,
        ))
        .first(&mut conn)
        .await
        .map_err(AppError::Database)?;

    let (user_id, user_username, existing_secret) = user_data;

    // Generate or use existing secret
    // M-1: When vault is available, secrets are encrypted at rest.
    // QR code is generated locally from the plaintext secret obtained from vault.
    let (secret, mut qr_code_base64) = if let Some(ref vault) = state.vault_client {
        if let Some(s) = existing_secret {
            if is_encrypted(&s) {
                // Get plaintext secret from vault (decrypt)
                let plaintext = vault.mfa_get_secret(&s).await.map_err(|e| {
                    AppError::Internal(anyhow::anyhow!("MFA secret decryption: {}", e))
                })?;
                let qr = AuthService::generate_totp_qr_code(
                    plaintext.as_str(),
                    &user_username,
                    "VAUBAN",
                )?;
                // plaintext (SensitiveString) zeroized on drop here
                (s, qr)
            } else {
                // Plaintext secret (pre-migration): encrypt-on-read, then generate QR
                let encrypted = vault.encrypt("mfa", &s).await.map_err(|e| {
                    AppError::Internal(anyhow::anyhow!("MFA encryption: {}", e))
                })?;
                diesel::update(
                    crate::schema::users::table.filter(crate::schema::users::id.eq(user_id)),
                )
                .set(crate::schema::users::mfa_secret.eq(Some(&encrypted)))
                .execute(&mut conn)
                .await
                .map_err(AppError::Database)?;
                tracing::info!(
                    user_id,
                    "Migrated plaintext MFA secret to encrypted (encrypt-on-read)"
                );
                // Get plaintext back from vault to generate QR
                let plaintext = vault.mfa_get_secret(&encrypted).await.map_err(|e| {
                    AppError::Internal(anyhow::anyhow!("MFA secret decryption: {}", e))
                })?;
                let qr = AuthService::generate_totp_qr_code(
                    plaintext.as_str(),
                    &user_username,
                    "VAUBAN",
                )?;
                // plaintext (SensitiveString) zeroized on drop here
                (encrypted, qr)
            }
        } else {
            // Generate new secret via vault
            let (encrypted_secret, plaintext) = vault
                .mfa_generate(&user_username, "VAUBAN")
                .await
                .map_err(|e| AppError::Internal(anyhow::anyhow!("MFA generation: {}", e)))?;
            let qr = AuthService::generate_totp_qr_code(
                plaintext.as_str(),
                &user_username,
                "VAUBAN",
            )?;
            // plaintext (SensitiveString) zeroized on drop here
            diesel::update(
                crate::schema::users::table.filter(crate::schema::users::id.eq(user_id)),
            )
            .set(crate::schema::users::mfa_secret.eq(Some(&encrypted_secret)))
            .execute(&mut conn)
            .await
            .map_err(AppError::Database)?;
            (encrypted_secret, qr)
        }
    } else {
        // Fallback: direct generation (dev mode without vault)
        let secret = if let Some(s) = existing_secret {
            s
        } else {
            let (new_secret, _uri) = AuthService::generate_totp_secret(&user_username, "VAUBAN")?;
            diesel::update(
                crate::schema::users::table.filter(crate::schema::users::id.eq(user_id)),
            )
            .set(crate::schema::users::mfa_secret.eq(Some(&new_secret)))
            .execute(&mut conn)
            .await
            .map_err(AppError::Database)?;
            new_secret
        };
        let qr = AuthService::generate_totp_qr_code(&secret, &user_username, "VAUBAN")?;
        (secret, qr)
    };

    let template = MfaSetupTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
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
) -> Result<impl IntoResponse, AppError> {
    use crate::models::AuthSession;
    use sha3::{Digest, Sha3_256};

    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new("My Sessions".to_string(), user.clone())
        .with_current_path("/accounts/sessions");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        base.into_fields();

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
            let device_info = s.device_info.clone().unwrap_or_else(|| {
                AuthSession::parse_device_info(s.user_agent.as_deref().unwrap_or(""))
            });
            // Determine if this is the current session by comparing token hashes
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
) -> Result<impl IntoResponse, AppError> {
    use crate::models::ApiKey;

    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new("API Keys".to_string(), user.clone())
        .with_current_path("/accounts/apikeys");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        base.into_fields();

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
            return Ok(Redirect::to("/accounts/sessions").into_response());
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
pub(crate) fn build_sessions_html(sessions: &[crate::models::AuthSession], client_token_hash: &str) -> String {
    use crate::models::AuthSession;

    if sessions.is_empty() {
        return r#"<li class="px-6 py-8 text-center text-gray-500 dark:text-gray-400">No active sessions</li>"#.to_string();
    }

    let mut html = String::new();
    for s in sessions {
        let device_info = s.device_info.clone().unwrap_or_else(|| {
            AuthSession::parse_device_info(s.user_agent.as_deref().unwrap_or(""))
        });
        // Determine if this is the current session by comparing token hashes
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
                r#"<form hx-post="/accounts/sessions/{}/revoke" hx-confirm="Are you sure you want to revoke this session?" hx-target="closest li" hx-swap="outerHTML">
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

/// Form data for creating an API key.
#[derive(Debug, serde::Deserialize)]
pub struct CreateApiKeyForm {
    pub name: String,
    pub scopes: Option<Vec<String>>,
    pub expires_in_days: Option<i64>,
    pub csrf_token: String,
}
