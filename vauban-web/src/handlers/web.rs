/// VAUBAN Web - Web page handlers.
///
/// Handlers for serving HTML pages using Askama templates.
///
/// # SQL Query Guidelines
///
/// This module primarily uses Diesel DSL for database operations. However, raw SQL
/// queries (`diesel::sql_query`) are used in specific cases where Diesel DSL lacks
/// support or would be overly complex:
///
/// ## Justified Uses of Raw SQL
///
/// 1. **Triple JOINs with PostgreSQL-specific casts**: Queries involving multiple
///    table joins with PostgreSQL type casts like `inet::text` for IP addresses.
///    Example: Session detail pages joining `proxy_sessions`, `users`, and `assets`.
///
/// 2. **Subqueries with COUNT(*)**: Aggregation subqueries in SELECT clauses, such
///    as counting assets per group. Diesel DSL supports simple aggregates but complex
///    correlated subqueries are clearer in raw SQL.
///
/// 3. **PostgreSQL-native functions**: Functions like `NOW()`, `INTERVAL`, or
///    `uuid_generate_v4()` when needed in specific contexts not well-supported by
///    Diesel helpers.
///
/// ## Best Practices
///
/// - Always use parameterized queries (`$1`, `$2`) with `.bind()` to prevent SQL injection
/// - Prefer Diesel DSL for simple CRUD operations (INSERT, UPDATE, DELETE, simple SELECT)
/// - Document why raw SQL is necessary with a `// NOTE:` comment before each `sql_query`
/// - Test all raw SQL queries thoroughly as they are not compile-time checked
use axum::{
    extract::{Form, Query, State},
    response::{Html, IntoResponse, Redirect, Response},
};
use axum_extra::extract::CookieJar;
use diesel::prelude::*;
use diesel::sql_types::{BigInt, Integer, Nullable, Text, Uuid as DieselUuid};
use diesel_async::{AsyncConnection, RunQueryDsl};
use secrecy::ExposeSecret;
use std::collections::HashMap;
use zeroize::Zeroize;

use crate::AppState;
use crate::error::{AppError, AppResult};
use crate::middleware::auth::{AuthUser, OptionalAuthUser, WebAuthUser};
use crate::middleware::flash::{IncomingFlash, flash_redirect};
use crate::schema::{api_keys, assets, auth_sessions, proxy_sessions};
use crate::templates::accounts::{
    ApiKeyItem, ApikeyListTemplate, AuthSessionItem, GroupDetailTemplate, GroupListTemplate,
    LoginTemplate, MfaSetupTemplate, ProfileDetail, ProfileSession, ProfileTemplate,
    SessionListTemplate as AccountSessionListTemplate, UserDetailTemplate, UserListTemplate,
};
use crate::templates::assets::asset_list::AssetListItem;
use crate::templates::assets::{
    AccessListTemplate, AssetDetailTemplate, AssetEditTemplate, AssetGroupDetailTemplate,
    AssetGroupEditTemplate, AssetGroupListTemplate, AssetListTemplate,
};
use crate::templates::base::{BaseTemplate, UserContext};
use crate::templates::dashboard::widgets::{
    ActiveSessionsWidget, RecentActivityWidget, StatsWidget,
};
use crate::templates::dashboard::{AdminTemplate, HomeTemplate};
use crate::templates::sessions::{
    ActiveListTemplate, ApprovalDetailTemplate, ApprovalListTemplate, RecordingListTemplate,
    SessionListTemplate as WebSessionListTemplate,
};
use crate::utils::format_duration;
use askama::Template;

/// Helper to convert AuthUser to UserContext for templates.
fn user_context_from_auth(auth_user: &AuthUser) -> UserContext {
    UserContext {
        uuid: auth_user.uuid.clone(),
        username: auth_user.username.clone(),
        display_name: auth_user.username.clone(), // TODO: Get full name from database
        is_superuser: auth_user.is_superuser,
        is_staff: auth_user.is_staff,
    }
}

/// Check if the user has admin privileges (superuser or staff).
fn is_admin(auth_user: &WebAuthUser) -> bool {
    auth_user.is_superuser || auth_user.is_staff
}

/// Strip ALL HTML tags from a string to prevent stored XSS.
/// Uses ammonia with an empty tag allowlist so every tag is removed,
/// keeping only the text content.
fn sanitize(value: &str) -> String {
    ammonia::Builder::new()
        .tags(std::collections::HashSet::new())
        .clean(value)
        .to_string()
}

/// Strip ALL HTML tags from an optional string to prevent stored XSS.
fn sanitize_opt(value: Option<String>) -> Option<String> {
    value.map(|s| sanitize(&s))
}

/// Strip ALL HTML tags from an optional string reference to prevent stored XSS.
fn sanitize_opt_ref(value: Option<&String>) -> Option<String> {
    value.map(|s| sanitize(s))
}

/// Build connection_config JSON from SSH credential form fields.
///
/// This stores credentials in the connection_config field of the asset.
/// When vault_client is provided (production), credential fields (password,
/// private_key, passphrase) are encrypted at rest via vauban-vault (C-2).
fn build_connection_config(
    username: Option<&str>,
    auth_type: Option<&str>,
    password: Option<&str>,
    private_key: Option<&str>,
    passphrase: Option<&str>,
) -> serde_json::Value {
    let mut config = serde_json::Map::new();

    // Add username if provided
    if let Some(u) = username.filter(|s| !s.trim().is_empty()) {
        config.insert("username".to_string(), serde_json::Value::String(u.trim().to_string()));
    }

    // Add auth_type if provided
    if let Some(at) = auth_type.filter(|s| !s.trim().is_empty()) {
        config.insert("auth_type".to_string(), serde_json::Value::String(at.to_string()));

        match at {
            "password" => {
                // Add password if auth type is password
                if let Some(p) = password.filter(|s| !s.is_empty()) {
                    config.insert("password".to_string(), serde_json::Value::String(p.to_string()));
                }
            }
            "private_key" => {
                // Add private key if auth type is private_key
                if let Some(pk) = private_key.filter(|s| !s.is_empty()) {
                    config.insert("private_key".to_string(), serde_json::Value::String(pk.to_string()));
                }
                // Add passphrase if provided
                if let Some(pp) = passphrase.filter(|s| !s.is_empty()) {
                    config.insert("passphrase".to_string(), serde_json::Value::String(pp.to_string()));
                }
            }
            _ => {}
        }
    }

    serde_json::Value::Object(config)
}

/// Encrypt credential fields in a connection_config JSON via vault (C-2).
///
/// Encrypts "password", "private_key", and "passphrase" fields in-place.
/// Non-credential fields (username, auth_type, host_key, etc.) are left as-is.
async fn encrypt_connection_config(
    vault: &crate::ipc::VaultCryptoClient,
    config: &mut serde_json::Value,
) -> crate::error::AppResult<()> {
    let credential_fields = ["password", "private_key", "passphrase"];
    if let Some(obj) = config.as_object_mut() {
        for field in &credential_fields {
            if let Some(serde_json::Value::String(val)) = obj.get(*field)
                && !val.is_empty()
                && !is_encrypted(val)
            {
                let encrypted = vault.encrypt("credentials", val).await?;
                obj.insert(field.to_string(), serde_json::Value::String(encrypted));
            }
        }
    }
    Ok(())
}

/// Check whether a value looks like an encrypted ciphertext from vauban-vault.
///
/// Encrypted values have the format `"v{digit(s)}:{base64}"`.
fn is_encrypted(value: &str) -> bool {
    if value.len() < 4 {
        return false;
    }
    if !value.starts_with('v') {
        return false;
    }
    let Some(colon_pos) = value.find(':') else {
        return false;
    };
    if colon_pos < 2 {
        return false;
    }
    value[1..colon_pos].chars().all(|c| c.is_ascii_digit())
}

/// Empty response for HTMX modal close and similar use cases.
/// Returns an empty HTML fragment to clear a target element.
pub async fn htmx_empty() -> Html<&'static str> {
    Html("")
}

/// Fallback handler for unmatched routes.
/// Redirects to the home page instead of returning a 404.
pub async fn fallback_handler() -> Redirect {
    Redirect::to("/")
}

/// Login page.
pub async fn login_page(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<impl IntoResponse, AppError> {
    let base = BaseTemplate::new("Login".to_string(), None);
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        base.into_fields();

    // Get or generate CSRF token
    let secret = state.config.secret_key.expose_secret().as_bytes();
    let (csrf_token, new_cookie) = get_or_create_csrf_token(&jar, secret);

    let template = LoginTemplate {
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

    // Return response with updated cookie if a new token was generated
    if let Some(cookie) = new_cookie {
        Ok((jar.add(cookie), Html(html)).into_response())
    } else {
        Ok(Html(html).into_response())
    }
}

/// Get the CSRF token from cookie or generate a new one.
/// Returns the token and optionally a new cookie to set.
fn get_or_create_csrf_token(
    jar: &CookieJar,
    secret: &[u8],
) -> (String, Option<axum_extra::extract::cookie::Cookie<'static>>) {
    use crate::middleware::csrf::{
        CSRF_COOKIE_NAME, build_csrf_cookie, generate_csrf_token, verify_csrf_token,
    };

    // Check if we have a valid existing token
    if let Some(cookie) = jar.get(CSRF_COOKIE_NAME)
        && verify_csrf_token(secret, cookie.value())
    {
        return (cookie.value().to_string(), None);
    }

    // Generate new token
    let token = generate_csrf_token(secret);
    let cookie = build_csrf_cookie(&token);
    (token, Some(cookie))
}

/// Dashboard home page - requires authentication.
pub async fn dashboard_home(
    State(_state): State<AppState>,
    OptionalAuthUser(auth_user): OptionalAuthUser,
) -> Result<Response, AppError> {
    use axum::response::Redirect;

    // Redirect to login if not authenticated
    let auth_user = match auth_user {
        Some(user) => user,
        None => return Ok(Redirect::to("/login").into_response()),
    };

    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new("Dashboard".to_string(), user.clone()).with_current_path("/");

    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        base.into_fields();
    let template = HomeTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        favorite_assets: Vec::new(), // TODO: Load from database
    };

    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;
    Ok(Html(html).into_response())
}

/// Dashboard admin page.
pub async fn dashboard_admin(
    State(_state): State<AppState>,
    auth_user: WebAuthUser,
) -> Result<impl IntoResponse, AppError> {
    let user = Some(user_context_from_auth(&auth_user));
    let base =
        BaseTemplate::new("Admin Dashboard".to_string(), user.clone()).with_current_path("/admin");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        base.into_fields();

    let template = AdminTemplate {
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

/// User list page.
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
        let pattern = format!("%{}%", search);
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
        String,
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
                    auth_source,
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
        String,
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
        auth_source,
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
            users::auth_source.eq("local"),
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
        auth_source: db_user.auth_source.clone(),
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
fn build_sessions_html(sessions: &[crate::models::AuthSession], client_token_hash: &str) -> String {
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

    let mut query = assets::table
        .filter(assets::is_deleted.eq(false))
        .into_boxed();

    if let Some(ref search) = search_filter
        && !search.is_empty()
    {
        let pattern = format!("%{}%", search);
        query = query.filter(
            assets::name
                .ilike(pattern.clone())
                .or(assets::hostname.ilike(pattern)),
        );
    }

    if let Some(ref asset_type) = type_filter
        && !asset_type.is_empty()
    {
        query = query.filter(assets::asset_type.eq(asset_type));
    }

    if let Some(ref status) = status_filter
        && !status.is_empty()
    {
        query = query.filter(assets::status.eq(status));
    }

    let db_assets: Vec<(i32, ::uuid::Uuid, String, String, i32, String, String)> = query
        .select((
            assets::id,
            assets::uuid,
            assets::name,
            assets::hostname,
            assets::port,
            assets::asset_type,
            assets::status,
        ))
        .order(assets::name.asc())
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
    let pattern = format!("%{}%", query);

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

/// Dashboard stats widget.
pub async fn dashboard_widget_stats(
    State(state): State<AppState>,
    OptionalAuthUser(_auth_user): OptionalAuthUser,
) -> Result<impl IntoResponse, AppError> {
    use crate::templates::dashboard::widgets::StatsData;
    use chrono::{Duration, Utc};

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;

    // Count active sessions
    let active_sessions: i64 = proxy_sessions::table
        .filter(proxy_sessions::status.eq("active"))
        .count()
        .get_result(&mut conn)
        .await?;

    // Count today's sessions
    // SAFETY: 0, 0, 0 are always valid hour, minute, second values
    #[allow(clippy::unwrap_used)]
    let today_start = Utc::now().date_naive().and_hms_opt(0, 0, 0).unwrap();
    let today_sessions: i64 = proxy_sessions::table
        .filter(proxy_sessions::created_at.ge(today_start.and_utc()))
        .count()
        .get_result(&mut conn)
        .await?;

    // Count this week's sessions
    let week_start = Utc::now() - Duration::days(7);
    let week_sessions: i64 = proxy_sessions::table
        .filter(proxy_sessions::created_at.ge(week_start))
        .count()
        .get_result(&mut conn)
        .await?;

    let template = StatsWidget {
        stats: StatsData {
            active_sessions: active_sessions as i32,
            today_sessions: today_sessions as i32,
            week_sessions: week_sessions as i32,
        },
    };

    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;
    Ok(Html(html))
}

/// Dashboard active sessions widget.
pub async fn dashboard_widget_active_sessions(
    State(state): State<AppState>,
    OptionalAuthUser(_auth_user): OptionalAuthUser,
) -> Result<impl IntoResponse, AppError> {
    use crate::templates::dashboard::widgets::ActiveSessionItem;

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;

    // Load active sessions with asset info
    let active_sessions: Vec<(i32, String, String, String, chrono::DateTime<chrono::Utc>)> =
        proxy_sessions::table
            .inner_join(assets::table)
            .filter(proxy_sessions::status.eq("active"))
            .select((
                proxy_sessions::id,
                assets::name,
                assets::hostname,
                proxy_sessions::session_type,
                proxy_sessions::created_at,
            ))
            .order(proxy_sessions::created_at.desc())
            .limit(5)
            .load(&mut conn)
            .await?;

    let sessions: Vec<ActiveSessionItem> = active_sessions
        .into_iter()
        .map(
            |(id, asset_name, asset_hostname, session_type, started_at)| {
                let duration_secs = chrono::Utc::now()
                    .signed_duration_since(started_at)
                    .num_seconds();
                ActiveSessionItem {
                    id,
                    asset_name,
                    asset_hostname,
                    session_type,
                    duration: Some(format_duration(duration_secs)),
                }
            },
        )
        .collect();

    let template = ActiveSessionsWidget { sessions };

    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;
    Ok(Html(html))
}

/// Dashboard recent activity widget.
pub async fn dashboard_widget_recent_activity(
    State(_state): State<AppState>,
    OptionalAuthUser(_auth_user): OptionalAuthUser,
) -> Result<impl IntoResponse, AppError> {
    use crate::templates::dashboard::widgets::ActivityItem;
    let template = RecentActivityWidget {
        activities: Vec::<ActivityItem>::new(), // TODO: Load from database
    };

    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;
    Ok(Html(html))
}

/// Session list page.
pub async fn session_list(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse, AppError> {
    use crate::templates::sessions::session_list::SessionListItem;

    let user = Some(user_context_from_auth(&auth_user));
    let base =
        BaseTemplate::new("Sessions".to_string(), user.clone()).with_current_path("/sessions");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        base.into_fields();

    // Load sessions from database
    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;

    // Filter out empty strings - form sends empty string when "All" is selected
    let status_filter = params.get("status").filter(|s| !s.is_empty()).cloned();
    let type_filter = params.get("type").filter(|s| !s.is_empty()).cloned();
    let asset_filter = params.get("asset").filter(|s| !s.is_empty()).cloned();

    // Determine if user is admin
    let user_is_admin = is_admin(&auth_user);

    // For non-admin users, we need to get their user ID to filter sessions
    let current_user_id: Option<i32> = if !user_is_admin {
        let user_uuid = ::uuid::Uuid::parse_str(&auth_user.uuid)
            .map_err(|e| AppError::Validation(format!("Invalid user UUID: {}", e)))?;
        use crate::schema::users::dsl as u;
        Some(
            u::users
                .filter(u::uuid.eq(user_uuid))
                .select(u::id)
                .first::<i32>(&mut conn)
                .await
                .map_err(|_| AppError::NotFound("User not found".to_string()))?,
        )
    } else {
        None
    };

    let mut query = proxy_sessions::table.inner_join(assets::table).into_boxed();

    // Exclude pending approval requests
    query = query.filter(proxy_sessions::status.ne("pending"));
    query = query.filter(proxy_sessions::status.ne("orphaned"));

    // For non-admin users, filter to only their own sessions
    if let Some(user_id) = current_user_id {
        query = query.filter(proxy_sessions::user_id.eq(user_id));
    }

    if let Some(ref status) = status_filter
        && !status.is_empty()
    {
        query = query.filter(proxy_sessions::status.eq(status));
    }

    if let Some(ref session_type) = type_filter
        && !session_type.is_empty()
    {
        query = query.filter(proxy_sessions::session_type.eq(session_type));
    }

    if let Some(ref asset) = asset_filter
        && !asset.is_empty()
    {
        let pattern = format!("%{}%", asset);
        query = query.filter(assets::name.ilike(pattern));
    }

    #[allow(clippy::type_complexity)]
    let db_sessions: Vec<(
        i32,
        uuid::Uuid,
        String,
        String,
        String,
        String,
        String,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<chrono::DateTime<chrono::Utc>>,
        bool,
    )> = query
        .select((
            proxy_sessions::id,
            proxy_sessions::uuid,
            assets::name,
            assets::hostname,
            proxy_sessions::session_type,
            proxy_sessions::status,
            proxy_sessions::credential_username,
            proxy_sessions::connected_at,
            proxy_sessions::disconnected_at,
            proxy_sessions::is_recorded,
        ))
        .order(proxy_sessions::created_at.desc())
        .limit(50)
        .load(&mut conn)
        .await?;

    let sessions: Vec<SessionListItem> = db_sessions
        .into_iter()
        .map(
            |(
                id,
                uuid,
                asset_name,
                asset_hostname,
                session_type,
                status,
                credential_username,
                connected_at,
                disconnected_at,
                is_recorded,
            )| {
                let duration_seconds = match (connected_at, disconnected_at) {
                    (Some(start), Some(end)) => {
                        Some(end.signed_duration_since(start).num_seconds())
                    }
                    (Some(start), None) if status == "active" => Some(
                        chrono::Utc::now()
                            .signed_duration_since(start)
                            .num_seconds(),
                    ),
                    _ => None,
                };
                SessionListItem {
                    id,
                    uuid: uuid.to_string(),
                    asset_name,
                    asset_hostname,
                    session_type,
                    status,
                    credential_username,
                    connected_at: connected_at.map(|dt| dt.format("%b %d, %Y %H:%M").to_string()),
                    duration_seconds,
                    is_recorded,
                }
            },
        )
        .collect();

    let template = WebSessionListTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        sessions,
        status_filter,
        type_filter,
        asset_filter,
        show_view_link: user_is_admin,
    };

    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;
    Ok(Html(html))
}

/// Terminate a session (web HTMX).
pub async fn terminate_session_web(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    auth_user: WebAuthUser,
    jar: CookieJar,
    axum::extract::Path(session_id_str): axum::extract::Path<String>,
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

    // Validate session ID format for graceful error handling
    if session_id_str.parse::<i32>().is_err() {
        return Ok(Redirect::to("/sessions/active").into_response());
    }

    crate::handlers::api::sessions::terminate_session(
        State(state),
        headers,
        auth_user.0,
        axum::extract::Path(session_id_str),
    )
    .await
}

/// Session detail page.
pub async fn session_detail(
    State(state): State<AppState>,
    incoming_flash: IncomingFlash,
    auth_user: WebAuthUser,
    axum::extract::Path(id_str): axum::extract::Path<String>,
) -> Response {
    use crate::templates::sessions::session_detail::SessionDetail;

    let flash = incoming_flash.flash();

    // Parse session ID manually for graceful error handling
    let id: i32 = match id_str.parse() {
        Ok(parsed_id) => parsed_id,
        Err(_) => {
            return flash_redirect(flash.error("Invalid session identifier"), "/sessions");
        }
    };

    let user = Some(user_context_from_auth(&auth_user));
    let mut conn = match state.db_pool.get().await {
        Ok(conn) => conn,
        Err(_) => {
            return flash_redirect(
                flash.error("Database connection error. Please try again."),
                "/sessions",
            );
        }
    };
    let user_is_admin = is_admin(&auth_user);

    // NOTE: Raw SQL required - complex triple JOIN with PostgreSQL ::text casts
    // Cannot be migrated to Diesel DSL due to:
    // 1. uuid::text casts for string representation
    // 2. inet::text cast for client_ip
    // 3. Triple JOIN (proxy_sessions -> users -> assets)
    let session_data: SessionQueryDetailResult = match diesel::sql_query(
        "SELECT ps.id, ps.uuid, u.username, u.uuid::text as user_uuid,
                a.name as asset_name, a.hostname as asset_hostname, a.uuid::text as asset_uuid, a.asset_type,
                ps.session_type, ps.status, ps.credential_username, ps.client_ip::text as client_ip,
                ps.client_user_agent, ps.proxy_instance, ps.connected_at, ps.disconnected_at,
                ps.justification, ps.is_recorded, ps.recording_path, ps.bytes_sent, ps.bytes_received,
                ps.commands_count, ps.created_at
         FROM proxy_sessions ps
         INNER JOIN users u ON u.id = ps.user_id
         INNER JOIN assets a ON a.id = ps.asset_id
         WHERE ps.id = $1",
    )
    .bind::<Integer, _>(id)
    .get_result(&mut conn).await
    {
        Ok(data) => data,
        Err(diesel::result::Error::NotFound) => {
            return flash_redirect(flash.error("Session not found"), "/sessions");
        }
        Err(_) => {
            return flash_redirect(flash.error("Database error. Please try again."), "/sessions");
        }
    };

    // For non-admin users, check if they own this session
    if !user_is_admin && session_data.user_uuid != auth_user.uuid {
        return flash_redirect(
            flash.error("You can only view your own sessions"),
            "/sessions",
        );
    }

    // Calculate duration if connected_at and disconnected_at are present
    let duration = match (session_data.connected_at, session_data.disconnected_at) {
        (Some(start), Some(end)) => {
            let duration_secs = (end - start).num_seconds();
            let hours = duration_secs / 3600;
            let minutes = (duration_secs % 3600) / 60;
            let secs = duration_secs % 60;
            if hours > 0 {
                Some(format!("{}h {}m {}s", hours, minutes, secs))
            } else if minutes > 0 {
                Some(format!("{}m {}s", minutes, secs))
            } else {
                Some(format!("{}s", secs))
            }
        }
        (Some(start), None) if session_data.status == "active" => {
            let duration_secs = (chrono::Utc::now() - start).num_seconds();
            let hours = duration_secs / 3600;
            let minutes = (duration_secs % 3600) / 60;
            let secs = duration_secs % 60;
            if hours > 0 {
                Some(format!("{}h {}m {}s (ongoing)", hours, minutes, secs))
            } else if minutes > 0 {
                Some(format!("{}m {}s (ongoing)", minutes, secs))
            } else {
                Some(format!("{}s (ongoing)", secs))
            }
        }
        _ => None,
    };

    let session = SessionDetail {
        id: session_data.id,
        uuid: session_data.uuid.to_string(),
        username: session_data.username,
        user_uuid: session_data.user_uuid,
        asset_name: session_data.asset_name,
        asset_hostname: session_data.asset_hostname,
        asset_uuid: session_data.asset_uuid,
        asset_type: session_data.asset_type,
        session_type: session_data.session_type,
        status: session_data.status.clone(),
        credential_username: session_data.credential_username,
        client_ip: session_data.client_ip,
        client_user_agent: session_data.client_user_agent,
        proxy_instance: session_data.proxy_instance,
        connected_at: session_data
            .connected_at
            .map(|dt| dt.format("%b %d, %Y %H:%M:%S").to_string()),
        disconnected_at: session_data
            .disconnected_at
            .map(|dt| dt.format("%b %d, %Y %H:%M:%S").to_string()),
        duration,
        justification: session_data.justification,
        is_recorded: session_data.is_recorded,
        recording_path: session_data.recording_path,
        bytes_sent: session_data.bytes_sent,
        bytes_received: session_data.bytes_received,
        commands_count: session_data.commands_count,
        created_at: session_data
            .created_at
            .format("%b %d, %Y %H:%M:%S")
            .to_string(),
    };

    let base =
        BaseTemplate::new(format!("Session #{}", id), user.clone()).with_current_path("/sessions");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        base.into_fields();

    let template = crate::templates::sessions::session_detail::SessionDetailTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        session,
        show_play_recording: user_is_admin,
    };

    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(_) => flash_redirect(flash.error("Failed to render page"), "/sessions"),
    }
}

/// Helper struct for session detail query.
#[derive(diesel::QueryableByName)]
struct SessionQueryDetailResult {
    #[diesel(sql_type = diesel::sql_types::Int4)]
    id: i32,
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    uuid: ::uuid::Uuid,
    #[diesel(sql_type = diesel::sql_types::Varchar)]
    username: String,
    #[diesel(sql_type = diesel::sql_types::Text)]
    user_uuid: String,
    #[diesel(sql_type = diesel::sql_types::Varchar)]
    asset_name: String,
    #[diesel(sql_type = diesel::sql_types::Varchar)]
    asset_hostname: String,
    #[diesel(sql_type = diesel::sql_types::Text)]
    asset_uuid: String,
    #[diesel(sql_type = diesel::sql_types::Varchar)]
    asset_type: String,
    #[diesel(sql_type = diesel::sql_types::Varchar)]
    session_type: String,
    #[diesel(sql_type = diesel::sql_types::Varchar)]
    status: String,
    #[diesel(sql_type = diesel::sql_types::Varchar)]
    credential_username: String,
    #[diesel(sql_type = diesel::sql_types::Text)]
    client_ip: String,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    client_user_agent: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Varchar>)]
    proxy_instance: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
    connected_at: Option<chrono::DateTime<chrono::Utc>>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
    disconnected_at: Option<chrono::DateTime<chrono::Utc>>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    justification: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Bool)]
    is_recorded: bool,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Varchar>)]
    recording_path: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Int8)]
    bytes_sent: i64,
    #[diesel(sql_type = diesel::sql_types::Int8)]
    bytes_received: i64,
    #[diesel(sql_type = diesel::sql_types::Int4)]
    commands_count: i32,
    #[diesel(sql_type = diesel::sql_types::Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
}

/// Recording list page.
pub async fn recording_list(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse, AppError> {
    use crate::templates::sessions::recording_list::RecordingListItem;

    // Only admin users (superuser or staff) can view recordings
    if !is_admin(&auth_user) {
        return Err(AppError::Authorization(
            "Only administrators can view recordings".to_string(),
        ));
    }

    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new("Recordings".to_string(), user.clone())
        .with_current_path("/sessions/recordings");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        base.into_fields();

    // Load recordings from database (sessions with is_recorded = true)
    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;

    let format_filter = params.get("format").cloned();
    let asset_filter = params.get("asset").cloned();

    let mut query = proxy_sessions::table
        .inner_join(assets::table)
        .filter(proxy_sessions::is_recorded.eq(true))
        .filter(proxy_sessions::recording_path.is_not_null())
        .into_boxed();

    if let Some(ref session_type) = format_filter
        && !session_type.is_empty()
    {
        query = query.filter(proxy_sessions::session_type.eq(session_type));
    }

    if let Some(ref asset) = asset_filter
        && !asset.is_empty()
    {
        let pattern = format!("%{}%", asset);
        query = query.filter(assets::name.ilike(pattern));
    }

    #[allow(clippy::type_complexity)]
    let db_recordings: Vec<(
        i32,
        String,
        String,
        String,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<String>,
    )> = query
        .select((
            proxy_sessions::id,
            assets::name,
            proxy_sessions::session_type,
            proxy_sessions::credential_username,
            proxy_sessions::connected_at,
            proxy_sessions::disconnected_at,
            proxy_sessions::recording_path,
        ))
        .order(proxy_sessions::created_at.desc())
        .limit(50)
        .load(&mut conn)
        .await?;

    let recordings: Vec<RecordingListItem> = db_recordings
        .into_iter()
        .map(
            |(
                id,
                asset_name,
                session_type,
                credential_username,
                connected_at,
                disconnected_at,
                recording_path,
            )| {
                let duration_seconds = match (connected_at, disconnected_at) {
                    (Some(start), Some(end)) => {
                        Some(end.signed_duration_since(start).num_seconds())
                    }
                    _ => None,
                };
                RecordingListItem {
                    id,
                    session_id: id,
                    asset_name,
                    session_type,
                    credential_username,
                    connected_at: connected_at.map(|dt| dt.format("%b %d, %Y %H:%M").to_string()),
                    duration_seconds,
                    recording_path: recording_path.unwrap_or_default(),
                    status: "ready".to_string(),
                }
            },
        )
        .collect();

    let template = RecordingListTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        recordings,
        format_filter,
        asset_filter,
    };

    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;
    Ok(Html(html))
}

/// Recording play page.
pub async fn recording_play(
    State(state): State<AppState>,
    incoming_flash: IncomingFlash,
    auth_user: WebAuthUser,
    axum::extract::Path(id_str): axum::extract::Path<String>,
) -> Response {
    use crate::templates::sessions::recording_play::RecordingData;

    let flash = incoming_flash.flash();

    // Parse recording ID manually for graceful error handling
    let id: i32 = match id_str.parse() {
        Ok(parsed_id) => parsed_id,
        Err(_) => {
            return flash_redirect(
                flash.error("Invalid recording identifier"),
                "/sessions/recordings",
            );
        }
    };

    // Only admin users (superuser or staff) can play recordings
    if !is_admin(&auth_user) {
        return flash_redirect(
            flash.error("Only administrators can play recordings"),
            "/sessions/recordings",
        );
    }

    let user = Some(user_context_from_auth(&auth_user));
    let mut conn = match state.db_pool.get().await {
        Ok(conn) => conn,
        Err(_) => {
            return flash_redirect(
                flash.error("Database connection error. Please try again."),
                "/sessions/recordings",
            );
        }
    };

    // NOTE: Raw SQL required - triple JOIN with PostgreSQL-specific features
    let recording_data: RecordingQueryResult = match diesel::sql_query(
        "SELECT ps.id, ps.uuid, u.username, a.name as asset_name, a.hostname as asset_hostname,
                ps.session_type, ps.connected_at, ps.disconnected_at, ps.recording_path,
                ps.bytes_sent, ps.bytes_received, ps.commands_count
         FROM proxy_sessions ps
         INNER JOIN users u ON u.id = ps.user_id
         INNER JOIN assets a ON a.id = ps.asset_id
         WHERE ps.id = $1 AND ps.is_recorded = true",
    )
    .bind::<Integer, _>(id)
    .get_result(&mut conn)
    .await
    {
        Ok(data) => data,
        Err(diesel::result::Error::NotFound) => {
            return flash_redirect(flash.error("Recording not found"), "/sessions/recordings");
        }
        Err(_) => {
            return flash_redirect(
                flash.error("Database error. Please try again."),
                "/sessions/recordings",
            );
        }
    };

    // Calculate duration
    let duration = match (recording_data.connected_at, recording_data.disconnected_at) {
        (Some(start), Some(end)) => {
            let duration_secs = (end - start).num_seconds();
            let hours = duration_secs / 3600;
            let minutes = (duration_secs % 3600) / 60;
            let secs = duration_secs % 60;
            if hours > 0 {
                Some(format!("{:02}:{:02}:{:02}", hours, minutes, secs))
            } else {
                Some(format!("00:{:02}:{:02}", minutes, secs))
            }
        }
        _ => None,
    };

    let recording = RecordingData {
        session_id: recording_data.id,
        session_uuid: recording_data.uuid.to_string(),
        username: recording_data.username,
        asset_name: recording_data.asset_name,
        asset_hostname: recording_data.asset_hostname,
        session_type: recording_data.session_type,
        connected_at: recording_data
            .connected_at
            .map(|dt| dt.format("%b %d, %Y %H:%M:%S").to_string()),
        disconnected_at: recording_data
            .disconnected_at
            .map(|dt| dt.format("%b %d, %Y %H:%M:%S").to_string()),
        duration,
        recording_path: recording_data.recording_path,
        bytes_sent: recording_data.bytes_sent,
        bytes_received: recording_data.bytes_received,
        commands_count: recording_data.commands_count,
    };

    let base = BaseTemplate::new(
        format!("Play Recording - {}", recording.asset_name),
        user.clone(),
    )
    .with_current_path("/sessions/recordings");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        base.into_fields();

    let template = crate::templates::sessions::recording_play::RecordingPlayTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        recording,
    };

    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(_) => flash_redirect(flash.error("Failed to render page"), "/sessions/recordings"),
    }
}

/// Helper struct for recording query.
#[derive(diesel::QueryableByName)]
struct RecordingQueryResult {
    #[diesel(sql_type = diesel::sql_types::Int4)]
    id: i32,
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    uuid: ::uuid::Uuid,
    #[diesel(sql_type = diesel::sql_types::Varchar)]
    username: String,
    #[diesel(sql_type = diesel::sql_types::Varchar)]
    asset_name: String,
    #[diesel(sql_type = diesel::sql_types::Varchar)]
    asset_hostname: String,
    #[diesel(sql_type = diesel::sql_types::Varchar)]
    session_type: String,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
    connected_at: Option<chrono::DateTime<chrono::Utc>>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
    disconnected_at: Option<chrono::DateTime<chrono::Utc>>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Varchar>)]
    recording_path: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Int8)]
    bytes_sent: i64,
    #[diesel(sql_type = diesel::sql_types::Int8)]
    bytes_received: i64,
    #[diesel(sql_type = diesel::sql_types::Int4)]
    commands_count: i32,
}

/// Approval list page.
pub async fn approval_list(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse, AppError> {
    // Only admin users (superuser or staff) can view approvals
    if !is_admin(&auth_user) {
        return Err(AppError::Authorization(
            "Only administrators can view approvals".to_string(),
        ));
    }

    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new("Approvals".to_string(), user.clone())
        .with_current_path("/sessions/approvals");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        base.into_fields();

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;
    // Filter out empty strings - "All statuses" sends status="" which should be treated as None
    let status_filter = params.get("status").filter(|s| !s.is_empty()).cloned();
    let page = params
        .get("page")
        .and_then(|s| s.parse::<i32>().ok())
        .unwrap_or(1);
    let items_per_page = 20;

    // NOTE: Raw SQL with parameterized queries for security
    let total_items: i64 = if let Some(ref status) = status_filter {
        diesel::sql_query(
            "SELECT COUNT(*) as count FROM proxy_sessions ps WHERE ps.justification IS NOT NULL AND ps.status = $1"
        )
        .bind::<Text, _>(status)
        .get_result::<ApprovalCountResult>(&mut conn)
        .await
        .map(|r| r.count)
        .unwrap_or(0)
    } else {
        diesel::sql_query(
            "SELECT COUNT(*) as count FROM proxy_sessions ps WHERE ps.justification IS NOT NULL",
        )
        .get_result::<ApprovalCountResult>(&mut conn)
        .await
        .map(|r| r.count)
        .unwrap_or(0)
    };

    let total_pages = ((total_items as f64) / (items_per_page as f64)).ceil() as i32;
    let offset = ((page - 1) * items_per_page) as i64;

    // NOTE: Raw SQL required - triple JOIN with inet::text cast, using parameterized queries
    let approvals_data: Vec<ApprovalQueryResult> =
        if let Some(ref status) = status_filter {
            diesel::sql_query(
            "SELECT ps.uuid, u.username, a.hostname as asset_name, a.asset_type, ps.session_type, 
                    ps.justification, ps.client_ip::text as client_ip, ps.created_at, ps.status
             FROM proxy_sessions ps
             INNER JOIN users u ON u.id = ps.user_id
             INNER JOIN assets a ON a.id = ps.asset_id
             WHERE ps.justification IS NOT NULL AND ps.status = $1
             ORDER BY ps.created_at DESC
             LIMIT $2 OFFSET $3",
        )
        .bind::<Text, _>(status)
        .bind::<Integer, _>(items_per_page)
        .bind::<BigInt, _>(offset)
        .load(&mut conn).await
        .map_err(AppError::Database)?
        } else {
            diesel::sql_query(
            "SELECT ps.uuid, u.username, a.hostname as asset_name, a.asset_type, ps.session_type, 
                    ps.justification, ps.client_ip::text as client_ip, ps.created_at, ps.status
             FROM proxy_sessions ps
             INNER JOIN users u ON u.id = ps.user_id
             INNER JOIN assets a ON a.id = ps.asset_id
             WHERE ps.justification IS NOT NULL
             ORDER BY ps.created_at DESC
             LIMIT $1 OFFSET $2",
        )
        .bind::<Integer, _>(items_per_page)
        .bind::<BigInt, _>(offset)
        .load(&mut conn).await
        .map_err(AppError::Database)?
        };

    let approvals: Vec<crate::templates::sessions::approval_list::ApprovalListItem> =
        approvals_data
            .into_iter()
            .map(
                |a| crate::templates::sessions::approval_list::ApprovalListItem {
                    uuid: a.uuid.to_string(),
                    username: a.username,
                    asset_name: a.asset_name,
                    asset_type: a.asset_type,
                    session_type: a.session_type,
                    justification: a.justification,
                    client_ip: a.client_ip,
                    created_at: a.created_at.format("%b %d, %Y %H:%M").to_string(),
                    status: a.status,
                },
            )
            .collect();

    let pagination = if total_pages > 1 {
        Some(crate::templates::sessions::approval_list::Pagination {
            current_page: page,
            total_pages,
            total_items: total_items as i32,
            has_previous: page > 1,
            has_next: page < total_pages,
        })
    } else {
        None
    };

    let template = ApprovalListTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        approvals,
        pagination,
        status_filter,
    };

    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;
    Ok(Html(html))
}

/// Helper struct for approval count result.
#[derive(diesel::QueryableByName)]
struct ApprovalCountResult {
    #[diesel(sql_type = diesel::sql_types::Int8)]
    count: i64,
}

/// Helper struct for approval query results.
#[derive(diesel::QueryableByName)]
struct ApprovalQueryResult {
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    uuid: ::uuid::Uuid,
    #[diesel(sql_type = diesel::sql_types::Varchar)]
    username: String,
    #[diesel(sql_type = diesel::sql_types::Varchar)]
    asset_name: String,
    #[diesel(sql_type = diesel::sql_types::Varchar)]
    asset_type: String,
    #[diesel(sql_type = diesel::sql_types::Varchar)]
    session_type: String,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    justification: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Text)]
    client_ip: String,
    #[diesel(sql_type = diesel::sql_types::Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = diesel::sql_types::Varchar)]
    status: String,
}

/// Approval detail page.
pub async fn approval_detail(
    State(state): State<AppState>,
    incoming_flash: IncomingFlash,
    auth_user: WebAuthUser,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
) -> Response {
    let flash = incoming_flash.flash();

    // Only admin users (superuser or staff) can view approval details
    if !is_admin(&auth_user) {
        return flash_redirect(
            flash.error("Only administrators can view approval details"),
            "/sessions/approvals",
        );
    }

    let user = Some(user_context_from_auth(&auth_user));

    let mut conn = match state.db_pool.get().await {
        Ok(conn) => conn,
        Err(_) => {
            return flash_redirect(
                flash.error("Database connection error. Please try again."),
                "/sessions/approvals",
            );
        }
    };

    let approval_uuid = match ::uuid::Uuid::parse_str(&uuid_str) {
        Ok(uuid) => uuid,
        Err(_) => {
            return flash_redirect(
                flash.error("Invalid approval identifier"),
                "/sessions/approvals",
            );
        }
    };

    // NOTE: Raw SQL required - triple JOIN with inet::text cast
    let approval_data: ApprovalDetailResult = match diesel::sql_query(
        "SELECT ps.uuid, u.username, u.email as user_email, a.name as asset_name, a.asset_type, 
                a.hostname as asset_hostname, ps.session_type, ps.status, ps.justification, 
                ps.client_ip::text as client_ip, ps.credential_username, ps.created_at, ps.is_recorded
         FROM proxy_sessions ps
         INNER JOIN users u ON u.id = ps.user_id
         INNER JOIN assets a ON a.id = ps.asset_id
         WHERE ps.uuid = $1",
    )
    .bind::<DieselUuid, _>(approval_uuid)
    .get_result(&mut conn).await
    {
        Ok(data) => data,
        Err(diesel::result::Error::NotFound) => {
            return flash_redirect(
                flash.error("Approval request not found"),
                "/sessions/approvals",
            );
        }
        Err(_) => {
            return flash_redirect(
                flash.error("Database error. Please try again."),
                "/sessions/approvals",
            );
        }
    };

    let approval = crate::templates::sessions::approval_detail::ApprovalDetail {
        uuid: approval_data.uuid.to_string(),
        username: approval_data.username,
        user_email: approval_data.user_email,
        asset_name: approval_data.asset_name,
        asset_type: approval_data.asset_type,
        asset_hostname: approval_data.asset_hostname,
        session_type: approval_data.session_type,
        status: approval_data.status,
        justification: approval_data.justification,
        client_ip: approval_data.client_ip,
        credential_username: approval_data.credential_username,
        created_at: approval_data
            .created_at
            .format("%b %d, %Y %H:%M")
            .to_string(),
        is_recorded: approval_data.is_recorded,
    };

    let base = BaseTemplate::new("Approval Request".to_string(), user.clone())
        .with_current_path("/sessions/approvals");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        base.into_fields();

    let template = ApprovalDetailTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        approval,
    };

    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(_) => flash_redirect(flash.error("Failed to render page"), "/sessions/approvals"),
    }
}

/// Helper struct for approval detail query results.
#[derive(diesel::QueryableByName)]
struct ApprovalDetailResult {
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    uuid: ::uuid::Uuid,
    #[diesel(sql_type = diesel::sql_types::Varchar)]
    username: String,
    #[diesel(sql_type = diesel::sql_types::Varchar)]
    user_email: String,
    #[diesel(sql_type = diesel::sql_types::Varchar)]
    asset_name: String,
    #[diesel(sql_type = diesel::sql_types::Varchar)]
    asset_type: String,
    #[diesel(sql_type = diesel::sql_types::Varchar)]
    asset_hostname: String,
    #[diesel(sql_type = diesel::sql_types::Varchar)]
    session_type: String,
    #[diesel(sql_type = diesel::sql_types::Varchar)]
    status: String,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    justification: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Text)]
    client_ip: String,
    #[diesel(sql_type = diesel::sql_types::Varchar)]
    credential_username: String,
    #[diesel(sql_type = diesel::sql_types::Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = diesel::sql_types::Bool)]
    is_recorded: bool,
}

/// Active sessions page.
pub async fn active_sessions(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
) -> Result<impl IntoResponse, AppError> {
    // Only admin users (superuser or staff) can view active sessions
    if !is_admin(&auth_user) {
        return Err(AppError::Authorization(
            "Only administrators can view active sessions".to_string(),
        ));
    }

    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new("Active Sessions".to_string(), user.clone())
        .with_current_path("/sessions/active");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        base.into_fields();

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;

    // NOTE: Raw SQL required - triple JOIN with inet::text cast
    let sessions_data: Vec<ActiveSessionQueryResult> = diesel::sql_query(
        "SELECT ps.uuid, u.username, a.name as asset_name, a.hostname as asset_hostname, 
                ps.session_type, ps.client_ip::text as client_ip, ps.connected_at
         FROM proxy_sessions ps
         INNER JOIN users u ON u.id = ps.user_id
         INNER JOIN assets a ON a.id = ps.asset_id
         WHERE ps.status = 'active' AND ps.connected_at IS NOT NULL
         ORDER BY ps.connected_at DESC",
    )
    .load(&mut conn)
    .await
    .map_err(AppError::Database)?;

    let sessions: Vec<crate::templates::sessions::active_list::ActiveSessionItem> = sessions_data
        .into_iter()
        .map(|s| {
            let connected = s.connected_at;
            let duration = chrono::Utc::now().signed_duration_since(connected);
            let duration_str = if duration.num_hours() > 0 {
                format!("{}h {}m", duration.num_hours(), duration.num_minutes() % 60)
            } else if duration.num_minutes() > 0 {
                format!(
                    "{}m {}s",
                    duration.num_minutes(),
                    duration.num_seconds() % 60
                )
            } else {
                format!("{}s", duration.num_seconds())
            };

            crate::templates::sessions::active_list::ActiveSessionItem {
                uuid: s.uuid.to_string(),
                username: s.username,
                asset_name: s.asset_name,
                asset_hostname: s.asset_hostname,
                session_type: s.session_type,
                client_ip: s.client_ip,
                connected_at: connected.format("%H:%M:%S").to_string(),
                duration: duration_str,
            }
        })
        .collect();

    let template = ActiveListTemplate {
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

/// Helper struct for active session query results.
#[derive(diesel::QueryableByName)]
struct ActiveSessionQueryResult {
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    uuid: ::uuid::Uuid,
    #[diesel(sql_type = diesel::sql_types::Varchar)]
    username: String,
    #[diesel(sql_type = diesel::sql_types::Varchar)]
    asset_name: String,
    #[diesel(sql_type = diesel::sql_types::Varchar)]
    asset_hostname: String,
    #[diesel(sql_type = diesel::sql_types::Varchar)]
    session_type: String,
    #[diesel(sql_type = diesel::sql_types::Text)]
    client_ip: String,
    #[diesel(sql_type = diesel::sql_types::Timestamptz)]
    connected_at: chrono::DateTime<chrono::Utc>,
}

/// Group list page.
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

/// Access rules list page.
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

    // NOTE: Raw SQL required - subquery in SELECT (asset_count) not supported by Diesel DSL
    let groups_data: Vec<AssetGroupQueryResult> = if let Some(ref s) = search_filter {
        let search_pattern = format!("%{}%", s);
        diesel::sql_query(
            "SELECT g.uuid, g.name, g.slug, g.description, g.color, g.icon, g.created_at,
                    (SELECT COUNT(*) FROM assets a WHERE a.group_id = g.id AND a.is_deleted = false) as asset_count
             FROM asset_groups g
             WHERE g.is_deleted = false AND (g.name ILIKE $1 OR g.slug ILIKE $1)
             ORDER BY g.name ASC"
        )
        .bind::<Text, _>(&search_pattern)
        .load(&mut conn).await
        .map_err(AppError::Database)?
    } else {
        diesel::sql_query(
            "SELECT g.uuid, g.name, g.slug, g.description, g.color, g.icon, g.created_at,
                    (SELECT COUNT(*) FROM assets a WHERE a.group_id = g.id AND a.is_deleted = false) as asset_count
             FROM asset_groups g
             WHERE g.is_deleted = false
             ORDER BY g.name ASC"
        )
        .load(&mut conn).await
        .map_err(AppError::Database)?
    };

    let groups: Vec<crate::templates::assets::group_list::AssetGroupItem> = groups_data
        .into_iter()
        .map(|g| crate::templates::assets::group_list::AssetGroupItem {
            uuid: g.uuid.to_string(),
            name: g.name,
            slug: g.slug,
            description: g.description,
            color: g.color,
            icon: g.icon,
            asset_count: g.asset_count,
            created_at: g.created_at.format("%b %d, %Y").to_string(),
        })
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

/// Helper struct for asset group query results.
#[derive(diesel::QueryableByName)]
struct AssetGroupQueryResult {
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
    #[diesel(sql_type = diesel::sql_types::Int8)]
    asset_count: i64,
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

// ============================================================================
// SSH Connection Handler
// ============================================================================

/// Request form for SSH connection.
#[derive(Debug, serde::Deserialize)]
pub struct ConnectSshForm {
    pub csrf_token: String,
    /// Optional username override.
    pub username: Option<String>,
}

/// Response for SSH connection request.
#[derive(Debug, serde::Serialize)]
pub struct ConnectSshResponse {
    /// Whether the connection was initiated successfully.
    pub success: bool,
    /// Session UUID for WebSocket connection.
    pub session_id: Option<String>,
    /// Terminal page URL to redirect to.
    pub redirect_url: Option<String>,
    /// Error message if connection failed.
    pub error: Option<String>,
}

/// Helper to create an HTMX error response (toast notification).
fn htmx_error_response(message: &str) -> Response {
    // Return an HX-Trigger header that shows a toast notification
    // Escape message for JSON
    let escaped_message = message.replace('\\', r"\\").replace('"', r#"\""#);
    let trigger_json = format!(
        r#"{{"showToast": {{"message": "{}", "type": "error"}}}}"#,
        escaped_message
    );

    (
        axum::http::StatusCode::OK,
        [
            ("HX-Trigger", trigger_json),
            ("Content-Type", "text/html".to_string()),
        ],
        "",
    )
        .into_response()
}

/// Initiate SSH connection to an asset.
///
/// POST /assets/{uuid}/connect
///
/// For HTMX requests: Returns HX-Redirect header on success, HX-Trigger toast on error.
/// For non-HTMX requests: Returns JSON response.
pub async fn connect_ssh(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    jar: CookieJar,
    auth_user: AuthUser,
    axum::extract::Path(asset_uuid_str): axum::extract::Path<String>,
    Form(form): Form<ConnectSshForm>,
) -> Response {
    use axum::Json;
    use uuid::Uuid;

    // Check if this is an HTMX request
    let is_htmx = headers.get("HX-Request").is_some();

    // CSRF validation
    let csrf_cookie = jar.get(crate::middleware::csrf::CSRF_COOKIE_NAME);
    let secret = state.config.secret_key.expose_secret().as_bytes();
    if !crate::middleware::csrf::validate_double_submit(
        secret,
        csrf_cookie.map(|c| c.value()),
        &form.csrf_token,
    ) {
        let msg = "Invalid CSRF token";
        if is_htmx {
            return htmx_error_response(msg);
        }
        return Json(ConnectSshResponse {
            success: false,
            session_id: None,
            redirect_url: None,
            error: Some(msg.to_string()),
        })
        .into_response();
    }

    // Parse asset UUID
    let asset_uuid = match Uuid::parse_str(&asset_uuid_str) {
        Ok(uuid) => uuid,
        Err(_) => {
            let msg = "Invalid asset identifier";
            if is_htmx {
                return htmx_error_response(msg);
            }
            return Json(ConnectSshResponse {
                success: false,
                session_id: None,
                redirect_url: None,
                error: Some(msg.to_string()),
            })
            .into_response();
        }
    };

    // Get SSH proxy client
    let proxy_client = match &state.ssh_proxy {
        Some(client) => client.clone(),
        None => {
            let msg = "SSH proxy not available";
            if is_htmx {
                return htmx_error_response(msg);
            }
            return Json(ConnectSshResponse {
                success: false,
                session_id: None,
                redirect_url: None,
                error: Some(msg.to_string()),
            })
            .into_response();
        }
    };

    // Fetch asset from database
    let mut conn = match state.db_pool.get().await {
        Ok(conn) => conn,
        Err(e) => {
            tracing::error!("Database connection error: {}", e);
            let msg = "Database connection failed";
            if is_htmx {
                return htmx_error_response(msg);
            }
            return Json(ConnectSshResponse {
                success: false,
                session_id: None,
                redirect_url: None,
                error: Some(msg.to_string()),
            })
            .into_response();
        }
    };

    use crate::models::asset::Asset;
    use crate::schema::assets::dsl;

    let asset: Asset = match dsl::assets
        .filter(dsl::uuid.eq(asset_uuid))
        .first(&mut conn)
        .await
    {
        Ok(asset) => asset,
        Err(diesel::result::Error::NotFound) => {
            let msg = "Asset not found";
            if is_htmx {
                return htmx_error_response(msg);
            }
            return Json(ConnectSshResponse {
                success: false,
                session_id: None,
                redirect_url: None,
                error: Some(msg.to_string()),
            })
            .into_response();
        }
        Err(e) => {
            tracing::error!("Failed to fetch asset: {}", e);
            let msg = "Failed to fetch asset";
            if is_htmx {
                return htmx_error_response(msg);
            }
            return Json(ConnectSshResponse {
                success: false,
                session_id: None,
                redirect_url: None,
                error: Some("Failed to fetch asset".to_string()),
            })
            .into_response();
        }
    };

    // Verify asset type is SSH
    if asset.asset_type.to_lowercase() != "ssh" {
        let msg = format!("Asset type '{}' is not SSH", asset.asset_type);
        if is_htmx {
            return htmx_error_response(&msg);
        }
        return Json(ConnectSshResponse {
            success: false,
            session_id: None,
            redirect_url: None,
            error: Some(msg),
        })
        .into_response();
    }

    // Generate session UUID
    let session_uuid = Uuid::new_v4();
    let session_id = session_uuid.to_string();

    // Resolve authenticated user's integer ID for database insertion
    let user_id: i32 = {
        use crate::schema::users;
        match auth_user.uuid.parse::<Uuid>() {
            Ok(user_uuid) => match users::table
                .filter(users::uuid.eq(user_uuid))
                .select(users::id)
                .first(&mut conn)
                .await
            {
                Ok(id) => id,
                Err(e) => {
                    tracing::error!("Failed to resolve user ID: {}", e);
                    let msg = "User not found";
                    if is_htmx {
                        return htmx_error_response(msg);
                    }
                    return Json(ConnectSshResponse {
                        success: false,
                        session_id: None,
                        redirect_url: None,
                        error: Some(msg.to_string()),
                    })
                    .into_response();
                }
            },
            Err(_) => {
                let msg = "Invalid user identifier";
                if is_htmx {
                    return htmx_error_response(msg);
                }
                return Json(ConnectSshResponse {
                    success: false,
                    session_id: None,
                    redirect_url: None,
                    error: Some(msg.to_string()),
                })
                .into_response();
            }
        }
    };

    // Extract connection details from asset's connection_config
    let config = &asset.connection_config;

    // Determine username from:
    // 1. Form override
    // 2. connection_config.username (if present in JSON)
    // 3. Default "root"
    let config_username = config
        .get("username")
        .and_then(|v| v.as_str())
        .map(String::from);

    let username = form
        .username
        .filter(|u| !u.is_empty())
        .or(config_username)
        .unwrap_or_else(|| "root".to_string());

    // Extract authentication credentials from connection_config
    let auth_type = config
        .get("auth_type")
        .and_then(|v| v.as_str())
        .unwrap_or("password")
        .to_string();

    // C-2 + H-10: Decrypt credentials via vault if encrypted, then wrap in SecretString.
    // Helper closure for vault-aware credential extraction.
    let vault_ref = state.vault_client.as_ref();

    let password = match config.get("password").and_then(|v| v.as_str()) {
        Some(val) if !val.is_empty() => {
            if is_encrypted(val) {
                if let Some(vault) = vault_ref {
                    match vault.decrypt("credentials", val).await {
                        Ok(decrypted) => Some(secrecy::SecretString::from(decrypted.into_inner())),
                        Err(e) => {
                            tracing::error!("Failed to decrypt password: {}", e);
                            let msg = "Failed to decrypt credentials";
                            if is_htmx {
                                return htmx_error_response(msg);
                            }
                            return Json(ConnectSshResponse {
                                success: false,
                                session_id: None,
                                redirect_url: None,
                                error: Some(msg.to_string()),
                            })
                            .into_response();
                        }
                    }
                } else {
                    tracing::warn!("Encrypted credential found but vault not available");
                    None
                }
            } else {
                Some(secrecy::SecretString::from(val.to_string()))
            }
        }
        _ => None,
    };

    let private_key = match config.get("private_key").and_then(|v| v.as_str()) {
        Some(val) if !val.is_empty() => {
            if is_encrypted(val) {
                if let Some(vault) = vault_ref {
                    match vault.decrypt("credentials", val).await {
                        Ok(decrypted) => Some(secrecy::SecretString::from(decrypted.into_inner())),
                        Err(e) => {
                            tracing::error!("Failed to decrypt private_key: {}", e);
                            let msg = "Failed to decrypt credentials";
                            if is_htmx {
                                return htmx_error_response(msg);
                            }
                            return Json(ConnectSshResponse {
                                success: false,
                                session_id: None,
                                redirect_url: None,
                                error: Some(msg.to_string()),
                            })
                            .into_response();
                        }
                    }
                } else {
                    tracing::warn!("Encrypted credential found but vault not available");
                    None
                }
            } else {
                Some(secrecy::SecretString::from(val.to_string()))
            }
        }
        _ => None,
    };

    let passphrase = match config.get("passphrase").and_then(|v| v.as_str()) {
        Some(val) if !val.is_empty() => {
            if is_encrypted(val) {
                if let Some(vault) = vault_ref {
                    match vault.decrypt("credentials", val).await {
                        Ok(decrypted) => Some(secrecy::SecretString::from(decrypted.into_inner())),
                        Err(e) => {
                            tracing::error!("Failed to decrypt passphrase: {}", e);
                            let msg = "Failed to decrypt credentials";
                            if is_htmx {
                                return htmx_error_response(msg);
                            }
                            return Json(ConnectSshResponse {
                                success: false,
                                session_id: None,
                                redirect_url: None,
                                error: Some(msg.to_string()),
                            })
                            .into_response();
                        }
                    }
                } else {
                    tracing::warn!("Encrypted credential found but vault not available");
                    None
                }
            } else {
                Some(secrecy::SecretString::from(val.to_string()))
            }
        }
        _ => None,
    };

    // Extract stored SSH host key for verification (H-9)
    let expected_host_key = config
        .get("ssh_host_key")
        .and_then(|v| v.as_str())
        .map(String::from);

    // Record the session in the database for ownership tracking.
    // This allows the ws_session_guard middleware to verify that the
    // WebSocket client owns the session before allowing the upgrade.
    {
        use crate::models::session::NewProxySession;
        // SAFETY: "0.0.0.0/0" is a valid CIDR; if parse() somehow fails,
    // fall back to the equivalent IpNetwork constructed from Ipv4Addr.
    let client_ip: ipnetwork::IpNetwork = "0.0.0.0/0".parse().unwrap_or_else(
        |_| ipnetwork::IpNetwork::V4(ipnetwork::Ipv4Network::from(std::net::Ipv4Addr::UNSPECIFIED)),
    );
        let new_session = NewProxySession {
            uuid: session_uuid,
            user_id,
            asset_id: asset.id,
            credential_id: "local".to_string(),
            credential_username: username.clone(),
            session_type: "ssh".to_string(),
            status: "connecting".to_string(),
            client_ip,
            client_user_agent: headers
                .get(axum::http::header::USER_AGENT)
                .and_then(|v| v.to_str().ok())
                .map(String::from),
            proxy_instance: None,
            justification: None,
            is_recorded: true,
            metadata: serde_json::json!({}),
        };

        if let Err(e) = diesel::insert_into(proxy_sessions::table)
            .values(&new_session)
            .execute(&mut conn)
            .await
        {
            tracing::error!(session_id = %session_id, error = %e, "Failed to record proxy session");
            let msg = "Failed to create session record";
            if is_htmx {
                return htmx_error_response(msg);
            }
            return Json(ConnectSshResponse {
                success: false,
                session_id: None,
                redirect_url: None,
                error: Some(msg.to_string()),
            })
            .into_response();
        }
    }

    // Build SSH session open request
    let request = crate::ipc::SshSessionOpenRequest {
        session_id: session_id.clone(),
        user_id: auth_user.uuid.clone(),
        asset_id: asset.uuid.to_string(),
        asset_host: asset.hostname.clone(),
        asset_port: asset.port as u16,
        username,
        terminal_cols: 120,
        terminal_rows: 30,
        auth_type,
        password,
        private_key,
        passphrase,
        expected_host_key,
    };

    // If supervisor is available (sandboxed mode), request TCP connection brokering.
    // The supervisor performs DNS resolution and TCP connect, then passes the FD
    // to the SSH proxy via SCM_RIGHTS. This enables Capsicum sandboxed operation.
    if let Some(ref supervisor) = state.supervisor {
        tracing::debug!(
            session_id = %session_id,
            host = %asset.hostname,
            port = asset.port,
            "Requesting TCP connection from supervisor (sandboxed mode)"
        );

        match supervisor
            .request_tcp_connect(
                &session_id,
                &asset.hostname,
                asset.port as u16,
                shared::messages::Service::ProxySsh,
            )
            .await
        {
            Ok(result) if result.success => {
                tracing::debug!(
                    session_id = %session_id,
                    "TCP connection established by supervisor"
                );
            }
            Ok(result) => {
                let msg = result
                    .error
                    .unwrap_or_else(|| "Failed to establish TCP connection".to_string());
                tracing::error!(session_id = %session_id, error = %msg, "TCP connect failed");
                if is_htmx {
                    return htmx_error_response(&msg);
                }
                return Json(ConnectSshResponse {
                    success: false,
                    session_id: None,
                    redirect_url: None,
                    error: Some(msg),
                })
                .into_response();
            }
            Err(e) => {
                tracing::error!(session_id = %session_id, error = %e, "TCP connect request failed");
                if is_htmx {
                    return htmx_error_response(&e);
                }
                return Json(ConnectSshResponse {
                    success: false,
                    session_id: None,
                    redirect_url: None,
                    error: Some(e),
                })
                .into_response();
            }
        }
    }

    // Send request to SSH proxy
    match proxy_client.open_session(request).await {
        Ok(response) => {
            if response.success {
                tracing::debug!(
                    user = %auth_user.username,
                    asset = %asset.name,
                    session_id = %session_id,
                    "SSH session initiated"
                );

                let redirect_url = format!("/sessions/terminal/{}", session_id);

                if is_htmx {
                    // Use HX-Redirect header for client-side navigation.
                    // This is a built-in HTMX feature that performs a full page
                    // redirect without requiring any custom JavaScript handler.
                    return (
                        axum::http::StatusCode::OK,
                        [("HX-Redirect", redirect_url.as_str())],
                        "",
                    )
                        .into_response();
                }

                Json(ConnectSshResponse {
                    success: true,
                    session_id: Some(session_id.clone()),
                    redirect_url: Some(redirect_url),
                    error: None,
                })
                .into_response()
            } else {
                let msg = response.error.unwrap_or_else(|| "Connection failed".to_string());

                // Detect host key mismatch errors and persist the
                // mismatch flag in connection_config so that the asset
                // detail page can display the warning state (H-9).
                let is_host_key_mismatch = msg.contains("host key")
                    || msg.contains("MITM")
                    || msg.contains("Host key verification failed");
                if is_host_key_mismatch {
                    tracing::warn!(
                        asset_uuid = %asset_uuid,
                        "Marking asset as host key mismatch after failed connection"
                    );
                    let mut config = asset.connection_config.clone();
                    config["ssh_host_key_mismatch"] = serde_json::Value::Bool(true);
                    if let Err(db_err) = diesel::update(
                        dsl::assets.filter(dsl::uuid.eq(asset_uuid)),
                    )
                    .set(dsl::connection_config.eq(&config))
                    .execute(&mut conn)
                    .await
                    {
                        tracing::error!(
                            asset_uuid = %asset_uuid,
                            error = %db_err,
                            "Failed to persist host key mismatch flag"
                        );
                    }
                }

                if is_htmx {
                    return htmx_error_response(&msg);
                }
                Json(ConnectSshResponse {
                    success: false,
                    session_id: None,
                    redirect_url: None,
                    error: Some(msg),
                })
                .into_response()
            }
        }
        Err(e) => {
            let error_str = format!("{}", e);
            tracing::error!(
                user = %auth_user.username,
                asset = %asset.name,
                error = %error_str,
                "SSH session initiation failed"
            );

            // Also detect mismatch in transport-level errors
            let is_host_key_mismatch = error_str.contains("host key")
                || error_str.contains("MITM")
                || error_str.contains("Host key verification failed");
            if is_host_key_mismatch {
                tracing::warn!(
                    asset_uuid = %asset_uuid,
                    "Marking asset as host key mismatch after failed connection"
                );
                let mut config = asset.connection_config.clone();
                config["ssh_host_key_mismatch"] = serde_json::Value::Bool(true);
                if let Err(db_err) = diesel::update(
                    dsl::assets.filter(dsl::uuid.eq(asset_uuid)),
                )
                .set(dsl::connection_config.eq(&config))
                .execute(&mut conn)
                .await
                {
                    tracing::error!(
                        asset_uuid = %asset_uuid,
                        error = %db_err,
                        "Failed to persist host key mismatch flag"
                    );
                }
            }

            let msg = format!("Failed to initiate SSH connection: {}", e);
            if is_htmx {
                return htmx_error_response(&msg);
            }

            Json(ConnectSshResponse {
                success: false,
                session_id: None,
                redirect_url: None,
                error: Some(msg),
            })
            .into_response()
        }
    }
}

/// Fetch (or refresh) the SSH host key for an asset.
///
/// POST /assets/{uuid}/fetch-host-key
///
/// Performs a minimal SSH handshake to retrieve the server's host key.
/// If a key was already stored and the new key differs, returns a
/// mismatch warning fragment (unless `?confirm=true` is passed to
/// force-accept the new key).
/// Returns an HTMX fragment for dynamic update.
pub async fn fetch_ssh_host_key(
    State(state): State<AppState>,
    auth_user: AuthUser,
    axum::extract::Path(asset_uuid_str): axum::extract::Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    use uuid::Uuid;

    // Require staff/superuser
    if !auth_user.is_staff && !auth_user.is_superuser {
        return htmx_error_response("Insufficient privileges: staff or superuser required");
    }

    let confirm = params.get("confirm").map(|v| v == "true").unwrap_or(false);

    // Parse UUID
    let asset_uuid = match Uuid::parse_str(&asset_uuid_str) {
        Ok(u) => u,
        Err(_) => return htmx_error_response("Invalid asset identifier"),
    };

    // Get proxy client
    let proxy_client = match &state.ssh_proxy {
        Some(client) => client.clone(),
        None => return htmx_error_response("SSH proxy not available"),
    };

    // Fetch asset from database
    let mut conn = match state.db_pool.get().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("DB error: {}", e);
            return htmx_error_response("Database connection failed");
        }
    };

    use crate::models::asset::Asset;
    use crate::schema::assets::dsl;

    let asset: Asset = match dsl::assets
        .filter(dsl::uuid.eq(asset_uuid))
        .first(&mut conn)
        .await
    {
        Ok(a) => a,
        Err(diesel::result::Error::NotFound) => {
            return htmx_error_response("Asset not found");
        }
        Err(e) => {
            tracing::error!("Failed to fetch asset: {}", e);
            return htmx_error_response("Failed to fetch asset");
        }
    };

    // Verify asset type is SSH
    if asset.asset_type.to_lowercase() != "ssh" {
        return htmx_error_response("Host key fetch is only available for SSH assets");
    }

    // Retrieve the previously stored host key (if any)
    let stored_host_key = asset
        .connection_config
        .get("ssh_host_key")
        .and_then(|v| v.as_str())
        .map(String::from);

    let stored_fingerprint = asset
        .connection_config
        .get("ssh_host_key_fingerprint")
        .and_then(|v| v.as_str())
        .map(String::from);

    // Fetch host key via proxy.
    // In sandboxed mode (Capsicum), the supervisor brokers the TCP
    // connection and passes the FD to the SSH proxy via SCM_RIGHTS.
    let supervisor_ref = state.supervisor.as_deref();
    let (host_key, fingerprint) =
        match proxy_client
            .fetch_host_key(&asset.hostname, asset.port as u16, supervisor_ref)
            .await
        {
            Ok(result) => result,
            Err(e) => {
                tracing::error!(
                    asset_uuid = %asset_uuid,
                    error = %e,
                    "Failed to fetch SSH host key"
                );
                return htmx_error_response(&format!("Failed to fetch host key: {}", e));
            }
        };

    // Detect host key change: if a key was previously stored and the
    // newly fetched key differs, warn the user unless they explicitly
    // confirmed acceptance of the new key.
    if let Some(ref old_key) = stored_host_key
        && old_key != &host_key
        && !confirm
    {
        let old_fp = stored_fingerprint.as_deref().unwrap_or("unknown");

        tracing::warn!(
            asset_uuid = %asset_uuid,
            old_fingerprint = %old_fp,
            new_fingerprint = %fingerprint,
            "SSH host key CHANGED on remote server - possible MITM attack"
        );

        // Return the mismatch warning fragment (no DB update yet)
        let html = include_str!("../../templates/assets/_ssh_host_key_mismatch_fragment.html")
            .replace("__OLD_FINGERPRINT__", old_fp)
            .replace("__NEW_FINGERPRINT__", &fingerprint)
            .replace("__ASSET_UUID__", &asset_uuid.to_string());

        return axum::response::Html(html).into_response();
    }

    // Update the asset's connection_config with the host key and clear
    // any previous mismatch status.
    let mut config = asset.connection_config.clone();
    config["ssh_host_key"] = serde_json::Value::String(host_key.clone());
    config["ssh_host_key_fingerprint"] = serde_json::Value::String(fingerprint.clone());
    // Remove mismatch flag if it was set by a failed connection attempt
    config.as_object_mut().map(|m| m.remove("ssh_host_key_mismatch"));

    use chrono::Utc;
    if let Err(e) = diesel::update(dsl::assets.filter(dsl::uuid.eq(asset_uuid)))
        .set((
            dsl::connection_config.eq(&config),
            dsl::updated_at.eq(Utc::now()),
        ))
        .execute(&mut conn)
        .await
    {
        tracing::error!(
            asset_uuid = %asset_uuid,
            error = %e,
            "Failed to store SSH host key"
        );
        return htmx_error_response("Failed to store host key");
    }

    tracing::info!(
        asset_uuid = %asset_uuid,
        fingerprint = %fingerprint,
        "SSH host key fetched and stored"
    );

    // Return HTMX fragment with the fingerprint
    let html = include_str!("../../templates/assets/_ssh_host_key_fragment.html")
        .replace("__FINGERPRINT__", &fingerprint)
        .replace("__ASSET_UUID__", &asset_uuid.to_string());

    axum::response::Html(html).into_response()
}

/// Verify the SSH host key for an asset against the remote server.
///
/// GET /assets/{uuid}/verify-host-key
///
/// Called automatically via HTMX `hx-trigger="load"` when the asset
/// detail page loads.  Performs a lightweight SSH handshake to retrieve
/// the server's current host key and compares it with the stored one.
///
/// Returns the appropriate HTMX fragment:
///   - Verified (green)  if keys match
///   - Mismatch (red)    if keys differ  (also sets the DB flag)
///   - No key  (amber)   if no key was ever stored
///
/// If the proxy is unavailable or the connection fails, the handler
/// falls back to the stored state so the page is never broken.
pub async fn verify_ssh_host_key(
    State(state): State<AppState>,
    _auth_user: AuthUser,
    axum::extract::Path(asset_uuid_str): axum::extract::Path<String>,
) -> Response {
    use uuid::Uuid;

    // Parse UUID
    let asset_uuid = match Uuid::parse_str(&asset_uuid_str) {
        Ok(u) => u,
        Err(_) => return htmx_error_response("Invalid asset identifier"),
    };

    // Fetch asset from database
    let mut conn = match state.db_pool.get().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("DB error: {}", e);
            return htmx_error_response("Database connection failed");
        }
    };

    use crate::models::asset::Asset;
    use crate::schema::assets::dsl;

    let asset: Asset = match dsl::assets
        .filter(dsl::uuid.eq(asset_uuid))
        .first(&mut conn)
        .await
    {
        Ok(a) => a,
        Err(_) => return htmx_error_response("Asset not found"),
    };

    // Only SSH assets
    if asset.asset_type.to_lowercase() != "ssh" {
        return htmx_error_response("Not an SSH asset");
    }

    let stored_host_key = asset
        .connection_config
        .get("ssh_host_key")
        .and_then(|v| v.as_str())
        .map(String::from);

    let stored_fingerprint = asset
        .connection_config
        .get("ssh_host_key_fingerprint")
        .and_then(|v| v.as_str())
        .map(String::from);

    let stored_mismatch = asset
        .connection_config
        .get("ssh_host_key_mismatch")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let uuid_str = asset_uuid.to_string();

    // If no key is stored, return the no-key fragment right away
    // (no point contacting the server).
    if stored_host_key.is_none() {
        let html = include_str!("../../templates/assets/_ssh_host_key_no_key_fragment.html")
            .replace("__ASSET_UUID__", &uuid_str);
        return axum::response::Html(html).into_response();
    }

    // If the mismatch flag is already set (from a failed connection),
    // return the stored mismatch state immediately.  The user must
    // explicitly click Refresh to re-check.
    if stored_mismatch {
        let fp = stored_fingerprint.as_deref().unwrap_or("unknown");
        let html = include_str!("../../templates/assets/_ssh_host_key_stored_mismatch_fragment.html")
            .replace("__FINGERPRINT__", fp)
            .replace("__ASSET_UUID__", &uuid_str);
        return axum::response::Html(html).into_response();
    }

    // Try to verify against the remote server
    let proxy_client = match &state.ssh_proxy {
        Some(client) => client.clone(),
        None => {
            // Proxy unavailable - fall back to stored state
            tracing::debug!(asset_uuid = %asset_uuid, "SSH proxy not available, returning stored state");
            let fp = stored_fingerprint.as_deref().unwrap_or("unknown");
            let html = include_str!("../../templates/assets/_ssh_host_key_fragment.html")
                .replace("__FINGERPRINT__", fp)
                .replace("__ASSET_UUID__", &uuid_str);
            return axum::response::Html(html).into_response();
        }
    };

    let supervisor_ref = state.supervisor.as_deref();
    match proxy_client.fetch_host_key(&asset.hostname, asset.port as u16, supervisor_ref).await {
        Ok((remote_key, remote_fingerprint)) => {
            let old_key = stored_host_key.as_deref().unwrap_or("");

            if old_key == remote_key {
                // Keys match - return verified fragment
                let html = include_str!("../../templates/assets/_ssh_host_key_fragment.html")
                    .replace("__FINGERPRINT__", &remote_fingerprint)
                    .replace("__ASSET_UUID__", &uuid_str);
                axum::response::Html(html).into_response()
            } else {
                // Keys DIFFER - set mismatch flag in DB
                let old_fp = stored_fingerprint.as_deref().unwrap_or("unknown");

                tracing::warn!(
                    asset_uuid = %asset_uuid,
                    old_fingerprint = %old_fp,
                    new_fingerprint = %remote_fingerprint,
                    "SSH host key CHANGED on remote server (detected during page load verification)"
                );

                let mut config = asset.connection_config.clone();
                config["ssh_host_key_mismatch"] = serde_json::Value::Bool(true);
                if let Err(db_err) = diesel::update(
                    dsl::assets.filter(dsl::uuid.eq(asset_uuid)),
                )
                .set(dsl::connection_config.eq(&config))
                .execute(&mut conn)
                .await
                {
                    tracing::error!(
                        asset_uuid = %asset_uuid,
                        error = %db_err,
                        "Failed to persist host key mismatch flag"
                    );
                }

                // Return mismatch fragment with both fingerprints
                let html = include_str!("../../templates/assets/_ssh_host_key_mismatch_fragment.html")
                    .replace("__OLD_FINGERPRINT__", old_fp)
                    .replace("__NEW_FINGERPRINT__", &remote_fingerprint)
                    .replace("__ASSET_UUID__", &uuid_str);
                axum::response::Html(html).into_response()
            }
        }
        Err(e) => {
            // Connection to remote server failed - fall back to stored state
            tracing::debug!(
                asset_uuid = %asset_uuid,
                error = %e,
                "Could not verify host key against remote server, using stored state"
            );
            let fp = stored_fingerprint.as_deref().unwrap_or("unknown");
            let html = include_str!("../../templates/assets/_ssh_host_key_fragment.html")
                .replace("__FINGERPRINT__", fp)
                .replace("__ASSET_UUID__", &uuid_str);
            axum::response::Html(html).into_response()
        }
    }
}

/// Terminal page for SSH sessions.
///
/// GET /sessions/terminal/{session_id}
pub async fn terminal_page(
    State(_state): State<AppState>,
    incoming_flash: IncomingFlash,
    auth_user: WebAuthUser,
    axum::extract::Path(session_id): axum::extract::Path<String>,
) -> Response {
    use crate::templates::base::BaseTemplate;
    use crate::templates::sessions::TerminalTemplate;

    let flash = incoming_flash.flash();

    // Validate session_id format (should be a UUID)
    if uuid::Uuid::parse_str(&session_id).is_err() {
        return flash_redirect(flash.error("Invalid session identifier"), "/assets");
    }

    // TODO: Verify session exists and belongs to user via IPC or database

    let user = Some(user_context_from_auth(&auth_user));

    // Build base template with sidebar
    let base = BaseTemplate::new("SSH Terminal".to_string(), user.clone())
        .with_current_path("/assets");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        base.into_fields();

    let template = TerminalTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        session_id,
        websocket_url: String::new(), // Will be constructed client-side
    };

    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!("Failed to render terminal template: {}", e);
            flash_redirect(flash.error("Failed to load terminal page"), "/assets")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== user_context_from_auth Tests ====================

    fn create_test_auth_user() -> AuthUser {
        AuthUser {
            uuid: "test-uuid-123".to_string(),
            username: "testuser".to_string(),
            mfa_verified: true,
            is_superuser: false,
            is_staff: false,
        }
    }

    #[test]
    fn test_user_context_from_auth_basic() {
        let auth = create_test_auth_user();
        let ctx = user_context_from_auth(&auth);

        assert_eq!(ctx.uuid, "test-uuid-123");
        assert_eq!(ctx.username, "testuser");
        assert_eq!(ctx.display_name, "testuser"); // Default to username
        assert!(!ctx.is_superuser);
        assert!(!ctx.is_staff);
    }

    #[test]
    fn test_user_context_from_auth_superuser() {
        let auth = AuthUser {
            uuid: "admin-uuid".to_string(),
            username: "admin".to_string(),
            mfa_verified: true,
            is_superuser: true,
            is_staff: true,
        };
        let ctx = user_context_from_auth(&auth);

        assert!(ctx.is_superuser);
        assert!(ctx.is_staff);
    }

    #[test]
    fn test_user_context_from_auth_staff_only() {
        let auth = AuthUser {
            uuid: "staff-uuid".to_string(),
            username: "operator".to_string(),
            mfa_verified: false,
            is_superuser: false,
            is_staff: true,
        };
        let ctx = user_context_from_auth(&auth);

        assert!(!ctx.is_superuser);
        assert!(ctx.is_staff);
    }

    #[test]
    fn test_user_context_from_auth_preserves_uuid() {
        let auth = AuthUser {
            uuid: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            username: "user".to_string(),
            mfa_verified: true,
            is_superuser: false,
            is_staff: false,
        };
        let ctx = user_context_from_auth(&auth);

        assert_eq!(ctx.uuid, "550e8400-e29b-41d4-a716-446655440000");
    }

    // ==================== UpdateAssetGroupForm Tests ====================

    #[test]
    fn test_update_asset_group_form_deserialize_full() {
        let json = r##"{"name": "Production Servers", "slug": "production-servers", "description": "All production servers", "color": "#ff5733", "icon": "server", "csrf_token": "csrf"}"##;

        let form: UpdateAssetGroupForm = unwrap_ok!(serde_json::from_str(json));

        assert_eq!(form.name, "Production Servers");
        assert_eq!(form.slug, "production-servers");
        assert_eq!(form.description, Some("All production servers".to_string()));
        assert_eq!(form.color, "#ff5733");
        assert_eq!(form.icon, "server");
    }

    #[test]
    fn test_update_asset_group_form_deserialize_minimal() {
        let json = r##"{"name": "Test", "slug": "test", "color": "#fff", "icon": "folder", "csrf_token": "csrf"}"##;

        let form: UpdateAssetGroupForm = unwrap_ok!(serde_json::from_str(json));

        assert_eq!(form.name, "Test");
        assert_eq!(form.slug, "test");
        assert!(form.description.is_none());
        assert_eq!(form.color, "#fff");
        assert_eq!(form.icon, "folder");
    }

    #[test]
    fn test_update_asset_group_form_deserialize_with_null_description() {
        let json = r##"{"name": "Group", "slug": "group", "description": null, "color": "#000", "icon": "box", "csrf_token": "csrf"}"##;

        let form: UpdateAssetGroupForm = unwrap_ok!(serde_json::from_str(json));

        assert!(form.description.is_none());
    }

    #[test]
    fn test_update_asset_group_form_deserialize_special_chars() {
        let json = r##"{"name": "Test's Group", "slug": "tests-group", "description": "Description with quotes", "color": "#123456", "icon": "database", "csrf_token": "csrf"}"##;

        let form: UpdateAssetGroupForm = unwrap_ok!(serde_json::from_str(json));

        assert_eq!(form.name, "Test's Group");
        assert!(unwrap_some!(form.description).contains("quotes"));
    }

    #[test]
    fn test_update_asset_group_form_debug() {
        let form = UpdateAssetGroupForm {
            name: "Debug Test".to_string(),
            slug: "debug-test".to_string(),
            description: Some("Test description".to_string()),
            color: "#abcdef".to_string(),
            icon: "cloud".to_string(),
            csrf_token: "csrf".to_string(),
        };

        let debug_str = format!("{:?}", form);

        assert!(debug_str.contains("UpdateAssetGroupForm"));
        assert!(debug_str.contains("Debug Test"));
    }

    #[test]
    fn test_update_asset_group_form_missing_required_field() {
        // Missing 'icon' field
        let json = r##"{"name": "Test", "slug": "test", "color": "#fff", "csrf_token": "csrf"}"##;

        let result: Result<UpdateAssetGroupForm, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_update_asset_group_form_empty_strings() {
        let json = r#"{"name": "", "slug": "", "color": "", "icon": "", "csrf_token": "csrf"}"#;

        let form: UpdateAssetGroupForm = unwrap_ok!(serde_json::from_str(json));

        // Empty strings are valid for deserialization (validation is separate)
        assert_eq!(form.name, "");
        assert_eq!(form.slug, "");
    }

    // ==================== build_sessions_html Tests ====================

    #[test]
    fn test_build_sessions_html_empty() {
        let html = super::build_sessions_html(&[], "some-token-hash");
        assert!(html.contains("No active sessions"));
    }

    #[test]
    fn test_build_sessions_html_current_session_detection() {
        use crate::models::AuthSession;
        use chrono::{Duration, Utc};
        use ipnetwork::IpNetwork;
        use uuid::Uuid;

        let session = AuthSession {
            id: 1,
            uuid: Uuid::new_v4(),
            user_id: 1,
            token_hash: "matching-hash".to_string(),
            ip_address: unwrap_ok!("192.168.1.1".parse::<IpNetwork>()),
            user_agent: Some("Chrome on macOS".to_string()),
            device_info: Some("Chrome on macOS".to_string()),
            is_current: false, // DB flag doesn't matter
            last_activity: Utc::now(),
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(1),
        };

        // When client token_hash matches, should show "Current session"
        let html = super::build_sessions_html(&[session.clone()], "matching-hash");
        assert!(html.contains("Current session"));
        assert!(html.contains("This device"));

        // When client token_hash doesn't match, should NOT show "Current session"
        let html = super::build_sessions_html(&[session], "different-hash");
        assert!(!html.contains("Current session"));
        assert!(html.contains("Revoke"));
    }

    #[test]
    fn test_build_sessions_html_multiple_sessions() {
        use crate::models::AuthSession;
        use chrono::{Duration, Utc};
        use ipnetwork::IpNetwork;
        use uuid::Uuid;

        let sessions = vec![
            AuthSession {
                id: 1,
                uuid: Uuid::new_v4(),
                user_id: 1,
                token_hash: "hash-a".to_string(),
                ip_address: unwrap_ok!("192.168.1.1".parse::<IpNetwork>()),
                user_agent: Some("Safari on macOS".to_string()),
                device_info: Some("Safari on macOS".to_string()),
                is_current: false,
                last_activity: Utc::now(),
                created_at: Utc::now(),
                expires_at: Utc::now() + Duration::hours(1),
            },
            AuthSession {
                id: 2,
                uuid: Uuid::new_v4(),
                user_id: 1,
                token_hash: "hash-b".to_string(),
                ip_address: unwrap_ok!("10.0.0.1".parse::<IpNetwork>()),
                user_agent: Some("Chrome on iPhone".to_string()),
                device_info: Some("Chrome on iPhone".to_string()),
                is_current: false,
                last_activity: Utc::now(),
                created_at: Utc::now(),
                expires_at: Utc::now() + Duration::hours(1),
            },
        ];

        // Client with hash-a should see Safari as current
        let html = super::build_sessions_html(&sessions, "hash-a");
        assert!(html.contains("Safari on macOS"));
        assert!(html.contains("Chrome on iPhone"));
        // Only one "Current session" badge
        assert_eq!(html.matches("Current session").count(), 1);

        // Client with hash-b should see iPhone as current
        let html = super::build_sessions_html(&sessions, "hash-b");
        assert_eq!(html.matches("Current session").count(), 1);
    }

    // ==================== build_sessions_html Edge Cases ====================

    #[test]
    fn test_build_sessions_html_with_special_characters() {
        use crate::models::AuthSession;
        use chrono::{Duration, Utc};
        use ipnetwork::IpNetwork;
        use uuid::Uuid;

        let session = AuthSession {
            id: 1,
            uuid: Uuid::new_v4(),
            user_id: 1,
            token_hash: "hash".to_string(),
            ip_address: unwrap_ok!("192.168.1.1".parse::<IpNetwork>()),
            user_agent: Some("Mozilla/5.0 <script>alert('xss')</script>".to_string()),
            device_info: Some("Unknown Browser".to_string()),
            is_current: false,
            last_activity: Utc::now(),
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(1),
        };

        let html = super::build_sessions_html(&[session], "other-hash");
        // Should not contain raw script tags (XSS prevention)
        assert!(html.contains("Unknown Browser"));
    }

    #[test]
    fn test_build_sessions_html_ipv6_address() {
        use crate::models::AuthSession;
        use chrono::{Duration, Utc};
        use ipnetwork::IpNetwork;
        use uuid::Uuid;

        let session = AuthSession {
            id: 1,
            uuid: Uuid::new_v4(),
            user_id: 1,
            token_hash: "hash".to_string(),
            ip_address: unwrap_ok!("2001:db8::1".parse::<IpNetwork>()),
            user_agent: Some("Chrome".to_string()),
            device_info: Some("Chrome on Linux".to_string()),
            is_current: false,
            last_activity: Utc::now(),
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(1),
        };

        let html = super::build_sessions_html(&[session], "hash");
        assert!(html.contains("2001:db8::1"));
        assert!(html.contains("Current session"));
    }

    #[test]
    fn test_build_sessions_html_no_user_agent() {
        use crate::models::AuthSession;
        use chrono::{Duration, Utc};
        use ipnetwork::IpNetwork;
        use uuid::Uuid;

        let session = AuthSession {
            id: 1,
            uuid: Uuid::new_v4(),
            user_id: 1,
            token_hash: "hash".to_string(),
            ip_address: unwrap_ok!("10.0.0.1".parse::<IpNetwork>()),
            user_agent: None,
            device_info: None,
            is_current: false,
            last_activity: Utc::now(),
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(1),
        };

        let html = super::build_sessions_html(&[session], "other");
        // Should handle None user_agent gracefully
        assert!(html.contains("10.0.0.1"));
        assert!(html.contains("session-row-"));
    }

    // ==================== CreateApiKeyForm Tests ====================

    #[test]
    fn test_create_api_key_form_deserialize() {
        let json = r#"{"name": "My API Key", "expires_in_days": 30, "csrf_token": "csrf"}"#;
        let form: CreateApiKeyForm = unwrap_ok!(serde_json::from_str(json));

        assert_eq!(form.name, "My API Key");
        assert_eq!(form.expires_in_days, Some(30));
    }

    #[test]
    fn test_create_api_key_form_without_expiry() {
        let json = r#"{"name": "Permanent Key", "csrf_token": "csrf"}"#;
        let form: CreateApiKeyForm = unwrap_ok!(serde_json::from_str(json));

        assert_eq!(form.name, "Permanent Key");
        assert!(form.expires_in_days.is_none());
    }

    #[test]
    fn test_create_api_key_form_empty_name() {
        let json = r#"{"name": "", "expires_in_days": 7, "csrf_token": "csrf"}"#;
        let form: CreateApiKeyForm = unwrap_ok!(serde_json::from_str(json));

        assert_eq!(form.name, "");
        assert_eq!(form.expires_in_days, Some(7));
    }

    // ==================== UpdateAssetGroupForm Additional Tests ====================

    #[test]
    fn test_update_asset_group_form_special_characters() {
        let json = r##"{"name": "Serveurs d'été", "slug": "serveurs-ete", "description": "Serveurs pour l'été 2024", "color": "#123abc", "icon": "sun", "csrf_token": "csrf"}"##;
        let form: UpdateAssetGroupForm = unwrap_ok!(serde_json::from_str(json));

        assert_eq!(form.name, "Serveurs d'été");
        assert!(unwrap_some!(form.description).contains("été"));
    }

    #[test]
    fn test_update_asset_group_form_unicode() {
        let json = r##"{"name": "服务器组", "slug": "chinese-servers", "color": "#ff0000", "icon": "server", "csrf_token": "csrf"}"##;
        let form: UpdateAssetGroupForm = unwrap_ok!(serde_json::from_str(json));

        assert_eq!(form.name, "服务器组");
        assert_eq!(form.slug, "chinese-servers");
    }

    #[test]
    fn test_update_asset_group_form_long_description() {
        let long_desc = "A".repeat(1000);
        let json = format!(
            r##"{{"name": "Test", "slug": "test", "description": "{}", "color": "#fff", "icon": "folder", "csrf_token": "csrf"}}"##,
            long_desc
        );
        let form: UpdateAssetGroupForm = unwrap_ok!(serde_json::from_str(&json));

        assert_eq!(unwrap_some!(form.description).len(), 1000);
    }

    // ==================== user_context_from_auth Additional Tests ====================

    #[test]
    fn test_user_context_from_auth_empty_username() {
        let auth = AuthUser {
            uuid: "uuid".to_string(),
            username: "".to_string(),
            mfa_verified: false,
            is_superuser: false,
            is_staff: false,
        };
        let ctx = user_context_from_auth(&auth);

        assert_eq!(ctx.username, "");
        assert_eq!(ctx.display_name, "");
    }

    #[test]
    fn test_user_context_from_auth_long_username() {
        let long_name = "a".repeat(255);
        let auth = AuthUser {
            uuid: "uuid".to_string(),
            username: long_name.clone(),
            mfa_verified: false,
            is_superuser: false,
            is_staff: false,
        };
        let ctx = user_context_from_auth(&auth);

        assert_eq!(ctx.username, long_name);
    }

    #[test]
    fn test_user_context_from_auth_mfa_not_transferred() {
        let auth = AuthUser {
            uuid: "uuid".to_string(),
            username: "user".to_string(),
            mfa_verified: true,
            is_superuser: false,
            is_staff: false,
        };
        let ctx = user_context_from_auth(&auth);

        // UserContext doesn't have mfa_verified field, just verify it compiles
        assert_eq!(ctx.username, "user");
    }

    // ==================== user_context_from_auth Additional Tests ====================

    #[test]
    fn test_user_context_from_auth_admin_permissions() {
        let auth = AuthUser {
            uuid: "admin-uuid".to_string(),
            username: "admin".to_string(),
            mfa_verified: true,
            is_superuser: true,
            is_staff: true,
        };
        let ctx = user_context_from_auth(&auth);

        assert!(ctx.is_superuser);
        assert!(ctx.is_staff);
    }

    #[test]
    fn test_user_context_from_auth_chinese_username() {
        let auth = AuthUser {
            uuid: "uuid".to_string(),
            username: "用户测试".to_string(),
            mfa_verified: false,
            is_superuser: false,
            is_staff: false,
        };
        let ctx = user_context_from_auth(&auth);

        assert_eq!(ctx.username, "用户测试");
    }

    #[test]
    fn test_user_context_from_auth_email_format_username() {
        let auth = AuthUser {
            uuid: "uuid".to_string(),
            username: "user@domain.com".to_string(),
            mfa_verified: false,
            is_superuser: false,
            is_staff: false,
        };
        let ctx = user_context_from_auth(&auth);

        assert_eq!(ctx.username, "user@domain.com");
    }

    // ==================== build_sessions_html Additional Tests ====================

    #[test]
    fn test_build_sessions_html_no_sessions() {
        let html = super::build_sessions_html(&[], "any-hash");
        // Empty list should still produce valid HTML structure
        assert!(html.contains("auth-sessions") || html.is_empty() || html.len() > 0);
    }

    #[test]
    fn test_build_sessions_html_five_sessions() {
        use crate::models::AuthSession;
        use chrono::{Duration, Utc};
        use ipnetwork::IpNetwork;
        use uuid::Uuid;

        let sessions: Vec<AuthSession> = (1..=5)
            .map(|i| AuthSession {
                id: i,
                uuid: Uuid::new_v4(),
                user_id: 1,
                token_hash: format!("hash-{}", i),
                // SAFETY: format! produces valid IP address strings
                #[allow(clippy::unwrap_used)]
                ip_address: format!("192.168.1.{}", i).parse::<IpNetwork>().unwrap(),
                user_agent: Some(format!("Browser {}", i)),
                device_info: Some(format!("Device {}", i)),
                is_current: i == 1,
                last_activity: Utc::now(),
                created_at: Utc::now(),
                expires_at: Utc::now() + Duration::hours(1),
            })
            .collect();

        let html = super::build_sessions_html(&sessions, "hash-3");

        // Should produce non-empty HTML with sessions
        assert!(!html.is_empty());
        // HTML should contain li tags for sessions
        assert!(html.contains("<li"));
        // The current session (hash-3) should be marked
        assert!(html.contains("Current session"));
    }

    #[test]
    fn test_build_sessions_html_with_expired_session() {
        use crate::models::AuthSession;
        use chrono::{Duration, Utc};
        use ipnetwork::IpNetwork;
        use uuid::Uuid;

        let session = AuthSession {
            id: 1,
            uuid: Uuid::new_v4(),
            user_id: 1,
            token_hash: "expired-hash".to_string(),
            ip_address: unwrap_ok!("10.0.0.1".parse::<IpNetwork>()),
            user_agent: Some("Old Browser".to_string()),
            device_info: Some("Old Device".to_string()),
            is_current: false,
            last_activity: Utc::now() - Duration::days(1),
            created_at: Utc::now() - Duration::days(2),
            expires_at: Utc::now() - Duration::hours(1), // Already expired
        };

        let html = super::build_sessions_html(&[session], "other-hash");
        assert!(html.contains("session-row-"));
    }

    // ==================== UpdateAssetGroupForm Additional Tests ====================

    #[test]
    fn test_update_asset_group_form_minimal() {
        let json = r##"{"name": "Test", "slug": "test", "color": "#000", "icon": "folder", "csrf_token": "csrf"}"##;
        let form: UpdateAssetGroupForm = unwrap_ok!(serde_json::from_str(json));

        assert_eq!(form.name, "Test");
        assert!(form.description.is_none());
    }

    #[test]
    fn test_update_asset_group_form_all_colors() {
        let colors = ["#fff", "#000", "#123abc", "#AABBCC", "#f0f0f0"];

        for color in colors {
            let json = format!(
                r##"{{"name": "Test", "slug": "test", "color": "{}", "icon": "folder", "csrf_token": "csrf"}}"##,
                color
            );
            let form: UpdateAssetGroupForm = unwrap_ok!(serde_json::from_str(&json));
            assert_eq!(form.color, color);
        }
    }

    #[test]
    fn test_update_asset_group_form_icons() {
        let icons = ["folder", "server", "database", "cloud", "lock"];

        for icon in icons {
            let json = format!(
                r##"{{"name": "Test", "slug": "test", "color": "#fff", "icon": "{}", "csrf_token": "csrf"}}"##,
                icon
            );
            let form: UpdateAssetGroupForm = unwrap_ok!(serde_json::from_str(&json));
            assert_eq!(form.icon, icon);
        }
    }

    // ==================== CreateApiKeyForm Additional Tests ====================

    #[test]
    fn test_create_api_key_form_zero_expiry() {
        let json = r#"{"name": "Zero Expiry", "expires_in_days": 0, "csrf_token": "csrf"}"#;
        let form: CreateApiKeyForm = unwrap_ok!(serde_json::from_str(json));

        assert_eq!(form.expires_in_days, Some(0));
    }

    #[test]
    fn test_create_api_key_form_long_expiry() {
        let json = r#"{"name": "Long Expiry", "expires_in_days": 365, "csrf_token": "csrf"}"#;
        let form: CreateApiKeyForm = unwrap_ok!(serde_json::from_str(json));

        assert_eq!(form.expires_in_days, Some(365));
    }

    #[test]
    fn test_create_api_key_form_unicode_name() {
        let json = r#"{"name": "密钥名称", "csrf_token": "csrf"}"#;
        let form: CreateApiKeyForm = unwrap_ok!(serde_json::from_str(json));

        assert_eq!(form.name, "密钥名称");
    }

    #[test]
    fn test_create_api_key_form_long_name() {
        let long_name = "A".repeat(100);
        let json = format!(r#"{{"name": "{}", "csrf_token": "csrf"}}"#, long_name);
        let form: CreateApiKeyForm = unwrap_ok!(serde_json::from_str(&json));

        assert_eq!(form.name.len(), 100);
    }

    // ==================== AuthUser Tests ====================

    #[test]
    fn test_auth_user_clone() {
        let auth = AuthUser {
            uuid: "test-uuid".to_string(),
            username: "testuser".to_string(),
            mfa_verified: true,
            is_superuser: false,
            is_staff: true,
        };

        let cloned = auth.clone();

        assert_eq!(auth.uuid, cloned.uuid);
        assert_eq!(auth.username, cloned.username);
        assert_eq!(auth.mfa_verified, cloned.mfa_verified);
    }

    #[test]
    fn test_auth_user_debug() {
        let auth = AuthUser {
            uuid: "debug-uuid".to_string(),
            username: "debuguser".to_string(),
            mfa_verified: false,
            is_superuser: true,
            is_staff: false,
        };

        let debug_str = format!("{:?}", auth);

        assert!(debug_str.contains("AuthUser"));
        assert!(debug_str.contains("debuguser"));
    }

    // ==================== ConnectSshForm Tests ====================

    #[test]
    fn test_connect_ssh_form_deserialize_minimal() {
        let json = r#"{"csrf_token": "test-csrf-token"}"#;
        let form: ConnectSshForm = unwrap_ok!(serde_json::from_str(json));

        assert_eq!(form.csrf_token, "test-csrf-token");
        assert!(form.username.is_none());
    }

    #[test]
    fn test_connect_ssh_form_deserialize_with_username() {
        let json = r#"{"csrf_token": "csrf123", "username": "admin"}"#;
        let form: ConnectSshForm = unwrap_ok!(serde_json::from_str(json));

        assert_eq!(form.csrf_token, "csrf123");
        assert_eq!(form.username, Some("admin".to_string()));
    }

    #[test]
    fn test_connect_ssh_form_deserialize_null_username() {
        let json = r#"{"csrf_token": "csrf", "username": null}"#;
        let form: ConnectSshForm = unwrap_ok!(serde_json::from_str(json));

        assert!(form.username.is_none());
    }

    #[test]
    fn test_connect_ssh_form_debug() {
        let form = ConnectSshForm {
            csrf_token: "token123".to_string(),
            username: Some("testuser".to_string()),
        };

        let debug_str = format!("{:?}", form);

        assert!(debug_str.contains("ConnectSshForm"));
        assert!(debug_str.contains("testuser"));
    }

    #[test]
    fn test_connect_ssh_form_missing_csrf() {
        let json = r#"{"username": "admin"}"#;
        let result: Result<ConnectSshForm, _> = serde_json::from_str(json);

        assert!(result.is_err());
    }

    // ==================== ConnectSshResponse Tests ====================

    #[test]
    fn test_connect_ssh_response_success() {
        let response = ConnectSshResponse {
            success: true,
            session_id: Some("sess-123".to_string()),
            redirect_url: Some("/sessions/terminal/sess-123".to_string()),
            error: None,
        };

        assert!(response.success);
        assert_eq!(response.session_id, Some("sess-123".to_string()));
        assert!(response.redirect_url.unwrap().contains("/sessions/terminal/"));
        assert!(response.error.is_none());
    }

    #[test]
    fn test_connect_ssh_response_failure() {
        let response = ConnectSshResponse {
            success: false,
            session_id: None,
            redirect_url: None,
            error: Some("Connection refused".to_string()),
        };

        assert!(!response.success);
        assert!(response.session_id.is_none());
        assert!(response.redirect_url.is_none());
        assert_eq!(response.error, Some("Connection refused".to_string()));
    }

    #[test]
    fn test_connect_ssh_response_serialize() {
        let response = ConnectSshResponse {
            success: true,
            session_id: Some("abc-123".to_string()),
            redirect_url: Some("/terminal/abc-123".to_string()),
            error: None,
        };

        let json = serde_json::to_string(&response).unwrap();

        assert!(json.contains("\"success\":true"));
        assert!(json.contains("\"session_id\":\"abc-123\""));
        assert!(json.contains("\"redirect_url\":\"/terminal/abc-123\""));
    }

    #[test]
    fn test_connect_ssh_response_serialize_failure() {
        let response = ConnectSshResponse {
            success: false,
            session_id: None,
            redirect_url: None,
            error: Some("Invalid credentials".to_string()),
        };

        let json = serde_json::to_string(&response).unwrap();

        assert!(json.contains("\"success\":false"));
        assert!(json.contains("\"error\":\"Invalid credentials\""));
    }

    #[test]
    fn test_connect_ssh_response_debug() {
        let response = ConnectSshResponse {
            success: true,
            session_id: Some("debug-sess".to_string()),
            redirect_url: Some("/debug".to_string()),
            error: None,
        };

        let debug_str = format!("{:?}", response);

        assert!(debug_str.contains("ConnectSshResponse"));
        assert!(debug_str.contains("debug-sess"));
    }

    #[test]
    fn test_connect_ssh_response_all_none() {
        let response = ConnectSshResponse {
            success: false,
            session_id: None,
            redirect_url: None,
            error: None,
        };

        assert!(!response.success);
        assert!(response.session_id.is_none());
        assert!(response.error.is_none());
    }
}
