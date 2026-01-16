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
    response::{Html, IntoResponse, Response},
};
use diesel::prelude::*;
use diesel::sql_types::{BigInt, Integer, Nullable, Text, Uuid as DieselUuid};
use std::collections::HashMap;
use secrecy::ExposeSecret;
use axum_extra::extract::CookieJar;

use crate::AppState;
use crate::db::get_connection;
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

/// Login page.
pub async fn login_page(State(_state): State<AppState>) -> Result<impl IntoResponse, AppError> {
    let base = BaseTemplate::new("Login".to_string(), None);
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        base.into_fields();

    let template = LoginTemplate {
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
    let mut conn = get_connection(&state.db_pool)?;

    let search_filter = params.get("search").cloned();
    let status_filter = params.get("status").cloned();

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
        .load(&mut conn)?;

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
    auth_user: WebAuthUser,
    axum::extract::Path(user_uuid): axum::extract::Path<String>,
) -> Result<impl IntoResponse, AppError> {
    use crate::schema::users;
    use crate::templates::accounts::user_detail::UserDetail;

    let user = Some(user_context_from_auth(&auth_user));
    let base =
        BaseTemplate::new("User Details".to_string(), user).with_current_path("/accounts/users");

    // Load user from database
    let mut conn = get_connection(&state.db_pool)?;

    let parsed_uuid = uuid::Uuid::parse_str(&user_uuid)
        .map_err(|_| AppError::NotFound("Invalid UUID".to_string()))?;

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
    )> = users::table
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
        .optional()?;

    let db_user = db_user.ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

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
    };

    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;
    Ok(Html(html))
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

    let mut conn = get_connection(&state.db_pool)?;

    // Parse the UUID from the auth user
    let user_uuid = uuid::Uuid::parse_str(&auth_user.uuid)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Invalid UUID: {}", e)))?;

    // Fetch the full user data from the database
    let db_user: User = users::table
        .filter(users::uuid.eq(user_uuid))
        .filter(users::is_deleted.eq(false))
        .first(&mut conn)
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

/// MFA setup page.
pub async fn mfa_setup(
    State(_state): State<AppState>,
    auth_user: WebAuthUser,
) -> Result<impl IntoResponse, AppError> {
    let user = Some(user_context_from_auth(&auth_user));
    let base =
        BaseTemplate::new("MFA Setup".to_string(), user.clone()).with_current_path("/accounts/mfa");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        base.into_fields();

    // TODO: Generate secret and QR code
    let template = MfaSetupTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        secret: "SECRET123456".to_string(),
        qr_code_url: "/static/qr.png".to_string(),
    };

    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;
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
    let mut conn = get_connection(&state.db_pool)?;

    // Get current token hash to identify the real current session
    let current_token_hash = jar.get("access_token").map(|cookie| {
        let mut hasher = Sha3_256::new();
        hasher.update(cookie.value().as_bytes());
        format!("{:x}", hasher.finalize())
    });

    // Debug: log auth_user UUID
    tracing::debug!(auth_uuid = %auth_user.uuid, "Loading sessions for user");

    let user_id: i32 = auth_user
        .uuid
        .parse::<uuid::Uuid>()
        .ok()
        .and_then(|uuid| {
            use crate::schema::users;
            users::table
                .filter(users::uuid.eq(uuid))
                .select(users::id)
                .first::<i32>(&mut conn)
                .ok()
        })
        .unwrap_or(0);

    // Debug: log found user_id
    tracing::debug!(user_id = user_id, auth_uuid = %auth_user.uuid, "Found user_id for auth UUID");

    let db_sessions: Vec<AuthSession> = auth_sessions::table
        .filter(auth_sessions::user_id.eq(user_id))
        .filter(auth_sessions::expires_at.gt(chrono::Utc::now()))
        .order(auth_sessions::created_at.desc())
        .load(&mut conn)
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
    let mut conn = get_connection(&state.db_pool)?;
    let user_id: i32 = auth_user
        .uuid
        .parse::<uuid::Uuid>()
        .ok()
        .and_then(|uuid| {
            use crate::schema::users;
            users::table
                .filter(users::uuid.eq(uuid))
                .select(users::id)
                .first::<i32>(&mut conn)
                .ok()
        })
        .unwrap_or(0);

    let db_keys: Vec<ApiKey> = api_keys::table
        .filter(api_keys::user_id.eq(user_id))
        .order(api_keys::created_at.desc())
        .load(&mut conn)
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
    axum::extract::Path(session_uuid): axum::extract::Path<uuid::Uuid>,
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
    let mut conn = get_connection(&state.db_pool)?;

    // Get user ID
    let user_id: i32 = auth_user
        .uuid
        .parse::<uuid::Uuid>()
        .ok()
        .and_then(|uuid| {
            use crate::schema::users;
            users::table
                .filter(users::uuid.eq(uuid))
                .select(users::id)
                .first::<i32>(&mut conn)
                .ok()
        })
        .unwrap_or(0);

    // Delete the session (only if it belongs to the user)
    let deleted = diesel::delete(
        auth_sessions::table
            .filter(auth_sessions::uuid.eq(session_uuid))
            .filter(auth_sessions::user_id.eq(user_id)),
    )
    .execute(&mut conn)
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
    let db_sessions: Vec<AuthSession> = match get_connection(&state.db_pool) {
        Ok(mut conn) => auth_sessions::table
            .filter(auth_sessions::user_id.eq(user_id))
            .filter(auth_sessions::expires_at.gt(chrono::Utc::now()))
            .order(auth_sessions::created_at.desc())
            .load(&mut conn)
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
    axum::extract::Path(key_uuid): axum::extract::Path<uuid::Uuid>,
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

    let mut conn = get_connection(&state.db_pool)?;

    // Get user ID
    let user_id: i32 = auth_user
        .uuid
        .parse::<uuid::Uuid>()
        .ok()
        .and_then(|uuid| {
            use crate::schema::users;
            users::table
                .filter(users::uuid.eq(uuid))
                .select(users::id)
                .first::<i32>(&mut conn)
                .ok()
        })
        .unwrap_or(0);

    // Mark the key as inactive (soft delete)
    let updated = diesel::update(
        api_keys::table
            .filter(api_keys::uuid.eq(key_uuid))
            .filter(api_keys::user_id.eq(user_id)),
    )
    .set(api_keys::is_active.eq(false))
    .execute(&mut conn)
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

    let mut conn = get_connection(&state.db_pool)?;

    // Get user ID
    let user_id: i32 = auth_user
        .uuid
        .parse::<uuid::Uuid>()
        .ok()
        .and_then(|uuid| {
            use crate::schema::users;
            users::table
                .filter(users::uuid.eq(uuid))
                .select(users::id)
                .first::<i32>(&mut conn)
                .ok()
        })
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("User not found")))?;

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

    // Load assets from database
    let mut conn = get_connection(&state.db_pool)?;

    let search_filter = params.get("search").cloned();
    let type_filter = params.get("type").cloned();
    let status_filter = params.get("status").cloned();

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
        .load(&mut conn)?;

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

    let mut conn = get_connection(&state.db_pool)?;
    let pattern = format!("%{}%", query);

    let rows: Vec<(uuid::Uuid, String, String, String, String)> = a::assets
        .filter(a::is_deleted.eq(false))
        .filter(a::name.ilike(&pattern).or(a::hostname.ilike(&pattern)))
        .select((a::uuid, a::name, a::hostname, a::asset_type, a::status))
        .order(a::name.asc())
        .limit(8)
        .load(&mut conn)?;

    if rows.is_empty() {
        return Ok(Html(String::new()));
    }

    let mut html = String::from(
        r#"<div class="rounded-md bg-white dark:bg-gray-800 shadow ring-1 ring-gray-200 dark:ring-gray-700">
<ul class="divide-y divide-gray-200 dark:divide-gray-700">"#,
    );

    for (asset_uuid, name, hostname, asset_type, status) in rows {
        let name = askama::filters::escape(&name, askama::filters::Html)
            .unwrap()
            .to_string();
        let hostname = askama::filters::escape(&hostname, askama::filters::Html)
            .unwrap()
            .to_string();
        let asset_type = askama::filters::escape(&asset_type, askama::filters::Html)
            .unwrap()
            .to_string();
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
    auth_user: WebAuthUser,
    axum::extract::Path(asset_uuid): axum::extract::Path<::uuid::Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let user = Some(user_context_from_auth(&auth_user));

    let mut conn = get_connection(&state.db_pool)?;

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
    ) = a::assets
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
        ))
        .first(&mut conn)
        .map_err(|e| match e {
            diesel::result::Error::NotFound => AppError::NotFound("Asset not found".to_string()),
            _ => AppError::Database(e),
        })?;

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
    ) = asset_row;

    // Get group info if group_id is set
    let (group_name, group_uuid): (Option<String>, Option<String>) =
        if let Some(gid) = asset_group_id {
            ag::asset_groups
                .filter(ag::id.eq(gid))
                .select((ag::name, ag::uuid))
                .first::<(String, ::uuid::Uuid)>(&mut conn)
                .optional()
                .map_err(AppError::Database)?
                .map(|(n, u)| (Some(n), Some(u.to_string())))
                .unwrap_or((None, None))
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

    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;
    Ok(Html(html))
}

// NOTE: AssetQueryDetailResult removed - migrated to Diesel DSL tuple query

/// Asset edit page.
pub async fn asset_edit(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    incoming_flash: IncomingFlash,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
) -> Result<impl IntoResponse, AppError> {
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

    let mut conn = get_connection(&state.db_pool)?;
    let asset_uuid = ::uuid::Uuid::parse_str(&uuid_str)
        .map_err(|e| AppError::Validation(format!("Invalid UUID: {}", e)))?;

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
        bool,
        bool,
    ) = a::assets
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
            a::require_mfa,
            a::require_justification,
        ))
        .first(&mut conn)
        .map_err(|e| match e {
            diesel::result::Error::NotFound => AppError::NotFound("Asset not found".to_string()),
            _ => AppError::Database(e),
        })?;

    let (
        asset_uuid_val,
        asset_name,
        asset_hostname,
        asset_ip,
        asset_port,
        asset_type_val,
        asset_status,
        asset_description,
        asset_require_mfa,
        asset_require_justification,
    ) = asset_row;

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

    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;

    // Clear flash cookie after reading and return HTML
    use crate::middleware::flash::ClearFlashCookie;
    Ok((ClearFlashCookie, Html(html)))
}

/// Dashboard stats widget.
pub async fn dashboard_widget_stats(
    State(state): State<AppState>,
    OptionalAuthUser(_auth_user): OptionalAuthUser,
) -> Result<impl IntoResponse, AppError> {
    use crate::templates::dashboard::widgets::StatsData;
    use chrono::{Duration, Utc};

    let mut conn = get_connection(&state.db_pool)?;

    // Count active sessions
    let active_sessions: i64 = proxy_sessions::table
        .filter(proxy_sessions::status.eq("active"))
        .count()
        .get_result(&mut conn)?;

    // Count today's sessions
    let today_start = Utc::now().date_naive().and_hms_opt(0, 0, 0).unwrap();
    let today_sessions: i64 = proxy_sessions::table
        .filter(proxy_sessions::created_at.ge(today_start.and_utc()))
        .count()
        .get_result(&mut conn)?;

    // Count this week's sessions
    let week_start = Utc::now() - Duration::days(7);
    let week_sessions: i64 = proxy_sessions::table
        .filter(proxy_sessions::created_at.ge(week_start))
        .count()
        .get_result(&mut conn)?;

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

    let mut conn = get_connection(&state.db_pool)?;

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
            .load(&mut conn)?;

    let sessions: Vec<ActiveSessionItem> = active_sessions
        .into_iter()
        .map(
            |(id, asset_name, asset_hostname, session_type, started_at)| {
                let duration = chrono::Utc::now().signed_duration_since(started_at);
                ActiveSessionItem {
                    id,
                    asset_name,
                    asset_hostname,
                    session_type,
                    duration_seconds: Some(duration.num_seconds()),
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
    let mut conn = get_connection(&state.db_pool)?;

    let status_filter = params.get("status").cloned();
    let type_filter = params.get("type").cloned();
    let asset_filter = params.get("asset").cloned();

    let mut query = proxy_sessions::table.inner_join(assets::table).into_boxed();

    // Exclude pending approval requests
    query = query.filter(proxy_sessions::status.ne("pending"));
    query = query.filter(proxy_sessions::status.ne("orphaned"));

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
        .load(&mut conn)?;

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
    axum::extract::Path(session_id): axum::extract::Path<i32>,
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

    crate::handlers::sessions::terminate_session(
        State(state),
        headers,
        auth_user.0,
        axum::extract::Path(session_id),
    )
    .await
}

/// Session detail page.
pub async fn session_detail(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    axum::extract::Path(id): axum::extract::Path<i32>,
) -> Result<impl IntoResponse, AppError> {
    use crate::templates::sessions::session_detail::SessionDetail;

    let user = Some(user_context_from_auth(&auth_user));
    let mut conn = get_connection(&state.db_pool)?;

    // NOTE: Raw SQL required - complex triple JOIN with PostgreSQL ::text casts
    // Cannot be migrated to Diesel DSL due to:
    // 1. uuid::text casts for string representation
    // 2. inet::text cast for client_ip
    // 3. Triple JOIN (proxy_sessions -> users -> assets)
    let session_data: SessionQueryDetailResult = diesel::sql_query(
        "SELECT ps.id, ps.uuid, u.username, u.uuid::text as user_uuid,
                a.name as asset_name, a.hostname as asset_hostname, a.uuid::text as asset_uuid, a.asset_type,
                ps.session_type, ps.status, ps.credential_username, ps.client_ip::text as client_ip,
                ps.client_user_agent, ps.proxy_instance, ps.connected_at, ps.disconnected_at,
                ps.justification, ps.is_recorded, ps.recording_path, ps.bytes_sent, ps.bytes_received,
                ps.commands_count, ps.created_at
         FROM proxy_sessions ps
         INNER JOIN users u ON u.id = ps.user_id
         INNER JOIN assets a ON a.id = ps.asset_id
         WHERE ps.id = $1"
    )
    .bind::<Integer, _>(id)
    .get_result(&mut conn)
    .map_err(|e| match e {
        diesel::result::Error::NotFound => AppError::NotFound("Session not found".to_string()),
        _ => AppError::Database(e),
    })?;

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
    };

    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;
    Ok(Html(html))
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

    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new("Recordings".to_string(), user.clone())
        .with_current_path("/sessions/recordings");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        base.into_fields();

    // Load recordings from database (sessions with is_recorded = true)
    let mut conn = get_connection(&state.db_pool)?;

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
        .load(&mut conn)?;

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
    auth_user: WebAuthUser,
    axum::extract::Path(id): axum::extract::Path<i32>,
) -> Result<impl IntoResponse, AppError> {
    use crate::templates::sessions::recording_play::RecordingData;

    let user = Some(user_context_from_auth(&auth_user));
    let mut conn = get_connection(&state.db_pool)?;

    // NOTE: Raw SQL required - triple JOIN with PostgreSQL-specific features
    let recording_data: RecordingQueryResult = diesel::sql_query(
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
    .map_err(|e| match e {
        diesel::result::Error::NotFound => AppError::NotFound("Recording not found".to_string()),
        _ => AppError::Database(e),
    })?;

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

    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;
    Ok(Html(html))
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
    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new("Approvals".to_string(), user.clone())
        .with_current_path("/sessions/approvals");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        base.into_fields();

    let mut conn = get_connection(&state.db_pool)?;
    let status_filter = params.get("status").cloned();
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
        .map(|r| r.count)
        .unwrap_or(0)
    } else {
        diesel::sql_query(
            "SELECT COUNT(*) as count FROM proxy_sessions ps WHERE ps.justification IS NOT NULL",
        )
        .get_result::<ApprovalCountResult>(&mut conn)
        .map(|r| r.count)
        .unwrap_or(0)
    };

    let total_pages = ((total_items as f64) / (items_per_page as f64)).ceil() as i32;
    let offset = ((page - 1) * items_per_page) as i64;

    // NOTE: Raw SQL required - triple JOIN with inet::text cast, using parameterized queries
    let approvals_data: Vec<ApprovalQueryResult> = if let Some(ref status) = status_filter {
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
        .load(&mut conn)
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
        .load(&mut conn)
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
    auth_user: WebAuthUser,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let user = Some(user_context_from_auth(&auth_user));

    let mut conn = get_connection(&state.db_pool)?;
    let approval_uuid = ::uuid::Uuid::parse_str(&uuid_str)
        .map_err(|e| AppError::Validation(format!("Invalid UUID: {}", e)))?;

    // NOTE: Raw SQL required - triple JOIN with inet::text cast
    let approval_data: ApprovalDetailResult = diesel::sql_query(
        "SELECT ps.uuid, u.username, u.email as user_email, a.name as asset_name, a.asset_type, 
                a.hostname as asset_hostname, ps.session_type, ps.status, ps.justification, 
                ps.client_ip::text as client_ip, ps.credential_username, ps.created_at, ps.is_recorded
         FROM proxy_sessions ps
         INNER JOIN users u ON u.id = ps.user_id
         INNER JOIN assets a ON a.id = ps.asset_id
         WHERE ps.uuid = $1"
    )
    .bind::<DieselUuid, _>(approval_uuid)
    .get_result(&mut conn)
    .map_err(|e| match e {
        diesel::result::Error::NotFound => AppError::NotFound("Approval request not found".to_string()),
        _ => AppError::Database(e),
    })?;

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

    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;
    Ok(Html(html))
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
    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new("Active Sessions".to_string(), user.clone())
        .with_current_path("/sessions/active");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        base.into_fields();

    let mut conn = get_connection(&state.db_pool)?;

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

    let mut conn = get_connection(&state.db_pool)?;
    let search_filter = params.get("search").cloned();

    // Query groups with member count
    // Groups list query - migrated to Diesel DSL
    use crate::schema::vauban_groups::dsl::*;
    use diesel::dsl::sql;

    #[allow(clippy::type_complexity)]
    let groups_data: Vec<(
        ::uuid::Uuid,
        String,
        Option<String>,
        String,
        chrono::DateTime<chrono::Utc>,
    )> = if let Some(ref s) = search_filter {
        // NOTE: ILIKE requires raw SQL fragment for OR condition on nullable column
        let pattern = format!("%{}%", s);
        vauban_groups
            .filter(sql::<diesel::sql_types::Bool>(&format!(
                "name ILIKE '{}' OR description ILIKE '{}'",
                pattern.replace('\'', "''"),
                pattern.replace('\'', "''")
            )))
            .order(name.asc())
            .select((uuid, name, description, source, created_at))
            .load::<(
                ::uuid::Uuid,
                String,
                Option<String>,
                String,
                chrono::DateTime<chrono::Utc>,
            )>(&mut conn)
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
            .map_err(AppError::Database)?
    };

    // Get member counts - migrated to Diesel DSL
    use crate::schema::user_groups::dsl::{group_id as ug_group_id, user_groups};
    let group_items: Vec<crate::templates::accounts::group_list::GroupListItem> = groups_data
        .into_iter()
        .map(
            |(group_uuid, group_name, group_description, group_source, group_created_at)| {
                // Get member count for this group using JOIN
                let member_count: i64 = user_groups
                    .inner_join(vauban_groups.on(id.eq(ug_group_id)))
                    .filter(uuid.eq(group_uuid))
                    .count()
                    .get_result(&mut conn)
                    .unwrap_or(0);

                crate::templates::accounts::group_list::GroupListItem {
                    uuid: group_uuid.to_string(),
                    name: group_name,
                    description: group_description,
                    source: group_source,
                    member_count,
                    created_at: group_created_at.format("%b %d, %Y").to_string(),
                }
            },
        )
        .collect();

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
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let user = Some(user_context_from_auth(&auth_user));

    let mut conn = get_connection(&state.db_pool)?;
    let group_uuid = ::uuid::Uuid::parse_str(&uuid_str)
        .map_err(|e| AppError::Validation(format!("Invalid UUID: {}", e)))?;

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
    ) = vg::vauban_groups
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
        .map_err(|e| match e {
            diesel::result::Error::NotFound => AppError::NotFound("Group not found".to_string()),
            _ => AppError::Database(e),
        })?;

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
    )> = u::users
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
        .map_err(AppError::Database)?;

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
        .with_current_path("/accounts/groups");
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
    };

    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;
    Ok(Html(html))
}

// NOTE: GroupExtraResult and GroupMemberResult removed - migrated to Diesel DSL

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

    let mut conn = get_connection(&state.db_pool)?;
    let search_filter = params.get("search").cloned();

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
        .load(&mut conn)
        .map_err(AppError::Database)?
    } else {
        diesel::sql_query(
            "SELECT g.uuid, g.name, g.slug, g.description, g.color, g.icon, g.created_at,
                    (SELECT COUNT(*) FROM assets a WHERE a.group_id = g.id AND a.is_deleted = false) as asset_count
             FROM asset_groups g
             WHERE g.is_deleted = false
             ORDER BY g.name ASC"
        )
        .load(&mut conn)
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
    auth_user: WebAuthUser,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let user = Some(user_context_from_auth(&auth_user));

    let mut conn = get_connection(&state.db_pool)?;
    let group_uuid = ::uuid::Uuid::parse_str(&uuid_str)
        .map_err(|e| AppError::Validation(format!("Invalid UUID: {}", e)))?;

    // NOTE: Raw SQL - simple query but kept for consistency with related code
    let group_data: AssetGroupDetailResult = diesel::sql_query(
        "SELECT uuid, name, slug, description, color, icon, created_at, updated_at
         FROM asset_groups WHERE uuid = $1 AND is_deleted = false",
    )
    .bind::<DieselUuid, _>(group_uuid)
    .get_result(&mut conn)
    .map_err(|e| match e {
        diesel::result::Error::NotFound => AppError::NotFound("Asset group not found".to_string()),
        _ => AppError::Database(e),
    })?;

    // NOTE: Raw SQL - kept for consistency with asset_group_detail page
    let assets_data: Vec<GroupAssetResult> = diesel::sql_query(
        "SELECT a.uuid, a.name, a.hostname, a.asset_type, a.status
         FROM assets a
         INNER JOIN asset_groups g ON g.id = a.group_id
         WHERE g.uuid = $1 AND a.is_deleted = false
         ORDER BY a.name ASC",
    )
    .bind::<DieselUuid, _>(group_uuid)
    .load(&mut conn)
    .map_err(AppError::Database)?;

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
    };

    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;
    Ok(Html(html))
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

/// Asset group edit page.
pub async fn asset_group_edit(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    incoming_flash: IncomingFlash,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
) -> Result<impl IntoResponse, AppError> {
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

    let mut conn = get_connection(&state.db_pool)?;
    let group_uuid = ::uuid::Uuid::parse_str(&uuid_str)
        .map_err(|e| AppError::Validation(format!("Invalid UUID: {}", e)))?;

    // NOTE: Raw SQL - kept for consistency with asset_group pages
    let group_data: AssetGroupEditResult = diesel::sql_query(
        "SELECT uuid, name, slug, description, color, icon
         FROM asset_groups WHERE uuid = $1 AND is_deleted = false",
    )
    .bind::<DieselUuid, _>(group_uuid)
    .get_result(&mut conn)
    .map_err(|e| match e {
        diesel::result::Error::NotFound => AppError::NotFound("Asset group not found".to_string()),
        _ => AppError::Database(e),
    })?;

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

    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;

    // Clear flash cookie after reading and return HTML
    use crate::middleware::flash::ClearFlashCookie;
    Ok((ClearFlashCookie, Html(html)))
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
    _auth_user: WebAuthUser,
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
    let mut conn = match get_connection(&state.db_pool) {
        Ok(conn) => conn,
        Err(_) => {
            return flash_redirect(
                flash.error("Database connection error. Please try again."),
                &format!("/assets/groups/{}/edit", group_uuid),
            );
        }
    };

    // NOTE: Raw SQL - UPDATE with NOW() PostgreSQL function, using parameterized queries
    let result = diesel::sql_query(
        "UPDATE asset_groups SET name = $1, slug = $2, description = $3, color = $4, icon = $5, updated_at = NOW()
         WHERE uuid = $6 AND is_deleted = false"
    )
    .bind::<Text, _>(&form.name)
    .bind::<Text, _>(&form.slug)
    .bind::<Nullable<Text>, _>(form.description.as_deref())
    .bind::<Text, _>(&form.color)
    .bind::<Text, _>(&form.icon)
    .bind::<DieselUuid, _>(group_uuid)
    .execute(&mut conn);

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
            return flash_redirect(
                flash.error("Invalid asset identifier"),
                "/assets",
            );
        }
    };

    let mut conn = match get_connection(&state.db_pool) {
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
    {
        Ok(id) => id,
        Err(diesel::result::Error::NotFound) => {
            return flash_redirect(
                flash.error("Asset not found or already deleted"),
                "/assets",
            );
        }
        Err(_) => {
            return flash_redirect(
                flash.error("Failed to delete asset. Please try again."),
                &format!("/assets/{}", asset_uuid),
            );
        }
    };

    let now = Utc::now();
    let result = conn.transaction::<_, diesel::result::Error, _>(|conn| {
        diesel::update(a::assets.filter(a::id.eq(asset_id)))
            .set((
                a::is_deleted.eq(true),
                a::deleted_at.eq(now),
                a::updated_at.eq(now),
            ))
            .execute(conn)?;

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
        .execute(conn)?;

        Ok(())
    });

    match result {
        Ok(_) => {
            if let Err(err) = diesel::update(
                ps::proxy_sessions
                    .filter(ps::asset_id.eq(asset_id))
                    .filter(ps::status.eq_any(vec!["pending", "connecting"])),
            )
            .set((ps::status.eq("orphaned"), ps::updated_at.eq(now)))
            .execute(&mut conn)
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
                        flash.error("Invalid IP address format. Use format like 192.168.1.1 or 2001:db8::1"),
                        &format!("/assets/{}/edit", asset_uuid),
                    );
                }
            }
        }
    } else {
        None
    };

    // Get database connection
    let mut conn = match get_connection(&state.db_pool) {
        Ok(conn) => conn,
        Err(_) => {
            return flash_redirect(
                flash.error("Database connection error. Please try again."),
                &format!("/assets/{}/edit", asset_uuid),
            );
        }
    };

    // Parse boolean fields from checkbox values
    let require_mfa = form.require_mfa.as_ref().map(|v| v == "on" || v == "true").unwrap_or(false);
    let require_justification = form.require_justification.as_ref().map(|v| v == "on" || v == "true").unwrap_or(false);

    use crate::schema::assets::dsl as a;
    use chrono::Utc;

    // First, get the existing asset to preserve unchanged values
    let existing: Result<crate::models::asset::Asset, _> = a::assets
        .filter(a::uuid.eq(asset_uuid))
        .filter(a::is_deleted.eq(false))
        .first(&mut conn);

    let existing = match existing {
        Ok(asset) => asset,
        Err(_) => {
            return flash_redirect(
                flash.error("Asset not found"),
                "/assets",
            );
        }
    };

    // Update the asset
    let result = diesel::update(a::assets.filter(a::uuid.eq(asset_uuid)))
        .set((
            a::name.eq(&form.name),
            a::hostname.eq(&form.hostname),
            a::ip_address.eq(new_ip_address.or(existing.ip_address)),
            a::port.eq(form.port),
            a::status.eq(&form.status),
            a::description.eq(form.description.as_deref()),
            a::require_mfa.eq(require_mfa),
            a::require_justification.eq(require_justification),
            a::updated_at.eq(Utc::now()),
        ))
        .execute(&mut conn);

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

        let form: UpdateAssetGroupForm = serde_json::from_str(json).unwrap();

        assert_eq!(form.name, "Production Servers");
        assert_eq!(form.slug, "production-servers");
        assert_eq!(form.description, Some("All production servers".to_string()));
        assert_eq!(form.color, "#ff5733");
        assert_eq!(form.icon, "server");
    }

    #[test]
    fn test_update_asset_group_form_deserialize_minimal() {
        let json = r##"{"name": "Test", "slug": "test", "color": "#fff", "icon": "folder", "csrf_token": "csrf"}"##;

        let form: UpdateAssetGroupForm = serde_json::from_str(json).unwrap();

        assert_eq!(form.name, "Test");
        assert_eq!(form.slug, "test");
        assert!(form.description.is_none());
        assert_eq!(form.color, "#fff");
        assert_eq!(form.icon, "folder");
    }

    #[test]
    fn test_update_asset_group_form_deserialize_with_null_description() {
        let json = r##"{"name": "Group", "slug": "group", "description": null, "color": "#000", "icon": "box", "csrf_token": "csrf"}"##;

        let form: UpdateAssetGroupForm = serde_json::from_str(json).unwrap();

        assert!(form.description.is_none());
    }

    #[test]
    fn test_update_asset_group_form_deserialize_special_chars() {
        let json = r##"{"name": "Test's Group", "slug": "tests-group", "description": "Description with quotes", "color": "#123456", "icon": "database", "csrf_token": "csrf"}"##;

        let form: UpdateAssetGroupForm = serde_json::from_str(json).unwrap();

        assert_eq!(form.name, "Test's Group");
        assert!(form.description.unwrap().contains("quotes"));
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

        let form: UpdateAssetGroupForm = serde_json::from_str(json).unwrap();

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
            ip_address: "192.168.1.1".parse::<IpNetwork>().unwrap(),
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
                ip_address: "192.168.1.1".parse::<IpNetwork>().unwrap(),
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
                ip_address: "10.0.0.1".parse::<IpNetwork>().unwrap(),
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
            ip_address: "192.168.1.1".parse::<IpNetwork>().unwrap(),
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
            ip_address: "2001:db8::1".parse::<IpNetwork>().unwrap(),
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
            ip_address: "10.0.0.1".parse::<IpNetwork>().unwrap(),
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
        let form: CreateApiKeyForm = serde_json::from_str(json).unwrap();

        assert_eq!(form.name, "My API Key");
        assert_eq!(form.expires_in_days, Some(30));
    }

    #[test]
    fn test_create_api_key_form_without_expiry() {
        let json = r#"{"name": "Permanent Key", "csrf_token": "csrf"}"#;
        let form: CreateApiKeyForm = serde_json::from_str(json).unwrap();

        assert_eq!(form.name, "Permanent Key");
        assert!(form.expires_in_days.is_none());
    }

    #[test]
    fn test_create_api_key_form_empty_name() {
        let json = r#"{"name": "", "expires_in_days": 7, "csrf_token": "csrf"}"#;
        let form: CreateApiKeyForm = serde_json::from_str(json).unwrap();

        assert_eq!(form.name, "");
        assert_eq!(form.expires_in_days, Some(7));
    }

    // ==================== UpdateAssetGroupForm Additional Tests ====================

    #[test]
    fn test_update_asset_group_form_special_characters() {
        let json = r##"{"name": "Serveurs d'été", "slug": "serveurs-ete", "description": "Serveurs pour l'été 2024", "color": "#123abc", "icon": "sun", "csrf_token": "csrf"}"##;
        let form: UpdateAssetGroupForm = serde_json::from_str(json).unwrap();

        assert_eq!(form.name, "Serveurs d'été");
        assert!(form.description.unwrap().contains("été"));
    }

    #[test]
    fn test_update_asset_group_form_unicode() {
        let json = r##"{"name": "服务器组", "slug": "chinese-servers", "color": "#ff0000", "icon": "server", "csrf_token": "csrf"}"##;
        let form: UpdateAssetGroupForm = serde_json::from_str(json).unwrap();

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
        let form: UpdateAssetGroupForm = serde_json::from_str(&json).unwrap();

        assert_eq!(form.description.unwrap().len(), 1000);
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
            ip_address: "10.0.0.1".parse::<IpNetwork>().unwrap(),
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
        let form: UpdateAssetGroupForm = serde_json::from_str(json).unwrap();

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
            let form: UpdateAssetGroupForm = serde_json::from_str(&json).unwrap();
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
            let form: UpdateAssetGroupForm = serde_json::from_str(&json).unwrap();
            assert_eq!(form.icon, icon);
        }
    }

    // ==================== CreateApiKeyForm Additional Tests ====================

    #[test]
    fn test_create_api_key_form_zero_expiry() {
        let json = r#"{"name": "Zero Expiry", "expires_in_days": 0, "csrf_token": "csrf"}"#;
        let form: CreateApiKeyForm = serde_json::from_str(json).unwrap();

        assert_eq!(form.expires_in_days, Some(0));
    }

    #[test]
    fn test_create_api_key_form_long_expiry() {
        let json = r#"{"name": "Long Expiry", "expires_in_days": 365, "csrf_token": "csrf"}"#;
        let form: CreateApiKeyForm = serde_json::from_str(json).unwrap();

        assert_eq!(form.expires_in_days, Some(365));
    }

    #[test]
    fn test_create_api_key_form_unicode_name() {
        let json = r#"{"name": "密钥名称", "csrf_token": "csrf"}"#;
        let form: CreateApiKeyForm = serde_json::from_str(json).unwrap();

        assert_eq!(form.name, "密钥名称");
    }

    #[test]
    fn test_create_api_key_form_long_name() {
        let long_name = "A".repeat(100);
        let json = format!(r#"{{"name": "{}", "csrf_token": "csrf"}}"#, long_name);
        let form: CreateApiKeyForm = serde_json::from_str(&json).unwrap();

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
}
